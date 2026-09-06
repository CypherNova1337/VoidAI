"""The analyzer contract.

An analyzer converts normalised telemetry into grounded Findings. It may use
statistics, signatures, graph algorithms, or arithmetic. It may not use a
language model — that is a hard architectural boundary, not a preference.

The reason is testability. Every analyzer in this package is deterministic:
the same input produces the same Findings with the same IDs, forever. That
property is what makes `voidai bench` a real regression suite rather than a
vibe check, and it is what lets the project claim measured precision and
recall at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import polars as pl

from voidai.ingest.inventory import CaptureWindow, Inventory
from voidai.ingest.inventory import resolution_evidence as _resolution_evidence
from voidai.ingest.ioc import IndicatorSet
from voidai.ingest.schema import (
    ALERT_SCHEMA,
    CONNECTION_SCHEMA,
    DNS_SCHEMA,
    PROCESS_SCHEMA,
    SSL_SCHEMA,
    empty,
)
from voidai.lexicon import Entity, EntityType, Evidence, Finding

Frame = pl.DataFrame | pl.LazyFrame


@dataclass
class AnalysisContext:
    """Everything an analyzer is allowed to look at.

    Passing one context to every analyzer, rather than letting each reach for
    files itself, keeps ingestion cost paid once and makes the data an
    analyzer saw reproducible from the context alone.

    Each source may be an eager `DataFrame` or a lazy `LazyFrame`. Analyzers
    should reach for the `*_scan()` accessors rather than the attributes, so
    that projection, filtering and aggregation push down into the scan instead
    of running after the whole capture has been materialised. On the 66-hour
    CTU-13 scenario that distinction is 7.2GB against a few hundred megabytes
    — the difference between running on the target hardware and not.
    """

    connections: Frame = field(default_factory=lambda: empty(CONNECTION_SCHEMA))
    dns: Frame = field(default_factory=lambda: empty(DNS_SCHEMA))
    alerts: Frame = field(default_factory=lambda: empty(ALERT_SCHEMA))

    #: TLS session records. Empty unless an `ssl.log` was found, and empty is
    #: an ordinary outcome: most captures in this project's test corpus carry
    #: none. Present-but-fingerprintless is a *third* state and not the same
    #: as either — see `analyzers/tlsdga.py`.
    ssl: Frame = field(default_factory=lambda: empty(SSL_SCHEMA))

    #: Windows process-creation records — Sysmon event ID 1, shipped as JSON
    #: lines. Empty unless host telemetry was found, and empty is the common
    #: case: this project's network corpora carry none at all, so the two host
    #: predicates are silent on every capture in `docs/benchmarks.md` before
    #: section 11.
    #:
    #: Present-but-too-small is a *third* state and the important one. Both
    #: host predicates are estate-relative — "rare across the estate", "unlike
    #: what this parent normally spawns" — so a capture from one machine
    #: carries the telemetry and still cannot support either claim. The
    #: analyzer measures that and declines, rather than emitting a rarity
    #: score of 1.0 for every process ever run; see `analyzers/host.py`.
    processes: Frame = field(default_factory=lambda: empty(PROCESS_SCHEMA))

    #: Indicators the operator placed on disk. Empty unless an IOC file was
    #: found, and empty is the normal case: intel is optional, and a run
    #: without it runs one analyzer fewer rather than failing. Loaded here
    #: with the rest of the ingest so that what an analyzer saw is
    #: reproducible from the context alone — and loaded from *files*, never
    #: fetched. See `voidai.ingest.ioc`.
    indicators: IndicatorSet = field(default_factory=IndicatorSet)

    #: Asset mappings the operator placed on disk. Empty unless an inventory
    #: file was found, and empty is the normal case: an inventory is optional,
    #: and a run without one names its subjects by address. Loaded from
    #: *files*, never derived — not from DHCP, not from reverse DNS, not from
    #: the traffic. See `voidai.ingest.inventory`.
    inventory: Inventory = field(default_factory=Inventory)

    #: When the telemetry was recorded. Measured from the sources above when
    #: an inventory is present and left unknown otherwise, because a mapping's
    #: age is judged against the capture rather than against the clock and
    #: nothing else here needs the figure.
    capture: CaptureWindow = field(default_factory=CaptureWindow)

    #: Reverse-resolution built from observed DNS answers: ip -> domain.
    ip_to_domain: dict[str, str] = field(default_factory=dict)
    #: Asset inventory as `actor()` consumes it: ip -> hostname. Populated
    #: from `inventory` at construction, and settable directly by a caller
    #: that has a map from somewhere else. A directly supplied entry wins, and
    #: carries no `resolution_evidence` — there is no file to cite.
    ip_to_host: dict[str, str] = field(default_factory=dict)

    #: Records scanned, when the caller already knows. Avoids a counting pass
    #: over a lazy source purely to fill in a receipt.
    known_record_count: int | None = None

    def __post_init__(self) -> None:
        """Apply the inventory, once, where every consumer sees the same result.

        Here rather than in the CLI because `voidai bench` and every library
        caller build a context directly and never touch `cli._detect`. A join
        performed on one path and not the other would give two
        content-addressed IDs for one finding over one capture, which is the
        reproducibility promise this project makes on its front page.
        """
        if self.inventory.is_empty():
            return
        if not self.capture.known:
            self.capture = self._observed_window()
        for address, hostname in self.inventory.applied(self.capture).items():
            self.ip_to_host.setdefault(address, hostname)

    def _observed_window(self) -> CaptureWindow:
        """First and last timestamp across every timestamped source.

        Costs one streaming min/max pass per source and is taken only when an
        inventory is actually loaded, so a run without one pays nothing.
        """
        first: float | None = None
        last: float | None = None
        for frame in (self.connections, self.dns, self.alerts, self.ssl, self.processes):
            bounds = (
                self._scan(frame)
                .select(pl.col("ts").min().alias("lo"), pl.col("ts").max().alias("hi"))
                .collect(engine="streaming")
            )
            if not bounds.height:
                continue
            low, high = bounds.row(0)
            if low is not None:
                first = float(low) if first is None else min(first, float(low))
            if high is not None:
                last = float(high) if last is None else max(last, float(high))
        return CaptureWindow.from_epochs(first, last)

    @staticmethod
    def _scan(frame: Frame) -> pl.LazyFrame:
        return frame.lazy() if isinstance(frame, pl.DataFrame) else frame

    def connection_scan(self) -> pl.LazyFrame:
        return self._scan(self.connections)

    def dns_scan(self) -> pl.LazyFrame:
        return self._scan(self.dns)

    def alert_scan(self) -> pl.LazyFrame:
        return self._scan(self.alerts)

    def ssl_scan(self) -> pl.LazyFrame:
        return self._scan(self.ssl)

    def process_scan(self) -> pl.LazyFrame:
        return self._scan(self.processes)

    def record_count(self) -> int:
        """Total records available.

        Eager sources answer for free. A lazy source costs one streaming pass,
        so callers that already know the figure should set
        `known_record_count` rather than pay for it twice.
        """
        if self.known_record_count is not None:
            return self.known_record_count

        total = 0
        for frame in (self.connections, self.dns, self.alerts, self.ssl, self.processes):
            if isinstance(frame, pl.DataFrame):
                total += frame.height
            else:
                counted = frame.select(pl.len()).collect(engine="streaming")
                total += int(counted.item()) if counted.height else 0
        return total

    def actor(self, ip: str) -> Entity:
        """Represent a source address as the most specific entity available.

        A finding that names `host:FINANCE-WS04` is worth more to an analyst
        than one naming `ip:10.2.14.88`, so prefer the inventory when it has
        an answer.
        """
        hostname = self.ip_to_host.get(ip)
        if hostname:
            return Entity(type=EntityType.HOST, value=hostname)
        return Entity(type=EntityType.IP, value=ip)

    def resolution_evidence(self, ip: str) -> list[Evidence]:
        """Provenance for the rename `actor()` just performed, if it did one.

        Spread into the evidence list at the call site, beside the `actor()`
        call it belongs to:

            subject=ctx.actor(src),
            evidence=[*self._evidence(score, artifacts), *ctx.resolution_evidence(src)],

        Empty when the address did not resolve, so the term is inert without an
        inventory and the ID of an unresolved finding is byte-identical to what
        it was before this method existed. An analyzer that names a host from
        telemetry rather than from an address never calls it and so cannot pick
        up a citation it did not rely on.

        A finding that names `host:FINANCE-WS04` asserts something no sensor
        said. `docs/roadmap.md` §6: a wrong mapping attaches a beacon to an
        innocent machine with full confidence and a clean chain of custody, so
        the chain has to carry the mapping itself — which file stated it, on
        which line, and how old the statement was when the traffic happened.
        """
        mapping = self.inventory.resolve(ip, self.capture)
        if mapping is None:
            return []
        # A caller-supplied `ip_to_host` entry overrides the file, and citing
        # a line that did not produce the name would be a false citation.
        if self.ip_to_host.get(mapping.address) != mapping.hostname:
            return []
        return [_resolution_evidence(mapping, self.capture)]

    def target(self, ip: str) -> Entity:
        """Represent a destination address, preferring an observed domain."""
        domain = self.ip_to_domain.get(ip)
        if domain:
            return Entity(type=EntityType.DOMAIN, value=domain)
        return Entity(type=EntityType.IP, value=ip)


@runtime_checkable
class Analyzer(Protocol):
    """The interface every detection component implements."""

    name: str
    version: str

    def analyze(self, ctx: AnalysisContext) -> list[Finding]: ...


class BaseAnalyzer:
    """Shared plumbing. Subclasses implement `analyze`."""

    name: str = "unnamed"
    version: str = "0.0.0"

    @property
    def qualname(self) -> str:
        """Stable identifier recorded on every Finding this analyzer emits.

        Version is part of it deliberately: when an algorithm changes, its
        findings must be distinguishable from those of the previous version
        in an archived report.
        """
        return f"{self.name}@{self.version}"

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError
