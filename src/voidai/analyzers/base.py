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

from voidai.ingest.schema import (
    ALERT_SCHEMA,
    CONNECTION_SCHEMA,
    DNS_SCHEMA,
    empty,
)
from voidai.lexicon import Entity, EntityType, Finding


@dataclass
class AnalysisContext:
    """Everything an analyzer is allowed to look at.

    Passing one context to every analyzer, rather than letting each reach for
    files itself, keeps ingestion cost paid once and makes the data an
    analyzer saw reproducible from the context alone.
    """

    connections: pl.DataFrame = field(default_factory=lambda: empty(CONNECTION_SCHEMA))
    dns: pl.DataFrame = field(default_factory=lambda: empty(DNS_SCHEMA))
    alerts: pl.DataFrame = field(default_factory=lambda: empty(ALERT_SCHEMA))

    #: Reverse-resolution built from observed DNS answers: ip -> domain.
    ip_to_domain: dict[str, str] = field(default_factory=dict)
    #: Optional asset inventory: ip -> hostname.
    ip_to_host: dict[str, str] = field(default_factory=dict)

    def record_count(self) -> int:
        return len(self.connections) + len(self.dns) + len(self.alerts)

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
