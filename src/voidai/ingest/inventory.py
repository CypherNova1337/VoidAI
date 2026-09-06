"""Local asset inventory files.

An inventory answers one question: which machine held this address. Nothing
here derives that answer — not from DHCP leases, not from reverse DNS, not
from traffic. An inventory is a file an operator wrote, read from disk and
from nowhere else, exactly like `voidai.ingest.ioc` and for the same reason
(`docs/roadmap.md` rule 11).

## What it is for

`AnalysisContext.actor()` names the subject of a network finding. Without an
inventory the best it can say is `ip:10.0.1.14`; with one it says
`host:FINANCE-WS04`, which is the same claim made more precisely — and, more
usefully, it is the *same subject* the endpoint agent already reports, so
network and host evidence land on one row of the queue instead of two.

## The format

Newline-delimited text, one mapping per line, with an optional metadata
header. Deliberately the same shape as an `.ioc` file, because an operator who
can write one can write the other:

    # name: corp-asset-register
    # source: netbox export
    # updated: 2025-06-10
    # reference: https://netbox.internal/dcim/
    # tlp: amber

    10.0.1.14   FINANCE-WS04   stated=2025-06-10  note=static lease
    10.0.1.20   HR-WS02

`# key: value` lines *before the first mapping* configure the register. After
that point a `#` line is an ordinary comment, so an operator annotating a
block halfway down cannot silently restate the provenance of everything above
it.

## Why every mapping carries a date

`docs/roadmap.md` §6: *a wrong mapping is worse than none*. An inventory that
names the wrong machine attaches a beacon to an innocent host with full
confidence and a clean chain of custody, which is the one failure this project
cannot tolerate — a citation is the thing an analyst is least likely to
re-check.

DHCP is what makes that failure ordinary rather than exotic. An address is not
a machine; it is a lease, and a lease that expired between the statement and
the capture points at somebody else. So a mapping is scored by *when it was
stated relative to the traffic it is being applied to*, and both numbers reach
the evidence payload:

  * stated within `STALE_AFTER_DAYS` of the capture — applied, unremarked.
  * stated earlier than that — applied, and flagged `stale` with its age, so
    an analyst reading the finding knows the name is an assertion of record
    rather than an observation.
  * stated more than `MAX_AGE_DAYS` before the capture — **not applied at
    all**, and reported as dropped. This mirrors the 730-day floor in
    `docs/ioc.md`: past some age a record is not weak evidence, it is a
    different estate.
  * stated *after* the capture ended — applied, and flagged. This is the
    sharper case and the easiest to miss: an inventory exported last week says
    nothing reliable about who held that address six months ago, and without
    the flag it resolves silently and confidently in exactly the direction a
    reader will not question.
  * undated — applied, and flagged `undated`. As in `ioc.py`, an unknown date
    is not a recent one; what it costs here is the flag, because unlike a
    confidence score there is nothing to decay.

Nothing about the observed traffic enters any of this. An address seen four
thousand times and an address seen once resolve identically, or the inventory
would be inferring mappings from data, which is the piece of work this module
is deliberately not.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from voidai.ingest.ioc import parse_date
from voidai.lexicon.models import Artifact, Evidence

#: Files read by `load_inventory`. One extension, deliberately: the same
#: opt-in rule `.ioc` uses, so a directory of telemetry cannot have the
#: operator's notes parsed as an asset register.
INVENTORY_SUFFIX = ".inv"

#: A mapping stated more than this many days before the capture is flagged.
#: Roughly a quarter — long enough that a static estate is not nagged about,
#: short enough that a DHCP lease will have turned over inside it.
STALE_AFTER_DAYS = 90

#: A mapping stated more than this many days before the capture is not applied
#: at all. The same horizon `docs/ioc.md` puts on an indicator, for the same
#: reason: past two years the record describes a different estate.
MAX_AGE_DAYS = 730

_HEADER = re.compile(r"^#\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.+?)\s*$")
_ATTRIBUTE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)=(.*)$")

#: One hostname label, RFC-1123, with `_` tolerated: Windows NetBIOS names
#: reach an asset register with underscores in them more often than anyone
#: would like, and rejecting the line would lose the mapping over a character
#: that cannot change which machine is meant.
_LABEL = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


@dataclass(frozen=True)
class CaptureWindow:
    """When the telemetry being analysed was recorded.

    Age is measured against the capture and never against the clock — the same
    rule `docs/ioc.md` states for indicator age, and for the same second
    reason: every ID in the Lexicon is content-addressed, so an age derived
    from `datetime.now()` would give the same run a different evidence ID
    every day and last week's citations would resolve to nothing.
    """

    start: date | None = None
    end: date | None = None

    @property
    def known(self) -> bool:
        return self.start is not None

    @classmethod
    def from_epochs(cls, first: float | None, last: float | None) -> CaptureWindow:
        return cls(start=_utc_date(first), end=_utc_date(last))


def _utc_date(epoch: float | None) -> date | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).date()
    except (OverflowError, OSError, ValueError):
        return None


@dataclass(frozen=True)
class Register:
    """One inventory file and what it declares about itself."""

    name: str
    path: str
    #: When the register was last reconciled. The fallback date for a mapping
    #: carrying no `stated=` of its own.
    updated: date | None = None
    reference: str | None = None
    tlp: str | None = None
    #: Header keys this module does not interpret, kept for the receipt.
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def dated(self) -> bool:
        return self.updated is not None


@dataclass(frozen=True)
class Mapping:
    """One address-to-hostname statement, with everything needed to judge it."""

    address: str
    hostname: str
    register: Register
    #: When this mapping was stated, from `stated=` or the register's
    #: `updated:`. `None` is an *unknown* date, never an implied recent one.
    stated: date | None = None
    note: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)
    source_file: str = ""
    source_line: int = 0
    #: The line as the operator wrote it. Carried so the evidence artifact can
    #: quote the statement rather than paraphrase it.
    source_text: str = ""

    def age_days(self, window: CaptureWindow) -> int | None:
        """Days between the statement and the start of the capture.

        Positive means the mapping predates the traffic, which is the ordinary
        case. Negative means it was stated afterwards. `None` means one of the
        two dates is unknown and no age can be computed.
        """
        if self.stated is None or window.start is None:
            return None
        return (window.start - self.stated).days

    def staleness(self, window: CaptureWindow) -> str:
        """How much this mapping's date lets it be trusted, in one word.

        Reported verbatim in the evidence payload, so the judgement an analyst
        would have to make is made in the open and recorded rather than
        implied by whether a name appeared.
        """
        if self.stated is None:
            return "undated"
        if window.start is None:
            return "unknown_window"
        age = self.age_days(window)
        assert age is not None  # both dates present
        if window.end is not None and self.stated > window.end:
            return "stated_after_capture"
        if age > MAX_AGE_DAYS:
            return "expired"
        if age > STALE_AFTER_DAYS:
            return "stale"
        return "current"

    def applies(self, window: CaptureWindow) -> bool:
        """Whether this mapping may rename anything at all."""
        return self.staleness(window) != "expired"


@dataclass(frozen=True)
class Coverage:
    """How much of the estate the inventory actually accounts for.

    A count of mappings answers the wrong question. An inventory of four
    hundred machines against a capture from a segment holding six of them has
    covered six, and an inventory of three against a segment of a hundred is a
    rounding error dressed as an improvement — `docs/roadmap.md` §6.
    """

    loaded: int = 0
    applied: int = 0
    dropped: int = 0
    observed: int = 0
    matched: int = 0

    @property
    def fraction(self) -> float:
        return self.matched / self.observed if self.observed else 0.0

    def summary(self) -> str:
        if not self.loaded:
            return "no mappings"
        head = f"{self.applied} of {self.loaded} mapping(s) applied"
        if self.dropped:
            head += f", {self.dropped} dropped as expired"
        if not self.observed:
            return head
        return f"{head} — resolved {self.matched} of {self.observed} observed address(es) ({self.fraction:.1%})"


class Inventory:
    """Every mapping from every loaded register, indexed by address.

    Lookup is exact and by address only. There is no prefix walk and no
    parent-network fallback: `10.0.1.0/24 -> FINANCE` would name a subnet, and
    a finding that asserts a beacon came from an entire floor is worse than
    one that admits it knows only the address.
    """

    def __init__(self) -> None:
        self.registers: list[Register] = []
        self.by_address: dict[str, Mapping] = {}
        #: Lines that were not a plausible mapping, as (file, line, text).
        self.rejected: list[tuple[str, int, str]] = []

    def __len__(self) -> int:
        return len(self.by_address)

    def is_empty(self) -> bool:
        return not self.by_address

    def add(self, mapping: Mapping) -> None:
        """Index one mapping, keeping the statement that can be trusted more.

        Two registers naming one address is the normal case once an estate has
        more than one source of truth. Rule 12 applies even though nothing is
        being ranked for display: with no tiebreaker the winner would depend on
        directory iteration order, and a finding's subject — and therefore its
        content-addressed ID — would change between runs over one capture.
        """
        existing = self.by_address.get(mapping.address)
        if existing is None or _outranks(mapping, existing):
            self.by_address[mapping.address] = mapping

    def resolve(self, address: str, window: CaptureWindow) -> Mapping | None:
        """The mapping for one address, or `None` if there is none to apply."""
        try:
            canonical = str(ipaddress.ip_address(address.strip()))
        except ValueError:
            return None
        mapping = self.by_address.get(canonical)
        if mapping is None or not mapping.applies(window):
            return None
        return mapping

    def applied(self, window: CaptureWindow) -> dict[str, str]:
        """Address to hostname, for every mapping this window permits.

        What `AnalysisContext.ip_to_host` is populated from. A mapping too old
        to apply is absent here rather than present and marked, because
        `actor()` reads a name or it does not — there is no third thing it
        could do with a mapping it has been told not to trust.
        """
        return {
            address: mapping.hostname
            for address, mapping in self.by_address.items()
            if mapping.applies(window)
        }

    def coverage(self, window: CaptureWindow, observed: set[str] | None = None) -> Coverage:
        """What loaded, what applies, and how much of the estate it reaches."""
        applied = self.applied(window)
        addresses = observed or set()
        return Coverage(
            loaded=len(self.by_address),
            applied=len(applied),
            dropped=len(self.by_address) - len(applied),
            observed=len(addresses),
            matched=sum(1 for address in addresses if address in applied),
        )

    def flagged(self, window: CaptureWindow) -> list[tuple[Mapping, str]]:
        """Every mapping whose date is worth an operator's attention.

        Sorted by address so the report is stable between runs.
        """
        return sorted(
            (
                (mapping, mapping.staleness(window))
                for mapping in self.by_address.values()
                if mapping.staleness(window) != "current"
            ),
            key=lambda pair: pair[0].address,
        )


def _outranks(candidate: Mapping, incumbent: Mapping) -> bool:
    """Whether a duplicate should replace the mapping already indexed.

    A total order, and every comparison is on content rather than on load
    order: more recently stated wins, a dated statement beats an undated one,
    and two statements that are genuinely indistinguishable by date fall back
    to the file and line they were written on, which no two mappings share.
    """
    if (candidate.stated is None) != (incumbent.stated is None):
        return incumbent.stated is None
    if (
        candidate.stated is not None
        and incumbent.stated is not None
        and candidate.stated != incumbent.stated
    ):
        return candidate.stated > incumbent.stated
    if candidate.source_file != incumbent.source_file:
        return candidate.source_file < incumbent.source_file
    return candidate.source_line < incumbent.source_line


def _valid_hostname(text: str) -> bool:
    """Whether a token can be a machine name.

    Not a domain check: a bare NetBIOS name is one label and is the normal
    thing to find in an asset register, so unlike `ioc.classify` a single
    label is accepted here. What is rejected is anything that would make the
    resulting `host:` entity meaningless — an empty name, a `#`, or something
    that is plainly a second address.
    """
    hostname = text.strip().rstrip(".")
    if not hostname or len(hostname) > 255:
        return False
    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass
    return all(_LABEL.match(label) for label in hostname.split("."))


def read_inventory_file(
    path: str | Path,
) -> tuple[Register, list[Mapping], list[tuple[str, int, str]]]:
    """Parse one `.inv` file into its register, its mappings and its rejects.

    Never raises on content. A malformed line is a rejected line: an operator
    who fat-fingered one entry of four hundred should get the other three
    hundred and ninety-nine and a report of the one, not a stack trace in the
    middle of an incident.
    """
    path = Path(path)
    header: dict[str, str] = {}
    rows: list[tuple[str, str, int, dict[str, str], str]] = []
    rejected: list[tuple[str, int, str]] = []
    in_header = True

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Register(name=path.stem, path=str(path)), [], []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            match = _HEADER.match(line)
            if in_header and match:
                header[match.group(1).lower()] = match.group(2)
            continue

        in_header = False
        tokens = line.split()
        if len(tokens) < 2:
            # An address with no name is not half a mapping, it is a typo.
            rejected.append((str(path), number, line))
            continue

        address, hostname = tokens[0], tokens[1]
        attributes: dict[str, str] = {}
        for token in tokens[2:]:
            attribute = _ATTRIBUTE.match(token)
            if attribute:
                attributes[attribute.group(1).lower()] = attribute.group(2)
            elif "note" in attributes:
                # A bare trailing word continues the previous `note=`, which is
                # how a human writes one. Anything before a note is discarded.
                attributes["note"] = f"{attributes['note']} {token}".strip()
        rows.append((address, hostname, number, attributes, line))

    register = _register_from_header(path, header)
    mappings: list[Mapping] = []
    for address, hostname, number, attributes, raw_line in rows:
        try:
            canonical = str(ipaddress.ip_address(address.strip()))
        except ValueError:
            # The whole line, not the token that failed: an operator reading
            # the report needs to recognise what they wrote.
            rejected.append((str(path), number, raw_line))
            continue
        if not _valid_hostname(hostname):
            rejected.append((str(path), number, raw_line))
            continue

        mappings.append(
            Mapping(
                address=canonical,
                hostname=hostname.strip().rstrip("."),
                register=register,
                stated=parse_date(attributes.get("stated") or attributes.get("first_seen") or "")
                or register.updated,
                note=attributes.get("note"),
                attributes={
                    key: value
                    for key, value in attributes.items()
                    if key not in {"stated", "first_seen", "note"}
                },
                source_file=str(path),
                source_line=number,
                source_text=raw_line,
            )
        )

    return register, mappings, rejected


def _register_from_header(path: Path, header: dict[str, str]) -> Register:
    known = {"name", "updated", "reference", "source", "tlp"}
    return Register(
        name=header.get("name") or path.stem,
        path=str(path),
        updated=parse_date(header.get("updated") or header.get("date") or ""),
        reference=header.get("reference") or header.get("source"),
        tlp=header.get("tlp"),
        metadata={key: value for key, value in header.items() if key not in known},
    )


def load_inventory(source: str | Path) -> Inventory:
    """Load every `.inv` file under a directory, or one file directly.

    Reads from disk and from nowhere else. A missing path yields an empty
    inventory rather than an error: an inventory is optional, and a run
    without one names its subjects by address, which is what every run did
    before this module existed.
    """
    path = Path(source)
    inventory = Inventory()

    if path.is_file():
        paths = [path]
    elif path.is_dir():
        paths = sorted(p for p in path.rglob(f"*{INVENTORY_SUFFIX}") if p.is_file())
    else:
        return inventory

    for inventory_path in paths:
        register, mappings, rejected = read_inventory_file(inventory_path)
        inventory.registers.append(register)
        inventory.rejected.extend(rejected)
        for mapping in mappings:
            inventory.add(mapping)

    return inventory


def resolution_evidence(mapping: Mapping, window: CaptureWindow) -> Evidence:
    """The provenance of one resolution, as a link in the chain of custody.

    A finding that names `host:FINANCE-WS04` rather than `ip:10.0.1.14` is
    asserting something the telemetry did not say, and this is the artifact
    that says who did say it and when. The locator is a file and a line an
    analyst can open; the excerpt is the statement as the operator wrote it.
    """
    staleness = mapping.staleness(window)
    age = mapping.age_days(window)
    summary = f"{mapping.address} is {mapping.hostname}, per {mapping.register.name}"
    if mapping.stated is None:
        summary += " (undated)"
    elif age is None:
        summary += f" (stated {mapping.stated.isoformat()})"
    elif age >= 0:
        summary += f" (stated {mapping.stated.isoformat()}, {age}d before the capture)"
    else:
        summary += f" (stated {mapping.stated.isoformat()}, {-age}d after the capture began)"
    if staleness not in {"current", "unknown_window"}:
        summary += f" — {staleness.replace('_', ' ')}"

    payload: dict[str, object] = {
        "address": mapping.address,
        "hostname": mapping.hostname,
        # The file itself is the artifact below, not a payload field: the
        # locator an analyst opens belongs in the chain of custody, and
        # repeating it here would only make the payload machine-specific.
        "register": mapping.register.name,
        "stated_on": mapping.stated.isoformat() if mapping.stated else None,
        "capture_start": window.start.isoformat() if window.start else None,
        "age_days": age,
        "staleness": staleness,
    }
    if mapping.register.reference:
        payload["reference"] = mapping.register.reference
    if mapping.register.tlp:
        payload["tlp"] = mapping.register.tlp
    if mapping.note:
        payload["note"] = mapping.note
    if mapping.attributes:
        payload["attributes"] = dict(sorted(mapping.attributes.items()))

    return Evidence(
        kind="asset_inventory",
        summary=summary,
        payload=payload,
        artifacts=[
            Artifact(
                source=mapping.source_file,
                locator=f"line:{mapping.source_line}",
                excerpt=mapping.source_text or None,
            )
        ],
    )
