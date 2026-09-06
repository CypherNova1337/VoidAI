"""Sysmon process-creation parser: Windows host telemetry as JSON lines.

Sysmon's native output is EVTX, a binary format that needs a dissector. This
parser deliberately reads the *other* thing every collector in the world
already produces: the same events shipped as newline-delimited JSON, one
object per line, by Winlogbeat, NXLog, Fluent Bit, Elastic Agent or
`Get-WinEvent | ConvertTo-Json`. That is what the public corpora ship too.

The reason is engineering rule 9. JSON lines need no new dependency, so host
telemetry costs the core six packages exactly nothing. EVTX is a later branch
and belongs behind an extra, alongside `[llm]` and `[tui]`.

Only **event ID 1**, process creation, is read. Sysmon writes twenty-odd event
types and the two predicates this feeds — `executes_rare_process` and
`exhibits_anomalous_lineage` — are both statements about a process being
created. Reading the rest would cost memory to hold records nothing measures.

## Three details that decide whether the output is usable

**The event time is `UtcTime`, not `@timestamp`.** `@timestamp` is when the
*shipper* received the record, and on the corpus in `tests/data` it lags the
event by a median of 34 seconds and a maximum of 84. The correlator orders
behaviours with a one-second floor within a single source, so taking the
shipper's clock would not merely blur the ordering — it would invent one.
`UtcTime` is Sysmon's own millisecond stamp for the moment the process
started. `@timestamp` is used only when `UtcTime` is absent.

**Lines are pre-filtered before any JSON is parsed.** A collector writes every
channel into one stream, so a Sysmon process creation can be one line in two
hundred. Parsing all of them to discard 99% would build a frame with every key
any Windows event has ever carried. A cheap substring test on the provider
name cuts the stream first; the structured check that follows is what actually
decides, so the test only has to be a superset and never a filter that can
wrongly reject.

**`ParentImage` is null at the root of a tree.** A process whose parent
started before the capture window has no parent record. That is ordinary, not
a parse failure, and every join downstream keeps nulls rather than dropping
them.
"""

from __future__ import annotations

import gzip
import json
import zlib
from pathlib import Path

import polars as pl

from voidai.ingest.schema import PROCESS_SCHEMA, conform, empty

#: Every Sysmon record carries this as its provider. Used only to skip lines
#: cheaply before parsing; `_SYSMON_PROVIDERS` below is what decides.
_PROVIDER_HINT = "Microsoft-Windows-Sysmon"

#: Accepted spellings of the provider across collectors. Winlogbeat writes
#: `SourceName`, some pipelines write only `Channel`, and the two disagree on
#: whether the suffix is present.
_SYSMON_PROVIDERS = frozenset(
    {
        "microsoft-windows-sysmon",
        "microsoft-windows-sysmon/operational",
    }
)

#: Sysmon's process-creation event.
_PROCESS_CREATE = 1

#: Comment lines. Not part of any collector's output — they exist so a
#: committed fixture can carry its own licence and provenance in-band, the way
#: `tests/data/real.passivedns` does.
_COMMENT = "#"

#: Sysmon's own timestamp, in two spellings. Millisecond precision, UTC, and
#: written by the sensor rather than by whatever shipped the record.
_UTC_FORMATS = ("%Y-%m-%d %H:%M:%S%.3f", "%Y-%m-%d %H:%M:%S")

#: Source field → normalised column. Collectors differ in casing but not in
#: spelling; the lookup below is case-insensitive.
_FIELDS: dict[str, str] = {
    "hostname": "host",
    "computer": "host",
    "user": "user",
    "image": "image",
    "commandline": "command_line",
    "currentdirectory": "current_directory",
    "integritylevel": "integrity_level",
    "processguid": "process_guid",
    "processid": "process_id",
    "parentimage": "parent_image",
    "parentcommandline": "parent_command_line",
    "parentprocessguid": "parent_guid",
    "parentprocessid": "parent_process_id",
}


def _open_text(path: Path) -> str:
    """Read a log, transparently decompressing `.gz`.

    Same contract as `zeek._open_text`, including that a `.gz` which cannot be
    decompressed yields no records instead of raising. Committed fixtures are
    gzipped because a JSON-lines process log is mostly repeated key names and
    compresses by a factor of twelve.
    """
    if path.suffix == ".gz":
        try:
            with gzip.open(path, "rt", errors="replace") as handle:
                return handle.read()
        except (OSError, EOFError, zlib.error):
            return ""
    return path.read_text(errors="replace")


def _sha256(hashes: object) -> str | None:
    """Pull SHA256 out of Sysmon's combined hash field.

    Written as `SHA1=…,MD5=…,SHA256=…,IMPHASH=…`, in an order that depends on
    the sensor's configured `HashAlgorithms`. Split rather than sliced, so a
    configuration that omits SHA256 yields null instead of another algorithm's
    digest under the wrong name.
    """
    if not isinstance(hashes, str):
        return None
    for part in hashes.split(","):
        name, _, value = part.partition("=")
        if name.strip().upper() == "SHA256" and value.strip():
            return value.strip()
    return None


def _is_process_create(record: dict[str, object]) -> bool:
    """Decide whether a parsed record is a Sysmon process creation.

    The provider is checked as well as the event ID: `EventID` 1 means
    something different in every other Windows channel, and a collector that
    merges channels into one file will offer plenty of them.
    """
    event_id = record.get("EventID")
    if isinstance(event_id, str):
        event_id = event_id.strip()
        event_id = int(event_id) if event_id.isdigit() else None
    if event_id != _PROCESS_CREATE:
        return False

    for key in ("SourceName", "Channel", "provider", "Provider"):
        value = record.get(key)
        if isinstance(value, str) and value.strip().lower() in _SYSMON_PROVIDERS:
            return True
    return False


def _row(record: dict[str, object], path: Path, line_number: int) -> dict[str, object]:
    """Flatten one Sysmon record onto the normalised schema.

    Field names are matched case-insensitively because collectors disagree:
    Winlogbeat preserves Sysmon's own PascalCase, Elastic's ECS pipeline
    lowercases, and NXLog does either depending on its configuration.
    """
    row: dict[str, object] = {
        "ts": None,
        "sha256": None,
        "source_file": str(path),
        "source_line": line_number,
    }
    for key, value in record.items():
        column = _FIELDS.get(key.lower())
        if column is not None and row.get(column) is None:
            row[column] = value
        elif key.lower() == "hashes":
            row["sha256"] = _sha256(value)

    row["utc_time"] = record.get("UtcTime") or record.get("utctime")
    row["shipper_time"] = record.get("@timestamp") or record.get("timestamp")
    return row


def read_sysmon(path: str | Path) -> pl.DataFrame:
    """Parse one Sysmon JSON-lines log into the normalised process schema.

    Returns an empty frame — never raises — for an unreadable file, a file of
    other event types, or a file that is not JSON at all. A capture directory
    is allowed to contain anything, and one unparseable file must not take the
    run down with it.
    """
    path = Path(path)
    try:
        text = _open_text(path)
    except OSError:
        return empty(PROCESS_SCHEMA)

    rows: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(_COMMENT):
            continue
        # The superset test. Cheap, and never the thing that rejects a record.
        if _PROVIDER_HINT not in stripped:
            continue
        try:
            record = json.loads(stripped)
        except ValueError:
            continue
        if not isinstance(record, dict) or not _is_process_create(record):
            continue
        rows.append(_row(record, path, line_number))

    if not rows:
        return empty(PROCESS_SCHEMA)

    frame = pl.DataFrame(rows, infer_schema_length=None)
    return conform(frame.with_columns(_timestamp(frame)), PROCESS_SCHEMA).sort("ts")


def _timestamp(frame: pl.DataFrame) -> pl.Expr:
    """Sysmon's own clock, falling back to the shipper's only if it must.

    See the module docstring: on the committed corpus the shipper's stamp lags
    the event by a median of 34 seconds. Every format is tried non-strictly
    and the first that parses wins, so a sensor writing whole seconds is read
    the same as one writing milliseconds.
    """
    # Cast before parsing. A column every record left absent infers as Null,
    # not as an empty string column, and the string parser rejects that dtype
    # outright rather than yielding nulls — so a collector that writes only
    # `UtcTime` would take the whole read down.
    candidates: list[pl.Expr] = []
    if "utc_time" in frame.columns:
        candidates += [
            pl.col("utc_time").cast(pl.Utf8).str.to_datetime(fmt, strict=False, time_zone="UTC")
            for fmt in _UTC_FORMATS
        ]
    if "shipper_time" in frame.columns:
        candidates.append(
            pl.col("shipper_time").cast(pl.Utf8).str.to_datetime(strict=False, time_zone="UTC")
        )
    if not candidates:
        return pl.lit(None, dtype=pl.Float64).alias("ts")

    return (pl.coalesce(candidates).dt.epoch("ms") / 1000.0).alias("ts")


#: Filename patterns searched for host telemetry. Deliberately narrow: `eve*.json`
#: belongs to Suricata and a directory holding both must not have one read as
#: the other.
_PATTERNS = (
    "sysmon*.json",
    "sysmon*.jsonl",
    "*.sysmon.json",
    "*.sysmon.jsonl",
    "*.sysmon.json.gz",
    "*.sysmon.jsonl.gz",
    "sysmon*.json.gz",
    "sysmon*.jsonl.gz",
)


def load_processes(directory: str | Path) -> pl.DataFrame:
    """Read every Sysmon JSON-lines log under a directory."""
    directory = Path(directory)
    if not directory.is_dir():
        return empty(PROCESS_SCHEMA)

    paths = sorted(p for pattern in _PATTERNS for p in directory.rglob(pattern) if p.is_file())
    frames = [read_sysmon(p) for p in dict.fromkeys(paths)]
    frames = [f for f in frames if not f.is_empty()]
    if not frames:
        return empty(PROCESS_SCHEMA)
    return pl.concat(frames, how="vertical").sort("ts")
