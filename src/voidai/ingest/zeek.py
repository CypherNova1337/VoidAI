"""Zeek log parsers.

Zeek emits either tab-separated logs with a `#fields` header or newline-
delimited JSON, depending on deployment. Both are common in the wild, so both
are supported and auto-detected.

Parsing is delegated to Polars' native readers, which are multi-threaded and
release the GIL. On a Pi 5 this is the difference between a pipeline that
keeps up with a live sensor and one that does not.
"""

from __future__ import annotations

import gzip
import io
from pathlib import Path

import polars as pl

from voidai.ingest.schema import (
    CONNECTION_SCHEMA,
    DNS_SCHEMA,
    conform,
    empty,
)

_UNSET = "-"  # Zeek's null token in TSV mode


def _open_text(path: Path) -> io.StringIO:
    """Read a log, transparently decompressing .gz."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="replace") as fh:
            return io.StringIO(fh.read())
    return io.StringIO(path.read_text(errors="replace"))


def _is_json(sample: str) -> bool:
    for line in sample.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        return stripped.startswith("{")
    return False


def _tsv_field_names(text: str) -> list[str] | None:
    """Extract column names from Zeek's `#fields` header line."""
    for line in text.splitlines():
        if line.startswith("#fields"):
            return line.split("\t")[1:]
        if not line.startswith("#"):
            break
    return None


def _read_zeek(path: Path) -> pl.DataFrame:
    """Read a Zeek log into a raw frame, TSV or JSON, with source line numbers."""
    buffer = _open_text(path)
    text = buffer.getvalue()
    if not text.strip():
        return pl.DataFrame()

    if _is_json(text):
        frame = pl.read_ndjson(io.StringIO(text), ignore_errors=True)
        # NDJSON has no comment lines, so record index maps directly to line.
        return frame.with_row_index("source_line", offset=1)

    names = _tsv_field_names(text)
    if names is None:
        return pl.DataFrame()

    # Track true file line numbers so an Artifact locator points at the real
    # line, not at an index into the comment-stripped subset.
    data_lines: list[str] = []
    line_numbers: list[int] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#") or not line.strip():
            continue
        data_lines.append(line)
        line_numbers.append(number)

    if not data_lines:
        return pl.DataFrame()

    frame = pl.read_csv(
        io.StringIO("\n".join(data_lines)),
        separator="\t",
        has_header=False,
        new_columns=names,
        null_values=[_UNSET],
        infer_schema_length=10_000,
        truncate_ragged_lines=True,
    )
    return frame.with_columns(pl.Series("source_line", line_numbers, dtype=pl.Int64))


def read_conn_log(path: str | Path) -> pl.DataFrame:
    """Parse a Zeek `conn.log` into the normalised connection schema."""
    path = Path(path)
    frame = _read_zeek(path)
    if frame.is_empty():
        return empty(CONNECTION_SCHEMA)

    renames = {
        "id.orig_h": "src_ip",
        "id.orig_p": "src_port",
        "id.resp_h": "dst_ip",
        "id.resp_p": "dst_port",
    }
    frame = frame.rename({k: v for k, v in renames.items() if k in frame.columns})
    frame = frame.with_columns(pl.lit(str(path)).alias("source_file"))
    return conform(frame, CONNECTION_SCHEMA)


def read_dns_log(path: str | Path) -> pl.DataFrame:
    """Parse a Zeek `dns.log` into the normalised DNS schema."""
    path = Path(path)
    frame = _read_zeek(path)
    if frame.is_empty():
        return empty(DNS_SCHEMA)

    renames = {
        "id.orig_h": "src_ip",
        "id.resp_h": "dst_ip",
    }
    frame = frame.rename({k: v for k, v in renames.items() if k in frame.columns})

    if "answers" in frame.columns and frame.schema["answers"] == pl.List(pl.Utf8):
        frame = frame.with_columns(pl.col("answers").list.join(";"))

    frame = frame.with_columns(pl.lit(str(path)).alias("source_file"))
    return conform(frame, DNS_SCHEMA)


def discover(directory: str | Path) -> dict[str, list[Path]]:
    """Find Zeek logs in a directory, grouped by log type.

    Handles both live output (`conn.log`) and rotated archives
    (`conn.14:00:00-15:00:00.log.gz`).
    """
    directory = Path(directory)
    groups: dict[str, list[Path]] = {}
    if not directory.is_dir():
        return groups

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        name = path.name
        if ".log" not in name:
            continue
        kind = name.split(".", 1)[0]
        groups.setdefault(kind, []).append(path)
    return groups


def load_connections(directory: str | Path) -> pl.DataFrame:
    """Load and concatenate every conn log found under a directory."""
    frames = [read_conn_log(p) for p in discover(directory).get("conn", [])]
    frames = [f for f in frames if not f.is_empty()]
    if not frames:
        return empty(CONNECTION_SCHEMA)
    return pl.concat(frames, how="vertical").sort("ts")


def load_dns(directory: str | Path) -> pl.DataFrame:
    """Load and concatenate every DNS log found under a directory."""
    frames = [read_dns_log(p) for p in discover(directory).get("dns", [])]
    frames = [f for f in frames if not f.is_empty()]
    if not frames:
        return empty(DNS_SCHEMA)
    return pl.concat(frames, how="vertical").sort("ts")
