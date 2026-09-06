"""Suricata EVE JSON parser.

Suricata writes newline-delimited JSON with one object per event and the alert
detail nested under an `alert` key:

    {"timestamp":"2018-04-04T10:00:00.123456+0000","event_type":"alert",
     "src_ip":"10.0.0.5","dest_ip":"1.2.3.4","dest_port":80,"proto":"TCP",
     "alert":{"signature_id":2001234,"signature":"ET TROJAN Foo",
              "category":"A Network Trojan was detected","severity":1}}

Only `event_type: alert` records are read. An EVE stream also carries flow,
http, tls, dns and stats events — often the great majority of its volume —
and none of them belong in `ALERT_SCHEMA`.

Parsing goes through Polars' NDJSON reader with the nested struct unpacked by
expression rather than in Python, for the same reason as everywhere else here:
an EVE file from a busy sensor is measured in gigabytes per day.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

from voidai.ingest.schema import ALERT_SCHEMA, conform, empty

_ALERT_EVENT = "alert"

#: Suricata's ISO-8601 with a numeric offset and microseconds.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S%.f%z"


def _alert_field(name: str, dtype: pl.DataType, present: set[str]) -> pl.Expr:
    """Pull one field out of the nested `alert` object.

    Returns a typed null column when the field is absent, so a sensor with an
    older or trimmed EVE schema degrades one signal rather than failing the
    parse. `present` is the set of fields the file's `alert` objects actually
    carry: asking a struct for a field it does not have raises at collect time,
    which is a whole log lost over one missing key.
    """
    if name not in present:
        return pl.lit(None, dtype=dtype).alias(name)
    return pl.col("alert").struct.field(name).cast(dtype, strict=False).alias(name)


def scan_eve(path: str | Path) -> pl.LazyFrame:
    """Lazily scan a Suricata EVE JSON file into the normalised alert schema."""
    path = Path(path)

    scan = pl.scan_ndjson(path, ignore_errors=True).with_row_index(
        "source_line", offset=1
    )

    schema = scan.collect_schema()
    available = set(schema.names())
    if "alert" not in available:
        return pl.LazyFrame(schema=ALERT_SCHEMA)

    # `alert` is only a struct when the reader inferred one. A file whose alert
    # objects are all null, or a producer that writes the key as a string,
    # leaves nothing to take fields from.
    alert_dtype = schema["alert"]
    alert_fields = (
        {field.name for field in alert_dtype.fields}
        if isinstance(alert_dtype, pl.Struct)
        else set()
    )

    if "event_type" in available:
        scan = scan.filter(pl.col("event_type") == _ALERT_EVENT)

    def column(name: str, dtype: pl.DataType) -> pl.Expr:
        if name in available:
            return pl.col(name).cast(dtype, strict=False).alias(name)
        return pl.lit(None, dtype=dtype).alias(name)

    return scan.select(
        pl.col("timestamp")
        .str.to_datetime(format=_TIMESTAMP_FORMAT, strict=False)
        .dt.epoch(time_unit="ms")
        .cast(pl.Float64)
        .truediv(1000.0)
        .alias("ts"),
        column("src_ip", pl.Utf8),
        # Suricata writes `dest_ip`; the normalised schema says `dst_ip`.
        (
            pl.col("dest_ip").cast(pl.Utf8).alias("dst_ip")
            if "dest_ip" in available
            else pl.lit(None, dtype=pl.Utf8).alias("dst_ip")
        ),
        (
            pl.col("dest_port").cast(pl.Int32, strict=False).alias("dst_port")
            if "dest_port" in available
            else pl.lit(None, dtype=pl.Int32).alias("dst_port")
        ),
        column("proto", pl.Utf8),
        _alert_field("signature", pl.Utf8, alert_fields),
        _alert_field("signature_id", pl.Int64, alert_fields),
        _alert_field("category", pl.Utf8, alert_fields),
        _alert_field("severity", pl.Int32, alert_fields),
        pl.lit(str(path)).alias("source_file"),
        pl.col("source_line").cast(pl.Int64),
    ).filter(pl.col("ts").is_not_null() & pl.col("signature").is_not_null())


def _read_salvaging(path: Path) -> pl.DataFrame:
    """Re-read a file that the bulk parser rejected, keeping valid lines.

    A single unparseable line must not discard a whole log, and there is a
    routine way to get one: rotation truncates the final record mid-write.
    Filtering line by line is slower, so it runs only after the fast path has
    already failed.
    """
    import json

    valid: list[str] = []
    try:
        with path.open("r", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped.startswith("{"):
                    continue
                try:
                    json.loads(stripped)
                except ValueError:
                    continue
                valid.append(stripped)
    except OSError:
        return empty(ALERT_SCHEMA)

    if not valid:
        return empty(ALERT_SCHEMA)

    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        tmp.write("\n".join(valid))
        salvaged = Path(tmp.name)
    try:
        frame = scan_eve(salvaged).collect(engine="streaming")
    except pl.exceptions.PolarsError:
        return empty(ALERT_SCHEMA)
    finally:
        salvaged.unlink(missing_ok=True)

    if frame.is_empty():
        return empty(ALERT_SCHEMA)
    # The salvaged file's name is not the real one; restore it.
    return conform(
        frame.with_columns(pl.lit(str(path)).alias("source_file")), ALERT_SCHEMA
    ).sort("ts")


def read_eve(path: str | Path) -> pl.DataFrame:
    """Read a Suricata EVE JSON file in full.

    Falls back to a line-by-line salvage when the bulk reader rejects the
    file, so one corrupt record costs one record rather than the whole log.
    """
    path = Path(path)
    if not path.is_file():
        return empty(ALERT_SCHEMA)
    try:
        frame = scan_eve(path).collect(engine="streaming")
    except pl.exceptions.PolarsError:
        # Every parse failure polars can raise, not an enumerated few: this is
        # the boundary between a stranger's file and the pipeline, and the
        # contract here is that a bad file costs its own records and no more.
        return _read_salvaging(path)
    except FileNotFoundError:
        return empty(ALERT_SCHEMA)
    if frame.is_empty():
        return _read_salvaging(path)
    return conform(frame, ALERT_SCHEMA).sort("ts")


def load_alerts(directory: str | Path) -> pl.DataFrame:
    """Read every EVE JSON file under a directory."""
    directory = Path(directory)
    if not directory.is_dir():
        return empty(ALERT_SCHEMA)

    paths = sorted(
        p
        for pattern in ("eve*.json", "*.eve.json", "alerts*.json")
        for p in directory.rglob(pattern)
    )
    frames = [read_eve(p) for p in dict.fromkeys(paths)]
    frames = [f for f in frames if not f.is_empty()]
    if not frames:
        return empty(ALERT_SCHEMA)
    return pl.concat(frames, how="vertical").sort("ts")
