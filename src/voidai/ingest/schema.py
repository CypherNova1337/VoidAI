"""Normalised record schemas.

Every parser converts its native format into one of these frames. Analyzers
are written against the normalised schema and never against a vendor format,
so adding a new sensor means writing one parser, not touching any detection
logic.

Timestamps are stored as Float64 epoch seconds rather than as a Datetime
dtype. Interval statistics are the hot path of this system, and differencing
a float column is materially cheaper than differencing a temporal one on a
CPU-only target. Conversion to wall-clock time happens once, at the point an
Artifact is minted for display.
"""

from __future__ import annotations

import polars as pl

# Connection records (Zeek conn.log, Suricata flow, netflow)

CONNECTION_SCHEMA: dict[str, pl.DataType] = {
    "ts": pl.Float64,  # epoch seconds
    "uid": pl.Utf8,  # sensor's connection identifier
    "src_ip": pl.Utf8,
    "src_port": pl.Int32,
    "dst_ip": pl.Utf8,
    "dst_port": pl.Int32,
    "proto": pl.Utf8,
    "service": pl.Utf8,  # zeek's app-layer guess, may be null
    "duration": pl.Float64,
    "orig_bytes": pl.Int64,
    "resp_bytes": pl.Int64,
    "orig_pkts": pl.Int64,
    "resp_pkts": pl.Int64,
    "conn_state": pl.Utf8,
    "source_file": pl.Utf8,
    "source_line": pl.Int64,
}

# DNS records (Zeek dns.log, Suricata dns events)

DNS_SCHEMA: dict[str, pl.DataType] = {
    "ts": pl.Float64,
    "uid": pl.Utf8,
    "src_ip": pl.Utf8,
    "dst_ip": pl.Utf8,
    "query": pl.Utf8,
    "qtype": pl.Utf8,
    "rcode": pl.Utf8,
    "answers": pl.Utf8,  # joined with ';' — kept flat for cheap columnar ops
    "source_file": pl.Utf8,
    "source_line": pl.Int64,
}

# Alert records (Suricata EVE, Snort)

ALERT_SCHEMA: dict[str, pl.DataType] = {
    "ts": pl.Float64,
    "src_ip": pl.Utf8,
    "dst_ip": pl.Utf8,
    "dst_port": pl.Int32,
    "proto": pl.Utf8,
    "signature": pl.Utf8,
    "signature_id": pl.Int64,
    "category": pl.Utf8,
    "severity": pl.Int32,
    "source_file": pl.Utf8,
    "source_line": pl.Int64,
}


def empty(schema: dict[str, pl.DataType]) -> pl.DataFrame:
    """An empty frame with the correct dtypes.

    Analyzers must behave identically on an empty frame and on a frame that
    happened to filter down to nothing, so parsers return this rather than
    `None` when a source yields no usable records.
    """
    return pl.DataFrame(schema=schema)


def conform(frame: pl.DataFrame, schema: dict[str, pl.DataType]) -> pl.DataFrame:
    """Coerce a frame to a schema, filling absent columns with nulls.

    Real-world logs omit fields. A Zeek deployment with no `orig_pkts` should
    degrade one analyzer's confidence, not crash the pipeline.
    """
    exprs = []
    for name, dtype in schema.items():
        if name in frame.columns:
            exprs.append(pl.col(name).cast(dtype, strict=False).alias(name))
        else:
            exprs.append(pl.lit(None, dtype=dtype).alias(name))
    return frame.select(exprs)
