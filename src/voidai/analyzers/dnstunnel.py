"""DNS tunnelling detection.

DNS is the one protocol that leaves almost every network unfiltered, which
makes it the obvious carrier for a covert channel. Tools like iodine, dnscat2
and the Cobalt Strike DNS beacon encode payload bytes into subdomain labels
under a zone the attacker controls, and read the reply out of the answer.

The traffic is unmistakable once you measure the right things:

    label entropy         encoded bytes approach the ~4.7 bits/char of base32;
                          real hostnames sit near 3.2
    subdomain cardinality a tunnel mints a fresh name per packet
    query length          tunnels fill the 253-character budget
    qtype skew            TXT and NULL carry more bytes than A

Entropy is weighted highest because it is the one signal benign
high-cardinality DNS does not produce. Content delivery networks generate
thousands of subdomains, but structured ones. The genuinely hard false
positive is reputation lookups — antivirus and spam-blocklist queries encode
hashes and reversed addresses into subdomains and look tunnel-shaped by every
measure except entropy, which stays low because they are hex or decimal rather
than base32.

Unlike the beaconing analyzer, this one has **not** been validated against a
real capture. The CTU-13 corpus is NetFlow and carries no query names, and no
comparable labelled DNS-tunnelling corpus was available. Everything below is
measured against synthesised traffic modelled on published tool behaviour, and
that distinction is recorded in docs/benchmarks.md rather than glossed.

No language model is involved at any point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.statistics import saturating, shannon_entropy, weighted_geometric_mean
from voidai.lexicon import Artifact, Entity, EntityType, Evidence, Finding, Predicate, Severity

_WEIGHTS = {
    "label_entropy": 0.40,
    "subdomain_cardinality": 0.25,
    "query_length": 0.25,
    "qtype_skew": 0.10,
}

#: Multi-part public suffixes common enough to matter. A full Public Suffix
#: List would be more correct, but it is a network-fetched, frequently-updated
#: dataset, and this project does not fetch anything at runtime. Getting the
#: registered domain slightly wrong splits or merges a few zones; it does not
#: change whether the traffic under them is entropic.
_MULTIPART_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "co.za", "co.jp", "ne.jp", "or.jp",
        "com.br", "com.cn", "com.mx", "com.tr", "co.in",
    }
)

#: Query types that carry more payload than an A record, and so are favoured
#: by tunnelling tools.
_HIGH_CAPACITY_QTYPES = frozenset({"TXT", "NULL", "CNAME", "MX", "SRV", "10", "16"})


def registered_domain(name: str) -> str:
    """Reduce a query name to the zone it belongs to.

    `a1b2c3.tunnel.example.com` becomes `example.com`, which is the unit an
    operator blocks and the unit this analyzer scores.
    """
    labels = [label for label in name.strip(".").lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTIPART_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def registered_domain_expr(column: str = "query") -> pl.Expr:
    """`registered_domain` as a Polars expression, over a column of names.

    Same rule, same suffix table, no Python call per row, and it keeps the
    reduction inside the columnar path where the DGA analyzer needs it over
    every query in a capture.

    Worth knowing what it is *not* worth: replacing `map_elements` with this
    moved a 1.1M-record run from 32k to 34k records/second, which is noise.
    The interpreter call per row was the obvious suspect and was not the
    bottleneck — that turned out to be scalar `np.clip` and an uncached
    character model, both in `tlsdga.py`, together worth 32k to 60k. The
    expression stays because it is the right shape for a streaming pass, not
    because it bought the speed.

    Kept here, beside the function it mirrors, so the two cannot drift onto
    different suffix tables. `test_dnstunnel.py` asserts they agree, over the
    real capture as well as the edge cases.
    """
    labels = pl.col(column).str.strip_chars(".").str.to_lowercase().str.split(".")
    count = labels.list.len()
    last_two = labels.list.slice(-2).list.join(".")
    last_three = labels.list.slice(-3).list.join(".")
    return (
        pl.when(count <= 2)
        .then(labels.list.join("."))
        .when((count >= 3) & last_two.is_in(list(_MULTIPART_SUFFIXES)))
        .then(last_three)
        .otherwise(last_two)
    )


def subdomain_of(name: str, zone: str) -> str:
    """The part of a query name left of its zone, with dots removed.

    Dots are stripped so entropy is measured over the encoded payload as one
    string. A tunnel that chunks its data across several short labels would
    otherwise score lower than one using a single long label, which is a
    property of the encoder's framing rather than of the channel.
    """
    # removesuffix rather than a slice: an empty zone makes `[:-len(zone)]`
    # into `[:0]`, which silently returns nothing instead of the whole name.
    return name.strip(".").lower().removesuffix(zone).replace(".", "")


@dataclass(frozen=True)
class DnsTunnelConfig:
    """Tunables, set from the separation between encoded and natural names."""

    min_queries: int = 50
    min_distinct_subdomains: int = 30
    #: Subdomains shorter than this give an unstable entropy estimate — a
    #: five-character label cannot exceed 2.3 bits however random it is.
    min_subdomain_length: int = 8

    #: Entropy in bits/char at which the score reaches 0 and 1. Natural
    #: hostnames measure ~3.2; base32-encoded payload ~4.6.
    entropy_floor: float = 3.2
    entropy_ceiling: float = 4.6

    #: Distinct subdomains at which cardinality is well-established.
    strong_cardinality: int = 200
    #: Mean subdomain length at which the length score is well-established.
    strong_length: int = 40

    score_threshold: float = 0.62
    critical_threshold: float = 0.85

    max_findings: int = 200
    artifact_samples: int = 5


@dataclass
class DnsTunnelScore:
    """The measurement for one (source, zone) pair."""

    score: float
    components: dict[str, float]
    queries: int
    distinct_subdomains: int
    mean_entropy: float
    mean_length: float
    high_capacity_fraction: float
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        return (
            f"weighted geometric mean of [{parts}] over {self.queries} queries to "
            f"{self.distinct_subdomains} distinct subdomains; "
            f"mean label entropy {self.mean_entropy:.2f} bits/char, "
            f"mean length {self.mean_length:.0f} chars"
        )


def score_zone(
    subdomains: list[str],
    qtypes: list[str],
    config: DnsTunnelConfig,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> DnsTunnelScore | None:
    """Measure one source's queries into one zone."""
    queries = len(subdomains)
    if queries < config.min_queries:
        return None

    distinct = {s for s in subdomains if s}
    if len(distinct) < config.min_distinct_subdomains:
        return None

    measurable = [s for s in distinct if len(s) >= config.min_subdomain_length]
    if not measurable:
        return None

    entropies = np.array([shannon_entropy(s) for s in measurable])
    lengths = np.array([len(s) for s in measurable], dtype=np.float64)

    mean_entropy = float(entropies.mean())
    mean_length = float(lengths.mean())

    span = max(config.entropy_ceiling - config.entropy_floor, 1e-9)
    components = {
        "label_entropy": float(
            np.clip((mean_entropy - config.entropy_floor) / span, 0.0, 1.0)
        ),
        "subdomain_cardinality": saturating(len(distinct), config.strong_cardinality),
        "query_length": saturating(mean_length, config.strong_length),
    }

    # A tunnel restricted to A records is still a tunnel, so an absent skew
    # must not sink the score. Included only when high-capacity types appear.
    high_capacity = sum(1 for q in qtypes if q and q.upper() in _HIGH_CAPACITY_QTYPES)
    fraction = high_capacity / len(qtypes) if qtypes else 0.0
    if fraction > 0:
        components["qtype_skew"] = min(1.0, fraction * 2.0)

    return DnsTunnelScore(
        score=weighted_geometric_mean(components, _WEIGHTS),
        components=components,
        queries=queries,
        distinct_subdomains=len(distinct),
        mean_entropy=mean_entropy,
        mean_length=mean_length,
        high_capacity_fraction=fraction,
        first_seen=first_seen,
        last_seen=last_seen,
    )


class DnsTunnelAnalyzer(BaseAnalyzer):
    """Emits `TUNNELS_DNS_OVER` findings for zones carrying encoded payload."""

    name = "dnstunnel"
    version = "0.1.0"

    def __init__(self, config: DnsTunnelConfig | None = None) -> None:
        self.config = config or DnsTunnelConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        grouped = self._group(ctx.dns_scan())
        if grouped.is_empty():
            return []

        scored: list[tuple[DnsTunnelScore, dict[str, object]]] = []
        for row in grouped.iter_rows(named=True):
            zone = str(row["zone"])
            subdomains = [subdomain_of(str(q), zone) for q in row["query"]]
            score = score_zone(
                subdomains,
                [str(q) if q is not None else "" for q in row["qtype"]],
                self.config,
                first_seen=float(row["first_ts"]),
                last_seen=float(row["last_ts"]),
            )
            if score is not None and score.score >= self.config.score_threshold:
                scored.append((score, row))

        scored.sort(key=lambda item: item[0].score, reverse=True)
        return [
            self._build_finding(score, row, ctx)
            for score, row in scored[: self.config.max_findings]
        ]

    def _group(self, scan: pl.LazyFrame) -> pl.DataFrame:
        """Group queries by (source, zone).

        The zone is derived with a Polars expression rather than a Python loop
        so a multi-million-row dns.log stays in the columnar path, consistent
        with every other analyzer here.
        """
        available = set(scan.collect_schema().names())
        if not {"query", "src_ip"} <= available:
            return pl.DataFrame()

        return (
            scan.drop_nulls(subset=["query", "src_ip", "ts"])
            .with_columns(
                pl.col("query")
                .str.strip_chars(".")
                .str.to_lowercase()
                .map_elements(registered_domain, return_dtype=pl.Utf8)
                .alias("zone")
            )
            .group_by(["src_ip", "zone"])
            .agg(
                pl.col("query"),
                pl.col("qtype"),
                pl.col("source_file").head(self.config.artifact_samples),
                pl.col("source_line").head(self.config.artifact_samples),
                pl.len().alias("queries"),
                pl.col("ts").min().alias("first_ts"),
                pl.col("ts").max().alias("last_ts"),
            )
            .filter(pl.col("queries") >= self.config.min_queries)
            .collect(engine="streaming")
        )

    def _artifacts(self, row: dict[str, object], score: DnsTunnelScore) -> list[Artifact]:
        files, lines, queries = row["source_file"], row["source_line"], row["query"]
        artifacts: list[Artifact] = []
        for index in range(min(len(lines), self.config.artifact_samples)):
            source = files[index] if index < len(files) and files[index] else "<unknown>"
            artifacts.append(
                Artifact(
                    source=str(source),
                    locator=f"line:{lines[index]}",
                    observed_at=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
                    excerpt=f"{row['src_ip']} -> {queries[index]}",
                )
            )
        return artifacts or [
            Artifact(source="<aggregate>", locator=f"{row['src_ip']}:{row['zone']}")
        ]

    def _build_finding(
        self,
        score: DnsTunnelScore,
        row: dict[str, object],
        ctx: AnalysisContext,
    ) -> Finding:
        evidence = Evidence(
            kind="dns_label_encoding",
            summary=(
                f"{score.queries} queries to {score.distinct_subdomains} distinct subdomains "
                f"under {row['zone']}, mean entropy {score.mean_entropy:.2f} bits/char"
            ),
            payload={
                "zone": row["zone"],
                "queries": score.queries,
                "distinct_subdomains": score.distinct_subdomains,
                "mean_entropy_bits": round(score.mean_entropy, 3),
                "mean_subdomain_length": round(score.mean_length, 1),
                "high_capacity_qtype_fraction": round(score.high_capacity_fraction, 3),
                "span_seconds": round(score.last_seen - score.first_seen, 1),
            },
            artifacts=self._artifacts(row, score),
        )

        return Finding(
            predicate=Predicate.TUNNELS_DNS_OVER,
            subject=ctx.actor(str(row["src_ip"])),
            object=Entity(type=EntityType.DOMAIN, value=str(row["zone"])),
            evidence=[evidence],
            confidence=round(score.score, 4),
            basis=score.basis(),
            severity=(
                Severity.CRITICAL
                if score.score >= self.config.critical_threshold
                else Severity.HIGH
            ),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )
