"""Horizontal fan-out detection: scanning, spam runs, and worm propagation.

A host that touches hundreds of destinations on one port, and touches each of
them once, is not browsing. It is enumerating. That covers port scanning, mass
mailing, SSH brute-force sweeps, and self-propagating worms — different intents
with one shape.

Two measurements, and the second is what makes it work:

    breadth    distinct destinations reached on a single port
    revisiting flows per destination

Breadth alone flags every busy workstation. On CTU-13 scenario 6 a normal user
reaches 1,486 web servers on port 80 — more destinations than the spam bot's
1,573 on port 25. What separates them is that the user goes *back*: 51.8 flows
per destination against the bot's 3.3. People return to the same handful of
sites all day; an enumerator has no reason to revisit anything.

Why this analyzer exists at all: beaconing cannot rank command-and-control
above legitimate periodic traffic, because on a real network there is a great
deal of legitimate periodic traffic and it looks the same. What distinguishes a
compromised host is that it does *several* suspicious things at once. This is
the second opinion — cheap, independent, and measuring something entirely
unlike a beacon. See `voidai.correlate` for where the two are combined.

No language model is involved at any point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.statistics import saturating, weighted_geometric_mean
from voidai.lexicon import Artifact, Entity, EntityType, Evidence, Finding, Predicate, Severity

_WEIGHTS = {
    "breadth": 0.55,
    "non_revisiting": 0.45,
}


@dataclass(frozen=True)
class FanoutConfig:
    """Tunables, set from measured separation rather than from intuition."""

    #: Below this, a host is simply busy. CTU-13 workstations reach a few
    #: dozen distinct servers on port 80 in an ordinary session.
    min_destinations: int = 50
    #: Destination count at which breadth is considered well-established.
    strong_destination_count: int = 250

    #: Flows per destination at which the revisiting score reaches zero.
    #: Benign browsing measures 20-64; enumeration measures 1-3.
    max_flows_per_destination: float = 12.0

    score_threshold: float = 0.55
    critical_threshold: float = 0.85

    #: Ports whose fan-out is structural. A resolver talks to the world by
    #: design, and so does an authoritative name server.
    ignore_ports: frozenset[int] = frozenset({53, 123})

    max_findings: int = 200
    artifact_samples: int = 5


@dataclass
class FanoutScore:
    """The measurement for one (source, port) pair."""

    score: float
    components: dict[str, float]
    destinations: int
    flows: int
    flows_per_destination: float
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        return (
            f"weighted geometric mean of [{parts}] over {self.destinations} distinct "
            f"destinations in {self.flows} flows "
            f"({self.flows_per_destination:.1f} flows per destination)"
        )


def score_fanout(
    destinations: int,
    flows: int,
    config: FanoutConfig,
    first_seen: float = 0.0,
    last_seen: float = 0.0,
) -> FanoutScore | None:
    """Measure one (source, port) pair. Returns None if it cannot qualify."""
    if destinations < config.min_destinations or flows <= 0:
        return None

    revisit = flows / destinations
    components = {
        "breadth": saturating(destinations, config.strong_destination_count),
        "non_revisiting": 1.0
        - min(1.0, max(0.0, revisit - 1.0) / config.max_flows_per_destination),
    }

    return FanoutScore(
        score=weighted_geometric_mean(components, _WEIGHTS),
        components=components,
        destinations=destinations,
        flows=flows,
        flows_per_destination=revisit,
        first_seen=first_seen,
        last_seen=last_seen,
    )


class FanoutAnalyzer(BaseAnalyzer):
    """Emits `SCANS` findings for hosts enumerating many destinations."""

    name = "fanout"
    version = "0.1.0"

    def __init__(self, config: FanoutConfig | None = None) -> None:
        self.config = config or FanoutConfig()

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """One streaming pass. Grouping by (source, port) is the whole job.

        Unlike beaconing this needs no second pass: every measurement is a
        scalar aggregate, and the handful of artifact samples come along in
        the same aggregation.
        """
        grouped = self._group(ctx.connection_scan())
        if grouped.is_empty():
            return []

        scored: list[tuple[FanoutScore, dict[str, object]]] = []
        for row in grouped.iter_rows(named=True):
            score = score_fanout(
                int(row["destinations"]),
                int(row["flows"]),
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
        filtered = scan.drop_nulls(subset=["src_ip", "dst_ip", "dst_port", "ts"])
        if self.config.ignore_ports:
            filtered = filtered.filter(
                ~pl.col("dst_port").is_in(list(self.config.ignore_ports))
            )

        return (
            filtered.group_by(["src_ip", "dst_port"])
            .agg(
                pl.col("dst_ip").n_unique().alias("destinations"),
                pl.len().alias("flows"),
                pl.col("ts").min().alias("first_ts"),
                pl.col("ts").max().alias("last_ts"),
                # Samples for the evidence chain, gathered in the same pass.
                pl.col("source_file").head(self.config.artifact_samples),
                pl.col("source_line").head(self.config.artifact_samples),
                pl.col("dst_ip").head(self.config.artifact_samples),
            )
            .filter(pl.col("destinations") >= self.config.min_destinations)
            .collect(engine="streaming")
        )

    def _artifacts(self, row: dict[str, object], score: FanoutScore) -> list[Artifact]:
        files, lines, targets = row["source_file"], row["source_line"], row["dst_ip"]
        artifacts: list[Artifact] = []
        for index in range(min(len(lines), self.config.artifact_samples)):
            source = files[index] if index < len(files) and files[index] else "<unknown>"
            artifacts.append(
                Artifact(
                    source=str(source),
                    locator=f"line:{lines[index]}",
                    observed_at=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
                    excerpt=f"{row['src_ip']} -> {targets[index]}:{row['dst_port']}",
                )
            )
        return artifacts or [
            Artifact(source="<aggregate>", locator=f"{row['src_ip']}:{row['dst_port']}")
        ]

    def _build_finding(
        self,
        score: FanoutScore,
        row: dict[str, object],
        ctx: AnalysisContext,
    ) -> Finding:
        artifacts = self._artifacts(row, score)
        evidence = Evidence(
            kind="destination_fanout",
            summary=(
                f"{score.destinations} distinct destinations on port {row['dst_port']} "
                f"at {score.flows_per_destination:.1f} flows each"
            ),
            payload={
                "destinations": score.destinations,
                "flows": score.flows,
                "flows_per_destination": round(score.flows_per_destination, 2),
                "port": row["dst_port"],
                "span_seconds": round(score.last_seen - score.first_seen, 1),
            },
            artifacts=artifacts,
        )

        return Finding(
            predicate=Predicate.SCANS,
            subject=ctx.actor(str(row["src_ip"])),
            object=Entity(type=EntityType.PORT, value=str(row["dst_port"])),
            evidence=[evidence, *ctx.resolution_evidence(str(row["src_ip"]))],
            confidence=round(score.score, 4),
            basis=score.basis(),
            severity=(
                Severity.HIGH if score.score >= self.config.critical_threshold else Severity.MEDIUM
            ),
            analyzer=self.qualname,
            first_seen=datetime.fromtimestamp(score.first_seen, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(score.last_seen, tz=timezone.utc),
        )
