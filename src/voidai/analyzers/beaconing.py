"""C2 beaconing detection.

An implant checking in with its controller leaves a signature that survives
encryption, domain fronting, and port choice: it is *regular*. The payload is
opaque, but the rhythm is not.

Six independent measurements are taken over each source→destination pair and
combined with a weighted geometric mean:

    interval regularity   how tightly inter-arrival times cluster (MAD/median)
    schedule floor        tightness of the lower quartile — timers have a
                          hard floor and a soft ceiling; people have neither
    payload uniformity    check-ins carry near-constant bytes; browsing does not
    periodicity           binned autocorrelation, which survives missed check-ins
    persistence           coverage of the observation window, without gaps
    destination rarity    how much of the estate talks to this destination

The geometric mean is the load-bearing choice. Any one of these signals in
isolation produces a flood of false positives — NTP is regular, a health check
is uniform, a cron job is periodic. Requiring all six simultaneously is what
separates an implant from infrastructure, and it is why this analyzer can run
with no allowlist tuning and still stay quiet.

Measurements that cannot be taken are omitted rather than scored zero, and the
weights renormalise over what remains. A sensor that does not record byte
counts loses a signal; it does not acquire a false one.

No language model is involved at any point.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import polars as pl

from voidai.analyzers.base import AnalysisContext, BaseAnalyzer
from voidai.analyzers.statistics import (
    autocorrelation_at_period,
    bimodal_gap_threshold,
    coalesce_bursts,
    coefficient_of_dispersion,
    destination_rarity,
    median_absolute_deviation,
    saturating,
    schedule_floor_dispersion,
    weighted_geometric_mean,
)
from voidai.lexicon import Artifact, Evidence, Finding, Predicate, Severity

_WEIGHTS = {
    "interval_regularity": 0.26,
    "schedule_floor": 0.12,
    "payload_uniformity": 0.20,
    "periodicity": 0.18,
    "persistence": 0.12,
    "destination_rarity": 0.12,
}


@dataclass(frozen=True)
class BeaconingConfig:
    """Tunables, with defaults chosen to favour precision over recall.

    A SOC drowning in alerts is worse off than one seeing nothing, so the
    defaults are set where a missed low-and-slow beacon is preferred to a
    daily false positive on a monitoring agent.
    """

    min_connections: int = 24
    min_span_seconds: float = 3600.0
    min_period_seconds: float = 1.0
    max_period_seconds: float = 86400.0

    #: Interval dispersion at which the regularity score reaches zero.
    #: 0.6 tolerates roughly ±60% jitter before a pair is dismissed outright.
    max_interval_dispersion: float = 0.6
    #: Payload dispersion at which the uniformity score reaches zero.
    max_size_dispersion: float = 0.5
    #: Lower-quartile spread at which the schedule-floor score reaches zero.
    #: Calibrated across both jitter models rather than one: a symmetrically
    #: jittered beacon at +/-50% sits at 0.33, while human browsing sits near
    #: 0.59. 0.6 keeps the wide separation between scheduled and interactive
    #: traffic without punishing the symmetric case that a tighter bound
    #: would have discarded.
    max_floor_dispersion: float = 0.6
    #: Sample count beyond which more samples add little confidence.
    #: Kept low deliberately: a 30-minute beacon can only check in 48 times a
    #: day, and that is the ceiling for its period, not a weakness in it.
    #: `min_connections` is what guards against small-sample flukes.
    strong_sample_count: int = 15

    score_threshold: float = 0.72
    #: Score above which a finding is promoted from HIGH to CRITICAL.
    critical_threshold: float = 0.90

    #: Protocols whose periodicity is structural rather than suspicious.
    #: Deliberately tiny — a large default allowlist is where detection
    #: coverage quietly goes to die.
    ignore_ports: frozenset[int] = frozenset({123})  # NTP
    ignore_services: frozenset[str] = frozenset({"ntp", "dhcp"})

    #: Ceiling on emitted findings, highest-scoring first.
    max_findings: int = 200
    #: Connections sampled as artifacts per finding.
    artifact_samples: int = 5


@dataclass
class BeaconScore:
    """The full measurement for one source→destination pair."""

    score: float
    components: dict[str, float]
    period_seconds: float
    interval_dispersion: float
    floor_dispersion: float
    median_bytes: float
    size_dispersion: float
    autocorrelation: float | None
    contacting_hosts: int
    sample_count: int
    raw_record_count: int
    burst_threshold: float | None
    span_seconds: float
    coverage: float
    first_seen: float
    last_seen: float

    def basis(self) -> str:
        """A one-line, checkable justification for the confidence score."""
        parts = ", ".join(f"{k}={v:.2f}" for k, v in sorted(self.components.items()))
        coalesced = ""
        if self.burst_threshold is not None:
            coalesced = (
                f"; {self.raw_record_count} records coalesced into {self.sample_count} "
                f"check-ins at a {self.burst_threshold:.2f}s burst gap"
            )
        return (
            f"weighted geometric mean of [{parts}] over {self.sample_count} check-ins "
            f"spanning {self.span_seconds / 3600:.1f}h; "
            f"period={self.period_seconds:.1f}s, jitter={self.interval_dispersion:.1%}"
            f"{coalesced}"
        )


def score_pair(
    timestamps: np.ndarray,
    payload_bytes: np.ndarray,
    config: BeaconingConfig,
    contacting_hosts: int = 1,
) -> BeaconScore | None:
    """Measure one source→destination pair. Returns None if it cannot qualify.

    Separated from the Polars and Lexicon plumbing so the mathematics can be
    tested directly against synthesised beacons and against known-benign
    periodic traffic.
    """
    timestamps = np.sort(np.asarray(timestamps, dtype=np.float64))
    sizes_in = np.asarray(payload_bytes, dtype=np.float64)
    if sizes_in.size != timestamps.size:
        sizes_in = np.full(timestamps.size, np.nan)

    span = float(timestamps[-1] - timestamps[0]) if timestamps.size else 0.0
    if span < config.min_span_seconds:
        return None

    # Collapse burst structure before measuring anything. One check-in often
    # arrives as several telemetry records — see `bimodal_gap_threshold` — and
    # every statistic below would otherwise describe record framing rather
    # than the beacon. A no-op on well-formed connection logs.
    raw_count = int(timestamps.size)
    burst_threshold = bimodal_gap_threshold(np.diff(timestamps))
    if burst_threshold is not None:
        timestamps, sizes_in = coalesce_bursts(timestamps, sizes_in, burst_threshold)

    sample_count = int(timestamps.size)
    if sample_count < config.min_connections:
        return None

    intervals = np.diff(timestamps)
    intervals = intervals[intervals > 0]
    if intervals.size < 3:
        return None

    period = float(np.median(intervals))
    if not (config.min_period_seconds <= period <= config.max_period_seconds):
        return None

    # --- the six measurements ---------------------------------------------
    interval_dispersion = coefficient_of_dispersion(intervals)
    regularity = 1.0 - min(1.0, interval_dispersion / config.max_interval_dispersion)

    floor_dispersion = schedule_floor_dispersion(intervals)
    schedule_floor = 1.0 - min(1.0, floor_dispersion / config.max_floor_dispersion)

    components: dict[str, float] = {
        "interval_regularity": regularity,
        "schedule_floor": schedule_floor,
    }

    sizes = sizes_in[np.isfinite(sizes_in)]
    if sizes.size >= 3:
        size_dispersion = coefficient_of_dispersion(sizes)
        median_bytes = float(np.median(sizes))
        components["payload_uniformity"] = 1.0 - min(
            1.0, size_dispersion / config.max_size_dispersion
        )
    else:
        # This sensor did not record byte counts. Omit the measurement so the
        # remaining weights renormalise, rather than inventing a value.
        size_dispersion, median_bytes = float("nan"), float("nan")

    autocorrelation = autocorrelation_at_period(
        timestamps, period, jitter_scale=median_absolute_deviation(intervals)
    )
    if autocorrelation is not None:
        components["periodicity"] = autocorrelation

    expected_intervals = span / period if period > 0 else 0.0
    coverage = (
        min(intervals.size, expected_intervals) / max(intervals.size, expected_intervals)
        if expected_intervals > 0
        else 0.0
    )
    components["persistence"] = coverage * saturating(sample_count, config.strong_sample_count)
    components["destination_rarity"] = destination_rarity(contacting_hosts)

    return BeaconScore(
        score=weighted_geometric_mean(components, _WEIGHTS),
        components=components,
        period_seconds=period,
        interval_dispersion=interval_dispersion,
        floor_dispersion=floor_dispersion,
        median_bytes=median_bytes,
        size_dispersion=size_dispersion,
        autocorrelation=autocorrelation,
        contacting_hosts=contacting_hosts,
        sample_count=sample_count,
        raw_record_count=raw_count,
        burst_threshold=burst_threshold,
        span_seconds=span,
        coverage=coverage,
        first_seen=float(timestamps[0]),
        last_seen=float(timestamps[-1]),
    )


class BeaconingAnalyzer(BaseAnalyzer):
    """Emits `BEACONS_TO` findings for periodic source→destination pairs."""

    name = "beaconing"
    version = "0.1.0"

    def __init__(self, config: BeaconingConfig | None = None) -> None:
        self.config = config or BeaconingConfig()

    # --- pipeline ---------------------------------------------------------

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Two streaming passes over the capture, neither materialising it.

        The naive shape — collect everything, then group — costs memory
        proportional to the capture, because the per-pair arrays of timestamps
        and byte counts hold every record in the file. On the 66-hour CTU-13
        scenario that peaked at 7.2GB, more than the Pi 5 this project targets
        has in total.

        Splitting it fixes that:

          Pass 1  group to one row per pair carrying only scalars — a count
                  and a first/last timestamp. Cheap enough to stream, and
                  enough to decide which pairs could possibly qualify.
          Pass 2  re-scan, keeping only those surviving pairs, and gather the
                  full arrays for them alone.

        Almost every pair fails the count-and-span gate, so pass 2 collects a
        tiny fraction of the capture. The cost is reading twice; the saving is
        that peak memory tracks the number of *candidate pairs* rather than
        the number of records.
        """
        scan = ctx.connection_scan().drop_nulls(subset=["ts", "src_ip", "dst_ip"])

        summary = self._pair_summary(scan)
        if summary.is_empty():
            return []

        prevalence = self._destination_prevalence(summary)
        candidates = self._candidates(summary)
        if candidates.is_empty():
            return []

        pairs = self._collect_series(scan, candidates)
        if pairs.is_empty():
            return []

        scored: list[tuple[BeaconScore, dict[str, object]]] = []
        for row in pairs.iter_rows(named=True):
            score = score_pair(
                np.asarray(row["ts"], dtype=np.float64),
                np.asarray(row["orig_bytes"], dtype=np.float64),
                self.config,
                contacting_hosts=prevalence.get(str(row["dst_ip"]), 1),
            )
            if score is not None and score.score >= self.config.score_threshold:
                scored.append((score, row))

        scored.sort(key=lambda item: item[0].score, reverse=True)
        return [
            self._build_finding(score, row, ctx)
            for score, row in scored[: self.config.max_findings]
        ]

    # --- pass 1: scalar summary per pair ----------------------------------

    def _pair_summary(self, scan: pl.LazyFrame) -> pl.DataFrame:
        """One row per (src, dst, port), carrying only scalars.

        Deliberately computed before the ignore-port filter. Destination
        prevalence is a property of the environment, and excluding NTP here
        would shrink the denominator and make ordinary infrastructure look
        rare.
        """
        return (
            scan.group_by(["src_ip", "dst_ip", "dst_port"])
            .agg(
                pl.len().alias("n"),
                pl.col("ts").min().alias("first_ts"),
                pl.col("ts").max().alias("last_ts"),
            )
            .collect(engine="streaming")
        )

    def _destination_prevalence(self, summary: pl.DataFrame) -> dict[str, int]:
        """How many distinct hosts contact each destination.

        Derived from the pass-1 summary rather than from a third scan: the
        summary already holds one row per (src, dst, port), so counting
        distinct sources per destination is a small in-memory aggregation.
        """
        if summary.is_empty():
            return {}
        counts = summary.group_by("dst_ip").agg(pl.col("src_ip").n_unique().alias("hosts"))
        return dict(zip(counts["dst_ip"].to_list(), counts["hosts"].to_list(), strict=True))

    def _candidates(self, summary: pl.DataFrame) -> pl.DataFrame:
        """Pairs that could possibly qualify, on count and span alone.

        Both gates are the ones `score_pair` applies anyway, hoisted forward so
        that pass 2 never gathers arrays for a pair destined to be rejected.
        """
        candidates = summary.filter(
            (pl.col("n") >= self.config.min_connections)
            & ((pl.col("last_ts") - pl.col("first_ts")) >= self.config.min_span_seconds)
        )
        if self.config.ignore_ports:
            candidates = candidates.filter(
                pl.col("dst_port").is_null()
                | ~pl.col("dst_port").is_in(list(self.config.ignore_ports))
            )
        return candidates.select("src_ip", "dst_ip", "dst_port")

    # --- pass 2: full arrays, candidates only -----------------------------

    def _collect_series(self, scan: pl.LazyFrame, candidates: pl.DataFrame) -> pl.DataFrame:
        """Gather timestamps, byte counts and artifact locators per candidate.

        A semi-join restricts the scan to surviving pairs before aggregation,
        so the list columns never hold the whole capture. `nulls_equal` keeps
        pairs whose destination port is null — ICMP, mostly — which a default
        join would silently drop.

        Each column is sorted by `ts` inside the aggregation rather than the
        frame being globally sorted first. The scoring maths sorts timestamps
        itself, but the artifact locators must stay aligned with the
        timestamps they describe, and a full sort of the capture is exactly
        the kind of work this refactor exists to avoid.
        """
        filtered = scan
        # Sensors differ in which columns they populate; NetFlow has no
        # application-layer guess at all. Resolving the schema first costs
        # nothing — it reads no data — and keeps a missing column a degraded
        # signal rather than a crash.
        available = set(scan.collect_schema().names())
        if self.config.ignore_services and "service" in available:
            filtered = filtered.filter(
                pl.col("service").is_null()
                | ~pl.col("service").str.to_lowercase().is_in(list(self.config.ignore_services))
            )

        return (
            filtered.join(
                candidates.lazy(),
                on=["src_ip", "dst_ip", "dst_port"],
                how="semi",
                nulls_equal=True,
            )
            .group_by(["src_ip", "dst_ip", "dst_port"])
            .agg(
                pl.col("ts").sort_by("ts"),
                pl.col("orig_bytes").sort_by("ts"),
                pl.col("source_file").sort_by("ts"),
                pl.col("source_line").sort_by("ts"),
                pl.len().alias("n"),
            )
            .filter(pl.col("n") >= self.config.min_connections)
            .collect(engine="streaming")
        )

    # --- evidence construction -------------------------------------------

    def _sample_indices(self, count: int) -> list[int]:
        """Pick spread-out representatives: first, last, and evenly between.

        An analyst verifying a finding wants to see the beacon at the start of
        the window and at the end, not five consecutive lines from the middle.
        """
        wanted = min(self.config.artifact_samples, count)
        if wanted <= 1:
            return [0]
        step = (count - 1) / (wanted - 1)
        return sorted({round(i * step) for i in range(wanted)})

    def _artifacts(self, row: dict[str, object], score: BeaconScore) -> list[Artifact]:
        timestamps = row["ts"]
        files = row["source_file"]
        lines = row["source_line"]
        artifacts: list[Artifact] = []

        for index in self._sample_indices(len(timestamps)):
            source = files[index] if index < len(files) and files[index] else "<unknown>"
            line = lines[index] if index < len(lines) and lines[index] is not None else index
            artifacts.append(
                Artifact(
                    source=str(source),
                    locator=f"line:{line}",
                    observed_at=datetime.fromtimestamp(float(timestamps[index]), tz=timezone.utc),
                    excerpt=(
                        f"{row['src_ip']} -> {row['dst_ip']}:{row['dst_port']} "
                        f"at t={float(timestamps[index]):.3f}"
                    ),
                )
            )
        return artifacts

    def _evidence(self, score: BeaconScore, artifacts: list[Artifact]) -> list[Evidence]:
        timing = Evidence(
            kind="interval_regularity",
            summary=(
                f"{score.sample_count} connections at {score.period_seconds:.1f}s intervals "
                f"(±{score.interval_dispersion:.1%}) over {score.span_seconds / 3600:.1f}h"
            ),
            payload={
                "period_seconds": round(score.period_seconds, 3),
                "interval_dispersion": round(score.interval_dispersion, 4),
                "floor_dispersion": round(score.floor_dispersion, 4),
                "autocorrelation": (
                    round(score.autocorrelation, 4)
                    if score.autocorrelation is not None
                    else None
                ),
                "coverage": round(score.coverage, 4),
                "sample_count": score.sample_count,
                "span_seconds": round(score.span_seconds, 1),
                "contacting_hosts": score.contacting_hosts,
                "raw_record_count": score.raw_record_count,
                "burst_threshold_seconds": (
                    round(score.burst_threshold, 3)
                    if score.burst_threshold is not None
                    else None
                ),
            },
            artifacts=artifacts,
        )

        evidence = [timing]
        if np.isfinite(score.median_bytes):
            evidence.append(
                Evidence(
                    kind="payload_uniformity",
                    summary=(
                        f"outbound payload {score.median_bytes:.0f} bytes median "
                        f"(±{score.size_dispersion:.1%})"
                    ),
                    payload={
                        "median_bytes": round(score.median_bytes, 1),
                        "size_dispersion": round(score.size_dispersion, 4),
                    },
                    artifacts=artifacts,
                )
            )
        return evidence

    def _build_finding(
        self,
        score: BeaconScore,
        row: dict[str, object],
        ctx: AnalysisContext,
    ) -> Finding:
        artifacts = self._artifacts(row, score)
        return Finding(
            predicate=Predicate.BEACONS_TO,
            subject=ctx.actor(str(row["src_ip"])),
            object=ctx.target(str(row["dst_ip"])),
            evidence=self._evidence(score, artifacts),
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
