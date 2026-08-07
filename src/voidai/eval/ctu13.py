"""Evaluation against the CTU-13 real-capture corpus.

CTU-13 is thirteen captures of real botnet traffic recorded on a university
network, with every flow labelled `Botnet`, `Normal`, or `Background`. It is
the closest thing the field has to ground truth for command-and-control
detection, and running against it is what separates a demo from a claim.

## Why the obvious metric is the wrong metric

The tempting evaluation is precision and recall against every `Botnet`-labelled
flow. That number would be meaningless here, and reporting it would be
dishonest in a direction that happens to flatter nobody.

A bot does far more than call home. The CTU-13 botnet labels cover spam runs,
ICMP floods, port scans, click fraud, and peer-to-peer chatter. A *beaconing*
detector is supposed to find the periodic check-in channel and ignore the
rest — flagging a spam burst as beaconing would be a bug, not a success. So
recall measured against all botnet traffic would punish the analyzer for being
correct, and its complement would reward a detector that simply alerted on
everything the infected host did.

Defining C2 as "the botnet traffic that looks periodic" and then measuring
whether we find periodic traffic is worse still: it is circular, and it would
score 1.000 by construction.

## What is measured instead

**Infected-host detection** — did the analyzer surface the compromised host at
all? This is the operational question a SOC actually asks, and it is derived
from the labels rather than from anything the detector computed.

**Pair precision** — of the source→destination pairs flagged as beaconing,
what fraction carry botnet labels? Non-circular, and directly interpretable:
it is the analyst's false-alarm rate.

**Alert burden** — findings per hour of capture. A detector with excellent
precision that emits four hundred alerts a day is still unusable, and this is
the number that says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import polars as pl

from voidai.analyzers import (
    AnalysisContext,
    BeaconingAnalyzer,
    BeaconingConfig,
    FanoutAnalyzer,
    FanoutConfig,
)
from voidai.correlate import IncidentQueue, build_queue
from voidai.ingest.netflow import LABEL_BOTNET, scan_labelled_netflow
from voidai.ingest.schema import CONNECTION_SCHEMA
from voidai.lexicon import Finding, Predicate
from voidai.telemetry import EnergyMeter, RunReceipt

#: Columns the analyzers need. Projecting early keeps the 1.4GB scenarios
#: inside a few hundred megabytes of working set.
_ANALYSIS_COLUMNS = [
    "ts",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "duration",
    "orig_bytes",
    "orig_pkts",
    "conn_state",
    "source_file",
    "source_line",
]


@dataclass(frozen=True)
class Scenario:
    """One CTU-13 capture and its published provenance."""

    key: str
    filename: str
    malware: str
    duration_hours: float
    #: The compromised host documented by the CTU-13 authors. Used only as a
    #: cross-check against the hosts derived from the label column, never as
    #: an input to detection.
    documented_infected: tuple[str, ...] = ("147.32.84.165",)

    @property
    def url(self) -> str:
        return f"https://mcfp.felk.cvut.cz/publicDatasets/{self.key}/{self.filename}"


SCENARIOS: dict[str, Scenario] = {
    "scenario03": Scenario(
        key="CTU-Malware-Capture-Botnet-44",
        filename="capture20110812.pcap.netflow.labeled",
        malware="Rbot",
        duration_hours=66.85,
    ),
    "scenario06": Scenario(
        key="CTU-Malware-Capture-Botnet-47",
        filename="capture20110816.pcap.netflow.labeled",
        malware="Menti",
        duration_hours=2.18,
    ),
}


@dataclass
class RealCaptureResult:
    """Outcome of running the analyzers against one real capture."""

    scenario: Scenario
    findings: list[Finding]
    receipt: RunReceipt

    flow_count: int = 0
    span_hours: float = 0.0
    infected_hosts: set[str] = field(default_factory=set)
    botnet_pairs: set[tuple[str, str]] = field(default_factory=set)
    flagged_pairs: list[tuple[str, str]] = field(default_factory=list)
    queue: IncidentQueue = field(default_factory=IncidentQueue)

    @property
    def best_infected_rank(self) -> int | None:
        """Best queue position held by a host the labels call compromised.

        The measure that actually matters. A true positive at rank 2 gets
        worked; the same true positive at rank 358 does not.
        """
        ranks = [
            rank
            for host in self.infected_hosts
            if (rank := self.queue.rank_of(host)) is not None
        ]
        return min(ranks) if ranks else None

    @property
    def true_positive_pairs(self) -> list[tuple[str, str]]:
        return [p for p in self.flagged_pairs if p in self.botnet_pairs]

    @property
    def pair_precision(self) -> float:
        """Fraction of flagged pairs that carry botnet labels."""
        if not self.flagged_pairs:
            return 1.0
        return len(self.true_positive_pairs) / len(self.flagged_pairs)

    @property
    def flagged_infected_hosts(self) -> set[str]:
        return {src for src, _ in self.flagged_pairs} & self.infected_hosts

    @property
    def infected_host_detected(self) -> bool:
        """Did any finding name a host the labels identify as compromised?"""
        return bool(self.flagged_infected_hosts)

    @property
    def findings_per_hour(self) -> float:
        return len(self.findings) / self.span_hours if self.span_hours > 0 else 0.0


def _ground_truth(path: Path) -> tuple[set[str], set[tuple[str, str]]]:
    """Derive infected hosts and botnet pairs from the label column alone.

    Read in a separate pass from the analysis frame so that the labels are
    never present in the data the analyzer sees. Segregating them by
    construction is stronger than remembering to drop a column.
    """
    labelled = (
        scan_labelled_netflow(path)
        .filter(pl.col("label") == LABEL_BOTNET)
        .select("src_ip", "dst_ip")
        .unique()
        .collect(engine="streaming")
    )
    pairs = {(row["src_ip"], row["dst_ip"]) for row in labelled.iter_rows(named=True)}
    return {src for src, _ in pairs}, pairs


def evaluate(
    path: str | Path,
    scenario: Scenario,
    config: BeaconingConfig | None = None,
) -> RealCaptureResult:
    """Run the beaconing analyzer against a real capture and score it."""
    path = Path(path)
    infected_hosts, botnet_pairs = _ground_truth(path)

    receipt = RunReceipt()
    with EnergyMeter() as meter:
        # Handed to the analyzer lazily. Collecting here would materialise the
        # whole capture — 7.2GB on the 66-hour scenario — before any filtering
        # had a chance to run.
        scan = scan_labelled_netflow(path).select(_ANALYSIS_COLUMNS)

        # Belt and braces: the analyzer must not be able to see ground truth
        # even if a future refactor changes the projection above.
        columns = set(scan.collect_schema().names())
        assert "label" not in columns, "ground truth leaked into analysis frame"
        assert columns <= set(CONNECTION_SCHEMA)

        extent = scan.select(
            pl.len().alias("records"),
            pl.col("ts").min().alias("first_ts"),
            pl.col("ts").max().alias("last_ts"),
        ).collect(engine="streaming")

        records = int(extent["records"][0]) if extent.height else 0
        ctx = AnalysisContext(connections=scan, known_record_count=records)

        findings = BeaconingAnalyzer(config).analyze(ctx)
        cap = config.max_findings if config else FanoutConfig().max_findings
        findings += FanoutAnalyzer(FanoutConfig(max_findings=cap)).analyze(ctx)
        queue = build_queue(findings)

    receipt.records_ingested = records
    receipt.findings_emitted = len(findings)
    receipt.finalize(meter.reading)

    span_hours = (
        (extent["last_ts"][0] - extent["first_ts"][0]) / 3600.0
        if records and extent["first_ts"][0] is not None
        else 0.0
    )

    return RealCaptureResult(
        scenario=scenario,
        findings=findings,
        receipt=receipt,
        flow_count=records,
        span_hours=float(span_hours),
        infected_hosts=infected_hosts,
        botnet_pairs=botnet_pairs,
        queue=queue,
        flagged_pairs=[
            (f.subject.value, f.object.value if f.object else "")
            for f in findings
            if f.predicate is Predicate.BEACONS_TO
        ],
    )
