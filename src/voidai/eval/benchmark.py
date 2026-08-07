"""The benchmark harness.

`voidai bench` regenerates a labelled corpus from a fixed seed, writes it out
as a real Zeek log, reads it back through the production parser, runs the
production analyzers, and scores the findings against ground truth — while
metering its own energy consumption.

Going through the file on disk rather than passing frames in memory is
deliberate. A benchmark that skips the parser cannot catch a parser
regression, and a parser regression is indistinguishable from a detection
regression to everyone except the person debugging it at 2am.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from voidai.analyzers import AnalysisContext, BeaconingAnalyzer
from voidai.eval.synth import Corpus, CorpusGenerator
from voidai.ingest.zeek import read_conn_log
from voidai.lexicon import Finding
from voidai.telemetry import EnergyMeter, RunReceipt


@dataclass
class DetectionScore:
    """Precision, recall, and F1 for one analyzer against known ground truth."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    missed_labels: list[str] = field(default_factory=list)
    false_positive_pairs: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        detected = self.true_positives + self.false_positives
        return self.true_positives / detected if detected else 1.0

    @property
    def recall(self) -> float:
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


@dataclass
class BenchmarkResult:
    detection: DetectionScore
    receipt: RunReceipt
    findings: list[Finding]
    corpus: Corpus


def _finding_endpoints(finding: Finding) -> tuple[str, str]:
    """Recover the raw addresses a finding refers to, for ground-truth matching."""
    return finding.subject.value, finding.object.value if finding.object else ""


def score_beaconing(findings: list[Finding], corpus: Corpus) -> DetectionScore:
    """Match findings to planted implants by (source, destination) address.

    Matching ignores port: an analyst who is told the right host is talking to
    the right C2 address has been given the answer, and penalising a port
    mismatch would measure bookkeeping rather than detection.
    """
    score = DetectionScore()
    truth = {(i.src_ip, i.dst_ip): i for i in corpus.implants}
    matched: set[tuple[str, str]] = set()

    for finding in findings:
        pair = _finding_endpoints(finding)
        if pair in truth:
            score.true_positives += 1
            matched.add(pair)
        else:
            score.false_positives += 1
            score.false_positive_pairs.append(f"{pair[0]} -> {pair[1]}")

    for pair, implant in truth.items():
        if pair not in matched:
            score.false_negatives += 1
            score.missed_labels.append(implant.label)

    return score


def run_benchmark(
    seed: int = 1337,
    hours: float = 24.0,
    workdir: Path | None = None,
) -> BenchmarkResult:
    """Run the full pipeline against a seeded corpus and score it."""
    corpus = CorpusGenerator(seed=seed).generate(hours=hours)
    receipt = RunReceipt()

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(workdir) if workdir else Path(tmp)
        log_path = corpus.write_zeek_conn_log(directory / "conn.log")

        with EnergyMeter() as meter:
            connections = read_conn_log(log_path)
            ctx = AnalysisContext(connections=connections)
            findings = BeaconingAnalyzer().analyze(ctx)

    receipt.records_ingested = len(connections)
    receipt.findings_emitted = len(findings)
    receipt.finalize(meter.reading)

    return BenchmarkResult(
        detection=score_beaconing(findings, corpus),
        receipt=receipt,
        findings=findings,
        corpus=corpus,
    )
