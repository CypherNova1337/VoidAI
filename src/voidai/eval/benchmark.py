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

from voidai.analyzers import (
    AnalysisContext,
    BeaconingAnalyzer,
    EgressAnalyzer,
    TlsDgaAnalyzer,
)
from voidai.eval.synth import (
    Corpus,
    CorpusGenerator,
    DgaCorpus,
    DgaCorpusGenerator,
    EgressCorpus,
    EgressCorpusGenerator,
    TlsCorpus,
    TlsCorpusGenerator,
    write_zeek_ssl_log,
)
from voidai.ingest.zeek import read_conn_log, read_ssl_log
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


@dataclass
class EgressBenchmarkResult:
    """Outcome of the volume-and-egress benchmark, reported separately.

    Its own corpus and its own score. Averaging it with the beaconing
    figures above would produce a number describing neither analyzer, and
    the two are measuring different behaviours against different decoys.
    """

    detection: DetectionScore
    receipt: RunReceipt
    findings: list[Finding]
    corpus: EgressCorpus


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


def score_egress(findings: list[Finding], corpus: EgressCorpus) -> DetectionScore:
    """Match egress findings to planted transfers by (source, destination).

    Matching ignores which of the three predicates was emitted. A 600KB
    upload to a rare new address is real, and `contacts_rare_destination` is
    the strongest claim the evidence supports for it — scoring that as a miss
    would penalise the analyzer for not overstating what it measured.

    A false positive is named with the decoy it fell for, because "one false
    positive" and "one false positive on the backup target only one machine
    uses" are different results and only the second is actionable.
    """
    score = DetectionScore()
    truth = {t.key: t for t in corpus.transfers}
    matched: set[tuple[str, str]] = set()

    for finding in findings:
        pair = _finding_endpoints(finding)
        if pair in truth:
            score.true_positives += 1
            matched.add(pair)
        else:
            score.false_positives += 1
            decoy = corpus.decoys.get(pair, "unlabelled")
            score.false_positive_pairs.append(f"{pair[0]} -> {pair[1]} ({decoy})")

    for pair, transfer in truth.items():
        if pair not in matched:
            score.false_negatives += 1
            score.missed_labels.append(transfer.label)

    return score


def run_egress_benchmark(
    seed: int = 1337,
    hours: float = 24.0,
    workdir: Path | None = None,
) -> EgressBenchmarkResult:
    """Run the egress analyzer against a seeded transfer corpus and score it.

    Through a real `conn.log` on disk, like `run_benchmark`, and for the same
    reason: a benchmark that skips the parser cannot catch a parser
    regression. It matters more here than for beaconing, because this
    analyzer reads `resp_bytes` and that column is the one Zeek writes as a
    bare `-` when it has nothing to record.
    """
    corpus = EgressCorpusGenerator(seed=seed).generate(hours=hours)
    receipt = RunReceipt()

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(workdir) if workdir else Path(tmp)
        log_path = corpus.write_zeek_conn_log(directory / "conn.log")

        with EnergyMeter() as meter:
            connections = read_conn_log(log_path)
            ctx = AnalysisContext(connections=connections)
            findings = EgressAnalyzer().analyze(ctx)

    receipt.records_ingested = len(connections)
    receipt.findings_emitted = len(findings)
    receipt.finalize(meter.reading)

    return EgressBenchmarkResult(
        detection=score_egress(findings, corpus),
        receipt=receipt,
        findings=findings,
        corpus=corpus,
    )


@dataclass
class DgaBenchmarkResult:
    """Outcome of the domain-generation benchmark.

    Its own corpus and its own score, like the egress result above. The DGA
    half and the TLS half are also kept apart from each other, because one is
    validated against a real corpus for specificity and the other is not
    validated against real data at all — averaging them would produce a number
    whose provenance nobody could state.
    """

    detection: DetectionScore
    receipt: RunReceipt
    findings: list[Finding]
    corpus: DgaCorpus


@dataclass
class TlsBenchmarkResult:
    detection: DetectionScore
    receipt: RunReceipt
    findings: list[Finding]
    corpus: TlsCorpus


def score_dga(findings: list[Finding], corpus: DgaCorpus) -> DetectionScore:
    """Match findings to planted generation families.

    Scored **per family, not per domain**. A family is a few hundred names and
    the analyzer reports a handful of exemplars by design, so counting domains
    would measure the exemplar cap rather than the detection: naming three of
    two hundred generated names has found the family, and naming two hundred
    would be the alert flood the cap exists to prevent.

    The dictionary-concatenation family is counted as a **miss**, not excluded.
    It is a real DGA family that this analyzer's character model cannot see —
    `analyzers/ngrams.py` explains why — and dropping it from the denominator
    would turn a documented limitation into a better-looking recall figure.
    """
    score = DetectionScore()
    matched: set[str] = set()

    for finding in findings:
        source, domain = _finding_endpoints(finding)
        family = corpus.family_of(source, domain)
        if family is not None:
            if family.label not in matched:
                score.true_positives += 1
                matched.add(family.label)
        else:
            decoy = corpus.decoys.get((source, domain), "unlabelled")
            score.false_positives += 1
            score.false_positive_pairs.append(f"{source} -> {domain} ({decoy})")

    for family in corpus.families:
        if family.label in matched:
            continue
        score.false_negatives += 1
        score.missed_labels.append(
            family.label
            if family.detectable
            else f"{family.label} (known limitation: dictionary generators)"
        )

    return score


def score_tls(findings: list[Finding], corpus: TlsCorpus) -> DetectionScore:
    """Match findings to planted rare clients by (host, fingerprint)."""
    score = DetectionScore()
    truth = {client.key: client for client in corpus.clients}
    matched: set[tuple[str, str]] = set()

    for finding in findings:
        pair = _finding_endpoints(finding)
        if pair in truth:
            score.true_positives += 1
            matched.add(pair)
        else:
            decoy = corpus.decoys.get(pair, "unlabelled")
            score.false_positives += 1
            score.false_positive_pairs.append(f"{pair[0]} presenting {pair[1]} ({decoy})")

    for pair, client in truth.items():
        if pair not in matched:
            score.false_negatives += 1
            score.missed_labels.append(client.label)

    return score


def run_dga_benchmark(seed: int = 1337, hours: float = 6.0) -> DgaBenchmarkResult:
    """Score the DGA half against a seeded corpus of generation families.

    The DNS frame is passed in memory rather than written to a `dns.log` and
    read back, unlike the connection benchmarks. `read_dns_log` is already
    covered by the tunnelling tests against a real capture, and what is under
    test here is a response-code path that the passivedns parser cannot
    produce at all.
    """
    corpus = DgaCorpusGenerator(seed=seed).generate(hours=hours)
    receipt = RunReceipt()

    with EnergyMeter() as meter:
        findings = TlsDgaAnalyzer().analyze(AnalysisContext(dns=corpus.queries))

    receipt.records_ingested = corpus.queries.height
    receipt.findings_emitted = len(findings)
    receipt.finalize(meter.reading)

    return DgaBenchmarkResult(
        detection=score_dga(findings, corpus),
        receipt=receipt,
        findings=findings,
        corpus=corpus,
    )


def run_tls_benchmark(
    seed: int = 1337,
    workdir: Path | None = None,
) -> TlsBenchmarkResult:
    """Score the TLS half, through a real `ssl.log` on disk.

    Through the file rather than the frame, for the reason `run_benchmark`
    gives: the `ja3` column arrives from a Zeek package and `established`
    arrives as the literal `T`, and a benchmark that skips the parser could
    not catch either going wrong.
    """
    corpus = TlsCorpusGenerator(seed=seed).generate()
    receipt = RunReceipt()

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(workdir) if workdir else Path(tmp)
        log_path = write_zeek_ssl_log(corpus.sessions, directory / "ssl.log")

        with EnergyMeter() as meter:
            sessions = read_ssl_log(log_path)
            findings = TlsDgaAnalyzer().analyze(AnalysisContext(ssl=sessions))

    receipt.records_ingested = sessions.height
    receipt.findings_emitted = len(findings)
    receipt.finalize(meter.reading)

    return TlsBenchmarkResult(
        detection=score_tls(findings, corpus),
        receipt=receipt,
        findings=findings,
        corpus=corpus,
    )
