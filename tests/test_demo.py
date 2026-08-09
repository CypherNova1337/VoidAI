"""The demo capture, end to end.

`voidai demo` is the first thing anyone evaluating this project will run, so
it is tested like a feature rather than left as a script. The assertions below
are the claims the demo makes out loud: three real formats, four behaviours on
one host, and that host at the top of the queue.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext
from voidai.correlate import build_queue
from voidai.eval.synth import build_demo_capture
from voidai.ingest import load_alerts, load_connections, load_passivedns
from voidai.lexicon import Finding

PATIENT_ZERO = "10.0.1.14"


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_demo_capture(tmp_path_factory.mktemp("demo"))


@pytest.fixture(scope="module")
def queue(capture: Path):  # type: ignore[no-untyped-def]
    ctx = AnalysisContext(
        connections=load_connections(capture),
        dns=load_passivedns(capture),
        alerts=load_alerts(capture),
    )
    findings: list[Finding] = []
    for analyzer in DEFAULT_ANALYZERS:
        findings += analyzer().analyze(ctx)
    return build_queue(findings)


class TestDemoCapture:
    def test_writes_all_three_formats(self, capture: Path) -> None:
        names = {p.name for p in capture.iterdir()}
        assert {"conn.log", "capture.passivedns", "eve.json"} <= names

    def test_every_file_parses_through_a_production_parser(self, capture: Path) -> None:
        """The demo must not bypass the parsers it is demonstrating."""
        assert load_connections(capture).height > 10_000
        assert load_passivedns(capture).height > 1_000
        assert load_alerts(capture).height > 1_000


class TestDemoDetection:
    def test_patient_zero_ranks_first(self, queue) -> None:  # type: ignore[no-untyped-def]
        assert queue.rank_of(PATIENT_ZERO) == 1

    def test_all_four_behaviours_corroborate(self, queue) -> None:  # type: ignore[no-untyped-def]
        top = queue.incidents[0]
        behaviours = {p.value for p in top.corroborating_predicates}
        assert behaviours == {
            "beacons_to",
            "scans",
            "tunnels_dns_over",
            "triggered_signature",
        }

    def test_priority_clears_the_field(self, queue) -> None:  # type: ignore[no-untyped-def]
        """Corroboration must be visible, not a hair's breadth."""
        top, runner_up = queue.incidents[0], queue.incidents[1]
        assert top.priority > runner_up.priority * 2

    def test_alert_flood_is_suppressed(self, queue) -> None:  # type: ignore[no-untyped-def]
        """55 hosts trip policy rules thousands of times and reach no incident."""
        noisy = [r for r in queue.incidents if r.subject.value != PATIENT_ZERO]
        assert all(
            "triggered_signature" not in {p.value for p in r.corroborating_predicates}
            for r in noisy
        )

    def test_every_finding_is_evidenced(self, queue) -> None:  # type: ignore[no-untyped-def]
        for ranked in queue.incidents:
            for finding in ranked.incident.findings:
                assert finding.evidence
                assert all(e.artifacts for e in finding.evidence)
