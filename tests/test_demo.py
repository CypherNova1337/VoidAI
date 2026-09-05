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
from voidai.ingest import load_alerts, load_connections, load_dns, load_passivedns, load_ssl
from voidai.lexicon import Finding

PATIENT_ZERO = "10.0.1.14"


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_demo_capture(tmp_path_factory.mktemp("demo"))


@pytest.fixture(scope="module")
def queue(capture: Path):  # type: ignore[no-untyped-def]
    # Sources chosen the way `cli._detect` chooses them: dns.log where it
    # exists, passivedns as the fallback. A fixture that read the fallback
    # while the CLI read the primary would be testing a capture the product
    # never analyses.
    ctx = AnalysisContext(
        connections=load_connections(capture),
        dns=load_dns(capture),
        alerts=load_alerts(capture),
        ssl=load_ssl(capture),
    )
    findings: list[Finding] = []
    for analyzer in DEFAULT_ANALYZERS:
        findings += analyzer().analyze(ctx)
    return build_queue(findings)


class TestDemoCapture:
    def test_writes_all_three_formats(self, capture: Path) -> None:
        names = {p.name for p in capture.iterdir()}
        assert {"conn.log", "dns.log", "capture.passivedns", "ssl.log", "eve.json"} <= names

    def test_every_file_parses_through_a_production_parser(self, capture: Path) -> None:
        """The demo must not bypass the parsers it is demonstrating."""
        assert load_connections(capture).height > 10_000
        assert load_dns(capture).height > 1_000
        assert load_passivedns(capture).height > 1_000
        assert load_ssl(capture).height > 100
        assert load_alerts(capture).height > 1_000


class TestDemoDetection:
    def test_patient_zero_ranks_first(self, queue) -> None:  # type: ignore[no-untyped-def]
        assert queue.rank_of(PATIENT_ZERO) == 1

    def test_every_independent_behaviour_corroborates(self, queue) -> None:  # type: ignore[no-untyped-def]
        top = queue.incidents[0]
        behaviours = {p.value for p in top.corroborating_predicates}
        assert behaviours == {
            "beacons_to",
            "scans",
            "tunnels_dns_over",
            "triggered_signature",
            "resolves_algorithmic_domain",
        }

    def test_the_rare_fingerprint_is_reported_but_does_not_corroborate(self, queue) -> None:  # type: ignore[no-untyped-def]
        """Patient zero presents a TLS client nothing else in the estate runs.

        It belongs in the incident an analyst reads, and it raises the
        combined confidence through the noisy-OR. What it may not do is
        multiply the priority: the fingerprint is a property of the same
        channel the beaconing finding already scored.
        """
        top = queue.incidents[0]
        predicates = {f.predicate.value for f in top.incident.findings}
        assert "presents_rare_tls_fingerprint" in predicates
        assert "presents_rare_tls_fingerprint" not in {
            p.value for p in top.corroborating_predicates
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


class TestTheCommandItself:
    """The pipeline is tested above; this tests that the command runs it.

    Every assertion above reaches the analyzers directly, which is the right
    way to test detection and the wrong way to notice that `voidai demo` no
    longer starts. It did not, for the length of one commit: `demo` invokes
    `run` as a Python function, `run` is a typer command, and an argument left
    out of that call arrives as an `OptionInfo` rather than as its default —
    so adding one option to `run` broke a different command entirely, with a
    type error naming neither of them.
    """

    def test_demo_runs_end_to_end(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from voidai import cli

        result = CliRunner().invoke(cli.app, ["demo", "--keep", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "incident(s)" in result.output

    @pytest.mark.parametrize("command", ["run", "hunt"])
    def test_the_pipeline_commands_accept_an_intel_path(
        self, command: str, capture: Path, tmp_path: Path
    ) -> None:
        """`--intel` reaches the analyzer from both commands that detect.

        They share `_detect`, and a wiring mistake in one of them is invisible
        from the other.
        """
        from typer.testing import CliRunner

        from voidai import cli

        (tmp_path / "operator.ioc").write_text(
            f"# name: demo-fixture\n# confidence: 0.9\n# updated: 2025-06-01\n{PATIENT_ZERO}\n"
        )
        args = [command, str(capture), "--intel", str(tmp_path), "--no-receipt"]
        if command == "run":
            args.append("--no-llm")
        result = CliRunner().invoke(cli.app, args)
        assert result.exit_code == 0, result.output

    def test_every_queued_incident_states_a_reason(self, capture: Path) -> None:
        """No queue row may carry a priority and a blank Behaviours cell.

        The cell was built only from corroborating predicates. Five of the
        eighteen predicates no longer corroborate, so an incident whose
        findings are all of that kind — a lone rare TLS fingerprint — rendered
        with a severity, a priority and no stated reason. An analyst cannot
        triage a row that will not say why it is there.
        """
        from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext
        from voidai.cli import _behaviours_cell
        from voidai.correlate import build_queue
        from voidai.ingest.suricata import load_alerts
        from voidai.ingest.zeek import load_connections, load_dns, load_ssl

        ctx = AnalysisContext(
            connections=load_connections(capture),
            dns=load_dns(capture),
            alerts=load_alerts(capture),
            ssl=load_ssl(capture),
        )
        findings = []
        for analyzer in DEFAULT_ANALYZERS:
            findings += analyzer().analyze(ctx)

        queue = build_queue(findings)
        assert queue.incidents, "the demo capture must produce incidents"
        blank = [
            r.subject.value for r in queue.incidents if not _behaviours_cell(r).strip()
        ]
        assert not blank, f"incidents listed with no reason: {blank}"

    def test_a_wholly_non_corroborating_incident_still_states_a_reason(self) -> None:
        """The specific case, built directly rather than hoped for in a corpus."""
        from voidai.cli import _behaviours_cell
        from voidai.correlate import build_queue
        from voidai.lexicon import (
            Artifact,
            Entity,
            EntityType,
            Evidence,
            Finding,
            Predicate,
        )

        finding = Finding(
            predicate=Predicate.PRESENTS_RARE_TLS_FINGERPRINT,
            subject=Entity(type=EntityType.IP, value="10.0.3.52"),
            object=Entity(type=EntityType.TLS_FINGERPRINT, value="a" * 32),
            evidence=[
                Evidence(
                    kind="ja3_rarity",
                    summary="synthetic",
                    artifacts=[Artifact(source="ssl.log", locator="line:1")],
                )
            ],
            confidence=0.83,
            basis="synthetic",
            analyzer="test@0",
        )
        ranked = build_queue([finding]).incidents[0]
        assert not ranked.corroborating_predicates, "fixture must be non-corroborating"
        assert "presents_rare_tls_fingerprint" in _behaviours_cell(ranked)
