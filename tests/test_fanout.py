"""Tests for horizontal fan-out detection.

The separation these assert is the one measured on CTU-13: a spam bot reaching
1,573 mail servers at 3.3 flows each must score high, while a user reaching
1,486 web servers at 51.8 flows each must not. Breadth alone cannot tell them
apart — revisiting can.
"""

from __future__ import annotations

import polars as pl
import pytest

from voidai.analyzers import AnalysisContext, FanoutAnalyzer, FanoutConfig, score_fanout
from voidai.ingest.schema import CONNECTION_SCHEMA, conform
from voidai.lexicon import EntityType, Predicate


class TestScoreFanout:
    def test_spam_run_scores_high(self) -> None:
        """CTU-13 scenario 6: 1,573 destinations on port 25, 3.3 flows each."""
        score = score_fanout(destinations=1573, flows=5203, config=FanoutConfig())
        assert score is not None
        assert score.score >= FanoutConfig().score_threshold

    def test_browsing_scores_low_despite_more_destinations(self) -> None:
        """The measured false positive that motivates the revisiting term.

        This host reaches *more* destinations than the spam bot. Breadth alone
        would rank it higher.
        """
        browsing = score_fanout(destinations=1486, flows=77036, config=FanoutConfig())
        spam = score_fanout(destinations=1573, flows=5203, config=FanoutConfig())
        assert browsing is not None and spam is not None
        assert browsing.score < FanoutConfig().score_threshold
        assert browsing.score < spam.score
        assert browsing.destinations < spam.destinations  # breadth favours browsing

    def test_ssh_sweep_scores_high(self) -> None:
        """CTU-13 scenario 3: 26,702 hosts on port 22, 1.9 flows each."""
        score = score_fanout(destinations=26702, flows=51501, config=FanoutConfig())
        assert score is not None
        assert score.score > 0.85

    def test_too_few_destinations_returns_none(self) -> None:
        assert score_fanout(destinations=10, flows=40, config=FanoutConfig()) is None

    def test_zero_flows_returns_none(self) -> None:
        assert score_fanout(destinations=100, flows=0, config=FanoutConfig()) is None

    def test_single_visit_per_destination_is_maximal(self) -> None:
        score = score_fanout(destinations=500, flows=500, config=FanoutConfig())
        assert score is not None
        assert score.components["non_revisiting"] == pytest.approx(1.0)

    def test_score_increases_with_breadth(self) -> None:
        narrow = score_fanout(destinations=60, flows=60, config=FanoutConfig())
        wide = score_fanout(destinations=5000, flows=5000, config=FanoutConfig())
        assert narrow is not None and wide is not None
        assert wide.score > narrow.score

    def test_basis_names_every_component(self) -> None:
        score = score_fanout(destinations=1573, flows=5203, config=FanoutConfig())
        assert score is not None
        for component in score.components:
            assert component in score.basis()


def _capture(rows: list[dict[str, object]]) -> pl.DataFrame:
    return conform(pl.DataFrame(rows), CONNECTION_SCHEMA)


def _sweep(src: str, port: int, destinations: int, flows_each: int = 1) -> list[dict[str, object]]:
    rows = []
    for index in range(destinations):
        for repeat in range(flows_each):
            rows.append(
                {
                    "ts": 1_750_000_000.0 + index * 2 + repeat,
                    "src_ip": src,
                    "src_port": 40000 + index,
                    "dst_ip": f"203.0.{index // 254}.{index % 254 + 1}",
                    "dst_port": port,
                    "proto": "tcp",
                    "orig_bytes": 400,
                    "source_file": "<synthetic>",
                    "source_line": len(rows) + 1,
                }
            )
    return rows


class TestFanoutAnalyzer:
    def test_detects_a_sweep(self) -> None:
        capture = _capture(_sweep("10.0.0.5", 22, destinations=400))
        findings = FanoutAnalyzer().analyze(AnalysisContext(connections=capture))
        assert len(findings) == 1
        assert findings[0].predicate is Predicate.SCANS
        assert findings[0].subject.value == "10.0.0.5"
        assert findings[0].object is not None
        assert findings[0].object.type is EntityType.PORT
        assert findings[0].object.value == "22"

    def test_ignores_heavy_revisiting(self) -> None:
        capture = _capture(_sweep("10.0.0.6", 443, destinations=300, flows_each=40))
        assert FanoutAnalyzer().analyze(AnalysisContext(connections=capture)) == []

    def test_ignores_resolver_ports(self) -> None:
        """A resolver talks to the world by design."""
        capture = _capture(_sweep("10.0.0.7", 53, destinations=900))
        assert FanoutAnalyzer().analyze(AnalysisContext(connections=capture)) == []

    def test_carries_resolvable_evidence(self) -> None:
        capture = _capture(_sweep("10.0.0.5", 22, destinations=400))
        finding = FanoutAnalyzer().analyze(AnalysisContext(connections=capture))[0]
        assert finding.evidence
        for evidence in finding.evidence:
            assert evidence.artifacts
            for artifact in evidence.artifacts:
                assert artifact.source and artifact.locator
        assert evidence.payload["destinations"] == 400

    def test_is_deterministic(self) -> None:
        capture = _capture(_sweep("10.0.0.5", 22, destinations=400))
        ctx = AnalysisContext(connections=capture)
        assert [f.id for f in FanoutAnalyzer().analyze(ctx)] == [
            f.id for f in FanoutAnalyzer().analyze(ctx)
        ]

    def test_lazy_and_eager_agree(self) -> None:
        capture = _capture(_sweep("10.0.0.5", 22, destinations=400))
        eager = FanoutAnalyzer().analyze(AnalysisContext(connections=capture))
        lazy = FanoutAnalyzer().analyze(AnalysisContext(connections=capture.lazy()))
        assert [f.id for f in eager] == [f.id for f in lazy]

    def test_empty_input(self) -> None:
        empty = conform(pl.DataFrame(), CONNECTION_SCHEMA)
        assert FanoutAnalyzer().analyze(AnalysisContext(connections=empty)) == []

    def test_max_findings_is_respected(self) -> None:
        rows = _sweep("10.0.0.5", 22, destinations=300) + _sweep("10.0.0.6", 23, destinations=300)
        analyzer = FanoutAnalyzer(FanoutConfig(max_findings=1))
        assert len(analyzer.analyze(AnalysisContext(connections=_capture(rows)))) == 1
