"""Tests for correlation and incident ranking.

The property under test is the one that took the CTU-13 true positive from
rank 358 of 395 to rank 1 of 133: a host exhibiting two independent
suspicious behaviours must outrank a host exhibiting one, even when the
single behaviour scores higher in isolation.
"""

from __future__ import annotations

import pytest

from voidai.correlate import CorrelationConfig, build_queue, correlate
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Predicate,
    Severity,
)


def _evidence(kind: str = "interval_regularity") -> Evidence:
    return Evidence(
        kind=kind,
        summary="synthetic evidence",
        artifacts=[Artifact(source="conn.log", locator=f"line:{abs(hash(kind)) % 1000}")],
    )


def beacon(host: str, target: str, confidence: float) -> Finding:
    return Finding(
        predicate=Predicate.BEACONS_TO,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.IP, value=target),
        evidence=[_evidence()],
        confidence=confidence,
        basis="synthetic",
        analyzer="beaconing@test",
    )


def scan(host: str, port: int, confidence: float) -> Finding:
    return Finding(
        predicate=Predicate.SCANS,
        subject=Entity(type=EntityType.IP, value=host),
        object=Entity(type=EntityType.PORT, value=str(port)),
        evidence=[_evidence("destination_fanout")],
        confidence=confidence,
        basis="synthetic",
        analyzer="fanout@test",
    )


class TestCorroboration:
    def test_two_behaviours_outrank_one_stronger_one(self) -> None:
        """The CTU-13 result in miniature.

        The compromised host beacons at 0.75 — weaker than the 0.99 monitoring
        agent it was buried under — but it also sweeps port 25.
        """
        queue = build_queue(
            [
                beacon("10.0.0.9", "198.51.100.1", 0.99),  # a monitoring agent
                beacon("10.0.0.5", "203.0.113.7", 0.75),  # the compromised host
                scan("10.0.0.5", 25, 0.90),
            ]
        )
        assert queue.rank_of("10.0.0.5") == 1
        assert queue.rank_of("10.0.0.9") == 2

    def test_single_behaviour_gets_no_multiplier(self) -> None:
        ranked = correlate([beacon("10.0.0.5", "203.0.113.7", 0.80)])[0]
        assert ranked.priority == pytest.approx(0.80)
        assert "no corroboration" in ranked.rationale

    def test_multiplier_grows_with_distinct_behaviours(self) -> None:
        one = correlate([beacon("10.0.0.5", "203.0.113.7", 0.8)])[0]
        two = correlate([beacon("10.0.0.5", "203.0.113.7", 0.8), scan("10.0.0.5", 25, 0.8)])[0]
        assert two.priority > one.priority * 1.4

    def test_multiplier_is_capped(self) -> None:
        config = CorrelationConfig(max_corroboration_multiplier=1.5)
        ranked = correlate(
            [
                beacon("10.0.0.5", "203.0.113.7", 0.9),
                scan("10.0.0.5", 25, 0.9),
                scan("10.0.0.5", 22, 0.9),
            ],
            config,
        )[0]
        assert ranked.priority <= 1.0 * 1.5

    def test_repeated_findings_of_one_kind_are_not_corroboration(self) -> None:
        """Twenty views of one behaviour are not twenty independent opinions.

        Without this, a chatty analyzer could manufacture certainty simply by
        emitting more findings about the same thing.
        """
        many = [beacon("10.0.0.5", f"203.0.113.{i}", 0.8) for i in range(1, 21)]
        ranked = correlate(many)[0]
        assert len(ranked.corroborating_predicates) == 1
        assert ranked.priority == pytest.approx(0.8)

    def test_strongest_finding_per_predicate_is_used(self) -> None:
        ranked = correlate(
            [beacon("10.0.0.5", "203.0.113.1", 0.4), beacon("10.0.0.5", "203.0.113.2", 0.9)]
        )[0]
        assert ranked.combined_confidence == pytest.approx(0.9)


class TestIncidentFormation:
    def test_groups_by_subject(self) -> None:
        queue = build_queue(
            [
                beacon("10.0.0.5", "203.0.113.1", 0.8),
                beacon("10.0.0.5", "203.0.113.2", 0.9),
                beacon("10.0.0.6", "203.0.113.3", 0.7),
            ]
        )
        assert len(queue) == 2
        assert len(queue.incidents[0].incident.findings) == 2

    def test_shared_destinations_do_not_merge_hosts(self) -> None:
        """Joining through destinations collapses an estate into one incident."""
        queue = build_queue(
            [beacon(f"10.0.0.{i}", "203.0.113.1", 0.8) for i in range(1, 20)]
        )
        assert len(queue) == 19

    def test_incident_takes_highest_finding_severity(self) -> None:
        ranked = correlate([beacon("10.0.0.5", "203.0.113.1", 0.95)])[0]
        assert ranked.incident.severity is Severity.HIGH

    def test_findings_are_ordered_by_confidence(self) -> None:
        ranked = correlate(
            [beacon("10.0.0.5", "203.0.113.1", 0.4), beacon("10.0.0.5", "203.0.113.2", 0.9)]
        )[0]
        confidences = [f.confidence for f in ranked.incident.findings]
        assert confidences == sorted(confidences, reverse=True)

    def test_empty_input(self) -> None:
        assert correlate([]) == []
        assert len(build_queue([])) == 0


class TestQueue:
    def test_ordering_is_deterministic(self) -> None:
        findings = [beacon(f"10.0.0.{i}", "203.0.113.1", 0.8) for i in range(1, 30)]
        first = [r.subject.value for r in build_queue(findings).incidents]
        second = [r.subject.value for r in build_queue(list(reversed(findings))).incidents]
        assert first == second

    def test_rank_of_absent_subject(self) -> None:
        queue = build_queue([beacon("10.0.0.5", "203.0.113.1", 0.8)])
        assert queue.rank_of("10.0.0.99") is None

    def test_corroborated_subset(self) -> None:
        queue = build_queue(
            [
                beacon("10.0.0.5", "203.0.113.1", 0.8),
                scan("10.0.0.5", 25, 0.8),
                beacon("10.0.0.6", "203.0.113.2", 0.9),
            ]
        )
        assert [r.subject.value for r in queue.corroborated] == ["10.0.0.5"]

    def test_top_respects_the_limit(self) -> None:
        queue = build_queue([beacon(f"10.0.0.{i}", "203.0.113.1", 0.8) for i in range(1, 10)])
        assert len(queue.top(3)) == 3

    def test_rationale_is_auditable(self) -> None:
        """A priority an analyst cannot check is one they cannot trust."""
        ranked = correlate([beacon("10.0.0.5", "203.0.113.1", 0.75), scan("10.0.0.5", 25, 0.9)])[0]
        assert "beacons_to=0.75" in ranked.rationale
        assert "scans=0.90" in ranked.rationale
        assert "corroborate" in ranked.rationale

    def test_severity_counts(self) -> None:
        queue = build_queue(
            [beacon("10.0.0.5", "203.0.113.1", 0.8), scan("10.0.0.6", 25, 0.6)]
        )
        counts = queue.severity_counts()
        assert sum(counts.values()) == 2
