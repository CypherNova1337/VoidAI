"""The Lexicon's guarantees, tested as guarantees rather than as behaviour.

Each test here corresponds to a claim the project makes in its documentation.
If one of these fails, a sentence in the README has become false.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    GrammarError,
    Incident,
    Predicate,
    Severity,
    validate_proposition,
)


@pytest.fixture
def artifact() -> Artifact:
    return Artifact(source="conn.log", locator="line:100", excerpt="10.0.0.1 -> 8.8.8.8")


@pytest.fixture
def evidence(artifact: Artifact) -> Evidence:
    return Evidence(
        kind="interval_regularity",
        summary="240 connections at 60.0s intervals",
        payload={"period_seconds": 60.0, "sample_count": 240},
        artifacts=[artifact],
    )


@pytest.fixture
def host() -> Entity:
    return Entity(type=EntityType.HOST, value="WEB01")


@pytest.fixture
def domain() -> Entity:
    return Entity(type=EntityType.DOMAIN, value="c2.example.net")


class TestContentAddressing:
    """Reproducible IDs — the property that makes citations durable."""

    def test_identical_content_yields_identical_id(self, artifact: Artifact) -> None:
        twin = Artifact(source="conn.log", locator="line:100", excerpt="different excerpt")
        assert artifact.id == twin.id  # identity is source+locator, not display text

    def test_different_content_yields_different_id(self, artifact: Artifact) -> None:
        other = Artifact(source="conn.log", locator="line:101")
        assert artifact.id != other.id

    def test_entity_ids_are_case_insensitive(self) -> None:
        assert (
            Entity(type=EntityType.HOST, value="WEB01").id
            == Entity(type=EntityType.HOST, value="web01").id
        )

    def test_entity_type_participates_in_identity(self) -> None:
        assert (
            Entity(type=EntityType.HOST, value="example.com").id
            != Entity(type=EntityType.DOMAIN, value="example.com").id
        )

    def test_evidence_order_of_artifacts_does_not_change_id(self, artifact: Artifact) -> None:
        second = Artifact(source="conn.log", locator="line:200")
        forward = Evidence(kind="k", summary="s", artifacts=[artifact, second])
        reverse = Evidence(kind="k", summary="s", artifacts=[second, artifact])
        assert forward.id == reverse.id

    def test_ids_carry_a_type_prefix(self, artifact: Artifact, evidence: Evidence) -> None:
        assert artifact.id.startswith("art_")
        assert evidence.id.startswith("ev_")


class TestGrammar:
    """The closed vocabulary: what the system is and is not able to say."""

    def test_valid_proposition_passes(self) -> None:
        validate_proposition(Predicate.BEACONS_TO, EntityType.HOST, EntityType.DOMAIN)

    def test_rejects_wrong_subject_type(self) -> None:
        with pytest.raises(GrammarError, match="cannot take a domain as subject"):
            validate_proposition(Predicate.BEACONS_TO, EntityType.DOMAIN, EntityType.IP)

    def test_rejects_wrong_object_type(self) -> None:
        with pytest.raises(GrammarError, match="cannot take a user as object"):
            validate_proposition(Predicate.BEACONS_TO, EntityType.HOST, EntityType.USER)

    def test_unary_predicate_rejects_an_object(self) -> None:
        with pytest.raises(GrammarError, match="unary"):
            validate_proposition(Predicate.MATCHES_THREAT_INTEL, EntityType.IP, EntityType.DOMAIN)

    def test_binary_predicate_requires_an_object(self) -> None:
        with pytest.raises(GrammarError, match="requires an object"):
            validate_proposition(Predicate.BEACONS_TO, EntityType.HOST, None)

    def test_every_predicate_has_a_grammar_rule(self) -> None:
        """No predicate may exist without a declared, enforceable signature."""
        for predicate in Predicate:
            spec = predicate.spec
            assert spec.subject_types, f"{predicate.value} has no permitted subjects"
            assert spec.description.strip(), f"{predicate.value} has no description"


class TestFindingRequiresEvidence:
    """The central claim: an unevidenced assertion cannot be constructed."""

    def test_finding_with_no_evidence_is_rejected(self, host: Entity, domain: Entity) -> None:
        with pytest.raises(ValidationError):
            Finding(
                predicate=Predicate.BEACONS_TO,
                subject=host,
                object=domain,
                evidence=[],
                confidence=0.99,
                basis="trust me",
                analyzer="test@0",
            )

    def test_evidence_with_no_artifact_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Evidence(kind="k", summary="s", artifacts=[])

    def test_ungrammatical_finding_is_rejected(self, evidence: Evidence, host: Entity) -> None:
        with pytest.raises(ValidationError):
            Finding(
                predicate=Predicate.BEACONS_TO,
                subject=Entity(type=EntityType.DOMAIN, value="bad.example"),
                object=host,
                evidence=[evidence],
                confidence=0.5,
                basis="x",
                analyzer="test@0",
            )

    def test_confidence_must_be_a_probability(self, evidence: Evidence, host: Entity, domain: Entity) -> None:
        for bad in (-0.1, 1.5):
            with pytest.raises(ValidationError):
                Finding(
                    predicate=Predicate.BEACONS_TO,
                    subject=host,
                    object=domain,
                    evidence=[evidence],
                    confidence=bad,
                    basis="x",
                    analyzer="test@0",
                )

    def test_basis_may_not_be_empty(self, evidence: Evidence, host: Entity, domain: Entity) -> None:
        """An unexplained confidence score is a guess wearing a number."""
        with pytest.raises(ValidationError):
            Finding(
                predicate=Predicate.BEACONS_TO,
                subject=host,
                object=domain,
                evidence=[evidence],
                confidence=0.9,
                basis="",
                analyzer="test@0",
            )


class TestFindingDefaults:
    def test_inherits_severity_and_techniques_from_grammar(
        self, evidence: Evidence, host: Entity, domain: Entity
    ) -> None:
        finding = Finding(
            predicate=Predicate.BEACONS_TO,
            subject=host,
            object=domain,
            evidence=[evidence],
            confidence=0.8,
            basis="measured",
            analyzer="test@0",
        )
        assert finding.severity == Severity.HIGH
        assert "T1071" in finding.attack_techniques

    def test_explicit_severity_overrides_default(
        self, evidence: Evidence, host: Entity, domain: Entity
    ) -> None:
        finding = Finding(
            predicate=Predicate.BEACONS_TO,
            subject=host,
            object=domain,
            evidence=[evidence],
            confidence=0.95,
            basis="measured",
            analyzer="test@0",
            severity=Severity.CRITICAL,
        )
        assert finding.severity == Severity.CRITICAL

    def test_renders_a_readable_sentence(
        self, evidence: Evidence, host: Entity, domain: Entity
    ) -> None:
        finding = Finding(
            predicate=Predicate.BEACONS_TO,
            subject=host,
            object=domain,
            evidence=[evidence],
            confidence=0.8,
            basis="measured",
            analyzer="test@0",
        )
        assert finding.sentence() == "host:WEB01 beacons to domain:c2.example.net"


class TestIncident:
    @pytest.fixture
    def finding(self, evidence: Evidence, host: Entity, domain: Entity) -> Finding:
        return Finding(
            predicate=Predicate.BEACONS_TO,
            subject=host,
            object=domain,
            evidence=[evidence],
            confidence=0.9,
            basis="measured",
            analyzer="test@0",
        )

    def test_takes_the_highest_severity_of_its_findings(self, finding: Finding) -> None:
        assert Incident(findings=[finding]).severity == Severity.HIGH

    def test_requires_at_least_one_finding(self) -> None:
        with pytest.raises(ValidationError):
            Incident(findings=[])

    def test_indexes_expose_the_evidence_chain(self, finding: Finding) -> None:
        incident = Incident(findings=[finding])
        assert finding.id in incident.finding_index()
        assert finding.evidence_ids()[0] in incident.evidence_index()

    def test_narrative_is_absent_by_default(self, finding: Finding) -> None:
        """A --no-llm run produces incidents with no narrative and no claims."""
        incident = Incident(findings=[finding])
        assert incident.narrative is None
        assert incident.verified_claims() == []
