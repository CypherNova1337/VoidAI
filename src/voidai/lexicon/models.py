"""The objects of the Lexicon.

The chain of custody runs strictly one way:

    Artifact  →  Evidence  →  Finding  →  Incident  →  Claim
    (raw byte   (measured    (grounded   (correlated  (language-layer
     location)   observation) assertion)  cluster)     commentary)

Nothing may skip a link. A Finding with no Evidence is rejected at
construction; a Claim citing an unknown Finding is struck by the verifier.
Both are enforced here rather than by convention, because a provenance rule
that lives in a style guide is a provenance rule that is already broken.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from voidai.lexicon.ids import (
    artifact_id,
    entity_id,
    evidence_id,
    finding_id,
    incident_id,
)
from voidai.lexicon.vocabulary import (
    EntityType,
    Predicate,
    Severity,
    validate_proposition,
)

_MAX_EXCERPT = 512


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Artifact(_Frozen):
    """A pointer into raw source data. The bottom of the evidence chain.

    An Artifact must be sufficient for an analyst to independently retrieve
    the original record. "Trust me" is not a locator.
    """

    id: str = ""
    source: str = Field(description="File path, stream name, or sensor identifier.")
    locator: str = Field(description="Line number, byte offset, packet index, or record key.")
    observed_at: datetime | None = None
    excerpt: str | None = Field(
        default=None,
        description="Verbatim slice of the original record, truncated for display.",
    )

    @field_validator("excerpt")
    @classmethod
    def _truncate(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return v if len(v) <= _MAX_EXCERPT else v[: _MAX_EXCERPT - 1] + "…"

    @model_validator(mode="after")
    def _assign_id(self) -> Artifact:
        if not self.id:
            object.__setattr__(self, "id", artifact_id(self.source, self.locator))
        return self


class Evidence(_Frozen):
    """A structured, measured observation bound to one or more Artifacts.

    `payload` holds the numbers an analyst would want to check: the measured
    interval, the computed entropy, the observed byte count. It is not prose.
    """

    id: str = ""
    kind: str = Field(description="Machine-readable observation type, e.g. 'interval_regularity'.")
    summary: str = Field(description="One line an analyst can read without decoding the payload.")
    payload: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[Artifact] = Field(min_length=1)

    @model_validator(mode="after")
    def _assign_id(self) -> Evidence:
        if not self.id:
            object.__setattr__(
                self,
                "id",
                evidence_id(self.kind, self.payload, [a.id for a in self.artifacts]),
            )
        return self

    def artifact_ids(self) -> list[str]:
        return [a.id for a in self.artifacts]


class Entity(_Frozen):
    """A noun: the thing a proposition is about."""

    id: str = ""
    type: EntityType
    value: str

    @model_validator(mode="after")
    def _assign_id(self) -> Entity:
        if not self.value.strip():
            raise ValueError("entity value must not be empty")
        if not self.id:
            object.__setattr__(self, "id", entity_id(self.type.value, self.value))
        return self

    def __str__(self) -> str:
        return f"{self.type.value}:{self.value}"


class Finding(_Frozen):
    """A grounded assertion: one sentence in the Lexicon.

    Constructing a Finding runs two checks that cannot be bypassed:

    1. The proposition is grammatical (`validate_proposition`).
    2. At least one Evidence object supports it.

    An analyzer that cannot satisfy both is not permitted to speak.
    """

    id: str = ""
    predicate: Predicate
    subject: Entity
    object: Entity | None = None
    evidence: list[Evidence] = Field(min_length=1)

    confidence: float = Field(ge=0.0, le=1.0)
    basis: str = Field(
        min_length=1,
        description="How the confidence was derived. Required: an unexplained score is a guess.",
    )
    severity: Severity | None = None
    analyzer: str = Field(description="Name and version of the component that produced this.")
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    attack_techniques: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _validate(self) -> Finding:
        validate_proposition(
            self.predicate,
            self.subject.type,
            self.object.type if self.object else None,
        )

        spec = self.predicate.spec
        if self.severity is None:
            object.__setattr__(self, "severity", spec.default_severity)
        if not self.attack_techniques:
            object.__setattr__(self, "attack_techniques", spec.attack_techniques)
        if not self.id:
            object.__setattr__(
                self,
                "id",
                finding_id(
                    self.predicate.value,
                    self.subject.id,
                    self.object.id if self.object else None,
                    [e.id for e in self.evidence],
                ),
            )
        return self

    def evidence_ids(self) -> list[str]:
        return [e.id for e in self.evidence]

    def entities(self) -> list[Entity]:
        return [self.subject] + ([self.object] if self.object else [])

    def sentence(self) -> str:
        """Render the proposition as a readable sentence."""
        verb = self.predicate.value.replace("_", " ")
        if self.object is None:
            return f"{self.subject} {verb}"
        return f"{self.subject} {verb} {self.object}"


class Claim(BaseModel):
    """A language-layer assertion, produced by the reasoning model.

    A Claim carries no authority of its own. It is an interpretation of
    Findings, and it survives only if every ID it cites resolves. See
    `voidai.reason.verifier`.
    """

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1)
    cites: list[str] = Field(
        default_factory=list,
        description="Finding or Evidence IDs supporting this claim.",
    )
    verified: bool = False
    rejection_reason: str | None = None


class Incident(BaseModel):
    """A correlated cluster of Findings sharing entities and a time window."""

    model_config = ConfigDict(extra="forbid")

    id: str = ""
    title: str = ""
    findings: list[Finding] = Field(min_length=1)
    severity: Severity = Severity.INFO
    score: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Populated by the reasoning layer. Absent in --no-llm runs, which is not
    # a degraded mode: the findings above stand on their own.
    narrative: str | None = None
    claims: list[Claim] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _assign(self) -> Incident:
        if not self.id:
            self.id = incident_id([f.id for f in self.findings])
        if self.severity == Severity.INFO and self.findings:
            self.severity = max(
                (f.severity for f in self.findings if f.severity),
                key=lambda s: s.rank,
                default=Severity.INFO,
            )
        if not self.title:
            self.title = self._derive_title()
        return self

    def _derive_title(self) -> str:
        top = max(self.findings, key=lambda f: (f.severity.rank if f.severity else 0, f.confidence))
        subjects = {f.subject.value for f in self.findings}
        host = top.subject.value if len(subjects) == 1 else f"{len(subjects)} hosts"
        return f"{top.predicate.value.replace('_', ' ').title()} — {host}"

    def entities(self) -> list[Entity]:
        seen: dict[str, Entity] = {}
        for f in self.findings:
            for e in f.entities():
                seen.setdefault(e.id, e)
        return list(seen.values())

    def evidence_index(self) -> dict[str, Evidence]:
        return {e.id: e for f in self.findings for e in f.evidence}

    def finding_index(self) -> dict[str, Finding]:
        return {f.id: f for f in self.findings}

    def verified_claims(self) -> list[Claim]:
        return [c for c in self.claims if c.verified]
