"""Correlation: findings into incidents, and incidents into an ordered queue.

## The problem this exists to solve

The beaconing analyzer finds the command-and-control channel in both CTU-13
scenarios tested. It also emits 395 findings on a two-hour capture, with the
true positive at rank 358. Detected and invisible are the same thing to an
analyst working a queue.

The instinct is to tighten the detector. That is wrong, and the data says so:
the high-scoring findings VoidAI cannot rank below the C2 are *genuinely*
beacon-like — perfectly regular, uniform payload, single-host destinations.
They are monitoring agents, backup jobs and keep-alives. No refinement of a
periodicity measure separates them, because on the axis of periodicity they
are not different.

## What actually separates a compromised host

It does more than one suspicious thing.

The CTU-13 scenario 6 host beacons every 33 seconds *and* mails 1,573 distinct
destinations on port 25 — rank 1 of 143,546 (host, port) pairs for fan-out.
Scenario 3's beacons *and* sweeps 26,702 hosts on port 22. Neither the
beaconing nor the fan-out signal is decisive alone: plenty of hosts beacon
benignly, and a busy workstation reaches more web servers than the spam bot
reached mail servers. Their conjunction is decisive, and no amount of tuning
either analyzer in isolation would find it.

So ranking belongs here, not in the analyzers. A `Finding` answers "how
beacon-like is this traffic?" An `Incident` answers "how much should an
analyst care about this host?" Conflating those two questions is what buried
the true positive at rank 358.

## How incidents are formed

By subject. Every finding about one host becomes one incident, because "what
is this host doing?" is the unit a responder actually works in.

Findings are deliberately *not* joined through shared destinations. Doing so
collapses the whole estate into a single component the moment two hosts touch
one popular address — and on a university network they do, immediately.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from voidai.lexicon import Entity, Finding, Incident, Predicate, Severity


@dataclass(frozen=True)
class CorrelationConfig:
    """Tunables for incident formation and priority."""

    #: Multiplier applied per additional independent predicate. Two distinct
    #: categories of suspicious behaviour on one host score 1.5x, three 2.0x.
    corroboration_bonus: float = 0.5
    #: Cap on the corroboration multiplier, so a host with many weak findings
    #: cannot climb past one with strong, genuinely independent evidence.
    max_corroboration_multiplier: float = 2.5

    #: Predicates that contribute evidence but do not count as an independent
    #: behaviour. A finding here still raises its host's combined confidence
    #: through the noisy-OR and still appears in the incident an analyst
    #: reads; what it may not do is multiply the priority, because a
    #: multiplier is a claim that two *separate* things were seen.
    #:
    #: Three reasons put a predicate in this set, and all three are the same
    #: rule at different levels — see roadmap rule 6.
    #:
    #: `shares_infrastructure_with` and `precedes` describe the environment,
    #: or VoidAI's own reasoning about two observations. They are bookkeeping,
    #: and a pair of bookkeeping entries is not two opinions.
    #:
    #: `contacts_rare_destination` is a real observation about the host, but
    #: it rests on a single cheap signal — estate-wide prevalence — and every
    #: host that talks to anything unusual earns one.
    #:
    #: `transfers_anomalous_volume` is the claim the egress analyzer makes
    #: when it *cannot* make the stronger one: either the sensor recorded no
    #: direction, or the four signals did not reach the exfiltration
    #: threshold. Partial evidence, by construction. Measured on CTU-13
    #: scenario 3: letting it corroborate moved the infected host from queue
    #: rank 2 to rank 5 and took corroborated incidents from 3 to 33, while
    #: contributing nothing to the true positive — which had no volume
    #: finding at all. On scenario 6 the bot's incident keeps its volume
    #: finding and still ranks 1, which is the shape wanted: evidence
    #: retained, false promotion removed.
    non_corroborating: frozenset[Predicate] = frozenset(
        {
            Predicate.SHARES_INFRASTRUCTURE_WITH,
            Predicate.PRECEDES,
            Predicate.CONTACTS_RARE_DESTINATION,
            Predicate.TRANSFERS_ANOMALOUS_VOLUME,
        }
    )


@dataclass
class RankedIncident:
    """An incident with the arithmetic behind its position in the queue."""

    incident: Incident
    priority: float
    combined_confidence: float
    corroborating_predicates: tuple[Predicate, ...]
    rationale: str

    @property
    def subject(self) -> Entity:
        return self.incident.findings[0].subject


def _noisy_or(confidences: list[float]) -> float:
    """Combine independent evidence: the chance at least one is real.

    Standard noisy-OR. Two independent findings at 0.7 and 0.6 combine to
    0.88, because for both to be wrong each must independently be wrong.

    Applied to the strongest finding *per predicate* rather than to every
    finding. Twenty beaconing findings on one host are twenty views of the
    same behaviour, not twenty independent reasons to believe it — treating
    them as independent would let a chatty analyzer manufacture certainty.
    """
    survival = 1.0
    for confidence in confidences:
        survival *= 1.0 - min(max(confidence, 0.0), 1.0)
    return 1.0 - survival


def correlate(
    findings: list[Finding],
    config: CorrelationConfig | None = None,
) -> list[RankedIncident]:
    """Group findings by subject and order the result by priority.

    Deterministic, like everything upstream of the language layer: the same
    findings produce the same incidents in the same order.
    """
    config = config or CorrelationConfig()
    if not findings:
        return []

    by_subject: dict[str, list[Finding]] = {}
    for finding in findings:
        by_subject.setdefault(finding.subject.id, []).append(finding)

    ranked = [
        _rank(subject_findings, config)
        for subject_findings in by_subject.values()
    ]
    # Ties broken by severity then subject id, so ordering is total and stable
    # across runs rather than dependent on dictionary insertion.
    ranked.sort(
        key=lambda r: (
            -r.priority,
            -(r.incident.severity.rank),
            r.incident.id,
        )
    )
    return ranked


def _rank(findings: list[Finding], config: CorrelationConfig) -> RankedIncident:
    """Score one subject's findings into a priority."""
    strongest: dict[Predicate, float] = {}
    for finding in findings:
        current = strongest.get(finding.predicate, 0.0)
        strongest[finding.predicate] = max(current, finding.confidence)

    combined = _noisy_or(list(strongest.values()))

    corroborating = tuple(
        sorted(
            (p for p in strongest if p not in config.non_corroborating),
            key=lambda p: p.value,
        )
    )
    multiplier = min(
        1.0 + config.corroboration_bonus * max(len(corroborating) - 1, 0),
        config.max_corroboration_multiplier,
    )
    priority = combined * multiplier

    incident = Incident(
        findings=sorted(findings, key=lambda f: -f.confidence),
        score=round(priority, 4),
    )

    return RankedIncident(
        incident=incident,
        priority=priority,
        combined_confidence=combined,
        corroborating_predicates=corroborating,
        rationale=_rationale(strongest, combined, multiplier, corroborating),
    )


def _rationale(
    strongest: dict[Predicate, float],
    combined: float,
    multiplier: float,
    corroborating: tuple[Predicate, ...],
) -> str:
    """Explain the priority in one checkable line.

    Same rule as a Finding's `basis`: a score an analyst cannot audit is a
    score they have no reason to trust.
    """
    parts = ", ".join(
        f"{predicate.value}={confidence:.2f}"
        for predicate, confidence in sorted(strongest.items(), key=lambda kv: kv[0].value)
    )
    if len(corroborating) > 1:
        corroboration = (
            f"; {len(corroborating)} independent behaviours corroborate "
            f"(x{multiplier:.1f})"
        )
    else:
        corroboration = "; single behaviour, no corroboration"
    return f"noisy-OR of [{parts}] = {combined:.3f}{corroboration}"


@dataclass
class IncidentQueue:
    """The analyst-facing result of a run."""

    incidents: list[RankedIncident] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.incidents)

    def top(self, count: int) -> list[RankedIncident]:
        return self.incidents[:count]

    def rank_of(self, subject_value: str) -> int | None:
        """1-based position of a subject, or None if absent.

        The measure that matters for the benchmark: a true positive at rank 3
        gets worked, and the same true positive at rank 358 does not.
        """
        for position, ranked in enumerate(self.incidents, start=1):
            if ranked.subject.value == subject_value:
                return position
        return None

    @property
    def corroborated(self) -> list[RankedIncident]:
        return [r for r in self.incidents if len(r.corroborating_predicates) > 1]

    def severity_counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for ranked in self.incidents:
            counts[ranked.incident.severity] = counts.get(ranked.incident.severity, 0) + 1
        return counts


def build_queue(
    findings: list[Finding],
    config: CorrelationConfig | None = None,
) -> IncidentQueue:
    return IncidentQueue(incidents=correlate(findings, config))
