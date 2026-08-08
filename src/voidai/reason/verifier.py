"""The claim verifier: the last gate before an analyst sees a sentence.

A grammar can force the model to emit well-formed citations. It cannot force
it to emit *true* ones. Small models cite confidently and wrongly — a
plausible-looking `fnd_` id that was never in the brief, or a real id attached
to a claim it does not support. That is the failure mode this module exists
to catch.

The rule is the same one the Lexicon enforces upstream: a claim with no
resolvable evidence is not "low confidence", it is **unsayable**. It does not
reach the report.

Three checks, in order of how often they fire on real output:

  **Resolution** — every cited ID must appear in the brief the model was
  shown. Not merely "exist somewhere": a model must not cite a finding from a
  different incident it happened to see earlier in the run.

  **Attribution** — a claim citing nothing is struck. The prompt asks for a
  citation on every claim, and a model that ignores that has produced prose,
  not a finding.

  **Fabrication** — claims naming addresses, hostnames or ports absent from
  the cited findings are struck. This is the check that catches the most
  dangerous output, because an invented IP address in an incident report reads
  exactly like a real one.

Struck claims are kept, not deleted, with the reason recorded. An analyst
auditing the tool needs to see what it refused to say, and the count of
strikes is reported on every run receipt as a standing measure of how much the
model is confabulating.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from voidai.lexicon import Claim, Finding

#: Tokens that look like network identifiers. Deliberately broad: over-
#: matching costs a struck claim the model could have kept, while under-
#: matching lets a fabricated address through, and those are not equally bad.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_PORT = re.compile(r"\bport\s+(\d{1,5})\b", re.IGNORECASE)

#: Words a claim may use about ports without naming one that must resolve.
_GENERIC_DOMAINS = frozenset({"e.g", "i.e"})


class StrikeReason:
    NO_CITATION = "no citation"
    UNRESOLVED_CITATION = "cites an unknown finding"
    FABRICATED_ENTITY = "names an entity absent from the cited evidence"


@dataclass
class VerificationReport:
    """What survived, what did not, and why."""

    claims: list[Claim] = field(default_factory=list)
    narrative: str = ""
    actions: list[str] = field(default_factory=list)
    narrative_struck: bool = False

    @property
    def verified(self) -> list[Claim]:
        return [c for c in self.claims if c.verified]

    @property
    def struck(self) -> list[Claim]:
        return [c for c in self.claims if not c.verified]

    @property
    def strike_count(self) -> int:
        return len(self.struck)

    @property
    def strike_rate(self) -> float:
        return self.strike_count / len(self.claims) if self.claims else 0.0


def _entities_in(text: str) -> tuple[set[str], set[str]]:
    """Extract addresses/domains and ports a sentence commits to."""
    addresses = set(_IPV4.findall(text))
    for candidate in _DOMAIN.findall(text):
        lowered = candidate.lower()
        if lowered in _GENERIC_DOMAINS:
            continue
        # An IPv4 literal also matches the domain pattern; classify it once.
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            addresses.add(lowered)
    return addresses, set(_PORT.findall(text))


def _grounded_vocabulary(findings: list[Finding]) -> tuple[set[str], set[str]]:
    """Every address, domain and port the cited findings actually mention."""
    addresses: set[str] = set()
    ports: set[str] = set()

    for finding in findings:
        for entity in finding.entities():
            value = entity.value.lower()
            if value.isdigit():
                ports.add(value)
            else:
                addresses.add(value)
        for evidence in finding.evidence:
            for key, payload_value in evidence.payload.items():
                if "port" in key and payload_value is not None:
                    ports.add(str(payload_value))
            for artifact in evidence.artifacts:
                if artifact.excerpt:
                    found_addresses, found_ports = _entities_in(artifact.excerpt)
                    addresses |= found_addresses
                    ports |= found_ports
    return addresses, ports


def verify(
    narrative: str,
    raw_claims: list[dict[str, object]],
    actions: list[str],
    findings: list[Finding],
    citable_ids: frozenset[str],
) -> VerificationReport:
    """Strike every claim that is not grounded in the brief.

    `citable_ids` is the set the brief actually showed the model, which is
    narrower than "all findings in the run". A model must not be credited for
    citing something it was never given.
    """
    by_id = {f.id: f for f in findings}
    report = VerificationReport(actions=list(actions))

    for raw in raw_claims:
        text = str(raw.get("text", "")).strip()
        if not text:
            continue

        cites = [str(c) for c in raw.get("cites", []) or []]
        claim = Claim(text=text, cites=cites)

        if not cites:
            claim.rejection_reason = StrikeReason.NO_CITATION
            report.claims.append(claim)
            continue

        unresolved = [c for c in cites if c not in citable_ids]
        if unresolved:
            claim.rejection_reason = (
                f"{StrikeReason.UNRESOLVED_CITATION}: {', '.join(sorted(unresolved))}"
            )
            report.claims.append(claim)
            continue

        cited = [by_id[c] for c in cites if c in by_id]
        allowed_addresses, allowed_ports = _grounded_vocabulary(cited)
        claimed_addresses, claimed_ports = _entities_in(text)

        invented = (claimed_addresses - allowed_addresses) | (claimed_ports - allowed_ports)
        if invented:
            claim.rejection_reason = (
                f"{StrikeReason.FABRICATED_ENTITY}: {', '.join(sorted(invented))}"
            )
            report.claims.append(claim)
            continue

        claim.verified = True
        report.claims.append(claim)

    # The narrative is prose rather than a finding, so it is not required to
    # carry citations — but it must not name entities the incident never
    # observed, which is the one way a summary can mislead outright.
    all_addresses, all_ports = _grounded_vocabulary(findings)
    narrative_addresses, narrative_ports = _entities_in(narrative)
    if (narrative_addresses - all_addresses) or (narrative_ports - all_ports):
        report.narrative = ""
        report.narrative_struck = True
    else:
        report.narrative = narrative

    return report
