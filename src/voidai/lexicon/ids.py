"""Content-addressed identifiers.

Every object in the Lexicon derives its identity from its content, not from a
counter or a UUID. Two runs over the same input produce byte-identical IDs.

This is not an aesthetic choice. Provenance is only meaningful if it is
reproducible: an analyst who re-runs an investigation must get the same
evidence IDs, or the citations in last week's report point at nothing.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_DIGEST_BYTES = 8


def _canonical(payload: Any) -> bytes:
    """Serialize to a stable byte string.

    Sorted keys, no insignificant whitespace, non-ASCII preserved. Any two
    structurally equal payloads serialize identically regardless of how they
    were constructed.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def content_id(prefix: str, payload: Any) -> str:
    """Return a stable, human-scannable ID such as ``ev_9f2a1c4b7d0e3a86``."""
    digest = hashlib.blake2b(_canonical(payload), digest_size=_DIGEST_BYTES)
    return f"{prefix}_{digest.hexdigest()}"


def artifact_id(source: str, locator: str) -> str:
    return content_id("art", {"source": source, "locator": locator})


def evidence_id(kind: str, payload: Any, artifacts: list[str]) -> str:
    return content_id("ev", {"kind": kind, "payload": payload, "artifacts": sorted(artifacts)})


def entity_id(entity_type: str, value: str) -> str:
    # Entity values are case-folded so HOST:WEB01 and host:web01 are one entity.
    return content_id("ent", {"type": entity_type, "value": value.strip().casefold()})


def finding_id(predicate: str, subject: str, obj: str | None, evidence: list[str]) -> str:
    return content_id(
        "fnd",
        {
            "predicate": predicate,
            "subject": subject,
            "object": obj,
            "evidence": sorted(evidence),
        },
    )


def incident_id(finding_ids: list[str]) -> str:
    return content_id("inc", {"findings": sorted(finding_ids)})
