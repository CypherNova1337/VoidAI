"""The language layer: the only place a model runs, and the gate after it."""

from voidai.reason.backend import (
    RESPONSE_GRAMMAR,
    SYSTEM_PROMPT,
    Completion,
    LlamaCppBackend,
    ReasoningBackend,
    ScriptedBackend,
    UnavailableBackend,
    default_backend,
)
from voidai.reason.brief import EvidenceBrief, build_brief, estimate_tokens
from voidai.reason.reasoner import Reasoner, ReasoningConfig, ReasoningResult
from voidai.reason.verifier import StrikeReason, VerificationReport, verify

__all__ = [
    "RESPONSE_GRAMMAR",
    "SYSTEM_PROMPT",
    "Completion",
    "EvidenceBrief",
    "LlamaCppBackend",
    "Reasoner",
    "ReasoningBackend",
    "ReasoningConfig",
    "ReasoningResult",
    "ScriptedBackend",
    "StrikeReason",
    "UnavailableBackend",
    "VerificationReport",
    "build_brief",
    "default_backend",
    "estimate_tokens",
    "verify",
]
