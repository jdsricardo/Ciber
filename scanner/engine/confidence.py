"""Central confidence scoring, kept separate from severity.

Severity answers "how bad would this be if true". Confidence answers
"how sure is the detector that it is true". A critical finding with weak
evidence must stay critical severity at low confidence, never be
downgraded to low severity to compensate.
"""
from __future__ import annotations
from dataclasses import dataclass
from .models import FindingStatus

@dataclass(frozen=True)
class ConfidenceInputs:
    evidence_strength: int
    reproducibility: int
    differential_quality: int = 0
    independent_confirmation: int = 0
    instability: int = 0
    ambiguity: int = 0

def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))

def score(inputs: ConfidenceInputs) -> int:
    raw = (
        inputs.evidence_strength * 0.35
        + inputs.reproducibility * 0.25
        + inputs.differential_quality * 0.2
        + inputs.independent_confirmation * 0.2
        - inputs.instability * 0.3
        - inputs.ambiguity * 0.2
    )
    return _clamp(round(raw))

def status_for(confidence: int, manual_review_required: bool = False, informational: bool = False) -> FindingStatus:
    if manual_review_required:
        return FindingStatus.MANUAL_REVIEW
    if informational:
        return FindingStatus.INFORMATIONAL
    if confidence >= 90:
        return FindingStatus.CONFIRMED
    if confidence >= 75:
        return FindingStatus.HIGH_CONFIDENCE
    if confidence >= 55:
        return FindingStatus.PROBABLE
    if confidence >= 30:
        return FindingStatus.POSSIBLE
    return FindingStatus.INFORMATIONAL
