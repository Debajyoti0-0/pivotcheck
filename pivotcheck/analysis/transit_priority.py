"""Transit evidence operator priority analysis.

Pure analysis over TransitEvidence — no system access, no socket logic.
Converts evidence composition into operator-priority interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pivotcheck.models.check import (
    TransitEvidence,
    TransitEvidenceAssessment,
)


class TransitPriority(str, Enum):
    """Operator priority for transit candidate investigation.

    This is INVESTIGATION PRIORITY, not pivot viability.
    HIGH = deserves operator attention first
    MEDIUM = deserves attention after HIGH candidates
    LOW = minimal evidence, investigate if time permits
    NONE = no actionable evidence

    A ``str`` Enum is the deliberate canonical representation:

    - ``TransitPriority.HIGH == "HIGH"`` and ``TransitPriority("HIGH")``
      both work (zero breakage for comparisons and construction),
    - ``.value`` provides the canonical string for JSON serialization
      and renderer output,
    - MyPy sees member types instead of plain ``str``.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass(frozen=True)
class TransitPriorityResult:
    """Priority assessment for a transit candidate."""

    priority: TransitPriority
    reason: str
    evidence_summary: str


def assess_transit_priority(evidence: TransitEvidence) -> TransitPriorityResult:
    """Convert transit evidence into operator investigation priority.

    Pure function: no I/O, no network activity, deterministic.

    Priority is INVESTIGATION VALUE, not pivot viability.
    HIGH = deserves operator attention first
    MEDIUM = deserves attention after HIGH candidates
    LOW = minimal evidence, investigate if time permits
    NONE = no actionable evidence
    """
    assessment = evidence.assessment

    # HIGH: Multiple independent observations supporting investigation
    if assessment in (
        TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
        TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2,
    ):
        return TransitPriorityResult(
            priority=TransitPriority.HIGH,
            reason="Multiple independent observations support investigating this transit candidate.",
            evidence_summary=_evidence_summary(evidence),
        )

    # MEDIUM: Single strong evidence type or new coverage
    if assessment in (
        TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
        TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE,
        TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE,
    ):
        return TransitPriorityResult(
            priority=TransitPriority.MEDIUM,
            reason="Single strong evidence type supports investigating this transit candidate.",
            evidence_summary=_evidence_summary(evidence),
        )

    # LOW: Routing only or historical evidence
    if assessment in (
        TransitEvidenceAssessment.ROUTING_ONLY,
        TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE,
    ):
        return TransitPriorityResult(
            priority=TransitPriority.LOW,
            reason="Only routing or historical evidence; investigate if time permits.",
            evidence_summary=_evidence_summary(evidence),
        )

    # NONE: Negative or contradictory evidence
    if assessment in (
        TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE,
        TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE,
        TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE,
    ):
        return TransitPriorityResult(
            priority=TransitPriority.NONE,
            reason="Negative or contradictory evidence; not recommended for investigation.",
            evidence_summary=_evidence_summary(evidence),
        )

    # Fallback
    return TransitPriorityResult(
        priority=TransitPriority.NONE,
        reason="Unable to assess priority.",
        evidence_summary=_evidence_summary(evidence),
    )


def _evidence_summary(evidence: TransitEvidence) -> str:
    """Generate a concise evidence summary string."""
    parts = []
    if evidence.route_present:
        parts.append("route")
    if evidence.neighbor_observed:
        parts.append(f"neighbor:{evidence.neighbor_state}")
    if evidence.tcp_connections_to_gateway > 0:
        parts.append(f"tcp:{evidence.tcp_connections_to_gateway}")
    if evidence.udp_flows_to_gateway > 0:
        parts.append(f"udp:{evidence.udp_flows_to_gateway}")
    if evidence.has_listen_on_gateway:
        parts.append("listen")
    if evidence.has_loopback_to_gateway:
        parts.append("loopback")
    return ", ".join(parts) if parts else "none"