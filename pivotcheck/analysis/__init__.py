"""Analysis engine: topology, reachability classification, pivot paths."""

from pivotcheck.analysis.comparison import (
    DiffFinding,
    DiffReport,
    NetworkRelationship,
    baseline_from_snapshot,
    classify_relationship,
    compare,
    coverage_view,
)
from pivotcheck.analysis.gateway import assess_transit_evidence
from pivotcheck.analysis.next_step import (
    NextStepCandidate,
    NextStepReport,
    select_next_investigation,
)
from pivotcheck.analysis.topology import (
    analyze,
    classify_networks,
    classify_routed_networks,
    infer_pivot_paths,
)
from pivotcheck.analysis.transit_priority import (
    TransitPriority,
    TransitPriorityResult,
    assess_transit_priority,
)
from pivotcheck.models.check import (
    TransitEvidence,
    TransitEvidenceAssessment,
    TransitEvidenceCollection,
)

__all__ = [
    "DiffFinding",
    "DiffReport",
    "NetworkRelationship",
    "NextStepCandidate",
    "NextStepReport",
    "TransitEvidence",
    "TransitEvidenceAssessment",
    "TransitEvidenceCollection",
    "TransitPriority",
    "TransitPriorityResult",
    "analyze",
    "assess_transit_evidence",
    "assess_transit_priority",
    "baseline_from_snapshot",
    "classify_networks",
    "classify_relationship",
    "classify_routed_networks",
    "compare",
    "coverage_view",
    "infer_pivot_paths",
    "select_next_investigation",
]
