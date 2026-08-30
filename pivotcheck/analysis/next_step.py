"""Next-step decision support: select the highest-priority investigation candidate.

Pure analysis over existing evidence — no system access, no socket logic.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from pivotcheck.analysis.comparison import DiffReport
from pivotcheck.analysis.recommendation import Recommendation
from pivotcheck.analysis.transit_priority import (
    TransitPriority,
    assess_transit_priority,
)
from pivotcheck.models.check import (
    ComparisonContext,
    TransitEvidence,
    TransitEvidenceAssessment,
    TransitEvidenceCollection,
)
from pivotcheck.models.result import DiscoverySnapshot


@dataclass(frozen=True)
class NextStepCandidate:
    """Single highest-priority investigation candidate."""

    network: str
    priority: TransitPriority
    reason: str
    transit_evidence: TransitEvidence
    comparison_context: ComparisonContext | None = None
    limitation: str = (
        "Route and topology evidence do not prove active reachability. "
        "This is prioritization context, not validation evidence."
    )
    suggested_action: str = ""

    def to_dict(self) -> dict:
        """Serialize per the documented ``next`` candidate contract.

        Keys follow the documented ``next`` candidate contract in
        README.md (Output Contracts): ``observed_evidence``
        (not the internal attribute name ``transit_evidence``), and the
        candidate never carries operator-facing limitation/suggestion
        fields — those are top-level report concerns.
        """
        data: dict = {
            "network": self.network,
            "priority": self.priority.value,
            "reason": self.reason,
            "observed_evidence": {
                "route": {
                    "present": self.transit_evidence.route_present,
                    "metric": self.transit_evidence.route_metric,
                    "type": self.transit_evidence.route_type,
                },
                "neighbor": {
                    "observed": self.transit_evidence.neighbor_observed,
                    "state": self.transit_evidence.neighbor_state,
                    "mac": self.transit_evidence.neighbor_mac,
                },
                "connections": {
                    "tcp_count": self.transit_evidence.tcp_connections_to_gateway,
                    "tcp_states": list(self.transit_evidence.tcp_connection_states),
                    "udp_count": self.transit_evidence.udp_flows_to_gateway,
                    "has_listen": self.transit_evidence.has_listen_on_gateway,
                    "has_loopback": self.transit_evidence.has_loopback_to_gateway,
                },
            },
            "transit_assessment": self.transit_evidence.assessment.value,
        }
        if self.comparison_context is not None:
            data["comparison_context"] = self.comparison_context.to_dict()
        return data


@dataclass(frozen=True)
class NextStepReport:
    """Report for next-step decision support."""

    tool: str = "pivotcheck"
    version: str = ""
    timestamp: str = ""
    schema_version: str = "1.1"
    command: str = "next"
    perspective_hostname: str = ""
    perspective_session_id: str = ""
    candidate: NextStepCandidate | None = None
    message: str | None = None  # "NO INVESTIGATION CANDIDATES" when empty

    def to_dict(self) -> dict:
        data: dict = {
            "schema_version": self.schema_version,
            "tool": self.tool,
            "version": self.version,
            "command": self.command,
            "timestamp": self.timestamp,
            "perspective": {
                "hostname": self.perspective_hostname,
                "session_id": self.perspective_session_id,
            },
        }
        if self.candidate is not None:
            data["candidate"] = self.candidate.to_dict()
            # Documented top-level fields (README.md, Output Contracts):
            # the suggested action is a structured object and limitations
            # answer "what does this evidence not prove" at report scope.
            data["suggested_action"] = {
                "command_template": self.candidate.suggested_action
            }
            data["limitations"] = [self.candidate.limitation]
        else:
            data["candidate"] = None
            data["message"] = self.message or "NO INVESTIGATION CANDIDATES"
        return data


# Priority weight per TransitPriority, ordered HIGH > MEDIUM > LOW > NONE.
# Derived from assess_transit_priority (single semantic source of truth);
# used by _transit_evidence_key so ranking can never drift from assessment.
_PRIORITY_WEIGHT: dict[TransitPriority, int] = {
    TransitPriority.HIGH: 1000,
    TransitPriority.MEDIUM: 100,
    TransitPriority.LOW: 10,
    TransitPriority.NONE: 0,
}


# DiffFinding classification -> ComparisonContext relationship vocabulary.
# ComparisonContext.relationship must always use the documented context
# vocabulary (models.check.ComparisonContext), never the internal
# DiffFinding classification label.
_CONTEXT_RELATIONSHIP: dict[str, str] = {
    "NEW_REACHABILITY": "NEW_COVERAGE",
    "EXPANDED_REACHABILITY": "EXPANDED_COVERAGE",
    "REDUCED_COVERAGE": "REDUCED_COVERAGE",
    "UNCHANGED_COVERAGE": "UNCHANGED",
    "MORE_SPECIFIC": "MORE_SPECIFIC",
    "ROUTE_CONTEXT_CHANGED": "CONTEXT_CHANGED",
}


def _canonical_network_key(network: str) -> tuple:
    """Canonical sort key for network CIDR."""
    net = ipaddress.ip_network(network, strict=False)
    return (net.version, int(net.network_address), net.prefixlen)


def _transit_evidence_key(evidence: TransitEvidence) -> tuple:
    """Deterministic sort key for transit evidence (ascending sort = best first).

    candidate_rank = (priority_rank, evidence_strength_rank, canonical_network_order)

    - priority_rank is derived from assess_transit_priority (single semantic
      source of truth); negated so higher priority sorts first.
    - evidence_strength_rank breaks ties within the same priority; negated.
    - canonical_network_order (version, network address, prefixlen), then
      gateway address, then source interface provide a total order so the
      result is stable under input permutation (never depends on set
      iteration or discovery ordering).
    """
    priority_result = assess_transit_priority(evidence)
    priority_weight = _PRIORITY_WEIGHT[priority_result.priority]

    # Evidence strength within priority
    assessment = evidence.assessment
    evidence_strength = 0
    if assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS:
        evidence_strength = 100
    elif assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2:
        evidence_strength = 90
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE:
        evidence_strength = 80
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE:
        evidence_strength = 70
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE:
        evidence_strength = 60
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE:
        evidence_strength = 50
    elif assessment == TransitEvidenceAssessment.ROUTING_ONLY:
        evidence_strength = 40
    elif assessment == TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE:
        evidence_strength = 30
    elif assessment == TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE:
        evidence_strength = 20
    elif assessment == TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE:
        evidence_strength = 10

    # Canonical tie-breakers: network, then gateway address, then interface
    net_key = _canonical_network_key(evidence.destination_network)
    gateway_key: tuple[int, int]
    try:
        gateway_ip = ipaddress.ip_address(evidence.gateway)
        gateway_key = (gateway_ip.version, int(gateway_ip))
    except ValueError:
        gateway_key = (0, -1)
    interface_key = evidence.source_interface

    return (-priority_weight, -evidence_strength, net_key, gateway_key, interface_key)


def select_next_investigation(
    snapshot: DiscoverySnapshot,
    *,
    transit_evidence: TransitEvidenceCollection,
    recommendations: tuple[Recommendation, ...] = (),
    comparison_report: DiffReport | None = None,
    baseline_name: str | None = None,
) -> NextStepReport:
    """Select the single highest-priority investigation candidate.

    Pure function: no I/O, no network activity, deterministic.
    """
    import socket as _socket
    import uuid
    from datetime import datetime, timezone

    from pivotcheck import __version__

    timestamp = datetime.now(timezone.utc).isoformat()
    perspective_hostname = _socket.gethostname()
    perspective_session_id = uuid.uuid4().hex[:16]

    if not transit_evidence.candidates:
        return NextStepReport(
            tool="pivotcheck",
            version=__version__,
            timestamp=timestamp,
            schema_version="1.1",
            command="next",
            perspective_hostname=perspective_hostname,
            perspective_session_id=perspective_session_id,
            message="NO INVESTIGATION CANDIDATES",
        )

    # Build a map of network -> comparison context
    comp_by_network = {}
    if comparison_report is not None:
        for finding in (
            comparison_report.new_networks
            + comparison_report.coverage_changes
            + comparison_report.specificity_changes
            + comparison_report.context_changes
            + comparison_report.unchanged_networks
        ):
            comp_by_network[finding.network] = finding

    candidates = []
    for evidence in transit_evidence.candidates:
        # Get priority from transit evidence
        priority_result = assess_transit_priority(evidence)

        # Skip NONE priority candidates
        if priority_result.priority == TransitPriority.NONE:
            continue

        # Get comparison context if available
        comparison_context: ComparisonContext | None = None
        if comparison_report is not None and baseline_name is not None:
            match_finding = comp_by_network.get(evidence.destination_network)
            if match_finding is not None:
                comparison_context = ComparisonContext(
                    baseline=baseline_name,
                    # ComparisonContext.relationship uses the documented
                    # context vocabulary (see models.check.ComparisonContext),
                    # NOT the internal DiffFinding classification label.
                    relationship=_CONTEXT_RELATIONSHIP[match_finding.classification],
                    classification=match_finding.classification,
                    related_network=match_finding.related_network,
                )

        # Build suggested action
        suggested_action = (
            f"Choose an explicit target in {evidence.destination_network} "
            f"and run: pivotcheck check <target> --port <port>"
        )
        if baseline_name:
            suggested_action += f" --baseline {baseline_name}"

        candidate = NextStepCandidate(
            network=evidence.destination_network,
            priority=TransitPriority(priority_result.priority),
            reason=priority_result.reason,
            transit_evidence=evidence,
            comparison_context=comparison_context,
            suggested_action=suggested_action,
        )
        candidates.append(candidate)

    if not candidates:
        return NextStepReport(
            tool="pivotcheck",
            version=__version__,
            timestamp=timestamp,
            schema_version="1.1",
            command="next",
            perspective_hostname=perspective_hostname,
            perspective_session_id=perspective_session_id,
            message="NO INVESTIGATION CANDIDATES",
        )

    # Sort by priority and evidence strength
    candidates.sort(key=lambda c: _transit_evidence_key(c.transit_evidence))

    best = candidates[0]

    return NextStepReport(
        tool="pivotcheck",
        version=__version__,
        timestamp=timestamp,
        schema_version="1.1",
        command="next",
        perspective_hostname=perspective_hostname,
        perspective_session_id=perspective_session_id,
        candidate=best,
    )