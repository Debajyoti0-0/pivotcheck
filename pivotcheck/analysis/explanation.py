"""Pure evidence-preserving explanations for a comparison finding or standalone network."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from pivotcheck.analysis.comparison import DiffFinding, DiffReport
from pivotcheck.models.baseline import Baseline
from pivotcheck.models.result import DiscoverySnapshot


@dataclass(frozen=True)
class NetworkExplanation:
    network: str
    classification: str
    reason: str
    origin: str | None
    interface: str | None
    gateway: str | None
    confidence: str | None
    current_vantage_point: str | None
    baseline_vantage_point: str | None
    route_evidence: tuple[str, ...] = ()
    reachability: str = "NOT ACTIVELY VALIDATED"
    transit_evidence: dict | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        data = self.__dict__.copy()
        data["route_evidence"] = list(self.route_evidence)
        data["transit_evidence"] = self.transit_evidence
        data["limitations"] = list(self.limitations)
        return data


def _finding(network: str, report: DiffReport) -> DiffFinding | None:
    for finding in (
        report.new_networks
        + report.coverage_changes
        + report.specificity_changes
        + report.context_changes
        + report.unchanged_networks
    ):
        if str(ipaddress.ip_network(finding.network, strict=False)) == network:
            return finding
    return None


def _reason(finding: DiffFinding | None, observed: bool = True) -> str:
    if finding is None:
        if observed:
            return "Network observed in current discovery evidence."
        return "Network not found in current discovery evidence."
    reasons = {
        "NEW_REACHABILITY": "Newly observed network not present in baseline.",
        "EXPANDED_REACHABILITY": "Network coverage expanded relative to baseline.",
        "REDUCED_COVERAGE": "Network coverage reduced relative to baseline.",
        "UNCHANGED_COVERAGE": "Network coverage unchanged since baseline.",
        "MORE_SPECIFIC": "More specific topology evidence observed.",
        "ROUTE_CONTEXT_CHANGED": "Route context changed for this network.",
    }
    return reasons.get(finding.classification, "Comparison context changed.")


def explain_network(
    network: str,
    current: DiscoverySnapshot,
    report: DiffReport | None = None,
    baseline: Baseline | None = None,
) -> NetworkExplanation:
    """Explain a network using current evidence and optional comparison context.

    If `report` and `baseline` are provided, includes comparison classification.
    If not, provides standalone explanation from current evidence only.
    """
    canonical = str(ipaddress.ip_network(network, strict=False))

    evidence = next(
        (item for item in current.networks
         if str(ipaddress.ip_network(item.cidr, strict=False)) == canonical),
        None
    )
    observed = evidence is not None

    if report is not None:
        finding = _finding(canonical, report)
        if finding is not None:
            classification = finding.classification
            reason = _reason(finding)
        else:
            # Comparison context covers a different scope than the current
            # snapshot: classification follows what the CURRENT evidence
            # actually shows, never an assumed observation.
            classification = "CURRENT_EVIDENCE" if observed else "NOT_OBSERVED"
            reason = _reason(None, observed)
    else:
        # Standalone mode: no comparison context.
        if observed:
            classification = "CURRENT_EVIDENCE"
            reason = _reason(None, observed)
        else:
            classification = "NOT_OBSERVED"
            reason = _reason(None, observed)

    routes = _route_evidence(canonical, current)
    
    # Get transit evidence if available
    transit_evidence = _transit_evidence_for_network(canonical, current)
    
    # Build limitations
    limitations = _build_limitations(evidence, transit_evidence)
    
    return NetworkExplanation(
        canonical,
        classification,
        reason,
        evidence.origin.value if evidence else None,
        evidence.interface if evidence else None,
        evidence.gateway if evidence else None,
        evidence.confidence.value if evidence else None,
        current.session.display_name if current.session else None,
        baseline.vantage_point.display_name if baseline and baseline.vantage_point else None,
        routes,
        transit_evidence=transit_evidence,
        limitations=limitations,
    )


def _transit_evidence_for_network(network: str, snapshot: DiscoverySnapshot) -> dict | None:
    """Get transit evidence for a network if it exists."""
    from pivotcheck.analysis.gateway import assess_transit_evidence
    from pivotcheck.analysis.next_step import assess_transit_priority
    
    transit_collection = assess_transit_evidence(snapshot)
    for evidence in transit_collection.candidates:
        if evidence.destination_network == network:
            priority_result = assess_transit_priority(evidence)
            return {
                "assessment": evidence.assessment.value,
                "priority": priority_result.priority.value,
                "reason": priority_result.reason,
                "evidence_summary": priority_result.evidence_summary,
                "route_present": evidence.route_present,
                "route_metric": evidence.route_metric,
                "neighbor_observed": evidence.neighbor_observed,
                "neighbor_state": evidence.neighbor_state,
                "tcp_connections_to_gateway": evidence.tcp_connections_to_gateway,
                "tcp_connection_states": list(evidence.tcp_connection_states),
                "udp_flows_to_gateway": evidence.udp_flows_to_gateway,
            }
    return None


def _build_limitations(
    evidence: object | None,
    transit_evidence: dict | None,
) -> tuple[str, ...]:
    """Build limitation statements for the explanation."""
    limitations = [
        "Route and topology evidence do not prove active reachability.",
        "This is prioritization context, not validation evidence.",
    ]
    if evidence is None:
        limitations += ("Network not found in current discovery evidence.",)
    if transit_evidence is None:
        limitations += ("No transit evidence (pivot path) found for this network.",)
    return tuple(limitations)


def _route_evidence(network: str, snapshot: DiscoverySnapshot) -> tuple[str, ...]:
    """Route-table lines that directly support this network's presence."""
    target = ipaddress.ip_network(network, strict=False)
    lines: list[str] = []
    for route in snapshot.routes:
        if route.destination == "default":
            continue
        destination = ipaddress.ip_network(route.destination, strict=False)
        if destination.version != target.version:
            continue
        if destination == target or (
            destination.version == target.version and destination.supernet_of(target)  # type: ignore[arg-type]
        ):
            via = f" via {route.gateway}" if route.gateway else ""
            lines.append(f"{route.destination}{via} dev {route.interface}")
    return tuple(sorted(lines))
