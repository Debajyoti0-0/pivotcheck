"""Deterministic, rule-based next-step recommendations.

Rules (documented contract; no opaque scoring):

1. HIGH   — new coverage whose current evidence is connected AND high
            confidence.
2. MEDIUM — new routed/inferred coverage, or expanded address-space
            coverage.
3. LOW    — inferred pivot paths and unchanged context.

Every recommendation carries its reason, the evidence that produced it,
a suggested operator action, and an explicit epistemic limitation. No
recommendation ever claims reachability or executes anything.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from pivotcheck.analysis.comparison import DiffReport
from pivotcheck.models.network import Confidence, DiscoveredNetwork, NetworkOrigin
from pivotcheck.models.result import DiscoverySnapshot


@dataclass(frozen=True)
class Recommendation:
    priority: str
    network: str
    reason: str
    suggested_action: str
    limitation: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        data = self.__dict__.copy()
        data["evidence"] = list(self.evidence)
        return data


def recommend(snapshot: DiscoverySnapshot, report: DiffReport) -> tuple[Recommendation, ...]:
    """Produce deterministic recommendations sorted by rule priority."""
    evidence = {
        str(ipaddress.ip_network(network.cidr, strict=False)): network
        for network in snapshot.networks
    }
    results: list[Recommendation] = []
    for finding in report.new_networks:
        network = evidence.get(finding.network)
        if network is None:
            continue  # never recommend without supporting evidence
        if (
            network.origin is NetworkOrigin.CONNECTED
            and network.confidence is Confidence.HIGH
        ):
            results.append(_recommendation(
                "HIGH", finding.network,
                "New high-confidence connected coverage observed.",
                _evidence_lines(network),
            ))
        else:
            origin_label = network.origin.value
            results.append(_recommendation(
                "MEDIUM", finding.network,
                f"New {origin_label} coverage is supported by current "
                "route or topology evidence.",
                _evidence_lines(network),
            ))
    for finding in report.coverage_changes:
        if finding.classification == "EXPANDED_REACHABILITY":
            network = evidence.get(finding.network)
            results.append(_recommendation(
                "MEDIUM", finding.network,
                "Current perspective shows expanded address-space coverage.",
                _evidence_lines(network) if network else (),
            ))
    for path in snapshot.pivot_paths:
        results.append(_recommendation(
            "LOW", path.destination_network,
            "Inferred pivot context is supported by routing evidence.",
            (
                f"gateway: {path.gateway}",
                f"interface: {path.source_interface}",
                f"confidence: {path.confidence.value}",
            ),
        ))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return tuple(sorted(results, key=lambda item: (order[item.priority], item.network, item.reason)))


def _evidence_lines(network: DiscoveredNetwork) -> tuple[str, ...]:
    lines = [f"origin: {network.origin.value}"]
    if network.interface:
        lines.append(f"interface: {network.interface}")
    if network.gateway:
        lines.append(f"gateway: {network.gateway}")
    lines.append(f"confidence: {network.confidence.value}")
    return tuple(lines)


def _recommendation(priority: str, network: str, reason: str, evidence: tuple[str, ...]) -> Recommendation:
    return Recommendation(
        priority,
        network,
        reason,
        "Perform explicit validation of an operator-chosen target.",
        "Route and topology evidence do not prove active reachability.",
        evidence,
    )