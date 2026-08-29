"""Pure presentation model builder for current and comparison-aware maps."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from pivotcheck.analysis.comparison import DiffFinding, DiffReport
from pivotcheck.models.baseline import Baseline
from pivotcheck.models.network import DiscoveredNetwork, NetworkOrigin, PivotPath
from pivotcheck.models.result import DiscoverySnapshot


@dataclass(frozen=True)
class MapNetwork:
    network: str
    state: str
    origin: str | None = None
    confidence: str | None = None
    interface: str | None = None
    gateway: str | None = None
    related_network: str | None = None
    annotations: tuple[str, ...] = ()


@dataclass(frozen=True)
class MapView:
    current: DiscoverySnapshot
    baseline: Baseline | None = None
    baseline_name: str | None = None
    new_coverage: tuple[MapNetwork, ...] = ()
    expanded_coverage: tuple[MapNetwork, ...] = ()
    current_connected: tuple[MapNetwork, ...] = ()
    current_routed: tuple[MapNetwork, ...] = ()
    more_specific_evidence: tuple[MapNetwork, ...] = ()
    context_changes: tuple[MapNetwork, ...] = ()
    baseline_only: tuple[MapNetwork, ...] = ()
    unchanged: tuple[MapNetwork, ...] = ()
    pivot_paths: tuple[PivotPath, ...] = ()


def build_map_view(
    current: DiscoverySnapshot,
    *,
    baseline: Baseline | None = None,
    baseline_name: str | None = None,
    report: DiffReport | None = None,
) -> MapView:
    """Build a deterministic map view without performing comparison or I/O."""
    if (baseline is None) != (report is None):
        raise ValueError("baseline and comparison report must be supplied together")
    connected = [
        _network_from_current(network, "CURRENT_CONNECTED")
        for network in current.networks
        if network.origin is NetworkOrigin.CONNECTED
    ]
    routed = [
        _network_from_current(network, "CURRENT_ROUTED")
        for network in current.networks
        if network.origin is not NetworkOrigin.CONNECTED
    ]
    if report is None:
        return MapView(
            current=current,
            current_connected=tuple(_sort(connected)),
            current_routed=tuple(_sort(routed)),
            pivot_paths=tuple(_sort_paths(current.pivot_paths)),
        )
    return MapView(
        current=current,
        baseline=baseline,
        baseline_name=baseline_name,
        new_coverage=tuple(
            _sort(_from_findings(report.new_networks, current, "NEW_COVERAGE"))
        ),
        expanded_coverage=tuple(
            _sort(
                _from_findings(
                    _coverage(report, "EXPANDED_REACHABILITY"),
                    current,
                    "EXPANDED_COVERAGE",
                )
            )
        ),
        current_connected=tuple(_sort(connected)),
        current_routed=tuple(_sort(routed)),
        more_specific_evidence=tuple(
            _sort(
                _from_findings(
                    report.specificity_changes, current, "MORE_SPECIFIC_EVIDENCE"
                )
            )
        ),
        context_changes=tuple(
            _sort(_from_findings(report.context_changes, current, "CONTEXT_CHANGED"))
        ),
        baseline_only=tuple(
            _sort(
                _from_findings(
                    _coverage(report, "REDUCED_COVERAGE"), current, "REDUCED_COVERAGE"
                )
            )
        ),
        unchanged=tuple(
            _sort(_from_findings(report.unchanged_networks, current, "UNCHANGED"))
        ),
        pivot_paths=tuple(_sort_paths(current.pivot_paths)),
    )


def _coverage(report: DiffReport, classification: str) -> tuple[DiffFinding, ...]:
    return tuple(
        item
        for item in report.coverage_changes
        if item.classification == classification
    )


def _from_findings(
    findings: tuple[DiffFinding, ...], current: DiscoverySnapshot, state: str
) -> list[MapNetwork]:
    by_cidr = {network.cidr: network for network in current.networks}
    return [
        _from_finding(finding, by_cidr.get(finding.network), state)
        for finding in findings
    ]


def _from_finding(
    finding: DiffFinding, evidence: DiscoveredNetwork | None, state: str
) -> MapNetwork:
    if evidence is None:
        return MapNetwork(
            finding.network, state, related_network=finding.related_network
        )
    return MapNetwork(
        finding.network,
        state,
        origin=evidence.origin.value,
        confidence=evidence.confidence.value,
        interface=evidence.interface,
        gateway=evidence.gateway,
        related_network=finding.related_network,
    )


def _network_from_current(network: DiscoveredNetwork, state: str) -> MapNetwork:
    return MapNetwork(
        network.cidr,
        state,
        network.origin.value,
        network.confidence.value,
        network.interface,
        network.gateway,
    )


def _sort(items: list[MapNetwork]) -> list[MapNetwork]:
    return sorted(items, key=lambda item: _network_key(item.network))


def _sort_paths(paths: tuple[PivotPath, ...]) -> list[PivotPath]:
    return sorted(
        paths,
        key=lambda path: (
            path.destination_network,
            path.source_interface,
            path.gateway,
        ),
    )


def _network_key(network: str) -> tuple[int, int, int]:
    parsed = ipaddress.ip_network(network)
    return parsed.version, int(parsed.network_address), parsed.prefixlen
