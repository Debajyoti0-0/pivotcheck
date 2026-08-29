"""Pure coverage and evidence comparison for network perspectives.

The coverage view collapses adjacent CIDRs for mathematical reachability
comparison.  The evidence view retains individual entries for route context
and specificity findings.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any, cast

from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import RouteType
from pivotcheck.models.result import DiscoverySnapshot


class NetworkRelationship(str, Enum):
    EXACT = "exact"
    BASELINE_COVERS_CURRENT = "baseline_covers_current"
    CURRENT_COVERS_BASELINE = "current_covers_baseline"
    DISJOINT = "disjoint"


def classify_relationship(
    baseline_network: str | ipaddress._BaseNetwork,
    current_network: str | ipaddress._BaseNetwork,
) -> NetworkRelationship:
    """Classify two canonical CIDRs into exactly one relation.

    CIDR blocks are hierarchical: same-family blocks either are disjoint or
    one contains the other.  A partial-overlap category would be dead code.
    Different IP families are intentionally treated as disjoint.
    """
    baseline = ipaddress.ip_network(str(baseline_network), strict=False)
    current = ipaddress.ip_network(str(current_network), strict=False)
    if baseline.version != current.version:
        return NetworkRelationship.DISJOINT
    if baseline == current:
        return NetworkRelationship.EXACT
    # Same family: narrow so supernet_of sees matching concrete types.
    if baseline.version == 4:
        b4 = cast(ipaddress.IPv4Network, baseline)
        c4 = cast(ipaddress.IPv4Network, current)
        if b4.supernet_of(c4):
            return NetworkRelationship.BASELINE_COVERS_CURRENT
        if c4.supernet_of(b4):
            return NetworkRelationship.CURRENT_COVERS_BASELINE
    else:
        b6 = cast(ipaddress.IPv6Network, baseline)
        c6 = cast(ipaddress.IPv6Network, current)
        if b6.supernet_of(c6):
            return NetworkRelationship.BASELINE_COVERS_CURRENT
        if c6.supernet_of(b6):
            return NetworkRelationship.CURRENT_COVERS_BASELINE
    return NetworkRelationship.DISJOINT


def coverage_view(
    entries: Iterable[BaselineNetwork],
) -> tuple[ipaddress._BaseNetwork, ...]:
    """Return deterministically collapsed coverage, partitioned by family."""
    by_family: dict[int, list[Any]] = {4: [], 6: []}
    for entry in entries:
        network = ipaddress.ip_network(entry.network)
        by_family[network.version].append(network)
    networks = [
        collapsed
        for family in (4, 6)
        for collapsed in ipaddress.collapse_addresses(by_family[family])
    ]
    return tuple(
        sorted(
            networks,
            key=lambda network: (
                network.version,
                int(network.network_address),
                network.prefixlen,
            ),
        )
    )


def baseline_from_snapshot(snapshot: DiscoverySnapshot) -> Baseline:
    """Pure, deterministic transformation from analyzed discovery output."""
    entries = tuple(
        BaselineNetwork(
            network=network.cidr,
            origin=network.origin,
            confidence=network.confidence,
            interface=network.interface,
            gateway=network.gateway,
            route_type=(
                RouteType.STATIC if network.gateway is not None else RouteType.CONNECTED
            ),
        )
        for network in snapshot.networks
    )
    return Baseline(
        created_at=snapshot.timestamp,
        source="discovery_snapshot",
        networks=entries,
        vantage_point=snapshot.session,
    )


@dataclass(frozen=True)
class DiffFinding:
    network: str
    classification: str
    relationship: NetworkRelationship | None
    related_network: str | None
    reachability_novelty: bool
    topology_novelty: bool


@dataclass(frozen=True)
class DiffReport:
    new_networks: tuple[DiffFinding, ...] = ()
    specificity_changes: tuple[DiffFinding, ...] = ()
    coverage_changes: tuple[DiffFinding, ...] = ()
    unchanged_networks: tuple[DiffFinding, ...] = ()
    context_changes: tuple[DiffFinding, ...] = ()
    warnings: tuple[str, ...] = ()


def compare(baseline: Baseline, current: Baseline) -> DiffReport:
    """Compare two perspectives without confusing evidence with coverage."""
    baseline_coverage = coverage_view(baseline.networks)
    current_coverage = coverage_view(current.networks)

    new: list[DiffFinding] = []
    coverage: list[DiffFinding] = []
    unchanged: list[DiffFinding] = []
    for current_network in current_coverage:
        relationships = [
            (known, classify_relationship(known, current_network))
            for known in baseline_coverage
            if known.version == current_network.version
        ]
        exact = next(
            (
                known
                for known, relation in relationships
                if relation is NetworkRelationship.EXACT
            ),
            None,
        )
        covering = next(
            (
                known
                for known, relation in relationships
                if relation is NetworkRelationship.BASELINE_COVERS_CURRENT
            ),
            None,
        )
        overlaps = [
            known
            for known, relation in relationships
            if relation is not NetworkRelationship.DISJOINT
        ]
        if exact is not None:
            unchanged.append(
                _finding(
                    current_network,
                    "UNCHANGED_COVERAGE",
                    NetworkRelationship.EXACT,
                    exact,
                    False,
                    False,
                )
            )
        elif covering is None and not overlaps:
            new.append(
                _finding(
                    current_network,
                    "NEW_REACHABILITY",
                    NetworkRelationship.DISJOINT,
                    None,
                    True,
                    True,
                )
            )
        elif covering is None:
            coverage.append(
                _finding(
                    current_network,
                    "EXPANDED_REACHABILITY",
                    NetworkRelationship.CURRENT_COVERS_BASELINE,
                    overlaps[0],
                    True,
                    True,
                )
            )

    for known_network in baseline_coverage:
        relationships = [
            (current_network, classify_relationship(known_network, current_network))
            for current_network in current_coverage
            if current_network.version == known_network.version
        ]
        retained = any(
            relation
            in (NetworkRelationship.EXACT, NetworkRelationship.CURRENT_COVERS_BASELINE)
            for _, relation in relationships
        )
        if not retained:
            related = next(
                (
                    network
                    for network, relation in relationships
                    if relation is NetworkRelationship.BASELINE_COVERS_CURRENT
                ),
                None,
            )
            coverage.append(
                _finding(
                    known_network,
                    "REDUCED_COVERAGE",
                    NetworkRelationship.BASELINE_COVERS_CURRENT
                    if related
                    else NetworkRelationship.DISJOINT,
                    related,
                    False,
                    True,
                )
            )

    specificity = _specificity_findings(baseline.networks, current.networks)
    contexts = _context_findings(baseline.networks, current.networks)
    return DiffReport(
        new_networks=tuple(_sorted_findings(new)),
        specificity_changes=tuple(_sorted_findings(specificity)),
        coverage_changes=tuple(_sorted_findings(coverage)),
        unchanged_networks=tuple(_sorted_findings(unchanged)),
        context_changes=tuple(_sorted_findings(contexts)),
    )


def _specificity_findings(
    baseline: tuple[BaselineNetwork, ...], current: tuple[BaselineNetwork, ...]
) -> list[DiffFinding]:
    findings = []
    for entry in current:
        for known in baseline:
            relation = classify_relationship(known.network, entry.network)
            if relation is NetworkRelationship.BASELINE_COVERS_CURRENT:
                findings.append(
                    _finding(
                        ipaddress.ip_network(entry.network),
                        "MORE_SPECIFIC",
                        relation,
                        ipaddress.ip_network(known.network),
                        False,
                        True,
                    )
                )
                break
    return findings


def _context_findings(
    baseline: tuple[BaselineNetwork, ...], current: tuple[BaselineNetwork, ...]
) -> list[DiffFinding]:
    findings = []
    for entry in current:
        for known in baseline:
            if entry.network != known.network:
                continue
            if _context(entry) != _context(known):
                findings.append(
                    _finding(
                        ipaddress.ip_network(entry.network),
                        "ROUTE_CONTEXT_CHANGED",
                        NetworkRelationship.EXACT,
                        ipaddress.ip_network(known.network),
                        False,
                        True,
                    )
                )
                break
    return findings


def _context(entry: BaselineNetwork) -> tuple[object, ...]:
    return entry.interface, entry.gateway, entry.route_type, entry.confidence


def _finding(
    network: ipaddress._BaseNetwork,
    classification: str,
    relationship: NetworkRelationship,
    related: ipaddress._BaseNetwork | None,
    reachability_novelty: bool,
    topology_novelty: bool,
) -> DiffFinding:
    return DiffFinding(
        str(network),
        classification,
        relationship,
        str(related) if related else None,
        reachability_novelty,
        topology_novelty,
    )


def _sorted_findings(findings: list[DiffFinding]) -> list[DiffFinding]:
    return sorted(
        findings,
        key=lambda item: (
            ipaddress.ip_network(item.network).version,
            int(ipaddress.ip_network(item.network).network_address),
            ipaddress.ip_network(item.network).prefixlen,
            item.classification,
            item.related_network or "",
        ),
    )
