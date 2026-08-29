"""Route context: correlate a checked destination with discovery evidence.

Pure analysis over normalized models — no system access, no socket logic.
"""

from __future__ import annotations

import ipaddress

from pivotcheck.analysis.comparison import DiffReport
from pivotcheck.analysis.recommendation import Recommendation
from pivotcheck.models.check import (
    ComparisonContext,
    NetworkMatch,
    PriorityContext,
    RouteContext,
    RouteContextType,
    ValidationContext,
)
from pivotcheck.models.network import DiscoveredNetwork
from pivotcheck.models.result import DiscoverySnapshot


def build_route_context(
    address: str,
    networks: tuple[DiscoveredNetwork, ...] | list[DiscoveredNetwork],
) -> RouteContext:
    """Find the most specific known network containing the address.

    Deterministic tie-breaking when multiple networks match (e.g. overlapping
    CIDRs): prefer the longest prefix; on equal prefixes prefer CONNECTED
    over ROUTED (direct evidence outranks routing evidence).
    """
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return RouteContext(context_type=RouteContextType.UNKNOWN)

    best: DiscoveredNetwork | None = None
    best_prefix = -1
    for net in networks:
        try:
            network = ipaddress.ip_network(net.cidr, strict=False)
        except ValueError:
            continue
        if network.version != addr.version or addr not in network:
            continue
        if network.prefixlen > best_prefix:
            best, best_prefix = net, network.prefixlen
        elif (
            network.prefixlen == best_prefix
            and best is not None
            and net.origin.value == "connected"
            and best.origin.value != "connected"
        ):
            best = net

    if best is None:
        return RouteContext(context_type=RouteContextType.UNKNOWN)

    return RouteContext(
        context_type=(
            RouteContextType.CONNECTED
            if best.origin.value == "connected"
            else RouteContextType.ROUTED
        ),
        network=best.cidr,
        gateway=best.gateway,
        interface=best.interface,
        confidence=best.confidence.value,
    )


def context_from_snapshot(address: str, snapshot: DiscoverySnapshot) -> RouteContext:
    """Convenience wrapper using an analyzed discovery snapshot."""
    return build_route_context(address, snapshot.networks)


def resolve_network_match(
    address: str,
    networks: tuple[DiscoveredNetwork, ...] | list[DiscoveredNetwork],
) -> NetworkMatch | None:
    """Resolve the most-specific normalized network containing an address.

    Deterministic rules:
    - Only networks of the same IP family as the address are considered.
    - The most-specific (longest-prefix) containing network wins.
    - On equal prefixes, CONNECTED outranks ROUTED (direct evidence).
    - Broader containing networks are preserved separately as context.
    - Returns None when no containing network is observed (MISSING CONTEXT,
      distinct from a known negative relationship).
    """
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return None

    containing: list[tuple[ipaddress._BaseNetwork, DiscoveredNetwork]] = []
    for net in networks:
        try:
            network = ipaddress.ip_network(net.cidr, strict=False)
        except ValueError:
            continue
        if network.version != addr.version or addr not in network:
            continue
        containing.append((network, net))

    if not containing:
        return None

    # Most-specific: longest prefix; on tie prefer CONNECTED.
    containing.sort(
        key=lambda item: (
            -item[0].prefixlen,
            0 if item[1].origin.value == "connected" else 1,
            str(item[0]),
        )
    )
    best_network, _ = containing[0]
    broader = sorted(
        {
            str(network)
            for network, _ in containing[1:]
            if network.prefixlen < best_network.prefixlen
        }
    )

    match_type = "EXACT" if best_network.prefixlen == addr.max_prefixlen else (
        "MOST_SPECIFIC" if len(containing) > 1 else "COVERED"
    )
    return NetworkMatch(
        network=str(best_network),
        match_type=match_type,
        broader_networks=tuple(broader),
    )


def resolve_comparison_context(
    network: str,
    report: DiffReport | None,
    baseline_name: str,
) -> ComparisonContext | None:
    """Determine how a network relates to a saved baseline perspective.

    Uses the existing comparison engine's findings; never re-implements
    comparison semantics. Returns None when no baseline comparison was
    requested (MISSING CONTEXT).
    """
    if report is None:
        return None
    canonical = str(ipaddress.ip_network(network, strict=False))
    for group, relationship in (
        (report.new_networks, "NEW_COVERAGE"),
        (report.coverage_changes, "EXPANDED_COVERAGE"),
        (report.specificity_changes, "MORE_SPECIFIC"),
        (report.context_changes, "CONTEXT_CHANGED"),
        (report.unchanged_networks, "UNCHANGED"),
    ):
        for finding in group:
            if finding.network == canonical:
                return ComparisonContext(
                    baseline=baseline_name,
                    relationship=relationship,
                    classification=finding.classification,
                    related_network=finding.related_network,
                )
    # The network exists in current evidence but has no direct finding
    # (e.g. a sub-network of collapsed coverage). This is a KNOWN state,
    # not missing context.
    return ComparisonContext(
        baseline=baseline_name,
        relationship="NOT_OBSERVED_IN_BASELINE",
    )


def resolve_priority_context(
    network: str,
    recommendations: tuple[Recommendation, ...],
) -> PriorityContext | None:
    """Associate an existing recommendation with a target's network.

    This is PRIORITIZATION CONTEXT only. It never creates a new
    recommendation and never treats a socket result as validation evidence.
    """
    canonical = str(ipaddress.ip_network(network, strict=False))
    for item in recommendations:
        if item.network == canonical:
            return PriorityContext(
                level=item.priority,
                reason=item.reason,
                network=item.network,
            )
    return None


def build_validation_context(
    address: str,
    snapshot: DiscoverySnapshot,
    *,
    report: DiffReport | None = None,
    baseline_name: str | None = None,
    recommendations: tuple[Recommendation, ...] = (),
) -> ValidationContext:
    """Build the full validation context for an explicitly chosen target.

    Pure and deterministic: no I/O, no socket activity, no rendering.
    The same snapshot is reused for route context, network relationship,
    comparison, and priority association — no duplicate discovery.
    """
    route_ctx = context_from_snapshot(address, snapshot)
    network_match = resolve_network_match(address, snapshot.networks)

    comparison: ComparisonContext | None = None
    priority: PriorityContext | None = None
    if network_match is not None and baseline_name is not None:
        comparison = resolve_comparison_context(
            network_match.network, report, baseline_name
        )
        priority = resolve_priority_context(network_match.network, recommendations)

    limitations: list[str] = []
    if route_ctx.context_type is RouteContextType.UNKNOWN:
        limitations.append(
            "No matching route context from discovery evidence; "
            "route context is absent, not confirmed absent."
        )
    else:
        limitations.append(
            "Route and topology evidence do not prove active reachability."
        )
    if network_match is None:
        limitations.append(
            "No containing network was observed in current discovery evidence."
        )
    if comparison is not None and comparison.relationship in (
        "NEW_COVERAGE",
        "EXPANDED_COVERAGE",
        "MORE_SPECIFIC",
        "CONTEXT_CHANGED",
    ):
        limitations.append(
            "Comparison findings describe evidence, not reachability."
        )

    return ValidationContext(
        target=address,
        network_match=network_match,
        route_context=route_ctx,
        comparison=comparison,
        priority=priority,
        limitations=tuple(limitations),
    )