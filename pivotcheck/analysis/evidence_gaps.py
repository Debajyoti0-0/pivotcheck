"""Evidence gap analysis: identify what evidence is missing for a network candidate.

Pure analysis over DiscoverySnapshot — no system access, no socket logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pivotcheck.models.network import (
    DiscoveredNetwork as Network,
)
from pivotcheck.models.result import DiscoverySnapshot


class EvidenceStatus(str, Enum):
    """Status of evidence collection for a specific evidence type."""

    OBSERVED = "OBSERVED"
    NOT_OBSERVED = "NOT_OBSERVED"
    NOT_COLLECTED = "NOT_COLLECTED"
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_PERFORMED = "NOT_PERFORMED"


@dataclass(frozen=True)
class EvidenceGap:
    """Gap analysis for a single evidence type."""

    evidence_type: str  # "route", "neighbor", "connection", "active_validation"
    status: EvidenceStatus
    details: str
    supporting_data: dict[str, object] | None = None

    def to_dict(self) -> dict:
        data: dict[str, object] = {
            "evidence_type": self.evidence_type,
            "status": self.status.value,
            "details": self.details,
        }
        if self.supporting_data is not None:
            data["supporting_data"] = self.supporting_data
        return data


@dataclass(frozen=True)
class GapsReport:
    """Complete evidence gap analysis for a network."""

    schema_version: str = "1.0"
    tool: str = "pivotcheck"
    version: str = ""
    command: str = "gaps"
    timestamp: str = ""
    network: str = ""
    gaps: tuple[EvidenceGap, ...] = ()

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "tool": self.tool,
            "version": self.version,
            "command": self.command,
            "timestamp": self.timestamp,
            "network": self.network,
            "gaps": [g.to_dict() for g in self.gaps],
        }


def analyze_evidence_gaps(
    snapshot: DiscoverySnapshot,
    network: str,
) -> GapsReport:
    """Analyze what evidence is present vs. missing for a network.

    Pure function: no I/O, no network activity, deterministic.

    Distinguishes:
    - OBSERVED: Collector ran and found evidence
    - NOT_OBSERVED: Collector ran but found no evidence for this network
    - NOT_COLLECTED: Collector was unavailable/degraded
    - NEGATIVE_EVIDENCE: Collector explicitly found absence (e.g., neighbor FAILED)
    - NOT_APPLICABLE: Evidence type doesn't apply to this context
    """
    from datetime import datetime, timezone

    from pivotcheck import __version__

    # Find the network in the snapshot
    target_network = None
    for net in snapshot.networks:
        if net.cidr == network:
            target_network = net
            break

    if target_network is None:
        # Network not in current snapshot - check if it's a sub-network of any known network
        # For now, treat as not observed
        from pivotcheck.models.network import Confidence, NetworkOrigin
        target_network = Network(
            cidr=network,
            origin=NetworkOrigin.INFERRED,
            confidence=Confidence.LOW,
        )

    gaps: list[EvidenceGap] = []

    # Route evidence
    route_gap = _analyze_route_evidence(snapshot, target_network)
    gaps.append(route_gap)

    # Neighbor evidence
    neighbor_gap = _analyze_neighbor_evidence(snapshot, target_network)
    gaps.append(neighbor_gap)

    # Connection evidence
    connection_gap = _analyze_connection_evidence(snapshot, target_network)
    gaps.append(connection_gap)

    # Active validation evidence
    validation_gap = _analyze_validation_evidence(snapshot, target_network)
    gaps.append(validation_gap)

    return GapsReport(
        version=__version__,
        timestamp=datetime.now(timezone.utc).isoformat(),
        network=network,
        gaps=tuple(gaps),
    )


def _analyze_route_evidence(
    snapshot: DiscoverySnapshot,
    network: Network,
) -> EvidenceGap:
    """Analyze route evidence for the network."""
    # Check if any route matches this network
    matching_routes = [
        r for r in snapshot.routes
        if r.destination == network.cidr or _network_contains(network.cidr, r.destination)
    ]

    if matching_routes:
        best_route = min(matching_routes, key=lambda r: r.metric or 9999)
        return EvidenceGap(
            evidence_type="route",
            status=EvidenceStatus.OBSERVED,
            details=f"Route to {best_route.destination} via {best_route.gateway} dev {best_route.interface} metric {best_route.metric}",
            supporting_data={
                "destination": best_route.destination,
                "gateway": best_route.gateway,
                "interface": best_route.interface,
                "metric": best_route.metric,
                "route_type": best_route.route_type.value if best_route.route_type else "unknown",
            },
        )
    else:
        return EvidenceGap(
            evidence_type="route",
            status=EvidenceStatus.NOT_OBSERVED,
            details=f"No route entry found for {network.cidr} in current routing table",
            supporting_data=None,
        )


def _analyze_neighbor_evidence(
    snapshot: DiscoverySnapshot,
    network: Network,
) -> EvidenceGap:
    """Analyze neighbor (ARP/ND) evidence for the network's gateway."""
    # Find the gateway for this network from routes
    gateway = None
    for route in snapshot.routes:
        if (route.destination == network.cidr or _network_contains(network.cidr, route.destination)) and route.gateway:
            gateway = route.gateway
            break

    if not gateway:
        return EvidenceGap(
            evidence_type="neighbor",
            status=EvidenceStatus.NOT_APPLICABLE,
            details="No gateway identified for this network (directly connected or no route)",
            supporting_data=None,
        )

    # Check if neighbor table has entry for this gateway
    matching_neighbors = [
        n for n in snapshot.neighbors
        if n.ip_address == gateway
    ]

    if not matching_neighbors:
        return EvidenceGap(
            evidence_type="neighbor",
            status=EvidenceStatus.NOT_OBSERVED,
            details=f"No ARP/ND entry for gateway {gateway}",
            supporting_data={"gateway": gateway},
        )

    neighbor = matching_neighbors[0]
    if neighbor.state == "FAILED":
        return EvidenceGap(
            evidence_type="neighbor",
            status=EvidenceStatus.NEGATIVE_EVIDENCE,
            details=f"Gateway {gateway} neighbor state is FAILED",
            supporting_data={
                "gateway": gateway,
                "state": neighbor.state,
                "mac": neighbor.mac_address,
                "interface": neighbor.interface,
            },
        )

    return EvidenceGap(
        evidence_type="neighbor",
        status=EvidenceStatus.OBSERVED,
        details=f"Gateway {gateway} neighbor state: {neighbor.state}",
        supporting_data={
            "gateway": gateway,
            "state": neighbor.state,
            "mac": neighbor.mac_address,
            "interface": neighbor.interface,
        },
    )


def _analyze_connection_evidence(
    snapshot: DiscoverySnapshot,
    network: Network,
) -> EvidenceGap:
    """Analyze socket/connection evidence for the network's gateway."""
    gateway = None
    for route in snapshot.routes:
        if (route.destination == network.cidr or _network_contains(network.cidr, route.destination)) and route.gateway:
            gateway = route.gateway
            break

    if not gateway:
        return EvidenceGap(
            evidence_type="connection",
            status=EvidenceStatus.NOT_APPLICABLE,
            details="No gateway identified for this network",
            supporting_data=None,
        )

    # Check for connections to gateway
    connections_to_gateway = [
        c for c in snapshot.connections
        if c.remote_address and c.remote_address.split("%")[0] == gateway
    ]

    if not connections_to_gateway:
        # Check if connection collection was available at all
        if snapshot.connections:
            return EvidenceGap(
                evidence_type="connection",
                status=EvidenceStatus.NOT_OBSERVED,
                details=f"No active connections to gateway {gateway}",
                supporting_data={"gateway": gateway, "total_connections": len(snapshot.connections)},
            )
        else:
            return EvidenceGap(
                evidence_type="connection",
                status=EvidenceStatus.NOT_COLLECTED,
                details="Socket/connection collection was unavailable",
                supporting_data=None,
            )

    # Categorize connections
    tcp_established = sum(1 for c in connections_to_gateway if c.protocol.value == "tcp" and c.state == "ESTABLISHED")
    tcp_other = sum(1 for c in connections_to_gateway if c.protocol.value == "tcp" and c.state != "ESTABLISHED")
    udp_count = sum(1 for c in connections_to_gateway if c.protocol.value == "udp")

    return EvidenceGap(
        evidence_type="connection",
        status=EvidenceStatus.OBSERVED,
        details=f"Connections to gateway {gateway}: {tcp_established} ESTABLISHED TCP, {tcp_other} other TCP, {udp_count} UDP",
        supporting_data={
            "gateway": gateway,
            "tcp_established": tcp_established,
            "tcp_other_states": tcp_other,
            "udp_count": udp_count,
            "total": len(connections_to_gateway),
        },
    )


def _analyze_validation_evidence(
    snapshot: DiscoverySnapshot,
    network: Network,
) -> EvidenceGap:
    """Analyze active validation evidence for the network."""
    # PivotCheck does not perform automatic validation
    # This is always NOT_PERFORMED unless explicitly done by operator
    return EvidenceGap(
        evidence_type="active_validation",
        status=EvidenceStatus.NOT_PERFORMED,
        details="No active validation performed. Run 'pivotcheck check <target> --port <port>' for explicit validation.",
        supporting_data=None,
    )


def _network_contains(network_cidr: str, route_destination: str) -> bool:
    """Check if a route destination is contained within a network CIDR."""
    try:
        import ipaddress
        network = ipaddress.ip_network(network_cidr, strict=False)
        if route_destination == "default":
            return False
        route_net = ipaddress.ip_network(route_destination, strict=False)
        # Both must be same version for subnet_of to work
        if network.version != route_net.version:
            return False
        # mypy doesn't narrow the union type after version check
        return route_net.subnet_of(network)  # type: ignore[arg-type]
    except ValueError:
        return False