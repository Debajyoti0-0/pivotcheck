"""Transit evidence correlation engine.

Pure analysis over normalized discovery models — no system access, no socket logic.
Correlates routes, neighbors, and connections per transit candidate (PivotPath).
"""

from __future__ import annotations

import ipaddress

from pivotcheck.models.check import (
    TransitEvidence,
    TransitEvidenceCollection,
    _derive_transit_assessment,
)
from pivotcheck.models.network import (
    Connection,
    ConnectionProtocol,
    Neighbor,
    PivotPath,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def assess_transit_evidence(snapshot: DiscoverySnapshot) -> TransitEvidenceCollection:
    """Correlate passive evidence per transit candidate.

    Deterministic, order-independent, no I/O, no network activity.
    The candidate universe is the existing inferred PivotPaths.
    """
    # Build lookup indexes for efficient correlation
    route_index = _index_routes(snapshot.routes)
    neighbor_index = _index_neighbors(snapshot.neighbors)
    connection_index = _index_connections(snapshot.connections)

    candidates: list[TransitEvidence] = []

    for pivot_path in snapshot.pivot_paths:
        evidence = _correlate_candidate(
            pivot_path=pivot_path,
            route_index=route_index,
            neighbor_index=neighbor_index,
            connection_index=connection_index,
        )
        candidates.append(evidence)

    # Deterministic sort: by gateway, then destination_network, then interface
    candidates.sort(
        key=lambda c: (
            c.gateway,
            c.destination_network,
            c.source_interface,
        )
    )

    return TransitEvidenceCollection(
        candidates=tuple(candidates),
        snapshot_timestamp=snapshot.timestamp,
    )


def _index_routes(routes: tuple[Route, ...]) -> dict[tuple[str, str], Route]:
    """Index routes by (gateway, destination_network) for PivotPath correlation.

    Returns the most specific (longest prefix) route for each gateway+dest pair.
    """
    index: dict[tuple[str, str], Route] = {}
    for route in routes:
        if route.route_type is not RouteType.STATIC or route.gateway is None:
            continue
        if route.destination == "default":
            continue
        try:
            dest_net = ipaddress.ip_network(route.destination, strict=False)
        except ValueError:
            continue
        key = (route.gateway, str(dest_net))
        existing = index.get(key)
        if existing is None:
            index[key] = route
        else:
            # Prefer more specific (longer prefix)
            try:
                existing_net = ipaddress.ip_network(existing.destination, strict=False)
                if dest_net.prefixlen > existing_net.prefixlen:
                    index[key] = route
            except ValueError:
                pass
    return index


def _index_neighbors(neighbors: tuple[Neighbor, ...]) -> dict[tuple[str, str], Neighbor]:
    """Index neighbors by (ip_address, interface).

    Deduplicates by keeping the first occurrence (deterministic after sorting).
    """
    # Sort for deterministic deduplication
    sorted_neighbors = sorted(
        neighbors,
        key=lambda n: (n.ip_address, n.interface, n.state or "", n.mac_address or "")
    )
    index: dict[tuple[str, str], Neighbor] = {}
    for neighbor in sorted_neighbors:
        key = (neighbor.ip_address, neighbor.interface)
        if key not in index:
            index[key] = neighbor
    return index


def _index_connections(connections: tuple[Connection, ...]) -> dict[str, list[Connection]]:
    """Index connections by gateway IP (both remote_address and local_address for LISTEN).

    Returns all connections where remote_address or local_address (for LISTEN) matches a gateway.
    """
    index: dict[str, list[Connection]] = {}
    for conn in connections:
        # Normalize addresses (strip zone index for IPv6)
        remote = conn.remote_address.split("%")[0] if conn.remote_address else None
        local = conn.local_address.split("%")[0] if conn.local_address else None

        # Index by remote address (outbound connections to gateway)
        if remote:
            index.setdefault(remote, []).append(conn)

        # Also index LISTEN sockets by local address (gateway listening on local interface)
        if conn.state == "LISTEN" and local:
            index.setdefault(local, []).append(conn)
    return index


def _is_loopback_address(address: str) -> bool:
    """Check if an address is loopback."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
        return ip.is_loopback
    except ValueError:
        return False


def _correlate_candidate(
    *,
    pivot_path: PivotPath,
    route_index: dict[tuple[str, str], Route],
    neighbor_index: dict[tuple[str, str], Neighbor],
    connection_index: dict[str, list[Connection]],
) -> TransitEvidence:
    """Correlate all evidence for a single transit candidate."""
    gateway = pivot_path.gateway
    destination_network = pivot_path.destination_network
    source_interface = pivot_path.source_interface

    # Determine address family
    try:
        gateway_ip = ipaddress.ip_address(gateway)
        address_family = gateway_ip.version
    except ValueError:
        address_family = 4  # fallback, validation will catch invalid

    # Route evidence
    route_key = (gateway, destination_network)
    route = route_index.get(route_key)
    route_metric = route.metric if route else None

    # Neighbor evidence (match on gateway IP + source_interface)
    neighbor_key = (gateway, source_interface)
    neighbor = neighbor_index.get(neighbor_key)
    neighbor_observed = neighbor is not None
    neighbor_state = neighbor.state if neighbor else None
    neighbor_mac = neighbor.mac_address if neighbor else None

    # Connection evidence
    connections_to_gateway = connection_index.get(gateway, [])

    # Filter and categorize connections
    tcp_states: list[str] = []
    udp_count = 0
    has_listen = False
    has_loopback = False

    # Deduplicate connections by (protocol, local_addr, local_port, remote_addr, remote_port, state)
    seen_connections: set[tuple] = set()

    for conn in connections_to_gateway:
        # Create deduplication key
        dedup_key = (
            conn.protocol.value,
            conn.local_address,
            conn.local_port,
            conn.remote_address,
            conn.remote_port,
            conn.state,
        )
        if dedup_key in seen_connections:
            continue
        seen_connections.add(dedup_key)

        # Check for loopback connections (both local and remote)
        is_loopback = False
        if conn.remote_address and _is_loopback_address(conn.remote_address):
            is_loopback = True
        if conn.local_address and _is_loopback_address(conn.local_address):
            is_loopback = True

        if is_loopback:
            has_loopback = True
            continue

        if conn.protocol == ConnectionProtocol.TCP:
            if conn.state:
                tcp_states.append(conn.state)
        elif (
            conn.protocol == ConnectionProtocol.UDP
            and conn.state
            and conn.state not in ("UNCONN",)
        ):
            # UDP connections with state (from ss parser)
            udp_count += 1

        # Check for LISTEN on gateway (local_address == gateway)
        if conn.state == "LISTEN" and conn.local_address and conn.local_address.split("%")[0] == gateway:
            has_listen = True

    # Deduplicate TCP states while preserving order (sort for determinism)
    unique_tcp_states = tuple(sorted(set(tcp_states)))
    tcp_count = sum(1 for state in tcp_states if state == "ESTABLISHED")

    # Derive assessment (canonical implementation lives in models.check and
    # is shared with TransitEvidence model validation; route_present is
    # always True for PivotPath-derived candidates by definition)
    assessment = _derive_transit_assessment(
        route_present=True,
        neighbor_observed=neighbor_observed,
        neighbor_state=neighbor_state,
        tcp_connections_to_gateway=tcp_count,
        tcp_connection_states=unique_tcp_states,
        udp_flows_to_gateway=udp_count,
        has_listen_on_gateway=has_listen,
        has_loopback_to_gateway=has_loopback,
    )

    return TransitEvidence(
        source_interface=source_interface,
        gateway=gateway,
        destination_network=destination_network,
        address_family=address_family,
        route_present=True,
        route_metric=route_metric,
        route_type="static",
        neighbor_observed=neighbor_observed,
        neighbor_state=neighbor_state,
        neighbor_mac=neighbor_mac,
        tcp_connections_to_gateway=tcp_count,
        tcp_connection_states=unique_tcp_states,
        udp_flows_to_gateway=udp_count,
        has_listen_on_gateway=has_listen,
        has_loopback_to_gateway=has_loopback,
        assessment=assessment,
    )


# NOTE: `_derive_transit_assessment` is intentionally NOT defined here.
# The single canonical implementation lives in `pivotcheck.models.check`
# and is imported above; TransitEvidence model validation and production
# correlation must never drift apart.
