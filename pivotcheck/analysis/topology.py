"""Topology analysis: network normalization, classification, pivot paths.

Consumes normalized discovery models and produces DiscoveredNetwork /
PivotPath classifications. Pure functions — no system access.
"""

from __future__ import annotations

import ipaddress

from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    Interface,
    InterfaceState,
    NetworkOrigin,
    PivotPath,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def classify_networks(
    interfaces: tuple[Interface, ...],
) -> list[DiscoveredNetwork]:
    """Classify directly connected networks from interface addressing.

    HIGH confidence requires an UP interface carrying the address.
    """
    networks: dict[str, DiscoveredNetwork] = {}
    for iface in interfaces:
        confidence = (
            Confidence.HIGH if iface.state == InterfaceState.UP else Confidence.LOW
        )
        for addr in iface.ipv4_addresses + iface.ipv6_addresses:
            if addr.prefix == 0:
                continue
            net = DiscoveredNetwork(
                cidr=addr.network,
                origin=NetworkOrigin.CONNECTED,
                confidence=confidence,
                interface=iface.name,
                gateway=None,
            )
            # Prefer HIGH-confidence entry if seen twice (e.g. iface flapped)
            existing = networks.get(net.cidr)
            if existing is None or (
                existing.confidence is not Confidence.HIGH
                and net.confidence is Confidence.HIGH
            ):
                networks[net.cidr] = net
    return list(networks.values())


def classify_routed_networks(routes: tuple[Route, ...]) -> list[DiscoveredNetwork]:
    """Classify networks reachable via gateways (MEDIUM confidence)."""
    networks: list[DiscoveredNetwork] = []
    for route in routes:
        if route.route_type is not RouteType.STATIC or route.gateway is None:
            continue
        networks.append(
            DiscoveredNetwork(
                cidr=str(ipaddress.ip_network(route.destination, strict=False)),
                origin=NetworkOrigin.ROUTED,
                confidence=Confidence.MEDIUM,
                interface=route.interface,
                gateway=route.gateway,
            )
        )
    return networks


def infer_pivot_paths(interfaces: tuple, routes: tuple[Route, ...]) -> list[PivotPath]:
    """Infer potential pivot paths: this host -> gateway -> routed network.

    Only MEDIUM-confidence paths are produced here; they are explicitly
    *potential* until validated with an active check.
    """
    up_interfaces = {i.name for i in interfaces if i.state == InterfaceState.UP}
    paths: list[PivotPath] = []
    for route in routes:
        if route.route_type is not RouteType.STATIC or route.gateway is None:
            continue
        if route.interface not in up_interfaces:
            continue
        paths.append(
            PivotPath(
                source_interface=route.interface,
                gateway=route.gateway,
                destination_network=str(
                    ipaddress.ip_network(route.destination, strict=False)
                ),
                confidence=Confidence.MEDIUM,
            )
        )
    return paths


def analyze(snapshot: DiscoverySnapshot) -> DiscoverySnapshot:
    """Return a new snapshot with networks and pivot_paths populated."""
    connected = classify_networks(snapshot.interfaces)
    routed = classify_routed_networks(snapshot.routes)

    # Merge: routed entries that duplicate a connected network are dropped —
    # direct connectivity supersedes a gateway path to the same CIDR.
    connected_cidrs = {n.cidr for n in connected}
    merged = connected + [n for n in routed if n.cidr not in connected_cidrs]

    pivot_paths = infer_pivot_paths(snapshot.interfaces, snapshot.routes)
    # A pivot path through a gateway into an already-connected network adds
    # nothing; filter those out.
    pivot_paths = [
        p for p in pivot_paths if p.destination_network not in connected_cidrs
    ]

    return DiscoverySnapshot(
        hostname=snapshot.hostname,
        os_name=snapshot.os_name,
        interfaces=snapshot.interfaces,
        routes=snapshot.routes,
        neighbors=snapshot.neighbors,
        dns=snapshot.dns,
        connections=snapshot.connections,
        networks=tuple(merged),
        pivot_paths=tuple(pivot_paths),
        warnings=snapshot.warnings,
        session=snapshot.session,
        timestamp=snapshot.timestamp,
        tool_version=snapshot.tool_version,
    )
