"""Determinism and input-order independence regression tests.

These tests ensure that PivotCheck's analysis layer produces identical
semantic results regardless of input ordering, iteration order, or
timing. This is critical for operator trust and reproducible results.
"""

from __future__ import annotations

import json
import random

from pivotcheck.analysis.comparison import DiffReport, baseline_from_snapshot, compare
from pivotcheck.analysis.evidence_gaps import analyze_evidence_gaps
from pivotcheck.analysis.explanation import explain_network
from pivotcheck.analysis.gateway import assess_transit_evidence
from pivotcheck.analysis.next_step import select_next_investigation
from pivotcheck.analysis.recommendation import recommend
from pivotcheck.analysis.topology import analyze
from pivotcheck.models.network import (
    Confidence,
    Connection,
    ConnectionProtocol,
    DiscoveredNetwork,
    Interface,
    InterfaceState,
    IPAddress,
    Neighbor,
    NetworkOrigin,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.session import SessionIdentity as Session


def _make_interface(name: str, ip: str, prefix: int) -> Interface:
    return Interface(
        name=name,
        state=InterfaceState.UP,
        mac_address="00:11:22:33:44:55",
        ipv4_addresses=(IPAddress(address=ip, prefix=prefix),),
        ipv6_addresses=(),
    )


def _make_route(dest: str, gw: str | None, iface: str, rtype: RouteType, metric: int | None = 100) -> Route:
    return Route(
        destination=dest,
        gateway=gw,
        interface=iface,
        route_type=rtype,
        metric=metric,
    )


def _make_neighbor(ip: str, iface: str, state: str = "REACHABLE") -> Neighbor:
    return Neighbor(ip_address=ip, interface=iface, mac_address="aa:bb:cc:dd:ee:ff", state=state)


def _make_connection(proto: str, local: str, lport: int, remote: str, rport: int, state: str) -> Connection:
    return Connection(
        protocol=ConnectionProtocol.TCP if proto == "tcp" else ConnectionProtocol.UDP,
        local_address=local,
        local_port=lport,
        remote_address=remote,
        remote_port=rport,
        state=state,
    )


def _make_network(cidr: str, origin: NetworkOrigin, conf: Confidence, iface: str | None = None, gw: str | None = None) -> DiscoveredNetwork:
    return DiscoveredNetwork(cidr=cidr, origin=origin, confidence=conf, interface=iface, gateway=gw)


def _make_pivot_path(iface: str, gw: str, dest: str, conf: Confidence) -> None:
    pass  # handled by topology analysis


def _make_snapshot(
    interfaces: list[Interface],
    routes: list[Route],
    neighbors: list[Neighbor],
    connections: list[Connection],
    networks: list[DiscoveredNetwork],
) -> DiscoverySnapshot:
    """Create a snapshot and run analysis to populate pivot_paths."""
    base_snapshot = DiscoverySnapshot(
        hostname="test-host",
        os_name="Linux",
        timestamp="2026-08-29T00:00:00+00:00",
        session=Session(provider="local", display_name="Test Host"),
        interfaces=tuple(interfaces),
        routes=tuple(routes),
        neighbors=tuple(neighbors),
        connections=tuple(connections),
        networks=tuple(networks),
        pivot_paths=(),
    )
    # Run topology analysis to populate pivot_paths
    return analyze(base_snapshot)


def _normalize_timestamps(obj: dict) -> dict:
    """Remove or normalize timestamps for deterministic comparison."""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in ("timestamp", "created_at", "snapshot_timestamp", "session_id"):
                result[k] = "NORMALIZED"
            elif isinstance(v, dict):
                result[k] = _normalize_timestamps(v)
            elif isinstance(v, list):
                result[k] = [_normalize_timestamps(item) if isinstance(item, dict) else item for item in v]
            else:
                result[k] = v
        return result
    return obj


class TestDeterminism:
    """Test that identical inputs produce identical outputs."""

    def test_topology_analysis_deterministic(self):
        """Same snapshot -> same analysis result."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]
        networks = [_make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0")]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)

        result1 = analyze(snapshot)
        result2 = analyze(snapshot)

        assert result1.networks == result2.networks
        assert result1.pivot_paths == result2.pivot_paths

    def test_transit_evidence_deterministic(self):
        """Same snapshot -> same transit evidence."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)

        evidence1 = assess_transit_evidence(snapshot)
        evidence2 = assess_transit_evidence(snapshot)

        assert evidence1.candidates == evidence2.candidates

    def test_next_step_deterministic(self):
        """Same snapshot -> same next candidate."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [
            _make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC),
            _make_route("10.60.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC),
        ]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
            _make_network("10.60.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)
        transit = assess_transit_evidence(snapshot)

        next1 = select_next_investigation(snapshot, transit_evidence=transit)
        next2 = select_next_investigation(snapshot, transit_evidence=transit)

        d1 = _normalize_timestamps(next1.to_dict())
        d2 = _normalize_timestamps(next2.to_dict())
        assert d1 == d2

    def test_recommendation_deterministic(self):
        """Same snapshot -> same recommendations."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = []
        networks = [_make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1")]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)

        recs1 = recommend(snapshot, DiffReport())
        recs2 = recommend(snapshot, DiffReport())

        assert [r.to_dict() for r in recs1] == [r.to_dict() for r in recs2]

    def test_evidence_gaps_deterministic(self):
        """Same snapshot -> same gaps analysis."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = []
        connections = []
        networks = [_make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1")]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)

        gaps1 = analyze_evidence_gaps(snapshot, "10.50.0.0/16")
        gaps2 = analyze_evidence_gaps(snapshot, "10.50.0.0/16")

        d1 = _normalize_timestamps(gaps1.to_dict())
        d2 = _normalize_timestamps(gaps2.to_dict())
        assert d1 == d2

    def test_explanation_deterministic(self):
        """Same snapshot -> same explanation."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = []
        connections = []
        networks = [_make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1")]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)

        exp1 = explain_network("10.50.0.0/16", snapshot)
        exp2 = explain_network("10.50.0.0/16", snapshot)

        d1 = _normalize_timestamps(exp1.to_dict())
        d2 = _normalize_timestamps(exp2.to_dict())
        assert d1 == d2


class TestInputOrderIndependence:
    """Test that input ordering does not affect analysis results."""

    def test_interface_order_independence(self):
        """Interface order should not matter."""
        iface1 = _make_interface("eth0", "10.10.20.5", 24)
        iface2 = _make_interface("eth1", "10.20.30.5", 24)

        routes = [
            _make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC),
            _make_route("10.60.0.0/16", "10.20.30.1", "eth1", RouteType.STATIC),
        ]
        neighbors = [
            _make_neighbor("10.10.20.1", "eth0"),
            _make_neighbor("10.20.30.1", "eth1"),
        ]
        connections = [
            _make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED"),
            _make_connection("tcp", "10.20.30.5", 55666, "10.20.30.1", 22, "ESTABLISHED"),
        ]
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.20.30.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth1"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
            _make_network("10.60.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth1", "10.20.30.1"),
        ]

        # Test all permutations of interface order
        for ifaces in ([iface1, iface2], [iface2, iface1]):
            snapshot = _make_snapshot(ifaces, routes, neighbors, connections, networks)
            result = analyze(snapshot)
            # Networks should be identical regardless of input order
            assert {n.cidr for n in result.networks} == {
                "10.10.20.0/24",
                "10.20.30.0/24",
                "10.50.0.0/16",
                "10.60.0.0/16",
            }

    def test_route_order_independence(self):
        """Route order should not matter."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]

        route1 = _make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)
        route2 = _make_route("10.60.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)
        route3 = _make_route("10.70.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)

        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
            _make_network("10.60.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
            _make_network("10.70.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        routes_list = [route1, route2, route3]
        for _ in range(10):
            shuffled = routes_list.copy()
            random.shuffle(shuffled)
            snapshot = _make_snapshot(interfaces, shuffled, neighbors, connections, networks)
            result = analyze(snapshot)
            assert {n.cidr for n in result.networks} == {
                "10.10.20.0/24",
                "10.50.0.0/16",
                "10.60.0.0/16",
                "10.70.0.0/16",
            }

    def test_connection_order_independence(self):
        """Connection order should not matter."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]

        conn1 = _make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")
        conn2 = _make_connection("tcp", "10.10.20.5", 44556, "10.10.20.1", 22, "ESTABLISHED")
        conn3 = _make_connection("tcp", "10.10.20.5", 44557, "10.10.20.1", 22, "TIME_WAIT")

        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        connections_list = [conn1, conn2, conn3]
        for _ in range(10):
            shuffled = connections_list.copy()
            random.shuffle(shuffled)
            snapshot = _make_snapshot(interfaces, routes, neighbors, shuffled, networks)
            transit = assess_transit_evidence(snapshot)
            # Transit evidence should be identical
            assert len(transit.candidates) == 1
            assert transit.candidates[0].tcp_connections_to_gateway == 2  # 2 ESTABLISHED

    def test_network_order_independence(self):
        """Network order should not matter."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [
            _make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC),
            _make_route("10.60.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC),
        ]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]

        net1 = _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0")
        net2 = _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1")
        net3 = _make_network("10.60.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1")

        networks_list = [net1, net2, net3]
        for _ in range(10):
            shuffled = networks_list.copy()
            random.shuffle(shuffled)
            snapshot = _make_snapshot(interfaces, routes, neighbors, connections, shuffled)
            result = analyze(snapshot)
            assert {n.cidr for n in result.networks} == {
                "10.10.20.0/24",
                "10.50.0.0/16",
                "10.60.0.0/16",
            }

    def test_neighbor_order_independence(self):
        """Neighbor order should not matter."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [
            _make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC),
            _make_route("10.60.0.0/16", "10.10.20.2", "eth0", RouteType.STATIC),
        ]
        connections = []
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
            _make_network("10.60.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.2"),
        ]

        neighbors_list = [
            _make_neighbor("10.10.20.1", "eth0"),
            _make_neighbor("10.10.20.2", "eth0"),
        ]
        for _ in range(10):
            shuffled = neighbors_list.copy()
            random.shuffle(shuffled)
            snapshot = _make_snapshot(interfaces, routes, shuffled, connections, networks)
            transit = assess_transit_evidence(snapshot)
            assert len(transit.candidates) == 2


class TestRepeatedExecution:
    """Test that repeated execution produces identical results."""

    def test_repeated_next_step(self):
        """Running next multiple times yields same candidate."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)
        transit = assess_transit_evidence(snapshot)

        results = []
        for _ in range(5):
            next_report = select_next_investigation(snapshot, transit_evidence=transit)
            results.append(_normalize_timestamps(next_report.to_dict()))

        # All results should be identical
        for r in results[1:]:
            assert r == results[0]

    def test_json_serialization_stable(self):
        """JSON serialization should be stable."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)
        transit = assess_transit_evidence(snapshot)
        next_report = select_next_investigation(snapshot, transit_evidence=transit)

        # Serialize multiple times
        json_strings = []
        for _ in range(5):
            json_strings.append(json.dumps(next_report.to_dict(), sort_keys=True))

        # All JSON strings should be identical
        for s in json_strings[1:]:
            assert s == json_strings[0]


class TestComparisonDeterminism:
    """Test that comparison is deterministic."""

    def test_compare_deterministic(self):
        """Same snapshots -> same diff."""
        interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
        routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
        neighbors = [_make_neighbor("10.10.20.1", "eth0")]
        connections = []
        networks = [
            _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
            _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
        ]

        snapshot = _make_snapshot(interfaces, routes, neighbors, connections, networks)
        baseline = baseline_from_snapshot(snapshot)

        diff1 = compare(baseline, baseline)
        diff2 = compare(baseline, baseline)

        # Normalize and compare
        d1 = diff1.to_dict() if hasattr(diff1, "to_dict") else str(diff1)
        d2 = diff2.to_dict() if hasattr(diff2, "to_dict") else str(diff2)
        assert d1 == d2