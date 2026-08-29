"""Unit tests for topology analysis and the discovery engine."""

import json

import pytest

from pivotcheck.analysis.topology import (
    analyze,
    classify_networks,
    classify_routed_networks,
    infer_pivot_paths,
)
from pivotcheck.models.network import (
    Confidence,
    DNSConfig,
    DNSServer,
    Interface,
    InterfaceState,
    IPAddress,
    Neighbor,
    NetworkOrigin,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def make_snapshot(**overrides) -> DiscoverySnapshot:
    defaults = {
        "hostname": "testhost",
        "os_name": "Linux 6.1",
        "interfaces": (
            Interface(
                name="eth0",
                state=InterfaceState.UP,
                mac_address="aa:bb:cc:dd:ee:01",
                ipv4_addresses=(IPAddress("10.10.20.15", 24),),
            ),
            Interface(
                name="eth1",
                state=InterfaceState.UP,
                ipv4_addresses=(IPAddress("192.168.100.5", 24),),
            ),
        ),
        "routes": (
            Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
            Route("192.168.100.0/24", None, "eth1", 101, RouteType.CONNECTED),
            Route("172.16.50.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
        ),
    }
    defaults.update(overrides)
    return DiscoverySnapshot(**defaults)


class TestClassifyNetworks:
    def test_high_confidence_for_up_interface(self):
        nets = classify_networks(make_snapshot().interfaces)
        by_cidr = {n.cidr: n for n in nets}
        assert by_cidr["10.10.20.0/24"].confidence is Confidence.HIGH
        assert by_cidr["10.10.20.0/24"].origin is NetworkOrigin.CONNECTED

    def test_down_interface_is_low_confidence(self):
        snapshot = make_snapshot(
            interfaces=(
                Interface(
                    name="eth0",
                    state=InterfaceState.DOWN,
                    ipv4_addresses=(IPAddress("10.10.20.15", 24),),
                ),
            )
        )
        nets = classify_networks(snapshot.interfaces)
        assert nets[0].confidence is Confidence.LOW


class TestClassifyRoutedNetworks:
    def test_static_routes_become_medium_confidence(self):
        nets = classify_routed_networks(make_snapshot().routes)
        routed = {n.cidr: n for n in nets}
        assert routed["172.16.50.0/24"].confidence is Confidence.MEDIUM
        assert routed["172.16.50.0/24"].gateway == "10.10.20.254"

    def test_connected_and_default_excluded(self):
        nets = classify_routed_networks(make_snapshot().routes)
        cidrs = {n.cidr for n in nets}
        assert "default" not in cidrs
        assert "10.10.20.0/24" not in cidrs


class TestInferPivotPaths:
    def test_path_through_gateway(self):
        paths = infer_pivot_paths(
            make_snapshot().interfaces, make_snapshot().routes
        )
        assert len(paths) == 1
        assert paths[0].gateway == "10.10.20.254"
        assert paths[0].destination_network == "172.16.50.0/24"
        assert paths[0].source_interface == "eth0"
        assert paths[0].confidence is Confidence.MEDIUM

    def test_down_interface_suppresses_path(self):
        snapshot = make_snapshot(
            interfaces=(
                Interface(name="eth0", state=InterfaceState.DOWN),
            )
        )
        paths = infer_pivot_paths(snapshot.interfaces, snapshot.routes)
        assert paths == []


class TestAnalyze:
    def test_merges_connected_and_routed(self):
        result = analyze(make_snapshot())
        cidrs = {n.cidr for n in result.networks}
        assert cidrs == {
            "10.10.20.0/24",
            "192.168.100.0/24",
            "172.16.50.0/24",
        }

    def test_routed_duplicate_of_connected_dropped(self):
        snapshot = make_snapshot(
            routes=(
                Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
                Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
                # redundant static route to an already-connected net
                Route("10.10.20.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
            )
        )
        result = analyze(snapshot)
        entries = [n for n in result.networks if n.cidr == "10.10.20.0/24"]
        assert len(entries) == 1
        assert entries[0].origin is NetworkOrigin.CONNECTED

    def test_pivot_path_not_created_for_connected_net(self):
        snapshot = make_snapshot(
            routes=(
                Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
                Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
                Route("10.10.20.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
            )
        )
        result = analyze(snapshot)
        assert result.pivot_paths == ()


class TestSerialization:
    def test_snapshot_to_dict_is_json_serializable(self):
        snapshot = make_snapshot(
            neighbors=(Neighbor("10.10.20.1", "eth0", "aa:bb:cc:dd:ee:01", "REACHABLE"),),
            dns=DNSConfig(servers=(DNSServer("10.10.20.1"),), search_domains=("corp.lan",)),
        )
        analyzed = analyze(snapshot)
        data = analyzed.to_dict()
        serialized = json.dumps(data)  # must not raise
        parsed = json.loads(serialized)

        assert parsed["tool"] == "pivotcheck"
        assert parsed["hostname"] == "testhost"
        assert parsed["interfaces"][0]["name"] == "eth0"
        assert parsed["networks"][0]["cidr"] in {
            "10.10.20.0/24",
            "192.168.100.0/24",
            "172.16.50.0/24",
        }
        assert parsed["pivot_paths"][0]["gateway"] == "10.10.20.254"

    def test_warnings_survive_analysis(self):
        from pivotcheck.models.result import DiscoveryWarning

        snapshot = make_snapshot(
            warnings=(DiscoveryWarning("neighbors", "permission denied"),)
        )
        result = analyze(snapshot)
        assert result.warnings[0].message == "permission denied"


class TestModelValidation:
    def test_invalid_ip_rejected(self):
        with pytest.raises(ValueError):
            IPAddress("999.999.999.999", 24)

    def test_invalid_prefix_rejected(self):
        with pytest.raises(ValueError):
            IPAddress("10.0.0.1", 99)

    def test_invalid_route_destination_rejected(self):
        with pytest.raises(ValueError):
            Route("not-a-cidr", None, "eth0")

    def test_invalid_gateway_rejected(self):
        with pytest.raises(ValueError):
            Route("10.0.0.0/24", "not-an-ip", "eth0")

    def test_invalid_neighbor_ip_rejected(self):
        with pytest.raises(ValueError):
            Neighbor("nope", "eth0")
