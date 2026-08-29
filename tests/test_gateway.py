"""Tests for transit evidence correlation engine (pure analysis).

Covers:
- Assessment enum values and semantics
- TransitEvidence model validation
- Pure correlation logic
- Determinism and edge cases
"""

import pytest

from pivotcheck.analysis.gateway import (
    _derive_transit_assessment,
    assess_transit_evidence,
)
from pivotcheck.models.check import (
    TransitEvidence,
    TransitEvidenceAssessment,
    TransitEvidenceCollection,
)
from pivotcheck.models.network import (
    Confidence,
    Connection,
    ConnectionProtocol,
    Interface,
    InterfaceState,
    IPAddress,
    Neighbor,
    PivotPath,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def make_snapshot(**overrides) -> DiscoverySnapshot:
    """Create a test snapshot with sensible defaults."""
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
        "neighbors": (),
        "connections": (),
    }
    defaults.update(overrides)
    return DiscoverySnapshot(**defaults)


def make_pivot_path(
    gateway: str = "10.10.20.254",
    destination_network: str = "172.16.50.0/24",
    source_interface: str = "eth0",
) -> PivotPath:
    return PivotPath(
        source_interface=source_interface,
        gateway=gateway,
        destination_network=destination_network,
        confidence=Confidence.MEDIUM,
    )


def make_neighbor(
    ip: str = "10.10.20.254",
    interface: str = "eth0",
    state: str = "REACHABLE",
    mac: str = "aa:bb:cc:dd:ee:ff",
) -> Neighbor:
    return Neighbor(ip_address=ip, interface=interface, mac_address=mac, state=state)


def make_connection(
    protocol: ConnectionProtocol = ConnectionProtocol.TCP,
    local_address: str = "10.10.20.15",
    local_port: int = 12345,
    remote_address: str = "10.10.20.254",
    remote_port: int = 445,
    state: str = "ESTABLISHED",
) -> Connection:
    return Connection(
        protocol=protocol,
        local_address=local_address,
        local_port=local_port,
        remote_address=remote_address,
        remote_port=remote_port,
        state=state,
    )


class TestTransitEvidenceAssessment:
    """Test the assessment enum values and semantics."""

    def test_all_enum_values_exist(self):
        """Verify all expected assessment values exist."""
        expected = {
            "ROUTING_ONLY",
            "ROUTING_PLUS_L2_EVIDENCE",
            "ROUTING_PLUS_ACTIVE_TCP_EVIDENCE",
            "ROUTING_PLUS_ACTIVE_UDP_EVIDENCE",
            "ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE",
            "MULTIPLE_SUPPORTING_SIGNALS",
            "MULTIPLE_SUPPORTING_SIGNALS_STALE_L2",
            "ROUTING_WITH_NEGATIVE_L2_EVIDENCE",
            "CONTRADICTORY_EVIDENCE",
            "INSUFFICIENT_EVIDENCE",
        }
        actual = {item.value for item in TransitEvidenceAssessment}
        assert actual == expected

    def test_no_operational_success_terms(self):
        """Ensure no enum values imply operational success."""
        forbidden = {
            "VIABLE", "WORKING", "REACHABLE", "FORWARDING",
            "SUCCESSFUL", "PIVOTABLE", "CONFIRMED", "VALIDATED",
        }
        actual = {item.value for item in TransitEvidenceAssessment}
        assert actual.isdisjoint(forbidden)


class TestTransitEvidenceModel:
    """Test the TransitEvidence immutable model validation."""

    def test_valid_model_creation(self):
        """Test creating a valid TransitEvidence."""
        evidence = TransitEvidence(
            source_interface="eth0",
            gateway="10.10.20.254",
            destination_network="172.16.50.0/24",
            address_family=4,
            assessment=TransitEvidenceAssessment.ROUTING_ONLY,
        )
        assert evidence.gateway == "10.10.20.254"
        assert evidence.destination_network == "172.16.50.0/24"
        assert evidence.source_interface == "eth0"
        assert evidence.address_family == 4

    def test_invalid_gateway_raises(self):
        """Test that invalid gateway IP raises ValueError."""
        with pytest.raises(ValueError, match="invalid gateway IP"):
            TransitEvidence(
                source_interface="eth0",
                gateway="not-an-ip",
                destination_network="172.16.50.0/24",
                address_family=4,
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,
            )

    def test_invalid_destination_cidr_raises(self):
        """Test that invalid destination CIDR raises ValueError."""
        with pytest.raises(ValueError, match="invalid destination network CIDR"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="not-a-cidr",
                address_family=4,
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,
            )

    def test_empty_interface_raises(self):
        """Test that empty source_interface raises ValueError."""
        with pytest.raises(ValueError, match="source_interface must be non-empty"):
            TransitEvidence(
                source_interface="",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=4,
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,
            )

    def test_invalid_address_family_raises(self):
        """Test that invalid address_family raises ValueError."""
        with pytest.raises(ValueError, match="address_family must be 4 or 6"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=5,
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,
            )

    def test_family_mismatch_raises(self):
        """Test that gateway/destination family mismatch raises ValueError."""
        with pytest.raises(ValueError, match="must be same address family"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",  # IPv4
                destination_network="2001:db8::/32",  # IPv6
                address_family=4,
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,
            )

    def test_link_local_gateway_allowed_with_global_dest(self):
        """Test that IPv6 link-local gateway with global destination is allowed."""
        evidence = TransitEvidence(
            source_interface="eth0",
            gateway="fe80::1",
            destination_network="2001:db8::/32",
            address_family=6,
            assessment=TransitEvidenceAssessment.ROUTING_ONLY,
        )
        assert evidence.gateway == "fe80::1"

    def test_invalid_neighbor_state_raises(self):
        """Test that invalid neighbor_state raises ValueError."""
        with pytest.raises(ValueError, match="invalid neighbor_state"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=4,
                neighbor_state="INVALID_STATE",
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,
            )

    def test_assessment_consistency_enforced(self):
        """Test that assessment must match evidence."""
        with pytest.raises(ValueError, match="assessment.*inconsistent with evidence"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=4,
                neighbor_observed=True,
                neighbor_state="REACHABLE",
                tcp_connections_to_gateway=1,
                tcp_connection_states=("ESTABLISHED",),
                assessment=TransitEvidenceAssessment.ROUTING_ONLY,  # Wrong - should be MULTIPLE_SUPPORTING_SIGNALS
            )

    def test_serialization(self):
        """Test to_dict serialization."""
        evidence = TransitEvidence(
            source_interface="eth0",
            gateway="10.10.20.254",
            destination_network="172.16.50.0/24",
            address_family=4,
            route_metric=50,
            neighbor_observed=True,
            neighbor_state="REACHABLE",
            neighbor_mac="aa:bb:cc:dd:ee:ff",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            assessment=TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
        )
        data = evidence.to_dict()
        assert data["source_interface"] == "eth0"
        assert data["gateway"] == "10.10.20.254"
        assert data["destination_network"] == "172.16.50.0/24"
        assert data["address_family"] == 4
        assert data["route"]["metric"] == 50
        assert data["neighbor"]["observed"] is True
        assert data["neighbor"]["state"] == "REACHABLE"
        assert data["neighbor"]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert data["connections"]["tcp_count"] == 1
        assert data["connections"]["tcp_states"] == ["ESTABLISHED"]
        assert data["assessment"] == "MULTIPLE_SUPPORTING_SIGNALS"


class TestTransitEvidenceCollection:
    """Test the TransitEvidenceCollection model."""

    def test_empty_collection(self):
        """Test empty collection serialization."""
        collection = TransitEvidenceCollection(
            candidates=(),
            snapshot_timestamp="2024-01-01T00:00:00Z",
        )
        data = collection.to_dict()
        assert data["snapshot_timestamp"] == "2024-01-01T00:00:00Z"
        assert data["candidates"] == []

    def test_collection_with_candidates(self):
        """Test collection with multiple candidates."""
        e1 = TransitEvidence(
            source_interface="eth0",
            gateway="10.10.20.254",
            destination_network="172.16.50.0/24",
            address_family=4,
            assessment=TransitEvidenceAssessment.ROUTING_ONLY,
        )
        e2 = TransitEvidence(
            source_interface="eth0",
            gateway="10.10.20.254",
            destination_network="192.168.100.0/24",
            address_family=4,
            assessment=TransitEvidenceAssessment.ROUTING_ONLY,
        )
        collection = TransitEvidenceCollection(
            candidates=(e1, e2),
            snapshot_timestamp="2024-01-01T00:00:00Z",
        )
        data = collection.to_dict()
        assert len(data["candidates"]) == 2
        assert data["candidates"][0]["destination_network"] == "172.16.50.0/24"
        assert data["candidates"][1]["destination_network"] == "192.168.100.0/24"


class TestDeriveTransitAssessment:
    """Test the single authoritative assessment derivation function."""

    def test_routing_only(self):
        """Route only -> ROUTING_ONLY."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_ONLY

    def test_routing_plus_l2_evidence_reachable(self):
        """Route + REACHABLE neighbor -> ROUTING_PLUS_L2_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="REACHABLE",
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE

    def test_routing_plus_l2_evidence_stale(self):
        """Route + STALE neighbor -> ROUTING_PLUS_L2_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="STALE",
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE

    def test_routing_plus_l2_evidence_permanent(self):
        """Route + PERMANENT neighbor -> ROUTING_PLUS_L2_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="PERMANENT",
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE

    def test_routing_plus_l2_evidence_delay(self):
        """Route + DELAY neighbor -> ROUTING_PLUS_L2_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="DELAY",
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE

    def test_routing_with_negative_l2_evidence(self):
        """Route + FAILED neighbor -> ROUTING_WITH_NEGATIVE_L2_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="FAILED",
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE

    def test_routing_plus_active_tcp_evidence(self):
        """Route + active TCP -> ROUTING_PLUS_ACTIVE_TCP_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE

    def test_routing_plus_active_udp_evidence(self):
        """Route + active UDP -> ROUTING_PLUS_ACTIVE_UDP_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=1,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE

    def test_routing_plus_historical_tcp_evidence(self):
        """Route + historical TCP -> ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=("TIME_WAIT",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE

    def test_multiple_supporting_signals(self):
        """Route + REACHABLE neighbor + active TCP -> MULTIPLE_SUPPORTING_SIGNALS."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="REACHABLE",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS

    def test_multiple_supporting_signals_stale_l2(self):
        """Route + STALE neighbor + active TCP -> MULTIPLE_SUPPORTING_SIGNALS_STALE_L2."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="STALE",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2

    def test_contradictory_evidence(self):
        """Route + FAILED neighbor + active TCP -> CONTRADICTORY_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="FAILED",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE

    def test_listen_not_counted_as_active(self):
        """LISTEN state should not count as active TCP evidence."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=("LISTEN",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=True,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_ONLY

    def test_loopback_not_counted_as_active(self):
        """Loopback connections should not count as active evidence."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=True,
        )
        assert result == TransitEvidenceAssessment.ROUTING_ONLY

    def test_time_wait_is_historical(self):
        """TIME_WAIT should be historical, not active."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=("TIME_WAIT",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE

    def test_close_wait_is_historical(self):
        """CLOSE_WAIT should be historical, not active."""
        result = _derive_transit_assessment(
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=("CLOSE_WAIT",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE

    def test_precedence_contradictory_over_multiple(self):
        """CONTRADICTORY_EVIDENCE should take precedence over MULTIPLE_SUPPORTING_SIGNALS."""
        # This is implicitly tested by the order in _derive_transit_assessment
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="FAILED",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE

    def test_precedence_multiple_over_active_tcp(self):
        """MULTIPLE_SUPPORTING_SIGNALS should take precedence over ROUTING_PLUS_ACTIVE_TCP_EVIDENCE."""
        result = _derive_transit_assessment(
            neighbor_observed=True,
            neighbor_state="REACHABLE",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS


class TestAssessTransitEvidence:
    """Test the main correlation engine with full snapshots."""

    def test_empty_pivot_paths_returns_empty_collection(self):
        """No pivot paths -> empty collection."""
        snapshot = make_snapshot(pivot_paths=())
        result = assess_transit_evidence(snapshot)
        assert isinstance(result, TransitEvidenceCollection)
        assert len(result.candidates) == 0

    def test_routing_only(self):
        """Pivot path with no neighbor/connection evidence -> ROUTING_ONLY."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_ONLY
        assert result.candidates[0].neighbor_observed is False
        assert result.candidates[0].tcp_connections_to_gateway == 0

    def test_routing_plus_reachable_neighbor(self):
        """Pivot path with REACHABLE neighbor -> ROUTING_PLUS_L2_EVIDENCE."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(state="REACHABLE"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE
        assert result.candidates[0].neighbor_observed is True
        assert result.candidates[0].neighbor_state == "REACHABLE"

    def test_routing_plus_stale_neighbor(self):
        """Pivot path with STALE neighbor -> ROUTING_PLUS_L2_EVIDENCE."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(state="STALE"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE
        assert result.candidates[0].neighbor_state == "STALE"

    def test_routing_with_failed_neighbor(self):
        """Pivot path with FAILED neighbor -> ROUTING_WITH_NEGATIVE_L2_EVIDENCE."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(state="FAILED"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE
        assert result.candidates[0].neighbor_state == "FAILED"

    def test_routing_plus_active_tcp(self):
        """Pivot path with ESTABLISHED TCP to gateway -> ROUTING_PLUS_ACTIVE_TCP_EVIDENCE."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(make_connection(state="ESTABLISHED"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE
        assert result.candidates[0].tcp_connections_to_gateway == 1
        assert "ESTABLISHED" in result.candidates[0].tcp_connection_states

    def test_multiple_supporting_signals(self):
        """Route + REACHABLE neighbor + ESTABLISHED TCP -> MULTIPLE_SUPPORTING_SIGNALS."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(state="REACHABLE"),),
            connections=(make_connection(state="ESTABLISHED"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS
        assert result.candidates[0].neighbor_observed is True
        assert result.candidates[0].neighbor_state == "REACHABLE"
        assert result.candidates[0].tcp_connections_to_gateway == 1

    def test_multiple_supporting_signals_stale_l2(self):
        """Route + STALE neighbor + ESTABLISHED TCP -> MULTIPLE_SUPPORTING_SIGNALS_STALE_L2."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(state="STALE"),),
            connections=(make_connection(state="ESTABLISHED"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2

    def test_contradictory_evidence(self):
        """Route + FAILED neighbor + ESTABLISHED TCP -> CONTRADICTORY_EVIDENCE."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(state="FAILED"),),
            connections=(make_connection(state="ESTABLISHED"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE

    def test_listen_not_counted(self):
        """LISTEN on gateway should not count as active evidence."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(make_connection(state="LISTEN", local_address="10.10.20.254", remote_address="0.0.0.0"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_ONLY
        assert result.candidates[0].has_listen_on_gateway is True

    def test_loopback_not_counted(self):
        """Loopback connections to gateway should not count as active evidence."""
        # Create a connection from loopback to the gateway - this should be detected as loopback
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(make_connection(local_address="127.0.0.1", remote_address="10.10.20.254"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_ONLY
        assert result.candidates[0].has_loopback_to_gateway is True

    def test_time_wait_is_historical(self):
        """TIME_WAIT should be historical evidence."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(make_connection(state="TIME_WAIT"),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE

    def test_same_gateway_multiple_destinations(self):
        """Same gateway, multiple destinations -> separate candidates."""
        snapshot = make_snapshot(
            pivot_paths=(
                make_pivot_path(destination_network="172.16.50.0/24"),
                make_pivot_path(destination_network="192.168.200.0/24"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 2
        assert result.candidates[0].destination_network == "172.16.50.0/24"
        assert result.candidates[1].destination_network == "192.168.200.0/24"
        assert result.candidates[0].gateway == result.candidates[1].gateway == "10.10.20.254"

    def test_same_destination_multiple_gateways(self):
        """Same destination, multiple gateways -> separate candidates."""
        snapshot = make_snapshot(
            pivot_paths=(
                make_pivot_path(gateway="10.10.20.254"),
                make_pivot_path(gateway="10.10.20.255", destination_network="172.16.50.0/24"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 2
        assert result.candidates[0].gateway == "10.10.20.254"
        assert result.candidates[1].gateway == "10.10.20.255"

    def test_same_gateway_different_interfaces(self):
        """Same gateway on different interfaces -> separate candidates."""
        snapshot = make_snapshot(
            pivot_paths=(
                make_pivot_path(source_interface="eth0"),
                make_pivot_path(source_interface="eth1", gateway="10.10.20.254"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 2
        assert result.candidates[0].source_interface == "eth0"
        assert result.candidates[1].source_interface == "eth1"

    def test_neighbor_on_wrong_interface_not_correlated(self):
        """Neighbor on different interface should not correlate."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(source_interface="eth0"),),
            neighbors=(make_neighbor(interface="eth1"),),  # Neighbor on eth1, pivot on eth0
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].neighbor_observed is False

    def test_ipv6_gateway(self):
        """IPv6 gateway should work correctly."""
        snapshot = make_snapshot(
            pivot_paths=(
                PivotPath(
                    source_interface="eth0",
                    gateway="2001:db8::1",
                    destination_network="2001:db8:1::/64",
                    confidence=Confidence.MEDIUM,
                ),
            ),
            neighbors=(
                Neighbor(ip_address="2001:db8::1", interface="eth0", mac_address="aa:bb:cc:dd:ee:ff", state="REACHABLE"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].address_family == 6
        assert result.candidates[0].gateway == "2001:db8::1"
        assert result.candidates[0].neighbor_observed is True

    def test_ipv6_link_local_interface_scoped(self):
        """IPv6 link-local gateway on different interfaces -> separate candidates."""
        snapshot = make_snapshot(
            pivot_paths=(
                PivotPath(
                    source_interface="eth0",
                    gateway="fe80::1",
                    destination_network="2001:db8:1::/64",
                    confidence=Confidence.MEDIUM,
                ),
                PivotPath(
                    source_interface="eth1",
                    gateway="fe80::1",
                    destination_network="2001:db8:2::/64",
                    confidence=Confidence.MEDIUM,
                ),
            ),
            neighbors=(
                Neighbor(ip_address="fe80::1", interface="eth0", mac_address="aa:bb:cc:dd:ee:01", state="REACHABLE"),
                Neighbor(ip_address="fe80::1", interface="eth1", mac_address="aa:bb:cc:dd:ee:02", state="REACHABLE"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 2
        assert result.candidates[0].source_interface == "eth0"
        assert result.candidates[1].source_interface == "eth1"
        assert result.candidates[0].neighbor_observed is True
        assert result.candidates[1].neighbor_observed is True

    def test_deterministic_ordering(self):
        """Output must be deterministic regardless of input order."""
        # Create snapshot with multiple pivot paths in different orders
        paths1 = (
            make_pivot_path(destination_network="172.16.50.0/24"),
            make_pivot_path(destination_network="192.168.200.0/24"),
        )
        paths2 = (
            make_pivot_path(destination_network="192.168.200.0/24"),
            make_pivot_path(destination_network="172.16.50.0/24"),
        )
        snapshot1 = make_snapshot(pivot_paths=paths1)
        snapshot2 = make_snapshot(pivot_paths=paths2)

        result1 = assess_transit_evidence(snapshot1)
        result2 = assess_transit_evidence(snapshot2)

        # Both should produce identical ordered results
        assert len(result1.candidates) == len(result2.candidates) == 2
        for c1, c2 in zip(result1.candidates, result2.candidates):
            assert c1.gateway == c2.gateway
            assert c1.destination_network == c2.destination_network
            assert c1.source_interface == c2.source_interface
            assert c1.assessment == c2.assessment

    def test_input_order_independence_routes(self):
        """Route input order should not affect output."""
        routes1 = (
            Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
            Route("172.16.50.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
            Route("192.168.200.0/24", "10.10.20.254", "eth0", 60, RouteType.STATIC),
        )
        routes2 = (
            Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
            Route("192.168.200.0/24", "10.10.20.254", "eth0", 60, RouteType.STATIC),
            Route("172.16.50.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
        )
        snapshot1 = make_snapshot(
            routes=routes1,
            pivot_paths=(
                make_pivot_path(destination_network="172.16.50.0/24"),
                make_pivot_path(destination_network="192.168.200.0/24"),
            ),
        )
        snapshot2 = make_snapshot(
            routes=routes2,
            pivot_paths=(
                make_pivot_path(destination_network="172.16.50.0/24"),
                make_pivot_path(destination_network="192.168.200.0/24"),
            ),
        )

        result1 = assess_transit_evidence(snapshot1)
        result2 = assess_transit_evidence(snapshot2)

        assert len(result1.candidates) == len(result2.candidates) == 2
        for c1, c2 in zip(result1.candidates, result2.candidates):
            assert c1.destination_network == c2.destination_network
            assert c1.assessment == c2.assessment

    def test_input_order_independence_neighbors(self):
        """Neighbor input order should not affect output."""
        neighbors1 = (
            make_neighbor(ip="10.10.20.254", state="REACHABLE"),
            make_neighbor(ip="10.10.20.255", state="STALE"),
        )
        neighbors2 = (
            make_neighbor(ip="10.10.20.255", state="STALE"),
            make_neighbor(ip="10.10.20.254", state="REACHABLE"),
        )
        snapshot1 = make_snapshot(
            pivot_paths=(
                make_pivot_path(gateway="10.10.20.254"),
                make_pivot_path(gateway="10.10.20.255"),
            ),
            neighbors=neighbors1,
        )
        snapshot2 = make_snapshot(
            pivot_paths=(
                make_pivot_path(gateway="10.10.20.254"),
                make_pivot_path(gateway="10.10.20.255"),
            ),
            neighbors=neighbors2,
        )

        result1 = assess_transit_evidence(snapshot1)
        result2 = assess_transit_evidence(snapshot2)

        assert len(result1.candidates) == len(result2.candidates) == 2
        for c1, c2 in zip(result1.candidates, result2.candidates):
            assert c1.gateway == c2.gateway
            assert c1.neighbor_state == c2.neighbor_state
            assert c1.assessment == c2.assessment

    def test_input_order_independence_connections(self):
        """Connection input order should not affect output."""
        conns1 = (
            make_connection(remote_address="10.10.20.254", state="ESTABLISHED"),
            make_connection(remote_address="10.10.20.255", state="ESTABLISHED"),
        )
        conns2 = (
            make_connection(remote_address="10.10.20.255", state="ESTABLISHED"),
            make_connection(remote_address="10.10.20.254", state="ESTABLISHED"),
        )
        snapshot1 = make_snapshot(
            pivot_paths=(
                make_pivot_path(gateway="10.10.20.254"),
                make_pivot_path(gateway="10.10.20.255"),
            ),
            connections=conns1,
        )
        snapshot2 = make_snapshot(
            pivot_paths=(
                make_pivot_path(gateway="10.10.20.254"),
                make_pivot_path(gateway="10.10.20.255"),
            ),
            connections=conns2,
        )

        result1 = assess_transit_evidence(snapshot1)
        result2 = assess_transit_evidence(snapshot2)

        assert len(result1.candidates) == len(result2.candidates) == 2
        for c1, c2 in zip(result1.candidates, result2.candidates):
            assert c1.gateway == c2.gateway
            assert c1.tcp_connections_to_gateway == c2.tcp_connections_to_gateway
            assert c1.assessment == c2.assessment

    def test_duplicate_neighbor_deduplication(self):
        """Duplicate neighbor entries should be deduplicated."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(
                make_neighbor(state="REACHABLE"),
                make_neighbor(state="STALE"),  # Duplicate IP+interface, different state
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        # Should keep first after sorting (REACHABLE comes before STALE alphabetically)
        assert result.candidates[0].neighbor_state == "REACHABLE"

    def test_duplicate_connection_deduplication(self):
        """Duplicate connection entries should be deduplicated."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(
                make_connection(state="ESTABLISHED"),
                make_connection(state="ESTABLISHED"),  # Exact duplicate
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].tcp_connections_to_gateway == 1
        assert result.candidates[0].tcp_connection_states == ("ESTABLISHED",)

    def test_udp_evidence(self):
        """UDP connections to gateway should be counted."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(
                make_connection(protocol=ConnectionProtocol.UDP, state="ESTAB"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].udp_flows_to_gateway == 1
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE

    def test_udp_unconn_not_counted(self):
        """UDP UNCONN should not count as active flow."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            connections=(
                make_connection(protocol=ConnectionProtocol.UDP, state="UNCONN"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].udp_flows_to_gateway == 0
        assert result.candidates[0].assessment == TransitEvidenceAssessment.ROUTING_ONLY

    def test_ipv4_ipv6_isolation(self):
        """IPv4 and IPv6 evidence must not cross-match."""
        snapshot = make_snapshot(
            pivot_paths=(
                make_pivot_path(gateway="10.10.20.254", destination_network="172.16.50.0/24"),
                PivotPath(
                    source_interface="eth0",
                    gateway="2001:db8::1",
                    destination_network="2001:db8:1::/64",
                    confidence=Confidence.MEDIUM,
                ),
            ),
            neighbors=(
                make_neighbor(ip="10.10.20.254", state="REACHABLE"),
                Neighbor(ip_address="2001:db8::1", interface="eth0", mac_address="aa:bb:cc:dd:ee:ff", state="REACHABLE"),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 2
        # Both should have neighbor evidence
        for c in result.candidates:
            assert c.neighbor_observed is True
            assert c.neighbor_state == "REACHABLE"

    def test_route_metric_captured(self):
        """Route metric should be captured in evidence."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            routes=(
                Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
                Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
                Route("172.16.50.0/24", "10.10.20.254", "eth0", 75, RouteType.STATIC),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].route_metric == 75

    def test_most_specific_route_selected(self):
        """Most specific route should be selected when multiple match."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(destination_network="172.16.50.0/24"),),
            routes=(
                Route("172.16.0.0/16", "10.10.20.254", "eth0", 50, RouteType.STATIC),
                Route("172.16.50.0/24", "10.10.20.254", "eth0", 60, RouteType.STATIC),
            ),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) == 1
        assert result.candidates[0].route_metric == 60  # More specific route


class TestRegression:
    """Ensure existing behavior is unchanged."""

    def test_topology_analysis_unchanged(self):
        """Existing topology analysis must remain unchanged."""
        from pivotcheck.analysis.topology import analyze, infer_pivot_paths
        snapshot = make_snapshot()
        analyze(snapshot)
        paths = infer_pivot_paths(snapshot.interfaces, snapshot.routes)
        assert len(paths) == 1
        assert paths[0].gateway == "10.10.20.254"
        assert paths[0].destination_network == "172.16.50.0/24"

    def test_map_view_unchanged(self):
        """Existing map view must remain unchanged."""
        from pivotcheck.analysis.map_view import build_map_view
        from pivotcheck.analysis.topology import analyze
        snapshot = make_snapshot()
        analyzed = analyze(snapshot)
        view = build_map_view(analyzed)
        assert len(view.pivot_paths) == 1
        assert view.pivot_paths[0].gateway == "10.10.20.254"

    def test_check_cli_unchanged(self):
        """Existing check CLI behavior must remain unchanged."""
        from pivotcheck.checks.context import build_validation_context
        snapshot = make_snapshot()
        ctx = build_validation_context("10.10.20.15", snapshot)
        assert ctx is not None
        assert ctx.route_context is not None


class TestDerivationTruthMatrix:
    """STABILIZATION-1: the route_present dimension of the truth matrix.

    Invariant: every assessment produced by _derive_transit_assessment is
    accepted by TransitEvidence model validation, and every assessment the
    model rejects cannot be derived from the evidence fields that produced
    the request.
    """

    def test_no_route_derives_insufficient_evidence(self):
        """route_present=False must derive INSUFFICIENT_EVIDENCE."""
        result = _derive_transit_assessment(
            route_present=False,
            neighbor_observed=False,
            neighbor_state=None,
            tcp_connections_to_gateway=0,
            tcp_connection_states=(),
            udp_flows_to_gateway=0,
            has_listen_on_gateway=False,
            has_loopback_to_gateway=False,
        )
        assert result is TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE

    def test_no_route_with_other_evidence_still_insufficient(self):
        """No route dominates: other evidence cannot rescue the assessment."""
        result = _derive_transit_assessment(
            route_present=False,
            neighbor_observed=True,
            neighbor_state="REACHABLE",
            tcp_connections_to_gateway=1,
            tcp_connection_states=("ESTABLISHED",),
            udp_flows_to_gateway=1,
            has_listen_on_gateway=True,
            has_loopback_to_gateway=False,
        )
        assert result is TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE

    def test_model_accepts_insufficient_evidence_when_no_route(self):
        """The model must accept INSUFFICIENT_EVIDENCE exactly when route_present=False."""
        evidence = TransitEvidence(
            source_interface="eth0",
            gateway="10.10.20.254",
            destination_network="172.16.50.0/24",
            address_family=4,
            route_present=False,
            assessment=TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE,
        )
        assert evidence.assessment is TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE

    def test_model_rejects_insufficient_evidence_with_route(self):
        """INSUFFICIENT_EVIDENCE with route_present=True must be rejected."""
        with pytest.raises(ValueError, match="inconsistent with evidence"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=4,
                route_present=True,
                assessment=TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE,
            )

    def test_model_rejects_mismatched_assessment(self):
        """Assessment contradicting the evidence fields must be rejected."""
        with pytest.raises(ValueError, match="inconsistent with evidence"):
            TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=4,
                neighbor_observed=True,
                neighbor_state="REACHABLE",
                assessment=TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
            )

    def test_bare_constructor_defaults_are_consistent(self):
        """Default field values must produce a valid model instance.

        Regression guard: the default assessment previously was
        INSUFFICIENT_EVIDENCE, so constructing TransitEvidence without an
        explicit assessment always raised ValueError.
        """
        evidence = TransitEvidence(
            source_interface="eth0",
            gateway="10.10.20.254",
            destination_network="172.16.50.0/24",
            address_family=4,
        )
        assert evidence.assessment is TransitEvidenceAssessment.ROUTING_ONLY

    def test_every_derived_assessment_accepted_by_model(self):
        """Every derivation output must round-trip through model validation.

        Walks the truth matrix: each evidence-field combination is derived,
        then a TransitEvidence is constructed with the derived assessment.
        Model rejection here would mean derivation and validation disagree.
        """
        compositions = [
            # (neighbor_observed, neighbor_state, tcp_count, tcp_states, udp, listen, loopback)
            (False, None, 0, (), 0, False, False),                     # ROUTING_ONLY
            (True, "REACHABLE", 0, (), 0, False, False),               # ROUTING_PLUS_L2
            (True, "STALE", 0, (), 0, False, False),                   # ROUTING_PLUS_L2
            (True, "PERMANENT", 0, (), 0, False, False),               # ROUTING_PLUS_L2
            (False, None, 1, ("ESTABLISHED",), 0, False, False),       # ACTIVE_TCP
            (False, None, 0, (), 1, False, False),                     # ACTIVE_UDP
            (False, None, 0, ("TIME_WAIT",), 0, False, False),         # HISTORICAL_TCP
            (False, None, 0, ("CLOSE_WAIT",), 0, False, False),        # HISTORICAL_TCP
            (True, "REACHABLE", 1, ("ESTABLISHED",), 0, False, False),  # MULTIPLE
            (True, "STALE", 1, ("ESTABLISHED",), 0, False, False),      # MULTIPLE_STALE
            (True, "FAILED", 0, (), 0, False, False),                   # NEGATIVE_L2
            (True, "FAILED", 1, ("ESTABLISHED",), 0, False, False),     # CONTRADICTORY
        ]
        for (observed, state, tcp_n, tcp_s, udp, listen, loopback) in compositions:
            derived = _derive_transit_assessment(
                route_present=True,
                neighbor_observed=observed,
                neighbor_state=state,
                tcp_connections_to_gateway=tcp_n,
                tcp_connection_states=tcp_s,
                udp_flows_to_gateway=udp,
                has_listen_on_gateway=listen,
                has_loopback_to_gateway=loopback,
            )
            # Must not raise: model accepts every derivable assessment
            evidence = TransitEvidence(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                address_family=4,
                route_present=True,
                neighbor_observed=observed,
                neighbor_state=state,
                tcp_connections_to_gateway=tcp_n,
                tcp_connection_states=tcp_s,
                udp_flows_to_gateway=udp,
                has_listen_on_gateway=listen,
                has_loopback_to_gateway=loopback,
                assessment=derived,
            )
            assert evidence.assessment is derived

    def test_production_correlation_never_produces_invalid_state(self):
        """Production derivation output must satisfy model validation."""
        snapshot = make_snapshot(
            pivot_paths=(make_pivot_path(),),
            neighbors=(make_neighbor(),),
            connections=(make_connection(),),
        )
        result = assess_transit_evidence(snapshot)
        assert len(result.candidates) >= 1
        for candidate in result.candidates:
            expected = _derive_transit_assessment(
                route_present=candidate.route_present,
                neighbor_observed=candidate.neighbor_observed,
                neighbor_state=candidate.neighbor_state,
                tcp_connections_to_gateway=candidate.tcp_connections_to_gateway,
                tcp_connection_states=candidate.tcp_connection_states,
                udp_flows_to_gateway=candidate.udp_flows_to_gateway,
                has_listen_on_gateway=candidate.has_listen_on_gateway,
                has_loopback_to_gateway=candidate.has_loopback_to_gateway,
            )
            assert candidate.assessment is expected