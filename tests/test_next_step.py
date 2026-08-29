"""Unit tests for next-step selection logic."""

import itertools
import json
from datetime import datetime, timezone

from pivotcheck.analysis.comparison import DiffFinding, DiffReport, NetworkRelationship
from pivotcheck.analysis.next_step import (
    _canonical_network_key,
    _transit_evidence_key,
    select_next_investigation,
)
from pivotcheck.analysis.recommendation import Recommendation
from pivotcheck.models.check import (
    TransitEvidence,
    TransitEvidenceAssessment,
    TransitEvidenceCollection,
)
from pivotcheck.models.network import (
    Confidence,
    Interface,
    InterfaceState,
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
                ipv4_addresses=(),
            ),
            Interface(
                name="eth1",
                state=InterfaceState.UP,
                ipv4_addresses=(),
            ),
        ),
        "routes": (
            Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
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


def make_evidence(
    assessment: TransitEvidenceAssessment,
    destination_network: str = "172.16.50.0/24",
    gateway: str = "10.10.20.254",
    source_interface: str = "eth0",
    **kwargs
) -> TransitEvidence:
    """Create a TransitEvidence with the given assessment and optional overrides.
    
    Note: The TransitEvidence model validates that the assessment matches the evidence fields.
    This helper creates evidence that is consistent with the given assessment.
    """
    # Base defaults that are valid for ROUTING_ONLY
    defaults = {
        "source_interface": source_interface,
        "gateway": gateway,
        "destination_network": destination_network,
        "address_family": 4,
        "route_present": True,
        "route_metric": 100,
        "route_type": "static",
        "neighbor_observed": False,
        "neighbor_state": None,
        "neighbor_mac": None,
        "tcp_connections_to_gateway": 0,
        "tcp_connection_states": (),
        "udp_flows_to_gateway": 0,
        "has_listen_on_gateway": False,
        "has_loopback_to_gateway": False,
        "assessment": TransitEvidenceAssessment.ROUTING_ONLY,
    }
    
    # Override with assessment-specific evidence
    if assessment == TransitEvidenceAssessment.ROUTING_ONLY:
        pass  # Use defaults
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "REACHABLE",
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE:
        defaults.update({
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE:
        defaults.update({
            "udp_flows_to_gateway": 1,
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE:
        defaults.update({
            "tcp_connections_to_gateway": 0,
            "tcp_connection_states": ("TIME_WAIT",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "REACHABLE",
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "STALE",
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "FAILED",
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "FAILED",
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE:
        # This assessment is for when there's no route evidence at all
        defaults.update({
            "route_present": False,
            "assessment": assessment,
        })
    else:
        # For any other assessment, use ROUTING_ONLY as base
        pass
    
    defaults.update(kwargs)
    return TransitEvidence(**defaults)


def make_recommendation(
    priority: str,
    network: str,
    reason: str = "test reason",
) -> Recommendation:
    return Recommendation(
        priority=priority,
        network=network,
        reason=reason,
        suggested_action="Perform explicit validation of an operator-chosen target.",
        limitation="Route and topology evidence do not prove active reachability.",
        evidence=(),
    )


def make_snapshot_with_pivot_paths(pivot_paths) -> DiscoverySnapshot:
    """Create a snapshot with the given pivot paths."""
    return make_snapshot(pivot_paths=tuple(pivot_paths))


class TestCanonicalNetworkKey:
    """Test the canonical network key function."""

    def test_ipv4_networks(self):
        """IPv4 networks should sort by version, network address, prefix."""
        key1 = _canonical_network_key("10.0.0.0/8")
        key2 = _canonical_network_key("10.10.0.0/16")
        key3 = _canonical_network_key("192.168.1.0/24")
        assert key1 < key2 < key3

    def test_ipv6_networks(self):
        """IPv6 networks should sort after IPv4."""
        key4 = _canonical_network_key("2001:db8::/32")
        key1 = _canonical_network_key("10.0.0.0/8")
        assert key1 < key4

    def test_same_network_different_prefix(self):
        """Same network with different prefix should sort by prefix."""
        key1 = _canonical_network_key("10.10.0.0/16")
        key2 = _canonical_network_key("10.10.0.0/24")
        assert key1 < key2


class TestTransitEvidenceKey:
    """Test the transit evidence sort key function."""

    def test_high_priority_beats_medium(self):
        """HIGH priority should beat MEDIUM."""
        high_evidence = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
            destination_network="10.50.0.0/16",
        )
        medium_evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="10.50.0.0/16",
        )
        high_key = _transit_evidence_key(high_evidence)
        medium_key = _transit_evidence_key(medium_evidence)
        assert high_key < medium_key  # Negative priority weight means higher priority comes first

    def test_medium_beats_low(self):
        """MEDIUM priority should beat LOW."""
        medium_evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="10.50.0.0/16",
        )
        low_evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="10.50.0.0/16",
        )
        medium_key = _transit_evidence_key(medium_evidence)
        low_key = _transit_evidence_key(low_evidence)
        assert medium_key < low_key

    def test_stronger_evidence_beats_weaker_at_same_priority(self):
        """Stronger evidence should beat weaker evidence at same priority."""
        # Both are HIGH priority, but MULTIPLE_SUPPORTING_SIGNALS > MULTIPLE_SUPPORTING_SIGNALS_STALE_L2
        strong = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
            destination_network="10.50.0.0/16",
        )
        weaker = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2,
            destination_network="10.50.0.0/16",
        )
        strong_key = _transit_evidence_key(strong)
        weaker_key = _transit_evidence_key(weaker)
        assert strong_key < weaker_key

    def test_deterministic_tie_breaker(self):
        """Same priority and evidence strength should use network as tie-breaker."""
        ev1 = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="10.10.0.0/16",
        )
        ev2 = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="10.20.0.0/16",
        )
        key1 = _transit_evidence_key(ev1)
        key2 = _transit_evidence_key(ev2)
        assert key1 < key2  # 10.10.0.0/16 < 10.20.0.0/16


class TestSelectNextInvestigation:
    """Test the main selection function."""

    def test_no_candidates_returns_no_candidate(self):
        """Empty candidate list should return NO INVESTIGATION CANDIDATES."""
        snapshot = make_snapshot(pivot_paths=())
        transit_evidence = TransitEvidenceCollection(
            candidates=(),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is None
        assert report.message == "NO INVESTIGATION CANDIDATES"

    def test_single_candidate_selected(self):
        """Single candidate should be selected."""
        pivot_path = make_pivot_path(destination_network="172.16.50.0/24")
        evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
        )
        snapshot = make_snapshot_with_pivot_paths([pivot_path])
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence,),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "172.16.50.0/24"
        assert report.candidate.priority == "MEDIUM"

    def test_high_beats_medium(self):
        """HIGH priority should beat MEDIUM."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        evidence_high = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence_medium = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence_high, evidence_medium),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "10.50.0.0/16"
        assert report.candidate.priority == "HIGH"

    def test_medium_beats_low(self):
        """MEDIUM priority should beat LOW."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        evidence_medium = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence_low = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence_medium, evidence_low),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "10.50.0.0/16"
        assert report.candidate.priority == "MEDIUM"

    def test_stronger_evidence_beats_weaker_at_same_priority(self):
        """Stronger evidence should beat weaker evidence at same priority."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        # Both HIGH priority, but MULTIPLE_SUPPORTING_SIGNALS > MULTIPLE_SUPPORTING_SIGNALS_STALE_L2
        strong = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        weaker = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(strong, weaker),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "10.50.0.0/16"

    def test_none_priority_candidates_skipped(self):
        """NONE priority candidates should be skipped."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        evidence_none = make_evidence(
            TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence_medium = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence_none, evidence_medium),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "172.16.50.0/24"

    def test_all_none_priority_returns_no_candidate(self):
        """All NONE priority candidates should return no candidate."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        evidence1 = make_evidence(
            TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence2 = make_evidence(
            TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence1, evidence2),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is None
        assert report.message == "NO INVESTIGATION CANDIDATES"

    def test_deterministic_ordering(self):
        """Input order should not affect output."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
            make_pivot_path(destination_network="192.168.100.0/24", gateway="10.10.30.1"),
        )
        evidence1 = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence2 = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        evidence3 = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="192.168.100.0/24",
            gateway="10.10.30.1",
        )

        # Test different input orders
        orders = [
            (evidence1, evidence2, evidence3),
            (evidence3, evidence1, evidence2),
            (evidence2, evidence3, evidence1),
        ]

        results = []
        for order in orders:
            snapshot = make_snapshot_with_pivot_paths(pivot_paths)
            transit_evidence = TransitEvidenceCollection(
                candidates=order,
                snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
            )
            report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
            results.append(report.candidate.network if report.candidate else None)

        # All should produce the same result (first network in canonical order)
        assert all(r == results[0] for r in results)

    def test_baseline_context_included(self):
        """Baseline context should be included when baseline provided."""

        pivot_path = make_pivot_path(destination_network="172.16.50.0/24")
        evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
        )
        snapshot = make_snapshot_with_pivot_paths([pivot_path])
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence,),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Create a mock comparison report
        finding = DiffFinding(
            network="172.16.50.0/24",
            classification="NEW_REACHABILITY",
            relationship=NetworkRelationship.DISJOINT,
            related_network=None,
            reachability_novelty=True,
            topology_novelty=True,
        )
        report = DiffReport(new_networks=(finding,))

        report_result = select_next_investigation(
            snapshot,
            transit_evidence=transit_evidence,
            comparison_report=report,
            baseline_name="workstation",
        )

        assert report_result.candidate is not None
        assert report_result.candidate.comparison_context is not None
        assert report_result.candidate.comparison_context.baseline == "workstation"
        assert report_result.candidate.comparison_context.relationship == "NEW_COVERAGE"

    def test_no_baseline_no_comparison_context(self):
        """Without baseline, comparison context should be None."""
        pivot_path = make_pivot_path(destination_network="172.16.50.0/24")
        evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
        )
        snapshot = make_snapshot_with_pivot_paths([pivot_path])
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence,),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.comparison_context is None

    def test_suggested_action_includes_baseline(self):
        """Suggested action should include baseline when provided."""
        pivot_path = make_pivot_path(destination_network="172.16.50.0/24")
        evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
        )
        snapshot = make_snapshot_with_pivot_paths([pivot_path])
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence,),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        report = select_next_investigation(
            snapshot,
            transit_evidence=transit_evidence,
            baseline_name="workstation",
        )

        assert report.candidate is not None
        assert "--baseline workstation" in report.candidate.suggested_action

    def test_suggested_action_without_baseline(self):
        """Suggested action should not include baseline when not provided."""
        pivot_path = make_pivot_path(destination_network="172.16.50.0/24")
        evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
        )
        snapshot = make_snapshot_with_pivot_paths([pivot_path])
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence,),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)

        assert report.candidate is not None
        assert "--baseline" not in report.candidate.suggested_action
        assert "pivotcheck check <target> --port <port>" in report.candidate.suggested_action

    def test_contradictory_evidence_skipped(self):
        """CONTRADICTORY_EVIDENCE should be skipped (NONE priority)."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        evidence_contradictory = make_evidence(
            TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence_medium = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence_contradictory, evidence_medium),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "172.16.50.0/24"

    def test_insufficient_evidence_skipped(self):
        """INSUFFICIENT_EVIDENCE should be skipped (NONE priority)."""
        pivot_paths = (
            make_pivot_path(destination_network="10.50.0.0/16", gateway="10.10.10.1"),
            make_pivot_path(destination_network="172.16.50.0/24", gateway="10.10.20.254"),
        )
        evidence_insufficient = make_evidence(
            TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        evidence_medium = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        snapshot = make_snapshot_with_pivot_paths(pivot_paths)
        transit_evidence = TransitEvidenceCollection(
            candidates=(evidence_insufficient, evidence_medium),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        report = select_next_investigation(snapshot, transit_evidence=transit_evidence)
        assert report.candidate is not None
        assert report.candidate.network == "172.16.50.0/24"


class TestPermutationStability:
    """Selection must be stable under input permutation (Phase 4 hardening).

    The result must never depend on set iteration, dict insertion accidents,
    or discovery ordering — only on the explicit deterministic sort key
    (priority, evidence strength, canonical network order).
    """

    def _three_candidates(self):
        """Three candidates with distinct priorities and networks."""
        high = make_evidence(
            TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS,
            destination_network="10.50.0.0/16",
            gateway="10.10.10.1",
        )
        medium = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            destination_network="172.16.50.0/24",
            gateway="10.10.20.254",
        )
        low = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="192.168.70.0/24",
            gateway="10.10.30.1",
        )
        return [high, medium, low]

    def _run(self, candidates):
        snapshot = make_snapshot_with_pivot_paths(
            [
                make_pivot_path(
                    destination_network=c.destination_network, gateway=c.gateway
                )
                for c in candidates
            ]
        )
        transit_evidence = TransitEvidenceCollection(
            candidates=tuple(candidates),
            snapshot_timestamp=datetime.now(timezone.utc).isoformat(),
        )
        return select_next_investigation(snapshot, transit_evidence=transit_evidence)

    def test_high_beats_all_under_every_permutation(self):
        """HIGH candidate must win for all 6 input permutations."""
        candidates = self._three_candidates()
        for perm in itertools.permutations(candidates):
            report = self._run(list(perm))
            assert report.candidate is not None
            assert report.candidate.network == "10.50.0.0/16"
            assert report.candidate.priority == "HIGH"

    def test_equal_priority_tie_breaks_canonically_under_permutation(self):
        """Equal-priority candidates must tie-break by canonical network order."""
        ev1 = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="10.20.0.0/16",
            gateway="10.10.10.1",
        )
        ev2 = make_evidence(
            TransitEvidenceAssessment.ROUTING_ONLY,
            destination_network="10.10.0.0/16",
            gateway="10.10.20.254",
        )
        for perm in itertools.permutations([ev1, ev2]):
            report = self._run(list(perm))
            assert report.candidate is not None
            assert report.candidate.network == "10.10.0.0/16"

    def test_real_candidate_serializes_without_crash(self):
        """A real selected candidate must produce valid JSON (Phase 6)."""
        candidates = self._three_candidates()
        report = self._run(candidates)
        assert report.candidate is not None
        data = report.to_dict()
        # Must be JSON-serializable without TypeError/AttributeError
        text = json.dumps(data)
        assert json.loads(text)["candidate"]["priority"] == "HIGH"
        assert json.loads(text)["candidate"]["transit_assessment"] == (
            "MULTIPLE_SUPPORTING_SIGNALS"
        )

    def test_key_is_total_order_over_distinct_identities(self):
        """The sort key must be a total order over distinct candidate identities."""
        keys = [_transit_evidence_key(c) for c in self._three_candidates()]
        assert len(set(keys)) == 3
        assert keys[0] < keys[1] < keys[2]