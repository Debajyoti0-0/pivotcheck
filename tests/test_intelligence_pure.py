"""Pure-logic tests for focus resolution, evidence, and determinism."""

import pytest

from pivotcheck.analysis.comparison import compare
from pivotcheck.analysis.explanation import explain_network
from pivotcheck.analysis.query import QueryOptions, resolve_focus_network
from pivotcheck.analysis.recommendation import recommend
from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
    PivotPath,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def perspective(*entries):
    return Baseline(created_at="now", networks=entries)


class TestFocusResolution:
    def test_exact_cidr_is_canonicalized(self):
        assert (
            resolve_focus_network("10.50.0.0/16", ["10.50.0.0/16"])
            == "10.50.0.0/16"
        )

    def test_ip_inside_single_network_resolves(self):
        assert resolve_focus_network("10.50.5.1", ["10.50.0.0/16"]) == "10.50.0.0/16"

    def test_ambiguous_ip_raises(self):
        with pytest.raises(ValueError, match="multiple networks"):
            resolve_focus_network("10.0.0.1", ["10.0.0.0/8", "10.0.0.0/16"])

    def test_unmatched_input_raises(self):
        with pytest.raises(ValueError, match="does not match"):
            resolve_focus_network("192.168.5.1", ["10.0.0.0/8"])

    def test_family_separation_in_options(self):
        options = QueryOptions(family="ipv6")
        snapshot = DiscoverySnapshot(
            "h",
            "o",
            networks=(
                DiscoveredNetwork("10.0.0.0/8", NetworkOrigin.CONNECTED, Confidence.HIGH),
                DiscoveredNetwork("2001:db8::/32", NetworkOrigin.ROUTED, Confidence.MEDIUM),
            ),
        )
        from pivotcheck.analysis.query import filter_snapshot

        filtered = filter_snapshot(snapshot, options)
        assert [n.cidr for n in filtered.networks] == ["2001:db8::/32"]


class TestExplanationEvidence:
    def test_route_evidence_is_attached_and_sorted(self):
        snapshot = DiscoverySnapshot(
            "h",
            "o",
            routes=(
                Route("10.50.0.0/16", "10.10.20.1", "tun0", route_type=RouteType.STATIC),
                Route("default", None, "eth0"),
            ),
            networks=(
                DiscoveredNetwork(
                    "10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.10.20.1"
                ),
            ),
        )
        report = compare(perspective(), perspective())
        explanation = explain_network("10.50.0.0/16", snapshot, report)
        assert explanation.route_evidence == ("10.50.0.0/16 via 10.10.20.1 dev tun0",)
        assert explanation.reachability == "NOT ACTIVELY VALIDATED"

    def test_json_dict_has_no_reachability_claim(self):
        snapshot = DiscoverySnapshot("h", "o")
        explanation = explain_network("10.0.0.0/8", snapshot, compare(perspective(), perspective()))
        data = explanation.to_dict()
        assert data["reachability"] == "NOT ACTIVELY VALIDATED"


class TestRecommendationRules:
    def test_no_recommendation_without_evidence(self):
        # Finding exists but snapshot has no matching network entry.
        report = compare(perspective(), perspective(BaselineNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH)))
        empty = DiscoverySnapshot("h", "o")
        assert recommend(empty, report) == ()

    def test_priority_ordering_high_before_medium_before_low(self):
        base = perspective(BaselineNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH))
        current_entries = (
            BaselineNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
            BaselineNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
            BaselineNetwork("192.168.0.0/24", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.0.0.1"),
        )
        report = compare(base, perspective(*current_entries))
        snapshot = DiscoverySnapshot(
            "h",
            "o",
            pivot_paths=(PivotPath("tun0", "10.0.0.1", "198.51.100.0/24", Confidence.MEDIUM),),
            networks=(
                DiscoveredNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
                DiscoveredNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
                DiscoveredNetwork("192.168.0.0/24", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.0.0.1"),
            ),
        )
        results = recommend(snapshot, report)
        priorities = [item.priority for item in results]
        assert priorities.index("HIGH") < priorities.index("MEDIUM") < priorities.index("LOW")
        # Every recommendation carries an explicit limitation.
        assert all(item.limitation for item in results)
        assert all(item.suggested_action for item in results)

    def test_evidence_lines_are_present(self):
        report = compare(perspective(), perspective(BaselineNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH)))
        snapshot = DiscoverySnapshot(
            "h", "o",
            networks=(DiscoveredNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),),
        )
        results = recommend(snapshot, report)
        assert any("interface: eth0" in line for line in results[0].evidence)