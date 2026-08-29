"""Pure query, explanation, summary, and recommendation behavior."""

from pivotcheck.analysis.comparison import compare
from pivotcheck.analysis.explanation import explain_network
from pivotcheck.analysis.query import QueryOptions, filter_report, filter_snapshot
from pivotcheck.analysis.recommendation import recommend
from pivotcheck.analysis.summary import summarize_comparison, summarize_snapshot
from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import Confidence, DiscoveredNetwork, NetworkOrigin
from pivotcheck.models.result import DiscoverySnapshot


def perspective(*entries):
    return Baseline(created_at="now", networks=entries)


def test_filters_family_interface_confidence_and_keeps_unknown_metadata():
    snapshot = DiscoverySnapshot("host", "OS", networks=(
        DiscoveredNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
        DiscoveredNetwork("2001:db8::/32", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.0.0.1"),
    ))
    filtered = filter_snapshot(snapshot, QueryOptions(interface="tun0", family="ipv6", minimum_confidence="medium"))
    assert [network.cidr for network in filtered.networks] == ["2001:db8::/32"]


def test_focus_includes_all_overlapping_networks_and_rejects_bad_input():
    snapshot = DiscoverySnapshot("host", "OS", networks=(
        DiscoveredNetwork("10.0.0.0/16", NetworkOrigin.CONNECTED, Confidence.HIGH),
        DiscoveredNetwork("10.0.10.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
    ))
    assert len(filter_snapshot(snapshot, QueryOptions(focus="10.0.10.5")).networks) == 2


def test_changes_only_does_not_change_comparison_semantics():
    base = perspective(BaselineNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH))
    current = perspective(BaselineNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH), BaselineNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH))
    report = compare(base, current)
    filtered = filter_report(report, DiscoverySnapshot("host", "OS"), QueryOptions(changes_only=True))
    assert len(filtered.new_networks) == 1
    assert filtered.unchanged_networks == ()


def test_summary_explanation_and_recommendation_are_evidence_based():
    base = perspective(BaselineNetwork("10.0.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH))
    current_base = perspective(BaselineNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"))
    report = compare(base, current_base)
    snapshot = DiscoverySnapshot("host", "OS", networks=(DiscoveredNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),))
    assert summarize_snapshot(snapshot).to_dict()["connected_coverage"] == 1
    assert summarize_comparison(report).to_dict()["new_coverage"] == 1
    explanation = explain_network("172.16.0.0/24", snapshot, report, base)
    assert explanation.classification == "NEW_REACHABILITY"
    assert explanation.reachability == "NOT ACTIVELY VALIDATED"
    recommendations = recommend(snapshot, report)
    assert recommendations[0].priority == "HIGH"


def test_recommendations_are_deterministic_when_input_order_changes():
    entries = (
        BaselineNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
        BaselineNetwork("192.168.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
    )
    report = compare(perspective(), perspective(*entries))
    first = DiscoverySnapshot("h", "o", networks=(DiscoveredNetwork("192.168.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH), DiscoveredNetwork("172.16.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH)))
    second = DiscoverySnapshot("h", "o", networks=tuple(reversed(first.networks)))
    assert recommend(first, report) == recommend(second, report)
