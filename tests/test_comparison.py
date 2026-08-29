"""Tests for pure baseline construction and coverage-based comparison."""

import json

import pytest

from pivotcheck.analysis.comparison import (
    NetworkRelationship,
    baseline_from_snapshot,
    classify_relationship,
    compare,
    coverage_view,
)
from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def entry(network, *, gateway=None, interface="eth0", confidence=Confidence.MEDIUM):
    return BaselineNetwork(
        network=network,
        origin=NetworkOrigin.ROUTED if gateway else NetworkOrigin.CONNECTED,
        confidence=confidence,
        interface=interface,
        gateway=gateway,
        route_type=RouteType.STATIC if gateway else RouteType.CONNECTED,
    )


def perspective(*networks):
    return Baseline(created_at="2026-01-01T00:00:00+00:00", networks=networks)


@pytest.mark.parametrize(
    ("baseline", "current", "expected"),
    [
        ("10.20.0.0/16", "10.20.0.0/16", NetworkRelationship.EXACT),
        ("10.20.0.0/16", "10.20.10.0/24", NetworkRelationship.BASELINE_COVERS_CURRENT),
        ("10.20.10.0/24", "10.20.0.0/16", NetworkRelationship.CURRENT_COVERS_BASELINE),
        ("10.20.0.0/24", "10.20.1.0/24", NetworkRelationship.DISJOINT),
        ("10.20.0.0/16", "2001:db8::/32", NetworkRelationship.DISJOINT),
    ],
)
def test_relationship_classification(baseline, current, expected):
    assert classify_relationship(baseline, current) is expected


def test_cidr_overlap_is_always_containment_or_disjoint():
    # Canonical CIDR boundaries make a separate partial-overlap category impossible.
    assert (
        classify_relationship("10.20.0.0/25", "10.20.0.64/26")
        is NetworkRelationship.BASELINE_COVERS_CURRENT
    )


def test_coverage_view_collapses_equivalent_aggregation():
    view = coverage_view((entry("10.20.0.0/25"), entry("10.20.0.128/25")))
    assert [str(network) for network in view] == ["10.20.0.0/24"]


def test_coverage_view_partitions_ipv4_and_ipv6():
    view = coverage_view((entry("10.20.0.0/24"), entry("2001:db8::/32")))
    assert [str(network) for network in view] == ["10.20.0.0/24", "2001:db8::/32"]


def test_completely_new_network_is_new_reachability():
    report = compare(
        perspective(entry("10.10.0.0/24")),
        perspective(entry("10.10.0.0/24"), entry("172.16.50.0/24")),
    )
    assert [item.network for item in report.new_networks] == ["172.16.50.0/24"]
    assert report.new_networks[0].reachability_novelty is True


def test_more_specific_network_preserves_topology_without_new_reachability():
    report = compare(
        perspective(entry("10.20.0.0/16")), perspective(entry("10.20.10.0/24"))
    )
    assert report.new_networks == ()
    assert report.specificity_changes[0].network == "10.20.10.0/24"
    assert report.specificity_changes[0].reachability_novelty is False
    assert report.specificity_changes[0].topology_novelty is True
    assert report.coverage_changes[0].classification == "REDUCED_COVERAGE"


def test_current_supernet_is_expanded_reachability():
    report = compare(
        perspective(entry("10.20.10.0/24")), perspective(entry("10.20.0.0/16"))
    )
    assert report.coverage_changes[0].classification == "EXPANDED_REACHABILITY"
    assert report.coverage_changes[0].reachability_novelty is True


def test_exact_network_with_different_gateway_is_context_change_only():
    report = compare(
        perspective(entry("172.16.50.0/24", gateway="10.10.20.1")),
        perspective(entry("172.16.50.0/24", gateway="192.168.56.1")),
    )
    assert report.new_networks == ()
    assert report.context_changes[0].classification == "ROUTE_CONTEXT_CHANGED"
    assert report.context_changes[0].reachability_novelty is False


def test_aggregate_equivalence_is_unchanged_coverage():
    report = compare(
        perspective(entry("10.20.0.0/25"), entry("10.20.0.128/25")),
        perspective(entry("10.20.0.0/24")),
    )
    assert report.new_networks == ()
    assert report.coverage_changes == ()
    assert report.unchanged_networks[0].classification == "UNCHANGED_COVERAGE"


def test_duplicate_entries_do_not_create_duplicate_findings():
    report = compare(
        perspective(entry("10.10.0.0/24"), entry("10.10.0.0/24")),
        perspective(entry("172.16.50.0/24"), entry("172.16.50.0/24")),
    )
    assert len(report.new_networks) == 1


def test_baseline_from_snapshot_canonicalizes_and_is_serializable():
    snapshot = DiscoverySnapshot(
        hostname="testhost",
        os_name="Linux",
        timestamp="2026-01-01T00:00:00+00:00",
        networks=(
            DiscoveredNetwork(
                "10.20.10.5/24",
                NetworkOrigin.ROUTED,
                Confidence.MEDIUM,
                "eth0",
                "10.20.10.1",
            ),
            DiscoveredNetwork(
                "10.20.10.0/24",
                NetworkOrigin.ROUTED,
                Confidence.MEDIUM,
                "eth0",
                "10.20.10.1",
            ),
        ),
    )
    baseline = baseline_from_snapshot(snapshot)
    assert baseline.networks[0].network == "10.20.10.0/24"
    assert len(baseline.networks) == 1
    assert json.loads(json.dumps(baseline.to_dict()))["schema_version"] == 1
