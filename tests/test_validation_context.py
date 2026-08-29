"""Tests for validation context linking (pure + CLI).

Covers:
- Pure target context resolution (network match, comparison, priority).
- CLI contextual check behavior (--baseline flag).
- Legacy check behavior remains unchanged.
"""



from pivotcheck.analysis.comparison import DiffFinding, DiffReport
from pivotcheck.analysis.recommendation import Recommendation
from pivotcheck.checks.context import (
    build_validation_context,
    resolve_comparison_context,
    resolve_network_match,
    resolve_priority_context,
)
from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.check import (
    CheckReport,
    CheckResult,
    CheckStatus,
    RouteContextType,
)
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def net(cidr, origin, gateway=None, interface="eth0", confidence=None):
    return DiscoveredNetwork(
        cidr=cidr,
        origin=origin,
        confidence=confidence or (
            Confidence.HIGH if origin is NetworkOrigin.CONNECTED else Confidence.MEDIUM
        ),
        interface=interface,
        gateway=gateway,
    )


def snapshot(*networks):
    return DiscoverySnapshot(
        hostname="testhost",
        os_name="Linux 6.1",
        networks=tuple(networks),
    )


def baseline_network(cidr, origin, gateway=None, interface="eth0"):
    return BaselineNetwork(
        network=cidr,
        origin=origin,
        confidence=(
            Confidence.HIGH if origin is NetworkOrigin.CONNECTED else Confidence.MEDIUM
        ),
        interface=interface,
        gateway=gateway,
        route_type=(
            RouteType.STATIC if gateway is not None else RouteType.CONNECTED
        ),
    )


def baseline(*networks):
    return Baseline(networks=tuple(networks))


def finding(network, classification, related=None):
    return DiffFinding(
        network=network,
        classification=classification,
        relationship=None,
        related_network=related,
        reachability_novelty=True,
        topology_novelty=True,
    )


def empty_report():
    return DiffReport()


def report_with_new(network):
    return DiffReport(new_networks=(finding(network, "NEW_REACHABILITY"),))


def report_with_expanded(network, related):
    return DiffReport(
        coverage_changes=(
            finding(network, "EXPANDED_REACHABILITY", related),
        )
    )


def report_with_specificity(network, related):
    return DiffReport(
        specificity_changes=(finding(network, "MORE_SPECIFIC", related),)
    )


def report_with_context_change(network):
    return DiffReport(
        context_changes=(finding(network, "ROUTE_CONTEXT_CHANGED"),)
    )


def report_with_unchanged(network):
    return DiffReport(
        unchanged_networks=(finding(network, "UNCHANGED_COVERAGE"),)
    )


def recommendation(priority, network, reason="test reason"):
    return Recommendation(
        priority=priority,
        network=network,
        reason=reason,
        suggested_action="Perform explicit validation of an operator-chosen target.",
        limitation="Route and topology evidence do not prove active reachability.",
        evidence=("origin: connected",),
    )


class TestResolveNetworkMatch:
    def test_target_inside_exact_network(self):
        match = resolve_network_match(
            "10.50.10.25", (net("10.50.0.0/16", NetworkOrigin.ROUTED),)
        )
        assert match is not None
        assert match.network == "10.50.0.0/16"
        assert match.match_type == "COVERED"
        assert match.broader_networks == ()

    def test_target_inside_multiple_nested_networks(self):
        match = resolve_network_match(
            "10.50.10.25",
            (
                net("10.0.0.0/8", NetworkOrigin.ROUTED),
                net("10.50.0.0/16", NetworkOrigin.ROUTED),
                net("10.50.10.0/24", NetworkOrigin.CONNECTED),
            ),
        )
        assert match is not None
        assert match.network == "10.50.10.0/24"  # most-specific wins
        assert match.match_type == "MOST_SPECIFIC"
        assert match.broader_networks == ("10.0.0.0/8", "10.50.0.0/16")

    def test_most_specific_deterministic_selection(self):
        # Order of input must not change the result.
        networks = (
            net("10.50.0.0/16", NetworkOrigin.ROUTED),
            net("10.0.0.0/8", NetworkOrigin.ROUTED),
            net("10.50.10.0/24", NetworkOrigin.CONNECTED),
        )
        match1 = resolve_network_match("10.50.10.25", networks)
        match2 = resolve_network_match("10.50.10.25", tuple(reversed(networks)))
        assert match1 is not None and match2 is not None
        assert match1.network == match2.network == "10.50.10.0/24"
        assert match1.broader_networks == match2.broader_networks

    def test_ipv4_family_separation(self):
        # IPv6 networks must not match an IPv4 address.
        match = resolve_network_match(
            "10.50.10.25",
            (net("2001:db8::/32", NetworkOrigin.ROUTED),),
        )
        assert match is None

    def test_ipv6_family_separation(self):
        match = resolve_network_match(
            "2001:db8::1",
            (net("2001:db8::/32", NetworkOrigin.ROUTED),),
        )
        assert match is not None
        assert match.network == "2001:db8::/32"

    def test_no_containing_network(self):
        match = resolve_network_match(
            "192.0.2.1",
            (net("10.50.0.0/16", NetworkOrigin.ROUTED),),
        )
        assert match is None

    def test_invalid_address_returns_none(self):
        assert resolve_network_match("not-an-ip", ()) is None

    def test_empty_evidence_returns_none(self):
        assert resolve_network_match("10.50.10.25", ()) is None

    def test_exact_host_route(self):
        match = resolve_network_match(
            "10.50.10.25",
            (net("10.50.10.25/32", NetworkOrigin.CONNECTED),),
        )
        assert match is not None
        assert match.match_type == "EXACT"

    def test_connected_beats_routed_on_equal_specificity(self):
        match = resolve_network_match(
            "10.50.10.25",
            (
                net("10.50.10.0/24", NetworkOrigin.ROUTED, gateway="10.9.9.9"),
                net("10.50.10.0/24", NetworkOrigin.CONNECTED),
            ),
        )
        assert match is not None
        assert match.network == "10.50.10.0/24"


class TestResolveComparisonContext:
    def test_new_coverage(self):
        ctx = resolve_comparison_context(
            "10.50.0.0/16", report_with_new("10.50.0.0/16"), "workstation"
        )
        assert ctx is not None
        assert ctx.baseline == "workstation"
        assert ctx.relationship == "NEW_COVERAGE"
        assert ctx.classification == "NEW_REACHABILITY"

    def test_expanded_coverage(self):
        ctx = resolve_comparison_context(
            "10.50.0.0/16",
            report_with_expanded("10.50.0.0/16", "10.0.0.0/8"),
            "workstation",
        )
        assert ctx is not None
        assert ctx.relationship == "EXPANDED_COVERAGE"
        assert ctx.related_network == "10.0.0.0/8"

    def test_more_specific_evidence(self):
        ctx = resolve_comparison_context(
            "10.50.10.0/24",
            report_with_specificity("10.50.10.0/24", "10.50.0.0/16"),
            "workstation",
        )
        assert ctx is not None
        assert ctx.relationship == "MORE_SPECIFIC"
        assert ctx.related_network == "10.50.0.0/16"

    def test_context_changed(self):
        ctx = resolve_comparison_context(
            "10.50.0.0/16",
            report_with_context_change("10.50.0.0/16"),
            "workstation",
        )
        assert ctx is not None
        assert ctx.relationship == "CONTEXT_CHANGED"

    def test_unchanged_coverage(self):
        ctx = resolve_comparison_context(
            "10.50.0.0/16",
            report_with_unchanged("10.50.0.0/16"),
            "workstation",
        )
        assert ctx is not None
        assert ctx.relationship == "UNCHANGED"

    def test_not_observed_in_baseline(self):
        # Network exists in current evidence but has no finding.
        ctx = resolve_comparison_context(
            "10.50.0.0/16", empty_report(), "workstation"
        )
        assert ctx is not None
        assert ctx.relationship == "NOT_OBSERVED_IN_BASELINE"

    def test_no_report_returns_none(self):
        # MISSING CONTEXT (no baseline requested) is distinct from
        # NOT_OBSERVED_IN_BASELINE (known negative).
        assert resolve_comparison_context("10.50.0.0/16", None, "workstation") is None


class TestResolvePriorityContext:
    def test_recommendation_association(self):
        recs = (recommendation("HIGH", "10.50.0.0/16"),)
        ctx = resolve_priority_context("10.50.0.0/16", recs)
        assert ctx is not None
        assert ctx.level == "HIGH"
        assert ctx.reason == "test reason"

    def test_no_recommendation(self):
        assert resolve_priority_context("10.50.0.0/16", ()) is None

    def test_recommendation_for_different_network(self):
        recs = (recommendation("HIGH", "10.99.0.0/16"),)
        assert resolve_priority_context("10.50.0.0/16", recs) is None

    def test_deterministic_ordering(self):
        recs = (
            recommendation("LOW", "10.50.0.0/16"),
            recommendation("HIGH", "10.50.0.0/16"),
        )
        ctx = resolve_priority_context("10.50.0.0/16", recs)
        assert ctx is not None
        # First match wins deterministically.
        assert ctx.level == "LOW"


class TestBuildValidationContext:
    def test_full_context_with_baseline(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED, gateway="10.50.1.1"))
        ctx = build_validation_context(
            "10.50.10.25",
            snap,
            report=report_with_new("10.50.0.0/16"),
            baseline_name="workstation",
            recommendations=(recommendation("HIGH", "10.50.0.0/16"),),
        )
        assert ctx.target == "10.50.10.25"
        assert ctx.network_match is not None
        assert ctx.network_match.network == "10.50.0.0/16"
        assert ctx.route_context is not None
        assert ctx.route_context.context_type is RouteContextType.ROUTED
        assert ctx.route_context.gateway == "10.50.1.1"
        assert ctx.comparison is not None
        assert ctx.comparison.relationship == "NEW_COVERAGE"
        assert ctx.priority is not None
        assert ctx.priority.level == "HIGH"
        assert ctx.limitations

    def test_no_baseline_means_no_comparison(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED))
        ctx = build_validation_context("10.50.10.25", snap)
        assert ctx.comparison is None  # MISSING CONTEXT
        assert ctx.priority is None
        assert ctx.network_match is not None
        assert ctx.route_context is not None

    def test_no_containing_network(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED))
        ctx = build_validation_context("192.0.2.1", snap)
        assert ctx.network_match is None
        assert ctx.route_context is not None
        assert ctx.route_context.context_type is RouteContextType.UNKNOWN
        assert any("No containing network" in line for line in ctx.limitations)

    def test_route_context_absent(self):
        snap = snapshot()
        ctx = build_validation_context("10.50.10.25", snap)
        assert ctx.network_match is None
        assert ctx.route_context is not None
        assert ctx.route_context.context_type is RouteContextType.UNKNOWN
        assert any("route context" in line for line in ctx.limitations)

    def test_unchanged_relationship_is_known_negative(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED))
        ctx = build_validation_context(
            "10.50.10.25",
            snap,
            report=report_with_unchanged("10.50.0.0/16"),
            baseline_name="workstation",
        )
        assert ctx.comparison is not None
        assert ctx.comparison.relationship == "UNCHANGED"
        # Unchanged is a known negative, not a limitation.
        assert not any(
            "Comparison findings describe evidence" in line
            for line in ctx.limitations
        )

    def test_new_coverage_has_limitation(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED))
        ctx = build_validation_context(
            "10.50.10.25",
            snap,
            report=report_with_new("10.50.0.0/16"),
            baseline_name="workstation",
        )
        assert any(
            "Comparison findings describe evidence" in line
            for line in ctx.limitations
        )


class TestValidationContextSerialization:
    def test_to_dict_structure(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED, gateway="10.50.1.1"))
        ctx = build_validation_context(
            "10.50.10.25",
            snap,
            report=report_with_new("10.50.0.0/16"),
            baseline_name="workstation",
            recommendations=(recommendation("HIGH", "10.50.0.0/16"),),
        )
        data = ctx.to_dict()
        assert data["target"] == "10.50.10.25"
        assert data["network_context"]["matched_network"]["network"] == "10.50.0.0/16"
        assert data["network_context"]["route_context"]["type"] == "ROUTED"
        assert data["comparison_context"]["baseline"] == "workstation"
        assert data["comparison_context"]["relationship"] == "NEW"
        assert data["priority_context"]["level"] == "HIGH"
        assert isinstance(data["limitations"], list)

    def test_to_dict_absent_context_is_null(self):
        snap = snapshot()
        ctx = build_validation_context("10.50.10.25", snap)
        data = ctx.to_dict()
        assert data["network_context"]["matched_network"] is None
        assert data["comparison_context"]["baseline"] is None
        assert data["comparison_context"]["relationship"] is None
        assert data["priority_context"]["level"] is None


class TestCheckReportSerialization:
    def test_legacy_report_unchanged(self):
        report = CheckReport(
            target="127.0.0.1",
            resolved_addresses=("127.0.0.1",),
            ports=(80,),
            timeout_s=3.0,
            results=(
                CheckResult(
                    target="127.0.0.1",
                    address="127.0.0.1",
                    port=80,
                    status=CheckStatus.SUCCESS,
                ),
            ),
        )
        data = report.to_dict()
        assert "validation_context" not in data  # legacy shape preserved

    def test_contextual_report_includes_validation_context(self):
        snap = snapshot(net("10.50.0.0/16", NetworkOrigin.ROUTED))
        vctx = build_validation_context(
            "10.50.10.25",
            snap,
            report=report_with_new("10.50.0.0/16"),
            baseline_name="workstation",
        )
        report = CheckReport(
            target="10.50.10.25",
            resolved_addresses=("10.50.10.25",),
            ports=(445,),
            timeout_s=3.0,
            results=(
                CheckResult(
                    target="10.50.10.25",
                    address="10.50.10.25",
                    port=445,
                    status=CheckStatus.REFUSED,
                ),
            ),
            validation_context=vctx,
        )
        data = report.to_dict()
        assert "validation_context" in data
        assert data["validation_context"]["target"] == "10.50.10.25"