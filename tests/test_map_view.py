"""Pure map-view and renderer tests; comparison classification is precomputed."""

import io
import json

from pivotcheck.analysis.comparison import compare
from pivotcheck.analysis.map_view import build_map_view
from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
    PivotPath,
)
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.session import SessionIdentity
from pivotcheck.output.map_view import render_map_view, render_map_view_json


def baseline(*cidrs):
    return Baseline(
        created_at="2026-01-01T00:00:00+00:00",
        networks=tuple(
            BaselineNetwork(cidr, NetworkOrigin.CONNECTED, Confidence.HIGH)
            for cidr in cidrs
        ),
        vantage_point=SessionIdentity("base", "fake", "Baseline host"),
    )


def snapshot(*networks, session=None, pivots=()):
    return DiscoverySnapshot(
        "current-host",
        "OS",
        networks=tuple(networks),
        session=session or SessionIdentity("current", "fake", "Current host"),
        pivot_paths=pivots,
    )


def test_current_only_map_is_deterministic_and_includes_pivots():
    current = snapshot(
        DiscoveredNetwork(
            "2001:db8::/32", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.0.0.1"
        ),
        DiscoveredNetwork(
            "10.10.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"
        ),
        pivots=(PivotPath("eth0", "10.10.0.1", "172.16.0.0/16", Confidence.MEDIUM),),
    )
    view = build_map_view(current)
    assert [item.network for item in view.current_connected] == ["10.10.0.0/24"]
    assert [item.network for item in view.current_routed] == ["2001:db8::/32"]
    assert view.pivot_paths[0].gateway == "10.10.0.1"


def test_map_consumes_new_coverage_without_recalculating_it():
    base = baseline("10.10.0.0/24")
    current = snapshot(
        DiscoveredNetwork(
            "172.16.50.0/24",
            NetworkOrigin.ROUTED,
            Confidence.MEDIUM,
            "tun0",
            "10.0.0.1",
        )
    )
    view = build_map_view(
        current,
        baseline=base,
        baseline_name="workstation",
        report=compare(
            base,
            Baseline(
                created_at="now",
                networks=tuple(
                    BaselineNetwork(
                        net.cidr, net.origin, net.confidence, net.interface, net.gateway
                    )
                    for net in current.networks
                ),
                vantage_point=current.session,
            ),
        ),
    )
    assert view.new_coverage[0].state == "NEW_COVERAGE"
    assert view.new_coverage[0].gateway == "10.0.0.1"
    assert view.baseline_name == "workstation"


def test_more_specific_and_reduced_coverage_remain_distinct():
    base = baseline("10.20.0.0/16")
    current_baseline = baseline("10.20.10.0/24")
    current = snapshot(
        DiscoveredNetwork(
            "10.20.10.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"
        )
    )
    view = build_map_view(
        current, baseline=base, report=compare(base, current_baseline)
    )
    assert view.new_coverage == ()
    assert view.more_specific_evidence[0].network == "10.20.10.0/24"
    assert view.baseline_only[0].state == "REDUCED_COVERAGE"


def test_expanded_context_and_missing_baseline_identity_are_preserved():
    base = Baseline(
        created_at="old",
        networks=(
            BaselineNetwork("10.20.10.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
        ),
    )
    current_baseline = baseline("10.20.0.0/16")
    current = snapshot(
        DiscoveredNetwork(
            "10.20.0.0/16", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"
        )
    )
    view = build_map_view(
        current, baseline=base, report=compare(base, current_baseline)
    )
    assert view.expanded_coverage[0].state == "EXPANDED_COVERAGE"
    output = io.StringIO()
    render_map_view(view, output)
    assert "vantage point: unavailable" in output.getvalue()


def test_context_change_is_annotation_category_not_new_coverage():
    base = Baseline(
        created_at="old",
        networks=(
            BaselineNetwork(
                "172.16.0.0/24",
                NetworkOrigin.ROUTED,
                Confidence.MEDIUM,
                "tun0",
                "10.0.0.1",
            ),
        ),
    )
    current_base = Baseline(
        created_at="now",
        networks=(
            BaselineNetwork(
                "172.16.0.0/24",
                NetworkOrigin.ROUTED,
                Confidence.MEDIUM,
                "tun0",
                "10.0.0.2",
            ),
        ),
    )
    current = snapshot(
        DiscoveredNetwork(
            "172.16.0.0/24", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.0.0.2"
        )
    )
    view = build_map_view(current, baseline=base, report=compare(base, current_base))
    assert view.new_coverage == ()
    assert view.context_changes[0].state == "CONTEXT_CHANGED"


def test_json_and_terminal_render_semantic_plain_text():
    view = build_map_view(
        snapshot(
            DiscoveredNetwork(
                "10.0.0.0/24",
                NetworkOrigin.CONNECTED,
                Confidence.HIGH,
                "very-long-interface-name",
            )
        )
    )
    terminal = io.StringIO()
    render_map_view(view, terminal, color=True)
    assert "[=] 10.0.0.0/24" in terminal.getvalue()
    assert "\033[" not in terminal.getvalue()
    document = io.StringIO()
    render_map_view_json(view, document)
    parsed = json.loads(document.getvalue())
    assert set(parsed["map"]) == {
        "new_coverage",
        "expanded_coverage",
        "current_connected",
        "current_routed",
        "more_specific_evidence",
        "context_changes",
        "baseline_only",
        "unchanged",
        "pivot_paths",
    }
