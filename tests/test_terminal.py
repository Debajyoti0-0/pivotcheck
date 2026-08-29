"""Tests for terminal renderers (detailed + map) and evidence display."""

import io

from pivotcheck.analysis.topology import analyze
from pivotcheck.models.network import (
    Interface,
    InterfaceState,
    IPAddress,
    Neighbor,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot, DiscoveryWarning
from pivotcheck.output.terminal import render_detailed, render_map


def make_snapshot(**overrides) -> DiscoverySnapshot:
    defaults = {
        "hostname": "ophost",
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
                state=InterfaceState.DOWN,
                ipv4_addresses=(IPAddress("192.168.56.101", 24),),
            ),
        ),
        "routes": (
            Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
            Route("172.16.50.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
        ),
        "neighbors": (Neighbor("10.10.20.1", "eth0", "aa:bb:cc:dd:ee:01", "REACHABLE"),),
        "warnings": (DiscoveryWarning("neighbors", "Permission denied"),),
    }
    defaults.update(overrides)
    # Renderers consume ANALYZED snapshots (networks + pivot_paths populated).
    return analyze(DiscoverySnapshot(**defaults))


def render(snapshot, renderer) -> str:
    buf = io.StringIO()
    renderer(snapshot, buf, color=False)
    return buf.getvalue()


class TestDetailedRenderer:
    def test_contains_all_sections(self):
        out = render(make_snapshot(), render_detailed)
        for section in (
            "NETWORK SUMMARY",
            "DIRECTLY CONNECTED NETWORKS",
            "ROUTED NETWORKS",
            "POTENTIAL PIVOT PATHS",
            "DISCOVERY WARNINGS",
            "RECOMMENDED NEXT STEP",
        ):
            assert section in out

    def test_summary_counts(self):
        out = render(make_snapshot(), render_detailed)
        assert "Direct Networks:       2" in out
        assert "Routed Networks:       1" in out
        assert "Potential Pivot Paths: 1" in out
        assert "Known Neighbors:       1" in out
        assert "Warnings:              1" in out

    def test_high_confidence_direct_network(self):
        out = render(make_snapshot(), render_detailed)
        assert "[HIGH] 10.10.20.0/24" in out
        assert "Interface : eth0" in out
        assert "Address   : 10.10.20.15/24" in out

    def test_low_confidence_down_interface(self):
        out = render(make_snapshot(), render_detailed)
        assert "[LOW] 192.168.56.0/24" in out
        assert "currently DOWN" in out

    def test_routed_network_evidence_mentions_route_not_reachability(self):
        out = render(make_snapshot(), render_detailed)
        assert "[MEDIUM] 172.16.50.0/24" in out
        assert "Gateway   : 10.10.20.254" in out
        assert "routing table contains" in out.lower()

    def test_pivot_path_shows_chain_and_caveat(self):
        out = render(make_snapshot(), render_detailed)
        assert "10.10.20.15" in out
        assert "eth0" in out
        assert "10.10.20.254" in out
        assert "172.16.50.0/24" in out
        assert "not yet validated" in out

    def test_warning_displayed_with_reason(self):
        out = render(make_snapshot(), render_detailed)
        assert "[!] Neighbors unavailable" in out
        assert "Permission denied" in out

    def test_empty_discovery_does_not_crash(self):
        snapshot = make_snapshot(
            interfaces=(), routes=(), neighbors=(), warnings=()
        )
        out = render(snapshot, render_detailed)
        assert "No directly connected networks found." in out
        assert "No additional routed networks discovered." in out
        assert "No pivot paths identified" in out

    def test_no_warnings_section_when_clean(self):
        snapshot = make_snapshot(warnings=())
        out = render(snapshot, render_detailed)
        assert "DISCOVERY WARNINGS" not in out

    def test_no_ansi_when_color_disabled(self):
        out = render(make_snapshot(), render_detailed)
        assert "\033[" not in out

    def test_loopback_never_creates_pivot_path(self):
        # loopback has no static routes; nothing to infer from
        snapshot = make_snapshot()
        out = render(snapshot, render_detailed)
        assert "127.0.0.0/8" not in out.split("ROUTED NETWORKS")[1].split(
            "POTENTIAL"
        )[0]


class TestMapRenderer:
    def test_shows_interfaces_and_networks(self):
        out = render(make_snapshot(), render_map)
        assert "LOCAL HOST" in out
        assert "eth0" in out
        assert "eth1" in out
        assert "10.10.20.0/24" in out
        assert "192.168.56.0/24" in out
        assert "172.16.50.0/24" in out

    def test_distinguishes_direct_from_routed(self):
        out = render(make_snapshot(), render_map)
        assert "directly connected" in out
        assert "route configured — reachability unverified" in out

    def test_legend_present(self):
        out = render(make_snapshot(), render_map)
        assert "Legend:" in out
        assert "configuration evidence, not confirmed reachability" in out

    def test_empty_snapshot_renders_host_only(self):
        snapshot = make_snapshot(interfaces=(), routes=())
        out = render(snapshot, render_map)
        assert "LOCAL HOST" in out
