"""Network safety invariant tests.

These tests prove that passive analysis commands perform ZERO network operations.
They use monkey-patching to intercept socket and network calls and fail if any
are made during passive analysis.
"""

from __future__ import annotations

import contextlib
import socket
from unittest.mock import patch

import pytest

from pivotcheck.analysis.evidence_gaps import analyze_evidence_gaps
from pivotcheck.analysis.explanation import explain_network
from pivotcheck.analysis.gateway import assess_transit_evidence
from pivotcheck.analysis.next_step import select_next_investigation
from pivotcheck.analysis.recommendation import recommend
from pivotcheck.analysis.summary import summarize_snapshot
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


class NetworkCallTracker:
    """Track all network-related calls."""

    def __init__(self):
        self.calls: list[dict] = []

    def record(self, func_name: str, args: tuple, kwargs: dict):
        self.calls.append({"function": func_name, "args": args, "kwargs": kwargs})

    def assert_no_calls(self, allowed_functions: set[str] | None = None):
        """Assert no network calls were made, except allowed ones."""
        if allowed_functions is None:
            allowed_functions = set()

        unexpected = [c for c in self.calls if c["function"] not in allowed_functions]
        if unexpected:
            raise AssertionError(
                f"Unexpected network calls during passive analysis: {unexpected}"
            )


@pytest.fixture
def tracker():
    return NetworkCallTracker()


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


def _make_snapshot() -> DiscoverySnapshot:
    """Create a test snapshot with some data."""
    interfaces = [_make_interface("eth0", "10.10.20.5", 24)]
    routes = [_make_route("10.50.0.0/16", "10.10.20.1", "eth0", RouteType.STATIC)]
    neighbors = [_make_neighbor("10.10.20.1", "eth0")]
    connections = [_make_connection("tcp", "10.10.20.5", 44555, "10.10.20.1", 22, "ESTABLISHED")]
    networks = [
        _make_network("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
        _make_network("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.1"),
    ]

    base = DiscoverySnapshot(
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
    return analyze(base)


class TestNoNetworkCallsInPassiveAnalysis:
    """Passive analysis must never make network calls."""

    def test_topology_analysis_no_network(self, tracker):
        """analyze() must not make network calls."""
        snapshot = _make_snapshot()

        # Patch socket functions to track calls
        original_socket = socket.socket

        def tracking_socket(*args, **kwargs):
            tracker.record("socket.socket", args, kwargs)
            return original_socket(*args, **kwargs)

        with patch("socket.socket", tracking_socket), patch(
            "socket.create_connection", lambda *a, **k: tracker.record("socket.create_connection", a, k)
        ), patch("socket.getaddrinfo", lambda *a, **k: tracker.record("socket.getaddrinfo", a, k)), patch(
            "socket.gethostbyname", lambda *a, **k: tracker.record("socket.gethostbyname", a, k)
        ):
            analyze(snapshot)

        tracker.assert_no_calls()

    def test_transit_evidence_no_network(self, tracker):
        """assess_transit_evidence() must not make network calls."""
        snapshot = _make_snapshot()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)), patch(
            "socket.create_connection", lambda *a, **k: tracker.record("socket.create_connection", a, k)
        ):
            assess_transit_evidence(snapshot)

        tracker.assert_no_calls()

    def test_next_step_no_network(self, tracker):
        """select_next_investigation() must not make network calls."""
        snapshot = _make_snapshot()
        transit = assess_transit_evidence(snapshot)

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)), patch(
            "socket.create_connection", lambda *a, **k: tracker.record("socket.create_connection", a, k)
        ):
            select_next_investigation(snapshot, transit_evidence=transit)

        tracker.assert_no_calls()

    def test_recommendation_no_network(self, tracker):
        """recommend() must not make network calls."""
        snapshot = _make_snapshot()
        from pivotcheck.analysis.comparison import DiffReport
        report = DiffReport()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)):
            recommend(snapshot, report)

        tracker.assert_no_calls()

    def test_evidence_gaps_no_network(self, tracker):
        """analyze_evidence_gaps() must not make network calls."""
        snapshot = _make_snapshot()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)), patch(
            "socket.create_connection", lambda *a, **k: tracker.record("socket.create_connection", a, k)
        ):
            analyze_evidence_gaps(snapshot, "10.50.0.0/16")

        tracker.assert_no_calls()

    def test_explanation_no_network(self, tracker):
        """explain_network() must not make network calls."""
        snapshot = _make_snapshot()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)), patch(
            "socket.create_connection", lambda *a, **k: tracker.record("socket.create_connection", a, k)
        ):
            explain_network("10.50.0.0/16", snapshot)

        tracker.assert_no_calls()

    def test_summary_no_network(self, tracker):
        """summarize_snapshot() must not make network calls."""
        snapshot = _make_snapshot()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)):
            summarize_snapshot(snapshot)

        tracker.assert_no_calls()


class TestActiveCommandsDoNetwork:
    """Verify that active commands DO make network calls (sanity check)."""

    def test_check_makes_network_call(self):
        """check command should make network calls."""
        from pivotcheck.checks.tcp import check_tcp

        call_made = {"value": False}

        original_connect = socket.socket.connect

        def tracking_connect(self, *args, **kwargs):
            call_made["value"] = True
            return original_connect(self, *args, **kwargs)

        with patch("socket.socket.connect", tracking_connect), contextlib.suppress(Exception):
            # This should fail on connection but the connect() should be called
            check_tcp("127.0.0.1", 9999, 0.1, target="127.0.0.1")

        assert call_made["value"], "check_tcp should call socket.connect"


class TestNoSubprocessNetworkCalls:
    """Passive analysis must not spawn network subprocesses."""

    def test_no_subprocess_in_analysis(self, tracker):
        """Analysis must not use subprocess for network operations."""
        import subprocess
        snapshot = _make_snapshot()

        original_run = subprocess.run

        def tracking_run(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", "")
            if isinstance(cmd, (list, str)):
                cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
                if any(net_tool in cmd_str.lower() for net_tool in ["ping", "nc", "nmap", "ss", "ip", "arp", "netstat", "route"]):
                    tracker.record("subprocess.run", (cmd_str,), kwargs)
            return original_run(*args, **kwargs)

        with patch("subprocess.run", tracking_run):
            analyze(snapshot)

        tracker.assert_no_calls()


class TestNoExternalHTTP:
    """Passive analysis must not make HTTP requests."""

    def test_no_http_requests(self, tracker):
        """Analysis must not use urllib or requests."""
        snapshot = _make_snapshot()

        # Try to patch common HTTP libraries
        modules_to_patch = [
            ("urllib.request", "urlopen"),
            ("requests", "get"),
            ("requests", "post"),
            ("httpx", "get"),
            ("aiohttp", "ClientSession"),
        ]

        patches = []
        for module_name, func_name in modules_to_patch:
            try:
                module = __import__(module_name, fromlist=[func_name])
                original_func = getattr(module, func_name, None)
                if original_func:
                    def make_tracker(mod_name, fn_name):
                        def tracker_func(*args, **kwargs):
                            tracker.record(f"{mod_name}.{fn_name}", args, kwargs)
                            raise RuntimeError(f"Blocked {mod_name}.{fn_name}")
                        return tracker_func
                    patches.append(patch(f"{module_name}.{func_name}", make_tracker(module_name, func_name)))
            except ImportError:
                pass

        if patches:
            # Apply patches manually
            for p in patches:
                p.start()
            try:
                analyze(snapshot)
            finally:
                for p in patches:
                    p.stop()
        else:
            # No HTTP libraries available to patch, just run analysis
            analyze(snapshot)

        tracker.assert_no_calls()


class TestDNSResolutionSafety:
    """Passive analysis must not resolve hostnames."""

    def test_no_dns_resolution_in_passive(self, tracker):
        """Passive analysis must not resolve hostnames."""
        import socket
        snapshot = _make_snapshot()

        original_getaddrinfo = socket.getaddrinfo

        def tracking_getaddrinfo(*args, **kwargs):
            tracker.record("socket.getaddrinfo", args, kwargs)
            return original_getaddrinfo(*args, **kwargs)

        with patch("socket.getaddrinfo", tracking_getaddrinfo):
            analyze(snapshot)

        tracker.assert_no_calls()


# Test that the test infrastructure itself works
class TestTrackerInfrastructure:
    """Verify the test tracking infrastructure works correctly."""

    def test_tracker_detects_socket_call(self):
        """Tracker should detect socket.socket() calls."""
        tracker = NetworkCallTracker()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)):
            socket.socket()

        assert len(tracker.calls) == 1
        assert tracker.calls[0]["function"] == "socket.socket"

    def test_tracker_allows_whitelist(self):
        """Tracker should allow whitelisted functions."""
        tracker = NetworkCallTracker()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)):
            socket.socket()

        # Should not raise with whitelist
        tracker.assert_no_calls(allowed_functions={"socket.socket"})

    def test_tracker_raises_on_unexpected(self):
        """Tracker should raise on unexpected calls."""
        tracker = NetworkCallTracker()

        with patch("socket.socket", lambda *a, **k: tracker.record("socket.socket", a, k)):
            socket.socket()

        with pytest.raises(AssertionError):
            tracker.assert_no_calls()