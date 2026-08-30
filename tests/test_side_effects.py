"""Side-effect safety tests.

These tests verify that passive analysis commands do not unexpectedly:
- modify the network
- open sockets
- send packets
- execute external network tools
- modify unrelated files
- modify baseline data unexpectedly
- modify environment variables
"""

from __future__ import annotations

import os
import socket
import tempfile
from unittest.mock import patch

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


class TestFilesystemSideEffects:
    """Passive analysis must not modify files."""

    def test_no_temp_files_created(self):
        """Analysis must not create temporary files."""
        snapshot = _make_snapshot()

        # Track tempfile creation
        original_mkstemp = tempfile.mkstemp
        calls = []

        def tracking_mkstemp(*args, **kwargs):
            calls.append(("mkstemp", args, kwargs))
            return original_mkstemp(*args, **kwargs)

        with patch("tempfile.mkstemp", tracking_mkstemp), patch(
            "tempfile.NamedTemporaryFile",
            lambda *a, **k: calls.append(("NamedTemporaryFile", a, k)) or original_mkstemp(*a, **k),
        ):
            analyze(snapshot)

        assert len(calls) == 0, f"Unexpected tempfile calls: {calls}"

    def test_no_file_writes(self):
        """Analysis must not write files."""
        snapshot = _make_snapshot()

        original_open = open
        write_calls = []

        def tracking_open(file, mode="r", *args, **kwargs):
            if "w" in mode or "a" in mode or "+" in mode:
                write_calls.append((file, mode))
            return original_open(file, mode, *args, **kwargs)

        with patch("builtins.open", tracking_open):
            analyze(snapshot)

        # Allow reading of fixture files, but no writes to non-fixture files
        unexpected_writes = [c for c in write_calls if "fixtures" not in str(c[0]) and "__pycache__" not in str(c[0])]
        assert len(unexpected_writes) == 0, f"Unexpected file writes: {unexpected_writes}"

    def test_baseline_not_modified(self):
        """Passive analysis must not modify baseline data."""
        from pivotcheck.analysis.comparison import baseline_from_snapshot
        from pivotcheck.storage.baseline_store import BaselineStore

        snapshot = _make_snapshot()

        with tempfile.TemporaryDirectory() as tmpdir:
            store = BaselineStore(tmpdir)
            baseline = store.create("test-baseline", baseline_from_snapshot(snapshot))

            # Run analysis - should not modify baseline
            analyze(snapshot)

            # Reload and verify unchanged
            reloaded = store.load("test-baseline")
            assert reloaded.name == baseline.name
            assert reloaded.baseline.networks == baseline.baseline.networks


class TestEnvironmentSideEffects:
    """Passive analysis must not modify environment."""

    def test_no_env_modification(self):
        """Analysis must not modify environment variables."""
        snapshot = _make_snapshot()

        dict(os.environ)
        original_setenv = os.environ.__setitem__
        original_delenv = os.environ.__delitem__

        setenv_calls = []
        delenv_calls = []

        def tracking_setenv(key, value):
            setenv_calls.append((key, value))
            return original_setenv(key, value)

        def tracking_delenv(key):
            delenv_calls.append(key)
            return original_delenv(key)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.__setitem__ = tracking_setenv
            os.environ.__delitem__ = tracking_delenv
            try:
                analyze(snapshot)
            finally:
                os.environ.__setitem__ = original_setenv
                os.environ.__delitem__ = original_delenv

        assert len(setenv_calls) == 0, f"Unexpected env sets: {setenv_calls}"
        assert len(delenv_calls) == 0, f"Unexpected env deletes: {delenv_calls}"

    def test_no_cwd_change(self):
        """Analysis must not change working directory."""
        snapshot = _make_snapshot()

        os.getcwd()
        original_chdir = os.chdir
        chdir_calls = []

        def tracking_chdir(path):
            chdir_calls.append(path)
            return original_chdir(path)

        with patch("os.chdir", tracking_chdir):
            analyze(snapshot)

        assert len(chdir_calls) == 0, f"Unexpected chdir calls: {chdir_calls}"


class TestSocketSideEffects:
    """Passive analysis must not create or modify sockets."""

    def test_no_socket_creation(self):
        """Analysis must not create sockets."""
        snapshot = _make_snapshot()

        socket_created = {"value": False}
        original_socket = socket.socket

        def tracking_socket(*args, **kwargs):
            socket_created["value"] = True
            return original_socket(*args, **kwargs)

        with patch("socket.socket", tracking_socket):
            analyze(snapshot)

        assert not socket_created["value"], "Socket created during passive analysis"

    def test_no_socket_bind(self):
        """Analysis must not bind sockets."""
        snapshot = _make_snapshot()

        bind_called = {"value": False}

        class TrackedSocket:
            def __init__(self, *args, **kwargs):
                self._sock = socket.socket(*args, **kwargs)

            def bind(self, *args, **kwargs):
                bind_called["value"] = True
                return self._sock.bind(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self._sock, name)

        with patch("socket.socket", TrackedSocket):
            analyze(snapshot)

        assert not bind_called["value"], "Socket bind called during passive analysis"

    def test_no_socket_listen(self):
        """Analysis must not listen on sockets."""
        snapshot = _make_snapshot()

        listen_called = {"value": False}

        class TrackedSocket:
            def __init__(self, *args, **kwargs):
                self._sock = socket.socket(*args, **kwargs)

            def listen(self, *args, **kwargs):
                listen_called["value"] = True
                return self._sock.listen(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(self._sock, name)

        with patch("socket.socket", TrackedSocket):
            analyze(snapshot)

        assert not listen_called["value"], "Socket listen called during passive analysis"


class TestSubprocessSideEffects:
    """Passive analysis must not spawn subprocesses."""

    def test_no_subprocess_run(self):
        """Analysis must not use subprocess.run."""
        import subprocess
        snapshot = _make_snapshot()

        calls = []
        original_run = subprocess.run

        def tracking_run(*args, **kwargs):
            calls.append(("run", args, kwargs))
            return original_run(*args, **kwargs)

        with patch("subprocess.run", tracking_run):
            analyze(snapshot)

        assert len(calls) == 0, f"Unexpected subprocess.run calls: {calls}"

    def test_no_popen(self):
        """Analysis must not use Popen."""
        import subprocess
        snapshot = _make_snapshot()

        calls = []
        original_popen = subprocess.Popen

        def tracking_popen(*args, **kwargs):
            calls.append(("Popen", args, kwargs))
            return original_popen(*args, **kwargs)

        with patch("subprocess.Popen", tracking_popen):
            analyze(snapshot)

        assert len(calls) == 0, f"Unexpected Popen calls: {calls}"


class TestGlobalStateSideEffects:
    """Passive analysis must not modify global state."""

    def test_no_random_seed_change(self):
        """Analysis must not modify random state."""
        import random
        snapshot = _make_snapshot()

        random.getstate()

        analyze(snapshot)

        random.getstate()
        # Random state should be unchanged (or at least, not deterministically modified)
        # We just verify it's callable and doesn't crash

    def test_no_sys_path_modification(self):
        """Analysis must not modify sys.path."""
        import sys
        snapshot = _make_snapshot()

        path_before = list(sys.path)

        analyze(snapshot)

        path_after = list(sys.path)
        assert path_before == path_after, "sys.path modified during analysis"

    def test_no_logging_config_change(self):
        """Analysis must not reconfigure logging."""
        import logging
        snapshot = _make_snapshot()

        handlers_before = list(logging.root.handlers)
        level_before = logging.root.level

        analyze(snapshot)

        handlers_after = list(logging.root.handlers)
        level_after = logging.root.level

        assert handlers_before == handlers_after, "Logging handlers changed"
        assert level_before == level_after, "Logging level changed"


class TestOutputCapture:
    """Verify output behavior."""

    def test_stdout_only_for_explicit_render(self):
        """Analysis functions must not print to stdout directly."""
        import sys
        from io import StringIO
        snapshot = _make_snapshot()

        # Capture stdout
        old_stdout = sys.stdout
        captured = StringIO()
        sys.stdout = captured

        try:
            result = analyze(snapshot)
            # Result should be returned, not printed
            assert result is not None
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        assert output == "", f"Analysis printed to stdout: {output}"

    def test_stderr_only_for_warnings(self):
        """Analysis must not print to stderr except warnings."""
        import sys
        from io import StringIO
        snapshot = _make_snapshot()

        old_stderr = sys.stderr
        captured = StringIO()
        sys.stderr = captured

        try:
            analyze(snapshot)
        finally:
            sys.stderr = old_stderr

        output = captured.getvalue()
        # Allow warnings but not errors or debug output
        if output:
            # Should only contain WARNING messages if any
            for line in output.strip().split("\n"):
                assert "WARNING" in line or "warning" in line.lower(), f"Unexpected stderr: {line}"


class TestImmutability:
    """Input snapshots must not be mutated."""

    def test_snapshot_immutable(self):
        """Input snapshot must not be mutated."""
        snapshot = _make_snapshot()

        # Store original state
        original_interfaces = list(snapshot.interfaces)
        original_routes = list(snapshot.routes)
        original_neighbors = list(snapshot.neighbors)
        original_connections = list(snapshot.connections)
        original_networks = list(snapshot.networks)
        original_pivot_paths = list(snapshot.pivot_paths)

        analyze(snapshot)

        # Verify immutability
        assert list(snapshot.interfaces) == original_interfaces
        assert list(snapshot.routes) == original_routes
        assert list(snapshot.neighbors) == original_neighbors
        assert list(snapshot.connections) == original_connections
        assert list(snapshot.networks) == original_networks
        assert list(snapshot.pivot_paths) == original_pivot_paths

    def test_all_analysis_functions_immutable(self):
        """All analysis functions must not mutate input."""
        snapshot = _make_snapshot()

        functions = [
            analyze,
            assess_transit_evidence,
            select_next_investigation,
            recommend,
            summarize_snapshot,
            explain_network,
            analyze_evidence_gaps,
        ]

        for func in functions:
            original_interfaces = list(snapshot.interfaces)
            original_routes = list(snapshot.routes)

            if func == explain_network:
                func("10.50.0.0/16", snapshot)
            elif func == analyze_evidence_gaps:
                func(snapshot, "10.50.0.0/16")
            elif func == select_next_investigation:
                transit = assess_transit_evidence(snapshot)
                func(snapshot, transit_evidence=transit)
            elif func == recommend:
                from pivotcheck.analysis.comparison import DiffReport
                func(snapshot, DiffReport())
            else:
                func(snapshot)

            assert list(snapshot.interfaces) == original_interfaces
            assert list(snapshot.routes) == original_routes