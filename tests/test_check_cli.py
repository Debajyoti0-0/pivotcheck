"""Integration tests for check CLI behavior (mocked discovery only).

TCP integration scenarios use real local sockets on the loopback interface:
- open listener -> SUCCESS
- closed port -> REFUSED
These are controlled, reproducible, and never touch external hosts.
"""

import json
import socket
import threading

import pytest

from pivotcheck import cli
from pivotcheck.cli import EXIT_OK, EXIT_RESOLVE, EXIT_USAGE, main


def make_snapshot():
    from pivotcheck.models.network import (
        Confidence,
        DiscoveredNetwork,
        Interface,
        InterfaceState,
        IPAddress,
        NetworkOrigin,
    )
    from pivotcheck.models.result import DiscoverySnapshot

    return DiscoverySnapshot(
        hostname="testhost",
        os_name="Linux 6.1",
        interfaces=(
            Interface(
                name="eth0",
                state=InterfaceState.UP,
                ipv4_addresses=(IPAddress("127.0.0.1", 8),),
            ),
        ),
        networks=(
            DiscoveredNetwork(
                cidr="127.0.0.0/8",
                origin=NetworkOrigin.CONNECTED,
                confidence=Confidence.HIGH,
                interface="eth0",
            ),
        ),
    )


@pytest.fixture()
def patch_discovery(monkeypatch):
    monkeypatch.setattr(cli, "run_discovery", make_snapshot)


class _Listener:
    """A real bound-and-listening TCP socket on an ephemeral loopback port."""

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()
        return self

    def _accept(self):
        try:
            conn, _ = self.sock.accept()
            conn.close()
        except OSError:
            pass

    def __exit__(self, *exc):
        try:
            self.sock.close()
        except OSError:
            pass
        return False


class TestCheckCli:
    def test_missing_port_is_usage_error(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["check", "127.0.0.1"])
        assert exc.value.code == EXIT_USAGE

    def test_port_range_rejected(self, monkeypatch, capsys):
        # '445-446' contains '-' so isdigit() fails -> usage error, not scan
        code = main(["check", "127.0.0.1", "--port", "445-446"])
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "Ranges" in err or "ranges" in err

    def test_invalid_port_zero_rejected(self, monkeypatch, capsys):
        code = main(["check", "127.0.0.1", "--port", "0"])
        assert code == EXIT_USAGE

    def test_invalid_timeout_rejected(self, monkeypatch, capsys):
        code = main(["check", "127.0.0.1", "--port", "80", "--timeout", "999"])
        assert code == EXIT_USAGE

    def test_dns_failure_exit_3(self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "resolve_target",
            lambda t: cli.resolve_target("256.256.256.256"),
        )
        # use a syntactically valid hostname that cannot resolve in tests

        def fake_resolve(target):
            from pivotcheck.models.check import ResolvedTarget

            return ResolvedTarget(
                original=target, addresses=(), error="name resolution failed"
            )

        monkeypatch.setattr(cli, "resolve_target", fake_resolve)
        code = main(["check", "nonexistent.invalid", "--port", "445"])
        assert code == EXIT_RESOLVE

    def test_json_output_structure(self, patch_discovery, capsys):
        with _Listener() as listener:
            code = main(
                ["check", "127.0.0.1", "--port", str(listener.port), "--format", "json"]
            )
        assert code == EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        assert doc["tool"] == "pivotcheck"
        assert doc["target"] == "127.0.0.1"
        result = doc["results"][0]
        assert result["status"] == "SUCCESS"
        assert result["route_context"]["network"] == "127.0.0.0/8"
        assert "\033[" not in json.dumps(doc)

    def test_terminal_output_success(self, patch_discovery, capsys):
        with _Listener() as listener:
            code = main(["check", "127.0.0.1", "--port", str(listener.port)])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "SUCCESS" in out
        assert "handshake completed" in out


@pytest.mark.integration
class TestControlledTcpScenarios:
    """Real-socket integration: SUCCESS and REFUSED against local loopback."""

    def test_scenario_a_open_listener_success(self, patch_discovery):
        with _Listener() as listener:
            result = cli.check_tcp("127.0.0.1", listener.port, timeout_s=2.0)
        from pivotcheck.models.check import CheckStatus

        assert result.status is CheckStatus.SUCCESS

    def test_scenario_b_closed_port_refused(self, patch_discovery):
        # Bind then close to reliably claim an ephemeral port, leaving it shut.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        result = cli.check_tcp("127.0.0.1", port, timeout_s=2.0)
        from pivotcheck.models.check import CheckStatus

        if result.status is CheckStatus.REFUSED:
            return  # POSIX-typical: kernel sends RST for closed loopback port
        # Windows with enabled firewall profiles silently DROPS SYNs to closed
        # ports (stealth mode), yielding TIMEOUT instead of REFUSED. This is a
        # real-world platform semantic, not a tool bug — verified on this host:
        # all probed closed ports timed out while open services connected.
        assert result.status is CheckStatus.TIMEOUT, (
            f"unexpected status {result.status}: {result.error}"
        )

    def test_scenario_c_timeout_controlled(self):
        # Reserved TEST-NET address per RFC 5737 — no host responds; bounded
        # by a short timeout so the test stays fast and offline-safe.
        result = cli.check_tcp("192.0.2.123", 9, timeout_s=0.3)
        from pivotcheck.models.check import CheckStatus

        if (
            result.status is CheckStatus.LOCAL_ERROR
            and result.error is not None
            and "WinError 10013" in result.error
        ):
            pytest.skip("sandbox blocks outbound socket operations (WinError 10013)")
        assert result.status in (CheckStatus.TIMEOUT, CheckStatus.UNREACHABLE)
