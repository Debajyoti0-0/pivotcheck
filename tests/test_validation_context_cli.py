"""CLI integration tests for validation context linking (--baseline flag)."""

import json
import socket
import threading

import pytest

from pivotcheck import cli
from pivotcheck.cli import (
    EXIT_BASELINE_NOT_FOUND,
    EXIT_BASELINE_SCHEMA,
    EXIT_OK,
    EXIT_RESOLVE,
    EXIT_USAGE,
    main,
)
from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def net(cidr, origin, gateway=None, interface="eth0"):
    return DiscoveredNetwork(
        cidr=cidr,
        origin=origin,
        confidence=(
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


def make_snapshot():
    return snapshot(net("127.0.0.0/8", NetworkOrigin.CONNECTED))


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


class TestCheckCliContextual:
    def test_legacy_check_unchanged(self, patch_discovery, capsys):
        """Legacy check without --baseline must behave exactly as before."""
        with _Listener() as listener:
            code = main(["check", "127.0.0.1", "--port", str(listener.port)])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "SUCCESS" in out
        assert "NETWORK CONTEXT" not in out  # no contextual sections
        assert "COMPARISON CONTEXT" not in out

    def test_legacy_json_unchanged(self, patch_discovery, capsys):
        with _Listener() as listener:
            code = main(
                ["check", "127.0.0.1", "--port", str(listener.port), "--format", "json"]
            )
        assert code == EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        assert "validation_context" not in doc

    def test_check_with_baseline_context(self, patch_discovery, capsys, tmp_path):
        # Create a baseline that does NOT contain 127.0.0.0/8 so the
        # comparison reports NEW_COVERAGE.
        store = cli.BaselineStore(tmp_path)
        store.create(
            "workstation",
            baseline(baseline_network("10.0.0.0/8", NetworkOrigin.ROUTED)),
        )
        with _Listener() as listener:
            code = main(
                [
                    "--data-dir",
                    str(tmp_path),
                    "check",
                    "127.0.0.1",
                    "--port",
                    str(listener.port),
                    "--baseline",
                    "workstation",
                ]
            )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "SUCCESS" in out
        assert "NETWORK CONTEXT" in out
        assert "COMPARISON CONTEXT" in out
        assert "Baseline: workstation" in out
        assert "NEW_COVERAGE" in out

    def test_check_with_baseline_json(self, patch_discovery, capsys, tmp_path):
        store = cli.BaselineStore(tmp_path)
        store.create(
            "workstation",
            baseline(baseline_network("10.0.0.0/8", NetworkOrigin.ROUTED)),
        )
        with _Listener() as listener:
            code = main(
                [
                    "--data-dir",
                    str(tmp_path),
                    "check",
                    "127.0.0.1",
                    "--port",
                    str(listener.port),
                    "--baseline",
                    "workstation",
                    "--format",
                    "json",
                ]
            )
        assert code == EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        assert "validation_context" in doc
        vctx = doc["validation_context"]
        assert vctx["target"] == "127.0.0.1"
        assert vctx["network_context"]["matched_network"]["network"] == "127.0.0.0/8"
        assert vctx["comparison_context"]["baseline"] == "workstation"
        assert vctx["comparison_context"]["relationship"] == "NEW"
        assert "\033[" not in json.dumps(doc)

    def test_missing_baseline_fails_explicitly(self, patch_discovery, capsys, tmp_path):
        """Requested baseline that does not exist must fail, not silently
        perform an uncontextualized check."""
        with _Listener() as listener:
            code = main(
                [
                    "--data-dir",
                    str(tmp_path),
                    "check",
                    "127.0.0.1",
                    "--port",
                    str(listener.port),
                    "--baseline",
                    "nonexistent",
                ]
            )
        assert code == EXIT_BASELINE_NOT_FOUND
        err = capsys.readouterr().err
        assert "baseline not found" in err

    def test_invalid_baseline_fails_explicitly(self, patch_discovery, capsys, tmp_path):
        # Write a corrupt baseline file.
        (tmp_path / "corrupt.json").write_text("{not valid json", encoding="utf-8")
        with _Listener() as listener:
            code = main(
                [
                    "--data-dir",
                    str(tmp_path),
                    "check",
                    "127.0.0.1",
                    "--port",
                    str(listener.port),
                    "--baseline",
                    "corrupt",
                ]
            )
        assert code == EXIT_BASELINE_SCHEMA
        err = capsys.readouterr().err
        assert "invalid" in err or "Unsupported" in err

    def test_no_duplicate_discovery(self, patch_discovery, monkeypatch, capsys, tmp_path):
        """The same snapshot must feed route context, comparison, and
        priority — discovery runs exactly once."""
        calls = []

        def counting_discovery():
            calls.append(1)
            return make_snapshot()

        monkeypatch.setattr(cli, "run_discovery", counting_discovery)
        store = cli.BaselineStore(tmp_path)
        store.create(
            "workstation",
            baseline(baseline_network("10.0.0.0/8", NetworkOrigin.ROUTED)),
        )
        with _Listener() as listener:
            code = main(
                [
                    "--data-dir",
                    str(tmp_path),
                    "check",
                    "127.0.0.1",
                    "--port",
                    str(listener.port),
                    "--baseline",
                    "workstation",
                ]
            )
        assert code == EXIT_OK
        assert len(calls) == 1  # exactly one discovery

    def test_priority_context_rendered(self, patch_discovery, capsys, tmp_path):
        """When the target's network has a HIGH recommendation, the
        operator priority context must be shown."""
        store = cli.BaselineStore(tmp_path)
        store.create(
            "workstation",
            baseline(baseline_network("10.0.0.0/8", NetworkOrigin.ROUTED)),
        )
        with _Listener() as listener:
            code = main(
                [
                    "--data-dir",
                    str(tmp_path),
                    "check",
                    "127.0.0.1",
                    "--port",
                    str(listener.port),
                    "--baseline",
                    "workstation",
                ]
            )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        # 127.0.0.0/8 is new connected high-confidence coverage -> HIGH.
        assert "OPERATOR PRIORITY CONTEXT" in out
        assert "HIGH" in out
        assert "prioritization context, not validation evidence" in out

    def test_exit_codes_preserved(self, patch_discovery, capsys):
        # Invalid port still usage error even with --baseline.
        code = main(["check", "127.0.0.1", "--port", "0", "--baseline", "x"])
        assert code == EXIT_USAGE

    def test_dns_failure_still_exit_3(self, patch_discovery, monkeypatch, capsys):
        def fake_resolve(target):
            from pivotcheck.models.check import ResolvedTarget

            return ResolvedTarget(
                original=target, addresses=(), error="name resolution failed"
            )

        monkeypatch.setattr(cli, "resolve_target", fake_resolve)
        code = main(["check", "nonexistent.invalid", "--port", "445"])
        assert code == EXIT_RESOLVE

    def test_multi_address_context_is_deterministic(
        self, patch_discovery, monkeypatch, capsys, tmp_path
    ):
        """A target resolving to multiple addresses must attach the FIRST
        resolved address's context deterministically — not whichever address
        happened to be validated last (regression for the per-address
        validation_context overwrite)."""
        from pivotcheck.models.check import CheckResult, CheckStatus, ResolvedTarget

        monkeypatch.setattr(
            cli,
            "resolve_target",
            lambda target: ResolvedTarget(
                original=target, addresses=("10.10.0.1", "10.10.0.2")
            ),
        )
        # Keep the test hermetic: no real packets leave the machine.
        monkeypatch.setattr(
            cli,
            "check_tcp",
            lambda address, port, timeout, target=None: CheckResult(
                target=target, address=address, port=port, status=CheckStatus.TIMEOUT
            ),
        )
        store = cli.BaselineStore(tmp_path)
        store.create(
            "workstation",
            baseline(baseline_network("192.168.0.0/16", NetworkOrigin.ROUTED)),
        )
        code = main(
            [
                "--data-dir",
                str(tmp_path),
                "check",
                "host.internal",
                "--port",
                "445",
                "--baseline",
                "workstation",
                "--format",
                "json",
            ]
        )
        assert code == EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        # Exactly one validation context, describing the FIRST resolved address.
        assert doc["validation_context"]["target"] == "10.10.0.1"
        # Both addresses were still validated (per-result data preserved).
        assert {r["address"] for r in doc["results"]} == {"10.10.0.1", "10.10.0.2"}