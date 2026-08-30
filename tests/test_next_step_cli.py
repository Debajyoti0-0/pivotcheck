"""CLI integration tests for pivotcheck next command."""

import json
from datetime import datetime, timezone

import pytest

from pivotcheck import __version__
from pivotcheck.cli import (
    EXIT_BASELINE_NOT_FOUND,
    EXIT_BASELINE_SCHEMA,
    EXIT_OK,
    EXIT_USAGE,
    main,
)


def make_candidate_snapshot():
    """Deterministic snapshot with one real transit candidate.

    Passive-only evidence: a static route via 10.10.20.254, a REACHABLE
    neighbor entry for the gateway, and an ESTABLISHED TCP connection to
    the gateway (observed connection table, no active probing).
    """
    from pivotcheck.models.network import (
        Confidence,
        Connection,
        ConnectionProtocol,
        Interface,
        InterfaceState,
        Neighbor,
        PivotPath,
        Route,
        RouteType,
    )
    from pivotcheck.models.result import DiscoverySnapshot

    return DiscoverySnapshot(
        hostname="candhost",
        os_name="Linux 6.1",
        timestamp=datetime.now(timezone.utc).isoformat(),
        interfaces=(
            Interface(
                name="eth0",
                state=InterfaceState.UP,
                mac_address="aa:bb:cc:dd:ee:01",
                ipv4_addresses=(),
            ),
        ),
        routes=(
            Route("default", "10.10.20.1", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
            Route("172.16.50.0/24", "10.10.20.254", "eth0", 50, RouteType.STATIC),
        ),
        neighbors=(
            Neighbor(
                ip_address="10.10.20.254",
                interface="eth0",
                mac_address="aa:bb:cc:dd:ee:99",
                state="REACHABLE",
            ),
        ),
        connections=(
            Connection(
                protocol=ConnectionProtocol.TCP,
                local_address="10.10.20.5",
                local_port=44444,
                remote_address="10.10.20.254",
                remote_port=445,
                state="ESTABLISHED",
            ),
        ),
        pivot_paths=(
            PivotPath(
                source_interface="eth0",
                gateway="10.10.20.254",
                destination_network="172.16.50.0/24",
                confidence=Confidence.MEDIUM,
            ),
        ),
    )


class TestNextCommand:
    """Test the next command CLI integration."""

    @pytest.fixture(autouse=True)
    def _no_evidence(self, monkeypatch):
        """Mock discovery to an evidence-free snapshot.

        The ``next`` command reads the host's real routing/neighbor state;
        whether an environment yields zero candidates is not deterministic
        (e.g. a cloud runner has a default route and yields a genuine
        candidate). Contract tests here construct the input explicitly:
        an empty snapshot guarantees the no-candidate path. Tests that
        exercise the candidate-present path override this patch below.
        Zero real network I/O either way — discovery only reads local state.
        """
        from pivotcheck import cli
        from pivotcheck.models.result import DiscoverySnapshot

        monkeypatch.setattr(
            cli,
            "run_discovery",
            lambda *a, **k: DiscoverySnapshot(hostname="", os_name="", networks=()),
        )

    def test_next_help(self, capsys):
        """Test that help works."""
        with pytest.raises(SystemExit) as exc:
            main(["next", "--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "next" in out
        assert "--baseline" in out
        assert "--format" in out
        assert "--json" in out

    def test_next_no_candidates(self, capsys):
        """Test next command with no candidates."""
        code = main(["next"])
        assert code == 0
        out = capsys.readouterr().out
        assert "NO INVESTIGATION CANDIDATES" in out
        assert "No actionable evidence found" in out

    def test_next_json_output(self, capsys):
        """Test JSON output format."""
        code = main(["next", "--json"])
        assert code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["tool"] == "pivotcheck"
        assert data["version"] == __version__
        assert "timestamp" in data
        assert data["candidate"] is None
        assert data["message"] == "NO INVESTIGATION CANDIDATES"
        # No ANSI in JSON
        assert "\033[" not in out

    def test_next_format_json(self, capsys):
        """Test --format json option."""
        code = main(["next", "--format", "json"])
        assert code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["candidate"] is None

    def test_next_no_color(self, capsys):
        """Test --no-color global option."""
        code = main(["--no-color", "next"])
        assert code == 0
        out = capsys.readouterr().out
        assert "NO INVESTIGATION CANDIDATES" in out
        # No ANSI escape codes
        assert "\033[" not in out

    def test_next_verbose(self, capsys):
        """Test -v verbose option."""
        code = main(["-v", "next"])
        assert code == 0
        out = capsys.readouterr().out
        assert "NO INVESTIGATION CANDIDATES" in out

    def test_next_invalid_format(self, capsys):
        """Test invalid format option (argparse-owned usage error)."""
        # Project-wide convention: argparse usage errors raise SystemExit
        # with EXIT_USAGE; main() returns runtime exit codes only.
        with pytest.raises(SystemExit) as exc:
            main(["--format", "invalid", "next"])
        assert exc.value.code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "invalid choice" in err.lower()

    def test_next_missing_baseline(self, capsys):
        """Test missing baseline."""
        code = main(["next", "--baseline", "nonexistent"])
        assert code == EXIT_BASELINE_NOT_FOUND
        err = capsys.readouterr().err
        assert "not found" in err.lower()

    def test_next_invalid_baseline(self, capsys, tmp_path):
        """Test invalid baseline file."""
        # Create a corrupt baseline file
        (tmp_path / "corrupt.json").write_text("{not valid json", encoding="utf-8")
        code = main(["--data-dir", str(tmp_path), "next", "--baseline", "corrupt"])
        assert code == EXIT_BASELINE_SCHEMA
        err = capsys.readouterr().err
        assert "invalid" in err.lower() or "unsupported" in err.lower()

    def test_next_invalid_argument(self, capsys):
        """Test invalid argument (argparse-owned usage error)."""
        with pytest.raises(SystemExit) as exc:
            main(["next", "--invalid-arg"])
        assert exc.value.code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "unrecognized" in err.lower() or "invalid" in err.lower()

    def test_next_exit_codes(self):
        """Test exit codes."""
        # Success (no candidates is still success)
        assert main(["next"]) == 0
        # Usage error: argparse-owned, raises SystemExit(EXIT_USAGE)
        with pytest.raises(SystemExit) as exc:
            main(["next", "--invalid"])
        assert exc.value.code == EXIT_USAGE
        # Baseline not found: runtime failure, returned as an integer
        assert main(["next", "--baseline", "nonexistent"]) == EXIT_BASELINE_NOT_FOUND

    def test_next_candidate_present_text(self, monkeypatch, capsys):
        """Candidate-present path must succeed and render without crashing."""
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_candidate_snapshot)
        code = main(["next"])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "NEXT INVESTIGATION CANDIDATE" in out
        assert "172.16.50.0/24" in out
        assert "Priority: HIGH" in out
        assert "MULTIPLE_SUPPORTING_SIGNALS" in out
        # Evidence contract: no false claims of reachability or pivot capability
        assert "do not prove active reachability" in out
        assert "not validation evidence" in out

    def test_next_candidate_present_json(self, monkeypatch, capsys):
        """Candidate-present JSON must be valid, ANSI-free, and consistent."""
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_candidate_snapshot)
        code = main(["next", "--json"])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "\033[" not in out
        data = json.loads(out)
        assert data["tool"] == "pivotcheck"
        candidate = data["candidate"]
        assert candidate is not None
        assert candidate["network"] == "172.16.50.0/24"
        assert candidate["priority"] == "HIGH"
        assert candidate["transit_assessment"] == "MULTIPLE_SUPPORTING_SIGNALS"
        assert "message" not in data
        # Evidence substructure preserved
        assert candidate["observed_evidence"]["neighbor"]["state"] == "REACHABLE"
        assert candidate["observed_evidence"]["connections"]["tcp_count"] == 1

    def test_next_candidate_present_json_format_flag(self, monkeypatch, capsys):
        """--format json must behave identically to --json."""
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_candidate_snapshot)
        code = main(["next", "--format", "json"])
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["candidate"]["priority"] == "HIGH"

    def test_next_candidate_present_no_color(self, monkeypatch, capsys):
        """Global --no-color must suppress ANSI even with a candidate."""
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_candidate_snapshot)
        code = main(["--no-color", "next"])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "\033[" not in out
        assert "NEXT INVESTIGATION CANDIDATE" in out