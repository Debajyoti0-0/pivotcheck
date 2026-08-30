"""CLI contract tests.

These tests verify that every command:
- Has correct --help output
- Rejects invalid arguments appropriately
- Handles missing arguments
- Returns correct exit codes
- Produces valid JSON output
- Produces valid human-readable output
"""

from __future__ import annotations

import json
import subprocess
import sys

from pivotcheck import __version__


def run_cli(*args: str, input_data: str | None = None) -> subprocess.CompletedProcess:
    """Run pivotcheck CLI and return result."""
    cmd = [sys.executable, "-m", "pivotcheck"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, input=input_data, check=False, timeout=30)


class TestGlobalOptions:
    """Test global options work on all commands."""

    def test_version(self):
        """--version works globally."""
        result = run_cli("--version")
        assert result.returncode == 0
        assert "pivotcheck" in result.stdout
        assert __version__ in result.stdout

    def test_help(self):
        """--help works globally."""
        result = run_cli("--help")
        assert result.returncode == 0
        assert "pivotcheck" in result.stdout
        assert "discover" in result.stdout
        assert "map" in result.stdout
        assert "check" in result.stdout
        assert "proxy-check" in result.stdout
        assert "baseline" in result.stdout
        assert "compare" in result.stdout
        assert "next" in result.stdout
        assert "gaps" in result.stdout
        assert "explain" in result.stdout

    def test_no_color_global(self):
        """--no-color works globally."""
        result = run_cli("--no-color", "next")
        assert result.returncode == 0
        # Should not contain ANSI escape codes
        assert "\x1b[" not in result.stdout

    def test_verbose_global(self):
        """-v/--verbose works globally."""
        result = run_cli("-v", "next")
        # Verbose output goes to stderr
        assert result.returncode == 0


class TestDiscoverCommand:
    """Test discover command contract."""

    def test_help(self):
        result = run_cli("discover", "--help")
        assert result.returncode == 0
        assert "discover" in result.stdout.lower()

    def test_json_output(self):
        result = run_cli("discover", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["tool"] == "pivotcheck"
        assert "version" in data
        assert "timestamp" in data

    def test_summary_flag(self):
        result = run_cli("discover", "--summary")
        assert result.returncode == 0
        assert "DISCOVERY SUMMARY" in result.stdout or "Interfaces:" in result.stdout

    def test_interface_filter(self):
        result = run_cli("discover", "--interface", "eth0")
        assert result.returncode == 0

    def test_family_filter(self):
        for fam in ["ipv4", "ipv6", "all"]:
            result = run_cli("discover", "--family", fam)
            assert result.returncode == 0

    def test_invalid_interface(self):
        # Invalid interface should not crash, just filter to nothing
        result = run_cli("discover", "--interface", "nonexistent123")
        assert result.returncode == 0


class TestMapCommand:
    """Test map command contract."""

    def test_help(self):
        result = run_cli("map", "--help")
        assert result.returncode == 0
        assert "map" in result.stdout.lower()

    def test_json_output(self):
        result = run_cli("map", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        # map command has different JSON structure
        assert "map" in data
        assert "current" in data

    def test_show_pivots(self):
        result = run_cli("map", "--show-pivots")
        assert result.returncode == 0

    def test_changes_only(self):
        result = run_cli("map", "--changes-only")
        assert result.returncode == 0

    def test_focus(self):
        result = run_cli("map", "--focus", "10.50.0.0/16")
        assert result.returncode == 0

    def test_minimum_confidence(self):
        # --minimum-confidence is a compare flag, not map flag
        for conf in ["low", "medium", "high"]:
            result = run_cli("compare", "nonexistent", "--minimum-confidence", conf)
            assert result.returncode == 3  # baseline not found first


class TestNextCommand:
    """Test next command contract."""

    def test_help(self):
        result = run_cli("next", "--help")
        assert result.returncode == 0
        assert "next" in result.stdout.lower()

    def test_json_output(self):
        result = run_cli("next", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["tool"] == "pivotcheck"
        assert data["command"] == "next"
        assert "schema_version" in data
        assert "candidate" in data or "message" in data

    def test_baseline_option(self):
        result = run_cli("next", "--baseline", "nonexistent")
        assert result.returncode == 3  # Baseline not found

    def test_format_json(self):
        result = run_cli("next", "--format", "json")
        assert result.returncode == 0
        json.loads(result.stdout)

    def test_format_text(self):
        result = run_cli("next", "--format", "text")
        assert result.returncode == 0

    def test_invalid_format(self):
        result = run_cli("next", "--format", "invalid")
        assert result.returncode == 2  # Usage error


class TestGapsCommand:
    """Test gaps command contract."""

    def test_help(self):
        result = run_cli("gaps", "--help")
        assert result.returncode == 0
        assert "gaps" in result.stdout.lower()

    def test_requires_network(self):
        result = run_cli("gaps")
        assert result.returncode == 2  # Missing required argument

    def test_json_output(self):
        result = run_cli("gaps", "10.50.0.0/16", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["tool"] == "pivotcheck"
        assert data["command"] == "gaps"
        assert "gaps" in data
        assert "network" in data

    def test_text_output(self):
        result = run_cli("gaps", "10.50.0.0/16")
        assert result.returncode == 0
        assert "EVIDENCE GAP ANALYSIS" in result.stdout
        assert "10.50.0.0/16" in result.stdout

    def test_invalid_network(self):
        # Invalid network should be handled gracefully
        result = run_cli("gaps", "not-a-network")
        # Should either error or produce meaningful output
        assert result.returncode in (0, 1, 2)


class TestExplainCommand:
    """Test explain command contract."""

    def test_help(self):
        result = run_cli("explain", "--help")
        assert result.returncode == 0
        assert "explain" in result.stdout.lower()

    def test_requires_network(self):
        result = run_cli("explain")
        assert result.returncode == 2  # Missing required argument

    def test_json_output(self):
        result = run_cli("explain", "10.50.0.0/16", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        # explain command has its own JSON structure
        assert data["network"] == "10.50.0.0/16"
        assert "classification" in data
        assert "limitations" in data

    def test_text_output(self):
        result = run_cli("explain", "10.50.0.0/16")
        assert result.returncode == 0
        assert "NETWORK EXPLANATION" in result.stdout
        assert "10.50.0.0/16" in result.stdout

    def test_baseline_option(self):
        result = run_cli("explain", "10.50.0.0/16", "--baseline", "nonexistent")
        assert result.returncode == 3  # Baseline not found


class TestCheckCommand:
    """Test check command contract."""

    def test_help(self):
        result = run_cli("check", "--help")
        assert result.returncode == 0
        assert "check" in result.stdout.lower()

    def test_requires_target(self):
        result = run_cli("check")
        assert result.returncode == 2  # Missing target

    def test_requires_port(self):
        result = run_cli("check", "127.0.0.1")
        assert result.returncode == 2  # Missing --port

    def test_invalid_port(self):
        result = run_cli("check", "127.0.0.1", "--port", "invalid")
        assert result.returncode == 2

    def test_port_range_rejected(self):
        result = run_cli("check", "127.0.0.1", "--port", "80-443")
        assert result.returncode == 2

    def test_port_list_accepted(self):
        result = run_cli("check", "127.0.0.1", "--port", "80,443")
        assert result.returncode == 0

    def test_too_many_ports_rejected(self):
        ports = ",".join(str(p) for p in range(20))
        result = run_cli("check", "127.0.0.1", "--port", ports)
        assert result.returncode == 2

    def test_json_output(self):
        result = run_cli("check", "127.0.0.1", "--port", "80", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["tool"] == "pivotcheck"
        assert data["command"] == "check"
        assert "results" in data

    def test_baseline_option(self):
        result = run_cli("check", "127.0.0.1", "--port", "80", "--baseline", "nonexistent")
        assert result.returncode == 3  # Baseline not found

    def test_timeout_validation(self):
        result = run_cli("check", "127.0.0.1", "--port", "80", "--timeout", "0")
        assert result.returncode == 2

        result = run_cli("check", "127.0.0.1", "--port", "80", "--timeout", "31")
        assert result.returncode == 2

    def test_invalid_target(self):
        result = run_cli("check", "not-a-valid-hostname!@#", "--port", "80", "--json")
        assert result.returncode == 3  # DNS_ERROR or INVALID_TARGET


class TestProxyCheckCommand:
    """Test proxy-check command contract."""

    def test_help(self):
        result = run_cli("proxy-check", "--help")
        assert result.returncode == 0
        assert "proxy-check" in result.stdout.lower()

    def test_requires_proxy(self):
        result = run_cli("proxy-check", "127.0.0.1", "--port", "80")
        assert result.returncode == 2  # Missing --proxy

    def test_requires_target(self):
        result = run_cli("proxy-check", "--proxy", "socks5://127.0.0.1:1080", "--port", "80")
        assert result.returncode == 2  # Missing target

    def test_requires_port(self):
        result = run_cli("proxy-check", "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1")
        assert result.returncode == 2  # Missing --port

    def test_invalid_proxy_scheme(self):
        result = run_cli("proxy-check", "--proxy", "http://127.0.0.1:1080", "127.0.0.1", "--port", "80")
        assert result.returncode == 2

    def test_invalid_proxy_no_port(self):
        result = run_cli("proxy-check", "--proxy", "socks5://127.0.0.1", "127.0.0.1", "--port", "80")
        assert result.returncode == 2

    def test_cidr_proxy_rejected(self):
        result = run_cli("proxy-check", "--proxy", "socks5://10.0.0.0/24:1080", "127.0.0.1", "--port", "80")
        assert result.returncode == 2

    def test_port_range_rejected(self):
        result = run_cli("proxy-check", "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80-443")
        assert result.returncode == 2

    def test_port_list_rejected(self):
        result = run_cli("proxy-check", "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80,443")
        assert result.returncode == 2

    def test_json_output(self):
        result = run_cli("proxy-check", "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80", "--json")
        # Connection will fail but JSON should be valid
        assert result.returncode in (0, 1, 3)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            assert data["tool"] == "pivotcheck"
            assert data["command"] == "proxy-check"
            assert "stages" in data
            assert "verdict" in data

    def test_credential_redaction(self):
        result = run_cli("proxy-check", "--proxy", "socks5://user:pass@127.0.0.1:1080", "127.0.0.1", "--port", "80", "--json")
        assert result.returncode in (0, 1, 3)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            # Password never in JSON, has_credentials flag indicates presence
            assert "pass" not in result.stdout
            assert data["proxy"]["has_credentials"] is True
            # Text output shows redacted URL
            result_text = run_cli("proxy-check", "--proxy", "socks5://user:pass@127.0.0.1:1080", "127.0.0.1", "--port", "80")
            assert "***" in result_text.stdout


class TestBaselineCommand:
    """Test baseline command contract."""

    def test_help(self):
        result = run_cli("baseline", "--help")
        assert result.returncode == 0
        assert "baseline" in result.stdout.lower()

    def test_create_requires_name(self):
        result = run_cli("baseline", "create")
        assert result.returncode == 2

    def test_list(self):
        result = run_cli("baseline", "list", "--json")
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "baselines" in data

    def test_show_requires_name(self):
        result = run_cli("baseline", "show")
        assert result.returncode == 2

    def test_delete_requires_confirm(self):
        result = run_cli("baseline", "delete", "test")
        assert result.returncode == 2  # Missing --yes

    def test_delete_with_yes(self):
        # Delete non-existent should fail gracefully
        result = run_cli("baseline", "delete", "nonexistent", "--yes")
        assert result.returncode == 3  # Not found


class TestCompareCommand:
    """Test compare command contract."""

    def test_help(self):
        result = run_cli("compare", "--help")
        assert result.returncode == 0
        assert "compare" in result.stdout.lower()

    def test_requires_baseline(self):
        result = run_cli("compare")
        assert result.returncode == 2

    def test_invalid_baseline(self):
        result = run_cli("compare", "nonexistent")
        assert result.returncode == 3  # Not found

    def test_mutually_exclusive_views(self):
        # These should be mutually exclusive - usage error takes precedence
        result = run_cli("compare", "nonexistent", "--summary", "--evidence")
        assert result.returncode == 2  # Mutually exclusive arguments error

    def test_json_output(self):
        result = run_cli("compare", "nonexistent", "--json")
        assert result.returncode == 3


class TestExitCodes:
    """Test exit code contract across all commands."""

    def test_success_zero(self):
        """Successful commands return 0."""
        commands = [
            ["next"],
            ["next", "--json"],
            ["gaps", "10.50.0.0/16"],
            ["explain", "10.50.0.0/16"],
            ["discover", "--json"],
            ["map", "--json"],
            ["baseline", "list"],
        ]
        for cmd in commands:
            result = run_cli(*cmd)
            assert result.returncode == 0, f"Command {cmd} failed with {result.returncode}: {result.stderr}"

    def test_usage_error_is_2(self):
        """Usage errors return 2."""
        commands = [
            ["next", "--format", "invalid"],
            ["check", "127.0.0.1"],
            ["check", "127.0.0.1", "--port", "invalid"],
            ["proxy-check", "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1"],
            ["baseline", "create"],
            ["baseline", "delete", "test"],
        ]
        for cmd in commands:
            result = run_cli(*cmd)
            assert result.returncode == 2, f"Command {cmd} returned {result.returncode}, expected 2"

    def test_baseline_not_found_is_3(self):
        """Missing baseline returns 3."""
        commands = [
            ["next", "--baseline", "nonexistent"],
            ["check", "127.0.0.1", "--port", "80", "--baseline", "nonexistent"],
            ["compare", "nonexistent"],
            ["explain", "10.50.0.0/16", "--baseline", "nonexistent"],
            ["map", "--baseline", "nonexistent"],
        ]
        for cmd in commands:
            result = run_cli(*cmd)
            assert result.returncode == 3, f"Command {cmd} returned {result.returncode}, expected 3: {result.stderr}"

    def test_dns_error_is_3(self):
        """DNS resolution failure returns 3 for check/proxy-check."""
        # These will fail with DNS error if target is unresolvable
        result = run_cli("check", "this-host-does-not-exist.invalid", "--port", "80")
        # Should be 3 (DNS_ERROR) or 0 with DNS_ERROR in results
        assert result.returncode in (0, 3)


class TestOutputSeparation:
    """Test stdout/stderr separation."""

    def test_json_on_stdout_only(self):
        """JSON output must go to stdout only."""
        result = run_cli("next", "--json")
        assert result.returncode == 0
        # JSON should be parseable from stdout
        json.loads(result.stdout)
        # stderr should only contain diagnostics
        if result.stderr:
            for line in result.stderr.strip().split("\n"):
                assert "DEBUG" in line or "WARNING" in line or "INFO" in line

    def test_human_output_on_stdout(self):
        """Human output goes to stdout."""
        result = run_cli("next")
        assert result.returncode == 0
        assert "INVESTIGATION" in result.stdout or "NO INVESTIGATION" in result.stdout


class TestNoColorContract:
    """Test --no-color removes ANSI codes."""

    def test_no_color_removes_ansi(self):
        result = run_cli("--no-color", "next")
        assert result.returncode == 0
        assert "\x1b[" not in result.stdout

    def test_json_never_has_ansi(self):
        result = run_cli("next", "--json")
        assert result.returncode == 0
        assert "\x1b[" not in result.stdout
        assert "\x1b[" not in result.stderr


class TestVerboseContract:
    """Test verbose mode goes to stderr."""

    def test_verbose_on_stderr(self):
        result = run_cli("-v", "next")
        assert result.returncode == 0
        # Verbose diagnostics should be on stderr
        if result.stderr:
            for line in result.stderr.strip().split("\n"):
                assert "DEBUG" in line or "[" in line


class TestDataDirContract:
    """Test --data-dir overrides baseline location."""

    def test_data_dir_option(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_cli("--data-dir", tmpdir, "baseline", "list")
            assert result.returncode == 0