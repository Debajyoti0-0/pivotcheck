"""Tests for JSON output and CLI behavior (args, exit codes, formats)."""

import json

import pytest

from pivotcheck.cli import EXIT_FATAL, EXIT_OK, EXIT_USAGE, main
from pivotcheck.models.network import Interface, InterfaceState, IPAddress
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.output.json import snapshot_to_string


def make_snapshot() -> DiscoverySnapshot:
    return DiscoverySnapshot(
        hostname="jsonhost",
        os_name="Linux 6.1",
        interfaces=(
            Interface(
                name="eth0",
                state=InterfaceState.UP,
                ipv4_addresses=(IPAddress("10.10.20.15", 24),),
            ),
        ),
    )


class TestJsonOutput:
    def test_valid_json_with_required_fields(self):
        doc = json.loads(snapshot_to_string(make_snapshot()))
        assert doc["tool"] == "pivotcheck"
        assert doc["version"]
        assert doc["timestamp"]
        assert doc["hostname"] == "jsonhost"
        assert isinstance(doc["interfaces"], list)
        assert isinstance(doc["warnings"], list)

    def test_no_ansi_in_json(self):
        text = snapshot_to_string(make_snapshot())
        assert "\033[" not in text

    def test_schema_keys_stable(self):
        doc = json.loads(snapshot_to_string(make_snapshot()))
        expected = {
            "tool", "version", "timestamp", "hostname", "os",
            "interfaces", "routes", "neighbors", "dns", "connections",
            "networks", "pivot_paths", "warnings", "session",
        }
        assert set(doc) == expected


class TestCli:
    def _run(self, argv, monkeypatch, capsys=None):
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_snapshot)
        return main(argv)

    def test_discover_text_ok(self, monkeypatch, capsys):
        assert self._run(["discover"], monkeypatch) == EXIT_OK

    def test_map_ok(self, monkeypatch, capsys):
        assert self._run(["map"], monkeypatch) == EXIT_OK

    def test_map_json_is_presentation_oriented(self, monkeypatch, capsys):
        assert self._run(["map", "--format", "json"], monkeypatch) == EXIT_OK
        document = json.loads(capsys.readouterr().out)
        assert "map" in document
        assert "current_connected" in document["map"]

    def test_discover_json_flag(self, monkeypatch, capsys):
        code = self._run(["discover", "--json"], monkeypatch)
        assert code == EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        assert doc["tool"] == "pivotcheck"

    def test_discover_format_json(self, monkeypatch, capsys):
        code = self._run(["discover", "--format", "json"], monkeypatch)
        assert code == EXIT_OK
        doc = json.loads(capsys.readouterr().out)
        assert doc["hostname"] == "jsonhost"

    def test_json_and_format_mutually_exclusive(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["discover", "--json", "--format", "text"])
        assert exc.value.code == EXIT_USAGE

    def test_no_command_shows_help_usage_error(self, monkeypatch, capsys):
        assert main([]) == EXIT_USAGE

    def test_version_flag(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "pivotcheck" in capsys.readouterr().out

    def test_help_flag(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "discover" in out
        assert "map" in out

    def test_fatal_engine_failure_exit_1(self, monkeypatch, capsys):
        from pivotcheck import cli

        def boom():
            raise RuntimeError("no /proc available")

        monkeypatch.setattr(cli, "run_discovery", boom)
        assert main(["discover"]) == EXIT_FATAL
        err = capsys.readouterr().err
        assert "Unable to perform network discovery" in err
        assert "no /proc available" in err

    def test_invalid_subcommand_exit_2(self, monkeypatch, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["bogus-command"])
        assert exc.value.code == EXIT_USAGE

    def test_json_output_has_no_color_codes_even_on_tty_like_stream(
        self, monkeypatch, capsys
    ):
        self._run(["discover", "--format", "json"], monkeypatch)
        out = capsys.readouterr().out
        assert "\033[" not in out
