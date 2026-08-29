"""CLI workflow tests using fake discovery providers."""

import json

from pivotcheck.discovery.provider import CollectedDiscoveryData
from pivotcheck.models.network import Interface, InterfaceState, IPAddress
from pivotcheck.models.session import SessionIdentity


class FakeProvider:
    def __init__(self, session, address):
        self.session = session
        self.address = address

    def get_session(self):
        return self.session

    def collect(self):
        return CollectedDiscoveryData(
            "host",
            "OS",
            interfaces=(
                Interface(
                    "eth0",
                    InterfaceState.UP,
                    ipv4_addresses=(IPAddress(self.address, 24),),
                ),
            ),
        )


def test_baseline_create_list_show_delete_json(monkeypatch, capsys, tmp_path):
    from pivotcheck import cli

    monkeypatch.setattr(
        cli,
        "run_discovery",
        lambda: __import__(
            "pivotcheck.discovery.engine", fromlist=["run_discovery"]
        ).run_discovery(FakeProvider(SessionIdentity("a", "fake", "A"), "10.10.0.1")),
    )
    base = ["--data-dir", str(tmp_path), "baseline"]
    assert cli.main([*base, "create", "--name", "Workstation"]) == 0
    capsys.readouterr()
    assert cli.main([*base, "list", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["baselines"][0]["name"] == "workstation"
    assert cli.main([*base, "show", "workstation", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["name"] == "workstation"
    assert cli.main([*base, "delete", "workstation"]) == 2
    assert cli.main([*base, "delete", "workstation", "--yes"]) == 0


def test_compare_renders_new_coverage_and_json(monkeypatch, capsys, tmp_path):
    from pivotcheck import cli

    baseline_provider = FakeProvider(SessionIdentity("a", "fake", "A"), "10.10.0.1")
    current_provider = FakeProvider(SessionIdentity("b", "fake", "B"), "172.16.50.1")
    monkeypatch.setattr(
        cli,
        "run_discovery",
        lambda: __import__(
            "pivotcheck.discovery.engine", fromlist=["run_discovery"]
        ).run_discovery(baseline_provider),
    )
    base = ["--data-dir", str(tmp_path)]
    assert cli.main([*base, "baseline", "create", "--name", "workstation"]) == 0
    capsys.readouterr()
    monkeypatch.setattr(
        cli,
        "run_discovery",
        lambda: __import__(
            "pivotcheck.discovery.engine", fromlist=["run_discovery"]
        ).run_discovery(current_provider),
    )
    assert cli.main([*base, "compare", "workstation", "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["comparison"]["new_reachability"][0]["network"] == "172.16.50.0/24"


def test_compare_missing_baseline_has_distinct_exit(tmp_path):
    from pivotcheck import cli

    assert cli.main(["--data-dir", str(tmp_path), "compare", "missing"]) == 3


def test_map_with_baseline_renders_delta_json(monkeypatch, capsys, tmp_path):
    from pivotcheck import cli

    baseline_provider = FakeProvider(SessionIdentity("a", "fake", "A"), "10.10.0.1")
    current_provider = FakeProvider(SessionIdentity("b", "fake", "B"), "172.16.50.1")
    monkeypatch.setattr(
        cli,
        "run_discovery",
        lambda: __import__(
            "pivotcheck.discovery.engine", fromlist=["run_discovery"]
        ).run_discovery(baseline_provider),
    )
    base = ["--data-dir", str(tmp_path)]
    assert cli.main([*base, "baseline", "create", "--name", "workstation"]) == 0
    capsys.readouterr()
    monkeypatch.setattr(
        cli,
        "run_discovery",
        lambda: __import__(
            "pivotcheck.discovery.engine", fromlist=["run_discovery"]
        ).run_discovery(current_provider),
    )
    assert (
        cli.main([*base, "map", "--baseline", "workstation", "--format", "json"]) == 0
    )
    document = json.loads(capsys.readouterr().out)
    assert document["baseline"]["name"] == "workstation"
    assert document["map"]["new_coverage"][0]["network"] == "172.16.50.0/24"


def test_map_with_missing_baseline_has_distinct_exit(tmp_path):
    from pivotcheck import cli

    assert cli.main(["--data-dir", str(tmp_path), "map", "--baseline", "missing"]) == 3
