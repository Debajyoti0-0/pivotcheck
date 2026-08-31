"""CLI-level tests for operator intelligence controls.

Covers: compare views (--summary/--evidence/--recommend/--explain),
filters (--interface/--family/--changes-only/--minimum-confidence),
map --show-pivots/--focus, discover --summary, and --output/--force
artifact behavior. Discovery is faked; no network access occurs.
"""

import json

import pytest

from pivotcheck.cli import EXIT_OK, EXIT_USAGE, main
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
    PivotPath,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.session import SessionIdentity


def make_snapshot() -> DiscoverySnapshot:
    return DiscoverySnapshot(
        hostname="ophost",
        os_name="Linux 6.1",
        routes=(
            Route("10.50.0.0/16", "10.10.20.1", "tun0", route_type=RouteType.STATIC),
        ),
        networks=(
            DiscoveredNetwork(
                "10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"
            ),
            DiscoveredNetwork(
                "10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "10.10.20.1"
            ),
            DiscoveredNetwork(
                "2001:db8:a::/48", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0", "fe80::1"
            ),
        ),
        pivot_paths=(
            PivotPath("tun0", "10.10.20.1", "10.60.0.0/16", Confidence.MEDIUM),
        ),
        session=SessionIdentity("sess-1", "local", "internal-server"),
    )


def make_baseline_snapshot() -> DiscoverySnapshot:
    """A smaller earlier perspective so comparisons have real changes."""
    return DiscoverySnapshot(
        hostname="ophost",
        os_name="Linux 6.1",
        networks=(
            DiscoveredNetwork(
                "10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"
            ),
        ),
        session=SessionIdentity("sess-0", "local", "workstation"),
    )


@pytest.fixture()
def baseline(tmp_path, monkeypatch):
    from pivotcheck import cli

    monkeypatch.setattr(cli, "run_discovery", make_baseline_snapshot)
    data = tmp_path / "data"
    assert main(["--data-dir", str(data), "baseline", "create", "--name", "workstation"]) == EXIT_OK
    monkeypatch.setattr(cli, "run_discovery", make_snapshot)
    return data


def _run(argv, data_dir=None):
    prefix = ["--data-dir", str(data_dir)] if data_dir else []
    return main(prefix + argv)


class TestCompareViews:
    def test_summary_view(self, baseline, capsys):
        assert _run(["compare", "workstation", "--summary"], baseline) == EXIT_OK
        out = capsys.readouterr().out
        assert "OPERATIONAL SUMMARY" in out
        assert "New Coverage" in out

    def test_evidence_view_shows_origin_and_reachability(self, baseline, capsys):
        assert _run(["compare", "workstation", "--evidence"], baseline) == EXIT_OK
        out = capsys.readouterr().out
        assert "NETWORK EXPLANATION" in out
        assert "NOT ACTIVELY VALIDATED" in out

    def test_recommend_view_is_deterministic_and_labeled(self, baseline, capsys):
        first = _run(["compare", "workstation", "--recommend"], baseline)
        out1 = capsys.readouterr().out
        second = _run(["compare", "workstation", "--recommend"], baseline)
        out2 = capsys.readouterr().out
        assert first == EXIT_OK == second
        assert out1 == out2
        assert "PRIORITY:" in out1
        assert "Limitation:" in out1

    def test_explain_by_cidr(self, baseline, capsys):
        code = _run(["compare", "workstation", "--explain", "10.50.0.0/16"], baseline)
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "10.50.0.0/16" in out
        assert "NOT ACTIVELY VALIDATED" in out

    def test_explain_by_ip_inside_network(self, baseline, capsys):
        code = _run(["compare", "workstation", "--explain", "10.50.5.1"], baseline)
        assert code == EXIT_OK
        assert "10.50.0.0/16" in capsys.readouterr().out

    def test_views_are_mutually_exclusive(self, baseline):
        with pytest.raises(SystemExit) as exc:
            _run(["compare", "workstation", "--summary", "--evidence"], baseline)
        assert exc.value.code == EXIT_USAGE

    def test_explain_unknown_network_is_usage_error(self, baseline, capsys):
        code = _run(["compare", "workstation", "--explain", "192.168.99.0/24"], baseline)
        assert code == EXIT_USAGE
        assert "does not match" in capsys.readouterr().err


class TestCompareFilters:
    def test_family_ipv6_hides_ipv4_changes(self, baseline, capsys):
        # First create a state where ipv6 is the only change.
        from pivotcheck import cli

        ipv6_only = DiscoverySnapshot(
            "ophost",
            "Linux 6.1",
            networks=(
                DiscoveredNetwork("2001:db8:b::/48", NetworkOrigin.ROUTED, Confidence.MEDIUM, "tun0"),
            ),
            session=make_snapshot().session,
        )
        monkey_snapshot = ipv6_only
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(cli, "run_discovery", lambda: monkey_snapshot)
        try:
            code = _run(["compare", "workstation", "--family", "ipv6"], baseline)
        finally:
            monkeypatch.undo()
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "2001:db8:b::/48" in out

    def test_minimum_confidence_filters_json(self, baseline, capsys):
        code = _run(
            [
                "compare", "workstation", "--format", "json",
                "--minimum-confidence", "high",
            ],
            baseline,
        )
        assert code == EXIT_OK
        document = json.loads(capsys.readouterr().out)
        networks = [
            item["network"]
            for item in document["comparison"]["new_reachability"]
        ]
        assert all("/16" not in net or net.startswith("10.10") for net in networks)

    def test_changes_only_keeps_identity_metadata(self, baseline, capsys):
        code = _run(["compare", "workstation", "--changes-only"], baseline)
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "Baseline: workstation" in out  # identity preserved


class TestCompareJsonAndOutput:
    def test_json_with_summary_section(self, baseline, capsys):
        code = _run(
            ["compare", "workstation", "--format", "json", "--summary"],
            baseline,
        )
        assert code == EXIT_OK
        document = json.loads(capsys.readouterr().out)
        assert "summary" in document
        assert "\033[" not in json.dumps(document)

    def test_json_with_recommendations_section(self, baseline, capsys):
        code = _run(
            ["compare", "workstation", "--format", "json", "--recommend"],
            baseline,
        )
        assert code == EXIT_OK
        document = json.loads(capsys.readouterr().out)
        recommendations = document["recommendations"]
        assert recommendations
        assert all(item["limitation"] for item in recommendations)

    def test_output_writes_artifact_and_refuses_overwrite(self, baseline, tmp_path, capsys):
        target = tmp_path / "comparison.json"
        code = _run(
            ["compare", "workstation", "--format", "json", "--output", str(target)],
            baseline,
        )
        assert code == EXIT_OK
        payload = target.read_text(encoding="utf-8")
        assert json.loads(payload)["comparison"]
        # Second write must refuse without --force; stdout stays clean.
        code = _run(
            ["compare", "workstation", "--format", "json", "--output", str(target)],
            baseline,
        )
        assert code == EXIT_USAGE
        assert "use --force" in capsys.readouterr().err
        code = _run(
            [
                "compare", "workstation", "--format", "json",
                "--output", str(target), "--force",
            ],
            baseline,
        )
        assert code == EXIT_OK

    def test_failed_output_leaves_no_partial_file(self, baseline, tmp_path):
        missing_dir = tmp_path / "nope" / "deep"
        code = _run(
            [
                "compare", "workstation", "--format", "json",
                "--output", str(missing_dir / "x.json"),
            ],
            baseline,
        )
        assert code != EXIT_OK
        assert not missing_dir.exists()


class TestMapControls:
    def test_show_pivots_limits_to_inferred_context(self, baseline, capsys):
        code = _run(
            ["map", "--baseline", "workstation", "--show-pivots"], baseline
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "INFERRED PIVOT CONTEXT" in out
        assert "ROUTING EVIDENCE ONLY" in out
        assert "CURRENT CONNECTED COVERAGE" not in out

    def test_focus_narrows_map(self, baseline, capsys):
        code = _run(
            ["map", "--baseline", "workstation", "--focus", "10.50.0.0/16"], baseline
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "10.50.0.0/16" in out
        assert "10.10.20.0/24" not in out

    def test_interface_filter_keeps_unknown_metadata_entries(self, baseline, capsys):
        code = _run(["map", "--interface", "eth0"], baseline)
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "10.10.20.0/24" in out


class TestDiscoverSummary:
    def test_discover_summary_counts(self, monkeypatch, capsys):
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_snapshot)
        assert main(["discover", "--summary"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "Connected Coverage: 1" in out
        assert "Routed Coverage: 2" in out
        assert "Inferred Pivot Paths: 1" in out


class TestNetworkArgumentValidation:
    """Stage 9 DEFECT-002 regression: invalid network arguments must follow
    the established CLI error contract (clean `[-]` message on stderr, no
    Python traceback, EXIT_USAGE, no partial output, no side effects).

    These tests fail against the defective 2.0.0 implementation, which
    leaked an uncaught ValueError traceback from models/network.py and
    exited 1.
    """

    BAD_NETWORKS = (
        "not-a-cidr",
        "999.999.1.0/24",  # malformed IPv4 octets
        "10.0.0.0/33",  # invalid IPv4 prefix length
        "10.0.0.0/120",  # IPv6 prefix length applied to IPv4
        "10.0.0.0/24/24",  # double prefix
        "2001:db8::/wxyz",  # malformed IPv6 prefix
    )

    @pytest.fixture(autouse=True)
    def fake_discovery(self, monkeypatch):
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", make_snapshot)

    @pytest.mark.parametrize("bad", BAD_NETWORKS)
    def test_gaps_invalid_network_is_usage_error(self, bad, capsys):
        assert _run(["gaps", bad]) == EXIT_USAGE
        err = capsys.readouterr().err
        assert "Invalid network argument" in err
        assert "Traceback" not in err
        assert "ValueError" not in err

    @pytest.mark.parametrize("bad", BAD_NETWORKS)
    def test_explain_invalid_network_is_usage_error(self, bad, capsys):
        assert _run(["explain", bad]) == EXIT_USAGE
        err = capsys.readouterr().err
        assert "Invalid network argument" in err
        assert "Traceback" not in err

    @pytest.mark.parametrize("bad", BAD_NETWORKS)
    def test_invalid_network_json_path_has_no_partial_result(self, bad, capsys):
        for command in ("gaps", "explain"):
            assert _run([command, bad, "--json"]) == EXIT_USAGE
            captured = capsys.readouterr()
            # No partial JSON artifact may pretend the request succeeded.
            assert captured.out.strip() == ""
            assert "Traceback" not in captured.err

    def test_invalid_network_fails_before_discovery(self, monkeypatch, capsys):
        """Invalid input must produce zero side effects: discovery (and any
        I/O behind it) must never run for an invalid network argument."""
        from pivotcheck import cli

        def _must_not_run(*_args, **_kwargs):
            raise AssertionError("discovery must not run for invalid input")

        monkeypatch.setattr(cli, "run_discovery", _must_not_run)
        assert _run(["gaps", "not-a-cidr"]) == EXIT_USAGE
        assert "Invalid network argument" in capsys.readouterr().err

    def test_valid_cidr_behavior_unchanged(self, capsys):
        assert _run(["gaps", "10.50.0.0/16"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "10.50.0.0/16" in out
        assert "EVIDENCE GAP" in out

    def test_bare_ip_still_valid(self, capsys):
        assert _run(["explain", "10.50.5.1"]) == EXIT_OK
        assert "10.50.0.0/16" in capsys.readouterr().out

    def test_host_bits_set_still_accepted(self, capsys):
        # strict=False semantics are preserved: host bits are normalized,
        # exactly as in 2.0.0.
        assert _run(["gaps", "10.50.5.1/16"]) == EXIT_OK

    def test_ipv6_cidr_still_valid(self, capsys):
        assert _run(["explain", "2001:db8:a::/48"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "2001:db8:a::/48" in out
        assert "CURRENT_EVIDENCE" in out

    def test_explain_unobserved_network_is_not_observed(self, capsys):
        """Stage 9 DEFECT-001 regression at the CLI boundary: absence of
        observation must never be promoted to CURRENT_EVIDENCE. Fails
        against 2.0.0, which reported CURRENT_EVIDENCE here."""
        assert _run(["explain", "192.168.99.0/24"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "NOT_OBSERVED" in out
        assert "CURRENT_EVIDENCE" not in out

    def test_explain_unobserved_network_json_classification(self, capsys):
        assert _run(["explain", "192.168.99.0/24", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["classification"] == "NOT_OBSERVED"
        assert payload["reason"] == "Network not found in current discovery evidence."