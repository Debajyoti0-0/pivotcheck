"""JSON schema stability and epistemic language audit tests.

These tests verify:
1. JSON output schemas are stable and follow contracts
2. No accidental field renaming or type changes
3. Epistemic language is accurate (no overclaiming)
4. Evidence states are correctly distinguished
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import ClassVar


def run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run pivotcheck CLI and return result."""
    cmd = [sys.executable, "-m", "pivotcheck"] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)


class TestJSONSchemaStability:
    """Test that JSON schemas are stable and follow contracts."""

    def test_check_json_schema(self):
        """Check command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "check", "127.0.0.1", "--port", "80", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        # Required top-level fields
        assert "schema_version" in data
        assert "tool" in data
        assert data["tool"] == "pivotcheck"
        assert "version" in data
        assert "command" in data
        assert data["command"] == "check"
        assert "timestamp" in data
        assert "perspective" in data
        assert "hostname" in data["perspective"]
        assert "session_id" in data["perspective"]
        assert "target" in data
        assert "resolved_addresses" in data
        assert "ports" in data
        assert "timeout_s" in data
        assert "results" in data

        # Results array structure
        for result in data["results"]:
            assert "target" in result
            assert "address" in result
            assert "port" in result
            assert "protocol" in result
            assert result["protocol"] == "tcp"
            assert "status" in result
            assert result["status"] in [
                "SUCCESS", "REFUSED", "TIMEOUT", "NO_ROUTE",
                "UNREACHABLE", "DNS_ERROR", "INVALID_TARGET", "LOCAL_ERROR"
            ]
            assert "elapsed_ms" in result
            assert "error" in result
            assert "route_context" in result

    def test_next_json_schema(self):
        """Next command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "next", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        assert "schema_version" in data
        assert "tool" in data
        assert data["tool"] == "pivotcheck"
        assert "version" in data
        assert "command" in data
        assert data["command"] == "next"
        assert "timestamp" in data
        assert "perspective" in data

        # Candidate or message
        assert ("candidate" in data and data["candidate"] is not None) or \
               ("message" in data and data["message"] == "NO INVESTIGATION CANDIDATES")

        if data.get("candidate"):
            cand = data["candidate"]
            assert "network" in cand
            assert "priority" in cand
            assert cand["priority"] in ["HIGH", "MEDIUM", "LOW"]
            assert "reason" in cand
            assert "observed_evidence" in cand
            assert "transit_assessment" in cand
            assert "comparison_context" in cand or cand.get("comparison_context") is None

    def test_proxy_check_json_schema(self):
        """Proxy-check command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "proxy-check",
             "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        # May fail due to connection refused, but JSON should be valid
        if result.returncode == 0:
            data = json.loads(result.stdout)

            assert "schema_version" in data
            assert "tool" in data
            assert data["tool"] == "pivotcheck"
            assert "command" in data
            assert data["command"] == "proxy-check"
            assert "timestamp" in data
            assert "perspective" in data
            assert "proxy" in data
            assert "scheme" in data["proxy"]
            assert data["proxy"]["scheme"] == "socks5"
            assert "host" in data["proxy"]
            assert "port" in data["proxy"]
            assert "has_credentials" in data["proxy"]
            assert "target" in data
            assert "host" in data["target"]
            assert "port" in data["target"]
            assert "timeout_s" in data
            assert "stages" in data
            assert "verdict" in data
            assert data["verdict"] in ["VALIDATED", "NOT_VALIDATED"]
            assert "limitation" in data

            for stage in data["stages"]:
                assert "stage" in stage
                assert stage["stage"] in ["proxy_tcp", "socks5_negotiation", "destination_connect"]
                assert "status" in stage
                assert "detail" in stage
                assert "elapsed_ms" in stage

    def test_gaps_json_schema(self):
        """Gaps command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "gaps", "10.50.0.0/16", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        assert "schema_version" in data
        assert "tool" in data
        assert data["tool"] == "pivotcheck"
        assert "command" in data
        assert data["command"] == "gaps"
        assert "timestamp" in data
        assert "network" in data
        assert "gaps" in data
        assert isinstance(data["gaps"], list)

        for gap in data["gaps"]:
            assert "evidence_type" in gap
            assert gap["evidence_type"] in ["route", "neighbor", "connection", "active_validation"]
            assert "status" in gap
            assert gap["status"] in [
                "OBSERVED", "NOT_OBSERVED", "NOT_COLLECTED",
                "NEGATIVE_EVIDENCE", "NOT_APPLICABLE", "NOT_PERFORMED"
            ]
            assert "details" in gap

    def test_explain_json_schema(self):
        """Explain command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "explain", "10.50.0.0/16", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        assert "network" in data
        assert data["network"] == "10.50.0.0/16"
        assert "classification" in data
        assert "reason" in data
        assert "limitations" in data
        assert isinstance(data["limitations"], list)
        assert len(data["limitations"]) > 0

    def test_discover_json_schema(self):
        """Discover command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "discover", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        assert "tool" in data
        assert data["tool"] == "pivotcheck"
        assert "version" in data
        assert "timestamp" in data
        assert "hostname" in data
        assert "os" in data
        assert "interfaces" in data
        assert "routes" in data
        assert "neighbors" in data
        assert "dns" in data
        assert "connections" in data
        assert "networks" in data
        assert "pivot_paths" in data
        assert "warnings" in data

    def test_map_json_schema(self):
        """Map command JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "map", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        assert "baseline" in data
        assert "current" in data
        assert "map" in data

    def test_baseline_list_json_schema(self):
        """Baseline list JSON has required fields."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "baseline", "list", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        assert "baselines" in data
        for baseline in data["baselines"]:
            assert "name" in baseline
            assert "created_at" in baseline
            assert "vantage_point" in baseline


class TestJSONTypeStability:
    """Test that JSON field types are stable."""

    def test_check_results_status_type(self):
        """Check status is always string enum."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "check", "127.0.0.1", "--port", "80", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        for r in data["results"]:
            assert isinstance(r["status"], str)
            assert isinstance(r["port"], int)
            assert isinstance(r["elapsed_ms"], (int, float, type(None)))
            assert isinstance(r["error"], (str, type(None)))

    def test_next_priority_type(self):
        """Next priority is always string enum."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "next", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        if data.get("candidate"):
            assert isinstance(data["candidate"]["priority"], str)
            assert data["candidate"]["priority"] in ["HIGH", "MEDIUM", "LOW", "NONE"]

    def test_proxy_check_verdict_type(self):
        """Proxy check verdict is always string enum."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "proxy-check",
             "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            assert isinstance(data["verdict"], str)
            assert data["verdict"] in ["VALIDATED", "NOT_VALIDATED"]


class TestJSONDeterminism:
    """Test that JSON output is deterministic."""

    def test_check_json_deterministic(self):
        """Same check input -> same JSON structure."""
        results = []
        for _ in range(3):
            result = subprocess.run(
                [sys.executable, "-m", "pivotcheck", "check", "127.0.0.1", "--port", "80", "--json"],
                capture_output=True, text=True, check=False, timeout=30
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                # Normalize timestamps
                data["timestamp"] = "NORMALIZED"
                data["perspective"]["session_id"] = "NORMALIZED"
                for r in data["results"]:
                    r["elapsed_ms"] = "NORMALIZED"
                results.append(json.dumps(data, sort_keys=True))

        if len(results) > 1:
            for r in results[1:]:
                assert r == results[0], "JSON output not deterministic"

    def test_next_json_deterministic(self):
        """Same next input -> same JSON structure."""
        results = []
        for _ in range(3):
            result = subprocess.run(
                [sys.executable, "-m", "pivotcheck", "next", "--json"],
                capture_output=True, text=True, check=False, timeout=30
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                data["timestamp"] = "NORMALIZED"
                data["perspective"]["session_id"] = "NORMALIZED"
                results.append(json.dumps(data, sort_keys=True))

        if len(results) > 1:
            for r in results[1:]:
                assert r == results[0], "JSON output not deterministic"


class TestEpistemicLanguageAudit:
    """Audit output for epistemic correctness - no overclaiming."""

    FORBIDDEN_TERMS: ClassVar[list[str]] = [
        "reachable",
        "confirmed",
        "verified",
        "exploitable",
        "pivot",
        "forwarding",
        "accessible",
        "connection successful",
        "working",
        "viable",
    ]

    ALLOWED_IN_CONTEXT: ClassVar[dict[str, list[str]]] = {
        "reachable": ["route evidence observed", "route context exists", "actively validated"],
        "pivot": ["inferred pivot context", "transit candidate", "pivot path"],
        "confirmed": ["actively validated", "validation confirmed"],
        "working": ["evidence observed", "actively validated"],
    }

    def test_check_output_no_overclaiming(self):
        """Check command output must not overclaim."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "check", "127.0.0.1", "--port", "80"],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout.lower()

        # Should not claim reachability without validation
        for term in ["confirmed", "verified", "exploitable"]:
            assert term not in output, f"Forbidden term '{term}' found in check output"

    def test_next_output_no_overclaiming(self):
        """Next command output must not overclaim."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "next"],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout.lower()

        # If candidates exist, must include limitation text
        if "no investigation candidates" not in output:
            assert "limitation" in output
            assert "do not prove active reachability" in output
            assert "not validation evidence" in output

    def test_proxy_check_output_no_overclaiming(self):
        """Proxy-check output must not overclaim."""
        # Check text output
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "proxy-check",
             "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80"],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout.lower()

        # Must include limitation
        assert "limitation" in output
        assert "does not prove general" in output
        assert "network reachability" in output

    def test_gaps_output_precise(self):
        """Gaps output must use precise evidence states."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "gaps", "10.50.0.0/16"],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout

        # Must distinguish evidence states
        assert "OBSERVED" in output or "NOT_OBSERVED" in output or \
               "NOT_COLLECTED" in output or "NEGATIVE_EVIDENCE" in output or \
               "NOT_APPLICABLE" in output or "NOT_PERFORMED" in output

    def test_explain_output_precise(self):
        """Explain output must use precise language."""
        # Check text output
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "explain", "10.50.0.0/16"],
            capture_output=True, text=True, check=False, timeout=30
        )
        output = result.stdout

        assert "Reachability" in output or "REACHABILITY" in output
        assert "NOT ACTIVELY VALIDATED" in output

        # Check JSON output for limitations
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "explain", "10.50.0.0/16", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)
        assert "limitations" in data
        assert len(data["limitations"]) > 0


class TestEvidenceStateDistinctions:
    """Test that evidence states are correctly distinguished."""

    def test_gaps_distinguishes_states(self):
        """Gaps command must distinguish all evidence states."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "gaps", "10.50.0.0/16", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        statuses = {gap["status"] for gap in data["gaps"]}
        # Should have at least NOT_OBSERVED and NOT_PERFORMED
        assert "NOT_OBSERVED" in statuses or "NOT_COLLECTED" in statuses
        assert "NOT_PERFORMED" in statuses

    def test_next_limitation_explicit(self):
        """Next command must explicitly state limitations."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "next", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        if data.get("candidate"):
            assert "limitations" in data
            assert len(data["limitations"]) > 0
            limitation = data["limitations"][0]
            assert "reachability" in limitation.lower() or "validation" in limitation.lower()


class TestNoImplicitScanning:
    """Verify no scanning behavior in output."""

    def test_check_rejects_cidr(self):
        """Check must reject CIDR notation or treat as unresolvable hostname."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "check", "10.50.0.0/16", "--port", "80"],
            capture_output=True, text=True, check=False, timeout=30
        )
        # CIDR notation is treated as invalid hostname -> DNS_ERROR (exit 3)
        # or could be rejected as invalid target (exit 2)
        assert result.returncode in (2, 3)

    def test_check_rejects_port_range(self):
        """Check must reject port ranges."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "check", "127.0.0.1", "--port", "80-443"],
            capture_output=True, text=True, check=False, timeout=30
        )
        assert result.returncode == 2

    def test_proxy_check_rejects_port_range(self):
        """Proxy-check must reject port ranges."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "proxy-check",
             "--proxy", "socks5://127.0.0.1:1080", "127.0.0.1", "--port", "80-443"],
            capture_output=True, text=True, check=False, timeout=30
        )
        assert result.returncode == 2

    def test_next_no_auto_validation(self):
        """Next command never auto-validates."""
        result = subprocess.run(
            [sys.executable, "-m", "pivotcheck", "next", "--json"],
            capture_output=True, text=True, check=False, timeout=30
        )
        data = json.loads(result.stdout)

        if data.get("candidate"):
            # Candidate suggests check command, never auto-runs it
            assert "suggested_action" in data
            action = data["suggested_action"]["command_template"]
            assert "check" in action
            assert "explicit" in action.lower() or "choose" in action.lower()