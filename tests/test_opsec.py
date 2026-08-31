"""OPSEC intelligence tests (v2.0 Step 7).

Adversarial discipline: no credentials can enter the engine (no
credential parameters exist), no I/O is possible (socket/subprocess/
filesystem/environment all explode if touched), and no evasion language
can ever be produced (the knowledge table is static and marker-scanned).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from pivotcheck.analysis.opsec import (
    assess_opsec,
    parse_action,
    parse_platform,
)
from pivotcheck.models.opsec import (
    OpsecAction,
    OpsecCategory,
    OpsecLikelihood,
    OpsecObservation,
    OpsecPlatform,
    OpsecResult,
)

SECRET = "DO_NOT_LEAK_OPSEC_SECRET"
PASSWORD = "DO_NOT_LEAK_PASSWORD"

# Evasion language that must never appear in any output.
_EVASION_MARKERS = (
    "clear the logs",
    "clear logs",
    "delete the logs",
    "disable auditing",
    "disable the audit",
    "bypass defender",
    "kill edr",
    "avoid detection by",
    "suppress telemetry",
    "hide activity",
    "how to evade",
)


# ---------------------------------------------------------------------------
# Action / platform parsing (fail closed)
# ---------------------------------------------------------------------------


class TestParsing:
    def test_valid_actions(self):
        for value in ("ssh-auth", "smb-auth", "winrm-auth", "tcp-connect", "socks5-connect"):
            assert parse_action(value) in OpsecAction

    def test_case_and_whitespace_normalization(self):
        assert parse_action("  SSH-AUTH ") is OpsecAction.SSH_AUTH

    def test_unknown_action_fails_closed(self):
        with pytest.raises(ValueError, match="unknown action"):
            parse_action("clear-logs")

    def test_malicious_action_string_cannot_escape(self):
        for hostile in (
            "ssh-auth; rm -rf /",
            "ssh-auth && whoami",
            "$(whoami)",
            "ssh-auth\nwhoami",
            "disables event log",
        ):
            with pytest.raises(ValueError, match="unknown action"):
                parse_action(hostile)

    def test_valid_platforms(self):
        for value in ("windows", "linux", "macos"):
            assert parse_platform(value) in OpsecPlatform

    def test_unknown_platform_fails_closed(self):
        with pytest.raises(ValueError, match="unknown platform"):
            parse_platform("mainframe")


# ---------------------------------------------------------------------------
# Knowledge mappings
# ---------------------------------------------------------------------------


class TestMappings:
    def test_ssh_auth_linux(self):
        result = assess_opsec(OpsecAction.SSH_AUTH, OpsecPlatform.LINUX)
        categories = {o.category for o in result.observations}
        assert OpsecCategory.AUTHENTICATION in categories
        assert any(o.likelihood is OpsecLikelihood.LIKELY for o in result.observations)
        assert any("sshd" in o.sources for o in result.observations)
        assert "audit policy" in " ".join(result.limitations).lower()

    def test_smb_auth_windows(self):
        result = assess_opsec(OpsecAction.SMB_AUTH, OpsecPlatform.WINDOWS)
        categories = {o.category for o in result.observations}
        assert OpsecCategory.AUTHENTICATION in categories
        assert OpsecCategory.NETWORK_CONNECTION in categories
        # Known Windows logon event IDs are documented references.
        all_ids = [eid for o in result.observations for eid in o.event_ids]
        assert "4624" in all_ids
        assert "4625" in all_ids

    def test_winrm_auth_windows(self):
        result = assess_opsec(OpsecAction.WINRM_AUTH, OpsecPlatform.WINDOWS)
        categories = {o.category for o in result.observations}
        assert OpsecCategory.REMOTE_MANAGEMENT in categories
        # The action performs authentication only: no process telemetry is
        # expected from it, and the engine must say so explicitly.
        process = next(
            o for o in result.observations if o.category is OpsecCategory.PROCESS_ACTIVITY
        )
        assert process.likelihood is OpsecLikelihood.NOT_EXPECTED

    def test_tcp_connect_windows(self):
        result = assess_opsec(OpsecAction.TCP_CONNECT, OpsecPlatform.WINDOWS)
        assert any(o.category is OpsecCategory.NETWORK_CONNECTION for o in result.observations)

    def test_tcp_connect_linux_environment_dependent(self):
        result = assess_opsec(OpsecAction.TCP_CONNECT, OpsecPlatform.LINUX)
        assert any(
            o.likelihood is OpsecLikelihood.ENVIRONMENT_DEPENDENT for o in result.observations
        )

    def test_socks5_connect(self):
        result = assess_opsec(OpsecAction.SOCKS5_CONNECT, OpsecPlatform.LINUX)
        assert any(o.category is OpsecCategory.NETWORK_CONNECTION for o in result.observations)

    def test_unmapped_combination_is_explicit_unknown(self):
        result = assess_opsec(OpsecAction.WINRM_AUTH, OpsecPlatform.MACOS)
        assert result.observations == ()
        assert "does not guess" in result.rationale
        assert any("UNKNOWN" in limitation for limitation in result.limitations)


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------


class TestModelValidation:
    def test_valid_observation(self):
        observation = OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description="x",
            likelihood=OpsecLikelihood.LIKELY,
            event_ids=("4624",),
            sources=("Security",),
        )
        assert observation.to_dict()["likelihood"] == "likely"

    def test_invalid_category_rejected(self):
        with pytest.raises(TypeError, match="invalid telemetry category"):
            OpsecObservation("authentication", "x", OpsecLikelihood.LIKELY)  # type: ignore[arg-type]

    def test_invalid_likelihood_rejected(self):
        with pytest.raises(TypeError, match="invalid telemetry likelihood"):
            OpsecObservation(OpsecCategory.AUTHENTICATION, "x", "likely")  # type: ignore[arg-type]

    def test_empty_description_rejected(self):
        with pytest.raises(ValueError, match="description"):
            OpsecObservation(OpsecCategory.AUTHENTICATION, "", OpsecLikelihood.LIKELY)

    def test_untrimmed_event_id_rejected(self):
        with pytest.raises(ValueError, match="trimmed"):
            OpsecObservation(
                OpsecCategory.AUTHENTICATION, "x", OpsecLikelihood.LIKELY, event_ids=(" 4624",)
            )

    def test_result_validation(self):
        with pytest.raises(TypeError, match="invalid action"):
            OpsecResult("ssh-auth", OpsecPlatform.LINUX, (), rationale="r")  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="rationale"):
            OpsecResult(OpsecAction.SSH_AUTH, OpsecPlatform.LINUX, (), rationale="")


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_invocation_identical(self):
        first = assess_opsec(OpsecAction.SMB_AUTH, OpsecPlatform.WINDOWS).to_dict()
        for _ in range(5):
            assert assess_opsec(OpsecAction.SMB_AUTH, OpsecPlatform.WINDOWS).to_dict() == first

    def test_no_timestamps_or_random_ids_in_result(self):
        result = assess_opsec(OpsecAction.WINRM_AUTH, OpsecPlatform.WINDOWS)
        payload = json.dumps(result.to_dict())
        assert "timestamp" not in payload
        assert "uuid" not in payload


# ---------------------------------------------------------------------------
# Security: no evasion, no secrets, no I/O
# ---------------------------------------------------------------------------


class TestNoEvasion:
    @pytest.mark.parametrize(
        "action,platform",
        [
            (OpsecAction.SSH_AUTH, OpsecPlatform.LINUX),
            (OpsecAction.SMB_AUTH, OpsecPlatform.WINDOWS),
            (OpsecAction.WINRM_AUTH, OpsecPlatform.WINDOWS),
            (OpsecAction.TCP_CONNECT, OpsecPlatform.LINUX),
            (OpsecAction.SOCKS5_CONNECT, OpsecPlatform.LINUX),
        ],
    )
    def test_no_evasion_language_in_any_output(self, action, platform):
        result = assess_opsec(action, platform)
        representations = [repr(result), str(result), json.dumps(result.to_dict())]
        for representation in representations:
            lowered = representation.lower()
            for marker in _EVASION_MARKERS:
                assert marker not in lowered, f"evasion language leaked: {marker}"

    def test_all_limitations_state_predictive_nature(self):
        for action in OpsecAction:
            for platform in OpsecPlatform:
                result = assess_opsec(action, platform)
                assert result.limitations
                joined = " ".join(result.limitations).lower()
                assert "does not observe" in joined


class TestSecretSafety:
    def test_engine_has_no_credential_surface(self):
        """Structural proof: the OPSEC engine accepts no credential
        objects — its signature is (action, platform) only."""
        import inspect

        from pivotcheck.analysis import opsec as opsec_module

        signature = inspect.signature(opsec_module.assess_opsec)
        assert list(signature.parameters) == ["action", "platform"]
        source = inspect.getsource(opsec_module)
        assert "Credential" not in source

    def test_no_marker_in_any_representation(self):
        result = assess_opsec(OpsecAction.SMB_AUTH, OpsecPlatform.WINDOWS)
        representations = [repr(result), str(result), json.dumps(result.to_dict())]
        for representation in representations:
            assert SECRET not in representation
            assert PASSWORD not in representation


class TestNoSideEffects:
    def test_engine_never_touches_socket_subprocess_filesystem_env(self, monkeypatch, tmp_path):
        def _explode(*args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("I/O attempted inside the pure OPSEC engine")

        monkeypatch.setattr(socket, "socket", _explode)
        monkeypatch.setattr(socket, "create_connection", _explode)
        monkeypatch.setattr(subprocess, "run", _explode)
        monkeypatch.setattr(subprocess, "Popen", _explode)
        monkeypatch.setattr(Path, "open", _explode)
        monkeypatch.setattr(Path, "read_text", _explode)
        monkeypatch.setattr(os, "system", _explode)

        for action in OpsecAction:
            for platform in OpsecPlatform:
                assess_opsec(action, platform)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestOpsecCLI:
    def test_cli_json_envelope(self, capsys):
        from pivotcheck.cli import EXIT_OK, main

        code = main(["opsec", "--action", "smb-auth", "--platform", "windows", "--json"])
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["tool"] == "pivotcheck"
        assert data["command"] == "opsec"
        assert data["schema_version"] == "1.0"
        assert data["result"]["action"] == "smb-auth"
        assert data["result"]["platform"] == "windows"
        assert data["result"]["observations"]
        assert "DO_NOT_LEAK_OPSEC_SECRET" not in json.dumps(data)

    def test_cli_unknown_action_is_usage(self, capsys):
        from pivotcheck.cli import EXIT_USAGE, main

        code = main(["opsec", "--action", "clear-logs", "--platform", "windows"])
        assert code == EXIT_USAGE
        assert "unknown action" in capsys.readouterr().err

    def test_cli_unknown_platform_is_usage(self, capsys):
        from pivotcheck.cli import EXIT_USAGE, main

        code = main(["opsec", "--action", "ssh-auth", "--platform", "vmware"])
        assert code == EXIT_USAGE

    def test_cli_text_output(self, capsys):
        from pivotcheck.cli import EXIT_OK, main

        code = main(["opsec", "--action", "winrm-auth", "--platform", "windows"])
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "OPSEC OBSERVABILITY ANALYSIS" in out
        assert "AUTHENTICATED" not in out  # predictive analysis, not validation results
        assert "does not observe" in out.lower()

    def test_cli_missing_required_arguments(self, capsys):
        from pivotcheck.cli import EXIT_USAGE, main

        for argv in (["opsec"], ["opsec", "--action", "ssh-auth"]):
            with pytest.raises(SystemExit) as excinfo:
                main(argv)
            assert excinfo.value.code == EXIT_USAGE
            err = capsys.readouterr().err
            assert "--action" in err or "--platform" in err
