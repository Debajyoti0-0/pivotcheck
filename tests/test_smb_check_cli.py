"""CLI tests for SMB authentication validation via `check --protocol smb`.

Follows the existing check-CLI test architecture: inject fakes at the cli
module boundary, invoke main(), assert exit codes + output contracts.
"""

from __future__ import annotations

import json

import pytest

from pivotcheck import __version__
from pivotcheck.cli import (
    EXIT_FATAL,
    EXIT_OK,
    EXIT_RESOLVE,
    EXIT_USAGE,
    main,
)
from pivotcheck.models.credentials import Credential, CredentialType
from pivotcheck.models.smb_check import SMBCheckResult, SMBCheckStatus

PASSWORD = "DO_NOT_LEAK_SMB_PASSWORD"
ENV_NAME = "PC_TEST_SMB_CRED"


def _make_result(status: SMBCheckStatus, detail: str | None = None) -> SMBCheckResult:
    from pivotcheck.models.smb_check import verdict_for

    return SMBCheckResult(
        target="10.10.10.20",
        port=445,
        username="operator",
        status=status,
        verdict=verdict_for(status),
        detail=detail,
        attempts=1,
        elapsed_ms=15.0,
    )


@pytest.fixture()
def smb_cred_env(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv(ENV_NAME, PASSWORD)
    return ENV_NAME


@pytest.fixture()
def fake_validate(monkeypatch: pytest.MonkeyPatch):
    def _install(status: SMBCheckStatus, detail: str | None = None):
        calls: list[tuple] = []

        def fake_validate(credential: Credential, target: str, port: int = 445, timeout: float = 10.0):
            calls.append((credential, target, port, timeout))
            return _make_result(status, detail)

        monkeypatch.setattr("pivotcheck.cli.validate_smb_auth", fake_validate)
        return calls

    return _install


class TestSMBUsage:
    def test_missing_credential_env_is_usage(self, capsys):
        code = main(["check", "10.10.10.20", "--port", "445", "--protocol", "smb"])
        assert code == EXIT_USAGE
        assert "--credential-env" in capsys.readouterr().err

    def test_port_list_rejected_for_smb(self, smb_cred_env, capsys):
        code = main(
            [
                "check", "10.10.10.20", "--port", "445,139",
                "--protocol", "smb", "--credential-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        assert "one target, one port" in capsys.readouterr().err

    def test_baseline_rejected_for_smb(self, smb_cred_env, fake_validate, capsys):
        fake_validate(SMBCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME, "--baseline", "pre-pivot",
            ]
        )
        assert code == EXIT_USAGE
        assert "--baseline" in capsys.readouterr().err

    def test_missing_env_variable_is_usage(self, monkeypatch, capsys):
        monkeypatch.delenv(ENV_NAME, raising=False)
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        assert ENV_NAME in capsys.readouterr().err

    def test_invalid_env_name_is_usage(self, capsys):
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", "bad name",
            ]
        )
        assert code == EXIT_USAGE


class TestSMBOutcomes:
    def test_authenticated_json_envelope(self, smb_cred_env, fake_validate, capsys):
        calls = fake_validate(SMBCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["tool"] == "pivotcheck"
        assert data["version"] == __version__
        assert data["command"] == "check"
        assert data["protocol"] == "smb"
        result = data["results"][0]
        assert result["status"] == "AUTHENTICATED"
        assert result["verdict"] == "EXPLICITLY_VALIDATED"
        assert result["attempts"] == 1
        assert "DO_NOT_LEAK_SMB_PASSWORD" not in json.dumps(data)
        credential, target, port, _timeout = calls[0]
        assert credential.source_name == ENV_NAME
        assert credential.credential_type is CredentialType.PASSWORD
        assert target == "10.10.10.20"
        assert port == 445

    def test_auth_failed_is_data_not_cli_failure(self, smb_cred_env, fake_validate, capsys):
        fake_validate(SMBCheckStatus.AUTH_FAILED, "authentication rejected by target")
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["verdict"] == "NEGATIVE_EVIDENCE"

    def test_dns_error_maps_to_resolve_exit(self, smb_cred_env, fake_validate, capsys):
        fake_validate(SMBCheckStatus.DNS_ERROR, "unresolvable")
        code = main(
            [
                "check", "host.invalid", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_RESOLVE

    def test_local_error_maps_to_fatal_exit(self, smb_cred_env, fake_validate, capsys):
        fake_validate(SMBCheckStatus.LOCAL_ERROR, "backend unavailable")
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_FATAL

    def test_text_output_contains_verdict_and_safety_boundary(self, smb_cred_env, fake_validate, capsys):
        fake_validate(SMBCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME,
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "SMB AUTHENTICATION VALIDATION" in out
        assert "AUTHENTICATED" in out
        assert "EXPLICITLY_VALIDATED" in out
        assert "does NOT prove" in out
        assert "DO_NOT_LEAK_SMB_PASSWORD" not in out

    def test_default_username_is_current_os_user(self, smb_cred_env, fake_validate, capsys):
        import getpass

        calls = fake_validate(SMBCheckStatus.AUTHENTICATED)
        main(
            [
                "check", "10.10.10.20", "--port", "445", "--protocol", "smb",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        credential, _target, _port, _timeout = calls[0]
        assert credential.username == getpass.getuser()


class TestTCPProtocolRegression:
    def test_tcp_path_unchanged_by_smb_addition(self, monkeypatch, capsys):
        from pivotcheck.models.check import CheckResult, CheckStatus
        from pivotcheck.models.result import DiscoverySnapshot

        def fake_check_tcp(address, port, timeout_s, target=None):
            return CheckResult(
                target=target or address,
                address=address,
                port=port,
                status=CheckStatus.REFUSED,
                elapsed_ms=1.0,
            )

        monkeypatch.setattr("pivotcheck.cli.check_tcp", fake_check_tcp)
        monkeypatch.setattr(
            "pivotcheck.cli.run_discovery",
            lambda: DiscoverySnapshot(hostname="", os_name="", networks=()),
        )
        code = main(["check", "127.0.0.1", "--port", "80", "--json"])
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["protocol"] == "tcp"
        assert data["results"][0]["status"] == "REFUSED"
