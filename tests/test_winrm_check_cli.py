"""CLI tests for WinRM authentication validation via `check --protocol winrm`.

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
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.winrm_check import WinRMCheckResult, WinRMCheckStatus

PASSWORD = "DO_NOT_LEAK_WINRM_PASSWORD"
ENV_NAME = "PC_TEST_WINRM_CRED"


def _make_result(status: WinRMCheckStatus, detail: str | None = None) -> WinRMCheckResult:
    from pivotcheck.models.winrm_check import verdict_for

    return WinRMCheckResult(
        target="10.10.10.20",
        port=5985,
        username="operator",
        status=status,
        verdict=verdict_for(status),
        detail=detail,
        attempts=1,
        elapsed_ms=18.0,
    )


@pytest.fixture()
def winrm_cred_env(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv(ENV_NAME, PASSWORD)
    return ENV_NAME


@pytest.fixture()
def fake_validate(monkeypatch: pytest.MonkeyPatch):
    def _install(status: WinRMCheckStatus, detail: str | None = None):
        calls: list[tuple] = []

        def fake_validate(credential: Credential, target: str, port: int = 5985, timeout: float = 10.0, transport_scheme: str = "http"):
            calls.append((credential, target, port, timeout, transport_scheme))
            return _make_result(status, detail)

        monkeypatch.setattr("pivotcheck.cli.validate_winrm_auth", fake_validate)
        return calls

    return _install


class TestWinRMUsage:
    def test_missing_credential_env_is_usage(self, capsys):
        code = main(["check", "10.10.10.20", "--port", "5985", "--protocol", "winrm"])
        assert code == EXIT_USAGE
        assert "--credential-env" in capsys.readouterr().err

    def test_port_list_rejected_for_winrm(self, winrm_cred_env, capsys):
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985,5986",
                "--protocol", "winrm", "--credential-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        assert "one target, one port" in capsys.readouterr().err

    def test_baseline_rejected_for_winrm(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--baseline", "pre-pivot",
            ]
        )
        assert code == EXIT_USAGE
        assert "--baseline" in capsys.readouterr().err

    def test_missing_env_variable_is_usage(self, monkeypatch, capsys):
        monkeypatch.delenv(ENV_NAME, raising=False)
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        assert ENV_NAME in capsys.readouterr().err

    def test_invalid_env_name_is_usage(self, capsys):
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", "bad name",
            ]
        )
        assert code == EXIT_USAGE


class TestWinRMOutcomes:
    def test_authenticated_json_envelope(self, winrm_cred_env, fake_validate, capsys):
        calls = fake_validate(WinRMCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["tool"] == "pivotcheck"
        assert data["version"] == __version__
        assert data["command"] == "check"
        assert data["protocol"] == "winrm"
        assert data["schema_version"] == "1.1"
        result = data["results"][0]
        assert result["status"] == "AUTHENTICATED"
        assert result["verdict"] == "EXPLICITLY_VALIDATED"
        assert result["attempts"] == 1
        assert "DO_NOT_LEAK_WINRM_PASSWORD" not in json.dumps(data)
        credential, target, port, _timeout, scheme = calls[0]
        assert credential.source_name == ENV_NAME
        assert credential.credential_type is CredentialType.PASSWORD
        assert target == "10.10.10.20"
        assert port == 5985
        assert scheme == "http"

    def test_auth_failed_is_data_not_cli_failure(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.AUTH_FAILED, "credentials rejected")
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["verdict"] == "NEGATIVE_EVIDENCE"

    def test_timeout_is_ambiguous_in_json(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.TIMEOUT, "timed out")
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["verdict"] == "AMBIGUOUS"

    def test_tls_failed_maps_to_ok_exit_with_data(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.TLS_FAILED, "certificate verify failed")
        code = main(
            [
                "check", "10.10.10.20", "--port", "5986", "--protocol", "winrm",
                "--winrm-transport", "https",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["status"] == "TLS_FAILED"
        assert data["results"][0]["verdict"] == "VALIDATION_NOT_PERFORMED"

    def test_dns_error_maps_to_resolve_exit(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.DNS_ERROR, "unresolvable")
        code = main(
            [
                "check", "host.invalid", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_RESOLVE

    def test_local_error_maps_to_fatal_exit(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.LOCAL_ERROR, "backend unavailable")
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_FATAL

    def test_text_output_contains_verdict_and_safety_boundary(self, winrm_cred_env, fake_validate, capsys):
        fake_validate(WinRMCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME,
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "WINRM AUTHENTICATION VALIDATION" in out
        assert "AUTHENTICATED" in out
        assert "EXPLICITLY_VALIDATED" in out
        assert "does NOT prove" in out
        assert "DO_NOT_LEAK_WINRM_PASSWORD" not in out

    def test_default_username_is_current_os_user(self, winrm_cred_env, fake_validate, capsys):
        import getpass

        calls = fake_validate(WinRMCheckStatus.AUTHENTICATED)
        main(
            [
                "check", "10.10.10.20", "--port", "5985", "--protocol", "winrm",
                "--credential-env", ENV_NAME, "--json",
            ]
        )
        credential, _target, _port, _timeout, _scheme = calls[0]
        assert credential.username == getpass.getuser()


class TestOtherProtocolRegression:
    def test_tcp_path_unchanged_by_winrm_addition(self, monkeypatch, capsys):
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

    def test_ssh_path_unchanged_by_winrm_addition(self, monkeypatch, capsys):
        from pivotcheck.models.ssh_check import SSHCheckResult, SSHCheckStatus

        def fake_validate_ssh_auth(config, credential):
            return SSHCheckResult(
                target=config.host,
                port=config.port,
                username="operator",
                status=SSHCheckStatus.AUTH_FAILED,
                verdict=__import__(
                    "pivotcheck.models.ssh_check", fromlist=["verdict_for"]
                ).verdict_for(SSHCheckStatus.AUTH_FAILED),
                attempts=1,
            )

        monkeypatch.setenv("PC_TEST_SSH_KEY_ENV", "-----BEGIN OPENSSH PRIVATE KEY-----\nDO_NOT_LEAK_KEY\n")
        monkeypatch.setattr(
            "pivotcheck.cli.validate_ssh_auth", fake_validate_ssh_auth
        )
        monkeypatch.setattr(
            "pivotcheck.cli.run_discovery",
            lambda: DiscoverySnapshot(hostname="", os_name="", networks=()),
        )
        code = main(
            [
                "check", "10.10.10.20", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", "PC_TEST_SSH_KEY_ENV", "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["status"] == "AUTH_FAILED"
