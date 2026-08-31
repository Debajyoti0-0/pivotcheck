"""CLI tests for SSH authentication validation via `check --protocol ssh`.

Follows the existing check-CLI test architecture: inject fakes at the cli
module boundary, invoke main(), assert exit codes + output contracts.
"""

from __future__ import annotations

import json

import pytest

from pivotcheck import __version__
from pivotcheck.cli import EXIT_OK, EXIT_RESOLVE, EXIT_USAGE, main
from pivotcheck.discovery.ssh import SSHConfig
from pivotcheck.models.credentials import Credential
from pivotcheck.models.ssh_check import SSHCheckResult, SSHCheckStatus

PEM_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "DO_NOT_LEAK_KEY_789\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
ENV_NAME = "PC_TEST_SSH_KEY_ENV"


def _make_result(status: SSHCheckStatus, detail: str | None = None) -> SSHCheckResult:
    from pivotcheck.models.ssh_check import verdict_for

    identity = True if status is SSHCheckStatus.AUTHENTICATED else (
        False if status is SSHCheckStatus.HOST_KEY_UNVERIFIED else None
    )
    return SSHCheckResult(
        target="target.internal",
        port=22,
        username="operator",
        status=status,
        verdict=verdict_for(status),
        detail=detail,
        server_identity_verified=identity,
        host_key_policy="strict",
        attempts=1,
        elapsed_ms=12.5,
    )


@pytest.fixture()
def ssh_key_env(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv(ENV_NAME, PEM_KEY)
    return ENV_NAME


@pytest.fixture()
def fake_validate(monkeypatch: pytest.MonkeyPatch):
    def _install(status: SSHCheckStatus, detail: str | None = None):
        calls: list[tuple] = []

        def fake_validate(config: SSHConfig, credential: Credential):
            calls.append((config, credential))
            return _make_result(status, detail)

        monkeypatch.setattr("pivotcheck.cli.validate_ssh_auth", fake_validate)
        return calls

    return _install


# ---------------------------------------------------------------------------
# Usage / preconditions
# ---------------------------------------------------------------------------


class TestSSHUsage:
    def test_missing_ssh_key_env_is_usage(self, capsys):
        code = main(["check", "target.internal", "--port", "22", "--protocol", "ssh"])
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "--ssh-key-env" in err

    def test_port_list_rejected_for_ssh(self, ssh_key_env, capsys):
        code = main(
            [
                "check", "target.internal", "--port", "22,8443",
                "--protocol", "ssh", "--ssh-key-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        assert "one target, one port" in capsys.readouterr().err

    def test_baseline_rejected_for_ssh(self, ssh_key_env, fake_validate, capsys):
        """--baseline is TCP-context semantics; SSH validation must refuse it."""
        fake_validate(SSHCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME, "--baseline", "pre-pivot",
            ]
        )
        assert code == EXIT_USAGE
        assert "--baseline" in capsys.readouterr().err

    def test_missing_env_variable_is_usage(self, monkeypatch, capsys):
        monkeypatch.delenv(ENV_NAME, raising=False)
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        assert ENV_NAME in capsys.readouterr().err

    def test_invalid_env_name_is_usage(self, capsys):
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", "bad name with spaces",
            ]
        )
        assert code == EXIT_USAGE

    def test_invalid_target_rejected_before_any_activity(self, ssh_key_env, capsys):
        code = main(
            [
                "check", "bad host name!", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME,
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "Invalid SSH target" in err


# ---------------------------------------------------------------------------
# Executed outcomes (faked transport)
# ---------------------------------------------------------------------------


class TestSSHCheckOutcomes:
    def test_authenticated_json_envelope(self, ssh_key_env, fake_validate, capsys):
        calls = fake_validate(SSHCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["tool"] == "pivotcheck"
        assert data["version"] == __version__
        assert data["command"] == "check"
        assert data["protocol"] == "ssh"
        assert data["schema_version"] == "1.1"
        result = data["results"][0]
        assert result["status"] == "AUTHENTICATED"
        assert result["verdict"] == "EXPLICITLY_VALIDATED"
        assert result["server_identity_verified"] is True
        assert result["attempts"] == 1
        assert data["limitations"]
        assert "DO_NOT_LEAK_KEY_789" not in json.dumps(data)
        # The credential was handed to the validator with provenance intact.
        config, credential = calls[0]
        assert isinstance(config, SSHConfig)
        assert config.port == 22
        assert credential.source_name == ENV_NAME

    def test_auth_failed_is_data_not_cli_failure(self, ssh_key_env, fake_validate, capsys):
        fake_validate(SSHCheckStatus.AUTH_FAILED, "authentication rejected by target")
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["verdict"] == "NEGATIVE_EVIDENCE"

    def test_timeout_is_ambiguous_in_json(self, ssh_key_env, fake_validate, capsys):
        fake_validate(SSHCheckStatus.TIMEOUT, "no response")
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["verdict"] == "AMBIGUOUS"

    def test_dns_error_maps_to_resolve_exit(self, ssh_key_env, fake_validate, capsys):
        fake_validate(SSHCheckStatus.DNS_ERROR, "could not resolve hostname")
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME, "--json",
            ]
        )
        assert code == EXIT_RESOLVE
        data = json.loads(capsys.readouterr().out)
        assert data["results"][0]["status"] == "DNS_ERROR"

    def test_text_output_contains_verdict_and_limits(self, ssh_key_env, fake_validate, capsys):
        fake_validate(SSHCheckStatus.AUTHENTICATED)
        code = main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME,
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "SSH AUTHENTICATION VALIDATION" in out
        assert "AUTHENTICATED" in out
        assert "EXPLICITLY_VALIDATED" in out
        assert "does NOT prove" in out
        assert "DO_NOT_LEAK_KEY_789" not in out

    def test_default_username_is_current_os_user(self, ssh_key_env, fake_validate, capsys):
        calls = fake_validate(SSHCheckStatus.AUTHENTICATED)
        main(
            [
                "check", "target.internal", "--port", "22", "--protocol", "ssh",
                "--ssh-key-env", ENV_NAME, "--json",
            ]
        )
        config, _credential = calls[0]
        assert config.user  # resolved to the current OS user
        import getpass

        assert config.user == getpass.getuser()


# ---------------------------------------------------------------------------
# TCP protocol regression (default path unchanged)
# ---------------------------------------------------------------------------


class TestTcpProtocolRegression:
    def test_protocol_defaults_to_tcp_and_port_lists_still_work(self, monkeypatch, capsys):
        from pivotcheck.models.check import CheckResult, CheckStatus

        def fake_check_tcp(address, port, timeout_s, target=None):
            return CheckResult(
                target=target or address,
                address=address,
                port=port,
                status=CheckStatus.REFUSED,
                elapsed_ms=1.0,
            )

        monkeypatch.setattr("pivotcheck.cli.check_tcp", fake_check_tcp)
        monkeypatch.setattr("pivotcheck.cli.run_discovery", lambda: __import__(
            "pivotcheck.models.result", fromlist=["DiscoverySnapshot"]
        ).DiscoverySnapshot(hostname="", os_name="", networks=()))
        code = main(["check", "127.0.0.1", "--port", "80,81", "--json"])
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["protocol"] == "tcp"
        assert len(data["results"]) == 2
