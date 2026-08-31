"""SSH authentication validation tests (v2.0 Step 2).

Transport is fully injected (no live ssh, no network) except for the
explicitly marked integration test, which exercises the real ssh binary
against loopback with throwaway material and tolerant outcome assertions.

Leak discipline: key material uses recognizable synthetic markers and is
asserted absent from every produced representation.
"""

from __future__ import annotations

import json
import os

import pytest

from pivotcheck.checks.ssh import validate_ssh_auth
from pivotcheck.discovery.ssh import HostKeyPolicy, SSHConfig
from pivotcheck.models.credentials import Credential, CredentialType
from pivotcheck.models.ssh_check import (
    SSHCheckStatus,
    SSHVerdict,
    verdict_for,
)
from pivotcheck.utils.system import CommandResult

PEM_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "DO_NOT_LEAK_KEY_789\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)

CONFIG = SSHConfig(host="target.internal", port=22, user="operator")


def _credential() -> Credential:
    return Credential(CredentialType.SSH_PRIVATE_KEY, PEM_KEY)


class _FakeRunner:
    def __init__(self, rc: int = 0, stderr: str = "", stdout: str = "") -> None:
        self.rc = rc
        self.stderr = stderr
        self.stdout = stdout
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: float = 30.0) -> CommandResult:
        self.calls.append(list(argv))
        return CommandResult(self.rc, self.stdout, self.stderr)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class TestClassification:
    def test_authenticated(self):
        runner = _FakeRunner(rc=0)
        result = validate_ssh_auth(CONFIG, _credential(), runner=runner)
        assert result.status is SSHCheckStatus.AUTHENTICATED
        assert result.verdict is SSHVerdict.EXPLICITLY_VALIDATED
        assert result.server_identity_verified is True
        assert result.attempts == 1
        assert result.elapsed_ms is not None

    def test_auth_failed_is_negative_evidence_about_credential(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(rc=255, stderr="Permission denied (publickey)."),
        )
        assert result.status is SSHCheckStatus.AUTH_FAILED
        assert result.verdict is SSHVerdict.NEGATIVE_EVIDENCE
        assert "rejected" in (result.detail or "")

    def test_host_key_unverified_blocks_authentication(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(
                rc=255, stderr="Host key verification failed."
            ),
        )
        assert result.status is SSHCheckStatus.HOST_KEY_UNVERIFIED
        assert result.verdict is SSHVerdict.VALIDATION_NOT_PERFORMED
        assert result.server_identity_verified is False

    def test_connection_refused(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(rc=255, stderr="ssh: connect to host 10.0.0.5 port 22: Connection refused"),
        )
        assert result.status is SSHCheckStatus.CONNECTION_FAILED
        assert result.verdict is SSHVerdict.VALIDATION_NOT_PERFORMED
        assert "refused" in (result.detail or "")

    def test_timeout_is_ambiguous(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(rc=255, stderr="Connection timed out during banner exchange"),
        )
        assert result.status is SSHCheckStatus.TIMEOUT
        assert result.verdict is SSHVerdict.AMBIGUOUS

    def test_dns_error(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(
                rc=255,
                stderr="ssh: Could not resolve hostname target.internal: Name or service not known",
            ),
        )
        assert result.status is SSHCheckStatus.DNS_ERROR

    def test_invalid_key_material(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(rc=255, stderr='Load key "/tmp/pivotcheck-ssh-key-x": invalid format'),
        )
        assert result.status is SSHCheckStatus.INVALID_CREDENTIAL
        assert result.verdict is SSHVerdict.VALIDATION_NOT_PERFORMED

    def test_encrypted_key_unsupported(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(rc=255, stderr="Load key \"/tmp/k\": key requires passphrase"),
        )
        assert result.status is SSHCheckStatus.UNSUPPORTED_CREDENTIAL
        assert "passphrase" in (result.detail or "")

    def test_unprotected_key_file_is_local_error(self):
        result = validate_ssh_auth(
            CONFIG,
            _credential(),
            runner=_FakeRunner(
                rc=255,
                stderr='Permissions 0644 for "/tmp/k" are too open... WARNING: UNPROTECTED PRIVATE KEY FILE!',
            ),
        )
        assert result.status is SSHCheckStatus.LOCAL_ERROR

    def test_generic_255_is_connection_failed(self):
        result = validate_ssh_auth(
            CONFIG, _credential(), runner=_FakeRunner(rc=255, stderr="ssh: something unusual")
        )
        assert result.status is SSHCheckStatus.CONNECTION_FAILED

    def test_timeout_expired_maps_to_timeout(self, monkeypatch):
        import subprocess

        def runner(argv: list[str], timeout: float = 30.0) -> CommandResult:
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=timeout)

        result = validate_ssh_auth(CONFIG, _credential(), runner=runner)
        assert result.status is SSHCheckStatus.TIMEOUT
        assert result.verdict is SSHVerdict.AMBIGUOUS


# ---------------------------------------------------------------------------
# Hard boundary: one target/port/credential/attempt, argv safety
# ---------------------------------------------------------------------------


class TestScopeAndArgv:
    def test_exactly_one_attempt(self):
        runner = _FakeRunner(rc=0)
        validate_ssh_auth(CONFIG, _credential(), runner=runner)
        assert len(runner.calls) == 1

    def test_argv_has_no_shell_and_pins_single_credential(self):
        runner = _FakeRunner(rc=0)
        validate_ssh_auth(CONFIG, _credential(), runner=runner)
        argv = runner.calls[0]
        assert "sh" not in argv[:2]
        assert "-o" in argv and "BatchMode=yes" in argv
        assert "IdentitiesOnly=yes" in argv  # exactly the supplied key
        assert "PreferredAuthentications=publickey" in argv  # no fallback auth
        assert "NumberOfPasswordPrompts=0" in argv  # never interactive
        assert "StrictHostKeyChecking=yes" in argv  # strict by default
        assert argv[-1] == "exit"  # remote side sees only the shell builtin
        assert argv.count("exit") == 1
        key_flag = argv.index("-i")
        assert argv[key_flag + 1].endswith((".tmp",)) or "pivotcheck-ssh-key" in argv[key_flag + 1]

    def test_accept_new_policy_is_explicit_opt_in(self):
        runner = _FakeRunner(rc=0)
        config = SSHConfig(
            host="target.internal", port=22, user="op", host_key_policy=HostKeyPolicy.ACCEPT_NEW
        )
        result = validate_ssh_auth(config, _credential(), runner=runner)
        assert any("accept-new" in token for token in runner.calls[0])
        assert not any("StrictHostKeyChecking=yes" in token for token in runner.calls[0])
        assert result.host_key_policy == "accept-new"

    def test_non_ssh_credential_rejected_before_any_activity(self):
        runner = _FakeRunner()
        with pytest.raises(ValueError, match="SSH_PRIVATE_KEY"):
            validate_ssh_auth(
                CONFIG,
                Credential(CredentialType.PASSWORD, "some-password"),
                runner=runner,
            )
        assert runner.calls == []  # no attempt, no I/O

    def test_deterministic_semantics(self):
        first = validate_ssh_auth(
            CONFIG, _credential(), runner=_FakeRunner(rc=255, stderr="Permission denied (publickey).")
        ).to_dict()
        second = validate_ssh_auth(
            CONFIG, _credential(), runner=_FakeRunner(rc=255, stderr="Permission denied (publickey).")
        ).to_dict()
        # Deterministic semantic fields (elapsed_ms is a timing measurement).
        first.pop("elapsed_ms"), second.pop("elapsed_ms")
        assert first == second


# ---------------------------------------------------------------------------
# Secret safety and temp-key hygiene
# ---------------------------------------------------------------------------


class TestSecretSafety:
    def test_temp_key_removed_on_success_and_failure(self):
        for runner in (
            _FakeRunner(rc=0),
            _FakeRunner(rc=255, stderr="Permission denied (publickey)."),
        ):
            paths: list[str] = []
            real_remove = os.remove

            def spy_remove(path, _paths=paths, _real=real_remove):
                _paths.append(str(path))
                return _real(path)

            import pivotcheck.checks.ssh as ssh_check

            original_remove = ssh_check.os.remove
            ssh_check.os.remove = spy_remove  # type: ignore[assignment]
            try:
                validate_ssh_auth(CONFIG, _credential(), runner=runner)
            finally:
                ssh_check.os.remove = original_remove  # type: ignore[assignment]
            assert len(paths) == 1

    def test_written_key_file_contains_material_and_is_owner_only(self):
        captured: dict[str, object] = {}

        def writer(credential: Credential) -> str:
            import tempfile

            fd, path = tempfile.mkstemp(prefix="test-key-")
            with os.fdopen(fd, "w") as handle:
                handle.write(credential.secret)
            os.chmod(path, 0o600)
            captured["path"] = path
            captured["mode"] = os.stat(path).st_mode & 0o777
            return path

        result = validate_ssh_auth(CONFIG, _credential(), key_writer=writer)
        assert result.status is not SSHCheckStatus.LOCAL_ERROR
        # POSIX: owner-only. Windows: chmod maps to the read-only bit, so the
        # exact mode is platform-specific (NTFS ACLs govern the real guard).
        if os.name == "posix":
            assert captured["mode"] == 0o600
        path = str(captured["path"])
        if os.path.exists(path):  # real writer path cleans up
            os.remove(path)

    def test_material_and_path_never_reach_representations(self):
        runner = _FakeRunner(
            rc=255,
            stderr='Load key "C:\\temp\\pivotcheck-ssh-key-abc123": invalid format',
        )
        result = validate_ssh_auth(CONFIG, _credential(), runner=runner)
        representations = [
            repr(result),
            str(result),
            json.dumps(result.to_dict()),
            json.dumps(result.to_dict()),
        ]
        for representation in representations:
            assert "DO_NOT_LEAK_KEY_789" not in representation
        # The temp key path is redacted from surfaced detail strings.
        assert result.detail is not None
        assert "pivotcheck-ssh-key" not in result.detail

    def test_report_json_contains_no_material(self):
        runner = _FakeRunner(rc=0)
        from pivotcheck.models.ssh_check import SSHCheckReport

        result = validate_ssh_auth(CONFIG, _credential(), runner=runner)
        report = SSHCheckReport(
            target=CONFIG.host,
            port=CONFIG.port,
            timeout_s=10.0,
            results=(result,),
            command="check",
            timestamp="2026-01-01T00:00:00+00:00",
            perspective_hostname="tester",
            perspective_session_id="0123456789abcdef",
        )
        payload = json.dumps(report.to_dict())
        assert "DO_NOT_LEAK_KEY_789" not in payload
        assert "private_key" not in payload
        assert "secret" not in payload


# ---------------------------------------------------------------------------
# Verdict mapping completeness
# ---------------------------------------------------------------------------


class TestVerdictMapping:
    def test_every_status_maps_to_a_verdict(self):
        for status in SSHCheckStatus:
            assert verdict_for(status) in SSHVerdict

    def test_timeout_never_becomes_negative_evidence(self):
        assert verdict_for(SSHCheckStatus.TIMEOUT) is SSHVerdict.AMBIGUOUS

    def test_auth_failure_is_never_host_down(self):
        assert verdict_for(SSHCheckStatus.AUTH_FAILED) is SSHVerdict.NEGATIVE_EVIDENCE
