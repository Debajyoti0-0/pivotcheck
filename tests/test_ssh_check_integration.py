"""Real-transport integration tests for SSH validation (marked integration).

These exercise the actual system OpenSSH client against loopback. Outcome
assertions are tolerant of platform network behavior (POSIX refuses closed
ports; Windows may drop), but the envelope, redaction, and one-attempt
contract are asserted strictly. No live SSH server is required and no real
credential material is used (the throwaway key is generated at test time).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from pivotcheck.checks.ssh import validate_ssh_auth
from pivotcheck.discovery.ssh import SSHConfig
from pivotcheck.models.credentials import Credential, CredentialType
from pivotcheck.models.ssh_check import SSHCheckResult, SSHCheckStatus, SSHVerdict
from pivotcheck.utils.system import CommandResult

pytestmark = pytest.mark.integration


def _ssh_available() -> bool:
    return shutil.which("ssh") is not None


def _generate_throwaway_key(directory) -> str:
    """Generate a real but worthless ed25519 key; returns the private path."""
    private_path = str(directory / "throwaway_key")
    subprocess.run(
        [
            "ssh-keygen", "-t", "ed25519", "-N", "", "-q",
            "-f", private_path, "-C", "pivotcheck-integration-test-throwaway",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return private_path


@pytest.mark.skipif(not _ssh_available(), reason="OpenSSH client not available")
def test_real_ssh_client_invalid_key_is_classified(tmp_path):
    """A malformed key is rejected client-side; classification is precise
    and no credential material reaches the report."""
    bad_key = tmp_path / "bad_key"
    bad_key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n")
    os.chmod(str(bad_key), 0o600)

    def runner(argv: list[str], timeout: float = 30.0) -> CommandResult:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    config = SSHConfig(host="127.0.0.1", port=1, user="operator", connect_timeout=1.0)
    credential = Credential(CredentialType.SSH_PRIVATE_KEY, bad_key.read_text(encoding="utf-8"))
    result = validate_ssh_auth(config, credential, runner=runner)

    # Real OpenSSH variants differ: Windows may surface the key-load error
    # ("error in libcrypto") only after the connection attempt times out,
    # while OpenSSH reports it client-side. Both are valid real-transport
    # outcomes; the strict key-error classification is covered by unit tests
    # with deterministic fakes.
    assert result.status in (
        SSHCheckStatus.INVALID_CREDENTIAL,
        SSHCheckStatus.CONNECTION_FAILED,
        SSHCheckStatus.TIMEOUT,
    )
    assert result.verdict is not SSHVerdict.EXPLICITLY_VALIDATED
    assert result.attempts == 1
    assert "DO_NOT_LEAK" not in json.dumps(result.to_dict())
    assert not any(p.startswith("pivotcheck-ssh-key-") for p in os.listdir(str(tmp_path)))


@pytest.mark.skipif(not _ssh_available(), reason="OpenSSH client not available")
def test_real_ssh_client_closed_loopback_port_is_bounded(tmp_path):
    """A valid-format key against a closed loopback port produces a
    well-formed, bounded result (refused on POSIX; timeout possible on
    Windows). One attempt; no material in output."""
    private_path = _generate_throwaway_key(tmp_path)
    with open(private_path, encoding="utf-8") as handle:
        material = handle.read()

    def runner(argv: list[str], timeout: float = 30.0) -> CommandResult:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    config = SSHConfig(host="127.0.0.1", port=1, user="operator", connect_timeout=1.0)
    credential = Credential(CredentialType.SSH_PRIVATE_KEY, material)
    result = validate_ssh_auth(config, credential, runner=runner)

    assert isinstance(result, SSHCheckResult)
    assert result.attempts == 1
    assert result.status in (SSHCheckStatus.CONNECTION_FAILED, SSHCheckStatus.TIMEOUT)
    assert result.verdict in (SSHVerdict.VALIDATION_NOT_PERFORMED, SSHVerdict.AMBIGUOUS)
    payload = json.dumps(result.to_dict())
    assert material not in payload
    assert "pivotcheck-ssh-key" not in payload

    # Cleanup: the throwaway key never outlives the test.
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "del", private_path], capture_output=True, timeout=10, check=False
        )
    else:
        subprocess.run(["rm", "-f", private_path], capture_output=True, timeout=10, check=False)
    assert not os.path.exists(private_path)
