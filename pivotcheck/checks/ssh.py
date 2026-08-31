"""SSH authentication validation (v2.0 Step 2).

Converts an already-held SSH private-key credential into one explicit,
bounded authentication attempt against exactly one operator-specified
target:port.

Hard boundary (enforced structurally, not by convention):

- ONE target, ONE port, ONE credential, ONE attempt. No loops, no
  retries, no CIDR/host/port/credential expansion, no scanning.
- The remote side receives only the shell's built-in ``exit`` — this
  proves authentication and channel establishment, nothing more.
- Transport is the system OpenSSH client (the same dependency the
  discovery layer already relies on). No new Python dependencies.
- Host keys: strict verification by default (no AutoAddPolicy);
  accept-new (TOFU) is an explicit operator opt-in. Server-identity
  verification is reported separately from authentication success.

The secret never appears here in any representation: the key material is
written to a temporary file purely because the OpenSSH client requires a
file path, with restrictive permissions, removed deterministically, and
its path is redacted from every surfaced detail string.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from collections.abc import Callable

from pivotcheck.discovery.ssh import HostKeyPolicy, SSHConfig
from pivotcheck.models.credentials import Credential, CredentialType
from pivotcheck.models.ssh_check import (
    SSHCheckResult,
    SSHCheckStatus,
    verdict_for,
)
from pivotcheck.utils.system import CommandResult, run_command

Runner = Callable[..., CommandResult]

# stderr markers, ordered: specific before generic.
_HOST_KEY_MARKERS = ("host key verification failed",)
_UNSUPPORTED_MARKERS = ("passphrase", "passphrase requested")
_INVALID_KEY_MARKERS = (
    "error loading key",
    "error in libcrypto",
    "invalid format",
    "load failed",
    "key_read",
    "not a recognized",
)
_DNS_MARKERS = ("could not resolve hostname", "name or service not known", "no address associated")
_TIMEOUT_MARKERS = ("connection timed out", "timed out")
_REFUSED_MARKERS = ("connection refused",)
_UNREACHABLE_MARKERS = ("no route to host", "network is unreachable", "host is unreachable")
_PROTOCOL_MARKERS = (
    "banner exchange",
    "kex_exchange_identification",
    "no matching key exchange",
    "no matching cipher",
    "remote protocol version",
)
_UNPROTECTED_MARKERS = ("unprotected private key file",)
_AUTH_MARKERS = ("permission denied",)


_TEMPKEY_RE = re.compile(r'[^\s"]*pivotcheck-ssh-key-[^\s"]*')


def _redact_key_path(text: str, key_path: str | None) -> str:
    """Remove the temporary key-file path from surfaced detail strings.

    The real temp path always contains the ``pivotcheck-ssh-key-`` prefix;
    the pattern-based pass also covers paths echoed by ssh that differ from
    the exact string we created.
    """
    text = _TEMPKEY_RE.sub("[keyfile]", text)
    if key_path and key_path in text:
        text = text.replace(key_path, "[keyfile]")
    return text


def _first_marker(text: str, markers: tuple[str, ...]) -> str | None:
    lowered = text.lower()
    for marker in markers:
        if marker in lowered:
            return marker
    return None


def _classify(rc: int, stderr: str) -> tuple[SSHCheckStatus, str | None]:
    """Map an ssh exit code + stderr to a precise, redacted outcome."""
    detail_source = (stderr or "").strip().splitlines()
    detail = detail_source[-1].strip() if detail_source else None

    if rc == 0:
        return SSHCheckStatus.AUTHENTICATED, None

    marker = _first_marker(stderr, _HOST_KEY_MARKERS)
    if marker:
        return SSHCheckStatus.HOST_KEY_UNVERIFIED, f"host key verification failed: {detail}"
    marker = _first_marker(stderr, _UNSUPPORTED_MARKERS)
    if marker:
        detail = (
            "key requires a passphrase; encrypted keys are not supported "
            "in non-interactive validation"
        )
        return (SSHCheckStatus.UNSUPPORTED_CREDENTIAL, detail)
    marker = _first_marker(stderr, _INVALID_KEY_MARKERS)
    if marker:
        return SSHCheckStatus.INVALID_CREDENTIAL, f"key material rejected by ssh client: {detail}"
    if _first_marker(stderr, _UNPROTECTED_MARKERS):
        return SSHCheckStatus.LOCAL_ERROR, "key file permissions rejected by ssh client"
    marker = _first_marker(stderr, _DNS_MARKERS)
    if marker:
        return SSHCheckStatus.DNS_ERROR, detail
    if _first_marker(stderr, _REFUSED_MARKERS):
        return SSHCheckStatus.CONNECTION_FAILED, "connection refused by target"
    marker = _first_marker(stderr, _UNREACHABLE_MARKERS)
    if marker:
        return SSHCheckStatus.CONNECTION_FAILED, detail or "network unreachable"
    marker = _first_marker(stderr, _TIMEOUT_MARKERS)
    if marker:
        return SSHCheckStatus.TIMEOUT, detail or "connection timed out"
    marker = _first_marker(stderr, _PROTOCOL_MARKERS)
    if marker:
        return SSHCheckStatus.CONNECTION_FAILED, f"protocol-level failure: {detail}"
    if _first_marker(stderr, _AUTH_MARKERS):
        return SSHCheckStatus.AUTH_FAILED, "authentication rejected by target"
    if rc == 255:
        return SSHCheckStatus.CONNECTION_FAILED, detail or "ssh transport failure"
    return SSHCheckStatus.LOCAL_ERROR, detail


def _write_temp_key(credential: Credential) -> str:
    """Write key material to a restrictive, temporary key file.

    Filesystem use is deliberate and bounded: the OpenSSH client only
    accepts a key *path*. The file is created with restrictive
    permissions, holds material already memory-resident, and is removed
    by the caller's ``finally`` block.
    """
    fd, path = tempfile.mkstemp(prefix="pivotcheck-ssh-key-")
    try:
        os.chmod(path, 0o600)  # POSIX: owner-only; Windows ACLs apply per profile
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(credential.secret)
            if not credential.secret.endswith("\n"):
                handle.write("\n")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass
        raise
    return path


def _default_runner(argv: list[str], timeout: float) -> CommandResult:
    return run_command(argv, timeout=timeout)


def validate_ssh_auth(
    config: SSHConfig,
    credential: Credential,
    runner: Runner | None = None,
    key_writer: Callable[[Credential], str] | None = None,
) -> SSHCheckResult:
    """Run ONE public-key authentication attempt and classify the outcome.

    Never raises for network/transport outcomes — those are classified
    data. Raises only for structurally invalid inputs (wrong credential
    type) before any activity.

    ``runner`` and ``key_writer`` are injectable for deterministic tests;
    production uses the system ``ssh`` binary via :func:`run_command`
    (sanitized environment, argument-array subprocess, no shell).
    """
    if credential.credential_type is not CredentialType.SSH_PRIVATE_KEY:
        raise ValueError(
            "SSH authentication validation requires an SSH_PRIVATE_KEY credential"
        )

    run = runner or _default_runner
    write_key = key_writer or _write_temp_key

    policy = config.host_key_policy
    connect_timeout = int(config.connect_timeout)
    overall_timeout = config.command_timeout + connect_timeout + 5.0

    target = (
        f"{config.user}@{config.host}" if config.user else config.host
    )
    argv: list[str] = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", f"StrictHostKeyChecking={policy.value}",
    ]
    if config.port != 22:
        argv += ["-p", str(config.port)]

    start = time.perf_counter()
    key_path: str | None = None
    try:
        key_path = write_key(credential)
        argv += ["-i", key_path, target, "--", "exit"]
        try:
            command_result = run(argv, overall_timeout)
        except subprocess.TimeoutExpired:
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            return SSHCheckResult(
                target=config.host,
                port=config.port,
                username=config.user or "",
                status=SSHCheckStatus.TIMEOUT,
                verdict=verdict_for(SSHCheckStatus.TIMEOUT),
                detail=f"validation exceeded {overall_timeout}s overall bound",
                server_identity_verified=None,
                host_key_policy=policy.value if isinstance(policy, HostKeyPolicy) else str(policy),
                elapsed_ms=elapsed,
            )
        status, raw_detail = _classify(command_result.returncode, command_result.stderr)
        detail = _redact_key_path(raw_detail, key_path) if raw_detail else None
        identity_verified: bool | None = None
        if status is SSHCheckStatus.AUTHENTICATED:
            identity_verified = True  # strict/TOFU: connection succeeded only
            # because the host key passed the configured policy
        elif status is SSHCheckStatus.HOST_KEY_UNVERIFIED:
            identity_verified = False
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        policy_value = policy.value if isinstance(policy, HostKeyPolicy) else str(policy)
        return SSHCheckResult(
            target=config.host,
            port=config.port,
            username=config.user or "",
            status=status,
            verdict=verdict_for(status),
            detail=detail,
            server_identity_verified=identity_verified,
            host_key_policy=policy_value,
            attempts=1,
            elapsed_ms=elapsed,
        )
    finally:
        if key_path is not None:
            try:
                os.remove(key_path)
            except OSError:
                pass  # temp key removal is best-effort; OS temp cleanup applies
