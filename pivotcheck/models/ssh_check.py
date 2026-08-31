"""SSH authentication validation results (v2.0 Step 2).

Evidence semantics — what a result proves, and what it does NOT:

- AUTHENTICATED: the supplied SSH private-key credential completed one
  successful public-key authentication against the SSH service at the
  target at test time. It proves nothing about command execution
  capability, file access, privilege level, or persistence of access.
- AUTH_FAILED: the SSH service actively rejected the credential. This is
  evidence about the *credential*, not about host availability.
- TIMEOUT: no response within the bound. AMBIGUOUS by nature.
- HOST_KEY_UNVERIFIED: the server's identity could not be verified, so
  authentication was not performed. These are separate facts and are
  reported separately: authentication success and server-identity
  verification are independent claims.
- VALIDATION_NOT_PERFORMED (verdict): the attempt never reached the
  authentication stage.

Exactly one target, one port, one credential, one attempt. No scanning,
no retries, no command execution (the remote side sees only the shell's
built-in ``exit``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pivotcheck import __version__


class SSHCheckStatus(str, Enum):
    """Outcome classification of one SSH authentication attempt."""

    AUTHENTICATED = "AUTHENTICATED"
    AUTH_FAILED = "AUTH_FAILED"  # service rejected the credential
    CONNECTION_FAILED = "CONNECTION_FAILED"  # refused / unreachable / no route
    TIMEOUT = "TIMEOUT"  # ambiguous, by nature
    DNS_ERROR = "DNS_ERROR"
    INVALID_TARGET = "INVALID_TARGET"
    HOST_KEY_UNVERIFIED = "HOST_KEY_UNVERIFIED"  # identity unconfirmed
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"  # malformed key material
    UNSUPPORTED_CREDENTIAL = "UNSUPPORTED_CREDENTIAL"  # e.g. encrypted key
    LOCAL_ERROR = "LOCAL_ERROR"  # local ssh client/environment failure


class SSHVerdict(str, Enum):
    """Evidence-level verdict: what the status actually proves."""

    EXPLICITLY_VALIDATED = "EXPLICITLY_VALIDATED"
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
    AMBIGUOUS = "AMBIGUOUS"
    VALIDATION_NOT_PERFORMED = "VALIDATION_NOT_PERFORMED"


_VERDICT_BY_STATUS: dict[SSHCheckStatus, SSHVerdict] = {
    SSHCheckStatus.AUTHENTICATED: SSHVerdict.EXPLICITLY_VALIDATED,
    SSHCheckStatus.AUTH_FAILED: SSHVerdict.NEGATIVE_EVIDENCE,
    SSHCheckStatus.TIMEOUT: SSHVerdict.AMBIGUOUS,
}

STATUS_LIMITATIONS: dict[SSHCheckStatus, tuple[str, ...]] = {
    SSHCheckStatus.AUTHENTICATED: (
        "The supplied credential authenticated to the SSH service at the target at test time. This does NOT prove command execution capability, file access, privilege level, or future access.",
    ),
    SSHCheckStatus.AUTH_FAILED: (
        "The SSH service rejected this credential. This is evidence about the credential/target pairing, NOT about host availability.",
    ),
    SSHCheckStatus.TIMEOUT: (
        "No response within the timeout. AMBIGUOUS: this does NOT prove the host is offline or that authentication would fail.",
    ),
    SSHCheckStatus.HOST_KEY_UNVERIFIED: (
        "The server's identity could not be verified against known_hosts, so authentication was not attempted. No claim is made about the credential or the service.",
    ),
}

_DEFAULT_LIMITATION = (
    "Validation did not reach the authentication stage, so no claim is made about the credential or the service."
)

REPORT_LIMITATIONS: tuple[str, ...] = (
    "Exactly one target, one port, one credential, one authentication attempt. No scanning, no retries, no command execution.",
    "Authentication success and server-identity verification are separate facts and are reported separately.",
    "TIMEOUT is ambiguous and never treated as proof of host state.",
)


def verdict_for(status: SSHCheckStatus) -> SSHVerdict:
    return _VERDICT_BY_STATUS.get(status, SSHVerdict.VALIDATION_NOT_PERFORMED)


def limitations_for(status: SSHCheckStatus) -> tuple[str, ...]:
    return STATUS_LIMITATIONS.get(status, (_DEFAULT_LIMITATION,))


@dataclass(frozen=True)
class SSHCheckResult:
    """Outcome of the single SSH authentication attempt."""

    target: str
    port: int
    username: str
    protocol: str = "ssh"
    status: SSHCheckStatus = SSHCheckStatus.LOCAL_ERROR
    verdict: SSHVerdict = SSHVerdict.VALIDATION_NOT_PERFORMED
    detail: str | None = None  # redacted; never credential material
    server_identity_verified: bool | None = None
    host_key_policy: str = "strict"
    attempts: int = 1
    elapsed_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "username": self.username,
            "protocol": self.protocol,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "limitations": list(limitations_for(self.status)),
            "detail": self.detail,
            "server_identity_verified": self.server_identity_verified,
            "host_key_policy": self.host_key_policy,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class SSHCheckReport:
    """Aggregated report for one SSH validation command invocation."""

    target: str
    port: int
    timeout_s: float
    results: tuple[SSHCheckResult, ...]
    limitations: tuple[str, ...] = field(default=REPORT_LIMITATIONS)
    command: str = "check"
    protocol: str = "ssh"
    schema_version: str = "1.1"
    timestamp: str = ""
    perspective_hostname: str = ""
    perspective_session_id: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "tool": "pivotcheck",
            "version": __version__,
            "command": self.command,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "perspective": {
                "hostname": self.perspective_hostname,
                "session_id": self.perspective_session_id,
            },
            "target": self.target,
            "port": self.port,
            "timeout_s": self.timeout_s,
            "results": [r.to_dict() for r in self.results],
            "limitations": list(self.limitations),
        }
