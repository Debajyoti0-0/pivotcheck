"""SMB authentication validation results (v2.0 Step 5).

Evidence semantics — what a result proves, and what it does NOT:

- AUTHENTICATED: the supplied credential completed one successful SMB2
  session setup against the target at test time. It proves nothing about
  share access, administrative access, remote execution, file read/write,
  or pivot capability.
- AUTH_FAILED: the SMB service rejected the credential (or refused to
  grant a non-guest session). Evidence about the credential/service
  pairing, NOT about host availability.
- TIMEOUT: no response within the bound. AMBIGUOUS by nature.
- VALIDATION_NOT_PERFORMED (verdict): the attempt never reached the
  authentication stage.

Guest sessions are refused by construction (signing/encryption required),
and a server's guest fallback is classified AUTH_FAILED: the supplied
credential was rejected; a guest session is not authentication.

Exactly one target, one port, one credential, one authentication attempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pivotcheck import __version__


class SMBCheckStatus(str, Enum):
    """Outcome classification of one SMB authentication attempt."""

    AUTHENTICATED = "AUTHENTICATED"
    AUTH_FAILED = "AUTH_FAILED"  # service rejected the credential (incl. guest fallback)
    CONNECTION_FAILED = "CONNECTION_FAILED"  # refused / unreachable / reset
    TIMEOUT = "TIMEOUT"  # ambiguous, by nature
    DNS_ERROR = "DNS_ERROR"
    INVALID_TARGET = "INVALID_TARGET"
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"  # malformed/unusable material
    UNSUPPORTED_CREDENTIAL = "UNSUPPORTED_CREDENTIAL"  # type not supported by backend
    PROTOCOL_ERROR = "PROTOCOL_ERROR"  # SMB negotiation/session protocol failure
    LOCAL_ERROR = "LOCAL_ERROR"  # local environment/backend availability failure


class SMBVerdict(str, Enum):
    """Evidence-level verdict: what the status actually proves."""

    EXPLICITLY_VALIDATED = "EXPLICITLY_VALIDATED"
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
    AMBIGUOUS = "AMBIGUOUS"
    VALIDATION_NOT_PERFORMED = "VALIDATION_NOT_PERFORMED"


_VERDICT_BY_STATUS: dict[SMBCheckStatus, SMBVerdict] = {
    SMBCheckStatus.AUTHENTICATED: SMBVerdict.EXPLICITLY_VALIDATED,
    SMBCheckStatus.AUTH_FAILED: SMBVerdict.NEGATIVE_EVIDENCE,
    SMBCheckStatus.TIMEOUT: SMBVerdict.AMBIGUOUS,
}

STATUS_LIMITATIONS: dict[SMBCheckStatus, tuple[str, ...]] = {
    SMBCheckStatus.AUTHENTICATED: (
        "The supplied credential completed SMB2 session setup at the target at test time. This does NOT prove share access, administrative access, file read/write, remote execution, or pivot capability.",
    ),
    SMBCheckStatus.AUTH_FAILED: (
        "The SMB service rejected this credential (a guest session was refused by PivotCheck). This is evidence about the credential/service pairing, NOT about host availability.",
    ),
    SMBCheckStatus.TIMEOUT: (
        "No response within the bound. AMBIGUOUS: this does NOT prove the host is offline or that authentication would fail.",
    ),
    SMBCheckStatus.INVALID_CREDENTIAL: (
        "The credential material was unusable before authentication was attempted. No claim is made about the service.",
    ),
    SMBCheckStatus.UNSUPPORTED_CREDENTIAL: (
        "This credential type is not supported by the current SMB backend. No claim is made about the service.",
    ),
}

_DEFAULT_LIMITATION = (
    "Validation did not reach the authentication stage, so no claim is made about the credential or the service."
)

REPORT_LIMITATIONS: tuple[str, ...] = (
    "Exactly one target, one port, one credential, one authentication attempt. No scanning, no retries, no credential fallback, no share enumeration, no command execution.",
    "SMB authentication success is NOT share access, administrative access, remote execution, or pivot capability.",
    "TIMEOUT is ambiguous and never treated as proof of host state.",
)


def verdict_for(status: SMBCheckStatus) -> SMBVerdict:
    return _VERDICT_BY_STATUS.get(status, SMBVerdict.VALIDATION_NOT_PERFORMED)


def limitations_for(status: SMBCheckStatus) -> tuple[str, ...]:
    return STATUS_LIMITATIONS.get(status, (_DEFAULT_LIMITATION,))


@dataclass(frozen=True)
class SMBCheckResult:
    """Outcome of the single SMB authentication attempt."""

    target: str
    port: int
    username: str
    protocol: str = "smb"
    status: SMBCheckStatus = SMBCheckStatus.LOCAL_ERROR
    verdict: SMBVerdict = SMBVerdict.VALIDATION_NOT_PERFORMED
    detail: str | None = None  # redacted; never credential material
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
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class SMBCheckReport:
    """Aggregated report for one SMB validation command invocation."""

    target: str
    port: int
    timeout_s: float
    results: tuple[SMBCheckResult, ...]
    limitations: tuple[str, ...] = field(default=REPORT_LIMITATIONS)
    command: str = "check"
    protocol: str = "smb"
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
