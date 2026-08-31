"""WinRM authentication validation results (v2.0 Step 6).

Evidence semantics — what a result proves, and what it does NOT:

- AUTHENTICATED: the supplied credential completed one successful WS-Man
  authentication against the WinRM service at the target at test time
  (a read-only service-configuration Get operation). It proves nothing
  about PowerShell access, command execution, filesystem access, service
  creation, privilege level, or pivot capability.
- AUTH_FAILED: the WinRM service rejected the credential. Evidence about
  the credential/service pairing, NOT about host availability.
- TLS_FAILED: the HTTPS transport failed certificate/TLS verification.
  Distinct from authentication failure: no claim about the credential.
- TIMEOUT: no response within the bound. AMBIGUOUS by nature.
- VALIDATION_NOT_PERFORMED (verdict): the attempt never reached the
  authentication stage.

Exactly one target, one port, one credential, one authentication attempt
(one WS-Man request). No shells, no commands, no retries, no fallbacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pivotcheck import __version__


class WinRMCheckStatus(str, Enum):
    """Outcome classification of one WinRM authentication attempt."""

    AUTHENTICATED = "AUTHENTICATED"
    AUTH_FAILED = "AUTH_FAILED"  # service rejected the credential
    CONNECTION_FAILED = "CONNECTION_FAILED"  # refused / unreachable / reset
    TIMEOUT = "TIMEOUT"  # ambiguous, by nature
    DNS_ERROR = "DNS_ERROR"
    INVALID_TARGET = "INVALID_TARGET"
    TLS_FAILED = "TLS_FAILED"  # HTTPS certificate/TLS verification failure
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"  # unusable material
    UNSUPPORTED_CREDENTIAL = "UNSUPPORTED_CREDENTIAL"  # type not supported
    PROTOCOL_ERROR = "PROTOCOL_ERROR"  # WS-Man protocol failure
    LOCAL_ERROR = "LOCAL_ERROR"  # local backend/environment failure


class WinRMVerdict(str, Enum):
    """Evidence-level verdict: what the status actually proves."""

    EXPLICITLY_VALIDATED = "EXPLICITLY_VALIDATED"
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
    AMBIGUOUS = "AMBIGUOUS"
    VALIDATION_NOT_PERFORMED = "VALIDATION_NOT_PERFORMED"


_VERDICT_BY_STATUS: dict[WinRMCheckStatus, WinRMVerdict] = {
    WinRMCheckStatus.AUTHENTICATED: WinRMVerdict.EXPLICITLY_VALIDATED,
    WinRMCheckStatus.AUTH_FAILED: WinRMVerdict.NEGATIVE_EVIDENCE,
    WinRMCheckStatus.TIMEOUT: WinRMVerdict.AMBIGUOUS,
}

STATUS_LIMITATIONS: dict[WinRMCheckStatus, tuple[str, ...]] = {
    WinRMCheckStatus.AUTHENTICATED: (
        "The supplied credential completed WS-Man authentication against the WinRM service at the target at test time. This does NOT prove PowerShell access, command execution, filesystem access, service creation, privilege level, or pivot capability.",
    ),
    WinRMCheckStatus.AUTH_FAILED: (
        "The WinRM service rejected this credential. This is evidence about the credential/service pairing, NOT about host availability.",
    ),
    WinRMCheckStatus.TIMEOUT: (
        "No response within the bound. AMBIGUOUS: this does NOT prove the host is offline or that authentication would fail.",
    ),
    WinRMCheckStatus.TLS_FAILED: (
        "The HTTPS transport failed certificate/TLS verification. No claim is made about the credential: authentication was not reached.",
    ),
    WinRMCheckStatus.INVALID_CREDENTIAL: (
        "The credential material was unusable before authentication was attempted. No claim is made about the service.",
    ),
    WinRMCheckStatus.UNSUPPORTED_CREDENTIAL: (
        "This credential type is not supported by the current WinRM backend. No claim is made about the service.",
    ),
}

_DEFAULT_LIMITATION = (
    "Validation did not reach the authentication stage, so no claim is made about the credential or the service."
)

REPORT_LIMITATIONS: tuple[str, ...] = (
    "Exactly one target, one port, one credential, one authentication attempt (one WS-Man request). No scanning, no retries, no credential fallback, no shells, no command execution.",
    "WinRM authentication success is NOT PowerShell access, command execution, administrative access, remote execution, or pivot capability.",
    "TIMEOUT is ambiguous and never treated as proof of host state.",
    "Server-identity/TLS verification and authentication success are separate facts and are reported separately.",
)


def verdict_for(status: WinRMCheckStatus) -> WinRMVerdict:
    return _VERDICT_BY_STATUS.get(status, WinRMVerdict.VALIDATION_NOT_PERFORMED)


def limitations_for(status: WinRMCheckStatus) -> tuple[str, ...]:
    return STATUS_LIMITATIONS.get(status, (_DEFAULT_LIMITATION,))


@dataclass(frozen=True)
class WinRMCheckResult:
    """Outcome of the single WinRM authentication attempt."""

    target: str
    port: int
    username: str
    protocol: str = "winrm"
    transport_scheme: str = "http"
    status: WinRMCheckStatus = WinRMCheckStatus.LOCAL_ERROR
    verdict: WinRMVerdict = WinRMVerdict.VALIDATION_NOT_PERFORMED
    detail: str | None = None  # redacted; never credential material
    attempts: int = 1
    elapsed_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "username": self.username,
            "protocol": self.protocol,
            "transport_scheme": self.transport_scheme,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "limitations": list(limitations_for(self.status)),
            "detail": self.detail,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class WinRMCheckReport:
    """Aggregated report for one WinRM validation command invocation."""

    target: str
    port: int
    timeout_s: float
    results: tuple[WinRMCheckResult, ...]
    limitations: tuple[str, ...] = field(default=REPORT_LIMITATIONS)
    command: str = "check"
    protocol: str = "winrm"
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
