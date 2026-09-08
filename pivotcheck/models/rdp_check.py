"""RDP pre-authentication observation results (G-08, Stage 36).

Evidence semantics — what a result proves, and what it does NOT:

- RDP_RESPONSE_OBSERVED: one bounded TPKT/X.224 exchange completed —
  the target answered a Connection Request with a structurally valid
  Connection Confirm. This proves ONLY that an RDP-speaking service
  responded at test time, plus the security protocol the server
  explicitly selected in that response. It does NOT prove authentication,
  authorization, desktop access, session establishment, command
  execution, user validity, or compromise.
- NEGOTIATION_ERROR: the server answered the X.224 exchange with an
  explicit negotiation failure. Evidence about the service's response,
  never about host availability.
- CONNECTION_FAILED / TIMEOUT / DNS_ERROR / TCP_ERROR: transport-level
  outcomes. TIMEOUT is AMBIGUOUS by nature — never host-down. A refused
  connection is evidence about this endpoint at test time, never about
  general host availability.
- MALFORMED_RESPONSE / NOT_RDP_RESPONSE: the endpoint answered, but the
  response is not a structurally valid RDP Connection Confirm. Evidence
  about the service on this port, never an upgrade to RDP evidence.

Exactly one target, one port, one connection, one request, one response.
Zero credentials, zero authentication, zero sessions, zero enumeration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pivotcheck import __version__


class RDPCheckStatus(str, Enum):
    """Outcome classification of one RDP observation attempt."""

    RDP_RESPONSE_OBSERVED = "RDP_RESPONSE_OBSERVED"
    NEGOTIATION_ERROR = "NEGOTIATION_ERROR"  # server sent X.224 negotiation failure
    NOT_RDP_RESPONSE = "NOT_RDP_RESPONSE"  # answer is not RDP traffic
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"  # claims RDP framing but is invalid
    TRUNCATED_RESPONSE = "TRUNCATED_RESPONSE"  # fewer bytes than declared
    CONNECTION_FAILED = "CONNECTION_FAILED"  # refused / unreachable / reset
    TIMEOUT = "TIMEOUT"  # ambiguous, by nature
    DNS_ERROR = "DNS_ERROR"
    TCP_ERROR = "TCP_ERROR"  # other transport-level failure
    INVALID_TARGET = "INVALID_TARGET"
    LOCAL_ERROR = "LOCAL_ERROR"  # local environment failure; outcome unknown


class RDPVerdict(str, Enum):
    """Evidence-level verdict: what the status actually proves."""

    OBSERVED = "OBSERVED"  # a bounded protocol observation was made
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"  # about this endpoint/service
    AMBIGUOUS = "AMBIGUOUS"
    VALIDATION_NOT_PERFORMED = "VALIDATION_NOT_PERFORMED"


_VERDICT_BY_STATUS: dict[RDPCheckStatus, RDPVerdict] = {
    RDPCheckStatus.RDP_RESPONSE_OBSERVED: RDPVerdict.OBSERVED,
    RDPCheckStatus.NEGOTIATION_ERROR: RDPVerdict.NEGATIVE_EVIDENCE,
    RDPCheckStatus.NOT_RDP_RESPONSE: RDPVerdict.NEGATIVE_EVIDENCE,
    RDPCheckStatus.MALFORMED_RESPONSE: RDPVerdict.NEGATIVE_EVIDENCE,
    RDPCheckStatus.TRUNCATED_RESPONSE: RDPVerdict.NEGATIVE_EVIDENCE,
    RDPCheckStatus.CONNECTION_FAILED: RDPVerdict.NEGATIVE_EVIDENCE,
    RDPCheckStatus.TIMEOUT: RDPVerdict.AMBIGUOUS,
}

STATUS_LIMITATIONS: dict[RDPCheckStatus, tuple[str, ...]] = {
    RDPCheckStatus.RDP_RESPONSE_OBSERVED: (
        "The target returned a structurally valid X.224 Connection Confirm at test time: an RDP-speaking service responded on this port. This does NOT prove authentication, authorization, desktop access, session establishment, command execution, user validity, or compromise. The reported security protocol is what the server selected in this exchange \u2014 not a capability inventory.",
    ),
    RDPCheckStatus.NEGOTIATION_ERROR: (
        "The target explicitly rejected the connection request (X.224 negotiation failure). Evidence about the service's response at test time, NOT about host availability.",
    ),
    RDPCheckStatus.NOT_RDP_RESPONSE: (
        "The endpoint answered but the response is not RDP traffic. This is evidence about the service on this port, never an upgrade to RDP evidence.",
    ),
    RDPCheckStatus.MALFORMED_RESPONSE: (
        "The response claimed RDP framing but was structurally invalid. Fail-closed: no RDP evidence is manufactured from malformed input.",
    ),
    RDPCheckStatus.TRUNCATED_RESPONSE: (
        "The response ended before the declared structure was complete. Fail-closed: no RDP evidence is manufactured from partial data.",
    ),
    RDPCheckStatus.CONNECTION_FAILED: (
        "The TCP connection failed. Evidence about this endpoint at test time, NOT about general host availability.",
    ),
    RDPCheckStatus.TIMEOUT: (
        "No response within the bound. AMBIGUOUS: this does NOT prove the host is offline, that the port is closed, or that RDP is absent.",
    ),
    RDPCheckStatus.TCP_ERROR: (
        "A transport-level failure occurred. Evidence about this connection attempt only.",
    ),
}

_DEFAULT_LIMITATION = (
    "The observation never reached a server response, so no claim is made about the service or the host."
)

REPORT_LIMITATIONS: tuple[str, ...] = (
    (
        "Exactly one target, one port, one connection, one request, one response. "
        "No credentials, no authentication, no session establishment, no "
        "enumeration, no retries, no protocol fallback."
    ),
    (
        "RDP_RESPONSE_OBSERVED is a pre-authentication protocol observation \u2014 "
        "never authentication, authorization, desktop access, command "
        "execution, or proof of compromise."
    ),
    "TIMEOUT is ambiguous and never treated as proof of host state.",
    (
        "The security protocol reported (if any) is what the server selected in "
        "this single exchange; it is not a capability inventory."
    ),
)


def verdict_for(status: RDPCheckStatus) -> RDPVerdict:
    return _VERDICT_BY_STATUS.get(status, RDPVerdict.VALIDATION_NOT_PERFORMED)


def limitations_for(status: RDPCheckStatus) -> tuple[str, ...]:
    return STATUS_LIMITATIONS.get(status, (_DEFAULT_LIMITATION,))


@dataclass(frozen=True)
class RDPCheckResult:
    """Outcome of the single RDP pre-authentication observation."""

    target: str
    port: int
    protocol: str = "rdp"
    status: RDPCheckStatus = RDPCheckStatus.LOCAL_ERROR
    verdict: RDPVerdict = RDPVerdict.VALIDATION_NOT_PERFORMED
    negotiated_protocol: str | None = None  # server-selected protocol, verbatim
    detail: str | None = None  # redacted exception classification; never credential material
    attempts: int = 1
    elapsed_ms: float | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError(f"invalid port: {self.port}")
        if self.attempts not in (0, 1):
            raise ValueError(f"attempts must be 0 or 1 (one-attempt contract): {self.attempts}")

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "limitations": list(limitations_for(self.status)),
            "negotiated_protocol": self.negotiated_protocol,
            "detail": self.detail,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class RDPCheckReport:
    """Aggregated report for one RDP observation command invocation."""

    target: str
    port: int
    timeout_s: float
    results: tuple[RDPCheckResult, ...]
    limitations: tuple[str, ...] = field(default=REPORT_LIMITATIONS)
    command: str = "check"
    protocol: str = "rdp"
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
