"""Explicit HTTP service validation results (Stage 26 gap program).

Evidence semantics — what a result proves, and what it does NOT:

- HTTP_RESPONSE: one HTTP response was observed from the target at test
  time. This proves ONLY that an HTTP-speaking service responded on this
  port. It proves NOTHING about authorization, authentication state,
  application health, content trust, or exploitability. A 200 response
  is an observation, not a grant; a 401/403 response is an observation,
  not a vulnerability finding.
- CONNECTION_FAILED: the TCP connection to the target failed. Evidence
  about this endpoint at test time — never about general host
  availability.
- TIMEOUT: no response within the bound. AMBIGUOUS by nature: this does
  NOT prove the host is offline or that no HTTP service exists.
- TLS_FAILED: the TLS handshake failed (including certificate
  verification). HTTP validation was NOT performed. Certificates are
  never bypassed and failures are never downgraded.
- PROTOCOL_ERROR: the endpoint responded but not with a valid HTTP
  response. Evidence about the service on this port, not the host.
- DNS_ERROR: the target name could not be resolved.

Exactly one target, one port, one request (HEAD /). No crawling, no
enumeration, no retries, no redirects followed — a redirect response is
reported as the observation it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from pivotcheck import __version__


class HTTPCheckStatus(str, Enum):
    """Outcome classification of one explicit HTTP request."""

    HTTP_RESPONSE = "HTTP_RESPONSE"  # a valid HTTP response was observed
    CONNECTION_FAILED = "CONNECTION_FAILED"  # refused / unreachable / no route
    TIMEOUT = "TIMEOUT"  # ambiguous, by nature
    TLS_FAILED = "TLS_FAILED"  # handshake/certificate failure; never bypassed
    PROTOCOL_ERROR = "PROTOCOL_ERROR"  # response was not valid HTTP
    DNS_ERROR = "DNS_ERROR"
    LOCAL_ERROR = "LOCAL_ERROR"  # local environment failure; outcome unknown


class HTTPVerdict(str, Enum):
    """Evidence-level verdict: what the status actually proves."""

    SERVICE_OBSERVED = "SERVICE_OBSERVED"
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
    AMBIGUOUS = "AMBIGUOUS"
    VALIDATION_NOT_PERFORMED = "VALIDATION_NOT_PERFORMED"


_VERDICT_BY_STATUS: dict[HTTPCheckStatus, HTTPVerdict] = {
    HTTPCheckStatus.HTTP_RESPONSE: HTTPVerdict.SERVICE_OBSERVED,
    HTTPCheckStatus.CONNECTION_FAILED: HTTPVerdict.NEGATIVE_EVIDENCE,
    HTTPCheckStatus.PROTOCOL_ERROR: HTTPVerdict.NEGATIVE_EVIDENCE,
    HTTPCheckStatus.TIMEOUT: HTTPVerdict.AMBIGUOUS,
}

STATUS_LIMITATIONS: dict[HTTPCheckStatus, tuple[str, ...]] = {
    HTTPCheckStatus.HTTP_RESPONSE: (
        "An HTTP response was observed from the target at test time. This does NOT prove authorization, authentication state, application health, content trust, or exploitability.",
    ),
    HTTPCheckStatus.CONNECTION_FAILED: (
        "The TCP connection failed. This is evidence about this endpoint at test time, NOT about general host availability.",
    ),
    HTTPCheckStatus.TIMEOUT: (
        "No response within the timeout. AMBIGUOUS: this does NOT prove the host is offline or that no HTTP service exists on this port.",
    ),
    HTTPCheckStatus.TLS_FAILED: (
        "The TLS handshake failed, so no HTTP request was sent. Certificates are verified and never bypassed; no claim is made about the service.",
    ),
    HTTPCheckStatus.PROTOCOL_ERROR: (
        "The endpoint responded but not with a valid HTTP response. This is evidence about the service on this port, not about the host.",
    ),
}

_DEFAULT_LIMITATION = (
    "Validation did not reach the HTTP request stage, so no claim is made "
    "about the service or the host."
)

REPORT_LIMITATIONS: tuple[str, ...] = (
    (
        "Exactly one target, one port, one HTTP HEAD request to '/'. No crawling, "
        "no enumeration, no retries, no redirects followed (a redirect response "
        "is reported as the observation it is)."
    ),
    (
        "HTTP_RESPONSE never implies authorization, application success, or "
        "content trust; a TCP connection success alone is never reported as an "
        "HTTP observation."
    ),
    "TIMEOUT is ambiguous and never treated as proof of host state.",
    (
        "TLS certificate verification is always enforced for https; verification "
        "failures are reported and never bypassed."
    ),
)


def verdict_for(status: HTTPCheckStatus) -> HTTPVerdict:
    return _VERDICT_BY_STATUS.get(status, HTTPVerdict.VALIDATION_NOT_PERFORMED)


def limitations_for(status: HTTPCheckStatus) -> tuple[str, ...]:
    return STATUS_LIMITATIONS.get(status, (_DEFAULT_LIMITATION,))


@dataclass(frozen=True)
class HTTPCheckResult:
    """Outcome of the single explicit HTTP request."""

    target: str
    port: int
    scheme: str = "http"  # "http" or "https"
    url_path: str = "/"
    protocol: str = "http"
    status: HTTPCheckStatus = HTTPCheckStatus.LOCAL_ERROR
    verdict: HTTPVerdict = HTTPVerdict.VALIDATION_NOT_PERFORMED
    http_status_code: int | None = None
    reason: str | None = None
    server: str | None = None
    content_type: str | None = None
    content_length: str | None = None
    location: str | None = None  # redirect target, when observed; never followed
    tls_verified: bool | None = None  # True for verified https; None for plain http
    detail: str | None = None  # exception class + message; never credential material
    attempts: int = 1
    elapsed_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "scheme": self.scheme,
            "url_path": self.url_path,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "limitations": list(limitations_for(self.status)),
            "http_status_code": self.http_status_code,
            "reason": self.reason,
            "server": self.server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "location": self.location,
            "tls_verified": self.tls_verified,
            "detail": self.detail,
            "attempts": self.attempts,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class HTTPCheckReport:
    """Aggregated report for one HTTP validation command invocation."""

    target: str
    port: int
    timeout_s: float
    results: tuple[HTTPCheckResult, ...]
    limitations: tuple[str, ...] = field(default=REPORT_LIMITATIONS)
    command: str = "check"
    protocol: str = "http"
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
