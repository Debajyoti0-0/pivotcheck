"""Result models for SOCKS5 proxy-path validation.

Presentation-independent models consumed by terminal and JSON output.
Mirrors the semantics discipline of :mod:`pivotcheck.models.check`:

- stage outcomes are classified precisely (never collapsed into "failure"),
- the verdict is only VALIDATED when every stage succeeded,
- credentials are structurally excluded from serialization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ProxyCheckVerdict(str, Enum):
    """Overall verdict of one proxy-check invocation.

    VALIDATED means exactly: the proxy accepted TCP, completed SOCKS5
    negotiation (including authentication when required), and accepted the
    CONNECT request for the operator-supplied destination. It never means
    general reachability, pivot capability, or arbitrary forwarding.
    """

    VALIDATED = "VALIDATED"
    NOT_VALIDATED = "NOT_VALIDATED"


class ProxyStageName(str, Enum):
    """The three validation stages, in execution order."""

    PROXY_TCP = "proxy_tcp"
    SOCKS_NEGOTIATION = "socks5_negotiation"
    DESTINATION_CONNECT = "destination_connect"


class ProxyStageStatus(str, Enum):
    """Precise outcome classification per stage.

    Stage 1 (proxy TCP) mirrors CheckStatus semantics. Stage 2 covers
    SOCKS5 method negotiation and RFC 1929 authentication. Stage 3
    preserves SOCKS5 CONNECT reply codes verbatim. PROXY_PROTOCOL_ERROR
    is the deterministic fallback for malformed/unknown protocol bytes —
    never treated as success.
    """

    # Stage 1: proxy TCP connection (CheckStatus-compatible values)
    SUCCESS = "SUCCESS"
    REFUSED = "REFUSED"
    TIMEOUT = "TIMEOUT"
    NO_ROUTE = "NO_ROUTE"
    UNREACHABLE = "UNREACHABLE"
    DNS_ERROR = "DNS_ERROR"
    LOCAL_ERROR = "LOCAL_ERROR"

    # Stage 2: SOCKS5 negotiation / authentication
    PROXY_PROTOCOL_ERROR = "PROXY_PROTOCOL_ERROR"
    NO_ACCEPTABLE_AUTH_METHOD = "NO_ACCEPTABLE_AUTH_METHOD"
    AUTH_FAILED = "AUTH_FAILED"

    # Stage 3: SOCKS5 CONNECT reply codes (RFC 1928 §6)
    GENERAL_FAILURE = "GENERAL_FAILURE"
    NOT_ALLOWED_BY_RULESET = "NOT_ALLOWED_BY_RULESET"
    NETWORK_UNREACHABLE = "NETWORK_UNREACHABLE"
    HOST_UNREACHABLE = "HOST_UNREACHABLE"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    TTL_EXPIRED = "TTL_EXPIRED"
    COMMAND_NOT_SUPPORTED = "COMMAND_NOT_SUPPORTED"
    ADDRESS_TYPE_NOT_SUPPORTED = "ADDRESS_TYPE_NOT_SUPPORTED"


# Which statuses are semantically possible per stage. The model enforces
# this so an impossible combination (e.g. AUTH_FAILED on the TCP stage)
# can never be constructed, serialized, or rendered.
_STAGE_ALLOWED_STATUS: dict[ProxyStageName, frozenset[ProxyStageStatus]] = {
    ProxyStageName.PROXY_TCP: frozenset(
        {
            ProxyStageStatus.SUCCESS,
            ProxyStageStatus.REFUSED,
            ProxyStageStatus.TIMEOUT,
            ProxyStageStatus.NO_ROUTE,
            ProxyStageStatus.UNREACHABLE,
            ProxyStageStatus.DNS_ERROR,
            ProxyStageStatus.LOCAL_ERROR,
        }
    ),
    ProxyStageName.SOCKS_NEGOTIATION: frozenset(
        {
            ProxyStageStatus.SUCCESS,
            ProxyStageStatus.TIMEOUT,
            ProxyStageStatus.PROXY_PROTOCOL_ERROR,
            ProxyStageStatus.NO_ACCEPTABLE_AUTH_METHOD,
            ProxyStageStatus.AUTH_FAILED,
        }
    ),
    ProxyStageName.DESTINATION_CONNECT: frozenset(
        {
            ProxyStageStatus.SUCCESS,
            ProxyStageStatus.TIMEOUT,
            ProxyStageStatus.PROXY_PROTOCOL_ERROR,
            ProxyStageStatus.GENERAL_FAILURE,
            ProxyStageStatus.NOT_ALLOWED_BY_RULESET,
            ProxyStageStatus.NETWORK_UNREACHABLE,
            ProxyStageStatus.HOST_UNREACHABLE,
            ProxyStageStatus.CONNECTION_REFUSED,
            ProxyStageStatus.TTL_EXPIRED,
            ProxyStageStatus.COMMAND_NOT_SUPPORTED,
            ProxyStageStatus.ADDRESS_TYPE_NOT_SUPPORTED,
        }
    ),
}

_REQUIRED_STAGES: tuple[ProxyStageName, ...] = (
    ProxyStageName.PROXY_TCP,
    ProxyStageName.SOCKS_NEGOTIATION,
    ProxyStageName.DESTINATION_CONNECT,
)

_PROXY_CHECK_LIMITATION = (
    "This result validates only the explicitly requested SOCKS5 CONNECT "
    "attempt from the supplied proxy to the supplied destination at the "
    "time of testing. It does not prove general network reachability, "
    "pivot capability, or arbitrary forwarding."
)


@dataclass(frozen=True)
class ProxyEndpoint:
    """A validated SOCKS5 proxy endpoint supplied by the operator.

    Credentials (when present) are kept for the protocol engine only.
    Serialization (:meth:`to_dict`, :attr:`display_url`) is redacted by
    construction: the password never leaves this object.
    """

    host: str
    port: int
    username: str | None = None
    password: str | None = None

    def __post_init__(self) -> None:
        if not self.host or not self.host.strip():
            raise ValueError("proxy host must not be empty")
        if "/" in self.host:
            raise ValueError(f"CIDR notation is not a valid proxy host: {self.host!r}")
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError(f"proxy port must be an integer: {self.port!r}")  # noqa: TRY004 - ValueError is the documented validation contract (caught by CLI)
        if not 1 <= self.port <= 65535:
            raise ValueError(f"proxy port out of range (1-65535): {self.port}")
        has_user = self.username is not None
        has_pass = self.password is not None
        if has_pass and not has_user:
            raise ValueError("proxy password requires a username")
        if has_user and has_pass:
            if not self.username or not self.password:
                raise ValueError("proxy username and password must be non-empty")
            if len(self.username.encode("utf-8")) > 255 or len(self.password.encode("utf-8")) > 255:
                raise ValueError(
                    "proxy username and password must be at most 255 bytes each (RFC 1929)"
                )

    @property
    def display_url(self) -> str:
        """Redacted URL form; safe for text output and logs."""
        host_part = f"[{self.host}]" if ":" in self.host else self.host
        if self.username is not None:
            return f"socks5://{self.username}:***@{host_part}:{self.port}"
        return f"socks5://{host_part}:{self.port}"

    def to_dict(self) -> dict:
        """Redacted serialization: scheme/host/port plus a credential flag."""
        return {
            "scheme": "socks5",
            "host": self.host,
            "port": self.port,
            "has_credentials": self.username is not None,
        }

    def __repr__(self) -> str:
        """Redacted representation for debugging; password never exposed."""
        if self.username is not None:
            return f"ProxyEndpoint(host={self.host!r}, port={self.port}, username={self.username!r}, password=***)"
        return f"ProxyEndpoint(host={self.host!r}, port={self.port})"


def redact_proxy_url(endpoint: ProxyEndpoint) -> str:
    """Public redaction helper (single authoritative form)."""
    return endpoint.display_url


def status_possible(stage: ProxyStageName, status: ProxyStageStatus) -> bool:
    """Whether ``status`` is a semantically possible outcome for ``stage``.

    Single authoritative check used by the protocol engine to keep its
    fallback classification inside the frozen stage/status model.
    """
    return status in _STAGE_ALLOWED_STATUS[stage]


@dataclass(frozen=True)
class ProxyStage:
    """Outcome of one proxy-check stage."""

    stage: ProxyStageName
    status: ProxyStageStatus
    detail: str | None = None
    elapsed_ms: float | None = None
    reply_code: int | None = None  # SOCKS5 REP byte; DESTINATION_CONNECT only

    def __post_init__(self) -> None:
        if self.status not in _STAGE_ALLOWED_STATUS[self.stage]:
            raise ValueError(
                f"status {self.status.value} is not possible for stage "
                f"{self.stage.value}"
            )
        if self.reply_code is not None:
            if self.stage is not ProxyStageName.DESTINATION_CONNECT:
                raise ValueError(
                    "reply_code is only defined for the destination_connect stage"
                )
            if not isinstance(self.reply_code, int) or isinstance(self.reply_code, bool):
                raise ValueError(f"reply_code must be an integer: {self.reply_code!r}")
            if not 0 <= self.reply_code <= 255:
                raise ValueError(f"reply_code out of range (0-255): {self.reply_code}")

    def to_dict(self) -> dict:
        return {
            "stage": self.stage.value,
            "status": self.status.value,
            "detail": self.detail,
            "elapsed_ms": self.elapsed_ms,
            "reply_code": self.reply_code,
        }


@dataclass(frozen=True)
class ProxyCheckReport:
    """Complete staged result of one proxy-check invocation."""

    proxy: ProxyEndpoint
    target: str
    port: int
    timeout_s: float
    stages: tuple[ProxyStage, ...]
    verdict: ProxyCheckVerdict
    timestamp: str = ""
    perspective_hostname: str = ""
    perspective_session_id: str = ""

    def __post_init__(self) -> None:
        if not self.stages:
            raise ValueError("a proxy-check report requires at least one stage")
        # Stages must appear exactly once, in execution order.
        seen: list[ProxyStageName] = []
        for stage in self.stages:
            if stage.stage in seen:
                raise ValueError(f"duplicate stage: {stage.stage.value}")
            seen.append(stage.stage)
        expected = [s for s in _REQUIRED_STAGES if s in seen]
        if seen != expected:
            raise ValueError(
                "stages must be in execution order "
                "(proxy_tcp, socks5_negotiation, destination_connect)"
            )
        all_success = len(seen) == len(_REQUIRED_STAGES) and all(
            s.status is ProxyStageStatus.SUCCESS for s in self.stages
        )
        if self.verdict is ProxyCheckVerdict.VALIDATED and not all_success:
            raise ValueError(
                "VALIDATED requires all three stages to have succeeded"
            )
        if self.verdict is ProxyCheckVerdict.NOT_VALIDATED and all_success:
            raise ValueError(
                "NOT_VALIDATED is inconsistent with all-success stages"
            )

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.1",
            "tool": "pivotcheck",
            "version": _version(),
            "command": "proxy-check",
            "timestamp": self.timestamp,
            "perspective": {
                "hostname": self.perspective_hostname,
                "session_id": self.perspective_session_id,
            },
            "proxy": self.proxy.to_dict(),
            "target": {"host": self.target, "port": self.port},
            "timeout_s": self.timeout_s,
            "stages": [s.to_dict() for s in self.stages],
            "verdict": self.verdict.value,
            "limitation": _PROXY_CHECK_LIMITATION,
        }


def _version() -> str:
    from pivotcheck import __version__

    return __version__
