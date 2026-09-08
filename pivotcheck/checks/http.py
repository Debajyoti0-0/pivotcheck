"""Explicit HTTP service validation.

One operator-selected target, one explicit port, one HTTP HEAD request to
a single URL path. No crawling, no enumeration, no retries, no redirects
followed, no credential material, no command execution. TLS certificates
are verified and never bypassed; verification failure is a reported
outcome, never a downgrade.

Observation, not overclaim: an HTTP_RESPONSE is evidence that an
HTTP-speaking service responded on this port at test time. It is NOT
authorization, application success, or content trust. TIMEOUT is
ambiguous and never host-down proof.

The HTTP transport is injectable for deterministic testing; the default
transport performs exactly one request over one socket.
"""

from __future__ import annotations

import socket
import ssl
import time
from collections.abc import Callable

from pivotcheck.checks.tcp import classify_socket_error, validate_port, validate_timeout
from pivotcheck.models.check import CheckStatus
from pivotcheck.models.http_check import HTTPCheckResult, HTTPCheckStatus, verdict_for

_MAX_RESPONSE_BYTES = 65536

_STATUS_BY_SOCKET_CLASS: dict[CheckStatus, HTTPCheckStatus] = {
    CheckStatus.REFUSED: HTTPCheckStatus.CONNECTION_FAILED,
    CheckStatus.NO_ROUTE: HTTPCheckStatus.CONNECTION_FAILED,
    CheckStatus.UNREACHABLE: HTTPCheckStatus.CONNECTION_FAILED,
    CheckStatus.TIMEOUT: HTTPCheckStatus.TIMEOUT,
    CheckStatus.LOCAL_ERROR: HTTPCheckStatus.LOCAL_ERROR,
}


class HTTPProtocolError(Exception):
    """The endpoint responded but not with a valid HTTP response."""


class HTTPTransportResponse:
    """Minimal transport-level view of one HTTP response."""

    __slots__ = ("headers", "reason", "status_code")

    def __init__(
        self, status_code: int, reason: str, headers: list[tuple[str, str]]
    ) -> None:
        self.status_code = status_code
        self.reason = reason
        self.headers = headers

    def header(self, name: str) -> str | None:
        """Case-insensitive first-header lookup."""
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None


Transport = Callable[[str, int, str, bytes, float], HTTPTransportResponse]


def validate_host(host: str) -> str:
    """Validate a hostname/IP-literal target (no scheme, path, or userinfo).

    The ``check`` command validates one host:port. URLs, paths, and
    credentials are deliberately not accepted in the host field.
    """
    if not isinstance(host, str) or not host.strip():
        raise ValueError(f"host must be a non-empty string: {host!r}")
    host = host.strip()
    if "://" in host:
        raise ValueError(
            f"host must be a bare hostname or IP literal, not a URL: {host!r}"
        )
    if "/" in host or "@" in host or any(c.isspace() for c in host):
        raise ValueError(f"host must be a bare hostname or IP literal: {host!r}")
    return host


def _default_transport(
    host: str, port: int, scheme: str, request_bytes: bytes, timeout_s: float
) -> HTTPTransportResponse:
    """Perform exactly one HTTP request over one fresh socket.

    Transport failures propagate as OSError for classification; a
    response that is not valid HTTP raises HTTPProtocolError.
    """
    sock = socket.socket(
        socket.AF_INET6 if ":" in host else socket.AF_INET,
        socket.SOCK_STREAM,
    )
    sock.settimeout(timeout_s)
    try:
        sock.connect((host, port))
        if scheme == "https":
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(request_bytes)
                raw = _read_response(tls)
        else:
            sock.sendall(request_bytes)
            raw = _read_response(sock)
    finally:
        sock.close()
    return _parse_response(raw)


def _read_response(sock: socket.socket) -> bytes:
    """Read a bounded HTTP response (headers + capped remainder) once."""
    chunks: list[bytes] = []
    total = 0
    while total < _MAX_RESPONSE_BYTES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    return b"".join(chunks)


def _parse_response(raw: bytes) -> HTTPTransportResponse:
    """Parse one raw HTTP response; raise HTTPProtocolError if not HTTP."""
    text = raw.decode("iso-8859-1")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    if not lines:
        raise HTTPProtocolError("empty response")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise HTTPProtocolError("response is not valid HTTP")
    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise HTTPProtocolError("response is not valid HTTP") from exc
    reason = parts[2] if len(parts) == 3 else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers.append((key.strip(), value.strip()))
    return HTTPTransportResponse(status_code, reason, headers)


def _status_from_socket_error(exc: OSError) -> HTTPCheckStatus:
    """Reuse the TCP errno classification; map to HTTP check statuses."""
    if isinstance(exc, socket.gaierror):
        return HTTPCheckStatus.DNS_ERROR
    mapped = _STATUS_BY_SOCKET_CLASS.get(classify_socket_error(exc))
    return mapped if mapped is not None else HTTPCheckStatus.LOCAL_ERROR


def _error_result(
    host: str,
    port: int,
    scheme: str,
    url_path: str,
    target: str,
    status: HTTPCheckStatus,
    exc: Exception,
    elapsed_ms: float,
    tls_verified: bool | None = None,
) -> HTTPCheckResult:
    return HTTPCheckResult(
        target=target,
        port=port,
        scheme=scheme,
        url_path=url_path,
        status=status,
        verdict=verdict_for(status),
        detail=f"{type(exc).__name__}: {exc}",
        tls_verified=tls_verified,
        elapsed_ms=round(elapsed_ms, 1),
    )


def check_http(
    host: str,
    port: int,
    timeout_s: float = 3.0,
    scheme: str = "http",
    url_path: str = "/",
    target: str | None = None,
    transport: Transport | None = None,
) -> HTTPCheckResult:
    """Attempt one explicit HTTP request and classify the outcome.

    Never raises for network-level outcomes; only invalid inputs raise
    ValueError (before any network activity). Exactly one request is
    sent; a redirect response is reported as observed and never followed.
    """
    validate_port(port)
    validate_timeout(timeout_s)
    if scheme not in ("http", "https"):
        raise ValueError(f"scheme must be 'http' or 'https': {scheme!r}")
    if not url_path.startswith("/"):
        raise ValueError(f"url_path must start with '/': {url_path!r}")
    result_target = validate_host(target) if target is not None else validate_host(host)

    request = (
        f"HEAD {url_path} HTTP/1.1\r\n"
        f"Host: {result_target}:{port}\r\n"
        "User-Agent: pivotcheck\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("iso-8859-1")

    transport_fn: Transport = transport if transport is not None else _default_transport
    start = time.perf_counter()
    try:
        response = transport_fn(host, port, scheme, request, timeout_s)
    except HTTPProtocolError as exc:
        return _error_result(
            host,
            port,
            scheme,
            url_path,
            result_target,
            HTTPCheckStatus.PROTOCOL_ERROR,
            exc,
            (time.perf_counter() - start) * 1000,
        )
    except ssl.SSLError as exc:
        return _error_result(
            host,
            port,
            scheme,
            url_path,
            result_target,
            HTTPCheckStatus.TLS_FAILED,
            exc,
            (time.perf_counter() - start) * 1000,
            tls_verified=False,
        )
    except OSError as exc:
        return _error_result(
            host,
            port,
            scheme,
            url_path,
            result_target,
            _status_from_socket_error(exc),
            exc,
            (time.perf_counter() - start) * 1000,
        )

    elapsed_ms = (time.perf_counter() - start) * 1000
    return HTTPCheckResult(
        target=result_target,
        port=port,
        scheme=scheme,
        url_path=url_path,
        status=HTTPCheckStatus.HTTP_RESPONSE,
        verdict=verdict_for(HTTPCheckStatus.HTTP_RESPONSE),
        http_status_code=response.status_code,
        reason=response.reason or None,
        server=response.header("Server"),
        content_type=response.header("Content-Type"),
        content_length=response.header("Content-Length"),
        location=response.header("Location"),
        tls_verified=True if scheme == "https" else None,
        elapsed_ms=round(elapsed_ms, 1),
    )
