"""TCP reachability validation.

Single-address, single-port connection attempts with deliberate error
classification. No scanning, no concurrency, no ranges — one explicit
attempt per call. The caller owns iteration over ports/addresses.
"""

from __future__ import annotations

import errno
import ipaddress
import socket
import time

from pivotcheck.models.check import CheckResult, CheckStatus

# Windows maps network-unreachable conditions to WSAEHOSTUNREACH(10065) /
# WSAENETUNREACH(10051); POSIX uses EHOSTUNREACH / ENETUNREACH.
# ENOROUTE (BSD/macOS) is not defined on all platforms, hence getattr.
_UNREACHABLE_ERRNOS = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
}
_NO_ROUTE_ERRNOS = {
    code
    for code in (
        getattr(errno, "ENOROUTE", None),  # BSD/macOS: no route to host
        getattr(errno, "ENETDOWN", None),
    )
    if code is not None
}


def validate_port(port: int) -> int:
    """Validate a TCP port is within 1-65535."""
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError(f"port must be an integer: {port!r}")  # noqa: TRY004 - ValueError is the documented validation contract (caught by CLI)
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range (1-65535): {port}")
    return port


def validate_timeout(timeout_s: float) -> float:
    """Validate timeout in seconds (0.1-30)."""
    if not isinstance(timeout_s, (int, float)) or isinstance(timeout_s, bool):
        raise ValueError(f"timeout must be a number: {timeout_s!r}")  # noqa: TRY004 - ValueError is the documented validation contract (caught by CLI)
    if not 0.1 <= timeout_s <= 30:
        raise ValueError(f"timeout out of range (0.1-30 seconds): {timeout_s}")
    return float(timeout_s)


def classify_socket_error(exc: OSError) -> CheckStatus:
    """Map a socket error to a precise status where the OS allows it.

    Some failures are inherently ambiguous across platforms; LOCAL_ERROR is
    the honest fallback rather than guessing 'host down'.
    """
    if isinstance(exc, (ConnectionRefusedError,)):
        return CheckStatus.REFUSED
    if isinstance(exc, TimeoutError):
        # Python 3.10+: socket.timeout is an alias of TimeoutError
        return CheckStatus.TIMEOUT
    if exc.errno == errno.ETIMEDOUT:
        # POSIX connect timeouts can surface as raw OSError(ETIMEDOUT)
        return CheckStatus.TIMEOUT
    if exc.errno == 10060:
        # Windows WSAETIMEDOUT (not present in errno on POSIX builds)
        return CheckStatus.TIMEOUT
    if isinstance(exc, PermissionError):
        return CheckStatus.LOCAL_ERROR
    if exc.errno in _NO_ROUTE_ERRNOS:
        return CheckStatus.NO_ROUTE
    if exc.errno in _UNREACHABLE_ERRNOS or exc.errno == errno.ENETDOWN:
        return CheckStatus.UNREACHABLE
    return CheckStatus.LOCAL_ERROR


def check_tcp(
    address: str,
    port: int,
    timeout_s: float = 3.0,
    target: str | None = None,
) -> CheckResult:
    """Attempt one TCP connection and classify the outcome.

    Never raises for network-level outcomes; only invalid inputs raise
    ValueError (before any socket activity).
    """
    validate_port(port)
    validate_timeout(timeout_s)
    try:
        ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError(f"address must be an IP literal: {address!r}") from exc

    result_target = target or address
    sock = socket.socket(
        socket.AF_INET6 if ":" in address else socket.AF_INET,
        socket.SOCK_STREAM,
    )
    sock.settimeout(timeout_s)
    start = time.perf_counter()
    try:
        sock.connect((address, port))
        elapsed_ms = (time.perf_counter() - start) * 1000
        return CheckResult(
            target=result_target,
            address=address,
            port=port,
            status=CheckStatus.SUCCESS,
            elapsed_ms=round(elapsed_ms, 1),
        )
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        status = classify_socket_error(exc)
        # Last-resort heuristic: some platforms raise plain OSError with
        # descriptive text instead of a typed timeout error.
        if status is CheckStatus.LOCAL_ERROR and "timed out" in str(exc).lower():
            status = CheckStatus.TIMEOUT
        return CheckResult(
            target=result_target,
            address=address,
            port=port,
            status=status,
            elapsed_ms=round(elapsed_ms, 1),
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        sock.close()
