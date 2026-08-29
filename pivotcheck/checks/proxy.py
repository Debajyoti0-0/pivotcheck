"""SOCKS5 proxy-path validation engine (RFC 1928 + RFC 1929).

Stdlib-only, deliberately minimal: one TCP connection to the proxy,
method negotiation (NO-AUTH / USERNAME-PASSWORD), one CONNECT request
for the operator-supplied destination, then close. No data tunneling,
no UDP ASSOCIATE, no BIND, no chaining, no retries, no scanning.

Destination hostnames are sent to the proxy with ATYP 0x03 (proxy-side
DNS) — they are never resolved locally. Only the proxy endpoint itself
uses the local resolver, via the existing ``resolve_target`` behavior.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import time

from pivotcheck.checks.resolver import resolve_target, validate_target
from pivotcheck.checks.tcp import (
    classify_socket_error,
    validate_port,
    validate_timeout,
)
from pivotcheck.models.check import CheckStatus
from pivotcheck.models.proxy_check import (
    ProxyCheckReport,
    ProxyCheckVerdict,
    ProxyEndpoint,
    ProxyStage,
    ProxyStageName,
    ProxyStageStatus,
    redact_proxy_url,
    status_possible,
)

# Public surface: redact_proxy_url is re-exported here as the single
# redaction entry point for callers of the checks package.
__all__ = ["redact_proxy_url"]

_SOCKS_VERSION = 0x05
_METHOD_NO_AUTH = 0x00
_METHOD_USERNAME_PASSWORD = 0x02
_METHOD_NO_ACCEPTABLE = 0xFF

# RFC 1928 §6 REP byte -> stage status. Single authoritative mapping;
# unknown codes fall back to PROXY_PROTOCOL_ERROR, never success.
_REPLY_CODE_STATUS: dict[int, ProxyStageStatus] = {
    0x00: ProxyStageStatus.SUCCESS,
    0x01: ProxyStageStatus.GENERAL_FAILURE,
    0x02: ProxyStageStatus.NOT_ALLOWED_BY_RULESET,
    0x03: ProxyStageStatus.NETWORK_UNREACHABLE,
    0x04: ProxyStageStatus.HOST_UNREACHABLE,
    0x05: ProxyStageStatus.CONNECTION_REFUSED,
    0x06: ProxyStageStatus.TTL_EXPIRED,
    0x07: ProxyStageStatus.COMMAND_NOT_SUPPORTED,
    0x08: ProxyStageStatus.ADDRESS_TYPE_NOT_SUPPORTED,
}

# CheckStatus (stage-1-compatible transport classification) -> stage
# status. The two enums share names for transport outcomes; this is the
# single mapping point between them.
_CHECK_STATUS_TO_STAGE: dict[CheckStatus, ProxyStageStatus] = {
    CheckStatus.SUCCESS: ProxyStageStatus.SUCCESS,
    CheckStatus.REFUSED: ProxyStageStatus.REFUSED,
    CheckStatus.TIMEOUT: ProxyStageStatus.TIMEOUT,
    CheckStatus.NO_ROUTE: ProxyStageStatus.NO_ROUTE,
    CheckStatus.UNREACHABLE: ProxyStageStatus.UNREACHABLE,
    CheckStatus.DNS_ERROR: ProxyStageStatus.DNS_ERROR,
    CheckStatus.LOCAL_ERROR: ProxyStageStatus.LOCAL_ERROR,
}


class _TruncatedReplyError(ConnectionError):
    """Server closed the connection mid-message (protocol violation)."""


def parse_proxy_url(url: str) -> ProxyEndpoint:
    """Parse ``socks5://[user:pass@]host:port`` into a ProxyEndpoint.

    Strictly limited to the socks5 scheme (SOCKS4/4a, HTTP CONNECT, and
    socks5h-style local-resolution semantics are out of scope). Raises
    ValueError for every deviation.
    """
    stripped = url.strip()
    if not stripped:
        raise ValueError("proxy URL must not be empty")
    scheme, sep, rest = stripped.partition("://")
    if not sep:
        raise ValueError(f"proxy URL requires a scheme: {url!r}")
    if scheme != "socks5":
        raise ValueError(
            f"unsupported proxy scheme {scheme!r}: only socks5:// is supported"
        )
    if not rest:
        raise ValueError("proxy URL requires a host and port")

    # Split userinfo off the authority (last '@' wins: passwords may
    # contain '@'; hosts cannot).
    at_sign = rest.rfind("@")
    userinfo: str | None = None
    if at_sign != -1:
        userinfo = rest[:at_sign]
        rest = rest[at_sign + 1 :]
    if not rest:
        raise ValueError("proxy URL requires a host and port")

    # IPv6 literal: [::1]:1080 ; else host:port
    if rest.startswith("["):
        close = rest.find("]")
        if close == -1:
            raise ValueError(f"unterminated IPv6 literal in proxy URL: {url!r}")
        host = rest[1:close]
        remainder = rest[close + 1 :]
        if not remainder.startswith(":"):
            raise ValueError(f"proxy URL requires a port: {url!r}")
        port_text = remainder[1:]
    else:
        colon = rest.rfind(":")
        if colon == -1:
            raise ValueError(f"proxy URL requires a port: {url!r}")
        host = rest[:colon]
        port_text = rest[colon + 1 :]

    if not host:
        raise ValueError("proxy host must not be empty")
    if "]" in host or host.startswith("["):
        raise ValueError(f"malformed proxy host: {host!r}")

    if not port_text.isdigit():
        raise ValueError(f"invalid proxy port: {port_text!r}")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"proxy port out of range (1-65535): {port}")

    username: str | None = None
    password: str | None = None
    if userinfo is not None:
        user, pwd_sep, pwd = userinfo.partition(":")
        username = user
        password = pwd if pwd_sep else None

    # Validate host as IP literal or RFC 1123 hostname (reuses the
    # destination rules; keeps proxy endpoints equally conservative).
    try:
        validate_target(host)
    except ValueError as exc:
        raise ValueError(f"invalid proxy host: {exc}") from exc

    return ProxyEndpoint(host=host, port=port, username=username, password=password)


def encode_connect_request(target: str, port: int) -> bytes:
    """Encode a SOCKS5 CONNECT request (VER CMD RSV ATYP DST.ADDR DST.PORT).

    IP literals are sent verbatim (ATYP 0x01 / 0x04). Hostnames are sent
    with ATYP 0x03 so the PROXY resolves them — the destination is never
    resolved locally.
    """
    validate_port(port)
    target = validate_target(target)
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # Hostname: proxy-side DNS (ATYP 0x03)
        try:
            encoded = target.encode("ascii")
        except UnicodeEncodeError:
            try:
                encoded = target.encode("idna")
            except UnicodeError as exc:
                raise ValueError(
                    f"destination hostname cannot be encoded: {target!r}"
                ) from exc
        if not 1 <= len(encoded) <= 255:
            raise ValueError(
                f"destination hostname length must be 1-255 bytes: {target!r}"
            )
        return (
            b"\x05\x01\x00\x03"
            + bytes([len(encoded)])
            + encoded
            + struct.pack("!H", port)
        )
    if ip.version == 4:
        return b"\x05\x01\x00\x01" + ip.packed + struct.pack("!H", port)
    return b"\x05\x01\x00\x04" + ip.packed + struct.pack("!H", port)


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Receive exactly ``count`` bytes.

    Raises TimeoutError (socket timeout) or _TruncatedReplyError when the
    peer closes the connection mid-message.
    """
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise _TruncatedReplyError(
                f"connection closed after {len(buf)} of {count} expected bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def check_proxy(
    endpoint: ProxyEndpoint,
    target: str,
    port: int,
    timeout_s: float = 3.0,
) -> ProxyCheckReport:
    """Run the full three-stage SOCKS5 validation.

    Never raises for network-level outcomes; only invalid input raises
    ValueError (before any socket activity).
    """
    validate_port(port)
    validate_timeout(timeout_s)
    validate_target(target)

    # Resolve the PROXY endpoint locally (the destination is never
    # resolved here — hostnames go to the proxy with ATYP 0x03).
    resolved = resolve_target(endpoint.host)
    if resolved.error is not None and not resolved.ok:
        return ProxyCheckReport(
            proxy=endpoint,
            target=target,
            port=port,
            timeout_s=timeout_s,
            stages=(
                ProxyStage(
                    stage=ProxyStageName.PROXY_TCP,
                    status=ProxyStageStatus.DNS_ERROR,
                    detail=resolved.error,
                ),
            ),
            verdict=ProxyCheckVerdict.NOT_VALIDATED,
        )

    connect_address = resolved.addresses[0]
    family = socket.AF_INET6 if ":" in connect_address else socket.AF_INET

    stages: list[ProxyStage] = []
    verdict = ProxyCheckVerdict.NOT_VALIDATED

    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout_s)
    start = time.perf_counter()
    try:
        sock.connect((connect_address, endpoint.port))
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        stages.append(
            ProxyStage(
                stage=ProxyStageName.PROXY_TCP,
                status=ProxyStageStatus.SUCCESS,
                elapsed_ms=elapsed,
            )
        )

        # ---- Stage 2: greeting + method selection (+ optional auth) ----
        if endpoint.username is not None:
            offer = b"\x05\x02\x00\x02"  # methods: NO-AUTH, USERNAME/PASSWORD
        else:
            offer = b"\x05\x01\x00"  # methods: NO-AUTH only
        sock.sendall(offer)
        reply = _recv_exact(sock, 2)
        if reply[0] != _SOCKS_VERSION:
            stages.append(
                _protocol_error(
                    ProxyStageName.SOCKS_NEGOTIATION,
                    f"unexpected SOCKS version {reply[0]} in method reply",
                )
            )
            return _report(endpoint, target, port, timeout_s, stages)
        method = reply[1]
        if method == _METHOD_NO_ACCEPTABLE:
            stages.append(
                ProxyStage(
                    stage=ProxyStageName.SOCKS_NEGOTIATION,
                    status=ProxyStageStatus.NO_ACCEPTABLE_AUTH_METHOD,
                    detail="proxy offered no acceptable authentication "
                    "method (reply 0xFF)",
                )
            )
            return _report(endpoint, target, port, timeout_s, stages)
        if method not in (_METHOD_NO_AUTH, _METHOD_USERNAME_PASSWORD) or (
            method == _METHOD_USERNAME_PASSWORD and endpoint.username is None
        ):
            # Server selected a method we did not offer.
            stages.append(
                _protocol_error(
                    ProxyStageName.SOCKS_NEGOTIATION,
                    f"proxy selected unoffered method 0x{method:02x}",
                )
            )
            return _report(endpoint, target, port, timeout_s, stages)

        negotiation_detail: str | None = None
        if method == _METHOD_USERNAME_PASSWORD:
            assert endpoint.username is not None and endpoint.password is not None
            user = endpoint.username.encode("utf-8")
            pwd = endpoint.password.encode("utf-8")
            sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
            auth_reply = _recv_exact(sock, 2)
            if auth_reply[0] != 0x01:
                stages.append(
                    _protocol_error(
                        ProxyStageName.SOCKS_NEGOTIATION,
                        "unexpected username/password subnegotiation version "
                        f"{auth_reply[0]}",
                    )
                )
                return _report(endpoint, target, port, timeout_s, stages)
            if auth_reply[1] != 0x00:
                stages.append(
                    ProxyStage(
                        stage=ProxyStageName.SOCKS_NEGOTIATION,
                        status=ProxyStageStatus.AUTH_FAILED,
                        detail="proxy rejected credentials (RFC 1929 reply 0x01)",
                    )
                )
                return _report(endpoint, target, port, timeout_s, stages)
        elif endpoint.username is not None:
            # RFC-legal: server picked NO-AUTH from our [NO-AUTH,
            # USERNAME/PASSWORD] offer. Recorded so the result cannot be
            # misread as "authenticated path validated".
            negotiation_detail = (
                "proxy selected NO-AUTH; supplied credentials were not used"
            )

        stages.append(
            ProxyStage(
                stage=ProxyStageName.SOCKS_NEGOTIATION,
                status=ProxyStageStatus.SUCCESS,
                detail=negotiation_detail,
            )
        )

        # ---- Stage 3: CONNECT ----
        sock.sendall(encode_connect_request(target, port))
        head = _recv_exact(sock, 4)
        if head[0] != _SOCKS_VERSION:
            stages.append(
                _protocol_error(
                    ProxyStageName.DESTINATION_CONNECT,
                    f"unexpected SOCKS version {head[0]} in CONNECT reply",
                )
            )
            return _report(endpoint, target, port, timeout_s, stages)
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(sock, 6)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 18)
        else:
            stages.append(
                _protocol_error(
                    ProxyStageName.DESTINATION_CONNECT,
                    f"invalid address type 0x{atyp:02x} in CONNECT reply",
                )
            )
            return _report(endpoint, target, port, timeout_s, stages)

        rep = head[1]
        status = _REPLY_CODE_STATUS.get(rep, ProxyStageStatus.PROXY_PROTOCOL_ERROR)
        stages.append(
            ProxyStage(
                stage=ProxyStageName.DESTINATION_CONNECT,
                status=status,
                reply_code=rep,
                detail=(
                    None
                    if status is ProxyStageStatus.SUCCESS
                    else f"SOCKS5 reply code 0x{rep:02x}"
                ),
            )
        )
        if status is ProxyStageStatus.SUCCESS:
            verdict = ProxyCheckVerdict.VALIDATED
        return _report(endpoint, target, port, timeout_s, stages, verdict)
    except _TruncatedReplyError as exc:
        stages.append(
            _protocol_error(_stage_after(stages), str(exc))
        )
        return _report(endpoint, target, port, timeout_s, stages)
    except OSError as exc:
        elapsed = round((time.perf_counter() - start) * 1000, 1)
        stage = _stage_after(stages)
        mapped = _CHECK_STATUS_TO_STAGE.get(
            classify_socket_error(exc), ProxyStageStatus.LOCAL_ERROR
        )
        if not status_possible(stage, mapped):
            # Deterministic fallback (documented in PROJECT_ARCHITECTURE.md):
            # after the TCP stage, raw transport outcomes such as a
            # mid-exchange connection reset carry no SOCKS5 reply meaning,
            # and the model forbids transport-only statuses there. They are
            # classified PROXY_PROTOCOL_ERROR — never success — with the raw
            # OS error preserved in ``detail`` for the operator.
            mapped = ProxyStageStatus.PROXY_PROTOCOL_ERROR
        stages.append(
            ProxyStage(
                stage=stage,
                status=mapped,
                elapsed_ms=elapsed,
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
        return _report(endpoint, target, port, timeout_s, stages)
    finally:
        sock.close()


def _stage_after(stages: list[ProxyStage]) -> ProxyStageName:
    """The stage a transport error belongs to, given completed stages."""
    completed = {s.stage for s in stages}
    if ProxyStageName.PROXY_TCP not in completed:
        return ProxyStageName.PROXY_TCP
    if ProxyStageName.SOCKS_NEGOTIATION not in completed:
        return ProxyStageName.SOCKS_NEGOTIATION
    return ProxyStageName.DESTINATION_CONNECT


def _protocol_error(stage: ProxyStageName, message: str) -> ProxyStage:
    """Build a PROXY_PROTOCOL_ERROR stage for the given stage."""
    return ProxyStage(
        stage=stage,
        status=ProxyStageStatus.PROXY_PROTOCOL_ERROR,
        detail=message,
    )


def _report(
    endpoint: ProxyEndpoint,
    target: str,
    port: int,
    timeout_s: float,
    stages: list[ProxyStage],
    verdict: ProxyCheckVerdict = ProxyCheckVerdict.NOT_VALIDATED,
) -> ProxyCheckReport:
    return ProxyCheckReport(
        proxy=endpoint,
        target=target,
        port=port,
        timeout_s=timeout_s,
        stages=tuple(stages),
        verdict=verdict,
    )
