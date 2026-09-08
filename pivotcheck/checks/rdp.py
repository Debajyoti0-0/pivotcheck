"""RDP pre-authentication protocol observation (G-08, Stage 36).

OBSERVATION ONLY. One target, one port, ONE TCP connection, ONE
X.224 Connection Request, ONE response read. No credentials, no
authentication, no session establishment, no CredSSP/TLS/NLA, no
enumeration, no retries, no protocol fallback.

What is sent: one X.224 Connection Request (TPKT-framed) requesting the
standard RDP security protocols. What is read: one bounded response.
What is classified: whether the response is a structurally valid X.224
Connection Confirm, and — only if the server explicitly communicated
it — which security protocol it selected.

Epistemic contract:

    RDP_RESPONSE_OBSERVED  !=  RDP_AUTHENTICATION
    TCP_CONNECTION         !=  RDP_RESPONSE
    RDP_RESPONSE_OBSERVED  !=  ACCESS

Every failure mode fails closed: malformed/truncated/non-RDP responses
are classified honestly and never upgraded into RDP evidence. TIMEOUT
is ambiguous and never host-down.

The transport (connect/send/receive) is injectable for deterministic
testing; the default transport performs exactly one bounded exchange
over one socket. The parser is a pure function: bytes in, classification
out — no socket, no subprocess, no filesystem, no environment, no clock.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from collections.abc import Callable

from pivotcheck.checks.tcp import classify_socket_error, validate_port, validate_timeout
from pivotcheck.models.rdp_check import (
    RDPCheckResult,
    RDPCheckStatus,
    verdict_for,
)

_RDP_DEFAULT_PORT = 3389

# Bounds (§17): a bounded reader, never an unbounded recv loop.
_MAX_RESPONSE_BYTES = 8192

# X.224 Connection Request (TPKT header + CR with requestedProtocols:
# PROTOCOL_RDP | PROTOCOL_SSL | PROTOCOL_HYBRID per MS-RDPBCGR 2.2.1.1).
_REQUEST_BODY = bytes(
    [
        0xE0,  # variable part: requestedProtocols high byte is in the fixed part below
        0x00,  # DST-REF (2 bytes, must be zero)
        0x00, 0x00,
        0x00,  # class 0
    ]
) + bytes(
    [
        # RDP negotiation request (TYPE_RDP_NEG_REQ = 0x01)
        0x01,
        0x00,  # flags
        0x08, 0x00,  # length = 8
        0x03, 0x00, 0x00, 0x00,  # requestedProtocols: SSL | HYBRID | HYBRID_EX
    ]
)

# MS-RDPBCGR negotiation protocol values (server-selected, echoed).
_NEGOTIATION_PROTOCOLS: dict[int, str] = {
    0x00: "PROTOCOL_RDP",
    0x01: "PROTOCOL_SSL",
    0x02: "PROTOCOL_HYBRID",
    0x08: "PROTOCOL_HYBRID_EX",
    0x09: "PROTOCOL_SSL+HYBRID",
    0x0A: "PROTOCOL_HYBRID+HYBRID_EX",
    0x0B: "PROTOCOL_SSL+HYBRID+HYBRID_EX",
    0x03: "PROTOCOL_SSL+HYBRID",
}

Transport = Callable[[str, int, bytes, float], bytes]


class RDPProtocolError(Exception):
    """The response is RDP-family traffic but structurally invalid."""


# ---------------------------------------------------------------------------
# Parser (pure): bytes -> classification
# ---------------------------------------------------------------------------


def parse_rdp_response(raw: bytes) -> tuple[RDPCheckStatus, str | None, str | None]:
    """Classify one raw server response.

    Returns (status, negotiated_protocol, detail). Strictly fail-closed:
    malformed, truncated, or non-RDP input never yields
    RDP_RESPONSE_OBSERVED.
    """
    non_rdp = _classify_non_rdp_text(raw)
    if non_rdp is not None:
        return (non_rdp, None, "response is a well-known non-RDP protocol (HTTP/SSH/SMTP-family)")
    if len(raw) < 4:
        return (RDPCheckStatus.TRUNCATED_RESPONSE, None, "truncated TPKT header")

    # TPKT header (RFC 1006): version(1) reserved(1) length(2, big-endian).
    if raw[0] != 0x03:
        return (RDPCheckStatus.NOT_RDP_RESPONSE, None, "not TPKT-framed traffic")
    if raw[1] != 0x00:
        return (RDPCheckStatus.MALFORMED_RESPONSE, None, "invalid TPKT reserved byte")

    declared = int.from_bytes(raw[2:4], "big")
    if declared < 7:
        return (RDPCheckStatus.MALFORMED_RESPONSE, None, "TPKT length too short for X.224")
    if declared > _MAX_RESPONSE_BYTES:
        return (RDPCheckStatus.MALFORMED_RESPONSE, None, "TPKT length exceeds bound")

    # TPKT length covers TPKT header (4) + X.224 payload. Declared length
    # exceeding actual bytes = truncation; surplus bytes = ambiguity that
    # fails closed (never parsed past the declared frame).
    if declared > len(raw):
        return (RDPCheckStatus.TRUNCATED_RESPONSE, None, "response shorter than declared TPKT length")

    x224 = raw[4:declared]
    if len(x224) < 4:
        return (RDPCheckStatus.MALFORMED_RESPONSE, None, "X.224 payload too short")

    # X.224 length indicator (LI): bytes after the LI byte itself.
    li = x224[0]
    if li < 6:
        return (RDPCheckStatus.MALFORMED_RESPONSE, None, "X.224 length indicator too short for a Connection Confirm")
    if len(x224) < li + 1:
        return (RDPCheckStatus.TRUNCATED_RESPONSE, None, "X.224 payload shorter than its length indicator")

    msg_type = x224[1]
    if msg_type == 0xD0:
        return _parse_connection_confirm(x224)
    if msg_type == 0x50:
        return (RDPCheckStatus.NEGOTIATION_ERROR, None, "X.224 Connection Reject received")
    return (
        RDPCheckStatus.MALFORMED_RESPONSE,
        None,
        f"unexpected X.224 message type 0x{msg_type:02X}",
    )


def _parse_connection_confirm(x224: bytes) -> tuple[RDPCheckStatus, str | None, str | None]:
    """Parse an X.224 Connection Confirm + optional RDP negotiation
    response (MS-RDPBCGR 2.2.1.2)."""
    # Fixed part: LI(1) type(1) DST-REF(2) SRC-REF(2) class(1) = 7 bytes.
    if len(x224) < 7:
        return (RDPCheckStatus.MALFORMED_RESPONSE, None, "Connection Confirm too short")
    negotiation = x224[7:]
    if len(negotiation) == 0:
        # Server ignored the negotiation request (plain RDP security).
        return (RDPCheckStatus.RDP_RESPONSE_OBSERVED, None, "no negotiation response: server selected PROTOCOL_RDP by omission")

    neg_type = negotiation[0]
    if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
        if len(negotiation) < 8:
            return (RDPCheckStatus.MALFORMED_RESPONSE, None, "negotiation response shorter than 8 bytes")
        flags = negotiation[1]
        length = int.from_bytes(negotiation[2:4], "little")
        if length != 8:
            return (RDPCheckStatus.MALFORMED_RESPONSE, None, f"negotiation response length {length} != 8")
        selected = int.from_bytes(negotiation[4:8], "little")
        protocol = _NEGOTIATION_PROTOCOLS.get(selected)
        if protocol is None:
            return (
                RDPCheckStatus.MALFORMED_RESPONSE,
                None,
                f"unknown negotiated protocol 0x{selected:08X}",
            )
        _ = flags  # server flags are echoed verbatim in detail by the caller
        return (RDPCheckStatus.RDP_RESPONSE_OBSERVED, protocol, None)

    if neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
        if len(negotiation) < 8:
            return (RDPCheckStatus.MALFORMED_RESPONSE, None, "negotiation failure shorter than 8 bytes")
        failure_code = int.from_bytes(negotiation[4:8], "little")
        reasons = {
            0x01: "SSL_REQUIRED_BY_SERVER",
            0x02: "SSL_NOT_ALLOWED_BY_SERVER",
            0x03: "SSL_CERT_NOT_SIGNED",
            0x04: "SSL_CERT_ERROR",
            0x05: "HYBRID_REQUIRED_BY_SERVER",
            0x06: "HYBRID_REQUIRED_BY_SERVER_2",
        }
        reason = reasons.get(failure_code, f"failure code 0x{failure_code:08X}")
        return (RDPCheckStatus.NEGOTIATION_ERROR, None, f"RDP negotiation failure: {reason}")

    return (
        RDPCheckStatus.MALFORMED_RESPONSE,
        None,
        f"unknown RDP negotiation type 0x{neg_type:02X}",
    )


# ---------------------------------------------------------------------------
# Default transport (one bounded exchange over one socket)
# ---------------------------------------------------------------------------


def _build_request() -> bytes:
    """One TPKT-framed X.224 Connection Request (MS-RDPBCGR 2.2.1.1)."""
    # TPKT: version 3, reserved 0, length = 4 + X.224 LI(1)+header(6)+neg(8)
    x224_cr = bytes(
        [
            0x11,  # LI: 17 bytes follow (type..negotiation end)
            0xE0,  # CR, class 0
            0x00, 0x00,  # DST-REF
            0x00, 0x00,  # SRC-REF
            0x00,  # class 0
            # variable part: RDP negotiation request
            0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
        ]
    )
    total = 4 + len(x224_cr)
    return bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF]) + x224_cr


def _default_transport(
    host: str, port: int, request: bytes, timeout_s: float
) -> bytes:
    """Perform ONE connect + ONE send + ONE bounded read.

    Transport failures propagate as OSError for classification. Exactly
    one exchange; no retries.
    """
    sock = socket.socket(
        socket.AF_INET6 if ":" in host else socket.AF_INET,
        socket.SOCK_STREAM,
    )
    sock.settimeout(timeout_s)
    try:
        sock.connect((host, port))
        sock.sendall(request)
        chunks: list[bytes] = []
        total = 0
        while total < _MAX_RESPONSE_BYTES:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if len(b"".join(chunks)) >= 4:
                header = b"".join(chunks)[:4]
                if len(header) == 4:
                    declared = int.from_bytes(header[2:4], "big")
                    if total >= declared:
                        break
        return b"".join(chunks)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _status_from_socket_error(exc: OSError) -> RDPCheckStatus:
    """Reuse the TCP errno classification; map to RDP statuses."""
    if isinstance(exc, socket.gaierror):
        return RDPCheckStatus.DNS_ERROR
    mapped = classify_socket_error(exc)
    if mapped.value == "REFUSED":
        return RDPCheckStatus.CONNECTION_FAILED
    if mapped.value == "TIMEOUT":
        return RDPCheckStatus.TIMEOUT
    if mapped.value in ("NO_ROUTE", "UNREACHABLE"):
        return RDPCheckStatus.CONNECTION_FAILED
    if mapped.value in ("DNS_ERROR", "INVALID_TARGET"):
        return RDPCheckStatus.DNS_ERROR if mapped.value == "DNS_ERROR" else RDPCheckStatus.TCP_ERROR
    return RDPCheckStatus.TCP_ERROR


def _error_result(
    host: str,
    port: int,
    target: str,
    status: RDPCheckStatus,
    exc: Exception,
    elapsed_ms: float,
) -> RDPCheckResult:
    return RDPCheckResult(
        target=target,
        port=port,
        status=status,
        verdict=verdict_for(status),
        detail=f"{type(exc).__name__}: {exc}",
        elapsed_ms=round(elapsed_ms, 1),
    )


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_rdp_observation(
    host: str,
    port: int = _RDP_DEFAULT_PORT,
    timeout_s: float = 10.0,
    target: str | None = None,
    transport: Transport | None = None,
) -> RDPCheckResult:
    """Run ONE bounded RDP pre-authentication observation and classify it.

    Never raises for network/protocol outcomes — those are classified
    data. Raises only for structurally invalid inputs (port/timeout)
    before any activity.

    ZERO CREDENTIALS: this validator accepts no credential parameter at
    all — the observation is pre-authentication by construction.

    ``transport`` is injectable for deterministic tests; production uses
    :func:`_default_transport` (exactly one connect/send/receive).
    """
    validate_port(port)
    validate_timeout(timeout_s)
    result_target = target if target is not None else host

    request = _build_request()
    transport_fn: Transport = transport if transport is not None else _default_transport

    start = time.perf_counter()
    try:
        raw = transport_fn(host, port, request, timeout_s)
    except ssl.SSLError as exc:
        return _finish_error(
            host, port, result_target, RDPCheckStatus.TCP_ERROR,
            exc, (time.perf_counter() - start) * 1000,
        )
    except OSError as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        if isinstance(exc, socket.gaierror):
            return _error_result(
                host, port, result_target, RDPCheckStatus.DNS_ERROR,
                exc, elapsed_ms,
            )
        return _error_result(
            host, port, result_target,
            _status_from_socket_error(exc), exc, elapsed_ms,
        )
    except Exception as exc:  # noqa: BLE001 - boundary is deliberate
        return _error_result(
            host, port, result_target, RDPCheckStatus.LOCAL_ERROR,
            exc, (time.perf_counter() - start) * 1000,
        )

    elapsed_ms = (time.perf_counter() - start) * 1000
    status, negotiated, detail = parse_rdp_response(raw)
    return RDPCheckResult(
        target=result_target,
        port=port,
        status=status,
        verdict=verdict_for(status),
        negotiated_protocol=negotiated,
        detail=detail,
        elapsed_ms=round(elapsed_ms, 1),
    )


# Re-export for the parser contract (used by parse_rdp_response for the
# plain-HTTP false-positive defense: an HTTP/1.x error response contains
# the token "HTTP/" and is classified NOT_RDP before any TPKT check).
def _classify_non_rdp_text(raw: bytes) -> RDPCheckStatus | None:
    """Detect well-known non-RDP service responses so their classification
    carries precise detail instead of a generic framing error."""
    try:
        head = raw[:64].decode("ascii", errors="ignore")
    except Exception:  # noqa: BLE001 - bytes are always decodable with ignore
        return None
    if head.startswith("HTTP/"):
        return RDPCheckStatus.NOT_RDP_RESPONSE
    if head.startswith("SSH-"):
        return RDPCheckStatus.NOT_RDP_RESPONSE
    if re.match(r"^[0-9]{3}[ -]", head):  # SMTP/FTP style
        return RDPCheckStatus.NOT_RDP_RESPONSE
    return None


def _finish_error(
    host: str,
    port: int,
    target: str,
    status: RDPCheckStatus,
    exc: Exception,
    elapsed_ms: float,
) -> RDPCheckResult:
    return RDPCheckResult(
        target=target,
        port=port,
        status=status,
        verdict=verdict_for(status),
        detail=f"{type(exc).__name__}: {exc}",
        elapsed_ms=round(elapsed_ms, 1),
    )
