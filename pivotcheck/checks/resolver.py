"""Target validation and DNS resolution.

Separated from the TCP checker: the checker receives normalized address
literals only. Resolution failures produce ResolvedTarget(error=...) rather
than exceptions, so callers can classify DNS_ERROR cleanly.
"""

from __future__ import annotations

import ipaddress
import socket

from pivotcheck.models.check import ResolvedTarget


def validate_target(raw: str) -> str:
    """Validate target syntax (IP literal or hostname). Returns it unchanged.

    Raises ValueError for empty input or malformed literals.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("target must not be empty")
    # Reject CIDR notation: PivotCheck validates one explicit host at a time.
    if "/" in raw:
        raise ValueError(
            f"CIDR notation is not a valid check target: {raw!r}. "
            "PivotCheck validates one explicit host at a time."
        )
    try:
        ipaddress.ip_address(raw)
        return raw  # valid IP literal (v4 or v6)
    except ValueError:
        pass
    # Hostname syntax check per RFC 1123 (lenient)
    if len(raw) > 253:
        raise ValueError(f"hostname too long: {raw!r}")
    labels = raw.rstrip(".").split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise ValueError(f"invalid hostname label in {raw!r}")
        if not all(c.isalnum() or c == "-" for c in label):
            raise ValueError(f"invalid character in hostname {raw!r}")
        if label[0] == "-" or label[-1] == "-":
            raise ValueError(f"invalid hyphen placement in {raw!r}")
    return raw


def resolve_target(raw: str) -> ResolvedTarget:
    """Resolve a validated target to one or more IP addresses.

    Deterministic behavior for multi-address hosts: ALL resolved addresses
    are returned and each is checked individually by the caller. Results are
    deduplicated while preserving resolver order.
    """
    try:
        target = validate_target(raw)
    except ValueError as exc:
        return ResolvedTarget(original=raw, addresses=(), error=str(exc))

    try:
        ipaddress.ip_address(target)
        return ResolvedTarget(original=target, addresses=(target,))
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return ResolvedTarget(
            original=target,
            addresses=(),
            error=f"name resolution failed: {exc}",
        )
    except OSError as exc:
        return ResolvedTarget(
            original=target,
            addresses=(),
            error=f"resolution error: {exc}",
        )

    seen: set[str] = set()
    addresses: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.add(addr)
            addresses.append(addr)
    if not addresses:
        return ResolvedTarget(
            original=target, addresses=(), error="name resolved to no addresses"
        )
    return ResolvedTarget(original=target, addresses=tuple(addresses))


def _is_ipv6_literal(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value.split("%")[0])  # strip zone index
        return True
    except ValueError:
        return False
