"""Shared validation helpers."""

from __future__ import annotations

import ipaddress


def validate_cidr(value: str) -> str:
    """Validate a CIDR string (or bare IP) and return its normalized form."""
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid CIDR or IP address: {value!r}") from exc


def validate_ip(value: str) -> str:
    """Validate an IP address string and return it unchanged."""
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value!r}") from exc
    return value
