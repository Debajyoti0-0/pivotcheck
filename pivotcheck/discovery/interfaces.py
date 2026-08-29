"""Network interface discovery (Linux).

Collects interface names, state, MAC addresses, and IPv4/IPv6 addressing by
parsing `ip -o addr show` and `ip -o link show`. Parsing is separated from
collection so both can be unit tested against fixtures.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from pivotcheck.models.network import (
    Interface,
    InterfaceState,
    IPAddress,
)
from pivotcheck.utils.system import CommandNotFoundError, CommandResult, run_command

# `ip -o addr show` line, e.g.:
# 2: eth0    inet 10.10.20.15/24 brd 10.10.20.255 scope global eth0\...
_ADDR_RE = re.compile(
    r"^(?P<ifindex>\d+):\s+(?P<name>\S+)\s+"
    r"(?P<family>inet6?)\s+(?P<address>\S+)"
)

# `ip -o link show` line prefix, e.g.:
# 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP ...
_LINK_PREFIX_RE = re.compile(
    r"^(?P<ifindex>\d+):\s+(?P<name>[^:@]+)(?:@\S+)?:\s+<(?P<flags>[^>]*)>"
)
_STATE_RE = re.compile(r"\bstate\s+(?P<state>\S+)")
_MAC_RE = re.compile(r"\blink/ether\s+(?P<mac>[0-9a-fA-F:]{17})")


@dataclass(frozen=True)
class InterfaceCollectionError(Exception):
    """Raised when interface data cannot be collected at all."""

    message: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


def parse_addr_show(output: str) -> dict[str, dict[str, list[IPAddress]]]:
    """Parse `ip -o addr show` output into per-interface address data."""
    interfaces: dict[str, dict[str, list[IPAddress]]] = {}
    for line in output.splitlines():
        match = _ADDR_RE.match(line.strip())
        if not match:
            continue
        name = match.group("name")
        family = match.group("family")
        raw_address = match.group("address")
        try:
            address_str, _, prefix_str = raw_address.partition("/")
            prefix = int(prefix_str) if prefix_str else (
                128 if family == "inet6" else 32
            )
            addr = IPAddress(address=address_str, prefix=prefix)
        except ValueError:
            continue  # skip malformed lines; never crash discovery
        entry = interfaces.setdefault(
            name, {"ipv4": [], "ipv6": []}
        )
        if family == "inet":
            entry["ipv4"].append(addr)
        else:
            entry["ipv6"].append(addr)
    return interfaces


def parse_link_show(output: str) -> dict[str, dict[str, str | None]]:
    """Parse `ip -o link show` output into per-interface link data."""
    links: dict[str, dict[str, str | None]] = {}
    for line in output.splitlines():
        match = _LINK_PREFIX_RE.match(line.strip())
        if not match:
            continue
        flags = (match.group("flags") or "").split(",")
        state_match = _STATE_RE.search(line)
        mac_match = _MAC_RE.search(line)
        state_raw = state_match.group("state") if state_match else None
        if state_raw and state_raw.upper() == "UP":
            state = InterfaceState.UP
        elif state_raw and state_raw.upper() == "DOWN":
            # NO-CARRIER devices report state DOWN even when administratively
            # raised; treat flag-UP devices as operationally usable.
            state = (
                InterfaceState.UP if "UP" in flags else InterfaceState.DOWN
            )
        else:
            # UNKNOWN is common for loopback/tun devices.
            state = (
                InterfaceState.UP if "UP" in flags else InterfaceState.UNKNOWN
            )
        links[match.group("name")] = {
            "state": state,
            "mac_address": mac_match.group("mac") if mac_match else None,
        }
    return links


def collect_interfaces(
    executor: Callable[[list[str]], CommandResult] = run_command,
) -> tuple[Interface, ...]:
    """Enumerate all network interfaces on this host.

    ``executor`` abstracts *where* the fixed discovery commands run (local
    subprocess by default, remote transport for other providers). Command
    intent and parsing are shared regardless of transport.

    Raises InterfaceCollectionError only if the `ip` command itself is
    unavailable or fails outright; individual malformed lines are skipped.
    """
    try:
        addr_result = executor(["ip", "-o", "addr", "show"])
        link_result = executor(["ip", "-o", "link", "show"])
    except CommandNotFoundError as exc:
        raise InterfaceCollectionError(str(exc)) from exc
    except Exception as exc:  # timeout / OSError from subprocess
        raise InterfaceCollectionError(f"failed to enumerate interfaces: {exc}") from exc

    addrs = parse_addr_show(addr_result.stdout)
    links = parse_link_show(link_result.stdout)

    interfaces: list[Interface] = []
    for name in sorted(set(addrs) | set(links)):
        addr_entry = addrs.get(name, {})
        link_entry = links.get(name, {})
        interfaces.append(
            Interface(
                name=name,
                state=link_entry.get("state", InterfaceState.UNKNOWN),  # type: ignore[arg-type]
                mac_address=link_entry.get("mac_address"),
                ipv4_addresses=tuple(addr_entry.get("ipv4", [])),
                ipv6_addresses=tuple(addr_entry.get("ipv6", [])),
            )
        )
    return tuple(interfaces)
