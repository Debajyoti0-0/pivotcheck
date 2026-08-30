"""macOS discovery collector.

Collects interfaces, routes, neighbors, DNS configuration, and sockets on
macOS using standard tools (`ifconfig`, `netstat -rn`, `arp -a`,
`scutil --dns`, `netstat -an`) and normalizes them into the same evidence
models used by the Linux and Windows collectors.

Parsing is separated from collection: every ``parse_*`` function is pure
(string in, models out) and tested against fixtures. The collector accepts
an injectable command runner so tests run without touching a live system.

macOS `netstat -an` does not report owning PIDs without elevated helpers,
so socket/process correlation is not collected by this collector; that
remains explicit, documented behavior rather than a silent omission.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from pivotcheck.models.network import (
    Connection,
    ConnectionProtocol,
    DNSConfig,
    DNSServer,
    Interface,
    InterfaceState,
    IPAddress,
    Neighbor,
    Route,
    RouteType,
)
from pivotcheck.utils.system import CommandResult, run_command

Runner = Callable[..., CommandResult]


# --------------------------------------------------------------------------
# ifconfig
# --------------------------------------------------------------------------

_IF_HEADER_RE = re.compile(
    r"^(?P<name>[a-z0-9]+):\s+flags=(?P<flags>\d+)<(?P<flagnames>[^>]*)>"
)
_MAC_RE = re.compile(r"^\s+ether\s+(?P<mac>[0-9a-fA-F:]{17})")
_INET_RE = re.compile(
    r"^\s+inet\s+(?P<addr>\d+\.\d+\.\d+\.\d+)(?:\s+-->\s+\S+)?\s+netmask\s+(?P<mask>0x[0-9a-fA-F]+)"
)
_INET6_RE = re.compile(
    r"^\s+inet6\s+(?P<addr>[0-9A-Fa-f:]+)(?:%[a-z0-9]+)?\s+prefixlen\s+(?P<prefix>\d+)"
)
_STATUS_RE = re.compile(r"^\s+status:\s*(?P<status>\S+)")


def _hexnetmask_to_prefix(mask: str) -> int | None:
    try:
        return int(mask, 16).bit_count()
    except ValueError:
        return None


def parse_ifconfig(output: str) -> tuple[Interface, ...]:
    """Parse `ifconfig -a` output into interfaces."""
    interfaces: list[Interface] = []
    name: str | None = None
    mac: str | None = None
    v4: list[IPAddress] = []
    v6: list[IPAddress] = []
    state = InterfaceState.UNKNOWN

    def flush() -> None:
        nonlocal name, mac, v4, v6, state
        if name is not None:
            interfaces.append(
                Interface(
                    name=name,
                    state=state,
                    mac_address=mac,
                    ipv4_addresses=tuple(v4),
                    ipv6_addresses=tuple(v6),
                )
            )
        name, mac, v4, v6, state = None, None, [], [], InterfaceState.UNKNOWN

    for raw in output.splitlines():
        header = _IF_HEADER_RE.match(raw)
        if header:
            flush()
            name = header.group("name")
            state = InterfaceState.UP if "UP" in header.group("flagnames").split(",") else InterfaceState.DOWN
            continue
        if name is None:
            continue
        mac_match = _MAC_RE.match(raw)
        if mac_match:
            mac = mac_match.group("mac")
            continue
        v4_match = _INET_RE.match(raw)
        if v4_match:
            prefix = _hexnetmask_to_prefix(v4_match.group("mask"))
            if prefix is not None:
                v4.append(IPAddress(v4_match.group("addr"), prefix))
            continue
        v6_match = _INET6_RE.match(raw)
        if v6_match:
            try:
                v6.append(IPAddress(v6_match.group("addr"), int(v6_match.group("prefix"))))
            except ValueError:
                continue
            continue
        status = _STATUS_RE.match(raw)
        if status:
            state = InterfaceState.UP if status.group("status") == "active" else InterfaceState.DOWN
    flush()
    return tuple(interfaces)


# --------------------------------------------------------------------------
# netstat -rn
# --------------------------------------------------------------------------

def _expand_bsd_destination(dest: str) -> str:
    """Expand BSD-style truncated destinations ('10.0.0/24', '127') to CIDR.

    BSD netstat truncates trailing zero octets and, for unprefixed entries,
    the octet count implies the mask length ('127' == 127.0.0.0/8).
    """
    if "/" in dest:
        addr_part, _, prefix = dest.partition("/")
    else:
        addr_part, prefix = dest, None
    octets = addr_part.split(".")
    if all(o.isdigit() for o in octets) and len(octets) < 4:
        addr_part += ".0" * (4 - len(octets))
        if prefix is None:
            prefix = str(8 * len(octets))
    if prefix is None:
        prefix = "128" if ":" in addr_part else "32"
    return f"{addr_part}/{prefix}"


def parse_netstat_rn(output: str) -> tuple[Route, ...]:
    """Parse `netstat -rn` output into routes (IPv4 and IPv6 tables)."""
    routes: list[Route] = []
    section: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith("Internet6"):
            section = "v6"
            continue
        if line.startswith("Internet"):
            section = "v4"
            continue
        if not line or line.startswith(("Routing tables", "Destination")):
            continue
        fields = line.split()
        if section is None or len(fields) < 4:
            continue
        dest, gw_raw, _flags, netif = fields[0], fields[1], fields[2], fields[3]
        try:
            if dest == "default":
                if gw_raw.startswith("link#"):
                    gateway = None
                else:
                    candidate = gw_raw.split("%")[0]
                    ipaddress.ip_address(candidate)  # validate
                    gateway = candidate
                routes.append(Route("default", gateway, netif, None, RouteType.DEFAULT))
                continue
            if gw_raw.startswith("link#"):
                gateway = None
            else:
                candidate = gw_raw.split("%")[0]  # strip IPv6 zone identifier
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue  # unparseable gateway: skip rather than emit bad evidence
                gateway = candidate
            network = ipaddress.ip_network(
                _expand_bsd_destination(dest), strict=False
            )
            rtype = RouteType.CONNECTED if gateway is None else RouteType.STATIC
            routes.append(Route(str(network), gateway, netif, None, rtype))
        except ValueError:
            continue
    return tuple(routes)


# --------------------------------------------------------------------------
# arp -a
# --------------------------------------------------------------------------

_ARP_ENTRY_RE = re.compile(
    r"^\S+\s+\((?P<ip>[0-9a-fA-F:.]+)\)\s+at\s+(?P<mac>\([iI]ncomplete\)|[0-9a-fA-F:]{5,17})"
    r"(?:\s+on\s+(?P<if>\S+))?(?:\s+ifscope\s+\[[^\]]*\])?(?:\s+\[(?P<scope>[^\]]*)\])?"
)


def _normalize_mac(mac_raw: str) -> str | None:
    """Zero-pad BSD-style unpadded MAC octets to a canonical 17-char form."""
    if len(mac_raw) == 17:
        return mac_raw
    if ":" not in mac_raw:
        return None
    octets = mac_raw.split(":")
    if len(octets) != 6 or any(not 1 <= len(o) <= 2 for o in octets):
        return None
    return ":".join(o.zfill(2) for o in octets)


def parse_arp_a(output: str) -> tuple[Neighbor, ...]:
    """Parse `arp -a` output into neighbors."""
    neighbors: list[Neighbor] = []
    for raw in output.splitlines():
        match = _ARP_ENTRY_RE.match(raw.strip())
        if not match:
            continue
        ip = match.group("ip")
        mac_raw = match.group("mac")
        mac: str | None
        state: str | None
        if mac_raw.lower() == "(incomplete)":
            mac, state = None, "INCOMPLETE"
        else:
            mac = _normalize_mac(mac_raw)
            if mac is None:
                continue  # non-MAC payload (e.g. utun peer addresses)
            state = "Permanent" if "permanent" in raw else None
        try:
            neighbors.append(Neighbor(ip, match.group("if") or "unknown", mac, state))
        except ValueError:
            continue
    return tuple(neighbors)


# --------------------------------------------------------------------------
# scutil --dns
# --------------------------------------------------------------------------

_NAMESERVER_RE = re.compile(r"nameserver\[\d+\]\s*:\s*(?P<addr>[0-9A-Fa-f:.]+)")
_SEARCH_RE = re.compile(r"search domain\[\d+\]\s*:\s*(?P<domain>\S+)")


def parse_scutil_dns(output: str) -> DNSConfig:
    """Parse `scutil --dns` into a DNSConfig."""
    servers: list[DNSServer] = []
    search: list[str] = []
    for raw in output.splitlines():
        ns = _NAMESERVER_RE.search(raw)
        if ns:
            try:
                server = DNSServer(ns.group("addr"), source="scutil --dns")
            except ValueError:
                continue
            if server not in servers:
                servers.append(server)
            continue
        sd = _SEARCH_RE.search(raw)
        if sd and sd.group("domain") not in search:
            search.append(sd.group("domain"))
    return DNSConfig(servers=tuple(servers), search_domains=tuple(search))


# --------------------------------------------------------------------------
# netstat -an
# --------------------------------------------------------------------------

_NETSTAT_RE = re.compile(
    r"^(?P<proto>tcp4?|tcp6|udp4?|udp6)\s+(?P<recvq>\d+)\s+(?P<sendq>\d+)\s+"
    r"(?P<local>\S+)\s+(?P<peer>\S+)(?:\s+(?P<state>\S+))?"
)


def _split_mac_addr(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        host, _, port = value.rpartition("]:")
        return host.lstrip("["), int(port)
    if value.startswith("*"):
        port_part = value.rsplit(".", 1)[1] if "." in value else value.split(":")[-1]
        return "*", int(port_part) if port_part.isdigit() else None
    if ":" in value:
        # IPv6 (macOS separates the port with a final dot, e.g. ::1.49153)
        if "." in value:
            host, _, port = value.rpartition(".")
        else:
            host, _, port = value.rpartition(":")
        return host, int(port)
    host, _, port = value.rpartition(".")
    return host, int(port)


def parse_netstat_an(output: str) -> tuple[Connection, ...]:
    """Parse `netstat -an` output into connections (no PID correlation)."""
    connections: list[Connection] = []
    for raw in output.splitlines():
        match = _NETSTAT_RE.match(raw.strip())
        if not match:
            continue
        proto_raw = match.group("proto")
        proto = ConnectionProtocol.TCP if proto_raw.startswith("tcp") else ConnectionProtocol.UDP
        local_host, local_port = _split_mac_addr(match.group("local"))
        peer_host, peer_port = _split_mac_addr(match.group("peer"))
        if local_port is None:
            continue  # a socket without a bound port carries no evidence
        state = match.group("state")
        if proto == ConnectionProtocol.UDP:
            state = None
        connections.append(
            Connection(
                protocol=proto,
                local_address="0.0.0.0" if local_host == "*" else local_host,
                local_port=local_port,
                remote_address=None if peer_host == "*" else peer_host,
                remote_port=peer_port if peer_host != "*" else None,
                state=state,
            )
        )
    return tuple(connections)


# --------------------------------------------------------------------------
# Collector
# --------------------------------------------------------------------------

def _fallback_runner(args: list[str], timeout: float = 10.0) -> CommandResult:
    return run_command(args, timeout)


class MacOSCollector:
    """Collect normalized evidence on macOS via standard tools.

    ``runner`` is injectable for deterministic testing; production uses
    :func:`run_command` (argument-array subprocess, sanitized environment).
    """

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner: Runner = runner or _fallback_runner

    def _run(self, *args: str) -> str:
        result = self._runner(list(args))
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f"{args[0]} exited {result.returncode}")
        return result.stdout

    def collect_interfaces(self) -> tuple[Interface, ...]:
        return parse_ifconfig(self._run("ifconfig", "-a"))

    def collect_routes(self) -> tuple[Route, ...]:
        return parse_netstat_rn(self._run("netstat", "-rn"))

    def collect_neighbors(self) -> tuple[Neighbor, ...]:
        return parse_arp_a(self._run("arp", "-a"))

    def collect_dns(self) -> DNSConfig:
        return parse_scutil_dns(self._run("scutil", "--dns"))

    def collect_connections(self) -> tuple[Connection, ...]:
        return parse_netstat_an(self._run("netstat", "-an"))
