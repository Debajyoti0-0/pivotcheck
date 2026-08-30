"""Windows discovery collector.

Collects interfaces, routes, neighbors, DNS configuration, and sockets on
Windows using always-available tools (`ipconfig`, `route print`, `arp -a`,
`netstat -ano`, `tasklist`) and normalizes them into the same evidence
models used by the Linux and macOS collectors.

Parsing is separated from collection: every ``parse_*`` function is pure
(string in, models out) and tested against fixtures. Collectors accept an
injectable command runner so tests run without touching a live system.

Locale caveat: Windows console tools localize labels per UI language.
Parsers anchor on structural data patterns (addresses, masks, table rows)
rather than header text where possible. Fully localized output may still
degrade collection; failures surface as warnings, never aborts.
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
# ipconfig /all
# --------------------------------------------------------------------------

_ADAPTER_RE = re.compile(r"^(?:Windows IP Configuration|\s*$)", re.IGNORECASE)
_ADAPTER_HEADER_RE = re.compile(r"^(?P<name>.+?adapter\s+(?P<alias>.+?)\s*:)\s*$", re.IGNORECASE)
_PHYSICAL_RE = re.compile(r"Physical Address[. ]*:\s*(?P<mac>[0-9A-Fa-f-]{12,17})", re.IGNORECASE)
_IPV4_RE = re.compile(r"IPv4 Address[. ]*:\s*(?P<addr>[0-9.]+)", re.IGNORECASE)
_IPV6_RE = re.compile(r"IPv6 Address[. ]*:\s*(?P<addr>[0-9A-Fa-f:]+)", re.IGNORECASE)
_LINKLOCAL6_RE = re.compile(r"Link-local IPv6 Address[. ]*:\s*(?P<addr>[0-9A-Fa-f:%]+)", re.IGNORECASE)
_MASK_RE = re.compile(r"Subnet Mask[. ]*:\s*(?P<mask>[0-9.]+)", re.IGNORECASE)
_PREFIXLEN_RE = re.compile(r"\(Preferred\)\s*$", re.IGNORECASE)
_DISCONNECTED_RE = re.compile(r"Media State[. ]*:\s*.*disconnected", re.IGNORECASE)
_DNS_RE = re.compile(r"DNS Servers[. ]*:\s*(?P<addr>[0-9A-Fa-f:.]+)", re.IGNORECASE)
_DNS_CONT_RE = re.compile(r"^\s{20,}(?P<addr>[0-9A-Fa-f:.]{7,})\s*$")
_HOSTNAME_RE = re.compile(r"Host Name[. ]*:\s*(?P<host>\S+)", re.IGNORECASE)


def _mask_to_prefix(mask: str) -> int | None:
    try:
        return int(ipaddress.IPv4Address(mask)).bit_count()
    except ValueError:
        return None


def parse_ipconfig(output: str) -> tuple[tuple[Interface, ...], tuple[DNSServer, ...], str | None]:
    """Parse `ipconfig /all` into interfaces, DNS servers, and hostname.

    IPv6 prefixes are not reported by ipconfig; link-local addresses use /128
    and global IPv6 addresses /64 as the standard Windows convention.
    """
    interfaces: list[Interface] = []
    dns_servers: list[DNSServer] = []
    hostname: str | None = None

    name: str | None = None
    state = InterfaceState.UNKNOWN
    mac: str | None = None
    v4: list[IPAddress] = []
    v6: list[IPAddress] = []

    def flush() -> None:
        nonlocal name, state, mac, v4, v6
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
        name, state, mac, v4, v6 = None, InterfaceState.UNKNOWN, None, [], []

    for raw in output.splitlines():
        line = raw.rstrip()
        host_match = _HOSTNAME_RE.search(line)
        if host_match:
            hostname = host_match.group("host")
            continue
        header = _ADAPTER_HEADER_RE.match(line)
        if header:
            flush()
            name = header.group("alias").strip()
            state = InterfaceState.UP
            continue
        if _DISCONNECTED_RE.search(line):
            state = InterfaceState.DOWN
            continue
        phys = _PHYSICAL_RE.search(line)
        if phys and name is not None:
            value = phys.group("mac")
            if value.lower().replace("-", "").strip("0") != "":  # skip null MACs
                mac = value.replace("-", ":").lower()
            continue
        v4m = _IPV4_RE.search(line)
        if v4m and name is not None:
            v4.append(IPAddress(v4m.group("addr"), 32))
            continue
        mask = _MASK_RE.search(line)
        if mask and v4 and v4[-1].prefix == 32:
            prefix = _mask_to_prefix(mask.group("mask"))
            if prefix is not None:
                v4[-1] = IPAddress(v4[-1].address, prefix)
            continue
        v6m = _LINKLOCAL6_RE.search(line) or _IPV6_RE.search(line)
        if v6m and name is not None:
            addr = v6m.group("addr").split("%")[0]
            prefix = 128 if "link-local" in line.lower() else 64
            try:
                v6.append(IPAddress(addr, prefix))
            except ValueError:
                continue
            continue
        dns = _DNS_RE.search(line) or _DNS_CONT_RE.match(line)
        if dns and name is not None:
            try:
                dns_servers.append(DNSServer(dns.group("addr"), source="ipconfig"))
            except ValueError:
                continue
    flush()
    return tuple(interfaces), tuple(dns_servers), hostname


# --------------------------------------------------------------------------
# route print
# --------------------------------------------------------------------------

_V4_ROUTE_RE = re.compile(
    r"^\s+(?P<dest>\d+\.\d+\.\d+\.\d+)\s+(?P<mask>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<gw>On-link|\d+\.\d+\.\d+\.\d+)\s+(?P<if>\d+\.\d+\.\d+\.\d+|\d+)\s+"
    r"(?P<metric>\d+)\s*$"
)
_V6_ROUTE_RE = re.compile(
    r"^\s*(?P<if>\d+)\s+(?P<metric>\d+|\s)\s+(?P<dest>[0-9A-Fa-f:]+/\d+)\s+"
    r"(?P<gw>On-link|[0-9A-Fa-f:%]+)?\s*$"
)


def parse_route_print(output: str) -> tuple[Route, ...]:
    """Parse `route print` IPv4 and IPv6 route tables."""
    routes: list[Route] = []
    section: str | None = None
    for raw in output.splitlines():
        line = raw.rstrip()
        if "IPv4 Route Table" in line:
            section = "v4"
            continue
        if "IPv6 Route Table" in line:
            section = "v6"
            continue
        if line.startswith(("Persistent Routes", "Interface List", "=======")):
            section = None if line.startswith(("Persistent Routes", "Interface List")) else section
            continue
        v4 = _V4_ROUTE_RE.match(line)
        if v4 and section == "v4":
            dest = v4.group("dest")
            mask = v4.group("mask")
            prefix = _mask_to_prefix(mask)
            if prefix is None:
                continue
            gateway = None if v4.group("gw") == "On-link" else v4.group("gw")
            interface = v4.group("if")  # route print reports the interface IP
            if prefix == 0:
                routes.append(Route("default", gateway, interface,
                                    int(v4.group("metric")), RouteType.DEFAULT))
            else:
                network = ipaddress.ip_network(f"{dest}/{prefix}", strict=False)
                rtype = RouteType.CONNECTED if gateway is None else RouteType.STATIC
                routes.append(Route(str(network), gateway, interface,
                                    int(v4.group("metric")), rtype))
            continue
        v6 = _V6_ROUTE_RE.match(line)
        if v6 and section == "v6":
            dest = v6.group("dest")
            gw_raw = (v6.group("gw") or "").strip()
            gateway = None if gw_raw in ("", "On-link") else gw_raw.split("%")[0]
            metric_raw = v6.group("metric").strip()
            metric = int(metric_raw) if metric_raw.isdigit() else None
            try:
                network = ipaddress.ip_network(dest, strict=False)
            except ValueError:
                continue
            if network.prefixlen == 0:
                routes.append(Route("default", gateway, f"if{v6.group('if')}",
                                    metric, RouteType.DEFAULT))
            else:
                rtype = RouteType.CONNECTED if gateway is None else RouteType.STATIC
                routes.append(Route(str(network), gateway, f"if{v6.group('if')}",
                                    metric, rtype))
    return tuple(routes)


# --------------------------------------------------------------------------
# arp -a
# --------------------------------------------------------------------------

_ARP_IF_RE = re.compile(r"^Interface:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s*---\s*(?P<idx>0x[0-9a-fA-F]+)")
_ARP_ENTRY_RE = re.compile(
    r"^\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9A-Fa-f-]{17}|(?:in)?complete)\s+"
    r"(?P<type>dynamic|static|invalid)?", re.IGNORECASE
)


def parse_arp_a(output: str) -> tuple[Neighbor, ...]:
    """Parse `arp -a` output into neighbors."""
    neighbors: list[Neighbor] = []
    current_if = "unknown"
    for raw in output.splitlines():
        line = raw.rstrip()
        if_match = _ARP_IF_RE.match(line)
        if if_match:
            current_if = f"if{int(if_match.group('idx'), 16)}"
            continue
        entry = _ARP_ENTRY_RE.match(line)
        if entry:
            ip = entry.group("ip")
            entry_type = (entry.group("type") or "").lower()
            mac_raw = entry.group("mac").lower()
            if entry_type == "invalid" or mac_raw == "ff:ff:ff:ff:ff:ff":
                # Broadcast/invalid entries are not neighbor evidence.
                continue
            mac = mac_raw.replace("-", ":") if "-" in mac_raw and len(mac_raw) == 17 else None
            state = entry.group("type")
            state = state.capitalize() if state else ("INCOMPLETE" if "incomplete" in mac_raw else None)
            try:
                neighbors.append(Neighbor(ip, current_if, mac, state))
            except ValueError:
                continue
    return tuple(neighbors)


# --------------------------------------------------------------------------
# netstat -ano
# --------------------------------------------------------------------------

_NETSTAT_RE = re.compile(
    r"^\s*(?P<proto>TCP|UDP)\s+(?P<local>\S+)\s+(?P<peer>\S+)"
    r"(?:\s+(?P<state>\S+))?(?:\s+(?P<pid>\d+))?\s*$"
)


def _split_win_addr(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        host, _, port = value.rpartition("]:")
        return host.lstrip("["), int(port)
    if value.startswith("*"):
        port_part = value.rsplit(":", 1)[1]
        return "*", int(port_part) if port_part.isdigit() else None
    host, _, port = value.rpartition(":")
    return host, int(port)


def parse_netstat_ano(output: str) -> tuple[Connection, ...]:
    """Parse `netstat -ano` output into connections (PID preserved)."""
    connections: list[Connection] = []
    for raw in output.splitlines():
        match = _NETSTAT_RE.match(raw.rstrip())
        if not match:
            continue
        proto = ConnectionProtocol.TCP if match.group("proto") == "TCP" else ConnectionProtocol.UDP
        local_host, local_port = _split_win_addr(match.group("local"))
        peer_host, peer_port = _split_win_addr(match.group("peer"))
        if local_port is None:
            continue  # a socket without a bound port carries no evidence
        pid = match.group("pid")
        state = match.group("state")
        if proto == ConnectionProtocol.UDP:
            # UDP rows have no state column; a trailing number is the PID.
            if state is not None and state.isdigit():
                pid = pid or state
            state = "LISTEN" if peer_host == "*" else None
        connections.append(
            Connection(
                protocol=proto,
                local_address="0.0.0.0" if local_host == "*" else local_host,
                local_port=local_port,
                remote_address=None if peer_host == "*" else peer_host,
                remote_port=peer_port if peer_host != "*" else None,
                state=state,
                process=f"{pid}/" if pid else None,
            )
        )
    return tuple(connections)


def parse_tasklist(output: str) -> dict[str, str]:
    """Parse `tasklist /fo csv /nh` into {pid: image_name}."""
    mapping: dict[str, str] = {}
    import csv
    import io

    for row in csv.reader(io.StringIO(output)):
        if len(row) >= 2 and row[1].isdigit():
            mapping[row[1]] = row[0]
    return mapping


# --------------------------------------------------------------------------
# Collector
# --------------------------------------------------------------------------

def _fallback_runner(args: list[str], timeout: float = 10.0) -> CommandResult:
    return run_command(args, timeout)


class WindowsCollector:
    """Collect normalized evidence on Windows via always-available tools.

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

    def collect_hostname(self) -> str | None:
        output = self._run("ipconfig", "/all")
        _, _, hostname = parse_ipconfig(output)
        return hostname

    def collect_interfaces(self) -> tuple[Interface, ...]:
        interfaces, _, _ = parse_ipconfig(self._run("ipconfig", "/all"))
        return interfaces

    def collect_dns(self) -> DNSConfig:
        _, servers, _ = parse_ipconfig(self._run("ipconfig", "/all"))
        return DNSConfig(servers=servers)

    def collect_routes(self) -> tuple[Route, ...]:
        return parse_route_print(self._run("route", "print"))

    def collect_neighbors(self) -> tuple[Neighbor, ...]:
        return parse_arp_a(self._run("arp", "-a"))

    def collect_connections(self) -> tuple[Connection, ...]:
        connections = parse_netstat_ano(self._run("netstat", "-ano"))
        try:
            pids = parse_tasklist(self._run("tasklist", "/fo", "csv", "/nh"))
        except Exception:  # noqa: BLE001 - correlation is best-effort only
            pids = {}
        if not pids:
            return connections
        correlated: list[Connection] = []
        for conn in connections:
            if conn.process and "/" in conn.process:
                pid = conn.process.split("/", 1)[0]
                name = pids.get(pid)
                correlated.append(
                    Connection(
                        protocol=conn.protocol,
                        local_address=conn.local_address,
                        local_port=conn.local_port,
                        remote_address=conn.remote_address,
                        remote_port=conn.remote_port,
                        state=conn.state,
                        process=f"{pid}/{name}" if name else conn.process,
                    )
                )
            else:
                correlated.append(conn)
        return tuple(correlated)
