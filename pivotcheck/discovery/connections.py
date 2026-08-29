"""Socket / connection discovery (Linux).

Parses `ss -tunap` when available; falls back to `netstat -tunap`.
Requires no privileges for basic output; process names appear only where
permitted (same-user or root).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pivotcheck.models.network import Connection, ConnectionProtocol
from pivotcheck.utils.system import CommandNotFoundError, CommandResult, run_command

# ss header: Netid State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process
_SS_RE = re.compile(
    r"^(?P<proto>tcp|udp)\s+(?P<state>\S+)\s+\d+\s+\d+\s+"
    r"(?P<local>\[?[0-9a-fA-F:.]+\]?:\d+|\*:\d+)\s+"
    r"(?P<peer>\[?[0-9a-fA-F:.]+\]?:\d+|\*:\d+)"
    r"(?:\s+users:\(\((?P<proc>.*?)\)\))?"
)

# netstat: tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 1234/sshd
_NETSTAT_RE = re.compile(
    r"^(?P<proto>tcp6?|udp6?)\s+\d+\s+\d+\s+"
    r"(?P<local>\S+)\s+(?P<peer>\S+)\s+(?P<state>\S+)"
    r"(?:\s+(?P<pidpid>\d+)/(?P<proc>\S+))?"
)


def _split_addr_port(value: str) -> tuple[str, int]:
    if value.startswith("["):  # IPv6 [::1]:22
        host, _, port = value.rpartition("]:")
        return host.lstrip("["), int(port)
    if value.startswith("*"):
        return "0.0.0.0", int(value.rsplit(":", 1)[1])
    host, _, port = value.rpartition(":")
    return host, int(port)


def _extract_proc(proc_field: str | None) -> str | None:
    """Extract '1234/sshd' style info from ss users:(("sshd",pid=1234,...))."""
    if not proc_field:
        return None
    match = re.search(r'"([^"]+)",pid=(\d+)', proc_field)
    if match:
        return f"{match.group(2)}/{match.group(1)}"
    return None


def parse_ss(output: str) -> tuple[Connection, ...]:
    """Parse `ss -tunap` output."""
    connections: list[Connection] = []
    for line in output.splitlines():
        match = _SS_RE.match(line.strip())
        if not match:
            continue
        try:
            local_host, local_port = _split_addr_port(match.group("local"))
            peer_raw = match.group("peer")
            remote_host, remote_port = _split_addr_port(peer_raw)
            state = match.group("state")
            protocol = (
                ConnectionProtocol.TCP
                if match.group("proto") == "tcp"
                else ConnectionProtocol.UDP
            )
            # UDP has no connection state; normalize to None unless LISTEN/UNCONN
            if protocol == ConnectionProtocol.UDP and state in ("UNCONN", "ESTAB"):
                state = "LISTEN" if remote_host == "0.0.0.0" else None
            connections.append(
                Connection(
                    protocol=protocol,
                    local_address=local_host,
                    local_port=local_port,
                    remote_address=remote_host,
                    remote_port=remote_port,
                    state=state,
                    process=_extract_proc(match.group("proc")),
                )
            )
        except ValueError:
            continue
    return tuple(connections)


def parse_netstat(output: str) -> tuple[Connection, ...]:
    """Parse `netstat -tunap` output as a fallback source."""
    connections: list[Connection] = []
    for line in output.splitlines():
        match = _NETSTAT_RE.match(line.strip())
        if not match:
            continue
        proto_raw = match.group("proto").rstrip("6")
        try:
            local_host, local_port = _split_addr_port(match.group("local"))
            remote_host, remote_port = _split_addr_port(match.group("peer"))
            connections.append(
                Connection(
                    protocol=(
                        ConnectionProtocol.TCP
                        if proto_raw == "tcp"
                        else ConnectionProtocol.UDP
                    ),
                    local_address=local_host,
                    local_port=local_port,
                    remote_address=remote_host,
                    remote_port=remote_port,
                    state=match.group("state"),
                    process=(
                        f"{match.group('pidpid')}/{match.group('proc')}"
                        if match.group("pidpid")
                        else None
                    ),
                )
            )
        except ValueError:
            continue
    return tuple(connections)


def collect_connections(
    executor: Callable[[list[str]], CommandResult] = run_command,
) -> tuple[Connection, ...]:
    """Collect listening sockets and established connections.

    Raises RuntimeError only if both ss and netstat are unavailable or fail.
    ``executor`` abstracts the transport (local subprocess or remote SSH).
    """
    errors: list[str] = []
    for args, parser in (
        (["ss", "-tunap"], parse_ss),
        (["netstat", "-tunap"], parse_netstat),
    ):
        try:
            result = executor(args)
        except CommandNotFoundError as exc:
            errors.append(str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 - collector fallback boundary
            errors.append(f"{args[0]} failed: {exc}")
            continue
        if result.returncode != 0:
            errors.append(f"{args[0]} exited {result.returncode}")
            continue
        return parser(result.stdout)
    raise RuntimeError(
        "could not enumerate sockets"
    ) from RuntimeError("; ".join(errors) if errors else "no socket source available")
