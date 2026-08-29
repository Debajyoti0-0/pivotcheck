"""ARP / neighbor table discovery (Linux).

Parses `ip neigh show`. Neighbor entries are *known hosts*, not confirmed
reachable hosts — callers must preserve that distinction downstream.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pivotcheck.models.network import Neighbor
from pivotcheck.utils.system import CommandNotFoundError, CommandResult, run_command

# 10.10.20.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
# fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router STALE
_NEIGH_RE = re.compile(
    r"^(?P<ip>\S+)\s+"
    r"(?:dev\s+(?P<dev>\S+)\s+)?"
    r"(?:lladdr\s+(?P<lladdr>[0-9a-fA-F:]{17})\s+)?"
    r"(?:(?P<extra>router|probed)\s+)?"
    r"(?P<state>REACHABLE|STALE|DELAY|PROBE|PERMANENT|INCOMPLETE|FAILED|NONE)"
)


def parse_neigh_show(output: str) -> tuple[Neighbor, ...]:
    """Parse `ip neigh show` output into Neighbor models."""
    neighbors: list[Neighbor] = []
    seen: set[tuple[str, str]] = set()
    for line in output.splitlines():
        match = _NEIGH_RE.match(line.strip())
        if not match or not match.group("dev"):
            continue
        key = (match.group("ip"), match.group("dev"))
        if key in seen:
            continue
        seen.add(key)
        try:
            neighbor = Neighbor(
                ip_address=match.group("ip"),
                mac_address=match.group("lladdr"),
                interface=match.group("dev"),
                state=match.group("state"),
            )
        except ValueError:
            continue
        neighbors.append(neighbor)
    return tuple(neighbors)


def collect_neighbors(
    executor: Callable[[list[str]], CommandResult] = run_command,
) -> tuple[Neighbor, ...]:
    """Collect known neighbors. Raises on total failure to run `ip`.

    ``executor`` abstracts the transport (local subprocess or remote SSH).
    """
    try:
        result = executor(["ip", "neigh", "show"])
    except (CommandNotFoundError, Exception) as exc:
        raise RuntimeError(f"could not access neighbor table: {exc}") from exc
    if result.returncode != 0:
        # e.g. permission issues on hardened systems — caller decides severity
        raise RuntimeError(
            f"ip neigh exited {result.returncode}: {result.stderr.strip()}"
        )
    return parse_neigh_show(result.stdout)
