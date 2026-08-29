"""Routing table discovery (Linux).

Parses `ip route show` (iproute2) with a fallback to `route -n`
(busybox/minimal containers). Parsers are pure and fixture-testable.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from pivotcheck.models.network import Route, RouteType
from pivotcheck.utils.system import CommandNotFoundError, CommandResult, run_command

# default via 10.10.20.1 dev eth0 proto dhcp src 10.10.20.15 metric 100
# Field order varies across kernels (e.g. 'dev' before 'via'), so scan
# tokens instead of matching a fixed layout.
_IPROUTE2_DEST_RE = re.compile(r"^(?P<dest>default|\S+)")
_VIA_RE = re.compile(r"\bvia\s+(?P<via>\S+)")
_DEV_RE = re.compile(r"\bdev\s+(?P<dev>\S+)")
_METRIC_RE = re.compile(r"\bmetric\s+(?P<metric>\d+)")

# busybox `route -n`: Dest GW Genmask Flags Metric Ref Use Iface
_ROUTE_N_RE = re.compile(
    r"^(?P<dest>\S+)\s+(?P<gw>\S+)\s+(?P<genmask>\S+)\s+"
    r"(?P<flags>\S+)\s+(?P<metric>\d+)\s+\d+\s+\d+\s+(?P<iface>\S+)\s*$"
)


def _classify(destination: str, gateway: str | None) -> RouteType:
    if destination == "default":
        return RouteType.DEFAULT
    if gateway is None:
        return RouteType.CONNECTED
    return RouteType.STATIC


def parse_ip_route(output: str) -> tuple[Route, ...]:
    """Parse iproute2 `ip route show` output."""
    routes: list[Route] = []
    for line in output.splitlines():
        line = line.strip()
        dest_match = _IPROUTE2_DEST_RE.match(line)
        if not dest_match:
            continue
        dev_match = _DEV_RE.search(line)
        if not dev_match:
            continue  # malformed / non-route line: skip silently
        dest_raw = dest_match.group("dest")
        if dest_raw == "default":
            destination = "default"
        else:
            # Normalize bare peer addresses (e.g. '10.8.0.1 dev tun0') to /32
            try:
                destination = str(ipaddress.ip_network(dest_raw, strict=False))
            except ValueError:
                continue  # malformed destination: skip silently
        via_match = _VIA_RE.search(line)
        metric_match = _METRIC_RE.search(line)
        gateway = via_match.group("via") if via_match else None
        try:
            route = Route(
                destination=destination,
                gateway=gateway,
                interface=dev_match.group("dev"),
                metric=(
                    int(metric_match.group("metric")) if metric_match else None
                ),
                route_type=_classify(dest_raw, gateway),
            )
        except ValueError:
            continue
        routes.append(route)
    return tuple(routes)


def _mask_to_prefix(genmask: str) -> int | None:
    try:
        return sum(int(octet).bit_count() for octet in genmask.split("."))
    except (ValueError, AttributeError):
        return None


def parse_route_n(output: str) -> tuple[Route, ...]:
    """Parse busybox/legacy `route -n` output."""
    routes: list[Route] = []
    for line in output.splitlines():
        match = _ROUTE_N_RE.match(line)
        if not match:
            continue
        prefix = _mask_to_prefix(match.group("genmask"))
        if prefix is None:
            continue
        if match.group("dest") == "0.0.0.0" and match.group("genmask") == "0.0.0.0":
            destination = "default"
            gateway = None if match.group("gw") == "0.0.0.0" else match.group("gw")
        else:
            destination = f"{match.group('dest')}/{prefix}"
            gateway = None if match.group("gw") == "0.0.0.0" else match.group("gw")
        try:
            route = Route(
                destination=destination,
                gateway=gateway,
                interface=match.group("iface"),
                metric=int(match.group("metric")) if match.group("metric") else None,
                route_type=_classify(destination, gateway),
            )
        except ValueError:
            continue
        routes.append(route)
    return tuple(routes)


def collect_routes(
    executor: Callable[[list[str]], CommandResult] = run_command,
) -> tuple[Route, ...]:
    """Read the main routing table.

    Tries `ip route show` first; falls back to `route -n` on systems without
    iproute2. Raises the last collection error only if both fail.
    ``executor`` abstracts the transport (local subprocess or remote SSH).
    """
    errors: list[str] = []
    for args, parser in (
        (["ip", "route", "show"], parse_ip_route),
        (["route", "-n"], parse_route_n),
    ):
        try:
            result = executor(args)
        except CommandNotFoundError as exc:
            errors.append(str(exc))
            continue
        except Exception as exc:  # noqa: BLE001 - timeout / OSError from subprocess
            errors.append(f"{args[0]} failed: {exc}")
            continue
        if result.returncode != 0:
            errors.append(f"{args[0]} exited {result.returncode}: {result.stderr.strip()}")
            continue
        return parser(result.stdout)
    raise RuntimeError(
        "could not read routing table; tried ip route show and route -n"
    ) from RuntimeError("; ".join(errors) if errors else "no route source available")
