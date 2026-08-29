"""Terminal rendering for PivotCheck.

Renderers consume normalized models only. They never execute commands,
perform discovery, or mutate state. Two presentation modes are provided:

- detailed discovery output (``discover``)
- topology-focused map output (``map``)

Color is ANSI-based, TTY-detected, and always optional.
"""

from __future__ import annotations

from typing import TextIO

from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    Interface,
    InterfaceState,
    NetworkOrigin,
)
from pivotcheck.models.result import DiscoverySnapshot

# ---------------------------------------------------------------------------
# ANSI handling
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"


class Theme:
    """ANSI color theme; a no-op theme is used when color is disabled."""

    def __init__(self, color: bool) -> None:
        self.color = color

    def _wrap(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.color else text

    def header(self, text: str) -> str:
        return self._wrap(_BOLD + _CYAN, text)

    def section(self, text: str) -> str:
        return self._wrap(_BOLD, text)

    def good(self, text: str) -> str:
        return self._wrap(_GREEN, text)

    def warn(self, text: str) -> str:
        return self._wrap(_YELLOW, text)

    def bad(self, text: str) -> str:
        return self._wrap(_RED, text)

    def dim(self, text: str) -> str:
        return self._wrap(_DIM, text)


def should_use_color(stream: TextIO, no_color_flag: bool) -> bool:
    """Enable color only for interactive TTYs unless explicitly forced off."""
    if no_color_flag or "NO_COLOR" in __import__("os").environ:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


_LINE = "─" * 62


def _rule(theme: Theme) -> str:
    return theme.dim(_LINE)


def _confidence_tag(confidence: Confidence, theme: Theme) -> str:
    tag = f"[{confidence.value.upper()}]"
    if confidence is Confidence.HIGH:
        return theme.good(tag)
    if confidence is Confidence.MEDIUM:
        return theme.warn(tag)
    return theme.bad(tag)


def _state_text(state: InterfaceState, theme: Theme) -> str:
    if state is InterfaceState.UP:
        return theme.good("UP")
    if state is InterfaceState.DOWN:
        return theme.bad("DOWN")
    return theme.dim("UNKNOWN")


# ---------------------------------------------------------------------------
# Evidence strings (single source of truth used by both renderers)
# ---------------------------------------------------------------------------

def connected_evidence(net: DiscoveredNetwork, iface: Interface | None) -> str:
    if iface and iface.state is InterfaceState.UP:
        addr = iface.ipv4_addresses[0] if iface.ipv4_addresses else None
        detail = f" has address {addr.address}/{addr.prefix}" if addr else " is active"
        return f"Active interface {iface.name}{detail}."
    if iface:
        return f"Interface {iface.name} has configured network but is currently DOWN."
    return "Interface information unavailable."


def routed_evidence(net: DiscoveredNetwork) -> str:
    return (
        f"Kernel routing table contains {net.cidr} via {net.gateway}"
        f" (interface {net.interface})."
    )


# ---------------------------------------------------------------------------
# Detailed renderer (discover)
# ---------------------------------------------------------------------------

def render_detailed(
    snapshot: DiscoverySnapshot,
    stream: TextIO,
    color: bool = False,
) -> None:
    """Render full passive discovery output."""
    theme = Theme(color)
    p = lambda s="": print(s, file=stream)

    p(theme.header("═" * 62))
    p(theme.header("PIVOTCHECK").center(66))
    p(theme.dim("Passive Network Discovery").center(62))
    p(theme.header("═" * 62))
    p()
    p(theme.good("[+] Host Discovery Complete"))
    p(f"    Hostname : {snapshot.hostname}")
    p(f"    OS       : {snapshot.os_name}")
    p()

    # -- summary ----------------------------------------------------------
    direct = [n for n in snapshot.networks if n.origin is NetworkOrigin.CONNECTED]
    routed = [n for n in snapshot.networks if n.origin is NetworkOrigin.ROUTED]
    p(_rule(theme))
    p(theme.section("NETWORK SUMMARY"))
    p(_rule(theme))
    p(f"Direct Networks:       {len(direct)}")
    p(f"Routed Networks:       {len(routed)}")
    p(f"Potential Pivot Paths: {len(snapshot.pivot_paths)}")
    p(f"Known Neighbors:       {len(snapshot.neighbors)}")
    p(f"Warnings:              {len(snapshot.warnings)}")
    p()

    # -- directly connected -------------------------------------------------
    p(_rule(theme))
    p(theme.section("DIRECTLY CONNECTED NETWORKS"))
    p(_rule(theme))
    if not direct:
        p(theme.bad("[-] No directly connected networks found."))
    iface_by_name = {i.name: i for i in snapshot.interfaces}
    for net in sorted(direct, key=lambda n: n.cidr):
        iface = iface_by_name.get(net.interface or "")
        p(f"{_confidence_tag(net.confidence, theme)} {net.cidr}")
        if iface:
            p(f"       Interface : {iface.name}")
            addrs = iface.ipv4_addresses + iface.ipv6_addresses
            matching = [
                a for a in addrs
                if a.network == net.cidr
            ]
            if matching:
                a = matching[0]
                p(f"       Address   : {a.address}/{a.prefix}")
            p(f"       State     : {_state_text(iface.state, theme)}")
        p(theme.dim(f"       Evidence  : {connected_evidence(net, iface)}"))
    p()

    # -- routed networks ----------------------------------------------------
    p(_rule(theme))
    p(theme.section("ROUTED NETWORKS"))
    p(_rule(theme))
    if not routed:
        p(theme.dim("[-] No additional routed networks discovered."))
    for net in sorted(routed, key=lambda n: n.cidr):
        p(f"{_confidence_tag(net.confidence, theme)} {net.cidr}")
        p(f"         Gateway   : {net.gateway}")
        p(f"         Interface : {net.interface}")
        p(theme.dim(f"         Evidence  : {routed_evidence(net)}"))
    p()

    # -- pivot paths ---------------------------------------------------------
    p(_rule(theme))
    p(theme.section("POTENTIAL PIVOT PATHS"))
    p(_rule(theme))
    if not snapshot.pivot_paths:
        p(theme.dim("[-] No pivot paths identified beyond local networks."))
    for path in snapshot.pivot_paths:
        src_ip = _source_ip_for_interface(snapshot, path.source_interface)
        p(theme.good(f"[+] {src_ip or 'this host'}"))
        p("     ↓")
        p(f"    {path.source_interface}")
        p("     ↓")
        p(f"  {path.gateway}")
        p("     ↓")
        p(f"  {path.destination_network}   "
          f"{theme.dim('(routing evidence only — not yet validated)')}")
        p(f"Confidence: {path.confidence.value.upper()}")
        p(theme.dim(
            f"Reason: Explicit route through gateway {path.gateway}"
        ))
        p()

    # -- warnings ------------------------------------------------------------
    if snapshot.warnings:
        p(_rule(theme))
        p(theme.section("DISCOVERY WARNINGS"))
        p(_rule(theme))
        for w in snapshot.warnings:
            p(theme.warn(f"[!] {w.source.capitalize()} unavailable"))
            p(f"    Reason: {w.message}")
        p()

    # -- recommended next step ----------------------------------------------
    p(_rule(theme))
    p(theme.section("RECOMMENDED NEXT STEP"))
    p(_rule(theme))
    if snapshot.pivot_paths:
        target_net = snapshot.pivot_paths[0].destination_network
        p("Validate the identified routed network when active checks are available:")
        p(f"  pivotcheck check <host-in-{target_net}>")
    elif routed:
        p("Review routed networks above; no explicit pivot paths were inferred.")
    else:
        p("No routed networks found — this host appears confined to local subnets.")
    p()


def _source_ip_for_interface(
    snapshot: DiscoverySnapshot, interface_name: str
) -> str | None:
    for iface in snapshot.interfaces:
        if iface.name == interface_name and iface.ipv4_addresses:
            return iface.ipv4_addresses[0].address
    return None


# ---------------------------------------------------------------------------
# Map renderer (map)
# ---------------------------------------------------------------------------

def render_map(
    snapshot: DiscoverySnapshot,
    stream: TextIO,
    color: bool = False,
) -> None:
    """Render a topology-focused view prioritizing relationships over detail.

    Deliberately conservative: shows only what the OS actually reports.
    A displayed route means 'the kernel has a path configured', never
    'the destination is confirmed reachable'.
    """
    theme = Theme(color)
    p = lambda s="": print(s, file=stream)

    p(theme.header("LOCAL HOST") + theme.dim(f"  ({snapshot.hostname})"))
    direct_by_iface: dict[str, list[DiscoveredNetwork]] = {}
    routed_by_iface: dict[str, list[DiscoveredNetwork]] = {}
    for net in snapshot.networks:
        bucket = direct_by_iface if net.origin is NetworkOrigin.CONNECTED \
            else routed_by_iface
        bucket.setdefault(net.interface or "?", []).append(net)

    all_ifaces = [i.name for i in snapshot.interfaces]
    for name in sorted(set(all_ifaces) | set(direct_by_iface) | set(routed_by_iface)):
        iface = next((i for i in snapshot.interfaces if i.name == name), None)
        state_txt = _state_text(iface.state, theme) if iface else theme.dim("?")
        branch = "└──" if name == max(
            set(all_ifaces) | set(direct_by_iface) | set(routed_by_iface)
        ) else "├──"
        p(f"   {branch} {name}  {state_txt}")

        nets = direct_by_iface.get(name, [])
        for i, net in enumerate(sorted(nets, key=lambda n: n.cidr)):
            last = i == len(nets) - 1 and name not in routed_by_iface
            connector = "└──" if last else "├──"
            p(f"   │     {connector} {_confidence_tag(net.confidence, theme)}"
              f" {net.cidr}  {theme.dim('directly connected')}")

        for i, net in enumerate(sorted(routed_by_iface.get(name, []), key=lambda n: n.cidr)):
            last = i == len(routed_by_iface.get(name, [])) - 1
            connector = "└──" if last else "├──"
            p(f"   │     {connector} Gateway: {net.gateway}")
            p(f"   │     │     {connector} {_confidence_tag(net.confidence, theme)}"
              f" {net.cidr}  {theme.dim('route configured — reachability unverified')}")

    p()
    p(theme.dim(
        "Legend: [HIGH] active interface carries this subnet · "
        "[MEDIUM] kernel route exists · "
        "[LOW] configured but inactive"
    ))
    p(theme.dim(
        "Note: routes shown are configuration evidence, not confirmed reachability."
    ))
