"""Deterministic, secure, self-contained HTML report (G-05, Stage 32).

PRESENTATION ONLY. The renderer consumes an already-analyzed
DiscoverySnapshot and produces one self-contained HTML document:

- Escaping: every model-derived value passes through html.escape()
  (UNTRUSTED DATA -> ESCAPED TEXT). No raw interpolation of data ever
  reaches the document.
- Epistemic preservation: origin/confidence/state strings are rendered
  VERBATIM from the source models. The renderer never strengthens
  meaning (INFERRED stays INFERRED; HYPOTHETICAL stays HYPOTHETICAL;
  contradictions stay visible) and never manufactures evidence.
- Self-contained: one inline <style> block, no scripts, no links, no
  remote resources of any kind. Works with networking fully disabled.
- Deterministic: no clock reads, no randomness, no environment access.
  The only timestamp rendered is the one already inside the supplied
  snapshot. Identical input -> identical bytes.
- Secret-safe: the renderer accepts only discovery models, which carry
  no credential material by construction. There is no code path that
  can embed a credential, environment value, or filesystem path.

Bounded: output size is proportional to the supplied report data; no
recursion, no expansion, no embedded assets.
"""

from __future__ import annotations

import html
from typing import Any

from pivotcheck import __version__
from pivotcheck.models.result import DiscoverySnapshot

_DISCLAIMER: tuple[str, ...] = (
    "This report contains PASSIVE DISCOVERY and ANALYSIS results only. No active validation was performed during its production.",
    "ROUTING \u2260 REACHABILITY: a routing-table entry implies nothing about forwarding or packet delivery.",
    "Confidence labels describe how directly evidence supports a network's presence \u2014 they never assert that a network is reachable, authenticated to, or executable.",
    "Pivot paths are evidence composition candidates, never confirmed pivot capability.",
    "No credential material exists in this document by construction.",
)


def escape(value: object) -> str:
    """Escape one model-derived value for safe HTML text/attribute use.

    html.escape with quote=True handles < > & " ' — the mandatory
    UNTRUSTED DATA -> ESCAPED TEXT boundary for every interpolation in
    this module.
    """
    return html.escape(str(value), quote=True)


def _table(headers: tuple[str, ...], rows: list[tuple[Any, ...]]) -> str:
    """Render an escaped table. Empty tables render as a note."""
    if not rows:
        return '<p class="empty">No entries collected.</p>'
    head = "".join(
        f'<th scope="col">{escape(header)}</th>' for header in headers
    )
    body = "".join(
        "<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _state_class(state: str) -> str:
    """CSS class derived deterministically from the state string itself."""
    allowed = {"high", "medium", "low", "connected", "routed", "inferred"}
    lowered = state.lower()
    return lowered if lowered in allowed else "other"


def render_html(snapshot: DiscoverySnapshot) -> str:
    """Render one DiscoverySnapshot as a self-contained HTML document.

    Pure and deterministic: identical snapshots produce identical bytes.
    Performs no I/O, executes nothing, fetches nothing.
    """
    e = escape

    # ---- Section: report metadata ------------------------------------
    metadata_rows = [
        ("Tool", "pivotcheck"),
        ("Version", __version__),
        ("Snapshot time (source data)", snapshot.timestamp),
        ("Perspective hostname", snapshot.hostname),
        ("Operating system", snapshot.os_name),
    ]

    # ---- Section: interfaces -----------------------------------------
    interface_rows = [
        (
            interface.name,
            interface.state.value,
            interface.mac_address or "unknown",
            ", ".join(
                f"{address.address}/{address.prefix}"
                for address in interface.ipv4_addresses
            )
            or "-",
            ", ".join(
                f"{address.address}/{address.prefix}"
                for address in interface.ipv6_addresses
            )
            or "-",
        )
        for interface in snapshot.interfaces
    ]

    # ---- Section: routes ---------------------------------------------
    route_rows = [
        (
            route.destination,
            route.gateway or "directly connected",
            route.interface,
            str(route.metric) if route.metric is not None else "-",
            route.route_type.value,
        )
        for route in snapshot.routes
    ]

    # ---- Section: evidence summary (networks) -------------------------
    network_rows = [
        (
            network.cidr,
            network.origin.value,
            network.confidence.value,
            network.interface or "-",
            network.gateway or "-",
        )
        for network in snapshot.networks
    ]

    # ---- Section: pivot path candidates --------------------------------
    pivot_rows = [
        (
            path.source_interface,
            path.gateway,
            path.destination_network,
            path.confidence.value,
        )
        for path in snapshot.pivot_paths
    ]

    # ---- Section: neighbors --------------------------------------------
    neighbor_rows = [
        (
            neighbor.ip_address,
            neighbor.interface,
            neighbor.mac_address or "unknown",
            neighbor.state or "unknown",
        )
        for neighbor in snapshot.neighbors
    ]

    # ---- Section: DNS ---------------------------------------------------
    dns_rows = [
        (server.address, server.source)
        for server in snapshot.dns.servers
    ]

    # ---- Section: warnings ----------------------------------------------
    warning_rows = [
        (warning.source, warning.message) for warning in snapshot.warnings
    ]

    limitations = "".join(
        f"<li>{e(item)}</li>" for item in _DISCLAIMER
    )
    metadata_html = "".join(
        f"<tr><th scope=\"row\">{e(label)}</th><td>{e(value)}</td></tr>"
        for label, value in metadata_rows
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PivotCheck Assessment Report</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: Georgia, 'Times New Roman', serif; margin: 2rem auto;
       max-width: 60rem; padding: 0 1rem; line-height: 1.5;
       color: #1a1a1a; background: #fdfdfc; }}
h1 {{ font-size: 1.6rem; border-bottom: 2px solid #444; }}
h2 {{ font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #999; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.75rem 0;
         font-family: 'Consolas', 'Courier New', monospace; font-size: 0.85rem; }}
th, td {{ border: 1px solid #bbb; padding: 0.35rem 0.5rem; text-align: left;
          overflow-wrap: anywhere; }}
th {{ background: #eceae5; }}
tbody tr:nth-child(even) {{ background: #f4f2ee; }}
.state-high {{ font-weight: bold; }}
.state-low {{ color: #7a5c00; }}
.state-routed {{ font-style: italic; }}
.chip {{ display: inline-block; border: 1px solid #888; padding: 0 0.3rem;
         border-radius: 3px; }}
.disclaimer {{ background: #f7f3e8; border: 1px solid #c9b98a;
               padding: 0.75rem 1rem; }}
.disclaimer li {{ margin: 0.4rem 0; }}
.empty {{ color: #666; font-style: italic; }}
@media print {{ body {{ max-width: none; }} .state-low {{ color: #6b5200; }} }}
</style>
</head>
<body>
<h1>PivotCheck Assessment Report</h1>
<p>Evidence-first passive discovery and analysis. This document is a
presentation artifact: every statement mirrors the source data exactly,
including its epistemic limits.</p>

<h2>1. Report Metadata</h2>
<table>
<tbody>
{metadata_html}
</tbody>
</table>

<h2>2. Interfaces (OBSERVED)</h2>
{_table(("Interface", "State", "MAC", ("IPv4 addresses"), "IPv6 addresses"), interface_rows)}

<h2>3. Routing Table (OBSERVED)</h2>
<p class="empty">Note: routing entries are OBSERVED table rows. A routing entry implies nothing about reachability, forwarding, or packet delivery.</p>
{_table(("Destination", "Gateway", "Interface", "Metric", "Type"), route_rows)}

<h2>4. Evidence Summary (ANALYZED)</h2>
<p class="empty">Origin and confidence are reproduced verbatim from the analysis. Confidence describes evidence directness only.</p>
{_table(("Network", "Origin", "Confidence", "Interface", "Gateway"), network_rows)}

<h2>5. Pivot Path Candidates (INFERRED)</h2>
<p class="empty">Candidates are evidence compositions \u2014 not confirmed pivots. Each requires explicit validation.</p>
{_table(("Source Interface", "Gateway", "Destination", "Confidence"), pivot_rows)}

<h2>6. Neighbors (OBSERVED)</h2>
{_table(("IP Address", "Interface", "MAC", "State"), neighbor_rows)}

<h2>7. DNS Configuration (OBSERVED)</h2>
{_table(("Server", "Source"), dns_rows)}

<h2>8. Discovery Warnings</h2>
{_table(("Source", "Message"), warning_rows)}

<h2>9. Limitations and Evidence Disclaimer</h2>
<div class="disclaimer">
<ul>
{limitations}
</ul>
</div>

<p class="empty">Generated by PivotCheck {e(__version__)} as a static,
self-contained artifact. This file contains no scripts and references no
external resources.</p>
</body>
</html>
"""


def snapshot_report_facts(snapshot: DiscoverySnapshot) -> dict[str, Any]:
    """Deterministic counts for summary rendering (pure helper)."""
    return {
        "interfaces": len(snapshot.interfaces),
        "routes": len(snapshot.routes),
        "networks": len(snapshot.networks),
        "pivot_paths": len(snapshot.pivot_paths),
        "neighbors": len(snapshot.neighbors),
        "warnings": len(snapshot.warnings),
    }
