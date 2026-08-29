"""Terminal and JSON rendering for next-step decision support."""

from __future__ import annotations

import json
from typing import TextIO

from pivotcheck.analysis.next_step import NextStepReport
from pivotcheck.analysis.transit_priority import TransitPriority
from pivotcheck.output.terminal import Theme


def render_next_step(report: NextStepReport, stream: TextIO, color: bool = False) -> None:
    """Render next-step decision support report."""
    theme = Theme(color)
    p = lambda s="": print(s, file=stream)

    if report.candidate is None:
        p(theme.section("NO INVESTIGATION CANDIDATES"))
        p()
        p("No actionable evidence found from current perspective.")
        return

    candidate = report.candidate
    evidence = candidate.transit_evidence

    p(theme.header("NEXT INVESTIGATION CANDIDATE"))
    p()
    p(f"Network: {candidate.network}")
    p(f"Priority: {_priority_tag(candidate.priority, theme)}")
    p(f"Reason: {candidate.reason}")
    p()

    p(theme.section("Evidence:"))
    # Route evidence
    if evidence.route_present:
        route_str = f"  [x] Route: {evidence.destination_network}"
        if evidence.route_metric is not None:
            route_str += f" (metric {evidence.route_metric})"
        if evidence.route_type:
            route_str += f" [{evidence.route_type}]"
        p(route_str)
    else:
        p("  [ ] Route: not observed")

    # Neighbor evidence
    if evidence.neighbor_observed:
        neighbor_str = f"  [x] Neighbor: {evidence.gateway}"
        if evidence.neighbor_state:
            neighbor_str += f" - {evidence.neighbor_state}"
        if evidence.neighbor_mac:
            neighbor_str += f" ({evidence.neighbor_mac})"
        p(neighbor_str)
    else:
        p("  [ ] Neighbor: not observed")

    # Connection evidence
    if evidence.tcp_connections_to_gateway > 0:
        tcp_str = f"  [x] Connection: {evidence.tcp_connections_to_gateway} ESTABLISHED TCP"
        if evidence.tcp_connection_states:
            states = [s for s in evidence.tcp_connection_states if s != "ESTABLISHED"]
            if states:
                tcp_str += f" ({', '.join(states)})"
        p(tcp_str)
    else:
        p("  [ ] Connection: no ESTABLISHED TCP to gateway")

    if evidence.udp_flows_to_gateway > 0:
        p(f"  [x] Connection: {evidence.udp_flows_to_gateway} UDP flow(s) to gateway")
    else:
        p("  [ ] Connection: no UDP flows to gateway")

    if evidence.has_listen_on_gateway:
        p("  [x] Connection: LISTEN on gateway")
    else:
        p("  [ ] Connection: no LISTEN on gateway")

    if evidence.has_loopback_to_gateway:
        p("  [ ] Connection: loopback to gateway (excluded)")
    else:
        p("  [ ] Connection: no loopback to gateway")

    p()
    p(f"Assessment: {evidence.assessment.value}")
    p()

    p(theme.section("Limitation:"))
    p(f"  {candidate.limitation}")
    p()

    p(theme.section("Suggested operator action:"))
    p(f"  {candidate.suggested_action}")

    # Comparison context if available
    if candidate.comparison_context is not None:
        p()
        p(theme.section("Comparison Context:"))
        ctx = candidate.comparison_context
        p(f"  Baseline: {ctx.baseline}")
        p(f"  Relationship: {ctx.relationship}")
        if ctx.classification:
            p(f"  Classification: {ctx.classification}")
        if ctx.related_network:
            p(f"  Related network: {ctx.related_network}")


def _priority_tag(priority: TransitPriority, theme: Theme) -> str:
    """Format priority with appropriate color."""
    if priority.value == "HIGH":
        return theme.good(priority.value)
    if priority.value == "MEDIUM":
        return theme.warn(priority.value)
    if priority.value == "LOW":
        return theme.dim(priority.value)
    return theme.bad(priority.value)


def render_next_step_json(report: NextStepReport, stream: TextIO) -> None:
    """Write the next-step report as JSON (no ANSI, stable keys)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")