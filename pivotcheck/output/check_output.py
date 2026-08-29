"""Terminal rendering for reachability check results.

Consumes normalized CheckReport models only. Language is deliberately
precise: timeouts are never presented as 'host offline'.
"""

from __future__ import annotations

from typing import TextIO

from pivotcheck.models.check import (
    CheckReport,
    CheckResult,
    CheckStatus,
    RouteContextType,
    ValidationContext,
)
from pivotcheck.output.terminal import Theme

_WIDTH = 62


def _status_symbol(status: CheckStatus, theme: Theme) -> str:
    if status is CheckStatus.SUCCESS:
        return theme.good("[+]")
    if status in (CheckStatus.REFUSED,):
        return theme.bad("[-]")
    if status is CheckStatus.TIMEOUT:
        return theme.warn("[?]")
    return theme.warn("[!]")


def _interpretation(result: CheckResult, timeout_s: float) -> str:
    if result.status is CheckStatus.SUCCESS:
        return "The TCP handshake completed successfully from the current host."
    if result.status is CheckStatus.REFUSED:
        return (
            "The TCP connection was actively refused. The network path may be "
            "functioning, but the target service is not accepting connections "
            "on this port or a device actively rejected the connection."
        )
    if result.status is CheckStatus.TIMEOUT:
        return (
            f"The TCP connection did not complete within {timeout_s:g} seconds. "
            "This result is AMBIGUOUS and does not prove the host is offline. "
            "Possible causes include filtering, firewall behavior, packet loss, "
            "or service unavailability."
        )
    if result.status is CheckStatus.NO_ROUTE:
        return "The local system could not establish a usable route to the destination."
    if result.status is CheckStatus.UNREACHABLE:
        return (
            "The network reported the destination (or an intermediate hop) as "
            "unreachable. Routing or firewall policy may be blocking the path."
        )
    if result.status is CheckStatus.DNS_ERROR:
        return f"Target name could not be resolved: {result.error}"
    if result.status is CheckStatus.INVALID_TARGET:
        return f"Target input was invalid: {result.error}"
    return f"A local error occurred before a definitive result: {result.error}"


def _context_lines(report: CheckReport, theme: Theme) -> list[str]:
    ctx = report.results[0].route_context if report.results else None
    if ctx is None or ctx.context_type is RouteContextType.UNKNOWN:
        return [
            theme.dim(
                "No matching route context from discovery evidence "
                "(run 'pivotcheck discover' on this host for correlation)."
            )
        ]
    lines = [f"Network: {ctx.network}", f"Type: {ctx.context_type.value}"]
    if ctx.gateway:
        lines.append(f"Gateway: {ctx.gateway}")
    if ctx.interface:
        lines.append(f"Interface: {ctx.interface}")
    if ctx.confidence:
        lines.append(f"Confidence: {ctx.confidence.upper()}")
    return lines


def _render_validation_context(
    ctx: ValidationContext, stream: TextIO, theme: Theme
) -> None:
    """Render the contextual sections of a check report.

    Renderers never infer relationship, recommendation, or route context;
    every displayed statement maps to a field already present in the model.
    """
    p = lambda s="": print(s, file=stream)

    # NETWORK CONTEXT
    p()
    p(theme.section("NETWORK CONTEXT:"))
    if ctx.network_match is not None:
        p(f"  Matched network: {ctx.network_match.network}")
        p(f"  Match type: {ctx.network_match.match_type}")
        if ctx.network_match.broader_networks:
            p("  Broader containing networks:")
            for broader in ctx.network_match.broader_networks:
                p(f"    {broader}")
    else:
        p(theme.dim("  No containing network observed in current discovery evidence."))
    if ctx.route_context is not None:
        if ctx.route_context.context_type is RouteContextType.UNKNOWN:
            p(theme.dim("  Route: no matching route context from discovery evidence."))
        else:
            route = f"  Route: {ctx.route_context.network}"
            if ctx.route_context.gateway:
                route += f" via {ctx.route_context.gateway}"
            if ctx.route_context.interface:
                route += f" dev {ctx.route_context.interface}"
            p(route)
            p(f"  Route type: {ctx.route_context.context_type.value}")
            if ctx.route_context.confidence:
                p(f"  Confidence: {ctx.route_context.confidence.upper()}")

    # COMPARISON CONTEXT
    if ctx.comparison is not None:
        p()
        p(theme.section("COMPARISON CONTEXT:"))
        p(f"  Baseline: {ctx.comparison.baseline}")
        p(f"  Relationship: {ctx.comparison.relationship}")
        if ctx.comparison.classification:
            p(f"  Classification: {ctx.comparison.classification}")
        if ctx.comparison.related_network:
            p(f"  Related network: {ctx.comparison.related_network}")

    # OPERATOR PRIORITY CONTEXT
    if ctx.priority is not None:
        p()
        p(theme.section("OPERATOR PRIORITY CONTEXT:"))
        p(f"  Level: {ctx.priority.level}")
        p(f"  Reason: {ctx.priority.reason}")
        p(theme.dim("  This is prioritization context, not validation evidence."))

    # LIMITATIONS
    if ctx.limitations:
        p()
        p(theme.section("LIMITATION:"))
        for limitation in ctx.limitations:
            p(f"  {limitation}")


def render_check(report: CheckReport, stream: TextIO, color: bool = False) -> None:
    """Render one check invocation's results."""
    theme = Theme(color)
    p = lambda s="": print(s, file=stream)

    p(theme.header("═" * _WIDTH))
    p(theme.header("PIVOTCHECK — REACHABILITY").center(_WIDTH + 4))
    p(theme.header("═" * _WIDTH))
    p()
    p("Target:")
    p(f"{report.target}")
    if len(report.resolved_addresses) > 1:
        p("Resolved Addresses:")
        for addr in report.resolved_addresses:
            p(f"  {addr}")

    # Route context (same for all results of this target)
    p()
    p(theme.section("Route Context:"))
    for line in _context_lines(report, theme):
        p(f"  {line}")

    p()
    p(theme.section("Results:"))
    for result in report.results:
        symbol = _status_symbol(result.status, theme)
        elapsed = (
            f"{result.elapsed_ms:.1f} ms"
            if result.elapsed_ms is not None
            else "n/a"
        )
        p(f"{symbol} {result.address}:{result.port} — {result.status.value}  "
          f"{theme.dim(elapsed)}")
        p(theme.dim(f"    {_interpretation(result, report.timeout_s)}"))
        p()

    succeeded = sum(1 for r in report.results if r.status is CheckStatus.SUCCESS)
    refused = sum(1 for r in report.results if r.status is CheckStatus.REFUSED)
    ambiguous = sum(
        1 for r in report.results
        if r.status not in (CheckStatus.SUCCESS, CheckStatus.REFUSED)
    )
    p(theme.section("Summary:"))
    p(f"  SUCCESS: {succeeded}   REFUSED: {refused}   "
      f"AMBIGUOUS/OTHER: {ambiguous}")

    # Contextual sections (only when a baseline was requested)
    if report.validation_context is not None:
        _render_validation_context(report.validation_context, stream, theme)


def render_check_json(report: CheckReport, stream: TextIO) -> None:
    """Write the check report as JSON (no ANSI, stable keys)."""
    import json

    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")