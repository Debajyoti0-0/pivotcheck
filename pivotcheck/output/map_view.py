"""Terminal and JSON renderers for the pure perspective-aware map view."""

from __future__ import annotations

import json
from typing import TextIO

from pivotcheck.analysis.map_view import MapNetwork, MapView


def map_view_to_dict(view: MapView) -> dict[str, object]:
    return {
        "baseline": {
            "name": view.baseline_name,
            "vantage_point": view.baseline.vantage_point.to_dict()
            if view.baseline and view.baseline.vantage_point
            else None,
        },
        "current": {
            "vantage_point": view.current.session.to_dict()
            if view.current.session
            else None
        },
        "map": {
            "new_coverage": [_network(item) for item in view.new_coverage],
            "expanded_coverage": [_network(item) for item in view.expanded_coverage],
            "current_connected": [_network(item) for item in view.current_connected],
            "current_routed": [_network(item) for item in view.current_routed],
            "more_specific_evidence": [
                _network(item) for item in view.more_specific_evidence
            ],
            "context_changes": [_network(item) for item in view.context_changes],
            "baseline_only": [_network(item) for item in view.baseline_only],
            "unchanged": [_network(item) for item in view.unchanged],
            "pivot_paths": [path.to_dict() for path in view.pivot_paths],
        },
    }


def render_map_view_json(view: MapView, stream: TextIO) -> None:
    json.dump(map_view_to_dict(view), stream, indent=2)
    stream.write("\n")


def render_map_view(view: MapView, stream: TextIO, *, color: bool = False) -> None:
    """Render comparison context using symbols that work without ANSI color."""
    del color  # symbols, not color, are the output contract
    print("PIVOTCHECK - PERSPECTIVE MAP", file=stream)
    if view.baseline is not None:
        print(f"BASELINE: {view.baseline_name}", file=stream)
        print(f"  vantage point: {_baseline_label(view)}", file=stream)
    print(f"CURRENT: {_current_label(view)}", file=stream)
    _section(stream, "NEW COVERAGE OBSERVED", "+", view.new_coverage)
    _section(stream, "EXPANDED COVERAGE", ">", view.expanded_coverage)
    _section(stream, "CURRENT CONNECTED COVERAGE", "=", view.current_connected)
    _section(stream, "CURRENT ROUTED COVERAGE", "=", view.current_routed)
    _section(
        stream, "MORE-SPECIFIC TOPOLOGY EVIDENCE", "*", view.more_specific_evidence
    )
    _section(stream, "ROUTE CONTEXT CHANGED", "~", view.context_changes)
    _section(
        stream,
        "BASELINE COVERAGE NOT OBSERVED FROM CURRENT VANTAGE POINT",
        "-",
        view.baseline_only,
    )
    if view.pivot_paths:
        print("\nINFERRED PIVOT CONTEXT", file=stream)
        for path in view.pivot_paths:
            print(f"[?] {path.destination_network}", file=stream)
            print(
                f"    observed route context: via {path.gateway} on "
                f"{path.source_interface}",
                file=stream,
            )
            print(f"    confidence: {path.confidence.value}", file=stream)
            print("    status: ROUTING EVIDENCE ONLY", file=stream)


def _section(
    stream: TextIO, title: str, marker: str, networks: tuple[MapNetwork, ...]
) -> None:
    if not networks:
        return
    print(f"\n{title}", file=stream)
    for network in networks:
        print(f"[{marker}] {network.network}", file=stream)
        if network.origin:
            evidence = f"{network.origin}"
            if network.gateway:
                evidence += f" via {network.gateway}"
            elif network.interface:
                evidence += f" via {network.interface}"
            print(f"    evidence: {evidence}", file=stream)
        if network.confidence:
            print(f"    confidence: {network.confidence}", file=stream)
        if network.related_network:
            print(f"    related coverage: {network.related_network}", file=stream)


def _network(network: MapNetwork) -> dict[str, object]:
    return {
        "network": network.network,
        "state": network.state,
        "origin": network.origin,
        "confidence": network.confidence,
        "interface": network.interface,
        "gateway": network.gateway,
        "related_network": network.related_network,
        "annotations": list(network.annotations),
    }


def _baseline_label(view: MapView) -> str:
    return (
        view.baseline.vantage_point.display_name
        if view.baseline and view.baseline.vantage_point
        else "unavailable"
    )


def _current_label(view: MapView) -> str:
    return view.current.session.display_name if view.current.session else "unavailable"
