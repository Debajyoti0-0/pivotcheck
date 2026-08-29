"""Render normalized summaries, explanations, and recommendations.

Renderers contain no network reasoning: every displayed statement maps
to a field of the corresponding analysis model.
"""

from __future__ import annotations

import json
from typing import Protocol, TextIO

from pivotcheck.analysis.explanation import NetworkExplanation
from pivotcheck.analysis.recommendation import Recommendation
from pivotcheck.analysis.summary import OperationalSummary


class _Serializable(Protocol):
    def to_dict(self) -> object: ...


def intelligence_to_json(value: _Serializable | tuple[_Serializable, ...]) -> object:
    if isinstance(value, tuple):
        return [item.to_dict() for item in value]
    return value.to_dict()


def render_json(
    value: _Serializable | tuple[_Serializable, ...], stream: TextIO
) -> None:
    json.dump(intelligence_to_json(value), stream, indent=2)
    stream.write("\n")


def render_summary(summary: OperationalSummary, stream: TextIO) -> None:
    print("OPERATIONAL SUMMARY", file=stream)
    for label, value in summary.values:
        print(f"  {label.replace('_', ' ').title()}: {value}", file=stream)


def render_explanation(item: NetworkExplanation, stream: TextIO) -> None:
    print("NETWORK EXPLANATION", file=stream)
    print(f"\nNetwork:\n{item.network}", file=stream)
    print(f"\nClassification:\n{item.classification}", file=stream)
    print(f"\nWhy:\n{item.reason}", file=stream)
    print("\nCurrent evidence:", file=stream)
    print(f"  Origin: {item.origin or 'unavailable'}", file=stream)
    print(f"  Interface: {item.interface or 'unavailable'}", file=stream)
    print(f"  Gateway: {item.gateway or 'unavailable'}", file=stream)
    print(f"  Confidence: {item.confidence or 'unavailable'}", file=stream)
    if item.route_evidence:
        print("  Route:", file=stream)
        for line in item.route_evidence:
            print(f"    {line}", file=stream)
    print(
        f"\nCurrent vantage point: {item.current_vantage_point or 'unknown'}",
        file=stream,
    )
    print(
        f"Baseline: {item.baseline_vantage_point or 'none'}",
        file=stream,
    )
    print(f"\nReachability:\n{item.reachability}", file=stream)


def render_recommendations(items: tuple[Recommendation, ...], stream: TextIO) -> None:
    if not items:
        print("NO RECOMMENDATIONS - no change evidence is available.", file=stream)
        return
    print("RECOMMENDED NEXT STEPS (deterministic rule-based priorities)", file=stream)
    for item in items:
        print(f"\nPRIORITY: {item.priority}", file=stream)
        print(f"Network: {item.network}", file=stream)
        print(f"Reason: {item.reason}", file=stream)
        if item.evidence:
            print("Evidence:", file=stream)
            for line in item.evidence:
                print(f"  {line}", file=stream)
        print(f"Suggested next action: {item.suggested_action}", file=stream)
        print(f"Limitation: {item.limitation}", file=stream)