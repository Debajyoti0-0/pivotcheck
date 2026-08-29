"""Dedicated human and JSON renderers for perspective comparison."""

from __future__ import annotations

import json
from typing import TextIO

from pivotcheck.analysis.comparison import DiffFinding, DiffReport
from pivotcheck.models.baseline import Baseline
from pivotcheck.models.check import public_comparison_label
from pivotcheck.storage.baseline_store import StoredBaseline


def comparison_to_dict(
    stored: StoredBaseline, current: Baseline, report: DiffReport
) -> dict[str, object]:
    return {
        "baseline": {"name": stored.name, "vantage_point": _session(stored.baseline)},
        "current": {"vantage_point": _session(current)},
        "comparison": {
            "new_reachability": [_finding(item) for item in report.new_networks],
            "expanded_coverage": [
                _finding(item)
                for item in report.coverage_changes
                if item.classification == "EXPANDED_REACHABILITY"
            ],
            "reduced_coverage": [
                _finding(item)
                for item in report.coverage_changes
                if item.classification == "REDUCED_COVERAGE"
            ],
            "specificity_changes": [
                _finding(item) for item in report.specificity_changes
            ],
            "context_changes": [_finding(item) for item in report.context_changes],
        },
    }


def render_comparison_json(
    stored: StoredBaseline, current: Baseline, report: DiffReport, stream: TextIO
) -> None:
    json.dump(comparison_to_dict(stored, current, report), stream, indent=2)
    stream.write("\n")


def render_comparison(
    stored: StoredBaseline,
    current: Baseline,
    report: DiffReport,
    stream: TextIO,
    *,
    verbose: bool = False,
) -> None:
    print("PIVOTCHECK - PERSPECTIVE COMPARISON", file=stream)
    print(f"Baseline: {stored.name}", file=stream)
    print(f"Baseline Vantage Point: {_label(stored.baseline)}", file=stream)
    print(f"Current Vantage Point: {_label(current)}", file=stream)
    _section(stream, "NEW ADDRESS-SPACE COVERAGE", report.new_networks, "+")
    _section(
        stream,
        "EXPANDED COVERAGE",
        [
            item
            for item in report.coverage_changes
            if item.classification == "EXPANDED_REACHABILITY"
        ],
        "+",
    )
    _section(
        stream,
        "LOST COVERAGE EVIDENCE",
        [
            item
            for item in report.coverage_changes
            if item.classification == "REDUCED_COVERAGE"
        ],
        "-",
    )
    _section(stream, "MORE SPECIFIC TOPOLOGY EVIDENCE", report.specificity_changes, "*")
    _section(stream, "ROUTE CONTEXT CHANGES", report.context_changes, "~")
    if verbose:
        _section(stream, "UNCHANGED COVERAGE", report.unchanged_networks, "=")


def _section(
    stream: TextIO,
    title: str,
    findings: list[DiffFinding] | tuple[DiffFinding, ...],
    marker: str,
) -> None:
    if not findings:
        return
    print(f"\n{title}", file=stream)
    for item in findings:
        print(f"[{marker}] {item.network}", file=stream)
        if item.related_network:
            print(f"    Related coverage: {item.related_network}", file=stream)


def _session(baseline: Baseline) -> dict[str, str] | None:
    return baseline.vantage_point.to_dict() if baseline.vantage_point else None


def _label(baseline: Baseline) -> str:
    return baseline.vantage_point.display_name if baseline.vantage_point else "unknown"


def _finding(finding: DiffFinding) -> dict[str, object]:
    return {
        "network": finding.network,
        "classification": public_comparison_label(finding.classification),
        "relationship": finding.relationship.value if finding.relationship else None,
        "related_network": finding.related_network,
        "reachability_novelty": finding.reachability_novelty,
        "topology_novelty": finding.topology_novelty,
    }
