"""Deterministic summaries derived from normalized models."""

from __future__ import annotations

from dataclasses import dataclass

from pivotcheck.analysis.comparison import DiffReport
from pivotcheck.models.network import NetworkOrigin
from pivotcheck.models.result import DiscoverySnapshot


@dataclass(frozen=True)
class OperationalSummary:
    values: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, int]:
        return dict(self.values)


def summarize_snapshot(snapshot: DiscoverySnapshot) -> OperationalSummary:
    return OperationalSummary((
        ("interfaces", len(snapshot.interfaces)), ("connected_coverage", sum(n.origin is NetworkOrigin.CONNECTED for n in snapshot.networks)),
        ("routed_coverage", sum(n.origin is NetworkOrigin.ROUTED for n in snapshot.networks)),
        ("neighbors", len(snapshot.neighbors)), ("dns_servers", len(snapshot.dns.servers)),
        ("connections", len(snapshot.connections)), ("inferred_pivot_paths", len(snapshot.pivot_paths)), ("warnings", len(snapshot.warnings)),
    ))


def summarize_comparison(report: DiffReport) -> OperationalSummary:
    return OperationalSummary((
        ("new_coverage", len(report.new_networks)),
        ("expanded_coverage", sum(item.classification == "EXPANDED_REACHABILITY" for item in report.coverage_changes)),
        ("reduced_coverage", sum(item.classification == "REDUCED_COVERAGE" for item in report.coverage_changes)),
        ("more_specific_evidence", len(report.specificity_changes)),
        ("context_changes", len(report.context_changes)),
        ("unchanged_coverage", len(report.unchanged_networks)),
    ))
