"""Pure presentation/query filters; never alters collection or comparison."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, replace

from pivotcheck.analysis.comparison import DiffFinding, DiffReport
from pivotcheck.analysis.map_view import MapNetwork, MapView
from pivotcheck.models.network import Confidence, DiscoveredNetwork
from pivotcheck.models.result import DiscoverySnapshot

_CONFIDENCE = {Confidence.LOW.value: 0, Confidence.MEDIUM.value: 1, Confidence.HIGH.value: 2}


@dataclass(frozen=True)
class QueryOptions:
    interface: str | None = None
    family: str = "all"
    focus: str | None = None
    changes_only: bool = False
    minimum_confidence: str | None = None

    def __post_init__(self) -> None:
        if self.family not in {"all", "ipv4", "ipv6"}:
            raise ValueError("family must be ipv4, ipv6, or all")
        if self.minimum_confidence and self.minimum_confidence not in _CONFIDENCE:
            raise ValueError("minimum confidence must be low, medium, or high")
        if self.focus:
            try:
                ipaddress.ip_network(self.focus, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid focus network: {self.focus!r}") from exc


def filter_snapshot(snapshot: DiscoverySnapshot, options: QueryOptions) -> DiscoverySnapshot:
    """Filter presentation evidence while retaining unrelated raw metadata."""
    networks = tuple(network for network in snapshot.networks if _matches(network.cidr, network.interface, network.confidence.value, options))
    paths = tuple(path for path in snapshot.pivot_paths if _matches(path.destination_network, path.source_interface, path.confidence.value, options))
    return replace(snapshot, networks=networks, pivot_paths=paths)


def filter_report(report: DiffReport, snapshot: DiscoverySnapshot, options: QueryOptions) -> DiffReport:
    evidence = {str(ipaddress.ip_network(network.cidr, strict=False)): network for network in snapshot.networks}
    def keep(items: tuple[DiffFinding, ...]) -> tuple[DiffFinding, ...]:
        return tuple(item for item in items if _finding_matches(item, evidence, options))
    return DiffReport(
        new_networks=keep(report.new_networks), specificity_changes=keep(report.specificity_changes),
        coverage_changes=keep(report.coverage_changes),
        unchanged_networks=() if options.changes_only else keep(report.unchanged_networks),
        context_changes=keep(report.context_changes), warnings=report.warnings,
    )


def filter_map_view(view: MapView, options: QueryOptions, *, show_pivots: bool = False) -> MapView:
    """Presentation-only map filtering; never recomputes comparison state.

    ``show_pivots=True`` selects ONLY the inferred pivot context (still
    subject to the same evidence filters). Otherwise every section is
    filtered consistently, pivot paths included, so family/interface/focus
    filters behave identically across all map content.
    """
    def keep(items: tuple[MapNetwork, ...]) -> tuple[MapNetwork, ...]:
        return tuple(item for item in items if _matches(item.network, item.interface, item.confidence, options))

    def keep_paths(paths: tuple) -> tuple:
        return tuple(
            path for path in paths
            if _matches(path.destination_network, path.source_interface, path.confidence.value, options)
        )

    if show_pivots:
        return replace(
            view,
            new_coverage=(), expanded_coverage=(),
            current_connected=(), current_routed=(),
            more_specific_evidence=(), context_changes=(),
            baseline_only=(), unchanged=(),
            pivot_paths=keep_paths(view.pivot_paths),
        )
    return replace(
        view,
        new_coverage=keep(view.new_coverage), expanded_coverage=keep(view.expanded_coverage),
        current_connected=() if options.changes_only else keep(view.current_connected),
        current_routed=() if options.changes_only else keep(view.current_routed),
        more_specific_evidence=keep(view.more_specific_evidence), context_changes=keep(view.context_changes),
        baseline_only=keep(view.baseline_only), unchanged=() if options.changes_only else keep(view.unchanged),
        pivot_paths=keep_paths(view.pivot_paths),
    )


def resolve_focus_network(candidate: str, known_networks) -> str:
    """Resolve operator input to exactly one canonical CIDR.

    Accepts an exact CIDR or a bare IP contained in exactly one known
    network. Ambiguous or unmatched input raises ValueError; this layer
    never silently picks an arbitrary network.
    """
    known = sorted({
        str(ipaddress.ip_network(network, strict=False))
        for network in known_networks
    })
    if "/" in candidate:
        canonical = str(ipaddress.ip_network(candidate, strict=False))
        if known and canonical not in set(known):
            raise ValueError(f"{canonical} does not match any known network")
        return canonical
    address = ipaddress.ip_address(candidate)
    matches = [
        network for network in known
        if ipaddress.ip_network(network).version == address.version
        and address in ipaddress.ip_network(network)
    ]
    if len(matches) == 1:
        return str(ipaddress.ip_network(matches[0], strict=False))
    if len(matches) > 1:
        listed = ", ".join(sorted(str(ipaddress.ip_network(n, strict=False)) for n in matches))
        raise ValueError(
            f"{candidate} is inside multiple networks; specify one explicitly: {listed}"
        )
    raise ValueError(f"{candidate} does not match any known network")


def _finding_matches(finding: DiffFinding, evidence: Mapping[str, DiscoveredNetwork], options: QueryOptions) -> bool:
    network = evidence.get(finding.network)
    if network is None:
        return _matches(finding.network, None, None, options)
    return _matches(finding.network, network.interface, network.confidence.value, options)


def _matches(network: str, interface: str | None, confidence: str | None, options: QueryOptions) -> bool:
    parsed = ipaddress.ip_network(network, strict=False)
    if options.family != "all" and parsed.version != (4 if options.family == "ipv4" else 6):
        return False
    if options.interface and interface is not None and interface != options.interface:
        return False
    if options.minimum_confidence and confidence is not None and _CONFIDENCE[confidence] < _CONFIDENCE[options.minimum_confidence]:
        return False
    if options.focus:
        focus = ipaddress.ip_network(options.focus, strict=False)
        if focus.version != parsed.version or not focus.overlaps(parsed):
            return False
    return True
