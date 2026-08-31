"""Multi-hop graph intelligence (v2.0 Step 4).

PURE ANALYSIS: no network I/O, no subprocesses, no filesystem access, no
environment access. Builds a canonical evidence-bounded graph from
already-normalized edge specifications (or directly from a
``DiscoverySnapshot``) and performs bounded simple-path discovery with
deterministic, explainable results.

What a returned path MEANS:

    "An evidence-supported candidate path exists between start and
    destination, composed of the per-hop evidence states below."

What it NEVER means:

    "The operator can pivot A -> B -> C." Connectivity is not
    authentication, forwarding, execution, tunneling, or capability.

Determinism: nodes, edges, contexts, and paths are canonically ordered;
input order never affects output. Cycles terminate via simple-path
traversal (per-path visited set); traversal and result counts are bounded
by ``max_hops`` and ``max_paths``.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from pivotcheck.models.graph import (
    _STATE_RANK,
    PATH_LIMITATIONS,
    EvidenceGraph,
    EvidencePath,
    EvidenceState,
    GraphEdge,
    GraphEdgeKind,
    GraphEdgeSpec,
    GraphNode,
    node_family,
    status_for_states,
)
from pivotcheck.models.result import DiscoverySnapshot

_DEFAULT_MAX_HOPS = 4
_DEFAULT_MAX_PATHS = 32


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def _merge_state(states: tuple[EvidenceState, ...]) -> EvidenceState:
    """Merge evidence states for one logical relationship.

    Rules (deterministic, no silent normalization):

    - A single state passes through unchanged.
    - UNKNOWN contributes nothing; it is dropped when other states exist.
    - A positive claim conflicting with a NEGATIVE claim is CONTRADICTORY.
    - Explicit validation subsumes weaker positive states for the same
      relationship (validated implies the relationship was exercised).
    - Anything else conflicting collapses to CONTRADICTORY.
    """
    unique = set(states)
    if not unique:
        return EvidenceState.UNKNOWN
    if len(unique) == 1:
        return next(iter(unique))
    unique.discard(EvidenceState.UNKNOWN)
    if not unique:
        return EvidenceState.UNKNOWN
    if EvidenceState.NEGATIVE in unique:
        return EvidenceState.CONTRADICTORY
    if EvidenceState.EXPLICITLY_VALIDATED in unique:
        return EvidenceState.EXPLICITLY_VALIDATED
    if EvidenceState.OBSERVED in unique and EvidenceState.INFERRED in unique:
        return EvidenceState.OBSERVED
    if EvidenceState.CONTRADICTORY in unique:
        return EvidenceState.CONTRADICTORY
    return next(iter(unique))


def build_graph(edges: tuple[GraphEdgeSpec, ...] | list[GraphEdgeSpec]) -> EvidenceGraph:
    """Build a canonical graph from edge specifications.

    - Nodes and edges are canonically ordered (input order is irrelevant).
    - Duplicate evidence for the same (source, destination, kind) merges
      into one edge; conflicting states become CONTRADICTORY.
    - Cross-family IP-literal edges are rejected.
    """
    for edge in edges:
        edge.validate_families()

    edge_groups: dict[tuple[str, str, GraphEdgeKind], list[GraphEdgeSpec]] = defaultdict(list)
    node_states: dict[str, list[EvidenceState]] = defaultdict(list)
    node_contexts: dict[str, set[str]] = defaultdict(set)

    for edge in edges:
        edge_groups[(edge.source, edge.destination, edge.kind)].append(edge)
        node_states[edge.source].append(edge.state)
        node_states[edge.destination].append(edge.state)
        if edge.context:
            node_contexts[edge.source].add(edge.context)
            node_contexts[edge.destination].add(edge.context)

    merged_edges: list[GraphEdge] = []
    for (source, destination, kind), group in sorted(
        edge_groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2].value)
    ):
        states = tuple(item.state for item in group)
        contexts = tuple(
            sorted({item.context for item in group if item.context})
        )
        merged_edges.append(
            GraphEdge(
                source=source,
                destination=destination,
                kind=kind,
                state=_merge_state(states),
                contexts=contexts,
            )
        )
    merged_edges.sort(key=lambda e: (e.source, e.destination, e.kind.value))

    node_identifiers = sorted(node_states)
    nodes = tuple(
        GraphNode(
            identifier=identifier,
            family=node_family(identifier),
            state=_merge_state(tuple(node_states[identifier])),
            contexts=tuple(sorted(node_contexts[identifier])),
        )
        for identifier in node_identifiers
    )
    return EvidenceGraph(nodes=nodes, edges=tuple(merged_edges))


# ---------------------------------------------------------------------------
# Derivation from normalized discovery evidence
# ---------------------------------------------------------------------------


def _contains(cidr: str, address: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def graph_edges_from_snapshot(
    snapshot: DiscoverySnapshot,
) -> tuple[GraphEdgeSpec, ...]:
    """Derive graph edge specifications from a normalized discovery snapshot.

    Derivation rules (all deterministic, evidence-faithful):

    - ROUTABLE_TO (INFERRED): a routing-table entry to ``destination`` via
      ``gateway``, where the gateway lives in a connected network. The
      entry is OBSERVED; the forwarding relationship is INFERRED.
    - L2_NEIGHBOR (OBSERVED): a neighbor (ARP) entry inside a connected
      network. The table entry is observed.

    Default routes are skipped: a default route has no meaningful
    destination node. Neighbor entries outside every connected network are
    skipped (no edge can be anchored).
    """
    connected = [
        network
        for network in snapshot.networks
        if network.origin.value == "connected"
    ]
    routed = [
        network
        for network in snapshot.networks
        if network.origin.value == "routed"
    ]
    edges: list[GraphEdgeSpec] = []

    for route in snapshot.routes:
        if route.route_type.value == "connected" or route.destination == "default":
            continue
        if route.gateway is None:
            continue
        # Anchor the edge at the network containing the gateway: a connected
        # network first, otherwise a routed network (nested routes are the
        # route table's own multi-hop topology evidence). The relationship
        # stays INFERRED either way — forwarding is never proven by a table
        # entry.
        anchor = next(
            (
                network
                for network in (*connected, *routed)
                if _contains(network.cidr, route.gateway)
            ),
            None,
        )
        if anchor is None:
            continue
        if anchor.cidr == route.destination:
            continue  # gateway inside its own destination: no edge to self
        edges.append(
            GraphEdgeSpec(
                source=anchor.cidr,
                destination=route.destination,
                kind=GraphEdgeKind.ROUTABLE_TO,
                state=EvidenceState.INFERRED,
                context=f"via {route.gateway} dev {route.interface}",
            )
        )

    for neighbor in snapshot.neighbors:
        anchor = next(
            (network for network in connected if _contains(network.cidr, neighbor.ip_address)),
            None,
        )
        if anchor is None:
            continue
        context = f"interface {neighbor.interface}"
        if neighbor.mac_address:
            context += f" mac {neighbor.mac_address}"
        edges.append(
            GraphEdgeSpec(
                source=anchor.cidr,
                destination=neighbor.ip_address,
                kind=GraphEdgeKind.L2_NEIGHBOR,
                state=EvidenceState.OBSERVED,
                context=context,
            )
        )
    return tuple(edges)


# ---------------------------------------------------------------------------
# Bounded simple-path discovery
# ---------------------------------------------------------------------------


def find_paths(
    graph: EvidenceGraph,
    start: str,
    destination: str,
    max_hops: int = _DEFAULT_MAX_HOPS,
    max_paths: int = _DEFAULT_MAX_PATHS,
) -> tuple[EvidencePath, ...]:
    """Discover evidence-supported candidate paths (bounded, deterministic).

    - Simple paths only (per-path visited set): cycles terminate
      deterministically and cyclic duplicates are never emitted.
    - Traversal never mutates the graph.
    - Results are sorted by (hop count, weakest evidence state, node
      sequence) and capped at ``max_paths``.

    Raises:
        ValueError: ``max_hops`` or ``max_paths`` is not a positive
            integer, or start/destination is empty.
    """
    if not isinstance(max_hops, int) or isinstance(max_hops, bool) or max_hops <= 0:
        raise ValueError("max_hops must be a positive integer")
    if not isinstance(max_paths, int) or isinstance(max_paths, bool) or max_paths <= 0:
        raise ValueError("max_paths must be a positive integer")
    if not start or not destination:
        raise ValueError("start and destination are required")

    adjacency: dict[str, list[GraphEdge]] = defaultdict(list)
    for edge in graph.edges:
        adjacency[edge.source].append(edge)
    for edges_from_source in adjacency.values():
        edges_from_source.sort(
            key=lambda e: (e.destination, e.kind.value, e.state.value)
        )

    found: list[EvidencePath] = []

    def walk(node: str, visited: tuple[str, ...], trail: tuple[GraphEdge, ...]) -> None:
        if len(found) >= max_paths:
            return
        if node == destination and trail:
            states = tuple(edge.state for edge in trail)
            found.append(
                EvidencePath(
                    nodes=visited,
                    edges=trail,
                    status=status_for_states(states),
                    weakest_state=min(states, key=lambda s: _STATE_RANK[s]),
                    validated=all(
                        state is EvidenceState.EXPLICITLY_VALIDATED for state in states
                    ),
                    limitations=PATH_LIMITATIONS,
                )
            )
            return
        if len(visited) > max_hops:
            return
        for edge in adjacency.get(node, ()):
            if edge.destination in visited:
                continue  # simple-path semantics: cycles terminate here
            walk(edge.destination, (*visited, edge.destination), (*trail, edge))
            if len(found) >= max_paths:
                return

    walk(start, (start,), ())

    found.sort(
        key=lambda path: (
            len(path.nodes),
            min(_STATE_RANK[edge.state] for edge in path.edges),
            path.nodes,
        )
    )
    return tuple(found[:max_paths])


def build_evidence_graph_and_paths(
    edges: tuple[GraphEdgeSpec, ...] | list[GraphEdgeSpec],
    start: str,
    destination: str,
    max_hops: int = _DEFAULT_MAX_HOPS,
    max_paths: int = _DEFAULT_MAX_PATHS,
) -> tuple[EvidenceGraph, tuple[EvidencePath, ...]]:
    """Convenience composition: canonical graph + bounded path search."""
    graph = build_graph(edges)
    return graph, find_paths(graph, start, destination, max_hops=max_hops, max_paths=max_paths)
