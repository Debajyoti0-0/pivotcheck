"""Multi-hop graph intelligence tests (v2.0 Step 4).

Adversarial matrix per the Step 4 specification: basics, branching, cycles,
duplicates, contradiction, negative evidence, family isolation,
disconnected components, invalid parameters, determinism, bounding, I/O
adversarial, secret safety.
"""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import pytest

from pivotcheck.analysis.graph import (
    build_graph,
    find_paths,
    graph_edges_from_snapshot,
)
from pivotcheck.discovery.ssh import SSHConfig  # noqa: F401  (structural no-leak proof)
from pivotcheck.models.graph import (
    EvidenceState,
    GraphEdgeKind,
    GraphEdgeSpec,
    PathStatus,
    node_family,
)
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    Neighbor,
    NetworkOrigin,
    Route,
    RouteType,
)
from pivotcheck.models.result import DiscoverySnapshot


def _edge(
    source: str,
    destination: str,
    kind: GraphEdgeKind = GraphEdgeKind.ROUTABLE_TO,
    state: EvidenceState = EvidenceState.OBSERVED,
    context: str | None = None,
) -> GraphEdgeSpec:
    return GraphEdgeSpec(source, destination, kind, state, context)


# ---------------------------------------------------------------------------
# Basic paths
# ---------------------------------------------------------------------------


class TestBasicPaths:
    def test_single_edge(self):
        graph = build_graph((_edge("a", "b"),))
        paths = find_paths(graph, "a", "b")
        assert len(paths) == 1
        assert paths[0].nodes == ("a", "b")
        assert paths[0].status is PathStatus.EVIDENCE_SUPPORTED
        assert paths[0].validated is False

    def test_two_hop_chain(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "c")))
        paths = find_paths(graph, "a", "c")
        assert len(paths) == 1
        assert paths[0].nodes == ("a", "b", "c")
        assert [e.source for e in paths[0].edges] == ["a", "b"]
        assert [e.destination for e in paths[0].edges] == ["b", "c"]

    def test_three_hop_chain(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "c"), _edge("c", "d")))
        paths = find_paths(graph, "a", "d")
        assert len(paths) == 1
        assert paths[0].nodes == ("a", "b", "c", "d")

    def test_explainability_per_hop(self):
        graph = build_graph(
            (_edge("a", "b", GraphEdgeKind.ROUTABLE_TO, EvidenceState.OBSERVED, "via gw"),)
        )
        payload = find_paths(graph, "a", "b")[0].to_dict()
        hop = payload["hops"][0]
        assert hop["source"] == "a"
        assert hop["destination"] == "b"
        assert hop["kind"] == "ROUTABLE_TO"
        assert hop["state"] == "OBSERVED"
        assert hop["contexts"] == ["via gw"]
        assert payload["limitations"]


# ---------------------------------------------------------------------------
# Branching
# ---------------------------------------------------------------------------


class TestBranching:
    def test_branching_paths_are_both_found_and_ordered(self):
        graph = build_graph(
            (_edge("a", "b"), _edge("a", "c"), _edge("b", "d"), _edge("c", "d"))
        )
        paths = find_paths(graph, "a", "d")
        assert len(paths) == 2
        node_sets = {p.nodes for p in paths}
        assert ("a", "b", "d") in node_sets
        assert ("a", "c", "d") in node_sets
        # Deterministic ordering: identical hop count -> stable node order.
        assert [p.nodes for p in paths] == sorted([p.nodes for p in paths])


# ---------------------------------------------------------------------------
# Cycles
# ---------------------------------------------------------------------------


class TestCycles:
    def test_two_node_cycle_terminates(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "a")))
        paths = find_paths(graph, "a", "b")
        assert len(paths) == 1
        assert paths[0].nodes == ("a", "b")

    def test_three_node_cycle_terminates(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "c"), _edge("c", "a")))
        paths = find_paths(graph, "a", "c")
        assert len(paths) == 1
        assert paths[0].nodes == ("a", "b", "c")

    def test_partial_cycle_does_not_duplicate(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "c"), _edge("c", "b")))
        paths = find_paths(graph, "a", "b")
        assert [p.nodes for p in paths] == [("a", "b")]

    def test_graph_is_not_mutated_by_traversal(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "a")))
        before = graph.to_dict()
        find_paths(graph, "a", "b")
        find_paths(graph, "b", "a")
        assert graph.to_dict() == before


# ---------------------------------------------------------------------------
# Duplicate evidence / canonicalization
# ---------------------------------------------------------------------------


class TestDuplicateEvidence:
    def test_duplicate_edges_merge_with_merged_contexts(self):
        graph = build_graph(
            (
                _edge("a", "b", context="route via gw1"),
                _edge("a", "b", context="route via gw1"),
                _edge("a", "b", context="confirmed by operator"),
            )
        )
        assert len(graph.edges) == 1
        assert graph.edges[0].contexts == ("confirmed by operator", "route via gw1")

    def test_conflicting_states_become_contradictory(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.OBSERVED),
                _edge("a", "b", state=EvidenceState.NEGATIVE),
            )
        )
        assert graph.edges[0].state is EvidenceState.CONTRADICTORY

    def test_contradictory_path_status(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.OBSERVED),
                _edge("a", "b", state=EvidenceState.NEGATIVE),
                _edge("b", "c"),
            )
        )
        paths = find_paths(graph, "a", "c")
        assert paths[0].status is PathStatus.CONTRADICTED
        assert paths[0].validated is False

    def test_different_kinds_are_distinct_edges(self):
        graph = build_graph(
            (
                _edge("a", "b", GraphEdgeKind.ROUTABLE_TO),
                _edge("a", "b", GraphEdgeKind.L2_NEIGHBOR),
            )
        )
        assert len(graph.edges) == 2
        paths = find_paths(graph, "a", "b")
        # Same logical relationship via two evidence kinds: simple-path
        # semantics emit both candidate paths (one per edge).
        assert len(paths) == 2

    def test_validated_subsumes_observed_for_same_relationship(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.OBSERVED),
                _edge("a", "b", state=EvidenceState.EXPLICITLY_VALIDATED),
            )
        )
        assert graph.edges[0].state is EvidenceState.EXPLICITLY_VALIDATED


# ---------------------------------------------------------------------------
# Path status composition
# ---------------------------------------------------------------------------


class TestPathStatusComposition:
    def test_validated_chain(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.EXPLICITLY_VALIDATED),
                _edge("b", "c", state=EvidenceState.EXPLICITLY_VALIDATED),
            )
        )
        paths = find_paths(graph, "a", "c")
        assert paths[0].status is PathStatus.EXPLICITLY_VALIDATED
        assert paths[0].validated is True
        assert paths[0].weakest_state is EvidenceState.EXPLICITLY_VALIDATED

    def test_mixed_validated_and_inferred_is_partially_validated(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.EXPLICITLY_VALIDATED),
                _edge("b", "c", state=EvidenceState.INFERRED),
            )
        )
        paths = find_paths(graph, "a", "c")
        assert paths[0].status is PathStatus.PARTIALLY_VALIDATED
        assert paths[0].validated is False
        assert paths[0].weakest_state is EvidenceState.INFERRED

    def test_observed_chain_is_evidence_supported(self):
        graph = build_graph((_edge("a", "b"), _edge("b", "c")))
        assert find_paths(graph, "a", "c")[0].status is PathStatus.EVIDENCE_SUPPORTED

    def test_inferred_chain_is_inferred_only(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.INFERRED),
                _edge("b", "c", state=EvidenceState.INFERRED),
            )
        )
        assert find_paths(graph, "a", "c")[0].status is PathStatus.INFERRED_ONLY


# ---------------------------------------------------------------------------
# Negative evidence
# ---------------------------------------------------------------------------


class TestNegativeEvidence:
    def test_negative_edge_is_preserved_and_path_is_contradicted(self):
        graph = build_graph(
            (
                _edge("a", "b", state=EvidenceState.NEGATIVE, context="service not observed"),
                _edge("b", "c"),
            )
        )
        paths = find_paths(graph, "a", "c")
        assert len(paths) == 1
        assert paths[0].status is PathStatus.CONTRADICTED
        assert paths[0].edges[0].state is EvidenceState.NEGATIVE
        assert "service not observed" in paths[0].edges[0].contexts


# ---------------------------------------------------------------------------
# IPv4 / IPv6 isolation
# ---------------------------------------------------------------------------


class TestFamilyIsolation:
    def test_cross_family_ip_edge_rejected(self):
        with pytest.raises(ValueError, match="cross-family"):
            build_graph((_edge("10.0.0.1", "fd00::1"),))

    def test_cross_family_edge_invalid_spec(self):
        """Family validation is fail-fast: constructing the spec raises."""
        with pytest.raises(ValueError, match="cross-family"):
            _edge("fd00::1", "10.0.0.1")

    def test_same_family_edges_coexist(self):
        graph = build_graph(
            (
                _edge("10.0.0.1", "10.0.0.2"),
                _edge("fd00::1", "fd00::2"),
            )
        )
        assert node_family("10.0.0.2") == "ipv4"
        assert node_family("fd00::2") == "ipv6"
        assert len(graph.edges) == 2

    def test_families_never_merge_in_paths(self):
        graph = build_graph(
            (
                _edge("10.0.0.1", "10.0.0.2"),
                _edge("fd00::1", "fd00::2"),
                # An adversarial mixed-family edge is impossible to construct
                # (rejected above), so paths stay within one family.
            )
        )
        assert find_paths(graph, "10.0.0.1", "fd00::2") == ()
        assert find_paths(graph, "fd00::1", "10.0.0.2") == ()

    def test_same_textual_suffix_is_not_a_merge(self):
        with pytest.raises(ValueError, match="cross-family"):
            build_graph((_edge("10.0.0.1", "fd00::1"),))


# ---------------------------------------------------------------------------
# Disconnected components / empty graph
# ---------------------------------------------------------------------------


class TestDisconnectedAndEmpty:
    def test_disconnected_components_yield_no_paths(self):
        graph = build_graph((_edge("a", "b"), _edge("x", "y")))
        assert find_paths(graph, "a", "y") == ()
        assert find_paths(graph, "x", "b") == ()

    def test_empty_graph(self):
        graph = build_graph(())
        assert graph.nodes == ()
        assert graph.edges == ()
        assert find_paths(graph, "a", "b") == ()


# ---------------------------------------------------------------------------
# Bounding and invalid parameters
# ---------------------------------------------------------------------------


class TestBounding:
    def _chain(self, count: int) -> tuple[GraphEdgeSpec, ...]:
        return tuple(_edge(f"n{i}", f"n{i + 1}") for i in range(count))

    def test_max_hops_bounds_traversal(self):
        graph = build_graph(self._chain(3))
        assert find_paths(graph, "n0", "n3", max_hops=1) == ()
        assert find_paths(graph, "n0", "n3", max_hops=2) == ()
        assert len(find_paths(graph, "n0", "n3", max_hops=3)) == 1

    def test_max_paths_bounds_results(self):
        graph = build_graph(
            (
                _edge("a", "b"),
                _edge("a", "c"),
                _edge("b", "d"),
                _edge("c", "d"),
            )
        )
        assert len(find_paths(graph, "a", "d", max_paths=1)) == 1

    def test_invalid_max_hops_rejected(self):
        graph = build_graph((_edge("a", "b"),))
        for bad in (0, -1, 1.5, "3", True):
            with pytest.raises(ValueError, match="max_hops"):
                find_paths(graph, "a", "b", max_hops=bad)  # type: ignore[arg-type]

    def test_invalid_max_paths_rejected(self):
        graph = build_graph((_edge("a", "b"),))
        for bad in (0, -2, 2.5, None):
            with pytest.raises(ValueError, match="max_paths"):
                find_paths(graph, "a", "b", max_paths=bad)  # type: ignore[arg-type]

    def test_large_chain_terminates_quickly(self):
        graph = build_graph(self._chain(200))
        paths = find_paths(graph, "n0", "n50", max_hops=50, max_paths=8)
        assert len(paths) == 1
        assert len(paths[0].nodes) == 51
        assert find_paths(graph, "n0", "n199", max_hops=10) == ()  # bounded


# ---------------------------------------------------------------------------
# Derivation from DiscoverySnapshot
# ---------------------------------------------------------------------------


def _snapshot() -> DiscoverySnapshot:
    return DiscoverySnapshot(
        hostname="vantage",
        os_name="linux",
        interfaces=(),
        routes=(
            Route("default", "10.10.20.254", "eth0", 100, RouteType.DEFAULT),
            Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
            Route("10.50.0.0/16", "10.10.20.254", "eth1", 50, RouteType.STATIC),
        ),
        neighbors=(
            Neighbor("10.10.20.1", "eth0", "aa:bb:cc:dd:ee:01", "REACHABLE"),
            Neighbor("192.168.99.9", "eth9", None, "STALE"),  # outside connected
        ),
        dns=None,
        networks=(
            DiscoveredNetwork(
                "10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"
            ),
            DiscoveredNetwork(
                "10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth1", "10.10.20.254"
            ),
        ),
    )


class TestSnapshotDerivation:
    def test_route_edges_are_derived_with_gateway_anchor(self):
        edges = graph_edges_from_snapshot(_snapshot())
        routable = [e for e in edges if e.kind is GraphEdgeKind.ROUTABLE_TO]
        assert len(routable) == 1
        assert routable[0].source == "10.10.20.0/24"
        assert routable[0].destination == "10.50.0.0/16"
        assert routable[0].state is EvidenceState.INFERRED  # entry observed, relationship inferred
        assert "via 10.10.20.254" in (routable[0].context or "")

    def test_default_route_is_skipped(self):
        edges = graph_edges_from_snapshot(_snapshot())
        assert all(e.destination != "default" for e in edges)

    def test_neighbor_edges_observed_inside_connected_network(self):
        edges = graph_edges_from_snapshot(_snapshot())
        neighbor_edges = [e for e in edges if e.kind is GraphEdgeKind.L2_NEIGHBOR]
        assert len(neighbor_edges) == 1
        assert neighbor_edges[0].source == "10.10.20.0/24"
        assert neighbor_edges[0].destination == "10.10.20.1"
        assert neighbor_edges[0].state is EvidenceState.OBSERVED
        assert "mac aa:bb:cc:dd:ee:01" in (neighbor_edges[0].context or "")

    def test_neighbor_outside_connected_network_skipped(self):
        edges = graph_edges_from_snapshot(_snapshot())
        assert all(e.destination != "192.168.99.9" for e in edges)

    def test_multi_hop_chain_from_nested_routes(self):
        snapshot = DiscoverySnapshot(
            hostname="vantage",
            os_name="linux",
            interfaces=(),
            routes=(
                Route("10.10.20.0/24", None, "eth0", 100, RouteType.CONNECTED),
                Route("10.50.0.0/16", "10.10.20.254", "eth0", 50, RouteType.STATIC),
                Route("10.60.0.0/24", "10.50.0.1", "eth0", 50, RouteType.STATIC),
            ),
            neighbors=(),
            dns=None,
            networks=(
                DiscoveredNetwork("10.10.20.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH, "eth0"),
                DiscoveredNetwork("10.50.0.0/16", NetworkOrigin.ROUTED, Confidence.MEDIUM, "eth0", "10.10.20.254"),
            ),
        )
        graph = build_graph(graph_edges_from_snapshot(snapshot))
        paths = find_paths(graph, "10.10.20.0/24", "10.60.0.0/24", max_hops=3)
        assert len(paths) == 1
        assert paths[0].nodes == ("10.10.20.0/24", "10.50.0.0/16", "10.60.0.0/24")
        # Every hop is INFERRED: routes observed, forwarding relationships not.
        assert paths[0].status is PathStatus.INFERRED_ONLY
        assert paths[0].validated is False


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def _evidence(self, order: int) -> tuple[GraphEdgeSpec, ...]:
        specs = [
            _edge("a", "b", context="route-a"),
            _edge("b", "c", context="route-b"),
            _edge("a", "c", state=EvidenceState.INFERRED, context="inferred-a"),
        ]
        rotated = specs[order % 3 :] + specs[: order % 3]
        return tuple(rotated)

    def _canonical(self) -> dict:
        return build_graph(
            (
                _edge("a", "b", context="route-a"),
                _edge("b", "c", context="route-b"),
                _edge("a", "c", state=EvidenceState.INFERRED, context="inferred-a"),
            )
        ).to_dict()

    @pytest.mark.parametrize("order", [0, 1, 2])
    def test_permutations_produce_identical_graphs(self, order: int):
        graph = build_graph(self._evidence(order))
        payload = json.dumps(graph.to_dict(), sort_keys=True)
        assert payload == json.dumps(self._canonical(), sort_keys=True)

    def test_path_output_order_independent(self):
        edges = (
            _edge("a", "b"),
            _edge("b", "c"),
            _edge("a", "c"),
        )
        graph_a = build_graph(edges)
        graph_b = build_graph(tuple(reversed(edges)))
        paths_a = json.dumps(
            [p.to_dict() for p in find_paths(graph_a, "a", "c")], sort_keys=True
        )
        paths_b = json.dumps(
            [p.to_dict() for p in find_paths(graph_b, "a", "c")], sort_keys=True
        )
        assert paths_a == paths_b


# ---------------------------------------------------------------------------
# Adversarial I/O and secret safety
# ---------------------------------------------------------------------------


class TestNoSideEffects:
    def test_engine_never_touches_socket_subprocess_filesystem_env(self, monkeypatch):
        def _explode(*args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("I/O attempted inside the pure graph engine")

        monkeypatch.setattr(socket, "socket", _explode)
        monkeypatch.setattr(socket, "create_connection", _explode)
        monkeypatch.setattr(socket, "getaddrinfo", _explode)
        monkeypatch.setattr(subprocess, "run", _explode)
        monkeypatch.setattr(subprocess, "Popen", _explode)
        monkeypatch.setattr(Path, "open", _explode)
        monkeypatch.setattr(Path, "read_text", _explode)

        graph = build_graph(
            (
                _edge("10.0.0.1", "10.0.0.2"),
                _edge("10.0.0.2", "10.0.0.3", GraphEdgeKind.L2_NEIGHBOR),
            )
        )
        paths = find_paths(graph, "10.0.0.1", "10.0.0.3")
        assert len(paths) == 1


class TestSecretSafety:
    def test_engine_never_introduces_material(self):
        """No credential exists anywhere in this test; the graph output must
        contain only what the caller supplied."""
        graph = build_graph((_edge("a", "b", context="via gw"),))
        payload = json.dumps(graph.to_dict()) + json.dumps(
            [p.to_dict() for p in find_paths(graph, "a", "b")]
        )
        assert "DO_NOT_LEAK_GRAPH_SECRET" not in payload
        assert "password" not in payload.lower()
        assert "private_key" not in payload.lower()

    def test_context_passthrough_is_the_only_free_text(self):
        graph = build_graph((_edge("a", "b", context="via 10.0.0.254 dev eth0"),))
        payload = json.dumps(graph.to_dict())
        assert "via 10.0.0.254 dev eth0" in payload
        assert "DO_NOT_LEAK_GRAPH_SECRET" not in payload

    def test_credential_types_are_structurally_absent(self):
        """Structural proof: no graph field can carry credential objects.

        The engine accepts only string identifiers, GraphEdgeKind, and
        EvidenceState — there is no parameter a credential could ride in.
        """
        import dataclasses
        import inspect

        from pivotcheck.models import graph as graph_module

        for model in (GraphEdgeSpec,):
            for field_info in dataclasses.fields(model):
                assert field_info.name != "credential"
                assert "Credential" not in str(field_info.type)
        # Module source contains no credential handling.
        source = inspect.getsource(graph_module)
        assert "Credential" not in source
