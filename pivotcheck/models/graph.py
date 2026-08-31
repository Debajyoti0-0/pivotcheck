"""Evidence-bounded topology graph models (v2.0 Step 4).

The graph is a REASONING layer over already-normalized evidence. Graph
connectivity is NOT authentication, forwarding, routing administration,
command execution, tunnel availability, or pivot capability. Every node,
edge, and path preserves the epistemic state of the evidence behind it:

    OBSERVED             fact collected from the vantage point
    INFERRED             derived deterministically from observed facts
                         (e.g. a route table entry implies a possible
                         routing relationship — the entry is observed,
                         the relationship is inferred)
    EXPLICITLY_VALIDATED proven by an explicit prior check (Step 2)
    NEGATIVE             explicitly ruled out by observation
    CONTRADICTORY        conflicting evidence; never silently normalized
    UNKNOWN              no usable evidence

Family isolation is structural: IPv4 and IPv6 nodes never share an edge
(mismatched IP-literal families are rejected at construction).

No secrets: the graph layer has no credential parameters. Edges carry
caller-supplied *context* strings only; credential material must never be
placed there by callers (enforced by adversarial tests at the call sites).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum


class GraphEdgeKind(str, Enum):
    """Relationship classes justified by existing repository evidence."""

    ROUTABLE_TO = "ROUTABLE_TO"  # routing-table evidence of a route via a gateway
    L2_NEIGHBOR = "L2_NEIGHBOR"  # ARP/neighbor observation
    NETWORK_CONNECTED = "NETWORK_CONNECTED"  # interface-connected coverage
    SERVICE_OBSERVED = "SERVICE_OBSERVED"  # a service interaction was observed
    AUTH_VALIDATED = "AUTH_VALIDATED"  # explicit prior authentication success


class EvidenceState(str, Enum):
    """Epistemic state of the evidence behind a graph element."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    EXPLICITLY_VALIDATED = "EXPLICITLY_VALIDATED"
    NEGATIVE = "NEGATIVE"
    CONTRADICTORY = "CONTRADICTORY"
    UNKNOWN = "UNKNOWN"


# Weakest-to-strongest ordering used for path composition and ranking.
_STATE_RANK = {
    EvidenceState.CONTRADICTORY: 0,
    EvidenceState.NEGATIVE: 1,
    EvidenceState.UNKNOWN: 2,
    EvidenceState.INFERRED: 3,
    EvidenceState.OBSERVED: 4,
    EvidenceState.EXPLICITLY_VALIDATED: 5,
}


class PathStatus(str, Enum):
    """Evidence-composition status of a multi-hop candidate path.

    Derived per-hop from the weakest evidence state in the path:

    - EXPLICITLY_VALIDATED: every hop carries explicit validation evidence.
    - EVIDENCE_SUPPORTED: every hop is OBSERVED or stronger.
    - PARTIALLY_VALIDATED: mixed validated and observed/inferred hops.
    - INFERRED_ONLY: at least one hop is INFERRED and none are weaker.
    - CONTRADICTED: at least one hop is CONTRADICTORY or NEGATIVE.

    A path status describes evidence composition ONLY — never capability
    (execution, forwarding, tunneling) and never certainty.
    """

    EXPLICITLY_VALIDATED = "EXPLICITLY_VALIDATED"
    EVIDENCE_SUPPORTED = "EVIDENCE_SUPPORTED"
    PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"
    INFERRED_ONLY = "INFERRED_ONLY"
    CONTRADICTED = "CONTRADICTED"


def status_for_states(states: tuple[EvidenceState, ...]) -> PathStatus:
    """Compose per-hop states into one path status (pure, deterministic)."""
    if not states:
        return PathStatus.INFERRED_ONLY
    states_set = set(states)
    if EvidenceState.CONTRADICTORY in states_set or EvidenceState.NEGATIVE in states_set:
        return PathStatus.CONTRADICTED
    if all(state is EvidenceState.EXPLICITLY_VALIDATED for state in states):
        return PathStatus.EXPLICITLY_VALIDATED
    if any(state is EvidenceState.EXPLICITLY_VALIDATED for state in states):
        return PathStatus.PARTIALLY_VALIDATED
    if all(state in (EvidenceState.OBSERVED, EvidenceState.EXPLICITLY_VALIDATED) for state in states):
        return PathStatus.EVIDENCE_SUPPORTED
    return PathStatus.INFERRED_ONLY


class GraphEdgeKindError(ValueError):
    """Raised for structurally invalid graph edge specifications."""


def node_family(node: str) -> str | None:
    """IPv4 / IPv6 family of an IP-literal node; None for named nodes."""
    try:
        return f"ipv{ipaddress.ip_address(node).version}"
    except ValueError:
        return None


@dataclass(frozen=True)
class GraphEdgeSpec:
    """Caller-supplied evidence for one relationship.

    ``context`` is free-form, display-safe metadata (e.g. "via 10.10.20.254
    dev eth1"). It must never contain credential material — the graph layer
    carries no credentials by construction.
    """

    source: str
    destination: str
    kind: GraphEdgeKind
    state: EvidenceState = EvidenceState.OBSERVED
    context: str | None = None

    def __post_init__(self) -> None:
        for name, value in (("source", self.source), ("destination", self.destination)):
            if not value or value.strip() != value:
                raise GraphEdgeKindError(f"edge {name} must be a non-empty, trimmed identifier")
            if any(ch.isspace() for ch in value):
                raise GraphEdgeKindError(f"edge {name} must not contain whitespace: {value!r}")
        if not isinstance(self.kind, GraphEdgeKind):
            raise GraphEdgeKindError(f"invalid edge kind: {self.kind!r}")
        if not isinstance(self.state, EvidenceState):
            raise GraphEdgeKindError(f"invalid evidence state: {self.state!r}")
        self.validate_families()

    def _family_pair(self) -> tuple[str | None, str | None]:
        return node_family(self.source), node_family(self.destination)

    def validate_families(self) -> None:
        """Reject IP-literal edges that cross address families."""
        source_family, destination_family = self._family_pair()
        if source_family and destination_family and source_family != destination_family:
            raise GraphEdgeKindError(
                f"cross-family edge rejected: {self.source!r} "
                f"({source_family}) -> {self.destination!r} ({destination_family})"
            )


@dataclass(frozen=True)
class GraphNode:
    """One canonical graph node with merged evidence state."""

    identifier: str
    family: str | None
    state: EvidenceState
    contexts: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "family": self.family,
            "state": self.state.value,
            "contexts": list(self.contexts),
        }


@dataclass(frozen=True)
class GraphEdge:
    """One canonical graph edge with merged evidence state and contexts."""

    source: str
    destination: str
    kind: GraphEdgeKind
    state: EvidenceState
    contexts: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "destination": self.destination,
            "kind": self.kind.value,
            "state": self.state.value,
            "contexts": list(self.contexts),
        }


@dataclass(frozen=True)
class EvidenceGraph:
    """Canonical, deterministic evidence-bounded graph."""

    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


PATH_LIMITATIONS: tuple[str, ...] = (
    "Path connectivity is evidence composition only. It does NOT prove authentication, command execution, traffic forwarding, tunnel availability, or pivot capability on any hop.",
    "A route-table hop is INFERRED: the routing entry is observed, but the gateway's willingness to forward is not.",
    "At least one hop is NOT explicitly validated; the path is a candidate for explicit validation, never a confirmed pivot path.",
)


@dataclass(frozen=True)
class EvidencePath:
    """One evidence-supported candidate path through the graph."""

    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    status: PathStatus
    weakest_state: EvidenceState
    validated: bool
    limitations: tuple[str, ...] = PATH_LIMITATIONS

    def to_dict(self) -> dict:
        return {
            "path": list(self.nodes),
            "status": self.status.value,
            "validated": self.validated,
            "weakest_state": self.weakest_state.value,
            "hops": [
                {
                    "source": edge.source,
                    "destination": edge.destination,
                    "kind": edge.kind.value,
                    "state": edge.state.value,
                    "contexts": list(edge.contexts),
                }
                for edge in self.edges
            ],
            "limitations": list(self.limitations),
        }
