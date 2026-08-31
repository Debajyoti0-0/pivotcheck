"""Result models for active reachability checks.

Presentation-independent models consumed by both terminal and JSON output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CheckStatus(str, Enum):
    """Outcome classification of a TCP reachability attempt.

    Semantics are deliberately precise:
    - SUCCESS: TCP three-way handshake completed.
    - REFUSED: target actively rejected the connection (RST). The path may
      be functional; the service/port is not accepting.
    - TIMEOUT: no response within the timeout. AMBIGUOUS — this does NOT
      prove the host is offline (filtering, loss, or service state).
    - NO_ROUTE: local system could not establish a usable route.
    - DNS_ERROR: target name could not be resolved.
    - INVALID_TARGET: input failed validation before any network activity.
    - LOCAL_ERROR: other local socket/OS error; result unknown.
    """

    SUCCESS = "SUCCESS"
    REFUSED = "REFUSED"
    TIMEOUT = "TIMEOUT"
    NO_ROUTE = "NO_ROUTE"
    UNREACHABLE = "UNREACHABLE"
    DNS_ERROR = "DNS_ERROR"
    INVALID_TARGET = "INVALID_TARGET"
    LOCAL_ERROR = "LOCAL_ERROR"


class RouteContextType(str, Enum):
    """How the checked destination relates to known discovery evidence."""

    CONNECTED = "CONNECTED"  # destination inside a directly attached subnet
    ROUTED = "ROUTED"  # destination inside a routed subnet via gateway
    UNKNOWN = "UNKNOWN"  # no matching discovery evidence


class TransitEvidenceAssessment(str, Enum):
    """Evidence composition assessment for a transit candidate.

    Describes what independent observations exist in the current snapshot.
    Does NOT imply forwarding, reachability, or pivot capability.
    """

    # Only routing table evidence
    ROUTING_ONLY = "ROUTING_ONLY"

    # Routing + neighbor evidence (any state except FAILED)
    ROUTING_PLUS_L2_EVIDENCE = "ROUTING_PLUS_L2_EVIDENCE"

    # Routing + active TCP connection to gateway
    ROUTING_PLUS_ACTIVE_TCP_EVIDENCE = "ROUTING_PLUS_ACTIVE_TCP_EVIDENCE"

    # Routing + active UDP flow to gateway
    ROUTING_PLUS_ACTIVE_UDP_EVIDENCE = "ROUTING_PLUS_ACTIVE_UDP_EVIDENCE"

    # Routing + historical TCP (TIME_WAIT, CLOSE_WAIT)
    ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE = "ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE"

    # Routing + neighbor (REACHABLE) + active TCP
    MULTIPLE_SUPPORTING_SIGNALS = "MULTIPLE_SUPPORTING_SIGNALS"

    # Routing + neighbor (STALE) + active TCP
    MULTIPLE_SUPPORTING_SIGNALS_STALE_L2 = "MULTIPLE_SUPPORTING_SIGNALS_STALE_L2"

    # Routing + FAILED neighbor (negative L2 evidence)
    ROUTING_WITH_NEGATIVE_L2_EVIDENCE = "ROUTING_WITH_NEGATIVE_L2_EVIDENCE"

    # Contradictory: FAILED neighbor but active TCP works
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"

    # No route evidence (should not occur for PivotPath-derived candidates)
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


# Internal comparison labels -> documented public vocabulary.
# Sources of internal labels:
#   - DiffFinding.classification (analysis/comparison.py)
#   - ComparisonContext.relationship (checks/context.py)
# Values without a documented alternative are deliberately passed through:
# they appear only under grouping keys that already identify the category.
_PUBLIC_COMPARISON_LABELS: dict[str, str] = {
    # DiffFinding.classification (internal analysis vocabulary)
    "NEW_REACHABILITY": "NEW",
    "EXPANDED_REACHABILITY": "EXPANDED",
    "REDUCED_COVERAGE": "REDUCED",
    "UNCHANGED_COVERAGE": "UNCHANGED",
    # ComparisonContext.relationship (context vocabulary)
    "NEW_COVERAGE": "NEW",
    "EXPANDED_COVERAGE": "EXPANDED",
    "UNCHANGED": "UNCHANGED",
    # Deliberate public values (documented known states / grouped categories)
    "MORE_SPECIFIC": "MORE_SPECIFIC",
    "ROUTE_CONTEXT_CHANGED": "ROUTE_CONTEXT_CHANGED",
    "CONTEXT_CHANGED": "CONTEXT_CHANGED",
    "NOT_OBSERVED_IN_BASELINE": "NOT_OBSERVED_IN_BASELINE",
    # Already-public labels (idempotent)
    "NEW": "NEW",
    "EXPANDED": "EXPANDED",
    "REDUCED": "REDUCED",
}


def public_comparison_label(value: str | None) -> str | None:
    """Map an internal comparison label to the documented public vocabulary.

    Single serialization-boundary mapping (see README.md, Output
    Contracts). Internal labels such as NEW_REACHABILITY must never reach
    operator-facing text or JSON verbatim.
    """
    if value is None:
        return None
    return _PUBLIC_COMPARISON_LABELS.get(value, value)


@dataclass(frozen=True)
class RouteContext:
    """Discovery-derived context for a checked destination."""

    context_type: RouteContextType
    network: str | None = None
    gateway: str | None = None
    interface: str | None = None
    confidence: str | None = None

    def to_dict(self) -> dict:
        return {
            "type": self.context_type.value,
            "network": self.network,
            "gateway": self.gateway,
            "interface": self.interface,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ResolvedTarget:
    """A validated target with its resolved address(es)."""

    original: str  # as typed by the operator
    addresses: tuple[str, ...]  # normalized IP literals after resolution
    error: str | None = None  # set when resolution failed

    @property
    def ok(self) -> bool:
        return bool(self.addresses)


@dataclass(frozen=True)
class CheckResult:
    """Result of one TCP validation attempt against one address:port."""

    target: str
    address: str
    port: int
    protocol: str = "tcp"
    status: CheckStatus = CheckStatus.LOCAL_ERROR
    elapsed_ms: float | None = None
    error: str | None = None
    route_context: RouteContext | None = None

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "address": self.address,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status.value,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "route_context": (
                self.route_context.to_dict() if self.route_context else None
            ),
        }


@dataclass(frozen=True)
class NetworkMatch:
    """The most-specific normalized network containing a validated target.

    ``match_type`` is one of:
    - EXACT: the target's own host route (/32 or /128) is present.
    - MOST_SPECIFIC: multiple networks contain the target; this is the
      longest-prefix match.
    - COVERED: only a broader network contains the target.

    Broader containing networks are preserved separately for context; they
    are never used to override the most-specific match.
    """

    network: str
    match_type: str
    broader_networks: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "network": self.network,
            "match_type": self.match_type,
            "broader_networks": list(self.broader_networks),
        }


@dataclass(frozen=True)
class ComparisonContext:
    """How the target's containing network relates to a saved baseline.

    ``relationship`` is one of:
    - NEW_COVERAGE: network is new relative to baseline coverage.
    - EXPANDED_COVERAGE: network expands baseline address-space coverage.
    - REDUCED_COVERAGE: network narrows baseline address-space coverage.
    - MORE_SPECIFIC: network is more-specific topology evidence.
    - CONTEXT_CHANGED: network unchanged but route context differs.
    - UNCHANGED: network and context match baseline.
    - NOT_OBSERVED_IN_BASELINE: network exists in current evidence but has
      no comparison finding (e.g. a sub-network of collapsed coverage).

    ``classification`` holds the internal DiffFinding classification label
    (e.g. NEW_REACHABILITY). These are INTERNAL analysis labels: they are
    never emitted verbatim to operators. All serialization boundaries map
    them through :func:`public_comparison_label` to the documented public
    vocabulary (NEW / EXPANDED / REDUCED / UNCHANGED, see README.md,
    Output Contracts).
    """

    baseline: str
    relationship: str
    classification: str | None = None
    related_network: str | None = None

    def to_dict(self) -> dict:
        return {
            "baseline": self.baseline,
            "relationship": public_comparison_label(self.relationship),
            "classification": public_comparison_label(self.classification),
            "related_network": self.related_network,
        }


@dataclass(frozen=True)
class PriorityContext:
    """Operator priority context associated with the target's network.

    This is PRIORITIZATION CONTEXT, never validation evidence. A successful
    TCP connection does not upgrade or create a recommendation.
    """

    level: str
    reason: str
    network: str

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "reason": self.reason,
            "network": self.network,
        }


@dataclass(frozen=True)
class ValidationContext:
    """Context attached to a CheckReport; never recomputed by renderers.

    Distinguishes MISSING CONTEXT (field is None) from KNOWN NEGATIVE
    CONTEXT (field present with an explicit relationship such as UNCHANGED).
    """

    target: str
    network_match: NetworkMatch | None = None
    route_context: RouteContext | None = None
    comparison: ComparisonContext | None = None
    priority: PriorityContext | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "network_context": {
                "matched_network": (
                    self.network_match.to_dict() if self.network_match else None
                ),
                "route_context": (
                    self.route_context.to_dict() if self.route_context else None
                ),
            },
            "comparison_context": {
                "baseline": self.comparison.baseline if self.comparison else None,
                "relationship": (
                    public_comparison_label(self.comparison.relationship)
                    if self.comparison
                    else None
                ),
                "classification": (
                    public_comparison_label(self.comparison.classification)
                    if self.comparison
                    else None
                ),
                "related_network": (
                    self.comparison.related_network if self.comparison else None
                ),
            },
            "priority_context": {
                "level": self.priority.level if self.priority else None,
                "reason": self.priority.reason if self.priority else None,
                "network": self.priority.network if self.priority else None,
            },
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class TransitEvidence:
    """Evidence assessment for one candidate transit path.

    Identity: source_interface + gateway + destination_network
    (matches PivotPath 1:1)
    """

    # Identity (matches PivotPath)
    source_interface: str
    gateway: str
    destination_network: str
    address_family: int  # 4 or 6 (for IPv6 link-local scoping)

    # Route evidence (always present for PivotPath-derived candidates)
    route_present: bool = True
    route_metric: int | None = None
    route_type: str = "static"  # always "static" for PivotPath

    # Neighbor evidence
    neighbor_observed: bool = False
    neighbor_state: str | None = None  # REACHABLE, STALE, FAILED, PERMANENT, DELAY
    neighbor_mac: str | None = None

    # Connection evidence (filtered to relevant only)
    tcp_connections_to_gateway: int = 0
    tcp_connection_states: tuple[str, ...] = ()  # e.g., ("ESTABLISHED", "TIME_WAIT")
    udp_flows_to_gateway: int = 0
    has_listen_on_gateway: bool = False
    has_loopback_to_gateway: bool = False

    # Derived assessment
    # Default is ROUTING_ONLY: consistent with the bare field defaults
    # (route_present=True, no neighbor/connection evidence). The model
    # re-derives and enforces consistency in __post_init__.
    assessment: TransitEvidenceAssessment = TransitEvidenceAssessment.ROUTING_ONLY

    def __post_init__(self) -> None:
        # Validate gateway is a valid IP address
        import ipaddress
        try:
            ipaddress.ip_address(self.gateway)
        except ValueError as exc:
            raise ValueError(f"invalid gateway IP: {self.gateway!r}") from exc

        # Validate destination_network is a valid CIDR
        try:
            ipaddress.ip_network(self.destination_network, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid destination network CIDR: {self.destination_network!r}") from exc

        # Validate source_interface is non-empty
        if not self.source_interface or not self.source_interface.strip():
            raise ValueError("source_interface must be non-empty")

        # Validate address_family
        if self.address_family not in (4, 6):
            raise ValueError(f"address_family must be 4 or 6, got {self.address_family}")

        # Validate gateway/destination family match (except link-local)
        gateway_ip = ipaddress.ip_address(self.gateway)
        dest_net = ipaddress.ip_network(self.destination_network, strict=False)
        if (
            gateway_ip.version != dest_net.version
            # Allow IPv6 link-local gateway with global destination
            and not (gateway_ip.version == 6 and gateway_ip.is_link_local)
        ):
            raise ValueError(
                f"gateway ({self.gateway}) and destination ({self.destination_network}) "
                "must be same address family"
            )

        # Validate neighbor_state if present
        if self.neighbor_state is not None:
            valid_states = {"REACHABLE", "STALE", "FAILED", "PERMANENT", "DELAY", "INCOMPLETE", "PROBE", "NONE"}
            if self.neighbor_state not in valid_states:
                raise ValueError(f"invalid neighbor_state: {self.neighbor_state!r}")

        # Verify assessment consistency with evidence
        expected_assessment = _derive_transit_assessment(
            route_present=self.route_present,
            neighbor_observed=self.neighbor_observed,
            neighbor_state=self.neighbor_state,
            tcp_connections_to_gateway=self.tcp_connections_to_gateway,
            tcp_connection_states=self.tcp_connection_states,
            udp_flows_to_gateway=self.udp_flows_to_gateway,
            has_listen_on_gateway=self.has_listen_on_gateway,
            has_loopback_to_gateway=self.has_loopback_to_gateway,
        )
        if self.assessment != expected_assessment:
            raise ValueError(
                f"assessment {self.assessment.value} inconsistent with evidence; "
                f"expected {expected_assessment.value}"
            )

    def to_dict(self) -> dict:
        return {
            "source_interface": self.source_interface,
            "gateway": self.gateway,
            "destination_network": self.destination_network,
            "address_family": self.address_family,
            "route": {
                "present": self.route_present,
                "metric": self.route_metric,
                "type": self.route_type,
            },
            "neighbor": {
                "observed": self.neighbor_observed,
                "state": self.neighbor_state,
                "mac": self.neighbor_mac,
            },
            "connections": {
                "tcp_count": self.tcp_connections_to_gateway,
                "tcp_states": list(self.tcp_connection_states),
                "udp_count": self.udp_flows_to_gateway,
                "has_listen": self.has_listen_on_gateway,
                "has_loopback": self.has_loopback_to_gateway,
            },
            "assessment": self.assessment.value,
        }


@dataclass(frozen=True)
class TransitEvidenceCollection:
    """Complete transit evidence for a discovery snapshot."""

    candidates: tuple[TransitEvidence, ...]
    snapshot_timestamp: str

    def to_dict(self) -> dict:
        return {
            "snapshot_timestamp": self.snapshot_timestamp,
            "candidates": [c.to_dict() for c in self.candidates],
        }


def _derive_transit_assessment(
    *,
    route_present: bool = True,
    neighbor_observed: bool,
    neighbor_state: str | None,
    tcp_connections_to_gateway: int,
    tcp_connection_states: tuple[str, ...],
    udp_flows_to_gateway: int,
    has_listen_on_gateway: bool,
    has_loopback_to_gateway: bool,
) -> TransitEvidenceAssessment:
    """Single authoritative assessment derivation from evidence fields.

    ``route_present`` defaults to True because every PivotPath-derived
    candidate carries route evidence by definition; pass
    ``route_present=False`` to derive INSUFFICIENT_EVIDENCE explicitly.

    Deterministic precedence:
    1. INSUFFICIENT_EVIDENCE (no route observed)
    2. CONTRADICTORY_EVIDENCE (FAILED neighbor + active TCP)
    3. MULTIPLE_SUPPORTING_SIGNALS (REACHABLE neighbor + active TCP)
    4. MULTIPLE_SUPPORTING_SIGNALS_STALE_L2 (STALE neighbor + active TCP)
    5. ROUTING_WITH_NEGATIVE_L2_EVIDENCE (FAILED neighbor, no active TCP)
    6. ROUTING_PLUS_ACTIVE_TCP_EVIDENCE (active TCP, no neighbor or other)
    7. ROUTING_PLUS_ACTIVE_UDP_EVIDENCE (active UDP, no TCP)
    8. ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE (historical TCP only)
    9. ROUTING_PLUS_L2_EVIDENCE (neighbor evidence, no active TCP)
    10. ROUTING_ONLY (route only)

    Invariant: every assessment this function can return is accepted by
    TransitEvidence model validation, and every assessment the model
    rejects cannot be derived from the evidence fields that produced it.
    """
    # No route evidence: nothing else can be assessed
    if not route_present:
        return TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE

    # Check for active TCP (ESTABLISHED)
    has_active_tcp = tcp_connections_to_gateway > 0 and "ESTABLISHED" in tcp_connection_states

    # Check for active UDP
    has_active_udp = udp_flows_to_gateway > 0

    # Check for historical TCP (TIME_WAIT, CLOSE_WAIT)
    historical_tcp_states = {"TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK", "CLOSING"}
    has_historical_tcp = any(state in historical_tcp_states for state in tcp_connection_states)

    # Check for LISTEN
    # (has_listen_on_gateway is accepted for signature symmetry with the
    # correlation engine but does not affect the derived assessment)

    # Check for loopback
    # (has_loopback_to_gateway is accepted for signature symmetry with the
    # correlation engine but does not affect the derived assessment)

    # Neighbor evidence
    has_neighbor = neighbor_observed
    neighbor_is_failed = neighbor_state == "FAILED"
    neighbor_is_reachable = neighbor_state == "REACHABLE"
    neighbor_is_stale = neighbor_state == "STALE"

    # Precedence order (highest first)
    if neighbor_is_failed and has_active_tcp:
        return TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE

    if neighbor_is_reachable and has_active_tcp:
        return TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS

    if neighbor_is_stale and has_active_tcp:
        return TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2

    if neighbor_is_failed and not has_active_tcp:
        return TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE

    if has_active_tcp:
        return TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE

    if has_active_udp:
        return TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE

    if has_historical_tcp:
        return TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE

    if has_neighbor and not neighbor_is_failed:
        return TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE

    # Route only (default for PivotPath-derived candidates)
    return TransitEvidenceAssessment.ROUTING_ONLY


@dataclass(frozen=True)
class CheckReport:
    """Aggregated results for one operator command invocation."""

    target: str
    resolved_addresses: tuple[str, ...]
    ports: tuple[int, ...]
    timeout_s: float
    results: tuple[CheckResult, ...]
    validation_context: ValidationContext | None = None
    command: str = "check"
    protocol: str = "tcp"  # additive (schema 1.1): which check protocol ran
    schema_version: str = "1.1"
    timestamp: str = ""
    perspective_hostname: str = ""
    perspective_session_id: str = ""

    def to_dict(self) -> dict:
        data = {
            "schema_version": self.schema_version,
            "tool": "pivotcheck",
            "version": _version(),
            "command": self.command,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
            "perspective": {
                "hostname": self.perspective_hostname,
                "session_id": self.perspective_session_id,
            },
            "target": self.target,
            "resolved_addresses": list(self.resolved_addresses),
            "ports": list(self.ports),
            "timeout_s": self.timeout_s,
            "results": [r.to_dict() for r in self.results],
        }
        if self.validation_context is not None:
            data["validation_context"] = self.validation_context.to_dict()
        return data


def _version() -> str:
    from pivotcheck import __version__

    return __version__
