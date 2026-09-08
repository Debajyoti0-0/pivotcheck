"""What-If analysis engine (G-04, Stage 31).

PURE ANALYSIS: no network I/O, no discovery, no subprocesses, no
filesystem access, no environment access. A DiscoverySnapshot plus
explicit hypothetical routes go in; a deterministic HYPOTHETICAL result
comes out.

Core laws enforced here:

- HYPOTHETICAL ≠ OBSERVED: findings are composed against observed state
  but never merge into it. The input snapshot is never mutated.
- Negative/contradictory evidence is preserved: a hypothesis that
  conflicts with observed evidence is reported CONTRADICTED, never
  SUPPORTED (existing stronger coverage, competing routes, down
  interfaces).
- No magic discovery: the engine invents nothing — it evaluates exactly
  the supplied hypotheses against exactly the supplied snapshot.
- Family isolation is structural (model-level), inherited from the
  HypotheticalRoute construction rules.
- Deterministic: hypotheses are deduplicated and evaluated in canonical
  key order; input permutation cannot change the result.
"""

from __future__ import annotations

import ipaddress
from typing import cast

from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    InterfaceState,
    NetworkOrigin,
)
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.whatif import (
    ANALYSIS_TYPE,
    HypothesisStatus,
    HypotheticalRoute,
    WhatIfFinding,
    WhatIfOutcome,
    WhatIfReport,
    WhatIfScenarioNetwork,
)

_MAX_HYPOTHESES = 64


class WhatIfInputError(ValueError):
    """Structurally invalid what-if input (fail closed, never guessed)."""


def analyze_what_if(
    snapshot: DiscoverySnapshot,
    hypotheses: tuple[HypotheticalRoute, ...] | list[HypotheticalRoute],
) -> WhatIfReport:
    """Evaluate hypothetical routing changes against observed state.

    Pure and deterministic. The snapshot is treated as immutable; the
    result contains no observed-state mutation and no upgraded epistemic
    claims. Duplicate hypotheses are evaluated once (canonical key
    order), and the hypothesis count is bounded — each hypothesis is
    evaluated independently against observed state, so no combinatorial
    explosion is possible.
    """
    if not isinstance(snapshot, DiscoverySnapshot):
        raise WhatIfInputError(
            f"what-if requires a DiscoverySnapshot: {type(snapshot).__name__}"
        )
    if not hypotheses:
        raise WhatIfInputError(
            "at least one hypothesis is required for what-if analysis"
        )
    if len(hypotheses) > _MAX_HYPOTHESES:
        raise WhatIfInputError(
            f"too many hypotheses ({len(hypotheses)}); the limit is {_MAX_HYPOTHESES}"
        )

    # Deterministic dedup + ordering: equivalent hypotheses evaluated
    # once; canonical key order makes the result permutation-invariant.
    unique: dict[tuple[str, str, str], HypotheticalRoute] = {}
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, HypotheticalRoute):
            raise WhatIfInputError(
                f"hypotheses must be HypotheticalRoute: {type(hypothesis).__name__}"
            )
        unique.setdefault(hypothesis.key, hypothesis)
    ordered = [unique[key] for key in sorted(unique)]

    interfaces_by_name: dict[str, InterfaceState] = {
        interface.name: interface.state for interface in snapshot.interfaces
    }
    observed_addresses = _observed_addresses(snapshot)
    observed_networks = {network.cidr: network for network in snapshot.networks}

    findings: list[WhatIfFinding] = []
    scenario: list[WhatIfScenarioNetwork] = []
    for hypothesis in ordered:
        finding = _evaluate(
            hypothesis, observed_networks, observed_addresses, interfaces_by_name
        )
        findings.append(finding)
        if (
            finding.status is HypothesisStatus.ACCEPTED
            and finding.outcome is not WhatIfOutcome.ALREADY_OBSERVED
            and finding.outcome is not WhatIfOutcome.CONTRADICTED
            and interfaces_by_name.get(hypothesis.interface) is InterfaceState.UP
        ):
            scenario.append(
                WhatIfScenarioNetwork(
                    network=hypothesis.key[0],
                    gateway=hypothesis.gateway,
                    interface=hypothesis.interface,
                    predicted_confidence=Confidence.MEDIUM.value.upper(),
                )
            )

    return WhatIfReport(
        analysis_type=ANALYSIS_TYPE,
        perspective_hostname=snapshot.hostname,
        findings=tuple(findings),
        scenario_networks=tuple(scenario),
    )


def _observed_addresses(snapshot: DiscoverySnapshot) -> dict[str, InterfaceState]:
    """Map each observed local address to its interface state (pure)."""
    result: dict[str, InterfaceState] = {}
    for interface in snapshot.interfaces:
        for address in interface.ipv4_addresses:
            result[address.address] = interface.state
        for address in interface.ipv6_addresses:
            result[address.address] = interface.state
    return result


def _evaluate(
    hypothesis: HypotheticalRoute,
    observed_networks: dict[str, DiscoveredNetwork],
    observed_addresses: dict[str, InterfaceState],
    interfaces_by_name: dict[str, InterfaceState],
) -> WhatIfFinding:
    """Evaluate one hypothesis against observed state (pure, no mutation)."""
    canonical = hypothesis.key[0]
    network = ipaddress.ip_network(canonical)

    # Contradiction 1: the network is ALREADY observed with stronger
    # evidence (directly connected on an UP interface).
    existing = observed_networks.get(canonical)
    if existing is not None:
        if (
            existing.origin is NetworkOrigin.CONNECTED
            and existing.confidence is Confidence.HIGH
        ):
            return _contradicted(
                hypothesis,
                predicted=(
                    "ROUTED (hypothetical) vs CONNECTED/HIGH (observed): "
                    "direct connectivity supersedes a gateway path to the "
                    "same network in the analysis merge rules"
                ),
                contradiction=(
                    f"{canonical} is already OBSERVED as directly connected on "
                    f"interface {existing.interface!r} with HIGH confidence; a "
                    "hypothetical route through a gateway contradicts the "
                    "stronger observed evidence"
                ),
            )
        if (
            existing.origin is NetworkOrigin.ROUTED
            and existing.gateway == hypothesis.gateway
        ):
            return WhatIfFinding(
                hypothesis=hypothesis,
                status=HypothesisStatus.ACCEPTED,
                outcome=WhatIfOutcome.ALREADY_OBSERVED,
                predicted_classification=(
                    f"{existing.origin.value} / {existing.confidence.value} "
                    "(already observed — the hypothesis adds nothing)"
                ),
                unknowns=(
                    "the hypothetical route duplicates an already-observed entry; nothing would change in the analysis",
                ),
            )
        if existing.origin is NetworkOrigin.ROUTED:
            return _contradicted(
                hypothesis,
                predicted=(
                    "ROUTED (hypothetical) vs competing existing route via a "
                    "different gateway"
                ),
                contradiction=(
                    f"{canonical} is already observed as ROUTED via a different "
                    f"gateway ({existing.gateway!r}); the hypothetical route "
                    "conflicts with observed routing evidence"
                ),
            )

    # Contradiction 2: the hypothetical network would cover an
    # already-observed more-specific network (supernet shadowing).
    for observed_cidr, observed in observed_networks.items():
        observed_net = ipaddress.ip_network(observed_cidr)
        if observed_net.version != network.version:
            continue
        # Same family: narrow for subnet_of's typed signature.
        if network.version == 4:
            n4 = cast(ipaddress.IPv4Network, network)
            o4 = cast(ipaddress.IPv4Network, observed_net)
            shadowed = o4.subnet_of(n4)
        else:
            n6 = cast(ipaddress.IPv6Network, network)
            o6 = cast(ipaddress.IPv6Network, observed_net)
            shadowed = o6.subnet_of(n6)
        if shadowed and observed_net != network:
            return _contradicted(
                hypothesis,
                predicted=(
                    "ROUTED (hypothetical) vs existing more-specific observed "
                    "coverage"
                ),
                contradiction=(
                    f"{canonical} would cover already-observed {observed_cidr} "
                    f"({observed.origin.value}/{observed.confidence.value}); a "
                    "route whose destination contains stronger observed "
                    "evidence is contradictory, not supporting"
                ),
            )

    # Evidence relation: gateway observability + interface state.
    supporting: list[str] = []
    unknowns: list[str] = []
    contradictions: list[str] = []

    gateway_state = observed_addresses.get(hypothesis.gateway)
    if gateway_state is InterfaceState.UP:
        supporting.append(
            f"gateway {hypothesis.gateway} is OBSERVED as a local address on "
            "an UP interface"
        )
    elif gateway_state is not None:
        supporting.append(
            f"gateway {hypothesis.gateway} is OBSERVED locally but its "
            f"interface is {gateway_state.value} (not UP)"
        )
    else:
        unknowns.append(
            f"gateway {hypothesis.gateway} is NOT observed on any local "
            "interface; whether it is reachable is UNKNOWN"
        )

    interface_state = interfaces_by_name.get(hypothesis.interface)
    if interface_state is InterfaceState.UP:
        pass  # fully usable: scenario composition applies
    elif interface_state is not None:
        contradictions.append(
            f"interface {hypothesis.interface!r} is observed "
            f"{interface_state.value} (not UP); PivotCheck's analysis "
            "suppresses pivot paths through non-UP interfaces"
        )
    else:
        unknowns.append(
            f"interface {hypothesis.interface!r} is NOT observed on this "
            "host; whether it exists is UNKNOWN"
        )

    outcome = (
        WhatIfOutcome.SUPPORTED_BY_EXISTING_EVIDENCE
        if supporting and not contradictions
        else WhatIfOutcome.INSUFFICIENT_EXISTING_EVIDENCE
    )
    predicted = _predicted_classification(interface_state)
    return WhatIfFinding(
        hypothesis=hypothesis,
        status=HypothesisStatus.ACCEPTED,
        outcome=outcome,
        predicted_classification=predicted,
        supporting=tuple(supporting),
        contradictions=tuple(contradictions),
        unknowns=tuple(unknowns),
    )


def _predicted_classification(interface_state: InterfaceState | None) -> str:
    """What the engine would conclude IF the hypothesis held (always
    labeled hypothetical in rendered output)."""
    if interface_state is InterfaceState.UP:
        return (
            "ROUTED / MEDIUM confidence (classify_routed_networks for a "
            "static route via this gateway); pivot path candidate present "
            "(interface UP) — HYPOTHETICAL"
        )
    if interface_state is None:
        return (
            "ROUTED / MEDIUM confidence would apply to a static route via "
            "this gateway, but the named interface is not observed; its "
            "state is UNKNOWN — HYPOTHETICAL"
        )
    return (
        "ROUTED / MEDIUM confidence for the route entry itself, but NO pivot "
        f"path (interface {interface_state.value}; pivot paths through "
        "non-UP interfaces are suppressed) — HYPOTHETICAL"
    )


def _contradicted(
    hypothesis: HypotheticalRoute, *, predicted: str, contradiction: str
) -> WhatIfFinding:
    return WhatIfFinding(
        hypothesis=hypothesis,
        status=HypothesisStatus.ACCEPTED,
        outcome=WhatIfOutcome.CONTRADICTED,
        predicted_classification=predicted,
        contradictions=(contradiction,),
    )
