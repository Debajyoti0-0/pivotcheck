"""What-If analysis models (G-04, Stage 31).

EPISTEMIC LAW: HYPOTHETICAL ≠ OBSERVED.

Every object in this module describes a *hypothetical scenario* — a
mathematical consequence of an explicit assumption. Nothing here is
evidence, observation, validation, or reachability. A What-If result is
what PivotCheck's analysis WOULD conclude IF the assumed change existed;
it is never a claim that the assumed change exists.

Every finding carries the constant ``HYPOTHETICAL`` epistemic marker.
The engine never upgrades hypothetical input into observed evidence, and
it never mutates the observed state it was given.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum

EPISTEMIC_STATE = "HYPOTHETICAL"
ANALYSIS_TYPE = "hypothetical"


class HypothesisStatus(str, Enum):
    """Structural validity of one hypothesis against observed state."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class WhatIfOutcome(str, Enum):
    """How existing observed evidence relates to one hypothesis.

    These are the §9 evidence-relation states:

    - SUPPORTED_BY_EXISTING_EVIDENCE: observed facts align with the
      assumption (e.g. the gateway address is observed as a local
      address on the named UP interface).
    - CONTRADICTED: observed facts conflict with the assumption
      (e.g. the network is already observed as directly connected on an
      UP interface — stronger evidence; or a competing route exists).
    - ALREADY_OBSERVED: the hypothetical change adds nothing — the exact
      relationship is already observed.
    - INSUFFICIENT_EXISTING_EVIDENCE: no observed evidence speaks for or
      against the assumption. The result stays HYPOTHETICAL/UNKNOWN.
    """

    SUPPORTED_BY_EXISTING_EVIDENCE = "SUPPORTED_BY_EXISTING_EVIDENCE"
    CONTRADICTED = "CONTRADICTED"
    ALREADY_OBSERVED = "ALREADY_OBSERVED"
    INSUFFICIENT_EXISTING_EVIDENCE = "INSUFFICIENT_EXISTING_EVIDENCE"


@dataclass(frozen=True)
class HypotheticalRoute:
    """One explicit hypothetical routing change.

    Purely declarative input: a network that does NOT exist in the
    observed state, with a gateway and interface that the operator
    assumes would carry it. Construction enforces structural sanity:

    - network must be a valid CIDR
    - gateway must be a valid IP literal in the SAME family as the
      network (IPv4/IPv6 isolation is structural, per the graph model)
    - gateway must NOT lie inside the hypothetical network (a route to a
      network via an address inside it is self-referential)
    - interface must be a non-empty trimmed identifier
    """

    network: str
    gateway: str
    interface: str

    def __post_init__(self) -> None:
        try:
            network = ipaddress.ip_network(self.network, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid hypothetical network CIDR: {self.network!r}") from exc
        try:
            gateway = ipaddress.ip_address(self.gateway)
        except ValueError as exc:
            raise ValueError(f"invalid hypothetical gateway address: {self.gateway!r}") from exc
        if not isinstance(self.interface, str) or not self.interface.strip():
            raise ValueError("hypothetical interface must be a non-empty identifier")
        if self.interface.strip() != self.interface:
            raise ValueError("hypothetical interface must not be padded")
        if network.version != gateway.version:
            raise ValueError(
                "cross-family hypothesis rejected: "
                f"{self.network!r} ({'ipv' + str(network.version)}) vs "
                f"{self.gateway!r} ({'ipv' + str(gateway.version)})"
            )
        if gateway in network:
            raise ValueError(
                "gateway address lies inside the hypothetical network; "
                "a route via an address inside its own destination is "
                "self-referential"
            )

    @property
    def key(self) -> tuple[str, str, str]:
        """Deterministic dedup key."""
        canonical = str(ipaddress.ip_network(self.network, strict=False))
        return (canonical, self.gateway, self.interface)

    def to_dict(self) -> dict:
        return {
            "network": str(ipaddress.ip_network(self.network, strict=False)),
            "gateway": self.gateway,
            "interface": self.interface,
            "epistemic_state": EPISTEMIC_STATE,
        }


@dataclass(frozen=True)
class WhatIfFinding:
    """One evaluated hypothesis with full provenance separation.

    ``assumption`` is what was assumed. ``supporting`` / ``contradictions``
    / ``unknowns`` quote OBSERVED evidence (or its absence) relative to
    the assumption. ``predicted_classification`` is what the analysis
    engine WOULD conclude IF the assumption held — always prefixed as
    hypothetical in rendered output. Nothing in this finding asserts the
    assumed state exists.
    """

    hypothesis: HypotheticalRoute
    status: HypothesisStatus
    outcome: WhatIfOutcome | None  # None only for rejected hypotheses
    rejection_reason: str | None = None
    predicted_classification: str | None = None
    supporting: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, HypothesisStatus):
            raise TypeError(f"invalid hypothesis status: {self.status!r}")
        if self.status is HypothesisStatus.REJECTED:
            if not self.rejection_reason:
                raise ValueError("a rejected hypothesis requires a reason")
        elif self.outcome is None:
            raise ValueError("an accepted hypothesis requires an outcome")

    def to_dict(self) -> dict:
        return {
            "epistemic_state": EPISTEMIC_STATE,
            "hypothesis": self.hypothesis.to_dict(),
            "status": self.status.value,
            "outcome": self.outcome.value if self.outcome else None,
            "rejection_reason": self.rejection_reason,
            "predicted_classification": self.predicted_classification,
            "supporting": list(self.supporting),
            "contradictions": list(self.contradictions),
            "unknowns": list(self.unknowns),
        }


@dataclass(frozen=True)
class WhatIfScenarioNetwork:
    """One composed hypothetical network in the derived scenario.

    Only accepted hypotheses whose named interface is observed UP reach
    composition. Every entry is marked HYPOTHETICAL.
    """

    network: str
    gateway: str
    interface: str
    predicted_confidence: str  # "MEDIUM" — what classify_routed_networks would yield

    def to_dict(self) -> dict:
        return {
            "epistemic_state": EPISTEMIC_STATE,
            "network": self.network,
            "gateway": self.gateway,
            "interface": self.interface,
            "predicted_confidence": self.predicted_confidence,
        }


WHATIF_LIMITATIONS: tuple[str, ...] = (
    "HYPOTHETICAL \u2260 OBSERVED: every predicted element derives from an assumed change, not from collected evidence. No hypothetical result proves the assumed state exists.",
    "ROUTE \u2260 REACHABILITY: a predicted routing-table entry implies nothing about forwarding, packet delivery, or gateway willingness.",
    "FORWARDING \u2260 AUTHENTICATION \u2260 EXECUTION: no capability is predicted by this analysis.",
    "No validation is performed: this analysis performs no network I/O and observes nothing new.",
    "Absence of contradictions does not make the assumption true; it only means the observed state does not speak against it.",
)


@dataclass(frozen=True)
class WhatIfReport:
    """Deterministic what-if analysis result for one observed snapshot."""

    analysis_type: str  # constant ANALYSIS_TYPE ("hypothetical")
    perspective_hostname: str
    findings: tuple[WhatIfFinding, ...]
    scenario_networks: tuple[WhatIfScenarioNetwork, ...] = ()
    limitations: tuple[str, ...] = field(default=WHATIF_LIMITATIONS)

    def __post_init__(self) -> None:
        if self.analysis_type != ANALYSIS_TYPE:
            raise ValueError(
                f"what-if reports must declare analysis_type={ANALYSIS_TYPE!r}"
            )

    def to_dict(self) -> dict:
        return {
            "analysis_type": self.analysis_type,
            "epistemic_state": EPISTEMIC_STATE,
            "perspective_hostname": self.perspective_hostname,
            "findings": [f.to_dict() for f in self.findings],
            "scenario_networks": [s.to_dict() for s in self.scenario_networks],
            "limitations": list(self.limitations),
        }
