"""Credential/host correlation models (v2.0 Step 3).

Correlation is RECOMMENDATION, never proof. A candidate asserts that a
credential/host relationship is worth explicit validation next — it never
asserts that the credential works, that the host is reachable, or that a
service is running unless that fact was explicitly observed and carried in
as evidence.

Secret-safety by construction: correlation operates on
:class:`CredentialRef` — a reference carrying type, provenance, and state
only. Credential material never enters this layer, so no representation
here can leak it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pivotcheck.models.credentials import (
    Credential,
    CredentialSource,
    CredentialState,
    CredentialType,
)


class CorrelationEvidenceKind(str, Enum):
    """Kinds of evidence the correlation engine consumes.

    Names align with PivotCheck's established terminology. Every kind is
    claimed by the caller; the engine never invents evidence.

    - KNOWN_HOST: historical SSH client identity evidence for the host.
      Proves a past client-side association ONLY — never reachability,
      never that an SSH service is listening, never that a credential
      works.
    - SSH_SERVICE_OBSERVED: an SSH service was explicitly observed on the
      host (e.g. a listening SSH socket in collected evidence).
    - SSH_SERVICE_NOT_OBSERVED: explicit negative evidence — the host is
      known but no SSH service has been observed. Absence of evidence is
      never silently promoted to this state.
    - NETWORK_OBSERVED: the host appears in the current network
      perspective (connected/routed coverage).
    - NEIGHBOR_OBSERVED: the host appears in neighbor (L2) evidence.
    - AUTH_VALIDATED: an explicit prior validation (Step 2) authenticated
      this credential against this host. Set only from real validation
      results; correlation never manufactures it.
    - AUTH_FAILED: an explicit prior validation rejected this credential
      for this host.
    """

    KNOWN_HOST = "KNOWN_HOST"
    SSH_SERVICE_OBSERVED = "SSH_SERVICE_OBSERVED"
    SSH_SERVICE_NOT_OBSERVED = "SSH_SERVICE_NOT_OBSERVED"
    NETWORK_OBSERVED = "NETWORK_OBSERVED"
    NEIGHBOR_OBSERVED = "NEIGHBOR_OBSERVED"
    AUTH_VALIDATED = "AUTH_VALIDATED"
    AUTH_FAILED = "AUTH_FAILED"


class CorrelationPriority(str, Enum):
    """Investigation priority for a credential/host candidate.

    Mirrors the established TransitPriority vocabulary: this is
    INVESTIGATION VALUE, not viability. A HIGH candidate still requires
    explicit validation before any claim of access.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass(frozen=True)
class CredentialRef:
    """Safe reference to one credential — type, provenance, state only.

    Built from the canonical :class:`Credential` via
    :meth:`from_credential`; credential material never crosses into the
    correlation layer, so no correlation representation can leak it.
    """

    credential_id: str
    credential_type: CredentialType
    source: CredentialSource
    source_name: str | None
    state: CredentialState

    def __post_init__(self) -> None:
        if not self.credential_id:
            raise ValueError("credential_id must be a non-empty identifier")
        if not isinstance(self.credential_type, CredentialType):
            raise TypeError(f"invalid credential type: {self.credential_type!r}")
        if not isinstance(self.source, CredentialSource):
            raise TypeError(f"invalid credential source: {self.source!r}")
        if not isinstance(self.state, CredentialState):
            raise TypeError(f"invalid credential state: {self.state!r}")

    @classmethod
    def from_credential(cls, credential: Credential, credential_id: str) -> CredentialRef:
        """Build a safe reference; credential material is never copied."""
        return cls(
            credential_id=credential_id,
            credential_type=credential.credential_type,
            source=credential.source,
            source_name=credential.source_name,
            state=credential.state,
        )

    def to_dict(self) -> dict:
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type.value,
            "credential_source": self.source.value,
            "source_name": self.source_name,
            "authentication_state": self.state.value,
        }


@dataclass(frozen=True)
class HostEvidence:
    """Evidence the caller has gathered about one host/vantage target."""

    target: str
    evidence: tuple[CorrelationEvidenceKind, ...] = ()

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("target must be a non-empty host identifier")
        for kind in self.evidence:
            if not isinstance(kind, CorrelationEvidenceKind):
                raise TypeError(f"invalid evidence kind: {kind!r}")


@dataclass(frozen=True)
class CredentialHostCandidate:
    """One recommended credential/host validation candidate."""

    credential_id: str
    credential_type: str
    credential_source: str
    target: str
    protocol: str | None
    priority: CorrelationPriority
    evidence: tuple[CorrelationEvidenceKind, ...]
    reason: str
    authentication_state: str
    validation_status: str | None = None  # prior explicit validation result

    def to_dict(self) -> dict:
        return {
            "credential_id": self.credential_id,
            "credential_type": self.credential_type,
            "credential_source": self.credential_source,
            "target": self.target,
            "protocol": self.protocol,
            "priority": self.priority.value,
            "evidence": [kind.value for kind in self.evidence],
            "reason": self.reason,
            "authentication_state": self.authentication_state,
            "validation_status": self.validation_status,
        }


@dataclass(frozen=True)
class RejectedPair:
    """A credential/host pair deliberately NOT recommended, and why."""

    credential_id: str
    target: str
    protocol: str | None
    reason: str

    def to_dict(self) -> dict:
        return {
            "credential_id": self.credential_id,
            "target": self.target,
            "protocol": self.protocol,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CorrelationReport:
    """Deterministic correlation output: candidates + suppressed pairs."""

    candidates: tuple[CredentialHostCandidate, ...] = ()
    rejected: tuple[RejectedPair, ...] = ()
    command: str = "correlate"
    schema_version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "candidates": [c.to_dict() for c in self.candidates],
            "rejected": [r.to_dict() for r in self.rejected],
        }
