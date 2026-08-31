"""Credential/host correlation engine (v2.0 Step 3).

PURE ANALYSIS: no I/O of any kind — no network, no subprocesses, no
filesystem, no environment access. Receives structured credential
references and host evidence; produces structured, explainable,
deterministic recommendations.

Epistemic law enforced throughout:

    CREDENTIAL_PRESENT  !=  AUTHENTICATION_VALIDATED
    KNOWN_HOST          !=  REACHABLE / SSH_SERVICE_LISTENING
    correlation         !=  validation

A candidate is a recommendation to perform explicit validation next. The
engine consumes prior validation outcomes (from Step 2's checker) but can
never manufacture them.

Determinism: identical evidence in any input order produces an identical
report. Candidate ordering is (priority, credential_id, target); evidence
lists are deduplicated and ordered canonically; duplicate credential/host
pairs merge into one candidate.
"""

from __future__ import annotations

from pivotcheck.models.correlation import (
    CorrelationEvidenceKind,
    CorrelationPriority,
    CorrelationReport,
    CredentialHostCandidate,
    CredentialRef,
    HostEvidence,
    RejectedPair,
)
from pivotcheck.models.credentials import CredentialState, CredentialType

# Protocol the credential type can plausibly authenticate to, for evidence
# matching. Representation only — this is not protocol implementation.
_PROTOCOL_FOR_TYPE: dict[CredentialType, str] = {
    CredentialType.SSH_PRIVATE_KEY: "ssh",
}

# Priority ranking for deterministic ordering (None sorts last).
_PRIORITY_ORDER = {
    CorrelationPriority.HIGH: 0,
    CorrelationPriority.MEDIUM: 1,
    CorrelationPriority.LOW: 2,
    CorrelationPriority.NONE: 3,
}

_KIND_ORDER = {
    kind: index for index, kind in enumerate(CorrelationEvidenceKind)
}


def _reason_for(
    priority: CorrelationPriority,
    evidence: tuple[CorrelationEvidenceKind, ...],
    credential: CredentialRef,
    target: str,
) -> str:
    """Build a display-safe reason chain. Evidence names only — never
    credential material (this layer never sees any)."""
    parts: list[str] = []
    if credential.state is CredentialState.AUTHENTICATION_VALIDATED:
        parts.append(
            f"{credential.credential_type.value} credential previously "
            "authenticated successfully to this target (explicit validation)"
        )
    else:
        parts.append(f"{credential.credential_type.value} credential is present")

    if CorrelationEvidenceKind.KNOWN_HOST in evidence:
        parts.append("target has historical SSH client identity evidence (known_hosts)")
    if CorrelationEvidenceKind.SSH_SERVICE_OBSERVED in evidence:
        parts.append("SSH service explicitly observed on target")
    elif CorrelationEvidenceKind.SSH_SERVICE_NOT_OBSERVED in evidence:
        parts.append(
            "SSH service has NOT been explicitly observed on target "
            "(negative evidence; availability unconfirmed)"
        )
    elif priority is not CorrelationPriority.HIGH:
        parts.append("SSH service availability has not been explicitly observed")
    if CorrelationEvidenceKind.NETWORK_OBSERVED in evidence:
        parts.append("target appears in the current network perspective")
    if CorrelationEvidenceKind.NEIGHBOR_OBSERVED in evidence:
        parts.append("target appears in neighbor (L2) evidence")

    if priority is CorrelationPriority.HIGH:
        parts.append("strong combined evidence justifies validation first")
    elif priority is CorrelationPriority.MEDIUM:
        parts.append("partial evidence; validation reasonable after HIGH candidates")
    elif priority is CorrelationPriority.LOW:
        parts.append("weak evidence; investigate only if time permits")
    return "; ".join(parts)


def _validate_protocol_status(
    credential: CredentialRef,
    evidence: tuple[CorrelationEvidenceKind, ...],
) -> tuple[str | None, str | None]:
    """Prior explicit validation outcome for this pair, if the caller
    supplied it. Correlation CONSUMES validation facts; it never creates
    them."""
    if CorrelationEvidenceKind.AUTH_VALIDATED in evidence:
        return "AUTHENTICATED", None
    if CorrelationEvidenceKind.AUTH_FAILED in evidence:
        return "AUTH_FAILED", None
    return None, None


def correlate(
    credentials: tuple[CredentialRef, ...],
    host_evidence: tuple[HostEvidence, ...],
) -> CorrelationReport:
    """Correlate credential references with host evidence.

    Pure and deterministic: input order never affects output; duplicate
    evidence merges; contradictory evidence is surfaced, not hidden.

    Rules (transparent, explainable):

    - HIGH: SSH credential + KNOWN_HOST + SSH_SERVICE_OBSERVED on the same
      target (strong combined evidence), or a previously AUTHENTICATED
      pairing re-surfaced with current host evidence.
    - MEDIUM: SSH credential + host evidence present, but the SSH service
      has not been explicitly observed (KNOWN_HOST or NETWORK/NEIGHBOR
      evidence only, possibly with explicit SSH_SERVICE_NOT_OBSERVED).
    - LOW: SSH credential + minimal host evidence (service state unknown).
    - REJECTED: pairs with no host evidence at all, pairs whose only
      evidence is a prior AUTH_FAILED (re-validating a rejected credential
      is not recommended without new evidence), and credentials whose type
      has no supported protocol mapping yet (documented; not fabricated).
    """
    evidence_by_target: dict[str, tuple[CorrelationEvidenceKind, ...]] = {}
    for host in host_evidence:
        existing = evidence_by_target.get(host.target, ())
        merged = tuple(dict.fromkeys((*existing, *host.evidence)))  # dedupe, order-stable
        evidence_by_target[host.target] = merged

    candidates: list[CredentialHostCandidate] = []
    rejected: list[RejectedPair] = []

    for credential in credentials:
        protocol = _PROTOCOL_FOR_TYPE.get(credential.credential_type)
        if protocol is None:
            rejected.append(
                RejectedPair(
                    credential_id=credential.credential_id,
                    target="*",
                    protocol=None,
                    reason=(
                        f"{credential.credential_type.value} credentials have no "
                        "protocol mapping in this PivotCheck build; correlation "
                        "is not fabricated without an evidence model"
                    ),
                )
            )
            continue

        for target, evidence in sorted(evidence_by_target.items()):
            auth_status, _ = _validate_protocol_status(credential, evidence)

            host_known = any(
                kind
                in (
                    CorrelationEvidenceKind.NETWORK_OBSERVED,
                    CorrelationEvidenceKind.NEIGHBOR_OBSERVED,
                    CorrelationEvidenceKind.KNOWN_HOST,
                    CorrelationEvidenceKind.SSH_SERVICE_OBSERVED,
                )
                for kind in evidence
            )
            if not host_known:
                rejected.append(
                    RejectedPair(
                        credential_id=credential.credential_id,
                        target=target,
                        protocol=protocol,
                        reason="no host evidence for this target",
                    )
                )
                continue

            if CorrelationEvidenceKind.AUTH_FAILED in evidence and (
                CorrelationEvidenceKind.AUTH_VALIDATED not in evidence
            ):
                rejected.append(
                    RejectedPair(
                        credential_id=credential.credential_id,
                        target=target,
                        protocol=protocol,
                        reason=(
                            "prior explicit validation rejected this credential "
                            "for this target; re-validation is not recommended "
                            "without new evidence"
                        ),
                    )
                )
                continue

            service_observed = CorrelationEvidenceKind.SSH_SERVICE_OBSERVED in evidence
            known_host = CorrelationEvidenceKind.KNOWN_HOST in evidence
            auth_validated = CorrelationEvidenceKind.AUTH_VALIDATED in evidence
            network_observed = CorrelationEvidenceKind.NETWORK_OBSERVED in evidence
            neighbor_observed = CorrelationEvidenceKind.NEIGHBOR_OBSERVED in evidence
            service_not_observed = (
                CorrelationEvidenceKind.SSH_SERVICE_NOT_OBSERVED in evidence
            )

            if (known_host and service_observed) or auth_validated:
                priority = CorrelationPriority.HIGH
            elif known_host or service_observed or network_observed or (
                network_observed and neighbor_observed
            ):
                # Host is present in the perspective with partial SSH
                # evidence (spec: network evidence alone still warrants
                # MEDIUM; an explicit SSH_SERVICE_NOT_OBSERVED negative
                # weakens to LOW).
                priority = (
                    CorrelationPriority.LOW
                    if (service_not_observed and not (known_host or service_observed))
                    else CorrelationPriority.MEDIUM
                )
            elif neighbor_observed:
                priority = CorrelationPriority.LOW
            else:
                priority = CorrelationPriority.LOW

            candidates.append(
                CredentialHostCandidate(
                    credential_id=credential.credential_id,
                    credential_type=credential.credential_type.value,
                    credential_source=credential.source.value,
                    target=target,
                    protocol=protocol,
                    priority=priority,
                    evidence=tuple(
                        sorted(evidence, key=lambda kind: _KIND_ORDER[kind])
                    ),
                    reason=_reason_for(priority, evidence, credential, target),
                    authentication_state=credential.state.value,
                    validation_status=auth_status,
                )
            )

    candidates.sort(
        key=lambda c: (
            _PRIORITY_ORDER[c.priority],
            c.credential_id,
            c.target,
        )
    )
    rejected.sort(key=lambda r: (r.credential_id, r.target))
    return CorrelationReport(candidates=tuple(candidates), rejected=tuple(rejected))
