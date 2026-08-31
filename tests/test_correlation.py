"""Credential/host correlation engine tests (v2.0 Step 3).

Leak-marker discipline applies even though the correlation layer never
touches material: credentials are built with DO_NOT_LEAK_* secrets and the
assertions prove those markers cannot reach any correlation representation.
"""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import pytest

from pivotcheck.analysis.correlation import correlate
from pivotcheck.models.correlation import (
    CorrelationEvidenceKind,
    CorrelationPriority,
    CorrelationReport,
    CredentialHostCandidate,
    CredentialRef,
    HostEvidence,
)
from pivotcheck.models.credentials import (
    Credential,
    CredentialSource,
    CredentialState,
    CredentialType,
)

PASSWORD = "DO_NOT_LEAK_PASSWORD"
NTLM = "a" * 32
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nDO_NOT_LEAK_PRIVATE_KEY\n"
TICKET = "DO_NOT_LEAK_TICKET"

LEAK_MARKERS = (PASSWORD, NTLM, "DO_NOT_LEAK_PRIVATE_KEY", TICKET)


def _ssh_credential(
    state: CredentialState = CredentialState.PRESENT,
    source: CredentialSource = CredentialSource.ENVIRONMENT,
) -> Credential:
    return Credential(
        CredentialType.SSH_PRIVATE_KEY, KEY, username="operator", source=source, state=state
    )


def _ssh_ref(
    credential_id: str = "key-1",
    state: CredentialState = CredentialState.PRESENT,
) -> CredentialRef:
    return CredentialRef.from_credential(_ssh_credential(state), credential_id)


# ---------------------------------------------------------------------------
# CredentialRef / model tests
# ---------------------------------------------------------------------------


class TestCredentialRef:
    def test_from_credential_carries_no_material(self):
        ref = CredentialRef.from_credential(_ssh_credential(), "key-1")
        for marker in LEAK_MARKERS:
            assert marker not in repr(ref)
            assert marker not in json.dumps(ref.to_dict())
        assert ref.credential_type is CredentialType.SSH_PRIVATE_KEY
        assert ref.state is CredentialState.PRESENT

    def test_empty_credential_id_rejected(self):
        with pytest.raises(ValueError, match="credential_id"):
            CredentialRef.from_credential(_ssh_credential(), "")

    def test_invalid_typed_fields_rejected(self):
        with pytest.raises(TypeError, match="invalid credential type"):
            CredentialRef("k", "ssh_private_key", CredentialSource.EXPLICIT, None, CredentialState.PRESENT)  # type: ignore[arg-type]

    def test_ref_is_immutable(self):
        ref = CredentialRef.from_credential(_ssh_credential(), "key-1")
        with pytest.raises(AttributeError):
            ref.credential_id = "other"  # type: ignore[misc]


class TestHostEvidence:
    def test_invalid_evidence_kind_rejected(self):
        with pytest.raises(TypeError, match="invalid evidence kind"):
            HostEvidence("10.10.10.5", ("KNOWN_HOST",))  # type: ignore[arg-type]

    def test_empty_target_rejected(self):
        with pytest.raises(ValueError, match="target"):
            HostEvidence("", (CorrelationEvidenceKind.KNOWN_HOST,))


class TestCandidateModel:
    def test_to_dict_shape(self):
        candidate = CredentialHostCandidate(
            credential_id="key-1",
            credential_type="ssh_private_key",
            credential_source="environment",
            target="10.10.10.5",
            protocol="ssh",
            priority=CorrelationPriority.HIGH,
            evidence=(CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED),
            reason="strong evidence",
            authentication_state="present",
        )
        data = candidate.to_dict()
        assert data["priority"] == "HIGH"
        assert data["evidence"] == ["KNOWN_HOST", "SSH_SERVICE_OBSERVED"]
        assert "reason" in data
        for marker in LEAK_MARKERS:
            assert marker not in json.dumps(data)

    def test_report_to_dict_shape(self):
        report = CorrelationReport()
        data = report.to_dict()
        assert data["schema_version"] == "1.0"
        assert data["candidates"] == []
        assert data["rejected"] == []


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------


class TestCorrelationRules:
    def test_high_known_host_plus_service(self):
        report = correlate(
            (_ssh_ref(),),
            (
                HostEvidence(
                    "10.10.10.5",
                    (
                        CorrelationEvidenceKind.KNOWN_HOST,
                        CorrelationEvidenceKind.SSH_SERVICE_OBSERVED,
                    ),
                ),
            ),
        )
        assert len(report.candidates) == 1
        candidate = report.candidates[0]
        assert candidate.priority is CorrelationPriority.HIGH
        assert candidate.protocol == "ssh"
        assert candidate.target == "10.10.10.5"
        assert CorrelationEvidenceKind.KNOWN_HOST in candidate.evidence
        assert CorrelationEvidenceKind.SSH_SERVICE_OBSERVED in candidate.evidence
        assert "known_hosts" in candidate.reason
        assert "observed" in candidate.reason

    def test_medium_known_host_without_service_observation(self):
        report = correlate(
            (_ssh_ref(),),
            (HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST,),),),
        )
        candidate = report.candidates[0]
        assert candidate.priority is CorrelationPriority.MEDIUM
        # Negative/unknown service state must be surfaced, never upgraded.
        assert "not been explicitly observed" in candidate.reason

    def test_medium_network_evidence_without_service(self):
        report = correlate(
            (_ssh_ref(),),
            (HostEvidence("10.10.10.5", (CorrelationEvidenceKind.NETWORK_OBSERVED,),),),
        )
        assert report.candidates[0].priority is CorrelationPriority.MEDIUM

    def test_low_minimal_evidence(self):
        report = correlate(
            (_ssh_ref(),),
            (
                HostEvidence(
                    "10.10.10.5",
                    (
                        CorrelationEvidenceKind.SSH_SERVICE_NOT_OBSERVED,
                        CorrelationEvidenceKind.NETWORK_OBSERVED,
                    ),
                ),
            ),
        )
        # Explicit negative service evidence with network presence: LOW.
        assert report.candidates[0].priority is CorrelationPriority.LOW

    def test_explicit_negative_service_evidence_surfaced(self):
        report = correlate(
            (_ssh_ref(),),
            (
                HostEvidence(
                    "10.10.10.5",
                    (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_NOT_OBSERVED),
                ),
            ),
        )
        candidate = report.candidates[0]
        assert candidate.priority is CorrelationPriority.MEDIUM
        assert "NOT been explicitly observed" in candidate.reason
        assert "SSH_SERVICE_NOT_OBSERVED" in [e.value for e in candidate.evidence]

    def test_prior_validation_failure_rejects_pair(self):
        report = correlate(
            (_ssh_ref(),),
            (
                HostEvidence(
                    "10.10.10.5",
                    (
                        CorrelationEvidenceKind.KNOWN_HOST,
                        CorrelationEvidenceKind.SSH_SERVICE_OBSERVED,
                        CorrelationEvidenceKind.AUTH_FAILED,
                    ),
                ),
            ),
        )
        assert report.candidates == ()
        assert len(report.rejected) == 1
        assert "rejected this credential" in report.rejected[0].reason

    def test_prior_validation_success_stays_high_and_is_reported(self):
        report = correlate(
            (_ssh_ref(state=CredentialState.AUTHENTICATION_VALIDATED),),
            (
                HostEvidence(
                    "10.10.10.5",
                    (CorrelationEvidenceKind.NETWORK_OBSERVED, CorrelationEvidenceKind.AUTH_VALIDATED),
                ),
            ),
        )
        candidate = report.candidates[0]
        assert candidate.priority is CorrelationPriority.HIGH
        assert candidate.validation_status == "AUTHENTICATED"
        assert candidate.authentication_state == "authentication_validated"

    def test_credential_without_any_host_evidence_rejected(self):
        report = correlate((_ssh_ref(),), (HostEvidence("10.10.10.5", ()),))
        assert report.candidates == ()
        assert report.rejected[0].reason == "no host evidence for this target"

    def test_non_ssh_credential_rejected_without_fabrication(self):
        ref = CredentialRef.from_credential(
            Credential(CredentialType.PASSWORD, PASSWORD, username="admin"), "pw-1"
        )
        report = correlate(
            (ref,),
            (
                HostEvidence(
                    "10.10.10.5",
                    (
                        CorrelationEvidenceKind.KNOWN_HOST,
                        CorrelationEvidenceKind.SSH_SERVICE_OBSERVED,
                    ),
                ),
            ),
        )
        assert report.candidates == ()
        assert "no protocol mapping" in report.rejected[0].reason

    def test_multiple_credentials_and_hosts(self):
        key_a = _ssh_ref("key-a")
        key_b = _ssh_ref("key-b")
        report = correlate(
            (key_a, key_b),
            (
                HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST,)),
                HostEvidence("10.20.30.5", (CorrelationEvidenceKind.SSH_SERVICE_OBSERVED,)),
            ),
        )
        assert len(report.candidates) == 4  # 2 credentials x 2 hosts
        # Deterministic ordering: priority, credential_id, target.
        assert [(c.credential_id, c.target) for c in report.candidates] == sorted(
            (c.credential_id, c.target) for c in report.candidates
        )

    def test_empty_inputs_produce_empty_report(self):
        report = correlate((), ())
        assert report.candidates == ()
        assert report.rejected == ()


# ---------------------------------------------------------------------------
# Determinism / duplicate suppression / family isolation
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_input_order_independence(self):
        hosts_a = (
            HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST,)),
            HostEvidence("10.10.10.6", (CorrelationEvidenceKind.NETWORK_OBSERVED,)),
            HostEvidence("fd00::5", (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED)),
        )
        hosts_b = (
            HostEvidence("fd00::5", (CorrelationEvidenceKind.SSH_SERVICE_OBSERVED, CorrelationEvidenceKind.KNOWN_HOST)),
            HostEvidence("10.10.10.6", (CorrelationEvidenceKind.NETWORK_OBSERVED,)),
            HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST,)),
        )
        first = json.dumps(correlate((_ssh_ref(),), hosts_a).to_dict(), sort_keys=True)
        second = json.dumps(correlate((_ssh_ref(),), hosts_b).to_dict(), sort_keys=True)
        assert first == second

    def test_duplicate_evidence_records_merge_to_one_candidate(self):
        report = correlate(
            (_ssh_ref(),),
            (
                HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST,)),
                HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST,)),
                HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED)),
            ),
        )
        assert len(report.candidates) == 1
        # Evidence merged and deduplicated, canonical order preserved.
        assert [e.value for e in report.candidates[0].evidence] == [
            "KNOWN_HOST",
            "SSH_SERVICE_OBSERVED",
        ]

    def test_repeated_invocation_identical(self):
        inputs = (
            (_ssh_ref(),),
            (HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED)),),
        )
        first = json.dumps(correlate(*inputs).to_dict(), sort_keys=True)
        for _ in range(5):
            assert json.dumps(correlate(*inputs).to_dict(), sort_keys=True) == first


# ---------------------------------------------------------------------------
# Security: no material, no I/O
# ---------------------------------------------------------------------------


class TestSecretSafety:
    def test_no_marker_in_any_representation(self):
        refs = (
            CredentialRef.from_credential(
                Credential(CredentialType.PASSWORD, PASSWORD, username="admin"), "pw-1"
            ),
            _ssh_ref("key-1"),
        )
        report = correlate(
            refs,
            (HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED)),),
        )
        representations = [
            repr(report),
            str(report),
            json.dumps(report.to_dict()),
        ]
        for representation in representations:
            for marker in LEAK_MARKERS:
                assert marker not in representation

    def test_explanations_are_display_safe(self):
        report = correlate(
            (_ssh_ref(),),
            (HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED)),),
        )
        reason = report.candidates[0].reason
        assert "DO_NOT_LEAK" not in reason
        assert "-----BEGIN" not in reason


class TestNoSideEffects:
    def test_engine_never_touches_socket_subprocess_or_filesystem(self, monkeypatch, tmp_path):
        def _explode(*args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("I/O attempted inside the pure correlation engine")

        monkeypatch.setattr(socket, "socket", _explode)
        monkeypatch.setattr(socket, "create_connection", _explode)
        monkeypatch.setattr(socket, "getaddrinfo", _explode)
        monkeypatch.setattr(subprocess, "run", _explode)
        monkeypatch.setattr(subprocess, "Popen", _explode)
        monkeypatch.setattr(Path, "open", _explode)
        monkeypatch.setattr(Path, "read_text", _explode)

        report = correlate(
            (_ssh_ref("key-1", CredentialState.AUTHENTICATION_VALIDATED),),
            (
                HostEvidence("10.10.10.5", (CorrelationEvidenceKind.KNOWN_HOST, CorrelationEvidenceKind.SSH_SERVICE_OBSERVED)),
                HostEvidence("fd00::5", (CorrelationEvidenceKind.NETWORK_OBSERVED,)),
            ),
        )
        assert len(report.candidates) == 2  # v4 and v6 targets stay isolated
        targets = [c.target for c in report.candidates]
        assert "10.10.10.5" in targets and "fd00::5" in targets
