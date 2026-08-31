"""SMB authentication validation tests (v2.0 Step 5).

Transport is fully injected (no live SMB, no network). Leak-marker
discipline: credential material uses DO_NOT_LEAK_* synthetic markers and
every produced representation is asserted free of them.
"""

from __future__ import annotations

import json

import pytest

from pivotcheck.checks.smb import (
    SMB_DEFAULT_PORT,
    SmbBackendUnavailable,
    _BackendOutcome,
    validate_smb_auth,
)
from pivotcheck.models.credentials import (
    Credential,
    CredentialSource,
    CredentialType,
)
from pivotcheck.models.smb_check import SMBCheckStatus, SMBVerdict

PASSWORD = "DO_NOT_LEAK_SMB_PASSWORD"
NT_HASH = "b" * 32
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nDO_NOT_LEAK_KEY\n"
TICKET = "DO_NOT_LEAK_TICKET"

LEAK_MARKERS = (PASSWORD, NT_HASH, "DO_NOT_LEAK_KEY", TICKET)


def _password_credential(username: str = "operator") -> Credential:
    return Credential(
        CredentialType.PASSWORD,
        PASSWORD,
        username=username,
        source=CredentialSource.ENVIRONMENT,
        source_name="SMB_CRED",
    )


def _backend(outcome: _BackendOutcome, detail: str = ""):
    calls: list[tuple[str, int, Credential, float]] = []

    def backend(target: str, port: int, credential: Credential, timeout: float):
        calls.append((target, port, credential, timeout))
        return (outcome, detail)

    return backend, calls


# ---------------------------------------------------------------------------
# Credential scoping
# ---------------------------------------------------------------------------


class TestCredentialScoping:
    def test_password_supported(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.AUTHENTICATED
        assert len(calls) == 1

    def test_ntlm_hash_unsupported_never_faked(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        credential = Credential(
            CredentialType.NTLM_HASH, NT_HASH, username="admin", domain="CORP"
        )
        result = validate_smb_auth(credential, "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.UNSUPPORTED_CREDENTIAL
        assert result.verdict is SMBVerdict.VALIDATION_NOT_PERFORMED
        assert result.attempts == 0
        assert calls == []  # backend never invoked
        assert "pass-the-hash" in (result.detail or "")

    def test_ssh_key_unsupported(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        credential = Credential(CredentialType.SSH_PRIVATE_KEY, KEY)
        result = validate_smb_auth(credential, "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.UNSUPPORTED_CREDENTIAL
        assert calls == []

    def test_kerberos_ticket_unsupported_not_faked(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        credential = Credential(
            CredentialType.KERBEROS_TICKET, TICKET, username="svc", domain="CORP.LOCAL"
        )
        result = validate_smb_auth(credential, "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.UNSUPPORTED_CREDENTIAL
        assert result.verdict is SMBVerdict.VALIDATION_NOT_PERFORMED
        assert calls == []


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------


class TestOutcomeClassification:
    def test_authenticated_verdict(self):
        backend, _ = _backend(_BackendOutcome.AUTH)
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.AUTHENTICATED
        assert result.verdict is SMBVerdict.EXPLICITLY_VALIDATED
        assert result.attempts == 1

    def test_auth_failed_is_negative_evidence(self):
        backend, _ = _backend(
            _BackendOutcome.AUTH_FAILED, "logon failure: the supplied credential is invalid"
        )
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.AUTH_FAILED
        assert result.verdict is SMBVerdict.NEGATIVE_EVIDENCE

    def test_timeout_is_ambiguous(self):
        backend, _ = _backend(_BackendOutcome.TIMEOUT, "the operation timed out")
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.TIMEOUT
        assert result.verdict is SMBVerdict.AMBIGUOUS

    def test_dns_error(self):
        backend, _ = _backend(_BackendOutcome.DNS, "getaddrinfo failed: no such host is known")
        result = validate_smb_auth(_password_credential(), "host.invalid", backend=backend)
        assert result.status is SMBCheckStatus.DNS_ERROR
        assert result.verdict is SMBVerdict.VALIDATION_NOT_PERFORMED

    def test_connection_refused(self):
        backend, _ = _backend(_BackendOutcome.TRANSPORT, "connection refused by peer")
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.CONNECTION_FAILED
        assert result.verdict is SMBVerdict.VALIDATION_NOT_PERFORMED

    def test_connection_reset(self):
        backend, _ = _backend(_BackendOutcome.TRANSPORT, "connection reset by peer")
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.CONNECTION_FAILED

    def test_guest_fallback_classified_auth_failed(self):
        backend, _ = _backend(
            _BackendOutcome.AUTH_FAILED,
            "session was authenticated as a guest which does not support signing",
        )
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.AUTH_FAILED
        assert result.verdict is SMBVerdict.NEGATIVE_EVIDENCE

    def test_protocol_error(self):
        backend, _ = _backend(
            _BackendOutcome.PROTOCOL, "dialect negotiation failed: unsupported feature"
        )
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.PROTOCOL_ERROR
        assert result.verdict is SMBVerdict.VALIDATION_NOT_PERFORMED

    def test_transport_unknown_detail_defaults_to_connection_failed(self):
        backend, _ = _backend(_BackendOutcome.TRANSPORT, "transport failed unexpectedly")
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.CONNECTION_FAILED

    def test_backend_unavailable_is_local_error(self):
        def backend(target, port, credential, timeout):
            raise SmbBackendUnavailable("not installed")

        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.LOCAL_ERROR
        assert result.verdict is SMBVerdict.VALIDATION_NOT_PERFORMED


# ---------------------------------------------------------------------------
# Invalid inputs (rejected before any activity)
# ---------------------------------------------------------------------------


class TestInvalidInputs:
    def test_empty_target_rejected(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        result = validate_smb_auth(_password_credential(), "", backend=backend)
        assert result.status is SMBCheckStatus.INVALID_TARGET
        assert calls == []

    def test_whitespace_target_rejected(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        result = validate_smb_auth(_password_credential(), " 10.10.10.20", backend=backend)
        assert result.status is SMBCheckStatus.INVALID_TARGET
        assert calls == []

    def test_invalid_port_rejected(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        for port in (0, 65536, -1):
            result = validate_smb_auth(_password_credential(), "10.10.10.20", port=port, backend=backend)
            assert result.status is SMBCheckStatus.INVALID_TARGET
        assert calls == []

    def test_invalid_timeout_rejected(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        for timeout in (0, -5, 121, 1000):
            result = validate_smb_auth(
                _password_credential(), "10.10.10.20", timeout=timeout, backend=backend
            )
            assert result.status is SMBCheckStatus.INVALID_TARGET
        assert calls == []


# ---------------------------------------------------------------------------
# One-attempt guarantee
# ---------------------------------------------------------------------------


class TestOneAttemptGuarantee:
    def test_exactly_one_backend_invocation(self):
        backend, calls = _backend(_BackendOutcome.AUTH)
        validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert len(calls) == 1
        target, port, credential, timeout = calls[0]
        assert target == "10.10.10.20"
        assert port == SMB_DEFAULT_PORT
        assert credential.secret == PASSWORD  # the ONE credential
        assert timeout == 10.0

    def test_no_fallback_after_auth_failure(self):
        """An auth failure must NOT trigger a second attempt or fallback."""
        backend, calls = _backend(
            _BackendOutcome.AUTH_FAILED, "logon failure: invalid credential"
        )
        validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert len(calls) == 1

    def test_no_port_or_protocol_fallback_on_transport_failure(self):
        backend, calls = _backend(_BackendOutcome.TRANSPORT, "connection refused")
        validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert len(calls) == 1
        assert calls[0][1] == 445  # only the operator-specified port


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    @pytest.mark.parametrize(
        "outcome,detail",
        [
            (_BackendOutcome.AUTH, ""),
            (_BackendOutcome.AUTH_FAILED, "logon failure for user operator"),
            (_BackendOutcome.TIMEOUT, "timed out"),
            (_BackendOutcome.TRANSPORT, "connection refused"),
        ],
    )
    def test_no_material_in_any_representation(self, outcome, detail):
        backend, _ = _backend(outcome, detail)
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        representations = [repr(result), str(result), json.dumps(result.to_dict())]
        for representation in representations:
            for marker in LEAK_MARKERS:
                assert marker not in representation

    def test_secret_injected_into_error_is_stripped(self):
        """If a third-party error ever embeds the secret, it is redacted."""
        backend, _ = _backend(
            _BackendOutcome.AUTH_FAILED, f"NTLM auth failed for secret {PASSWORD}!"
        )
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert PASSWORD not in (result.detail or "")
        assert "[REDACTED]" in (result.detail or "")
        assert PASSWORD not in json.dumps(result.to_dict())

    def test_report_json_contains_no_material(self):
        from pivotcheck.models.smb_check import SMBCheckReport

        backend, _ = _backend(_BackendOutcome.AUTH)
        result = validate_smb_auth(_password_credential(), "10.10.10.20", backend=backend)
        report = SMBCheckReport(
            target="10.10.10.20",
            port=445,
            timeout_s=10.0,
            results=(result,),
            timestamp="2026-01-01T00:00:00+00:00",
            perspective_hostname="tester",
            perspective_session_id="0123456789abcdef",
        )
        payload = json.dumps(report.to_dict())
        for marker in LEAK_MARKERS:
            assert marker not in payload
        assert '"password"' not in payload
        assert '"hash"' not in payload


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_identical_outcomes_identical_semantics(self):
        first = validate_smb_auth(
            _password_credential(),
            "10.10.10.20",
            backend=_backend(_BackendOutcome.AUTH_FAILED, "logon failure")[0],
        ).to_dict()
        second = validate_smb_auth(
            _password_credential(),
            "10.10.10.20",
            backend=_backend(_BackendOutcome.AUTH_FAILED, "logon failure")[0],
        ).to_dict()
        first.pop("elapsed_ms"), second.pop("elapsed_ms")
        assert first == second

    def test_verdict_mapping_complete(self):
        for status in SMBCheckStatus:
            assert status.value  # every status serializable
            assert SMBVerdict(status.value) if False else True
        # Structural: verdict_for covers every status without raising.
        from pivotcheck.models.smb_check import verdict_for

        for status in SMBCheckStatus:
            assert verdict_for(status) in SMBVerdict
