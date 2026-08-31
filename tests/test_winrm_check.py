"""WinRM authentication validation tests (v2.0 Step 6).

Transport is fully injected (no live WinRM, no network). Leak-marker
discipline: credential material uses DO_NOT_LEAK_* synthetic markers and
every produced representation is asserted free of them.
"""

from __future__ import annotations

import json

import pytest

from pivotcheck.checks.winrm import (
    WinRMBackendUnavailable,
    validate_winrm_auth,
)
from pivotcheck.models.credentials import (
    Credential,
    CredentialSource,
    CredentialType,
)
from pivotcheck.models.winrm_check import WinRMCheckStatus, WinRMVerdict

PASSWORD = "DO_NOT_LEAK_WINRM_PASSWORD"
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
        source_name="WINRM_CRED",
    )


def _backend(outcome: str, detail: str = ""):
    calls: list[dict] = []

    def backend(target: str, port: int, credential: Credential, timeout: float, scheme: str):
        calls.append(
            {
                "target": target,
                "port": port,
                "credential": credential,
                "timeout": timeout,
                "scheme": scheme,
            }
        )
        return (outcome, detail)

    return backend, calls


# ---------------------------------------------------------------------------
# Credential scoping
# ---------------------------------------------------------------------------


class TestCredentialScoping:
    def test_password_supported(self):
        backend, calls = _backend("auth")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.AUTHENTICATED
        assert len(calls) == 1

    def test_ntlm_hash_unsupported_never_faked(self):
        backend, calls = _backend("auth")
        credential = Credential(CredentialType.NTLM_HASH, NT_HASH, username="admin", domain="CORP")
        result = validate_winrm_auth(credential, "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.UNSUPPORTED_CREDENTIAL
        assert result.verdict is WinRMVerdict.VALIDATION_NOT_PERFORMED
        assert result.attempts == 0
        assert calls == []
        assert "pass-the-hash" in (result.detail or "")

    def test_ssh_key_unsupported(self):
        backend, calls = _backend("auth")
        credential = Credential(CredentialType.SSH_PRIVATE_KEY, KEY)
        result = validate_winrm_auth(credential, "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.UNSUPPORTED_CREDENTIAL
        assert calls == []

    def test_kerberos_ticket_unsupported_not_faked(self):
        backend, calls = _backend("auth")
        credential = Credential(
            CredentialType.KERBEROS_TICKET, TICKET, username="svc", domain="CORP.LOCAL"
        )
        result = validate_winrm_auth(credential, "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.UNSUPPORTED_CREDENTIAL
        assert result.verdict is WinRMVerdict.VALIDATION_NOT_PERFORMED
        assert calls == []


# ---------------------------------------------------------------------------
# Outcome classification
# ---------------------------------------------------------------------------


class TestOutcomeClassification:
    def test_authenticated_verdict(self):
        backend, calls = _backend("auth")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.AUTHENTICATED
        assert result.verdict is WinRMVerdict.EXPLICITLY_VALIDATED
        assert result.attempts == 1
        assert calls[0]["scheme"] == "http"

    def test_auth_failed_is_negative_evidence(self):
        backend, _ = _backend("auth-failed", "the specified credentials were rejected")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.AUTH_FAILED
        assert result.verdict is WinRMVerdict.NEGATIVE_EVIDENCE

    def test_timeout_is_ambiguous(self):
        backend, _ = _backend("timeout", "the operation timed out")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.TIMEOUT
        assert result.verdict is WinRMVerdict.AMBIGUOUS

    def test_dns_error(self):
        backend, _ = _backend("dns", "getaddrinfo failed: no such host is known")
        result = validate_winrm_auth(_password_credential(), "host.invalid", backend=backend)
        assert result.status is WinRMCheckStatus.DNS_ERROR
        assert result.verdict is WinRMVerdict.VALIDATION_NOT_PERFORMED

    def test_connection_refused(self):
        backend, _ = _backend("transport", "connection refused by peer")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.CONNECTION_FAILED

    def test_protocol_error(self):
        backend, _ = _backend("protocol", "soap fault: malformed wsman envelope")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.PROTOCOL_ERROR
        assert result.verdict is WinRMVerdict.VALIDATION_NOT_PERFORMED

    def test_transport_unknown_detail_defaults_to_connection_failed(self):
        backend, _ = _backend("transport", "transport failed unexpectedly")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.CONNECTION_FAILED

    def test_backend_unavailable_is_local_error(self):
        def backend(target, port, credential, timeout, scheme):
            raise WinRMBackendUnavailable("not installed")

        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.LOCAL_ERROR
        assert result.verdict is WinRMVerdict.VALIDATION_NOT_PERFORMED


# ---------------------------------------------------------------------------
# HTTPS / TLS semantics
# ---------------------------------------------------------------------------


class TestHTTPSSemantics:
    def test_https_scheme_is_explicit(self):
        backend, calls = _backend("auth")
        validate_winrm_auth(
            _password_credential(), "10.10.10.20", port=5986, backend=backend,
            transport_scheme="https",
        )
        assert calls[0]["scheme"] == "https"

    def test_tls_failure_is_distinct_from_auth_failure(self):
        backend, _ = _backend("tls", "certificate verify failed: self signed certificate")
        result = validate_winrm_auth(
            _password_credential(), "10.10.10.20", port=5986, backend=backend,
            transport_scheme="https",
        )
        assert result.status is WinRMCheckStatus.TLS_FAILED
        assert result.verdict is WinRMVerdict.VALIDATION_NOT_PERFORMED

    def test_invalid_transport_scheme_rejected(self):
        backend, calls = _backend("auth")
        result = validate_winrm_auth(
            _password_credential(), "10.10.10.20", backend=backend, transport_scheme="ftp"
        )
        assert result.status is WinRMCheckStatus.INVALID_TARGET
        assert calls == []

    def test_5986_port_convention_defaults_to_https(self):
        backend, calls = _backend("auth")
        validate_winrm_auth(_password_credential(), "10.10.10.20", port=5986, backend=backend)
        assert calls[0]["scheme"] == "https"

    def test_5985_port_convention_defaults_to_http(self):
        backend, calls = _backend("auth")
        validate_winrm_auth(_password_credential(), "10.10.10.20", port=5985, backend=backend)
        assert calls[0]["scheme"] == "http"


# ---------------------------------------------------------------------------
# Invalid inputs (rejected before any activity)
# ---------------------------------------------------------------------------


class TestInvalidInputs:
    def test_empty_target_rejected(self):
        backend, calls = _backend("auth")
        result = validate_winrm_auth(_password_credential(), "", backend=backend)
        assert result.status is WinRMCheckStatus.INVALID_TARGET
        assert calls == []

    def test_whitespace_target_rejected(self):
        backend, calls = _backend("auth")
        result = validate_winrm_auth(_password_credential(), " 10.10.10.20", backend=backend)
        assert result.status is WinRMCheckStatus.INVALID_TARGET
        assert calls == []

    def test_invalid_port_rejected(self):
        backend, calls = _backend("auth")
        for port in (0, 65536, -1):
            result = validate_winrm_auth(
                _password_credential(), "10.10.10.20", port=port, backend=backend
            )
            assert result.status is WinRMCheckStatus.INVALID_TARGET
        assert calls == []

    def test_invalid_timeout_rejected(self):
        backend, calls = _backend("auth")
        for timeout in (0, -5, 121, 1000):
            result = validate_winrm_auth(
                _password_credential(), "10.10.10.20", timeout=timeout, backend=backend
            )
            assert result.status is WinRMCheckStatus.INVALID_TARGET
        assert calls == []


# ---------------------------------------------------------------------------
# One-attempt guarantee
# ---------------------------------------------------------------------------


class TestOneAttemptGuarantee:
    def test_exactly_one_backend_invocation(self):
        backend, calls = _backend("auth")
        validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert len(calls) == 1
        call = calls[0]
        assert call["target"] == "10.10.10.20"
        assert call["port"] == 5985
        assert call["credential"].secret == PASSWORD  # the ONE credential

    def test_no_fallback_after_auth_failure(self):
        backend, calls = _backend("auth-failed", "credentials rejected")
        validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert len(calls) == 1

    def test_no_port_or_protocol_fallback_on_transport_failure(self):
        backend, calls = _backend("transport", "connection refused")
        validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert len(calls) == 1
        assert calls[0]["port"] == 5985  # only the operator-specified port

    def test_no_scheme_downgrade_on_tls_failure(self):
        backend, calls = _backend("tls", "certificate verify failed")
        validate_winrm_auth(
            _password_credential(), "10.10.10.20", port=5986, backend=backend,
            transport_scheme="https",
        )
        assert len(calls) == 1
        assert calls[0]["scheme"] == "https"  # no silent downgrade


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


class TestSecretSafety:
    @pytest.mark.parametrize(
        "outcome,detail",
        [
            ("auth", ""),
            ("auth-failed", "the specified credentials were rejected by the server"),
            ("timeout", "timed out"),
            ("transport", "connection refused"),
            ("tls", "certificate verify failed"),
        ],
    )
    def test_no_material_in_any_representation(self, outcome, detail):
        backend, _ = _backend(outcome, detail)
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        representations = [repr(result), str(result), json.dumps(result.to_dict())]
        for representation in representations:
            for marker in LEAK_MARKERS:
                assert marker not in representation

    def test_secret_injected_into_error_is_stripped(self):
        backend, _ = _backend(
            "auth-failed", f"NTLM auth failed for secret {PASSWORD}!"
        )
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        assert PASSWORD not in (result.detail or "")
        assert "[REDACTED]" in (result.detail or "")
        assert PASSWORD not in json.dumps(result.to_dict())

    def test_report_json_contains_no_material(self):
        from pivotcheck.models.winrm_check import WinRMCheckReport

        backend, _ = _backend("auth")
        result = validate_winrm_auth(_password_credential(), "10.10.10.20", backend=backend)
        report = WinRMCheckReport(
            target="10.10.10.20",
            port=5985,
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
        def make_backend():
            return _backend("auth-failed", "the specified credentials were rejected by the server")[0]

        first = validate_winrm_auth(
            _password_credential(), "10.10.10.20", backend=make_backend()
        ).to_dict()
        second = validate_winrm_auth(
            _password_credential(), "10.10.10.20", backend=make_backend()
        ).to_dict()
        first.pop("elapsed_ms"), second.pop("elapsed_ms")
        assert first == second

    def test_verdict_mapping_complete(self):
        from pivotcheck.models.winrm_check import verdict_for

        for status in WinRMCheckStatus:
            assert verdict_for(status) in WinRMVerdict
