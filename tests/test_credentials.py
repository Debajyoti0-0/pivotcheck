"""Credential abstraction tests (v2.0 Step 1).

Leak-marker discipline: every test uses deliberately recognizable secret
material (DO_NOT_LEAK_*) and asserts that material never appears in any
representation PivotCheck produces.
"""

from __future__ import annotations

import dataclasses
import json
import os

import pytest

from pivotcheck.models.credentials import (
    Credential,
    CredentialSource,
    CredentialState,
    CredentialType,
)
from pivotcheck.utils.credential_loader import CredentialLoadError, load_credential

PASSWORD = "DO_NOT_LEAK_PASSWORD_123"
NTLM = "DO_NOT_LEAK"  # replaced by valid hex below; leak marker kept in tests
NTLM_VALID = "a" * 32
NTLM_FULL = f"{'b' * 32}:{'c' * 32}"
PEM_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "DO_NOT_LEAK_PRIVATE_KEY_789\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
TICKET = "DO_NOT_LEAK_KERBEROS_TICKET_000"

LEAK_MARKERS = (
    "DO_NOT_LEAK_PASSWORD_123",
    "DO_NOT_LEAK_PRIVATE_KEY_789",
    "DO_NOT_LEAK_KERBEROS_TICKET_000",
    "a" * 32,
    "b" * 32,
)


def _every_representation(credential: Credential) -> list[str]:
    """Every string form the public surface can produce."""
    return [
        repr(credential),
        str(credential),
        json.dumps(credential.to_dict()),
        json.dumps([credential.to_dict()]),
    ]


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestCredentialModel:
    def test_password_credential(self):
        cred = Credential(CredentialType.PASSWORD, PASSWORD, username="alice")
        assert cred.credential_type is CredentialType.PASSWORD
        assert cred.username == "alice"
        assert cred.domain is None
        assert cred.state is CredentialState.PRESENT

    def test_ntlm_hash_single(self):
        cred = Credential(CredentialType.NTLM_HASH, NTLM_VALID, username="bob", domain="CORP")
        assert cred.domain == "CORP"

    def test_ntlm_hash_lm_nt_pair(self):
        cred = Credential(CredentialType.NTLM_HASH, NTLM_FULL, username="bob", domain="CORP")
        assert cred.secret == NTLM_FULL

    def test_ntlm_invalid_format_rejected(self):
        with pytest.raises(ValueError, match="NTLM credential"):
            Credential(CredentialType.NTLM_HASH, "zz-not-hex-123456789012345678901")

    def test_stored_material_validated_verbatim_regression(self):
        """Validation must check exactly what is stored (no silent strip).

        Regression: validation previously stripped whitespace before
        matching while storing the raw value, so a whitespace-padded hash
        validated but was stored padded. The loader strips; direct
        construction must reject padded material.
        """
        with pytest.raises(ValueError, match="whitespace is not permitted"):
            Credential(CredentialType.NTLM_HASH, f"  {NTLM_VALID}")
        with pytest.raises(ValueError, match="no leading whitespace"):
            Credential(CredentialType.SSH_PRIVATE_KEY, f"  {PEM_KEY}")

    def test_ssh_private_key_requires_pem_header(self):
        cred = Credential(CredentialType.SSH_PRIVATE_KEY, PEM_KEY)
        assert cred.credential_type is CredentialType.SSH_PRIVATE_KEY
        with pytest.raises(ValueError, match="PEM private key header"):
            Credential(CredentialType.SSH_PRIVATE_KEY, "not a key")

    def test_kerberos_ticket_representation(self):
        cred = Credential(
            CredentialType.KERBEROS_TICKET, TICKET, username="svc-cifs", domain="CORP.LOCAL"
        )
        assert cred.domain == "CORP.LOCAL"

    def test_domain_rejected_for_non_domain_types(self):
        with pytest.raises(ValueError, match="do not take a domain"):
            Credential(CredentialType.PASSWORD, PASSWORD, domain="CORP")
        with pytest.raises(ValueError, match="do not take a domain"):
            Credential(CredentialType.SSH_PRIVATE_KEY, PEM_KEY, domain="CORP")

    def test_empty_secret_rejected(self):
        with pytest.raises(ValueError, match="must not be empty"):
            Credential(CredentialType.PASSWORD, "")

    def test_empty_username_rejected(self):
        with pytest.raises(ValueError, match="username"):
            Credential(CredentialType.PASSWORD, PASSWORD, username="")

    def test_invalid_type_rejected(self):
        with pytest.raises(TypeError, match="invalid credential type"):
            Credential("password", PASSWORD)  # type: ignore[arg-type]

    def test_invalid_source_and_state_types_rejected(self):
        with pytest.raises(TypeError, match="invalid credential source"):
            Credential(CredentialType.PASSWORD, PASSWORD, source="environment")  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="invalid credential state"):
            Credential(CredentialType.PASSWORD, PASSWORD, state="present")  # type: ignore[arg-type]

    def test_equality_includes_secret_material(self):
        a = Credential(CredentialType.PASSWORD, "one")
        b = Credential(CredentialType.PASSWORD, "one")
        c = Credential(CredentialType.PASSWORD, "two")
        assert a == b
        assert a != c

    def test_epistemic_state_distinct_from_possession(self):
        cred = Credential(CredentialType.PASSWORD, PASSWORD)
        assert cred.state is CredentialState.PRESENT
        validated = Credential(
            CredentialType.PASSWORD, PASSWORD, state=CredentialState.AUTHENTICATION_VALIDATED
        )
        assert validated.state is CredentialState.AUTHENTICATION_VALIDATED
        assert validated != cred  # state changes identity


# ---------------------------------------------------------------------------
# Security tests: leak-marker sweep over every representation
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    @pytest.mark.parametrize(
        "credential",
        [
            Credential(CredentialType.PASSWORD, PASSWORD, username="alice"),
            Credential(CredentialType.NTLM_HASH, NTLM_VALID, username="bob", domain="CORP"),
            Credential(CredentialType.NTLM_HASH, NTLM_FULL, username="bob", domain="CORP"),
            Credential(CredentialType.SSH_PRIVATE_KEY, PEM_KEY),
            Credential(
                CredentialType.KERBEROS_TICKET,
                TICKET,
                username="svc",
                domain="CORP.LOCAL",
            ),
        ],
        ids=["password", "ntlm", "ntlm-full", "ssh-key", "kerberos"],
    )
    def test_no_representation_contains_material(self, credential: Credential):
        secret = credential.secret
        assert secret, "test material must be non-empty"
        for representation in _every_representation(credential):
            assert secret not in representation, f"material leaked in: {representation}"
            assert secret.split("\n")[0] not in representation

    def test_repr_uses_redacted_marker(self):
        cred = Credential(CredentialType.PASSWORD, PASSWORD, username="alice")
        assert repr(cred) == (
            "Credential(type=password, username=alice, secret=[REDACTED], source=explicit)"
        )
        assert str(cred) == repr(cred)

    def test_dataclass_default_repr_is_not_used(self):
        # Guard: the field must stay repr=False so dataclass machinery can
        # never reintroduce material into repr().
        field_reprs = {f.name: f.repr for f in dataclasses.fields(Credential)}
        assert field_reprs["secret"] is False

    def test_to_dict_has_secret_present_not_material(self):
        cred = Credential(CredentialType.PASSWORD, PASSWORD, username="alice", domain=None)
        safe = cred.to_dict()
        assert safe["secret_present"] is True
        assert safe["credential_type"] == "password"
        assert "secret" not in safe
        assert "secret_value" not in safe
        # The type name is metadata; the material never appears.
        assert PASSWORD not in json.dumps(safe)

    def test_validation_error_does_not_embed_material(self):
        bad_material = "zz-secret-material-99-not-hex-12345678901"
        with pytest.raises(ValueError) as excinfo:
            Credential(CredentialType.NTLM_HASH, bad_material)
        assert bad_material not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_repeated_serialization_identical(self):
        cred = Credential(
            CredentialType.NTLM_HASH,
            NTLM_VALID,
            username="bob",
            domain="CORP",
            source=CredentialSource.ENVIRONMENT,
            source_name="NTLM_HASH_ENV",
        )
        first = json.dumps(cred.to_dict(), sort_keys=True)
        for _ in range(5):
            assert json.dumps(cred.to_dict(), sort_keys=True) == first
        assert repr(cred) == repr(
            Credential(
                CredentialType.NTLM_HASH,
                NTLM_VALID,
                username="bob",
                domain="CORP",
                source=CredentialSource.ENVIRONMENT,
                source_name="NTLM_HASH_ENV",
            )
        )


# ---------------------------------------------------------------------------
# Environment loader
# ---------------------------------------------------------------------------


class TestCredentialLoader:
    def test_load_password(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_PASSWORD_ENV", PASSWORD)
        cred = load_credential(CredentialType.PASSWORD, "PC_TEST_PASSWORD_ENV", username="alice")
        assert cred.secret == PASSWORD  # verbatim: whitespace may be significant
        assert cred.source is CredentialSource.ENVIRONMENT
        assert cred.source_name == "PC_TEST_PASSWORD_ENV"
        assert cred.username == "alice"

    def test_load_strips_whitespace_for_hash_and_key(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_NTLM_ENV", f"  {NTLM_VALID}\n")
        cred = load_credential(CredentialType.NTLM_HASH, "PC_TEST_NTLM_ENV")
        assert cred.secret == NTLM_VALID

        monkeypatch.setenv("PC_TEST_KEY_ENV", f"\n{PEM_KEY}\n")
        key = load_credential(CredentialType.SSH_PRIVATE_KEY, "PC_TEST_KEY_ENV")
        assert key.secret.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_password_whitespace_preserved(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_PW_ENV", "  spaced secret  ")
        cred = load_credential(CredentialType.PASSWORD, "PC_TEST_PW_ENV")
        assert cred.secret == "  spaced secret  "

    def test_missing_variable_raises_with_name_only(self, monkeypatch):
        monkeypatch.delenv("PC_TEST_MISSING_ENV", raising=False)
        with pytest.raises(CredentialLoadError, match="PC_TEST_MISSING_ENV"):
            load_credential(CredentialType.PASSWORD, "PC_TEST_MISSING_ENV")
        # The error names the variable, never a value.
        with pytest.raises(CredentialLoadError) as excinfo:
            load_credential(CredentialType.PASSWORD, "PC_TEST_MISSING_ENV")
        assert PASSWORD not in str(excinfo.value)

    def test_empty_variable_rejected(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_EMPTY_ENV", "")
        with pytest.raises(CredentialLoadError, match="empty"):
            load_credential(CredentialType.PASSWORD, "PC_TEST_EMPTY_ENV")

    def test_whitespace_only_rejected_for_stripped_types(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_WS_ENV", "   \n\t  ")
        with pytest.raises(CredentialLoadError, match="empty or whitespace"):
            load_credential(CredentialType.NTLM_HASH, "PC_TEST_WS_ENV")

    def test_invalid_material_rejected_without_value_leak(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_BAD_ENV", "definitely-not-a-ntlm-hash")
        with pytest.raises(CredentialLoadError, match="not valid for ntlm_hash") as excinfo:
            load_credential(CredentialType.NTLM_HASH, "PC_TEST_BAD_ENV")
        assert "definitely-not-a-ntlm-hash" not in str(excinfo.value)

    def test_environment_not_mutated(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_KEEP_ENV", PASSWORD)
        before = dict(os.environ)
        load_credential(CredentialType.PASSWORD, "PC_TEST_KEEP_ENV")
        assert dict(os.environ) == before

    def test_provenance_records_name_never_value(self, monkeypatch):
        monkeypatch.setenv("PC_TEST_PROV_ENV", PASSWORD)
        cred = load_credential(CredentialType.PASSWORD, "PC_TEST_PROV_ENV")
        provenance = json.dumps(cred.to_dict())
        assert cred.source_name == "PC_TEST_PROV_ENV"
        assert PASSWORD not in provenance

    def test_no_env_enumeration(self, monkeypatch):
        # The loader must read only the named variable: deleting every other
        # variable must not change loader behavior.
        monkeypatch.setenv("PC_TEST_ONLY_ENV", PASSWORD)
        monkeypatch.setattr(os, "environ", {"PC_TEST_ONLY_ENV": PASSWORD})
        cred = load_credential(CredentialType.PASSWORD, "PC_TEST_ONLY_ENV")
        assert cred.secret == PASSWORD


# ---------------------------------------------------------------------------
# Safety: zero network I/O, zero subprocesses, zero filesystem writes
# ---------------------------------------------------------------------------


class TestNoSideEffects:
    def test_credential_surface_performs_no_network_or_subprocess_io(self, monkeypatch):
        def _explode(*args, **kwargs):  # pragma: no cover - must never run
            raise AssertionError("network/subprocess I/O attempted during credential use")

        import socket
        import subprocess

        monkeypatch.setattr(socket, "socket", _explode)
        monkeypatch.setattr(socket, "create_connection", _explode)
        monkeypatch.setattr(subprocess, "run", _explode)
        monkeypatch.setattr(subprocess, "Popen", _explode)

        cred = Credential(CredentialType.NTLM_HASH, NTLM_VALID, username="bob", domain="CORP")
        _ = repr(cred)
        _ = str(cred)
        _ = json.dumps(cred.to_dict())
        monkeypatch.setenv("PC_TEST_IO_ENV", NTLM_VALID)
        loaded = load_credential(CredentialType.NTLM_HASH, "PC_TEST_IO_ENV")
        _ = json.dumps(loaded.to_dict())

    def test_no_filesystem_writes(self, tmp_path):
        before = sorted(p.name for p in tmp_path.iterdir())
        cred = Credential(CredentialType.PASSWORD, PASSWORD, username="alice")
        _ = repr(cred)
        _ = json.dumps(cred.to_dict())
        after = sorted(p.name for p in tmp_path.iterdir())
        assert before == after
