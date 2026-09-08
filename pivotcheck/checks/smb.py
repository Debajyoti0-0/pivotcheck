"""SMB authentication validation (v2.0 Step 5).

Converts an already-held PASSWORD credential into ONE explicit SMB2
session-setup attempt against exactly one operator-specified target:port.

Backend decision (documented, deliberate):

- ``smbprotocol`` (MIT license; pure Python; Python >= 3.10; deps:
  cryptography + pyspnego) as an OPTIONAL extra ``[smb]``. The runtime
  core of PivotCheck stays dependency-free: importing PivotCheck never
  requires smbprotocol, and this module degrades to a LOCAL_ERROR when
  the extra is absent.
- ``auth_protocol="ntlm"`` is forced: deterministic, no Kerberos
  fallback (protocol fallback is forbidden by the one-attempt contract).
- Guest fallback is refused by construction: the session requires
  signing/encryption, so a server's guest downgrade raises and is
  classified AUTH_FAILED (the supplied credential was rejected — a
  guest session is not authentication).
- Only the smallest protocol operation needed to prove authentication is
  performed: negotiate + session setup, then disconnect. NO share
  enumeration, NO tree connects, NO file operations, NO execution.

Hard boundary (structural):

- ONE target, ONE port, ONE credential, ONE attempt. No loops, no
  retries, no credential/protocol fallback, no scanning.
- Credential material never appears in any surfaced detail: third-party
  exception strings are normalized and the secret value is stripped
  defensively.

Known limitation (updated G-01, Stage 35): NTLM pass-the-hash IS supported
through the backend's documented public credential primitive
(``spnego.NTLMHash``), which ``smbprotocol.Session`` forwards credentials
to (source-audited: Session.username flows verbatim into
``spnego.client`` whose typed signature includes ``NTLMHash``). The
translation is an explicit typed boundary: NTLM_HASH → NTLMHash — the
hash is NEVER converted into a password. A hash without a username is
rejected (a hash alone does not identify an account).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from enum import IntEnum

from pivotcheck.models.credentials import Credential, CredentialType
from pivotcheck.models.smb_check import (
    SMBCheckResult,
    SMBCheckStatus,
    verdict_for,
)

SMB_DEFAULT_PORT = 445

LOG = logging.getLogger(__name__)


class SmbBackendUnavailable(RuntimeError):
    """The optional SMB backend (smbprotocol) is not installed."""


class _BackendOutcome(IntEnum):
    """Normalized backend outcomes (raw third-party errors are normalized
    into these before classification)."""

    AUTH = 0
    AUTH_FAILED = 1
    TIMEOUT = 2
    DNS = 3
    TRANSPORT = 4
    PROTOCOL = 5


# Classification markers (matched against normalized backend detail text).
_AUTH_MARKERS = ("logon failure", "access denied", "wrong password", "none mapped")
_GUEST_MARKERS = ("guest",)
_DNS_MARKERS = ("getaddrinfo", "name or service not known", "no address associated", "no such host is known")
_REFUSED_MARKERS = ("connection refused", "actively refused", "econnrefused")
_UNREACHABLE_MARKERS = (
    "no route to host",
    "network is unreachable",
    "host is unreachable",
    "enetunreach",
)
_RESET_MARKERS = ("connection reset", "econnreset", "forcibly closed")
_TIMEOUT_MARKERS = ("timed out", "timeout", "timedout")
_PROTOCOL_MARKERS = ("protocol", "dialect", "negotiate", "unsupported feature", "malformed")


def _first(text: str, markers: tuple[str, ...]) -> str | None:
    for marker in markers:
        if marker in text:
            return marker
    return None


def _strip_secret(text: str, secret: str | None) -> str:
    if secret and secret in text:
        text = text.replace(secret, "[REDACTED]")
    return text


def _ntlm_hash_credential(credential: Credential) -> object:
    """Translate the NTLM_HASH credential into the backend's typed hash
    primitive (G-01, Stage 35).

    Explicit typed boundary: NTLM_HASH -> spnego.NTLMHash (the documented
    public credential class accepted by ``spnego.client``, which
    smbprotocol.Session forwards credentials to). The hash is NEVER
    converted into a password, never stored, never serialized.

    - 32-hex secret  -> nt_hash (LM omitted; modern NTLM ignores it)
    - LM:NT secret   -> lm_hash + nt_hash
    - Hex is normalized to uppercase (case-agnostic material).
    - Username carries the optional domain in NTLM 'DOMAIN\\user' form.
    """
    try:
        from spnego import NTLMHash
    except ImportError as exc:
        raise SmbBackendUnavailable(
            "the NTLM hash backend is unavailable: install the optional "
            "'smb' extra (pip install 'pivotcheck[smb]')"
        ) from exc
    secret = credential.secret
    if ":" in secret:
        lm_raw, _, nt_raw = secret.partition(":")
        lm_hash: str | None = lm_raw.upper()
        nt_hash: str = nt_raw.upper()
    else:
        lm_hash = None
        nt_hash = secret.upper()
    username = credential.username or ""
    if credential.domain:
        username = f"{credential.domain}\\{username}"
    return NTLMHash(username=username, lm_hash=lm_hash, nt_hash=nt_hash)


def _normalize_detail(text: object, secret: str | None) -> str:
    """Third-party exception text -> one redacted, single-line detail."""
    cleaned = " ".join(str(text).split())
    return _strip_secret(cleaned, secret)[:300]


def _classify_detail(detail: str) -> SMBCheckStatus | None:
    """Refine a TRANSPORT outcome using its normalized detail text."""
    lowered = detail.lower()
    if _first(lowered, _DNS_MARKERS):
        return SMBCheckStatus.DNS_ERROR
    if _first(lowered, _REFUSED_MARKERS):
        return SMBCheckStatus.CONNECTION_FAILED
    if _first(lowered, _RESET_MARKERS):
        return SMBCheckStatus.CONNECTION_FAILED
    if _first(lowered, _UNREACHABLE_MARKERS):
        return SMBCheckStatus.CONNECTION_FAILED
    if _first(lowered, _TIMEOUT_MARKERS):
        return SMBCheckStatus.TIMEOUT
    if _first(lowered, _GUEST_MARKERS) or _first(lowered, _AUTH_MARKERS):
        return SMBCheckStatus.AUTH_FAILED
    if _first(lowered, _PROTOCOL_MARKERS):
        return SMBCheckStatus.PROTOCOL_ERROR
    return None


# ---------------------------------------------------------------------------
# Real backend (smbprotocol, optional extra; imported lazily)
# ---------------------------------------------------------------------------


def _default_backend(
    target: str, port: int, credential: Credential, timeout: float
) -> tuple[_BackendOutcome, str]:
    """Run the real smbprotocol backend.

    One connection, one session setup (auth_protocol forced to ntlm for
    determinism), one disconnect. Raises SmbBackendUnavailable only when
    the optional extra is missing.

    Credential boundary (G-01): PASSWORD credentials supply the secret as
    the password; NTLM_HASH credentials are translated into the backend's
    typed hash primitive (spnego.NTLMHash) with password=None — the hash
    is never masqueraded as a password (source-audited: Session forwards
    its username verbatim to spnego.client, whose typed signature
    includes NTLMHash).
    """
    try:
        from smbprotocol.connection import Connection
        from smbprotocol.exceptions import (
            SMBAuthenticationError,
            SMBException,
        )
        from smbprotocol.session import Session
    except ImportError as exc:
        raise SmbBackendUnavailable(
            "the SMB backend is unavailable: install the optional 'smb' extra "
            "(pip install 'pivotcheck[smb]')"
        ) from exc

    if credential.credential_type is CredentialType.NTLM_HASH:
        backend_username: object = _ntlm_hash_credential(credential)
        backend_password: str | None = None
    else:
        backend_username = credential.username
        backend_password = credential.secret

    import uuid

    connection = Connection(uuid.uuid4(), target, port=port)
    session = None
    try:
        connection.connect(timeout=int(timeout))
        session = Session(
            connection,
            username=backend_username,
            password=backend_password,
            require_encryption=True,
            auth_protocol="ntlm",
        )
        session.connect()
        return (_BackendOutcome.AUTH, "")
    except SMBAuthenticationError as exc:
        return (
            _BackendOutcome.AUTH_FAILED,
            _normalize_detail(exc, credential.secret),
        )
    except SMBException as exc:
        lowered = str(exc).lower()
        if "timeout" in lowered:
            return (_BackendOutcome.TIMEOUT, _normalize_detail(exc, credential.secret))
        return (_BackendOutcome.TRANSPORT, _normalize_detail(exc, credential.secret))
    except OSError as exc:
        detail = _normalize_detail(exc, credential.secret)
        lowered = detail.lower()
        if "timed out" in lowered:
            return (_BackendOutcome.TIMEOUT, detail)
        if _first(lowered, _DNS_MARKERS):
            return (_BackendOutcome.DNS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    finally:
        if session is not None:
            try:
                session.disconnect()  # prove-of-auth session is torn down immediately
            except Exception as cleanup_exc:  # noqa: BLE001 - cleanup is best-effort
                LOG.debug("smb session cleanup failed: %s", cleanup_exc)
        try:
            connection.disconnect()
        except Exception as cleanup_exc:  # noqa: BLE001 - cleanup is best-effort
            LOG.debug("smb connection cleanup failed: %s", cleanup_exc)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_smb_auth(
    credential: Credential,
    target: str,
    port: int = SMB_DEFAULT_PORT,
    timeout: float = 10.0,
    backend: Callable[[str, int, Credential, float], tuple[_BackendOutcome, str]] | None = None,
) -> SMBCheckResult:
    """Run ONE SMB session-setup authentication attempt and classify it.

    Never raises for network/protocol outcomes — those are classified
    data. Raises only for structurally invalid inputs (unsupported
    credential type, invalid target/port/timeout) before any activity.

    ``backend`` is injectable for deterministic tests; production uses
    :func:`_default_backend` (smbprotocol, optional extra).
    """
    if credential.credential_type is CredentialType.PASSWORD:
        pass  # supported: NTLM session-setup auth via smbprotocol
    elif credential.credential_type is CredentialType.NTLM_HASH:
        # Supported (G-01, Stage 35): pass-the-hash via the backend's
        # documented spnego.NTLMHash primitive. One hard requirement: a
        # hash alone does not identify an account, so a username is
        # mandatory. The hash is never masqueraded as a password.
        if not credential.username:
            return _unsupported(credential, target, port, (
                "NTLM hash pass-the-hash requires a username: the hash "
                "authenticates an account, it does not identify one "
                "(supply --smb-user)"
            ))
    else:
        return _unsupported(credential, target, port, (
            f"{credential.credential_type.value} credentials are not supported "
            "by SMB validation"
        ))

    if not target or target.strip() != target or any(ch.isspace() for ch in target):
        return _invalid_target(credential, target, port, "target contains invalid characters")
    if not 1 <= port <= 65535:
        return _invalid_target(credential, target, port, f"invalid port: {port}")
    if not 0 < timeout <= 120:
        return _invalid_target(credential, target, port, f"invalid timeout: {timeout}")

    run_backend = backend or _default_backend
    start = time.perf_counter()

    try:
        outcome, raw_detail = run_backend(target, port, credential, timeout)
    except SmbBackendUnavailable as exc:
        return _finish(
            credential, target, port,
            SMBCheckStatus.LOCAL_ERROR, _normalize_detail(exc, credential.secret), start,
        )
    except Exception as exc:  # noqa: BLE001 - boundary is deliberate
        return _finish(
            credential, target, port,
            SMBCheckStatus.LOCAL_ERROR, _normalize_detail(exc, credential.secret), start,
        )
    detail: str | None = _strip_secret(raw_detail, credential.secret) if raw_detail else None
    attempts = 1

    if outcome is _BackendOutcome.AUTH:
        status = SMBCheckStatus.AUTHENTICATED
    elif outcome is _BackendOutcome.AUTH_FAILED:
        status = SMBCheckStatus.AUTH_FAILED
    elif outcome is _BackendOutcome.TIMEOUT:
        status = SMBCheckStatus.TIMEOUT
    elif outcome is _BackendOutcome.DNS:
        status = SMBCheckStatus.DNS_ERROR
    elif outcome is _BackendOutcome.PROTOCOL:
        status = SMBCheckStatus.PROTOCOL_ERROR
    elif outcome is _BackendOutcome.TRANSPORT:
        refined = _classify_detail(detail or "")
        status = refined or SMBCheckStatus.CONNECTION_FAILED
    else:
        status = SMBCheckStatus.LOCAL_ERROR

    elapsed = round((time.perf_counter() - start) * 1000, 1)
    return SMBCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        status=status,
        verdict=verdict_for(status),
        detail=detail,
        attempts=attempts,
        elapsed_ms=elapsed,
    )


def _finish(
    credential: Credential,
    target: str,
    port: int,
    status: SMBCheckStatus,
    detail: str | None,
    start: float,
) -> SMBCheckResult:
    attempts = 1 if status not in (
        SMBCheckStatus.UNSUPPORTED_CREDENTIAL,
        SMBCheckStatus.INVALID_TARGET,
        SMBCheckStatus.LOCAL_ERROR,
    ) else 0
    elapsed = round((time.perf_counter() - start) * 1000, 1) if attempts else None
    return SMBCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        status=status,
        verdict=verdict_for(status),
        detail=detail,
        attempts=attempts,
        elapsed_ms=elapsed,
    )


def _unsupported(credential: Credential, target: str, port: int, reason: str) -> SMBCheckResult:
    status = SMBCheckStatus.UNSUPPORTED_CREDENTIAL
    return SMBCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        status=status,
        verdict=verdict_for(status),
        detail=reason,
        attempts=0,
        elapsed_ms=None,
    )


def _invalid_target(credential: Credential, target: str, port: int, reason: str) -> SMBCheckResult:
    status = SMBCheckStatus.INVALID_TARGET
    return SMBCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        status=status,
        verdict=verdict_for(status),
        detail=reason,
        attempts=0,
        elapsed_ms=None,
    )
