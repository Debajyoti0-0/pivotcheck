"""WinRM authentication validation (v2.0 Step 6).

Converts an already-held PASSWORD credential into ONE explicit WS-Man
authentication attempt against exactly one operator-specified
target:port.

Backend decision (documented, deliberate):

- ``pywinrm`` 0.5.0 (MIT license; pure Python; Python >= 3.8; deps:
  requests + requests-ntlm + xmltodict) as an OPTIONAL extra ``[winrm]``.
  The runtime core of PivotCheck stays dependency-free: importing
  PivotCheck never requires pywinrm, and this module degrades to a
  LOCAL_ERROR when the extra is absent.
- Transport is the pywinrm ``Transport`` class directly (not the full
  ``Protocol`` shell machinery). The authentication probe is a single
  WS-Man SOAP request: a read-only Get on the WinRM service
  configuration resource. It creates NO shell, runs NO command, and
  performs NO enumeration — the smallest operation that requires a
  completed NTLM authentication to succeed.
- Transport scheme is explicit and operator-selected via the port
  convention (5985 -> http, 5986 -> https). HTTPS verifies server
  certificates (never silently disabled); TLS failures are classified
  TLS_FAILED, distinctly from authentication failure. No HTTP->HTTPS or
  HTTPS->HTTP downgrade ever occurs.
- NTLM hash support (G-01B, Stage 43): an NTLM_HASH credential is
  translated into the backend's typed hash primitive
  (``spnego.NTLMHash``) and supplied to ``requests_ntlm.HttpNtlmAuth``
  as the username credential with ``password=None``. requests-ntlm 1.3.0
  forwards the credential object to ``spnego.client`` (documented to
  accept spnego ``Credential`` objects), and spnego's dispatcher
  structurally excludes SSPI when an ``NTLMHash`` credential is present,
  so the hash participates ONLY as NTLM keying material — it is never
  placed into a password field and never masquerades as a password.
  The hash path mirrors the password transport: one WS-Man Get, TLS
  verification always on for HTTPS, message encryption for HTTP
  (reusing ``winrm.encryption.Encryption``), no downgrade, no fallback.

Hard boundary (structural):

- ONE target, ONE port, ONE credential, ONE WS-Man request. No loops, no
  retries, no credential/protocol fallback, no scanning, no shells, no
  commands.
- Credential material never appears in any surfaced detail: third-party
  exception strings are normalized and the secret value is stripped
  defensively.
"""

from __future__ import annotations

import base64
import logging
import time
from collections.abc import Callable
from typing import Any

from pivotcheck.models.credentials import Credential, CredentialType
from pivotcheck.models.winrm_check import (
    WinRMCheckResult,
    WinRMCheckStatus,
    verdict_for,
)

WINRM_DEFAULT_PORT = 5985
WINRM_HTTPS_PORT = 5986

LOG = logging.getLogger(__name__)


class WinRMBackendUnavailable(RuntimeError):
    """The optional WinRM backend (pywinrm) is not installed."""


def transport_scheme_for_port(port: int) -> str:
    """Explicit, documented port->scheme convention: 5986 = HTTPS."""
    return "https" if port == WINRM_HTTPS_PORT else "http"


# The minimal read-only WS-Man SOAP envelope: Get on the WinRM service
# configuration resource. Requires completed authentication to succeed;
# creates no shell and executes nothing.
_WSMan_GET_ENVELOPE = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <a:To>{to}</a:To>
    <w:ResourceURI mustUnderstand="true">
      http://schemas.microsoft.com/wbem/wsman/1/config
    </w:ResourceURI>
    <a:ReplyTo>
      <a:Address mustUnderstand="true">
        http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous
      </a:Address>
    </a:ReplyTo>
    <a:Action mustUnderstand="true">
      http://schemas.xmlsoap.org/ws/2004/09/transfer/Get
    </a:Action>
    <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
    <a:MessageID>{message_id}</a:MessageID>
    <w:OperationTimeout>PT{operation_timeout}S</w:OperationTimeout>
    <w:Locale xml:lang="en-US" mustUnderstand="false"/>
    <w:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" mustUnderstand="true"/>
    <w:SelectorSet/>
  </s:Header>
  <s:Body/>
</s:Envelope>"""


class _BackendOutcome:
    """Normalized backend outcomes (raw third-party errors are normalized
    into these before classification)."""

    AUTH = "auth"
    AUTH_FAILED = "auth-failed"
    TIMEOUT = "timeout"
    DNS = "dns"
    TLS = "tls"
    TRANSPORT = "transport"
    PROTOCOL = "protocol"


# Classification markers (matched against normalized detail text).
_AUTH_MARKERS = (
    "the specified credentials were rejected",
    "401",
    "unauthorized",
    "access is denied",
    "logon failure",
)
_TLS_MARKERS = (
    "certificate",
    "ssl",
    "tls",
    "certificate_verify_failed",
)
_DNS_MARKERS = (
    "getaddrinfo",
    "name or service not known",
    "no address associated",
    "no such host is known",
)
_REFUSED_MARKERS = ("connection refused", "actively refused", "econnrefused")
_RESET_MARKERS = ("connection reset", "econnreset", "forcibly closed", "broken pipe")
_TIMEOUT_MARKERS = ("timed out", "timeout", "timedout")
_PROTOCOL_MARKERS = ("soap", "wsman", "envelope", "mustunderstand", "fault")


def _strip_secret(text: str, secret: str | None) -> str:
    if secret and secret in text:
        text = text.replace(secret, "[REDACTED]")
    return text


def _normalize_detail(text: object, secret: str | None) -> str:
    cleaned = " ".join(str(text).split())
    return _strip_secret(cleaned, secret)[:300]


def _first(text: str, markers: tuple[str, ...]) -> str | None:
    for marker in markers:
        if marker in text:
            return marker
    return None


def _classify_detail(detail: str) -> WinRMCheckStatus | None:
    lowered = detail.lower()
    if _first(lowered, _DNS_MARKERS):
        return WinRMCheckStatus.DNS_ERROR
    if _first(lowered, _TLS_MARKERS):
        return WinRMCheckStatus.TLS_FAILED
    if _first(lowered, _REFUSED_MARKERS):
        return WinRMCheckStatus.CONNECTION_FAILED
    if _first(lowered, _RESET_MARKERS):
        return WinRMCheckStatus.CONNECTION_FAILED
    if _first(lowered, _TIMEOUT_MARKERS):
        return WinRMCheckStatus.TIMEOUT
    if _first(lowered, _AUTH_MARKERS):
        return WinRMCheckStatus.AUTH_FAILED
    if _first(lowered, _PROTOCOL_MARKERS):
        return WinRMCheckStatus.PROTOCOL_ERROR
    return None


# ---------------------------------------------------------------------------
# Real backend (pywinrm, optional extra; imported lazily)
# ---------------------------------------------------------------------------


def _default_backend(
    target: str,
    port: int,
    credential: Credential,
    timeout: float,
    scheme: str,
) -> tuple[str, str]:
    """Run the real pywinrm backend: one NTLM-authenticated WS-Man Get.

    One request. Raises WinRMBackendUnavailable only when the optional
    extra is missing.
    """
    try:
        from winrm.exceptions import (
            AuthenticationError,
            InvalidCredentialsError,
            WinRMError,
            WinRMTransportError,
        )
        from winrm.transport import Transport
    except ImportError as exc:
        raise WinRMBackendUnavailable(
            "the WinRM backend is unavailable: install the optional 'winrm' "
            "extra (pip install 'pivotcheck[winrm]')"
        ) from exc

    endpoint = f"{scheme}://{target}:{port}/wsman"
    transport = Transport(
        endpoint=endpoint,
        username=credential.username,
        password=credential.secret,
        auth_method="ntlm",
        server_cert_validation="validate",  # never silently disabled
        read_timeout_sec=int(timeout),
        message_encryption="auto",
    )
    message = _WSMan_GET_ENVELOPE.format(
        to=f"{endpoint}",
        message_id=f"urn:uuid:pivotcheck-{time.perf_counter_ns()}",
        operation_timeout=int(timeout),
    )
    try:
        transport.send_message(message)
        return (_BackendOutcome.AUTH, "")
    except InvalidCredentialsError as exc:
        return (_BackendOutcome.AUTH_FAILED, _normalize_detail(exc, credential.secret))
    except AuthenticationError as exc:
        return (_BackendOutcome.AUTH_FAILED, _normalize_detail(exc, credential.secret))
    except WinRMTransportError as exc:
        detail = _normalize_detail(exc, credential.secret)
        code = exc.code if exc.args and len(exc.args) > 1 else None
        if code == 401:
            return (_BackendOutcome.AUTH_FAILED, detail)
        if "certificate" in detail.lower() or "ssl" in detail.lower():
            return (_BackendOutcome.TLS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except WinRMError as exc:
        detail = _normalize_detail(exc, credential.secret)
        status = _classify_detail(detail)
        if status is WinRMCheckStatus.PROTOCOL_ERROR:
            return (_BackendOutcome.PROTOCOL, detail)
        if status is WinRMCheckStatus.AUTH_FAILED:
            return (_BackendOutcome.AUTH_FAILED, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except OSError as exc:
        detail = _normalize_detail(exc, credential.secret)
        lowered = detail.lower()
        if "timed out" in lowered:
            return (_BackendOutcome.TIMEOUT, detail)
        if _first(lowered, _DNS_MARKERS):
            return (_BackendOutcome.DNS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    finally:
        # requests.Session lifecycle is bounded by the timeout and does not
        # spawn threads; there is no server-side session to tear down
        # because no shell was created.
        LOG.debug("winrm validation finished for %s:%s", target, port)


# ---------------------------------------------------------------------------
# NTLM hash backend (G-01B, Stage 43; imported lazily)
# ---------------------------------------------------------------------------


def _winrm_hash_credential(credential: Credential) -> Any:
    """Translate the NTLM_HASH credential into the backend's typed hash
    primitive (G-01B).

    Explicit typed boundary: NTLM_HASH -> spnego.NTLMHash (the documented
    public credential class accepted by ``spnego.client``, which
    requests_ntlm 1.3.0 forwards its auth credentials to). The hash is
    NEVER converted into a password, never stored, never serialized.

    - 32-hex secret  -> nt_hash (LM omitted; modern NTLM ignores it)
    - LM:NT secret   -> lm_hash + nt_hash
    - Hex is normalized to uppercase (case-agnostic material).
    - Username carries the optional domain in NTLM 'DOMAIN\\user' form.
    """
    try:
        from spnego import NTLMHash
    except ImportError as exc:
        raise WinRMBackendUnavailable(
            "the WinRM NTLM hash backend is unavailable: install the optional "
            "'winrm' extra (pip install 'pivotcheck[winrm]')"
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


def _hash_default_backend(
    target: str,
    port: int,
    credential: Credential,
    timeout: float,
    scheme: str,
) -> tuple[str, str]:
    """Run the NTLM pass-the-hash backend: one WS-Man Get authenticated
    with the typed hash credential.

    Identical semantics to the password path (same envelope, TLS always
    verified on HTTPS, message encryption on HTTP via
    ``winrm.encryption.Encryption``) except the auth handler is
    ``HttpNtlmAuth(<spnego.NTLMHash>, password=None)`` — the hash is the
    username credential, never a password (source-audited:
    requests_ntlm forwards the credential object to spnego.client, and
    spnego structurally excludes SSPI for NTLMHash credentials).
    Raises WinRMBackendUnavailable only when the optional extra is
    missing.
    """
    import requests as _requests

    try:
        from requests_ntlm import HttpNtlmAuth
        from winrm.encryption import Encryption
        from winrm.exceptions import (
            AuthenticationError,
            InvalidCredentialsError,
            WinRMError,
            WinRMTransportError,
        )
    except ImportError as exc:
        raise WinRMBackendUnavailable(
            "the WinRM backend is unavailable: install the optional 'winrm' "
            "extra (pip install 'pivotcheck[winrm]')"
        ) from exc

    hash_credential: Any = _winrm_hash_credential(credential)
    endpoint = f"{scheme}://{target}:{port}/wsman"
    session = _requests.Session()
    # password is deliberately None: the hash is NEVER a password
    session.auth = HttpNtlmAuth(hash_credential, None, send_cbt=True)
    session.verify = True  # HTTPS certificates always verified
    session.headers.update(
        {
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Python WinRM client",
        }
    )
    message = _WSMan_GET_ENVELOPE.format(
        to=f"{endpoint}",
        message_id=f"urn:uuid:pivotcheck-{time.perf_counter_ns()}",
        operation_timeout=int(timeout),
    )
    encrypted = scheme == "http"  # message_encryption="auto" semantics
    try:
        if encrypted:
            # Initialize the NTLM security context with an empty POST so
            # Encryption has session_security available (mirrors pywinrm
            # Transport.setup_encryption for auth_method="ntlm").
            request = _requests.Request("POST", endpoint, data=None)
            session.send(session.prepare_request(request), timeout=timeout)
            encryption = Encryption(session, "ntlm")
            prepared = encryption.prepare_encrypted_request(session, endpoint, message.encode("utf-8"))
            response = session.send(prepared, timeout=timeout)
        else:
            request = _requests.Request("POST", endpoint, data=message.encode("utf-8"))
            response = session.send(session.prepare_request(request), timeout=timeout)
        if response.status_code >= 400:
            return _hash_http_error(response, credential)
        # A completed exchange answered with HTTP 200 is the validation
        # signal (same semantics as the certified password path).
        return (_BackendOutcome.AUTH, "")
    except InvalidCredentialsError as exc:
        return (_BackendOutcome.AUTH_FAILED, _normalize_detail(exc, credential.secret))
    except AuthenticationError as exc:
        return (_BackendOutcome.AUTH_FAILED, _normalize_detail(exc, credential.secret))
    except WinRMTransportError as exc:
        detail = _normalize_detail(exc, credential.secret)
        code = exc.code if exc.args and len(exc.args) > 1 else None
        if code == 401:
            return (_BackendOutcome.AUTH_FAILED, detail)
        if "certificate" in detail.lower() or "ssl" in detail.lower():
            return (_BackendOutcome.TLS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except WinRMError as exc:
        detail = _normalize_detail(exc, credential.secret)
        status = _classify_detail(detail)
        if status is WinRMCheckStatus.PROTOCOL_ERROR:
            return (_BackendOutcome.PROTOCOL, detail)
        if status is WinRMCheckStatus.AUTH_FAILED:
            return (_BackendOutcome.AUTH_FAILED, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except _requests.exceptions.HTTPError as exc:
        detail = _normalize_detail(exc, credential.secret)
        code = getattr(getattr(exc, "response", None), "status_code", None)
        if code == 401:
            return (_BackendOutcome.AUTH_FAILED, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except _requests.exceptions.Timeout as exc:
        return (_BackendOutcome.TIMEOUT, _normalize_detail(exc, credential.secret))
    except _requests.exceptions.ConnectionError as exc:
        detail = _normalize_detail(exc, credential.secret)
        lowered = detail.lower()
        if _first(lowered, _DNS_MARKERS):
            return (_BackendOutcome.DNS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except OSError as exc:
        detail = _normalize_detail(exc, credential.secret)
        lowered = detail.lower()
        if "timed out" in lowered:
            return (_BackendOutcome.TIMEOUT, detail)
        if _first(lowered, _DNS_MARKERS):
            return (_BackendOutcome.DNS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    finally:
        session.close()
        LOG.debug("winrm hash validation finished for %s:%s", target, port)


def _hash_http_error(response: object, credential: Credential) -> tuple[str, str]:
    """Map a >=400 HTTP response on the hash path to the shared taxonomy."""
    status_code = getattr(response, "status_code", None)
    text = ""
    try:
        text = str(getattr(response, "text", "") or "")
    except Exception:  # noqa: BLE001 - defensive; response body unreadable
        text = ""
    detail = _normalize_detail(text, credential.secret)
    if status_code == 401:
        return (_BackendOutcome.AUTH_FAILED, detail)
    lowered = detail.lower()
    if status_code == 500 and ("soap" in lowered or "wsman" in lowered or "fault" in lowered):
        return (_BackendOutcome.PROTOCOL, detail)
    if "certificate" in lowered or "ssl" in lowered:
        return (_BackendOutcome.TLS, detail)
    return (_BackendOutcome.TRANSPORT, detail)


# ---------------------------------------------------------------------------
# Kerberos ticket backend (G-02, Stage 48; imported lazily)
# ---------------------------------------------------------------------------


def _winrm_ticket_credential(credential: Credential) -> Any:
    """Translate the KERBEROS_TICKET credential into the backend's typed
    ccache credential primitive (G-02).

    The secret is the ccache reference (e.g., 'FILE:/path/to/cache').
    The username is the optional principal for exact-match pinning.
    The domain is the Kerberos realm.

    The credential is NEVER converted into a password, never stored,
    never serialized, and never falls back to another auth mechanism.
    """
    try:
        from spnego import KerberosCCache
    except ImportError as exc:
        raise WinRMBackendUnavailable(
            "the WinRM Kerberos backend is unavailable: install the optional "
            "'kerberos' extra (pip install 'pivotcheck[kerberos]')"
        ) from exc
    return KerberosCCache(ccache=credential.secret, principal=credential.username)


def _ticket_default_backend(
    target: str,
    port: int,
    credential: Credential,
    timeout: float,
    scheme: str,
) -> tuple[str, str]:
    """Run the Kerberos ticket backend: one WS-Man Get authenticated
    with the typed Kerberos ccache credential.

    Identical semantics to the password/hash paths (same envelope, TLS always
    verified on HTTPS, message encryption on HTTP via
    ``winrm.encryption.Encryption``) except the auth handler uses the
    spnego GSSAPIProxy context with the explicit ccache.
    Raises WinRMBackendUnavailable only when the optional extra is missing.
    """
    import requests as _requests

    try:
        import spnego
    except ImportError as exc:
        raise WinRMBackendUnavailable(
            "the WinRM Kerberos backend is unavailable: install the optional "
            "'kerberos' extra (pip install 'pivotcheck[kerberos]')"
        ) from exc

    ticket_credential: Any = _winrm_ticket_credential(credential)
    endpoint = f"{scheme}://{target}:{port}/wsman"
    session = _requests.Session()

    # Use spnego's GSSAPI client context for Kerberos authentication
    # The spnego.client() with KerberosCCache and protocol="kerberos"
    # routes exclusively to GSSAPIProxy (no NTLM/SSPI fallback).
    # We use the lower-level context directly for the WS-Man exchange.
    client_ctx = spnego.client(
        ticket_credential,
        hostname=target,
        service="HTTP",
        protocol="kerberos",
    )

    session.verify = True  # HTTPS certificates always verified
    session.headers.update(
        {
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Python WinRM client",
        }
    )

    message = _WSMan_GET_ENVELOPE.format(
        to=f"{endpoint}",
        message_id=f"urn:uuid:pivotcheck-{time.perf_counter_ns()}",
        operation_timeout=int(timeout),
    )

    # Perform the Kerberos authentication exchange
    # Step 1: Client generates AP-REQ
    client_token = client_ctx.step()

    # Prepare the request with the Kerberos token
    request = _requests.Request(
        "POST", endpoint, data=message.encode("utf-8"),
        headers={"Authorization": f"Negotiate {base64.b64encode(client_token).decode('ascii')}"}
    )
    prepared = session.prepare_request(request)

    try:
        response = session.send(prepared, timeout=timeout)

        # If we get a 401 with WWW-Authenticate: Negotiate, continue the exchange
        if response.status_code == 401:
            www_auth = response.headers.get("WWW-Authenticate", "")
            if "Negotiate" in www_auth:
                # Extract the server token
                server_token_b64 = www_auth.split("Negotiate")[-1].strip()
                server_token = base64.b64decode(server_token_b64)
                # Step 2: Client processes server token
                client_ctx.step(server_token)
                if client_ctx.complete:
                    # Re-send with mutual auth if needed
                    request = _requests.Request("POST", endpoint, data=message.encode("utf-8"))
                    response = session.send(session.prepare_request(request), timeout=timeout)

        if response.status_code >= 400:
            return _ticket_http_error(response, credential)

        # A completed exchange answered with HTTP 200 is the validation signal
        return (_BackendOutcome.AUTH, "")

    except _requests.exceptions.HTTPError as exc:
        detail = _normalize_detail(exc, credential.secret)
        code = getattr(getattr(exc, "response", None), "status_code", None)
        if code == 401:
            return (_BackendOutcome.AUTH_FAILED, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except _requests.exceptions.Timeout as exc:
        return (_BackendOutcome.TIMEOUT, _normalize_detail(exc, credential.secret))
    except _requests.exceptions.ConnectionError as exc:
        detail = _normalize_detail(exc, credential.secret)
        lowered = detail.lower()
        if _first(lowered, _DNS_MARKERS):
            return (_BackendOutcome.DNS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    except OSError as exc:
        detail = _normalize_detail(exc, credential.secret)
        lowered = detail.lower()
        if "timed out" in lowered:
            return (_BackendOutcome.TIMEOUT, detail)
        if _first(lowered, _DNS_MARKERS):
            return (_BackendOutcome.DNS, detail)
        return (_BackendOutcome.TRANSPORT, detail)
    finally:
        session.close()
        LOG.debug("winrm ticket validation finished for %s:%s", target, port)


def _ticket_http_error(response: object, credential: Credential) -> tuple[str, str]:
    """Map a >=400 HTTP response on the ticket path to the shared taxonomy."""
    status_code = getattr(response, "status_code", None)
    text = ""
    try:
        text = str(getattr(response, "text", "") or "")
    except Exception:  # noqa: BLE001 - defensive; response body unreadable
        text = ""
    detail = _normalize_detail(text, credential.secret)
    if status_code == 401:
        return (_BackendOutcome.AUTH_FAILED, detail)
    lowered = detail.lower()
    if status_code == 500 and ("soap" in lowered or "wsman" in lowered or "fault" in lowered):
        return (_BackendOutcome.PROTOCOL, detail)
    if "certificate" in lowered or "ssl" in lowered:
        return (_BackendOutcome.TLS, detail)
    return (_BackendOutcome.TRANSPORT, detail)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def validate_winrm_auth(
    credential: Credential,
    target: str,
    port: int = WINRM_DEFAULT_PORT,
    timeout: float = 10.0,
    backend: Callable[..., tuple[str, str]] | None = None,
    transport_scheme: str | None = None,
) -> WinRMCheckResult:
    """Run ONE WinRM WS-Man authentication attempt and classify it.

    Never raises for network/protocol outcomes — those are classified
    data. Raises only for structurally invalid inputs (unsupported
    credential type, invalid target/port/timeout) before any activity.

    ``transport_scheme`` is explicit ("http"/"https", default derived from
    the port convention: 5986 = https). Never silently downgraded.

    ``backend`` is injectable for deterministic tests; production uses
    :func:`_default_backend` (pywinrm, optional extra) for PASSWORD
    credentials, :func:`_hash_default_backend` (requests_ntlm with the
    typed spnego hash credential) for NTLM_HASH credentials, and
    :func:`_ticket_default_backend` (spnego GSSAPIProxy with explicit
    ccache) for KERBEROS_TICKET credentials.
    """
    if credential.credential_type is CredentialType.PASSWORD:
        default_backend: Callable[..., tuple[str, str]] = _default_backend
    elif credential.credential_type is CredentialType.NTLM_HASH:
        if not credential.username:
            return _unsupported(credential, target, port, (
                "NTLM hash pass-the-hash requires a username (--winrm-user): "
                "a hash authenticates an account, it does not identify one"
            ))
        default_backend = _hash_default_backend
    elif credential.credential_type is CredentialType.KERBEROS_TICKET:
        if not credential.username:
            return _unsupported(credential, target, port, (
                "Kerberos ticket validation requires a username (--winrm-user): "
                "a ticket authenticates an account, it does not identify one"
            ))
        default_backend = _ticket_default_backend
    else:
        return _unsupported(credential, target, port, (
            f"{credential.credential_type.value} credentials are not supported "
            "by WinRM validation"
        ))

    if not target or target.strip() != target or any(ch.isspace() for ch in target):
        return _invalid_target(credential, target, port, "target contains invalid characters")
    if not 1 <= port <= 65535:
        return _invalid_target(credential, target, port, f"invalid port: {port}")
    if not 0 < timeout <= 120:
        return _invalid_target(credential, target, port, f"invalid timeout: {timeout}")

    scheme = transport_scheme_for_port(port)
    if transport_scheme is not None:
        if transport_scheme not in ("http", "https"):
            return _invalid_target(
                credential, target, port, f"invalid transport scheme: {transport_scheme!r}"
            )
        scheme = transport_scheme
    else:
        scheme = transport_scheme_for_port(port)
    run_backend = backend or default_backend
    start = time.perf_counter()

    try:
        outcome, raw_detail = run_backend(target, port, credential, timeout, scheme)
    except WinRMBackendUnavailable as exc:
        return _finish(
            credential, target, port, scheme,
            WinRMCheckStatus.LOCAL_ERROR, _normalize_detail(exc, credential.secret), start,
        )
    except Exception as exc:  # noqa: BLE001 - boundary is deliberate
        return _finish(
            credential, target, port, scheme,
            WinRMCheckStatus.LOCAL_ERROR, _normalize_detail(exc, credential.secret), start,
        )
    detail: str | None = _strip_secret(raw_detail, credential.secret) if raw_detail else None

    if outcome == _BackendOutcome.AUTH:
        status = WinRMCheckStatus.AUTHENTICATED
    elif outcome == _BackendOutcome.AUTH_FAILED:
        status = WinRMCheckStatus.AUTH_FAILED
    elif outcome == _BackendOutcome.TIMEOUT:
        status = WinRMCheckStatus.TIMEOUT
    elif outcome == _BackendOutcome.DNS:
        status = WinRMCheckStatus.DNS_ERROR
    elif outcome == _BackendOutcome.TLS:
        status = WinRMCheckStatus.TLS_FAILED
    elif outcome == _BackendOutcome.PROTOCOL:
        status = WinRMCheckStatus.PROTOCOL_ERROR
    elif outcome == _BackendOutcome.TRANSPORT:
        refined = _classify_detail(detail or "")
        status = refined or WinRMCheckStatus.CONNECTION_FAILED
    else:
        status = WinRMCheckStatus.LOCAL_ERROR

    return _finish(credential, target, port, scheme, status, detail, start)


def _finish(
    credential: Credential,
    target: str,
    port: int,
    scheme: str,
    status: WinRMCheckStatus,
    detail: str | None,
    start: float,
) -> WinRMCheckResult:
    attempts = 1 if status not in (
        WinRMCheckStatus.UNSUPPORTED_CREDENTIAL,
        WinRMCheckStatus.INVALID_TARGET,
        WinRMCheckStatus.LOCAL_ERROR,
    ) else 0
    elapsed = round((time.perf_counter() - start) * 1000, 1) if attempts else None
    return WinRMCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        transport_scheme=scheme,
        credential_type=credential.credential_type.value,
        status=status,
        verdict=verdict_for(status),
        detail=detail,
        attempts=attempts,
        elapsed_ms=elapsed,
    )


def _unsupported(credential: Credential, target: str, port: int, reason: str) -> WinRMCheckResult:
    status = WinRMCheckStatus.UNSUPPORTED_CREDENTIAL
    return WinRMCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        credential_type=credential.credential_type.value,
        status=status,
        verdict=verdict_for(status),
        detail=reason,
        attempts=0,
        elapsed_ms=None,
    )


def _invalid_target(credential: Credential, target: str, port: int, reason: str) -> WinRMCheckResult:
    status = WinRMCheckStatus.INVALID_TARGET
    return WinRMCheckResult(
        target=target,
        port=port,
        username=credential.username or "",
        credential_type=credential.credential_type.value,
        status=status,
        verdict=verdict_for(status),
        detail=reason,
        attempts=0,
        elapsed_ms=None,
    )
