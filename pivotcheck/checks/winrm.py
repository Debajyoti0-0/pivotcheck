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
- NTLM hash support: requests-ntlm (the underlying auth handler) accepts
  password material only through pywinrm's public surface. Hash
  pass-the-hash is therefore NOT supported and an NTLM_HASH credential
  is classified UNSUPPORTED_CREDENTIAL rather than faked.

Hard boundary (structural):

- ONE target, ONE port, ONE credential, ONE WS-Man request. No loops, no
  retries, no credential/protocol fallback, no scanning, no shells, no
  commands.
- Credential material never appears in any surfaced detail: third-party
  exception strings are normalized and the secret value is stripped
  defensively.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

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
        from winrm.exceptions import (  # type: ignore[import-not-found]
            AuthenticationError,
            InvalidCredentialsError,
            WinRMError,
            WinRMTransportError,
        )
        from winrm.transport import Transport  # type: ignore[import-not-found]
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
    :func:`_default_backend` (pywinrm, optional extra).
    """
    if credential.credential_type is CredentialType.PASSWORD:
        pass  # supported: NTLM auth via pywinrm
    elif credential.credential_type is CredentialType.NTLM_HASH:
        return _unsupported(credential, target, port, (
            "NTLM hash pass-the-hash is not supported by the current WinRM "
            "backend; supply a PASSWORD credential instead"
        ))
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
    run_backend = backend or _default_backend
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
        status=status,
        verdict=verdict_for(status),
        detail=reason,
        attempts=0,
        elapsed_ms=None,
    )
