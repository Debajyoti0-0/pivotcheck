"""Terminal and JSON rendering for WinRM authentication validation.

Renderers consume already-derived report objects. They never perform
discovery, authentication, inference, or alter evidence.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.winrm_check import WinRMCheckReport

_COLOR_CODES = {
    "green": "\033[92m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "reset": "\033[0m",
}

_STATUS_COLORS = {
    "AUTHENTICATED": "green",
    "AUTH_FAILED": "red",
    "TIMEOUT": "yellow",
    "TLS_FAILED": "yellow",
}

_STATUS_SUMMARY: dict[str, str] = {
    "AUTHENTICATED": "Credential accepted by the WinRM service (WS-Man authentication completed).",
    "AUTH_FAILED": "Credential rejected by the WinRM service.",
    "TIMEOUT": "No response within the bound; outcome is AMBIGUOUS.",
    "CONNECTION_FAILED": "Network path/transport failed before authentication.",
    "DNS_ERROR": "Target name could not be resolved.",
    "INVALID_TARGET": "Target failed validation before any network activity.",
    "TLS_FAILED": "HTTPS certificate/TLS verification failed; authentication not reached.",
    "INVALID_CREDENTIAL": "Credential material was unusable before authentication.",
    "UNSUPPORTED_CREDENTIAL": "Credential type not supported by the current WinRM backend.",
    "PROTOCOL_ERROR": "WS-Man protocol failure.",
    "LOCAL_ERROR": "Local backend/environment failure; outcome unknown.",
}


def _status_color(status: str) -> str:
    return _COLOR_CODES.get(_STATUS_COLORS.get(status, ""), "")


def render_winrm_check(
    report: WinRMCheckReport,
    stream: TextIO = sys.stdout,
    color: bool = False,
) -> None:
    """Render the WinRM validation report in human-readable form."""
    result = report.results[0] if report.results else None

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_COLOR_CODES['reset']}" if color else text

    stream.write("WINRM AUTHENTICATION VALIDATION\n")
    stream.write("=" * 31 + "\n")
    if result is None:
        stream.write("No validation result was produced.\n")
        return

    status_value = result.status.value
    status_text = c(_status_color(status_value), status_value)
    stream.write(f"\nTarget:    {result.target}:{result.port}\n")
    stream.write(f"Username:  {result.username}\n")
    stream.write("Protocol:  winrm (NTLM WS-Man request, one attempt)\n")
    stream.write(f"Transport: {result.transport_scheme}\n")
    stream.write(f"Timeout:   {report.timeout_s}s\n")
    stream.write(f"\nResult:    {status_text}")
    stream.write(f"\nVerdict:   {result.verdict.value}")
    if result.detail:
        stream.write(f"\nDetail:    {result.detail}")
    if result.elapsed_ms is not None:
        stream.write(f"\nElapsed:   {result.elapsed_ms} ms")

    stream.write("\n\nWhat this means:\n")
    summary = _STATUS_SUMMARY.get(status_value, "")
    if summary:
        stream.write(f"  - {summary}\n")
    if status_value == "AUTHENTICATED":
        stream.write(
            "  - Authentication success does NOT prove PowerShell access, command "
            "execution, filesystem access, service creation, privilege level, "
            "or pivot capability.\n"
        )
    if result.detail:
        stream.write(f"  - Detail: {result.detail}\n")

    stream.write("\nLimitations:\n")
    stream.writelines(f"  - {limitation}\n" for limitation in report.limitations)
    stream.flush()


def render_winrm_check_json(report: WinRMCheckReport, stream: TextIO = sys.stdout) -> None:
    """Render the report as the stable JSON envelope (no ANSI codes)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")
    stream.flush()
