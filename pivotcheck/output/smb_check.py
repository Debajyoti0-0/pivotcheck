"""Terminal and JSON rendering for SMB authentication validation.

Renderers consume already-derived report objects. They never perform
discovery, authentication, inference, or alter evidence.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.smb_check import SMBCheckReport

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
}

_STATUS_SUMMARY: dict[str, str] = {
    "AUTHENTICATED": "Credential accepted by the SMB service (SMB2 session setup completed).",
    "AUTH_FAILED": "Credential rejected by the SMB service (guest fallback refused).",
    "TIMEOUT": "No response within the bound; outcome is AMBIGUOUS.",
    "CONNECTION_FAILED": "Network path/transport failed before authentication.",
    "DNS_ERROR": "Target name could not be resolved.",
    "INVALID_TARGET": "Target failed validation before any network activity.",
    "INVALID_CREDENTIAL": "Credential material was unusable before authentication.",
    "UNSUPPORTED_CREDENTIAL": "Credential type not supported by the current SMB backend.",
    "PROTOCOL_ERROR": "SMB negotiation/session protocol failure.",
    "LOCAL_ERROR": "Local backend/environment failure; outcome unknown.",
}


def _status_color(status: str) -> str:
    return _COLOR_CODES.get(_STATUS_COLORS.get(status, ""), "")


def render_smb_check(
    report: SMBCheckReport,
    stream: TextIO = sys.stdout,
    color: bool = False,
) -> None:
    """Render the SMB validation report in human-readable form."""
    result = report.results[0] if report.results else None

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_COLOR_CODES['reset']}" if color else text

    stream.write("SMB AUTHENTICATION VALIDATION\n")
    stream.write("=" * 29 + "\n")
    if result is None:
        stream.write("No validation result was produced.\n")
        return

    status_value = result.status.value
    status_text = c(_status_color(status_value), status_value)
    stream.write(f"\nTarget:    {result.target}:{result.port}\n")
    stream.write(f"Username:  {result.username}\n")
    stream.write("Protocol:  smb (NTLM session setup, one attempt)\n")
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
            "  - Authentication success does NOT prove share access, administrative "
            "access, file read/write, remote execution, or pivot capability.\n"
        )
    if result.detail:
        stream.write(f"  - Detail: {result.detail}\n")

    stream.write("\nLimitations:\n")
    stream.writelines(f"  - {limitation}\n" for limitation in report.limitations)
    stream.flush()


def render_smb_check_json(report: SMBCheckReport, stream: TextIO = sys.stdout) -> None:
    """Render the report as the stable JSON envelope (no ANSI codes)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")
    stream.flush()
