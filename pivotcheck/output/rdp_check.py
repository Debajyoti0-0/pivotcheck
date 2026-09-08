"""Terminal and JSON rendering for RDP pre-authentication observation.

Renderers consume already-derived report objects. They never perform
discovery, validation, or alter evidence. Every rendered element carries
the honest epistemic state of its input — an RDP observation is never
presented as authentication, access, or compromise.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.rdp_check import RDPCheckReport

_COLOR_CODES = {
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "reset": "\033[0m",
}

_STATUS_COLORS = {
    "RDP_RESPONSE_OBSERVED": "green",
    "NEGOTIATION_ERROR": "yellow",
    "NOT_RDP_RESPONSE": "yellow",
    "MALFORMED_RESPONSE": "yellow",
    "TRUNCATED_RESPONSE": "yellow",
    "CONNECTION_FAILED": "red",
    "TIMEOUT": "yellow",
}

_STATUS_SUMMARY: dict[str, str] = {
    "RDP_RESPONSE_OBSERVED": (
        "An RDP-speaking service responded with a valid X.224 Connection "
        "Confirm on this port."
    ),
    "NEGOTIATION_ERROR": (
        "The service explicitly rejected the connection request."
    ),
    "NOT_RDP_RESPONSE": (
        "The endpoint answered, but the response is not RDP traffic."
    ),
    "MALFORMED_RESPONSE": (
        "The response claimed RDP framing but was structurally invalid."
    ),
    "TRUNCATED_RESPONSE": (
        "The response ended before the declared structure was complete."
    ),
    "CONNECTION_FAILED": (
        "The TCP connection failed before any RDP exchange."
    ),
    "TIMEOUT": (
        "No response within the bound; the outcome is AMBIGUOUS."
    ),
}


def _status_color(status: str) -> str:
    color = _STATUS_COLORS.get(status)
    return _COLOR_CODES.get(color, "") if color else ""


def render_rdp_check(
    report: RDPCheckReport,
    stream: TextIO = sys.stdout,
    color: bool = False,
) -> None:
    """Render the RDP observation report in human-readable form."""
    result = report.results[0] if report.results else None

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_COLOR_CODES['reset']}" if color else text

    stream.write("RDP PRE-AUTHENTICATION OBSERVATION\n")
    stream.write("=" * 34 + "\n")
    if result is None:
        stream.write("No observation result was produced.\n")
        return

    status_value = result.status.value
    stream.write(f"\nTarget:   {result.target}:{result.port}\n")
    stream.write(f"Timeout:  {report.timeout_s}s\n")
    stream.write(
        f"\nResult:   {c(_status_color(status_value), status_value)}"
    )
    if result.negotiated_protocol is not None:
        stream.write(
            f"\nProtocol: {result.negotiated_protocol} "
            "(server-selected in this exchange)"
        )
    stream.write(f"\nVerdict:  {result.verdict.value}")
    if result.detail:
        stream.write(f"\nDetail:   {result.detail}")
    if result.elapsed_ms is not None:
        stream.write(f"\nElapsed:  {result.elapsed_ms} ms")

    stream.write("\n\nWhat this means:\n")
    summary = _STATUS_SUMMARY.get(status_value)
    if summary:
        stream.write(f"  - {summary}\n")
    if status_value == "RDP_RESPONSE_OBSERVED":
        stream.write(
            "  - This is a pre-authentication protocol observation. It does "
            "NOT prove authentication, authorization, desktop access, "
            "session establishment, command execution, or compromise.\n"
        )

    stream.write("\nLimitations:\n")
    stream.writelines(f"  - {item}\n" for item in report.limitations)
    stream.flush()


def render_rdp_check_json(report: RDPCheckReport, stream: TextIO = sys.stdout) -> None:
    """Render the report as the stable JSON envelope (no ANSI codes)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")
    stream.flush()
