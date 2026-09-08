"""Terminal and JSON rendering for HTTP service validation.

Renderers consume already-derived report objects. They never perform
discovery, requests, inference, or alter evidence.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.http_check import HTTPCheckReport

_COLOR_CODES = {
    "green": "\033[92m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "reset": "\033[0m",
}

_STATUS_COLORS = {
    "HTTP_RESPONSE": "green",
    "CONNECTION_FAILED": "red",
    "TIMEOUT": "yellow",
    "TLS_FAILED": "yellow",
    "PROTOCOL_ERROR": "yellow",
}

_STATUS_SUMMARY: dict[str, str] = {
    "HTTP_RESPONSE": "An HTTP-speaking service responded on this port.",
    "CONNECTION_FAILED": "The TCP connection failed before any HTTP request.",
    "TIMEOUT": "No response within the bound; outcome is AMBIGUOUS.",
    "TLS_FAILED": "TLS handshake failed; no HTTP request was sent.",
    "PROTOCOL_ERROR": "The endpoint responded but not with valid HTTP.",
    "DNS_ERROR": "Target name could not be resolved.",
    "LOCAL_ERROR": "Local environment failure; outcome unknown.",
}


def _status_color(status: str) -> str:
    return _COLOR_CODES.get(_STATUS_COLORS.get(status, ""), "")


def render_http_check(
    report: HTTPCheckReport,
    stream: TextIO = sys.stdout,
    color: bool = False,
) -> None:
    """Render the HTTP validation report in human-readable form."""
    result = report.results[0] if report.results else None

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_COLOR_CODES['reset']}" if color else text

    stream.write(c(_COLOR_CODES["reset"] + "\n" if color else "", ""))
    stream.write("HTTP SERVICE VALIDATION\n")
    stream.write("=" * 22 + "\n")
    if result is None:
        stream.write("No validation result was produced.\n")
        return

    status_value = result.status.value
    status_text = c(_status_color(status_value), status_value)
    stream.write(f"\nTarget:    {result.target}:{result.port}\n")
    stream.write(f"Scheme:    {result.scheme} (HEAD {result.url_path}, one request)\n")
    stream.write(f"Timeout:   {report.timeout_s}s\n")
    stream.write(f"\nResult:    {status_text}")
    if result.http_status_code is not None:
        reason = f" {result.reason}" if result.reason else ""
        stream.write(f"\nResponse:  HTTP {result.http_status_code}{reason}")
    if result.server is not None:
        stream.write(f"\nServer:    {result.server}")
    if result.content_type is not None:
        stream.write(f"\nContent:   {result.content_type}")
    if result.location is not None:
        stream.write(f"\nRedirect:  {result.location} (not followed)")
    if result.scheme == "https" and result.tls_verified is not None:
        stream.write(
            f"\nTLS:       certificate "
            f"{'VERIFIED' if result.tls_verified else 'NOT VERIFIED'}"
        )
    stream.write(f"\nVerdict:   {result.verdict.value}")
    if result.detail:
        stream.write(f"\nDetail:    {result.detail}")
    if result.elapsed_ms is not None:
        stream.write(f"\nElapsed:   {result.elapsed_ms} ms")

    stream.write("\n\nWhat this means:\n")
    summary = _STATUS_SUMMARY.get(status_value, "")
    if summary:
        stream.write(f"  - {summary}\n")
    if status_value == "HTTP_RESPONSE":
        stream.write(
            "  - An HTTP response does NOT prove authorization, authentication "
            "state, application health, content trust, or exploitability.\n"
        )

    stream.write("\nLimitations:\n")
    stream.writelines(f"  - {limitation}\n" for limitation in report.limitations)
    stream.flush()


def render_http_check_json(report: HTTPCheckReport, stream: TextIO = sys.stdout) -> None:
    """Render the report as the stable JSON envelope (no ANSI codes)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")
    stream.flush()
