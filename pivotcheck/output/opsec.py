"""Terminal and JSON rendering for OPSEC intelligence.

Renderers consume already-derived result objects. They never perform
analysis, observation, or I/O.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.opsec import OpsecResult

_COLOR_CODES = {
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "reset": "\033[0m",
}

_LIKELIHOOD_COLORS = {
    "documented": "green",
    "likely": "yellow",
    "possible": "yellow",
    "environment_dependent": "yellow",
    "not_expected": "",
    "unknown": "yellow",
}


def _likelihood_color(likelihood: str) -> str:
    return _COLOR_CODES.get(_LIKELIHOOD_COLORS.get(likelihood, ""), "")


def render_opsec(
    result: OpsecResult,
    stream: TextIO = sys.stdout,
    color: bool = False,
) -> None:
    """Render the OPSEC result in human-readable form."""
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_COLOR_CODES['reset']}" if color else text

    stream.write("OPSEC OBSERVABILITY ANALYSIS\n")
    stream.write("=" * 28 + "\n")
    stream.write(f"\nAction:   {result.action.value}\n")
    stream.write(f"Platform: {result.platform.value}\n")
    stream.write(f"\nRationale: {result.rationale}\n")

    if not result.observations:
        stream.write(
            "\nNo OPSEC knowledge is documented for this action/platform "
            "combination; PivotCheck does not guess.\n"
        )

    for observation in result.observations:
        likelihood_text = c(
            _likelihood_color(observation.likelihood.value),
            observation.likelihood.value.upper(),
        )
        stream.write(f"\n[{likelihood_text}] {observation.category.value}\n")
        stream.write(f"  {observation.description}\n")
        if observation.event_ids:
            stream.write(f"  Event IDs (environment-dependent): {', '.join(observation.event_ids)}\n")
        if observation.sources:
            stream.write(f"  Sources: {', '.join(observation.sources)}\n")

    stream.write("\nLimitations:\n")
    stream.writelines(f"  - {limitation}\n" for limitation in result.limitations)
    stream.flush()


def render_opsec_json(result: OpsecResult, stream: TextIO = sys.stdout) -> None:
    """Render the result as the stable JSON envelope (no ANSI codes)."""
    payload = {
        "schema_version": "1.0",
        "tool": "pivotcheck",
        "command": "opsec",
        "result": result.to_dict(),
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")
    stream.flush()
