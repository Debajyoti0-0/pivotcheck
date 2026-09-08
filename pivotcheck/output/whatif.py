"""Terminal and JSON rendering for What-If analysis (G-04).

Renderers consume already-derived report objects. They never perform
discovery, analysis, or alter evidence. Every rendered element carries
the HYPOTHETIC marker — hypothetical findings are never presented as
observations.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.whatif import WhatIfReport

_COLOR_CODES = {
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "cyan": "\033[96m",
    "reset": "\033[0m",
}

_OUTCOME_COLORS = {
    "SUPPORTED_BY_EXISTING_EVIDENCE": "green",
    "CONTRADICTED": "red",
    "ALREADY_OBSERVED": "cyan",
    "INSUFFICIENT_EXISTING_EVIDENCE": "yellow",
}


def render_what_if(
    report: WhatIfReport,
    stream: TextIO = sys.stdout,
    color: bool = False,
) -> None:
    """Render the what-if report in human-readable form."""

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_COLOR_CODES['reset']}" if color else text

    stream.write("PIVOTCHECK - WHAT-IF ANALYSIS (HYPOTHETICAL)\n")
    stream.write("=" * 44 + "\n")
    stream.write(
        f"Perspective: {report.perspective_hostname or 'unknown'}\n"
    )
    stream.write(
        "Every result below derives from ASSUMED changes. Nothing here is "
        "observed, validated, or reachable.\n"
    )

    for finding in report.findings:
        hyp = finding.hypothesis
        outcome_text = finding.outcome.value if finding.outcome else "REJECTED"
        color_name = _OUTCOME_COLORS.get(outcome_text, "")
        stream.write(f"\nHYPOTHESIS: {hyp.network} via {hyp.gateway} "
                     f"on {hyp.interface}\n")
        stream.write(
            f"  Status:  {finding.status.value}   "
            f"Outcome: {c(color_name, outcome_text)}\n"
        )
        if finding.rejection_reason:
            stream.write(f"  Reason:  {finding.rejection_reason}\n")
        if finding.predicted_classification:
            stream.write(
                f"  Predicted (HYPOTHETICAL): {finding.predicted_classification}\n"
            )
        stream.writelines(f"  [+] Supporting observed evidence: {item}\n" for item in finding.supporting)
        stream.writelines(f"  [!] CONTRADICTED by observed evidence: {item}\n" for item in finding.contradictions)
        stream.writelines(f"  [?] UNKNOWN: {item}\n" for item in finding.unknowns)

    if report.scenario_networks:
        stream.write("\nDERIVED SCENARIO (hypothetical network view)\n")
        stream.write("-" * 46 + "\n")
        stream.writelines(f"  [H] {entry.network} via {entry.gateway} on "
                f"{entry.interface} -> predicted {entry.predicted_confidence} "
                "confidence IF the assumption held\n" for entry in report.scenario_networks)
    else:
        stream.write("\nDERIVED SCENARIO: no compositional changes result "
                     "from the accepted hypotheses.\n")

    stream.write("\nLimitations:\n")
    stream.writelines(f"  - {limitation}\n" for limitation in report.limitations)
    stream.flush()


def render_what_if_json(report: WhatIfReport, stream: TextIO = sys.stdout) -> None:
    """Render the report as the stable JSON envelope (no ANSI codes)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")
    stream.flush()
