"""Terminal and JSON rendering for evidence gap analysis."""

from __future__ import annotations

import json
from typing import TextIO

from pivotcheck.analysis.evidence_gaps import EvidenceStatus, GapsReport
from pivotcheck.output.terminal import Theme


def render_gaps(report: GapsReport, stream: TextIO, color: bool = False) -> None:
    """Render gaps report as text."""
    theme = Theme(color)
    p = lambda s="": print(s, file=stream)

    p(theme.header("=" * 60))
    p(theme.header("PIVOTCHECK — EVIDENCE GAP ANALYSIS").center(64))
    p(theme.header("=" * 60))
    p()
    p(f"Network: {report.network}")
    p()

    # Status order for display
    status_order = [
        EvidenceStatus.OBSERVED,
        EvidenceStatus.NEGATIVE_EVIDENCE,
        EvidenceStatus.NOT_OBSERVED,
        EvidenceStatus.NOT_COLLECTED,
        EvidenceStatus.NOT_PERFORMED,
        EvidenceStatus.NOT_APPLICABLE,
    ]

    for status in status_order:
        matching = [g for g in report.gaps if g.status == status]
        if not matching:
            continue

        if status == EvidenceStatus.OBSERVED:
            label = theme.good("OBSERVED")
        elif status == EvidenceStatus.NEGATIVE_EVIDENCE:
            label = theme.bad("NEGATIVE_EVIDENCE")
        elif status == EvidenceStatus.NOT_OBSERVED:
            label = theme.warn("NOT_OBSERVED")
        elif status == EvidenceStatus.NOT_COLLECTED:
            label = theme.warn("NOT_COLLECTED")
        elif status == EvidenceStatus.NOT_PERFORMED:
            label = theme.dim("NOT_PERFORMED")
        else:
            label = theme.dim("NOT_APPLICABLE")

        for gap in matching:
            p(f"{gap.evidence_type.upper()}:")
            p(f"  {label}")
            p(f"  {gap.details}")
            if gap.supporting_data:
                for key, value in gap.supporting_data.items():
                    p(f"    {key}: {value}")
            p()

    p(theme.section("Limitation:"))
    p("  Passive evidence only. Active validation required to confirm reachability.")
    p("  NOT_OBSERVED ≠ NOT_COLLECTED ≠ NEGATIVE_EVIDENCE ≠ NOT_APPLICABLE")


def render_gaps_json(report: GapsReport, stream: TextIO) -> None:
    """Write the gaps report as JSON (no ANSI, stable keys)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")