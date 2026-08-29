"""Terminal and JSON rendering for proxy-check validation results."""

from __future__ import annotations

import json
from typing import TextIO

from pivotcheck.models.proxy_check import (
    ProxyCheckReport,
    ProxyStage,
    ProxyStageStatus,
)
from pivotcheck.output.terminal import Theme

_WIDTH = 60

_STAGE_TITLES = {
    "proxy_tcp": "Stage 1 — Proxy TCP",
    "socks5_negotiation": "Stage 2 — SOCKS5 negotiation",
    "destination_connect": "Stage 3 — Destination CONNECT",
}

_LIMITATION = (
    "This result validates only the explicitly requested SOCKS5 CONNECT "
    "attempt from the supplied proxy to the supplied destination at the "
    "time of testing. It does not prove general network reachability, "
    "pivot capability, or arbitrary forwarding."
)


def _status_line(status: ProxyStageStatus, theme: Theme) -> str:
    if status is ProxyStageStatus.SUCCESS:
        return theme.good(status.value)
    if status in (
        ProxyStageStatus.TIMEOUT,
        ProxyStageStatus.NO_ACCEPTABLE_AUTH_METHOD,
        ProxyStageStatus.AUTH_FAILED,
    ):
        return theme.warn(status.value)
    return theme.bad(status.value)


def _render_stage(stage: ProxyStage, p, theme: Theme) -> None:
    p(f"{_STAGE_TITLES[stage.stage.value]}:")
    p(f"  {_status_line(stage.status, theme)}")
    if stage.elapsed_ms is not None:
        p(f"  Elapsed: {stage.elapsed_ms:.1f} ms")
    if stage.reply_code is not None:
        p(f"  SOCKS5 reply code: 0x{stage.reply_code:02x}")
    if stage.detail:
        p(theme.dim(f"  {stage.detail}"))
    p()


def render_proxy_check(
    report: ProxyCheckReport, stream: TextIO, color: bool = False
) -> None:
    """Render one proxy-check report to staged text."""
    theme = Theme(color)
    p = lambda s="": print(s, file=stream)

    p(theme.header("═" * _WIDTH))
    p(theme.header("PIVOTCHECK — PROXY CHECK").center(_WIDTH + 4))
    p(theme.header("═" * _WIDTH))
    p()
    p("Proxy:")
    p(f"  {report.proxy.display_url}")
    p()
    p("Target:")
    p(f"  {report.target}:{report.port}")
    p()

    for stage in report.stages:
        _render_stage(stage, p, theme)

    p("Verdict:")
    if report.verdict.value == "VALIDATED":
        p(f"  {theme.good(report.verdict.value)}")
    else:
        p(f"  {theme.bad(report.verdict.value)}")
    p()

    p(theme.section("Limitation:"))
    for line in _split_limitation(_LIMITATION):
        p(f"  {line}")


def _split_limitation(text: str) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    for word in words:
        current.append(word)
        if sum(len(w) + 1 for w in current) > 64:
            lines.append(" ".join(current[:-1]))
            current = [word]
    if current:
        lines.append(" ".join(current))
    return lines


def render_proxy_check_json(report: ProxyCheckReport, stream: TextIO) -> None:
    """Write the proxy-check report as JSON (no ANSI, stable keys)."""
    json.dump(report.to_dict(), stream, indent=2)
    stream.write("\n")
