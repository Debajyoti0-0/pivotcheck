"""Regression tests: text output must survive encoding-constrained streams.

Historical defect: renderers use box-drawing characters and em dashes; under
cp1252 file redirection ``print`` raised UnicodeEncodeError (exit 1) even for
successful commands. The fix is one centralized encoding boundary in
``cli.main``; these tests exercise the REAL command/output paths, not just
the helper.
"""

from __future__ import annotations

import io
import json
import sys

from pivotcheck import cli
from pivotcheck.checks.proxy import ProxyEndpoint
from pivotcheck.models.proxy_check import (
    ProxyCheckReport,
    ProxyCheckVerdict,
    ProxyStage,
    ProxyStageName,
    ProxyStageStatus,
)


def _cp1252_stream() -> io.TextIOWrapper:
    """A real text stream whose encoding cannot represent the box char."""
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")


def _utf8_stream() -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="")


def _get_stream_bytes(stream: io.TextIOWrapper) -> bytes:
    """Extract bytes from a TextIOWrapper's underlying buffer."""
    return stream.buffer.getvalue()  # type: ignore[attr-defined]


def _validated_report() -> ProxyCheckReport:
    return ProxyCheckReport(
        proxy=ProxyEndpoint(host="127.0.0.1", port=1080),
        target="example.internal",
        port=443,
        timeout_s=3.0,
        stages=(
            ProxyStage(
                stage=ProxyStageName.PROXY_TCP,
                status=ProxyStageStatus.SUCCESS,
                elapsed_ms=1.0,
            ),
            ProxyStage(stage=ProxyStageName.SOCKS_NEGOTIATION, status=ProxyStageStatus.SUCCESS),
            ProxyStage(
                stage=ProxyStageName.DESTINATION_CONNECT,
                status=ProxyStageStatus.SUCCESS,
                reply_code=0,
            ),
        ),
        verdict=ProxyCheckVerdict.VALIDATED,
    )


def _run_proxy_check_text(monkeypatch, stream) -> int:
    """Run the real proxy-check command path with stdout pointed at stream."""

    def fake_engine(endpoint, target, port, timeout_s):
        return _validated_report()

    monkeypatch.setattr(cli, "check_proxy", fake_engine)
    monkeypatch.setattr(sys, "stdout", stream)
    return cli.main(
        [
            "proxy-check",
            "--proxy",
            "socks5://127.0.0.1:1080",
            "example.internal",
            "--port",
            "443",
        ]
    )


class TestEncodingConstrainedTextOutput:
    """The real command paths must not raise UnicodeEncodeError (exit 1)."""

    def test_proxy_check_text_survives_cp1252(self, monkeypatch):
        stream = _cp1252_stream()
        code = _run_proxy_check_text(monkeypatch, stream)
        stream.flush()
        text = _get_stream_bytes(stream).decode("cp1252")
        assert code == cli.EXIT_OK
        assert "PIVOTCHECK" in text
        assert "VALIDATED" in text
        # Decoration characters are deterministically escaped, never dropped
        assert "\\u2550" in text
        assert "\u2550" not in text

    def test_check_text_survives_cp1252(self, monkeypatch):
        from pivotcheck.models.check import CheckResult, CheckStatus
        from pivotcheck.models.result import DiscoverySnapshot

        monkeypatch.setattr(
            cli,
            "run_discovery",
            lambda: DiscoverySnapshot(hostname="", os_name="", networks=()),
        )

        # Deterministic TIMEOUT result: an encoding test must not depend on
        # live network behavior. Whether a closed loopback port REFUSES
        # (POSIX) or DROPS (Windows firewall) is environment-dependent, so
        # the transport boundary is mocked and the intended outcome is
        # constructed explicitly. Zero real network calls.
        def fake_check_tcp(address, port, timeout_s, target=None):
            return CheckResult(
                target=target or address,
                address=address,
                port=port,
                status=CheckStatus.TIMEOUT,
            )

        monkeypatch.setattr(cli, "check_tcp", fake_check_tcp)
        stream = _cp1252_stream()
        monkeypatch.setattr(sys, "stdout", stream)
        code = cli.main(["check", "127.0.0.1", "--port", "1", "--timeout", "0.1"])
        stream.flush()
        text = _get_stream_bytes(stream).decode("cp1252")
        assert code == cli.EXIT_OK
        assert "REACHABILITY" in text  # real check header (doc example says TCP CHECK)
        assert "TIMEOUT" in text
        assert "\\u2550" in text
        assert "\u2550" not in text


class TestUtf8Unchanged:
    def test_utf8_output_byte_identical_to_unwrapped_rendering(self, monkeypatch):
        """UTF-8-capable streams must be bit-for-bit unchanged by the fix."""
        stream = _utf8_stream()
        code = _run_proxy_check_text(monkeypatch, stream)
        stream.flush()
        wrapped_bytes = _get_stream_bytes(stream)
        assert code == cli.EXIT_OK

        # Same report rendered directly (no CLI boundary) must match exactly.
        direct = io.StringIO()
        from pivotcheck.output.proxy_check import render_proxy_check

        render_proxy_check(_validated_report(), direct, color=False)
        assert wrapped_bytes == direct.getvalue().encode("utf-8")
        assert "\u2550" in wrapped_bytes.decode("utf-8")
        assert "\\u2550" not in wrapped_bytes.decode("utf-8")


class TestJsonUnaffected:
    def test_proxy_check_json_through_cp1252_stream(self, monkeypatch):
        """JSON is ASCII-safe and must pass through the boundary untouched."""
        stream = _cp1252_stream()

        def fake_engine(endpoint, target, port, timeout_s):
            return _validated_report()

        monkeypatch.setattr(cli, "check_proxy", fake_engine)
        monkeypatch.setattr(sys, "stdout", stream)
        code = cli.main(
            [
                "proxy-check",
                "--proxy",
                "socks5://127.0.0.1:1080",
                "example.internal",
                "--port",
                "443",
                "--json",
            ]
        )
        stream.flush()
        raw = _get_stream_bytes(stream).decode("cp1252")
        assert code == cli.EXIT_OK
        assert "\x1b[" not in raw
        assert "\\u2550" not in raw  # no decoration ever enters the JSON path
        data = json.loads(raw)
        assert data["verdict"] == "VALIDATED"
        assert data["command"] == "proxy-check"
        assert [s["stage"] for s in data["stages"]] == [
            "proxy_tcp",
            "socks5_negotiation",
            "destination_connect",
        ]


class TestBoundarySelection:
    """The boundary must engage only where it is needed."""

    def test_stream_without_encoding_returned_unchanged(self):
        from pivotcheck.output.writer import text_stream

        s = io.StringIO()
        assert text_stream(s) is s

    def test_utf8_stream_returned_unchanged(self):
        from pivotcheck.output.writer import text_stream

        w = _utf8_stream()
        assert text_stream(w) is w

    def test_cp1252_stream_is_wrapped(self):
        from pivotcheck.output.writer import text_stream

        w = _cp1252_stream()
        assert text_stream(w) is not w

