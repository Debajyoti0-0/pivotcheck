"""CLI tests for proxy-check: syntax, output, exit codes, redaction."""

from __future__ import annotations

import json

import pytest

from pivotcheck import cli
from pivotcheck.cli import EXIT_OK, EXIT_RESOLVE, EXIT_USAGE, main


@pytest.fixture
def fake_engine(monkeypatch):
    """Replace the protocol engine with a controllable result factory."""

    class FakeEngine:
        def __init__(self):
            self.calls = []
            self.reports = []

        def __call__(self, endpoint, target, port, timeout_s):

            self.calls.append((endpoint, target, port, timeout_s))
            report = self.reports.pop(0)
            # Bind the CLI-supplied endpoint so redaction is exercised
            object.__setattr__(report, "proxy", endpoint)
            return report

    engine = FakeEngine()
    monkeypatch.setattr(cli, "check_proxy", engine)
    return engine


def _validated_report():
    from pivotcheck.checks.proxy import ProxyEndpoint
    from pivotcheck.models.proxy_check import (
        ProxyCheckReport,
        ProxyCheckVerdict,
        ProxyStage,
        ProxyStageName,
        ProxyStageStatus,
    )

    return ProxyCheckReport(
        proxy=ProxyEndpoint(host="127.0.0.1", port=1080),
        target="example.internal",
        port=443,
        timeout_s=3.0,
        stages=(
            ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.SUCCESS, elapsed_ms=12.5),
            ProxyStage(stage=ProxyStageName.SOCKS_NEGOTIATION, status=ProxyStageStatus.SUCCESS),
            ProxyStage(stage=ProxyStageName.DESTINATION_CONNECT, status=ProxyStageStatus.SUCCESS, reply_code=0),
        ),
        verdict=ProxyCheckVerdict.VALIDATED,
    )


def _refused_report():
    from pivotcheck.checks.proxy import ProxyEndpoint
    from pivotcheck.models.proxy_check import (
        ProxyCheckReport,
        ProxyCheckVerdict,
        ProxyStage,
        ProxyStageName,
        ProxyStageStatus,
    )

    return ProxyCheckReport(
        proxy=ProxyEndpoint(host="127.0.0.1", port=1080),
        target="example.internal",
        port=443,
        timeout_s=3.0,
        stages=(
            ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.REFUSED),
        ),
        verdict=ProxyCheckVerdict.NOT_VALIDATED,
    )


def _dns_error_report():
    from pivotcheck.checks.proxy import ProxyEndpoint
    from pivotcheck.models.proxy_check import (
        ProxyCheckReport,
        ProxyCheckVerdict,
        ProxyStage,
        ProxyStageName,
        ProxyStageStatus,
    )

    return ProxyCheckReport(
        proxy=ProxyEndpoint(host="nonexistent.invalid", port=1080),
        target="example.internal",
        port=443,
        timeout_s=3.0,
        stages=(
            ProxyStage(
                stage=ProxyStageName.PROXY_TCP,
                status=ProxyStageStatus.DNS_ERROR,
                detail="name resolution failed",
            ),
        ),
        verdict=ProxyCheckVerdict.NOT_VALIDATED,
    )


class TestProxyCheckCliSyntax:
    def test_help_works(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["proxy-check", "--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "socks5://" in out
        assert "--proxy" in out

    def test_missing_proxy_is_usage_error(self, capsys):
        # argparse-owned usage error: required argument missing
        with pytest.raises(SystemExit) as exc:
            main(["proxy-check", "target.example", "--port", "443"])
        assert exc.value.code == EXIT_USAGE

    def test_missing_target_is_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["proxy-check", "--proxy", "socks5://127.0.0.1:1080", "--port", "443"])
        assert exc.value.code == EXIT_USAGE

    def test_missing_port_is_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["proxy-check", "--proxy", "socks5://127.0.0.1:1080", "target.example"])
        assert exc.value.code == EXIT_USAGE

    def test_invalid_proxy_url_is_usage_error(self, monkeypatch, capsys):
        code = main(
            [
                "proxy-check",
                "--proxy", "socks4://127.0.0.1:1080",
                "target.example",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "socks4" in err

    def test_port_range_rejected(self, monkeypatch, capsys):
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "target.example",
                "--port", "100-200",
            ]
        )
        assert code == EXIT_USAGE

    def test_port_list_rejected(self, monkeypatch, capsys):
        """MVP contract: exactly one port. Lists are out of scope."""
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "target.example",
                "--port", "80,443",
            ]
        )
        assert code == EXIT_USAGE

    def test_cidr_target_rejected(self, monkeypatch, capsys):
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "10.10.20.0/24",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "CIDR" in err

    def test_invalid_timeout_rejected(self, monkeypatch, capsys):
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "target.example",
                "--port", "443",
                "--timeout", "31",
            ]
        )
        assert code == EXIT_USAGE

    def test_timeout_lower_bound_accepted(self, fake_engine):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "target.example",
                "--port", "443",
                "--timeout", "0.1",
            ]
        )
        assert code == EXIT_OK

    def test_invalid_target_rejected_before_engine(self, fake_engine):
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "bad hostname!",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        assert fake_engine.calls == []


class TestProxyCheckCliOutput:
    def test_validated_text_output(self, fake_engine, capsys):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "PROXY CHECK" in out
        assert "socks5://127.0.0.1:1080" in out
        assert "example.internal" in out
        assert "Stage 1" in out and "SUCCESS" in out
        assert "Verdict" in out and "VALIDATED" in out
        assert "does not prove" in out

    def test_failure_text_output(self, fake_engine, capsys):
        fake_engine.reports.append(_refused_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK  # validation data, not CLI failure
        out = capsys.readouterr().out
        assert "REFUSED" in out
        assert "NOT_VALIDATED" in out

    def test_json_output_contract(self, fake_engine, capsys):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
                "--json",
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "\033[" not in out
        data = json.loads(out)
        assert data["tool"] == "pivotcheck"
        assert data["command"] == "proxy-check"
        assert data["verdict"] == "VALIDATED"
        assert data["proxy"]["host"] == "127.0.0.1"
        assert data["proxy"]["port"] == 1080
        assert data["target"] == {"host": "example.internal", "port": 443}
        assert [s["stage"] for s in data["stages"]] == [
            "proxy_tcp",
            "socks5_negotiation",
            "destination_connect",
        ]
        assert "limitation" in data

    def test_json_failure_output(self, fake_engine, capsys):
        fake_engine.reports.append(_refused_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
                "--format", "json",
            ]
        )
        assert code == EXIT_OK
        data = json.loads(capsys.readouterr().out)
        assert data["verdict"] == "NOT_VALIDATED"
        assert data["stages"][0]["status"] == "REFUSED"

    def test_no_color_flag(self, fake_engine, capsys):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "--no-color",
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        assert "\033[" not in capsys.readouterr().out

    def test_credentials_redacted_in_text(self, fake_engine, capsys):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice:s3cr3t@127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert "s3cr3t" not in out
        assert "alice:***@" in out

    def test_credentials_redacted_in_json(self, fake_engine, capsys):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice:s3cr3t@127.0.0.1:1080",
                "example.internal",
                "--port", "443",
                "--json",
            ]
        )
        assert code == EXIT_OK
        raw = capsys.readouterr().out
        assert "s3cr3t" not in raw
        data = json.loads(raw)
        assert data["proxy"]["has_credentials"] is True

    def test_proxy_dns_error_exit_code(self, fake_engine, capsys):
        """Proxy-endpoint resolution failure mirrors `check`: exit 3."""
        fake_engine.reports.append(_dns_error_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://nonexistent.invalid:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_RESOLVE

    def test_engine_receives_parsed_arguments(self, fake_engine, capsys):
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "8443",
                "--timeout", "5",
            ]
        )
        assert code == EXIT_OK
        endpoint, target, port, timeout_s = fake_engine.calls[0]
        assert endpoint.host == "127.0.0.1"
        assert target == "example.internal"
        assert port == 8443
        assert timeout_s == 5.0


class TestProxyCheckSafety:
    def test_no_automatic_targets(self, fake_engine):
        """Engine is called exactly once with exactly the operator's input."""
        fake_engine.reports.append(_validated_report())
        main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert len(fake_engine.calls) == 1

    def test_no_local_resolution_of_destination(self, fake_engine):
        """CLI must not pre-resolve the destination hostname."""
        fake_engine.reports.append(_validated_report())
        import socket as _socket

        calls = []
        orig = _socket.getaddrinfo

        def spy(host, *a, **k):
            calls.append(host)
            return orig(host, *a, **k)

        _socket.getaddrinfo = spy
        try:
            code = main(
                [
                    "proxy-check",
                    "--proxy", "socks5://127.0.0.1:1080",
                    "example.invalid",
                    "--port", "443",
                ]
            )
        finally:
            _socket.getaddrinfo = orig
        assert code == EXIT_OK
        assert calls == []


SENTINEL_SECRET = "PIVOTCHECK_SECRET_SENTINEL_9f3c"


class TestProxyCheckSecureCredentials:
    """Security tests for --proxy-auth-env credential handling."""

    def test_env_password_works(self, fake_engine, monkeypatch):
        """Environment variable provides password; username from URL."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        endpoint, *_ = fake_engine.calls[0]
        assert endpoint.username == "alice"
        assert endpoint.password == SENTINEL_SECRET

    def test_env_password_reaches_rfc1929(self, fake_engine, monkeypatch):
        """Environment password is used in RFC 1929 authentication (engine receives it)."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://bob@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        endpoint, *_ = fake_engine.calls[0]
        assert endpoint.password == SENTINEL_SECRET

    def test_sentinel_never_in_text_output(self, fake_engine, monkeypatch, capsys):
        """Sentinel secret must not appear in text output."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        out = capsys.readouterr().out
        assert SENTINEL_SECRET not in out
        assert "alice:***@" in out

    def test_sentinel_never_in_json_output(self, fake_engine, monkeypatch, capsys):
        """Sentinel secret must not appear in JSON output."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
                "--json",
            ]
        )
        assert code == EXIT_OK
        raw = capsys.readouterr().out
        assert SENTINEL_SECRET not in raw
        data = json.loads(raw)
        assert data["proxy"]["has_credentials"] is True

    def test_sentinel_never_in_stderr(self, fake_engine, monkeypatch, capsys):
        """Sentinel secret must not appear in stderr (even on errors)."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        # Trigger an error after credential parsing (e.g., invalid target)
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "bad hostname!",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert SENTINEL_SECRET not in err

    def test_sentinel_never_in_report_to_dict(self, fake_engine, monkeypatch):
        """Sentinel secret must not appear in report.to_dict()."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        endpoint, *_ = fake_engine.calls[0]
        # The report in fake_engine has the CLI-bound endpoint
        # But we can check the endpoint directly
        assert SENTINEL_SECRET not in str(endpoint.to_dict())
        assert endpoint.to_dict()["has_credentials"] is True

    def test_inline_password_still_works(self, fake_engine, capsys):
        """Backward compatibility: inline password in URL still accepted."""
        fake_engine.reports.append(_validated_report())

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice:inlinepass@127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        endpoint, *_ = fake_engine.calls[0]
        assert endpoint.username == "alice"
        assert endpoint.password == "inlinepass"
        out = capsys.readouterr().out
        assert "inlinepass" not in out
        assert "alice:***@" in out

    def test_both_sources_rejected(self, fake_engine, monkeypatch, capsys):
        """Inline password + --proxy-auth-env must be rejected (mutual exclusion)."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice:inlinepass@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "both" in err.lower() or "mutual" in err.lower() or "conflict" in err.lower()

    def test_missing_env_var_rejected(self, fake_engine, capsys):
        """--proxy-auth-env with nonexistent variable must be rejected."""
        fake_engine.reports.append(_validated_report())

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "NONEXISTENT_VAR",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "not set" in err.lower() or "missing" in err.lower()
        assert "NONEXISTENT_VAR" in err

    def test_empty_env_var_rejected(self, fake_engine, monkeypatch, capsys):
        """--proxy-auth-env with empty value must be rejected."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("EMPTY_VAR", "")

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "EMPTY_VAR",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_USAGE
        err = capsys.readouterr().err
        assert "empty" in err.lower()
        assert "EMPTY_VAR" in err

    def test_invalid_env_var_name_rejected(self, fake_engine, capsys):
        """Invalid environment variable name must be rejected."""
        fake_engine.reports.append(_validated_report())

        for bad_name in ["123INVALID", "VAR-NAME", "VAR.NAME", "VAR=NAME", "VAR NAME", ""]:
            code = main(
                [
                    "proxy-check",
                    "--proxy", "socks5://alice@127.0.0.1:1080",
                    "--proxy-auth-env", bad_name,
                    "example.internal",
                    "--port", "443",
                ]
            )
            assert code == EXIT_USAGE, f"bad name {bad_name!r} should be rejected"

    def test_no_credentials_no_auth_offered(self, fake_engine, capsys):
        """No username in URL and no --proxy-auth-env → NO-AUTH offered."""
        fake_engine.reports.append(_validated_report())

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        endpoint, *_ = fake_engine.calls[0]
        assert endpoint.username is None
        assert endpoint.password is None

    def test_username_without_password_uses_noauth(self, fake_engine, capsys):
        """URL with username but no password (and no env) uses NO-AUTH."""
        fake_engine.reports.append(_validated_report())
        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK
        endpoint, *_ = fake_engine.calls[0]
        assert endpoint.username == "alice"
        assert endpoint.password is None
        out = capsys.readouterr().out
        assert "alice:***@" in out

    def test_one_transaction_invariant(self, fake_engine, monkeypatch):
        """Secure credential handling does not introduce retries/fallbacks."""
        fake_engine.reports.append(_validated_report())
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", SENTINEL_SECRET)

        main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert len(fake_engine.calls) == 1

    def test_auth_failed_is_data_not_fatal(self, fake_engine, monkeypatch):
        """Authentication rejection (AUTH_FAILED) remains exit 0, data in report."""
        from pivotcheck.checks.proxy import ProxyEndpoint
        from pivotcheck.models.proxy_check import (
            ProxyCheckReport,
            ProxyCheckVerdict,
            ProxyStage,
            ProxyStageName,
            ProxyStageStatus,
        )

        auth_failed_report = ProxyCheckReport(
            proxy=ProxyEndpoint(host="127.0.0.1", port=1080, username="alice", password="wrong"),
            target="example.internal",
            port=443,
            timeout_s=3.0,
            stages=(
                ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.SUCCESS, elapsed_ms=1.0),
                ProxyStage(stage=ProxyStageName.SOCKS_NEGOTIATION, status=ProxyStageStatus.AUTH_FAILED),
                ProxyStage(stage=ProxyStageName.DESTINATION_CONNECT, status=ProxyStageStatus.SUCCESS, reply_code=0),
            ),
            verdict=ProxyCheckVerdict.NOT_VALIDATED,
        )
        fake_engine.reports.append(auth_failed_report)
        monkeypatch.setenv("PIVOTCHECK_PROXY_PASSWORD", "wrong")

        code = main(
            [
                "proxy-check",
                "--proxy", "socks5://alice@127.0.0.1:1080",
                "--proxy-auth-env", "PIVOTCHECK_PROXY_PASSWORD",
                "example.internal",
                "--port", "443",
            ]
        )
        assert code == EXIT_OK  # validation data, not CLI failure
