"""Tests for proxy-check URL parsing, models, and redaction semantics."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from pivotcheck.checks.proxy import (
    ProxyEndpoint,
    parse_proxy_url,
    redact_proxy_url,
)
from pivotcheck.models.proxy_check import (
    ProxyCheckReport,
    ProxyCheckVerdict,
    ProxyStage,
    ProxyStageName,
    ProxyStageStatus,
)


class TestParseProxyUrl:
    """URL contract: socks5://[user[:pass]@]host:port — nothing else."""

    def test_simple_no_auth(self):
        ep = parse_proxy_url("socks5://127.0.0.1:1080")
        assert ep.host == "127.0.0.1"
        assert ep.port == 1080
        assert ep.username is None
        assert ep.password is None

    def test_user_pass(self):
        ep = parse_proxy_url("socks5://alice:s3cr3t@10.0.0.5:1080")
        assert ep.host == "10.0.0.5"
        assert ep.port == 1080
        assert ep.username == "alice"
        assert ep.password == "s3cr3t"

    def test_ipv6_literal_host(self):
        ep = parse_proxy_url("socks5://[::1]:1080")
        assert ep.host == "::1"
        assert ep.port == 1080

    def test_ipv6_with_userinfo(self):
        ep = parse_proxy_url("socks5://u:p@[::1]:1080")
        assert ep.host == "::1"
        assert ep.username == "u"

    def test_username_without_password_allowed(self):
        """Username without password is allowed (for --proxy-auth-env)."""
        ep = parse_proxy_url("socks5://user@127.0.0.1:1080")
        assert ep.username == "user"
        assert ep.password is None

    def test_missing_scheme_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("127.0.0.1:1080")

    def test_wrong_scheme_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("socks4://127.0.0.1:1080")
        with pytest.raises(ValueError):
            parse_proxy_url("http://127.0.0.1:1080")
        with pytest.raises(ValueError):
            parse_proxy_url("socks5h://127.0.0.1:1080")

    def test_missing_port_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("socks5://127.0.0.1")

    def test_invalid_port_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("socks5://127.0.0.1:0")
        with pytest.raises(ValueError):
            parse_proxy_url("socks5://127.0.0.1:65536")
        with pytest.raises(ValueError):
            parse_proxy_url("socks5://127.0.0.1:notaport")

    def test_empty_host_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("socks5://:1080")

    def test_empty_input_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("")
        with pytest.raises(ValueError):
            parse_proxy_url("   ")

    def test_cidr_in_proxy_host_rejected(self):
        with pytest.raises(ValueError):
            parse_proxy_url("socks5://10.0.0.0/24:1080")


class TestProxyEndpointRedaction:
    """Credentials must never survive into any operator-facing form."""

    def test_no_auth_unchanged(self):
        assert redact_proxy_url(ProxyEndpoint(host="1.2.3.4", port=1080)) == "socks5://1.2.3.4:1080"

    def test_user_pass_redacted(self):
        ep = parse_proxy_url("socks5://alice:s3cr3t@1.2.3.4:1080")
        out = redact_proxy_url(ep)
        assert "s3cr3t" not in out
        assert out == "socks5://alice:***@1.2.3.4:1080"

    def test_endpoint_to_dict_has_no_credentials(self):
        ep = parse_proxy_url("socks5://alice:s3cr3t@1.2.3.4:1080")
        d = ep.to_dict()
        assert "password" not in json.dumps(d)
        assert d == {"scheme": "socks5", "host": "1.2.3.4", "port": 1080, "has_credentials": True}


class TestProxyStageModel:
    def test_stage_immutability(self):
        s = ProxyStage(
            stage=ProxyStageName.PROXY_TCP,
            status=ProxyStageStatus.SUCCESS,
        )
        with pytest.raises(FrozenInstanceError):
            s.status = ProxyStageStatus.REFUSED

    def test_stage_to_dict_stable_keys(self):
        d = ProxyStage(
            stage=ProxyStageName.SOCKS_NEGOTIATION,
            status=ProxyStageStatus.AUTH_FAILED,
            detail="server rejected credentials (reply 0x01)",
        ).to_dict()
        assert d["stage"] == "socks5_negotiation"
        assert d["status"] == "AUTH_FAILED"
        assert "detail" in d

    def test_report_requires_consistent_verdict(self):
        """VALIDATED verdict must be impossible with a failing stage."""
        with pytest.raises(ValueError):
            ProxyCheckReport(
                proxy=ProxyEndpoint(host="1.2.3.4", port=1080),
                target="example.internal",
                port=443,
                timeout_s=3.0,
                stages=(
                    ProxyStage(
                        stage=ProxyStageName.PROXY_TCP,
                        status=ProxyStageStatus.REFUSED,
                    ),
                ),
                verdict=ProxyCheckVerdict.VALIDATED,
            )

    def test_report_requires_all_success_for_validated(self):
        with pytest.raises(ValueError):
            ProxyCheckReport(
                proxy=ProxyEndpoint(host="1.2.3.4", port=1080),
                target="example.internal",
                port=443,
                timeout_s=3.0,
                stages=(
                    ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.SUCCESS),
                    ProxyStage(stage=ProxyStageName.SOCKS_NEGOTIATION, status=ProxyStageStatus.SUCCESS),
                    ProxyStage(stage=ProxyStageName.DESTINATION_CONNECT, status=ProxyStageStatus.CONNECTION_REFUSED),
                ),
                verdict=ProxyCheckVerdict.VALIDATED,
            )

    def test_report_rejects_validated_with_missing_stages(self):
        with pytest.raises(ValueError):
            ProxyCheckReport(
                proxy=ProxyEndpoint(host="1.2.3.4", port=1080),
                target="example.internal",
                port=443,
                timeout_s=3.0,
                stages=(ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.SUCCESS),),
                verdict=ProxyCheckVerdict.VALIDATED,
            )

    def test_report_rejects_invalidated_with_all_success_stages(self):
        """All-success stages must never carry NOT_VALIDATED."""
        with pytest.raises(ValueError):
            ProxyCheckReport(
                proxy=ProxyEndpoint(host="1.2.3.4", port=1080),
                target="example.internal",
                port=443,
                timeout_s=3.0,
                stages=(
                    ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.SUCCESS),
                    ProxyStage(stage=ProxyStageName.SOCKS_NEGOTIATION, status=ProxyStageStatus.SUCCESS),
                    ProxyStage(stage=ProxyStageName.DESTINATION_CONNECT, status=ProxyStageStatus.SUCCESS),
                ),
                verdict=ProxyCheckVerdict.NOT_VALIDATED,
            )

    def test_report_to_dict_contract(self):
        report = ProxyCheckReport(
            proxy=ProxyEndpoint(host="1.2.3.4", port=1080),
            target="example.internal",
            port=443,
            timeout_s=3.0,
            stages=(
                ProxyStage(stage=ProxyStageName.PROXY_TCP, status=ProxyStageStatus.SUCCESS, elapsed_ms=12.5),
                ProxyStage(stage=ProxyStageName.SOCKS_NEGOTIATION, status=ProxyStageStatus.SUCCESS),
                ProxyStage(
                    stage=ProxyStageName.DESTINATION_CONNECT,
                    status=ProxyStageStatus.CONNECTION_REFUSED,
                    reply_code=5,
                ),
            ),
            verdict=ProxyCheckVerdict.NOT_VALIDATED,
        )
        d = report.to_dict()
        assert d["tool"] == "pivotcheck"
        assert d["command"] == "proxy-check"
        assert d["verdict"] == "NOT_VALIDATED"
        assert d["proxy"] == {"scheme": "socks5", "host": "1.2.3.4", "port": 1080, "has_credentials": False}
        assert d["target"] == {"host": "example.internal", "port": 443}
        assert [s["stage"] for s in d["stages"]] == [
            "proxy_tcp",
            "socks5_negotiation",
            "destination_connect",
        ]
        assert d["stages"][2]["reply_code"] == 5
        assert "password" not in json.dumps(d).lower()
        assert "limitation" in d
