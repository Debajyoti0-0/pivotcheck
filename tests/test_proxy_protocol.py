"""Protocol engine tests against a deterministic in-process fake SOCKS5 server.

No network beyond loopback; every byte the client sends is asserted.
"""

from __future__ import annotations

import socket
import struct
import threading
import time

import pytest

from pivotcheck.checks.proxy import (
    ProxyEndpoint,
    check_proxy,
    encode_connect_request,
)
from pivotcheck.models.proxy_check import ProxyStageStatus


class FakeSocks5Server:
    """Scripted SOCKS5 server on 127.0.0.1 for one connection.

    ``script`` is a list of (receive_expect_bytes | None, send_bytes | None)
    executed in order; the server closes after the script completes.
    """

    def __init__(self, script, greet_methods=(0x05, 0x00)):
        self.script = script
        self.greet_methods = greet_methods
        self.received = []
        self.sock = None
        self._srv = None
        self.port = None

    def __enter__(self):
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        srv = self._srv
        if srv is None:
            return
        try:
            srv.close()
        except OSError:
            pass

    def _serve(self):
        srv = self._srv
        if srv is None:
            return
        try:
            srv.settimeout(5)
            conn, _ = srv.accept()
            self.sock = conn
            for expect, send in self.script:
                if expect is None and send is None:
                    time.sleep(2)  # hold the connection open (timeout tests)
                    break
                if expect is not None:
                    data = conn.recv(4096)
                    self.received.append(data)
                    assert data == expect, f"expected {expect!r}, got {data!r}"
                if send is not None:
                    conn.sendall(send)
            conn.close()
        except Exception:  # noqa: BLE001 - server thread boundary; must never propagate into the test
            if self.sock:
                try:
                    self.sock.close()
                except OSError:
                    pass


def _ep(port, username=None, password=None):
    return ProxyEndpoint(host="127.0.0.1", port=port, username=username, password=password)


# ---------------------------------------------------------------- URL/ATYP

class TestConnectRequestEncoding:
    """ATYP semantics: proxy-side DNS for hostnames, literals verbatim."""

    def test_ipv4_uses_atyp_1(self):
        req = encode_connect_request("10.10.20.25", 445)
        assert req[:3] == b"\x05\x01\x00"
        assert req[3] == 0x01
        assert req[4:8] == socket.inet_aton("10.10.20.25")
        assert struct.unpack("!H", req[8:10])[0] == 445

    def test_ipv6_uses_atyp_4(self):
        req = encode_connect_request("2001:db8::1", 443)
        assert req[3] == 0x04
        assert req[4:20] == socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        assert struct.unpack("!H", req[20:22])[0] == 443

    def test_hostname_uses_atyp_3(self):
        req = encode_connect_request("example.internal", 443)
        assert req[3] == 0x03
        name = req[5 : 4 + 1 + req[4]]
        assert name == b"example.internal"
        assert req[4] == len("example.internal")
        assert struct.unpack("!H", req[-2:])[0] == 443

    def test_hostname_too_long_rejected(self):
        with pytest.raises(ValueError):
            encode_connect_request("a" * 256, 443)

    def test_hostname_not_resolved_locally(self):
        """The engine must never resolve destination hostnames locally."""
        import pivotcheck.checks.proxy as proxy_mod

        calls = []
        orig = proxy_mod.socket.getaddrinfo

        def spy(host, *a, **k):
            calls.append(host)
            return orig(host, *a, **k)

        proxy_mod.socket.getaddrinfo = spy
        try:
            req = encode_connect_request("does-not-resolve.invalid", 443)
        finally:
            proxy_mod.socket.getaddrinfo = orig
        assert req[3] == 0x03
        assert calls == []  # destination never locally resolved


# ---------------------------------------------------------------- engine

class TestProxyTcpStage:
    def test_success(self):
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05\x00"),  # greeting -> NO-AUTH selected
                (b"\x05\x01\x00\x01\x0a\x0a\x14\x19\x01\xbd", b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.verdict.value == "VALIDATED"
        assert report.stages[0].status is ProxyStageStatus.SUCCESS
        assert report.stages[1].status is ProxyStageStatus.SUCCESS
        assert report.stages[2].status is ProxyStageStatus.SUCCESS

    def test_refused(self, monkeypatch):
        """A refusal is classified REFUSED.

        The refusal is injected at the socket boundary rather than
        synthesized by connecting to a closed loopback port: whether an
        OS refuses (RST) or silently drops (timeout) a dead port is
        environment-dependent, but the classification contract is not.
        """
        import pivotcheck.checks.proxy as proxy_mod

        def refuse(self, address):
            raise ConnectionRefusedError(10061, "Connection refused")

        monkeypatch.setattr(proxy_mod.socket.socket, "connect", refuse)
        report = check_proxy(_ep(1080), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[0].status is ProxyStageStatus.REFUSED
        assert report.verdict.value == "NOT_VALIDATED"

    def test_dns_failure(self):
        report = check_proxy(
            ProxyEndpoint(host="nonexistent.invalid", port=1080),
            "10.10.20.25",
            445,
            timeout_s=2.0,
        )
        assert report.stages[0].status is ProxyStageStatus.DNS_ERROR
        assert report.verdict.value == "NOT_VALIDATED"


class TestNegotiationStage:
    def test_transport_error_after_tcp_stays_in_model(self, monkeypatch):
        """A mid-exchange connection reset must be classified, never crash.

        Regression: the engine used to attribute a raw transport error on a
        later stage a transport-only status (e.g. LOCAL_ERROR on
        destination_connect), which the model forbids — raising ValueError
        out of check_proxy. The deterministic fallback (PROXY_PROTOCOL_ERROR,
        detail preserved) keeps the result inside the frozen stage model.
        """
        import pivotcheck.checks.proxy as proxy_mod
        from pivotcheck.models.proxy_check import ProxyStageName

        with FakeSocks5Server([(b"\x05\x01\x00", b"\x05\x00")]) as srv:
            def reset(self, data):
                raise ConnectionResetError(10054, "connection reset by peer")

            monkeypatch.setattr(proxy_mod.socket.socket, "sendall", reset)
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.verdict.value == "NOT_VALIDATED"
        assert report.stages[1].stage is ProxyStageName.SOCKS_NEGOTIATION
        assert report.stages[1].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR
        assert "ConnectionResetError" in (report.stages[1].detail or "")

    def test_no_acceptable_auth_method(self):
        with FakeSocks5Server(
            [
                (b"\x05\x02\x00\x02", None),
                (None, b"\x05\xFF"),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port, "u", "p"), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[0].status is ProxyStageStatus.SUCCESS
        assert report.stages[1].status is ProxyStageStatus.NO_ACCEPTABLE_AUTH_METHOD

    def test_bad_version_in_method_reply(self):
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x04\x00"),  # wrong version
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[1].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR

    def test_truncated_method_reply(self):
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05"),  # truncated
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[1].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR

    def test_server_selects_unoffered_method(self):
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05\x02"),  # selects auth we did not offer
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[1].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR


class TestAuthStage:
    def test_auth_success(self):
        with FakeSocks5Server(
            [
                (b"\x05\x02\x00\x02", b"\x05\x02"),
                (b"\x01\x01u\x01p", b"\x01\x00"),
                (b"\x05\x01\x00\x01\x0a\x0a\x14\x19\x01\xbd", b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port, "u", "p"), "10.10.20.25", 445, timeout_s=2.0)
        assert report.verdict.value == "VALIDATED"

    def test_auth_failed(self):
        with FakeSocks5Server(
            [
                (b"\x05\x02\x00\x02", b"\x05\x02"),
                (b"\x01\x01u\x01p", b"\x01\x01"),  # RFC1929 failure
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port, "u", "p"), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[1].status is ProxyStageStatus.AUTH_FAILED

    def test_auth_bad_version(self):
        with FakeSocks5Server(
            [
                (b"\x05\x02\x00\x02", b"\x05\x02"),
                (b"\x01\x01u\x01p", b"\x02\x00"),  # wrong version
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port, "u", "p"), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[1].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR

    def test_auth_truncated(self):
        with FakeSocks5Server(
            [
                (b"\x05\x02\x00\x02", b"\x05\x02"),
                (b"\x01\x01u\x01p", b"\x01"),  # truncated
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port, "u", "p"), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[1].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR


class TestConnectStage:
    @pytest.mark.parametrize(
        "code,status",
        [
            (0x00, ProxyStageStatus.SUCCESS),
            (0x01, ProxyStageStatus.GENERAL_FAILURE),
            (0x02, ProxyStageStatus.NOT_ALLOWED_BY_RULESET),
            (0x03, ProxyStageStatus.NETWORK_UNREACHABLE),
            (0x04, ProxyStageStatus.HOST_UNREACHABLE),
            (0x05, ProxyStageStatus.CONNECTION_REFUSED),
            (0x06, ProxyStageStatus.TTL_EXPIRED),
            (0x07, ProxyStageStatus.COMMAND_NOT_SUPPORTED),
            (0x08, ProxyStageStatus.ADDRESS_TYPE_NOT_SUPPORTED),
        ],
    )
    def test_reply_mapping(self, code, status):
        reply = bytes([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05\x00"),
                (b"\x05\x01\x00\x01\x0a\x0a\x14\x19\x01\xbd", reply),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[2].status is status
        assert report.stages[2].reply_code == code
        expected_validated = code == 0x00
        assert (report.verdict.value == "VALIDATED") is expected_validated

    def test_unknown_reply_code_is_not_success(self):
        reply = bytes([0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05\x00"),
                (b"\x05\x01\x00\x01\x0a\x0a\x14\x19\x01\xbd", reply),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[2].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR
        assert report.verdict.value == "NOT_VALIDATED"

    def test_connect_reply_bad_version(self):
        reply = bytes([0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05\x00"),
                (b"\x05\x01\x00\x01\x0a\x0a\x14\x19\x01\xbd", reply),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[2].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR

    def test_connect_reply_truncated(self):
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", b"\x05\x00"),
                (b"\x05\x01\x00\x01\x0a\x0a\x14\x19\x01\xbd", b"\x05\x00\x00"),
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=2.0)
        assert report.stages[2].status is ProxyStageStatus.PROXY_PROTOCOL_ERROR


class TestTimeoutSemantics:
    def test_timeout_during_negotiation(self):
        with FakeSocks5Server(
            [
                (b"\x05\x01\x00", None),  # server receives greeting
                (None, None),  # then holds the connection silently
            ]
        ) as srv:
            report = check_proxy(_ep(srv.port), "10.10.20.25", 445, timeout_s=0.5)
        assert report.stages[0].status is ProxyStageStatus.SUCCESS
        assert report.stages[1].status is ProxyStageStatus.TIMEOUT
        assert report.verdict.value == "NOT_VALIDATED"
