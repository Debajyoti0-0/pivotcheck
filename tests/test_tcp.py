"""Unit tests for TCP validation and error classification (mocked sockets)."""

import errno
import socket
from unittest import mock

import pytest

from pivotcheck.checks.tcp import (
    check_tcp,
    classify_socket_error,
    validate_port,
    validate_timeout,
)
from pivotcheck.models.check import CheckStatus


class TestValidation:
    def test_valid_port(self):
        assert validate_port(445) == 445

    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_invalid_ports_rejected(self, port):
        with pytest.raises(ValueError):
            validate_port(port)

    def test_non_int_port_rejected(self):
        with pytest.raises(ValueError):
            validate_port("445")  # type: ignore[arg-type]

    def test_valid_timeout(self):
        assert validate_timeout(3) == 3.0

    @pytest.mark.parametrize("t", [0, 0.05, 31, -3])
    def test_invalid_timeouts_rejected(self, t):
        with pytest.raises(ValueError):
            validate_timeout(t)

    def test_non_ip_address_rejected_before_socket(self):
        with pytest.raises(ValueError):
            check_tcp("fileserver.internal", 445)


class TestClassifySocketError:
    def test_refused(self):
        exc = ConnectionRefusedError()
        assert classify_socket_error(exc) is CheckStatus.REFUSED

    def test_timeout(self):
        assert classify_socket_error(TimeoutError()) is CheckStatus.TIMEOUT

    def test_network_unreachable(self):
        exc = OSError(errno.ENETUNREACH, "Network is unreachable")
        assert classify_socket_error(exc) is CheckStatus.UNREACHABLE

    def test_host_unreachable(self):
        exc = OSError(errno.EHOSTUNREACH, "No route to host")
        assert classify_socket_error(exc) is CheckStatus.UNREACHABLE

    def test_generic_error_is_local_error(self):
        # deliberately NOT guessed as host-down
        exc = OSError(errno.EIO, "mystery failure")
        assert classify_socket_error(exc) is CheckStatus.LOCAL_ERROR


class TestCheckTcpMocked:
    """Socket behavior mocked so unit tests never touch the network."""

    def _patch_socket(self, side_effect=None):
        sock = mock.MagicMock()
        if side_effect is not None:
            sock.connect.side_effect = side_effect
        return mock.patch("socket.socket", return_value=sock)

    def test_success(self):
        with self._patch_socket():
            result = check_tcp("127.0.0.1", 8445, timeout_s=1.0)
        assert result.status is CheckStatus.SUCCESS
        assert result.elapsed_ms is not None
        assert result.error is None

    def test_refused(self):
        with self._patch_socket(ConnectionRefusedError()):
            result = check_tcp("127.0.0.1", 8446, timeout_s=1.0)
        assert result.status is CheckStatus.REFUSED

    def test_timeout_via_socket_timeout(self):
        with self._patch_socket(TimeoutError()):
            result = check_tcp("10.255.255.1", 8447, timeout_s=0.2)
        assert result.status is CheckStatus.TIMEOUT

    def test_timeout_via_ambiguous_oserror_message(self):
        # Windows raises OSError(WSAETIMEDOUT=10060) for connect timeouts;
        # classification must be errno-based, not message-text based.
        with self._patch_socket(OSError(10060, "A connection attempt failed "
                                                 "because the connected party "
                                                 "did not properly respond")):
            result = check_tcp("10.255.255.1", 8448, timeout_s=0.2)
        assert result.status is CheckStatus.TIMEOUT

    def test_timeout_via_posix_etimedout(self):
        # Linux can raise raw OSError(ETIMEDOUT) from connect()
        import errno as _errno

        with self._patch_socket(OSError(_errno.ETIMEDOUT, "Connection timed out")):
            result = check_tcp("10.255.255.1", 8452, timeout_s=0.2)
        assert result.status is CheckStatus.TIMEOUT

    def test_unreachable(self):
        with self._patch_socket(
            OSError(errno.ENETUNREACH, "Network is unreachable")
        ):
            result = check_tcp("192.0.2.1", 9, timeout_s=1.0)
        assert result.status is CheckStatus.UNREACHABLE

    def test_generic_local_error_preserved_with_detail(self):
        err = OSError(errno.EIO, "inexplicable")
        with self._patch_socket(err):
            result = check_tcp("127.0.0.1", 8449, timeout_s=1.0)
        assert result.status is CheckStatus.LOCAL_ERROR
        assert result.error is not None
        assert "inexplicable" in result.error

    def test_socket_closed_on_all_paths(self):
        sock = mock.MagicMock()
        sock.connect.side_effect = ConnectionRefusedError()
        with mock.patch("socket.socket", return_value=sock):
            check_tcp("127.0.0.1", 8450, timeout_s=1.0)
        sock.close.assert_called_once()

    def test_ipv6_address_uses_af_inet6(self):
        sock = mock.MagicMock()
        with mock.patch("socket.socket", return_value=sock) as factory:
            result = check_tcp("::1", 8451, timeout_s=1.0)
        args = factory.call_args[0]
        assert args[0] == socket.AF_INET6
        assert result.status is CheckStatus.SUCCESS
