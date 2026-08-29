"""Unit tests for target validation and DNS resolution."""

import socket
from unittest import mock

import pytest

from pivotcheck.checks.resolver import resolve_target, validate_target


class TestValidateTarget:
    def test_valid_ipv4(self):
        assert validate_target("10.10.20.25") == "10.10.20.25"

    def test_valid_ipv6(self):
        assert validate_target("::1") == "::1"
        assert validate_target("fd00::1") == "fd00::1"

    def test_valid_hostname(self):
        assert validate_target("fileserver.internal") == "fileserver.internal"

    def test_empty_rejected(self):
        with pytest.raises(ValueError):
            validate_target("")

    def test_cidr_rejected(self):
        with pytest.raises(ValueError):
            validate_target("172.16.50.0/24")

    def test_invalid_characters_rejected(self):
        with pytest.raises(ValueError):
            validate_target("bad_host!.local")

    def test_leading_hyphen_label_rejected(self):
        with pytest.raises(ValueError):
            validate_target("-bad.example.com")

    def test_overlong_label_rejected(self):
        with pytest.raises(ValueError):
            validate_target("a" * 64 + ".com")


class TestResolveTarget:
    def test_ip_literal_skips_dns(self):
        result = resolve_target("192.168.1.1")
        assert result.ok
        assert result.addresses == ("192.168.1.1",)
        assert result.error is None

    def test_dns_failure_returns_error_not_exception(self):
        with mock.patch(
            "socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name unknown")
        ):
            result = resolve_target("nonexistent.invalid")
        assert not result.ok
        assert result.error is not None
        assert "resolution failed" in result.error

    def test_multiple_addresses_preserved_in_order(self):
        infos = [
            (socket.AF_INET, None, None, "", ("172.16.50.10", 0)),
            (socket.AF_INET, None, None, "", ("172.16.50.11", 0)),
            (socket.AF_INET, None, None, "", ("172.16.50.10", 0)),  # dup
        ]
        with mock.patch("socket.getaddrinfo", return_value=infos):
            result = resolve_target("fileserver.internal")
        assert result.addresses == ("172.16.50.10", "172.16.50.11")

    def test_invalid_target_becomes_resolved_error(self):
        result = resolve_target("172.16.50.0/24")
        assert not result.ok
        assert "CIDR" in (result.error or "")
