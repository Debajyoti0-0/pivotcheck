"""Unit tests for neighbor and DNS discovery parsers."""

from pivotcheck.discovery.dns import parse_resolv_conf
from pivotcheck.discovery.neighbors import parse_neigh_show
from tests.fixtures.dns import (
    MALFORMED_RESOLV,
    NO_SEARCH,
    SYSTEMD_RESOLVED_STUB,
    TYPICAL_RESOLV,
)
from tests.fixtures.neighbors import EMPTY_NEIGH, TYPICAL_NEIGH


class TestParseNeighShow:
    def test_parses_all_entries(self):
        neighbors = parse_neigh_show(TYPICAL_NEIGH)
        assert len(neighbors) == 6

    def test_reachable_with_mac(self):
        n = [x for x in parse_neigh_show(TYPICAL_NEIGH) if x.ip_address == "10.10.20.1"]
        assert n[0].mac_address == "aa:bb:cc:dd:ee:01"
        assert n[0].state == "REACHABLE"
        assert n[0].interface == "eth0"

    def test_failed_entry_no_mac(self):
        n = [x for x in parse_neigh_show(TYPICAL_NEIGH) if x.state == "FAILED"]
        assert len(n) == 1
        assert n[0].mac_address is None

    def test_ipv6_neighbor(self):
        n = [x for x in parse_neigh_show(TYPICAL_NEIGH) if ":" in x.ip_address]
        assert n[0].ip_address == "fe80::1"

    def test_empty_table(self):
        assert parse_neigh_show(EMPTY_NEIGH) == ()


class TestParseResolvConf:
    def test_typical_servers_and_search(self):
        config = parse_resolv_conf(TYPICAL_RESOLV)
        assert [s.address for s in config.servers] == ["10.10.20.1", "10.10.20.53"]
        assert config.search_domains == ("corp.example.internal", "example.internal")

    def test_systemd_stub_detected(self):
        config = parse_resolv_conf(SYSTEMD_RESOLVED_STUB)
        assert config.servers[0].address == "127.0.0.53"

    def test_no_search_domains(self):
        config = parse_resolv_conf(NO_SEARCH)
        assert len(config.servers) == 2
        assert config.search_domains == ()

    def test_malformed_entries_skipped(self):
        config = parse_resolv_conf(MALFORMED_RESOLV)
        # 'not-an-ip' skipped, valid one kept, bare 'search' ignored
        assert [s.address for s in config.servers] == ["10.10.20.1"]
        assert config.search_domains == ()
