"""Unit tests for interface discovery parsers."""


from pivotcheck.discovery.interfaces import (
    parse_addr_show,
    parse_link_show,
)
from pivotcheck.models.network import InterfaceState
from tests.fixtures.addr_show import (
    DEBIAN_MULTI_IFACE,
    SECONDARY_ADDRESS,
)


class TestParseAddrShow:
    def test_parses_all_interfaces(self):
        result = parse_addr_show(DEBIAN_MULTI_IFACE)
        assert set(result) == {"lo", "eth0", "eth1", "tun0"}

    def test_ipv4_address_and_prefix(self):
        eth0 = parse_addr_show(DEBIAN_MULTI_IFACE)["eth0"]
        v4 = [a for a in eth0["ipv4"] if a.address == "10.10.20.15"]
        assert len(v4) == 1
        assert v4[0].prefix == 24

    def test_ipv6_link_local_and_global(self):
        eth0 = parse_addr_show(DEBIAN_MULTI_IFACE)["eth0"]
        v6_addrs = {a.address for a in eth0["ipv6"]}
        assert "fe80::a00:27ff:fe1a:2b3c" in v6_addrs
        assert "fd00:dead:beef::15" in v6_addrs
        assert all(a.prefix == 64 or a.prefix == 128 for a in eth0["ipv6"])

    def test_peer_tun_address(self):
        tun0 = parse_addr_show(DEBIAN_MULTI_IFACE)["tun0"]
        assert tun0["ipv4"][0].address == "10.8.0.2"
        assert tun0["ipv4"][0].prefix == 32

    def test_secondary_addresses_kept(self):
        br = parse_addr_show(SECONDARY_ADDRESS)["br-01ab2cd3ef4a"]
        assert len(br["ipv4"]) == 2

    def test_malformed_lines_skipped(self):
        result = parse_addr_show("garbage line\n2: eth0 inet 10.0.0.1/24\n")
        assert list(result) == ["eth0"]

    def test_invalid_address_skipped(self):
        result = parse_addr_show("2: eth0 inet 999.999.999.999/24\n")
        assert result == {}

    def test_empty_input(self):
        assert parse_addr_show("") == {}


class TestParseLinkShow:
    def test_up_state_and_mac(self):
        output = (
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel "
            "state UP mode DEFAULT group default qlen 1000\\    "
            "link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff\n"
        )
        links = parse_link_show(output)
        assert links["eth0"]["state"] is InterfaceState.UP
        assert links["eth0"]["mac_address"] == "aa:bb:cc:dd:ee:01"

    def test_down_state(self):
        output = (
            "3: eth1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop "
            "state DOWN mode DEFAULT group default qlen 1000\\    "
            "link/ether aa:bb:cc:dd:ee:02 brd ff:ff:ff:ff:ff:ff\n"
        )
        links = parse_link_show(output)
        assert links["eth1"]["state"] is InterfaceState.DOWN

    def test_loopback_no_mac(self):
        output = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue "
            "state UNKNOWN mode DEFAULT group default qlen 1000\n"
        )
        links = parse_link_show(output)
        # loopback with UP flag is operationally fine despite state UNKNOWN
        assert links["lo"]["state"] is InterfaceState.UP
        assert links["lo"]["mac_address"] is None

    def test_vlan_interface_name_with_at(self):
        output = (
            "5: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 "
            "state UP \\    link/ether aa:bb:cc:dd:ee:03\n"
        )
        links = parse_link_show(output)
        assert "eth0.100" in links
