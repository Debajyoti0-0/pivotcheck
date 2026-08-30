"""Windows and macOS collector tests (PivotCheck v2.0 Phase 2).

Pure parser tests use deterministic fixtures. Collector contract tests use
injected fake runners so no test touches a live system. Platform dispatch
is tested by monkeypatching platform.system().
"""

from __future__ import annotations

import pytest

from pivotcheck.discovery.local import LocalProvider
from pivotcheck.discovery.macos import (
    MacOSCollector,
    parse_ifconfig,
    parse_netstat_an,
    parse_netstat_rn,
    parse_scutil_dns,
)
from pivotcheck.discovery.macos import (
    parse_arp_a as parse_mac_arp,
)
from pivotcheck.discovery.windows import (
    WindowsCollector,
    parse_arp_a,
    parse_ipconfig,
    parse_netstat_ano,
    parse_route_print,
    parse_tasklist,
)
from pivotcheck.models.network import ConnectionProtocol, InterfaceState, RouteType
from tests.fixtures import macos as macfix
from tests.fixtures import windows as winfix


class _FakeRunner:
    """Deterministic command runner backed by a fixture map."""

    def __init__(self, commands: dict[tuple[str, ...], str]) -> None:
        self._commands = commands
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, args, timeout: float = 10.0):
        from pivotcheck.utils.system import CommandResult

        self.calls.append(tuple(args))
        try:
            return CommandResult(0, self._commands[tuple(args)], "")
        except KeyError:
            return CommandResult(1, "", f"unknown fixture command: {args}")


# ---------------------------------------------------------------------------
# Windows parsers
# ---------------------------------------------------------------------------


class TestWindowsIpconfig:
    def test_parses_adapters_with_addresses_and_prefixes(self):
        interfaces, _, _ = parse_ipconfig(winfix.IPCONFIG_ALL)
        by_name = {i.name: i for i in interfaces}
        assert set(by_name) == {"Ethernet", "Ethernet 2", "Wi-Fi"}

        eth = by_name["Ethernet"]
        assert eth.state is InterfaceState.UP
        assert eth.mac_address == "3c:97:0e:12:34:56"
        assert eth.ipv4_addresses[0].address == "10.10.20.15"
        assert eth.ipv4_addresses[0].prefix == 24

        wifi = by_name["Wi-Fi"]
        assert wifi.ipv4_addresses[0].address == "192.168.100.5"
        assert wifi.ipv4_addresses[0].prefix == 24
        assert wifi.mac_address == "7c:b5:9b:11:22:33"

    def test_disconnected_media_state_maps_to_down(self):
        interfaces, _, _ = parse_ipconfig(winfix.IPCONFIG_ALL)
        assert {i.state for i in interfaces if i.name == "Ethernet 2"} == {
            InterfaceState.DOWN
        }

    def test_dns_servers_collected_in_order(self):
        _, servers, _ = parse_ipconfig(winfix.IPCONFIG_ALL)
        assert [s.address for s in servers if s.address.startswith("10.10.20")] == [
            "10.10.20.1",
            "10.10.20.53",
        ]
        assert all(s.source == "ipconfig" for s in servers)

    def test_hostname_extracted(self):
        _, _, hostname = parse_ipconfig(winfix.IPCONFIG_ALL)
        assert hostname == "DESKTOP-WKS01"

    def test_null_mac_rejected(self):
        output = winfix.IPCONFIG_ALL.replace("3C-97-0E-12-34-56", "00-00-00-00-00-00")
        interfaces, _, _ = parse_ipconfig(output)
        eth = next(i for i in interfaces if i.name == "Ethernet")
        assert eth.mac_address is None


class TestWindowsRoutePrint:
    def test_default_route(self):
        routes = parse_route_print(winfix.ROUTE_PRINT)
        default = [r for r in routes if r.destination == "default"]
        assert len(default) == 1
        assert default[0].gateway == "10.10.20.254"
        assert default[0].route_type is RouteType.DEFAULT
        assert default[0].metric == 25

    def test_connected_and_static_routes(self):
        routes = parse_route_print(winfix.ROUTE_PRINT)
        lan = [r for r in routes if r.destination == "10.10.20.0/24"]
        assert len(lan) == 1
        assert lan[0].gateway is None
        assert lan[0].route_type is RouteType.CONNECTED

    def test_ipv6_routes_parsed(self):
        routes = parse_route_print(winfix.ROUTE_PRINT)
        fe80 = [r for r in routes if r.destination == "fe80::/64"]
        assert len(fe80) == 1
        assert fe80[0].gateway is None
        assert fe80[0].route_type is RouteType.CONNECTED

    def test_determinism(self):
        assert parse_route_print(winfix.ROUTE_PRINT) == parse_route_print(
            winfix.ROUTE_PRINT
        )


class TestWindowsArp:
    def test_broadcast_and_invalid_entries_excluded(self):
        neighbors = parse_arp_a(winfix.ARP_A)
        by_ip = {n.ip_address: n for n in neighbors}
        assert by_ip["10.10.20.1"].mac_address == "a4:2b:b0:aa:bb:cc"
        assert by_ip["10.10.20.25"].state == "Static"
        assert "192.168.100.255" not in by_ip  # broadcast/invalid excluded
        assert all(n.interface.startswith("if") for n in neighbors)


class TestWindowsNetstat:
    def test_tcp_connections_with_pid(self):
        connections = parse_netstat_ano(winfix.NETSTAT_ANO)
        established = [
            c
            for c in connections
            if c.state == "ESTABLISHED"
        ]
        assert len(established) == 1
        conn = established[0]
        assert conn.protocol is ConnectionProtocol.TCP
        assert conn.local_address == "10.10.20.15"
        assert conn.remote_address == "140.82.114.23"
        assert conn.remote_port == 443
        assert conn.process == "1890/"

    def test_ipv6_bracketed_addresses(self):
        connections = parse_netstat_ano(winfix.NETSTAT_ANO)
        v6 = [
            c
            for c in connections
            if c.local_address == "::" and c.protocol is ConnectionProtocol.TCP
        ]
        assert len(v6) == 1
        assert v6[0].local_port == 135

    def test_udp_listening_state(self):
        connections = parse_netstat_ano(winfix.NETSTAT_ANO)
        udp = [c for c in connections if c.protocol is ConnectionProtocol.UDP]
        assert all(c.state == "LISTEN" for c in udp)
        assert all(c.process == "4812/" for c in udp if c.local_port == 5353)

    def test_tasklist_mapping(self):
        pids = parse_tasklist(winfix.TASKLIST_CSV)
        assert pids["1890"] == "firefox.exe"
        assert pids["4"] == "System"


# ---------------------------------------------------------------------------
# macOS parsers
# ---------------------------------------------------------------------------


class TestMacIfconfig:
    def test_interfaces_states_and_addresses(self):
        interfaces = parse_ifconfig(macfix.IFCONFIG)
        by_name = {i.name: i for i in interfaces}
        assert {"lo0", "en0", "en1", "utun3"} <= set(by_name)

        en0 = by_name["en0"]
        assert en0.state is InterfaceState.UP
        assert en0.mac_address == "a4:83:e7:aa:bb:cc"
        assert en0.ipv4_addresses[0].address == "10.0.0.5"
        assert en0.ipv4_addresses[0].prefix == 24
        assert len(en0.ipv6_addresses) == 2

        en1 = by_name["en1"]
        assert en1.state is InterfaceState.DOWN

    def test_vpn_interface_address(self):
        interfaces = parse_ifconfig(macfix.IFCONFIG)
        utun = next(i for i in interfaces if i.name == "utun3")
        assert utun.ipv4_addresses[0].address == "10.8.0.2"
        assert utun.ipv4_addresses[0].prefix == 32


class TestMacRoutes:
    def test_default_route(self):
        routes = parse_netstat_rn(macfix.NETSTAT_RN)
        defaults = [r for r in routes if r.destination == "default"]
        assert len(defaults) == 2  # one v4, one v6
        v4_default = next(r for r in defaults if r.gateway == "10.0.0.1")
        assert v4_default.route_type is RouteType.DEFAULT
        assert v4_default.interface == "en0"

    def test_connected_route_via_link(self):
        routes = parse_netstat_rn(macfix.NETSTAT_RN)
        lan = [r for r in routes if r.destination == "10.0.0.0/24"]
        assert len(lan) == 1
        assert lan[0].gateway is None
        assert lan[0].route_type is RouteType.CONNECTED

    def test_bsd_truncated_destination_expanded(self):
        routes = parse_netstat_rn(macfix.NETSTAT_RN)
        assert any(r.destination == "10.0.0.0/24" for r in routes)

    def test_loopback_network_route(self):
        routes = parse_netstat_rn(macfix.NETSTAT_RN)
        # BSD netstat prints the loopback network as '127' (== 127.0.0.0/8);
        # the table lists 127.0.0.1 as its gateway, so it is classified STATIC.
        loop = [r for r in routes if r.destination == "127.0.0.0/8"]
        assert len(loop) == 1
        assert loop[0].gateway == "127.0.0.1"
        assert loop[0].route_type is RouteType.STATIC


class TestMacArp:
    def test_entries_and_incomplete(self):
        neighbors = parse_mac_arp(macfix.ARP_A)
        by_ip = {n.ip_address: n for n in neighbors}
        assert by_ip["10.0.0.1"].mac_address == "a4:2b:b0:01:02:03"  # zero-padded
        assert by_ip["10.0.0.25"].mac_address == "00:1b:44:11:3a:b7"
        assert by_ip["10.0.0.99"].mac_address is None
        assert by_ip["10.0.0.99"].state == "INCOMPLETE"
        assert by_ip["10.0.0.5"].state == "Permanent"
        # utun peer lines carry an address, not a MAC: excluded
        assert "10.8.0.1" not in by_ip
        assert len(neighbors) == 4


class TestMacScutilDns:
    def test_servers_deduplicated_with_search_domains(self):
        config = parse_scutil_dns(macfix.SCUTIL_DNS)
        addresses = [s.address for s in config.servers]
        assert addresses.count("10.0.0.1") == 1
        assert "10.0.0.53" in addresses
        assert "lan" in config.search_domains


class TestMacNetstatAn:
    def test_tcp_and_udp_parsing(self):
        connections = parse_netstat_an(macfix.NETSTAT_AN)
        tcp_listen = [
            c for c in connections if c.state == "LISTEN" and c.protocol is ConnectionProtocol.TCP
        ]
        assert any(c.local_port == 22 and c.local_address == "0.0.0.0" for c in tcp_listen)
        established = [c for c in connections if c.state == "ESTABLISHED"]
        assert len(established) == 2
        udp = [c for c in connections if c.protocol is ConnectionProtocol.UDP]
        assert all(c.state is None for c in udp)
        assert all(c.process is None for c in connections)  # macOS: no PIDs


# ---------------------------------------------------------------------------
# Collector contract tests (fake runners, zero live I/O)
# ---------------------------------------------------------------------------


class TestWindowsCollectorContract:
    def _collector(self) -> WindowsCollector:
        runner = _FakeRunner(
            {
                ("ipconfig", "/all"): winfix.IPCONFIG_ALL,
                ("route", "print"): winfix.ROUTE_PRINT,
                ("arp", "-a"): winfix.ARP_A,
                ("netstat", "-ano"): winfix.NETSTAT_ANO,
                ("tasklist", "/fo", "csv", "/nh"): winfix.TASKLIST_CSV,
            }
        )
        return WindowsCollector(runner=runner)

    def test_all_layers_produce_normalized_evidence(self):
        collector = self._collector()
        interfaces = collector.collect_interfaces()
        routes = collector.collect_routes()
        neighbors = collector.collect_neighbors()
        dns = collector.collect_dns()
        connections = collector.collect_connections()
        assert len(interfaces) == 3
        assert len(routes) > 5
        assert len(neighbors) == 4
        assert len(dns.servers) >= 3
        assert len(connections) == 7
        # Process correlation: PID 1890 -> firefox.exe
        established = next(c for c in connections if c.state == "ESTABLISHED")
        assert established.process == "1890/firefox.exe"

    def test_command_failure_raises_for_provider_warning_wrapper(self):
        # The collector raises on total command failure; LocalProvider wraps
        # that into a DiscoveryWarning so discovery never aborts.
        from pivotcheck.utils.system import CommandResult

        collector = WindowsCollector(
            runner=lambda args, timeout=10.0: CommandResult(1, "", "boom")
        )
        with pytest.raises(RuntimeError):
            collector.collect_interfaces()

    def test_no_subprocess_from_parsers(self):
        # Parsers are pure: identical input, identical output.
        assert parse_route_print(winfix.ROUTE_PRINT) == parse_route_print(
            winfix.ROUTE_PRINT
        )


class TestMacOSCollectorContract:
    def test_all_layers_produce_normalized_evidence(self):
        runner = _FakeRunner(
            {
                ("ifconfig", "-a"): macfix.IFCONFIG,
                ("netstat", "-rn"): macfix.NETSTAT_RN,
                ("arp", "-a"): macfix.ARP_A,
                ("scutil", "--dns"): macfix.SCUTIL_DNS,
                ("netstat", "-an"): macfix.NETSTAT_AN,
            }
        )
        collector = MacOSCollector(runner=runner)
        assert len(collector.collect_interfaces()) == 4
        assert len(collector.collect_routes()) >= 7
        assert len(collector.collect_neighbors()) == 4
        assert len(collector.collect_dns().servers) == 2
        assert len(collector.collect_connections()) == 6

    def test_runner_receives_argument_arrays(self):
        runner = _FakeRunner(
            {
                ("ifconfig", "-a"): macfix.IFCONFIG,
                ("netstat", "-rn"): macfix.NETSTAT_RN,
                ("arp", "-a"): macfix.ARP_A,
                ("scutil", "--dns"): macfix.SCUTIL_DNS,
                ("netstat", "-an"): macfix.NETSTAT_AN,
            }
        )
        MacOSCollector(runner=runner).collect_interfaces()
        assert all(isinstance(call, tuple) for call in runner.calls)
        assert ("ifconfig", "-a") in runner.calls  # no shell strings ever


# ---------------------------------------------------------------------------
# Platform dispatch (LocalProvider keeps its public contract)
# ---------------------------------------------------------------------------


class TestPlatformDispatch:
    def _make_stub(self, include_hostname: bool):
        from pivotcheck.models.network import DNSConfig

        class _Stub:
            def collect_interfaces(self):
                return ()

            def collect_routes(self):
                return ()

            def collect_neighbors(self):
                return ()

            def collect_dns(self):
                return DNSConfig()

            def collect_connections(self):
                return ()

        if include_hostname:
            _Stub.collect_hostname = lambda self: "WIN-STUB"
        return _Stub()

    def test_windows_dispatch(self, monkeypatch):
        stub = self._make_stub(include_hostname=True)
        monkeypatch.setattr("platform.system", lambda: "Windows")
        monkeypatch.setattr(
            "pivotcheck.discovery.local.WindowsCollector", lambda: stub
        )
        provider = LocalProvider()
        data = provider.collect()
        assert data.hostname == "WIN-STUB"
        assert data.warnings  # locale caveat warning attached

    def test_macos_dispatch(self, monkeypatch):
        stub = self._make_stub(include_hostname=False)
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        monkeypatch.setattr("pivotcheck.discovery.local.MacOSCollector", lambda: stub)
        provider = LocalProvider()
        data = provider.collect()
        assert data.hostname  # platform metadata fallback
        assert not data.hostname.startswith("WIN-STUB")
        assert data.warnings == ()

    def test_linux_path_unchanged(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        provider = LocalProvider()
        # Real Linux collectors will fail in this sandbox; the provider must
        # still return a valid, warning-carrying CollectedDiscoveryData.
        data = provider.collect()
        assert data.hostname
        assert isinstance(data.warnings, tuple)
