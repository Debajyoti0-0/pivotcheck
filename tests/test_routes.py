"""Unit tests for route discovery parsers."""


from pivotcheck.discovery.routes import parse_ip_route, parse_route_n
from pivotcheck.models.network import RouteType
from tests.fixtures.routes import (
    BUSYBOX_ROUTE_N,
    DEBIAN_DUAL_HOMED,
    MALFORMED,
    MULTIPLE_DEFAULTS,
    VPN_TUNNEL,
)


class TestParseIpRoute:
    def test_default_route(self):
        routes = parse_ip_route(DEBIAN_DUAL_HOMED)
        defaults = [r for r in routes if r.route_type is RouteType.DEFAULT]
        assert len(defaults) == 1
        assert defaults[0].gateway == "10.10.20.1"
        assert defaults[0].interface == "eth0"
        assert defaults[0].metric == 100

    def test_connected_route_has_no_gateway(self):
        routes = parse_ip_route(DEBIAN_DUAL_HOMED)
        connected = {
            r.destination: r for r in routes if r.route_type is RouteType.CONNECTED
        }
        assert "10.10.20.0/24" in connected
        assert connected["10.10.20.0/24"].gateway is None

    def test_static_routed_network(self):
        routes = parse_ip_route(DEBIAN_DUAL_HOMED)
        static = [r for r in routes if r.route_type is RouteType.STATIC]
        assert len(static) == 1
        assert static[0].destination == "172.16.50.0/24"
        assert static[0].gateway == "10.10.20.254"

    def test_multiple_defaults_detected(self):
        routes = parse_ip_route(MULTIPLE_DEFAULTS)
        defaults = [r for r in routes if r.route_type is RouteType.DEFAULT]
        assert len(defaults) == 2

    def test_vpn_peer_and_subnet(self):
        routes = parse_ip_route(VPN_TUNNEL)
        by_dest = {r.destination: r for r in routes}
        # /32 peer route is connected (no via)
        assert by_dest["10.8.0.1/32"].route_type is RouteType.CONNECTED
        # wider subnet through the tunnel gateway is static
        assert by_dest["10.8.0.0/24"].route_type is RouteType.STATIC
        assert by_dest["10.8.0.0/24"].gateway == "10.8.0.1"

    def test_malformed_lines_skipped(self):
        routes = parse_ip_route(MALFORMED)
        dests = {r.destination for r in routes}
        assert "this" not in dests
        assert "999.999.999.999/24" not in dests
        assert "default" in dests
        assert "10.10.20.0/24" in dests


class TestParseRouteN:
    def test_busybox_default(self):
        routes = parse_route_n(BUSYBOX_ROUTE_N)
        defaults = [r for r in routes if r.route_type is RouteType.DEFAULT]
        assert len(defaults) == 1
        assert defaults[0].gateway == "10.10.20.1"

    def test_busybox_connected(self):
        routes = parse_route_n(BUSYBOX_ROUTE_N)
        connected = {r.destination for r in routes if r.route_type is RouteType.CONNECTED}
        assert "10.10.20.0/24" in connected

    def test_busybox_static(self):
        routes = parse_route_n(BUSYBOX_ROUTE_N)
        static = [r for r in routes if r.route_type is RouteType.STATIC]
        assert static[0].destination == "172.16.50.0/24"
        assert static[0].gateway == "10.10.20.254"
        assert static[0].metric == 50

    def test_header_lines_ignored(self):
        routes = parse_route_n(BUSYBOX_ROUTE_N)
        assert len(routes) == 3
