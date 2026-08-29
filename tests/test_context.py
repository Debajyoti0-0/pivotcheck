"""Unit tests for route context correlation."""

from pivotcheck.checks.context import build_route_context
from pivotcheck.models.check import RouteContextType
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    NetworkOrigin,
)


def net(cidr, origin, gateway=None, interface="eth0"):
    return DiscoveredNetwork(
        cidr=cidr,
        origin=origin,
        confidence=(
            Confidence.HIGH if origin is NetworkOrigin.CONNECTED else Confidence.MEDIUM
        ),
        interface=interface,
        gateway=gateway,
    )


NETWORKS = (
    net("10.10.20.0/24", NetworkOrigin.CONNECTED),
    net("172.16.50.0/24", NetworkOrigin.ROUTED, gateway="10.10.20.254"),
    net("10.0.0.0/8", NetworkOrigin.ROUTED, gateway="10.10.20.1"),
)


class TestRouteContext:
    def test_direct_network_match(self):
        ctx = build_route_context("10.10.20.99", NETWORKS)
        assert ctx.context_type is RouteContextType.CONNECTED
        assert ctx.network == "10.10.20.0/24"

    def test_routed_network_match(self):
        ctx = build_route_context("172.16.50.10", NETWORKS)
        assert ctx.context_type is RouteContextType.ROUTED
        assert ctx.gateway == "10.10.20.254"

    def test_no_match_is_unknown(self):
        ctx = build_route_context("192.0.2.1", NETWORKS)
        assert ctx.context_type is RouteContextType.UNKNOWN

    def test_longest_prefix_wins(self):
        # 10.10.20.5 matches both 10.0.0.0/8 and 10.10.20.0/24 — /24 is
        # more specific and must win deterministically.
        ctx = build_route_context("10.10.20.5", NETWORKS)
        assert ctx.network == "10.10.20.0/24"

    def test_connected_beats_routed_on_equal_specificity(self):
        networks = (
            net("10.10.20.0/24", NetworkOrigin.ROUTED, gateway="10.9.9.9"),
            net("10.10.20.0/24", NetworkOrigin.CONNECTED),
        )
        ctx = build_route_context("10.10.20.7", networks)
        assert ctx.context_type is RouteContextType.CONNECTED

    def test_invalid_address_unknown(self):
        assert build_route_context("not-an-ip", NETWORKS).context_type \
            is RouteContextType.UNKNOWN

    def test_empty_evidence_unknown(self):
        assert build_route_context("10.10.20.1", ()).context_type \
            is RouteContextType.UNKNOWN
