"""Realistic fixture outputs of `ip route show` for parser tests."""

# Typical dual-homed host: default via eth0, static route to internal net,
# connected routes for both LANs.
DEBIAN_DUAL_HOMED = """\
default via 10.10.20.1 dev eth0 proto dhcp src 10.10.20.15 metric 100
10.10.20.0/24 dev eth0 proto kernel scope link src 10.10.20.15 metric 100
172.16.50.0/24 via 10.10.20.254 dev eth0 proto static metric 50
192.168.100.0/24 dev eth1 proto kernel scope link src 192.168.100.5 metric 101
"""

# Multiple defaults with different metrics — must warn / pick lowest.
MULTIPLE_DEFAULTS = """\
default via 10.10.20.1 dev eth0 metric 100
default via 192.168.100.1 dev eth1 metric 200
10.10.20.0/24 dev eth0 proto kernel scope link src 10.10.20.15 metric 100
192.168.100.0/24 dev eth1 proto kernel scope link src 192.168.100.5 metric 101
"""

# VPN tunnel: /32 peer route plus wider routed subnet through the tunnel.
VPN_TUNNEL = """\
default via 10.10.20.1 dev eth0 proto dhcp src 10.10.20.15 metric 100
10.8.0.1 dev tun0 proto kernel scope link src 10.8.0.2
10.8.0.0/24 via 10.8.0.1 dev tun0 proto static metric 50
10.10.20.0/24 dev eth0 proto kernel scope link src 10.10.20.15 metric 100
"""

# Busybox `route -n` style output (Alpine / minimal containers).
BUSYBOX_ROUTE_N = """\
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.10.20.1      0.0.0.0         UG    100    0        0 eth0
10.10.20.0      0.0.0.0         255.255.255.0   U     100    0        0 eth0
172.16.50.0     10.10.20.254    255.255.255.0   UG    50     0        0 eth0
"""

# Malformed lines that parsers must skip without crashing.
MALFORMED = """\
default via 10.10.20.1 dev eth0 metric 100
this is not a route at all
10.10.20.0/24 dev eth0 proto kernel scope link src 10.10.20.15 metric 100
999.999.999.999/24 via 10.10.20.254 dev eth0
"""
