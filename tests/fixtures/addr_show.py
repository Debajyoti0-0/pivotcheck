"""Realistic fixture outputs of `ip -o addr show` for parser tests.

Debian 12 (two interfaces + loopback), one line per address (-o flag).
"""

DEBIAN_MULTI_IFACE = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever
2: eth0    inet 10.10.20.15/24 brd 10.10.20.255 scope global dynamic eth0\\       valid_lft 85919sec preferred_lft 85919sec
2: eth0    inet6 fe80::a00:27ff:fe1a:2b3c/64 scope link \\       valid_lft forever preferred_lft forever
2: eth0    inet6 fd00:dead:beef::15/128 scope global \\       valid_lft forever preferred_lft forever
3: eth1    inet 192.168.100.5/24 brd 192.168.100.255 scope global eth1\\       valid_lft forever preferred_lft forever
4: tun0    inet 10.8.0.2 peer 10.8.0.1/32 scope global tun0\\       valid_lft forever preferred_lft forever
"""

# Single interface, down state addresses still listed by kernel.
SINGLE_IFACE_DOWN = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: ens192    inet 172.16.50.10/24 brd 172.16.50.255 scope global ens192\\       valid_lft forever preferred_lft forever
"""

# Hostname with digits/dashes, secondary address on same interface.
SECONDARY_ADDRESS = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: br-01ab2cd3ef4a    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-01ab2cd3ef4a\\       valid_lft forever preferred_lft forever
2: br-01ab2cd3ef4a    inet 172.18.0.1/20 brd 172.18.15.255 scope global br-01ab2cd3ef4a\\       valid_lft forever preferred_lft forever
"""
