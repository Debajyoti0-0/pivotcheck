"""Realistic fixture outputs of `ip neigh show` for parser tests."""

TYPICAL_NEIGH = """\
10.10.20.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
10.10.20.25 dev eth0 lladdr aa:bb:cc:dd:ee:02 STALE
10.10.20.99 dev eth0  FAILED
192.168.100.1 dev eth1 lladdr aa:bb:cc:dd:ee:03 PERMANENT
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router STALE
10.10.20.42 dev eth0 lladdr aa:bb:cc:dd:ee:04 DELAY
"""

EMPTY_NEIGH = ""
