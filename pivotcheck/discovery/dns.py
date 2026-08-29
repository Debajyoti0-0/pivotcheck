"""DNS resolver configuration discovery (Linux, passive).

Reads /etc/resolv.conf directly. On systemd-resolved systems this yields the
local stub (127.0.0.53); that is reported as-is with its source noted so the
operator knows real upstream servers were not visible.
"""

from __future__ import annotations

import re

from pivotcheck.models.network import DNSConfig, DNSServer
from pivotcheck.utils.system import read_file_safe

_RESOLV_CONF = "/etc/resolv.conf"

_NAMESERVER_RE = re.compile(r"^nameserver\s+(\S+)", re.MULTILINE)
_SEARCH_RE = re.compile(r"^search\s+(.+)$", re.MULTILINE)


def parse_resolv_conf(content: str) -> DNSConfig:
    """Parse resolv.conf content into a DNSConfig model."""
    servers: list[DNSServer] = []
    search_domains: list[str] = []

    for address in _NAMESERVER_RE.findall(content):
        try:
            server = DNSServer(address=address, source="resolv.conf")
        except ValueError:
            continue  # skip malformed nameserver entries
        servers.append(server)

    for line in _SEARCH_RE.findall(content):
        search_domains.extend(line.split())

    return DNSConfig(servers=tuple(servers), search_domains=tuple(search_domains))


def collect_dns(path: str = _RESOLV_CONF) -> DNSConfig | None:
    """Discover resolver configuration. Returns None if unreadable."""
    content = read_file_safe(path)
    if content is None:
        return None
    return parse_resolv_conf(content)
