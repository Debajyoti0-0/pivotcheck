"""Normalized network data models.

These models are the single source of truth for PivotCheck's internal
representation of host network state. Discovery modules produce them,
analysis modules consume them, and output modules serialize them.

Models are intentionally independent from any presentation format.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum


class InterfaceState(str, Enum):
    """Operational state of a network interface."""

    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class RouteType(str, Enum):
    """Classification of a routing table entry."""

    DEFAULT = "default"
    CONNECTED = "connected"  # directly attached network, no gateway
    STATIC = "static"  # via a gateway (or otherwise non-connected)


class NetworkOrigin(str, Enum):
    """How a network became known to PivotCheck."""

    CONNECTED = "connected"  # interface address implies this subnet
    ROUTED = "routed"  # explicit routing table entry via gateway
    INFERRED = "inferred"  # indirect evidence (DNS, naming). Not confirmed.


class Confidence(str, Enum):
    """Confidence that a network is reachable from this host."""

    HIGH = "high"  # directly connected + active interface
    MEDIUM = "medium"  # explicit routing table entry
    LOW = "low"  # inferred only — never present as fact


@dataclass(frozen=True)
class IPAddress:
    """A single address with its prefix length."""

    address: str
    prefix: int

    def __post_init__(self) -> None:
        addr = ipaddress.ip_address(self.address)  # raises ValueError if invalid
        max_prefix = 128 if addr.version == 6 else 32
        if not 0 <= self.prefix <= max_prefix:
            raise ValueError(
                f"invalid prefix length {self.prefix} for IPv{addr.version}"
            )

    @property
    def version(self) -> int:
        return ipaddress.ip_address(self.address).version

    @property
    def network(self) -> str:
        """CIDR network containing this address, e.g. '10.10.20.0/24'."""
        iface = ipaddress.ip_interface(f"{self.address}/{self.prefix}")
        return str(iface.network)

    def to_dict(self) -> dict:
        return {"address": self.address, "prefix": self.prefix}


@dataclass(frozen=True)
class Interface:
    """A network interface and its addressing."""

    name: str
    state: InterfaceState = InterfaceState.UNKNOWN
    mac_address: str | None = None
    ipv4_addresses: tuple[IPAddress, ...] = ()
    ipv6_addresses: tuple[IPAddress, ...] = ()

    @property
    def networks(self) -> list[str]:
        """Unique CIDR networks directly attached to this interface."""
        seen: dict[str, None] = {}
        for addr in self.ipv4_addresses + self.ipv6_addresses:
            if addr.prefix == 0:
                continue  # /0 carries no usable local network information
            seen.setdefault(addr.network, None)
        return list(seen)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "mac_address": self.mac_address,
            "ipv4_addresses": [a.to_dict() for a in self.ipv4_addresses],
            "ipv6_addresses": [a.to_dict() for a in self.ipv6_addresses],
            "networks": self.networks,
        }


@dataclass(frozen=True)
class Route:
    """A single routing table entry."""

    destination: str  # CIDR or 'default'
    gateway: str | None  # None for directly connected routes
    interface: str
    metric: int | None = None
    route_type: RouteType = RouteType.CONNECTED

    def __post_init__(self) -> None:
        if self.destination != "default":
            try:
                ipaddress.ip_network(self.destination, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"invalid route destination: {self.destination!r}"
                ) from exc
        if self.gateway is not None:
            try:
                ipaddress.ip_address(self.gateway)
            except ValueError as exc:
                raise ValueError(f"invalid route gateway: {self.gateway!r}") from exc

    def to_dict(self) -> dict:
        return {
            "destination": self.destination,
            "gateway": self.gateway,
            "interface": self.interface,
            "metric": self.metric,
            "route_type": self.route_type.value,
        }


@dataclass(frozen=True)
class Neighbor:
    """An entry from the ARP / neighbor table.

    Presence in this table does NOT confirm current reachability.
    """

    ip_address: str
    interface: str
    mac_address: str | None = None
    state: str | None = None  # e.g. REACHABLE, STALE, FAILED, PERMANENT

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError as exc:
            raise ValueError(f"invalid neighbor IP: {self.ip_address!r}") from exc

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "interface": self.interface,
            "state": self.state,
        }


@dataclass(frozen=True)
class DNSServer:
    """A configured DNS resolver."""

    address: str
    source: str = "resolv.conf"  # where this was learned from

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError(f"invalid DNS server address: {self.address!r}") from exc

    def to_dict(self) -> dict:
        return {"address": self.address, "source": self.source}


@dataclass(frozen=True)
class DNSConfig:
    """Resolver configuration discovered on this host."""

    servers: tuple[DNSServer, ...] = ()
    search_domains: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "servers": [s.to_dict() for s in self.servers],
            "search_domains": list(self.search_domains),
        }


class ConnectionProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass(frozen=True)
class Connection:
    """An existing socket (listening or established)."""

    protocol: ConnectionProtocol
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None  # LISTEN, ESTABLISHED, ...
    process: str | None = None  # pid/name when available

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol.value,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "state": self.state,
            "process": self.process,
        }


@dataclass(frozen=True)
class DiscoveredNetwork:
    """A normalized network with reachability classification."""

    cidr: str
    origin: NetworkOrigin
    confidence: Confidence
    interface: str | None = None
    gateway: str | None = None

    def __post_init__(self) -> None:
        try:
            ipaddress.ip_network(self.cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid network CIDR: {self.cidr!r}") from exc

    def to_dict(self) -> dict:
        return {
            "cidr": self.cidr,
            "origin": self.origin.value,
            "confidence": self.confidence.value,
            "interface": self.interface,
            "gateway": self.gateway,
        }


@dataclass(frozen=True)
class PivotPath:
    """A potential pivot route through a gateway."""

    source_interface: str
    gateway: str
    destination_network: str
    confidence: Confidence

    def to_dict(self) -> dict:
        return {
            "source_interface": self.source_interface,
            "gateway": self.gateway,
            "destination_network": self.destination_network,
            "confidence": self.confidence.value,
        }
