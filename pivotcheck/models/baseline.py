"""Versioned, comparison-oriented network perspective models."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone

from pivotcheck.models.network import Confidence, NetworkOrigin, RouteType
from pivotcheck.models.session import SessionIdentity


@dataclass(frozen=True)
class BaselineNetwork:
    """One piece of network evidence retained for comparison."""

    network: str
    origin: NetworkOrigin
    confidence: Confidence
    interface: str | None = None
    gateway: str | None = None
    route_type: RouteType = RouteType.CONNECTED

    def __post_init__(self) -> None:
        try:
            canonical = str(ipaddress.ip_network(self.network, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid baseline network: {self.network!r}") from exc
        object.__setattr__(self, "network", canonical)

    def to_dict(self) -> dict[str, object]:
        return {
            "network": self.network,
            "origin": self.origin.value,
            "confidence": self.confidence.value,
            "interface": self.interface,
            "gateway": self.gateway,
            "route_type": self.route_type.value,
        }


@dataclass(frozen=True)
class Baseline:
    """A normalized, serializable network perspective."""

    schema_version: int = 1
    created_at: str = ""
    source: str = "discovery_snapshot"
    networks: tuple[BaselineNetwork, ...] = ()
    vantage_point: SessionIdentity | None = None

    def __post_init__(self) -> None:
        if self.schema_version < 1:
            raise ValueError("baseline schema_version must be positive")
        if not self.created_at:
            object.__setattr__(
                self, "created_at", datetime.now(timezone.utc).isoformat()
            )
        # Exact duplicate evidence has no additional comparison meaning.
        unique = tuple(sorted(set(self.networks), key=_network_sort_key))
        object.__setattr__(self, "networks", unique)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "source": self.source,
            "networks": [network.to_dict() for network in self.networks],
            "vantage_point": (
                self.vantage_point.to_dict() if self.vantage_point else None
            ),
        }


def _network_sort_key(entry: BaselineNetwork) -> tuple[object, ...]:
    network = ipaddress.ip_network(entry.network)
    return (
        network.version,
        int(network.network_address),
        network.prefixlen,
        entry.origin.value,
        entry.confidence.value,
        entry.interface or "",
        entry.gateway or "",
        entry.route_type.value,
    )
