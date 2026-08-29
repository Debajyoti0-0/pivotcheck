"""Provider contract for obtaining normalized discovery inputs.

Providers collect data only.  The discovery engine remains responsible for
topology analysis and construction of the final DiscoverySnapshot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from pivotcheck.models.network import Connection, DNSConfig, Interface, Neighbor, Route
from pivotcheck.models.result import DiscoveryWarning
from pivotcheck.models.session import SessionIdentity


class ProviderError(RuntimeError):
    """A provider could not initialize or collect any observation."""


@dataclass(frozen=True)
class CollectedDiscoveryData:
    """Normalized, pre-analysis collector output from one provider."""

    hostname: str
    os_name: str
    interfaces: tuple[Interface, ...] = ()
    routes: tuple[Route, ...] = ()
    neighbors: tuple[Neighbor, ...] = ()
    dns: DNSConfig = field(default_factory=DNSConfig)
    connections: tuple[Connection, ...] = ()
    warnings: tuple[DiscoveryWarning, ...] = ()


class SessionProvider(Protocol):
    """Obtains normalized collection data from one named vantage point."""

    def get_session(self) -> SessionIdentity: ...

    def collect(self) -> CollectedDiscoveryData: ...
