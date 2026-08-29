"""Local implementation of the normalized discovery provider contract."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from pivotcheck.discovery.connections import collect_connections
from pivotcheck.discovery.dns import collect_dns
from pivotcheck.discovery.interfaces import collect_interfaces
from pivotcheck.discovery.neighbors import collect_neighbors
from pivotcheck.discovery.provider import CollectedDiscoveryData, ProviderError
from pivotcheck.discovery.routes import collect_routes
from pivotcheck.models.network import Connection, DNSConfig, Interface, Neighbor, Route
from pivotcheck.models.result import DiscoverySnapshot, DiscoveryWarning
from pivotcheck.models.session import SessionIdentity

T = TypeVar("T")


def _safe_collect(
    name: str,
    collector: Callable[[], T],
    fallback: T,
    warnings: list[DiscoveryWarning],
) -> T:
    """Preserve collector degradation as warnings within a valid session."""
    try:
        return collector()
    except Exception as exc:  # noqa: BLE001 - collector boundary is deliberate
        warnings.append(
            DiscoveryWarning(
                source=name,
                message=f"Could not collect {name}: {exc}. Continuing.",
            )
        )
        return fallback


class LocalProvider:
    """Collect normalized inputs from the host running PivotCheck."""

    def __init__(self, session: SessionIdentity | None = None) -> None:
        self._session = session or SessionIdentity()
        if self._session.provider != "local":
            raise ValueError("LocalProvider requires a session with provider='local'")

    def get_session(self) -> SessionIdentity:
        return self._session

    def collect(self) -> CollectedDiscoveryData:
        try:
            metadata = DiscoverySnapshot.collect_metadata()
        except Exception as exc:
            raise ProviderError("local provider metadata collection failed") from exc

        warnings: list[DiscoveryWarning] = []
        interfaces: tuple[Interface, ...] = _safe_collect(
            "interfaces", collect_interfaces, (), warnings
        )
        routes: tuple[Route, ...] = _safe_collect("routes", collect_routes, (), warnings)
        neighbors: tuple[Neighbor, ...] = _safe_collect(
            "neighbors", collect_neighbors, (), warnings
        )
        dns = _safe_collect("dns", collect_dns, None, warnings) or DNSConfig()
        connections: tuple[Connection, ...] = _safe_collect(
            "connections", collect_connections, (), warnings
        )
        return CollectedDiscoveryData(
            hostname=metadata["hostname"],
            os_name=metadata["os_name"],
            interfaces=interfaces,
            routes=routes,
            neighbors=neighbors,
            dns=dns,
            connections=connections,
            warnings=tuple(warnings),
        )
