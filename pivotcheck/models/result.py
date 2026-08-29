"""Result and snapshot models for discovery output."""

from __future__ import annotations

import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pivotcheck import __version__
from pivotcheck.models.network import (
    Connection,
    DiscoveredNetwork,
    DNSConfig,
    Interface,
    Neighbor,
    PivotPath,
    Route,
)
from pivotcheck.models.session import SessionIdentity


@dataclass(frozen=True)
class DiscoveryWarning:
    """A non-fatal problem encountered during discovery."""

    source: str  # module that produced the warning, e.g. "neighbors"
    message: str

    def to_dict(self) -> dict:
        return {"source": self.source, "message": self.message}


@dataclass(frozen=True)
class DiscoverySnapshot:
    """Complete normalized result of a passive discovery run."""

    hostname: str
    os_name: str
    interfaces: tuple[Interface, ...] = ()
    routes: tuple[Route, ...] = ()
    neighbors: tuple[Neighbor, ...] = ()
    dns: DNSConfig = field(default_factory=DNSConfig)
    connections: tuple[Connection, ...] = ()
    networks: tuple[DiscoveredNetwork, ...] = ()
    pivot_paths: tuple[PivotPath, ...] = ()
    warnings: tuple[DiscoveryWarning, ...] = ()
    session: SessionIdentity | None = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool_version: str = __version__

    @classmethod
    def collect_metadata(cls) -> dict[str, str]:
        return {
            "hostname": platform.node(),
            "os_name": f"{platform.system()} {platform.release()}",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "pivotcheck",
            "version": self.tool_version,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "os": self.os_name,
            "session": self.session.to_dict() if self.session else None,
            "interfaces": [i.to_dict() for i in self.interfaces],
            "routes": [r.to_dict() for r in self.routes],
            "neighbors": [n.to_dict() for n in self.neighbors],
            "dns": self.dns.to_dict(),
            "connections": [c.to_dict() for c in self.connections],
            "networks": [n.to_dict() for n in self.networks],
            "pivot_paths": [p.to_dict() for p in self.pivot_paths],
            "warnings": [w.to_dict() for w in self.warnings],
        }
