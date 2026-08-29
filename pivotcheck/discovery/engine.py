"""Discovery engine: orchestrates all passive collectors into a snapshot.

Pipeline: raw OS data -> parsers -> normalized models -> analysis -> snapshot.
Each collector degrades independently; failures become warnings, never aborts.
"""

from __future__ import annotations

from pivotcheck.analysis.topology import analyze
from pivotcheck.discovery.local import LocalProvider
from pivotcheck.discovery.provider import SessionProvider
from pivotcheck.models.result import DiscoverySnapshot


def run_discovery(provider: SessionProvider | None = None) -> DiscoverySnapshot:
    """Execute all passive discovery layers and return an analyzed snapshot.

    Never raises for individual collector failures — those are captured as
    warnings on the returned snapshot. Only raises if even basic host
    metadata is unavailable.
    """
    provider = provider or LocalProvider()
    session = provider.get_session()
    collection = provider.collect()

    snapshot = DiscoverySnapshot(
        hostname=collection.hostname,
        os_name=collection.os_name,
        interfaces=collection.interfaces,
        routes=collection.routes,
        neighbors=collection.neighbors,
        dns=collection.dns,
        connections=collection.connections,
        warnings=collection.warnings,
        session=session,
    )
    return analyze(snapshot)
