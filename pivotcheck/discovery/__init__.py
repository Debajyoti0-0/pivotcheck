"""Passive discovery modules.

Each module converts raw OS data into normalized models from
:mod:`pivotcheck.models`. Parsers are pure functions (string in, models out)
so they can be tested against fixtures without touching a live system.
"""

"""Normalized discovery collectors and provider implementations."""

from pivotcheck.discovery.local import LocalProvider
from pivotcheck.discovery.provider import (
    CollectedDiscoveryData,
    ProviderError,
    SessionProvider,
)

__all__ = [
    "CollectedDiscoveryData",
    "LocalProvider",
    "ProviderError",
    "SessionProvider",
]
