"""Immutable identity for the vantage point that produced an observation."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import uuid4


@dataclass(frozen=True)
class SessionIdentity:
    """Stable identity for a provider's vantage point, not one collection."""

    session_id: str = field(default_factory=lambda: str(uuid4()))
    provider: str = "local"
    display_name: str = "Local host"

    def __post_init__(self) -> None:
        for name, value in (
            ("session_id", self.session_id),
            ("provider", self.provider),
            ("display_name", self.display_name),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        object.__setattr__(self, "session_id", self.session_id.strip())
        object.__setattr__(self, "provider", self.provider.strip())
        object.__setattr__(self, "display_name", self.display_name.strip())

    def to_dict(self) -> dict[str, str]:
        return {
            "session_id": self.session_id,
            "provider": self.provider,
            "display_name": self.display_name,
        }
