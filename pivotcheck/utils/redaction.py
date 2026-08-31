"""Redaction boundary for authentication material.

Central helper so every layer that could surface a secret (exceptions,
logs, debug output, serialized objects) has one auditable way to remove
it. PivotCheck v1 deliberately never stores credentials; this boundary
exists so Phase 4+ transports that *handle* credential material cannot
accidentally leak it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

REDACTED = "REDACTED"


class SecretRedactor:
    """Replaces known secret values with the REDACTED marker."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        # Empty secrets are skipped: redacting "" would destroy text.
        self._secrets: tuple[str, ...] = tuple(s for s in secrets if s)

    @property
    def secrets(self) -> tuple[str, ...]:
        return self._secrets

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        return text

    def redact_message(self, message: object) -> str:
        """Redact any object's string form (exception messages, log args)."""
        return self.redact(str(message))


def redact(text: str, secrets: Sequence[str]) -> str:
    """One-shot convenience redaction."""
    return SecretRedactor(secrets).redact(text)
