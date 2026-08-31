"""Explicit, minimal environment-backed credential loading (v2.0 Step 1).

Design contract:

- Reads **exactly one** named environment variable per credential. Never
  enumerates the environment.
- Never logs, prints, persists, or echoes the secret; failures name the
  variable, never its value.
- Never mutates ``os.environ`` and never touches the filesystem.
- Produces a typed :class:`~pivotcheck.models.credentials.Credential`
  whose provenance records the variable *name* only.

Whitespace handling is format-aware and documented:

- ``PASSWORD`` / ``KERBEROS_TICKET``: material is used **verbatim** —
  leading/trailing spaces may be significant.
- ``NTLM_HASH`` / ``SSH_PRIVATE_KEY``: surrounding whitespace is
  formatting noise and is stripped before validation.
"""

from __future__ import annotations

import os

from pivotcheck.models.credentials import (
    Credential,
    CredentialSource,
    CredentialType,
)


class CredentialLoadError(RuntimeError):
    """A credential could not be loaded from its named source.

    The message names the source (e.g. the environment variable name) and
    the reason; it never contains the value.
    """


def load_credential(
    credential_type: CredentialType,
    environment_variable: str,
    username: str | None = None,
    domain: str | None = None,
) -> Credential:
    """Load one credential from exactly one named environment variable.

    Raises:
        CredentialLoadError: the variable is missing, or contains nothing
            usable (empty / whitespace-only for whitespace-stripped types).
        ValueError: the material failed format validation for its type
            (the value itself is never included in the error).
    """
    if not environment_variable:
        raise CredentialLoadError("an environment variable name is required")
    if environment_variable not in os.environ:
        raise CredentialLoadError(
            f"environment variable '{environment_variable}' is not set"
        )
    value = os.environ[environment_variable]

    stripped_types = (CredentialType.NTLM_HASH, CredentialType.SSH_PRIVATE_KEY)
    if credential_type in stripped_types:
        material = value.strip()
        if not material:
            raise CredentialLoadError(
                f"environment variable '{environment_variable}' is empty or whitespace"
            )
    else:
        material = value
        if not material:
            raise CredentialLoadError(
                f"environment variable '{environment_variable}' is empty"
            )

    try:
        return Credential(
            credential_type=credential_type,
            secret=material,
            username=username,
            domain=domain,
            source=CredentialSource.ENVIRONMENT,
            source_name=environment_variable,
        )
    except ValueError as exc:
        # Re-raise without the material: validation errors may embed the
        # offending value (e.g. a repr of an invalid NTLM string).
        raise CredentialLoadError(
            f"environment variable '{environment_variable}' contains material "
            f"that is not valid for {credential_type.value} credentials"
        ) from exc
