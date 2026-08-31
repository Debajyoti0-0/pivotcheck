"""Credential abstraction (v2.0 Step 1: data model only).

A credential is evidence that authentication *material exists* — nothing
more. Possession never implies validity:

    CREDENTIAL_PRESENT  !=  AUTHENTICATION_VALIDATED

Proving validity belongs exclusively to future, explicit, active
validation modules. This module is pure data: no network I/O, no
subprocesses, no filesystem access, no environment access, no
persistence. Loading from the environment lives in
:mod:`pivotcheck.utils.credential_loader`.

Secret-safety contract (adversarially tested):

- ``repr()`` / ``str()`` render ``secret=[REDACTED]`` — never material.
- ``to_dict()`` emits ``secret_present`` as a boolean — never material.
- Secret material participates in equality (two credentials holding
  different secrets are different credentials) but can never reach any
  string representation through the public surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from pivotcheck.utils.redaction import REDACTED as REDACTED_LABEL

_PEM_KEY_RE = re.compile(r"^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_NTLM_RE = re.compile(r"^([0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$")


class CredentialType(str, Enum):
    """Authentication material kinds PivotCheck can represent.

    Representation is not implementation: no protocol logic exists for any
    of these yet (v2.0 Step 1 is data abstraction only).
    """

    PASSWORD = "password"
    NTLM_HASH = "ntlm_hash"
    SSH_PRIVATE_KEY = "ssh_private_key"
    KERBEROS_TICKET = "kerberos_ticket"


class CredentialSource(str, Enum):
    """Where the credential came from (provenance metadata only)."""

    EXPLICIT = "explicit"  # supplied directly by the operator
    ENVIRONMENT = "environment"  # loaded from a named environment variable
    DISCOVERED = "discovered"  # observed on a host; existence is NOT validity


class CredentialState(str, Enum):
    """Epistemic state: possession is distinct from proven validity."""

    PRESENT = "present"  # material exists; nothing is proven about it
    AUTHENTICATION_VALIDATED = "authentication_validated"  # proven by an
    # explicit future validation check; set ONLY by that check, never here


@dataclass(frozen=True)
class Credential:
    """One credential and its safe metadata.

    ``secret`` is the sensitive material itself. It is memory-resident
    only: never serialized, never logged, never written. ``domain`` is the
    Windows domain for NTLM material or the Kerberos realm for ticket
    material; it is ignored for other types (pass ``None``).

    Provenance never carries values: ``source`` + ``source_name`` identify
    *where* the credential came from (e.g. the environment variable name),
    never what was in it.
    """

    credential_type: CredentialType
    secret: str = field(repr=False)
    username: str | None = None
    domain: str | None = None  # Windows domain / Kerberos realm
    source: CredentialSource = CredentialSource.EXPLICIT
    source_name: str | None = None  # e.g. the environment variable name
    state: CredentialState = CredentialState.PRESENT

    def __post_init__(self) -> None:
        if not isinstance(self.credential_type, CredentialType):
            raise TypeError(f"invalid credential type: {self.credential_type!r}")
        if not self.secret:
            raise ValueError("credential secret must not be empty")
        if not isinstance(self.source, CredentialSource):
            raise TypeError(f"invalid credential source: {self.source!r}")
        if not isinstance(self.state, CredentialState):
            raise TypeError(f"invalid credential state: {self.state!r}")
        if self.credential_type is CredentialType.NTLM_HASH and not _NTLM_RE.match(
            self.secret.strip()
        ):
            raise ValueError(
                "NTLM credential must be 32 hex chars (or LM:NT 32:32 hex)"
            )
        if self.credential_type is CredentialType.SSH_PRIVATE_KEY and not _PEM_KEY_RE.match(
            self.secret.lstrip()
        ):
            raise ValueError(
                "SSH private key credential must contain a PEM private key header"
            )
        domain_types = (CredentialType.NTLM_HASH, CredentialType.KERBEROS_TICKET)
        if self.credential_type not in domain_types and self.domain is not None:
            raise ValueError(
                f"{self.credential_type.value} credentials do not take a domain/realm"
            )
        if self.username is not None and not self.username:
            raise ValueError("username must be None or non-empty")
        if self.source_name is not None and not self.source_name:
            raise ValueError("source_name must be None or non-empty")

    @property
    def secret_present(self) -> bool:
        """True: material is held in memory. Exposed instead of the material."""
        return bool(self.secret)

    def to_dict(self) -> dict:
        """Safe serialization: metadata only, never secret material."""
        return {
            "credential_type": self.credential_type.value,
            "username": self.username,
            "domain": self.domain,
            "secret_present": self.secret_present,
            "source": self.source.value,
            "source_name": self.source_name,
            "state": self.state.value,
        }

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        parts = [f"type={self.credential_type.value}"]
        if self.username is not None:
            parts.append(f"username={self.username}")
        if self.domain is not None:
            parts.append(f"domain={self.domain}")
        parts.append(f"secret=[{REDACTED_LABEL}]")
        parts.append(f"source={self.source.value}")
        return f"Credential({', '.join(parts)})"
