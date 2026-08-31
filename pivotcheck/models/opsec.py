"""OPSEC intelligence models (v2.0 Step 7).

OPSEC intelligence is PREDICTIVE ANALYSIS, not observation and not evasion.

It describes the observability that an explicitly described action is
reasonably expected to produce on a platform, based on documented platform
behavior. It never claims PivotCheck observed telemetry on a target (no
OBSERVED claim is ever manufactured), and it never provides evasion,
suppression, or detection-bypass guidance.

This module is pure data: no network I/O, no subprocesses, no filesystem
access, no environment access. It holds no credential material — the
OPSEC engine operates on an action/platform description only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class OpsecAction(str, Enum):
    """Constrained action vocabulary — exactly the capabilities PivotCheck
    implements (Steps 2, 5, 6 and the v1 TCP/SOCKS5 checks). Unknown or
    free-form actions fail closed; there is no generic answer."""

    SSH_AUTH = "ssh-auth"
    SMB_AUTH = "smb-auth"
    WINRM_AUTH = "winrm-auth"
    TCP_CONNECT = "tcp-connect"
    SOCKS5_CONNECT = "socks5-connect"


class OpsecPlatform(str, Enum):
    """Platform where telemetry is expected to land."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class OpsecCategory(str, Enum):
    """Finite telemetry taxonomy — categories only, not hundreds of event
    types. PivotCheck is not a SIEM."""

    AUTHENTICATION = "authentication"
    NETWORK_CONNECTION = "network_connection"
    REMOTE_MANAGEMENT = "remote_management"
    SESSION_ACTIVITY = "session_activity"
    PROCESS_ACTIVITY = "process_activity"
    SYSTEM_AUDIT = "system_audit"


class OpsecLikelihood(str, Enum):
    """Likelihood of one telemetry observation for the described action.

    These are calibrated claims about platform behavior:

    - DOCUMENTED: the platform's own documentation describes this
      telemetry for this class of operation.
    - LIKELY: standard platform behavior produces it, but audit policy
      and configuration govern availability.
    - POSSIBLE: only some environments/configurations produce it.
    - ENVIRONMENT_DEPENDENT: strongly configuration-gated.
    - NOT_EXPECTED: the described action does not itself perform the
      operation this telemetry records (environment add-ons may still
      log; absence of the event is not proof of absence of logging).
    """

    DOCUMENTED = "documented"
    LIKELY = "likely"
    POSSIBLE = "possible"
    ENVIRONMENT_DEPENDENT = "environment_dependent"
    NOT_EXPECTED = "not_expected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OpsecObservation:
    """One expected-telemetry description."""

    category: OpsecCategory
    description: str
    likelihood: OpsecLikelihood
    event_ids: tuple[str, ...] = ()  # documented IDs; environment-dependent
    sources: tuple[str, ...] = ()  # e.g. log channels; informational only

    def __post_init__(self) -> None:
        if not isinstance(self.category, OpsecCategory):
            raise TypeError(f"invalid telemetry category: {self.category!r}")
        if not isinstance(self.likelihood, OpsecLikelihood):
            raise TypeError(f"invalid telemetry likelihood: {self.likelihood!r}")
        if not self.description:
            raise ValueError("observation description must not be empty")
        for event_id in self.event_ids:
            if not event_id or event_id.strip() != event_id:
                raise ValueError("event IDs must be non-empty, trimmed identifiers")
        for source in self.sources:
            if not source or source.strip() != source:
                raise ValueError("sources must be non-empty, trimmed identifiers")

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "description": self.description,
            "likelihood": self.likelihood.value,
            "event_ids": list(self.event_ids),
            "sources": list(self.sources),
        }


@dataclass(frozen=True)
class OpsecResult:
    """Deterministic OPSEC analysis result for one action/platform pair."""

    action: OpsecAction
    platform: OpsecPlatform
    observations: tuple[OpsecObservation, ...]
    rationale: str
    limitations: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if not isinstance(self.action, OpsecAction):
            raise TypeError(f"invalid action: {self.action!r}")
        if not isinstance(self.platform, OpsecPlatform):
            raise TypeError(f"invalid platform: {self.platform!r}")
        if not isinstance(self.observations, tuple):
            raise TypeError("observations must be a tuple of OpsecObservation")
        if not self.rationale:
            raise ValueError("rationale must not be empty")

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "platform": self.platform.value,
            "observations": [o.to_dict() for o in self.observations],
            "rationale": self.rationale,
            "limitations": list(self.limitations),
        }
