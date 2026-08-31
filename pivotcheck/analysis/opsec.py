"""OPSEC intelligence engine (v2.0 Step 7).

PURE ANALYSIS: no network I/O, no subprocesses, no filesystem access, no
environment access, no credential access. A structured
(action, platform) description goes in; a deterministic, explainable
observability description comes out.

Boundary of the capability (mandatory):

- The engine describes LIKELY/POSSIBLE/ENVIRONMENT_DEPENDENT telemetry —
  it never guarantees an event occurred, because PivotCheck does not
  observe target telemetry.
- It NEVER provides evasion, suppression, log clearing, security-control
  bypass, or stealth guidance. "What might be observable" is in scope;
  "how to become invisible" is not, and no output path can express it.

Determinism: the knowledge mapping is a static table; identical inputs
produce identical results in any environment.
"""

from __future__ import annotations

from pivotcheck.models.opsec import (
    OpsecAction,
    OpsecCategory,
    OpsecLikelihood,
    OpsecObservation,
    OpsecPlatform,
    OpsecResult,
)

_BASE_LIMITATIONS: tuple[str, ...] = (
    "Predictive analysis only: PivotCheck does not observe telemetry on the target. Nothing listed was confirmed to have occurred.",
    "Telemetry availability depends on audit policy, logging configuration, and deployed security tooling on the target.",
    "Event IDs and log channels are environment-dependent (Windows version, domain vs. standalone, audit settings) and are documented references, not guarantees.",
    "Absence of a listed event does not prove absence of logging, and presence of a listed event is not guaranteed.",
    "PivotCheck does not provide evasion, telemetry suppression, or security-control bypass guidance of any kind.",
)

# Telemetry descriptions per (action, platform). Only combinations grounded
# in the protocols PivotCheck actually implements are mapped; unmapped
# combinations yield an explicit UNKNOWN result rather than a guess.
_KNOWLEDGE: dict[tuple[OpsecAction, OpsecPlatform], tuple[OpsecObservation, ...]] = {
    # --- SSH authentication on Linux: sshd records the session ---
    (OpsecAction.SSH_AUTH, OpsecPlatform.LINUX): (
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "sshd records a public-key authentication attempt in the "
                "system journal/syslog (Accepted/Failed publickey for user)"
            ),
            likelihood=OpsecLikelihood.LIKELY,
            event_ids=(),
            sources=("sshd", "systemd-journald", "syslog"),
        ),
        OpsecObservation(
            category=OpsecCategory.SESSION_ACTIVITY,
            description=(
                "a successful authentication opens a session recorded in "
                "login accounting (wtmp/btmp) and the journal"
            ),
            likelihood=OpsecLikelihood.ENVIRONMENT_DEPENDENT,
            sources=("wtmp", "systemd-journald"),
        ),
        OpsecObservation(
            category=OpsecCategory.SYSTEM_AUDIT,
            description=(
                "auditd may record authentication- and session-related "
                "system calls if audit rules are configured"
            ),
            likelihood=OpsecLikelihood.ENVIRONMENT_DEPENDENT,
            sources=("auditd",),
        ),
    ),
    (OpsecAction.SSH_AUTH, OpsecPlatform.WINDOWS): (
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "Windows OpenSSH server logs authentication attempts to the "
                "OpenSSH/Operational channel and, when the port is "
                "configured, Security logon events (4624/4625)"
            ),
            likelihood=OpsecLikelihood.ENVIRONMENT_DEPENDENT,
            event_ids=("4624", "4625"),
            sources=("OpenSSH/Operational", "Microsoft-Windows-Security-Auditing"),
        ),
    ),
    # --- SMB authentication on Windows ---
    (OpsecAction.SMB_AUTH, OpsecPlatform.WINDOWS): (
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "an NTLM session-setup attempt generates logon telemetry "
                "(successful logon 4624 type 3, failed logon 4625) when "
                "account/logon auditing is enabled"
            ),
            likelihood=OpsecLikelihood.LIKELY,
            event_ids=("4624", "4625"),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "domain environments additionally record credential "
                "validation on the domain controller (4776/4768/4771)"
            ),
            likelihood=OpsecLikelihood.POSSIBLE,
            event_ids=("4776", "4768", "4771"),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
        OpsecObservation(
            category=OpsecCategory.NETWORK_CONNECTION,
            description=(
                "Windows Filtering Platform may record the SMB network "
                "connection (5156/5158) when connection auditing is enabled"
            ),
            likelihood=OpsecLikelihood.POSSIBLE,
            event_ids=("5156", "5158"),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "this validation performs authentication only: it does NOT "
                "connect to shares, so share-access telemetry (5140/5145) "
                "is not expected from the validation itself"
            ),
            likelihood=OpsecLikelihood.NOT_EXPECTED,
            event_ids=("5140", "5145"),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
    ),
    # --- WinRM authentication on Windows ---
    (OpsecAction.WINRM_AUTH, OpsecPlatform.WINDOWS): (
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "the WS-Man authentication generates logon telemetry "
                "(4624 type 3 with the WinRM service, failed logon 4625) "
                "when account/logon auditing is enabled"
            ),
            likelihood=OpsecLikelihood.LIKELY,
            event_ids=("4624", "4625"),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
        OpsecObservation(
            category=OpsecCategory.REMOTE_MANAGEMENT,
            description=(
                "the WinRM service records operational activity in its "
                "dedicated operational log"
            ),
            likelihood=OpsecLikelihood.LIKELY,
            sources=("Microsoft-Windows-WinRM/Operational",),
        ),
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "domain environments additionally record credential "
                "validation on the domain controller (4776)"
            ),
            likelihood=OpsecLikelihood.POSSIBLE,
            event_ids=("4776",),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
        OpsecObservation(
            category=OpsecCategory.PROCESS_ACTIVITY,
            description=(
                "this validation performs authentication only: no remote "
                "shell is created and no command is executed, so "
                "process-creation telemetry (4688, Sysmon 1) and PowerShell "
                "script-block logging (4104) are not expected from the "
                "validation itself"
            ),
            likelihood=OpsecLikelihood.NOT_EXPECTED,
            event_ids=("4688", "4104"),
            sources=("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-PowerShell/Operational"),
        ),
    ),
    # --- TCP connect ---
    (OpsecAction.TCP_CONNECT, OpsecPlatform.WINDOWS): (
        OpsecObservation(
            category=OpsecCategory.NETWORK_CONNECTION,
            description=(
                "Windows Filtering Platform may record the outbound "
                "connection (5156) when connection auditing is enabled"
            ),
            likelihood=OpsecLikelihood.POSSIBLE,
            event_ids=("5156",),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
        OpsecObservation(
            category=OpsecCategory.AUTHENTICATION,
            description=(
                "a TCP connection performs no authentication: no logon "
                "telemetry is expected from the connection attempt itself"
            ),
            likelihood=OpsecLikelihood.NOT_EXPECTED,
            event_ids=("4624", "4625"),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
    ),
    (OpsecAction.TCP_CONNECT, OpsecPlatform.LINUX): (
        OpsecObservation(
            category=OpsecCategory.NETWORK_CONNECTION,
            description=(
                "Linux distributions do not log outbound TCP connections by "
                "default; netfilter/audit logging appears only where "
                "explicitly configured"
            ),
            likelihood=OpsecLikelihood.ENVIRONMENT_DEPENDENT,
            sources=("auditd",),
        ),
    ),
    # --- SOCKS5 CONNECT ---
    (OpsecAction.SOCKS5_CONNECT, OpsecPlatform.LINUX): (
        OpsecObservation(
            category=OpsecCategory.NETWORK_CONNECTION,
            description=(
                "the proxy observes the CONNECT request at the application "
                "layer; PivotCheck cannot describe the proxy's own logging "
                "configuration"
            ),
            likelihood=OpsecLikelihood.ENVIRONMENT_DEPENDENT,
        ),
        OpsecObservation(
            category=OpsecCategory.NETWORK_CONNECTION,
            description=(
                "the connection to the proxy and from the proxy to the "
                "destination are network-observable events; logging depends "
                "on the systems in path"
            ),
            likelihood=OpsecLikelihood.ENVIRONMENT_DEPENDENT,
        ),
    ),
    (OpsecAction.SOCKS5_CONNECT, OpsecPlatform.WINDOWS): (
        OpsecObservation(
            category=OpsecCategory.NETWORK_CONNECTION,
            description=(
                "Windows Filtering Platform may record the connection to "
                "the proxy (5156) when connection auditing is enabled"
            ),
            likelihood=OpsecLikelihood.POSSIBLE,
            event_ids=("5156",),
            sources=("Microsoft-Windows-Security-Auditing",),
        ),
    ),
}

_RATIONALE: dict[OpsecAction, str] = {
    OpsecAction.SSH_AUTH: (
        "SSH authentication is an auditable, identity-bound operation: sshd "
        "records authentication and session activity by default on Linux."
    ),
    OpsecAction.SMB_AUTH: (
        "SMB session setup is an NTLM-authenticated operation that Windows "
        "records as logon telemetry when the relevant audit policies are "
        "enabled."
    ),
    OpsecAction.WINRM_AUTH: (
        "WS-Man authentication is a remote-management operation that Windows "
        "records as logon telemetry and in the WinRM operational log."
    ),
    OpsecAction.TCP_CONNECT: (
        "A bare TCP connection is a network event without identity context; "
        "it is only observable where connection auditing or network logging "
        "is configured."
    ),
    OpsecAction.SOCKS5_CONNECT: (
        "A SOCKS5 CONNECT is observable at the proxy (application layer) and "
        "on the network path; the proxy's own logging is outside PivotCheck's "
        "knowledge."
    ),
}


def assess_opsec(action: OpsecAction, platform: OpsecPlatform) -> OpsecResult:
    """Describe the likely observability of one explicitly described action.

    Pure and deterministic: a static knowledge table keyed by
    (action, platform). Unmapped combinations produce an explicit UNKNOWN
    result (never a guess), and the result always carries limitations.

    No credentials are accepted or inspected: this analysis needs only the
    action and the platform.
    """
    observations = _KNOWLEDGE.get((action, platform))
    if observations is None:
        return OpsecResult(
            action=action,
            platform=platform,
            observations=(),
            rationale=(
                "No OPSEC knowledge is documented for this action/platform "
                "combination. PivotCheck does not guess."
            ),
            limitations=(
                "UNKNOWN: this combination is not mapped.",
                *_BASE_LIMITATIONS,
            ),
        )
    return OpsecResult(
        action=action,
        platform=platform,
        observations=observations,
        rationale=_RATIONALE[action],
        limitations=_BASE_LIMITATIONS,
    )


def parse_action(value: str) -> OpsecAction:
    """Parse a CLI action string. Unknown actions fail closed."""
    try:
        return OpsecAction(value.strip().lower())
    except ValueError as exc:
        valid = ", ".join(action.value for action in OpsecAction)
        raise ValueError(
            f"unknown action: {value!r}. Valid actions: {valid}"
        ) from exc


def parse_platform(value: str) -> OpsecPlatform:
    """Parse a CLI platform string. Unknown platforms fail closed."""
    try:
        return OpsecPlatform(value.strip().lower())
    except ValueError as exc:
        valid = ", ".join(platform.value for platform in OpsecPlatform)
        raise ValueError(
            f"unknown platform: {value!r}. Valid platforms: {valid}"
        ) from exc
