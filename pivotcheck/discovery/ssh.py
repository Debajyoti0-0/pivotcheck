"""SSH transport provider: observe a remote vantage point.

Transport concern ONLY. This module executes the *same fixed discovery
commands* the local collectors define, on a remote host, through the
system OpenSSH client, and feeds raw stdout into the existing parsers.
No analysis, comparison, or rendering logic lives here.

Security contract:

- Fixed argv construction; no local shell interpolation.
- Only collector-defined commands are ever sent; there is no generic
  remote-execution API exposed to operators.
- Host-key verification is ON by default (OpenSSH ``StrictHostKeyChecking=yes``
  semantics under ``BatchMode``); disabling verification is impossible.
  An explicit opt-in ``ACCEPT_NEW`` policy auto-accepts only *new* hosts
  while still rejecting changed keys.
- Authentication delegates entirely to the operator's existing SSH setup
  (agent, keys, ~/.ssh/config). PivotCheck never accepts, stores, logs,
  or serializes credentials. ``BatchMode=yes`` guarantees no interactive
  password prompt can block or leak.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum

from pivotcheck.discovery.connections import collect_connections
from pivotcheck.discovery.dns import parse_resolv_conf
from pivotcheck.discovery.interfaces import collect_interfaces
from pivotcheck.discovery.neighbors import collect_neighbors
from pivotcheck.discovery.provider import (
    CollectedDiscoveryData,
    ProviderError,
)
from pivotcheck.discovery.routes import collect_routes
from pivotcheck.models.network import DNSConfig
from pivotcheck.models.result import DiscoveryWarning
from pivotcheck.models.session import SessionIdentity
from pivotcheck.utils.system import CommandResult

_SSH_BINARY = "ssh"
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$"
)
_USER_RE = re.compile(r"^[a-z_][a-z0-9._-]{0,31}$", re.IGNORECASE)


class HostKeyPolicy(str, Enum):
    """How the system OpenSSH client treats unverified host keys."""

    # Values are literal OpenSSH StrictHostKeyChecking options.
    STRICT = "yes"  # reject unknown AND changed keys (default)
    ACCEPT_NEW = "accept-new"  # trust first contact; changed keys still fail


class SSHConfigError(ValueError):
    """Invalid SSH target configuration."""


@dataclass(frozen=True)
class SSHConfig:
    """Validated, secret-free description of a remote vantage point."""

    host: str
    port: int = 22
    user: str | None = None  # None -> delegate to ssh config / agent identity
    connect_timeout: float = 10.0
    command_timeout: float = 15.0
    key_file: str | None = None  # reference only; never read or stored
    host_key_policy: HostKeyPolicy = HostKeyPolicy.STRICT

    def __post_init__(self) -> None:
        if not self.host or not _HOST_RE.match(self.host):
            raise SSHConfigError(f"invalid SSH host: {self.host!r}")
        if not 1 <= self.port <= 65535:
            raise SSHConfigError(f"invalid SSH port: {self.port}")
        if self.user is not None and not _USER_RE.match(self.user):
            raise SSHConfigError(f"invalid SSH user: {self.user!r}")
        if not 0 < self.connect_timeout <= 60:
            raise SSHConfigError("connect_timeout must be within (0, 60] seconds")
        if not 0 < self.command_timeout <= 120:
            raise SSHConfigError("command_timeout must be within (0, 120] seconds")


class SSHProviderError(ProviderError):
    """The SSH provider could not complete collection."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


class SSHExecutor:
    """Runs fixed argv commands on a remote host via system OpenSSH.

    Implements the same callable boundary the collectors accept as
    ``executor``; swap-in is invisible to parsers and models.
    """

    def __init__(self, config: SSHConfig) -> None:
        self._config = config
        binary = shutil.which(_SSH_BINARY)
        if binary is None:
            raise SSHProviderError(
                "transport-unavailable",
                "the OpenSSH client ('ssh') was not found on this system",
            )
        self._binary = binary

    def _argv(self, command: list[str]) -> list[str]:
        config = self._config
        argv = [
            self._binary,
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(config.connect_timeout)}",
            "-o", f"StrictHostKeyChecking={config.host_key_policy.value}",
        ]
        if config.port != 22:
            argv += ["-p", str(config.port)]
        if config.key_file:
            argv += ["-i", config.key_file]
        target = f"{config.user}@{config.host}" if config.user else config.host
        # The remote side receives the fixed command tokens joined by spaces;
        # every token originates from PivotCheck's own collector definitions,
        # never from operator input.
        return [*argv, target, "--", *command]

    def __call__(self, command: list[str]) -> CommandResult:
        try:
            proc = subprocess.run(
                self._argv(command),
                capture_output=True,
                text=True,
                timeout=self._config.command_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SSHProviderError(
                "timeout",
                f"remote command exceeded {self._config.command_timeout}s",
            ) from exc
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)


class SSHProvider:
    """Collect normalized discovery inputs from one remote vantage point."""

    def __init__(
        self,
        config: SSHConfig,
        session: SessionIdentity | None = None,
        label: str | None = None,
    ) -> None:
        self._executor = SSHExecutor(config)
        self._label = label
        if session is not None and session.provider != "ssh":
            raise ValueError("SSHProvider requires a session with provider='ssh'")
        self._session = session

    def get_session(self) -> SessionIdentity:
        if self._session is not None:
            return self._session
        hostname = self._safe_remote_hostname()
        display_name = self._label or hostname or self._executor_target()
        self._session = SessionIdentity(
            provider="ssh", display_name=f"ssh:{display_name}"
        )
        return self._session

    def collect(self) -> CollectedDiscoveryData:
        warnings: list[DiscoveryWarning] = []

        def safe(name: str, fn):
            try:
                return fn()
            except Exception as exc:  # noqa: BLE001 - degradation is deliberate
                warnings.append(
                    DiscoveryWarning(
                        source=name,
                        message=f"Could not collect {name} over ssh: {exc}. Continuing.",
                    )
                )
                return None

        interfaces = safe("interfaces", lambda: collect_interfaces(self._executor))
        routes = safe("routes", lambda: collect_routes(self._executor))
        neighbors = safe("neighbors", lambda: collect_neighbors(self._executor))
        connections = safe("connections", lambda: collect_connections(self._executor))
        dns_content = safe("dns", self._read_resolv_conf)
        dns = parse_resolv_conf(dns_content) if dns_content else DNSConfig()

        if all(
            value in (None, ())
            for value in (interfaces, routes, neighbors, connections, dns_content)
        ):
            raise SSHProviderError(
                "collection-failed",
                "no discovery data could be collected from the remote host",
            )

        hostname = self._safe_remote_hostname() or "unknown"
        return CollectedDiscoveryData(
            hostname=hostname,
            os_name="remote (Linux assumed)",
            interfaces=interfaces or (),
            routes=routes or (),
            neighbors=neighbors or (),
            dns=dns,
            connections=connections or (),
            warnings=tuple(warnings),
        )

    def _read_resolv_conf(self) -> str | None:
        result = self._executor(["cat", "/etc/resolv.conf"])
        if result.returncode != 0:
            raise RuntimeError(
                f"cat exited {result.returncode}: {result.stderr.strip()}"
            )
        return result.stdout

    def _safe_remote_hostname(self) -> str | None:
        """Best-effort remote hostname; failure degrades, never aborts."""
        try:
            result = self._executor(["hostname"])
        except Exception:  # noqa: BLE001 - identity is best-effort
            return None
        name = result.stdout.strip()
        return name if result.returncode == 0 and name else None

    def _executor_target(self) -> str:
        config = getattr(self._executor, "_config", None)
        return getattr(config, "host", "unknown")
