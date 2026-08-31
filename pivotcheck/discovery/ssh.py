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

import logging
import re
import shutil
import subprocess
from collections.abc import Callable
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
from pivotcheck.discovery.remote import (
    RemoteSessionError,
    RemoteSessionMixin,
    SessionConnectError,
    SessionExecutionError,
    SessionTimeoutError,
)
from pivotcheck.discovery.routes import collect_routes
from pivotcheck.models.network import DNSConfig
from pivotcheck.models.result import DiscoveryWarning
from pivotcheck.models.session import SessionIdentity
from pivotcheck.utils.system import CommandResult

LOG = logging.getLogger(__name__)

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


class SSHSession(RemoteSessionMixin):
    """RemoteSession implementation over the system OpenSSH client.

    Lifecycle semantics for the SSH transport: the OpenSSH client opens a
    connection per executed command, so ``connect()`` validates the
    transport (client binary availability) without emitting any network
    traffic, and ``close()`` finalizes the logical session. Every command
    runs through :class:`SSHExecutor`, which enforces fixed argv, the
    configured timeouts, and strict host-key policy.

    ``run`` exposes the full :class:`CommandResult` (returncode + stderr)
    for collectors that need it; the protocol-level ``execute`` returns
    stdout only. Both are available; neither changes v1 observable
    behavior.
    """

    def __init__(self, executor: Callable[[list[str]], CommandResult]) -> None:
        super().__init__()
        self._executor = executor

    def _executor_call(self, command: list[str]) -> CommandResult:
        return self._executor(list(command))

    def _do_connect(self) -> None:
        if (
            isinstance(self._executor, SSHExecutor)
            and getattr(self._executor, "_binary", None) is None
        ):
            # SSHExecutor validates binary availability at construction; a
            # missing client is a connect-stage failure for this transport.
            raise SessionConnectError("the OpenSSH client is not available")
        target = self._describe_target()
        LOG.debug("SSH session connect: %s", target)

    def _do_execute(self, command) -> str:
        if not command or not all(isinstance(token, str) for token in command):
            raise SessionExecutionError("remote commands must be string argv sequences")
        LOG.debug("SSH remote command: %s", command[0] if command else "(empty)")
        try:
            result = self._executor_call(list(command))
        except SSHProviderError as exc:
            if exc.kind == "timeout":
                raise SessionTimeoutError(str(exc).replace(f"{exc.kind}: ", "", 1)) from exc
            raise SessionExecutionError(str(exc)) from exc
        return result.stdout

    def run(self, command: list[str]) -> CommandResult:
        """Full-result execution for rc-aware collectors (compatibility)."""
        self._require_open()
        self.calls.append(command[0] if command else "")
        try:
            return self._executor_call(list(command))
        except RemoteSessionError:
            raise
        except SSHProviderError as exc:
            if exc.kind == "timeout":
                raise SessionTimeoutError(str(exc).replace(f"{exc.kind}: ", "", 1)) from exc
            raise SessionExecutionError(str(exc)) from exc
        except Exception as exc:
            raise SessionExecutionError(str(exc)) from exc

    def __call__(self, command: list[str]) -> CommandResult:
        """Executor-callable compatibility: collectors invoke the session
        exactly like the raw SSHExecutor they previously received."""
        return self.run(command)

    def _do_close(self) -> None:
        LOG.debug("SSH session closed: %s", self._describe_target())

    def _describe_target(self) -> str:
        config = getattr(self._executor, "_config", None)
        host = getattr(config, "host", "unknown")
        port = getattr(config, "port", 22)
        # Metadata only: never authentication material (none is ever held).
        return f"{host}:{port} (auth: delegated to operator SSH config)"


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
        self._transport: SSHSession | None = None
        if session is not None and session.provider != "ssh":
            raise ValueError("SSHProvider requires a session with provider='ssh'")
        self._session = session

    def transport(self) -> SSHSession:
        """Open a new logical SSHSession (factory).

        Session ownership: the provider owns the transport; collectors only
        execute through it. Each collection run opens a fresh session and
        always closes it — a closed session is never reused (no zombie
        connections). The most recently used session is retained on
        ``_last_transport`` for inspection and testing.
        """
        return SSHSession(self._executor)

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

        # Lifecycle guarantee: the session always closes, including when a
        # collector raises; cleanup failures never mask the original error.
        with self.transport() as session:
            interfaces = safe("interfaces", lambda: collect_interfaces(session))
            routes = safe("routes", lambda: collect_routes(session))
            neighbors = safe("neighbors", lambda: collect_neighbors(session))
            connections = safe("connections", lambda: collect_connections(session))
            dns_content = safe("dns", lambda: self._read_resolv_conf(session))
        self._last_transport = session

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

    def _read_resolv_conf(self, session: SSHSession) -> str | None:
        result = session.run(["cat", "/etc/resolv.conf"])
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
