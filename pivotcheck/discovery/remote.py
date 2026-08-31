"""Transport-neutral remote session architecture (v2.0 Phase 3).

Defines the lifecycle contract every remote transport implements:

    CREATE -> CONNECT -> EXECUTE -> (COLLECT) -> CLOSE -> DESTROY

Layer responsibilities are strictly separated:

- ``RemoteSession`` (this module) — transport only: connect, execute a
  fixed argv command, close. Knows nothing about evidence semantics.
- ``RemoteCollector`` — orchestrates named command specs over a session
  and hands raw stdout to parser callables.
- Platform parsers — raw output -> normalized models.
- Analysis — normalized models -> conclusions (pure; never a session).

Guarantees:

- Deterministic cleanup: sessions used as context managers always close,
  including when collection fails; a cleanup failure never masks the
  original exception.
- Explicit targeting: a session is always bound to one operator-supplied
  vantage point. No transport ever discovers its own targets.
- Credential safety: configuration carries authentication *metadata*
  only; secret material, when a future transport adds it, must flow
  through :mod:`pivotcheck.utils.redaction` and never into evidence,
  logs, or exceptions.

SSH is the only transport implemented in Phase 3 (see
:pmod:`pivotcheck.discovery.ssh`). WinRM/WMI/SMB are planned, not
currently available.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from pivotcheck.utils.system import CommandResult

if TYPE_CHECKING:
    # Type-checking only: typing_extensions is NOT a runtime dependency.
    from typing_extensions import Self

LOG = logging.getLogger(__name__)


class RemoteSessionError(RuntimeError):
    """Base class for structured remote-session failures."""

    kind = "session-error"

    def __init__(self, detail: str) -> None:
        super().__init__(f"{self.kind}: {detail}")
        self.detail = detail


class SessionConnectError(RemoteSessionError):
    """The session could not be established (transport unavailable/unreachable)."""

    kind = "connect"


class SessionAuthenticationError(RemoteSessionError):
    """Authentication failed. Detail must never contain credential material."""

    kind = "authentication"


class SessionExecutionError(RemoteSessionError):
    """A command could not be executed on an established session."""

    kind = "execution"


class SessionTimeoutError(RemoteSessionError):
    """An operation exceeded its configured timeout."""

    kind = "timeout"


class SessionCleanupError(RemoteSessionError):
    """Closing the session failed. Never raised when it would mask an
    in-flight exception from the managed block."""


class RemoteSession(Protocol):
    """Transport-neutral lifecycle contract for remote vantage points."""

    def connect(self) -> None: ...

    def execute(self, command: Sequence[str]) -> str: ...

    def close(self) -> None: ...


class RemoteSessionMixin:
    """Shared lifecycle machinery: misuse detection + guaranteed cleanup.

    Transports mix this in and implement ``_do_connect``, ``_do_execute``,
    and ``_do_close``. The mixin guarantees:

    - ``execute`` before ``connect`` or after ``close`` is a structured
      ``SessionExecutionError`` (never silent misuse).
    - ``close`` is idempotent.
    - Context-manager use always closes, even on failure, and a cleanup
      failure never hides the block's original exception.
    """

    def __init__(self) -> None:
        self._connected = False
        self._closed = False
        self.calls: list[str] = []  # executed command names, in order

    def _do_connect(self) -> None: ...

    def _do_execute(self, command: Sequence[str]) -> str:
        raise NotImplementedError

    def _do_close(self) -> None: ...

    def connect(self) -> None:
        if self._closed:
            raise SessionConnectError("session already closed; create a new session")
        if self._connected:
            return  # idempotent connect
        try:
            self._do_connect()
        except RemoteSessionError:
            raise
        except Exception as exc:
            raise SessionConnectError(str(exc)) from exc
        self._connected = True

    def execute(self, command: Sequence[str]) -> str:
        self._require_open()
        self.calls.append(command[0] if command else "")
        try:
            return self._do_execute(command)
        except RemoteSessionError:
            raise
        except Exception as exc:
            raise SessionExecutionError(str(exc)) from exc

    def close(self) -> None:
        if self._closed:
            return  # idempotent close
        self._closed = True
        self._connected = False
        try:
            self._do_close()
        except Exception as exc:
            raise SessionCleanupError(str(exc)) from exc

    def _require_open(self) -> None:
        if self._closed:
            raise SessionExecutionError("session is closed")
        if not self._connected:
            raise SessionExecutionError("session is not connected; call connect() first")

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.close()
        except Exception as cleanup_exc:
            if exc_type is None:
                raise
            # Never mask the original failure; surface cleanup separately.
            LOG.warning(
                "session cleanup failed (%s); original error preserved: %s",
                cleanup_exc,
                exc,
            )


@dataclass(frozen=True)
class RemoteSessionConfig:
    """Transport-neutral session description (metadata only, no secrets).

    ``proxy_config`` is reserved for a future phase; it is represented as
    an opaque placeholder so transports can accept transport configuration
    without another architecture change. It is never populated by default
    and no proxy behavior is implemented yet.
    """

    target: str
    port: int = 22
    connect_timeout: float = 10.0
    command_timeout: float = 15.0
    auth_method: str = "delegated"  # metadata only; e.g. "ssh-agent"
    proxy_config: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("remote session target is required")
        if not 1 <= self.port <= 65535:
            raise ValueError(f"invalid remote session port: {self.port}")
        if not 0 < self.connect_timeout <= 120:
            raise ValueError("connect_timeout must be within (0, 120] seconds")
        if not 0 < self.command_timeout <= 300:
            raise ValueError("command_timeout must be within (0, 300] seconds")


@dataclass(frozen=True)
class CommandSpec:
    """One named collection command: fixed argv plus its parser.

    ``argv`` tokens always originate from PivotCheck's collector
    definitions, never from operator input.
    """

    name: str
    argv: tuple[str, ...]
    parser: Callable[[str], object]
    required: bool = False  # required specs failing => collector failure


class RemoteCollector:
    """Executes named command specs over one session and parses output.

    Transport-only orchestration: raw stdout -> parser -> parsed value.
    Individual spec failures degrade to warnings; only ``required`` specs
    failing escalates. Returns ``(results, warnings)``.
    """

    def __init__(
        self,
        session: RemoteSession,
        specs: Sequence[CommandSpec],
        executor: Callable[[Sequence[str]], CommandResult] | None = None,
    ) -> None:
        self._session = session
        self._specs = tuple(specs)
        self._executor = executor  # None -> session.execute (stdout only)

    def collect(self) -> tuple[dict[str, object], list[tuple[str, str]]]:
        results: dict[str, object] = {}
        warnings: list[tuple[str, str]] = []
        for spec in self._specs:  # deterministic, definition order
            try:
                if self._executor is not None:
                    raw = self._executor(spec.argv).stdout
                else:
                    raw = self._session.execute(spec.argv)
                results[spec.name] = spec.parser(raw)
            except Exception as exc:
                warnings.append((spec.name, f"Could not collect {spec.name}: {exc}. Continuing."))
                if spec.required:
                    raise
        return results, warnings
