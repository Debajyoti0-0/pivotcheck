"""Reusable remote-session lifecycle contract (v2.0 Phase 3).

Every transport (SSH now; WinRM/WMI/SMB in Phase 4) must satisfy
``run_remote_session_contract``. The contract verifies lifecycle
correctness independent of transport mechanics.
"""

from __future__ import annotations

import pytest

from pivotcheck.discovery.remote import (
    RemoteSessionMixin,
    SessionExecutionError,
    SessionTimeoutError,
)


def run_remote_session_contract(session_factory) -> None:
    """Executed the full lifecycle contract against one transport factory."""
    # 1. connect -> execute -> close
    session = session_factory()
    session.connect()
    out = session.execute(["echo", "probe"])
    assert isinstance(out, str)
    session.close()

    # 2. execute after close is a structured error, not silent misuse
    with pytest.raises(SessionExecutionError):
        session.execute(["echo", "again"])
    # close is idempotent
    session.close()

    # 3. execute before connect is rejected
    fresh = session_factory()
    with pytest.raises(SessionExecutionError):
        fresh.execute(["echo", "early"])
    fresh.close()

    # 4. connect after close is rejected (no zombie reuse)
    with pytest.raises(Exception):  # noqa: B017 - transport-specific class
        session.connect()

    # 5. deterministic execution order
    ordered = session_factory()
    ordered.connect()
    ordered.execute(["cmd-a"])
    ordered.execute(["cmd-b"])
    ordered.execute(["cmd-c"])
    ordered.close()
    assert ordered.calls == ["cmd-a", "cmd-b", "cmd-c"]

    # 6. context manager closes on success
    managed = session_factory()
    with managed as s:
        s.execute(["echo", "inside"])
    assert managed._closed is True

    # 7. context manager closes on failure AND preserves the original error
    failing = session_factory()
    with pytest.raises(RuntimeError, match="collection boom"), failing as s:
        s.execute(["echo", "before failure"])
        raise RuntimeError("collection boom")
    assert failing._closed is True

    # 8. timeout semantics: a transport-declared timeout surfaces as
    #    SessionTimeoutError and leaves the session closable.
    timing = session_factory()
    timing.connect()
    with pytest.raises(SessionTimeoutError):
        timing.execute(["timeouts"])
    timing.close()


class FakeRemoteSession(RemoteSessionMixin):
    """Deterministic in-memory transport for contract testing."""

    def __init__(
        self,
        outputs: dict[str, str] | None = None,
        fail_on: str | None = None,
        timeout_on: str | None = None,
        close_fails: bool = False,
    ) -> None:
        super().__init__()
        self.outputs = outputs or {}
        self.fail_on = fail_on
        self.timeout_on = timeout_on
        self.close_fails = close_fails
        self.calls: list[str] = []
        self.close_count = 0
        self.connect_count = 0

    def _do_connect(self) -> None:
        self.connect_count += 1

    def _do_execute(self, command) -> str:
        # Command recording is handled by RemoteSessionMixin.execute.
        name = command[0] if command else ""
        if name == self.timeout_on:
            raise SessionTimeoutError("remote command exceeded 15s")
        if name == self.fail_on:
            raise RuntimeError(f"transport failure on {name}")
        return self.outputs.get(name, f"stdout:{name}")

    def _do_close(self) -> None:
        self.close_count += 1
        if self.close_fails:
            raise RuntimeError("socket shutdown failed")
