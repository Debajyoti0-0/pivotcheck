"""Phase 3 tests: RemoteSession abstraction, SSH lifecycle, redaction."""

from __future__ import annotations

import logging

import pytest

from pivotcheck.discovery.provider import ProviderError
from pivotcheck.discovery.remote import (
    RemoteCollector,
    RemoteSessionConfig,
    SessionCleanupError,
    SessionConnectError,
    SessionExecutionError,
    SessionTimeoutError,
)
from pivotcheck.discovery.ssh import (
    SSHConfig,
    SSHExecutor,
    SSHProvider,
    SSHProviderError,
    SSHSession,
)
from pivotcheck.utils.redaction import REDACTED, SecretRedactor, redact
from pivotcheck.utils.system import CommandResult
from tests.remote_session_contract import FakeRemoteSession, run_remote_session_contract

# ---------------------------------------------------------------------------
# Transport-neutral contract (foundation for all Phase 4 transports)
# ---------------------------------------------------------------------------


class TestTransportContract:
    def test_fake_remote_session_satisfies_contract(self):
        run_remote_session_contract(lambda: FakeRemoteSession(timeout_on="timeouts"))

    def test_ssh_session_satisfies_contract(self):
        def factory() -> SSHSession:
            outputs = {"echo": "probe\n", "cmd-a": "a\n", "cmd-b": "b\n", "cmd-c": "c\n"}

            def executor(command: list[str]) -> CommandResult:
                if command[0] == "timeouts":
                    raise SSHProviderError("timeout", "remote command exceeded 15s")
                return CommandResult(0, outputs.get(command[0], ""), "")

            return SSHSession(executor)

        run_remote_session_contract(factory)

    def test_cleanup_failure_does_not_mask_original_error(self):
        def factory() -> FakeRemoteSession:
            return FakeRemoteSession(close_fails=True)

        # The contract still applies; cleanup failure is checked separately.
        session = factory()
        session.connect()
        with pytest.raises(RuntimeError, match="collection boom"), session as s:
            s.execute(["echo", "x"])
            raise RuntimeError("collection boom")
        assert session.close_count == 1  # close was attempted exactly once

    def test_cleanup_failure_without_block_error_raises_cleanup_error(self):
        session = FakeRemoteSession(close_fails=True)
        with pytest.raises(SessionCleanupError), session as s:
            s.execute(["echo", "x"])


# ---------------------------------------------------------------------------
# SSHSession lifecycle specifics
# ---------------------------------------------------------------------------


class TestSSHSessionLifecycle:
    def _executor(self, output: str = "ok\n") -> object:
        def executor(command: list[str]) -> CommandResult:
            return CommandResult(0, output, "")

        return executor

    def test_connect_validates_transport_before_use(self):
        session = SSHSession(self._executor())
        with pytest.raises(SessionExecutionError):
            session.execute(["hostname"])  # not connected yet
        session.connect()
        assert session.execute(["hostname"]) == "ok\n"

    def test_closed_session_rejects_execution(self):
        session = SSHSession(self._executor())
        session.connect()
        session.close()
        with pytest.raises(SessionExecutionError, match="closed"):
            session.run(["hostname"])

    def test_non_string_argv_rejected(self):
        session = SSHSession(self._executor())
        session.connect()
        with pytest.raises(SessionExecutionError, match="argv sequences"):
            session.execute(["ip", "route", 42])  # type: ignore[list-item]

    def test_executor_error_wrapped_as_execution_error(self):
        def executor(command: list[str]) -> CommandResult:
            raise RuntimeError("connection reset")

        session = SSHSession(executor)
        session.connect()
        with pytest.raises(SessionExecutionError, match="connection reset"):
            session.execute(["hostname"])
        # Session remains closable after a failed execution.
        session.close()

    def test_timeout_classified_as_session_timeout(self):
        """Executor timeout errors surface as SessionTimeoutError with the
        original detail preserved (v1 callers catch Exception, so behavior
        is unchanged; classification is strictly improved)."""

        def executor(command: list[str]) -> CommandResult:
            raise SSHProviderError("timeout", "remote command exceeded 15s")

        session = SSHSession(executor)
        session.connect()
        with pytest.raises(SessionTimeoutError, match="remote command exceeded 15s"):
            session.run(["hostname"])
        with pytest.raises(SessionTimeoutError, match="remote command exceeded"):
            session.execute(["hostname"])
        # Session remains closable after a failed execution.
        session.close()

    def test_connect_failure_wraps_as_session_connect_error(self):
        # A real SSHExecutor whose client binary vanished at connect time.
        executor = SSHExecutor.__new__(SSHExecutor)
        executor._binary = None
        executor._config = SSHConfig(host="h")
        session = SSHSession(executor)
        with pytest.raises(SessionConnectError):
            session.connect()

    def test_logging_never_contains_secrets(self, caplog):
        session = SSHSession(self._executor())
        with caplog.at_level(logging.DEBUG, logger="pivotcheck.discovery.ssh"):
            session.connect()
            session.execute(["hostname"])
            session.close()
        joined = "\n".join(record.getMessage() for record in caplog.records)
        assert "password" not in joined.lower()
        assert "DEADBEEF" not in joined  # no credential material is ever held


# ---------------------------------------------------------------------------
# SSHProvider lifecycle integration (v1 behavior preserved)
# ---------------------------------------------------------------------------


class _FakeTransport:
    """Same fake-transport shape the existing SSH provider tests use."""

    def __init__(self, call=None, results=None, error=None):
        self._call = call
        self._results = results or {}
        self._error = error

    def __call__(self, command):
        if self._error is not None:
            raise self._error
        if self._call is not None:
            return self._call(command)
        return CommandResult(0, self._results.get(command[0], ""), "")


def _make_provider(transport) -> SSHProvider:
    provider = SSHProvider.__new__(SSHProvider)
    provider._executor = transport
    provider._label = None
    provider._session = None
    provider._transport = None
    return provider


class TestSSHProviderLifecycle:
    def test_collect_closes_session_on_success(self):
        table = {
            "ip": "2: eth0    inet 10.50.1.5/24 brd 10.50.1.255 scope global eth0\n",
            "cat": "nameserver 10.0.0.53\n",
            "hostname": "remote-vantage\n",
        }
        provider = _make_provider(_FakeTransport(results=table))
        collection = provider.collect()
        assert collection.hostname == "remote-vantage"
        assert provider._last_transport._closed is True

    def test_collect_closes_session_on_failure(self):
        provider = _make_provider(_FakeTransport(error=RuntimeError("network unreachable")))
        with pytest.raises(SSHProviderError, match="collection-failed"):
            provider.collect()
        assert provider._last_transport._closed is True

    def test_collect_reopens_a_fresh_session_each_run(self):
        table = {"cat": "nameserver 10.0.0.53\n"}
        provider = _make_provider(_FakeTransport(results=table))
        provider.collect()
        provider.collect()  # a closed session must never be reused
        assert provider._last_transport._closed is True

    def test_provider_error_kinds_unchanged(self):
        provider = _make_provider(_FakeTransport(error=RuntimeError("down")))
        with pytest.raises(ProviderError):
            provider.collect()


# ---------------------------------------------------------------------------
# RemoteCollector orchestration
# ---------------------------------------------------------------------------


class TestRemoteCollector:
    def test_specs_execute_in_order_and_degrade_individually(self):
        from pivotcheck.discovery.remote import CommandSpec

        session = FakeRemoteSession(outputs={"alpha": "parsed-alpha\n"})

        def parser(raw: str) -> str:
            return raw.strip()

        def failing_parser(raw: str) -> str:
            raise ValueError("unparseable")

        collector = RemoteCollector(
            session,
            (
                CommandSpec("alpha", ("alpha",), parser),
                CommandSpec("beta", ("beta",), failing_parser),
            ),
        )
        session.connect()
        results, warnings = collector.collect()
        assert results["alpha"] == "parsed-alpha"
        assert "beta" not in results
        assert warnings[0][0] == "beta"
        assert session.calls == ["alpha", "beta"]

    def test_required_spec_failure_escalates(self):
        from pivotcheck.discovery.remote import CommandSpec

        session = FakeRemoteSession(fail_on="core")

        def parser(raw: str) -> str:
            return raw

        collector = RemoteCollector(
            session, (CommandSpec("core", ("core",), parser, required=True),)
        )
        session.connect()
        with pytest.raises(SessionExecutionError):
            collector.collect()


# ---------------------------------------------------------------------------
# RemoteSessionConfig: explicit targeting, metadata-only authentication
# ---------------------------------------------------------------------------


class TestRemoteSessionConfig:
    def test_valid_config(self):
        config = RemoteSessionConfig(target="vantage.internal", port=2222)
        assert config.target == "vantage.internal"
        assert config.auth_method == "delegated"
        assert config.proxy_config is None  # future capability, not implemented

    def test_explicit_target_required(self):
        with pytest.raises(ValueError, match="target is required"):
            RemoteSessionConfig(target="")

    def test_port_and_timeout_bounds(self):
        with pytest.raises(ValueError, match="port"):
            RemoteSessionConfig(target="h", port=0)
        with pytest.raises(ValueError, match="connect_timeout"):
            RemoteSessionConfig(target="h", connect_timeout=0)
        with pytest.raises(ValueError, match="command_timeout"):
            RemoteSessionConfig(target="h", command_timeout=999)

    def test_config_holds_no_secret_field(self):
        import dataclasses

        names = {f.name for f in dataclasses.fields(RemoteSessionConfig)}
        forbidden = {"password", "secret", "token", "hash", "ticket", "key_material"}
        assert not (names & forbidden)


# ---------------------------------------------------------------------------
# Credential redaction boundary
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_replaces_known_secrets(self):
        redactor = SecretRedactor(["s3cret-value", "hunter2"])
        assert redactor.redact("connect with s3cret-value now") == f"connect with {REDACTED} now"
        assert redactor.redact("p=hunter2;") == f"p={REDACTED};"

    def test_empty_secret_is_ignored(self):
        assert SecretRedactor([""]).redact("untouched") == "untouched"

    def test_exception_message_redaction(self):
        redactor = SecretRedactor(["s3cret-value"])
        original = ValueError("auth failed with s3cret-value")
        assert redactor.redact_message(original) == f"auth failed with {REDACTED}"

    def test_one_shot_helper(self):
        assert redact("token=abc123", ["abc123"]) == f"token={REDACTED}"

    def test_serialized_objects_have_no_secret_material(self):
        session = FakeRemoteSession(outputs={"alpha": "fine\n"})
        session.connect()
        out = session.execute(["alpha"])
        assert "s3cret" not in out  # transports never carry material by design
        session.close()
