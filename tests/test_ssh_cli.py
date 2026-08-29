"""CLI-level tests for SSH vantage-point selection (no real connections)."""

import pytest

from pivotcheck.cli import EXIT_FATAL, EXIT_OK, EXIT_USAGE, main
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.session import SessionIdentity


def local_snapshot() -> DiscoverySnapshot:
    return DiscoverySnapshot(
        "cli-host",
        "Linux 6.1",
        session=SessionIdentity("local-1", "local", "Local host"),
    )


class TestSSHArgumentValidation:
    def test_local_discovery_unchanged_without_ssh_flags(self, monkeypatch):
        from pivotcheck import cli

        monkeypatch.setattr(cli, "run_discovery", local_snapshot)
        assert main(["discover", "--summary"]) == EXIT_OK

    def test_invalid_host_is_usage_error(self, monkeypatch, capsys):
        code = main(["discover", "--ssh", "bad host!"])
        assert code == EXIT_USAGE
        assert "invalid SSH host" in capsys.readouterr().err

    def test_malformed_user_at_host_is_usage_error(self, capsys):
        code = main(["discover", "--ssh-user", "just-a-user"])
        assert code == EXIT_USAGE
        assert "USER@HOST" in capsys.readouterr().err

    def test_invalid_port_is_usage_error(self, capsys):
        assert main(["discover", "--ssh", "h", "--ssh-port", "99999"]) == EXIT_USAGE

    def test_timeout_out_of_range_is_usage_error(self, capsys):
        assert (
            main(["discover", "--ssh", "h", "--ssh-timeout", "999"]) == EXIT_USAGE
        )

    def test_provider_failure_is_fatal_not_usage(self, monkeypatch, capsys):
        from pivotcheck import cli
        from pivotcheck.discovery.provider import ProviderError

        class FailingProvider:
            def get_session(self):
                return SessionIdentity("x", "ssh", "ssh:x")

            def collect(self):
                raise ProviderError("auth failed")

        def failing_provider(args):
            return FailingProvider(), None

        monkeypatch.setattr(cli, "_ssh_provider", failing_provider)
        code = main(["discover", "--ssh", "real-host.example"])
        assert code == EXIT_FATAL
        err = capsys.readouterr().err
        assert "Unable to perform network discovery" in err

    def test_ssh_flags_are_mutually_exclusive(self):
        with pytest.raises(SystemExit) as exc:
            main(["discover", "--ssh", "a", "--ssh-user", "u@b"])
        assert exc.value.code == EXIT_USAGE