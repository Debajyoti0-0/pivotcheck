"""SSH provider tests: pure config, argv construction, mocked transport.

No test connects to a real SSH server. Transport is exercised through a
fake executor and by inspecting argv construction; integration with a
live sshd is deliberately out of the default suite.
"""

import subprocess

import pytest

from pivotcheck.discovery.engine import run_discovery
from pivotcheck.discovery.ssh import (
    HostKeyPolicy,
    SSHConfig,
    SSHConfigError,
    SSHExecutor,
    SSHProvider,
    SSHProviderError,
)
from pivotcheck.models.session import SessionIdentity
from pivotcheck.utils.system import CommandResult


class TestSSHConfig:
    def test_valid_minimal_config(self):
        config = SSHConfig(host="10.0.0.5")
        assert config.host_key_policy is HostKeyPolicy.STRICT
        assert config.port == 22

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"host": ""},
            {"host": "bad host!"},
            {"host": "-leading-dash"},  # option-injection attempt
            {"host": "ok", "port": 0},
            {"host": "ok", "port": 70000},
            {"host": "ok", "user": "bad user"},
            {"host": "ok", "user": "user;id"},
            {"host": "ok", "connect_timeout": 0},
            {"host": "ok", "connect_timeout": 61},
            {"host": "ok", "command_timeout": -1},
            {"host": "ok", "command_timeout": 121},
        ],
    )
    def test_invalid_configs_are_rejected(self, kwargs):
        with pytest.raises(SSHConfigError):
            SSHConfig(**kwargs)

    def test_config_contains_no_secret_field(self):
        data = SSHConfig(host="h", key_file="/tmp/id_ed25519").__dict__
        assert "password" not in {key.lower() for key in data}


class TestArgvConstruction:
    def make_executor(
        self,
        *,
        host_key_policy: HostKeyPolicy = HostKeyPolicy.STRICT,
        port: int = 22,
        user: str | None = None,
        connect_timeout: float = 10.0,
        command_timeout: float = 15.0,
        key_file: str | None = None,
    ):
        defaults = {
            "host": "target-host",
            "host_key_policy": host_key_policy,
            "port": port,
            "user": user,
            "connect_timeout": connect_timeout,
            "command_timeout": command_timeout,
            "key_file": key_file,
        }
        executor = SSHConfig(**defaults)
        return SSHExecutor.__new__(SSHExecutor), executor

    def test_strict_is_default_and_batch_mode_always_set(self):
        fake, config = self.make_executor()
        import shutil

        binary = shutil.which("ssh")
        assert binary is not None
        fake._binary = binary
        fake._config = config
        argv = fake._argv(["ip", "route", "show"])
        assert "BatchMode=yes" in argv
        # OpenSSH's strictest literal option value is 'yes'.
        assert "StrictHostKeyChecking=yes" in argv
        assert argv[-5] == "target-host"
        assert argv[-4] == "--"  # end-of-options guard before remote command
        assert argv[-3:] == ["ip", "route", "show"]

    def test_accept_new_policy_is_explicit(self):
        fake, config = self.make_executor(
            host_key_policy=HostKeyPolicy.ACCEPT_NEW
        )
        import shutil

        binary = shutil.which("ssh")
        assert binary is not None
        fake._binary = binary
        fake._config = config
        assert (
            "StrictHostKeyChecking=accept-new"
            in fake._argv(["hostname"])
        )

    def test_user_port_and_key_are_fixed_argv_tokens(self):
        fake, config = self.make_executor(
            user="op", port=2222, key_file="/home/op/id_ed25519"
        )
        import shutil

        binary = shutil.which("ssh")
        assert binary is not None
        fake._binary = binary
        fake._config = config
        argv = fake._argv(["ip", "neigh", "show"])
        assert "op@target-host" in argv
        assert argv[argv.index("-p") + 1] == "2222"
        assert argv[argv.index("-i") + 1] == "/home/op/id_ed25519"

    def test_no_shell_metacharacters_in_argv(self):
        fake, config = self.make_executor(user="op")
        import shutil

        binary = shutil.which("ssh")
        assert binary is not None
        fake._binary = binary
        fake._config = config
        argv = fake._argv(["ip", "-o", "addr", "show"])
        assert not any(token in (";", "|", "&", "$(", "`") for token in argv)


class FakeTransport:
    """Records commands; delegates behavior to an optional call function."""

    def __init__(self, results=None, error=None, call=None):
        self.commands: list[list[str]] = []
        self.results = results or {}
        self.error = error
        self._call = call

    def __call__(self, command):
        self.commands.append(list(command))
        if self.error:
            raise self.error
        if self._call is not None:
            return self._call(command)
        stdout = self.results.get(command[0], "")
        return CommandResult(0, stdout, "")


def make_provider(transport):
    provider = SSHProvider.__new__(SSHProvider)
    provider._executor = transport
    provider._label = None
    provider._session = None
    return provider


class TestRemoteCollection:
    def test_full_collection_uses_existing_parsers(self):
        table = {
            ("ip", "-o", "addr", "show"): "2: eth0    inet 10.50.1.5/24 brd 10.50.1.255 scope global eth0\n",
            ("ip", "-o", "link", "show"): "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n    link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff\n",
            ("ip", "route", "show"): "default via 10.50.1.1 dev eth0 proto dhcp metric 100\n10.50.1.0/24 dev eth0 proto kernel scope link src 10.50.1.5\n",
            ("ip", "neigh", "show"): "10.50.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n",
            ("cat", "/etc/resolv.conf"): "nameserver 10.0.0.53\n",
            ("hostname",): "remote-vantage\n",
        }

        def smart_call(command):
            return CommandResult(0, table.get(tuple(command), ""), "")

        transport = FakeTransport(call=smart_call)
        provider = make_provider(transport)
        collection = provider.collect()
        session = provider.get_session()
        snapshot = run_discovery(provider)

        assert session.provider == "ssh"
        assert session.display_name == "ssh:remote-vantage"
        assert any(net.cidr == "10.50.1.0/24" for net in snapshot.networks)
        assert snapshot.hostname == "remote-vantage"
        assert collection.dns.servers[0].address == "10.0.0.53"

    def test_partial_collector_failure_degrades_to_warnings(self):
        def failing_ip(command):
            if command[:2] == ["ip", "-o"]:
                raise RuntimeError("connection reset")
            return CommandResult(0, "", "")

        transport = FakeTransport(call=failing_ip)
        provider = make_provider(transport)
        collection = provider.collect()  # must NOT raise
        sources = {warning.source for warning in collection.warnings}
        assert "interfaces" in sources

    def test_total_collection_failure_raises_provider_error(self):
        transport = FakeTransport(error=RuntimeError("network unreachable"))
        provider = make_provider(transport)
        with pytest.raises(SSHProviderError, match="collection-failed"):
            provider.collect()

    def test_identity_degrades_gracefully_without_hostname(self):
        transport = FakeTransport(results={"cat": "nameserver 10.0.0.53\n"})
        provider = make_provider(transport)
        session = provider.get_session()
        assert session.provider == "ssh"
        assert "@" not in session.display_name or session.display_name.startswith("ssh:")

    def test_explicit_session_is_preserved(self):
        identity = SessionIdentity("vantage-b", "ssh", "ssh:dmz-host")
        provider = SSHProvider(config=None, session=identity) if False else make_provider(FakeTransport())
        provider._session = identity
        assert provider.get_session() is identity


class TestTimeoutAndTransportErrors:
    def test_timeout_maps_to_provider_error(self, monkeypatch):
        executor = SSHExecutor.__new__(SSHExecutor)
        import shutil

        binary = shutil.which("ssh")
        assert binary is not None
        executor._binary = binary
        executor._config = SSHConfig(host="h", command_timeout=15)

        def boom(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=15)

        monkeypatch.setattr(subprocess, "run", boom)
        with pytest.raises(SSHProviderError, match="timeout"):
            executor(["ip", "route", "show"])

    def test_missing_ssh_binary_is_transport_unavailable(self, monkeypatch):
        monkeypatch.setattr(
            "pivotcheck.discovery.ssh.shutil.which", lambda name: None
        )
        with pytest.raises(SSHProviderError, match="transport-unavailable"):
            SSHExecutor(SSHConfig(host="h"))  # type: ignore[assignment]