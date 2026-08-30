"""Unit tests for session identity and the provider/engine boundary."""

import json
from dataclasses import FrozenInstanceError

import pytest

from pivotcheck.analysis.comparison import baseline_from_snapshot
from pivotcheck.discovery.engine import run_discovery
from pivotcheck.discovery.local import LocalProvider
from pivotcheck.discovery.provider import (
    CollectedDiscoveryData,
    ProviderError,
)
from pivotcheck.models.network import (
    Confidence,
    DiscoveredNetwork,
    Interface,
    InterfaceState,
    IPAddress,
    NetworkOrigin,
)
from pivotcheck.models.result import DiscoverySnapshot, DiscoveryWarning
from pivotcheck.models.session import SessionIdentity


class FakeProvider:
    def __init__(self, session, collection=None, error=None):
        self.session = session
        self.collection = collection or CollectedDiscoveryData("fake", "Test OS")
        self.error = error

    def get_session(self):
        return self.session

    def collect(self):
        if self.error:
            raise self.error
        return self.collection


def test_explicit_session_identity_is_immutable_and_serializable():
    session = SessionIdentity("vantage-a", "fake", "Internal server")
    assert session.to_dict() == {
        "session_id": "vantage-a",
        "provider": "fake",
        "display_name": "Internal server",
    }
    assert json.loads(json.dumps(session.to_dict()))["provider"] == "fake"
    with pytest.raises(FrozenInstanceError):
        session.display_name = "changed"


def test_generated_session_identity_is_safe_and_non_empty():
    first = SessionIdentity()
    second = SessionIdentity()
    assert first.session_id
    assert first.session_id != second.session_id
    assert first.provider == "local"


@pytest.mark.parametrize(
    ("session_id", "provider", "display_name"),
    [("", "local", "Local"), ("id", "", "Local"), ("id", "local", "  ")],
)
def test_session_identity_rejects_empty_values(session_id, provider, display_name):
    with pytest.raises(ValueError):
        SessionIdentity(session_id, provider, display_name)


def test_fake_provider_is_analyzed_and_identity_is_attached():
    session = SessionIdentity("fake-a", "fake", "Fake A")
    collection = CollectedDiscoveryData(
        hostname="fake-host",
        os_name="FakeOS",
        interfaces=(
            Interface(
                "eth0",
                InterfaceState.UP,
                ipv4_addresses=(IPAddress("10.20.1.2", 24),),
            ),
        ),
        warnings=(DiscoveryWarning("neighbors", "permission denied"),),
    )
    snapshot = run_discovery(FakeProvider(session, collection))
    assert snapshot.session == session
    assert snapshot.networks[0].cidr == "10.20.1.0/24"
    assert snapshot.warnings == collection.warnings


def test_provider_failure_is_distinct_from_collector_warning():
    provider = FakeProvider(
        SessionIdentity("bad", "fake", "Bad"), error=ProviderError("offline")
    )
    with pytest.raises(ProviderError, match="offline"):
        run_discovery(provider)


def test_local_provider_preserves_collector_degradation(monkeypatch):
    from pivotcheck.discovery import local

    # This test targets the Linux collector path specifically; pin the
    # platform so cross-platform dispatch does not change its meaning.
    monkeypatch.setattr("platform.system", lambda: "Linux")


    session = SessionIdentity("local-a", "local", "Local A")
    monkeypatch.setattr(
        local.DiscoverySnapshot,
        "collect_metadata",
        lambda: {"hostname": "local-host", "os_name": "TestOS"},
    )
    monkeypatch.setattr(
        local,
        "collect_interfaces",
        lambda: (
            Interface(
                "eth0",
                InterfaceState.UP,
                ipv4_addresses=(IPAddress("192.168.10.2", 24),),
            ),
        ),
    )
    monkeypatch.setattr(local, "collect_routes", lambda: ())
    monkeypatch.setattr(
        local,
        "collect_neighbors",
        lambda: (_ for _ in ()).throw(PermissionError("denied")),
    )
    monkeypatch.setattr(local, "collect_dns", lambda: None)
    monkeypatch.setattr(local, "collect_connections", lambda: ())

    snapshot = run_discovery(LocalProvider(session))
    assert snapshot.session == session
    assert snapshot.networks[0].cidr == "192.168.10.0/24"
    assert snapshot.warnings[0].source == "neighbors"


def test_default_and_explicit_local_provider_have_equivalent_content(monkeypatch):
    from pivotcheck.discovery import engine

    session = SessionIdentity("local-a", "local", "Local A")
    collection = CollectedDiscoveryData("host", "OS")
    provider = FakeProvider(session, collection)
    monkeypatch.setattr(engine, "LocalProvider", lambda: provider)
    default = engine.run_discovery()
    explicit = engine.run_discovery(provider)
    default_data = default.to_dict()
    explicit_data = explicit.to_dict()
    default_data.pop("timestamp")
    explicit_data.pop("timestamp")
    assert default_data == explicit_data


def test_baseline_retains_snapshot_vantage_point():
    session = SessionIdentity("local-a", "local", "Local A")
    snapshot = DiscoverySnapshot(
        hostname="host",
        os_name="OS",
        session=session,
        networks=(
            DiscoveredNetwork(
                "10.20.0.0/24",
                NetworkOrigin.CONNECTED,
                Confidence.HIGH,
            ),
        ),
    )
    baseline = baseline_from_snapshot(snapshot)
    assert baseline.vantage_point == session
    assert baseline.to_dict()["vantage_point"]["session_id"] == "local-a"


@pytest.mark.integration
def test_default_local_provider_collects_a_named_vantage_point():
    snapshot = run_discovery()
    assert snapshot.session is not None
    assert snapshot.session.provider == "local"
