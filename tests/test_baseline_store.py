"""Unit tests for safe baseline persistence."""

import json

import pytest

from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import Confidence, NetworkOrigin
from pivotcheck.models.session import SessionIdentity
from pivotcheck.storage.baseline_store import (
    BaselineExistsError,
    BaselineNameError,
    BaselineNotFoundError,
    BaselineSchemaError,
    BaselineStore,
    validate_baseline_name,
)


def baseline():
    return Baseline(
        created_at="2026-01-01T00:00:00+00:00",
        networks=(
            BaselineNetwork("10.20.0.0/24", NetworkOrigin.CONNECTED, Confidence.HIGH),
        ),
        vantage_point=SessionIdentity("local-a", "local", "Local A"),
    )


@pytest.mark.parametrize(
    "raw, expected", [(" WorkStation ", "workstation"), ("vpn-entry", "vpn-entry")]
)
def test_baseline_name_normalization(raw, expected):
    assert validate_baseline_name(raw) == expected


@pytest.mark.parametrize(
    "name", ["", "   ", "../../bad", "a/b", "a\\b", ".hidden", "x" * 64]
)
def test_baseline_name_rejects_unsafe_identifiers(name):
    with pytest.raises(BaselineNameError):
        validate_baseline_name(name)


def test_create_load_list_and_delete(tmp_path):
    store = BaselineStore(tmp_path)
    stored = store.create("WorkStation", baseline())
    assert stored.name == "workstation"
    assert store.load("WORKSTATION").baseline == baseline()
    assert [item.name for item in store.list()] == ["workstation"]
    store.delete("workstation")
    with pytest.raises(BaselineNotFoundError):
        store.load("workstation")


def test_duplicate_requires_force_and_atomic_replacement(tmp_path):
    store = BaselineStore(tmp_path)
    store.create("workstation", baseline())
    with pytest.raises(BaselineExistsError):
        store.create("workstation", baseline())
    replacement = Baseline(created_at="2026-02-01T00:00:00+00:00")
    store.create("workstation", replacement, force=True)
    assert store.load("workstation").baseline.created_at == "2026-02-01T00:00:00+00:00"


def test_failed_atomic_replacement_leaves_original(tmp_path, monkeypatch):
    store = BaselineStore(tmp_path)
    store.create("workstation", baseline())
    monkeypatch.setattr(
        "pivotcheck.storage.baseline_store.os.replace",
        lambda *_: (_ for _ in ()).throw(OSError("disk failure")),
    )
    with pytest.raises(OSError):
        store.create("workstation", Baseline(created_at="new"), force=True)
    assert store.load("workstation").baseline.created_at == "2026-01-01T00:00:00+00:00"


@pytest.mark.parametrize(
    "document, error",
    [
        ({}, "schema_version"),
        ({"schema_version": 0}, "older"),
        ({"schema_version": 2}, "newer"),
        ({"schema_version": 1, "name": "workstation"}, "invalid baseline fields"),
    ],
)
def test_schema_validation(tmp_path, document, error):
    path = tmp_path / "workstation.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BaselineSchemaError, match=error):
        BaselineStore(tmp_path).load("workstation")


def test_invalid_json_is_rejected(tmp_path):
    (tmp_path / "workstation.json").write_text("{bad", encoding="utf-8")
    with pytest.raises(BaselineSchemaError, match="invalid baseline JSON"):
        BaselineStore(tmp_path).load("workstation")


def test_unknown_fields_are_rejected_without_silent_data_loss(tmp_path):
    document = {"name": "workstation", **baseline().to_dict(), "future_field": True}
    (tmp_path / "workstation.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(BaselineSchemaError, match="unsupported baseline fields"):
        BaselineStore(tmp_path).load("workstation")
