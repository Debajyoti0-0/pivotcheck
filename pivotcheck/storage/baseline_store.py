"""Versioned JSON persistence for baseline evidence; no CLI or analysis logic."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pivotcheck.models.baseline import Baseline, BaselineNetwork
from pivotcheck.models.network import Confidence, NetworkOrigin, RouteType
from pivotcheck.models.session import SessionIdentity

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SCHEMA_VERSION = 1


class BaselineNameError(ValueError):
    """An operator-facing baseline name is invalid."""


class BaselineExistsError(FileExistsError):
    """Creating a baseline would overwrite existing evidence."""


class BaselineNotFoundError(FileNotFoundError):
    """The requested baseline does not exist."""


class BaselineSchemaError(ValueError):
    """Persisted JSON is invalid or uses an unsupported format version."""


@dataclass(frozen=True)
class StoredBaseline:
    name: str
    baseline: Baseline


def validate_baseline_name(name: str) -> str:
    """Normalize a safe identifier; names are case-insensitive on disk."""
    if not isinstance(name, str):
        raise BaselineNameError("baseline name must be a string")
    normalized = name.strip().lower()
    if not _NAME_RE.fullmatch(normalized):
        raise BaselineNameError(
            "baseline name must be 1-63 lowercase letters, digits, or hyphens"
        )
    return normalized


def default_data_dir() -> Path:
    """Resolve data location: environment override, then platform default."""
    configured = os.environ.get("PIVOTCHECK_DATA_DIR")
    if configured:
        return Path(configured).expanduser() / "pivotcheck"
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        return (
            Path(root) / "pivotcheck"
            if root
            else Path.home() / "AppData" / "Local" / "pivotcheck"
        )
    return (
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "pivotcheck"
    )


class BaselineStore:
    """Owns safe file naming, version validation, and atomic persistence."""

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self.data_dir = Path(data_dir).expanduser() if data_dir else default_data_dir()

    def create(
        self, name: str, baseline: Baseline, *, force: bool = False
    ) -> StoredBaseline:
        normalized = validate_baseline_name(name)
        path = self._path(normalized)
        self._ensure_directory()
        if path.exists() and not force:
            raise BaselineExistsError(f"baseline already exists: {normalized}")
        payload = {"name": normalized, **baseline.to_dict()}
        self._atomic_write(path, payload)
        return StoredBaseline(normalized, baseline)

    def load(self, name: str) -> StoredBaseline:
        normalized = validate_baseline_name(name)
        path = self._path(normalized)
        if not path.is_file():
            raise BaselineNotFoundError(f"baseline not found: {normalized}")
        return self._parse_document(path, expected_name=normalized)

    def list(self) -> tuple[StoredBaseline, ...]:
        if not self.data_dir.is_dir():
            return ()
        results = [
            self._parse_document(path) for path in sorted(self.data_dir.glob("*.json"))
        ]
        return tuple(sorted(results, key=lambda item: item.name))

    def delete(self, name: str) -> None:
        normalized = validate_baseline_name(name)
        path = self._path(normalized)
        if not path.is_file():
            raise BaselineNotFoundError(f"baseline not found: {normalized}")
        path.unlink()

    def _path(self, normalized_name: str) -> Path:
        return self.data_dir / f"{normalized_name}.json"

    def _ensure_directory(self) -> None:
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _atomic_write(self, path: Path, payload: dict[str, object]) -> None:
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.data_dir, delete=False
            ) as handle:
                temporary = handle.name
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            temporary = None
            try:
                path.chmod(0o600)
            except OSError:
                pass  # platform permission models differ
        finally:
            if temporary:
                try:
                    Path(temporary).unlink(missing_ok=True)
                except OSError:
                    pass

    def _parse_document(
        self, path: Path, expected_name: str | None = None
    ) -> StoredBaseline:
        try:
            with path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise BaselineSchemaError(f"invalid baseline JSON: {path.name}") from exc
        except OSError as exc:
            raise BaselineSchemaError(f"could not read baseline: {path.name}") from exc
        if not isinstance(data, dict):
            raise BaselineSchemaError("baseline document must be a JSON object")
        unexpected = set(data) - {
            "schema_version",
            "name",
            "created_at",
            "source",
            "networks",
            "vantage_point",
        }
        if unexpected:
            raise BaselineSchemaError(
                f"unsupported baseline fields: {', '.join(sorted(unexpected))}"
            )
        version = data.get("schema_version")
        if not isinstance(version, int):
            raise BaselineSchemaError("baseline schema_version is missing or invalid")
        if version < _SCHEMA_VERSION:
            raise BaselineSchemaError(f"unsupported older baseline schema: {version}")
        if version > _SCHEMA_VERSION:
            raise BaselineSchemaError(f"unsupported newer baseline schema: {version}")
        try:
            name = validate_baseline_name(data["name"])
            if expected_name and name != expected_name:
                raise BaselineSchemaError("baseline name does not match its file name")
            created_at = _required_string(data, "created_at")
            source = _required_string(data, "source")
            networks_data = data["networks"]
            if not isinstance(networks_data, list):
                raise TypeError("networks must be a list")
            networks = tuple(_network_from_dict(item) for item in networks_data)
            vantage = _session_from_dict(data.get("vantage_point"))
            baseline = Baseline(
                schema_version=version,
                created_at=created_at,
                source=source,
                networks=networks,
                vantage_point=vantage,
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, BaselineSchemaError):
                raise
            raise BaselineSchemaError(f"invalid baseline fields: {exc}") from exc
        return StoredBaseline(name, baseline)


def _required_string(data: dict[str, object], field: str) -> str:
    value = data[field]
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _network_from_dict(data: object) -> BaselineNetwork:
    if not isinstance(data, dict):
        raise TypeError("network entry must be an object")
    unexpected = set(data) - {
        "network",
        "origin",
        "confidence",
        "interface",
        "gateway",
        "route_type",
    }
    if unexpected:
        raise ValueError(f"unsupported network fields: {', '.join(sorted(unexpected))}")
    return BaselineNetwork(
        network=_required_string(data, "network"),
        origin=NetworkOrigin(_required_string(data, "origin")),
        confidence=Confidence(_required_string(data, "confidence")),
        interface=_optional_string(data, "interface"),
        gateway=_optional_string(data, "gateway"),
        route_type=RouteType(_required_string(data, "route_type")),
    )


def _session_from_dict(data: object) -> SessionIdentity | None:
    if data is None:
        return None
    if not isinstance(data, dict):
        raise TypeError("vantage_point must be an object or null")
    unexpected = set(data) - {"session_id", "provider", "display_name"}
    if unexpected:
        raise ValueError(
            f"unsupported vantage_point fields: {', '.join(sorted(unexpected))}"
        )
    return SessionIdentity(
        _required_string(data, "session_id"),
        _required_string(data, "provider"),
        _required_string(data, "display_name"),
    )


def _optional_string(data: dict[str, object], field: str) -> str | None:
    value = data.get(field)
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"{field} must be a string or null")
