"""Pytest bootstrap — guarantee a writable temporary directory.

Pytest stores per-test temp dirs under ``<system-temp>/pytest-of-<user>`` and
scans that folder at startup. On this project's primary development machine the
profile is OneDrive-synced, and a locked or half-synced leftover directory makes
that scan fail with ``PermissionError: [WinError 5] Access is denied`` — which
crashes collection before a single test runs.

To keep the suite runnable everywhere, we probe that exact directory and, only
when it is unusable, redirect temp storage to a project-local ``.pytest_tmp/``.
Healthy environments (Linux, CI, well-behaved Windows) are left completely
untouched, and an explicit ``pytest --basetemp=DIR`` still wins because CLI
options are parsed before this module is imported.
"""

from __future__ import annotations

import getpass
import os
import tempfile
from pathlib import Path

_PROJECT_TMP = Path(__file__).resolve().parent / ".pytest_tmp"


def _pytest_temp_root_usable() -> bool:
    """Return True if pytest's default temp location can be created and read.

    Mirrors what pytest does at startup: it derives ``pytest-of-<user>`` inside
    the system temp root and ``os.scandir``s it. Replicating that here lets us
    detect the broken case precisely instead of interfering with healthy hosts.
    """
    root = Path(tempfile.gettempdir())
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - platform/user-db dependent  # noqa: BLE001
        return True  # cannot predict pytest's path; do not interfere
    candidate = root / f"pytest-of-{user}"
    try:
        root.mkdir(parents=True, exist_ok=True)
        if candidate.exists():
            # The exact operation that raises WinError 5 in the broken case.
            with os.scandir(candidate) as entries:
                next(entries, None)
        else:
            # Root exists but is empty of our dir; confirm it is writable.
            with tempfile.NamedTemporaryFile(dir=root):
                pass
        return True
    except OSError:
        return False


def _redirect_temp_to_project() -> None:
    """Pin temp storage to a project-local directory for this test session."""
    _PROJECT_TMP.mkdir(parents=True, exist_ok=True)
    # tempfile caches the resolved dir on first use; clear it, then set the
    # standard env vars so tempfile.gettempdir() — used by pytest's
    # TempPathFactory when --basetemp is absent — resolves to _PROJECT_TMP.
    tempfile.tempdir = None
    for var in ("TMPDIR", "TEMP", "TMP"):
        os.environ[var] = str(_PROJECT_TMP)


if not _pytest_temp_root_usable():
    _redirect_temp_to_project()
