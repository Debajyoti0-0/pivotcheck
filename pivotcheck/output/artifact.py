"""Explicit atomic JSON result artifacts, separate from baseline lifecycle."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_json_artifact(path: str | Path, content: str, *, force: bool = False) -> None:
    target = Path(path)
    if target.exists() and not force:
        raise FileExistsError(f"output file already exists: {target}")
    if not target.parent.is_dir():
        raise OSError(f"output directory does not exist: {target.parent}")
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as handle:
            temporary = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        temporary = None
    finally:
        if temporary:
            Path(temporary).unlink(missing_ok=True)
