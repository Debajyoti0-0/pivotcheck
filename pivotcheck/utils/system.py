"""Small utilities shared across discovery modules."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


class CommandNotFoundError(Exception):
    """A required system command is not available."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(
    args: list[str],
    timeout: float = 10.0,
) -> CommandResult:
    """Run a system command with a sanitized, deterministic environment.

    Raises CommandNotFoundError if the binary is missing and
    subprocess.TimeoutExpired on timeout. Never raises on non-zero exit.
    """
    binary = shutil.which(args[0])
    if binary is None:
        raise CommandNotFoundError(f"command not found: {args[0]}")
    env = dict(os.environ)
    env["LC_ALL"] = "C"  # stable, parseable output regardless of locale
    env.pop("LANG", None)
    proc = subprocess.run(
        [binary, *args[1:]],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)


def read_file_safe(path: str) -> str | None:
    """Read a file, returning None instead of raising on any error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None
