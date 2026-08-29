"""JSON serialization of discovery snapshots.

Consumes normalized models only. Output contains no ANSI formatting and is
stable across runs apart from the timestamp field.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from pivotcheck.models.result import DiscoverySnapshot


def render_json(snapshot: DiscoverySnapshot, stream: TextIO) -> None:
    """Write the snapshot as pretty-printed JSON to the given stream."""
    json.dump(snapshot.to_dict(), stream, indent=2)
    stream.write("\n")


def snapshot_to_string(snapshot: DiscoverySnapshot) -> str:
    """Return the JSON document as a string (useful for tests/files)."""
    return json.dumps(snapshot.to_dict(), indent=2) + "\n"


def write_snapshot_file(snapshot: DiscoverySnapshot, path: str) -> None:
    """Persist a snapshot to a file (for future diff/compare support)."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(snapshot_to_string(snapshot))


def emit_json_if_requested(snapshot: DiscoverySnapshot, enabled: bool) -> None:
    """Convenience wrapper writing to stdout when JSON mode is active."""
    if enabled:
        render_json(snapshot, sys.stdout)
