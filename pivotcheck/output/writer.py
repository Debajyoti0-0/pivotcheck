"""Centralized output-encoding safety for operator-facing streams.

This module is the single boundary between PivotCheck's text renderers and
the physical output stream. Rendering code never handles encoding itself.

Policy:
- If the destination encoding can represent PivotCheck's decoration
  characters (UTF-8 terminals, pipes, and files), the stream is returned
  unchanged — output is byte-identical to unwrapped rendering.
- Otherwise a delegating wrapper escapes only the characters the encoding
  cannot represent, in deterministic visible ``\\uXXXX`` form. Commands
  therefore never crash merely because decoration cannot be encoded, and no
  character is silently dropped.

JSON output is unaffected: it is produced with ``json.dump`` (ASCII-safe by
default) and passes through the boundary unchanged.

Failure classification: only *representational* encoding failures
(``UnicodeEncodeError`` for the destination's declared encoding) are
remediated here. Real I/O failures (broken pipe, permissions, disk full)
propagate unchanged — this layer never swallows unrelated errors.
"""

from __future__ import annotations

from typing import Any, TextIO, cast

# Decoration characters used by PivotCheck text renderers (box drawing,
# dashes). Used only as an engagement probe; per-write escaping handles any
# other character a restrictive encoding rejects.
_PROBE = "\u2550\u2014\u2500\u2502"


class _EncodingSafeStream:
    """Delegating stream that escapes unencodable characters on write.

    All attribute access (``flush``, ``isatty``, ``encoding``, ...) is
    delegated to the wrapped stream, so color detection, flush-at-exit, and
    test capture behave exactly as with the original stream.
    """

    def __init__(self, stream: Any, encoding: str) -> None:
        self._stream = stream
        self._encoding = encoding

    def write(self, text: str) -> int:
        try:
            text.encode(self._encoding)
        except UnicodeEncodeError:
            text = text.encode(
                self._encoding, errors="backslashreplace"
            ).decode(self._encoding)
        return self._stream.write(text)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def text_stream(stream: TextIO) -> TextIO:
    """Return ``stream`` (or a safe wrapper) for operator-facing text output.

    Engages only when the stream declares an encoding that cannot represent
    the decoration probe. Streams without a usable ``encoding`` attribute
    (e.g. ``io.StringIO``) and UTF-8-capable streams are returned unchanged.
    """
    encoding = getattr(stream, "encoding", None)
    if not isinstance(encoding, str) or not encoding:
        return stream
    try:
        _PROBE.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return cast(TextIO, _EncodingSafeStream(stream, encoding))
    return stream
