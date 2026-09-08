"""Encrypted baseline container (G-03, Stage 30).

Format (versioned, deterministic, minimal):

    {
      "pivotcheck_encrypted_baseline": 1,       <- format discriminator+version
      "encryption": "fernet/v1",
      "kdf": "scrypt/v1",
      "salt": "<base64 16 bytes>",
      "kdf_n": 16384, "kdf_r": 8, "kdf_p": 1,
      "ciphertext": "<base64 Fernet token>"
    }

Properties:

- Fernet (AES-128-CBC + HMAC-SHA256, versioned token) provides
  confidentiality + integrity + authenticity: wrong password, modified
  ciphertext, modified salt, or truncated payloads fail CLOSED with
  InvalidToken. No custom crypto; no unauthenticated mode.
- Key derivation: hashlib.scrypt (stdlib) with centrally-defined,
  versioned parameters (Section 8 of the stage contract). Parameters
  are validated against hard bounds BEFORE deriving, so an attacker-
  crafted container cannot trigger resource amplification.
- The password is used only to derive a key in memory. It is never
  logged, never stored in the container, never serialized.
- Plaintext fallback is impossible: a container marked encrypted either
  decrypts fully or raises. A plaintext file is never accepted as an
  encrypted one and vice versa at the store layer.
- Format carries no operator metadata beyond the crypto envelope.

Threat model (documented, not overclaimed): protects against unauthorized
reading of stored baseline contents at rest. Does NOT protect a
compromised running host, a compromised process, stolen passwords,
already-decrypted memory, or operator misuse.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

CONTAINER_FORMAT_VERSION = 1
ENCRYPTION_SCHEME = "fernet/v1"
KDF_SCHEME = "scrypt/v1"

# Central, documented, versioned scrypt parameters (production-authoritative).
KDF_N = 2**14  # 16384
KDF_R = 8
KDF_P = 1
_SALT_BYTES = 16

# Hard bounds: reject attacker-controlled resource amplification before
# any expensive derivation. Generous upper bounds still reject hostile
# parameter inflation while permitting legitimate future parameter
# bumps via a new kdf scheme version. Bounds are coherent with the
# maxmem cap: worst case memory = 128 * _MAX_N * _MAX_R ≤ 1 GiB.
_MIN_N, _MAX_N = 2**12, 2**20  # 4096 .. 1,048,576
_MIN_R, _MAX_R = 1, 8
_MIN_P, _MAX_P = 1, 8
_SCRYPT_MAXMEM = 1024 * 1024 * 1024  # 1 GiB, within the C int limit
_MAX_CIPHERTEXT_CHARS = 64 * 1024 * 1024  # bounded read/alloc upstream of Fernet


class EncryptedBaselineError(ValueError):
    """Base class: an encrypted container could not be processed."""


class EncryptedBaselineFormatError(EncryptedBaselineError):
    """The container is malformed, truncated, or not an encrypted baseline."""


class EncryptedBaselineVersionError(EncryptedBaselineError):
    """The container uses an unsupported format/scheme/KDF version."""


class EncryptedBaselineKeyError(EncryptedBaselineError):
    """Wrong password, tampered ciphertext, or failed authentication."""


class EncryptedBaselineParameterError(EncryptedBaselineError):
    """KDF parameters are missing, malformed, or outside accepted bounds."""


def encrypt_baseline_document(
    plaintext_json: str,
    password: str,
    *,
    kdf_n: int | None = None,
    kdf_r: int | None = None,
    kdf_p: int | None = None,
) -> str:
    """Encrypt one serialized baseline JSON document.

    ``plaintext_json`` is the exact serialized document (the store's
    existing JSON). Returns the serialized encrypted container (JSON).
    The password participates in key derivation only; it is never
    embedded in the output.

    KDF parameters default to the centrally-defined production values
    and may be overridden ONLY within the hard bounds (used by tests
    with explicitly reduced cost; production remains authoritative).
    """
    if not isinstance(password, str) or not password:
        raise EncryptedBaselineParameterError(
            "encryption password must be a non-empty string"
        )
    n, r, p = _validated_kdf_parameters(
        {
            "kdf_n": KDF_N if kdf_n is None else kdf_n,
            "kdf_r": KDF_R if kdf_r is None else kdf_r,
            "kdf_p": KDF_P if kdf_p is None else kdf_p,
        }
    )
    salt = _os_urandom(_SALT_BYTES)
    key = _derive_key(password, salt, n, r, p)
    token = _fernet_encrypt(key, plaintext_json.encode("utf-8"))
    container = {
        "pivotcheck_encrypted_baseline": CONTAINER_FORMAT_VERSION,
        "encryption": ENCRYPTION_SCHEME,
        "kdf": KDF_SCHEME,
        "salt": _b64e(salt),
        "kdf_n": n,
        "kdf_r": r,
        "kdf_p": p,
        "ciphertext": token.decode("ascii"),
    }
    return json.dumps(container, indent=2, sort_keys=True) + "\n"


def decrypt_baseline_document(container_json: str, password: str) -> str:
    """Validate, authenticate, and decrypt one encrypted container.

    Returns the plaintext baseline JSON document. Every failure mode is
    fail-closed with a precise typed error; partial plaintext is never
    returned.
    """
    if not isinstance(password, str) or not password:
        raise EncryptedBaselineParameterError(
            "decryption password must be a non-empty string"
        )
    container = _parse_container(container_json)
    salt = _decode_salt(container)
    n, r, p = _validated_kdf_parameters(container)
    key = _derive_key(password, salt, n, r, p)
    token = _decode_ciphertext(container)
    plaintext = _fernet_decrypt(key, token)
    return plaintext.decode("utf-8")


def is_encrypted_container(raw: str) -> bool:
    """Cheap structural discriminator (does NOT validate cryptography).

    Distinguishes an encrypted container from a plaintext baseline
    document by the presence of the format marker. Never raises for
    arbitrary input.
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return False
    return (
        isinstance(data, dict)
        and "pivotcheck_encrypted_baseline" in data
        and "ciphertext" in data
    )


def is_encrypted_file(path: Any) -> bool:
    """File-level discriminator: reads the file and classifies its form.

    Used by the store to decide the parse path. Read errors are reported
    as encrypted-format errors only when the file exists.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise EncryptedBaselineFormatError(
            f"could not read baseline container: {exc.__class__.__name__}"
        ) from exc
    except UnicodeDecodeError as exc:
        # A binary file is neither valid plaintext JSON nor a valid
        # container; classify as format error (fail closed).
        raise EncryptedBaselineFormatError(
            "baseline file is not valid text (neither plaintext JSON nor an "
            f"encrypted container): {exc}"
        ) from exc
    return is_encrypted_container(raw)


# ---------------------------------------------------------------------------
# Internal primitives (single crypto boundary; lazily import cryptography)
# ---------------------------------------------------------------------------


def _os_urandom(count: int) -> bytes:
    import os

    return os.urandom(count)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise EncryptedBaselineFormatError(
            f"container field is not valid base64: {exc.__class__.__name__}"
        ) from exc


def _b64d_urlsafe(data: str) -> bytes:
    """Decode URL-safe base64 (Fernet token alphabet)."""
    try:
        return base64.urlsafe_b64decode(data)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise EncryptedBaselineFormatError(
            f"container ciphertext is not valid base64: {exc.__class__.__name__}"
        ) from exc


def _derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """scrypt KDF (stdlib). Parameters are already bounds-checked here."""
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
        maxmem=_SCRYPT_MAXMEM,
    )


def _validated_kdf_parameters(container: dict) -> tuple[int, int, int]:
    marker = "kdf_n"
    if marker not in container:
        raise EncryptedBaselineParameterError("KDF parameters missing (kdf_n)")
    if container.get("kdf_r") is None:
        raise EncryptedBaselineParameterError("KDF parameters missing (kdf_r)")
    if container.get("kdf_p") is None:
        raise EncryptedBaselineParameterError("KDF parameters missing (kdf_p)")
    values = []
    for name, low, high in (
        ("kdf_n", _MIN_N, _MAX_N),
        ("kdf_r", _MIN_R, _MAX_R),
        ("kdf_p", _MIN_P, _MAX_P),
    ):
        value = container[name]
        if not isinstance(value, int) or isinstance(value, bool):
            raise EncryptedBaselineParameterError(f"KDF parameter {name} is invalid")
        if not low <= value <= high:
            raise EncryptedBaselineParameterError(
                f"KDF parameter {name}={value} outside accepted bounds "
                f"[{low}, {high}]"
            )
        values.append(value)
    return values[0], values[1], values[2]


def _parse_container(container_json: str) -> dict:
    try:
        data = json.loads(container_json)
    except (json.JSONDecodeError, ValueError) as exc:
        raise EncryptedBaselineFormatError(
            f"encrypted container is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise EncryptedBaselineFormatError(
            "encrypted container must be a JSON object"
        )
    unexpected = set(data) - {
        "pivotcheck_encrypted_baseline",
        "encryption",
        "kdf",
        "salt",
        "kdf_n",
        "kdf_r",
        "kdf_p",
        "ciphertext",
    }
    if unexpected:
        raise EncryptedBaselineFormatError(
            f"unsupported container fields: {', '.join(sorted(unexpected))}"
        )
    version = data.get("pivotcheck_encrypted_baseline")
    if not isinstance(version, int) or isinstance(version, bool):
        raise EncryptedBaselineFormatError(
            "container format version is missing or invalid"
        )
    if version > CONTAINER_FORMAT_VERSION:
        raise EncryptedBaselineVersionError(
            f"unsupported newer container format: {version}"
        )
    if version < CONTAINER_FORMAT_VERSION:
        raise EncryptedBaselineVersionError(
            f"unsupported older container format: {version}"
        )
    if data.get("encryption") != ENCRYPTION_SCHEME:
        raise EncryptedBaselineVersionError(
            f"unsupported encryption scheme: {data.get('encryption')!r}"
        )
    if data.get("kdf") != KDF_SCHEME:
        raise EncryptedBaselineVersionError(
            f"unsupported KDF scheme: {data.get('kdf')!r}"
        )
    if "salt" not in data:
        raise EncryptedBaselineFormatError("container salt is missing")
    if "ciphertext" not in data:
        raise EncryptedBaselineFormatError("container ciphertext is missing")
    if not isinstance(data["ciphertext"], str) or not data["ciphertext"]:
        raise EncryptedBaselineFormatError("container ciphertext is invalid")
    if len(data["ciphertext"]) > _MAX_CIPHERTEXT_CHARS:
        raise EncryptedBaselineFormatError("container ciphertext exceeds size bound")
    if not isinstance(data["salt"], str) or not data["salt"]:
        raise EncryptedBaselineFormatError("container salt is invalid")
    return data


def _decode_salt(container: dict) -> bytes:
    salt = _b64d(container["salt"])
    if len(salt) < 8:
        raise EncryptedBaselineFormatError("container salt is too short")
    return salt


def _decode_ciphertext(container: dict) -> bytes:
    """Validate the token's base64 form, then return the token BYTES as
    Fernet expects them (the base64 string itself, not decoded data)."""
    _b64d_urlsafe(container["ciphertext"])  # fail closed on malformed base64
    return container["ciphertext"].encode("ascii")


def _fernet_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt via the audited Fernet primitive (optional extra, lazy)."""
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:  # pragma: no cover - exercised via extra absence
        raise EncryptedBaselineError(
            "encryption requires the optional 'encrypt' extra: "
            "pip install 'pivotcheck[encrypt]'"
        ) from exc
    return Fernet(base64.urlsafe_b64encode(key)).encrypt(plaintext)


def _fernet_decrypt(key: bytes, token: bytes) -> bytes:
    """Decrypt+authenticate via Fernet. Any failure is fail-closed."""
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError as exc:  # pragma: no cover
        raise EncryptedBaselineError(
            "decryption requires the optional 'encrypt' extra: "
            "pip install 'pivotcheck[encrypt]'"
        ) from exc
    try:
        return Fernet(base64.urlsafe_b64encode(key)).decrypt(token)
    except InvalidToken as exc:
        # Wrong password, tampered ciphertext, modified salt, or truncation
        # are all indistinguishable by design — fail closed, no partial data.
        raise EncryptedBaselineKeyError(
            "decryption failed: wrong password or tampered container"
        ) from exc
