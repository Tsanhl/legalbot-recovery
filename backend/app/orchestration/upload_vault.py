"""Encrypted-at-rest storage helpers for answer-scoped user uploads."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..crypto import LocalCipher

UPLOAD_VAULT_SCHEMA = "legalbot.encrypted-upload.v1"


def write_encrypted_upload(
    destination: Path,
    plaintext: bytes,
    *,
    cipher: LocalCipher,
) -> None:
    """Atomically persist one encrypted upload with owner-only permissions."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.parent.chmod(0o700)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}-", suffix=".tmp", dir=destination.parent
    )
    try:
        ciphertext = cipher.encrypt_bytes(plaintext)
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(ciphertext)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        destination.chmod(0o600)
    except Exception:
        Path(temporary).unlink(missing_ok=True)
        raise


def read_upload(
    path: Path,
    *,
    cipher: LocalCipher,
    encrypted: bool,
) -> bytes:
    """Read one upload, decrypting only records explicitly marked encrypted."""

    stored = path.read_bytes()
    return cipher.decrypt_bytes(stored) if encrypted else stored


def migrate_plaintext_upload(
    path: Path,
    *,
    cipher: LocalCipher,
) -> None:
    """Replace a legacy plaintext upload atomically without changing its path."""

    plaintext = path.read_bytes()
    write_encrypted_upload(path, plaintext, cipher=cipher)
