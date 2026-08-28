from __future__ import annotations

from pathlib import Path

from app.orchestration.upload_vault import (
    migrate_plaintext_upload,
    read_upload,
    write_encrypted_upload,
)


def test_upload_vault_never_persists_plaintext(
    tmp_path: Path,
    cipher: object,
) -> None:
    path = tmp_path / "upload.enc"
    plaintext = b"private upload facts and owner-only context"

    write_encrypted_upload(path, plaintext, cipher=cipher)  # type: ignore[arg-type]

    assert path.read_bytes() != plaintext
    assert plaintext not in path.read_bytes()
    assert read_upload(path, cipher=cipher, encrypted=True) == plaintext  # type: ignore[arg-type]
    assert path.stat().st_mode & 0o777 == 0o600


def test_legacy_upload_migration_is_atomic_and_readable(
    tmp_path: Path,
    cipher: object,
) -> None:
    path = tmp_path / "legacy-upload"
    plaintext = b"legacy private upload"
    path.write_bytes(plaintext)

    migrate_plaintext_upload(path, cipher=cipher)  # type: ignore[arg-type]

    assert plaintext not in path.read_bytes()
    assert read_upload(path, cipher=cipher, encrypted=True) == plaintext  # type: ignore[arg-type]
