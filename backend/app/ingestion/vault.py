"""Immutable content-addressed storage and dual-key de-duplication."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from .models import SourceIdentity


@dataclass(frozen=True, slots=True)
class VaultObject:
    sha256: str
    size: int
    path: Path


class ContentAddressedVault:
    """A write-once SHA-256 object vault.

    Files are never replaced.  A new temporary inode is fsynced and linked into
    its final hash path, so concurrent writers can only converge on identical
    bytes.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects" / "sha256"
        self.objects.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def object_path(self, sha256: str) -> Path:
        if not re_full_sha256(sha256):
            raise ValueError("invalid SHA-256 digest")
        return self.objects / sha256[:2] / sha256

    def put_bytes(self, data: bytes) -> VaultObject:
        digest = self.digest(data)
        target = self.object_path(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            self._verify_existing(target, digest, len(data))
            return VaultObject(digest, len(data), target)

        fd, temporary_name = tempfile.mkstemp(prefix=".incoming-", dir=target.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o444)
            try:
                os.link(temporary, target)
            except FileExistsError:
                self._verify_existing(target, digest, len(data))
            self._fsync_directory(target.parent)
        finally:
            temporary.unlink(missing_ok=True)
        return VaultObject(digest, len(data), target)

    def read_bytes(self, sha256: str) -> bytes:
        path = self.object_path(sha256)
        data = path.read_bytes()
        if self.digest(data) != sha256:
            raise OSError(f"vault corruption detected for {sha256}")
        return data

    @staticmethod
    def _verify_existing(path: Path, digest: str, expected_size: int) -> None:
        if (
            path.stat().st_size != expected_size
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise OSError(f"immutable vault collision or corruption at {path}")

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


class DedupeStatus(StrEnum):
    NEW = "new"
    DUPLICATE_CONTENT = "duplicate_content"
    DUPLICATE_IDENTITY = "duplicate_identity"
    DUPLICATE_IDENTITY_AND_CONTENT = "duplicate_identity_and_content"
    IDENTITY_CONFLICT = "identity_conflict"


@dataclass(frozen=True, slots=True)
class DedupeDecision:
    status: DedupeStatus
    content_sha256: str
    source_identity: str
    existing_source_identity: str | None = None
    existing_content_sha256: str | None = None

    @property
    def can_stage(self) -> bool:
        return self.status is DedupeStatus.NEW


class DedupeLedger:
    """Persistent SHA-256 and source-identity de-duplication ledger.

    A stable identity resolving to new bytes is quarantined as a conflict.  A
    caller that knows the bytes are a legitimate revision must provide a
    versioned ``SourceIdentity``.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def register(self, source_identity: SourceIdentity, content_sha256: str) -> DedupeDecision:
        if not re_full_sha256(content_sha256):
            raise ValueError("invalid SHA-256 digest")
        identity_key = source_identity.canonical_key
        with self._lock:
            payload = self._read()
            by_identity: dict[str, str] = payload["by_identity"]
            by_content: dict[str, str] = payload["by_content"]
            identity_hash = by_identity.get(identity_key)
            content_identity = by_content.get(content_sha256)

            if identity_hash == content_sha256:
                status = DedupeStatus.DUPLICATE_IDENTITY_AND_CONTENT
            elif identity_hash is not None:
                return DedupeDecision(
                    DedupeStatus.IDENTITY_CONFLICT,
                    content_sha256,
                    identity_key,
                    existing_source_identity=identity_key,
                    existing_content_sha256=identity_hash,
                )
            elif content_identity is not None:
                return DedupeDecision(
                    DedupeStatus.DUPLICATE_CONTENT,
                    content_sha256,
                    identity_key,
                    existing_source_identity=content_identity,
                    existing_content_sha256=content_sha256,
                )
            else:
                by_identity[identity_key] = content_sha256
                by_content[content_sha256] = identity_key
                self._write(payload)
                return DedupeDecision(DedupeStatus.NEW, content_sha256, identity_key)

            return DedupeDecision(
                status,
                content_sha256,
                identity_key,
                existing_source_identity=identity_key,
                existing_content_sha256=identity_hash,
            )

    def register_representation(
        self, source_identity: SourceIdentity, content_sha256: str
    ) -> DedupeDecision:
        """Register one representation of a logical source identity.

        Unlike :meth:`register`, this operation deliberately permits multiple
        byte representations for one identity (for example PDF and annotated
        DOCX). Exact content and identity duplication are still reported so
        the catalogue can account for each alias without indexing the body
        twice.
        """

        if not re_full_sha256(content_sha256):
            raise ValueError("invalid SHA-256 digest")
        identity_key = source_identity.canonical_key
        with self._lock:
            payload = self._read()
            by_content: dict[str, str] = payload["by_content"]
            raw_groups = payload.setdefault("representation_by_identity", {})
            if not isinstance(raw_groups, dict):
                raise ValueError("representation identity ledger must be an object")
            stored = raw_groups.get(identity_key, [])
            if not isinstance(stored, list) or not all(isinstance(item, str) for item in stored):
                raise ValueError("representation identity entries must be SHA-256 lists")
            identity_hashes = cast(list[str], stored)
            content_identity = by_content.get(content_sha256)

            if content_sha256 in identity_hashes:
                status = DedupeStatus.DUPLICATE_IDENTITY_AND_CONTENT
            elif identity_hashes:
                identity_hashes.append(content_sha256)
                identity_hashes.sort()
                raw_groups[identity_key] = identity_hashes
                by_content.setdefault(content_sha256, identity_key)
                self._write(payload)
                return DedupeDecision(
                    DedupeStatus.DUPLICATE_IDENTITY,
                    content_sha256,
                    identity_key,
                    existing_source_identity=identity_key,
                    existing_content_sha256=identity_hashes[0],
                )
            elif content_identity is not None:
                raw_groups[identity_key] = [content_sha256]
                self._write(payload)
                return DedupeDecision(
                    DedupeStatus.DUPLICATE_CONTENT,
                    content_sha256,
                    identity_key,
                    existing_source_identity=content_identity,
                    existing_content_sha256=content_sha256,
                )
            else:
                raw_groups[identity_key] = [content_sha256]
                by_content[content_sha256] = identity_key
                self._write(payload)
                return DedupeDecision(DedupeStatus.NEW, content_sha256, identity_key)

            return DedupeDecision(
                status,
                content_sha256,
                identity_key,
                existing_source_identity=identity_key,
                existing_content_sha256=content_sha256,
            )

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "schema": "legalbot.dedupe.v1",
                "by_identity": {},
                "by_content": {},
                "representation_by_identity": {},
            }
        decoded: object = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
            raise ValueError("de-duplication ledger must be a JSON object with string keys")
        payload = cast(dict[str, Any], decoded)
        if payload.get("schema") != "legalbot.dedupe.v1":
            raise ValueError("unsupported de-duplication ledger schema")
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        fd, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        finally:
            Path(temporary_name).unlink(missing_ok=True)
