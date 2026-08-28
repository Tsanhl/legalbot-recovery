"""Encrypted, content-addressed local runtime object storage.

This is deliberately not cloud/object-service integration.  It provides the
same immutable object/metadata boundary on the owner-only host so long jobs can
resume without leaving plaintext prompts, evidence packs or drafts on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..crypto import LocalCipher
from ..db import Database


class EncryptedObjectStore:
    def __init__(self, root: Path, database: Database, cipher: LocalCipher) -> None:
        self.root = root
        self.database = database
        self.cipher = cipher
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def put_json(
        self,
        *,
        namespace: str,
        value: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
        ttl_days: int | None = 30,
    ) -> str:
        if not namespace.replace("_", "").replace("-", "").isalnum():
            raise ValueError("invalid runtime object namespace")
        plaintext = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
        digest = hashlib.sha256(plaintext).hexdigest()
        object_key = f"{namespace}:{digest}"
        relative = Path(namespace) / digest[:2] / f"{digest}.enc"
        destination = self.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not destination.exists():
            temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
            encrypted = self.cipher.encrypt_text(plaintext.decode("utf-8"))
            with temporary.open("xb") as handle:
                handle.write(encrypted)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            destination.chmod(0o600)
        expires_at = None
        if ttl_days is not None:
            expires_at = (datetime.now(UTC) + timedelta(days=ttl_days)).isoformat()
        self.database.store_runtime_object(
            object_key=object_key,
            namespace=namespace,
            content_sha256=digest,
            relative_path=str(relative),
            byte_size=len(plaintext),
            metadata=metadata or {},
            expires_at=expires_at,
        )
        return object_key

    def get_json(self, object_key: str) -> dict[str, Any]:
        row = self.database.fetchone(
            "SELECT * FROM runtime_objects WHERE object_key=?", (object_key,)
        )
        if row is None:
            raise KeyError(object_key)
        path = (self.root / str(row["relative_path"])).resolve()
        if not path.is_relative_to(self.root.resolve()) or not path.is_file():
            raise RuntimeError("runtime object path failed local-vault validation")
        value = json.loads(self.cipher.decrypt_text(path.read_bytes()))
        if not isinstance(value, dict):
            raise ValueError("runtime object is not a JSON object")
        digest = hashlib.sha256(
            json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if digest != row["content_sha256"]:
            raise RuntimeError("runtime object content hash mismatch")
        return value
