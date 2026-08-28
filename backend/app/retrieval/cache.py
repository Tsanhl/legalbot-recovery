"""Build-scoped, safe-ID-only retrieval cache.

The cache is disposable and cannot hydrate prose by itself.  Callers must load
the referenced chunks from the exact ACTIVE build before constructing an
EvidenceSpan.  Upload-scoped and online results are never cacheable.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import tempfile
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

CACHE_ENTRY_SCHEMA = "legalbot.safe-retrieval-cache.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,254}$")
_CACHE_FIELDS = frozenset(
    {"schema", "cache_key", "active_build_id", "created_at", "expires_at", "hits"}
)
_HIT_FIELDS = frozenset({"source_version_id", "chunk_id", "rank", "score"})


@dataclass(frozen=True, slots=True)
class SafeCachedHit:
    source_version_id: str
    chunk_id: str
    rank: int
    score: float

    def validate(self) -> None:
        if not _SAFE_ID.fullmatch(self.source_version_id) or not _SAFE_ID.fullmatch(self.chunk_id):
            raise ValueError("retrieval cache IDs are unsafe")
        if self.rank < 1 or not math.isfinite(self.score):
            raise ValueError("retrieval cache rank or score is invalid")


def validate_safe_cache_payload(payload: Any) -> tuple[SafeCachedHit, ...]:
    """Validate the complete safe-ID-only cache schema recursively."""

    if not isinstance(payload, dict) or set(payload) != _CACHE_FIELDS:
        raise ValueError("retrieval cache fields are invalid")
    if payload.get("schema") != CACHE_ENTRY_SCHEMA:
        raise ValueError("retrieval cache schema is invalid")
    if not _SHA256.fullmatch(str(payload.get("cache_key") or "")):
        raise ValueError("retrieval cache key is invalid")
    if not _SAFE_ID.fullmatch(str(payload.get("active_build_id") or "")):
        raise ValueError("retrieval cache build ID is unsafe")
    for field in ("created_at", "expires_at"):
        try:
            value = float(payload[field])
        except (TypeError, ValueError) as exc:
            raise ValueError("retrieval cache timestamp is invalid") from exc
        if not math.isfinite(value) or value < 0:
            raise ValueError("retrieval cache timestamp is invalid")
    raw_hits = payload.get("hits")
    if not isinstance(raw_hits, list) or len(raw_hits) > 100:
        raise ValueError("retrieval cache hits are invalid")
    hits: list[SafeCachedHit] = []
    for item in raw_hits:
        if not isinstance(item, dict) or set(item) != _HIT_FIELDS:
            raise ValueError("retrieval cache hit fields are invalid")
        hit = SafeCachedHit(**item)
        hit.validate()
        hits.append(hit)
    return tuple(hits)


def cache_allowed(*, upload_ids: Sequence[str], online_result: bool) -> bool:
    """Return false for context that is not part of the immutable ACTIVE build."""

    return not upload_ids and not online_result


class SafeRetrievalCache:
    def __init__(
        self,
        root: Path,
        *,
        ttl_seconds: int = 900,
        max_entries: int = 1_000,
    ) -> None:
        if ttl_seconds < 1 or max_entries < 1:
            raise ValueError("retrieval cache bounds must be positive")
        self.root = root
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def get(self, *, active_build_id: str, key: str) -> tuple[SafeCachedHit, ...] | None:
        self._validate_key(key)
        path = self._entry_path(active_build_id, key)
        with self._locked():
            try:
                if path.stat().st_size > 1_000_000:
                    raise ValueError
                payload = json.loads(path.read_text(encoding="utf-8"))
                hits = validate_safe_cache_payload(payload)
                if (
                    payload.get("cache_key") != key
                    or payload.get("active_build_id") != active_build_id
                    or float(payload["expires_at"]) <= time.time()
                ):
                    raise ValueError
                os.utime(path, None)
                return hits
            except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError):
                path.unlink(missing_ok=True)
                return None

    def put(
        self,
        *,
        active_build_id: str,
        key: str,
        hits: Sequence[SafeCachedHit],
    ) -> None:
        self._validate_key(key)
        if len(hits) > 100:
            raise ValueError("retrieval cache entry exceeds the safe hit cap")
        for hit in hits:
            hit.validate()
        path = self._entry_path(active_build_id, key)
        payload = {
            "schema": CACHE_ENTRY_SCHEMA,
            "cache_key": key,
            "active_build_id": active_build_id,
            "created_at": time.time(),
            "expires_at": time.time() + self.ttl_seconds,
            "hits": [asdict(hit) for hit in hits],
        }
        serialised = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        with self._locked():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.parent.chmod(0o700)
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{key}-", suffix=".tmp", dir=path.parent
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    os.fchmod(handle.fileno(), 0o600)
                    handle.write(serialised)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
                path.chmod(0o600)
            except Exception:
                Path(temporary).unlink(missing_ok=True)
                raise
            self._evict_locked()

    def invalidate_for_pointer_change(self, *, active_build_id: str) -> int:
        """Remove every namespace except the newly selected ACTIVE build."""

        keep = self._namespace(active_build_id)
        removed = 0
        with self._locked():
            for directory in self.root.iterdir():
                if not directory.is_dir() or directory.name == keep:
                    continue
                for path in directory.glob("*.json"):
                    path.unlink(missing_ok=True)
                    removed += 1
                with suppress(OSError):
                    directory.rmdir()
        return removed

    def clear_build(self, active_build_id: str) -> int:
        directory = self.root / self._namespace(active_build_id)
        removed = 0
        with self._locked():
            for path in directory.glob("*.json") if directory.is_dir() else ():
                path.unlink(missing_ok=True)
                removed += 1
            with suppress(OSError):
                directory.rmdir()
        return removed

    def _entry_path(self, active_build_id: str, key: str) -> Path:
        return self.root / self._namespace(active_build_id) / f"{key}.json"

    @staticmethod
    def _namespace(active_build_id: str) -> str:
        if not _SAFE_ID.fullmatch(active_build_id):
            raise ValueError("retrieval cache build ID is required")
        return hashlib.sha256(active_build_id.encode("utf-8")).hexdigest()[:24]

    @staticmethod
    def _validate_key(key: str) -> None:
        if not _SHA256.fullmatch(key):
            raise ValueError("retrieval cache key must be a lowercase SHA-256")

    def _evict_locked(self) -> None:
        entries = sorted(
            self.root.glob("*/*.json"),
            key=lambda path: path.stat().st_mtime,
        )
        for path in entries[: max(0, len(entries) - self.max_entries)]:
            path.unlink(missing_ok=True)

    def _locked(self) -> _FileLock:
        return _FileLock(self.root / ".cache.lock")


class _FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: Any | None = None

    def __enter__(self) -> None:
        self.handle = self.path.open("a+b")
        os.fchmod(self.handle.fileno(), 0o600)
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)

    def __exit__(self, *_args: object) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
