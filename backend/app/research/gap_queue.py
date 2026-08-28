"""Persistent review queue for detected legal-knowledge coverage gaps."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, cast


class GapStatus(StrEnum):
    OPEN = "open"
    CANDIDATE_STAGED = "candidate_staged"
    REVIEW_REQUIRED = "review_required"
    REJECTED = "rejected"
    RESOLVED_EXTERNALLY = "resolved_externally"


class GapKind(StrEnum):
    LEGISLATION = "legislation"
    COMMENCEMENT_OR_EFFECT = "commencement_or_effect"
    CASE_AUTHORITY = "case_authority"
    PROCEDURE = "procedure"
    REGULATOR = "regulator"
    SCHOLARSHIP = "scholarship"
    CITATION_METADATA = "citation_metadata"
    RETRIEVAL_MISS = "retrieval_miss"
    LICENCE = "licence"


class LegacyGapQueueReadOnlyError(RuntimeError):
    """Raised when retired JSON storage is asked to accept new records."""


@dataclass(frozen=True, slots=True)
class GapCandidate:
    source_id: str
    source_identity: str
    canonical_url: str
    metadata_sha256: str
    staged_at: str


@dataclass(frozen=True, slots=True)
class GapItem:
    gap_id: str
    subject: str
    jurisdiction: str
    kind: GapKind
    reason_code: str
    description: str
    query_alias: str | None
    priority: int
    status: GapStatus
    created_at: str
    updated_at: str
    candidates: tuple[GapCandidate, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


class GapQueue:
    """Legacy audit reader. Writes require an explicit test/migration opt-in."""

    def __init__(self, path: str | Path, *, allow_writes: bool = False) -> None:
        self.path = Path(path)
        self.allow_writes = allow_writes
        if allow_writes:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _require_writable(self) -> None:
        if not self.allow_writes:
            raise LegacyGapQueueReadOnlyError(
                "the JSON research gap queue is an immutable audit artifact; use SQLite"
            )

    def enqueue(
        self,
        *,
        subject: str,
        jurisdiction: str,
        kind: GapKind,
        reason_code: str,
        description: str,
        query_alias: str | None = None,
        priority: int = 50,
        metadata: Mapping[str, Any] | None = None,
    ) -> GapItem:
        self._require_writable()
        if not 0 <= priority <= 100:
            raise ValueError("priority must be between 0 and 100")
        if not subject.strip() or not reason_code.strip() or not description.strip():
            raise ValueError("subject, reason and generalized description are required")
        now = datetime.now(UTC).isoformat()
        item = GapItem(
            f"gap_{uuid.uuid4().hex}",
            subject.strip(),
            jurisdiction,
            kind,
            reason_code,
            description,
            query_alias,
            priority,
            GapStatus.OPEN,
            now,
            now,
            metadata=dict(metadata or {}),
        )
        with self._lock:
            payload = self._read()
            for raw in payload["items"]:
                existing = self._deserialize(raw)
                if (
                    existing.subject == item.subject
                    and existing.jurisdiction == item.jurisdiction
                    and existing.kind is item.kind
                    and existing.reason_code == item.reason_code
                    and existing.status
                    in {GapStatus.OPEN, GapStatus.CANDIDATE_STAGED, GapStatus.REVIEW_REQUIRED}
                ):
                    return existing
            payload["items"].append(self._serialize(item))
            self._write(payload)
        return item

    def stage_candidate(
        self,
        gap_id: str,
        *,
        source_id: str,
        source_identity: str,
        canonical_url: str,
        metadata: Mapping[str, Any],
    ) -> GapItem:
        self._require_writable()
        metadata_bytes = json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8")
        candidate = GapCandidate(
            source_id,
            source_identity,
            canonical_url,
            hashlib.sha256(metadata_bytes).hexdigest(),
            datetime.now(UTC).isoformat(),
        )
        with self._lock:
            payload = self._read()
            raw = self._find(payload, gap_id)
            existing = self._deserialize(raw)
            if existing.status not in {
                GapStatus.OPEN,
                GapStatus.CANDIDATE_STAGED,
                GapStatus.REVIEW_REQUIRED,
            }:
                raise ValueError(
                    f"cannot stage a candidate for gap in state {existing.status.value}"
                )
            candidates = tuple(
                sorted(
                    {
                        candidate.source_identity: candidate
                        for candidate in (*existing.candidates, candidate)
                    }.values(),
                    key=lambda value: value.source_identity,
                )
            )
            updated = GapItem(
                **{
                    **asdict(existing),
                    "kind": existing.kind,
                    "status": GapStatus.CANDIDATE_STAGED,
                    "updated_at": datetime.now(UTC).isoformat(),
                    "candidates": candidates,
                }
            )
            raw.clear()
            raw.update(self._serialize(updated))
            self._write(payload)
            return updated

    def require_review(self, gap_id: str) -> GapItem:
        return self._transition(gap_id, GapStatus.REVIEW_REQUIRED)

    def reject(self, gap_id: str) -> GapItem:
        return self._transition(gap_id, GapStatus.REJECTED)

    def resolve_externally(self, gap_id: str) -> GapItem:
        return self._transition(gap_id, GapStatus.RESOLVED_EXTERNALLY)

    def list(self, *, status: GapStatus | None = None) -> tuple[GapItem, ...]:
        with self._lock:
            items = tuple(self._deserialize(raw) for raw in self._read()["items"])
        filtered = (item for item in items if status is None or item.status is status)
        return tuple(
            sorted(filtered, key=lambda item: (-item.priority, item.created_at, item.gap_id))
        )

    def _transition(self, gap_id: str, status: GapStatus) -> GapItem:
        self._require_writable()
        with self._lock:
            payload = self._read()
            raw = self._find(payload, gap_id)
            item = self._deserialize(raw)
            updated = GapItem(
                **{
                    **asdict(item),
                    "kind": item.kind,
                    "status": status,
                    "updated_at": datetime.now(UTC).isoformat(),
                    "candidates": item.candidates,
                }
            )
            raw.clear()
            raw.update(self._serialize(updated))
            self._write(payload)
            return updated

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema": "legalbot.gap-queue.v1", "items": []}
        decoded: object = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
            raise ValueError("gap queue must be a JSON object with string keys")
        payload = cast(dict[str, Any], decoded)
        if payload.get("schema") != "legalbot.gap-queue.v1":
            raise ValueError("unsupported gap queue schema")
        items = payload.get("items")
        if not isinstance(items, list):
            raise ValueError("gap queue items must be a JSON array")
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        self._require_writable()
        data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.path)
        finally:
            Path(temporary_name).unlink(missing_ok=True)

    @staticmethod
    def _find(payload: dict[str, Any], gap_id: str) -> dict[str, Any]:
        items = payload.get("items")
        if not isinstance(items, list):
            raise ValueError("gap queue items must be a JSON array")
        for candidate in items:
            if not isinstance(candidate, dict) or not all(
                isinstance(key, str) for key in candidate
            ):
                raise ValueError("each gap queue item must be a JSON object")
            raw = cast(dict[str, Any], candidate)
            if raw.get("gap_id") == gap_id:
                return raw
        raise KeyError(gap_id)

    @staticmethod
    def _serialize(item: GapItem) -> dict[str, Any]:
        result = asdict(item)
        result["kind"] = item.kind.value
        result["status"] = item.status.value
        return result

    @staticmethod
    def _deserialize(raw: Mapping[str, Any]) -> GapItem:
        return GapItem(
            gap_id=raw["gap_id"],
            subject=raw["subject"],
            jurisdiction=raw["jurisdiction"],
            kind=GapKind(raw["kind"]),
            reason_code=raw["reason_code"],
            description=raw["description"],
            query_alias=raw.get("query_alias"),
            priority=int(raw["priority"]),
            status=GapStatus(raw["status"]),
            created_at=raw["created_at"],
            updated_at=raw["updated_at"],
            candidates=tuple(GapCandidate(**candidate) for candidate in raw.get("candidates", [])),
            metadata=raw.get("metadata", {}),
        )
