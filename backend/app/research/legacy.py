"""One-way bridge from the retired JSON gap queue into durable SQLite."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, cast

from ..crypto import LocalCipher
from ..db import Database
from .control_plane import ResearchControlPlane
from .gap_queue import GapCandidate, GapItem, GapKind, GapStatus
from .models import (
    ResearchCandidateDraft,
    ResearchCandidateStatus,
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)


def _priority(value: int) -> ResearchPriority:
    if value >= 80:
        return ResearchPriority.HIGH
    if value >= 40:
        return ResearchPriority.MEDIUM
    return ResearchPriority.LOW


class DatabaseGapCandidateSink:
    """Compatibility sink used by answer-time research; it never writes JSON."""

    def __init__(self, control: ResearchControlPlane) -> None:
        self.control = control
        self.database = control.database

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
        metadata: dict[str, Any] | None = None,
    ) -> GapItem:
        material = "\0".join((subject, jurisdiction, kind.value, reason_code))
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        task = self.control.admit(
            ResearchTaskRequest(
                # This compatibility sink has no canonical answer-gap row to
                # bind.  Keep it in the discovery/staging lane instead of
                # manufacturing a knowledge-gap identity that the owner could
                # mistake for a released-answer failure.
                task_type=ResearchTaskType.BROAD_DISCOVERY,
                trigger=ResearchTrigger.ENQUIRY,
                priority=_priority(priority),
                subject=subject,
                jurisdiction=jurisdiction,
                as_of_date=date.today(),
                query_sha256=digest,
                idempotency_key=f"answer-time-gap:{digest}",
                staging_only=True,
            )
        )
        now = str(task["created_at"])
        return GapItem(
            gap_id=str(task["id"]),
            subject=subject,
            jurisdiction=jurisdiction,
            kind=kind,
            reason_code=reason_code,
            description="An official candidate requires owner review.",
            query_alias=None,
            priority=priority,
            status=GapStatus.OPEN,
            created_at=now,
            updated_at=now,
            metadata={"storage": "sqlite", "disposition": "staged_only"},
        )

    def stage_candidate(
        self,
        gap_id: str,
        *,
        source_id: str,
        source_identity: str,
        canonical_url: str,
        metadata: Mapping[str, Any],
    ) -> GapItem:
        metadata_sha = hashlib.sha256(
            json.dumps(dict(metadata), ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        row = self.control.stage_candidate(
            gap_id,
            ResearchCandidateDraft(
                source_id=source_id,
                source_identity=source_identity,
                canonical_url=canonical_url,
                metadata_sha256=metadata_sha,
                status=ResearchCandidateStatus.SYSTEM_VERIFIED,
                safe_metadata=dict(metadata),
            ),
        )
        task = self.database.research_task(gap_id)
        if task is None:
            raise KeyError(gap_id)
        return self._item(task, candidate=row, status=GapStatus.CANDIDATE_STAGED)

    def require_review(self, gap_id: str) -> GapItem:
        task = self.database.research_task(gap_id)
        if task is None:
            raise KeyError(gap_id)
        refinement_id = f"refinement-{hashlib.sha256(gap_id.encode()).hexdigest()[:40]}"
        self.database.create_refinement(
            refinement_id=refinement_id,
            fingerprint=f"answer-time-candidate:{gap_id}",
            category="missing",
            scope="source",
            priority=int(task["base_priority"]),
            origin="official_answer_time_candidate",
            knowledge_gap_id=str(task["knowledge_gap_id"] or "") or None,
            research_task_id=gap_id,
            safe_target={"research_task_id": gap_id},
        )
        self.database.mark_staged_research_task_for_review(gap_id, refinement_id=refinement_id)
        updated = self.database.research_task(gap_id)
        if updated is None:
            raise KeyError(gap_id)
        return self._item(updated, status=GapStatus.REVIEW_REQUIRED)

    def _item(
        self,
        task: Any,
        *,
        candidate: Any | None = None,
        status: GapStatus,
    ) -> GapItem:
        candidates: tuple[GapCandidate, ...] = ()
        if candidate is not None:
            candidates = (
                GapCandidate(
                    source_id=str(candidate["source_id"]),
                    source_identity=str(candidate["source_identity"]),
                    canonical_url=str(candidate["canonical_url"]),
                    metadata_sha256=str(candidate["metadata_sha256"]),
                    staged_at=str(candidate["created_at"]),
                ),
            )
        return GapItem(
            gap_id=str(task["id"]),
            subject=str(task["subject"]),
            jurisdiction=str(task["jurisdiction"]),
            kind=GapKind.RETRIEVAL_MISS,
            reason_code="answer_time_official_candidate",
            description="An official candidate requires owner review.",
            query_alias=None,
            priority=int(task["base_priority"]),
            status=status,
            created_at=str(task["created_at"]),
            updated_at=str(task["updated_at"]),
            candidates=candidates,
            metadata={"storage": "sqlite", "disposition": "staged_only"},
        )


class LegacyResearchGapImporter:
    """Import once, then preserve the exact legacy bytes only as an encrypted audit."""

    def __init__(
        self,
        database: Database,
        control: ResearchControlPlane,
        cipher: LocalCipher,
    ) -> None:
        self.database = database
        self.control = control
        self.cipher = cipher

    def import_file(self, path: Path) -> dict[str, int | str]:
        raw = path.read_bytes()
        manifest_sha = hashlib.sha256(raw).hexdigest()
        if self.database.legacy_research_gap_imported(manifest_sha):
            archive = self._archive_and_remove_plaintext(path, raw, manifest_sha)
            return {
                "manifest_sha256": manifest_sha,
                "imported": 0,
                "skipped": 0,
                "archive": archive.name,
            }
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("schema") != "legalbot.gap-queue.v1":
            raise ValueError("legacy research gap queue schema is invalid")
        items = payload.get("items")
        if not isinstance(items, list):
            raise ValueError("legacy research gap queue items are invalid")
        imported = 0
        skipped = 0
        for raw_item in items:
            if not isinstance(raw_item, dict):
                skipped += 1
                continue
            item = cast(dict[str, Any], raw_item)
            try:
                self._import_item(item, manifest_sha)
            except (KeyError, TypeError, ValueError):
                skipped += 1
            else:
                imported += 1
        self.database.record_legacy_research_gap_import(
            manifest_sha256=manifest_sha,
            schema_name="legalbot.gap-queue.v1",
            imported_count=imported,
            skipped_count=skipped,
        )
        archive = self._archive_and_remove_plaintext(path, raw, manifest_sha)
        return {
            "manifest_sha256": manifest_sha,
            "imported": imported,
            "skipped": skipped,
            "archive": archive.name,
        }

    def _archive_and_remove_plaintext(self, path: Path, raw: bytes, manifest_sha: str) -> Path:
        """Atomically install, decrypt-verify, then remove one plaintext manifest."""

        try:
            serialised = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("legacy research gap queue is not UTF-8") from exc
        if hashlib.sha256(serialised.encode("utf-8")).hexdigest() != manifest_sha:
            raise RuntimeError("legacy research gap queue changed before archival")
        destination = path.with_name(f"{path.name}.enc")
        if destination.exists():
            encrypted = destination.read_bytes()
            if self.cipher.decrypt_text(encrypted).encode("utf-8") != raw:
                raise RuntimeError("legacy research encrypted archive does not match plaintext")
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.", suffix=".enc.tmp", dir=path.parent
            )
            temporary = Path(temporary_name)
            try:
                encrypted = self.cipher.encrypt_text(serialised)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(encrypted)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.chmod(0o600)
                os.replace(temporary, destination)
                destination.chmod(0o600)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
            if self.cipher.decrypt_text(destination.read_bytes()).encode("utf-8") != raw:
                raise RuntimeError("legacy research encrypted archive verification failed")
        path.unlink(missing_ok=True)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return destination

    def _import_item(self, item: dict[str, Any], manifest_sha: str) -> None:
        gap_id = str(item["gap_id"])
        description = str(item["description"])
        query_alias = str(item.get("query_alias") or "")
        note = json.dumps(
            {"description": description, "query_alias": query_alias},
            ensure_ascii=False,
            sort_keys=True,
        )
        note_sha = hashlib.sha256(note.encode("utf-8")).hexdigest()
        priority_value = int(item.get("priority", 50))
        task = self.control.admit(
            ResearchTaskRequest(
                # Legacy JSON items predate the durable answer-gap table and
                # therefore cannot honestly be admitted as gap_research.  They
                # are preserved as manual discovery tasks plus an encrypted
                # missing-source refinement below.
                task_type=ResearchTaskType.BROAD_DISCOVERY,
                trigger=ResearchTrigger.MANUAL,
                priority=_priority(priority_value),
                subject=str(item["subject"]),
                jurisdiction=str(item["jurisdiction"]),
                as_of_date=datetime.now(UTC).date(),
                query_sha256=note_sha,
                idempotency_key=f"legacy-gap:{manifest_sha}:{gap_id}",
                staging_only=True,
            )
        )
        refinement_id = (
            f"refinement-{hashlib.sha256(f'{manifest_sha}:{gap_id}'.encode()).hexdigest()[:40]}"
        )
        self.database.create_refinement(
            refinement_id=refinement_id,
            fingerprint=f"legacy-gap:{manifest_sha}:{gap_id}",
            category="missing",
            scope="source",
            priority=priority_value,
            origin="legacy_research_gap_import",
            research_task_id=str(task["id"]),
            safe_target={"legacy_gap_id": gap_id, "manifest_sha256": manifest_sha},
            encrypted_note=self.cipher.encrypt_text(note),
            note_sha256=note_sha,
        )
        raw_candidates = item.get("candidates", [])
        if not isinstance(raw_candidates, list):
            raw_candidates = []
        for raw_candidate in raw_candidates[:20]:
            if not isinstance(raw_candidate, dict):
                continue
            try:
                metadata_sha = str(raw_candidate["metadata_sha256"])
                self.control.stage_candidate(
                    str(task["id"]),
                    ResearchCandidateDraft(
                        source_id=str(raw_candidate["source_id"]),
                        source_identity=str(raw_candidate["source_identity"]),
                        canonical_url=str(raw_candidate["canonical_url"]),
                        metadata_sha256=metadata_sha,
                        status=ResearchCandidateStatus.EXPERT_REVIEW,
                        safe_metadata={"legacy_manifest_sha256": manifest_sha},
                    ),
                )
            except (KeyError, TypeError, ValueError):
                continue
        self.database.mark_staged_research_task_for_review(
            str(task["id"]), refinement_id=refinement_id, reason="legacy_gap_imported"
        )
