"""Event-driven freshness intake that can stage research but never index it."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Protocol

from ..crypto import LocalCipher
from ..db import Database
from ..privacy import assert_review_payload_safe, scrub_pii
from .models import (
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")
_SAFE_SOURCE_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class KnowledgeEventType(StrEnum):
    KNOWLEDGE_GAP = "knowledge_gap"
    SOURCE_CHANGED = "source_changed"
    PROJECT_CLARIFICATION = "project_clarification"


@dataclass(frozen=True, slots=True)
class KnowledgeUpdateEventRequest:
    event_type: KnowledgeEventType
    subject: str
    jurisdiction: str = "England and Wales"
    source_id: str | None = None
    authority_identity_id: str | None = None
    knowledge_gap_id: str | None = None
    source_date: date | None = None
    as_of_date: date | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    query_sha256: str | None = None
    safe_payload: Mapping[str, Any] = field(default_factory=dict)
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class KnowledgeUpdateReceipt:
    event_id: str
    idempotency_key: str
    status: str
    dispatch_mode: str
    research_task_id: str | None
    owner_admission_required: bool = True
    writes_index: bool = False
    stages_quarantine_only: bool = True


class ResearchAdmitter(Protocol):
    def admit(self, request: ResearchTaskRequest) -> Any: ...


class _RowLike(Protocol):
    def __getitem__(self, key: str) -> Any: ...


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = (
        json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class KnowledgeFreshnessCoordinator:
    """Persist a webhook/event and optionally admit one staging-only crawl.

    "Direct" means direct admission to the existing durable queue, not direct
    crawling or direct indexing.  Every fetched byte still enters encrypted
    quarantine and every proposition-level source still requires owner
    admission before a consolidated successor candidate can be built.
    """

    def __init__(
        self,
        database: Database,
        cipher: LocalCipher,
        admitter: ResearchAdmitter,
        *,
        batch_threshold: int = 4,
    ) -> None:
        if not 2 <= batch_threshold <= 100:
            raise ValueError("knowledge-update batch threshold is invalid")
        self.database = database
        self.cipher = cipher
        self.admitter = admitter
        self.batch_threshold = batch_threshold

    def receive(self, request: KnowledgeUpdateEventRequest) -> KnowledgeUpdateReceipt:
        normalized = self._validate(request)
        identity = {
            "schema": "legalbot.knowledge-update-event.v1",
            "event_type": request.event_type.value,
            "subject": normalized["subject"],
            "jurisdiction": normalized["jurisdiction"],
            "source_id": normalized["source_id"],
            "authority_identity_id": normalized["authority_identity_id"],
            "knowledge_gap_id": normalized["knowledge_gap_id"],
            "source_date": normalized["source_date"],
            "as_of_date": normalized["as_of_date"],
            "observed_at": normalized["observed_at"],
            "query_sha256": normalized["query_sha256"],
            "safe_payload_sha256": normalized["safe_payload_sha256"],
            "detail_sha256": normalized["detail_sha256"],
        }
        idempotency_key = _canonical_sha256(identity)
        event_id = f"knowledge-event-{idempotency_key[:40]}"
        existing = self.database.fetchone(
            "SELECT * FROM knowledge_update_events WHERE idempotency_key=?",
            (idempotency_key,),
        )
        if existing is not None:
            # A process may have stopped after the durable insert but before
            # queue admission.  An exact webhook retry resumes that one event;
            # the downstream research task identity is independently idempotent.
            if str(existing["status"]) == "received":
                self._dispatch(str(existing["id"]), request, normalized)
                existing = self.database.fetchone(
                    "SELECT * FROM knowledge_update_events WHERE idempotency_key=?",
                    (idempotency_key,),
                )
                if existing is None:
                    raise RuntimeError("knowledge update event disappeared")
            return self._receipt(existing)

        stamp = str(normalized["observed_at"])
        with self.database.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM knowledge_update_events WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                return self._receipt(existing)
            pending = connection.execute(
                """
                SELECT COUNT(*) AS n FROM knowledge_update_events
                WHERE status IN ('received','queued_for_quarantine')
                """
            ).fetchone()
            pending_count = int(pending["n"] if pending is not None else 0)
            dispatch_mode = (
                "batched_durable_queue"
                if pending_count + 1 >= self.batch_threshold
                else "direct_durable_queue_admission"
            )
            connection.execute(
                """
                INSERT INTO knowledge_update_events(
                  id,idempotency_key,event_type,source_id,authority_identity_id,
                  knowledge_gap_id,subject,jurisdiction,source_date,as_of_date,
                  observed_at,last_updated_at,query_sha256,safe_payload_json,
                  encrypted_detail,status,dispatch_mode,owner_admission_required,
                  writes_index,created_at,updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'received', ?, 1, 0, ?, ?)
                """,
                (
                    event_id,
                    idempotency_key,
                    request.event_type.value,
                    normalized["source_id"],
                    normalized["authority_identity_id"],
                    normalized["knowledge_gap_id"],
                    normalized["subject"],
                    normalized["jurisdiction"],
                    normalized["source_date"],
                    normalized["as_of_date"],
                    stamp,
                    stamp,
                    normalized["query_sha256"],
                    normalized["safe_payload_json"],
                    (
                        self.cipher.encrypt_text(request.detail.strip())
                        if request.detail and request.detail.strip()
                        else None
                    ),
                    dispatch_mode,
                    stamp,
                    stamp,
                ),
            )
        self._dispatch(event_id, request, normalized)
        persisted = self.database.fetchone(
            "SELECT * FROM knowledge_update_events WHERE id=?", (event_id,)
        )
        if persisted is None:
            raise RuntimeError("knowledge update event disappeared")
        return self._receipt(persisted)

    def _dispatch(
        self,
        event_id: str,
        request: KnowledgeUpdateEventRequest,
        normalized: Mapping[str, Any],
    ) -> None:
        if request.event_type is KnowledgeEventType.PROJECT_CLARIFICATION:
            self._set_status(event_id, "recorded_for_owner_review")
            return
        if not normalized["source_id"]:
            self._set_status(event_id, "owner_route_required")
            return
        if request.event_type is KnowledgeEventType.KNOWLEDGE_GAP and (
            not normalized["knowledge_gap_id"] or not normalized["query_sha256"]
        ):
            self._set_status(event_id, "verified_gap_binding_required")
            return
        task_type = (
            ResearchTaskType.GAP_RESEARCH
            if request.event_type is KnowledgeEventType.KNOWLEDGE_GAP
            else ResearchTaskType.SOURCE_UPDATE_CHECK
        )
        try:
            task = self.admitter.admit(
                ResearchTaskRequest(
                    task_type=task_type,
                    trigger=ResearchTrigger.ENQUIRY,
                    priority=ResearchPriority.HIGH,
                    subject=str(normalized["subject"]),
                    jurisdiction=str(normalized["jurisdiction"]),
                    as_of_date=request.as_of_date or _utc(request.observed_at).date(),
                    source_id=str(normalized["source_id"]),
                    authority_identity_id=(
                        str(normalized["authority_identity_id"])
                        if normalized["authority_identity_id"]
                        else None
                    ),
                    knowledge_gap_id=(
                        str(normalized["knowledge_gap_id"])
                        if normalized["knowledge_gap_id"]
                        else None
                    ),
                    query_sha256=(
                        str(normalized["query_sha256"]) if normalized["query_sha256"] else None
                    ),
                )
            )
        except (KeyError, RuntimeError, ValueError) as exc:
            failure_code = f"admission_{type(exc).__name__.casefold()}"
            self._set_status(event_id, "admission_blocked", failure_code=failure_code)
            return
        try:
            task_id = str(task["id"] or "")
        except (KeyError, TypeError):
            task_id = ""
        if not _SAFE_ID.fullmatch(task_id):
            self._set_status(event_id, "admission_blocked", failure_code="task_identity_invalid")
            return
        self._set_status(
            event_id,
            "queued_for_quarantine",
            research_task_id=task_id,
        )

    def _set_status(
        self,
        event_id: str,
        status: str,
        *,
        research_task_id: str | None = None,
        failure_code: str | None = None,
    ) -> None:
        self.database.execute(
            """
            UPDATE knowledge_update_events
            SET status=?,research_task_id=COALESCE(research_task_id, ?),
                failure_code=?,updated_at=? WHERE id=?
            """,
            (status, research_task_id, failure_code, datetime.now(UTC).isoformat(), event_id),
        )

    @staticmethod
    def _receipt(row: _RowLike) -> KnowledgeUpdateReceipt:
        return KnowledgeUpdateReceipt(
            event_id=str(row["id"]),
            idempotency_key=str(row["idempotency_key"]),
            status=str(row["status"]),
            dispatch_mode=str(row["dispatch_mode"]),
            research_task_id=(
                str(row["research_task_id"]) if row["research_task_id"] is not None else None
            ),
            owner_admission_required=bool(row["owner_admission_required"]),
            writes_index=bool(row["writes_index"]),
        )

    @staticmethod
    def _validate(request: KnowledgeUpdateEventRequest) -> dict[str, Any]:
        subject = " ".join(request.subject.split()).casefold()
        jurisdiction = " ".join(request.jurisdiction.split())
        source_id = " ".join((request.source_id or "").split()) or None
        authority = " ".join((request.authority_identity_id or "").split()) or None
        gap_id = " ".join((request.knowledge_gap_id or "").split()) or None
        query_sha256 = request.query_sha256 or None
        if (
            not subject
            or len(subject) > 80
            or scrub_pii(subject) != subject
            or not jurisdiction
            or len(jurisdiction) > 80
            or scrub_pii(jurisdiction) != jurisdiction
        ):
            raise ValueError("knowledge update taxonomy is invalid")
        if source_id is not None and not _SAFE_SOURCE_ID.fullmatch(source_id):
            raise ValueError("knowledge update source is invalid")
        if authority is not None and (
            len(authority) > 255
            or "\n" in authority
            or "\r" in authority
            or scrub_pii(authority) != authority
        ):
            raise ValueError("knowledge update authority is invalid")
        if gap_id is not None and not _SAFE_ID.fullmatch(gap_id):
            raise ValueError("knowledge update gap is invalid")
        if query_sha256 is not None and not _SHA256.fullmatch(query_sha256):
            raise ValueError("knowledge update query digest is invalid")
        if request.event_type is KnowledgeEventType.SOURCE_CHANGED and (
            source_id is None or authority is None
        ):
            raise ValueError("source-change event requires source and authority identities")
        if request.detail is not None and len(request.detail) > 20_000:
            raise ValueError("knowledge update detail is too large")
        safe_payload_json = json.dumps(
            dict(request.safe_payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        if len(safe_payload_json) > 20_000:
            raise ValueError("knowledge update payload is too large")
        assert_review_payload_safe(safe_payload_json)
        observed = _utc(request.observed_at)
        return {
            "subject": subject,
            "jurisdiction": jurisdiction,
            "source_id": source_id,
            "authority_identity_id": authority,
            "knowledge_gap_id": gap_id,
            "source_date": request.source_date.isoformat() if request.source_date else None,
            "as_of_date": request.as_of_date.isoformat() if request.as_of_date else None,
            "observed_at": observed.isoformat(),
            "query_sha256": query_sha256,
            "safe_payload_json": safe_payload_json,
            "safe_payload_sha256": hashlib.sha256(safe_payload_json.encode()).hexdigest(),
            "detail_sha256": (
                hashlib.sha256(request.detail.strip().encode()).hexdigest()
                if request.detail and request.detail.strip()
                else None
            ),
        }
