"""Encrypted, append-only owner refinement and answer-feedback workflows."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from sqlite3 import Row
from uuid import uuid4

from ..crypto import LocalCipher
from ..db import Database
from ..types import AnswerFeedbackRequest, RefinementTransitionRequest

_PUBLIC_RELEASE_STATES = frozenset({"verified_full", "verified_concise", "verified_limited"})
_PRIORITY_BY_RATING = {
    "helpful": 20,
    "partly_helpful": 60,
    "not_helpful": 90,
}
_CATEGORY_FLOOR = {
    "privacy": 100,
    "currentness": 95,
    "authority": 95,
    "accuracy": 90,
    "citation": 85,
}


@dataclass(frozen=True, slots=True)
class FeedbackResult:
    refinement_id: str
    status: str
    priority: int
    duplicate: bool


class RefinementService:
    def __init__(self, database: Database, cipher: LocalCipher) -> None:
        self.database = database
        self.cipher = cipher

    def submit_answer_feedback(
        self,
        answer_id: str,
        request: AnswerFeedbackRequest,
    ) -> FeedbackResult:
        answer = self.database.answer(answer_id)
        if answer is None:
            raise KeyError("answer_not_found")
        if str(answer["release_state"] or "") not in _PUBLIC_RELEASE_STATES:
            raise PermissionError("answer_not_released")

        target_id = self._validate_feedback_target(answer_id, request)
        priority = max(
            _PRIORITY_BY_RATING[request.rating],
            _CATEGORY_FLOOR.get(request.category, 0),
        )
        note = request.note.strip() if request.note else ""
        note_sha256 = hashlib.sha256(note.encode("utf-8")).hexdigest() if note else None
        payload_identity = {
            "rating": request.rating,
            "category": request.category,
            "scope": request.scope,
            "target_id": target_id,
            "note_sha256": note_sha256,
        }
        payload_sha256 = hashlib.sha256(
            json.dumps(payload_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        fingerprint = hashlib.sha256(
            f"answer-feedback-v1\0{answer_id}\0{request.idempotency_key}".encode()
        ).hexdigest()
        existing = self.database.fetchone(
            "SELECT id, status, priority, safe_target_json FROM refinements WHERE fingerprint=?",
            (fingerprint,),
        )
        if existing is not None:
            safe_target = json.loads(str(existing["safe_target_json"] or "{}"))
            if safe_target.get("payload_sha256") != payload_sha256:
                raise RuntimeError("idempotency_payload_mismatch")
            return FeedbackResult(
                refinement_id=str(existing["id"]),
                status=str(existing["status"]),
                priority=int(existing["priority"]),
                duplicate=True,
            )

        row = self.database.create_refinement(
            refinement_id=f"refinement-{uuid4().hex}",
            fingerprint=fingerprint,
            category="answer_feedback",
            scope=request.scope,
            priority=priority,
            origin="released_answer_feedback",
            answer_id=answer_id,
            job_id=str(answer["job_id"]),
            safe_target={
                **payload_identity,
                "payload_sha256": payload_sha256,
            },
            encrypted_note=self.cipher.encrypt_text(note) if note else None,
            note_sha256=note_sha256,
        )
        return FeedbackResult(
            refinement_id=str(row["id"]),
            status=str(row["status"]),
            priority=int(row["priority"]),
            duplicate=False,
        )

    def transition(
        self,
        refinement_id: str,
        request: RefinementTransitionRequest,
    ) -> Row:
        note = request.note.strip() if request.note else ""
        return self.database.transition_refinement(
            refinement_id,
            to_status=request.to_status,
            event_type=request.event_type,
            encrypted_note=self.cipher.encrypt_text(note) if note else None,
            root_cause=request.root_cause,
            repair_version=request.repair_version,
            regression_case_id=request.regression_case_id,
            resolution_evidence=(
                {
                    "report_id": request.resolution_evidence_id,
                    "report_sha256": request.resolution_evidence_sha256,
                }
                if request.resolution_evidence_id and request.resolution_evidence_sha256
                else None
            ),
        )

    def _validate_feedback_target(
        self,
        answer_id: str,
        request: AnswerFeedbackRequest,
    ) -> str | None:
        claims, _links, evidence = self.database.answer_claims_and_evidence(answer_id)
        if request.scope == "answer":
            if request.target_id not in {None, "", answer_id}:
                raise ValueError("feedback_target_not_owned")
            return answer_id
        if not request.target_id:
            raise ValueError("feedback_target_required")
        if request.scope == "section":
            allowed = {str(row["section_id"]) for row in claims}
        elif request.scope == "claim":
            allowed = {
                str(value)
                for row in claims
                for value in (row["id"], row["model_claim_id"])
                if value
            }
        else:
            allowed = {str(row["id"]) for row in evidence}
        if request.target_id not in allowed:
            raise ValueError("feedback_target_not_owned")
        return request.target_id
