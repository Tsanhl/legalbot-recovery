from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.orchestration.refinements import RefinementService
from app.orchestration.runner import AnswerRunner
from app.types import (
    AnswerFeedbackRequest,
    KnowledgeGap,
    RefinementTransitionRequest,
)


def _released_answer(database: object, cipher: object) -> None:
    database.create_job(  # type: ignore[attr-defined]
        job_id="job-feedback",
        encrypted_question=cipher.encrypt_text("Private legal question"),  # type: ignore[attr-defined]
        question_summary="Private question",
        request={"word_target": 1_000},
    )
    database.store_answer_version(  # type: ignore[attr-defined]
        answer_id="answer-feedback",
        job_id="job-feedback",
        version_number=1,
        version_kind="candidate",
        encrypted_content=cipher.encrypt_text("Released answer"),  # type: ignore[attr-defined]
        word_count=2,
        policy_version="test-policy",
        model_version="test-model",
        index_build_id=None,
        release_state="verified_limited",
    )
    database.store_claims(  # type: ignore[attr-defined]
        "answer-feedback",
        [
            {
                "id": "claim-visible",
                "section_id": "analysis",
                "encrypted_text": cipher.encrypt_text("A supported claim"),  # type: ignore[attr-defined]
                "proposition_hash": hashlib.sha256(b"A supported claim").hexdigest(),
                "verification_status": "verified",
            }
        ],
    )


def test_feedback_is_encrypted_owned_and_idempotent(database: object, cipher: object) -> None:
    _released_answer(database, cipher)
    service = RefinementService(database, cipher)  # type: ignore[arg-type]
    request = AnswerFeedbackRequest(
        rating="not_helpful",
        category="currentness",
        scope="claim",
        target_id="claim-visible",
        note="The authority appears out of date.",
        idempotency_key="feedback-idempotency-0001",
    )

    first = service.submit_answer_feedback("answer-feedback", request)
    second = service.submit_answer_feedback("answer-feedback", request)

    assert first.priority == 95
    assert second.refinement_id == first.refinement_id
    assert second.duplicate is True
    row = database.fetchone(  # type: ignore[attr-defined]
        "SELECT encrypted_note, occurrence_count FROM refinements WHERE id=?",
        (first.refinement_id,),
    )
    assert row["encrypted_note"]
    assert b"out of date" not in row["encrypted_note"]
    assert row["occurrence_count"] == 1

    changed_note = request.model_copy(update={"note": "A different owner note."})
    with pytest.raises(RuntimeError, match="idempotency_payload_mismatch"):
        service.submit_answer_feedback("answer-feedback", changed_note)


def test_feedback_rejects_foreign_target_and_unreleased_answer(
    database: object, cipher: object
) -> None:
    _released_answer(database, cipher)
    service = RefinementService(database, cipher)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not_owned"):
        service.submit_answer_feedback(
            "answer-feedback",
            AnswerFeedbackRequest(
                rating="partly_helpful",
                category="accuracy",
                scope="claim",
                target_id="claim-from-another-answer",
                idempotency_key="feedback-idempotency-0002",
            ),
        )
    database.execute(  # type: ignore[attr-defined]
        "UPDATE answer_versions SET release_state='held_for_review' WHERE id='answer-feedback'"
    )
    with pytest.raises(PermissionError, match="not_released"):
        service.submit_answer_feedback(
            "answer-feedback",
            AnswerFeedbackRequest(
                rating="helpful",
                category="clarity",
                idempotency_key="feedback-idempotency-0003",
            ),
        )


def test_refinement_transition_is_append_only(database: object, cipher: object) -> None:
    _released_answer(database, cipher)
    service = RefinementService(database, cipher)  # type: ignore[arg-type]
    created = service.submit_answer_feedback(
        "answer-feedback",
        AnswerFeedbackRequest(
            rating="partly_helpful",
            category="completeness",
            idempotency_key="feedback-idempotency-0004",
        ),
    )
    row = service.transition(
        created.refinement_id,
        RefinementTransitionRequest(
            to_status="triaged",
            event_type="owner_triaged",
            note="Review later",
        ),
    )
    assert row["status"] == "triaged"
    events = database.fetchall(  # type: ignore[attr-defined]
        "SELECT event_type, to_status, encrypted_note FROM refinement_events "
        "WHERE refinement_id=? ORDER BY sequence",
        (created.refinement_id,),
    )
    assert [item["event_type"] for item in events] == ["created", "owner_triaged"]
    assert events[-1]["encrypted_note"]


def test_answer_gap_is_idempotently_projected_to_missing_inbox(
    tmp_path: Path, database: object, cipher: object
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    database.create_job(  # type: ignore[attr-defined]
        job_id="job-gap-inbox",
        encrypted_question=cipher.encrypt_text("Private question"),  # type: ignore[attr-defined]
        question_summary="Private question",
        request={"word_target": 1_000},
    )
    runner = AnswerRunner(
        settings=settings,
        database=database,  # type: ignore[arg-type]
        cipher=cipher,  # type: ignore[arg-type]
        retriever=SimpleNamespace(),  # type: ignore[arg-type]
        model=SimpleNamespace(),  # type: ignore[arg-type]
    )
    proposition = "Private missing proposition that must remain encrypted."
    gap = KnowledgeGap(
        id="gap-owner-inbox-001",
        job_id="job-gap-inbox",
        missing_proposition=proposition,
        jurisdiction="England and Wales",
        subject="contract",
        searches_attempted=[{"source": "private search detail"}],
        rejection_reasons=["private rejection detail"],
    )
    path = runner.gaps.persist(gap)

    runner._store_gap(gap, path)
    runner._store_gap(gap, path)

    rows = database.fetchall(  # type: ignore[attr-defined]
        "SELECT * FROM refinements WHERE category='missing'"
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["job_id"] == gap.job_id and row["knowledge_gap_id"] == gap.id
    assert row["occurrence_count"] == 1
    assert row["encrypted_note"] is None
    safe_target = json.loads(row["safe_target_json"])
    assert safe_target == {
        "job_id": gap.job_id,
        "knowledge_gap_id": gap.id,
        "proposition_sha256": hashlib.sha256(proposition.encode()).hexdigest(),
    }
    assert proposition not in row["safe_target_json"]


@pytest.mark.asyncio
async def test_feedback_and_admin_refinement_api_are_safe(database: object, cipher: object) -> None:
    _released_answer(database, cipher)
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database, cipher=cipher)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            created = await client.post(
                "/api/v1/answers/answer-feedback/feedback",
                json={
                    "rating": "partly_helpful",
                    "category": "completeness",
                    "scope": "section",
                    "target_id": "analysis",
                    "note": "Private owner feedback",
                    "idempotency_key": "feedback-api-idempotency-001",
                },
            )
            assert created.status_code == 201
            refinement_id = created.json()["refinement_id"]

            inbox = await client.get("/api/v1/admin/refinements")
            assert inbox.status_code == 200
            serialised = inbox.text
            assert "Private owner feedback" not in serialised
            assert "encrypted_note" not in serialised
            assert inbox.json()["items"][0]["id"] == refinement_id

            detail = await client.get(f"/api/v1/admin/refinements/{refinement_id}/detail")
            assert detail.status_code == 200
            assert detail.json()["note"] == "Private owner feedback"
            assert detail.json()["access_ref"].startswith("owner-read-")
            read_event = database.fetchone(  # type: ignore[attr-defined]
                """
                SELECT event_type,safe_payload_json FROM refinement_events
                WHERE refinement_id=? ORDER BY sequence DESC LIMIT 1
                """,
                (refinement_id,),
            )
            assert read_event["event_type"] == "owner_sensitive_read"
            assert "Private owner feedback" not in read_event["safe_payload_json"]

            transitioned = await client.post(
                f"/api/v1/admin/refinements/{refinement_id}/transition",
                json={
                    "to_status": "triaged",
                    "event_type": "owner_triaged",
                    "root_cause": "incomplete_issue_coverage",
                },
            )
            assert transitioned.status_code == 200

            issue = await client.post(
                "/api/v1/answers/answer-feedback/issues",
                json={
                    "category": "citation_error",
                    "severity": "high",
                    "affected_layer": "citation",
                    "expected_ids": ["evidence-expected"],
                    "observed_ids": ["evidence-observed"],
                    "note": "Private issue detail",
                },
            )
            assert issue.status_code == 201
            issue_detail = await client.get(
                f"/api/v1/admin/evaluation-issues/{issue.json()['issue_id']}/detail"
            )
            assert issue_detail.status_code == 200
            assert issue_detail.json()["note"] == "Private issue detail"
            issue_read = database.fetchone(  # type: ignore[attr-defined]
                """
                SELECT event_type,safe_payload_json FROM evaluation_issue_events
                WHERE issue_id=? ORDER BY sequence DESC LIMIT 1
                """,
                (issue.json()["issue_id"],),
            )
            assert issue_read["event_type"] == "owner_sensitive_read"
            assert "Private issue detail" not in issue_read["safe_payload_json"]
            refreshed = await client.get("/api/v1/admin/refinements")
            debug = next(
                item
                for item in refreshed.json()["items"]
                if item["id"] == issue.json()["refinement_id"]
            )
            assert debug["category"] == "debug"
            assert debug["priority"] == 90
            assert debug["target"] == {
                "issue_id": issue.json()["issue_id"],
                "answer_id": "answer-feedback",
                "job_id": "job-feedback",
            }
            assert "Private issue detail" not in refreshed.text
            stored = database.fetchone(  # type: ignore[attr-defined]
                "SELECT encrypted_note FROM refinements WHERE id=?",
                (debug["id"],),
            )
            assert stored["encrypted_note"] is None
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
