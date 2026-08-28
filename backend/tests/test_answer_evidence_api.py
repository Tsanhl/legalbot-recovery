from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import _frozen_job_request, app
from app.evaluation.owner_quality_normal_live_readiness import (
    activate_owner_quality_normal_live_readiness,
    owner_quality_normal_live_release_authority,
)
from app.types import (
    CASE_PROPOSITION_REVIEW_SCHEMA,
    EvidenceSpan,
    QuestionRequest,
    case_proposition_review_sha256,
)


def test_job_request_freezes_default_as_of_date_at_admission() -> None:
    payload = QuestionRequest(question="What is the current legal position?")

    request = _frozen_job_request(payload, admitted_on=date(2026, 8, 22))

    assert request["as_of_date"] == "2026-08-22"
    assert "question" not in request


def test_job_request_preserves_explicit_as_of_date() -> None:
    payload = QuestionRequest(
        question="What was the legal position?",
        as_of_date=date(2025, 4, 6),
    )

    request = _frozen_job_request(payload, admitted_on=date(2026, 8, 22))

    assert request["as_of_date"] == "2025-04-06"


def _store_released_answer(
    database: object,
    cipher: object,
    evidence: EvidenceSpan,
) -> dict[str, str]:
    database.create_job(  # type: ignore[attr-defined]
        job_id="job-evidence-dto",
        encrypted_question=cipher.encrypt_text("Private question"),  # type: ignore[attr-defined]
        question_summary="Private question",
        request={"word_target": 1_000},
    )
    database.store_answer_version(  # type: ignore[attr-defined]
        answer_id="answer-evidence-dto",
        job_id="job-evidence-dto",
        version_number=1,
        version_kind="candidate",
        encrypted_content=cipher.encrypt_text("Released answer"),  # type: ignore[attr-defined]
        word_count=2,
        policy_version="test-policy",
        model_version="test-model",
        index_build_id=evidence.index_build_id,
        release_state="verified_full",
    )
    review: dict[str, object] = {
        "schema": CASE_PROPOSITION_REVIEW_SCHEMA,
        "source_version_id": evidence.source_version_id,
        "chunk_id": evidence.chunk_id,
        "legal_locator": evidence.locator,
        "exact_span_sha256": evidence.content_sha256,
        "proposition_hash": "d" * 64,
        "legal_role": "holding_ratio",
        "later_treatment_reviewed_as_of_date": "2026-08-15",
        "later_treatment_status": "confirmed_current",
        "contrary_or_limiting_authority_ids": [],
        "reviewer_role": "england_wales_qualified_solicitor",
        "reviewer_ref": f"reviewer:{'a' * 64}",
        "review_scope": "ordinary",
        "second_review_status": "not_required",
        "second_reviewer_ref": None,
    }
    review["seal_sha256"] = case_proposition_review_sha256(review)
    evidence_payload = evidence.model_dump(mode="json")
    evidence_payload["citation_data"] = {
        "source_type": "legislation",
        "title": "Example Act 2026",
        "provision": "s 1",
        "url": "https://official.invalid/act?private-token=secret",
        "source_text": "Never expose this source text",
        "local_path": "/Users/AliceOwner/Desktop/private-source.pdf",
        "nested": {"credential": "secret"},
    }
    evidence_payload["case_currentness_reviews"] = [review]
    evidence_payload["case_currentness_manifest_seals"] = ["e" * 64]
    database.store_evidence([evidence_payload])  # type: ignore[attr-defined]
    database.store_claims(  # type: ignore[attr-defined]
        "answer-evidence-dto",
        [
            {
                "id": "claim-evidence-dto",
                "section_id": "analysis",
                "encrypted_text": cipher.encrypt_text("A supported claim"),  # type: ignore[attr-defined]
                "material": True,
                "proposition_hash": hashlib.sha256(b"A supported claim").hexdigest(),
                "verification_status": "verified",
                "evidence_ids": [evidence.id],
            }
        ],
    )
    return {key: str(value) for key, value in review.items() if isinstance(value, str)}


@pytest.mark.asyncio
async def test_answer_evidence_api_projects_only_allowlisted_metadata(
    database: object,
    cipher: object,
    evidence: EvidenceSpan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review = _store_released_answer(database, cipher, evidence)
    previous = getattr(app.state, "services", None)
    monkeypatch.setattr(
        "app.api.main._require_released_job_read_authority",
        lambda **_kwargs: None,
    )
    database_type = type(database)

    def forbid_raw_second_read(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("released evidence DTO performed a raw second read")

    monkeypatch.setattr(database_type, "answer", forbid_raw_second_read)
    monkeypatch.setattr(database_type, "job", forbid_raw_second_read)
    monkeypatch.setattr(database_type, "answer_claims_and_evidence", forbid_raw_second_read)
    app.state.services = SimpleNamespace(
        database=database,
        cipher=cipher,
        settings=SimpleNamespace(owner_identifiers=("AliceOwner",)),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get("/api/v1/answers/answer-evidence-dto/evidence")
        assert response.status_code == 200
        record = response.json()["evidence"][0]
        assert record["citation_data"] == {
            "provision": "s 1",
            "source_type": "legislation",
            "title": "Example Act 2026",
        }
        serialised = json.dumps(record, sort_keys=True)
        assert "private-token" not in serialised
        assert "Never expose this source text" not in serialised
        assert "/Users/" not in serialised
        assert "credential" not in serialised

        currentness = record["case_currentness_reviews"]
        assert currentness == [
            {
                "exact_span_sha256": evidence.content_sha256,
                "proposition_hash": review["proposition_hash"],
                "legal_role": "holding_ratio",
                "later_treatment_reviewed_as_of_date": "2026-08-15",
                "later_treatment_status": "confirmed_current",
                "reviewer_role": "england_wales_qualified_solicitor",
                "review_scope": "ordinary",
                "second_review_status": "not_required",
                "seal_sha256": review["seal_sha256"],
            }
        ]
        assert review["reviewer_ref"] not in serialised
        assert record["case_currentness_manifest_seals"] == ["e" * 64]
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_answer_evidence_api_fails_closed_on_corrupt_review_metadata(
    database: object,
    cipher: object,
    evidence: EvidenceSpan,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _store_released_answer(database, cipher, evidence)
    database.execute(  # type: ignore[attr-defined]
        "UPDATE evidence_spans SET case_currentness_reviews_json='[{}]' WHERE id=?",
        (evidence.id,),
    )
    previous = getattr(app.state, "services", None)
    monkeypatch.setattr(
        "app.api.main._require_released_job_read_authority",
        lambda **_kwargs: None,
    )
    app.state.services = SimpleNamespace(
        database=database,
        cipher=cipher,
        settings=SimpleNamespace(owner_identifiers=()),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get("/api/v1/answers/answer-evidence-dto/evidence")
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "Released evidence metadata failed its safe projection"
        )
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_underlying_ready_normal_live_is_stopped_before_job_or_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class DatabaseSentinel:
        jobs_created = 0

        @staticmethod
        def service_is_recent(_name: str) -> bool:
            return True

        @staticmethod
        def active_index_id() -> str:
            return "underlying-ready-candidate"

        def create_job(self, *_args: Any, **_kwargs: Any) -> None:
            self.jobs_created += 1
            raise AssertionError("uncertified normal-live intake created a job")

    class ModelSentinel:
        calls = 0

        @staticmethod
        async def health() -> bool:
            return True

        async def draft(self, **_kwargs: Any) -> None:
            self.calls += 1
            raise AssertionError("uncertified normal-live intake invoked the model")

    class RunnerSentinel:
        calls = 0

        def schedule(self, _job_id: str) -> None:
            self.calls += 1
            raise AssertionError("uncertified normal-live intake scheduled a model job")

    monkeypatch.setattr(
        "app.evaluation.owner_quality_normal_live_readiness."
        "owner_quality_normal_live_readiness_status",
        lambda *_args, **_kwargs: {
            "normal_live_ready": True,
            "blocking_reason_codes": [],
        },
    )
    database = DatabaseSentinel()
    model = ModelSentinel()
    runner = RunnerSentinel()
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=SimpleNamespace(project_root=tmp_path, model_id="local-model"),
        database=database,
        retriever=SimpleNamespace(active_build_id=lambda: "underlying-ready-candidate"),
        model=model,
        runner=runner,
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            health = await client.get("/api/v1/health")
            intake = await client.post(
                "/api/v1/questions",
                json={"question": "Was a contract formed?", "word_target": 500},
            )
            conversations = await client.get("/api/v1/conversations")
        assert health.status_code == 200
        assert health.json()["status"] == "not_ready"
        assert "normal_live_release_content_certification_missing" in health.json()["reasons"]
        assert intake.status_code == 503
        assert intake.json()["detail"] == (
            "TECHNICAL_IMPLEMENTATION_REQUIRED:normal_live_release_content_certification_missing"
        )
        assert conversations.status_code == 200
        assert conversations.json() == {"items": []}
        assert database.jobs_created == 0
        assert runner.calls == 0
        assert model.calls == 0
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_superseded_evaluation_headers_stop_before_job_or_model(
    tmp_path: Path,
) -> None:
    class DatabaseSentinel:
        jobs_created = 0

        def create_job(self, *_args: Any, **_kwargs: Any) -> None:
            self.jobs_created += 1
            raise AssertionError("superseded evaluation intake created a job")

    class RunnerSentinel:
        calls = 0

        def schedule(self, _job_id: str) -> None:
            self.calls += 1
            raise AssertionError("superseded evaluation intake scheduled a model job")

    database = DatabaseSentinel()
    runner = RunnerSentinel()
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=SimpleNamespace(project_root=tmp_path),
        database=database,
        runner=runner,
        model=SimpleNamespace(calls=0),
        observability=SimpleNamespace(
            validate_live30_binding=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("superseded admission reached observability")
            )
        ),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.post(
                "/api/v1/questions",
                headers={
                    "x-evaluation-run-id": "legacy-run",
                    "x-evaluation-case-id": "live60-q01",
                },
                json={"question": "Was a contract formed?", "word_target": 500},
            )
        assert response.status_code == 503
        assert response.json()["detail"] == (
            "TECHNICAL_IMPLEMENTATION_REQUIRED:"
            "superseded_evaluation_release_content_certification_missing"
        )
        assert database.jobs_created == 0
        assert runner.calls == 0
        assert app.state.services.model.calls == 0
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


def test_normal_live_promotion_and_authority_are_unconditionally_stopped(
    tmp_path: Path,
) -> None:
    class DatabaseSentinel:
        writes = 0

        def activate_normal_live_readiness_state(self, *_args: Any, **_kwargs: Any) -> str:
            self.writes += 1
            raise AssertionError("uncertified readiness generation was persisted")

    database = DatabaseSentinel()
    with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
        activate_owner_quality_normal_live_readiness(
            tmp_path,
            database=database,  # type: ignore[arg-type]
        )
    with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
        owner_quality_normal_live_release_authority(
            tmp_path,
            database=database,  # type: ignore[arg-type]
        )
    assert database.writes == 0


@pytest.mark.asyncio
async def test_admin_quality_returns_only_safe_counts_digests_and_presence(
    database: Any,
    cipher: Any,
) -> None:
    secret = "PRIVATE QUALITY REVIEW PAYLOAD MUST NOT ENTER BROWSER STATE"
    database.create_job(
        job_id="job-safe-quality-admin",
        encrypted_question=cipher.encrypt_text("Private quality question"),
        question_summary="Private quality question",
        request={"word_target": 500},
    )
    database.store_answer_version(
        answer_id="answer-safe-quality-admin",
        job_id="job-safe-quality-admin",
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("Private answer"),
        word_count=2,
        policy_version="test-policy",
        model_version="test-model",
        index_build_id=None,
    )
    database.store_quality_report(
        {
            "id": "quality-safe-admin",
            "answer_version_id": "answer-safe-quality-admin",
            "evidence_passed": False,
            "academic_score": 62.0,
            "rubric_scores": {"analysis": 62},
            "findings": [{"code": "private", "message": secret}],
            "release_state": "held_for_review",
            "ai_evidence_review": {"private_review": secret},
            "ai_evidence_adjudication": {"private_adjudication": secret},
            "assessment_standards": {"private_standards": secret},
        },
        "test-policy",
        encrypted_source_draft=cipher.encrypt_text(secret),
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4311))
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get("/api/v1/admin/quality")
        assert response.status_code == 200
        item = response.json()["items"][0]
        assert set(item) == {
            "quality_report_id",
            "answer_version_id",
            "evidence_passed",
            "academic_score",
            "release_state",
            "policy_version",
            "policy_sha256",
            "created_at",
            "rubric_score_count",
            "rubric_scores_sha256",
            "finding_count",
            "findings_sha256",
            "ai_evidence_review_present",
            "ai_evidence_adjudication_present",
            "assessment_standards_present",
            "source_draft_present",
        }
        assert item["rubric_score_count"] == 1
        assert item["finding_count"] == 1
        assert item["ai_evidence_review_present"] is True
        assert item["ai_evidence_adjudication_present"] is True
        assert item["assessment_standards_present"] is True
        assert item["source_draft_present"] is True
        serialised = json.dumps(response.json(), sort_keys=True)
        assert secret not in serialised
        for forbidden_key in (
            "encrypted_source_draft",
            "ai_evidence_review_json",
            "ai_evidence_adjudication_json",
            "assessment_standards_json",
            "rubric_scores_json",
            "findings_json",
        ):
            assert forbidden_key not in serialised
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
