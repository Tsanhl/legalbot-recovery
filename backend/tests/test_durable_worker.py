from __future__ import annotations

import asyncio
import copy
import sqlite3
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from pydantic import ValidationError

from app.assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from app.config import Settings
from app.db import JobQueueCapacityError
from app.evaluation.live_suite import sealed_sha256
from app.orchestration.classifier import classify_subjects
from app.orchestration.contracts import ModelDraft
from app.orchestration.object_store import EncryptedObjectStore
from app.orchestration.routing import build_section_tasks, decide_route
from app.orchestration.runner import (
    AnswerRunner,
    _bind_model_draft_context,
    _section_retrieval_subject,
)
from app.orchestration.worker import DurableAnswerWorker
from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.quality.evaluator import QualityEvaluator
from app.retrieval.budget import bind_retrieval_budget
from app.types import (
    AnswerRoute,
    IssuePlan,
    JobStage,
    JobStatus,
    QualityFinding,
    Severity,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


@pytest.fixture(autouse=True)
def _reset_retrieval_budget():
    bind_retrieval_budget(deadline_at=None)
    yield
    bind_retrieval_budget(deadline_at=None)


def _job(database, cipher, job_id: str = "job-durable") -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary="Private encrypted question",
        request={"task_type": "general", "word_target": 500},
        route="direct",
    )


def test_job_admission_is_atomically_bounded_by_job_type(database, cipher) -> None:
    database.create_job(
        job_id="queue-cap-first",
        encrypted_question=cipher.encrypt_text("First bounded queue question"),
        question_summary="Private encrypted question",
        request={"word_target": 1500},
        queue_capacity=1,
    )

    with pytest.raises(JobQueueCapacityError, match="answer_queue_capacity_exhausted"):
        database.create_job(
            job_id="queue-cap-refused",
            encrypted_question=cipher.encrypt_text("Second bounded queue question"),
            question_summary="Private encrypted question",
            request={"word_target": 1500},
            queue_capacity=1,
        )

    assert database.job("queue-cap-refused") is None
    database.update_job(
        "queue-cap-first",
        status="cancelled",
        stage="cancelled",
        progress=1,
        message="Cancelled before execution.",
    )
    database.create_job(
        job_id="queue-cap-after-terminal",
        encrypted_question=cipher.encrypt_text("Replacement bounded queue question"),
        question_summary="Private encrypted question",
        request={"word_target": 1500},
        queue_capacity=1,
    )
    assert database.job("queue-cap-after-terminal")["status"] == "queued"


def test_queue_capacity_does_not_mask_duplicate_idempotency(database, cipher) -> None:
    database.create_job(
        job_id="queue-idempotent-first",
        encrypted_question=cipher.encrypt_text("First idempotent question"),
        question_summary="Private encrypted question",
        request={"word_target": 1500},
        idempotency_key="same-safe-retry",
        queue_capacity=1,
    )

    with pytest.raises(sqlite3.IntegrityError):
        database.create_job(
            job_id="queue-idempotent-retry",
            encrypted_question=cipher.encrypt_text("First idempotent question"),
            question_summary="Private encrypted question",
            request={"word_target": 1500},
            idempotency_key="same-safe-retry",
            queue_capacity=1,
        )


def test_legacy_evaluation_identity_cannot_bypass_a_full_queue(database, cipher) -> None:
    database.create_job(
        job_id="queue-evaluation-first",
        encrypted_question=cipher.encrypt_text("First bounded evaluation question"),
        question_summary="Private encrypted question",
        request={"word_target": 1500},
        queue_capacity=1,
    )
    database.execute(
        """INSERT INTO jobs(
             id,status,stage,progress,encrypted_question,question_summary,request_json,
             evaluation_run_id,evaluation_case_id,created_at,updated_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "legacy-evaluation-observation",
            "system_error",
            "system_error",
            1,
            b"",
            "Private encrypted question",
            "{}",
            "evaluation-run",
            "live60-q01",
            "2026-08-22T00:00:00+00:00",
            "2026-08-22T00:00:00+00:00",
        ),
    )
    request_sha256 = "a" * 64
    authority = {
        "schema": "test-evaluation-authority.v1",
        "run_id": "evaluation-run",
        "case_id": "live60-q01",
        "request_sha256": request_sha256,
    }
    authority["seal_sha256"] = sealed_sha256(authority)

    with pytest.raises(sqlite3.IntegrityError, match="legacy evaluation identity"):
        database.create_job(
            job_id="queue-evaluation-rebind",
            encrypted_question=cipher.encrypt_text("New durable evaluation request"),
            question_summary="Private encrypted question",
            request={"word_target": 1500},
            evaluation_run_id="evaluation-run",
            evaluation_case_id="live60-q01",
            evaluation_request_sha256=request_sha256,
            evaluation_authority=authority,
            queue_capacity=1,
        )
    assert database.job("queue-evaluation-rebind") is None


def test_job_admission_rejects_unknown_unclaimable_queue(database, cipher) -> None:
    with pytest.raises(ValueError, match="not supported"):
        database.create_job(
            job_id="unknown-queue",
            encrypted_question=cipher.encrypt_text("Unknown worker question"),
            question_summary="Private encrypted question",
            request={"word_target": 1500},
            job_type="unknown-worker-class",
        )

    assert database.job("unknown-queue") is None


def test_route_and_sections_bound_every_7000_word_answer() -> None:
    decision = decide_route(
        "Advise the parties on liability, causation, defences and remedies.",
        7_000,
        TaskType.PROBLEM,
    )
    assert decision.route == AnswerRoute.FULL_ENQUIRY
    plan = IssuePlan(
        jurisdiction="England and Wales",
        subject="contract",
        proposition_keys=["breach", "remedies"],
        queries=["safe"],
        notes_considered=0,
        notes_used=0,
        unsafe_notes_excluded=0,
    )
    sections = build_section_tasks(
        question="Advise on breach, causation, limitation clause and remedies.",
        word_target=7_000,
        issue_plan=plan,
    )
    assert len(sections) == 12
    assert all(500 <= item.word_target <= 700 for item in sections)
    assert sum(item.word_target for item in sections) == 7_000


def test_section_plan_preserves_intermediate_word_target() -> None:
    plan = IssuePlan(
        jurisdiction="England and Wales",
        subject="contract",
        proposition_keys=["breach"],
        queries=["safe"],
        notes_considered=0,
        notes_used=0,
        unsafe_notes_excluded=0,
    )
    sections = build_section_tasks(
        question="Advise on breach and remedies.", word_target=1_300, issue_plan=plan
    )
    assert all(500 <= item.word_target <= 700 for item in sections)
    assert sum(item.word_target for item in sections) == 1_300


def test_model_draft_cannot_change_immutable_legal_context() -> None:
    candidate = ModelDraft(
        raw_text="",
        structured=StructuredDraft(
            title="Answer",
            task_type=TaskType.ESSAY,
            jurisdiction="Scotland",
            as_of_date="1999-01-01",
            sections=[
                StructuredSectionDraft(
                    id="model-section",
                    heading="Model heading",
                    claims=[
                        StructuredClaimDraft(
                            id="model-claim",
                            text="Model-controlled legal context must be replaced.",
                            evidence_ids=[],
                        )
                    ],
                )
            ],
        ),
        rubric_scores={},
        model_version="test-model",
        metrics={},
    )
    bound = _bind_model_draft_context(
        candidate,
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 15),
    )
    assert bound.structured.task_type == TaskType.PROBLEM
    assert bound.structured.jurisdiction == "England and Wales"
    assert str(bound.structured.as_of_date) == "2026-08-15"


def test_model_section_and_claim_ids_reject_prose_or_paths() -> None:
    with pytest.raises(ValidationError):
        StructuredClaimDraft(id="claim /Users/owner/private", text="Unsafe id")
    with pytest.raises(ValidationError):
        StructuredSectionDraft(
            id="section contains prose",
            heading="Heading",
            claims=[],
        )


def test_composite_longform_sections_do_not_inherit_one_subject_filter() -> None:
    recognised = classify_subjects(
        "Advise on company law directors' duties, employment discrimination and UK GDPR data protection."
    )
    assert {"company", "employment", "data protection"}.issubset(recognised)
    assert (
        _section_retrieval_subject(
            "Overview and issues",
            whole_question_subject="company",
            recognised_subjects=recognised,
        )
        is None
    )
    assert (
        _section_retrieval_subject(
            "Employment discrimination and remedies",
            whole_question_subject="company",
            recognised_subjects=recognised,
        )
        == "employment"
    )


def test_long_section_queries_keep_tail_facts_and_focus_inside_budget() -> None:
    plan = IssuePlan(
        jurisdiction="England and Wales",
        subject="contract",
        proposition_keys=["remedies"],
        queries=["safe"],
        notes_considered=0,
        notes_used=0,
        unsafe_notes_excluded=0,
    )
    question = "Advise on breach. " + ("background " * 180) + "Final fact: limitation clause."
    sections = build_section_tasks(question=question, word_target=2_000, issue_plan=plan)

    assert all(len(item.query) <= 1_200 for item in sections)
    assert all("Final fact: limitation clause." in item.query for item in sections)
    assert all("Focus issue:" in item.query for item in sections)


def test_answer_job_lease_expiry_is_terminal(database, cipher) -> None:
    _job(database, cipher)
    first = database.claim_next_job("worker-one", lease_seconds=60)
    assert first is not None and first["lease_owner"] == "worker-one"
    assert database.claim_next_job("worker-two") is None
    database.execute(
        "UPDATE jobs SET lease_expires_at=? WHERE id='job-durable'",
        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),),
    )
    reclaimed = database.claim_next_job("worker-two")
    assert reclaimed is None
    row = database.job("job-durable")
    assert row["status"] == "system_error"
    assert row["error_code"] == "lease_lost"
    assert int(row["attempt_count"]) == 1


def test_index_build_job_lease_expiry_can_be_reclaimed(database) -> None:
    database.create_job(
        job_id="job-index",
        encrypted_question=b"",
        question_summary="Private encrypted question",
        request={"job_type": "index_build", "build_id": "b1"},
        job_type="index_build",
    )
    first = database.claim_next_job("worker-one", lease_seconds=60)
    assert first is not None
    database.execute(
        "UPDATE jobs SET lease_expires_at=? WHERE id='job-index'",
        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(),),
    )
    reclaimed = database.claim_next_job("worker-two")
    assert reclaimed is not None and reclaimed["lease_owner"] == "worker-two"
    assert int(reclaimed["attempt_count"]) == 2


def test_ordinary_release_outbox_stops_without_content_certification(database, cipher) -> None:
    _job(database, cipher)
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES ('test-live-build','active','data/indexes/test-live-build',
                  1,1,1,'embed','rerank','2026-08-20T00:00:00+00:00')
        """
    )
    database.execute(
        "UPDATE jobs SET pinned_index_build_id='test-live-build' WHERE id='job-durable'"
    )
    database.store_answer_version(
        answer_id="answer-one",
        job_id="job-durable",
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text("Verified"),
        word_count=1,
        policy_version="test",
        model_version="test",
        index_build_id=None,
    )
    authority = {
        "schema": "legalbot.owner-quality-normal-live-release-authority.v1",
        "normal_live_ready": True,
        "release_audience": "normal_live",
        "candidate_build_id": "test-live-build",
        "readiness_generation_sha256": "3" * 64,
        "trusted_owner_o04_signature_verified": True,
        "trusted_post_run_owner_acceptance_signature_verified": True,
    }
    authority["seal_sha256"] = sealed_sha256(authority)
    database.activate_normal_live_readiness_state(authority, verifier=lambda: authority)
    with pytest.raises(RuntimeError, match="normal_live_release_content_certification_missing"):
        database.release_answer_once(
            "answer-one",
            "verified_full",
            normal_live_authority=authority,
            normal_live_authority_verifier=lambda: authority,
        )
    assert database.fetchone("SELECT COUNT(*) AS n FROM release_outbox")["n"] == 0
    assert database.answer("answer-one")["release_state"] is None


def test_local_runtime_objects_are_encrypted_and_hash_checked(tmp_path, database, cipher) -> None:
    store = EncryptedObjectStore(tmp_path / "objects", database, cipher)
    key = store.put_json(namespace="checkpoints", value={"private": "secret"})
    row = database.fetchone("SELECT * FROM runtime_objects WHERE object_key=?", (key,))
    blob = (tmp_path / "objects" / row["relative_path"]).read_bytes()
    assert b"secret" not in blob
    assert store.get_json(key) == {"private": "secret"}


@pytest.mark.asyncio
async def test_long_form_repairs_only_failed_section_with_its_frozen_pack(evidence) -> None:
    first = StructuredSectionDraft(
        id="section-01",
        heading="Duty",
        claims=[
            StructuredClaimDraft(
                id="claim-01", text="Unsupported duty.", evidence_ids=[evidence.id]
            )
        ],
    )
    second = StructuredSectionDraft(
        id="section-02",
        heading="Remedies",
        claims=[
            StructuredClaimDraft(
                id="claim-02", text="Preserve this section.", evidence_ids=[evidence.id]
            )
        ],
    )
    structured = StructuredDraft(
        title="Long answer",
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date="2026-08-12",
        sections=[first, second],
    )

    class RepairModel:
        calls: ClassVar[list[dict]] = []

        async def repair(self, **kwargs):
            self.calls.append(kwargs)
            repaired = kwargs["prior"].model_copy(
                update={
                    "sections": [
                        first.model_copy(
                            update={
                                "claims": [
                                    first.claims[0].model_copy(
                                        update={"text": "Repaired supported duty."}
                                    )
                                ]
                            }
                        )
                    ]
                }
            )
            return ModelDraft("", repaired, {}, "test-model", {})

    runner = object.__new__(AnswerRunner)
    runner.model = RepairModel()
    prior = ModelDraft("", structured, {}, "test-model", {})
    result = await runner._repair_longform_sections(
        question="Advise on duty and remedies.",
        prior=prior,
        failed_sections=["section-01"],
        findings=[
            QualityFinding(
                gate="claim_evidence",
                code="unsupported_material_law",
                message="unsupported",
                severity=Severity.HARD_BLOCKER,
                section_id="section-01",
                claim_id="claim-01",
            )
        ],
        evidence_by_id={evidence.id: evidence},
        section_evidence_by_id={"section-01": {evidence.id: evidence}},
        word_target=7_000,
        upload_context=(),
    )

    assert len(runner.model.calls) == 1
    assert len(runner.model.calls[0]["prior"].sections) == 1
    assert runner.model.calls[0]["word_target"] == 700
    assert list(runner.model.calls[0]["evidence"]) == [evidence.id]
    assert result.structured.sections[0].claims[0].text == "Repaired supported duty."
    assert result.structured.sections[1] == second


@pytest.mark.asyncio
async def test_worker_runs_upload_expiry_without_process_restart(
    tmp_path: Path,
    database: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    services = SimpleNamespace(
        settings=settings,
        database=database,
        observability=None,
        runner=SimpleNamespace(),
        deletion_guard=object(),
    )
    worker = DurableAnswerWorker(services, worker_id="worker-upload-purge", poll_seconds=0.01)
    calls: list[Path] = []

    def purge_once(observed_settings: Settings, _database: Any, *, guard: object) -> int:
        assert guard is services.deletion_guard
        calls.append(observed_settings.project_root)
        worker.stop()
        return 0

    monkeypatch.setattr("app.orchestration.worker.purge_expired_uploads", purge_once)
    await worker.run_forever()
    assert calls == [settings.project_root]


def _checkpoint_runner(
    *,
    tmp_path: Path,
    database: Any,
    cipher: Any,
    model: Any,
    model_id: str = "mlx-community/Qwen3.5-9B-4bit",
) -> AnswerRunner:
    settings = Settings(project_root=tmp_path, test_mode=True, model_id=model_id)
    settings.ensure_runtime_dirs()

    class Retriever:
        def active_build_id(self) -> str:
            return "build-1"

    return AnswerRunner(
        settings=settings,
        database=database,
        cipher=cipher,
        retriever=Retriever(),
        model=model,
    )


@pytest.mark.asyncio
async def test_longform_repair_resume_reuses_completed_sections_and_rejects_drift(
    tmp_path: Path, database: Any, cipher: Any, evidence: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    _job(database, cipher, "job-repair-resume")
    database.bind_job_assessment_bundle("job-repair-resume", OWNER_ASSESSMENT_BUNDLE.sha256)
    sections = [
        StructuredSectionDraft(
            id=f"section-{number:02d}",
            heading=f"Section {number}",
            claims=[
                StructuredClaimDraft(
                    id=f"claim-{number:02d}",
                    text=f"Original claim {number}.",
                    evidence_ids=[evidence.id],
                )
            ],
        )
        for number in (1, 2)
    ]
    prior = ModelDraft(
        "",
        StructuredDraft(
            title="Long answer",
            task_type=TaskType.PROBLEM,
            jurisdiction="England and Wales",
            as_of_date="2026-08-14",
            sections=sections,
        ),
        {},
        "test-model",
        {},
    )
    findings = [
        QualityFinding(
            gate="claim_evidence",
            code="unsupported_material_law",
            message="unsupported",
            severity=Severity.HARD_BLOCKER,
            section_id=section.id,
            claim_id=section.claims[0].id,
        )
        for section in sections
    ]

    class CrashOnceModel:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.crashed = False

        async def repair(self, **kwargs: Any) -> ModelDraft:
            section = kwargs["prior"].sections[0]
            self.calls.append(section.id)
            if section.id == "section-02" and not self.crashed:
                self.crashed = True
                raise RuntimeError("simulated process interruption")
            replacement = section.model_copy(
                update={
                    "claims": [
                        section.claims[0].model_copy(update={"text": f"Repaired {section.id}."})
                    ]
                }
            )
            structured = kwargs["prior"].model_copy(update={"sections": [replacement]})
            return ModelDraft("private repaired prose", structured, {}, "test-model", {})

    model = CrashOnceModel()
    runner = _checkpoint_runner(tmp_path=tmp_path, database=database, cipher=cipher, model=model)
    arguments = {
        "job_id": "job-repair-resume",
        "question": "Advise on both issues.",
        "prior": prior,
        "failed_sections": ["section-01", "section-02"],
        "findings": findings,
        "evidence_by_id": {evidence.id: evidence},
        "section_evidence_by_id": {section.id: {evidence.id: evidence} for section in sections},
        "word_target": 7_000,
        "upload_context": (),
        "repair_round": 1,
    }
    with pytest.raises(RuntimeError, match="simulated process interruption"):
        await runner._repair_longform_sections(**arguments)

    result = await runner._repair_longform_sections(**arguments)
    assert model.calls == ["section-01", "section-02", "section-02"]
    assert [item.claims[0].text for item in result.structured.sections] == [
        "Repaired section-01.",
        "Repaired section-02.",
    ]
    complete = database.fetchall(
        """
        SELECT section_key,input_digest,evidence_pack_digest,output_object_key
        FROM job_stage_attempts
        WHERE job_id='job-repair-resume' AND stage_key='repair-01' AND status='complete'
        ORDER BY section_key
        """
    )
    assert [row["section_key"] for row in complete] == ["section-01", "section-02"]
    assert all(row["input_digest"] and row["evidence_pack_digest"] for row in complete)
    first_object = database.fetchone(
        "SELECT * FROM runtime_objects WHERE object_key=?", (complete[0]["output_object_key"],)
    )
    encrypted = (runner.objects.root / first_object["relative_path"]).read_bytes()
    assert b"private repaired prose" not in encrypted

    changed = evidence.model_copy(update={"text": "Changed frozen evidence."})
    drifted = copy.copy(arguments)
    drifted["evidence_by_id"] = {changed.id: changed}
    drifted["section_evidence_by_id"] = {section.id: {changed.id: changed} for section in sections}
    with pytest.raises(RuntimeError, match="does not match frozen inputs"):
        await runner._repair_longform_sections(**drifted)
    assert model.calls == ["section-01", "section-02", "section-02"]

    monkeypatch.setattr(
        "app.orchestration.runner.REPAIR_CHECKPOINT_PROMPT_VERSION",
        "changed-repair-contract-v2",
    )
    with pytest.raises(RuntimeError, match="does not match frozen inputs"):
        await runner._repair_longform_sections(**arguments)
    assert model.calls == ["section-01", "section-02", "section-02"]

    changed_model_runner = _checkpoint_runner(
        tmp_path=tmp_path,
        database=database,
        cipher=cipher,
        model=model,
        model_id="local-changed-model-revision",
    )
    with pytest.raises(RuntimeError, match="does not match frozen inputs"):
        await changed_model_runner._repair_longform_sections(**arguments)
    assert model.calls == ["section-01", "section-02", "section-02"]


@pytest.mark.asyncio
async def test_direct_repair_checkpoint_is_reused_without_second_model_call(
    tmp_path: Path, database: Any, cipher: Any, evidence: Any
) -> None:
    _job(database, cipher, "job-direct-repair")
    database.bind_job_assessment_bundle("job-direct-repair", OWNER_ASSESSMENT_BUNDLE.sha256)
    section = StructuredSectionDraft(
        id="section-01",
        heading="Issue",
        claims=[StructuredClaimDraft(id="claim-01", text="Original.", evidence_ids=[evidence.id])],
    )
    prior = StructuredDraft(
        title="Answer",
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date="2026-08-14",
        sections=[section],
    )
    finding = QualityFinding(
        gate="analysis",
        code="needs_repair",
        message="repair",
        severity=Severity.REPAIRABLE,
        section_id=section.id,
    )

    class DirectModel:
        calls = 0

        async def repair(self, **kwargs: Any) -> ModelDraft:
            self.calls += 1
            assert database.job("job-direct-repair")["model_call_deadline_at"] is not None
            repaired = kwargs["prior"].model_copy(
                update={
                    "sections": [
                        section.model_copy(
                            update={
                                "claims": [
                                    section.claims[0].model_copy(
                                        update={"text": "Repaired direct claim."}
                                    )
                                ]
                            }
                        )
                    ]
                }
            )
            return ModelDraft("direct private output", repaired, {}, "test-model", {})

    model = DirectModel()
    runner = _checkpoint_runner(tmp_path=tmp_path, database=database, cipher=cipher, model=model)
    kwargs = {
        "job_id": "job-direct-repair",
        "repair_round": 1,
        "section_key": "direct",
        "question": "Advise.",
        "prior": prior,
        "failed_sections": [section.id],
        "repair_plan_sections": [section.id],
        "findings": [finding],
        "evidence": {evidence.id: evidence},
        "word_target": 1_000,
        "upload_context": (),
    }
    first, first_reused = await runner._repair_with_checkpoint(**kwargs)
    second, second_reused = await runner._repair_with_checkpoint(**kwargs)
    assert first.structured == second.structured
    assert first_reused is False
    assert second_reused is True
    assert model.calls == 1
    assert database.job("job-direct-repair")["model_call_deadline_at"] is None


@pytest.mark.asyncio
async def test_direct_repair_hard_timeout_clears_exact_model_call_fence(
    tmp_path: Path,
    database: Any,
    cipher: Any,
    evidence: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _job(database, cipher, "job-direct-repair-timeout")
    database.bind_job_assessment_bundle("job-direct-repair-timeout", OWNER_ASSESSMENT_BUNDLE.sha256)
    section = StructuredSectionDraft(
        id="section-timeout",
        heading="Issue",
        claims=[
            StructuredClaimDraft(
                id="claim-timeout",
                text="Original.",
                evidence_ids=[evidence.id],
            )
        ],
    )
    prior = StructuredDraft(
        title="Answer",
        task_type=TaskType.PROBLEM,
        jurisdiction="England and Wales",
        as_of_date="2026-08-14",
        sections=[section],
    )
    finding = QualityFinding(
        gate="analysis",
        code="needs_repair",
        message="repair",
        severity=Severity.REPAIRABLE,
        section_id=section.id,
    )

    class HangingDirectModel:
        async def repair(self, **_kwargs: Any) -> ModelDraft:
            row = database.job("job-direct-repair-timeout")
            assert row["model_call_deadline_at"] is not None
            assert row["model_call_token"] is not None
            await asyncio.Event().wait()
            raise AssertionError("the hard model-call timeout did not cancel repair")

    monkeypatch.setattr("app.jobs.ANSWER_MODEL_CALL_SECONDS", 0.01)
    runner = _checkpoint_runner(
        tmp_path=tmp_path,
        database=database,
        cipher=cipher,
        model=HangingDirectModel(),
    )

    with pytest.raises(TimeoutError):
        await runner._repair_with_checkpoint(
            job_id="job-direct-repair-timeout",
            repair_round=1,
            section_key="direct",
            question="Advise.",
            prior=prior,
            failed_sections=[section.id],
            repair_plan_sections=[section.id],
            findings=[finding],
            evidence={evidence.id: evidence},
            word_target=1_000,
            upload_context=(),
        )

    row = database.job("job-direct-repair-timeout")
    assert row["model_call_deadline_at"] is None
    assert row["model_call_token"] is None
    attempt = database.fetchone(
        "SELECT status,error_code FROM job_stage_attempts "
        "WHERE job_id='job-direct-repair-timeout' AND stage_key='repair-01'"
    )
    assert attempt is not None
    assert attempt["status"] == "failed"
    assert attempt["error_code"] == "TimeoutError"


@pytest.mark.asyncio
async def test_worker_claims_and_finishes_one_job(database, cipher) -> None:
    _job(database, cipher)

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del raise_on_error
            database.update_job(
                job_id,
                status="complete",
                stage="complete",
                progress=1,
                message="done",
            )

    services = SimpleNamespace(database=database, runner=Runner())
    worker = DurableAnswerWorker(services, poll_seconds=0.01)
    task = asyncio.create_task(worker.run_forever())
    for _ in range(100):
        if database.job("job-durable")["status"] == "complete":
            break
        await asyncio.sleep(0.01)
    worker.stop()
    await task
    assert database.job("job-durable")["status"] == "complete"


@pytest.mark.asyncio
async def test_worker_crash_does_not_treat_attempt_ordinal_as_changed_condition(
    database, cipher
) -> None:
    _job(database, cipher)

    class Runner:
        calls = 0

        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            self.calls += 1
            raise RuntimeError("opaque worker crash")

    runner = Runner()
    services = SimpleNamespace(database=database, runner=runner, observability=None)
    worker = DurableAnswerWorker(services, poll_seconds=0.01)
    task = asyncio.create_task(worker.run_forever())
    row = None
    for _ in range(100):
        row = database.job("job-durable")
        if row is not None and row["status"] == "system_error":
            break
        await asyncio.sleep(0.01)
    worker.stop()
    await task
    assert row is not None
    assert row["status"] == "system_error"
    assert int(row["attempt_count"]) == 1
    assert runner.calls == 1
    retry_trace = database.retry_decisions("job", "job-durable")
    assert len(retry_trace) == 1
    assert retry_trace[0]["decision_action"] == "stop"
    assert retry_trace[0]["decision_reason"] == "retry_condition_unchanged"


def test_materially_similar_opposite_claims_are_blocked() -> None:
    draft = StructuredDraft(
        title="Conflicting",
        task_type="general",
        jurisdiction="England and Wales",
        as_of_date="2026-08-12",
        sections=[
            StructuredSectionDraft(
                id="one",
                heading="First",
                claims=[
                    StructuredClaimDraft(
                        id="affirmative",
                        text="The supplier is liable for the contractual loss under the governing test",
                        evidence_ids=[],
                    )
                ],
            ),
            StructuredSectionDraft(
                id="two",
                heading="Second",
                claims=[
                    StructuredClaimDraft(
                        id="negative",
                        text="The supplier is not liable for the contractual loss under the governing test",
                        evidence_ids=[],
                    )
                ],
            ),
        ],
    )
    report = QualityEvaluator().evaluate(
        answer_version_id="answer-conflict",
        draft=draft,
        rendered_text="safe",
        evidence_by_id={},
        word_count=20,
        word_target=100,
    )
    assert "material_contradiction" in {item.code for item in report.findings}


@pytest.mark.asyncio
async def test_worker_in_flight_workflow_deadline_terminates_slow_runner(
    database: Any, cipher: Any
) -> None:
    from types import SimpleNamespace

    from app.jobs import TERMINAL_WORKFLOW, deadline_after
    from app.privacy import PRIVATE_QUESTION_SUMMARY

    database.create_job(
        job_id="job-deadline",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at=deadline_after(1),
    )

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            await asyncio.sleep(5)

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner(), observability=None),
        poll_seconds=0.05,
    )
    task = asyncio.create_task(worker.run_forever())
    row = None
    for _ in range(80):
        row = database.job("job-deadline")
        if row is not None and row["status"] == "system_error":
            break
        await asyncio.sleep(0.05)
    worker.stop()
    await task
    assert row is not None
    assert row["status"] == "system_error"
    assert float(row["progress"]) == 1.0
    assert row["error_code"] == TERMINAL_WORKFLOW


@pytest.mark.asyncio
async def test_worker_invalid_persisted_deadline_fails_only_that_job(
    database: Any, cipher: Any
) -> None:
    database.create_job(
        job_id="job-invalid-deadline",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at="not-an-iso-deadline",
    )
    database.create_job(
        job_id="job-after-invalid-deadline",
        encrypted_question=cipher.encrypt_text("Another private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
    )

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del raise_on_error
            database.update_job(
                job_id, status="complete", stage="complete", progress=1, message="done"
            )

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner(), observability=None),
        poll_seconds=0.01,
    )
    task = asyncio.create_task(worker.run_forever())
    for _ in range(100):
        invalid = database.job("job-invalid-deadline")
        following = database.job("job-after-invalid-deadline")
        if invalid["status"] == "system_error" and following["status"] == "complete":
            break
        await asyncio.sleep(0.01)
    worker.stop()
    await task
    assert database.job("job-invalid-deadline")["error_code"] == "invalid_persisted_deadline"
    assert database.job("job-after-invalid-deadline")["status"] == "complete"


@pytest.mark.asyncio
async def test_worker_enforces_persisted_model_call_deadline(database: Any, cipher: Any) -> None:
    from app.jobs import TERMINAL_MODEL_TIMEOUT, deadline_after

    database.create_job(
        job_id="job-model-deadline",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at=deadline_after(3600),
        model_call_deadline_at=deadline_after(-1),
    )

    class Runner:
        calls = 0

        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            self.calls += 1

    runner = Runner()
    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=runner, observability=None),
        poll_seconds=0.01,
    )
    task = asyncio.create_task(worker.run_forever())
    for _ in range(100):
        row = database.job("job-model-deadline")
        if row["status"] == "system_error":
            break
        await asyncio.sleep(0.01)
    worker.stop()
    await task
    assert database.job("job-model-deadline")["error_code"] == TERMINAL_MODEL_TIMEOUT
    assert runner.calls == 0


@pytest.mark.asyncio
async def test_worker_in_flight_cancel_terminates_slow_runner(database: Any, cipher: Any) -> None:
    from types import SimpleNamespace

    from app.jobs import TERMINAL_CANCELLED
    from app.privacy import PRIVATE_QUESTION_SUMMARY

    database.create_job(
        job_id="job-cancel-inflight",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
    )

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            await asyncio.sleep(5)

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner(), observability=None),
        poll_seconds=0.05,
    )
    task = asyncio.create_task(worker.run_forever())
    claimed = False
    for _ in range(40):
        row = database.job("job-cancel-inflight")
        if row is not None and row["status"] == "running":
            claimed = True
            database.request_cancel_job("job-cancel-inflight")
            break
        await asyncio.sleep(0.05)
    assert claimed is True
    row = None
    for _ in range(40):
        row = database.job("job-cancel-inflight")
        if row is not None and row["status"] == "cancelled":
            break
        await asyncio.sleep(0.05)
    worker.stop()
    await task
    assert row is not None
    assert row["status"] == "cancelled"
    assert float(row["progress"]) == 1.0
    assert row["error_code"] == TERMINAL_CANCELLED


@pytest.mark.asyncio
async def test_worker_stage_deadline_terminates_researching(database: Any, cipher: Any) -> None:
    from types import SimpleNamespace

    from app.jobs import TERMINAL_STAGE_TIMEOUT, deadline_after
    from app.privacy import PRIVATE_QUESTION_SUMMARY

    database.create_job(
        job_id="job-stage-deadline",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at=deadline_after(3600),
    )
    database.arm_stage_deadline("job-stage-deadline", seconds=1)

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            await asyncio.sleep(5)

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner(), observability=None),
        poll_seconds=0.05,
    )
    task = asyncio.create_task(worker.run_forever())
    row = None
    for _ in range(80):
        row = database.job("job-stage-deadline")
        if row is not None and row["status"] == "system_error":
            break
        await asyncio.sleep(0.05)
    worker.stop()
    await task
    assert row is not None
    assert row["status"] == "system_error"
    assert row["error_code"] == TERMINAL_STAGE_TIMEOUT
    assert float(row["progress"]) == 1.0


@pytest.mark.asyncio
async def test_worker_maps_retrieval_deadline_error_to_stage_timeout(
    database: Any, cipher: Any
) -> None:
    from types import SimpleNamespace

    from app.jobs import TERMINAL_STAGE_TIMEOUT, deadline_after

    database.create_job(
        job_id="job-map-deadline",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at=deadline_after(3600),
    )
    database.arm_stage_deadline("job-map-deadline", seconds=-1)

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            raise RuntimeError("retrieval_deadline_exceeded")

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner(), observability=None),
        poll_seconds=0.05,
    )
    task = asyncio.create_task(worker.run_forever())
    row = None
    for _ in range(80):
        row = database.job("job-map-deadline")
        if row is not None and row["status"] == "system_error":
            break
        await asyncio.sleep(0.05)
    worker.stop()
    await task
    assert row is not None
    assert row["status"] == "system_error"
    assert row["error_code"] == TERMINAL_STAGE_TIMEOUT
    assert float(row["progress"]) == 1.0


@pytest.mark.asyncio
async def test_worker_maps_retrieval_budget_exceeded_before_inference(
    database: Any, cipher: Any
) -> None:
    from types import SimpleNamespace

    from app.jobs import deadline_after
    from app.retrieval.budget import RetrievalBudgetExhausted

    database.create_job(
        job_id="job-map-budget",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at=deadline_after(3600),
    )
    database.arm_stage_deadline("job-map-budget", seconds=300)

    class Runner:
        async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
            del job_id, raise_on_error
            raise RetrievalBudgetExhausted(
                "retrieval_budget_exceeded",
                "planned rerank work cannot fit the remaining research budget",
            )

    worker = DurableAnswerWorker(
        SimpleNamespace(database=database, runner=Runner(), observability=None),
        poll_seconds=0.05,
    )
    task = asyncio.create_task(worker.run_forever())
    row = None
    for _ in range(80):
        row = database.job("job-map-budget")
        if row is not None and row["status"] == "system_error":
            break
        await asyncio.sleep(0.05)
    worker.stop()
    await task
    assert row is not None
    assert row["status"] == "system_error"
    assert row["error_code"] == "retrieval_budget_exceeded"
    assert float(row["progress"]) == 1.0


def test_arm_stage_deadline_sets_started_and_deadline(database: Any, cipher: Any) -> None:
    _job(database, cipher, "job-arm-deadline")
    deadline = database.arm_stage_deadline("job-arm-deadline", seconds=300)
    row = database.job("job-arm-deadline")
    assert row is not None
    assert row["stage_deadline_at"] == deadline
    started = datetime.fromisoformat(str(row["stage_started_at"]))
    ended = datetime.fromisoformat(str(row["stage_deadline_at"]))
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    if ended.tzinfo is None:
        ended = ended.replace(tzinfo=UTC)
    assert abs((ended - started).total_seconds() - 300) < 1


def test_arm_stage_deadline_allows_negative_seconds(database: Any, cipher: Any) -> None:
    _job(database, cipher, "job-arm-past")
    database.arm_stage_deadline("job-arm-past", seconds=-1)
    row = database.job("job-arm-past")
    assert row is not None
    deadline = datetime.fromisoformat(str(row["stage_deadline_at"]))
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    assert deadline < datetime.now(UTC)


def test_arm_stage_deadline_refuses_terminal_jobs(database: Any, cipher: Any) -> None:
    _job(database, cipher, "job-arm-terminal")
    database.update_job(
        "job-arm-terminal",
        status=JobStatus.ERROR,
        stage=JobStage.ERROR,
        progress=1,
        message="terminal",
    )
    with pytest.raises(ValueError, match="terminal"):
        database.arm_stage_deadline("job-arm-terminal", seconds=300)


def test_model_call_deadline_is_explicitly_armed_and_cleared(database: Any, cipher: Any) -> None:
    _job(database, cipher, "job-model-call-window")

    call_token, deadline = database.arm_model_call_deadline("job-model-call-window", seconds=300)

    assert database.job("job-model-call-window")["model_call_deadline_at"] == deadline
    assert database.clear_model_call_deadline("job-model-call-window", call_token="0" * 32) is False
    assert database.job("job-model-call-window")["model_call_deadline_at"] == deadline
    assert (
        database.clear_model_call_deadline("job-model-call-window", call_token=call_token) is True
    )
    assert database.job("job-model-call-window")["model_call_deadline_at"] is None


def test_runner_arms_stage_deadline_only_when_stage_changes(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    from app.jobs import ANSWER_STAGE_SECONDS
    from app.retrieval.budget import retrieval_deadline_at

    _job(database, cipher, "job-stage-once")
    runner = _checkpoint_runner(
        tmp_path=tmp_path,
        database=database,
        cipher=cipher,
        model=SimpleNamespace(),
    )
    armed: list[int] = []
    original = database.arm_stage_deadline

    def _spy(job_id: str, *, seconds: int) -> str:
        armed.append(seconds)
        return original(job_id, seconds=seconds)

    database.arm_stage_deadline = _spy  # type: ignore[method-assign]
    runner._event("job-stage-once", JobStage.RESEARCHING, 0.16, "Researching")
    first = database.job("job-stage-once")["stage_deadline_at"]
    bound = retrieval_deadline_at()
    runner._event("job-stage-once", JobStage.RESEARCHING, 0.20, "Still researching")
    second = database.job("job-stage-once")["stage_deadline_at"]
    assert first == second
    assert armed == [ANSWER_STAGE_SECONDS]
    assert bound is not None
    runner._event("job-stage-once", JobStage.QUALIFYING, 0.32, "Qualifying evidence")
    assert armed == [ANSWER_STAGE_SECONDS, ANSWER_STAGE_SECONDS]
    assert database.job("job-stage-once")["stage_deadline_at"] != first
