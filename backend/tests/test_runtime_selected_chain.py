from __future__ import annotations

import hashlib
import pytest
from datetime import date
from pathlib import Path

from app.citations.oscola import render_answer
from app.contracts.runtime_selected_chain import (
    build_selected_runtime_inputs,
    persist_selected_runtime_chain,
)
from app.contracts.schema_registry import ContractSchemaRegistry
from app.db import utc_iso
from app.evaluation.evaluation_job_authority import build_evaluation_job_authority
from app.evaluation.ge_qwen_development_authority import GEQwenDevelopmentAdmissionBinding
from app.orchestration.object_store import EncryptedObjectStore
from app.quality.policy import POLICY_VERSION
from app.runtime_adapters import expected_model_visible_fact_inputs
from app.types import (
    EvidenceSpan,
    IssuePlan,
    MaterialLane,
    QualityReport,
    ReleaseState,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


@pytest.mark.parametrize("with_application", [False, True])
def test_actual_runner_contract_builder_persists_complete_unpublished_chain(
    tmp_path: Path, database, cipher, with_application
) -> None:
    candidate_id = "candidate-visible-r1"
    request_sha256 = "a" * 64
    candidate_sha256 = "b" * 64
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES (?,?,?,?,?,?,?,?,?)
        """,
        (
            candidate_id,
            "candidate",
            "data/indexes/candidate-visible-r1",
            1,
            1,
            1,
            "embedding-model",
            "reranker-model",
            utc_iso(),
        ),
    )
    binding = GEQwenDevelopmentAdmissionBinding(
        run_id="ge-qwen-visible-proof-r1",
        case_id="visible-supported-01",
        request_sha256=request_sha256,
        candidate_build_id=candidate_id,
        authority_file_sha256="c" * 64,
        authority_seal_sha256="d" * 64,
        owner_scope_sha256="e" * 64,
        runtime_binding_sha256="f" * 64,
        idempotency_key_sha256="1" * 64,
        expected_disposition="supported_answer",
    )
    authority = build_evaluation_job_authority(binding)
    job_id = "job-selected-runtime-1"
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("What notice is required?"),
        question_summary="Private encrypted question",
        request={"upload_ids": [], "word_target": 700},
        idempotency_key=binding.idempotency_key_sha256,
        pinned_index_build_id=candidate_id,
        evaluation_run_id=binding.run_id,
        evaluation_case_id=binding.case_id,
        evaluation_request_sha256=request_sha256,
        evaluation_authority=authority,
    )
    database.execute(
        """
        UPDATE jobs SET status='running',stage='verifying',lease_owner='worker-1',
          lease_expires_at=?,attempt_count=1 WHERE id=?
        """,
        ("2099-01-01T00:00:00+00:00", job_id),
    )
    evidence = EvidenceSpan(
        id="evidence-1",
        source_version_id="source-version-1",
        chunk_id="chunk-1",
        text="The prescribed notice must be served before proceedings.",
        locator="s 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="housing",
        citation_data={
            "source_type": "legislation",
            "title": "Example Act 2026",
            "provision": "s 1",
            "reviewed_as_of": "2026-09-08",
            "commencement_status": "in_force",
        },
        canonical_citation="Example Act 2026, s 1",
        currentness_status="current",
        content_sha256="2" * 64,
        index_build_id=candidate_id,
        canonical_url="https://www.legislation.gov.uk/example",
        retrieval_relevance_score=0.99,
        retrieval_route="frozen_reviewed_research_receipt",
        retrieval_threshold=0.5,
        retrieval_threshold_policy_sha256="3" * 64,
        retrieval_threshold_qualified=True,
        retrieval_qualification_reason="threshold_qualified",
        legal_role="statutory_rule",
        provision_extent_status="england_and_wales",
        identity_verified=True,
        currentness_verified=True,
    )
    issue_plan = IssuePlan(
        jurisdiction="England and Wales",
        subject="housing",
        proposition_keys=["notice"],
        queries=["prescribed notice proceedings"],
        notes_considered=0,
        notes_used=0,
        unsafe_notes_excluded=0,
    )
    registry = ContractSchemaRegistry.from_project_root(Path(__file__).resolve().parents[2])
    objects = EncryptedObjectStore(tmp_path / "objects", database, cipher)
    selected = build_selected_runtime_inputs(
        job=database.job(job_id),
        request_sha256=request_sha256,
        question="What notice is required?",
        task_type=TaskType.GENERAL,
        answer_route="direct",
        jurisdiction="England and Wales",
        as_of_date=date(2026, 9, 8),
        issue_plan=issue_plan,
        evidence=[evidence],
        visible_facts=expected_model_visible_fact_inputs(
            question="What notice is required?", upload_context=[]
        ),
        candidate_id=candidate_id,
        candidate_sha256=candidate_sha256,
        objects=objects,
        registry=registry,
    )
    draft = StructuredDraft(
        title="Notice requirements",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 9, 8),
        sections=[
            StructuredSectionDraft(
                id="section-1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text="The prescribed notice must be served before proceedings.",
                        evidence_ids=[evidence.id],
                    )
                ],
            )
        ],
    )
    if with_application:
        draft.sections[0].claims.append(StructuredClaimDraft(
            id="application-1",kind="application",text="On the stated facts the prescribed notice is required before proceedings.",
            evidence_ids=[evidence.id],fact_quotes=["What notice is required?"],rule_claim_ids=["claim-1"],
        ))
    rendered = render_answer(draft, {evidence.id: evidence}).markdown
    answer_id = "answer-selected-runtime-1"
    database.store_answer_version(
        answer_id=answer_id,
        job_id=job_id,
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text(rendered),
        word_count=len(rendered.split()),
        policy_version=POLICY_VERSION,
        model_version="pinned-revision",
        index_build_id=candidate_id,
    )
    rendered_sha256 = hashlib.sha256(rendered.encode()).hexdigest()
    report = QualityReport(
        id="quality-report-1",
        answer_version_id=answer_id,
        evidence_passed=True,
        academic_score=90,
        ai_evidence_review={"passed": True},
        ai_full_answer_review={
            "passed": True,
            "rendered_answer_sha256": rendered_sha256,
        },
        release_state=ReleaseState.VERIFIED_FULL,
    )

    persisted = persist_selected_runtime_chain(
        database=database,
        objects=objects,
        registry=registry,
        selected_inputs=selected.value,
        answer_id=answer_id,
        draft=draft,
        rendered_answer=rendered,
        report=report,
        model_id="mlx-community/Qwen3.5-9B-4bit",
        model_version="pinned-revision",
        repair_count=0,
    )

    assert persisted.status == "verified_unpublished"
    assert persisted.answer_id == answer_id
    assert persisted.release_state == "verified_full"
    assert len(persisted.object_keys) == 10
