from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from app.assessment.standards_scoring import (
    AssessmentStandardsReport,
    score_applicable_standards,
)
from app.evaluation.owner_quality_canary_artifacts import (
    DETERMINISTIC_RELEASE_GATES,
    OwnerCanaryDeterministicGateReport,
    OwnerCanaryEvidenceBundle,
    OwnerCanaryReleaseAttestation,
    seal_owner_canary_deterministic_gate_report,
    seal_owner_canary_evidence_bundle,
    seal_owner_canary_release_attestation,
    verify_positive_release_artifacts,
)
from app.evaluation.owner_quality_canary_circuit import seal_owner_canary_case_result
from app.quality.ai_evidence_reviewer import (
    AIEvidenceAdjudication,
    AIEvidenceReviewResult,
    adjudicate_ai_evidence_review,
    ai_evidence_reviewer_toolchain_sha256,
    freeze_material_claims,
    seal_ai_evidence_review,
)
from app.quality.policy import POLICY_SHA256
from app.types import (
    EvidenceSpan,
    MaterialLane,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)

RUN_ID = "owner-development-artifact-test"
AUTHORIZATION_SHA256 = "a" * 64
MANIFEST_SHA256 = "b" * 64
CANDIDATE_BUILD_ID = "candidate-v111"
CANDIDATE_MANIFEST_SHA256 = "c" * 64
CASE_ID = "live30-q01"
JOB_ID = "job-owner-canary-001"
ANSWER_VERSION_ID = "answer-version-001"
ANSWER_ARTIFACT_ID = "answer-artifact-001"
ANSWER_SHA256 = "d" * 64
WORD_TARGET = 1_000
WORD_COUNT = 1_000


def _positive_artifacts() -> tuple[
    AIEvidenceReviewResult,
    AIEvidenceAdjudication,
    AssessmentStandardsReport,
    OwnerCanaryEvidenceBundle,
    OwnerCanaryDeterministicGateReport,
    OwnerCanaryReleaseAttestation,
]:
    evidence = EvidenceSpan(
        id="evidence-001",
        source_version_id="source-version-001",
        chunk_id="chunk-001",
        text="Verified statutory text states the governing requirement.",
        locator="s 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="Public law",
        currentness_status="current",
        content_sha256="e" * 64,
        index_build_id=CANDIDATE_BUILD_ID,
        retrieval_relevance_score=1.0,
        retrieval_route="exact_legislation_reference",
        retrieval_threshold=1.0,
        retrieval_threshold_policy_sha256="f" * 64,
        retrieval_threshold_qualified=True,
        retrieval_qualification_reason="exact_identity_locator_verified",
        identity_verified=True,
        currentness_verified=True,
    )
    evidence_by_id = {evidence.id: evidence}
    draft = StructuredDraft(
        title="Analysis",
        task_type=TaskType.ESSAY,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        sections=[
            StructuredSectionDraft(
                id="section-001",
                heading="Issue",
                claims=[
                    StructuredClaimDraft(
                        id="claim-001",
                        text=(
                            "The better view applies the governing requirement because the "
                            "verified statutory text supports it; however, the conclusion "
                            "remains qualified by any contrary current authority."
                        ),
                        evidence_ids=[evidence.id],
                    )
                ],
            )
        ],
    )
    frozen = freeze_material_claims(draft=draft, evidence_by_id=evidence_by_id)
    review = seal_ai_evidence_review(
        model_output={
            "claims": [
                {
                    "claim_id": frozen[0].identity.claim_id,
                    "verdict": "supported",
                    "reason_codes": ["evidence_checked"],
                    "cited_evidence_ids": [evidence.id],
                }
            ]
        },
        source_draft=draft,
        frozen_claims=frozen,
        invocation_id="review-invocation-001",
        model_id="reviewer-model",
        model_version="2026-08-20",
        policy_sha256=POLICY_SHA256,
        toolchain_sha256=ai_evidence_reviewer_toolchain_sha256(),
    )
    adjudication = adjudicate_ai_evidence_review(review)
    standards = score_applicable_standards(
        draft=draft,
        question="Critically assess the governing public-law requirement and its limits.",
        subject="Public law",
        evidence_by_id=evidence_by_id,
        supported_claim_ids=("claim-001",),
    )
    evidence_bundle = seal_owner_canary_evidence_bundle(
        run_id=RUN_ID,
        authorization_seal_sha256=AUTHORIZATION_SHA256,
        canary_manifest_seal_sha256=MANIFEST_SHA256,
        case_id=CASE_ID,
        candidate_build_id=CANDIDATE_BUILD_ID,
        candidate_manifest_sha256=CANDIDATE_MANIFEST_SHA256,
        job_id=JOB_ID,
        answer_version_id=ANSWER_VERSION_ID,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        ai_review=review,
        evidence_by_id=evidence_by_id,
        deterministic_citations={evidence.id: "Public Act 2026, s 1"},
    )
    gates = seal_owner_canary_deterministic_gate_report(
        run_id=RUN_ID,
        authorization_seal_sha256=AUTHORIZATION_SHA256,
        canary_manifest_seal_sha256=MANIFEST_SHA256,
        case_id=CASE_ID,
        candidate_build_id=CANDIDATE_BUILD_ID,
        candidate_manifest_sha256=CANDIDATE_MANIFEST_SHA256,
        job_id=JOB_ID,
        answer_version_id=ANSWER_VERSION_ID,
        answer_sha256=ANSWER_SHA256,
        requested_word_target=WORD_TARGET,
        word_count=WORD_COUNT,
        evidence_bundle=evidence_bundle,
        source_release_report_sha256="f" * 64,
        gate_implementation_sha256="1" * 64,
        passed_gates={gate: True for gate in DETERMINISTIC_RELEASE_GATES},
    )
    attestation = seal_owner_canary_release_attestation(
        answer_artifact_id=ANSWER_ARTIFACT_ID,
        runtime_release_state="verified_full",
        evidence_bundle=evidence_bundle,
        deterministic_gate_report=gates,
    )
    return review, adjudication, standards, evidence_bundle, gates, attestation


def test_positive_attempt_recomputes_all_runtime_artifact_bindings() -> None:
    review, adjudication, standards, evidence_bundle, gates, attestation = _positive_artifacts()

    result = seal_owner_canary_case_result(
        result_id="result-owner-canary-001",
        run_id=RUN_ID,
        authorization_seal_sha256=AUTHORIZATION_SHA256,
        canary_manifest_seal_sha256=MANIFEST_SHA256,
        case_id=CASE_ID,
        attempt_number=1,
        input_revision_sha256="2" * 64,
        candidate_build_id=CANDIDATE_BUILD_ID,
        candidate_manifest_sha256=CANDIDATE_MANIFEST_SHA256,
        job_id=JOB_ID,
        answer_version_id=ANSWER_VERSION_ID,
        answer_artifact_id=ANSWER_ARTIFACT_ID,
        released=True,
        answer_sha256=ANSWER_SHA256,
        word_count=WORD_COUNT,
        ai_review=review,
        ai_adjudication=adjudication,
        standards_report=standards,
        evidence_bundle=evidence_bundle,
        deterministic_gate_report=gates,
        release_attestation=attestation,
    )

    assert result.release_attestation == attestation
    assert result.evidence_bundle == evidence_bundle
    assert result.deterministic_gate_report == gates


def test_positive_artifact_reconciliation_rejects_cross_job_substitution() -> None:
    review, _adjudication, _standards, evidence_bundle, gates, attestation = _positive_artifacts()

    with pytest.raises(ValueError, match="differs from the attempt"):
        verify_positive_release_artifacts(
            run_id=RUN_ID,
            authorization_seal_sha256=AUTHORIZATION_SHA256,
            canary_manifest_seal_sha256=MANIFEST_SHA256,
            case_id=CASE_ID,
            candidate_build_id=CANDIDATE_BUILD_ID,
            candidate_manifest_sha256=CANDIDATE_MANIFEST_SHA256,
            job_id="job-owner-canary-substituted",
            answer_version_id=ANSWER_VERSION_ID,
            answer_sha256=ANSWER_SHA256,
            word_count=WORD_COUNT,
            ai_review=review,
            evidence_bundle=evidence_bundle,
            deterministic_gate_report=gates,
            release_attestation=attestation,
        )


def test_positive_attempt_cannot_omit_ai_standards_or_gate_proof() -> None:
    review, adjudication, standards, evidence_bundle, gates, attestation = _positive_artifacts()
    common: dict[str, Any] = {
        "result_id": "result-owner-canary-001",
        "run_id": RUN_ID,
        "authorization_seal_sha256": AUTHORIZATION_SHA256,
        "canary_manifest_seal_sha256": MANIFEST_SHA256,
        "case_id": CASE_ID,
        "attempt_number": 1,
        "input_revision_sha256": "2" * 64,
        "candidate_build_id": CANDIDATE_BUILD_ID,
        "candidate_manifest_sha256": CANDIDATE_MANIFEST_SHA256,
        "job_id": JOB_ID,
        "answer_version_id": ANSWER_VERSION_ID,
        "answer_artifact_id": ANSWER_ARTIFACT_ID,
        "released": True,
        "answer_sha256": ANSWER_SHA256,
        "word_count": WORD_COUNT,
        "ai_review": review,
        "ai_adjudication": adjudication,
        "standards_report": standards,
        "evidence_bundle": evidence_bundle,
        "deterministic_gate_report": gates,
        "release_attestation": attestation,
    }

    for missing in ("ai_review", "standards_report", "deterministic_gate_report"):
        value = {**common, missing: None}
        with pytest.raises(ValueError, match="lacks positive runtime artifacts"):
            seal_owner_canary_case_result(**value)


def test_deterministic_gate_report_requires_exact_positive_gate_set() -> None:
    review, _adjudication, _standards, evidence_bundle, _gates, _attestation = _positive_artifacts()
    del review
    passed = {gate: True for gate in DETERMINISTIC_RELEASE_GATES}
    passed.pop("quotation_accuracy")

    with pytest.raises(ValueError, match="exact policy"):
        seal_owner_canary_deterministic_gate_report(
            run_id=RUN_ID,
            authorization_seal_sha256=AUTHORIZATION_SHA256,
            canary_manifest_seal_sha256=MANIFEST_SHA256,
            case_id=CASE_ID,
            candidate_build_id=CANDIDATE_BUILD_ID,
            candidate_manifest_sha256=CANDIDATE_MANIFEST_SHA256,
            job_id=JOB_ID,
            answer_version_id=ANSWER_VERSION_ID,
            answer_sha256=ANSWER_SHA256,
            requested_word_target=WORD_TARGET,
            word_count=WORD_COUNT,
            evidence_bundle=evidence_bundle,
            source_release_report_sha256="f" * 64,
            gate_implementation_sha256="1" * 64,
            passed_gates=passed,
        )
