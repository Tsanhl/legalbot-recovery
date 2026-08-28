from __future__ import annotations

import asyncio
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.assessment.standards_scoring import (
    AssessmentStandardsReport,
    score_applicable_standards,
)
from app.config import Settings
from app.crypto import LocalCipher
from app.evaluation.canary_review_workspace import create_canary_review_workspace
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_gold import LiveSuiteExpertQualification
from app.evaluation.live_suite_stage_a_v2 import STAGE_A_V2_SCHEMA
from app.evaluation.live_suite_stage_a_v2_runner import (
    STAGE_A_RUNNER_POLICY_SHA256,
    STAGE_A_SCORER_IDENTITY_SHA256,
    run_stage_a_v2_create_only,
    validate_stage_a_inputs,
)
from app.evaluation.owner_quality_canary import (
    ALL60_QUALIFICATION_SCHEMA,
    All60CaseQualification,
    OwnerQualityCanaryManifest,
    freeze_owner_quality_canary_manifest,
)
from app.evaluation.owner_quality_canary_authorization import (
    OPERATIONAL_PROOF_SCHEMA,
    OWNER_QUALITY_O04_SCHEMA,
    PROMOTED_ACTIVE_PROOF_SCHEMA,
    OwnerCanaryOperationalProof,
    OwnerDecisionRequired,
    OwnerQualityO04Approval,
    PromotedActiveCandidateProof,
    issue_development_authorization,
    issue_holdout_authorization,
    load_owner_canary_authorization,
    owner_canary_policy_bindings,
    verify_authorization_manifest,
)
from app.evaluation.owner_quality_canary_circuit import (
    OwnerCanaryAttemptRequest,
    OwnerCanaryCaseAttemptResult,
    run_owner_canary_serial,
    seal_owner_canary_case_result,
)
from app.evaluation.sealed_candidate import SealedCandidateIdentity
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

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
INTEGRATION_SHA = "1" * 40
REVIEW_TOOLCHAIN_SHA = ai_evidence_reviewer_toolchain_sha256()
NOW = datetime(2026, 8, 20, 2, 0, tzinfo=UTC)
STAGE_A_RUN_ID = "stage-a-owner-auth-001"


@pytest.fixture(autouse=True)
def _fixed_clean_integration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_authorization._local_clean_integration_sha",
        lambda _root: INTEGRATION_SHA,
    )


def _candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        embedding_model="Qwen/Qwen3-Embedding-0.6B",
        reranker_model="Qwen/Qwen3-Reranker-0.6B",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )


def _contracts() -> tuple[
    Any,
    SealedCandidateIdentity,
    All60CaseQualification,
    LiveSuiteExpertQualification,
    OwnerQualityCanaryManifest,
]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    candidate = _candidate()
    expert_cases: list[dict[str, Any]] = []
    for case_index, case in enumerate(bundle.registry.cases):
        issues: list[dict[str, Any]] = []
        for issue_index, _topic in enumerate(case.must_cover_issues, start=1):
            positive = case_index == 0 and issue_index == 1
            issues.append(
                {
                    "schema": "legalbot.live-issue-qualification.v1",
                    "issue_id": f"issue-{issue_index:02d}",
                    "status": "qualified" if positive else "knowledge_gap",
                    "reason_code": None if positive else "no_qualified_span",
                    "exact_gold_spans": (
                        [
                            {
                                "schema": "legalbot.live-gold-span.v1",
                                "gold_span_id": "gold-owner-auth-1",
                                "issue_id": "issue-01",
                                "stable_source_id": "source-owner-auth-1",
                                "legal_authority_id": None,
                                "source_version_id": "source-version-owner-auth-1",
                                "chunk_id": "chunk-owner-auth-1",
                                "legal_locator": "section 1",
                                "content_sha256": "e" * 64,
                                "source_type": "legislation",
                                "legal_role": "statutory_text",
                                "proposition_hash": None,
                                "case_currentness_review": None,
                                "relevance_grade": 3,
                                "contrary_or_limiting": False,
                            }
                        ]
                        if positive
                        else []
                    ),
                }
            )
        expert_cases.append(
            {
                "schema": "legalbot.live-case-qualification.v1",
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": "limited" if case_index == 0 else "knowledge_gap",
                "contrary_authority_status": "reviewed_none",
                "acceptable_source_ids": ["source-owner-auth-1"] if case_index == 0 else [],
                "issues": issues,
            }
        )
    expert_value: dict[str, Any] = {
        "schema": "legalbot.live-expert-qualification.v1",
        "suite_id": bundle.manifest.suite_id,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "index_build_id": candidate.build_id,
        "as_of_date": date(2026, 8, 20).isoformat(),
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "expert_approved",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": "legal_reviewer",
        "approval_reviewer_ref": f"reviewer:{'f' * 64}",
        "owner_is_primary_reviewer": True,
        "independent_second_review_status": "not_required",
        "independent_second_reviewer_role": None,
        "independent_second_reviewer_ref": None,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": 60,
        "cases": expert_cases,
    }
    expert_value["seal_sha256"] = sealed_sha256(expert_value)
    expert = LiveSuiteExpertQualification.model_validate(expert_value)
    case_ids = [case.case_id for case in bundle.registry.cases]
    qualification_value = {
        "schema": ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": "candidate-v111",
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": [],
        "limited_case_ids": case_ids,
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    qualification_value["seal_sha256"] = sealed_sha256(qualification_value)
    qualification = All60CaseQualification.model_validate(qualification_value)
    manifest = freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        qualification=qualification,
    )
    return bundle, candidate, qualification, expert, manifest


def _stage_a(
    *,
    bundle: Any,
    candidate: SealedCandidateIdentity,
    qualification: All60CaseQualification,
    expert: LiveSuiteExpertQualification,
    passed: bool = True,
) -> dict[str, Any]:
    validated = validate_stage_a_inputs(
        bundle=bundle,
        candidate=candidate,
        all60_qualification=qualification,
        expert_qualification=expert,
        as_of_date=expert.as_of_date,
    )
    value: dict[str, Any] = {
        "schema": STAGE_A_V2_SCHEMA,
        "candidate_build_id": candidate.build_id,
        "run_id": "stage-a-owner-auth-001",
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "all60_qualification_seal_sha256": qualification.seal_sha256,
        "expert_qualification_seal_sha256": expert.seal_sha256,
        "as_of_date": expert.as_of_date.isoformat(),
        "case_count": 60,
        "issue_count": 585,
        "issue_status_counts": validated.status_counts,
        "issue_identity_set_sha256": validated.issue_identity_set_sha256,
        "completed_checkpoint_count": 585,
        "completed_issue_count": 585,
        "checkpoint_set_sha256": "2" * 64,
        "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "code_revision": INTEGRATION_SHA,
        "code_dirty": False,
        "timeout_count": 0,
        "worker_failure_count": 0,
        "hard_failure_count": 0,
        "run_status": "passed" if passed else "gate_failed",
        "review_complete": True,
        "unreviewed_issue_count": 0,
        "scored_issue_count": 1,
        "selected_qualified_issue_count": 1,
        "selected_limited_issue_count": 0,
        "selected_knowledge_gap_count": 584,
        "recall_at_5": 1.0 if passed else 0.0,
        "recall_at_10": 1.0,
        "mrr": 1.0,
        "ndcg": 1.0,
        "exact_span_recall": 1.0,
        "filter_violation_count": 0,
        "stage_a_passed": passed,
        "authorization_eligible": passed,
        "metrics_source": "derived_rankings",
        "fabricated_gap_recall": False,
        "requires_305_positive_spans": False,
        "writes_active": False,
        "writes_o04": False,
        "answer_generation_invoked": False,
    }
    value["seal_sha256"] = sealed_sha256(value)
    return value


class _StageARetriever:
    def __init__(self, candidate_build_id: str, *, passing: bool) -> None:
        self._candidate_build_id = candidate_build_id
        self._passing = passing

    def active_build_id(self) -> str:
        return self._candidate_build_id

    async def retrieve(self, **_kwargs: Any) -> tuple[EvidenceSpan, ...]:
        if not self._passing:
            return ()
        return (
            EvidenceSpan(
                id="evidence-owner-auth-1",
                source_version_id="source-version-owner-auth-1",
                chunk_id="chunk-owner-auth-1",
                text="Verified statutory text for the sealed Stage A test issue.",
                locator="section 1",
                lane=MaterialLane.PRIMARY_AUTHORITY,
                jurisdiction="England and Wales",
                subject="general",
                currentness_status="current",
                content_sha256="e" * 64,
                index_build_id=self._candidate_build_id,
                retrieval_relevance_score=1.0,
                retrieval_route="exact_legislation_reference",
                retrieval_threshold=1.0,
                retrieval_threshold_policy_sha256="f" * 64,
                retrieval_threshold_qualified=True,
                retrieval_qualification_reason="exact_identity_locator_verified",
                legal_role="statutory_text",
                identity_verified=True,
                currentness_verified=True,
            ),
        )


def _write_stage_a_artifacts(
    *,
    settings: Settings,
    bundle: Any,
    candidate: SealedCandidateIdentity,
    qualification: All60CaseQualification,
    expert: LiveSuiteExpertQualification,
    run_id: str = STAGE_A_RUN_ID,
    passing: bool = True,
) -> dict[str, Any]:
    return asyncio.run(
        run_stage_a_v2_create_only(
            run_id=run_id,
            output_root=settings.evaluation_dir / "stage-a-v2",
            bundle=bundle,
            candidate=candidate,
            all60_qualification=qualification,
            expert_qualification=expert,
            retriever=_StageARetriever(candidate.build_id, passing=passing),
            as_of_date=expert.as_of_date,
            code_revision=INTEGRATION_SHA,
            code_dirty=False,
        )
    )


def _development_authorization(tmp_path: Path) -> tuple[Any, Any, Any, Any]:
    bundle, candidate, qualification, expert, manifest = _contracts()
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_stage_a_artifacts(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
    )
    authorization = issue_development_authorization(
        settings=settings,
        path=tmp_path / "development-authorization.json",
        run_id="owner-development-001",
        stage_a_run_id=STAGE_A_RUN_ID,
        bundle=bundle,
        candidate=candidate,
        manifest=manifest,
        qualification=qualification,
        expert_qualification=expert,
        issued_at=NOW,
        _synthetic_non_authoritative_test_only=True,
    )
    return bundle, qualification, manifest, authorization


def _external_holdout_proofs(
    *,
    manifest: OwnerQualityCanaryManifest,
    stage_a: dict[str, Any],
    authorized_case_ids: tuple[str, ...] | None = None,
    candidate_build_id: str = "candidate-v111",
) -> tuple[
    PromotedActiveCandidateProof,
    OwnerCanaryOperationalProof,
    OwnerQualityO04Approval,
]:
    active_value: dict[str, Any] = {
        "schema": PROMOTED_ACTIVE_PROOF_SCHEMA,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": manifest.candidate_manifest_sha256,
        "active_pointer_sha256": "3" * 64,
        "owner_promotion_ref": "promotion:" + "4" * 64,
        "catalogue_active_build_id": candidate_build_id,
        "pointer_active_build_id": candidate_build_id,
        "active_reconciled": True,
        "verified_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    active_value["seal_sha256"] = sealed_sha256(active_value)
    active = PromotedActiveCandidateProof.model_validate(active_value)

    operations_value: dict[str, Any] = {
        "schema": OPERATIONAL_PROOF_SCHEMA,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": manifest.candidate_manifest_sha256,
        "promoted_active_proof_seal_sha256": active.seal_sha256,
        "owner_only_smoke_sha256": "5" * 64,
        "rollback_repromotion_sha256": "6" * 64,
        "browser_recovery_sha256": "7" * 64,
        "readiness_sha256": "8" * 64,
        "disk_heartbeat_lease_sha256": "9" * 64,
        "model_identity_sha256": "b" * 64,
        "owner_only": True,
        "loopback_only": True,
        "operational_proof_passed": True,
        "blocking_gate_count": 0,
        "verified_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    operations_value["seal_sha256"] = sealed_sha256(operations_value)
    operations = OwnerCanaryOperationalProof.model_validate(operations_value)

    policies = owner_canary_policy_bindings()
    o04_value: dict[str, Any] = {
        "schema": OWNER_QUALITY_O04_SCHEMA,
        "decision_code": "O-04",
        "approval_id": "o04:" + "c" * 64,
        "run_id": "owner-holdout-001",
        "lane": "blind_holdout",
        "canary_manifest_id": manifest.manifest_id,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": manifest.candidate_manifest_sha256,
        "qualification_seal_sha256": manifest.qualification_seal_sha256,
        "stage_a_seal_sha256": stage_a["seal_sha256"],
        "integration_sha": INTEGRATION_SHA,
        "policy_bindings_seal_sha256": policies.seal_sha256,
        "promoted_active_proof_seal_sha256": active.seal_sha256,
        "operational_proof_seal_sha256": operations.seal_sha256,
        "authorized_case_ids": list(authorized_case_ids or manifest.blind_holdout_case_ids),
        "authorized_pass_count": 1,
        "one_serial_pass": True,
        "owner_signed": True,
        "owner_ref": "owner:" + "d" * 64,
        "owner_signature_ref": "signature:" + "e" * 64,
        "signature_verification_sha256": "f" * 64,
        "signature_verified": True,
        "signed_at": NOW.isoformat().replace("+00:00", "Z"),
    }
    o04_value["seal_sha256"] = sealed_sha256(o04_value)
    return active, operations, OwnerQualityO04Approval.model_validate(o04_value)


def test_development_authorization_is_create_only_and_needs_no_active_or_o04(
    tmp_path: Path,
) -> None:
    bundle, candidate, qualification, expert, manifest = _contracts()
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_stage_a_artifacts(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
    )
    path = tmp_path / "development.json"
    authorization = issue_development_authorization(
        settings=settings,
        path=path,
        run_id="owner-development-001",
        stage_a_run_id=STAGE_A_RUN_ID,
        bundle=bundle,
        candidate=candidate,
        manifest=manifest,
        qualification=qualification,
        expert_qualification=expert,
        issued_at=NOW,
        _synthetic_non_authoritative_test_only=True,
    )

    assert authorization.authorized_case_ids == manifest.development_case_ids
    assert authorization.requires_active is False
    assert authorization.requires_operational_proof is False
    assert authorization.requires_o04 is False
    assert load_owner_canary_authorization(path, manifest=manifest) == authorization
    assert not (tmp_path / "data/indexes/ACTIVE.json").exists()
    with pytest.raises(FileExistsError, match="create-only"):
        issue_development_authorization(
            settings=settings,
            path=path,
            run_id="owner-development-001",
            stage_a_run_id=STAGE_A_RUN_ID,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            issued_at=NOW,
            _synthetic_non_authoritative_test_only=True,
        )
    failed_run_id = "stage-a-owner-auth-failed"
    _write_stage_a_artifacts(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
        run_id=failed_run_id,
        passing=False,
    )
    with pytest.raises(ValueError, match="terminal failure marker"):
        issue_development_authorization(
            settings=settings,
            path=tmp_path / "failed-stage-a.json",
            run_id="owner-development-002",
            stage_a_run_id=failed_run_id,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            issued_at=NOW,
            _synthetic_non_authoritative_test_only=True,
        )
    assert bundle.registry.case_count == 60


def test_authoritative_development_requires_strict_completion_preflight(
    tmp_path: Path,
) -> None:
    bundle, candidate, qualification, expert, manifest = _contracts()
    with pytest.raises(OwnerDecisionRequired) as caught:
        issue_development_authorization(
            settings=Settings(project_root=tmp_path),
            path=tmp_path / "authoritative-development.json",
            run_id="owner-development-authoritative",
            stage_a_run_id=STAGE_A_RUN_ID,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            issued_at=NOW,
        )
    assert caught.value.reason_code == "authoritative_completion_preflight_required"
    assert not (tmp_path / "authoritative-development.json").exists()


def test_development_authorization_rejects_synthetic_one_issue_stage_a(
    tmp_path: Path,
) -> None:
    bundle, candidate, qualification, expert, manifest = _contracts()
    synthetic = _stage_a(
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
    )
    synthetic.update(
        {
            "case_count": 1,
            "issue_count": 1,
            "completed_checkpoint_count": 1,
            "completed_issue_count": 1,
        }
    )
    synthetic["seal_sha256"] = sealed_sha256(synthetic)
    settings = Settings(project_root=tmp_path, test_mode=True)
    run_id = "stage-a-synthetic-summary-only"
    run_dir = settings.evaluation_dir / "stage-a-v2" / run_id
    run_dir.mkdir(parents=True, mode=0o700)
    run_dir.parent.chmod(0o700)
    run_dir.chmod(0o700)
    result_path = run_dir / "stage-a-result.json"
    result_path.write_text(json.dumps(synthetic), encoding="utf-8")
    result_path.chmod(0o600)

    with pytest.raises(ValueError, match="artifact is missing"):
        issue_development_authorization(
            settings=settings,
            path=tmp_path / "synthetic.json",
            run_id="owner-development-synthetic",
            stage_a_run_id=run_id,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            issued_at=NOW,
            _synthetic_non_authoritative_test_only=True,
        )
    assert not (tmp_path / "synthetic.json").exists()


def test_development_authorization_recomputes_checkpoint_set(
    tmp_path: Path,
) -> None:
    bundle, candidate, qualification, expert, manifest = _contracts()
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_stage_a_artifacts(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
    )
    checkpoint = next(
        iter(
            sorted(
                (settings.evaluation_dir / "stage-a-v2" / STAGE_A_RUN_ID / "checkpoints").iterdir()
            )
        )
    )
    value = json.loads(checkpoint.read_text(encoding="utf-8"))
    value["ranked_identity_tokens"] = ["miss:" + "3" * 64]
    value["seal_sha256"] = sealed_sha256(value)
    checkpoint.write_text(json.dumps(value), encoding="utf-8")
    checkpoint.chmod(0o600)

    with pytest.raises(ValueError, match="checkpoint recomputation"):
        issue_development_authorization(
            settings=settings,
            path=tmp_path / "tampered-checkpoint.json",
            run_id="owner-development-tampered",
            stage_a_run_id=STAGE_A_RUN_ID,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            issued_at=NOW,
            _synthetic_non_authoritative_test_only=True,
        )
    assert not (tmp_path / "tampered-checkpoint.json").exists()


def test_development_authorization_rechecks_local_clean_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle, candidate, qualification, expert, manifest = _contracts()
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_stage_a_artifacts(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
    )
    observed = iter((INTEGRATION_SHA, "2" * 40))
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_authorization._local_clean_integration_sha",
        lambda _root: next(observed),
    )
    with pytest.raises(RuntimeError, match="HEAD changed"):
        issue_development_authorization(
            settings=settings,
            path=tmp_path / "changed-head.json",
            run_id="owner-development-changed-head",
            stage_a_run_id=STAGE_A_RUN_ID,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            issued_at=NOW,
            _synthetic_non_authoritative_test_only=True,
        )
    assert not (tmp_path / "changed-head.json").exists()


def test_holdout_cannot_skip_authoritative_completion_preflight(
    tmp_path: Path,
) -> None:
    bundle, candidate, qualification, expert, manifest = _contracts()
    settings = Settings(project_root=tmp_path)
    stage_a = _write_stage_a_artifacts(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert=expert,
    )
    active, operations, owner_o04 = _external_holdout_proofs(manifest=manifest, stage_a=stage_a)
    with pytest.raises(OwnerDecisionRequired, match="OWNER_DECISION_REQUIRED") as caught:
        issue_holdout_authorization(
            settings=settings,
            path=tmp_path / "holdout.json",
            run_id="owner-holdout-001",
            stage_a_run_id=STAGE_A_RUN_ID,
            bundle=bundle,
            candidate=candidate,
            manifest=manifest,
            qualification=qualification,
            expert_qualification=expert,
            promoted_active=active,
            operational_proof=operations,
            owner_o04=owner_o04,
            issued_at=NOW,
        )
    assert caught.value.reason_code == "authoritative_completion_preflight_required"
    assert not (tmp_path / "holdout.json").exists()


def test_authorization_rechecks_exact_immutable_manifest_ids(tmp_path: Path) -> None:
    _bundle, _qualification, manifest, authorization = _development_authorization(tmp_path)
    changed = manifest.model_dump(mode="json", by_alias=True)
    changed["development_case_ids"][0], changed["blind_holdout_case_ids"][0] = (
        changed["blind_holdout_case_ids"][0],
        changed["development_case_ids"][0],
    )
    changed["seal_sha256"] = sealed_sha256(changed)
    with pytest.raises(ValidationError, match="lane lists"):
        OwnerQualityCanaryManifest.model_validate(changed)

    auth_changed = authorization.model_copy(
        update={
            "authorized_case_ids": manifest.blind_holdout_case_ids,
        }
    )
    with pytest.raises(ValueError, match="immutable manifest"):
        verify_authorization_manifest(auth_changed, manifest)


def _review_and_standards(
    *, case: Any, strong_standards: bool = True
) -> tuple[AIEvidenceReviewResult, AIEvidenceAdjudication, AssessmentStandardsReport]:
    evidence_by_id = {
        f"evidence-{number}": EvidenceSpan(
            id=f"evidence-{number}",
            source_version_id=f"source-version-{number}",
            chunk_id=f"chunk-{number}",
            text=(
                "Verified authority supplies the governing requirement, element, "
                "defence, application and supported competing outcome."
            ),
            locator=f"s {number}",
            lane=MaterialLane.PRIMARY_AUTHORITY,
            jurisdiction=case.jurisdiction,
            subject=case.subject,
            currentness_status="current",
            content_sha256=str(number + 3) * 64,
            index_build_id="candidate-v111",
            retrieval_relevance_score=1.0,
            retrieval_route="exact_legislation_reference",
            retrieval_threshold=1.0,
            retrieval_threshold_policy_sha256="f" * 64,
            retrieval_threshold_qualified=True,
            retrieval_qualification_reason="exact_identity_locator_verified",
            identity_verified=True,
            currentness_verified=True,
        )
        for number in (1, 2)
    }
    evidence_ids = list(evidence_by_id)
    if strong_standards:
        claim_text = (
            "The better view, although qualified, applies every requirement, element "
            "and defence because on these facts the alternative competing outcome "
            "depends on a missing fact; however the stronger conclusion follows. " + case.question
        )
        sections = [
            StructuredSectionDraft(
                id=f"section-{number}",
                heading=f"Issue {number}",
                claims=[
                    StructuredClaimDraft(
                        id=f"claim-{number}",
                        text=claim_text,
                        evidence_ids=evidence_ids,
                    )
                ],
            )
            for number in (1, 2, 3)
        ]
    else:
        sections = [
            StructuredSectionDraft(
                id="section-1",
                heading="Rule",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text="The statutory proposition applies.",
                        evidence_ids=evidence_ids,
                    )
                ],
            )
        ]
    draft = StructuredDraft(
        title="Analysis",
        task_type=TaskType(case.task_type),
        jurisdiction=case.jurisdiction,
        as_of_date=date(2026, 8, 20),
        sections=sections,
    )
    frozen = freeze_material_claims(draft=draft, evidence_by_id=evidence_by_id)
    model_claims = [
        {
            "claim_id": item.identity.claim_id,
            "verdict": "supported",
            "reason_codes": ["evidence_checked"],
            "cited_evidence_ids": list(item.identity.evidence_span_ids),
        }
        for item in frozen
    ]
    review = seal_ai_evidence_review(
        model_output={"claims": model_claims},
        source_draft=draft,
        frozen_claims=frozen,
        invocation_id="review-invocation-1",
        invocation_ids=tuple(f"review-invocation-{number}" for number in range(1, len(frozen) + 1)),
        model_id="reviewer-model",
        model_version="2026-08-20",
        policy_sha256=POLICY_SHA256,
        toolchain_sha256=REVIEW_TOOLCHAIN_SHA,
    )
    standards = score_applicable_standards(
        draft=draft,
        question=case.question,
        subject=case.subject,
        evidence_by_id=evidence_by_id,
        supported_claim_ids=tuple(item.identity.claim_id for item in frozen),
    )
    assert standards.source_draft_sha256 == review.source_draft_sha256
    return review, adjudicate_ai_evidence_review(review), standards


def _circuit_fixture(tmp_path: Path) -> tuple[Any, Any, Any, Any, LocalCipher, dict[str, str]]:
    bundle, _qualification, manifest, authorization = _development_authorization(tmp_path)
    workspace = create_canary_review_workspace(
        project_root=tmp_path,
        review_date=date(2026, 8, 20),
        run_id=authorization.run_id,
        lane="development",
        canary_manifest=manifest,
        runtime_run_manifest_sha256=authorization.seal_sha256,
    )
    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    initial = {
        case_id: sealed_sha256({"case_id": case_id, "revision": "initial"})
        for case_id in authorization.authorized_case_ids
    }
    return bundle, manifest, authorization, workspace, cipher, initial


@pytest.mark.parametrize("missing", ["ai", "standards", "standards_avoidance"])
def test_missing_ai_or_standards_freezes_before_next_submission(
    tmp_path: Path, missing: str
) -> None:
    bundle, manifest, authorization, workspace, cipher, initial = _circuit_fixture(tmp_path)
    first_case = bundle.registry.case(authorization.authorized_case_ids[0])
    review, adjudication, standards = _review_and_standards(
        case=first_case,
        strong_standards=missing != "standards_avoidance",
    )
    if missing == "standards_avoidance":
        assert standards.avoidance_passed is False
    else:
        assert standards.avoidance_passed is True
    calls: list[str] = []

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        calls.append(request.case_id)
        return seal_owner_canary_case_result(
            result_id=f"result-{request.case_id}-{request.attempt_number}",
            run_id=request.run_id,
            authorization_seal_sha256=authorization.seal_sha256,
            canary_manifest_seal_sha256=manifest.seal_sha256,
            case_id=request.case_id,
            attempt_number=request.attempt_number,
            input_revision_sha256=request.input_revision_sha256,
            candidate_build_id=authorization.candidate_build_id,
            candidate_manifest_sha256=authorization.candidate_manifest_sha256,
            released=False,
            ai_review=None if missing == "ai" else review,
            ai_adjudication=None if missing == "ai" else adjudication,
            standards_report=(None if missing == "standards" else standards),
        )

    result = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        case_projector=lambda _result: pytest.fail("blocked result must not project"),
    )

    assert result.status == "stopped"
    assert result.stopped_case_id == authorization.authorized_case_ids[0]
    assert calls == [authorization.authorized_case_ids[0]]
    expected = {
        "ai": "ai_review_missing",
        "standards": "standards_review_missing",
        "standards_avoidance": "standards_avoidance_failed",
    }[missing]
    assert expected in result.stop_reason_codes
    encrypted = workspace.root / "debug-bundles" / f"{result.debug_artifact_id}.enc"
    debug = json.loads(cipher.decrypt_bytes(encrypted.read_bytes()))
    assert debug["next_case_submitted"] is False
    assert debug["question_prose_retained"] is False
    assert debug["answer_prose_retained"] is False

    second_calls: list[str] = []

    def second_callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        second_calls.append(request.case_id)
        raise AssertionError("frozen circuit invoked another callback")

    with pytest.raises(FileExistsError):
        run_owner_canary_serial(
            authorization=authorization,
            manifest=manifest,
            bundle=bundle,
            workspace=workspace,
            cipher=cipher,
            initial_input_revision_sha256_by_case=initial,
            case_callback=second_callback,
            case_projector=lambda _result: pytest.fail("frozen run must not project"),
        )
    assert second_calls == []


def test_retry_requires_changed_input_and_stops_repeated_semantic_failure(
    tmp_path: Path,
) -> None:
    bundle, manifest, authorization, workspace, cipher, initial = _circuit_fixture(tmp_path)
    first_case = bundle.registry.case(authorization.authorized_case_ids[0])
    review, adjudication, standards = _review_and_standards(case=first_case)
    assert standards.avoidance_passed is True
    revisions = ["6" * 64, "7" * 64, "8" * 64]
    calls: list[tuple[str, int, str]] = []

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        calls.append((request.case_id, request.attempt_number, request.input_revision_sha256))
        return seal_owner_canary_case_result(
            result_id=f"result-{request.case_id}-{request.attempt_number}",
            run_id=request.run_id,
            authorization_seal_sha256=authorization.seal_sha256,
            canary_manifest_seal_sha256=manifest.seal_sha256,
            case_id=request.case_id,
            attempt_number=request.attempt_number,
            input_revision_sha256=request.input_revision_sha256,
            candidate_build_id=authorization.candidate_build_id,
            candidate_manifest_sha256=authorization.candidate_manifest_sha256,
            released=False,
            ai_review=review,
            ai_adjudication=adjudication,
            standards_report=standards,
            next_input_revision_sha256=revisions[request.attempt_number - 1],
        )

    result = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        case_projector=lambda _result: pytest.fail("non-release must not project"),
    )

    assert result.status == "stopped"
    assert len(calls) == 2
    assert {case_id for case_id, _attempt, _revision in calls} == {
        authorization.authorized_case_ids[0]
    }
    assert [attempt for _case, attempt, _revision in calls] == [1, 2]
    assert "repeated_failure_fingerprint" in result.stop_reason_codes
    assert authorization.authorized_case_ids[1] not in {
        case_id for case_id, _attempt, _revision in calls
    }
