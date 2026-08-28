from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Never

import pytest
from cryptography.fernet import Fernet

from app.assessment.standards_scoring import (
    AssessmentStandardsReport,
    score_applicable_standards,
)
from app.crypto import LocalCipher
from app.evaluation.canary_review_workspace import (
    CanaryReviewWorkspace,
    create_canary_review_workspace,
)
from app.evaluation.live_suite import (
    LiveEvaluationBundle,
    load_live_evaluation_bundle,
    sealed_sha256,
)
from app.evaluation.owner_quality_canary import (
    ALL60_QUALIFICATION_SCHEMA,
    All60CaseQualification,
    OwnerQualityCanaryManifest,
    freeze_owner_quality_canary_manifest,
)
from app.evaluation.owner_quality_canary_artifacts import (
    DETERMINISTIC_RELEASE_GATES,
    OwnerCanaryCaseProjectionReceipt,
    seal_owner_canary_deterministic_gate_report,
    seal_owner_canary_evidence_bundle,
    seal_owner_canary_release_attestation,
)
from app.evaluation.owner_quality_canary_authorization import (
    DEVELOPMENT_AUTHORIZATION_SCHEMA,
    OwnerQualityDevelopmentAuthorization,
    owner_canary_policy_bindings,
)
from app.evaluation.owner_quality_canary_circuit import (
    OwnerCanaryAttemptRequest,
    OwnerCanaryCaseAttemptResult,
    run_owner_canary_serial,
    seal_owner_canary_case_result,
)
from app.evaluation.owner_quality_canary_projection import (
    OwnerCanaryProjectionAdapter,
    execute_owner_quality_canary_review,
    finalize_owner_canary_review_package,
)
from app.quality.ai_evidence_reviewer import (
    AIEvidenceAdjudication,
    AIEvidenceReviewResult,
    adjudicate_ai_evidence_review,
    ai_evidence_reviewer_toolchain_sha256,
    freeze_material_claims,
    seal_ai_evidence_review,
)
from app.quality.policy import POLICY_SHA256
from app.text_metrics import word_count
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
CANDIDATE_BUILD_ID = "candidate-v111"
CANDIDATE_MANIFEST_SHA256 = "a" * 64
NOW = datetime(2026, 8, 20, 4, 0, tzinfo=UTC)


def _contracts(
    tmp_path: Path,
) -> tuple[
    LiveEvaluationBundle,
    OwnerQualityCanaryManifest,
    OwnerQualityDevelopmentAuthorization,
    CanaryReviewWorkspace,
    dict[str, str],
    LocalCipher,
]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    case_ids = [case.case_id for case in bundle.registry.cases]
    qualification_value: dict[str, Any] = {
        "schema": ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": CANDIDATE_BUILD_ID,
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": case_ids,
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    qualification_value["seal_sha256"] = sealed_sha256(qualification_value)
    qualification = All60CaseQualification.model_validate(qualification_value)
    manifest = freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id=CANDIDATE_BUILD_ID,
        candidate_manifest_sha256=CANDIDATE_MANIFEST_SHA256,
        qualification=qualification,
    )
    policies = owner_canary_policy_bindings()
    authorization_value: dict[str, Any] = {
        "schema": DEVELOPMENT_AUTHORIZATION_SCHEMA,
        "authorization_id": "owner-canary-development-" + "1" * 20,
        "run_id": "owner-development-projection-001",
        "suite_id": manifest.suite_id,
        "suite_manifest_seal_sha256": manifest.suite_manifest_seal_sha256,
        "suite_registry_canonical_sha256": manifest.suite_registry_canonical_sha256,
        "canary_manifest_id": manifest.manifest_id,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "candidate_build_id": manifest.candidate_build_id,
        "candidate_manifest_sha256": manifest.candidate_manifest_sha256,
        "qualification_seal_sha256": manifest.qualification_seal_sha256,
        "stage_a_seal_sha256": "2" * 64,
        "integration_sha": "3" * 40,
        "integration_git_dirty": False,
        "policy_bindings": policies.model_dump(mode="json", by_alias=True),
        "authorized_case_ids": list(manifest.development_case_ids),
        "authorized_case_count": 30,
        "serial_execution_required": True,
        "maximum_attempt_count": 3,
        "restart_allowed": False,
        "purpose": "evaluation_only",
        "local_only": True,
        "online_research_allowed": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "lane": "development",
        "requires_active": False,
        "requires_owner_promotion": False,
        "requires_operational_proof": False,
        "requires_o04": False,
    }
    authorization_value["seal_sha256"] = sealed_sha256(authorization_value)
    authorization = OwnerQualityDevelopmentAuthorization.model_validate(authorization_value)
    workspace = create_canary_review_workspace(
        project_root=tmp_path,
        review_date=date(2026, 8, 20),
        run_id=authorization.run_id,
        lane="development",
        canary_manifest=manifest,
        runtime_run_manifest_sha256=authorization.seal_sha256,
    )
    initial = {
        case_id: sealed_sha256({"case_id": case_id, "revision": "initial"})
        for case_id in authorization.authorized_case_ids
    }
    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    return bundle, manifest, authorization, workspace, initial, cipher


def _evidence(case: Any, *, threshold_policy_sha256: str) -> dict[str, EvidenceSpan]:
    return {
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
            index_build_id=CANDIDATE_BUILD_ID,
            retrieval_relevance_score=1.0,
            retrieval_route="exact_legislation_reference",
            retrieval_threshold=1.0,
            retrieval_threshold_policy_sha256=threshold_policy_sha256,
            retrieval_threshold_qualified=True,
            retrieval_qualification_reason="exact_identity_locator_verified",
            identity_verified=True,
            currentness_verified=True,
        )
        for number in (1, 2)
    }


def _review(
    case: Any, evidence_by_id: dict[str, EvidenceSpan]
) -> tuple[AIEvidenceReviewResult, AIEvidenceAdjudication, AssessmentStandardsReport]:
    question_terms = case.question.replace('"', "").replace("“", "").replace("”", "")
    claim_text = (
        "The better view, although qualified, applies every requirement, element and "
        "defence because on these facts the alternative competing outcome depends on "
        "a missing fact; however the stronger conclusion follows. " + question_terms
    )
    draft = StructuredDraft(
        title="Analysis",
        task_type=TaskType(case.task_type),
        jurisdiction=case.jurisdiction,
        as_of_date=date(2026, 8, 20),
        sections=[
            StructuredSectionDraft(
                id=f"section-{number}",
                heading=f"Issue {number}",
                claims=[
                    StructuredClaimDraft(
                        id=f"claim-{number}",
                        text=claim_text,
                        evidence_ids=list(evidence_by_id),
                    )
                ],
            )
            for number in (1, 2, 3)
        ],
    )
    frozen = freeze_material_claims(draft=draft, evidence_by_id=evidence_by_id)
    review = seal_ai_evidence_review(
        model_output={
            "claims": [
                {
                    "claim_id": item.identity.claim_id,
                    "verdict": "supported",
                    "reason_codes": ["evidence_checked"],
                    "cited_evidence_ids": list(item.identity.evidence_span_ids),
                }
                for item in frozen
            ]
        },
        source_draft=draft,
        frozen_claims=frozen,
        invocation_id=f"review-{case.case_id}",
        invocation_ids=tuple(
            f"review-{case.case_id}-{number}" for number in range(1, len(frozen) + 1)
        ),
        model_id="reviewer-model",
        model_version="2026-08-20",
        policy_sha256=POLICY_SHA256,
        toolchain_sha256=ai_evidence_reviewer_toolchain_sha256(),
    )
    standards = score_applicable_standards(
        draft=draft,
        question=case.question,
        subject=case.subject,
        evidence_by_id=evidence_by_id,
        supported_claim_ids=tuple(item.identity.claim_id for item in frozen),
    )
    assert standards.avoidance_passed
    return review, adjudicate_ai_evidence_review(review), standards


def _positive_result(
    *,
    request: OwnerCanaryAttemptRequest,
    case: Any,
    authorization: OwnerQualityDevelopmentAuthorization,
    manifest: OwnerQualityCanaryManifest,
    answers: dict[str, bytes],
) -> OwnerCanaryCaseAttemptResult:
    evidence_by_id = _evidence(
        case,
        threshold_policy_sha256=(authorization.policy_bindings.relevance_threshold_policy_sha256),
    )
    review, adjudication, standards = _review(case, evidence_by_id)
    content = ("analysis " * request.requested_word_target).rstrip().encode("utf-8")
    assert word_count(content.decode("utf-8")) == request.requested_word_target
    artifact_id = f"answer-artifact-{request.case_id}"
    answers[artifact_id] = content
    job_id = f"job-{request.case_id}"
    answer_version_id = f"answer-version-{request.case_id}"
    evidence_bundle = seal_owner_canary_evidence_bundle(
        run_id=request.run_id,
        authorization_seal_sha256=authorization.seal_sha256,
        canary_manifest_seal_sha256=manifest.seal_sha256,
        case_id=request.case_id,
        candidate_build_id=authorization.candidate_build_id,
        candidate_manifest_sha256=authorization.candidate_manifest_sha256,
        job_id=job_id,
        answer_version_id=answer_version_id,
        jurisdiction=case.jurisdiction,
        as_of_date=date(2026, 8, 20),
        ai_review=review,
        evidence_by_id=evidence_by_id,
        deterministic_citations={
            evidence_id: f"Public Act 2026, s {number}"
            for number, evidence_id in enumerate(evidence_by_id, start=1)
        },
    )
    answer_sha256 = hashlib.sha256(content).hexdigest()
    gate_report = seal_owner_canary_deterministic_gate_report(
        run_id=request.run_id,
        authorization_seal_sha256=authorization.seal_sha256,
        canary_manifest_seal_sha256=manifest.seal_sha256,
        case_id=request.case_id,
        candidate_build_id=authorization.candidate_build_id,
        candidate_manifest_sha256=authorization.candidate_manifest_sha256,
        job_id=job_id,
        answer_version_id=answer_version_id,
        answer_sha256=answer_sha256,
        requested_word_target=request.requested_word_target,
        word_count=request.requested_word_target,
        evidence_bundle=evidence_bundle,
        source_release_report_sha256="4" * 64,
        gate_implementation_sha256="5" * 64,
        passed_gates={gate: True for gate in DETERMINISTIC_RELEASE_GATES},
    )
    release = seal_owner_canary_release_attestation(
        answer_artifact_id=artifact_id,
        runtime_release_state="verified_full",
        evidence_bundle=evidence_bundle,
        deterministic_gate_report=gate_report,
    )
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
        job_id=job_id,
        answer_version_id=answer_version_id,
        answer_artifact_id=artifact_id,
        released=True,
        answer_sha256=answer_sha256,
        word_count=request.requested_word_target,
        ai_review=review,
        ai_adjudication=adjudication,
        standards_report=standards,
        evidence_bundle=evidence_bundle,
        deterministic_gate_report=gate_report,
        release_attestation=release,
    )


def test_exact_30_wrapper_projects_full_answers_and_seals_completeness(
    tmp_path: Path,
) -> None:
    bundle, manifest, authorization, workspace, initial, cipher = _contracts(tmp_path)
    answers: dict[str, bytes] = {}

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        return _positive_result(
            request=request,
            case=bundle.registry.case(request.case_id),
            authorization=authorization,
            manifest=manifest,
            answers=answers,
        )

    execution = execute_owner_quality_canary_review(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        answer_loader=answers.__getitem__,
        gap_inventory_by_case={case_id: () for case_id in authorization.authorized_case_ids},
    )

    assert execution.circuit_result.status == "passed"
    package = execution.final_package
    assert package is not None
    assert package.case_ids == authorization.authorized_case_ids
    assert package.projection_receipt_seal_sha256s == (
        execution.circuit_result.projection_receipt_seal_sha256s
    )
    assert package.answer_only is True
    assert package.plaintext_questions_included is False
    assert package.tuning_input_allowed is True
    for case_id in package.case_ids:
        assert (workspace.root / "cases" / case_id / "released-answer.md").is_file()
        assert (workspace.root / "ai-reviews" / f"{case_id}.json").is_file()
        assert (workspace.root / "standards" / f"{case_id}.json").is_file()
        assert (workspace.root / "gaps" / f"{case_id}.json").is_file()

    first_case = package.case_ids[0]
    metrics = workspace.root / "safe-metrics" / f"{first_case}-metrics.json"
    retained = metrics.with_name(f"{first_case}-metrics-retained.json")
    metrics.rename(retained)
    metrics.symlink_to(retained)
    with pytest.raises(ValueError, match="unsafe"):
        finalize_owner_canary_review_package(
            workspace=workspace,
            authorization=authorization,
            manifest=manifest,
            circuit_result=execution.circuit_result,
            receipts=package.projection_receipts,
        )


def test_projection_failure_stops_before_next_case(tmp_path: Path) -> None:
    bundle, manifest, authorization, workspace, initial, cipher = _contracts(tmp_path)
    answers: dict[str, bytes] = {}
    calls: list[str] = []

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        calls.append(request.case_id)
        result = _positive_result(
            request=request,
            case=bundle.registry.case(request.case_id),
            authorization=authorization,
            manifest=manifest,
            answers=answers,
        )
        assert result.answer_artifact_id is not None
        answers[result.answer_artifact_id] += b" changed"
        return result

    adapter = OwnerCanaryProjectionAdapter(
        workspace=workspace,
        authorization=authorization,
        manifest=manifest,
        answer_loader=answers.__getitem__,
        gap_inventory_by_case={case_id: () for case_id in authorization.authorized_case_ids},
    )
    circuit = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        case_projector=adapter.project,
    )

    assert circuit.status == "stopped"
    assert circuit.stop_reason_codes == (
        "case_projection_failure",
        "case_projection_binding_failure",
    )
    assert calls == [authorization.authorized_case_ids[0]]
    assert circuit.completed_case_ids == ()


def test_runtime_frontier_failure_leaves_no_plaintext_answer(tmp_path: Path) -> None:
    bundle, manifest, authorization, workspace, initial, cipher = _contracts(tmp_path)
    answers: dict[str, bytes] = {}

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        return _positive_result(
            request=request,
            case=bundle.registry.case(request.case_id),
            authorization=authorization,
            manifest=manifest,
            answers=answers,
        )

    adapter = OwnerCanaryProjectionAdapter(
        workspace=workspace,
        authorization=authorization,
        manifest=manifest,
        answer_loader=answers.__getitem__,
        gap_inventory_by_case={case_id: () for case_id in authorization.authorized_case_ids},
        pre_readable_commit_callback=lambda _case_id: (_ for _ in ()).throw(
            RuntimeError("owned_runtime_frontier_changed")
        ),
    )
    circuit = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        case_projector=adapter.project,
    )

    first_case = authorization.authorized_case_ids[0]
    assert circuit.status == "stopped"
    assert not (workspace.root / "cases" / first_case / "released-answer.md").exists()


def test_end_reattestation_failure_leaves_all_answers_nonreadable(tmp_path: Path) -> None:
    bundle, manifest, authorization, workspace, initial, cipher = _contracts(tmp_path)
    answers: dict[str, bytes] = {}

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        return _positive_result(
            request=request,
            case=bundle.registry.case(request.case_id),
            authorization=authorization,
            manifest=manifest,
            answers=answers,
        )

    def failed_end_reattestation() -> Never:
        raise RuntimeError("owned_runtime_end_model_manifest_changed")

    with pytest.raises(RuntimeError, match="end_model_manifest_changed"):
        execute_owner_quality_canary_review(
            authorization=authorization,
            manifest=manifest,
            bundle=bundle,
            workspace=workspace,
            cipher=cipher,
            initial_input_revision_sha256_by_case=initial,
            case_callback=callback,
            answer_loader=answers.__getitem__,
            gap_inventory_by_case={case_id: () for case_id in authorization.authorized_case_ids},
            owned_runtime_finalizer=failed_end_reattestation,
        )

    assert not any(workspace.root.glob("cases/*/released-answer.md"))


def test_circuit_revalidates_tampered_model_instances_before_projection(
    tmp_path: Path,
) -> None:
    bundle, manifest, authorization, workspace, initial, cipher = _contracts(tmp_path)
    answers: dict[str, bytes] = {}
    projected: list[str] = []

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        valid = _positive_result(
            request=request,
            case=bundle.registry.case(request.case_id),
            authorization=authorization,
            manifest=manifest,
            answers=answers,
        )
        return valid.model_copy(update={"candidate_build_id": "candidate-substituted"})

    def projector(
        result: OwnerCanaryCaseAttemptResult,
    ) -> OwnerCanaryCaseProjectionReceipt:
        projected.append(result.case_id)
        raise AssertionError("tampered result reached projection")

    circuit = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        case_projector=projector,
    )

    assert circuit.status == "stopped"
    assert circuit.stop_reason_codes == ("worker_hard_failure", "worker_result_invalid")
    assert projected == []


def test_same_semantic_failure_stops_on_second_changed_input(tmp_path: Path) -> None:
    bundle, manifest, authorization, workspace, initial, cipher = _contracts(tmp_path)
    case = bundle.registry.case(authorization.authorized_case_ids[0])
    review, adjudication, standards = _review(
        case,
        _evidence(
            case,
            threshold_policy_sha256=(
                authorization.policy_bindings.relevance_threshold_policy_sha256
            ),
        ),
    )
    calls: list[int] = []

    def callback(request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        calls.append(request.attempt_number)
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
            next_input_revision_sha256=str(6 + request.attempt_number) * 64,
        )

    circuit = run_owner_canary_serial(
        authorization=authorization,
        manifest=manifest,
        bundle=bundle,
        workspace=workspace,
        cipher=cipher,
        initial_input_revision_sha256_by_case=initial,
        case_callback=callback,
        case_projector=lambda _result: pytest.fail("non-release must never project"),
    )

    assert calls == [1, 2]
    assert "repeated_failure_fingerprint" in circuit.stop_reason_codes
    assert authorization.authorized_case_ids[1] not in circuit.completed_case_ids
