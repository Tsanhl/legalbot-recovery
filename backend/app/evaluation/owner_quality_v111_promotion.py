"""Versioned v1.11 owner-quality promotion presentation and atomic entry.

This is deliberately separate from the legacy Live60 production attestation.
A development circuit/package is technical evidence, not deployment authority.
The owner must create a second exact confirmation artifact before this module
will call the atomic candidate-promotion primitive.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..text_metrics import word_count
from ..types import OnlineMode, QuestionRequest, TaskType
from .all60_qualification import (
    ALL60_REPLAY_EXPERT_FILENAME,
    EXACT_ALL60_FILENAME,
    ExactAll60Qualification,
    load_replayed_exact_all60_qualification,
)
from .canary_review_workspace import (
    CanaryReviewWorkspace,
    CanaryReviewWorkspaceManifest,
    ReleasedAnswerProjection,
)
from .live30 import _exclusive_write, assert_safe_evaluation_payload
from .live_suite import load_live_evaluation_bundle, sealed_sha256
from .live_suite_stage_a_v2_runner import STAGE_A_SCORER_IDENTITY_SHA256
from .owner_quality_canary import (
    load_verified_owner_quality_canary_manifest,
)
from .owner_quality_canary_acceptance import (
    OwnerCanaryAcceptanceSummary,
    require_development_owner_acceptance_for_promotion_presentation,
)
from .owner_quality_canary_artifacts import verify_case_projection_receipt
from .owner_quality_canary_authorization import (
    OwnerDecisionRequired,
    OwnerQualityDevelopmentAuthorization,
    load_owner_canary_authorization,
    replay_authorization_completion_preflight,
)
from .owner_quality_canary_circuit import OwnerCanaryCircuitResult, _request
from .owner_quality_canary_projection import (
    AI_PROJECTION_SCHEMA,
    RETRY_PROJECTION_SCHEMA,
    SAFE_METRICS_SCHEMA,
    STANDARDS_PROJECTION_SCHEMA,
    OwnerCanaryFinalReviewPackage,
    OwnerCanaryGapInventory,
    _sealed_projection,
)
from .owner_quality_canary_runtime import (
    OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME,
    OWNER_CANARY_RUNTIME_AUTH_FILENAME,
    OwnerCanaryRuntimeReleaseReport,
    build_owner_canary_runtime_attempt_envelope,
    derive_owner_canary_gap_inventory,
    load_owner_canary_runtime_context,
    load_verified_all60_batch_for_owner_runtime,
    owner_canary_idempotency_key,
    owner_canary_initial_input_revisions,
    validate_owner_canary_api_admission,
)
from .owner_quality_owned_model_runtime import (
    VerifiedEndedOwnerCanaryRuntime,
    load_ended_owner_canary_runtime,
    load_owner_canary_runtime_binding_and_memory_policy,
)
from .sealed_candidate import load_sealed_candidate_identity
from .v111_technical_attestation import (
    FIXED_CHECK_MATRIX_SHA256,
    StageAReplayInputs,
)
from .v111_technical_attestation_admission import (
    load_admitted_v111_technical_attestation,
    require_admitted_v111_technical_attestation,
)

V111_PROMOTION_PRESENTATION_SCHEMA = "legalbot.owner-quality-v111-promotion-presentation.v1"
V111_OWNER_AUTHORIZATION_SCHEMA = "legalbot.owner-quality-v111-promotion-authorization.v1"

_SAFE_RELATIVE = re.compile(r"^data/evaluations/[A-Za-z0-9][A-Za-z0-9._/-]{1,500}$")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class V111PromotionArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    relative_path: str
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("relative_path")
    @classmethod
    def relative_path_is_evaluation_scoped(cls, value: str) -> str:
        if (
            not _SAFE_RELATIVE.fullmatch(value)
            or value.startswith("/")
            or "//" in value
            or any(part in {"", ".", ".."} for part in Path(value).parts)
        ):
            raise ValueError("v1.11 promotion reference is unsafe")
        return value


class OwnerQualityV111PromotionPresentation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-v111-promotion-presentation.v1"] = Field(
        default="legalbot.owner-quality-v111-promotion-presentation.v1", alias="schema"
    )
    presentation_id: str = Field(pattern=r"^promotion:[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    canary_manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    development_authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_final_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_owner_acceptance_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_development_case_count: Literal[30]
    exact_development_case_ids: tuple[str, ...]
    exact_development_answer_sha256s: tuple[str, ...]
    canary_manifest: V111PromotionArtifactRef
    all60_qualification: V111PromotionArtifactRef
    development_authorization: V111PromotionArtifactRef
    development_final_package: V111PromotionArtifactRef
    development_owner_acceptance: V111PromotionArtifactRef
    technical_attestation_admission: V111PromotionArtifactRef
    technical_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    technical_admission_id: str = Field(pattern=r"^v111-technical-admission:[0-9a-f]{64}$")
    technical_admission_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_final_attestation_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_matrix_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_artifact_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_artifact_member_count: Literal[32]
    technical_stage_a_result_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_stage_a_attestation_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_rollback_plan_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    technical_rollback_policy_binding_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scorer_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    legacy_technical_summaries_accepted: Literal[False]
    test_results_passed: Literal[True]
    rollback_plan_ready: Literal[True]
    exact_artifacts_verified: Literal[True]
    owner_decision_required: Literal[True]
    owner_authorization_present: Literal[False]
    authorizes_active: Literal[False]
    writes_active: Literal[False]
    writes_previous: Literal[False]
    created_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def presentation_is_exact_and_sealed(self) -> Self:
        if (
            len(self.exact_development_case_ids) != 30
            or len(set(self.exact_development_case_ids)) != 30
            or len(self.exact_development_answer_sha256s) != 30
            or self.technical_matrix_sha256 != FIXED_CHECK_MATRIX_SHA256
            or self.scorer_identity_sha256 != STAGE_A_SCORER_IDENTITY_SHA256
            or self.technical_attestation_admission.artifact_seal_sha256
            != self.technical_admission_seal_sha256
        ):
            raise ValueError("v1.11 promotion presentation is not exact or technically bound")
        identity = sealed_sha256(
            {
                "candidate_build_id": self.candidate_build_id,
                "candidate_manifest_sha256": self.candidate_manifest_sha256,
                "integration_sha": self.integration_sha,
                "canary_manifest_seal_sha256": self.canary_manifest_seal_sha256,
                "all60_qualification_file_sha256": self.all60_qualification.file_sha256,
                "development_final_package_seal_sha256": (
                    self.development_final_package_seal_sha256
                ),
                "development_owner_acceptance_seal_sha256": (
                    self.development_owner_acceptance_seal_sha256
                ),
                "technical_admission_id": self.technical_admission_id,
                "technical_admission_seal_sha256": self.technical_admission_seal_sha256,
                "technical_attestation_admission_file_sha256": (
                    self.technical_attestation_admission.file_sha256
                ),
                "technical_artifact_set_sha256": self.technical_artifact_set_sha256,
            }
        )
        if self.presentation_id != f"promotion:{identity}":
            raise ValueError("v1.11 promotion presentation identity differs")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("v1.11 promotion presentation seal does not match")
        return self


class OwnerQualityV111PromotionAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-v111-promotion-authorization.v1"] = Field(
        default="legalbot.owner-quality-v111-promotion-authorization.v1", alias="schema"
    )
    authorization_id: str = Field(pattern=r"^owner-promotion:[0-9a-f]{64}$")
    presentation_id: str = Field(pattern=r"^promotion:[0-9a-f]{64}$")
    presentation_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    decision: Literal["AUTHORIZE_ACTIVE"]
    exact_confirmation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    local_owner_confirmation: Literal[True]
    technical_completion_alone_sufficient: Literal[False]
    authorizes_active: Literal[True]
    authorizes_o04: Literal[False]
    authorizes_normal_live: Literal[False]
    one_time: Literal[True]
    authorized_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def authorization_is_exact_and_sealed(self) -> Self:
        expected = "owner-promotion:" + sealed_sha256(
            {
                "presentation_id": self.presentation_id,
                "presentation_seal_sha256": self.presentation_seal_sha256,
                "candidate_build_id": self.candidate_build_id,
                "candidate_manifest_sha256": self.candidate_manifest_sha256,
                "owner_ref": self.owner_ref,
                "exact_confirmation_sha256": self.exact_confirmation_sha256,
            }
        )
        if self.authorization_id != expected:
            raise ValueError("v1.11 owner promotion authorization identity differs")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("v1.11 owner promotion authorization seal does not match")
        return self


def _resolve(project_root: Path, reference: V111PromotionArtifactRef) -> Path:
    root = project_root.resolve()
    path = (root / reference.relative_path).resolve(strict=True)
    if (
        not path.is_relative_to(root)
        or path.is_symlink()
        or not path.is_file()
        or _file_sha256(path) != reference.file_sha256
    ):
        raise ValueError("v1.11 promotion artifact bytes differ")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("seal_sha256") != reference.artifact_seal_sha256:
        raise ValueError("v1.11 promotion artifact seal differs")
    return path


def _ref(project_root: Path, path: Path, *, seal_sha256: str) -> V111PromotionArtifactRef:
    root = project_root.resolve()
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError("v1.11 promotion input is outside the project")
    relative = resolved.relative_to(root).as_posix()
    return V111PromotionArtifactRef(
        relative_path=relative,
        file_sha256=_file_sha256(resolved),
        artifact_seal_sha256=seal_sha256,
    )


def _load_sealed_object(path: Path, *, schema: str) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != schema
        or value.get("seal_sha256") != sealed_sha256(value)
    ):
        raise ValueError(f"{schema} artifact is invalid")
    assert_safe_evaluation_payload(value)
    return value


def _workspace_for_package(
    *, package_path: Path, package: OwnerCanaryFinalReviewPackage
) -> CanaryReviewWorkspace:
    if (
        package_path.name != "final-review-package.json"
        or package_path.parent.name != "safe-metrics"
    ):
        raise ValueError("development package is outside its fixed workspace location")
    root = package_path.parent.parent
    manifest_path = root / "workspace-manifest.json"
    manifest = CanaryReviewWorkspaceManifest.model_validate_json(manifest_path.read_bytes())
    if manifest.seal_sha256 != package.workspace_seal_sha256:
        raise ValueError("development package differs from workspace")
    return CanaryReviewWorkspace(root=root, manifest=manifest)


def _verify_final_package_files(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    expected_lane: Literal["development", "blind_holdout"] = "development",
) -> None:
    if not package.authoritative_owned_runtime or package.synthetic_non_authoritative:
        raise ValueError("owner-quality package contains synthetic or unbound runtime evidence")
    if (
        package.lane != expected_lane
        or package.case_ids != workspace.manifest.expected_case_ids
        or package.candidate_build_id != workspace.manifest.candidate_build_id
        or package.candidate_manifest_sha256 != workspace.manifest.candidate_manifest_sha256
        or package.owned_runtime_start_attestation_sha256 is None
        or package.owned_runtime_end_attestation_sha256 is None
        or package.owned_runtime_instance_sha256 is None
        or package.owned_runtime_memory_policy_sha256 is None
        or package.owned_runtime_checkpoint_set_sha256 is None
    ):
        raise ValueError("v1.11 requires the exact owner-quality final package")
    for receipt in package.projection_receipts:
        case_root = workspace.root / "cases" / receipt.case_id
        answer_path = case_root / "released-answer.md"
        release_path = case_root / "release-attestation.json"
        if (
            answer_path.is_symlink()
            or not answer_path.is_file()
            or _file_sha256(answer_path) != receipt.answer_sha256
            or word_count(answer_path.read_text(encoding="utf-8")) != receipt.word_count
            or release_path.is_symlink()
            or not release_path.is_file()
        ):
            raise ValueError("owner-quality released-answer projection changed")
        release = ReleasedAnswerProjection.model_validate_json(release_path.read_bytes())
        if release.seal_sha256 != receipt.release_projection_seal_sha256:
            raise ValueError("owner-quality release projection changed")
        projections = {
            receipt.evidence_projection_sha256: workspace.root
            / "evidence-citation-maps"
            / f"{receipt.case_id}.json",
            receipt.ai_projection_sha256: workspace.root / "ai-reviews" / f"{receipt.case_id}.json",
            receipt.standards_projection_sha256: workspace.root
            / "standards"
            / f"{receipt.case_id}.json",
            receipt.gap_projection_sha256: workspace.root / "gaps" / f"{receipt.case_id}.json",
            receipt.metrics_projection_sha256: workspace.root
            / "safe-metrics"
            / f"{receipt.case_id}-metrics.json",
            receipt.retry_projection_sha256: workspace.root
            / "retry-trace"
            / f"{receipt.case_id}-projection.json",
        }
        if any(
            path.is_symlink() or not path.is_file() or _file_sha256(path) != digest
            for digest, path in projections.items()
        ):
            raise ValueError("owner-quality machine projection changed")
        runtime_report = OwnerCanaryRuntimeReleaseReport.model_validate_json(
            workspace.read_private_bytes(
                "safe-metrics", f"{receipt.case_id}-runtime-attempt-1.json"
            )
        )
        if (
            not runtime_report.authoritative_db_projection
            or runtime_report.synthetic_non_authoritative
            or runtime_report.run_id != package.run_id
            or runtime_report.case_id != receipt.case_id
            or runtime_report.attempt_number != 1
            or runtime_report.job_id != receipt.job_id
            or runtime_report.answer_version_id != receipt.answer_version_id
            or runtime_report.answer_sha256 != receipt.answer_sha256
            or runtime_report.candidate_build_id != package.candidate_build_id
            or runtime_report.candidate_manifest_sha256 != package.candidate_manifest_sha256
            or runtime_report.owned_runtime_start_attestation_sha256
            != package.owned_runtime_start_attestation_sha256
            or runtime_report.owned_runtime_instance_sha256 != package.owned_runtime_instance_sha256
            or runtime_report.owned_runtime_memory_policy_sha256
            != package.owned_runtime_memory_policy_sha256
        ):
            raise ValueError("owner-quality package contains synthetic or unbound runtime evidence")
    circuit_paths = tuple((workspace.root / "retry-trace").glob("circuit-*-result.json"))
    circuits = tuple(
        OwnerCanaryCircuitResult.model_validate_json(path.read_bytes())
        for path in circuit_paths
        if not path.is_symlink()
    )
    matching = tuple(
        item for item in circuits if item.seal_sha256 == package.circuit_result_seal_sha256
    )
    if (
        len(matching) != 1
        or matching[0].status != "passed"
        or matching[0].completed_case_ids != package.case_ids
        or matching[0].projection_receipt_seal_sha256s != package.projection_receipt_seal_sha256s
    ):
        raise ValueError("owner-quality package lacks its exact passed serial circuit")


def _replay_all60_for_workspace(
    *,
    settings: Settings,
    bundle: Any,
    candidate: Any,
    qualification_path: Path,
    workspace: CanaryReviewWorkspace,
    integration_sha: str,
) -> tuple[ExactAll60Qualification, Any]:
    supplied = ExactAll60Qualification.model_validate_json(qualification_path.read_bytes())
    from .live_suite_gold import load_suite_expert_qualification
    from .live_suite_path_b import load_default_v2_repair

    expert_path = workspace.root / "safe-metrics" / ALL60_REPLAY_EXPERT_FILENAME
    expert = load_suite_expert_qualification(
        expert_path,
        bundle=bundle,
        index_build_id=candidate.build_id,
        as_of_date=supplied.as_of_date,
        catalog_path=settings.database_path,
        repair=load_default_v2_repair(settings.project_root),
    )
    ai_review_batch = load_verified_all60_batch_for_owner_runtime(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        expert=expert,
        qualification=supplied,
        integration_sha=integration_sha,
        evaluation_root=workspace.root / "safe-metrics",
    )
    replayed = load_replayed_exact_all60_qualification(
        qualification_path,
        bundle=bundle,
        candidate=candidate,
        candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
        expert_qualification_path=expert_path,
        ai_review_batch=ai_review_batch,
        catalog_path=settings.database_path,
        project_root=settings.project_root,
        integration_sha=integration_sha,
    )
    if replayed.candidate_manifest_sha256 != candidate.candidate_manifest_sha256:
        raise ValueError("development all-60 replay candidate differs")
    return replayed, expert


def _technical_stage_a_inputs(
    *,
    settings: Settings,
    bundle: Any,
    candidate: Any,
    qualification_path: Path,
    workspace: CanaryReviewWorkspace,
    authorization: OwnerQualityDevelopmentAuthorization,
) -> StageAReplayInputs:
    replayed, expert = _replay_all60_for_workspace(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification_path=qualification_path,
        workspace=workspace,
        integration_sha=authorization.integration_sha,
    )
    return StageAReplayInputs(
        output_root=settings.evaluation_dir / "stage-a-v2",
        run_id=authorization.stage_a_run_id,
        bundle=bundle,
        all60_qualification=replayed,
        expert_qualification=expert,
        as_of_date=replayed.as_of_date,
        completion_preflight_verified_result_sha256=(
            authorization.completion_preflight_verified_result_sha256
        ),
    )


def _verify_reprojected_case_sidecars(
    *,
    workspace: CanaryReviewWorkspace,
    receipt: Any,
    envelope: Any,
    gaps: tuple[Any, ...],
) -> None:
    """Recompute every owner-visible sidecar from the durable attempt envelope."""

    result = envelope.attempt_result
    if any(
        item is None
        for item in (
            result.job_id,
            result.answer_version_id,
            result.answer_artifact_id,
            result.answer_sha256,
            result.word_count,
            result.evidence_bundle,
            result.ai_review,
            result.ai_adjudication,
            result.standards_report,
            result.deterministic_gate_report,
            result.release_attestation,
        )
    ):
        raise ValueError("owner-quality durable attempt lacks positive projection artifacts")
    evidence = result.evidence_bundle
    review = result.ai_review
    adjudication = result.ai_adjudication
    standards = result.standards_report
    gates = result.deterministic_gate_report
    release = result.release_attestation
    verify_case_projection_receipt(
        receipt=receipt,
        workspace_seal_sha256=workspace.manifest.seal_sha256,
        attempt_result_seal_sha256=result.seal_sha256,
        run_id=result.run_id,
        authorization_seal_sha256=result.authorization_seal_sha256,
        canary_manifest_seal_sha256=result.canary_manifest_seal_sha256,
        case_id=result.case_id,
        candidate_build_id=result.candidate_build_id,
        candidate_manifest_sha256=result.candidate_manifest_sha256,
        job_id=str(result.job_id),
        answer_version_id=str(result.answer_version_id),
        answer_artifact_id=str(result.answer_artifact_id),
        answer_sha256=str(result.answer_sha256),
        word_count=int(result.word_count),
        evidence_bundle_seal_sha256=evidence.seal_sha256,
        ai_review_seal_sha256=review.seal_sha256,
        ai_adjudication_seal_sha256=adjudication.seal_sha256,
        standards_report_seal_sha256=standards.seal_sha256,
        deterministic_gate_report_seal_sha256=gates.seal_sha256,
        release_attestation_seal_sha256=release.seal_sha256,
    )
    raw = workspace.read_private_bytes("cases", result.case_id, "released-answer.md")
    release_gate_inputs = {
        **gates.gates,
        "ai_evidence_review": True,
        "applicable_standards": True,
    }
    release_material: dict[str, Any] = {
        "schema": "legalbot.canary-released-answer-projection.v1",
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "case_id": result.case_id,
        "lane": workspace.manifest.lane,
        "answer_sha256": hashlib.sha256(raw).hexdigest(),
        "word_count": word_count(raw.decode("utf-8")),
        "release_gates": dict(sorted(release_gate_inputs.items())),
        "all_required_release_gates_passed": True,
    }
    release_material["seal_sha256"] = sealed_sha256(release_material)
    expected_release = ReleasedAnswerProjection.model_validate(release_material)
    observed_release = ReleasedAnswerProjection.model_validate_json(
        workspace.read_private_bytes("cases", result.case_id, "release-attestation.json")
    )
    expected_gap_material: dict[str, Any] = {
        "schema": "legalbot.owner-canary-gap-inventory.v1",
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "run_id": result.run_id,
        "authorization_seal_sha256": result.authorization_seal_sha256,
        "canary_manifest_seal_sha256": result.canary_manifest_seal_sha256,
        "case_id": result.case_id,
        "candidate_build_id": result.candidate_build_id,
        "candidate_manifest_sha256": result.candidate_manifest_sha256,
        "gap_count": len(gaps),
        "gaps": [item.model_dump(mode="json") for item in gaps],
        "detailed_content_retained": False,
    }
    expected_gap_material["seal_sha256"] = sealed_sha256(expected_gap_material)
    expected_gap = OwnerCanaryGapInventory.model_validate(expected_gap_material)
    traces = tuple(review.invocation_traces)
    trace_seals = tuple(item.seal_sha256 for item in traces)
    raw_input_tokens = tuple(item.input_token_count for item in traces)
    raw_output_tokens = tuple(item.output_token_count for item in traces)
    expected_values = {
        ("evidence-citation-maps", f"{result.case_id}.json"): evidence.model_dump(
            mode="json", by_alias=True
        ),
        ("ai-reviews", f"{result.case_id}.json"): _sealed_projection(
            AI_PROJECTION_SCHEMA,
            {
                "workspace_seal_sha256": workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "review": review.model_dump(mode="json", by_alias=True),
                "adjudication": adjudication.model_dump(mode="json", by_alias=True),
            },
        ),
        ("standards", f"{result.case_id}.json"): _sealed_projection(
            STANDARDS_PROJECTION_SCHEMA,
            {
                "workspace_seal_sha256": workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "report": standards.model_dump(mode="json", by_alias=True),
            },
        ),
        ("gaps", f"{result.case_id}.json"): expected_gap.model_dump(mode="json", by_alias=True),
        ("safe-metrics", f"{result.case_id}-metrics.json"): _sealed_projection(
            SAFE_METRICS_SCHEMA,
            {
                "workspace_seal_sha256": workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "attempt_number": result.attempt_number,
                "answer_byte_count": len(raw),
                "word_count": int(result.word_count),
                "evidence_span_count": len(evidence.evidence_span_ids),
                "material_claim_count": review.material_claim_count,
                "applicable_standard_count": len(standards.scores),
                "reviewer_invocation_count": len(traces),
                "reviewer_invocation_trace_seal_sha256s": list(trace_seals),
                "reviewer_total_duration_ms": sum(item.duration_ms for item in traces),
                "reviewer_total_input_tokens": sum(
                    int(value) for value in raw_input_tokens if value is not None
                ),
                "reviewer_total_output_tokens": sum(
                    int(value) for value in raw_output_tokens if value is not None
                ),
                "reviewer_token_counts_complete": all(
                    value is not None for value in (*raw_input_tokens, *raw_output_tokens)
                ),
            },
        ),
        ("retry-trace", f"{result.case_id}-projection.json"): _sealed_projection(
            RETRY_PROJECTION_SCHEMA,
            {
                "workspace_seal_sha256": workspace.manifest.seal_sha256,
                "case_id": result.case_id,
                "attempt_number": result.attempt_number,
                "input_revision_sha256": result.input_revision_sha256,
                "attempt_result_seal_sha256": result.seal_sha256,
                "failure_reason_codes": list(result.failure_reason_codes),
                "deterministic_hard_failure_codes": list(result.deterministic_hard_failure_codes),
                "worker_hard_failure": result.worker_hard_failure,
                "next_input_revision_sha256": result.next_input_revision_sha256,
            },
        ),
    }
    if expected_release != observed_release:
        raise ValueError("owner-quality release sidecar differs from durable projection")
    for (category, filename), expected in expected_values.items():
        observed = json.loads(workspace.read_private_bytes(category, filename))
        if observed != expected:
            raise ValueError("owner-quality review sidecar differs from durable projection")
    persisted_receipt = type(receipt).model_validate_json(
        workspace.read_private_bytes("safe-metrics", f"{result.case_id}-projection-receipt.json")
    )
    if persisted_receipt != receipt:
        raise ValueError("owner-quality persisted projection receipt differs")


def _verify_db_backed_development_package(
    *,
    settings: Settings,
    database: Database,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    expected_lane: Literal["development", "blind_holdout"] = "development",
) -> None:
    """Re-project all 30 receipts from the local encrypted database."""

    if package.lane != expected_lane:
        raise ValueError("owner-quality DB projection lane differs")

    context = load_owner_canary_runtime_context(
        settings=settings,
        database=database,
        review_date=workspace.manifest.review_date,
        run_id=package.run_id,
        lane=expected_lane,
    )
    if (
        context.authorization.seal_sha256 != package.authorization_seal_sha256
        or context.manifest.seal_sha256 != package.canary_manifest_seal_sha256
        or context.authorization.authorized_case_ids != package.case_ids
    ):
        raise ValueError("development package differs from its DB replay context")
    qualification = ExactAll60Qualification.model_validate_json(
        workspace.read_private_bytes(EXACT_ALL60_FILENAME)
    )
    gap_inventory = derive_owner_canary_gap_inventory(
        database=database,
        authorization=context.authorization,
        bundle=context.bundle,
        qualification=qualification,
    )
    cipher = LocalCipher.from_local_key(create=False)
    revisions = owner_canary_initial_input_revisions(
        authorization=context.authorization,
        manifest=context.manifest,
    )
    runtime_binding, memory_policy = load_owner_canary_runtime_binding_and_memory_policy(
        settings=settings,
        candidate=context.candidate,
        integration_sha=context.authorization.integration_sha,
    )
    ended_runtime: VerifiedEndedOwnerCanaryRuntime = load_ended_owner_canary_runtime(
        settings=settings,
        workspace_root=workspace.root,
        candidate=context.candidate,
        authorization_seal_sha256=context.authorization.seal_sha256,
        canary_manifest_seal_sha256=context.manifest.seal_sha256,
        workspace_seal_sha256=context.workspace_manifest.seal_sha256,
        runtime_binding=runtime_binding,
        memory_policy=memory_policy,
        completion_preflight_result_sha256=(
            context.authorization.completion_preflight_verified_result_sha256
        ),
        expected_case_ids=context.authorization.authorized_case_ids,
        database=database,
    )
    if (
        package.owned_runtime_start_attestation_sha256 != ended_runtime.start.seal_sha256
        or package.owned_runtime_end_attestation_sha256 != ended_runtime.end.seal_sha256
        or package.owned_runtime_instance_sha256 != ended_runtime.start.runtime_instance_sha256
        or package.owned_runtime_memory_policy_sha256 != ended_runtime.start.memory_policy_sha256
        or package.owned_runtime_checkpoint_set_sha256 != ended_runtime.end.checkpoint_set_sha256
    ):
        raise ValueError("owner-quality package differs from its ended owned runtime")
    before_by_case = {
        item.case_id: item for item in ended_runtime.checkpoints if item.phase == "before_case"
    }
    for ordinal, receipt in enumerate(package.projection_receipts, start=1):
        case = context.bundle.registry.case(receipt.case_id)
        request = _request(
            authorization=context.authorization,
            manifest=context.manifest,
            case_id=receipt.case_id,
            sequence_number=ordinal,
            attempt_number=1,
            word_target=case.word_target,
            input_revision_sha256=revisions[receipt.case_id],
        )
        payload = QuestionRequest(
            question=case.question,
            task_type=TaskType(case.task_type),
            jurisdiction=case.jurisdiction,
            as_of_date=context.as_of_date,
            word_target=case.word_target,
            online_mode=OnlineMode.LOCAL_ONLY,
            upload_ids=[],
        )
        binding = validate_owner_canary_api_admission(
            settings=settings,
            database=database,
            review_date=workspace.manifest.review_date,
            lane=expected_lane,
            run_id=package.run_id,
            case_id=receipt.case_id,
            attempt_number=1,
            input_revision_sha256=request.input_revision_sha256,
            attempt_request_seal_sha256=request.seal_sha256,
            raw_idempotency_key=owner_canary_idempotency_key(request.seal_sha256),
            payload=payload,
            _context=context,
            historical_ended_runtime=True,
            _ended_runtime_capability=ended_runtime,
        )
        envelope = build_owner_canary_runtime_attempt_envelope(
            settings=settings,
            database=database,
            cipher=cipher,
            binding=binding,
            answer_id=receipt.answer_version_id,
        )
        persisted_report = OwnerCanaryRuntimeReleaseReport.model_validate_json(
            workspace.read_private_bytes(
                "safe-metrics", f"{receipt.case_id}-runtime-attempt-1.json"
            )
        )
        if (
            envelope.runtime_report != persisted_report
            or envelope.attempt_result.seal_sha256 != receipt.attempt_result_seal_sha256
            or envelope.attempt_result.job_id != receipt.job_id
            or envelope.attempt_result.answer_version_id != receipt.answer_version_id
            or persisted_report.owned_runtime_before_checkpoint_sha256
            != before_by_case[receipt.case_id].seal_sha256
            or persisted_report.owned_runtime_frontier_generation
            != before_by_case[receipt.case_id].frontier_generation
        ):
            raise ValueError("owner-quality package differs from local DB projection")
        _verify_reprojected_case_sidecars(
            workspace=workspace,
            receipt=receipt,
            envelope=envelope,
            gaps=gap_inventory[receipt.case_id],
        )


def _clean_integration_sha(project_root: Path) -> str:
    from ..retrieval.retrieval_reattest import _clean_integration_sha as clean_sha

    return clean_sha(project_root)


def prepare_owner_quality_v111_promotion_presentation(
    *,
    settings: Settings,
    database: Database,
    canary_manifest_path: Path,
    all60_qualification_path: Path,
    development_authorization_path: Path,
    development_final_package_path: Path,
    development_owner_acceptance_path: Path,
    technical_attestation_admission_path: Path,
    destination: Path,
    created_at: datetime,
) -> OwnerQualityV111PromotionPresentation:
    """Verify exact dev30 evidence and write a non-authorizing presentation."""

    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("v1.11 promotion presentation timestamp must be timezone-aware")
    project_root = settings.project_root.resolve()
    manifest_hint = _load_sealed_object(
        canary_manifest_path, schema="legalbot.owner-quality-canary-manifest.v1"
    )
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    candidate = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=str(manifest_hint.get("candidate_build_id") or ""),
    )
    manifest = load_verified_owner_quality_canary_manifest(
        canary_manifest_path,
        bundle=bundle,
        candidate=candidate,
        qualification_path=all60_qualification_path,
    )
    authorization = load_owner_canary_authorization(
        development_authorization_path, manifest=manifest
    )
    if not isinstance(authorization, OwnerQualityDevelopmentAuthorization):
        raise ValueError("v1.11 promotion presentation requires development authorization")
    package = OwnerCanaryFinalReviewPackage.model_validate_json(
        development_final_package_path.read_bytes()
    )
    acceptance = OwnerCanaryAcceptanceSummary.model_validate_json(
        development_owner_acceptance_path.read_bytes()
    )
    workspace = _workspace_for_package(
        package_path=development_final_package_path.resolve(strict=True), package=package
    )
    replay_authorization_completion_preflight(
        settings=settings,
        authorization=authorization,
        candidate=candidate,
        run_dir=(
            workspace.root
            / "safe-metrics"
            / OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME
            / Path(authorization.completion_preflight_artifact_ref).name
        ),
    )
    _verify_final_package_files(workspace=workspace, package=package)
    technical_stage_a = _technical_stage_a_inputs(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification_path=all60_qualification_path,
        workspace=workspace,
        authorization=authorization,
    )
    if workspace.read_private_bytes(OWNER_CANARY_RUNTIME_AUTH_FILENAME) != (
        development_authorization_path.read_bytes()
    ):
        raise ValueError("development authorization differs from fixed runtime workspace")
    _verify_db_backed_development_package(
        settings=settings,
        database=database,
        workspace=workspace,
        package=package,
    )
    verified_acceptance = require_development_owner_acceptance_for_promotion_presentation(
        workspace=workspace, package=package
    )
    if verified_acceptance.seal_sha256 != acceptance.seal_sha256:
        raise ValueError("development owner acceptance differs from current chain head")
    integration_sha = _clean_integration_sha(project_root)
    technical_admission = load_admitted_v111_technical_attestation(
        technical_attestation_admission_path,
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=technical_stage_a,
        expected_integration_sha=integration_sha,
        phase="prepromotion",
    )
    technical_receipt = dict(
        require_admitted_v111_technical_attestation(technical_admission).receipt
    )
    if (
        candidate.candidate_manifest_sha256 != manifest.candidate_manifest_sha256
        or authorization.integration_sha != integration_sha
        or authorization.seal_sha256 != package.authorization_seal_sha256
        or manifest.seal_sha256 != package.canary_manifest_seal_sha256
        or package.run_id != authorization.run_id
        or package.case_ids != manifest.development_case_ids
        or package.candidate_build_id != candidate.build_id
        or package.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        or technical_receipt.get("candidate_build_id") != candidate.build_id
        or technical_receipt.get("candidate_manifest_sha256") != candidate.candidate_manifest_sha256
        or technical_receipt.get("integration_sha") != integration_sha
        or technical_receipt.get("matrix_sha256") != FIXED_CHECK_MATRIX_SHA256
        or technical_receipt.get("scorer_identity_sha256") != STAGE_A_SCORER_IDENTITY_SHA256
        or technical_receipt.get("stage_a_result_seal_sha256") != authorization.stage_a_seal_sha256
        or technical_receipt.get("completion_preflight_verified_result_sha256")
        != authorization.completion_preflight_verified_result_sha256
        or technical_receipt.get("legacy_favorable_summaries_accepted") is not False
    ):
        raise ValueError("v1.11 promotion presentation inputs are not exact and passing")
    refs = {
        "canary_manifest": _ref(
            project_root, canary_manifest_path, seal_sha256=manifest.seal_sha256
        ),
        "all60_qualification": _ref(
            project_root,
            all60_qualification_path,
            seal_sha256=manifest.qualification_seal_sha256,
        ),
        "development_authorization": _ref(
            project_root, development_authorization_path, seal_sha256=authorization.seal_sha256
        ),
        "development_final_package": _ref(
            project_root, development_final_package_path, seal_sha256=package.seal_sha256
        ),
        "development_owner_acceptance": _ref(
            project_root, development_owner_acceptance_path, seal_sha256=acceptance.seal_sha256
        ),
        "technical_attestation_admission": _ref(
            project_root,
            technical_admission.receipt_path,
            seal_sha256=technical_admission.seal_sha256,
        ),
    }
    identity = sealed_sha256(
        {
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "integration_sha": integration_sha,
            "canary_manifest_seal_sha256": manifest.seal_sha256,
            "all60_qualification_file_sha256": refs["all60_qualification"].file_sha256,
            "development_final_package_seal_sha256": package.seal_sha256,
            "development_owner_acceptance_seal_sha256": acceptance.seal_sha256,
            "technical_admission_id": technical_admission.admission_id,
            "technical_admission_seal_sha256": technical_admission.seal_sha256,
            "technical_attestation_admission_file_sha256": refs[
                "technical_attestation_admission"
            ].file_sha256,
            "technical_artifact_set_sha256": technical_receipt["artifact_set_sha256"],
        }
    )
    material: dict[str, Any] = {
        "schema": V111_PROMOTION_PRESENTATION_SCHEMA,
        "presentation_id": f"promotion:{identity}",
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "integration_sha": integration_sha,
        "canary_manifest_id": manifest.manifest_id,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "development_run_id": authorization.run_id,
        "development_authorization_seal_sha256": authorization.seal_sha256,
        "development_final_package_seal_sha256": package.seal_sha256,
        "development_owner_acceptance_seal_sha256": acceptance.seal_sha256,
        "exact_development_case_count": 30,
        "exact_development_case_ids": list(package.case_ids),
        "exact_development_answer_sha256s": list(package.answer_sha256s),
        **{key: value.model_dump(mode="json") for key, value in refs.items()},
        "technical_run_id": technical_admission.run_id,
        "technical_admission_id": technical_admission.admission_id,
        "technical_admission_seal_sha256": technical_admission.seal_sha256,
        "technical_final_attestation_seal_sha256": technical_receipt[
            "final_attestation_seal_sha256"
        ],
        "technical_matrix_sha256": technical_receipt["matrix_sha256"],
        "technical_artifact_set_sha256": technical_receipt["artifact_set_sha256"],
        "technical_artifact_member_count": technical_receipt["artifact_member_count"],
        "technical_stage_a_result_seal_sha256": technical_receipt["stage_a_result_seal_sha256"],
        "technical_stage_a_attestation_seal_sha256": technical_receipt[
            "stage_a_attestation_seal_sha256"
        ],
        "technical_rollback_plan_seal_sha256": technical_receipt["rollback_plan_seal_sha256"],
        "technical_rollback_policy_binding_seal_sha256": technical_receipt[
            "rollback_policy_binding"
        ]["seal_sha256"],
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "legacy_technical_summaries_accepted": False,
        "test_results_passed": True,
        "rollback_plan_ready": True,
        "exact_artifacts_verified": True,
        "owner_decision_required": True,
        "owner_authorization_present": False,
        "authorizes_active": False,
        "writes_active": False,
        "writes_previous": False,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    material["seal_sha256"] = sealed_sha256(material)
    presentation = OwnerQualityV111PromotionPresentation.model_validate(material)
    assert_safe_evaluation_payload(material)
    _exclusive_write(
        destination,
        (json.dumps(material, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
    )
    destination.chmod(0o600)
    return presentation


def expected_owner_promotion_confirmation(
    presentation: OwnerQualityV111PromotionPresentation,
) -> str:
    return (
        f"AUTHORIZE-ACTIVE {presentation.candidate_build_id} "
        f"{presentation.presentation_id} {presentation.seal_sha256}"
    )


def write_owner_quality_v111_promotion_authorization(
    *,
    presentation_path: Path,
    destination: Path,
    owner_ref: str,
    exact_confirmation: str,
    authorized_at: datetime,
) -> OwnerQualityV111PromotionAuthorization:
    """Refuse self-sealed promotion intent until a trusted signature policy exists.

    A typed phrase and a locally recomputed JSON seal prove neither owner
    possession nor owner presence.  Keeping this historical constructor closed
    prevents a caller from upgrading a self-authored file into ACTIVE authority.
    """

    del presentation_path, destination, owner_ref, exact_confirmation, authorized_at
    raise OwnerDecisionRequired("trusted_owner_promotion_signature_policy_missing")


def require_v111_service_authorization(
    *,
    build_id: str,
    presentation: Any,
    owner_authorization: Any,
) -> tuple[OwnerQualityV111PromotionPresentation, OwnerQualityV111PromotionAuthorization]:
    presented = (
        presentation
        if isinstance(presentation, OwnerQualityV111PromotionPresentation)
        else OwnerQualityV111PromotionPresentation.model_validate(presentation)
    )
    owner = (
        owner_authorization
        if isinstance(owner_authorization, OwnerQualityV111PromotionAuthorization)
        else OwnerQualityV111PromotionAuthorization.model_validate(owner_authorization)
    )
    if (
        presented.candidate_build_id != build_id
        or owner.candidate_build_id != build_id
        or owner.candidate_manifest_sha256 != presented.candidate_manifest_sha256
        or owner.presentation_id != presented.presentation_id
        or owner.presentation_seal_sha256 != presented.seal_sha256
        or owner.exact_confirmation_sha256
        != hashlib.sha256(expected_owner_promotion_confirmation(presented).encode()).hexdigest()
    ):
        raise ValueError("v1.11 promotion owner authorization differs from presentation")
    return presented, owner


def verify_v111_promotion_for_service(
    *,
    settings: Settings,
    database: Database,
    build_id: str,
    presentation: Any,
    owner_authorization: Any,
) -> tuple[OwnerQualityV111PromotionPresentation, OwnerQualityV111PromotionAuthorization]:
    """Service boundary: reverify exact bytes, not merely self-sealed models."""

    presented, owner = require_v111_service_authorization(
        build_id=build_id,
        presentation=presentation,
        owner_authorization=owner_authorization,
    )
    _verify_presentation_at_promotion(
        settings=settings,
        database=database,
        presentation=presented,
    )
    raise OwnerDecisionRequired("trusted_owner_promotion_signature_policy_missing")


def _verify_presentation_at_promotion(
    *,
    settings: Settings,
    database: Database,
    presentation: OwnerQualityV111PromotionPresentation,
) -> None:
    project_root = settings.project_root.resolve()
    paths = {
        field: _resolve(project_root, getattr(presentation, field))
        for field in (
            "canary_manifest",
            "all60_qualification",
            "development_authorization",
            "development_final_package",
            "development_owner_acceptance",
            "technical_attestation_admission",
        )
    }
    candidate = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=presentation.candidate_build_id,
    )
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    manifest = load_verified_owner_quality_canary_manifest(
        paths["canary_manifest"],
        bundle=bundle,
        candidate=candidate,
        qualification_path=paths["all60_qualification"],
    )
    authorization = load_owner_canary_authorization(
        paths["development_authorization"], manifest=manifest
    )
    if not isinstance(authorization, OwnerQualityDevelopmentAuthorization):
        raise ValueError("v1.11 promotion replay requires development authorization")
    package = OwnerCanaryFinalReviewPackage.model_validate_json(
        paths["development_final_package"].read_bytes()
    )
    acceptance = OwnerCanaryAcceptanceSummary.model_validate_json(
        paths["development_owner_acceptance"].read_bytes()
    )
    workspace = _workspace_for_package(
        package_path=paths["development_final_package"], package=package
    )
    replay_authorization_completion_preflight(
        settings=settings,
        authorization=authorization,
        candidate=candidate,
        run_dir=(
            workspace.root
            / "safe-metrics"
            / OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME
            / Path(authorization.completion_preflight_artifact_ref).name
        ),
    )
    _verify_final_package_files(workspace=workspace, package=package)
    technical_stage_a = _technical_stage_a_inputs(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification_path=paths["all60_qualification"],
        workspace=workspace,
        authorization=authorization,
    )
    if (
        workspace.read_private_bytes(OWNER_CANARY_RUNTIME_AUTH_FILENAME)
        != paths["development_authorization"].read_bytes()
    ):
        raise ValueError("development authorization differs from fixed runtime workspace")
    _verify_db_backed_development_package(
        settings=settings,
        database=database,
        workspace=workspace,
        package=package,
    )
    verified = require_development_owner_acceptance_for_promotion_presentation(
        workspace=workspace, package=package
    )
    technical_admission = load_admitted_v111_technical_attestation(
        paths["technical_attestation_admission"],
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=technical_stage_a,
        expected_integration_sha=presentation.integration_sha,
        phase="prepromotion",
    )
    technical_receipt = dict(technical_admission.receipt)
    if (
        not isinstance(authorization, OwnerQualityDevelopmentAuthorization)
        or _clean_integration_sha(project_root) != presentation.integration_sha
        or candidate.build_id != presentation.candidate_build_id
        or manifest.seal_sha256 != presentation.canary_manifest_seal_sha256
        or manifest.manifest_id != presentation.canary_manifest_id
        or manifest.candidate_build_id != presentation.candidate_build_id
        or manifest.candidate_manifest_sha256 != presentation.candidate_manifest_sha256
        or authorization.seal_sha256 != presentation.development_authorization_seal_sha256
        or authorization.run_id != presentation.development_run_id
        or authorization.integration_sha != presentation.integration_sha
        or authorization.candidate_build_id != presentation.candidate_build_id
        or authorization.candidate_manifest_sha256 != presentation.candidate_manifest_sha256
        or package.seal_sha256 != presentation.development_final_package_seal_sha256
        or package.run_id != presentation.development_run_id
        or package.authorization_seal_sha256 != presentation.development_authorization_seal_sha256
        or package.canary_manifest_seal_sha256 != presentation.canary_manifest_seal_sha256
        or package.candidate_build_id != presentation.candidate_build_id
        or package.candidate_manifest_sha256 != presentation.candidate_manifest_sha256
        or verified.seal_sha256 != acceptance.seal_sha256
        or acceptance.seal_sha256 != presentation.development_owner_acceptance_seal_sha256
        or candidate.candidate_manifest_sha256 != presentation.candidate_manifest_sha256
        or package.case_ids != presentation.exact_development_case_ids
        or package.answer_sha256s != presentation.exact_development_answer_sha256s
        or technical_admission.admission_id != presentation.technical_admission_id
        or technical_admission.seal_sha256 != presentation.technical_admission_seal_sha256
        or technical_admission.run_id != presentation.technical_run_id
        or technical_receipt.get("final_attestation_seal_sha256")
        != presentation.technical_final_attestation_seal_sha256
        or technical_receipt.get("matrix_sha256") != presentation.technical_matrix_sha256
        or technical_receipt.get("artifact_set_sha256")
        != presentation.technical_artifact_set_sha256
        or technical_receipt.get("artifact_member_count")
        != presentation.technical_artifact_member_count
        or technical_receipt.get("stage_a_result_seal_sha256")
        != presentation.technical_stage_a_result_seal_sha256
        or technical_receipt.get("stage_a_result_seal_sha256") != authorization.stage_a_seal_sha256
        or technical_receipt.get("stage_a_attestation_seal_sha256")
        != presentation.technical_stage_a_attestation_seal_sha256
        or technical_receipt.get("rollback_plan_seal_sha256")
        != presentation.technical_rollback_plan_seal_sha256
        or technical_receipt.get("rollback_policy_binding", {}).get("seal_sha256")
        != presentation.technical_rollback_policy_binding_seal_sha256
        or technical_receipt.get("scorer_identity_sha256") != presentation.scorer_identity_sha256
        or presentation.legacy_technical_summaries_accepted is not False
    ):
        raise ValueError("v1.11 promotion presentation became stale or inconsistent")


def promote_candidate_index_v111(
    *,
    settings: Settings,
    database: Database,
    presentation_path: Path,
    owner_authorization_path: Path,
) -> dict[str, str]:
    """Only v1.11 ACTIVE entry: reverify evidence, then atomically promote."""

    presentation = OwnerQualityV111PromotionPresentation.model_validate_json(
        presentation_path.read_bytes()
    )
    owner = OwnerQualityV111PromotionAuthorization.model_validate_json(
        owner_authorization_path.read_bytes()
    )
    from ..retrieval.service import promote_candidate_index

    return promote_candidate_index(
        settings,
        database,
        presentation.candidate_build_id,
        v111_promotion_presentation=presentation,
        v111_owner_authorization=owner,
    )
