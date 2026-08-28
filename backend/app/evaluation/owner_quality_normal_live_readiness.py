"""Fail-closed v1.11 normal-live readiness over exact owner-quality artifacts.

The legacy production-readiness report remains useful for pre-holdout technical
and operational work, but it is not a v1.11 normal-live decision.  This module
loads one fixed local pointer and a versioned contract that must bind the exact
development and blind-holdout runs, their 30/30 owner acceptance summaries,
promotion, operations, and O-04.  It never creates any of those artifacts.

Owner-signature booleans and self-seals are not trusted signatures.  Until an
owner-approved cryptographic verifier is implemented, even an otherwise exact
contract remains blocked at ``trusted_owner_o04_signature_verifier_missing``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from ..db import Database
from .all60_qualification import ExactAll60Qualification
from .canary_review_workspace import CanaryReviewWorkspace, CanaryReviewWorkspaceManifest
from .live_suite import LiveEvaluationBundle, load_live_evaluation_bundle, sealed_sha256
from .live_suite_stage_a_v2_runner import STAGE_A_SCORER_IDENTITY_SHA256
from .owner_quality_canary import (
    OwnerQualityCanaryManifest,
    load_verified_owner_quality_canary_manifest,
    owner_quality_manifest_bytes,
)
from .owner_quality_canary_acceptance import (
    OWNER_CANARY_ACCEPTANCE_FILENAME,
    OwnerCanaryAcceptanceSummary,
    require_development_owner_acceptance_for_promotion_presentation,
    require_holdout_owner_acceptance_for_normal_live_readiness,
)
from .owner_quality_canary_authorization import (
    DEVELOPMENT_AUTHORIZATION_SCHEMA,
    HOLDOUT_AUTHORIZATION_SCHEMA,
    OwnerCanaryOperationalProof,
    OwnerDecisionRequired,
    OwnerQualityDevelopmentAuthorization,
    OwnerQualityHoldoutAuthorization,
    OwnerQualityO04Approval,
    PromotedActiveCandidateProof,
    replay_authorization_completion_preflight,
    verify_authorization_manifest,
)
from .owner_quality_canary_projection import OwnerCanaryFinalReviewPackage
from .owner_quality_canary_runtime import OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME
from .sealed_candidate import SealedCandidateIdentity, load_sealed_candidate_identity
from .secure_artifact_io import open_private_file_at, read_private_file_at
from .v111_technical_attestation import FIXED_CHECK_MATRIX_SHA256

OWNER_QUALITY_NORMAL_LIVE_POINTER_SCHEMA = "legalbot.owner-quality-normal-live-readiness-pointer.v1"
OWNER_QUALITY_NORMAL_LIVE_CONTRACT_SCHEMA = (
    "legalbot.owner-quality-normal-live-readiness-contract.v1"
)
OWNER_QUALITY_NORMAL_LIVE_STATUS_SCHEMA = "legalbot.owner-quality-normal-live-status.v1"
OWNER_QUALITY_NORMAL_LIVE_RELEASE_AUTHORITY_SCHEMA = (
    "legalbot.owner-quality-normal-live-release-authority.v1"
)
OWNER_QUALITY_NORMAL_LIVE_POINTER = Path("data/evaluations/canary-output-review/NORMAL-LIVE.json")
NORMAL_LIVE_CONTENT_CERTIFICATION_STOP = "normal_live_release_content_certification_missing"

_SAFE_RELATIVE_PATH = re.compile(r"^data/evaluations/[A-Za-z0-9][A-Za-z0-9._/-]{1,500}$")


class OwnerQualityReadinessArtifactRef(BaseModel):
    """One immutable, project-relative evaluation artifact reference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    relative_path: str
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("relative_path")
    @classmethod
    def path_is_safe_and_evaluation_scoped(cls, value: str) -> str:
        if (
            not _SAFE_RELATIVE_PATH.fullmatch(value)
            or value.startswith("/")
            or "//" in value
            or any(part in {"", ".", ".."} for part in Path(value).parts)
        ):
            raise ValueError("owner-quality readiness artifact path is unsafe")
        return value


class OwnerQualityReadinessEvidenceRef(BaseModel):
    """One private immutable operations-evidence file, identified by exact bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    relative_path: str
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("relative_path")
    @classmethod
    def path_is_safe_and_evaluation_scoped(cls, value: str) -> str:
        return OwnerQualityReadinessArtifactRef.path_is_safe_and_evaluation_scoped(value)


class OwnerQualityNormalLiveReadinessContract(BaseModel):
    """Exact artifact graph required before v1.11 normal-live can be considered."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-normal-live-readiness-contract.v1"] = Field(
        default="legalbot.owner-quality-normal-live-readiness-contract.v1",
        alias="schema",
    )
    profile: Literal["legalbot-v1.11-owner-only-normal-live"]
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    development_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    blind_holdout_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    integration_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    all60_qualification: OwnerQualityReadinessArtifactRef
    canary_manifest: OwnerQualityReadinessArtifactRef
    development_authorization: OwnerQualityReadinessArtifactRef
    development_final_package: OwnerQualityReadinessArtifactRef
    development_owner_acceptance: OwnerQualityReadinessArtifactRef
    promotion_presentation: OwnerQualityReadinessArtifactRef
    technical_attestation_admission: OwnerQualityReadinessArtifactRef
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
    promoted_active_proof: OwnerQualityReadinessArtifactRef
    operational_proof: OwnerQualityReadinessArtifactRef
    owner_only_smoke_evidence: OwnerQualityReadinessEvidenceRef
    rollback_repromotion_evidence: OwnerQualityReadinessEvidenceRef
    browser_recovery_evidence: OwnerQualityReadinessEvidenceRef
    technical_readiness_evidence: OwnerQualityReadinessEvidenceRef
    disk_heartbeat_lease_evidence: OwnerQualityReadinessEvidenceRef
    model_identity_evidence: OwnerQualityReadinessEvidenceRef
    owner_o04: OwnerQualityReadinessArtifactRef
    blind_holdout_authorization: OwnerQualityReadinessArtifactRef
    blind_holdout_final_package: OwnerQualityReadinessArtifactRef
    blind_holdout_owner_acceptance: OwnerQualityReadinessArtifactRef
    exact_development_case_count: Literal[30]
    exact_blind_holdout_case_count: Literal[30]
    one_blind_serial_pass: Literal[True]
    owner_acceptance_required_for_every_answer: Literal[True]
    trusted_owner_signature_required: Literal[True]
    owner_signature_self_claim_sufficient: Literal[False]
    legacy_readiness_sufficient: Literal[False]
    local_only: Literal[True]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    writes_active: Literal[False]
    writes_previous: Literal[False]
    writes_o04: Literal[False]
    authorizes_normal_live: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def contract_is_distinct_exact_and_sealed(self) -> Self:
        references = (
            self.all60_qualification,
            self.canary_manifest,
            self.development_authorization,
            self.development_final_package,
            self.development_owner_acceptance,
            self.promotion_presentation,
            self.technical_attestation_admission,
            self.promoted_active_proof,
            self.operational_proof,
            self.owner_o04,
            self.blind_holdout_authorization,
            self.blind_holdout_final_package,
            self.blind_holdout_owner_acceptance,
        )
        evidence = (
            self.owner_only_smoke_evidence,
            self.rollback_repromotion_evidence,
            self.browser_recovery_evidence,
            self.technical_readiness_evidence,
            self.disk_heartbeat_lease_evidence,
            self.model_identity_evidence,
        )
        paths = tuple(item.relative_path for item in (*references, *evidence))
        if len(paths) != len(set(paths)):
            raise ValueError("owner-quality readiness contract reuses an artifact path")
        if self.development_run_id == self.blind_holdout_run_id:
            raise ValueError("development and blind holdout must use different run identities")
        if (
            self.technical_attestation_admission.artifact_seal_sha256
            != self.technical_admission_seal_sha256
            or self.technical_matrix_sha256 != FIXED_CHECK_MATRIX_SHA256
            or self.scorer_identity_sha256 != STAGE_A_SCORER_IDENTITY_SHA256
        ):
            raise ValueError("technical admission reference and contract seal differ")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-quality normal-live contract seal does not match")
        return self


class OwnerQualityNormalLiveReadinessPointer(BaseModel):
    """Fixed local pointer to one immutable v1.11 readiness contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-normal-live-readiness-pointer.v1"] = Field(
        default="legalbot.owner-quality-normal-live-readiness-pointer.v1",
        alias="schema",
    )
    profile: Literal["legalbot-v1.11-owner-only-normal-live"]
    current_contract: OwnerQualityReadinessArtifactRef
    owner_configured: Literal[True]
    create_only_contract: Literal[True]
    writes_active: Literal[False]
    writes_previous: Literal[False]
    writes_o04: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def pointer_is_sealed(self) -> Self:
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-quality normal-live pointer seal does not match")
        return self


def _reference_parts(relative_path: str) -> tuple[str, ...]:
    parts = PurePosixPath(relative_path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("owner-quality readiness artifact path is unsafe")
    return parts


def _read_project_file(
    project_root: Path,
    relative_parts: tuple[str, ...],
    *,
    owner_private: bool,
) -> tuple[Path, bytes]:
    data = read_private_file_at(
        project_root,
        relative_parts,
        required_parent_mode=0o700 if owner_private else None,
        required_file_mode=0o600 if owner_private else None,
    )
    return project_root.absolute().joinpath(*relative_parts), data


def _read_reference(
    project_root: Path,
    reference: OwnerQualityReadinessArtifactRef | OwnerQualityReadinessEvidenceRef,
) -> tuple[Path, bytes]:
    path, data = _read_project_file(
        project_root,
        _reference_parts(reference.relative_path),
        owner_private=True,
    )
    if hashlib.sha256(data).hexdigest() != reference.file_sha256:
        raise ValueError("owner-quality readiness artifact file digest differs")
    return path, data


@contextmanager
def _open_reference_file(
    project_root: Path,
    reference: OwnerQualityReadinessArtifactRef | OwnerQualityReadinessEvidenceRef,
) -> Iterator[tuple[Path, bytes, int]]:
    """Retain the exact referenced inode while a path-based verifier runs."""

    parts = _reference_parts(reference.relative_path)
    with open_private_file_at(
        project_root,
        parts,
        required_parent_mode=0o700,
        required_file_mode=0o600,
    ) as (descriptor, data):
        if hashlib.sha256(data).hexdigest() != reference.file_sha256:
            raise ValueError("owner-quality readiness artifact file digest differs")
        yield project_root.absolute().joinpath(*parts), data, descriptor


def _resolve_reference(project_root: Path, reference: OwnerQualityReadinessArtifactRef) -> Path:
    path, _data = _read_reference(project_root, reference)
    return path


def _resolve_evidence_reference(
    project_root: Path, reference: OwnerQualityReadinessEvidenceRef
) -> Path:
    path, _data = _read_reference(project_root, reference)
    return path


def _load_referenced_model[ModelT: BaseModel](
    project_root: Path,
    reference: OwnerQualityReadinessArtifactRef,
    model_type: type[ModelT],
) -> tuple[Path, ModelT]:
    path, data = _read_reference(project_root, reference)
    model = model_type.model_validate_json(data)
    seal = getattr(model, "seal_sha256", None)
    if seal != reference.artifact_seal_sha256:
        raise ValueError("owner-quality readiness artifact seal differs from its reference")
    return path, model


def _load_pointer(project_root: Path) -> OwnerQualityNormalLiveReadinessPointer:
    try:
        _path, data = _read_project_file(
            project_root,
            tuple(OWNER_QUALITY_NORMAL_LIVE_POINTER.parts),
            owner_private=True,
        )
    except FileNotFoundError as exc:
        raise FileNotFoundError("owner-quality normal-live pointer is absent") from exc
    return OwnerQualityNormalLiveReadinessPointer.model_validate_json(data)


def _load_authorization_reference(
    project_root: Path,
    reference: OwnerQualityReadinessArtifactRef,
    *,
    manifest: OwnerQualityCanaryManifest,
) -> tuple[Path, OwnerQualityDevelopmentAuthorization | OwnerQualityHoldoutAuthorization]:
    path, data = _read_reference(project_root, reference)
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("owner-canary authorization artifact is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("owner-canary authorization must be an object")
    if payload.get("schema") == DEVELOPMENT_AUTHORIZATION_SCHEMA:
        authorization: OwnerQualityDevelopmentAuthorization | OwnerQualityHoldoutAuthorization = (
            OwnerQualityDevelopmentAuthorization.model_validate(payload)
        )
    elif payload.get("schema") == HOLDOUT_AUTHORIZATION_SCHEMA:
        authorization = OwnerQualityHoldoutAuthorization.model_validate(payload)
    else:
        raise ValueError("frozen Live60 v1/v2 authorization is not owner-quality auth")
    verify_authorization_manifest(authorization, manifest)
    if authorization.seal_sha256 != reference.artifact_seal_sha256:
        raise ValueError("owner-quality readiness authorization seal differs")
    return path, authorization


def _load_verified_canary_manifest_reference(
    project_root: Path,
    reference: OwnerQualityReadinessArtifactRef,
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    qualification_reference: OwnerQualityReadinessArtifactRef,
) -> OwnerQualityCanaryManifest:
    """Apply the mandatory derivation loader to the exact securely read bytes."""

    with (
        _open_reference_file(project_root, reference) as (
            _manifest_path,
            manifest_bytes,
            manifest_fd,
        ),
        _open_reference_file(project_root, qualification_reference) as (
            _qualification_path,
            _qualification_bytes,
            qualification_fd,
        ),
    ):
        # On the supported macOS workflow, fdescfs exposes the retained regular
        # descriptors as ordinary no-follow paths.  The mandatory loader can
        # therefore keep its public path contract without reopening attacker-
        # replaceable workspace names.
        manifest = load_verified_owner_quality_canary_manifest(
            Path(f"/dev/fd/{manifest_fd}"),
            bundle=bundle,
            candidate=candidate,
            qualification_path=Path(f"/dev/fd/{qualification_fd}"),
        )
        if (
            manifest_bytes != owner_quality_manifest_bytes(manifest)
            or manifest.seal_sha256 != reference.artifact_seal_sha256
        ):
            raise ValueError("owner-quality canary manifest is a favorable redraw")
        return manifest


def _workspace_for_package(
    *,
    project_root: Path,
    package_reference: OwnerQualityReadinessArtifactRef,
    acceptance_reference: OwnerQualityReadinessArtifactRef,
    package_path: Path,
    acceptance_path: Path,
    package: OwnerCanaryFinalReviewPackage,
) -> CanaryReviewWorkspace:
    if (
        package_path.name != "final-review-package.json"
        or package_path.parent.name != "safe-metrics"
    ):
        raise ValueError("owner-quality final package is outside its fixed workspace location")
    package_relative = PurePosixPath(package_reference.relative_path)
    workspace_relative = package_relative.parent.parent
    expected_acceptance_relative = (
        workspace_relative / "safe-metrics" / OWNER_CANARY_ACCEPTANCE_FILENAME
    ).as_posix()
    if (
        acceptance_reference.relative_path != expected_acceptance_relative
        or acceptance_path
        != project_root.absolute().joinpath(*PurePosixPath(expected_acceptance_relative).parts)
    ):
        raise ValueError("owner acceptance is outside the exact final-package workspace")
    _manifest_path, manifest_bytes = _read_project_file(
        project_root,
        (*workspace_relative.parts, "workspace-manifest.json"),
        owner_private=True,
    )
    manifest = CanaryReviewWorkspaceManifest.model_validate_json(manifest_bytes)
    root = project_root.absolute().joinpath(*workspace_relative.parts)
    workspace = CanaryReviewWorkspace(root=root, manifest=manifest)
    if manifest.seal_sha256 != package.workspace_seal_sha256:
        raise ValueError("owner-quality workspace differs from its final package")
    return workspace


def _shared_authorization_bindings_are_exact(
    development: OwnerQualityDevelopmentAuthorization,
    holdout: OwnerQualityHoldoutAuthorization,
) -> bool:
    return all(
        (
            development.suite_id == holdout.suite_id,
            development.suite_manifest_seal_sha256 == holdout.suite_manifest_seal_sha256,
            development.suite_registry_canonical_sha256 == holdout.suite_registry_canonical_sha256,
            development.canary_manifest_id == holdout.canary_manifest_id,
            development.canary_manifest_seal_sha256 == holdout.canary_manifest_seal_sha256,
            development.candidate_build_id == holdout.candidate_build_id,
            development.candidate_manifest_sha256 == holdout.candidate_manifest_sha256,
            development.qualification_seal_sha256 == holdout.qualification_seal_sha256,
            development.stage_a_run_id == holdout.stage_a_run_id,
            development.stage_a_seal_sha256 == holdout.stage_a_seal_sha256,
            development.completion_preflight_artifact_ref
            == holdout.completion_preflight_artifact_ref,
            development.completion_preflight_verified_result_sha256
            == holdout.completion_preflight_verified_result_sha256,
            development.completion_preflight_authoritative is True,
            holdout.completion_preflight_authoritative is True,
            development.integration_sha == holdout.integration_sha,
            development.policy_bindings.seal_sha256 == holdout.policy_bindings.seal_sha256,
        )
    )


def _verify_exact_artifacts(
    *,
    project_root: Path,
    database: Database | None,
    contract: OwnerQualityNormalLiveReadinessContract,
) -> OwnerQualityO04Approval:
    if database is None:
        raise ValueError("owner-quality normal-live verification requires the live catalogue")
    settings = Settings(project_root=project_root)
    candidate = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=contract.candidate_build_id,
    )
    bundle = load_live_evaluation_bundle(
        project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    _qualification_path, qualification_bytes = _read_reference(
        project_root, contract.all60_qualification
    )
    qualification = ExactAll60Qualification.model_validate_json(qualification_bytes)
    if qualification.seal_sha256 != contract.all60_qualification.artifact_seal_sha256:
        raise ValueError("owner-quality all-60 qualification seal differs")
    manifest = _load_verified_canary_manifest_reference(
        project_root,
        contract.canary_manifest,
        bundle=bundle,
        candidate=candidate,
        qualification_reference=contract.all60_qualification,
    )
    _qualification_path_after, qualification_bytes_after = _read_reference(
        project_root, contract.all60_qualification
    )
    if qualification_bytes_after != qualification_bytes:
        raise ValueError("owner-quality all-60 qualification changed during verification")
    _development_auth_path, development_auth = _load_authorization_reference(
        project_root,
        contract.development_authorization,
        manifest=manifest,
    )
    _holdout_auth_path, holdout_auth = _load_authorization_reference(
        project_root,
        contract.blind_holdout_authorization,
        manifest=manifest,
    )
    if not isinstance(development_auth, OwnerQualityDevelopmentAuthorization) or not isinstance(
        holdout_auth, OwnerQualityHoldoutAuthorization
    ):
        raise ValueError("owner-quality readiness authorization lanes are reversed")
    if (
        development_auth.seal_sha256 != contract.development_authorization.artifact_seal_sha256
        or holdout_auth.seal_sha256 != contract.blind_holdout_authorization.artifact_seal_sha256
    ):
        raise ValueError("owner-quality readiness authorization seal differs")

    development_package_path, development_package = _load_referenced_model(
        project_root,
        contract.development_final_package,
        OwnerCanaryFinalReviewPackage,
    )
    development_acceptance_path, development_acceptance = _load_referenced_model(
        project_root,
        contract.development_owner_acceptance,
        OwnerCanaryAcceptanceSummary,
    )
    holdout_package_path, holdout_package = _load_referenced_model(
        project_root,
        contract.blind_holdout_final_package,
        OwnerCanaryFinalReviewPackage,
    )
    holdout_acceptance_path, holdout_acceptance = _load_referenced_model(
        project_root,
        contract.blind_holdout_owner_acceptance,
        OwnerCanaryAcceptanceSummary,
    )
    development_workspace = _workspace_for_package(
        project_root=project_root,
        package_reference=contract.development_final_package,
        acceptance_reference=contract.development_owner_acceptance,
        package_path=development_package_path,
        acceptance_path=development_acceptance_path,
        package=development_package,
    )
    holdout_workspace = _workspace_for_package(
        project_root=project_root,
        package_reference=contract.blind_holdout_final_package,
        acceptance_reference=contract.blind_holdout_owner_acceptance,
        package_path=holdout_package_path,
        acceptance_path=holdout_acceptance_path,
        package=holdout_package,
    )
    replay_authorization_completion_preflight(
        settings=settings,
        authorization=development_auth,
        candidate=candidate,
        run_dir=(
            development_workspace.root
            / "safe-metrics"
            / OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME
            / Path(development_auth.completion_preflight_artifact_ref).name
        ),
    )
    replay_authorization_completion_preflight(
        settings=settings,
        authorization=holdout_auth,
        candidate=candidate,
        run_dir=(
            holdout_workspace.root
            / "safe-metrics"
            / OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME
            / Path(holdout_auth.completion_preflight_artifact_ref).name
        ),
    )
    # Reuse the promotion-grade file inventory and durable DB projection for
    # both lanes.  A self-sealed final package/feedback summary is not runtime
    # evidence, and pre-run O-04 cannot authenticate post-run answer bytes.
    from .owner_quality_v111_promotion import (
        OwnerQualityV111PromotionPresentation,
        _replay_all60_for_workspace,
        _technical_stage_a_inputs,
        _verify_db_backed_development_package,
        _verify_final_package_files,
    )
    from .v111_technical_attestation_admission import (
        load_admitted_v111_technical_attestation,
    )

    technical_stage_a = _technical_stage_a_inputs(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification_path=_qualification_path,
        workspace=development_workspace,
        authorization=development_auth,
    )
    _replay_all60_for_workspace(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        qualification_path=_qualification_path,
        workspace=holdout_workspace,
        integration_sha=holdout_auth.integration_sha,
    )

    _verify_final_package_files(
        workspace=development_workspace,
        package=development_package,
        expected_lane="development",
    )
    _verify_db_backed_development_package(
        settings=settings,
        database=database,
        workspace=development_workspace,
        package=development_package,
        expected_lane="development",
    )
    _verify_final_package_files(
        workspace=holdout_workspace,
        package=holdout_package,
        expected_lane="blind_holdout",
    )
    _verify_db_backed_development_package(
        settings=settings,
        database=database,
        workspace=holdout_workspace,
        package=holdout_package,
        expected_lane="blind_holdout",
    )
    verified_development_acceptance = (
        require_development_owner_acceptance_for_promotion_presentation(
            workspace=development_workspace,
            package=development_package,
        )
    )
    verified_holdout_acceptance = require_holdout_owner_acceptance_for_normal_live_readiness(
        workspace=holdout_workspace,
        package=holdout_package,
    )

    _presentation_path, presentation = _load_referenced_model(
        project_root,
        contract.promotion_presentation,
        OwnerQualityV111PromotionPresentation,
    )
    technical_admission_path, _technical_admission_bytes = _read_reference(
        project_root,
        contract.technical_attestation_admission,
    )
    technical_admission = load_admitted_v111_technical_attestation(
        technical_admission_path,
        settings=settings,
        database=database,
        candidate=candidate,
        stage_a=technical_stage_a,
        expected_integration_sha=contract.integration_sha,
        phase="postpromotion",
    )
    technical_receipt = dict(technical_admission.receipt)

    _promotion_path, promotion = _load_referenced_model(
        project_root,
        contract.promoted_active_proof,
        PromotedActiveCandidateProof,
    )
    _operations_path, operations = _load_referenced_model(
        project_root,
        contract.operational_proof,
        OwnerCanaryOperationalProof,
    )
    operations_evidence = (
        (
            contract.owner_only_smoke_evidence,
            operations.owner_only_smoke_sha256,
        ),
        (
            contract.rollback_repromotion_evidence,
            operations.rollback_repromotion_sha256,
        ),
        (
            contract.browser_recovery_evidence,
            operations.browser_recovery_sha256,
        ),
        (
            contract.technical_readiness_evidence,
            operations.readiness_sha256,
        ),
        (
            contract.disk_heartbeat_lease_evidence,
            operations.disk_heartbeat_lease_sha256,
        ),
        (
            contract.model_identity_evidence,
            operations.model_identity_sha256,
        ),
    )
    for reference, expected_sha256 in operations_evidence:
        _resolve_evidence_reference(project_root, reference)
        if reference.file_sha256 != expected_sha256:
            raise ValueError("operational proof differs from immutable evidence bytes")
    # The current six files have no typed, replayable semantic schemas.  Hash
    # equality to a self-sealed favorable summary cannot prove smoke, rollback,
    # browser recovery, readiness, disk/lease/heartbeat, or model identity.
    raise OwnerDecisionRequired("typed_operational_evidence_replay_contract_missing")
    _o04_path, owner_o04 = _load_referenced_model(
        project_root,
        contract.owner_o04,
        OwnerQualityO04Approval,
    )

    _active_path, active_bytes = _read_project_file(
        project_root,
        ("data", "indexes", "ACTIVE.json"),
        owner_private=False,
    )
    active_payload = json.loads(active_bytes)
    active_rows = database.fetchall("SELECT id,status FROM index_builds WHERE status='active'")
    _build_manifest_path, build_manifest_bytes = _read_project_file(
        project_root,
        ("data", "indexes", "builds", contract.candidate_build_id, "manifest.json"),
        owner_private=False,
    )
    if (
        not isinstance(active_payload, dict)
        or active_payload.get("build_id") != contract.candidate_build_id
        or hashlib.sha256(active_bytes).hexdigest() != promotion.active_pointer_sha256
        or active_payload.get("manifest_sha256") != hashlib.sha256(build_manifest_bytes).hexdigest()
        or len(active_rows) != 1
        or str(active_rows[0]["id"]) != contract.candidate_build_id
    ):
        raise ValueError("ACTIVE pointer, promotion proof and catalogue are not reconciled")

    from ..retrieval.retrieval_reattest import _clean_integration_sha

    current_integration_sha = _clean_integration_sha(project_root)

    expected_candidate = (contract.candidate_build_id, contract.candidate_manifest_sha256)
    bound_candidates = (
        (manifest.candidate_build_id, manifest.candidate_manifest_sha256),
        (development_auth.candidate_build_id, development_auth.candidate_manifest_sha256),
        (holdout_auth.candidate_build_id, holdout_auth.candidate_manifest_sha256),
        (development_package.candidate_build_id, development_package.candidate_manifest_sha256),
        (holdout_package.candidate_build_id, holdout_package.candidate_manifest_sha256),
        (presentation.candidate_build_id, presentation.candidate_manifest_sha256),
        (promotion.candidate_build_id, promotion.candidate_manifest_sha256),
        (operations.candidate_build_id, operations.candidate_manifest_sha256),
        (owner_o04.candidate_build_id, owner_o04.candidate_manifest_sha256),
    )
    exact_checks = (
        all(candidate == expected_candidate for candidate in bound_candidates),
        contract.canary_manifest_id == manifest.manifest_id,
        contract.canary_manifest_seal_sha256 == manifest.seal_sha256,
        contract.development_run_id == development_auth.run_id == development_package.run_id,
        contract.blind_holdout_run_id == holdout_auth.run_id == holdout_package.run_id,
        contract.integration_sha
        == development_auth.integration_sha
        == holdout_auth.integration_sha,
        contract.integration_sha == current_integration_sha,
        presentation.integration_sha == contract.integration_sha,
        presentation.canary_manifest_seal_sha256 == manifest.seal_sha256,
        presentation.development_authorization_seal_sha256 == development_auth.seal_sha256,
        presentation.development_final_package_seal_sha256 == development_package.seal_sha256,
        presentation.development_owner_acceptance_seal_sha256 == development_acceptance.seal_sha256,
        _shared_authorization_bindings_are_exact(development_auth, holdout_auth),
        development_package.authorization_seal_sha256 == development_auth.seal_sha256,
        holdout_package.authorization_seal_sha256 == holdout_auth.seal_sha256,
        development_package.canary_manifest_seal_sha256 == manifest.seal_sha256,
        holdout_package.canary_manifest_seal_sha256 == manifest.seal_sha256,
        development_package.case_ids == manifest.development_case_ids,
        holdout_package.case_ids == manifest.blind_holdout_case_ids,
        verified_development_acceptance.seal_sha256 == development_acceptance.seal_sha256,
        verified_holdout_acceptance.seal_sha256 == holdout_acceptance.seal_sha256,
        contract.promotion_presentation.artifact_seal_sha256 == presentation.seal_sha256,
        presentation.technical_run_id == contract.technical_run_id,
        presentation.technical_admission_id == contract.technical_admission_id,
        presentation.technical_admission_seal_sha256 == contract.technical_admission_seal_sha256,
        presentation.technical_final_attestation_seal_sha256
        == contract.technical_final_attestation_seal_sha256,
        presentation.technical_matrix_sha256 == contract.technical_matrix_sha256,
        presentation.technical_artifact_set_sha256 == contract.technical_artifact_set_sha256,
        presentation.technical_artifact_member_count == contract.technical_artifact_member_count,
        presentation.technical_stage_a_result_seal_sha256
        == contract.technical_stage_a_result_seal_sha256,
        presentation.technical_stage_a_attestation_seal_sha256
        == contract.technical_stage_a_attestation_seal_sha256,
        presentation.technical_rollback_plan_seal_sha256
        == contract.technical_rollback_plan_seal_sha256,
        presentation.technical_rollback_policy_binding_seal_sha256
        == contract.technical_rollback_policy_binding_seal_sha256,
        presentation.scorer_identity_sha256 == contract.scorer_identity_sha256,
        presentation.legacy_technical_summaries_accepted is False,
        contract.legacy_technical_summaries_accepted is False,
        technical_admission.run_id == contract.technical_run_id,
        technical_admission.admission_id == contract.technical_admission_id,
        technical_admission.seal_sha256 == contract.technical_admission_seal_sha256,
        technical_receipt.get("final_attestation_seal_sha256")
        == contract.technical_final_attestation_seal_sha256,
        technical_receipt.get("matrix_sha256") == contract.technical_matrix_sha256,
        technical_receipt.get("artifact_set_sha256") == contract.technical_artifact_set_sha256,
        technical_receipt.get("artifact_member_count") == contract.technical_artifact_member_count,
        technical_receipt.get("stage_a_result_seal_sha256")
        == contract.technical_stage_a_result_seal_sha256,
        technical_receipt.get("stage_a_result_seal_sha256") == development_auth.stage_a_seal_sha256,
        technical_receipt.get("stage_a_attestation_seal_sha256")
        == contract.technical_stage_a_attestation_seal_sha256,
        technical_receipt.get("rollback_plan_seal_sha256")
        == contract.technical_rollback_plan_seal_sha256,
        technical_receipt.get("rollback_policy_binding", {}).get("seal_sha256")
        == contract.technical_rollback_policy_binding_seal_sha256,
        technical_receipt.get("scorer_identity_sha256") == contract.scorer_identity_sha256,
        technical_receipt.get("legacy_favorable_summaries_accepted") is False,
        promotion.owner_promotion_ref == presentation.presentation_id,
        all(
            owner_ref == owner_o04.owner_ref
            for owner_ref in verified_development_acceptance.latest_owner_refs
        ),
        all(
            owner_ref == owner_o04.owner_ref
            for owner_ref in verified_holdout_acceptance.latest_owner_refs
        ),
        promotion.seal_sha256 == operations.promoted_active_proof_seal_sha256,
        holdout_auth.active_build_id == promotion.candidate_build_id,
        holdout_auth.promoted_active_proof_seal_sha256 == promotion.seal_sha256,
        holdout_auth.operational_proof_seal_sha256 == operations.seal_sha256,
        holdout_auth.o04_approval_seal_sha256 == owner_o04.seal_sha256,
        holdout_auth.o04_approval_ref == owner_o04.approval_id,
        holdout_auth.owner_ref == owner_o04.owner_ref,
        owner_o04.run_id == holdout_auth.run_id,
        owner_o04.canary_manifest_id == manifest.manifest_id,
        owner_o04.canary_manifest_seal_sha256 == manifest.seal_sha256,
        owner_o04.qualification_seal_sha256 == holdout_auth.qualification_seal_sha256,
        owner_o04.stage_a_seal_sha256 == holdout_auth.stage_a_seal_sha256,
        owner_o04.integration_sha == holdout_auth.integration_sha,
        owner_o04.policy_bindings_seal_sha256 == holdout_auth.policy_bindings.seal_sha256,
        owner_o04.promoted_active_proof_seal_sha256 == promotion.seal_sha256,
        owner_o04.operational_proof_seal_sha256 == operations.seal_sha256,
        owner_o04.authorized_case_ids == holdout_auth.authorized_case_ids,
        development_auth.authorized_case_ids == manifest.development_case_ids,
        holdout_auth.authorized_case_ids == manifest.blind_holdout_case_ids,
        set(development_auth.authorized_case_ids).isdisjoint(holdout_auth.authorized_case_ids),
    )
    if not all(exact_checks):
        raise ValueError("owner-quality normal-live artifact bindings differ")
    return owner_o04


def _verify_trusted_owner_o04_signature(_approval: OwnerQualityO04Approval) -> None:
    """Remain fail-closed until the owner chooses and configures a trusted verifier."""

    raise OwnerDecisionRequired("trusted_owner_o04_signature_verifier_missing")


def _verify_trusted_post_run_owner_acceptance_signature() -> None:
    """Remain closed until all 30 final answer digests have owner-authenticated passes."""

    raise OwnerDecisionRequired("trusted_post_run_owner_acceptance_signature_verifier_missing")


def _verified_release_authority_from_artifacts(
    *,
    project_root: Path,
    database: Database,
    pointer: OwnerQualityNormalLiveReadinessPointer | None = None,
    contract: OwnerQualityNormalLiveReadinessContract | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Replay the full artifact/signature graph, excluding only DB admission."""

    runtime_settings = settings or Settings(project_root=project_root)
    if runtime_settings.project_root.resolve() != project_root.resolve():
        raise RuntimeError("owner_quality_first_live_settings_invalid")
    parsed_model = urlparse(runtime_settings.model_url)
    forbidden_environment = {
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LEGALBOT_ADAPTER_PATH",
        "LEGALBOT_LORA_PATH",
        "LEGALBOT_MODEL_ADAPTER_PATH",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    }
    if (
        runtime_settings.live_profile != FIRST_LIVE_LOCAL_ONLY_PROFILE
        or runtime_settings.online_default != "local_only"
        or runtime_settings.official_research_enabled
        or runtime_settings.xerj_enabled
        or runtime_settings.phoenix_enabled
        or runtime_settings.host != "127.0.0.1"
        or runtime_settings.port != 8777
        or parsed_model.hostname != "127.0.0.1"
        or parsed_model.port != 8778
        or parsed_model.scheme != "http"
        or parsed_model.username is not None
        or parsed_model.password is not None
        or any(os.environ.get(name) for name in forbidden_environment)
    ):
        raise RuntimeError("owner_quality_first_live_settings_invalid")

    current_pointer = pointer or _load_pointer(project_root)
    current_contract = contract
    if current_contract is None:
        _contract_path, current_contract = _load_referenced_model(
            project_root,
            current_pointer.current_contract,
            OwnerQualityNormalLiveReadinessContract,
        )
    owner_o04 = _verify_exact_artifacts(
        project_root=project_root,
        database=database,
        contract=current_contract,
    )
    _verify_trusted_owner_o04_signature(owner_o04)
    _verify_trusted_post_run_owner_acceptance_signature()
    active_build_id = database.active_index_id()
    if active_build_id != current_contract.candidate_build_id:
        raise RuntimeError("owner_quality_normal_live_active_candidate_changed")
    value: dict[str, Any] = {
        "schema": OWNER_QUALITY_NORMAL_LIVE_RELEASE_AUTHORITY_SCHEMA,
        "profile": "legalbot-v1.11-owner-only-normal-live",
        "normal_live_ready": True,
        "candidate_build_id": current_contract.candidate_build_id,
        "candidate_manifest_sha256": current_contract.candidate_manifest_sha256,
        "integration_sha": current_contract.integration_sha,
        "readiness_pointer_seal_sha256": current_pointer.seal_sha256,
        "readiness_contract_seal_sha256": current_contract.seal_sha256,
        "readiness_generation_sha256": sealed_sha256(
            {
                "schema": "legalbot.owner-quality-normal-live-generation.v1",
                "pointer_seal_sha256": current_pointer.seal_sha256,
                "contract_seal_sha256": current_contract.seal_sha256,
                "candidate_build_id": current_contract.candidate_build_id,
                "candidate_manifest_sha256": current_contract.candidate_manifest_sha256,
                "integration_sha": current_contract.integration_sha,
            }
        ),
        "trusted_owner_o04_signature_verified": True,
        "trusted_post_run_owner_acceptance_signature_verified": True,
        "release_audience": "normal_live",
    }
    value["seal_sha256"] = sealed_sha256(value)
    return value


def _require_current_db_readiness_generation(
    *, database: Database, authority: Mapping[str, Any]
) -> None:
    state = database.normal_live_readiness_state()
    if (
        state is None
        or not bool(state["active"])
        or state["generation_sha256"] != authority.get("readiness_generation_sha256")
        or state["authority_sha256"] != authority.get("seal_sha256")
        or state["candidate_build_id"] != authority.get("candidate_build_id")
    ):
        raise RuntimeError("owner_quality_normal_live_generation_not_admitted")


def activate_owner_quality_normal_live_readiness(
    project_root: Path, *, database: Database, settings: Settings | None = None
) -> str:
    """Fail closed until ordinary releases have exact semantic content binding."""

    del project_root, database, settings
    raise RuntimeError(
        f"TECHNICAL_IMPLEMENTATION_REQUIRED:{NORMAL_LIVE_CONTENT_CERTIFICATION_STOP}"
    )


def owner_quality_normal_live_readiness_status(
    project_root: Path,
    *,
    database: Database | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Return a prose-free v1.11 status; malformed or absent state never raises."""

    status: dict[str, Any] = {
        "schema": OWNER_QUALITY_NORMAL_LIVE_STATUS_SCHEMA,
        "profile": "legalbot-v1.11-owner-only-normal-live",
        "pointer_relative_path": OWNER_QUALITY_NORMAL_LIVE_POINTER.as_posix(),
        "pointer_present": False,
        "contract_present": False,
        "exact_artifacts_verified": False,
        "trusted_owner_o04_signature_verified": False,
        "trusted_post_run_owner_acceptance_signature_verified": False,
        "db_readiness_generation_verified": False,
        "owner_acceptance_development_30_passed": False,
        "owner_acceptance_blind_holdout_30_passed": False,
        "legacy_readiness_sufficient": False,
        "normal_live_ready": False,
        "blocking_reason_codes": [],
        "error_code": None,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
    }
    try:
        pointer = _load_pointer(project_root)
        status["pointer_present"] = True
        _contract_path, contract = _load_referenced_model(
            project_root,
            pointer.current_contract,
            OwnerQualityNormalLiveReadinessContract,
        )
        status["contract_present"] = True
        owner_o04 = _verify_exact_artifacts(
            project_root=project_root,
            database=database,
            contract=contract,
        )
        status["exact_artifacts_verified"] = True
        status["owner_acceptance_development_30_passed"] = True
        status["owner_acceptance_blind_holdout_30_passed"] = True
        _verify_trusted_owner_o04_signature(owner_o04)
        status["trusted_owner_o04_signature_verified"] = True
        _verify_trusted_post_run_owner_acceptance_signature()
        status["trusted_post_run_owner_acceptance_signature_verified"] = True
        if database is None:
            raise RuntimeError("owner_quality_normal_live_catalogue_missing")
        authority = _verified_release_authority_from_artifacts(
            project_root=project_root,
            database=database,
            pointer=pointer,
            contract=contract,
            settings=settings,
        )
        _require_current_db_readiness_generation(
            database=database,
            authority=authority,
        )
        status["db_readiness_generation_verified"] = True
        status["normal_live_ready"] = True
    except FileNotFoundError:
        status["blocking_reason_codes"] = ["owner_quality_normal_live_pointer_missing"]
    except OwnerDecisionRequired as exc:
        status["blocking_reason_codes"] = [exc.reason_code]
        status["error_code"] = "OwnerDecisionRequired"
    except (
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        status["blocking_reason_codes"] = ["owner_quality_normal_live_artifact_verification_failed"]
        status["error_code"] = type(exc).__name__
    underlying_ready = status["normal_live_ready"] is True
    status["normal_live_ready"] = False
    if underlying_ready:
        blocking = list(status["blocking_reason_codes"])
        if NORMAL_LIVE_CONTENT_CERTIFICATION_STOP not in blocking:
            blocking.append(NORMAL_LIVE_CONTENT_CERTIFICATION_STOP)
        status["blocking_reason_codes"] = blocking
    return status


def owner_quality_normal_live_release_authority(
    project_root: Path, *, database: Database, settings: Settings | None = None
) -> dict[str, Any]:
    """Recompute and seal the exact current authority used at publication.

    This is deliberately deterministic and read-only.  Callers must replay it
    inside the database release transaction; an earlier readiness check is not
    a publication credential.
    """

    del project_root, database, settings
    raise RuntimeError(
        f"TECHNICAL_IMPLEMENTATION_REQUIRED:{NORMAL_LIVE_CONTENT_CERTIFICATION_STOP}"
    )
