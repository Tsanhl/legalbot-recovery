"""Non-authorizing Phase-2 certification and qualification preparation.

This module deliberately stops before owner authority.  It binds a conservative
contract draft and a question-free qualification inventory to the exact Git
tree, sealed candidate, and immutable Owner Certification 60 registry.  It does
not select a 30/30 complement, invoke retrieval or a model, qualify legal
currentness, or authorize a run.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..config import Settings
from ..governance.v111_decision_generation import require_exact_clean_head
from .live_suite import LiveEvaluationBundle, canonical_json, sealed_sha256
from .sealed_candidate import SealedCandidateIdentity

CONTRACT_SCHEMA = "legalbot.v111-certification-contract-draft.v1"
QUALIFICATION_PREPARATION_SCHEMA = "legalbot.v111-qualification-preparation.v1"
PREPARATION_INDEX_SCHEMA = "legalbot.v111-phase2-preparation-index.v1"
CONTRACT_FILENAME = "certification-contract-draft.json"
QUALIFICATION_FILENAME = "qualification-currentness-preparation.json"
INDEX_FILENAME = "PREPARATION-INDEX.json"

_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_BUILD_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SCORER_SEMANTIC_SCHEMA = "legalbot.scorer-closure-semantic-equivalence.v1"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _artifact_sha256(value: Mapping[str, Any], *, field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    return _sha256_bytes(canonical_json(material))


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class CodeBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    worktree_clean: Literal[True]


class CandidateBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    status: Literal["candidate"]
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    document_count: int = Field(ge=1)
    chunk_count: int = Field(ge=1)
    vector_count: int = Field(ge=1)
    embedding_model: str = Field(min_length=1, max_length=255)
    reranker_model: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def vectors_cover_every_chunk(self) -> Self:
        if self.vector_count != self.chunk_count:
            raise ValueError("candidate vectors do not cover every chunk")
        return self


class RegistryBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    suite_id: Literal["live-evaluation-60-v1"]
    suite_version: Literal["1.0.0"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registry_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_count: int = Field(ge=1)
    issue_count: int = Field(ge=1)
    issue_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CandidatePolicyBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    quality_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_guidance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provision_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_manifest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RetrievalEvidenceBinding(BaseModel):
    """Historical proof plus an exact current non-scorer closure equivalence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    selected_attestation_schema: Literal["legalbot.retrieval-reattestation.v2"]
    selected_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_attestation_history_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_integration_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    selected_closure_manifest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_closure_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_closure_aggregate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_closure_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    current_closure_tree: str = Field(pattern=r"^[0-9a-f]{40}$")
    current_closure_aggregate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    member_count: int = Field(ge=1)
    selected_member_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_member_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_python_runtime_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_python_runtime_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_legacy_scorer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_legacy_scorer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_semantic_closure_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_semantic_closure_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    equivalence_ignores: tuple[Literal["revision"], Literal["tree"]]
    semantic_equivalence_proven: Literal[True]

    @model_validator(mode="after")
    def only_git_identity_differs(self) -> Self:
        if self.equivalence_ignores != ("revision", "tree"):
            raise ValueError("scorer closure equivalence may ignore only revision and tree")
        if (
            self.selected_attestation_history_id != self.selected_attestation_sha256
            or self.selected_member_set_sha256 != self.current_member_set_sha256
            or self.selected_python_runtime_sha256 != self.current_python_runtime_sha256
            or self.selected_legacy_scorer_sha256 != self.current_legacy_scorer_sha256
            or self.selected_semantic_closure_sha256 != self.current_semantic_closure_sha256
        ):
            raise ValueError("current scorer closure is not semantically equal to selected proof")
        return self


class SourceHierarchyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rank: int = Field(ge=1, le=4)
    source_class: Literal[
        "official_legislation",
        "official_judgment_or_court_publication",
        "official_rules_or_practice_direction",
        "official_regulator_or_government_material",
    ]
    may_support_material_claim: Literal[True]
    required_checks: tuple[str, ...]

    @field_validator("required_checks")
    @classmethod
    def checks_are_nonempty_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or len(values) != len(set(values)):
            raise ValueError("source hierarchy checks must be nonempty and unique")
        return values


class CurrentnessPolicyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    jurisdiction: Literal["England and Wales"]
    owner_cutoff_date: None = None
    cutoff_state: Literal["pending_owner_official_source_review"]
    candidate_snapshot_date_is_not_owner_cutoff: Literal[True]
    legislation_rule: Literal[
        "verify_extent_effective_date_repeals_pending_changes_and_material_unapplied_effects"
    ]
    case_rule: Literal["verify_subsequent_treatment_and_precedential_role_through_owner_cutoff"]
    pending_change_rule: Literal[
        "not_current_law_until_in_force_at_cutoff_but_disclose_if_material"
    ]
    conflict_rule: Literal[
        "bind_material_contrary_authority_and_explain_priority_or_limit_the_claim"
    ]
    material_delta_rule: Literal[
        "candidate_reseal_requalification_reattestation_and_development_rerun"
    ]
    hierarchy: tuple[SourceHierarchyRule, ...]

    @model_validator(mode="after")
    def hierarchy_is_complete(self) -> Self:
        if tuple(item.rank for item in self.hierarchy) != (1, 2, 3, 4):
            raise ValueError("source hierarchy must contain exact ranks 1-4")
        if len({item.source_class for item in self.hierarchy}) != 4:
            raise ValueError("source hierarchy contains duplicate classes")
        return self


class EvidencePolicyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    material_claim_requires_frozen_evidence_span: Literal[True]
    source_identity_jurisdiction_currentness_required: Literal[True]
    case_proposition_requires_reviewed_legal_role: Literal[True]
    model_generated_citations_allowed: Literal[False]
    deterministic_oscola_required: Literal[True]
    teaching_or_feedback_as_independent_authority_allowed: Literal[False]
    private_path_or_owner_identifier_allowed: Literal[False]
    unsupported_issue_disposition: Literal["verified_limited_or_held"]
    invented_authority_tolerance: Literal[0]
    false_quotation_tolerance: Literal[0]
    unsupported_material_assertion_tolerance: Literal[0]
    unsupported_typed_material_fact_tolerance: Literal[0]
    non_atomic_material_claim_tolerance: Literal[0]
    material_contradiction_tolerance: Literal[0]


class ScoringPolicyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issue_pass_rule: Literal["qualified_positive_span_and_all_material_assertions_evidence_bound"]
    question_pass_rule: Literal[
        "every_registry_issue_dispositioned_zero_hard_blockers_and_owner_adjudication_pass"
    ]
    aggregation_rule: Literal["no_average_may_mask_a_question_or_issue_failure"]
    development_case_count: Literal[30]
    sealed_validation_case_count: Literal[30]
    stage_a_recall_at_5_minimum: float = Field(ge=0, le=1)
    stage_a_recall_at_10_minimum: float = Field(ge=0, le=1)
    stage_a_mrr_minimum: float = Field(ge=0, le=1)
    stage_a_filter_violation_maximum: Literal[0]
    required_validation_release_state: Literal["verified_full"]
    minimum_validation_question_passes: Literal[30]
    automated_academic_target: Literal[70]
    automated_academic_target_is_legal_safety_gate: Literal[False]
    owner_adjudication_required: Literal[True]
    rubric_or_threshold_relaxation_after_results_allowed: Literal[False]

    @model_validator(mode="after")
    def conservative_thresholds_are_frozen(self) -> Self:
        if (
            self.stage_a_recall_at_5_minimum != 1.0
            or self.stage_a_recall_at_10_minimum != 0.95
            or self.stage_a_mrr_minimum != 0.8
        ):
            raise ValueError("Stage A thresholds differ from the conservative draft")
        return self


class ExecutionPolicyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    generation_concurrency: Literal[1]
    maximum_memory_bytes: Literal[12884901888]
    minimum_free_memory_bytes: Literal[3221225472]
    model_transport: Literal["private_unix_domain_socket"]
    first_live_bind: Literal["127.0.0.1"]
    preflight_failure_consumes_sealed_run: Literal[False]
    run_begins: Literal["first_committed_answer_generation_request"]
    quality_motivated_selective_rerun_allowed: Literal[False]
    maximum_same_failure_fingerprint: Literal[2]
    transient_attempt_limit_per_case: Literal[2]
    resume_requires_same_run_and_authenticated_checkpoint: Literal[True]
    resume_requires_unchanged_snapshot_and_unexposed_output: Literal[True]
    missing_case_disposition: Literal["failure_unless_frozen_invalid_run_rule_applies"]
    result_exposure_ends_sealed_status: Literal[True]


class PreservationPolicyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    create_only_artifacts: Literal[True]
    prior_cycles_immutable: Literal[True]
    raw_question_answer_and_review_storage: Literal["owner_private_lane_specific_roots"]
    ordinary_logs_may_contain_question_or_answer_text: Literal[False]
    ordinary_logs_may_contain_private_paths: Literal[False]
    development_and_validation_roots_must_differ: Literal[True]
    validation_outputs_hidden_until_valid_o04: Literal[True]
    training_export_allowed: Literal[False]
    cloud_or_publication_allowed: Literal[False]


class FreezeRequirements(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    owner_signature_mechanism: Literal["ed25519_public_key_pending_signed_package"]
    owner_cutoff: Literal["pending"]
    exact_prompt_sha256: Literal["pending_production_candidate_freeze"]
    exact_model_and_runtime_sha256: Literal["pending_production_candidate_freeze"]
    evaluator_and_reviewer_sha256: Literal["pending_production_candidate_freeze"]
    split_manifest_sha256: Literal["pending_post_qualification_owner_secret"]
    private_review_roots: Literal["pending_signed_non_synced_root_bindings"]
    local_security_material: Literal["pending_signed_package_and_local_provisioning"]


class CertificationContractDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-certification-contract-draft.v1"] = Field(
        default="legalbot.v111-certification-contract-draft.v1", alias="schema"
    )
    document_state: Literal["draft_owner_signature_required"]
    authorizing: Literal[False]
    owner_signature_present: Literal[False]
    development_run_authorized: Literal[False]
    sealed_validation_authorized: Literal[False]
    promotion_authorized: Literal[False]
    generated_at: datetime
    code: CodeBinding
    candidate: CandidateBinding
    registry: RegistryBinding
    candidate_policies: CandidatePolicyBinding
    retrieval_evidence: RetrievalEvidenceBinding
    currentness: CurrentnessPolicyDraft
    evidence: EvidencePolicyDraft
    scoring: ScoringPolicyDraft
    execution: ExecutionPolicyDraft
    preservation: PreservationPolicyDraft
    freeze_requirements: FreezeRequirements
    contract_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def draft_is_sealed_but_never_authorizing(self) -> Self:
        expected = _artifact_sha256(
            self.model_dump(mode="json", by_alias=True), field="contract_draft_sha256"
        )
        if self.contract_draft_sha256 != expected:
            raise ValueError("certification contract draft seal does not match")
        if self.currentness.owner_cutoff_date is not None:
            raise ValueError("draft must not invent the owner legal-currentness cutoff")
        return self


class CandidateSourceInventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_manifest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_manifest_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_snapshot_date: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    source_count: int = Field(ge=1)
    authority_lane_count: int = Field(ge=0)
    latest_revised_snapshot_count: int = Field(ge=0)
    historical_authority_count: int = Field(ge=0)
    current_law_eligible_count: int = Field(ge=0)
    subsequent_treatment_required_count: int = Field(ge=0)
    subsequent_treatment_verified_count: int = Field(ge=0)
    omitted_required_family_count: int = Field(ge=0)

    @model_validator(mode="after")
    def source_counts_are_possible(self) -> Self:
        bounded = (
            self.authority_lane_count,
            self.latest_revised_snapshot_count,
            self.historical_authority_count,
            self.current_law_eligible_count,
            self.subsequent_treatment_required_count,
            self.subsequent_treatment_verified_count,
        )
        if any(value > self.source_count for value in bounded):
            raise ValueError("candidate source inventory count exceeds source count")
        if self.subsequent_treatment_verified_count > self.subsequent_treatment_required_count:
            raise ValueError("verified treatment count exceeds required treatment count")
        return self


class QualificationIssuePreparation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issue_id: str = Field(pattern=r"^issue-[0-9]{2}$")
    issue_label_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registry_issue_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_state: Literal["pending_official_source_and_currentness_review"]
    gold_evidence_state: Literal["not_assessed"]
    material_gap_state: Literal["not_assessed"]


class QualificationCasePreparation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ordinal: int = Field(ge=1, le=60)
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_type: Literal["problem", "essay"]
    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue_count: int = Field(ge=1)
    issues: tuple[QualificationIssuePreparation, ...]
    qualification_state: Literal["pending_official_source_and_currentness_review"]

    @model_validator(mode="after")
    def issue_inventory_is_complete(self) -> Self:
        expected = tuple(f"issue-{number:02d}" for number in range(1, self.issue_count + 1))
        if tuple(issue.issue_id for issue in self.issues) != expected:
            raise ValueError("qualification case issue inventory is incomplete")
        return self


class QualificationPreparationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-qualification-preparation.v1"] = Field(
        default="legalbot.v111-qualification-preparation.v1", alias="schema"
    )
    document_state: Literal["preparation_only_owner_currentness_decision_required"]
    authorizing: Literal[False]
    legally_qualified: Literal[False]
    answer_model_invoked: Literal[False]
    stage_a_invoked: Literal[False]
    development_30_invoked: Literal[False]
    split_created: Literal[False]
    candidate_changed: Literal[False]
    generated_at: datetime
    code: CodeBinding
    candidate: CandidateBinding
    registry: RegistryBinding
    candidate_sources: CandidateSourceInventory
    retrieval_evidence: RetrievalEvidenceBinding
    owner_cutoff_date: None = None
    workflow: tuple[str, ...]
    cases: tuple[QualificationCasePreparation, ...]
    pending_case_count: int = Field(ge=1)
    pending_issue_count: int = Field(ge=1)
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("workflow")
    @classmethod
    def workflow_is_nonempty_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or len(values) != len(set(values)):
            raise ValueError("qualification workflow must be nonempty and unique")
        return values

    @model_validator(mode="after")
    def pending_inventory_is_exact(self) -> Self:
        case_ids = tuple(item.case_id for item in self.cases)
        expected_ids = tuple(
            [f"live30-q{number:02d}" for number in range(1, 31)]
            + [f"live60-q{number:02d}" for number in range(31, 61)]
        )
        issue_count = sum(item.issue_count for item in self.cases)
        identities = tuple(
            issue.registry_issue_identity_sha256 for case in self.cases for issue in case.issues
        )
        if (
            case_ids != expected_ids
            or self.pending_case_count != len(self.cases)
            or self.pending_issue_count != issue_count
            or self.registry.case_count != len(self.cases)
            or self.registry.issue_count != issue_count
            or len(identities) != len(set(identities))
        ):
            raise ValueError("qualification preparation inventory is incomplete")
        expected = _artifact_sha256(
            self.model_dump(mode="json", by_alias=True), field="report_sha256"
        )
        if self.report_sha256 != expected:
            raise ValueError("qualification preparation seal does not match")
        return self


class Phase2PreparationIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.v111-phase2-preparation-index.v1"] = Field(
        default="legalbot.v111-phase2-preparation-index.v1", alias="schema"
    )
    authorizing: Literal[False]
    contract_filename: Literal["certification-contract-draft.json"]
    contract_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    contract_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_filename: Literal["qualification-currentness-preparation.json"]
    qualification_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_semantic_closure_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_code_commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    exact_code_tree_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    index_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def index_seal_matches(self) -> Self:
        expected = _artifact_sha256(
            self.model_dump(mode="json", by_alias=True), field="index_sha256"
        )
        if self.index_sha256 != expected:
            raise ValueError("Phase-2 preparation index seal does not match")
        return self


@dataclass(frozen=True, slots=True)
class Phase2PreparationPackage:
    contract: CertificationContractDraft
    qualification: QualificationPreparationReport


@dataclass(frozen=True, slots=True)
class _CatalogueSnapshot:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    link_count: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _catalogue_snapshot(descriptor: int) -> _CatalogueSnapshot:
    observed = os.fstat(descriptor)
    if (
        not stat.S_ISREG(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o600
        or observed.st_nlink != 1
    ):
        raise RuntimeError("Phase-2 catalogue must be one private owner file")
    return _CatalogueSnapshot(
        device=observed.st_dev,
        inode=observed.st_ino,
        uid=observed.st_uid,
        gid=observed.st_gid,
        mode=observed.st_mode,
        link_count=observed.st_nlink,
        size=observed.st_size,
        modified_ns=observed.st_mtime_ns,
        changed_ns=observed.st_ctime_ns,
        sha256=_descriptor_sha256(descriptor),
    )


def _catalogue_sidecars(path: Path) -> tuple[Path, Path, Path]:
    return Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal")


class ImmutablePhase2Catalogue:
    """A pinned, immutable SQLite reader that cannot create catalogue state."""

    def __init__(
        self,
        *,
        path: Path,
        descriptor: int,
        connection: sqlite3.Connection,
        snapshot: _CatalogueSnapshot,
    ) -> None:
        self.path = path
        self._descriptor = descriptor
        self._connection = connection
        self._snapshot = snapshot
        self._closed = False

    def _require_no_sidecars(self) -> None:
        if any(os.path.lexists(path) for path in _catalogue_sidecars(self.path)):
            raise RuntimeError("Phase-2 immutable catalogue refuses journal sidecar state")

    def _require_unchanged(self, *, include_hash: bool = False) -> None:
        if self._closed:
            raise RuntimeError("Phase-2 immutable catalogue is closed")
        self._require_no_sidecars()
        if self.path.resolve(strict=True) != self.path:
            raise RuntimeError("Phase-2 catalogue path became symbolic or indirect")
        path_stat = os.stat(self.path, follow_symlinks=False)
        descriptor_stat = os.fstat(self._descriptor)
        expected = self._snapshot
        observed = (
            path_stat.st_dev,
            path_stat.st_ino,
            path_stat.st_uid,
            path_stat.st_gid,
            path_stat.st_mode,
            path_stat.st_nlink,
            path_stat.st_size,
            path_stat.st_mtime_ns,
            path_stat.st_ctime_ns,
        )
        pinned = (
            descriptor_stat.st_dev,
            descriptor_stat.st_ino,
            descriptor_stat.st_uid,
            descriptor_stat.st_gid,
            descriptor_stat.st_mode,
            descriptor_stat.st_nlink,
            descriptor_stat.st_size,
            descriptor_stat.st_mtime_ns,
            descriptor_stat.st_ctime_ns,
        )
        baseline = (
            expected.device,
            expected.inode,
            expected.uid,
            expected.gid,
            expected.mode,
            expected.link_count,
            expected.size,
            expected.modified_ns,
            expected.changed_ns,
        )
        if observed != baseline or pinned != baseline:
            raise RuntimeError("Phase-2 catalogue identity or stat changed during read")
        if include_hash and _descriptor_sha256(self._descriptor) != expected.sha256:
            raise RuntimeError("Phase-2 catalogue bytes changed during read")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_unchanged()
        self._connection.execute("BEGIN")
        try:
            yield self._connection
        finally:
            self._connection.rollback()
            self._require_unchanged()

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        self._require_unchanged()
        row = cast(sqlite3.Row | None, self._connection.execute(sql, params).fetchone())
        self._require_unchanged()
        return row

    def close(self) -> None:
        if self._closed:
            return
        failure: BaseException | None = None
        try:
            self._require_unchanged(include_hash=True)
        except BaseException as exc:
            failure = exc
        try:
            self._connection.close()
        finally:
            os.close(self._descriptor)
            self._closed = True
        if failure is not None:
            raise failure

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()


def open_immutable_phase2_catalogue(path: Path) -> ImmutablePhase2Catalogue:
    """Open one pre-existing catalogue with SQLite immutable read-only semantics."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("secure no-follow catalogue open is unavailable")
    absolute = path.absolute()
    if absolute.parent.resolve(strict=True) != absolute.parent:
        raise RuntimeError("Phase-2 catalogue ancestors may not be symbolic links")
    if any(os.path.lexists(sidecar) for sidecar in _catalogue_sidecars(absolute)):
        raise RuntimeError("Phase-2 immutable catalogue refuses journal sidecar state")
    descriptor = os.open(absolute, os.O_RDONLY | no_follow)
    connection: sqlite3.Connection | None = None
    try:
        snapshot = _catalogue_snapshot(descriptor)
        path_stat = os.stat(absolute, follow_symlinks=False)
        if (path_stat.st_dev, path_stat.st_ino) != (snapshot.device, snapshot.inode):
            raise RuntimeError("Phase-2 catalogue path is not the pinned file")
        connection = sqlite3.connect(
            f"{absolute.as_uri()}?mode=ro&immutable=1",
            uri=True,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            raise RuntimeError("Phase-2 catalogue query-only mode is unavailable")
        database_rows = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [Path(str(row[2])) for row in database_rows if str(row[1]) == "main"]
        if len(main_paths) != 1 or main_paths[0] != absolute:
            raise RuntimeError("Phase-2 catalogue connection opened a different file")
        integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
        if integrity != ["ok"]:
            raise RuntimeError("Phase-2 catalogue integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("Phase-2 catalogue foreign-key check failed")
        reader = ImmutablePhase2Catalogue(
            path=absolute,
            descriptor=descriptor,
            connection=connection,
            snapshot=snapshot,
        )
        reader._require_unchanged()
        return reader
    except BaseException:
        if connection is not None:
            connection.close()
        os.close(descriptor)
        raise


def _exact_commit_tree_sha(project_root: Path, commit_sha: str) -> str:
    """Resolve the checked commit tree with trusted Git and no ambient config."""

    if _GIT_SHA.fullmatch(commit_sha) is None:
        raise ValueError("integration SHA is invalid")
    root = project_root.resolve(strict=True)
    git = Path("/usr/bin/git")
    if git.is_symlink() or not git.is_file() or git.stat().st_uid != 0:
        raise RuntimeError("trusted system Git executable is unavailable")
    result = subprocess.run(
        [
            str(git),
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(root),
            "rev-parse",
            "--verify",
            f"{commit_sha}^{{tree}}",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        },
        shell=False,
    )
    tree = result.stdout.strip()
    if result.returncode != 0 or _GIT_SHA.fullmatch(tree) is None:
        raise RuntimeError("integration commit tree identity is invalid")
    return tree


def exact_clean_code_binding(project_root: Path, *, expected_head: str) -> CodeBinding:
    """Return raw-byte-verified Git identity for one clean, caller-pinned HEAD."""

    if _GIT_SHA.fullmatch(expected_head) is None:
        raise ValueError("expected HEAD is invalid")
    head = require_exact_clean_head(project_root, expected_head)
    tree = _exact_commit_tree_sha(project_root, head)
    return CodeBinding(commit_sha=head, tree_sha=tree, worktree_clean=True)


def candidate_binding(candidate: SealedCandidateIdentity) -> CandidateBinding:
    if candidate.status != "candidate":
        raise ValueError("candidate status is not eligible for Phase-2 preparation")
    return CandidateBinding(
        build_id=candidate.build_id,
        status=cast(Literal["candidate"], candidate.status),
        manifest_sha256=candidate.candidate_manifest_sha256,
        seal_sha256=candidate.candidate_seal_sha256,
        source_manifest_sha256=candidate.source_manifest_sha256,
        document_count=candidate.document_count,
        chunk_count=candidate.chunk_count,
        vector_count=candidate.vector_count,
        embedding_model=candidate.embedding_model,
        reranker_model=candidate.reranker_model,
    )


def _closure_component_sha256(schema_name: str, value: Any) -> str:
    return _sha256_bytes(canonical_json({"schema": schema_name, "value": value}))


def build_retrieval_evidence_binding(
    *,
    selected_attestation_schema: str,
    selected_attestation_sha256: str,
    selected_attestation_history_id: str,
    selected_integration_commit: str,
    selected_closure_manifest_file_sha256: str,
    selected_closure_manifest_sha256: str,
    selected_closure: Mapping[str, Any],
    current_closure: Mapping[str, Any],
    code: CodeBinding,
) -> RetrievalEvidenceBinding:
    """Prove closure equality while deliberately ignoring only Git identity."""

    selected_members = selected_closure.get("members")
    current_members = current_closure.get("members")
    selected_runtime = selected_closure.get("python_runtime")
    current_runtime = current_closure.get("python_runtime")
    selected_legacy = str(selected_closure.get("legacy_scorer_implementation_sha256") or "")
    current_legacy = str(current_closure.get("legacy_scorer_implementation_sha256") or "")
    selected_count = selected_closure.get("member_count")
    current_count = current_closure.get("member_count")
    if (
        not isinstance(selected_members, list)
        or not isinstance(current_members, list)
        or not isinstance(selected_runtime, Mapping)
        or not isinstance(current_runtime, Mapping)
        or isinstance(selected_count, bool)
        or not isinstance(selected_count, int)
        or isinstance(current_count, bool)
        or not isinstance(current_count, int)
        or selected_count <= 0
        or selected_count != len(selected_members)
        or current_count != len(current_members)
        or _SHA256.fullmatch(selected_legacy) is None
        or _SHA256.fullmatch(current_legacy) is None
    ):
        raise RuntimeError("scorer closure semantic material is malformed")
    selected_aggregate = str(selected_closure.get("aggregate_sha256") or "")
    current_aggregate = str(current_closure.get("aggregate_sha256") or "")
    if (
        _SHA256.fullmatch(selected_aggregate) is None
        or _SHA256.fullmatch(current_aggregate) is None
        or selected_closure.get("revision") != selected_integration_commit
        or current_closure.get("revision") != code.commit_sha
        or current_closure.get("tree") != code.tree_sha
    ):
        raise RuntimeError("scorer closure Git or aggregate binding is invalid")

    selected_member_set = _closure_component_sha256(
        "legalbot.scorer-closure-members.v1", selected_members
    )
    current_member_set = _closure_component_sha256(
        "legalbot.scorer-closure-members.v1", current_members
    )
    selected_runtime_sha256 = _closure_component_sha256(
        "legalbot.scorer-closure-python-runtime.v1", dict(selected_runtime)
    )
    current_runtime_sha256 = _closure_component_sha256(
        "legalbot.scorer-closure-python-runtime.v1", dict(current_runtime)
    )
    selected_semantic = _sha256_bytes(
        canonical_json(
            {
                "schema": _SCORER_SEMANTIC_SCHEMA,
                "members": selected_members,
                "python_runtime": dict(selected_runtime),
                "legacy_scorer_implementation_sha256": selected_legacy,
            }
        )
    )
    current_semantic = _sha256_bytes(
        canonical_json(
            {
                "schema": _SCORER_SEMANTIC_SCHEMA,
                "members": current_members,
                "python_runtime": dict(current_runtime),
                "legacy_scorer_implementation_sha256": current_legacy,
            }
        )
    )
    if (
        selected_members != current_members
        or dict(selected_runtime) != dict(current_runtime)
        or selected_legacy != current_legacy
        or selected_semantic != current_semantic
    ):
        raise RuntimeError("current scorer closure differs from selected historical proof")
    return RetrievalEvidenceBinding(
        selected_attestation_schema=cast(
            Literal["legalbot.retrieval-reattestation.v2"], selected_attestation_schema
        ),
        selected_attestation_sha256=selected_attestation_sha256,
        selected_attestation_history_id=selected_attestation_history_id,
        selected_integration_commit=selected_integration_commit,
        selected_closure_manifest_file_sha256=selected_closure_manifest_file_sha256,
        selected_closure_manifest_sha256=selected_closure_manifest_sha256,
        selected_closure_aggregate_sha256=selected_aggregate,
        current_closure_commit=code.commit_sha,
        current_closure_tree=code.tree_sha,
        current_closure_aggregate_sha256=current_aggregate,
        member_count=selected_count,
        selected_member_set_sha256=selected_member_set,
        current_member_set_sha256=current_member_set,
        selected_python_runtime_sha256=selected_runtime_sha256,
        current_python_runtime_sha256=current_runtime_sha256,
        selected_legacy_scorer_sha256=selected_legacy,
        current_legacy_scorer_sha256=current_legacy,
        selected_semantic_closure_sha256=selected_semantic,
        current_semantic_closure_sha256=current_semantic,
        equivalence_ignores=("revision", "tree"),
        semantic_equivalence_proven=True,
    )


def load_phase2_candidate_and_retrieval_evidence(
    *,
    settings: Settings,
    database: ImmutablePhase2Catalogue,
    candidate_build_id: str,
    code: CodeBinding,
) -> tuple[SealedCandidateIdentity, RetrievalEvidenceBinding]:
    """Verify sealed candidate and selected proof without requiring its old HEAD."""

    if _SAFE_BUILD_ID.fullmatch(candidate_build_id) is None:
        raise ValueError("candidate build ID is invalid")
    from ..retrieval.diagnostic_slice import refuse_diagnostic_slice_for_production
    from ..retrieval.retrieval_reattest import (
        REATTESTATION_SCHEMA,
        _attestation_path,
        _candidate_identity,
        _history_row,
        _require_exact_reattestation_schema,
        _validate_selected_artifact,
    )
    from ..retrieval.scorer_closure import (
        WorktreeReader,
        _current_python_runtime,
        build_closure,
        load_scorer_closure_reference,
    )

    refuse_diagnostic_slice_for_production(
        candidate_build_id, purpose="Phase-2 full-candidate preparation"
    )
    with database.transaction() as connection:
        _require_exact_reattestation_schema(connection)
    row_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (candidate_build_id,))
    if row_value is None:
        raise RuntimeError("Phase-2 candidate is absent from the immutable catalogue")
    row = dict(row_value)
    if str(row.get("status") or "") != "candidate" or str(row.get("stage") or "") != "candidate":
        raise RuntimeError("Phase-2 preparation requires the exact sealed candidate state")
    retrieval_identity = _candidate_identity(settings, row, verify_tree=True)
    history = _history_row(database, candidate_build_id)
    if history is None:
        raise RuntimeError("Phase-2 candidate has no selected retrieval attestation")
    selected = _validate_selected_artifact(
        settings,
        row,
        history,
        retrieval_identity,
        require_current_scorer=False,
    )
    if (
        selected.schema != REATTESTATION_SCHEMA
        or selected.history_id is None
        or selected.integration_sha is None
        or selected.scorer_closure_aggregate_sha256 is None
    ):
        raise RuntimeError("Phase-2 preparation requires a complete successor attestation")

    attestation_path = _attestation_path(settings, candidate_build_id, selected.path)
    attestation_raw = attestation_path.read_bytes()
    if _sha256_bytes(attestation_raw) != selected.sha256:
        raise RuntimeError("selected retrieval attestation changed during replay")
    attestation_payload = json.loads(attestation_raw)
    if not isinstance(attestation_payload, dict):
        raise RuntimeError("selected retrieval attestation is not an object")
    closure_value = attestation_payload.get("scorer_closure")
    if not isinstance(closure_value, Mapping):
        raise RuntimeError("selected retrieval evidence has no scorer closure reference")
    closure_relative = closure_value.get("manifest_path")
    if not isinstance(closure_relative, str) or not closure_relative:
        raise RuntimeError("selected scorer closure path is invalid")
    closure_path = settings.project_root / closure_relative
    closure_reference = load_scorer_closure_reference(
        project_root=settings.project_root,
        manifest_path=closure_path,
        require_current=False,
        expected_head=selected.integration_sha,
        expected_legacy_digest=selected.scorer_implementation_sha256,
    )
    if closure_reference.aggregate_sha256 != selected.scorer_closure_aggregate_sha256:
        raise RuntimeError("selected attestation and closure aggregate differ")
    closure_raw = closure_path.read_bytes()
    if _sha256_bytes(closure_raw) != closure_reference.manifest_file_sha256:
        raise RuntimeError("selected scorer closure changed during replay")
    closure_manifest = json.loads(closure_raw)
    selected_closure = (
        closure_manifest.get("integration_baseline_closure")
        if isinstance(closure_manifest, dict)
        else None
    )
    if not isinstance(selected_closure, Mapping):
        raise RuntimeError("selected scorer closure manifest has no baseline closure")
    current_closure = build_closure(
        WorktreeReader(settings.project_root),
        revision=code.commit_sha,
        tree=code.tree_sha,
        python_runtime=_current_python_runtime(),
    )
    retrieval_evidence = build_retrieval_evidence_binding(
        selected_attestation_schema=selected.schema,
        selected_attestation_sha256=selected.sha256,
        selected_attestation_history_id=selected.history_id,
        selected_integration_commit=selected.integration_sha,
        selected_closure_manifest_file_sha256=closure_reference.manifest_file_sha256,
        selected_closure_manifest_sha256=closure_reference.manifest_sha256,
        selected_closure=selected_closure,
        current_closure=current_closure,
        code=code,
    )
    manifest_path = settings.index_dir / "builds" / candidate_build_id / "manifest.json"
    seal_path = settings.index_dir / "builds" / candidate_build_id / "seal.json"
    candidate = SealedCandidateIdentity(
        build_id=candidate_build_id,
        status="candidate",
        candidate_manifest_sha256=_file_sha256(manifest_path),
        candidate_seal_sha256=_file_sha256(seal_path),
        source_manifest_sha256=retrieval_identity.source_manifest_sha256,
        embedding_model=retrieval_identity.embedding_model,
        reranker_model=retrieval_identity.reranker_model,
        document_count=retrieval_identity.document_count,
        chunk_count=retrieval_identity.chunk_count,
        vector_count=retrieval_identity.vector_count,
    )
    if str(row.get("manifest_sha256") or "") != candidate.candidate_seal_sha256:
        raise RuntimeError("candidate catalogue seal identity differs")
    return candidate, retrieval_evidence


def _registry_issue_rows(bundle: LiveEvaluationBundle) -> tuple[dict[str, str | int], ...]:
    rows: list[dict[str, str | int]] = []
    ordinal = 0
    for case in bundle.registry.cases:
        for issue_number, label in enumerate(case.must_cover_issues, start=1):
            ordinal += 1
            issue_id = f"issue-{issue_number:02d}"
            label_sha256 = _sha256_bytes(label.encode("utf-8"))
            identity = sealed_sha256(
                {
                    "schema": "legalbot.v111-registry-issue-identity.v1",
                    "ordinal": ordinal,
                    "case_id": case.case_id,
                    "case_record_sha256": case.record_sha256,
                    "issue_id": issue_id,
                    "issue_label_sha256": label_sha256,
                }
            )
            rows.append(
                {
                    "ordinal": ordinal,
                    "case_id": case.case_id,
                    "issue_id": issue_id,
                    "issue_label_sha256": label_sha256,
                    "registry_issue_identity_sha256": identity,
                }
            )
    return tuple(rows)


def registry_binding(bundle: LiveEvaluationBundle) -> RegistryBinding:
    rows = _registry_issue_rows(bundle)
    inventory_sha256 = sealed_sha256(
        {
            "schema": "legalbot.v111-registry-issue-inventory.v1",
            "issue_identity_sha256s": [
                str(item["registry_issue_identity_sha256"]) for item in rows
            ],
        }
    )
    return RegistryBinding(
        suite_id=bundle.manifest.suite_id,
        suite_version=bundle.manifest.suite_version,
        suite_manifest_seal_sha256=bundle.manifest.seal_sha256,
        registry_file_sha256=bundle.registry.file_sha256,
        registry_canonical_sha256=bundle.registry.canonical_sha256,
        run_plan_file_sha256=bundle.manifest.run_plan_sha256,
        case_count=bundle.registry.case_count,
        issue_count=len(rows),
        issue_inventory_sha256=inventory_sha256,
    )


def load_candidate_source_inventory(
    *, build_root: Path, candidate: SealedCandidateIdentity
) -> tuple[CandidateSourceInventory, CandidatePolicyBinding]:
    """Read descriptor-pinned aggregate identities from the exact candidate seal."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure candidate preparation replay is unavailable")

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def read_member(root_descriptor: int, name: str) -> bytes:
        descriptor = os.open(name, os.O_RDONLY | no_follow, dir_fd=root_descriptor)
        try:
            before = os.fstat(descriptor)
            path_before = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or before.st_size < 1
                or before.st_size > 256 * 1024 * 1024
                or identity(before) != identity(path_before)
            ):
                raise RuntimeError("candidate preparation artifact identity is unsafe")
            blocks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                block = os.read(descriptor, min(remaining, 1024 * 1024))
                if not block:
                    raise RuntimeError("candidate preparation artifact changed during replay")
                blocks.append(block)
                remaining -= len(block)
            if os.read(descriptor, 1):
                raise RuntimeError("candidate preparation artifact changed during replay")
            after = os.fstat(descriptor)
            path_after = os.stat(name, dir_fd=root_descriptor, follow_symlinks=False)
            if identity(before) != identity(after) or identity(before) != identity(path_after):
                raise RuntimeError("candidate preparation artifact changed during replay")
            return b"".join(blocks)
        finally:
            os.close(descriptor)

    root_descriptor = os.open(build_root, os.O_RDONLY | directory_flag | no_follow)
    try:
        root_before = os.fstat(root_descriptor)
        root_path_before = os.stat(build_root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_before.st_mode)
            or root_before.st_uid != os.getuid()
            or identity(root_before) != identity(root_path_before)
        ):
            raise RuntimeError("candidate build root identity is unsafe")
        seal_bytes = read_member(root_descriptor, "seal.json")
        source_bytes = read_member(root_descriptor, "approved-source-manifest.json")
        root_after = os.fstat(root_descriptor)
        root_path_after = os.stat(build_root, follow_symlinks=False)
        if identity(root_before) != identity(root_after) or identity(root_before) != identity(
            root_path_after
        ):
            raise RuntimeError("candidate build root changed during preparation replay")
    finally:
        os.close(root_descriptor)

    if _sha256_bytes(seal_bytes) != candidate.candidate_seal_sha256:
        raise RuntimeError("candidate seal bytes differ from the catalogue-bound candidate")
    source = json.loads(source_bytes)
    seal = json.loads(seal_bytes)
    if not isinstance(source, dict) or not isinstance(seal, dict):
        raise RuntimeError("candidate preparation artifacts are malformed")
    sources = source.get("sources")
    if not isinstance(sources, list):
        raise RuntimeError("candidate preparation artifacts are malformed")
    source_file_sha256 = _sha256_bytes(source_bytes)
    if (
        seal.get("manifest_sha256") != candidate.candidate_manifest_sha256
        or source.get("manifest_sha256") != candidate.source_manifest_sha256
        or seal.get("source_manifest_file_sha256") != source_file_sha256
        or int(source.get("source_count") or -1) != len(sources)
        or len(sources) != candidate.document_count
    ):
        raise RuntimeError("candidate source inventory does not match the sealed candidate")
    currentness = Counter(str(item.get("currentness_status") or "") for item in sources)
    inventory = CandidateSourceInventory(
        source_manifest_file_sha256=source_file_sha256,
        source_manifest_identity_sha256=candidate.source_manifest_sha256,
        candidate_snapshot_date=str(source.get("current_law_as_of_date") or ""),
        source_count=len(sources),
        authority_lane_count=sum(item.get("lane") == "primary_authority" for item in sources),
        latest_revised_snapshot_count=currentness["latest_available_revised_snapshot"],
        historical_authority_count=currentness["historical"],
        current_law_eligible_count=sum(
            item.get("full_current_law_verification_eligible") is True for item in sources
        ),
        subsequent_treatment_required_count=sum(
            item.get("subsequent_treatment_check_required") is True for item in sources
        ),
        subsequent_treatment_verified_count=sum(
            item.get("subsequent_treatment_verified") is True for item in sources
        ),
        omitted_required_family_count=len(source.get("omitted_required_families") or ()),
    )
    policies = CandidatePolicyBinding(
        quality_policy_sha256=str(seal.get("quality_policy_sha256") or ""),
        retrieval_policy_sha256=str(seal.get("retrieval_policy_sha256") or ""),
        assessment_guidance_sha256=str(seal.get("assessment_guidance_sha256") or ""),
        provision_verification_sha256=str(seal.get("provision_verification_sha256") or ""),
        source_manifest_file_sha256=source_file_sha256,
        index_tree_sha256=str(seal.get("lance_tree_sha256") or ""),
    )
    return inventory, policies


def _source_hierarchy() -> tuple[SourceHierarchyRule, ...]:
    return (
        SourceHierarchyRule(
            rank=1,
            source_class="official_legislation",
            may_support_material_claim=True,
            required_checks=(
                "identity",
                "extent",
                "effective_date",
                "repeal_and_amendment",
                "material_unapplied_effects",
            ),
        ),
        SourceHierarchyRule(
            rank=2,
            source_class="official_judgment_or_court_publication",
            may_support_material_claim=True,
            required_checks=(
                "identity",
                "jurisdiction",
                "precedential_role",
                "subsequent_treatment",
                "material_contrary_authority",
            ),
        ),
        SourceHierarchyRule(
            rank=3,
            source_class="official_rules_or_practice_direction",
            may_support_material_claim=True,
            required_checks=("identity", "jurisdiction", "in_force_at_cutoff", "amendments"),
        ),
        SourceHierarchyRule(
            rank=4,
            source_class="official_regulator_or_government_material",
            may_support_material_claim=True,
            required_checks=(
                "identity",
                "legal_role",
                "jurisdiction",
                "publication_date",
                "supersession",
            ),
        ),
    )


def build_phase2_preparation_package(
    *,
    generated_at: datetime,
    code: CodeBinding,
    candidate: SealedCandidateIdentity,
    bundle: LiveEvaluationBundle,
    candidate_sources: CandidateSourceInventory,
    candidate_policies: CandidatePolicyBinding,
    retrieval_evidence: RetrievalEvidenceBinding,
) -> Phase2PreparationPackage:
    """Build the exact non-authorizing draft and pending qualification inventory."""

    if generated_at.tzinfo is None:
        raise ValueError("generated_at must be timezone-aware")
    generated_at = generated_at.astimezone(UTC)
    candidate_model = candidate_binding(candidate)
    registry_model = registry_binding(bundle)

    contract_material: dict[str, Any] = {
        "schema": CONTRACT_SCHEMA,
        "document_state": "draft_owner_signature_required",
        "authorizing": False,
        "owner_signature_present": False,
        "development_run_authorized": False,
        "sealed_validation_authorized": False,
        "promotion_authorized": False,
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "code": code.model_dump(mode="json"),
        "candidate": candidate_model.model_dump(mode="json"),
        "registry": registry_model.model_dump(mode="json"),
        "candidate_policies": candidate_policies.model_dump(mode="json"),
        "retrieval_evidence": retrieval_evidence.model_dump(mode="json"),
        "currentness": CurrentnessPolicyDraft(
            jurisdiction="England and Wales",
            cutoff_state="pending_owner_official_source_review",
            candidate_snapshot_date_is_not_owner_cutoff=True,
            legislation_rule=(
                "verify_extent_effective_date_repeals_pending_changes_and_material_unapplied_effects"
            ),
            case_rule="verify_subsequent_treatment_and_precedential_role_through_owner_cutoff",
            pending_change_rule=(
                "not_current_law_until_in_force_at_cutoff_but_disclose_if_material"
            ),
            conflict_rule=(
                "bind_material_contrary_authority_and_explain_priority_or_limit_the_claim"
            ),
            material_delta_rule=(
                "candidate_reseal_requalification_reattestation_and_development_rerun"
            ),
            hierarchy=_source_hierarchy(),
        ).model_dump(mode="json"),
        "evidence": EvidencePolicyDraft(
            material_claim_requires_frozen_evidence_span=True,
            source_identity_jurisdiction_currentness_required=True,
            case_proposition_requires_reviewed_legal_role=True,
            model_generated_citations_allowed=False,
            deterministic_oscola_required=True,
            teaching_or_feedback_as_independent_authority_allowed=False,
            private_path_or_owner_identifier_allowed=False,
            unsupported_issue_disposition="verified_limited_or_held",
            invented_authority_tolerance=0,
            false_quotation_tolerance=0,
            unsupported_material_assertion_tolerance=0,
            unsupported_typed_material_fact_tolerance=0,
            non_atomic_material_claim_tolerance=0,
            material_contradiction_tolerance=0,
        ).model_dump(mode="json"),
        "scoring": ScoringPolicyDraft(
            issue_pass_rule=("qualified_positive_span_and_all_material_assertions_evidence_bound"),
            question_pass_rule=(
                "every_registry_issue_dispositioned_zero_hard_blockers_and_owner_adjudication_pass"
            ),
            aggregation_rule="no_average_may_mask_a_question_or_issue_failure",
            development_case_count=30,
            sealed_validation_case_count=30,
            stage_a_recall_at_5_minimum=1.0,
            stage_a_recall_at_10_minimum=0.95,
            stage_a_mrr_minimum=0.8,
            stage_a_filter_violation_maximum=0,
            required_validation_release_state="verified_full",
            minimum_validation_question_passes=30,
            automated_academic_target=70,
            automated_academic_target_is_legal_safety_gate=False,
            owner_adjudication_required=True,
            rubric_or_threshold_relaxation_after_results_allowed=False,
        ).model_dump(mode="json"),
        "execution": ExecutionPolicyDraft(
            generation_concurrency=1,
            maximum_memory_bytes=12884901888,
            minimum_free_memory_bytes=3221225472,
            model_transport="private_unix_domain_socket",
            first_live_bind="127.0.0.1",
            preflight_failure_consumes_sealed_run=False,
            run_begins="first_committed_answer_generation_request",
            quality_motivated_selective_rerun_allowed=False,
            maximum_same_failure_fingerprint=2,
            transient_attempt_limit_per_case=2,
            resume_requires_same_run_and_authenticated_checkpoint=True,
            resume_requires_unchanged_snapshot_and_unexposed_output=True,
            missing_case_disposition="failure_unless_frozen_invalid_run_rule_applies",
            result_exposure_ends_sealed_status=True,
        ).model_dump(mode="json"),
        "preservation": PreservationPolicyDraft(
            create_only_artifacts=True,
            prior_cycles_immutable=True,
            raw_question_answer_and_review_storage="owner_private_lane_specific_roots",
            ordinary_logs_may_contain_question_or_answer_text=False,
            ordinary_logs_may_contain_private_paths=False,
            development_and_validation_roots_must_differ=True,
            validation_outputs_hidden_until_valid_o04=True,
            training_export_allowed=False,
            cloud_or_publication_allowed=False,
        ).model_dump(mode="json"),
        "freeze_requirements": FreezeRequirements(
            owner_signature_mechanism="ed25519_public_key_pending_signed_package",
            owner_cutoff="pending",
            exact_prompt_sha256="pending_production_candidate_freeze",
            exact_model_and_runtime_sha256="pending_production_candidate_freeze",
            evaluator_and_reviewer_sha256="pending_production_candidate_freeze",
            split_manifest_sha256="pending_post_qualification_owner_secret",
            private_review_roots="pending_signed_non_synced_root_bindings",
            local_security_material="pending_signed_package_and_local_provisioning",
        ).model_dump(mode="json"),
    }
    contract_material["contract_draft_sha256"] = _artifact_sha256(
        contract_material, field="contract_draft_sha256"
    )
    contract = CertificationContractDraft.model_validate(contract_material)

    issue_rows = _registry_issue_rows(bundle)
    rows_by_case: dict[str, list[dict[str, str | int]]] = {}
    for row in issue_rows:
        rows_by_case.setdefault(str(row["case_id"]), []).append(row)
    cases: list[QualificationCasePreparation] = []
    for case in bundle.registry.cases:
        issues = tuple(
            QualificationIssuePreparation(
                issue_id=str(row["issue_id"]),
                issue_label_sha256=str(row["issue_label_sha256"]),
                registry_issue_identity_sha256=str(row["registry_issue_identity_sha256"]),
                qualification_state="pending_official_source_and_currentness_review",
                gold_evidence_state="not_assessed",
                material_gap_state="not_assessed",
            )
            for row in rows_by_case[case.case_id]
        )
        cases.append(
            QualificationCasePreparation(
                ordinal=case.ordinal,
                case_id=case.case_id,
                question_sha256=case.question_sha256,
                record_sha256=case.record_sha256,
                task_type=case.task_type,
                subject_sha256=_sha256_bytes(case.subject.encode("utf-8")),
                issue_count=len(issues),
                issues=issues,
                qualification_state="pending_official_source_and_currentness_review",
            )
        )
    report_material: dict[str, Any] = {
        "schema": QUALIFICATION_PREPARATION_SCHEMA,
        "document_state": "preparation_only_owner_currentness_decision_required",
        "authorizing": False,
        "legally_qualified": False,
        "answer_model_invoked": False,
        "stage_a_invoked": False,
        "development_30_invoked": False,
        "split_created": False,
        "candidate_changed": False,
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "code": code.model_dump(mode="json"),
        "candidate": candidate_model.model_dump(mode="json"),
        "registry": registry_model.model_dump(mode="json"),
        "candidate_sources": candidate_sources.model_dump(mode="json"),
        "retrieval_evidence": retrieval_evidence.model_dump(mode="json"),
        "owner_cutoff_date": None,
        "workflow": (
            "stage_official_primary_source_currentness_review_without_owner_cutoff",
            "record_dated_potential_material_deltas_and_gaps_for_owner_review",
            "owner_decides_and_signs_exact_cutoff_and_materiality_rule",
            "replay_official_primary_sources_through_signed_cutoff",
            "verify_identity_jurisdiction_effective_date_repeal_and_pending_changes",
            "verify_case_precedential_role_subsequent_treatment_and_contrary_authority",
            "bind_each_registry_issue_to_positive_frozen_spans_or_record_material_gap",
            "verify_exact_candidate_membership_and_source_rights_for_every_span",
            "record_ambiguity_conflict_and_abstention_or_limited_disposition",
            "independently_review_all_issue_evidence_without_stage_a_results",
            "freeze_create_only_qualification_bound_to_candidate_registry_cutoff_and_code",
        ),
        "cases": [item.model_dump(mode="json") for item in cases],
        "pending_case_count": len(cases),
        "pending_issue_count": len(issue_rows),
    }
    report_material["report_sha256"] = _artifact_sha256(report_material, field="report_sha256")
    qualification = QualificationPreparationReport.model_validate(report_material)
    return Phase2PreparationPackage(contract=contract, qualification=qualification)


def _write_private_create_only(path: Path, payload: BaseModel) -> bytes:
    encoded = canonical_json(payload.model_dump(mode="json", by_alias=True))
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError("Phase-2 preparation artifact permissions are unsafe")
    return encoded


def write_phase2_preparation_package(
    output_directory: Path, package: Phase2PreparationPackage
) -> Phase2PreparationIndex:
    """Create one private directory containing the two non-authorizing artifacts."""

    output_directory = output_directory.resolve()
    if output_directory.exists():
        raise FileExistsError(output_directory)
    output_directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_directory.mkdir(mode=0o700)
    try:
        contract_bytes = _write_private_create_only(
            output_directory / CONTRACT_FILENAME, package.contract
        )
        qualification_bytes = _write_private_create_only(
            output_directory / QUALIFICATION_FILENAME, package.qualification
        )
        index_material: dict[str, Any] = {
            "schema": PREPARATION_INDEX_SCHEMA,
            "authorizing": False,
            "contract_filename": CONTRACT_FILENAME,
            "contract_file_sha256": _sha256_bytes(contract_bytes),
            "contract_draft_sha256": package.contract.contract_draft_sha256,
            "qualification_filename": QUALIFICATION_FILENAME,
            "qualification_file_sha256": _sha256_bytes(qualification_bytes),
            "qualification_report_sha256": package.qualification.report_sha256,
            "retrieval_semantic_closure_sha256": (
                package.contract.retrieval_evidence.current_semantic_closure_sha256
            ),
            "exact_code_commit_sha": package.contract.code.commit_sha,
            "exact_code_tree_sha": package.contract.code.tree_sha,
        }
        index_material["index_sha256"] = _artifact_sha256(index_material, field="index_sha256")
        index = Phase2PreparationIndex.model_validate(index_material)
        _write_private_create_only(output_directory / INDEX_FILENAME, index)
        return index
    except BaseException:
        shutil.rmtree(output_directory)
        raise


def verify_phase2_preparation_package(output_directory: Path) -> Phase2PreparationIndex:
    """Strictly replay the non-authorizing package; never convert it into authority."""

    if not output_directory.is_absolute() or output_directory != output_directory.resolve(
        strict=True
    ):
        raise RuntimeError("Phase-2 preparation directory identity is unsafe")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure Phase-2 preparation replay is unavailable")

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    descriptor = os.open(output_directory, os.O_RDONLY | directory_flag | no_follow)
    try:
        root_before = os.fstat(descriptor)
        path_before = os.stat(output_directory, follow_symlinks=False)
        expected_names = {CONTRACT_FILENAME, QUALIFICATION_FILENAME, INDEX_FILENAME}
        if (
            not stat.S_ISDIR(root_before.st_mode)
            or root_before.st_uid != os.getuid()
            or stat.S_IMODE(root_before.st_mode) != 0o700
            or identity(root_before) != identity(path_before)
            or set(os.listdir(descriptor)) != expected_names
        ):
            raise RuntimeError("Phase-2 preparation directory members are unsafe")

        members: dict[str, bytes] = {}
        for name in sorted(expected_names):
            member = os.open(name, os.O_RDONLY | no_follow, dir_fd=descriptor)
            try:
                before = os.fstat(member)
                member_path_before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or before.st_size < 1
                    or before.st_size > 32 * 1024 * 1024
                    or identity(before) != identity(member_path_before)
                ):
                    raise RuntimeError("Phase-2 preparation artifact identity is unsafe")
                blocks: list[bytes] = []
                remaining = before.st_size
                while remaining:
                    block = os.read(member, min(remaining, 1024 * 1024))
                    if not block:
                        raise RuntimeError("Phase-2 preparation artifact changed during replay")
                    blocks.append(block)
                    remaining -= len(block)
                if os.read(member, 1):
                    raise RuntimeError("Phase-2 preparation artifact changed during replay")
                after = os.fstat(member)
                member_path_after = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if identity(before) != identity(after) or identity(before) != identity(
                    member_path_after
                ):
                    raise RuntimeError("Phase-2 preparation artifact changed during replay")
                members[name] = b"".join(blocks)
            finally:
                os.close(member)
        root_after = os.fstat(descriptor)
        path_after = os.stat(output_directory, follow_symlinks=False)
        if (
            identity(root_before) != identity(root_after)
            or identity(root_before) != identity(path_after)
            or set(os.listdir(descriptor)) != expected_names
        ):
            raise RuntimeError("Phase-2 preparation directory changed during replay")
    finally:
        os.close(descriptor)

    contract_bytes = members[CONTRACT_FILENAME]
    qualification_bytes = members[QUALIFICATION_FILENAME]
    index_bytes = members[INDEX_FILENAME]
    contract = CertificationContractDraft.model_validate_json(contract_bytes)
    qualification = QualificationPreparationReport.model_validate_json(qualification_bytes)
    index = Phase2PreparationIndex.model_validate_json(index_bytes)
    if (
        _sha256_bytes(contract_bytes) != index.contract_file_sha256
        or _sha256_bytes(qualification_bytes) != index.qualification_file_sha256
        or contract.contract_draft_sha256 != index.contract_draft_sha256
        or qualification.report_sha256 != index.qualification_report_sha256
        or contract.code != qualification.code
        or contract.candidate != qualification.candidate
        or contract.registry != qualification.registry
        or contract.retrieval_evidence != qualification.retrieval_evidence
        or (
            contract.retrieval_evidence.current_semantic_closure_sha256
            != index.retrieval_semantic_closure_sha256
        )
        or contract.code.commit_sha != index.exact_code_commit_sha
        or contract.code.tree_sha != index.exact_code_tree_sha
    ):
        raise RuntimeError("Phase-2 preparation package binding does not replay")
    return index
