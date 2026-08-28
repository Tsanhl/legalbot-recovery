"""Owner-quality canary authorization without changing frozen Live60 readers.

Development authorization is candidate-pinned and explicitly independent of
``ACTIVE`` and O-04.  Blind-holdout authorization is a separate schema and is
issued only after externally supplied, sealed promotion, operations and
owner-signed O-04 artifacts all bind the exact complementary holdout lane.

This module can create technical execution authorizations.  It deliberately
has no function that creates an owner signature, O-04, promotion, operations
proof, ``ACTIVE`` or ``PREVIOUS``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import Settings
from ..model_runtime.config import PINNED_RUNTIME_MODEL_VERSION, PINNED_RUNTIME_REPO
from ..orchestration.retry_policy import MAX_ATTEMPTS, MAX_RETRIES
from ..quality.ai_evidence_reviewer import (
    AI_EVIDENCE_REVIEWER_ROLE,
    AI_REVIEWER_EXECUTION_MODE,
    ai_evidence_reviewer_prompt_sha256,
    ai_evidence_reviewer_toolchain_sha256,
)
from ..quality.policy import POLICY_SHA256
from ..retrieval.relevance_policy import (
    FROZEN_STATUS,
    RelevanceThresholdPolicy,
    load_relevance_threshold_policy,
)
from ..runtime_adapters import (
    DRAFT_SYSTEM_PROMPT_SHA256,
    GENERATION_CONFIG_SHA256,
    PROMPT_VERSION,
    STRUCTURED_DRAFT_SCHEMA_SHA256,
)
from .live30 import _exclusive_write, _private_directory, assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_gold import LiveSuiteExpertQualification
from .live_suite_stage_a_v2 import STAGE_A_V2_SCHEMA
from .live_suite_stage_a_v2_runner import (
    STAGE_A_RUNNER_POLICY_SHA256,
    STAGE_A_SCORER_IDENTITY_SHA256,
    UNBOUND_COMPLETION_PREFLIGHT_SHA256,
    load_verified_stage_a_v2_artifact_set,
    validate_stage_a_inputs,
)
from .owner_quality_canary import (
    All60CaseQualification,
    OwnerQualityCanaryManifest,
)
from .quality_implementation_identity import quality_implementation_identities
from .sealed_candidate import SealedCandidateIdentity

DEVELOPMENT_AUTHORIZATION_SCHEMA = "legalbot.owner-quality-canary-development-authorization.v1"
HOLDOUT_AUTHORIZATION_SCHEMA = "legalbot.owner-quality-canary-holdout-authorization.v1"
PROMOTED_ACTIVE_PROOF_SCHEMA = "legalbot.owner-quality-promoted-active-proof.v1"
OPERATIONAL_PROOF_SCHEMA = "legalbot.owner-quality-operational-proof.v1"
OWNER_QUALITY_O04_SCHEMA = "legalbot.owner-quality-o04-approval.v1"
POLICY_BINDINGS_SCHEMA = "legalbot.owner-quality-canary-policy-bindings.v2"

OWNER_CANARY_RETRY_POLICY_VERSION = "legalbot.owner-canary-retry-policy.v1"
OWNER_CANARY_RETRY_POLICY = {
    "schema": OWNER_CANARY_RETRY_POLICY_VERSION,
    "initial_attempt_count": 1,
    "maximum_retry_count": MAX_RETRIES,
    "maximum_attempt_count": MAX_ATTEMPTS,
    "retry_requires_changed_input_identity": True,
    "deterministic_safety_retry_allowed": False,
    "repeated_failure_fingerprint_retry_allowed": False,
    "word_tolerance_percent": 5,
    "serial_stop_before_next_case": True,
}
OWNER_CANARY_RETRY_POLICY_SHA256 = sealed_sha256(OWNER_CANARY_RETRY_POLICY)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INTEGRATION_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_LOCAL_INTEGRATION_ROOT = Path(__file__).resolve().parents[3]

OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
UNBOUND_COMPLETION_PREFLIGHT_REF = "legacy-completion-preflight-unbound"
UNBOUND_COMPLETION_PREFLIGHT_SEAL = "0" * 64


class OwnerDecisionRequired(RuntimeError):
    """Fail-closed stop for an owner judgment with no trusted verifier."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(OWNER_DECISION_REQUIRED)


def _local_clean_integration_sha(project_root: Path) -> str:
    """Derive authorization provenance from the local clean checkout."""

    from ..retrieval.retrieval_reattest import _clean_integration_sha

    return _clean_integration_sha(project_root)


def _sealed_model_is_valid(value: BaseModel) -> bool:
    dumped = value.model_dump(mode="json", by_alias=True)
    observed = str(dumped.get("seal_sha256") or "")
    if observed == sealed_sha256(dumped):
        return True
    # Backwards-safe reader only.  Pre-hardening rows did not carry the Stage A
    # run identity or authoritative completion-preflight binding.  They may
    # still be inspected, but runtime replay rejects either sentinel before
    # they can authorize work.
    if dumped.get("stage_a_run_id") == "legacy-stage-a-unbound" or (
        dumped.get("completion_preflight_artifact_ref") == UNBOUND_COMPLETION_PREFLIGHT_REF
        and dumped.get("completion_preflight_verified_result_sha256")
        == UNBOUND_COMPLETION_PREFLIGHT_SEAL
        and dumped.get("completion_preflight_authoritative") is False
    ):
        legacy = dict(dumped)
        if dumped.get("stage_a_run_id") == "legacy-stage-a-unbound":
            legacy.pop("stage_a_run_id", None)
        if (
            dumped.get("completion_preflight_artifact_ref") == UNBOUND_COMPLETION_PREFLIGHT_REF
            and dumped.get("completion_preflight_verified_result_sha256")
            == UNBOUND_COMPLETION_PREFLIGHT_SEAL
            and dumped.get("completion_preflight_authoritative") is False
        ):
            legacy.pop("completion_preflight_artifact_ref", None)
            legacy.pop("completion_preflight_verified_result_sha256", None)
            legacy.pop("completion_preflight_authoritative", None)
        return observed == sealed_sha256(legacy)
    return False


class OwnerCanaryPolicyBindings(BaseModel):
    """Exact retry, standards and independent-review identities."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-canary-policy-bindings.v2"] = Field(
        default="legalbot.owner-quality-canary-policy-bindings.v2", alias="schema"
    )
    retry_policy_version: Literal["legalbot.owner-canary-retry-policy.v1"]
    retry_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standards_bundle_version: str = Field(min_length=1, max_length=127)
    standards_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer_model_id: str = Field(min_length=1, max_length=255)
    answer_model_version: str = Field(min_length=1, max_length=255)
    draft_prompt_version: str = Field(min_length=1, max_length=255)
    draft_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    structured_draft_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    relevance_threshold_policy_version: str = Field(min_length=1, max_length=255)
    relevance_threshold_policy_status: Literal["FROZEN_CALIBRATED"]
    relevance_threshold_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    semantic_relevance_threshold: float = Field(ge=0.0, le=1.0)
    ai_reviewer_role: Literal["ai_evidence_reviewer"]
    ai_reviewer_execution_mode: Literal["separate_verification_pass_same_model_adapter"]
    ai_reviewer_model_independent: Literal[False]
    ai_reviewer_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_reviewer_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_reviewer_toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_reviewer_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluator_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standards_scorer_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    quality_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def policy_identities_are_tracked_and_sealed(self) -> Self:
        implementations = quality_implementation_identities()
        expected = {
            "retry_policy_version": OWNER_CANARY_RETRY_POLICY_VERSION,
            "retry_policy_sha256": OWNER_CANARY_RETRY_POLICY_SHA256,
            "standards_bundle_version": OWNER_ASSESSMENT_BUNDLE.version,
            "standards_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
            "answer_model_id": PINNED_RUNTIME_REPO,
            "answer_model_version": PINNED_RUNTIME_MODEL_VERSION,
            "draft_prompt_version": PROMPT_VERSION,
            "draft_prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
            "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
            "generation_config_sha256": GENERATION_CONFIG_SHA256,
            "ai_reviewer_role": AI_EVIDENCE_REVIEWER_ROLE,
            "ai_reviewer_execution_mode": AI_REVIEWER_EXECUTION_MODE,
            "ai_reviewer_model_independent": False,
            "ai_reviewer_prompt_sha256": ai_evidence_reviewer_prompt_sha256(),
            "ai_reviewer_policy_sha256": POLICY_SHA256,
            "ai_reviewer_toolchain_sha256": ai_evidence_reviewer_toolchain_sha256(),
            "ai_reviewer_implementation_sha256": implementations.ai_reviewer_sha256,
            "evaluator_implementation_sha256": implementations.evaluator_sha256,
            "standards_scorer_implementation_sha256": (implementations.standards_scorer_sha256),
            "quality_implementation_sha256": implementations.combined_sha256,
        }
        for field, expected_value in expected.items():
            if getattr(self, field) != expected_value:
                raise ValueError("owner-canary policy identity differs from tracked bytes")
        if not _sealed_model_is_valid(self):
            raise ValueError("owner-canary policy bindings seal does not match")
        return self


def _relevance_policy_for_authorization(
    settings: Settings | None,
) -> RelevanceThresholdPolicy:
    if settings is None:
        return load_relevance_threshold_policy(
            _LOCAL_INTEGRATION_ROOT / "config" / "relevance_threshold_policy.v1.json",
            test_mode=True,
        )
    policy = load_relevance_threshold_policy(
        settings.relevance_threshold_policy_path,
        test_mode=settings.test_mode,
    )
    if not policy.frozen:
        raise OwnerDecisionRequired("relevance_threshold_policy_not_frozen")
    return policy


def owner_canary_policy_bindings(*, settings: Settings | None = None) -> OwnerCanaryPolicyBindings:
    """Build policy bindings entirely from tracked local identities."""

    implementations = quality_implementation_identities()
    relevance_policy = _relevance_policy_for_authorization(settings)
    if relevance_policy.semantic_threshold is None:
        raise OwnerDecisionRequired("relevance_threshold_policy_not_frozen")
    material: dict[str, Any] = {
        "schema": POLICY_BINDINGS_SCHEMA,
        "retry_policy_version": OWNER_CANARY_RETRY_POLICY_VERSION,
        "retry_policy_sha256": OWNER_CANARY_RETRY_POLICY_SHA256,
        "standards_bundle_version": OWNER_ASSESSMENT_BUNDLE.version,
        "standards_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "answer_model_id": PINNED_RUNTIME_REPO,
        "answer_model_version": PINNED_RUNTIME_MODEL_VERSION,
        "draft_prompt_version": PROMPT_VERSION,
        "draft_prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
        "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
        "generation_config_sha256": GENERATION_CONFIG_SHA256,
        "relevance_threshold_policy_version": relevance_policy.version,
        "relevance_threshold_policy_status": FROZEN_STATUS,
        "relevance_threshold_policy_sha256": relevance_policy.policy_sha256,
        "semantic_relevance_threshold": relevance_policy.semantic_threshold,
        "ai_reviewer_role": AI_EVIDENCE_REVIEWER_ROLE,
        "ai_reviewer_execution_mode": AI_REVIEWER_EXECUTION_MODE,
        "ai_reviewer_model_independent": False,
        "ai_reviewer_prompt_sha256": ai_evidence_reviewer_prompt_sha256(),
        "ai_reviewer_policy_sha256": POLICY_SHA256,
        "ai_reviewer_toolchain_sha256": ai_evidence_reviewer_toolchain_sha256(),
        "ai_reviewer_implementation_sha256": implementations.ai_reviewer_sha256,
        "evaluator_implementation_sha256": implementations.evaluator_sha256,
        "standards_scorer_implementation_sha256": implementations.standards_scorer_sha256,
        "quality_implementation_sha256": implementations.combined_sha256,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerCanaryPolicyBindings.model_validate(material)


class PromotedActiveCandidateProof(BaseModel):
    """Externally created proof that the exact candidate is reconciled ACTIVE."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-promoted-active-proof.v1"] = Field(
        default="legalbot.owner-quality-promoted-active-proof.v1", alias="schema"
    )
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    active_pointer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_promotion_ref: str = Field(pattern=r"^promotion:[0-9a-f]{64}$")
    catalogue_active_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    pointer_active_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    active_reconciled: Literal[True]
    verified_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def promoted_active_is_exact_and_sealed(self) -> Self:
        if (
            self.catalogue_active_build_id != self.candidate_build_id
            or self.pointer_active_build_id != self.candidate_build_id
        ):
            raise ValueError("promoted ACTIVE identities are not reconciled")
        if not _sealed_model_is_valid(self):
            raise ValueError("promoted ACTIVE proof seal does not match")
        return self


class OwnerCanaryOperationalProof(BaseModel):
    """Externally created all-green owner-only operational evidence bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-operational-proof.v1"] = Field(
        default="legalbot.owner-quality-operational-proof.v1", alias="schema"
    )
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    promoted_active_proof_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_only_smoke_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rollback_repromotion_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    browser_recovery_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    readiness_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    disk_heartbeat_lease_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_only: Literal[True]
    loopback_only: Literal[True]
    operational_proof_passed: Literal[True]
    blocking_gate_count: Literal[0]
    verified_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def operational_proof_is_sealed(self) -> Self:
        if not _sealed_model_is_valid(self):
            raise ValueError("owner-canary operational proof seal does not match")
        return self


class OwnerQualityO04Approval(BaseModel):
    """Reader contract for an externally owner-signed holdout O-04 artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-quality-o04-approval.v1"] = Field(
        default="legalbot.owner-quality-o04-approval.v1", alias="schema"
    )
    decision_code: Literal["O-04"]
    approval_id: str = Field(pattern=r"^o04:[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["blind_holdout"]
    canary_manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Legacy rows parse for safe inspection but cannot replay because this
    # sentinel has no private Stage-A artifact directory.
    stage_a_run_id: str = Field(
        default="legacy-stage-a-unbound",
        pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$",
    )
    stage_a_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    policy_bindings_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    promoted_active_proof_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_proof_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorized_case_ids: tuple[str, ...]
    authorized_pass_count: Literal[1]
    one_serial_pass: Literal[True]
    owner_signed: Literal[True]
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    owner_signature_ref: str = Field(pattern=r"^signature:[0-9a-f]{64}$")
    signature_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_verified: Literal[True]
    signed_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("authorized_case_ids")
    @classmethod
    def authorized_ids_are_exactly_thirty_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != 30 or len(set(values)) != 30:
            raise ValueError("owner-quality O-04 must name exactly 30 unique cases")
        if any(not _CASE_ID.fullmatch(value) for value in values):
            raise ValueError("owner-quality O-04 contains an invalid case ID")
        return values

    @model_validator(mode="after")
    def o04_is_owner_signed_and_sealed(self) -> Self:
        if not _sealed_model_is_valid(self):
            raise ValueError("owner-quality O-04 seal does not match")
        return self


class _OwnerCanaryAuthorizationBase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    authorization_id: str = Field(pattern=r"^owner-canary-(?:development|holdout)-[0-9a-f]{20}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Legacy rows parse for safe inspection but cannot replay because this
    # sentinel has no private Stage-A artifact directory.
    stage_a_run_id: str = Field(
        default="legacy-stage-a-unbound",
        pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$",
    )
    stage_a_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completion_preflight_artifact_ref: str = Field(
        default=UNBOUND_COMPLETION_PREFLIGHT_REF,
        pattern=(
            r"^(?:legacy-completion-preflight-unbound|"
            r"completion-preflight/[0-9]{4}-[0-9]{2}-[0-9]{2}/"
            r"[a-z0-9][a-z0-9._:-]{2,127})$"
        ),
    )
    completion_preflight_verified_result_sha256: str = Field(
        default=UNBOUND_COMPLETION_PREFLIGHT_SEAL,
        pattern=r"^[0-9a-f]{64}$",
    )
    completion_preflight_authoritative: bool = False
    integration_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    integration_git_dirty: Literal[False]
    policy_bindings: OwnerCanaryPolicyBindings
    authorized_case_ids: tuple[str, ...]
    authorized_case_count: Literal[30]
    serial_execution_required: Literal[True]
    maximum_attempt_count: Literal[3]
    restart_allowed: Literal[False]
    purpose: Literal["evaluation_only"]
    local_only: Literal[True]
    online_research_allowed: Literal[False]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    writes_active: Literal[False]
    writes_previous: Literal[False]
    writes_o04: Literal[False]
    issued_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("authorized_case_ids")
    @classmethod
    def authorized_ids_are_exactly_thirty_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != 30 or len(set(values)) != 30:
            raise ValueError("owner-canary authorization must name exactly 30 cases")
        if any(not _CASE_ID.fullmatch(value) for value in values):
            raise ValueError("owner-canary authorization contains an invalid case ID")
        return values

    @model_validator(mode="after")
    def authorization_is_sealed(self) -> Self:
        bound = (
            self.completion_preflight_artifact_ref != UNBOUND_COMPLETION_PREFLIGHT_REF
            and self.completion_preflight_verified_result_sha256
            != UNBOUND_COMPLETION_PREFLIGHT_SEAL
        )
        if bound != self.completion_preflight_authoritative:
            raise ValueError("owner-canary completion-preflight binding is inconsistent")
        if not _sealed_model_is_valid(self):
            raise ValueError("owner-canary authorization seal does not match")
        return self


class OwnerQualityDevelopmentAuthorization(_OwnerCanaryAuthorizationBase):
    schema_name: Literal["legalbot.owner-quality-canary-development-authorization.v1"] = Field(
        default="legalbot.owner-quality-canary-development-authorization.v1",
        alias="schema",
    )
    lane: Literal["development"]
    requires_active: Literal[False]
    requires_owner_promotion: Literal[False]
    requires_operational_proof: Literal[False]
    requires_o04: Literal[False]


class OwnerQualityHoldoutAuthorization(_OwnerCanaryAuthorizationBase):
    schema_name: Literal["legalbot.owner-quality-canary-holdout-authorization.v1"] = Field(
        default="legalbot.owner-quality-canary-holdout-authorization.v1",
        alias="schema",
    )
    lane: Literal["blind_holdout"]
    requires_active: Literal[True]
    requires_owner_promotion: Literal[True]
    requires_operational_proof: Literal[True]
    requires_o04: Literal[True]
    active_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    promoted_active_proof_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    operational_proof_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    o04_approval_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    o04_approval_ref: str = Field(pattern=r"^o04:[0-9a-f]{64}$")
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")


type OwnerCanaryAuthorization = (
    OwnerQualityDevelopmentAuthorization | OwnerQualityHoldoutAuthorization
)


def _verified_stage_a_seal(
    stage_a: Mapping[str, Any],
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    integration_sha: str,
    completion_preflight_verified_result_sha256: str,
) -> str:
    """Verify the complete 60-case/585-issue runner result, not a metric subset."""

    payload = dict(stage_a)
    seal = str(payload.get("seal_sha256") or "")
    if seal != sealed_sha256(payload):
        raise ValueError("Stage A seal does not match its contents")
    as_of_raw = payload.get("as_of_date")
    try:
        as_of_date = date.fromisoformat(str(as_of_raw))
    except ValueError as exc:
        raise ValueError("Stage A as-of date is invalid") from exc
    validated = validate_stage_a_inputs(
        bundle=bundle,
        candidate=candidate,
        all60_qualification=qualification,
        expert_qualification=expert_qualification,
        as_of_date=as_of_date,
    )
    expected_positive_count = len(validated.positive_issues)
    run_id = str(payload.get("run_id") or "")
    expected = {
        "schema": STAGE_A_V2_SCHEMA,
        "candidate_build_id": candidate.build_id,
        "run_id": run_id,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "all60_qualification_seal_sha256": qualification.seal_sha256,
        "expert_qualification_seal_sha256": expert_qualification.seal_sha256,
        "completion_preflight_verified_result_sha256": (
            completion_preflight_verified_result_sha256
        ),
        "completion_preflight_authoritative": (
            completion_preflight_verified_result_sha256 != UNBOUND_COMPLETION_PREFLIGHT_SHA256
        ),
        "as_of_date": expert_qualification.as_of_date.isoformat(),
        "case_count": 60,
        "issue_count": 585,
        "issue_status_counts": validated.status_counts,
        "issue_identity_set_sha256": validated.issue_identity_set_sha256,
        "completed_checkpoint_count": 585,
        "completed_issue_count": 585,
        "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "scored_issue_count": expected_positive_count,
        "selected_qualified_issue_count": validated.status_counts.get("qualified", 0),
        "selected_limited_issue_count": validated.status_counts.get("limited", 0),
        "selected_knowledge_gap_count": validated.status_counts.get("knowledge_gap", 0),
        "code_revision": integration_sha,
        "code_dirty": False,
        "timeout_count": 0,
        "worker_failure_count": 0,
        "hard_failure_count": 0,
        "run_status": "passed",
    }
    if not _SAFE_ID.fullmatch(run_id):
        raise ValueError("Stage A runner identity is invalid")
    for field, expected_value in expected.items():
        if payload.get(field) != expected_value:
            raise ValueError(f"Stage A complete runner identity mismatch: {field}")
    checkpoint_set_sha256 = payload.get("checkpoint_set_sha256")
    if not isinstance(checkpoint_set_sha256, str) or not _SHA256.fullmatch(checkpoint_set_sha256):
        raise ValueError("Stage A checkpoint-set identity is missing")
    raw_metrics = (
        payload.get("recall_at_5"),
        payload.get("recall_at_10"),
        payload.get("mrr"),
    )
    metrics = tuple(
        float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None
        for value in raw_metrics
    )
    if (
        payload.get("review_complete") is not True
        or payload.get("unreviewed_issue_count") != 0
        or not isinstance(payload.get("scored_issue_count"), int)
        or isinstance(payload.get("scored_issue_count"), bool)
        or int(payload["scored_issue_count"]) < 1
        or payload.get("stage_a_passed") is not True
        or payload.get("authorization_eligible") is not True
        or payload.get("metrics_source") != "derived_rankings"
        or any(value is None for value in metrics)
        or metrics[0] != 1.0
        or metrics[1] is None
        or metrics[1] < 0.95
        or metrics[2] is None
        or metrics[2] < 0.8
        or payload.get("filter_violation_count") != 0
        or payload.get("writes_active") is not False
        or payload.get("writes_o04") is not False
        or payload.get("answer_generation_invoked") is not False
    ):
        raise ValueError("Stage A has not passed for the exact candidate")
    assert_safe_evaluation_payload(payload)
    return seal


def _validate_common_inputs(
    *,
    settings: Settings,
    stage_a_run_id: str,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    manifest: OwnerQualityCanaryManifest,
    qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    integration_sha: str,
    completion_preflight_verified_result_sha256: str,
) -> tuple[str, OwnerCanaryPolicyBindings]:
    if (
        bundle.manifest.suite_id != manifest.suite_id
        or bundle.manifest.seal_sha256 != manifest.suite_manifest_seal_sha256
        or bundle.registry.canonical_sha256 != manifest.suite_registry_canonical_sha256
        or candidate.build_id != manifest.candidate_build_id
        or candidate.candidate_manifest_sha256 != manifest.candidate_manifest_sha256
        or candidate.chunk_count < 1
        or candidate.vector_count != candidate.chunk_count
        or qualification.case_ids != tuple(case.case_id for case in bundle.registry.cases)
        or expert_qualification.index_build_id != candidate.build_id
        or expert_qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or expert_qualification.run_plan_sha256 != bundle.manifest.run_plan_sha256
        or qualification.seal_sha256 != manifest.qualification_seal_sha256
        or qualification.candidate_build_id != manifest.candidate_build_id
        or qualification.suite_manifest_seal_sha256 != manifest.suite_manifest_seal_sha256
        or qualification.suite_registry_canonical_sha256 != manifest.suite_registry_canonical_sha256
    ):
        raise ValueError("qualification or candidate differs from the canary manifest")
    stage_a = load_verified_stage_a_v2_artifact_set(
        output_root=settings.evaluation_dir / "stage-a-v2",
        run_id=stage_a_run_id,
        bundle=bundle,
        candidate=candidate,
        all60_qualification=qualification,
        expert_qualification=expert_qualification,
        as_of_date=expert_qualification.as_of_date,
        code_revision=integration_sha,
        completion_preflight_verified_result_sha256=(completion_preflight_verified_result_sha256),
    )
    stage_a_seal = _verified_stage_a_seal(
        stage_a,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert_qualification=expert_qualification,
        integration_sha=integration_sha,
        completion_preflight_verified_result_sha256=(completion_preflight_verified_result_sha256),
    )
    policies = owner_canary_policy_bindings(settings=settings)
    return stage_a_seal, policies


def replay_authorization_stage_a(
    *,
    settings: Settings,
    authorization: OwnerCanaryAuthorization,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    output_root: Path | None = None,
) -> dict[str, Any]:
    """Replay all 585 private checkpoints behind a loaded authorization."""

    if authorization.stage_a_run_id == "legacy-stage-a-unbound":
        raise ValueError("owner-canary authorization has no replayable Stage A run")
    stage_a = load_verified_stage_a_v2_artifact_set(
        output_root=output_root or settings.evaluation_dir / "stage-a-v2",
        run_id=authorization.stage_a_run_id,
        bundle=bundle,
        candidate=candidate,
        all60_qualification=qualification,
        expert_qualification=expert_qualification,
        as_of_date=expert_qualification.as_of_date,
        code_revision=authorization.integration_sha,
        completion_preflight_verified_result_sha256=(
            authorization.completion_preflight_verified_result_sha256
        ),
    )
    observed_seal = _verified_stage_a_seal(
        stage_a,
        bundle=bundle,
        candidate=candidate,
        qualification=qualification,
        expert_qualification=expert_qualification,
        integration_sha=authorization.integration_sha,
        completion_preflight_verified_result_sha256=(
            authorization.completion_preflight_verified_result_sha256
        ),
    )
    if observed_seal != authorization.stage_a_seal_sha256:
        raise ValueError("owner-canary authorization Stage A replay seal differs")
    return stage_a


def _completion_runtime_binding_for_authorization(
    *,
    settings: Settings,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
) -> dict[str, Any]:
    """Recompute the current completion runtime/toolchain binding locally."""

    from ..observability.live_metrics import load_slo_policy
    from .candidate_completion_runtime import build_local_completion_runtime_binding

    slo_path = settings.observability_slo_path
    if slo_path.is_symlink() or not slo_path.is_file():
        raise RuntimeError("completion_preflight_slo_policy_invalid")
    slo_policy = load_slo_policy(slo_path)
    return build_local_completion_runtime_binding(
        settings=settings,
        candidate=candidate,
        slo_policy_id=slo_policy.policy_id,
        slo_policy_sha256=hashlib.sha256(slo_path.read_bytes()).hexdigest(),
        integration_sha=integration_sha,
    )


def _verified_completion_preflight_for_authorization(
    *,
    settings: Settings,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
    run_dir: Path,
    memory_policy: object,
) -> tuple[str, dict[str, Any]]:
    """Replay the strict private preflight and return its stable relative ref."""

    from .candidate_completion_preflight import (
        load_verified_authoritative_completion_preflight,
    )

    binding = _completion_runtime_binding_for_authorization(
        settings=settings,
        candidate=candidate,
        integration_sha=integration_sha,
    )
    toolchain = binding.get("model_toolchain")
    if not isinstance(toolchain, Mapping):
        raise RuntimeError("completion_preflight_runtime_binding_invalid")
    base = settings.evaluation_dir.resolve(strict=True)
    resolved_run = run_dir.resolve(strict=True)
    try:
        relative = resolved_run.relative_to(base)
    except ValueError as exc:
        raise RuntimeError("completion_preflight_run_outside_private_root") from exc
    parts = relative.parts
    if (
        len(parts) != 3
        or parts[0] != "completion-preflight"
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", parts[1])
        or not _SAFE_ID.fullmatch(parts[2])
    ):
        raise RuntimeError("completion_preflight_run_reference_invalid")
    verified = load_verified_authoritative_completion_preflight(
        resolved_run,
        project_root=settings.project_root,
        memory_policy=memory_policy,  # type: ignore[arg-type]
        expected_candidate_build_id=candidate.build_id,
        expected_candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        expected_integration_sha=integration_sha,
        expected_runtime_binding_sha256=str(binding.get("seal_sha256") or ""),
        expected_trusted_toolchain_identity_sha256=str(
            toolchain.get("trusted_toolchain_identity_sha256") or ""
        ),
        expected_base_python_runtime_manifest_sha256=str(
            toolchain.get("base_python_runtime_manifest_sha256") or ""
        ),
        expected_venv_control_manifest_sha256=str(
            toolchain.get("venv_control_manifest_sha256") or ""
        ),
    )
    return relative.as_posix(), verified


def replay_authorization_completion_preflight(
    *,
    settings: Settings,
    authorization: OwnerCanaryAuthorization,
    candidate: SealedCandidateIdentity,
    run_dir: Path | None = None,
) -> dict[str, Any]:
    """Replay the exact authoritative completion preflight bound to an auth."""

    if not authorization.completion_preflight_authoritative:
        raise OwnerDecisionRequired("authoritative_completion_preflight_required")
    binding = _completion_runtime_binding_for_authorization(
        settings=settings,
        candidate=candidate,
        integration_sha=authorization.integration_sha,
    )
    from .candidate_completion_authority import load_completion_memory_policy

    memory_policy = load_completion_memory_policy(
        settings.completion_memory_policy_path,
        owner_decision_root=settings.owner_decision_root,
        candidate=candidate,
        runtime_binding=binding,
        integration_sha=authorization.integration_sha,
    )
    source_run = run_dir or (
        settings.evaluation_dir / authorization.completion_preflight_artifact_ref
    )
    if run_dir is None:
        observed_ref, verified = _verified_completion_preflight_for_authorization(
            settings=settings,
            candidate=candidate,
            integration_sha=authorization.integration_sha,
            run_dir=source_run,
            memory_policy=memory_policy,
        )
        if observed_ref != authorization.completion_preflight_artifact_ref:
            raise ValueError("owner-canary completion-preflight reference differs")
    else:
        from .candidate_completion_preflight import (
            load_verified_authoritative_completion_preflight,
        )

        toolchain = binding.get("model_toolchain")
        if not isinstance(toolchain, Mapping):
            raise RuntimeError("completion_preflight_runtime_binding_invalid")
        verified = load_verified_authoritative_completion_preflight(
            source_run,
            project_root=settings.project_root,
            memory_policy=memory_policy,
            expected_candidate_build_id=candidate.build_id,
            expected_candidate_manifest_sha256=candidate.candidate_manifest_sha256,
            expected_integration_sha=authorization.integration_sha,
            expected_runtime_binding_sha256=str(binding.get("seal_sha256") or ""),
            expected_trusted_toolchain_identity_sha256=str(
                toolchain.get("trusted_toolchain_identity_sha256") or ""
            ),
            expected_base_python_runtime_manifest_sha256=str(
                toolchain.get("base_python_runtime_manifest_sha256") or ""
            ),
            expected_venv_control_manifest_sha256=str(
                toolchain.get("venv_control_manifest_sha256") or ""
            ),
        )
    if (
        verified.get("seal_sha256") != authorization.completion_preflight_verified_result_sha256
        or verified.get("candidate_build_id") != authorization.candidate_build_id
        or verified.get("candidate_manifest_sha256") != authorization.candidate_manifest_sha256
        or verified.get("integration_sha") != authorization.integration_sha
        or verified.get("suite_manifest_seal_sha256") != authorization.suite_manifest_seal_sha256
        or verified.get("authoritative") is not True
        or verified.get("completion_preflight_passed") is not True
    ):
        raise ValueError("owner-canary completion-preflight replay differs")
    return verified


def _common_material(
    *,
    lane: Literal["development", "blind_holdout"],
    run_id: str,
    manifest: OwnerQualityCanaryManifest,
    stage_a_run_id: str,
    stage_a_seal: str,
    completion_preflight_artifact_ref: str,
    completion_preflight_verified_result_sha256: str,
    completion_preflight_authoritative: bool,
    integration_sha: str,
    policies: OwnerCanaryPolicyBindings,
    authorized_case_ids: tuple[str, ...],
    issued_at: datetime,
) -> dict[str, Any]:
    if not _SAFE_ID.fullmatch(run_id):
        raise ValueError("owner-canary run identity is invalid")
    identity = sealed_sha256(
        {
            "lane": lane,
            "run_id": run_id,
            "canary_manifest_seal_sha256": manifest.seal_sha256,
            "stage_a_run_id": stage_a_run_id,
            "stage_a_seal_sha256": stage_a_seal,
            "completion_preflight_verified_result_sha256": (
                completion_preflight_verified_result_sha256
            ),
            "integration_sha": integration_sha,
            "policy_bindings_seal_sha256": policies.seal_sha256,
        }
    )[:20]
    return {
        "authorization_id": f"owner-canary-{'development' if lane == 'development' else 'holdout'}-{identity}",
        "run_id": run_id,
        "suite_id": manifest.suite_id,
        "suite_manifest_seal_sha256": manifest.suite_manifest_seal_sha256,
        "suite_registry_canonical_sha256": manifest.suite_registry_canonical_sha256,
        "canary_manifest_id": manifest.manifest_id,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "candidate_build_id": manifest.candidate_build_id,
        "candidate_manifest_sha256": manifest.candidate_manifest_sha256,
        "qualification_seal_sha256": manifest.qualification_seal_sha256,
        "stage_a_run_id": stage_a_run_id,
        "stage_a_seal_sha256": stage_a_seal,
        "completion_preflight_artifact_ref": completion_preflight_artifact_ref,
        "completion_preflight_verified_result_sha256": (
            completion_preflight_verified_result_sha256
        ),
        "completion_preflight_authoritative": completion_preflight_authoritative,
        "integration_sha": integration_sha,
        "integration_git_dirty": False,
        "policy_bindings": policies.model_dump(mode="json", by_alias=True),
        "authorized_case_ids": list(authorized_case_ids),
        "authorized_case_count": 30,
        "serial_execution_required": True,
        "maximum_attempt_count": MAX_ATTEMPTS,
        "restart_allowed": False,
        "purpose": "evaluation_only",
        "local_only": True,
        "online_research_allowed": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
    }


def _write_authorization(path: Path, authorization: OwnerCanaryAuthorization) -> Path:
    """Write once. Even identical existing bytes require a new run identity."""

    if path.exists() or path.is_symlink():
        raise FileExistsError("owner-canary authorization is create-only")
    value = authorization.model_dump(mode="json", by_alias=True)
    assert_safe_evaluation_payload(value)
    _private_directory(path.parent)
    _exclusive_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    path.chmod(0o600)
    return path


def issue_development_authorization(
    *,
    settings: Settings,
    path: Path,
    run_id: str,
    stage_a_run_id: str,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    manifest: OwnerQualityCanaryManifest,
    qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    issued_at: datetime,
    completion_preflight_run_dir: Path | None = None,
    completion_memory_policy: object | None = None,
    _synthetic_non_authoritative_test_only: bool = False,
) -> OwnerQualityDevelopmentAuthorization:
    """Create development authorization without consulting ACTIVE or O-04."""

    integration_sha = _local_clean_integration_sha(_LOCAL_INTEGRATION_ROOT)
    if _synthetic_non_authoritative_test_only:
        if not settings.test_mode:
            raise ValueError("synthetic owner-canary authorization requires test mode")
        if completion_preflight_run_dir is not None or completion_memory_policy is not None:
            raise ValueError("synthetic authorization cannot claim authoritative preflight")
        completion_ref = UNBOUND_COMPLETION_PREFLIGHT_REF
        completion_seal = UNBOUND_COMPLETION_PREFLIGHT_SEAL
        completion_authoritative = False
    else:
        if completion_preflight_run_dir is None or completion_memory_policy is None:
            raise OwnerDecisionRequired("authoritative_completion_preflight_required")
        completion_ref, verified_completion = _verified_completion_preflight_for_authorization(
            settings=settings,
            candidate=candidate,
            integration_sha=integration_sha,
            run_dir=completion_preflight_run_dir,
            memory_policy=completion_memory_policy,
        )
        completion_seal = str(verified_completion["seal_sha256"])
        completion_authoritative = True
    stage_a_seal, policies = _validate_common_inputs(
        settings=settings,
        stage_a_run_id=stage_a_run_id,
        bundle=bundle,
        candidate=candidate,
        manifest=manifest,
        qualification=qualification,
        expert_qualification=expert_qualification,
        integration_sha=integration_sha,
        completion_preflight_verified_result_sha256=completion_seal,
    )
    if _local_clean_integration_sha(_LOCAL_INTEGRATION_ROOT) != integration_sha:
        raise RuntimeError("integration HEAD changed during development authorization")
    material = {
        "schema": DEVELOPMENT_AUTHORIZATION_SCHEMA,
        **_common_material(
            lane="development",
            run_id=run_id,
            manifest=manifest,
            stage_a_run_id=stage_a_run_id,
            stage_a_seal=stage_a_seal,
            completion_preflight_artifact_ref=completion_ref,
            completion_preflight_verified_result_sha256=completion_seal,
            completion_preflight_authoritative=completion_authoritative,
            integration_sha=integration_sha,
            policies=policies,
            authorized_case_ids=manifest.development_case_ids,
            issued_at=issued_at,
        ),
        "lane": "development",
        "requires_active": False,
        "requires_owner_promotion": False,
        "requires_operational_proof": False,
        "requires_o04": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    authorization = OwnerQualityDevelopmentAuthorization.model_validate(material)
    if _local_clean_integration_sha(_LOCAL_INTEGRATION_ROOT) != integration_sha:
        raise RuntimeError("integration HEAD changed before development authorization write")
    _write_authorization(path, authorization)
    return authorization


def issue_holdout_authorization(
    *,
    settings: Settings,
    path: Path,
    run_id: str,
    stage_a_run_id: str,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    manifest: OwnerQualityCanaryManifest,
    qualification: All60CaseQualification,
    expert_qualification: LiveSuiteExpertQualification,
    promoted_active: PromotedActiveCandidateProof,
    operational_proof: OwnerCanaryOperationalProof,
    owner_o04: OwnerQualityO04Approval,
    issued_at: datetime,
    completion_preflight_run_dir: Path | None = None,
    completion_memory_policy: object | None = None,
) -> OwnerQualityHoldoutAuthorization:
    """Fail closed until a trusted owner-signature verifier is supplied.

    Hash-shaped fields and self-seals are not signatures.  The current project
    has no trusted owner public-key/keychain verifier and the operational proof
    schema has no immutable artifact references, so these reader contracts can
    never authorize a blind run.
    """

    integration_sha = _local_clean_integration_sha(_LOCAL_INTEGRATION_ROOT)
    if completion_preflight_run_dir is None or completion_memory_policy is None:
        raise OwnerDecisionRequired("authoritative_completion_preflight_required")
    _completion_ref, verified_completion = _verified_completion_preflight_for_authorization(
        settings=settings,
        candidate=candidate,
        integration_sha=integration_sha,
        run_dir=completion_preflight_run_dir,
        memory_policy=completion_memory_policy,
    )
    _validate_common_inputs(
        settings=settings,
        stage_a_run_id=stage_a_run_id,
        bundle=bundle,
        candidate=candidate,
        manifest=manifest,
        qualification=qualification,
        expert_qualification=expert_qualification,
        integration_sha=integration_sha,
        completion_preflight_verified_result_sha256=str(verified_completion["seal_sha256"]),
    )
    if _local_clean_integration_sha(_LOCAL_INTEGRATION_ROOT) != integration_sha:
        raise RuntimeError("integration HEAD changed during holdout authorization")
    raise OwnerDecisionRequired("trusted_owner_o04_signature_verifier_missing")


def verify_authorization_manifest(
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
) -> None:
    """Recheck a loaded authorization against the immutable split contract."""

    expected_ids = (
        manifest.development_case_ids
        if authorization.lane == "development"
        else manifest.blind_holdout_case_ids
    )
    checks = (
        authorization.canary_manifest_id == manifest.manifest_id,
        authorization.canary_manifest_seal_sha256 == manifest.seal_sha256,
        authorization.suite_manifest_seal_sha256 == manifest.suite_manifest_seal_sha256,
        authorization.suite_registry_canonical_sha256 == manifest.suite_registry_canonical_sha256,
        authorization.candidate_build_id == manifest.candidate_build_id,
        authorization.candidate_manifest_sha256 == manifest.candidate_manifest_sha256,
        authorization.qualification_seal_sha256 == manifest.qualification_seal_sha256,
        authorization.authorized_case_ids == expected_ids,
    )
    if not all(checks):
        raise ValueError("owner-canary authorization differs from immutable manifest")


def load_owner_canary_authorization(
    path: Path, *, manifest: OwnerQualityCanaryManifest
) -> OwnerCanaryAuthorization:
    if not path.is_file() or path.is_symlink():
        raise ValueError("owner-canary authorization artifact is missing")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("owner-canary authorization artifact is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("owner-canary authorization must be an object")
    schema = payload.get("schema")
    if schema == DEVELOPMENT_AUTHORIZATION_SCHEMA:
        authorization: OwnerCanaryAuthorization = (
            OwnerQualityDevelopmentAuthorization.model_validate(payload)
        )
    elif schema == HOLDOUT_AUTHORIZATION_SCHEMA:
        authorization = OwnerQualityHoldoutAuthorization.model_validate(payload)
    else:
        raise ValueError("frozen Live60 v1/v2 authorization is not owner-quality auth")
    verify_authorization_manifest(authorization, manifest)
    return authorization
