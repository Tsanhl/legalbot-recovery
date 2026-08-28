"""Owned, candidate-pinned producer for the 585 Live60 evidence reviews.

The authoritative entry point accepts only the concrete loopback completion
launcher.  It derives every review input from the sealed suite, expert overlay
and exact candidate membership, invokes the tracked ``ai_evidence_reviewer``
prompt through the launcher-owned model process, and persists prose-free,
create-only checkpoints.

Synthetic helpers deliberately use a different schema and are never eligible
for all-60 qualification.  A consumer must validate the completed batch
attestation as well as the 585 checkpoints; a directory of self-sealed
checkpoints alone is not an authority boundary.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, Self, cast

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..model_runtime.config import PINNED_RUNTIME_MODEL_VERSION, PINNED_RUNTIME_REPO
from ..orchestration.retry_policy import (
    MAX_ATTEMPTS,
    MAX_RETRIES,
    decide_retry,
    failure_fingerprint,
    normalise_failure_reason_code,
)
from ..privacy import scrub_prompt_data
from ..quality.ai_evidence_reviewer import (
    AI_EVIDENCE_REVIEWER_ROLE,
    AIReviewerClaimCheckpoint,
    FrozenClaimReviewInput,
    ai_evidence_reviewer_prompt_sha256,
    ai_evidence_reviewer_prompt_text,
    ai_evidence_reviewer_toolchain_sha256,
    invoke_ai_evidence_reviewer,
    seal_ai_reviewer_claim_checkpoint,
)
from ..quality.draft_identity import source_draft_sha256
from ..quality.policy import POLICY_SHA256
from ..runtime_adapters import MODEL_OUTPUT_TOKENS
from ..types import EvidenceSpan, StructuredDraft
from .candidate_completion_authority import (
    LAUNCHER_END_SCHEMA,
    LAUNCHER_START_SCHEMA,
    MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
    MEMORY_MEASUREMENT_METHOD,
    MEMORY_MEASUREMENT_SCHEMA,
    MEMORY_SAMPLE_INTERVAL_SECONDS,
    CompletionMemoryPolicy,
    LoadedCompletionMemoryPolicy,
    WorkflowMemorySampler,
    verify_launcher_attestation,
)
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_gold import LiveSuiteExpertQualification
from .nonrelease_artifacts import safe_json_bytes, sealed_safe_payload
from .sealed_candidate import SealedCandidateIdentity
from .secure_artifact_io import (
    create_private_directory_at,
    list_directory_at,
    open_directory_at,
    read_private_file_at,
    write_private_file_at,
)

ALL60_AI_REVIEW_BATCH_SCHEMA = "legalbot.live60-ai-review-batch-attestation.v2"
ALL60_AI_REVIEW_MANIFEST_SCHEMA = "legalbot.live60-ai-review-batch-manifest.v2"
ALL60_AI_REVIEW_INTENT_SCHEMA = "legalbot.live60-ai-review-invocation-intent.v2"
ALL60_AI_REVIEW_OUTCOME_SCHEMA = "legalbot.live60-ai-review-invocation-outcome.v2"
ALL60_AI_REVIEW_STOP_SCHEMA = "legalbot.live60-ai-review-batch-stop.v1"
ALL60_AI_REVIEW_SYNTHETIC_SCHEMA = "legalbot.live60-ai-review-synthetic-receipt.v1"
ALL60_AI_REVIEW_INPUT_POLICY_SCHEMA = "legalbot.live60-ai-review-input-policy.v2"

ALL60_CASE_COUNT = 60
ALL60_ISSUE_COUNT = 585
ALL60_REVIEW_ROOT_NAME = "all60-ai-review"
REQUIRED_ALL60_AI_REASON_CODES = frozenset(
    {
        "issue_relevance_supported",
        "contrary_authority_checked",
        "currentness_inputs_checked",
    }
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_ROW_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_CHECKPOINT_NAME = re.compile(r"^(?P<ordinal>[0-9]{4})-(?P<opaque>[0-9a-f]{24})\.json$")
_ATTEMPT_NAME = re.compile(
    r"^(?P<ordinal>[0-9]{4})-(?P<opaque>[0-9a-f]{24})-a(?P<attempt>[123])\.json$"
)
_MAX_SAFE_ARTIFACT_BYTES = 2_000_000
_MEMORY_FAILURE_CODES = frozenset(
    {
        "memory_headroom_below_owner_minimum",
        "memory_measurement_unavailable",
        "memory_sampling_interval_exceeded",
        "memory_working_set_exceeds_owner_ceiling",
    }
)
_DETERMINISTIC_REVIEW_FAILURE_CODES = frozenset(
    {
        *_MEMORY_FAILURE_CODES,
        "model_socket_owner_unverifiable",
        "reviewer_runtime_identity_mismatch",
        "reviewer_checkpoint_binding_mismatch",
        "reviewer_prompt_or_mode_identity_mismatch",
    }
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("all60 reviewer timestamp must be timezone aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("all60_batch_implementation_missing")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_failure_code(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            return explicit
    return normalise_failure_reason_code(type(exc).__name__)


def all60_ai_review_input_policy_sha256() -> str:
    """Bind the All60-specific machine constraints added to the base prompt."""

    return sealed_sha256(
        {
            "schema": ALL60_AI_REVIEW_INPUT_POLICY_SCHEMA,
            "base_quality_policy_sha256": POLICY_SHA256,
            "reviewer_prompt_sha256": ai_evidence_reviewer_prompt_sha256(),
            "reviewer_toolchain_sha256": ai_evidence_reviewer_toolchain_sha256(),
            "required_reason_codes": sorted(REQUIRED_ALL60_AI_REASON_CODES),
            "only_supported_passes": True,
            "positive_frozen_evidence_citation_required": True,
            "deterministic_candidate_gates_override_ai": True,
            "owner_memory_policy_applies_before_retry": True,
            "missing_memory_measurement_stops": True,
            "retry_fingerprint_excludes_attempt_number": True,
            "launcher_start_end_attestations_replayed": True,
            "model_input_is_transient": True,
            "safe_artifacts_are_prose_free": True,
        }
    )


class TrustedAll60ReviewerInput(Protocol):
    """Narrow contract returned by the candidate-gating loader."""

    @property
    def ordinal(self) -> int: ...

    @property
    def row_id(self) -> str: ...

    @property
    def case_id(self) -> str: ...

    @property
    def issue_id(self) -> str: ...

    @property
    def issue_identity_sha256(self) -> str: ...

    @property
    def deterministic_gate_sha256(self) -> str: ...

    @property
    def draft(self) -> StructuredDraft: ...

    @property
    def frozen_claim(self) -> FrozenClaimReviewInput: ...

    @property
    def evidence_by_id(self) -> Mapping[str, EvidenceSpan]: ...


class All60ReviewIssueIdentity(BaseModel):
    """Prose-free identity of one exact, candidate-gated reviewer input."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-ai-review-issue-identity.v1"] = Field(
        default="legalbot.live60-ai-review-issue-identity.v1", alias="schema"
    )
    ordinal: int = Field(ge=1, le=ALL60_ISSUE_COUNT)
    row_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    issue_id: str = Field(pattern=r"^issue-[0-9]{2}$")
    issue_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gate_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_claim_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_span_count: int = Field(ge=1, le=10_000)
    evidence_span_ids: tuple[str, ...]
    identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evidence_span_ids")
    @classmethod
    def evidence_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or any(not _SAFE_ID.fullmatch(value) for value in values):
            raise ValueError("all60 review issue evidence identities are invalid")
        if len(values) != len(set(values)):
            raise ValueError("all60 review issue evidence identities are duplicated")
        return values

    @model_validator(mode="after")
    def issue_identity_is_exact(self) -> Self:
        if self.row_id != f"{self.case_id}:{self.issue_id}":
            raise ValueError("all60 review issue row identity is inconsistent")
        if self.evidence_span_count != len(self.evidence_span_ids):
            raise ValueError("all60 review issue evidence inventory is incomplete")
        material = self.model_dump(mode="json", by_alias=True)
        material.pop("identity_sha256", None)
        if self.identity_sha256 != sealed_sha256(material):
            raise ValueError("all60 review issue identity seal does not match")
        return self


def _issue_identity(value: TrustedAll60ReviewerInput) -> All60ReviewIssueIdentity:
    frozen = value.frozen_claim
    evidence_ids = tuple(frozen.identity.evidence_span_ids)
    if (
        set(value.evidence_by_id) != set(evidence_ids)
        or tuple(value.evidence_by_id[evidence_id] for evidence_id in evidence_ids)
        != frozen.evidence
    ):
        raise ValueError("all60 review evidence map differs from its frozen claim")
    material: dict[str, Any] = {
        "schema": "legalbot.live60-ai-review-issue-identity.v1",
        "ordinal": value.ordinal,
        "row_id": value.row_id,
        "case_id": value.case_id,
        "issue_id": value.issue_id,
        "issue_identity_sha256": value.issue_identity_sha256,
        "deterministic_gate_sha256": value.deterministic_gate_sha256,
        "source_draft_sha256": source_draft_sha256(value.draft),
        "frozen_claim_bundle_sha256": hashlib.sha256(
            _canonical_json(
                {
                    "schema": "legalbot.frozen-material-claim-bundle.v2",
                    "claims": [frozen.identity.model_dump(mode="json")],
                }
            )
        ).hexdigest(),
        "claim_sha256": frozen.identity.claim_sha256,
        "evidence_bundle_sha256": frozen.identity.evidence_bundle_sha256,
        "evidence_span_count": len(evidence_ids),
        "evidence_span_ids": list(evidence_ids),
    }
    # Use the reviewer's canonical helper, not this local reconstruction, at
    # admission time.  The local value is overwritten below after lazy import
    # so a future schema change fails closed rather than silently diverging.
    from ..quality.ai_evidence_reviewer import frozen_claim_bundle_sha256

    material["frozen_claim_bundle_sha256"] = frozen_claim_bundle_sha256((frozen,))
    material["identity_sha256"] = sealed_sha256(material)
    return All60ReviewIssueIdentity.model_validate(material)


class All60ReviewBatchManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-ai-review-batch-manifest.v2"] = Field(
        default="legalbot.live60-ai-review-batch-manifest.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_date: date
    suite_id: Literal["live-evaluation-60-v1"]
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expert_qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_as_of_date: date
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    trusted_model_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_toolchain_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_environment_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_python_runtime_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    venv_control_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_id: str = Field(min_length=1, max_length=255)
    model_version: str = Field(min_length=1, max_length=255)
    reviewer_role: Literal["ai_evidence_reviewer"]
    reviewer_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    batch_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retry_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_source_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_host_physical_memory_bytes: int = Field(ge=1)
    memory_policy_max_peak_combined_working_set_bytes: int = Field(ge=1)
    memory_policy_minimum_host_available_memory_bytes: int = Field(ge=1)
    max_attempts: Literal[3]
    max_retries: Literal[2]
    case_count: Literal[60]
    issue_count: Literal[585]
    issue_identity_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launcher_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    launcher_start_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authoritative: Literal[True]
    qualification_eligible_on_complete_pass_only: Literal[True]
    purpose: Literal["evaluation_only"]
    local_only: Literal[True]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    writes_active: Literal[False]
    writes_o04: Literal[False]
    releases_answers: Literal[False]
    crawler_used: Literal[False]
    plaintext_prose_persisted: Literal[False]
    create_only: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def manifest_is_sealed(self) -> Self:
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all60 AI review manifest seal does not match")
        return self


class All60ReviewInvocationIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-ai-review-invocation-intent.v2"] = Field(
        default="legalbot.live60-ai-review-invocation-intent.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    ordinal: int = Field(ge=1, le=ALL60_ISSUE_COUNT)
    row_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS)
    request_id: str = Field(pattern=r"^all60-ai-[0-9a-f]{32}$")
    invocation_nonce_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue_input_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_instance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owned_listener_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launch_nonce_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prior_failure_fingerprints: tuple[str, ...]
    condition_change: Literal[
        "initial_owned_runtime",
        "fresh_owned_runtime_after_retryable_failure",
        "resumed_owned_runtime",
    ]
    created_at: datetime
    prose_persisted: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("prior_failure_fingerprints")
    @classmethod
    def prior_fingerprints_are_valid(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) > MAX_RETRIES or any(not _SHA256.fullmatch(value) for value in values):
            raise ValueError("all60 reviewer prior failure fingerprints are invalid")
        return values

    @model_validator(mode="after")
    def intent_is_exact_and_sealed(self) -> Self:
        if len(self.prior_failure_fingerprints) != self.attempt_number - 1:
            raise ValueError("all60 reviewer attempt history is incomplete")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all60 reviewer invocation intent seal does not match")
        return self


class All60ReviewInvocationOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-ai-review-invocation-outcome.v2"] = Field(
        default="legalbot.live60-ai-review-invocation-outcome.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    ordinal: int = Field(ge=1, le=ALL60_ISSUE_COUNT)
    row_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS)
    intent_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_id: str = Field(pattern=r"^all60-ai-[0-9a-f]{32}$")
    invocation_nonce_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue_input_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["passed", "review_blocked", "invocation_failed"]
    invocation_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    duration_ms: int = Field(ge=0, le=86_400_000)
    input_token_count: int | None = Field(default=None, ge=0, le=10_000_000)
    output_token_count: int | None = Field(default=None, ge=0, le=10_000_000)
    usage_observed: bool
    memory_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_measurement_schema: Literal["legalbot.completion-memory-measurement.v2"]
    memory_measurement_method: Literal["owned_process_tree_os_rss_and_host_available_sampled_100ms"]
    memory_sampling_interval_seconds: float = Field(gt=0, le=0.1)
    memory_max_allowed_sample_interval_seconds: float = Field(gt=0, le=0.25)
    memory_sample_count: int = Field(ge=0)
    memory_max_observed_sample_interval_seconds: float = Field(ge=0)
    memory_max_sampling_jitter_seconds: float = Field(ge=0)
    controller_peak_rss_bytes: int = Field(ge=0)
    sidecar_peak_rss_bytes: int = Field(ge=0)
    peak_combined_working_set_bytes: int = Field(ge=0)
    minimum_host_available_memory_bytes: int = Field(ge=0)
    startup_memory_measurement_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    startup_memory_sample_count: int = Field(ge=0)
    startup_memory_max_observed_sample_interval_seconds: float = Field(ge=0)
    startup_controller_peak_rss_bytes: int = Field(ge=0)
    startup_sidecar_peak_rss_bytes: int = Field(ge=0)
    startup_peak_combined_working_set_bytes: int = Field(ge=0)
    startup_minimum_host_available_memory_bytes: int = Field(ge=0)
    checkpoint: AIReviewerClaimCheckpoint | None = None
    checkpoint_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    failure_reason_code: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    failure_fingerprint_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    deterministic_safety_failure: bool
    retry_action: Literal["retry", "stop", "not_applicable"]
    retry_reason: Literal[
        "retry_allowed",
        "deterministic_safety_failure",
        "non_retryable_failure",
        "repeated_failure_fingerprint",
        "retry_condition_unchanged",
        "retry_cap_exhausted",
        "not_applicable",
    ]
    completed_at: datetime
    prose_persisted: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def outcome_is_exact_and_sealed(self) -> Self:
        if (
            self.memory_measurement_schema != MEMORY_MEASUREMENT_SCHEMA
            or self.memory_measurement_method != MEMORY_MEASUREMENT_METHOD
            or self.memory_sampling_interval_seconds != MEMORY_SAMPLE_INTERVAL_SECONDS
            or self.memory_max_allowed_sample_interval_seconds != MEMORY_MAX_SAMPLE_INTERVAL_SECONDS
            or not (
                max(self.controller_peak_rss_bytes, self.sidecar_peak_rss_bytes)
                <= self.peak_combined_working_set_bytes
                <= self.controller_peak_rss_bytes + self.sidecar_peak_rss_bytes
            )
            or not (
                max(
                    self.startup_controller_peak_rss_bytes,
                    self.startup_sidecar_peak_rss_bytes,
                )
                <= self.startup_peak_combined_working_set_bytes
                <= self.startup_controller_peak_rss_bytes + self.startup_sidecar_peak_rss_bytes
            )
        ):
            raise ValueError("all60 reviewer memory measurement is inconsistent")
        successful = self.status in {"passed", "review_blocked"}
        if successful != (self.checkpoint is not None):
            raise ValueError("all60 reviewer outcome checkpoint state is inconsistent")
        if successful:
            assert self.checkpoint is not None
            if (
                self.invocation_id != self.request_id
                or self.checkpoint_seal_sha256 != self.checkpoint.seal_sha256
                or self.failure_reason_code is not None
                or self.failure_fingerprint_sha256 is not None
                or self.retry_action != "not_applicable"
                or self.retry_reason != "not_applicable"
                or self.deterministic_safety_failure != (self.status == "review_blocked")
                or not self.usage_observed
                or self.input_token_count is None
                or self.output_token_count is None
            ):
                raise ValueError("all60 reviewer completed outcome is inconsistent")
        elif (
            self.checkpoint_seal_sha256 is not None
            or self.failure_reason_code is None
            or self.failure_fingerprint_sha256 is None
            or self.retry_action == "not_applicable"
            or self.retry_reason == "not_applicable"
            or self.invocation_id != self.request_id
        ):
            raise ValueError("all60 reviewer failed outcome is incomplete")
        if self.usage_observed != (
            self.input_token_count is not None and self.output_token_count is not None
        ):
            raise ValueError("all60 reviewer usage observation is inconsistent")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all60 reviewer outcome seal does not match")
        return self


class All60ReviewBatchAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-ai-review-batch-attestation.v2"] = Field(
        default="legalbot.live60-ai-review-batch-attestation.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expert_qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    required_as_of_date: date
    runtime_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    model_id: str = Field(min_length=1, max_length=255)
    model_version: str = Field(min_length=1, max_length=255)
    trusted_model_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_toolchain_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_environment_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_python_runtime_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    venv_control_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    batch_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retry_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_source_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_host_physical_memory_bytes: int = Field(ge=1)
    memory_policy_max_peak_combined_working_set_bytes: int = Field(ge=1)
    memory_policy_minimum_host_available_memory_bytes: int = Field(ge=1)
    case_count: Literal[60]
    issue_count: Literal[585]
    passed_issue_count: Literal[585]
    checkpoint_count: Literal[585]
    invocation_count: int = Field(ge=585, le=585 * MAX_ATTEMPTS)
    invocation_nonce_count: int = Field(ge=585, le=585 * MAX_ATTEMPTS)
    invocation_ids_unique: Literal[True]
    invocation_nonces_unique: Literal[True]
    input_token_count: int = Field(ge=0)
    output_token_count: int = Field(ge=0)
    total_token_count: int = Field(ge=0)
    reviewer_duration_ms: int = Field(ge=0)
    issue_identity_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    invocation_intent_ledger_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    invocation_outcome_ledger_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launcher_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    launcher_start_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launcher_end_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    real_catalogue_unchanged: Literal[True]
    candidate_unchanged: Literal[True]
    active_pointer_unchanged: Literal[True]
    git_worktree_clean_start_end: Literal[True]
    authoritative: Literal[True]
    qualification_eligible: Literal[True]
    completed: Literal[True]
    all_reviews_passed: Literal[True]
    purpose: Literal["evaluation_only"]
    local_only: Literal[True]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    writes_active: Literal[False]
    writes_o04: Literal[False]
    releases_answers: Literal[False]
    crawler_used: Literal[False]
    plaintext_prose_persisted: Literal[False]
    created_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def attestation_is_complete_and_sealed(self) -> Self:
        if (
            self.invocation_count != self.invocation_nonce_count
            or self.total_token_count != self.input_token_count + self.output_token_count
        ):
            raise ValueError("all60 AI review batch counters are inconsistent")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all60 AI review batch attestation seal does not match")
        return self


class SyntheticAll60ReviewReceipt(BaseModel):
    """Explicitly non-authoritative receipt for tests and contract exercises."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-ai-review-synthetic-receipt.v1"] = Field(
        default="legalbot.live60-ai-review-synthetic-receipt.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    checkpoint_seal_sha256s: tuple[str, ...]
    checkpoint_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_kind: Literal["injected_test_double"]
    reason_code: Literal["synthetic_test_double_non_authoritative"]
    authoritative: Literal[False]
    qualification_eligible: Literal[False]
    writes_active: Literal[False]
    writes_o04: Literal[False]
    releases_answers: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("checkpoint_seal_sha256s")
    @classmethod
    def checkpoint_seals_are_digests(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SHA256.fullmatch(value) for value in values):
            raise ValueError("synthetic checkpoint digest is invalid")
        return values

    @model_validator(mode="after")
    def receipt_is_non_authoritative_and_sealed(self) -> Self:
        if self.checkpoint_set_sha256 != sealed_sha256(
            {
                "schema": "legalbot.live60-ai-review-synthetic-checkpoint-set.v1",
                "checkpoint_seal_sha256s": list(self.checkpoint_seal_sha256s),
            }
        ):
            raise ValueError("synthetic checkpoint set does not match")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("synthetic receipt seal does not match")
        return self


_VERIFIED_ALL60_AI_REVIEW_BATCH_TOKEN = object()


class VerifiedAll60AIReviewBatch:
    """Opaque authority capability returned only by the full ledger replay."""

    __slots__ = (
        "_attestation",
        "_checkpoint_directory",
        "_checkpoint_names",
        "_checkpoints",
        "_token",
    )

    def __init__(
        self,
        *,
        attestation: All60ReviewBatchAttestation,
        checkpoints: tuple[AIReviewerClaimCheckpoint, ...],
        checkpoint_names: tuple[str, ...],
        checkpoint_directory: Path,
        token: object,
    ) -> None:
        if token is not _VERIFIED_ALL60_AI_REVIEW_BATCH_TOKEN:
            raise RuntimeError("all60_ai_review_batch_capability_not_loader_verified")
        if len(checkpoints) != ALL60_ISSUE_COUNT or len(checkpoint_names) != ALL60_ISSUE_COUNT:
            raise RuntimeError("all60_ai_review_batch_capability_incomplete")
        self._attestation = attestation
        self._checkpoints = checkpoints
        self._checkpoint_names = checkpoint_names
        self._checkpoint_directory = checkpoint_directory
        self._token = token

    @property
    def attestation(self) -> All60ReviewBatchAttestation:
        return self._attestation

    @property
    def checkpoints(self) -> tuple[AIReviewerClaimCheckpoint, ...]:
        return self._checkpoints

    @property
    def checkpoint_names(self) -> tuple[str, ...]:
        return self._checkpoint_names

    @property
    def checkpoint_directory(self) -> Path:
        return self._checkpoint_directory

    @property
    def manifest_seal_sha256(self) -> str:
        return self._attestation.manifest_seal_sha256

    @property
    def checkpoint_set_sha256(self) -> str:
        return self._attestation.checkpoint_set_sha256

    @property
    def invocation_intent_ledger_sha256(self) -> str:
        return self._attestation.invocation_intent_ledger_sha256

    @property
    def invocation_outcome_ledger_sha256(self) -> str:
        return self._attestation.invocation_outcome_ledger_sha256

    @property
    def launcher_start_attestation_sha256(self) -> str:
        return self._attestation.launcher_start_attestation_sha256

    @property
    def launcher_end_attestation_sha256(self) -> str:
        return self._attestation.launcher_end_attestation_sha256


def require_verified_all60_ai_review_batch(value: object) -> VerifiedAll60AIReviewBatch:
    """Reject dicts, subclasses, synthetic receipts, and caller-minted duck types."""

    if (
        type(value) is not VerifiedAll60AIReviewBatch
        or getattr(value, "_token", None) is not _VERIFIED_ALL60_AI_REVIEW_BATCH_TOKEN
    ):
        raise RuntimeError("all60_ai_review_batch_capability_not_loader_verified")
    return value


def build_synthetic_all60_review_receipt(
    *, run_id: str, checkpoint_seal_sha256s: Sequence[str]
) -> SyntheticAll60ReviewReceipt:
    """Build test telemetry that can never satisfy the production schema."""

    checkpoint_seals = tuple(checkpoint_seal_sha256s)
    material: dict[str, Any] = {
        "schema": ALL60_AI_REVIEW_SYNTHETIC_SCHEMA,
        "run_id": run_id,
        "checkpoint_seal_sha256s": list(checkpoint_seals),
        "checkpoint_set_sha256": sealed_sha256(
            {
                "schema": "legalbot.live60-ai-review-synthetic-checkpoint-set.v1",
                "checkpoint_seal_sha256s": list(checkpoint_seals),
            }
        ),
        "runtime_kind": "injected_test_double",
        "reason_code": "synthetic_test_double_non_authoritative",
        "authoritative": False,
        "qualification_eligible": False,
        "writes_active": False,
        "writes_o04": False,
        "releases_answers": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return SyntheticAll60ReviewReceipt.model_validate(material)


class All60ReviewBatchStore:
    """Descriptor-relative, create-only store for one exact review run."""

    def __init__(
        self,
        *,
        evaluation_root: Path,
        run_date: date,
        run_id: str,
        resume: bool,
    ) -> None:
        if not _SAFE_ID.fullmatch(run_id) or run_id.casefold() != run_id:
            raise ValueError("all60 review run ID is invalid")
        date_value = run_date.isoformat()
        if not _DATE.fullmatch(date_value):
            raise ValueError("all60 review run date is invalid")
        if evaluation_root.is_symlink() or not evaluation_root.is_dir():
            raise ValueError("all60 review evaluation root is unsafe")
        relative = (ALL60_REVIEW_ROOT_NAME, date_value, run_id)
        if resume:
            try:
                with open_directory_at(evaluation_root, relative) as run_fd:
                    if stat.S_IMODE(os.fstat(run_fd).st_mode) != 0o700:
                        raise ValueError("all60 review run directory is not owner-private")
                for child in ("checkpoints", "intents", "outcomes"):
                    with open_directory_at(evaluation_root, (*relative, child)) as child_fd:
                        if stat.S_IMODE(os.fstat(child_fd).st_mode) != 0o700:
                            raise ValueError("all60 review artifact directory is not owner-private")
            except FileNotFoundError as exc:
                raise FileNotFoundError("all60 review run does not exist for resume") from exc
        else:
            create_private_directory_at(evaluation_root, relative, exist_ok=False)
            for child in ("checkpoints", "intents", "outcomes"):
                create_private_directory_at(evaluation_root, (*relative, child), exist_ok=False)
        self.evaluation_root = evaluation_root
        self.run_date = run_date
        self.run_id = run_id
        self.relative = relative

    @property
    def run_path(self) -> Path:
        return self.evaluation_root.joinpath(*self.relative)

    @property
    def checkpoint_path(self) -> Path:
        return self.run_path / "checkpoints"

    @staticmethod
    def _opaque(row_id: str) -> str:
        if not _ROW_ID.fullmatch(row_id):
            raise ValueError("all60 review row ID is invalid")
        return hashlib.sha256(row_id.encode("utf-8")).hexdigest()[:24]

    @classmethod
    def checkpoint_name(cls, ordinal: int, row_id: str) -> str:
        if not 1 <= ordinal <= ALL60_ISSUE_COUNT:
            raise ValueError("all60 review ordinal is invalid")
        return f"{ordinal:04d}-{cls._opaque(row_id)}.json"

    @classmethod
    def attempt_name(cls, ordinal: int, row_id: str, attempt: int) -> str:
        if not 1 <= attempt <= MAX_ATTEMPTS:
            raise ValueError("all60 review attempt is invalid")
        return f"{ordinal:04d}-{cls._opaque(row_id)}-a{attempt}.json"

    def _write(self, relative: Sequence[str], value: Mapping[str, Any]) -> None:
        payload = safe_json_bytes(value)
        if len(payload) > _MAX_SAFE_ARTIFACT_BYTES:
            raise ValueError("all60 review safe artifact exceeds its byte bound")
        write_private_file_at(self.evaluation_root, (*self.relative, *relative), payload)

    def _read(self, relative: Sequence[str]) -> dict[str, Any]:
        payload = read_private_file_at(
            self.evaluation_root,
            (*self.relative, *relative),
        )
        if len(payload) > _MAX_SAFE_ARTIFACT_BYTES:
            raise ValueError("all60 review safe artifact exceeds its byte bound")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("all60 review safe artifact is invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("all60 review safe artifact is not an object")
        assert_safe_evaluation_payload(value)
        return value

    def members(self, child: str) -> tuple[str, ...]:
        if child not in {"checkpoints", "intents", "outcomes"}:
            raise ValueError("all60 review artifact class is invalid")
        return list_directory_at(self.evaluation_root, (*self.relative, child))

    def write_manifest(self, value: All60ReviewBatchManifest) -> None:
        self._write(("manifest.json",), value.model_dump(mode="json", by_alias=True))

    def read_manifest(self) -> All60ReviewBatchManifest:
        return All60ReviewBatchManifest.model_validate(self._read(("manifest.json",)))

    def write_launcher_start(self, value: Mapping[str, Any]) -> None:
        self._write(("launcher-start-attestation.json",), value)

    def read_launcher_start(self) -> dict[str, Any]:
        return self._read(("launcher-start-attestation.json",))

    def write_launcher_end(self, value: Mapping[str, Any]) -> None:
        self._write(("launcher-end-attestation.json",), value)

    def read_launcher_end(self) -> dict[str, Any]:
        return self._read(("launcher-end-attestation.json",))

    def write_intent(self, value: All60ReviewInvocationIntent) -> None:
        self._write(
            ("intents", self.attempt_name(value.ordinal, value.row_id, value.attempt_number)),
            value.model_dump(mode="json", by_alias=True),
        )

    def read_intent(
        self, *, ordinal: int, row_id: str, attempt: int
    ) -> All60ReviewInvocationIntent | None:
        name = self.attempt_name(ordinal, row_id, attempt)
        if name not in self.members("intents"):
            return None
        return All60ReviewInvocationIntent.model_validate(self._read(("intents", name)))

    def write_outcome(self, value: All60ReviewInvocationOutcome) -> None:
        self._write(
            ("outcomes", self.attempt_name(value.ordinal, value.row_id, value.attempt_number)),
            value.model_dump(mode="json", by_alias=True),
        )

    def read_outcome(
        self, *, ordinal: int, row_id: str, attempt: int
    ) -> All60ReviewInvocationOutcome | None:
        name = self.attempt_name(ordinal, row_id, attempt)
        if name not in self.members("outcomes"):
            return None
        return All60ReviewInvocationOutcome.model_validate(self._read(("outcomes", name)))

    def write_checkpoint(
        self,
        *,
        ordinal: int,
        row_id: str,
        checkpoint: AIReviewerClaimCheckpoint,
    ) -> None:
        self._write(
            ("checkpoints", self.checkpoint_name(ordinal, row_id)),
            checkpoint.model_dump(mode="json", by_alias=True),
        )

    def read_checkpoint(self, *, ordinal: int, row_id: str) -> AIReviewerClaimCheckpoint | None:
        name = self.checkpoint_name(ordinal, row_id)
        if name not in self.members("checkpoints"):
            return None
        return AIReviewerClaimCheckpoint.model_validate(self._read(("checkpoints", name)))

    def write_stop(self, value: Mapping[str, Any]) -> None:
        self._write(("batch-stop.json",), value)

    def read_stop(self) -> dict[str, Any] | None:
        try:
            return self._read(("batch-stop.json",))
        except FileNotFoundError:
            return None

    def write_attestation(self, value: All60ReviewBatchAttestation) -> None:
        self._write(("batch-attestation.json",), value.model_dump(mode="json", by_alias=True))

    def read_attestation(self) -> All60ReviewBatchAttestation | None:
        try:
            return All60ReviewBatchAttestation.model_validate(
                self._read(("batch-attestation.json",))
            )
        except FileNotFoundError:
            return None


@dataclass(slots=True)
class _TransportObservation:
    duration_ms: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    response_request_id: str | None = None


@dataclass(frozen=True, slots=True)
class _InvocationMemoryObservation:
    memory_sample_count: int
    memory_max_observed_sample_interval_seconds: float
    memory_max_sampling_jitter_seconds: float
    controller_peak_rss_bytes: int
    sidecar_peak_rss_bytes: int
    peak_combined_working_set_bytes: int
    minimum_host_available_memory_bytes: int
    startup_memory_measurement_sha256: str | None
    startup_memory_sample_count: int
    startup_memory_max_observed_sample_interval_seconds: float
    startup_controller_peak_rss_bytes: int
    startup_sidecar_peak_rss_bytes: int
    startup_peak_combined_working_set_bytes: int
    startup_minimum_host_available_memory_bytes: int

    def safe_fields(self, *, memory_policy_sha256: str) -> dict[str, Any]:
        return {
            "memory_policy_sha256": memory_policy_sha256,
            "memory_measurement_schema": MEMORY_MEASUREMENT_SCHEMA,
            "memory_measurement_method": MEMORY_MEASUREMENT_METHOD,
            "memory_sampling_interval_seconds": MEMORY_SAMPLE_INTERVAL_SECONDS,
            "memory_max_allowed_sample_interval_seconds": (MEMORY_MAX_SAMPLE_INTERVAL_SECONDS),
            "memory_sample_count": self.memory_sample_count,
            "memory_max_observed_sample_interval_seconds": round(
                self.memory_max_observed_sample_interval_seconds, 6
            ),
            "memory_max_sampling_jitter_seconds": round(self.memory_max_sampling_jitter_seconds, 6),
            "controller_peak_rss_bytes": self.controller_peak_rss_bytes,
            "sidecar_peak_rss_bytes": self.sidecar_peak_rss_bytes,
            "peak_combined_working_set_bytes": self.peak_combined_working_set_bytes,
            "minimum_host_available_memory_bytes": self.minimum_host_available_memory_bytes,
            "startup_memory_measurement_sha256": self.startup_memory_measurement_sha256,
            "startup_memory_sample_count": self.startup_memory_sample_count,
            "startup_memory_max_observed_sample_interval_seconds": round(
                self.startup_memory_max_observed_sample_interval_seconds, 6
            ),
            "startup_controller_peak_rss_bytes": self.startup_controller_peak_rss_bytes,
            "startup_sidecar_peak_rss_bytes": self.startup_sidecar_peak_rss_bytes,
            "startup_peak_combined_working_set_bytes": (
                self.startup_peak_combined_working_set_bytes
            ),
            "startup_minimum_host_available_memory_bytes": (
                self.startup_minimum_host_available_memory_bytes
            ),
        }


def _invocation_memory_observation(
    *, sampler: WorkflowMemorySampler | None, startup: Mapping[str, Any] | None
) -> _InvocationMemoryObservation:
    return _InvocationMemoryObservation(
        memory_sample_count=sampler.sample_count if sampler is not None else 0,
        memory_max_observed_sample_interval_seconds=(
            sampler.maximum_observed_sample_interval_seconds if sampler is not None else 0.0
        ),
        memory_max_sampling_jitter_seconds=(
            sampler.maximum_sampling_jitter_seconds if sampler is not None else 0.0
        ),
        controller_peak_rss_bytes=(sampler.controller_peak_rss_bytes if sampler else 0),
        sidecar_peak_rss_bytes=(sampler.sidecar_peak_rss_bytes if sampler else 0),
        peak_combined_working_set_bytes=(sampler.peak_combined_working_set_bytes if sampler else 0),
        minimum_host_available_memory_bytes=(
            (sampler.minimum_host_available_memory_bytes or 0) if sampler else 0
        ),
        startup_memory_measurement_sha256=(
            str(startup.get("seal_sha256"))
            if isinstance(startup, Mapping)
            and _SHA256.fullmatch(str(startup.get("seal_sha256") or ""))
            else None
        ),
        startup_memory_sample_count=(
            int(startup.get("sample_count") or 0) if isinstance(startup, Mapping) else 0
        ),
        startup_memory_max_observed_sample_interval_seconds=(
            float(startup.get("maximum_observed_sample_interval_seconds") or 0)
            if isinstance(startup, Mapping)
            else 0.0
        ),
        startup_controller_peak_rss_bytes=(
            int(startup.get("controller_sampled_peak_rss_bytes") or 0)
            if isinstance(startup, Mapping)
            else 0
        ),
        startup_sidecar_peak_rss_bytes=(
            int(startup.get("owned_sidecar_tree_sampled_peak_rss_bytes") or 0)
            if isinstance(startup, Mapping)
            else 0
        ),
        startup_peak_combined_working_set_bytes=(
            int(startup.get("sampled_peak_combined_working_set_bytes") or 0)
            if isinstance(startup, Mapping)
            else 0
        ),
        startup_minimum_host_available_memory_bytes=(
            int(startup.get("minimum_sampled_host_available_memory_bytes") or 0)
            if isinstance(startup, Mapping)
            else 0
        ),
    )


def _memory_failure_reason(
    observation: _InvocationMemoryObservation,
    policy: CompletionMemoryPolicy,
) -> str | None:
    if (
        observation.memory_sample_count < 1
        or observation.startup_memory_sample_count < 1
        or observation.sidecar_peak_rss_bytes < 1
        or observation.startup_sidecar_peak_rss_bytes < 1
        or observation.peak_combined_working_set_bytes < 1
        or observation.startup_peak_combined_working_set_bytes < 1
        or observation.minimum_host_available_memory_bytes < 1
        or observation.startup_minimum_host_available_memory_bytes < 1
        or observation.startup_memory_measurement_sha256 is None
    ):
        return "memory_measurement_unavailable"
    if (
        observation.memory_max_observed_sample_interval_seconds > MEMORY_MAX_SAMPLE_INTERVAL_SECONDS
        or observation.startup_memory_max_observed_sample_interval_seconds
        > MEMORY_MAX_SAMPLE_INTERVAL_SECONDS
    ):
        return "memory_sampling_interval_exceeded"
    if (
        max(
            observation.peak_combined_working_set_bytes,
            observation.startup_peak_combined_working_set_bytes,
        )
        > policy.max_peak_combined_working_set_bytes
    ):
        return "memory_working_set_exceeds_owner_ceiling"
    if (
        min(
            observation.minimum_host_available_memory_bytes,
            observation.startup_minimum_host_available_memory_bytes,
        )
        < policy.minimum_host_available_memory_bytes
    ):
        return "memory_headroom_below_owner_minimum"
    return None


def _memory_observation_from_outcome(
    outcome: All60ReviewInvocationOutcome,
) -> _InvocationMemoryObservation:
    return _InvocationMemoryObservation(
        memory_sample_count=outcome.memory_sample_count,
        memory_max_observed_sample_interval_seconds=(
            outcome.memory_max_observed_sample_interval_seconds
        ),
        memory_max_sampling_jitter_seconds=outcome.memory_max_sampling_jitter_seconds,
        controller_peak_rss_bytes=outcome.controller_peak_rss_bytes,
        sidecar_peak_rss_bytes=outcome.sidecar_peak_rss_bytes,
        peak_combined_working_set_bytes=outcome.peak_combined_working_set_bytes,
        minimum_host_available_memory_bytes=outcome.minimum_host_available_memory_bytes,
        startup_memory_measurement_sha256=outcome.startup_memory_measurement_sha256,
        startup_memory_sample_count=outcome.startup_memory_sample_count,
        startup_memory_max_observed_sample_interval_seconds=(
            outcome.startup_memory_max_observed_sample_interval_seconds
        ),
        startup_controller_peak_rss_bytes=outcome.startup_controller_peak_rss_bytes,
        startup_sidecar_peak_rss_bytes=outcome.startup_sidecar_peak_rss_bytes,
        startup_peak_combined_working_set_bytes=(outcome.startup_peak_combined_working_set_bytes),
        startup_minimum_host_available_memory_bytes=(
            outcome.startup_minimum_host_available_memory_bytes
        ),
    )


def _semantic_failure_fingerprint(
    *, reason_code: str, identity: All60ReviewIssueIdentity, runtime_binding_sha256: str
) -> str:
    """Fingerprint semantic failure identity; an attempt ordinal is never semantic."""

    return failure_fingerprint(
        stage="all60_ai_evidence_review",
        reason_code=reason_code,
        scope_id=identity.row_id,
        identity_digests=(identity.identity_sha256, runtime_binding_sha256),
    )


class _OwnedReviewerTransport:
    """One-shot transport to the exact launcher-owned loopback model."""

    def __init__(self, *, launcher: Any, request_id: str) -> None:
        self.launcher = launcher
        self.request_id = request_id
        self.observation = _TransportObservation()
        self._used = False

    @staticmethod
    def _counter(value: Any, *, label: str, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise RuntimeError(f"reviewer_{label}_invalid")
        return int(value)

    async def invoke_json(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, Any],
        mode: str,
    ) -> tuple[str, dict[str, Any], dict[str, int]]:
        if self._used:
            raise RuntimeError("reviewer_transport_reuse_refused")
        self._used = True
        from .candidate_completion_runtime import LoopbackCandidateCompletionLauncher

        if type(self.launcher) is not LoopbackCandidateCompletionLauncher:
            raise RuntimeError("non_authoritative_all60_reviewer_runtime_refused")
        if system_prompt != ai_evidence_reviewer_prompt_text() or mode != "semantic_verify":
            raise RuntimeError("reviewer_prompt_or_mode_identity_mismatch")
        if not await LoopbackCandidateCompletionLauncher._health(self.launcher):
            raise RuntimeError("model_socket_owner_unverifiable")
        safe_payload = scrub_prompt_data(
            dict(user_payload), self.launcher.settings.owner_identifiers
        )
        if not isinstance(safe_payload, dict):
            raise RuntimeError("reviewer_payload_invalid")
        safe_payload["all60_review_constraints"] = {
            "schema": ALL60_AI_REVIEW_INPUT_POLICY_SCHEMA,
            "policy_sha256": all60_ai_review_input_policy_sha256(),
            "required_reason_codes": sorted(REQUIRED_ALL60_AI_REASON_CODES),
            "only_supported_passes": True,
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps(safe_payload, ensure_ascii=False, sort_keys=True),
            },
        ]
        envelope = {
            "request_id": self.request_id,
            "mode": mode,
            "payload": {**safe_payload, "messages": messages},
            "messages": messages,
            "max_tokens": MODEL_OUTPUT_TOKENS,
            "temperature": 0.0,
            "top_p": 1.0,
            "seed": 0,
            "stop": [],
        }
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=5, read=300, write=30, pool=5),
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    f"{self.launcher.settings.model_url.rstrip('/')}/api/v1/generate",
                    json=envelope,
                )
                response.raise_for_status()
        finally:
            self.observation.duration_ms = round((time.perf_counter() - started) * 1_000)
        try:
            body = response.json()
        except (TypeError, ValueError) as exc:
            raise RuntimeError("reviewer_response_invalid") from exc
        if not isinstance(body, Mapping):
            raise RuntimeError("reviewer_response_invalid")
        response_request_id = body.get("request_id")
        self.observation.response_request_id = (
            str(response_request_id) if isinstance(response_request_id, str) else None
        )
        usage = body.get("usage")
        if not isinstance(usage, Mapping):
            raise RuntimeError("reviewer_usage_invalid")
        input_tokens = self._counter(
            usage.get("input_tokens"), label="input_tokens", maximum=10_000_000
        )
        output_tokens = self._counter(
            usage.get("output_tokens"), label="output_tokens", maximum=10_000_000
        )
        generation_ms = self._counter(
            body.get("generation_ms"), label="duration", maximum=86_400_000
        )
        self.observation.input_tokens = input_tokens
        self.observation.output_tokens = output_tokens
        self.observation.duration_ms = generation_ms
        warnings = body.get("warnings")
        if (
            response_request_id != self.request_id
            or body.get("api_version") != "v1"
            or body.get("model_version") != PINNED_RUNTIME_MODEL_VERSION
            or body.get("model_version") != self.launcher.runtime_binding.get("model_version")
            or body.get("backend") != "mlx_lm"
            or body.get("deterministic") is not True
            or not isinstance(warnings, Sequence)
            or isinstance(warnings, str | bytes | bytearray)
            or "stub_mode" in warnings
        ):
            raise RuntimeError("reviewer_runtime_identity_mismatch")
        structured = body.get("structured")
        if isinstance(structured, str):
            try:
                structured = json.loads(structured)
            except json.JSONDecodeError as exc:
                raise RuntimeError("reviewer_response_invalid") from exc
        if not isinstance(structured, dict):
            raw = body.get("raw_text")
            if not isinstance(raw, str):
                raise RuntimeError("reviewer_response_invalid")
            try:
                structured = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError("reviewer_response_invalid") from exc
        if not isinstance(structured, dict) or structured.get("chain_of_thought") not in {
            None,
        }:
            raise RuntimeError("reviewer_response_invalid")
        if not await LoopbackCandidateCompletionLauncher._health(self.launcher):
            raise RuntimeError("model_socket_owner_unverifiable")
        return (
            self.request_id,
            structured,
            {
                "duration_ms": generation_ms,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
        )


def _validate_runtime_binding(
    *, runtime_binding: Mapping[str, Any], candidate: SealedCandidateIdentity
) -> None:
    model_toolchain = runtime_binding.get("model_toolchain")
    if (
        runtime_binding.get("seal_sha256") != sealed_sha256(runtime_binding)
        or runtime_binding.get("candidate_build_id") != candidate.build_id
        or runtime_binding.get("candidate_manifest_sha256") != candidate.candidate_manifest_sha256
        or runtime_binding.get("candidate_seal_sha256") != candidate.candidate_seal_sha256
        or runtime_binding.get("model_id") != PINNED_RUNTIME_REPO
        or runtime_binding.get("model_version") != PINNED_RUNTIME_MODEL_VERSION
        or runtime_binding.get("reviewer_role") != AI_EVIDENCE_REVIEWER_ROLE
        or runtime_binding.get("reviewer_prompt_sha256") != ai_evidence_reviewer_prompt_sha256()
        or runtime_binding.get("reviewer_policy_sha256") != POLICY_SHA256
        or runtime_binding.get("reviewer_toolchain_sha256")
        != ai_evidence_reviewer_toolchain_sha256()
        or runtime_binding.get("max_attempts") != MAX_ATTEMPTS
        or runtime_binding.get("max_retries") != MAX_RETRIES
        or not _GIT_SHA.fullmatch(str(runtime_binding.get("integration_sha") or ""))
        or not isinstance(model_toolchain, Mapping)
        or not _SHA256.fullmatch(
            str(model_toolchain.get("trusted_toolchain_identity_sha256") or "")
        )
        or not _SHA256.fullmatch(
            str(model_toolchain.get("installed_environment_manifest_sha256") or "")
        )
        or not _SHA256.fullmatch(
            str(model_toolchain.get("base_python_runtime_manifest_sha256") or "")
        )
        or not _SHA256.fullmatch(str(model_toolchain.get("venv_control_manifest_sha256") or ""))
        or not _SHA256.fullmatch(str(runtime_binding.get("trusted_model_identity_sha256") or ""))
        or not _SHA256.fullmatch(str(runtime_binding.get("reviewer_implementation_sha256") or ""))
        or not _SHA256.fullmatch(str(runtime_binding.get("retry_implementation_sha256") or ""))
    ):
        raise RuntimeError("all60_reviewer_runtime_binding_mismatch")


def _validate_memory_policy_binding(
    *,
    memory_policy: LoadedCompletionMemoryPolicy,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
) -> None:
    if type(memory_policy) is not LoadedCompletionMemoryPolicy:
        raise RuntimeError("completion_memory_policy_not_loader_verified")
    policy = memory_policy.policy
    if (
        policy.candidate_build_id != candidate.build_id
        or policy.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        or policy.runtime_binding_sha256 != runtime_binding.get("seal_sha256")
        or policy.integration_sha != runtime_binding.get("integration_sha")
        or not _SHA256.fullmatch(memory_policy.source_file_sha256)
    ):
        raise RuntimeError("all60_reviewer_memory_policy_binding_mismatch")


def _manifest_material(
    *,
    run_id: str,
    run_date: date,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    required_as_of_date: date,
    runtime_binding: Mapping[str, Any],
    issue_identities: Sequence[All60ReviewIssueIdentity],
    launcher_run_id: str,
    launcher_start_attestation_sha256: str,
    memory_policy: LoadedCompletionMemoryPolicy,
) -> dict[str, Any]:
    model_toolchain = cast(Mapping[str, Any], runtime_binding["model_toolchain"])
    identity_set = sealed_sha256(
        {
            "schema": "legalbot.live60-ai-review-issue-identity-set.v1",
            "issue_identity_sha256s": [item.identity_sha256 for item in issue_identities],
        }
    )
    material: dict[str, Any] = {
        "schema": ALL60_AI_REVIEW_MANIFEST_SCHEMA,
        "run_id": run_id,
        "run_date": run_date.isoformat(),
        "suite_id": bundle.manifest.suite_id,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "expert_qualification_seal_sha256": expert.seal_sha256,
        "required_as_of_date": required_as_of_date.isoformat(),
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "candidate_seal_sha256": candidate.candidate_seal_sha256,
        "candidate_source_manifest_sha256": candidate.source_manifest_sha256,
        "runtime_binding_sha256": runtime_binding["seal_sha256"],
        "integration_sha": runtime_binding["integration_sha"],
        "trusted_model_identity_sha256": runtime_binding["trusted_model_identity_sha256"],
        "trusted_toolchain_identity_sha256": model_toolchain["trusted_toolchain_identity_sha256"],
        "installed_environment_manifest_sha256": model_toolchain[
            "installed_environment_manifest_sha256"
        ],
        "base_python_runtime_manifest_sha256": model_toolchain[
            "base_python_runtime_manifest_sha256"
        ],
        "venv_control_manifest_sha256": model_toolchain["venv_control_manifest_sha256"],
        "model_id": runtime_binding["model_id"],
        "model_version": runtime_binding["model_version"],
        "reviewer_role": AI_EVIDENCE_REVIEWER_ROLE,
        "reviewer_prompt_sha256": ai_evidence_reviewer_prompt_sha256(),
        "reviewer_policy_sha256": POLICY_SHA256,
        "reviewer_toolchain_sha256": ai_evidence_reviewer_toolchain_sha256(),
        "reviewer_implementation_sha256": runtime_binding["reviewer_implementation_sha256"],
        "batch_implementation_sha256": _file_sha256(Path(__file__)),
        "input_policy_sha256": all60_ai_review_input_policy_sha256(),
        "retry_implementation_sha256": runtime_binding["retry_implementation_sha256"],
        "memory_policy_sha256": memory_policy.policy.seal_sha256,
        "memory_policy_source_file_sha256": memory_policy.source_file_sha256,
        "memory_policy_host_physical_memory_bytes": (
            memory_policy.policy.host_physical_memory_bytes
        ),
        "memory_policy_max_peak_combined_working_set_bytes": (
            memory_policy.policy.max_peak_combined_working_set_bytes
        ),
        "memory_policy_minimum_host_available_memory_bytes": (
            memory_policy.policy.minimum_host_available_memory_bytes
        ),
        "max_attempts": MAX_ATTEMPTS,
        "max_retries": MAX_RETRIES,
        "case_count": ALL60_CASE_COUNT,
        "issue_count": ALL60_ISSUE_COUNT,
        "issue_identity_set_sha256": identity_set,
        "launcher_run_id": launcher_run_id,
        "launcher_start_attestation_sha256": launcher_start_attestation_sha256,
        "authoritative": True,
        "qualification_eligible_on_complete_pass_only": True,
        "purpose": "evaluation_only",
        "local_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_o04": False,
        "releases_answers": False,
        "crawler_used": False,
        "plaintext_prose_persisted": False,
        "create_only": True,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return material


def _checkpoint_set_sha256(checkpoints: Sequence[AIReviewerClaimCheckpoint]) -> str:
    return sealed_sha256(
        {
            "schema": "legalbot.live60-ai-review-checkpoint-set.v1",
            "checkpoint_seal_sha256s": [item.seal_sha256 for item in checkpoints],
        }
    )


def _intent_ledger_sha256(intents: Sequence[All60ReviewInvocationIntent]) -> str:
    return sealed_sha256(
        {
            "schema": "legalbot.live60-ai-review-intent-ledger.v1",
            "intent_seal_sha256s": [item.seal_sha256 for item in intents],
        }
    )


def _outcome_ledger_sha256(outcomes: Sequence[All60ReviewInvocationOutcome]) -> str:
    return sealed_sha256(
        {
            "schema": "legalbot.live60-ai-review-outcome-ledger.v1",
            "outcome_seal_sha256s": [item.seal_sha256 for item in outcomes],
        }
    )


def _batch_attestation_material(
    *,
    manifest: All60ReviewBatchManifest,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    required_as_of_date: date,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    checkpoints: Sequence[AIReviewerClaimCheckpoint],
    intents: Sequence[All60ReviewInvocationIntent],
    outcomes: Sequence[All60ReviewInvocationOutcome],
    start: Mapping[str, Any],
    end: Mapping[str, Any],
    created_at: datetime,
) -> dict[str, Any]:
    model_toolchain = cast(Mapping[str, Any], runtime_binding["model_toolchain"])
    invocation_ids = tuple(
        item.invocation_id for item in outcomes if item.invocation_id is not None
    )
    invocation_nonces = tuple(item.invocation_nonce_sha256 for item in intents)
    material: dict[str, Any] = {
        "schema": ALL60_AI_REVIEW_BATCH_SCHEMA,
        "run_id": manifest.run_id,
        "manifest_seal_sha256": manifest.seal_sha256,
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "candidate_seal_sha256": candidate.candidate_seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "expert_qualification_seal_sha256": expert.seal_sha256,
        "required_as_of_date": required_as_of_date.isoformat(),
        "runtime_binding_sha256": runtime_binding["seal_sha256"],
        "integration_sha": runtime_binding["integration_sha"],
        "model_id": runtime_binding["model_id"],
        "model_version": runtime_binding["model_version"],
        "trusted_model_identity_sha256": runtime_binding["trusted_model_identity_sha256"],
        "trusted_toolchain_identity_sha256": model_toolchain["trusted_toolchain_identity_sha256"],
        "installed_environment_manifest_sha256": model_toolchain[
            "installed_environment_manifest_sha256"
        ],
        "base_python_runtime_manifest_sha256": model_toolchain[
            "base_python_runtime_manifest_sha256"
        ],
        "venv_control_manifest_sha256": model_toolchain["venv_control_manifest_sha256"],
        "reviewer_prompt_sha256": ai_evidence_reviewer_prompt_sha256(),
        "reviewer_policy_sha256": POLICY_SHA256,
        "reviewer_toolchain_sha256": ai_evidence_reviewer_toolchain_sha256(),
        "reviewer_implementation_sha256": runtime_binding["reviewer_implementation_sha256"],
        "batch_implementation_sha256": _file_sha256(Path(__file__)),
        "input_policy_sha256": all60_ai_review_input_policy_sha256(),
        "retry_implementation_sha256": runtime_binding["retry_implementation_sha256"],
        "memory_policy_sha256": memory_policy.policy.seal_sha256,
        "memory_policy_source_file_sha256": memory_policy.source_file_sha256,
        "memory_policy_host_physical_memory_bytes": (
            memory_policy.policy.host_physical_memory_bytes
        ),
        "memory_policy_max_peak_combined_working_set_bytes": (
            memory_policy.policy.max_peak_combined_working_set_bytes
        ),
        "memory_policy_minimum_host_available_memory_bytes": (
            memory_policy.policy.minimum_host_available_memory_bytes
        ),
        "case_count": ALL60_CASE_COUNT,
        "issue_count": ALL60_ISSUE_COUNT,
        "passed_issue_count": len(checkpoints),
        "checkpoint_count": len(checkpoints),
        "invocation_count": len(intents),
        "invocation_nonce_count": len(invocation_nonces),
        "invocation_ids_unique": len(invocation_ids) == len(set(invocation_ids)),
        "invocation_nonces_unique": len(invocation_nonces) == len(set(invocation_nonces)),
        "input_token_count": sum(item.input_token_count or 0 for item in outcomes),
        "output_token_count": sum(item.output_token_count or 0 for item in outcomes),
        "total_token_count": sum(
            (item.input_token_count or 0) + (item.output_token_count or 0) for item in outcomes
        ),
        "reviewer_duration_ms": sum(item.duration_ms for item in outcomes),
        "issue_identity_set_sha256": manifest.issue_identity_set_sha256,
        "checkpoint_set_sha256": _checkpoint_set_sha256(checkpoints),
        "invocation_intent_ledger_sha256": _intent_ledger_sha256(intents),
        "invocation_outcome_ledger_sha256": _outcome_ledger_sha256(outcomes),
        "launcher_run_id": manifest.launcher_run_id,
        "launcher_start_attestation_sha256": start["seal_sha256"],
        "launcher_end_attestation_sha256": end["seal_sha256"],
        "real_catalogue_unchanged": end["real_catalogue_unchanged"],
        "candidate_unchanged": end["candidate_unchanged"],
        "active_pointer_unchanged": end["active_pointer_unchanged"],
        "git_worktree_clean_start_end": end["git_worktree_clean_start_end"],
        "authoritative": True,
        "qualification_eligible": True,
        "completed": True,
        "all_reviews_passed": True,
        "purpose": "evaluation_only",
        "local_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_o04": False,
        "releases_answers": False,
        "crawler_used": False,
        "plaintext_prose_persisted": False,
        "created_at": _utc_iso(created_at),
    }
    material["seal_sha256"] = sealed_sha256(material)
    return material


def _validate_inventory(
    values: Sequence[TrustedAll60ReviewerInput],
) -> tuple[All60ReviewIssueIdentity, ...]:
    if len(values) != ALL60_ISSUE_COUNT:
        raise ValueError("all60 reviewer inventory must contain exactly 585 issues")
    identities = tuple(_issue_identity(value) for value in values)
    if tuple(item.ordinal for item in identities) != tuple(range(1, ALL60_ISSUE_COUNT + 1)):
        raise ValueError("all60 reviewer inventory order is incomplete")
    expected_case_ids = tuple(
        [f"live30-q{number:02d}" for number in range(1, 31)]
        + [f"live60-q{number:02d}" for number in range(31, 61)]
    )
    observed_case_ids = tuple(dict.fromkeys(item.case_id for item in identities))
    if observed_case_ids != expected_case_ids or len({item.row_id for item in identities}) != 585:
        raise ValueError("all60 reviewer suite/issue identities are incomplete")
    return identities


def _checkpoint_matches(
    checkpoint: AIReviewerClaimCheckpoint,
    *,
    issue: TrustedAll60ReviewerInput,
    identity: All60ReviewIssueIdentity,
    runtime_binding: Mapping[str, Any],
) -> bool:
    return bool(
        checkpoint.source_draft_sha256 == identity.source_draft_sha256
        and checkpoint.frozen_claim_bundle_sha256 == identity.frozen_claim_bundle_sha256
        and checkpoint.claim_identity == issue.frozen_claim.identity
        and checkpoint.model_id == runtime_binding.get("model_id")
        and checkpoint.model_version == runtime_binding.get("model_version")
        and checkpoint.prompt_sha256 == ai_evidence_reviewer_prompt_sha256()
        and checkpoint.policy_sha256 == POLICY_SHA256
        and checkpoint.toolchain_sha256 == ai_evidence_reviewer_toolchain_sha256()
        and checkpoint.invocation_trace.timing_source != "deterministic_zero"
        and checkpoint.invocation_trace.input_token_count is not None
        and checkpoint.invocation_trace.output_token_count is not None
    )


def _review_passes(checkpoint: AIReviewerClaimCheckpoint) -> bool:
    return bool(
        checkpoint.decision.verdict == "supported"
        and REQUIRED_ALL60_AI_REASON_CODES.issubset(checkpoint.decision.reason_codes)
        and checkpoint.decision.cited_evidence_ids
    )


def _sealed_model(model: type[BaseModel], material: dict[str, Any]) -> BaseModel:
    material["seal_sha256"] = sealed_sha256(material)
    return model.model_validate(material)


def _stop_payload(
    *,
    manifest: All60ReviewBatchManifest,
    ordinal: int,
    row_id: str,
    attempt_number: int,
    reason_code: str,
    failure_fingerprint_sha256: str,
) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": ALL60_AI_REVIEW_STOP_SCHEMA,
            "run_id": manifest.run_id,
            "manifest_seal_sha256": manifest.seal_sha256,
            "status": "stopped",
            "ordinal": ordinal,
            "row_id": row_id,
            "attempt_number": attempt_number,
            "reason_code": reason_code,
            "failure_fingerprint_sha256": failure_fingerprint_sha256,
            "debug_required": True,
            "resume_allowed": False,
            "writes_active": False,
            "writes_o04": False,
            "releases_answers": False,
            "created_at": _utc_iso(datetime.now(UTC)),
        }
    )


async def _execute_review_attempt(
    *,
    launcher: Any,
    run_id: str,
    issue: TrustedAll60ReviewerInput,
    identity: All60ReviewIssueIdentity,
    intent: All60ReviewInvocationIntent,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    prior_fingerprints: Sequence[str],
) -> tuple[All60ReviewInvocationOutcome, AIReviewerClaimCheckpoint | None]:
    """Invoke once, then classify quality/retry only after OS-memory sampling."""

    transport = _OwnedReviewerTransport(launcher=launcher, request_id=intent.request_id)
    sampler: WorkflowMemorySampler | None = None
    memory_task: asyncio.Task[None] | None = None
    checkpoint: AIReviewerClaimCheckpoint | None = None
    failure: BaseException | None = None
    started = time.perf_counter()
    try:
        if (
            launcher._sidecar is None
            or launcher._launch_nonce is None
            or launcher._owned_listener_proof_sha256 is None
            or launcher._verified_toolchain is None
        ):
            raise RuntimeError("model_socket_owner_unverifiable")
        sampler = WorkflowMemorySampler(
            owned_sidecar_pid=launcher._sidecar.pid,
            launch_nonce=launcher._launch_nonce,
            owned_listener_proof_sha256=launcher._owned_listener_proof_sha256,
            system_tools=launcher._verified_toolchain.system_tools,
        )
        sampler.sample()
        memory_task = asyncio.create_task(
            sampler.run(), name=f"all60-review-memory-{intent.ordinal:04d}-{intent.attempt_number}"
        )
        review = await invoke_ai_evidence_reviewer(
            model=transport,
            draft=issue.draft,
            evidence_by_id=issue.evidence_by_id,
            model_id=str(runtime_binding["model_id"]),
            model_version=str(runtime_binding["model_version"]),
            policy_sha256=POLICY_SHA256,
        )
        if len(review.claims) != 1 or len(review.invocation_traces) != 1:
            raise RuntimeError("reviewer_response_invalid")
        checkpoint = seal_ai_reviewer_claim_checkpoint(
            source_draft_sha256=identity.source_draft_sha256,
            frozen_claim_bundle_sha256=identity.frozen_claim_bundle_sha256,
            frozen_claim=issue.frozen_claim,
            decision=review.claims[0],
            invocation_trace=review.invocation_traces[0],
            model_id=str(runtime_binding["model_id"]),
            model_version=str(runtime_binding["model_version"]),
            policy_sha256=POLICY_SHA256,
            toolchain_sha256=ai_evidence_reviewer_toolchain_sha256(),
        )
        if not _checkpoint_matches(
            checkpoint,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
        ):
            raise RuntimeError("reviewer_checkpoint_binding_mismatch")
    except Exception as exc:
        failure = exc
    finally:
        if sampler is not None:
            sampler.stop()
        if memory_task is not None:
            try:
                await memory_task
                assert sampler is not None
                sampler.sample()
            except Exception as exc:
                failure = failure or exc

    memory = _invocation_memory_observation(
        sampler=sampler,
        startup=(
            launcher._startup_memory_measurement
            if isinstance(launcher._startup_memory_measurement, Mapping)
            else None
        ),
    )
    memory_reason = _memory_failure_reason(memory, memory_policy.policy)
    if memory_reason is not None:
        failure = RuntimeError(memory_reason)
        checkpoint = None
    duration_ms = max(
        transport.observation.duration_ms,
        round((time.perf_counter() - started) * 1_000),
    )
    common: dict[str, Any] = {
        "schema": ALL60_AI_REVIEW_OUTCOME_SCHEMA,
        "run_id": run_id,
        "ordinal": identity.ordinal,
        "row_id": identity.row_id,
        "attempt_number": intent.attempt_number,
        "intent_seal_sha256": intent.seal_sha256,
        "request_id": intent.request_id,
        "invocation_nonce_sha256": intent.invocation_nonce_sha256,
        "issue_input_identity_sha256": identity.identity_sha256,
        **memory.safe_fields(memory_policy_sha256=memory_policy.policy.seal_sha256),
        "completed_at": _utc_iso(datetime.now(UTC)),
        "prose_persisted": False,
    }
    if failure is None and checkpoint is not None:
        trace = checkpoint.invocation_trace
        if (
            trace.invocation_id != intent.request_id
            or trace.duration_ms != transport.observation.duration_ms
            or trace.input_token_count != transport.observation.input_tokens
            or trace.output_token_count != transport.observation.output_tokens
        ):
            raise RuntimeError("reviewer_invocation_trace_mismatch")
        status: Literal["passed", "review_blocked"] = (
            "passed" if _review_passes(checkpoint) else "review_blocked"
        )
        outcome_material = {
            **common,
            "status": status,
            "invocation_id": trace.invocation_id,
            "duration_ms": trace.duration_ms,
            "input_token_count": trace.input_token_count,
            "output_token_count": trace.output_token_count,
            "usage_observed": True,
            "checkpoint": checkpoint.model_dump(mode="json", by_alias=True),
            "checkpoint_seal_sha256": checkpoint.seal_sha256,
            "failure_reason_code": None,
            "failure_fingerprint_sha256": None,
            "deterministic_safety_failure": status == "review_blocked",
            "retry_action": "not_applicable",
            "retry_reason": "not_applicable",
        }
        return (
            cast(
                All60ReviewInvocationOutcome,
                _sealed_model(All60ReviewInvocationOutcome, outcome_material),
            ),
            checkpoint,
        )

    reason_code = _safe_failure_code(failure or RuntimeError("reviewer_response_invalid"))
    deterministic = reason_code in _DETERMINISTIC_REVIEW_FAILURE_CODES
    fingerprint = _semantic_failure_fingerprint(
        reason_code=reason_code,
        identity=identity,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
    )
    decision = decide_retry(
        attempt_number=intent.attempt_number,
        failure_reason_code=reason_code,
        failure_fingerprint_sha256=fingerprint,
        prior_failure_fingerprints=prior_fingerprints,
        deterministic_safety=deterministic,
        retryable=not deterministic,
        input_or_condition_changed=(
            intent.attempt_number == 1
            or intent.condition_change == "fresh_owned_runtime_after_retryable_failure"
        ),
    )
    outcome_material = {
        **common,
        "status": "invocation_failed",
        "invocation_id": intent.request_id,
        "duration_ms": duration_ms,
        "input_token_count": transport.observation.input_tokens,
        "output_token_count": transport.observation.output_tokens,
        "usage_observed": transport.observation.input_tokens is not None
        and transport.observation.output_tokens is not None,
        "checkpoint": None,
        "checkpoint_seal_sha256": None,
        "failure_reason_code": reason_code,
        "failure_fingerprint_sha256": fingerprint,
        "deterministic_safety_failure": deterministic,
        "retry_action": decision.action,
        "retry_reason": decision.reason,
    }
    return (
        cast(
            All60ReviewInvocationOutcome,
            _sealed_model(All60ReviewInvocationOutcome, outcome_material),
        ),
        None,
    )


async def run_authoritative_all60_ai_review_batch(
    *,
    run_id: str,
    run_date: date,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    required_as_of_date: date,
    runtime: object,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    resume: bool,
) -> All60ReviewBatchAttestation:
    """Run the real serial batch through the exact owned launcher.

    There is intentionally no transport/factory/callback argument.  Tests use
    :func:`build_synthetic_all60_review_receipt`, whose output has a distinct
    non-authoritative schema.
    """

    from .candidate_completion_runtime import LoopbackCandidateCompletionLauncher

    if type(runtime) is not LoopbackCandidateCompletionLauncher:
        raise RuntimeError("non_authoritative_all60_reviewer_runtime_refused")
    from .all60_evidence_review import (
        load_all60_reviewer_batch_inputs,
    )

    launcher = runtime
    if launcher.candidate != candidate or launcher.runtime_binding != dict(runtime_binding):
        raise RuntimeError("all60_reviewer_runtime_binding_mismatch")
    _validate_runtime_binding(runtime_binding=runtime_binding, candidate=candidate)
    _validate_memory_policy_binding(
        memory_policy=memory_policy,
        candidate=candidate,
        runtime_binding=runtime_binding,
    )
    if (
        bundle.registry.case_count != ALL60_CASE_COUNT
        or bundle.manifest.case_count != ALL60_CASE_COUNT
        or expert.case_count != ALL60_CASE_COUNT
        or expert.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or expert.run_plan_sha256 != bundle.manifest.run_plan_sha256
        or expert.index_build_id != candidate.build_id
        or expert.as_of_date != required_as_of_date
        or candidate.status != "candidate"
    ):
        raise ValueError("all60 reviewer sealed input identities differ")
    raw_start = LoopbackCandidateCompletionLauncher.production_start_attestation(launcher)
    model_toolchain = cast(Mapping[str, Any], runtime_binding["model_toolchain"])
    start = verify_launcher_attestation(
        raw_start,
        schema=LAUNCHER_START_SCHEMA,
        run_id=launcher.run_id,
        candidate=candidate,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
        integration_sha=str(runtime_binding["integration_sha"]),
        trusted_model_identity_sha256=str(runtime_binding["trusted_model_identity_sha256"]),
        trusted_toolchain_identity_sha256=str(model_toolchain["trusted_toolchain_identity_sha256"]),
        installed_environment_manifest_sha256=str(
            model_toolchain["installed_environment_manifest_sha256"]
        ),
        base_python_runtime_manifest_sha256=str(
            model_toolchain["base_python_runtime_manifest_sha256"]
        ),
        venv_control_manifest_sha256=str(model_toolchain["venv_control_manifest_sha256"]),
        launcher_implementation_sha256=str(runtime_binding["launcher_implementation_sha256"]),
    )
    candidate_root = launcher.settings.index_dir / "builds" / candidate.build_id
    inventory = tuple(
        load_all60_reviewer_batch_inputs(
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=required_as_of_date,
            candidate_build_root=candidate_root,
        )
    )
    identities = _validate_inventory(cast(Sequence[TrustedAll60ReviewerInput], inventory))
    store = All60ReviewBatchStore(
        evaluation_root=launcher.base_settings.evaluation_dir,
        run_date=run_date,
        run_id=run_id,
        resume=resume,
    )
    if resume:
        # A partial batch may contain a model call whose result is unknowable.
        # A new launcher cannot attest the prior process, so resumption is not
        # an authoritative operation; use a fresh run ID after debugging.
        raise RuntimeError("all60_reviewer_resume_requires_new_run_id")
    store.write_launcher_start(start)
    manifest = All60ReviewBatchManifest.model_validate(
        _manifest_material(
            run_id=run_id,
            run_date=run_date,
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=required_as_of_date,
            runtime_binding=runtime_binding,
            issue_identities=identities,
            launcher_run_id=launcher.run_id,
            launcher_start_attestation_sha256=str(start["seal_sha256"]),
            memory_policy=memory_policy,
        )
    )
    store.write_manifest(manifest)

    expected_checkpoint_names = tuple(
        store.checkpoint_name(item.ordinal, item.row_id) for item in identities
    )
    observed_checkpoint_names = store.members("checkpoints")
    if observed_checkpoint_names != expected_checkpoint_names[: len(observed_checkpoint_names)]:
        raise RuntimeError("all60_reviewer_checkpoint_prefix_invalid")
    intent_names = store.members("intents")
    outcome_names = store.members("outcomes")
    expected_attempt_names = {
        store.attempt_name(identity.ordinal, identity.row_id, attempt)
        for identity in identities
        for attempt in range(1, MAX_ATTEMPTS + 1)
    }
    if (
        any(_ATTEMPT_NAME.fullmatch(name) is None for name in (*intent_names, *outcome_names))
        or not set(intent_names).issubset(expected_attempt_names)
        or not set(outcome_names).issubset(expected_attempt_names)
    ):
        raise RuntimeError("all60_reviewer_invocation_ledger_invalid")

    # One warm owned model serves the normal serial path.  A retry receives a
    # fresh owned process, making the changed condition real and attested.
    await LoopbackCandidateCompletionLauncher._fresh_runtime_for_case(
        launcher, "all60-review-batch"
    )
    all_intents: list[All60ReviewInvocationIntent] = []
    all_outcomes: list[All60ReviewInvocationOutcome] = []
    checkpoints: list[AIReviewerClaimCheckpoint] = []
    for raw_issue, identity in zip(inventory, identities, strict=True):
        issue = cast(TrustedAll60ReviewerInput, raw_issue)
        prior_fingerprints: list[str] = []
        checkpoint = store.read_checkpoint(ordinal=identity.ordinal, row_id=identity.row_id)
        terminal_blocked = False
        for attempt_number in range(1, MAX_ATTEMPTS + 1):
            intent = store.read_intent(
                ordinal=identity.ordinal,
                row_id=identity.row_id,
                attempt=attempt_number,
            )
            outcome = store.read_outcome(
                ordinal=identity.ordinal,
                row_id=identity.row_id,
                attempt=attempt_number,
            )
            if intent is None and outcome is not None:
                raise RuntimeError("all60_reviewer_outcome_without_intent")
            if intent is not None and outcome is None:
                interrupted_fingerprint = _semantic_failure_fingerprint(
                    reason_code="interrupted_invocation_unknown",
                    identity=identity,
                    runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
                )
                store.write_stop(
                    _stop_payload(
                        manifest=manifest,
                        ordinal=identity.ordinal,
                        row_id=identity.row_id,
                        attempt_number=attempt_number,
                        reason_code="interrupted_invocation_unknown",
                        failure_fingerprint_sha256=interrupted_fingerprint,
                    )
                )
                raise RuntimeError("all60_reviewer_interrupted_invocation_unknown")
            if intent is not None and outcome is not None:
                if (
                    outcome.intent_seal_sha256 != intent.seal_sha256
                    or outcome.request_id != intent.request_id
                    or outcome.invocation_nonce_sha256 != intent.invocation_nonce_sha256
                ):
                    raise RuntimeError("all60_reviewer_invocation_ledger_mismatch")
                all_intents.append(intent)
                all_outcomes.append(outcome)
                if outcome.status in {"passed", "review_blocked"}:
                    assert outcome.checkpoint is not None
                    if checkpoint is None:
                        store.write_checkpoint(
                            ordinal=identity.ordinal,
                            row_id=identity.row_id,
                            checkpoint=outcome.checkpoint,
                        )
                        checkpoint = outcome.checkpoint
                    elif checkpoint != outcome.checkpoint:
                        raise RuntimeError("all60_reviewer_checkpoint_outcome_mismatch")
                    terminal_blocked = outcome.status == "review_blocked"
                    break
                assert outcome.failure_fingerprint_sha256 is not None
                prior_fingerprints.append(outcome.failure_fingerprint_sha256)
                if outcome.retry_action == "stop":
                    terminal_blocked = True
                    break
                continue

            if checkpoint is not None:
                raise RuntimeError("all60_reviewer_checkpoint_without_success_outcome")
            if attempt_number > 1:
                await LoopbackCandidateCompletionLauncher._fresh_runtime_for_case(
                    launcher, f"all60-review-retry-{identity.ordinal:04d}-{attempt_number}"
                )
            if (
                launcher._instance_sha256 is None
                or launcher._owned_listener_proof_sha256 is None
                or launcher._launch_nonce is None
            ):
                raise RuntimeError("model_socket_owner_unverifiable")
            nonce = os.urandom(32)
            request_id = f"all60-ai-{hashlib.sha256(nonce).hexdigest()[:32]}"
            condition: Literal[
                "initial_owned_runtime",
                "fresh_owned_runtime_after_retryable_failure",
                "resumed_owned_runtime",
            ]
            if attempt_number > 1:
                condition = "fresh_owned_runtime_after_retryable_failure"
            elif resume:
                condition = "resumed_owned_runtime"
            else:
                condition = "initial_owned_runtime"
            intent_material: dict[str, Any] = {
                "schema": ALL60_AI_REVIEW_INTENT_SCHEMA,
                "run_id": run_id,
                "ordinal": identity.ordinal,
                "row_id": identity.row_id,
                "attempt_number": attempt_number,
                "request_id": request_id,
                "invocation_nonce_sha256": hashlib.sha256(nonce).hexdigest(),
                "issue_input_identity_sha256": identity.identity_sha256,
                "runtime_binding_sha256": runtime_binding["seal_sha256"],
                "runtime_instance_sha256": launcher._instance_sha256,
                "owned_listener_proof_sha256": launcher._owned_listener_proof_sha256,
                "launch_nonce_sha256": hashlib.sha256(
                    launcher._launch_nonce.encode("utf-8")
                ).hexdigest(),
                "prior_failure_fingerprints": list(prior_fingerprints),
                "condition_change": condition,
                "created_at": _utc_iso(datetime.now(UTC)),
                "prose_persisted": False,
            }
            intent = cast(
                All60ReviewInvocationIntent,
                _sealed_model(All60ReviewInvocationIntent, intent_material),
            )
            store.write_intent(intent)
            all_intents.append(intent)
            outcome, produced_checkpoint = await _execute_review_attempt(
                launcher=launcher,
                run_id=run_id,
                issue=issue,
                identity=identity,
                intent=intent,
                runtime_binding=runtime_binding,
                memory_policy=memory_policy,
                prior_fingerprints=prior_fingerprints,
            )
            store.write_outcome(outcome)
            all_outcomes.append(outcome)
            if outcome.status in {"passed", "review_blocked"}:
                if produced_checkpoint is None or outcome.checkpoint != produced_checkpoint:
                    raise RuntimeError("all60_reviewer_checkpoint_outcome_mismatch")
                store.write_checkpoint(
                    ordinal=identity.ordinal,
                    row_id=identity.row_id,
                    checkpoint=produced_checkpoint,
                )
                checkpoint = produced_checkpoint
                terminal_blocked = outcome.status == "review_blocked"
                break
            if outcome.failure_fingerprint_sha256 is None:
                raise RuntimeError("all60_reviewer_failure_fingerprint_missing")
            prior_fingerprints.append(outcome.failure_fingerprint_sha256)
            if outcome.retry_action == "retry":
                continue
            terminal_blocked = True
            break
        if checkpoint is None:
            terminal_blocked = True
        if terminal_blocked or checkpoint is None or not _review_passes(checkpoint):
            last = all_outcomes[-1]
            reason = last.failure_reason_code or "ai_review_not_supported"
            checkpoint_digest = (
                checkpoint.seal_sha256
                if checkpoint is not None
                else identity.frozen_claim_bundle_sha256
            )
            fingerprint = last.failure_fingerprint_sha256 or failure_fingerprint(
                stage="all60_ai_evidence_review",
                reason_code=reason,
                scope_id=identity.row_id,
                identity_digests=(identity.identity_sha256, checkpoint_digest),
            )
            store.write_stop(
                _stop_payload(
                    manifest=manifest,
                    ordinal=identity.ordinal,
                    row_id=identity.row_id,
                    attempt_number=last.attempt_number,
                    reason_code=reason,
                    failure_fingerprint_sha256=fingerprint,
                )
            )
            raise RuntimeError("all60_reviewer_batch_frozen_for_debug")
        checkpoints.append(checkpoint)

    if len(checkpoints) != ALL60_ISSUE_COUNT:
        raise RuntimeError("all60_reviewer_checkpoint_set_incomplete")
    invocation_ids = [
        outcome.invocation_id for outcome in all_outcomes if outcome.invocation_id is not None
    ]
    invocation_nonces = [intent.invocation_nonce_sha256 for intent in all_intents]
    if len(invocation_ids) != len(set(invocation_ids)) or len(invocation_nonces) != len(
        set(invocation_nonces)
    ):
        raise RuntimeError("all60_reviewer_invocation_identity_reused")
    end_raw = await LoopbackCandidateCompletionLauncher.production_end_attestation(launcher)
    end = verify_launcher_attestation(
        end_raw,
        schema=LAUNCHER_END_SCHEMA,
        run_id=launcher.run_id,
        candidate=candidate,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
        integration_sha=str(runtime_binding["integration_sha"]),
        trusted_model_identity_sha256=str(runtime_binding["trusted_model_identity_sha256"]),
        trusted_toolchain_identity_sha256=str(model_toolchain["trusted_toolchain_identity_sha256"]),
        installed_environment_manifest_sha256=str(
            model_toolchain["installed_environment_manifest_sha256"]
        ),
        base_python_runtime_manifest_sha256=str(
            model_toolchain["base_python_runtime_manifest_sha256"]
        ),
        venv_control_manifest_sha256=str(model_toolchain["venv_control_manifest_sha256"]),
        launcher_implementation_sha256=str(runtime_binding["launcher_implementation_sha256"]),
        verified_start_attestation=start,
    )
    store.write_launcher_end(end)
    attestation = All60ReviewBatchAttestation.model_validate(
        _batch_attestation_material(
            manifest=manifest,
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=required_as_of_date,
            runtime_binding=runtime_binding,
            memory_policy=memory_policy,
            checkpoints=checkpoints,
            intents=all_intents,
            outcomes=all_outcomes,
            start=start,
            end=end,
            created_at=datetime.now(UTC),
        )
    )
    store.write_attestation(attestation)
    return attestation


def _validate_replayed_attempt(
    *,
    intent: All60ReviewInvocationIntent,
    outcome: All60ReviewInvocationOutcome,
    issue: TrustedAll60ReviewerInput,
    identity: All60ReviewIssueIdentity,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    prior_fingerprints: Sequence[str],
) -> AIReviewerClaimCheckpoint | None:
    expected_condition = (
        "initial_owned_runtime"
        if intent.attempt_number == 1
        else "fresh_owned_runtime_after_retryable_failure"
    )
    if (
        intent.ordinal != identity.ordinal
        or intent.row_id != identity.row_id
        or intent.issue_input_identity_sha256 != identity.identity_sha256
        or intent.runtime_binding_sha256 != runtime_binding["seal_sha256"]
        or intent.prior_failure_fingerprints != tuple(prior_fingerprints)
        or intent.condition_change != expected_condition
        or outcome.run_id != intent.run_id
        or outcome.ordinal != identity.ordinal
        or outcome.row_id != identity.row_id
        or outcome.attempt_number != intent.attempt_number
        or outcome.intent_seal_sha256 != intent.seal_sha256
        or outcome.request_id != intent.request_id
        or outcome.invocation_nonce_sha256 != intent.invocation_nonce_sha256
        or outcome.issue_input_identity_sha256 != identity.identity_sha256
        or outcome.memory_policy_sha256 != memory_policy.policy.seal_sha256
    ):
        raise ValueError("all60 reviewer attempt binding differs")

    memory_reason = _memory_failure_reason(
        _memory_observation_from_outcome(outcome), memory_policy.policy
    )
    if outcome.status in {"passed", "review_blocked"}:
        checkpoint = outcome.checkpoint
        if (
            memory_reason is not None
            or checkpoint is None
            or outcome.status != "passed"
            or outcome.deterministic_safety_failure
            or not _review_passes(checkpoint)
            or not _checkpoint_matches(
                checkpoint,
                issue=issue,
                identity=identity,
                runtime_binding=runtime_binding,
            )
            or checkpoint.invocation_trace.invocation_id != intent.request_id
            or checkpoint.invocation_trace.duration_ms != outcome.duration_ms
            or checkpoint.invocation_trace.input_token_count != outcome.input_token_count
            or checkpoint.invocation_trace.output_token_count != outcome.output_token_count
        ):
            raise ValueError("all60 reviewer passed attempt is not independently bound")
        return checkpoint

    reason_code = outcome.failure_reason_code
    fingerprint = outcome.failure_fingerprint_sha256
    if reason_code is None or fingerprint is None:
        raise ValueError("all60 reviewer failed attempt is incomplete")
    if memory_reason is not None and reason_code != memory_reason:
        raise ValueError("all60 reviewer memory failure was not applied before retry")
    expected_fingerprint = _semantic_failure_fingerprint(
        reason_code=reason_code,
        identity=identity,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
    )
    deterministic = reason_code in _DETERMINISTIC_REVIEW_FAILURE_CODES
    decision = decide_retry(
        attempt_number=intent.attempt_number,
        failure_reason_code=reason_code,
        failure_fingerprint_sha256=expected_fingerprint,
        prior_failure_fingerprints=prior_fingerprints,
        deterministic_safety=deterministic,
        retryable=not deterministic,
        input_or_condition_changed=(
            intent.attempt_number == 1
            or intent.condition_change == "fresh_owned_runtime_after_retryable_failure"
        ),
    )
    if (
        fingerprint != expected_fingerprint
        or outcome.deterministic_safety_failure is not deterministic
        or outcome.retry_action != decision.action
        or outcome.retry_reason != decision.reason
    ):
        raise ValueError("all60 reviewer retry decision replay differs")
    return None


def load_verified_all60_ai_review_batch(
    *,
    evaluation_root: Path,
    run_date: date,
    run_id: str,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    required_as_of_date: date,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    candidate_build_root: Path,
) -> VerifiedAll60AIReviewBatch:
    """Replay the exact 585-input batch and return an unforgeable capability."""

    from .all60_evidence_review import (
        load_all60_reviewer_batch_inputs,
    )

    _validate_runtime_binding(runtime_binding=runtime_binding, candidate=candidate)
    _validate_memory_policy_binding(
        memory_policy=memory_policy,
        candidate=candidate,
        runtime_binding=runtime_binding,
    )
    inventory = tuple(
        load_all60_reviewer_batch_inputs(
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=required_as_of_date,
            candidate_build_root=candidate_build_root,
        )
    )
    identities = _validate_inventory(cast(Sequence[TrustedAll60ReviewerInput], inventory))
    store = All60ReviewBatchStore(
        evaluation_root=evaluation_root,
        run_date=run_date,
        run_id=run_id,
        resume=True,
    )
    expected_run_members = (
        "batch-attestation.json",
        "checkpoints",
        "intents",
        "launcher-end-attestation.json",
        "launcher-start-attestation.json",
        "manifest.json",
        "outcomes",
    )
    if list_directory_at(evaluation_root, store.relative) != expected_run_members:
        raise ValueError("all60 reviewer batch root inventory differs")
    if store.read_stop() is not None:
        raise ValueError("all60 reviewer batch is frozen and not qualification eligible")

    manifest = store.read_manifest()
    attestation = store.read_attestation()
    if attestation is None:
        raise ValueError("all60 reviewer batch attestation is missing")
    start_raw = store.read_launcher_start()
    end_raw = store.read_launcher_end()
    model_toolchain = cast(Mapping[str, Any], runtime_binding["model_toolchain"])
    start = verify_launcher_attestation(
        start_raw,
        schema=LAUNCHER_START_SCHEMA,
        run_id=manifest.launcher_run_id,
        candidate=candidate,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
        integration_sha=str(runtime_binding["integration_sha"]),
        trusted_model_identity_sha256=str(runtime_binding["trusted_model_identity_sha256"]),
        trusted_toolchain_identity_sha256=str(model_toolchain["trusted_toolchain_identity_sha256"]),
        installed_environment_manifest_sha256=str(
            model_toolchain["installed_environment_manifest_sha256"]
        ),
        base_python_runtime_manifest_sha256=str(
            model_toolchain["base_python_runtime_manifest_sha256"]
        ),
        venv_control_manifest_sha256=str(model_toolchain["venv_control_manifest_sha256"]),
        launcher_implementation_sha256=str(runtime_binding["launcher_implementation_sha256"]),
    )
    end = verify_launcher_attestation(
        end_raw,
        schema=LAUNCHER_END_SCHEMA,
        run_id=manifest.launcher_run_id,
        candidate=candidate,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
        integration_sha=str(runtime_binding["integration_sha"]),
        trusted_model_identity_sha256=str(runtime_binding["trusted_model_identity_sha256"]),
        trusted_toolchain_identity_sha256=str(model_toolchain["trusted_toolchain_identity_sha256"]),
        installed_environment_manifest_sha256=str(
            model_toolchain["installed_environment_manifest_sha256"]
        ),
        base_python_runtime_manifest_sha256=str(
            model_toolchain["base_python_runtime_manifest_sha256"]
        ),
        venv_control_manifest_sha256=str(model_toolchain["venv_control_manifest_sha256"]),
        launcher_implementation_sha256=str(runtime_binding["launcher_implementation_sha256"]),
        verified_start_attestation=start,
    )
    expected_manifest = All60ReviewBatchManifest.model_validate(
        _manifest_material(
            run_id=run_id,
            run_date=run_date,
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=required_as_of_date,
            runtime_binding=runtime_binding,
            issue_identities=identities,
            launcher_run_id=manifest.launcher_run_id,
            launcher_start_attestation_sha256=str(start["seal_sha256"]),
            memory_policy=memory_policy,
        )
    )
    if manifest != expected_manifest:
        raise ValueError("all60 reviewer batch manifest binding differs")

    expected_checkpoint_names = tuple(
        store.checkpoint_name(item.ordinal, item.row_id) for item in identities
    )
    if store.members("checkpoints") != expected_checkpoint_names:
        raise ValueError("all60 reviewer checkpoint filenames differ")
    observed_intent_names = store.members("intents")
    observed_outcome_names = store.members("outcomes")
    if observed_intent_names != observed_outcome_names:
        raise ValueError("all60 reviewer intent/outcome filenames differ")

    checkpoints: list[AIReviewerClaimCheckpoint] = []
    intents: list[All60ReviewInvocationIntent] = []
    outcomes: list[All60ReviewInvocationOutcome] = []
    expected_attempt_names: list[str] = []
    runtime_instances_by_issue: dict[str, set[str]] = {}
    listener_proofs_by_issue: dict[str, set[str]] = {}
    launch_nonces_by_issue: dict[str, set[str]] = {}
    request_ids: set[str] = set()
    invocation_nonces: set[str] = set()
    for raw_issue, identity, checkpoint_name in zip(
        inventory, identities, expected_checkpoint_names, strict=True
    ):
        issue = cast(TrustedAll60ReviewerInput, raw_issue)
        prior_fingerprints: list[str] = []
        terminal_checkpoint: AIReviewerClaimCheckpoint | None = None
        runtime_instances = runtime_instances_by_issue.setdefault(identity.row_id, set())
        listener_proofs = listener_proofs_by_issue.setdefault(identity.row_id, set())
        launch_nonces = launch_nonces_by_issue.setdefault(identity.row_id, set())
        for attempt_number in range(1, MAX_ATTEMPTS + 1):
            attempt_name = store.attempt_name(identity.ordinal, identity.row_id, attempt_number)
            intent = store.read_intent(
                ordinal=identity.ordinal,
                row_id=identity.row_id,
                attempt=attempt_number,
            )
            outcome = store.read_outcome(
                ordinal=identity.ordinal,
                row_id=identity.row_id,
                attempt=attempt_number,
            )
            if intent is None and outcome is None:
                if attempt_number == 1 or terminal_checkpoint is None:
                    raise ValueError("all60 reviewer attempt ledger is incomplete")
                break
            if intent is None or outcome is None:
                raise ValueError("all60 reviewer intent/outcome pair is incomplete")
            expected_attempt_names.append(attempt_name)
            if (
                intent.run_id != run_id
                or intent.request_id in request_ids
                or intent.invocation_nonce_sha256 in invocation_nonces
                or (
                    attempt_number > 1
                    and (
                        intent.runtime_instance_sha256 in runtime_instances
                        or intent.owned_listener_proof_sha256 in listener_proofs
                        or intent.launch_nonce_sha256 in launch_nonces
                    )
                )
            ):
                raise ValueError("all60 reviewer invocation identity is reused")
            request_ids.add(intent.request_id)
            invocation_nonces.add(intent.invocation_nonce_sha256)
            runtime_instances.add(intent.runtime_instance_sha256)
            listener_proofs.add(intent.owned_listener_proof_sha256)
            launch_nonces.add(intent.launch_nonce_sha256)
            replayed_checkpoint = _validate_replayed_attempt(
                intent=intent,
                outcome=outcome,
                issue=issue,
                identity=identity,
                runtime_binding=runtime_binding,
                memory_policy=memory_policy,
                prior_fingerprints=prior_fingerprints,
            )
            intents.append(intent)
            outcomes.append(outcome)
            if replayed_checkpoint is not None:
                terminal_checkpoint = replayed_checkpoint
                if attempt_number < MAX_ATTEMPTS:
                    next_name = store.attempt_name(
                        identity.ordinal, identity.row_id, attempt_number + 1
                    )
                    if next_name in observed_intent_names or next_name in observed_outcome_names:
                        raise ValueError("all60 reviewer attempt exists after terminal pass")
                break
            assert outcome.failure_fingerprint_sha256 is not None
            prior_fingerprints.append(outcome.failure_fingerprint_sha256)
            if outcome.retry_action != "retry":
                raise ValueError("all60 reviewer terminal failure cannot qualify")
        if terminal_checkpoint is None:
            raise ValueError("all60 reviewer issue has no terminal passing checkpoint")
        persisted_checkpoint = AIReviewerClaimCheckpoint.model_validate(
            store._read(("checkpoints", checkpoint_name))
        )
        if persisted_checkpoint != terminal_checkpoint:
            raise ValueError("all60 reviewer checkpoint differs from its terminal outcome")
        checkpoints.append(persisted_checkpoint)

    exact_attempt_names = tuple(sorted(expected_attempt_names))
    if (
        observed_intent_names != exact_attempt_names
        or observed_outcome_names != exact_attempt_names
        or len(checkpoints) != ALL60_ISSUE_COUNT
        or len(intents) != len(outcomes)
        or len(intents) != len(request_ids)
        or len(intents) != len(invocation_nonces)
    ):
        raise ValueError("all60 reviewer exact ledger inventory differs")

    expected_attestation = All60ReviewBatchAttestation.model_validate(
        _batch_attestation_material(
            manifest=manifest,
            bundle=bundle,
            candidate=candidate,
            expert=expert,
            required_as_of_date=required_as_of_date,
            runtime_binding=runtime_binding,
            memory_policy=memory_policy,
            checkpoints=checkpoints,
            intents=intents,
            outcomes=outcomes,
            start=start,
            end=end,
            created_at=attestation.created_at,
        )
    )
    if attestation != expected_attestation:
        raise ValueError("all60 reviewer batch attestation replay differs")
    return VerifiedAll60AIReviewBatch(
        attestation=attestation,
        checkpoints=tuple(checkpoints),
        checkpoint_names=expected_checkpoint_names,
        checkpoint_directory=store.checkpoint_path,
        token=_VERIFIED_ALL60_AI_REVIEW_BATCH_TOKEN,
    )
