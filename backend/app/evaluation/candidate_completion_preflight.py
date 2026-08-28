"""Candidate-pinned, non-release full-workflow completion preflight.

The retrieval-only runtime preflight proves that the sealed candidate can be
queried.  This module proves the materially different property that complete
answer workflows (including deterministic gates and the independent evidence
reviewer) finish inside the provisional route/word-band ceilings.

Only safe counters, hashes and opaque identifiers are written here.  The
runtime adapter may retain workflow prose only in the application's encrypted
stores; it must never publish an answer or consult ``ACTIVE``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..observability.live_metrics import SLOBand, SLOPolicy, load_slo_policy, percentile
from ..orchestration.retry_policy import (
    MAX_ATTEMPTS,
    MAX_RETRIES,
    decide_retry,
    failure_fingerprint,
    is_deterministic_safety_failure,
    normalise_failure_reason_code,
)
from .candidate_completion_authority import (
    LAUNCHER_END_SCHEMA,
    LAUNCHER_START_SCHEMA,
    MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
    CompletionMemoryPolicy,
    LoadedCompletionMemoryPolicy,
    host_physical_memory_bytes,
    verify_launcher_attestation,
)
from .candidate_runtime_preflight import build_preflight_case_selection
from .live_suite import (
    LiveEvaluationBundle,
    LiveQuestionCase,
    load_live_evaluation_bundle,
    sealed_sha256,
)
from .nonrelease_artifacts import (
    CreateOnlyRunDirectory,
    sealed_safe_payload,
    verify_sealed_artifact,
)
from .owner_quality_canary_authorization import OwnerDecisionRequired
from .sealed_candidate import SealedCandidateIdentity

COMPLETION_PREFLIGHT_SCHEMA = "legalbot.candidate-completion-preflight.v3"
COMPLETION_SAMPLE_SCHEMA = "legalbot.candidate-completion-sample.v1"
COMPLETION_RESULT_SCHEMA = "legalbot.candidate-completion-result.v3"
COMPLETION_STOP_SCHEMA = "legalbot.candidate-completion-stop.v2"
COMPLETION_BINDING_SCHEMA = "legalbot.candidate-completion-runtime-binding.v2"
COMPLETION_RETRY_POLICY_VERSION = "legalbot.candidate-completion-retry-policy.v2"
COMPLETION_AUTHORITY_SCHEMA = "legalbot.candidate-completion-authority.v1"
COMPLETION_VERIFIED_RESULT_SCHEMA = "legalbot.verified-authoritative-completion-preflight.v1"

WARM_RUNS_PER_CASE = 3
COMPLETION_PREFLIGHT_POLICY = {
    "schema": "legalbot.candidate-completion-policy.v3",
    "case_specific_authority": False,
    "representative_selection": "generic-sealed-hash-ranked-case-per-route-word-band",
    "cold_definition": "first-full-workflow-after-verified-fresh-model-instance-per-case",
    "warm_definition": "three-subsequent-full-workflows-on-the-same-model-instance",
    "warm_runs_per_case": WARM_RUNS_PER_CASE,
    "percentile_population": "successful-warm-workflows-only",
    "percentile": 0.95,
    "attempts": MAX_ATTEMPTS,
    "retries": MAX_RETRIES,
    "repeat_fingerprint": "stop-on-second-occurrence",
    "owner_memory_policy_application": "every-attempt-before-retry-classification",
    "release_allowed": False,
    "active_required": False,
    "online_research_allowed": False,
}
COMPLETION_PREFLIGHT_POLICY_SHA256 = sealed_sha256(COMPLETION_PREFLIGHT_POLICY)
COMPLETION_RETRY_POLICY_SHA256 = sealed_sha256(
    {
        "schema": COMPLETION_RETRY_POLICY_VERSION,
        "max_attempts": MAX_ATTEMPTS,
        "max_retries": MAX_RETRIES,
        "deterministic_safety_failures_retry": False,
        "repeated_failure_fingerprint_stops": True,
        "owner_memory_breach_stops_before_retry": True,
        "missing_attempt_memory_measurement_stops_before_retry": True,
        "whole_workflow_retry_creates_new_encrypted_job": True,
    }
)

_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DETERMINISTIC_PREFLIGHT_FAILURES = frozenset(
    {
        "answer_release_state_present",
        "candidate_identity_mismatch",
        "cold_model_restart_unavailable",
        "evidence_empty",
        "hard_quality_gate_failed",
        "model_identity_mismatch",
        "model_artifact_identity_mismatch",
        "model_artifact_manifest_invalid",
        "model_sidecar_identity_mismatch",
        "model_listener_not_exclusively_loopback",
        "model_socket_owner_unverifiable",
        "memory_headroom_below_owner_minimum",
        "memory_measurement_unavailable",
        "memory_measurement_identity_invalid",
        "memory_sampling_interval_exceeded",
        "memory_working_set_exceeds_owner_ceiling",
        "non_loopback_runtime",
        "online_research_enabled",
        "owned_sidecar_nonce_mismatch",
        "owned_sidecar_process_missing",
        "plaintext_prose_written",
        "public_release_attempted",
        "route_identity_mismatch",
        "runtime_binding_mismatch",
        "standards_identity_mismatch",
        "reviewer_identity_mismatch",
        "word_tolerance_failed",
    }
)


class CompletionWorkflowObservation(BaseModel):
    """One prose-free observation returned by a full-workflow runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.candidate-completion-observation.v2"] = Field(
        default="legalbot.candidate-completion-observation.v2", alias="schema"
    )
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sample_kind: Literal["cold", "warm"]
    sample_ordinal: int = Field(ge=1, le=WARM_RUNS_PER_CASE)
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS)
    route: Literal["sectioned", "full_enquiry"]
    word_target: int = Field(ge=1_000, le=10_000)
    slo_band_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_]{2,63}$")
    runtime_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_instance_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    cold_launch_proof_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    model_version: str = Field(min_length=1, max_length=255)
    model_state: Literal["verified_fresh_instance", "warm_same_instance", "unavailable"]
    retrieval_cache_state: Literal["bypassed", "enabled_state_unobserved", "unavailable"]
    status: Literal["succeeded", "failed"]
    failure_reason_code: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    completion_seconds: float = Field(ge=0)
    stage_timings_seconds: dict[str, float]
    reviewer_phase_seconds: float = Field(ge=0)
    ttft_observed: bool
    time_to_first_token_seconds: float | None = Field(default=None, ge=0)
    controller_peak_rss_bytes: int = Field(ge=0)
    sidecar_peak_rss_bytes: int = Field(ge=0)
    model_allocator_peak_bytes: int | None = Field(default=None, ge=0)
    peak_combined_working_set_bytes: int = Field(ge=0)
    minimum_host_available_memory_bytes: int = Field(ge=0)
    memory_measurement_schema: Literal["legalbot.completion-memory-measurement.v2"] = (
        "legalbot.completion-memory-measurement.v2"
    )
    memory_measurement_method: Literal[
        "owned_process_tree_os_rss_and_host_available_sampled_100ms"
    ] = "owned_process_tree_os_rss_and_host_available_sampled_100ms"
    memory_sampling_interval_seconds: float = Field(default=0.1, gt=0, le=0.1)
    memory_max_allowed_sample_interval_seconds: float = Field(default=0.25, gt=0, le=0.25)
    memory_sample_count: int = Field(ge=0)
    memory_max_observed_sample_interval_seconds: float = Field(ge=0)
    memory_max_sampling_jitter_seconds: float = Field(ge=0)
    startup_controller_peak_rss_bytes: int = Field(ge=0)
    startup_sidecar_peak_rss_bytes: int = Field(ge=0)
    startup_peak_combined_working_set_bytes: int = Field(ge=0)
    startup_minimum_host_available_memory_bytes: int = Field(ge=0)
    startup_memory_sample_count: int = Field(ge=0)
    startup_memory_max_observed_sample_interval_seconds: float = Field(ge=0)
    startup_memory_max_sampling_jitter_seconds: float = Field(ge=0)
    startup_memory_measurement_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    input_token_count: int = Field(ge=0)
    output_token_count: int = Field(ge=0)
    total_token_count: int = Field(ge=0)
    evidence_span_count: int = Field(ge=0)
    material_claim_count: int = Field(ge=0)
    quality_release_state: str | None = Field(default=None, max_length=64)
    hard_quality_gates_passed: bool
    ai_evidence_reviewer_passed: bool
    standards_avoidance_passed: bool
    word_tolerance_passed: bool
    public_release_written: bool
    answer_release_state_present: bool
    plaintext_prose_written: bool
    encrypted_prose_retained: bool

    @field_validator("stage_timings_seconds")
    @classmethod
    def timings_are_safe(cls, value: dict[str, float]) -> dict[str, float]:
        required = {"retrieval", "drafting", "verification", "reviewer"}
        if not required.issubset(value):
            raise ValueError("completion observation omits required stage timings")
        cleaned: dict[str, float] = {}
        for key, raw in value.items():
            if not _SAFE_CODE.fullmatch(key):
                raise ValueError("completion stage timing key is unsafe")
            number = float(raw)
            if number < 0:
                raise ValueError("completion stage timing cannot be negative")
            cleaned[key] = round(number, 6)
        return cleaned

    @model_validator(mode="after")
    def observation_is_consistent(self) -> CompletionWorkflowObservation:
        if self.memory_max_allowed_sample_interval_seconds != MEMORY_MAX_SAMPLE_INTERVAL_SECONDS:
            raise ValueError("memory sampling precision policy is not the tracked maximum")
        if self.sample_kind == "cold" and self.sample_ordinal != 1:
            raise ValueError("cold sample ordinal must be one")
        if self.ttft_observed != (self.time_to_first_token_seconds is not None):
            raise ValueError("TTFT observability flag disagrees with its value")
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("completion token totals are inconsistent")
        maximum_possible_combined = self.controller_peak_rss_bytes + self.sidecar_peak_rss_bytes
        if not (
            max(self.controller_peak_rss_bytes, self.sidecar_peak_rss_bytes)
            <= self.peak_combined_working_set_bytes
            <= maximum_possible_combined
        ):
            raise ValueError("combined working-set measurement is inconsistent")
        startup_maximum_possible_combined = (
            self.startup_controller_peak_rss_bytes + self.startup_sidecar_peak_rss_bytes
        )
        if not (
            max(self.startup_controller_peak_rss_bytes, self.startup_sidecar_peak_rss_bytes)
            <= self.startup_peak_combined_working_set_bytes
            <= startup_maximum_possible_combined
        ):
            raise ValueError("startup combined working-set measurement is inconsistent")
        if self.status == "failed":
            if self.failure_reason_code is None:
                raise ValueError("failed completion observation needs a safe reason code")
            return self
        if self.failure_reason_code is not None:
            raise ValueError("successful completion observation cannot have a failure code")
        if (
            self.completion_seconds <= 0
            or sum(self.stage_timings_seconds.values()) <= 0
            or abs(self.stage_timings_seconds["reviewer"] - self.reviewer_phase_seconds) > 1e-6
            or self.total_token_count < 1
            or self.peak_combined_working_set_bytes < 1
            or self.minimum_host_available_memory_bytes < 1
            or self.sidecar_peak_rss_bytes < 1
            or self.memory_sample_count < 1
            or self.memory_max_observed_sample_interval_seconds
            > self.memory_max_allowed_sample_interval_seconds
            or self.startup_peak_combined_working_set_bytes < 1
            or self.startup_minimum_host_available_memory_bytes < 1
            or self.startup_memory_sample_count < 1
            or self.startup_memory_max_observed_sample_interval_seconds
            > self.memory_max_allowed_sample_interval_seconds
            or self.startup_memory_measurement_sha256 is None
        ):
            raise ValueError("successful workflow omits required timing, token or memory metrics")
        if (
            self.evidence_span_count < 1
            or self.material_claim_count < 1
            or self.quality_release_state != "verified_full"
            or not self.hard_quality_gates_passed
            or not self.ai_evidence_reviewer_passed
            or not self.standards_avoidance_passed
            or not self.word_tolerance_passed
            or self.public_release_written
            or self.answer_release_state_present
            or self.plaintext_prose_written
            or not self.encrypted_prose_retained
        ):
            raise ValueError("successful completion observation did not pass every hard gate")
        if self.runtime_instance_sha256 is None or self.cold_launch_proof_sha256 is None:
            raise ValueError("successful workflow omits its fresh-instance proof binding")
        expected_model_state = (
            "verified_fresh_instance" if self.sample_kind == "cold" else "warm_same_instance"
        )
        expected_cache_state = (
            "bypassed" if self.sample_kind == "cold" else "enabled_state_unobserved"
        )
        if self.model_state != expected_model_state:
            raise ValueError("workflow model-state label is not supported by its launch proof")
        if self.retrieval_cache_state != expected_cache_state:
            raise ValueError("workflow retrieval-cache state is overstated or inconsistent")
        return self


class SyntheticCompletionWorkflowRuntime(Protocol):
    """Test-only workflow adapter; its results can never be authoritative."""

    async def run_workflow(
        self,
        *,
        case: LiveQuestionCase,
        band: SLOBand,
        as_of_date: date,
        sample_kind: Literal["cold", "warm"],
        sample_ordinal: int,
        attempt_number: int,
        runtime_binding_sha256: str,
    ) -> CompletionWorkflowObservation: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


@dataclass(frozen=True, slots=True)
class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def completion_runtime_binding(
    *,
    candidate: SealedCandidateIdentity,
    model_id: str,
    model_revision: str,
    model_version: str,
    model_runtime_implementation_sha256: str,
    launcher_implementation_sha256: str,
    authority_implementation_sha256: str,
    model_artifact_metadata_sha256: str,
    trusted_model_identity_sha256: str,
    model_toolchain: Mapping[str, str],
    model_runtime_profile: Mapping[str, int | bool],
    draft_prompt_version: str,
    draft_prompt_implementation_sha256: str,
    quality_policy_version: str,
    quality_policy_sha256: str,
    standards_bundle_version: str,
    standards_bundle_sha256: str,
    reviewer_role: str,
    reviewer_prompt_sha256: str,
    reviewer_policy_sha256: str,
    reviewer_toolchain_sha256: str,
    reviewer_implementation_sha256: str,
    retry_implementation_sha256: str,
    slo_policy_id: str,
    slo_policy_sha256: str,
    integration_sha: str,
) -> dict[str, Any]:
    """Seal the exact identities that every observed workflow must match."""

    for value in (
        draft_prompt_implementation_sha256,
        model_runtime_implementation_sha256,
        launcher_implementation_sha256,
        authority_implementation_sha256,
        model_artifact_metadata_sha256,
        trusted_model_identity_sha256,
        quality_policy_sha256,
        standards_bundle_sha256,
        reviewer_prompt_sha256,
        reviewer_policy_sha256,
        reviewer_toolchain_sha256,
        reviewer_implementation_sha256,
        retry_implementation_sha256,
        slo_policy_sha256,
        *model_toolchain.values(),
    ):
        if not _SHA256.fullmatch(value):
            raise ValueError("completion runtime binding contains an invalid digest")
    if not re.fullmatch(r"[0-9a-f]{40,64}", integration_sha):
        raise ValueError("completion runtime binding integration SHA is invalid")
    expected_toolchain_keys = {
        "trusted_toolchain_identity_sha256",
        "uv_executable_sha256",
        "python_executable_sha256",
        "model_runtime_lock_sha256",
        "model_runtime_pyproject_sha256",
        "locked_package_set_sha256",
        "launch_environment_policy_sha256",
        "installed_environment_manifest_sha256",
        "base_python_runtime_manifest_sha256",
        "venv_control_manifest_sha256",
        "system_tool_set_sha256",
    }
    if set(model_toolchain) != expected_toolchain_keys:
        raise ValueError("completion runtime binding toolchain identity is incomplete")
    expected_profile_keys = {
        "context_window_tokens",
        "max_output_tokens",
        "prefill_step_size",
        "kv_cache_bits",
        "kv_group_size",
        "clear_cache_after_request",
        "single_flight_generation",
    }
    if set(model_runtime_profile) != expected_profile_keys:
        raise ValueError("completion runtime binding memory profile is incomplete")
    if any(
        isinstance(value, int) and not isinstance(value, bool) and value < 1
        for value in model_runtime_profile.values()
    ):
        raise ValueError("completion runtime binding memory profile is invalid")
    return sealed_safe_payload(
        {
            "schema": COMPLETION_BINDING_SCHEMA,
            **candidate.safe_dict(),
            "model_id": model_id,
            "model_revision": model_revision,
            "model_version": model_version,
            "model_runtime_implementation_sha256": model_runtime_implementation_sha256,
            "launcher_implementation_sha256": launcher_implementation_sha256,
            "authority_implementation_sha256": authority_implementation_sha256,
            "model_artifact_metadata_sha256": model_artifact_metadata_sha256,
            "trusted_model_identity_sha256": trusted_model_identity_sha256,
            "model_toolchain": dict(model_toolchain),
            "model_runtime_profile": dict(model_runtime_profile),
            "draft_prompt_version": draft_prompt_version,
            "draft_prompt_implementation_sha256": draft_prompt_implementation_sha256,
            "quality_policy_version": quality_policy_version,
            "quality_policy_sha256": quality_policy_sha256,
            "standards_bundle_version": standards_bundle_version,
            "standards_bundle_sha256": standards_bundle_sha256,
            "reviewer_role": reviewer_role,
            "reviewer_prompt_sha256": reviewer_prompt_sha256,
            "reviewer_policy_sha256": reviewer_policy_sha256,
            "reviewer_toolchain_sha256": reviewer_toolchain_sha256,
            "reviewer_implementation_sha256": reviewer_implementation_sha256,
            "retry_policy_version": COMPLETION_RETRY_POLICY_VERSION,
            "retry_policy_sha256": COMPLETION_RETRY_POLICY_SHA256,
            "retry_implementation_sha256": retry_implementation_sha256,
            "max_attempts": MAX_ATTEMPTS,
            "max_retries": MAX_RETRIES,
            "slo_policy_id": slo_policy_id,
            "slo_policy_sha256": slo_policy_sha256,
            "integration_sha": integration_sha,
        }
    )


def _validate_observation_binding(
    observation: CompletionWorkflowObservation,
    *,
    case: LiveQuestionCase,
    band: SLOBand,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
    sample_kind: Literal["cold", "warm"],
    sample_ordinal: int,
    attempt_number: int,
) -> None:
    expected = (
        case.case_id,
        case.question_sha256,
        sample_kind,
        sample_ordinal,
        attempt_number,
        case.expected_research_route,
        case.word_target,
        band.id,
        runtime_binding["seal_sha256"],
        candidate.build_id,
        runtime_binding["model_version"],
    )
    observed = (
        observation.case_id,
        observation.question_sha256,
        observation.sample_kind,
        observation.sample_ordinal,
        observation.attempt_number,
        observation.route,
        observation.word_target,
        observation.slo_band_id,
        observation.runtime_binding_sha256,
        observation.candidate_build_id,
        observation.model_version,
    )
    if observed != expected:
        raise RuntimeError("runtime_binding_mismatch")


def _safe_reason_code(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if _SAFE_CODE.fullmatch(explicit):
            return explicit
    candidate = re.sub(r"(?<!^)(?=[A-Z])", "_", type(exc).__name__).casefold()
    return normalise_failure_reason_code(candidate.removesuffix("_exception") or "runtime_error")


def _failed_observation(
    *,
    case: LiveQuestionCase,
    band: SLOBand,
    sample_kind: Literal["cold", "warm"],
    sample_ordinal: int,
    attempt_number: int,
    runtime_binding: Mapping[str, Any],
    candidate: SealedCandidateIdentity,
    reason_code: str,
) -> CompletionWorkflowObservation:
    return CompletionWorkflowObservation(
        case_id=case.case_id,
        question_sha256=case.question_sha256,
        sample_kind=sample_kind,
        sample_ordinal=sample_ordinal,
        attempt_number=attempt_number,
        route=case.expected_research_route,
        word_target=case.word_target,
        slo_band_id=band.id,
        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
        candidate_build_id=candidate.build_id,
        model_version=str(runtime_binding["model_version"]),
        model_state="unavailable",
        retrieval_cache_state="unavailable",
        status="failed",
        failure_reason_code=normalise_failure_reason_code(reason_code),
        completion_seconds=0,
        stage_timings_seconds={
            "retrieval": 0,
            "drafting": 0,
            "verification": 0,
            "reviewer": 0,
        },
        reviewer_phase_seconds=0,
        ttft_observed=False,
        time_to_first_token_seconds=None,
        controller_peak_rss_bytes=0,
        sidecar_peak_rss_bytes=0,
        model_allocator_peak_bytes=None,
        peak_combined_working_set_bytes=0,
        minimum_host_available_memory_bytes=0,
        memory_sample_count=0,
        memory_max_allowed_sample_interval_seconds=0.25,
        memory_max_observed_sample_interval_seconds=0,
        memory_max_sampling_jitter_seconds=0,
        startup_controller_peak_rss_bytes=0,
        startup_sidecar_peak_rss_bytes=0,
        startup_peak_combined_working_set_bytes=0,
        startup_minimum_host_available_memory_bytes=0,
        startup_memory_sample_count=0,
        startup_memory_max_observed_sample_interval_seconds=0,
        startup_memory_max_sampling_jitter_seconds=0,
        startup_memory_measurement_sha256=None,
        input_token_count=0,
        output_token_count=0,
        total_token_count=0,
        evidence_span_count=0,
        material_claim_count=0,
        quality_release_state=None,
        hard_quality_gates_passed=False,
        ai_evidence_reviewer_passed=False,
        standards_avoidance_passed=False,
        word_tolerance_passed=False,
        public_release_written=False,
        answer_release_state_present=False,
        plaintext_prose_written=False,
        encrypted_prose_retained=True,
    )


def _sample_labels() -> tuple[tuple[Literal["cold", "warm"], int], ...]:
    return (("cold", 1), *(("warm", ordinal) for ordinal in range(1, 4)))


def _completion_case_contract(case: LiveQuestionCase, slo_policy: SLOPolicy) -> dict[str, Any]:
    band = slo_policy.band_for(
        route=case.expected_research_route,
        word_target=case.word_target,
    )
    band_contract = {
        "schema": "legalbot.completion-preflight-slo-band.v1",
        "slo_band_id": band.id,
        "route": band.route,
        "word_min": band.word_min,
        "word_max": band.word_max,
        "targets_p95_seconds": dict(sorted(band.targets_p95_seconds.items())),
    }
    return {
        "case_id": case.case_id,
        "question_sha256": case.question_sha256,
        "record_sha256": case.record_sha256,
        "task_type": case.task_type,
        "route": case.expected_research_route,
        "word_target": case.word_target,
        "slo_band_id": band.id,
        "slo_band_sha256": sealed_sha256(band_contract),
        "completion_p95_ceiling_seconds": float(band.targets_p95_seconds["completion_seconds"]),
    }


def _verify_completion_case_selection(
    manifest: Mapping[str, Any],
    *,
    bundle: LiveEvaluationBundle,
    slo_policy: SLOPolicy,
) -> tuple[tuple[str, ...], list[dict[str, Any]]]:
    """Rebuild the generic route/word-band representative set."""

    case_ids_value = manifest.get("case_ids")
    if not isinstance(case_ids_value, list) or not all(
        isinstance(case_id, str) and re.fullmatch(r"live60-q[0-9]{2}", case_id)
        for case_id in case_ids_value
    ):
        raise RuntimeError("authoritative_completion_preflight_case_contract_invalid")
    case_ids = tuple(case_ids_value)
    expected_selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo_policy,
        additional_case_ids=None,
    )
    expected_case_ids = expected_selection.selected_case_ids
    expected_case_contracts = [
        _completion_case_contract(bundle.registry.case(case_id), slo_policy)
        for case_id in expected_case_ids
    ]
    expected_plan = [
        {"sample_kind": kind, "sample_ordinal": ordinal} for kind, ordinal in _sample_labels()
    ]
    if (
        case_ids != expected_case_ids
        or manifest.get("case_count") != len(case_ids)
        or manifest.get("case_selection") != expected_selection.safe_dict()
        or manifest.get("case_contracts") != expected_case_contracts
        or manifest.get("sample_plan") != expected_plan
        or manifest.get("warm_runs_per_case") != WARM_RUNS_PER_CASE
    ):
        raise RuntimeError("authoritative_completion_preflight_case_contract_invalid")
    return case_ids, expected_case_contracts


def _band_summaries(
    *, samples: Sequence[Mapping[str, Any]], slo_policy: SLOPolicy
) -> list[dict[str, Any]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    ttft: dict[str, list[float]] = defaultdict(list)
    for sample in samples:
        if sample["sample_kind"] != "warm":
            continue
        grouped[str(sample["slo_band_id"])].append(float(sample["completion_seconds"]))
        observed_ttft = sample.get("time_to_first_token_seconds")
        if isinstance(observed_ttft, int | float):
            ttft[str(sample["slo_band_id"])].append(float(observed_ttft))
    summaries: list[dict[str, Any]] = []
    for band_id in sorted(grouped):
        band = slo_policy.band_by_id(band_id)
        values = grouped[band_id]
        observed = percentile(values, 0.95)
        ceiling = float(band.targets_p95_seconds["completion_seconds"])
        observed_ttft = percentile(ttft.get(band_id, ()), 0.95)
        summaries.append(
            {
                "slo_band_id": band_id,
                "route": band.route,
                "warm_sample_count": len(values),
                "minimum_warm_sample_count": WARM_RUNS_PER_CASE,
                "completion_p95_seconds": observed,
                "completion_p95_ceiling_seconds": ceiling,
                "completion_p95_passed": observed is not None and observed <= ceiling,
                "ttft_sample_count": len(ttft.get(band_id, ())),
                "ttft_p95_seconds": observed_ttft,
                "ttft_p95_ceiling_seconds": float(
                    band.targets_p95_seconds["time_to_first_token_seconds"]
                ),
            }
        )
    return summaries


def _memory_policy_failure(
    observation: CompletionWorkflowObservation,
    policy: CompletionMemoryPolicy | None,
) -> CompletionWorkflowObservation:
    if policy is None:
        return observation
    reason_code: str | None = None
    if (
        observation.memory_sample_count < 1
        or observation.startup_memory_sample_count < 1
        or observation.peak_combined_working_set_bytes < 1
        or observation.startup_peak_combined_working_set_bytes < 1
        or observation.sidecar_peak_rss_bytes < 1
        or observation.startup_sidecar_peak_rss_bytes < 1
        or observation.minimum_host_available_memory_bytes < 1
        or observation.startup_minimum_host_available_memory_bytes < 1
        or observation.startup_memory_measurement_sha256 is None
    ):
        reason_code = "memory_measurement_unavailable"
    elif (
        observation.memory_max_observed_sample_interval_seconds
        > observation.memory_max_allowed_sample_interval_seconds
        or observation.startup_memory_max_observed_sample_interval_seconds
        > observation.memory_max_allowed_sample_interval_seconds
    ):
        reason_code = "memory_sampling_interval_exceeded"
    elif (
        max(
            observation.peak_combined_working_set_bytes,
            observation.startup_peak_combined_working_set_bytes,
        )
        > policy.max_peak_combined_working_set_bytes
    ):
        reason_code = "memory_working_set_exceeds_owner_ceiling"
    elif (
        min(
            observation.minimum_host_available_memory_bytes,
            observation.startup_minimum_host_available_memory_bytes,
        )
        < policy.minimum_host_available_memory_bytes
    ):
        reason_code = "memory_headroom_below_owner_minimum"
    if reason_code is None:
        return observation
    payload = observation.model_dump(mode="json", by_alias=True)
    payload.update(status="failed", failure_reason_code=reason_code)
    return CompletionWorkflowObservation.model_validate(payload)


def _validate_memory_policy_binding(
    policy: CompletionMemoryPolicy,
    *,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
    require_host_match: bool,
) -> None:
    if (
        policy.candidate_build_id != candidate.build_id
        or policy.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        or policy.runtime_binding_sha256 != runtime_binding.get("seal_sha256")
        or policy.integration_sha != runtime_binding.get("integration_sha")
        or (
            require_host_match and policy.host_physical_memory_bytes != host_physical_memory_bytes()
        )
    ):
        raise ValueError("completion memory policy binding mismatch")


def _verify_completion_memory_envelope(
    policy: CompletionMemoryPolicy,
    *,
    observed_maximum_peak: int,
    observed_minimum_headroom: int | None,
) -> None:
    """Replay the owner-selected ceiling against startup and workflow observations."""

    if (
        observed_maximum_peak > policy.max_peak_combined_working_set_bytes
        or observed_minimum_headroom is None
        or observed_minimum_headroom < policy.minimum_host_available_memory_bytes
    ):
        raise RuntimeError("authoritative_completion_preflight_memory_policy_exceeded")


def _memory_observation_extrema(
    observations: Sequence[Mapping[str, Any]],
) -> tuple[int, int | None]:
    """Return run-wide peak and headroom across successful and failed attempts."""

    maximum_peak = 0
    minimum_headroom: int | None = None
    for observation in observations:
        maximum_peak = max(
            maximum_peak,
            int(observation["peak_combined_working_set_bytes"]),
            int(observation["startup_peak_combined_working_set_bytes"]),
        )
        observed_headroom = min(
            int(observation["minimum_host_available_memory_bytes"]),
            int(observation["startup_minimum_host_available_memory_bytes"]),
        )
        minimum_headroom = (
            observed_headroom
            if minimum_headroom is None
            else min(minimum_headroom, observed_headroom)
        )
    return maximum_peak, minimum_headroom


def _load_private_completion_artifact(path: Path, *, run_dir: Path) -> dict[str, Any]:
    try:
        path.resolve(strict=True).relative_to(run_dir)
        metadata = path.lstat()
    except (OSError, ValueError) as exc:
        raise RuntimeError("authoritative_completion_preflight_artifact_invalid") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_size > 8 * 1024 * 1024
    ):
        raise RuntimeError("authoritative_completion_preflight_storage_invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, Mapping):
            raise ValueError
        return verify_sealed_artifact(value)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("authoritative_completion_preflight_artifact_invalid") from exc


def _verify_completion_retry_attempt(
    attempt: Mapping[str, Any],
    *,
    case: LiveQuestionCase,
    band: SLOBand,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
    sample_kind: Literal["cold", "warm"],
    sample_ordinal: int,
    attempt_number: int,
    prior_fingerprints: Sequence[str],
    memory_policy: CompletionMemoryPolicy,
) -> str:
    """Replay a persisted retry decision from its exact deterministic inputs."""

    try:
        failed_observation = CompletionWorkflowObservation.model_validate(
            {
                key: value
                for key, value in attempt.items()
                if key
                not in {
                    "seal_sha256",
                    "failure_fingerprint_sha256",
                    "decision_action",
                    "decision_reason",
                    "retries_remaining",
                }
            }
        )
        _validate_observation_binding(
            failed_observation,
            case=case,
            band=band,
            candidate=candidate,
            runtime_binding=runtime_binding,
            sample_kind=sample_kind,
            sample_ordinal=sample_ordinal,
            attempt_number=attempt_number,
        )
        failed_observation = _memory_policy_failure(failed_observation, memory_policy)
    except (RuntimeError, ValueError) as exc:
        raise RuntimeError("authoritative_completion_preflight_retry_chain_invalid") from exc
    reason_code = normalise_failure_reason_code(
        str(failed_observation.failure_reason_code or "runtime_error")
    )
    expected_fingerprint = failure_fingerprint(
        stage="completion_preflight",
        reason_code=reason_code,
        scope_id=case.case_id,
        identity_digests=(
            case.question_sha256,
            candidate.candidate_manifest_sha256,
            str(runtime_binding["seal_sha256"]),
        ),
        safe_context={
            "sample_kind": sample_kind,
            "sample_ordinal": sample_ordinal,
        },
    )
    deterministic = (
        reason_code in _DETERMINISTIC_PREFLIGHT_FAILURES
        or is_deterministic_safety_failure(reason_code)
    )
    decision = decide_retry(
        attempt_number=attempt_number,
        failure_reason_code=reason_code,
        failure_fingerprint_sha256=expected_fingerprint,
        prior_failure_fingerprints=prior_fingerprints,
        deterministic_safety=deterministic,
        retryable=not deterministic,
        input_or_condition_changed=not deterministic,
    )
    if (
        failed_observation.status != "failed"
        or attempt.get("failure_reason_code") != reason_code
        or attempt.get("failure_fingerprint_sha256") != expected_fingerprint
        or attempt.get("decision_action") != decision.action
        or attempt.get("decision_reason") != decision.reason
        or attempt.get("retries_remaining") != decision.retries_remaining
        or not decision.should_retry
    ):
        raise RuntimeError("authoritative_completion_preflight_retry_chain_invalid")
    return expected_fingerprint


def load_verified_authoritative_completion_preflight(
    run_dir: Path,
    *,
    project_root: Path,
    memory_policy: LoadedCompletionMemoryPolicy,
    expected_candidate_build_id: str,
    expected_candidate_manifest_sha256: str,
    expected_integration_sha: str,
    expected_runtime_binding_sha256: str,
    expected_trusted_toolchain_identity_sha256: str,
    expected_base_python_runtime_manifest_sha256: str,
    expected_venv_control_manifest_sha256: str,
) -> dict[str, Any]:
    """Replay one passing production preflight for downstream authorization.

    This is the only public completion-preflight loader intended for Stage A,
    canary authorization, promotion, or readiness.  Synthetic results and
    caller-injected observations fail before an authorization envelope exists.
    """

    if type(memory_policy) is not LoadedCompletionMemoryPolicy:
        raise RuntimeError("completion_memory_policy_not_loader_verified")
    if project_root.is_symlink() or not project_root.is_dir():
        raise RuntimeError("authoritative_completion_preflight_project_invalid")
    resolved_project_root = project_root.resolve(strict=True)
    bundle_root = resolved_project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    slo_policy_path = resolved_project_root / "config/observability_slo.yaml"
    if bundle_root.is_symlink() or slo_policy_path.is_symlink():
        raise RuntimeError("authoritative_completion_preflight_policy_source_invalid")
    try:
        bundle = load_live_evaluation_bundle(bundle_root)
        slo_policy = load_slo_policy(slo_policy_path)
        slo_policy_source_file_sha256 = hashlib.sha256(slo_policy_path.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        raise RuntimeError("authoritative_completion_preflight_policy_source_invalid") from exc
    expected_suite_manifest_seal_sha256 = bundle.manifest.seal_sha256
    expected_memory_policy_sha256 = memory_policy.policy.seal_sha256
    expected_digests = (
        expected_candidate_manifest_sha256,
        expected_suite_manifest_seal_sha256,
        expected_runtime_binding_sha256,
        expected_memory_policy_sha256,
        expected_trusted_toolchain_identity_sha256,
        expected_base_python_runtime_manifest_sha256,
        expected_venv_control_manifest_sha256,
    )
    if (
        not _SAFE_CODE.fullmatch(expected_candidate_build_id)
        or not re.fullmatch(r"[0-9a-f]{40,64}", expected_integration_sha)
        or any(not _SHA256.fullmatch(value) for value in expected_digests)
        or not _SHA256.fullmatch(memory_policy.source_file_sha256)
        or run_dir.is_symlink()
        or not run_dir.is_dir()
    ):
        raise RuntimeError("authoritative_completion_preflight_binding_invalid")
    resolved_run_dir = run_dir.resolve(strict=True)
    run_metadata = resolved_run_dir.stat()
    if (
        stat.S_IMODE(run_metadata.st_mode) != 0o700
        or run_metadata.st_uid != os.getuid()
        or not _SAFE_CODE.fullmatch(resolved_run_dir.name)
    ):
        raise RuntimeError("authoritative_completion_preflight_storage_invalid")

    actual_members: set[str] = set()
    for member in resolved_run_dir.rglob("*"):
        relative_name = member.relative_to(resolved_run_dir).as_posix()
        metadata = member.lstat()
        if member.is_symlink():
            raise RuntimeError("authoritative_completion_preflight_storage_invalid")
        if member.is_dir():
            if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
                raise RuntimeError("authoritative_completion_preflight_storage_invalid")
            continue
        if not member.is_file() or member.suffix != ".json":
            raise RuntimeError("authoritative_completion_preflight_storage_invalid")
        actual_members.add(relative_name)

    manifest = _load_private_completion_artifact(
        resolved_run_dir / "run-manifest.json", run_dir=resolved_run_dir
    )
    result = _load_private_completion_artifact(
        resolved_run_dir / "result.json", run_dir=resolved_run_dir
    )
    runtime_binding = manifest.get("runtime_binding")
    authority = manifest.get("authority")
    if not isinstance(runtime_binding, Mapping) or not isinstance(authority, Mapping):
        raise RuntimeError("authoritative_completion_preflight_manifest_invalid")
    try:
        verified_runtime_binding = verify_sealed_artifact(
            runtime_binding, schema=COMPLETION_BINDING_SCHEMA
        )
    except ValueError as exc:
        raise RuntimeError("authoritative_completion_preflight_manifest_invalid") from exc
    model_toolchain = verified_runtime_binding.get("model_toolchain")
    if not isinstance(model_toolchain, Mapping):
        raise RuntimeError("authoritative_completion_preflight_manifest_invalid")
    candidate = SealedCandidateIdentity(
        build_id=str(manifest.get("candidate_build_id") or ""),
        status=str(manifest.get("candidate_status") or ""),
        candidate_manifest_sha256=str(manifest.get("candidate_manifest_sha256") or ""),
        candidate_seal_sha256=str(manifest.get("candidate_seal_sha256") or ""),
        source_manifest_sha256=str(manifest.get("source_manifest_sha256") or ""),
        embedding_model=str(manifest.get("embedding_model") or ""),
        reranker_model=str(manifest.get("reranker_model") or ""),
        document_count=int(manifest.get("document_count") or 0),
        chunk_count=int(manifest.get("chunk_count") or 0),
        vector_count=int(manifest.get("vector_count") or 0),
    )
    candidate_digests = (
        candidate.candidate_manifest_sha256,
        candidate.candidate_seal_sha256,
        candidate.source_manifest_sha256,
    )
    try:
        _validate_memory_policy_binding(
            memory_policy.policy,
            candidate=candidate,
            runtime_binding=verified_runtime_binding,
            require_host_match=True,
        )
    except ValueError as exc:
        raise RuntimeError("authoritative_completion_preflight_memory_policy_invalid") from exc
    policy = memory_policy.policy
    expected_memory_contract = {
        "host_physical_memory_bytes": policy.host_physical_memory_bytes,
        "max_peak_combined_working_set_bytes": policy.max_peak_combined_working_set_bytes,
        "minimum_host_available_memory_bytes": policy.minimum_host_available_memory_bytes,
        "owner_decision_id": policy.owner_decision_id,
        "owner_decision_request_seal_sha256": (policy.owner_decision_request_seal_sha256),
        "owner_decision_resolution_seal_sha256": (policy.owner_decision_resolution_seal_sha256),
        "owner_selected_option_id": policy.owner_selected_option_id,
    }
    if (
        manifest.get("schema") != COMPLETION_PREFLIGHT_SCHEMA
        or manifest.get("run_id") != resolved_run_dir.name
        or candidate.build_id != expected_candidate_build_id
        or candidate.candidate_manifest_sha256 != expected_candidate_manifest_sha256
        or any(not _SHA256.fullmatch(value) for value in candidate_digests)
        or candidate.document_count < 1
        or candidate.chunk_count < 1
        or candidate.vector_count != candidate.chunk_count
        or manifest.get("suite_manifest_seal_sha256") != expected_suite_manifest_seal_sha256
        or manifest.get("suite_id") != bundle.manifest.suite_id
        or manifest.get("suite_registry_canonical_sha256") != bundle.registry.canonical_sha256
        or manifest.get("slo_policy_id") != slo_policy.policy_id
        or manifest.get("slo_policy_source_file_sha256") != slo_policy_source_file_sha256
        or verified_runtime_binding.get("seal_sha256") != expected_runtime_binding_sha256
        or verified_runtime_binding.get("integration_sha") != expected_integration_sha
        or verified_runtime_binding.get("candidate_build_id") != candidate.build_id
        or verified_runtime_binding.get("candidate_manifest_sha256")
        != candidate.candidate_manifest_sha256
        or verified_runtime_binding.get("slo_policy_id") != slo_policy.policy_id
        or verified_runtime_binding.get("slo_policy_sha256") != slo_policy_source_file_sha256
        or model_toolchain.get("trusted_toolchain_identity_sha256")
        != expected_trusted_toolchain_identity_sha256
        or model_toolchain.get("base_python_runtime_manifest_sha256")
        != expected_base_python_runtime_manifest_sha256
        or model_toolchain.get("venv_control_manifest_sha256")
        != expected_venv_control_manifest_sha256
        or manifest.get("memory_policy_sha256") != expected_memory_policy_sha256
        or manifest.get("memory_policy_configured") is not True
        or manifest.get("memory_policy_source_file_sha256") != memory_policy.source_file_sha256
        or manifest.get("memory_policy_contract") != expected_memory_contract
        or manifest.get("policy_sha256") != COMPLETION_PREFLIGHT_POLICY_SHA256
        or authority.get("schema") != COMPLETION_AUTHORITY_SCHEMA
        or authority.get("authoritative") is not True
        or authority.get("synthetic_non_authoritative") is not False
        or manifest.get("local_only") is not True
        or manifest.get("online_research_allowed") is not False
        or manifest.get("requires_active") is not False
        or manifest.get("writes_active") is not False
        or manifest.get("writes_o04") is not False
        or manifest.get("writes_release") is not False
        or manifest.get("public_traffic_allowed") is not False
        or manifest.get("plaintext_prose_allowed") is not False
    ):
        raise RuntimeError("authoritative_completion_preflight_manifest_invalid")

    start_attestation = authority.get("production_launcher_start_attestation")
    if not isinstance(start_attestation, Mapping):
        raise RuntimeError("authoritative_completion_preflight_manifest_invalid")
    verified_start = verify_launcher_attestation(
        start_attestation,
        schema=LAUNCHER_START_SCHEMA,
        run_id=resolved_run_dir.name,
        candidate=candidate,
        runtime_binding_sha256=expected_runtime_binding_sha256,
        integration_sha=expected_integration_sha,
        trusted_model_identity_sha256=str(
            verified_runtime_binding.get("trusted_model_identity_sha256") or ""
        ),
        trusted_toolchain_identity_sha256=expected_trusted_toolchain_identity_sha256,
        installed_environment_manifest_sha256=str(
            model_toolchain.get("installed_environment_manifest_sha256") or ""
        ),
        base_python_runtime_manifest_sha256=expected_base_python_runtime_manifest_sha256,
        venv_control_manifest_sha256=expected_venv_control_manifest_sha256,
        launcher_implementation_sha256=str(
            verified_runtime_binding.get("launcher_implementation_sha256") or ""
        ),
    )

    expected_case_selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo_policy,
        additional_case_ids=None,
    ).safe_dict()
    case_ids, expected_case_contracts = _verify_completion_case_selection(
        manifest,
        bundle=bundle,
        slo_policy=slo_policy,
    )

    expected_members = {"run-manifest.json", "result.json"}
    sample_seals: list[str] = []
    loaded_samples: list[dict[str, Any]] = []
    cold_bindings: dict[str, tuple[str, str]] = {}
    cold_instance_sha256s: set[str] = set()
    cold_launch_proof_sha256s: set[str] = set()
    loaded_attempts: list[dict[str, Any]] = []
    for case_id in case_ids:
        case = bundle.registry.case(case_id)
        band = slo_policy.band_for(
            route=case.expected_research_route,
            word_target=case.word_target,
        )
        for sample_kind, sample_ordinal in _sample_labels():
            sample_name = f"samples/{case_id}/{sample_kind}-{sample_ordinal:02d}.json"
            expected_members.add(sample_name)
            sample = _load_private_completion_artifact(
                resolved_run_dir / sample_name, run_dir=resolved_run_dir
            )
            try:
                observation = CompletionWorkflowObservation.model_validate(
                    {key: value for key, value in sample.items() if key != "seal_sha256"}
                )
            except ValueError as exc:
                raise RuntimeError("authoritative_completion_preflight_sample_invalid") from exc
            if (
                observation.status != "succeeded"
                or observation.case_id != case_id
                or observation.sample_kind != sample_kind
                or observation.sample_ordinal != sample_ordinal
                or observation.question_sha256 != case.question_sha256
                or observation.route != case.expected_research_route
                or observation.word_target != case.word_target
                or observation.slo_band_id != band.id
                or observation.runtime_binding_sha256 != expected_runtime_binding_sha256
                or observation.candidate_build_id != expected_candidate_build_id
                or observation.model_version != verified_runtime_binding.get("model_version")
            ):
                raise RuntimeError("authoritative_completion_preflight_sample_invalid")
            instance_binding = (
                str(observation.runtime_instance_sha256),
                str(observation.cold_launch_proof_sha256),
            )
            if sample_kind == "cold":
                if (
                    instance_binding[0] in cold_instance_sha256s
                    or instance_binding[1] in cold_launch_proof_sha256s
                ):
                    raise RuntimeError("authoritative_completion_preflight_cold_proof_reused")
                cold_bindings[case_id] = instance_binding
                cold_instance_sha256s.add(instance_binding[0])
                cold_launch_proof_sha256s.add(instance_binding[1])
            elif cold_bindings.get(case_id) != instance_binding:
                raise RuntimeError("authoritative_completion_preflight_cold_warm_fork")
            prior_fingerprints: list[str] = []
            for attempt_number in range(1, observation.attempt_number):
                attempt_name = (
                    f"attempts/{case_id}/{sample_kind}-{sample_ordinal:02d}-attempt-"
                    f"{attempt_number:02d}.json"
                )
                expected_members.add(attempt_name)
                attempt = _load_private_completion_artifact(
                    resolved_run_dir / attempt_name, run_dir=resolved_run_dir
                )
                expected_fingerprint = _verify_completion_retry_attempt(
                    attempt,
                    case=case,
                    band=band,
                    candidate=candidate,
                    runtime_binding=verified_runtime_binding,
                    sample_kind=sample_kind,
                    sample_ordinal=sample_ordinal,
                    attempt_number=attempt_number,
                    prior_fingerprints=prior_fingerprints,
                    memory_policy=policy,
                )
                prior_fingerprints.append(expected_fingerprint)
                loaded_attempts.append(attempt)
            sample_seals.append(str(sample["seal_sha256"]))
            loaded_samples.append(sample)

    if actual_members != expected_members:
        raise RuntimeError("authoritative_completion_preflight_artifact_set_invalid")
    expected_sample_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.candidate-completion-sample-set.v1",
            "sample_seal_sha256s": sample_seals,
        }
    )
    expected_slo_band_ids = sorted(
        {
            slo_policy.band_for(
                route=case.expected_research_route,
                word_target=case.word_target,
            ).id
            for case in bundle.registry.cases
        }
    )
    expected_band_summaries = _band_summaries(
        samples=loaded_samples,
        slo_policy=slo_policy,
    )
    if len(cold_instance_sha256s) != len(case_ids) or len(cold_launch_proof_sha256s) != len(
        case_ids
    ):
        raise RuntimeError("authoritative_completion_preflight_cold_proof_invalid")
    observed_maximum_peak, observed_minimum_headroom = _memory_observation_extrema(
        [*loaded_samples, *loaded_attempts]
    )
    _verify_completion_memory_envelope(
        policy,
        observed_maximum_peak=observed_maximum_peak,
        observed_minimum_headroom=observed_minimum_headroom,
    )
    end_attestation = result.get("production_launcher_end_attestation")
    if not isinstance(end_attestation, Mapping):
        raise RuntimeError("authoritative_completion_preflight_result_invalid")
    verified_end = verify_launcher_attestation(
        end_attestation,
        schema=LAUNCHER_END_SCHEMA,
        run_id=resolved_run_dir.name,
        candidate=candidate,
        runtime_binding_sha256=expected_runtime_binding_sha256,
        integration_sha=expected_integration_sha,
        trusted_model_identity_sha256=str(
            verified_runtime_binding.get("trusted_model_identity_sha256") or ""
        ),
        trusted_toolchain_identity_sha256=expected_trusted_toolchain_identity_sha256,
        installed_environment_manifest_sha256=str(
            model_toolchain.get("installed_environment_manifest_sha256") or ""
        ),
        base_python_runtime_manifest_sha256=expected_base_python_runtime_manifest_sha256,
        venv_control_manifest_sha256=expected_venv_control_manifest_sha256,
        verified_start_attestation=verified_start,
    )
    band_summaries = result.get("band_summaries")
    if (
        result.get("schema") != COMPLETION_RESULT_SCHEMA
        or result.get("run_id") != resolved_run_dir.name
        or result.get("run_manifest_sha256") != manifest.get("seal_sha256")
        or result.get("candidate_build_id") != expected_candidate_build_id
        or result.get("candidate_manifest_sha256") != expected_candidate_manifest_sha256
        or result.get("suite_manifest_seal_sha256") != expected_suite_manifest_seal_sha256
        or result.get("suite_registry_canonical_sha256") != bundle.registry.canonical_sha256
        or result.get("slo_policy_id") != slo_policy.policy_id
        or result.get("slo_policy_source_file_sha256") != slo_policy_source_file_sha256
        or result.get("runtime_binding_sha256") != expected_runtime_binding_sha256
        or result.get("policy_sha256") != COMPLETION_PREFLIGHT_POLICY_SHA256
        or result.get("memory_policy_sha256") != expected_memory_policy_sha256
        or result.get("memory_policy_configured") is not True
        or result.get("memory_policy_source_file_sha256") != memory_policy.source_file_sha256
        or result.get("memory_policy_host_physical_memory_bytes")
        != policy.host_physical_memory_bytes
        or result.get("memory_policy_max_peak_combined_working_set_bytes")
        != policy.max_peak_combined_working_set_bytes
        or result.get("memory_policy_minimum_host_available_memory_bytes")
        != policy.minimum_host_available_memory_bytes
        or result.get("authoritative") is not True
        or result.get("synthetic_non_authoritative") is not False
        or result.get("synthetic_checks_passed") is not True
        or result.get("completion_preflight_passed") is not True
        or result.get("memory_safety_passed") is not True
        or result.get("route_word_band_coverage_passed") is not True
        or result.get("status") != "passed"
        or result.get("case_ids") != list(case_ids)
        or result.get("case_count") != len(case_ids)
        or result.get("case_selection") != expected_case_selection
        or result.get("case_contracts") != expected_case_contracts
        or result.get("expected_slo_band_ids") != expected_slo_band_ids
        or result.get("observed_slo_band_ids") != expected_slo_band_ids
        or result.get("sample_count") != len(sample_seals)
        or result.get("expected_sample_count") != len(sample_seals)
        or result.get("cold_sample_count") != len(case_ids)
        or result.get("verified_fresh_model_instance_count") != len(case_ids)
        or result.get("cold_model_proof_passed") is not True
        or result.get("warm_sample_count") != len(case_ids) * WARM_RUNS_PER_CASE
        or result.get("sample_set_sha256") != expected_sample_set_sha256
        or result.get("maximum_peak_combined_working_set_bytes") != observed_maximum_peak
        or result.get("minimum_observed_host_available_memory_bytes") != observed_minimum_headroom
        or result.get("production_launcher_start_attestation_sha256")
        != verified_start.get("seal_sha256")
        or result.get("writes_active") is not False
        or result.get("writes_o04") is not False
        or result.get("writes_release") is not False
        or result.get("public_traffic_used") is not False
        or result.get("plaintext_prose_written") is not False
        or band_summaries != expected_band_summaries
        or any(row.get("completion_p95_passed") is not True for row in expected_band_summaries)
    ):
        raise RuntimeError("authoritative_completion_preflight_result_invalid")

    return sealed_safe_payload(
        {
            "schema": COMPLETION_VERIFIED_RESULT_SCHEMA,
            "run_id": resolved_run_dir.name,
            "candidate_build_id": expected_candidate_build_id,
            "candidate_manifest_sha256": expected_candidate_manifest_sha256,
            "integration_sha": expected_integration_sha,
            "suite_manifest_seal_sha256": expected_suite_manifest_seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "slo_policy_id": slo_policy.policy_id,
            "slo_policy_source_file_sha256": slo_policy_source_file_sha256,
            "runtime_binding_sha256": expected_runtime_binding_sha256,
            "memory_policy_sha256": expected_memory_policy_sha256,
            "memory_policy_source_file_sha256": memory_policy.source_file_sha256,
            "memory_policy_host_physical_memory_bytes": (policy.host_physical_memory_bytes),
            "memory_policy_max_peak_combined_working_set_bytes": (
                policy.max_peak_combined_working_set_bytes
            ),
            "memory_policy_minimum_host_available_memory_bytes": (
                policy.minimum_host_available_memory_bytes
            ),
            "trusted_toolchain_identity_sha256": (expected_trusted_toolchain_identity_sha256),
            "base_python_runtime_manifest_sha256": (expected_base_python_runtime_manifest_sha256),
            "venv_control_manifest_sha256": expected_venv_control_manifest_sha256,
            "run_manifest_sha256": manifest["seal_sha256"],
            "result_sha256": result["seal_sha256"],
            "sample_set_sha256": expected_sample_set_sha256,
            "production_launcher_start_attestation_sha256": verified_start["seal_sha256"],
            "production_launcher_end_attestation_sha256": verified_end["seal_sha256"],
            "case_ids": list(case_ids),
            "case_count": len(case_ids),
            "case_contracts_sha256": sealed_sha256(
                {
                    "schema": "legalbot.completion-preflight-case-contract-set.v1",
                    "case_contracts": expected_case_contracts,
                }
            ),
            "case_specific_authority": False,
            "case_selection_sha256": str(manifest["case_selection"]["selected_set_sha256"]),
            "cold_warm_contract_passed": True,
            "memory_safety_passed": True,
            "authoritative": True,
            "synthetic_non_authoritative": False,
            "completion_preflight_passed": True,
            "writes_active": False,
            "writes_o04": False,
            "writes_release": False,
        }
    )


async def _execute_candidate_completion_preflight(
    *,
    run_id: str,
    output_root: Path,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    runtime: SyntheticCompletionWorkflowRuntime,
    runtime_binding: Mapping[str, Any],
    slo_policy: SLOPolicy,
    as_of_date: date,
    additional_case_ids: Sequence[str] | None = None,
    clock: Clock | None = None,
    memory_policy: CompletionMemoryPolicy | None,
    memory_policy_source_file_sha256: str | None,
    authoritative: bool,
    launcher_start_attestation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Run generic deterministic representatives serially, never releasing prose."""

    if runtime_binding.get("schema") != COMPLETION_BINDING_SCHEMA:
        raise ValueError("completion runtime binding schema mismatch")
    if runtime_binding.get("seal_sha256") != sealed_sha256(runtime_binding):
        raise ValueError("completion runtime binding seal mismatch")
    if runtime_binding.get("candidate_build_id") != candidate.build_id:
        raise ValueError("completion runtime binding candidate mismatch")
    if runtime_binding.get("max_attempts") != MAX_ATTEMPTS:
        raise ValueError("completion runtime binding retry cap mismatch")
    if runtime_binding.get("retry_policy_sha256") != COMPLETION_RETRY_POLICY_SHA256:
        raise ValueError("completion runtime retry identity mismatch")
    if bundle.registry.case_count != 60:
        raise ValueError("completion preflight requires the sealed Live60 registry")
    if authoritative and memory_policy is None:
        raise RuntimeError("completion_memory_policy_missing")
    if authoritative and not _SHA256.fullmatch(memory_policy_source_file_sha256 or ""):
        raise RuntimeError("completion_memory_policy_not_loader_verified")
    if memory_policy is not None:
        _validate_memory_policy_binding(
            memory_policy,
            candidate=candidate,
            runtime_binding=runtime_binding,
            require_host_match=authoritative,
        )
    if authoritative != (launcher_start_attestation is not None):
        raise RuntimeError("completion_authority_contract_invalid")
    authoritative_launcher: Any | None = None
    if authoritative:
        from .candidate_completion_runtime import LoopbackCandidateCompletionLauncher

        if type(runtime) is not LoopbackCandidateCompletionLauncher:
            raise RuntimeError("non_authoritative_completion_runtime_refused")
        authoritative_launcher = runtime

    selection = build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo_policy,
        additional_case_ids=additional_case_ids,
    )
    selected_ids = selection.selected_case_ids
    cases = tuple(bundle.registry.case(case_id) for case_id in selected_ids)
    resolved_clock = clock or SystemClock()
    store = CreateOnlyRunDirectory(root=output_root, run_id=run_id, resume=False)
    manifest = sealed_safe_payload(
        {
            "schema": COMPLETION_PREFLIGHT_SCHEMA,
            "run_id": run_id,
            "suite_id": bundle.manifest.suite_id,
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "slo_policy_id": runtime_binding["slo_policy_id"],
            "slo_policy_source_file_sha256": runtime_binding["slo_policy_sha256"],
            **candidate.safe_dict(),
            "runtime_binding": dict(runtime_binding),
            "authority": {
                "schema": COMPLETION_AUTHORITY_SCHEMA,
                "authoritative": authoritative,
                "synthetic_non_authoritative": not authoritative,
                "production_launcher_start_attestation": (
                    dict(launcher_start_attestation)
                    if launcher_start_attestation is not None
                    else None
                ),
            },
            "memory_policy_sha256": (
                memory_policy.seal_sha256 if memory_policy is not None else None
            ),
            "memory_policy_configured": memory_policy is not None,
            "memory_policy_source_file_sha256": memory_policy_source_file_sha256,
            "memory_policy_contract": (
                {
                    "host_physical_memory_bytes": memory_policy.host_physical_memory_bytes,
                    "max_peak_combined_working_set_bytes": (
                        memory_policy.max_peak_combined_working_set_bytes
                    ),
                    "minimum_host_available_memory_bytes": (
                        memory_policy.minimum_host_available_memory_bytes
                    ),
                    "owner_decision_id": memory_policy.owner_decision_id,
                    "owner_decision_request_seal_sha256": (
                        memory_policy.owner_decision_request_seal_sha256
                    ),
                    "owner_decision_resolution_seal_sha256": (
                        memory_policy.owner_decision_resolution_seal_sha256
                    ),
                    "owner_selected_option_id": memory_policy.owner_selected_option_id,
                }
                if memory_policy is not None
                else None
            ),
            "as_of_date": as_of_date.isoformat(),
            "case_ids": list(selected_ids),
            "case_count": len(cases),
            "case_selection": selection.safe_dict(),
            "case_contracts": [_completion_case_contract(case, slo_policy) for case in cases],
            "sample_plan": [
                {"sample_kind": kind, "sample_ordinal": ordinal}
                for kind, ordinal in _sample_labels()
            ],
            "warm_runs_per_case": WARM_RUNS_PER_CASE,
            "policy_sha256": COMPLETION_PREFLIGHT_POLICY_SHA256,
            "created_at": resolved_clock.now().isoformat(),
            "purpose": "candidate_full_completion_memory_preflight_only",
            "local_only": True,
            "online_research_allowed": False,
            "requires_active": False,
            "writes_active": False,
            "writes_o04": False,
            "writes_release": False,
            "public_traffic_allowed": False,
            "plaintext_prose_allowed": False,
            "eligible_for_training": False,
            "training_export_allowed": False,
        }
    )
    store.write_json("run-manifest.json", manifest)

    samples: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    cold_instance_bindings: dict[str, tuple[str, str]] = {}
    for case in cases:
        band = slo_policy.band_for(route=case.expected_research_route, word_target=case.word_target)
        for sample_kind, sample_ordinal in _sample_labels():
            prior_fingerprints: list[str] = []
            for attempt_number in range(1, MAX_ATTEMPTS + 1):
                try:
                    if authoritative_launcher is not None:
                        observation = await LoopbackCandidateCompletionLauncher.run_workflow(
                            authoritative_launcher,
                            case=case,
                            band=band,
                            as_of_date=as_of_date,
                            sample_kind=sample_kind,
                            sample_ordinal=sample_ordinal,
                            attempt_number=attempt_number,
                            runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
                        )
                    else:
                        observation = await runtime.run_workflow(
                            case=case,
                            band=band,
                            as_of_date=as_of_date,
                            sample_kind=sample_kind,
                            sample_ordinal=sample_ordinal,
                            attempt_number=attempt_number,
                            runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
                        )
                    _validate_observation_binding(
                        observation,
                        case=case,
                        band=band,
                        candidate=candidate,
                        runtime_binding=runtime_binding,
                        sample_kind=sample_kind,
                        sample_ordinal=sample_ordinal,
                        attempt_number=attempt_number,
                    )
                except Exception as exc:
                    reason_code = _safe_reason_code(exc)
                    observation = _failed_observation(
                        case=case,
                        band=band,
                        sample_kind=sample_kind,
                        sample_ordinal=sample_ordinal,
                        attempt_number=attempt_number,
                        runtime_binding=runtime_binding,
                        candidate=candidate,
                        reason_code=reason_code,
                    )
                observation = _memory_policy_failure(observation, memory_policy)
                if observation.status == "succeeded":
                    instance_binding = (
                        str(observation.runtime_instance_sha256),
                        str(observation.cold_launch_proof_sha256),
                    )
                    if sample_kind == "cold":
                        cold_instance_bindings[case.case_id] = instance_binding
                    elif cold_instance_bindings.get(case.case_id) != instance_binding:
                        observation = _failed_observation(
                            case=case,
                            band=band,
                            sample_kind=sample_kind,
                            sample_ordinal=sample_ordinal,
                            attempt_number=attempt_number,
                            runtime_binding=runtime_binding,
                            candidate=candidate,
                            reason_code="runtime_binding_mismatch",
                        )
                    if observation.status != "succeeded":
                        # Continue through the ordinary deterministic failure path.
                        pass
                    else:
                        payload = sealed_safe_payload(
                            observation.model_dump(mode="json", by_alias=True)
                        )
                        store.write_json(
                            f"samples/{case.case_id}/{sample_kind}-{sample_ordinal:02d}.json",
                            payload,
                        )
                        samples.append(payload)
                        break

                reason_code = normalise_failure_reason_code(
                    str(observation.failure_reason_code or "runtime_error")
                )
                fingerprint = failure_fingerprint(
                    stage="completion_preflight",
                    reason_code=reason_code,
                    scope_id=case.case_id,
                    identity_digests=(
                        case.question_sha256,
                        candidate.candidate_manifest_sha256,
                        str(runtime_binding["seal_sha256"]),
                    ),
                    safe_context={
                        "sample_kind": sample_kind,
                        "sample_ordinal": sample_ordinal,
                    },
                )
                deterministic = (
                    reason_code in _DETERMINISTIC_PREFLIGHT_FAILURES
                    or is_deterministic_safety_failure(reason_code)
                )
                decision = decide_retry(
                    attempt_number=attempt_number,
                    failure_reason_code=reason_code,
                    failure_fingerprint_sha256=fingerprint,
                    prior_failure_fingerprints=prior_fingerprints,
                    deterministic_safety=deterministic,
                    retryable=not deterministic,
                    input_or_condition_changed=not deterministic,
                )
                failure_payload = sealed_safe_payload(
                    {
                        **observation.model_dump(mode="json", by_alias=True),
                        "failure_fingerprint_sha256": fingerprint,
                        "decision_action": decision.action,
                        "decision_reason": decision.reason,
                        "retries_remaining": decision.retries_remaining,
                    }
                )
                store.write_json(
                    f"attempts/{case.case_id}/{sample_kind}-{sample_ordinal:02d}-attempt-"
                    f"{attempt_number:02d}.json",
                    failure_payload,
                )
                attempts.append(failure_payload)
                prior_fingerprints.append(fingerprint)
                if decision.should_retry:
                    continue
                stopped = sealed_safe_payload(
                    {
                        "schema": COMPLETION_STOP_SCHEMA,
                        "run_id": run_id,
                        "candidate_build_id": candidate.build_id,
                        "runtime_binding_sha256": runtime_binding["seal_sha256"],
                        "case_id": case.case_id,
                        "sample_kind": sample_kind,
                        "sample_ordinal": sample_ordinal,
                        "attempt_number": attempt_number,
                        "failure_reason_code": reason_code,
                        "failure_fingerprint_sha256": fingerprint,
                        "stop_reason": decision.reason,
                        "completed_sample_count": len(samples),
                        "authoritative": authoritative,
                        "synthetic_non_authoritative": not authoritative,
                        "completion_preflight_passed": False,
                        "memory_policy_sha256": (
                            memory_policy.seal_sha256 if memory_policy is not None else None
                        ),
                        "memory_policy_source_file_sha256": memory_policy_source_file_sha256,
                        "writes_active": False,
                        "writes_o04": False,
                        "writes_release": False,
                        "plaintext_prose_written": False,
                        "status": "stopped",
                    }
                )
                if authoritative:
                    assert authoritative_launcher is not None
                    end_attestation = (
                        await LoopbackCandidateCompletionLauncher.production_end_attestation(
                            authoritative_launcher
                        )
                    )
                    verified_end = verify_launcher_attestation(
                        end_attestation,
                        schema=LAUNCHER_END_SCHEMA,
                        run_id=run_id,
                        candidate=candidate,
                        runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
                        integration_sha=str(runtime_binding["integration_sha"]),
                        trusted_model_identity_sha256=str(
                            runtime_binding["trusted_model_identity_sha256"]
                        ),
                        trusted_toolchain_identity_sha256=str(
                            runtime_binding["model_toolchain"]["trusted_toolchain_identity_sha256"]
                        ),
                        installed_environment_manifest_sha256=str(
                            runtime_binding["model_toolchain"][
                                "installed_environment_manifest_sha256"
                            ]
                        ),
                        base_python_runtime_manifest_sha256=str(
                            runtime_binding["model_toolchain"][
                                "base_python_runtime_manifest_sha256"
                            ]
                        ),
                        venv_control_manifest_sha256=str(
                            runtime_binding["model_toolchain"]["venv_control_manifest_sha256"]
                        ),
                        verified_start_attestation=launcher_start_attestation,
                    )
                    stopped = sealed_safe_payload(
                        {
                            **stopped,
                            "production_launcher_end_attestation": verified_end,
                        }
                    )
                store.write_json("STOPPED.json", stopped)
                return stopped

    band_summaries = _band_summaries(samples=samples, slo_policy=slo_policy)
    expected_band_ids = {
        slo_policy.band_for(route=case.expected_research_route, word_target=case.word_target).id
        for case in bundle.registry.cases
    }
    observed_band_ids = {str(row["slo_band_id"]) for row in band_summaries}
    expected_samples = len(cases) * (1 + WARM_RUNS_PER_CASE)
    synthetic_checks_passed = (
        len(samples) == expected_samples
        and bool(band_summaries)
        and observed_band_ids == expected_band_ids
        and all(
            row["warm_sample_count"] >= WARM_RUNS_PER_CASE and row["completion_p95_passed"] is True
            for row in band_summaries
        )
        and all(
            sample["hard_quality_gates_passed"] is True
            and sample["public_release_written"] is False
            and sample["answer_release_state_present"] is False
            and sample["plaintext_prose_written"] is False
            for sample in samples
        )
        and len(cold_instance_bindings) == len(cases)
        and (
            memory_policy is None
            or all(
                sample["peak_combined_working_set_bytes"]
                <= memory_policy.max_peak_combined_working_set_bytes
                and sample["startup_peak_combined_working_set_bytes"]
                <= memory_policy.max_peak_combined_working_set_bytes
                and sample["minimum_host_available_memory_bytes"]
                >= memory_policy.minimum_host_available_memory_bytes
                and sample["startup_minimum_host_available_memory_bytes"]
                >= memory_policy.minimum_host_available_memory_bytes
                for sample in samples
            )
        )
    )
    launcher_end_attestation: dict[str, Any] | None = None
    if authoritative:
        assert authoritative_launcher is not None
        raw_end = await LoopbackCandidateCompletionLauncher.production_end_attestation(
            authoritative_launcher
        )
        launcher_end_attestation = verify_launcher_attestation(
            raw_end,
            schema=LAUNCHER_END_SCHEMA,
            run_id=run_id,
            candidate=candidate,
            runtime_binding_sha256=str(runtime_binding["seal_sha256"]),
            integration_sha=str(runtime_binding["integration_sha"]),
            trusted_model_identity_sha256=str(runtime_binding["trusted_model_identity_sha256"]),
            trusted_toolchain_identity_sha256=str(
                runtime_binding["model_toolchain"]["trusted_toolchain_identity_sha256"]
            ),
            installed_environment_manifest_sha256=str(
                runtime_binding["model_toolchain"]["installed_environment_manifest_sha256"]
            ),
            base_python_runtime_manifest_sha256=str(
                runtime_binding["model_toolchain"]["base_python_runtime_manifest_sha256"]
            ),
            venv_control_manifest_sha256=str(
                runtime_binding["model_toolchain"]["venv_control_manifest_sha256"]
            ),
            verified_start_attestation=launcher_start_attestation,
        )
    passed = authoritative and synthetic_checks_passed and launcher_end_attestation is not None
    maximum_peak, observed_minimum_headroom = _memory_observation_extrema([*samples, *attempts])
    minimum_headroom = observed_minimum_headroom or 0
    result = sealed_safe_payload(
        {
            "schema": COMPLETION_RESULT_SCHEMA,
            "run_id": run_id,
            "run_manifest_sha256": manifest["seal_sha256"],
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "slo_policy_id": runtime_binding["slo_policy_id"],
            "slo_policy_source_file_sha256": runtime_binding["slo_policy_sha256"],
            "runtime_binding_sha256": runtime_binding["seal_sha256"],
            "policy_sha256": COMPLETION_PREFLIGHT_POLICY_SHA256,
            "case_ids": list(selected_ids),
            "case_count": len(cases),
            "case_selection": selection.safe_dict(),
            "case_contracts": [_completion_case_contract(case, slo_policy) for case in cases],
            "expected_slo_band_ids": sorted(expected_band_ids),
            "observed_slo_band_ids": sorted(observed_band_ids),
            "route_word_band_coverage_passed": observed_band_ids == expected_band_ids,
            "sample_count": len(samples),
            "expected_sample_count": expected_samples,
            "cold_sample_count": sum(row["sample_kind"] == "cold" for row in samples),
            "verified_fresh_model_instance_count": len(cold_instance_bindings),
            "cold_model_proof_passed": len(cold_instance_bindings) == len(cases),
            "warm_sample_count": sum(row["sample_kind"] == "warm" for row in samples),
            "band_summaries": band_summaries,
            "sample_set_sha256": sealed_sha256(
                {
                    "schema": "legalbot.candidate-completion-sample-set.v1",
                    "sample_seal_sha256s": [row["seal_sha256"] for row in samples],
                }
            ),
            "authoritative": authoritative,
            "synthetic_non_authoritative": not authoritative,
            "synthetic_checks_passed": synthetic_checks_passed,
            "production_launcher_start_attestation_sha256": (
                launcher_start_attestation.get("seal_sha256")
                if launcher_start_attestation is not None
                else None
            ),
            "production_launcher_end_attestation": launcher_end_attestation,
            "memory_policy_sha256": (
                memory_policy.seal_sha256 if memory_policy is not None else None
            ),
            "memory_policy_configured": memory_policy is not None,
            "memory_policy_source_file_sha256": memory_policy_source_file_sha256,
            "memory_policy_host_physical_memory_bytes": (
                memory_policy.host_physical_memory_bytes if memory_policy is not None else None
            ),
            "memory_policy_max_peak_combined_working_set_bytes": (
                memory_policy.max_peak_combined_working_set_bytes
                if memory_policy is not None
                else None
            ),
            "memory_policy_minimum_host_available_memory_bytes": (
                memory_policy.minimum_host_available_memory_bytes
                if memory_policy is not None
                else None
            ),
            "maximum_peak_combined_working_set_bytes": maximum_peak,
            "minimum_observed_host_available_memory_bytes": minimum_headroom,
            "memory_safety_passed": (
                memory_policy is not None
                and maximum_peak <= memory_policy.max_peak_combined_working_set_bytes
                and minimum_headroom >= memory_policy.minimum_host_available_memory_bytes
            ),
            "completion_preflight_passed": passed,
            "writes_active": False,
            "writes_o04": False,
            "writes_release": False,
            "public_traffic_used": False,
            "plaintext_prose_written": False,
            "status": (
                "passed"
                if passed
                else (
                    "synthetic_passed_non_authoritative"
                    if synthetic_checks_passed and not authoritative
                    else "failed"
                )
            ),
        }
    )
    store.write_json("result.json", result)
    return result


async def run_synthetic_candidate_completion_preflight(
    *,
    run_id: str,
    output_root: Path,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    runtime: SyntheticCompletionWorkflowRuntime,
    runtime_binding: Mapping[str, Any],
    slo_policy: SLOPolicy,
    as_of_date: date,
    additional_case_ids: Sequence[str] | None = None,
    clock: Clock | None = None,
    memory_policy: CompletionMemoryPolicy | None = None,
) -> dict[str, Any]:
    """Exercise the deterministic contract with fakes, always non-authoritatively."""

    return await _execute_candidate_completion_preflight(
        run_id=run_id,
        output_root=output_root,
        bundle=bundle,
        candidate=candidate,
        runtime=runtime,
        runtime_binding=runtime_binding,
        slo_policy=slo_policy,
        as_of_date=as_of_date,
        additional_case_ids=additional_case_ids,
        clock=clock,
        memory_policy=memory_policy,
        memory_policy_source_file_sha256=None,
        authoritative=False,
        launcher_start_attestation=None,
    )


async def run_candidate_completion_preflight(
    *,
    run_id: str,
    output_root: Path,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    runtime: object,
    runtime_binding: Mapping[str, Any],
    slo_policy: SLOPolicy,
    as_of_date: date,
    memory_policy: LoadedCompletionMemoryPolicy,
    additional_case_ids: Sequence[str] | None = None,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Run the authoritative preflight only through the concrete owned launcher."""

    # Local import avoids a module cycle while making protocol/fake injection
    # impossible at the production entry point.  Subclasses are also refused.
    from .candidate_completion_runtime import LoopbackCandidateCompletionLauncher

    if type(runtime) is not LoopbackCandidateCompletionLauncher:
        raise RuntimeError("non_authoritative_completion_runtime_refused")
    if type(memory_policy) is not LoadedCompletionMemoryPolicy:
        raise RuntimeError("completion_memory_policy_not_loader_verified")
    # OwnerDecisionResolution is currently only self-sealed. Even a caller
    # that reaches into Python internals to forge the loader wrapper cannot
    # cross this production boundary until a trusted owner verifier exists.
    raise OwnerDecisionRequired("trusted_owner_memory_signature_verifier_missing")
    launcher = runtime
    allowed_output_root = (launcher.base_settings.evaluation_dir / "completion-preflight").resolve(
        strict=False
    )
    resolved_output_root = output_root.resolve(strict=False)
    try:
        output_relative = resolved_output_root.relative_to(allowed_output_root)
    except ValueError as exc:
        raise RuntimeError("completion_output_root_invalid") from exc
    if (
        len(output_relative.parts) != 1
        or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", output_relative.parts[0]) is None
    ):
        raise RuntimeError("completion_output_root_invalid")
    model_toolchain = runtime_binding.get("model_toolchain")
    trusted_toolchain_identity_sha256 = (
        str(model_toolchain.get("trusted_toolchain_identity_sha256") or "")
        if isinstance(model_toolchain, Mapping)
        else ""
    )
    start = LoopbackCandidateCompletionLauncher.production_start_attestation(launcher)
    verified_start = verify_launcher_attestation(
        start,
        schema=LAUNCHER_START_SCHEMA,
        run_id=run_id,
        candidate=candidate,
        runtime_binding_sha256=str(runtime_binding.get("seal_sha256") or ""),
        integration_sha=str(runtime_binding.get("integration_sha") or ""),
        trusted_model_identity_sha256=str(
            runtime_binding.get("trusted_model_identity_sha256") or ""
        ),
        trusted_toolchain_identity_sha256=trusted_toolchain_identity_sha256,
        installed_environment_manifest_sha256=(
            str(model_toolchain.get("installed_environment_manifest_sha256") or "")
            if isinstance(model_toolchain, Mapping)
            else ""
        ),
        base_python_runtime_manifest_sha256=(
            str(model_toolchain.get("base_python_runtime_manifest_sha256") or "")
            if isinstance(model_toolchain, Mapping)
            else ""
        ),
        venv_control_manifest_sha256=(
            str(model_toolchain.get("venv_control_manifest_sha256") or "")
            if isinstance(model_toolchain, Mapping)
            else ""
        ),
        launcher_implementation_sha256=str(
            runtime_binding.get("launcher_implementation_sha256") or ""
        ),
    )
    return await _execute_candidate_completion_preflight(
        run_id=run_id,
        output_root=output_root,
        bundle=bundle,
        candidate=candidate,
        runtime=launcher,
        runtime_binding=runtime_binding,
        slo_policy=slo_policy,
        as_of_date=as_of_date,
        additional_case_ids=additional_case_ids,
        clock=clock,
        memory_policy=memory_policy.policy,
        memory_policy_source_file_sha256=memory_policy.source_file_sha256,
        authoritative=True,
        launcher_start_attestation=verified_start,
    )
