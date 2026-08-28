"""Serial fail-closed circuit for one authorized owner-quality canary lane.

The controller invokes a supplied case callback one case at a time.  It never
submits the next case until the current result has passed release, word-band,
AI-evidence, standards-avoidance and deterministic gates.  A retry is possible
only for the same case, only with a new input identity, and never beyond the
tracked initial-plus-two policy.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..assessment.guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    applicable_guidance_rules,
)
from ..assessment.standards_scoring import AssessmentStandardsReport
from ..crypto import LocalCipher
from ..orchestration.retry_policy import (
    MAX_ATTEMPTS,
    decide_retry,
    failure_fingerprint,
)
from ..quality.ai_evidence_reviewer import (
    AIEvidenceAdjudication,
    AIEvidenceReviewResult,
    frozen_claim_bundle_sha256,
)
from .canary_review_workspace import CanaryReviewWorkspace
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .owner_quality_canary import OwnerQualityCanaryManifest
from .owner_quality_canary_artifacts import (
    OwnerCanaryCaseProjectionReceipt,
    OwnerCanaryDeterministicGateReport,
    OwnerCanaryEvidenceBundle,
    OwnerCanaryReleaseAttestation,
    verify_case_projection_receipt,
    verify_positive_release_artifacts,
)
from .owner_quality_canary_authorization import (
    OwnerCanaryAuthorization,
    verify_authorization_manifest,
)

ATTEMPT_REQUEST_SCHEMA = "legalbot.owner-canary-attempt-request.v1"
ATTEMPT_RESULT_SCHEMA = "legalbot.owner-canary-attempt-result.v2"
CIRCUIT_RESULT_SCHEMA = "legalbot.owner-canary-circuit-result.v2"
CIRCUIT_DEBUG_SCHEMA = "legalbot.owner-canary-debug-bundle.v1"
CIRCUIT_START_SCHEMA = "legalbot.owner-canary-circuit-start.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")

_NON_RETRYABLE_CONTROLLER_CODES = frozenset(
    {
        "ai_adjudication_missing",
        "ai_deterministic_gate_failure",
        "ai_review_identity_mismatch",
        "ai_review_missing",
        "deterministic_hard_gate",
        "case_projection_binding_failure",
        "case_projection_failure",
        "standards_identity_mismatch",
        "standards_review_missing",
        "worker_hard_failure",
        "worker_result_binding_failure",
        "worker_result_invalid",
    }
)


class OwnerCanaryAttemptRequest(BaseModel):
    """Prose-free, locally sealed input identity passed to the callback."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-attempt-request.v1"] = Field(
        default="legalbot.owner-canary-attempt-request.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lane: Literal["development", "blind_holdout"]
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    sequence_number: int = Field(ge=1, le=30)
    attempt_number: int = Field(ge=1, le=3)
    requested_word_target: int = Field(ge=1_000, le=10_000)
    input_revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def request_is_sealed(self) -> Self:
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary attempt request seal does not match")
        return self


class OwnerCanaryCaseAttemptResult(BaseModel):
    """Sealed callback result; answer/question prose is never part of the contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-attempt-result.v2"] = Field(
        default="legalbot.owner-canary-attempt-result.v2", alias="schema"
    )
    result_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    attempt_number: int = Field(ge=1, le=3)
    input_revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_version_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$"
    )
    answer_artifact_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$"
    )
    released: bool
    answer_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    word_count: int | None = Field(default=None, ge=0)
    deterministic_hard_failure_codes: tuple[str, ...] = ()
    worker_hard_failure: bool = False
    worker_hard_failure_code: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$"
    )
    ai_review: AIEvidenceReviewResult | None = None
    ai_adjudication: AIEvidenceAdjudication | None = None
    standards_report: AssessmentStandardsReport | None = None
    evidence_bundle: OwnerCanaryEvidenceBundle | None = None
    deterministic_gate_report: OwnerCanaryDeterministicGateReport | None = None
    release_attestation: OwnerCanaryReleaseAttestation | None = None
    next_input_revision_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    failure_reason_codes: tuple[str, ...] = ()
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("deterministic_hard_failure_codes", "failure_reason_codes")
    @classmethod
    def reason_codes_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_CODE.fullmatch(value) for value in values):
            raise ValueError("owner-canary result contains an unsafe reason code")
        if len(values) != len(set(values)):
            raise ValueError("owner-canary result contains duplicate reason codes")
        return values

    @model_validator(mode="after")
    def result_is_consistent_and_sealed(self) -> Self:
        if self.worker_hard_failure != (self.worker_hard_failure_code is not None):
            raise ValueError("worker hard-failure identity is inconsistent")
        positive = (
            self.job_id,
            self.answer_version_id,
            self.answer_artifact_id,
            self.answer_sha256,
            self.word_count,
            self.ai_review,
            self.ai_adjudication,
            self.standards_report,
            self.evidence_bundle,
            self.deterministic_gate_report,
            self.release_attestation,
        )
        if self.released:
            if any(value is None for value in positive):
                raise ValueError("released owner-canary result lacks positive runtime artifacts")
            if self.worker_hard_failure or self.deterministic_hard_failure_codes:
                raise ValueError("released owner-canary result contains a hard failure")
            verify_positive_release_artifacts(
                run_id=self.run_id,
                authorization_seal_sha256=self.authorization_seal_sha256,
                canary_manifest_seal_sha256=self.canary_manifest_seal_sha256,
                case_id=self.case_id,
                candidate_build_id=self.candidate_build_id,
                candidate_manifest_sha256=self.candidate_manifest_sha256,
                job_id=cast(str, self.job_id),
                answer_version_id=cast(str, self.answer_version_id),
                answer_sha256=cast(str, self.answer_sha256),
                word_count=cast(int, self.word_count),
                ai_review=cast(AIEvidenceReviewResult, self.ai_review),
                evidence_bundle=cast(OwnerCanaryEvidenceBundle, self.evidence_bundle),
                deterministic_gate_report=cast(
                    OwnerCanaryDeterministicGateReport, self.deterministic_gate_report
                ),
                release_attestation=cast(OwnerCanaryReleaseAttestation, self.release_attestation),
            )
        elif any(
            value is not None
            for value in (
                self.answer_artifact_id,
                self.answer_sha256,
                self.word_count,
                self.evidence_bundle,
                self.deterministic_gate_report,
                self.release_attestation,
            )
        ):
            raise ValueError("non-release owner-canary result exposes positive artifacts")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary attempt result seal does not match")
        return self


def seal_owner_canary_case_result(
    *,
    result_id: str,
    run_id: str,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    case_id: str,
    attempt_number: int,
    input_revision_sha256: str,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    job_id: str | None = None,
    answer_version_id: str | None = None,
    answer_artifact_id: str | None = None,
    released: bool,
    answer_sha256: str | None = None,
    word_count: int | None = None,
    deterministic_hard_failure_codes: Sequence[str] = (),
    worker_hard_failure_code: str | None = None,
    ai_review: AIEvidenceReviewResult | None = None,
    ai_adjudication: AIEvidenceAdjudication | None = None,
    standards_report: AssessmentStandardsReport | None = None,
    evidence_bundle: OwnerCanaryEvidenceBundle | None = None,
    deterministic_gate_report: OwnerCanaryDeterministicGateReport | None = None,
    release_attestation: OwnerCanaryReleaseAttestation | None = None,
    next_input_revision_sha256: str | None = None,
    failure_reason_codes: Sequence[str] = (),
) -> OwnerCanaryCaseAttemptResult:
    material: dict[str, Any] = {
        "schema": ATTEMPT_RESULT_SCHEMA,
        "result_id": result_id,
        "run_id": run_id,
        "authorization_seal_sha256": authorization_seal_sha256,
        "canary_manifest_seal_sha256": canary_manifest_seal_sha256,
        "case_id": case_id,
        "attempt_number": attempt_number,
        "input_revision_sha256": input_revision_sha256,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "job_id": job_id,
        "answer_version_id": answer_version_id,
        "answer_artifact_id": answer_artifact_id,
        "released": released,
        "answer_sha256": answer_sha256,
        "word_count": word_count,
        "deterministic_hard_failure_codes": list(deterministic_hard_failure_codes),
        "worker_hard_failure": worker_hard_failure_code is not None,
        "worker_hard_failure_code": worker_hard_failure_code,
        "ai_review": (
            None if ai_review is None else ai_review.model_dump(mode="json", by_alias=True)
        ),
        "ai_adjudication": (
            None
            if ai_adjudication is None
            else ai_adjudication.model_dump(mode="json", by_alias=True)
        ),
        "standards_report": (
            None
            if standards_report is None
            else standards_report.model_dump(mode="json", by_alias=True)
        ),
        "evidence_bundle": (
            None
            if evidence_bundle is None
            else evidence_bundle.model_dump(mode="json", by_alias=True)
        ),
        "deterministic_gate_report": (
            None
            if deterministic_gate_report is None
            else deterministic_gate_report.model_dump(mode="json", by_alias=True)
        ),
        "release_attestation": (
            None
            if release_attestation is None
            else release_attestation.model_dump(mode="json", by_alias=True)
        ),
        "next_input_revision_sha256": next_input_revision_sha256,
        "failure_reason_codes": list(failure_reason_codes),
    }
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerCanaryCaseAttemptResult.model_validate(material)


class OwnerCanaryAttemptTrace(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    attempt_number: int = Field(ge=1, le=3)
    input_revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    blocking_reason_codes: tuple[str, ...]
    failure_fingerprint_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    projection_receipt_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    action: Literal["case_passed", "retry", "stop"]
    decision_reason: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")

    @field_validator("blocking_reason_codes")
    @classmethod
    def blockers_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_CODE.fullmatch(value) for value in values):
            raise ValueError("owner-canary trace contains an unsafe blocker")
        if len(values) != len(set(values)):
            raise ValueError("owner-canary trace contains duplicate blockers")
        return values

    @model_validator(mode="after")
    def projection_receipt_only_marks_a_pass(self) -> Self:
        if (self.action == "case_passed") != (self.projection_receipt_seal_sha256 is not None):
            raise ValueError("owner-canary pass trace lacks an exact projection receipt")
        return self


class OwnerCanaryCircuitResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-circuit-result.v2"] = Field(
        default="legalbot.owner-canary-circuit-result.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lane: Literal["development", "blind_holdout"]
    status: Literal["passed", "stopped"]
    expected_case_count: Literal[30]
    completed_case_ids: tuple[str, ...]
    projection_receipt_seal_sha256s: tuple[str, ...]
    callback_invocation_count: int = Field(ge=0)
    stopped_case_id: str | None = Field(default=None, pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    stop_reason_codes: tuple[str, ...]
    attempt_trace: tuple[OwnerCanaryAttemptTrace, ...]
    debug_artifact_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    debug_ciphertext_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    debug_projection_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    no_next_case_submitted_after_stop: Literal[True]
    restart_allowed: Literal[False]
    frozen: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("completed_case_ids")
    @classmethod
    def completed_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _CASE_ID.fullmatch(value) for value in values):
            raise ValueError("owner-canary circuit contains an invalid completed case")
        if len(values) != len(set(values)):
            raise ValueError("owner-canary circuit contains duplicate completed cases")
        return values

    @field_validator("projection_receipt_seal_sha256s")
    @classmethod
    def receipt_seals_are_valid_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SHA256.fullmatch(value) for value in values):
            raise ValueError("owner-canary circuit contains an invalid projection receipt")
        if len(values) != len(set(values)):
            raise ValueError("owner-canary circuit contains duplicate projection receipts")
        return values

    @field_validator("stop_reason_codes")
    @classmethod
    def stop_codes_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_CODE.fullmatch(value) for value in values):
            raise ValueError("owner-canary circuit contains an unsafe stop code")
        if len(values) != len(set(values)):
            raise ValueError("owner-canary circuit contains duplicate stop codes")
        return values

    @model_validator(mode="after")
    def terminal_state_is_consistent_and_sealed(self) -> Self:
        debug_values = (
            self.debug_artifact_id,
            self.debug_ciphertext_sha256,
            self.debug_projection_seal_sha256,
        )
        if len(self.projection_receipt_seal_sha256s) != len(self.completed_case_ids):
            raise ValueError("owner-canary completed cases lack exact projection receipts")
        passed_trace_receipts = tuple(
            item.projection_receipt_seal_sha256
            for item in self.attempt_trace
            if item.action == "case_passed"
        )
        if passed_trace_receipts != self.projection_receipt_seal_sha256s:
            raise ValueError("owner-canary projection receipts differ from the attempt trace")
        if self.status == "passed":
            if (
                len(self.completed_case_ids) != 30
                or self.stopped_case_id is not None
                or self.stop_reason_codes
                or any(value is not None for value in debug_values)
            ):
                raise ValueError("passed owner-canary circuit is incomplete")
        elif (
            self.stopped_case_id is None
            or not self.stop_reason_codes
            or any(value is None for value in debug_values)
        ):
            raise ValueError("stopped owner-canary circuit lacks frozen debug evidence")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary circuit result seal does not match")
        return self


class OwnerCanaryCaseCallback(Protocol):
    def __call__(
        self, request: OwnerCanaryAttemptRequest
    ) -> OwnerCanaryCaseAttemptResult | Mapping[str, Any]: ...


type CaseCallback = Callable[
    [OwnerCanaryAttemptRequest],
    OwnerCanaryCaseAttemptResult | Mapping[str, Any],
]


class OwnerCanaryCaseProjector(Protocol):
    def __call__(
        self, result: OwnerCanaryCaseAttemptResult
    ) -> OwnerCanaryCaseProjectionReceipt | Mapping[str, Any]: ...


type CaseProjector = Callable[
    [OwnerCanaryCaseAttemptResult],
    OwnerCanaryCaseProjectionReceipt | Mapping[str, Any],
]


def _request(
    *,
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
    case_id: str,
    sequence_number: int,
    attempt_number: int,
    word_target: int,
    input_revision_sha256: str,
) -> OwnerCanaryAttemptRequest:
    material: dict[str, Any] = {
        "schema": ATTEMPT_REQUEST_SCHEMA,
        "run_id": authorization.run_id,
        "authorization_seal_sha256": authorization.seal_sha256,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "lane": authorization.lane,
        "case_id": case_id,
        "sequence_number": sequence_number,
        "attempt_number": attempt_number,
        "requested_word_target": word_target,
        "input_revision_sha256": input_revision_sha256,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerCanaryAttemptRequest.model_validate(material)


def _blocking_codes(
    *,
    result: OwnerCanaryCaseAttemptResult,
    authorization: OwnerCanaryAuthorization,
    word_target: int,
    question_sha256: str,
    task_type: str,
    subject: str,
) -> tuple[str, ...]:
    codes: list[str] = []
    if result.worker_hard_failure:
        codes.append("worker_hard_failure")
        if result.worker_hard_failure_code:
            codes.append(result.worker_hard_failure_code)
    if result.deterministic_hard_failure_codes:
        codes.append("deterministic_hard_gate")
        codes.extend(result.deterministic_hard_failure_codes)
    if not result.released:
        codes.append("non_release")
    elif result.word_count is None:
        codes.append("word_count_missing")
    else:
        minimum = math.ceil(word_target * 0.95)
        maximum = math.floor(word_target * 1.05)
        if not minimum <= result.word_count <= maximum:
            codes.append("word_outside_tolerance")

    review = result.ai_review
    adjudication = result.ai_adjudication
    if review is None:
        codes.append("ai_review_missing")
    elif (
        review.policy_sha256 != authorization.policy_bindings.ai_reviewer_policy_sha256
        or review.prompt_sha256 != authorization.policy_bindings.ai_reviewer_prompt_sha256
        or review.toolchain_sha256 != authorization.policy_bindings.ai_reviewer_toolchain_sha256
        or review.material_claim_count < 1
        or review.frozen_claim_bundle_sha256 != frozen_claim_bundle_sha256(review.claims)
    ):
        codes.append("ai_review_identity_mismatch")
    elif not review.passed:
        codes.append("ai_review_failed")
    if adjudication is None:
        codes.append("ai_adjudication_missing")
    elif review is not None and (
        adjudication.review_id != review.review_id
        or adjudication.review_seal_sha256 != review.seal_sha256
        or tuple((item.claim_id, item.verdict) for item in adjudication.claims)
        != tuple((item.claim_id, item.verdict) for item in review.claims)
    ):
        codes.append("ai_review_identity_mismatch")
    elif not adjudication.passed:
        codes.append("ai_adjudication_failed")
        if adjudication.deterministic_blocking_reason_codes:
            codes.append("ai_deterministic_gate_failure")

    if (
        result.evidence_bundle is not None
        and result.evidence_bundle.relevance_threshold_policy_sha256
        != authorization.policy_bindings.relevance_threshold_policy_sha256
    ):
        codes.append("relevance_threshold_policy_identity_mismatch")

    standards = result.standards_report
    expected_rule_ids = tuple(
        rule.rule_id
        for rule in applicable_guidance_rules(
            OWNER_ASSESSMENT_BUNDLE,
            task_type=task_type,
            subject=subject,
        )
    )
    if standards is None:
        codes.append("standards_review_missing")
    elif (
        standards.bundle_sha256 != authorization.policy_bindings.standards_bundle_sha256
        or standards.bundle_version != authorization.policy_bindings.standards_bundle_version
        or standards.question_sha256 != question_sha256
        or standards.task_type != task_type
        or (review is not None and standards.source_draft_sha256 != review.source_draft_sha256)
        or tuple(item.rule_id for item in standards.scores) != expected_rule_ids
    ):
        codes.append("standards_identity_mismatch")
    elif not standards.avoidance_passed:
        codes.append("standards_avoidance_failed")
    codes.extend(result.failure_reason_codes)
    return tuple(dict.fromkeys(codes))


def _fingerprint(
    *,
    authorization: OwnerCanaryAuthorization,
    case_id: str,
    blocking_codes: Sequence[str],
) -> str:
    blockers_sha = sealed_sha256(
        {
            "schema": "legalbot.owner-canary-blocking-set.v1",
            "blocking_reason_codes": sorted(set(blocking_codes)),
        }
    )
    return failure_fingerprint(
        stage="owner_canary",
        reason_code=blocking_codes[0],
        scope_id=case_id,
        identity_digests=(
            authorization.seal_sha256,
            blockers_sha,
        ),
    )


def _result_material(
    *,
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
    status: Literal["passed", "stopped"],
    completed_case_ids: Sequence[str],
    projection_receipt_seal_sha256s: Sequence[str],
    callback_invocation_count: int,
    stopped_case_id: str | None,
    stop_reason_codes: Sequence[str],
    attempt_trace: Sequence[OwnerCanaryAttemptTrace],
    debug_artifact_id: str | None = None,
    debug_ciphertext_sha256: str | None = None,
    debug_projection_seal_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": CIRCUIT_RESULT_SCHEMA,
        "run_id": authorization.run_id,
        "authorization_seal_sha256": authorization.seal_sha256,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "lane": authorization.lane,
        "status": status,
        "expected_case_count": 30,
        "completed_case_ids": list(completed_case_ids),
        "projection_receipt_seal_sha256s": list(projection_receipt_seal_sha256s),
        "callback_invocation_count": callback_invocation_count,
        "stopped_case_id": stopped_case_id,
        "stop_reason_codes": list(stop_reason_codes),
        "attempt_trace": [item.model_dump(mode="json") for item in attempt_trace],
        "debug_artifact_id": debug_artifact_id,
        "debug_ciphertext_sha256": debug_ciphertext_sha256,
        "debug_projection_seal_sha256": debug_projection_seal_sha256,
        "no_next_case_submitted_after_stop": True,
        "restart_allowed": False,
        "frozen": True,
    }


def _write_terminal_result(
    *,
    workspace: CanaryReviewWorkspace,
    circuit_identity: str,
    material: dict[str, Any],
) -> OwnerCanaryCircuitResult:
    material["seal_sha256"] = sealed_sha256(material)
    result = OwnerCanaryCircuitResult.model_validate(material)
    workspace.write_safe_json(
        category="retry-trace",
        filename=f"circuit-{circuit_identity}-result.json",
        value=result.model_dump(mode="json", by_alias=True),
    )
    return result


def _stop(
    *,
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
    workspace: CanaryReviewWorkspace,
    cipher: LocalCipher,
    circuit_identity: str,
    completed_case_ids: Sequence[str],
    projection_receipt_seal_sha256s: Sequence[str],
    callback_invocation_count: int,
    stopped_case_id: str,
    stop_reason_codes: Sequence[str],
    attempt_trace: Sequence[OwnerCanaryAttemptTrace],
) -> OwnerCanaryCircuitResult:
    debug_material: dict[str, Any] = {
        "schema": CIRCUIT_DEBUG_SCHEMA,
        "run_id": authorization.run_id,
        "authorization_seal_sha256": authorization.seal_sha256,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "lane": authorization.lane,
        "stopped_case_id": stopped_case_id,
        "stop_reason_codes": list(stop_reason_codes),
        "completed_case_ids": list(completed_case_ids),
        "projection_receipt_seal_sha256s": list(projection_receipt_seal_sha256s),
        "callback_invocation_count": callback_invocation_count,
        "attempt_trace": [item.model_dump(mode="json") for item in attempt_trace],
        "question_prose_retained": False,
        "answer_prose_retained": False,
        "exception_prose_retained": False,
        "next_case_submitted": False,
        "restart_allowed": False,
        "frozen": True,
    }
    debug_material["seal_sha256"] = sealed_sha256(debug_material)
    assert_safe_evaluation_payload(debug_material)
    artifact_id = f"canary-debug-{circuit_identity}"
    _payload_path, sidecar_path = workspace.write_encrypted_projection(
        category="debug-bundles",
        artifact_id=artifact_id,
        content=(json.dumps(debug_material, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
        cipher=cipher,
        case_id=stopped_case_id,
    )
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    material = _result_material(
        authorization=authorization,
        manifest=manifest,
        status="stopped",
        completed_case_ids=completed_case_ids,
        projection_receipt_seal_sha256s=projection_receipt_seal_sha256s,
        callback_invocation_count=callback_invocation_count,
        stopped_case_id=stopped_case_id,
        stop_reason_codes=stop_reason_codes,
        attempt_trace=attempt_trace,
        debug_artifact_id=artifact_id,
        debug_ciphertext_sha256=str(sidecar["ciphertext_sha256"]),
        debug_projection_seal_sha256=str(sidecar["seal_sha256"]),
    )
    return _write_terminal_result(
        workspace=workspace, circuit_identity=circuit_identity, material=material
    )


def run_owner_canary_serial(
    *,
    authorization: OwnerCanaryAuthorization,
    manifest: OwnerQualityCanaryManifest,
    bundle: LiveEvaluationBundle,
    workspace: CanaryReviewWorkspace,
    cipher: LocalCipher,
    initial_input_revision_sha256_by_case: Mapping[str, str],
    case_callback: OwnerCanaryCaseCallback | CaseCallback,
    case_projector: OwnerCanaryCaseProjector | CaseProjector,
) -> OwnerCanaryCircuitResult:
    """Run one immutable lane serially and freeze on the first unresolved case."""

    verify_authorization_manifest(authorization, manifest)
    if (
        bundle.manifest.seal_sha256 != manifest.suite_manifest_seal_sha256
        or bundle.registry.canonical_sha256 != manifest.suite_registry_canonical_sha256
        or workspace.manifest.run_id != authorization.run_id
        or workspace.manifest.lane != authorization.lane
        or workspace.manifest.canary_manifest_seal_sha256 != manifest.seal_sha256
        or workspace.manifest.runtime_run_manifest_sha256 != authorization.seal_sha256
        or workspace.manifest.candidate_build_id != authorization.candidate_build_id
        or workspace.manifest.candidate_manifest_sha256 != authorization.candidate_manifest_sha256
        or workspace.manifest.expected_case_ids != authorization.authorized_case_ids
    ):
        raise ValueError("owner-canary circuit bindings differ from authorization")
    initial = dict(initial_input_revision_sha256_by_case)
    if set(initial) != set(authorization.authorized_case_ids) or any(
        not _SHA256.fullmatch(value) for value in initial.values()
    ):
        raise ValueError("owner-canary initial input identities are incomplete")

    circuit_identity = hashlib.sha256(
        f"{authorization.authorization_id}\0{workspace.manifest.seal_sha256}".encode()
    ).hexdigest()[:20]
    start: dict[str, Any] = {
        "schema": CIRCUIT_START_SCHEMA,
        "run_id": authorization.run_id,
        "authorization_seal_sha256": authorization.seal_sha256,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "lane": authorization.lane,
        "case_ids": list(authorization.authorized_case_ids),
        "case_count": 30,
        "maximum_attempt_count": MAX_ATTEMPTS,
        "serial_execution": True,
        "restart_allowed": False,
        "frozen": True,
    }
    start["seal_sha256"] = sealed_sha256(start)
    workspace.write_safe_json(
        category="retry-trace",
        filename=f"circuit-{circuit_identity}-start.json",
        value=start,
    )

    completed: list[str] = []
    projection_receipt_seals: list[str] = []
    trace: list[OwnerCanaryAttemptTrace] = []
    callback_count = 0
    for sequence_number, case_id in enumerate(authorization.authorized_case_ids, start=1):
        case = bundle.registry.case(case_id)
        input_revision = initial[case_id]
        used_inputs = {input_revision}
        prior_fingerprints: list[str] = []
        for attempt_number in range(1, MAX_ATTEMPTS + 1):
            request = _request(
                authorization=authorization,
                manifest=manifest,
                case_id=case_id,
                sequence_number=sequence_number,
                attempt_number=attempt_number,
                word_target=case.word_target,
                input_revision_sha256=input_revision,
            )
            callback_count += 1
            try:
                raw_result = case_callback(request)
                result = OwnerCanaryCaseAttemptResult.model_validate(
                    raw_result.model_dump(mode="json", by_alias=True)
                    if isinstance(raw_result, BaseModel)
                    else raw_result
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                worker_blockers = ("worker_hard_failure", "worker_result_invalid")
                fingerprint = _fingerprint(
                    authorization=authorization,
                    case_id=case_id,
                    blocking_codes=worker_blockers,
                )
                trace.append(
                    OwnerCanaryAttemptTrace(
                        case_id=case_id,
                        attempt_number=attempt_number,
                        input_revision_sha256=input_revision,
                        result_seal_sha256=None,
                        blocking_reason_codes=worker_blockers,
                        failure_fingerprint_sha256=fingerprint,
                        action="stop",
                        decision_reason="worker_hard_failure",
                    )
                )
                return _stop(
                    authorization=authorization,
                    manifest=manifest,
                    workspace=workspace,
                    cipher=cipher,
                    circuit_identity=circuit_identity,
                    completed_case_ids=completed,
                    projection_receipt_seal_sha256s=projection_receipt_seals,
                    callback_invocation_count=callback_count,
                    stopped_case_id=case_id,
                    stop_reason_codes=worker_blockers,
                    attempt_trace=trace,
                )

            blockers: tuple[str, ...]
            if (
                result.run_id != authorization.run_id
                or result.authorization_seal_sha256 != authorization.seal_sha256
                or result.canary_manifest_seal_sha256 != manifest.seal_sha256
                or result.case_id != case_id
                or result.attempt_number != attempt_number
                or result.input_revision_sha256 != input_revision
                or result.candidate_build_id != authorization.candidate_build_id
                or result.candidate_manifest_sha256 != authorization.candidate_manifest_sha256
            ):
                blockers = ("worker_hard_failure", "worker_result_binding_failure")
            else:
                blockers = _blocking_codes(
                    result=result,
                    authorization=authorization,
                    word_target=case.word_target,
                    question_sha256=case.question_sha256,
                    task_type=case.task_type,
                    subject=case.subject,
                )
            if not blockers:
                try:
                    raw_receipt = case_projector(result)
                    receipt = OwnerCanaryCaseProjectionReceipt.model_validate(
                        raw_receipt.model_dump(mode="json", by_alias=True)
                        if isinstance(raw_receipt, BaseModel)
                        else raw_receipt
                    )
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
                        job_id=cast(str, result.job_id),
                        answer_version_id=cast(str, result.answer_version_id),
                        answer_artifact_id=cast(str, result.answer_artifact_id),
                        answer_sha256=cast(str, result.answer_sha256),
                        word_count=cast(int, result.word_count),
                        evidence_bundle_seal_sha256=cast(
                            OwnerCanaryEvidenceBundle, result.evidence_bundle
                        ).seal_sha256,
                        ai_review_seal_sha256=cast(
                            AIEvidenceReviewResult, result.ai_review
                        ).seal_sha256,
                        ai_adjudication_seal_sha256=cast(
                            AIEvidenceAdjudication, result.ai_adjudication
                        ).seal_sha256,
                        standards_report_seal_sha256=cast(
                            AssessmentStandardsReport, result.standards_report
                        ).seal_sha256,
                        deterministic_gate_report_seal_sha256=cast(
                            OwnerCanaryDeterministicGateReport,
                            result.deterministic_gate_report,
                        ).seal_sha256,
                        release_attestation_seal_sha256=cast(
                            OwnerCanaryReleaseAttestation, result.release_attestation
                        ).seal_sha256,
                    )
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    projection_blockers = (
                        "case_projection_failure",
                        "case_projection_binding_failure",
                    )
                    projection_fingerprint = _fingerprint(
                        authorization=authorization,
                        case_id=case_id,
                        blocking_codes=projection_blockers,
                    )
                    trace.append(
                        OwnerCanaryAttemptTrace(
                            case_id=case_id,
                            attempt_number=attempt_number,
                            input_revision_sha256=input_revision,
                            result_seal_sha256=result.seal_sha256,
                            blocking_reason_codes=projection_blockers,
                            failure_fingerprint_sha256=projection_fingerprint,
                            projection_receipt_seal_sha256=None,
                            action="stop",
                            decision_reason="case_projection_failure",
                        )
                    )
                    return _stop(
                        authorization=authorization,
                        manifest=manifest,
                        workspace=workspace,
                        cipher=cipher,
                        circuit_identity=circuit_identity,
                        completed_case_ids=completed,
                        projection_receipt_seal_sha256s=projection_receipt_seals,
                        callback_invocation_count=callback_count,
                        stopped_case_id=case_id,
                        stop_reason_codes=projection_blockers,
                        attempt_trace=trace,
                    )
                trace.append(
                    OwnerCanaryAttemptTrace(
                        case_id=case_id,
                        attempt_number=attempt_number,
                        input_revision_sha256=input_revision,
                        result_seal_sha256=result.seal_sha256,
                        blocking_reason_codes=(),
                        failure_fingerprint_sha256=None,
                        projection_receipt_seal_sha256=receipt.seal_sha256,
                        action="case_passed",
                        decision_reason="case_passed",
                    )
                )
                projection_receipt_seals.append(receipt.seal_sha256)
                completed.append(case_id)
                break

            fingerprint = _fingerprint(
                authorization=authorization,
                case_id=case_id,
                blocking_codes=blockers,
            )
            hard_stop = any(
                code in _NON_RETRYABLE_CONTROLLER_CODES
                or code in result.deterministic_hard_failure_codes
                for code in blockers
            )
            next_input = result.next_input_revision_sha256
            changed_input = (
                next_input is not None
                and next_input != input_revision
                and next_input not in used_inputs
            )
            decision = decide_retry(
                attempt_number=attempt_number,
                failure_reason_code=blockers[0],
                failure_fingerprint_sha256=fingerprint,
                prior_failure_fingerprints=prior_fingerprints,
                deterministic_safety=hard_stop,
                retryable=not hard_stop,
                input_or_condition_changed=changed_input,
            )
            if decision.reason == "retry_condition_unchanged" and next_input is None:
                decision_reason = "retry_input_missing"
            elif decision.reason == "retry_condition_unchanged" and next_input == input_revision:
                decision_reason = "retry_input_unchanged"
            elif decision.reason == "retry_condition_unchanged" and next_input in used_inputs:
                decision_reason = "retry_input_reused"
            else:
                decision_reason = decision.reason
            should_retry = decision.should_retry and decision_reason == "retry_allowed"
            trace.append(
                OwnerCanaryAttemptTrace(
                    case_id=case_id,
                    attempt_number=attempt_number,
                    input_revision_sha256=input_revision,
                    result_seal_sha256=result.seal_sha256,
                    blocking_reason_codes=blockers,
                    failure_fingerprint_sha256=fingerprint,
                    action="retry" if should_retry else "stop",
                    decision_reason=decision_reason,
                )
            )
            prior_fingerprints.append(fingerprint)
            if should_retry and next_input is not None:
                used_inputs.add(next_input)
                input_revision = next_input
                continue
            stop_codes = tuple(dict.fromkeys((*blockers, decision_reason)))
            return _stop(
                authorization=authorization,
                manifest=manifest,
                workspace=workspace,
                cipher=cipher,
                circuit_identity=circuit_identity,
                completed_case_ids=completed,
                projection_receipt_seal_sha256s=projection_receipt_seals,
                callback_invocation_count=callback_count,
                stopped_case_id=case_id,
                stop_reason_codes=stop_codes,
                attempt_trace=trace,
            )
        else:  # pragma: no cover - range and retry-cap logic make this unreachable.
            raise AssertionError("owner-canary attempt loop escaped retry policy")

    material = _result_material(
        authorization=authorization,
        manifest=manifest,
        status="passed",
        completed_case_ids=completed,
        projection_receipt_seal_sha256s=projection_receipt_seals,
        callback_invocation_count=callback_count,
        stopped_case_id=None,
        stop_reason_codes=(),
        attempt_trace=trace,
    )
    return _write_terminal_result(
        workspace=workspace, circuit_identity=circuit_identity, material=material
    )
