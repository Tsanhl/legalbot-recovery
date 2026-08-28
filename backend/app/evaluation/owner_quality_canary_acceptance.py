"""Exact-30 owner-acceptance gate after technical canary completion.

Technical completion and a final review package are not owner acceptance.  This
module reconciles the latest append-only feedback decision for every exact
answer in a 30-case package, writes one create-only privacy-safe summary, and
provides mandatory consumers for development/promotion presentation and
holdout/normal-live readiness.  The summary is required but never sufficient
for promotion, O-04, ACTIVE, or normal live use.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canary_review_workspace import CanaryReviewWorkspace
from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .owner_quality_canary_feedback import (
    OwnerCanaryFeedbackIndex,
    load_owner_canary_feedback_index_chain,
)
from .owner_quality_canary_projection import OwnerCanaryFinalReviewPackage

OWNER_CANARY_ACCEPTANCE_SCHEMA = "legalbot.owner-canary-acceptance-summary.v1"
OWNER_CANARY_ACCEPTANCE_FILENAME = "owner-acceptance-summary.json"


@dataclass(frozen=True, slots=True)
class _AcceptanceSnapshot:
    chain: tuple[OwnerCanaryFeedbackIndex, ...]
    latest: tuple[OwnerCanaryFeedbackIndex, ...]
    chain_sha256: str


class OwnerCanaryAcceptanceSummary(BaseModel):
    """Sealed exact-answer acceptance summary with no owner-authentication claim."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-acceptance-summary.v1"] = Field(
        default="legalbot.owner-canary-acceptance-summary.v1", alias="schema"
    )
    acceptance_id: str = Field(pattern=r"^owner-canary-acceptance-[0-9a-f]{20}$")
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_id: str = Field(pattern=r"^owner-quality-canary-[0-9a-f]{20}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_review_package_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    circuit_result_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_count: Literal[30]
    case_ids: tuple[str, ...]
    answer_sha256s: tuple[str, ...]
    feedback_chain_entry_count: int = Field(ge=30, le=9999)
    feedback_chain_record_seal_sha256s: tuple[str, ...]
    feedback_chain_index_seal_sha256s: tuple[str, ...]
    feedback_chain_head_record_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feedback_chain_head_index_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feedback_chain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    latest_feedback_sequence_numbers: tuple[int, ...]
    latest_feedback_record_seal_sha256s: tuple[str, ...]
    latest_feedback_index_seal_sha256s: tuple[str, ...]
    latest_decisions: tuple[Literal["pass"], ...]
    latest_owner_refs: tuple[str, ...]
    explicit_latest_owner_decision_count: Literal[30]
    all_latest_owner_decisions_passed: Literal[True]
    owner_reference_authentication: Literal["not_cryptographically_verified"]
    owner_signature_verified: Literal[False]
    o04_signature_verified: Literal[False]
    technical_completion_alone_sufficient: Literal[False]
    development_completion_gate_passed: bool
    holdout_post_run_acceptance_gate_passed: bool
    authorizes_active: Literal[False]
    authorizes_promotion: Literal[False]
    authorizes_o04: Literal[False]
    authorizes_normal_live: Literal[False]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    plaintext_questions_included: Literal[False]
    plaintext_answers_included: Literal[False]
    create_only: Literal[True]
    created_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def created_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("owner-acceptance timestamp must be timezone-aware")
        return value

    @field_validator("case_ids")
    @classmethod
    def case_ids_are_exact(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != 30 or len(set(values)) != 30:
            raise ValueError("owner acceptance requires exactly 30 unique case IDs")
        return values

    @field_validator(
        "answer_sha256s",
        "feedback_chain_record_seal_sha256s",
        "feedback_chain_index_seal_sha256s",
        "latest_feedback_record_seal_sha256s",
        "latest_feedback_index_seal_sha256s",
    )
    @classmethod
    def digest_sequences_are_valid(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in values
        ):
            raise ValueError("owner acceptance contains an invalid digest")
        return values

    @model_validator(mode="after")
    def acceptance_is_exact_and_sealed(self) -> Self:
        chain_count = self.feedback_chain_entry_count
        exact_count = 30
        aligned_exact = (
            self.case_ids,
            self.answer_sha256s,
            self.latest_feedback_sequence_numbers,
            self.latest_feedback_record_seal_sha256s,
            self.latest_feedback_index_seal_sha256s,
            self.latest_decisions,
            self.latest_owner_refs,
        )
        if any(len(values) != exact_count for values in aligned_exact):
            raise ValueError("owner acceptance latest-decision inventory is incomplete")
        if (
            len(self.feedback_chain_record_seal_sha256s) != chain_count
            or len(self.feedback_chain_index_seal_sha256s) != chain_count
            or self.feedback_chain_head_record_seal_sha256
            != self.feedback_chain_record_seal_sha256s[-1]
            or self.feedback_chain_head_index_seal_sha256
            != self.feedback_chain_index_seal_sha256s[-1]
            or len(set(self.latest_feedback_sequence_numbers)) != exact_count
            or any(
                sequence < 1 or sequence > chain_count
                for sequence in self.latest_feedback_sequence_numbers
            )
            or any(not owner_ref.startswith("owner:") for owner_ref in self.latest_owner_refs)
            or self.development_completion_gate_passed != (self.lane == "development")
            or self.holdout_post_run_acceptance_gate_passed != (self.lane == "blind_holdout")
        ):
            raise ValueError("owner acceptance chain or lane result is inconsistent")
        expected_id = (
            "owner-canary-acceptance-"
            + sealed_sha256(
                {
                    "workspace_seal_sha256": self.workspace_seal_sha256,
                    "run_id": self.run_id,
                    "lane": self.lane,
                    "final_review_package_seal_sha256": self.final_review_package_seal_sha256,
                    "feedback_chain_sha256": self.feedback_chain_sha256,
                }
            )[:20]
        )
        if self.acceptance_id != expected_id:
            raise ValueError("owner acceptance identity does not match its bound inputs")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner acceptance summary seal does not match")
        return self


def _validated_package(
    *, workspace: CanaryReviewWorkspace, package: OwnerCanaryFinalReviewPackage
) -> OwnerCanaryFinalReviewPackage:
    package = OwnerCanaryFinalReviewPackage.model_validate(
        package.model_dump(mode="json", by_alias=True)
    )
    manifest = workspace.manifest
    if (
        manifest.seal_sha256 != package.workspace_seal_sha256
        or manifest.run_id != package.run_id
        or manifest.lane != package.lane
        or manifest.runtime_run_manifest_sha256 != package.authorization_seal_sha256
        or manifest.canary_manifest_seal_sha256 != package.canary_manifest_seal_sha256
        or manifest.candidate_build_id != package.candidate_build_id
        or manifest.candidate_manifest_sha256 != package.candidate_manifest_sha256
        or manifest.expected_case_ids != package.case_ids
    ):
        raise ValueError("owner acceptance inputs differ from the exact review package")
    return package


def _feedback_chain_sha256(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    chain: tuple[OwnerCanaryFeedbackIndex, ...],
) -> str:
    return sealed_sha256(
        {
            "schema": "legalbot.owner-canary-feedback-chain-binding.v1",
            "workspace_seal_sha256": workspace.manifest.seal_sha256,
            "final_review_package_seal_sha256": package.seal_sha256,
            "feedback_chain_record_seal_sha256s": [
                item.feedback_record_seal_sha256 for item in chain
            ],
            "feedback_chain_index_seal_sha256s": [item.seal_sha256 for item in chain],
        }
    )


def _acceptance_snapshot(
    *, workspace: CanaryReviewWorkspace, package: OwnerCanaryFinalReviewPackage
) -> _AcceptanceSnapshot:
    package = _validated_package(workspace=workspace, package=package)
    chain = load_owner_canary_feedback_index_chain(workspace=workspace, package=package)
    expected_answers = dict(zip(package.case_ids, package.answer_sha256s, strict=True))
    latest_by_case: dict[str, OwnerCanaryFeedbackIndex] = {}
    for index in chain:
        expected_answer = expected_answers.get(index.case_id)
        if expected_answer is None:
            raise ValueError("owner feedback contains a case outside the final package")
        if index.answer_sha256 != expected_answer:
            raise ValueError("owner feedback is bound to a stale or mismatched answer")
        latest_by_case[index.case_id] = index
    missing = tuple(case_id for case_id in package.case_ids if case_id not in latest_by_case)
    if missing:
        raise ValueError("owner acceptance is missing one or more exact-case decisions")
    latest = tuple(latest_by_case[case_id] for case_id in package.case_ids)
    failed = tuple(index for index in latest if index.decision != "pass" or not index.owner_pass)
    if failed:
        raise ValueError("latest owner decision is revise or reject; exact-30 acceptance failed")
    if len(latest) != 30:
        raise ValueError("owner acceptance does not contain exactly 30 latest decisions")
    return _AcceptanceSnapshot(
        chain=chain,
        latest=latest,
        chain_sha256=_feedback_chain_sha256(
            workspace=workspace,
            package=package,
            chain=chain,
        ),
    )


def _summary_material(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    snapshot: _AcceptanceSnapshot,
    created_at: datetime,
) -> dict[str, Any]:
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("owner-acceptance timestamp must be timezone-aware")
    manifest = workspace.manifest
    identity = sealed_sha256(
        {
            "workspace_seal_sha256": manifest.seal_sha256,
            "run_id": package.run_id,
            "lane": package.lane,
            "final_review_package_seal_sha256": package.seal_sha256,
            "feedback_chain_sha256": snapshot.chain_sha256,
        }
    )[:20]
    material: dict[str, Any] = {
        "schema": OWNER_CANARY_ACCEPTANCE_SCHEMA,
        "acceptance_id": f"owner-canary-acceptance-{identity}",
        "workspace_seal_sha256": manifest.seal_sha256,
        "run_id": package.run_id,
        "lane": package.lane,
        "authorization_seal_sha256": package.authorization_seal_sha256,
        "canary_manifest_id": manifest.canary_manifest_id,
        "canary_manifest_seal_sha256": package.canary_manifest_seal_sha256,
        "canary_manifest_file_sha256": manifest.canary_manifest_file_sha256,
        "candidate_build_id": package.candidate_build_id,
        "candidate_manifest_sha256": package.candidate_manifest_sha256,
        "final_review_package_seal_sha256": package.seal_sha256,
        "circuit_result_seal_sha256": package.circuit_result_seal_sha256,
        "case_count": 30,
        "case_ids": list(package.case_ids),
        "answer_sha256s": list(package.answer_sha256s),
        "feedback_chain_entry_count": len(snapshot.chain),
        "feedback_chain_record_seal_sha256s": [
            item.feedback_record_seal_sha256 for item in snapshot.chain
        ],
        "feedback_chain_index_seal_sha256s": [item.seal_sha256 for item in snapshot.chain],
        "feedback_chain_head_record_seal_sha256": (snapshot.chain[-1].feedback_record_seal_sha256),
        "feedback_chain_head_index_seal_sha256": snapshot.chain[-1].seal_sha256,
        "feedback_chain_sha256": snapshot.chain_sha256,
        "latest_feedback_sequence_numbers": [item.sequence_number for item in snapshot.latest],
        "latest_feedback_record_seal_sha256s": [
            item.feedback_record_seal_sha256 for item in snapshot.latest
        ],
        "latest_feedback_index_seal_sha256s": [item.seal_sha256 for item in snapshot.latest],
        "latest_decisions": [item.decision for item in snapshot.latest],
        "latest_owner_refs": [item.owner_ref for item in snapshot.latest],
        "explicit_latest_owner_decision_count": 30,
        "all_latest_owner_decisions_passed": True,
        "owner_reference_authentication": "not_cryptographically_verified",
        "owner_signature_verified": False,
        "o04_signature_verified": False,
        "technical_completion_alone_sufficient": False,
        "development_completion_gate_passed": package.lane == "development",
        "holdout_post_run_acceptance_gate_passed": package.lane == "blind_holdout",
        "authorizes_active": False,
        "authorizes_promotion": False,
        "authorizes_o04": False,
        "authorizes_normal_live": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "plaintext_questions_included": False,
        "plaintext_answers_included": False,
        "create_only": True,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
    }
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    return material


def create_owner_canary_acceptance_summary(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    created_at: datetime,
) -> OwnerCanaryAcceptanceSummary:
    """Write one exact-30 owner-acceptance summary after all latest decisions pass."""

    package = _validated_package(workspace=workspace, package=package)
    if OWNER_CANARY_ACCEPTANCE_FILENAME in workspace.list_private_directory("safe-metrics"):
        raise FileExistsError("owner-acceptance summary is create-only")
    snapshot = _acceptance_snapshot(workspace=workspace, package=package)
    summary = OwnerCanaryAcceptanceSummary.model_validate(
        _summary_material(
            workspace=workspace,
            package=package,
            snapshot=snapshot,
            created_at=created_at,
        )
    )
    workspace.write_safe_json(
        category="safe-metrics",
        filename=OWNER_CANARY_ACCEPTANCE_FILENAME,
        value=summary.model_dump(mode="json", by_alias=True),
    )
    return verify_owner_canary_acceptance_summary(
        workspace=workspace,
        package=package,
        expected=summary,
    )


def verify_owner_canary_acceptance_summary(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
    expected: OwnerCanaryAcceptanceSummary | None = None,
) -> OwnerCanaryAcceptanceSummary:
    """Reconcile the persisted summary against the current full feedback-chain head."""

    package = _validated_package(workspace=workspace, package=package)
    try:
        raw = workspace.read_private_bytes("safe-metrics", OWNER_CANARY_ACCEPTANCE_FILENAME)
    except FileNotFoundError as exc:
        raise ValueError("exact-30 owner-acceptance summary is required") from exc
    persisted = OwnerCanaryAcceptanceSummary.model_validate_json(raw)
    if expected is not None:
        expected = OwnerCanaryAcceptanceSummary.model_validate(
            expected.model_dump(mode="json", by_alias=True)
        )
        if persisted.seal_sha256 != expected.seal_sha256:
            raise ValueError("persisted owner acceptance differs from the expected summary")
    snapshot = _acceptance_snapshot(workspace=workspace, package=package)
    expected_fields: dict[str, Any] = {
        "workspace_seal_sha256": workspace.manifest.seal_sha256,
        "run_id": package.run_id,
        "lane": package.lane,
        "authorization_seal_sha256": package.authorization_seal_sha256,
        "canary_manifest_id": workspace.manifest.canary_manifest_id,
        "canary_manifest_seal_sha256": package.canary_manifest_seal_sha256,
        "canary_manifest_file_sha256": workspace.manifest.canary_manifest_file_sha256,
        "candidate_build_id": package.candidate_build_id,
        "candidate_manifest_sha256": package.candidate_manifest_sha256,
        "final_review_package_seal_sha256": package.seal_sha256,
        "circuit_result_seal_sha256": package.circuit_result_seal_sha256,
        "case_ids": package.case_ids,
        "answer_sha256s": package.answer_sha256s,
        "feedback_chain_entry_count": len(snapshot.chain),
        "feedback_chain_record_seal_sha256s": tuple(
            item.feedback_record_seal_sha256 for item in snapshot.chain
        ),
        "feedback_chain_index_seal_sha256s": tuple(item.seal_sha256 for item in snapshot.chain),
        "feedback_chain_head_record_seal_sha256": (snapshot.chain[-1].feedback_record_seal_sha256),
        "feedback_chain_head_index_seal_sha256": snapshot.chain[-1].seal_sha256,
        "feedback_chain_sha256": snapshot.chain_sha256,
        "latest_feedback_sequence_numbers": tuple(item.sequence_number for item in snapshot.latest),
        "latest_feedback_record_seal_sha256s": tuple(
            item.feedback_record_seal_sha256 for item in snapshot.latest
        ),
        "latest_feedback_index_seal_sha256s": tuple(item.seal_sha256 for item in snapshot.latest),
        "latest_decisions": tuple(item.decision for item in snapshot.latest),
        "latest_owner_refs": tuple(item.owner_ref for item in snapshot.latest),
    }
    if any(getattr(persisted, field) != value for field, value in expected_fields.items()):
        raise ValueError("owner-acceptance summary is stale or bound to different inputs")
    return persisted


def require_development_owner_acceptance_for_promotion_presentation(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
) -> OwnerCanaryAcceptanceSummary:
    """Require dev exact-30 owner passes; this still grants no promotion authority."""

    summary = verify_owner_canary_acceptance_summary(workspace=workspace, package=package)
    if summary.lane != "development" or not summary.development_completion_gate_passed:
        raise ValueError("development owner acceptance is required for promotion presentation")
    return summary


def require_holdout_owner_acceptance_for_normal_live_readiness(
    *,
    workspace: CanaryReviewWorkspace,
    package: OwnerCanaryFinalReviewPackage,
) -> OwnerCanaryAcceptanceSummary:
    """Require holdout exact-30 owner passes; all other normal-live gates remain required."""

    summary = verify_owner_canary_acceptance_summary(workspace=workspace, package=package)
    if summary.lane != "blind_holdout" or not summary.holdout_post_run_acceptance_gate_passed:
        raise ValueError("holdout owner acceptance is required for normal-live readiness")
    return summary
