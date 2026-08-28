"""Create-only exact all-60 qualification derived from reviewed gold.

The artifact produced here is the only file-based all-60 qualification accepted
by the owner-quality sampling and Stage A entry points.  It is derived from the
sealed expert overlay and exact catalogue matches; callers cannot provide its
seal or hand-author case dispositions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..legal_roles import MATERIAL_CASE_ROLES
from .all60_evidence_review import (
    All60OwnerDecisionRequired,
    all60_issue_identity_sha256,
    verify_all60_candidate_evidence_reviews,
)
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_gold import LiveGoldSpan, LiveSuiteExpertQualification
from .owner_quality_canary import All60CaseQualification
from .sealed_candidate import SealedCandidateIdentity

EXACT_ALL60_QUALIFICATION_SCHEMA = "legalbot.live60-all-case-qualification.v3"
EXACT_ALL60_ISSUE_BINDING_SCHEMA = "legalbot.live60-all-issue-binding.v2"
EXACT_ALL60_CASE_BINDING_SCHEMA = "legalbot.live60-all-case-binding.v1"
EXACT_ALL60_FILENAME = "all60-qualification.json"
ALL60_REPLAY_EXPERT_FILENAME = "all60-expert-qualification.json"
ALL60_REPLAY_CHECKPOINT_DIRNAME = "all60-ai-review-checkpoints"
ALL60_REPLAY_BATCH_ROOT_NAME = "all60-ai-review"


def _binding_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("binding_sha256", None)
    return sealed_sha256(material)


class ExactAll60IssueBinding(BaseModel):
    """Prose-free identity and positive-span proof for one frozen issue."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-all-issue-binding.v2"] = Field(
        default="legalbot.live60-all-issue-binding.v2", alias="schema"
    )
    ordinal: int = Field(ge=1, le=585)
    row_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    issue_id: str = Field(pattern=r"^issue-[0-9]{2}$")
    issue_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["qualified"]
    positive_span_count: int = Field(ge=1, le=10_000)
    positive_span_binding_sha256s: tuple[str, ...]
    contrary_span_binding_sha256s: tuple[str, ...]
    material_case_currentness_review_sha256s: tuple[str, ...]
    claim_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_checkpoint_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_invocation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    ai_reviewer_model_id: str = Field(min_length=1, max_length=255)
    ai_reviewer_model_version: str = Field(min_length=1, max_length=255)
    ai_reviewer_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_reviewer_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_reviewer_toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gate_set_member_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_catalogue_match_passed: Literal[True]
    exact_candidate_membership_passed: Literal[True]
    jurisdiction_gate_passed: Literal[True]
    authority_lane_gate_passed: Literal[True]
    source_rights_gate_passed: Literal[True]
    locator_gate_passed: Literal[True]
    contrary_authority_gate_passed: Literal[True]
    ai_evidence_review_passed: Literal[True]
    currentness_gate_passed: Literal[True]
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "positive_span_binding_sha256s",
        "contrary_span_binding_sha256s",
        "material_case_currentness_review_sha256s",
    )
    @classmethod
    def digests_are_valid_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in values
        ):
            raise ValueError("all-60 issue binding contains an invalid digest")
        if len(values) != len(set(values)):
            raise ValueError("all-60 issue binding contains duplicate digests")
        return values

    @model_validator(mode="after")
    def positive_binding_is_complete(self) -> Self:
        if self.positive_span_count != len(self.positive_span_binding_sha256s):
            raise ValueError("all-60 issue positive-span inventory is incomplete")
        if self.binding_sha256 != _binding_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all-60 issue binding seal does not match")
        return self


class ExactAll60CaseBinding(BaseModel):
    """Prose-free exact issue inventory for one fully qualified case."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-all-case-binding.v1"] = Field(
        default="legalbot.live60-all-case-binding.v1", alias="schema"
    )
    ordinal: int = Field(ge=1, le=60)
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["qualified"]
    contrary_authority_status: Literal["reviewed_none", "reviewed_and_bound"]
    issue_count: int = Field(ge=1, le=99)
    issue_ids: tuple[str, ...]
    issue_binding_sha256s: tuple[str, ...]
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("issue_ids")
    @classmethod
    def issue_ids_are_ordered_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        expected = tuple(f"issue-{number:02d}" for number in range(1, len(values) + 1))
        if values != expected:
            raise ValueError("all-60 case issue identities are incomplete or out of order")
        return values

    @field_validator("issue_binding_sha256s")
    @classmethod
    def issue_digests_are_valid_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in values
        ):
            raise ValueError("all-60 case binding contains an invalid issue digest")
        if len(values) != len(set(values)):
            raise ValueError("all-60 case binding contains duplicate issue digests")
        return values

    @model_validator(mode="after")
    def issue_inventory_is_complete(self) -> Self:
        if self.issue_count != len(self.issue_ids) or self.issue_count != len(
            self.issue_binding_sha256s
        ):
            raise ValueError("all-60 case issue inventory is incomplete")
        if self.binding_sha256 != _binding_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("all-60 case binding seal does not match")
        return self


class ExactAll60Qualification(All60CaseQualification):
    """Exact 60-case/585-issue artifact accepted by file-based consumers."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-all-case-qualification.v3"] = Field(
        default="legalbot.live60-all-case-qualification.v3", alias="schema"
    )
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_source_manifest_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_lance_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provision_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expert_qualification_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    ai_review_batch_run_date: date
    ai_review_batch_attestation_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_checkpoint_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_intent_ledger_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_outcome_ledger_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_launcher_start_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_batch_launcher_end_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    as_of_date: date
    issue_count: Literal[585]
    qualified_issue_count: Literal[585]
    positive_span_issue_count: Literal[585]
    exact_catalogue_match_issue_count: Literal[585]
    currentness_gate_issue_count: Literal[585]
    deterministic_gate_issue_count: Literal[585]
    ai_evidence_review_issue_count: Literal[585]
    currentness_basis: Literal["sealed-candidate-currentness-plus-exact-case-proposition-reviews"]
    case_bindings: tuple[ExactAll60CaseBinding, ...]
    issue_bindings: tuple[ExactAll60IssueBinding, ...]
    issue_identity_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue_binding_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gate_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_evidence_review_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    derivation: Literal["sealed-candidate-spans-deterministic-gates-and-independent-ai-reviews"]
    stage_a_used_for_qualification: Literal[False]
    selected_only_coverage_reused: Literal[False]
    owner_authored_seal_accepted: Literal[False]
    purpose: Literal["evaluation_only"]
    local_only: Literal[True]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    writes_active: Literal[False]
    writes_o04: Literal[False]
    create_only: Literal[True]

    @model_validator(mode="after")
    def exact_inventory_is_complete(self) -> Self:
        case_ids = tuple(item.case_id for item in self.case_bindings)
        issue_rows = tuple(item.row_id for item in self.issue_bindings)
        issue_identities = tuple(item.issue_identity_sha256 for item in self.issue_bindings)
        issue_bindings = tuple(item.binding_sha256 for item in self.issue_bindings)
        review_checkpoints = tuple(
            item.ai_review_checkpoint_seal_sha256 for item in self.issue_bindings
        )
        review_invocations = tuple(item.ai_review_invocation_id for item in self.issue_bindings)
        if (
            self.qualified_case_ids != self.case_ids
            or self.limited_case_ids
            or case_ids != self.case_ids
            or tuple(item.ordinal for item in self.case_bindings) != tuple(range(1, 61))
            or len(issue_rows) != 585
            or len(set(issue_rows)) != 585
            or tuple(item.ordinal for item in self.issue_bindings) != tuple(range(1, 586))
            or sum(item.issue_count for item in self.case_bindings) != 585
            or tuple(
                binding for case in self.case_bindings for binding in case.issue_binding_sha256s
            )
            != issue_bindings
            or len(set(review_checkpoints)) != 585
            or len(set(review_invocations)) != 585
            or len(
                {
                    (item.ai_reviewer_model_id, item.ai_reviewer_model_version)
                    for item in self.issue_bindings
                }
            )
            != 1
        ):
            raise ValueError("exact all-60 qualification inventory is incomplete")
        if self.issue_identity_set_sha256 != sealed_sha256(
            {
                "schema": "legalbot.live60-all-issue-identity-set.v1",
                "issue_identity_sha256s": list(issue_identities),
            }
        ):
            raise ValueError("exact all-60 issue identity set does not match")
        if self.issue_binding_set_sha256 != sealed_sha256(
            {
                "schema": "legalbot.live60-all-issue-binding-set.v1",
                "issue_binding_sha256s": list(issue_bindings),
            }
        ):
            raise ValueError("exact all-60 issue binding set does not match")
        if self.deterministic_gate_set_sha256 != sealed_sha256(
            {
                "schema": "legalbot.live60-deterministic-gate-set.v1",
                "gate_sha256s": [
                    item.deterministic_gate_set_member_sha256 for item in self.issue_bindings
                ],
            }
        ):
            raise ValueError("exact all-60 deterministic gate set does not match")
        if self.ai_evidence_review_set_sha256 != sealed_sha256(
            {
                "schema": "legalbot.live60-ai-evidence-review-set.v1",
                "checkpoint_seal_sha256s": list(review_checkpoints),
            }
        ):
            raise ValueError("exact all-60 AI evidence-review set does not match")
        return self


def _span_binding(span: LiveGoldSpan) -> str:
    review = span.case_currentness_review
    return sealed_sha256(
        {
            "schema": "legalbot.live60-all-positive-span-binding.v1",
            "gold_span_id": span.gold_span_id,
            "issue_id": span.issue_id,
            "stable_source_id": span.stable_source_id,
            "source_version_id": span.source_version_id,
            "chunk_id": span.chunk_id,
            "content_sha256": span.content_sha256,
            "legal_locator_sha256": sealed_sha256(
                {
                    "schema": "legalbot.legal-locator-binding.v1",
                    "legal_locator": span.legal_locator,
                }
            ),
            "legal_role": span.legal_role,
            "source_type": span.source_type,
            "proposition_hash": span.proposition_hash,
            "case_currentness_review_sha256": (review.seal_sha256 if review is not None else None),
            "contrary_or_limiting": span.contrary_or_limiting,
        }
    )


def _validate_material_case_currentness(span: LiveGoldSpan, *, as_of_date: date) -> str | None:
    if span.source_type != "case" or span.legal_role not in MATERIAL_CASE_ROLES:
        return None
    review = span.case_currentness_review
    if (
        review is None
        or not review.qualifies_for_present_law
        or review.later_treatment_reviewed_as_of_date != as_of_date
    ):
        raise ValueError("material case span lacks current as-of proposition review")
    return review.seal_sha256


def build_exact_all60_qualification(
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert_qualification: LiveSuiteExpertQualification,
    required_as_of_date: date,
    candidate_build_root: Path,
    ai_review_batch: object,
) -> ExactAll60Qualification:
    """Derive the exact qualification; no caller-supplied output fields are accepted."""

    expert = LiveSuiteExpertQualification.model_validate(
        expert_qualification.model_dump(mode="json", by_alias=True)
    )
    registry_ids = tuple(case.case_id for case in bundle.registry.cases)
    if (
        bundle.registry.case_count != 60
        or len(registry_ids) != 60
        or candidate.status != "candidate"
        or candidate.chunk_count < 1
        or candidate.vector_count != candidate.chunk_count
        or expert.suite_id != bundle.manifest.suite_id
        or expert.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
        or expert.run_plan_sha256 != bundle.manifest.run_plan_sha256
        or expert.index_build_id != candidate.build_id
        or expert.as_of_date != required_as_of_date
        or expert.case_count != 60
        or tuple(case.case_id for case in expert.cases) != registry_ids
    ):
        raise ValueError("all-60 derivation inputs have mismatched sealed identities")
    preflight_issue_count = 0
    for source_case, expert_case in zip(bundle.registry.cases, expert.cases, strict=True):
        expected_issue_ids = tuple(
            f"issue-{number:02d}" for number in range(1, len(source_case.must_cover_issues) + 1)
        )
        if (
            expert_case.case_id != source_case.case_id
            or expert_case.question_sha256 != source_case.question_sha256
            or expert_case.record_sha256 != source_case.record_sha256
            or expert_case.status != "qualified"
            or tuple(issue.issue_id for issue in expert_case.issues) != expected_issue_ids
            or expert_case.contrary_authority_status not in {"reviewed_none", "reviewed_and_bound"}
            or any(
                issue.status != "qualified"
                or issue.reason_code is not None
                or not any(not span.contrary_or_limiting for span in issue.exact_gold_spans)
                for issue in expert_case.issues
            )
        ):
            raise ValueError("all-60 derivation found missing, limited or unbound issue review")
        preflight_issue_count += len(expert_case.issues)
    if preflight_issue_count != 585:
        raise ValueError("all-60 derivation requires exactly 585 issue reviews")
    evidence_reviews = verify_all60_candidate_evidence_reviews(
        bundle=bundle,
        candidate=candidate,
        expert=expert,
        required_as_of_date=required_as_of_date,
        candidate_build_root=candidate_build_root,
        ai_review_batch=ai_review_batch,
    )
    from .all60_ai_review_batch import require_verified_all60_ai_review_batch

    verified_batch = require_verified_all60_ai_review_batch(ai_review_batch)
    checkpoint_directory = verified_batch.checkpoint_directory
    batch_run_root = checkpoint_directory.parent
    batch_date_root = batch_run_root.parent
    batch_evaluation_root = batch_date_root.parent
    try:
        batch_run_date = date.fromisoformat(batch_date_root.name)
    except ValueError as exc:
        raise ValueError("all-60 reviewer batch path has no exact run date") from exc
    if (
        checkpoint_directory.name != "checkpoints"
        or batch_run_root.name != verified_batch.attestation.run_id
        or batch_evaluation_root.name != ALL60_REPLAY_BATCH_ROOT_NAME
    ):
        raise ValueError("all-60 reviewer batch path identity differs")

    issue_bindings: list[ExactAll60IssueBinding] = []
    case_bindings: list[ExactAll60CaseBinding] = []
    global_ordinal = 0
    for case_ordinal, (source_case, expert_case) in enumerate(
        zip(bundle.registry.cases, expert.cases, strict=True), start=1
    ):
        expected_issue_ids = tuple(
            f"issue-{number:02d}" for number in range(1, len(source_case.must_cover_issues) + 1)
        )
        if (
            expert_case.case_id != source_case.case_id
            or expert_case.question_sha256 != source_case.question_sha256
            or expert_case.record_sha256 != source_case.record_sha256
            or expert_case.status != "qualified"
            or tuple(issue.issue_id for issue in expert_case.issues) != expected_issue_ids
            or expert_case.contrary_authority_status not in {"reviewed_none", "reviewed_and_bound"}
        ):
            raise ValueError("all-60 derivation found missing, limited or unbound case review")
        case_issue_bindings: list[ExactAll60IssueBinding] = []
        for topic, issue in zip(source_case.must_cover_issues, expert_case.issues, strict=True):
            global_ordinal += 1
            if issue.status != "qualified" or issue.reason_code is not None:
                raise ValueError("all-60 derivation refuses limited or missing issues")
            positive = tuple(
                span for span in issue.exact_gold_spans if not span.contrary_or_limiting
            )
            contrary = tuple(span for span in issue.exact_gold_spans if span.contrary_or_limiting)
            if not positive:
                raise ValueError("all-60 derivation requires a positive frozen span per issue")
            currentness_reviews = tuple(
                digest
                for digest in (
                    _validate_material_case_currentness(span, as_of_date=expert.as_of_date)
                    for span in issue.exact_gold_spans
                )
                if digest is not None
            )
            issue_identity = all60_issue_identity_sha256(
                case_id=source_case.case_id,
                issue_id=issue.issue_id,
                question_sha256=source_case.question_sha256,
                record_sha256=source_case.record_sha256,
                topic=topic,
            )
            row_id = f"{source_case.case_id}:{issue.issue_id}"
            ai_review = evidence_reviews.issues.get(row_id)
            if ai_review is None:
                raise ValueError("all-60 issue lacks an exact AI evidence-review binding")
            material: dict[str, Any] = {
                "schema": EXACT_ALL60_ISSUE_BINDING_SCHEMA,
                "ordinal": global_ordinal,
                "row_id": row_id,
                "case_id": source_case.case_id,
                "issue_id": issue.issue_id,
                "issue_identity_sha256": issue_identity,
                "status": "qualified",
                "positive_span_count": len(positive),
                "positive_span_binding_sha256s": [_span_binding(span) for span in positive],
                "contrary_span_binding_sha256s": [_span_binding(span) for span in contrary],
                "material_case_currentness_review_sha256s": list(currentness_reviews),
                "claim_sha256": ai_review.claim_sha256,
                "evidence_bundle_sha256": ai_review.evidence_bundle_sha256,
                "ai_review_checkpoint_seal_sha256": ai_review.checkpoint_seal_sha256,
                "ai_review_invocation_id": ai_review.invocation_id,
                "ai_reviewer_model_id": ai_review.model_id,
                "ai_reviewer_model_version": ai_review.model_version,
                "ai_reviewer_prompt_sha256": ai_review.prompt_sha256,
                "ai_reviewer_policy_sha256": ai_review.policy_sha256,
                "ai_reviewer_toolchain_sha256": ai_review.toolchain_sha256,
                "deterministic_gate_set_member_sha256": (ai_review.deterministic_gate_sha256),
                "exact_catalogue_match_passed": True,
                "exact_candidate_membership_passed": True,
                "jurisdiction_gate_passed": True,
                "authority_lane_gate_passed": True,
                "source_rights_gate_passed": True,
                "locator_gate_passed": True,
                "contrary_authority_gate_passed": True,
                "ai_evidence_review_passed": True,
                "currentness_gate_passed": True,
            }
            material["binding_sha256"] = _binding_sha256(material)
            case_issue_bindings.append(ExactAll60IssueBinding.model_validate(material))
        case_material: dict[str, Any] = {
            "schema": EXACT_ALL60_CASE_BINDING_SCHEMA,
            "ordinal": case_ordinal,
            "case_id": source_case.case_id,
            "question_sha256": source_case.question_sha256,
            "record_sha256": source_case.record_sha256,
            "status": "qualified",
            "contrary_authority_status": expert_case.contrary_authority_status,
            "issue_count": len(case_issue_bindings),
            "issue_ids": [item.issue_id for item in case_issue_bindings],
            "issue_binding_sha256s": [item.binding_sha256 for item in case_issue_bindings],
        }
        case_material["binding_sha256"] = _binding_sha256(case_material)
        case_bindings.append(ExactAll60CaseBinding.model_validate(case_material))
        issue_bindings.extend(case_issue_bindings)
    if global_ordinal != 585:
        raise ValueError("all-60 derivation requires exactly 585 frozen issues")

    issue_identity_sha256s = [item.issue_identity_sha256 for item in issue_bindings]
    issue_binding_sha256s = [item.binding_sha256 for item in issue_bindings]
    issue_identity_set_sha256 = sealed_sha256(
        {
            "schema": "legalbot.live60-all-issue-identity-set.v1",
            "issue_identity_sha256s": issue_identity_sha256s,
        }
    )
    if verified_batch.attestation.issue_identity_set_sha256 != issue_identity_set_sha256:
        raise ValueError("all-60 reviewer batch issue inventory differs")
    material = {
        "schema": EXACT_ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": candidate.build_id,
        "case_count": 60,
        "case_ids": list(registry_ids),
        "qualified_case_ids": list(registry_ids),
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "candidate_seal_sha256": candidate.candidate_seal_sha256,
        "candidate_source_manifest_sha256": candidate.source_manifest_sha256,
        "candidate_source_manifest_file_sha256": (
            evidence_reviews.candidate_source_manifest_file_sha256
        ),
        "candidate_lance_tree_sha256": evidence_reviews.candidate_lance_tree_sha256,
        "provision_verification_sha256": evidence_reviews.provision_verification_sha256,
        "expert_qualification_seal_sha256": expert.seal_sha256,
        "ai_review_batch_run_id": verified_batch.attestation.run_id,
        "ai_review_batch_run_date": batch_run_date.isoformat(),
        "ai_review_batch_attestation_seal_sha256": (
            evidence_reviews.ai_review_batch_attestation_seal_sha256
        ),
        "ai_review_batch_manifest_seal_sha256": (
            evidence_reviews.ai_review_batch_manifest_seal_sha256
        ),
        "ai_review_batch_checkpoint_set_sha256": (
            evidence_reviews.ai_review_batch_checkpoint_set_sha256
        ),
        "ai_review_batch_intent_ledger_sha256": (
            evidence_reviews.ai_review_batch_intent_ledger_sha256
        ),
        "ai_review_batch_outcome_ledger_sha256": (
            evidence_reviews.ai_review_batch_outcome_ledger_sha256
        ),
        "ai_review_batch_launcher_start_sha256": (
            evidence_reviews.ai_review_batch_launcher_start_sha256
        ),
        "ai_review_batch_launcher_end_sha256": (
            evidence_reviews.ai_review_batch_launcher_end_sha256
        ),
        "as_of_date": expert.as_of_date.isoformat(),
        "issue_count": 585,
        "qualified_issue_count": 585,
        "positive_span_issue_count": 585,
        "exact_catalogue_match_issue_count": 585,
        "currentness_gate_issue_count": 585,
        "deterministic_gate_issue_count": 585,
        "ai_evidence_review_issue_count": 585,
        "currentness_basis": ("sealed-candidate-currentness-plus-exact-case-proposition-reviews"),
        "case_bindings": [item.model_dump(mode="json", by_alias=True) for item in case_bindings],
        "issue_bindings": [item.model_dump(mode="json", by_alias=True) for item in issue_bindings],
        "issue_identity_set_sha256": issue_identity_set_sha256,
        "issue_binding_set_sha256": sealed_sha256(
            {
                "schema": "legalbot.live60-all-issue-binding-set.v1",
                "issue_binding_sha256s": issue_binding_sha256s,
            }
        ),
        "deterministic_gate_set_sha256": evidence_reviews.deterministic_gate_set_sha256,
        "ai_evidence_review_set_sha256": evidence_reviews.ai_review_set_sha256,
        "derivation": ("sealed-candidate-spans-deterministic-gates-and-independent-ai-reviews"),
        "stage_a_used_for_qualification": False,
        "selected_only_coverage_reused": False,
        "owner_authored_seal_accepted": False,
        "purpose": "evaluation_only",
        "local_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "writes_active": False,
        "writes_o04": False,
        "create_only": True,
    }
    assert_safe_evaluation_payload(material)
    material["seal_sha256"] = sealed_sha256(material)
    return ExactAll60Qualification.model_validate(material)


def exact_all60_qualification_bytes(value: ExactAll60Qualification) -> bytes:
    qualification = ExactAll60Qualification.model_validate(
        value.model_dump(mode="json", by_alias=True)
    )
    payload = qualification.model_dump(mode="json", by_alias=True)
    assert_safe_evaluation_payload(payload)
    return (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def load_replayed_exact_all60_qualification(
    qualification_path: Path,
    *,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    candidate_build_root: Path,
    expert_qualification_path: Path,
    ai_review_batch: object,
    catalog_path: Path,
    project_root: Path,
    integration_sha: str,
) -> ExactAll60Qualification:
    """Replay v3 candidate, expert-overlay and 585-checkpoint derivation.

    Parsing a favorable self-sealed v3 JSON object is not qualification.  Every
    production consumer calls this function so the exact candidate Lance tree,
    approved-source/provision bytes, expert spans and independent AI checkpoint
    set are re-opened and deterministically rebuilt before use.
    """

    if (
        qualification_path.is_symlink()
        or not qualification_path.is_file()
        or stat.S_IMODE(qualification_path.stat().st_mode) != 0o600
        or expert_qualification_path.is_symlink()
        or not expert_qualification_path.is_file()
        or stat.S_IMODE(expert_qualification_path.stat().st_mode) != 0o600
    ):
        raise ValueError("all-60 replay inputs are missing or not owner-private")
    raw = qualification_path.read_bytes()
    try:
        supplied = ExactAll60Qualification.model_validate_json(raw)
    except Exception as exc:
        raise ValueError("all-60 v3 qualification contract is invalid") from exc
    require_trusted_all60_currentness_resolution(
        project_root=project_root,
        candidate=candidate,
        required_as_of_date=supplied.as_of_date,
        all60_inventory_sha256=supplied.issue_identity_set_sha256,
        integration_sha=integration_sha,
    )

    from .live_suite_gold import load_suite_expert_qualification
    from .live_suite_path_b import load_default_v2_repair

    expert = load_suite_expert_qualification(
        expert_qualification_path,
        bundle=bundle,
        index_build_id=candidate.build_id,
        as_of_date=supplied.as_of_date,
        catalog_path=catalog_path,
        repair=load_default_v2_repair(project_root),
    )
    replay_candidate = (
        candidate if candidate.status == "candidate" else replace(candidate, status="candidate")
    )
    expected = build_exact_all60_qualification(
        bundle=bundle,
        candidate=replay_candidate,
        expert_qualification=expert,
        required_as_of_date=supplied.as_of_date,
        candidate_build_root=candidate_build_root,
        ai_review_batch=ai_review_batch,
    )
    if supplied != expected or raw != exact_all60_qualification_bytes(expected):
        raise ValueError("all-60 qualification differs from its replayed authoritative evidence")
    return expected


def require_trusted_all60_currentness_resolution(
    *,
    project_root: Path,
    candidate: SealedCandidateIdentity,
    required_as_of_date: date,
    all60_inventory_sha256: str,
    integration_sha: str,
) -> None:
    """Require an exact owner resolution, then stop for trusted signature policy.

    The current generic owner-decision resolution is self-sealed and has no
    cryptographic owner proof.  We still validate its exact request/option and
    candidate/date/integration bindings so it cannot later be treated as a
    transferable favorable decision; execution remains closed until a trusted
    verifier is selected.
    """

    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", integration_sha):
        raise ValueError("all-60 currentness integration identity is invalid")
    from ..governance.owner_stop import (
        OwnerDecisionRequest,
        OwnerDecisionResolution,
        require_owner_resolution,
    )
    from .secure_artifact_io import read_private_file_at

    if not re.fullmatch(r"[0-9a-f]{64}", all60_inventory_sha256):
        raise ValueError("all-60 currentness inventory identity is invalid")
    identity = sealed_sha256(
        {
            "schema": "legalbot.all60-currentness-owner-decision-identity.v1",
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "candidate_source_manifest_sha256": candidate.source_manifest_sha256,
            "all60_inventory_sha256": all60_inventory_sha256,
            "as_of_date": required_as_of_date.isoformat(),
            "integration_sha": integration_sha,
        }
    )
    decision_id = f"v111-all60-currentness-{identity[:20]}"
    row_id = f"candidate:{candidate.build_id}"
    parts = ("data", "evaluations", "owner-decisions", decision_id)
    try:
        request = OwnerDecisionRequest.model_validate_json(
            read_private_file_at(project_root, (*parts, "request.json"))
        )
        resolution = OwnerDecisionResolution.model_validate_json(
            read_private_file_at(project_root, (*parts, "resolution.json"))
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        raise All60OwnerDecisionRequired(
            "LEGAL_CURRENTNESS_OWNER_DECISION_UNRESOLVED",
            row_id=row_id,
            decision_id=decision_id,
        ) from exc
    expected_evidence = {
        "candidate-manifest": candidate.candidate_manifest_sha256,
        "candidate-source-manifest": candidate.source_manifest_sha256,
        "all60-inventory": all60_inventory_sha256,
        "legal-as-of-date": hashlib.sha256(required_as_of_date.isoformat().encode()).hexdigest(),
        "integration": hashlib.sha256(integration_sha.encode()).hexdigest(),
    }
    observed_evidence = {item.evidence_id: item.sha256 for item in request.evidence}
    if (
        request.decision_id != decision_id
        or request.category != "legal_currentness"
        or request.scope_id != f"currentness:{identity[:20]}"
        or observed_evidence != expected_evidence
        or "authoritative_development_canary" not in request.blocked_actions
        or {item.option_id for item in request.options}
        != {
            "stage-official-currentness-review",
            "owner-accepts-bound-as-of-date",
            "defer-and-keep-closed",
        }
    ):
        raise All60OwnerDecisionRequired(
            "LEGAL_CURRENTNESS_OWNER_DECISION_BINDING_INVALID",
            row_id=row_id,
            decision_id=decision_id,
        )
    try:
        verified = require_owner_resolution(request, resolution)
    except PermissionError as exc:
        raise All60OwnerDecisionRequired(
            "LEGAL_CURRENTNESS_OWNER_DECISION_BINDING_INVALID",
            row_id=row_id,
            decision_id=decision_id,
        ) from exc
    if verified.selected_option_id != "owner-accepts-bound-as-of-date":
        raise All60OwnerDecisionRequired(
            "LEGAL_CURRENTNESS_OWNER_REVIEW_OR_DEFERRAL_SELECTED",
            row_id=row_id,
            decision_id=decision_id,
        )
    raise All60OwnerDecisionRequired(
        "TRUSTED_OWNER_DECISION_SIGNATURE_VERIFIER_MISSING",
        row_id=row_id,
        decision_id=decision_id,
    )


def write_exact_all60_qualification(
    *, output_directory: Path, qualification: ExactAll60Qualification
) -> Path:
    """Create one private deterministic artifact and refuse overwrite/symlinks."""

    if output_directory.is_symlink():
        raise ValueError("all-60 output directory must not be a symlink")
    if output_directory.exists():
        if not output_directory.is_dir():
            raise ValueError("all-60 output destination is not a directory")
        if stat.S_IMODE(output_directory.stat().st_mode) != 0o700:
            raise ValueError("all-60 output directory must have mode 0700")
    else:
        parent = output_directory.parent
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError("all-60 output parent must be an existing safe directory")
        output_directory.mkdir(mode=0o700)
    destination = output_directory / EXACT_ALL60_FILENAME
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("exact all-60 qualification is create-only")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(exact_all60_qualification_bytes(qualification))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    if (
        stat.S_IMODE(output_directory.stat().st_mode) != 0o700
        or stat.S_IMODE(destination.stat().st_mode) != 0o600
    ):
        raise RuntimeError("exact all-60 qualification permissions are not private")
    return destination
