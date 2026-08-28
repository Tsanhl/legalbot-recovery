"""Expert-reviewed legal-gold overlay for manifest-driven live suites.

Live60 overlays are authored as part of this same review plane. Live60 requires
one primary legal_reviewer. Independent second review is optional metadata, not
a mandatory second human. AI cannot be a reviewer. The suite still answers
England-and-Wales law.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..types import CASE_PROPOSITION_REVIEWER_ROLES
from .live30_gold import (
    Live30CaseQualification,
    Live30GoldSpan,
    Live30IssueQualification,
)
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_reviewer_identity import (
    build_owner_reviewer_identity,
    reviewer_role_is_forbidden_machine,
)

GOLD_SCHEMA = "legalbot.live-expert-qualification.v1"
GOLD_CASE_SCHEMA = "legalbot.live-case-qualification.v1"
GOLD_ISSUE_SCHEMA = "legalbot.live-issue-qualification.v1"
GOLD_SPAN_SCHEMA = "legalbot.live-gold-span.v1"


class LiveGoldSpan(Live30GoldSpan):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-gold-span.v1"] = Field(
        default="legalbot.live-gold-span.v1", alias="schema"
    )


class LiveIssueQualification(Live30IssueQualification):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-issue-qualification.v1"] = Field(
        default="legalbot.live-issue-qualification.v1", alias="schema"
    )
    exact_gold_spans: tuple[LiveGoldSpan, ...] = ()


class LiveCaseQualification(Live30CaseQualification):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-case-qualification.v1"] = Field(
        default="legalbot.live-case-qualification.v1", alias="schema"
    )
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    issues: tuple[LiveIssueQualification, ...]

    @property
    def exact_gold_spans(self) -> tuple[LiveGoldSpan, ...]:
        return tuple(span for issue in self.issues for span in issue.exact_gold_spans)

    def issue(self, issue_id: str) -> LiveIssueQualification:
        for item in self.issues:
            if item.issue_id == issue_id:
                return item
        raise KeyError(issue_id)


class LiveSuiteExpertQualification(BaseModel):
    """Sealed expert overlay for one exact registry and candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-expert-qualification.v1"] = Field(
        default="legalbot.live-expert-qualification.v1", alias="schema"
    )
    suite_id: Literal["live-evaluation-60-v1"]
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    as_of_date: date
    purpose: Literal["evaluation_only"]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    approval_status: Literal["expert_approved"]
    approval_role: Literal["legal_expert_owner"]
    approval_reviewer_role: str
    approval_reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    owner_is_primary_reviewer: Literal[True]
    independent_second_review_status: Literal[
        "needs_independent_review", "confirmed", "not_required"
    ]
    independent_second_reviewer_role: str | None = None
    independent_second_reviewer_ref: str | None = Field(
        default=None, pattern=r"^(?:reviewer:[0-9a-f]{64})?$"
    )
    ai_role: Literal["mechanical_accuracy_verifier_only"]
    ai_second_reviewer_forbidden: Literal[True]
    material_disagreement_status: Literal["none", "adjudicated"]
    adjudication_ref: str | None = Field(default=None, pattern=r"^adjudication:[0-9a-f]{64}$")
    case_count: Literal[60]
    cases: tuple[LiveCaseQualification, ...]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("approval_reviewer_role", "independent_second_reviewer_role")
    @classmethod
    def reviewer_role_is_qualified(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value not in CASE_PROPOSITION_REVIEWER_ROLES:
            raise ValueError("Live60 reviewer has an unsupported qualification role")
        return value

    @model_validator(mode="after")
    def qualification_is_complete_and_sealed(self) -> Self:
        expected_ids = tuple(
            [f"live30-q{number:02d}" for number in range(1, 31)]
            + [f"live60-q{number:02d}" for number in range(31, 61)]
        )
        if tuple(case.case_id for case in self.cases) != expected_ids:
            raise ValueError("expert qualification must contain Q1-Q60 in order")
        if reviewer_role_is_forbidden_machine(self.independent_second_reviewer_role):
            raise ValueError("AI cannot be a Live60 reviewer")
        if self.independent_second_review_status == "confirmed":
            if (
                self.independent_second_reviewer_role is None
                or self.independent_second_reviewer_ref is None
            ):
                raise ValueError(
                    "confirmed second-review status requires independent reviewer details"
                )
            if self.approval_reviewer_ref == self.independent_second_reviewer_ref:
                raise ValueError("complete-gold second reviewer must be independent")
            if self.independent_second_reviewer_ref in {
                span.case_currentness_review.reviewer_ref
                for case in self.cases
                for span in case.exact_gold_spans
                if span.case_currentness_review is not None
            }:
                raise ValueError("complete-gold second reviewer authored a bound case review")
        else:
            if (
                self.independent_second_reviewer_role is not None
                or self.independent_second_reviewer_ref is not None
            ):
                raise ValueError(
                    "second reviewer metadata must be empty unless status is confirmed"
                )
        if self.material_disagreement_status == "adjudicated":
            if self.adjudication_ref is None:
                raise ValueError("adjudicated disagreement requires a safe reference")
        elif self.adjudication_ref is not None:
            raise ValueError("adjudication reference requires an adjudicated disagreement")
        if any(
            span.case_currentness_review is not None
            and span.case_currentness_review.later_treatment_reviewed_as_of_date != self.as_of_date
            for case in self.cases
            for span in case.exact_gold_spans
        ):
            raise ValueError("case proposition review date differs from the overlay date")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("expert qualification seal does not match its contents")
        return self

    def case(self, case_id: str) -> LiveCaseQualification:
        for item in self.cases:
            if item.case_id == case_id:
                return item
        raise KeyError(case_id)


def load_suite_expert_qualification(
    path: Path,
    *,
    bundle: LiveEvaluationBundle,
    index_build_id: str,
    as_of_date: date,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
) -> LiveSuiteExpertQualification:
    if not path.is_file():
        raise ValueError("expert qualification manifest is missing")
    qualification = LiveSuiteExpertQualification.model_validate_json(path.read_bytes())
    if qualification.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256:
        raise ValueError("expert qualification is bound to a different registry")
    if qualification.run_plan_sha256 != bundle.manifest.run_plan_sha256:
        raise ValueError("expert qualification is bound to a different run plan")
    if qualification.index_build_id != index_build_id:
        raise ValueError("expert qualification is bound to a different index build")
    if qualification.as_of_date != as_of_date:
        raise ValueError("expert qualification has a different legal as-of date")
    for item, source in zip(qualification.cases, bundle.registry.cases, strict=True):
        if item.case_id != source.case_id:
            raise ValueError("expert qualification case order mismatch")
        if item.question_sha256 != source.question_sha256:
            raise ValueError("expert qualification question digest mismatch")
        if item.record_sha256 != source.record_sha256:
            raise ValueError("expert qualification record digest mismatch")
        expected_issues = tuple(
            f"issue-{number:02d}" for number in range(1, len(source.must_cover_issues) + 1)
        )
        if tuple(issue.issue_id for issue in item.issues) != expected_issues:
            raise ValueError("expert qualification must disposition every issue in order")
    from .live_suite_span_accuracy import verify_overlay_spans_exact_match

    verify_overlay_spans_exact_match(
        qualification,
        catalog_path=catalog_path,
        repair=repair,
    )
    return qualification


def qualification_template_for_suite(
    bundle: LiveEvaluationBundle,
    *,
    index_build_id: str,
    as_of_date: date,
) -> dict[str, Any]:
    """Return a deliberately unsealable, prose-free template."""

    identity = build_owner_reviewer_identity(as_of_date=as_of_date)
    return {
        "schema": GOLD_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "index_build_id": index_build_id,
        "as_of_date": as_of_date.isoformat(),
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "needs_expert_annotation",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": identity["approval_reviewer_role"],
        "approval_reviewer_ref": identity["approval_reviewer_ref"],
        "owner_is_primary_reviewer": True,
        "independent_second_review_status": "not_required",
        "independent_second_reviewer_role": None,
        "independent_second_reviewer_ref": None,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": bundle.registry.case_count,
        "cases": [
            {
                "schema": GOLD_CASE_SCHEMA,
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": "needs_expert_annotation",
                "contrary_authority_status": "needs_expert_annotation",
                "acceptable_source_ids": [],
                "issues": [
                    {
                        "schema": GOLD_ISSUE_SCHEMA,
                        "issue_id": f"issue-{number:02d}",
                        "status": "needs_expert_annotation",
                        "reason_code": None,
                        "exact_gold_spans": [],
                    }
                    for number in range(1, len(case.must_cover_issues) + 1)
                ],
            }
            for case in bundle.registry.cases
        ],
        "seal_sha256": None,
        "instructions": (
            "The owner is the one primary qualified E&W reviewer. "
            "A second human review is optional. AI checks mechanical accuracy of "
            "hashes and locators only and cannot seal gold. "
            "Do not approve nearest-vector candidates as legal gold; bind exact spans, "
            "legal roles, contrary authority and proposition-level currentness."
        ),
    }
