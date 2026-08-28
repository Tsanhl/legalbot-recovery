"""Owner-approved, prose-free expert qualification for the live-30 suite.

The immutable question registry deliberately contains no source gold.  This
separate overlay is the only supported way to bind expert-reviewed authority
and locator identities to those development questions.  It contains no legal
prose and is sealed by a canonical SHA-256; creating the overlay remains a
human legal-review task.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..legal_roles import MATERIAL_CASE_ROLES, REVIEWED_GOLD_LEGAL_ROLES
from ..types import CASE_PROPOSITION_REVIEWER_ROLES, CasePropositionReview
from .live30 import EXPECTED_CASE_IDS, LiveEvaluationSuite

GOLD_SCHEMA = "legalbot.live30-expert-qualification.v2"
GOLD_CASE_SCHEMA = "legalbot.live30-case-qualification.v2"
GOLD_ISSUE_SCHEMA = "legalbot.live30-issue-qualification.v1"
GOLD_SPAN_SCHEMA = "legalbot.live30-gold-span.v2"

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_LOCATOR = re.compile(r"^[^\n\r]{1,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def qualification_sha256(value: dict[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return hashlib.sha256(_canonical_bytes(material)).hexdigest()


class Live30GoldSpan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=GOLD_SPAN_SCHEMA, alias="schema")
    gold_span_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    issue_id: str = Field(pattern=r"^issue-[0-9]{2}$")
    # ``stable_source_id`` is the application's immutable, privacy-safe
    # ``documents.source_identity_id``.  It is deliberately distinct from a
    # human legal identity such as ``neutral-citation:[2002] UKHL 12``.  The
    # latter contains spaces/brackets and must never be overloaded into an
    # internal-ID field or compared to one by accident.
    stable_source_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    legal_authority_id: str | None = None
    source_version_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    chunk_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    legal_locator: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_type: Literal["case", "legislation", "official_secondary", "scholarship"]
    legal_role: str
    proposition_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    case_currentness_review: CasePropositionReview | None = None
    relevance_grade: int = Field(ge=1, le=3)
    contrary_or_limiting: bool = False

    @field_validator("legal_locator")
    @classmethod
    def locator_is_safe(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not _SAFE_LOCATOR.fullmatch(cleaned):
            raise ValueError("gold locator is empty, multiline or too long")
        lowered = cleaned.casefold()
        if "/users/" in lowered or "\\users\\" in lowered or lowered.startswith("file:"):
            raise ValueError("gold locator contains prohibited path metadata")
        return cleaned

    @field_validator("legal_authority_id")
    @classmethod
    def legal_authority_identity_is_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.split())
        if not _SAFE_LOCATOR.fullmatch(cleaned):
            raise ValueError("legal authority identity is empty, multiline or too long")
        lowered = cleaned.casefold()
        if "/users/" in lowered or "\\users\\" in lowered or lowered.startswith("file:"):
            raise ValueError("legal authority identity contains prohibited path metadata")
        return cleaned

    @field_validator("legal_role")
    @classmethod
    def legal_role_is_reviewed(cls, value: str) -> str:
        if value not in REVIEWED_GOLD_LEGAL_ROLES:
            raise ValueError("gold span has an unsupported legal role")
        return value

    @model_validator(mode="after")
    def case_proposition_review_is_exact(self) -> Self:
        is_present_law_case_proposition = (
            self.source_type == "case" and self.legal_role in MATERIAL_CASE_ROLES
        )
        if is_present_law_case_proposition:
            review = self.case_currentness_review
            if self.proposition_hash is None or review is None:
                raise ValueError("present-law case gold requires an exact proposition review")
            if not review.qualifies_for_present_law:
                raise ValueError("case gold later-treatment review is not release-qualified")
            if (
                review.source_version_id != self.source_version_id
                or review.chunk_id != self.chunk_id
                or review.legal_locator != self.legal_locator
                or review.exact_span_sha256 != self.content_sha256
                or review.proposition_hash != self.proposition_hash
                or review.legal_role != self.legal_role
            ):
                raise ValueError("case gold and proposition review do not bind the same exact span")
        elif self.case_currentness_review is not None:
            raise ValueError("case proposition review is allowed only for present-law case gold")
        elif self.source_type == "case" and self.proposition_hash is not None:
            raise ValueError(
                "non-proposition case gold cannot carry a present-law proposition hash"
            )
        return self


class Live30IssueQualification(BaseModel):
    """Expert disposition for one immutable must-cover issue.

    ``qualified`` means the issue has complete reviewed support for the live
    evaluation. ``limited`` means the recorded spans are valid but knowingly
    incomplete. ``knowledge_gap`` is an explicit decision that no qualifying
    gold span is presently available; it must never be filled with a nearest
    vector merely to make ranking metrics numeric.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=GOLD_ISSUE_SCHEMA, alias="schema")
    issue_id: str = Field(pattern=r"^issue-[0-9]{2}$")
    status: Literal["qualified", "limited", "knowledge_gap"]
    reason_code: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    exact_gold_spans: tuple[Live30GoldSpan, ...] = ()

    @model_validator(mode="after")
    def disposition_matches_gold(self) -> Self:
        if any(span.issue_id != self.issue_id for span in self.exact_gold_spans):
            raise ValueError("issue qualification contains a span for another issue")
        span_ids = [span.gold_span_id for span in self.exact_gold_spans]
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("gold span IDs are duplicated within an issue")
        span_keys = [
            (
                span.source_version_id,
                span.chunk_id,
                span.legal_locator.casefold(),
                span.content_sha256,
                span.legal_role,
                span.proposition_hash,
                (
                    span.case_currentness_review.seal_sha256
                    if span.case_currentness_review is not None
                    else None
                ),
                span.contrary_or_limiting,
            )
            for span in self.exact_gold_spans
        ]
        if len(span_keys) != len(set(span_keys)):
            raise ValueError("gold span identity is duplicated within an issue")
        positive_count = sum(not span.contrary_or_limiting for span in self.exact_gold_spans)
        if self.status == "qualified":
            if not positive_count or self.reason_code is not None:
                raise ValueError("qualified issue requires positive gold and no limitation reason")
        elif self.status == "limited":
            if not positive_count or self.reason_code is None:
                raise ValueError(
                    "limited issue requires positive gold and a safe limitation reason"
                )
        elif self.exact_gold_spans or self.reason_code is None:
            raise ValueError(
                "knowledge-gap issue requires a reason and cannot contain fabricated gold"
            )
        return self


class Live30CaseQualification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=GOLD_CASE_SCHEMA, alias="schema")
    case_id: str = Field(pattern=r"^live30-q(?:0[1-9]|[12][0-9]|30)$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["qualified", "limited", "knowledge_gap"]
    contrary_authority_status: Literal["reviewed_none", "reviewed_and_bound"]
    acceptable_source_ids: tuple[str, ...] = ()
    issues: tuple[Live30IssueQualification, ...]

    @field_validator("acceptable_source_ids")
    @classmethod
    def source_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_ID.fullmatch(value) for value in values):
            raise ValueError("acceptable source IDs must be safe IDs")
        if len(values) != len(set(values)):
            raise ValueError("acceptable source IDs are duplicated")
        return values

    @model_validator(mode="after")
    def spans_are_complete(self) -> Self:
        if not self.issues:
            raise ValueError("case qualification contains no issue dispositions")
        issue_ids = [issue.issue_id for issue in self.issues]
        if len(issue_ids) != len(set(issue_ids)):
            raise ValueError("issue qualification IDs are duplicated")
        spans = self.exact_gold_spans
        span_ids = [span.gold_span_id for span in spans]
        if len(span_ids) != len(set(span_ids)):
            raise ValueError("gold span IDs are duplicated across issues")
        source_ids = set(self.acceptable_source_ids)
        if spans and not source_ids:
            raise ValueError("case with gold spans has no acceptable source identities")
        if any(span.stable_source_id not in source_ids for span in spans):
            raise ValueError("gold span source identity is not acceptable for the case")
        review_authority_ids = {
            authority_id
            for span in spans
            if span.case_currentness_review is not None
            for authority_id in (span.case_currentness_review.contrary_or_limiting_authority_ids)
        }
        if not review_authority_ids.issubset(source_ids):
            raise ValueError(
                "case review limiting-authority identity is not acceptable for the case"
            )
        derived_status: Literal["qualified", "limited", "knowledge_gap"]
        issue_statuses = {issue.status for issue in self.issues}
        if issue_statuses == {"qualified"}:
            derived_status = "qualified"
        elif issue_statuses == {"knowledge_gap"}:
            derived_status = "knowledge_gap"
        else:
            derived_status = "limited"
        if self.status != derived_status:
            raise ValueError("case status disagrees with its issue dispositions")
        contrary_count = sum(span.contrary_or_limiting for span in spans)
        if (self.contrary_authority_status == "reviewed_and_bound") != bool(contrary_count):
            raise ValueError("contrary-authority review status disagrees with bound gold")
        return self

    @property
    def exact_gold_spans(self) -> tuple[Live30GoldSpan, ...]:
        """Flatten reviewed issue gold for source/currentness reconciliation."""

        return tuple(span for issue in self.issues for span in issue.exact_gold_spans)

    def issue(self, issue_id: str) -> Live30IssueQualification:
        for item in self.issues:
            if item.issue_id == issue_id:
                return item
        raise KeyError(issue_id)


class Live30ExpertQualification(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=GOLD_SCHEMA, alias="schema")
    suite_id: str = "live-evaluation-30-v1"
    suite_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    as_of_date: date
    purpose: str = "evaluation_only"
    eligible_for_training: bool = False
    training_export_allowed: bool = False
    approval_status: str = "expert_approved"
    approval_role: str = "legal_expert_owner"
    approval_reviewer_role: str
    approval_reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    independent_second_review_status: Literal["confirmed"]
    independent_second_reviewer_role: str
    independent_second_reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    material_disagreement_status: Literal["none", "adjudicated"]
    adjudication_ref: str | None = Field(default=None, pattern=r"^adjudication:[0-9a-f]{64}$")
    case_count: int = 30
    cases: tuple[Live30CaseQualification, ...]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("approval_reviewer_role", "independent_second_reviewer_role")
    @classmethod
    def reviewer_role_is_qualified(cls, value: str) -> str:
        if value not in CASE_PROPOSITION_REVIEWER_ROLES:
            raise ValueError("Live30 reviewer has an unsupported qualification role")
        return value

    @model_validator(mode="after")
    def qualification_is_complete_and_sealed(self) -> Self:
        if (
            self.suite_id != "live-evaluation-30-v1"
            or self.purpose != "evaluation_only"
            or self.eligible_for_training
            or self.training_export_allowed
            or self.approval_status != "expert_approved"
            or self.approval_role != "legal_expert_owner"
            or self.case_count != 30
        ):
            raise ValueError("expert qualification contract is invalid")
        if tuple(case.case_id for case in self.cases) != EXPECTED_CASE_IDS:
            raise ValueError("expert qualification must contain Q1-Q30 in order")
        if self.approval_reviewer_ref == self.independent_second_reviewer_ref:
            raise ValueError("Live30 complete-gold second reviewer must be independent")
        if self.independent_second_reviewer_ref in {
            span.case_currentness_review.reviewer_ref
            for case in self.cases
            for span in case.exact_gold_spans
            if span.case_currentness_review is not None
        }:
            raise ValueError("Live30 complete-gold second reviewer authored a bound case review")
        if self.material_disagreement_status == "adjudicated":
            if self.adjudication_ref is None:
                raise ValueError("adjudicated Live30 disagreement requires a safe reference")
        elif self.adjudication_ref is not None:
            raise ValueError("Live30 adjudication reference requires an adjudicated disagreement")
        if any(
            span.case_currentness_review is not None
            and span.case_currentness_review.later_treatment_reviewed_as_of_date != self.as_of_date
            for case in self.cases
            for span in case.exact_gold_spans
        ):
            raise ValueError("case proposition review date differs from qualification as-of date")
        material = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != qualification_sha256(material):
            raise ValueError("expert qualification seal does not match its contents")
        return self

    def case(self, case_id: str) -> Live30CaseQualification:
        for item in self.cases:
            if item.case_id == case_id:
                return item
        raise KeyError(case_id)


def load_expert_qualification(
    path: Path,
    *,
    suite: LiveEvaluationSuite,
    index_build_id: str,
    as_of_date: date,
) -> Live30ExpertQualification:
    if not path.is_file():
        raise ValueError("expert qualification manifest is missing")
    qualification = Live30ExpertQualification.model_validate_json(path.read_bytes())
    if qualification.suite_canonical_sha256 != suite.canonical_sha256:
        raise ValueError("expert qualification is bound to a different suite")
    if qualification.index_build_id != index_build_id:
        raise ValueError("expert qualification is bound to a different index build")
    if qualification.as_of_date != as_of_date:
        raise ValueError("expert qualification has a different legal as-of date")
    by_id = {case.case_id: case for case in suite.cases}
    for item in qualification.cases:
        source = by_id[item.case_id]
        if item.question_sha256 != source.question_sha256:
            raise ValueError("expert qualification question digest mismatch")
        if item.record_sha256 != source.record_sha256:
            raise ValueError("expert qualification case digest mismatch")
        expected_issues = tuple(
            f"issue-{number:02d}" for number in range(1, len(source.must_cover_issues) + 1)
        )
        if tuple(issue.issue_id for issue in item.issues) != expected_issues:
            raise ValueError(
                "expert qualification must disposition every must-cover issue in order"
            )
    return qualification


def qualification_template(
    suite: LiveEvaluationSuite, *, index_build_id: str, as_of_date: date
) -> dict[str, Any]:
    """Return a deliberately unsealable, prose-free owner annotation template."""

    return {
        "schema": GOLD_SCHEMA,
        "suite_id": "live-evaluation-30-v1",
        "suite_canonical_sha256": suite.canonical_sha256,
        "index_build_id": index_build_id,
        "as_of_date": as_of_date.isoformat(),
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "needs_expert_annotation",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": None,
        "approval_reviewer_ref": None,
        "independent_second_review_status": "needs_independent_review",
        "independent_second_reviewer_role": None,
        "independent_second_reviewer_ref": None,
        "material_disagreement_status": "needs_adjudication_review",
        "adjudication_ref": None,
        "case_count": 30,
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
            for case in suite.cases
        ],
        "seal_sha256": None,
        "instructions": (
            "Expert review required; do not approve nearest-vector candidates as legal gold. "
            "Present-law case propositions require a sealed exact-span review, qualified "
            "reviewer role/ref, later-treatment status/date, limiting-authority IDs and any "
            "required independent second review."
        ),
    }
