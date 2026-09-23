"""Separate-pass review of the complete rendered answer and material omissions."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..contracts import canonical_json_bytes
from ..prompt_templates import (
    FULL_ANSWER_REVIEWER_TEMPLATE_NAME,
    FULL_ANSWER_REVIEWER_TEMPLATE_SHA256,
    prompt_template_text,
)
from ..types import EvidenceSpan, StructuredDraft
from .draft_identity import source_draft_sha256

FULL_ANSWER_REVIEW_SCHEMA = "legalbot.ai-full-answer-review.v1"
FULL_ANSWER_REVIEWER_ROLE = "ai_full_answer_reviewer"
FULL_ANSWER_REVIEWER_EXECUTION_MODE = "separate_verification_pass_same_model_adapter"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SAFE_REASON = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


class JSONReviewModel(Protocol):
    async def invoke_json(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, Any],
        mode: str,
    ) -> tuple[str, dict[str, Any]]: ...


class OmissionReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issue_id: str
    status: Literal["none", "material", "uncertain"]
    reason_code: str

    @field_validator("issue_id")
    @classmethod
    def issue_id_is_safe(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("full-answer review issue ID is invalid")
        return value

    @field_validator("reason_code")
    @classmethod
    def reason_is_safe(cls, value: str) -> str:
        if _SAFE_REASON.fullmatch(value) is None:
            raise ValueError("full-answer review reason code is invalid")
        return value


class FullAnswerReviewerOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reviewed_claim_ids: tuple[str, ...]
    complete_rendered_answer_reviewed: Literal[True]
    all_material_omissions_checked: Literal[True]
    omissions: tuple[OmissionReview, ...]
    verdict: Literal["pass", "hold"]

    @field_validator("reviewed_claim_ids")
    @classmethod
    def claim_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SAFE_ID.fullmatch(value) is None for value in values):
            raise ValueError("full-answer review claim ID is invalid")
        if len(values) != len(set(values)):
            raise ValueError("full-answer review claim IDs are duplicated")
        return values

    @model_validator(mode="after")
    def verdict_matches_omissions(self) -> FullAnswerReviewerOutput:
        expected = "pass" if all(item.status == "none" for item in self.omissions) else "hold"
        if self.verdict != expected:
            raise ValueError("full-answer review verdict differs from omission findings")
        return self


class FullAnswerReviewResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.ai-full-answer-review.v1"] = Field(
        alias="schema", default=FULL_ANSWER_REVIEW_SCHEMA
    )
    review_id: str = Field(pattern=r"^full-answer-review-[0-9a-f]{24}$")
    reviewer_role: Literal["ai_full_answer_reviewer"] = FULL_ANSWER_REVIEWER_ROLE
    reviewer_execution_mode: Literal["separate_verification_pass_same_model_adapter"] = (
        FULL_ANSWER_REVIEWER_EXECUTION_MODE
    )
    model_independent: Literal[False] = False
    professional_legal_sign_off: Literal[False] = False
    can_authorize_release: Literal[False] = False
    invocation_id: str
    model_id: str
    model_version: str
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rendered_answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fact_inputs_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issue_ids: tuple[str, ...]
    reviewed_claim_ids: tuple[str, ...]
    complete_rendered_answer_reviewed: Literal[True]
    all_material_omissions_checked: Literal[True]
    omissions: tuple[OmissionReview, ...]
    verdict: Literal["pass", "hold"]
    passed: bool
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def result_is_closed(self) -> FullAnswerReviewResult:
        if any(_SAFE_ID.fullmatch(value) is None for value in self.issue_ids):
            raise ValueError("full-answer result issue ID is invalid")
        if len(self.issue_ids) != len(set(self.issue_ids)):
            raise ValueError("full-answer result issue IDs are duplicated")
        if tuple(item.issue_id for item in self.omissions) != self.issue_ids:
            raise ValueError("full-answer result does not cover issues in frozen order")
        expected_pass = self.verdict == "pass" and all(
            item.status == "none" for item in self.omissions
        )
        if self.passed != expected_pass:
            raise ValueError("full-answer pass differs from its findings")
        value = self.model_dump(mode="json", by_alias=True)
        observed = value.pop("seal_sha256")
        if observed != hashlib.sha256(canonical_json_bytes(value)).hexdigest():
            raise ValueError("full-answer review seal is invalid")
        return self


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _evidence_rows(evidence_by_id: Mapping[str, EvidenceSpan]) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": span.id,
            "source_version_id": span.source_version_id,
            "chunk_id": span.chunk_id,
            "content_sha256": span.content_sha256,
            "text": span.text,
            "locator": span.locator,
            "jurisdiction": span.jurisdiction,
            "currentness_status": span.currentness_status,
        }
        for _identifier, span in sorted(evidence_by_id.items())
    ]


async def invoke_full_answer_reviewer(
    *,
    model: JSONReviewModel,
    question: str,
    draft: StructuredDraft,
    rendered_answer: str,
    evidence_by_id: Mapping[str, EvidenceSpan],
    fact_inputs: Sequence[Mapping[str, Any]],
    issue_ids: Sequence[str],
    model_id: str,
    model_version: str,
) -> FullAnswerReviewResult:
    """Run and seal one complete-answer coverage review."""

    frozen_issue_ids = tuple(dict.fromkeys(str(item) for item in issue_ids))
    if not frozen_issue_ids or any(_SAFE_ID.fullmatch(item) is None for item in frozen_issue_ids):
        raise ValueError("full-answer review requires safe frozen issue IDs")
    claims = [
        {
            "claim_id": claim.id,
            "text": claim.text,
            "evidence_ids": list(claim.evidence_ids),
        }
        for section in draft.sections
        for claim in section.claims
        if claim.material
    ]
    claim_ids = tuple(item["claim_id"] for item in claims)
    if not claim_ids:
        raise ValueError("a purported answer requires at least one material claim")
    allowed_evidence = set(evidence_by_id)
    if any(not set(item["evidence_ids"]) <= allowed_evidence for item in claims):
        raise ValueError("full-answer claim references evidence outside the frozen pack")
    facts = [dict(item) for item in fact_inputs]
    evidence = _evidence_rows(evidence_by_id)
    payload = {
        "schema": "legalbot.ai-full-answer-review-input.v1",
        "question": question,
        "question_sha256": hashlib.sha256(question.encode("utf-8")).hexdigest(),
        "rendered_answer": rendered_answer,
        "rendered_answer_sha256": hashlib.sha256(
            rendered_answer.encode("utf-8")
        ).hexdigest(),
        "source_draft_sha256": source_draft_sha256(draft),
        "issue_ids": list(frozen_issue_ids),
        "material_claims": claims,
        "candidate_visible_facts": facts,
        "frozen_evidence": evidence,
    }
    invocation_id, raw = await model.invoke_json(
        system_prompt=prompt_template_text(FULL_ANSWER_REVIEWER_TEMPLATE_NAME),
        user_payload=payload,
        mode="full_answer_review",
    )
    output = FullAnswerReviewerOutput.model_validate(raw)
    if output.reviewed_claim_ids != claim_ids:
        raise ValueError("full-answer reviewer did not cover claims in frozen order")
    if tuple(item.issue_id for item in output.omissions) != frozen_issue_ids:
        raise ValueError("full-answer reviewer did not cover issues in frozen order")
    material: dict[str, Any] = {
        "schema": FULL_ANSWER_REVIEW_SCHEMA,
        "review_id": "full-answer-review-"
        + _hash(
            {
                "invocation_id": invocation_id,
                "rendered_answer_sha256": payload["rendered_answer_sha256"],
                "issues": list(frozen_issue_ids),
            }
        )[:24],
        "reviewer_role": FULL_ANSWER_REVIEWER_ROLE,
        "reviewer_execution_mode": FULL_ANSWER_REVIEWER_EXECUTION_MODE,
        "model_independent": False,
        "professional_legal_sign_off": False,
        "can_authorize_release": False,
        "invocation_id": invocation_id,
        "model_id": model_id,
        "model_version": model_version,
        "prompt_sha256": FULL_ANSWER_REVIEWER_TEMPLATE_SHA256,
        "question_sha256": payload["question_sha256"],
        "rendered_answer_sha256": payload["rendered_answer_sha256"],
        "source_draft_sha256": payload["source_draft_sha256"],
        "fact_inputs_sha256": _hash(facts),
        "evidence_bundle_sha256": _hash(evidence),
        "issue_ids": list(frozen_issue_ids),
        **output.model_dump(mode="json"),
        "passed": output.verdict == "pass",
    }
    material["seal_sha256"] = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    return FullAnswerReviewResult.model_validate(material)


__all__ = [
    "FULL_ANSWER_REVIEW_SCHEMA",
    "FullAnswerReviewResult",
    "invoke_full_answer_reviewer",
]
