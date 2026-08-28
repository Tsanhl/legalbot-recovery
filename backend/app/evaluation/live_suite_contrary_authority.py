"""Sealed contrary-authority review for a defined source set.

``reviewed_none_in_defined_source_set`` is not a claim that English law has
no contrary authority. Critical or disputed propositions still need
independent second review. Code never self-authors this record.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

CONTRARY_REVIEW_SCHEMA = "legalbot.contrary-authority-review.v1"
ALLOWED_STATUSES = frozenset(
    {
        "unsigned",
        "reviewed_none_in_defined_source_set",
        "reviewed_and_bound",
        "needs_independent_second_review",
    }
)


class ContraryAuthorityReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.contrary-authority-review.v1"] = Field(alias="schema")
    suite_id: Literal["live-evaluation-60-v1"]
    as_of_date: str
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    index_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    owner_authored: Literal[True]
    ai_self_authored: Literal[False]
    status: Literal[
        "reviewed_none_in_defined_source_set",
        "reviewed_and_bound",
        "needs_independent_second_review",
    ]
    defined_source_set_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    defined_source_set_review_method: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    defined_source_set_reviewed_as_of_date: str
    reviewer_scope: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    means_english_law_has_no_contrary_authority: Literal[False]
    critical_or_disputed_requires_independent_second_review: Literal[True]
    bound_contrary_span_count: int = Field(ge=0)
    independent_second_review_status: Literal[
        "not_required", "needs_independent_review", "confirmed"
    ]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def review_is_honest(self) -> ContraryAuthorityReview:
        if self.status == "reviewed_and_bound" and self.bound_contrary_span_count < 1:
            raise ValueError("reviewed_and_bound requires at least one contrary span")
        if (
            self.status == "reviewed_none_in_defined_source_set"
            and self.bound_contrary_span_count != 0
        ):
            raise ValueError("reviewed_none_in_defined_source_set cannot bind contrary spans")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("contrary-authority review seal does not match its contents")
        return self


def contrary_review_template(*, as_of_date: str) -> dict[str, Any]:
    payload = {
        "schema": CONTRARY_REVIEW_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date,
        "suite_registry_canonical_sha256": None,
        "run_plan_sha256": None,
        "index_build_id": None,
        "run_id": None,
        "owner_authored": False,
        "ai_self_authored": False,
        "status": "unsigned",
        "defined_source_set_id": "live60-defined-source-set-unsigned",
        "defined_source_set_review_method": None,
        "defined_source_set_reviewed_as_of_date": None,
        "reviewer_scope": None,
        "means_english_law_has_no_contrary_authority": False,
        "critical_or_disputed_requires_independent_second_review": True,
        "bound_contrary_span_count": 0,
        "independent_second_review_status": "needs_independent_review",
        "seal_sha256": None,
        "unsigned": True,
        "note": (
            "reviewed_none_in_defined_source_set is not a claim that English law "
            "has no contrary authority"
        ),
    }
    assert_safe_evaluation_payload(payload)
    return payload


def load_contrary_authority_review(path: Path) -> ContraryAuthorityReview:
    if not path.is_file():
        raise ValueError("contrary-authority review is missing")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("ai_self_authored") is True:
        raise ValueError("code must not self-author contrary-authority reviews")
    if payload.get("means_english_law_has_no_contrary_authority") is True:
        raise ValueError("reviewed_none cannot mean English law has no contrary authority")
    return ContraryAuthorityReview.model_validate(payload)
