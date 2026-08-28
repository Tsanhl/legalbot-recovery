"""Verified knowledge-gap attestation. A reason string is not gold."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .live_suite import sealed_sha256

GAP_VERIFICATION_SCHEMA = "legalbot.gap-verification.v2"


class GapVerificationV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.gap-verification.v2"] = Field(
        default="legalbot.gap-verification.v2", alias="schema"
    )
    issue_id: str
    defined_source_set_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    source_set_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    search_review_method: str = Field(pattern=r"^[a-z0-9._:-]{3,80}$")
    coverage_result: Literal[
        "reviewed_none_in_defined_source_set",
        "defined_source_set_exhausted",
        "held_statute_keep_as_gap",
        "later_treatment_unresolved",
    ]
    as_of_date: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    reason_code: str = Field(pattern=r"^[a-z0-9._:-]{3,80}$")
    review_actor: Literal["human", "ai", "hybrid", "deterministic"]
    positive_span_count: Literal[0] = 0
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def gap_has_no_positive_span(self) -> Self:
        if self.positive_span_count != 0:
            raise ValueError("verified knowledge_gap cannot have a positive span")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != sealed_sha256(dumped):
            raise ValueError("gap verification seal does not match its contents")
        return self


def seal_gap_verification(material: Mapping[str, Any]) -> GapVerificationV2:
    payload = dict(material)
    payload.setdefault("schema", GAP_VERIFICATION_SCHEMA)
    payload.setdefault("positive_span_count", 0)
    payload["seal_sha256"] = sealed_sha256(payload)
    return GapVerificationV2.model_validate(payload)
