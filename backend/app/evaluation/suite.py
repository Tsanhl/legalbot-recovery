"""Strict source-of-truth schema for legal retrieval and answer evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

EXPECTED_SPLITS = {"development": 144, "promotion": 48, "adversarial_holdout": 48}
EXPECTED_CATEGORIES = {
    "core_single_authority": 80,
    "paraphrase_terminology_typo": 40,
    "multi_authority_conflict_time": 30,
    "knowledge_gap_clarification_refusal": 25,
    "privacy_injection_lane_jurisdiction": 25,
    "ocr_upload_boundary": 20,
    "long_form": 20,
}
ALLOWED_STATUSES = {"needs_expert_annotation", "expert_annotated", "sealed"}


class GoldSpan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_version_id: str
    chunk_id: str
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    exact_locator: str
    character_start: int = Field(ge=0)
    character_end: int = Field(gt=0)
    relevance_grade: int = Field(ge=1, le=3)
    supported_issue_ids: list[str]

    @model_validator(mode="after")
    def offsets_are_ordered(self) -> GoldSpan:
        if self.character_end <= self.character_start:
            raise ValueError("gold-span character offsets are not ordered")
        if not self.supported_issue_ids:
            raise ValueError("gold span must support at least one issue")
        return self


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    suite_version: str
    split: str
    category: str
    status: str
    synthetic: bool
    query: str = Field(min_length=3, max_length=30_000)
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    paraphrase_group: str | None = None
    task_type: str
    subject: str
    jurisdiction: str
    as_of_date: date
    word_target: int = Field(ge=100, le=10_000)
    expected_research_route: str
    expected_drafting_route: str
    expected_behaviour: str
    acceptable_source_ids: list[str]
    exact_gold_spans: list[GoldSpan]
    forbidden_lanes: list[str]
    forbidden_source_ids: list[str]
    must_cover_issues: list[str]
    known_contrary_authority_ids: list[str]
    rubric: dict[str, Any]
    privacy_flags: list[str]
    failure_mode_labels: list[str]
    corpus_manifest_sha256: str | None = None
    index_build_id: str | None = None
    # Optional A2 intentional-abstention behavioral gold. Existing cases omit these.
    preferred_behavior: str | None = None
    allowed_behaviors: list[str] | None = None
    reason_code: str | None = None
    required_response_elements: list[str] | None = None
    forbidden_response_elements: list[str] | None = None
    safe_remainder_present: bool | None = None
    privacy_subtype: str | None = None
    a2_membership: str | None = None
    a2_template_family: str | None = None
    # Optional A2 repeat-stability canary fields (development knowledge families).
    repeat_group_id: str | None = None
    canonical_case_id: str | None = None
    evaluation_role: str | None = None
    independent_score_weight: int | None = None

    @model_validator(mode="after")
    def validate_case_state(self) -> EvaluationCase:
        expected = hashlib.sha256(self.query.encode("utf-8")).hexdigest()
        if self.query_sha256 != expected:
            raise ValueError("query_sha256 does not match the exact query")
        if self.split not in EXPECTED_SPLITS:
            raise ValueError("invalid evaluation split")
        if self.category not in EXPECTED_CATEGORIES:
            raise ValueError("invalid evaluation category")
        if self.status not in ALLOWED_STATUSES:
            raise ValueError("invalid annotation status")
        if self.expected_behaviour == "answer" and not self.must_cover_issues:
            raise ValueError("answer cases need explicit must-cover issues")
        if self.status in {"expert_annotated", "sealed"}:
            if not self.corpus_manifest_sha256 or not re.fullmatch(
                r"[0-9a-f]{64}", self.corpus_manifest_sha256
            ):
                raise ValueError("annotated cases must bind a corpus manifest")
            if self.expected_behaviour == "answer" and (
                not self.acceptable_source_ids or not self.exact_gold_spans
            ):
                raise ValueError("annotated answer cases need sources and exact gold spans")
        if self.split != "development" and self.status == "expert_annotated":
            raise ValueError("promotion and holdout cases must be sealed before use")
        return self


@dataclass(frozen=True, slots=True)
class EvaluationSuite:
    version: str
    cases: tuple[EvaluationCase, ...]
    sha256: str


def load_evaluation_suite(path: Path, *, require_complete: bool = True) -> EvaluationSuite:
    if not path.is_file():
        raise ValueError(f"evaluation suite is missing: {path}")
    cases: list[EvaluationCase] = []
    case_ids: set[str] = set()
    canonical_lines: list[str] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
            case = EvaluationCase.model_validate(value)
        except Exception as exc:
            raise ValueError(f"invalid evaluation case at line {line_number}") from exc
        if case.case_id in case_ids:
            raise ValueError(f"duplicated evaluation case: {case.case_id}")
        case_ids.add(case.case_id)
        cases.append(case)
        canonical_lines.append(json.dumps(case.model_dump(mode="json"), sort_keys=True))
    if not cases:
        raise ValueError("evaluation suite contains no cases")
    versions = {case.suite_version for case in cases}
    if len(versions) != 1:
        raise ValueError("evaluation suite mixes versions")
    groups: dict[str, set[str]] = {}
    for case in cases:
        if case.paraphrase_group:
            groups.setdefault(case.paraphrase_group, set()).add(case.split)
    leaked = sorted(key for key, splits in groups.items() if len(splits) > 1)
    if leaked:
        raise ValueError("paraphrase families cross split boundaries")
    if require_complete:
        split_counts = Counter(case.split for case in cases)
        category_counts = Counter(case.category for case in cases)
        if dict(split_counts) != EXPECTED_SPLITS:
            raise ValueError(f"evaluation split counts must equal {EXPECTED_SPLITS}")
        if dict(category_counts) != EXPECTED_CATEGORIES:
            raise ValueError(f"evaluation category counts must equal {EXPECTED_CATEGORIES}")
        if any(case.status == "needs_expert_annotation" for case in cases):
            raise ValueError("promotion suite still contains unannotated cases")
    canonical = ("\n".join(canonical_lines) + "\n").encode("utf-8")
    return EvaluationSuite(
        version=versions.pop(),
        cases=tuple(cases),
        sha256=hashlib.sha256(canonical).hexdigest(),
    )
