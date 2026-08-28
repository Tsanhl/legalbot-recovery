"""Manifest-driven live evaluation registries and generation run plans.

The sealed Live30 inputs remain owned by :mod:`app.evaluation.live30`.  This
module provides the version-neutral reader used by Live60 and later suites.
It intentionally stores questions only in the immutable registry; normal run
manifests and telemetry contain hashes and safe identifiers only.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, Self
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .live30 import (
    STRUCTURAL_STANDARD_IDS,
    case_record_sha256,
    question_sha256,
)

LEGACY_QUESTION_CASE_SCHEMA = "legalbot.live-evaluation-case.v1"
QUESTION_CASE_SCHEMA = "legalbot.live-evaluation-case.v2"
SUITE_MANIFEST_SCHEMA = "legalbot.live-evaluation-suite-manifest.v2"
RUN_PLAN_SCHEMA = "legalbot.live-evaluation-run-plan.v1"
RUN_PLAN_CASE_SCHEMA = "legalbot.live-evaluation-run-plan-case.v1"

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q(?P<ordinal>[0-9]{2})$")
_LONDON = ZoneInfo("Europe/London")


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def sealed_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return hashlib.sha256(canonical_json(material)).hexdigest()


class LiveQuestionCase(BaseModel):
    """One immutable owner-supplied question, without expert legal gold."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-case.v1", "legalbot.live-evaluation-case.v2"] = (
        Field(alias="schema")
    )
    suite_id: str = Field(pattern=r"^live-evaluation-(?:30|60)-v1$")
    suite_version: str = "1.0.0"
    split: str = "development_live"
    purpose: str = "evaluation_only"
    eligible_for_training: bool = False
    training_export_allowed: bool = False
    immutable: bool = True
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    ordinal: int = Field(ge=1, le=60)
    question: str = Field(min_length=20, max_length=50_000)
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_type: Literal["essay", "problem"]
    subject: str = Field(min_length=2, max_length=120)
    jurisdiction: str = "England and Wales"
    as_of_policy: str = "run_date"
    word_target: int = Field(ge=1_000, le=10_000)
    expected_research_route: Literal["sectioned", "full_enquiry"]
    expected_drafting_route: Literal["sectioned"] = "sectioned"
    expected_behaviour: Literal["answer"] = "answer"
    structural_standard_ids: tuple[str, ...]
    must_cover_issues: tuple[str, ...]
    acceptable_source_ids: tuple[str, ...] = ()
    exact_gold_spans: tuple[dict[str, Any], ...] = ()
    known_contrary_authority_ids: tuple[str, ...] = ()
    forbidden_lanes: tuple[str, ...] = ()
    coverage_status: Literal["unqualified"] = "unqualified"

    @field_validator("must_cover_issues")
    @classmethod
    def issues_are_safe_and_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(" ".join(value.split()) for value in values)
        if len(cleaned) < 2:
            raise ValueError("each difficult question needs at least two issues")
        if any(not value or len(value) > 180 or "\n" in value for value in cleaned):
            raise ValueError("must-cover issue is empty, multiline or too long")
        if len({value.casefold() for value in cleaned}) != len(cleaned):
            raise ValueError("must-cover issues are duplicated")
        return cleaned

    @model_validator(mode="after")
    def immutable_question_contract_is_consistent(self) -> Self:
        fixed = {
            "suite_version": "1.0.0",
            "split": "development_live",
            "purpose": "evaluation_only",
            "eligible_for_training": False,
            "training_export_allowed": False,
            "immutable": True,
            "jurisdiction": "England and Wales",
            "as_of_policy": "run_date",
            "expected_drafting_route": "sectioned",
            "expected_behaviour": "answer",
            "coverage_status": "unqualified",
        }
        for key, expected in fixed.items():
            if getattr(self, key) != expected:
                raise ValueError(f"{key} conflicts with the live evaluation contract")
        match = _CASE_ID.fullmatch(self.case_id)
        if match is None or int(match.group("ordinal")) != self.ordinal:
            raise ValueError("case_id and ordinal disagree")
        expected_prefix = "live30" if self.ordinal <= 30 else "live60"
        expected_suite = "live-evaluation-30-v1" if self.ordinal <= 30 else "live-evaluation-60-v1"
        if not self.case_id.startswith(expected_prefix) or self.suite_id != expected_suite:
            raise ValueError("case lineage does not match its immutable ordinal")
        expected_schema = (
            LEGACY_QUESTION_CASE_SCHEMA if self.ordinal <= 30 else QUESTION_CASE_SCHEMA
        )
        if self.schema_name != expected_schema:
            raise ValueError("case schema does not match its immutable lineage")
        if self.question_sha256 != question_sha256(self.question):
            raise ValueError("question digest does not match the exact question")
        if tuple(self.structural_standard_ids) != STRUCTURAL_STANDARD_IDS:
            raise ValueError("structural standards do not match the frozen order")
        if any(
            (
                self.acceptable_source_ids,
                self.exact_gold_spans,
                self.known_contrary_authority_ids,
                self.forbidden_lanes,
            )
        ):
            raise ValueError("question registry must not pretend to contain expert gold")
        expected_record_hash = case_record_sha256(self.model_dump(mode="json", by_alias=True))
        if self.record_sha256 != expected_record_hash:
            raise ValueError("record digest does not cover the immutable question")
        return self


@dataclass(frozen=True, slots=True)
class LiveQuestionRegistry:
    cases: tuple[LiveQuestionCase, ...]
    file_sha256: str
    canonical_sha256: str

    @property
    def case_count(self) -> int:
        return len(self.cases)

    @property
    def total_word_target(self) -> int:
        return sum(case.word_target for case in self.cases)

    def case(self, case_id: str) -> LiveQuestionCase:
        for item in self.cases:
            if item.case_id == case_id:
                return item
        raise KeyError(case_id)


class LiveSuiteLineage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    legacy_suite_id: Literal["live-evaluation-30-v1"]
    legacy_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    legacy_registry_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    preserved_case_ids: tuple[str, ...]
    new_question_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted_no_go_memo_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    supersedes_only: tuple[
        Literal[
            "live30_only_scope",
            "stability_repeat_strategy",
            "single_master_review_document",
        ],
        ...,
    ]


class LiveSuiteManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-suite-manifest.v2"] = Field(
        default="legalbot.live-evaluation-suite-manifest.v2", alias="schema"
    )
    suite_id: Literal["live-evaluation-60-v1"]
    suite_version: Literal["1.0.0"]
    split: Literal["development_live"]
    purpose: Literal["evaluation_only"]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    immutable: Literal[True]
    accepted_baseline_status: Literal["no_go"]
    owner_promotion_required: Literal[True]
    live_authorization_required: Literal[True]
    expert_reviewers_required: Literal[1]
    expert_annotation_required_before_scoring: Literal[True]
    case_count: Literal[60]
    total_word_target: Literal[215000]
    task_type_counts: dict[Literal["problem", "essay"], int]
    word_target_counts: dict[str, int]
    case_ids: tuple[str, ...]
    registry_path: str
    registry_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    question_hashes: dict[str, str]
    record_hashes: dict[str, str]
    run_plan_path: str
    run_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lineage: LiveSuiteLineage
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("registry_path", "run_plan_path")
    @classmethod
    def paths_are_safe_and_relative(cls, value: str) -> str:
        if not _SAFE_RELATIVE_PATH.fullmatch(value) or value.startswith("/") or ".." in value:
            raise ValueError("suite artifact path must be a safe relative path")
        return value

    @model_validator(mode="after")
    def manifest_is_self_consistent(self) -> Self:
        if self.task_type_counts != {"problem": 39, "essay": 21}:
            raise ValueError("Live60 task-type distribution is incorrect")
        if self.word_target_counts != {
            "1000": 11,
            "2000": 11,
            "3000": 11,
            "4000": 10,
            "5000": 9,
            "6000": 2,
            "7000": 1,
            "8000": 2,
            "9000": 1,
            "10000": 2,
        }:
            raise ValueError("Live60 word-target distribution is incorrect")
        if len(self.case_ids) != 60 or len(set(self.case_ids)) != 60:
            raise ValueError("Live60 manifest must contain 60 unique case IDs")
        if set(self.question_hashes) != set(self.case_ids):
            raise ValueError("Live60 question hashes do not cover every case")
        if set(self.record_hashes) != set(self.case_ids):
            raise ValueError("Live60 record hashes do not cover every case")
        if any(not _SHA256.fullmatch(value) for value in self.question_hashes.values()):
            raise ValueError("Live60 question hash is invalid")
        if any(not _SHA256.fullmatch(value) for value in self.record_hashes.values()):
            raise ValueError("Live60 record hash is invalid")
        if self.lineage.preserved_case_ids != self.case_ids[:30]:
            raise ValueError("Live30 lineage does not match the first 30 cases")
        if self.lineage.supersedes_only != (
            "live30_only_scope",
            "stability_repeat_strategy",
            "single_master_review_document",
        ):
            raise ValueError("Live60 supersession scope is not exact")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("suite manifest seal does not match its contents")
        return self


class LiveRunPlanCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-run-plan-case.v1"] = Field(
        default="legalbot.live-evaluation-run-plan-case.v1", alias="schema"
    )
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    disposition: Literal["generate_once", "coverage_only_not_selected"]
    pass_count: int = Field(ge=0, le=1)
    expected_research_route: Literal["sectioned", "full_enquiry"]

    @model_validator(mode="after")
    def pass_count_matches_disposition(self) -> Self:
        expected = 1 if self.disposition == "generate_once" else 0
        if self.pass_count != expected:
            raise ValueError("run-plan pass count disagrees with disposition")
        return self


class LiveGenerationRunPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-run-plan.v1"] = Field(
        default="legalbot.live-evaluation-run-plan.v1", alias="schema"
    )
    run_plan_id: Literal["live60-single-pass-30-v1"]
    suite_id: Literal["live-evaluation-60-v1"]
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    purpose: Literal["evaluation_only"]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    local_only_first_run: Literal[True]
    online_research_allowed: Literal[False]
    model_generation_concurrency: Literal[1]
    as_of_policy: Literal["run_admission_europe_london"]
    legal_date_timezone: Literal["Europe/London"]
    problem_structure_id: Literal["live60-problem-v1"]
    essay_structure_id: Literal["live60-essay-v1"]
    unsupported_issue_disposition: Literal["limited_or_held"]
    nonselected_disposition: Literal["coverage_only_not_selected"]
    cross_border_limit_case_ids: tuple[str, ...]
    stability_repeats: Literal[0]
    generation_case_count: Literal[30]
    generation_total_word_target: Literal[114000]
    generation_task_type_counts: dict[Literal["problem", "essay"], int]
    generation_route_counts: dict[Literal["sectioned", "full_enquiry"], int]
    cases: tuple[LiveRunPlanCase, ...]
    annexes: dict[Literal["A", "B", "C"], tuple[str, ...]]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def plan_is_self_consistent(self) -> Self:
        if len(self.cases) != 60 or len({case.case_id for case in self.cases}) != 60:
            raise ValueError("Live60 run plan must disposition every case exactly once")
        generated = tuple(
            case.case_id for case in self.cases if case.disposition == "generate_once"
        )
        if len(generated) != self.generation_case_count:
            raise ValueError("Live60 selected generation count is incorrect")
        if self.generation_task_type_counts != {"problem": 19, "essay": 11}:
            raise ValueError("Live60 generation task-type mix is incorrect")
        if self.generation_route_counts != {"sectioned": 15, "full_enquiry": 15}:
            raise ValueError("Live60 generation route mix is incorrect")
        if self.cross_border_limit_case_ids != (
            "live60-q43",
            "live60-q55",
            "live60-q60",
        ):
            raise ValueError("cross-border foreign-law limits are incomplete")
        ordered_annexes = (self.annexes["A"], self.annexes["B"], self.annexes["C"])
        annex_ids = tuple(case_id for annex in ordered_annexes for case_id in annex)
        if any(len(annex) != 10 for annex in ordered_annexes):
            raise ValueError("each Live60 annex must contain exactly 10 answers")
        if annex_ids != generated:
            raise ValueError("annex order must exactly partition selected generations")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("run-plan seal does not match its contents")
        return self


@dataclass(frozen=True, slots=True)
class LiveEvaluationBundle:
    root: Path
    registry: LiveQuestionRegistry
    manifest: LiveSuiteManifest
    run_plan: LiveGenerationRunPlan


def load_question_registry(path: Path) -> LiveQuestionRegistry:
    if not path.is_file():
        raise ValueError(f"live question registry is missing: {path}")
    raw_bytes = path.read_bytes()
    try:
        lines = raw_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("live question registry must be UTF-8") from exc
    cases: list[LiveQuestionCase] = []
    canonical_lines: list[bytes] = []
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            case = LiveQuestionCase.model_validate(json.loads(raw))
        except Exception as exc:
            raise ValueError(f"invalid live question at line {line_number}") from exc
        cases.append(case)
        canonical_lines.append(canonical_json(case.model_dump(mode="json", by_alias=True)))
    if not cases:
        raise ValueError("live question registry contains no cases")
    ids = [case.case_id for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("live question registry contains duplicated IDs")
    hashes = [case.question_sha256 for case in cases]
    if len(hashes) != len(set(hashes)):
        raise ValueError("live question registry contains duplicated questions")
    return LiveQuestionRegistry(
        cases=tuple(cases),
        file_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        canonical_sha256=hashlib.sha256(b"".join(canonical_lines)).hexdigest(),
    )


def _safe_child(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError("suite artifact escaped its bundle root")
    return candidate


def load_live_evaluation_bundle(
    root: Path,
    *,
    legacy_live30_registry: Path | None = None,
    legacy_live30_manifest: Path | None = None,
    new_question_source: Path | None = None,
    accepted_no_go_memo: Path | None = None,
) -> LiveEvaluationBundle:
    """Load and cross-check the complete manifest-driven Live60 contract."""

    root = root.resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("Live60 manifest is missing")
    manifest = LiveSuiteManifest.model_validate_json(manifest_path.read_bytes())
    registry_path = _safe_child(root, manifest.registry_path)
    run_plan_path = _safe_child(root, manifest.run_plan_path)
    registry = load_question_registry(registry_path)
    run_plan = LiveGenerationRunPlan.model_validate_json(run_plan_path.read_bytes())

    if registry.file_sha256 != manifest.registry_file_sha256:
        raise ValueError("registry file digest does not match the manifest")
    if registry.canonical_sha256 != manifest.registry_canonical_sha256:
        raise ValueError("registry canonical digest does not match the manifest")
    if hashlib.sha256(run_plan_path.read_bytes()).hexdigest() != manifest.run_plan_sha256:
        raise ValueError("run-plan file digest does not match the manifest")
    if run_plan.suite_registry_canonical_sha256 != registry.canonical_sha256:
        raise ValueError("run plan is bound to another question registry")

    case_ids = tuple(case.case_id for case in registry.cases)
    expected_ids = tuple(
        [f"live30-q{number:02d}" for number in range(1, 31)]
        + [f"live60-q{number:02d}" for number in range(31, 61)]
    )
    if case_ids != expected_ids:
        raise ValueError("Live60 registry must contain immutable Q1-Q60 order")
    if case_ids != manifest.case_ids:
        raise ValueError("registry order differs from the suite manifest")
    if case_ids != tuple(case.case_id for case in run_plan.cases):
        raise ValueError("run plan does not disposition the registry in exact order")
    if registry.case_count != manifest.case_count:
        raise ValueError("registry count differs from the suite manifest")
    if registry.total_word_target != manifest.total_word_target:
        raise ValueError("registry total differs from the suite manifest")
    if Counter(case.task_type for case in registry.cases) != Counter(manifest.task_type_counts):
        raise ValueError("registry task-type distribution differs from the manifest")
    if Counter(str(case.word_target) for case in registry.cases) != Counter(
        manifest.word_target_counts
    ):
        raise ValueError("registry word distribution differs from the manifest")
    if {case.case_id: case.question_sha256 for case in registry.cases} != manifest.question_hashes:
        raise ValueError("registry question hashes differ from the manifest")
    if {case.case_id: case.record_sha256 for case in registry.cases} != manifest.record_hashes:
        raise ValueError("registry record hashes differ from the manifest")

    selected = [
        registry.case(item.case_id)
        for item in run_plan.cases
        if item.disposition == "generate_once"
    ]
    if sum(case.word_target for case in selected) != run_plan.generation_total_word_target:
        raise ValueError("selected answer word total differs from the run plan")
    if Counter(case.task_type for case in selected) != Counter(
        run_plan.generation_task_type_counts
    ):
        raise ValueError("selected answer task mix differs from the run plan")
    if Counter(case.expected_research_route for case in selected) != Counter(
        run_plan.generation_route_counts
    ):
        raise ValueError("selected answer route mix differs from the run plan")
    for item in run_plan.cases:
        if item.expected_research_route != registry.case(item.case_id).expected_research_route:
            raise ValueError("run plan route differs from the immutable question")

    if legacy_live30_registry is None:
        candidate = root.parent / "live-evaluation-30-v1" / "cases.jsonl"
        legacy_live30_registry = candidate
    if not legacy_live30_registry.is_file():
        raise ValueError("sealed legacy Live30 registry is required for lineage verification")
    legacy_bytes = legacy_live30_registry.read_bytes()
    if hashlib.sha256(legacy_bytes).hexdigest() != manifest.lineage.legacy_registry_file_sha256:
        raise ValueError("legacy Live30 registry digest differs from the lineage seal")
    legacy = load_question_registry(legacy_live30_registry)
    if registry.cases[:30] != legacy.cases:
        raise ValueError("Live60 changed an immutable Live30 question record")
    if legacy_live30_manifest is None:
        candidate = root.parent / "live-evaluation-30-v1" / "manifest.json"
        legacy_live30_manifest = candidate
    if not legacy_live30_manifest.is_file():
        raise ValueError("sealed legacy Live30 manifest is required for lineage verification")
    if (
        hashlib.sha256(legacy_live30_manifest.read_bytes()).hexdigest()
        != manifest.lineage.legacy_manifest_sha256
    ):
        raise ValueError("legacy Live30 manifest digest differs from the lineage seal")
    source_digest_record = root / "source-questions-31-60.sha256"
    memo_digest_record = root / "accepted-no-go-memo.sha256"
    if not source_digest_record.is_file() or (
        source_digest_record.read_text(encoding="ascii").strip()
        != manifest.lineage.new_question_source_sha256
    ):
        raise ValueError("Q31-Q60 source digest record is missing or inconsistent")
    if not memo_digest_record.is_file() or (
        memo_digest_record.read_text(encoding="ascii").strip()
        != manifest.lineage.accepted_no_go_memo_sha256
    ):
        raise ValueError("accepted NO-GO memo digest record is missing or inconsistent")
    if new_question_source is not None and (
        hashlib.sha256(new_question_source.read_bytes()).hexdigest()
        != manifest.lineage.new_question_source_sha256
    ):
        raise ValueError("Q31-Q60 source digest differs from the lineage seal")
    if accepted_no_go_memo is not None and (
        hashlib.sha256(accepted_no_go_memo.read_bytes()).hexdigest()
        != manifest.lineage.accepted_no_go_memo_sha256
    ):
        raise ValueError("accepted NO-GO memo digest differs from the lineage seal")

    return LiveEvaluationBundle(
        root=root,
        registry=registry,
        manifest=manifest,
        run_plan=run_plan,
    )


def admission_as_of_date(now: datetime | None = None) -> date:
    """Return the E&W legal date at run admission using Europe/London."""

    instant = now or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("run-admission time must be timezone-aware")
    return instant.astimezone(_LONDON).date()


def disposition_for_case(
    run_plan: LiveGenerationRunPlan, case_id: str
) -> Literal["generate_once", "coverage_only_not_selected"]:
    if not _SAFE_ID.fullmatch(case_id):
        raise ValueError("invalid case ID")
    for item in run_plan.cases:
        if item.case_id == case_id:
            return item.disposition
    raise KeyError(case_id)
