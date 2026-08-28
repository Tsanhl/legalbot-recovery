"""Immutable live-30 registry and privacy-safe local E2E run storage.

This module intentionally has no dependency on the serving database or API.
The committed registry is evaluation input, while every runtime copy of a
question, answer, review, issue detail or knowledge-gap detail is encrypted.
Normal JSONL logs contain identifiers, state and timings only.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..crypto import LocalCipher
from ..privacy import contains_absolute_private_path

SUITE_ID = "live-evaluation-30-v1"
SUITE_VERSION = "1.0.0"
SUITE_SPLIT = "development_live"
SUITE_PURPOSE = "evaluation_only"
CASE_SCHEMA = "legalbot.live-evaluation-case.v1"
SUITE_MANIFEST_SCHEMA = "legalbot.live-evaluation-suite-manifest.v1"
RUN_MANIFEST_SCHEMA = "legalbot.e2e-run-manifest.v1"
RUN_EVENT_SCHEMA = "legalbot.e2e-run-event.v1"
CASE_INDEX_SCHEMA = "legalbot.e2e-case-index.v1"

EXPECTED_CASE_IDS = tuple(f"live30-q{number:02d}" for number in range(1, 31))
EXPECTED_WORD_TARGET_COUNTS: dict[int, int] = {
    1_000: 5,
    2_000: 5,
    3_000: 5,
    4_000: 5,
    5_000: 5,
    6_000: 1,
    7_000: 1,
    8_000: 1,
    9_000: 1,
    10_000: 1,
}
EXPECTED_TOTAL_WORD_TARGET = 115_000
STRATIFIED_SAMPLE_IDS = (
    "live30-q01",
    "live30-q03",
    "live30-q07",
    "live30-q09",
    "live30-q13",
    "live30-q17",
    "live30-q25",
    "live30-q27",
    "live30-q30",
)

SECTIONED_CASE_IDS = frozenset(
    {
        "live30-q01",
        "live30-q02",
        "live30-q03",
        "live30-q04",
        "live30-q05",
        "live30-q06",
        "live30-q07",
        "live30-q08",
        "live30-q09",
        "live30-q10",
        "live30-q12",
        "live30-q14",
        "live30-q17",
        "live30-q19",
        "live30-q22",
        "live30-q24",
    }
)
FULL_ENQUIRY_CASE_IDS = frozenset(EXPECTED_CASE_IDS) - SECTIONED_CASE_IDS

# These IDs bind structure and evaluation criteria. They do not assert that an
# automated score is calibrated to a human 70+ result.
STRUCTURAL_STANDARD_IDS = (
    "structure.issue_spotting",
    "structure.rule_accuracy",
    "structure.application_or_critical_analysis",
    "structure.authority_and_counterargument",
    "structure.completeness_and_uncertainty",
    "structure.structure_and_conclusion",
    "structure.claim_evidence_binding",
    "structure.oscola_accuracy",
    "structure.requested_word_target",
)

_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CASE_JSON_NAMES = frozenset(
    {
        "coverage.json",
        "retrieval.json",
        "evidence-map.json",
        "metrics.json",
        "quality.json",
    }
)
_SAFE_RUN_JSON_NAMES = frozenset(
    {
        "aggregate-metrics.json",
        "coverage-summary.json",
        "expert-qualification.json",
        "review-export.json",
        "run-privacy-report.json",
        "slo-evaluation.json",
    }
)
_FORBIDDEN_SAFE_ARTIFACT_KEYS = frozenset(
    {
        "question",
        "raw_question",
        "answer",
        "answer_text",
        "source_text",
        "prompt",
        "system_prompt",
        "filename",
        "path",
        "absolute_path",
        "human_note",
    }
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def question_sha256(question: str) -> str:
    return hashlib.sha256(question.encode("utf-8")).hexdigest()


def case_record_sha256(value: Mapping[str, Any]) -> str:
    """Hash every immutable case field except the self-referential record hash."""

    material = dict(value)
    material.pop("record_sha256", None)
    return hashlib.sha256(_canonical_json(material)).hexdigest()


class LiveEvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=CASE_SCHEMA, alias="schema")
    suite_id: str = SUITE_ID
    suite_version: str = SUITE_VERSION
    split: str = SUITE_SPLIT
    purpose: str = SUITE_PURPOSE
    eligible_for_training: bool = False
    training_export_allowed: bool = False
    immutable: bool = True
    case_id: str = Field(pattern=r"^live30-q(?:0[1-9]|[12][0-9]|30)$")
    ordinal: int = Field(ge=1, le=30)
    question: str = Field(min_length=20, max_length=50_000)
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_type: str
    subject: str = Field(min_length=2, max_length=120)
    jurisdiction: str = "England and Wales"
    as_of_policy: str = "run_date"
    word_target: int = Field(ge=1_000, le=10_000)
    expected_research_route: str
    expected_drafting_route: str
    expected_behaviour: str = "answer"
    structural_standard_ids: tuple[str, ...]
    must_cover_issues: tuple[str, ...]
    acceptable_source_ids: tuple[str, ...] = ()
    exact_gold_spans: tuple[dict[str, Any], ...] = ()
    known_contrary_authority_ids: tuple[str, ...] = ()
    forbidden_lanes: tuple[str, ...] = ()
    coverage_status: str = "unqualified"

    @field_validator("task_type")
    @classmethod
    def task_type_is_supported(cls, value: str) -> str:
        if value not in {"essay", "problem", "general"}:
            raise ValueError("unsupported task type")
        return value

    @field_validator("expected_research_route", "expected_drafting_route")
    @classmethod
    def route_is_supported(cls, value: str) -> str:
        if value not in {"direct", "sectioned", "full_enquiry"}:
            raise ValueError("unsupported route")
        return value

    @field_validator("must_cover_issues")
    @classmethod
    def issues_are_conservative_and_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) < 2:
            raise ValueError("each difficult question needs at least two must-cover issues")
        cleaned = tuple(value.strip() for value in values)
        if any(not value or len(value) > 180 or "\n" in value for value in cleaned):
            raise ValueError("must-cover issue is empty, multiline or too long")
        if len({value.casefold() for value in cleaned}) != len(cleaned):
            raise ValueError("must-cover issues are duplicated")
        return cleaned

    @model_validator(mode="after")
    def immutable_contract_is_consistent(self) -> Self:
        constants = {
            "schema_name": CASE_SCHEMA,
            "suite_id": SUITE_ID,
            "suite_version": SUITE_VERSION,
            "split": SUITE_SPLIT,
            "purpose": SUITE_PURPOSE,
            "eligible_for_training": False,
            "training_export_allowed": False,
            "immutable": True,
            "jurisdiction": "England and Wales",
            "as_of_policy": "run_date",
            "expected_behaviour": "answer",
            "coverage_status": "unqualified",
        }
        for key, expected in constants.items():
            if getattr(self, key) != expected:
                raise ValueError(f"{key} does not match the immutable live-30 contract")
        if self.case_id != f"live30-q{self.ordinal:02d}":
            raise ValueError("case_id and ordinal disagree")
        if self.question_sha256 != question_sha256(self.question):
            raise ValueError("question_sha256 does not match the exact supplied question")
        if self.word_target not in EXPECTED_WORD_TARGET_COUNTS:
            raise ValueError("word target is outside the frozen live-30 strata")
        expected_route = "sectioned" if self.case_id in SECTIONED_CASE_IDS else "full_enquiry"
        if self.expected_research_route != expected_route:
            raise ValueError("research route does not match the frozen per-case route matrix")
        if self.expected_drafting_route != "sectioned":
            raise ValueError("every difficult live-30 answer uses sectioned drafting")
        if tuple(self.structural_standard_ids) != STRUCTURAL_STANDARD_IDS:
            raise ValueError("structural standard IDs do not match the frozen order")
        if any(
            (
                self.acceptable_source_ids,
                self.exact_gold_spans,
                self.known_contrary_authority_ids,
                self.forbidden_lanes,
            )
        ):
            raise ValueError("unqualified live inputs must not pretend to contain source gold")
        expected_record_hash = case_record_sha256(self.model_dump(mode="json", by_alias=True))
        if self.record_sha256 != expected_record_hash:
            raise ValueError("record_sha256 does not cover the immutable record")
        return self


@dataclass(frozen=True, slots=True)
class LiveEvaluationSuite:
    cases: tuple[LiveEvaluationCase, ...]
    file_sha256: str
    canonical_sha256: str

    @property
    def case_count(self) -> int:
        return len(self.cases)

    @property
    def total_word_target(self) -> int:
        return sum(case.word_target for case in self.cases)

    def manifest(self) -> dict[str, Any]:
        return {
            "schema": SUITE_MANIFEST_SCHEMA,
            "suite_id": SUITE_ID,
            "suite_version": SUITE_VERSION,
            "split": SUITE_SPLIT,
            "purpose": SUITE_PURPOSE,
            "eligible_for_training": False,
            "training_export_allowed": False,
            "immutable": True,
            "case_count": self.case_count,
            "total_word_target": self.total_word_target,
            "word_target_counts": {
                str(target): count
                for target, count in sorted(
                    Counter(case.word_target for case in self.cases).items()
                )
            },
            "case_ids": [case.case_id for case in self.cases],
            "stratified_sample_ids": list(STRATIFIED_SAMPLE_IDS),
            "file_sha256": self.file_sha256,
            "canonical_sha256": self.canonical_sha256,
            "question_hashes": {case.case_id: case.question_sha256 for case in self.cases},
            "record_hashes": {case.case_id: case.record_sha256 for case in self.cases},
        }


def load_live30_suite(path: Path, *, require_complete: bool = True) -> LiveEvaluationSuite:
    if not path.is_file():
        raise ValueError(f"live-30 registry is missing: {path}")
    raw_bytes = path.read_bytes()
    try:
        lines = raw_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("live-30 registry must be UTF-8") from exc

    cases: list[LiveEvaluationCase] = []
    canonical_lines: list[bytes] = []
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            case = LiveEvaluationCase.model_validate(json.loads(raw))
        except Exception as exc:
            raise ValueError(f"invalid live-30 record at line {line_number}") from exc
        cases.append(case)
        canonical_lines.append(_canonical_json(case.model_dump(mode="json", by_alias=True)))

    if not cases:
        raise ValueError("live-30 registry contains no cases")
    ids = [case.case_id for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("live-30 registry contains duplicated case IDs")
    question_hashes = [case.question_sha256 for case in cases]
    if len(question_hashes) != len(set(question_hashes)):
        raise ValueError("live-30 registry contains duplicated questions")

    suite = LiveEvaluationSuite(
        cases=tuple(cases),
        file_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        canonical_sha256=hashlib.sha256(b"".join(canonical_lines)).hexdigest(),
    )
    if require_complete:
        if tuple(ids) != EXPECTED_CASE_IDS:
            raise ValueError("live-30 registry must contain Q1-Q30 in immutable order")
        counts = Counter(case.word_target for case in cases)
        if dict(counts) != EXPECTED_WORD_TARGET_COUNTS:
            raise ValueError(f"word-target distribution must equal {EXPECTED_WORD_TARGET_COUNTS}")
        if suite.total_word_target != EXPECTED_TOTAL_WORD_TARGET:
            raise ValueError(f"total word target must equal {EXPECTED_TOTAL_WORD_TARGET}")
        if not set(STRATIFIED_SAMPLE_IDS).issubset(ids):
            raise ValueError("stratified sample IDs are missing from the live-30 registry")
    return suite


class RunEventType(StrEnum):
    RUN_CREATED = "run_created"
    CASE_REGISTERED = "case_registered"
    CASE_STARTED = "case_started"
    STAGE_COMPLETED = "stage_completed"
    ARTIFACT_STORED = "artifact_stored"
    CASE_COMPLETED = "case_completed"
    CASE_FAILED = "case_failed"
    ISSUE_LOGGED = "issue_logged"
    KNOWLEDGE_GAP_LOGGED = "knowledge_gap_logged"
    RUN_COMPLETED = "run_completed"


class RunStage(StrEnum):
    RUN = "run"
    INTAKE = "intake"
    ROUTING = "routing"
    RETRIEVAL = "retrieval"
    EVIDENCE_FREEZE = "evidence_freeze"
    DRAFTING = "drafting"
    VERIFICATION = "verification"
    REPAIR = "repair"
    ASSEMBLY = "assembly"
    RELEASE = "release"
    HUMAN_REVIEW = "human_review"


class RunStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    VERIFIED_LIMITED = "verified_limited"
    HELD_FOR_REVIEW = "held_for_review"
    SYSTEM_ERROR = "system_error"
    CANCELLED = "cancelled"


class SensitiveArtifactKind(StrEnum):
    ANSWER = "answer"
    HUMAN_REVIEW = "human_review"
    ISSUE_DETAIL = "issue_detail"
    KNOWLEDGE_GAP_DETAIL = "knowledge_gap_detail"


class E2ERunEvent(BaseModel):
    """Allowlisted normal-log record: identifiers, status and timings only."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=RUN_EVENT_SCHEMA, alias="schema")
    event_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    timestamp: datetime
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str | None = Field(default=None, pattern=r"^live30-q(?:0[1-9]|[12][0-9]|30)$")
    event_type: RunEventType
    stage: RunStage
    status: RunStatus
    duration_ms: int | None = Field(default=None, ge=0)
    attempt: int | None = Field(default=None, ge=1)
    artifact_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    error_code: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class E2ECaseIndexEntry(BaseModel):
    """Append-only safe case index; it deliberately contains no legal prose."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=CASE_INDEX_SCHEMA, alias="schema")
    entry_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    timestamp: datetime
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str = Field(pattern=r"^live30-q(?:0[1-9]|[12][0-9]|30)$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: RunStatus
    artifact_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")


class RunProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    git_sha: str = Field(pattern=r"^[0-9a-f]{7,64}$")
    git_dirty: bool
    model_version: str | None = None
    index_build_id: str | None = None
    prompt_version: str | None = None
    router_version: str | None = None
    classifier_version: str | None = None
    policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    assessment_rules_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "model_version",
        "index_build_id",
        "prompt_version",
        "router_version",
        "classifier_version",
    )
    @classmethod
    def versions_are_log_safe(cls, value: str | None) -> str | None:
        if value is not None and not _SAFE_VERSION.fullmatch(value):
            raise ValueError("version identity is not safe for a plaintext manifest")
        return value


class E2ERunManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=RUN_MANIFEST_SCHEMA, alias="schema")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    suite_id: str = SUITE_ID
    suite_version: str = SUITE_VERSION
    suite_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    split: str = SUITE_SPLIT
    purpose: str = SUITE_PURPOSE
    eligible_for_training: bool = False
    training_export_allowed: bool = False
    local_only: bool = True
    case_count: int = 30
    total_word_target: int = EXPECTED_TOTAL_WORD_TARGET
    created_at: datetime
    as_of_date: date
    initial_status: RunStatus = RunStatus.CREATED
    encrypted_unreleased_retention_days: int = Field(default=30, ge=1, le=365)
    provenance: RunProvenance

    @model_validator(mode="after")
    def run_contract_is_fixed(self) -> Self:
        if (
            self.suite_id != SUITE_ID
            or self.suite_version != SUITE_VERSION
            or self.split != SUITE_SPLIT
            or self.purpose != SUITE_PURPOSE
            or self.eligible_for_training
            or self.training_export_allowed
            or not self.local_only
            or self.case_count != 30
            or self.total_word_target != EXPECTED_TOTAL_WORD_TARGET
        ):
            raise ValueError("run manifest conflicts with the live-30 evaluation contract")
        return self


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _exclusive_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _append_jsonl(path: Path, value: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(descriptor, "ab") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(_canonical_json(value.model_dump(mode="json", by_alias=True)))
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        path.chmod(0o600)


def assert_safe_evaluation_payload(value: Any, *, key: str | None = None) -> None:
    """Reject prose/private fields from plaintext evaluation telemetry."""

    if key is not None and key.casefold() in _FORBIDDEN_SAFE_ARTIFACT_KEYS:
        raise ValueError(f"forbidden plaintext evaluation field: {key}")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            assert_safe_evaluation_payload(child, key=str(child_key))
    elif isinstance(value, list | tuple):
        for child in value:
            assert_safe_evaluation_payload(child, key=key)
    elif isinstance(value, str):
        lowered = value.casefold()
        if (
            "\n" in value
            or "/users/" in lowered
            or "\\users\\" in lowered
            or lowered.startswith("file:")
            or lowered.startswith("sk-")
            or "bearer " in lowered
            or "-----begin" in lowered
        ):
            raise ValueError("plaintext evaluation telemetry contains sensitive text")


def _write_safe_json(path: Path, value: Mapping[str, Any]) -> None:
    assert_safe_evaluation_payload(value)
    _exclusive_write(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )


def _append_safe_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    assert_safe_evaluation_payload(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        with os.fdopen(descriptor, "ab") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(_canonical_json(dict(value)))
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        path.chmod(0o600)


def write_suite_manifest(path: Path, suite: LiveEvaluationSuite) -> Path:
    """Create, but never replace, the safe immutable suite manifest."""

    _exclusive_write(path, json.dumps(suite.manifest(), indent=2, sort_keys=True).encode() + b"\n")
    return path


class Live30RunStore:
    """Filesystem-only run registry using the project's LocalCipher primitive."""

    def __init__(self, project_root: Path, cipher: LocalCipher) -> None:
        self.project_root = project_root.resolve()
        self.cipher = cipher
        self.runs_root = self.project_root / "data" / "evaluations" / "e2e" / "runs"
        self.logs_root = self.project_root / "logs"
        if not self.runs_root.resolve().is_relative_to(self.project_root):
            raise ValueError("E2E runs root escapes the project through a symlink")
        if not self.logs_root.resolve().is_relative_to(self.project_root):
            raise ValueError("E2E logs root escapes the project through a symlink")
        self.events_log = self.logs_root / "e2e-run-events.jsonl"
        self.case_index_log = self.logs_root / "e2e-case-index.jsonl"

    @staticmethod
    def _validate_id(value: str, *, label: str) -> str:
        if not _SAFE_ID.fullmatch(value):
            raise ValueError(f"invalid {label}")
        return value

    def _run_path(self, run_id: str) -> Path:
        self._validate_id(run_id, label="run_id")
        path = (self.runs_root / run_id).resolve()
        if not path.is_relative_to(self.runs_root.resolve()):
            raise ValueError("run path escaped the E2E run root")
        return path

    def _case_path(self, run_id: str, case_id: str) -> Path:
        if case_id not in EXPECTED_CASE_IDS:
            raise ValueError("invalid live-30 case ID")
        path = (self._run_path(run_id) / "cases" / case_id).resolve()
        if not path.is_relative_to(self._run_path(run_id)):
            raise ValueError("case path escaped the E2E run root")
        return path

    def create_run(
        self,
        *,
        run_id: str,
        suite: LiveEvaluationSuite,
        provenance: RunProvenance,
        as_of_date: date | None = None,
    ) -> E2ERunManifest:
        if suite.case_count != 30 or suite.total_word_target != EXPECTED_TOTAL_WORD_TARGET:
            raise ValueError("only a complete verified live-30 suite may create a run")
        destination = self._run_path(run_id)
        _private_directory(self.runs_root)
        if destination.exists():
            raise FileExistsError(f"E2E run already exists: {run_id}")

        created_at = datetime.now(UTC)
        manifest = E2ERunManifest(
            run_id=run_id,
            suite_file_sha256=suite.file_sha256,
            suite_canonical_sha256=suite.canonical_sha256,
            created_at=created_at,
            as_of_date=as_of_date or created_at.date(),
            provenance=provenance,
        )
        temporary = self.runs_root / f".{run_id}.{uuid.uuid4().hex}.tmp"
        try:
            _private_directory(temporary)
            _private_directory(temporary / "cases")
            _exclusive_write(
                temporary / "manifest.json",
                json.dumps(
                    manifest.model_dump(mode="json", by_alias=True),
                    indent=2,
                    sort_keys=True,
                ).encode()
                + b"\n",
            )
            for case in suite.cases:
                case_root = temporary / "cases" / case.case_id
                _private_directory(case_root)
                _private_directory(case_root / "artifacts")
                private_record = {
                    "schema": "legalbot.e2e-encrypted-question.v1",
                    "run_id": run_id,
                    "as_of_date": manifest.as_of_date.isoformat(),
                    "case": case.model_dump(mode="json", by_alias=True),
                }
                encrypted = self.cipher.encrypt_text(
                    json.dumps(private_record, ensure_ascii=False, sort_keys=True)
                )
                _exclusive_write(case_root / "question.enc", encrypted)
                safe_case = {
                    "schema": "legalbot.e2e-safe-case.v1",
                    "case_id": case.case_id,
                    "question_sha256": case.question_sha256,
                    "record_sha256": case.record_sha256,
                    "word_target": case.word_target,
                    "expected_research_route": case.expected_research_route,
                    "expected_drafting_route": case.expected_drafting_route,
                    "as_of_date": manifest.as_of_date.isoformat(),
                    "purpose": SUITE_PURPOSE,
                    "eligible_for_training": False,
                    "training_export_allowed": False,
                }
                _exclusive_write(
                    case_root / "case.json",
                    json.dumps(safe_case, indent=2, sort_keys=True).encode() + b"\n",
                )
            os.rename(temporary, destination)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

        self.record_event(
            E2ERunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=created_at,
                run_id=run_id,
                event_type=RunEventType.RUN_CREATED,
                stage=RunStage.RUN,
                status=RunStatus.CREATED,
            )
        )
        for case in suite.cases:
            _append_jsonl(
                self.case_index_log,
                E2ECaseIndexEntry(
                    entry_id=uuid.uuid4().hex,
                    timestamp=created_at,
                    run_id=run_id,
                    case_id=case.case_id,
                    question_sha256=case.question_sha256,
                    status=RunStatus.CREATED,
                ),
            )
            self.record_event(
                E2ERunEvent(
                    event_id=uuid.uuid4().hex,
                    timestamp=created_at,
                    run_id=run_id,
                    case_id=case.case_id,
                    event_type=RunEventType.CASE_REGISTERED,
                    stage=RunStage.INTAKE,
                    status=RunStatus.CREATED,
                )
            )
        return manifest

    def record_event(self, event: E2ERunEvent) -> None:
        if not self._run_path(event.run_id).is_dir():
            raise FileNotFoundError(f"unknown E2E run: {event.run_id}")
        _append_jsonl(self.events_log, event)

    def record_case_status(
        self,
        *,
        run_id: str,
        case_id: str,
        status: RunStatus,
        artifact_id: str | None = None,
    ) -> None:
        """Append a terminal/queue state without exposing question or answer prose."""

        _, case = self.load_encrypted_question(run_id=run_id, case_id=case_id)
        _append_jsonl(
            self.case_index_log,
            E2ECaseIndexEntry(
                entry_id=uuid.uuid4().hex,
                timestamp=datetime.now(UTC),
                run_id=run_id,
                case_id=case_id,
                question_sha256=case.question_sha256,
                status=status,
                artifact_id=artifact_id,
            ),
        )

    def load_run_manifest(self, run_id: str) -> E2ERunManifest:
        path = self._run_path(run_id) / "manifest.json"
        if not path.is_file():
            raise FileNotFoundError(f"unknown E2E run: {run_id}")
        manifest = E2ERunManifest.model_validate_json(path.read_bytes())
        if manifest.run_id != run_id:
            raise ValueError("E2E run manifest identity check failed")
        return manifest

    def store_safe_case_json(
        self,
        *,
        run_id: str,
        case_id: str,
        filename: str,
        value: Mapping[str, Any],
    ) -> Path:
        """Create one immutable, prose-free case telemetry artifact."""

        if filename not in _SAFE_CASE_JSON_NAMES:
            raise ValueError("safe case artifact name is not allowlisted")
        destination = self._case_path(run_id, case_id) / filename
        _write_safe_json(destination, value)
        return destination

    def store_safe_case_pass_json(
        self,
        *,
        run_id: str,
        case_id: str,
        pass_number: int,
        value: Mapping[str, Any],
    ) -> Path:
        """Create one immutable outcome for a specific controlled pass."""

        if pass_number not in {1, 2, 3}:
            raise ValueError("live-30 pass number must be 1, 2 or 3")
        destination = self._case_path(run_id, case_id) / "outcomes" / f"pass-{pass_number}.json"
        if not destination.resolve().is_relative_to(self._case_path(run_id, case_id)):
            raise ValueError("pass outcome path escaped the case root")
        _write_safe_json(destination, value)
        return destination

    def load_safe_case_pass_json(
        self, *, run_id: str, case_id: str, pass_number: int
    ) -> dict[str, Any] | None:
        if pass_number not in {1, 2, 3}:
            raise ValueError("live-30 pass number must be 1, 2 or 3")
        path = self._case_path(run_id, case_id) / "outcomes" / f"pass-{pass_number}.json"
        if not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("safe pass outcome is not a JSON object")
        assert_safe_evaluation_payload(value)
        return value

    def store_safe_run_json(self, *, run_id: str, filename: str, value: Mapping[str, Any]) -> Path:
        """Create one immutable, prose-free run telemetry artifact."""

        if filename not in _SAFE_RUN_JSON_NAMES:
            raise ValueError("safe run artifact name is not allowlisted")
        destination = self._run_path(run_id) / filename
        _write_safe_json(destination, value)
        return destination

    def append_safe_run_index(
        self,
        *,
        run_id: str,
        index_name: str,
        value: Mapping[str, Any],
    ) -> Path:
        """Append an issue or gap record containing IDs/hashes only."""

        if index_name not in {"issues", "knowledge-gaps"}:
            raise ValueError("safe run index is not allowlisted")
        destination = self._run_path(run_id) / index_name / "index.jsonl"
        _append_safe_jsonl(destination, value)
        return destination

    def load_encrypted_question(
        self, *, run_id: str, case_id: str
    ) -> tuple[date, LiveEvaluationCase]:
        path = self._case_path(run_id, case_id) / "question.enc"
        value = json.loads(self.cipher.decrypt_text(path.read_bytes()))
        if value.get("schema") != "legalbot.e2e-encrypted-question.v1":
            raise ValueError("encrypted question schema is invalid")
        if value.get("run_id") != run_id:
            raise ValueError("encrypted question run identity check failed")
        return date.fromisoformat(str(value["as_of_date"])), LiveEvaluationCase.model_validate(
            value["case"]
        )

    def store_sensitive_artifact(
        self,
        *,
        run_id: str,
        case_id: str,
        kind: SensitiveArtifactKind,
        artifact_id: str,
        content: str,
    ) -> Path:
        self._validate_id(artifact_id, label="artifact_id")
        if not content:
            raise ValueError("sensitive artifact is empty")
        case_root = self._case_path(run_id, case_id)
        if not case_root.is_dir():
            raise FileNotFoundError(f"case is not registered in run: {case_id}")
        artifact_root = case_root / "artifacts" / kind.value
        _private_directory(artifact_root)
        destination = artifact_root / f"{artifact_id}.enc"
        envelope = {
            "schema": "legalbot.e2e-sensitive-artifact.v1",
            "run_id": run_id,
            "case_id": case_id,
            "artifact_id": artifact_id,
            "kind": kind.value,
            "content": content,
        }
        _exclusive_write(
            destination,
            self.cipher.encrypt_text(json.dumps(envelope, ensure_ascii=False, sort_keys=True)),
        )
        timestamp = datetime.now(UTC)
        _, case = self.load_encrypted_question(run_id=run_id, case_id=case_id)
        _append_jsonl(
            self.case_index_log,
            E2ECaseIndexEntry(
                entry_id=uuid.uuid4().hex,
                timestamp=timestamp,
                run_id=run_id,
                case_id=case_id,
                question_sha256=case.question_sha256,
                status=RunStatus.RUNNING,
                artifact_id=artifact_id,
            ),
        )
        self.record_event(
            E2ERunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=timestamp,
                run_id=run_id,
                case_id=case_id,
                event_type=RunEventType.ARTIFACT_STORED,
                stage=(
                    RunStage.HUMAN_REVIEW
                    if kind is SensitiveArtifactKind.HUMAN_REVIEW
                    else RunStage.VERIFICATION
                ),
                status=RunStatus.RUNNING,
                artifact_id=artifact_id,
            )
        )
        return destination

    def store_released_answer(
        self,
        *,
        run_id: str,
        case_id: str,
        pass_number: int,
        content: str,
    ) -> Path:
        """Persist only a gate-passed released answer as owner-local Markdown."""

        if pass_number not in {1, 2, 3}:
            raise ValueError("live-30 pass number must be 1, 2 or 3")
        if not content.strip() or contains_absolute_private_path(content):
            raise ValueError("released answer is empty or contains prohibited path metadata")
        case_root = self._case_path(run_id, case_id)
        destination = (
            case_root / "released-answer.md"
            if pass_number == 1
            else case_root / "released-answers" / f"pass-{pass_number}.md"
        )
        _exclusive_write(destination, content.encode("utf-8"))
        return destination

    def load_released_answer(self, *, run_id: str, case_id: str, pass_number: int) -> str:
        if pass_number not in {1, 2, 3}:
            raise ValueError("live-30 pass number must be 1, 2 or 3")
        case_root = self._case_path(run_id, case_id)
        path = (
            case_root / "released-answer.md"
            if pass_number == 1
            else case_root / "released-answers" / f"pass-{pass_number}.md"
        )
        return path.read_text(encoding="utf-8")

    def load_sensitive_artifact(
        self,
        *,
        run_id: str,
        case_id: str,
        kind: SensitiveArtifactKind,
        artifact_id: str,
    ) -> str:
        self._validate_id(artifact_id, label="artifact_id")
        path = self._case_path(run_id, case_id) / "artifacts" / kind.value / f"{artifact_id}.enc"
        value = json.loads(self.cipher.decrypt_text(path.read_bytes()))
        expected = (run_id, case_id, kind.value, artifact_id)
        observed = (
            value.get("run_id"),
            value.get("case_id"),
            value.get("kind"),
            value.get("artifact_id"),
        )
        if value.get("schema") != "legalbot.e2e-sensitive-artifact.v1" or observed != expected:
            raise ValueError("encrypted artifact identity check failed")
        return str(value["content"])


def safe_summary(suite: LiveEvaluationSuite) -> dict[str, Any]:
    """Return CLI-safe registry metadata without question or issue prose."""

    manifest = suite.manifest()
    manifest.pop("question_hashes", None)
    manifest.pop("record_hashes", None)
    return manifest


def safe_json_lines(path: Path) -> Sequence[dict[str, Any]]:
    """Read a generated safe log for diagnostics/tests, rejecting non-objects."""

    values: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError(f"safe log line {line_number} is not an object")
        values.append(value)
    return values
