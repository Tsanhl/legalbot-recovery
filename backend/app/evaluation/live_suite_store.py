"""Encrypted run storage for manifest-driven live evaluation suites."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..crypto import LocalCipher
from .live30 import (
    RunEventType,
    RunProvenance,
    RunStage,
    RunStatus,
    SensitiveArtifactKind,
    _append_safe_jsonl,
    _exclusive_write,
    _private_directory,
    _write_safe_json,
    assert_safe_evaluation_payload,
)
from .live_suite import (
    LiveEvaluationBundle,
    LiveGenerationRunPlan,
    LiveQuestionCase,
    LiveSuiteManifest,
    admission_as_of_date,
)

RUN_MANIFEST_SCHEMA = "legalbot.live-evaluation-run-manifest.v2"
RUN_EVENT_SCHEMA = "legalbot.live-evaluation-run-event.v2"
CASE_INDEX_SCHEMA = "legalbot.live-evaluation-case-index.v2"

_SAFE_CASE_JSON_NAMES = frozenset(
    {
        "coverage.json",
        "retrieval.json",
        "evidence-map.json",
        "metrics.json",
        "outcome.json",
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
        "runtime-status.json",
        "slo-evaluation.json",
    }
)
_SAFE_RUN_INDEX_NAMES = frozenset({"issues", "knowledge-gaps"})
_MAX_SAFE_JSON_BYTES = 4 * 1024 * 1024
_MAX_SAFE_INDEX_BYTES = 8 * 1024 * 1024


class LiveSuiteRunManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-run-manifest.v2"] = Field(
        default="legalbot.live-evaluation-run-manifest.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_version: Literal["1.0.0"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_registry_canonical_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_id: Literal["live60-single-pass-30-v1"]
    run_plan_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    purpose: Literal["evaluation_only"]
    eligible_for_training: Literal[False]
    training_export_allowed: Literal[False]
    local_only: Literal[True]
    online_research_allowed: Literal[False]
    case_count: Literal[60]
    total_word_target: Literal[215000]
    generation_case_count: Literal[30]
    generation_total_word_target: Literal[114000]
    created_at: datetime
    as_of_date: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    legal_date_timezone: Literal["Europe/London"]
    initial_status: Literal["created"]
    encrypted_unreleased_retention_days: int = Field(default=30, ge=1, le=365)
    provenance: RunProvenance


class LiveSuiteRunEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-run-event.v2"] = Field(
        default="legalbot.live-evaluation-run-event.v2", alias="schema"
    )
    event_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    timestamp: datetime
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str | None = Field(default=None, pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    event_type: RunEventType
    stage: RunStage
    status: RunStatus
    duration_ms: int | None = Field(default=None, ge=0)
    attempt: int | None = Field(default=None, ge=1)
    artifact_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    error_code: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class LiveSuiteCaseIndexEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-evaluation-case-index.v2"] = Field(
        default="legalbot.live-evaluation-case-index.v2", alias="schema"
    )
    entry_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    timestamp: datetime
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition: Literal["generate_once", "coverage_only_not_selected"]
    status: RunStatus


class EncryptedQuestionEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.e2e-encrypted-question.v2"] = Field(alias="schema")
    run_id: str
    as_of_date: str
    case: LiveQuestionCase


class LiveSuiteRunStore:
    """Create-only store bound to exact suite and run-plan snapshots.

    Layout is fixed at ``data/evaluations/e2e/runs/<run_id>/`` with per-case
    ``retrieval.json``, ``evidence-map.json``, ``coverage.json``,
    ``metrics.json`` and ``outcome.json``. Do not invent a parallel evaluation
    root.
    """

    def __init__(self, project_root: Path, cipher: LocalCipher) -> None:
        self.project_root = project_root.resolve()
        self.cipher = cipher
        self.runs_root = self.project_root / "data/evaluations/e2e/runs"
        self.logs_root = self.project_root / "logs/events"
        if not self.runs_root.resolve().is_relative_to(self.project_root):
            raise ValueError("E2E run root escapes the project")
        if not self.logs_root.resolve().is_relative_to(self.project_root):
            raise ValueError("E2E log root escapes the project")
        self.events_log = self.logs_root / "live60-run-events.jsonl"
        self.case_index_log = self.logs_root / "live60-case-index.jsonl"

    @staticmethod
    def _safe_id(value: str, *, label: str) -> str:
        import re

        if re.fullmatch(r"^[a-z0-9][a-z0-9._:-]{2,127}$", value) is None:
            raise ValueError(f"invalid {label}")
        return value

    def _run_path(self, run_id: str) -> Path:
        self._safe_id(run_id, label="run_id")
        path = (self.runs_root / run_id).resolve()
        if not path.is_relative_to(self.runs_root.resolve()):
            raise ValueError("run path escaped the E2E root")
        return path

    def _run_plan(self, run_id: str) -> dict[str, Any]:
        path = self._run_path(run_id) / "generation-run-plan.json"
        if not path.is_file():
            raise ValueError("run-plan snapshot is missing")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("run-plan snapshot is not an object")
        return value

    def _case_ids(self, run_id: str) -> tuple[str, ...]:
        plan = self._run_plan(run_id)
        cases = plan.get("cases")
        if not isinstance(cases, list):
            raise ValueError("run-plan case list is invalid")
        output: list[str] = []
        for item in cases:
            if not isinstance(item, dict) or not isinstance(item.get("case_id"), str):
                raise ValueError("run-plan case identity is invalid")
            output.append(item["case_id"])
        if len(output) != len(set(output)):
            raise ValueError("run-plan snapshot contains duplicated cases")
        return tuple(output)

    def _case_path(self, run_id: str, case_id: str) -> Path:
        if case_id not in self._case_ids(run_id):
            raise ValueError("case is not part of this run plan")
        path = (self._run_path(run_id) / "cases" / case_id).resolve()
        if not path.is_relative_to(self._run_path(run_id)):
            raise ValueError("case path escaped the E2E run root")
        return path

    def create_run(
        self,
        *,
        run_id: str,
        bundle: LiveEvaluationBundle,
        provenance: RunProvenance,
        admitted_at: datetime | None = None,
    ) -> LiveSuiteRunManifest:
        destination = self._run_path(run_id)
        _private_directory(self.runs_root)
        if destination.exists():
            raise FileExistsError(f"E2E run already exists: {run_id}")
        instant = admitted_at or datetime.now().astimezone()
        legal_date = admission_as_of_date(instant)
        manifest = LiveSuiteRunManifest(
            run_id=run_id,
            suite_id=bundle.manifest.suite_id,
            suite_version=bundle.manifest.suite_version,
            suite_manifest_seal_sha256=bundle.manifest.seal_sha256,
            suite_registry_file_sha256=bundle.registry.file_sha256,
            suite_registry_canonical_sha256=bundle.registry.canonical_sha256,
            run_plan_id=bundle.run_plan.run_plan_id,
            run_plan_file_sha256=bundle.manifest.run_plan_sha256,
            run_plan_seal_sha256=bundle.run_plan.seal_sha256,
            purpose="evaluation_only",
            eligible_for_training=False,
            training_export_allowed=False,
            local_only=True,
            online_research_allowed=False,
            case_count=60,
            total_word_target=215_000,
            generation_case_count=30,
            generation_total_word_target=114_000,
            created_at=instant,
            as_of_date=legal_date.isoformat(),
            legal_date_timezone=bundle.run_plan.legal_date_timezone,
            initial_status="created",
            provenance=provenance,
        )
        temporary = self.runs_root / f".{run_id}.{uuid.uuid4().hex}.tmp"
        dispositions = {item.case_id: item.disposition for item in bundle.run_plan.cases}
        try:
            _private_directory(temporary)
            _private_directory(temporary / "cases")
            _exclusive_write(
                temporary / "manifest.json",
                json.dumps(
                    manifest.model_dump(mode="json", by_alias=True),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8")
                + b"\n",
            )
            _exclusive_write(
                temporary / "suite-manifest.json",
                (bundle.root / "manifest.json").read_bytes(),
            )
            _exclusive_write(
                temporary / "generation-run-plan.json",
                (bundle.root / bundle.manifest.run_plan_path).read_bytes(),
            )
            for case in bundle.registry.cases:
                case_root = temporary / "cases" / case.case_id
                _private_directory(case_root)
                _private_directory(case_root / "artifacts")
                envelope = {
                    "schema": "legalbot.e2e-encrypted-question.v2",
                    "run_id": run_id,
                    "as_of_date": legal_date.isoformat(),
                    "case": case.model_dump(mode="json", by_alias=True),
                }
                _exclusive_write(
                    case_root / "question.enc",
                    self.cipher.encrypt_text(
                        json.dumps(envelope, ensure_ascii=False, sort_keys=True)
                    ),
                )
                _write_safe_json(
                    case_root / "case.json",
                    {
                        "schema": "legalbot.e2e-safe-case.v2",
                        "case_id": case.case_id,
                        "question_sha256": case.question_sha256,
                        "record_sha256": case.record_sha256,
                        "ordinal": case.ordinal,
                        "task_type": case.task_type,
                        "subject": case.subject,
                        "jurisdiction": case.jurisdiction,
                        "as_of_date": legal_date.isoformat(),
                        "word_target": case.word_target,
                        "expected_research_route": case.expected_research_route,
                        "expected_drafting_route": case.expected_drafting_route,
                        "disposition": dispositions[case.case_id],
                        "status": "created",
                    },
                )
            os.replace(temporary, destination)
        except Exception:
            import shutil

            shutil.rmtree(temporary, ignore_errors=True)
            raise
        self.record_event(
            LiveSuiteRunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=instant,
                run_id=run_id,
                event_type=RunEventType.RUN_CREATED,
                stage=RunStage.RUN,
                status=RunStatus.CREATED,
            )
        )
        for case in bundle.registry.cases:
            self.record_case_status(
                run_id=run_id,
                case=case,
                disposition=dispositions[case.case_id],
                status=RunStatus.CREATED,
                timestamp=instant,
            )
        return manifest

    def load_run_manifest(self, run_id: str) -> LiveSuiteRunManifest:
        path = self._run_path(run_id) / "manifest.json"
        if not path.is_file():
            raise ValueError("run manifest is missing")
        manifest = LiveSuiteRunManifest.model_validate_json(path.read_bytes())
        suite_path = self._run_path(run_id) / "suite-manifest.json"
        plan_path = self._run_path(run_id) / "generation-run-plan.json"
        if not suite_path.is_file() or not plan_path.is_file():
            raise ValueError("run contract snapshot is missing")
        suite = LiveSuiteManifest.model_validate_json(suite_path.read_bytes())
        plan = LiveGenerationRunPlan.model_validate_json(plan_path.read_bytes())
        if suite.seal_sha256 != manifest.suite_manifest_seal_sha256:
            raise ValueError("run suite snapshot differs from its manifest")
        if hashlib.sha256(plan_path.read_bytes()).hexdigest() != manifest.run_plan_file_sha256:
            raise ValueError("run-plan snapshot file digest differs from its manifest")
        if plan.seal_sha256 != manifest.run_plan_seal_sha256:
            raise ValueError("run-plan snapshot seal differs from its manifest")
        return manifest

    def load_run_plan(self, run_id: str) -> LiveGenerationRunPlan:
        """Return the immutable, manifest-bound generation-plan snapshot."""

        manifest = self.load_run_manifest(run_id)
        path = self._run_path(run_id) / "generation-run-plan.json"
        plan = LiveGenerationRunPlan.model_validate_json(path.read_bytes())
        if plan.run_plan_id != manifest.run_plan_id:
            raise ValueError("run-plan snapshot identity differs from its manifest")
        return plan

    def load_encrypted_question(
        self, *, run_id: str, case_id: str
    ) -> tuple[date, LiveQuestionCase]:
        path = self._case_path(run_id, case_id) / "question.enc"
        envelope = EncryptedQuestionEnvelope.model_validate_json(
            self.cipher.decrypt_text(path.read_bytes())
        )
        if envelope.run_id != run_id or envelope.case.case_id != case_id:
            raise ValueError("encrypted question identity mismatch")
        suite = LiveSuiteManifest.model_validate_json(
            (self._run_path(run_id) / "suite-manifest.json").read_bytes()
        )
        if (
            suite.question_hashes.get(case_id) != envelope.case.question_sha256
            or suite.record_hashes.get(case_id) != envelope.case.record_sha256
        ):
            raise ValueError("encrypted question differs from the suite snapshot")
        return datetime.strptime(envelope.as_of_date, "%Y-%m-%d").date(), envelope.case

    def record_event(self, event: LiveSuiteRunEvent) -> None:
        if not self._run_path(event.run_id).is_dir():
            raise ValueError("cannot record an event for a missing run")
        if event.case_id is not None and event.case_id not in self._case_ids(event.run_id):
            raise ValueError("event case is not in the run plan")
        _append_safe_jsonl(
            self.events_log,
            event.model_dump(mode="json", by_alias=True),
        )
        _append_safe_jsonl(
            self._run_path(event.run_id) / "events.jsonl",
            event.model_dump(mode="json", by_alias=True),
        )

    def record_case_status(
        self,
        *,
        run_id: str,
        case: LiveQuestionCase,
        disposition: Literal["generate_once", "coverage_only_not_selected"],
        status: RunStatus,
        timestamp: datetime,
    ) -> None:
        entry = LiveSuiteCaseIndexEntry(
            entry_id=uuid.uuid4().hex,
            timestamp=timestamp,
            run_id=run_id,
            case_id=case.case_id,
            question_sha256=case.question_sha256,
            disposition=disposition,
            status=status,
        )
        _append_safe_jsonl(
            self.case_index_log,
            entry.model_dump(mode="json", by_alias=True),
        )
        _append_safe_jsonl(
            self._run_path(run_id) / "case-index.jsonl",
            entry.model_dump(mode="json", by_alias=True),
        )

    def store_safe_case_json(
        self,
        *,
        run_id: str,
        case_id: str,
        filename: str,
        value: dict[str, Any],
    ) -> Path:
        if filename not in _SAFE_CASE_JSON_NAMES:
            raise ValueError("safe case artifact filename is not allowlisted")
        path = self._case_path(run_id, case_id) / filename
        _write_safe_json(path, value)
        return path

    def store_sensitive_artifact(
        self,
        *,
        run_id: str,
        case_id: str,
        kind: SensitiveArtifactKind,
        artifact_id: str,
        content: str,
    ) -> Path:
        self._safe_id(artifact_id, label="artifact_id")
        path = self._case_path(run_id, case_id) / "artifacts" / (f"{kind.value}-{artifact_id}.enc")
        _exclusive_write(path, self.cipher.encrypt_text(content))
        return path

    def load_sensitive_artifact(
        self,
        *,
        run_id: str,
        case_id: str,
        kind: SensitiveArtifactKind,
        artifact_id: str,
    ) -> str:
        self._safe_id(artifact_id, label="artifact_id")
        path = self._case_path(run_id, case_id) / "artifacts" / (f"{kind.value}-{artifact_id}.enc")
        if not path.is_file():
            raise ValueError("encrypted artifact is missing")
        return self.cipher.decrypt_text(path.read_bytes())

    def store_safe_run_json(self, *, run_id: str, filename: str, value: dict[str, Any]) -> Path:
        if filename not in _SAFE_RUN_JSON_NAMES:
            raise ValueError("safe run artifact filename is not allowlisted")
        path = self._run_path(run_id) / filename
        _write_safe_json(path, value)
        return path

    def append_safe_run_index(
        self,
        *,
        run_id: str,
        index_name: str,
        value: dict[str, Any],
    ) -> Path:
        if index_name not in _SAFE_RUN_INDEX_NAMES:
            raise ValueError("safe run index is not allowlisted")
        path = self._run_path(run_id) / f"{index_name}.jsonl"
        _append_safe_jsonl(path, value)
        return path

    def load_safe_run_json(self, *, run_id: str, filename: str) -> dict[str, Any]:
        if filename not in _SAFE_RUN_JSON_NAMES:
            raise ValueError("safe run artifact filename is not allowlisted")
        path = self._run_path(run_id) / filename
        if path.stat().st_size > _MAX_SAFE_JSON_BYTES:
            raise ValueError("safe run artifact exceeds its size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("safe run artifact is not an object")
        assert_safe_evaluation_payload(value)
        return value

    def load_safe_case_json(self, *, run_id: str, case_id: str, filename: str) -> dict[str, Any]:
        """Load one explicitly allowlisted prose-free case projection."""

        if filename not in _SAFE_CASE_JSON_NAMES | {"case.json"}:
            raise ValueError("safe case artifact filename is not allowlisted")
        path = self._case_path(run_id, case_id) / filename
        if path.stat().st_size > _MAX_SAFE_JSON_BYTES:
            raise ValueError("safe case artifact exceeds its size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("safe case artifact is not an object")
        assert_safe_evaluation_payload(value)
        if value.get("case_id") != case_id:
            raise ValueError("safe case artifact identity differs from its location")
        return value

    def load_safe_run_index(self, *, run_id: str, index_name: str) -> tuple[dict[str, Any], ...]:
        """Read an append-only safe issue/gap index without decrypting notes."""

        if index_name not in _SAFE_RUN_INDEX_NAMES:
            raise ValueError("safe run index is not allowlisted")
        path = self._run_path(run_id) / f"{index_name}.jsonl"
        if not path.is_file():
            return ()
        if path.stat().st_size > _MAX_SAFE_INDEX_BYTES:
            raise ValueError("safe run index exceeds its size limit")
        output: list[dict[str, Any]] = []
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"safe run index contains invalid JSON at line {line_number}"
                ) from exc
            if not isinstance(value, dict):
                raise ValueError("safe run index contains a non-object")
            assert_safe_evaluation_payload(value)
            output.append(value)
        return tuple(output)
