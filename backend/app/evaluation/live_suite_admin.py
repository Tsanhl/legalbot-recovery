"""Privacy-safe owner projections for manifest-driven live evaluation runs.

This reader is deliberately separate from :mod:`live30_admin`: sealed Live30
runs keep their existing reader and artifact conventions.  The API may dispatch
to this reader only after identifying a v2 manifest-driven run.  Ordinary list
and detail views never decrypt a question, answer or reviewer note.  The
released-answer method decrypts only a one-pass outcome whose immutable hard
release gates and artifact digest still verify.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..privacy import contains_absolute_private_path
from .live30 import SensitiveArtifactKind, assert_safe_evaluation_payload
from .live_suite_execute import Live60ExecutionOutcome
from .live_suite_store import LiveSuiteRunManifest, LiveSuiteRunStore

RUN_LIST_SCHEMA = "legalbot.live-suite-admin-run-list.v1"
RUN_DETAIL_SCHEMA = "legalbot.live-suite-admin-run-detail.v1"
RELEASED_ANSWER_SCHEMA = "legalbot.live-suite-admin-released-answer.v1"
_RUN_MANIFEST_SCHEMA = "legalbot.live-evaluation-run-manifest.v2"
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024


class LiveSuiteAdminIntegrityError(ValueError):
    """Raised when an owner projection cannot be produced safely."""


def _safe_string(value: Any, *, maximum: int = 255) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > maximum or contains_absolute_private_path(cleaned):
        return None
    return cleaned


def _safe_ids(value: Any, *, maximum: int = 2_000) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    output: list[str] = []
    for item in value[:maximum]:
        cleaned = _safe_string(item)
        if cleaned is not None and cleaned not in output:
            output.append(cleaned)
    return output


def _project_outcome(outcome: Live60ExecutionOutcome) -> dict[str, Any]:
    release_state = (
        outcome.runtime_release_state
        if outcome.runtime_release_state is not None
        else "verified_full"
        if outcome.terminal_state == "released"
        else "verified_limited"
        if outcome.terminal_state == "verified_limited"
        else "not_released"
    )
    word_target_delta = (
        outcome.word_count - outcome.requested_word_target
        if outcome.word_count is not None
        else None
    )
    word_target_within_tolerance = (
        abs(word_target_delta) <= max(1, round(outcome.requested_word_target * 0.05))
        if word_target_delta is not None
        else None
    )
    return {
        "pass_number": outcome.pass_number,
        # Fields that are not part of the immutable outcome remain explicit so
        # the owner console cannot misinterpret an absent browser property.
        "status": outcome.terminal_state,
        "terminal_state": outcome.terminal_state,
        "release_state": release_state,
        "released": outcome.released,
        "job_id": outcome.job_id,
        "trace_id": outcome.trace_id,
        "word_count": outcome.word_count,
        "word_target": outcome.requested_word_target,
        "word_target_within_tolerance": word_target_within_tolerance,
        "word_target_delta": word_target_delta,
        "route": outcome.expected_research_route,
        "model_version": None,
        "index_build_id": None,
        "policy_version": None,
        "assessment_bundle_sha256": None,
        "assessment_rule_ids": [],
        "triggered_assessment_rule_ids": [],
        "rule_evaluation_state": "not_recorded",
        "evidence": [],
        "rubric": [],
        "repairs": [],
        "privacy_passed": outcome.privacy_passed,
        "evidence_passed": outcome.evidence_passed,
        "currentness_passed": outcome.currentness_passed,
        "jurisdiction_passed": outcome.jurisdiction_passed,
        "citation_passed": outcome.citation_passed,
        "injection_passed": outcome.injection_passed,
        "oscola_passed": outcome.oscola_passed,
        "release_gate_report_sha256": outcome.release_gate_report_sha256,
        "issue_ids": list(outcome.issue_ids),
        "knowledge_gap_ids": list(outcome.knowledge_gap_ids),
        "failure_codes": list(outcome.failure_codes),
        "completion_duration_ms": outcome.completion_duration_ms,
        "completed_at": outcome.completed_at.isoformat(),
    }


def _project_index_entry(value: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    identifier = _safe_string(value.get("issue_id" if kind == "issue" else "gap_id"))
    if identifier is None:
        identifier = _safe_string(value.get("id"))
    if identifier is None:
        raise LiveSuiteAdminIntegrityError(f"safe {kind} record has no identifier")
    return {
        "id": identifier,
        "case_id": _safe_string(value.get("case_id")),
        "issue_id": _safe_string(value.get("issue_id")),
        "category": _safe_string(value.get("category"))
        or _safe_string(value.get("reason_code"))
        or kind,
        "severity": _safe_string(value.get("severity")) or "unclassified",
        "affected_layer": _safe_string(value.get("affected_layer")),
        "status": _safe_string(value.get("status")) or "open",
        "reason_code": _safe_string(value.get("reason_code")),
        "expected_ids": _safe_ids(value.get("safe_expected_ids", value.get("expected_ids"))),
        "observed_ids": _safe_ids(value.get("safe_observed_ids", value.get("observed_ids"))),
        "regression_case_id": _safe_string(value.get("regression_case_id")),
        "fixed_version": _safe_string(value.get("fixed_version")),
    }


class LiveSuiteAdminReader:
    """Read-only adapter for v2 manifest-driven local owner views."""

    def __init__(
        self,
        store: LiveSuiteRunStore,
        *,
        owner_identifiers: Sequence[str] = (),
    ) -> None:
        self.store = store
        self.owner_identifiers = tuple(
            value for value in owner_identifiers if isinstance(value, str) and value.strip()
        )

    @staticmethod
    def _manifest_schema(path: Path) -> str | None:
        if not path.is_file() or path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, OSError):
            return None
        if not isinstance(value, dict):
            return None
        return _safe_string(value.get("schema"))

    def _optional_case_json(
        self, *, run_id: str, case_id: str, filename: str
    ) -> dict[str, Any] | None:
        try:
            return self.store.load_safe_case_json(run_id=run_id, case_id=case_id, filename=filename)
        except FileNotFoundError:
            return None

    def _optional_run_json(self, *, run_id: str, filename: str) -> dict[str, Any] | None:
        try:
            return self.store.load_safe_run_json(run_id=run_id, filename=filename)
        except FileNotFoundError:
            return None

    def _outcome(self, *, run_id: str, case_id: str) -> Live60ExecutionOutcome | None:
        value = self._optional_case_json(run_id=run_id, case_id=case_id, filename="outcome.json")
        if value is None:
            return None
        outcome = Live60ExecutionOutcome.model_validate(value)
        if outcome.run_id != run_id or outcome.case_id != case_id:
            raise LiveSuiteAdminIntegrityError(
                "terminal outcome identity differs from its location"
            )
        return outcome

    def _run_summary(self, manifest: LiveSuiteRunManifest) -> dict[str, Any]:
        plan = self.store.load_run_plan(manifest.run_id)
        selected = tuple(item.case_id for item in plan.cases if item.disposition == "generate_once")
        coverage_only = tuple(
            item.case_id for item in plan.cases if item.disposition == "coverage_only_not_selected"
        )
        outcomes = [
            outcome
            for case_id in selected
            if (outcome := self._outcome(run_id=manifest.run_id, case_id=case_id)) is not None
        ]
        coverage_count = sum(
            self._optional_case_json(
                run_id=manifest.run_id, case_id=item.case_id, filename="coverage.json"
            )
            is not None
            for item in plan.cases
        )
        coverage_summary = self._optional_run_json(
            run_id=manifest.run_id, filename="coverage-summary.json"
        )
        aggregate = self._optional_run_json(
            run_id=manifest.run_id, filename="aggregate-metrics.json"
        )
        privacy_report = self._optional_run_json(
            run_id=manifest.run_id, filename="run-privacy-report.json"
        )
        privacy_report_passed = (
            privacy_report.get("passed")
            if privacy_report is not None and isinstance(privacy_report.get("passed"), bool)
            else None
        )
        if aggregate is not None and aggregate.get("complete") is True:
            status = "completed"
        elif outcomes:
            status = "running"
        elif coverage_summary is not None and coverage_summary.get("stage_a_passed") is True:
            status = "awaiting_live_authorization"
        elif coverage_summary is not None:
            status = "stage_a_failed_or_incomplete"
        elif coverage_count:
            status = "coverage_running"
        else:
            status = "not_started"
        terminal_counts = Counter(outcome.terminal_state for outcome in outcomes)
        return {
            "run_id": manifest.run_id,
            "suite_id": manifest.suite_id,
            "suite_version": manifest.suite_version,
            "run_plan_id": manifest.run_plan_id,
            "created_at": manifest.created_at.isoformat(),
            "as_of_date": manifest.as_of_date,
            "legal_date_timezone": manifest.legal_date_timezone,
            "status": status,
            "expected_case_count": manifest.case_count,
            "expected_total_word_target": manifest.total_word_target,
            "selected_generation_case_count": manifest.generation_case_count,
            "selected_generation_total_word_target": (manifest.generation_total_word_target),
            "coverage_only_case_count": len(coverage_only),
            "coverage_completed_case_count": coverage_count,
            "selected_completed_case_count": len(outcomes),
            # Compatibility aliases used by the current owner console.
            "completed_case_count": len(outcomes),
            "pass_outcome_count": len(outcomes),
            "released_outcome_count": sum(outcome.released for outcome in outcomes),
            "limited_outcome_count": terminal_counts.get("verified_limited", 0),
            "held_or_failed_outcome_count": sum(not outcome.released for outcome in outcomes),
            "privacy_report_passed": privacy_report_passed,
            "local_only": manifest.local_only,
            "online_research_allowed": manifest.online_research_allowed,
            "purpose": manifest.purpose,
            "eligible_for_training": manifest.eligible_for_training,
            "training_export_allowed": manifest.training_export_allowed,
            "model_version": manifest.provenance.model_version,
            "index_build_id": manifest.provenance.index_build_id,
            "policy_sha256": manifest.provenance.policy_sha256,
            "assessment_rules_sha256": manifest.provenance.assessment_rules_sha256,
        }

    def list_runs(self) -> dict[str, Any]:
        root = self.store.runs_root
        if not root.is_dir():
            return {
                "schema": RUN_LIST_SCHEMA,
                "items": [],
                "invalid_run_count": 0,
                "skipped_legacy_run_count": 0,
            }
        items: list[dict[str, Any]] = []
        invalid = 0
        legacy = 0
        for entry in sorted(root.iterdir(), key=lambda path: path.name, reverse=True):
            if not entry.is_dir() or entry.is_symlink() or entry.name.startswith("."):
                continue
            schema = self._manifest_schema(entry / "manifest.json")
            if schema != _RUN_MANIFEST_SCHEMA:
                if schema is not None:
                    legacy += 1
                else:
                    invalid += 1
                continue
            try:
                manifest = self.store.load_run_manifest(entry.name)
                items.append(self._run_summary(manifest))
            except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError):
                invalid += 1
        items.sort(key=lambda item: str(item["created_at"]), reverse=True)
        return {
            "schema": RUN_LIST_SCHEMA,
            "items": items,
            "invalid_run_count": invalid,
            "skipped_legacy_run_count": legacy,
        }

    def run_detail(self, run_id: str) -> dict[str, Any]:
        manifest = self.store.load_run_manifest(run_id)
        plan = self.store.load_run_plan(run_id)
        summary = self._run_summary(manifest)
        issue_records = self.store.load_safe_run_index(run_id=run_id, index_name="issues")
        gap_records = self.store.load_safe_run_index(run_id=run_id, index_name="knowledge-gaps")
        cases: list[dict[str, Any]] = []
        for plan_case in plan.cases:
            case_id = plan_case.case_id
            safe_case = self.store.load_safe_case_json(
                run_id=run_id, case_id=case_id, filename="case.json"
            )
            outcome = self._outcome(run_id=run_id, case_id=case_id)
            coverage = self._optional_case_json(
                run_id=run_id, case_id=case_id, filename="coverage.json"
            )
            artifacts = {
                key.replace("-", "_").removesuffix(".json"): value
                for key in (
                    "retrieval.json",
                    "evidence-map.json",
                    "metrics.json",
                    "quality.json",
                )
                if (value := self._optional_case_json(run_id=run_id, case_id=case_id, filename=key))
                is not None
            }
            case_issues = [
                _project_index_entry(value, kind="issue")
                for value in issue_records
                if value.get("case_id") == case_id
            ]
            case_gaps = [
                _project_index_entry(value, kind="knowledge_gap")
                for value in gap_records
                if value.get("case_id") == case_id
            ]
            status: str
            passes: list[dict[str, Any]]
            if outcome is not None:
                status = outcome.terminal_state
                projected = _project_outcome(outcome)
                gate_report = artifacts.get("quality")
                if (
                    isinstance(gate_report, Mapping)
                    and gate_report.get("schema") == "legalbot.live60-release-gate-report.v1"
                ):
                    assessment_rule_ids = _safe_ids(gate_report.get("assessment_rule_ids"))
                    triggered_rule_ids = _safe_ids(gate_report.get("triggered_assessment_rule_ids"))
                    raw_evidence = gate_report.get("evidence")
                    evidence = (
                        [dict(item) for item in raw_evidence if isinstance(item, Mapping)]
                        if isinstance(raw_evidence, list)
                        else []
                    )
                    raw_score = gate_report.get("academic_score")
                    score = (
                        float(raw_score)
                        if isinstance(raw_score, int | float) and not isinstance(raw_score, bool)
                        else None
                    )
                    projected.update(
                        {
                            "model_version": _safe_string(gate_report.get("model_version")),
                            "index_build_id": _safe_string(gate_report.get("index_build_id")),
                            "policy_version": _safe_string(gate_report.get("policy_sha256")),
                            "assessment_bundle_sha256": _safe_string(
                                gate_report.get("assessment_bundle_sha256")
                            ),
                            "assessment_rule_ids": assessment_rule_ids,
                            "triggered_assessment_rule_ids": triggered_rule_ids,
                            "rule_evaluation_state": "recorded",
                            "evidence": evidence,
                            "rubric": [
                                {
                                    "criterion_id": "automated_academic_score",
                                    "score": score,
                                    "status": "advisory",
                                    "assessment_rule_ids": triggered_rule_ids,
                                    "verification_signal": ("automated_lint_not_blind_calibration"),
                                }
                            ],
                        }
                    )
                passes = [projected]
            elif coverage is not None:
                status = _safe_string(coverage.get("deterministic_outcome")) or "covered"
                passes = []
            elif plan_case.disposition == "coverage_only_not_selected":
                status = "coverage_only_not_selected"
                passes = []
            else:
                status = "not_run"
                passes = []
            cases.append(
                {
                    "case_id": case_id,
                    "ordinal": safe_case.get("ordinal"),
                    "task_type": _safe_string(safe_case.get("task_type")),
                    "subject": _safe_string(safe_case.get("subject")),
                    "jurisdiction": _safe_string(safe_case.get("jurisdiction")),
                    "as_of_date": _safe_string(safe_case.get("as_of_date")),
                    "status": status,
                    "release_state": (
                        _project_outcome(outcome)["release_state"]
                        if outcome is not None
                        else "not_run"
                    ),
                    "released": bool(outcome and outcome.released),
                    "disposition": plan_case.disposition,
                    "word_target": safe_case.get("word_target"),
                    "expected_research_route": _safe_string(
                        safe_case.get("expected_research_route")
                    ),
                    "expected_drafting_route": _safe_string(
                        safe_case.get("expected_drafting_route")
                    ),
                    "coverage": coverage,
                    "passes": passes,
                    "safe_artifacts": artifacts,
                    "issues": case_issues,
                    "knowledge_gaps": case_gaps,
                }
            )
        value = {"schema": RUN_DETAIL_SCHEMA, "run": summary, "cases": cases}
        assert_safe_evaluation_payload(value)
        return value

    def released_answer(self, *, run_id: str, case_id: str, pass_number: int) -> dict[str, Any]:
        if pass_number != 1:
            raise LiveSuiteAdminIntegrityError("manifest-driven Live60 authorizes one pass only")
        self.store.load_run_manifest(run_id)
        outcome = self._outcome(run_id=run_id, case_id=case_id)
        if outcome is None:
            raise FileNotFoundError("terminal outcome is missing")
        if not outcome.released or not all(
            (
                outcome.privacy_passed,
                outcome.evidence_passed,
                outcome.currentness_passed,
                outcome.jurisdiction_passed,
                outcome.citation_passed,
                outcome.injection_passed,
                outcome.oscola_passed,
            )
        ):
            raise PermissionError("answer is not a hard-gate-passed released artifact")
        if (
            outcome.answer_artifact_id is None
            or outcome.answer_sha256 is None
            or outcome.release_gate_report_sha256 is None
        ):
            raise LiveSuiteAdminIntegrityError("released outcome has incomplete provenance")
        gate_report = self.store.load_safe_case_json(
            run_id=run_id, case_id=case_id, filename="quality.json"
        )
        gate_path = self.store._case_path(run_id, case_id) / "quality.json"
        gates = gate_report.get("gates")
        if (
            gate_report.get("schema") != "legalbot.live60-release-gate-report.v1"
            or gate_report.get("run_id") != run_id
            or gate_report.get("case_id") != case_id
            or not isinstance(gates, Mapping)
            or any(
                gates.get(name) is not True
                for name in (
                    "privacy",
                    "evidence",
                    "currentness",
                    "jurisdiction",
                    "citation",
                    "injection",
                    "oscola",
                )
            )
            or hashlib.sha256(gate_path.read_bytes()).hexdigest()
            != outcome.release_gate_report_sha256
        ):
            raise LiveSuiteAdminIntegrityError(
                "released outcome differs from its immutable hard-gate report"
            )
        content = self.store.load_sensitive_artifact(
            run_id=run_id,
            case_id=case_id,
            kind=SensitiveArtifactKind.ANSWER,
            artifact_id=outcome.answer_artifact_id,
        )
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != outcome.answer_sha256:
            raise LiveSuiteAdminIntegrityError(
                "released answer digest differs from its terminal outcome"
            )
        folded = content.casefold()
        if contains_absolute_private_path(content) or any(
            identifier.casefold() in folded for identifier in self.owner_identifiers
        ):
            raise PermissionError("released answer failed the owner-view privacy recheck")
        return {
            "schema": RELEASED_ANSWER_SCHEMA,
            "run_id": run_id,
            "case_id": case_id,
            "pass_number": 1,
            "release_state": _project_outcome(outcome)["release_state"],
            "word_count": outcome.word_count,
            "answer_sha256": outcome.answer_sha256,
            "release_gate_report_sha256": outcome.release_gate_report_sha256,
            "content": content,
        }
