"""Privacy-safe owner views over immutable live-30 evaluation artifacts.

The ordinary admin feeds expose identifiers, outcomes and diagnostics only.
They never decrypt questions, held answers, issue notes or gap prose.  Released
answer prose is available through a separate method which revalidates the
recorded release gates and the encrypted artifact digest before decrypting it.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..privacy import contains_absolute_private_path
from .live30 import (
    EXPECTED_CASE_IDS,
    E2ERunManifest,
    Live30RunStore,
    SensitiveArtifactKind,
    assert_safe_evaluation_payload,
)

PUBLIC_RELEASE_STATES = frozenset({"verified_full", "verified_concise", "verified_limited"})
_MAX_SAFE_JSON_BYTES = 2 * 1024 * 1024
_MAX_SAFE_INDEX_BYTES = 4 * 1024 * 1024


class Live30AdminIntegrityError(ValueError):
    """Raised when an owner view cannot be produced without weakening a gate."""


def _read_safe_object(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise Live30AdminIntegrityError("safe evaluation artifact is missing") from exc
    if size > _MAX_SAFE_JSON_BYTES:
        raise Live30AdminIntegrityError("safe evaluation artifact exceeds its size limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Live30AdminIntegrityError("safe evaluation artifact is invalid JSON") from exc
    if not isinstance(value, dict):
        raise Live30AdminIntegrityError("safe evaluation artifact is not an object")
    assert_safe_evaluation_payload(value)
    return value


def _safe_string(value: Any, *, maximum: int = 255) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    if not cleaned or len(cleaned) > maximum or contains_absolute_private_path(cleaned):
        return None
    return cleaned


def _safe_string_list(value: Any, *, maximum: int = 500) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    result: list[str] = []
    for item in value[:maximum]:
        cleaned = _safe_string(item)
        if cleaned is not None and cleaned not in result:
            result.append(cleaned)
    return result


def _safe_evidence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    result: list[dict[str, Any]] = []
    for item in value[:2_000]:
        if not isinstance(item, Mapping):
            continue
        evidence_span_id = _safe_string(item.get("evidence_span_id"))
        stable_source_id = _safe_string(item.get("stable_source_id"))
        legal_locator = _safe_string(item.get("legal_locator"))
        if not evidence_span_id or not stable_source_id or not legal_locator:
            continue
        result.append(
            {
                "evidence_span_id": evidence_span_id,
                "stable_source_id": stable_source_id,
                "legal_locator": legal_locator,
                "legal_role": _safe_string(item.get("legal_role")) or "unclassified",
                "identity_state": _safe_string(item.get("identity_state")) or "unverified",
                "support_state": _safe_string(item.get("support_state")) or "partial",
                "retrieval_rank": (
                    int(item["retrieval_rank"])
                    if isinstance(item.get("retrieval_rank"), int)
                    and 1 <= int(item["retrieval_rank"]) <= 10_000
                    else None
                ),
                "currentness_state": _safe_string(item.get("currentness_state")) or "unverified",
                "jurisdiction_state": _safe_string(item.get("jurisdiction_state")) or "unverified",
            }
        )
    return result


def _safe_rubric(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    result: list[dict[str, Any]] = []
    for item in value[:200]:
        if not isinstance(item, Mapping):
            continue
        criterion_id = _safe_string(item.get("criterion_id"))
        if not criterion_id:
            continue
        score = item.get("score")
        result.append(
            {
                "criterion_id": criterion_id,
                "score": (
                    float(score)
                    if isinstance(score, int | float) and 0 <= float(score) <= 100
                    else None
                ),
                "status": _safe_string(item.get("status")) or "not_scored",
                "assessment_rule_ids": _safe_string_list(
                    item.get("assessment_rule_ids"), maximum=500
                ),
                "verification_signal": _safe_string(item.get("verification_signal")),
            }
        )
    return result


def _safe_repairs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes | bytearray):
        return []
    result: list[dict[str, Any]] = []
    for item in value[:500]:
        if not isinstance(item, Mapping):
            continue
        repair_id = _safe_string(item.get("repair_id"))
        reason_code = _safe_string(item.get("reason_code"))
        if not repair_id or not reason_code:
            continue
        attempt_count = item.get("attempt_count")
        result.append(
            {
                "repair_id": repair_id,
                "section_id": _safe_string(item.get("section_id")),
                "reason_code": reason_code,
                "status": _safe_string(item.get("status")) or "pending",
                "attempt_count": (
                    int(attempt_count)
                    if isinstance(attempt_count, int) and 0 <= attempt_count <= 100
                    else 0
                ),
            }
        )
    return result


def _safe_outcome(value: Mapping[str, Any], *, case_id: str, pass_number: int) -> dict[str, Any]:
    if value.get("case_id") != case_id or value.get("pass_number") != pass_number:
        raise Live30AdminIntegrityError("pass outcome identity does not match its location")
    release_state = _safe_string(value.get("release_state")) or "not_released"
    released = value.get("released") is True
    if released != (release_state in PUBLIC_RELEASE_STATES):
        raise Live30AdminIntegrityError("pass outcome release flags disagree")
    repairs = value.get("repairs", value.get("repair_records", ()))
    completion_duration_ms = value.get("completion_duration_ms")
    return {
        "pass_number": pass_number,
        "job_id": _safe_string(value.get("job_id")),
        "trace_id": _safe_string(value.get("trace_id")),
        "status": _safe_string(value.get("status")) or "system_error",
        "release_state": release_state,
        "released": released,
        "privacy_passed": value.get("privacy_passed") is True,
        "evidence_passed": value.get("evidence_passed") is True,
        "word_count": value.get("word_count") if isinstance(value.get("word_count"), int) else None,
        "word_target": value.get("word_target")
        if isinstance(value.get("word_target"), int)
        else None,
        "word_target_within_tolerance": (
            value.get("word_target_within_tolerance")
            if isinstance(value.get("word_target_within_tolerance"), bool)
            else None
        ),
        "word_target_delta": (
            value.get("word_target_delta")
            if isinstance(value.get("word_target_delta"), int)
            else None
        ),
        "route": _safe_string(value.get("route")),
        "model_version": _safe_string(value.get("model_version")),
        "index_build_id": _safe_string(value.get("index_build_id")),
        "policy_version": _safe_string(value.get("policy_version")),
        "assessment_bundle_sha256": _safe_string(value.get("assessment_bundle_sha256")),
        # The complete bundle is provenance.  It must not be described as the
        # subset that actually fired during verification.
        "assessment_rule_ids": _safe_string_list(value.get("assessment_rule_ids")),
        "triggered_assessment_rule_ids": _safe_string_list(
            value.get("triggered_assessment_rule_ids")
        ),
        "rule_evaluation_state": (
            "recorded"
            if isinstance(value.get("triggered_assessment_rule_ids"), list | tuple)
            else "not_recorded"
        ),
        "evidence": _safe_evidence(value.get("evidence")),
        "rubric": _safe_rubric(value.get("rubric")),
        "repairs": _safe_repairs(repairs),
        "failure_codes": _safe_string_list(value.get("failure_codes"), maximum=200),
        "completion_duration_ms": (
            completion_duration_ms
            if isinstance(completion_duration_ms, int) and completion_duration_ms >= 0
            else None
        ),
    }


def _read_safe_index(path: Path, *, case_id: str, kind: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    if path.stat().st_size > _MAX_SAFE_INDEX_BYTES:
        raise Live30AdminIntegrityError(f"{kind} index exceeds its size limit")
    records: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise Live30AdminIntegrityError(f"{kind} index is invalid JSONL") from exc
        if not isinstance(value, dict):
            raise Live30AdminIntegrityError(f"{kind} index contains a non-object")
        assert_safe_evaluation_payload(value)
        if value.get("case_id") != case_id:
            continue
        identifier = _safe_string(
            value.get("issue_id") if kind == "issue" else value.get("gap_id"),
        ) or _safe_string(value.get("id"))
        if not identifier:
            continue
        records.append(
            {
                "id": identifier,
                "category": _safe_string(value.get("category"))
                or _safe_string(value.get("reason_code"))
                or kind,
                "severity": _safe_string(value.get("severity")) or "unclassified",
                "affected_layer": _safe_string(value.get("affected_layer")),
                "status": _safe_string(value.get("status")) or "open",
                "expected_ids": _safe_string_list(
                    value.get("safe_expected_ids", value.get("expected_ids"))
                ),
                "observed_ids": _safe_string_list(
                    value.get("safe_observed_ids", value.get("observed_ids"))
                ),
                "regression_case_id": _safe_string(value.get("regression_case_id")),
                "fixed_version": _safe_string(value.get("fixed_version")),
            }
        )
    return records


class Live30AdminReader:
    """Read-only adapter for the local owner console."""

    def __init__(
        self,
        store: Live30RunStore,
        *,
        owner_identifiers: Sequence[str] = (),
        database: Any | None = None,
    ) -> None:
        self.store = store
        self.owner_identifiers = tuple(value for value in owner_identifiers if value.strip())
        self.database = database

    def _database_repairs(self, job_id: str | None) -> list[dict[str, Any]]:
        """Project durable repair attempts onto a prose-free owner DTO."""

        if self.database is None or not job_id:
            return []
        rows = self.database.fetchall(
            """
            SELECT id,stage_key,section_key,status,attempt_number,error_code
            FROM job_stage_attempts
            WHERE job_id=? AND stage_key LIKE 'repair-%'
            ORDER BY stage_key,section_key,attempt_number,id
            """,
            (job_id,),
        )
        repairs: list[dict[str, Any]] = []
        for row in rows:
            repair_id = _safe_string(row["id"])
            stage_key = _safe_string(row["stage_key"])
            if not repair_id or not stage_key:
                continue
            repairs.append(
                {
                    "repair_id": repair_id,
                    "section_id": _safe_string(row["section_key"]),
                    "reason_code": _safe_string(row["error_code"]) or "quality_repair",
                    "status": _safe_string(row["status"]) or "pending",
                    "attempt_count": (
                        int(row["attempt_number"])
                        if isinstance(row["attempt_number"], int)
                        and 0 <= int(row["attempt_number"]) <= 100
                        else 0
                    ),
                }
            )
        return repairs

    def list_runs(self) -> dict[str, Any]:
        root = self.store.runs_root
        if not root.is_dir():
            return {"items": [], "invalid_run_count": 0}
        items: list[dict[str, Any]] = []
        invalid = 0
        for entry in sorted(root.iterdir(), key=lambda path: path.name, reverse=True):
            if not entry.is_dir() or entry.is_symlink() or entry.name.startswith("."):
                continue
            try:
                manifest = self.store.load_run_manifest(entry.name)
                items.append(self._run_summary(manifest))
            except (FileNotFoundError, OSError, ValueError, TypeError, json.JSONDecodeError):
                invalid += 1
        items.sort(key=lambda item: str(item["created_at"]), reverse=True)
        return {"items": items, "invalid_run_count": invalid}

    def _run_summary(self, manifest: E2ERunManifest) -> dict[str, Any]:
        run_root = self.store.runs_root / manifest.run_id
        outcomes: list[dict[str, Any]] = []
        pass_one_count = 0
        for case_id in EXPECTED_CASE_IDS:
            for pass_number in (1, 2, 3):
                path = run_root / "cases" / case_id / "outcomes" / f"pass-{pass_number}.json"
                if not path.is_file():
                    continue
                outcome = _safe_outcome(
                    _read_safe_object(path), case_id=case_id, pass_number=pass_number
                )
                outcomes.append(outcome)
                if pass_number == 1:
                    pass_one_count += 1
        privacy_state: bool | None = None
        privacy_path = run_root / "run-privacy-report.json"
        if privacy_path.is_file():
            privacy = _read_safe_object(privacy_path)
            privacy_state = (
                privacy.get("passed") if isinstance(privacy.get("passed"), bool) else None
            )
        status = (
            "not_started" if not outcomes else "completed" if pass_one_count == 30 else "running"
        )
        counts = Counter(str(item["release_state"]) for item in outcomes)
        return {
            "run_id": manifest.run_id,
            "suite_id": manifest.suite_id,
            "suite_version": manifest.suite_version,
            "created_at": manifest.created_at.isoformat(),
            "as_of_date": manifest.as_of_date.isoformat(),
            "status": status,
            "expected_case_count": 30,
            "completed_case_count": pass_one_count,
            "pass_outcome_count": len(outcomes),
            "released_outcome_count": sum(bool(item["released"]) for item in outcomes),
            "limited_outcome_count": counts.get("verified_limited", 0),
            "held_or_failed_outcome_count": sum(not bool(item["released"]) for item in outcomes),
            "privacy_report_passed": privacy_state,
            "local_only": manifest.local_only,
            "purpose": manifest.purpose,
            "eligible_for_training": manifest.eligible_for_training,
            "training_export_allowed": manifest.training_export_allowed,
            "model_version": manifest.provenance.model_version,
            "index_build_id": manifest.provenance.index_build_id,
            "policy_sha256": manifest.provenance.policy_sha256,
            "assessment_rules_sha256": manifest.provenance.assessment_rules_sha256,
        }

    def run_detail(self, run_id: str) -> dict[str, Any]:
        manifest = self.store.load_run_manifest(run_id)
        summary = self._run_summary(manifest)
        run_root = self.store.runs_root / run_id
        issue_index = run_root / "issues" / "index.jsonl"
        gap_index = run_root / "knowledge-gaps" / "index.jsonl"
        cases: list[dict[str, Any]] = []
        for ordinal, case_id in enumerate(EXPECTED_CASE_IDS, start=1):
            safe_case = _read_safe_object(run_root / "cases" / case_id / "case.json")
            if safe_case.get("case_id") != case_id:
                raise Live30AdminIntegrityError("safe case identity does not match its location")
            passes: list[dict[str, Any]] = []
            for pass_number in (1, 2, 3):
                path = run_root / "cases" / case_id / "outcomes" / f"pass-{pass_number}.json"
                if path.is_file():
                    outcome = _safe_outcome(
                        _read_safe_object(path),
                        case_id=case_id,
                        pass_number=pass_number,
                    )
                    if not outcome["repairs"]:
                        outcome["repairs"] = self._database_repairs(outcome["job_id"])
                    passes.append(outcome)
            latest = passes[-1] if passes else None
            cases.append(
                {
                    "case_id": case_id,
                    "ordinal": ordinal,
                    "status": latest["status"] if latest else "not_run",
                    "release_state": latest["release_state"] if latest else "not_run",
                    "released": bool(latest and latest["released"]),
                    "word_target": safe_case.get("word_target"),
                    "expected_research_route": _safe_string(
                        safe_case.get("expected_research_route")
                    ),
                    "expected_drafting_route": _safe_string(
                        safe_case.get("expected_drafting_route")
                    ),
                    "as_of_date": _safe_string(safe_case.get("as_of_date")),
                    "passes": passes,
                    "issues": _read_safe_index(issue_index, case_id=case_id, kind="issue"),
                    "knowledge_gaps": _read_safe_index(
                        gap_index, case_id=case_id, kind="knowledge_gap"
                    ),
                }
            )
        return {"run": summary, "cases": cases}

    def released_answer(self, *, run_id: str, case_id: str, pass_number: int) -> dict[str, Any]:
        if case_id not in EXPECTED_CASE_IDS or pass_number not in {1, 2, 3}:
            raise Live30AdminIntegrityError("invalid live-30 answer identity")
        # This validates the run ID and containment before constructing any
        # descendant path from a URL parameter.
        self.store.load_run_manifest(run_id)
        path = (
            self.store.runs_root
            / run_id
            / "cases"
            / case_id
            / "outcomes"
            / f"pass-{pass_number}.json"
        )
        outcome_raw = _read_safe_object(path)
        outcome = _safe_outcome(outcome_raw, case_id=case_id, pass_number=pass_number)
        artifact_id = _safe_string(outcome_raw.get("answer_artifact_id"))
        answer_sha256 = _safe_string(outcome_raw.get("answer_sha256"))
        if (
            not outcome["released"]
            or outcome["release_state"] not in PUBLIC_RELEASE_STATES
            or not outcome["privacy_passed"]
            or not outcome["evidence_passed"]
            or not artifact_id
            or not answer_sha256
        ):
            raise PermissionError("answer is not a released privacy-and-evidence-passed artifact")
        content = self.store.load_sensitive_artifact(
            run_id=run_id,
            case_id=case_id,
            kind=SensitiveArtifactKind.ANSWER,
            artifact_id=artifact_id,
        )
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != answer_sha256:
            raise Live30AdminIntegrityError("released answer digest does not match its outcome")
        folded = content.casefold()
        if contains_absolute_private_path(content) or any(
            identifier.casefold() in folded for identifier in self.owner_identifiers
        ):
            raise PermissionError("released answer failed the owner-view privacy recheck")
        return {
            "run_id": run_id,
            "case_id": case_id,
            "pass_number": pass_number,
            "release_state": outcome["release_state"],
            "word_count": outcome["word_count"],
            "answer_sha256": answer_sha256,
            "content": content,
        }
