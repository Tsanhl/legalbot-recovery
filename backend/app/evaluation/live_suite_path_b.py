"""Path-B reviewed-row export, import, overlay reconstruction and owner seal.

AI cannot be a reviewer. Named qualifies still require exact spans.
This module never writes ACTIVE.json, PREVIOUS.json or O-04.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import Any, Literal

from ..crypto import LocalCipher
from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, load_live_evaluation_bundle, sealed_sha256
from .live_suite_gold import (
    GOLD_CASE_SCHEMA,
    GOLD_ISSUE_SCHEMA,
    GOLD_SCHEMA,
    LiveSuiteExpertQualification,
)
from .live_suite_owner_decisions import apply_owner_ticks
from .live_suite_reviewer_identity import OWNER_REVIEWER_ROLE
from .live_suite_span_accuracy import verify_user_span_exact_match

REVIEW_EXPORT_SCHEMA = "legalbot.live60-review-export.v1"
REVIEW_IMPORT_SCHEMA = "legalbot.live60-review-import.v1"
OVERLAY_RECONSTRUCTION_SCHEMA = "legalbot.live60-overlay-reconstruction.v1"
OWNER_SEAL_ATTEMPT_SCHEMA = "legalbot.live60-owner-overlay-seal.v1"
ALLOWED_STATUSES = frozenset({"qualified", "limited", "knowledge_gap"})
LIVE60_ROOT = Path("benchmarks/evaluation/live-evaluation-60-v1")
FULL_RUN_SELECTED_CASE_COUNT = 30
FULL_RUN_SELECTED_ISSUE_COUNT = 305
DEFAULT_V2_REPAIR = Path("Live60-2026-08-16/artifacts/held-span-contiguous-repair-v2.json")
UNRESOLVED_CONTRARY = frozenset(
    {"", "blank", "unresolved", "reviewed_none", "reviewed_none_in_defined_source_set"}
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value))
    path.chmod(0o600)


def _issue_rows(bundle: LiveEvaluationBundle) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in bundle.registry.cases:
        plan = next(item for item in bundle.run_plan.cases if item.case_id == case.case_id)
        for number, topic in enumerate(case.must_cover_issues, start=1):
            rows.append(
                {
                    "row_id": f"{case.case_id}:issue-{number:02d}",
                    "case_id": case.case_id,
                    "issue_id": f"issue-{number:02d}",
                    "topic_sha256": hashlib.sha256(topic.encode("utf-8")).hexdigest(),
                    "question_sha256": case.question_sha256,
                    "record_sha256": case.record_sha256,
                    "generation_disposition": plan.disposition,
                    "status": "knowledge_gap",
                    "exact_gold_spans": [],
                    "contrary_authority_status": "blank",
                }
            )
    return rows


def export_review_candidates(
    *,
    project_root: Path,
    destination: Path,
    cipher: LocalCipher,
    as_of_date: date,
    ticks: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Write sealed candidate rows. Plaintext span preview is encrypted only."""

    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    rows = _issue_rows(bundle)
    by_id = {row["row_id"]: row for row in rows}
    preview_rows: list[dict[str, Any]] = []
    for case in (ticks or {}).get("cases", ()):
        for issue in case.get("issues", ()):
            row_id = f"{case['case_id']}:{issue['issue_id']}"
            if row_id not in by_id:
                raise ValueError("tick names an issue that is not in the frozen pack")
            status = str(issue.get("status") or issue.get("owner_tick") or "knowledge_gap")
            if status not in ALLOWED_STATUSES:
                raise ValueError("tick status is not an allowed owner disposition")
            spans = list(issue.get("exact_gold_spans") or ())
            by_id[row_id]["status"] = status
            by_id[row_id]["exact_gold_spans"] = [
                {
                    key: span[key]
                    for key in (
                        "chunk_id",
                        "content_sha256",
                        "legal_locator",
                        "source_version_id",
                        "legal_authority_id",
                        "parent_chunk_id",
                        "legal_role",
                        "official_snapshot_sha256",
                        "derivation_manifest_sha256",
                    )
                    if span.get(key)
                }
                for span in spans
            ]
            if spans:
                preview_rows.append(
                    {
                        "row_id": row_id,
                        "span_previews": [
                            {"legal_locator": span.get("legal_locator")} for span in spans
                        ],
                    }
                )
    ordered = [by_id[row["row_id"]] for row in rows]
    if len(ordered) != 585:
        raise ValueError("review export must contain exactly 585 issue rows")
    export_id = f"live60-review-export-{as_of_date.isoformat()}"
    preview_object = f"{export_id}.preview.enc"
    encrypted = cipher.encrypt_text(json.dumps(preview_rows, sort_keys=True))
    object_dir = destination.parent / "encrypted"
    object_dir.mkdir(parents=True, exist_ok=True)
    preview_path = object_dir / preview_object
    preview_path.write_bytes(encrypted)
    preview_path.chmod(0o600)
    payload = {
        "schema": REVIEW_EXPORT_SCHEMA,
        "export_id": export_id,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date.isoformat(),
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "issue_count": 585,
        "row_count": len(ordered),
        "rows": ordered,
        "plaintext_span_preview": "encrypted_object_only",
        "encrypted_preview_object": preview_object,
        "encrypted_preview_sha256": _sha256_bytes(encrypted),
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
        "seals_expert_gold": False,
        "writes_active": False,
        "writes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    payload["export_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload({key: value for key, value in payload.items() if key != "rows"})
    dumped = json.dumps(payload)
    if '"question":' in dumped:
        raise ValueError("review export must not contain question prose")
    _write_json(destination, payload)
    return {
        "schema": REVIEW_EXPORT_SCHEMA,
        "export_path": str(destination),
        "export_sha256": payload["export_sha256"],
        "row_count": 585,
        "encrypted_preview_object": preview_object,
        "seals_expert_gold": False,
        "writes_active": False,
    }


def import_reviewed_rows(
    *,
    project_root: Path,
    export_path: Path,
    reviewed_path: Path,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Accept only rows that match the sealed export. Re-check identities."""

    export = json.loads(export_path.read_text(encoding="utf-8"))
    if export.get("schema") != REVIEW_EXPORT_SCHEMA:
        raise ValueError("review import requires a path-B export")
    expected = dict(export)
    expected.pop("export_sha256", None)
    if sealed_sha256(expected) != export.get("export_sha256"):
        raise ValueError("review export seal does not match its contents")
    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    if export["suite_registry_canonical_sha256"] != bundle.registry.canonical_sha256:
        raise ValueError("review export is bound to a different registry")
    if export["run_plan_sha256"] != bundle.manifest.run_plan_sha256:
        raise ValueError("review export is bound to a different run plan")
    reviewed = json.loads(reviewed_path.read_text(encoding="utf-8"))
    if reviewed.get("schema") not in {REVIEW_IMPORT_SCHEMA, REVIEW_EXPORT_SCHEMA}:
        raise ValueError("reviewed rows use an unsupported schema")
    if reviewed.get("reviewer_identity") in {"ai", "model", "assistant"}:
        raise ValueError("AI cannot be a Live60 reviewer")
    export_ids = {row["row_id"]: row for row in export["rows"]}
    imported: list[dict[str, Any]] = []
    for row in reviewed.get("rows", ()):
        row_id = str(row.get("row_id") or "")
        if row_id not in export_ids:
            raise ValueError("reviewed row is not in the sealed export")
        source = export_ids[row_id]
        if row.get("case_id") != source["case_id"] or row.get("issue_id") != source["issue_id"]:
            raise ValueError("reviewed row identity does not match the export")
        status = str(row.get("status") or "")
        if status not in ALLOWED_STATUSES:
            raise ValueError("reviewed row status is not an allowed owner disposition")
        spans = list(row.get("exact_gold_spans") or ())
        if status in {"qualified", "limited"} and not spans:
            raise ValueError("named qualify ticks require exact spans; none were supplied")
        for span in spans:
            verify_user_span_exact_match(
                chunk_id=str(span["chunk_id"]),
                content_sha256=str(span["content_sha256"]),
                legal_locator=str(span["legal_locator"]),
                source_version_id=span.get("source_version_id"),
                legal_authority_id=span.get("legal_authority_id"),
                parent_chunk_id=span.get("parent_chunk_id"),
                legal_role=span.get("legal_role") or span.get("role"),
                official_snapshot_sha256=span.get("official_snapshot_sha256"),
                derivation_manifest_sha256=span.get("derivation_manifest_sha256"),
                catalog_path=catalog_path,
                repair=repair,
            )
        imported.append(
            {
                "row_id": row_id,
                "case_id": source["case_id"],
                "issue_id": source["issue_id"],
                "status": status,
                "exact_gold_spans": spans,
                "question_sha256": source["question_sha256"],
                "record_sha256": source["record_sha256"],
                "topic_sha256": source["topic_sha256"],
                "contrary_authority_status": _imported_contrary_status(row),
            }
        )
    payload = {
        "schema": REVIEW_IMPORT_SCHEMA,
        "export_sha256": export["export_sha256"],
        "suite_id": export["suite_id"],
        "as_of_date": export["as_of_date"],
        "suite_registry_canonical_sha256": export["suite_registry_canonical_sha256"],
        "run_plan_sha256": export["run_plan_sha256"],
        "imported_row_count": len(imported),
        "rows": imported,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "seals_expert_gold": False,
        "writes_active": False,
        "writes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    assert_safe_evaluation_payload({key: value for key, value in payload.items() if key != "rows"})
    return payload


def _imported_contrary_status(row: Mapping[str, Any]) -> str:
    status = str(row.get("contrary_authority_status") or "unresolved")
    if status == "reviewed_and_bound":
        return "reviewed_and_bound"
    return "unresolved"


def _case_has_contrary_spans(case: Mapping[str, Any]) -> bool:
    return any(
        bool(span.get("contrary_or_limiting"))
        for issue in case.get("issues") or ()
        for span in issue.get("exact_gold_spans") or ()
    )


def _hold_seal_payload(blockers: Sequence[str]) -> dict[str, Any]:
    payload = {
        "schema": OWNER_SEAL_ATTEMPT_SCHEMA,
        "attempted": True,
        "sealed": False,
        "wrote_expert_qualification": False,
        "approval_status": "uncertain_hold",
        "writes_active": False,
        "writes_o04": False,
        "blocking_reason_codes": list(blockers),
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    assert_safe_evaluation_payload(payload)
    return payload


def reconstruct_overlay(
    *,
    project_root: Path,
    imported: Mapping[str, Any],
    as_of_date: date,
) -> dict[str, Any]:
    """Rebuild explicit dispositions for all 585 issues. Does not seal gold."""

    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    by_id = {row["row_id"]: row for row in imported.get("rows", ())}
    selected_ids = set(selected_generation_case_ids(bundle))
    cases: list[dict[str, Any]] = []
    missing: list[str] = []
    counts = {"qualified": 0, "limited": 0, "knowledge_gap": 0}
    selected_issue_count = 0
    selected_qualified_issue_count = 0
    selected_positive_span_issue_count = 0
    selected_qualified_case_count = 0
    issue_identities: list[dict[str, str]] = []
    for case in bundle.registry.cases:
        issues: list[dict[str, Any]] = []
        case_contrary = "unresolved"
        for number, topic in enumerate(case.must_cover_issues, start=1):
            row_id = f"{case.case_id}:issue-{number:02d}"
            row = by_id.get(row_id)
            if row is None:
                missing.append(row_id)
                continue
            status = str(row["status"])
            if status not in ALLOWED_STATUSES:
                raise ValueError("overlay reconstruction requires an explicit disposition")
            counts[status] += 1
            if status == "qualified":
                reason: str | None = None
            elif status == "limited":
                reason = "owner_confirmed_limited_support"
            else:
                reason = "owner_confirmed_knowledge_gap"
            row_contrary = _imported_contrary_status(row)
            if row_contrary == "reviewed_and_bound":
                case_contrary = "reviewed_and_bound"
            issues.append(
                {
                    "schema": GOLD_ISSUE_SCHEMA,
                    "issue_id": f"issue-{number:02d}",
                    "status": status,
                    "reason_code": reason,
                    "exact_gold_spans": list(row.get("exact_gold_spans") or ()),
                }
            )
            issue_identities.append(
                {
                    "row_id": row_id,
                    "case_id": case.case_id,
                    "issue_id": f"issue-{number:02d}",
                    "question_sha256": str(row.get("question_sha256") or case.question_sha256),
                    "record_sha256": str(row.get("record_sha256") or case.record_sha256),
                    "topic_sha256": str(
                        row.get("topic_sha256") or hashlib.sha256(topic.encode("utf-8")).hexdigest()
                    ),
                }
            )
        statuses = {issue["status"] for issue in issues}
        if statuses == {"qualified"}:
            case_status: Literal["qualified", "limited", "knowledge_gap"] = "qualified"
        elif statuses == {"knowledge_gap"}:
            case_status = "knowledge_gap"
        else:
            case_status = "limited"
        source_ids = sorted(
            {
                str(span["stable_source_id"])
                for issue in issues
                for span in issue["exact_gold_spans"]
                if span.get("stable_source_id")
            }
        )
        cases.append(
            {
                "schema": GOLD_CASE_SCHEMA,
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": case_status,
                "contrary_authority_status": case_contrary,
                "acceptable_source_ids": source_ids,
                "issues": issues,
            }
        )
        if case.case_id in selected_ids:
            selected_issue_count += len(issues)
            if case_status == "qualified":
                selected_qualified_case_count += 1
            for issue in issues:
                if issue["status"] == "qualified":
                    selected_qualified_issue_count += 1
                if issue["status"] == "qualified" and issue["exact_gold_spans"]:
                    selected_positive_span_issue_count += 1
    if missing:
        raise ValueError("overlay reconstruction requires all 585 explicit dispositions")
    payload = {
        "schema": OVERLAY_RECONSTRUCTION_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date.isoformat(),
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "issue_count": 585,
        "case_count": 60,
        "qualified_issue_count": counts["qualified"],
        "limited_issue_count": counts["limited"],
        "knowledge_gap_issue_count": counts["knowledge_gap"],
        "selected_case_count": FULL_RUN_SELECTED_CASE_COUNT,
        "selected_qualified_case_count": selected_qualified_case_count,
        "selected_issue_count": selected_issue_count,
        "selected_qualified_issue_count": selected_qualified_issue_count,
        "selected_positive_span_issue_count": selected_positive_span_issue_count,
        "full_run_overlay_ready": (
            selected_qualified_case_count == FULL_RUN_SELECTED_CASE_COUNT
            and selected_qualified_issue_count == FULL_RUN_SELECTED_ISSUE_COUNT
            and selected_positive_span_issue_count == FULL_RUN_SELECTED_ISSUE_COUNT
        ),
        "cases": cases,
        "issue_identities": issue_identities,
        "seals_expert_gold": False,
        "overlay_sealable": False,
        "writes_active": False,
        "writes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key not in {"cases", "issue_identities"}}
    )
    return payload


def _verify_issue_identities(
    *,
    bundle: LiveEvaluationBundle,
    reconstruction: Mapping[str, Any],
) -> list[str]:
    blockers: list[str] = []
    identities = list(reconstruction.get("issue_identities") or ())
    expected: dict[str, dict[str, str]] = {}
    for case in bundle.registry.cases:
        for number, topic in enumerate(case.must_cover_issues, start=1):
            row_id = f"{case.case_id}:issue-{number:02d}"
            expected[row_id] = {
                "row_id": row_id,
                "case_id": case.case_id,
                "issue_id": f"issue-{number:02d}",
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "topic_sha256": hashlib.sha256(topic.encode("utf-8")).hexdigest(),
            }
    if len(identities) != 585 or {item.get("row_id") for item in identities} != set(expected):
        blockers.append("issue_identity_mismatch")
        return blockers
    for item in identities:
        want = expected[str(item["row_id"])]
        for key in (
            "case_id",
            "issue_id",
            "question_sha256",
            "record_sha256",
            "topic_sha256",
        ):
            if str(item.get(key) or "") != want[key]:
                blockers.append("proposition_identity_mismatch")
                return blockers
    return blockers


def _full_run_seal_blockers(
    reconstruction: Mapping[str, Any],
    bundle: LiveEvaluationBundle,
) -> list[str]:
    """Path B full-30 overlay may seal only when every selected issue is qualified."""

    selected_ids = set(selected_generation_case_ids(bundle))
    selected_cases = [
        case for case in reconstruction.get("cases") or () if case.get("case_id") in selected_ids
    ]
    blockers: list[str] = []
    selected_issues = [issue for case in selected_cases for issue in case.get("issues") or ()]
    qualified_cases = [case for case in selected_cases if case.get("status") == "qualified"]
    qualified_with_spans = [
        issue
        for issue in selected_issues
        if issue.get("status") == "qualified" and issue.get("exact_gold_spans")
    ]
    if len(selected_cases) != FULL_RUN_SELECTED_CASE_COUNT:
        blockers.append("selected_case_count_not_30")
    if len(qualified_cases) != FULL_RUN_SELECTED_CASE_COUNT:
        blockers.append("selected_qualified_case_count_not_30")
    if len(selected_issues) != FULL_RUN_SELECTED_ISSUE_COUNT:
        blockers.append("selected_issue_count_not_305")
    if len(qualified_with_spans) != FULL_RUN_SELECTED_ISSUE_COUNT:
        blockers.append("selected_issues_missing_positive_exact_spans")
    return blockers


def load_default_v2_repair(project_root: Path) -> dict[str, Any] | None:
    path = project_root / DEFAULT_V2_REPAIR
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("default held-span repair is not a JSON object")
    if payload.get("schema") != "legalbot.live60-held-span-contiguous-repair.v2":
        raise ValueError("default held-span repair is not the accepted v2 artifact")
    return payload


def _apply_sealed_contrary(
    cases: Sequence[Mapping[str, Any]],
    contrary: Any,
) -> tuple[list[dict[str, Any]], list[str]]:
    blockers: list[str] = []
    if contrary.status == "needs_independent_second_review":
        return [dict(case) for case in cases], ["contrary_review_unresolved"]
    if contrary.independent_second_review_status == "needs_independent_review":
        return [dict(case) for case in cases], ["contrary_review_unresolved"]
    updated: list[dict[str, Any]] = []
    for case in cases:
        payload = dict(case)
        incoming = str(payload.get("contrary_authority_status") or "unresolved")
        if incoming in UNRESOLVED_CONTRARY:
            incoming = "unresolved"
        has_contrary = _case_has_contrary_spans(payload)
        if contrary.status == "reviewed_none_in_defined_source_set":
            if has_contrary:
                blockers.append("contrary_none_conflicts_with_bound_spans")
                payload["contrary_authority_status"] = "unresolved"
            else:
                payload["contrary_authority_status"] = "reviewed_none"
        elif contrary.status == "reviewed_and_bound":
            if has_contrary or incoming == "reviewed_and_bound":
                payload["contrary_authority_status"] = "reviewed_and_bound"
            else:
                blockers.append("contrary_bound_unresolved_for_case")
                payload["contrary_authority_status"] = "unresolved"
        else:
            blockers.append("contrary_review_unresolved")
            payload["contrary_authority_status"] = "unresolved"
        updated.append(payload)
    return updated, blockers


def seal_overlay_from_reviewed_rows(
    *,
    project_root: Path,
    reconstruction: Mapping[str, Any],
    reviewer_ref: str,
    index_build_id: str,
    destination: Path | None = None,
    run_id: str | None = None,
    contrary_review_path: Path | None = None,
    owner_decisions_path: Path | None = None,
    require_full_30_selected: bool = True,
) -> dict[str, Any]:
    """Owner-only seal bound to sealed contrary-review and D1-D15 artifacts.

    The live Path-B full-30 route refuses an overlay unless all 30 selected
    cases are qualified with positive exact spans. Coverage-only gaps may remain.
    """

    from .live_suite_contrary_authority import load_contrary_authority_review
    from .live_suite_owner_decision_contract import load_owner_decisions

    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    blockers: list[str] = []
    if not run_id:
        blockers.append("run_id_missing")
    if contrary_review_path is None or not contrary_review_path.is_file():
        blockers.append("contrary_review_missing_or_unresolved")
    if owner_decisions_path is None or not owner_decisions_path.is_file():
        blockers.append("owner_decisions_missing_or_unsealed")
    if not reviewer_ref.startswith("reviewer:") or len(reviewer_ref) != len("reviewer:") + 64:
        blockers.append("owner_reviewer_ref_invalid")
    if "ai" in reviewer_ref.casefold():
        blockers.append("ai_reviewer_forbidden")
    if reconstruction.get("issue_count") != 585:
        blockers.append("issue_count_not_585")
    if reconstruction.get("suite_registry_canonical_sha256") != bundle.registry.canonical_sha256:
        blockers.append("registry_mismatch")
    if reconstruction.get("run_plan_sha256") != bundle.manifest.run_plan_sha256:
        blockers.append("run_plan_mismatch")
    as_of = date.fromisoformat(str(reconstruction.get("as_of_date")))
    cases = list(reconstruction.get("cases") or ())
    if len(cases) != 60:
        blockers.append("case_count_not_60")
    blockers.extend(_verify_issue_identities(bundle=bundle, reconstruction=reconstruction))
    if require_full_30_selected:
        blockers.extend(_full_run_seal_blockers(reconstruction, bundle))

    contrary = None
    decisions = None
    if "contrary_review_missing_or_unresolved" not in blockers:
        assert contrary_review_path is not None
        try:
            contrary = load_contrary_authority_review(contrary_review_path)
        except (OSError, UnicodeError, ValueError, TypeError):
            blockers.append("contrary_review_missing_or_unresolved")
    if "owner_decisions_missing_or_unsealed" not in blockers:
        assert owner_decisions_path is not None
        try:
            decisions = load_owner_decisions(owner_decisions_path)
        except (OSError, UnicodeError, ValueError, TypeError):
            blockers.append("owner_decisions_missing_or_unsealed")
    if contrary is not None:
        if contrary.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256:
            blockers.append("contrary_registry_mismatch")
        if contrary.run_plan_sha256 != bundle.manifest.run_plan_sha256:
            blockers.append("contrary_run_plan_mismatch")
        if contrary.as_of_date != as_of.isoformat():
            blockers.append("contrary_legal_date_mismatch")
        if contrary.index_build_id != index_build_id:
            blockers.append("contrary_build_mismatch")
        if contrary.run_id != run_id:
            blockers.append("contrary_run_mismatch")
        if contrary.defined_source_set_reviewed_as_of_date != as_of.isoformat():
            blockers.append("contrary_source_set_date_mismatch")
    if decisions is not None:
        if decisions.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256:
            blockers.append("owner_decisions_registry_mismatch")
        if decisions.run_plan_sha256 != bundle.manifest.run_plan_sha256:
            blockers.append("owner_decisions_run_plan_mismatch")
        if decisions.as_of_date != as_of.isoformat():
            blockers.append("owner_decisions_legal_date_mismatch")
        if decisions.index_build_id != index_build_id:
            blockers.append("owner_decisions_build_mismatch")
        if decisions.run_id != run_id:
            blockers.append("owner_decisions_run_mismatch")
    if contrary is not None:
        cases, contrary_blockers = _apply_sealed_contrary(cases, contrary)
        blockers.extend(contrary_blockers)
    if blockers or contrary is None or decisions is None:
        return _hold_seal_payload(blockers or ["contrary_review_missing_or_unresolved"])

    overlay = {
        "schema": GOLD_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "index_build_id": index_build_id,
        "as_of_date": as_of.isoformat(),
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "expert_approved",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": OWNER_REVIEWER_ROLE,
        "approval_reviewer_ref": reviewer_ref,
        "owner_is_primary_reviewer": True,
        "independent_second_review_status": contrary.independent_second_review_status,
        "independent_second_reviewer_role": None,
        "independent_second_reviewer_ref": None,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": 60,
        "cases": cases,
    }
    overlay["seal_sha256"] = sealed_sha256(overlay)
    try:
        qualification = LiveSuiteExpertQualification.model_validate(overlay)
    except Exception:
        return _hold_seal_payload(["overlay_failed_expert_qualification_validation"])
    payload = {
        "schema": OWNER_SEAL_ATTEMPT_SCHEMA,
        "attempted": True,
        "sealed": True,
        "wrote_expert_qualification": False,
        "approval_status": "expert_approved",
        "writes_active": False,
        "writes_o04": False,
        "blocking_reason_codes": [],
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "seal_sha256": qualification.seal_sha256,
    }
    if destination is not None:
        _write_json(destination, qualification.model_dump(mode="json", by_alias=True))
        payload["wrote_expert_qualification"] = True
    assert_safe_evaluation_payload(payload)
    return payload


def apply_owner_ticks_still_fail_closed(
    *,
    bundle: LiveEvaluationBundle,
    identity: Mapping[str, Any],
    issue_pack: Mapping[str, Any],
    mechanical: Mapping[str, Any],
    qualified_issue_ids: Sequence[str],
) -> None:
    apply_owner_ticks(
        bundle=bundle,
        identity=identity,
        issue_pack=issue_pack,
        mechanical=mechanical,
        contrary_authority_status=None,
        qualified_issue_ids=qualified_issue_ids,
    )


def selected_generation_case_ids(bundle: LiveEvaluationBundle) -> tuple[str, ...]:
    return tuple(
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    )


def frozen_selected_issue_identities(
    bundle: LiveEvaluationBundle,
) -> tuple[dict[str, str], ...]:
    """Exact 305 selected issue identities bound to the frozen 30 cases."""

    selected = set(selected_generation_case_ids(bundle))
    return tuple(
        {
            "row_id": str(row["row_id"]),
            "case_id": str(row["case_id"]),
            "issue_id": str(row["issue_id"]),
            "topic_sha256": str(row["topic_sha256"]),
            "question_sha256": str(row["question_sha256"]),
            "record_sha256": str(row["record_sha256"]),
        }
        for row in _issue_rows(bundle)
        if row["case_id"] in selected
    )


def overlay_complete_from_dispositions_v2(
    reconstruction: Mapping[str, Any],
    bundle: LiveEvaluationBundle,
) -> dict[str, Any]:
    """V2 completeness from verified dispositions. V1 blockers remain for audit."""

    from .live_suite_overlay_complete import (
        overlay_complete_v2,
        selected_issues_from_reconstruction,
    )

    selected_ids = selected_generation_case_ids(bundle)
    issues = selected_issues_from_reconstruction(reconstruction, selected_ids)
    selected_cases = [
        case
        for case in reconstruction.get("cases") or ()
        if case.get("case_id") in set(selected_ids)
    ]
    payload = overlay_complete_v2(
        selected_issues=issues,
        selected_cases=selected_cases,
        bundle=bundle,
    )
    payload["v1_seal_blockers"] = _full_run_seal_blockers(reconstruction, bundle)
    return payload
