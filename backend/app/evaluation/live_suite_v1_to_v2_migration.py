"""V1→V2 migration of the 305 selected Path-B issues without re-research.

Reuses the 77 hash-matched qualified issues as mechanical reuse that still
requires independent semantic attestation. Missing reviewed input is
UNREVIEWED/HOLD. A reason string alone is not a VERIFIED knowledge gap.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import load_live_evaluation_bundle
from .live_suite_gap_verification import GapVerificationV2
from .live_suite_official_materialise import classify_unmatched_official_candidate
from .live_suite_overlay_complete import overlay_complete_v2
from .live_suite_path_b import LIVE60_ROOT, selected_generation_case_ids
from .live_suite_span_accuracy import check_user_span_exact_match

MIGRATION_SCHEMA = "legalbot.live60-v1-to-v2-migration.v1"
DEFAULT_MIGRATION_PATH = Path("Live60-2026-08-16/artifacts/V1_TO_V2_MIGRATION.json")
HELD_STATUTE_REASONS = frozenset(
    {
        "held_statute_held-provision-01",
        "held_statute_held-provision-02",
        "held_statute_held-provision-03",
        "held_statute_held-provision-04",
    }
)


def _public_span(span: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "gold_span_id": span.get("gold_span_id"),
        "chunk_id": span.get("chunk_id"),
        "content_sha256": span.get("content_sha256"),
        "legal_locator": span.get("legal_locator"),
        "source_version_id": span.get("source_version_id"),
        "legal_authority_id": span.get("legal_authority_id"),
        "legal_role": span.get("legal_role"),
        "stable_source_id": span.get("stable_source_id"),
        "source_type": span.get("source_type"),
        "relevance_grade": span.get("relevance_grade"),
        "contrary_or_limiting": span.get("contrary_or_limiting"),
    }


def _mechanical_reuse(
    spans: list[dict[str, Any]],
    *,
    catalog_path: Path | None,
    repair: Mapping[str, Any] | None,
) -> str:
    if not spans:
        return "invalidated"
    if catalog_path is None and repair is None:
        return "mechanical_exact_reused"
    for span in spans:
        report = check_user_span_exact_match(
            chunk_id=str(span["chunk_id"]),
            content_sha256=str(span["content_sha256"]),
            legal_locator=str(span["legal_locator"]),
            source_version_id=span.get("source_version_id"),
            catalog_path=catalog_path,
            repair=repair,
            legal_authority_id=span.get("legal_authority_id"),
            legal_role=span.get("legal_role"),
        )
        if report.get("exact_match") is not True:
            return "invalidated"
    return "mechanical_exact_reused"


def migrate_selected_issue(
    *,
    row: Mapping[str, Any],
    bind: Mapping[str, Any] | None,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
    gap_verification: Mapping[str, Any] | GapVerificationV2 | None = None,
    semantic_result_seal_sha256: str | None = None,
) -> dict[str, Any]:
    """Migrate one selected issue. Never invent a span. Never auto-VERIFIED."""

    row_id = str(row.get("row_id") or f"{row.get('case_id')}:{row.get('issue_id')}")
    status = str(row.get("status") or "knowledge_gap")
    spans = [_public_span(span) for span in row.get("exact_gold_spans") or ()]
    bind_status = str((bind or {}).get("bind_status") or "")
    bind_reason = str((bind or {}).get("reason") or row.get("reason_code") or "")
    if status == "qualified" and spans:
        mechanical = _mechanical_reuse(spans, catalog_path=catalog_path, repair=repair)
        verified = mechanical == "mechanical_exact_reused" and bool(semantic_result_seal_sha256)
        return {
            "row_id": row_id,
            "case_id": row.get("case_id"),
            "issue_id": row.get("issue_id"),
            "disposition": "qualified" if mechanical != "invalidated" else "unreviewed",
            "final_verification_status": "VERIFIED" if verified else "HOLD",
            "migration_action": mechanical,
            "v2_classification": (
                "semantic_verified"
                if verified
                else "invalidated"
                if mechanical == "invalidated"
                else "semantic_reverify_required"
            ),
            "gap_reason": None,
            "limitation_reason": None,
            "exact_gold_spans": spans,
            "invented_span": False,
            "semantic_result_seal_sha256": semantic_result_seal_sha256,
            "semantic_verifier": "independent_required_no_new_source_hunt",
        }
    if bind_status == "candidate":
        pending = classify_unmatched_official_candidate(
            row_id=row_id,
            reason=bind_reason or "official_bytes_no_catalogue_or_repair_hash",
            ingested=False,
        )
        return {
            "row_id": row_id,
            "case_id": row.get("case_id"),
            "issue_id": row.get("issue_id"),
            "disposition": pending["disposition"],
            "final_verification_status": "HOLD",
            "migration_action": "pending_official_materialisation",
            "v2_classification": "pending_official_materialisation",
            "gap_reason": pending["reason_code"],
            "limitation_reason": None,
            "exact_gold_spans": [],
            "invented_span": False,
            "semantic_verifier": "not_applicable_until_exact_match",
        }
    reason = bind_reason or str(row.get("reason_code") or "no_safe_span")
    if reason in HELD_STATUTE_REASONS or reason.startswith("held_statute_"):
        reason = reason if reason.startswith("held_statute_") else f"held_statute_{reason}"
        action = "held_statute_keep_as_gap"
    elif "later_treatment" in reason:
        action = "later_treatment_missing_ids_keep_gap"
    else:
        action = "keep_gap_explicit_reason"
    gap_ok = False
    gap_payload: dict[str, Any] | None = None
    if gap_verification is not None:
        record = (
            gap_verification
            if isinstance(gap_verification, GapVerificationV2)
            else GapVerificationV2.model_validate(gap_verification)
        )
        gap_ok = True
        gap_payload = record.model_dump(mode="json", by_alias=True)
    return {
        "row_id": row_id,
        "case_id": row.get("case_id"),
        "issue_id": row.get("issue_id"),
        "disposition": "knowledge_gap",
        "final_verification_status": "VERIFIED" if gap_ok else "HOLD",
        "migration_action": action,
        "v2_classification": "gap_verified" if gap_ok else "gap_attestation_required",
        "gap_reason": reason,
        "limitation_reason": None,
        "exact_gold_spans": [],
        "invented_span": False,
        "gap_verification": gap_payload,
        "semantic_verifier": "not_applicable_until_gap_attestation",
    }


def build_v1_to_v2_migration(
    *,
    project_root: Path,
    reviewed_rows: Mapping[str, Any] | None = None,
    bind_result: Mapping[str, Any] | None = None,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bundle = load_live_evaluation_bundle(project_root / LIVE60_ROOT)
    selected_ids = set(selected_generation_case_ids(bundle))
    rows = list((reviewed_rows or {}).get("rows") or ())
    if not rows:
        empty_payload: dict[str, Any] = {
            "schema": MIGRATION_SCHEMA,
            "as_of_date": "2026-08-16",
            "suite_id": "live-evaluation-60-v1",
            "reviewed_rows_sha256": None,
            "selected_issue_count": 0,
            "counts": {
                "qualified": 0,
                "limited": 0,
                "knowledge_gap": 0,
                "pending_official_materialisation": 0,
                "unreviewed": 305,
                "selected_qualified": 0,
                "selected_limited": 0,
                "selected_verified_knowledge_gap": 0,
                "selected_knowledge_gap": 0,
                "selected_unreviewed": 305,
                "knowledge_gap_total": 0,
                "spans_bound": 0,
            },
            "migration_actions": {},
            "unreviewed_issue_count": 305,
            "review_overlay_complete": False,
            "final_verification_status": "UNREVIEWED",
            "blocking_reason_codes": ["reviewed_input_missing"],
            "re_research": False,
            "invented_span": False,
            "writes_active": False,
            "writes_o04": False,
            "issues": [],
        }
        assert_safe_evaluation_payload(
            {key: value for key, value in empty_payload.items() if key != "issues"}
        )
        return empty_payload
    bind_by = {str(item.get("row_id")): item for item in (bind_result or {}).get("issues") or ()}
    selected_rows = [
        row
        for row in rows
        if str(row.get("case_id")) in selected_ids
        or str(row.get("row_id", "")).split(":", 1)[0] in selected_ids
    ]
    migrated = [
        migrate_selected_issue(
            row=row,
            bind=bind_by.get(str(row.get("row_id"))),
            catalog_path=catalog_path,
            repair=repair,
        )
        for row in selected_rows
    ]
    counts = Counter(item["disposition"] for item in migrated)
    actions = Counter(item["migration_action"] for item in migrated)
    overlay = overlay_complete_v2(selected_issues=migrated, bundle=bundle)
    selected_qualified = int(counts.get("qualified") or 0)
    selected_limited = int(counts.get("limited") or 0)
    selected_unreviewed = int(overlay["unreviewed_issue_count"] or 0)
    selected_knowledge_gap = max(
        0, 305 - selected_qualified - selected_limited - selected_unreviewed
    )
    payload: dict[str, Any] = {
        "schema": MIGRATION_SCHEMA,
        "as_of_date": "2026-08-16",
        "suite_id": "live-evaluation-60-v1",
        "reviewed_rows_sha256": str(
            (reviewed_rows or {}).get("reviewed_rows_sha256")
            or (bind_result or {}).get("import", {}).get("reviewed_rows_sha256")
            or ""
        )
        or None,
        "selected_issue_count": len(migrated),
        "counts": {
            "qualified": selected_qualified,
            "limited": selected_limited,
            "knowledge_gap": int(counts.get("knowledge_gap") or 0),
            "pending_official_materialisation": int(
                counts.get("pending_official_materialisation") or 0
            ),
            "unreviewed": selected_unreviewed,
            "selected_qualified": selected_qualified,
            "selected_limited": selected_limited,
            "selected_unreviewed": selected_unreviewed,
            "selected_verified_knowledge_gap": sum(
                1
                for item in migrated
                if item["disposition"] == "knowledge_gap"
                and item["final_verification_status"] == "VERIFIED"
            ),
            "selected_knowledge_gap": selected_knowledge_gap,
            "knowledge_gap_total": 585 - selected_qualified - selected_limited,
            "spans_bound": sum(len(item["exact_gold_spans"]) for item in migrated),
        },
        "migration_actions": dict(sorted(actions.items())),
        "unreviewed_issue_count": overlay["unreviewed_issue_count"],
        "review_overlay_complete": overlay["review_overlay_complete"],
        "re_research": False,
        "invented_span": False,
        "writes_active": False,
        "writes_o04": False,
        "issues": migrated,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "issues"}
    )
    return payload


def write_v1_to_v2_migration(
    *,
    project_root: Path,
    reviewed_rows_path: Path | None = None,
    bind_result_path: Path | None = None,
    destination: Path | None = None,
) -> dict[str, Any]:
    reviewed = None
    bind = None
    if reviewed_rows_path and reviewed_rows_path.is_file():
        reviewed = json.loads(reviewed_rows_path.read_text(encoding="utf-8"))
    if bind_result_path and bind_result_path.is_file():
        bind = json.loads(bind_result_path.read_text(encoding="utf-8"))
    payload = build_v1_to_v2_migration(
        project_root=project_root,
        reviewed_rows=reviewed,
        bind_result=bind,
    )
    path = destination or (project_root / DEFAULT_MIGRATION_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload
