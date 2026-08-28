"""Honest Path-B full-run remaining-status record.

Inspects existing artifacts and records why overlay sealing, candidate/Stage A
and owner live gates cannot proceed. Never fabricates gold, ACTIVE, O-04 or a
Stage A pass.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite_current_state import CurrentLiveStateResolver, ticks_are_known_stale
from .live_suite_owner_control_confirm import write_unsigned_owner_control_templates
from .live_suite_remaining_gates import attempt_remaining_live_run_gates

FULL_RUN_STATUS_SCHEMA = "legalbot.live60-full-run-remaining-status.v1"
ARTIFACTS = Path("Live60-2026-08-16/artifacts")
DEFAULT_STATUS_PATH = ARTIFACTS / "full-run-remaining-status.json"
V2_REPAIR = ARTIFACTS / "held-span-contiguous-repair-v2.json"
TICKS = ARTIFACTS / "owner-tick-progress.json"
ROUTE = ARTIFACTS / "owner-route-selection.json"
SEALED_DECISIONS = ARTIFACTS / "owner-decisions-d1-d15-sealed.json"
SEALED_CONTRARY = ARTIFACTS / "contrary-authority-review-sealed.json"
EXPERT_OVERLAY = Path("data/evaluations/expert-qualification.json")
ACTIVE_POINTER = Path("data/indexes/ACTIVE.json")
PREVIOUS_POINTER = Path("data/indexes/PREVIOUS.json")


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("full-run status input is not a JSON object")
    return payload


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build_full_run_remaining_status(
    *,
    project_root: Path,
    as_of_date: date,
    write_unsigned_templates: bool = True,
) -> dict[str, Any]:
    artifacts = project_root / ARTIFACTS
    ticks = _read_json(project_root / TICKS) or {}
    route = _read_json(project_root / ROUTE) or {}
    repair = _read_json(project_root / V2_REPAIR) or {}
    if write_unsigned_templates:
        decisions_unsigned = artifacts / "owner-decisions-d1-d15-unsigned.json"
        contrary_unsigned = artifacts / "contrary-authority-review-unsigned.json"
        if not decisions_unsigned.is_file() or not contrary_unsigned.is_file():
            write_unsigned_owner_control_templates(
                destination_dir=artifacts,
                as_of_date=as_of_date,
                overwrite=False,
            )

    overlay_blockers = [
        "owner_evidence_reviews_absent",
        "selected_qualified_case_count_not_30",
        "selected_issues_missing_positive_exact_spans",
        "contrary_review_missing_or_unsealed",
        "owner_decisions_missing_or_unsealed",
        "held_statutes_still_hold",
        "overlay_not_sealable",
    ]
    if (project_root / SEALED_CONTRARY).is_file():
        overlay_blockers = [
            item for item in overlay_blockers if item != "contrary_review_missing_or_unsealed"
        ]
    if (project_root / SEALED_DECISIONS).is_file():
        overlay_blockers = [
            item for item in overlay_blockers if item != "owner_decisions_missing_or_unsealed"
        ]
    if repair.get("qualified") is True or repair.get("seals_expert_gold") is True:
        overlay_blockers.append("unexpected_repair_gold_seal")
    gold_eligible = [
        span for span in repair.get("repairs") or () if span.get("gold_eligible_candidate") is True
    ]

    resolver = CurrentLiveStateResolver(project_root=project_root, ticks=ticks)
    issue_state = resolver.authoritative_issue_state()
    remaining_ticks = {
        **ticks,
        "qualified_issue_count": int(issue_state["selected_qualified"]),
        "limited_issue_count": int(issue_state["selected_limited"]),
        "knowledge_gap_issue_count": int(issue_state["knowledge_gap"]),
        "issue_count": 585,
        "overlay_sealable": ticks.get("overlay_sealable"),
    }
    remaining = attempt_remaining_live_run_gates(
        project_root=project_root,
        ticks=remaining_ticks,
    )
    candidate_blockers = [
        "no_sealed_ranking_gold_overlay",
        "no_current_date_rights_qualified_candidate",
        "stage_a_requires_qualified_exact_spans",
    ]
    payload = {
        "schema": FULL_RUN_STATUS_SCHEMA,
        "as_of_date": as_of_date.isoformat(),
        "suite_id": "live-evaluation-60-v1",
        "route": route.get("route") or "path_b",
        "target": route.get("target") or "full_30_answer_run",
        "current_issue_state": {
            "knowledge_gap": int(issue_state["knowledge_gap"]),
            "limited": int(issue_state["limited"]),
            "qualified": int(issue_state["qualified"]),
            "spans_bound": int(issue_state["spans_bound"]),
            "selected_qualified": int(issue_state["selected_qualified"]),
            "selected_limited": int(issue_state["selected_limited"]),
            "selected_knowledge_gap": int(issue_state["selected_knowledge_gap"]),
            "reviewed_rows_sha256": issue_state["reviewed_rows_sha256"],
        },
        "stale_tick_progress_ignored": ticks_are_known_stale(ticks),
        "path_b_overlay": {
            "attempted": True,
            "sealed": False,
            "wrote_expert_qualification": (project_root / EXPERT_OVERLAY).is_file(),
            "unsigned_owner_control_templates_present": (
                (artifacts / "owner-decisions-d1-d15-unsigned.json").is_file()
                and (artifacts / "contrary-authority-review-unsigned.json").is_file()
            ),
            "owner_authored_decisions_present": (project_root / SEALED_DECISIONS).is_file(),
            "owner_authored_contrary_present": (project_root / SEALED_CONTRARY).is_file(),
            "held_span_repair_schema": repair.get("schema"),
            "held_span_repair_qualified": bool(repair.get("qualified")),
            "v2_gold_eligible_repair_count": len(gold_eligible),
            "blocking_reason_codes": overlay_blockers,
        },
        "candidate_stage_a": {
            "attempted": True,
            "passed": False,
            "candidate_built": False,
            "promoted": False,
            "blocking_reason_codes": candidate_blockers,
        },
        "owner_live_gates": remaining["attempts"],
        "fabricated_any_pass": False,
        "any_gate_passed": False,
        "generation_authorised": False,
        "o04_authorised": False,
        "runtime_blocked_by_path_b_span_gap": False,
        "live_runtime_separation": remaining.get("live_runtime_separation"),
        "writes_active": False,
        "writes_previous": False,
        "writes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
        "active_pointer_present": (project_root / ACTIVE_POINTER).is_file(),
        "previous_pointer_present": (project_root / PREVIOUS_POINTER).is_file(),
    }
    assert_safe_evaluation_payload(
        {
            key: value
            for key, value in payload.items()
            if key
            not in {
                "owner_live_gates",
                "path_b_overlay",
                "candidate_stage_a",
                "current_issue_state",
                "live_runtime_separation",
            }
        }
    )
    return payload


def write_full_run_remaining_status(
    *,
    project_root: Path,
    as_of_date: date,
    destination: Path | None = None,
) -> dict[str, Any]:
    payload = build_full_run_remaining_status(
        project_root=project_root,
        as_of_date=as_of_date,
    )
    path = destination or (project_root / DEFAULT_STATUS_PATH)
    _write_json(path, payload)
    return payload
