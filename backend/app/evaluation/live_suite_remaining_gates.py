"""Fail-closed attempts at remaining Live60 live-run gates.

This module must not invent legal gold, Stage A scores, ACTIVE, rollback,
browser-recovery, readiness-green or O-04 records. It only inspects what
already exists and records why the next live-run step is refused.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_runtime_separation import (
    PATH_B_OVERLAY_SPAN_BLOCKER,
    PATH_B_SELECTED_ISSUE_COUNT,
    classify_live_and_live60_state,
)

REMAINING_GATES_SCHEMA = "legalbot.live60-remaining-gate-attempts.v1"
GATES_DIR = Path("data/evaluations/e2e/gates")
ACTIVE_POINTER = Path("data/indexes/ACTIVE.json")
PREVIOUS_POINTER = Path("data/indexes/PREVIOUS.json")
READINESS_REPORT = Path("data/reports/production-readiness.json")


def overlay_seal_blockers(ticks: Mapping[str, Any]) -> list[str]:
    blockers: list[str] = []
    qualified = int(ticks.get("qualified_issue_count") or 0)
    limited = int(ticks.get("limited_issue_count") or 0)
    gaps = int(ticks.get("knowledge_gap_issue_count") or 0)
    if qualified == 0 and limited == 0:
        blockers.append("no_qualified_or_limited_issue_with_exact_spans")
    if gaps == int(ticks.get("issue_count") or 0) and gaps > 0:
        blockers.append("all_issues_knowledge_gap_stage_a_cannot_pass")
    if ticks.get("overlay_sealable") is not True:
        blockers.append("overlay_not_sealable")
    if ticks.get("expert_qualification_sealed") is True:
        blockers.append("unexpected_existing_seal")
    return blockers


def try_seal_overlay_from_owner_ticks(
    *,
    ticks: Mapping[str, Any],
    destination: Path | None = None,
) -> dict[str, Any]:
    """Refuse to write expert-qualification.json unless ranking gold exists."""

    blockers = overlay_seal_blockers(ticks)
    sealed_path_exists = bool(destination and destination.is_file())
    payload = {
        "attempted": True,
        "sealed": False,
        "wrote_expert_qualification": False,
        "existing_sealed_overlay_present": sealed_path_exists,
        "qualified_issue_count": int(ticks.get("qualified_issue_count") or 0),
        "limited_issue_count": int(ticks.get("limited_issue_count") or 0),
        "knowledge_gap_issue_count": int(ticks.get("knowledge_gap_issue_count") or 0),
        "blocking_reason_codes": blockers,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
    }
    assert_safe_evaluation_payload(payload)
    if blockers:
        return payload
    raise ValueError(
        "owner ticks include ranking gold but overlay sealing still requires "
        "exact-match verified spans, contrary authority and currentness fields"
    )


def _present(path: Path) -> bool:
    return path.is_file()


def _readiness_v6_attempt(project_root: Path) -> dict[str, Any]:
    path = project_root / READINESS_REPORT
    blockers = ["readiness_v6_cannot_be_green_while_prior_gates_fail"]
    passed = False
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            gates = payload.get("blocking_gates")
            copied: list[str] = []
            if isinstance(gates, list) and all(isinstance(item, str) for item in gates):
                copied = [item for item in gates if item]
                if copied:
                    blockers = copied
            ready = payload.get("ready") is True and payload.get("status") == "ready"
            passed = bool(ready) and not copied
            if ready and not passed and "readiness_v6_blocking_gates_present" not in blockers:
                blockers.append("readiness_v6_blocking_gates_present")
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            blockers = ["readiness_report_unreadable"]
            passed = False
    return {
        "attempted": True,
        "passed": passed,
        "readiness_report_present": path.is_file(),
        "blocking_reason_codes": blockers,
    }


def attempt_remaining_live_run_gates(
    *,
    project_root: Path,
    ticks: Mapping[str, Any],
    official: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect remaining live-run gates. Never fabricate a pass."""

    try:
        overlay = try_seal_overlay_from_owner_ticks(
            ticks=ticks,
            destination=project_root / "data" / "evaluations" / "expert-qualification.json",
        )
    except ValueError:
        overlay = {
            "attempted": True,
            "sealed": False,
            "wrote_expert_qualification": False,
            "blocking_reason_codes": ["overlay_seal_requires_exact_match_verified_spans"],
        }
    active = project_root / ACTIVE_POINTER
    previous = project_root / PREVIOUS_POINTER
    rollback = project_root / GATES_DIR / "rollback-drill.json"
    browser = project_root / GATES_DIR / "browser-recovery-drill.json"
    o04_glob = list((project_root / "data" / "evaluations").glob("**/o04*.json"))
    attempts = {
        "overlay_sealed_from_owner_ticks": overlay,
        "run_date_candidate_frozen": {
            "attempted": True,
            "passed": False,
            "active_pointer_present": _present(active),
            "blocking_reason_codes": [
                "no_current_date_rights_qualified_candidate",
                "previous_current_law_candidates_superseded_or_failed",
            ],
        },
        "stage_a_all_60": {
            "attempted": True,
            "passed": False,
            "blocking_reason_codes": [
                "no_sealed_ranking_gold_overlay",
                "recall_at_5_requires_qualified_exact_spans",
            ],
        },
        "owner_promote_ACTIVE": {
            "attempted": True,
            "passed": False,
            "wrote_active_pointer": False,
            "active_pointer_present": _present(active),
            "blocking_reason_codes": ["owner_promotion_not_invoked", "no_passing_candidate"],
        },
        "rollback_and_repromotion": {
            "attempted": True,
            "passed": False,
            "previous_pointer_present": _present(previous),
            "rollback_drill_present": _present(rollback),
            "blocking_reason_codes": ["no_ACTIVE_to_roll_back", "rollback_drill_absent"],
        },
        "real_local_browser_recovery": {
            "attempted": True,
            "passed": False,
            "browser_recovery_present": _present(browser),
            "blocking_reason_codes": [
                "browser_recovery_requires_real_owner_observed_reload",
                "no_ACTIVE_ordinary_job",
            ],
        },
        "readiness_v6_green": _readiness_v6_attempt(project_root),
        "owner_O-04_exact_30_ids": {
            "attempted": True,
            "passed": False,
            "wrote_o04": False,
            "o04_artifact_count": len(o04_glob),
            "blocking_reason_codes": ["o04_must_be_owner_issued_not_code_issued"],
        },
    }
    for attempt in attempts.values():
        assert_safe_evaluation_payload(attempt)
    overlay_blockers = [str(item) for item in overlay.get("blocking_reason_codes") or () if item]
    overlay_sealed = overlay.get("sealed") is True
    if not overlay_sealed and PATH_B_OVERLAY_SPAN_BLOCKER not in overlay_blockers:
        overlay_blockers.append(PATH_B_OVERLAY_SPAN_BLOCKER)
    qualified = min(
        int(ticks.get("qualified_issue_count") or ticks.get("qualified") or 0),
        PATH_B_SELECTED_ISSUE_COUNT,
    )
    serving_index_present = _present(active)
    live_runtime_separation = classify_live_and_live60_state(
        serving_index_present=serving_index_present,
        previous_approved_active_present=serving_index_present,
        runtime_eligible_approved_source_count=1 if serving_index_present else 0,
        path_b_selected_qualified_with_spans=qualified,
        overlay_sealed=overlay_sealed,
        overlay_blockers=overlay_blockers,
    )
    payload = {
        "schema": REMAINING_GATES_SCHEMA,
        "fabricated_any_pass": False,
        "any_gate_passed": any(
            bool(attempt.get("passed") or attempt.get("sealed")) for attempt in attempts.values()
        ),
        "official_page_ticks_1_to_4_recorded": official is not None,
        "reviewer_policy": {
            "owner_is_primary_reviewer": True,
            "ai_role": "mechanical_accuracy_verifier_only",
            "ai_second_reviewer_forbidden": True,
        },
        "generation_authorised": False,
        "o04_authorised": False,
        "overlay_sealable": False,
        "runtime_blocked_by_path_b_span_gap": False,
        "evaluation_requires_owner_promoted_active": False,
        "evaluation_requires_o04": False,
        "live_runtime_separation": live_runtime_separation,
        "attempts": attempts,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    assert_safe_evaluation_payload(live_runtime_separation)
    assert_safe_evaluation_payload(
        {
            key: value
            for key, value in payload.items()
            if key not in {"attempts", "live_runtime_separation"}
        }
    )
    return payload
