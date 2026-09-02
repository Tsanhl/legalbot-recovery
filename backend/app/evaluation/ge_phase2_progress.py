"""Case-scoped Phase 2 progress. One held case is not a global stall."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

GLOBAL_HARD_STOP_REASONS = (
    "manifest_or_hash_mismatch",
    "corrupt_or_untraceable_source_bytes",
    "mandatory_evaluator_regression_failure",
    "integrity_or_privacy_failure",
    "zero_runnable_visible_cases",
    "explicit_owner_stop",
)


def phase2_progress(
    *,
    case_results: Sequence[Mapping[str, Any]],
    hard_stop_reasons: Sequence[str] = (),
    locator_hold_count: int = 0,
    locator_pending_count: int = 0,
    locator_reject_count: int = 0,
) -> dict[str, Any]:
    reasons = [str(item) for item in hard_stop_reasons if str(item).strip()]
    if not case_results and "zero_runnable_visible_cases" not in reasons:
        reasons.append("zero_runnable_visible_cases")
    global_hard_stop = bool(reasons)
    held: list[str] = []
    for row in case_results:
        factual = row.get("factual_result")
        outcome = ""
        if isinstance(factual, Mapping):
            outcome = str(factual.get("outcome") or "")
        if outcome != "FACTUAL_PASS":
            held.append(str(row.get("case_id") or row.get("ordinal") or ""))
    if global_hard_stop:
        state = "HARD_STOP"
    elif held:
        state = "RUNNING_WITH_CASE_BLOCKERS"
    else:
        state = "RUNNING"
    return {
        "schema": "legalbot.ge-phase2-progress-and-blocker-ledger.v1",
        "overall_progress": not global_hard_stop,
        "overall_state": state,
        "global_hard_stop": global_hard_stop,
        "hard_stop_reasons": reasons,
        "runnable_visible_cases": len(case_results),
        "held_or_fail_closed_cases": len(held),
        "held_case_ids": held,
        "locator_hold_count": locator_hold_count,
        "locator_pending_count": locator_pending_count,
        "locator_reject_count": locator_reject_count,
        "one_held_case_sets_global_progress_false": False,
        "continue_independent_work": not global_hard_stop,
    }
