"""Separate ordinary LIVE runtime from Live60 Path-B overlay promotion.

The 305/305 selected-issue contract remains the overlay seal and Live60
promotion gate. It must not hold the ordinary serving runtime, replace an
existing ACTIVE pointer, or admit unapproved candidate evidence.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

PATH_B_SELECTED_ISSUE_COUNT = 305
PATH_B_OVERLAY_SPAN_BLOCKER = "selected_issues_missing_positive_exact_spans"
LIVE60_BENCHMARK_HARD_GATE_KEYS = frozenset(
    {
        "sealed_expert_overlay",
        "stage_a_coverage_and_thresholds",
    }
)

RuntimeStatus = Literal["NOT_SERVING", "LIVE", "DEGRADED"]
EvaluationCandidateState = Literal[
    "BUILDING",
    "EVIDENCE_REVIEW",
    "REVIEW_COMPLETE",
    "STAGE_A_READY",
    "EVALUATION_READY",
    "EVALUATING",
    "EVALUATED",
    "FAILED",
]
ProductionPromotionState = Literal[
    "NOT_ELIGIBLE",
    "ELIGIBLE",
    "AWAITING_OPERATOR",
    "PROMOTED",
    "ROLLED_BACK",
]
EVALUATION_CANDIDATE_STATES: tuple[EvaluationCandidateState, ...] = (
    "BUILDING",
    "EVIDENCE_REVIEW",
    "REVIEW_COMPLETE",
    "STAGE_A_READY",
    "EVALUATION_READY",
    "EVALUATING",
    "EVALUATED",
    "FAILED",
)


def early_canary_may_run_before_all_305(
    *,
    any_selected_case_fully_verified: bool,
    v2_verified_selected: int,
    selected_total: int = PATH_B_SELECTED_ISSUE_COUNT,
) -> dict[str, Any]:
    """A debugging canary may run before overlay completeness. It is never promotable."""

    del selected_total
    return {
        "allowed": bool(any_selected_case_fully_verified or v2_verified_selected > 0),
        "promotable": False,
        "non_promotable_diagnostic_canary": True,
        "full_30_not_authorized": True,
    }


def full_selected_run_requires_305_verified(
    *,
    v2_verified_selected: int,
    total_hold: int,
    selected_total: int = PATH_B_SELECTED_ISSUE_COUNT,
) -> bool:
    return (
        v2_verified_selected == selected_total
        and total_hold == 0
        and selected_total == PATH_B_SELECTED_ISSUE_COUNT
    )


def ordinary_live_smoke_uses_active(
    *,
    active_build_id: str | None,
    job_pinned_build_id: str | None,
) -> None:
    """Ordinary LIVE proof must pin ACTIVE after promotion, never an evaluation build."""

    if not active_build_id:
        raise ValueError("ordinary LIVE smoke requires ACTIVE")
    if str(job_pinned_build_id or "") != str(active_build_id):
        raise ValueError("ordinary LIVE smoke must pin ACTIVE")


def ordinary_live_admission_allowed(
    *,
    serving_index_present: bool,
    path_b_qualified_issue_count: int | None = None,
) -> bool:
    """Ordinary LIVE admission depends on a serving index, never on Path-B 305/305."""

    del path_b_qualified_issue_count
    return bool(serving_index_present)


def live_query_decision(
    *,
    serving_index_present: bool,
    proposition_evidence_runtime_eligible: bool,
    path_b_qualified_issue_count: int | None = None,
) -> dict[str, Any]:
    """Fail closed per unsupported proposition; do not hold the whole application."""

    del path_b_qualified_issue_count
    if not serving_index_present:
        return {
            "admitted": False,
            "reason": "serving_index_missing",
            "fail_closed_scope": "query",
            "global_runtime_hold": False,
            "runtime_blocked_by_path_b_span_gap": False,
        }
    if not proposition_evidence_runtime_eligible:
        return {
            "admitted": False,
            "reason": "proposition_evidence_not_runtime_eligible",
            "fail_closed_scope": "query",
            "global_runtime_hold": False,
            "runtime_blocked_by_path_b_span_gap": False,
        }
    return {
        "admitted": True,
        "reason": "runtime_eligible_evidence",
        "fail_closed_scope": None,
        "global_runtime_hold": False,
        "runtime_blocked_by_path_b_span_gap": False,
    }


def candidate_evidence_runtime_eligible(
    *,
    approved: bool,
    current: bool,
    exact_hash_matched: bool,
) -> bool:
    """Unapproved Path-B candidate bytes cannot enter the LIVE evidence pool."""

    return bool(approved and current and exact_hash_matched)


def live60_overlay_may_replace_production(
    *,
    overlay_sealed: bool,
    path_b_selected_qualified_with_spans: int,
    overlay_blockers: Sequence[str] = (),
) -> bool:
    """Unsealed or incomplete Path-B overlays must not replace ACTIVE/production."""

    if not overlay_sealed:
        return False
    if path_b_selected_qualified_with_spans != PATH_B_SELECTED_ISSUE_COUNT:
        return False
    return PATH_B_OVERLAY_SPAN_BLOCKER not in overlay_blockers


def derive_evaluation_candidate_state(
    *,
    candidate_build_present: bool = False,
    unreviewed_issue_count: int | None = None,
    hold_issue_count: int | None = None,
    review_complete: bool = False,
    stage_a_ready: bool = False,
    evaluation_authorized: bool = False,
    evaluating: bool = False,
    evaluated: bool = False,
    failed: bool = False,
) -> EvaluationCandidateState:
    """Advance the evaluation-candidate machine without collapsing it into ready."""

    holds = 0 if hold_issue_count is None else int(hold_issue_count)
    unreviewed = unreviewed_issue_count
    issues_cleared = (unreviewed is None or int(unreviewed) == 0) and holds == 0
    if failed:
        return "FAILED"
    if evaluated:
        return "EVALUATED"
    if evaluating:
        return "EVALUATING"
    if evaluation_authorized:
        return "EVALUATION_READY"
    if stage_a_ready:
        return "STAGE_A_READY"
    if (review_complete and issues_cleared) or (unreviewed == 0 and holds == 0):
        return "REVIEW_COMPLETE"
    if candidate_build_present:
        return "EVIDENCE_REVIEW"
    return "BUILDING"


def derive_production_promotion_state(
    *,
    rolled_back: bool = False,
    operator_promoted: bool = False,
    v1_overlay_may_replace_production: bool = False,
) -> ProductionPromotionState:
    """Production promotion stays operator-only; evaluation success is not promote."""

    if rolled_back:
        return "ROLLED_BACK"
    if operator_promoted:
        return "PROMOTED"
    if v1_overlay_may_replace_production:
        return "AWAITING_OPERATOR"
    return "NOT_ELIGIBLE"


def classify_live_and_live60_state(
    *,
    serving_index_present: bool,
    previous_approved_active_present: bool = False,
    runtime_eligible_approved_source_count: int = 0,
    path_b_selected_qualified_with_spans: int,
    path_b_selected_issue_count: int = PATH_B_SELECTED_ISSUE_COUNT,
    overlay_sealed: bool,
    overlay_blockers: Sequence[str] = (),
    candidate_evidence_unapproved: bool = True,
    degraded: bool = False,
    candidate_build_present: bool = False,
    unreviewed_issue_count: int | None = None,
    hold_issue_count: int | None = None,
    review_complete: bool = False,
    stage_a_ready: bool = False,
    evaluation_authorized: bool = False,
    evaluating: bool = False,
    evaluated: bool = False,
    evaluation_failed: bool = False,
    rolled_back: bool = False,
    operator_promoted: bool | None = None,
) -> dict[str, Any]:
    """Return the required runtime vs Live60 candidate/overlay/promotion split."""

    blockers = tuple(overlay_blockers)
    span_gap = (
        PATH_B_OVERLAY_SPAN_BLOCKER in blockers
        or path_b_selected_qualified_with_spans != path_b_selected_issue_count
    )
    full_path_b = (
        overlay_sealed
        and path_b_selected_qualified_with_spans == path_b_selected_issue_count
        and PATH_B_OVERLAY_SPAN_BLOCKER not in blockers
    )
    overlay_status = "SEALED" if overlay_sealed and full_path_b else "UNSEALED"
    may_replace = live60_overlay_may_replace_production(
        overlay_sealed=overlay_sealed,
        path_b_selected_qualified_with_spans=path_b_selected_qualified_with_spans,
        overlay_blockers=blockers,
    )
    promotion_status = "ELIGIBLE" if may_replace else "HOLD"
    if not serving_index_present:
        runtime_status: RuntimeStatus = "NOT_SERVING"
    elif degraded:
        runtime_status = "DEGRADED"
    else:
        runtime_status = "LIVE"
    promoted = serving_index_present if operator_promoted is None else operator_promoted
    evaluation_state = derive_evaluation_candidate_state(
        candidate_build_present=candidate_build_present or serving_index_present,
        unreviewed_issue_count=unreviewed_issue_count,
        hold_issue_count=hold_issue_count,
        review_complete=review_complete,
        stage_a_ready=stage_a_ready,
        evaluation_authorized=evaluation_authorized,
        evaluating=evaluating,
        evaluated=evaluated,
        failed=evaluation_failed,
    )
    production_state = derive_production_promotion_state(
        rolled_back=rolled_back,
        operator_promoted=promoted,
        v1_overlay_may_replace_production=may_replace and not promoted,
    )
    current_approved = (
        "AVAILABLE"
        if serving_index_present or runtime_eligible_approved_source_count > 0
        else "UNAVAILABLE"
    )
    payload = {
        "runtime_status": runtime_status,
        "live60_candidate_status": "COMPLETE" if full_path_b else "REMEDIATION",
        "live60_overlay_status": overlay_status,
        "live60_promotion_status": promotion_status,
        "evaluation_candidate_state": evaluation_state,
        "production_promotion_state": production_state,
        "evaluation_requires_active": False,
        "evaluation_requires_owner_promoted_active": False,
        "evaluation_requires_o04": False,
        "evaluation_requires_rollback_drill": False,
        "evaluation_requires_browser_recovery": False,
        "evaluation_requires_production_readiness_green": False,
        "current_approved_runtime_evidence": current_approved,
        "candidate_unapproved_evidence": (
            "NOT_RUNTIME_ELIGIBLE" if candidate_evidence_unapproved else "RUNTIME_ELIGIBLE"
        ),
        "path_b_overlay_seal_blocked": not full_path_b,
        "path_b_overlay_promotion_blocked": promotion_status == "HOLD",
        "runtime_blocked_by_path_b_span_gap": False,
        "ordinary_live_query_admitted": ordinary_live_admission_allowed(
            serving_index_present=serving_index_present,
            path_b_qualified_issue_count=path_b_selected_qualified_with_spans,
        ),
        "previous_approved_active_preserved": bool(
            previous_approved_active_present and not may_replace
        ),
        "path_b_selected_qualified_with_spans": path_b_selected_qualified_with_spans,
        "path_b_selected_issue_count": path_b_selected_issue_count,
        "path_b_span_gap": span_gap,
    }
    return payload


def split_readiness_blocking_gates(
    hard_gates: Mapping[str, bool],
) -> dict[str, list[str]]:
    """Keep Live60 overlay/Stage A off the ordinary runtime availability list."""

    runtime_blocking: list[str] = []
    live60_blocking: list[str] = []
    for key, passed in hard_gates.items():
        if passed:
            continue
        if key in LIVE60_BENCHMARK_HARD_GATE_KEYS or key == PATH_B_OVERLAY_SPAN_BLOCKER:
            live60_blocking.append(key)
        else:
            runtime_blocking.append(key)
    return {
        "runtime_blocking_gates": sorted(runtime_blocking),
        "live60_benchmark_blocking_gates": sorted(live60_blocking),
    }
