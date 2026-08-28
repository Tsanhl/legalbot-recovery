from __future__ import annotations

from pathlib import Path

from app.evaluation.live_runtime_separation import (
    PATH_B_OVERLAY_SPAN_BLOCKER,
    candidate_evidence_runtime_eligible,
    classify_live_and_live60_state,
    live60_overlay_may_replace_production,
    live_query_decision,
    ordinary_live_admission_allowed,
    split_readiness_blocking_gates,
)
from app.evaluation.live_suite_remaining_gates import (
    attempt_remaining_live_run_gates,
    try_seal_overlay_from_owner_ticks,
)

OVERLAY_BLOCKERS = (PATH_B_OVERLAY_SPAN_BLOCKER,)


def _ticks(*, qualified: int) -> dict[str, object]:
    return {
        "issue_count": 585,
        "qualified_issue_count": qualified,
        "limited_issue_count": 0,
        "knowledge_gap_issue_count": 585 - qualified,
        "overlay_sealable": False,
        "expert_qualification_sealed": False,
    }


def test_path_b_304_of_305_blocks_overlay_not_ordinary_live() -> None:
    state = classify_live_and_live60_state(
        serving_index_present=True,
        previous_approved_active_present=True,
        runtime_eligible_approved_source_count=12,
        path_b_selected_qualified_with_spans=304,
        overlay_sealed=False,
        overlay_blockers=OVERLAY_BLOCKERS,
    )
    assert state["runtime_status"] == "LIVE"
    assert state["live60_candidate_status"] == "REMEDIATION"
    assert state["live60_overlay_status"] == "UNSEALED"
    assert state["live60_promotion_status"] == "HOLD"
    assert state["current_approved_runtime_evidence"] == "AVAILABLE"
    assert state["path_b_overlay_seal_blocked"] is True
    assert state["path_b_overlay_promotion_blocked"] is True
    assert state["ordinary_live_query_admitted"] is True
    assert state["runtime_blocked_by_path_b_span_gap"] is False
    assert state["previous_approved_active_preserved"] is True
    assert (
        live60_overlay_may_replace_production(
            overlay_sealed=False,
            path_b_selected_qualified_with_spans=304,
            overlay_blockers=OVERLAY_BLOCKERS,
        )
        is False
    )
    assert ordinary_live_admission_allowed(
        serving_index_present=True,
        path_b_qualified_issue_count=304,
    )


def test_unrelated_live_query_runs_when_path_b_is_59_of_305() -> None:
    decision = live_query_decision(
        serving_index_present=True,
        proposition_evidence_runtime_eligible=True,
        path_b_qualified_issue_count=59,
    )
    assert decision == {
        "admitted": True,
        "reason": "runtime_eligible_evidence",
        "fail_closed_scope": None,
        "global_runtime_hold": False,
        "runtime_blocked_by_path_b_span_gap": False,
    }
    assert ordinary_live_admission_allowed(
        serving_index_present=True,
        path_b_qualified_issue_count=59,
    )


def test_unapproved_candidate_query_fails_closed_without_global_hold() -> None:
    decision = live_query_decision(
        serving_index_present=True,
        proposition_evidence_runtime_eligible=False,
        path_b_qualified_issue_count=59,
    )
    assert decision["admitted"] is False
    assert decision["reason"] == "proposition_evidence_not_runtime_eligible"
    assert decision["fail_closed_scope"] == "query"
    assert decision["global_runtime_hold"] is False
    assert decision["runtime_blocked_by_path_b_span_gap"] is False
    state = classify_live_and_live60_state(
        serving_index_present=True,
        previous_approved_active_present=True,
        runtime_eligible_approved_source_count=12,
        path_b_selected_qualified_with_spans=59,
        overlay_sealed=False,
        overlay_blockers=OVERLAY_BLOCKERS,
    )
    assert state["runtime_status"] == "LIVE"
    assert state["runtime_blocked_by_path_b_span_gap"] is False


def test_failed_candidate_overlay_does_not_replace_previous_active(
    tmp_path: Path,
) -> None:
    active = tmp_path / "data" / "indexes" / "ACTIVE.json"
    overlay = tmp_path / "data" / "evaluations" / "expert-qualification.json"
    active.parent.mkdir(parents=True)
    overlay.parent.mkdir(parents=True)
    previous = b'{"build_id":"approved-production","schema":"legalbot.active-pointer.v1"}\n'
    active.write_bytes(previous)
    overlay_result = try_seal_overlay_from_owner_ticks(
        ticks=_ticks(qualified=304),
        destination=overlay,
    )
    assert overlay_result["sealed"] is False
    assert overlay_result["wrote_expert_qualification"] is False
    assert not overlay.exists()
    assert active.read_bytes() == previous
    report = attempt_remaining_live_run_gates(
        project_root=tmp_path,
        ticks=_ticks(qualified=304),
    )
    assert report["generation_authorised"] is False
    assert report["evaluation_requires_owner_promoted_active"] is False
    assert report["evaluation_requires_o04"] is False
    assert report["attempts"]["owner_promote_ACTIVE"]["wrote_active_pointer"] is False
    assert report["live_runtime_separation"]["runtime_status"] == "LIVE"
    assert report["live_runtime_separation"]["previous_approved_active_preserved"] is True
    assert report["live_runtime_separation"]["live60_promotion_status"] == "HOLD"
    assert active.read_bytes() == previous


def test_candidate_evidence_does_not_leak_into_live_when_runtime_available() -> None:
    assert (
        candidate_evidence_runtime_eligible(
            approved=False,
            current=True,
            exact_hash_matched=True,
        )
        is False
    )
    assert (
        candidate_evidence_runtime_eligible(
            approved=True,
            current=True,
            exact_hash_matched=False,
        )
        is False
    )
    state = classify_live_and_live60_state(
        serving_index_present=True,
        previous_approved_active_present=True,
        runtime_eligible_approved_source_count=12,
        path_b_selected_qualified_with_spans=77,
        overlay_sealed=False,
        overlay_blockers=OVERLAY_BLOCKERS,
        candidate_evidence_unapproved=True,
    )
    assert state["runtime_status"] == "LIVE"
    assert state["candidate_unapproved_evidence"] == "NOT_RUNTIME_ELIGIBLE"
    leaked = live_query_decision(
        serving_index_present=True,
        proposition_evidence_runtime_eligible=candidate_evidence_runtime_eligible(
            approved=False,
            current=True,
            exact_hash_matched=True,
        ),
        path_b_qualified_issue_count=77,
    )
    assert leaked["admitted"] is False
    assert leaked["global_runtime_hold"] is False


def test_readiness_split_keeps_path_b_span_gap_off_runtime_list() -> None:
    split = split_readiness_blocking_gates(
        {
            "sealed_expert_overlay": False,
            "stage_a_coverage_and_thresholds": False,
            "owner_promoted_active": True,
            "source_registry": True,
            PATH_B_OVERLAY_SPAN_BLOCKER: False,
        }
    )
    assert "sealed_expert_overlay" not in split["runtime_blocking_gates"]
    assert "stage_a_coverage_and_thresholds" not in split["runtime_blocking_gates"]
    assert PATH_B_OVERLAY_SPAN_BLOCKER not in split["runtime_blocking_gates"]
    assert PATH_B_OVERLAY_SPAN_BLOCKER in split["live60_benchmark_blocking_gates"]
    assert "sealed_expert_overlay" in split["live60_benchmark_blocking_gates"]
