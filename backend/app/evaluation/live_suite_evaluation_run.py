"""Evaluation-only 30-case run against a pinned candidate build.

Qualified cases generate; limited cases emit a limited answer; held cases are
deterministic holds. One held case does not block the other 29. Fail-closed
answer gates stay. This path does not write ACTIVE or issue O-04.

``plan_evaluation_only_run`` never claims a hard gate passed. Real outcomes
come from ``execute_evaluation_only_run`` after terminal jobs exist.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite_evaluation_auth import (
    Live60EvaluationExecutionAuthorizationV2,
    verify_evaluation_runtime_bindings,
)
from .live_suite_execute import Live60ExecutionOutcome
from .live_suite_overlay_complete import derive_case_execution_status

EVALUATION_RUN_V2_SCHEMA = "legalbot.live60-evaluation-run.v2"
CaseTerminal = Literal["released", "verified_limited", "held"]
PENDING_GATE = None


def plan_case_terminal(execution_status: str) -> CaseTerminal:
    if execution_status == "generate":
        return "released"
    if execution_status == "verified_limited":
        return "verified_limited"
    return "held"


def plan_evaluation_only_run(
    *,
    authorization: Live60EvaluationExecutionAuthorizationV2,
    candidate_build_id: str,
    selected_cases: Sequence[Mapping[str, Any]],
    active_build_id: str | None = None,
    overlay_complete: bool,
    unreviewed_issue_count: int,
    fallback_to_active: bool = False,
) -> dict[str, Any]:
    """Plan mixed-outcome evaluation. Gates remain pending until real jobs finish."""

    if not overlay_complete:
        raise ValueError("evaluation requires a v2-complete overlay")
    if unreviewed_issue_count != 0:
        raise ValueError("evaluation requires unreviewed_issue_count == 0")
    binding = verify_evaluation_runtime_bindings(
        authorization=authorization,
        candidate_build_id=candidate_build_id,
        active_build_id=active_build_id,
        fallback_to_active=fallback_to_active,
    )
    if authorization.candidate_build_id != candidate_build_id:
        raise ValueError("evaluation run is not pinned to the authorization candidate")
    outcomes: list[dict[str, Any]] = []
    for case in selected_cases:
        status = str(case.get("execution_status") or "")
        if not status:
            status = derive_case_execution_status(list(case.get("issues") or ()))
        terminal = plan_case_terminal(status)
        outcomes.append(
            {
                "case_id": case.get("case_id"),
                "execution_status": status,
                "planned_terminal_state": terminal,
                "terminal_state": None,
                "blocked_by_other_held_case": False,
                "evidence_gate": PENDING_GATE,
                "currentness_gate": PENDING_GATE,
                "jurisdiction_gate": PENDING_GATE,
                "citation_gate": PENDING_GATE,
                "privacy_gate": PENDING_GATE,
                "oscola_gate": PENDING_GATE,
                "rights_gate": PENDING_GATE,
                "job_id": None,
                "answer_sha256": None,
            }
        )
    payload = {
        "schema": EVALUATION_RUN_V2_SCHEMA,
        "evaluation_run_id": authorization.evaluation_run_id,
        "candidate_build_id": candidate_build_id,
        "active_build_id": active_build_id,
        "used_active_fallback": binding["used_active_fallback"],
        "started": False,
        "planned": True,
        "evaluating": False,
        "writes_active": False,
        "writes_o04": False,
        "production_promotion_state": "NOT_ELIGIBLE",
        "case_count": len(outcomes),
        "held_case_count": sum(item["planned_terminal_state"] == "held" for item in outcomes),
        "limited_case_count": sum(
            item["planned_terminal_state"] == "verified_limited" for item in outcomes
        ),
        "generate_case_count": sum(
            item["planned_terminal_state"] == "released" for item in outcomes
        ),
        "one_held_case_blocks_others": False,
        "outcomes": outcomes,
        "local_only": True,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "outcomes"}
    )
    return payload


def start_evaluation_only_run(
    *,
    authorization: Live60EvaluationExecutionAuthorizationV2,
    candidate_build_id: str,
    selected_cases: Sequence[Mapping[str, Any]],
    active_build_id: str | None = None,
    overlay_complete: bool,
    unreviewed_issue_count: int,
    fallback_to_active: bool = False,
) -> dict[str, Any]:
    """Compatibility alias for the planner. Does not execute the model."""

    return plan_evaluation_only_run(
        authorization=authorization,
        candidate_build_id=candidate_build_id,
        selected_cases=selected_cases,
        active_build_id=active_build_id,
        overlay_complete=overlay_complete,
        unreviewed_issue_count=unreviewed_issue_count,
        fallback_to_active=fallback_to_active,
    )


def outcome_gate_payload(outcome: Live60ExecutionOutcome) -> dict[str, Any]:
    return {
        "case_id": outcome.case_id,
        "terminal_state": outcome.terminal_state,
        "job_id": outcome.job_id,
        "answer_sha256": outcome.answer_sha256,
        "release_gate_report_sha256": outcome.release_gate_report_sha256,
        "evidence_gate": outcome.evidence_passed if outcome.released else False,
        "currentness_gate": outcome.currentness_passed if outcome.released else False,
        "jurisdiction_gate": outcome.jurisdiction_passed if outcome.released else False,
        "citation_gate": outcome.citation_passed if outcome.released else False,
        "privacy_gate": outcome.privacy_passed if outcome.released else False,
        "oscola_gate": outcome.oscola_passed if outcome.released else False,
        "rights_gate": bool(outcome.released),
        "released": outcome.released,
    }


async def execute_evaluation_only_run(
    *,
    authorization: Live60EvaluationExecutionAuthorizationV2,
    candidate_build_id: str,
    executor: Any,
    active_build_id: str | None = None,
) -> dict[str, Any]:
    """Run the shared Live60 HTTP executor in evaluation mode and aggregate real outcomes."""

    verify_evaluation_runtime_bindings(
        authorization=authorization,
        candidate_build_id=candidate_build_id,
        active_build_id=active_build_id,
        fallback_to_active=False,
    )
    outcomes: tuple[Live60ExecutionOutcome, ...] = await executor.execute()
    mapped = [outcome_gate_payload(item) for item in outcomes]
    payload = {
        "schema": EVALUATION_RUN_V2_SCHEMA,
        "evaluation_run_id": authorization.evaluation_run_id,
        "candidate_build_id": candidate_build_id,
        "active_build_id": active_build_id,
        "used_active_fallback": False,
        "started": True,
        "planned": False,
        "evaluating": False,
        "writes_active": False,
        "writes_o04": False,
        "production_promotion_state": "NOT_ELIGIBLE",
        "case_count": len(mapped),
        "held_case_count": sum(item["terminal_state"] == "held" for item in mapped),
        "limited_case_count": sum(item["terminal_state"] == "verified_limited" for item in mapped),
        "generate_case_count": sum(item["terminal_state"] == "released" for item in mapped),
        "one_held_case_blocks_others": False,
        "outcomes": mapped,
        "local_only": True,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "outcomes"}
    )
    return payload
