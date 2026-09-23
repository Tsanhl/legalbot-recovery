"""Evaluation Control Plane v2 scoped states.

A case-local hold keeps phase_execution_state ACTIVE. Downstream NOT_STARTED
is not FAILED. Locator owner-adoption is not answer gold.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from app.contracts.schema_registry import seal_contract

from .ge_phase2_progress import GLOBAL_HARD_STOP_REASONS, NOT_STARTED, phase2_progress
from .ge_principal_blocker import claim_assurance_state, classify_principal_blocker
from .ge_progression_taxonomy import (
    PROGRESSION_DISPOSITIONS,
    classify_progression_from_route,
    qualified_review_eligible,
)

PHASE_ACTIVE = "ACTIVE"
PHASE_HARD_STOPPED = "HARD_STOPPED"
RUN_READY = "READY"
RUN_RUNNING = "RUNNING"
RUN_COMPLETE = "COMPLETE"
RUN_COMPLETE_WITH_CASE_HOLDS = "COMPLETE_WITH_CASE_HOLDS"
RUN_BLOCKED_BY_SYSTEM_ERROR = "BLOCKED_BY_SYSTEM_ERROR"
CASE_PASS = "PASS"
CASE_HOLD = "HOLD"
CASE_FAIL_CLOSED = "FAIL_CLOSED"
CASE_SYSTEM_ERROR = "SYSTEM_ERROR"
BLOCKER_GLOBAL = "GLOBAL"
BLOCKER_RUN = "RUN"
BLOCKER_CASE = "CASE"
BLOCKER_CLAIM = "CLAIM"
BLOCKER_SOURCE = "SOURCE"
LOCATOR_EVALUATION_LABEL = "OWNER_ADOPTED_LOCATOR_EVALUATION_DECISION"

ASSURANCE_GATES = (
    "source_identity_verified",
    "source_staged",
    "source_runtime_admitted",
    "locator_evaluation_approved",
    "locator_currentness_verified",
    "locator_extent_verified",
    "proposition_qualified",
    "answer_legal_gold",
    "training_gold",
    "runtime_promoted",
)

DECISION_MAKERS = (
    "ai_research_recommendation",
    "owner_adoption",
    "qualified_legal_review",
    "second_legal_review",
)


def global_hard_stop_from_reasons(reasons: Sequence[str]) -> bool:
    return any(str(item) in GLOBAL_HARD_STOP_REASONS for item in reasons if str(item).strip())


def case_assurance_state(row: Mapping[str, Any]) -> str:
    factual = row.get("factual_result")
    outcome = ""
    if isinstance(factual, Mapping):
        outcome = str(factual.get("outcome") or "")
    if outcome == "FACTUAL_PASS":
        return CASE_PASS
    if outcome == "SYSTEM_ERROR":
        return CASE_SYSTEM_ERROR
    if not (row.get("evidence") or []):
        return CASE_FAIL_CLOSED
    return CASE_HOLD


def _progression_disposition(row: Mapping[str, Any]) -> str:
    factual = row.get("factual_result")
    if isinstance(factual, Mapping):
        progression = factual.get("progression")
        if isinstance(progression, Mapping) and progression.get("disposition"):
            return str(progression["disposition"])
        outcome = str(factual.get("outcome") or "")
    else:
        outcome = ""
    from .ge_hold_reason_router import freeze_pass_case, route_hold

    routed = freeze_pass_case(row) if outcome == "FACTUAL_PASS" else route_hold(row)
    return str(
        classify_progression_from_route(
            case_id=str(row.get("case_id") or ""),
            factual_status=outcome or str(routed.get("factual_status") or "FACTUAL_HOLD"),
            hold_reason_code=routed.get("hold_reason_code"),
            evidence_present=bool(row.get("evidence") or []),
        )["disposition"]
    )


def control_plane_v2(
    *,
    case_results: Sequence[Mapping[str, Any]],
    hard_stop_reasons: Sequence[str] = (),
    diagnostic_execution: str = "COMPLETE",
    diagnostic_report: str = "APPROVED_SCOPED",
    routed: bool = True,
    runnable_queue_count: int = 0,
    locator_hold_count: int = 0,
    locator_pending_count: int = 0,
    locator_reject_count: int = 1,
    terminally_classified: bool = False,
    run_id: str = "UNBOUND",
    controller_id: str = "UNBOUND",
    current_stage: str = "DIAGNOSTIC_EVALUATION",
    authority_status: str = "NOT_RECORDED",
    authority_mechanism: str = "NOT_RECORDED",
    authority_authenticated: bool = False,
    authority_scope_sha256: str | None = None,
) -> dict[str, Any]:
    reasons = [
        str(item)
        for item in hard_stop_reasons
        if str(item).strip() and str(item) in GLOBAL_HARD_STOP_REASONS
    ]
    if not case_results and "zero_runnable_visible_cases" not in reasons:
        reasons.append("zero_runnable_visible_cases")
    hard_stop = global_hard_stop_from_reasons(reasons)
    progress = phase2_progress(
        case_results=case_results,
        hard_stop_reasons=reasons,
        diagnostic_execution=diagnostic_execution,
        diagnostic_report=diagnostic_report,
        routed=routed,
        runnable_queue_count=runnable_queue_count,
        locator_hold_count=locator_hold_count,
        locator_pending_count=locator_pending_count,
        locator_reject_count=locator_reject_count,
        terminally_classified=terminally_classified,
    )
    case_counts: Counter[str] = Counter()
    claim_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    progression_counts: Counter[str] = Counter()
    qlr_eligible = 0
    blockers: list[dict[str, Any]] = []
    for row in case_results:
        case_state = case_assurance_state(row)
        case_counts[case_state] += 1
        claim_counts[claim_assurance_state(row)] += 1
        disposition = _progression_disposition(row)
        progression_counts[disposition] += 1
        if qualified_review_eligible(disposition):
            qlr_eligible += 1
        if case_state != CASE_PASS:
            blocker = classify_principal_blocker(row)
            blocker_counts[blocker] += 1
            blockers.append(
                {
                    "scope": BLOCKER_CASE,
                    "case_id": str(row.get("case_id") or "UNIDENTIFIED"),
                    "code": blocker,
                    "status": case_state,
                }
            )
    if hard_stop:
        phase = PHASE_HARD_STOPPED
        run_state = RUN_BLOCKED_BY_SYSTEM_ERROR
        scope = BLOCKER_GLOBAL
    else:
        phase = PHASE_ACTIVE
        held = case_counts[CASE_HOLD] + case_counts[CASE_FAIL_CLOSED]
        if diagnostic_execution != "COMPLETE":
            run_state = RUN_RUNNING
        elif held > 0:
            run_state = RUN_COMPLETE_WITH_CASE_HOLDS
        else:
            run_state = RUN_COMPLETE
        scope = BLOCKER_CASE if held else BLOCKER_RUN
    blockers.extend(
        {
            "scope": BLOCKER_GLOBAL,
            "case_id": None,
            "code": reason,
            "status": "SYSTEM_ERROR",
        }
        for reason in reasons
    )
    body = {
        "schema": "legalbot.ge-evaluation-control-plane.v2",
        "run_id": run_id,
        "controller_id": controller_id,
        "current_stage": current_stage,
        "authority": {
            "status": authority_status,
            "mechanism": authority_mechanism,
            "authenticated": authority_authenticated,
            "scope_sha256": authority_scope_sha256,
        },
        "phase_execution_state": phase,
        "run_execution_state": run_state,
        "global_hard_stop": hard_stop,
        "hard_stop_reasons": reasons,
        "blocker_scope": scope,
        "overall_progress": phase == PHASE_ACTIVE,
        "case_local_hold_sets_phase_progress_false": False,
        "legacy_overall_state": progress["overall_state"],
        "case_assurance_counts": {
            "PASS": case_counts[CASE_PASS],
            "HOLD": case_counts[CASE_HOLD],
            "FAIL_CLOSED": case_counts[CASE_FAIL_CLOSED],
            "SYSTEM_ERROR": case_counts[CASE_SYSTEM_ERROR],
        },
        "claim_assurance_counts": {
            "SUPPORTED": claim_counts["SUPPORTED"],
            "PARTIALLY_SUPPORTED": claim_counts["PARTIALLY_SUPPORTED"],
            "UNSUPPORTED": claim_counts["UNSUPPORTED"],
            "NOT_REVIEWABLE": claim_counts["NOT_REVIEWABLE"],
        },
        "principal_blocker_counts": dict(sorted(blocker_counts.items())),
        "blockers": blockers,
        "progression_disposition_counts": {
            name: int(progression_counts.get(name, 0)) for name in PROGRESSION_DISPOSITIONS
        },
        "factual_hold_is_not_equivalent_failure": True,
        "qualified_review_eligible_count": qlr_eligible,
        "qualified_human_review_required": qlr_eligible > 0,
        "gold_eligible_count": 0,
        "downstream_gates": {
            "qualified_legal_review": NOT_STARTED,
            "answer_legal_gold": NOT_STARTED,
            "training_gold": NOT_STARTED,
            "runtime_promoted": NOT_STARTED,
        },
        "locator_evaluation_label": LOCATOR_EVALUATION_LABEL,
        "answer_legal_gold": False,
        "training_gold": False,
        "not_started_is_not_failed": True,
        "one_held_case_sets_global_progress_false": False,
        "assurance_gates_are_separate": True,
        "decision_makers_are_separate": True,
        "assurance_gate_names": list(ASSURANCE_GATES),
        "decision_maker_names": list(DECISION_MAKERS),
    }
    return seal_contract(body)
