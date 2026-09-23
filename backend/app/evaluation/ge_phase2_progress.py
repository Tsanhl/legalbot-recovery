"""Phase 2 control-plane states. Downstream NOT_STARTED is not FAILED."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .ge_factual_gap_fill import sidecar_packs

NOT_STARTED = "NOT_STARTED"
RUNNING = "RUNNING"
COMPLETE = "COMPLETE"
COMPLETE_WITH_HOLDS = "COMPLETE_WITH_HOLDS"
AWAITING_OWNER_DECISION = "AWAITING_OWNER_DECISION"
AWAITING_OWNER_DIAGNOSTIC_APPROVAL = "AWAITING_OWNER_DIAGNOSTIC_APPROVAL"
ROUTING_AND_REPAIRING_HELD_CASES = "ROUTING_AND_REPAIRING_HELD_CASES"
PHASE2_COMPLETE_WITH_ROUTED_HOLDS = "PHASE2_COMPLETE_WITH_ROUTED_HOLDS"
MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING = "MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING"
EVALUATION_PACKET_COMPLETION_RUNNING = "EVALUATION_PACKET_COMPLETION_RUNNING"
EVALUATION_PACKET_COMPLETION_WITH_CASE_GAPS = "EVALUATION_PACKET_COMPLETION_WITH_CASE_GAPS"
AWAITING_OWNER_EVALUATION_REVIEW = "AWAITING_OWNER_EVALUATION_REVIEW"
AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW = (
    "AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW"
)
EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW = (
    "EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW"
)
AWAITING_QUALIFIED_REVIEWER = "AWAITING_QUALIFIED_REVIEWER"
ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW = (
    "ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW"
)
REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW = (
    "REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW"
)
AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING = (
    "AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING"
)
ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION = (
    "ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION"
)
SEALED_UNSEEN_ONE_PASS_COMPLETE_HOLD_NO_REPAIR = (
    "SEALED_UNSEEN_ONE_PASS_COMPLETE_HOLD_NO_REPAIR"
)
POST_UNSEEN_FRESH_AUDITED_ROUTE_PASS_AWAITING_NEW_UNSEEN_BANK_DESIGN = (
    "POST_UNSEEN_FRESH_AUDITED_ROUTE_PASS_AWAITING_NEW_UNSEEN_BANK_DESIGN"
)
NEW_UNSEEN_BANK_DESIGN_PREPARED_AWAITING_OWNER_CREATION_AUTHORIZATION = (
    "NEW_UNSEEN_BANK_DESIGN_PREPARED_AWAITING_OWNER_CREATION_AUTHORIZATION"
)
EXPANDED_UNSEEN_CREATION_AUTHORIZED_AWAITING_INDEPENDENT_CUSTODIAN = (
    "EXPANDED_UNSEEN_CREATION_AUTHORIZED_AWAITING_INDEPENDENT_CUSTODIAN"
)
QUALIFIED_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING = (
    "QUALIFIED_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING"
)
BLOCKED = "BLOCKED"
TERMINAL_HOLD = "TERMINAL_HOLD"
FAIL_CLOSED = "FAIL_CLOSED"
NOT_APPLICABLE = "NOT_APPLICABLE"
HARD_STOP = "HARD_STOP"
NO_OP_UNCHANGED_INPUTS = "NO_OP_UNCHANGED_INPUTS"
NO_OP_UNCHANGED_CASE_INPUTS = "NO_OP_UNCHANGED_CASE_INPUTS"
NO_OP_UNCHANGED_RESEARCH_INPUTS = "NO_OP_UNCHANGED_RESEARCH_INPUTS"

EVALUATION_POLICY_VERSION = "legalbot.ge-evaluation-policy.control-plane.v1"
EVALUATOR_VERSION = "legalbot.ge-diagnostic-evaluator.v2"

GLOBAL_HARD_STOP_REASONS = (
    "manifest_or_hash_mismatch",
    "corrupt_or_untraceable_source_bytes",
    "mandatory_evaluator_regression_failure",
    "integrity_or_privacy_failure",
    "zero_runnable_visible_cases",
    "explicit_owner_stop",
)

DOWNSTREAM_GATES = (
    "qualified_legal_review",
    "answer_legal_gold",
    "legal_gold",
    "catalogue_admission",
    "full_current_law_eligible",
    "answer_weight_training",
    "sealed_unseen_execution",
    "promotion",
    "live",
)

CONTROL_PLANES = {
    "evidence_diagnostic": (
        "locator_review",
        "locator_package",
        "diagnostic_r2_execution",
        "diagnostic_r2_case_classification",
        "diagnostic_report",
    ),
    "legal_judgment": (
        "qualified_legal_review",
        "answer_legal_gold",
        "legal_gold",
    ),
    "deployment_training": (
        "catalogue_admission",
        "full_current_law_eligible",
        "answer_weight_training",
        "sealed_unseen_execution",
        "promotion",
        "live",
    ),
}


def explicit_stage_states(
    *,
    locator_review: str = COMPLETE,
    locator_package: str = "RESOLVED_66_APPROVE_0_HOLD_1_REJECT",
    diagnostic_r2_execution: str = COMPLETE,
    diagnostic_r2_cases_processed: int = 331,
    diagnostic_r2_factual_pass: int = 38,
    diagnostic_r2_factual_hold: int = 293,
    diagnostic_report: str = "APPROVED_SCOPED",
) -> dict[str, Any]:
    downstream = {name: NOT_STARTED for name in DOWNSTREAM_GATES}
    return {
        "locator_review": locator_review,
        "locator_package": locator_package,
        "diagnostic_r2_execution": diagnostic_r2_execution,
        "diagnostic_r2_cases_processed": diagnostic_r2_cases_processed,
        "diagnostic_r2_factual_pass": diagnostic_r2_factual_pass,
        "diagnostic_r2_factual_hold": diagnostic_r2_factual_hold,
        "diagnostic_r2_case_classification": COMPLETE_WITH_HOLDS,
        "diagnostic_report": diagnostic_report,
        **downstream,
        "not_started_is_not_failed": True,
        "control_planes": {
            name: {
                gate: (COMPLETE if gate in CONTROL_PLANES["evidence_diagnostic"] else NOT_STARTED)
                for gate in gates
            }
            if name != "evidence_diagnostic"
            else {
                "locator_review": locator_review,
                "locator_package": locator_package,
                "diagnostic_r2_execution": diagnostic_r2_execution,
                "diagnostic_r2_case_classification": COMPLETE_WITH_HOLDS,
                "diagnostic_report": diagnostic_report,
            }
            for name, gates in CONTROL_PLANES.items()
        },
    }


def phase2_r2_complete(
    *,
    locator_package_resolved: bool,
    r2_job_succeeded: bool,
    processed_cases: int,
    classified_cases: int,
    diagnostic_report_written: bool,
    expected_cases: int = 331,
) -> bool:
    return (
        locator_package_resolved
        and r2_job_succeeded
        and processed_cases == expected_cases
        and classified_cases == expected_cases
        and diagnostic_report_written
    )


def phase2_progress(
    *,
    case_results: Sequence[Mapping[str, Any]],
    hard_stop_reasons: Sequence[str] = (),
    locator_hold_count: int = 0,
    locator_pending_count: int = 0,
    locator_reject_count: int = 0,
    diagnostic_execution: str = COMPLETE,
    diagnostic_report: str = "WRITTEN",
    runnable_queue_count: int | None = None,
    qualified_review_ready_count: int | None = None,
    routed: bool = False,
    terminally_classified: bool = False,
    awaiting_qualified_reviewer: bool = False,
    answer_reconstruction_required: bool = False,
    revised_answers_awaiting_blind_review: bool = False,
    ai_auto_review_complete: bool = False,
    answer_weight_training_complete: bool = False,
) -> dict[str, Any]:
    """Global state follows runnable mechanical work, not FACTUAL_HOLD count."""

    reasons = [str(item) for item in hard_stop_reasons if str(item).strip()]
    if not case_results and "zero_runnable_visible_cases" not in reasons:
        reasons.append("zero_runnable_visible_cases")
    global_hard_stop = bool(reasons)
    held: list[str] = []
    classified = 0
    for row in case_results:
        factual = row.get("factual_result")
        outcome = ""
        if isinstance(factual, Mapping):
            outcome = str(factual.get("outcome") or "")
        if outcome in {"FACTUAL_PASS", "FACTUAL_HOLD"}:
            classified += 1
        if outcome != "FACTUAL_PASS":
            held.append(str(row.get("case_id") or row.get("ordinal") or ""))
    runnable = 0 if runnable_queue_count is None else int(runnable_queue_count)
    review_ready = 0 if qualified_review_ready_count is None else int(qualified_review_ready_count)
    if global_hard_stop:
        state = HARD_STOP
    elif diagnostic_execution != COMPLETE:
        state = RUNNING
    elif diagnostic_report not in {"APPROVED_SCOPED", "APPROVED"} or not routed:
        state = AWAITING_OWNER_DIAGNOSTIC_APPROVAL
    elif runnable > 0:
        state = ROUTING_AND_REPAIRING_HELD_CASES
    elif revised_answers_awaiting_blind_review:
        state = REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW
    elif answer_weight_training_complete:
        state = ANSWER_WEIGHT_TRAINING_COMPLETE_AWAITING_FRESH_VISIBLE_EVALUATION
    elif ai_auto_review_complete:
        state = AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING
    elif answer_reconstruction_required:
        state = ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW
    elif awaiting_qualified_reviewer:
        state = AWAITING_QUALIFIED_REVIEWER
    elif terminally_classified:
        state = EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW
    else:
        state = MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    r2_complete = phase2_r2_complete(
        locator_package_resolved=locator_pending_count == 0 and locator_hold_count == 0,
        r2_job_succeeded=diagnostic_execution == COMPLETE and not global_hard_stop,
        processed_cases=len(case_results),
        classified_cases=classified,
        diagnostic_report_written=diagnostic_report in {"WRITTEN", "APPROVED_SCOPED", "APPROVED"},
    )
    return {
        "schema": "legalbot.ge-phase2-progress-and-blocker-ledger.v2",
        "overall_progress": not global_hard_stop,
        "overall_state": state,
        "global_hard_stop": global_hard_stop,
        "hard_stop_reasons": reasons,
        "runnable_visible_cases": len(case_results),
        "runnable_queue_count": runnable,
        "qualified_review_ready_count": review_ready,
        "held_or_fail_closed_cases": len(held),
        "held_case_ids": held,
        "locator_hold_count": locator_hold_count,
        "locator_pending_count": locator_pending_count,
        "locator_reject_count": locator_reject_count,
        "one_held_case_sets_global_progress_false": False,
        "not_started_downstream_is_not_failed": True,
        "diagnostic_factual_hold_is_not_equivalent_failure": True,
        "terminally_classified": terminally_classified,
        "phase2_r2_complete": r2_complete,
        "continue_independent_work": not global_hard_stop,
        "terminal_mechanical_hold_is_not_pipeline_dead": True,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def git_commit_hash(project_root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def sidecar_manifest_hash(project_root: Path) -> str:
    digests: list[str] = []
    for pack in sidecar_packs(project_root):
        path = pack / "STAGED-SOURCE-MANIFEST.json"
        if path.is_file():
            digests.append(_sha256_file(path))
    body = {"sidecar_manifest_file_sha256": sorted(digests)}
    return hashlib.sha256(_canonical_bytes(body)).hexdigest()


def evaluation_fingerprint(
    *,
    project_root: Path,
    locator_manifest_hash: str,
    answer_set_hash: str,
    visible_pack_hash: str = "",
    evaluator_path: Path | None = None,
) -> dict[str, str]:
    evaluator = evaluator_path or (
        project_root / "backend/app/evaluation/ge_diagnostic_evaluator.py"
    )
    planner = project_root / "scripts/run_ge_retrieval_training_cycle.py"
    router = project_root / "backend/app/evaluation/ge_hold_reason_router.py"
    inputs = {
        "code_commit": git_commit_hash(project_root),
        "locator_manifest_hash": locator_manifest_hash,
        "evidence_sidecar_hash": sidecar_manifest_hash(project_root),
        "visible_pack_hash": visible_pack_hash,
        "evaluator_version": EVALUATOR_VERSION,
        "evaluator_file_sha256": _sha256_file(evaluator) if evaluator.is_file() else "",
        "retrieval_planner_file_sha256": _sha256_file(planner) if planner.is_file() else "",
        "hold_router_file_sha256": _sha256_file(router) if router.is_file() else "",
        "evaluation_policy_version": EVALUATION_POLICY_VERSION,
    }
    inputs["input_fingerprint_sha256"] = hashlib.sha256(_canonical_bytes(inputs)).hexdigest()
    value = dict(inputs)
    value["answer_set_hash"] = answer_set_hash
    value["fingerprint_sha256"] = hashlib.sha256(_canonical_bytes(value)).hexdigest()
    return value


def input_fingerprint_unchanged(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return str(left.get("input_fingerprint_sha256") or "") == str(
        right.get("input_fingerprint_sha256") or ""
    ) and bool(left.get("input_fingerprint_sha256"))


def fingerprint_unchanged(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return str(left.get("fingerprint_sha256") or "") == str(
        right.get("fingerprint_sha256") or ""
    ) and bool(left.get("fingerprint_sha256"))
