from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.ge_hold_reason_router import (
    CASE_008,
    CASE_174,
    CASE_312,
    freeze_pass_case,
    route_hold,
    route_results,
)
from app.evaluation.ge_phase2_progress import (
    AWAITING_OWNER_DIAGNOSTIC_APPROVAL,
    HARD_STOP,
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NOT_STARTED,
    NO_OP_UNCHANGED_INPUTS,
    ROUTING_AND_REPAIRING_HELD_CASES,
    explicit_stage_states,
    fingerprint_unchanged,
    input_fingerprint_unchanged,
    phase2_progress,
    phase2_r2_complete,
)


def test_phase2_progress_awaits_owner_after_completed_holds() -> None:
    ledger = phase2_progress(
        case_results=[
            {"case_id": "a", "factual_result": {"outcome": "FACTUAL_PASS"}},
            {"case_id": "b", "factual_result": {"outcome": "FACTUAL_HOLD"}},
        ],
        diagnostic_execution="COMPLETE",
        diagnostic_report="WRITTEN",
    )
    assert ledger["overall_progress"] is True
    assert ledger["overall_state"] == AWAITING_OWNER_DIAGNOSTIC_APPROVAL
    assert ledger["held_or_fail_closed_cases"] == 1
    stopped = phase2_progress(case_results=[], hard_stop_reasons=["explicit_owner_stop"])
    assert stopped["overall_progress"] is False
    assert stopped["overall_state"] == HARD_STOP


def test_routed_state_uses_runnable_queue_not_hold_count() -> None:
    cases = [{"case_id": f"c{i}", "factual_result": {"outcome": "FACTUAL_HOLD"}} for i in range(5)]
    repairing = phase2_progress(
        case_results=cases,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=2,
        locator_hold_count=0,
        locator_pending_count=0,
    )
    assert repairing["overall_state"] == ROUTING_AND_REPAIRING_HELD_CASES
    assert repairing["phase2_r2_complete"] is False  # 5 != 331
    complete = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        locator_hold_count=0,
        locator_pending_count=0,
    )
    assert complete["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING


def test_not_started_is_not_failed() -> None:
    stages = explicit_stage_states()
    assert stages["qualified_legal_review"] == NOT_STARTED
    assert stages["answer_weight_training"] == NOT_STARTED
    assert stages["live"] == NOT_STARTED
    assert stages["not_started_is_not_failed"] is True
    assert stages["locator_review"] == "COMPLETE"


def test_r2_complete_does_not_require_later_gates() -> None:
    assert phase2_r2_complete(
        locator_package_resolved=True,
        r2_job_succeeded=True,
        processed_cases=331,
        classified_cases=331,
        diagnostic_report_written=True,
    )
    assert not phase2_r2_complete(
        locator_package_resolved=True,
        r2_job_succeeded=True,
        processed_cases=330,
        classified_cases=330,
        diagnostic_report_written=True,
    )


def test_named_case_routes() -> None:
    passed = freeze_pass_case(
        {
            "case_id": CASE_008,
            "factual_result": {"outcome": "FACTUAL_PASS", "checks": {}},
            "evidence": [{"evidence_span_sha256": "a" * 64, "locator": "section 20"}],
        }
    )
    assert passed["next_route"] == "QUALIFIED_LEGAL_REVIEW_QUEUE"
    assert passed["qualified_review_ready"] is True
    assert passed["frozen_regression"] is True
    assert passed["terminal_for_entire_pipeline"] is False
    routed_174 = route_hold(
        {
            "case_id": CASE_174,
            "topic_id": "international-commercial-mediation",
            "factual_result": {
                "outcome": "FACTUAL_HOLD",
                "checks": {
                    "claim_evidence_support": "PASS",
                    "jurisdiction_scope": "FAIL",
                    "requested_date_and_currentness": "PASS",
                },
                "reasons": {"jurisdiction_scope": "cross-border facts"},
            },
            "evidence": [{"title": "ICC Mediation Rules", "locator": "article 5"}],
            "improvement_reasons": ["factual:jurisdiction_scope"],
        }
    )
    assert routed_174["hold_reason_code"] == "JURISDICTION_SCOPE_REVIEW"
    assert routed_174["machine_repairable"] is False
    assert routed_174["automatic_reopen_cable_and_wireless"] is False
    routed_312 = route_hold(
        {
            "case_id": CASE_312,
            "topic_id": "wills-and-estates",
            "issue_tags": ["video-will"],
            "factual_result": {
                "outcome": "FACTUAL_HOLD",
                "checks": {"claim_evidence_support": "PASS", "jurisdiction_scope": "PASS"},
                "reasons": {},
            },
            "evidence": [{"title": "Wills Act 1837 (as at 2024-01-15)", "locator": "section 9"}],
            "improvement_reasons": ["case_validity:video_will_sequence_fact_dependent"],
        }
    )
    assert routed_312["hold_reason_code"] == "FACT_DEPENDENT_OUTCOME"
    assert routed_312["terminal_for_retrieval"] is True
    assert routed_312["terminal_for_mechanical_route"] is True
    assert routed_312["terminal_for_entire_pipeline"] is False
    assert routed_312["qualified_review_ready"] is True
    assert routed_312["conditional_answer_potentially_approvable"] is True
    assert routed_312["machine_repairable"] is False


def test_no_evidence_is_machine_repairable() -> None:
    routed = route_hold(
        {
            "case_id": "administrative-law:cp-d02",
            "topic_id": "administrative-law",
            "factual_result": {
                "outcome": "FACTUAL_HOLD",
                "checks": {"claim_evidence_support": "FAIL"},
                "reasons": {"claim_evidence_support": "No relevant primary-authority passage was selected."},
            },
            "evidence": [],
        }
    )
    assert routed["hold_reason_code"] == "RETRIEVAL_NO_EVIDENCE"
    assert routed["machine_repairable"] is True
    assert routed["next_route"] == "MECHANICAL_REPAIR"


def test_route_results_splits_runnable_and_terminal() -> None:
    bundled = route_results(
        [
            {
                "case_id": CASE_008,
                "factual_result": {"outcome": "FACTUAL_PASS", "checks": {}},
                "evidence": [{"locator": "section 20"}],
            },
            {
                "case_id": "x-missing",
                "factual_result": {
                    "outcome": "FACTUAL_HOLD",
                    "checks": {"claim_evidence_support": "FAIL"},
                    "reasons": {},
                },
                "evidence": [],
            },
            {
                "case_id": CASE_174,
                "factual_result": {
                    "outcome": "FACTUAL_HOLD",
                    "checks": {"claim_evidence_support": "PASS", "jurisdiction_scope": "FAIL"},
                    "reasons": {"jurisdiction_scope": "cross-border"},
                },
                "evidence": [{"title": "Ohpen"}],
            },
        ]
    )
    assert bundled["factual_pass_count"] == 1
    assert bundled["runnable_queue_count"] == 1
    assert bundled["terminal_queue_count"] == 1
    assert bundled["terminal_for_entire_pipeline_count"] == 0
    assert bundled["qualified_review_ready_count"] == 2
    assert bundled["targeted_repair_case_ids"] == ["x-missing"]


def test_frozen_r2_hold_manifest_invariants() -> None:
    path = Path(
        "data/evaluations/general-enquiries/"
        "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2/visible/RESULTS.jsonl"
    )
    if not path.is_file():
        return
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    routed = route_results(rows)
    assert routed["hold_count"] == 293
    assert routed["factual_pass_count"] == 38
    holds = {item["case_id"]: item for item in routed["holds"]}
    assert CASE_008 not in holds
    assert holds[CASE_174]["hold_reason_code"] == "JURISDICTION_SCOPE_REVIEW"
    assert holds[CASE_312]["hold_reason_code"] == "FACT_DEPENDENT_OUTCOME"
    assert routed["runnable_queue_count"] + routed["terminal_queue_count"] == 293


def test_attempt_counts_apply_only_to_named_rows() -> None:
    bundled = route_results(
        [
            {
                "case_id": "x-missing",
                "factual_result": {
                    "outcome": "FACTUAL_HOLD",
                    "checks": {"claim_evidence_support": "FAIL"},
                    "reasons": {},
                },
                "evidence": [],
            }
        ],
        attempt_counts={"x-missing": 2},
    )
    assert bundled["holds"][0]["attempt_count"] == 2


def test_load_targeted_repair_queue_roundtrip(tmp_path: Path) -> None:
    from app.evaluation.ge_hold_reason_router import load_targeted_repair_case_ids

    path = tmp_path / "queue.json"
    path.write_text(
        json.dumps({"case_ids": ["administrative-law:cp-d02", "tort-law:cp-d01"]}),
        encoding="utf-8",
    )
    assert load_targeted_repair_case_ids(path) == [
        "administrative-law:cp-d02",
        "tort-law:cp-d01",
    ]


def test_noop_compares_input_fingerprint() -> None:
    left = {"input_fingerprint_sha256": "abc", "fingerprint_sha256": "zzz"}
    right = {"input_fingerprint_sha256": "abc", "fingerprint_sha256": "yyy"}
    assert input_fingerprint_unchanged(left, right)
    assert not fingerprint_unchanged(left, right)
    assert NO_OP_UNCHANGED_INPUTS == "NO_OP_UNCHANGED_INPUTS"
