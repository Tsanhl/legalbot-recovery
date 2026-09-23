from __future__ import annotations

import json
from pathlib import Path

from app.evaluation.ge_claim_support_router import (
    CLAIM_FAILURE_CLASSES,
    classify_claim_case,
    route_claim_cases,
)
from app.evaluation.ge_kajima_mediation_family import (
    ATTACHABLE_PENDING_TARGETED_FAMILY,
    OUTSIDE_TARGETED_MEDIATION_FAMILY,
    TARGETED_MEDIATION_FAMILY,
    execute_kajima_attachments,
)
from app.evaluation.ge_currentness_subrouter import (
    CURRENTNESS_SUBREASONS,
    classify_currentness_subreason,
)
from app.evaluation.ge_hold_reason_router import (
    CASE_008,
    CASE_174,
    CASE_312,
    route_results,
)
from app.evaluation.ge_phase2_progress import (
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NO_OP_UNCHANGED_CASE_INPUTS,
    phase2_progress,
)
from app.evaluation.ge_qualified_review_packets import build_review_packet
from scripts.run_ge_retrieval_training_cycle import ISSUE_LOCATOR_HINTS, TOPIC_SOURCES

DELTA = Path(
    "data/evaluations/general-enquiries/"
    "LegalBot-GE-2026-09-02-mechanical-repair-delta-r1/visible/RESULTS.jsonl"
)
HINTS = {
    "accessibility": (("Equality Act 2010", "section 20"),),
    "trustees": (("Trustee Act 2000", "section 3"),),
}


def _hold_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "case_id": "administrative-law:cp-d99",
        "topic_id": "administrative-law",
        "issue_tags": ["accessibility"],
        "question": "The online form is inaccessible. What duty applies?",
        "user_facing_answer": "The selected passage has not been shown to be complete controlling law.",
        "factual_result": {
            "outcome": "FACTUAL_HOLD",
            "checks": {
                "claim_evidence_support": "FAIL",
                "requested_date_and_currentness": "PASS",
                "jurisdiction_scope": "PASS",
            },
            "diagnostic_checks": {
                "issue_relevance": {"outcome": "FAIL", "reason": "shares no material terms"},
                "passage_completeness": {"outcome": "PASS", "reason": ""},
                "quotation_fidelity": {"outcome": "PASS", "reason": ""},
            },
            "reasons": {"claim_evidence_support": "shares no material terms"},
        },
        "evidence": [
            {
                "title": "Equality Act 2010",
                "locator": "section 20",
                "quote": "Where this Act imposes a duty to make reasonable adjustments...",
                "evidence_span_sha256": "a" * 64,
            }
        ],
    }
    row.update(overrides)
    return row


def test_matched_hint_with_issue_relevance_fail_is_evaluator_false_negative() -> None:
    routed = classify_claim_case(_hold_row(), locator_hints=HINTS, topic_sources=TOPIC_SOURCES)
    assert routed["failure_class"] == "EVALUATOR_FALSE_NEGATIVE"
    assert routed["machine_repairable"] is False
    assert routed["mechanical_status"] == "EXHAUSTED"
    assert routed["qualified_review_ready"] is True
    assert routed["terminal_for_entire_pipeline"] is False


def test_off_topic_unmatched_hint_is_wrong_route_not_generic_retrieval() -> None:
    routed = classify_claim_case(
        _hold_row(
            case_id="pensions-law:cp-d11",
            topic_id="pensions-law",
            issue_tags=["trustees"],
            evidence=[
                {
                    "title": "Companies Act 2006",
                    "locator": "section 175",
                    "quote": "A director of a company must avoid a situation...",
                    "evidence_span_sha256": "b" * 64,
                }
            ],
        ),
        locator_hints=HINTS,
        topic_sources=TOPIC_SOURCES,
    )
    assert routed["failure_class"] == "ANSWER_USES_WRONG_LEGAL_ROUTE"
    assert routed["machine_repairable"] is False
    assert routed["proposed_mechanical_action"] == "NO_DETERMINISTIC_ON_TOPIC_LOCATOR"


def test_on_topic_unmatched_hint_is_attachable_until_inputs_repeat() -> None:
    row = _hold_row(
        issue_tags=["accessibility"],
        evidence=[
            {
                "title": "Equality Act 2010",
                "locator": "section 29",
                "quote": "A person must not discriminate...",
                "evidence_span_sha256": "c" * 64,
            }
        ],
    )
    first = classify_claim_case(row, locator_hints=HINTS, topic_sources=TOPIC_SOURCES)
    assert first["failure_class"] == "EVIDENCE_SELECTION_DEFECT"
    assert first["machine_repairable"] is True
    assert first["proposed_mechanical_action"] == "ATTACH_HINTED_LOCATOR"
    repeated = classify_claim_case(
        row,
        locator_hints=HINTS,
        topic_sources=TOPIC_SOURCES,
        previous_input_hash=first["case_input_hash"],
    )
    assert repeated["mechanical_status"] == "EXHAUSTED"
    assert repeated["proposed_mechanical_action"] == NO_OP_UNCHANGED_CASE_INPUTS
    assert repeated["qualified_review_ready"] is True


def test_named_cases_are_never_claim_mechanical() -> None:
    for case_id in (CASE_008, CASE_174, CASE_312):
        routed = classify_claim_case(
            _hold_row(case_id=case_id),
            locator_hints=HINTS,
            topic_sources=TOPIC_SOURCES,
        )
        assert routed["machine_repairable"] is False
        assert routed["named_case_invariant"] is True


def test_currentness_subreason_is_closed_set() -> None:
    classified = classify_currentness_subreason(
        {
            "question": "As at 15 January 2024, was the video will valid?",
            "factual_result": {
                "diagnostic_checks": {"historical_date_applicability": {"outcome": "FAIL"}},
                "reasons": {"requested_date_and_currentness": "historical date"},
            },
            "evidence": [
                {
                    "title": "Wills Act 1837 (as at 2024-01-15)",
                    "locator": "section 9",
                    "point_in_time_as_at": "2024-01-15",
                    "currentness_verified": False,
                    "provision_extent_status": "unverified",
                }
            ],
        }
    )
    assert classified["currentness_subreason"] == "HISTORIC_AS_OF_DATE_REVIEW"
    assert classified["currentness_subreason"] in CURRENTNESS_SUBREASONS
    analysis = classified["currentness_analysis"]
    assert analysis["required_as_of_date"] == "2024-01-15"
    assert analysis["candidate_reviewer_decision"] == "HOLD"


def test_case_312_packet_is_conditional_not_validity_gold() -> None:
    packet = build_review_packet(
        {
            "case_id": CASE_312,
            "topic_id": "wills-and-estates",
            "issue_tags": ["video-will"],
            "question": "On 15 January 2024 a video-witnessed will was signed. Is it valid?",
            "user_facing_answer": "Validity depends on the signing and witnessing sequence.",
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "factual_result": {
                "outcome": "FACTUAL_HOLD",
                "checks": {"claim_evidence_support": "PASS"},
            },
            "evidence": [{"title": "Wills Act 1837 (as at 2024-01-15)", "locator": "section 9"}],
            "improvement_reasons": ["case_validity:video_will_sequence_fact_dependent"],
        }
    )
    assert packet["qualified_legal_review"] == "NOT_STARTED"
    assert packet["do_not_assert_definitive_validity"] is True
    assert packet["conditional_answer_potentially_approvable"] is True
    assert packet["terminal_for_entire_pipeline"] is False
    assert packet["proposed_deterministic_edits"]


def test_delta_claim_queue_exhausts_without_generic_retrieval() -> None:
    if not DELTA.is_file():
        return
    rows = [json.loads(line) for line in DELTA.read_text(encoding="utf-8").splitlines() if line.strip()]
    routed = route_results(rows)
    assert routed["factual_pass_count"] == 41
    assert routed["runnable_queue_count"] == 53
    assert routed["qualified_review_ready_count"] == 278
    assert routed["terminal_for_entire_pipeline_count"] == 0
    claim_rows = [row for row in rows if row["case_id"] in set(routed["runnable_case_ids"])]
    classified = route_claim_cases(
        claim_rows,
        locator_hints=ISSUE_LOCATOR_HINTS,
        topic_sources=TOPIC_SOURCES,
    )
    assert classified["case_count"] == 53
    assert classified["no_generic_retrieval"] is True
    runnable_case_ids = set(classified["runnable_case_ids"])
    assert runnable_case_ids == {"international-commercial-mediation:cp-d09"}
    assert classified["remaining_changed_input_runnable_count"] == 1
    assert classified["case_status"]["international-commercial-mediation:cp-d09"] == (
        ATTACHABLE_PENDING_TARGETED_FAMILY
    )
    assert classified["attachment_executed"] is False
    assert classified["attach_executed"] is False
    assert classified["factual_status_unchanged"] is True
    assert classified["claim_support_status_unchanged"] is True
    assert classified["frozen_baseline_unchanged"] is True
    d09 = next(item for item in classified["rows"] if item["case_id"] == "international-commercial-mediation:cp-d09")
    assert d09["proposed_mechanical_action"] == "ATTACH_HINTED_LOCATOR"
    assert d09["next_route"] == TARGETED_MEDIATION_FAMILY
    assert d09["locator_candidate_status"] == "ATTACHABLE"
    assert d09["mechanical_execution_status"] == "PENDING_TARGETED_FAMILY"
    assert d09["attach_executed"] is False
    assert d09["qualified_legal_review"] == "NOT_STARTED"
    assert d09["answer_gold"] == "NOT_STARTED"
    assert d09["attachable_hints"]
    assert all("Kajima" in item["title"] for item in d09["attachable_hints"])
    assert d09["factual_status"] == "FACTUAL_HOLD"
    assert d09["claim_support_status"] == "FAIL"
    assert set(classified["counts_by_failure_class"]) <= set(CLAIM_FAILURE_CLASSES)
    assert CASE_008 not in classified["moved_to_qualified_review_case_ids"]
    assert CASE_174 not in classified["moved_to_qualified_review_case_ids"]
    assert CASE_312 not in classified["moved_to_qualified_review_case_ids"]
    currentness = [
        item for item in routed["holds"] if item["hold_reason_code"] == "CURRENTNESS_UNRESOLVED"
    ]
    assert len(currentness) == 184
    assert {item["currentness_subreason"] for item in currentness} <= set(CURRENTNESS_SUBREASONS)
    assert sum(1 for item in currentness if item.get("currentness_subreason")) == 184
    progress = phase2_progress(
        case_results=rows,
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        qualified_review_ready_count=331,
        locator_hold_count=0,
        locator_pending_count=0,
        locator_reject_count=1,
    )
    assert progress["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    assert progress["phase2_r2_complete"] is True
    packet_008 = build_review_packet(next(row for row in rows if row["case_id"] == CASE_008))
    packet_174 = build_review_packet(next(row for row in rows if row["case_id"] == CASE_174))
    assert packet_008["factual_diagnostic_status"] == "FACTUAL_PASS"
    assert packet_008["qualified_legal_review"] == "NOT_STARTED"
    assert "Cable" not in json.dumps(packet_174["accepted_locators"])
    assert packet_174["no_arbitration_act_s9_for_mediation"] is True


def test_attachable_mediation_case_is_not_executed_outside_targeted_family() -> None:
    row = _hold_row(
        case_id="international-commercial-mediation:cp-d09",
        topic_id="international-commercial-mediation",
        issue_tags=["multi-tier-clause", "refusal"],
        question=(
            "Our dispute clause says negotiation first, then mediation, then court. "
            "The other side will not cooperate. What can we do without getting the next step wrong?"
        ),
        evidence=[
            {
                "title": "ICC Mediation Rules (contractually incorporated edition)",
                "locator": "article 5",
                "quote": "The Centre may appoint a Mediator.",
                "evidence_span_sha256": "d" * 64,
            }
        ],
    )
    discovered = classify_claim_case(
        row,
        locator_hints=ISSUE_LOCATOR_HINTS,
        topic_sources=TOPIC_SOURCES,
    )
    assert discovered["locator_candidate_status"] == "ATTACHABLE"
    assert discovered["case_status"] == ATTACHABLE_PENDING_TARGETED_FAMILY
    assert discovered["attach_executed"] is False
    assert discovered["next_route"] == TARGETED_MEDIATION_FAMILY
    blocked = execute_kajima_attachments(
        route="CLAIM_LEVEL_MECHANICAL_REPAIR",
        rows=[row],
        decisions=[
            {
                "case_id": "international-commercial-mediation:cp-d09",
                "decision": "ATTACH",
                "exact_kajima_paragraph": "paragraph 29",
            }
        ],
    )
    assert blocked["attach_executed"] is False
    assert blocked["refused_reason"] == OUTSIDE_TARGETED_MEDIATION_FAMILY
    assert [item.get("locator") for item in row["evidence"]] == ["article 5"]
