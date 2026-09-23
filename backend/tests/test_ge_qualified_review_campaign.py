from __future__ import annotations

import json

from app.evaluation.ge_currentness_packets import load_jsonl
from app.evaluation.ge_phase2_progress import (
    AWAITING_QUALIFIED_REVIEWER,
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NOT_STARTED,
    phase2_progress,
)
from app.evaluation.ge_progression_taxonomy import (
    FAIL_CLOSED_NO_EVIDENCE,
    HOLD_MATERIAL,
    TORT_D13,
    VERIFIED_FULL_CANDIDATE,
    VERIFIED_LIMITED_CANDIDATE,
)
from app.evaluation.ge_qualified_review_campaign import (
    CAMPAIGN_ID,
    DEFAULT_OUTPUT,
    EXPECTED_PROGRESSION_MANIFEST,
    EXPECTED_PROGRESSION_STATE,
    deleted_spans,
    overlay_working_dispositions,
    question_still_materially_answered,
    recommended_decision,
    run_qualified_review_campaign,
    verify_progression_pack,
)
from app.evaluation.ge_qualified_review_packets import REVIEWER_OPTIONS


def test_phase2_default_is_unchanged() -> None:
    ledger = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert ledger["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    awaiting = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        awaiting_qualified_reviewer=True,
    )
    assert awaiting["overall_state"] == AWAITING_QUALIFIED_REVIEWER
    assert awaiting["overall_progress"] is True


def test_progression_pack_hashes_recompute() -> None:
    receipt = verify_progression_pack()
    assert receipt["manifest_sha256"] == EXPECTED_PROGRESSION_MANIFEST
    assert receipt["state_sha256"] == EXPECTED_PROGRESSION_STATE
    assert receipt["pass"] is True
    assert receipt["qualified_review_queue"] == 330
    assert receipt["excluded"] == [TORT_D13]


def test_deleted_spans_and_adequacy() -> None:
    original = "The will is valid. Erasure is automatic in every case."
    contracted = "Erasure is not automatic. A listed ground must apply."
    spans = deleted_spans(original, contracted)
    assert any("valid" in item["deleted_text"] or "automatic in every" in item["deleted_text"] for item in spans)
    assert question_still_materially_answered(
        "Can I ask my employer to delete recordings?",
        "UK GDPR Article 17 gives a right to obtain erasure of personal data where a listed ground applies, but it is not automatic.",
    )
    assert question_still_materially_answered("Short?", "No.") is False


def test_claim_support_fail_reclassifies_only_that_case() -> None:
    progression = [
        {"case_id": "keep:1", "disposition": VERIFIED_LIMITED_CANDIDATE, "topic_id": "keep", "diagnostic_factual_outcome": "FACTUAL_HOLD"},
        {"case_id": "drop:1", "disposition": VERIFIED_LIMITED_CANDIDATE, "topic_id": "drop", "diagnostic_factual_outcome": "FACTUAL_HOLD"},
        {"case_id": TORT_D13, "disposition": "FAIL_CLOSED_NO_EVIDENCE", "topic_id": "tort-law", "diagnostic_factual_outcome": "FACTUAL_HOLD"},
    ]
    receipts = [
        {"case_id": "keep:1", "working_disposition": VERIFIED_LIMITED_CANDIDATE},
        {"case_id": "drop:1", "working_disposition": HOLD_MATERIAL},
    ]
    overlaid = overlay_working_dispositions(progression, receipts)
    by_id = {item["case_id"]: item for item in overlaid}
    assert by_id["keep:1"]["working_disposition"] == VERIFIED_LIMITED_CANDIDATE
    assert by_id["drop:1"]["working_disposition"] == HOLD_MATERIAL
    assert by_id["drop:1"]["frozen_progression_disposition"] == VERIFIED_LIMITED_CANDIDATE
    assert by_id[TORT_D13]["qualified_review_eligible"] is False


def test_ai_recommendation_does_not_equal_reviewer_decision_codes_as_populated_field() -> None:
    assert recommended_decision(VERIFIED_LIMITED_CANDIDATE, "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT", "x") == "APPROVE_WITH_EDIT"
    assert recommended_decision(HOLD_MATERIAL, "HOLD_FOR_QUALIFIED_REVIEW", "x") == "HOLD"
    assert set(REVIEWER_OPTIONS) == {"APPROVE", "APPROVE_WITH_EDIT", "HOLD", "REJECT"}


def test_campaign_id_is_create_only_name() -> None:
    assert CAMPAIGN_ID == "LegalBot-GE-2026-09-03-qualified-review-campaign-r1"
    assert NOT_STARTED == "NOT_STARTED"


def test_campaign_prepares_330_workbook_and_awaits_reviewer() -> None:
    first = run_qualified_review_campaign()
    assert first["result"] in {"CREATED", "IDEMPOTENT_UNCHANGED"}
    second = run_qualified_review_campaign()
    assert second["result"] == "IDEMPOTENT_UNCHANGED"
    state = json.loads((DEFAULT_OUTPUT / "STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8"))
    assert state["overall_state"] == AWAITING_QUALIFIED_REVIEWER
    assert state["overall_progress"] is True
    assert state["qualified_legal_review"] == NOT_STARTED
    assert state["answer_legal_gold"] == NOT_STARTED
    assert state["answer_weight_training"] == NOT_STARTED
    assert state["sealed_unseen_execution"] == NOT_STARTED
    assert state["human_qualified_reviewer_identity_supplied"] is False
    assert state["ai_did_not_complete_qualified_review"] is True
    assert state["qualified_review_queue"] == 330
    counts = state["working_disposition_counts"]
    assert counts[VERIFIED_FULL_CANDIDATE] == 42
    assert counts[VERIFIED_LIMITED_CANDIDATE] == 2
    assert counts[HOLD_MATERIAL] == 18
    assert counts[FAIL_CLOSED_NO_EVIDENCE] == 1
    assert state["direct_review_ready_count"] == 312
    verification = json.loads(
        (DEFAULT_OUTPUT / "FIVE-CONTRACTED-ANSWER-VERIFICATION.json").read_text(encoding="utf-8")
    )
    assert set(verification["retained_verified_limited"]) == {
        "ai-and-data-protection:cp-d07",
        "competition-law:cp-d02",
    }
    assert set(verification["reclassified_hold_material"]) == {
        "ai-and-data-protection:cp-d03",
        "ai-and-data-protection:cp-d09",
        "land-law:cp-d17",
    }
    workbook = load_jsonl(DEFAULT_OUTPUT / "QUALIFIED-REVIEW-WORKBOOK.jsonl")
    assert len(workbook) == 330
    assert all(not row["qualified_review_decision"] for row in workbook)
    assert all(row["final_review_status"] == "REVIEW_NOT_COMPLETED" for row in workbook)
    assert TORT_D13 not in {row["case_id"] for row in workbook}
    gold = json.loads((DEFAULT_OUTPUT / "ANSWER-GOLD-CANDIDATE-REGISTER.json").read_text(encoding="utf-8"))
    assert gold["case_ids"] == []
    training = json.loads((DEFAULT_OUTPUT / "TRAINING-READINESS-AUDIT.json").read_text(encoding="utf-8"))
    assert training["training_authorisation"] == ""
