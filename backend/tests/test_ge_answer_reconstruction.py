from __future__ import annotations

import json

from app.evaluation.ge_answer_reconstruction import (
    CAMPAIGN_ID,
    DEFAULT_OUTPUT,
    contains_forbidden,
    handwritten_library,
    planner_safe,
    run_answer_reconstruction,
)
from app.evaluation.ge_currentness_packets import load_jsonl, sha256_file
from app.evaluation.ge_diagnostic_evaluator import PLANNER_PREFIXES
from app.evaluation.ge_fact_dependent_packets import CONDITIONAL_ANSWER
from app.evaluation.ge_grok_independent_review import EXPECTED_QLR_WORKBOOK, is_diagnostic_template
from app.evaluation.ge_grok_readiness_audit import CUSTOM_FIVE
from app.evaluation.ge_hold_reason_router import CASE_174, CASE_312
from app.evaluation.ge_phase2_progress import (
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NOT_STARTED,
    REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW,
    phase2_progress,
)
from app.evaluation.ge_progression_taxonomy import LAND_LAW_D05, VERIFIED_FULL_CANDIDATE
from app.evaluation.ge_qualified_review_campaign import DEFAULT_OUTPUT as QLR_PACK


def test_phase2_revised_answers_state_is_opt_in() -> None:
    default = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert default["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    revised = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        revised_answers_awaiting_blind_review=True,
    )
    assert revised["overall_state"] == REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW


def test_planner_safe_and_handwritten_library() -> None:
    assert planner_safe("Do not wait overnight.").lower().startswith("on these facts")
    assert not any(
        planner_safe("Do not wait overnight.").casefold().startswith(prefix)
        for prefix in PLANNER_PREFIXES
    )
    library = handwritten_library()
    assert library[CASE_312] == CONDITIONAL_ANSWER
    assert "Arbitration Act 1996 section 9 is not used" in library[CASE_174]
    assert "1 May 2026" in library[LAND_LAW_D05]
    assert "interim payment" in library["land-law:cp-d17"].casefold()
    assert contains_forbidden(library[CASE_174]) == []


def test_campaign_id() -> None:
    assert CAMPAIGN_ID == "LegalBot-GE-2026-09-03-answer-reconstruction-r1"


def test_reconstruction_pack() -> None:
    first = run_answer_reconstruction()
    assert first["result"] in {"CREATED", "IDEMPOTENT_UNCHANGED"}
    second = run_answer_reconstruction()
    assert second["result"] == "IDEMPOTENT_UNCHANGED"
    assert sha256_file(QLR_PACK / "QUALIFIED-REVIEW-WORKBOOK.jsonl") == EXPECTED_QLR_WORKBOOK
    state = json.loads((DEFAULT_OUTPUT / "STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8"))
    assert state["overall_state"] == REVISED_ANSWERS_AWAITING_INDEPENDENT_BLIND_REVIEW
    assert state["qualified_legal_review"] == NOT_STARTED
    assert state["answer_legal_gold"] == NOT_STARTED
    assert state["professional_legal_sign_off"] is False
    rows = load_jsonl(DEFAULT_OUTPUT / "ANSWER-RECONSTRUCTION.jsonl")
    assert len(rows) == 330
    assert len({item["case_id"] for item in rows}) == 330
    assert all(item["revised_answer_hash"] != item["original_answer_hash"] for item in rows)
    assert all(not contains_forbidden(item["revised_answer"]) for item in rows)
    assert all(not is_diagnostic_template(item["revised_answer"]) for item in rows)
    full = [item for item in rows if item["working_disposition"] == VERIFIED_FULL_CANDIDATE]
    assert len(full) == 42
    assert all(not is_diagnostic_template(item["revised_answer"]) for item in full)
    by_id = {item["case_id"]: item for item in rows}
    assert by_id[CASE_312]["revised_answer"] == CONDITIONAL_ANSWER
    assert "Arbitration Act 1996 section 9 is not used" in by_id[CASE_174]["revised_answer"]
    assert "1 May 2026" in by_id[LAND_LAW_D05]["revised_answer"]
    assert "15 August 2026" in by_id[LAND_LAW_D05]["revised_answer"]
    assert "interim payment" in by_id["land-law:cp-d17"]["revised_answer"].casefold()
    assert "not completely mapped" in by_id["competition-law:cp-d02"]["revised_answer"].casefold()
    assert set(CUSTOM_FIVE) <= set(by_id)
    blind = load_jsonl(DEFAULT_OUTPUT / "REVISED-QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl")
    assert len(blind) == 330
    assert all("ai_advisory_recommendation" not in item for item in blind)
    checks = load_jsonl(DEFAULT_OUTPUT / "CHANGED-ANSWER-CHECKS.jsonl")
    assert len(checks) == 330
