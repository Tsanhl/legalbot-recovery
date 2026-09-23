from __future__ import annotations

import json

from app.evaluation.ge_currentness_packets import load_jsonl, sha256_file, sha256_text
from app.evaluation.ge_grok_independent_review import (
    CAMPAIGN_ID,
    DEFAULT_OUTPUT,
    EXPECTED_QLR_WORKBOOK,
    REVIEWER_KIND,
    REVIEWER_MODEL,
    build_blind_row,
    is_diagnostic_template,
    run_grok_independent_review,
)
from app.evaluation.ge_grok_review_overrides import (
    RECOMMEND_APPROVE,
    RECOMMEND_HOLD,
    RECOMMEND_REJECT,
)
from app.evaluation.ge_hold_reason_router import CASE_174, CASE_312
from app.evaluation.ge_phase2_progress import AWAITING_QUALIFIED_REVIEWER, NOT_STARTED
from app.evaluation.ge_progression_taxonomy import LAND_LAW_D05, TORT_D13
from app.evaluation.ge_qualified_review_campaign import DEFAULT_OUTPUT as QLR_PACK


def test_template_detection_and_blinding() -> None:
    row = {
        "review_ordinal": 1,
        "risk_tier": 1,
        "case_id": "demo:1",
        "topic": "demo",
        "progression_disposition": "HOLD_MATERIAL",
        "working_disposition": "HOLD_MATERIAL",
        "question": "Can I challenge this?",
        "candidate_answer": (
            "The closest verified source text found in this run says: hello. "
            "I cannot give a final merits view until more is checked."
        ),
        "candidate_answer_hash": "",
        "material_claims": [],
        "evidence_references": [],
        "currentness_result": "FAIL",
        "jurisdiction_result": "FAIL",
        "named_case_invariant": False,
        "case_174_excludes_cable_and_arbitration_s9": False,
        "case_312_no_definitive_validity": False,
        "land_law_d05_date_ambiguity_preserved": False,
        "reviewed_answer_hash": "",
        "reviewed_evidence_hash": "a" * 64,
        "ai_advisory_recommendation": "APPROVE",
        "qualified_review_decision": "APPROVE",
    }
    row["candidate_answer_hash"] = sha256_text(row["candidate_answer"])
    row["reviewed_answer_hash"] = row["candidate_answer_hash"]
    assert is_diagnostic_template(row["candidate_answer"]) is True
    blind = build_blind_row(row)
    assert "ai_advisory_recommendation" not in blind
    assert "qualified_review_decision" not in blind
    assert blind["question"] == "Can I challenge this?"


def test_campaign_id_and_role() -> None:
    assert CAMPAIGN_ID == "LegalBot-GE-2026-09-03-grok-independent-review-r1"
    assert REVIEWER_KIND == "AI_MODEL_REVIEWER"
    assert REVIEWER_MODEL == "Cursor Grok 4.6"


def test_grok_review_pack() -> None:
    first = run_grok_independent_review()
    assert first["result"] in {"CREATED", "IDEMPOTENT_UNCHANGED"}
    second = run_grok_independent_review()
    assert second["result"] == "IDEMPOTENT_UNCHANGED"
    assert sha256_file(QLR_PACK / "QUALIFIED-REVIEW-WORKBOOK.jsonl") == EXPECTED_QLR_WORKBOOK
    state = json.loads((DEFAULT_OUTPUT / "STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8"))
    assert state["overall_state"] == AWAITING_QUALIFIED_REVIEWER
    assert state["qualified_legal_review"] == NOT_STARTED
    assert state["professional_legal_sign_off"] is False
    assert state["legal_gold"] == NOT_STARTED
    reviews = load_jsonl(DEFAULT_OUTPUT / "GROK-INDEPENDENT-REVIEW.jsonl")
    assert len(reviews) == 330
    assert len({item["case_id"] for item in reviews}) == 330
    assert TORT_D13 not in {item["case_id"] for item in reviews}
    assert all(item["reviewer_kind"] == REVIEWER_KIND for item in reviews)
    assert all(item["professional_legal_sign_off"] is False for item in reviews)
    assert all(item["ai_recommended_decision"] != RECOMMEND_APPROVE for item in reviews)
    by_id = {item["case_id"]: item for item in reviews}
    assert by_id[CASE_174]["ai_recommended_decision"] == RECOMMEND_HOLD
    assert by_id[CASE_312]["ai_recommended_decision"] == "RECOMMEND_APPROVE_WITH_EDIT"
    assert by_id[LAND_LAW_D05]["ai_recommended_decision"] == RECOMMEND_HOLD
    assert by_id["wills-and-estates:cp-s02"]["ai_recommended_decision"] == RECOMMEND_REJECT
    blind = load_jsonl(DEFAULT_OUTPUT / "QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl")
    assert len(blind) == 330
    assert all("ai_advisory_recommendation" not in item for item in blind)
    attestation = json.loads((DEFAULT_OUTPUT / "GROK-REVIEW-ATTESTATION.json").read_text(encoding="utf-8"))
    assert attestation["professional_legal_sign_off"] is False
    assert attestation["human_reviewer_identity"] == ""
    assert attestation["signature"] == ""
