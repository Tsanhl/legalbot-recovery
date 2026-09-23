from __future__ import annotations

import json

from app.evaluation.ge_currentness_packets import load_jsonl, sha256_file
from app.evaluation.ge_grok_independent_review import EXPECTED_QLR_WORKBOOK, is_diagnostic_template
from app.evaluation.ge_grok_readiness_audit import (
    CAMPAIGN_ID,
    CHATGPT_PACK,
    CUSTOM_FIVE,
    DEFAULT_OUTPUT,
    EXPECTED_BLIND,
    EXPECTED_CHATGPT_PROMPT,
    EXPECTED_CHATGPT_REVIEW,
    REVIEWER_KIND,
    REVIEWER_MODEL,
    count_markers,
    load_blind_rows,
    run_grok_readiness_audit,
)
from app.evaluation.ge_grok_review_overrides import RECOMMEND_HOLD
from app.evaluation.ge_phase2_progress import (
    ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NOT_STARTED,
    phase2_progress,
)
from app.evaluation.ge_progression_taxonomy import VERIFIED_FULL_CANDIDATE
from app.evaluation.ge_qualified_review_campaign import DEFAULT_OUTPUT as QLR_PACK


def test_phase2_reconstruction_required_is_opt_in() -> None:
    default = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert default["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    required = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        answer_reconstruction_required=True,
    )
    assert required["overall_state"] == ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW
    assert required["overall_progress"] is True


def test_chatgpt_ingest_hashes() -> None:
    assert sha256_file(CHATGPT_PACK / "CHATGPT-INDEPENDENT-REVIEW.jsonl") == EXPECTED_CHATGPT_REVIEW
    assert sha256_file(CHATGPT_PACK / "GROK-INDEPENDENT-READINESS-PROMPT.txt") == EXPECTED_CHATGPT_PROMPT
    reviews = load_jsonl(CHATGPT_PACK / "CHATGPT-INDEPENDENT-REVIEW.jsonl")
    assert len(reviews) == 330
    assert {item["ai_recommended_decision"] for item in reviews} == {RECOMMEND_HOLD}


def test_blind_markers_match_chatgpt() -> None:
    blinds = load_blind_rows()
    assert len(blinds) == 330
    assert sha256_file(
        CHATGPT_PACK.parent / "LegalBot-GE-2026-09-03-grok-independent-review-r1" / "QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl"
    ) == EXPECTED_BLIND
    markers = count_markers(blinds)
    assert markers["closest_verified"] == 325
    assert markers["withholds_final_merits"] == 325
    assert markers["incomplete_controlling_law"] == 325
    assert markers["owner_review_disclaimer"] == 325
    assert markers["planner_notes"] == 256
    assert markers["generic_emergency"] == 49
    full = [item for item in blinds if item["working_disposition"] == VERIFIED_FULL_CANDIDATE]
    assert len(full) == 42
    assert all(is_diagnostic_template(item["candidate_answer"]) for item in full)
    custom = {
        item["case_id"]
        for item in blinds
        if not is_diagnostic_template(item["candidate_answer"])
    }
    assert custom == set(CUSTOM_FIVE)


def test_campaign_id_and_role() -> None:
    assert CAMPAIGN_ID == "LegalBot-GE-2026-09-03-grok-readiness-audit-r1"
    assert REVIEWER_KIND == "AI_MODEL_REVIEWER"
    assert REVIEWER_MODEL == "Cursor Grok 4.6"


def test_readiness_pack() -> None:
    first = run_grok_readiness_audit()
    assert first["result"] in {"CREATED", "IDEMPOTENT_UNCHANGED"}
    second = run_grok_readiness_audit()
    assert second["result"] == "IDEMPOTENT_UNCHANGED"
    assert sha256_file(QLR_PACK / "QUALIFIED-REVIEW-WORKBOOK.jsonl") == EXPECTED_QLR_WORKBOOK
    state = json.loads((DEFAULT_OUTPUT / "STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8"))
    assert state["overall_state"] == ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW
    assert state["qualified_legal_review"] == NOT_STARTED
    assert state["professional_legal_sign_off"] is False
    assert state["recommendation_counts"][RECOMMEND_HOLD] == 330
    assert state["dual_ai_current_hash_consensus"] == "HOLD_330"
    reviews = load_jsonl(DEFAULT_OUTPUT / "GROK-INDEPENDENT-REVIEW.jsonl")
    assert len(reviews) == 330
    assert all(item["ai_recommended_decision"] == RECOMMEND_HOLD for item in reviews)
    assert all(item["professional_legal_sign_off"] is False for item in reviews)
    claims = load_jsonl(DEFAULT_OUTPUT / "GROK-CLAIM-REVIEW.jsonl")
    assert len(claims) == 890
    edits = load_jsonl(DEFAULT_OUTPUT / "GROK-EDIT-REGISTER.jsonl")
    assert len(edits) == 330
    assert all(not item["proposed_final_answer"] for item in edits)
    audit = json.loads((DEFAULT_OUTPUT / "GROK-READINESS-AUDIT.json").read_text(encoding="utf-8"))
    assert audit["exact_answer_hashes_recommended_approve"] == 0
    assert audit["fallback_template_answers"] == 325
    attestation = json.loads((DEFAULT_OUTPUT / "GROK-REVIEW-ATTESTATION.json").read_text(encoding="utf-8"))
    assert attestation["reviewer_kind"] == REVIEWER_KIND
    assert attestation["professional_legal_sign_off"] is False
    register = json.loads((DEFAULT_OUTPUT / "GROK-HASH-REGISTER.json").read_text(encoding="utf-8"))
    assert "GROK-READINESS-AUDIT.json" in register["files"]
