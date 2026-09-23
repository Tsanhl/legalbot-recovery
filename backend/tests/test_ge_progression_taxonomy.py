from __future__ import annotations

from app.evaluation.ge_control_plane_v2 import control_plane_v2
from app.evaluation.ge_diagnostic_evaluator import evaluate_factual_checks
from app.evaluation.ge_phase2_progress import (
    EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW,
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NOT_STARTED,
    phase2_progress,
)
from app.evaluation.ge_progression_taxonomy import (
    CASE_174,
    CASE_312,
    CONDITIONAL_REVIEW_READY,
    FAIL_CLOSED_NO_EVIDENCE,
    HOLD_MATERIAL,
    LAND_LAW_D05,
    REVIEW_READY_CURRENTNESS,
    REVIEW_READY_JURISDICTION,
    TORT_D13,
    VERIFIED_FULL_CANDIDATE,
    VERIFIED_LIMITED_CANDIDATE,
    classify_progression_from_route,
    gold_eligible,
    is_factual_failure,
    progression_from_checks,
    qualified_review_eligible,
)
from tests.test_ge_retrieval_training_cycle import S174, _row


def test_phase2_progress_default_is_unchanged() -> None:
    ledger = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert ledger["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    assert ledger["diagnostic_factual_hold_is_not_equivalent_failure"] is True


def test_terminally_classified_state_requires_explicit_flag() -> None:
    ledger = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        terminally_classified=True,
    )
    assert ledger["overall_state"] == EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW
    assert ledger["overall_progress"] is True


def test_currentness_pending_is_review_ready_not_failure() -> None:
    result = progression_from_checks(
        checks={
            "claim_evidence_support": "PASS",
            "requested_date_and_currentness": "FAIL",
            "jurisdiction_scope": "PASS",
            "integrity_chain": "PASS",
            "safety_and_urgent_action": "PASS",
            "privacy_and_instruction_isolation": "PASS",
        },
        evidence_present=True,
    )
    assert result["disposition"] == REVIEW_READY_CURRENTNESS
    assert result["is_factual_failure"] is False
    assert result["qualified_review_eligible"] is True
    assert result["answer_gold"] is False
    assert result["training_eligible"] is False
    assert gold_eligible(result["disposition"]) is False


def test_jurisdiction_pending_is_review_ready_not_failure() -> None:
    result = classify_progression_from_route(
        case_id=CASE_174,
        factual_status="FACTUAL_HOLD",
        hold_reason_code="JURISDICTION_SCOPE_REVIEW",
        evidence_present=True,
    )
    assert result["disposition"] == REVIEW_READY_JURISDICTION
    assert is_factual_failure(result["disposition"]) is False


def test_case_312_is_conditional_review_ready() -> None:
    result = classify_progression_from_route(
        case_id=CASE_312,
        factual_status="FACTUAL_HOLD",
        hold_reason_code="FACT_DEPENDENT_OUTCOME",
        evidence_present=True,
    )
    assert result["disposition"] == CONDITIONAL_REVIEW_READY
    assert result["qualified_review_eligible"] is True
    assert result["legal_gold"] is False


def test_no_evidence_after_research_is_fail_closed() -> None:
    result = classify_progression_from_route(
        case_id=TORT_D13,
        factual_status="FACTUAL_HOLD",
        hold_reason_code="RETRIEVAL_NO_EVIDENCE",
        evidence_present=False,
        research_exhausted=True,
    )
    assert result["disposition"] == FAIL_CLOSED_NO_EVIDENCE
    assert qualified_review_eligible(result["disposition"]) is False
    assert is_factual_failure(result["disposition"]) is True


def test_attached_no_evidence_with_contraction_is_limited_candidate() -> None:
    result = classify_progression_from_route(
        case_id="ai-and-data-protection:cp-d03",
        factual_status="FACTUAL_HOLD",
        hold_reason_code="RETRIEVAL_NO_EVIDENCE",
        evidence_present=False,
        attached_after_research=True,
        contraction_applied=True,
    )
    assert result["disposition"] == VERIFIED_LIMITED_CANDIDATE
    assert result["answer_gold"] is False


def test_claim_not_supported_starts_as_hold_material() -> None:
    result = classify_progression_from_route(
        case_id="land-law:cp-d02",
        factual_status="FACTUAL_HOLD",
        hold_reason_code="CLAIM_NOT_SUPPORTED",
        evidence_present=True,
    )
    assert result["disposition"] == HOLD_MATERIAL
    assert result["qualified_review_eligible"] is True
    assert result["training_eligible"] is False


def test_background_locator_does_not_fail_claim_support_when_material_locator_passes() -> None:
    prompt = (
        "A public authority’s online form is inaccessible to me because of a "
        "disability. How can I get help using the service and raise a complaint?"
    )
    mixed = evaluate_factual_checks(
        case={
            "prompt": prompt,
            "issue_tags": ["accessibility", "public-duty", "equality"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                chunk_id="c174",
                title="Equality Act 2010",
                locator="section 174",
                quote=S174,
                stored_text=S174,
            ),
            _row(
                chunk_id="c20",
                title="Equality Act 2010",
                locator="section 20",
                quote="A duty to make reasonable adjustments applies to the listed services.",
                stored_text="A duty to make reasonable adjustments applies to the listed services.",
            ),
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert mixed.checks["claim_evidence_support"] == "PASS"
    assert "BACKGROUND" in mixed.locator_materiality
    only_wrong = evaluate_factual_checks(
        case={
            "prompt": prompt,
            "issue_tags": ["accessibility", "public-duty", "equality"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[
            _row(
                title="Equality Act 2010",
                locator="section 174",
                quote=S174,
                stored_text=S174,
            )
        ],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert only_wrong.checks["claim_evidence_support"] == "FAIL"


def test_evaluator_progression_keeps_factual_hold_when_currentness_fails() -> None:
    result = evaluate_factual_checks(
        case={
            "prompt": "May a person do the prohibited act under this rule?",
            "issue_tags": ["prohibited-act"],
            "primary_jurisdiction": "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=[_row()],
        source_manifest_sha256="b" * 64,
        user_facing_answer_text="Your question is repeated.",
    )
    assert result.failed
    assert result.checks["claim_evidence_support"] == "PASS"
    assert result.progression["disposition"] in {
        REVIEW_READY_CURRENTNESS,
        REVIEW_READY_JURISDICTION,
    }
    assert result.progression["is_factual_failure"] is False
    assert result.progression["legal_gold"] is False


def test_control_plane_reports_progression_and_stays_not_gold() -> None:
    plane = control_plane_v2(
        case_results=[
            {"case_id": "pass:1", "factual_result": {"outcome": "FACTUAL_PASS"}, "evidence": [{}]},
            {
                "case_id": CASE_174,
                "factual_result": {"outcome": "FACTUAL_HOLD", "checks": {"claim_evidence_support": "PASS"}},
                "evidence": [{"quote": "text", "title": "Ohpen"}],
            },
        ],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert plane["factual_hold_is_not_equivalent_failure"] is True
    assert plane["gold_eligible_count"] == 0
    assert plane["answer_legal_gold"] is False
    assert plane["training_gold"] is False
    assert plane["downstream_gates"]["qualified_legal_review"] == NOT_STARTED
    assert plane["progression_disposition_counts"][VERIFIED_FULL_CANDIDATE] == 1
    assert plane["progression_disposition_counts"][REVIEW_READY_JURISDICTION] == 1


def test_latest_delta_reclassifies_331_without_calling_holds_failures() -> None:
    from app.evaluation.ge_ai_advisory_campaign import CONSERVATIVE_PROPOSED, SIX_NO_EVIDENCE
    from app.evaluation.ge_currentness_packets import load_latest_delta_rows
    from app.evaluation.ge_progression_taxonomy import classify_331_rows, summarize_dispositions

    rows = load_latest_delta_rows()
    classified = classify_331_rows(
        rows,
        attached_ids=[case_id for case_id in SIX_NO_EVIDENCE if case_id != TORT_D13],
        exhausted_ids=[TORT_D13],
        contraction_ids=list(CONSERVATIVE_PROPOSED),
        incomplete_final_ids=[LAND_LAW_D05],
    )
    summary = summarize_dispositions(classified)
    counts = summary["disposition_counts"]
    assert summary["total"] == 331
    assert summary["diagnostic_factual_counts"]["FACTUAL_PASS"] == 42
    assert summary["diagnostic_factual_counts"]["FACTUAL_HOLD"] == 289
    assert counts[VERIFIED_FULL_CANDIDATE] == 42
    assert counts[VERIFIED_LIMITED_CANDIDATE] == 5
    assert counts[REVIEW_READY_CURRENTNESS] == 211
    assert counts[REVIEW_READY_JURISDICTION] == 56
    assert counts[CONDITIONAL_REVIEW_READY] == 1
    assert counts[HOLD_MATERIAL] == 15
    assert counts[FAIL_CLOSED_NO_EVIDENCE] == 1
    assert summary["qualified_review_eligible_count"] == 330
    assert summary["cases_advanced_without_legal_approval_count"] == 315
    assert summary["hard_evidence_gap_count"] == 16
    assert summary["gold_ineligible_count"] == 331
    by_id = {item["case_id"]: item for item in classified}
    assert by_id[CASE_174]["disposition"] == REVIEW_READY_JURISDICTION
    assert by_id[CASE_312]["disposition"] == CONDITIONAL_REVIEW_READY
    assert by_id[LAND_LAW_D05]["disposition"] == REVIEW_READY_CURRENTNESS
    assert by_id[TORT_D13]["disposition"] == FAIL_CLOSED_NO_EVIDENCE
    assert all(item["answer_gold"] is False for item in classified)
    assert all(item["training_eligible"] is False for item in classified)
    result = classify_progression_from_route(
        case_id=LAND_LAW_D05,
        factual_status="FACTUAL_HOLD",
        hold_reason_code="CURRENTNESS_UNRESOLVED",
        evidence_present=True,
        incomplete_final=True,
    )
    assert result["disposition"] == REVIEW_READY_CURRENTNESS
    assert result["is_factual_failure"] is False
