from __future__ import annotations

from app.evaluation.ge_ai_advisory_campaign import (
    CASE_174,
    CASE_312,
    DEFAULT_OUTPUT,
    EXPECTED_MASTER_INDEX,
    EXPECTED_MASTER_MANIFEST,
    EXPECTED_RESIDUAL_MANIFEST,
    INCORRECT_RESIDUAL_ENDING,
    SIX_NO_EVIDENCE,
    TERMINAL_ADVISORY_CLASSES,
    currentness_locator_disposition,
    jurisdiction_case_disposition,
    residual_hash_erratum,
    residual_case_disposition,
    verify_master_hashes,
)
from app.evaluation.ge_currentness_packets import EXPECTED_R2_RESULTS, load_jsonl, mutation_guard
from app.evaluation.ge_evaluation_completion_campaign import DEFAULT_MASTER_PACK
from app.evaluation.ge_factual_gap_fill import lookup_official
from app.evaluation.ge_phase2_progress import (
    AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW,
    MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING,
    NOT_STARTED,
    phase2_progress,
)


def test_phase2_progress_default_is_unchanged() -> None:
    ledger = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert ledger["overall_state"] == MECHANICAL_EVALUATION_COMPLETE_REVIEW_PENDING
    assert AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW != ledger["overall_state"]


def test_new_official_identifiers_are_registered() -> None:
    assert lookup_official("Land Registration Act 2002")["identifier"] == "ukpga/2002/9"
    assert lookup_official("Senior Courts Act 1981 section 37")["identifier"].endswith("section/37")
    vabeo = lookup_official(
        "The Competition Act 1998 (Vertical Agreements Block Exemption) Order 2022"
    )
    assert vabeo is not None
    assert vabeo["identifier"] == "uksi/2022/516"
    assert lookup_official("The Civil Procedure Rules 1998 Part 25")["identifier"].endswith("part/25")


def test_residual_hash_erratum_does_not_rewrite_history() -> None:
    erratum = residual_hash_erratum()
    assert erratum["incorrect_reported_ending"] == INCORRECT_RESIDUAL_ENDING
    assert erratum["correct_sha256"] == EXPECTED_RESIDUAL_MANIFEST
    assert erratum["immutable_historical_receipt_not_rewritten"] is True
    assert erratum["correct_sha256"].endswith("15b0dd678")
    assert not erratum["correct_sha256"].endswith(INCORRECT_RESIDUAL_ENDING)


def test_master_pack_hashes_recomputed() -> None:
    hashes = verify_master_hashes(DEFAULT_MASTER_PACK)
    assert hashes["master_manifest_sha256"] == EXPECTED_MASTER_MANIFEST
    assert hashes["master_index_sha256"] == EXPECTED_MASTER_INDEX
    assert hashes["residual_support_manifest_sha256"] == EXPECTED_RESIDUAL_MANIFEST


def test_frozen_r2_unchanged() -> None:
    mutation = mutation_guard()
    assert mutation["unchanged"] is True
    assert mutation["frozen_hashes"]["r2_results"] == EXPECTED_R2_RESULTS


def test_land_law_cp_d05_holds_on_ambiguous_date() -> None:
    packet = {
        "case_id": "land-law:cp-d05",
        "applicable_law_date_status": "INVALID_OR_AMBIGUOUS",
        "applicable_law_date_basis": "INVALID_OR_AMBIGUOUS",
    }
    locator = {
        "source_type": "PRIMARY_LEGISLATION",
        "later_treatment_or_appeal_status": "not_applicable_non_case_law",
        "source_version_date": "2026-08-14",
        "retrieval_date": "2026-09-03",
        "amendments_effective_by_relevant_date": "unclassified",
    }
    result = currentness_locator_disposition(locator, packet)
    assert result["locator_decision"] == "HOLD_CURRENTNESS"
    assert result["currentness_not_inferred_from_retrieval_date"] is True


def test_currentness_not_approved_from_retrieval_date_or_unclassified_effects() -> None:
    packet = {
        "case_id": "administrative-law:cp-d01",
        "applicable_law_date_status": "DEFAULTED_TO_OWNER_CUTOFF",
        "applicable_law_date_basis": "DEFAULT_OWNER_CUTOFF_NO_HISTORIC_DATE",
        "jurisdiction": "England and Wales",
    }
    locator = {
        "source_type": "PRIMARY_LEGISLATION",
        "later_treatment_or_appeal_status": "not_applicable_non_case_law",
        "source_version_date": "2026-08-14",
        "retrieval_date": "2026-09-03",
        "amendments_effective_by_relevant_date": "official_xml_unapplied_effect_markup_count=0; unclassified",
        "territorial_extent": "unverified",
    }
    result = currentness_locator_disposition(locator, packet)
    assert result["locator_decision"] == "HOLD_CURRENTNESS"
    assert result["threshold_passed"] is False


def test_case_law_holds_without_later_treatment_search() -> None:
    packet = {
        "case_id": "tort-law:cp-d01",
        "applicable_law_date_status": "DEFAULTED_TO_OWNER_CUTOFF",
        "applicable_law_date_basis": "DEFAULT_OWNER_CUTOFF_NO_HISTORIC_DATE",
    }
    locator = {
        "source_type": "CASE_LAW",
        "later_treatment_or_appeal_status": "later_treatment_search_not_executed_in_this_packet",
        "source_version_date": "2023-02-07",
        "retrieval_date": "2026-09-03",
        "amendments_effective_by_relevant_date": "not_recorded",
        "territorial_extent": "unverified",
    }
    result = currentness_locator_disposition(locator, packet)
    assert result["locator_decision"] == "HOLD_CURRENTNESS"
    assert "later_treatment_search_not_executed" in result["reasons"]


def test_case_174_jurisdiction_is_conditional_not_pass() -> None:
    packet = {
        "case_id": CASE_174,
        "jurisdiction_subreason": "CONTRACTUAL_INCORPORATION_AND_CROSS_BORDER_SCOPE",
    }
    result = jurisdiction_case_disposition(packet)
    assert result["route_decision"] == "CONDITIONAL_OR_LIMITED_SCOPE"
    assert result["terminal_advisory_class"] == "HOLD_FOR_QUALIFIED_REVIEW"
    assert result["do_not_convert_to_factual_pass"] is True
    assert result["jurisdiction_not_inferred_from_topic_name"] is True


def test_genuinely_unsupported_is_insufficient_authority() -> None:
    packet = {
        "case_id": "land-law:cp-d02",
        "hold_reason": "CLAIM_NOT_SUPPORTED",
        "failure_class": "GENUINELY_UNSUPPORTED_PROPOSITION",
    }
    result = residual_case_disposition(packet)
    assert result["route_decision"] == "INSUFFICIENT_AUTHORITY"
    assert result["terminal_advisory_class"] == "INSUFFICIENT_AUTHORITY"


def test_campaign_pack_if_present() -> None:
    if not DEFAULT_OUTPUT.is_dir():
        return
    dispositions = load_jsonl(DEFAULT_OUTPUT / "AI-ASSISTED-OWNER-ADVISORY-DISPOSITIONS.jsonl")
    assert len(dispositions) == 331
    assert len({item["case_id"] for item in dispositions}) == 331
    for item in dispositions:
        assert item["terminal_advisory_class"] in TERMINAL_ADVISORY_CLASSES
        assert item["individual_human_row_reviewed"] is False
        assert item["qualified_legal_review"] == NOT_STARTED
        assert item["answer_legal_gold"] is False
        assert item["legal_gold"] is False
        assert item["reviewer_kind"] == "AI_EVIDENCE_REVIEWER"
    state = __import__("json").loads((DEFAULT_OUTPUT / "STATE-TRANSITION-RECEIPT.json").read_text(encoding="utf-8"))
    assert state["overall_state"] == AI_ADVISORY_COMPLETE_AWAITING_QUALIFIED_LEGAL_REVIEW
    assert state["overall_progress"] is True
    assert state["human_case_by_case_owner_review"] == "NOT_PERFORMED"
    assert state["qualified_legal_review"] == NOT_STARTED
    assert state["answer_weight_training"] == NOT_STARTED
    assert state["sealed_unseen_execution"] == NOT_STARTED
    assert state["live"] == NOT_STARTED
    six = load_jsonl(DEFAULT_OUTPUT / "KNOWLEDGE-GAP-RESEARCH-REGISTER.jsonl")
    assert {item["case_id"] for item in six} == set(SIX_NO_EVIDENCE)
    case_312 = next(item for item in dispositions if item["case_id"] == CASE_312)
    assert case_312["terminal_advisory_class"] == "FACT_DEPENDENT_HOLD"
    d05 = next(item for item in dispositions if item["case_id"] == "land-law:cp-d05")
    assert d05["route_decision"] == "HOLD_CURRENTNESS"
    case_174 = next(item for item in dispositions if item["case_id"] == CASE_174)
    assert case_174["do_not_convert_to_factual_pass"] is True
    erratum = __import__("json").loads((DEFAULT_OUTPUT / "RESIDUAL-HASH-ERRATUM.json").read_text(encoding="utf-8"))
    assert erratum["correct_sha256"] == EXPECTED_RESIDUAL_MANIFEST
    assert "15f0dd678" not in erratum["correct_sha256"]
