from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.phase2a_safe_fallback_qualification import (
    EVIDENCE_REQUIREMENT_STATUS,
    FAILURE_STATUS,
    HUMAN_ESCALATION_CTA,
    PERFORMANCE_BOND_BASIS_CLASS,
    PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256,
    PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES,
    PERFORMANCE_BOND_OUTCOME_CLASS,
    PERFORMANCE_BOND_REASON_CODE,
    PERFORMANCE_BOND_REGISTRY_ORDINAL,
    PERFORMANCE_BOND_ROW_ID,
    PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
    PERFORMANCE_BOND_UI_CTA,
    QUALIFICATION_STATUS,
    build_performance_bond_safe_fallback_disposition,
    performance_bond_safe_fallback_contract,
    qualify_performance_bond_safe_fallback_disposition,
    safe_fallback_contract,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OWNER_ADOPTION_SHA256 = "b" * 64
PROJECT_RESCUE_CONTRACT_SHA256 = "ba6c131f06e05bed9f6b6aa5743dc974f3b13618e3af39ffcaaabaf0f84c72f6"


@pytest.fixture(scope="module")
def bundle():
    return load_live_evaluation_bundle(PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1")


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _reseal(value: dict[str, Any], field: str = "record_content_sha256") -> None:
    value.pop(field, None)
    value[field] = hashlib.sha256(_canonical(value)).hexdigest()


def test_existing_project_rescue_contract_identity_is_unchanged() -> None:
    assert safe_fallback_contract()["contract_content_sha256"] == (PROJECT_RESCUE_CONTRACT_SHA256)


def test_performance_bond_contract_is_exactly_row_scoped_and_non_authorizing() -> None:
    contract = performance_bond_safe_fallback_contract()

    assert contract["row_id"] == PERFORMANCE_BOND_ROW_ID
    assert contract["registry_ordinal"] == PERFORMANCE_BOND_REGISTRY_ORDINAL
    assert contract["held9_advisory_content_sha256"] == (
        PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256
    )
    assert contract["qualification_status"] == QUALIFICATION_STATUS
    assert contract["qualification_result_when_contract_violated"] == FAILURE_STATUS
    assert contract["outcome_class"] == PERFORMANCE_BOND_OUTCOME_CLASS
    assert contract["basis_class"] == PERFORMANCE_BOND_BASIS_CLASS
    assert contract["reason_code"] == PERFORMANCE_BOND_REASON_CODE
    assert contract["ui_cta"] == PERFORMANCE_BOND_UI_CTA
    assert contract["human_escalation_cta"] == HUMAN_ESCALATION_CTA
    assert contract["reply_match_mode"] == "EXACT_UTF8_STRING"
    assert contract["required_user_message"] == PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE
    assert contract["required_missing_information_categories"] == list(
        PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES
    )
    assert contract["registry_policy"] == {
        "row_remains_in_all585": True,
        "case_count": 60,
        "issue_count": 585,
        "row_removal_permitted": False,
    }
    assert contract["retained_underlying_holds"] == {
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "legal_rule_release_prohibited": True,
        "citation_release_prohibited": True,
        "evidence_span_release_prohibited": True,
        "underlying_substantive_answer_not_qualified": True,
    }
    assert all(
        contract["scope"][field] is False
        for field in (
            "production_qualification_performed",
            "phase2b_authorized",
            "development30_authorized",
            "validation30_authorized",
            "promotion_authorized",
            "active_or_previous_write_authorized",
            "live_activation_authorized",
        )
    )


def test_exact_performance_bond_fallback_passes_without_releasing_law(bundle) -> None:
    disposition = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    result = qualify_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        disposition=disposition,
        expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )

    assert result["qualification_status"] == QUALIFICATION_STATUS
    assert result["phase2a_row_technically_passed"] is True
    assert result["basis"]["basis_class"] == PERFORMANCE_BOND_BASIS_CLASS
    assert result["basis"]["evidence_requirement_status"] == (EVIDENCE_REQUIREMENT_STATUS)
    assert result["contract_checks"]["material_legal_claim_released"] is False
    assert result["contract_checks"]["legal_rule_release_prohibited"] is True
    assert result["contract_checks"]["citation_release_prohibited"] is True
    assert result["contract_checks"]["evidence_span_release_prohibited"] is True
    assert result["contract_checks"]["currentness_hold_retained"] is True
    assert result["contract_checks"]["later_treatment_hold_retained"] is True
    assert result["contract_checks"]["underlying_substantive_answer_not_qualified"] is True
    assert result["event_projection"] == {
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "reason_code": PERFORMANCE_BOND_REASON_CODE,
        "ui_cta": PERFORMANCE_BOND_UI_CTA,
    }
    assert result["phase2b_authorized"] is False


def test_performance_bond_fallback_requests_all_seven_exact_inputs(bundle) -> None:
    disposition = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )

    assert disposition["user_message"] == PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE
    assert disposition["missing_information_categories"] == list(
        PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES
    )
    assert len(disposition["missing_information_categories"]) == 7
    assert disposition["substantive_performance_bond_advice_refused"] is True
    assert disposition["supplementation_requested"] is True
    assert disposition["qualified_human_legal_review_required"] is True
    assert disposition["knowledge_gap_event"] is False
    assert disposition["matter_information_gap_event"] is True
    assert disposition["evidence_span_ids"] == []
    assert disposition["source_version_ids"] == []
    assert disposition["citations"] == []


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("substantive_performance_bond_advice_refused", False),
        ("supplementation_requested", False),
        ("qualified_human_legal_review_required", False),
        ("knowledge_gap_event", True),
        ("matter_information_gap_event", False),
        ("material_legal_claim_released", True),
        ("currentness_hold_retained", False),
        ("later_treatment_hold_retained", False),
        ("legal_rule_release_prohibited", False),
        ("citation_release_prohibited", False),
        ("evidence_span_release_prohibited", False),
        ("underlying_substantive_answer_not_qualified", False),
        ("phase2b_authorized", True),
    ),
)
def test_any_changed_safety_or_retained_hold_assertion_fails_closed(
    bundle, field, unsafe_value
) -> None:
    disposition = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    changed = copy.deepcopy(disposition)
    changed[field] = unsafe_value
    _reseal(changed)

    with pytest.raises(ValueError, match="does not exactly satisfy"):
        qualify_performance_bond_safe_fallback_disposition(
            bundle=bundle,
            disposition=changed,
            expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
        )


@pytest.mark.parametrize("field", ("evidence_span_ids", "source_version_ids", "citations"))
def test_any_legal_evidence_or_citation_fails_closed(bundle, field) -> None:
    disposition = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    changed = copy.deepcopy(disposition)
    changed[field] = ["not-permitted"]
    _reseal(changed)

    with pytest.raises(ValueError, match="does not exactly satisfy"):
        qualify_performance_bond_safe_fallback_disposition(
            bundle=bundle,
            disposition=changed,
            expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
        )


def test_contract_disposition_and_qualification_have_valid_self_seals(bundle) -> None:
    contract = performance_bond_safe_fallback_contract()
    disposition = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    qualification = qualify_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        disposition=disposition,
        expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )

    for value, field in (
        (contract, "contract_content_sha256"),
        (disposition, "record_content_sha256"),
        (qualification, "record_content_sha256"),
    ):
        material = dict(value)
        observed = material.pop(field)
        assert observed == hashlib.sha256(_canonical(material)).hexdigest()
