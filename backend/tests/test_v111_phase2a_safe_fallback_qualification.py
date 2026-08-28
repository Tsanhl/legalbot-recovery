from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.phase2a_safe_fallback_qualification import (
    ACTION,
    BASIS_CLASS,
    EVIDENCE_REQUIREMENT_STATUS,
    FAILURE_STATUS,
    HUMAN_ESCALATION_CTA,
    MISSING_INFORMATION_CATEGORIES,
    OUTCOME_CLASS,
    QUALIFICATION_STATUS,
    REASON_CODE,
    ROW_ID,
    SAFE_FALLBACK_MESSAGE,
    UI_CTA,
    build_safe_fallback_disposition,
    qualify_safe_fallback_disposition,
    safe_fallback_contract,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OWNER_ADOPTION_SHA256 = "a" * 64


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


def test_contract_is_phase2a_only_and_preserves_the_585th_registry_contract() -> None:
    contract = safe_fallback_contract()

    assert contract["row_id"] == ROW_ID
    assert contract["registry_policy"] == {
        "row_remains_in_all585": True,
        "case_count": 60,
        "issue_count": 585,
        "row_removal_permitted": False,
    }
    assert contract["outcome_class"] == OUTCOME_CLASS
    assert contract["qualification_status"] == QUALIFICATION_STATUS
    assert contract["basis_class"] == BASIS_CLASS
    assert contract["reason_code"] == REASON_CODE
    assert contract["required_action"] == ACTION
    assert contract["human_escalation_cta"] == HUMAN_ESCALATION_CTA
    assert contract["ui_cta"] == UI_CTA
    assert contract["reply_match_mode"] == "EXACT_UTF8_STRING"
    assert contract["qualification_result_when_contract_satisfied"] == QUALIFICATION_STATUS
    assert contract["qualification_result_when_contract_violated"] == FAILURE_STATUS
    assert contract["event_policy"] == {
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "event_reason_code": REASON_CODE,
        "ui_cta": UI_CTA,
    }
    assert contract["scope"]["owner_adoption_required_before_application"] is True
    assert contract["scope"]["production_qualification_performed"] is False
    assert all(
        contract["scope"][field] is False
        for field in (
            "phase2b_authorized",
            "development30_authorized",
            "validation30_authorized",
            "promotion_authorized",
            "active_or_previous_write_authorized",
            "live_activation_authorized",
        )
    )


def test_valid_exact_fallback_is_a_phase2a_row_pass_without_legal_gold(bundle) -> None:
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    result = qualify_safe_fallback_disposition(
        bundle=bundle,
        disposition=disposition,
        expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )

    assert result["qualification_status"] == QUALIFICATION_STATUS
    assert result["phase2a_row_technically_passed"] is True
    assert result["basis"]["basis_class"] == BASIS_CLASS
    assert result["basis"]["evidence_requirement_status"] == EVIDENCE_REQUIREMENT_STATUS
    assert result["contract_checks"]["legal_knowledge_failure"] is False
    assert result["contract_checks"]["knowledge_gap_event"] is False
    assert result["contract_checks"]["matter_information_gap_event"] is True
    assert result["contract_checks"]["material_legal_claim_released"] is False
    assert result["contract_checks"]["exact_evidence_span_required"] is False
    assert result["contract_checks"]["row_remains_in_all585"] is True
    assert result["event_projection"] == {
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "reason_code": REASON_CODE,
        "ui_cta": UI_CTA,
    }
    assert result["phase2b_authorized"] is False


def test_fallback_names_every_required_category_and_requests_human_review(bundle) -> None:
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )

    assert disposition["user_message"] == SAFE_FALLBACK_MESSAGE
    assert disposition["missing_information_categories"] == list(MISSING_INFORMATION_CATEGORIES)
    assert len(disposition["missing_information_categories"]) == 8
    assert disposition["substantive_project_rescue_advice_refused"] is True
    assert disposition["supplementation_requested"] is True
    assert disposition["qualified_human_legal_review_required"] is True
    assert disposition["knowledge_gap_event"] is False
    assert disposition["matter_information_gap_event"] is True
    assert disposition["human_escalation_cta"] == HUMAN_ESCALATION_CTA
    assert disposition["ui_cta"] == UI_CTA
    assert "Please provide:" in disposition["user_message"]
    assert "Once these are supplied" in disposition["user_message"]
    assert "qualified human lawyer" in disposition["user_message"]


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("substantive_project_rescue_advice_refused", False),
        ("supplementation_requested", False),
        ("qualified_human_legal_review_required", False),
        ("knowledge_gap_event", True),
        ("matter_information_gap_event", False),
        ("legal_knowledge_failure", True),
        ("material_legal_claim_released", True),
        ("answer_model_invoked_for_this_issue", True),
        ("row_remains_in_all585", False),
        ("phase2b_authorized", True),
        ("ui_cta", "GENERIC_CONTACT_SUPPORT"),
        ("reason_code", "GENERIC_KNOWLEDGE_GAP"),
    ),
)
def test_any_changed_safety_assertion_fails_closed(bundle, field, unsafe_value) -> None:
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    changed = copy.deepcopy(disposition)
    changed[field] = unsafe_value
    _reseal(changed)

    with pytest.raises(ValueError, match="does not exactly satisfy"):
        qualify_safe_fallback_disposition(
            bundle=bundle,
            disposition=changed,
            expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
        )


def test_substantive_advice_inserted_into_message_fails_closed(bundle) -> None:
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    changed = copy.deepcopy(disposition)
    changed["user_message"] += " Terminate the contractor immediately."
    _reseal(changed)

    with pytest.raises(ValueError, match="does not exactly satisfy"):
        qualify_safe_fallback_disposition(
            bundle=bundle,
            disposition=changed,
            expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
        )


def test_omitted_or_relabelled_missing_category_fails_closed(bundle) -> None:
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    for categories in (
        disposition["missing_information_categories"][:-1],
        [
            *disposition["missing_information_categories"][:-1],
            "GENERIC_OTHER",
        ],
    ):
        changed = copy.deepcopy(disposition)
        changed["missing_information_categories"] = categories
        _reseal(changed)
        with pytest.raises(ValueError, match="does not exactly satisfy"):
            qualify_safe_fallback_disposition(
                bundle=bundle,
                disposition=changed,
                expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
            )


@pytest.mark.parametrize("field", ("evidence_span_ids", "source_version_ids", "citations"))
def test_invented_evidence_or_citation_fails_closed(bundle, field) -> None:
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    changed = copy.deepcopy(disposition)
    changed[field] = ["invented-value"]
    _reseal(changed)

    with pytest.raises(ValueError, match="does not exactly satisfy"):
        qualify_safe_fallback_disposition(
            bundle=bundle,
            disposition=changed,
            expected_owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
        )


def test_wrong_or_missing_owner_adoption_digest_fails_closed(bundle) -> None:
    with pytest.raises(ValueError, match="owner-adoption digest"):
        build_safe_fallback_disposition(
            bundle=bundle,
            owner_adoption_packet_content_sha256="not-a-sha256",
        )

    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    with pytest.raises(ValueError, match="does not exactly satisfy"):
        qualify_safe_fallback_disposition(
            bundle=bundle,
            disposition=disposition,
            expected_owner_adoption_packet_content_sha256="b" * 64,
        )


def test_contract_and_records_have_stable_self_seals(bundle) -> None:
    contract = safe_fallback_contract()
    disposition = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=OWNER_ADOPTION_SHA256,
    )
    qualification = qualify_safe_fallback_disposition(
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
