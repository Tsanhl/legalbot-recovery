"""Deterministic Phase-2A qualification for exact fact-dependent fallbacks.

This module is deliberately additive.  It does not change the immutable Live60
registry, make an owner decision, invoke a model, or qualify a production run.
It defines exact contracts that a later digest-bound owner packet may adopt for
``live60-q58:issue-14`` and ``live60-q58:issue-09``.  The second contract is a
no-legal-claim fallback only: all performance-bond rules, citations and spans
remain prohibited while the bond and demand documents are absent.

The issue is not treated as a legal-knowledge failure.  A row can pass this
contract only when it releases no substantive project-rescue advice, names the
complete required-input categories, requests supplementation, and routes the
matter to qualified human legal review.  Because no material legal proposition
is released, an EvidenceSpan is neither required nor permitted for this row.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from .live_suite import LiveEvaluationBundle

CONTRACT_SCHEMA = "legalbot.v111.phase2a.fact-dependent-safe-fallback-contract.v1"
DISPOSITION_SCHEMA = "legalbot.v111.phase2a.fact-dependent-safe-fallback-disposition.v1"
QUALIFICATION_SCHEMA = "legalbot.v111.phase2a.safe-fallback-qualification-row.v1"

ROW_ID = "live60-q58:issue-14"
CASE_ID = "live60-q58"
ISSUE_ID = "issue-14"
ISSUE_LABEL = "project-rescue strategy"
REGISTRY_ORDINAL = 533
QUESTION_SHA256 = "1bafa6ee578cb27eec30db9f39db6c9d61fe85b7adb6483d17142e2c6d298687"
CASE_RECORD_SHA256 = "eb318379874e1d5da73a5895510f5610ea5ae3825a86f5b803f15f5b17f3dfb1"

OUTCOME_CLASS = "FACT_DEPENDENT_HUMAN_ESCALATION_FALLBACK_REQUIRED"
QUALIFICATION_STATUS = "PASS_SAFE_FALLBACK"
FAILURE_STATUS = "FAIL_SAFE_FALLBACK_CONTRACT"
BASIS_CLASS = "OWNER_ADOPTED_FACT_DEPENDENT_HUMAN_ESCALATION_FALLBACK_CONTRACT"
REASON_CODE = "INSUFFICIENT_MATTER_FACTS_FOR_PROJECT_RESCUE_ADVICE"
ACTION = "REQUEST_SUPPLEMENTATION_AND_HUMAN_LEGAL_REVIEW"
HUMAN_ESCALATION_CTA = "OFFER_QUALIFIED_HUMAN_LEGAL_REVIEW"
UI_CTA = "SUPPLY_DOCUMENTS_AND_ESCALATE_HUMAN"
EVIDENCE_REQUIREMENT_STATUS = "NOT_APPLICABLE_NO_MATERIAL_LEGAL_CLAIM_RELEASED"

PERFORMANCE_BOND_ROW_ID = "live60-q58:issue-09"
PERFORMANCE_BOND_CASE_ID = "live60-q58"
PERFORMANCE_BOND_ISSUE_ID = "issue-09"
PERFORMANCE_BOND_ISSUE_LABEL = "performance bonds"
PERFORMANCE_BOND_REGISTRY_ORDINAL = 528
PERFORMANCE_BOND_OUTCOME_CLASS = "FACT_DEPENDENT_NO_LEGAL_CLAIM_HUMAN_ESCALATION_FALLBACK_REQUIRED"
PERFORMANCE_BOND_BASIS_CLASS = "OWNER_ADOPTED_PERFORMANCE_BOND_NO_LEGAL_CLAIM_FALLBACK_CONTRACT"
PERFORMANCE_BOND_REASON_CODE = "INSUFFICIENT_MATTER_FACTS_FOR_PERFORMANCE_BOND_ADVICE"
PERFORMANCE_BOND_ACTION = "REQUEST_BOND_AND_DEMAND_DOCUMENTS_AND_HUMAN_LEGAL_REVIEW"
PERFORMANCE_BOND_UI_CTA = "SUPPLY_BOND_AND_DEMAND_DOCUMENTS_AND_ESCALATE_QUALIFIED_HUMAN"
PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256 = (
    "599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

MISSING_INFORMATION_CATEGORIES: tuple[str, ...] = (
    "RELEVANT_CONTRACTS_AND_AMENDMENTS",
    "BREACH_DEFAULT_RESERVATION_AND_REMEDY_NOTICES",
    "CURE_TERMINATION_AND_OTHER_APPLICABLE_DEADLINES",
    "FINANCING_CASH_FLOW_LENDING_AND_GUARANTEE_INFORMATION",
    "SECURITY_DOCUMENTS_PRIORITY_AND_ENFORCEMENT_STATUS",
    "INSURANCE_POLICIES_COVERAGE_POSITIONS_AND_NOTIFICATIONS",
    "SITE_OPERATIONAL_AND_SAFETY_STATUS",
    "REQUIRED_CONTRACTUAL_LENDER_REGULATORY_AND_THIRD_PARTY_CONSENTS",
)

PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES: tuple[str, ...] = (
    "BOND_INSTRUMENT_AND_AMENDMENTS",
    "DEMAND_SERVICE_RECORDS_AND_DEMAND_CONDITION_COMPLIANCE_EVIDENCE",
    "BOND_EXPIRY_INFORMATION",
    "UNDERLYING_CONTRACT_AND_TERMINATION_NOTICES",
    "GOVERNING_LAW_MATERIAL",
    "FRAUD_EVIDENCE",
    "URGENCY_AND_INJUNCTION_EVIDENCE",
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _seal(value: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    payload = dict(value)
    payload.pop(field, None)
    payload[field] = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return payload


SAFE_FALLBACK_MESSAGE = (
    "The available information is insufficient to provide a safe project-rescue "
    "strategy. Please provide: (1) the relevant contracts and amendments; (2) "
    "breach, default, reservation-of-rights and remedy notices; (3) cure, "
    "termination and other applicable deadlines; (4) financing, cash-flow, "
    "lending and guarantee information; (5) security documents, priority and "
    "enforcement status; (6) insurance policies, coverage positions and "
    "notifications; (7) site, operational and safety status; and (8) required "
    "contractual, lender, regulatory and third-party consents. Once these are "
    "supplied, the issues can be reviewed further. Would you like this referred "
    "to a qualified human lawyer for legal review?"
)

PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE = (
    "現有資料不足以安全判斷該履約保證是見索即付保證還是從屬保證、索款是否合規，"
    "或是否有基礎申請禁制令。請提供保證書及修訂、索款文件與送達紀錄、到期日、"
    "基礎合約及終止通知、準據法、欺詐證據及緊急救濟材料，並交由合資格律師審核。"
)


def safe_fallback_contract() -> dict[str, Any]:
    """Return the immutable contract content for exact owner adoption."""

    payload = {
        "schema": CONTRACT_SCHEMA,
        "row_id": ROW_ID,
        "case_id": CASE_ID,
        "issue_id": ISSUE_ID,
        "issue_label": ISSUE_LABEL,
        "registry_ordinal": REGISTRY_ORDINAL,
        "question_sha256": QUESTION_SHA256,
        "case_record_sha256": CASE_RECORD_SHA256,
        "outcome_class": OUTCOME_CLASS,
        "qualification_status": QUALIFICATION_STATUS,
        "basis_class": BASIS_CLASS,
        "reason_code": REASON_CODE,
        "required_action": ACTION,
        "human_escalation_cta": HUMAN_ESCALATION_CTA,
        "ui_cta": UI_CTA,
        "required_missing_information_categories": list(MISSING_INFORMATION_CATEGORIES),
        "required_user_message": SAFE_FALLBACK_MESSAGE,
        "reply_match_mode": "EXACT_UTF8_STRING",
        "qualification_result_when_contract_satisfied": QUALIFICATION_STATUS,
        "qualification_result_when_contract_violated": FAILURE_STATUS,
        "pass_requirements": {
            "substantive_project_rescue_advice_refused": True,
            "all_missing_information_categories_identified": True,
            "supplementation_requested": True,
            "qualified_human_legal_review_required": True,
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "material_legal_claim_released": False,
            "answer_model_invoked_for_this_issue": False,
        },
        "event_policy": {
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "event_reason_code": REASON_CODE,
            "ui_cta": UI_CTA,
        },
        "evidence_policy": {
            "status": EVIDENCE_REQUIREMENT_STATUS,
            "exact_evidence_span_required": False,
            "evidence_spans_permitted": False,
            "citations_permitted": False,
        },
        "registry_policy": {
            "row_remains_in_all585": True,
            "case_count": 60,
            "issue_count": 585,
            "row_removal_permitted": False,
        },
        "scope": {
            "phase2a_only": True,
            "owner_adoption_required_before_application": True,
            "production_qualification_performed": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "promotion_authorized": False,
            "active_or_previous_write_authorized": False,
            "live_activation_authorized": False,
        },
    }
    return _seal(payload, field="contract_content_sha256")


def _assert_registry_binding(bundle: LiveEvaluationBundle) -> None:
    if len(bundle.registry.cases) != 60:
        raise ValueError("safe-fallback contract requires the exact 60-case registry")
    issue_count = sum(len(case.must_cover_issues) for case in bundle.registry.cases)
    if issue_count != 585:
        raise ValueError("safe-fallback contract requires the exact 585-row registry")
    case = bundle.registry.case(CASE_ID)
    if (
        case.question_sha256 != QUESTION_SHA256
        or case.record_sha256 != CASE_RECORD_SHA256
        or len(case.must_cover_issues) < 14
        or case.must_cover_issues[13] != ISSUE_LABEL
    ):
        raise ValueError("safe-fallback row no longer matches the immutable registry")
    ordinal = 0
    observed_ordinal: int | None = None
    for registry_case in bundle.registry.cases:
        for issue_number, _label in enumerate(registry_case.must_cover_issues, start=1):
            ordinal += 1
            if registry_case.case_id == CASE_ID and issue_number == 14:
                observed_ordinal = ordinal
    if observed_ordinal != REGISTRY_ORDINAL:
        raise ValueError("safe-fallback row ordinal changed")


def _assert_performance_bond_registry_binding(bundle: LiveEvaluationBundle) -> None:
    if len(bundle.registry.cases) != 60:
        raise ValueError("performance-bond fallback requires the exact 60-case registry")
    issue_count = sum(len(case.must_cover_issues) for case in bundle.registry.cases)
    if issue_count != 585:
        raise ValueError("performance-bond fallback requires the exact 585-row registry")
    case = bundle.registry.case(PERFORMANCE_BOND_CASE_ID)
    if (
        case.question_sha256 != QUESTION_SHA256
        or case.record_sha256 != CASE_RECORD_SHA256
        or len(case.must_cover_issues) < 9
        or case.must_cover_issues[8] != PERFORMANCE_BOND_ISSUE_LABEL
    ):
        raise ValueError("performance-bond fallback row no longer matches the registry")
    ordinal = 0
    observed_ordinal: int | None = None
    for registry_case in bundle.registry.cases:
        for issue_number, _label in enumerate(registry_case.must_cover_issues, start=1):
            ordinal += 1
            if registry_case.case_id == PERFORMANCE_BOND_CASE_ID and issue_number == 9:
                observed_ordinal = ordinal
    if observed_ordinal != PERFORMANCE_BOND_REGISTRY_ORDINAL:
        raise ValueError("performance-bond fallback row ordinal changed")


def performance_bond_safe_fallback_contract() -> dict[str, Any]:
    """Return the exact no-legal-claim performance-bond fallback contract."""

    payload = {
        "schema": CONTRACT_SCHEMA,
        "row_id": PERFORMANCE_BOND_ROW_ID,
        "case_id": PERFORMANCE_BOND_CASE_ID,
        "issue_id": PERFORMANCE_BOND_ISSUE_ID,
        "issue_label": PERFORMANCE_BOND_ISSUE_LABEL,
        "registry_ordinal": PERFORMANCE_BOND_REGISTRY_ORDINAL,
        "question_sha256": QUESTION_SHA256,
        "case_record_sha256": CASE_RECORD_SHA256,
        "held9_advisory_content_sha256": (PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256),
        "outcome_class": PERFORMANCE_BOND_OUTCOME_CLASS,
        "qualification_status": QUALIFICATION_STATUS,
        "basis_class": PERFORMANCE_BOND_BASIS_CLASS,
        "reason_code": PERFORMANCE_BOND_REASON_CODE,
        "required_action": PERFORMANCE_BOND_ACTION,
        "human_escalation_cta": HUMAN_ESCALATION_CTA,
        "ui_cta": PERFORMANCE_BOND_UI_CTA,
        "required_missing_information_categories": list(
            PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES
        ),
        "required_user_message": PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
        "reply_match_mode": "EXACT_UTF8_STRING",
        "qualification_result_when_contract_satisfied": QUALIFICATION_STATUS,
        "qualification_result_when_contract_violated": FAILURE_STATUS,
        "pass_requirements": {
            "substantive_performance_bond_advice_refused": True,
            "all_missing_information_categories_identified": True,
            "supplementation_requested": True,
            "qualified_human_legal_review_required": True,
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "material_legal_claim_released": False,
            "answer_model_invoked_for_this_issue": False,
        },
        "excluded_unsupported_components": [
            "Shanghai Shipyard performance-bond classification and injunction analysis.",
            "Any Wuhan legal rule until an exact cross-row owner decision and retained-hold review.",
        ],
        "retained_underlying_holds": {
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "legal_rule_release_prohibited": True,
            "citation_release_prohibited": True,
            "evidence_span_release_prohibited": True,
            "underlying_substantive_answer_not_qualified": True,
        },
        "event_policy": {
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "event_reason_code": PERFORMANCE_BOND_REASON_CODE,
            "ui_cta": PERFORMANCE_BOND_UI_CTA,
        },
        "evidence_policy": {
            "status": EVIDENCE_REQUIREMENT_STATUS,
            "exact_evidence_span_required": False,
            "evidence_spans_permitted": False,
            "citations_permitted": False,
        },
        "registry_policy": {
            "row_remains_in_all585": True,
            "case_count": 60,
            "issue_count": 585,
            "row_removal_permitted": False,
        },
        "scope": {
            "phase2a_only": True,
            "owner_adoption_required_before_application": True,
            "production_qualification_performed": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "promotion_authorized": False,
            "active_or_previous_write_authorized": False,
            "live_activation_authorized": False,
        },
    }
    return _seal(payload, field="contract_content_sha256")


def build_safe_fallback_disposition(
    *,
    bundle: LiveEvaluationBundle,
    owner_adoption_packet_content_sha256: str,
) -> dict[str, Any]:
    """Build the only disposition eligible to satisfy the contract.

    The owner-adoption digest is an input deliberately: this implementation
    cannot apply itself before a later exact owner packet binds the contract.
    """

    _assert_registry_binding(bundle)
    if not _SHA256.fullmatch(owner_adoption_packet_content_sha256):
        raise ValueError("safe-fallback disposition lacks an exact owner-adoption digest")
    contract = safe_fallback_contract()
    payload = {
        "schema": DISPOSITION_SCHEMA,
        "row_id": ROW_ID,
        "case_id": CASE_ID,
        "issue_id": ISSUE_ID,
        "issue_label": ISSUE_LABEL,
        "registry_ordinal": REGISTRY_ORDINAL,
        "question_sha256": QUESTION_SHA256,
        "case_record_sha256": CASE_RECORD_SHA256,
        "contract_content_sha256": contract["contract_content_sha256"],
        "owner_adoption_packet_content_sha256": owner_adoption_packet_content_sha256,
        "outcome_class": OUTCOME_CLASS,
        "reason_code": REASON_CODE,
        "action": ACTION,
        "human_escalation_cta": HUMAN_ESCALATION_CTA,
        "ui_cta": UI_CTA,
        "user_message": SAFE_FALLBACK_MESSAGE,
        "reply_match_mode": "EXACT_UTF8_STRING",
        "missing_information_categories": list(MISSING_INFORMATION_CATEGORIES),
        "substantive_project_rescue_advice_refused": True,
        "supplementation_requested": True,
        "qualified_human_legal_review_required": True,
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "legal_knowledge_failure": False,
        "material_legal_claim_released": False,
        "answer_model_invoked_for_this_issue": False,
        "evidence_requirement_status": EVIDENCE_REQUIREMENT_STATUS,
        "evidence_span_ids": [],
        "source_version_ids": [],
        "citations": [],
        "row_remains_in_all585": True,
        "phase2a_only": True,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "promotion_authorized": False,
        "active_or_previous_written": False,
    }
    return _seal(payload, field="record_content_sha256")


def qualify_safe_fallback_disposition(
    *,
    bundle: LiveEvaluationBundle,
    disposition: Mapping[str, Any],
    expected_owner_adoption_packet_content_sha256: str,
) -> dict[str, Any]:
    """Fail closed unless ``disposition`` is the exact adopted safe response."""

    if not _SHA256.fullmatch(expected_owner_adoption_packet_content_sha256):
        raise ValueError("safe-fallback qualification lacks an owner-adoption digest")
    expected = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=(expected_owner_adoption_packet_content_sha256),
    )
    if _canonical_json(disposition) != _canonical_json(expected):
        raise ValueError("safe-fallback disposition does not exactly satisfy the adopted contract")
    contract = safe_fallback_contract()
    payload = {
        "schema": QUALIFICATION_SCHEMA,
        "row_id": ROW_ID,
        "case_id": CASE_ID,
        "issue_id": ISSUE_ID,
        "issue_label": ISSUE_LABEL,
        "registry_ordinal": REGISTRY_ORDINAL,
        "qualification_status": QUALIFICATION_STATUS,
        "phase2a_row_technically_passed": True,
        "basis": {
            "basis_class": BASIS_CLASS,
            "outcome_class": OUTCOME_CLASS,
            "reason_code": REASON_CODE,
            "contract_content_sha256": contract["contract_content_sha256"],
            "owner_adoption_packet_content_sha256": (expected_owner_adoption_packet_content_sha256),
            "safe_fallback_record_content_sha256": expected["record_content_sha256"],
            "evidence_requirement_status": EVIDENCE_REQUIREMENT_STATUS,
            "event_reason_code": REASON_CODE,
            "human_escalation_cta": HUMAN_ESCALATION_CTA,
            "ui_cta": UI_CTA,
        },
        "contract_checks": {
            "substantive_project_rescue_advice_refused": True,
            "all_missing_information_categories_identified": True,
            "supplementation_requested": True,
            "qualified_human_legal_review_required": True,
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "legal_knowledge_failure": False,
            "material_legal_claim_released": False,
            "answer_model_invoked_for_this_issue": False,
            "exact_evidence_span_required": False,
            "row_remains_in_all585": True,
        },
        "event_projection": {
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "reason_code": REASON_CODE,
            "ui_cta": UI_CTA,
        },
        "owner_adopted_safe_fallback_contract": True,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "promotion_authorized": False,
        "active_or_previous_written": False,
    }
    return _seal(payload, field="record_content_sha256")


def build_performance_bond_safe_fallback_disposition(
    *,
    bundle: LiveEvaluationBundle,
    owner_adoption_packet_content_sha256: str,
) -> dict[str, Any]:
    """Build the only performance-bond fallback eligible for row qualification."""

    _assert_performance_bond_registry_binding(bundle)
    if not _SHA256.fullmatch(owner_adoption_packet_content_sha256):
        raise ValueError(
            "performance-bond fallback disposition lacks an exact owner-adoption digest"
        )
    contract = performance_bond_safe_fallback_contract()
    payload = {
        "schema": DISPOSITION_SCHEMA,
        "row_id": PERFORMANCE_BOND_ROW_ID,
        "case_id": PERFORMANCE_BOND_CASE_ID,
        "issue_id": PERFORMANCE_BOND_ISSUE_ID,
        "issue_label": PERFORMANCE_BOND_ISSUE_LABEL,
        "registry_ordinal": PERFORMANCE_BOND_REGISTRY_ORDINAL,
        "question_sha256": QUESTION_SHA256,
        "case_record_sha256": CASE_RECORD_SHA256,
        "held9_advisory_content_sha256": (PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256),
        "contract_content_sha256": contract["contract_content_sha256"],
        "owner_adoption_packet_content_sha256": owner_adoption_packet_content_sha256,
        "outcome_class": PERFORMANCE_BOND_OUTCOME_CLASS,
        "reason_code": PERFORMANCE_BOND_REASON_CODE,
        "action": PERFORMANCE_BOND_ACTION,
        "human_escalation_cta": HUMAN_ESCALATION_CTA,
        "ui_cta": PERFORMANCE_BOND_UI_CTA,
        "user_message": PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
        "reply_match_mode": "EXACT_UTF8_STRING",
        "missing_information_categories": list(PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES),
        "substantive_performance_bond_advice_refused": True,
        "supplementation_requested": True,
        "qualified_human_legal_review_required": True,
        "knowledge_gap_event": False,
        "matter_information_gap_event": True,
        "legal_knowledge_failure": False,
        "material_legal_claim_released": False,
        "answer_model_invoked_for_this_issue": False,
        "currentness_hold_retained": True,
        "later_treatment_hold_retained": True,
        "legal_rule_release_prohibited": True,
        "citation_release_prohibited": True,
        "evidence_span_release_prohibited": True,
        "underlying_substantive_answer_not_qualified": True,
        "evidence_requirement_status": EVIDENCE_REQUIREMENT_STATUS,
        "evidence_span_ids": [],
        "source_version_ids": [],
        "citations": [],
        "row_remains_in_all585": True,
        "phase2a_only": True,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "promotion_authorized": False,
        "active_or_previous_written": False,
    }
    return _seal(payload, field="record_content_sha256")


def qualify_performance_bond_safe_fallback_disposition(
    *,
    bundle: LiveEvaluationBundle,
    disposition: Mapping[str, Any],
    expected_owner_adoption_packet_content_sha256: str,
) -> dict[str, Any]:
    """Fail closed unless the exact no-legal-claim fallback was adopted."""

    if not _SHA256.fullmatch(expected_owner_adoption_packet_content_sha256):
        raise ValueError("performance-bond fallback lacks an owner-adoption digest")
    expected = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=(expected_owner_adoption_packet_content_sha256),
    )
    if _canonical_json(disposition) != _canonical_json(expected):
        raise ValueError(
            "performance-bond fallback disposition does not exactly satisfy the adopted contract"
        )
    contract = performance_bond_safe_fallback_contract()
    payload = {
        "schema": QUALIFICATION_SCHEMA,
        "row_id": PERFORMANCE_BOND_ROW_ID,
        "case_id": PERFORMANCE_BOND_CASE_ID,
        "issue_id": PERFORMANCE_BOND_ISSUE_ID,
        "issue_label": PERFORMANCE_BOND_ISSUE_LABEL,
        "registry_ordinal": PERFORMANCE_BOND_REGISTRY_ORDINAL,
        "qualification_status": QUALIFICATION_STATUS,
        "phase2a_row_technically_passed": True,
        "basis": {
            "basis_class": PERFORMANCE_BOND_BASIS_CLASS,
            "outcome_class": PERFORMANCE_BOND_OUTCOME_CLASS,
            "reason_code": PERFORMANCE_BOND_REASON_CODE,
            "contract_content_sha256": contract["contract_content_sha256"],
            "held9_advisory_content_sha256": (PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256),
            "owner_adoption_packet_content_sha256": (expected_owner_adoption_packet_content_sha256),
            "safe_fallback_record_content_sha256": expected["record_content_sha256"],
            "evidence_requirement_status": EVIDENCE_REQUIREMENT_STATUS,
            "event_reason_code": PERFORMANCE_BOND_REASON_CODE,
            "human_escalation_cta": HUMAN_ESCALATION_CTA,
            "ui_cta": PERFORMANCE_BOND_UI_CTA,
        },
        "contract_checks": {
            "substantive_performance_bond_advice_refused": True,
            "all_missing_information_categories_identified": True,
            "supplementation_requested": True,
            "qualified_human_legal_review_required": True,
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "legal_knowledge_failure": False,
            "material_legal_claim_released": False,
            "answer_model_invoked_for_this_issue": False,
            "exact_evidence_span_required": False,
            "row_remains_in_all585": True,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "legal_rule_release_prohibited": True,
            "citation_release_prohibited": True,
            "evidence_span_release_prohibited": True,
            "underlying_substantive_answer_not_qualified": True,
        },
        "event_projection": {
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "reason_code": PERFORMANCE_BOND_REASON_CODE,
            "ui_cta": PERFORMANCE_BOND_UI_CTA,
        },
        "owner_adopted_safe_fallback_contract": True,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "promotion_authorized": False,
        "active_or_previous_written": False,
    }
    return _seal(payload, field="record_content_sha256")
