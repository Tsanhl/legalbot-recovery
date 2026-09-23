"""Question-free coverage and creation controls; never generates or runs a bank."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[3]
REQUEST_ID = "LegalBot-GE-2026-09-05-expanded-bank-creation-r1"
REQUEST_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / REQUEST_ID
PREDECESSOR_ID = "LegalBot-GE-2026-09-04-new-unseen-bank-design-r1"
STATE = "EXPANDED_UNSEEN_CREATION_AUTHORIZED_AWAITING_INDEPENDENT_CUSTODIAN"

# These are public coverage families, never private scenario wording or facts.
DOMAIN_FAMILIES = {
    "administrative-law": ("public-decision-reasons", "complaint-or-review-route", "consultation-fairness", "public-body-powers", "review-time-sensitivity", "access-to-public-information"),
    "ai-and-data-protection": ("data-access-and-correction", "data-misuse", "automated-decisions", "surveillance", "marketing-consent", "children-online-privacy"),
    "business-and-company-law": ("starting-small-business", "director-duties", "shareholder-dispute", "personal-guarantees", "partnership-liability", "business-insolvency"),
    "commercial-law": ("supplier-nonpayment", "business-goods", "delivery-risk", "agency-authority", "business-service-dispute", "commercial-credit"),
    "competition-law": ("unfair-market-conduct", "price-fixing-concerns", "exclusivity", "dominant-supplier", "competition-complaint", "consumer-competition-loss"),
    "contemporary-biolaw-and-regulation": ("fertility-parenthood", "genetic-information", "research-consent", "human-tissue", "regulated-products", "biomedical-regulator-complaint"),
    "contract-law": ("formation-and-terms", "misrepresentation", "cancellation-and-deposit", "breach-and-loss", "unfair-terms", "settlement-enforceability"),
    "criminal-law": ("police-contact-and-advice", "suspect-rights", "fraud-and-theft", "harassment-and-threats", "victim-evidence", "criminal-civil-boundary"),
    "eu-internal-market-law": ("cross-border-goods", "cross-border-services", "post-exit-rights", "northern-ireland-scope", "cross-border-consumers", "regulatory-jurisdiction"),
    "international-commercial-mediation": ("agreement-to-mediate", "mediator-impartiality", "confidentiality", "settlement-enforcement", "cross-border-enforcement", "mediation-and-court-route"),
    "land-law": ("title-and-ownership", "coownership", "easements-and-access", "restrictive-covenants", "lease-ownership", "property-transfer"),
    "law-and-medicine": ("treatment-consent", "medical-records", "clinical-negligence", "treatment-refusal", "nhs-complaints", "urgent-treatment-boundaries"),
    "pensions-law": ("workplace-enrolment", "missing-contributions", "pension-benefits", "pension-transfer", "pension-scam", "pension-complaint"),
    "private-international-law": ("governing-law", "court-jurisdiction", "foreign-judgment", "cross-border-contract", "cross-border-injury", "service-abroad"),
    "tort-law": ("personal-injury", "property-damage", "negligent-advice", "defamation", "nuisance-liability", "causation-and-loss"),
    "trusts-law": ("trustee-duties", "beneficiary-information", "trustee-conflicts", "misused-trust-assets", "family-property-trust", "trust-distribution"),
    "wills-and-estates": ("will-formalities", "intestacy", "executor-administration", "estate-debts", "inheritance-dispute", "capacity-and-influence"),
    "housing": ("repairs-and-damp", "deposit-return", "eviction-notice", "rent-and-possession", "homelessness-help", "england-wales-tenure"),
    "employment": ("pay-and-holidays", "dismissal", "workplace-discrimination", "employment-status", "redundancy", "grievance-and-tribunal"),
    "family": ("separation-and-divorce", "child-arrangements", "financial-support", "domestic-abuse", "cohabitation-property", "parental-responsibility"),
    "immigration": ("visa-conditions", "application-evidence", "refusal-and-review", "family-immigration", "asylum-and-protection", "detention-and-urgent-advice"),
    "benefits-and-debt": ("benefit-decision", "benefit-appeal", "debt-collection", "enforcement-agents", "insolvency-options", "priority-debt-and-hardship"),
    "consumer": ("faulty-goods-and-remedies", "online-cancellation", "poor-services-and-repairs", "digital-products", "subscriptions-and-terms", "marketplace-seller-identity"),
    "banking-financial-services": ("unauthorised-payments", "authorised-payment-scam", "card-purchase-dispute", "bank-account-restriction", "credit-and-lending", "financial-ombudsman-route"),
    "insurance": ("claim-refusal", "policy-exclusions", "disclosure-and-misrepresentation", "claims-delay", "underinsurance", "insurance-complaint"),
    "education-send": ("school-admission", "school-exclusion", "special-education-support", "school-discrimination", "university-dispute", "england-wales-education-routes"),
    "social-care-mental-capacity": ("care-needs-assessment", "care-charges", "mental-capacity", "power-of-attorney", "adult-safeguarding", "deprivation-of-liberty"),
    "equality-discrimination": ("services-discrimination", "reasonable-adjustments", "harassment", "housing-discrimination", "public-sector-equality", "equalities-complaint-route"),
    "public-services-utilities": ("energy-billing", "water-service", "telecom-service", "council-service", "service-disconnection", "regulator-and-ombudsman"),
    "travel-transport": ("flight-disruption", "package-holiday", "rail-disruption", "travel-agent-failure", "accessibility-in-travel", "cross-border-travel-scope"),
    "motoring-parking": ("private-parking-demand", "public-parking-penalty", "vehicle-purchase", "vehicle-repair", "road-traffic-procedure", "vehicle-damage-dispute"),
    "neighbours-community": ("boundary-dispute", "noise-and-nuisance", "access-and-trespass", "trees-and-hedges", "neighbour-harassment", "planning-and-enforcement"),
    "tax-personal-finance": ("income-tax-decision", "tax-penalty-appeal", "council-tax", "self-employment-records", "estate-tax-triage", "tax-debt-and-time-limits"),
    "intellectual-property-online-content": ("copyright-use", "online-image-misuse", "trademark-small-business", "platform-takedown", "content-licensing", "online-reputation"),
    "civil-procedure-dispute-resolution": ("preaction-complaint", "small-claims-route", "defending-court-papers", "limitation-and-service", "judgment-enforcement", "costs-and-settlement"),
}
ORIGINAL_DOMAINS = tuple(DOMAIN_FAMILIES)[:23]
SYSTEM_FAMILIES = (
    "unreadable-upload", "ocr-date-ambiguity", "missing-pages", "conflicting-documents",
    "forged-or-unverified-document", "upload-prompt-injection", "source-prompt-injection",
    "cross-matter-isolation", "personal-data-redaction", "unknown-jurisdiction",
    "england-wales-divergence", "scotland-ni-or-foreign-routing", "urgent-safety",
    "unsafe-or-dishonest-request", "fabricated-case-citation", "missing-controlling-authority",
    "stale-source-or-uncommenced-law", "deadline-calculation", "arithmetic-and-currency",
    "followup-correction-and-history", "output-truncation", "no-unauthorised-sending-or-filing",
    "source-outage-and-honest-hold",
)


class ExpandedUnseenError(ValueError):
    """Public creation inputs are invalid or attempted to confer execution authority."""


def digest(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def seal(value: dict[str, Any]) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != "content_sha256"}
    return {**body, "content_sha256": digest(body)}


def require_seal(value: dict[str, Any]) -> None:
    if value.get("content_sha256") != seal(value)["content_sha256"]:
        raise ExpandedUnseenError("content seal mismatch")


def coverage_slots() -> list[dict[str, Any]]:
    rows = []
    for domain, families in DOMAIN_FAMILIES.items():
        for number, family in enumerate(families, 1):
            for variant in ("narrative", "document"):
                rows.append({
                    "slot_id": f"{domain}:{number:02d}:{variant}",
                    "domain": domain,
                    "family": family,
                    "variant": variant,
                    "synthetic_upload_required": variant == "document",
                    "multi_turn_required": number in (3, 6),
                    "cross_issue_required": number == 6,
                    "private_case_created": False,
                })
    return rows


def validate_coverage(rows: list[dict[str, Any]]) -> None:
    expected = {row["slot_id"]: row for row in coverage_slots()}
    if len(rows) != 420 or len({row.get("slot_id") for row in rows}) != 420:
        raise ExpandedUnseenError("missing or duplicate coverage slot")
    if {row["slot_id"]: row for row in rows} != expected:
        raise ExpandedUnseenError("coverage changed or private content entered public slots")
    if Counter(row["domain"] for row in rows) != {domain: 12 for domain in DOMAIN_FAMILIES}:
        raise ExpandedUnseenError("domain denominator mismatch")


def creation_contract() -> dict[str, Any]:
    return seal({
        "schema": "legalbot.ge-expanded-unseen-creation-contract.v1",
        "request_id": REQUEST_ID,
        "predecessor_design_id": PREDECESSOR_ID,
        "creation_authorized": True,
        "scope_expansion_authorized": True,
        "bank_created": False,
        "execution_authorized": False,
        "scope": "ENGLAND_AND_WALES_WITH_EXPLICIT_JURISDICTION_ROUTING",
        "legal_case_count": 420,
        "domain_count": 35,
        "cases_per_domain": 12,
        "system_case_count": 23,
        "original_domains_preserved": list(ORIGINAL_DOMAINS),
        "minimum_upload_cases": 210,
        "minimum_multi_turn_cases": 140,
        "minimum_cross_issue_cases": 70,
        "original_consumer_example": "EXPOSED_REQUIREMENT_NOT_AN_UNSEEN_CASE",
        "source_selection": "SCENARIO_FIRST_NO_SELECTION_FOR_EASY_AVAILABLE_EXCERPTS",
        "candidate_input": "USER_NARRATIVE_AND_USER_UPLOADS_ONLY",
        "reference_evidence_visible_to_candidate": False,
        "candidate_must_retrieve_authority": True,
        "case_law_policy": "RELEVANT_VERIFIED_HOLDING_OR_EXPLAINED_NOT_REQUIRED",
        "case_law_quota": None,
        "law_verified_before_seal": False,
        "source_admission": False,
        "material_claim_review": "ALL_DECLARED_AND_UNDECLARED_PLUS_MATERIAL_OMISSIONS",
        "quality_threshold": 70,
        "quality_maxima": {"legal_and_factual_accuracy": 25, "issue_coverage_and_reasoning": 15,
            "authority_and_currentness": 15, "practical_steps_and_urgency": 15,
            "uncertainty_limits_and_clarification": 10, "organisation_and_plain_language": 10,
            "traceability_and_citations": 10},
        "critical_floors": {"legal_and_factual_accuracy": 17.5,
            "authority_and_currentness": 10.5, "practical_steps_and_urgency": 9},
        "pass_denominators": {"legal_factual": 420, "legal_quality": 420, "system": 23},
        "appropriate_hold_behavior": "REPORT_SEPARATELY_NO_FALSE_COMPLETE_LEGAL_ANSWER_PASS",
        "new_custodian_required": True,
        "provider_independent_from_candidate": True,
        "custodian_authenticated": False,
        "same_provider_substitution_allowed": False,
        "private_root_created": False,
        "encryption_at_rest_required": True,
        "key_must_be_held_by_custodian": True,
        "developer_may_view_private_content": False,
        "retired_bank_access": "PROHIBITED",
        "training": "NOT_AUTHORIZED",
        "adapter": "INACTIVE_EXCLUDED",
        "professional_legal_sign_off": False,
        "answer_legal_gold": "NOT_STARTED",
        "promotion": "NOT_STARTED",
        "live": "NOT_STARTED",
        "future_execution_requires": "OWNER_AUTHORIZATION_FOR_EXACT_BANK_AND_RUNTIME_HASHES",
        "coverage_claim": "REPRESENTATIVE_BREADTH_NOT_ALL_POSSIBLE_LAW_OR_QUESTIONS",
    })


def verify_request(root: Path = REQUEST_ROOT) -> dict[str, Any]:
    inventory = json.loads((root / "ARTIFACT-SHA256-REGISTER.json").read_text())
    actual = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in root.rglob("*") if p.is_file() and p.name != "ARTIFACT-SHA256-REGISTER.json"}
    if actual != inventory.get("artifacts"):
        raise ExpandedUnseenError("artifact register mismatch")
    contract = json.loads((root / "CREATION-CONTRACT.json").read_text())
    if contract != creation_contract():
        raise ExpandedUnseenError("creation contract differs from authorized scope")
    rows = [json.loads(line) for line in (root / "COVERAGE-SLOTS.jsonl").read_text().splitlines()]
    validate_coverage(rows)
    state = json.loads((root / "STATE.json").read_text())
    require_seal(state)
    if state["overall_state"] != STATE or state["bank_created"] is not False:
        raise ExpandedUnseenError("unestablished custody or bank creation claim")
    if state["execution_authorized"] is not False:
        raise ExpandedUnseenError("execution authority drift")
    return {"verified": True, "legal_slots": len(rows), "domains": 35, "system_slots": 23,
        "creation_authorized": True, "bank_created": False, "execution_authorized": False,
        "overall_state": STATE}


def validate_custodian_connection(receipt: dict[str, Any]) -> None:
    """Validate required evidence references; real transport/key verification is separate."""
    if receipt.get("provider") in (None, "", "openai", "codex"):
        raise ExpandedUnseenError("independent custodian provider missing")
    for name in ("identity", "authentication_receipt_sha256", "private_root_identity_sha256",
                 "encryption_recipient_fingerprint", "access_isolation_receipt_sha256"):
        if not isinstance(receipt.get(name), str) or not receipt[name].strip():
            raise ExpandedUnseenError(f"custody evidence missing: {name}")
    if receipt.get("retired_bank_access") != "DENIED":
        raise ExpandedUnseenError("retired bank must remain excluded")
    if receipt.get("developer_has_decryption_key") is not False:
        raise ExpandedUnseenError("developer cannot hold the custodian decryption key")
    if receipt.get("execution_authorized") is not False:
        raise ExpandedUnseenError("creation connection cannot authorize evaluation")
