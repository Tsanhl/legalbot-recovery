"""Jurisdiction-scope review packets. Preparation only; no scope decision."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.contracts.schema_registry import seal_contract

from .ge_authority_roles import authority_dependency
from .ge_currentness_packets import (
    evidence_manifest_hash,
    material_claims,
    sha256_text,
)
from .ge_hold_reason_router import CASE_174, QUALIFIED_LEGAL_REVIEW_QUEUE, route_hold
from .ge_locator_gold_overlay import iso_date_from_prompt
from .ge_phase2_progress import NOT_STARTED

PACKET_SCHEMA = "legalbot.ge-jurisdiction-scope-packet.v1"
CASE_174_REVIEWER_QUESTION = (
    "Does the accepted ICC / Ohpen / Kajima / Churchill material support "
    "the precise jurisdictional and procedural proposition made in the "
    "candidate answer, within the relevant England-and-Wales context?"
)
CASE_174_ACCEPTED = (
    ("ICC Mediation Rules (contractually incorporated edition)", "article 5"),
    ("Ohpen Operations UK Ltd v Invesco Fund Managers Ltd", "paragraph 32"),
    ("Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd", "paragraph 29"),
    ("Churchill v Merthyr Tydfil County Borough Council", ""),
)
CASE_174_EXCLUDED = (
    "Cable & Wireless plc v IBM United Kingdom Ltd",
    "Arbitration Act 1996 section 9",
)
JURISDICTION_DECISIONS = (
    "IN_SCOPE",
    "OUT_OF_SCOPE",
    "CONDITIONAL_OR_LIMITED_SCOPE",
    "ANSWER_EDIT_REQUIRED",
    "HOLD_FOR_QUALIFIED_REVIEW",
)


def classify_jurisdiction_subreason(row: Mapping[str, Any], routed: Mapping[str, Any]) -> str:
    topic = str(row.get("topic_id") or routed.get("topic") or "")
    detail = str(routed.get("hold_reason_detail") or "").casefold()
    titles = " ".join(
        str(item.get("title") or "")
        for item in row.get("evidence") or []
        if isinstance(item, dict)
    ).casefold()
    if str(row.get("case_id") or "") == CASE_174 or "icc" in titles:
        return "CONTRACTUAL_INCORPORATION_AND_CROSS_BORDER_SCOPE"
    if topic == "private-international-law" or "choice of law" in detail or "rome" in titles:
        return "CHOICE_OF_LAW_OR_APPLICABLE_LAW"
    if topic == "eu-internal-market-law" or "european union" in detail:
        return "EU_RETAINED_OR_ASSIMILATED_SCOPE"
    if topic == "pensions-law":
        return "SCHEME_SITUS_OR_REGULATORY_SCOPE"
    if "extent" in detail or "territor" in detail:
        return "TERRITORIAL_EXTENT_OR_APPLICATION"
    if "procedur" in detail:
        return "PROCEDURAL_VERSUS_SUBSTANTIVE"
    return "CROSS_BORDER_OR_FORUM_SCOPE"


def _evidence_rows(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [item for item in (row.get("evidence") or []) if isinstance(item, dict)]


def _title_locator(item: Mapping[str, Any]) -> tuple[str, str]:
    return str(item.get("title") or ""), str(item.get("locator") or "")


def _title_attached(wanted: str, attached: set[str]) -> bool:
    wanted_cf = wanted.casefold()
    if any(wanted_cf in item or item in wanted_cf for item in attached):
        return True
    first_party = wanted_cf.split(" v ")[0].strip()
    return bool(first_party) and any(first_party in item for item in attached)


def build_jurisdiction_packet(row: Mapping[str, Any], *, routed: Mapping[str, Any] | None = None) -> dict[str, Any]:
    case_id = str(row.get("case_id") or "")
    routed_row = routed or route_hold(row)
    question = str(row.get("question") or row.get("prompt") or "")
    answer = str(row.get("user_facing_answer") or row.get("answer") or "")
    evidence = _evidence_rows(row)
    accepted = [{"title": title, "locator": locator} for title, locator in (_title_locator(item) for item in evidence)]
    attached_titles = {str(item.get("title") or "").casefold() for item in evidence}
    excluded = []
    required_missing = []
    if case_id == CASE_174:
        for title, locator in CASE_174_ACCEPTED:
            if not _title_attached(title, attached_titles):
                required_missing.append({"title": title, "locator": locator, "status": "accepted_not_attached"})
        excluded = [{"title": name, "reason": "rejected_or_non_mandatory_route"} for name in CASE_174_EXCLUDED]
        reviewer_question = CASE_174_REVIEWER_QUESTION
    else:
        reviewer_question = (
            "Is the candidate answer within the territorial, procedural and applicable-law "
            "scope of the attached authorities for this question, and should the answer be "
            "limited, edited, or held?"
        )
    cable = any("cable & wireless" in str(item.get("title") or "").casefold() for item in evidence)
    arb = any(
        "arbitration act 1996" in str(item.get("title") or "").casefold()
        and "section 9" in str(item.get("locator") or "").casefold()
        for item in evidence
    )
    if case_id == CASE_174 and (cable or arb):
        raise RuntimeError("case 174 packet included a forbidden authority")
    source_jurisdictions = sorted(
        {
            str(item.get("jurisdiction") or "")
            for item in evidence
            if item.get("jurisdiction")
        }
    )
    packet = {
        "schema": PACKET_SCHEMA,
        "case_id": case_id,
        "topic": str(row.get("topic_id") or routed_row.get("topic") or ""),
        "subtopic": str(row.get("scenario_family_id") or routed_row.get("subtopic") or ""),
        "question": question,
        "candidate_answer": answer,
        "material_claims": material_claims(row),
        "factual_status": "FACTUAL_HOLD",
        "claim_support_status": str(routed_row.get("claim_support_status") or ""),
        "hold_reason": "JURISDICTION_SCOPE_REVIEW",
        "jurisdiction_subreason": classify_jurisdiction_subreason(row, routed_row),
        "claimed_jurisdiction": str(row.get("primary_jurisdiction") or "England and Wales"),
        "source_jurisdiction": source_jurisdictions or ["not_recorded_on_all_locators"],
        "territorial_extent_or_application": [
            {
                "title": item.get("title"),
                "locator": item.get("locator"),
                "provision_extent_status": item.get("provision_extent_status") or "unverified",
            }
            for item in evidence
        ],
        "contractual_incorporation_issue": (
            "ICC Mediation Rules are treated as a contractually incorporated edition. "
            "Latest edition and applicable edition are not assumed to be the same."
            if case_id == CASE_174
            else ""
        ),
        "choice_of_law_issue": (
            "The contract chooses English law and ICC mediation before an English court."
            if case_id == CASE_174
            else str(routed_row.get("hold_reason_detail") or "")
        ),
        "procedural_versus_substantive": (
            "The remaining issue is jurisdictional/procedural competence to require or stay "
            "for mediation, not a merits determination."
            if case_id == CASE_174
            else "not_separately_classified"
        ),
        "competing_legal_routes": str(routed_row.get("hold_reason_detail") or ""),
        "accepted_authorities": (
            [{"title": title, "locator": locator} for title, locator in CASE_174_ACCEPTED]
            if case_id == CASE_174
            else accepted
        ),
        "attached_authorities": accepted,
        "accepted_not_attached": required_missing,
        "excluded_authorities": excluded,
        "authority_roles": [
            {
                "title": item.get("title"),
                "locator": item.get("locator"),
                **authority_dependency(str(item.get("title") or ""), case_id=case_id),
            }
            for item in evidence
        ],
        "exact_question_for_reviewer": reviewer_question,
        "facts_relevant_to_scope": question,
        "missing_facts": [],
        "review_options": list(JURISDICTION_DECISIONS),
        "owner_jurisdiction_decision": "",
        "qualified_legal_review_decision": "",
        "packet_status": "READY_FOR_OWNER_JURISDICTION_REVIEW",
        "review_status": NOT_STARTED,
        "owner_decision": "",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "admitted": False,
        "no_cable_and_wireless": True,
        "no_arbitration_act_s9_for_mediation": case_id == CASE_174,
        "do_not_convert_to_factual_pass": True,
        "do_not_reopen_generic_retrieval": True,
        "named_case_invariant": case_id == CASE_174,
        "next_route": QUALIFIED_LEGAL_REVIEW_QUEUE,
        "applicable_law_date": iso_date_from_prompt(question) or "",
        "question_hash": sha256_text(question),
        "answer_hash": sha256_text(answer),
        "evidence_manifest_hash": evidence_manifest_hash(row),
        "locator_count": len(evidence),
        "case_result_sha256": str(row.get("content_sha256") or ""),
    }
    sealed = seal_contract(packet, digest_field="packet_hash")
    if sealed["owner_jurisdiction_decision"] != "" or sealed["qualified_legal_review"] != NOT_STARTED:
        raise RuntimeError("jurisdiction packet filled a decision")
    attached = " ".join(
        f"{item.get('title')} {item.get('locator')}" for item in sealed.get("attached_authorities") or []
    ).casefold()
    if case_id == CASE_174 and ("cable & wireless" in attached or "arbitration act 1996" in attached):
        raise RuntimeError("case 174 packet attached a forbidden authority")
    return sealed


def build_jurisdiction_packets(
    rows: Sequence[Mapping[str, Any]],
    *,
    routed_holds: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    packets = [
        build_jurisdiction_packet(row, routed=routed_holds.get(str(row.get("case_id") or "")))
        for row in rows
    ]
    packets.sort(key=lambda item: str(item["case_id"]))
    return packets
