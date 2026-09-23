"""Case 312 fact-dependent formality packet. No definitive validity."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.contracts.schema_registry import seal_contract

from .ge_currentness_packets import evidence_manifest_hash, material_claims, sha256_text
from .ge_hold_reason_router import CASE_312, FACT_INPUT_OR_REVIEW_QUEUE, route_hold
from .ge_locator_gold_overlay import iso_date_from_prompt
from .ge_phase2_progress import NOT_STARTED

PACKET_SCHEMA = "legalbot.ge-fact-dependent-packet.v1"
FACT_DEPENDENT_DECISIONS = (
    "CONDITIONAL_ANSWER_ACCEPTABLE",
    "MORE_FACTS_REQUIRED",
    "ANSWER_EDIT_REQUIRED",
    "HOLD",
)
APPLICABLE_DATE = "2024-01-15"
FORMALITY_AUTHORITIES = (
    ("Wills Act 1837 (as at 2024-01-15)", "section 9"),
    (
        "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
        "article 2",
    ),
    ("The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022", "article 2"),
)
CONDITIONAL_ANSWER = (
    "On 15 January 2024 the Wills Act 1837 section 9 formalities, as modified by the "
    "2020 electronic-communications (coronavirus) order and still in the window before "
    "the 2022 order ended that temporary regime, could be satisfied by a live video link "
    "if the will-maker and both witnesses followed the required signing and witnessing "
    "sequence. If that sequence was followed, the will could be formally valid. If it was "
    "not followed, section 9 was not satisfied. The known facts do not identify the order "
    "of signing and witnessing, so no definitive validity conclusion is given."
)
MISSING_FACTS = (
    "Whether the will-maker signed (or acknowledged) in the simultaneous live presence, by video, of both witnesses.",
    "Whether each witness attested and signed in the required presence of the will-maker.",
    "The order of those steps and whether they were a single contemporaneous session.",
    "Whether any person signed at the will-maker's direction, and if so whether that was acknowledged as required.",
)


def build_fact_dependent_packet(
    row: Mapping[str, Any],
    *,
    routed: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    case_id = str(row.get("case_id") or "")
    if case_id != CASE_312:
        raise ValueError("fact-dependent packet builder is limited to case 312")
    routed_row = routed or route_hold(row)
    question = str(row.get("question") or row.get("prompt") or "")
    answer = str(row.get("user_facing_answer") or row.get("answer") or "")
    evidence = [item for item in (row.get("evidence") or []) if isinstance(item, dict)]
    date = iso_date_from_prompt(question) or APPLICABLE_DATE
    if date != APPLICABLE_DATE:
        raise RuntimeError("case 312 applicable date escaped 15 January 2024")
    branches = [
        {
            "branch_id": "sequence_satisfied",
            "assumption": "The live video signing and witnessing sequence met section 9 as modified on 15 January 2024.",
            "outcome": "The will could be formally valid. This is not a definitive finding.",
        },
        {
            "branch_id": "sequence_not_satisfied",
            "assumption": "The required signing and witnessing sequence was not completed.",
            "outcome": "Section 9 was not satisfied, so the will would not be formally valid on that ground.",
        },
        {
            "branch_id": "sequence_unknown",
            "assumption": "The order of signing and witnessing remains unknown.",
            "outcome": "No definitive validity conclusion may be stated.",
        },
    ]
    packet = {
        "schema": PACKET_SCHEMA,
        "case_id": CASE_312,
        "topic": str(row.get("topic_id") or "wills-and-estates"),
        "subtopic": str(row.get("scenario_family_id") or routed_row.get("subtopic") or ""),
        "question": question,
        "candidate_answer": answer,
        "material_claims": material_claims(row),
        "factual_status": "FACTUAL_HOLD",
        "factual_outcome": "HOLD",
        "claim_support_status": str(routed_row.get("claim_support_status") or "PASS"),
        "hold_reason": "FACT_DEPENDENT_OUTCOME",
        "packet_status": "READY_FOR_FACT_DEPENDENT_REVIEW",
        "answer_may_be_conditionally_approvable": True,
        "do_not_assert_definitive_validity": True,
        "applicable_law_date": APPLICABLE_DATE,
        "owner_currentness_cutoff": "2026-08-28",
        "formality_authorities": [
            {"title": title, "locator": locator} for title, locator in FORMALITY_AUTHORITIES
        ],
        "attached_authorities": [
            {"title": item.get("title"), "locator": item.get("locator")} for item in evidence
        ],
        "known_facts": [
            "The events are placed in England on 15 January 2024.",
            "A will-maker and two witnesses used a live video link.",
            "The will was signed in several stages.",
        ],
        "missing_facts": list(MISSING_FACTS),
        "factual_branches": branches,
        "proposed_conditional_answer": CONDITIONAL_ANSWER,
        "exact_question_for_reviewer": (
            "May a conditional formality answer be accepted that states the 15 January 2024 "
            "section 9 route, the 2020 and 2022 instruments, the missing sequence facts, and "
            "alternative outcomes, without declaring that the will is valid or invalid?"
        ),
        "review_options": list(FACT_DEPENDENT_DECISIONS),
        "owner_fact_dependent_decision": "",
        "qualified_legal_review_decision": "",
        "owner_decision": "",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "review_status": NOT_STARTED,
        "do_not_further_retrieve": True,
        "named_case_invariant": True,
        "next_route": FACT_INPUT_OR_REVIEW_QUEUE,
        "question_hash": sha256_text(question),
        "answer_hash": sha256_text(answer),
        "evidence_manifest_hash": evidence_manifest_hash(row),
        "locator_count": len(evidence),
        "case_result_sha256": str(row.get("content_sha256") or ""),
    }
    sealed = seal_contract(packet, digest_field="packet_hash")
    if sealed["factual_status"] != "FACTUAL_HOLD":
        raise RuntimeError("case 312 packet changed factual hold")
    if sealed["owner_fact_dependent_decision"] != "":
        raise RuntimeError("case 312 packet filled an owner decision")
    lowered = sealed["proposed_conditional_answer"].casefold()
    if "the will is valid" in lowered or "the will is invalid" in lowered:
        raise RuntimeError("case 312 packet asserted a definitive validity outcome")
    return sealed
