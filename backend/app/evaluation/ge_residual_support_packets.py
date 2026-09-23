"""Residual claim-support and no-evidence packets. Mechanical retrieval is closed."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.contracts.schema_registry import seal_contract

from .ge_claim_support_router import classify_claim_case
from .ge_currentness_packets import evidence_manifest_hash, material_claims, sha256_text
from .ge_hold_reason_router import QUALIFIED_LEGAL_REVIEW_QUEUE, route_hold
from .ge_phase2_progress import NOT_STARTED

PACKET_SCHEMA = "legalbot.ge-residual-support-packet.v1"
RESIDUAL_DECISIONS = (
    "SUPPORT_CONFIRMED",
    "ANSWER_CONTRACTION_REQUIRED",
    "WRONG_LEGAL_ROUTE",
    "INSUFFICIENT_AUTHORITY",
    "HOLD",
    "REJECT",
)

def _unsupported_proposition(claim: Mapping[str, Any], routed: Mapping[str, Any]) -> str:
    propositions = claim.get("propositions") or []
    if propositions and isinstance(propositions[0], Mapping):
        return str(
            propositions[0].get("normalized_legal_proposition")
            or propositions[0].get("failure_reason")
            or routed.get("hold_reason_detail")
            or ""
        )
    return str(routed.get("hold_reason_detail") or "")


NO_EVIDENCE_CLASSES = (
    "GENUINELY_EVIDENCE_PRESENT_FALSE",
    "EVIDENCE_PRESENT_BUT_NOT_FOR_MATERIAL_PROPOSITION",
    "PACKET_LEVEL_METADATA_MISSING",
    "STALE_HISTORICAL_HOLD_REASON",
    "UNUSABLE_OR_REJECTED_EVIDENCE",
    "OFFICIAL_SOURCE_UNAVAILABLE_FAIL_CLOSED",
)


def classify_no_evidence_label(row: Mapping[str, Any], routed: Mapping[str, Any]) -> dict[str, Any]:
    evidence = [item for item in (row.get("evidence") or []) if isinstance(item, dict)]
    present = bool(evidence)
    missing = [str(item) for item in row.get("known_missing_primary_authorities") or []]
    titles = " ".join(str(item.get("title") or "") for item in evidence).casefold()
    if "cable & wireless" in titles or any("cable" in name.casefold() for name in missing):
        code = "UNUSABLE_OR_REJECTED_EVIDENCE"
        if not present:
            code = "OFFICIAL_SOURCE_UNAVAILABLE_FAIL_CLOSED"
        note = "Rejected or fail-closed Cable & Wireless is not treated as missing recoverable evidence."
    elif present is False and routed.get("evidence_present") is False:
        code = "GENUINELY_EVIDENCE_PRESENT_FALSE"
        note = (
            "Latest accepted delta RESULTS have an empty evidence array. "
            "This is not a stale NO_EVIDENCE label relative to that delta."
        )
    elif present and routed.get("evidence_present") is False:
        code = "STALE_HISTORICAL_HOLD_REASON"
        note = "Evidence rows exist on the latest record but the hold code still says no evidence."
    elif present and routed.get("claim_support_status") != "PASS":
        code = "EVIDENCE_PRESENT_BUT_NOT_FOR_MATERIAL_PROPOSITION"
        note = "Evidence is attached at case level but does not support the material proposition."
    else:
        code = "GENUINELY_EVIDENCE_PRESENT_FALSE"
        note = "Empty evidence on the latest accepted case record."
    return {
        "no_evidence_class": code,
        "evidence_present_on_latest_record": present,
        "routed_evidence_present": routed.get("evidence_present") is True,
        "evidence_row_count": len(evidence),
        "classification_note": note,
        "known_missing_primary_authorities": missing,
    }


def build_residual_packet(
    row: Mapping[str, Any],
    *,
    routed: Mapping[str, Any] | None = None,
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]] | None = None,
    topic_sources: Mapping[str, tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    routed_row = routed or route_hold(row)
    claim = classify_claim_case(
        row,
        locator_hints=locator_hints or {},
        topic_sources=topic_sources,
        attempt_count=2,
    )
    question = str(row.get("question") or row.get("prompt") or "")
    answer = str(row.get("user_facing_answer") or row.get("answer") or "")
    evidence = [item for item in (row.get("evidence") or []) if isinstance(item, dict)]
    no_ev = {}
    if routed_row.get("hold_reason_code") == "RETRIEVAL_NO_EVIDENCE":
        no_ev = classify_no_evidence_label(row, routed_row)
    overclaim = str(claim.get("failure_class") or "") == "ANSWER_OVERCLAIMS_EVIDENCE"
    wrong_route = str(claim.get("failure_class") or "") == "ANSWER_USES_WRONG_LEGAL_ROUTE"
    unavailable = no_ev.get("no_evidence_class") == "OFFICIAL_SOURCE_UNAVAILABLE_FAIL_CLOSED"
    contraction = bool(claim.get("candidate_constrained_answer")) and overclaim
    packet = {
        "schema": PACKET_SCHEMA,
        "case_id": str(row.get("case_id") or ""),
        "topic": str(row.get("topic_id") or routed_row.get("topic") or ""),
        "subtopic": str(row.get("scenario_family_id") or routed_row.get("subtopic") or ""),
        "question": question,
        "candidate_answer": answer,
        "material_claims": material_claims(row),
        "factual_status": "FACTUAL_HOLD",
        "claim_support_status": str(routed_row.get("claim_support_status") or "FAIL"),
        "hold_reason": str(routed_row.get("hold_reason_code") or ""),
        "exact_unsupported_proposition": _unsupported_proposition(claim, routed_row),
        "existing_attached_evidence": [
            {
                "title": item.get("title"),
                "locator": item.get("locator"),
                "quote": item.get("quote"),
                "evidence_span_sha256": item.get("evidence_span_sha256"),
            }
            for item in evidence
        ],
        "why_support_remains_insufficient": str(routed_row.get("hold_reason_detail") or ""),
        "answer_overclaims": overclaim,
        "wrong_legal_route": wrong_route,
        "deterministic_contraction_available": contraction,
        "official_authority_unavailable": unavailable,
        "legal_judgment_required": True,
        "failure_class": claim.get("failure_class"),
        "no_evidence_reconciliation": no_ev,
        "mechanical_status": "EXHAUSTED",
        "terminal_for_mechanical_route": True,
        "terminal_for_entire_pipeline": False,
        "machine_repairable": False,
        "do_not_generic_retrieve": True,
        "do_not_reclassify_to_pass": True,
        "packet_status": "READY_FOR_RESIDUAL_SUPPORT_REVIEW",
        "precise_qualified_review_question": (
            "Why does the attached evidence fail to support the candidate proposition, "
            "and should the answer be contracted, rerouted, held, or rejected without "
            "another generic retrieval?"
        ),
        "review_options": list(RESIDUAL_DECISIONS),
        "owner_residual_decision": "",
        "qualified_legal_review_decision": "",
        "owner_decision": "",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "review_status": NOT_STARTED,
        "next_route": QUALIFIED_LEGAL_REVIEW_QUEUE,
        "question_hash": sha256_text(question),
        "answer_hash": sha256_text(answer),
        "evidence_manifest_hash": evidence_manifest_hash(row),
        "locator_count": len(evidence),
        "evidence_present_on_latest_record": bool(evidence),
        "case_result_sha256": str(row.get("content_sha256") or ""),
        "propositions": claim.get("propositions") or [],
    }
    sealed = seal_contract(packet, digest_field="packet_hash")
    if sealed["owner_residual_decision"] != "" or sealed["qualified_legal_review"] != NOT_STARTED:
        raise RuntimeError("residual packet filled a decision")
    if sealed["mechanical_status"] != "EXHAUSTED":
        raise RuntimeError("residual packet reopened mechanical repair")
    return sealed


def build_residual_packets(
    rows: Sequence[Mapping[str, Any]],
    *,
    routed_holds: Mapping[str, Mapping[str, Any]],
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
    topic_sources: Mapping[str, tuple[str, ...]] | None = None,
) -> list[dict[str, Any]]:
    packets = [
        build_residual_packet(
            row,
            routed=routed_holds.get(str(row.get("case_id") or "")),
            locator_hints=locator_hints,
            topic_sources=topic_sources,
        )
        for row in rows
    ]
    packets.sort(key=lambda item: str(item["case_id"]))
    return packets
