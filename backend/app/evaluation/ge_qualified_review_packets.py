"""Prepare non-approving qualified-review packets. Review remains NOT_STARTED."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from app.contracts.schema_registry import seal_contract

from .ge_currentness_packets import evidence_manifest_hash, sha256_text
from .ge_currentness_subrouter import classify_currentness_subreason, currentness_analysis_fields
from .ge_hold_reason_router import CASE_008, CASE_174, CASE_312, QUALIFIED_LEGAL_REVIEW_QUEUE, freeze_pass_case, route_hold
from .ge_locator_gold_overlay import iso_date_from_prompt
from .ge_phase2_progress import NOT_STARTED

REVIEWER_OPTIONS = ("APPROVE", "APPROVE_WITH_EDIT", "HOLD", "REJECT")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _evidence_spans(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for item in row.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        spans.append(
            {
                "title": str(item.get("title") or ""),
                "locator": str(item.get("locator") or ""),
                "quote": str(item.get("quote") or ""),
                "oscola_parenthetical": str(item.get("oscola_parenthetical") or ""),
                "source_version_id": str(item.get("source_version_id") or ""),
                "chunk_id": str(item.get("chunk_id") or ""),
                "evidence_span_sha256": str(item.get("evidence_span_sha256") or ""),
                "currentness_reviewed_as_of_date": item.get("currentness_reviewed_as_of_date"),
                "currentness_verified": item.get("currentness_verified"),
                "full_current_law_verification_eligible": item.get("full_current_law_verification_eligible"),
                "provision_extent_status": item.get("provision_extent_status"),
                "unapplied_effect_count": item.get("unapplied_effect_count"),
                "point_in_time_as_at": item.get("point_in_time_as_at"),
                "jurisdiction": item.get("jurisdiction"),
            }
        )
    return spans


def _unsupported(row: Mapping[str, Any], routed: Mapping[str, Any]) -> list[str]:
    if routed.get("claim_support_status") == "PASS" or routed.get("factual_status") == "FACTUAL_PASS":
        return []
    factual = row.get("factual_result")
    reason = ""
    if isinstance(factual, Mapping):
        reasons = factual.get("reasons")
        if isinstance(reasons, Mapping):
            reason = str(reasons.get("claim_evidence_support") or "")
    return [reason or str(routed.get("hold_reason_detail") or "")]


def _proposed_edits(case_id: str, routed: Mapping[str, Any]) -> list[dict[str, str]]:
    edits: list[dict[str, str]] = []
    if case_id == CASE_312:
        edits.append(
            {
                "kind": "conditional_formality_answer",
                "status": "proposed_not_gold",
                "text": (
                    "State the Wills Act 1837 s9 formality requirements as they stood on "
                    "15 January 2024, including the temporary video-witnessing window. "
                    "Identify the missing signing and witnessing sequence facts. Give the "
                    "outcome under each material factual alternative. Do not assert a "
                    "definitive validity conclusion."
                ),
            }
        )
    if routed.get("hold_reason_code") == "FACT_DEPENDENT_OUTCOME":
        edits.append(
            {
                "kind": "fact_dependent_conditional_answer",
                "status": "proposed_not_gold",
                "text": (
                    "A qualified reviewer may approve a conditional answer that states the "
                    "governing rule, missing facts, and alternative outcomes without a "
                    "definitive merits conclusion."
                ),
            }
        )
    return edits


def build_review_packet(
    row: Mapping[str, Any],
    *,
    routed: Mapping[str, Any] | None = None,
    claim_row: Mapping[str, Any] | None = None,
    evaluation_as_of_date: str = "2026-08-28",
) -> dict[str, Any]:
    case_id = str(row.get("case_id") or "")
    routed_row = routed or (
        freeze_pass_case(row)
        if str((row.get("factual_result") or {}).get("outcome") or "") == "FACTUAL_PASS"
        else route_hold(row)
    )
    factual = row.get("factual_result") if isinstance(row.get("factual_result"), Mapping) else {}
    currentness = {}
    if routed_row.get("hold_reason_code") == "CURRENTNESS_UNRESOLVED" or case_id == CASE_312:
        currentness = classify_currentness_subreason(row)
    elif routed_row.get("factual_status") == "FACTUAL_PASS":
        currentness = {
            "currentness_subreason": None,
            "currentness_analysis": currentness_analysis_fields(
                row, evaluation_as_of_date=evaluation_as_of_date
            ),
        }
    competing = ""
    if case_id == CASE_174:
        competing = (
            "Cross-border jurisdiction-scope only. Mandatory route is ICC article 5, "
            "Ohpen, Kajima and Churchill. Cable & Wireless and Arbitration Act 1996 "
            "section 9 must not be added."
        )
    elif routed_row.get("hold_reason_code") == "JURISDICTION_SCOPE_REVIEW":
        competing = str(routed_row.get("hold_reason_detail") or "")
    packet = {
        "schema": "legalbot.ge-qualified-review-packet.v1",
        "case_id": case_id,
        "qualified_legal_review": "NOT_STARTED",
        "answer_legal_gold": "NOT_STARTED",
        "question": str(row.get("question") or row.get("prompt") or ""),
        "answer": str(row.get("user_facing_answer") or row.get("answer") or ""),
        "issue_list": list(row.get("issue_tags") or []),
        "jurisdiction": str(row.get("primary_jurisdiction") or "ENGLAND_AND_WALES"),
        "relevant_date_or_as_of_date": iso_date_from_prompt(
            str(row.get("question") or row.get("prompt") or "")
        )
        or evaluation_as_of_date,
        "accepted_locators": [
            {"title": item.get("title"), "locator": item.get("locator")}
            for item in row.get("evidence") or []
            if isinstance(item, dict)
        ],
        "exact_evidence_spans": _evidence_spans(row),
        "unsupported_or_contested_propositions": (
            [item.get("normalized_legal_proposition") or item.get("failure_reason") for item in claim_row.get("propositions") or []]
            if claim_row
            else _unsupported(row, routed_row)
        ),
        "claim_failure_class": None if claim_row is None else claim_row.get("failure_class"),
        "claim_mechanical_status": None if claim_row is None else claim_row.get("mechanical_status"),
        "factual_diagnostic_status": routed_row.get("factual_status")
        or (factual.get("outcome") if isinstance(factual, Mapping) else ""),
        "hold_reason": routed_row.get("hold_reason_code"),
        "hold_reason_detail": routed_row.get("hold_reason_detail"),
        "currentness_subreason": currentness.get("currentness_subreason"),
        "currentness_subreasons_additional": currentness.get("currentness_subreasons_additional") or [],
        "currentness_analysis": currentness.get("currentness_analysis")
        or currentness_analysis_fields(row, evaluation_as_of_date=evaluation_as_of_date),
        "competing_authority_or_scope_issue": competing,
        "proposed_reviewer_options": list(REVIEWER_OPTIONS),
        "proposed_deterministic_edits": _proposed_edits(case_id, routed_row),
        "named_case_invariant": case_id in {CASE_008, CASE_174, CASE_312},
        "terminal_for_mechanical_route": True,
        "terminal_for_entire_pipeline": False,
        "qualified_review_ready": True,
        "conditional_answer_potentially_approvable": case_id == CASE_312
        or routed_row.get("hold_reason_code") == "FACT_DEPENDENT_OUTCOME",
        "do_not_assert_definitive_validity": case_id == CASE_312,
        "no_cable_and_wireless": True,
        "no_arbitration_act_s9_for_mediation": case_id == CASE_174,
        "next_route": QUALIFIED_LEGAL_REVIEW_QUEUE,
        "review_queue_bucket": (
            "FACTUAL_PASS"
            if routed_row.get("factual_status") == "FACTUAL_PASS"
            else str(routed_row.get("hold_reason_code") or "QUALIFIED_LEGAL_REVIEW_REQUIRED")
        ),
    }
    packet["audit_hashes"] = {
        "case_result_sha256": str(row.get("content_sha256") or ""),
        "packet_body_sha256": _sha({key: value for key, value in packet.items() if key != "audit_hashes"}),
        "evidence_span_sha256": [
            str(item.get("evidence_span_sha256") or "") for item in packet["exact_evidence_spans"]
        ],
    }
    return packet


def build_factual_pass_packet(
    row: Mapping[str, Any],
    *,
    routed: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    routed_row = routed or freeze_pass_case(row)
    base = build_review_packet(row, routed=routed_row)
    question = str(row.get("question") or row.get("prompt") or "")
    answer = str(row.get("user_facing_answer") or row.get("answer") or "")
    packet = {
        **base,
        "topic": str(row.get("topic_id") or ""),
        "subtopic": str(row.get("scenario_family_id") or ""),
        "packet_status": "READY_FOR_FACTUAL_PASS_REVIEW",
        "factual_status": "FACTUAL_PASS",
        "route": "FACTUAL_PASS",
        "candidate_answer": answer,
        "owner_decision": "",
        "qualified_legal_review_decision": "",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "question_hash": sha256_text(question),
        "answer_hash": sha256_text(answer),
        "evidence_manifest_hash": evidence_manifest_hash(row),
        "locator_count": len(base.get("exact_evidence_spans") or []),
        "do_not_treat_factual_pass_as_gold": True,
    }
    sealed = seal_contract(packet, digest_field="packet_hash")
    if sealed["factual_status"] != "FACTUAL_PASS":
        raise RuntimeError("factual-pass packet lost FACTUAL_PASS")
    if sealed["qualified_legal_review"] != NOT_STARTED or sealed["answer_legal_gold"] != NOT_STARTED:
        raise RuntimeError("factual-pass packet filled a later gate")
    if sealed["legal_gold"] is not False:
        raise RuntimeError("factual-pass packet set legal gold")
    return sealed


def build_review_pack(
    rows: Sequence[Mapping[str, Any]],
    *,
    ready_ids: Sequence[str],
    routed_by_id: Mapping[str, Mapping[str, Any]] | None = None,
    claim_by_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    wanted = set(ready_ids)
    packets: list[dict[str, Any]] = []
    lookup = routed_by_id or {}
    claims = claim_by_id or {}
    for row in rows:
        case_id = str(row.get("case_id") or "")
        if case_id not in wanted:
            continue
        packets.append(
            build_review_packet(
                row,
                routed=lookup.get(case_id),
                claim_row=claims.get(case_id),
            )
        )
    subreasons = Counter(
        str(item.get("currentness_subreason") or "NOT_APPLICABLE") for item in packets
    )
    return {
        "schema": "legalbot.ge-qualified-review-preparation-manifest.v1",
        "qualified_legal_review": "NOT_STARTED",
        "packet_count": len(packets),
        "case_ids": [item["case_id"] for item in packets],
        "packets": packets,
        "currentness_subreason_counts_in_packets": dict(sorted(subreasons.items())),
        "reviewer_options": list(REVIEWER_OPTIONS),
        "substantive_approval_recorded": False,
    }
