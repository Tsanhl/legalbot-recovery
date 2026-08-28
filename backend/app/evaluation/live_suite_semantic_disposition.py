"""Deterministic V2 disposition of substantive semantic HOLDs.

Do not retry a sealed unsupported / partial / contradiction result until the
model says yes. Proof determines LIMITED or KNOWLEDGE_GAP. Actor type does not.
Contradiction never becomes unrestricted qualified.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_gap_verification import seal_gap_verification
from .live_suite_semantic_resume import classify_semantic_hold_cause

SEMANTIC_DISPOSITION_SCHEMA = "legalbot.semantic-hold-disposition.v2"
AdjudicationChoice = Literal["QUALIFIED", "LIMITED", "KNOWLEDGE_GAP", "KEEP_HOLD"]
DEFAULT_SOURCE_SET_ID = "ewofficial-2026-08-17-v1"
DEFAULT_SOURCE_SET_SHA256 = "fa1e469f1258927a7fa5159ad0bd7262fc01396fbac29725b0ecacf5efc95758"
PARTIAL_LIMITATION_REASON = "exact_span_supports_narrower_proposition_only"
UNSUPPORTED_GAP_REASON = "semantic_unsupported_defined_source_set_exhausted"
CONTRADICTION_HOLD_REASON = "contradiction_unbound_contrary_authority"
CONTRADICTION_GAP_REASON = "contradiction_unbound_no_safe_current_proposition"


def dispose_semantic_hold(
    record: Mapping[str, Any],
    *,
    contrary_bound: bool = False,
    defined_source_set_id: str = DEFAULT_SOURCE_SET_ID,
    source_set_manifest_sha256: str = DEFAULT_SOURCE_SET_SHA256,
    as_of_date: str = "2026-08-17",
    retry_until_supported: bool = False,
) -> dict[str, Any]:
    """Map a sealed semantic result onto QUALIFIED, LIMITED, KNOWLEDGE_GAP, or KEEP_HOLD."""

    if retry_until_supported:
        raise ValueError("a substantive semantic HOLD cannot be retried until it says yes")
    cause = classify_semantic_hold_cause(record)
    nested = record.get("semantic_result")
    nested_map = nested if isinstance(nested, Mapping) else {}
    spans = list(record.get("exact_gold_spans") or record.get("verified_positive_spans") or ())
    contradiction = int(nested_map.get("contradiction_count") or 0) > 0 or cause == "CONTRADICTION"
    recommendation: AdjudicationChoice = "KEEP_HOLD"
    reason = "semantic_hold_not_uniquely_determined"
    issue_update: dict[str, Any] = {}
    if cause == "SUPPORTED" and not contradiction:
        if spans:
            recommendation = "QUALIFIED"
            reason = "exact_span_semantically_supported"
            issue_update = {
                "disposition": "qualified",
                "status": "qualified",
                "final_verification_status": "VERIFIED",
                "exact_gold_spans": spans,
                "invented_span": False,
                "gap_reason": None,
                "limitation_reason": None,
                "semantic_result": dict(nested_map)
                if nested_map
                else record.get("semantic_result"),
                "semantic_result_seal_sha256": nested_map.get("seal_sha256")
                or record.get("semantic_result_seal_sha256"),
            }
        else:
            recommendation = "KEEP_HOLD"
            reason = "supported_without_exact_span"
            issue_update = {
                "disposition": "HOLD",
                "status": "HOLD",
                "final_verification_status": "HOLD",
                "limitation_reason": "supported_without_exact_span",
            }
    elif cause == "UNSUPPORTED" and not contradiction:
        if spans:
            spans = []
        gap = seal_gap_verification(
            {
                "issue_id": str(record.get("issue_id") or ""),
                "defined_source_set_id": defined_source_set_id,
                "source_set_manifest_sha256": source_set_manifest_sha256,
                "search_review_method": "deterministic_semantic_hold_disposition",
                "coverage_result": "defined_source_set_exhausted",
                "as_of_date": as_of_date,
                "reason_code": UNSUPPORTED_GAP_REASON,
                "review_actor": "deterministic",
            }
        )
        recommendation = "KNOWLEDGE_GAP"
        reason = UNSUPPORTED_GAP_REASON
        dumped = gap.model_dump(mode="json", by_alias=True)
        issue_update = {
            "disposition": "knowledge_gap",
            "status": "knowledge_gap",
            "final_verification_status": "VERIFIED",
            "exact_gold_spans": [],
            "invented_span": False,
            "gap_reason": UNSUPPORTED_GAP_REASON,
            "gap_verification": dumped,
            "gap_verification_seal_sha256": dumped["seal_sha256"],
            "limitation_reason": None,
        }
    elif cause == "PARTIAL_SUPPORT" and spans and not contradiction:
        recommendation = "LIMITED"
        reason = PARTIAL_LIMITATION_REASON
        issue_update = {
            "disposition": "limited",
            "status": "limited",
            "final_verification_status": "VERIFIED",
            "exact_gold_spans": spans,
            "invented_span": False,
            "limitation_reason": PARTIAL_LIMITATION_REASON,
            "semantic_result": dict(nested_map) if nested_map else record.get("semantic_result"),
            "semantic_result_seal_sha256": nested_map.get("seal_sha256")
            or record.get("semantic_result_seal_sha256"),
        }
    elif contradiction:
        if contrary_bound and spans:
            recommendation = "LIMITED"
            reason = "contradiction_represented_with_bound_contrary"
            issue_update = {
                "disposition": "limited",
                "status": "limited",
                "final_verification_status": "VERIFIED",
                "exact_gold_spans": spans,
                "limitation_reason": "bound_contrary_or_limiting_authority",
                "semantic_result_seal_sha256": nested_map.get("seal_sha256")
                or record.get("semantic_result_seal_sha256"),
            }
        else:
            recommendation = "KEEP_HOLD"
            reason = CONTRADICTION_HOLD_REASON
            issue_update = {
                "disposition": "HOLD",
                "status": "HOLD",
                "final_verification_status": "HOLD",
                "limitation_reason": CONTRADICTION_HOLD_REASON,
                "gap_reason": CONTRADICTION_HOLD_REASON,
            }
    payload = {
        "schema": SEMANTIC_DISPOSITION_SCHEMA,
        "row_id": record.get("row_id"),
        "issue_id": record.get("issue_id"),
        "cause": cause,
        "recommendation": recommendation,
        "reason_code": reason,
        "actor_type": "deterministic",
        "actor_type_does_not_determine_acceptance": True,
        "retried_until_supported": False,
        "unrestricted_qualified": recommendation == "QUALIFIED",
        "span_count": len(spans),
        "issue_update": issue_update,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "issue_update"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "issue_update"}
    )
    return payload


def finalize_unbound_contradiction_as_gap(
    issue: Mapping[str, Any],
    *,
    defined_source_set_id: str = DEFAULT_SOURCE_SET_ID,
    source_set_manifest_sha256: str = DEFAULT_SOURCE_SET_SHA256,
    as_of_date: str = "2026-08-17",
) -> dict[str, Any]:
    """When contrary authority cannot be bound, no safe current proposition remains."""

    gap = seal_gap_verification(
        {
            "issue_id": str(issue.get("issue_id") or ""),
            "defined_source_set_id": defined_source_set_id,
            "source_set_manifest_sha256": source_set_manifest_sha256,
            "search_review_method": "deterministic_unbound_contradiction_review",
            "coverage_result": "defined_source_set_exhausted",
            "as_of_date": as_of_date,
            "reason_code": CONTRADICTION_GAP_REASON,
            "review_actor": "deterministic",
        }
    )
    dumped = gap.model_dump(mode="json", by_alias=True)
    issue_update = {
        "disposition": "knowledge_gap",
        "status": "knowledge_gap",
        "final_verification_status": "VERIFIED",
        "exact_gold_spans": [],
        "invented_span": False,
        "gap_reason": CONTRADICTION_GAP_REASON,
        "gap_verification": dumped,
        "gap_verification_seal_sha256": dumped["seal_sha256"],
        "limitation_reason": None,
        "unrestricted_qualified": False,
    }
    payload = {
        "schema": SEMANTIC_DISPOSITION_SCHEMA,
        "row_id": issue.get("row_id"),
        "issue_id": issue.get("issue_id"),
        "cause": "CONTRADICTION",
        "recommendation": "KNOWLEDGE_GAP",
        "reason_code": CONTRADICTION_GAP_REASON,
        "actor_type": "deterministic",
        "actor_type_does_not_determine_acceptance": True,
        "contrary_bound": False,
        "unrestricted_qualified": False,
        "issue_update": issue_update,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "issue_update"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "issue_update"}
    )
    contradiction_cannot_be_unrestricted_qualified(payload)
    return payload


def contradiction_cannot_be_unrestricted_qualified(disposition: Mapping[str, Any]) -> None:
    if (
        str(disposition.get("cause") or "") == "CONTRADICTION"
        and str(disposition.get("recommendation") or "") == "QUALIFIED"
    ):
        raise ValueError("contradiction cannot become unrestricted qualified")


def summarize_adjudication_pack(pack: Mapping[str, Any]) -> dict[str, Any]:
    """Safe summary of an owner adjudication pack. No evidence prose."""

    counts = {"QUALIFIED": 0, "LIMITED": 0, "KNOWLEDGE_GAP": 0, "KEEP_HOLD": 0}
    rows: list[dict[str, Any]] = []
    for item in pack.get("rows") or ():
        rec = str(item.get("ai_recommendation") or item.get("recommendation") or "KEEP_HOLD")
        if rec in counts:
            counts[rec] += 1
        rows.append(
            {
                "row_id": item.get("row_id"),
                "semantic_cause": item.get("cause"),
                "recommended_final_disposition": rec,
                "evidence_count": item.get("span_count") or item.get("evidence_count") or 0,
                "contrary_status": item.get("contrary_status") or "unspecified",
                "currentness_status": item.get("currentness_status") or "unspecified",
                "reason_code": item.get("reason_code") or (item.get("reason_codes") or [None])[0],
            }
        )
    payload = {
        "pack_sha256": pack.get("pack_sha256"),
        "qualified_recommendations": counts["QUALIFIED"],
        "limited_recommendations": counts["LIMITED"],
        "knowledge_gap_recommendations": counts["KNOWLEDGE_GAP"],
        "keep_hold_recommendations": counts["KEEP_HOLD"],
        "rows": rows,
        "writes_active": False,
    }
    assert_safe_evaluation_payload({key: value for key, value in payload.items() if key != "rows"})
    return payload


def build_policy_adjudication_rows(
    records: Sequence[Mapping[str, Any]],
    *,
    contrary_bound_row_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    bound = contrary_bound_row_ids or set()
    rows: list[dict[str, Any]] = []
    for record in records:
        disposed = dispose_semantic_hold(
            record,
            contrary_bound=str(record.get("row_id") or "") in bound,
        )
        contradiction_cannot_be_unrestricted_qualified(disposed)
        nested = record.get("semantic_result")
        nested_map = nested if isinstance(nested, Mapping) else {}
        rows.append(
            {
                "row_id": record.get("row_id"),
                "case_id": record.get("case_id"),
                "issue_id": record.get("issue_id"),
                "cause": disposed["cause"],
                "semantic_result": nested_map.get("result") or record.get("result"),
                "semantic_result_seal_sha256": nested_map.get("seal_sha256")
                or record.get("semantic_result_seal_sha256"),
                "span_count": disposed["span_count"],
                "ai_recommendation": disposed["recommendation"],
                "recommendation": disposed["recommendation"],
                "reason_code": disposed["reason_code"],
                "available_choices": ["QUALIFIED", "LIMITED", "KNOWLEDGE_GAP", "KEEP_HOLD"],
                "actor_type": "deterministic",
            }
        )
    return rows
