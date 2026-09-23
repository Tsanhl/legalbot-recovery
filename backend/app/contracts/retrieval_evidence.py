"""Selected RetrievalResult and EvidencePack contracts without plaintext evidence."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from ..jurisdictions import compatible
from ..types import EvidenceSpan
from .schema_registry import ContractSchemaRegistry, canonical_json_bytes, seal_contract

_LANES = {
    "primary_authority": "primary_authority",
    "procedure_rule": "official_secondary",
    "regulator_rule": "official_secondary",
    "official_guidance": "official_secondary",
    "official_metadata": "official_secondary",
    "official_secondary": "official_secondary",
    "secondary_scholarship": "scholarship",
    "book_or_treatise": "scholarship",
    "scholarship": "scholarship",
}
_ROUTES = {
    "exact_authority_identity",
    "exact_legislation_reference",
    "hybrid_rrf",
    "frozen_reviewed_research_receipt",
}
_CURRENTNESS_CURRENT = {
    "current",
    "confirmed_current",
    "qualified_current",
    "latest_available",
    "latest_available_revised_snapshot",
    "latest-available-revised-snapshot",
    "point_in_time",
    "point_in_time_current_at_target_ceiling",
    "current_binding_supreme_court_authority",
    "binding_successor_in_same_proceedings",
    "persuasive_first_instance_with_current_statutory_confirmation",
}
_CURRENTNESS_HISTORICAL = {
    "historical",
    "historical_as_enacted",
    "as_enacted",
    "repealed",
    "qualified_historical",
}
_UNRESOLVED_SCOPE = {"", "unknown", "unverified", "unresolved", "not_reviewed"}


@dataclass(frozen=True, slots=True)
class QualifiedEvidenceInput:
    span: EvidenceSpan
    issue_ids: tuple[str, ...]
    selected_token_count: int
    selected_rank: int


@dataclass(frozen=True, slots=True)
class RetrievalEvidenceContracts:
    retrieval_result: Mapping[str, Any]
    evidence_pack: Mapping[str, Any]


def _stamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _currentness(span: EvidenceSpan) -> str:
    value = str(span.currentness_status).strip().casefold()
    if value in _CURRENTNESS_HISTORICAL:
        return "qualified_historical"
    if value in _CURRENTNESS_CURRENT:
        return "qualified_current"
    raise ValueError("evidence currentness status is not an explicit qualified state")


def _optional_day(value: Any, *, field: str) -> date | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"evidence {field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError(f"evidence {field} must be an ISO date") from None


def _currentness_scope(span: EvidenceSpan, *, requested_as_of_date: date | None) -> dict[str, Any]:
    citation = span.citation_data
    reviewed = _optional_day(citation.get("reviewed_as_of"), field="reviewed_as_of")
    if reviewed is None:
        raise ValueError("evidence requires an actual currentness review date")
    effective_from = _optional_day(citation.get("effective_from"), field="effective_from")
    effective_to = _optional_day(citation.get("effective_to"), field="effective_to")
    if effective_from is not None and effective_to is not None and effective_from > effective_to:
        raise ValueError("evidence effective date range is reversed")
    if requested_as_of_date is not None:
        if reviewed < requested_as_of_date:
            raise ValueError("evidence currentness review predates the requested date")
        if effective_from is not None and requested_as_of_date < effective_from:
            raise ValueError("evidence was not effective on the requested date")
        if effective_to is not None and requested_as_of_date > effective_to:
            raise ValueError("evidence was not effective on the requested date")
        if _currentness(span) == "qualified_historical" and (
            effective_from is None or effective_to is None
        ):
            raise ValueError("historical evidence requires a bounded effective date range")
    extent = str(span.provision_extent_status or "").strip().casefold()
    if extent in _UNRESOLVED_SCOPE:
        raise ValueError("evidence extent is unresolved")
    commencement = str(citation.get("commencement_status") or "").strip().casefold()
    if commencement in _UNRESOLVED_SCOPE:
        raise ValueError("evidence commencement is unresolved")
    return {
        "reviewed_as_of": reviewed.isoformat(),
        "effective_from": effective_from.isoformat() if effective_from is not None else None,
        "effective_to": effective_to.isoformat() if effective_to is not None else None,
        "extent_status": span.provision_extent_status,
        "commencement_status": citation["commencement_status"],
    }


def _qualification_receipt(
    span: EvidenceSpan,
    *,
    issue_ids: Sequence[str],
    requested_as_of_date: date | None,
) -> str:
    if (
        not span.identity_verified
        or not span.currentness_verified
        or span.retrieval_threshold_qualified is not True
        or span.retrieval_threshold_policy_sha256 is None
    ):
        raise ValueError("evidence span is not fully qualified")
    lane = _LANES.get(str(span.lane))
    if lane is None:
        raise ValueError("evidence lane cannot enter a material evidence pack")
    route = str(span.retrieval_route or "")
    if route not in _ROUTES:
        raise ValueError("evidence retrieval route is not selected")
    currentness_scope = _currentness_scope(
        span,
        requested_as_of_date=requested_as_of_date,
    )
    material = {
        "schema": "legalbot.evidence-qualification-receipt.v1",
        "evidence_id": span.id,
        "source_version_id": span.source_version_id,
        "chunk_id": span.chunk_id,
        "content_sha256": span.content_sha256,
        "jurisdiction": span.jurisdiction,
        "lane": lane,
        "currentness_status": _currentness(span),
        **currentness_scope,
        "identity_verified": span.identity_verified,
        "currentness_verified": span.currentness_verified,
        "retrieval_threshold_policy_sha256": span.retrieval_threshold_policy_sha256,
        "retrieval_qualification_reason": span.retrieval_qualification_reason,
        "case_currentness_manifest_seals": list(span.case_currentness_manifest_seals),
        "issue_ids": list(issue_ids),
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _evidence_ref(
    item: QualifiedEvidenceInput, *, requested_as_of_date: date | None
) -> dict[str, Any]:
    span = item.span
    lane = _LANES[str(span.lane)]
    currentness_scope = _currentness_scope(
        span,
        requested_as_of_date=requested_as_of_date,
    )
    return {
        "evidence_id": span.id,
        "source_version_id": span.source_version_id,
        "chunk_id": span.chunk_id,
        "content_sha256": span.content_sha256,
        "locator": span.locator,
        "jurisdiction": span.jurisdiction,
        "lane": lane,
        "legal_role": span.legal_role,
        "currentness_status": _currentness(span),
        **currentness_scope,
        "qualification_receipt_sha256": _qualification_receipt(
            span,
            issue_ids=item.issue_ids,
            requested_as_of_date=requested_as_of_date,
        ),
        "retrieval_route": span.retrieval_route,
        "retrieval_score": span.retrieval_relevance_score,
        "selection_reason": span.retrieval_qualification_reason or "threshold_qualified",
        "score_system": "hybrid_rrf_reranker_v1",
    }


def validate_retrieval_evidence_scope(
    *,
    query_plan: Mapping[str, Any],
    evidence_pack: Mapping[str, Any],
    retrieval_result: Mapping[str, Any] | None = None,
) -> None:
    """Reject cross-issue, cross-jurisdiction or invented currentness bindings.

    JSON Schema closes shape.  This closes the semantic relations that a
    schema cannot express and is safe to call again at release time.
    """

    plan_issues = tuple(query_plan["issue_ids"])
    if len(plan_issues) != len(set(plan_issues)):
        raise ValueError("frozen query plan contains duplicate issues")
    plan_issue_set = set(plan_issues)
    plan_jurisdiction = query_plan.get("jurisdiction")
    requested = (
        date.fromisoformat(query_plan["requested_as_of_date"])
        if query_plan.get("requested_as_of_date") is not None
        else None
    )
    selected = list(evidence_pack["selected"])
    selected_ids = [str(item["evidence_id"]) for item in selected]
    if len(selected_ids) != len(set(selected_ids)):
        raise ValueError("evidence pack contains duplicate selected evidence")
    if selected and not isinstance(plan_jurisdiction, str):
        raise ValueError("evidence pack requires a resolved plan jurisdiction")
    for item in selected:
        if not compatible(plan_jurisdiction, item["jurisdiction"]):
            raise ValueError("evidence pack jurisdiction is outside the frozen query plan")
        reviewed = _optional_day(item.get("reviewed_as_of"), field="reviewed_as_of")
        if reviewed is None:
            raise ValueError("evidence pack lacks an actual currentness review date")
        effective_from = _optional_day(item.get("effective_from"), field="effective_from")
        effective_to = _optional_day(item.get("effective_to"), field="effective_to")
        if effective_from is not None and effective_to is not None and effective_from > effective_to:
            raise ValueError("evidence pack effective date range is reversed")
        if requested is not None:
            if reviewed < requested:
                raise ValueError("evidence pack currentness review predates the requested date")
            if effective_from is not None and requested < effective_from:
                raise ValueError("evidence pack source was not effective on the requested date")
            if effective_to is not None and requested > effective_to:
                raise ValueError("evidence pack source was not effective on the requested date")
            if item["currentness_status"] == "qualified_historical" and (
                effective_from is None or effective_to is None
            ):
                raise ValueError("historical evidence pack source lacks a bounded effective range")
        if str(item.get("extent_status") or "").strip().casefold() in _UNRESOLVED_SCOPE:
            raise ValueError("evidence pack extent is unresolved")
        if str(item.get("commencement_status") or "").strip().casefold() in _UNRESOLVED_SCOPE:
            raise ValueError("evidence pack commencement is unresolved")

    coverage = list(evidence_pack["issue_coverage"])
    coverage_ids = [str(item["issue_id"]) for item in coverage]
    if len(coverage_ids) != len(set(coverage_ids)) or set(coverage_ids) != plan_issue_set:
        raise ValueError("evidence coverage does not exactly match the frozen plan issues")
    selected_set = set(selected_ids)
    covered_evidence: set[str] = set()
    coverage_gaps: set[tuple[str, str]] = set()
    for item in coverage:
        ids = set(item["evidence_ids"])
        gaps = set(item["gap_codes"])
        if not ids <= selected_set:
            raise ValueError("evidence coverage references evidence outside the pack")
        expected = "satisfied" if ids and not gaps else "partial" if ids else "gap"
        if item["status"] != expected:
            raise ValueError("evidence coverage status is inconsistent with evidence and gaps")
        covered_evidence.update(ids)
        coverage_gaps.update((item["issue_id"], code) for code in gaps)
    if covered_evidence != selected_set:
        raise ValueError("selected evidence is not bound to exactly one or more frozen issues")
    declared_gaps = {(item["issue_id"], item["code"]) for item in evidence_pack["gaps"]}
    if coverage_gaps != declared_gaps or any(issue not in plan_issue_set for issue, _ in declared_gaps):
        raise ValueError("evidence gaps do not match issue coverage")
    if retrieval_result is not None:
        if list(retrieval_result["selected_evidence_ids"]) != selected_ids:
            raise ValueError("retrieval selection differs from the evidence pack")
        result_allocations = {
            item["issue_id"]: (
                item["status"],
                set(item["selected_evidence_ids"]),
                set(item["reason_codes"]),
            )
            for item in retrieval_result["issue_allocations"]
        }
        pack_allocations = {
            item["issue_id"]: (item["status"], set(item["evidence_ids"]), set(item["gap_codes"]))
            for item in coverage
        }
        if result_allocations != pack_allocations:
            raise ValueError("retrieval issue allocations differ from evidence coverage")


def build_retrieval_evidence_contracts(
    *,
    query_plan: Mapping[str, Any],
    query_plan_sha256: str,
    candidate_sha256: str,
    evidence: Sequence[QualifiedEvidenceInput],
    fact_snapshot_sha256: str | None,
    created_at: datetime,
    registry: ContractSchemaRegistry,
    degraded: bool = False,
    issue_gap_codes: Mapping[str, Sequence[str]] | None = None,
    timing_ms: Mapping[str, int] | None = None,
    peak_memory_bytes: int = 0,
) -> RetrievalEvidenceContracts:
    """Bind qualified spans to one result and one prompt-safe evidence pack."""

    registry.validate_new(query_plan)
    requested_as_of_date = (
        date.fromisoformat(query_plan["requested_as_of_date"])
        if query_plan["requested_as_of_date"] is not None
        else None
    )
    plan_issue_ids = set(query_plan["issue_ids"])
    if not plan_issue_ids and evidence:
        raise ValueError("selected evidence requires frozen plan issues")
    plan_jurisdiction = query_plan.get("jurisdiction")
    if evidence and not isinstance(plan_jurisdiction, str):
        raise ValueError("selected evidence requires a resolved plan jurisdiction")
    selected = tuple(evidence)
    if len(selected) > int(query_plan["budgets"]["final_top_k"]):
        raise ValueError("selected evidence exceeds the frozen final top-k")
    if len({item.span.id for item in selected}) != len(selected):
        raise ValueError("selected evidence IDs must be unique")
    if sorted(item.selected_rank for item in selected) != list(range(1, len(selected) + 1)):
        raise ValueError("selected evidence ranks must be contiguous")
    for item in selected:
        if not item.issue_ids:
            raise ValueError("selected evidence requires at least one issue binding")
        if not set(item.issue_ids) <= plan_issue_ids:
            raise ValueError("selected evidence issue is outside the frozen query plan")
        if not compatible(plan_jurisdiction, item.span.jurisdiction, item.span.citation_data):
            raise ValueError("selected evidence jurisdiction is outside the frozen query plan")
        if item.selected_token_count < 0:
            raise ValueError("selected evidence token count cannot be negative")
        _qualification_receipt(
            item.span,
            issue_ids=item.issue_ids,
            requested_as_of_date=requested_as_of_date,
        )

    gaps_by_issue = {
        issue_id: tuple(dict.fromkeys(codes)) for issue_id, codes in (issue_gap_codes or {}).items()
    }
    if not set(gaps_by_issue) <= plan_issue_ids:
        raise ValueError("evidence gap issue is outside the frozen query plan")
    evidence_by_issue: dict[str, list[str]] = defaultdict(list)
    tokens_by_issue: dict[str, int] = defaultdict(int)
    for item in selected:
        for issue_id in item.issue_ids:
            evidence_by_issue[issue_id].append(item.span.id)
            tokens_by_issue[issue_id] += item.selected_token_count
    all_issues = list(dict.fromkeys((*query_plan["issue_ids"], *gaps_by_issue)))
    allocations: list[dict[str, Any]] = []
    issue_gaps: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for issue_id in all_issues:
        ids = list(dict.fromkeys(evidence_by_issue.get(issue_id, ())))
        gap_codes = list(gaps_by_issue.get(issue_id, ()))
        status = "satisfied" if ids and not gap_codes else "partial" if ids else "gap"
        allocations.append(
            {
                "issue_id": issue_id,
                "status": status,
                "selected_evidence_ids": ids,
                "selected_token_count": tokens_by_issue.get(issue_id, 0),
                "reason_codes": gap_codes,
            }
        )
        coverage.append(
            {
                "issue_id": issue_id,
                "status": status,
                "evidence_ids": ids,
                "gap_codes": gap_codes,
            }
        )
        issue_gaps.extend({"issue_id": issue_id, "reason_code": code} for code in gap_codes)

    candidate_records = []
    for item in selected:
        span = item.span
        receipt = _qualification_receipt(
            span,
            issue_ids=item.issue_ids,
            requested_as_of_date=requested_as_of_date,
        )
        candidate_identity = hashlib.sha256(
            canonical_json_bytes(
                {
                    "evidence_id": span.id,
                    "source_version_id": span.source_version_id,
                    "chunk_id": span.chunk_id,
                    "selected_rank": item.selected_rank,
                    "query_plan_sha256": query_plan_sha256,
                }
            )
        ).hexdigest()
        candidate_records.append(
            {
                "candidate_record_id": f"retrieval-candidate-{candidate_identity[:40]}",
                "evidence_span_id": span.id,
                "source_version_id": span.source_version_id,
                "locator": span.locator,
                "issue_ids": list(item.issue_ids),
                "disposition": "selected",
                "reason_codes": [span.retrieval_qualification_reason or "threshold_qualified"],
                "lexical_rank": None,
                "vector_rank": None,
                "fused_rank": item.selected_rank,
                "rerank_score": span.retrieval_relevance_score,
                "reranker_rank": item.selected_rank,
                "selected_rank": item.selected_rank,
                "chunk_sha256": span.content_sha256,
                "qualification_status": "qualified",
                "currentness_status": _currentness(span),
                "qualification_receipt_sha256": receipt,
            }
        )
    timings = {
        key: int((timing_ms or {}).get(key, 0))
        for key in ("lexical", "vector", "fusion", "reranker", "qualification", "selection")
    }
    timings["total"] = int((timing_ms or {}).get("total", sum(timings.values())))
    stamp = _stamp(created_at)
    result_identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "query_plan_sha256": query_plan_sha256,
                "candidate_sha256": candidate_sha256,
                "candidate_records": candidate_records,
                "created_at": stamp,
            }
        )
    ).hexdigest()
    retrieval_result = seal_contract(
        {
            "schema": "legalbot.retrieval-result.v1",
            "retrieval_result_id": f"retrieval-result-{result_identity[:40]}",
            "query_plan_id": query_plan["query_plan_id"],
            "query_plan_sha256": query_plan_sha256,
            "candidate_id": query_plan["candidate_id"],
            "candidate_sha256": candidate_sha256,
            "policy_sha256": query_plan["policy_sha256"],
            "routes": {
                "lexical": "used"
                if query_plan["data_intent"] in {"KNOWLEDGE_ONLY", "HYBRID"}
                else "not_applicable",
                "vector": "used"
                if query_plan["data_intent"] in {"KNOWLEDGE_ONLY", "HYBRID"}
                else "not_applicable",
                "reranker": "used"
                if query_plan["data_intent"] in {"KNOWLEDGE_ONLY", "HYBRID"}
                else "not_applicable",
            },
            "candidates": candidate_records,
            "selected_evidence_ids": [item.span.id for item in selected],
            "issue_gaps": issue_gaps,
            "degraded": degraded,
            "created_at": stamp,
            "issue_allocations": allocations,
            "timing_ms": timings,
            "resource_use": {
                "candidate_count": len(candidate_records),
                "selected_count": len(selected),
                "selected_token_count": sum(item.selected_token_count for item in selected),
                "peak_memory_bytes": max(0, peak_memory_bytes),
            },
        }
    )
    registry.validate_new(retrieval_result)

    refs = [
        _evidence_ref(
            item,
            requested_as_of_date=requested_as_of_date,
        )
        for item in selected
    ]
    pack_identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "query_plan_sha256": query_plan_sha256,
                "retrieval_result_sha256": retrieval_result["content_sha256"],
                "selected": refs,
                "fact_snapshot_sha256": fact_snapshot_sha256,
                "created_at": stamp,
            }
        )
    ).hexdigest()
    relevance_policies = {item.span.retrieval_threshold_policy_sha256 for item in selected}
    if len(relevance_policies) > 1:
        raise ValueError("selected evidence uses more than one relevance policy")
    relevance_policy_sha256 = (
        next(iter(relevance_policies)) if relevance_policies else str(query_plan["policy_sha256"])
    )
    evidence_pack = seal_contract(
        {
            "schema": "legalbot.evidence-pack.v1",
            "evidence_pack_id": f"evidence-pack-{pack_identity[:40]}",
            "query_plan_id": query_plan["query_plan_id"],
            "candidate_id": query_plan["candidate_id"],
            "index_generation_sha256": candidate_sha256,
            "relevance_policy_sha256": relevance_policy_sha256,
            "requested_as_of_date": query_plan["requested_as_of_date"],
            "selected": refs,
            "gaps": [
                {"issue_id": item["issue_id"], "code": item["reason_code"]} for item in issue_gaps
            ],
            "created_at": stamp,
            "query_plan_sha256": query_plan_sha256,
            "retrieval_result_sha256": retrieval_result["content_sha256"],
            "fact_snapshot_sha256": fact_snapshot_sha256,
            "issue_coverage": coverage,
        }
    )
    registry.validate_new(evidence_pack)
    validate_retrieval_evidence_scope(
        query_plan=query_plan,
        retrieval_result=retrieval_result,
        evidence_pack=evidence_pack,
    )
    return RetrievalEvidenceContracts(
        retrieval_result=retrieval_result,
        evidence_pack=evidence_pack,
    )


__all__ = [
    "QualifiedEvidenceInput",
    "RetrievalEvidenceContracts",
    "build_retrieval_evidence_contracts",
    "validate_retrieval_evidence_scope",
]
