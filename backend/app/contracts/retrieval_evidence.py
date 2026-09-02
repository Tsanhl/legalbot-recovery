"""Selected RetrievalResult and EvidencePack contracts without plaintext evidence."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

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
_ROUTES = {"exact_authority_identity", "exact_legislation_reference", "hybrid_rrf"}


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
    value = str(span.currentness_status).casefold()
    if any(token in value for token in ("historical", "as_enacted", "repealed")):
        return "qualified_historical"
    return "qualified_current"


def _qualification_receipt(span: EvidenceSpan, *, issue_ids: Sequence[str]) -> str:
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
    material = {
        "schema": "legalbot.evidence-qualification-receipt.v1",
        "evidence_id": span.id,
        "source_version_id": span.source_version_id,
        "chunk_id": span.chunk_id,
        "content_sha256": span.content_sha256,
        "jurisdiction": span.jurisdiction,
        "lane": lane,
        "currentness_status": _currentness(span),
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
    citation = span.citation_data
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
        "effective_from": citation.get("effective_from"),
        "effective_to": citation.get("effective_to"),
        "reviewed_as_of": (
            citation.get("reviewed_as_of")
            or (requested_as_of_date.isoformat() if requested_as_of_date is not None else None)
        ),
        "extent_status": span.provision_extent_status,
        "commencement_status": str(citation.get("commencement_status") or "not_applicable"),
        "qualification_receipt_sha256": _qualification_receipt(span, issue_ids=item.issue_ids),
        "retrieval_route": span.retrieval_route,
        "retrieval_score": span.retrieval_relevance_score,
        "selection_reason": span.retrieval_qualification_reason or "threshold_qualified",
        "score_system": "hybrid_rrf_reranker_v1",
    }


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
        if item.selected_token_count < 0:
            raise ValueError("selected evidence token count cannot be negative")
        _qualification_receipt(item.span, issue_ids=item.issue_ids)

    gaps_by_issue = {
        issue_id: tuple(dict.fromkeys(codes)) for issue_id, codes in (issue_gap_codes or {}).items()
    }
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
        receipt = _qualification_receipt(span, issue_ids=item.issue_ids)
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
            requested_as_of_date=(
                date.fromisoformat(query_plan["requested_as_of_date"])
                if query_plan["requested_as_of_date"] is not None
                else None
            ),
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
    return RetrievalEvidenceContracts(
        retrieval_result=retrieval_result,
        evidence_pack=evidence_pack,
    )


__all__ = [
    "QualifiedEvidenceInput",
    "RetrievalEvidenceContracts",
    "build_retrieval_evidence_contracts",
]
