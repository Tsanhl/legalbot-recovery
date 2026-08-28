"""Stage A v2 scores only issues with positive verified gold.

Knowledge-gap and unreviewed issues are counted separately. Recall@5 is never
fabricated for a knowledge gap. A caller cannot mint a passing Stage A record
by injecting Recall/MRR numbers. Metrics for authorization must be derived
from candidate-pinned retrieval rankings.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_overlay_complete import POSITIVE_SPAN_DISPOSITIONS

STAGE_A_V2_SCHEMA = "legalbot.live60-stage-a-v2.v1"
POSITIVE_GOLD_STATUSES = frozenset({"qualified", "limited"})


def ranking_evaluable_v2(status: str | None) -> bool:
    return status in POSITIVE_GOLD_STATUSES


def _sha256_mapping(value: Mapping[str, Any]) -> str:
    encoded = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def compute_ranking_metrics(
    rankings: Sequence[Mapping[str, Any]],
) -> dict[str, float | int | None]:
    """Derive Recall@5/10, MRR, nDCG and exact-span recall from ranked hits."""

    if not rankings:
        return {
            "recall_at_5": None,
            "recall_at_10": None,
            "mrr": None,
            "ndcg": None,
            "exact_span_recall": None,
            "filter_violation_count": 0,
            "scored_issue_count": 0,
        }
    hits_at_5 = 0
    hits_at_10 = 0
    reciprocal = 0.0
    ndcg_sum = 0.0
    gold_total = 0
    gold_retrieved = 0
    filter_violations = 0
    scored = 0
    for item in rankings:
        gold_ids = [str(value) for value in (item.get("gold_span_ids") or ()) if value]
        ranked_ids = [str(value) for value in (item.get("ranked_chunk_ids") or ())]
        if not gold_ids:
            continue
        scored += 1
        gold_total += len(gold_ids)
        gold_set = set(gold_ids)
        gold_retrieved += len(gold_set.intersection(ranked_ids))
        filter_violations += int(item.get("filter_violation_count") or 0)
        ranks = [index + 1 for index, chunk_id in enumerate(ranked_ids) if chunk_id in gold_set]
        if any(rank <= 5 for rank in ranks):
            hits_at_5 += 1
        if any(rank <= 10 for rank in ranks):
            hits_at_10 += 1
        if ranks:
            reciprocal += 1.0 / min(ranks)
            dcg = sum(1.0 / math.log2(rank + 1) for rank in ranks)
            ideal = sum(1.0 / math.log2(index + 2) for index in range(len(gold_ids)))
            ndcg_sum += (dcg / ideal) if ideal else 0.0
    return {
        "recall_at_5": round(hits_at_5 / scored, 8) if scored else None,
        "recall_at_10": round(hits_at_10 / scored, 8) if scored else None,
        "mrr": round(reciprocal / scored, 8) if scored else None,
        "ndcg": round(ndcg_sum / scored, 8) if scored else None,
        "exact_span_recall": round(gold_retrieved / gold_total, 8) if gold_total else None,
        "filter_violation_count": filter_violations,
        "scored_issue_count": scored,
    }


def score_stage_a_v2(
    *,
    issues: Sequence[Mapping[str, Any]],
    unreviewed_issue_count: int,
    recall_at_5: float | None = None,
    recall_at_10: float | None = None,
    mrr: float | None = None,
    filter_violation_count: int = 0,
    candidate_build_id: str,
    rankings: Sequence[Mapping[str, Any]] | None = None,
    ndcg: float | None = None,
    exact_span_recall: float | None = None,
) -> dict[str, Any]:
    """Score ranking metrics. Caller-injected numbers cannot mint a passing seal."""

    from ..retrieval.diagnostic_slice import refuse_diagnostic_slice_for_production

    refuse_diagnostic_slice_for_production(candidate_build_id, purpose="production Stage A")
    scored = [
        item
        for item in issues
        if ranking_evaluable_v2(str(item.get("status") or item.get("disposition") or ""))
    ]
    gaps = [
        item
        for item in issues
        if str(item.get("status") or item.get("disposition") or "") == "knowledge_gap"
    ]
    limited = [
        item
        for item in issues
        if str(item.get("status") or item.get("disposition") or "") == "limited"
    ]
    qualified = [
        item
        for item in issues
        if str(item.get("status") or item.get("disposition") or "") == "qualified"
    ]
    review_complete = unreviewed_issue_count == 0
    fabricated_gap_recall = False
    metrics_source = "caller_injected"
    authorization_eligible = False
    if rankings is not None:
        derived = compute_ranking_metrics(rankings)
        recall_at_5 = derived["recall_at_5"]
        recall_at_10 = derived["recall_at_10"]
        mrr = derived["mrr"]
        ndcg = derived["ndcg"]
        exact_span_recall = derived["exact_span_recall"]
        filter_violation_count = int(derived["filter_violation_count"] or 0)
        metrics_source = "derived_rankings"
    if not scored:
        recall_at_5 = None
        recall_at_10 = None
        mrr = None
        ndcg = None
        exact_span_recall = None
    passed = bool(
        review_complete
        and scored
        and rankings is not None
        and recall_at_5 == 1.0
        and recall_at_10 is not None
        and recall_at_10 >= 0.95
        and mrr is not None
        and mrr >= 0.8
        and filter_violation_count == 0
    )
    authorization_eligible = passed
    payload = {
        "schema": STAGE_A_V2_SCHEMA,
        "candidate_build_id": candidate_build_id,
        "review_complete": review_complete,
        "unreviewed_issue_count": unreviewed_issue_count,
        "scored_issue_count": len(scored),
        "selected_qualified_issue_count": len(qualified),
        "selected_limited_issue_count": len(limited),
        "selected_knowledge_gap_count": len(gaps),
        "recall_at_5": recall_at_5,
        "recall_at_10": recall_at_10,
        "mrr": mrr,
        "ndcg": ndcg,
        "exact_span_recall": exact_span_recall,
        "filter_violation_count": filter_violation_count,
        "stage_a_passed": passed,
        "authorization_eligible": authorization_eligible,
        "metrics_source": metrics_source,
        "fabricated_gap_recall": fabricated_gap_recall,
        "requires_305_positive_spans": False,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload


async def evaluate_stage_a_from_retrieval(
    *,
    retriever: Any,
    issues: Sequence[Mapping[str, Any]],
    candidate_build_id: str,
    unreviewed_issue_count: int,
    as_of_date: date,
    jurisdiction: str = "England and Wales",
) -> dict[str, Any]:
    """Run candidate-pinned retrieval and derive Stage A from rankings."""

    rankings: list[dict[str, Any]] = []
    for issue in issues:
        status = str(issue.get("status") or issue.get("disposition") or "")
        if status not in POSITIVE_SPAN_DISPOSITIONS:
            continue
        gold_ids = []
        for span in issue.get("exact_gold_spans") or issue.get("verified_positive_spans") or ():
            chunk_id = span.get("chunk_id") if isinstance(span, Mapping) else None
            if chunk_id:
                gold_ids.append(str(chunk_id))
        query = str(issue.get("topic") or issue.get("proposition") or issue.get("issue_id") or "")
        evidence = list(
            await retriever.retrieve(
                query=query,
                jurisdiction=str(issue.get("jurisdiction") or jurisdiction),
                subject=issue.get("subject"),
                as_of_date=as_of_date,
                limit=10,
            )
        )
        ranked_ids = [
            str(getattr(item, "chunk_id", "") or item.get("chunk_id")) for item in evidence
        ]
        rankings.append(
            {
                "issue_id": issue.get("issue_id"),
                "gold_span_ids": gold_ids,
                "ranked_chunk_ids": ranked_ids,
                "filter_violation_count": 0,
            }
        )
    return score_stage_a_v2(
        issues=issues,
        unreviewed_issue_count=unreviewed_issue_count,
        candidate_build_id=candidate_build_id,
        rankings=rankings,
    )
