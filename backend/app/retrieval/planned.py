"""Adapter from a frozen QueryPlan v2 to the existing hybrid retrieval runtime."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Any

from ..contracts import ContractSchemaRegistry
from .models import RetrievalPlanItem


def retrieval_item_from_query_plan(
    plan: Mapping[str, Any],
    *,
    query: str,
    subject: str | None,
    registry: ContractSchemaRegistry,
    cacheable: bool = True,
) -> RetrievalPlanItem:
    """Return one exact-budget hybrid item or reject a non-knowledge intent."""

    registry.validate_new(plan)
    if plan.get("data_intent") not in {"KNOWLEDGE_ONLY", "HYBRID"}:
        raise ValueError("query plan does not authorize knowledge retrieval")
    if not query.strip():
        raise ValueError("retrieval query cannot be blank")
    jurisdiction = plan.get("jurisdiction")
    requested_as_of_date = plan.get("requested_as_of_date")
    if not isinstance(jurisdiction, str) or not jurisdiction.strip():
        raise ValueError("knowledge retrieval requires a resolved jurisdiction")
    if not isinstance(requested_as_of_date, str):
        raise ValueError("knowledge retrieval requires a resolved as-of date")
    budgets = plan["budgets"]
    rewrite = plan["rewrite"]
    return RetrievalPlanItem(
        query=query,
        jurisdiction=jurisdiction,
        subject=subject,
        as_of_date=date.fromisoformat(requested_as_of_date),
        limit=int(budgets["final_top_k"]),
        cacheable=cacheable,
        query_rewrite_version=f"query-plan-v2:{rewrite['status']}",
        lexical_depth=int(budgets["lexical_depth"]),
        vector_depth=int(budgets["vector_depth"]),
        reranker_candidates=int(budgets["reranker_candidates"]),
    )


__all__ = ["retrieval_item_from_query_plan"]
