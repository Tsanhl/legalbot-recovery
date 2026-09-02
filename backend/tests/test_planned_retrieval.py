from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from app.contracts import ContractSchemaRegistry, build_query_plan, seal_contract
from app.retrieval import retrieval_item_from_query_plan


def _plan(*, knowledge: bool = True):
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    conversation = seal_contract(
        {
            "schema": "legalbot.conversation-snapshot.v1",
            "snapshot_id": "conversation-snapshot-retrieval-plan",
            "conversation_id": "conversation-retrieval-plan",
            "owner_scope_sha256": "6" * 64,
            "revision": 0,
            "created_at": "2026-09-01T00:00:00+00:00",
            "messages": [],
            "truncated": False,
            "omitted_message_count": 0,
            "omitted_before_ordinal": None,
            "truncation_reason": "none",
            "estimated_tokens": 0,
        }
    )
    facts = seal_contract(
        {
            "schema": "legalbot.matter-fact-snapshot.v2",
            "snapshot_id": "fact-snapshot-retrieval-plan",
            "conversation_id": "conversation-retrieval-plan",
            "owner_scope_sha256": "6" * 64,
            "conversation_revision": 0,
            "created_at": "2026-09-01T00:00:00+00:00",
            "facts": [],
        }
    )
    frozen = build_query_plan(
        request_id="request-retrieval-plan",
        request_sha256="1" * 64,
        original_question_sha256="2" * 64,
        task_type="general",
        answer_route="direct",
        requires_knowledge=knowledge,
        requires_matter=not knowledge,
        response_disposition="ANSWER",
        jurisdiction="England and Wales",
        jurisdiction_status="explicit",
        requested_as_of_date=date(2026, 9, 1),
        as_of_date_status="explicit",
        issue_ids=(),
        missing_facts=(),
        query_variants_ref="query-variants-retrieval-plan",
        query_variants_sha256="3" * 64,
        candidate_id="candidate-retrieval-plan" if knowledge else None,
        policy_sha256="4" * 64,
        config_sha256="5" * 64,
        conversation_snapshot=conversation if not knowledge else None,
        fact_snapshot=facts if not knowledge else None,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "standalone",
        },
        risk_flags=(),
        request_observed_at=datetime(2026, 9, 1, tzinfo=UTC),
        frozen_at=datetime(2026, 9, 1, tzinfo=UTC),
        registry=registry,
    )
    return registry, frozen.value


def test_frozen_budgets_drive_hybrid_search_and_rerank_top_k() -> None:
    registry, plan = _plan()
    item = retrieval_item_from_query_plan(
        plan,
        query="consumer refund deadline",
        subject="consumer",
        registry=registry,
    )
    assert item.limit == 12
    assert item.lexical_depth == 80
    assert item.vector_depth == 80
    assert item.reranker_candidates == 32


def test_matter_only_plan_cannot_enter_vector_retrieval() -> None:
    registry, plan = _plan(knowledge=False)
    with pytest.raises(ValueError, match="does not authorize"):
        retrieval_item_from_query_plan(
            plan,
            query="private matter fact",
            subject=None,
            registry=registry,
        )
