from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from app.contracts import ContractSchemaRegistry, QueryBudgets, build_query_plan, seal_contract


def _registry() -> ContractSchemaRegistry:
    return ContractSchemaRegistry.from_project_root(Path.cwd())


def _conversation() -> dict[str, object]:
    return seal_contract(
        {
            "schema": "legalbot.conversation-snapshot.v1",
            "snapshot_id": "conversation-snapshot-test",
            "conversation_id": "conversation-test",
            "owner_scope_sha256": "1" * 64,
            "revision": 2,
            "created_at": "2026-09-01T00:00:00+00:00",
            "messages": [],
            "truncated": False,
            "omitted_message_count": 0,
            "omitted_before_ordinal": None,
            "truncation_reason": "none",
            "estimated_tokens": 0,
        }
    )


def _facts() -> dict[str, object]:
    return seal_contract(
        {
            "schema": "legalbot.matter-fact-snapshot.v2",
            "snapshot_id": "fact-snapshot-test",
            "conversation_id": "conversation-test",
            "owner_scope_sha256": "1" * 64,
            "conversation_revision": 2,
            "created_at": "2026-09-01T00:00:00+00:00",
            "facts": [],
        }
    )


def _build(**updates):
    values = {
        "request_id": "request-test",
        "request_sha256": "2" * 64,
        "original_question_sha256": "3" * 64,
        "task_type": "general",
        "answer_route": "direct",
        "requires_knowledge": True,
        "requires_matter": True,
        "response_disposition": "ANSWER",
        "jurisdiction": "England and Wales",
        "jurisdiction_status": "explicit",
        "requested_as_of_date": date(2026, 9, 1),
        "as_of_date_status": "explicit",
        "issue_ids": ("issue-test",),
        "missing_facts": (),
        "query_variants_ref": "query-variants-test",
        "query_variants_sha256": "4" * 64,
        "candidate_id": "candidate-test",
        "policy_sha256": "5" * 64,
        "config_sha256": "6" * 64,
        "conversation_snapshot": _conversation(),
        "fact_snapshot": _facts(),
        "rewrite": {
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "standalone",
        },
        "risk_flags": (),
        "request_observed_at": datetime(2026, 9, 1, tzinfo=UTC),
        "frozen_at": datetime(2026, 9, 1, tzinfo=UTC),
        "registry": _registry(),
    }
    values.update(updates)
    return build_query_plan(**values)


def test_hybrid_plan_binds_both_snapshots_and_required_capabilities() -> None:
    frozen = _build()
    assert frozen.value["data_intent"] == "HYBRID"
    assert frozen.value["fact_snapshot_id"] == "fact-snapshot-test"
    assert set(frozen.value["required_capabilities"]) == {
        "contracts.selected",
        "candidate.bound",
        "retrieval.hybrid",
        "reranker.cross_encoder",
        "matter.lookup",
    }
    assert len(frozen.content_sha256) == 64
    _registry().validate_new(frozen.value)


def test_knowledge_answer_requires_candidate_and_consistent_budgets() -> None:
    with pytest.raises(ValueError, match="candidate"):
        _build(requires_matter=False, fact_snapshot=None, candidate_id=None)
    with pytest.raises(ValueError, match="budgets"):
        _build(
            requires_matter=False,
            fact_snapshot=None,
            budgets=QueryBudgets(reranker_candidates=4, final_top_k=8),
        )


def test_matter_plan_rejects_cross_conversation_snapshot() -> None:
    facts = _facts()
    facts["conversation_id"] = "conversation-other"
    facts = seal_contract(facts)
    with pytest.raises(ValueError, match="identity"):
        _build(fact_snapshot=facts)


def test_system_hold_forces_no_retrieval() -> None:
    frozen = _build(
        requires_knowledge=True,
        requires_matter=True,
        response_disposition="SYSTEM_HOLD",
    )
    assert frozen.value["data_intent"] == "NO_RETRIEVAL"
