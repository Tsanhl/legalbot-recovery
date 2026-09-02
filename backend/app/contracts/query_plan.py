"""Deterministic QueryPlan v2 construction and retrieval-intent routing."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Literal

from .schema_registry import ContractSchemaRegistry, canonical_json_bytes

DataIntent = Literal["NO_RETRIEVAL", "KNOWLEDGE_ONLY", "MATTER_ONLY", "HYBRID"]
ResponseDisposition = Literal[
    "ANSWER",
    "CLARIFY",
    "LIMITED",
    "REFUSE_UNSAFE",
    "URGENT_NEXT_STEP",
    "OUT_OF_SCOPE",
    "SYSTEM_HOLD",
]
AnswerRoute = Literal["direct", "sectioned", "full_enquiry"]
TaskKind = Literal["general", "problem", "essay"]


@dataclass(frozen=True, slots=True)
class QueryBudgets:
    lexical_depth: int = 80
    vector_depth: int = 80
    reranker_candidates: int = 32
    final_top_k: int = 12
    context_tokens: int = 12_000
    initial_clarification_questions: int = 3

    def as_contract(self) -> dict[str, int]:
        return {
            "lexical_depth": self.lexical_depth,
            "vector_depth": self.vector_depth,
            "reranker_candidates": self.reranker_candidates,
            "final_top_k": self.final_top_k,
            "context_tokens": self.context_tokens,
            "initial_clarification_questions": self.initial_clarification_questions,
        }


@dataclass(frozen=True, slots=True)
class FrozenQueryPlan:
    value: Mapping[str, Any]
    content_sha256: str


def _intent(*, knowledge: bool, matter: bool, disposition: ResponseDisposition) -> DataIntent:
    if disposition == "SYSTEM_HOLD":
        return "NO_RETRIEVAL"
    if knowledge and matter:
        return "HYBRID"
    if knowledge:
        return "KNOWLEDGE_ONLY"
    if matter:
        return "MATTER_ONLY"
    return "NO_RETRIEVAL"


def build_query_plan(
    *,
    request_id: str,
    request_sha256: str,
    original_question_sha256: str,
    task_type: TaskKind,
    answer_route: AnswerRoute,
    requires_knowledge: bool,
    requires_matter: bool,
    response_disposition: ResponseDisposition,
    jurisdiction: str | None,
    jurisdiction_status: Literal["explicit", "derived_for_clarification", "unresolved"],
    requested_as_of_date: date | None,
    as_of_date_status: Literal["explicit", "service_default", "unresolved"],
    issue_ids: Sequence[str],
    missing_facts: Sequence[Mapping[str, Any]],
    query_variants_ref: str,
    query_variants_sha256: str,
    candidate_id: str | None,
    policy_sha256: str,
    config_sha256: str,
    conversation_snapshot: Mapping[str, Any] | None,
    fact_snapshot: Mapping[str, Any] | None,
    rewrite: Mapping[str, Any],
    risk_flags: Sequence[str],
    request_observed_at: datetime,
    frozen_at: datetime,
    registry: ContractSchemaRegistry,
    budgets: QueryBudgets | None = None,
) -> FrozenQueryPlan:
    """Freeze the retrieval/matter routing decision before either lookup starts."""

    data_intent = _intent(
        knowledge=requires_knowledge,
        matter=requires_matter,
        disposition=response_disposition,
    )
    if response_disposition == "ANSWER" and data_intent == "NO_RETRIEVAL":
        raise ValueError("an answer must have a knowledge or matter retrieval intent")
    if requires_matter and fact_snapshot is None:
        raise ValueError("matter lookup requires a frozen fact snapshot")
    if fact_snapshot is not None and conversation_snapshot is None:
        raise ValueError("a fact snapshot requires the matching conversation snapshot")
    if fact_snapshot is not None and conversation_snapshot is not None:
        if fact_snapshot.get("conversation_id") != conversation_snapshot.get("conversation_id"):
            raise ValueError("fact and conversation snapshot identity differs")
        if fact_snapshot.get("conversation_revision") != conversation_snapshot.get("revision"):
            raise ValueError("fact and conversation snapshot revision differs")
        if fact_snapshot.get("owner_scope_sha256") != conversation_snapshot.get(
            "owner_scope_sha256"
        ):
            raise ValueError("fact and conversation owner scope differs")
    if candidate_id is None:
        if requires_knowledge:
            raise ValueError("knowledge retrieval requires a bound candidate")
        candidate_id = "candidate-no-knowledge-retrieval"
    selected_budgets = budgets or QueryBudgets()
    if requires_knowledge and (
        selected_budgets.lexical_depth < 1
        or selected_budgets.vector_depth < 1
        or selected_budgets.reranker_candidates < selected_budgets.final_top_k
        or selected_budgets.reranker_candidates > 32
        or selected_budgets.final_top_k < 1
    ):
        raise ValueError("hybrid retrieval budgets are inconsistent")
    required_capabilities = ["contracts.selected"]
    if data_intent in {"KNOWLEDGE_ONLY", "HYBRID"}:
        required_capabilities.extend(
            ("candidate.bound", "retrieval.hybrid", "reranker.cross_encoder")
        )
    if data_intent in {"MATTER_ONLY", "HYBRID"}:
        required_capabilities.append("matter.lookup")
    if rewrite.get("status") == "accepted":
        required_capabilities.append("conversation.rewrite")

    observed = request_observed_at
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    frozen = frozen_at
    if frozen.tzinfo is None:
        frozen = frozen.replace(tzinfo=UTC)
    conversation_ref = {
        "conversation_id": None,
        "revision": 0,
        "content_sha256": None,
        "truncated": False,
        "omitted_message_count": 0,
    }
    fact_snapshot_id: str | None = None
    if conversation_snapshot is not None:
        conversation_ref = {
            "conversation_id": conversation_snapshot["conversation_id"],
            "revision": conversation_snapshot["revision"],
            "content_sha256": conversation_snapshot["content_sha256"],
            "truncated": conversation_snapshot["truncated"],
            "omitted_message_count": conversation_snapshot["omitted_message_count"],
        }
    if fact_snapshot is not None:
        fact_snapshot_id = str(fact_snapshot["snapshot_id"])
    identity_material = {
        "schema": "legalbot.query-plan-identity.v2",
        "request_id": request_id,
        "request_sha256": request_sha256,
        "data_intent": data_intent,
        "candidate_id": candidate_id,
        "conversation_snapshot": conversation_ref,
        "fact_snapshot_id": fact_snapshot_id,
        "policy_sha256": policy_sha256,
        "config_sha256": config_sha256,
        "frozen_at": frozen.astimezone(UTC).isoformat(),
    }
    identity = hashlib.sha256(canonical_json_bytes(identity_material)).hexdigest()
    value = {
        "schema": "legalbot.query-plan.v2",
        "query_plan_id": f"query-plan-{identity[:40]}",
        "request_id": request_id,
        "request_sha256": request_sha256,
        "original_question_sha256": original_question_sha256,
        "task_type": task_type,
        "data_intent": data_intent,
        "answer_route": answer_route,
        "jurisdiction_status": jurisdiction_status,
        "jurisdiction": jurisdiction,
        "requested_as_of_date": (
            requested_as_of_date.isoformat() if requested_as_of_date is not None else None
        ),
        "issue_ids": list(dict.fromkeys(issue_ids)),
        "missing_facts": [dict(item) for item in missing_facts],
        "allowed_authority_lanes": [
            "primary_authority",
            "official_secondary",
            "scholarship",
        ],
        "query_variants_ref": query_variants_ref,
        "query_variants_sha256": query_variants_sha256,
        "budgets": selected_budgets.as_contract(),
        "conversation_snapshot": conversation_ref,
        "fact_snapshot_id": fact_snapshot_id,
        "candidate_id": candidate_id,
        "policy_sha256": policy_sha256,
        "config_sha256": config_sha256,
        "rewrite": dict(rewrite),
        "frozen_at": frozen.astimezone(UTC).isoformat(),
        "contract_pack_id": "legalbot-phase2-contract-pack-v1",
        "response_disposition": response_disposition,
        "risk_flags": list(dict.fromkeys(risk_flags)),
        "required_capabilities": list(dict.fromkeys(required_capabilities)),
        "request_observed_at": observed.astimezone(UTC).isoformat(),
        "as_of_date_status": as_of_date_status,
        "schema_selection_sha256": registry.manifest_sha256,
    }
    registry.validate_new(value)
    digest = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
    return FrozenQueryPlan(value=value, content_sha256=digest)


__all__ = [
    "AnswerRoute",
    "DataIntent",
    "FrozenQueryPlan",
    "QueryBudgets",
    "ResponseDisposition",
    "TaskKind",
    "build_query_plan",
]
