from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from app.contracts import (
    ContractSchemaRegistry,
    QualifiedEvidenceInput,
    build_query_plan,
    build_retrieval_evidence_contracts,
)
from app.types import EvidenceSpan, MaterialLane


def _registry() -> ContractSchemaRegistry:
    return ContractSchemaRegistry.from_project_root(Path.cwd())


def _plan():
    return build_query_plan(
        request_id="request-evidence-contract",
        request_sha256="1" * 64,
        original_question_sha256="2" * 64,
        task_type="general",
        answer_route="direct",
        requires_knowledge=True,
        requires_matter=False,
        response_disposition="ANSWER",
        jurisdiction="England and Wales",
        jurisdiction_status="explicit",
        requested_as_of_date=date(2026, 9, 1),
        as_of_date_status="explicit",
        issue_ids=("issue-refund",),
        missing_facts=(),
        query_variants_ref="query-variants-evidence-contract",
        query_variants_sha256="3" * 64,
        candidate_id="candidate-evidence-contract",
        policy_sha256="4" * 64,
        config_sha256="5" * 64,
        conversation_snapshot=None,
        fact_snapshot=None,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "standalone",
        },
        risk_flags=(),
        request_observed_at=datetime(2026, 9, 1, tzinfo=UTC),
        frozen_at=datetime(2026, 9, 1, tzinfo=UTC),
        registry=_registry(),
    )


def _span(*, qualified: bool = True, lane=MaterialLane.PRIMARY_AUTHORITY) -> EvidenceSpan:
    return EvidenceSpan(
        id="evidence-refund-1",
        source_version_id="source-version-refund-1",
        chunk_id="chunk-refund-1",
        text="Private retrieved legal text must not enter the contract.",
        locator="section 20",
        lane=lane,
        jurisdiction="England and Wales",
        subject="consumer",
        citation_data={"reviewed_as_of": "2026-09-01"},
        currentness_status="current",
        content_sha256="6" * 64,
        index_build_id="candidate-evidence-contract",
        retrieval_relevance_score=0.92,
        retrieval_route="hybrid_rrf",
        retrieval_threshold=0.5,
        retrieval_threshold_policy_sha256="7" * 64,
        retrieval_threshold_qualified=qualified,
        retrieval_qualification_reason="threshold_qualified",
        legal_role="statutory_rule",
        provision_extent_status="verified",
        identity_verified=qualified,
        currentness_verified=qualified,
    )


def test_result_and_pack_bind_qualified_evidence_without_plaintext() -> None:
    plan = _plan()
    contracts = build_retrieval_evidence_contracts(
        query_plan=plan.value,
        query_plan_sha256=plan.content_sha256,
        candidate_sha256="8" * 64,
        evidence=(
            QualifiedEvidenceInput(
                span=_span(),
                issue_ids=("issue-refund",),
                selected_token_count=120,
                selected_rank=1,
            ),
        ),
        fact_snapshot_sha256=None,
        created_at=datetime(2026, 9, 1, tzinfo=UTC),
        registry=_registry(),
    )

    _registry().validate_new(contracts.retrieval_result)
    _registry().validate_new(contracts.evidence_pack)
    assert contracts.retrieval_result["selected_evidence_ids"] == ["evidence-refund-1"]
    assert contracts.evidence_pack["issue_coverage"][0]["status"] == "satisfied"
    assert "Private retrieved legal text" not in str(contracts.retrieval_result)
    assert "Private retrieved legal text" not in str(contracts.evidence_pack)


def test_unqualified_or_teaching_evidence_cannot_enter_pack() -> None:
    plan = _plan()
    common = {
        "query_plan": plan.value,
        "query_plan_sha256": plan.content_sha256,
        "candidate_sha256": "8" * 64,
        "fact_snapshot_sha256": None,
        "created_at": datetime(2026, 9, 1, tzinfo=UTC),
        "registry": _registry(),
    }
    with pytest.raises(ValueError, match="not fully qualified"):
        build_retrieval_evidence_contracts(
            **common,
            evidence=(
                QualifiedEvidenceInput(
                    span=_span(qualified=False),
                    issue_ids=("issue-refund",),
                    selected_token_count=100,
                    selected_rank=1,
                ),
            ),
        )
    with pytest.raises(ValueError, match="lane"):
        build_retrieval_evidence_contracts(
            **common,
            evidence=(
                QualifiedEvidenceInput(
                    span=_span(lane=MaterialLane.PRIVATE_TEACHING),
                    issue_ids=("issue-refund",),
                    selected_token_count=100,
                    selected_rank=1,
                ),
            ),
        )
