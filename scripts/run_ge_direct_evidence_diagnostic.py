"""Run the synthetic direct-evidence isolation diagnostic outside formal scores."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from jsonschema.exceptions import ValidationError

from backend.app.contracts import (
    ClaimContractInput,
    ContractSchemaRegistry,
    QualifiedEvidenceInput,
    build_claim_set,
    build_query_plan,
    build_retrieval_evidence_contracts,
    validate_claim_support_graph,
)
from backend.app.contracts.schema_registry import canonical_json_bytes
from backend.app.types import EvidenceSpan, MaterialLane

ROOT = Path(__file__).resolve().parents[1]
STAMP = datetime(2026, 9, 8, 16, 0, tzinfo=UTC)
DAY = date(2026, 9, 5)


def _sha(value: str | bytes | dict[str, Any]) -> str:
    raw = value if isinstance(value, bytes) else (
        value.encode() if isinstance(value, str) else canonical_json_bytes(value)
    )
    return hashlib.sha256(raw).hexdigest()


def _plan(registry: ContractSchemaRegistry):
    question = "Synthetic Wales notice case for evidence-route isolation."
    return build_query_plan(
        request_id="request-direct-evidence-diagnostic",
        request_sha256=_sha(question),
        original_question_sha256=_sha(question),
        task_type="general",
        answer_route="direct",
        requires_knowledge=True,
        requires_matter=False,
        response_disposition="ANSWER",
        jurisdiction="Wales",
        jurisdiction_status="explicit",
        requested_as_of_date=DAY,
        as_of_date_status="explicit",
        issue_ids=("issue-notice-period",),
        missing_facts=(),
        query_variants_ref="query-variants-direct-evidence-diagnostic",
        query_variants_sha256=_sha("synthetic notice period query"),
        candidate_id="candidate-direct-evidence-diagnostic",
        policy_sha256=_sha("diagnostic relevance policy"),
        config_sha256=_sha("diagnostic configuration"),
        conversation_snapshot=None,
        fact_snapshot=None,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "standalone",
        },
        risk_flags=(),
        request_observed_at=STAMP,
        frozen_at=STAMP,
        registry=registry,
    )


def _direct_span() -> tuple[EvidenceSpan, dict[str, Any]]:
    passage = "A notice must be given at least 30 days before the specified action."
    fixture = {
        "source_identity": "synthetic-official-act-2026",
        "version": "2026-09-05",
        "jurisdiction": "Wales",
        "locator": "synthetic section 4(1)",
        "passage": passage,
        "effective_from": "2026-01-01",
        "effective_to": None,
        "reviewed_as_of": DAY.isoformat(),
        "commencement_status": "commenced",
        "extent_status": "verified_wales",
    }
    fixture["verification_sha256"] = _sha(fixture)
    span = EvidenceSpan(
        id="evidence-synthetic-notice-1",
        source_version_id="source-version-synthetic-notice-2026",
        chunk_id="chunk-synthetic-notice-section-4",
        text=passage,
        locator=fixture["locator"],
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="Wales",
        subject="synthetic-notice-law",
        citation_data={
            "reviewed_as_of": fixture["reviewed_as_of"],
            "effective_from": fixture["effective_from"],
            "effective_to": fixture["effective_to"],
            "commencement_status": fixture["commencement_status"],
        },
        currentness_status="qualified_current",
        content_sha256=_sha(passage),
        index_build_id="candidate-direct-evidence-diagnostic",
        retrieval_relevance_score=1.0,
        retrieval_route="exact_legislation_reference",
        retrieval_threshold=0.5,
        retrieval_threshold_policy_sha256=_sha("diagnostic relevance policy"),
        retrieval_threshold_qualified=True,
        retrieval_qualification_reason="direct_verified_fixture",
        legal_role="synthetic_statutory_rule",
        provision_extent_status=fixture["extent_status"],
        identity_verified=True,
        currentness_verified=True,
    )
    return span, fixture


def build_diagnostic() -> dict[str, Any]:
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    plan = _plan(registry)
    candidate_sha = _sha("same frozen synthetic candidate")
    normal = build_retrieval_evidence_contracts(
        query_plan=plan.value,
        query_plan_sha256=plan.content_sha256,
        candidate_sha256=candidate_sha,
        evidence=(),
        issue_gap_codes={"issue-notice-period": ("no_qualified_evidence",)},
        fact_snapshot_sha256=None,
        created_at=STAMP,
        registry=registry,
    )
    unsupported_rule = ClaimContractInput(
        claim_id="claim-normal-rule",
        kind="legal_rule",
        encrypted_text_ref="synthetic-normal-rule-text",
        text_sha256=_sha("Unsupported synthetic legal rule."),
        materiality_basis="issue_element",
        issue_ids=("issue-notice-period",),
        evidence_ids=(),
    )
    normal_rejection: dict[str, Any]
    try:
        build_claim_set(
            job_id="job-normal-route",
            draft_id="draft-normal-route",
            draft_sha256=_sha("normal route draft"),
            query_plan_sha256=plan.content_sha256,
            fact_snapshot_sha256=None,
            evidence_pack_sha256=normal.evidence_pack["content_sha256"],
            claims=(unsupported_rule,),
            created_at=STAMP,
            registry=registry,
        )
    except (ValueError, ValidationError) as exc:
        normal_rejection = {
            "rejected": True,
            "exception_type": type(exc).__name__,
            "reason": "MATERIAL_LEGAL_RULE_LACKS_SELECTED_EVIDENCE",
        }
    else:  # pragma: no cover - a safety assertion, not an expected branch
        raise RuntimeError("normal route admitted an unsupported material legal rule")

    span, fixture = _direct_span()
    direct = build_retrieval_evidence_contracts(
        query_plan=plan.value,
        query_plan_sha256=plan.content_sha256,
        candidate_sha256=candidate_sha,
        evidence=(
            QualifiedEvidenceInput(
                span=span,
                issue_ids=("issue-notice-period",),
                selected_token_count=15,
                selected_rank=1,
            ),
        ),
        fact_snapshot_sha256=_sha("synthetic fact snapshot"),
        created_at=STAMP,
        registry=registry,
    )
    claims = (
        ClaimContractInput(
            claim_id="claim-direct-rule",
            kind="legal_rule",
            encrypted_text_ref="synthetic-direct-rule-text",
            text_sha256=_sha(fixture["passage"]),
            materiality_basis="issue_element",
            issue_ids=("issue-notice-period",),
            evidence_ids=(span.id,),
        ),
        ClaimContractInput(
            claim_id="claim-direct-fact",
            kind="user_fact",
            encrypted_text_ref="synthetic-direct-fact-text",
            text_sha256=_sha("Notice was given fewer than 30 days before the action."),
            materiality_basis="outcome_premise",
            issue_ids=("issue-notice-period",),
            fact_ids=("fact-notice-timing",),
        ),
        ClaimContractInput(
            claim_id="claim-direct-application",
            kind="application",
            encrypted_text_ref="synthetic-direct-application-text",
            text_sha256=_sha("The synthetic timing requirement is not met."),
            materiality_basis="outcome_premise",
            issue_ids=("issue-notice-period",),
            fact_ids=("fact-notice-timing",),
            evidence_ids=(span.id,),
            depends_on_claim_ids=("claim-direct-rule", "claim-direct-fact"),
        ),
    )
    claim_set = build_claim_set(
        job_id="job-direct-route",
        draft_id="draft-direct-route",
        draft_sha256=_sha("direct route draft"),
        query_plan_sha256=plan.content_sha256,
        fact_snapshot_sha256=_sha("synthetic fact snapshot"),
        evidence_pack_sha256=direct.evidence_pack["content_sha256"],
        claims=claims,
        created_at=STAMP,
        registry=registry,
    )
    validate_claim_support_graph(
        claim_set,
        issue_ids=plan.value["issue_ids"],
        evidence_ids=direct.retrieval_result["selected_evidence_ids"],
        facts=(
            {
                "fact_id": "fact-notice-timing",
                "status": "confirmed",
                "affected_issue_ids": ["issue-notice-period"],
            },
        ),
    )
    return {
        "schema": "legalbot.ge-direct-evidence-diagnostic.v1",
        "created_at": STAMP.isoformat(),
        "classification": "VISIBLE_SYNTHETIC_DIAGNOSTIC",
        "formal_end_to_end_score_included": False,
        "unseen_material_used": False,
        "model_generation_executed": False,
        "training_executed": False,
        "same_frozen_query_plan": True,
        "query_plan_sha256": plan.content_sha256,
        "candidate_sha256": candidate_sha,
        "normal_route": {
            "selected_evidence_ids": normal.retrieval_result["selected_evidence_ids"],
            "issue_coverage": normal.evidence_pack["issue_coverage"],
            "claim_gate": normal_rejection,
        },
        "direct_evidence_route": {
            "verification_kind": "SYNTHETIC_FIXTURE_EXACT_HASH_AND_SCOPE_VERIFICATION",
            "fixture": fixture,
            "selected_evidence_ids": direct.retrieval_result["selected_evidence_ids"],
            "issue_coverage": direct.evidence_pack["issue_coverage"],
            "claim_set_sha256": claim_set["content_sha256"],
            "claim_support_graph_valid": True,
        },
        "diagnosis": {
            "isolated_component": "RETRIEVAL_OR_EVIDENCE_QUALIFICATION",
            "answer_model_diagnosed": False,
            "result": "DIRECT_VERIFIED_EVIDENCE_CLOSES_THE_SYNTHETIC_ROUTE_WHILE_EMPTY_RETRIEVAL_FAILS_CLOSED",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("diagnostic output must be a new file inside the workspace")
    value = build_diagnostic()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(value) + b"\n")
    print(json.dumps({"output": str(output), "sha256": _sha(output.read_bytes())}, sort_keys=True))


if __name__ == "__main__":
    main()
