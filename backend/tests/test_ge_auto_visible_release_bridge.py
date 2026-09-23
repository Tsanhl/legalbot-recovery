"""Synthetic selected-contract bridge tests; no model, source IO or publication."""
from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from backend.app.contracts.retrieval_evidence import (
    QualifiedEvidenceInput,
    build_retrieval_evidence_contracts,
)
from backend.app.contracts.schema_registry import ContractSchemaRegistry, canonical_json_bytes
from backend.app.types import EvidenceSpan, MaterialLane
from backend.tests import test_ge_auto_case_contracts as case_fixtures
from jsonschema.exceptions import ValidationError
from scripts import ge_auto_case_driver as driver
from scripts import ge_auto_visible_answer_review as review
from scripts import ge_auto_visible_release_bridge as bridge

ROOT = Path(__file__).resolve().parents[2]
STAMP = datetime(2026, 9, 5, 12, tzinfo=UTC)
ANSWER = "Because you report paying 10 units, synthetic Rule 1 may apply."
LAW = "Synthetic Rule 1: a person who pays 10 units may request remedy R."


class Vault:
    def __call__(self, raw, provenance):
        text_hash = hashlib.sha256(raw).hexdigest()
        cipher_hash = hashlib.sha256(b"cipher:" + raw).hexdigest()
        return {"encrypted_ref": "encrypted-" + cipher_hash[:40],
                "plaintext_sha256": text_hash, "ciphertext_sha256": cipher_hash,
                "receipt_sha256": hashlib.sha256(canonical_json_bytes(provenance)).hexdigest()}


def bundle():
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    request = case_fixtures.request()
    case_contracts = case_fixtures.c.build_case_contracts(
        **case_fixtures.arguments(registry, req=request))
    binding = case_contracts.binding
    evidence_id = "evidence-synthetic"
    span = EvidenceSpan(id=evidence_id, source_version_id="source-version-synthetic",
        chunk_id="chunk-synthetic", text=LAW, locator="Synthetic Rule 1",
        lane=MaterialLane.PRIMARY_AUTHORITY, jurisdiction="England",
        subject="synthetic", citation_data={"reviewed_as_of": "2026-09-05",
            "effective_from": "2026-01-01", "effective_to": "2026-12-31",
            "commencement_status": "verified_for_requested_date"},
        currentness_status="qualified_current", content_sha256=hashlib.sha256(LAW.encode()).hexdigest(),
        index_build_id="synthetic-build", retrieval_relevance_score=1.0,
        retrieval_route="hybrid_rrf", retrieval_threshold=0.5,
        retrieval_threshold_policy_sha256="a" * 64,
        retrieval_threshold_qualified=True,
        retrieval_qualification_reason="required_reviewed_context_retrieved",
        legal_role="statutory_rule", provision_extent_status="verified_for_requested_jurisdiction",
        identity_verified=True, currentness_verified=True)
    selected = build_retrieval_evidence_contracts(query_plan=binding.query_plan,
        query_plan_sha256=hashlib.sha256(canonical_json_bytes(binding.query_plan)).hexdigest(),
        candidate_sha256="b" * 64,
        evidence=(QualifiedEvidenceInput(span=span,
            issue_ids=tuple(binding.query_plan["issue_ids"]), selected_token_count=20,
            selected_rank=1),),
        fact_snapshot_sha256=binding.fact_snapshot["content_sha256"],
        created_at=STAMP, registry=registry)
    fact_projection = driver.build_fact_projection(case_id=request["case_id"], turn=1,
        requests=[request], fact_snapshot=binding.fact_snapshot,
        query_plan=binding.query_plan)
    fact_id = fact_projection["facts"][0]["fact_id"]
    issue_id = binding.query_plan["issue_ids"][0]
    answer_span = {"start": 0, "end": len(ANSWER), "text": ANSWER}
    fact_text = fact_projection["facts"][0]["text"]
    fact_excerpt = "I paid 10 units."
    fact_start = fact_text.index(fact_excerpt)
    output = {"claims": [
        {"claim_id": "claim-rule", "claim_sha256": hashlib.sha256(ANSWER.encode()).hexdigest(),
         "answer_span": answer_span, "material": True, "kind": "LEGAL", "status": "SUPPORTED",
         "requirement_ids": [issue_id], "depends_on_claim_ids": [],
         "evidence_spans": [{"source_id": "source-synthetic", "block_id": "block-synthetic",
             "start": 0, "end": len(LAW), "text": LAW}], "fact_spans": [], "explanation": "supported"},
        {"claim_id": "claim-fact", "claim_sha256": hashlib.sha256(ANSWER.encode()).hexdigest(),
         "answer_span": answer_span, "material": True, "kind": "FACT", "status": "SUPPORTED",
         "requirement_ids": [issue_id], "depends_on_claim_ids": [], "evidence_spans": [],
         "fact_spans": [{"fact_id": fact_id, "start": fact_start,
             "end": fact_start + len(fact_excerpt), "text": fact_excerpt}], "explanation": "stated"},
        {"claim_id": "claim-application", "claim_sha256": hashlib.sha256(ANSWER.encode()).hexdigest(),
         "answer_span": answer_span, "material": True, "kind": "APPLICATION", "status": "SUPPORTED",
         "requirement_ids": [issue_id], "depends_on_claim_ids": ["claim-rule", "claim-fact"],
         "evidence_spans": [], "fact_spans": [], "explanation": "depends on rule and fact"},
    ], "factual_checks": {key: {"status": "PASS", "reason": "synthetic pass"}
                          for key in review.FACTUAL_CHECKS}}
    output_sha = review.sha256(review.canonical(output))
    finalized = {"review_acceptance": "ACCEPTED_PARENT_VERIFIED_AI_REVIEW",
        "full_answer_pass": True, "professional_legal_sign_off": False,
        "reviewed_claim_set_sha256": review.sha256(review.canonical(output["claims"])),
        "review_output_sha256": output_sha, "review_schema_sha256": "c" * 64,
        "bindings": {"packet_sha256": "d" * 64}}
    terminal = {"case_id": request["case_id"], "turn": 1,
        "answer": {"status": "ANSWER", "answer": ANSWER, "cited_proposition_ids": ["p1"]},
        "rendered_answer": ANSWER,
        "rendered_answer_sha256": hashlib.sha256(ANSWER.encode()).hexdigest()}
    material = {"candidate": terminal["answer"], "terminal": terminal,
        "fact_projection": fact_projection,
        "evidence": {"case_id": request["case_id"], "source_references": [],
            "sources": [{"source_id": "source-synthetic", "selected_evidence_id": evidence_id,
                "blocks": [{"block_id": "block-synthetic", "text": LAW}]}]},
        "source_review": {"case_id": request["case_id"]},
        "requirements": [{"requirement_id": issue_id, "text": "Synthetic issue"}],
        "candidate_receipt": {"synthetic": True},
        "selected_contracts": {"conversation_snapshot": binding.conversation_snapshot,
            "fact_snapshot": binding.fact_snapshot, "query_plan": binding.query_plan,
            "retrieval_result": selected.retrieval_result,
            "evidence_pack": selected.evidence_pack}}
    return registry, output, finalized, material


def build(registry, output, finalized, material, *, verify=True):
    return bridge.build_selected_release_contracts(review_output=output,
        finalized_review=finalized, review_material=material, created_at=STAMP,
        model_sha256="1" * 64, prompt_sha256="2" * 64,
        renderer_sha256="3" * 64, policy_bundle_sha256="4" * 64,
        registry=registry, encrypt_store=Vault(),
        host_verify=lambda action, binding: verify and action == "visible_selected_release")


def test_reviewed_visible_answer_populates_and_closes_existing_contract_chain():
    result = build(*bundle())
    assert result["status"] == "SELECTED_RELEASE_CHECKS_PASS"
    assert result["claim_set"]["claims"][2]["kind"] == "application"
    assert result["claim_set"]["claims"][2]["fact_ids"]
    assert result["claim_set"]["claims"][2]["evidence_ids"] == ["evidence-synthetic"]
    assert result["validation_report"]["final_disposition"] == "verified_full"
    assert result["verified_release"]["release_state"] == "verified_full"
    assert result["terminal_event"]["data"]["terminal_kind"] == "committed"
    assert result["answer_job"]["state"] == "complete"
    assert len(result["integrity_chain"]["chain_sha256"]) == 64
    assert result["publication_performed"] is False


@pytest.mark.parametrize("defect", ["fact", "evidence", "dependency", "host"])
def test_release_bridge_fails_closed_at_changed_predecessor(defect):
    registry, output, finalized, material = bundle()
    if defect == "fact":
        material["fact_projection"]["facts"][0]["text"] += " altered"
    elif defect == "evidence":
        material["evidence"]["sources"][0]["selected_evidence_id"] = "evidence-other"
    elif defect == "dependency":
        output["claims"][2]["depends_on_claim_ids"] = ["claim-rule"]
        finalized["reviewed_claim_set_sha256"] = review.sha256(review.canonical(output["claims"]))
    with pytest.raises((ValueError, ValidationError)):
        build(registry, output, finalized, material, verify=defect != "host")


@pytest.mark.parametrize("defect", [None, "request", "fence", "host"])
def test_durable_coordinates_bind_the_existing_chain_without_minting_authority(defect):
    registry, output, finalized, material = bundle()
    coordinates = {"job_id": "actual-job-001", "draft_id": "actual-draft-001",
        "answer_id": "actual-answer-001", "attempt_id": "actual-attempt-002",
        "lease_generation": 2, "sequence": 9, "idempotency_sha256": "5" * 64,
        "request_sha256": material["selected_contracts"]["query_plan"]["request_sha256"]}
    if defect == "request":
        coordinates["request_sha256"] = "6" * 64
    if defect == "fence":
        coordinates["lease_generation"] = 0
    calls = []

    def verify(action, value):
        calls.append((action, value))
        return defect != "host"

    def invoke():
        return bridge.build_selected_release_contracts(review_output=output,
            finalized_review=finalized, review_material=material, created_at=STAMP,
            model_sha256="1" * 64, prompt_sha256="2" * 64, renderer_sha256="3" * 64,
            policy_bundle_sha256="4" * 64, registry=registry, encrypt_store=Vault(),
            host_verify=verify, runtime_coordinates=coordinates)

    if defect is not None:
        with pytest.raises(ValueError):
            invoke()
        return
    result = invoke()
    assert result["answer_job"]["job_id"] == coordinates["job_id"]
    assert result["answer_job"]["lease_generation"] == 2
    assert result["terminal_event"]["sequence"] == 9
    assert result["verified_release"]["answer_id"] == coordinates["answer_id"]
    expected = hashlib.sha256(b"release-v1\0actual-job-001").hexdigest()
    assert result["verified_release"]["outbox_id"] == "release-" + expected[:40]
    assert calls[0] == ("runtime_release_coordinates", coordinates)
    assert calls[-1][1]["runtime_coordinates_sha256"] == bridge._digest(coordinates)
    assert result["publication_performed"] is False
