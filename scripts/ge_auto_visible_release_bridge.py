"""Bind one accepted visible answer review to the selected release contracts.

This adapter reuses ClaimSet v1, ValidationReport v1, VerifiedRelease v1 and the
existing integrity verifier.  It performs no model call, source IO, publication,
ACTIVE mutation, production admission or training.  A passing result proves only
that the exact non-live visible chain satisfied the selected release checks.
"""
from __future__ import annotations

import copy
import hashlib
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from backend.app.contracts import (
    AnswerIntegrityChainVerifier,
    ClaimContractInput,
    ContractSchemaRegistry,
    ValidationCheckInput,
    build_claim_set,
    build_committed_terminal_event,
    build_complete_answer_job,
    build_validation_report,
    build_verified_release,
    canonical_json_bytes,
    committed_terminal_event_id,
    validate_claim_support_graph,
)
from backend.app.contracts.retrieval_evidence import validate_retrieval_evidence_scope

from scripts import ge_auto_case_protocol as protocol
from scripts import ge_auto_visible_answer_review as answer_review

VERSION = "legalbot.ge-visible-selected-release-contracts.v1"
KIND_MAP = {
    "LEGAL": "legal_rule",
    "FACT": "user_fact",
    "APPLICATION": "application",
    "LIMITATION": "limitation",
}
CHECK_MAP = {
    "identity": "integrity_chain",
    "fact_provenance": "user_fact_provenance",
    "evidence_support": "claim_evidence_support",
    "currentness": "requested_date_and_currentness",
    "quotation": "citation_and_quotation_identity",
    "citation": "citation_and_quotation_identity",
    "date_amount": "dates_amounts_and_deadlines",
    "contradiction": "contradiction_and_counterauthority",
    "privacy": "privacy_and_instruction_isolation",
    "output_shape": "integrity_chain",
}


def _need(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def _digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _digest_bytes(canonical_json_bytes(value))


def _exact_hash(value: str, code: str) -> str:
    _need(isinstance(value, str) and len(value) == 64
          and all(char in "0123456789abcdef" for char in value)
          and value != "0" * 64, code)
    return value


def _review_claim_kind(claim: Mapping[str, Any], by_id: Mapping[str, Mapping[str, Any]]) -> str:
    kind = str(claim["kind"])
    if kind in KIND_MAP:
        return KIND_MAP[kind]
    if kind == "ADVICE":
        dependencies = [by_id[item] for item in claim["depends_on_claim_ids"]]
        if (any(item["kind"] == "LEGAL" and item["status"] == "SUPPORTED" for item in dependencies)
                and any(item["kind"] == "FACT" and item["status"] == "SUPPORTED" for item in dependencies)):
            return "application"
        _need(not claim["material"], "MATERIAL_ADVICE_REQUIRES_RULE_FACT_DEPENDENCIES")
        return "limitation"
    _need(kind == "OTHER" and not claim["material"], "MATERIAL_OTHER_CLAIM_UNMAPPABLE")
    return "limitation"


def _basis(claim: Mapping[str, Any], kind: str) -> str:
    if not claim["material"]:
        return "non_material_explanation"
    if kind == "application":
        return "outcome_premise"
    if kind == "limitation":
        return "scope_or_limitation"
    return "issue_element"


def _status(value: str) -> str:
    if value == "PASS":
        return "PASS"
    if value == "NOT_APPLICABLE":
        return "NOT_APPLICABLE"
    return "FAIL"


def build_selected_release_contracts(
    *,
    review_output: Mapping[str, Any],
    finalized_review: Mapping[str, Any],
    review_material: Mapping[str, Any],
    created_at: datetime,
    model_sha256: str,
    prompt_sha256: str,
    renderer_sha256: str,
    policy_bundle_sha256: str,
    registry: ContractSchemaRegistry,
    encrypt_store: Callable[[bytes, Mapping[str, Any]], Mapping[str, Any]],
    host_verify: Callable[[str, Mapping[str, Any]], bool],
    runtime_coordinates: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct and verify a complete selected chain after accepted AI review."""
    _need(finalized_review.get("review_acceptance") == "ACCEPTED_PARENT_VERIFIED_AI_REVIEW"
          and finalized_review.get("full_answer_pass") is True,
          "ACCEPTED_FULL_VISIBLE_REVIEW_REQUIRED")
    _need(finalized_review.get("professional_legal_sign_off") is False,
          "VISIBLE_REVIEW_CANNOT_CLAIM_PROFESSIONAL_SIGN_OFF")
    selected = copy.deepcopy(review_material["selected_contracts"])
    for key in ("conversation_snapshot", "query_plan", "fact_snapshot",
                "retrieval_result", "evidence_pack"):
        registry.validate_new(selected[key])
    query_plan = selected["query_plan"]
    fact_snapshot = selected["fact_snapshot"]
    retrieval_result = selected["retrieval_result"]
    evidence_pack = selected["evidence_pack"]
    validate_retrieval_evidence_scope(query_plan=query_plan,
        retrieval_result=retrieval_result, evidence_pack=evidence_pack)
    terminal = review_material["terminal"]
    candidate = review_material["candidate"]
    _need(terminal["answer"] == candidate and candidate["status"] == "ANSWER",
          "EXACT_ANSWER_TERMINAL_REQUIRED")
    answer_bytes = terminal["rendered_answer"].encode("utf-8")
    _need(_digest_bytes(answer_bytes) == terminal["rendered_answer_sha256"],
          "RENDERED_ANSWER_CHANGED")
    review_claims = list(review_output["claims"])
    _need(answer_review.sha256(answer_review.canonical(review_claims))
          == finalized_review["reviewed_claim_set_sha256"],
          "FINALIZED_REVIEW_CLAIMS_CHANGED")
    _need(set(item["requirement_id"] for item in review_material["requirements"])
          == set(query_plan["issue_ids"]), "REVIEW_REQUIREMENTS_OUTSIDE_QUERY_PLAN")
    projected = review_material["fact_projection"]
    _need(projected["fact_snapshot_sha256"] == fact_snapshot["content_sha256"]
          and projected["query_plan_sha256"] == _digest(query_plan),
          "FACT_PROJECTION_SELECTED_CONTRACT_MISMATCH")
    facts = {item["fact_id"]: item for item in fact_snapshot["facts"]}
    projected_facts = {item["fact_id"]: item for item in projected["facts"]}
    _need(set(facts) == set(projected_facts), "FACT_PROJECTION_COVERAGE_CHANGED")
    for fact_id, item in projected_facts.items():
        _need(_digest_bytes(item["text"].encode("utf-8")) == item["text_sha256"]
              == facts[fact_id]["value_sha256"]
              and item["status"] == facts[fact_id]["status"],
              "FACT_PROJECTION_PLAINTEXT_MISMATCH")
    evidence_sources = {item["source_id"]: item for item in review_material["evidence"]["sources"]}
    selected_ids = {item["evidence_id"] for item in evidence_pack["selected"]}
    _need(len(evidence_sources) == len(review_material["evidence"]["sources"]),
          "DUPLICATE_REVIEW_EVIDENCE_SOURCE")
    _need({item["selected_evidence_id"] for item in evidence_sources.values()} == selected_ids,
          "REVIEW_EVIDENCE_SELECTED_CONTRACT_MISMATCH")
    by_id = {item["claim_id"]: item for item in review_claims}
    _need(len(by_id) == len(review_claims), "DUPLICATE_REVIEW_CLAIM")
    contract_inputs = []
    job_id = "visible-job-" + _digest({"request": query_plan["request_sha256"],
        "answer": terminal["rendered_answer_sha256"]})[:40]
    draft_id = "visible-draft-" + terminal["rendered_answer_sha256"][:40]
    coordinates = None
    if runtime_coordinates is not None:
        coordinates = copy.deepcopy(dict(runtime_coordinates))
        _need(set(coordinates) == {"job_id", "draft_id", "answer_id", "attempt_id",
            "lease_generation", "sequence", "idempotency_sha256", "request_sha256"},
            "RUNTIME_RELEASE_COORDINATES_INVALID")
        for key in ("job_id", "draft_id", "answer_id", "attempt_id"):
            protocol.checked(coordinates[key], protocol.ID)
        _need(all(type(coordinates[key]) is int and coordinates[key] > 0
                  for key in ("lease_generation", "sequence")),
              "RUNTIME_RELEASE_FENCE_INVALID")
        _exact_hash(coordinates["idempotency_sha256"], "RUNTIME_IDEMPOTENCY_REQUIRED")
        _need(coordinates["request_sha256"] == query_plan["request_sha256"],
              "RUNTIME_REQUEST_CHANGED")
        _need(callable(host_verify) and host_verify("runtime_release_coordinates",
            copy.deepcopy(coordinates)) is True, "RUNTIME_RELEASE_COORDINATES_UNVERIFIED")
        job_id, draft_id = coordinates["job_id"], coordinates["draft_id"]
    kinds = {claim_id: _review_claim_kind(claim, by_id) for claim_id, claim in by_id.items()}
    direct = {claim_id: {
        "fact_ids": list(dict.fromkeys(span["fact_id"] for span in claim["fact_spans"])),
        "evidence_ids": list(dict.fromkeys(
            evidence_sources[span["source_id"]]["selected_evidence_id"]
            for span in claim["evidence_spans"])),
    } for claim_id, claim in by_id.items()}
    resolved: dict[str, dict[str, list[str]]] = {}
    visiting: set[str] = set()

    def resolve(claim_id: str) -> dict[str, list[str]]:
        _need(claim_id in by_id and claim_id not in visiting,
              "APPLICATION_DEPENDENCY_CYCLE_OR_ID")
        if claim_id in resolved:
            return resolved[claim_id]
        visiting.add(claim_id)
        facts_for_claim = list(direct[claim_id]["fact_ids"])
        evidence_for_claim = list(direct[claim_id]["evidence_ids"])
        if kinds[claim_id] == "application":
            for dependency_id in by_id[claim_id]["depends_on_claim_ids"]:
                dependency = resolve(dependency_id)
                facts_for_claim.extend(dependency["fact_ids"])
                evidence_for_claim.extend(dependency["evidence_ids"])
        visiting.remove(claim_id)
        resolved[claim_id] = {
            "fact_ids": list(dict.fromkeys(facts_for_claim)),
            "evidence_ids": list(dict.fromkeys(evidence_for_claim)),
        }
        return resolved[claim_id]

    for claim in review_claims:
        _need(claim["status"] == "SUPPORTED" or not claim["material"],
              "MATERIAL_REVIEW_CLAIM_NOT_SUPPORTED")
        kind = kinds[claim["claim_id"]]
        links = resolve(claim["claim_id"])
        fact_ids, evidence_ids = links["fact_ids"], links["evidence_ids"]
        text = claim["answer_span"]["text"]
        provenance = {"schema": "legalbot.ge-visible-reviewed-claim-provenance.v1",
            "job_id": job_id, "claim_id": claim["claim_id"],
            "text_sha256": _digest_bytes(text.encode("utf-8")),
            "review_output_sha256": finalized_review["review_output_sha256"]}
        stored = encrypt_store(text.encode("utf-8"), provenance)
        _need(isinstance(stored, Mapping)
              and set(stored) == {"encrypted_ref", "plaintext_sha256", "ciphertext_sha256", "receipt_sha256"}
              and stored["plaintext_sha256"] == provenance["text_sha256"],
              "REVIEWED_CLAIM_ENCRYPTION_RECEIPT")
        gap_codes = ()
        if kind == "limitation":
            gap_codes = ("reviewer.scope_limitation" if claim["material"]
                         else "reviewer.non_material_explanation",)
        row = ClaimContractInput(claim_id=claim["claim_id"], kind=kind,
            encrypted_text_ref=str(stored["encrypted_ref"]), text_sha256=provenance["text_sha256"],
            materiality_basis=_basis(claim, kind),
            issue_ids=tuple(claim["requirement_ids"]), fact_ids=tuple(fact_ids),
            evidence_ids=tuple(evidence_ids),
            depends_on_claim_ids=tuple(claim["depends_on_claim_ids"]),
            gap_codes=gap_codes)
        contract_inputs.append(row)
    query_plan_sha256 = _digest(query_plan)
    claim_set = build_claim_set(job_id=job_id, draft_id=draft_id,
        draft_sha256=terminal["rendered_answer_sha256"],
        query_plan_sha256=query_plan_sha256,
        fact_snapshot_sha256=fact_snapshot["content_sha256"],
        evidence_pack_sha256=evidence_pack["content_sha256"],
        claims=tuple(contract_inputs), created_at=created_at, registry=registry)
    validate_claim_support_graph(claim_set, issue_ids=query_plan["issue_ids"],
        evidence_ids=sorted(selected_ids), facts=fact_snapshot["facts"])
    all_ids = tuple(item["claim_id"] for item in claim_set["claims"] if item["material"])
    checks = []
    for ordinal, (kind, review_key) in enumerate(CHECK_MAP.items(), 1):
        source = review_output["factual_checks"][review_key]
        affected = all_ids
        if kind == "fact_provenance":
            affected = tuple(item["claim_id"] for item in claim_set["claims"]
                             if item["material"] and item["kind"] in {"user_fact", "application"})
        elif kind in {"evidence_support", "currentness", "quotation", "citation", "contradiction"}:
            affected = tuple(item["claim_id"] for item in claim_set["claims"]
                             if item["material"] and item["kind"] in {"legal_rule", "application", "limitation"})
        checks.append(ValidationCheckInput(check_id=f"visible-check-{ordinal:02d}",
            kind=kind, result=_status(source["status"]), material=True,
            reason_code="ai_answer_review_" + source["status"].lower(),
            affected_ids=affected, validator_sha256=finalized_review["review_schema_sha256"],
            input_sha256=finalized_review["bindings"]["packet_sha256"],
            output_sha256=finalized_review["review_output_sha256"]))
    report = build_validation_report(draft_id=draft_id,
        draft_sha256=terminal["rendered_answer_sha256"],
        validator_bundle_sha256=finalized_review["review_schema_sha256"], checks=tuple(checks),
        advisory_status="PASS", advisory_report_sha256=finalized_review["review_output_sha256"],
        repair_parent_id=None, requested_disposition="verified_full",
        claim_set_sha256=claim_set["content_sha256"],
        evidence_pack_sha256=evidence_pack["content_sha256"],
        fact_snapshot_sha256=fact_snapshot["content_sha256"],
        policy_sha256=query_plan["policy_sha256"], created_at=created_at, registry=registry)
    for value, code in ((model_sha256, "MODEL_HASH_REQUIRED"),
                        (prompt_sha256, "PROMPT_HASH_REQUIRED"),
                        (renderer_sha256, "RENDERER_HASH_REQUIRED"),
                        (policy_bundle_sha256, "POLICY_HASH_REQUIRED")):
        _exact_hash(value, code)
    attempt_id = "visible-attempt-" + query_plan["request_sha256"][:40]
    lease_generation, sequence = 1, 1
    if coordinates is not None:
        attempt_id = coordinates["attempt_id"]
        lease_generation, sequence = coordinates["lease_generation"], coordinates["sequence"]
    terminal_event_id = committed_terminal_event_id(job_id=job_id,
        attempt_id=attempt_id, lease_generation=lease_generation, sequence=sequence)
    validation_sha256 = _digest(report.value)
    answer_id = "visible-answer-" + terminal["rendered_answer_sha256"][:40]
    outbox_id = "visible-outbox-" + _digest({"job": job_id, "answer": answer_id})[:40]
    if coordinates is not None:
        answer_id = coordinates["answer_id"]
        outbox_id = "release-" + _digest_bytes(f"release-v1\0{job_id}".encode())[:40]
    release = build_verified_release(job_id=job_id, answer_id=answer_id,
        release_state="verified_full", answer_content_sha256=terminal["rendered_answer_sha256"],
        request_sha256=query_plan["request_sha256"], query_plan=query_plan,
        query_plan_sha256=query_plan_sha256,
        conversation_snapshot=review_material["selected_contracts"]["conversation_snapshot"],
        fact_snapshot=fact_snapshot, retrieval_result=retrieval_result,
        evidence_pack=evidence_pack, claim_set=claim_set, validation_report=report.value,
        validation_report_sha256=validation_sha256, model_sha256=model_sha256,
        prompt_sha256=prompt_sha256, renderer_sha256=renderer_sha256,
        policy_bundle_sha256=policy_bundle_sha256, repair_count=0, parent_answer_id=None,
        outbox_id=outbox_id, committed_at=created_at, terminal_event_id=terminal_event_id,
        release_reason_codes=("visible_development_ai_review_pass", "non_live_no_publication"),
        registry=registry)
    terminal_event = build_committed_terminal_event(verified_release=release,
        attempt_id=attempt_id, lease_generation=lease_generation, sequence=sequence,
        emitted_at=created_at, registry=registry)
    conversation = review_material["selected_contracts"].get("conversation_snapshot")
    _need(conversation is not None, "SELECTED_CONVERSATION_SNAPSHOT_REQUIRED")
    answer_job = build_complete_answer_job(job_id=job_id,
        request_id=query_plan["request_id"], request_sha256=query_plan["request_sha256"],
        idempotency_sha256=(coordinates["idempotency_sha256"] if coordinates is not None
            else _digest({"request": query_plan["request_sha256"], "candidate": query_plan["candidate_id"]})),
        owner_scope_sha256=conversation["owner_scope_sha256"], attempt_id=attempt_id,
        lease_generation=lease_generation, conversation_snapshot_sha256=conversation["content_sha256"],
        fact_snapshot_sha256=fact_snapshot["content_sha256"], query_plan_sha256=query_plan_sha256,
        retrieval_result_sha256=retrieval_result["content_sha256"],
        evidence_pack_sha256=evidence_pack["content_sha256"],
        claim_set_sha256=claim_set["content_sha256"], validation_report_sha256=validation_sha256,
        release_sha256=release["content_sha256"], created_at=created_at,
        terminal_at=created_at, registry=registry)
    chain = AnswerIntegrityChainVerifier(registry).verify_complete(job_id=job_id,
        request_id=query_plan["request_id"], request_sha256=query_plan["request_sha256"],
        conversation_snapshot=conversation, fact_snapshot=fact_snapshot, query_plan=query_plan,
        retrieval_result=retrieval_result, evidence_pack=evidence_pack, claim_set=claim_set,
        validation_report=report.value, verified_release=release,
        terminal_event=terminal_event, answer_job=answer_job)
    binding = {"job_id": job_id, "request_sha256": query_plan["request_sha256"],
        "review_output_sha256": finalized_review["review_output_sha256"],
        "claim_set_sha256": claim_set["content_sha256"],
        "validation_report_sha256": validation_sha256,
        "verified_release_sha256": release["content_sha256"],
        "integrity_chain_sha256": chain.chain_sha256}
    if coordinates is not None:
        binding["runtime_coordinates_sha256"] = _digest(coordinates)
    _need(callable(host_verify) and host_verify("visible_selected_release", copy.deepcopy(binding)) is True,
          "VISIBLE_RELEASE_HOST_VERIFICATION_DENIED")
    return {"schema": VERSION, "status": "SELECTED_RELEASE_CHECKS_PASS",
        "job_id": job_id, "answer_id": answer_id,
        "conversation_snapshot": conversation, "fact_snapshot": fact_snapshot,
        "query_plan": query_plan, "retrieval_result": retrieval_result,
        "evidence_pack": evidence_pack, "claim_set": claim_set,
        "validation_report": report.value, "verified_release": release,
        "terminal_event": terminal_event, "answer_job": answer_job,
        "integrity_chain": {"job_id": chain.job_id, "request_id": chain.request_id,
            "schema_selection_sha256": chain.schema_selection_sha256,
            "object_sha256": dict(chain.object_sha256),
            "terminal_event_id": chain.terminal_event_id,
            "chain_sha256": chain.chain_sha256},
        "host_binding": binding, "publication_performed": False,
        "production_admission": False, "training": False,
        "professional_legal_sign_off": False}


__all__ = ["VERSION", "build_selected_release_contracts"]
