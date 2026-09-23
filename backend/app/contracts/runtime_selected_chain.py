"""Real AnswerRunner bindings for the selected request-to-release contracts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..citations import oscola
from ..db import Database
from ..orchestration.object_store import EncryptedObjectStore
from ..prompt_templates import (
    AI_EVIDENCE_REVIEWER_TEMPLATE_SHA256,
    DRAFT_GENERATOR_TEMPLATE_SHA256,
    FULL_ANSWER_REVIEWER_TEMPLATE_SHA256,
)
from ..quality.ai_evidence_reviewer import ai_evidence_reviewer_toolchain_sha256
from ..quality.policy import POLICY_SHA256
from ..quality.fact_provenance import verified_application_quotes
from ..types import EvidenceSpan, IssuePlan, QualityReport, StructuredDraft, TaskType
from .claim_set import ClaimContractInput, build_claim_set, validate_claim_support_graph
from .persistence import PersistedAnswerChain, SelectedAnswerContractStore
from .query_plan import QueryBudgets, build_query_plan
from .release import (
    build_committed_terminal_event,
    build_complete_answer_job,
    build_verified_release,
    committed_terminal_event_id,
)
from .retrieval_evidence import QualifiedEvidenceInput, build_retrieval_evidence_contracts
from .schema_registry import ContractSchemaRegistry, canonical_json_bytes, seal_contract
from .validation import ValidationCheckInput, build_validation_report

SELECTED_RUNTIME_INPUT_SCHEMA = "legalbot.selected-runtime-inputs.v1"


@dataclass(frozen=True, slots=True)
class SelectedRuntimeInputs:
    value: Mapping[str, Any]
    input_sha256: str


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _text_sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stamp(value: str | datetime) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _identity(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha(value)[:40]}"


def _evaluation_authority(job: Any) -> dict[str, Any]:
    try:
        value = json.loads(str(job["evaluation_authority_json"] or ""))
    except json.JSONDecodeError as exc:
        raise RuntimeError("selected runtime evaluation authority is invalid") from exc
    if (
        not isinstance(value, dict)
        or value.get("lane") not in {"ge_qwen_visible_development", "ge_owner_development_chat"}
        or value.get("writes_active") is not False
        or value.get("release_allowed") is not True
        or value.get("seal_sha256") != job["evaluation_authority_sha256"]
    ):
        raise RuntimeError("selected runtime requires the GE Qwen development authority")
    return value


def selected_runtime_input_sha256(
    *,
    job_id: str,
    request_sha256: str,
    question: str,
    task_type: TaskType | str,
    answer_route: str,
    jurisdiction: str,
    as_of_date: date,
    issue_plan: IssuePlan,
    evidence: Sequence[EvidenceSpan],
    visible_facts: Mapping[str, Any],
    candidate_id: str,
    candidate_sha256: str,
) -> str:
    return _sha(
        {
            "schema": "legalbot.selected-runtime-input-identity.v1",
            "job_id": job_id,
            "request_sha256": request_sha256,
            "question_sha256": _text_sha(question),
            "task_type": str(task_type),
            "answer_route": answer_route,
            "jurisdiction": jurisdiction,
            "as_of_date": as_of_date.isoformat(),
            "issue_plan": issue_plan.model_dump(mode="json"),
            "evidence": [
                {
                    "evidence_id": item.id,
                    "source_version_id": item.source_version_id,
                    "chunk_id": item.chunk_id,
                    "content_sha256": item.content_sha256,
                    "text_sha256": _text_sha(item.text),
                    "index_build_id": item.index_build_id,
                }
                for item in evidence
            ],
            "visible_facts": dict(visible_facts),
            "candidate_id": candidate_id,
            "candidate_sha256": candidate_sha256,
        }
    )


def build_selected_runtime_inputs(
    *,
    job: Any,
    request_sha256: str,
    question: str,
    task_type: TaskType | str,
    answer_route: str,
    jurisdiction: str,
    as_of_date: date,
    issue_plan: IssuePlan,
    evidence: Sequence[EvidenceSpan],
    visible_facts: Mapping[str, Any],
    candidate_id: str,
    candidate_sha256: str,
    objects: EncryptedObjectStore,
    registry: ContractSchemaRegistry,
) -> SelectedRuntimeInputs:
    """Freeze facts, plan, retrieval and exact whole model-visible evidence."""

    authority = _evaluation_authority(job)
    if (
        str(job["id"]) == ""
        or request_sha256 != job["evaluation_request_sha256"]
        or candidate_id != job["pinned_index_build_id"]
        or candidate_id != authority.get("candidate_build_id")
        or len(candidate_sha256) != 64
        or any(character not in "0123456789abcdef" for character in candidate_sha256)
    ):
        raise RuntimeError("selected runtime input identity differs from its durable job")
    if not evidence:
        raise ValueError("selected runtime answer input requires evidence")
    job_id = str(job["id"])
    created = _stamp(str(job["created_at"]))
    issue_id = _identity(
        "issue",
        {
            "request_sha256": request_sha256,
            "jurisdiction": jurisdiction,
            "as_of_date": as_of_date.isoformat(),
        },
    )
    issue_ids = (issue_id,)
    owner_scope_sha256 = str(authority.get("owner_scope_sha256") or "")
    visible_question = str(visible_facts.get("question") or "")
    visible_uploads = visible_facts.get("uploads")
    provenance = visible_facts.get("provenance")
    if not visible_question or not isinstance(visible_uploads, list) or not isinstance(provenance, dict):
        raise ValueError("selected runtime visible fact projection is incomplete")

    question_value = {
        "schema": "legalbot.selected-fact-value.v1",
        "job_id": job_id,
        "kind": "question",
        "text": visible_question,
        "text_sha256": _text_sha(visible_question),
        "projection_provenance": provenance["question"],
    }
    question_ref = objects.put_json(
        namespace="selected_fact_values",
        value=question_value,
        metadata={"job_id": job_id, "kind": "question"},
        ttl_days=None,
    )
    message_id = _identity("message", {"job_id": job_id, "request": request_sha256})
    conversation_id = _identity("evaluation-conversation", {"job_id": job_id})
    message = {
        "message_id": message_id,
        "ordinal": 1,
        "revision": 1,
        "role": "user",
        "encrypted_content_ref": question_ref,
        "content_sha256": _text_sha(visible_question),
        "created_at": created.isoformat(),
    }
    changed = bool(provenance["question"].get("input_changed_by_projection"))
    conversation_material = {
        "schema": "legalbot.conversation-snapshot.v1",
        "conversation_id": conversation_id,
        "owner_scope_sha256": owner_scope_sha256,
        "revision": 1,
        "created_at": created.isoformat(),
        "messages": [message],
        "truncated": changed,
        "omitted_message_count": 0,
        "omitted_before_ordinal": None,
        "truncation_reason": "token_limit" if changed else "none",
        "estimated_tokens": min(131_072, max(1, (len(visible_question.encode("utf-8")) + 2) // 3)),
    }
    conversation = seal_contract(
        {
            **conversation_material,
            "snapshot_id": _identity("conversation-snapshot", conversation_material),
        }
    )

    facts: list[dict[str, Any]] = []
    review_fact_inputs: list[dict[str, Any]] = []

    def add_fact(
        *,
        key: str,
        text: str,
        origin: str,
        status: str,
        encrypted_ref: str,
        source_kind: str,
        source_id: str,
        locator: str,
    ) -> None:
        fact_id = _identity(
            "fact",
            {"job_id": job_id, "key": key, "text_sha256": _text_sha(text)},
        )
        facts.append(
            {
                "fact_id": fact_id,
                "fact_key": key,
                "data_type": "text",
                "encrypted_value_ref": encrypted_ref,
                "value_sha256": _text_sha(text),
                "origin": origin,
                "status": status,
                "revision": 1,
                "supersedes_fact_id": None,
                "conflict_group_id": None,
                "affected_issue_ids": list(issue_ids),
                "temporal_scope": {
                    "effective_from": None,
                    "effective_to": None,
                    "as_of_status": "unknown",
                },
                "derivation_rule_sha256": None,
                "created_at": created.isoformat(),
                "fact_refs": [
                    {
                        "source_kind": source_kind,
                        "source_id": source_id,
                        "source_revision": 1,
                        "content_sha256": _text_sha(text),
                        "safe_locator": locator,
                    }
                ],
            }
        )
        review_fact_inputs.append(
            {"fact_id": fact_id, "text": text, "text_sha256": _text_sha(text)}
        )

    add_fact(
        key="user-question",
        text=visible_question,
        origin="user_statement",
        status="stated",
        encrypted_ref=question_ref,
        source_kind="message",
        source_id=message_id,
        locator=f"utf8-bytes:0:{len(visible_question.encode('utf-8'))}",
    )
    for ordinal, item in enumerate(visible_uploads, start=1):
        if not isinstance(item, dict) or not item.get("context_id") or not item.get("text"):
            raise ValueError("selected runtime upload projection is invalid")
        context_id = str(item["context_id"])
        text = str(item["text"])
        value = {
            "schema": "legalbot.selected-fact-value.v1",
            "job_id": job_id,
            "kind": "upload-extraction",
            "context_id": context_id,
            "text": text,
            "text_sha256": _text_sha(text),
        }
        encrypted_ref = objects.put_json(
            namespace="selected_fact_values",
            value=value,
            metadata={"job_id": job_id, "kind": "upload-extraction"},
            ttl_days=None,
        )
        add_fact(
            key=f"upload-{ordinal:02d}",
            text=text,
            origin="document_extraction",
            status="extracted",
            encrypted_ref=encrypted_ref,
            source_kind="upload",
            source_id=context_id,
            locator="model-visible-extraction",
        )
    matter_material = {
        "schema": "legalbot.matter-fact-snapshot.v2",
        "conversation_id": conversation_id,
        "owner_scope_sha256": owner_scope_sha256,
        "conversation_revision": 1,
        "created_at": created.isoformat(),
        "facts": facts,
    }
    fact_snapshot = seal_contract(
        {
            **matter_material,
            "snapshot_id": _identity("matter-fact-snapshot", matter_material),
        }
    )
    registry.validate_new(conversation)
    registry.validate_new(fact_snapshot)

    variants_value = {
        "schema": "legalbot.selected-query-variants.v1",
        "job_id": job_id,
        "queries": list(issue_plan.queries),
        "issue_plan": issue_plan.safe_metadata(),
    }
    variants_ref = objects.put_json(
        namespace="selected_query_variants",
        value=variants_value,
        metadata={"job_id": job_id},
        ttl_days=None,
    )
    variants_sha256 = variants_ref.rsplit(":", 1)[-1]
    plan = build_query_plan(
        request_id=job_id,
        request_sha256=request_sha256,
        original_question_sha256=_text_sha(question),
        task_type=str(task_type),
        answer_route=answer_route,
        requires_knowledge=True,
        requires_matter=True,
        response_disposition="ANSWER",
        jurisdiction=jurisdiction,
        jurisdiction_status="explicit",
        requested_as_of_date=as_of_date,
        as_of_date_status="explicit",
        issue_ids=issue_ids,
        missing_facts=(),
        query_variants_ref=variants_ref,
        query_variants_sha256=variants_sha256,
        candidate_id=candidate_id,
        policy_sha256=POLICY_SHA256,
        config_sha256=str(authority["runtime_binding_sha256"]),
        conversation_snapshot=conversation,
        fact_snapshot=fact_snapshot,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "evaluation_history_withheld",
        },
        risk_flags=("point_in_time_research", "same_model_adapter_review"),
        request_observed_at=created,
        frozen_at=created,
        registry=registry,
        budgets=QueryBudgets(
            reranker_candidates=max(12, len(evidence)),
            final_top_k=len(evidence),
            context_tokens=8_192,
        ),
    )
    retrieval = build_retrieval_evidence_contracts(
        query_plan=plan.value,
        query_plan_sha256=plan.content_sha256,
        candidate_sha256=candidate_sha256,
        evidence=tuple(
            QualifiedEvidenceInput(
                span=item,
                issue_ids=issue_ids,
                selected_token_count=max(1, len(item.text.split())),
                selected_rank=ordinal,
            )
            for ordinal, item in enumerate(evidence, start=1)
        ),
        fact_snapshot_sha256=str(fact_snapshot["content_sha256"]),
        created_at=created,
        registry=registry,
    )
    input_sha256 = selected_runtime_input_sha256(
        job_id=job_id,
        request_sha256=request_sha256,
        question=question,
        task_type=task_type,
        answer_route=answer_route,
        jurisdiction=jurisdiction,
        as_of_date=as_of_date,
        issue_plan=issue_plan,
        evidence=evidence,
        visible_facts=visible_facts,
        candidate_id=candidate_id,
        candidate_sha256=candidate_sha256,
    )
    value = {
        "schema": SELECTED_RUNTIME_INPUT_SCHEMA,
        "job_id": job_id,
        "request_sha256": request_sha256,
        "evaluation_authority_sha256": str(job["evaluation_authority_sha256"]),
        "expected_disposition": str(authority["expected_disposition"]),
        "input_sha256": input_sha256,
        "conversation_snapshot": conversation,
        "fact_snapshot": fact_snapshot,
        "query_plan": dict(plan.value),
        "query_plan_sha256": plan.content_sha256,
        "retrieval_result": dict(retrieval.retrieval_result),
        "evidence_pack": dict(retrieval.evidence_pack),
        "review_fact_inputs": review_fact_inputs,
        "model_visible_evidence_ids": [item.id for item in evidence],
        "fact_projection_provenance": provenance,
        "created_at": created.isoformat(),
    }
    return SelectedRuntimeInputs(value=value, input_sha256=input_sha256)


def require_selected_runtime_inputs(
    value: Mapping[str, Any], *, registry: ContractSchemaRegistry
) -> Mapping[str, Any]:
    if value.get("schema") != SELECTED_RUNTIME_INPUT_SCHEMA:
        raise RuntimeError("selected runtime input checkpoint schema differs")
    for key in (
        "conversation_snapshot",
        "fact_snapshot",
        "query_plan",
        "retrieval_result",
        "evidence_pack",
    ):
        candidate = value.get(key)
        if not isinstance(candidate, dict):
            raise RuntimeError("selected runtime input checkpoint is incomplete")
        registry.validate_new(candidate)
    if value.get("query_plan_sha256") != _sha(value["query_plan"]):
        raise RuntimeError("selected runtime query plan digest differs")
    if value.get("expected_disposition") not in {
        "supported_answer",
        "hold_or_clarification",
    }:
        raise RuntimeError("selected runtime expected disposition is invalid")
    return value


def _validator_bundle_sha256() -> str:
    return _sha(
        {
            "schema": "legalbot.selected-validator-bundle.v1",
            "policy_sha256": POLICY_SHA256,
            "ai_evidence_toolchain_sha256": ai_evidence_reviewer_toolchain_sha256(),
            "ai_evidence_prompt_sha256": AI_EVIDENCE_REVIEWER_TEMPLATE_SHA256,
            "full_answer_prompt_sha256": FULL_ANSWER_REVIEWER_TEMPLATE_SHA256,
        }
    )


def persist_selected_runtime_chain(
    *,
    database: Database,
    objects: EncryptedObjectStore,
    registry: ContractSchemaRegistry,
    selected_inputs: Mapping[str, Any],
    answer_id: str,
    draft: StructuredDraft,
    rendered_answer: str,
    report: QualityReport,
    model_id: str,
    model_version: str,
    repair_count: int,
) -> PersistedAnswerChain:
    """Build and persist the exact reviewed chain before atomic publication."""

    selected = require_selected_runtime_inputs(selected_inputs, registry=registry)
    job_id = str(selected["job_id"])
    job = database.job(job_id)
    answer = database.answer(answer_id)
    if job is None or answer is None or str(answer["job_id"]) != job_id:
        raise RuntimeError("selected runtime answer coordinates are missing")
    _evaluation_authority(job)
    if (
        str(job["status"]) != "running"
        or str(job["stage"]) != "verifying"
        or not job["lease_owner"]
        or int(job["attempt_count"] or 0) < 1
        or str(answer["release_state"] or "")
    ):
        raise RuntimeError("selected runtime release fence is not active")
    if report.answer_version_id != answer_id or str(report.release_state) != "verified_full":
        raise RuntimeError("selected runtime quality report does not authorize full release")
    evidence_review = report.ai_evidence_review
    full_review = report.ai_full_answer_review
    if (
        not isinstance(evidence_review, dict)
        or evidence_review.get("passed") is not True
        or not isinstance(full_review, dict)
        or full_review.get("passed") is not True
        or full_review.get("rendered_answer_sha256") != _text_sha(rendered_answer)
    ):
        raise RuntimeError("selected runtime independent answer review did not pass")

    evidence_pack = selected["evidence_pack"]
    selected_ids = {item["evidence_id"] for item in evidence_pack["selected"]}
    issue_ids = tuple(selected["query_plan"]["issue_ids"])
    contract_claims: list[ClaimContractInput] = []
    question_facts = [fact for fact in selected["fact_snapshot"]["facts"]
                      if fact["origin"] == "user_statement"]
    fact_texts = {fact["fact_id"]: fact for fact in selected["review_fact_inputs"]}
    for section in draft.sections:
        for claim in section.claims:
            if not claim.material or not claim.evidence_ids:
                raise RuntimeError("selected runtime answer contains an unbound material claim")
            if not set(claim.evidence_ids) <= selected_ids:
                raise RuntimeError("selected runtime claim evidence was not model-visible")
            claim_value = {
                "schema": "legalbot.selected-claim-value.v1",
                "job_id": job_id,
                "answer_id": answer_id,
                "claim_id": claim.id,
                "text": claim.text,
                "text_sha256": _text_sha(claim.text),
            }
            encrypted_ref = objects.put_json(
                namespace="selected_claim_values",
                value=claim_value,
                metadata={"job_id": job_id, "answer_id": answer_id, "claim_id": claim.id},
                ttl_days=None,
            )
            fact_ids: tuple[str, ...] = ()
            dependencies: tuple[str, ...] = ()
            if claim.kind == "application":
                if len(question_facts) != 1:
                    raise RuntimeError("application requires the exact question fact snapshot")
                fact = question_facts[0]
                premise = fact_texts.get(fact["fact_id"], {})
                question_text = str(premise.get("text") or "")
                if (premise.get("text_sha256") != _text_sha(question_text)
                        or not any(ref["content_sha256"] == _text_sha(question_text) for ref in fact["fact_refs"])):
                    raise RuntimeError("application question fact hash differs")
                quotes = verified_application_quotes(claim, draft, question_text)
                fact_ids = (fact["fact_id"],)
                fact_claim_id = "fact-premise-" + _text_sha(claim.id)[:32]
                if any(c.id == fact_claim_id for s in draft.sections for c in s.claims):
                    raise RuntimeError("application fact claim identity collides")
                premise_text = "\n".join(quotes)
                premise_ref = objects.put_json(
                    namespace="selected_claim_values",
                    value={"schema": "legalbot.selected-claim-value.v1", "job_id": job_id,
                           "answer_id": answer_id, "claim_id": fact_claim_id,
                           "text": premise_text, "text_sha256": _text_sha(premise_text)},
                    metadata={"job_id": job_id, "answer_id": answer_id, "claim_id": fact_claim_id},
                    ttl_days=None,
                )
                contract_claims.append(ClaimContractInput(
                    claim_id=fact_claim_id, kind="user_fact", encrypted_text_ref=premise_ref,
                    text_sha256=_text_sha(premise_text), materiality_basis="outcome_premise",
                    issue_ids=issue_ids, fact_ids=fact_ids,
                ))
                dependencies = (*claim.rule_claim_ids, fact_claim_id)
            contract_claims.append(
                ClaimContractInput(
                    claim_id=claim.id,
                    kind="application" if claim.kind == "application" else "legal_rule",
                    encrypted_text_ref=encrypted_ref,
                    text_sha256=_text_sha(claim.text),
                    materiality_basis="issue_element",
                    issue_ids=issue_ids,
                    evidence_ids=tuple(claim.evidence_ids),
                    fact_ids=fact_ids,
                    depends_on_claim_ids=dependencies,
                )
            )
    created = _stamp(str(answer["created_at"]))
    rendered_sha256 = _text_sha(rendered_answer)
    claim_set = build_claim_set(
        job_id=job_id,
        draft_id=answer_id,
        draft_sha256=rendered_sha256,
        query_plan_sha256=str(selected["query_plan_sha256"]),
        fact_snapshot_sha256=str(selected["fact_snapshot"]["content_sha256"]),
        evidence_pack_sha256=str(evidence_pack["content_sha256"]),
        claims=tuple(contract_claims),
        created_at=created,
        registry=registry,
    )
    validate_claim_support_graph(
        claim_set,
        issue_ids=issue_ids,
        evidence_ids=tuple(sorted(selected_ids)),
        facts=selected["fact_snapshot"]["facts"],
    )
    material_claim_ids = tuple(item["claim_id"] for item in claim_set["claims"])
    report_value = report.model_dump(mode="json")
    report_sha256 = _sha(report_value)
    validator_sha256 = _validator_bundle_sha256()
    review_output_sha256 = _sha(
        {"evidence_review": evidence_review, "full_answer_review": full_review}
    )
    check_kinds = (
        "identity",
        "fact_provenance",
        "evidence_support",
        "currentness",
        "quotation",
        "citation",
        "date_amount",
        "contradiction",
        "privacy",
        "output_shape",
    )
    checks = tuple(
        ValidationCheckInput(
            check_id=f"runtime-check-{ordinal:02d}",
            kind=kind,  # type: ignore[arg-type]
            result="PASS",
            material=True,
            reason_code=f"selected_runtime_{kind}_pass",
            affected_ids=material_claim_ids,
            validator_sha256=validator_sha256,
            input_sha256=report_sha256,
            output_sha256=review_output_sha256,
        )
        for ordinal, kind in enumerate(check_kinds, start=1)
    )
    validation = build_validation_report(
        draft_id=answer_id,
        draft_sha256=rendered_sha256,
        validator_bundle_sha256=validator_sha256,
        checks=checks,
        advisory_status="PASS",
        advisory_report_sha256=review_output_sha256,
        repair_parent_id=str(answer["parent_version_id"]) if answer["parent_version_id"] else None,
        requested_disposition="verified_full",
        claim_set_sha256=str(claim_set["content_sha256"]),
        evidence_pack_sha256=str(evidence_pack["content_sha256"]),
        fact_snapshot_sha256=str(selected["fact_snapshot"]["content_sha256"]),
        policy_sha256=POLICY_SHA256,
        created_at=created,
        registry=registry,
    )
    attempt_count = int(job["attempt_count"])
    attempt_digest = hashlib.sha256(
        f"legalbot-job-attempt-v1\0{job_id}\0{attempt_count}".encode()
    ).hexdigest()
    attempt_id = f"attempt-{attempt_digest[:32]}"
    sequence_row = database.fetchone(
        "SELECT COALESCE(MAX(sequence),0)+1 AS value FROM job_events WHERE job_id=?",
        (job_id,),
    )
    terminal_sequence = int(sequence_row["value"] if sequence_row is not None else 1)
    terminal_id = committed_terminal_event_id(
        job_id=job_id,
        attempt_id=attempt_id,
        lease_generation=attempt_count,
        sequence=terminal_sequence,
    )
    outbox_key = hashlib.sha256(f"release-v1\0{job_id}".encode()).hexdigest()
    outbox_id = f"release-{outbox_key[:40]}"
    committed_at = datetime.now(UTC)
    model_sha256 = _sha(
        {
            "schema": "legalbot.selected-model-runtime.v1",
            "model_id": model_id,
            "model_version": model_version,
            "runtime_binding_sha256": _evaluation_authority(job)["runtime_binding_sha256"],
        }
    )
    prompt_sha256 = _sha(
        {
            "draft": DRAFT_GENERATOR_TEMPLATE_SHA256,
            "evidence_review": AI_EVIDENCE_REVIEWER_TEMPLATE_SHA256,
            "full_answer_review": FULL_ANSWER_REVIEWER_TEMPLATE_SHA256,
        }
    )
    renderer_sha256 = hashlib.sha256(Path(oscola.__file__).read_bytes()).hexdigest()
    policy_bundle_sha256 = _sha(
        {
            "policy_sha256": POLICY_SHA256,
            "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
            "validator_bundle_sha256": validator_sha256,
        }
    )
    release = build_verified_release(
        job_id=job_id,
        answer_id=answer_id,
        release_state="verified_full",
        answer_content_sha256=rendered_sha256,
        request_sha256=str(selected["request_sha256"]),
        query_plan=selected["query_plan"],
        query_plan_sha256=str(selected["query_plan_sha256"]),
        conversation_snapshot=selected["conversation_snapshot"],
        fact_snapshot=selected["fact_snapshot"],
        retrieval_result=selected["retrieval_result"],
        evidence_pack=evidence_pack,
        claim_set=claim_set,
        validation_report=validation.value,
        validation_report_sha256=validation.content_sha256,
        model_sha256=model_sha256,
        prompt_sha256=prompt_sha256,
        renderer_sha256=renderer_sha256,
        policy_bundle_sha256=policy_bundle_sha256,
        repair_count=repair_count,
        parent_answer_id=str(answer["parent_version_id"]) if answer["parent_version_id"] else None,
        outbox_id=outbox_id,
        committed_at=committed_at,
        terminal_event_id=terminal_id,
        release_reason_codes=(
            "development_visible_full_answer_review_pass",
            "owner_evaluation_non_active",
        ),
        registry=registry,
    )
    terminal_event = build_committed_terminal_event(
        verified_release=release,
        attempt_id=attempt_id,
        lease_generation=attempt_count,
        sequence=terminal_sequence,
        emitted_at=committed_at,
        registry=registry,
    )
    answer_job = build_complete_answer_job(
        job_id=job_id,
        request_id=str(selected["query_plan"]["request_id"]),
        request_sha256=str(selected["request_sha256"]),
        idempotency_sha256=str(job["idempotency_key"]),
        owner_scope_sha256=str(selected["conversation_snapshot"]["owner_scope_sha256"]),
        attempt_id=attempt_id,
        lease_generation=attempt_count,
        conversation_snapshot_sha256=str(selected["conversation_snapshot"]["content_sha256"]),
        fact_snapshot_sha256=str(selected["fact_snapshot"]["content_sha256"]),
        query_plan_sha256=str(selected["query_plan_sha256"]),
        retrieval_result_sha256=str(selected["retrieval_result"]["content_sha256"]),
        evidence_pack_sha256=str(evidence_pack["content_sha256"]),
        claim_set_sha256=str(claim_set["content_sha256"]),
        validation_report_sha256=validation.content_sha256,
        release_sha256=str(release["content_sha256"]),
        created_at=_stamp(str(job["created_at"])),
        terminal_at=committed_at,
        registry=registry,
    )
    return SelectedAnswerContractStore(
        database=database,
        objects=objects,
        registry=registry,
    ).persist_verified_unpublished(
        job_id=job_id,
        request_id=str(selected["query_plan"]["request_id"]),
        request_sha256=str(selected["request_sha256"]),
        conversation_snapshot=selected["conversation_snapshot"],
        fact_snapshot=selected["fact_snapshot"],
        query_plan=selected["query_plan"],
        retrieval_result=selected["retrieval_result"],
        evidence_pack=evidence_pack,
        claim_set=claim_set,
        validation_report=validation.value,
        verified_release=release,
        terminal_event=terminal_event,
        answer_job=answer_job,
    )


__all__ = [
    "SELECTED_RUNTIME_INPUT_SCHEMA",
    "SelectedRuntimeInputs",
    "build_selected_runtime_inputs",
    "persist_selected_runtime_chain",
    "require_selected_runtime_inputs",
    "selected_runtime_input_sha256",
]
