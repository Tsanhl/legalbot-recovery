"""Full selected contracts for one explicitly supplied CaseProtocol turn.

build_case_contracts returns CaseContracts.binding (the actual index adapter's
ContractBinding), hash-only artifact lineage, and the protocol's own ordered
history projection. No filesystem discovery, model, encryption implementation,
capability issuance, indexing or legal/factual approval takes place here.
Artifact lineage is the actual context receipt: its sealed content_sha256 is
ContractBinding.context_receipt_sha256 (the self reference is not hashed twice).

The host supplies every pin, an exact request digest using protocol.digest, and
an already verified encrypt_store(bytes, provenance) callback. That callback MUST
encrypt, persist and verify ciphertext before returning exactly encrypted_ref,
plaintext_sha256, ciphertext_sha256, receipt_sha256. The last is backend canonical
digest(encryption_receipt_material(provenance, the other three fields)). The
receipt is a content binding, NOT a signature or proof of encryption: those remain
the trusted host's responsibility. No permissive callback or plaintext fallback.
Use idempotent exclusive storage keyed by provenance; failed partial writes must
survive and are not retried or deleted here.

PriorTurn contains the actual prior request, exact sealed terminal bytes, prior
CaseContracts, and its artifact-lineage digest pinned OUTSIDE that result. This
extra binding is necessary: the protocol's question-only history projection
cannot itself prove the earlier request hash. The host verifies custody and
terminal completion; this helper checks their supplied byte/content bindings.
Prior snapshots and evidence records are reused unchanged. Full question text is
stated evidence, never semantic facts, inferred corrections or confirmed law.
All prior answers are conservatively scope-filtered from ConversationSnapshot,
including answers for which this helper has no blind-review eligibility adapter.
They remain verbatim in protocol_history; no role is relabelled system/user.

UploadEvidence supplies actual due raw bytes and the actual host extraction
receipt bytes. The latter's JSON must bind raw_sha256, text_sha256, parser_sha256;
additional receipt fields are retained through its exact hash. Extraction is not
rerun or vouched for here. Upload text is copied exactly from the bound request.
No future uploads or inferred missing facts are accepted.

Limits: 24 user turns (selected conversation schema limit), 500 evidence records,
16 MB inputs, and 131072 UTF-8 bytes of question history as a deliberately
conservative estimated-token measure, NOT execution of the pinned tokenizer.
Exceeding a bound fails rather than silently dropping user evidence. The empty
baseline uses explicit shared creation/seal coordinates so it stays common across
cases; zero-source closure validates structure only. Production schemas unchanged.
Pin freshness, genuine models, ciphertext security, external authenticity,
semantic correction resolution and actual runtime/lookup remain host duties.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass, fields
from datetime import UTC, date, datetime
from typing import Any

from backend.app.contracts.query_plan import QueryBudgets, build_query_plan
from backend.app.contracts.schema_registry import (
    ContractSchemaRegistry,
    canonical_json_bytes,
    load_json_strict,
    seal_contract,
)
from backend.app.research.ge_auto_index import RESEARCH_GAPS, SUPPORTED_JURISDICTIONS, digest

from scripts import ge_auto_case_protocol as protocol
from scripts.ge_auto_case_index_adapter import ContractBinding

SCHEMA = "legalbot.ge-case-contract-artifacts.v1"
MAX_BYTES = 16_000_000
MAX_USER_TURNS = 24
MAX_FACTS = 500
MAX_ESTIMATED_TOKENS = 131_072
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class ContractBuildError(ValueError):
    """Stable non-sensitive errors; user text and callback exceptions stay private."""


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ContractBuildError(code)


def _hash(value: str) -> str:
    _need(
        isinstance(value, str) and bool(_SHA.fullmatch(value)) and value != "0" * 64,
        "EXACT_HASH_REQUIRED",
    )
    return value


def _id(value: str) -> str:
    _need(isinstance(value, str) and bool(_ID.fullmatch(value)), "SAFE_ID_REQUIRED")
    return value


def _stamp(value: datetime) -> str:
    _need(
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None,
        "EXPLICIT_OBSERVED_TIME_REQUIRED",
    )
    return value.astimezone(UTC).isoformat()


def _identity(kind: str, value: Any) -> str:
    return f"{kind}-{digest(value)[:40]}"


@dataclass(frozen=True)
class ContractPins:
    owner_scope_sha256: str
    owner_instruction_sha256: str
    protocol_policy_sha256: str
    query_policy_sha256: str
    qualification_policy_sha256: str
    config_sha256: str
    runtime_sha256: str
    model_sha256: str
    parser_sha256: str
    ocr_sha256: str | None
    chunker_sha256: str
    tokenizer_sha256: str
    embedding_model_sha256: str
    reranker_model_sha256: str
    lexical_config_sha256: str
    vector_schema_sha256: str
    encrypt_store_sha256: str
    schema_selection_sha256: str
    candidate_id: str
    baseline_generation_id: str
    baseline_created_at: datetime
    baseline_sealed_at: datetime

    def material(self) -> dict[str, Any]:
        result = asdict(self)
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name.endswith("_sha256"):
                if field.name != "ocr_sha256" or value is not None:
                    _hash(value)
            elif field.name.endswith("_id"):
                _id(value)
            else:
                result[field.name] = _stamp(value)
        _need(self.baseline_created_at <= self.baseline_sealed_at, "BASELINE_TIME_ORDER")
        return result


@dataclass(frozen=True)
class UploadEvidence:
    raw: bytes
    extraction_receipt: bytes


@dataclass(frozen=True)
class CaseContracts:
    binding: ContractBinding
    artifact_lineage: Mapping[str, Any]
    protocol_history: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class PriorTurn:
    request: Mapping[str, Any]
    terminal_bytes: bytes
    contracts: CaseContracts
    expected_artifact_lineage_sha256: str


def encryption_receipt_material(provenance: Mapping, stored: Mapping) -> dict:
    """Public exact receipt recipe for the trusted storage callback."""
    return {
        "schema": "legalbot.ge-case-encrypted-artifact-receipt.v1",
        "provenance_sha256": digest(provenance),
        **{key: stored[key] for key in ("encrypted_ref", "plaintext_sha256", "ciphertext_sha256")},
    }


def _contracts(binding: ContractBinding) -> dict[str, Mapping]:
    return {
        key: getattr(binding, key)
        for key in ("conversation_snapshot", "fact_snapshot", "query_plan", "knowledge_generation")
    }


def _contract_hashes(binding: ContractBinding) -> dict[str, str]:
    return {key: digest(value) for key, value in _contracts(binding).items()}


def _adapter_fields(binding: ContractBinding) -> dict:
    return {
        key: getattr(binding, key)
        for key in (
            "expected_knowledge_generation_sha256",
            "expected_schema_selection_sha256",
            "issue_id",
            "affected_claim_sha256",
            "existing_retrieval_sha256",
            "gap_class",
        )
    }


def _validate_prior(
    prior: PriorTurn,
    handle: Mapping,
    *,
    case_id: str,
    pins: ContractPins,
    registry: ContractSchemaRegistry,
) -> dict:
    _need(isinstance(prior, PriorTurn), "FULL_PRIOR_TURN_REQUIRED")
    protocol.checked(prior.request, protocol.REQUEST_SCHEMA)
    _need(
        prior.request["case_id"] == case_id
        and prior.request["turn"] == handle["turn"]
        and protocol.digest(prior.request) == handle["request_sha256"],
        "PRIOR_REQUEST_BINDING",
    )
    _need(
        isinstance(prior.terminal_bytes, bytes)
        and len(prior.terminal_bytes) <= MAX_BYTES
        and protocol.digest(prior.terminal_bytes) == handle["terminal_sha256"],
        "PRIOR_TERMINAL_HASH",
    )
    terminal = protocol.decode(prior.terminal_bytes)
    _need(
        isinstance(terminal, dict)
        and terminal.get("case_id") == case_id
        and terminal.get("turn") == handle["turn"]
        and terminal.get("request_sha256") == handle["request_sha256"]
        and terminal.get("policy_sha256") == pins.protocol_policy_sha256
        and terminal.get("schema") == protocol.VERSION,
        "PRIOR_TERMINAL_SCOPE",
    )
    protocol.checked(terminal.get("answer"), protocol.FINAL_SCHEMA)
    _need(
        terminal.get("state") == "FINAL_RECORDED_AWAITING_BLIND_SCORING"
        and terminal.get("production") is False
        and terminal.get("training") is False
        and isinstance(terminal.get("artifacts"), dict)
        and terminal["artifacts"].get(f"turn-{handle['turn']:04d}/request.json")
        == handle["request_sha256"],
        "PRIOR_TERMINAL_REQUEST_ARTIFACT",
    )
    old = prior.contracts
    _need(type(old) is CaseContracts, "FULL_PRIOR_CONTRACTS_REQUIRED")
    lineage = old.artifact_lineage
    _hash(prior.expected_artifact_lineage_sha256)
    _need(
        lineage.get("content_sha256") == prior.expected_artifact_lineage_sha256
        and seal_contract(lineage)["content_sha256"] == prior.expected_artifact_lineage_sha256,
        "PRIOR_ARTIFACT_LINEAGE_HASH",
    )
    _need(
        lineage.get("schema") == SCHEMA
        and lineage.get("case_id") == case_id
        and lineage.get("request_sha256") == handle["request_sha256"]
        and lineage.get("turn") == handle["turn"]
        and lineage.get("pins_sha256") == digest(pins.material())
        and lineage.get("contracts_sha256") == _contract_hashes(old.binding)
        and lineage.get("adapter_binding") == _adapter_fields(old.binding)
        and old.binding.context_receipt_sha256 == prior.expected_artifact_lineage_sha256,
        "PRIOR_CONTRACT_BINDING",
    )
    for contract in _contracts(old.binding).values():
        registry.validate_new(contract)
    _need(
        old.binding.query_plan["request_sha256"] == handle["request_sha256"],
        "PRIOR_QUERY_REQUEST_BINDING",
    )
    return {
        "turn": handle["turn"],
        "question": prior.request["question"],
        "due_uploads": deepcopy(prior.request["due_uploads"]),
        "answer": terminal["answer"],
        "request_sha256": handle["request_sha256"],
    }


def build_case_contracts(
    *,
    request: Mapping[str, Any],
    request_sha256: str,
    ordered_history: Sequence[PriorTurn],
    due_uploads: Mapping[str, UploadEvidence],
    jurisdiction: str,
    as_of_date: date,
    issue_id: str,
    pins: ContractPins,
    registry: ContractSchemaRegistry,
    observed_at: datetime,
    encrypt_store: Callable[[bytes, Mapping], Mapping],
    query_variants: Sequence[str],
    missing_facts: Sequence[Mapping],
    budgets: QueryBudgets,
    response_disposition: str,
    answer_route: str,
    affected_claim_sha256: str,
    existing_retrieval_sha256: str,
    gap_class: str,
) -> CaseContracts:
    """Build real selected contracts; missing bindings fail, never get placeholders.

    Own question evidence always exists in this protocol, hence requires_matter
    is always True. SYSTEM_HOLD is refused here because ContractBinding serves
    research lookup; the parent handles holds before lookup. Query variants and
    missing-fact keys are exact host inputs, not generated or confirmed here.
    """
    _need(
        type(pins) is ContractPins and type(registry) is ContractSchemaRegistry,
        "REAL_PINS_AND_REGISTRY_REQUIRED",
    )
    material = pins.material()
    _need(registry.manifest_sha256 == pins.schema_selection_sha256, "SCHEMA_SELECTION_CHANGED")
    _need(callable(encrypt_store), "VERIFIED_ENCRYPT_STORE_REQUIRED")
    stamp = _stamp(observed_at)
    _need(pins.baseline_sealed_at <= observed_at, "BASELINE_SEALED_AFTER_REQUEST")
    protocol.checked(request, protocol.REQUEST_SCHEMA)
    _hash(request_sha256)
    _need(protocol.digest(request) == request_sha256, "REQUEST_HASH_MISMATCH")
    request = deepcopy(dict(request))
    due_uploads = dict(due_uploads)
    _need(request["question"].strip() != "", "EMPTY_QUESTION")
    _need(
        jurisdiction in SUPPORTED_JURISDICTIONS and jurisdiction in request["jurisdictions"],
        "EXPLICIT_JURISDICTION_REQUIRED",
    )
    _need(
        type(as_of_date) is date and request["as_of_date"] == as_of_date.isoformat(),
        "EXPLICIT_DATE_REQUIRED",
    )
    _id(issue_id)
    _hash(affected_claim_sha256)
    _hash(existing_retrieval_sha256)
    _need(gap_class in RESEARCH_GAPS, "NON_RESEARCH_GAP")
    _need(
        response_disposition
        in {"ANSWER", "CLARIFY", "LIMITED", "REFUSE_UNSAFE", "URGENT_NEXT_STEP", "OUT_OF_SCOPE"},
        "UNSUPPORTED_DISPOSITION",
    )
    _need(answer_route in {"direct", "sectioned", "full_enquiry"}, "ANSWER_ROUTE_REQUIRED")
    _need(type(budgets) is QueryBudgets, "EXPLICIT_QUERY_BUDGETS_REQUIRED")
    _need(
        not isinstance(query_variants, str | bytes)
        and 0 < len(query_variants) <= 32
        and all(isinstance(v, str) and 0 < len(v) <= 50000 and v.strip() for v in query_variants),
        "EXACT_QUERY_VARIANTS_REQUIRED",
    )
    variants = list(query_variants)
    missing = deepcopy(list(missing_facts))
    turn, case_id = request["turn"], request["case_id"]
    handles = request["history"]
    _need(
        [h["turn"] for h in handles] == list(range(1, turn))
        and len(ordered_history) == len(handles),
        "ORDERED_OWN_HISTORY_REQUIRED",
    )
    _need(turn <= MAX_USER_TURNS, "FULL_CONVERSATION_MESSAGE_LIMIT")
    history = []
    for index, (prior, handle) in enumerate(zip(ordered_history, handles, strict=True)):
        history.append(
            _validate_prior(prior, handle, case_id=case_id, pins=pins, registry=registry)
        )
        _need(prior.request["history"] == handles[:index], "PRIOR_HISTORY_CHAIN")
        _need(prior.contracts.protocol_history == tuple(history[:-1]), "PRIOR_HISTORY_PROJECTION")
        previous_stamp = datetime.fromisoformat(prior.contracts.artifact_lineage["observed_at"])
        _need(previous_stamp <= observed_at, "HISTORY_TIME_ORDER")
    size = len(protocol.canonical(request)) + sum(
        len(protocol.canonical(p.request)) + len(p.terminal_bytes) for p in ordered_history
    )
    question_bytes = sum(len(h["question"].encode("utf-8")) for h in history)
    question_bytes += len(request["question"].encode("utf-8"))
    _need(question_bytes <= MAX_ESTIMATED_TOKENS, "CONVERSATION_TOKEN_ESTIMATE_LIMIT")
    uploads = request["due_uploads"]
    _need(
        len({u["upload_id"] for u in uploads}) == len(uploads)
        and set(due_uploads) == {u["upload_id"] for u in uploads},
        "EXACT_DUE_UPLOADS_REQUIRED",
    )
    for upload in uploads:
        evidence = due_uploads[upload["upload_id"]]
        _need(
            type(evidence) is UploadEvidence
            and isinstance(evidence.raw, bytes)
            and isinstance(evidence.extraction_receipt, bytes),
            "ACTUAL_UPLOAD_BYTES_REQUIRED",
        )
        size += len(evidence.raw) + len(evidence.extraction_receipt)
        _need(size <= MAX_BYTES, "INPUT_SIZE_LIMIT")
        _need(
            digest(evidence.raw) == upload["sha256"]
            and digest(upload["text"].encode("utf-8")) == upload["text_sha256"]
            and digest(evidence.extraction_receipt) == upload["extraction_sha256"],
            "UPLOAD_RAW_TEXT_EXTRACTION_HASH",
        )
        extraction = load_json_strict(evidence.extraction_receipt)
        _need(
            isinstance(extraction, dict)
            and extraction.get("raw_sha256") == upload["sha256"]
            and extraction.get("text_sha256") == upload["text_sha256"]
            and extraction.get("parser_sha256") == pins.parser_sha256,
            "EXTRACTION_RECEIPT_BINDING",
        )
    _need(size + len(canonical_json_bytes(variants)) <= MAX_BYTES, "INPUT_SIZE_LIMIT")

    seed = {"case_id": case_id, "owner_scope_sha256": pins.owner_scope_sha256}
    conversation_id = _identity("case-conversation", seed)
    turn_seed = {**seed, "turn": turn, "request_sha256": request_sha256}
    last = ordered_history[-1].contracts if ordered_history else None
    messages = deepcopy(last.binding.conversation_snapshot["messages"]) if last else []
    facts = deepcopy(last.binding.fact_snapshot["facts"]) if last else []
    _need(len(facts) + 1 + len(uploads) <= MAX_FACTS, "MATTER_FACT_LIMIT")
    _need(
        [m["ordinal"] for m in messages] == list(range(1, 2 * turn - 1, 2))
        and all(m["role"] == "user" for m in messages),
        "PRIOR_MESSAGE_SCOPE",
    )
    for message, previous in zip(messages, history, strict=True):
        _need(
            message["content_sha256"] == digest(previous["question"].encode("utf-8")),
            "PRIOR_QUESTION_CHANGED",
        )
    artifacts = deepcopy(last.artifact_lineage["evidence_artifacts"]) if last else []
    new_artifacts = []

    def store(raw: bytes, kind: str, source: Mapping) -> Mapping:
        provenance = {
            "schema": "legalbot.ge-case-artifact-provenance.v1",
            **turn_seed,
            "kind": kind,
            "source": dict(source),
            "pins_sha256": digest(material),
            "observed_at": stamp,
            "plaintext_sha256": digest(raw),
        }
        try:
            returned = encrypt_store(raw, deepcopy(provenance))
        except Exception:
            raise ContractBuildError("ENCRYPT_STORE_FAILED") from None
        _need(
            isinstance(returned, Mapping)
            and set(returned)
            == {"encrypted_ref", "plaintext_sha256", "ciphertext_sha256", "receipt_sha256"},
            "ENCRYPT_STORE_RECEIPT_REQUIRED",
        )
        ack = deepcopy(dict(returned))
        ref = _id(ack["encrypted_ref"])
        for key in ("plaintext_sha256", "ciphertext_sha256", "receipt_sha256"):
            _hash(ack[key])
        _need(
            not ref.lower().startswith(
                ("plain:", "plaintext:", "file:", "data:", "http:", "https:")
            )
            and ref.encode() != raw
            and ack["ciphertext_sha256"] != ack["plaintext_sha256"],
            "PLAINTEXT_REFERENCE_DENIED",
        )
        _need(
            ack["plaintext_sha256"] == digest(raw)
            and ack["receipt_sha256"] == digest(encryption_receipt_material(provenance, ack)),
            "ENCRYPT_STORE_UNBOUND_RECEIPT",
        )
        record = {"provenance": provenance, **ack}
        _need(
            not any(a["encrypted_ref"] == ref and a != record for a in artifacts + new_artifacts),
            "ENCRYPTED_REFERENCE_REUSED",
        )
        new_artifacts.append(record)
        return ack

    def fact(text: str, kind: str, source: Mapping, refs: list[dict]) -> dict:
        stored = store(text.encode("utf-8"), kind, source)
        ident = _identity("case-evidence", {**turn_seed, "kind": kind, "source": source})
        return {
            "fact_id": ident,
            "fact_key": ident,
            "data_type": "text",
            "encrypted_value_ref": stored["encrypted_ref"],
            "value_sha256": stored["plaintext_sha256"],
            "origin": "user_statement" if kind == "question" else "document_extraction",
            "status": "stated" if kind == "question" else "extracted",
            "revision": 1,
            "supersedes_fact_id": None,
            "conflict_group_id": None,
            "affected_issue_ids": [issue_id],
            "temporal_scope": {
                "effective_from": None,
                "effective_to": None,
                "as_of_status": "unknown",
            },
            "derivation_rule_sha256": None,
            "created_at": stamp,
            "fact_refs": refs,
        }

    message_id = _identity("case-message", turn_seed)
    question = request["question"]
    question_hash = digest(question.encode("utf-8"))
    current_fact = fact(
        question,
        "question",
        {"message_id": message_id, "request_sha256": request_sha256},
        [
            {
                "source_kind": "message",
                "source_id": message_id,
                "source_revision": 1,
                "content_sha256": question_hash,
                "safe_locator": f"utf8-bytes:0:{len(question.encode('utf-8'))}",
            }
        ],
    )
    facts.append(current_fact)
    messages.append(
        {
            "message_id": message_id,
            "ordinal": 2 * turn - 1,
            "revision": 1,
            "role": "user",
            "encrypted_content_ref": current_fact["encrypted_value_ref"],
            "content_sha256": question_hash,
            "created_at": stamp,
        }
    )
    for upload in uploads:
        source = {
            "upload_id": upload["upload_id"],
            "raw_sha256": upload["sha256"],
            "text_sha256": upload["text_sha256"],
            "extraction_sha256": upload["extraction_sha256"],
        }
        evidence = due_uploads[upload["upload_id"]]
        raw_receipt = store(evidence.raw, "upload-raw", source)
        extraction_receipt = store(evidence.extraction_receipt, "upload-extraction-receipt", source)
        source = {
            **source,
            "raw_encrypted_ref": raw_receipt["encrypted_ref"],
            "extraction_encrypted_ref": extraction_receipt["encrypted_ref"],
        }
        refs = [
            {
                "source_kind": "upload",
                "source_id": raw_receipt["encrypted_ref"],
                "source_revision": 1,
                "content_sha256": upload["sha256"],
                "safe_locator": "whole-raw-upload",
            },
            {
                "source_kind": "upload",
                "source_id": extraction_receipt["encrypted_ref"],
                "source_revision": 1,
                "content_sha256": upload["extraction_sha256"],
                "safe_locator": "text-sha256:" + upload["text_sha256"],
            },
        ]
        facts.append(fact(upload["text"], "upload-extraction", source, refs))
    conversation_material = {
        "schema": "legalbot.conversation-snapshot.v1",
        "conversation_id": conversation_id,
        "owner_scope_sha256": pins.owner_scope_sha256,
        "revision": 2 * turn - 1,
        "created_at": stamp,
        "messages": messages,
        "truncated": bool(history),
        "omitted_message_count": len(history),
        "omitted_before_ordinal": None,
        "truncation_reason": "scope_filter" if history else "none",
        "estimated_tokens": question_bytes,
    }
    conversation = seal_contract(
        {
            **conversation_material,
            "snapshot_id": _identity("conversation-snapshot", conversation_material),
        }
    )
    matter_material = {
        "schema": "legalbot.matter-fact-snapshot.v2",
        "conversation_id": conversation_id,
        "owner_scope_sha256": pins.owner_scope_sha256,
        "conversation_revision": 2 * turn - 1,
        "created_at": stamp,
        "facts": facts,
    }
    matter = seal_contract(
        {**matter_material, "snapshot_id": _identity("matter-snapshot", matter_material)}
    )
    for value in (conversation, matter):
        registry.validate_new(value)
    artifact_count = len(new_artifacts)
    variants_receipt = store(
        canonical_json_bytes(variants), "query-variants", {"request_sha256": request_sha256}
    )
    query = build_query_plan(
        request_id=_identity("case-request", turn_seed),
        request_sha256=request_sha256,
        original_question_sha256=question_hash,
        task_type="general",
        answer_route=answer_route,
        requires_knowledge=True,
        requires_matter=True,
        response_disposition=response_disposition,
        jurisdiction=jurisdiction,
        jurisdiction_status="explicit",
        requested_as_of_date=as_of_date,
        as_of_date_status="explicit",
        issue_ids=[issue_id],
        missing_facts=missing,
        query_variants_ref=variants_receipt["encrypted_ref"],
        query_variants_sha256=variants_receipt["plaintext_sha256"],
        candidate_id=pins.candidate_id,
        policy_sha256=pins.query_policy_sha256,
        config_sha256=pins.config_sha256,
        conversation_snapshot=conversation,
        fact_snapshot=matter,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "host-variants-no-semantic-rewrite",
        },
        risk_flags=["unverified-user-evidence", "semantic-corrections-not-resolved"],
        request_observed_at=observed_at,
        frozen_at=observed_at,
        registry=registry,
        budgets=budgets,
    ).value
    toolchain = {
        key: material[key]
        for key in (
            "parser_sha256",
            "ocr_sha256",
            "chunker_sha256",
            "tokenizer_sha256",
            "embedding_model_sha256",
            "lexical_config_sha256",
            "vector_schema_sha256",
            "reranker_model_sha256",
        )
    }
    baseline = seal_contract(
        {
            "schema": "legalbot.research-empty-baseline.v1",
            "generation_id": pins.baseline_generation_id,
            "source_manifest_sha256": digest([]),
            "qualification_policy_sha256": pins.qualification_policy_sha256,
            "sources": [],
            "toolchain": toolchain,
            "counts": {
                "source_versions": 0,
                "canonical_objects": 0,
                "chunks": 0,
                "lexical_rows": 0,
                "vector_rows": 0,
                "embedding_dimensions": 1024,
            },
            "file_manifest_sha256": digest([]),
            "closure_status": "validated",
            "attestations": [],
            "created_at": material["baseline_created_at"],
            "sealed_at": material["baseline_sealed_at"],
            "non_live": True,
            "production_admission": False,
            "training": False,
        }
    )
    registry.validate_new(baseline)
    contract_values = {
        "query_plan": query,
        "fact_snapshot": matter,
        "conversation_snapshot": conversation,
        "knowledge_generation": baseline,
    }
    adapter_fields = {
        "expected_knowledge_generation_sha256": baseline["content_sha256"],
        "expected_schema_selection_sha256": registry.manifest_sha256,
        "issue_id": issue_id,
        "affected_claim_sha256": affected_claim_sha256,
        "existing_retrieval_sha256": existing_retrieval_sha256,
        "gap_class": gap_class,
    }
    lineage = seal_contract(
        {
            "schema": SCHEMA,
            **turn_seed,
            "observed_at": stamp,
            "pins": material,
            "pins_sha256": digest(material),
            "contracts_sha256": {key: digest(value) for key, value in contract_values.items()},
            "adapter_binding": adapter_fields,
            "protocol_request_digest_profile": "protocol.digest:compact-json-no-newline",
            "contract_digest_profile": "backend.canonical_json_bytes:sorted-json-final-newline",
            "protocol_empty_baseline_sha256": protocol.digest([]),
            "baseline_source_manifest": [],
            "baseline_file_manifest": [],
            "query_plan_sha256": digest(query),
            "prior_artifact_lineage_sha256s": [
                p.expected_artifact_lineage_sha256 for p in ordered_history
            ],
            "protocol_history_sha256": protocol.digest(history),
            "excluded_assistant_messages": [
                {
                    "turn": h["turn"],
                    "ordinal": 2 * h["turn"],
                    "answer_sha256": protocol.digest(h["answer"]),
                    "reason": "no-eligible-blind-review-binding",
                }
                for h in history
            ],
            "current_question_fact_id": current_fact["fact_id"],
            "historical_fact_ids": [f["fact_id"] for f in facts[: len(facts) - len(uploads) - 1]],
            "evidence_artifacts": artifacts + new_artifacts[:artifact_count],
            "query_variants_artifact": new_artifacts[-1],
            "estimated_tokens_method": "utf8-byte-count-conservative-estimate-no-tokenizer-execution",
            "semantic_facts_inferred": False,
            "conditions_confirmed": False,
            "assistant_review_eligibility_assessed": False,
            "encryption_verified_by": "trusted-host-callback",
            "host_custody_verified_here": False,
            "runtime_pin_authenticity_verified_here": False,
            "non_live": True,
            "production_admission": False,
            "training": False,
            "professional_legal_sign_off": False,
            "legal_gold": False,
        }
    )
    binding = ContractBinding(
        registry=registry,
        **contract_values,
        **adapter_fields,
        context_receipt_sha256=lineage["content_sha256"],
    )
    return CaseContracts(binding, lineage, tuple(deepcopy(history)))
