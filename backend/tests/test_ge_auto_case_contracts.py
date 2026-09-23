"""Synthetic contracts and real in-memory encryption; no bank, model or file IO.

The actual selected schemas, QueryPlan builder and index ContractBinding validator
run. Synthetic terminal/extraction receipts are fixtures, never custody evidence.
Fernet uses an ephemeral in-memory key, not a host keychain or configured store.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from backend.app.contracts.query_plan import QueryBudgets
from backend.app.contracts.schema_registry import (
    ContractSchemaRegistry,
    canonical_json_bytes,
    seal_contract,
)
from backend.app.research.ge_auto_index import digest
from cryptography.fernet import Fernet
from jsonschema.exceptions import ValidationError
from scripts import ge_auto_case_contracts as c
from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_case_index_adapter import bind_contracts

ROOT = Path(__file__).resolve().parents[2]
STAMP = datetime(2026, 9, 5, 10, tzinfo=UTC)
QUESTION = 'Synthetic request only: "I paid 10 units."\nI have not confirmed any conditions. £ é'


class MemoryVault:
    def __init__(self):
        self.cipher = Fernet(Fernet.generate_key())
        self.blobs = {}
        self.calls = []

    def __call__(self, raw, provenance):
        self.calls.append((raw, deepcopy(provenance)))
        ciphertext = self.cipher.encrypt(raw)
        ref = "enc-" + digest(ciphertext)[:40]
        self.blobs[ref] = ciphertext
        assert self.cipher.decrypt(self.blobs[ref]) == raw
        ack = {
            "encrypted_ref": ref,
            "plaintext_sha256": digest(raw),
            "ciphertext_sha256": digest(ciphertext),
        }
        # Independent host recipe: do not use the helper to mint the test receipt.
        receipt = {
            "schema": "legalbot.ge-case-encrypted-artifact-receipt.v1",
            "provenance_sha256": digest(provenance),
            **ack,
        }
        return {**ack, "receipt_sha256": digest(receipt)}

    def text(self, ref):
        return self.cipher.decrypt(self.blobs[ref]).decode("utf-8")


@pytest.fixture(scope="module")
def registry():
    return ContractSchemaRegistry.from_project_root(ROOT)


def pins(registry):
    values = {
        f.name: digest(("synthetic-pin:" + f.name).encode())
        for f in fields(c.ContractPins)
        if f.name.endswith("_sha256")
    }
    values.update(
        schema_selection_sha256=registry.manifest_sha256,
        ocr_sha256=None,
        candidate_id="candidate-synthetic",
        baseline_generation_id="baseline-synthetic-empty",
        baseline_created_at=STAMP - timedelta(hours=1),
        baseline_sealed_at=STAMP - timedelta(hours=1),
    )
    return c.ContractPins(**values)


def request(question=QUESTION, case_id="case-synthetic", turn=1, history=(), uploads=()):
    return {
        "schema": p.VERSION,
        "case_id": case_id,
        "turn": turn,
        "question": question,
        "jurisdictions": ["England"],
        "as_of_date": "2026-09-05",
        "due_uploads": list(uploads),
        "history": list(history),
    }


def upload(pin):
    raw = b"Raw synthetic UTF-8 upload\nSecond line."
    text = "Raw synthetic UTF-8 upload\nSecond line."
    extraction = canonical_json_bytes(
        {
            "raw_sha256": digest(raw),
            "text_sha256": digest(text.encode()),
            "parser_sha256": pin.parser_sha256,
            "synthetic_test_only": True,
        }
    )
    descriptor = {
        "upload_id": "upload-synthetic",
        "sha256": digest(raw),
        "media_type": "text/plain",
        "text": text,
        "text_sha256": digest(text.encode()),
        "extraction_sha256": digest(extraction),
    }
    return descriptor, c.UploadEvidence(raw, extraction)


def arguments(registry, req=None, vault=None):
    req = req or request()
    return dict(
        request=req,
        request_sha256=p.digest(req),
        ordered_history=[],
        due_uploads={},
        jurisdiction="England",
        as_of_date=date(2026, 9, 5),
        issue_id="issue-synthetic",
        pins=pins(registry),
        registry=registry,
        observed_at=STAMP,
        encrypt_store=vault or MemoryVault(),
        query_variants=["Exact synthetic host query"],
        missing_facts=[],
        budgets=QueryBudgets(20, 20, 8, 4, 2048, 2),
        response_disposition="LIMITED",
        answer_route="full_enquiry",
        affected_claim_sha256=digest(b"synthetic affected claim input"),
        existing_retrieval_sha256=digest(b"synthetic prior retrieval receipt"),
        gap_class="missing_authority",
    )


def seal_prior(req, result):
    terminal = {
        "schema": p.VERSION,
        "case_id": req["case_id"],
        "turn": req["turn"],
        "request_sha256": p.digest(req),
        "policy_sha256": result.artifact_lineage["pins"]["protocol_policy_sha256"],
        "state": "FINAL_RECORDED_AWAITING_BLIND_SCORING",
        "answer": {
            "status": "HOLD",
            "answer": "Synthetic unreviewed assistant answer: deadline 999.",
            "cited_proposition_ids": [],
        },
        "artifacts": {f"turn-{req['turn']:04d}/request.json": p.digest(req)},
        "production": False,
        "training": False,
    }
    raw = p.canonical(terminal)
    handle = {
        "turn": req["turn"],
        "request_sha256": p.digest(req),
        "terminal_sha256": p.digest(raw),
    }
    prior = c.PriorTurn(req, raw, result, result.artifact_lineage["content_sha256"])
    return handle, prior


def followup(registry, with_upload=False):
    vault = MemoryVault()
    args = arguments(registry, vault=vault)
    if with_upload:
        descriptor, evidence = upload(args["pins"])
        args["request"]["due_uploads"] = [descriptor]
        args["request_sha256"] = p.digest(args["request"])
        args["due_uploads"] = {descriptor["upload_id"]: evidence}
    first = c.build_case_contracts(**args)
    handle, prior = seal_prior(args["request"], first)
    current = request(
        "Correction: I said 10 units; I now say 12. That is my statement only.",
        turn=2,
        history=[handle],
    )
    next_args = arguments(registry, current, vault)
    next_args.update(ordered_history=[prior], observed_at=STAMP + timedelta(minutes=1))
    return first, next_args, vault


def test_full_selected_contracts_real_query_builder_and_index_binding(registry, monkeypatch):
    vault = MemoryVault()
    args = arguments(registry, vault=vault)
    descriptor, evidence = upload(args["pins"])
    args["request"]["due_uploads"] = [descriptor]
    args["request_sha256"] = p.digest(args["request"])
    args["due_uploads"] = {descriptor["upload_id"]: evidence}
    called = []
    real = c.build_query_plan

    def capture(**kwargs):
        called.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(c, "build_query_plan", capture)
    result = c.build_case_contracts(**args)
    b = result.binding
    assert b.context_receipt_sha256 == result.artifact_lineage["content_sha256"]
    assert len(called) == 1 and called[0]["requires_matter"] is True
    assert b.query_plan["data_intent"] == "HYBRID"
    lineage = bind_contracts(b, request_sha256=args["request_sha256"])
    assert lineage.request_sha256 == p.digest(args["request"])
    assert b.query_plan["original_question_sha256"] == digest(QUESTION.encode())
    assert lineage.fact_snapshot_sha256 == b.fact_snapshot["content_sha256"]
    for contract in c._contracts(b).values():
        registry.validate_new(contract)
    question_fact, upload_fact = b.fact_snapshot["facts"]
    assert (question_fact["origin"], question_fact["status"]) == ("user_statement", "stated")
    assert (upload_fact["origin"], upload_fact["status"]) == ("document_extraction", "extracted")
    assert vault.text(question_fact["encrypted_value_ref"]) == QUESTION
    assert vault.text(upload_fact["encrypted_value_ref"]) == descriptor["text"]
    assert question_fact["fact_refs"][0]["content_sha256"] == digest(QUESTION.encode())
    assert (
        question_fact["fact_refs"][0]["source_id"]
        == b.conversation_snapshot["messages"][0]["message_id"]
    )
    for ref, expected in zip(
        upload_fact["fact_refs"], [evidence.raw, evidence.extraction_receipt], strict=True
    ):
        assert vault.cipher.decrypt(vault.blobs[ref["source_id"]]) == expected
        assert ref["content_sha256"] == digest(expected)
        assert set(ref) == {
            "source_kind",
            "source_id",
            "source_revision",
            "content_sha256",
            "safe_locator",
        }
    assert b.knowledge_generation["sources"] == []
    assert b.knowledge_generation["file_manifest_sha256"] == digest([])
    assert b.knowledge_generation["source_manifest_sha256"] == digest([]) != p.digest([])
    assert b.knowledge_generation["counts"] == dict(
        source_versions=0,
        canonical_objects=0,
        chunks=0,
        lexical_rows=0,
        vector_rows=0,
        embedding_dimensions=1024,
    )
    assert b.knowledge_generation["non_live"] is True
    assert (
        b.knowledge_generation["production_admission"]
        is b.knowledge_generation["training"]
        is False
    )
    assert b.knowledge_generation["attestations"] == []
    assert (
        vault.text(b.query_plan["query_variants_ref"])
        == canonical_json_bytes(args["query_variants"]).decode()
    )
    assert QUESTION not in str(c._contracts(b)) + str(result.artifact_lineage)
    assert result.artifact_lineage["conditions_confirmed"] is False
    assert (
        result.artifact_lineage["content_sha256"]
        == seal_contract(result.artifact_lineage)["content_sha256"]
    )


def test_followup_keeps_historical_snapshots_exact_and_filters_assistant_role(registry):
    first, args, vault = followup(registry, with_upload=True)
    frozen = deepcopy(c._contracts(first.binding))
    second = c.build_case_contracts(**args)
    assert c._contracts(first.binding) == frozen
    before, after = first.binding, second.binding
    assert after.fact_snapshot["facts"][:2] == before.fact_snapshot["facts"]
    assert after.conversation_snapshot["messages"][0] == before.conversation_snapshot["messages"][0]
    assert [m["ordinal"] for m in after.conversation_snapshot["messages"]] == [1, 3]
    assert [m["role"] for m in after.conversation_snapshot["messages"]] == ["user", "user"]
    assert (
        after.conversation_snapshot["revision"] == after.fact_snapshot["conversation_revision"] == 3
    )
    assert after.conversation_snapshot["truncated"] is True
    assert after.conversation_snapshot["truncation_reason"] == "scope_filter"
    assert after.conversation_snapshot["omitted_message_count"] == 1
    assert after.conversation_snapshot["omitted_before_ordinal"] is None
    current = after.fact_snapshot["facts"][-1]
    assert vault.text(current["encrypted_value_ref"]) == args["request"]["question"]
    assert current["status"] == "stated" and current["supersedes_fact_id"] is None
    assert all(
        f["temporal_scope"] == dict(effective_from=None, effective_to=None, as_of_status="unknown")
        and f["status"] not in {"confirmed", "superseded"}
        for f in after.fact_snapshot["facts"]
    )
    assert "deadline 999" in second.protocol_history[0]["answer"]["answer"]
    assert "deadline 999" not in str(c._contracts(after)) + str(second.artifact_lineage)
    assert after.knowledge_generation == before.knowledge_generation
    bind_contracts(after, request_sha256=args["request_sha256"])
    # Third turn exercises exact complete ordered history, not only a last-message window.
    handle, prior = seal_prior(args["request"], second)
    third_req = request(
        "A further synthetic question.", turn=3, history=[*args["request"]["history"], handle]
    )
    third_args = arguments(registry, third_req, vault)
    third_args.update(
        ordered_history=[*args["ordered_history"], prior], observed_at=STAMP + timedelta(minutes=2)
    )
    third = c.build_case_contracts(**third_args)
    assert len(third.protocol_history) == 2
    assert third.binding.fact_snapshot["facts"][:-1] == second.binding.fact_snapshot["facts"]


@pytest.mark.parametrize(
    "field",
    [
        f.name
        for f in fields(c.ContractPins)
        if f.name.endswith("_sha256") and f.name != "ocr_sha256"
    ],
)
def test_every_required_pin_missing_is_refused_before_storage(registry, field):
    args = arguments(registry)
    args["pins"] = replace(args["pins"], **{field: None})
    with pytest.raises(c.ContractBuildError, match="HASH_REQUIRED"):
        c.build_case_contracts(**args)
    assert args["encrypt_store"].calls == []


@pytest.mark.parametrize(
    "change,error",
    [
        ({"jurisdiction": "California"}, "JURISDICTION"),
        ({"as_of_date": date(2026, 9, 4)}, "DATE"),
        ({"as_of_date": "2026-09-05"}, "DATE"),
        ({"observed_at": datetime(2026, 9, 5)}, "OBSERVED_TIME"),
        ({"encrypt_store": None}, "ENCRYPT_STORE"),
        ({"query_variants": []}, "QUERY_VARIANTS"),
        ({"response_disposition": "SYSTEM_HOLD"}, "DISPOSITION"),
        ({"gap_class": "missing_fact"}, "NON_RESEARCH"),
        ({"due_uploads": {"future-upload": c.UploadEvidence(b"", b"")}}, "DUE_UPLOADS"),
    ],
)
def test_missing_scope_callbacks_and_due_inventory_fail_closed(registry, change, error):
    args = arguments(registry)
    args.update(change)
    with pytest.raises(c.ContractBuildError, match=error):
        c.build_case_contracts(**args)


def test_protocol_digest_and_selected_schema_pins_are_not_interchangeable(registry):
    args = arguments(registry)
    args["request_sha256"] = digest(args["request"])
    with pytest.raises(c.ContractBuildError, match="REQUEST_HASH"):
        c.build_case_contracts(**args)
    args = arguments(registry)
    args["pins"] = replace(args["pins"], schema_selection_sha256=digest(b"wrong schema selection"))
    with pytest.raises(c.ContractBuildError, match="SCHEMA_SELECTION_CHANGED"):
        c.build_case_contracts(**args)


@pytest.mark.parametrize(
    "mode",
    [
        "bad-plaintext",
        "bad-receipt",
        "same-ciphertext",
        "plain-ref",
        "no-receipt",
        "foreign-provenance",
    ],
)
def test_storage_callback_must_bind_actual_bytes_and_provenance(registry, mode):
    vault = MemoryVault()

    def bad(raw, provenance):
        ack = vault(raw, provenance)
        if mode == "bad-plaintext":
            ack["plaintext_sha256"] = digest(b"wrong plaintext")
        if mode == "bad-receipt":
            ack["receipt_sha256"] = digest(b"unbound receipt")
        if mode == "same-ciphertext":
            ack["ciphertext_sha256"] = ack["plaintext_sha256"]
        if mode == "plain-ref":
            ack["encrypted_ref"] = "plaintext:some-text"
        if mode == "no-receipt":
            del ack["receipt_sha256"]
        if mode == "foreign-provenance":
            ack["receipt_sha256"] = digest(
                c.encryption_receipt_material({**provenance, "case_id": "different-case"}, ack)
            )
        return ack

    args = arguments(registry)
    args["encrypt_store"] = bad
    with pytest.raises(c.ContractBuildError, match="ENCRYPT_STORE|PLAINTEXT_REFERENCE"):
        c.build_case_contracts(**args)


def test_callback_failure_does_not_expose_private_error_or_retry(registry):
    calls = []

    def fail(raw, provenance):
        calls.append(provenance)
        raise RuntimeError("Private text must not be in the error")

    args = arguments(registry)
    args["encrypt_store"] = fail
    with pytest.raises(c.ContractBuildError, match="^ENCRYPT_STORE_FAILED$"):
        c.build_case_contracts(**args)
    assert len(calls) == 1


@pytest.mark.parametrize("mode", ["raw", "text", "extraction", "parser"])
def test_actual_upload_and_extraction_binding_required(registry, mode):
    args = arguments(registry)
    descriptor, evidence = upload(args["pins"])
    if mode == "raw":
        evidence = replace(evidence, raw=b"Other bytes")
    if mode == "text":
        descriptor["text"] = "Invented condition confirmed"
    if mode == "extraction":
        evidence = replace(evidence, extraction_receipt=b"{}")
    if mode == "parser":
        receipt = canonical_json_bytes(
            dict(
                raw_sha256=descriptor["sha256"],
                text_sha256=descriptor["text_sha256"],
                parser_sha256=digest(b"wrong parser"),
            )
        )
        evidence = replace(evidence, extraction_receipt=receipt)
        descriptor["extraction_sha256"] = digest(receipt)
    args["request"]["due_uploads"] = [descriptor]
    args["request_sha256"] = p.digest(args["request"])
    args["due_uploads"] = {descriptor["upload_id"]: evidence}
    with pytest.raises(
        c.ContractBuildError, match="UPLOAD_RAW_TEXT_EXTRACTION_HASH|EXTRACTION_RECEIPT_BINDING"
    ):
        c.build_case_contracts(**args)
    assert args["encrypt_store"].calls == []


@pytest.mark.parametrize(
    "mode", ["question", "terminal", "case", "contract", "lineage", "missing-history"]
)
def test_own_history_hashes_cannot_be_replaced_or_inferred(registry, mode):
    _, args, vault = followup(registry)
    before = len(vault.calls)
    prior = args["ordered_history"][0]
    if mode == "question":
        prior = replace(prior, request={**prior.request, "question": "Different history"})
    if mode == "terminal":
        prior = replace(prior, terminal_bytes=prior.terminal_bytes + b" ")
    if mode == "case":
        prior = replace(prior, request={**prior.request, "case_id": "foreign-case"})
    if mode == "contract":
        altered = deepcopy(prior.contracts.binding.fact_snapshot)
        altered["facts"][0]["status"] = "confirmed"
        changed = replace(
            prior.contracts,
            binding=replace(prior.contracts.binding, fact_snapshot=seal_contract(altered)),
        )
        prior = replace(prior, contracts=changed)
    if mode == "lineage":
        prior = replace(prior, expected_artifact_lineage_sha256=digest(b"foreign lineage"))
    args["ordered_history"] = [] if mode == "missing-history" else [prior]
    with pytest.raises(c.ContractBuildError):
        c.build_case_contracts(**args)
    assert len(vault.calls) == before


@pytest.mark.parametrize(
    "constant", ["MAX_USER_TURNS", "MAX_FACTS", "MAX_BYTES", "MAX_ESTIMATED_TOKENS"]
)
def test_resource_limits_fail_before_storage(registry, monkeypatch, constant):
    args = arguments(registry)
    monkeypatch.setattr(c, constant, 0)
    with pytest.raises(c.ContractBuildError, match="LIMIT"):
        c.build_case_contracts(**args)
    assert args["encrypt_store"].calls == []


def test_shared_empty_baseline_has_no_case_or_request_specific_identity(registry):
    first = c.build_case_contracts(**arguments(registry))
    args = arguments(
        registry, request("Another synthetic question.", case_id="other-synthetic-case")
    )
    args["observed_at"] = STAMP + timedelta(hours=2)
    second = c.build_case_contracts(**args)
    assert first.binding.knowledge_generation == second.binding.knowledge_generation
    assert (
        first.binding.conversation_snapshot["conversation_id"]
        != second.binding.conversation_snapshot["conversation_id"]
    )
    production = seal_contract(
        {
            **second.binding.knowledge_generation,
            "schema": "legalbot.knowledge-generation-manifest.v1",
        }
    )
    with pytest.raises(ValidationError):
        registry.validate_new(production)


def test_snapshot_id_binds_actual_immutable_artifact_refs_and_time(registry):
    args = arguments(registry)
    first = c.build_case_contracts(**args)
    frozen = deepcopy(c._contracts(first.binding))
    # A host retry that stores different ciphertext produces new snapshot IDs,
    # never the same snapshot ID purporting to have a different sealed content.
    second = c.build_case_contracts(**args)
    for name in ("conversation_snapshot", "fact_snapshot"):
        a, b = getattr(first.binding, name), getattr(second.binding, name)
        assert a["snapshot_id"] != b["snapshot_id"]
        assert a["content_sha256"] != b["content_sha256"]
    assert c._contracts(first.binding) == frozen


def test_terminal_must_bind_its_actual_own_request_artifact(registry):
    _, args, _ = followup(registry)
    prior = args["ordered_history"][0]
    terminal = p.decode(prior.terminal_bytes)
    terminal["artifacts"]["turn-0001/request.json"] = digest(b"wrong request artifact")
    raw = p.canonical(terminal)
    args["ordered_history"] = [replace(prior, terminal_bytes=raw)]
    args["request"]["history"][0]["terminal_sha256"] = p.digest(raw)
    args["request_sha256"] = p.digest(args["request"])
    with pytest.raises(c.ContractBuildError, match="PRIOR_TERMINAL_REQUEST_ARTIFACT"):
        c.build_case_contracts(**args)
