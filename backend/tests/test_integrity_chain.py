from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from scripts.check_system_design import synthesize

from app.contracts import (
    AnswerIntegrityChainVerifier,
    ContractSchemaRegistry,
    IntegrityChainError,
    SelectedAnswerContractStore,
    build_committed_terminal_event,
    build_complete_answer_job,
    build_verified_release,
    canonical_json_bytes,
    committed_terminal_event_id,
    seal_contract,
)
from app.orchestration.object_store import EncryptedObjectStore

ROOT = Path.cwd()
SCHEMAS = ROOT / "docs" / "system-design" / "schemas"


def _make(name: str) -> dict[str, Any]:
    document = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    value = synthesize(document)
    if name == "query-plan.v2.schema.json":
        value.update(
            data_intent="KNOWLEDGE_ONLY",
            response_disposition="ANSWER",
            jurisdiction_status="explicit",
            as_of_date_status="explicit",
        )
    if name == "claim-set.v1.schema.json":
        value["claims"][0]["fact_ids"] = ["fact-abc"]
    if "content_sha256" in document.get("properties", {}):
        value = seal_contract(value)
    return value


def _chain() -> tuple[ContractSchemaRegistry, dict[str, Any]]:
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    conversation = _make("conversation-snapshot.v1.schema.json")
    conversation.update(
        snapshot_id="conversation-snapshot-1",
        conversation_id="conversation-1",
        revision=1,
    )
    conversation = seal_contract(conversation)
    fact = _make("matter-fact-snapshot.v2.schema.json")
    fact.update(
        snapshot_id="fact-snapshot-1",
        conversation_id="conversation-1",
        conversation_revision=1,
    )
    fact = seal_contract(fact)
    plan = _make("query-plan.v2.schema.json")
    plan.update(
        query_plan_id="query-plan-1",
        request_id="request-1",
        request_sha256="1" * 64,
        conversation_snapshot={
            "conversation_id": "conversation-1",
            "revision": 1,
            "content_sha256": conversation["content_sha256"],
            "truncated": conversation["truncated"],
            "omitted_message_count": conversation["omitted_message_count"],
        },
        fact_snapshot_id="fact-snapshot-1",
        candidate_id="candidate-1",
        schema_selection_sha256=registry.manifest_sha256,
        jurisdiction="England and Wales",
        requested_as_of_date="2026-09-01",
    )
    plan_sha256 = hashlib.sha256(canonical_json_bytes(plan)).hexdigest()
    retrieval = _make("retrieval-result.v1.schema.json")
    retrieval.update(
        query_plan_id="query-plan-1",
        query_plan_sha256=plan_sha256,
        candidate_id="candidate-1",
        candidate_sha256="2" * 64,
    )
    retrieval = seal_contract(retrieval)
    evidence = _make("evidence-pack.v1.schema.json")
    evidence.update(
        query_plan_id="query-plan-1",
        query_plan_sha256=plan_sha256,
        retrieval_result_sha256=retrieval["content_sha256"],
        fact_snapshot_sha256=fact["content_sha256"],
        candidate_id="candidate-1",
    )
    evidence = seal_contract(evidence)
    claims = _make("claim-set.v1.schema.json")
    claims.update(
        job_id="job-1",
        query_plan_sha256=plan_sha256,
        fact_snapshot_sha256=fact["content_sha256"],
        evidence_pack_sha256=evidence["content_sha256"],
    )
    claims = seal_contract(claims)
    validation = _make("validation-report.v1.schema.json")
    validation.update(
        validation_report_id="validation-report-1",
        claim_set_sha256=claims["content_sha256"],
        evidence_pack_sha256=evidence["content_sha256"],
        fact_snapshot_sha256=fact["content_sha256"],
    )
    validation_sha256 = hashlib.sha256(canonical_json_bytes(validation)).hexdigest()
    release = _make("verified-release.v1.schema.json")
    release.update(
        release_id="release-1",
        job_id="job-1",
        request_sha256="1" * 64,
        query_plan_sha256=plan_sha256,
        conversation_snapshot_sha256=conversation["content_sha256"],
        fact_snapshot_sha256=fact["content_sha256"],
        retrieval_result_sha256=retrieval["content_sha256"],
        evidence_pack_sha256=evidence["content_sha256"],
        claim_set_sha256=claims["content_sha256"],
        verification_report_sha256=validation_sha256,
        validation_report_id="validation-report-1",
        schema_selection_sha256=registry.manifest_sha256,
        conversation_revision=1,
        response_disposition="ANSWER",
        requested_as_of_date="2026-09-01",
        jurisdiction="England and Wales",
        candidate_sha256="2" * 64,
        terminal_event_id="event-terminal-1",
    )
    release = seal_contract(release)
    terminal = _make("job-event.v1.schema.json")
    terminal.update(
        event_id="event-terminal-1",
        job_id="job-1",
        event="done",
        sequence=9,
        attempt_id="attempt-1",
        lease_generation=1,
    )
    terminal["data"].update(
        terminal_kind="committed",
        release_id="release-1",
        release_sha256=release["content_sha256"],
        status="complete",
        release_state=release["release_state"],
        answer_id=release["answer_id"],
        message_code="job.terminal.committed",
        reset_from_sequence=None,
    )
    answer_job = _make("answer-job.v1.schema.json")
    answer_job.update(
        job_id="job-1",
        request_id="request-1",
        request_sha256="1" * 64,
        conversation_snapshot_sha256=conversation["content_sha256"],
        fact_snapshot_sha256=fact["content_sha256"],
        query_plan_sha256=plan_sha256,
        retrieval_result_sha256=retrieval["content_sha256"],
        evidence_pack_sha256=evidence["content_sha256"],
        claim_set_sha256=claims["content_sha256"],
        validation_report_sha256=validation_sha256,
        release_sha256=release["content_sha256"],
        state="complete",
    )
    answer_job = seal_contract(answer_job)
    return registry, {
        "job_id": "job-1",
        "request_id": "request-1",
        "request_sha256": "1" * 64,
        "conversation_snapshot": conversation,
        "fact_snapshot": fact,
        "query_plan": plan,
        "retrieval_result": retrieval,
        "evidence_pack": evidence,
        "claim_set": claims,
        "validation_report": validation,
        "verified_release": release,
        "terminal_event": terminal,
        "answer_job": answer_job,
    }


def test_complete_chain_closes_every_predecessor_and_terminal_identity() -> None:
    registry, values = _chain()
    receipt = AnswerIntegrityChainVerifier(registry).verify_complete(**values)
    assert receipt.job_id == "job-1"
    assert receipt.terminal_event_id == "event-terminal-1"
    assert len(receipt.object_sha256) == 8
    assert len(receipt.chain_sha256) == 64


def test_substituted_retrieval_digest_stops_release() -> None:
    registry, values = _chain()
    values["evidence_pack"]["retrieval_result_sha256"] = "f" * 64
    values["evidence_pack"] = seal_contract(values["evidence_pack"])
    with pytest.raises(IntegrityChainError, match="evidence retrieval digest"):
        AnswerIntegrityChainVerifier(registry).verify_complete(**values)


def test_release_builders_close_the_real_terminal_digest() -> None:
    registry, values = _chain()
    attempt_id = "attempt-1"
    lease_generation = 1
    sequence = 9
    terminal_id = committed_terminal_event_id(
        job_id="job-1",
        attempt_id=attempt_id,
        lease_generation=lease_generation,
        sequence=sequence,
    )
    validation_sha256 = hashlib.sha256(
        canonical_json_bytes(values["validation_report"])
    ).hexdigest()
    values["validation_report"]["final_disposition"] = "verified_full"
    validation_sha256 = hashlib.sha256(
        canonical_json_bytes(values["validation_report"])
    ).hexdigest()
    release = build_verified_release(
        job_id="job-1",
        answer_id=str(values["verified_release"]["answer_id"]),
        release_state="verified_full",
        answer_content_sha256=str(values["verified_release"]["answer_content_sha256"]),
        request_sha256="1" * 64,
        query_plan=values["query_plan"],
        query_plan_sha256=hashlib.sha256(canonical_json_bytes(values["query_plan"])).hexdigest(),
        conversation_snapshot=values["conversation_snapshot"],
        fact_snapshot=values["fact_snapshot"],
        retrieval_result=values["retrieval_result"],
        evidence_pack=values["evidence_pack"],
        claim_set=values["claim_set"],
        validation_report=values["validation_report"],
        validation_report_sha256=validation_sha256,
        model_sha256="2" * 64,
        prompt_sha256="3" * 64,
        renderer_sha256="4" * 64,
        policy_bundle_sha256="5" * 64,
        repair_count=0,
        parent_answer_id=None,
        outbox_id="outbox-1",
        committed_at=__import__("datetime").datetime(2026, 9, 1, tzinfo=__import__("datetime").UTC),
        terminal_event_id=terminal_id,
        release_reason_codes=("all_material_checks_passed",),
        registry=registry,
    )
    terminal = build_committed_terminal_event(
        verified_release=release,
        attempt_id=attempt_id,
        lease_generation=lease_generation,
        sequence=sequence,
        emitted_at=__import__("datetime").datetime(2026, 9, 1, tzinfo=__import__("datetime").UTC),
        registry=registry,
    )
    answer_job = build_complete_answer_job(
        job_id="job-1",
        request_id="request-1",
        request_sha256="1" * 64,
        idempotency_sha256="6" * 64,
        owner_scope_sha256=str(values["conversation_snapshot"]["owner_scope_sha256"]),
        attempt_id=attempt_id,
        lease_generation=lease_generation,
        conversation_snapshot_sha256=str(values["conversation_snapshot"]["content_sha256"]),
        fact_snapshot_sha256=str(values["fact_snapshot"]["content_sha256"]),
        query_plan_sha256=hashlib.sha256(canonical_json_bytes(values["query_plan"])).hexdigest(),
        retrieval_result_sha256=str(values["retrieval_result"]["content_sha256"]),
        evidence_pack_sha256=str(values["evidence_pack"]["content_sha256"]),
        claim_set_sha256=str(values["claim_set"]["content_sha256"]),
        validation_report_sha256=validation_sha256,
        release_sha256=str(release["content_sha256"]),
        created_at=__import__("datetime").datetime(2026, 9, 1, tzinfo=__import__("datetime").UTC),
        terminal_at=__import__("datetime").datetime(2026, 9, 1, tzinfo=__import__("datetime").UTC),
        registry=registry,
    )
    values.update(
        verified_release=release,
        terminal_event=terminal,
        answer_job=answer_job,
    )
    receipt = AnswerIntegrityChainVerifier(registry).verify_complete(**values)
    assert receipt.terminal_event_id == terminal_id
    assert terminal["data"]["release_sha256"] == release["content_sha256"]


def test_complete_chain_persists_encrypted_immutable_and_unpublished(
    tmp_path, database, cipher
) -> None:
    registry, values = _chain()
    database.create_job(
        job_id="job-1",
        encrypted_question=cipher.encrypt_text("private legal question"),
        question_summary="Private encrypted question",
        request={"word_target": 1500},
        idempotency_key="selected-chain-job-1",
    )
    objects = EncryptedObjectStore(tmp_path / "runtime_objects", database, cipher)
    store = SelectedAnswerContractStore(
        database=database,
        objects=objects,
        registry=registry,
    )

    persisted = store.persist_verified_unpublished(**values)
    repeated = store.persist_verified_unpublished(**values)
    reopened = store.load_verified_unpublished("job-1")

    assert repeated == persisted
    assert reopened == persisted
    assert persisted.status == "verified_unpublished"
    assert len(persisted.object_keys) == 10
    assert (
        database.fetchone(
            "SELECT status,object_count FROM selected_answer_contract_chains WHERE job_id='job-1'"
        )["status"]
        == "verified_unpublished"
    )
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM selected_answer_contract_objects WHERE job_id='job-1'"
        )["n"]
        == 10
    )
    assert database.fetchone("SELECT COUNT(*) AS n FROM release_outbox")["n"] == 0

    plan_key = persisted.object_keys["query_plan"]
    object_row = database.fetchone(
        "SELECT relative_path FROM runtime_objects WHERE object_key=?", (plan_key,)
    )
    encrypted = (tmp_path / "runtime_objects" / object_row["relative_path"]).read_bytes()
    assert b"legalbot.query-plan.v2" not in encrypted
    assert objects.get_json(plan_key) == values["query_plan"]

    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute(
            "UPDATE selected_answer_contract_chains SET status='verified_unpublished' "
            "WHERE job_id='job-1'"
        )
    with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
        database.execute("DELETE FROM selected_answer_contract_chains WHERE job_id='job-1'")
    with pytest.raises(sqlite3.IntegrityError, match="release binding is immutable"):
        database.execute(
            "UPDATE selected_answer_release_bindings SET release_sha256=? WHERE job_id='job-1'",
            ("f" * 64,),
        )


def test_selected_chain_binds_atomically_to_normal_live_outbox(
    tmp_path, database, cipher
) -> None:
    registry, values = _chain()
    answer_text = "Verified selected answer"
    answer_sha256 = hashlib.sha256(answer_text.encode("utf-8")).hexdigest()
    outbox_key = hashlib.sha256(b"release-v1\0job-1").hexdigest()
    outbox_id = f"release-{outbox_key[:40]}"

    release = deepcopy(values["verified_release"])
    release.update(
        answer_id="answer-one",
        answer_content_sha256=answer_sha256,
        outbox_id=outbox_id,
    )
    release = seal_contract(release)
    terminal = deepcopy(values["terminal_event"])
    terminal["data"].update(
        answer_id="answer-one",
        release_sha256=release["content_sha256"],
    )
    answer_job = deepcopy(values["answer_job"])
    answer_job["release_sha256"] = release["content_sha256"]
    answer_job = seal_contract(answer_job)
    values.update(
        verified_release=release,
        terminal_event=terminal,
        answer_job=answer_job,
    )

    database.create_job(
        job_id="job-1",
        encrypted_question=cipher.encrypt_text("private legal question"),
        question_summary="Private encrypted question",
        request={"word_target": 1500},
        idempotency_key="selected-publication-job-1",
    )
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,created_at
        ) VALUES ('candidate-1','active','data/indexes/candidate-1',
                  1,1,1,'embed','rerank','2026-09-01T00:00:00+00:00')
        """
    )
    database.execute(
        "UPDATE jobs SET status='running',stage='verifying',"
        "pinned_index_build_id='candidate-1' WHERE id='job-1'"
    )
    database.store_answer_version(
        answer_id="answer-one",
        job_id="job-1",
        version_number=1,
        version_kind="structured",
        encrypted_content=cipher.encrypt_text(answer_text),
        word_count=3,
        policy_version="test",
        model_version="test",
        index_build_id="candidate-1",
    )
    objects = EncryptedObjectStore(tmp_path / "publication_objects", database, cipher)
    store = SelectedAnswerContractStore(
        database=database,
        objects=objects,
        registry=registry,
    )
    store.persist_verified_unpublished(**values)
    proof = store.load_publication_proof("job-1")
    authority = {
        "schema": "legalbot.owner-quality-normal-live-release-authority.v1",
        "normal_live_ready": True,
        "release_audience": "normal_live",
        "candidate_build_id": "candidate-1",
        "readiness_generation_sha256": "3" * 64,
        "trusted_owner_o04_signature_verified": True,
        "trusted_post_run_owner_acceptance_signature_verified": True,
    }
    authority["seal_sha256"] = hashlib.sha256(
        canonical_json_bytes(authority)
    ).hexdigest()
    database.activate_normal_live_readiness_state(authority, verifier=lambda: authority)

    stale = dict(proof)
    stale["answer_content_sha256"] = "f" * 64
    with pytest.raises(RuntimeError, match="publication proof is absent or stale"):
        database.release_answer_once(
            "answer-one",
            "verified_full",
            normal_live_authority=authority,
            normal_live_authority_verifier=lambda: authority,
            selected_publication_verifier=lambda: stale,
        )
    assert database.fetchone("SELECT COUNT(*) AS n FROM release_outbox")["n"] == 0

    database.release_answer_once(
        "answer-one",
        "verified_full",
        normal_live_authority=authority,
        normal_live_authority_verifier=lambda: authority,
        selected_publication_verifier=lambda: proof,
    )
    outbox = database.fetchone("SELECT * FROM release_outbox WHERE job_id='job-1'")
    publication = database.fetchone(
        "SELECT * FROM selected_answer_publications WHERE job_id='job-1'"
    )
    assert outbox["id"] == outbox_id
    assert outbox["answer_sha256"] == answer_sha256
    assert publication["outbox_id"] == outbox_id
    assert publication["chain_sha256"] == proof["chain_sha256"]
    assert publication["release_sha256"] == proof["release_sha256"]
    assert publication["terminal_event_id"] == proof["terminal_event_id"]
    assert database.job("job-1")["status"] == "complete"
    with pytest.raises(sqlite3.IntegrityError, match="publication is immutable"):
        database.execute(
            "UPDATE selected_answer_publications SET published_at=published_at "
            "WHERE job_id='job-1'"
        )
