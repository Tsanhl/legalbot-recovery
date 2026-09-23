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
    ClaimContractInput,
    ContractSchemaRegistry,
    IntegrityChainError,
    QualifiedEvidenceInput,
    SelectedAnswerContractStore,
    ValidationCheckInput,
    build_claim_set,
    build_committed_terminal_event,
    build_complete_answer_job,
    build_retrieval_evidence_contracts,
    build_validation_report,
    build_verified_release,
    canonical_json_bytes,
    committed_terminal_event_id,
    seal_contract,
)
from app.orchestration.object_store import EncryptedObjectStore
from app.types import EvidenceSpan, MaterialLane

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
    fact_item_schema = json.loads(
        (SCHEMAS / "matter-fact-snapshot.v2.schema.json").read_text(encoding="utf-8")
    )["properties"]["facts"]["items"]
    fact_item = synthesize(fact_item_schema)
    fact_item.update(
        fact_id="fact-1",
        fact_key="consumer.condition",
        data_type="text",
        encrypted_value_ref="encrypted-fact-1",
        value_sha256="a" * 64,
        origin="user_confirmation",
        status="confirmed",
        supersedes_fact_id=None,
        conflict_group_id=None,
        affected_issue_ids=["issue-1"],
        derivation_rule_sha256=None,
    )
    fact["facts"] = [fact_item]
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
        issue_ids=["issue-1"],
    )
    plan["budgets"]["final_top_k"] = 1
    plan["budgets"]["context_tokens"] = 200
    plan_sha256 = hashlib.sha256(canonical_json_bytes(plan)).hexdigest()
    contracts = build_retrieval_evidence_contracts(
        query_plan=plan,
        query_plan_sha256=plan_sha256,
        candidate_sha256="2" * 64,
        evidence=(
            QualifiedEvidenceInput(
                span=EvidenceSpan(
                    id="evidence-1",
                    source_version_id="source-version-1",
                    chunk_id="chunk-1",
                    text="Private evidence text is held outside the contract.",
                    locator="section 1",
                    lane=MaterialLane.PRIMARY_AUTHORITY,
                    jurisdiction="England and Wales",
                    subject="consumer",
                    citation_data={
                        "reviewed_as_of": "2026-09-01",
                        "commencement_status": "not_applicable",
                    },
                    currentness_status="qualified_current",
                    content_sha256="b" * 64,
                    index_build_id="candidate-1",
                    retrieval_relevance_score=0.9,
                    retrieval_route="hybrid_rrf",
                    retrieval_threshold=0.5,
                    retrieval_threshold_policy_sha256="c" * 64,
                    retrieval_threshold_qualified=True,
                    retrieval_qualification_reason="threshold_qualified",
                    legal_role="statutory_rule",
                    provision_extent_status="verified",
                    identity_verified=True,
                    currentness_verified=True,
                ),
                issue_ids=("issue-1",),
                selected_token_count=100,
                selected_rank=1,
            ),
        ),
        fact_snapshot_sha256=fact["content_sha256"],
        created_at=__import__("datetime").datetime(
            2026, 9, 1, tzinfo=__import__("datetime").UTC
        ),
        registry=registry,
    )
    retrieval = dict(contracts.retrieval_result)
    evidence = dict(contracts.evidence_pack)
    claims = build_claim_set(
        job_id="job-1",
        draft_id="draft-1",
        draft_sha256="d" * 64,
        query_plan_sha256=plan_sha256,
        fact_snapshot_sha256=fact["content_sha256"],
        evidence_pack_sha256=evidence["content_sha256"],
        claims=(
            ClaimContractInput(
                claim_id="claim-rule",
                kind="legal_rule",
                encrypted_text_ref="encrypted-claim-rule",
                text_sha256="e" * 64,
                materiality_basis="issue_element",
                issue_ids=("issue-1",),
                evidence_ids=("evidence-1",),
            ),
            ClaimContractInput(
                claim_id="claim-fact",
                kind="user_fact",
                encrypted_text_ref="encrypted-claim-fact",
                text_sha256="f" * 64,
                materiality_basis="issue_element",
                issue_ids=("issue-1",),
                fact_ids=("fact-1",),
            ),
            ClaimContractInput(
                claim_id="claim-application",
                kind="application",
                encrypted_text_ref="encrypted-claim-application",
                text_sha256="0" * 64,
                materiality_basis="outcome_premise",
                issue_ids=("issue-1",),
                fact_ids=("fact-1",),
                evidence_ids=("evidence-1",),
                depends_on_claim_ids=("claim-rule", "claim-fact"),
            ),
        ),
        created_at=__import__("datetime").datetime(
            2026, 9, 1, tzinfo=__import__("datetime").UTC
        ),
        registry=registry,
    )
    all_claims = ("claim-rule", "claim-fact", "claim-application")
    checks = []
    affected_by_kind = {
        "identity": all_claims,
        "privacy": all_claims,
        "output_shape": all_claims,
        "fact_provenance": ("claim-fact", "claim-application"),
        "evidence_support": ("claim-rule", "claim-application"),
        "currentness": ("claim-rule", "claim-application"),
        "citation": ("claim-rule", "claim-application"),
        "contradiction": ("claim-rule", "claim-application"),
    }
    for number, (kind, affected_ids) in enumerate(affected_by_kind.items(), start=1):
        checks.append(
            ValidationCheckInput(
                check_id=f"check-{number}",
                kind=kind,  # type: ignore[arg-type]
                result="PASS",
                material=True,
                reason_code="verified",
                affected_ids=affected_ids,
                validator_sha256=str(number) * 64,
                input_sha256=str(number) * 64,
            )
        )
    frozen_validation = build_validation_report(
        draft_id="draft-1",
        draft_sha256="d" * 64,
        validator_bundle_sha256="9" * 64,
        checks=tuple(checks),
        advisory_status="PASS",
        advisory_report_sha256="8" * 64,
        repair_parent_id=None,
        requested_disposition="verified_full",
        claim_set_sha256=claims["content_sha256"],
        evidence_pack_sha256=evidence["content_sha256"],
        fact_snapshot_sha256=fact["content_sha256"],
        policy_sha256=plan["policy_sha256"],
        created_at=__import__("datetime").datetime(
            2026, 9, 1, tzinfo=__import__("datetime").UTC
        ),
        registry=registry,
    )
    validation = frozen_validation.value
    validation_sha256 = frozen_validation.content_sha256
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
        validation_report_id=validation["validation_report_id"],
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


def test_release_stops_when_application_loses_fact_dependency() -> None:
    registry, values = _chain()
    application = next(
        claim
        for claim in values["claim_set"]["claims"]
        if claim["claim_id"] == "claim-application"
    )
    application["depends_on_claim_ids"] = ["claim-rule"]
    values["claim_set"] = seal_contract(values["claim_set"])
    with pytest.raises(ValueError, match="legal-rule and user-fact"):
        AnswerIntegrityChainVerifier(registry).verify_complete(**values)


def test_release_stops_when_currentness_review_predates_requested_date() -> None:
    registry, values = _chain()
    values["evidence_pack"]["selected"][0]["reviewed_as_of"] = "2026-08-31"
    values["evidence_pack"] = seal_contract(values["evidence_pack"])
    with pytest.raises(ValueError, match="predates the requested date"):
        AnswerIntegrityChainVerifier(registry).verify_complete(**values)


def test_release_stops_when_material_claim_has_no_check_coverage() -> None:
    registry, values = _chain()
    check = next(
        item
        for item in values["validation_report"]["checks"]
        if item["kind"] == "evidence_support"
    )
    check["affected_ids"] = ["claim-rule"]
    with pytest.raises(ValueError, match="material claim lacks a passing evidence_support"):
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
    with pytest.raises(RuntimeError, match="atomically replayed normal-live authority"):
        database.release_answer_once(
            "answer-one", "verified_full", selected_publication_verifier=lambda: proof,
        )
    assert database.fetchone("SELECT COUNT(*) AS n FROM release_outbox")["n"] == 0
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
