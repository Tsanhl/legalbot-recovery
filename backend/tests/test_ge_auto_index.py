"""Synthetic dependencies; real local SQLite/LanceDB. NO actual embedding validation.

Run with a fresh --basetemp INSIDE this workspace and -p no:cacheprovider.
No network, model loading, production inputs, ACTIVE or private bank access.
"""

from __future__ import annotations

import copy
import fcntl
import json
import sqlite3
from dataclasses import asdict, replace
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.contracts import ContractSchemaRegistry, build_query_plan, seal_contract
from app.ingestion.models import (
    BlockKind,
    DocumentFormat,
    ParseResult,
    ParseStatus,
    StructuralBlock,
)
from app.research.ge_auto_index import (
    PENDING_EMBEDDING_VALIDATION,
    REVIEW_CHECKS,
    AutoResearchIndex,
    Capture,
    Lineage,
    ModelPin,
    ResearchPolicy,
    RuntimeEmbeddingAdapter,
    Scope,
    digest,
)
from app.retrieval.lancedb import ImmutableLanceRepository

WORKSPACE = Path(__file__).resolve().parents[2]
STAMP = "2026-09-05T00:00:00+00:00"
H = digest(b"synthetic test hash")


class SyntheticEmbeddingDependency:
    """Test-only vectors; never an implementation or evidence of model execution."""

    def __init__(self, pin):
        self.pin = pin
        self.calls = 0
        self.valid = True
        self.failure = False
        self.bad_vector = None

    def verify_binding(self):
        return self.valid

    def embed_documents(self, texts):
        self.calls += 1
        if self.failure:
            raise OSError("synthetic interrupted embedding")
        if self.bad_vector is not None:
            return [self.bad_vector for _ in texts]
        return [[1.0, float("emergency" in text.lower()), *([0.0] * 1022)] for text in texts]

    def embed_query(self, text):
        return self.embed_documents([text])[0]


@pytest.fixture(scope="module")
def registry():
    return ContractSchemaRegistry.from_project_root(WORKSPACE)


def contracts(registry, jurisdiction="England", revision=1):
    conversation = seal_contract(
        {
            "schema": "legalbot.conversation-snapshot.v1",
            "snapshot_id": "conversation-snapshot-test",
            "conversation_id": "conversation-test",
            "owner_scope_sha256": H,
            "revision": revision,
            "created_at": STAMP,
            "messages": [],
            "truncated": False,
            "omitted_message_count": 0,
            "omitted_before_ordinal": None,
            "truncation_reason": "none",
            "estimated_tokens": 0,
        }
    )
    facts = seal_contract(
        {
            "schema": "legalbot.matter-fact-snapshot.v2",
            "snapshot_id": f"facts-test-{revision}",
            "conversation_id": "conversation-test",
            "owner_scope_sha256": H,
            "conversation_revision": revision,
            "created_at": STAMP,
            "facts": [],
        }
    )
    plan = build_query_plan(
        request_id="request-test",
        request_sha256=H,
        original_question_sha256=H,
        task_type="general",
        answer_route="direct",
        requires_knowledge=True,
        requires_matter=True,
        response_disposition="ANSWER",
        jurisdiction=jurisdiction,
        jurisdiction_status="explicit",
        requested_as_of_date=date(2026, 9, 5),
        as_of_date_status="explicit",
        issue_ids=["issue-notice"],
        missing_facts=[],
        query_variants_ref="query-variants-test",
        query_variants_sha256=H,
        candidate_id="candidate-test",
        policy_sha256=H,
        config_sha256=H,
        conversation_snapshot=conversation,
        fact_snapshot=facts,
        rewrite={
            "status": "not_needed",
            "encrypted_query_ref": None,
            "query_sha256": None,
            "reason_code": "standalone",
        },
        risk_flags=[],
        request_observed_at=datetime(2026, 9, 5, tzinfo=UTC),
        frozen_at=datetime(2026, 9, 5, tzinfo=UTC),
        registry=registry,
    ).value
    generation = seal_contract(
        {
            "schema": "legalbot.knowledge-generation-manifest.v1",
            "generation_id": "generation-test",
            "source_manifest_sha256": H,
            "qualification_policy_sha256": H,
            "sources": [
                {
                    "source_version_id": "source-test",
                    "bytes_sha256": H,
                    "canonical_sha256": H,
                    "lane": "primary_authority",
                    "jurisdiction": jurisdiction,
                    "qualification_receipt_sha256": H,
                }
            ],
            "toolchain": {
                **dict.fromkeys(
                    (
                        "parser_sha256",
                        "chunker_sha256",
                        "tokenizer_sha256",
                        "embedding_model_sha256",
                        "lexical_config_sha256",
                        "vector_schema_sha256",
                        "reranker_model_sha256",
                    ),
                    H,
                ),
                "ocr_sha256": None,
            },
            "counts": {
                "source_versions": 1,
                "canonical_objects": 1,
                "chunks": 1,
                "lexical_rows": 1,
                "vector_rows": 1,
                "embedding_dimensions": 1024,
            },
            "file_manifest_sha256": H,
            "closure_status": "validated",
            "attestations": [],
            "created_at": STAMP,
            "sealed_at": STAMP,
        }
    )
    return plan, facts, generation, conversation


def bind(registry, plan, facts, generation, conversation):
    return Lineage.bind(
        registry=registry,
        query_plan=plan,
        fact_snapshot=facts,
        knowledge_generation=generation,
        expected_request_sha256=H,
        expected_knowledge_generation_sha256=generation["content_sha256"],
        conversation_snapshot=conversation,
    )


@pytest.fixture
def env(tmp_path, registry):
    # Refuse accidentally running these persistence tests outside the requested workspace.
    assert tmp_path.is_relative_to(WORKSPACE), "supply fresh workspace-local --basetemp"
    lineage = bind(registry, *contracts(registry))
    scopes = [
        Scope(str(tmp_path / "shared"), "shared_research", "visible-test"),
        Scope(str(tmp_path / "reference"), "private_reference", "synthetic-reference"),
        Scope(str(tmp_path / "case-one"), "candidate_case_local", "synthetic-candidate", "case-1"),
        Scope(str(tmp_path / "case-two"), "candidate_case_local", "synthetic-candidate", "case-2"),
    ]
    pin = ModelPin("1" * 40, H, digest(b"synthetic embedding recipe - NOT MODEL VALIDATION"))
    verified = set()
    policy = ResearchPolicy(
        workspace=tmp_path,
        owner_instruction=b"synthetic owner authorization",
        expected_owner_instruction_sha256=digest(b"synthetic owner authorization"),
        scopes=scopes,
        model=pin,
        reviewers=["reviewer-context"],
        verify_review=lambda reviewer, receipt: digest(receipt) in verified,
    )

    def authorize(action, binding, scope=scopes[0], role="development", actor="research-context"):
        return policy.authorize(
            scope=scope, actor=actor, role=role, action=action, binding_sha256=binding
        )

    cap = authorize("jobs", digest(asdict(lineage)))
    index = AutoResearchIndex(policy=policy, capability=cap, scope=scopes[0], lineage=lineage)
    return SimpleNamespace(
        index=index,
        policy=policy,
        cap=cap,
        lineage=lineage,
        scopes=scopes,
        verified=verified,
        auth=authorize,
        provider=SyntheticEmbeddingDependency(pin),
    )


def start(env, *, gap_class="missing_authority", claim=H):
    gap = env.index.enqueue(
        env.cap,
        issue_id="issue-notice",
        gap_class=gap_class,
        affected_claim_sha256=claim,
        failure_fingerprint=H,
    )
    attempt = env.index.begin_attempt(env.cap, gap, inputs_sha256=H, existing_retrieval_sha256=H)
    return gap, attempt


def captured(env, gap, attempt, *, suffix=""):
    text = "Section 1 Notice requires written delivery." + suffix
    context = "Section 2 An emergency waives the notice requirement."
    parsed = ParseResult(
        ParseStatus.READY,
        DocumentFormat.TEXT,
        (
            StructuralBlock(0, BlockKind.PARAGRAPH, text, source_anchor="section-1", page=1),
            StructuralBlock(1, BlockKind.PARAGRAPH, context, source_anchor="section-2", page=1),
        ),
    )
    source = Capture(
        env.scopes[0],
        "research-context",
        (text + "\n" + context).encode(),
        parsed,
        H,
        "https://synthetic.invalid/notice",
        "https://synthetic.invalid/notice",
        (),
        STAMP,
        "synthetic-notice",
        "legislation",
        "England",
        H,
    )
    operation = env.index.reserve(env.cap, attempt, kind="capture", input_sha256=digest(source.raw))
    source_digest = env.index.capture(env.cap, operation, source)
    review = {
        "reviewer_id": "reviewer-context",
        "capture_sha256": source_digest,
        "source_sha256": digest(source.raw),
        "parsed_sha256": digest(asdict(parsed)),
        "scope": asdict(source.scope),
        "issue_id": "issue-notice",
        "affected_claim_sha256": H,
        "jurisdiction": "England",
        "as_of_date": "2026-09-05",
        "valid_from": "2026-01-01",
        "valid_to": "2026-12-31",
        "checks": sorted(REVIEW_CHECKS),
        "decision": "ELIGIBLE_RESEARCH_ONLY",
        "uncertainties": [],
        "quote": "Notice requires written delivery.",
        "locator": "section-1",
        "quote_block_ordinal": 0,
        "context_block_ordinals": [0, 1],
    }
    env.verified.add(digest(review))
    return source, review


def prepared(env):
    gap, attempt = start(env)
    source, review = captured(env, gap, attempt)
    value = env.index.prepare(env.cap, gap=gap, attempt=attempt, sources=[(source, review)])
    return gap, attempt, value


def built(env):
    gap, attempt, value = prepared(env)
    generation = env.index.build(env.auth("build", value.sha256), value, provider=env.provider)
    return gap, attempt, value, generation


def retrieved(env):
    gap, attempt, value, generation = built(env)
    result = env.index.retrieve(
        env.auth("retrieve", generation),
        build_sha256=value.sha256,
        generation_sha256=generation,
        query="written notice",
        lineage=env.lineage,
        provider=env.provider,
        limit=1,
    )
    return gap, attempt, value, generation, result


def test_selected_contract_lineage_and_corrected_turn(registry):
    plan, facts, generation, conversation = contracts(registry)
    lineage = bind(registry, plan, facts, generation, conversation)
    assert lineage.query_plan_sha256 == digest(plan)
    assert lineage.fact_snapshot_sha256 == facts["content_sha256"]
    assert lineage.knowledge_generation_sha256 == generation["content_sha256"]
    assert lineage.candidate_id == plan["candidate_id"]
    corrected = bind(registry, *contracts(registry, revision=2))
    assert corrected != lineage
    _, facts2, _, _ = contracts(registry, revision=2)
    with pytest.raises(ValueError, match="lineage"):
        bind(registry, plan, facts2, generation, conversation)
    legacy = {**plan, "schema": "legalbot.query-plan.v1"}
    with pytest.raises(ValueError, match="v2"):
        bind(registry, legacy, facts, generation, conversation)
    tampered = {**facts, "conversation_revision": 2}
    with pytest.raises(ValueError):
        bind(registry, plan, tampered, generation, conversation)
    with pytest.raises(ValueError, match="baseline"):
        Lineage.bind(
            registry=registry,
            query_plan=plan,
            fact_snapshot=facts,
            knowledge_generation=generation,
            expected_request_sha256=H,
            expected_knowledge_generation_sha256=digest(b"wrong baseline"),
            conversation_snapshot=conversation,
        )


@pytest.mark.parametrize(
    "jurisdiction",
    [
        "England",
        "Wales",
        "Scotland",
        "Northern Ireland",
        "US federal",
        "California",
        "New York",
        "Texas",
    ],
)
def test_explicit_uk_us_lineage(registry, jurisdiction):
    assert bind(registry, *contracts(registry, jurisdiction)).jurisdiction == jurisdiction


def test_owner_digest_roles_scope_and_capability_tampering(env):
    with pytest.raises(PermissionError, match="owner"):
        ResearchPolicy(
            workspace=env.policy.workspace,
            owner_instruction=b"different instruction",
            expected_owner_instruction_sha256=H,
            scopes=env.scopes,
            model=env.provider.pin,
            reviewers=[],
            verify_review=lambda *_: True,
        )
    with pytest.raises(PermissionError, match="role"):
        env.auth("jobs", H, env.scopes[1], "candidate")
    with pytest.raises(PermissionError):
        env.policy.require(
            replace(env.cap, actor="forged-reviewer"),
            env.scopes[0],
            "jobs",
            env.index.lineage_sha256,
        )
    with pytest.raises(PermissionError):
        env.policy.require(replace(env.cap, action="build"), env.scopes[0], "build", H)
    with pytest.raises(PermissionError):
        AutoResearchIndex(
            policy=env.policy, capability=env.cap, scope=env.scopes[2], lineage=env.lineage
        )
    with pytest.raises(PermissionError, match="disjoint"):
        ResearchPolicy(
            workspace=env.policy.workspace,
            owner_instruction=b"owner",
            expected_owner_instruction_sha256=digest(b"owner"),
            scopes=[env.scopes[0], replace(env.scopes[1], root=env.scopes[0].root + "/nested")],
            model=env.provider.pin,
            reviewers=[],
            verify_review=lambda *_: True,
        )


@pytest.mark.parametrize(("kind", "budget"), [("query", 4), ("capture", 8)])
def test_durable_atomic_budget_counts_failed_and_reserved_work(env, kind, budget):
    gap, attempt = start(env)
    for number in range(budget):
        operation = env.index.reserve(
            env.cap, attempt, kind=kind, input_sha256=digest(str(number).encode())
        )
        assert operation
        if number == 0:
            env.index.finish_operation(
                env.cap, operation, receipt={"error": "synthetic timeout"}, success=False
            )
    assert env.index.reserve(env.cap, attempt, kind=kind, input_sha256=digest(b"0")) is None
    reopened = AutoResearchIndex(
        policy=env.policy, capability=env.cap, scope=env.scopes[0], lineage=env.lineage
    )
    assert (
        reopened.reserve(env.cap, attempt, kind=kind, input_sha256=digest(b"over budget")) is None
    )
    assert reopened.status(gap)["state"] == "HOLD_BUDGET"
    with sqlite3.connect(env.index.root / "metadata.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == budget
        assert db.execute("SELECT count(*) FROM operations WHERE state='FAILED'").fetchone()[0] == 1


def test_bounded_retry_duplicate_noop_and_non_research_hold(env):
    gap, attempt = start(env)
    assert (
        env.index.enqueue(
            env.cap,
            issue_id="issue-notice",
            gap_class="missing_authority",
            affected_claim_sha256=H,
            failure_fingerprint=H,
        )
        == gap
    )
    assert (
        env.index.begin_attempt(env.cap, gap, inputs_sha256=H, existing_retrieval_sha256=H) is None
    )
    env.index.fail_attempt(env.cap, attempt, fingerprint=H, reason="official service blocked")
    with pytest.raises(ValueError, match="documented"):
        env.index.begin_attempt(
            env.cap, gap, inputs_sha256=digest(b"new"), existing_retrieval_sha256=H
        )
    retry = env.index.begin_attempt(
        env.cap,
        gap,
        inputs_sha256=digest(b"new"),
        existing_retrieval_sha256=H,
        change_reason="corrected canonical locator",
    )
    env.index.fail_attempt(env.cap, retry, fingerprint=H, reason="official service still blocked")
    with pytest.raises(ValueError, match="exhausted"):
        env.index.begin_attempt(
            env.cap,
            gap,
            inputs_sha256=digest(b"third"),
            existing_retrieval_sha256=H,
            change_reason="another change",
        )
    assert len(env.index.status(gap)["attempts"]) == 2
    held = env.index.enqueue(
        env.cap,
        issue_id="issue-notice",
        gap_class="missing_user_fact",
        affected_claim_sha256=H,
        failure_fingerprint=H,
    )
    with pytest.raises(ValueError, match="cannot repair"):
        env.index.begin_attempt(env.cap, held, inputs_sha256=H, existing_retrieval_sha256=H)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_sha256", digest(b"different bytes")),
        ("parsed_sha256", digest(b"different parse")),
        ("jurisdiction", "Scotland"),
        ("as_of_date", "2025-09-05"),
        ("valid_to", "2025-12-31"),
        ("quote", "Invented legal proposition"),
        ("locator", "section-99"),
        ("context_block_ordinals", [1]),
        ("checks", ["official_identity"]),
        ("uncertainties", ["commencement unresolved"]),
        ("decision", "APPROVED"),
        ("reviewer_id", "research-context"),
    ],
)
def test_exact_independent_source_eligibility_holds(env, field, value):
    gap, attempt = start(env)
    source, review = captured(env, gap, attempt)
    review[field] = value
    env.verified.add(digest(review))
    with pytest.raises((ValueError, PermissionError)):
        env.index.prepare(env.cap, gap=gap, attempt=attempt, sources=[(source, review)])
    assert env.index.status(gap)["state"] == "RESEARCHING"
    assert not (env.index.root / "builds").exists()
    with sqlite3.connect(env.index.root / "metadata.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM objects WHERE kind='raw_source'").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT count(*) FROM objects WHERE kind='source_review_attempt'"
            ).fetchone()[0]
            == 1
        )


def test_unverified_receipt_and_cross_lane_capture_denied(env):
    gap, attempt = start(env)
    source, review = captured(env, gap, attempt)
    env.verified.clear()
    with pytest.raises(PermissionError, match="independent"):
        env.index.prepare(env.cap, gap=gap, attempt=attempt, sources=[(source, review)])
    operation = env.index.reserve(
        env.cap, attempt, kind="capture", input_sha256=digest(b"cross lane")
    )
    with pytest.raises(PermissionError, match="cross-lane"):
        env.index.capture(env.cap, operation, replace(source, scope=env.scopes[1]))


def test_real_lancedb_readback_context_non_active_duplicate_and_closure(env):
    gap, attempt, value, generation, result = retrieved(env)
    assert env.index.status(gap)["state"] == "INDEXED_PENDING_CLAIM_REVIEW"
    assert len(result["selected_ids"]) == 1
    assert len(result["evidence"]) == 2  # exception context survives a one-hit budget
    assert any("emergency" in row["text"] for row in result["evidence"])
    assert result["lexical_ids"] and result["vector_ids"]
    directory = env.index.root / "builds" / ("ge-auto-" + value.sha256)
    receipt = json.loads((directory / "generation.json").read_bytes())
    assert receipt["embedding_validation"] == PENDING_EMBEDDING_VALIDATION
    assert receipt["chunk_count"] == 2
    assert receipt["model_sha256"] == digest(asdict(env.provider.pin))
    assert (
        not receipt["admitted"]
        and not receipt["legal_gold"]
        and not receipt["qualified_legal_review"]
    )
    env.provider.failure = True
    before = env.provider.calls
    assert (
        env.index.build(env.auth("build", value.sha256), value, provider=env.provider) == generation
    )
    assert env.provider.calls == before
    with pytest.raises(PermissionError, match="GE held"):
        ImmutableLanceRepository(env.index.root).promote(directory.name)
    assert not (env.index.root / "ACTIVE.json").exists()
    assert not (env.index.root / "PREVIOUS.json").exists()
    review = {
        "reviewer_id": "reviewer-context",
        "gap": gap,
        "affected_claim_sha256": H,
        "retrieval_sha256": result["retrieval_sha256"],
        "generation_sha256": generation,
        "lineage_sha256": env.index.lineage_sha256,
        "decision": "VERIFIED_AFFECTED_CLAIM",
        "material_omissions_checked": True,
        "contrary_authority_checked": True,
        "supported_chunk_ids": result["selected_ids"],
    }
    close_cap = env.auth("close_gap", result["retrieval_sha256"])
    with pytest.raises(PermissionError):
        env.index.close_gap(
            close_cap, gap=gap, retrieval_sha256=result["retrieval_sha256"], claim_review=review
        )
    env.verified.add(digest(review))
    env.index.close_gap(
        close_cap, gap=gap, retrieval_sha256=result["retrieval_sha256"], claim_review=review
    )
    assert env.index.status(gap)["state"] == "CLOSED"
    assert env.index.status(gap)["attempts"][-1][2] == "COMPLETE"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("jurisdiction", "Texas"),
        ("as_of_date", "2027-01-01"),
        ("fact_snapshot_sha256", digest(b"corrected facts")),
    ],
)
def test_wrong_jurisdiction_date_and_fact_revision_excluded(env, field, value):
    _, _, prepared_value, generation = built(env)
    calls = env.provider.calls
    with pytest.raises(ValueError, match="lineage"):
        env.index.retrieve(
            env.auth("retrieve", generation),
            build_sha256=prepared_value.sha256,
            generation_sha256=generation,
            query="notice",
            provider=env.provider,
            lineage=replace(env.lineage, **{field: value}),
        )
    assert env.provider.calls == calls


@pytest.mark.parametrize("bad_vector", [[0.0] * 1024, [1.0], [float("nan")] * 1024])
def test_invalid_vectors_preserve_incomplete_attempt(env, bad_vector):
    gap, _, value = prepared(env)
    env.provider.bad_vector = bad_vector
    with pytest.raises(ValueError):
        env.index.build(env.auth("build", value.sha256), value, provider=env.provider)
    incomplete = env.index.root / "builds" / (".ge-auto-" + value.sha256 + ".incomplete")
    assert (incomplete / "build-boundary.json").exists()
    assert env.index.status(gap)["state"] == "HOLD_BUILD"
    before = env.provider.calls
    with pytest.raises(ValueError, match="not running"):
        env.index.build(env.auth("build", value.sha256), value, provider=env.provider)
    assert env.provider.calls == before
    assert incomplete.exists()


def test_model_pin_and_single_job_lock(env):
    _, _, value = prepared(env)
    env.provider.pin = replace(env.provider.pin, files_sha256=digest(b"wrong model files"))
    with pytest.raises(PermissionError, match="pinned"):
        env.index.build(env.auth("build", value.sha256), value, provider=env.provider)
    assert env.provider.calls == 0
    env.provider.pin = env.policy.model
    lock = env.policy.workspace / ".ge-auto-index-embedding.lock"
    with lock.open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError), env.index._embedding_lock(env.provider):
            pytest.fail("concurrent embedding was permitted")


def test_filesystem_generation_tampering_and_cross_case_denial(env):
    _, _, value, generation = built(env)
    cap = env.auth("retrieve", generation, scope=env.scopes[2], role="candidate")
    with pytest.raises(PermissionError):
        env.index.retrieve(
            cap,
            build_sha256=value.sha256,
            generation_sha256=generation,
            query="notice",
            lineage=env.lineage,
            provider=env.provider,
        )
    directory = env.index.root / "builds" / ("ge-auto-" + value.sha256)
    (directory / "unexpected-file").write_bytes(b"tampered generation")
    with pytest.raises(ValueError, match="integrity"):
        env.index.retrieve(
            env.auth("retrieve", generation),
            build_sha256=value.sha256,
            generation_sha256=generation,
            query="notice",
            lineage=env.lineage,
            provider=env.provider,
        )


def test_symlink_and_parent_root_denial(env):
    _, _, value = prepared(env)
    destination = env.policy.workspace / "unrelated"
    destination.mkdir()
    (env.index.root / "builds").symlink_to(destination, target_is_directory=True)
    with pytest.raises(PermissionError, match="symlink"):
        env.index.build(env.auth("build", value.sha256), value, provider=env.provider)
    assert not list(destination.iterdir())
    with pytest.raises(PermissionError, match="cross-root"):
        Scope(str(env.policy.workspace.parent / "escape"), "shared_research", "origin").validate(
            env.policy.workspace
        )
    with pytest.raises(PermissionError, match="cross-root"):
        Scope(str(env.policy.workspace / ".." / "escape"), "shared_research", "origin").validate(
            env.policy.workspace
        )


def test_cannot_close_gap_with_wrong_affected_claim_or_missing_evidence(env):
    gap, _, _, generation, result = retrieved(env)
    review = {
        "reviewer_id": "reviewer-context",
        "gap": gap,
        "affected_claim_sha256": digest(b"different claim"),
        "retrieval_sha256": result["retrieval_sha256"],
        "generation_sha256": generation,
        "lineage_sha256": env.index.lineage_sha256,
        "decision": "VERIFIED_AFFECTED_CLAIM",
        "material_omissions_checked": True,
        "contrary_authority_checked": True,
        "supported_chunk_ids": [],
    }
    env.verified.add(digest(review))
    with pytest.raises(ValueError, match="affected-claim"):
        env.index.close_gap(
            env.auth("close_gap", result["retrieval_sha256"]),
            gap=gap,
            retrieval_sha256=result["retrieval_sha256"],
            claim_review=review,
        )
    assert env.index.status(gap)["state"] != "CLOSED"


def test_prepared_bytes_cannot_be_substituted(env):
    _, _, value = prepared(env)
    forged = replace(value, payload=value.payload + b" ")
    with pytest.raises(PermissionError):
        env.index.build(env.auth("build", value.sha256), forged, provider=env.provider)
    raw = copy.deepcopy(json.loads(value.payload))
    raw["sources"][0]["jurisdiction"] = "Texas"
    assert digest(raw) != value.sha256


def test_runtime_adapter_binds_actual_identity_format_without_inference():
    identity = {
        "source_repo": "Qwen/Qwen3-Embedding-0.6B",
        "revision": "2" * 40,
        "file_manifest_sha256": H,
        "directory": "models/synthetic",
        "dimensions": 1024,
        "local_files_only": True,
        "device": "cpu",
        "max_tokens": 2048,
        "batch_size": 1,
        "torch_threads": 2,
        "normalise_embeddings": True,
        "training": False,
    }
    identity["identity_sha256"] = digest(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )
    session = SimpleNamespace(identity=identity, provider=object())
    provider = RuntimeEmbeddingAdapter(
        session, expected_identity=identity, verify_identity=lambda: identity
    )
    assert provider.verify_binding()
    assert provider.pin == ModelPin.from_runtime_identity(identity)
    session.identity = {**identity, "revision": "3" * 40}
    assert provider.verify_binding() is False
    session.identity = identity
    session.provider = None
    assert provider.verify_binding() is False
    with pytest.raises(ValueError, match="identity digest"):
        ModelPin.from_runtime_identity({**identity, "dimensions": 768})


def test_mutated_source_bytes_in_sqlite_deny_retrieval(env):
    _, _, value, generation = built(env)
    with sqlite3.connect(env.index.root / "metadata.sqlite3") as db:
        db.execute("UPDATE objects SET payload=? WHERE kind='raw_source'", (b"wrong source bytes",))
    with pytest.raises(ValueError, match="modified exact"):
        env.index.retrieve(
            env.auth("retrieve", generation),
            build_sha256=value.sha256,
            generation_sha256=generation,
            query="notice",
            lineage=env.lineage,
            provider=env.provider,
        )


def test_wrong_owner_fact_and_unsupported_jurisdiction_hold(registry):
    plan, facts, generation, conversation = contracts(registry)
    foreign = seal_contract({**facts, "owner_scope_sha256": digest(b"different owner")})
    with pytest.raises(ValueError, match="lineage"):
        bind(registry, plan, foreign, generation, conversation)
    with pytest.raises(ValueError, match="scope"):
        bind(registry, *contracts(registry, "Puerto Rico"))


def test_published_generation_recovers_sqlite_commit_without_inference(env, monkeypatch):
    gap, _, value = prepared(env)
    original = env.index._record_generation

    def interrupted(*args):
        raise OSError("synthetic interruption after publish")

    monkeypatch.setattr(env.index, "_record_generation", interrupted)
    cap = env.auth("build", value.sha256)
    with pytest.raises(OSError, match="after publish"):
        env.index.build(cap, value, provider=env.provider)
    assert env.index.status(gap)["state"] == "HOLD_BUILD"
    monkeypatch.setattr(env.index, "_record_generation", original)
    env.provider.failure = True
    calls = env.provider.calls
    assert env.index.build(cap, value, provider=env.provider)
    assert env.provider.calls == calls
    assert env.index.status(gap)["state"] == "INDEXED_PENDING_CLAIM_REVIEW"
    assert env.index.status(gap)["attempts"][-1][-1] == "synthetic interruption after publish"


def test_historical_generation_retained_but_not_readable_under_new_date(env, registry):
    _, _, value, generation = built(env)
    plan, facts, baseline, conversation = contracts(registry)
    later = bind(
        registry, {**plan, "requested_as_of_date": "2027-01-01"}, facts, baseline, conversation
    )
    cap = env.auth("jobs", digest(asdict(later)))
    later_index = AutoResearchIndex(
        policy=env.policy, capability=cap, scope=env.scopes[0], lineage=later
    )
    with pytest.raises(PermissionError, match="lineage"):
        later_index.retrieve(
            env.auth("retrieve", generation),
            build_sha256=value.sha256,
            generation_sha256=generation,
            query="notice",
            lineage=later,
            provider=env.provider,
        )
    assert (env.index.root / "builds" / ("ge-auto-" + value.sha256) / "generation.json").exists()
