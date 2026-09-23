"""Synthetic dependency tests, NOT model, legal, Lance or custody validation.

Run .venv/bin/python -B -m unittest backend.tests.test_ge_auto_case_index_adapter -v
Only code/schema reads. All filesystem writes are replaced by a memory store;
SQLite is :memory:. Real contracts, capability checks, parser models, structural
chunker, backend enqueue/capture/prepare and metadata readback execute. Lance,
embeddings and optional reranking are explicit dependency fakes, never proof.

All full contracts validate through the real selected registry, including the
distinct research-empty-baseline.v1. The production knowledge-generation contract
is never weakened, substituted or supplied a dummy baseline source.
"""

from __future__ import annotations

import base64
import copy
import json
import sqlite3
import unittest
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import patch

from backend.app.contracts import ContractSchemaRegistry, build_query_plan, seal_contract
from backend.app.ingestion.models import BlockKind, DocumentFormat, ParseResult, ParseStatus, StructuralBlock
from backend.app.research import ge_auto_index as real
from scripts import ge_auto_case_index_adapter as a
from scripts import ge_auto_case_protocol as p


ROOT = Path(__file__).resolve().parents[2]
CASE = ROOT / "synthetic-unit-only-case"
STAMP = "2026-09-05T00:00:00+00:00"
H = p.digest(b"synthetic unit dependency identity, NOT an execution receipt")
RETRY = p.digest(b"synthetic frozen retry profile")


class MemoryStore:
    """No filesystem artifacts or cleanup. Exclusive creation and digest checks."""
    pool = {}

    def __new__(cls, root):
        key = str(root)
        if key not in cls.pool:
            obj = super().__new__(cls)
            obj.root, obj.files, obj.dirs, obj.locked = Path(root), {}, set(), False
            cls.pool[key] = obj
        return cls.pool[key]

    def __init__(self, root):
        pass

    def exists(self, name):
        p.parts(name)
        return name in self.files or name in self.dirs

    def read(self, name):
        p.parts(name)
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]

    def write_new(self, name, raw):
        p.parts(name)
        if self.exists(name):
            raise FileExistsError(name)
        self.files[name] = bytes(raw)

    def mkdir_new(self, name):
        p.parts(name)
        if self.exists(name):
            raise FileExistsError(name)
        self.dirs.add(name)

    @contextmanager
    def lock(self):
        if self.locked:
            raise BlockingIOError()
        self.locked = True
        try:
            yield
        finally:
            self.locked = False


def contracts(registry):
    conv = seal_contract({"schema": "legalbot.conversation-snapshot.v1",
        "snapshot_id": "conversation-snapshot-synthetic", "conversation_id": "conversation-synthetic",
        "owner_scope_sha256": H, "revision": 1, "created_at": STAMP, "messages": [],
        "truncated": False, "omitted_message_count": 0, "omitted_before_ordinal": None,
        "truncation_reason": "none", "estimated_tokens": 0})
    facts = seal_contract({"schema": "legalbot.matter-fact-snapshot.v2",
        "snapshot_id": "facts-synthetic", "conversation_id": "conversation-synthetic",
        "owner_scope_sha256": H, "conversation_revision": 1, "created_at": STAMP, "facts": []})
    plan = build_query_plan(request_id="request-synthetic", request_sha256=H, original_question_sha256=H,
        task_type="general", answer_route="direct", requires_knowledge=True, requires_matter=True,
        response_disposition="ANSWER", jurisdiction="England", jurisdiction_status="explicit",
        requested_as_of_date=date(2026, 9, 5), as_of_date_status="explicit", issue_ids=["issue-notice"],
        missing_facts=[], query_variants_ref="queries-synthetic", query_variants_sha256=H,
        candidate_id="candidate-synthetic", policy_sha256=H, config_sha256=H,
        conversation_snapshot=conv, fact_snapshot=facts, rewrite={"status": "not_needed",
        "encrypted_query_ref": None, "query_sha256": None, "reason_code": "standalone"}, risk_flags=[],
        request_observed_at=datetime(2026, 9, 5, tzinfo=UTC), frozen_at=datetime(2026, 9, 5, tzinfo=UTC),
        registry=registry).value
    gen = seal_contract({"schema": "legalbot.research-empty-baseline.v1",
        "generation_id": "generation-synthetic-empty", "source_manifest_sha256": real.digest([]),
        "qualification_policy_sha256": H, "sources": [], "toolchain": {
            **dict.fromkeys(("parser_sha256", "chunker_sha256", "tokenizer_sha256", "embedding_model_sha256",
                            "lexical_config_sha256", "vector_schema_sha256", "reranker_model_sha256"), H),
            "ocr_sha256": None},
        "counts": {"source_versions": 0, "canonical_objects": 0, "chunks": 0, "lexical_rows": 0,
                   "vector_rows": 0, "embedding_dimensions": 1024}, "file_manifest_sha256": H,
        "closure_status": "validated", "attestations": [], "created_at": STAMP, "sealed_at": STAMP,
        "non_live": True, "production_admission": False, "training": False})
    return a.ContractBinding(registry, plan, facts, conv, gen, gen["content_sha256"],
                             registry.manifest_sha256, "issue-notice", H, H, "missing_authority", H)


def source(scope, number, text):
    url = f"https://www.legislation.gov.uk/synthetic-only-{number}"
    raw = ("<synthetic>" + text + "</synthetic>").encode()
    block = StructuralBlock(1, BlockKind.PARAGRAPH, text, source_anchor=f"synthetic-part-{number}")
    capture = real.Capture(scope, "researcher-synthetic", raw,
        ParseResult(ParseStatus.READY, DocumentFormat.XML, (block,)), H, url, url, (), STAMP,
        f"synthetic-source-{number}", "official-primary", "England", H)
    original = {"canonical_url": url, "final_url": url, "redirect_chain": [], "fetched_at": STAMP,
        "raw_b64": base64.b64encode(raw).decode(), "parser_sha256": H, "parser_receipt_sha256": H,
        "parts": [{"part_id": "p1", "parent_id": None, "locator": block.source_anchor, "text": text}]}
    span = {"source_sha256": real.digest(raw), "part_id": "p1", "start": 0, "end": len(text), "text": text}
    return a.SourceBinding(capture, {"p1": 1}, (1,)), original, span


class FakeSession:
    """Synthetic vectors in memory only. Not an actual Qwen provider."""
    def __init__(self, host):
        self.host, self.identity, self.provider, self.calls = host, copy.deepcopy(host.identity), None, []

    def __enter__(self):
        if self.host.active:
            raise AssertionError("test single-model lease overlap")
        self.host.active = True
        self.provider = object()
        self.host.events.append("embedding-enter")
        return self

    def __exit__(self, *_):
        self.host.events.append("embedding-exit")
        if not self.host.leak_session:
            self.provider = None
            self.host.active = False

    def embed_documents(self, texts):
        self.host.events.append("embed-documents")
        if self.host.fail_embedding:
            raise RuntimeError("synthetic interrupted dependency")
        self.calls.extend({"kind": "document", "text_sha256": p.digest(text.encode()),
                           "tokens": len(text.split()), "vector_sha256": H, "seconds": 0.0}
                          for text in texts)
        return [[1.0] + [0.0] * 1023 for _ in texts]

    def embed_query(self, text):
        self.host.events.append("embed-query")
        self.calls.append({"kind": "query", "text_sha256": p.digest(text.encode()),
                           "tokens": len(text.split()), "vector_sha256": H, "seconds": 0.0})
        return [1.0] + [0.0] * 1023

    def receipt(self):
        # A protocol-shaped dependency fake. It never leaves this in-memory test.
        return {"schema": "legalbot.ge-auto-research-embedding-inference.v1",
            "model_identity": self.identity, "calls": self.calls, "actual_inference_calls": len(self.calls),
            "provider": "PINNED_LOCAL_QWEN", "synthetic_vectors": False, "training": False}


class MemoryIndex(real.AutoResearchIndex):
    """Real SQLite job/prepare code; explicit fake Lance build/retrieval dependency."""
    host = None

    def __init__(self, **kwargs):
        # Only suppress the actual directory mkdir. _db below is exclusively in memory.
        with patch.object(Path, "mkdir", return_value=None):
            super().__init__(**kwargs)

    @contextmanager
    def _db(self):
        conn = self.host.sqlite
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    def build(self, cap, prepared, *, provider):
        self.policy.require(cap, self.scope, "build", prepared.sha256)
        data = self._get(prepared.sha256, "prepared_build")
        if prepared.sha256 in self.host.generations:
            return self._read_generation(prepared.sha256)[0]["generation_sha256"]
        self.host.events.append("fake-lance-build")
        provider.embed_documents([r["text"] for r in data["rows"]])
        material = {"build_sha256": prepared.sha256, "scope": asdict(self.scope),
                    "lineage": asdict(self.lineage), "rows_sha256": real.digest(data["rows"])}
        receipt = {**material, "generation_sha256": real.digest(material)}
        self.host.generations[prepared.sha256] = receipt
        self._record_generation(data, receipt)
        return receipt["generation_sha256"]

    def _read_generation(self, key):
        result = copy.deepcopy(self.host.generations[key])
        body = {k: v for k, v in result.items() if k != "generation_sha256"}
        if real.digest(body) != result["generation_sha256"]:
            raise ValueError("synthetic persisted generation tamper")
        prepared = self._get(key, "prepared_build")
        self._verify_sources(prepared)
        if real.digest(prepared["rows"]) != result["rows_sha256"]:
            raise ValueError("synthetic persisted row tamper")
        return result, self.root

    def retrieve(self, cap, *, build_sha256, generation_sha256, query, lineage, provider, limit):
        self.policy.require(cap, self.scope, "retrieve", generation_sha256)
        provider.embed_query(query)
        self.host.events.append("fake-lance-retrieve")
        build = self._get(build_sha256, "prepared_build")
        self._read_generation(build_sha256)
        # Querying the point returns ONLY that source. Companion query must really run.
        matching = [review for review in build["reviews"] if review["quote"] == query]
        capture_sha = (matching[0] if matching else build["reviews"][0])["capture_sha256"]
        rows = [r for r in build["rows"] if r["capture_sha256"] == capture_sha]
        if self.host.drop_companion and matching and matching[0] == build["reviews"][-1]:
            rows = []
        value = {"schema": "legalbot.ge-auto-index-retrieval.v1", "scope": asdict(self.scope),
            "lineage": asdict(lineage), "build_sha256": build_sha256,
            "generation_sha256": generation_sha256, "query_sha256": real.digest(query.encode()),
            "retrieval_runtime_sha256": self.host.pins.index_runtime_sha256, "selected_ids": [r["id"] for r in rows],
            "evidence": rows, "retriever_id": cap.actor, "lexical_ids": [r["id"] for r in rows],
            "vector_ids": [r["id"] for r in rows]}
        with self._db() as conn:
            key = self._put(conn, "retrieval", value)
        if self.host.change_returned_row and value["evidence"]:
            value["evidence"][0]["text"] = "tampered dependency response"
        return {**value, "retrieval_sha256": key}


class Host:
    def __init__(self, actual_registry):
        self.events, self.active, self.leak_session, self.fail_embedding = [], False, False, False
        self.drop_companion = self.change_returned_row = False
        self.denied_action, self.trust_policy_reviews = None, True
        self.verified = set()
        self.sqlite = sqlite3.connect(":memory:", isolation_level=None)
        self.generations = {}
        self.scope = real.Scope(str(CASE / "legal-index"), "candidate_case_local", "synthetic-run", "case-synthetic")
        self.identity = {"source_repo": "Qwen/Qwen3-Embedding-0.6B", "revision": "1" * 40,
            "file_manifest_sha256": H, "directory": "synthetic-not-a-model", "dimensions": 1024,
            "local_files_only": True, "device": "cpu", "max_tokens": 2048, "batch_size": 1,
            "torch_threads": 2, "normalise_embeddings": True, "training": False}
        self.identity["identity_sha256"] = real.digest(json.dumps(self.identity, sort_keys=True, separators=(",", ":")).encode())
        self.policy = real.ResearchPolicy(workspace=ROOT, owner_instruction=b"synthetic authorization",
            expected_owner_instruction_sha256=real.digest(b"synthetic authorization"), scopes=[self.scope],
            model=real.ModelPin.from_runtime_identity(self.identity), reviewers=["reviewer-synthetic"],
            verify_review=self.policy_review)
        self.contract = contracts(actual_registry)
        primary = source(self.scope, 1, "Synthetic requirement applies subject to the companion definition.")
        companion = source(self.scope, 2, "Synthetic definition and exception. Effective 2026-01-01 to 2026-12-31.")
        self.sources = (primary[0], companion[0])
        self.prop = {"proposition_id": "prop-synthetic", "jurisdiction": "England", "as_of_date": "2026-09-05",
            "point": primary[2], "conditions": [companion[2]], "context": [companion[2]],
            "currentness": {"status": "VERIFIED", "checks": [companion[2]],
                           "valid_from": "2026-01-01", "valid_to": "2026-12-31"}}
        output = {"sources": [{"source_sha256": real.digest(s.capture.raw), "decision": "ELIGIBLE",
            "checks": dict.fromkeys(p.SOURCE_CHECKS, True), "holds": []} for s in self.sources],
            "propositions": [{"proposition_id": self.prop["proposition_id"], "proposition_sha256": p.digest(self.prop),
                "decision": "ELIGIBLE", "checks": dict.fromkeys(p.PROPOSITION_CHECKS, True), "holds": []}]}
        self.review = a.ReviewBinding({"context_id": "reviewer-synthetic", "input_sha256": H,
            "receipt_sha256": H, "output": output}, "mapper-synthetic", H, "selector-synthetic", H)
        self.data = {"case_id": "case-synthetic", "lane": "candidate_case_local",
            "lineage": {"request_sha256": H, "policy_sha256": H}, "baseline_sha256": a.EMPTY,
            "baseline_kind": "EMPTY", "own_prior_generations": [], "sources": [primary[1], companion[1]],
            "propositions": [self.prop], "review_sha256": p.digest(output),
            "public_queries": [{"query": "synthetic general legal notice rule", "jurisdiction": "England",
                                "as_of_date": "2026-09-05"}]}
        self.pins = a.AdapterPins("case-synthetic", H, H, real.digest(self.policy.owner_instruction),
            self.policy.sha256, real.digest(Path(real.__file__).read_bytes()), p.digest(Path(a.__file__).read_bytes()),
            H, self.identity, self.contract.expected_knowledge_generation_sha256, actual_registry.manifest_sha256, (RETRY,))

    def policy_review(self, reviewer, receipt):
        return self.trust_policy_reviews and reviewer == "reviewer-synthetic" and real.digest(receipt) in self.verified

    def verify(self, binding):
        action = binding["action"]
        self.events.append(action)
        if action == self.denied_action:
            return False
        if binding["scope"] != asdict(self.scope) or binding["pins"]["request_sha256"] != H:
            return False
        if action == "translated_source_review":
            receipt = binding["index_review"]
            # Explicit dependency fake: exact eligible output and receipt hashes only.
            if (receipt["protocol_review_sha256"] != self.data["review_sha256"]
                or receipt["reviewer_role_receipt_sha256"] != self.review.reviewer_receipt["receipt_sha256"]):
                return False
            self.verified.add(real.digest(receipt))
        return True

    def capability(self, action, key):
        return self.policy.authorize(scope=self.scope, actor="candidate-synthetic", role="candidate",
                                     action=action, binding_sha256=key)

    def session(self):
        return FakeSession(self)

    def adapter(self, **changes):
        kwargs = dict(case_root=CASE, pins=self.pins, policy=self.policy, scope=self.scope,
            bindings={self.prop["proposition_id"]: a.PropositionBinding(self.contract, self.sources)},
            review=self.review, capability_factory=self.capability, host_verify=self.verify,
            embedding_session_factory=self.session, verify_identity=lambda: copy.deepcopy(self.identity))
        kwargs.update(changes)
        return a.CaseIndexAdapter(**kwargs)

    def request(self, kind, data=None, profile=None, attempt=1):
        envelope = {"data": copy.deepcopy(data if data is not None else self.data), "retry_profile_sha256": profile}
        reservation = {"case_id": "case-synthetic", "request_sha256": H, "policy_sha256": H,
            "kind": kind, "attempt": attempt, "input_sha256": p.digest(envelope), "budget": None,
            "attempt_root": f"operations/{kind}-{p.digest(envelope)}/attempt-{attempt}"}
        return envelope, reservation


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = ContractSchemaRegistry.from_project_root(ROOT)

    def setUp(self):
        MemoryStore.pool = {}
        self.host = Host(self.registry)
        MemoryIndex.host = self.host
        self.store_patch = patch.object(p, "CaseStore", MemoryStore)
        self.index_patch = patch.object(real, "AutoResearchIndex", MemoryIndex)
        self.store_patch.start()
        self.index_patch.start()
        self.addCleanup(self.store_patch.stop)
        self.addCleanup(self.index_patch.stop)
        self.addCleanup(self.host.sqlite.close)

    def build(self, adapter=None):
        adapter = adapter or self.host.adapter()
        return adapter, adapter.index(*self.host.request("index"))

    def retrieve(self, adapter, built):
        return adapter.retrieve(*self.host.request("retrieve", {"build": built,
            "public_queries": self.host.data["public_queries"]}))

    def test_distinct_selected_empty_contract_and_production_contract_refused(self):
        lineage = a.bind_contracts(self.host.contract, request_sha256=H)
        self.assertEqual(lineage.knowledge_generation_sha256, self.host.contract.knowledge_generation["content_sha256"])
        old = {**self.host.contract.knowledge_generation, "schema": "legalbot.knowledge-generation-manifest.v1"}
        with self.assertRaisesRegex(a.AdapterHold, "RESEARCH_EMPTY_BASELINE_REQUIRED"):
            a.bind_contracts(replace(self.host.contract, knowledge_generation=old), request_sha256=H)
        self.assertFalse(MemoryStore.pool)
        self.assertNotIn("embedding-enter", self.host.events)

    def test_real_contract_lineage_v2_and_distinct_hash_profiles(self):
        lineage = a.bind_contracts(self.host.contract, request_sha256=H)
        self.assertEqual(lineage.fact_snapshot_sha256, self.host.contract.fact_snapshot["content_sha256"])
        self.assertEqual(lineage.query_plan_sha256, real.digest(self.host.contract.query_plan))
        self.assertNotEqual(a.EMPTY, real.digest([]))
        bad = replace(self.host.contract, expected_schema_selection_sha256="a" * 64)
        with self.assertRaisesRegex(a.AdapterHold, "SCHEMA_SELECTION_CHANGED"):
            a.bind_contracts(bad, request_sha256=H)

    def test_no_dummy_baseline_source_or_nonempty_counts(self):
        for change in ({"sources": [{"bytes_sha256": H}]},
                       {"counts": {**self.host.contract.knowledge_generation["counts"], "chunks": 1}}):
            with self.subTest(change=change):
                gen = {**self.host.contract.knowledge_generation, **change}
                with self.assertRaises(a.AdapterHold):
                    a.bind_contracts(replace(self.host.contract, knowledge_generation=gen), request_sha256=H)

    def test_real_empty_contract_rejects_training_admission_and_live_flags(self):
        for key, value in (("non_live", False), ("production_admission", True), ("training", True)):
            with self.subTest(key=key):
                gen = seal_contract({**self.host.contract.knowledge_generation, key: value})
                contract = replace(self.host.contract, knowledge_generation=gen,
                                   expected_knowledge_generation_sha256=gen["content_sha256"])
                with self.assertRaisesRegex(a.AdapterHold, "EMPTY_BASELINE_CONTRACT_INVALID"):
                    a.bind_contracts(contract, request_sha256=H)

    def test_missing_fact_gap_cannot_enter_research_jobs(self):
        contract = replace(self.host.contract, gap_class="missing_user_fact")
        with self.assertRaisesRegex(a.AdapterHold, "NON_RESEARCH_GAP_DENIED"):
            a.bind_contracts(contract, request_sha256=H)
        self.assertFalse(self.host.sqlite.execute("SELECT name FROM sqlite_master").fetchall())

    def test_contract_tamper_and_legacy_fact_rejected(self):
        for change in ({"conversation_revision": 2}, {"schema": "legalbot.matter-fact-snapshot.v1"}):
            bad = replace(self.host.contract, fact_snapshot={**self.host.contract.fact_snapshot, **change})
            with self.assertRaises(ValueError):
                a.bind_contracts(bad, request_sha256=H)

    def test_callbacks_call_real_prepare_and_require_cross_source_retrieval(self):
        adapter, built = self.build()
        result = self.retrieve(adapter, built)
        p.checked(built, p.INDEX_SCHEMA)
        p.checked(result, p.RETRIEVAL_SCHEMA)
        self.assertEqual(result["evidence"][0]["proposition"], self.host.prop)
        self.assertEqual(self.host.events.count("fake-lance-build"), 1)
        self.assertEqual(self.host.events.count("fake-lance-retrieve"), 3)
        self.assertLess(self.host.events.index("translated_source_review"), self.host.events.index("embedding-enter"))
        self.assertLess(self.host.events.index("embedding-exit"), self.host.events.index("complete_retrieved_context"))
        receipt = adapter._get(result["receipt_sha256"])
        self.assertEqual(receipt["reranker"], {"status": "NOT_RUN"})
        self.assertEqual(receipt["parent_actual_validation"], "REQUIRED")
        selected = adapter.read_selected_contracts(result)
        self.assertEqual(selected["query_plan"], self.host.contract.query_plan)
        self.assertEqual(selected["fact_snapshot"], self.host.contract.fact_snapshot)
        self.assertEqual(len(selected["evidence_pack"]["selected"]), 2)
        self.assertEqual({row["jurisdiction"] for row in selected["evidence_pack"]["selected"]}, {"England"})
        self.assertEqual(selected["retrieval_result"]["selected_evidence_ids"],
                         [row["evidence_id"] for row in selected["evidence_pack"]["selected"]])
        self.assertTrue(all(row["reviewed_as_of"] == "2026-09-05"
                            for row in selected["evidence_pack"]["selected"]))
        self.assertFalse(self.host.active)

    def test_backend_stores_only_legal_text_and_lineage_hashes(self):
        adapter, built = self.build()
        self.retrieve(adapter, built)
        rows = self.host.sqlite.execute("SELECT kind,payload FROM objects").fetchall()
        all_bytes = b"\n".join(bytes(r[1]) for r in rows)
        self.assertNotIn(b'"fact_snapshot":', all_bytes)
        self.assertNotIn(b'"conversation_snapshot":', all_bytes)
        self.assertNotIn(b'"original_question":', all_bytes)
        self.assertIn(self.host.prop["point"]["text"].encode(), all_bytes)
        self.assertIn(self.host.prop["conditions"][0]["text"].encode(), all_bytes)
        self.assertTrue(self.host.sqlite.execute("SELECT 1 FROM objects WHERE kind='prepared_build'").fetchone())
        self.assertTrue(self.host.sqlite.execute("SELECT 1 FROM objects WHERE kind='retrieval'").fetchone())

    def test_duplicate_index_and_retrieval_no_model_and_no_overwrite(self):
        adapter, built = self.build()
        got = self.retrieve(adapter, built)
        old_files = dict(adapter.store.files)
        calls = self.host.events.count("embedding-enter")
        self.assertEqual(adapter.index(*self.host.request("index")), built)
        self.assertEqual(self.retrieve(adapter, built), got)
        self.assertEqual(self.host.events.count("embedding-enter"), calls)
        self.assertEqual(adapter.store.files, old_files)

    def test_missing_companion_holds_and_preserves_failure(self):
        adapter, built = self.build()
        self.host.drop_companion = True
        with self.assertRaisesRegex(a.AdapterHold, "REQUIRED_COMPANION_CONTEXT_NOT_RETRIEVED"):
            self.retrieve(adapter, built)
        self.assertTrue(any("retrieve-" in k and "-failed-1" in k for k in adapter.store.files))
        self.assertFalse(any("retrieve-" in k and "-complete" in k for k in adapter.store.files))

    def test_actual_backend_review_verifier_cannot_be_replaced_by_host_tick(self):
        self.host.trust_policy_reviews = False
        with self.assertRaises(PermissionError):
            self.build()
        self.assertNotIn("embedding-enter", self.host.events)

    def test_host_must_verify_actual_role_receipt_before_any_index_io(self):
        self.host.denied_action = "translated_source_review"
        with self.assertRaisesRegex(a.AdapterHold, "HOST_VERIFICATION_DENIED"):
            self.build()
        self.assertNotIn("embedding-enter", self.host.events)
        self.assertFalse(self.host.sqlite.execute("SELECT name FROM sqlite_master").fetchall())

    def test_role_context_reuse_and_unbound_receipt_hash_rejected(self):
        with self.assertRaisesRegex(a.AdapterHold, "ROLE_CONTEXTS_NOT_SEPARATE"):
            self.host.adapter(review=replace(self.host.review, mapper_context_id="reviewer-synthetic"))
        with self.assertRaises(p.ProtocolError):
            self.host.adapter(review=replace(self.host.review, mapper_receipt_sha256="self-declared-review"))

    def test_missing_or_false_review_checks_hold(self):
        for which in ("sources", "propositions"):
            with self.subTest(which=which):
                changed = copy.deepcopy(self.host.review)
                changed.reviewer_receipt["output"][which][0]["checks"]["quote_support"] = False
                data = copy.deepcopy(self.host.data)
                data["review_sha256"] = p.digest(changed.reviewer_receipt["output"])
                adapter = self.host.adapter(review=changed)
                with self.assertRaisesRegex(a.AdapterHold, "INDEPENDENT_REVIEW_HOLD"):
                    adapter.index(*self.host.request("index", data))

    def test_source_text_offsets_locator_and_raw_bytes_preserved(self):
        for field in ("text", "locator", "raw_b64"):
            with self.subTest(field=field):
                data = copy.deepcopy(self.host.data)
                if field == "raw_b64":
                    data["sources"][0][field] = base64.b64encode(b"changed original bytes").decode()
                else:
                    data["sources"][0]["parts"][0][field] += " changed"
                with self.assertRaises(a.AdapterHold):
                    self.host.adapter().index(*self.host.request("index", data))
        prop = copy.deepcopy(self.host.prop)
        prop["point"]["end"] -= 1
        with self.assertRaisesRegex(a.AdapterHold, "SOURCE_SPAN_CHANGED"):
            self.translate(proposition=prop)

    def test_complete_reviewed_adjacent_block_is_retrieved_and_preserved(self):
        first = self.host.sources[0]
        extra = StructuralBlock(2, BlockKind.PARAGRAPH, "Another synthetic limiting condition.", source_anchor="condition")
        # This fixture explicitly grants independent coverage of the additional
        # actual parse block; no model-written replacement or omitted chunk.
        parsed = replace(first.capture.parsed, body_blocks=(*first.capture.parsed.body_blocks, extra))
        self.host.sources = (replace(first, capture=replace(first.capture, parsed=parsed),
                                    reviewed_block_ordinals=(1, 2)), self.host.sources[1])
        adapter, built = self.build()
        got = self.retrieve(adapter, built)
        self.assertEqual(got["evidence"][0]["proposition"], self.host.prop)
        values = self.host.sqlite.execute("SELECT payload FROM objects WHERE kind='prepared_build'").fetchall()
        self.assertIn(extra.text.encode(), values[0][0])

    def translate(self, **changes):
        args = dict(source=self.host.sources[0], original=self.host.data["sources"][0], proposition=self.host.prop,
            review=self.host.review, contracts=self.host.contract,
            lineage=a.bind_contracts(self.host.contract, request_sha256=H), scope=self.host.scope)
        args.update(changes)
        return a.translate_review(**args)

    def test_parent_cycles_missing_coverage_and_chunk_merge_hold(self):
        original = copy.deepcopy(self.host.data["sources"][0])
        original["parts"][0]["parent_id"] = "p1"
        with self.assertRaisesRegex(a.AdapterHold, "PART_PARENT_CYCLE_OR_MISSING"):
            self.translate(original=original)
        with self.assertRaisesRegex(a.AdapterHold, "REQUIRED_CONTEXT_NOT_REVIEWED"):
            self.translate(source=replace(self.host.sources[0], reviewed_block_ordinals=()))
        src = self.host.sources[0]
        extra = StructuralBlock(2, BlockKind.PARAGRAPH, "Unreviewed adjacent exception.", source_anchor="extra")
        parsed = replace(src.capture.parsed, body_blocks=(*src.capture.parsed.body_blocks, extra))
        with self.assertRaisesRegex(a.AdapterHold, "CHUNK_CONTEXT_REVIEW_REQUIRED"):
            self.translate(source=replace(src, capture=replace(src.capture, parsed=parsed)))

    def test_currentness_unknown_dates_not_invented(self):
        prop = copy.deepcopy(self.host.prop)
        prop["currentness"]["valid_from"] = None
        review = copy.deepcopy(self.host.review)
        review.reviewer_receipt["output"]["propositions"][0]["proposition_sha256"] = p.digest(prop)
        with self.assertRaisesRegex(a.AdapterHold, "CURRENTNESS_UNRESOLVED"):
            self.translate(proposition=prop, review=review)

    def test_case_root_traversal_other_lane_and_other_case_denied(self):
        for root, scope in ((CASE / ".." / "outside", self.host.scope),
            (CASE, replace(self.host.scope, case_id="another-case")),
            (CASE, replace(self.host.scope, lane="private_reference")),
            (CASE, replace(self.host.scope, root=str(ROOT / "another-case" / "legal-index")))):
            with self.subTest(root=root, scope=scope):
                with self.assertRaises(a.AdapterHold):
                    self.host.adapter(case_root=root, scope=scope)

    def test_symlink_scope_denied_without_following(self):
        actual = Path.is_symlink
        def linked(path):
            return path == CASE or actual(path)
        with patch.object(Path, "is_symlink", linked):
            with self.assertRaises(PermissionError):
                self.host.adapter()

    def test_wrong_capability_scope_or_actor_review_not_accepted(self):
        def wrong(action, key):
            return self.host.policy.authorize(scope=self.host.scope, actor="candidate-synthetic", role="candidate",
                action="jobs", binding_sha256="f" * 64)
        with self.assertRaises(a.AdapterHold):
            self.build(self.host.adapter(capability_factory=wrong))
        self.assertNotIn("embedding-enter", self.host.events)

    def test_oracle_fields_and_reservation_traversal_rejected(self):
        data = copy.deepcopy(self.host.data)
        data["oracle_answer"] = "not permitted"
        with self.assertRaises(p.ProtocolError):
            self.host.adapter().index(*self.host.request("index", data))
        envelope, reservation = self.host.request("index")
        reservation["attempt_root"] = "../other-case/attempt-1"
        with self.assertRaises(p.ProtocolError):
            self.host.adapter().index(envelope, reservation)

    def test_foreign_prior_generation_never_opens_external_store(self):
        data = copy.deepcopy(self.host.data)
        data["own_prior_generations"] = ["b" * 64]
        with self.assertRaises(a.AdapterHold):
            self.host.adapter().index(*self.host.request("index", data))
        self.assertEqual(set(MemoryStore.pool), {str(CASE), str(CASE / "index-adapter")})
        self.assertNotIn("embedding-enter", self.host.events)

    def test_runtime_and_model_identity_pins_fail_before_inference(self):
        with self.assertRaisesRegex(a.AdapterHold, "INDEX_OR_ADAPTER_RUNTIME_CHANGED"):
            self.host.adapter(pins=replace(self.host.pins, index_runtime_sha256="b" * 64))
        adapter = self.host.adapter(verify_identity=lambda: {})
        with self.assertRaisesRegex(a.AdapterHold, "MODEL_IDENTITY_UNVERIFIED"):
            self.build(adapter)
        self.assertNotIn("embed-documents", self.host.events)

    def test_model_session_must_close_before_evidence(self):
        self.host.leak_session = True
        with self.assertRaisesRegex(a.AdapterHold, "EMBEDDING_SESSION_NOT_CLOSED"):
            self.build()
        self.assertNotIn("complete_retrieved_context", self.host.events)

    def test_changed_retry_bounded_and_original_failure_immutable(self):
        adapter = self.host.adapter()
        self.host.fail_embedding = True
        with self.assertRaises(a.AdapterHold):
            adapter.index(*self.host.request("index"))
        failures = {k: v for k, v in adapter.store.files.items() if "-failed-" in k}
        calls = self.host.events.count("embedding-enter")
        with self.assertRaisesRegex(a.AdapterHold, "UNCHANGED_INDEX_ACTION_HOLD"):
            adapter.index(*self.host.request("index"))
        self.assertEqual(self.host.events.count("embedding-enter"), calls)
        self.host.fail_embedding = False
        built = adapter.index(*self.host.request("index", profile=RETRY, attempt=2))
        self.assertTrue(built["non_live"])
        for k, raw in failures.items():
            self.assertEqual(adapter.store.files[k], raw)

    def test_two_same_failure_fingerprints_stop_no_third_model(self):
        adapter = self.host.adapter()
        self.host.fail_embedding = True
        for profile, attempt in ((None, 1), (RETRY, 2)):
            with self.assertRaises(a.AdapterHold):
                adapter.index(*self.host.request("index", profile=profile, attempt=attempt))
        calls = self.host.events.count("embedding-enter")
        with self.assertRaisesRegex(a.AdapterHold, "INDEX_RETRY_EXHAUSTED"):
            adapter.index(*self.host.request("index", profile=RETRY, attempt=2))
        self.assertEqual(self.host.events.count("embedding-enter"), calls)

    def test_interrupted_attempt_does_not_start_another_model(self):
        adapter = self.host.adapter()
        self.host.fail_embedding = True
        with self.assertRaises(a.AdapterHold):
            adapter.index(*self.host.request("index"))
        # Simulate a process stop before a failure pointer was ever published.
        original_exists = adapter.store.exists
        with patch.object(adapter.store, "exists", side_effect=lambda name:
                          False if "-failed-1" in name else original_exists(name)):
            before = self.host.events.count("embedding-enter")
            with self.assertRaisesRegex(a.AdapterHold, "INTERRUPTED_INDEX_ACTION_HOLD"):
                adapter.index(*self.host.request("index", profile=RETRY, attempt=2))
            self.assertEqual(self.host.events.count("embedding-enter"), before)

    def test_cached_bundle_cannot_be_relabelled_with_new_runtime_pins(self):
        adapter, built = self.build()
        changed = self.host.adapter(pins=replace(self.host.pins, host_verifier_sha256="f" * 64))
        before = self.host.events.count("embedding-enter")
        with self.assertRaisesRegex(a.AdapterHold, "BUILD_BUNDLE_CHANGED"):
            changed.index(*self.host.request("index"))
        self.assertEqual(self.host.events.count("embedding-enter"), before)

    def test_adapter_receipt_and_persisted_generation_tamper_detected(self):
        adapter, built = self.build()
        path = "objects/" + built["receipt_sha256"] + ".json"
        original = adapter.store.files[path]
        adapter.store.files[path] = original + b" "  # Deliberate test adversary, never normal writes.
        with self.assertRaisesRegex(a.AdapterHold, "ADAPTER_OBJECT_TAMPERED"):
            adapter.index(*self.host.request("index"))
        adapter.store.files[path] = original
        next(iter(self.host.generations.values()))["rows_sha256"] = "a" * 64
        with self.assertRaises(ValueError):
            adapter.index(*self.host.request("index"))

    def test_returned_retrieval_tamper_vs_sqlite_readback(self):
        adapter, built = self.build()
        self.host.change_returned_row = True
        with self.assertRaisesRegex(a.AdapterHold, "RETRIEVAL_READBACK_CHANGED"):
            self.retrieve(adapter, built)

    def test_cached_evidence_omission_rejected_even_with_recomputed_local_hashes(self):
        adapter, built = self.build()
        got = self.retrieve(adapter, built)
        receipt = adapter._get(got["receipt_sha256"])
        receipt["evidence"][0]["proposition"]["conditions"] = []
        forged = {**got, "receipt_sha256": adapter._put(receipt), "evidence": receipt["evidence"]}
        with self.assertRaisesRegex(a.AdapterHold, "CACHED_EVIDENCE_CHANGED"):
            adapter._check_retrieval(forged)

    def test_optional_host_reranker_runs_only_after_embedding_close(self):
        def rerank(job):
            self.assertFalse(self.host.active)
            self.assertTrue(job["embedding_sessions_closed"])
            self.host.events.append("synthetic-reranker-call")
            return {"ordered_proposition_ids": [e["proposition"]["proposition_id"] for e in job["evidence"]],
                "receipt": {"model": "Qwen/Qwen3-Reranker-0.6B", "model_identity_sha256": H,
                    "input_sha256": p.digest(job), "actual_inference_calls": 1,
                    "execution_receipt_sha256": H, "exclusive_model_lease_sha256": H,
                    "session_closed": True, "synthetic_vectors": False, "training": False}}
        adapter = self.host.adapter(pins=replace(self.host.pins, reranker_identity_sha256=H), rerank=rerank)
        adapter, built = self.build(adapter)
        got = self.retrieve(adapter, built)
        self.assertLess(max(i for i, v in enumerate(self.host.events) if v == "embedding-exit"),
                        self.host.events.index("synthetic-reranker-call"))
        self.assertEqual(adapter._get(got["receipt_sha256"])["reranker"]["status"], "HOST_VERIFIED_EXECUTION")
        self.assertEqual(got["evidence"][0]["proposition"], self.host.prop)


if __name__ == "__main__":
    unittest.main()
