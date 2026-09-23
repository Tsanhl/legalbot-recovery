"""CaseProtocol callbacks backed by the existing GE SQLite/Lance index.

No CLI, model/network defaults, bank discovery, contract synthesis or capability
issuer. Construct one CaseIndexAdapter per immutable turn, then pass its index
and retrieve methods to CaseProtocol.run_case. Both accept (envelope, reservation)
unchanged. The parent supplies full selected contracts, actual parsed Captures,
part/block bindings, fresh role receipts, policy/capability and identity verifiers.
Nothing in a request/model output can supply these trusted dependencies.

Protocol hashes use compact JSON; backend hashes use canonical JSON WITH a final
newline. Return build/generation hashes identify adapter BUNDLES of real backend
builds (one per proposition), not a fabricated single Lance generation. Inspect
the content-addressed receipt for constituent hashes. Backend retrieval objects
are persisted and read back before EvidencePack release. Every prepared row of
every companion source must actually be retrieved. Missing context is a HOLD.

The only baseline supported here is EMPTY, protocol.digest([]), bound to the full
selected legalbot.research-empty-baseline.v1 contract. That separate non-live
contract has zero sources/counts and 1024 dimensions. The production knowledge
generation v1 contract is not weakened or repurposed. Never use a dummy source,
schema bypass, nonempty shared generation or an invented qualification receipt.
The parent builds the full contracts and pins the current schema-selection digest;
older receipts remain historical after any schema or runtime change.

Full question/fact/conversation contracts are validated in memory; ONLY lineage
hashes enter the legal index or adapter receipts. Own earlier generation handles
are checked against this exact case store; they are not opened as external stores
or automatically reused as current evidence. Every turn maps/reviews sources anew.

host_verify(binding) must check real completion/fence/parser/source-review and
runtime evidence out of band. In particular it must verify the exact translated
index review against the actual SOURCE REVIEWER receipt, including block coverage.
The policy's independent-review verifier must accept that SAME exact receipt.
Neither context IDs nor self-reported checks establish custody or independence.
No permissive/default verifier exists. Parent OS isolation remains necessary.

embedding_session_factory() must provide the pinned local runtime session; the
backend RuntimeEmbeddingAdapter verifies its identity via verify_identity(). No
test-vector path exists. Optional rerank(job) is a trusted host callback which
must execute pinned Qwen3-Reranker under the same single-model lease, close it and
return an independently verifiable receipt. It runs only AFTER embedding exit.
Without that callback reranking is explicitly NOT_RUN. This file never closes a
knowledge gap, admits sources, writes ACTIVE, scores answers or enables production.

Create-only receipts preserve failures. Identical successful calls perform hash
verification without model inference. An interrupted attempt holds; a failed call
has at most one changed pre-frozen profile retry, coordinated by CaseProtocol.
Local hashes are tamper detection, not signatures against a hostile host. Actual
parent integration/visible validation is still required; dependency tests are not
proof of embedding, legal accuracy, custody or production readiness.
"""

from __future__ import annotations

import base64
import copy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from scripts import ge_auto_case_protocol as protocol


VERSION = "legalbot.ge-case-index-adapter.v1"
EMPTY = protocol.digest([])
PUBLIC_QUERY = protocol.obj({"query": protocol.string(600),
    "jurisdiction": {"enum": list(protocol.UK + protocol.US)}, "as_of_date": protocol.DAY})
LEGAL_INPUT_SCHEMA = protocol.obj({
    "case_id": protocol.ID, "lane": {"const": "candidate_case_local"},
    "lineage": protocol.obj({"request_sha256": protocol.HASH, "policy_sha256": protocol.HASH}),
    "baseline_sha256": {"const": EMPTY}, "baseline_kind": {"const": "EMPTY"},
    "own_prior_generations": protocol.array(protocol.HASH, 31),
    "sources": protocol.array(protocol.CAPTURE_SCHEMA, 8, 1),
    "propositions": protocol.array(protocol.PROPOSITION, 32, 1),
    "review_sha256": protocol.HASH,
    "public_queries": protocol.array(PUBLIC_QUERY, 4, 1),
})
ROLE_RECEIPT_SCHEMA = protocol.obj({"context_id": protocol.string(100),
    "input_sha256": protocol.HASH, "receipt_sha256": protocol.HASH,
    "output": protocol.REVIEWER_SCHEMA})


class AdapterHold(protocol.ActionHold):
    """Stable, non-sensitive terminal reason suitable for the protocol's holds."""


def need(condition, code):
    if not condition:
        raise AdapterHold(code)


def _backend():
    # Match the actual runtime's package identity; no heavy model imports here.
    from backend.app.research import ge_auto_index
    return ge_auto_index


def spans(proposition):
    return [proposition["point"], *proposition["conditions"],
            *proposition["context"], *proposition["currentness"]["checks"]]


def _evidence_lane_and_role(url):
    """Classify only an already policy-approved official source identity."""
    host = (urlsplit(url).hostname or "").lower()
    if host == "legislation.gov.uk" or host.endswith(".legislation.gov.uk"):
        return "primary_authority", "statutory_rule"
    if (host == "caselaw.nationalarchives.gov.uk" or host.endswith(".courts.gov")
            or "court" in host or "judiciary" in host):
        return "primary_authority", "case_law_rule"
    return "official_secondary", "official_guidance"


@dataclass(frozen=True)
class ContractBinding:
    registry: Any
    query_plan: Mapping
    fact_snapshot: Mapping
    conversation_snapshot: Mapping
    knowledge_generation: Mapping
    expected_knowledge_generation_sha256: str
    expected_schema_selection_sha256: str
    issue_id: str
    affected_claim_sha256: str
    existing_retrieval_sha256: str
    gap_class: str
    context_receipt_sha256: str


@dataclass(frozen=True)
class SourceBinding:
    """Actual backend Capture, never reconstructed from model-authored text.

    part_ordinals maps EVERY protocol part to its actual parser block ordinal.
    reviewed_block_ordinals is host-verified full chunk coverage, including any
    parent/definition/currentness blocks and blocks merged by StructuralChunker.
    New coverage needs actual independent review; the adapter never ticks it.
    """
    capture: Any
    part_ordinals: Mapping[str, int]
    reviewed_block_ordinals: tuple[int, ...]


@dataclass(frozen=True)
class PropositionBinding:
    contracts: ContractBinding
    sources: tuple[SourceBinding, ...]


@dataclass(frozen=True)
class ReviewBinding:
    reviewer_receipt: Mapping
    mapper_context_id: str
    mapper_receipt_sha256: str
    selector_context_id: str
    selector_receipt_sha256: str


@dataclass(frozen=True)
class AdapterPins:
    case_id: str
    request_sha256: str
    protocol_policy_sha256: str
    owner_instruction_sha256: str
    index_policy_sha256: str
    index_runtime_sha256: str
    adapter_runtime_sha256: str
    host_verifier_sha256: str
    expected_model_identity: Mapping
    baseline_contract_sha256: str
    schema_selection_sha256: str
    retry_profile_sha256s: tuple[str, ...] = ()
    reranker_identity_sha256: str | None = None


def bind_contracts(binding: ContractBinding, *, request_sha256: str):
    """Real selected-schema validation; never persist or project private facts."""
    index = _backend()
    gen = binding.knowledge_generation
    need(gen.get("schema") == "legalbot.research-empty-baseline.v1", "RESEARCH_EMPTY_BASELINE_REQUIRED")
    need(gen.get("sources") == [], "NONEMPTY_BASELINE_DENIED")
    counts = gen.get("counts", {})
    need(set(counts) == {"source_versions", "canonical_objects", "chunks", "lexical_rows",
                         "vector_rows", "embedding_dimensions"}
         and counts["embedding_dimensions"] == 1024
         and all(counts[k] == 0 for k in counts if k != "embedding_dimensions"),
         "EMPTY_BASELINE_COUNTS")
    need(gen.get("source_manifest_sha256") == index.digest([]), "EMPTY_MANIFEST_BINDING")
    need(binding.registry.manifest_sha256 == binding.expected_schema_selection_sha256,
         "SCHEMA_SELECTION_CHANGED")
    for key in (binding.affected_claim_sha256, binding.existing_retrieval_sha256,
                binding.expected_knowledge_generation_sha256, binding.context_receipt_sha256):
        protocol.checked(key, protocol.HASH)
    from backend.app.contracts.schema_registry import ValidationError
    try:
        binding.registry.validate_new(gen)
    except (ValueError, TypeError, KeyError, ValidationError):
        raise AdapterHold("EMPTY_BASELINE_CONTRACT_INVALID") from None
    lineage = index.Lineage.bind(registry=binding.registry, query_plan=binding.query_plan,
        fact_snapshot=binding.fact_snapshot, conversation_snapshot=binding.conversation_snapshot,
        knowledge_generation=gen, expected_request_sha256=request_sha256,
        expected_knowledge_generation_sha256=binding.expected_knowledge_generation_sha256)
    need(binding.issue_id in lineage.issue_ids, "ISSUE_NOT_IN_QUERY_PLAN")
    need(binding.gap_class in index.RESEARCH_GAPS, "NON_RESEARCH_GAP_DENIED")
    return lineage


def translate_review(*, source: SourceBinding, original: Mapping, proposition: Mapping,
                     review: ReviewBinding, contracts: ContractBinding, lineage, scope):
    """Mechanical translation ONLY; host and policy must verify the returned object."""
    index = _backend()
    capture = source.capture
    need(type(capture) is index.Capture and capture.scope == scope, "CAPTURE_SCOPE_OR_TYPE")
    protocol.checked(original, protocol.CAPTURE_SCHEMA)
    need(capture.raw == base64.b64decode(original["raw_b64"], validate=True), "RAW_CAPTURE_CHANGED")
    need(all(getattr(capture, key) == original[key] for key in
             ("canonical_url", "final_url", "fetched_at", "parser_sha256"))
         and list(capture.redirect_chain) == original["redirect_chain"], "CAPTURE_PROVENANCE_CHANGED")
    need(capture.jurisdiction == lineage.jurisdiction == proposition["jurisdiction"]
         and lineage.as_of_date == proposition["as_of_date"], "LEGAL_SCOPE_CHANGED")
    from backend.app.ingestion.sanitation import sanitize_parse_result
    need(capture.parsed.is_ready and sanitize_parse_result(capture.parsed) == capture.parsed,
         "PARSE_NOT_READY_OR_SANITIZED")
    need(not capture.parsed.comments and not capture.parsed.revisions, "ANNOTATIONS_NOT_AUTHORITY")
    blocks = {b.ordinal: b for b in capture.parsed.body_blocks}
    parts = {p["part_id"]: p for p in original["parts"]}
    need(len(parts) == len(original["parts"]) and len(blocks) == len(capture.parsed.body_blocks),
         "DUPLICATE_PART_OR_BLOCK")
    need(set(parts) == set(source.part_ordinals)
         and all(type(n) is int for n in source.part_ordinals.values())
         and len(set(source.part_ordinals.values())) == len(parts), "PART_BLOCK_INVENTORY")
    for part_id, part in parts.items():
        block = blocks.get(source.part_ordinals[part_id])
        need(block is not None and block.text == part["text"] and block.source_anchor == part["locator"],
             "PART_TEXT_OR_LOCATOR_CHANGED")
        visited, parent = {part_id}, part["parent_id"]
        while parent is not None:
            need(parent in parts and parent not in visited, "PART_PARENT_CYCLE_OR_MISSING")
            visited.add(parent)
            parent = parts[parent]["parent_id"]
    raw_sha = index.digest(capture.raw)
    selected = [s for s in spans(proposition) if s["source_sha256"] == raw_sha]
    need(selected, "UNREFERENCED_SOURCE")
    mandatory = set()
    for span in selected:
        part = parts.get(span["part_id"])
        need(part is not None and 0 <= span["start"] < span["end"] <= len(part["text"])
             and part["text"][span["start"]:span["end"]] == span["text"], "SOURCE_SPAN_CHANGED")
        parent = part["part_id"]
        while parent is not None:
            mandatory.add(source.part_ordinals[parent])
            parent = parts[parent]["parent_id"]
    coverage = source.reviewed_block_ordinals
    need(all(type(n) is int for n in coverage) and len(set(coverage)) == len(coverage)
         and mandatory <= set(coverage) <= set(blocks), "REQUIRED_CONTEXT_NOT_REVIEWED")
    from backend.app.ingestion.chunking import StructuralChunker
    included = [c for c in StructuralChunker().chunk_body(capture.parsed, document_sha256=raw_sha)
                if set(c.block_ordinals) & set(coverage)]
    need(included and all(set(c.block_ordinals) <= set(coverage) for c in included),
         "CHUNK_CONTEXT_REVIEW_REQUIRED")
    quote = selected[0]
    need(any(quote["text"] in c.text for c in included), "QUOTE_SPLIT_NOT_RETRIEVABLE")
    receipt = review.reviewer_receipt
    protocol.checked(receipt, ROLE_RECEIPT_SCHEMA)
    output = receipt["output"]
    srows = [s for s in output["sources"] if s["source_sha256"] == raw_sha]
    prows = [p for p in output["propositions"] if p["proposition_id"] == proposition["proposition_id"]]
    need(len(srows) == len(prows) == 1, "INDEPENDENT_REVIEW_MISSING_OR_DUPLICATE")
    for row in (*srows, *prows):
        need(row["decision"] == "ELIGIBLE" and row["holds"] == []
             and all(v is True for v in row["checks"].values()), "INDEPENDENT_REVIEW_HOLD")
    need(prows[0]["proposition_sha256"] == protocol.digest(proposition), "PROPOSITION_REVIEW_CHANGED")
    current = proposition["currentness"]
    need(current["status"] == "VERIFIED" and current["checks"]
         and current["valid_from"] is not None and current["valid_to"] is not None,
         "CURRENTNESS_UNRESOLVED")
    protocol.day(current["valid_from"])
    protocol.day(current["valid_to"])
    need(current["valid_from"] <= lineage.as_of_date <= current["valid_to"], "CURRENTNESS_DATE_HOLD")
    need(receipt["context_id"] not in (review.mapper_context_id, review.selector_context_id,
                                      capture.researcher_id), "REVIEWER_NOT_SEPARATE")
    manifest = capture.manifest()
    return {"reviewer_id": receipt["context_id"], "capture_sha256": index.digest(manifest),
        "source_sha256": raw_sha, "parsed_sha256": index.digest(asdict(capture.parsed)),
        "scope": asdict(scope), "issue_id": contracts.issue_id,
        "affected_claim_sha256": contracts.affected_claim_sha256,
        "jurisdiction": lineage.jurisdiction, "as_of_date": lineage.as_of_date,
        "valid_from": current["valid_from"], "valid_to": current["valid_to"],
        "checks": sorted(srows[0]["checks"]), "decision": "ELIGIBLE_RESEARCH_ONLY",
        "uncertainties": [], "quote": quote["text"],
        "locator": parts[quote["part_id"]]["locator"],
        "quote_block_ordinal": source.part_ordinals[quote["part_id"]],
        "context_block_ordinals": list(coverage),
        "protocol_review_sha256": protocol.digest(output),
        "source_review_sha256": protocol.digest(srows[0]),
        "proposition_review_sha256": protocol.digest(prows[0]),
        "proposition_sha256": protocol.digest(proposition),
        "reviewer_role_receipt_sha256": receipt["receipt_sha256"],
        "reviewer_input_sha256": receipt["input_sha256"],
        "mapper_receipt_sha256": review.mapper_receipt_sha256,
        "selector_receipt_sha256": review.selector_receipt_sha256,
        "parser_receipt_sha256": original["parser_receipt_sha256"],
        "part_inventory_sha256": protocol.digest(original["parts"]),
        "required_spans_sha256": protocol.digest(selected),
        "all_required_spans_sha256": protocol.digest(spans(proposition))}


class CaseIndexAdapter:
    def __init__(self, *, case_root: Path, pins: AdapterPins, policy, scope,
                 bindings: Mapping[str, PropositionBinding], review: ReviewBinding,
                 capability_factory: Callable, host_verify: Callable,
                 embedding_session_factory: Callable, verify_identity: Callable,
                 rerank: Callable | None = None):
        index = _backend()
        self.root = Path(case_root)
        need(self.root.is_absolute() and ".." not in self.root.parts
             and self.root != policy.workspace and self.root.is_relative_to(policy.workspace),
             "CASE_ROOT_DENIED")
        need(type(policy) is index.ResearchPolicy and type(scope) is index.Scope
             and scope.root == str(self.root / "legal-index")
             and scope.lane == "candidate_case_local" and scope.case_id == pins.case_id
             and scope in policy.scopes, "INDEX_SCOPE_DENIED")
        scope.validate(policy.workspace)
        need(all(callable(c) for c in (capability_factory, host_verify,
             embedding_session_factory, verify_identity)), "TRUSTED_CALLBACK_REQUIRED")
        need((rerank is None) == (pins.reranker_identity_sha256 is None), "RERANKER_PIN_REQUIRED")
        self.pins = copy.deepcopy(pins)
        self.policy, self.scope = policy, scope
        self.bindings = dict(bindings)  # Parent-owned full contracts remain in memory only.
        self.review = copy.deepcopy(review)
        self.capability_factory, self.host_verify = capability_factory, host_verify
        self.embedding_session_factory, self.verify_identity = embedding_session_factory, verify_identity
        self.rerank = rerank
        self.store = protocol.CaseStore(self.root / "index-adapter")
        self.selected_contracts = None
        self._pin_check()

    def _pin_check(self):
        index = _backend()
        for h in (self.pins.request_sha256, self.pins.protocol_policy_sha256,
                  self.pins.host_verifier_sha256, self.pins.baseline_contract_sha256,
                  self.pins.schema_selection_sha256, *self.pins.retry_profile_sha256s):
            protocol.checked(h, protocol.HASH)
        protocol.checked(self.pins.case_id, protocol.ID)
        protocol.checked(self.review.reviewer_receipt, ROLE_RECEIPT_SCHEMA)
        for h in (self.review.mapper_receipt_sha256, self.review.selector_receipt_sha256):
            protocol.checked(h, protocol.HASH)
        contexts = (self.review.mapper_context_id, self.review.selector_context_id,
                    self.review.reviewer_receipt["context_id"])
        for context in contexts:
            protocol.checked(context, protocol.string(100))
        need(len(set(contexts)) == len(contexts), "ROLE_CONTEXTS_NOT_SEPARATE")
        if self.pins.reranker_identity_sha256 is not None:
            protocol.checked(self.pins.reranker_identity_sha256, protocol.HASH)
        need(self.policy.sha256 == self.pins.index_policy_sha256
             and index.digest(self.policy.owner_instruction) == self.pins.owner_instruction_sha256,
             "OWNER_OR_POLICY_PIN_CHANGED")
        need(index.digest(Path(index.__file__).read_bytes()) == self.pins.index_runtime_sha256
             and protocol.digest(Path(__file__).read_bytes()) == self.pins.adapter_runtime_sha256,
             "INDEX_OR_ADAPTER_RUNTIME_CHANGED")
        need(index.ModelPin.from_runtime_identity(self.pins.expected_model_identity) == self.policy.model,
             "MODEL_PIN_CHANGED")

    def _verify(self, action, **details):
        binding = {"schema": VERSION, "action": action, "case_root": str(self.root),
            "scope": asdict(self.scope), "pins": asdict(self.pins), "baseline_sha256": EMPTY,
            "non_live": True, "private_reference_inputs": False, **details}
        need(self.host_verify(copy.deepcopy(binding)) is True, "HOST_VERIFICATION_DENIED")

    def _cap(self, action, key):
        self._verify("capability", index_action=action, binding_sha256=key)
        cap = self.capability_factory(action, key)
        self.policy.require(cap, self.scope, action, key)
        return cap

    def _database(self, lineage):
        index = _backend()
        cap = self._cap("jobs", index.digest(asdict(lineage)))
        db = index.AutoResearchIndex(policy=self.policy, capability=cap, scope=self.scope, lineage=lineage)
        return db, cap

    def _input(self, envelope, reservation, kind):
        self._pin_check()
        need(isinstance(envelope, dict) and set(envelope) == {"data", "retry_profile_sha256"}
             and isinstance(envelope["data"], dict), "PROTOCOL_ENVELOPE_CHANGED")
        protocol.checked(envelope["retry_profile_sha256"], {"anyOf": [protocol.HASH, {"const": None}]})
        protocol.checked(reservation, protocol.obj({"case_id": protocol.ID,
            "request_sha256": protocol.HASH, "policy_sha256": protocol.HASH,
            "kind": {"const": kind}, "attempt": {"type": "integer", "minimum": 1, "maximum": 2},
            "input_sha256": protocol.HASH, "budget": {"const": None},
            "attempt_root": protocol.string(500)}))
        profile = envelope["retry_profile_sha256"]
        need(profile is None or profile in self.pins.retry_profile_sha256s, "UNFROZEN_RETRY_PROFILE")
        need(reservation.get("case_id") == self.pins.case_id
             and reservation.get("request_sha256") == self.pins.request_sha256
             and reservation.get("policy_sha256") == self.pins.protocol_policy_sha256
             and reservation.get("kind") == kind
             and reservation.get("input_sha256") == protocol.digest(envelope), "PROTOCOL_RESERVATION_CHANGED")
        path = protocol.parts(reservation["attempt_root"])
        need(len(path) == 3 and path[0] == "operations" and path[1].startswith(kind + "-")
             and path[2] == "attempt-" + str(reservation["attempt"]), "PROTOCOL_JOB_PATH_CHANGED")
        need(type(reservation.get("attempt")) is int and reservation["attempt"] in (1, 2)
             and reservation.get("budget") is None, "PROTOCOL_ATTEMPT_CHANGED")
        self._verify("protocol_reservation", envelope_sha256=protocol.digest(envelope), reservation=reservation)
        return copy.deepcopy(envelope["data"])

    def _preflight(self, data):
        protocol.checked(data, LEGAL_INPUT_SCHEMA)
        need(data["case_id"] == self.pins.case_id and data["lineage"] == {
            "request_sha256": self.pins.request_sha256, "policy_sha256": self.pins.protocol_policy_sha256},
            "LEGAL_INPUT_LINEAGE_CHANGED")
        need(protocol.digest(self.review.reviewer_receipt["output"]) == data["review_sha256"],
             "REVIEW_OUTPUT_CHANGED")
        sources = {protocol.digest(base64.b64decode(s["raw_b64"], validate=True)): s for s in data["sources"]}
        props = {p["proposition_id"]: p for p in data["propositions"]}
        need(len(props) == len(data["propositions"]) and set(props) == set(self.bindings)
             and len(sources) == len(data["sources"]), "INPUT_INVENTORY_CHANGED")
        required_sources = {s["source_sha256"] for p in props.values() for s in spans(p)}
        need(set(sources) == required_sources, "SOURCE_INVENTORY_CHANGED")
        prepared = []
        for pid, proposition in props.items():
            binding = self.bindings[pid]
            lineage = bind_contracts(binding.contracts, request_sha256=self.pins.request_sha256)
            need(lineage.knowledge_generation_sha256 == self.pins.baseline_contract_sha256
                 and lineage.schema_selection_sha256 == self.pins.schema_selection_sha256,
                 "FROZEN_BASELINE_OR_SCHEMA_CHANGED")
            need(any(q["jurisdiction"] == lineage.jurisdiction and q["as_of_date"] == lineage.as_of_date
                     for q in data["public_queries"]), "QUERY_PLAN_SCOPE_CHANGED")
            used = {s["source_sha256"] for s in spans(proposition)}
            need(len(binding.sources) == len(used)
                 and {_backend().digest(s.capture.raw) for s in binding.sources} == used,
                 "HOST_SOURCE_BINDINGS_CHANGED")
            reviews = []
            for source in binding.sources:
                original = sources[_backend().digest(source.capture.raw)]
                translated = translate_review(source=source, original=original, proposition=proposition,
                    review=self.review, contracts=binding.contracts, lineage=lineage, scope=self.scope)
                self._verify("translated_source_review", legal_input_sha256=protocol.digest(data),
                    context_receipt_sha256=binding.contracts.context_receipt_sha256,
                    lineage=asdict(lineage), capture_manifest=source.capture.manifest(),
                    part_ordinals=dict(source.part_ordinals), index_review=translated,
                    reviewer_receipt=self.review.reviewer_receipt,
                    mapper_context_id=self.review.mapper_context_id,
                    selector_context_id=self.review.selector_context_id)
                self.policy.independent(translated, (source.capture.researcher_id, lineage.candidate_id))
                reviews.append((source.capture, translated))
            self._verify("contract_lineage", lineage=asdict(lineage),
                context_receipt_sha256=binding.contracts.context_receipt_sha256,
                existing_retrieval_sha256=binding.contracts.existing_retrieval_sha256,
                knowledge_generation_sha256=binding.contracts.expected_knowledge_generation_sha256)
            prepared.append((proposition, binding.contracts, lineage, reviews))
        return prepared

    def _put(self, value):
        raw = protocol.canonical(value)
        key = protocol.digest(raw)
        name = "objects/" + key + ".json"
        if self.store.exists(name):
            need(self.store.read(name) == raw, "ADAPTER_OBJECT_TAMPERED")
        else:
            self.store.write_new(name, raw)
        need(self.store.read(name) == raw, "ADAPTER_WRITE_READBACK")
        return key

    def _get(self, key):
        protocol.checked(key, protocol.HASH)
        raw = self.store.read("objects/" + key + ".json")
        need(protocol.digest(raw) == key, "ADAPTER_OBJECT_TAMPERED")
        return protocol.decode(raw)

    def _pointer(self, name):
        key = self.store.read(name).decode("ascii")
        return self._get(key)

    def _save_pointer(self, name, value):
        raw = self._put(value).encode("ascii")
        if self.store.exists(name):
            need(self.store.read(name) == raw, "IMMUTABLE_POINTER_CHANGED")
        else:
            self.store.write_new(name, raw)

    def _run(self, kind, envelope, reservation, work, check):
        self._verify("open_adapter_store")
        parent = protocol.CaseStore(self.root)
        if not parent.exists("index-adapter"):
            parent.mkdir_new("index-adapter")
        with self.store.lock():
            if not self.store.exists("objects"):
                self.store.mkdir_new("objects")
            identity = {"scope": asdict(self.scope), "case_id": self.pins.case_id,
                        "baseline_sha256": EMPTY, "protocol_policy_sha256": self.pins.protocol_policy_sha256,
                        "baseline_contract_sha256": self.pins.baseline_contract_sha256,
                        "schema_selection_sha256": self.pins.schema_selection_sha256}
            if self.store.exists("IDENTITY"):
                need(self._pointer("IDENTITY") == identity, "ADAPTER_STORE_IDENTITY")
            else:
                self._save_pointer("IDENTITY", identity)
            key = kind + "-" + protocol.digest(envelope["data"])
            if self.store.exists(key + "-complete"):
                value = self._pointer(key + "-complete")
                check(value)
                return value
            previous = None
            for n in (1, 2):
                start, failed = key + f"-attempt-{n}", key + f"-failed-{n}"
                if not self.store.exists(start):
                    break
                previous = self._pointer(start)
                need(previous["pins_sha256"] == protocol.digest(asdict(self.pins)), "ATTEMPT_PINS_CHANGED")
                need(self.store.exists(failed), "INTERRUPTED_INDEX_ACTION_HOLD")
                self._pointer(failed)  # Verify preserved failure bytes, even on exhaustion.
            else:
                raise AdapterHold("INDEX_RETRY_EXHAUSTED")
            if previous is not None:
                need(envelope["retry_profile_sha256"] is not None
                     and previous["envelope_sha256"] != protocol.digest(envelope), "UNCHANGED_INDEX_ACTION_HOLD")
            need(reservation["attempt"] == n, "ATTEMPT_SEQUENCE_CHANGED")
            self._save_pointer(start, {"envelope_sha256": protocol.digest(envelope),
                "reservation_sha256": protocol.digest(reservation), "pins_sha256": protocol.digest(asdict(self.pins))})
            try:
                result = work()
                check(result)
                self._save_pointer(key + "-complete", result)
                return result
            except Exception as exc:
                reason = str(exc) if isinstance(exc, AdapterHold) else "INDEX_ADAPTER_DEPENDENCY_FAILURE"
                self._save_pointer(failed, {"reason": reason, "fingerprint": protocol.digest({"reason": reason}),
                                          "attempt": n, "preserved": True})
                raise AdapterHold(reason) from None

    def _model_receipt(self, session):
        receipt = copy.deepcopy(session.receipt())
        need(receipt.get("model_identity") == self.pins.expected_model_identity
             and receipt.get("provider") == "PINNED_LOCAL_QWEN"
             and receipt.get("synthetic_vectors") is False and receipt.get("training") is False
             and type(receipt.get("actual_inference_calls")) is int
             and receipt["actual_inference_calls"] > 0
             and receipt["actual_inference_calls"] == len(receipt.get("calls", [])), "INFERENCE_RECEIPT_REQUIRED")
        self._verify("embedding_execution", receipt=receipt)
        return receipt

    def _build(self, data, prepared, profile):
        index = _backend()
        entries, pending = [], []
        for proposition, contracts, lineage, reviews in prepared:
            db, jobs = self._database(lineage)
            need(jobs.actor != self.review.reviewer_receipt["context_id"], "REVIEWER_NOT_SEPARATE")
            key = "built-" + protocol.digest({"legal_input": protocol.digest(data),
                "proposition": proposition, "lineage": asdict(lineage), "reviews": [r for _, r in reviews],
                "context_receipt_sha256": contracts.context_receipt_sha256})
            if self.store.exists(key):
                entry = self._pointer(key)
                self._check_entry(entry, lineage)
                entries.append(entry)
                continue
            gap = db.enqueue(jobs, issue_id=contracts.issue_id, gap_class=contracts.gap_class,
                affected_claim_sha256=contracts.affected_claim_sha256,
                failure_fingerprint=protocol.digest({"proposition": proposition, "review": data["review_sha256"]}))
            attempt = db.begin_attempt(jobs, gap,
                inputs_sha256=protocol.digest({"input": key, "retry_profile": profile}),
                existing_retrieval_sha256=contracts.existing_retrieval_sha256,
                change_reason="parent-frozen-index-profile" if profile else "")
            need(attempt is not None, "UNCHANGED_OR_UNCERTAIN_BACKEND_ATTEMPT")
            pending.append((db, jobs, gap, attempt))
            try:
                for capture, _ in reviews:
                    operation = db.reserve(jobs, attempt, kind="capture", input_sha256=index.digest(capture.manifest()))
                    need(operation is not None, "BACKEND_CAPTURE_RESERVATION_HOLD")
                    db.capture(jobs, operation, capture)  # Register already host-captured bytes, NO new HTTP.
                build = db.prepare(jobs, gap=gap, attempt=attempt, sources=reviews)
                value = protocol.decode(build.payload)
                self._verify("prepared_build", build_sha256=build.sha256,
                             lineage=asdict(lineage), row_manifest_sha256=index.digest(value["rows"]))
                with self.embedding_session_factory() as session:
                    provider = index.RuntimeEmbeddingAdapter(session,
                        expected_identity=self.pins.expected_model_identity, verify_identity=self.verify_identity)
                    need(provider.verify_binding(), "MODEL_IDENTITY_UNVERIFIED")
                    generation = db.build(self._cap("build", build.sha256), build, provider=provider)
                    inference = self._model_receipt(session)
                need(session.provider is None, "EMBEDDING_SESSION_NOT_CLOSED")
                entry = {"proposition": proposition, "lineage": asdict(lineage), "build_sha256": build.sha256,
                         "generation_sha256": generation, "inference_sha256": self._put(inference),
                         "context_receipt_sha256": contracts.context_receipt_sha256}
                self._check_entry(entry, lineage)
                self._save_pointer(key, entry)
                entries.append(entry)
            except Exception:
                for database, capability, gap_id, attempt_id in pending:
                    rows = database.status(gap_id)["attempts"]
                    if any(r[0] == attempt_id and r[2] == "RUNNING" for r in rows):
                        database.fail_attempt(capability, attempt_id,
                            fingerprint=protocol.digest({"action": "index", "input": key}), reason="ADAPTER_BUILD_HOLD")
                raise
        bundle = {"schema": VERSION, "kind": "build_bundle", "case_id": self.pins.case_id,
            "request_sha256": self.pins.request_sha256, "legal_input_sha256": protocol.digest(data),
            "pins_sha256": protocol.digest(asdict(self.pins)),
            "review_sha256": data["review_sha256"], "baseline_sha256": EMPTY,
            "public_queries": data["public_queries"], "entries": entries,
            "parent_actual_validation": "REQUIRED", "reranker": "NOT_RUN"}
        receipt = self._put(bundle)
        result = {"build_sha256": protocol.digest([e["build_sha256"] for e in entries]),
            "generation_sha256": protocol.digest([e["generation_sha256"] for e in entries]),
            "receipt_sha256": receipt, "baseline_sha256": EMPTY,
            "legal_input_sha256": protocol.digest(data), "case_id": self.pins.case_id,
            "non_live": True, "active_mutated": False}
        self._save_pointer("generation-" + result["generation_sha256"], result)
        return result

    def _check_entry(self, entry, lineage):
        db, _ = self._database(lineage)
        need(_backend().digest(entry["lineage"]) == _backend().digest(asdict(lineage)), "BUILD_LINEAGE_CHANGED")
        need(entry["context_receipt_sha256"] == self.bindings[entry["proposition"]["proposition_id"]].contracts.context_receipt_sha256,
             "CONTEXT_RECEIPT_CHANGED")
        receipt, _ = db._read_generation(entry["build_sha256"])
        prepared = db._get(entry["build_sha256"], "prepared_build")
        need(prepared["runtime_sha256"] == self.pins.index_runtime_sha256
             and lineage.schema_selection_sha256 == self.pins.schema_selection_sha256
             and lineage.knowledge_generation_sha256 == self.pins.baseline_contract_sha256,
             "PERSISTED_BUILD_PINS_CHANGED")
        need(receipt["generation_sha256"] == entry["generation_sha256"], "PERSISTED_GENERATION_CHANGED")
        self._verify("persisted_generation", receipt=receipt, inference=self._get(entry["inference_sha256"]))
        return db

    def _check_build(self, value):
        protocol.checked(value, protocol.INDEX_SCHEMA)
        bundle = self._get(value["receipt_sha256"])
        need(bundle["case_id"] == value["case_id"] == self.pins.case_id
             and bundle["request_sha256"] == self.pins.request_sha256
             and bundle["pins_sha256"] == protocol.digest(asdict(self.pins))
             and bundle["legal_input_sha256"] == value["legal_input_sha256"]
             and bundle["baseline_sha256"] == value["baseline_sha256"] == EMPTY
             and value["build_sha256"] == protocol.digest([e["build_sha256"] for e in bundle["entries"]])
             and value["generation_sha256"] == protocol.digest([e["generation_sha256"] for e in bundle["entries"]]),
             "BUILD_BUNDLE_CHANGED")
        ids = [e["proposition"]["proposition_id"] for e in bundle["entries"]]
        need(len(ids) == len(set(ids)) and set(ids) == set(self.bindings)
             and bundle["review_sha256"] == protocol.digest(self.review.reviewer_receipt["output"]),
             "BUILD_REVIEW_OR_INVENTORY_CHANGED")
        for entry in bundle["entries"]:
            rows = [p for p in self.review.reviewer_receipt["output"]["propositions"]
                    if p["proposition_id"] == entry["proposition"]["proposition_id"]]
            need(len(rows) == 1 and rows[0]["proposition_sha256"] == protocol.digest(entry["proposition"])
                 and rows[0]["decision"] == "ELIGIBLE", "CACHED_PROPOSITION_CHANGED")
            binding = self.bindings[entry["proposition"]["proposition_id"]]
            lineage = bind_contracts(binding.contracts, request_sha256=self.pins.request_sha256)
            self._check_entry(entry, lineage)
        return bundle

    def index(self, envelope, reservation):
        data = self._input(envelope, reservation, "index")
        prepared = self._preflight(data)  # No index/model/storage IO on a source/contract HOLD.
        def work():
            for prior in data["own_prior_generations"]:
                old = self._pointer("generation-" + prior)
                need(old["case_id"] == self.pins.case_id and old["generation_sha256"] == prior
                     and old["baseline_sha256"] == EMPTY, "PRIOR_GENERATION_SCOPE")
                self._verify("own_prior_generation", result=old)
            return self._build(data, prepared, envelope["retry_profile_sha256"])
        def check(value):
            need(value["legal_input_sha256"] == protocol.digest(data), "CACHED_INPUT_CHANGED")
            return self._check_build(value)
        return self._run("index", envelope, reservation, work, check)

    def _retrieve(self, data, bundle):
        index = _backend()
        evidence, actual, contract_sources = [], [], {}
        for entry in bundle["entries"]:
            proposition = entry["proposition"]
            binding = self.bindings[proposition["proposition_id"]]
            lineage = bind_contracts(binding.contracts, request_sha256=self.pins.request_sha256)
            db = self._check_entry(entry, lineage)
            build = db._get(entry["build_sha256"], "prepared_build")
            required = {r["id"]: r for r in build["rows"]}
            need(required and len(required) == len(build["rows"]), "EMPTY_OR_DUPLICATE_BUILD_ROWS")
            # Public gap queries plus one exact, reviewed anchor per companion group.
            # These are bounded local retrieval calls, never additional web searches.
            queries = [q["query"] for q in bundle["public_queries"]
                       if q["jurisdiction"] == lineage.jurisdiction and q["as_of_date"] == lineage.as_of_date]
            queries += [review["quote"] for review in build["reviews"]]
            queries = list(dict.fromkeys(queries))
            need(1 <= len(queries) <= 12, "LOCAL_RETRIEVAL_BUDGET")
            found, receipts = {}, []
            with self.embedding_session_factory() as session:
                provider = index.RuntimeEmbeddingAdapter(session,
                    expected_identity=self.pins.expected_model_identity, verify_identity=self.verify_identity)
                need(provider.verify_binding(), "MODEL_IDENTITY_UNVERIFIED")
                for query in queries:
                    result = db.retrieve(self._cap("retrieve", entry["generation_sha256"]),
                        build_sha256=entry["build_sha256"], generation_sha256=entry["generation_sha256"],
                        query=query, lineage=lineage, provider=provider, limit=8)
                    sha = result["retrieval_sha256"]
                    saved = db._get(sha, "retrieval")
                    need(index.digest({k: v for k, v in result.items() if k != "retrieval_sha256"}) == sha
                         and index.digest(saved) == sha
                         and index.digest(saved["lineage"]) == index.digest(asdict(lineage))
                         and saved["scope"] == asdict(self.scope)
                         and saved["build_sha256"] == entry["build_sha256"]
                         and saved["generation_sha256"] == entry["generation_sha256"]
                         and saved["query_sha256"] == index.digest(query.encode()), "RETRIEVAL_READBACK_CHANGED")
                    need(set(saved["selected_ids"]) <= required.keys(), "RETRIEVAL_UNKNOWN_HIT")
                    groups = {required[r]["group"] for r in saved["selected_ids"]}
                    for row in saved["evidence"]:
                        need(row == required.get(row["id"]) and row["group"] in groups,
                             "RETRIEVAL_EVIDENCE_CHANGED")
                        found[row["id"]] = row
                    receipts.append(sha)
                inference = self._model_receipt(session)
            need(session.provider is None, "EMBEDDING_SESSION_NOT_CLOSED")
            need(set(found) == set(required), "REQUIRED_COMPANION_CONTEXT_NOT_RETRIEVED")
            self._verify("complete_retrieved_context", proposition=proposition,
                generation_sha256=entry["generation_sha256"], retrieval_sha256s=receipts,
                required_rows_sha256=index.digest(build["rows"]), review_sha256=bundle["review_sha256"])
            actual.append({"proposition_id": proposition["proposition_id"], "retrieval_sha256s": receipts,
                           "inference_sha256": self._put(inference)})
            evidence.append({"origin": "CASE_LOCAL", "proposition": proposition,
                             "eligibility_receipt_sha256": bundle["review_sha256"]})
            document_calls = {
                call["text_sha256"]: call["tokens"]
                for call in self._get(entry["inference_sha256"])["calls"]
                if call["kind"] == "document"
            }
            source_manifests = {index.digest(source): source for source in build["sources"]}
            source_reviews = {review["capture_sha256"]: review for review in build["reviews"]}
            for row in found.values():
                source_sha = row["capture_sha256"]
                need(source_sha in source_manifests and source_sha in source_reviews,
                     "RETRIEVED_SOURCE_IDENTITY_MISSING")
                need(row["text_sha256"] in document_calls, "RETRIEVED_TOKEN_RECEIPT_MISSING")
                record = contract_sources.setdefault(source_sha, {
                    "manifest": source_manifests[source_sha], "reviews": [], "rows": {},
                    "issue_ids": set(), "generation_sha256s": set()})
                need(record["manifest"] == source_manifests[source_sha], "SOURCE_MANIFEST_CHANGED")
                record["reviews"].append(source_reviews[source_sha])
                saved_row = {**row, "actual_token_count": document_calls[row["text_sha256"]]}
                need(row["id"] not in record["rows"] or record["rows"][row["id"]] == saved_row,
                     "RETRIEVED_CONTEXT_ROW_CHANGED")
                record["rows"][row["id"]] = saved_row
                record["issue_ids"].update(binding.contracts.query_plan["issue_ids"])
                record["generation_sha256s"].add(entry["generation_sha256"])
        reranker = {"status": "NOT_RUN"}
        if self.rerank is not None:
            job = {"case_id": self.pins.case_id, "request_sha256": self.pins.request_sha256,
                "public_queries": bundle["public_queries"], "evidence": evidence,
                "embedding_sessions_closed": True, "model_identity_sha256": self.pins.reranker_identity_sha256}
            self._verify("reranker_before_load", job_sha256=protocol.digest(job))
            reranked = self.rerank(copy.deepcopy(job))
            protocol.checked(reranked, protocol.obj({"ordered_proposition_ids": protocol.array(protocol.ID, 32, 1),
                "receipt": protocol.obj({"model": {"const": "Qwen/Qwen3-Reranker-0.6B"},
                    "model_identity_sha256": protocol.HASH, "input_sha256": protocol.HASH,
                    "actual_inference_calls": {"type": "integer", "minimum": 1},
                    "execution_receipt_sha256": protocol.HASH, "exclusive_model_lease_sha256": protocol.HASH,
                    "session_closed": {"const": True}, "synthetic_vectors": {"const": False},
                    "training": {"const": False}})}))
            order, receipt = reranked["ordered_proposition_ids"], reranked["receipt"]
            need(len(order) == len(evidence) and set(order) == {e["proposition"]["proposition_id"] for e in evidence}
                 and receipt["model_identity_sha256"] == self.pins.reranker_identity_sha256
                 and receipt["input_sha256"] == protocol.digest(job), "RERANK_BINDING_CHANGED")
            self._verify("reranker_execution", job=job, result=reranked)
            evidence = sorted(evidence, key=lambda e: order.index(e["proposition"]["proposition_id"]))
            reranker = {"status": "HOST_VERIFIED_EXECUTION", "receipt_sha256": self._put(reranked)}
        receipt = self._put({"schema": VERSION, "kind": "retrieval_bundle", "build": data["build"],
            "actual": actual, "evidence": evidence, "reranker": reranker,
            "parent_actual_validation": "REQUIRED"})
        result = {"baseline_sha256": EMPTY, "generation_sha256": data["build"]["generation_sha256"],
                "receipt_sha256": receipt, "evidence": evidence}
        self._build_selected_contracts(result, bundle, contract_sources)
        return result

    def _build_selected_contracts(self, result, bundle, contract_sources):
        """Populate the existing RetrievalResult/EvidencePack contracts.

        One selected evidence object represents the exact retrieved context bundle
        for one source version.  Its component row IDs and token counts remain in
        the create-only adapter receipt; no source or passage is reconstructed.
        """
        from backend.app.contracts.retrieval_evidence import (
            QualifiedEvidenceInput, build_retrieval_evidence_contracts,
        )
        from backend.app.contracts.schema_registry import canonical_json_bytes
        from backend.app.types import EvidenceSpan, MaterialLane

        bindings = [self.bindings[item["proposition"]["proposition_id"]].contracts
                    for item in result["evidence"]]
        need(bindings, "SELECTED_CONTRACT_BINDING_REQUIRED")
        query_plan = bindings[0].query_plan
        fact_snapshot = bindings[0].fact_snapshot
        conversation_snapshot = bindings[0].conversation_snapshot
        need(all(binding.query_plan == query_plan and binding.fact_snapshot == fact_snapshot
                 and binding.conversation_snapshot == conversation_snapshot
                 for binding in bindings), "MULTIPLE_PRE_SOURCE_QUERY_PLANS_HOLD")
        need(set(query_plan["issue_ids"]) == set().union(
            *(set(record["issue_ids"]) for record in contract_sources.values())),
            "SELECTED_EVIDENCE_ISSUE_COVERAGE_CHANGED")
        candidate_sha = protocol.digest({"candidate_id": query_plan["candidate_id"],
            "model_identity": self.pins.expected_model_identity,
            "protocol_policy_sha256": self.pins.protocol_policy_sha256,
            "adapter_runtime_sha256": self.pins.adapter_runtime_sha256})
        qualified = []
        component_receipts = []
        for rank, (capture_sha, record) in enumerate(sorted(contract_sources.items()), 1):
            manifest = record["manifest"]
            source_sha = manifest["source_sha256"]
            reviews = record["reviews"]
            need(reviews and all(review["decision"] == "ELIGIBLE_RESEARCH_ONLY" for review in reviews),
                 "SELECTED_SOURCE_REVIEW_CHANGED")
            valid_from = max(review["valid_from"] for review in reviews)
            valid_to = min(review["valid_to"] for review in reviews)
            need(valid_from <= valid_to, "SELECTED_SOURCE_CURRENTNESS_RANGE_EMPTY")
            rows = [record["rows"][key] for key in sorted(record["rows"])]
            need(rows, "SELECTED_SOURCE_CONTEXT_EMPTY")
            context_text = "\n\n".join(row["text"] for row in rows)
            component = {"capture_sha256": capture_sha, "source_sha256": source_sha,
                "row_ids": [row["id"] for row in rows],
                "row_text_sha256s": [row["text_sha256"] for row in rows],
                "row_token_counts": [row["actual_token_count"] for row in rows],
                "generation_sha256s": sorted(record["generation_sha256s"]),
                "context_text_sha256": protocol.digest(context_text.encode())}
            lane, role = _evidence_lane_and_role(manifest["canonical_url"])
            evidence_id = "evidence-" + protocol.digest(component)[:40]
            component["evidence_id"] = evidence_id
            component["source_version_id"] = "source-version-" + source_sha[:40]
            component_receipts.append(component)
            span = EvidenceSpan(id=evidence_id,
                source_version_id=component["source_version_id"],
                chunk_id="context-bundle-" + protocol.digest(component)[:40],
                text=context_text, locator="; ".join(dict.fromkeys(r["locator"] for r in reviews)),
                lane=MaterialLane(lane), jurisdiction=manifest["jurisdiction"],
                subject="general-enquiries", citation_data={
                    "reviewed_as_of": query_plan["requested_as_of_date"],
                    "effective_from": valid_from, "effective_to": valid_to,
                    "commencement_status": "verified_for_requested_date",
                    "canonical_url": manifest["canonical_url"],
                    "component_receipt_sha256": protocol.digest(component)},
                canonical_citation=None, currentness_status="qualified_current",
                content_sha256=protocol.digest(context_text.encode()),
                index_build_id=result["generation_sha256"],
                canonical_url=manifest["canonical_url"], retrieval_relevance_score=None,
                retrieval_route="hybrid_rrf", retrieval_threshold=None,
                retrieval_threshold_policy_sha256=protocol.digest({
                    "required_complete_context": True,
                    "index_policy_sha256": self.pins.index_policy_sha256,
                    "reranker_identity_sha256": self.pins.reranker_identity_sha256}),
                retrieval_threshold_qualified=True,
                retrieval_qualification_reason="required_reviewed_context_retrieved",
                legal_role=role, provision_extent_status="verified_for_requested_jurisdiction",
                identity_verified=True, currentness_verified=True)
            qualified.append(QualifiedEvidenceInput(span=span,
                issue_ids=tuple(sorted(record["issue_ids"])),
                selected_token_count=sum(row["actual_token_count"] for row in rows),
                selected_rank=rank))
        created = datetime.now(UTC)
        built = build_retrieval_evidence_contracts(query_plan=query_plan,
            query_plan_sha256=__import__("hashlib").sha256(canonical_json_bytes(query_plan)).hexdigest(),
            candidate_sha256=candidate_sha, evidence=tuple(qualified),
            fact_snapshot_sha256=fact_snapshot["content_sha256"], created_at=created,
            registry=bindings[0].registry)
        material = {"schema": "legalbot.ge-selected-retrieval-contracts.v1",
            "protocol_retrieval_receipt_sha256": result["receipt_sha256"],
            "query_plan": query_plan, "fact_snapshot": fact_snapshot,
            "conversation_snapshot": conversation_snapshot,
            "retrieval_result": built.retrieval_result, "evidence_pack": built.evidence_pack,
            "component_receipts": component_receipts,
            "created_at": created.isoformat(), "source_count": len(contract_sources),
            "plaintext_evidence_persisted_here": False, "production_admission": False,
            "training": False}
        pointer = "selected-contracts-" + result["receipt_sha256"]
        self._save_pointer(pointer, material)
        self.selected_contracts = copy.deepcopy(material)

    def read_selected_contracts(self, result):
        """Revalidate and return the persisted selected contract bundle."""
        self._check_retrieval(result)
        value = self._pointer("selected-contracts-" + result["receipt_sha256"])
        need(value.get("protocol_retrieval_receipt_sha256") == result["receipt_sha256"],
             "SELECTED_CONTRACT_RECEIPT_CHANGED")
        registry = next(iter(self.bindings.values())).contracts.registry
        for key in ("conversation_snapshot", "query_plan", "fact_snapshot",
                    "retrieval_result", "evidence_pack"):
            registry.validate_new(value[key])
        from backend.app.contracts.retrieval_evidence import validate_retrieval_evidence_scope
        validate_retrieval_evidence_scope(query_plan=value["query_plan"],
            retrieval_result=value["retrieval_result"], evidence_pack=value["evidence_pack"])
        self.selected_contracts = copy.deepcopy(value)
        return copy.deepcopy(value)

    def _check_retrieval(self, value):
        protocol.checked(value, protocol.RETRIEVAL_SCHEMA)
        receipt = self._get(value["receipt_sha256"])
        bundle = self._check_build(receipt["build"])
        need(value["baseline_sha256"] == EMPTY and value["evidence"] == receipt["evidence"]
             and value["generation_sha256"] == receipt["build"]["generation_sha256"], "RETRIEVAL_BUNDLE_CHANGED")
        by_id = {e["proposition"]["proposition_id"]: e for e in bundle["entries"]}
        need(len(receipt["actual"]) == len(by_id) == len(value["evidence"]), "RETRIEVAL_COVERAGE_CHANGED")
        actual_ids = [item["proposition_id"] for item in receipt["actual"]]
        evidence_ids = [item["proposition"]["proposition_id"] for item in value["evidence"]]
        need(len(set(actual_ids)) == len(actual_ids) and set(actual_ids) == set(by_id)
             and len(set(evidence_ids)) == len(evidence_ids) and set(evidence_ids) == set(by_id),
             "RETRIEVAL_INVENTORY_CHANGED")
        for item in value["evidence"]:
            need(item == {"origin": "CASE_LOCAL", "proposition": by_id[item["proposition"]["proposition_id"]]["proposition"],
                          "eligibility_receipt_sha256": bundle["review_sha256"]}, "CACHED_EVIDENCE_CHANGED")
        for item in receipt["actual"]:
            entry = by_id[item["proposition_id"]]
            lineage = bind_contracts(self.bindings[item["proposition_id"]].contracts,
                                     request_sha256=self.pins.request_sha256)
            db, _ = self._database(lineage)
            index = _backend()
            prepared = db._get(entry["build_sha256"], "prepared_build")
            required = {r["id"]: r for r in prepared["rows"]}
            queries = [q["query"] for q in bundle["public_queries"]
                       if q["jurisdiction"] == lineage.jurisdiction and q["as_of_date"] == lineage.as_of_date]
            queries += [r["quote"] for r in prepared["reviews"]]
            query_hashes = {index.digest(q.encode()) for q in queries}
            need(len(item["retrieval_sha256s"]) == len(set(item["retrieval_sha256s"]))
                 == len(query_hashes), "CACHED_RETRIEVAL_QUERY_COVERAGE")
            found, executed_queries = {}, set()
            saved_receipts = []
            for sha in item["retrieval_sha256s"]:
                saved = db._get(sha, "retrieval")
                need(saved["generation_sha256"] == entry["generation_sha256"]
                     and saved["build_sha256"] == entry["build_sha256"]
                     and saved["scope"] == asdict(self.scope)
                     and index.digest(saved["lineage"]) == index.digest(asdict(lineage))
                     and index.digest(saved) == sha
                     and saved["retrieval_runtime_sha256"] == self.pins.index_runtime_sha256,
                     "RETRIEVAL_GENERATION_CHANGED")
                need(set(saved["selected_ids"]) <= required.keys(), "CACHED_RETRIEVAL_UNKNOWN_HIT")
                groups = {required[r]["group"] for r in saved["selected_ids"]}
                for row in saved["evidence"]:
                    need(row == required.get(row["id"]) and row["group"] in groups, "CACHED_RETRIEVAL_ROW_CHANGED")
                    found[row["id"]] = row
                executed_queries.add(saved["query_sha256"])
                saved_receipts.append(saved)
            need(executed_queries == query_hashes and set(found) == set(required), "CACHED_CONTEXT_NOT_RETRIEVED")
            self._verify("persisted_retrieval", receipts=saved_receipts,
                         inference=self._get(item["inference_sha256"]))
        reranker = receipt["reranker"]
        if self.rerank is None:
            need(reranker == {"status": "NOT_RUN"}, "UNEXECUTED_RERANKER_CLAIM")
            rerank_receipt = None
        else:
            need(reranker["status"] == "HOST_VERIFIED_EXECUTION", "RERANKER_RECEIPT_MISSING")
            rerank_receipt = self._get(reranker["receipt_sha256"])
            need(rerank_receipt["ordered_proposition_ids"] == evidence_ids
                 and rerank_receipt["receipt"]["model_identity_sha256"] == self.pins.reranker_identity_sha256,
                 "CACHED_RERANKER_CHANGED")
        self._verify("persisted_evidence_pack", result=value, receipt=receipt, reranker_receipt=rerank_receipt)

    def retrieve(self, envelope, reservation):
        data = self._input(envelope, reservation, "retrieve")
        protocol.checked(data, protocol.obj({"build": protocol.INDEX_SCHEMA,
                                            "public_queries": protocol.array(PUBLIC_QUERY, 4, 1)}))
        def work():
            bundle = self._check_build(data["build"])
            need(bundle["public_queries"] == data["public_queries"], "RETRIEVAL_QUERIES_CHANGED")
            return self._retrieve(data, bundle)
        def check(value):
            receipt = self._get(value["receipt_sha256"])
            need(receipt["build"] == data["build"], "CACHED_RETRIEVAL_BUILD_CHANGED")
            bundle = self._get(data["build"]["receipt_sha256"])
            need(bundle["public_queries"] == data["public_queries"], "CACHED_RETRIEVAL_QUERIES_CHANGED")
            return self._check_retrieval(value)
        return self._run("retrieve", envelope, reservation, work, check)
