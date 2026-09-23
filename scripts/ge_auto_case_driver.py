"""Explicit host composition for one due, non-live CaseProtocol turn.

No bank discovery, CLI defaults, downloads, model calls on import, or authority
reconstruction from on-disk JSON. Parent code constructs the real CaseCustody,
issues a case capability and constructs CodexRoleRuntime with custody.role_guard.
It passes those live objects, exact pins, actual global marker bytes/callback,
actual due extraction receipts, prior contracts, Fernet key and trusted callbacks
here. Call constructdriver(...).runturn(...) in the child; the parent services functions.web
through service_web(request_bytes, reservation) -> WebObservation. That callback
may block on the parent's protected filesystem broker. Its returned observation
is separately checked by host_evidence_verify before custody publishes it.

The parent must implement host_evidence_verify(kind, binding) and
native_index_verify(adapter_binding) as real closed trust checks. Neither has a
fallback here. resolve_gap receives the actual planner/reviewer output and must
supply actual gap/empty-baseline-lookup receipts and any clarification-to-contract
mapping. No source quote is silently relabelled a candidate claim. No empty
baseline manifest is relabelled an executed lookup. The native verifier can
inspect protected driver observations; wrapper/native build translations are
recorded there before retrieval. The original native receipts remain unchanged.

Only independently reviewed spans covering COMPLETE blocks can enter index
coverage. Parent headings must also be covered. Structural chunks touching an
unreviewed block fail the native adapter's preflight; this driver never expands
review coverage to make a chunk eligible. Missing trust dependencies stay HOLD.
A state-only request's inferred US federal query currently needs an explicit
federal request jurisdiction in the contracts helper; otherwise HOLD, no rewrite.
Actual custody/host execution validation is required before any run promotion.
"""
from __future__ import annotations

import base64
import copy
import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path

from backend.app.contracts.query_plan import QueryBudgets
from backend.app.contracts.schema_registry import ContractSchemaRegistry
from backend.app.ingestion.models import (
    BlockKind,
    DocumentFormat,
    ParseResult,
    ParseStatus,
    StructuralBlock,
)
from backend.app.research import ge_auto_index as research
from cryptography.fernet import Fernet, InvalidToken

from scripts import ge_auto_case_contracts as contracts
from scripts import ge_auto_case_custody as custody_api
from scripts import ge_auto_case_index_adapter as adapter
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as bridge
from scripts.ge_auto_role_runtime import CodexRoleRuntime

VERSION = "legalbot.ge-case-driver.v1"
EMPTY = p.digest([])


# The protocol deliberately preserves codes for EXACT ActionHold instances.
# An exception subclass would erase the specific material/technical hold code.
DriverHold = p.ActionHold


def need(condition, code):
    if not condition:
        raise DriverHold(code)


def _mkdir(store, name):
    for end in range(1, len(p.parts(name)) + 1):
        part = "/".join(p.parts(name)[:end])
        if not store.exists(part):
            store.mkdir_new(part)


class FernetArtifactStore:
    """Real authenticated encryption; key remains in host memory, never in a file.

    Existing artifacts are accepted only if this instance observed their original
    exclusive write. A fresh process cannot adopt existing ledger files as trust.
    Caller-supplied keys must be retained outside all worker roots by the parent.
    """
    def __init__(self, *, store: p.CaseStore, key: bytes, prefix: str):
        need(isinstance(key, bytes), "EXPLICIT_FERNET_KEY_REQUIRED")
        try:
            self._cipher = Fernet(key)
        except (ValueError, TypeError):
            raise DriverHold("INVALID_FERNET_KEY") from None
        p.parts(prefix)
        self.store, self.prefix = store, prefix
        self._observed, self._lock = {}, threading.RLock()

    def __call__(self, raw: bytes, provenance: Mapping):
        need(isinstance(raw, bytes) and len(raw) <= 10_000_000, "ENCRYPTION_INPUT_LIMIT")
        need(isinstance(provenance, Mapping), "ENCRYPTION_PROVENANCE_REQUIRED")
        material = copy.deepcopy(dict(provenance))
        need(material.get("plaintext_sha256") == research.digest(raw), "ENCRYPTION_PLAINTEXT_BINDING")
        ident = research.digest(material)
        ref = "enc-" + ident
        base = self.prefix + "/" + ref
        with self._lock:
            if ident in self._observed:
                ack, expected_receipt = self._observed[ident]
                cipher = self.store.read(base + ".fernet")
                receipt = self.store.read(base + ".json")
                need(p.digest(cipher) == ack["ciphertext_sha256"] and receipt == expected_receipt,
                     "ENCRYPTED_ARTIFACT_CHANGED")
                try:
                    need(self._cipher.decrypt(cipher) == raw, "ENCRYPTED_PLAINTEXT_CHANGED")
                except InvalidToken:
                    raise DriverHold("ENCRYPTED_AUTHENTICATION_FAILED") from None
                return copy.deepcopy(ack)
            _mkdir(self.store, self.prefix)
            need(not self.store.exists(base + ".fernet") and not self.store.exists(base + ".json"),
                 "UNOBSERVED_OR_PARTIAL_ENCRYPTED_ARTIFACT")
            cipher = self._cipher.encrypt(raw)
            self.store.write_new(base + ".fernet", cipher)
            saved = self.store.read(base + ".fernet")
            need(saved == cipher and self._cipher.decrypt(saved) == raw, "ENCRYPTION_READBACK_FAILED")
            ack = {"encrypted_ref": ref, "plaintext_sha256": research.digest(raw),
                   "ciphertext_sha256": research.digest(saved)}
            receipt = contracts.encryption_receipt_material(material, ack)
            from backend.app.contracts.schema_registry import canonical_json_bytes
            receipt_raw = canonical_json_bytes(receipt)
            self.store.write_new(base + ".json", receipt_raw)
            need(self.store.read(base + ".json") == receipt_raw, "ENCRYPTION_RECEIPT_CHANGED")
            ack["receipt_sha256"] = research.digest(receipt)
            self._observed[ident] = (copy.deepcopy(ack), receipt_raw)
            return ack


@dataclass(frozen=True)
class WebObservation:
    raw_utf8: str
    hits: Sequence[Mapping]
    tool_call_id: str
    # Actual parent observation, not worker-authored request data.
    host_receipt: bytes


@dataclass(frozen=True)
class GapResolution:
    """Out-of-band host gap decision, bound to the actual planner inputs.

    query_ids must name actual planner gap_ids with one kind/jurisdiction/date.
    receipt must bind the supplied gap/claim/lookup identities; the trusted host
    verifier checks the actual lookup and clarification mapping provenance.
    """
    issue_id: str
    query_ids: tuple[str, ...]
    gap_class: str
    affected_claim_sha256: str
    existing_retrieval_sha256: str
    missing_facts: tuple[Mapping, ...]
    response_disposition: str
    answer_route: str
    receipt: bytes


@dataclass(frozen=True)
class DriverPins:
    contract: contracts.ContractPins
    embedding_identity: Mapping
    reranker_identity: Mapping
    # Exact file hashes and callback code-object hashes, frozen by the parent.
    code_sha256s: Mapping[str, str]
    host_evidence_verifier_sha256: str
    native_index_verifier_sha256: str
    gap_resolver_sha256: str
    web_service_sha256: str
    global_marker_callback_sha256: str

    def material(self):
        """JSON-safe pins; contract timestamps use the helper's canonical form."""
        return {**asdict(self), "contract": self.contract.material()}


CODE_FILES = (
    "scripts/ge_auto_case_driver.py", "scripts/ge_auto_case_protocol.py",
    "scripts/ge_auto_case_custody.py", "scripts/ge_auto_case_contracts.py",
    "scripts/ge_auto_role_runtime.py", "scripts/ge_auto_host_bridge.py",
    "scripts/ge_auto_case_index_adapter.py", "scripts/ge_auto_research_intake.py",
    "scripts/ge_auto_xml_tables.py", "scripts/ge_auto_research_runtime.py",
    "scripts/ge_auto_research_reranker.py", "backend/app/research/ge_auto_index.py",
    "backend/app/ingestion/chunking.py", "backend/app/ingestion/parsers.py",
    "backend/app/ingestion/models.py", "backend/app/ingestion/sanitation.py",
    "backend/app/contracts/schema_registry.py", "backend/app/contracts/query_plan.py",
    "backend/app/retrieval/qwen.py", "backend/app/retrieval/lancedb.py",
    "scripts/ge_unseen_sources.py",
)


def complete_reviewed_blocks(proposition, original, part_ordinals):
    """Coverage is the union of exact reviewed spans, never a whole-source guess."""
    p.checked(proposition, p.PROPOSITION)
    p.checked(original, p.CAPTURE_SCHEMA)
    source_sha = p.digest(base64.b64decode(original["raw_b64"], validate=True))
    parts = {part["part_id"]: part for part in original["parts"]}
    need(len(parts) == len(original["parts"]) and set(parts) == set(part_ordinals)
         and all(type(n) is int for n in part_ordinals.values())
         and len(set(part_ordinals.values())) == len(parts), "CAPTURE_PART_MAP_CHANGED")
    intervals = {}
    for span in adapter.spans(proposition):
        if span["source_sha256"] != source_sha:
            continue
        part = parts.get(span["part_id"])
        need(part is not None and 0 <= span["start"] < span["end"] <= len(part["text"])
             and part["text"][span["start"]:span["end"]] == span["text"], "REVIEWED_SPAN_CHANGED")
        intervals.setdefault(span["part_id"], []).append((span["start"], span["end"]))
    complete = set()
    for part_id, ranges in intervals.items():
        end = 0
        for start, stop in sorted(ranges):
            if start > end:
                break
            end = max(end, stop)
        if end == len(parts[part_id]["text"]):
            complete.add(part_id)
    need(intervals and set(intervals) <= complete, "PARTIAL_BLOCK_REVIEW_HOLD")
    for part_id in intervals:
        seen, parent = {part_id}, parts[part_id]["parent_id"]
        while parent is not None:
            need(parent in parts and parent not in seen, "PARENT_MAP_CHANGED")
            need(parent in complete, "UNREVIEWED_PARENT_BLOCK_HOLD")
            seen.add(parent)
            parent = parts[parent]["parent_id"]
    return tuple(sorted(part_ordinals[part_id] for part_id in complete))


def build_fact_projection(*, case_id, turn, requests, fact_snapshot, query_plan):
    """Project only candidate-visible user material and bind it to selected facts.

    The MatterFactSnapshot intentionally stores encrypted values.  Independent
    answer review still needs the exact plaintext that the candidate saw, so the
    live host reconstructs this narrow projection from its already-bound request
    objects.  It never reads author expectations or infers semantic sub-facts.
    """
    need(isinstance(requests, tuple | list) and len(requests) == turn,
         "FACT_PROJECTION_REQUEST_COUNT")
    material = []
    for ordinal, request in enumerate(requests, 1):
        p.checked(request, p.REQUEST_SCHEMA)
        need(request["case_id"] == case_id and request["turn"] == ordinal,
             "FACT_PROJECTION_REQUEST_SCOPE")
        material.append({"turn": ordinal, "kind": "question",
            "source_id": "request-" + p.digest(request)[:40],
            "text": request["question"],
            "text_sha256": p.digest(request["question"].encode("utf-8")),
            "origin": "user_statement", "status": "stated"})
        for upload in request["due_uploads"]:
            material.append({"turn": ordinal, "kind": "upload_extraction",
                "source_id": upload["upload_id"], "text": upload["text"],
                "text_sha256": upload["text_sha256"],
                "origin": "document_extraction", "status": "extracted"})
    facts = list(fact_snapshot["facts"])
    need(len(facts) == len(material), "FACT_PROJECTION_FACT_COUNT")
    projected = []
    for fact, source in zip(facts, material, strict=True):
        need(fact["value_sha256"] == source["text_sha256"]
             and fact["origin"] == source["origin"]
             and fact["status"] == source["status"], "FACT_PROJECTION_FACT_BINDING")
        projected.append({"fact_id": fact["fact_id"], "turn": source["turn"],
            "kind": source["kind"], "source_id": source["source_id"],
            "text": source["text"], "text_sha256": source["text_sha256"],
            "origin": fact["origin"], "status": fact["status"],
            "affected_issue_ids": list(fact["affected_issue_ids"])})
    need(query_plan["fact_snapshot_id"] == fact_snapshot["snapshot_id"],
         "FACT_PROJECTION_QUERY_FACT_BINDING")
    return {"schema": "legalbot.ge-visible-fact-projection.v1",
        "case_id": case_id, "turn": turn,
        "request_sha256": p.digest(requests[-1]),
        "query_plan_id": query_plan["query_plan_id"],
        "query_plan_sha256": research.digest(query_plan),
        "fact_snapshot_id": fact_snapshot["snapshot_id"],
        "fact_snapshot_sha256": fact_snapshot["content_sha256"],
        "facts": projected, "semantic_facts_inferred": False,
        "author_expectations_included": False}


def capture_from_ledger(*, store, reservation, original, scope, researcher_id, jurisdiction,
                        source_review, reviewer_receipt_sha256):
    """Reconstruct actual Capture from the HostCapture ledger, not model text."""
    p.checked(original, p.CAPTURE_SCHEMA)
    base = "broker/capture-" + p.digest(reservation)
    receipt_raw = store.read(base + "/parser-receipt.json")
    need(p.digest(receipt_raw) == original["parser_receipt_sha256"], "PARSER_LEDGER_RECEIPT_CHANGED")
    receipt = p.decode(receipt_raw)
    need(receipt["reservation_sha256"] == p.digest(reservation)
         and receipt["parser_mode"] == bridge.PARSER_MODE and receipt["include_legal_tables"] is True,
         "PARSER_LEDGER_MODE_OR_RESERVATION")
    for name, sha in receipt["files"].items():
        need(len(p.parts(name)) == 1 and p.digest(store.read(base + "/" + name)) == sha,
             "PARSER_LEDGER_FILE_CHANGED")
    need({"raw.bytes", "transport.json", "parse-manifest.json", "parts.json"} <= set(receipt["files"]),
         "PARSER_LEDGER_INCOMPLETE")
    raw = store.read(base + "/raw.bytes")
    manifest = p.decode(store.read(base + "/parse-manifest.json"))
    transport = p.decode(store.read(base + "/transport.json"))
    need(raw == base64.b64decode(original["raw_b64"], validate=True)
         and manifest["raw_sha256"] == receipt["source_sha256"] == p.digest(raw)
         and research.digest(manifest["parsed"]) == manifest["parsed_sha256"] == receipt["intake_parsed_sha256"]
         and original["parser_sha256"] == manifest["parser_sha256"] == receipt["parser_sha256"],
         "CAPTURE_RAW_OR_PARSE_CHANGED")
    need(manifest["source_review"] == "NOT_PERFORMED" and manifest["production_admission"] is False
         and manifest["legal_gold"] is False, "PARSER_CANNOT_APPROVE_SOURCE")
    parts = bridge.structural_parts(manifest)
    need(parts == original["parts"] == p.decode(store.read(base + "/parts.json"))
         and p.digest(parts) == receipt["parsed_sha256"], "CAPTURE_PARTS_CHANGED")
    for key in ("canonical_url", "final_url", "redirect_chain", "fetched_at"):
        need(original[key] == transport[key] == receipt[key], "CAPTURE_TRANSPORT_CHANGED")
    need(source_review["source_sha256"] == p.digest(raw) and source_review["decision"] == "ELIGIBLE"
         and source_review["holds"] == [] and set(source_review["checks"]) == set(p.SOURCE_CHECKS)
         and all(v is True for v in source_review["checks"].values()), "SOURCE_REVIEW_HOLD")
    value = manifest["parsed"]
    need(not value["comments"] and not value["revisions"], "ANNOTATIONS_NOT_AUTHORITY")
    blocks = tuple(StructuralBlock(**{**b, "kind": BlockKind(b["kind"]),
                                     "heading_path": tuple(b["heading_path"])}) for b in value["body_blocks"])
    parsed = ParseResult(ParseStatus(value["status"]), DocumentFormat(value["document_format"]),
                         blocks, (), (), tuple(value["diagnostics"]))
    need(research.digest(asdict(parsed)) == manifest["parsed_sha256"], "TYPED_PARSE_CHANGED")
    mapping = {part["part_id"]: b.ordinal for part, b in zip(parts, blocks, strict=True)}
    rights = research.digest({"source_sha256": p.digest(raw), "rights_check": source_review["checks"]["rights"],
                              "source_review": source_review, "reviewer_receipt_sha256": reviewer_receipt_sha256})
    capture = research.Capture(scope, researcher_id, raw, parsed, original["parser_sha256"],
        original["canonical_url"], original["final_url"], tuple(original["redirect_chain"]),
        original["fetched_at"], original["canonical_url"], "INDEPENDENTLY_REVIEWED_OFFICIAL_SOURCE",
        jurisdiction, rights)
    return capture, mapping


class CaseDriver:
    def __init__(self, *, workspace_root: Path, case_root: Path, protected_host_root: Path,
                 request: Mapping, due_uploads: Mapping[str, contracts.UploadEvidence],
                 upload_receipt_paths: Mapping[str, str], ordered_history: Sequence[contracts.PriorTurn],
                 policy: p.FrozenPolicy, pins: DriverPins, registry: ContractSchemaRegistry,
                 custody: custody_api.CaseCustody, host_key: object, capability: object,
                 role_runtime: CodexRoleRuntime, fernet_key: bytes, global_marker_bytes: bytes,
                 establish_global_marker: Callable, service_web: Callable, resolve_gap: Callable,
                 host_evidence_verify: Callable, native_index_verify: Callable,
                 observed_at: datetime, query_budgets: QueryBudgets, web_timeout_seconds: int):
        need(type(custody) is custody_api.CaseCustody and type(role_runtime) is CodexRoleRuntime,
             "ACTUAL_CUSTODY_AND_CODEX_RUNTIME_REQUIRED")
        need(type(pins) is DriverPins and type(registry) is ContractSchemaRegistry
             and type(policy) is p.FrozenPolicy, "EXPLICIT_CONTRACT_DEPENDENCIES_REQUIRED")
        self.workspace, self.root, self.protected = map(Path, (workspace_root, case_root, protected_host_root))
        for path in (self.root, self.protected):
            custody_api.root_path(path, self.workspace)
        need(not self.root.is_relative_to(self.protected) and not self.protected.is_relative_to(self.root),
             "PROTECTED_ROOT_MUST_BE_DISJOINT")
        need(custody.workspace == self.workspace and custody.root == self.protected
             and role_runtime.case_root == self.root and role_runtime.protected_root == self.protected
             and role_runtime.capability is capability and role_runtime.verify == custody.role_guard,
             "RUNTIME_CUSTODY_SCOPE_CHANGED")
        p.checked(request, p.REQUEST_SCHEMA)
        self.request = p.decode(p.canonical(request))
        self.request_sha = p.digest(self.request)
        self.policy, self.pins, self.registry = policy, pins, registry
        self.custody, self.host_key, self.capability = custody, host_key, capability
        self.runtime, self.uploads = role_runtime, dict(due_uploads)
        self.upload_receipt_paths, self.history = dict(upload_receipt_paths), tuple(ordered_history)
        need(isinstance(global_marker_bytes, bytes) and bool(global_marker_bytes), "ACTUAL_GLOBAL_MARKER_REQUIRED")
        self.global_marker = global_marker_bytes
        self.marker_callback, self.service_web, self.resolve_gap = establish_global_marker, service_web, resolve_gap
        self.host_verify, self.native_verify = host_evidence_verify, native_index_verify
        self.observed_at, self.budgets = observed_at, query_budgets
        need(type(observed_at) is datetime and observed_at.tzinfo is not None
             and type(query_budgets) is QueryBudgets, "EXPLICIT_DATE_AND_BUDGETS_REQUIRED")
        need(type(web_timeout_seconds) is int and 1 <= web_timeout_seconds <= 600, "WEB_WAIT_BOUND")
        self.web_timeout = web_timeout_seconds
        self.store = custody_api.CustodyStore(self.root)
        self.host_store = custody.store
        self.prefix = "driver/" + self.request_sha
        self.vault = FernetArtifactStore(store=self.host_store, key=fernet_key, prefix=self.prefix + "/encrypted")
        self.roles, self.captures, self.contracts = {}, {}, {}
        self.native_retrievals, self.selected_retrieval_contracts = {}, None
        self.native_builds, self.native_observations, self.translated_reviews = {}, {}, {}
        self.native_adapter, self.research_policy = None, None
        self._protocol, self._terminal_result = None, None
        self._callback_bindings = {}
        self._started = False
        self._check_pins()
        context = custody.bridge_context(capability)
        need(context.request_sha256 == self.request_sha and context.case_id == self.request["case_id"]
             and context.policy_sha256 == p.digest(policy.manifest()), "CAPABILITY_REQUEST_CHANGED")
        need(set(self.uploads) == set(self.upload_receipt_paths)
             == {u["upload_id"] for u in self.request["due_uploads"]}, "EXACT_DUE_UPLOADS_REQUIRED")

    def _check_pins(self):
        need(set(self.pins.code_sha256s) == set(CODE_FILES), "EXACT_DRIVER_CODE_PINS_REQUIRED")
        for relative, expected in self.pins.code_sha256s.items():
            path = self.workspace / relative
            need(not any(part.is_symlink() for part in (path, *path.parents))
                 and path.stat().st_nlink == 1 and p.digest(path.read_bytes()) == expected, "DRIVER_CODE_CHANGED")
        for name, callback, expected in (("EVIDENCE", self.host_verify, self.pins.host_evidence_verifier_sha256),
            ("NATIVE_INDEX", self.native_verify, self.pins.native_index_verifier_sha256),
            ("GAP", self.resolve_gap, self.pins.gap_resolver_sha256),
            ("WEB", self.service_web, self.pins.web_service_sha256),
            ("MARKER", self.marker_callback, self.pins.global_marker_callback_sha256)):
            code = getattr(getattr(callback, "__func__", callback), "__code__", None)
            function = getattr(callback, "__func__", callback)
            owner = getattr(callback, "__self__", None)
            if name not in self._callback_bindings:
                need(callable(callback) and code is not None and bridge.callback_sha256(callback) == expected,
                     "TRUSTED_HOST_" + name + "_CALLBACK_CHANGED")
                self._callback_bindings[name] = (function, owner, code, expected)
            else:
                original, original_owner, original_code, original_hash = self._callback_bindings[name]
                # marshal uses reference-count-sensitive TYPE_REF flags. A
                # returned constant can change its serialized hash while the
                # immutable code object is unchanged. After the initial exact
                # hash check, retain that object AND bound owner, not a rehash or
                # a newly loaded callback with the same apparent source.
                need(function is original and owner is original_owner and code is original_code
                     and expected == original_hash, "TRUSTED_HOST_" + name + "_CALLBACK_CHANGED")
        cp, policy, cust = self.pins.contract, self.policy.manifest(), self.custody.pins
        cp.material()
        need(policy == self.custody.policy and policy["baseline_kind"] == "EMPTY"
             and policy["baseline_sha256"] == EMPTY and policy["production"] is False and policy["training"] is False,
             "COMMON_EMPTY_NON_LIVE_POLICY_REQUIRED")
        need(cp.owner_instruction_sha256 == policy["owner_instruction_sha256"]
             and cp.runtime_sha256 == policy["runtime_sha256"] == cust["runtime_sha256"]
             and cp.protocol_policy_sha256 == p.digest(policy)
             and cp.schema_selection_sha256 == self.registry.manifest_sha256,
             "CONTRACT_OWNER_RUNTIME_SCHEMA_CHANGED")
        from scripts.ge_auto_research_intake import parser_binding
        need(cp.parser_sha256 == cust["parser_sha256"] == parser_binding(include_legal_tables=True)
             and cp.encrypt_store_sha256 == bridge.callback_sha256(FernetArtifactStore.__call__),
             "PARSER_OR_ENCRYPTION_PIN_CHANGED")
        need(cp.embedding_model_sha256 == cust["embedding_model_sha256"] == self.pins.embedding_identity["identity_sha256"]
             and cp.reranker_model_sha256 == self.pins.reranker_identity["identity_sha256"], "MODEL_CONTRACT_PINS_CHANGED")
        need(cust["index_callback_sha256"] == bridge.callback_sha256(type(self).index)
             and cust["retrieve_callback_sha256"] == bridge.callback_sha256(type(self).retrieve)
             and cust["index_runtime_sha256"] == self.pins.code_sha256s["backend/app/research/ge_auto_index.py"]
             and cust["role_runtime_sha256"] == self.pins.code_sha256s["scripts/ge_auto_role_runtime.py"],
             "NATIVE_DRIVER_CALLBACK_PINS_CHANGED")

    def _host_check(self, kind, binding):
        self._check_pins()
        need(self.host_verify(kind, p.decode(p.canonical({"case_root": str(self.root),
            "protected_host_root": str(self.protected), "request_sha256": self.request_sha,
            "policy_sha256": p.digest(self.policy.manifest()), **binding}))) is True,
            "HOST_EVIDENCE_VERIFICATION_DENIED")

    def _record(self, kind, value):
        path = self.prefix + "/" + kind + "-" + p.digest(value) + ".json"
        _mkdir(self.host_store, self.prefix)
        raw = p.canonical(value)
        if self.host_store.exists(path):
            need(self.native_observations.get(path) == p.digest(raw)
                 and self.host_store.read(path) == raw, "UNOBSERVED_DRIVER_RECORD")
        else:
            self.host_store.write_new(path, raw)
            need(self.host_store.read(path) == raw, "DRIVER_RECORD_CHANGED")
            self.native_observations[path] = p.digest(raw)
        return path

    def _invoke(self, job):
        result = self._roles(job)  # Custody checks actual runtime completion first.
        p.checked(result, p.obj({"context_id": p.string(100), "input_sha256": p.HASH,
                                "receipt_sha256": p.HASH, "output": p.SCHEMAS[job.role]}))
        self.roles[job.role] = copy.deepcopy(result)
        self._record("role", {"role": job.role, "receipt": result})
        return result

    def _search(self, envelope, reservation):
        callback = self.custody.search_callback(self.host_key, self.capability,
            timeout_seconds=self.web_timeout, poll_seconds=0.1)
        request_path = "broker/search-" + p.digest(reservation) + "/request.json"
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(callback, envelope, reservation)
            deadline = time.monotonic() + self.web_timeout
            while not self.store.exists(request_path):
                if future.done():
                    return future.result()
                need(time.monotonic() < deadline, "BROKER_REQUEST_DEADLINE")
                time.sleep(0.05)
            request_raw = self.store.read(request_path)
            observation = self.service_web(request_raw, copy.deepcopy(reservation))
            need(type(observation) is WebObservation and isinstance(observation.host_receipt, bytes)
                 and bool(observation.host_receipt), "ACTUAL_HOST_WEB_OBSERVATION_REQUIRED")
            self._host_check("web_observation", {"request_sha256": self.request_sha,
                "broker_request_sha256": p.digest(request_raw), "reservation": reservation,
                "raw_sha256": p.digest(observation.raw_utf8.encode()), "hits_sha256": p.digest(observation.hits),
                "tool_call_id": observation.tool_call_id, "host_receipt": p.decode(observation.host_receipt)})
            self.custody.publish_web_response(self.host_key, self.capability, reservation,
                raw_utf8=observation.raw_utf8, hits=list(observation.hits), tool_call_id=observation.tool_call_id)
            return future.result()

    def _capture(self, envelope, reservation):
        result = self._capture_callback(envelope, reservation)
        sha = p.digest(base64.b64decode(result["raw_b64"], validate=True))
        record = {"reservation": copy.deepcopy(reservation), "capture": copy.deepcopy(result),
                  "researcher_id": self.roles["selector"]["context_id"]}
        need(sha not in self.captures or self.captures[sha] == record, "AMBIGUOUS_CAPTURE_LEDGER")
        self.captures[sha] = record
        self._record("capture", record)
        return result

    def _contracts_for(self, proposition):
        need(len(self.history) == len(self.request["history"]), "TECHNICAL_PRIOR_CONTRACT_SNAPSHOT_MISSING")
        plan = self.roles["planner"]["output"]
        resolution = self.resolve_gap(copy.deepcopy({"request": self.request, "planner_receipt": self.roles["planner"],
            "proposition": proposition, "reviewer_receipt": self.roles["reviewer"], "baseline_sha256": EMPTY}))
        need(type(resolution) is GapResolution and isinstance(resolution.receipt, bytes) and resolution.receipt,
             "ACTUAL_GAP_RESOLUTION_REQUIRED")
        selected = [q for q in plan["queries"] if q["gap_id"] in resolution.query_ids]
        need(selected and len(set(resolution.query_ids)) == len(resolution.query_ids)
             and {q["gap_id"] for q in selected} == set(resolution.query_ids), "GAP_QUERY_IDENTITY_CHANGED")
        need(all(q["jurisdiction"] == proposition["jurisdiction"] and q["as_of_date"] == proposition["as_of_date"]
                 and q["kind"] == resolution.gap_class for q in selected), "GAP_QUERY_SCOPE_CHANGED")
        need(proposition["jurisdiction"] in self.request["jurisdictions"], "FEDERAL_CONTRACT_SCOPE_NOT_EXPLICIT")
        # The helper cannot infer the schema's missing-fact linkage/blocking boolean.
        need(not plan["clarifications"] or resolution.missing_facts, "CLARIFICATION_MAPPING_REQUIRED")
        self._host_check("gap_resolution", {"resolution": {k: v for k, v in asdict(resolution).items() if k != "receipt"},
            "receipt": p.decode(resolution.receipt), "planner_receipt": self.roles["planner"],
            "proposition": proposition, "baseline_sha256": EMPTY})
        result = self._build_selected_contract(resolution, selected, self.observed_at)
        self._record("contracts", {"proposition_sha256": p.digest(proposition),
            "artifact_lineage": result.artifact_lineage, "gap_receipt_sha256": p.digest(resolution.receipt)})
        return result

    def _build_selected_contract(self, resolution, selected, observed_at):
        return contracts.build_case_contracts(request=self.request, request_sha256=self.request_sha,
            ordered_history=self.history, due_uploads=self.uploads,
            jurisdiction=selected[0]["jurisdiction"], as_of_date=date.fromisoformat(selected[0]["as_of_date"]),
            issue_id=resolution.issue_id, pins=self.pins.contract, registry=self.registry, observed_at=observed_at,
            encrypt_store=self.vault, query_variants=[q["query"] for q in selected],
            missing_facts=resolution.missing_facts, budgets=self.budgets,
            response_disposition=resolution.response_disposition, answer_route=resolution.answer_route,
            affected_claim_sha256=resolution.affected_claim_sha256,
            existing_retrieval_sha256=resolution.existing_retrieval_sha256, gap_class=resolution.gap_class)

    def build_history_contract(self, *, resolution: GapResolution, observed_at: datetime):
        """Host-authorized POST-terminal snapshot, never a prior legal approval.

        Requires actual queries from this turn's planner and an actual host
        lookup/affected-issue receipt. A no-query turn remains a technical hold.
        The explicit timestamp records retrospective construction truthfully.
        """
        terminal = self.read_terminal()
        need(terminal["answer"] is not None and "planner" in self.roles, "HISTORY_PLANNER_AND_TERMINAL_REQUIRED")
        need(type(resolution) is GapResolution and isinstance(resolution.receipt, bytes) and resolution.receipt,
             "ACTUAL_GAP_RESOLUTION_REQUIRED")
        need(type(observed_at) is datetime and observed_at.tzinfo is not None
             and observed_at >= self.observed_at, "EXPLICIT_HISTORY_BUILD_TIME_REQUIRED")
        need(len(self.history) == len(self.request["history"]), "TECHNICAL_PRIOR_CONTRACT_SNAPSHOT_MISSING")
        plan = self.roles["planner"]["output"]
        selected = [q for q in plan["queries"] if q["gap_id"] in resolution.query_ids]
        need(selected and len(set(resolution.query_ids)) == len(resolution.query_ids)
             and {q["gap_id"] for q in selected} == set(resolution.query_ids), "ACTUAL_HISTORY_PLANNER_QUERY_REQUIRED")
        need(all((q["kind"], q["jurisdiction"], q["as_of_date"]) ==
                 (resolution.gap_class, selected[0]["jurisdiction"], selected[0]["as_of_date"]) for q in selected),
             "GAP_QUERY_SCOPE_CHANGED")
        need(not plan["clarifications"] or resolution.missing_facts, "CLARIFICATION_MAPPING_REQUIRED")
        evidence = {"kind": "POST_TERMINAL_HOST_HISTORY_CONTRACT", "terminal_sha256": terminal["terminal_sha256"],
            "planner_receipt": self.roles["planner"], "observed_at": observed_at.isoformat(),
            "resolution": {k: v for k, v in asdict(resolution).items() if k != "receipt"},
            "receipt": p.decode(resolution.receipt), "baseline_sha256": EMPTY,
            "legal_proposition": None, "source_approval": False}
        self._host_check("history_contract_resolution", evidence)
        result = self._build_selected_contract(resolution, selected, observed_at)
        self._record("post-terminal-history-contract", {**evidence, "artifact_lineage": result.artifact_lineage})
        key = "history-" + resolution.issue_id
        need(key not in self.contracts, "HISTORY_CONTRACT_ALREADY_OBSERVED")
        self.contracts[key] = result
        return copy.deepcopy(result)

    def _review_verify(self, reviewer, receipt):
        expected = self.translated_reviews.get(research.digest(receipt))
        return (expected is not None and expected == receipt
                and reviewer == self.roles["reviewer"]["context_id"])

    def _make_adapter(self, data):
        need(self.native_adapter is None and {"planner", "selector", "mapper", "reviewer"} <= self.roles.keys(),
             "ACTUAL_COMPLETE_ROLE_CHAIN_REQUIRED")
        need(1 <= len(data["propositions"]) <= 8, "RERANK_PAIR_BUDGET_HOLD")
        review = adapter.ReviewBinding(self.roles["reviewer"], self.roles["mapper"]["context_id"],
            self.roles["mapper"]["receipt_sha256"], self.roles["selector"]["context_id"],
            self.roles["selector"]["receipt_sha256"])
        need(data["review_sha256"] == p.digest(review.reviewer_receipt["output"]), "SOURCE_REVIEW_CHANGED")
        scope = research.Scope(str(self.root / "legal-index"), "candidate_case_local",
                               self.policy.run_id, self.request["case_id"])
        owner = self.custody.policy["owner_instruction_sha256"]
        # The custody reader is not exposed; parent supplies actual owner bytes in
        # a separately verified initialization receipt through its host callback.
        owner_raw = self._owner_bytes
        need(p.digest(owner_raw) == owner, "OWNER_BYTES_CHANGED")
        policy = research.ResearchPolicy(workspace=self.workspace, owner_instruction=owner_raw,
            expected_owner_instruction_sha256=owner, scopes=(scope,),
            model=research.ModelPin.from_runtime_identity(self.pins.embedding_identity),
            reviewers=(review.reviewer_receipt["context_id"],), verify_review=self._review_verify)
        bindings = {}
        originals = {p.digest(base64.b64decode(s["raw_b64"], validate=True)): s for s in data["sources"]}
        for prop in data["propositions"]:
            result = self._contracts_for(prop)
            self.contracts[prop["proposition_id"]] = result
            lineage = adapter.bind_contracts(result.binding, request_sha256=self.request_sha)
            bound = []
            for sha in sorted({s["source_sha256"] for s in adapter.spans(prop)}):
                need(sha in self.captures and originals[sha] == self.captures[sha]["capture"],
                     "UNOBSERVED_CAPTURE_OR_PRIOR_SOURCE_HOLD")
                source_row = next(s for s in self.roles["reviewer"]["output"]["sources"] if s["source_sha256"] == sha)
                capture, mapping = capture_from_ledger(store=self.store,
                    reservation=self.captures[sha]["reservation"], original=originals[sha], scope=scope,
                    researcher_id=self.captures[sha]["researcher_id"], jurisdiction=prop["jurisdiction"],
                    source_review=source_row, reviewer_receipt_sha256=self.roles["reviewer"]["receipt_sha256"])
                coverage = complete_reviewed_blocks(prop, originals[sha], mapping)
                source = adapter.SourceBinding(capture, mapping, coverage)
                translated = adapter.translate_review(source=source, original=originals[sha], proposition=prop,
                    review=review, contracts=result.binding, lineage=lineage, scope=scope)
                self.translated_reviews[research.digest(translated)] = copy.deepcopy(translated)
                bound.append(source)
            bindings[prop["proposition_id"]] = adapter.PropositionBinding(result.binding, tuple(bound))
        baseline = {b.contracts.expected_knowledge_generation_sha256 for b in bindings.values()}
        need(len(baseline) == 1, "COMMON_BASELINE_CONTRACT_CHANGED")
        pins = adapter.AdapterPins(self.request["case_id"], self.request_sha, p.digest(self.policy.manifest()),
            owner, policy.sha256, self.pins.code_sha256s["backend/app/research/ge_auto_index.py"],
            self.pins.code_sha256s["scripts/ge_auto_case_index_adapter.py"], self.pins.native_index_verifier_sha256,
            self.pins.embedding_identity, next(iter(baseline)), self.registry.manifest_sha256,
            self.policy.retry_profile_sha256s, self.pins.reranker_identity["identity_sha256"])
        from scripts.ge_auto_research_runtime import PinnedEmbeddingSession, verified_model_identity
        def capability(action, binding):
            return policy.authorize(scope=scope, actor=self.pins.contract.candidate_id,
                role="candidate", action=action, binding_sha256=binding)
        self.research_policy = policy
        self.native_adapter = adapter.CaseIndexAdapter(case_root=self.root, pins=pins, policy=policy, scope=scope,
            bindings=bindings, review=review, capability_factory=capability, host_verify=self.native_verify,
            embedding_session_factory=PinnedEmbeddingSession, verify_identity=verified_model_identity, rerank=self._rerank)

    def _rerank(self, job):
        from scripts.ge_auto_research_reranker import PinnedRerankerSession
        need(job["embedding_sessions_closed"] is True
             and job["model_identity_sha256"] == self.pins.reranker_identity["identity_sha256"], "RERANK_SCOPE_CHANGED")
        pairs, ids = [], []
        for item in job["evidence"]:
            prop = item["proposition"]
            queries = [q["query"] for q in job["public_queries"]
                       if q["jurisdiction"] == prop["jurisdiction"] and q["as_of_date"] == prop["as_of_date"]]
            need(queries, "RERANK_QUERY_SCOPE")
            # Complete reviewed evidence, no truncation or omission of conditions.
            doc = "\n".join(dict.fromkeys(s["text"] for s in adapter.spans(prop)))
            pairs.append(("\n".join(dict.fromkeys(queries)), doc))
            ids.append(prop["proposition_id"])
        need(1 <= len(pairs) <= 8, "RERANK_PAIR_BUDGET_HOLD")
        with PinnedRerankerSession() as session:
            need(session.identity == self.pins.reranker_identity and session.lock is not None,
                 "RERANKER_IDENTITY_CHANGED")
            lease = {"job_sha256": p.digest(job), "lock_path": str(Path(session.lock.name)),
                     "exclusive_lock_observed": True, "model_identity": session.identity}
            scores = session.predict(pairs)
            execution = copy.deepcopy(session.receipt())
        need(session.model is None and session.tokenizer is None and session.lock is None,
             "RERANKER_NOT_CLOSED")
        need(len(scores) == len(ids) and all(math.isfinite(s) and 0 <= s <= 1 for s in scores)
             and execution["actual_pairs_scored"] == len(ids), "RERANKER_EXECUTION_INCOMPLETE")
        self._record("reranker", {"job": job, "execution": execution, "lease": lease, "scores": scores})
        return {"ordered_proposition_ids": [ids[i] for i in sorted(range(len(ids)), key=lambda i: (-scores[i], i))],
            "receipt": {"model": "Qwen/Qwen3-Reranker-0.6B", "model_identity_sha256": job["model_identity_sha256"],
                "input_sha256": p.digest(job), "actual_inference_calls": len(scores),
                "execution_receipt_sha256": p.digest(execution), "exclusive_model_lease_sha256": p.digest(lease),
                "session_closed": True, "synthetic_vectors": False, "training": False}}

    def _wrap_native(self, kind, envelope, native):
        inventory = self.store.inventory("legal-index")
        files = {"legal-index/" + name: sha for name, sha in inventory.items()}
        need(files, "ACTUAL_NATIVE_INDEX_FILES_REQUIRED")
        common = {"case_root": str(self.root), "index_root": str(self.root / "legal-index"),
            "case_id": self.request["case_id"], "request_sha256": self.request_sha,
            "policy_sha256": p.digest(self.policy.manifest()), "run_id": self.policy.run_id,
            "baseline_sha256": EMPTY, "lane": "candidate_case_local"}
        receipt = {**common, "kind": kind, "input_sha256": p.digest(envelope),
            "result_sha256": p.digest({k: v for k, v in native.items() if k != "receipt_sha256"}),
            "index_runtime_sha256": self.custody.pins["index_runtime_sha256"],
            "embedding_model_sha256": self.custody.pins["embedding_model_sha256"],
            "non_live": True, "active_mutated": False, "synthetic_vectors": False, "files": files}
        path = "index/" + kind + "-" + self.request_sha + "-" + p.digest(envelope) + ".json"
        _mkdir(self.host_store, "index")
        self.host_store.write_new(path, p.canonical(receipt))
        need(self.host_store.read(path) == p.canonical(receipt), "NATIVE_WRAPPER_READBACK_CHANGED")
        result = {**native, "receipt_sha256": p.digest(receipt)}
        self._record("native-result", {"kind": kind, "envelope": envelope, "native": native,
                                      "protocol_result": result, "protected_receipt": path})
        if kind == "index":
            self.native_builds[p.digest(result)] = (copy.deepcopy(result), copy.deepcopy(native))
        else:
            self.native_retrievals[p.digest(result)] = copy.deepcopy(native)
        return custody_api.IndexObservation(result, path, files)

    def index(self, envelope, reservation):
        try:
            self._check_pins()
            if self.native_adapter is None:
                self._make_adapter(envelope["data"])
            native = self.native_adapter.index(envelope, reservation)
            return self._wrap_native("index", envelope, native)
        except (adapter.AdapterHold, contracts.ContractBuildError) as exc:
            raise p.ActionHold(str(exc)) from None

    def retrieve(self, envelope, reservation):
        self._check_pins()
        build = envelope["data"]["build"]
        pair = self.native_builds.get(p.digest(build))
        need(pair is not None and pair[0] == build and self.native_adapter is not None,
             "UNOBSERVED_NATIVE_BUILD_TRANSLATION")
        translated = copy.deepcopy(envelope)
        translated["data"]["build"] = copy.deepcopy(pair[1])
        native_reservation = {**reservation, "input_sha256": p.digest(translated)}
        self._record("native-reservation-translation", {"protocol_envelope": envelope,
            "protocol_reservation": reservation, "native_envelope": translated, "native_reservation": native_reservation})
        self._host_check("native_reservation_translation", {"protocol_envelope": envelope,
            "protocol_reservation": reservation, "native_envelope": translated, "native_reservation": native_reservation})
        try:
            native = self.native_adapter.retrieve(translated, native_reservation)
        except adapter.AdapterHold as exc:
            raise p.ActionHold(str(exc)) from None
        return self._wrap_native("retrieve", envelope, native)

    def run(self, *, active_owner_instruction_bytes: bytes):
        """Perform the single due invocation; no implicit dispatch from construction."""
        need(not self._started, "DRIVER_ALREADY_DISPATCHED")
        self._started = True
        self._check_pins()
        need(isinstance(active_owner_instruction_bytes, bytes)
             and p.digest(active_owner_instruction_bytes) == self.policy.owner_instruction_sha256,
             "ACTUAL_OWNER_INSTRUCTION_REQUIRED")
        self._owner_bytes = bytes(active_owner_instruction_bytes)
        self._host_check("driver_start", {"global_marker_sha256": p.digest(self.global_marker),
            "owner_instruction_sha256": p.digest(self._owner_bytes), "pins": self.pins.material()})
        need(callable(getattr(self.custody, "register_global_marker", None)), "GLOBAL_MARKER_CUSTODY_API_REQUIRED")
        need(self.marker_callback(self.global_marker) is True, "ACTUAL_PARENT_MARKER_CALLBACK_DENIED")
        self.custody.register_global_marker(self.host_key, marker_bytes=self.global_marker)
        for upload in self.request["due_uploads"]:
            evidence = self.uploads[upload["upload_id"]]
            need(type(evidence) is contracts.UploadEvidence, "ACTUAL_UPLOAD_EVIDENCE_REQUIRED")
            path = self.upload_receipt_paths[upload["upload_id"]]
            need(path.startswith("uploads/") and self.host_store.read(path) == evidence.extraction_receipt,
                 "PROTECTED_EXTRACTION_RECEIPT_CHANGED")
            self.custody.register_upload(self.host_key, self.capability, upload=upload,
                raw=evidence.raw, protected_receipt=path)
        encrypted = []
        inputs = [("question", self.request["question"].encode("utf-8"))]
        for upload in self.request["due_uploads"]:
            evidence = self.uploads[upload["upload_id"]]
            inputs.extend((("upload-raw:" + upload["upload_id"], evidence.raw),
                ("upload-text:" + upload["upload_id"], upload["text"].encode("utf-8")),
                ("upload-extraction:" + upload["upload_id"], evidence.extraction_receipt)))
        for kind, raw in inputs:
            provenance = {"schema": "legalbot.ge-driver-due-artifact.v1", "case_id": self.request["case_id"],
                "request_sha256": self.request_sha, "turn": self.request["turn"], "kind": kind,
                "pins_sha256": research.digest(self.pins.contract.material()), "plaintext_sha256": p.digest(raw)}
            encrypted.append({"kind": kind, **self.vault(raw, provenance)})
        self._record("due-input-encryption", encrypted)
        self._roles = self.custody.role_callback(self.host_key, self.capability, self.runtime)
        self._capture_callback = self.custody.capture_callback(self.host_key, self.capability)
        protocol = p.CaseProtocol(case_root=self.root, policy=self.policy, capability=self.capability,
                                  guard=self.custody.protocol_guard, store=self.store)
        self._protocol = protocol
        from scripts.ge_unseen_sources import is_allowed_source_url
        result = protocol.run_case(self.request, uploads={k: v.raw for k, v in self.uploads.items()},
            establish_one_pass=lambda binding: self.custody.establish_one_pass(self.host_key, self.capability, binding),
            invoke_role=self._invoke, search=self._search, capture=self._capture, official_url=is_allowed_source_url,
            index=self.custody.index_callback(self.host_key, self.capability, "index", self.index),
            retrieve=self.custody.index_callback(self.host_key, self.capability, "retrieve", self.retrieve))
        evidence_pack = p.decode(self.store.read(f"turn-{self.request['turn']:04d}/EvidencePack.json"))
        if evidence_pack["evidence"]:
            need(self.native_adapter is not None, "ACTUAL_NATIVE_ADAPTER_REQUIRED")
            native = self.native_retrievals.get(p.digest(evidence_pack))
            need(native is not None, "ACTUAL_NATIVE_RETRIEVAL_BINDING_REQUIRED")
            self.selected_retrieval_contracts = self.native_adapter.read_selected_contracts(native)
        self._terminal_result = copy.deepcopy(result)
        self._record("terminal", {"terminal_sha256": result["terminal_sha256"],
                                  "request_sha256": self.request_sha, "actual_parent_validation": "REQUIRED"})
        return result

    def read_terminal(self):
        """Reverify the observed terminal and every sealed artifact with custody."""
        need(self._terminal_result is not None, "OBSERVED_TERMINAL_REQUIRED")
        value, sha = self._protocol._terminal(self.request["turn"], self._terminal_result["terminal_sha256"])
        return {**copy.deepcopy(value), "terminal_sha256": sha}

    @property
    def terminal_result(self):
        if self._terminal_result is None:
            return None
        self.read_terminal()
        return copy.deepcopy(self._terminal_result)

    @property
    def terminal_bytes(self):
        if self._terminal_result is None:
            return None
        self.read_terminal()
        return self.store.read(f"turn-{self.request['turn']:04d}/terminal.json")

    def read_answer_projection(self):
        """Return the exact final role object (possibly HOLD or None), no rewrite."""
        return copy.deepcopy(self.read_terminal()["answer"])

    def read_evidence_pack(self):
        terminal = self.read_terminal()
        path = f"turn-{self.request['turn']:04d}/EvidencePack.json"
        raw = self.store.read(path)
        need(p.digest(raw) == terminal["artifacts"][path], "EVIDENCE_PACK_CHANGED")
        return p.decode(raw)

    def read_source_captures(self):
        """Observed successes, including inherited own-case captures; no approval.

        Failed capture/broker attempts remain in the case ledger and terminal
        artifact manifest. This accessor does not turn them into Capture values.
        """
        self.read_terminal()
        result = []
        for sha, record in sorted(self.captures.items()):
            base = "broker/capture-" + p.digest(record["reservation"])
            original = record["capture"]
            raw_receipt = self.store.read(base + "/parser-receipt.json")
            need(p.digest(raw_receipt) == original["parser_receipt_sha256"], "CAPTURE_READBACK_CHANGED")
            for name, expected in p.decode(raw_receipt)["files"].items():
                need(len(p.parts(name)) == 1 and p.digest(self.store.read(base + "/" + name)) == expected,
                     "CAPTURE_READBACK_CHANGED")
            need(p.digest(base64.b64decode(original["raw_b64"], validate=True)) == sha,
                 "CAPTURE_READBACK_CHANGED")
            result.append(copy.deepcopy(record))
        return tuple(result)

    def read_contracts(self):
        """Actual in-memory contracts by proposition ID; may be empty on HOLD."""
        self.read_terminal()
        return copy.deepcopy(self.contracts)

    def read_selected_retrieval_contracts(self):
        """Return the actual selected RetrievalResult/EvidencePack contract bundle."""
        self.read_terminal()
        need(self.selected_retrieval_contracts is not None,
             "SELECTED_RETRIEVAL_CONTRACTS_UNAVAILABLE")
        return copy.deepcopy(self.selected_retrieval_contracts)

    def read_fact_projection(self):
        """Exact visible facts for independent review; no author/oracle fields."""
        self.read_terminal()
        if self.selected_retrieval_contracts is not None:
            selected = self.read_selected_retrieval_contracts()
            query_plan, fact_snapshot = selected["query_plan"], selected["fact_snapshot"]
        else:
            need(bool(self.contracts), "FACT_PROJECTION_CONTRACTS_UNAVAILABLE")
            binding = next(iter(self.contracts.values())).binding
            query_plan, fact_snapshot = binding.query_plan, binding.fact_snapshot
        requests = [prior.request for prior in self.history] + [self.request]
        return build_fact_projection(case_id=self.request["case_id"],
            turn=self.request["turn"], requests=requests,
            fact_snapshot=fact_snapshot, query_plan=query_plan)

    def read_answer_review_material(self):
        """Assemble exact candidate-visible artifacts after selected retrieval.

        This is a read-only projection from the observed runtime.  It does not
        launch the answer reviewer or accept any claim.  Source blocks come from
        the same live SourceBindings that entered the selected native index.
        """
        terminal = self.read_terminal()
        candidate = terminal.get("answer")
        need(candidate is not None and "final" in self.roles,
             "ANSWER_REVIEW_CANDIDATE_UNAVAILABLE")
        selected = self.read_selected_retrieval_contracts()
        protocol_pack = self.read_evidence_pack()
        retrieved_ids = {row["proposition"]["proposition_id"]
                         for row in protocol_pack["evidence"]}
        need(retrieved_ids and self.native_adapter is not None,
             "ANSWER_REVIEW_SELECTED_EVIDENCE_REQUIRED")
        components = {row["source_version_id"]: row
                      for row in selected["component_receipts"]}
        selected_refs = {row["source_version_id"]: row
                         for row in selected["evidence_pack"]["selected"]}
        need(set(components) == set(selected_refs),
             "ANSWER_REVIEW_SELECTED_SOURCE_COVERAGE")
        source_rows = []
        review_records = []
        for source_version_id, component in sorted(components.items()):
            source_sha = component["source_sha256"]
            need(source_sha in self.captures, "ANSWER_REVIEW_CAPTURE_UNAVAILABLE")
            original = self.captures[source_sha]["capture"]
            coverages = []
            for proposition_id in retrieved_ids:
                binding = self.native_adapter.bindings.get(proposition_id)
                need(binding is not None, "ANSWER_REVIEW_PROPOSITION_BINDING")
                for source in binding.sources:
                    if research.digest(source.capture.raw) == source_sha:
                        coverages.extend(source.reviewed_block_ordinals)
            coverage = sorted(set(coverages))
            need(coverage, "ANSWER_REVIEW_CONTEXT_COVERAGE")
            ordinal_to_part = {ordinal: part_id for part_id, ordinal in
                               next(source.part_ordinals for proposition_id in retrieved_ids
                                    for source in self.native_adapter.bindings[proposition_id].sources
                                    if research.digest(source.capture.raw) == source_sha).items()}
            parts = {part["part_id"]: part for part in original["parts"]}
            block_ids = [ordinal_to_part[ordinal] for ordinal in coverage]
            blocks = [{"block_id": part_id, "ordinal": ordinal,
                       "locator": parts[part_id]["locator"],
                       "text": parts[part_id]["text"],
                       "text_sha256": p.digest(parts[part_id]["text"].encode("utf-8"))}
                      for ordinal, part_id in zip(coverage, block_ids, strict=True)]
            records = [copy.deepcopy(row) for row in self.translated_reviews.values()
                       if row["source_sha256"] == source_sha]
            need(records, "ANSWER_REVIEW_SOURCE_REVIEW_UNAVAILABLE")
            review_records.extend(records)
            valid_from = max(row["valid_from"] for row in records)
            valid_to = min(row["valid_to"] for row in records)
            ref = selected_refs[source_version_id]
            need(ref["evidence_id"] == component["evidence_id"],
                 "ANSWER_REVIEW_EVIDENCE_ID_CHANGED")
            source_rows.append({"source_id": "source-" + source_sha[:40],
                "selected_evidence_id": ref["evidence_id"],
                "raw_sha256": source_sha, "parser_sha256": original["parser_sha256"],
                "parsed_sha256": records[0]["parsed_sha256"],
                "canonical_url": original["canonical_url"], "final_url": original["final_url"],
                "source_review_sha256": p.digest(records),
                "valid_from": valid_from, "valid_to": valid_to,
                "jurisdiction": ref["jurisdiction"], "scope": "candidate_case_local",
                "limits": ["AI source review; no professional legal sign-off."],
                "required_context_block_ids": block_ids, "blocks": blocks})
        issue_ids = list(selected["query_plan"]["issue_ids"])
        queries = [row["query"] for row in self.roles["planner"]["output"]["queries"]]
        clarifications = [row["question"] for row in self.roles["planner"]["output"]["clarifications"]]
        issue_text = "Pre-answer planner scope: " + " | ".join(queries + clarifications)
        requirements = [{"requirement_id": issue_id, "text": issue_text}
                        for issue_id in issue_ids]
        need(requirements, "ANSWER_REVIEW_REQUIREMENTS_UNAVAILABLE")
        source_context = self.roles["reviewer"]["context_id"]
        return {"candidate": candidate, "terminal": {k: v for k, v in terminal.items()
                    if k != "terminal_sha256"},
            "fact_projection": self.read_fact_projection(),
            "evidence": {"case_id": self.request["case_id"],
                "source_references": protocol_pack["source_references"],
                "sources": source_rows},
            "source_review": {"case_id": self.request["case_id"],
                "reviewer_ids": [source_context], "context_ids": [source_context],
                "records": review_records},
            "requirements": requirements, "candidate_receipt": self.roles["final"],
            "selected_contracts": selected}


@dataclass(frozen=True)
class DueTurn:
    """HOST releases this only after the preceding observed answer terminal.

    The parent issues a new capability from the SAME live custody and constructs
    a new actual CodexRoleRuntime for that capability. No future turn is accepted
    by constructdriver. ordered_history contains actual earlier contracts, or is
    empty when they do not exist (later indexing then holds at the contract gate).
    """
    request: Mapping
    due_uploads: Mapping[str, contracts.UploadEvidence]
    upload_receipt_paths: Mapping[str, str]
    ordered_history: Sequence[contracts.PriorTurn]
    capability: object
    role_runtime: CodexRoleRuntime
    observed_at: datetime
    prior_capture_observations: object | None = None


class CaseSession:
    """One persistent HOST process/object per case; never trusted JSON reload.

    runturn(owner bytes) consumes the explicitly constructed first due turn.
    runturn(owner bytes, due=DueTurn(...)) accepts only the next HOST-released
    turn. The same custody, protected root, pins, key and broker callbacks remain
    bound. Each due turn has its own role runtime and contract/index lineage.
    """
    def __init__(self, initial_inputs):
        initial = CaseDriver(**initial_inputs)
        need(initial.request["turn"] == 1 and not initial.history, "FRESH_SESSION_FIRST_TURN_REQUIRED")
        self._inputs = dict(initial_inputs)  # Host-only; contains the in-memory key.
        self._turns = {1: initial}
        self._current = 1
        self._lock = threading.Lock()
        self._capture_handles = {}

    def runturn(self, *, active_owner_instruction_bytes: bytes, due: DueTurn | None = None):
        need(self._lock.acquire(blocking=False), "CONCURRENT_TURN_DENIED")
        try:
            current = self._turns[self._current]
            if due is not None:
                need(type(due) is DueTurn, "EXPLICIT_DUE_TURN_REQUIRED")
                terminal = current.read_terminal()
                need(terminal["answer"] is not None, "FOLLOWUP_REQUIRES_ANSWER_TERMINAL")
                p.checked(due.request, p.REQUEST_SCHEMA)
                expected_history = []
                for turn, previous in self._turns.items():
                    old = previous.read_terminal()
                    expected_history.append({"turn": turn, "request_sha256": previous.request_sha,
                                             "terminal_sha256": old["terminal_sha256"]})
                need(due.request["turn"] == self._current + 1
                     and due.request["case_id"] == current.request["case_id"]
                     and due.request["history"] == expected_history, "FOLLOWUP_HISTORY_CHANGED")
                for prior in due.ordered_history:
                    need(type(prior) is contracts.PriorTurn, "ACTUAL_PRIOR_CONTRACT_REQUIRED")
                    previous = self._turns.get(prior.request["turn"])
                    need(previous is not None and prior.request == previous.request
                         and prior.terminal_bytes == previous.store.read(f"turn-{prior.request['turn']:04d}/terminal.json"),
                         "PRIOR_CONTRACT_TERMINAL_CHANGED")
                    need(any(prior.contracts.artifact_lineage == actual.artifact_lineage
                             and prior.expected_artifact_lineage_sha256 == actual.artifact_lineage["content_sha256"]
                             for actual in previous.contracts.values()), "UNOBSERVED_PRIOR_CONTRACT_SNAPSHOT")
                inputs = {**self._inputs, **{name: getattr(due, name) for name in DueTurn.__dataclass_fields__
                                           if name != "prior_capture_observations"}}
                next_driver = CaseDriver(**inputs)
                # Copies only captures observed in this live family. The fresh
                # reviewer must reassess every reused source/proposition.
                handle = due.prior_capture_observations
                if handle is None:
                    handle = self.prior_capture_observations(self._current)
                self._inherit_captures(next_driver, handle)
                self._current += 1
                self._turns[self._current] = next_driver
                current = next_driver
            return current.run(active_owner_instruction_bytes=active_owner_instruction_bytes)
        finally:
            self._lock.release()

    def _turn(self, turn):
        need(type(turn) is int and turn in self._turns, "UNOBSERVED_TURN")
        return self._turns[turn]

    @property
    def current_driver(self):
        """Live HOST-only driver for the pinned native verifier; never serialize."""
        return self._turns[self._current]

    @property
    def terminal_result(self):
        return self.current_driver.terminal_result

    @property
    def terminal_bytes(self):
        return self.current_driver.terminal_bytes

    @property
    def roles(self):
        return copy.deepcopy(self.current_driver.roles)

    @property
    def contracts(self):
        return self.current_driver.read_contracts()

    def prior_capture_observations(self, turn: int):
        """Opaque in-process handle; only this live family's verified captures."""
        driver = self._turn(turn)
        captures = driver.read_source_captures()
        handle = object()
        self._capture_handles[handle] = (turn, driver.read_terminal()["terminal_sha256"], captures)
        return handle

    def _inherit_captures(self, target, handle):
        need(type(handle) is object and handle in self._capture_handles, "UNOBSERVED_CAPTURE_FAMILY_HANDLE")
        turn, terminal_sha, captures = self._capture_handles[handle]
        previous = self._turn(turn)
        need(target.custody is previous.custody and target.root == previous.root
             and target.protected == previous.protected and target.policy == previous.policy
             and target.request["case_id"] == previous.request["case_id"]
             and target.request["turn"] == turn + 1
             and previous.read_terminal()["terminal_sha256"] == terminal_sha
             and previous.read_source_captures() == captures, "PRIOR_CAPTURE_CUSTODY_CHANGED")
        target.captures = copy.deepcopy(previous.captures)

    def build_history_contract(self, turn: int, *, resolution: GapResolution, observed_at: datetime):
        need(self._lock.acquire(blocking=False), "CONCURRENT_TURN_DENIED")
        try:
            need(turn == self._current, "SEALED_FOLLOWUP_HISTORY_CANNOT_CHANGE")
            return self._turn(turn).build_history_contract(resolution=resolution, observed_at=observed_at)
        finally:
            self._lock.release()

    def read_terminal(self, turn: int):
        return self._turn(turn).read_terminal()

    def read_answer_projection(self, turn: int):
        return self._turn(turn).read_answer_projection()

    def read_evidence_pack(self, turn: int):
        return self._turn(turn).read_evidence_pack()

    def read_source_captures(self, turn: int):
        return self._turn(turn).read_source_captures()

    def read_contracts(self, turn: int):
        return self._turn(turn).read_contracts()

    def read_fact_projection(self, turn: int):
        return self._turn(turn).read_fact_projection()

    def read_answer_review_material(self, turn: int):
        return self._turn(turn).read_answer_review_material()


def constructdriver(**explicit_inputs) -> CaseSession:
    """Explicit keyword arguments are exactly those required by CaseDriver.

    No bank, roots, requests, pins, runtime, custody, verifier or key defaults.
    This creates a HOST object only; runturn is the blocking execution boundary.
    The parent owns process launch/IPC and calls its real functions.web service
    in response to service_web requests; that service must return WebObservation.
    """
    return CaseSession(explicit_inputs)
