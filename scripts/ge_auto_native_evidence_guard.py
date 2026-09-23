"""Closed host verifier for CaseDriver's native index adapter.

Construct before the driver; pass ``guard.verify`` directly as native_index_verify.
The getter is called only by verify. expected_code_sha256s must contain every
driver.CODE_FILES entry AND this file, frozen by the parent after implementation.
No callbacks, pins, capabilities or paths are accepted from worker JSON.

This is a read-only verifier, not a source reviewer, model runner or capability
issuer. It trusts the parent's live Python objects, pinned native code and custody
observations. It checks the actual adapter call frame and live embedding session;
an arbitrary self-sealed receipt, even matching a file, cannot bootstrap trust.
Accepted sessions are retained until the guard is discarded, enabling closure and
receipt checks on cached calls. A fresh guard cannot adopt old inference receipts.
Use one guard across the ordered CaseSession turns. This is not protection against
a hostile parent Python interpreter or proof of model quality/legal currentness.

SQLite opens mode=ro; Lance is opened only at the already-published, manifest-bound
generation. No model identity scanner, model loader, network or write API is used.
Query vector hashes are bound to the observed live pinned session, not independently
recomputed by a second inference. Document vectors also have persisted Lance
readback. All full prepared context rows must be present before evidence release.
Original legal holds, admission, training and production flags are never changed.
"""

from __future__ import annotations

import copy
import fcntl
import inspect
import math
import os
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType

from backend.app.contracts.schema_registry import canonical_json_bytes, seal_contract
from backend.app.ingestion.chunking import StructuralChunker
from backend.app.research import ge_auto_index as research

from scripts import ge_auto_case_contracts as contracts
from scripts import ge_auto_case_custody as custody_api
from scripts import ge_auto_case_driver as driver_api
from scripts import ge_auto_case_index_adapter as adapter_api
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_research_runtime as embedding
from scripts.ge_auto_role_runtime import CodexRoleRuntime

GUARD_FILE = "scripts/ge_auto_native_evidence_guard.py"
COMMON_FIELDS = frozenset({"schema", "action", "case_root", "scope", "pins",
                           "baseline_sha256", "non_live", "private_reference_inputs"})
ACTION_FIELDS = MappingProxyType({
    "capability": frozenset({"index_action", "binding_sha256"}),
    "protocol_reservation": frozenset({"envelope_sha256", "reservation"}),
    "open_adapter_store": frozenset(),
    "embedding_execution": frozenset({"receipt"}),
    "persisted_generation": frozenset({"receipt", "inference"}),
    "persisted_evidence_pack": frozenset({"result", "receipt", "reranker_receipt"}),
    "contract_lineage": frozenset({"lineage", "context_receipt_sha256",
        "existing_retrieval_sha256", "knowledge_generation_sha256"}),
    "complete_retrieved_context": frozenset({"proposition", "generation_sha256",
        "retrieval_sha256s", "required_rows_sha256", "review_sha256"}),
    "reranker_before_load": frozenset({"job_sha256"}),
    "reranker_execution": frozenset({"job", "result"}),
    "persisted_retrieval": frozenset({"receipts", "inference"}),
    "translated_source_review": frozenset({"legal_input_sha256", "context_receipt_sha256",
        "lineage", "capture_manifest", "part_ordinals", "index_review", "reviewer_receipt",
        "mapper_context_id", "selector_context_id"}),
    "prepared_build": frozenset({"build_sha256", "lineage", "row_manifest_sha256"}),
    "own_prior_generation": frozenset({"result"}),
})


class EvidenceHold(ValueError):
    """Only fixed codes leave this helper; never disclose evidence in an error."""


def _need(condition, code):
    if not condition:
        raise EvidenceHold(code)


def _same(actual, expected, code):
    _need(p.canonical(actual) == p.canonical(expected), code)


def _fields(value, names):
    _need(type(value) is dict and set(value) == set(names), "EXACT_FIELDS_REQUIRED")


def _hash(value):
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "HASH_REQUIRED")
    return value


def _safe(path, root, *, file=False):
    path, root = Path(path), Path(root)
    _need(path.is_absolute() and root.is_absolute() and ".." not in path.parts
          and path.is_relative_to(root), "PATH_SCOPE")
    _need(not any(q.is_symlink() for q in (path, *path.parents)), "SYMLINK_DENIED")
    if file:
        _need(path.is_file() and path.stat().st_nlink == 1, "REGULAR_UNLINKED_FILE_REQUIRED")
    return path


def _closed(session):
    _need(session.provider is None and session.lock is None, "EMBEDDING_SESSION_STILL_OPEN")


@dataclass
class _Turn:
    driver: object
    adapter: object
    identity: bytes
    legal: dict | None = None
    operation: tuple | None = None
    prepared: dict = field(default_factory=dict)
    generations: dict = field(default_factory=dict)
    inferences: dict = field(default_factory=dict)
    retrieved: dict = field(default_factory=dict)
    reranked: dict = field(default_factory=dict)
    pending_rerank: str | None = None


class NativeEvidenceGuard:
    """Fail-closed bound-method API; no getter invocation during construction."""

    def __init__(self, driver_getter: Callable, *, workspace_root: Path,
                 expected_code_sha256s: Mapping[str, str]):
        _need(callable(driver_getter), "TRUSTED_DRIVER_GETTER_REQUIRED")
        self.workspace = Path(workspace_root)
        _safe(self.workspace, self.workspace)
        _need(isinstance(expected_code_sha256s, Mapping), "FROZEN_CODE_PINS_REQUIRED")
        pins = dict(expected_code_sha256s)
        _need(set(driver_api.CODE_FILES) | {GUARD_FILE} <= pins.keys(), "ALL_CODE_PINS_REQUIRED")
        for name, sha in pins.items():
            _need(type(name) is str and name.endswith(".py") and not Path(name).is_absolute()
                  and ".." not in Path(name).parts
                  and name.startswith(("scripts/", "backend/app/")), "CODE_PATH_REQUIRED")
            _hash(sha)
        self.expected_code_sha256s = MappingProxyType(pins)
        self._getter = driver_getter
        self._turns = {}
        self._lock = threading.RLock()
        self.last_hold = None

    def verify(self, binding) -> bool:
        """Return literal bool. Missing, altered or out-of-order evidence holds."""
        frame = inspect.currentframe()
        caller = frame.f_back
        try:
            with self._lock:
                _need(type(binding) is dict and type(binding.get("action")) is str,
                      "ACTION_REQUIRED")
                action = binding["action"]
                _need(action in ACTION_FIELDS, "UNKNOWN_ACTION")
                _fields(binding, COMMON_FIELDS | ACTION_FIELDS[action])
                driver, state = self._live(binding, caller)
                details = {k: binding[k] for k in ACTION_FIELDS[action]}
                self._dispatch(driver, state, action, details, caller.f_back)
                self.last_hold = None
                return True
        except Exception as exc:
            # Dependency/parser/SQLite/Lance errors fail closed without leaking bytes.
            self.last_hold = str(exc) if type(exc) is EvidenceHold else "NATIVE_EVIDENCE_UNAVAILABLE"
            return False
        finally:
            del caller, frame  # Do not retain Python frames, model providers or keys.

    def _live(self, binding, caller):
        d = self._getter()
        _need(type(d) is driver_api.CaseDriver, "LIVE_CASE_DRIVER_REQUIRED")
        _need(d.workspace == self.workspace, "WORKSPACE_CHANGED")
        for name, sha in self.expected_code_sha256s.items():
            path = _safe(self.workspace / name, self.workspace, file=True)
            _need(p.digest(path.read_bytes()) == sha, "FROZEN_CODE_CHANGED")
        _same(d.pins.code_sha256s, {n: self.expected_code_sha256s[n] for n in driver_api.CODE_FILES},
              "DRIVER_CODE_PINS_CHANGED")
        d._check_pins()
        _need(type(d.custody) is custody_api.CaseCustody and type(d.runtime) is CodexRoleRuntime,
              "ACTUAL_CUSTODY_RUNTIME_REQUIRED")
        a = d.native_adapter
        _need(type(a) is adapter_api.CaseIndexAdapter and a.policy is d.research_policy,
              "ACTUAL_ADAPTER_REQUIRED")
        _need(caller.f_code is adapter_api.CaseIndexAdapter._verify.__code__
              and caller.f_locals.get("self") is a, "PINNED_ADAPTER_CALL_REQUIRED")
        _same(binding, caller.f_locals["binding"], "ADAPTER_CALL_CHANGED")
        # Driver construction pins callback hash; subsequent checks retain the
        # exact immutable function/code/owner. Re-marshalling code is refcount
        # sensitive in this Python runtime and is not a stable second identity.
        _need(d.native_verify == self.verify and a.host_verify == self.verify,
              "NATIVE_CALLBACK_CHANGED")
        _need(a.embedding_session_factory is embedding.PinnedEmbeddingSession
              and a.verify_identity is embedding.verified_model_identity
              and a.rerank == d._rerank, "NATIVE_EXECUTION_CALLBACK_CHANGED")
        _safe(d.root, self.workspace)
        _safe(d.protected, self.workspace)
        _need(d.root != self.workspace and not d.root.is_relative_to(d.protected)
              and not d.protected.is_relative_to(d.root), "PROTECTED_ROOT_NOT_DISJOINT")
        _need(d.host_store is d.custody.store and d.custody.root == d.protected
              and d.store.root == d.root and a.root == d.root, "ACTUAL_STORE_ROOT_CHANGED")
        case = d.custody._case(d.capability)
        _same(case["request"], d.request, "CUSTODY_REQUEST_CHANGED")
        _need(case["root"] == d.root and case["request_sha"] == d.request_sha == p.digest(d.request),
              "CUSTODY_TURN_CHANGED")
        scope = research.Scope(str(d.root / "legal-index"), "candidate_case_local",
                               d.policy.run_id, d.request["case_id"])
        _same(asdict(a.scope), asdict(scope), "ACTUAL_SCOPE_CHANGED")
        _need(d.contracts and set(d.contracts) == set(a.bindings), "ACTUAL_CONTRACTS_REQUIRED")
        baseline = {c.binding.expected_knowledge_generation_sha256 for c in d.contracts.values()}
        _need(len(baseline) == 1, "COMMON_BASELINE_REQUIRED")
        expected = adapter_api.AdapterPins(d.request["case_id"], d.request_sha,
            p.digest(d.policy.manifest()), d.pins.contract.owner_instruction_sha256,
            d.research_policy.sha256, self.expected_code_sha256s["backend/app/research/ge_auto_index.py"],
            self.expected_code_sha256s["scripts/ge_auto_case_index_adapter.py"],
            d.pins.native_index_verifier_sha256, d.pins.embedding_identity, next(iter(baseline)),
            d.registry.manifest_sha256, d.policy.retry_profile_sha256s,
            d.pins.reranker_identity["identity_sha256"])
        _same(asdict(a.pins), asdict(expected), "ACTUAL_ADAPTER_PINS_CHANGED")
        _same({k: binding[k] for k in COMMON_FIELDS}, {
            "schema": adapter_api.VERSION, "action": binding["action"], "case_root": str(d.root),
            "scope": asdict(scope), "pins": asdict(expected), "baseline_sha256": adapter_api.EMPTY,
            "non_live": True, "private_reference_inputs": False}, "COMMON_BINDING_CHANGED")
        a._pin_check()
        self._roles(d, case)
        pin_material = d.pins.material()
        identity = p.canonical({"request": d.request, "pins": pin_material,
                                "root": str(d.root), "protected": str(d.protected)})
        key = (str(d.root), d.request_sha)
        if key not in self._turns:
            self._turns[key] = _Turn(d, a, identity)
        state = self._turns[key]
        _need(state.driver is d and state.adapter is a and state.identity == identity,
              "LIVE_DRIVER_REPLACED")
        return d, state

    @staticmethod
    def _records(d, kind):
        prefix = "driver/" + d.request_sha + "/" + kind + "-"
        output = []
        for name, sha in tuple(d.native_observations.items()):
            if not name.startswith(prefix):
                continue
            _hash(sha)
            raw = d.host_store.read(name)
            _need(p.digest(raw) == sha, "PROTECTED_OBSERVATION_CHANGED")
            value = p.decode(raw)
            _need(raw == p.canonical(value) and name == prefix + p.digest(value) + ".json",
                  "PROTECTED_RECORD_IDENTITY_CHANGED")
            output.append(value)
        return output

    def _record(self, d, kind, value):
        _need(any(p.canonical(v) == p.canonical(value) for v in self._records(d, kind)),
              "PROCESS_OBSERVED_PROTECTED_RECORD_REQUIRED")

    def _roles(self, d, case):
        contexts = []
        for role in ("planner", "selector", "mapper", "reviewer"):
            receipt = d.roles[role]
            _fields(receipt, {"context_id", "input_sha256", "receipt_sha256", "output"})
            context, sha = receipt["context_id"], _hash(receipt["receipt_sha256"])
            p.parts(context)
            _need(len(p.parts(context)) == 1, "ROLE_CONTEXT_PATH")
            contexts.append(context)
            rec = case["roles"][context]
            _need(rec["role"] == role and rec.get("complete") is True and rec.get("launched") is True
                  and rec["receipt"] == sha and rec["input_sha256"] == receipt["input_sha256"],
                  "ACTUAL_COMPLETED_ROLE_REQUIRED")
            _need(d.runtime.receipts.get(sha) == d.protected / context / "COMPLETE.json",
                  "RUNTIME_COMPLETION_NOT_OBSERVED")
            raws = {}
            for name in ("START.json", "COMPLETE.json", "stdout.log", "stderr.log"):
                path = context + "/" + name
                raw = d.host_store.read(path)
                _need(path in case["protected"] and d.custody._protected[path] == p.digest(raw),
                      "CUSTODY_COMPLETION_NOT_PROTECTED")
                raws[name] = raw
            _need(p.digest(raws["COMPLETE.json"]) == sha, "ROLE_RECEIPT_CHANGED")
            start, complete = p.decode(raws["START.json"]), p.decode(raws["COMPLETE.json"])
            _need(complete["start_sha256"] == p.digest(raws["START.json"]), "ROLE_START_CHANGED")
            _same({k: complete[k] for k in start}, start, "ROLE_START_COMPLETION_CHANGED")
            expected = {"case_root": str(d.root), "job_root": rec["job_root"], "role": role,
                "context_id": context, "input_sha256": receipt["input_sha256"],
                "model": d.custody.pins["model"], "provider": d.custody.pins["provider"],
                "browse": False, "fresh_context": True, "cli_identity": d.custody.pins["cli_identity"],
                "runtime_file_sha256": self.expected_code_sha256s["scripts/ge_auto_role_runtime.py"],
                "training": False, "input_inventory": rec["inventory"]}
            _same({k: start[k] for k in expected}, expected, "ROLE_EXECUTION_PINS_CHANGED")
            _same(start["fence"], {"own_exact_input_readable": True, "outside_public_file_denied": True,
                "input_write_open_denied": True, "private_bank_probe": "NOT_ATTEMPTED",
                "profile_sha256": rec["profile_sha256"]}, "ROLE_FENCE_CHANGED")
            begin, end = datetime.fromisoformat(start["started"]), datetime.fromisoformat(complete["completed"])
            _need(begin.tzinfo is not None and end.tzinfo is not None and end >= begin
                  and type(complete["returncode"]) is int and complete["returncode"] == 0
                  and complete["error"] is None, "ROLE_EXECUTION_FAILED")
            for name in ("stdout", "stderr"):
                _need(p.digest(raws[name + ".log"]) == complete[name + "_sha256"], "ROLE_LOG_CHANGED")
            log = raws["stderr.log"].decode(errors="replace")
            for key in ("model", "provider"):
                _need(set(re.findall(r"(?m)^" + key + r":\s*(\S+)", log)) == {d.custody.pins[key]},
                      "ACTUAL_ROLE_MODEL_CHANGED")
            d.custody._inventory(case, rec["relative"], rec["inventory"])
            output = d.store.read(rec["relative"] + "/output.json")
            _need(p.digest(output) == complete["output_sha256"], "ROLE_OUTPUT_BYTES_CHANGED")
            p.checked(p.decode(output), p.SCHEMAS[role])
            _same(p.decode(output), receipt["output"], "ROLE_OUTPUT_CHANGED")
            _same(rec["output"], receipt["output"], "CUSTODY_ROLE_OUTPUT_CHANGED")
            self._record(d, "role", {"role": role, "receipt": receipt})
        _need(len(set(contexts)) == 4, "ROLE_CONTEXTS_NOT_SEPARATE")
        _same(asdict(d.native_adapter.review), asdict(adapter_api.ReviewBinding(d.roles["reviewer"],
            d.roles["mapper"]["context_id"], d.roles["mapper"]["receipt_sha256"],
            d.roles["selector"]["context_id"], d.roles["selector"]["receipt_sha256"])), "REVIEW_BINDING_CHANGED")

    def _reservation(self, d, state, details):
        r = details["reservation"]
        _fields(r, {"case_id", "request_sha256", "policy_sha256", "kind", "attempt", "input_sha256", "budget", "attempt_root"})
        _need(r["kind"] in ("index", "retrieve") and details["envelope_sha256"] == r["input_sha256"],
              "NATIVE_RESERVATION_CHANGED")
        case = d.custody._case(d.capability)
        matches = [pair for pair in case["operations"].values() if pair[0] == r]
        if r["kind"] == "retrieve":
            translations = [v for v in self._records(d, "native-reservation-translation")
                            if v.get("native_reservation") == r]
            _need(len(translations) == 1, "NATIVE_TRANSLATION_REQUIRED")
            t = translations[0]
            _fields(t, {"protocol_envelope", "protocol_reservation", "native_envelope", "native_reservation"})
            pr, pe = t["protocol_reservation"], t["protocol_envelope"]
            _same(case["operations"][("retrieve", p.digest(pe))], (pr, pe), "UNOBSERVED_PROTOCOL_RESERVATION")
            pair = d.native_builds[p.digest(pe["data"]["build"])]
            _same(pair[0], pe["data"]["build"], "WRAPPED_BUILD_CHANGED")
            self._native_build_record(d, pair)
            translated = copy.deepcopy(pe)
            translated["data"]["build"] = pair[1]
            _same(t["native_envelope"], translated, "NATIVE_ENVELOPE_TRANSLATION_CHANGED")
            _same(r, {**pr, "input_sha256": p.digest(translated)}, "NATIVE_RESERVATION_TRANSLATION_CHANGED")
            matches = [(pr, pe)]
            envelope = translated
        else:
            _need(len(matches) == 1, "OBSERVED_PROTOCOL_RESERVATION_REQUIRED")
            envelope = matches[0][1]
        _need(len(matches) == 1, "AMBIGUOUS_PROTOCOL_RESERVATION")
        original_r, original_e = matches[0]
        _same(d.custody._find_operation(case, r["kind"], p.digest(original_e), p.digest(original_r)),
              (original_r, original_e), "STORED_PROTOCOL_RESERVATION_CHANGED")
        _need(p.digest(envelope) == details["envelope_sha256"], "RESERVED_ENVELOPE_CHANGED")
        state.operation = (copy.deepcopy(r), copy.deepcopy(envelope))
        if r["kind"] == "index":
            p.checked(envelope["data"], adapter_api.LEGAL_INPUT_SCHEMA)
            if state.legal is not None:
                _same(state.legal, envelope["data"], "TURN_LEGAL_INPUT_CHANGED")
            state.legal = copy.deepcopy(envelope["data"])
        _need(state.legal is not None, "GUARD_DID_NOT_OBSERVE_BUILD_INPUT")

    def _native_build_record(self, d, pair):
        found = [v for v in self._records(d, "native-result") if v.get("kind") == "index"
                 and v.get("protocol_result") == pair[0] and v.get("native") == pair[1]]
        _need(len(found) == 1, "PROTECTED_NATIVE_BUILD_REQUIRED")
        raw = d.host_store.read(found[0]["protected_receipt"])
        _need(p.digest(raw) == pair[0]["receipt_sha256"], "NATIVE_WRAPPER_CHANGED")
        _same(pair[0], {**pair[1], "receipt_sha256": p.digest(raw)}, "WRAPPER_NATIVE_PAIR_CHANGED")
        wrapper = p.decode(raw)
        _need(wrapper["kind"] == "index" and wrapper["request_sha256"] == d.request_sha
              and wrapper["result_sha256"] == p.digest({k: v for k, v in pair[1].items() if k != "receipt_sha256"}),
              "PROTECTED_WRAPPER_BINDING_CHANGED")

    def _contract(self, d, state, pid):
        actual = d.contracts[pid]
        _need(type(actual) is contracts.CaseContracts, "ACTUAL_CONTRACT_RESULT_REQUIRED")
        b = actual.binding
        _need(d.native_adapter.bindings[pid].contracts is b, "DRIVER_CONTRACT_BINDING_CHANGED")
        art = actual.artifact_lineage
        _same(seal_contract(art), art, "ARTIFACT_LINEAGE_HASH_CHANGED")
        _need(art["content_sha256"] == b.context_receipt_sha256, "CONTEXT_RECEIPT_CHANGED")
        _same(art["pins"], d.pins.contract.material(), "CONTRACT_PINS_CHANGED")
        values = {name: getattr(b, name) for name in
                  ("query_plan", "fact_snapshot", "conversation_snapshot", "knowledge_generation")}
        _same(art["contracts_sha256"], {k: research.digest(v) for k, v in values.items()},
              "ACTUAL_CONTRACT_HASH_CHANGED")
        _same(art["adapter_binding"], {name: getattr(b, name) for name in (
            "expected_knowledge_generation_sha256", "expected_schema_selection_sha256", "issue_id",
            "affected_claim_sha256", "existing_retrieval_sha256", "gap_class")}, "CONTRACT_ADAPTER_BINDING_CHANGED")
        prop = self._prop(state, pid)
        rows = [r for r in self._records(d, "contracts") if r.get("proposition_sha256") == p.digest(prop)]
        _need(len(rows) == 1, "PROTECTED_CONTRACT_RESULT_REQUIRED")
        _same(rows[0]["artifact_lineage"], art, "PROTECTED_CONTRACT_LINEAGE_CHANGED")
        _hash(rows[0]["gap_receipt_sha256"])
        return b, asdict(adapter_api.bind_contracts(b, request_sha256=d.request_sha))

    @staticmethod
    def _prop(state, pid):
        found = [v for v in state.legal["propositions"] if v["proposition_id"] == pid]
        _need(len(found) == 1, "EXACT_PROPOSITION_REQUIRED")
        return found[0]

    def _source(self, d, state, pid, source):
        b, lineage = self._contract(d, state, pid)
        prop = self._prop(state, pid)
        _need(any(p.canonical(v) == p.canonical(prop) for v in d.roles["mapper"]["output"]["propositions"]),
              "ACTUAL_MAPPER_PROPOSITION_CHANGED")
        sha = research.digest(source.capture.raw)
        obs = d.captures[sha]
        original = obs["capture"]
        _need(any(p.canonical(s) == p.canonical(original) for s in state.legal["sources"]),
              "LEGAL_INPUT_SOURCE_CHANGED")
        saved = self._capture_observation(d, obs)
        _need(saved["source_sha256"] == sha
              and saved["parsed_sha256"] == p.digest(original["parts"])
              and saved["parse_binding"]["parser_receipt_sha256"] == original["parser_receipt_sha256"]
              and original["parser_sha256"] == d.pins.contract.parser_sha256,
              "UNOBSERVED_RAW_PARSER_EXECUTION")
        sr = [r for r in d.roles["reviewer"]["output"]["sources"] if r["source_sha256"] == sha]
        _need(len(sr) == 1, "EXACT_SOURCE_REVIEW_REQUIRED")
        capture, mapping = driver_api.capture_from_ledger(store=d.store, reservation=obs["reservation"],
            original=original, scope=d.native_adapter.scope, researcher_id=obs["researcher_id"],
            jurisdiction=prop["jurisdiction"], source_review=sr[0],
            reviewer_receipt_sha256=d.roles["reviewer"]["receipt_sha256"])
        _need(capture == source.capture, "ACTUAL_RAW_PARSED_CAPTURE_CHANGED")
        _same(mapping, source.part_ordinals, "ACTUAL_PART_MAP_CHANGED")
        coverage = driver_api.complete_reviewed_blocks(prop, original, mapping)
        _same(coverage, source.reviewed_block_ordinals, "REVIEWED_COVERAGE_CHANGED")
        translated = adapter_api.translate_review(source=source, original=original, proposition=prop,
            review=d.native_adapter.review, contracts=b,
            lineage=adapter_api.bind_contracts(b, request_sha256=d.request_sha), scope=d.native_adapter.scope)
        _same(d.translated_reviews[research.digest(translated)], translated, "ACTUAL_TRANSLATION_CHANGED")
        return b, lineage, translated

    def _capture_observation(self, d, obs):
        """Own earlier captures retain their original custody and researcher."""
        case = d.custody._case(d.capability)
        reservation, original = obs["reservation"], obs["capture"]
        key = p.digest(reservation)
        found = []
        for own in case["family"]["turns"].values():
            if own["request"]["turn"] > d.request["turn"] or key not in own["capture"]:
                continue
            _need(own["root"] == d.root and own["request"]["case_id"] == d.request["case_id"],
                  "CAPTURE_FAMILY_CHANGED")
            d.custody._check_protected(own)
            pair = own["operations"][("capture", reservation["input_sha256"])]
            _same(pair[0], reservation, "CAPTURE_RESERVATION_CHANGED")
            _same(d.custody._find_operation(own, "capture", reservation["input_sha256"], key), pair,
                  "CAPTURE_STORED_OPERATION_CHANGED")
            _need(own["outputs"][("capture", reservation["input_sha256"])] == p.digest(original),
                  "CAPTURE_OUTPUT_NOT_OBSERVED")
            role = own["roles"][obs["researcher_id"]]
            _need(role["role"] == "selector" and role.get("complete") is True,
                  "ORIGINAL_CAPTURE_RESEARCHER_CHANGED")
            if own is case:
                self._record(d, "capture", obs)
            else:
                # The live family contains only custody-issued ordered turns;
                # prior reuse is allowed only after its immutable terminal.
                _need(own["request"]["turn"] in case["family"]["terminal"], "UNSEALED_PRIOR_CAPTURE")
            found.append(own["capture"][key])
        _need(len(found) == 1, "ACTUAL_OWN_CAPTURE_OBSERVATION_REQUIRED")
        return found[0]

    def _sqlite_raw(self, d, key, kind):
        path = _safe(d.root / "legal-index/metadata.sqlite3", self.workspace, file=True)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            db.execute("PRAGMA query_only=ON")
            row = db.execute("SELECT kind,payload FROM objects WHERE digest=?", (_hash(key),)).fetchone()
        _need(row is not None and row[0] == kind and type(row[1]) is bytes
              and research.digest(row[1]) == key, "SQLITE_OBJECT_READBACK_CHANGED")
        return row[1]

    def _sqlite(self, d, key, kind):
        return p.decode(self._sqlite_raw(d, key, kind))

    def _prepared(self, d, state, key):
        value = self._sqlite(d, key, "prepared_build")
        _fields(value, {"schema", "scope", "policy_sha256", "lineage", "gap", "attempt", "sources", "reviews",
            "source_manifest_sha256", "review_manifest_sha256", "chunk_manifest_sha256", "chunker_sha256",
            "model", "model_sha256", "rows", "runtime_sha256", "query_instruction_sha256"})
        matches = []
        for pid in d.contracts:
            b, lineage = self._contract(d, state, pid)
            # Several propositions can share contracts; reviews disambiguate.
            if (p.canonical(value["lineage"]) == p.canonical(lineage)
                    and {r["proposition_sha256"] for r in value["reviews"]} == {p.digest(self._prop(state, pid))}):
                matches.append((pid, b, lineage))
        _need(len(matches) == 1, "PREPARED_PROPOSITION_BINDING_REQUIRED")
        pid, b, lineage = matches[0]
        chunker = StructuralChunker()
        chunker_sha = research.digest({"schema": chunker.schema, "max_chars": chunker.max_chars,
            "min_chars": chunker.min_chars, "implementation": self.expected_code_sha256s["backend/app/ingestion/chunking.py"],
            "sanitation": self.expected_code_sha256s["backend/app/ingestion/sanitation.py"]})
        rows, sources, reviews = [], [], []
        for source in d.native_adapter.bindings[pid].sources:
            _, _, review = self._source(d, state, pid, source)
            manifest = source.capture.manifest()
            capture_sha, review_sha = research.digest(manifest), research.digest(review)
            _need(self._sqlite_raw(d, research.digest(source.capture.raw), "raw_source") == source.capture.raw,
                  "SQLITE_RAW_CHANGED")
            _same(self._sqlite(d, manifest["parsed_sha256"], "parsed_source"), asdict(source.capture.parsed),
                  "SQLITE_PARSED_CHANGED")
            _same(self._sqlite(d, capture_sha, "capture"), manifest, "SQLITE_CAPTURE_CHANGED")
            _same(self._sqlite(d, review_sha, "source_review_attempt"), review, "SQLITE_REVIEW_CHANGED")
            group = research.digest({"capture": capture_sha, "review": review_sha})
            chunks = chunker.chunk_body(source.capture.parsed, document_sha256=research.digest(source.capture.raw))
            included = [c for c in chunks if set(c.block_ordinals) & set(review["context_block_ordinals"])]
            _need(included and all(set(c.block_ordinals) <= set(review["context_block_ordinals"]) for c in included),
                  "UNREVIEWED_PREPARED_CONTEXT")
            for chunk in included:
                rows.append({"id": research.digest({"group": group, "chunk": asdict(chunk), "chunker": chunker_sha}),
                    "text": chunk.text, "text_sha256": research.digest(chunk.text.encode()),
                    "structural_chunk": asdict(chunk), "group": group, "capture_sha256": capture_sha,
                    "review_sha256": review_sha, "jurisdiction": source.capture.jurisdiction,
                    "valid_from": review["valid_from"], "valid_to": review["valid_to"],
                    "lane": d.native_adapter.scope.lane, "scope_sha256": research.digest(asdict(d.native_adapter.scope))})
            sources.append(manifest)
            reviews.append(review)
        _need(rows and len(rows) == len({r["id"] for r in rows}) and len(rows) <= 8192,
              "PREPARED_ROW_INVENTORY")
        from backend.app.retrieval.qwen import LEGAL_RETRIEVAL_INSTRUCTION
        expected = {"schema": "legalbot.ge-auto-index-build.v1", "scope": asdict(d.native_adapter.scope),
            "policy_sha256": d.research_policy.sha256, "lineage": lineage, "gap": value["gap"],
            "attempt": value["attempt"], "sources": sources, "reviews": reviews,
            "source_manifest_sha256": research.digest(sources), "review_manifest_sha256": research.digest(reviews),
            "chunk_manifest_sha256": research.digest(rows), "chunker_sha256": chunker_sha,
            "model": asdict(d.research_policy.model), "model_sha256": research.digest(asdict(d.research_policy.model)),
            "rows": rows, "runtime_sha256": self.expected_code_sha256s["backend/app/research/ge_auto_index.py"],
            "query_instruction_sha256": research.digest(LEGAL_RETRIEVAL_INSTRUCTION.encode())}
        _same(value, expected, "PREPARED_BUILD_CHANGED")
        self._prepared_attempt(d, state, value, b, pid)
        state.prepared[key] = (pid, copy.deepcopy(value))
        return pid, value

    def _prepared_attempt(self, d, state, value, b, pid):
        _need(type(value["attempt"]) is int and value["attempt"] > 0, "PREPARED_ATTEMPT_REQUIRED")
        path = _safe(d.root / "legal-index/metadata.sqlite3", self.workspace, file=True)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            db.execute("PRAGMA query_only=ON")
            gap = db.execute("SELECT payload,state FROM gaps WHERE id=?", (_hash(value["gap"]),)).fetchone()
            attempt = db.execute("SELECT gap,state FROM attempts WHERE id=?", (value["attempt"],)).fetchone()
        expected = {"scope": value["scope"], "lineage": value["lineage"], "issue_id": b.issue_id,
            "gap_class": b.gap_class, "affected_claim_sha256": b.affected_claim_sha256,
            "failure_fingerprint": p.digest({"proposition": self._prop(state, pid), "review": state.legal["review_sha256"]})}
        _need(gap and research.digest(gap[0]) == value["gap"] and attempt
              and attempt[0] == value["gap"] and attempt[1] not in ("FAILED", "CANCELLED"), "SQLITE_GAP_ATTEMPT_CHANGED")
        _same(p.decode(gap[0]), expected, "SQLITE_GAP_BINDING_CHANGED")
        for source in value["sources"]:
            binding = {"gap": value["gap"], "capture_sha256": research.digest(source), "attempt": value["attempt"]}
            _same(self._sqlite(d, research.digest(binding), "capture_binding"), binding, "CAPTURE_ATTEMPT_CHANGED")

    def _tree(self, root):
        result = {}
        for directory, dirs, files in os.walk(_safe(root, self.workspace), followlinks=False):
            for name in (*dirs, *files):
                path = _safe(Path(directory) / name, self.workspace)
                if path.is_file() and path != root / "generation.json":
                    _safe(path, self.workspace, file=True)
                    result[path.relative_to(root).as_posix()] = research.digest(path.read_bytes())
        _need(result and len(result) <= 16384, "GENERATION_FILE_INVENTORY_REQUIRED")
        return result

    @staticmethod
    def _lance_rows(root, count):
        import lancedb
        table = lancedb.connect(str(root / "lance/authority")).open_table("chunks")
        _need(table.count_rows() == count, "LANCE_ROW_COUNT_CHANGED")
        return table.to_arrow().to_pylist()

    def _generation(self, d, state, build_sha):
        pid, prepared = self._prepared(d, state, build_sha)
        root = _safe(d.root / "legal-index/builds" / ("ge-auto-" + _hash(build_sha)), self.workspace)
        path = _safe(root / "generation.json", self.workspace, file=True)
        raw = path.read_bytes()
        receipt = p.decode(raw)
        _fields(receipt, {"schema", "build_sha256", "scope", "lineage", "source_manifest_sha256",
            "review_manifest_sha256", "chunk_manifest_sha256", "model_sha256", "rows_sha256", "files",
            "chunk_count", "embedding_execution", "embedding_validation", "non_live", "admitted", "legal_gold",
            "qualified_legal_review", "full_current_law_eligible", "generation_sha256"})
        _need(raw == canonical_json_bytes(receipt) and research.digest({k: v for k, v in receipt.items()
              if k != "generation_sha256"}) == receipt["generation_sha256"], "GENERATION_RECEIPT_HASH_CHANGED")
        _same(self._sqlite(d, research.digest(receipt), "generation"), receipt, "SQLITE_GENERATION_CHANGED")
        expected = {"schema": "legalbot.ge-auto-index-generation.v1", "build_sha256": build_sha,
            **{k: prepared[k] for k in ("scope", "lineage", "source_manifest_sha256", "review_manifest_sha256",
                                      "chunk_manifest_sha256", "model_sha256")},
            "chunk_count": len(prepared["rows"]), "embedding_execution": "INJECTED_PROVIDER_EXECUTED",
            "embedding_validation": research.PENDING_EMBEDDING_VALIDATION,
            "non_live": True, "admitted": False, "legal_gold": False,
            "qualified_legal_review": False, "full_current_law_eligible": False}
        _same({k: receipt[k] for k in expected}, expected, "GENERATION_PINS_OR_FLAGS_CHANGED")
        _same(self._tree(root), receipt["files"], "GENERATION_FILES_CHANGED")
        rows = self._lance_rows(root, len(prepared["rows"]))
        self._row_bindings(rows, prepared["rows"], receipt["rows_sha256"])
        _same(self._tree(root), receipt["files"], "GENERATION_CHANGED_DURING_READBACK")
        _need(path.read_bytes() == raw, "GENERATION_RECEIPT_CHANGED_DURING_READBACK")
        previous = [sha for sha, build in state.generations.items() if build == build_sha]
        _need(not previous or previous == [receipt["generation_sha256"]], "OBSERVED_GENERATION_REPLACED")
        state.generations[receipt["generation_sha256"]] = build_sha
        return pid, prepared, receipt, rows

    @staticmethod
    def _row_bindings(rows, prepared, rows_sha):
        _need(type(rows) is list and len(rows) == len(prepared), "LANCE_ROWS_REQUIRED")
        _need(research.digest(sorted(rows, key=lambda r: r["id"])) == rows_sha, "LANCE_ROWS_HASH_CHANGED")
        actual = {r["id"]: r for r in rows}
        _need(len(actual) == len(rows) and set(actual) == {r["id"] for r in prepared}, "LANCE_ROW_IDS_CHANGED")
        for row in prepared:
            native = actual[row["id"]]
            _fields(native, {"id", "text", "jurisdiction", "valid_from", "valid_to", "vector", "binding_json"})
            _same({k: native[k] for k in ("id", "text", "jurisdiction", "valid_from", "valid_to")},
                  {k: row[k] for k in ("id", "text", "jurisdiction", "valid_from", "valid_to")}, "LANCE_TEXT_OR_SCOPE_CHANGED")
            _need(native["binding_json"] == canonical_json_bytes(row).decode(), "LANCE_STRUCTURAL_BINDING_CHANGED")
            vector = native["vector"]
            _need(type(vector) is list and len(vector) == 1024 and all(type(v) in (int, float)
                  and math.isfinite(v) for v in vector) and any(v != 0 for v in vector), "LANCE_VECTOR_INVALID")

    @staticmethod
    def _lease(session, workspace):
        lock = session.lock
        path = _safe(workspace / "data/research/ge-auto-research/embedding.lock", workspace, file=True)
        _need(lock is not None and not lock.closed and Path(lock.name) == path
              and os.fstat(lock.fileno()).st_ino == path.stat().st_ino, "ACTUAL_EMBEDDING_LEASE_REQUIRED")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            fcntl.flock(fd, fcntl.LOCK_UN)
            raise EvidenceHold("EMBEDDING_LEASE_NOT_HELD")
        finally:
            os.close(fd)

    def _embedding(self, d, state, receipt, frame):
        _need(frame.f_code is adapter_api.CaseIndexAdapter._model_receipt.__code__
              and frame.f_locals.get("self") is d.native_adapter, "LIVE_MODEL_RECEIPT_CALL_REQUIRED")
        session = frame.f_locals["session"]
        _need(type(session) is embedding.PinnedEmbeddingSession and session.provider is not None,
              "LIVE_PINNED_EMBEDDING_SESSION_REQUIRED")
        _same(session.identity, d.pins.embedding_identity, "LIVE_MODEL_IDENTITY_CHANGED")
        self._lease(session, self.workspace)
        _same(receipt, session.receipt(), "LIVE_SESSION_RECEIPT_CHANGED")
        parent = frame.f_back
        _need(parent.f_locals.get("self") is d.native_adapter and parent.f_locals.get("session") is session,
              "ACTUAL_EMBEDDING_OPERATION_REQUIRED")
        if parent.f_code is adapter_api.CaseIndexAdapter._build.__code__:
            build_sha = parent.f_locals["build"].sha256
            _, prepared, generation, rows = self._generation(d, state, build_sha)
            _need(parent.f_locals["generation"] == generation["generation_sha256"], "LIVE_BUILD_GENERATION_CHANGED")
            self._inference(receipt, d.pins.embedding_identity, "document", [r["text"] for r in prepared["rows"]])
            by_id = {r["id"]: r for r in rows}
            for row, call in zip(prepared["rows"], receipt["calls"], strict=True):
                _need(call["vector_sha256"] == embedding._digest(by_id[row["id"]]["vector"]),
                      "LIVE_DOCUMENT_VECTOR_READBACK_CHANGED")
            kind = "document"
        elif parent.f_code is adapter_api.CaseIndexAdapter._retrieve.__code__:
            entry = parent.f_locals["entry"]
            build_sha = entry["build_sha256"]
            _, prepared, generation, _ = self._generation(d, state, build_sha)
            queries = self._queries(state, prepared)
            self._inference(receipt, d.pins.embedding_identity, "query", queries)
            _same(parent.f_locals["queries"], queries, "LIVE_RETRIEVAL_QUERIES_CHANGED")
            saved = [self._sqlite(d, sha, "retrieval") for sha in parent.f_locals["receipts"]]
            self._retrievals(d, state, saved, build_sha)
            kind = "query"
        else:
            raise EvidenceHold("UNKNOWN_EMBEDDING_CALL_SITE")
        sha = p.digest(receipt)
        if sha in state.inferences:
            _need(state.inferences[sha][1] is session, "INFERENCE_RECEIPT_REPLAY")
        state.inferences[sha] = (copy.deepcopy(receipt), session, kind, build_sha)

    @staticmethod
    def _inference(receipt, identity, kind, texts):
        _fields(receipt, {"schema", "model_identity", "calls", "actual_inference_calls", "training", "provider", "synthetic_vectors"})
        _same({k: receipt[k] for k in receipt if k != "calls"}, {
            "schema": "legalbot.ge-auto-research-embedding-inference.v1", "model_identity": identity,
            "actual_inference_calls": len(texts), "training": False, "provider": "PINNED_LOCAL_QWEN",
            "synthetic_vectors": False}, "INFERENCE_IDENTITY_OR_COUNT_CHANGED")
        _need(texts and type(receipt["calls"]) is list and len(receipt["calls"]) == len(texts), "ACTUAL_CALLS_REQUIRED")
        for call, text in zip(receipt["calls"], texts, strict=True):
            _fields(call, {"kind", "text_sha256", "tokens", "vector_sha256", "seconds"})
            _need(call["kind"] == kind and call["text_sha256"] == research.digest(text.encode())
                  and type(call["tokens"]) is int and 1 <= call["tokens"] <= embedding.MAX_TOKENS
                  and type(call["seconds"]) in (int, float) and math.isfinite(call["seconds"])
                  and call["seconds"] >= 0, "INFERENCE_CALL_BINDING_CHANGED")
            _hash(call["vector_sha256"])

    def _observed_inference(self, d, state, receipt, kind, build_sha):
        sha = p.digest(receipt)
        _need(sha in state.inferences, "UNOBSERVED_INFERENCE_RECEIPT")
        actual, session, actual_kind, actual_build = state.inferences[sha]
        _same(actual, receipt, "OBSERVED_INFERENCE_CHANGED")
        _need(actual_kind == kind and actual_build == build_sha, "INFERENCE_OPERATION_CHANGED")
        _closed(session)
        _same(session.receipt(), receipt, "CLOSED_SESSION_RECEIPT_CHANGED")
        _same(d.native_adapter._get(sha), receipt, "PERSISTED_INFERENCE_CHANGED")
        return sha

    @staticmethod
    def _queries(state, prepared):
        lineage = prepared["lineage"]
        values = [q["query"] for q in state.legal["public_queries"]
                  if q["jurisdiction"] == lineage["jurisdiction"] and q["as_of_date"] == lineage["as_of_date"]]
        values += [r["quote"] for r in prepared["reviews"]]
        values = list(dict.fromkeys(values))
        _need(1 <= len(values) <= 12, "LOCAL_QUERY_BUDGET")
        return values

    def _retrievals(self, d, state, receipts, build_sha):
        pid, prepared, generation, native_rows = self._generation(d, state, build_sha)
        queries = self._queries(state, prepared)
        _need(type(receipts) is list and len(receipts) == len(queries), "RETRIEVAL_QUERY_COVERAGE")
        found = set()
        for receipt, query in zip(receipts, queries, strict=True):
            _fields(receipt, {"schema", "scope", "lineage", "build_sha256", "generation_sha256", "query_sha256",
                "retrieval_runtime_sha256", "selected_ids", "evidence", "retriever_id", "lexical_ids", "vector_ids"})
            _same(self._sqlite(d, research.digest(receipt), "retrieval"), receipt, "SQLITE_RETRIEVAL_CHANGED")
            fixed = {"schema": "legalbot.ge-auto-index-retrieval.v1", "scope": asdict(d.native_adapter.scope),
                "lineage": prepared["lineage"], "build_sha256": build_sha,
                "generation_sha256": generation["generation_sha256"], "query_sha256": research.digest(query.encode()),
                "retrieval_runtime_sha256": self.expected_code_sha256s["backend/app/research/ge_auto_index.py"],
                "retriever_id": d.pins.contract.candidate_id}
            _same({k: receipt[k] for k in fixed}, fixed, "RETRIEVAL_PINS_CHANGED")
            self._retrieval_rows(receipt, prepared["rows"], native_rows)
            found.update(r["id"] for r in receipt["evidence"])
        _need(found == {r["id"] for r in prepared["rows"]}, "FULL_PREPARED_CONTEXT_NOT_RETRIEVED")
        return pid, prepared, generation

    @staticmethod
    def _retrieval_rows(receipt, prepared, native_rows):
        rows = {r["id"]: r for r in prepared}
        ranks = {}
        for hits in (receipt["lexical_ids"], receipt["vector_ids"]):
            _need(type(hits) is list and len(hits) <= 8 and len(set(hits)) == len(hits)
                  and set(hits) <= rows.keys(), "UNKNOWN_OR_DUPLICATE_NATIVE_HIT")
            for rank, key in enumerate(hits, 1):
                ranks[key] = ranks.get(key, 0) + 1 / (60 + rank)
        selected = sorted(ranks, key=lambda key: (-ranks[key], key))[:8]
        _same(receipt["selected_ids"], selected, "NATIVE_FUSION_CHANGED")
        groups = {rows[key]["group"] for key in selected}
        expected = [rows[r["id"]] for r in native_rows if rows[r["id"]]["group"] in groups]
        _same(receipt["evidence"], expected, "RETRIEVED_GROUP_CONTEXT_CHANGED")
        _need(all(r["jurisdiction"] == receipt["lineage"]["jurisdiction"]
                  and r["valid_from"] <= receipt["lineage"]["as_of_date"] <= r["valid_to"] for r in expected),
              "RETRIEVAL_LEGAL_SCOPE_CHANGED")

    def _job(self, d, state):
        ids = [p0["proposition_id"] for p0 in state.legal["propositions"]]
        _need(set(state.retrieved) == set(ids), "EVERY_PROPOSITION_CONTEXT_REQUIRED")
        for _, session, _, _ in state.inferences.values():
            _closed(session)
        return {"case_id": d.request["case_id"], "request_sha256": d.request_sha,
            "public_queries": state.legal["public_queries"], "evidence": [
                {"origin": "CASE_LOCAL", "proposition": self._prop(state, pid),
                 "eligibility_receipt_sha256": state.legal["review_sha256"]} for pid in ids],
            "embedding_sessions_closed": True, "model_identity_sha256": d.pins.reranker_identity["identity_sha256"]}

    def _reranker(self, d, state, job, result):
        _same(job, self._job(d, state), "ACTUAL_RERANK_JOB_CHANGED")
        _need(state.pending_rerank == p.digest(job) or p.digest(job) in state.reranked, "RERANK_NOT_OBSERVED_BEFORE_LOAD")
        records = [r for r in self._records(d, "reranker") if r.get("job") == job]
        _need(len(records) == 1, "PROTECTED_RERANK_EXECUTION_REQUIRED")
        record = records[0]
        _fields(record, {"job", "execution", "lease", "scores"})
        execution, scores = record["execution"], record["scores"]
        _fields(execution, {"schema", "model_identity", "loading_info", "calls", "actual_pairs_scored", "training", "classification_head_created"})
        _same({k: execution[k] for k in ("schema", "model_identity", "actual_pairs_scored", "training", "classification_head_created")},
            {"schema": "legalbot.ge-auto-research-reranking.v1", "model_identity": d.pins.reranker_identity,
             "actual_pairs_scored": len(job["evidence"]), "training": False, "classification_head_created": False},
            "RERANK_EXECUTION_PINS_CHANGED")
        _need(type(execution["loading_info"]) is dict and all(not execution["loading_info"].get(k)
              for k in ("missing_keys", "unexpected_keys", "mismatched_keys", "error_msgs")), "RERANK_WEIGHTS_NOT_EXACT")
        _need(type(scores) is list and 1 <= len(scores) == len(job["evidence"]) <= 8
              and len(execution["calls"]) == len(scores), "RERANK_PAIR_COVERAGE")
        for item, score, call in zip(job["evidence"], scores, execution["calls"], strict=True):
            _fields(call, {"query_sha256", "document_sha256", "tokens", "score", "seconds"})
            prop = item["proposition"]
            query = "\n".join(dict.fromkeys(q["query"] for q in job["public_queries"]
                if q["jurisdiction"] == prop["jurisdiction"] and q["as_of_date"] == prop["as_of_date"]))
            doc = "\n".join(dict.fromkeys(s["text"] for s in adapter_api.spans(prop)))
            _need(type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1
                  and call["score"] == score and type(call["tokens"]) is int and 1 <= call["tokens"] <= 2048
                  and type(call["seconds"]) in (int, float) and math.isfinite(call["seconds"]) and call["seconds"] >= 0
                  and call["query_sha256"] == embedding._digest(query)
                  and call["document_sha256"] == embedding._digest(doc), "RERANK_PAIR_BINDING_CHANGED")
        lease = {"job_sha256": p.digest(job), "lock_path": str(self.workspace / "data/research/ge-auto-research/embedding.lock"),
                 "exclusive_lock_observed": True, "model_identity": d.pins.reranker_identity}
        _same(record["lease"], lease, "RERANK_LEASE_CHANGED")
        ids = [item["proposition"]["proposition_id"] for item in job["evidence"]]
        expected = {"ordered_proposition_ids": [ids[i] for i in sorted(range(len(ids)), key=lambda i: (-scores[i], i))],
            "receipt": {"model": "Qwen/Qwen3-Reranker-0.6B", "model_identity_sha256": job["model_identity_sha256"],
                "input_sha256": p.digest(job), "actual_inference_calls": len(scores),
                "execution_receipt_sha256": p.digest(execution), "exclusive_model_lease_sha256": p.digest(lease),
                "session_closed": True, "synthetic_vectors": False, "training": False}}
        _same(result, expected, "RERANK_RESULT_CHANGED")
        state.reranked[p.digest(job)] = copy.deepcopy(result)

    def _dispatch(self, d, s, action, v, frame):
        a = d.native_adapter
        if action == "protocol_reservation":
            self._reservation(d, s, v)
            return
        _need(s.operation is not None and s.legal is not None, "ACTUAL_RESERVATION_REQUIRED_FIRST")
        _need(s.legal["review_sha256"] == p.digest(d.roles["reviewer"]["output"]), "ACTUAL_REVIEW_CHANGED")
        if action == "open_adapter_store":
            _safe(a.root / "index-adapter", self.workspace)
            if a.store.exists("IDENTITY"):
                _same(a._pointer("IDENTITY"), {"scope": asdict(a.scope), "case_id": d.request["case_id"],
                    "baseline_sha256": adapter_api.EMPTY, "protocol_policy_sha256": p.digest(d.policy.manifest()),
                    "baseline_contract_sha256": a.pins.baseline_contract_sha256,
                    "schema_selection_sha256": d.registry.manifest_sha256}, "ADAPTER_STORE_IDENTITY_CHANGED")
        elif action == "translated_source_review":
            found = []
            for pid, bound in a.bindings.items():
                for source in bound.sources:
                    if source.capture.manifest() == v["capture_manifest"]:
                        b, lineage, translated = self._source(d, s, pid, source)
                        if translated == v["index_review"]:
                            found.append({"legal_input_sha256": p.digest(s.legal), "context_receipt_sha256": b.context_receipt_sha256,
                                "lineage": lineage, "capture_manifest": source.capture.manifest(),
                                "part_ordinals": dict(source.part_ordinals), "index_review": translated,
                                "reviewer_receipt": d.roles["reviewer"], "mapper_context_id": d.roles["mapper"]["context_id"],
                                "selector_context_id": d.roles["selector"]["context_id"]})
            _need(len(found) == 1, "EXACT_ACTUAL_TRANSLATION_REQUIRED")
            _same(v, found[0], "TRANSLATION_BINDING_CHANGED")
        elif action == "contract_lineage":
            expected = []
            for pid in d.contracts:
                b, lineage = self._contract(d, s, pid)
                expected.append({"lineage": lineage, "context_receipt_sha256": b.context_receipt_sha256,
                    "existing_retrieval_sha256": b.existing_retrieval_sha256,
                    "knowledge_generation_sha256": b.expected_knowledge_generation_sha256})
            _need(any(p.canonical(v) == p.canonical(e) for e in expected), "EXACT_CONTRACT_LINEAGE_REQUIRED")
        elif action == "capability":
            kind, sha = v["index_action"], _hash(v["binding_sha256"])
            if kind == "jobs":
                _need(any(research.digest(self._contract(d, s, pid)[1]) == sha for pid in d.contracts), "JOBS_LINEAGE_CHANGED")
            elif kind == "build":
                _need(s.operation[0]["kind"] == "index" and sha in s.prepared, "UNOBSERVED_PREPARED_BUILD")
                self._prepared(d, s, sha)
            elif kind == "retrieve":
                _need(s.operation[0]["kind"] == "retrieve" and sha in s.generations, "UNOBSERVED_RETRIEVAL_GENERATION")
                self._generation(d, s, s.generations[sha])
            else:
                raise EvidenceHold("UNKNOWN_INDEX_CAPABILITY_ACTION")
        elif action == "prepared_build":
            _need(s.operation[0]["kind"] == "index", "BUILD_RESERVATION_REQUIRED")
            _, value = self._prepared(d, s, v["build_sha256"])
            _same(v, {"build_sha256": research.digest(value), "lineage": value["lineage"],
                      "row_manifest_sha256": research.digest(value["rows"])}, "PREPARED_BINDING_CHANGED")
        elif action == "embedding_execution":
            self._embedding(d, s, v["receipt"], frame)
        elif action == "persisted_generation":
            _, _, receipt, _ = self._generation(d, s, v["receipt"]["build_sha256"])
            _same(v["receipt"], receipt, "PERSISTED_GENERATION_BINDING_CHANGED")
            self._observed_inference(d, s, v["inference"], "document", receipt["build_sha256"])
        elif action == "complete_retrieved_context":
            build = s.generations[v["generation_sha256"]]
            saved = [self._sqlite(d, sha, "retrieval") for sha in v["retrieval_sha256s"]]
            pid, prepared, generation = self._retrievals(d, s, saved, build)
            _same(v, {"proposition": self._prop(s, pid), "generation_sha256": generation["generation_sha256"],
                "retrieval_sha256s": [research.digest(r) for r in saved], "required_rows_sha256": research.digest(prepared["rows"]),
                "review_sha256": s.legal["review_sha256"]}, "COMPLETE_CONTEXT_BINDING_CHANGED")
            actual = [sha for sha, (_, session, kind, key) in s.inferences.items() if kind == "query" and key == build]
            _need(len(actual) == 1, "OBSERVED_QUERY_SESSION_REQUIRED")
            _closed(s.inferences[actual[0]][1])
            s.retrieved[pid] = {"proposition_id": pid, "retrieval_sha256s": v["retrieval_sha256s"], "inference_sha256": actual[0]}
        elif action == "persisted_retrieval":
            _need(v["receipts"], "PERSISTED_RETRIEVAL_REQUIRED")
            build = v["receipts"][0]["build_sha256"]
            pid, _, _ = self._retrievals(d, s, v["receipts"], build)
            sha = self._observed_inference(d, s, v["inference"], "query", build)
            _same(s.retrieved[pid], {"proposition_id": pid, "retrieval_sha256s": [research.digest(r) for r in v["receipts"]],
                                    "inference_sha256": sha}, "PERSISTED_CONTEXT_NOT_OBSERVED")
        elif action == "reranker_before_load":
            _need(v["job_sha256"] == p.digest(self._job(d, s)), "RERANK_JOB_CHANGED")
            s.pending_rerank = v["job_sha256"]
        elif action == "reranker_execution":
            self._reranker(d, s, v["job"], v["result"])
        elif action == "persisted_evidence_pack":
            self._evidence(d, s, v)
        elif action == "own_prior_generation":
            self._prior(d, s, v["result"])
        else:
            raise EvidenceHold("UNKNOWN_ACTION")

    def _evidence(self, d, s, v):
        result, receipt = v["result"], v["receipt"]
        p.checked(result, p.RETRIEVAL_SCHEMA)
        _same(d.native_adapter._get(result["receipt_sha256"]), receipt, "EVIDENCE_BUNDLE_BYTES_CHANGED")
        _fields(receipt, {"schema", "kind", "build", "actual", "evidence", "reranker", "parent_actual_validation"})
        job = self._job(d, s)
        reranked = s.reranked[p.digest(job)]
        self._reranker(d, s, job, reranked)
        _same(v["reranker_receipt"], reranked, "EVIDENCE_RERANK_CHANGED")
        _same(d.native_adapter._get(p.digest(reranked)), reranked, "PERSISTED_RERANK_CHANGED")
        order = reranked["ordered_proposition_ids"]
        evidence = sorted(job["evidence"], key=lambda e: order.index(e["proposition"]["proposition_id"]))
        build = s.operation[1]["data"]["build"]
        bundle = d.native_adapter._get(build["receipt_sha256"])
        ids = [x["proposition_id"] for x in s.legal["propositions"]]
        _same(receipt, {"schema": adapter_api.VERSION, "kind": "retrieval_bundle", "build": build,
            "actual": [s.retrieved[pid] for pid in ids], "evidence": evidence,
            "reranker": {"status": "HOST_VERIFIED_EXECUTION", "receipt_sha256": p.digest(reranked)},
            "parent_actual_validation": "REQUIRED"}, "EVIDENCE_PACK_CHANGED")
        _need(bundle["legal_input_sha256"] == p.digest(s.legal) and build["generation_sha256"] ==
              p.digest([entry["generation_sha256"] for entry in bundle["entries"]]), "EVIDENCE_BUILD_CHANGED")
        _same(result, {"baseline_sha256": adapter_api.EMPTY, "generation_sha256": build["generation_sha256"],
                      "receipt_sha256": p.digest(receipt), "evidence": evidence}, "EVIDENCE_RESULT_CHANGED")
        for item in receipt["actual"]:
            self._dispatch(d, s, "persisted_retrieval", {"receipts": [self._sqlite(d, sha, "retrieval")
                for sha in item["retrieval_sha256s"]], "inference": d.native_adapter._get(item["inference_sha256"])}, None)

    def _prior(self, d, state, result):
        p.checked(result, p.INDEX_SCHEMA)
        _need(result["generation_sha256"] in state.legal["own_prior_generations"], "UNREQUESTED_PRIOR_GENERATION")
        candidates = [s for s in self._turns.values() if s.driver.root == d.root
                      and s.driver.request["turn"] < d.request["turn"]]
        found = []
        for prior in candidates:
            for pair in prior.driver.native_builds.values():
                if pair[1] == result:
                    self._native_build_record(prior.driver, pair)
                    found.append(prior)
        _need(len(found) == 1, "UNOBSERVED_OWN_PRIOR_GENERATION")
        prior = found[0]
        _same(d.native_adapter._pointer("generation-" + result["generation_sha256"]), result, "PRIOR_GENERATION_POINTER_CHANGED")
        bundle = prior.adapter._get(result["receipt_sha256"])
        for entry in bundle["entries"]:
            _, _, receipt, _ = self._generation(prior.driver, prior, entry["build_sha256"])
            _need(receipt["generation_sha256"] == entry["generation_sha256"], "PRIOR_GENERATION_CHANGED")
            self._observed_inference(prior.driver, prior, prior.adapter._get(entry["inference_sha256"]),
                                     "document", entry["build_sha256"])
