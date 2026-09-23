"""Protected parent custody for one frozen, non-live UK/USA EMPTY-baseline run.

Parent API (never disclose the ledger, host_key or capabilities to model workers):

* Construct CaseCustody with explicit workspace_root, trusted_root, FrozenPolicy,
  runtime pins, a fresh opaque object() host_key, an active_owner_instruction()
  reader returning the currently active instruction BYTES, and query_privacy().
  The latter receives (case_binding, public_query) and must actually verify that
  only generalized public legal information will be sent. Unknown is False.
* issue_case(host_key, case_root=..., request=...) returns an in-process object
  capability. Pass it to CaseProtocol with protocol_guard and to the adapters.
* register_global_marker(host_key, marker_bytes=ACTUAL_PARENT_MARKER_BYTES) requires
  the pinned global_marker_verifier(binding, bytes) to verify the actual parent
  global marker. establish_one_pass(host_key, cap, binding) then only binds that
  observation to this case; it cannot mint substitute execution authority.
* role_callback(host_key, cap, actual_CodexRoleRuntime) invokes and checks the
  actual runtime and its protected START/COMPLETE/logs before returning output.
* search_callback(host_key, cap) builds the synchronous broker. After the parent
  ACTUALLY calls functions.web, publish_web_response(host_key, cap, reservation,
  raw_utf8=full_actual_output, hits=actual_normalized_hits, tool_call_id=...) records
  that host observation outside the worker root, then publishes response + ready.
  This host-only call is the observation boundary, not a tool execution itself.
* capture_callback(host_key, cap) wraps real transport/intake callbacks. Their
  observed bytes and parses are registered before the bridge's receipt checks.
* index_callback(host_key, cap, kind, callback) wraps a pinned native host adapter.
  It must return IndexObservation(result, protected_receipt, files). The receipt
  is an actual host-written, case-bound native execution record under trusted_root;
  its exact contract is checked by _index_observation. Files stay in legal-index.
* register_upload/register_scoring accept exact host-produced protected receipts.

The three guard methods are separate closed action vocabularies. role_guard
adapts the runtime's existing action-less binding to the single role-launch action.
Guards never issue capabilities or accept payload-created grants. A case capability
cannot register a web, role, parse, retrieval, or scoring receipt. Registration
requires the separate host key, pinned callbacks and verified bound files.

The trusted root MUST be outside every case root, inaccessible under the actual
role OS fence. Local JSON hashes are integrity pins, NOT cryptographic signatures,
independent/provider or professional assurance. The parent owns these process/OS
boundaries and active-owner selection. There is no automatic trusted-ledger reload:
a new process cannot adopt old self-sealed files merely because their hashes fit.
No defaults select roots, banks, sources, models, network, production or ACTIVE.
"""
from __future__ import annotations

import base64
import copy
import os
import re
import stat
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as bridge

VERSION = "legalbot.ge-case-custody.v1"
ROLES = frozenset(p.SCHEMAS)
OPERATIONS = ROLES | {"search", "capture", "index", "retrieve"}
BASE = {"action", "case_root", "index_root", "case_id", "request_sha256", "policy_sha256",
        "run_id", "baseline_sha256", "lane"}
PROTOCOL_FIELDS = {
    "case_protocol_start": set(), "reserve_budget": {"reservation"},
    "changed_retry": {"kind", "retry_profile_sha256", "failure_sha256"},
    "role_disclosure": {"role", "context_id", "job_root", "input_sha256"},
    "role_receipt": {"role", "context_id", "receipt_sha256", "output_sha256"},
    "public_query": {"query", "query_sha256"},
    "actual_web_result": {"raw_sha256", "tool_receipt_sha256", "hits_sha256"},
    "actual_capture_parse": {"source_sha256", "parsed_sha256", "parser_sha256", "parser_receipt_sha256"},
    "actual_retrieved_evidence": {"result_sha256", "index_receipt_sha256"},
    "terminal_receipt": {"terminal_sha256", "turn"}, "scoring_closed": {"receipt_sha256"},
    "establish_global_one_pass": {"marker_binding_sha256"}, "global_one_pass_receipt": {"marker"},
    "due_upload_extraction": {"upload"},
    **{"execute_" + kind: {"input_sha256", "reservation_sha256"} for kind in OPERATIONS},
    **{kind + "_receipt": {"input_sha256", "output_sha256"} for kind in OPERATIONS},
}
BRIDGE_FIELDS = {
    "use_reservation": {"public_input"}, "authorize_search": {"public_input", "started_at"},
    "authorize_capture": {"public_input", "started_at"},
    "web_response": {"request_file_sha256", "response_sha256", "raw_sha256", "hits_sha256",
                     "tool_receipt_sha256", "tool", "ready_file_sha256"},
    "search_complete": {"request_file_sha256", "output_sha256", "files", "response_sha256"},
    "capture_execute": {"url", "max_bytes", "timeout_seconds", "transport_code_sha256",
                        "parser_adapter_sha256", "parser_sha256", "parser_mode", "include_legal_tables"},
    "capture_file_write": {"name", "sha256", "byte_count"},
    "capture_parse": {"source_sha256", "parsed_sha256", "parser_sha256", "parser_receipt_sha256",
                      "files", "fetched_at", "redirect_chain", "parser_mode", "include_legal_tables"},
    "capture_complete": {"request_file_sha256", "output_sha256", "files", "parser_receipt_sha256"},
}
PIN_HASHES = {"runtime_sha256", "role_runtime_sha256", "role_callback_sha256", "parser_sha256",
    "transport_callback_sha256", "parser_callback_sha256", "index_runtime_sha256", "embedding_model_sha256",
    "index_callback_sha256", "retrieve_callback_sha256", "active_owner_reader_sha256", "query_privacy_sha256",
    "global_marker_verifier_sha256"}


class CustodyError(PermissionError):
    pass


def require(condition, code):
    if not condition:
        raise CustodyError(code)


def exact(value, expected):
    require(isinstance(value, dict) and p.canonical(value) == p.canonical(expected), "EXACT_BINDING_REQUIRED")


def root_path(value, workspace):
    value = Path(value)
    require(value.is_absolute() and value != workspace and value.is_relative_to(workspace)
            and ".." not in value.parts, "ROOT_OUTSIDE_EXPLICIT_WORKSPACE")
    return value


class CustodyStore(p.CaseStore):
    """Only bounded, no-follow enumeration inside an already authorized root."""
    def names(self, name):
        with self.directory(p.parts(name)) as fd:
            names = os.listdir(fd)
            require(len(names) <= 2048, "DIRECTORY_LIMIT")
            for child in names:
                p.parts(child)
                info = os.stat(child, dir_fd=fd, follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode), "SYMLINK_DENIED")
            return sorted(names)

    def inventory(self, name):
        result = {}
        def walk(relative, depth):
            require(depth <= 8 and len(result) <= 2048, "INVENTORY_LIMIT")
            for child in self.names(relative):
                path = relative + "/" + child
                with self.directory(p.parts(relative)) as fd:
                    info = os.stat(child, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    walk(path, depth + 1)
                else:
                    result[path[len(name) + 1:]] = p.digest(self.read(path))
        walk(name, 0)
        return result


@dataclass(frozen=True)
class IndexObservation:
    """Trusted native callback result, never deserialize this type from worker JSON.

    protected_receipt is relative to trusted_root. Its JSON must include the
    common case binding plus kind, input_sha256, result_sha256 (result WITHOUT
    receipt_sha256), index_runtime_sha256, embedding_model_sha256, non_live=True,
    active_mutated=False, synthetic_vectors=False, and files (case-root relative
    inventory, all under legal-index/). result.receipt_sha256 pins the exact bytes.
    The native host adapter writes it AFTER actual native execution/validation.
    """
    result: dict
    protected_receipt: str
    files: dict


class CaseCustody:
    def __init__(self, *, workspace_root, trusted_root, policy, pins, host_key,
                 active_owner_instruction, query_privacy, global_marker_verifier, store=None):
        self.workspace = Path(workspace_root)
        require(self.workspace.is_absolute() and self.workspace != Path("/") and ".." not in self.workspace.parts,
                "EXPLICIT_WORKSPACE_REQUIRED")
        self.root = root_path(trusted_root, self.workspace)
        require(type(host_key) is object, "OPAQUE_HOST_KEY_REQUIRED")
        self._host_key = host_key
        self.policy = p.decode(p.canonical(policy.manifest()))
        require(self.policy["baseline_kind"] == "EMPTY" and self.policy["baseline_sha256"] == p.digest([])
                and self.policy["lane"] == "candidate_case_local" and self.policy["production"] is False
                and self.policy["training"] is False, "COMMON_EMPTY_NON_LIVE_BASELINE_REQUIRED")
        self.policy_sha = p.digest(self.policy)
        self.pins = p.decode(p.canonical(pins))
        require(set(self.pins) == PIN_HASHES | {"model", "provider", "cli_identity"}, "EXPLICIT_RUNTIME_PINS_REQUIRED")
        for key in PIN_HASHES:
            p.checked(self.pins[key], p.HASH)
        require(self.pins["runtime_sha256"] == self.policy["runtime_sha256"]
                and re.fullmatch(r"gpt-[A-Za-z0-9_.-]+", self.pins["model"])
                and self.pins["provider"] == "openai", "PINNED_ROLE_RUNTIME_REQUIRED")
        cli = self.pins["cli_identity"]
        require(set(cli) == {"version", "launcher_sha256", "package_sha256", "native_sha256"}
                and isinstance(cli["version"], str) and bool(cli["version"]), "CLI_IDENTITY_REQUIRED")
        for key in ("launcher_sha256", "package_sha256", "native_sha256"):
            p.checked(cli[key], p.HASH)
        self._owner_reader, self._privacy = active_owner_instruction, query_privacy
        self._marker_verifier = global_marker_verifier
        self._active()
        self.store = store if store is not None else CustodyStore(self.root)
        require(Path(self.store.root) == self.root, "PROTECTED_STORE_ROOT_MISMATCH")
        self._lock, self._cases, self._caps, self._contexts = threading.RLock(), {}, {}, {}
        self._sequence, self._protected, self._once = 0, {}, None
        self._role_binding = None
        # No reloading/resealing old ledger bytes as new authority.
        self._write("CUSTODY-START.json", {"schema": VERSION, "scope": "UK_USA_FIRST", "policy": self.policy,
            "pins": self.pins, "signatures": False, "professional_assurance": False})

    def _active(self):
        require(bridge.callback_sha256(self._owner_reader) == self.pins["active_owner_reader_sha256"]
                and bridge.callback_sha256(self._privacy) == self.pins["query_privacy_sha256"]
                and bridge.callback_sha256(self._marker_verifier) == self.pins["global_marker_verifier_sha256"], "PARENT_CALLBACK_PIN_CHANGED")
        raw = self._owner_reader()
        require(isinstance(raw, bytes) and p.digest(raw) == self.policy["owner_instruction_sha256"],
                "OWNER_INSTRUCTION_NOT_ACTIVE")

    def _host(self, key):
        require(key is self._host_key, "HOST_ONLY_REGISTRATION")
        self._active()

    def _write(self, name, value):
        raw = value if isinstance(value, bytes) else p.canonical(value)
        self.store.write_new(name, raw)
        require(self.store.read(name) == raw, "PROTECTED_WRITE_CHANGED")
        self._protected[name] = p.digest(raw)
        return p.digest(raw)

    def _record(self, kind, case, evidence):
        with self._lock:
            self._sequence += 1
            path = f"CUSTODY-{self._sequence:06d}.json"
            sha = self._write(path, {"schema": VERSION, "kind": kind,
                "case": self._common(case), "evidence": evidence, "sequence": self._sequence})
            case["protected"].add(path)
            return sha

    def _check_protected(self, case):
        # Pins are process-held observations, not self-described JSON digests.
        paths = {"CUSTODY-START.json"} | case["protected"]
        if self._once is not None:
            paths.add("OBSERVED-GLOBAL-ONCE.bytes")
        for path in paths:
            require(p.digest(self.store.read(path)) == self._protected[path], "PROTECTED_LEDGER_CHANGED")

    def _case(self, cap):
        self._active()
        require(type(cap) is object and cap in self._caps, "UNISSUED_CASE_CAPABILITY")
        case = self._caps[cap]
        self._check_protected(case)
        return case

    def _common(self, case):
        return {"case_root": str(case["root"]), "index_root": str(case["root"] / "legal-index"),
            "case_id": case["request"]["case_id"], "request_sha256": case["request_sha"],
            "policy_sha256": self.policy_sha, "run_id": self.policy["run_id"],
            "baseline_sha256": self.policy["baseline_sha256"], "lane": "candidate_case_local"}

    def _history_values(self, case, field):
        return [value for prior in case["family"]["turns"].values()
                if prior["request"]["turn"] <= case["request"]["turn"] for value in prior[field].values()]

    def issue_case(self, key, *, case_root, request, store=None):
        self._host(key)
        p.checked(request, p.REQUEST_SCHEMA)
        request = p.decode(p.canonical(request))
        require(all(j in p.UK + p.US for j in request["jurisdictions"]), "UK_USA_SCOPE_REQUIRED")
        root = root_path(case_root, self.workspace)
        require(not root.is_relative_to(self.root) and not self.root.is_relative_to(root), "PROTECTED_ROOT_MUST_BE_DISJOINT")
        request_sha, case_id = p.digest(request), request["case_id"]
        with self._lock:
            family = self._cases.get(case_id)
            for other in self._cases.values():
                require(other["root"] == root if other is family else
                        not (root.is_relative_to(other["root"]) or other["root"].is_relative_to(root)), "CASE_ROOT_COLLISION")
            if family and request["turn"] in family["turns"]:
                prior = family["turns"][request["turn"]]
                require(prior["request_sha"] == request_sha, "SEALED_TURN_INPUT_CHANGED")
                return prior["cap"]
            family = family or {"root": root, "turns": {}, "terminal": {}, "budgets": {}, "scored": None}
            require(not family["scored"] and request["turn"] == len(family["turns"]) + 1,
                    "ORDERED_UNSCORED_TURN_REQUIRED")
            expected = []
            for turn in range(1, request["turn"]):
                require(turn in family["terminal"] and family["terminal"][turn]["answer"] is not None,
                        "UNSEALED_OR_FAILED_HISTORY")
                previous = family["turns"][turn]
                terminal = self._terminal(previous, family["terminal"][turn]["sha"], turn)
                expected.append({"turn": turn, "request_sha256": previous["request_sha"], "terminal_sha256": terminal["sha"]})
            require(request["history"] == expected, "SAME_CASE_EXACT_HISTORY_REQUIRED")
            target_store = store if store is not None else CustodyStore(root)
            require(Path(target_store.root) == root, "CASE_STORE_ROOT_MISMATCH")
            cap = object()
            case = {"cap": cap, "root": root, "request": request, "request_sha": request_sha,
                "store": target_store, "family": family, "queries": {}, "operations": {}, "outputs": {},
                "roles": {}, "web": {}, "capture": {}, "index": {}, "uploads": {}, "capture_adapters": set(), "protected": set()}
            case["cap_id"] = p.digest({"case_root": str(root), "request_sha256": request_sha, "policy_sha256": self.policy_sha})
            self._caps[cap], family["turns"][request["turn"]], self._cases[case_id] = case, case, family
            self._record("ISSUED_CASE", case, {"capability_id": case["cap_id"], "turn": request["turn"]})
            return cap

    def bridge_context(self, cap):
        case = self._case(cap)
        return bridge.BridgeContext(case["request"]["case_id"], case["request_sha"], self.policy_sha,
            self.pins["runtime_sha256"], case["cap_id"], bridge.callback_sha256(self.bridge_guard),
            tuple(case["request"]["jurisdictions"]), case["request"]["as_of_date"])

    def _public(self, case, query):
        fields = ("query", "jurisdiction", "as_of_date")
        value = {k: query[k] for k in fields}
        p.checked(value, bridge._SEARCH_INPUT)
        scopes = set(case["request"]["jurisdictions"])
        if scopes.intersection(p.US):
            scopes.add("US federal")
        require(value["jurisdiction"] in scopes and value["as_of_date"] == case["request"]["as_of_date"], "PUBLIC_QUERY_SCOPE")
        require(self._privacy(copy.deepcopy(self._common(case)), copy.deepcopy(value)) is True, "PUBLIC_QUERY_PRIVACY_UNVERIFIED")
        return value

    def _find_operation(self, case, kind, input_sha, reservation_sha=None):
        require(kind in OPERATIONS, "UNKNOWN_OPERATION")
        found = []
        for name in case["store"].names("operations"):
            if not re.fullmatch(re.escape(kind) + r"-[0-9a-f]{64}", name):
                continue
            for attempt in (1, 2):
                root = "operations/" + name + f"/attempt-{attempt}"
                path = root + "/reservation.json"
                if not case["store"].exists(path):
                    continue
                raw = case["store"].read(path)
                reservation = p.decode(raw)
                if reservation.get("input_sha256") != input_sha or (reservation_sha and p.digest(raw) != reservation_sha):
                    continue
                envelope = p.decode(case["store"].read(root + "/input.json"))
                require(set(reservation) == {"case_id", "request_sha256", "policy_sha256", "kind", "attempt", "input_sha256", "budget", "attempt_root"}
                    and all(reservation[k] == self._common(case)[k] for k in ("case_id", "request_sha256", "policy_sha256"))
                    and reservation["kind"] == kind and reservation["attempt"] == attempt
                    and reservation["attempt_root"] == root and p.digest(envelope) == input_sha, "OPERATION_SCOPE_OR_INPUT_CHANGED")
                profile = envelope["retry_profile_sha256"]
                require((attempt == 1 and profile is None) or (attempt == 2 and kind != "final" and profile in self.policy["retry_profiles"]),
                        "UNFROZEN_OR_FINAL_RETRY")
                if kind in ("search", "capture"):
                    budget = reservation["budget"]
                    require(case["family"]["budgets"].get((kind, budget["ordinal"])) == budget, "UNISSUED_BUDGET")
                    exact(p.decode(case["store"].read(f"budget/{kind}-{budget['ordinal']:02d}.json")), budget)
                else:
                    require(reservation["budget"] is None, "UNEXPECTED_OPERATION_BUDGET")
                found.append((reservation, envelope))
        require(len(found) == 1, "EXACT_RESERVED_OPERATION_REQUIRED")
        return found[0]

    def _inventory(self, case, relative, files):
        require(isinstance(files, dict) and 1 <= len(files) <= 2048, "BOUND_FILE_INVENTORY_REQUIRED")
        for name, sha in files.items():
            p.parts(name)
            p.checked(sha, p.HASH)
            path = relative + "/" + name if relative else name
            require(p.digest(case["store"].read(path)) == sha, "BOUND_FILE_CHANGED")

    def _role_disclosure(self, case, details):
        role, context = details["role"], details["context_id"]
        require(role in ROLES, "UNKNOWN_ROLE")
        if role == "reviewer":
            require(all(any(r["role"] == required and r.get("complete") for r in case["roles"].values())
                        for required in ("selector", "mapper")), "FRESH_SELECTOR_AND_MAPPER_BEFORE_REVIEWER")
        relative = Path(details["job_root"]).relative_to(case["root"]).as_posix()
        require(re.fullmatch(f"turn-{case['request']['turn']:04d}/jobs/{role}-a[12]", relative), "ROLE_ROOT_BINDING")
        data = p.decode(case["store"].read(relative + "/input.json"))
        require(data["case_id"] == case["request"]["case_id"] and data["role"] == role
                and p.digest(data) == details["input_sha256"], "ROLE_INPUT_BINDING")
        require(context == "ctx-" + p.digest({"case_root": str(case["root"]), "job": relative,
            "input": p.digest({"data": data["payload"], "retry_profile_sha256": data["retry_profile_sha256"]}),
            "policy": self.policy_sha}), "ROLE_CONTEXT_BINDING")
        exact(p.decode(case["store"].read(relative + "/schema.json")), p.SCHEMAS[role])
        require(case["store"].read(relative + "/prompt.txt") == p.PROMPTS[role].encode(), "ROLE_PROMPT_CHANGED")
        inventory = case["store"].inventory(relative)
        require("output.json" not in inventory and "role-receipt.json" not in inventory, "ROLE_NOT_FRESH")
        prior = self._contexts.get(context)
        record = {**details, "relative": relative, "inventory": inventory, "cap_id": case["cap_id"]}
        require(prior is None or prior == record, "CONTEXT_REUSE_OR_ROLE_COLLISION")
        # Separate selector/mapper/reviewer contexts are enforced across the run.
        require(all(r["context_id"] != context or r["role"] == role for r in case["roles"].values()), "REVIEWER_CONTEXT_NOT_INDEPENDENT")
        self._contexts[context] = record
        case["roles"][context] = record

    def protocol_guard(self, cap, binding):
        try:
            case = self._case(cap)
            action = binding["action"]
            require(action in PROTOCOL_FIELDS and set(binding) == BASE | PROTOCOL_FIELDS[action], "UNKNOWN_ACTION_OR_FIELDS")
            require({k: binding[k] for k in BASE - {"action"}} == self._common(case), "PROTOCOL_SCOPE_CHANGED")
            d = {k: binding[k] for k in PROTOCOL_FIELDS[action]}
            for name, value in d.items():
                if name.endswith("sha256"):
                    p.checked(value, p.HASH)
            if (action.startswith("execute_") or action in {"reserve_budget", "changed_retry", "role_disclosure", "public_query", "due_upload_extraction"}):
                require(not case["family"]["scored"] and case["request"]["turn"] not in case["family"]["terminal"],
                        "SEALED_OR_SCORED_MUTATION_DENIED")
            if action == "case_protocol_start":
                require(not case["family"]["scored"], "POST_SCORE_DENIED")
            elif action == "public_query":
                p.checked(d["query"], p.QUERY)
                require(p.digest(d["query"]) == d["query_sha256"], "QUERY_HASH_CHANGED")
                value = self._public(case, d["query"])
                case["queries"][p.digest(value)] = value
            elif action == "reserve_budget":
                r = d["reservation"]
                require(set(r) == {"case_id", "policy_sha256", "request_sha256", "operation", "input_sha256", "kind", "ordinal", "maximum"}
                    and r["kind"] in ("search", "capture") and type(r["ordinal"]) is int
                    and 1 <= r["ordinal"] <= {"search": 4, "capture": 8}[r["kind"]]
                    and r["maximum"] == {"search": 4, "capture": 8}[r["kind"]]
                    and all(r[k] == self._common(case)[k] for k in ("case_id", "request_sha256", "policy_sha256"))
                    and re.fullmatch("operations/" + r["kind"] + r"-[0-9a-f]{64}", r["operation"]), "INVALID_BUDGET_SCOPE")
                p.checked(r["input_sha256"], p.HASH)
                key = (r["kind"], r["ordinal"])
                require(key not in case["family"]["budgets"], "BUDGET_ALREADY_CONSUMED")
                case["family"]["budgets"][key] = copy.deepcopy(r)
                self._record("RESERVED_BUDGET", case, r)
            elif action == "changed_retry":
                require(d["kind"] in OPERATIONS - {"final"} and d["retry_profile_sha256"] in self.policy["retry_profiles"], "RETRY_NOT_FROZEN")
                failures = [p.digest(case["store"].read(r["attempt_root"] + "/failure.json"))
                    for r, _ in case["operations"].values() if r["kind"] == d["kind"] and r["attempt"] == 1
                    and case["store"].exists(r["attempt_root"] + "/failure.json")]
                require(d["failure_sha256"] in failures, "UNOBSERVED_RETRY_FAILURE")
            elif action.startswith("execute_"):
                kind = action.removeprefix("execute_")
                require(self._once is not None, "GLOBAL_ONCE_NOT_ESTABLISHED")
                r, envelope = self._find_operation(case, kind, d["input_sha256"], d["reservation_sha256"])
                require((kind, d["input_sha256"]) not in case["operations"], "OPERATION_ALREADY_STARTED")
                if kind == "index":
                    self._index_input(case, envelope["data"])
                if kind == "retrieve":
                    require(("index", p.digest(envelope["data"]["build"])) in case["index"], "UNOBSERVED_INDEX_BEFORE_RETRIEVAL")
                case["operations"][(kind, d["input_sha256"])] = (r, envelope)
            elif action == "role_disclosure":
                self._role_disclosure(case, d)
            elif action == "role_receipt":
                require(any(value == d for value in case["outputs"].get("role_receipts", [])), "UNREGISTERED_ROLE_RECEIPT")
            elif action == "actual_web_result":
                require(any(all(w[k] == v for k, v in d.items()) for w in self._history_values(case, "web")), "UNOBSERVED_WEB_RESULT")
            elif action == "actual_capture_parse":
                require(any(c.get("parse_binding") == d for c in self._history_values(case, "capture")), "UNOBSERVED_ACTUAL_PARSE")
            elif action == "actual_retrieved_evidence":
                record = case["index"][("retrieve", d["result_sha256"])]
                require(record["index_receipt_sha256"] == d["index_receipt_sha256"], "UNOBSERVED_RETRIEVAL")
                self._inventory(case, "", record["files"])
            elif action == "terminal_receipt":
                self._terminal(case, d["terminal_sha256"], d["turn"])
            elif action == "establish_global_one_pass":
                require(d["marker_binding_sha256"] == p.digest(self._marker_input(case)), "MARKER_INPUT_CHANGED")
            elif action == "global_one_pass_receipt":
                require(self._once is not None and d["marker"] == self._once, "UNISSUED_GLOBAL_MARKER")
            elif action == "due_upload_extraction":
                require(case["uploads"].get(p.digest(d["upload"])) == d["upload"], "UNREGISTERED_UPLOAD_EXTRACTION")
            elif action == "scoring_closed":
                require(case["family"]["scored"] == d["receipt_sha256"], "UNREGISTERED_SCORING_RECEIPT")
            elif action.endswith("_receipt"):
                kind = action.removesuffix("_receipt")
                require(case["outputs"].get((kind, d["input_sha256"])) == d["output_sha256"], "UNREGISTERED_OPERATION_OUTPUT")
            else:
                raise CustodyError("UNKNOWN_ACTION")
            return True
        except (KeyError, TypeError, ValueError, OSError, AttributeError):
            return False

    def _marker_input(self, case):
        return {k: self._common(case)[k] for k in ("run_id", "policy_sha256", "baseline_sha256", "case_id", "request_sha256")}

    def _index_input(self, case, legal):
        require(legal["case_id"] == case["request"]["case_id"] and legal["lane"] == "candidate_case_local"
            and legal["baseline_kind"] == "EMPTY" and legal["baseline_sha256"] == p.digest([])
            and legal["lineage"] == {"request_sha256": case["request_sha"], "policy_sha256": self.policy_sha}, "INDEX_INPUT_SCOPE")
        reviews = [r for r in case["roles"].values() if r["role"] == "reviewer" and r.get("complete")
                   and p.digest(r["output"]) == legal["review_sha256"]]
        require(len(reviews) == 1, "ACTUAL_INDEPENDENT_REVIEW_REQUIRED")
        review = reviews[0]
        mappers = [r for r in case["roles"].values() if r["role"] == "mapper" and r.get("complete")]
        require(mappers and all(m["context_id"] != review["context_id"] for m in mappers), "REVIEWER_MAPPER_COLLISION")
        approved_sources = {r["source_sha256"] for r in review["output"]["sources"]
            if r["decision"] == "ELIGIBLE" and all(v is True for v in r["checks"].values()) and not r["holds"]}
        approved_props = {r["proposition_sha256"] for r in review["output"]["propositions"]
            if r["decision"] == "ELIGIBLE" and all(v is True for v in r["checks"].values()) and not r["holds"]}
        mapped = {p.digest(prop) for mapper in mappers for prop in mapper["output"]["propositions"]}
        require(legal["propositions"] and all(p.digest(prop) in approved_props & mapped for prop in legal["propositions"]),
                "UNREVIEWED_OR_CHANGED_PROPOSITION")
        for source in legal["sources"]:
            sha = p.digest(base64.b64decode(source["raw_b64"], validate=True))
            require(sha in approved_sources and any(value.get("parse_binding") == {
                "source_sha256": sha, "parsed_sha256": p.digest(source["parts"]),
                "parser_sha256": source["parser_sha256"], "parser_receipt_sha256": source["parser_receipt_sha256"]}
                for value in self._history_values(case, "capture")), "SOURCE_NOT_HOST_OBSERVED_AND_REVIEWED")

    def establish_one_pass(self, key, cap, binding):
        self._host(key)
        case = self._case(cap)
        exact(binding, self._marker_input(case))
        with self._lock:
            require(self._once is not None, "ACTUAL_PARENT_GLOBAL_MARKER_REQUIRED")
            self._record("CASE_ONCE_BOUND", case, {"marker_sha256": self._once["marker_sha256"]})
            return copy.deepcopy(self._once)

    def register_global_marker(self, key, *, marker_bytes):
        self._host(key)
        require(isinstance(marker_bytes, bytes) and 0 < len(marker_bytes) <= p.MAX_BYTES, "ACTUAL_PARENT_MARKER_BYTES_REQUIRED")
        binding = {"run_id": self.policy["run_id"], "policy_sha256": self.policy_sha,
            "baseline_sha256": p.digest([]), "runtime_sha256": self.pins["runtime_sha256"],
            "owner_instruction_sha256": self.policy["owner_instruction_sha256"], "marker_sha256": p.digest(marker_bytes)}
        require(self._marker_verifier(copy.deepcopy(binding), marker_bytes) is True, "PARENT_GLOBAL_MARKER_NOT_VERIFIED")
        with self._lock:
            if self._once is not None:
                require(self._once["marker_sha256"] == p.digest(marker_bytes)
                    and self.store.read("OBSERVED-GLOBAL-ONCE.bytes") == marker_bytes, "GLOBAL_MARKER_CHANGED")
            else:
                sha = self._write("OBSERVED-GLOBAL-ONCE.bytes", marker_bytes)
                self._once = {"run_id": self.policy["run_id"], "policy_sha256": self.policy_sha,
                    "baseline_sha256": p.digest([]), "marker_sha256": sha, "global_pre_answer_one_pass": True}
            return copy.deepcopy(self._once)

    def role_guard(self, cap, binding):
        try:
            case = self._case(cap)
            require(set(binding) == {"case_root", "job_root", "role", "context_id", "input_sha256", "model", "provider", "browse"}, "ROLE_LAUNCH_FIELDS")
            record = case["roles"][binding["context_id"]]
            expected = {k: record[k] for k in ("job_root", "role", "context_id", "input_sha256")}
            expected.update(case_root=str(case["root"]), model=self.pins["model"], provider=self.pins["provider"], browse=False)
            exact(binding, expected)
            require(binding["browse"] is False and record.get("launch_authorized") is True, "ROLE_HOST_LAUNCH_NOT_AUTHORIZED")
            self._inventory(case, record["relative"], record["inventory"])
            return True
        except (KeyError, TypeError, ValueError, OSError):
            return False

    def role_callback(self, key, cap, runtime):
        self._host(key)
        case = self._case(cap)
        from scripts import ge_auto_role_runtime as roles
        require(type(runtime) is roles.CodexRoleRuntime, "ACTUAL_PINNED_ROLE_RUNTIME_REQUIRED")
        with self._lock:
            if self._role_binding is None:
                function = type(runtime).__call__
                code = getattr(function, "__code__", None)
                expected = self.pins["role_callback_sha256"]
                require(code is not None and bridge.callback_sha256(function) == expected,
                        "ACTUAL_PINNED_ROLE_RUNTIME_REQUIRED")
                # marshal bytes depend on constant reference counts. A successful
                # role caches regex constants and can change the hash of unchanged
                # code. Verify the external pin once, then retain exact identities
                # across invocations and factories for this custody instance.
                self._role_binding = (type(runtime), function, code, expected,
                                      roles.__file__, self.pins["role_runtime_sha256"])
            runtime_type, function, code, expected, module_file, module_sha = self._role_binding

        def runtime_matches():
            bound = getattr(runtime, "__call__", None)
            return (type(runtime) is runtime_type is roles.CodexRoleRuntime
                and runtime_type.__call__ is function and function.__code__ is code
                and getattr(bound, "__func__", None) is function
                and getattr(bound, "__self__", None) is runtime
                and self.pins["role_callback_sha256"] == expected
                and runtime.case_root == case["root"] and runtime.protected_root == self.root
                and runtime.model == self.pins["model"] and runtime.provider == self.pins["provider"]
                and runtime.expected_cli == self.pins["cli_identity"]
                and runtime.capability is cap and runtime.verify == self.role_guard
                and roles.__file__ == module_file and self.pins["role_runtime_sha256"] == module_sha
                and p.digest(Path(module_file).read_bytes()) == module_sha)

        require(runtime_matches(), "ACTUAL_PINNED_ROLE_RUNTIME_REQUIRED")
        def invoke(job):
            self._host(key)
            case = self._case(cap)
            require(type(job) is p.RoleJob and runtime_matches(),
                    "PINNED_ROLE_JOB_AND_RUNTIME_REQUIRED")
            record = case["roles"][job.context_id]
            require(not record.get("launched") and job.role == record["role"] and job.root == Path(record["job_root"])
                    and job.input_sha256 == record["input_sha256"] and job.allow_browsing is False, "FRESH_DISCLOSED_ROLE_REQUIRED")
            exact(job.input, p.decode(case["store"].read(record["relative"] + "/input.json")))
            exact(job.schema, p.SCHEMAS[job.role])
            require(job.prompt == p.PROMPTS[job.role], "ROLE_PROMPT_CHANGED")
            self._inventory(case, record["relative"], record["inventory"])
            require(case["store"].inventory(record["relative"]) == record["inventory"], "ROLE_INVENTORY_CHANGED")
            profile = roles.profile(job.root)
            record["profile_sha256"] = p.digest(profile.encode())
            record["launched"] = record["launch_authorized"] = True
            try:
                result = runtime(job)
            finally:
                record["launch_authorized"] = False
            self._complete_role(key, cap, runtime, job, result)
            return result
        return invoke

    def _complete_role(self, key, cap, runtime, job, result):
        self._host(key)
        case, context = self._case(cap), job.context_id
        record = case["roles"][context]
        require(record.get("launched") and not record.get("complete"), "ROLE_COMPLETION_WITHOUT_HOST_LAUNCH")
        sha = result["receipt_sha256"]
        require(runtime.receipts.get(sha) == self.root / context / "COMPLETE.json", "UNISSUED_RUNTIME_COMPLETION")
        raw = self.store.read(context + "/COMPLETE.json")
        require(p.digest(raw) == sha, "ROLE_COMPLETE_HASH_CHANGED")
        complete = p.decode(raw)
        started_raw = self.store.read(context + "/START.json")
        started = p.decode(started_raw)
        require(complete["start_sha256"] == p.digest(started_raw)
                and all(complete.get(k) == v for k, v in started.items()), "ROLE_START_CHANGED")
        expected = {"case_root": str(case["root"]), "job_root": str(job.root), "role": job.role,
            "context_id": context, "input_sha256": job.input_sha256, "model": self.pins["model"],
            "provider": self.pins["provider"], "browse": False, "fresh_context": True,
            "cli_identity": self.pins["cli_identity"], "runtime_file_sha256": self.pins["role_runtime_sha256"],
            "training": False, "input_inventory": record["inventory"]}
        require(all(started.get(k) == v for k, v in expected.items())
                and started["browse"] is False and started["fresh_context"] is True and started["training"] is False,
                "ROLE_EXECUTION_IDENTITY_CHANGED")
        exact(started["fence"], {"own_exact_input_readable": True, "outside_public_file_denied": True,
            "input_write_open_denied": True, "private_bank_probe": "NOT_ATTEMPTED", "profile_sha256": record["profile_sha256"]})
        start, end = datetime.fromisoformat(started["started"]), datetime.fromisoformat(complete["completed"])
        require(start.tzinfo is not None and end.tzinfo is not None and end >= start
                and type(complete["returncode"]) is int and complete["returncode"] == 0 and complete["error"] is None,
                "ROLE_NOT_SUCCESSFULLY_COMPLETED")
        for name in ("stdout", "stderr"):
            require(p.digest(self.store.read(context + "/" + name + ".log")) == complete[name + "_sha256"], "ROLE_LOG_CHANGED")
        log = self.store.read(context + "/stderr.log").decode(errors="replace")
        require(set(re.findall(r"(?m)^model:\s*(\S+)", log)) == {self.pins["model"]}
            and set(re.findall(r"(?m)^provider:\s*(\S+)", log)) == {self.pins["provider"]}, "ACTUAL_ROLE_MODEL_PROVIDER_MISMATCH")
        self._inventory(case, record["relative"], record["inventory"])
        output_name = "output.json"
        if complete.get("span_materialization_sha256") is not None:
            require(job.role == "mapper" and complete.get("span_canonicalization_sha256") is None,
                    "UNEXPECTED_SPAN_MATERIALIZATION")
            reference_raw = case["store"].read(record["relative"] + "/span-references.json")
            require(p.digest(reference_raw) == complete.get("model_output_sha256"), "MODEL_OUTPUT_CHANGED")
            expected_output, expected_receipt = p.materialize_mapper_spans(
                p.decode(reference_raw), job.input["payload"])
            receipt_raw = case["store"].read(record["relative"] + "/span-materialization.json")
            require(p.digest(receipt_raw) == complete["span_materialization_sha256"]
                    and p.decode(receipt_raw) == expected_receipt, "SPAN_MATERIALIZATION_CHANGED")
            require(p.decode(case["store"].read(record["relative"] + "/output.json")) == expected_output,
                    "MATERIALIZED_MAPPER_OUTPUT_CHANGED")
        if complete.get("span_canonicalization_sha256") is not None:
            require(job.role == "mapper", "UNEXPECTED_SPAN_CANONICALIZATION")
            model_raw = case["store"].read(record["relative"] + "/output.json")
            model_output = p.checked(p.decode(model_raw), p.SCHEMAS[job.role])
            require(p.digest(model_raw) == complete.get("model_output_sha256"),
                    "MODEL_OUTPUT_CHANGED")
            receipt_raw = case["store"].read(record["relative"] + "/span-canonicalization.json")
            expected_output, expected_receipt = p.canonicalize_mapper_spans(
                model_output, job.input["payload"])
            require(p.digest(receipt_raw) == complete["span_canonicalization_sha256"]
                    and p.decode(receipt_raw) == expected_receipt,
                    "SPAN_CANONICALIZATION_CHANGED")
            output_name = "normalized-output.json"
            normalized_raw = case["store"].read(record["relative"] + "/" + output_name)
            require(p.decode(normalized_raw) == expected_output,
                    "NORMALIZED_MAPPER_OUTPUT_CHANGED")
        output_raw = case["store"].read(record["relative"] + "/" + output_name)
        output = p.checked(p.decode(output_raw), p.SCHEMAS[job.role])
        require(p.digest(output_raw) == complete["output_sha256"] and result == {
            "context_id": context, "input_sha256": job.input_sha256, "receipt_sha256": sha, "output": output}, "ROLE_OUTPUT_CHANGED")
        binding = {"role": job.role, "context_id": context, "receipt_sha256": sha, "output_sha256": p.digest(output)}
        self._record("ACTUAL_ROLE_COMPLETION", case, {**binding, "complete_file_sha256": sha})
        for name in ("START.json", "COMPLETE.json", "stdout.log", "stderr.log"):
            self._protected[context + "/" + name] = p.digest(self.store.read(context + "/" + name))
            case["protected"].add(context + "/" + name)
        record.update(complete=True, output=output, receipt=sha)
        case["outputs"].setdefault("role_receipts", []).append(binding)
        for (kind, input_sha), (reservation, _) in case["operations"].items():
            if kind == job.role and reservation["attempt_root"].endswith("attempt-" + record["relative"][-1]):
                case["outputs"][(kind, input_sha)] = p.digest(output)

    def _bridge_operation(self, case, binding):
        expected = {"schema": bridge.VERSION, "case_root": str(case["root"]), "lane": "candidate_case_local",
                    **p.decode(p.canonical(asdict(self.bridge_context(case["cap"]))))}
        require(all(binding.get(k) == v for k, v in expected.items()), "BRIDGE_CASE_BINDING_CHANGED")
        if binding["action"] == "bind_case_root":
            require(set(binding) == set(expected) | {"action"}, "BRIDGE_BIND_FIELDS")
            return None
        action = binding["action"]
        core = {"action", "broker_root", "kind", "input_sha256", "reservation_sha256", "attempt", "budget", "retry_profile_sha256"}
        require(action in BRIDGE_FIELDS and set(binding) == set(expected) | core | BRIDGE_FIELDS[action], "UNKNOWN_BRIDGE_ACTION_OR_FIELDS")
        kind = binding["kind"]
        require(kind in ("search", "capture"), "BRIDGE_OPERATION_KIND")
        r, envelope = case["operations"][(kind, binding["input_sha256"])]
        require(p.digest(r) == binding["reservation_sha256"] and binding["budget"] == r["budget"]
            and binding["attempt"] == r["attempt"] and binding["retry_profile_sha256"] == envelope["retry_profile_sha256"], "BRIDGE_RESERVATION_CHANGED")
        root = "broker/" + kind + "-" + p.digest(r)
        require(binding["broker_root"] == str(case["root"] / root), "BRIDGE_ROOT_CHANGED")
        return r, envelope, root

    def bridge_guard(self, cap, binding):
        try:
            case = self._case(cap)
            op = self._bridge_operation(case, binding)
            if op is None:
                return True
            r, envelope, root = op
            action, key = binding["action"], p.digest(r)
            if action in ("use_reservation", "authorize_search", "authorize_capture"):
                require(binding["public_input"] == envelope["data"], "BRIDGE_PUBLIC_INPUT_CHANGED")
                if r["kind"] == "search":
                    require(case["queries"].get(p.digest(envelope["data"])) == self._public(case, envelope["data"]), "UNAPPROVED_PUBLIC_QUERY")
                else:
                    require(any(envelope["data"]["url"] in [h["url"] for h in w["result"]["hits"]] for w in case["web"].values()), "CAPTURE_NOT_FROM_OWN_SEARCH")
            elif action == "web_response":
                value = case["web"][key]
                require(all(value[k] == binding[k] for k in BRIDGE_FIELDS[action]), "WEB_PROTECTED_PIN_MISMATCH")
                self._inventory(case, root, value["files"])
            elif action == "capture_execute":
                require(binding["url"] == envelope["data"]["url"] and binding["parser_sha256"] == self.pins["parser_sha256"]
                    and binding["parser_mode"] == bridge.PARSER_MODE and binding["include_legal_tables"] is True
                    and (binding["transport_code_sha256"], binding["parser_adapter_sha256"]) in case["capture_adapters"]
                    and 0 < binding["max_bytes"] <= bridge.MAX_RAW_BYTES and 0 < binding["timeout_seconds"] <= 60, "UNPINNED_CAPTURE_EXECUTION")
            elif action == "capture_file_write":
                observed = case["capture"][key]["emitting"]
                require(observed == {k: binding[k] for k in ("name", "sha256", "byte_count")}, "UNOBSERVED_CAPTURE_FILE")
            elif action == "capture_parse":
                value = case["capture"][key]
                require(binding["source_sha256"] == value["source_sha256"] and binding["parsed_sha256"] == value["parsed_sha256"]
                    and binding["parser_sha256"] == self.pins["parser_sha256"]
                    and binding["parser_mode"] == bridge.PARSER_MODE and binding["include_legal_tables"] is True
                    and binding["fetched_at"] == value["transport"]["fetched_at"]
                    and binding["redirect_chain"] == value["transport"]["redirect_chain"], "UNOBSERVED_CAPTURE_PARSE")
                self._inventory(case, root, binding["files"])
                raw = case["store"].read(root + "/parser-receipt.json")
                require(p.digest(raw) == binding["parser_receipt_sha256"], "PARSER_RECEIPT_CHANGED")
                receipt = p.decode(raw)
                require(receipt["source_sha256"] == value["source_sha256"] and receipt["parsed_sha256"] == value["parsed_sha256"]
                    and receipt["reservation_sha256"] == key and receipt["parser_sha256"] == self.pins["parser_sha256"], "PARSER_RECEIPT_SCOPE")
                value["parse_binding"] = {k: binding[k] for k in PROTOCOL_FIELDS["actual_capture_parse"]}
                self._record("ACTUAL_CAPTURE_PARSE", case, value["parse_binding"])
            elif action in ("search_complete", "capture_complete"):
                self._inventory(case, root, binding["files"])
                result_raw = case["store"].read(root + "/result.json")
                require(p.digest(result_raw) == binding["output_sha256"]
                    and p.digest(case["store"].read(root + "/request.json")) == binding["request_file_sha256"], "BRIDGE_RESULT_CHANGED")
                result = p.decode(result_raw)
                if action == "search_complete":
                    require(result == case["web"][key]["result"] and binding["response_sha256"] == case["web"][key]["response_sha256"], "WEB_RESULT_CHANGED")
                else:
                    value = case["capture"][key]
                    require(p.digest(base64.b64decode(result["raw_b64"], validate=True)) == value["source_sha256"]
                        and p.digest(result["parts"]) == value["parsed_sha256"]
                        and result["parser_receipt_sha256"] == value["parse_binding"]["parser_receipt_sha256"]
                        == binding["parser_receipt_sha256"], "CAPTURE_RESULT_CHANGED")
                case["outputs"][(r["kind"], r["input_sha256"])] = p.digest(result)
            else:
                raise CustodyError("UNKNOWN_BRIDGE_ACTION")
            return True
        except (KeyError, TypeError, ValueError, OSError, AttributeError):
            return False

    def search_callback(self, key, cap, **wait_options):
        self._host(key)
        case = self._case(cap)
        require(set(wait_options) <= {"timeout_seconds", "poll_seconds", "monotonic", "sleep", "now"}, "SEARCH_OPTIONS_SCOPE")
        return bridge.make_search_callback(case_root=case["root"], context=self.bridge_context(cap),
            capability=cap, verify=self.bridge_guard, store=case["store"], **wait_options)

    def publish_web_response(self, key, cap, reservation, *, raw_utf8, hits, tool_call_id):
        self._host(key)
        case = self._case(cap)
        r, envelope = case["operations"][("search", reservation["input_sha256"])]
        exact(reservation, r)
        self._public(case, envelope["data"])
        require(isinstance(tool_call_id, str) and 0 < len(tool_call_id) <= 200, "ACTUAL_HOST_TOOL_CALL_ID_REQUIRED")
        key_sha, root = p.digest(r), "broker/search-" + p.digest(r)
        require(key_sha not in case["web"], "WEB_CALL_ALREADY_RECORDED")
        request_raw = case["store"].read(root + "/request.json")
        request = p.decode(request_raw)
        require(request["reservation_sha256"] == key_sha and request["public_input"] == envelope["data"]
                and request["context"] == p.decode(p.canonical(asdict(self.bridge_context(cap))))
                and request["tool_arguments"] == bridge.search_arguments(envelope["data"]), "WEB_REQUEST_CHANGED")
        tool_sha = self._record("ACTUAL_HOST_WEB_CALL", case, {"tool": "functions.web", "tool_call_id": tool_call_id,
            "request_file_sha256": p.digest(request_raw), "reservation_sha256": key_sha,
            "raw_sha256": p.digest(raw_utf8.encode()), "hits_sha256": p.digest(hits)})
        response = bridge.web_response(request_raw, raw_utf8=raw_utf8, hits=hits, tool_receipt_sha256=tool_sha)
        ready = p.canonical({"response_sha256": p.digest(response)})
        result = p.decode(response)["result"]
        value = {"request_file_sha256": p.digest(request_raw), "response_sha256": p.digest(response),
            "raw_sha256": p.digest(raw_utf8.encode()), "hits_sha256": p.digest(hits), "tool_receipt_sha256": tool_sha,
            "tool": "functions.web", "ready_file_sha256": p.digest(ready), "result": result,
            "files": {"request.json": p.digest(request_raw), "response.json": p.digest(response), "response-ready.json": p.digest(ready)}}
        self._record("PROTECTED_WEB_RESPONSE", case, {k: v for k, v in value.items() if k != "result"})
        case["web"][key_sha] = value
        case["store"].write_new(root + "/response.json", response)
        case["store"].write_new(root + "/response-ready.json", ready)
        return tool_sha

    def capture_callback(self, key, cap, *, transport=bridge.fetch_official, parser=bridge.parse_official_capture, **options):
        self._host(key)
        case = self._case(cap)
        require(bridge.callback_sha256(transport) == self.pins["transport_callback_sha256"]
                and bridge.callback_sha256(parser) == self.pins["parser_callback_sha256"], "NATIVE_CAPTURE_CALLBACK_PIN")
        require(set(options) <= {"max_bytes", "timeout_seconds", "now"}, "CAPTURE_OPTIONS_SCOPE")
        current = {}
        def capture_transport(url, *, max_bytes, timeout_seconds, emit):
            value = case["capture"][current["key"]]
            def observed_emit(name, data):
                raw = data if isinstance(data, bytes) else p.canonical(data)
                value["emitting"] = {"name": name, "sha256": p.digest(raw), "byte_count": len(raw)}
                try:
                    emit(name, data)
                finally:
                    value.pop("emitting", None)
                value["files"][name] = p.digest(raw)
            result = transport(url, max_bytes=max_bytes, timeout_seconds=timeout_seconds, emit=observed_emit)
            self._inventory(case, current["root"], value["files"])
            raw = case["store"].read(current["root"] + "/raw.bytes")
            require(p.digest(raw) == result["raw_sha256"], "OBSERVED_TRANSPORT_RAW_CHANGED")
            value.update(transport=copy.deepcopy(result), source_sha256=p.digest(raw))
            self._record("ACTUAL_TRANSPORT_CALLBACK", case, {"reservation_sha256": current["key"], "files": value["files"]})
            return result
        def capture_parser(raw, **kwargs):
            value = case["capture"][current["key"]]
            require(p.digest(raw) == value["source_sha256"], "PARSE_RAW_NOT_OBSERVED")
            manifest = parser(raw, **kwargs)
            require(manifest["parser_sha256"] == self.pins["parser_sha256"]
                    and manifest["raw_sha256"] == value["source_sha256"], "ACTUAL_PARSER_PIN_MISMATCH")
            value["parsed_sha256"] = p.digest(bridge.structural_parts(manifest))
            self._record("ACTUAL_PARSER_CALLBACK", case, {"reservation_sha256": current["key"],
                "source_sha256": value["source_sha256"], "parsed_sha256": value["parsed_sha256"], "parser_sha256": self.pins["parser_sha256"]})
            return manifest
        case["capture_adapters"].add((bridge.callback_sha256(capture_transport), bridge.callback_sha256(capture_parser)))
        callback = bridge.make_capture_callback(case_root=case["root"], context=self.bridge_context(cap), capability=cap,
            verify=self.bridge_guard, store=case["store"], parser_sha256=self.pins["parser_sha256"],
            transport=capture_transport, parser=capture_parser, **options)
        def invoke(envelope, reservation):
            self._host(key)
            self._case(cap)
            res_key = p.digest(reservation)
            require(not current and res_key not in case["capture"], "CAPTURE_ATTEMPT_ALREADY_OBSERVED")
            current.update(key=res_key, root="broker/capture-" + res_key)
            case["capture"][res_key] = {"files": {}}
            try:
                return callback(envelope, reservation)
            finally:
                current.clear()
        return invoke

    def index_callback(self, key, cap, kind, callback):
        self._host(key)
        case = self._case(cap)
        require(kind in ("index", "retrieve") and bridge.callback_sha256(callback) == self.pins[kind + "_callback_sha256"], "INDEX_CALLBACK_PIN_REQUIRED")
        def invoke(envelope, reservation):
            self._host(key)
            self._case(cap)
            require(case["operations"].get((kind, p.digest(envelope))) == (reservation, envelope), "UNAUTHORIZED_NATIVE_INDEX_OPERATION")
            observation = callback(copy.deepcopy(envelope), copy.deepcopy(reservation))
            self._index_observation(key, cap, kind, envelope, reservation, observation)
            return copy.deepcopy(observation.result)
        return invoke

    def _index_observation(self, key, cap, kind, envelope, reservation, observation):
        self._host(key)
        case = self._case(cap)
        require(type(observation) is IndexObservation and observation.protected_receipt.startswith("index/"), "ACTUAL_HOST_INDEX_OBSERVATION_REQUIRED")
        result = p.checked(observation.result, p.INDEX_SCHEMA if kind == "index" else p.RETRIEVAL_SCHEMA)
        raw = self.store.read(observation.protected_receipt)
        require(p.digest(raw) == result["receipt_sha256"], "PROTECTED_INDEX_RECEIPT_HASH")
        receipt = p.decode(raw)
        expected = {**self._common(case), "kind": kind, "input_sha256": p.digest(envelope),
            "result_sha256": p.digest({k: v for k, v in result.items() if k != "receipt_sha256"}),
            "index_runtime_sha256": self.pins["index_runtime_sha256"], "embedding_model_sha256": self.pins["embedding_model_sha256"],
            "non_live": True, "active_mutated": False, "synthetic_vectors": False, "files": observation.files}
        exact(receipt, expected)
        require(receipt["non_live"] is True and receipt["active_mutated"] is False and receipt["synthetic_vectors"] is False
                and observation.files and all(path.startswith("legal-index/") for path in observation.files), "CASE_LOCAL_REAL_INDEX_FILES_REQUIRED")
        self._inventory(case, "", observation.files)
        require(result["baseline_sha256"] == p.digest([]), "INDEX_BASELINE_CHANGED")
        if kind == "index":
            legal = envelope["data"]
            require(result["case_id"] == case["request"]["case_id"] and result["legal_input_sha256"] == p.digest(legal)
                    and legal["baseline_sha256"] == p.digest([]) and legal["baseline_kind"] == "EMPTY"
                    and legal["lineage"] == {"request_sha256": case["request_sha"], "policy_sha256": self.policy_sha}, "INDEX_LEGAL_INPUT_BINDING")
            reviewers = [r for r in case["roles"].values() if r["role"] == "reviewer" and r.get("complete")]
            require(any(p.digest(r["output"]) == legal["review_sha256"] for r in reviewers), "INDEPENDENT_SOURCE_REVIEW_REQUIRED")
            record = {"result": copy.deepcopy(result), "files": copy.deepcopy(observation.files)}
        else:
            built = envelope["data"]["build"]
            require(("index", p.digest(built)) in case["index"] and result["generation_sha256"] == built["generation_sha256"]
                    and all(e["origin"] == "CASE_LOCAL" for e in result["evidence"]), "UNOBSERVED_OR_CROSS_BASELINE_RETRIEVAL")
            record = {"index_receipt_sha256": built["receipt_sha256"], "files": copy.deepcopy(observation.files)}
        self._protected[observation.protected_receipt] = p.digest(raw)
        case["protected"].add(observation.protected_receipt)
        self._record("ACTUAL_NATIVE_" + kind.upper(), case, {"receipt_sha256": p.digest(raw), "output_sha256": p.digest(result)})
        case["index"][(kind, p.digest(result))] = record
        case["outputs"][(kind, p.digest(envelope))] = p.digest(result)

    def register_upload(self, key, cap, *, upload, raw, protected_receipt):
        """Bind a prior extraction to this exact request without circular hashes.

        The extraction receipt predates the request (which includes its hash), so
        it binds case/root/policy/runtime/turn/upload and raw/text hashes. The
        protected custody entry then binds it to the newly frozen request hash.
        """
        self._host(key)
        case = self._case(cap)
        require(upload in case["request"]["due_uploads"] and isinstance(raw, bytes) and p.digest(raw) == upload["sha256"]
                and p.digest(upload["text"].encode()) == upload["text_sha256"]
                and protected_receipt.startswith("uploads/"), "UPLOAD_SCOPE_OR_BYTES")
        receipt_raw = self.store.read(protected_receipt)
        require(p.digest(receipt_raw) == upload["extraction_sha256"], "UPLOAD_EXTRACTION_RECEIPT_CHANGED")
        receipt = p.decode(receipt_raw)
        require(all(receipt.get(k) == v for k, v in self._common(case).items() if k != "request_sha256")
                and receipt["runtime_sha256"] == self.pins["runtime_sha256"]
                and receipt["turn"] == case["request"]["turn"] and receipt["upload_id"] == upload["upload_id"]
                and receipt["raw_sha256"] == upload["sha256"] and receipt["text_sha256"] == upload["text_sha256"]
                and receipt["actual_extraction"] is True, "ACTUAL_UPLOAD_RECEIPT_REQUIRED")
        self._protected[protected_receipt] = p.digest(receipt_raw)
        case["protected"].add(protected_receipt)
        case["uploads"][p.digest(upload)] = copy.deepcopy(upload)
        self._record("HOST_UPLOAD_EXTRACTION", case, {"upload_sha256": p.digest(upload)})

    def _terminal(self, current, sha, turn):
        family = current["family"]
        require(type(turn) is int and turn in family["turns"], "FOREIGN_HISTORY_TURN")
        case = family["turns"][turn]
        raw = case["store"].read(f"turn-{turn:04d}/terminal.json")
        require(p.digest(raw) == sha, "TERMINAL_HASH_CHANGED")
        value = p.decode(raw)
        require(value["schema"] == p.VERSION and value["case_id"] == case["request"]["case_id"] and value["request_sha256"] == case["request_sha"]
                and value["policy_sha256"] == self.policy_sha and value["turn"] == turn
                and value["production"] is False and value["training"] is False and self._once is not None
                and value["context_ids_are_custody_proof"] is False
                and value["actual_parent_validation"] == "NOT_ESTABLISHED_BY_PROTOCOL"
                and value["state"] == ("FINAL_RECORDED_AWAITING_BLIND_SCORING" if value["answer"] is not None else "HOLD_FINAL_ATTEMPT_CONSUMED"),
                "TERMINAL_CASE_OR_POLICY_CHANGED")
        require(p.digest(case["store"].read(f"turn-{turn:04d}/request.json")) == case["request_sha"]
                and p.digest(case["store"].read("policy.json")) == self.policy_sha, "TERMINAL_REQUEST_OR_POLICY_CHANGED")
        exact(p.decode(case["store"].read("GLOBAL-MARKER.json")), self._once)
        self._inventory(case, "", value["artifacts"])
        if value["answer"] is not None:
            require(any(r["role"] == "final" and r.get("complete") and r["output"] == value["answer"] for r in case["roles"].values()), "UNOBSERVED_FINAL_ANSWER")
        else:
            require(any(r["kind"] == "final" and case["store"].exists(r["attempt_root"] + "/failure.json")
                        for r, _ in case["operations"].values()), "UNOBSERVED_TERMINAL_HOLD")
        result = {"sha": sha, "answer": copy.deepcopy(value["answer"])}
        if turn in family["terminal"]:
            require(family["terminal"][turn] == result, "IMMUTABLE_TERMINAL_CHANGED")
        else:
            self._record("VERIFIED_CASE_TERMINAL", case, {"turn": turn, "terminal_sha256": sha})
            family["terminal"][turn] = result
        return result

    def register_scoring(self, key, cap, *, protected_receipt, receipt_sha256):
        self._host(key)
        case = self._case(cap)
        require(protected_receipt.startswith("scoring/") and case["request"]["turn"] in case["family"]["terminal"], "TERMINAL_BEFORE_SCORING_REQUIRED")
        raw = self.store.read(protected_receipt)
        require(p.digest(raw) == receipt_sha256, "SCORING_RECEIPT_HASH_CHANGED")
        receipt = p.decode(raw)
        require(all(receipt.get(k) == v for k, v in self._common(case).items())
                and receipt["terminal_sha256"] == case["family"]["terminal"][case["request"]["turn"]]["sha"], "SCORING_RECEIPT_SCOPE_CHANGED")
        require(case["family"]["scored"] in (None, receipt_sha256), "SCORING_ALREADY_CLOSED")
        self._protected[protected_receipt] = receipt_sha256
        case["protected"].add(protected_receipt)
        case["family"]["scored"] = receipt_sha256
        self._record("SCORING_CLOSED", case, {"receipt_sha256": receipt_sha256})
