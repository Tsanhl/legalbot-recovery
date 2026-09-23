"""Concrete host composition with a protected parent-tool observation mailbox.

This process never impersonates functions.web. It asks the active Codex parent
to check generalized queries and perform that tool call, and retains the exact
parent observation before releasing it to the isolated case workflow. Requests
have a bounded wait shared with the broker. No unattended browser/CLI fallback exists.
No bank discovery, weight training, source admission or production pointers.
"""
from __future__ import annotations

import copy
import ctypes
import errno
import os
import re
import threading
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from backend.app.contracts import ContractSchemaRegistry
from backend.app.contracts.query_plan import QueryBudgets
from backend.app.research import ge_auto_index as index
from cryptography.fernet import Fernet

from scripts import ge_auto_case_contracts as contracts
from scripts import ge_auto_case_custody as custody_api
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as bridge
from scripts.ge_auto_case_driver import (
    CODE_FILES,
    CaseDriver,
    CaseSession,
    DriverPins,
    DueTurn,
    FernetArtifactStore,
    GapResolution,
    WebObservation,
)
from scripts.ge_auto_research_intake import parser_binding
from scripts.ge_auto_research_reranker import verified_reranker_identity
from scripts.ge_auto_research_runtime import verified_model_identity
from scripts.ge_auto_role_runtime import CodexRoleRuntime, cli_identity, safe, write_new

VERSION = "legalbot.ge-case-host.v1"
ROOT = Path(__file__).resolve().parents[1]
EMPTY = p.digest([])
PRIVACY_PROMPT = "Check that this query contains only generalized public legal information; HOLD private facts."
PARENT_WAIT_SECONDS = 300


def need(value, code):
    if not value:
        raise RuntimeError(code)


def file_sha(path):
    return p.digest(read_bytes(path))


def read_bytes(path, *, maximum=p.MAX_BYTES):
    """Bounded no-follow read, including owner/marker reads after construction."""
    path = Path(path)
    safe(path, ROOT)
    raw = p.CaseStore(path.parent).read(path.name)
    need(len(raw) <= maximum, "HOST_FILE_SIZE_LIMIT")
    return raw


def publish_parent_response(response_path, value):
    """Atomically publish one parent-observed mailbox response.

    An exclusive atomic rename makes ``response.json`` the commit boundary, so
    the waiting host cannot observe a file between create and write/fsync.
    A failed staging object is retained for diagnosis.
    """
    response_path = Path(response_path)
    safe(response_path, ROOT)
    need(response_path.name == "response.json", "PARENT_RESPONSE_PATH_REQUIRED")
    request_path = response_path.with_name("request.json")
    request_raw = read_bytes(request_path)
    request = p.decode(request_raw)
    raw = p.canonical(value)
    response = p.decode(raw)
    key = p.digest(request)
    need(
        response.get("request_sha256") == key
        and response.get("kind") == request.get("kind")
        and response.get("parent_observed") is True,
        "PARENT_OBSERVATION_BINDING",
    )
    if response_path.exists():
        need(read_bytes(response_path, maximum=3_000_000) == raw, "PARENT_RESPONSE_ALREADY_CHANGED")
        return p.digest(raw)
    need(not response_path.with_name("HOLD.json").exists(), "PARENT_REQUEST_ALREADY_TIMED_OUT")
    staged = response_path.with_name(f"response-{p.digest(raw)}.staged")
    if staged.exists():
        need(read_bytes(staged, maximum=3_000_000) == raw, "PARENT_RESPONSE_STAGE_CHANGED")
    else:
        write_new(staged, raw)
    libc = ctypes.CDLL(None, use_errno=True)
    renamex_np = getattr(libc, "renamex_np", None)
    need(renamex_np is not None, "PARENT_RESPONSE_ATOMIC_NOREPLACE_UNAVAILABLE")
    renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex_np.restype = ctypes.c_int
    result = renamex_np(os.fsencode(staged), os.fsencode(response_path), 0x00000004)
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(response_path)
        raise OSError(code, os.strerror(code), response_path)
    descriptor = os.open(response_path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    need(read_bytes(response_path, maximum=3_000_000) == raw, "PARENT_RESPONSE_COMMIT_CHANGED")
    return p.digest(raw)


def normalize_parent_web_hits(raw_utf8):
    """Project the exact functions.web text into deterministic broker hits."""
    need(isinstance(raw_utf8, str) and raw_utf8, "PARENT_WEB_TEXT_REQUIRED")
    hits = []
    seen = set()
    # Host-rendered search results sometimes attach the separator directly to
    # the final character of a snippet.  A preceding newline is therefore not
    # part of the result boundary; the newline after the separator still is.
    for block in re.split(r"\n?-{20,}\n", raw_utf8):
        lines = block.strip().splitlines()
        if not lines:
            continue
        match = re.fullmatch(r"(?:(.*?)\s+)?\((https://[^)]+)\)", lines[0])
        if match is None:
            continue
        title, url = match.groups()
        if url in seen:
            continue
        seen.add(url)
        hits.append({
            "url": url,
            "title": (title or urlsplit(url).hostname or "Official source")[:500],
            "snippet": "\n".join(lines[1:])[:4000],
        })
    need(hits, "PARENT_WEB_HITS_REQUIRED")
    return hits


def build_parent_web_response(request_path, raw_utf8):
    """Bind normalized hits and the complete parent tool output to one request."""
    request_path = Path(request_path)
    safe(request_path, ROOT)
    request = p.decode(read_bytes(request_path))
    need(request.get("kind") == "web", "PARENT_WEB_REQUEST_REQUIRED")
    key = p.digest(request)
    references = sorted(set(re.findall(r"turn\d+(?:search|fetch|view)\d+", raw_utf8)))
    return {
        "kind": "web",
        "request_sha256": key,
        "parent_observed": True,
        "tool": "functions.web",
        "raw_utf8": raw_utf8,
        "hits": normalize_parent_web_hits(raw_utf8),
        "tool_observation_id": "parent-observed-web-" + key[:12],
        "platform_call_id_available": False,
        "tool_reference_ids": references,
    }


class ParentMailbox:
    """Only a protected host-parent response can complete an actual tool request."""
    def __init__(self, root, *, timeout_seconds=PARENT_WAIT_SECONDS):
        self.root = Path(root)
        safe(self.root, ROOT)
        need(type(timeout_seconds) is int and 1 <= timeout_seconds <= 600, "BOUNDED_HOST_WAIT_REQUIRED")
        self.timeout = timeout_seconds
        self.observations, self.pending = {}, {}
        self.lock = threading.RLock()

    def exchange(self, kind, payload):
        need(kind in ("privacy", "web"), "UNKNOWN_HOST_TOOL_REQUEST")
        request = {"schema": VERSION, "kind": kind, "payload": copy.deepcopy(payload)}
        key = p.digest(request)
        with self.lock:
            if key in self.observations:
                row = self.observations[key]
                need(self.verify_observation(row["response"]), "PARENT_OBSERVATION_CHANGED")
                return copy.deepcopy(row["response"])
            need(key not in self.pending, "UNCHANGED_PARENT_REQUEST_NOT_RETRIED")
            folder = self.root / (kind + "-" + key)
            write_new(folder / "request.json", p.canonical(request))
            print(kind, str(folder / "request.json"), flush=True)
            self.pending[key] = folder
        deadline = time.monotonic() + self.timeout
        while not (folder / "response.json").exists():
            if time.monotonic() >= deadline:
                write_new(folder / "HOLD.json", {"reason": "PARENT_TOOL_TIMEOUT", "request_sha256": key,
                    "automatic_retry": False, "observed_at": datetime.now(UTC).isoformat()})
                raise RuntimeError("PARENT_TOOL_TIMEOUT")
            time.sleep(0.1)
        response_path = folder / "response.json"
        raw = read_bytes(response_path, maximum=3_000_000)
        response = p.decode(raw)
        need(response.get("request_sha256") == key and response.get("kind") == kind
             and response.get("parent_observed") is True, "PARENT_OBSERVATION_BINDING")
        with self.lock:
            self.observations[key] = {"request": request, "response": response, "request_path": str(folder / "request.json"),
                "response_path": str(response_path), "response_sha256": p.digest(raw)}
        return copy.deepcopy(response)

    def verify_observation(self, response):
        """An observed protected response, never trust reloaded worker JSON."""
        row = self.observations.get(response.get("request_sha256")) if isinstance(response, dict) else None
        return (row is not None and row["response"] == response
            and read_bytes(row["request_path"]) == p.canonical(row["request"])
            and p.digest(row["request"]) == response["request_sha256"]
            and file_sha(row["response_path"]) == row["response_sha256"])


class CaseHost:
    """One case family retained in one host process through all due turns."""
    def __init__(self, *, run_id, case_id, case_root, protected_root, mailbox_root,
                 owner_instruction_path, expected_owner_sha256, owner_scope_sha256,
                 global_marker_path, global_marker_sha256, runtime_manifest,
                 baseline_created_at, model=None, provider=None):
        self.root, self.protected = Path(case_root), Path(protected_root)
        self.owner_path, self.marker_path = Path(owner_instruction_path), Path(global_marker_path)
        for path in (self.root, self.protected, self.owner_path, self.marker_path, Path(mailbox_root)):
            safe(path, ROOT)
        need(not self.root.is_relative_to(self.protected) and not self.protected.is_relative_to(self.root), "CASE_HOST_ROOT_COLLISION")
        mailbox = Path(mailbox_root)
        need(not mailbox.is_relative_to(self.root) and not self.root.is_relative_to(mailbox)
             and not self.owner_path.is_relative_to(self.root) and not self.marker_path.is_relative_to(self.root),
             "HOST_CONTROL_INSIDE_CASE_ROOT")
        self.owner_sha, self.owner_scope_sha = expected_owner_sha256, owner_scope_sha256
        self.marker_sha = global_marker_sha256
        self.runtime_manifest = copy.deepcopy(runtime_manifest)
        self.runtime_sha = p.digest(self.runtime_manifest)
        model = self.runtime_manifest["model"] if model is None else model
        provider = self.runtime_manifest["provider"] if provider is None else provider
        self.case_id, self.run_id = case_id, run_id
        p.checked(case_id, p.ID)
        p.checked(run_id, p.ID)
        for sha in (self.owner_sha, self.owner_scope_sha, self.marker_sha):
            p.checked(sha, p.HASH)
        self.created_at = baseline_created_at
        need(isinstance(self.created_at, datetime) and self.created_at.tzinfo is not None, "BASELINE_TIMESTAMP_REQUIRED")
        self.policy = p.FrozenPolicy(run_id, expected_owner_sha256, self.runtime_sha, "EMPTY", EMPTY)
        self.policy_sha = p.digest(self.policy.manifest())
        self._verify_runtime()
        self.owner_bytes()
        self.establish_marker(read_bytes(self.marker_path))
        self.mailbox = ParentMailbox(mailbox_root, timeout_seconds=PARENT_WAIT_SECONDS)
        self.embedding, self.reranker = verified_model_identity(), verified_reranker_identity()
        self.registry = ContractSchemaRegistry.from_project_root(ROOT)
        self.cli = cli_identity()
        self.model, self.provider = model, provider
        need(provider == "openai" and self.runtime_manifest["model"] == model
             and self.runtime_manifest["provider"] == provider
             and self.runtime_manifest["cli_identity"] == self.cli
             and self.runtime_manifest["embedding_identity"] == self.embedding
             and self.runtime_manifest["reranker_identity"] == self.reranker
             and self.runtime_manifest["schema_selection_sha256"] == self.registry.manifest_sha256,
             "FROZEN_HOST_RUNTIME_CHANGED")
        self._verify_runtime()
        self.key, self.fernet = object(), Fernet.generate_key()
        self.session, self.drivers, self.history = None, [], []
        self.host_observations, self.resolutions, self.upload_observations = {}, {}, {}
        self.history_holds, self.last_host_hold = {}, None
        self._turn_lock, self._incomplete_turn = threading.Lock(), False
        from scripts.ge_auto_native_evidence_guard import NativeEvidenceGuard
        self.native_guard = NativeEvidenceGuard(lambda: self.driver, workspace_root=ROOT,
            expected_code_sha256s={name: sha for name, sha in self.runtime_manifest["code_sha256s"].items()
                                  if name.endswith(".py")})
        pins = {"runtime_sha256": self.runtime_sha, "model": model, "provider": provider,
            "cli_identity": self.cli, "role_runtime_sha256": file_sha(ROOT / "scripts/ge_auto_role_runtime.py"),
            "role_callback_sha256": bridge.callback_sha256(CodexRoleRuntime.__call__),
            "parser_sha256": parser_binding(include_legal_tables=True),
            "transport_callback_sha256": bridge.callback_sha256(bridge.fetch_official),
            "parser_callback_sha256": bridge.callback_sha256(bridge.parse_official_capture),
            "index_runtime_sha256": file_sha(ROOT / "backend/app/research/ge_auto_index.py"),
            "embedding_model_sha256": self.embedding["identity_sha256"],
            "index_callback_sha256": bridge.callback_sha256(CaseDriver.index),
            "retrieve_callback_sha256": bridge.callback_sha256(CaseDriver.retrieve),
            "active_owner_reader_sha256": bridge.callback_sha256(self.owner_bytes),
            "query_privacy_sha256": bridge.callback_sha256(self.privacy),
            "global_marker_verifier_sha256": bridge.callback_sha256(self.verify_marker)}
        for root in (self.root, self.protected):
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            safe(root, ROOT)
        self.custody = custody_api.CaseCustody(workspace_root=ROOT, trusted_root=self.protected,
            policy=self.policy, pins=pins, host_key=self.key, active_owner_instruction=self.owner_bytes,
            query_privacy=self.privacy, global_marker_verifier=self.verify_marker)
        # Preserve the audit key only in the role-inaccessible protected root.
        write_new(self.protected / "artifact-encryption.key", self.fernet)

    @property
    def driver(self):
        return self.session.current_driver if self.session is not None else None

    def _verify_runtime(self):
        need(p.digest(self.runtime_manifest) == self.runtime_sha, "HOST_MANIFEST_CHANGED")
        need(self.runtime_manifest["schema"] == VERSION and self.runtime_manifest["training"] is False
             and self.runtime_manifest["production"] is False and self.runtime_manifest["shared_baseline_sources"] == [],
             "EMPTY_NONLIVE_RUNTIME_REQUIRED")
        need(set(CODE_FILES) | {"scripts/ge_auto_case_host.py", "scripts/ge_auto_native_evidence_guard.py"}
             <= set(self.runtime_manifest["code_sha256s"]), "HOST_RUNTIME_INVENTORY_INCOMPLETE")
        for relative, sha in self.runtime_manifest["code_sha256s"].items():
            need(isinstance(relative, str) and not Path(relative).is_absolute()
                 and ".." not in Path(relative).parts and relative.startswith(("scripts/", "backend/app/", "docs/system-design/schemas/")),
                 "HOST_RUNTIME_PATH_SCOPE")
            p.checked(sha, p.HASH)
            need(file_sha(ROOT / relative) == sha, "HOST_CODE_CHANGED")

    def owner_bytes(self):
        raw = read_bytes(self.owner_path)
        need(p.digest(raw) == self.owner_sha, "ACTIVE_OWNER_INSTRUCTION_CHANGED")
        return raw

    def verify_marker(self, binding, raw):
        expected = {"run_id": self.run_id, "policy_sha256": self.policy_sha,
            "baseline_sha256": EMPTY, "runtime_sha256": self.runtime_sha,
            "owner_instruction_sha256": self.owner_sha, "marker_sha256": self.marker_sha}
        return (binding == expected and p.digest(raw) == self.marker_sha
                and read_bytes(self.marker_path) == raw)

    def establish_marker(self, raw):
        self._verify_runtime()
        need(read_bytes(self.marker_path) == raw and p.digest(raw) == self.marker_sha, "GLOBAL_MARKER_CHANGED")
        marker = p.decode(raw)
        need(marker["run_id"] == self.run_id and marker["runtime_sha256"] == self.runtime_sha
             and marker["baseline_sha256"] == EMPTY and marker["training"] is False,
             "GLOBAL_MARKER_SCOPE_CHANGED")
        return True

    def privacy(self, binding, public_query):
        self._verify_runtime()
        need(binding["case_id"] == self.case_id and binding["case_root"] == str(self.root)
             and binding["policy_sha256"] == self.policy_sha and self.driver is not None
             and binding["request_sha256"] == self.driver.request_sha, "PRIVACY_CASE_SCOPE")
        response = self.mailbox.exchange("privacy", {"case_id": self.case_id,
            "case_request_sha256": binding["request_sha256"], "public_query": public_query,
            "question": PRIVACY_PROMPT})
        return (response.get("decision") == "ALLOW" and isinstance(response.get("reason"), str)
                and bool(response["reason"].strip()) and response.get("query_sha256") == p.digest(public_query))

    def service_web(self, request_bytes, reservation):
        self._verify_runtime()
        need(self.driver is not None, "DUE_DRIVER_REQUIRED")
        request = p.decode(request_bytes)
        expected_path = "broker/search-" + p.digest(reservation) + "/request.json"
        need(self.driver.store.read(expected_path) == request_bytes
             and request["reservation_sha256"] == p.digest(reservation)
             and request["context"] == p.decode(p.canonical(asdict(self.custody.bridge_context(self.driver.capability))))
             and request["tool_arguments"] == bridge.search_arguments(request["public_input"]),
             "ACTUAL_BROKER_REQUEST_REQUIRED")
        case = self.custody._case(self.driver.capability)
        recorded, envelope = case["operations"][("search", reservation["input_sha256"])]
        need(recorded == reservation and request["public_input"] == envelope["data"], "ACTUAL_BROKER_RESERVATION_REQUIRED")
        response = self.mailbox.exchange("web", {"case_id": self.case_id,
            "broker_request": request, "broker_request_sha256": p.digest(request_bytes),
            "reservation": reservation})
        need(response.get("tool") == "functions.web" and isinstance(response.get("raw_utf8"), str)
             and response.get("tool_observation_id") and isinstance(response.get("hits"), list), "ACTUAL_WEB_OBSERVATION_REQUIRED")
        observation = WebObservation(response["raw_utf8"], response["hits"],
                                     response["tool_observation_id"], p.canonical(response))
        self.host_observations[p.digest(observation.host_receipt)] = {"response": copy.deepcopy(response),
            "broker_request_sha256": p.digest(request_bytes), "reservation": copy.deepcopy(reservation)}
        return observation

    @staticmethod
    def issue_id_for_queries(queries):
        """Derive issue identity only from the pre-source planner output.

        Source/proposition identity must not create or change the issue that
        retrieval is meant to answer.  The caller still validates jurisdiction,
        date and gap-kind agreement before using this composite issue key.
        """
        need(isinstance(queries, list) and queries, "PRE_SOURCE_ISSUE_QUERIES_REQUIRED")
        for query in queries:
            p.checked(query, p.QUERY)
        return "issue-" + p.digest({"planner_queries": queries})[:32]

    def resolve_gap(self, value):
        need(self.driver is not None and value["request"] == self.driver.request
             and value["planner_receipt"] == self.driver.roles["planner"]
             and value["reviewer_receipt"] == self.driver.roles["reviewer"] and value["baseline_sha256"] == EMPTY,
             "GAP_ROLE_SCOPE_CHANGED")
        prop, planner = value["proposition"], value["planner_receipt"]["output"]
        candidates = [q for q in planner["queries"] if q["jurisdiction"] == prop["jurisdiction"] and q["as_of_date"] == prop["as_of_date"]]
        need(candidates and len({q["kind"] for q in candidates}) == 1, "AMBIGUOUS_GAP_QUERY_KIND_HOLD")
        need(candidates[0]["kind"] != "unsupported_claim", "UNSUPPORTED_CLAIM_REQUIRES_ACTUAL_CLAIM")
        issue = self.issue_id_for_queries(candidates)
        target = {"kind": "PRE_ANSWER_RESEARCH_PROPOSITION", "proposition": prop,
                  "candidate_answer_claim": False, "request_sha256": self.driver.request_sha}
        # Actually execute the explicitly empty shared-baseline lookup. There is
        # no vector query or purported database hit in an empty logical baseline.
        started = datetime.now(UTC).isoformat()
        sources = self.runtime_manifest["shared_baseline_sources"]
        need(sources == [] and p.digest(sources) == EMPTY, "BASELINE_IS_NOT_EMPTY")
        matches = [s for s in sources if s.get("jurisdiction") == prop["jurisdiction"]]
        need(matches == [], "EMPTY_BASELINE_LOOKUP_CHANGED")
        lookup = {"kind": "EXECUTED_FROZEN_EMPTY_BASELINE_LOOKUP", "queries": candidates,
            "request_sha256": self.driver.request_sha, "runtime_sha256": self.runtime_sha,
            "baseline_sha256": EMPTY, "source_count_inspected": len(sources), "matches": matches,
            "database_or_vector_inference_claimed": False, "started_at": started,
            "completed_at": datetime.now(UTC).isoformat(), "function_sha256": bridge.callback_sha256(self.resolve_gap)}
        lookup_path = self.protected / "host-observations" / ("lookup-" + p.digest(lookup) + ".json")
        write_new(lookup_path, p.canonical(lookup))
        missing = tuple({"fact_key": "unresolved-" + p.digest(c)[:24], "affected_issue_ids": [issue],
                         "blocks_definite_conclusion": True} for c in planner["clarifications"])
        fields = {"issue_id": issue, "query_ids": tuple(q["gap_id"] for q in candidates),
            "gap_class": candidates[0]["kind"], "affected_claim_sha256": index.digest(target),
            "existing_retrieval_sha256": p.digest(lookup), "missing_facts": missing,
            "response_disposition": "LIMITED" if missing else "ANSWER", "answer_route": "full_enquiry"}
        receipt = {"kind": "HOST_GAP_RESOLUTION", "resolution": fields, "target": target,
            "lookup_file": str(lookup_path), "lookup_file_sha256": file_sha(lookup_path),
            "clarifications": planner["clarifications"], "conservative_clarification_policy": "ALL_BLOCK_DEFINITE_CONCLUSION",
            "planner_receipt_sha256": value["planner_receipt"]["receipt_sha256"],
            "reviewer_receipt_sha256": value["reviewer_receipt"]["receipt_sha256"]}
        raw = p.canonical(receipt)
        self._save_resolution(raw, "gap")
        return GapResolution(**fields, receipt=raw)

    def _save_resolution(self, raw, kind):
        path = self.protected / "host-observations" / (kind + "-" + p.digest(raw) + ".json")
        write_new(path, raw)
        need(read_bytes(path) == raw, "HOST_RESOLUTION_READBACK_CHANGED")
        self.resolutions[p.digest(raw)] = {"receipt": p.decode(raw), "path": str(path)}

    def host_evidence_verify(self, kind, binding):
        """Closed action/binding checks against this live host's observations."""
        try:
            self._verify_runtime()
            self.owner_bytes()
            base = {"case_root": str(self.root), "protected_host_root": str(self.protected),
                "request_sha256": self.driver.request_sha, "policy_sha256": self.policy_sha}
            fields = {
                "driver_start": {"global_marker_sha256", "owner_instruction_sha256", "pins"},
                "web_observation": {"broker_request_sha256", "reservation", "raw_sha256", "hits_sha256", "tool_call_id", "host_receipt"},
                "gap_resolution": {"resolution", "receipt", "planner_receipt", "proposition", "baseline_sha256"},
                "history_contract_resolution": {"kind", "terminal_sha256", "planner_receipt", "observed_at", "resolution", "receipt", "baseline_sha256", "legal_proposition", "source_approval"},
                "native_reservation_translation": {"protocol_envelope", "protocol_reservation", "native_envelope", "native_reservation"},
            }
            need(kind in fields and set(binding) == set(base) | fields[kind]
                 and all(binding[k] == v for k, v in base.items()), "HOST_EVIDENCE_SCOPE_OR_FIELDS")
            if kind == "driver_start":
                valid = (binding["global_marker_sha256"] == self.marker_sha
                    and binding["owner_instruction_sha256"] == self.owner_sha
                    and binding["pins"] == self.driver.pins.material()
                    and self.establish_marker(read_bytes(self.marker_path)))
            elif kind == "web_observation":
                receipt = binding["host_receipt"]
                observed = self.host_observations.get(p.digest(receipt))
                valid = (observed is not None and observed["response"] == receipt
                    and self.mailbox.verify_observation(receipt)
                    and binding["broker_request_sha256"] == observed["broker_request_sha256"]
                    and binding["reservation"] == observed["reservation"]
                    and binding["raw_sha256"] == p.digest(receipt["raw_utf8"].encode())
                    and binding["hits_sha256"] == p.digest(receipt["hits"])
                    and binding["tool_call_id"] == receipt["tool_observation_id"])
            elif kind in ("gap_resolution", "history_contract_resolution"):
                receipt = binding["receipt"]
                saved = self.resolutions.get(p.digest(receipt))
                lookup = p.decode(read_bytes(receipt["lookup_file"])) if saved is not None else {}
                valid = (saved is not None and saved["receipt"] == receipt
                    and read_bytes(saved["path"]) == p.canonical(receipt)
                    and p.canonical(binding["resolution"]) == p.canonical(receipt["resolution"])
                    and file_sha(receipt["lookup_file"]) == receipt["lookup_file_sha256"]
                    and receipt["resolution"]["existing_retrieval_sha256"] == p.digest(lookup)
                    and lookup["request_sha256"] == self.driver.request_sha and lookup["runtime_sha256"] == self.runtime_sha
                    and lookup["matches"] == [] and lookup["source_count_inspected"] == 0
                    and binding["baseline_sha256"] == lookup["baseline_sha256"] == EMPTY
                    and binding["planner_receipt"] == self.driver.roles["planner"]
                    and receipt["resolution"]["affected_claim_sha256"] == index.digest(receipt["target"]))
                if kind == "gap_resolution":
                    valid = (valid and receipt["kind"] == "HOST_GAP_RESOLUTION"
                        and receipt["target"]["kind"] == "PRE_ANSWER_RESEARCH_PROPOSITION"
                        and receipt["target"]["proposition"] == binding["proposition"]
                        and binding["proposition"] in self.driver.roles["mapper"]["output"]["propositions"]
                        and receipt["reviewer_receipt_sha256"] == self.driver.roles["reviewer"]["receipt_sha256"])
                else:
                    valid = (valid and receipt["kind"] == "HOST_HISTORY_RESOLUTION"
                        and receipt["target"]["kind"] == "POST_TERMINAL_USER_ISSUE"
                        and receipt["terminal_sha256"] == binding["terminal_sha256"] == self.driver.read_terminal()["terminal_sha256"]
                        and binding["kind"] == "POST_TERMINAL_HOST_HISTORY_CONTRACT"
                        and datetime.fromisoformat(binding["observed_at"]) >= datetime.fromisoformat(lookup["completed_at"])
                        and binding["source_approval"] is False and binding["legal_proposition"] is None)
            else:
                target = {key: binding[key] for key in fields[kind]}
                name = self.driver.prefix + "/native-reservation-translation-" + p.digest(target) + ".json"
                pe, pr = target["protocol_envelope"], target["protocol_reservation"]
                pair = self.driver.native_builds[p.digest(pe["data"]["build"])]
                expected = copy.deepcopy(pe)
                expected["data"]["build"] = pair[1]
                recorded = self.custody._case(self.driver.capability)["operations"][("retrieve", p.digest(pe))]
                valid = (recorded == (pr, pe) and pair[0] == pe["data"]["build"]
                    and target["native_envelope"] == expected
                    and target["native_reservation"] == {**pr, "input_sha256": p.digest(expected)}
                    and self.driver.native_observations.get(name) == p.digest(target)
                    and self.custody.store.read(name) == p.canonical(target))
            need(valid, "HOST_EVIDENCE_NOT_OBSERVED")
            self.last_host_hold = None
            return True
        except (KeyError, TypeError, ValueError, RuntimeError, OSError, AttributeError):
            self.last_host_hold = "HOST_EVIDENCE_VERIFICATION_HOLD"
            return False

    def _history_contract(self):
        current = self.driver
        plan = current.roles.get("planner", {}).get("output", {})
        if not plan.get("queries"):
            return None
        query = plan["queries"][0]
        need(query["kind"] != "unsupported_claim", "UNSUPPORTED_CLAIM_REQUIRES_ACTUAL_CLAIM")
        issue = "history-" + p.digest({"request": current.request_sha, "query": query})[:32]
        started = datetime.now(UTC).isoformat()
        sources = self.runtime_manifest["shared_baseline_sources"]
        need(sources == [] and p.digest(sources) == EMPTY, "BASELINE_IS_NOT_EMPTY")
        matches = [source for source in sources if source.get("jurisdiction") == query["jurisdiction"]]
        lookup = {"kind":"EXECUTED_FROZEN_EMPTY_BASELINE_LOOKUP", "query":query,
            "request_sha256":current.request_sha, "runtime_sha256":self.runtime_sha,
            "baseline_sha256":EMPTY, "source_count_inspected":len(sources), "matches":matches,
            "database_or_vector_inference_claimed":False, "started_at":started,
            "completed_at":datetime.now(UTC).isoformat(), "function_sha256":bridge.callback_sha256(self._history_contract)}
        lookup_path = self.protected / "host-observations" / ("history-lookup-" + p.digest(lookup) + ".json")
        write_new(lookup_path, p.canonical(lookup))
        target = {"kind":"POST_TERMINAL_USER_ISSUE", "request_sha256":current.request_sha,
                  "query":query, "candidate_answer_claim":False, "legal_approval":False}
        fields = {"issue_id":issue, "query_ids":(query["gap_id"],), "gap_class":query["kind"],
            "affected_claim_sha256":index.digest(target), "existing_retrieval_sha256":p.digest(lookup),
            "missing_facts":tuple({"fact_key":"unresolved-" + p.digest(c)[:24], "affected_issue_ids":[issue],
                                  "blocks_definite_conclusion":True} for c in plan["clarifications"]),
            "response_disposition":"LIMITED", "answer_route":"full_enquiry"}
        receipt = {"kind":"HOST_HISTORY_RESOLUTION", "resolution":fields, "target":target,
            "lookup_file":str(lookup_path), "lookup_file_sha256":file_sha(lookup_path),
            "terminal_sha256":current.read_terminal()["terminal_sha256"],
            "clarifications":plan["clarifications"], "query_selection":"FIRST_OBSERVED_QUERY_FOR_HISTORY_ONLY"}
        raw = p.canonical(receipt)
        self._save_resolution(raw, "history-gap")
        return self.session.build_history_contract(current.request["turn"],
            resolution=GapResolution(**fields, receipt=raw), observed_at=datetime.now(UTC))

    def _contract_pins(self):
        config = self.runtime_manifest["configuration"]
        return contracts.ContractPins(
            owner_scope_sha256=self.owner_scope_sha, owner_instruction_sha256=self.owner_sha,
            protocol_policy_sha256=self.policy_sha, query_policy_sha256=p.digest(config["query_policy"]),
            qualification_policy_sha256=p.digest(config["research_eligibility_policy"]),
            config_sha256=p.digest(config), runtime_sha256=self.runtime_sha,
            model_sha256=p.digest({"model": self.model, "provider": self.provider, "cli_identity": self.cli,
                                   "remote_weights_digest_available": False}),
            parser_sha256=parser_binding(include_legal_tables=True),
            ocr_sha256=file_sha(ROOT / "scripts/ge_unseen_fixtures.py"),
            chunker_sha256=file_sha(ROOT / "backend/app/ingestion/chunking.py"),
            tokenizer_sha256=file_sha(ROOT / self.embedding["directory"] / "tokenizer.json"),
            embedding_model_sha256=self.embedding["identity_sha256"],
            reranker_model_sha256=self.reranker["identity_sha256"],
            lexical_config_sha256=file_sha(ROOT / "backend/app/retrieval/lancedb.py"),
            vector_schema_sha256=file_sha(ROOT / "backend/app/retrieval/models.py"),
            encrypt_store_sha256=bridge.callback_sha256(FernetArtifactStore.__call__),
            schema_selection_sha256=self.registry.manifest_sha256, candidate_id="candidate-" + self.case_id,
            baseline_generation_id=self.runtime_manifest["baseline_generation_id"],
            baseline_created_at=self.created_at, baseline_sealed_at=self.created_at)

    def extract_upload(self, *, path, upload_id, turn, media_type):
        """Execute the existing PDF/OCR extractor on actual due bytes once."""
        self._verify_runtime()
        need(not self._incomplete_turn and not self._turn_lock.locked()
             and type(turn) is int and turn == len(self.drivers) + 1, "ONLY_DUE_UPLOAD_TURN")
        if self.drivers:
            need(self.drivers[-1].read_terminal()["answer"] is not None, "FOLLOWUP_REQUIRES_ANSWER_TERMINAL")
        path = Path(path)
        safe(path, ROOT)
        p.checked(upload_id, p.ID)
        raw = read_bytes(path, maximum=8_000_000)
        need(raw and media_type in ("application/pdf", "image/png", "text/plain"), "UPLOAD_FORMAT_OR_SIZE")
        initial = {"source_file_sha256": p.digest(raw), "extractor_sha256": file_sha(ROOT / "scripts/ge_unseen_fixtures.py"),
                   "started_at": datetime.now(UTC).isoformat()}
        folder = self.protected / "uploads" / (f"turn-{turn:04d}-" + upload_id)
        write_new(folder / "START.json", p.canonical(initial))
        write_new(folder / "SOURCE.bytes", raw)
        if media_type == "text/plain":
            text = raw.decode("utf-8")
            extraction = {"file_sha256": p.digest(raw), "format": "TEXT", "page_count": 1,
                "pages": [{"text": text, "text_sha256": p.digest(raw), "error": None}],
                "error": None, "method": "EXACT_UTF8_DECODE_NO_OCR"}
        else:
            from scripts.ge_unseen_fixtures import extract_uploads
            fmt = "PDF" if media_type == "application/pdf" else "PNG"
            extraction = extract_uploads([{"path": path.name, "sha256": p.digest(raw), "format": fmt}], path.parent)[0]
        write_new(folder / "EXTRACTION.json", p.canonical(extraction))
        need(extraction.get("error") is None and extraction.get("pages")
             and extraction["file_sha256"] == p.digest(raw)
             and extraction["page_count"] == len(extraction["pages"])
             and all(page.get("error") is None for page in extraction["pages"]), "UPLOAD_EXTRACTION_HOLD")
        text = "\n".join(page["text"] for page in extraction["pages"])
        need(all(p.digest(page["text"].encode()) == page["text_sha256"] for page in extraction["pages"]), "EXTRACTED_TEXT_CHANGED")
        receipt = {"case_root": str(self.root), "index_root": str(self.root / "legal-index"),
            "case_id": self.case_id, "policy_sha256": self.policy_sha, "run_id": self.run_id,
            "baseline_sha256": EMPTY, "lane": "candidate_case_local", "runtime_sha256": self.runtime_sha,
            "turn": turn, "upload_id": upload_id, "raw_sha256": p.digest(raw),
            "text_sha256": p.digest(text.encode()), "parser_sha256": initial["extractor_sha256"],
            "actual_extraction": True, "native_receipt_sha256": file_sha(folder / "EXTRACTION.json"),
            "extraction_result": extraction, "source_file_sha256": p.digest(raw)}
        receipt_raw = p.canonical(receipt)
        receipt_path = folder / "BOUND-EXTRACTION.json"
        write_new(receipt_path, receipt_raw)
        upload = {"upload_id": upload_id, "sha256": p.digest(raw), "media_type": media_type,
                  "text": text, "text_sha256": p.digest(text.encode()), "extraction_sha256": p.digest(receipt_raw)}
        p.checked(upload, p.UPLOAD)
        value = (upload, contracts.UploadEvidence(raw, receipt_raw), receipt_path.relative_to(self.protected).as_posix())
        self.upload_observations[(turn, upload_id)] = copy.deepcopy(value)
        return value

    def run_turn(self, *, question, jurisdictions, as_of_date, uploads=()):
        """Caller supplies only this due turn; no future questions are accepted."""
        need(self._turn_lock.acquire(blocking=False), "CONCURRENT_HOST_TURN_DENIED")
        try:
            need(not self._incomplete_turn, "HOST_TURN_INCOMPLETE_NO_REDISPATCH")
            self._verify_runtime()
            return self._run_turn(question=question, jurisdictions=jurisdictions, as_of_date=as_of_date, uploads=uploads)
        finally:
            self._turn_lock.release()

    def _run_turn(self, *, question, jurisdictions, as_of_date, uploads):
        turn = len(self.drivers) + 1
        need(not isinstance(jurisdictions, str) and isinstance(uploads, tuple | list), "EXPLICIT_DUE_INPUTS_REQUIRED")
        seen = set()
        for value in uploads:
            need(isinstance(value, tuple | list) and len(value) == 3, "ACTUAL_DUE_UPLOAD_REQUIRED")
            upload, evidence, relative = value
            identity = (turn, upload["upload_id"])
            need(identity not in seen and self.upload_observations.get(identity) == tuple(value)
                 and read_bytes(self.protected / relative) == evidence.extraction_receipt,
                 "UNOBSERVED_OR_CHANGED_DUE_UPLOAD")
            seen.add(identity)
        history = [{"turn": n, "request_sha256": d.request_sha,
                    "terminal_sha256": d.read_terminal()["terminal_sha256"]} for n, d in enumerate(self.drivers, 1)]
        request = {"schema": p.VERSION, "case_id": self.case_id, "turn": turn,
            "question": question, "jurisdictions": list(jurisdictions), "as_of_date": as_of_date,
            "due_uploads": [u[0] for u in uploads], "history": history}
        p.checked(request, p.REQUEST_SCHEMA)
        self._incomplete_turn = True
        cap = self.custody.issue_case(self.key, case_root=self.root, request=request)
        runtime = CodexRoleRuntime(case_root=self.root, protected_root=self.protected,
            model=self.model, provider=self.provider, expected_cli=self.cli, capability=cap, verify=self.custody.role_guard)
        cp = self._contract_pins()
        pins = DriverPins(cp, self.embedding, self.reranker,
            {name: self.runtime_manifest["code_sha256s"][name] for name in CODE_FILES},
            bridge.callback_sha256(self.host_evidence_verify), bridge.callback_sha256(self.native_guard.verify),
            bridge.callback_sha256(self.resolve_gap), bridge.callback_sha256(self.service_web),
            bridge.callback_sha256(self.establish_marker))
        evidence = {u[0]["upload_id"]: u[1] for u in uploads}
        receipt_paths = {u[0]["upload_id"]: u[2] for u in uploads}
        observed = datetime.now(UTC)
        if self.session is None:
            self.session = CaseSession(dict(workspace_root=ROOT, case_root=self.root, protected_host_root=self.protected,
                request=request, due_uploads=evidence, upload_receipt_paths=receipt_paths, ordered_history=(),
                policy=self.policy, pins=pins, registry=self.registry, custody=self.custody, host_key=self.key,
                capability=cap, role_runtime=runtime, fernet_key=self.fernet,
                global_marker_bytes=read_bytes(self.marker_path), establish_global_marker=self.establish_marker,
                service_web=self.service_web, resolve_gap=self.resolve_gap, host_evidence_verify=self.host_evidence_verify,
                native_index_verify=self.native_guard.verify, observed_at=observed,
                query_budgets=QueryBudgets(**self.runtime_manifest["configuration"]["query_budgets"]),
                web_timeout_seconds=PARENT_WAIT_SECONDS))
            result = self.session.runturn(active_owner_instruction_bytes=self.owner_bytes())
        else:
            result = self.session.runturn(active_owner_instruction_bytes=self.owner_bytes(), due=DueTurn(
                request, evidence, receipt_paths, tuple(self.history), cap, runtime, observed))
        current = self.driver
        self.drivers.append(current)
        self._incomplete_turn = False
        try:
            bound = current.read_contracts()
            if not bound and result.get("answer") is not None:
                previous = self._history_contract()
                if previous is not None:
                    bound = current.read_contracts()
            if bound:
                previous = next(iter(bound.values()))
                self.history.append(contracts.PriorTurn(current.request, current.terminal_bytes,
                    previous, previous.artifact_lineage["content_sha256"]))
            else:
                raise RuntimeError("TECHNICAL_PRIOR_CONTRACT_SNAPSHOT_MISSING")
        except (ValueError, RuntimeError, OSError, KeyError, TypeError) as exc:
            # The sealed one-pass answer remains the exact returned terminal.
            # History-only preparation cannot relabel it a model/legal failure.
            code = str(exc) if type(exc) in (RuntimeError, contracts.ContractBuildError, p.ActionHold) else type(exc).__name__
            row = {"turn": turn, "terminal_sha256": result["terminal_sha256"],
                "kind": "POST_TERMINAL_HISTORY_HOLD", "code": code,
                "terminal_changed": False, "automatic_retry": False}
            self.history_holds[turn] = row
            write_new(self.protected / "host-observations" / f"history-hold-{turn:04d}.json", p.canonical(row))
        return result

    def read_answer_projection(self):
        """Exact deterministic rendering for candidate/substantive review."""
        need(self.driver is not None, "OBSERVED_DRIVER_REQUIRED")
        terminal = self.driver.read_terminal()
        text = terminal["rendered_answer"]
        need((text is None and terminal["answer"] is None and terminal["rendered_answer_sha256"] is None)
             or (isinstance(text, str) and p.digest(text.encode("utf-8")) == terminal["rendered_answer_sha256"]),
             "RENDERED_ANSWER_CHANGED")
        return text

    def read_selected_retrieval_contracts(self):
        """Expose the actual current turn's selected backend contracts read-only."""
        need(self.driver is not None, "OBSERVED_DRIVER_REQUIRED")
        return self.driver.read_selected_retrieval_contracts()

    def read_fact_projection(self):
        """Expose only the exact candidate-visible facts bound to MatterFactSnapshot."""
        need(self.driver is not None, "OBSERVED_DRIVER_REQUIRED")
        return self.driver.read_fact_projection()

    def read_answer_review_material(self):
        """Expose the current turn's exact post-terminal review projection."""
        need(self.driver is not None, "OBSERVED_DRIVER_REQUIRED")
        return self.driver.read_answer_review_material()


def runtime_manifest(*, model, provider):
    """Resolve exact installed bytes and actual selected configuration; no inference."""
    names = set(CODE_FILES) | {"scripts/ge_auto_case_host.py", "scripts/ge_auto_native_evidence_guard.py",
        "scripts/ge_unseen_fixtures.py", "backend/app/retrieval/lancedb.py", "backend/app/retrieval/models.py",
        "scripts/model/manifests/qwen3-retrieval-models.json"}
    names.update(str(path.relative_to(ROOT)) for path in (ROOT / "docs/system-design/schemas").glob("*.schema.json"))
    return {"schema": VERSION, "model": model, "provider": provider, "cli_identity": cli_identity(),
        "code_sha256s": {name: file_sha(ROOT / name) for name in sorted(names)},
        "embedding_identity": verified_model_identity(), "reranker_identity": verified_reranker_identity(),
        "schema_selection_sha256": ContractSchemaRegistry.from_project_root(ROOT).manifest_sha256,
        "shared_baseline_sources": [], "baseline_generation_id": "ge-case-local-empty-baseline-v1",
        "configuration": {"query_policy": {"queries":4, "captures":8, "final_attempts":1, "case_local_only":True},
            "research_eligibility_policy": {"source_checks":list(p.SOURCE_CHECKS), "proposition_checks":list(p.PROPOSITION_CHECKS),
                "reviewer_kind":"AI_MODEL_REVIEWER", "professional_sign_off":False, "production_admission":False},
            "query_budgets":asdict(QueryBudgets(reranker_candidates=8, final_top_k=8)),
            "currentness_unknown":"HOLD", "training":False, "no_unseen_feedback_reuse":True},
        "remote_weights_digest_available":False, "training":False, "production":False}
