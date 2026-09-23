"""Synthetic guard tests: no bank, model, network, disk artifacts or deletion.

Real selected contracts, parser-ledger reconstruction, source translation and
structural chunk reconstruction execute on synthetic text. SQLite uses :memory:.
Lance/session/OS execution dependencies are explicit test doubles where needed;
these tests do not establish actual inference, custody isolation or legal quality.
"""
from __future__ import annotations

import ast
import copy
import inspect
import sqlite3
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from backend.app.contracts.schema_registry import ContractSchemaRegistry, canonical_json_bytes
from backend.app.research import ge_auto_index as r
from backend.tests import test_ge_auto_case_contracts as cf
from backend.tests import test_ge_auto_case_driver as df
from backend.tests.test_ge_auto_case_custody import MemoryStore
from backend.tests.test_ge_auto_case_index_adapter import MemoryIndex
from scripts import ge_auto_case_contracts as c
from scripts import ge_auto_case_custody as custody
from scripts import ge_auto_case_driver as driver
from scripts import ge_auto_case_index_adapter as a
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as bridge
from scripts import ge_auto_native_evidence_guard as g
from scripts import ge_auto_research_runtime as runtime
from scripts.ge_auto_role_runtime import CodexRoleRuntime

ROOT = Path(__file__).resolve().parents[2]
H = p.digest(b"synthetic-native-guard-only")


def code_pins():
    return {name: p.digest((ROOT / name).read_bytes()) for name in (*driver.CODE_FILES, g.GUARD_FILE)}


def make_guard(getter=lambda: None):
    return g.NativeEvidenceGuard(getter, workspace_root=ROOT, expected_code_sha256s=code_pins())


def observe(d, kind, value):
    name = "driver/" + d.request_sha + "/" + kind + "-" + p.digest(value) + ".json"
    raw = p.canonical(value)
    d.host_store.files[name] = raw
    d.native_observations[name] = p.digest(raw)
    return name


@pytest.fixture(scope="module")
def registry():
    return ContractSchemaRegistry.from_project_root(ROOT)


@pytest.fixture
def sample(registry):
    guard = make_guard()
    args = cf.arguments(registry)
    actual = c.build_case_contracts(**args)
    kwargs, base = df.ledger_fixture()
    prop = df.proposition(kwargs["original"])
    cap, mapping = driver.capture_from_ledger(**kwargs)
    covered = driver.complete_reviewed_blocks(prop, kwargs["original"], mapping)
    source = a.SourceBinding(cap, mapping, covered)
    sr = kwargs["source_review"]
    reviewed = {"sources": [sr], "propositions": [{"proposition_id": prop["proposition_id"],
        "proposition_sha256": p.digest(prop), "decision": "ELIGIBLE", "checks": dict.fromkeys(p.PROPOSITION_CHECKS, True), "holds": []}]}
    roles = {role: {"context_id": "synthetic-" + role, "input_sha256": H, "receipt_sha256": H,
                   "output": output} for role, output in {
        "planner": {"queries": [], "clarifications": [], "holds": []},
        "selector": {"urls": [kwargs["original"]["canonical_url"]], "holds": []},
        "mapper": {"propositions": [prop], "holds": []}, "reviewer": reviewed}.items()}
    review = a.ReviewBinding(roles["reviewer"], roles["mapper"]["context_id"], H, roles["selector"]["context_id"], H)
    # Correct fixture researcher is distinct from fresh reviewer; rights bind the
    # exact synthetic review output. No official-source assertion is tested.
    original = kwargs["original"]
    reservation = {"kind": "capture", "input_sha256": H, "fixture": "memory-only"}
    # Existing synthetic ledger's reservation is intentionally used unchanged.
    reservation = kwargs["reservation"] | {"input_sha256": H}
    # Rebind this synthetic reservation in memory, preserving the parser bytes.
    new_base = "broker/capture-" + p.digest(reservation)
    for name, raw in tuple(kwargs["store"].files.items()):
        if name.startswith(base + "/"):
            kwargs["store"].files[new_base + name[len(base):]] = raw
    parsed_receipt = p.decode(kwargs["store"].files[new_base + "/parser-receipt.json"])
    parsed_receipt["reservation_sha256"] = p.digest(reservation)
    kwargs["store"].files[new_base + "/parser-receipt.json"] = p.canonical(parsed_receipt)
    original["parser_receipt_sha256"] = p.digest(parsed_receipt)
    kwargs.update(reservation=reservation, original=original, researcher_id="synthetic-selector",
                  reviewer_receipt_sha256=H)
    cap, mapping = driver.capture_from_ledger(**kwargs)
    source = a.SourceBinding(cap, mapping, covered)
    d = NS(request=args["request"], request_sha=args["request_sha256"], root=kwargs["store"].root,
           store=kwargs["store"], host_store=MemoryStore(ROOT / "synthetic-guard-protected"),
           native_observations={}, roles=roles, contracts={prop["proposition_id"]: actual}, translated_reviews={})
    d.pins = NS(contract=replace(args["pins"], parser_sha256=original["parser_sha256"]))
    # Use actual contract pins for contract checks; parser-binding assertion is
    # checked in a separate source fixture adjustment below.
    args["pins"] = d.pins.contract
    actual = c.build_case_contracts(**args)
    d.contracts = {prop["proposition_id"]: actual}
    d.native_adapter = NS(bindings={prop["proposition_id"]: a.PropositionBinding(actual.binding, (source,))},
                          scope=cap.scope, review=review)
    obs = {"reservation": reservation, "capture": original, "researcher_id": "synthetic-selector"}
    d.captures = {r.digest(cap.raw): obs}
    legal = {"case_id": d.request["case_id"], "lane": "candidate_case_local",
        "lineage": {"request_sha256": d.request_sha, "policy_sha256": args["pins"].protocol_policy_sha256},
        "baseline_sha256": a.EMPTY, "baseline_kind": "EMPTY", "own_prior_generations": [],
        "sources": [original], "propositions": [prop], "review_sha256": p.digest(reviewed),
        "public_queries": [{"query": "Synthetic public query", "jurisdiction": "England", "as_of_date": "2026-09-05"}]}
    state = g._Turn(d, d.native_adapter, b"synthetic", legal=legal, operation=({"kind": "index"}, {"data": legal}))
    bound = a.bind_contracts(actual.binding, request_sha256=d.request_sha)
    translated = a.translate_review(source=source, original=original, proposition=prop, review=review,
                                    contracts=actual.binding, lineage=bound, scope=cap.scope)
    d.translated_reviews[r.digest(translated)] = translated
    observe(d, "contracts", {"proposition_sha256": p.digest(prop), "artifact_lineage": actual.artifact_lineage,
                              "gap_receipt_sha256": H})
    observe(d, "capture", obs)
    capture_record = {"source_sha256": r.digest(cap.raw), "parsed_sha256": p.digest(original["parts"]),
                      "parse_binding": {"parser_receipt_sha256": original["parser_receipt_sha256"]}}
    case = {"request": d.request, "root": d.root, "request_sha": d.request_sha, "protected": set(),
            "capture": {p.digest(reservation): capture_record},
            "operations": {("capture", H): (reservation, {"synthetic-input": True})},
            "outputs": {("capture", H): p.digest(original)},
            "roles": {"synthetic-selector": {"role": "selector", "complete": True}}}
    case["family"] = {"turns": {1: case}, "terminal": {}}
    d.capability = object()
    d.custody = NS(_case=lambda cap0: case, _check_protected=lambda case0: None,
                  _find_operation=lambda case0, kind, key, sha: case0["operations"][(kind, key)])
    return NS(guard=guard, d=d, state=state, actual=actual, source=source, prop=prop, original=original,
              capture_record=capture_record, case=case, base=new_base, translated=translated, args=args)


def test_constructor_is_lazy_frozen_and_bound_method_hashable():
    calls = []
    pins = code_pins()
    guard = g.NativeEvidenceGuard(lambda: calls.append(True), workspace_root=ROOT, expected_code_sha256s=pins)
    assert calls == [] and len(bridge.callback_sha256(guard.verify)) == 64
    pins[g.GUARD_FILE] = H
    assert guard.expected_code_sha256s[g.GUARD_FILE] != H
    with pytest.raises(TypeError):
        guard.expected_code_sha256s[g.GUARD_FILE] = H


@pytest.mark.parametrize("missing", [g.GUARD_FILE, "scripts/ge_auto_case_driver.py", "backend/app/research/ge_auto_index.py"])
def test_missing_transitive_pin_refused(missing):
    pins = code_pins()
    pins.pop(missing)
    with pytest.raises(g.EvidenceHold, match="ALL_CODE_PINS"):
        g.NativeEvidenceGuard(lambda: None, workspace_root=ROOT, expected_code_sha256s=pins)


def test_adapter_action_inventory_is_exact_not_invented():
    tree = ast.parse((ROOT / "scripts/ge_auto_case_index_adapter.py").read_bytes())
    actions = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute) and node.func.attr == "_verify"
               and node.args and isinstance(node.args[0], ast.Constant)}
    assert actions == set(g.ACTION_FIELDS)
    assert len(actions) == 14
    assert len(actions) + (3 - 1) + (2 - 1) == 17


@pytest.mark.parametrize("action", list(g.ACTION_FIELDS))
@pytest.mark.parametrize("mutation", ["extra", "missing"])
def test_every_action_rejects_extra_or_missing_fields_before_getter(action, mutation):
    calls = []
    guard = make_guard(lambda: calls.append(True))
    value = dict.fromkeys(g.COMMON_FIELDS | g.ACTION_FIELDS[action], None)
    value["action"] = action
    if mutation == "extra":
        value["all_checks_passed"] = True
    else:
        value.pop("non_live")
    assert guard.verify(value) is False and calls == []
    assert guard.last_hold == "EXACT_FIELDS_REQUIRED"


@pytest.mark.parametrize("value", [None, True, {}, {"action": "close_gap"}, {"action": []}])
def test_unknown_actions_fail_without_getter(value):
    guard = make_guard(lambda: pytest.fail("getter must not run"))
    assert guard.verify(value) is False


def test_self_sealed_protected_record_cannot_bootstrap_observation(sample):
    d, guard = sample.d, sample.guard
    value = {"job": {"fabricated": True}}
    name = observe(d, "reranker", value)
    guard._record(d, "reranker", value)
    d.native_observations.pop(name)
    with pytest.raises(g.EvidenceHold, match="PROCESS_OBSERVED"):
        guard._record(d, "reranker", value)


def test_changed_observed_protected_bytes_hold(sample):
    name = observe(sample.d, "reranker", {"synthetic": True})
    sample.d.host_store.files[name] += b" "
    with pytest.raises(g.EvidenceHold, match="OBSERVATION_CHANGED"):
        sample.guard._records(sample.d, "reranker")


def test_actual_contract_and_source_translation_reconstructed(sample):
    x = sample
    b, lineage, translated = x.guard._source(x.d, x.state, x.prop["proposition_id"], x.source)
    assert b is x.actual.binding and lineage == asdict(a.bind_contracts(b, request_sha256=x.d.request_sha))
    assert translated == x.translated
    assert translated["context_block_ordinals"] == list(x.source.reviewed_block_ordinals)


@pytest.mark.parametrize("name", ["query_plan", "fact_snapshot", "conversation_snapshot", "knowledge_generation"])
def test_actual_contract_hash_mutation_holds(sample, name):
    x = sample
    getattr(x.actual.binding, name)["content_sha256"] = H
    with pytest.raises(g.EvidenceHold, match="CONTRACT_HASH_CHANGED"):
        x.guard._contract(x.d, x.state, x.prop["proposition_id"])


@pytest.mark.parametrize("name", ["raw.bytes", "parse-manifest.json", "parts.json", "parser-receipt.json", "transport.json"])
def test_raw_parser_ledger_tamper_not_reapproved(sample, name):
    x = sample
    x.d.store.files[x.base + "/" + name] += b"changed"
    with pytest.raises((g.EvidenceHold, driver.DriverHold)):
        x.guard._source(x.d, x.state, x.prop["proposition_id"], x.source)


def test_translation_cannot_be_replaced_with_boolean_all_pass(sample):
    x = sample
    x.d.translated_reviews[r.digest(x.translated)] = {"all_pass": True}
    with pytest.raises(g.EvidenceHold, match="ACTUAL_TRANSLATION_CHANGED"):
        x.guard._source(x.d, x.state, x.prop["proposition_id"], x.source)


def test_unreviewed_parent_coverage_is_not_silently_expanded(sample):
    x = sample
    source = replace(x.source, reviewed_block_ordinals=x.source.reviewed_block_ordinals[1:])
    with pytest.raises(g.EvidenceHold, match="REVIEWED_COVERAGE_CHANGED"):
        x.guard._source(x.d, x.state, x.prop["proposition_id"], source)


def test_own_prior_capture_uses_original_observation_and_researcher(sample):
    x = sample
    old = x.case
    current = {**old, "request": {**old["request"], "turn": 2}, "capture": {}, "operations": {}, "roles": {}, "outputs": {}}
    family = {"turns": {1: old, 2: current}, "terminal": {1: {"synthetic": True}}}
    old["family"] = current["family"] = family
    x.d.request = current["request"]
    x.d.custody._case = lambda cap: current
    # Original driver capture JSON may be outside the current prefix. The real
    # custody family observation and stored reservation/output remain necessary.
    x.d.native_observations.clear()
    obs = next(iter(x.d.captures.values()))
    assert x.guard._capture_observation(x.d, obs) == x.capture_record
    old["roles"][obs["researcher_id"]]["complete"] = False
    with pytest.raises(g.EvidenceHold, match="RESEARCHER_CHANGED"):
        x.guard._capture_observation(x.d, obs)


def inference(texts, kind="document"):
    return {"schema": "legalbot.ge-auto-research-embedding-inference.v1", "model_identity": {"identity_sha256": H},
        "calls": [{"kind": kind, "text_sha256": p.digest(t.encode()), "tokens": 3, "vector_sha256": H, "seconds": 0.01}
                  for t in texts], "actual_inference_calls": len(texts), "training": False,
        "provider": "PINNED_LOCAL_QWEN", "synthetic_vectors": False}


@pytest.mark.parametrize("change", ["count", "kind", "text", "tokens", "vector", "training", "identity", "extra", "nan"])
def test_inference_each_call_and_pin_is_bound(change):
    value = inference(["Synthetic text"])
    if change == "count":
        value["actual_inference_calls"] = True
    elif change == "kind":
        value["calls"][0]["kind"] = "query"
    elif change == "text":
        value["calls"][0]["text_sha256"] = H
    elif change == "tokens":
        value["calls"][0]["tokens"] = 2049
    elif change == "vector":
        value["calls"][0]["vector_sha256"] = "fake"
    elif change == "training":
        value["training"] = True
    elif change == "identity":
        value["model_identity"] = {}
    elif change == "extra":
        value["calls"][0]["approved"] = True
    else:
        value["calls"][0]["seconds"] = float("nan")
    with pytest.raises(g.EvidenceHold):
        g.NativeEvidenceGuard._inference(value, {"identity_sha256": H}, "document", ["Synthetic text"])


def test_inference_schema_accepts_exact_per_text_calls_and_rejects_wrong_order():
    value = inference(["A", "B"])
    g.NativeEvidenceGuard._inference(value, value["model_identity"], "document", ["A", "B"])
    with pytest.raises(g.EvidenceHold, match="CALL_BINDING"):
        g.NativeEvidenceGuard._inference(value, value["model_identity"], "document", ["B", "A"])


def test_persisted_inference_requires_live_observation_and_closed_unchanged_session(sample):
    x = sample
    value = inference(["A"])
    x.d.native_adapter._get = lambda sha: copy.deepcopy(value)
    with pytest.raises(g.EvidenceHold, match="UNOBSERVED_INFERENCE"):
        x.guard._observed_inference(x.d, x.state, value, "document", H)
    session = NS(provider=object(), lock=None, receipt=lambda: copy.deepcopy(value))
    x.state.inferences[p.digest(value)] = (copy.deepcopy(value), session, "document", H)
    with pytest.raises(g.EvidenceHold, match="STILL_OPEN"):
        x.guard._observed_inference(x.d, x.state, value, "document", H)
    session.provider = None
    assert x.guard._observed_inference(x.d, x.state, value, "document", H) == p.digest(value)
    session.receipt = lambda: {**value, "actual_inference_calls": 999}
    with pytest.raises(g.EvidenceHold, match="CLOSED_SESSION_RECEIPT_CHANGED"):
        x.guard._observed_inference(x.d, x.state, value, "document", H)


def test_embedding_receipt_direct_call_is_not_a_live_session(sample):
    with pytest.raises(g.EvidenceHold, match="LIVE_MODEL_RECEIPT_CALL"):
        sample.guard._embedding(sample.d, sample.state, inference(["A"]), inspect.currentframe())


def rows():
    prepared = [{"id": str(i), "text": "Synthetic " + str(i), "jurisdiction": "England",
                 "valid_from": "2026-09-05", "valid_to": "2026-09-05", "group": "A" if i < 2 else "B"}
                for i in range(3)]
    native = [{**{k: row[k] for k in ("id", "text", "jurisdiction", "valid_from", "valid_to")},
               "vector": [1.0] + [0.0] * 1023, "binding_json": canonical_json_bytes(row).decode()} for row in prepared]
    return prepared, native


@pytest.mark.parametrize("change", ["id", "text", "span", "vector", "duplicate", "flag"])
def test_lance_readback_is_not_satisfied_by_a_self_resealed_manifest(change):
    prepared, native = rows()
    if change == "id":
        native[0]["id"] = "unknown"
    elif change == "text":
        native[0]["text"] = "fabricated condition"
    elif change == "span":
        native[0]["binding_json"] = canonical_json_bytes({**prepared[0], "group": "B"}).decode()
    elif change == "vector":
        native[0]["vector"] = [0.0] * 1024
    elif change == "duplicate":
        native[1] = copy.deepcopy(native[0])
    else:
        native[0]["admitted"] = True
    with pytest.raises(g.EvidenceHold):
        g.NativeEvidenceGuard._row_bindings(native, prepared, r.digest(sorted(native, key=lambda row: row["id"])))


def test_lance_row_binding_full_exact_readback():
    prepared, native = rows()
    g.NativeEvidenceGuard._row_bindings(native, prepared, r.digest(native))


def test_complete_row_groups_required_not_just_hit_count():
    prepared, native = rows()
    receipt = {"lexical_ids": ["0"], "vector_ids": ["0"], "selected_ids": ["0"],
               "evidence": prepared[:2], "lineage": {"jurisdiction": "England", "as_of_date": "2026-09-05"}}
    g.NativeEvidenceGuard._retrieval_rows(receipt, prepared, native)
    receipt["evidence"] = prepared[:1]
    with pytest.raises(g.EvidenceHold, match="GROUP_CONTEXT_CHANGED"):
        g.NativeEvidenceGuard._retrieval_rows(receipt, prepared, native)
    receipt["evidence"] = prepared
    with pytest.raises(g.EvidenceHold, match="GROUP_CONTEXT_CHANGED"):
        g.NativeEvidenceGuard._retrieval_rows(receipt, prepared, native)


def test_missing_companion_source_is_held_across_all_persisted_queries(sample, monkeypatch):
    x = sample
    prepared, native = rows()
    build = {"rows": prepared, "lineage": {"jurisdiction": "England", "as_of_date": "2026-09-05"},
             "reviews": [{"quote": "Synthetic public query"}]}
    gen = {"generation_sha256": H}
    x.d.pins = NS(contract=NS(candidate_id="candidate-synthetic"))
    monkeypatch.setattr(x.guard, "_generation", lambda *args: ("synthetic-p", build, gen, native))
    receipt = {"schema": "legalbot.ge-auto-index-retrieval.v1", "scope": asdict(x.d.native_adapter.scope),
        "lineage": build["lineage"], "build_sha256": H, "generation_sha256": H,
        "query_sha256": p.digest(b"Synthetic public query"),
        "retrieval_runtime_sha256": x.guard.expected_code_sha256s["backend/app/research/ge_auto_index.py"],
        "selected_ids": ["0"], "evidence": prepared[:2], "retriever_id": "candidate-synthetic",
        "lexical_ids": ["0"], "vector_ids": ["0"]}
    monkeypatch.setattr(x.guard, "_sqlite", lambda *args: copy.deepcopy(receipt))
    with pytest.raises(g.EvidenceHold, match="FULL_PREPARED_CONTEXT_NOT_RETRIEVED"):
        x.guard._retrievals(x.d, x.state, [receipt], H)


def test_sqlite_actual_query_rehash_and_read_only_mode(sample, monkeypatch):
    x = sample
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE objects (digest TEXT PRIMARY KEY, kind TEXT, payload BLOB)")
    raw = canonical_json_bytes({"synthetic": "payload"})
    sha = r.digest(raw)
    db.execute("INSERT INTO objects VALUES (?,?,?)", (sha, "prepared_build", raw))
    calls = []
    # Real SQLite SQL/readback, memory-only connection, explicitly no disk store.
    class Connection:
        execute = db.execute
        def close(self):
            calls.append("closed")
    def connect(path, *, uri, timeout):
        calls.append((path, uri, timeout))
        return Connection()
    monkeypatch.setattr(g, "_safe", lambda path, root, **kw: Path(path))
    monkeypatch.setattr(g.sqlite3, "connect", connect)
    assert x.guard._sqlite_raw(x.d, sha, "prepared_build") == raw
    assert calls[0][0].endswith("metadata.sqlite3?mode=ro") and calls[-1] == "closed"
    with pytest.raises(g.EvidenceHold, match="SQLITE_OBJECT"):
        x.guard._sqlite_raw(x.d, sha, "generation")
    db.execute("PRAGMA query_only=OFF")
    db.execute("UPDATE objects SET payload=? WHERE digest=?", (b"tampered", sha))
    with pytest.raises(g.EvidenceHold, match="SQLITE_OBJECT"):
        x.guard._sqlite_raw(x.d, sha, "prepared_build")
    db.close()


def test_native_lance_path_and_count_readback(sample, monkeypatch):
    import lancedb
    calls = []
    _, native = rows()
    table = NS(count_rows=lambda: len(native), to_arrow=lambda: NS(to_pylist=lambda: native))
    connection = NS(open_table=lambda name: calls.append(name) or table)
    monkeypatch.setattr(lancedb, "connect", lambda path: calls.append(path) or connection)
    root = sample.d.root / "legal-index/builds/ge-auto-synthetic"
    assert sample.guard._lance_rows(root, len(native)) == native
    assert calls == [str(root / "lance/authority"), "chunks"]
    with pytest.raises(g.EvidenceHold, match="LANCE_ROW_COUNT_CHANGED"):
        sample.guard._lance_rows(root, len(native) + 1)


def test_each_action_requires_observed_reservation(sample):
    x = sample
    x.state.operation = None
    for action in g.ACTION_FIELDS:
        if action != "protocol_reservation":
            with pytest.raises(g.EvidenceHold, match="ACTUAL_RESERVATION_REQUIRED_FIRST"):
                x.guard._dispatch(x.d, x.state, action, {}, None)


def test_unknown_capability_and_self_sealed_reservation_deny(sample):
    x = sample
    with pytest.raises(g.EvidenceHold, match="UNKNOWN_INDEX_CAPABILITY"):
        x.guard._dispatch(x.d, x.state, "capability", {"index_action": "close_gap", "binding_sha256": H}, None)
    reservation = {"case_id": x.d.request["case_id"], "request_sha256": x.d.request_sha, "policy_sha256": H,
                   "kind": "index", "attempt": 1, "input_sha256": H, "budget": None,
                   "attempt_root": "operations/index-" + H + "/attempt-1"}
    with pytest.raises(g.EvidenceHold, match="OBSERVED_PROTOCOL_RESERVATION"):
        x.guard._reservation(x.d, x.state, {"envelope_sha256": H, "reservation": reservation})


def role_observations(x):
    """Deliberately synthetic protected execution records for verifier tests."""
    d, guard, case = x.d, x.guard, x.case
    d.protected = d.host_store.root
    d.runtime = NS(receipts={})
    d.custody.pins = {"model": "synthetic-model", "provider": "synthetic-provider", "cli_identity": {"synthetic": H}}
    d.custody._protected = {}
    d.custody._inventory = lambda own, relative, inventory: custody.CaseCustody._inventory(d.custody, own, relative, inventory)
    case["store"] = d.store
    for role, receipt in d.roles.items():
        context = receipt["context_id"]
        relative = "roles/" + context
        input_raw = p.canonical({"synthetic-role-input": role})
        d.store.files[relative + "/input.json"] = input_raw
        inventory = {"input.json": p.digest(input_raw)}
        receipt["input_sha256"] = p.digest(input_raw)
        record = {"role": role, "input_sha256": receipt["input_sha256"], "launched": True, "complete": True,
                  "job_root": str(d.root / relative), "relative": relative, "inventory": inventory, "profile_sha256": H}
        start = {"case_root": str(d.root), "job_root": record["job_root"], "role": role, "context_id": context,
            "input_sha256": receipt["input_sha256"], **d.custody.pins, "browse": False, "fresh_context": True,
            "runtime_file_sha256": guard.expected_code_sha256s["scripts/ge_auto_role_runtime.py"],
            "training": False, "input_inventory": inventory, "started": "2026-09-05T00:00:00+00:00",
            "fence": {"own_exact_input_readable": True, "outside_public_file_denied": True,
                "input_write_open_denied": True, "private_bank_probe": "NOT_ATTEMPTED", "profile_sha256": H}}
        output_raw = p.canonical(receipt["output"])
        d.store.files[relative + "/output.json"] = output_raw
        stdout = b"Synthetic output log"
        stderr = b"model: synthetic-model\nprovider: synthetic-provider\n"
        complete = {**start, "start_sha256": p.digest(start), "completed": "2026-09-05T00:00:01+00:00",
            "returncode": 0, "error": None, "output_sha256": p.digest(output_raw),
            "stdout_sha256": p.digest(stdout), "stderr_sha256": p.digest(stderr)}
        for name, raw in {"START.json": p.canonical(start), "COMPLETE.json": p.canonical(complete),
                          "stdout.log": stdout, "stderr.log": stderr}.items():
            path = context + "/" + name
            d.host_store.files[path] = raw
            d.custody._protected[path] = p.digest(raw)
            case["protected"].add(path)
        receipt["receipt_sha256"] = p.digest(complete)
        record.update(receipt=receipt["receipt_sha256"], output=receipt["output"])
        case["roles"][context] = record
        d.runtime.receipts[receipt["receipt_sha256"]] = d.protected / context / "COMPLETE.json"
        observe(d, "role", {"role": role, "receipt": receipt})
    d.native_adapter.review = a.ReviewBinding(d.roles["reviewer"], d.roles["mapper"]["context_id"],
        d.roles["mapper"]["receipt_sha256"], d.roles["selector"]["context_id"], d.roles["selector"]["receipt_sha256"])


def test_all_four_role_completions_rechecked_against_runtime_custody_and_bytes(sample):
    role_observations(sample)
    sample.guard._roles(sample.d, sample.case)


@pytest.mark.parametrize("change", ["runtime", "custody", "input", "output", "log", "role", "record", "receipt"])
def test_completed_role_label_alone_never_passes(sample, change):
    x = sample
    role_observations(x)
    receipt = x.d.roles["reviewer"]
    rec = x.case["roles"][receipt["context_id"]]
    if change == "runtime":
        x.d.runtime.receipts.clear()
    elif change == "custody":
        rec["complete"] = False
    elif change == "input":
        x.d.store.files[rec["relative"] + "/input.json"] += b"tamper"
    elif change == "output":
        x.d.store.files[rec["relative"] + "/output.json"] += b"tamper"
    elif change == "log":
        x.d.host_store.files[receipt["context_id"] + "/stderr.log"] = b"model: a different model"
    elif change == "role":
        rec["role"] = "mapper"
    elif change == "record":
        x.d.native_observations.clear()
    else:
        receipt["output"]["sources"][0]["checks"]["rights"] = False
    with pytest.raises((g.EvidenceHold, custody.CustodyError)):
        x.guard._roles(x.d, x.case)


def common_fixture(x, monkeypatch):
    """Isolate common/call-frame verification from separately tested evidence.

    Driver/custody checks are test-only dependency stubs; this is not an actual
    execution authorization. The guard itself has no bypass options.
    """
    d = driver.CaseDriver.__new__(driver.CaseDriver)
    d.__dict__.update(x.d.__dict__)
    d.workspace, d.protected, d.registry = ROOT, d.host_store.root, x.actual.binding.registry
    d.policy = p.FrozenPolicy("synthetic-run", H, H, "EMPTY", a.EMPTY)
    d._check_pins = lambda: None
    d.runtime = CodexRoleRuntime.__new__(CodexRoleRuntime)
    actual_custody = custody.CaseCustody.__new__(custody.CaseCustody)
    actual_custody.store, actual_custody.root = d.host_store, d.protected
    actual_custody._case = lambda cap: x.case
    d.custody = actual_custody
    guard = make_guard(lambda: d)
    cp = x.actual.artifact_lineage["pins"]
    d.pins = driver.DriverPins(x.args["pins"], {"identity_sha256": H}, {"identity_sha256": H},
        {name: guard.expected_code_sha256s[name] for name in driver.CODE_FILES}, H, H, H, H, H)
    d.research_policy = NS(sha256=H)
    ad = a.CaseIndexAdapter.__new__(a.CaseIndexAdapter)
    ad.root, ad.policy, ad.scope = d.root, d.research_policy, r.Scope(str(d.root / "legal-index"),
        "candidate_case_local", d.policy.run_id, d.request["case_id"])
    ad.bindings = d.native_adapter.bindings
    ad._pin_check = lambda: None
    ad.pins = a.AdapterPins(d.request["case_id"], d.request_sha, p.digest(d.policy.manifest()),
        cp["owner_instruction_sha256"], H, guard.expected_code_sha256s["backend/app/research/ge_auto_index.py"],
        guard.expected_code_sha256s["scripts/ge_auto_case_index_adapter.py"], H, d.pins.embedding_identity,
        x.actual.binding.expected_knowledge_generation_sha256, d.registry.manifest_sha256,
        d.policy.retry_profile_sha256s, H)
    d.native_adapter = ad
    ad.embedding_session_factory = runtime.PinnedEmbeddingSession
    ad.verify_identity = runtime.verified_model_identity
    ad.rerank = d._rerank
    ad.host_verify = d.native_verify = guard.verify
    monkeypatch.setattr(guard, "_roles", lambda *args: None)
    seen = []
    monkeypatch.setattr(guard, "_dispatch", lambda *args: seen.append(args[2]))
    return d, guard, seen


def test_real_adapter_call_frame_and_json_safe_datetime_pin_snapshot(sample, monkeypatch):
    d, guard, seen = common_fixture(sample, monkeypatch)
    d.native_adapter._verify("open_adapter_store")
    assert seen == ["open_adapter_store"] and guard.last_hold is None
    assert guard._turns
    binding = {"schema": a.VERSION, "action": "open_adapter_store", "case_root": str(d.root),
        "scope": asdict(d.native_adapter.scope), "pins": asdict(d.native_adapter.pins), "baseline_sha256": a.EMPTY,
        "non_live": True, "private_reference_inputs": False}
    assert guard.verify(binding) is False
    assert guard.last_hold == "PINNED_ADAPTER_CALL_REQUIRED"


@pytest.mark.parametrize("key,value", [("schema", "different"), ("case_root", str(ROOT)), ("scope", {}),
    ("pins", {}), ("baseline_sha256", H), ("non_live", 1), ("private_reference_inputs", True)])
def test_every_common_field_is_derived_from_driver_not_binding(sample, monkeypatch, key, value):
    d, guard, seen = common_fixture(sample, monkeypatch)
    with pytest.raises(a.AdapterHold):
        d.native_adapter._verify("open_adapter_store", **{key: value})
    assert seen == [] and guard.last_hold == "COMMON_BINDING_CHANGED"


def test_driver_and_frozen_pin_substitution_rejected(sample, monkeypatch):
    d, guard, seen = common_fixture(sample, monkeypatch)
    d.pins = replace(d.pins, code_sha256s={**d.pins.code_sha256s, "scripts/ge_auto_case_driver.py": H})
    with pytest.raises(a.AdapterHold):
        d.native_adapter._verify("open_adapter_store")
    assert seen == [] and guard.last_hold == "DRIVER_CODE_PINS_CHANGED"


def rerank_fixture(x):
    x.d.pins.reranker_identity = {"identity_sha256": H}
    x.state.retrieved = {x.prop["proposition_id"]: {"synthetic": True}}
    job = x.guard._job(x.d, x.state)
    query = job["public_queries"][0]["query"]
    doc = "\n".join(dict.fromkeys(span["text"] for span in a.spans(x.prop)))
    execution = {"schema": "legalbot.ge-auto-research-reranking.v1", "model_identity": x.d.pins.reranker_identity,
        "loading_info": {}, "calls": [{"query_sha256": runtime._digest(query), "document_sha256": runtime._digest(doc),
            "tokens": 20, "score": 0.25, "seconds": 0.1}], "actual_pairs_scored": 1,
        "training": False, "classification_head_created": False}
    lease = {"job_sha256": p.digest(job), "lock_path": str(ROOT / "data/research/ge-auto-research/embedding.lock"),
             "exclusive_lock_observed": True, "model_identity": x.d.pins.reranker_identity}
    result = {"ordered_proposition_ids": [x.prop["proposition_id"]], "receipt": {
        "model": "Qwen/Qwen3-Reranker-0.6B", "model_identity_sha256": H, "input_sha256": p.digest(job),
        "actual_inference_calls": 1, "execution_receipt_sha256": p.digest(execution),
        "exclusive_model_lease_sha256": p.digest(lease), "session_closed": True, "synthetic_vectors": False, "training": False}}
    x.state.pending_rerank = p.digest(job)
    record = {"job": job, "execution": execution, "lease": lease, "scores": [0.25]}
    observe(x.d, "reranker", record)
    return job, result, record


def test_protected_reranker_pairs_lease_order_and_receipt(sample):
    job, result, _ = rerank_fixture(sample)
    sample.guard._reranker(sample.d, sample.state, job, result)
    assert sample.state.reranked[p.digest(job)] == result


@pytest.mark.parametrize("change", ["unobserved", "document", "query", "model", "score", "order", "lease", "training", "extra"])
def test_reranker_self_report_or_changed_full_context_holds(sample, change):
    x = sample
    job, result, record = rerank_fixture(x)
    x.d.native_observations.clear()
    if change == "document":
        record["execution"]["calls"][0]["document_sha256"] = runtime._digest(x.prop["point"]["text"])
    elif change == "query":
        record["execution"]["calls"][0]["query_sha256"] = H
    elif change == "model":
        record["execution"]["model_identity"] = {"identity_sha256": p.digest(b"different-model")}
    elif change == "score":
        record["scores"] = [0.75]
    elif change == "order":
        result["ordered_proposition_ids"] = ["not-this-proposition"]
    elif change == "lease":
        record["lease"]["lock_path"] = str(ROOT / "different-lock")
    elif change == "training":
        record["execution"]["training"] = True
    elif change == "extra":
        result["all_pass"] = True
    if change != "unobserved":
        observe(x.d, "reranker", record)
    with pytest.raises(g.EvidenceHold):
        x.guard._reranker(x.d, x.state, job, result)


@pytest.fixture
def prepared_sample(sample, monkeypatch):
    x = sample
    identity = {"source_repo": "Qwen/Qwen3-Embedding-0.6B", "revision": "1" * 40, "file_manifest_sha256": H,
        "directory": "synthetic-not-a-model", "dimensions": 1024, "local_files_only": True, "device": "cpu",
        "max_tokens": 2048, "batch_size": 1, "torch_threads": 2, "normalise_embeddings": True, "training": False}
    identity["identity_sha256"] = runtime._digest(identity)
    policy = r.ResearchPolicy(workspace=ROOT, owner_instruction=b"synthetic-owner",
        expected_owner_instruction_sha256=p.digest(b"synthetic-owner"), scopes=(x.source.capture.scope,),
        model=r.ModelPin.from_runtime_identity(identity), reviewers=(x.d.roles["reviewer"]["context_id"],),
        verify_review=lambda who, value: who == x.translated["reviewer_id"] and value == x.translated)
    x.d.research_policy = policy
    lineage = a.bind_contracts(x.actual.binding, request_sha256=x.d.request_sha)
    cap = policy.authorize(scope=x.source.capture.scope, actor=lineage.candidate_id, role="candidate",
                           action="jobs", binding_sha256=r.digest(asdict(lineage)))
    host = NS(sqlite=sqlite3.connect(":memory:", isolation_level=None))
    monkeypatch.setattr(MemoryIndex, "host", host)
    # The existing memory subclass exercises real enqueue/capture/prepare, with
    # directory mkdir suppressed and no build/model method called here.
    db = MemoryIndex(policy=policy, capability=cap, scope=x.source.capture.scope, lineage=lineage)
    gap = db.enqueue(cap, issue_id=x.actual.binding.issue_id, gap_class=x.actual.binding.gap_class,
                     affected_claim_sha256=x.actual.binding.affected_claim_sha256,
                     failure_fingerprint=p.digest({"proposition": x.prop, "review": x.state.legal["review_sha256"]}))
    attempt = db.begin_attempt(cap, gap, inputs_sha256=H, existing_retrieval_sha256=x.actual.binding.existing_retrieval_sha256)
    op = db.reserve(cap, attempt, kind="capture", input_sha256=r.digest(x.source.capture.manifest()))
    db.capture(cap, op, x.source.capture)
    prepared = db.prepare(cap, gap=gap, attempt=attempt, sources=[(x.source.capture, x.translated)])
    x.db, x.prepared, x.sqlite = db, p.decode(prepared.payload), host.sqlite
    x.build_sha = prepared.sha256
    # Read-only SQL uses the actual same memory database; close is intercepted so
    # successive reads remain possible. No files are created by these tests.
    class Connection:
        execute = host.sqlite.execute
        def close(self):
            pass
    monkeypatch.setattr(g, "_safe", lambda path, root, **kw: Path(path))
    monkeypatch.setattr(g.sqlite3, "connect", lambda *args, **kwargs: Connection())
    yield x
    host.sqlite.close()


def test_real_sqlite_prepared_build_recomputed_from_source_parser_and_contracts(prepared_sample):
    x = prepared_sample
    pid, value = x.guard._prepared(x.d, x.state, x.build_sha)
    assert pid == x.prop["proposition_id"] and value == x.prepared
    assert value["rows"] and value["reviews"] == [x.translated]


def test_self_resealed_prepared_row_text_does_not_match_actual_raw(prepared_sample):
    x = prepared_sample
    bad = copy.deepcopy(x.prepared)
    bad["rows"][0]["text"] = "Fabricated statutory words."
    bad["chunk_manifest_sha256"] = r.digest(bad["rows"])
    raw = canonical_json_bytes(bad)
    sha = r.digest(raw)
    x.sqlite.execute("PRAGMA query_only=OFF")
    x.sqlite.execute("INSERT INTO objects VALUES (?,?,?)", (sha, "prepared_build", raw))
    with pytest.raises(g.EvidenceHold, match="PREPARED_BUILD_CHANGED"):
        x.guard._prepared(x.d, x.state, sha)


@pytest.fixture
def generation_sample(prepared_sample, monkeypatch):
    x = prepared_sample
    native = [{**{k: row[k] for k in ("id", "text", "jurisdiction", "valid_from", "valid_to")},
               "vector": [1.0] + [0.0] * 1023, "binding_json": canonical_json_bytes(row).decode()}
              for row in x.prepared["rows"]]
    manifest = {"build-boundary.json": p.digest(b"synthetic boundary"), "lance/authority/fake.lance": H}
    value = {"schema": "legalbot.ge-auto-index-generation.v1", "build_sha256": x.build_sha,
        **{k: x.prepared[k] for k in ("scope", "lineage", "source_manifest_sha256", "review_manifest_sha256",
                                    "chunk_manifest_sha256", "model_sha256")},
        "rows_sha256": r.digest(sorted(native, key=lambda row: row["id"])), "files": manifest,
        "chunk_count": len(native), "embedding_execution": "INJECTED_PROVIDER_EXECUTED",
        "embedding_validation": r.PENDING_EMBEDDING_VALIDATION, "non_live": True, "admitted": False,
        "legal_gold": False, "qualified_legal_review": False, "full_current_law_eligible": False}
    value["generation_sha256"] = r.digest(value)
    x.generation, x.native_rows, x.manifest = value, native, manifest
    x.sqlite.execute("PRAGMA query_only=OFF")
    x.sqlite.execute("INSERT INTO objects VALUES (?,?,?)", (r.digest(value), "generation", canonical_json_bytes(value)))
    real_read = Path.read_bytes
    target = x.d.root / "legal-index/builds" / ("ge-auto-" + x.build_sha) / "generation.json"
    monkeypatch.setattr(Path, "read_bytes", lambda path: canonical_json_bytes(x.generation) if path == target else real_read(path))
    monkeypatch.setattr(x.guard, "_tree", lambda root: copy.deepcopy(x.manifest))
    monkeypatch.setattr(x.guard, "_lance_rows", lambda root, count: copy.deepcopy(x.native_rows))
    return x


def test_generation_sqlite_receipt_and_native_rows_all_bound(generation_sample):
    x = generation_sample
    pid, prepared, generation, native = x.guard._generation(x.d, x.state, x.build_sha)
    assert pid == x.prop["proposition_id"] and prepared == x.prepared
    assert generation == x.generation and native == x.native_rows


@pytest.mark.parametrize("change", ["lance", "files", "receipt", "admitted", "legal_gold"])
def test_generation_corrupt_or_approval_upgrade_is_held(generation_sample, change):
    x = generation_sample
    if change == "lance":
        x.native_rows[0]["text"] += " fabricated"
    elif change == "files":
        x.manifest["lance/authority/fake.lance"] = p.digest(b"different")
    elif change == "receipt":
        x.generation["chunk_count"] += 1
    else:
        x.generation[change] = True
    with pytest.raises(g.EvidenceHold):
        x.guard._generation(x.d, x.state, x.build_sha)
