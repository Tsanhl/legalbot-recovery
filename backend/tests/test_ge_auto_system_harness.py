"""Own synthetic inputs only; no bank, evaluation artifacts, files or cleanup.

Protocol operations use an in-memory create-only store. Capability/vector tests
extract ONLY public production code definitions and exercise their real refusal
logic; they do not claim pinned inference or a persisted index integration pass.
"""
from __future__ import annotations

import ast
import base64
import copy
import hashlib
import math
import struct
from contextlib import nullcontext
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Sequence

import pytest

from scripts import ge_auto_system_harness as h
from scripts import ge_auto_case_protocol as protocol


SECRET = "synthetic-private-question-query-source-answer"
ROOT = Path(__file__).resolve().parents[2]


def permit(context, operation):
    return {"authorized": True, "policy_sha256": context.policy_sha256,
            "capability_sha256": context.capability_sha256, "case_id": context.case_id,
            "case_store_id": context.case_store_id, "scope_kind": context.scope_kind,
            "case_input_sha256": context.case_input_sha256,
            "runtime_binding_sha256": context.runtime_binding_sha256,
            "turn_id": context.turn_id, "operation": operation}


@pytest.fixture
def env():
    value = SimpleNamespace(capability=object(), guards=[], delegates=[])
    value.context = h.CaseContext(run_id="synthetic-run", case_id="synthetic-case",
        turn_id="turn-1", attempt_id="fault-1", case_store_id="synthetic-case-store",
        case_input_sha256=h.digest(SECRET), policy_sha256=h.digest("policy"),
        capability_sha256=h.digest("synthetic capability fingerprint"), runtime_binding_sha256=h.digest("runtime"))
    def authorize(capability, context, operation, request):
        value.guards.append((capability, context, operation, copy.deepcopy(request)))
        if capability is not value.capability or context != value.context:
            raise PermissionError("wrong capability or context")
        if (request.get("case_id", context.case_id) != context.case_id
                or request.get("case_store_id", context.case_store_id) != context.case_store_id):
            raise PermissionError("wrong case/store")
        return permit(context, operation)
    value.authorize = authorize
    return value


def harness(env, kind, callbacks, **kwargs):
    return h.CaseFaultHarness(context=env.context, fault=h.FaultSpec(kind, h.FAULTS[kind][0], **kwargs),
        capability=env.capability, authorize=env.authorize, callbacks=callbacks)


def checked_hold(receipt):
    h.assert_fail_closed(receipt)
    assert receipt["system_pass"] is False
    assert receipt["runtime_integration_validated"] is False
    assert receipt["actual_embedding_inference_claimed"] is False
    assert not any(receipt[k] for k in ("production_admission", "weight_training", "active_mutation", "promotion", "live"))
    assert SECRET not in repr(receipt)
    assert receipt["context"]["scope_kind"] == "candidate_case_local"


def test_target_names_match_public_question_free_family_code_only():
    path = ROOT / "backend/app/evaluation/ge_everyday_unseen.py"
    tree = ast.parse(path.read_text())
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "SYSTEM_FAMILIES" for t in n.targets))
    families = ast.literal_eval(node.value)
    assert len(families) == 23
    assert dict(h.TARGET_FAMILIES) == {cid: families[int(cid[-2:])-1] for cid in h.TARGET_FAMILIES}
    assert len(h.support_report()["not_targeted_system_ids"]) == 15
    assert h.support_report()["protocol_requires_external_ocr_hook"] is True


@pytest.mark.parametrize("kind", ["ocr-error", "search-outage", "capture-outage"])
def test_exception_is_injected_at_actual_authorized_callback_trigger(env, kind):
    operation = h.FAULTS[kind][1]
    def underlying(request):
        pytest.fail("pre-call injected failure must not execute the dependency")
    test = harness(env, kind, {operation: underlying})
    def driver(ports):
        try:
            ports[operation]({"payload": SECRET})
        except (h.InjectedOCRFailure, h.InjectedSourceOutage):
            return {"status": "HOLD"}
        pytest.fail("actual exception not delivered")
    receipt = test.exercise(driver)
    checked_hold(receipt)
    assert len(env.guards) == 1 and env.guards[0][0] is env.capability
    assert receipt["calls"][operation] == 1
    assert any(e["kind"] == "CALLBACK_TRIGGERED" for e in receipt["events"])
    assert not any(e["kind"] == "DELEGATE_CALLED" for e in receipt["events"])
    assert receipt["callback_bindings"][operation] == h.callback_identity(underlying)


@pytest.mark.parametrize("kind", ["ocr-ambiguous-date", "ocr-missing-page"])
def test_real_ocr_result_is_altered_and_required_date_or_page_validation_refuses(env, kind):
    original = {"page_count": 2, "pages": [
        {"page_number": 1, "text": SECRET + " Document date: 2026-03-05"},
        {"page_number": 2, "text": "Synthetic second page."}]}
    before = copy.deepcopy(original)
    delivered = []
    def ocr(request):
        env.delegates.append("ocr")
        return original
    def validate_extraction(value, expected_pages):
        if len(value["pages"]) != expected_pages or value["page_count"] != len(value["pages"]):
            raise ValueError("incomplete page coverage")
        if any(len(page.get("date_candidates", [])) > 1 for page in value["pages"]):
            raise ValueError("date cannot be resolved from OCR")
    test = harness(env, kind, {"ocr": ocr})
    def driver(ports):
        extracted = ports["ocr"]({"expected_pages": 2, "document_sha256": h.digest("synthetic bytes")})
        delivered.append(extracted)
        try:
            validate_extraction(extracted, 2)
        except ValueError:
            return {"status": "HOLD"}
        return {"status": "READY"}
    checked_hold(test.exercise(driver))
    assert env.delegates == ["ocr"] and original == before
    assert delivered[0] != original
    if kind == "ocr-missing-page":
        assert len(delivered[0]["pages"]) == 1 and delivered[0]["page_count"] == 2
    else:
        assert "01/02/2026" in delivered[0]["pages"][0]["text"]


@pytest.mark.parametrize("kind", ["capture-stale-source", "capture-uncommenced-source"])
def test_currentness_fault_alters_source_copy_and_index_date_guard_refuses(env, kind):
    raw = (SECRET + " synthetic source").encode()
    original = {"raw": raw, "text": raw.decode(), "raw_sha256": hashlib.sha256(raw).hexdigest()}
    saved = copy.deepcopy(original)
    def capture(request):
        return original
    def index(request):
        source = request["source"]
        assert hashlib.sha256(source["raw"]).hexdigest() == source["raw_sha256"]
        currentness = source["currentness"]
        if (currentness.get("commenced") is not True
                or currentness.get("valid_to", "9999-12-31") < request["as_of"]):
            raise ValueError("controlling source not current at requested date")
        pytest.fail("invalid currentness reached index publication")
    test = harness(env, kind, {"capture": capture, "index": index})
    def driver(ports):
        source = ports["capture"]({"as_of": "2026-09-05"})
        try:
            ports["index"]({"source": source, "as_of": "2026-09-05"})
        except ValueError:
            return {"status": "HOLD"}
    checked_hold(test.exercise(driver))
    assert original == saved


def _production_guards():
    """Extract pure production guards, avoiding package/data/model side effects."""
    path = ROOT / "backend/app/research/ge_auto_index.py"
    tree = ast.parse(path.read_text())
    chosen = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "LANE_ROLES" for t in node.targets):
            chosen.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "Capability":
            chosen.append(node)
        if isinstance(node, ast.ClassDef) and node.name in ("ResearchPolicy", "AutoResearchIndex"):
            name = "require" if node.name == "ResearchPolicy" else "_vector"
            fn = copy.deepcopy(next(n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == name))
            fn.decorator_list = []
            chosen.append(fn)
    @dataclass(frozen=True)
    class Scope:
        root: str
        lane: str = "candidate_case_local"
        def validate(self, workspace):
            assert self.root.startswith("/synthetic/") and workspace == "/synthetic"
    namespace = {"dataclass": dataclass, "Scope": Scope, "Sequence": Sequence,
                 "math": math, "struct": struct}
    exec(compile(ast.Module(body=chosen, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def test_cross_case_injection_is_refused_by_actual_production_capability_guard(env):
    code = _production_guards()
    scope = code["Scope"]("/synthetic/own-case")
    issuer = object()
    cap = code["Capability"](env.context.policy_sha256, scope, "synthetic-actor", "candidate",
                             "build", env.context.case_input_sha256, issuer)
    policy = SimpleNamespace(_issuer=issuer, _issued={cap}, sha256=env.context.policy_sha256, workspace="/synthetic")
    env.capability = cap
    attempted = []
    def authorize(capability, context, operation, request):
        attempted.append(request)
        requested_scope = scope if request.get("case_id") == context.case_id else code["Scope"]("/synthetic/other-case")
        code["require"](policy, capability, requested_scope, "build", context.case_input_sha256)
        return permit(context, operation)
    env.authorize = authorize
    def index(request):
        pytest.fail("foreign storage must never be read")
    test = harness(env, "cross-case-index-request", {"index": index})
    def driver(ports):
        try:
            ports["index"]({"case_id": env.context.case_id, "case_store_id": env.context.case_store_id})
        except PermissionError:
            return {"status": "REFUSED"}
    receipt = test.exercise(driver)
    checked_hold(receipt)
    assert attempted[0]["case_id"] != env.context.case_id
    assert not any(e["kind"] == "DELEGATE_CALLED" for e in receipt["events"])


@pytest.mark.parametrize("guard_behavior", ["accept", "unrelated_exception"])
def test_unsafe_or_broken_guard_cannot_earn_isolation_credit(env, guard_behavior):
    def wrong_guard(capability, context, operation, request):
        if guard_behavior == "unrelated_exception":
            raise RuntimeError("unrelated guard infrastructure failure")
        return permit(context, operation)
    env.authorize = wrong_guard
    def index(request):
        pytest.fail("even an unsafe guard must not cause another case read")
    test = harness(env, "cross-case-index-request", {"index": index})
    def driver(ports):
        try:
            ports["index"]({})
        except Exception:
            return {"status": "HOLD"}
    receipt = test.exercise(driver)
    assert receipt["fault_exercised"] is True and receipt["fail_closed_observed"] is False
    with pytest.raises(AssertionError):
        h.assert_fail_closed(receipt)


@pytest.mark.parametrize("index_behavior", ["actual_vector_refusal", "unrelated_error", "accept"])
def test_invalid_vector_is_fault_only_and_requires_actual_numeric_guard_refusal(env, index_behavior):
    vector_guard = _production_guards()["_vector"]
    class NoInferenceProvider:
        pin = "SYNTHETIC_TEST_OBJECT_NOT_A_MODEL_PIN"
        dimensions = 1024
        def verify_binding(self):
            return False  # Never claim a pinned/loaded model in these tests.
        def embed_documents(self, texts):
            pytest.fail("invalid-vector fault must not claim or call inference")
    def index(request):
        vectors = provider.embed_documents(["own synthetic structural chunk"])
        if index_behavior == "actual_vector_refusal":
            for vector in vectors:
                vector_guard(vector)  # Actual production numeric validation.
        elif index_behavior == "unrelated_error":
            raise ValueError("unrelated index outage")
        return {"status": "OK"}
    test = harness(env, "invalid-vector", {"index": index})
    provider = test.wrap_embedder(NoInferenceProvider())
    assert provider.verify_binding() is False
    def driver(ports):
        try:
            ports["index"]({"case_id": env.context.case_id})
        except ValueError:
            pass
        return {"status": "HOLD"}
    receipt = test.exercise(driver)
    assert receipt["family"] is None and receipt["actual_embedding_inference_claimed"] is False
    if index_behavior == "actual_vector_refusal":
        checked_hold(receipt)
    else:
        assert receipt["fail_closed_observed"] is False
        with pytest.raises(AssertionError):
            h.assert_fail_closed(receipt)


def test_no_callback_and_narrative_hold_do_not_prove_a_fault(env):
    def search(request):
        return {"status": "OK"}
    test = harness(env, "search-outage", {"search": search})
    receipt = test.exercise(lambda ports: {"status": "HOLD", "reason": "I tested the fault"})
    assert receipt["status"] == "NOT_EXERCISED"
    with pytest.raises(AssertionError):
        h.assert_fail_closed(receipt)
    # Merely changing and resealing narrative fields still cannot prove a trigger.
    receipt.update(fault_exercised=True, fail_closed_observed=True)
    receipt["content_sha256"] = h.digest({k:v for k,v in receipt.items() if k != "content_sha256"})
    with pytest.raises(AssertionError):
        h.assert_fail_closed(receipt)


def test_downstream_answer_after_ignored_fault_is_a_failure_even_if_driver_reports_hold(env):
    def capture(request):
        pytest.fail("outage is injected before capture")
    def answer(request):
        return {"status": "OK", "answer": SECRET}
    test = harness(env, "capture-outage", {"capture": capture, "answer": answer})
    def driver(ports):
        try:
            ports["capture"]({})
        except h.InjectedSourceOutage:
            pass
        ports["answer"]({})
        return {"status": "HOLD"}
    receipt = test.exercise(driver)
    assert receipt["fail_closed_observed"] is False and receipt["unsafe_downstream_events"]
    with pytest.raises(AssertionError):
        h.assert_fail_closed(receipt)


def test_calls_are_bounded_and_fault_instance_cannot_replay_or_escape_exercise(env):
    delegated = []
    def search(request):
        delegated.append(request)
        return {"status": "OK"}
    test = harness(env, "search-outage", {"search": search})
    wrapped = test.wrap_callbacks()
    with pytest.raises(h.HarnessError):
        wrapped["search"]({})
    def driver(ports):
        for _ in range(5):
            try:
                ports["search"]({"query": SECRET})
            except (h.InjectedSourceOutage, h.HarnessError):
                pass
        return {"status": "HOLD"}
    receipt = test.exercise(driver)
    assert len(delegated) == 3 and receipt["calls"]["search"] == 4
    assert sum(e["kind"] == "FAULT_INJECTED" for e in receipt["events"]) == 1
    with pytest.raises(h.HarnessError, match="ALREADY_CONSUMED"):
        test.exercise(driver)
    with pytest.raises(h.HarnessError):
        wrapped["search"]({})


@pytest.mark.parametrize("kind,result", [
    ("ocr-missing-page", {"pages": [{"text": "only one"}], "page_count": 1}),
    ("ocr-ambiguous-date", {"pages": [{"text": "no date"}], "page_count": 1}),
    ("capture-prompt-injection", {"text": "no raw capture"}),
    ("answer-truncation", {"answer": ""}),
])
def test_unsupported_actual_payload_never_becomes_exercised_or_pass(env, kind, result):
    operation = h.FAULTS[kind][1]
    def callback(request):
        return result
    test = harness(env, kind, {operation: callback})
    def driver(ports):
        try:
            ports[operation]({"expected_pages": 1})
        except h.FaultNotApplicable:
            return {"status": "HOLD"}
    receipt = test.exercise(driver)
    assert receipt["status"] == "NOT_EXERCISED" and receipt["unsupported_reason"]
    with pytest.raises(AssertionError):
        h.assert_fail_closed(receipt)


class MemoryStore:
    def __init__(self):
        self.root = Path("/synthetic/case-root")
        self.files, self.dirs = {}, set()
    def exists(self, name):
        return name in self.files or name in self.dirs
    def mkdir_new(self, name):
        if self.exists(name):
            raise FileExistsError(name)
        self.dirs.add(name)
    def write_new(self, name, raw):
        if self.exists(name):
            raise FileExistsError(name)
        self.files[name] = bytes(raw)
    def read(self, name):
        return self.files[name]
    def lock(self):
        return nullcontext()


def case_protocol(env, *, verify_capture=None):
    policy = protocol.FrozenPolicy("synthetic-run", h.digest("owner"), h.digest("runtime"), "EMPTY", protocol.digest([]))
    env.context = replace(env.context, policy_sha256=protocol.digest(policy.manifest()))
    store = MemoryStore()
    def guard(capability, binding):
        assert capability is env.capability
        assert binding["case_id"] == env.context.case_id
        assert binding["policy_sha256"] == env.context.policy_sha256
        if binding["action"] == "actual_capture_parse" and verify_capture:
            return verify_capture(binding)
        return True
    p = protocol.CaseProtocol(case_root=store.root, policy=policy, capability=env.capability, guard=guard, store=store)
    p.case_id, p.request_sha256 = env.context.case_id, env.context.case_input_sha256
    p.touched, p.choose_retry, p.turn, p.turn_root = {}, None, 1, "turn-0001"
    p.official_url = lambda url:url == "https://synthetic.invalid/official"
    return p, store


@pytest.mark.parametrize("kind", ["search-outage", "capture-outage"])
def test_actual_protocol_reserves_operation_then_preserves_injected_failure_without_retry(env, kind):
    p, store = case_protocol(env)
    operation = h.FAULTS[kind][1]
    def host(envelope, reservation):
        pytest.fail("fault precedes host IO")
    test = harness(env, kind, {operation: host})
    def driver(ports):
        with pytest.raises(protocol.ActionHold):
            p._operation(operation, "synthetic-operation", {"as_of_date": "2026-09-05"},
                         ports[operation], lambda result:None, budget=True)
        retained = dict(store.files)
        with pytest.raises(protocol.ActionHold):
            p._operation(operation, "synthetic-operation", {"as_of_date": "2026-09-05"},
                         ports[operation], lambda result:None, budget=True)
        assert store.files == retained
        return {"status": "HOLD"}
    receipt = test.exercise(driver, protocol=True)
    checked_hold(receipt)
    assert receipt["calls"][operation] == 1
    assert any(path.endswith("reservation.json") for path in store.files)
    assert any(path.endswith("failure.json") for path in store.files)
    assert not any(path.endswith("success.json") for path in store.files)


@pytest.mark.parametrize("kind", ["capture-prompt-injection", "capture-stale-source", "capture-uncommenced-source"])
def test_actual_protocol_rejects_mutated_capture_without_forging_parser_receipt(env, kind):
    url = "https://synthetic.invalid/official"
    raw = SECRET.encode()
    original = {"canonical_url": url, "final_url": url, "redirect_chain": [],
                "fetched_at": "2026-09-05T00:00:00+00:00", "raw": raw,
                "parser_sha256": h.digest("parser-code"), "parser_receipt_sha256": h.digest("original parser receipt"),
                "parts": [{"part_id": "p1", "parent_id": None, "locator": "synthetic paragraph", "text": SECRET}]}
    retained = copy.deepcopy(original)
    def verify_capture(binding):
        return (binding["source_sha256"] == protocol.digest(raw)
                and binding["parsed_sha256"] == protocol.digest(original["parts"]))
    p, store = case_protocol(env, verify_capture=verify_capture)
    def capture(envelope, reservation):
        env.delegates.append("capture")
        return original
    test = harness(env, kind, {"capture": capture})
    def driver(ports):
        with pytest.raises(protocol.ActionHold):
            p._operation("capture", "source", {"url":url, "as_of_date":"2026-09-05"},
                         ports["capture"], lambda value:p._capture(value,url), budget=True)
        return {"status":"HOLD"}
    receipt = test.exercise(driver,protocol=True)
    checked_hold(receipt)
    assert env.delegates == ["capture"] and original == retained
    output = protocol.decode(next(raw for name,raw in store.files.items() if name.endswith("output.json")))
    assert output["parser_receipt_sha256"] == original["parser_receipt_sha256"]
    assert base64.b64decode(output["raw_b64"]) != raw
    assert any("POST_CAPTURE_MUTATION" in e.get("effect", "") for e in receipt["events"])


def test_actual_protocol_final_schema_rejects_truncated_role_output_once(env):
    p, store = case_protocol(env)
    returned = []
    def invoke_role(job):
        result = {"context_id":job.context_id, "input_sha256":job.input_sha256,
                  "receipt_sha256":h.digest("actual synthetic role receipt"),
                  "output":{"status":"HOLD", "answer":SECRET*4, "cited_proposition_ids":[]}}
        returned.append(copy.deepcopy(result))
        return result
    test = harness(env,"answer-truncation",{"answer":invoke_role})
    def driver(ports):
        p.invoke_role = ports["invoke_role"]
        with pytest.raises(protocol.ActionHold):
            p._role("final",{"synthetic":"own case only"},lambda value:protocol.checked(value,protocol.FINAL_SCHEMA))
        return {"status":"HOLD"}
    receipt = test.exercise(driver,protocol=True)
    checked_hold(receipt)
    assert len(returned)==1 and receipt["calls"]["answer"]==1
    assert len(returned[0]["output"]["answer"]) > 64
    assert any("final" in path and path.endswith("failure.json") for path in store.files)


def test_protocol_reservation_for_another_case_refused_before_callback(env):
    def search(envelope, reservation):
        pytest.fail("other case callback not allowed")
    test = harness(env,"search-outage",{"search":search})
    def driver(ports):
        with pytest.raises(h.HarnessError,match="CASE_BINDING"):
            ports["search"]({"data":{}},{"case_id":"other-case"})
        return {"status":"HOLD"}
    receipt=test.exercise(driver,protocol=True)
    assert receipt["status"]=="NOT_EXERCISED" and not env.guards


def test_context_scope_hashes_and_target_family_are_fail_closed(env):
    for changes in ({"scope_kind":"shared_research"},{"lane":"production"},{"policy_sha256":"not-a-hash"}):
        with pytest.raises(h.HarnessError):
            replace(env.context,**changes)
    for kind, system_id in (("ocr-error","system:23"),("invented-fault","system:01"),("invalid-vector","system:08")):
        with pytest.raises(h.HarnessError):
            h.FaultSpec(kind,system_id)
    with pytest.raises(h.HarnessError):
        h.FaultSpec("search-outage","system:23",trigger_call=5)


def test_distinct_harnesses_do_not_share_case_fault_state(env):
    def search(request):
        return {"status":"OK"}
    first=harness(env,"search-outage",{"search":search})
    second=harness(env,"search-outage",{"search":search})
    def driver(ports):
        try:
            ports["search"]({})
        except h.InjectedSourceOutage:
            return {"status":"HOLD"}
    a,b=first.exercise(driver),second.exercise(driver)
    checked_hold(a)
    checked_hold(b)
    a["events"].clear()
    assert b["events"] and first._events and second._events
