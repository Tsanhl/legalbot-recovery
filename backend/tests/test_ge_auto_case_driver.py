"""Synthetic in-memory driver plumbing; NOT model, network or legal validation.

Real Fernet, selected contracts, protocol, custody and intake are exercised.
Roles/fences/tool service use explicitly labelled test doubles. All artifact
stores are in memory: no private data, real CLI, model inference or network.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from backend.app.contracts.query_plan import QueryBudgets
from backend.app.contracts.schema_registry import ContractSchemaRegistry
from backend.app.research import ge_auto_index as research
from backend.tests import test_ge_auto_case_contracts as cf
from backend.tests import test_ge_auto_case_custody as hf
from cryptography.fernet import Fernet
from scripts import ge_auto_case_driver as d
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as b
from scripts import ge_auto_role_runtime as roles

ROOT = Path(__file__).resolve().parents[2]
STAMP = datetime(2026, 9, 5, tzinfo=UTC)
H = p.digest(b"synthetic driver test identity")


def memory(name="synthetic-driver-memory"):
    return hf.MemoryStore(ROOT / name)


def test_fact_projection_is_exactly_bound_to_candidate_visible_snapshot():
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    req = cf.request()
    built = cf.c.build_case_contracts(**cf.arguments(registry, req=req))
    projection = d.build_fact_projection(case_id=req["case_id"], turn=1,
        requests=[req], fact_snapshot=built.binding.fact_snapshot,
        query_plan=built.binding.query_plan)
    assert projection["facts"] == [{
        "fact_id": built.binding.fact_snapshot["facts"][0]["fact_id"],
        "turn": 1, "kind": "question",
        "source_id": "request-" + p.digest(req)[:40],
        "text": req["question"], "text_sha256": p.digest(req["question"].encode()),
        "origin": "user_statement", "status": "stated",
        "affected_issue_ids": ["issue-synthetic"],
    }]
    assert projection["author_expectations_included"] is False
    assert projection["semantic_facts_inferred"] is False


def test_fact_projection_rejects_plaintext_not_bound_to_snapshot():
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    req = cf.request()
    built = cf.c.build_case_contracts(**cf.arguments(registry, req=req))
    changed = copy.deepcopy(req)
    changed["question"] += " changed"
    with pytest.raises(d.DriverHold, match="FACT_PROJECTION_FACT_BINDING"):
        d.build_fact_projection(case_id=req["case_id"], turn=1,
            requests=[changed], fact_snapshot=built.binding.fact_snapshot,
            query_plan=built.binding.query_plan)


def test_fernet_roundtrip_real_receipt_and_same_instance_idempotence():
    store, key, raw = memory(), Fernet.generate_key(), b"Only this synthetic due question."
    vault = d.FernetArtifactStore(store=store, key=key, prefix="encrypted/due")
    provenance = {"plaintext_sha256": p.digest(raw), "request_sha256": H}
    ack = vault(raw, provenance)
    cipher = store.read("encrypted/due/" + ack["encrypted_ref"] + ".fernet")
    receipt_raw = store.read("encrypted/due/" + ack["encrypted_ref"] + ".json")
    assert Fernet(key).decrypt(cipher) == raw
    assert raw not in cipher and raw not in receipt_raw and key not in receipt_raw
    assert ack["receipt_sha256"] == p.digest(receipt_raw)
    assert ack["ciphertext_sha256"] == p.digest(cipher)
    assert vault(raw, provenance) == ack
    assert len(store.files) == 2
    restarted = d.FernetArtifactStore(store=store, key=key, prefix="encrypted/due")
    with pytest.raises(d.DriverHold, match="UNOBSERVED_OR_PARTIAL"):
        restarted(raw, provenance)


@pytest.mark.parametrize("suffix", [".fernet", ".json"])
def test_fernet_refuses_changed_ciphertext_or_receipt(suffix):
    store, raw = memory(), b"synthetic bytes"
    vault = d.FernetArtifactStore(store=store, key=Fernet.generate_key(), prefix="encrypted")
    provenance = {"plaintext_sha256": p.digest(raw)}
    ack = vault(raw, provenance)
    store.files["encrypted/" + ack["encrypted_ref"] + suffix] += b"changed"
    with pytest.raises(d.DriverHold, match="ENCRYPTED_ARTIFACT_CHANGED"):
        vault(raw, provenance)


def test_partial_encryption_failure_is_retained_and_not_adopted(monkeypatch):
    store, raw = memory(), b"synthetic bytes"
    vault = d.FernetArtifactStore(store=store, key=Fernet.generate_key(), prefix="encrypted")
    original = store.write_new
    def fail_receipt(name, value):
        if name.endswith(".json"):
            raise OSError("synthetic receipt write interrupted")
        original(name, value)
    monkeypatch.setattr(store, "write_new", fail_receipt)
    with pytest.raises(OSError):
        vault(raw, {"plaintext_sha256": p.digest(raw)})
    assert len(store.files) == 1 and next(iter(store.files)).endswith(".fernet")
    with pytest.raises(d.DriverHold, match="UNOBSERVED_OR_PARTIAL"):
        vault(raw, {"plaintext_sha256": p.digest(raw)})


def ledger_fixture():
    store, reservation = memory(), {"synthetic-reservation": H}
    base = "broker/capture-" + p.digest(reservation)
    raw = b'<html><body><h1>Synthetic rule</h1><p>Only if condition A applies.</p><p>Context B.</p></body></html>'
    manifest = b.parse_official_capture(raw, source_url=hf.URL, expected_raw_sha256=p.digest(raw))
    parts = b.structural_parts(manifest)
    transport = {"canonical_url": hf.URL, "final_url": hf.URL, "redirect_chain": [],
                 "fetched_at": STAMP.isoformat()}
    values = {"raw.bytes": raw, "transport.json": p.canonical(transport),
              "parse-manifest.json": p.canonical(manifest), "parts.json": p.canonical(parts)}
    receipt = {**transport, "reservation_sha256": p.digest(reservation), "parser_mode": b.PARSER_MODE,
               "include_legal_tables": True, "files": {k: p.digest(v) for k, v in values.items()},
               "source_sha256": p.digest(raw), "parsed_sha256": p.digest(parts),
               "intake_parsed_sha256": manifest["parsed_sha256"], "parser_sha256": manifest["parser_sha256"]}
    values["parser-receipt.json"] = p.canonical(receipt)
    d._mkdir(store, base)
    for name, data in values.items():
        store.write_new(base + "/" + name, data)
    original = {**transport, "raw_b64": base64.b64encode(raw).decode(), "parts": parts,
                "parser_sha256": manifest["parser_sha256"], "parser_receipt_sha256": p.digest(receipt)}
    reviewed = {"source_sha256": p.digest(raw), "decision": "ELIGIBLE", "holds": [],
                "checks": dict.fromkeys(p.SOURCE_CHECKS, True)}
    kwargs = dict(store=store, reservation=reservation, original=original,
                  scope=research.Scope(str(ROOT / "synthetic-case/legal-index"), "candidate_case_local", "synthetic-run", "synthetic-case"),
                  researcher_id="synthetic-selector", jurisdiction="England", source_review=reviewed,
                  reviewer_receipt_sha256=H)
    return kwargs, base


def proposition(original):
    spans = [{"source_sha256": p.digest(base64.b64decode(original["raw_b64"])),
              "part_id": part["part_id"], "start": 0, "end": len(part["text"]), "text": part["text"]}
             for part in original["parts"]]
    return {"proposition_id": "synthetic-p", "jurisdiction": "England", "as_of_date": "2026-09-05",
            "point": spans[1], "conditions": [], "context": [spans[0], spans[2]],
            "currentness": {"status": "VERIFIED", "checks": [spans[2]],
                            "valid_from": "2026-09-05", "valid_to": "2026-09-05"}}


def test_actual_capture_reconstructed_from_exact_parser_ledger():
    kwargs, _ = ledger_fixture()
    capture, mapping = d.capture_from_ledger(**kwargs)
    assert type(capture) is research.Capture
    assert capture.raw == base64.b64decode(kwargs["original"]["raw_b64"])
    assert [(b.text, b.source_anchor) for b in capture.parsed.body_blocks] == [
        (part["text"], part["locator"]) for part in kwargs["original"]["parts"]]
    assert d.complete_reviewed_blocks(proposition(kwargs["original"]), kwargs["original"], mapping) == tuple(mapping.values())


@pytest.mark.parametrize("name", ["raw.bytes", "parse-manifest.json", "parts.json", "parser-receipt.json", "transport.json"])
def test_capture_ledger_tamper_is_not_rebound(name):
    kwargs, base = ledger_fixture()
    kwargs["store"].files[base + "/" + name] += b" "
    with pytest.raises(d.DriverHold, match="CHANGED"):
        d.capture_from_ledger(**kwargs)


def test_partial_or_unreviewed_parent_blocks_never_expand_coverage():
    kwargs, _ = ledger_fixture()
    _, mapping = d.capture_from_ledger(**kwargs)
    original = kwargs["original"]
    prop = proposition(original)
    prop["point"]["end"] -= 1
    prop["point"]["text"] = prop["point"]["text"][:-1]
    with pytest.raises(d.DriverHold, match="PARTIAL_BLOCK_REVIEW_HOLD"):
        d.complete_reviewed_blocks(prop, original, mapping)
    prop = proposition(original)
    prop["context"] = prop["context"][1:]
    with pytest.raises(d.DriverHold, match="UNREVIEWED_PARENT_BLOCK_HOLD"):
        d.complete_reviewed_blocks(prop, original, mapping)
    prop = proposition(original)
    bad_mapping = dict.fromkeys(mapping, 1)
    with pytest.raises(d.DriverHold, match="PART_MAP"):
        d.complete_reviewed_blocks(prop, original, bad_mapping)


class SyntheticDriverHost(hf.Host):
    """In-memory fake execution harness; production guards are not relaxed."""
    def __init__(self, registry):
        self.key, self.owner, self.global_allowed = object(), hf.OWNER, True
        self.protected, self.store = memory("synthetic-driver-host"), memory("synthetic-driver-case")
        runtime_sha = p.digest((ROOT / "scripts/ge_auto_role_runtime.py").read_bytes())
        self.policy = p.FrozenPolicy("synthetic-run", p.digest(hf.OWNER), runtime_sha, "EMPTY", d.EMPTY)
        self.pins = dict.fromkeys(hf.c.PIN_HASHES, runtime_sha)
        self.pins.update(model="gpt-synthetic-test", provider="openai", cli_identity={"version": "SYNTHETIC",
            "launcher_sha256": H, "package_sha256": H, "native_sha256": H},
            role_callback_sha256=b.callback_sha256(hf.fake_role_call), parser_sha256=hf.intake.parser_binding(include_legal_tables=True),
            transport_callback_sha256=b.callback_sha256(b.fetch_official), parser_callback_sha256=b.callback_sha256(b.parse_official_capture),
            index_runtime_sha256=p.digest((ROOT / "backend/app/research/ge_auto_index.py").read_bytes()),
            index_callback_sha256=b.callback_sha256(d.CaseDriver.index), retrieve_callback_sha256=b.callback_sha256(d.CaseDriver.retrieve),
            active_owner_reader_sha256=b.callback_sha256(self.active_owner), query_privacy_sha256=b.callback_sha256(self.privacy),
            global_marker_verifier_sha256=b.callback_sha256(self.verify_marker))
        identity = {"source_repo": "Qwen/Qwen3-Embedding-0.6B", "revision": "a" * 40,
            "file_manifest_sha256": H, "directory": "synthetic-model-not-opened", "dimensions": 1024,
            "local_files_only": True, "device": "cpu", "max_tokens": 2048, "batch_size": 1,
            "torch_threads": 2, "normalise_embeddings": True, "training": False}
        self.embedding_identity = {**identity, "identity_sha256": p.digest(identity)}
        self.pins["embedding_model_sha256"] = p.digest(identity)
        self.ledger = self.new_ledger()
        self.elapsed, self.calls, self.mutation, self.research, self.native = 0, [], None, False, {}
        self.registry = registry
        cp = replace(cf.pins(registry), owner_instruction_sha256=self.policy.owner_instruction_sha256,
            protocol_policy_sha256=p.digest(self.policy.manifest()), runtime_sha256=runtime_sha,
            parser_sha256=self.pins["parser_sha256"], embedding_model_sha256=self.pins["embedding_model_sha256"],
            encrypt_store_sha256=b.callback_sha256(d.FernetArtifactStore.__call__),
            baseline_created_at=STAMP - timedelta(hours=1), baseline_sealed_at=STAMP - timedelta(hours=1))
        self.driver_pins = d.DriverPins(cp, self.embedding_identity,
            {"identity_sha256": cp.reranker_model_sha256},
            {name: p.digest((ROOT / name).read_bytes()) for name in d.CODE_FILES},
            b.callback_sha256(self.host_verify), b.callback_sha256(self.native_verify), b.callback_sha256(self.gap),
            b.callback_sha256(self.web), b.callback_sha256(self.marker))

    def marker(self, raw):
        return self.global_allowed and raw == hf.OUTER

    def host_verify(self, kind, binding):
        if binding["request_sha256"] != p.digest(self.request_value) or not self.marker(hf.OUTER):
            return False
        if kind == "driver_start":
            return True
        if kind == "web_observation":
            return binding["tool_call_id"] == "synthetic-web-empty" and binding["host_receipt"] == {"synthetic_only": True}
        if kind in ("gap_resolution", "history_contract_resolution"):
            return binding["receipt"] == {"synthetic_empty_lookup_only": True, "request_sha256": p.digest(self.request_value)}
        return False

    def native_verify(self, binding):
        raise AssertionError("No actual native execution in this HOLD test")

    def gap(self, binding):
        return resolution(binding["request"])

    def web(self, request, reservation):
        value = p.decode(request)
        expected = {"query": "Scotland synthetic public rule", "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}
        if not self.research or value["public_input"] != expected or value["tool_arguments"] != b.search_arguments(expected):
            raise AssertionError("Unexpected synthetic query")
        return d.WebObservation('{"synthetic_only":true}', [], "synthetic-web-empty", p.canonical({"synthetic_only": True}))

    def arguments(self):
        self.issue()
        return dict(workspace_root=ROOT, case_root=self.store.root, protected_host_root=self.protected.root,
            request=self.request_value, due_uploads={}, upload_receipt_paths={}, ordered_history=[],
            policy=self.policy, pins=self.driver_pins, registry=self.registry, custody=self.ledger,
            host_key=self.key, capability=self.cap, role_runtime=self.runtime(), fernet_key=Fernet.generate_key(),
            global_marker_bytes=hf.OUTER, establish_global_marker=self.marker, service_web=self.web,
            resolve_gap=self.gap, host_evidence_verify=self.host_verify, native_index_verify=self.native_verify,
            observed_at=STAMP, query_budgets=QueryBudgets(20, 20, 8, 4, 2048, 2), web_timeout_seconds=1)


@pytest.fixture
def host(monkeypatch):
    monkeypatch.setattr(hf, "ROOT", ROOT)
    monkeypatch.setattr(hf, "H", p.digest((ROOT / "scripts/ge_auto_role_runtime.py").read_bytes()))
    monkeypatch.setattr(roles.CodexRoleRuntime, "__call__", hf.fake_role_call)
    monkeypatch.setattr(roles, "profile", hf.fake_profile)
    host = SyntheticDriverHost(ContractSchemaRegistry.from_project_root(ROOT))
    monkeypatch.setattr(d.custody_api, "CustodyStore", lambda root: {host.store.root: host.store, host.protected.root: host.protected}[Path(root)])
    return host


def test_real_protocol_custody_hold_flow_encrypts_inputs_and_exports_exact_terminal(host):
    session = d.constructdriver(**host.arguments())
    result = session.runturn(active_owner_instruction_bytes=hf.OWNER)
    assert result["answer"]["status"] == "HOLD"
    assert host.calls == ["planner", "final"]
    assert session.read_answer_projection(1) == result["answer"]
    assert session.read_terminal(1)["terminal_sha256"] == result["terminal_sha256"]
    assert session.read_evidence_pack(1)["evidence"] == []
    assert session.read_source_captures(1) == ()
    assert session.read_contracts(1) == {}
    assert host.protected.read("OBSERVED-GLOBAL-ONCE.bytes") == hf.OUTER
    assert any(path.endswith(".fernet") for path in host.protected.files)
    with pytest.raises(d.DriverHold, match="ALREADY_DISPATCHED"):
        session.runturn(active_owner_instruction_bytes=hf.OWNER)


def test_persistent_two_turn_hold_and_exact_host_due_history(host):
    session = d.constructdriver(**host.arguments())
    first = session.runturn(active_owner_instruction_bytes=hf.OWNER)
    history = [{"turn": 1, "request_sha256": first["request_sha256"], "terminal_sha256": first["terminal_sha256"]}]
    req = host.request(turn=2, history=history)
    req["question"] = "New synthetic due follow-up released after terminal."
    host.issue(req)
    due = d.DueTurn(req, {}, {}, [], host.cap, host.runtime(), STAMP)
    second = session.runturn(active_owner_instruction_bytes=hf.OWNER, due=due)
    assert second["answer"]["status"] == "HOLD" and host.calls == ["planner", "final", "planner", "final"]
    assert session.read_terminal(1)["terminal_sha256"] == first["terminal_sha256"]
    with pytest.raises(d.DriverHold, match="TECHNICAL_PRIOR_CONTRACT_SNAPSHOT_MISSING"):
        session._turns[2]._contracts_for({})
    with pytest.raises(d.DriverHold, match="FOLLOWUP_HISTORY_CHANGED"):
        session.runturn(active_owner_instruction_bytes=hf.OWNER, due=due)


def test_parent_marker_denial_and_foreign_runtime_fail_before_role_disclosure(host):
    args = host.arguments()
    with pytest.raises(d.DriverHold, match="ACTUAL_CUSTODY"):
        d.constructdriver(**{**args, "role_runtime": object()})
    session = d.constructdriver(**args)
    host.global_allowed = False
    with pytest.raises(d.DriverHold, match="HOST_EVIDENCE_VERIFICATION_DENIED"):
        session.runturn(active_owner_instruction_bytes=hf.OWNER)
    assert host.calls == [] and not host.store.files


def test_actual_code_pin_change_is_rejected_without_execution(host):
    args = host.arguments()
    bad = {**host.driver_pins.code_sha256s, "scripts/ge_auto_case_driver.py": H}
    with pytest.raises(d.DriverHold, match="DRIVER_CODE_CHANGED"):
        d.constructdriver(**{**args, "pins": replace(host.driver_pins, code_sha256s=bad)})
    assert host.calls == []


def test_terminal_read_api_detects_changed_evidence_pack(host):
    session = d.constructdriver(**host.arguments())
    session.runturn(active_owner_instruction_bytes=hf.OWNER)
    host.store.files["turn-0001/EvidencePack.json"] += b"changed"
    with pytest.raises((p.ProtocolError, hf.c.CustodyError), match="TAMPERED|VERIFIER_DENIED|CHANGED"):
        session.read_evidence_pack(1)


def test_native_receipt_translation_preserves_original_and_rejects_unknown_build():
    driver = d.CaseDriver.__new__(d.CaseDriver)
    driver._check_pins = lambda: None  # unit dependency seam only
    native = {"receipt_sha256": H, "generation_sha256": p.digest(b"native-generation")}
    wrapped = {**native, "receipt_sha256": p.digest(b"protected-wrapper")}
    driver.native_builds = {p.digest(wrapped): (copy.deepcopy(wrapped), copy.deepcopy(native))}
    calls = []
    driver.native_adapter = SimpleNamespace(retrieve=lambda e, r: calls.append((e, r)) or {"synthetic": True})
    driver._record = lambda *args: None
    driver._host_check = lambda *args: None
    driver._wrap_native = lambda kind, envelope, value: value
    envelope = {"data": {"build": wrapped, "public_queries": []}, "retry_profile_sha256": None}
    reservation = {"input_sha256": p.digest(envelope), "ordinal": 1}
    before = copy.deepcopy((envelope, reservation))
    driver.retrieve(envelope, reservation)
    assert (envelope, reservation) == before
    assert calls[0][0]["data"]["build"] == native
    assert calls[0][1] == {**reservation, "input_sha256": p.digest(calls[0][0])}
    envelope["data"]["build"]["generation_sha256"] = H
    with pytest.raises(d.DriverHold, match="UNOBSERVED_NATIVE_BUILD_TRANSLATION"):
        driver.retrieve(envelope, reservation)
    assert len(calls) == 1


def resolution(req):
    return d.GapResolution("issue-synthetic", ("g1",), "missing_authority", H, H, (), "LIMITED", "full_enquiry",
        p.canonical({"synthetic_empty_lookup_only": True, "request_sha256": p.digest(req)}))


def test_broker_hold_can_build_truthful_post_terminal_history_and_follow_up(host):
    args = host.arguments()
    host.research = True
    session = d.constructdriver(**args)
    first = session.runturn(active_owner_instruction_bytes=hf.OWNER)
    assert first["answer"]["status"] == "HOLD"
    assert any(name.endswith("response-ready.json") for name in host.store.files), {
        "holds": first["holds"], "files": {name: p.decode(raw) for name, raw in host.store.files.items()
            if name.endswith("failure.json")}}
    built = session.build_history_contract(1, resolution=resolution(host.request_value), observed_at=STAMP + timedelta(seconds=1))
    assert built.binding.knowledge_generation["sources"] == []
    assert built.binding.fact_snapshot["facts"][0]["origin"] == "user_statement"
    assert session.terminal_result == first and session.terminal_bytes == p.canonical({
        k: v for k, v in first.items() if k not in ("terminal_sha256", "dispatch")})
    assert "planner" in session.roles and session.contracts
    prior = d.contracts.PriorTurn(host.request_value, session.terminal_bytes, built, built.artifact_lineage["content_sha256"])
    old = session.terminal_bytes
    handle = session.prior_capture_observations(1)
    history = [{"turn": 1, "request_sha256": first["request_sha256"], "terminal_sha256": first["terminal_sha256"]}]
    req = host.request(turn=2, history=history)
    host.issue(req)
    host.research = False
    due = d.DueTurn(req, {}, {}, [prior], host.cap, host.runtime(), STAMP + timedelta(seconds=2), handle)
    second = session.runturn(active_owner_instruction_bytes=hf.OWNER, due=due)
    assert second["answer"]["status"] == "HOLD" and session._turns[1].terminal_bytes == old
    assert session.current_driver.history[0].contracts.artifact_lineage == built.artifact_lineage


def test_post_terminal_history_without_actual_planner_query_holds(host):
    session = d.constructdriver(**host.arguments())
    session.runturn(active_owner_instruction_bytes=hf.OWNER)
    with pytest.raises(d.DriverHold, match="ACTUAL_HISTORY_PLANNER_QUERY_REQUIRED"):
        session.build_history_contract(1, resolution=resolution(host.request_value), observed_at=STAMP)
    assert session.contracts == {}


def test_prior_capture_handles_are_live_family_scoped_and_recheck_files(host):
    session = d.constructdriver(**host.arguments())
    session.runturn(active_owner_instruction_bytes=hf.OWNER)
    driver = session.current_driver
    kwargs, base = ledger_fixture()
    # Test-only observed capture injection; assertions below test handle/tamper
    # behavior, not actual official capture or source approval.
    driver.store.files.update(kwargs["store"].files)
    raw_sha = p.digest(base64.b64decode(kwargs["original"]["raw_b64"]))
    driver.captures[raw_sha] = {"reservation": kwargs["reservation"], "capture": kwargs["original"],
                                "researcher_id": "synthetic-prior-selector"}
    handle = session.prior_capture_observations(1)
    target = SimpleNamespace(custody=driver.custody, root=driver.root, protected=driver.protected,
        policy=driver.policy, request={"case_id": driver.request["case_id"], "turn": 2})
    session._inherit_captures(target, handle)
    assert target.captures == driver.captures and target.captures is not driver.captures
    with pytest.raises(d.DriverHold, match="UNOBSERVED_CAPTURE_FAMILY_HANDLE"):
        session._inherit_captures(target, object())
    target.root = ROOT / "synthetic-other-case"
    with pytest.raises(d.DriverHold, match="PRIOR_CAPTURE_CUSTODY_CHANGED"):
        session._inherit_captures(target, handle)
    target.root = driver.root
    driver.store.files[base + "/raw.bytes"] += b"tampered"
    with pytest.raises(d.DriverHold, match="CAPTURE_READBACK_CHANGED"):
        session._inherit_captures(target, handle)


def test_actual_contract_capture_and_adapter_composition_without_inference(host):
    driver = d.CaseDriver(**host.arguments())
    driver._owner_bytes = hf.OWNER
    kwargs, _ = ledger_fixture()
    driver.store.files.update(kwargs["store"].files)
    original = kwargs["original"]
    prop = proposition(original)
    prop["jurisdiction"] = "Scotland"
    sha = p.digest(base64.b64decode(original["raw_b64"]))
    driver.captures[sha] = {"capture": original, "reservation": kwargs["reservation"], "researcher_id": "selector-synthetic"}
    plan = {"queries": [{"gap_id": "g1", "kind": "missing_authority", "query": "Scotland synthetic public rule",
                        "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}], "clarifications": [], "holds": []}
    review = {"sources": [kwargs["source_review"]], "propositions": [{"proposition_id": prop["proposition_id"],
        "proposition_sha256": p.digest(prop), "decision": "ELIGIBLE", "holds": [], "checks": dict.fromkeys(p.PROPOSITION_CHECKS, True)}]}
    driver.roles = {name: {"context_id": name + "-synthetic", "input_sha256": H, "receipt_sha256": H, "output": output}
                    for name, output in {"planner": plan, "selector": {"urls": [hf.URL], "holds": []},
                                         "mapper": {"propositions": [prop], "holds": []}, "reviewer": review}.items()}
    data = {"case_id": driver.request["case_id"], "lane": "candidate_case_local",
        "lineage": {"request_sha256": driver.request_sha, "policy_sha256": p.digest(driver.policy.manifest())},
        "baseline_sha256": d.EMPTY, "baseline_kind": "EMPTY", "own_prior_generations": [],
        "sources": [original], "propositions": [prop], "review_sha256": p.digest(review),
        "public_queries": [{k: plan["queries"][0][k] for k in ("query", "jurisdiction", "as_of_date")}]}
    driver._make_adapter(data)
    assert type(driver.native_adapter) is d.adapter.CaseIndexAdapter
    assert type(driver.research_policy) is research.ResearchPolicy
    value = driver.contracts[prop["proposition_id"]]
    assert value.binding.query_plan["request_sha256"] == driver.request_sha
    assert value.binding.knowledge_generation["counts"]["chunks"] == 0
    fact = value.binding.fact_snapshot["facts"][0]
    assert fact["origin"] == "user_statement"
    encrypted_path = driver.prefix + "/encrypted/" + fact["encrypted_value_ref"] + ".fernet"
    assert driver.vault._cipher.decrypt(driver.host_store.read(encrypted_path)) == driver.request["question"].encode()
    assert driver.native_adapter.bindings[prop["proposition_id"]].contracts is value.binding
    assert len(driver.translated_reviews) == 1
    assert not any(name.startswith("legal-index/") for name in driver.store.files)


def test_answer_review_material_comes_from_selected_live_source_bindings():
    kwargs, _ = ledger_fixture()
    capture, mapping = d.capture_from_ledger(**kwargs)
    original = kwargs["original"]
    prop = proposition(original)
    raw_sha = p.digest(capture.raw)
    evidence_id = "evidence-synthetic"
    source_binding = d.adapter.SourceBinding(capture, mapping, tuple(mapping.values()))
    driver = d.CaseDriver.__new__(d.CaseDriver)
    driver.request = {"case_id": "synthetic-case"}
    driver.roles = {
        "planner": {"output": {"queries": [{"query": "Synthetic public rule"}],
                                  "clarifications": []}},
        "reviewer": {"context_id": "source-review-context"},
        "final": {"context_id": "final-context", "receipt_sha256": H},
    }
    driver.native_adapter = SimpleNamespace(bindings={
        prop["proposition_id"]: d.adapter.PropositionBinding(
            SimpleNamespace(), (source_binding,))})
    driver.captures = {raw_sha: {"capture": original}}
    translated = {"source_sha256": raw_sha, "parsed_sha256": p.digest(b"parsed"),
                  "valid_from": "2026-09-05", "valid_to": "2026-09-05"}
    driver.translated_reviews = {H: translated}
    driver.read_terminal = lambda: {"answer": {"status": "ANSWER", "answer": "Synthetic",
        "cited_proposition_ids": [prop["proposition_id"]]}, "rendered_answer": "Synthetic"}
    driver.read_evidence_pack = lambda: {"evidence": [{"proposition": prop}],
        "source_references": []}
    driver.read_selected_retrieval_contracts = lambda: {
        "query_plan": {"issue_ids": ["issue-synthetic"]},
        "evidence_pack": {"selected": [{"source_version_id": "source-version-synthetic",
            "evidence_id": evidence_id, "jurisdiction": "England"}]},
        "component_receipts": [{"source_version_id": "source-version-synthetic",
            "source_sha256": raw_sha, "evidence_id": evidence_id}],
    }
    driver.read_fact_projection = lambda: {"schema": "synthetic-fact-projection"}
    material = driver.read_answer_review_material()
    source = material["evidence"]["sources"][0]
    assert source["selected_evidence_id"] == evidence_id
    assert source["raw_sha256"] == raw_sha
    assert source["required_context_block_ids"] == [part["part_id"] for part in original["parts"]]
    assert [block["text"] for block in source["blocks"]] == [part["text"] for part in original["parts"]]
    assert material["source_review"]["reviewer_ids"] == ["source-review-context"]
    assert material["requirements"][0]["requirement_id"] == "issue-synthetic"


def test_normalizes_specific_native_hold_for_protocol_without_approving(host):
    driver = d.CaseDriver(**host.arguments())
    def held(*args):
        raise d.adapter.AdapterHold("CHUNK_CONTEXT_REVIEW_REQUIRED")
    driver.native_adapter = SimpleNamespace(index=held)
    with pytest.raises(p.ActionHold, match="CHUNK_CONTEXT_REVIEW_REQUIRED") as caught:
        driver.index({}, {})
    assert type(caught.value) is p.ActionHold


def test_pinned_callback_owner_cannot_be_swapped_after_initial_check(host):
    driver = d.CaseDriver(**host.arguments())
    other = SyntheticDriverHost.__new__(SyntheticDriverHost)
    driver.service_web = other.web  # Identical bytecode, different host custody.
    with pytest.raises(d.DriverHold, match="TRUSTED_HOST_WEB_CALLBACK_CHANGED"):
        driver._check_pins()
