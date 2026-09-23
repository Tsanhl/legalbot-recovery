"""Synthetic in-memory custody integration; no actual roles, network or index.

The protocol/bridge/intake execute real code on our own synthetic inputs. The
role runtime entry point and OS profile are explicit test doubles, with their own
test-only pins; these tests do NOT establish actual model, fence or inference
readiness. No temp files, deletion, bank or evaluation artifact reads occur.
"""
from __future__ import annotations

import copy
import marshal
import re
import sys
import types
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts import ge_auto_case_custody as c
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as b
from scripts import ge_auto_research_intake as intake
from scripts import ge_auto_role_runtime as roles

ROOT = Path("/synthetic-workspace")
URL = "https://www.legislation.gov.uk/synthetic-test-only"
NOW = "2026-09-05T00:00:00+00:00"
OWNER = b"SYNTHETIC owner instruction: UK USA, non-live, EMPTY baseline, no training."
OUTER = b"SYNTHETIC actual-parent-marker stand-in; not an execution authorization."
H = p.digest(b"SYNTHETIC PIN, no actual model/CLI/inference evidence")
HTML = b"<html><body><h1>Synthetic source</h1><p>Only synthetic condition A applies.</p></body></html>"


class MemoryStore:
    def __init__(self, root):
        self.root, self.files, self.dirs = Path(root), {}, {""}
        self.accesses, self.locked = [], False
    def read(self, name):
        p.parts(name)
        self.accesses.append(("read", name))
        if name not in self.files:
            raise FileNotFoundError(name)
        return self.files[name]
    def exists(self, name):
        p.parts(name)
        return name in self.files or name in self.dirs
    def mkdir_new(self, name):
        p.parts(name)
        if self.exists(name):
            raise FileExistsError(name)
        assert name.rpartition("/")[0] in self.dirs
        self.dirs.add(name)
    def write_new(self, name, raw):
        p.parts(name)
        assert isinstance(raw, bytes) and len(raw) <= p.MAX_BYTES
        if self.exists(name):
            raise FileExistsError(name)
        assert name.rpartition("/")[0] in self.dirs
        self.accesses.append(("write", name))
        self.files[name] = raw
    def names(self, name):
        prefix = name + "/"
        return sorted({path[len(prefix):].split("/")[0] for path in self.files.keys() | self.dirs
                       if path.startswith(prefix)})
    def inventory(self, name):
        prefix = name + "/"
        return {path[len(prefix):]:p.digest(raw) for path,raw in self.files.items() if path.startswith(prefix)}
    @contextmanager
    def lock(self):
        assert not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False


def fake_role_call(runtime, job):
    """Pinned synthetic entry point, never launches subprocesses."""
    return runtime.test_host.complete(runtime, job)


def fake_profile(work):
    return "SYNTHETIC FENCE ONLY " + str(work)


def warming_role_host(monkeypatch):
    """A successful synthetic role caches regex constants like the real runtime.

    The unique pattern prevents interference with any other test's regex cache.
    No hash mock, CLI, disk write, model invocation or cache purge is used.
    """
    namespace = {'re': re}
    source = ('def call(runtime, job):\n'
              '    result = runtime.test_host.complete(runtime, job)\n'
              '    re.search(r"(?m)^model:\\s*(\\S+)(?#' + uuid.uuid4().hex + ')", "model: synthetic")\n'
              '    return result\n')
    exec(compile(source, '<synthetic-role-regex-cache>', 'exec'), namespace)
    function = namespace['call']
    monkeypatch.setattr(roles.CodexRoleRuntime, '__call__', function)
    monkeypatch.setattr(sys.modules[__name__], 'fake_role_call', function)
    monkeypatch.setattr(roles, 'profile', fake_profile)
    return Host(), function


class Host:
    def __init__(self):
        self.key, self.owner, self.global_allowed = object(), OWNER, True
        self.protected = MemoryStore(ROOT / "protected")
        self.store = MemoryStore(ROOT / "cases/A")
        self.policy = p.FrozenPolicy("synthetic-run", p.digest(OWNER), H, "EMPTY", p.digest([]))
        self.pins = {name:H for name in c.PIN_HASHES}
        # Bind actual public runtime code bytes; all role execution stays synthetic.
        self.pins['role_runtime_sha256'] = p.digest(Path(roles.__file__).read_bytes())
        self.pins.update(model="gpt-synthetic-test",provider="openai",
            cli_identity={"version":"SYNTHETIC", "launcher_sha256":H,"package_sha256":H,"native_sha256":H},
            role_callback_sha256=b.callback_sha256(fake_role_call),
            parser_sha256=intake.parser_binding(include_legal_tables=True),
            transport_callback_sha256=b.callback_sha256(self.transport),
            parser_callback_sha256=b.callback_sha256(b.parse_official_capture),
            index_callback_sha256=b.callback_sha256(self.index), retrieve_callback_sha256=b.callback_sha256(self.retrieve),
            active_owner_reader_sha256=b.callback_sha256(self.active_owner), query_privacy_sha256=b.callback_sha256(self.privacy),
            global_marker_verifier_sha256=b.callback_sha256(self.verify_marker))
        self.ledger = self.new_ledger()
        self.elapsed, self.calls, self.mutation = 0, [], None
        self.research, self.native = False, {}

    def new_ledger(self, **changes):
        args={"workspace_root":ROOT,"trusted_root":self.protected.root,"policy":self.policy,"pins":self.pins,
            "host_key":self.key,"active_owner_instruction":self.active_owner,"query_privacy":self.privacy,
            "global_marker_verifier":self.verify_marker,"store":self.protected}
        return c.CaseCustody(**(args|changes))

    def active_owner(self):
        return self.owner
    def privacy(self, binding, query):
        return (binding["case_root"] == str(self.store.root) and query["jurisdiction"] == "Scotland"
                and "PRIVATE" not in query["query"] and "@" not in query["query"])
    def verify_marker(self, binding, raw):
        return (self.global_allowed and raw == OUTER and binding == {"run_id":self.policy.run_id,
            "policy_sha256":p.digest(self.policy.manifest()),"baseline_sha256":p.digest([]),"runtime_sha256":H,
            "owner_instruction_sha256":p.digest(OWNER),"marker_sha256":p.digest(OUTER)})
    def request(self, *, case_id="case-A", turn=1, history=None):
        return {"schema":p.VERSION,"case_id":case_id,"turn":turn,"question":"PRIVATE synthetic person needs clarification.",
            "jurisdictions":["Scotland"],"as_of_date":"2026-09-05","due_uploads":[],"history":history or []}
    def issue(self, request=None, store=None):
        self.request_value = request or self.request()
        self.store = store or self.store
        self.cap = self.ledger.issue_case(self.key,case_root=self.store.root,request=self.request_value,store=self.store)
        self.protocol = p.CaseProtocol(case_root=self.store.root,policy=self.policy,capability=self.cap,
                                      guard=self.ledger.protocol_guard,store=self.store)
        return self.cap
    def runtime(self):
        runtime=roles.CodexRoleRuntime.__new__(roles.CodexRoleRuntime)
        runtime.case_root,runtime.protected_root=self.store.root,self.protected.root
        runtime.model,runtime.provider=self.pins["model"],self.pins["provider"]
        runtime.expected_cli,runtime.capability,runtime.verify=self.pins["cli_identity"],self.cap,self.ledger.role_guard
        runtime.receipts,runtime.test_host={},self
        return runtime

    def output(self, job):
        data=job.input["payload"]
        if job.role=="planner":
            return {"queries":[{"gap_id":"g1","kind":"missing_authority","query":"Scotland synthetic public rule",
                "jurisdiction":"Scotland","as_of_date":"2026-09-05"}] if self.research else [],
                "clarifications":[],"holds":[] if self.research else ["INSUFFICIENT_AUTHORITY"]}
        if job.role=="selector":
            return {"urls":[URL],"holds":[]}
        if job.role=="mapper":
            source=data["sources"][0]
            part=source["parts"][-1]
            span={"source_sha256":source["source_sha256"],"part_id":part["part_id"],"start":0,"end":len(part["text"]),"text":part["text"]}
            return {"propositions":[{"proposition_id":"synthetic-p1","jurisdiction":"Scotland","as_of_date":"2026-09-05",
                "point":span,"conditions":[span],"context":[span],"currentness":{"status":"VERIFIED","checks":[span],
                "valid_from":"2026-01-01","valid_to":"2026-12-31"}}],"holds":[]}
        if job.role=="reviewer":
            return {"sources":[{"source_sha256":s["source_sha256"],"decision":"ELIGIBLE",
                "checks":dict.fromkeys(p.SOURCE_CHECKS,True),"holds":[]} for s in data["sources"]],
                "propositions":[{"proposition_id":prop["proposition_id"],"proposition_sha256":p.digest(prop),
                "decision":"ELIGIBLE","checks":dict.fromkeys(p.PROPOSITION_CHECKS,True),"holds":[]}
                for prop in data["mapping"]["propositions"]]}
        return {"status":"HOLD","answer":"Synthetic-only result; no actual model assurance.","cited_proposition_ids":[]}

    def complete(self, runtime, job):
        binding={"case_root":str(self.store.root),"job_root":str(job.root),"role":job.role,
            "context_id":job.context_id,"input_sha256":job.input_sha256,"model":runtime.model,
            "provider":runtime.provider,"browse":False}
        assert runtime.verify(runtime.capability,binding) is True
        self.calls.append(job.role)
        relative=job.root.relative_to(self.store.root).as_posix()
        inventory=self.store.inventory(relative)
        self.protected.mkdir_new(job.context_id)
        started={**binding,"started":NOW,"fresh_context":True,"cli_identity":self.pins["cli_identity"],
            "input_inventory":inventory,"runtime_file_sha256":self.pins['role_runtime_sha256'],"training":False,
            "fence":{"own_exact_input_readable":True,"outside_public_file_denied":True,"input_write_open_denied":True,
                "private_bank_probe":"NOT_ATTEMPTED","profile_sha256":p.digest(fake_profile(job.root).encode())}}
        if self.mutation=="fence":
            started["fence"]["outside_public_file_denied"]=False
        if self.mutation=="cli":
            started["cli_identity"]={**started["cli_identity"],"native_sha256":p.digest(b"other cli")}
        if self.mutation=="inventory":
            started["input_inventory"]={}
        start_raw=p.canonical(started)
        self.protected.write_new(job.context_id+"/START.json",start_raw)
        out=self.output(job)
        output_raw=p.canonical(out)
        self.store.write_new(relative+"/output.json",output_raw)
        stdout=b"Synthetic process stdout"
        stderr=f"model: {runtime.model}\nprovider: {runtime.provider}\n".encode()
        if self.mutation=="model":
            stderr=b"model: gpt-other\nprovider: openai\n"
        if self.mutation=="provider":
            stderr=b"model: gpt-synthetic-test\nprovider: other\n"
        self.protected.write_new(job.context_id+"/stdout.log",stdout)
        self.protected.write_new(job.context_id+"/stderr.log",stderr)
        receipt={**started,"completed":NOW,"start_sha256":p.digest(start_raw),"returncode":0,"error":None,
            "stdout_sha256":p.digest(stdout),"stderr_sha256":p.digest(stderr),"output_sha256":p.digest(output_raw)}
        if getattr(self, "reference_transport", False) and job.role == "mapper":
            refs = copy.deepcopy(out)
            for prop in refs["propositions"]:
                for span in [prop["point"], *prop["conditions"], *prop["context"], *prop["currentness"]["checks"]]:
                    span.pop("text", None)
            resolved, materialization = p.materialize_mapper_spans(refs, job.input["payload"])
            assert resolved == out
            refs_raw = p.canonical(refs)
            if self.mutation == "materialization":
                materialization["span_count"] += 1
            materialization_raw = p.canonical(materialization)
            self.store.write_new(relative + "/span-references.json", refs_raw)
            self.store.write_new(relative + "/span-materialization.json", materialization_raw)
            receipt.update(model_output_sha256=p.digest(refs_raw),
                           span_materialization_sha256=p.digest(materialization_raw))
        if self.mutation=="output":
            receipt["output_sha256"]=p.digest(b"different output")
        if self.mutation=="input":
            self.store.files[relative+"/input.json"]=b"{}"  # Explicit synthetic corruption, no disk mutation.
        raw=p.canonical(receipt)
        self.protected.write_new(job.context_id+"/COMPLETE.json",raw)
        sha=p.digest(raw)
        if self.mutation!="unissued":
            runtime.receipts[sha]=self.protected.root/job.context_id/"COMPLETE.json"
        return {"context_id":job.context_id,"input_sha256":job.input_sha256,"receipt_sha256":sha,"output":out}

    def sleep(self, seconds):
        self.elapsed+=seconds
        case=self.ledger._case(self.cap)
        reservation=next(r for (kind,_),(r,_) in case["operations"].items()
                         if kind=="search" and p.digest(r) not in case["web"])
        self.ledger.publish_web_response(self.key,self.cap,reservation,raw_utf8='{"synthetic_tool_double":true}',
            hits=[{"url":URL,"title":"Synthetic source","snippet":"Synthetic discovery"}],tool_call_id="synthetic-call-1")

    def transport(self, url, *, max_bytes, timeout_seconds, emit):
        assert url==URL
        value={"canonical_url":url,"final_url":url,"redirect_chain":[],"fetched_at":NOW,
            "raw_sha256":p.digest(HTML),"byte_count":len(HTML),"http_status":200}
        emit("raw.bytes",HTML)
        emit("transport.json",value)
        return value

    def observation(self, kind, envelope, result):
        if not self.store.exists("legal-index"):
            self.store.mkdir_new("legal-index")
        name="legal-index/"+kind+"-"+p.digest(envelope)+".json"
        self.store.write_new(name,p.canonical({"synthetic_native_double":kind,"input":p.digest(envelope)}))
        files={name:p.digest(self.store.files[name])}
        if not self.protected.exists("index"):
            self.protected.mkdir_new("index")
        path="index/"+kind+"-"+p.digest(envelope)+".json"
        case=self.ledger._case(self.cap)
        receipt={**self.ledger._common(case),"kind":kind,"input_sha256":p.digest(envelope),
            "result_sha256":p.digest(result),"index_runtime_sha256":H,"embedding_model_sha256":H,
            "non_live":True,"active_mutated":False,"synthetic_vectors":False,"files":files}
        self.protected.write_new(path,p.canonical(receipt))
        result={**result,"receipt_sha256":p.digest(self.protected.files[path])}
        return c.IndexObservation(result,path,files)
    def index(self, envelope, reservation):
        legal=envelope["data"]
        build=p.digest({"synthetic_build":p.digest(legal)})
        self.native[build]=copy.deepcopy(legal)
        return self.observation("index",envelope,{"build_sha256":build,"generation_sha256":p.digest({"generation":build}),
            "baseline_sha256":p.digest([]),"legal_input_sha256":p.digest(legal),"case_id":self.request_value["case_id"],
            "non_live":True,"active_mutated":False})
    def retrieve(self, envelope, reservation):
        built=envelope["data"]["build"]
        legal=self.native[built["build_sha256"]]
        return self.observation("retrieve",envelope,{"baseline_sha256":p.digest([]),"generation_sha256":built["generation_sha256"],
            "evidence":[{"origin":"CASE_LOCAL","proposition":prop,"eligibility_receipt_sha256":legal["review_sha256"]}
                        for prop in legal["propositions"]]})

    def run(self):
        self.ledger.register_global_marker(self.key,marker_bytes=OUTER)
        return self.protocol.run_case(self.request_value,uploads={},
            establish_one_pass=lambda binding:self.ledger.establish_one_pass(self.key,self.cap,binding),
            invoke_role=self.ledger.role_callback(self.key,self.cap,self.runtime()),
            search=self.ledger.search_callback(self.key,self.cap,timeout_seconds=5,poll_seconds=1,
                monotonic=lambda:self.elapsed,sleep=self.sleep),
            capture=self.ledger.capture_callback(self.key,self.cap,transport=self.transport,now=lambda:NOW),
            official_url=b.is_allowed_source_url,
            index=self.ledger.index_callback(self.key,self.cap,"index",self.index),
            retrieve=self.ledger.index_callback(self.key,self.cap,"retrieve",self.retrieve))


@pytest.fixture
def host(monkeypatch):
    monkeypatch.setattr(roles.CodexRoleRuntime,"__call__",fake_role_call)
    monkeypatch.setattr(roles,"profile",fake_profile)
    return Host()


def binding(host, action, **details):
    case=host.ledger._case(host.cap)
    return {**host.ledger._common(case),"action":action,**details}


def test_role_callback_survives_successful_regex_cache_warmup(monkeypatch):
    host, function = warming_role_host(monkeypatch)
    code = function.__code__
    legacy_before = p.digest(marshal.dumps(code, 4))
    host.issue()
    host.research = True
    result = host.run()
    assert host.calls == ['planner', 'selector', 'mapper', 'reviewer', 'final']
    assert function is roles.CodexRoleRuntime.__call__ and function.__code__ is code
    # Preserve the original failure mechanism even when the shared helper uses
    # stable serialization. This does not mock any callback hash or invocation.
    assert p.digest(marshal.dumps(code, 4)) != legacy_before
    assert result['answer']['status'] == 'HOLD'
    # New wrapper for another role/turn must reuse the same custody-level code
    # binding; hashing the now-warmed function again would fail at the factory.
    host.ledger.role_callback(host.key, host.cap, host.runtime())


def test_role_callback_initial_external_pin_is_still_required(host):
    host.issue()
    host.ledger.pins['role_callback_sha256'] = p.digest(b'unapproved role code')
    with pytest.raises(c.CustodyError, match='ACTUAL_PINNED_ROLE_RUNTIME_REQUIRED'):
        host.ledger.role_callback(host.key, host.cap, host.runtime())
    assert host.ledger._role_binding is None and host.calls == []


@pytest.mark.parametrize('change', ['function', 'code', 'bound_owner', 'verifier_owner',
                                   'model', 'provider', 'capability', 'pin',
                                   'module_file', 'module_bytes', 'module_pin'])
def test_role_callback_replacements_still_refused_before_next_role(host, monkeypatch, change):
    host.issue()
    runtime = host.runtime()
    invoke = host.ledger.role_callback(host.key, host.cap, runtime)
    function = roles.CodexRoleRuntime.__call__
    if change == 'function':
        # Even a replacement with the exact same code/hash cannot take over.
        replacement = types.FunctionType(function.__code__, function.__globals__)
        monkeypatch.setattr(roles.CodexRoleRuntime, '__call__', replacement)
    elif change == 'code':
        # Equal bytes in a newly allocated code object are still a replacement.
        monkeypatch.setattr(function, '__code__', function.__code__.replace())
    elif change == 'bound_owner':
        runtime.__call__ = types.MethodType(function, host.runtime())
    elif change == 'verifier_owner':
        runtime.verify = types.MethodType(host.ledger.role_guard.__func__, object())
    elif change == 'model': runtime.model = 'gpt-other'
    elif change == 'provider': runtime.provider = 'other'
    elif change == 'capability': runtime.capability = object()
    elif change == 'module_file': monkeypatch.setattr(roles, '__file__', __file__)
    elif change == 'module_bytes':
        original_read = Path.read_bytes
        module_path = Path(roles.__file__)
        monkeypatch.setattr(Path, 'read_bytes', lambda path: b'changed runtime bytes'
                            if path == module_path else original_read(path))
    elif change == 'module_pin': host.ledger.pins['role_runtime_sha256'] = H
    else: host.ledger.pins['role_callback_sha256'] = p.digest(b'changed callback pin')
    # A legitimate RoleJob class reaches the pre-invocation guard. No fake
    # receipt, inventory or record is needed: rejection precedes those accesses.
    job = p.RoleJob(role='selector', root=host.store.root / 'unused', input={},
                    input_sha256=H, context_id='unlaunched-context', schema=p.SELECTOR_SCHEMA,
                    prompt=p.PROMPTS['selector'], allow_browsing=False)
    with pytest.raises(c.CustodyError, match='PINNED_ROLE_JOB_AND_RUNTIME_REQUIRED'):
        invoke(job)
    assert host.calls == []
    with pytest.raises(c.CustodyError, match='ACTUAL_PINNED_ROLE_RUNTIME_REQUIRED'):
        host.ledger.role_callback(host.key, host.cap, runtime)


def test_real_protocol_hold_flow_uses_protected_role_receipts_and_actual_parent_marker_observation(host):
    host.issue()
    result=host.run()
    assert host.calls==["planner","final"] and result["answer"]["status"]=="HOLD"
    assert result["actual_parent_validation"]=="NOT_ESTABLISHED_BY_PROTOCOL"
    assert host.protected.files["OBSERVED-GLOBAL-ONCE.bytes"]==OUTER
    assert "GLOBAL-ONCE.json" not in host.protected.files
    retained=dict(host.store.files)
    again=host.run()
    assert again["dispatch"]=="NO_OP_COMPLETE" and host.calls==["planner","final"]
    assert host.store.files==retained


def test_real_protocol_bridge_and_intake_with_synthetic_native_observations(host):
    host.research=True
    host.issue()
    result=host.run()
    assert host.calls==["planner","selector","mapper","reviewer","final"]
    case=host.ledger._case(host.cap)
    assert len({r["context_id"] for r in case["roles"].values()})==5
    assert len(case["web"])==len(case["capture"])==1
    assert {key[0] for key in case["index"]}=={"index","retrieve"}
    assert result["generation_sha256"] and result["answer"]["status"]=="HOLD"
    assert all(not e.get("admitted",False) for e in [p.decode(raw) for name,raw in host.protected.files.items() if name.startswith("CUSTODY-")])


@pytest.mark.parametrize("tamper", [False, True])
def test_mapper_reference_materialization_is_recomputed_by_custody(host, tamper):
    host.research = True
    host.reference_transport = True
    host.mutation = "materialization" if tamper else None
    host.issue()
    if tamper:
        with pytest.raises(c.CustodyError, match="SPAN_MATERIALIZATION_CHANGED"):
            host.run()
        assert "reviewer" not in host.calls
    else:
        result = host.run()
        assert "reviewer" in host.calls
        assert result["generation_sha256"]


@pytest.mark.parametrize("capability", [None, {}, {"authorized":True}, "capability", object()])
def test_payload_created_or_unissued_caps_cannot_use_guard_or_host_registration(host, capability):
    host.issue()
    value=binding(host,"case_protocol_start")
    assert host.ledger.protocol_guard(capability,value) is False
    with pytest.raises(c.CustodyError,match="HOST_ONLY"):
        host.ledger.register_global_marker(capability,marker_bytes=OUTER)


@pytest.mark.parametrize("field,value", [("case_id","other"),("case_root",str(ROOT/"cases/B")),
    ("request_sha256",p.digest(b"other request")),("policy_sha256",H),("baseline_sha256",H),
    ("index_root",str(ROOT/"other-index")),("lane","shared_research"),("run_id","other-run")])
def test_exact_protocol_scope_hash_swaps_are_denied(host, field, value):
    host.issue()
    data=binding(host,"case_protocol_start")
    data[field]=value
    assert host.ledger.protocol_guard(host.cap,data) is False


def test_unknown_actions_extra_fields_and_fake_actual_receipts_are_denied(host):
    host.issue()
    for action,fields in [("invented_action",{}),("case_protocol_start",{"approved":True}),
        ("actual_web_result",{"raw_sha256":H,"tool_receipt_sha256":H,"hits_sha256":H}),
        ("actual_capture_parse",dict.fromkeys(c.PROTOCOL_FIELDS["actual_capture_parse"],H)),
        ("actual_retrieved_evidence",{"result_sha256":H,"index_receipt_sha256":H}),
        ("actual_retrieved_evidence",{"result_sha256":H,"index_receipt_sha256":None}),
        ("role_receipt",{"role":"reviewer","context_id":"invented","receipt_sha256":H,"output_sha256":H})]:
        assert host.ledger.protocol_guard(host.cap,binding(host,action,**fields)) is False
    assert host.ledger.role_guard(host.cap,{"authorized":True}) is False
    assert host.ledger.bridge_guard(host.cap,{"action":"invented_action"}) is False


def test_owner_revocation_and_protected_ledger_change_fail_closed(host):
    host.issue()
    value=binding(host,"case_protocol_start")
    host.owner=b"new revoked instruction"
    assert host.ledger.protocol_guard(host.cap,value) is False
    host.owner=OWNER
    host.protected.files["CUSTODY-START.json"]=b'{"self_sealed":"forged"}'
    assert host.ledger.protocol_guard(host.cap,value) is False


def test_no_local_marker_substitute_without_actual_pinned_parent_verification(host):
    host.issue()
    case=host.ledger._case(host.cap)
    with pytest.raises(c.CustodyError,match="ACTUAL_PARENT_GLOBAL"):
        host.ledger.establish_one_pass(host.key,host.cap,host.ledger._marker_input(case))
    host.global_allowed=False
    with pytest.raises(c.CustodyError,match="GLOBAL_MARKER_NOT_VERIFIED"):
        host.ledger.register_global_marker(host.key,marker_bytes=OUTER)
    assert "OBSERVED-GLOBAL-ONCE.bytes" not in host.protected.files
    host.global_allowed=True
    with pytest.raises(c.CustodyError):
        host.ledger.register_global_marker(host.key,marker_bytes=b"forged self-sealed marker")


@pytest.mark.parametrize("mutation", ["fence","cli","inventory","model","provider","output","input","unissued"])
def test_actual_role_completion_must_match_protected_execution_and_readonly_files(host,mutation):
    host.issue()
    host.mutation=mutation
    with pytest.raises((c.CustodyError,p.ProtocolError)):
        host.run()
    case=host.ledger._case(host.cap)
    assert not case["outputs"].get("role_receipts")
    assert any(name.endswith("COMPLETE.json") for name in host.protected.files)
    assert not any(name.endswith("terminal.json") for name in host.store.files)


def test_public_privacy_is_mandatory_and_denial_never_authorizes_search(host):
    host.issue()
    query={"gap_id":"g1","kind":"missing_authority","query":"PRIVATE person's unique transaction",
           "jurisdiction":"Scotland","as_of_date":"2026-09-05"}
    assert host.ledger.protocol_guard(host.cap,binding(host,"public_query",query=query,query_sha256=p.digest(query))) is False
    assert not host.ledger._case(host.cap)["queries"]


@pytest.mark.parametrize('change', ['remove_filter', 'query', 'jurisdiction', 'as_of_date'])
def test_web_response_refuses_changed_discovery_arguments_or_public_input(host, monkeypatch, change):
    host.research = True
    host.issue()
    def tamper_then_publish(seconds):
        name = next(name for name in host.store.files if name.startswith('broker/search-')
                    and name.endswith('/request.json'))
        request = p.decode(host.store.files[name])
        expected = b.search_arguments(request['public_input'])
        assert request['tool_arguments'] == expected
        if change == 'remove_filter':
            request['tool_arguments'] = {'search_query': [{'q': request['public_input']['query']}],
                                         'response_length': 'long'}
            assert request['tool_arguments'] != expected
        elif change == 'query':
            request['tool_arguments']['search_query'][0]['q'] = 'substituted query'
        elif change == 'jurisdiction':
            request['public_input']['jurisdiction'] = 'England'
        else:
            request['public_input']['as_of_date'] = '2000-01-01'
        host.store.files[name] = p.canonical(request)  # synthetic tampering, no disk writes
        Host.sleep(host, seconds)
    monkeypatch.setattr(host, 'sleep', tamper_then_publish)
    with pytest.raises(c.CustodyError, match='WEB_REQUEST_CHANGED'):
        host.run()
    assert not host.ledger._case(host.cap)['web']
    assert not any(name.endswith('/response-ready.json') for name in host.store.files)


def test_cross_case_receipt_and_retrieval_hashes_do_not_cross_capabilities(host):
    host.research=True
    cap_a=host.issue()
    host.run()
    a=host.ledger._case(cap_a)
    web=next(iter(a["web"].values()))
    parse=next(iter(a["capture"].values()))["parse_binding"]
    retrieval=next((sha,value) for (kind,sha),value in a["index"].items() if kind=="retrieve")
    host.issue(host.request(case_id="case-B"),MemoryStore(ROOT/"cases/B"))
    assert host.ledger.protocol_guard(host.cap,binding(host,"actual_web_result",**{k:web[k] for k in c.PROTOCOL_FIELDS["actual_web_result"]})) is False
    assert host.ledger.protocol_guard(host.cap,binding(host,"actual_capture_parse",**parse)) is False
    assert host.ledger.protocol_guard(host.cap,binding(host,"actual_retrieved_evidence",result_sha256=retrieval[0],index_receipt_sha256=retrieval[1]["index_receipt_sha256"])) is False


def test_same_case_history_exact_terminal_and_final_once_are_preserved(host):
    host.issue()
    first=host.run()
    retained=dict(host.store.files)
    previous=host.request_value
    next_request=host.request(turn=2,history=[{"turn":1,"request_sha256":p.digest(previous),"terminal_sha256":first["terminal_sha256"]}])
    host.issue(next_request)
    second=host.run()
    assert second["turn"]==2 and host.calls==["planner","final","planner","final"]
    assert all(host.store.files[name]==raw for name,raw in retained.items())
    changed=copy.deepcopy(next_request)
    changed["question"]="changed private prompt"
    with pytest.raises(c.CustodyError,match="SEALED_TURN"):
        host.issue(changed)


def test_forged_or_other_case_history_and_trusted_root_overlap_are_refused(host):
    host.issue()
    with pytest.raises(c.CustodyError):
        host.ledger.issue_case(host.key,case_root=host.protected.root,request=host.request(case_id="case-B"),store=host.protected)
    request=host.request(turn=2,history=[{"turn":1,"request_sha256":H,"terminal_sha256":H}])
    with pytest.raises(c.CustodyError,match="UNSEALED_OR_FAILED"):
        host.issue(request)
    with pytest.raises(FileExistsError):
        host.new_ledger()  # No reload of self-sealed files as fresh host authority.


def test_protected_scoring_receipt_closes_case_without_changing_prior_terminal(host):
    host.issue()
    result=host.run()
    retained=dict(host.store.files)
    host.protected.mkdir_new("scoring")
    receipt={**host.ledger._common(host.ledger._case(host.cap)),"terminal_sha256":result["terminal_sha256"],"opaque_scoring_receipt":True}
    raw=p.canonical(receipt)
    host.protected.write_new("scoring/result.json",raw)
    host.ledger.register_scoring(host.key,host.cap,protected_receipt="scoring/result.json",receipt_sha256=p.digest(raw))
    host.protocol.mark_scored(case_id=host.request_value["case_id"],receipt_sha256=p.digest(raw))
    assert all(host.store.files[name]==value for name,value in retained.items())
    assert host.ledger.protocol_guard(host.cap,binding(host,"case_protocol_start")) is False


def test_common_empty_baseline_and_explicit_callback_pins_cannot_be_relaxed(host):
    with pytest.raises(c.CustodyError,match="EMPTY"):
        host.new_ledger(policy=p.FrozenPolicy("synthetic-run",p.digest(OWNER),H,"SHARED_FROZEN",H))
    changed={**host.pins,"query_privacy_sha256":p.digest(b"different privacy callback")}
    with pytest.raises(c.CustodyError,match="CALLBACK_PIN"):
        host.new_ledger(pins=changed)


def test_upload_receipt_has_no_circular_request_hash_and_is_host_registered_only(host):
    raw=b"Synthetic extracted upload"
    upload={"upload_id":"u1","sha256":p.digest(raw),"media_type":"text/plain","text":raw.decode(),"text_sha256":p.digest(raw)}
    receipt={"case_root":str(host.store.root),"index_root":str(host.store.root/"legal-index"),
        "case_id":"case-A","policy_sha256":p.digest(host.policy.manifest()),"run_id":host.policy.run_id,
        "baseline_sha256":p.digest([]),"lane":"candidate_case_local","runtime_sha256":H,"turn":1,"upload_id":"u1",
        "raw_sha256":p.digest(raw),"text_sha256":p.digest(raw),"actual_extraction":True}
    host.protected.mkdir_new("uploads")
    host.protected.write_new("uploads/u1.json",p.canonical(receipt))
    upload["extraction_sha256"]=p.digest(host.protected.files["uploads/u1.json"])
    request=host.request()
    request["due_uploads"]=[upload]
    host.issue(request)
    assert not host.ledger.protocol_guard(host.cap,binding(host,"due_upload_extraction",upload=upload))
    with pytest.raises(c.CustodyError,match="HOST_ONLY"):
        host.ledger.register_upload(host.cap,host.cap,upload=upload,raw=raw,protected_receipt="uploads/u1.json")
    host.ledger.register_upload(host.key,host.cap,upload=upload,raw=raw,protected_receipt="uploads/u1.json")
    assert host.ledger.protocol_guard(host.cap,binding(host,"due_upload_extraction",upload=upload))


def test_retrieval_file_mutation_invalidates_actual_receipt_even_with_original_result_hash(host):
    host.research=True
    host.issue()
    host.run()
    case=host.ledger._case(host.cap)
    (kind,sha),record=next((key,value) for key,value in case["index"].items() if key[0]=="retrieve")
    guard=binding(host,"actual_retrieved_evidence",result_sha256=sha,index_receipt_sha256=record["index_receipt_sha256"])
    assert host.ledger.protocol_guard(host.cap,guard)
    name=next(iter(record["files"]))
    host.store.files[name]=b"changed synthetic native evidence"
    assert host.ledger.protocol_guard(host.cap,guard) is False


def test_unregistered_self_sealed_native_payload_is_not_an_index_observation(host):
    host.issue()
    with pytest.raises(c.CustodyError,match="HOST_INDEX_OBSERVATION"):
        host.ledger._index_observation(host.key,host.cap,"index",{}, {},
            {"result":{"receipt_sha256":H},"approved":True,"content_sha256":H})


def test_sealed_turn_cannot_disclose_new_reviewer_or_reserve_new_budget(host):
    host.issue()
    host.run()
    record={"case_id":"case-A","policy_sha256":host.ledger.policy_sha,"request_sha256":p.digest(host.request_value),
        "operation":"operations/search-"+H,"input_sha256":H,"kind":"search","ordinal":1,"maximum":4}
    assert host.ledger.protocol_guard(host.cap,binding(host,"reserve_budget",reservation=record)) is False
    assert host.ledger.protocol_guard(host.cap,binding(host,"role_disclosure",role="reviewer",context_id="invented",
        job_root=str(host.store.root/"turn-0001/jobs/reviewer-a1"),input_sha256=H)) is False
