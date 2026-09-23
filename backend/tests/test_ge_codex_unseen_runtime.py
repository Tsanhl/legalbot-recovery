"""Control-boundary regressions using only in-memory synthetic state."""
from pathlib import Path

import pytest
from scripts import run_ge_codex_unseen as runner


def test_terminal_state_cannot_start_another_model_call(monkeypatch):
    monkeypatch.setattr(Path,"exists",lambda p:p.name=="STATE-TRANSITION-RECEIPT.json")
    monkeypatch.setattr(runner,"verify_runtime",lambda:pytest.fail("must stop before runtime"))
    with pytest.raises(RuntimeError,match="terminal bank"):
        runner.run("candidate")


def test_cannot_retire_bank_without_execution(monkeypatch):
    monkeypatch.setattr(runner,"verify_runtime",lambda:{})
    monkeypatch.setattr(runner,"verify_bank",lambda:{})
    monkeypatch.setattr(Path,"is_file",lambda p:False)
    with pytest.raises(RuntimeError,match="no one-pass"):
        runner.finalise()


def test_reject_symlink_before_reading_target(monkeypatch):
    path=runner.ROOT/"synthetic-output"
    monkeypatch.setattr(Path,"is_symlink",lambda p:p==path)
    monkeypatch.setattr(Path,"read_text",lambda p:pytest.fail("target must not be opened"))
    with pytest.raises(RuntimeError,match="symlink refused"):
        runner.read(path)


def test_reject_external_path_before_reading(monkeypatch):
    monkeypatch.setattr(Path,"read_text",lambda p:pytest.fail("external path must not be read"))
    with pytest.raises(RuntimeError,match="outside authorized workspace"):
        runner.read(Path("/synthetic-forbidden-file"))


def test_reject_parent_traversal_before_filesystem_access(monkeypatch):
    monkeypatch.setattr(Path,"is_symlink",lambda p:pytest.fail("must reject traversal lexically"))
    with pytest.raises(RuntimeError,match="outside authorized workspace"):
        runner.safe_path(runner.ROOT/".."/"synthetic-other-workspace")


def test_failed_worker_output_is_not_accepted(monkeypatch):
    def read(path):
        if path.name=="output.json":
            return {"cases":[{"case_id":"synthetic"}]}
        if path.name=="COMPLETION.json":
            return {"returncode":1}
        pytest.fail("failed execution must stop before trusting any controls")
    monkeypatch.setattr(runner,"read",read)
    with pytest.raises(RuntimeError,match="failed invocation"):
        runner.validate_job(runner.PRIVATE/"author/shard-01")


def test_recorded_schema_failure_is_terminal_before_reading_bad_output(monkeypatch):
    def read(path):
        if path.name=="COMPLETION.json":
            return {"returncode":0,"validation_error":"ValidationError"}
        pytest.fail("must reject recorded failure before parsing malformed output")
    monkeypatch.setattr(runner,"read",read)
    with pytest.raises(RuntimeError,match="failed invocation"):
        runner.validate_job(runner.PRIVATE/"author/shard-01")


def test_malformed_shard_does_not_stop_unrelated_status(monkeypatch):
    import jsonschema
    bad=runner.PRIVATE/"author/shard-01"
    good=runner.PRIVATE/"author/shard-02"
    monkeypatch.setattr(Path,"glob",lambda p,pattern:iter([bad,good]) if p.name=="author" else iter([]))
    monkeypatch.setattr(Path,"exists",lambda p:True)
    monkeypatch.setattr(Path,"is_file",lambda p:True)
    def read(path):
        if path.name=="COMPLETION.json":
            return {"returncode":0,"validated_rows":1,"validation_error":None}
        return {"cases":[{"case_id":"synthetic"}]}
    monkeypatch.setattr(runner,"read",read)
    def validate(path):
        if path==bad:
            raise jsonschema.ValidationError("synthetic malformed output")
        return {"cases":[{"case_id":"synthetic"}]}
    monkeypatch.setattr(runner,"validate_job",validate)
    result=runner.status()["author"]
    assert result["failed_shards"]==1
    assert result["validated_rows"]==1


def test_worker_profile_protects_controls_and_attachments():
    work=runner.PRIVATE/"synthetic-role"
    profile=runner.profile(work)
    for name in ("input.json","schema.json","INVOCATION.json","COMPLETION.json"):
        assert f'(deny file-write* (literal "{work/name}"))' in profile
    for name in ("uploads","fixtures","sources"):
        assert f'(deny file-write* (subpath "{work/name}"))' in profile
    assert 'require-not (subpath' in profile


def test_source_capture_rejects_untrusted_host_without_network(monkeypatch):
    rows=[]
    monkeypatch.setattr(Path,"exists",lambda p:False)
    monkeypatch.setattr(runner,"write",lambda p,value:rows.append(value))
    monkeypatch.setattr(runner,"urlopen",lambda *a,**k:pytest.fail("no network on rejected host"))
    result=runner.capture("https://synthetic.invalid/pretend-law",runner.PRIVATE/"synthetic")
    assert result["status"]=="REJECTED_SOURCE_HOST"
    assert "raw_sha256" not in result
    assert rows==[result]


def test_dynamic_stage_is_bound_to_source_output(monkeypatch):
    work=runner.PRIVATE/"followup/shard-01"
    monkeypatch.setattr(runner,"read",lambda p:{"input_sha256":"unchanged",
        "source_stage":"candidate","source_shard":"shard-01","source_output_sha256":"old"})
    monkeypatch.setattr(runner,"sha",lambda p:"unchanged" if p.name=="input.json" else "new")
    with pytest.raises(RuntimeError,match="dynamic stage lineage mismatch"):
        runner.validate_lineage(work)


def assigned_slot(code):
    return next(r for r in runner.coverage_slots() if r["jurisdiction_code"]==code)


def test_legal_draft_cannot_follow_host_jurisdiction():
    slot=assigned_slot("UK-ENG")
    with pytest.raises((RuntimeError,ValueError),match="jurisdiction"):
        runner.validate_author_scope([{"case_id":slot["slot_id"],"jurisdiction":"Hong Kong",
            "question":"Synthetic question in another jurisdiction."}],[slot])


def test_label_alone_cannot_hide_missing_user_jurisdiction():
    slot=assigned_slot("US-CA")
    with pytest.raises((RuntimeError,ValueError)):
        runner.validate_author_scope([{"case_id":slot["slot_id"],"jurisdiction":"US-CA",
            "question":"Synthetic question with no place stated."}],[slot])


def test_assigned_uk_and_us_cases_are_allowed():
    for code,place in (("UK-WLS","Wales"),("US-CA","California"),("UK-SCT","Scotland")):
        slot=assigned_slot(code)
        runner.validate_author_scope([{"case_id":slot["slot_id"],"jurisdiction":code,
            "question":f"Synthetic question about a matter in {place}."}],[slot])


@pytest.mark.parametrize("code,question",[
    ("US-GA","I run a synthetic repair workshop in the US state of Georgia. What information do I need?"),
    ("US-MI","My Michigan workshop has received a synthetic notice. How should I record the facts?"),
    ("US-MS","Our Mississippi studio received a disputed bill. What information should I collect?"),
    ("US-VT","A contractor sent a quote from his Vermont workshop. What information should I keep?")])
def test_natural_location_phrasing_is_not_a_scope_failure(code,question):
    slot=assigned_slot(code)
    runner.validate_author_scope([{"case_id":slot["slot_id"],"jurisdiction":code,"question":question}],[slot])


def test_geographical_book_title_is_not_a_matter_location():
    slot=assigned_slot("US-MI")
    with pytest.raises(ValueError,match="assigned location"):
        runner.validate_author_scope([{"case_id":slot["slot_id"],"jurisdiction":"US-MI",
            "question":"My Michigan law textbook describes a rule. What happens to my dispute?"}],[slot])


def test_scope_recheck_does_not_accept_schema_or_execution_failure():
    assert runner.completion_recheckable("author",{"returncode":0,"validation_error":"UKUSScopeError"})
    for stage,completion in (("oracle",{"returncode":0,"validation_error":"UKUSScopeError"}),
            ("author",{"returncode":0,"validation_error":"ValidationError"}),
            ("author",{"returncode":1,"validation_error":"UKUSScopeError"})):
        assert not runner.completion_recheckable(stage,completion)


def test_scope_change_cannot_be_applied_after_seal(monkeypatch):
    monkeypatch.setattr(Path,"exists",lambda p:p.name=="BANK-SEAL.json")
    monkeypatch.setattr(runner,"read",lambda p:pytest.fail("no private read after seal"))
    with pytest.raises(RuntimeError,match="prohibited after seal"):
        runner.amend_uk_usa_scope()


def test_scope_receipt_rejects_changed_contract(monkeypatch):
    value=runner.seal({"run_id":runner.RUN_ID,"scope_contract":{"scope":"different"},
        "owner_authorization_sha256":"a","one_pass_authorization_retained":True})
    monkeypatch.setattr(runner,"read",lambda p:value)
    monkeypatch.setattr(runner,"sha",lambda p:"a")
    with pytest.raises(RuntimeError,match="scope amendment"):
        runner.require_scope_amendment()


def test_redirect_does_not_fetch_a_different_host():
    request=runner.Request("https://www.uscourts.gov/original")
    with pytest.raises(ValueError,match="cross-host"):
        runner.OfficialRedirectHandler().redirect_request(
            request,None,302,"Found",{},"https://synthetic.invalid/secret")


def test_valid_scope_receipt_is_still_bound_to_exact_assignments(monkeypatch):
    value=runner.seal({"run_id":runner.RUN_ID,"scope_contract":runner.scope_contract(),
        "owner_authorization_sha256":"a","one_pass_authorization_retained":True,
        "coverage_slots_sha256":"a"})
    wrong=runner.seal({"legal_slots":[],"system_slots":[]})
    monkeypatch.setattr(runner,"read",lambda p:value if p.name=="UK-USA-SCOPE-AMENDMENT.json" else wrong)
    monkeypatch.setattr(runner,"sha",lambda p:"a")
    with pytest.raises(RuntimeError,match="assignments changed"):
        runner.require_scope_amendment()


@pytest.mark.parametrize("lineage_valid",[True,False])
def test_oracle_part_uses_real_runner_validation_and_lineage(monkeypatch,lineage_valid):
    from scripts import ge_unseen_oracle_parts as parts
    work=runner.PRIVATE/"oracle-parts/shard-01-part-01"
    output={"oracles":[]}
    records={"COMPLETION.json":{"returncode":0,"validation_error":None},
        "output.json":output,"schema.json":runner.ORACLE_SCHEMA,
        "input.json":{"cases":[]},"INVOCATION.json":{"input_sha256":"synthetic-hash"}}
    protected=runner.PRIVATE/"receipts/oracle-parts/shard-01-part-01.json"
    def read(path):
        if path==protected:
            return {"input_sha256":"synthetic-hash","schema_sha256":"synthetic-hash","input_inventory":{}}
        if path.name=="shard-01-part-01-complete.json":
            return {"output_sha256":"synthetic-hash"}
        return records[path.name]
    monkeypatch.setattr(runner,"read",read)
    monkeypatch.setattr(runner,"sha",lambda p:"synthetic-hash")
    monkeypatch.setattr(Path,"exists",lambda p:True)
    seen=[]
    def validate(module,path):
        assert module is runner and path==work
        seen.append(path)
        if not lineage_valid:
            raise RuntimeError("synthetic changed part lineage")
    monkeypatch.setattr(parts,"validate_part_lineage",validate)
    if lineage_valid:
        assert runner.validate_job(work)==output
    else:
        with pytest.raises(RuntimeError,match="changed part lineage"):
            runner.validate_job(work)
    assert seen==[work]


@pytest.mark.parametrize("action",["prepare_followups","prepare_reviews"])
def test_recorded_candidate_failure_does_not_stall_other_downstream_preparation(monkeypatch,action):
    work=runner.PRIVATE/"candidate/shard-01"
    monkeypatch.setattr(runner,"verify_runtime",lambda:{})
    monkeypatch.setattr(runner,"verify_bank",lambda:{})
    monkeypatch.setattr(runner,"collect",lambda *args:[])
    monkeypatch.setattr(Path,"glob",lambda p,pattern:iter([work]) if p.name=="candidate" else iter([]))
    monkeypatch.setattr(Path,"exists",lambda p:False)
    monkeypatch.setattr(Path,"is_file",lambda p:True)
    def read(path):
        if path.name=="CASE-MAPPING.json":
            return []
        if path.name=="input.json":
            return {"cases":[]}
        if path.name=="COMPLETION.json":
            return {"returncode":124,"validation_error":"FileNotFoundError"}
        pytest.fail("failed output must not be opened or promoted")
    monkeypatch.setattr(runner,"read",read)
    monkeypatch.setattr(runner,"validate_job",lambda p:pytest.fail("recorded failure is terminal locally"))
    assert list(getattr(runner,action)().values())==[0]
