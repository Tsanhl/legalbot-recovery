"""Synthetic host composition only: no model files, CLI, OCR, network or private reads.

Actual selected schemas, Fernet, CaseHost/Driver/Custody/Protocol compose against
in-memory artifacts. Role/fence/installed-identity/tool observations are explicit
test doubles, not real host isolation, legal, inference or functions.web proof.
"""
from __future__ import annotations

import copy
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from backend.app.contracts import ContractSchemaRegistry
from backend.app.contracts.query_plan import QueryBudgets
from backend.tests import test_ge_auto_case_custody as hf
from scripts import ge_auto_case_driver as d
from scripts import ge_auto_case_host as h
from scripts import ge_auto_case_protocol as p
from scripts import ge_auto_host_bridge as bridge
from scripts import ge_auto_native_evidence_guard as ng
from scripts import ge_auto_role_runtime as roles

ROOT = Path(__file__).resolve().parents[2]
VIRTUAL = ROOT / "synthetic-case-host-memory"
H = p.digest(b"synthetic host fixture identity, not real execution")
OWNER = b"Synthetic non-live host authorization fixture only."


def test_issue_identity_is_fixed_before_source_selection() -> None:
    queries = [{"gap_id": "gap-currentness", "kind": "currentness",
        "query": "Synthetic currentness query", "jurisdiction": "Wales",
        "as_of_date": "2026-09-05"}]
    expected = h.CaseHost.issue_id_for_queries(queries)
    assert expected == h.CaseHost.issue_id_for_queries(copy.deepcopy(queries))
    assert expected.startswith("issue-")
    assert "source" not in expected


class MemoryFS:
    def __init__(self):
        self.files, self.dirs, self.events = {}, {VIRTUAL}, []
        self.locked = set()

    def write(self, path, raw):
        path = Path(path)
        if path in self.files:
            raise FileExistsError(path)
        if not path.is_relative_to(VIRTUAL):
            raise AssertionError("test write outside virtual root")
        self.dirs.update((path.parent, *path.parent.parents))
        self.files[path] = raw if isinstance(raw, bytes) else p.canonical(raw)
        self.events.append(("write", path))

    def read(self, path):
        path = Path(path)
        if path in self.files:
            self.events.append(("read", path))
            return self.files[path]
        # Only code/config/schema reads in this repository, never models/banks.
        if any(path.is_relative_to(ROOT / base) for base in ("scripts", "backend/app", "docs/system-design/schemas")):
            return path.read_bytes()
        raise FileNotFoundError(path)

    def store(self, root):
        fs = self
        class Store:
            def __init__(self):
                self.root = Path(root)
            def read(self, name):
                p.parts(name)
                return fs.read(self.root / name)
            def write_new(self, name, raw):
                p.parts(name)
                if self.root not in fs.dirs:
                    raise FileNotFoundError("CaseStore root was not created")
                fs.write(self.root / name, raw)
            def exists(self, name):
                p.parts(name)
                return self.root / name in fs.files or self.root / name in fs.dirs
            def mkdir_new(self, name):
                p.parts(name)
                if self.exists(name):
                    raise FileExistsError(name)
                fs.dirs.add(self.root / name)
            def names(self, name):
                prefix = self.root / name
                return sorted({str(path.relative_to(prefix)).split("/")[0] for path in fs.files.keys() | fs.dirs
                    if path != prefix and path.is_relative_to(prefix)})
            def inventory(self, name):
                prefix = self.root / name
                return {path.relative_to(prefix).as_posix(): p.digest(raw) for path, raw in fs.files.items()
                        if path.is_relative_to(prefix)}
            @contextmanager
            def lock(self):
                if self.root in fs.locked:
                    raise BlockingIOError()
                fs.locked.add(self.root)
                try:
                    yield
                finally:
                    fs.locked.remove(self.root)
        return Store()


class Fixture:
    def __init__(self, fs):
        self.fs, self.host = fs, None
        self.calls, self.research = [], False
        self.clock = 0.0
        self.respond = True
        self.privacy = "ALLOW"
        self.public_query = {"query": "Scotland synthetic public rule", "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}

    def output(self, job):
        if job.role == "planner":
            return {"queries": [{"gap_id": "g1", "kind": "missing_authority", **self.public_query}] if self.research else [],
                    "clarifications": [], "holds": [] if self.research else ["INSUFFICIENT_AUTHORITY"]}
        return {"status": "HOLD", "answer": "Synthetic legal HOLD, no actual model evidence.", "cited_proposition_ids": []}

    def complete(self, runtime, job):
        double = hf.Host.__new__(hf.Host)
        double.store, double.protected = self.fs.store(self.host.root), self.fs.store(self.host.protected)
        double.pins, double.mutation = self.host.custody.pins, None
        double.calls, double.output = self.calls, self.output
        return hf.Host.complete(double, runtime, job)

    def sleep(self, seconds):
        self.clock += seconds
        if not self.respond:
            return
        for path, raw in list(self.fs.files.items()):
            if path.name != "request.json" or not path.parent.name.startswith(("privacy-", "web-")):
                continue
            target = path.with_name("response.json")
            if target in self.fs.files:
                continue
            req = p.decode(raw)
            response = {"request_sha256": p.digest(raw), "kind": req["kind"], "parent_observed": True}
            if req["kind"] == "privacy":
                response.update(decision=self.privacy, reason="Synthetic parent decision only.",
                    query_sha256=p.digest(req["payload"]["public_query"]))
            else:
                broker = req["payload"]["broker_request"]
                assert broker["tool_arguments"] == bridge.search_arguments(broker["public_input"])
                response.update(tool="functions.web", raw_utf8='{"synthetic_fixture":true}',
                    hits=[], tool_observation_id="synthetic-tool-observation")
            self.fs.write(target, p.canonical(response))


@pytest.fixture
def fixture(monkeypatch):
    fs, registry = MemoryFS(), ContractSchemaRegistry.from_project_root(ROOT)
    fixture = Fixture(fs)
    monkeypatch.setattr(h, "write_new", fs.write)
    monkeypatch.setattr(p, "CaseStore", fs.store)
    monkeypatch.setattr(d.custody_api, "CustodyStore", fs.store)
    old_exists, old_mkdir = Path.exists, Path.mkdir
    def exists(path):
        return path in fs.files or path in fs.dirs if path.is_relative_to(VIRTUAL) else old_exists(path)
    def mkdir(path, *args, **kwargs):
        if not path.is_relative_to(VIRTUAL):
            return old_mkdir(path, *args, **kwargs)
        fs.dirs.update((path, *path.parents))
        fs.events.append(("mkdir", path))
    monkeypatch.setattr(Path, "exists", exists)
    monkeypatch.setattr(Path, "mkdir", mkdir)
    cli = {"version": "SYNTHETIC", "launcher_sha256": H, "package_sha256": H, "native_sha256": H}
    embed = {"source_repo": "Qwen/Qwen3-Embedding-0.6B", "revision": "a" * 40,
        "file_manifest_sha256": H, "directory": str((VIRTUAL / "synthetic-model").relative_to(ROOT)), "dimensions": 1024,
        "local_files_only": True, "device": "cpu", "max_tokens": 2048, "batch_size": 1,
        "torch_threads": 2, "normalise_embeddings": True, "training": False}
    embed["identity_sha256"] = p.digest(embed)
    rerank = {"identity_sha256": p.digest(b"synthetic reranker identity")}
    monkeypatch.setattr(h, "verified_model_identity", lambda: copy.deepcopy(embed))
    monkeypatch.setattr(h, "verified_reranker_identity", lambda: copy.deepcopy(rerank))
    monkeypatch.setattr(h, "cli_identity", lambda: copy.deepcopy(cli))
    monkeypatch.setattr(roles, "cli_identity", lambda: copy.deepcopy(cli))
    def role(runtime, job):
        return fixture.complete(runtime, job)
    monkeypatch.setattr(roles.CodexRoleRuntime, "__call__", role)
    monkeypatch.setattr(roles, "profile", hf.fake_profile)
    monkeypatch.setattr(hf, "H", p.digest((ROOT / "scripts/ge_auto_role_runtime.py").read_bytes()))
    # Replace only this module's clock object, not the shared time module used
    # by the driver/bridge thread; their real short waits must still progress.
    monkeypatch.setattr(h, "time", SimpleNamespace(sleep=fixture.sleep, monotonic=lambda: fixture.clock))
    names = set(d.CODE_FILES) | {"scripts/ge_auto_case_host.py", "scripts/ge_auto_native_evidence_guard.py",
        "scripts/ge_unseen_fixtures.py", "backend/app/retrieval/models.py",
        "scripts/model/manifests/qwen3-retrieval-models.json"}
    manifest = {"schema": h.VERSION, "model": "gpt-synthetic-test", "provider": "openai", "cli_identity": cli,
        "embedding_identity": embed, "reranker_identity": rerank, "schema_selection_sha256": registry.manifest_sha256,
        "code_sha256s": {name: p.digest((ROOT / name).read_bytes()) for name in names},
        "shared_baseline_sources": [], "baseline_generation_id": "synthetic-empty-baseline",
        "configuration": {"query_policy": {"queries": 4, "captures": 8}, "research_eligibility_policy": {"synthetic_only": True},
            "query_budgets": asdict(QueryBudgets(reranker_candidates=8, final_top_k=8))},
        "training": False, "production": False}
    fixture.manifest = manifest
    fs.write(VIRTUAL / "owner.json", OWNER)
    marker = {"run_id": "synthetic-run", "runtime_sha256": p.digest(manifest), "baseline_sha256": h.EMPTY, "training": False}
    fs.write(VIRTUAL / "marker.json", p.canonical(marker))
    fs.write(VIRTUAL / "synthetic-model/tokenizer.json", b"synthetic tokenizer bytes, never loaded")
    fixture.args = dict(run_id="synthetic-run", case_id="case-synthetic", case_root=VIRTUAL / "case",
        protected_root=VIRTUAL / "host", mailbox_root=VIRTUAL / "mailbox", owner_instruction_path=VIRTUAL / "owner.json",
        expected_owner_sha256=p.digest(OWNER), owner_scope_sha256=H, global_marker_path=VIRTUAL / "marker.json",
        global_marker_sha256=p.digest(marker), runtime_manifest=manifest,
        baseline_created_at=datetime.now(UTC) - timedelta(minutes=1))
    return fixture


def make(fixture):
    fixture.host = h.CaseHost(**fixture.args)
    return fixture.host


def run(host, **kwargs):
    return host.run_turn(question="Synthetic own due question", jurisdictions=["Scotland"], as_of_date="2026-09-05", **kwargs)


def test_constructor_matches_wrapper_filters_native_python_pins_and_creates_roots(fixture):
    host = make(fixture)
    assert type(host.native_guard) is ng.NativeEvidenceGuard
    assert all(name.endswith(".py") for name in host.native_guard.expected_code_sha256s)
    assert any(name.endswith(".json") for name in host.runtime_manifest["code_sha256s"])
    events = fixture.fs.events
    for root in (host.root, host.protected):
        assert ("mkdir", root) in events
        assert events.index(("mkdir", root)) < events.index(("write", host.protected / "CUSTODY-START.json"))
    assert host.model == fixture.manifest["model"] and host.session is None


def test_real_composition_two_hold_turns_keeps_terminal_and_projection(fixture):
    host = make(fixture)
    first = run(host)
    assert first["answer"]["status"] == "HOLD" and len(host.drivers) == 1
    assert host.read_answer_projection() == first["rendered_answer"]
    assert host.history_holds[1]["code"] == "TECHNICAL_PRIOR_CONTRACT_SNAPSHOT_MISSING"
    assert host.driver.terminal_result == first
    second = run(host)
    assert second["turn"] == 2 and host.drivers[0].terminal_result == first
    assert fixture.calls == ["planner", "final", "planner", "final"]


def test_actual_query_mailbox_and_postterminal_history_flow(fixture, capsys):
    fixture.research = True
    host = make(fixture)
    first = run(host)
    assert first["answer"]["status"] == "HOLD"
    assert host.history and not host.history_holds
    assert host.host_observations and host.resolutions
    log = capsys.readouterr().out
    assert "privacy " in log and "web " in log and "synthetic public rule" not in log
    assert all(line.endswith("/request.json") for line in log.splitlines())
    fixture.research = False
    second = run(host)
    assert second["answer"]["status"] == "HOLD" and len(host.driver.history) == 1
    assert host.drivers[0].terminal_result == first


@pytest.mark.parametrize("jurisdiction,site_hint,search_count", [
    ("England", "site:gov.uk", 2), ("US federal", "site:.gov", 1)])
def test_service_web_accepts_actual_bridge_discovery_and_binds_mailbox_observation(
        fixture, jurisdiction, site_hint, search_count):
    fixture.research = True
    fixture.public_query = {"query": "Synthetic public notice requirements", "jurisdiction": jurisdiction, "as_of_date": "2026-09-05"}
    host = make(fixture)
    host.run_turn(question="Synthetic own due question", jurisdictions=[jurisdiction], as_of_date="2026-09-05")
    # A terminal HOLD alone cannot prove that the request reached the parent.
    assert len(host.host_observations) == 1
    observed = next(iter(host.host_observations.values()))
    reservation = observed["reservation"]
    path = "broker/search-" + p.digest(reservation) + "/request.json"
    request_bytes = host.driver.store.read(path)
    request = p.decode(request_bytes)
    assert request["public_input"] == fixture.public_query
    assert request["tool_arguments"] == bridge.search_arguments(fixture.public_query)
    assert request["tool_arguments"] != {"search_query": [{"q": fixture.public_query["query"]}], "response_length": "long"}
    assert site_hint in request["tool_arguments"]["search_query"][0]["q"]
    assert len(request["tool_arguments"]["search_query"]) == search_count
    assert request["budget"]["maximum"] == 4 and request["budget"]["ordinal"] == 1
    assert observed["broker_request_sha256"] == p.digest(request_bytes)
    rows = [row for row in host.mailbox.observations.values() if row["request"]["kind"] == "web"]
    assert len(rows) == 1
    assert rows[0]["request"]["payload"] == {"case_id": host.case_id, "broker_request": request,
        "broker_request_sha256": p.digest(request_bytes), "reservation": reservation}
    assert host.mailbox.verify_observation(observed["response"])
    response = p.decode(host.driver.store.read(path.replace("/request.json", "/response.json")))
    assert response["request_sha256"] == p.digest(request_bytes)
    assert response["reservation_sha256"] == p.digest(reservation)
    assert response["result"]["raw_utf8"] == observed["response"]["raw_utf8"]
    assert response["result"]["hits"] == observed["response"]["hits"]


@pytest.mark.parametrize("mutation", ["stripped_filter", "different_args", "foreign_context", "reservation_hash",
    "unpersisted_bytes", "public_query", "public_jurisdiction", "public_date", "unrecorded_reservation"])
def test_service_web_refuses_changed_bound_bridge_request_before_mailbox(fixture, mutation):
    fixture.research = True
    host = make(fixture)
    run(host)
    assert len(host.host_observations) == 1
    observed = next(iter(host.host_observations.values()))
    reservation = copy.deepcopy(observed["reservation"])
    path = host.root / ("broker/search-" + p.digest(reservation) + "/request.json")
    request = p.decode(fixture.fs.read(path))
    error = "ACTUAL_BROKER_REQUEST_REQUIRED"
    if mutation == "stripped_filter":
        request["tool_arguments"] = {"search_query": [{"q": request["public_input"]["query"]}], "response_length": "long"}
    elif mutation == "different_args":
        request["tool_arguments"]["search_query"][0]["q"] += " altered"
    elif mutation == "foreign_context":
        request["context"]["case_id"] = "foreign-case"
    elif mutation == "reservation_hash":
        request["reservation_sha256"] = H
    elif mutation in ("public_query", "public_jurisdiction", "public_date"):
        field, value = {"public_query": ("query", "Changed synthetic public rule"),
            "public_jurisdiction": ("jurisdiction", "England"), "public_date": ("as_of_date", "2000-01-01")}[mutation]
        request["public_input"][field] = value
        request["tool_arguments"] = bridge.search_arguments(request["public_input"])
        error = "ACTUAL_BROKER_RESERVATION_REQUIRED"
    elif mutation == "unrecorded_reservation":
        reservation["budget"]["ordinal"] = 2
        request["reservation_sha256"] = p.digest(reservation)
        path = host.root / ("broker/search-" + p.digest(reservation) + "/request.json")
        error = "ACTUAL_BROKER_RESERVATION_REQUIRED"
    else:
        request["requested_at"] = "2000-01-01T00:00:00+00:00"
    raw = p.canonical(request)
    if mutation != "unpersisted_bytes":
        fixture.fs.files[path] = raw  # Explicit corruption of synthetic memory only.
    mailbox_before = copy.deepcopy(host.mailbox.observations)
    observations_before = copy.deepcopy(host.host_observations)
    events_before = len(fixture.fs.events)
    with pytest.raises(RuntimeError, match=error):
        host.service_web(raw, reservation)
    assert host.mailbox.observations == mailbox_before
    assert host.host_observations == observations_before
    assert not any(event == "write" for event, _ in fixture.fs.events[events_before:])


def test_exact_utf8_due_upload_has_custody_receipt_without_circular_request_hash(fixture):
    host = make(fixture)
    path = VIRTUAL / "due.txt"
    fixture.fs.write(path, "Own synthetic upload £ é".encode())
    upload = host.extract_upload(path=path, upload_id="due-1", turn=1, media_type="text/plain")
    receipt = p.decode(upload[1].extraction_receipt)
    assert "request_sha256" not in receipt and receipt["turn"] == 1 and receipt["actual_extraction"] is True
    result = run(host, uploads=[upload])
    assert result["answer"]["status"] == "HOLD"
    assert host.driver.request["due_uploads"] == [upload[0]]
    assert host.driver.uploads["due-1"].raw == fixture.fs.read(path)


@pytest.mark.parametrize("mutation", ["wrong-turn", "changed", "duplicate"])
def test_unobserved_changed_and_duplicate_uploads_are_denied(fixture, mutation):
    host = make(fixture)
    fixture.fs.write(VIRTUAL / "due.txt", b"Synthetic own upload")
    if mutation == "wrong-turn":
        with pytest.raises(RuntimeError, match="ONLY_DUE_UPLOAD_TURN"):
            host.extract_upload(path=VIRTUAL / "due.txt", upload_id="due-1", turn=2, media_type="text/plain")
        return
    value = host.extract_upload(path=VIRTUAL / "due.txt", upload_id="due-1", turn=1, media_type="text/plain")
    uploads = [value, value] if mutation == "duplicate" else [({**value[0], "text": "changed"}, value[1], value[2])]
    with pytest.raises(RuntimeError, match="UNOBSERVED_OR_CHANGED_DUE_UPLOAD"):
        run(host, uploads=uploads)
    assert fixture.calls == []


@pytest.mark.parametrize("field", ["owner", "marker", "runtime"])
def test_init_rejects_changed_authority_before_custody_write(fixture, field):
    if field == "runtime":
        fixture.args["runtime_manifest"] = {**fixture.manifest, "training": True}
    else:
        fixture.fs.files[VIRTUAL / (field + ".json")] += b"changed"
    with pytest.raises((RuntimeError, ValueError)):
        make(fixture)
    assert VIRTUAL / "host/CUSTODY-START.json" not in fixture.fs.files


def test_mailbox_exact_bytes_cache_and_mutation_and_timeout_no_repeat(fixture, capsys):
    mailbox = h.ParentMailbox(VIRTUAL / "mailbox", timeout_seconds=1)
    payload = {"public_query": {"query": "synthetic query", "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}}
    response = mailbox.exchange("privacy", payload)
    row = mailbox.observations[response["request_sha256"]]
    assert p.digest(fixture.fs.read(row["request_path"])) == response["request_sha256"]
    assert mailbox.exchange("privacy", payload) == response
    assert len(capsys.readouterr().out.splitlines()) == 1
    fixture.fs.files[Path(row["request_path"])] += b" "
    with pytest.raises(RuntimeError, match="PARENT_OBSERVATION_CHANGED"):
        mailbox.exchange("privacy", payload)
    fixture.respond = False
    with pytest.raises(RuntimeError, match="PARENT_TOOL_TIMEOUT"):
        mailbox.exchange("privacy", {"public_query": {**payload["public_query"], "query": "different"}})
    with pytest.raises(RuntimeError, match="UNCHANGED_PARENT_REQUEST_NOT_RETRIED"):
        mailbox.exchange("privacy", {"public_query": {**payload["public_query"], "query": "different"}})


def test_parent_response_publication_is_an_atomic_create_only_link(tmp_path, monkeypatch):
    monkeypatch.setattr(h, "ROOT", tmp_path)
    monkeypatch.setitem(h.write_new.__globals__, "ROOT", tmp_path)
    folder = tmp_path / "privacy-atomic"
    folder.mkdir()
    request = {"schema": h.VERSION, "kind": "privacy", "payload": {"public_query": {
        "query": "synthetic public query", "jurisdiction": "Scotland", "as_of_date": "2026-09-05"}}}
    request_path = folder / "request.json"
    request_path.write_bytes(p.canonical(request))
    response_path = folder / "response.json"
    response = {"request_sha256": p.digest(request), "kind": "privacy", "parent_observed": True,
        "decision": "ALLOW", "reason": "Synthetic public query only.",
        "query_sha256": p.digest(request["payload"]["public_query"])}
    receipt = h.publish_parent_response(response_path, response)
    staged = folder / f"response-{receipt}.staged"
    assert response_path.read_bytes() == p.canonical(response)
    assert not staged.exists()
    assert h.publish_parent_response(response_path, response) == receipt

    expired = tmp_path / "privacy-expired"
    expired.mkdir()
    (expired / "request.json").write_bytes(p.canonical(request))
    (expired / "HOLD.json").write_bytes(p.canonical({"reason": "PARENT_TOOL_TIMEOUT"}))
    with pytest.raises(RuntimeError, match="PARENT_REQUEST_ALREADY_TIMED_OUT"):
        h.publish_parent_response(expired / "response.json", response)
    assert not (expired / "response.json").exists()


def test_parent_web_normalizer_retains_untitled_official_results():
    raw = """First title (https://example.gov/first)\nfirst snippet
--------------------
 (https://uscode.house.gov/view.xhtml?edition=prelim&req=section)\nsecond snippet"""
    hits = h.normalize_parent_web_hits(raw)
    assert hits == [
        {"url": "https://example.gov/first", "title": "First title", "snippet": "first snippet"},
        {"url": "https://uscode.house.gov/view.xhtml?edition=prelim&req=section",
         "title": "uscode.house.gov", "snippet": "second snippet"},
    ]


def test_parent_web_normalizer_accepts_separator_attached_to_prior_snippet():
    raw = """Act (https://www.legislation.gov.uk/act.pdf)
statutory text.--------------------
Currentness page (https://law.gov.wales/status)
commencement and amendments"""
    assert h.normalize_parent_web_hits(raw) == [
        {"url": "https://www.legislation.gov.uk/act.pdf", "title": "Act",
         "snippet": "statutory text."},
        {"url": "https://law.gov.wales/status", "title": "Currentness page",
         "snippet": "commencement and amendments"},
    ]


def test_host_evidence_closed_fields_and_exact_web_reservation(fixture):
    fixture.research = True
    host = make(fixture)
    run(host)
    driver = host.driver
    common = {"case_root": str(host.root), "protected_host_root": str(host.protected),
        "request_sha256": driver.request_sha, "policy_sha256": host.policy_sha}
    observed = next(iter(host.host_observations.values()))
    response = observed["response"]
    binding = {**common, "broker_request_sha256": observed["broker_request_sha256"], "reservation": observed["reservation"],
        "raw_sha256": p.digest(response["raw_utf8"].encode()), "hits_sha256": p.digest(response["hits"]),
        "tool_call_id": response["tool_observation_id"], "host_receipt": response}
    assert host.host_evidence_verify("web_observation", binding) is True
    assert host.host_evidence_verify("web_observation", {**binding, "extra": True}) is False
    assert host.host_evidence_verify("web_observation", {**binding, "broker_request_sha256": H}) is False
    assert host.host_evidence_verify("unknown", binding) is False


def test_history_only_preparation_error_preserves_completed_terminal(fixture, monkeypatch):
    host = make(fixture)
    def fail():
        raise RuntimeError("SYNTHETIC_HISTORY_ONLY_HOLD")
    monkeypatch.setattr(host, "_history_contract", fail)
    result = run(host)
    assert result == host.driver.terminal_result and result["answer"]["status"] == "HOLD"
    assert host.history_holds[1]["code"] == "SYNTHETIC_HISTORY_ONLY_HOLD"
