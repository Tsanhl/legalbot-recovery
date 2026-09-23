"""In-memory dependency fakes only: NOT unseen/model/network/index proof.

Use real protocol schemas, citation renderer and main answer schema. All host,
extraction and protected-store operations below are synthetic. No bank, model,
network, filesystem writes or artifact cleanup is performed by these tests.
"""
from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from scripts import ge_unseen_case_route as v
from scripts import ge_auto_case_protocol as p
from scripts.run_ge_codex_unseen import ANSWER_SCHEMA

H = p.digest(b"synthetic identity; not a real execution receipt")
STAMP = datetime(2026, 9, 5, tzinfo=UTC)
URL = "https://www.legislation.gov.uk/ukpga/2015/15/data.xml"
RAW = b'''<Legislation xmlns="http://www.legislation.gov.uk/namespaces/legislation"
 xmlns:dc="http://purl.org/dc/elements/1.1/"><Metadata><dc:title>Synthetic Test Act</dc:title></Metadata>
 <Body><P>Synthetic rule.</P><P>Only with condition A.</P><P>Currentness test context.</P></Body></Legislation>'''


def evidence_fixture(raw=RAW, url=URL):
    sha = p.digest(raw)
    parts = [{"part_id": f"part-{n}", "parent_id": None, "locator": f"synthetic/section/{n}", "text": text}
             for n, text in enumerate(("Synthetic rule.", "Only with condition A.", "Currentness test context."), 1)]
    spans = [{"source_sha256": sha, "part_id": part["part_id"], "start": 0,
              "end": len(part["text"]), "text": part["text"]} for part in parts]
    prop = {"proposition_id": "synthetic-prop", "jurisdiction": "England", "as_of_date": "2026-09-05",
        "point": spans[0], "conditions": [spans[1]], "context": [spans[2]],
        "currentness": {"status": "VERIFIED", "checks": [spans[2]],
                        "valid_from": "2026-09-05", "valid_to": "2026-09-05"}}
    capture = {"canonical_url": url, "final_url": url, "redirect_chain": [], "fetched_at": STAMP.isoformat(),
        "raw_b64": base64.b64encode(raw).decode(), "parser_sha256": H, "parser_receipt_sha256": H, "parts": parts}
    pack = {"baseline_sha256": v.EMPTY, "generation_sha256": H, "retrieval_receipt_sha256": H,
        "evidence": [{"origin": "CASE_LOCAL", "proposition": prop, "eligibility_receipt_sha256": H}]}
    pack["source_references"] = p.retrieved_source_references(pack["evidence"], {sha: capture})
    records = [{"capture": capture, "reservation": {"synthetic_only": True}, "researcher_id": "synthetic-selector"}]
    return pack, records


def due(turn=1, previous=None, **changes):
    return {"schema": v.VERSION, "case_id": "q0001", "turn": turn,
        "question": "Synthetic user question." if turn == 1 else "Correction: synthetic fact changed.",
        "jurisdictions": ["England"], "as_of_date": "2026-09-05", "uploads": [],
        "previous_terminal_sha256": previous, **changes}


class MemoryStore:
    def __init__(self, root):
        self.root, self.files, self.dirs = Path(root), {}, set()

    def mkdir_new(self, name):
        p.parts(name)
        if name in self.dirs:
            raise FileExistsError(name)
        self.dirs.add(name)

    def read(self, name):
        p.parts(name)
        return self.files[name]

    def write_new(self, name, raw):
        p.parts(name)
        if name in self.files:
            raise FileExistsError(name)
        self.files[name] = raw


class SyntheticHost:
    """Persistent host double. Never used by the production constructor."""
    def __init__(self, kwargs, fs, stores):
        self.kwargs, self.fs, self.stores = kwargs, fs, stores
        self.root, self.protected = kwargs["case_root"], kwargs["protected_root"]
        self.case_id = kwargs["case_id"]
        self.runtime_sha = p.digest(kwargs["runtime_manifest"])
        self.policy = p.FrozenPolicy(kwargs["run_id"], kwargs["expected_owner_sha256"], self.runtime_sha, "EMPTY", v.EMPTY)
        self.policy_sha = p.digest(self.policy.manifest())
        self.session = self
        self.calls, self.extracts, self.events, self.terminals = [], [], [], {}
        self.pack, self.records = evidence_fixture()
        self.fail, self.no_answer, self.changed_rendering, self.changed_request = False, False, False, False

    def establish_marker(self, raw):
        self.events.append("marker")
        return raw == b"synthetic protected marker"

    def owner_bytes(self):
        return self.fs[self.kwargs["owner_instruction_path"]]

    def extract_upload(self, **kwargs):
        self.extracts.append(kwargs)
        raw = self.stores[self.root / "due-uploads"].read(kwargs["path"].relative_to(self.root / "due-uploads").as_posix())
        text = "Synthetic extraction; not actual OCR."
        receipt = p.canonical({"extraction_result": {"pages": [{"text": text}]}})
        return ({"upload_id": kwargs["upload_id"], "sha256": p.digest(raw), "media_type": kwargs["media_type"],
            "text": text, "text_sha256": p.digest(text.encode()), "extraction_sha256": p.digest(receipt)},
            SimpleNamespace(raw=raw, extraction_receipt=receipt), "uploads/synthetic.json")

    def run_turn(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        self.events.append("question")
        if self.fail:
            raise RuntimeError("synthetic failure, no actual inference")
        turn = len(self.calls)
        answer = None if self.no_answer else {"status": "ANSWER", "answer": f"  Synthetic answer {turn}: £5 — exact.\n",
                                               "cited_proposition_ids": ["synthetic-prop"]}
        if not self.pack["evidence"] and answer:
            answer.update(status="CLARIFICATION", cited_proposition_ids=[])
        request = {"schema": p.VERSION, "case_id": self.case_id, "turn": turn,
            "question": "wrong due text" if self.changed_request else kwargs["question"],
            "jurisdictions": kwargs["jurisdictions"], "as_of_date": kwargs["as_of_date"],
            "due_uploads": [u[0] for u in kwargs["uploads"]],
            "history": [{"turn": n, "request_sha256": t["request_sha256"], "terminal_sha256": t["terminal_sha256"]}
                        for n, t in self.terminals.items()]}
        rendered = p.render_source_links(answer, self.pack["source_references"]) if answer else None
        if self.changed_rendering:
            rendered += "Changed outside renderer."
        terminal = {"case_id": self.case_id, "turn": turn, "request_sha256": p.digest(request),
            "policy_sha256": self.policy_sha, "answer": answer, "rendered_answer": rendered,
            "rendered_answer_sha256": p.digest(rendered.encode()) if rendered is not None else None,
            "citation_renderer": "DETERMINISTIC_SOURCE_LINKS_NOT_OSCOLA_CERTIFIED", "holds": [],
            "generation_sha256": self.pack["generation_sha256"]}
        terminal["terminal_sha256"] = p.digest(terminal)
        self.terminals[turn] = terminal
        return copy.deepcopy(terminal)

    def read_terminal(self, turn):
        return copy.deepcopy(self.terminals[turn])

    def read_answer_projection(self, turn):
        return copy.deepcopy(self.terminals[turn]["answer"])

    def read_evidence_pack(self, turn):
        return copy.deepcopy(self.pack)

    def read_source_captures(self, turn):
        return copy.deepcopy(self.records)


@pytest.fixture
def harness(monkeypatch):
    stores, hosts = {}, []
    root = v.ROOT / "synthetic-route-memory"
    fs = {root / "owner.json": b"synthetic owner", root / "marker.json": b"synthetic protected marker"}
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", lambda path: fs[path] if path in fs else original_read(path))
    def store_factory(path):
        return stores.setdefault(Path(path), MemoryStore(path))
    monkeypatch.setattr(p, "CaseStore", store_factory)
    def host_factory(kwargs):
        host = SyntheticHost(kwargs, fs, stores)
        hosts.append(host)
        return host
    monkeypatch.setattr(v, "_actual_host", host_factory)
    runtime = {"code_sha256s": {name: v.file_sha(v.ROOT / name) for name in v.CODE},
        "shared_baseline_sources": [], "training": False, "production": False,
        "baseline_created_at": STAMP.isoformat()}
    kwargs = {"run_id": "synthetic-run", "case_id": "q0001", "case_root": root / "cases/q0001",
        "protected_root": root / "protected/q0001", "mailbox_root": root / "protected/q0001/mailbox",
        "owner_instruction_path": root / "owner.json", "expected_owner_sha256": p.digest(fs[root / "owner.json"]),
        "owner_scope_sha256": H, "global_marker_path": root / "marker.json", "global_marker_sha256": p.digest(fs[root / "marker.json"]),
        "runtime_manifest": runtime, "baseline_created_at": STAMP, "model": "gpt-synthetic-test", "provider": "openai"}
    def create():
        return v.CaseRoute(host_kwargs=kwargs, expected_runtime_sha256=p.digest(kwargs["runtime_manifest"]))
    return SimpleNamespace(stores=stores, hosts=hosts, fs=fs, kwargs=kwargs, create=create)


def test_real_main_schema_rendered_text_hash_and_captured_source_projection(harness):
    route = harness.create()
    result = v.run_case_turn(route, due())
    jsonschema.validate(result["answer_output"], ANSWER_SCHEMA)
    row = result["answer_output"]["answers"][0]
    terminal = route.host.terminals[1]
    assert row["answer"] == terminal["rendered_answer"] != terminal["answer"]["answer"]
    assert row["answer"].startswith(terminal["answer"]["answer"])
    assert result["review_candidate"]["answer_sha256"] == p.digest(row["answer"].encode())
    assert [s["quote"] for s in row["sources"]] == ["Synthetic rule.", "Only with condition A.", "Currentness test context."]
    assert all(s["title"] == "Synthetic Test Act" and s["kind"] == "LEGISLATION" for s in row["sources"])
    assert row["self_audit"] == []
    exported = result["source_exports"][0]
    assert route.store.read(exported["relative_path"]) == RAW
    assert result["review_candidate"]["evidence"][1]["raw_sha256"] == p.digest(RAW)
    assert route.host.events.index("marker") < route.host.events.index("question")
    assert not {"oracle", "case_type", "expected_system_assertions"} & result["review_candidate"].keys()


def test_duplicate_noop_then_same_live_host_t2_seals_rendered_history(harness):
    route = harness.create()
    first = route.run_turn(due())
    sealed = copy.deepcopy(route.store.files)
    assert route.run_turn(due())["dispatch"] == "NO_OP_COMPLETE"
    assert route.store.files == sealed
    second = route.run_turn(due(2, first["terminal_sha256"]))
    assert len(harness.hosts) == 1 and len(route.host.calls) == 2
    assert second["stage"] == "followup" and second["review_candidate"]["case_id"] == "q0001:turn-2"
    history = second["review_candidate"]["user_input"]["history"]
    assert history == [{"role": "user", "text": due()["question"]},
                       {"role": "assistant", "text": first["answer_output"]["answers"][0]["answer"]}]
    assert all(route.store.files[name] == raw for name, raw in sealed.items())
    assert route.read_result(1)["route_result_sha256"] == first["route_result_sha256"]


@pytest.mark.parametrize("field", ["oracle", "reference", "cases", "future_turns", "history", "expected_sources"])
def test_no_extra_private_context_fields_are_disclosed(harness, field):
    route = harness.create()
    with pytest.raises(p.ProtocolError, match="SCHEMA_MISMATCH"):
        route.run_turn({**due(), field: []})
    assert not route.host.calls


@pytest.mark.parametrize("change", [{"case_id": "q0002"}, {"turn": 2}, {"previous_terminal_sha256": H}])
def test_foreign_case_early_followup_and_forged_history_refused(harness, change):
    route = harness.create()
    with pytest.raises(v.RouteHold):
        route.run_turn(due(**change))
    assert not route.host.calls


def test_changed_t1_cannot_replace_answer_and_third_turn_denied(harness):
    route = harness.create()
    result = route.run_turn(due())
    with pytest.raises(v.RouteHold, match="SEALED_DUE_INPUT_CHANGED"):
        route.run_turn(due(question="A replaced question"))
    with pytest.raises(v.RouteHold, match="PRIOR_TERMINAL_PIN_CHANGED"):
        route.run_turn(due(2, H))
    route.run_turn(due(2, result["terminal_sha256"]))
    with pytest.raises(p.ProtocolError):
        route.run_turn(due(3, route.host.terminals[2]["terminal_sha256"]))
    assert len(route.host.calls) == 2


def test_restart_cannot_adopt_or_overwrite_protected_route(harness):
    route = harness.create()
    route.run_turn(due())
    before = copy.deepcopy(route.store.files)
    with pytest.raises(FileExistsError):
        harness.create()
    assert len(harness.hosts) == 1 and route.store.files == before


def test_interrupted_host_call_consumed_without_retry(harness):
    route = harness.create()
    route.host.fail = True
    with pytest.raises(RuntimeError):
        route.run_turn(due())
    assert "unseen-route/turn-0001/HOLD.json" in route.store.files
    route.host.fail = False
    with pytest.raises(v.RouteHold):
        route.run_turn(due())
    with pytest.raises(v.RouteHold):
        route.run_turn(due(2, H))
    assert len(route.host.calls) == 1


@pytest.mark.parametrize("target", ["rendering", "request", "journal", "terminal", "marker", "code"])
def test_tamper_blocks_projection_or_replay_without_new_answer(harness, target):
    route = harness.create()
    if target in ("rendering", "request"):
        setattr(route.host, "changed_rendering" if target == "rendering" else "changed_request", True)
        with pytest.raises(v.RouteHold):
            route.run_turn(due())
    else:
        route.run_turn(due())
        if target == "journal":
            route.store.files["unseen-route/turn-0001/RESULT.json"] += b" "
        elif target == "terminal":
            route.host.terminals[1]["terminal_sha256"] = H
        elif target == "marker":
            harness.fs[harness.kwargs["global_marker_path"]] += b"changed"
        else:
            route._pins[v.CODE[0]] = H
        with pytest.raises(v.RouteHold):
            route.read_result(1)
    assert len(route.host.calls) == 1


def test_due_bytes_extracted_once_not_supplied_fixture_text(harness):
    route = harness.create()
    raw = b"%PDF-1.7\nSynthetic test bytes, not a real PDF."
    route.upload_store.files["turn-0001/one.pdf"] = raw
    item = {"upload_id": "u-one", "relative_path": "turn-0001/one.pdf", "sha256": p.digest(raw), "media_type": "application/pdf"}
    request = due(uploads=[item])
    first = route.run_turn(request)
    route.run_turn(request)
    assert len(route.host.extracts) == 1
    assert route.host.calls[0]["uploads"][0][0]["text"].startswith("Synthetic extraction")
    assert route.host.extracts[0]["path"] == route.root / "due-uploads/turn-0001/one.pdf"
    second = route.run_turn(due(2, first["terminal_sha256"]))
    assert route.host.calls[1]["uploads"] == () and len(route.host.extracts) == 1
    assert second["upload_exports"] == first["upload_exports"]
    assert second["review_candidate"]["user_input"]["attachments"] == first["review_candidate"]["user_input"]["attachments"]
    export = second["upload_exports"][0]
    assert export["review_relative_path"] == "due-uploads/turn-0001/one.pdf"
    assert route.store.read(export["relative_path"]) == raw


@pytest.mark.parametrize("path", ["../q0002/file.pdf", "/some/file.pdf", "turn-0002/later.pdf", "turn-0001/../file.pdf", "turn-0001/foreign/file.pdf"])
def test_upload_traversal_cross_case_and_future_turn_never_read(harness, path):
    route = harness.create()
    item = {"upload_id": "u", "relative_path": path, "sha256": H, "media_type": "application/pdf"}
    with pytest.raises((p.ProtocolError, v.RouteHold)):
        route.run_turn(due(uploads=[item]))
    assert not route.host.extracts and not route.host.calls


def test_upload_hash_tamper_prevents_extraction(harness):
    route = harness.create()
    route.upload_store.files["turn-0001/one.pdf"] = b"%PDF-tampered"
    item = {"upload_id": "u", "relative_path": "turn-0001/one.pdf", "sha256": H, "media_type": "application/pdf"}
    with pytest.raises(v.RouteHold, match="DUE_UPLOAD_BYTES_CHANGED"):
        route.run_turn(due(uploads=[item]))
    assert not route.host.extracts and not route.host.calls


def test_missing_source_kind_holds_output_keeps_exact_rendered_answer_and_bytes(harness):
    route = harness.create()
    raw = b"<html><head><title>An official-looking title</title></head><body>Synthetic text.</body></html>"
    route.host.pack, route.host.records = evidence_fixture(raw)
    result = route.run_turn(due())
    assert result["answer_output"] is None and result["state"] == "HOLD_PROJECTION"
    assert result["projection_holds"][0]["code"] == "SOURCE_METADATA_MISSING_OR_AMBIGUOUS"
    assert result["review_candidate"]["answer"] == route.host.terminals[1]["rendered_answer"]
    assert result["review_candidate"]["candidate_source_metadata"] == []
    assert result["review_candidate"]["projection_hold"] is True
    assert result["review_candidate"]["unknown_source_metadata"] == result["projection_holds"]
    assert result["review_candidate"]["source_references"] == route.host.pack["source_references"]
    assert route.store.read(result["source_exports"][0]["relative_path"]) == raw
    route.run_turn(due())
    assert len(route.host.calls) == 1


def test_usa_pdf_without_metadata_keeps_answer_and_all_captures_for_review(harness):
    route = harness.create()
    raw = b"%PDF-1.7\nSynthetic PDF dependency fake; not actual parser proof."
    route.host.pack, route.host.records = evidence_fixture(raw, "https://www.supremecourt.gov/opinions/synthetic.pdf")
    route.host.pack["evidence"][0]["proposition"]["jurisdiction"] = "US federal"
    result = route.run_turn(due(jurisdictions=["US federal"]))
    review = result["review_candidate"]
    assert result["answer_output"] is None and review is not None and review["projection_hold"] is True
    assert review["answer"] == route.host.terminals[1]["rendered_answer"]
    assert review["answer_sha256"] == route.host.terminals[1]["rendered_answer_sha256"]
    assert review["candidate_source_metadata"] == []  # No type inferred from court hostname.
    assert review["evidence"][1]["raw_sha256"] == p.digest(raw)
    assert review["protocol_holds"] == []  # Metadata absence is not a legal/factual HOLD.


def test_closed_route_retains_readback_but_cannot_answer_after_review_boundary(harness):
    route = harness.create()
    first = route.run_turn(due())
    closed = route.close()
    assert route.close() == closed
    assert route.read_result(1)["route_result_sha256"] == first["route_result_sha256"]
    with pytest.raises(v.RouteHold, match="CASE_ROUTE_CLOSED"):
        route.run_turn(due(2, first["terminal_sha256"]))
    assert len(route.host.calls) == 1


def test_no_final_means_no_invented_answer_or_followup(harness):
    route = harness.create()
    route.host.no_answer = True
    result = route.run_turn(due())
    assert result["answer_output"] is None and result["review_candidate"] is None
    with pytest.raises(v.RouteHold, match="FOLLOWUP_WITHOUT_FIRST_ANSWER"):
        route.run_turn(due(2, result["terminal_sha256"]))


def test_clarification_without_authority_is_compatible_and_not_complete(harness):
    route = harness.create()
    route.host.pack = {"baseline_sha256": v.EMPTY, "generation_sha256": None,
                       "retrieval_receipt_sha256": None, "evidence": [], "source_references": []}
    route.host.records = []
    result = route.run_turn(due(jurisdictions=[], as_of_date=None))
    row = result["answer_output"]["answers"][0]
    assert row["sources"] == [] and row["complete_substantive_answer"] is False
    assert route.host.calls[0]["jurisdictions"] == [] and route.host.calls[0]["as_of_date"] is None


@pytest.mark.parametrize("change", ["mailbox", "case_root", "baseline", "timestamp"])
def test_host_protection_and_common_empty_pins_required_before_constructor(harness, change):
    if change == "mailbox":
        harness.kwargs["mailbox_root"] = harness.kwargs["case_root"] / "mailbox"
    elif change == "case_root":
        harness.kwargs["case_root"] = harness.kwargs["case_root"].with_name("q0002")
    elif change == "baseline":
        harness.kwargs["runtime_manifest"]["shared_baseline_sources"] = [{"synthetic_source": H}]
    else:
        harness.kwargs["runtime_manifest"]["baseline_created_at"] = "changed"
    with pytest.raises(v.RouteHold):
        harness.create()
    assert not harness.hosts


def test_metadata_requires_explicit_type_and_preserves_actual_title():
    raw = b'<html><head><title>  Real &amp; exact title  </title><meta name="dc.type" content="Judgment"></head></html>'
    got = v.captured_metadata(raw)
    assert got["title"] == "  Real & exact title  " and got["kind"] == "CASE_LAW"
    assert got["raw_sha256"] == p.digest(raw)
    with pytest.raises(v.RouteHold):
        v.captured_metadata(raw.replace(b'content="Judgment"', b'content="unknown"'))
    with pytest.raises(v.RouteHold):
        v.captured_metadata(b'%PDF-1.7\nNo metadata classification')
    with pytest.raises(v.RouteHold):
        v.captured_metadata(b'<!ENTITY e SYSTEM "https://invalid.invalid">')


def test_source_span_and_reference_tamper_cannot_be_projected():
    pack, records = evidence_fixture()
    answer = {"status": "ANSWER", "answer": "Synthetic.", "cited_proposition_ids": ["synthetic-prop"]}
    pack["evidence"][0]["proposition"]["point"]["text"] = "Invented quotation"
    with pytest.raises(v.RouteHold, match="CAPTURE_QUOTE_CHANGED"):
        v.project_sources(answer, pack, records)
    pack, records = evidence_fixture()
    pack["source_references"][0]["sources"][0]["canonical_url"] = "https://invented.invalid"
    with pytest.raises(v.RouteHold, match="SOURCE_REFERENCE_CHANGED"):
        v.project_sources(answer, pack, records)


def test_connection_worker_constructs_before_receiving_due_and_persists_host(harness):
    class Connection:
        def __init__(self):
            self.sent, self.n = [], 0
        def send(self, value):
            self.sent.append(value)
        def recv(self):
            assert len(harness.hosts) == 1
            self.n += 1
            if self.n == 1:
                assert self.sent[0]["event"] == "READY" and self.sent[0]["questions_disclosed"] == 0
                return {"command": "run_turn", "due": due()}
            if self.n == 2:
                return {"command": "run_turn", "due": due(2, self.sent[-1]["result"]["terminal_sha256"])}
            return {"command": "close"}
    connection = Connection()
    v.serve_case(connection, host_kwargs=harness.kwargs, expected_runtime_sha256=p.digest(harness.kwargs["runtime_manifest"]))
    assert [item["event"] for item in connection.sent] == ["READY", "RESULT", "RESULT", "CLOSED"]
    assert len(harness.hosts[0].calls) == 2
