"""Synthetic in-memory dispatch integration, NOT model/network/bank proof.

The real CaseRoute/protocol schemas/render projection are used with the named
SyntheticHost double from the route tests. All 443 input rows, captures, tool/
review receipts and IO below are dependency fakes. No filesystem writes, model
jobs, network requests or private-bank reads take place.
"""
from __future__ import annotations

import copy
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import ge_unseen_case_dispatch as d
from scripts import ge_unseen_case_route as route
from scripts import ge_auto_case_protocol as p
from scripts import run_ge_codex_unseen as main
from backend.tests.test_ge_unseen_case_route import SyntheticHost, RAW, URL, H, STAMP, evidence_fixture


class MemoryFiles:
    def __init__(self):
        self.files, self.dirs, self.reads = {}, set(), []
        self.lock = threading.RLock()
        self.on_read = None

    def read(self, path, expected=None):
        path = Path(path)
        with self.lock:
            self.reads.append(path)
            if self.on_read:
                self.on_read(path)
            if path not in self.files:
                raise FileNotFoundError(str(path))
            raw = self.files[path]
            d.need(expected is None or p.digest(raw) == expected, "FILE_HASH_CHANGED")
            return raw

    def exists(self, path):
        with self.lock:
            return Path(path) in self.files or Path(path) in self.dirs

    def mkdir(self, path):
        with self.lock:
            if self.exists(path):
                raise FileExistsError(str(path))
            self.dirs.update((Path(path), *Path(path).parents))

    def write(self, path, value):
        raw = value if isinstance(value, bytes) else p.canonical(value)
        with self.lock:
            if self.exists(path):
                raise FileExistsError(str(path))
            self.files[Path(path)] = raw
            self.dirs.update(Path(path).parents)
        return p.digest(raw)


class MemoryStore:
    def __init__(self, root, io):
        self.root, self.io = Path(root), io
    def read(self, name):
        p.parts(name)
        return self.io.read(self.root / name)
    def mkdir_new(self, name):
        p.parts(name)
        self.io.mkdir(self.root / name)
    def write_new(self, name, raw):
        p.parts(name)
        self.io.write(self.root / name, raw)


@pytest.fixture
def harness(monkeypatch):
    io, stores, hosts = MemoryFiles(), {}, {}
    base = d.ROOT / "synthetic-dispatch-memory"
    private, public = base / "private", base / "public"
    owner = base / "owner.json"
    io.write(owner, b"Synthetic authority fixture, not a real owner receipt")
    codes = {name: (d.ROOT / name).read_bytes() for name in (d.SELF, *route.CODE)}
    io.files.update({d.ROOT / name: raw for name, raw in codes.items()})
    original_read = Path.read_bytes
    def path_read(path):
        if path.is_relative_to(base) or path in io.files:
            return io.read(path)
        return original_read(path)  # Only existing public schema/code reads.
    monkeypatch.setattr(Path, "read_bytes", path_read)
    monkeypatch.setattr(d, "_Files", lambda: io)
    def store_factory(root):
        return stores.setdefault(Path(root), MemoryStore(root, io))
    monkeypatch.setattr(p, "CaseStore", store_factory)
    lease_lock = threading.Lock()
    @contextmanager
    def lease(root):
        if not lease_lock.acquire(blocking=False):
            raise BlockingIOError("synthetic active dispatch lease")
        try:
            yield
        finally:
            lease_lock.release()
    monkeypatch.setattr(d, "_lease", lease)
    count = SimpleNamespace(active=0, peak=0, constructed=0, due_calls=[], reference_calls=[])
    count_lock = threading.Lock()
    class Host(SyntheticHost):
        def establish_marker(self, raw):
            marker = p.decode(raw)
            return marker["global_pre_answer_one_pass"] is True and marker["baseline_sha256"] == d.EMPTY
        def run_turn(self, **kwargs):
            count.due_calls.append((self.case_id, kwargs["question"], list(kwargs["jurisdictions"])))
            time.sleep(0.0005)
            return super().run_turn(**kwargs)
    def host_factory(kwargs):
        host = Host(kwargs, io.files, stores)
        qid = kwargs["case_id"]
        if qid == "q0002":
            host.no_answer = True
        if qid == "q0003":
            host.pack, host.records = evidence_fixture(b"<html><title>Synthetic USA/PDF-like missing type</title></html>")
        if qid == "q0004":
            host.fail = True
        hosts[qid] = host
        return host
    monkeypatch.setattr(route, "_actual_host", host_factory)
    original_make = d._make_route
    def make_route(**kwargs):
        with count_lock:
            count.constructed += 1
            count.active += 1
            count.peak = max(count.peak, count.active)
        made = original_make(**kwargs)
        original_close = made.close
        def close():
            try:
                return original_close()
            finally:
                with count_lock:
                    count.active -= 1
        made.close = close
        return made
    monkeypatch.setattr(d, "_make_route", make_route)
    mapping, shard_cases = [], {}
    for n in range(1, 444):
        system = n > 420
        shard = f"shard-{36 if system else (n - 1) // 12 + 1:02d}"
        qid = f"q{n:04d}"
        rows = shard_cases.setdefault(shard, [])
        mapping.append({"case_id": f"system:{n - 420:02d}" if system else f"synthetic-legal:{n:04d}",
            "opaque_id": qid, "shard": shard, "number": len(rows) + 1, "has_followup": n in (1, 2),
            "jurisdiction_code": "UK-NIR" if n <= 210 else "US-CA", "system": system})
        question = "Synthetic matter in England." if n != 2 else "Synthetic matter without any location."
        rows.append({"case_id": qid, "question": question, "attachment_directory": "uploads/" + qid,
                     "attachments": {"files": [], "extraction": []}})
    input_hashes, inventory = {}, {}
    raw_upload = b"%PDF-1.7\nSynthetic dependency bytes, not an actual PDF."
    upload = private / "candidate/shard-01/uploads/q0001/one.pdf"
    io.write(upload, raw_upload)
    inventory[upload.relative_to(private).as_posix()] = p.digest(raw_upload)
    shard_cases["shard-01"][0]["attachments"] = {"files": [{"path": "one.pdf", "sha256": p.digest(raw_upload)}],
        "extraction": [{"never_disclose_this_precomputed_text": "SYNTHETIC POISONED EXPECTED TEXT"}]}
    for shard, rows in shard_cases.items():
        path = private / "candidate" / shard / "input.json"
        input_hashes[shard] = io.write(path, {"as_of": "2026-09-05", "cases": rows})
        inventory[path.relative_to(private).as_posix()] = input_hashes[shard]
    mapping_sha = io.write(private / "CASE-MAPPING.json", mapping)
    followups = {}
    for row in mapping[:2]:
        initial = shard_cases[row["shard"]][row["number"] - 1]
        value = d.make_followup_release(row, initial["question"], "Correction: now in Wales, synthetic only.")
        followups[row["opaque_id"]] = io.write(private / "case-route-inputs/followups" / (row["opaque_id"] + ".json"), value)
    def parent_blind_material(binding):
        assert count.active == 0  # No reference material released while case hosts live.
        count.reference_calls.append(copy.deepcopy(binding))
        sources = []
        if binding["mapping"]["opaque_id"] == "q0001":
            raw, text = RAW + b"\n", "Synthetic second version of the same URL."
            sources.append({"raw": raw, "evidence": {"url": URL, "final_url": URL,
                "raw_sha256": p.digest(raw), "text": text, "text_sha256": p.digest(text.encode()),
                "status": "CAPTURED_NOT_LEGAL_VERIFIED", "captured_at": STAMP.isoformat()}})
        return {"binding_sha256": p.digest(binding),
            "oracle": {"case_id": binding["mapping"]["case_id"], "system_assertions": []},
            "expected_system_assertions": [], "sources": sources}
    runtime = {"model": "gpt-synthetic-test", "provider": "openai", "baseline_created_at": STAMP.isoformat(),
        "shared_baseline_sources": [], "training": False, "production": False,
        "code_sha256s": {name: p.digest(raw) for name, raw in codes.items()}}
    config = d.freeze_binding(runtime_manifest=runtime, owner_instruction_path=owner.relative_to(d.ROOT).as_posix(),
        owner_instruction_sha256=p.digest(io.read(owner)), owner_scope_sha256=H,
        followup_file_sha256s=followups, review_material_callback=parent_blind_material)
    frozen = d.seal({"run_id": "synthetic-dispatch", "case_route": config, "runtime_files": runtime["code_sha256s"],
        "case_mapping_sha256": mapping_sha, "expected_case_turns": {r["opaque_id"]: 2 if r["has_followup"] else 1 for r in mapping},
        "denominators": {"legal": 420, "system": 23}, "allowed_candidate_shards": list(shard_cases),
        "input_hashes": input_hashes, "candidate_inventory": inventory, "bank_sha256": H,
        "review_prompt_sha256": p.digest(main.REVIEW_PROMPT)})
    io.write(public / "ONE-PASS-START.json", d.seal({"runtime_sha256": frozen["content_sha256"], "bank_sha256": H}))
    r = SimpleNamespace(ROOT=d.ROOT, PRIVATE=private, PUBLIC=public, RUN_ID="synthetic-dispatch",
                        review_schema=main.review_schema, REVIEW_PROMPT=main.REVIEW_PROMPT)
    r.verify_runtime = lambda: copy.deepcopy(frozen)  # Explicit synthetic main dependency only.
    def reject_legacy(*args, **kwargs):
        raise AssertionError("No candidate CLI, recapture or oracle collection permitted")
    r.invoke = r.capture = r.collect = reject_legacy
    def observe_read(path):
        if path.parent == private / "case-route-inputs/followups":
            qid = path.stem
            assert qid in hosts and 1 in hosts[qid].terminals
            assert private / "case-route/control" / qid / "T1-RESULT.json" in io.files
    io.on_read = observe_read
    return SimpleNamespace(io=io, r=r, frozen=frozen, count=count, hosts=hosts, mapping=mapping,
                           attach=parent_blind_material, private=private, public=public, lease=lease_lock)


def test_all443_real_route_glue_once_only_t2_versions_and_metadata_review(harness):
    h = harness
    summary = d.dispatch_candidate(h.r, h.frozen)
    assert summary["case_count"] == 443 and summary["denominators"] == {"legal": 420, "system": 23}
    assert h.count.constructed == 443 and 1 < h.count.peak <= 4 and h.count.active == 0
    assert all("POISONED" not in question for _, question, _ in h.count.due_calls)
    assert "POISONED" not in h.hosts["q0001"].calls[0]["uploads"][0][0]["text"]
    assert h.hosts["q0001"].calls[0]["jurisdictions"] == ["England"]  # Hidden map says UK-NIR.
    assert h.hosts["q0002"].calls[0]["jurisdictions"] == []
    assert h.hosts["q0001"].calls[1]["jurisdictions"] == ["Wales"]
    assert len(h.hosts["q0002"].calls) == 1
    assert h.private / "case-route-inputs/followups/q0002.json" not in h.io.reads
    snapshot = copy.deepcopy(h.io.files)
    assert d.dispatch_candidate(h.r, h.frozen)["dispatch"] == "NO_OP_CASE_ROUTE_COMPLETE"
    assert d.followup_noop(h.r, h.frozen)["new_model_calls"] == 0 and h.io.files == snapshot
    final = d.final_collect(h.r, h.frozen)
    assert len(final["cases"]) == 443
    assert sum(len(c["turns"]) for c in final["cases"]) == 445
    by_id = {c["mapping"]["opaque_id"]: c for c in final["cases"]}
    assert by_id["q0002"]["turns"][1]["disposition"]["state"] == "WITHHELD_NO_T1_ANSWER"
    assert by_id["q0004"]["turns"][0]["disposition"]["state"] == "HOLD_HOST_ERROR"
    candidates = d.collect_answers(h.r, h.frozen, "candidate")
    assert len(candidates) == 441
    assert next(x for x in candidates if x["case_id"] == "q0003")["projection_hold"] is True
    assert len(d.collect_answers(h.r, h.frozen, "followup")) == 1
    prepared = d.prepare_reviews(h.r, h.frozen, attach_blind_material=h.attach)
    assert len(prepared["jobs"]) == 442 and len(prepared["unanswered_turns"]) == 3
    assert not any(path.name == "INVOCATION.json" for path in h.io.files)
    specs = d.review_job_specs(h.r, h.frozen)
    held = next(s for s in specs if s["case_id"] == "q0003:turn-1")
    assert held["projection_hold"] is True
    job = Path(specs[0]["directory"])
    review = p.decode(h.io.read(job / "input.json"))["cases"][0]
    ids = d.review_source_ids(h.r, h.frozen, job)
    captured = [e for e in review["evidence"] if e.get("url") == URL]
    assert len(captured) == 2 and len({e["source_id"] for e in captured}) == 2
    assert {e["raw_sha256"] for e in captured} == {p.digest(RAW), p.digest(RAW + b"\n")}
    assert all(e["source_id"] in ids for e in captured)
    assert (job / "due-uploads/turn-0001/upload-001.pdf") in h.io.files
    assert d.collect_reviews(h.r, h.frozen) == []  # No invented review invocations.
    with pytest.raises(FileNotFoundError):
        d.validate_review_job(h.r, h.frozen, job)
    # Actual receipt SHAPES are exercised with explicit in-memory dependency
    # fakes. These are not real fences, reviewer execution or model proof.
    props = main.review_schema()["properties"]["reviews"]["items"]["properties"]
    reviewed = {"case_id": review["case_id"], "answer_sha256": review["answer_sha256"],
        "checks": dict.fromkeys(props["checks"]["properties"], "HOLD"),
        "applicability_reasons": dict.fromkeys(props["applicability_reasons"]["properties"], "Synthetic only."),
        "material_claims": [], "omissions": ["Synthetic review; no legal validation."],
        "unclaimed_assertions_count": 0, "source_currentness": "HOLD",
        "scores": dict.fromkeys(props["scores"]["properties"], 0),
        "score_reasons": dict.fromkeys(props["score_reasons"]["properties"], "Synthetic only."),
        "complete_substantive_answer": False, "system_behavior_pass": False,
        "system_behavior_reasons": ["Synthetic only."], "system_checks": [],
        "critical_or_high_defects": ["Synthetic review is not actual model validation."]}
    invocation = {"input_sha256": p.digest(h.io.read(job / "input.json")), "fresh_context": True,
        "provider": "OPENAI", "model": "SYNTHETIC_DEPENDENCY_FAKE", "prompt_sha256": p.digest(main.REVIEW_PROMPT),
        "browse": False,
        "fence": {"own_input_readable": True, "outside_workspace_file_denied": True}, "synthetic_only": True}
    h.io.write(job / "INVOCATION.json", invocation)
    trusted = {"input_sha256": invocation["input_sha256"], "schema_sha256": p.digest(h.io.read(job / "schema.json")),
        "prompt_sha256": invocation["prompt_sha256"], "work": job.relative_to(h.private).as_posix(),
        "input_inventory": {path.relative_to(job).as_posix(): p.digest(raw)
                            for path, raw in h.io.files.items() if path.is_relative_to(job)}}
    protected = h.private / "receipts/reviews"
    h.io.write(protected / (job.name + ".json"), trusted)
    output = {"reviews": [reviewed]}
    output_sha = h.io.write(job / "output.json", output)
    completion = {"returncode": 0, "validation_error": None, "validated_rows": 1, "output_present": True,
                  "stage": "reviews", "shard": job.name}
    h.io.write(job / "COMPLETION.json", completion)
    h.io.write(protected / (job.name + "-complete.json"), {**completion, "output_sha256": output_sha})
    assert d.validate_review_job(h.r, h.frozen, job) == output
    assert d.collect_reviews(h.r, h.frozen) == [reviewed]
    for forbidden_browse in (True, None):
        # Memory-only invoker fault: even fresh-context claims do not authorize
        # post-answer source research. The original synthetic receipt stays saved.
        h.io.files[job / "INVOCATION.json"] = p.canonical({**invocation, "browse": forbidden_browse})
        with pytest.raises(d.DispatchHold, match="ACTUAL_FRESH_REVIEW_INVOCATION_REQUIRED"):
            d.validate_review_job(h.r, h.frozen, job)
    h.io.files[job / "INVOCATION.json"] = p.canonical(invocation)
    count = len(h.count.reference_calls)
    assert d.prepare_reviews(h.r, h.frozen, attach_blind_material=h.attach)["dispatch"] == "NO_OP_REVIEW_PREPARED"
    assert len(h.count.reference_calls) == count
    # Even a locally re-sealed job manifest cannot replace the protected ledger pin.
    manifest_path = job / "CASE-ROUTE-REVIEW.json"
    manifest = p.decode(h.io.files[manifest_path])
    manifest["answer_sha256"] = H
    h.io.files[manifest_path] = p.canonical(d.seal(manifest))
    with pytest.raises(d.DispatchHold, match="FILE_HASH_CHANGED"):
        d.review_source_ids(h.r, h.frozen, job)


def test_main_onepass_required_before_any_host_or_dispatch_write(harness):
    h = harness
    h.io.files.pop(h.public / "ONE-PASS-START.json")  # Memory-only fault, no file deletion.
    snapshot = copy.deepcopy(h.io.files)
    with pytest.raises(FileNotFoundError):
        d.dispatch_candidate(h.r, h.frozen)
    assert h.count.constructed == 0 and h.io.files == snapshot


def test_frozen_main_case_runtime_mismatch_prevents_disclosure(harness):
    h = harness
    h.frozen["runtime_files"][d.SELF] = H
    h.frozen.update(d.seal(h.frozen))
    with pytest.raises(d.DispatchHold, match="CASE_AND_MAIN_RUNTIME_PIN_MISMATCH"):
        d.dispatch_candidate(h.r, h.frozen)
    assert h.count.constructed == 0


def test_interrupt_classification_keeps_completed_case_and_never_restarts_hosts(harness, monkeypatch):
    h = harness
    original_write = h.io.write
    interrupted = False
    def omit_final_disposition(path, value):
        nonlocal interrupted
        if path == h.private / "case-route/control/q0001/DISPOSITION.json" and not interrupted:
            interrupted = True
            raise OSError("synthetic interruption after observed T1/T2, before case disposition")
        return original_write(path, value)
    monkeypatch.setattr(h.io, "write", omit_final_disposition)
    class InterruptedPool:
        def __init__(self, **kwargs):
            assert kwargs["max_workers"] == 4
            self.n = 0
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def submit(self, callback, *args):
            self.n += 1
            if self.n > 1:
                raise OSError("synthetic coordinator interruption")
            callback(*args)
            return SimpleNamespace()
    monkeypatch.setattr(d, "ThreadPoolExecutor", InterruptedPool)
    with pytest.raises(OSError):
        d.dispatch_candidate(h.r, h.frozen)
    assert h.count.constructed == 1
    with pytest.raises(FileNotFoundError):
        d.dispatch_candidate(h.r, h.frozen)
    assert h.count.constructed == 1
    with h.lease:
        with pytest.raises(BlockingIOError):
            d.close_interrupted(h.r, h.frozen)
    complete = d.close_interrupted(h.r, h.frozen)
    assert complete["case_count"] == 443 and complete["recorded_answers"] == 2
    assert complete["turn_dispositions"]["ANSWER_RECORDED_BEFORE_INTERRUPTION"] == 2
    assert h.count.constructed == 1
    assert complete["turn_dispositions"]["HOLD_NOT_EXECUTED_AFTER_INTERRUPTION"] == 443
    assert d.followup_noop(h.r, h.frozen)["new_model_calls"] == 0


@pytest.mark.parametrize("question, expected", [
    ("No location stated.", []), ("A matter in England and Wales.", ["England and Wales"]),
    ("New England is mentioned.", []), ("In Georgia.", []),
    ("In Georgia, USA.", ["Georgia"]), ("Washington is mentioned.", []),
    ("In Washington State.", ["Washington"]), ("In California and Scotland.", ["California", "Scotland"]),
])
def test_only_own_explicit_jurisdiction_text_is_projected(question, expected):
    result = d.own_question_scopes(question)
    assert result["scopes"] == expected and result["mapping_jurisdiction_used"] is False
    assert all(question[s["start"]:s["end"]] == s["text"] for s in result["spans"])


def test_release_schema_rejects_oracles_and_cross_case_upload_paths():
    mapping = {"opaque_id": "q0001"}
    with pytest.raises(p.ProtocolError):
        d.make_followup_release(mapping, "Synthetic question", "Due question", [{"name": "../q0002/x.pdf", "sha256": H}])
    release = d.make_followup_release(mapping, "Synthetic question", "Due question")
    release["oracle"] = {}
    with pytest.raises(p.ProtocolError):
        d._check_release(release)


@pytest.mark.parametrize("field,value", [("case_id", "q0002"), ("mapping_sha256", H), ("initial_question_sha256", H)])
def test_due_release_exact_mapping_and_initial_question_binding(harness, field, value):
    h = harness
    h.io.on_read = None  # This pure parent-release test supplies an observed-T1 double.
    mapping = h.mapping[0]
    case = {"question": "Synthetic matter in England."}
    release = d.make_followup_release(mapping, case["question"], "Own due followup")
    release[field] = value
    path = h.private / "case-route-inputs/followups/q0001.json"
    h.io.files[path] = p.canonical(release)  # Memory-only malformed, freshly pinned fixture.
    config = {"followup_file_sha256s": {"q0001": p.digest(h.io.files[path])}}
    def read_json(path, sha):
        return p.decode(h.io.read(path, sha))
    ctx = SimpleNamespace(private=h.private, root=h.private / "case-route", config=config, io=h.io, json=read_json)
    first = {"turn": 1, "case_id": "q0001", "review_candidate": {"synthetic": True}, "terminal_sha256": H}
    with pytest.raises(d.DispatchHold, match="T2_MAPPING_CHANGED"):
        d._release_second(ctx, {"mapping": mapping}, case, first)
    assert not h.count.constructed and not any(p.name == "T2-RELEASE.json" for p in h.io.files)


def test_capture_version_export_rejects_unofficial_url_and_changed_text_hash(harness):
    h = harness
    ctx = SimpleNamespace(io=h.io)
    folder = h.private / "synthetic-review-only"
    text = "Synthetic captured text"
    evidence = {"url": URL, "final_url": URL, "raw_sha256": p.digest(RAW), "text": text,
                "text_sha256": p.digest(text.encode()), "status": "CAPTURED_NOT_LEGAL_VERIFIED"}
    first, _ = d._version_source(ctx, folder, evidence, RAW)
    second, _ = d._version_source(ctx, folder, {**evidence, "raw_sha256": p.digest(RAW + b"\n")}, RAW + b"\n")
    assert first["source_id"] != second["source_id"]
    with pytest.raises(d.DispatchHold, match="REVIEW_CAPTURE_BINDING"):
        d._version_source(ctx, folder, {**evidence, "text_sha256": H}, RAW)
    with pytest.raises(d.DispatchHold, match="REVIEW_CAPTURE_BINDING"):
        d._version_source(ctx, folder, {**evidence, "url": "https://private.invalid/"}, RAW)
