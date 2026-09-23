"""Concrete main-run glue. No IO, bank discovery or execution on import.

MAIN INTEGRATION (parent implements/finalizes these hooks before freezing):

* Add this file, ge_unseen_case_route.py and every CaseHost runtime code file to
  main.runtime_files(). Put the exact common CaseHost runtime in frozen['case_route']
  using freeze_binding(...); its baseline_created_at is the common ISO timestamp.
  Build it with ge_auto_case_host.runtime_manifest(model=explicit_model,
  provider='openai'), add the route/main/dispatcher code pins and one common
  timezone-aware baseline_created_at=stamp.isoformat(), then freeze its digest.
  The factory resolves installed runtime identities; it does not certify readiness.
  Parent readiness must bind this final manifest/code set before prepare_candidates
  seals the main freeze. Do not infer the model from a CLI identity or choose a
  new timestamp per case. No schema-generation/model call is needed by this helper.
* Parent creates case-route-inputs/followups/qNNNN.json from the exact author
  mapping, using make_followup_release, BEFORE freeze. Pin its actual file hash
  in the binding. This helper never reads an author/oracle/reference directory.
  Deferred upload files belong only to case-route-inputs/uploads/qNNNN/<name>.
  Existing author/fixture schemas have no upload_turn/release_turn contract.
  Candidate attachments.files is an already validated INITIAL-DUE projection;
  this helper does not infer scheduling from document names, prose or an oracle.
  Parent must resolve ambiguous timing before freeze. T2's release schema is
  {schema,case_id,mapping_sha256,initial_question_sha256,question,uploads}, with
  uploads=[{name:basename,sha256:actual_file_sha256}]; no future extraction text.
* After main verifies readiness and writes its real ONE-PASS-START.json, call
  dispatch_candidate(r, frozen). No candidate r.invoke/batch CLI is used. The
  parent rejects --only for this all-case route; partial replay is not supported.
  active parent services each real CaseHost ParentMailbox under
  PRIVATE/case-route/protected/qNNNN/mailbox. Exactly four trusted HOST threads
  share this process; model role isolation is CaseHost's fence, not thread custody.
* Delegate main followup preparation/execution to followup_noop(r, frozen), main
  candidate/followup collection to collect_answers, and case-route validation to
  validate_turn/validate_run. Do not synthesize legacy INVOCATION/COMPLETION.
* Once dispatch is terminal, call prepare_reviews(r, frozen,
  attach_blind_material=parent_callback). The callback is mandatory if answers
  exist; freeze its code hash. It runs only after ALL case hosts have closed.
  It receives {mapping, turn, answer_sha256, main_freeze_sha256} and returns
  {binding_sha256, oracle, expected_system_assertions, sources}. Parent verifies
  its own frozen oracle/reference lineage. Each sources item is {evidence, raw}
  from an EXISTING exact capture, never a recapture. evidence has url, final_url,
  raw_sha256, text, text_sha256, and status='CAPTURED_NOT_LEGAL_VERIFIED'. No callback/source
  data is ever released back to a candidate or an index. This callback's code pin
  is an identity check, not a signature or external custody proof.
* Review jobs are one turn each at PRIVATE/case-route/reviews/qNNNN-turn-NN.
  prepare_reviews writes input.json/schema.json and CASE-ROUTE-REVIEW.json only.
  review_job_specs returns verified paths for the parent's actual r.invoke with
  REVIEW_PROMPT. validate_review_job validates those actual main-invoker receipts;
  Invoke with browse=False; validation enforces that exact recorded setting.
  Protected receipts are PRIVATE/receipts/reviews/<job>.json and
  <job>-complete.json, matching work.parent.name == 'reviews'.
  collect_reviews is the corresponding main collect('review','reviews') hook.
  No invocations are fabricated or launched by these preparation/read helpers.
  validate_review_output checks the exact prepared answer/source IDs;
  it does NOT replace the parent's actual reviewer-custody/completion validation.
  final_collect supplies every case/required turn (including missing answers),
  while collect_answers includes metadata-held answers from review_candidate.
  Main must replace its legacy candidate-sources/<URL-hash> lookup with
  review_source_ids; versioned source files live in each review job's sources/.

Run index and CASE-ROUTE-START are exclusive, after the main one-pass marker.
Unfinished dispatch cannot be restarted. close_interrupted may ONLY classify
missing dispositions while holding the now-free dispatch flock; it never starts
another host/model. Existing receipts/failed attempts are never changed/deleted.
All 443 cases (420 legal, 23 system) and every required turn remain accounted for.
Metadata compatibility holds do not discard a terminal rendered answer or become
legal/factual review failures. No legal pass, source admission or training claim.

Jurisdiction input is a conservative inventory of explicit full names in the own
question, with source-character spans; no mapping jurisdiction/oracle is consulted.
It is an allowed research-scope inventory, not established user facts. Ambiguous
names/unknown locations stay empty/clarification. T2 uses new explicit names or
its own T1 inventory. as_of is the frozen candidate envelope's research date, not
an inferred event date. Event-date uncertainty remains the planner/review's HOLD.

Tests use in-memory dependency doubles; parent actual visible validation and the
final frozen readiness gates are still required. Do not run against a held bank.
"""
from __future__ import annotations

import copy
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from scripts import ge_auto_case_protocol as p
from scripts import ge_unseen_case_route as route_api
from scripts.ge_auto_host_bridge import callback_sha256
from scripts.ge_auto_role_runtime import safe
from scripts.ge_unseen_sources import is_allowed_source_url, redirect_allowed

ROOT = Path(__file__).resolve().parents[1]
VERSION = "legalbot.ge-unseen-case-dispatch.v1"
RELEASE_VERSION = "legalbot.ge-unseen-due-release.v1"
TOTAL, WORKERS = 443, 4
SELF = "scripts/ge_unseen_case_dispatch.py"
EMPTY = p.digest([])


class DispatchHold(ValueError):
    """Stable diagnostic codes, never private exception/question text."""


def need(ok, code):
    if not ok:
        raise DispatchHold(code)


def seal(value):
    body = {k: v for k, v in value.items() if k != "content_sha256"}
    return {**body, "content_sha256": p.digest(body)}


class _Files:
    def read(self, path, expected=None):
        path = Path(path)
        safe(path, ROOT)
        raw = p.CaseStore(path.parent).read(path.name)
        need(expected is None or p.digest(raw) == expected, "FILE_HASH_CHANGED")
        return raw

    def exists(self, path):
        safe(path, ROOT)
        return p.CaseStore(path.parent).exists(path.name)

    def mkdir(self, path):
        safe(path, ROOT)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)

    def write(self, path, value):
        safe(path, ROOT)
        raw = value if isinstance(value, bytes) else p.canonical(value)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        p.CaseStore(path.parent).write_new(path.name, raw)
        return p.digest(raw)


@contextmanager
def _lease(root):
    with p.CaseStore(root).lock():
        yield


def _make_route(**kwargs):
    return route_api.CaseRoute(**kwargs)


def freeze_binding(*, runtime_manifest, owner_instruction_path, owner_instruction_sha256,
                   owner_scope_sha256, followup_file_sha256s, review_material_callback):
    """Pure freeze value; followup hashes are FILE hashes, not inferred content."""
    p.checked(owner_instruction_sha256, p.HASH); p.checked(owner_scope_sha256, p.HASH)
    p.parts(owner_instruction_path)
    for key, sha in followup_file_sha256s.items():
        need(re.fullmatch(r"q\d{4}", key), "OPAQUE_CASE_ID_REQUIRED")
        p.checked(sha, p.HASH)
    return {"schema": VERSION, "runtime_manifest": copy.deepcopy(runtime_manifest),
        "runtime_sha256": p.digest(runtime_manifest), "owner_instruction_path": owner_instruction_path,
        "owner_instruction_sha256": owner_instruction_sha256, "owner_scope_sha256": owner_scope_sha256,
        "followup_file_sha256s": dict(followup_file_sha256s), "max_workers": WORKERS,
        "review_material_callback_sha256": callback_sha256(review_material_callback)}


def make_followup_release(mapping, initial_question, question, uploads=()):
    """Parent author-to-due projection; receives no oracle/source selections."""
    value = {"schema": RELEASE_VERSION, "case_id": mapping["opaque_id"],
        "mapping_sha256": p.digest(mapping), "initial_question_sha256": p.digest(initial_question.encode()),
        "question": question, "uploads": list(uploads)}
    _check_release(value)
    return value


def _check_release(value):
    p.checked(value, p.obj({"schema": {"const": RELEASE_VERSION}, "case_id": p.ID,
        "mapping_sha256": p.HASH, "initial_question_sha256": p.HASH, "question": p.string(50000),
        "uploads": p.array(p.obj({"name": p.string(120), "sha256": p.HASH}), 16)}))
    need(len({x["name"] for x in value["uploads"]}) == len(value["uploads"]), "DUPLICATE_RELEASE_UPLOAD")
    for item in value["uploads"]:
        need(len(p.parts(item["name"])) == 1, "RELEASE_UPLOAD_SCOPE")


def own_question_scopes(question):
    """Literal own-text inventory only; no city/state/private-map inference."""
    candidates = []
    aliases = {"Washington State": "Washington", "State of Washington": "Washington",
               "Washington, DC": "District of Columbia", "Washington, D.C.": "District of Columbia",
               "United Kingdom": "UK"}
    names = {name: name for name in (*p.UK, *p.US) if name not in ("Georgia", "Washington")}
    names.update(aliases)
    for text, name in names.items():
        for match in re.finditer(r"(?<!\w)" + re.escape(text) + r"(?!\w)", question, re.IGNORECASE):
            if name == "England" and question[max(0, match.start() - 4):match.start()].casefold() == "new ":
                continue
            candidates.append((match.start(), match.end(), name))
    for match in re.finditer(r"(?<!\w)(?:Georgia, (?:USA|US)|(?:US state of|State of) Georgia)(?!\w)", question, re.IGNORECASE):
        candidates.append((match.start(), match.end(), "Georgia"))
    selected = []
    for start, end, name in sorted(candidates, key=lambda x: (-(x[1] - x[0]), x[0])):
        if not any(start < prior[1] and end > prior[0] for prior in selected):
            selected.append((start, end, name))
    spans = [{"start": start, "end": end, "text": question[start:end], "scope": name}
             for start, end, name in sorted(selected)]
    scopes = list(dict.fromkeys(s["scope"] for s in spans))
    return {"scopes": scopes if len(scopes) <= 8 else [], "spans": spans,
        "basis": "EXPLICIT_OWN_QUESTION_NAMES_NOT_ESTABLISHED_FACTS", "mapping_jurisdiction_used": False}


class _Context:
    def __init__(self, r, frozen):
        self.r, self.frozen, self.io = r, copy.deepcopy(frozen), _Files()
        need(Path(r.ROOT) == ROOT, "WORKSPACE_CHANGED")
        self.private, self.public = Path(r.PRIVATE), Path(r.PUBLIC)
        for path in (self.private, self.public):
            safe(path, ROOT)
        need(self.private != self.public and not self.private.is_relative_to(self.public)
             and not self.public.is_relative_to(self.private), "RUN_ROOT_COLLISION")
        need(r.verify_runtime() == frozen and frozen == seal(frozen), "MAIN_FREEZE_CHANGED")
        need(frozen["run_id"] == r.RUN_ID, "RUN_ID_CHANGED")
        self.config = frozen["case_route"]
        c = self.config
        need(set(c) == {"schema", "runtime_manifest", "runtime_sha256", "owner_instruction_path",
            "owner_instruction_sha256", "owner_scope_sha256", "followup_file_sha256s", "max_workers",
            "review_material_callback_sha256"} and c["schema"] == VERSION and c["max_workers"] == WORKERS,
            "CASE_ROUTE_FREEZE_REQUIRED")
        runtime = c["runtime_manifest"]
        need(p.digest(runtime) == c["runtime_sha256"] and runtime["shared_baseline_sources"] == []
             and runtime["training"] is False and runtime["production"] is False, "EMPTY_FROZEN_RUNTIME_REQUIRED")
        for name in (SELF, *route_api.CODE, *runtime["code_sha256s"]):
            p.parts(name)
            expected = runtime["code_sha256s"].get(name)
            need(expected is not None and frozen["runtime_files"].get(name) == expected,
                 "CASE_AND_MAIN_RUNTIME_PIN_MISMATCH")
            self.io.read(ROOT / name, expected)
        stamp = datetime.fromisoformat(runtime["baseline_created_at"])
        need(stamp.tzinfo is not None, "COMMON_BASELINE_TIMESTAMP_REQUIRED")
        self.stamp = stamp
        p.parts(c["owner_instruction_path"])
        self.owner_path = ROOT / c["owner_instruction_path"]
        self.io.read(self.owner_path, c["owner_instruction_sha256"])
        self.main_start = self.json(self.public / "ONE-PASS-START.json")
        need(self.main_start == seal(self.main_start)
             and self.main_start["runtime_sha256"] == frozen["content_sha256"]
             and self.main_start["bank_sha256"] == frozen["bank_sha256"], "MAIN_ONEPASS_REQUIRED")
        self.main_start_sha = p.digest(self.io.read(self.public / "ONE-PASS-START.json"))
        self.root = self.private / "case-route"
        self.marker = self.public / "CASE-ROUTE-START.json"

    def json(self, path, sha=None):
        return p.decode(self.io.read(path, sha))

    def ref(self, path):
        return {"path": path.relative_to(self.root).as_posix(), "sha256": p.digest(self.io.read(path))}

    def from_ref(self, ref):
        p.parts(ref["path"])
        return self.json(self.root / ref["path"], ref["sha256"])

    def mapping(self):
        rows = self.json(self.private / "CASE-MAPPING.json", self.frozen["case_mapping_sha256"])
        need(isinstance(rows, list) and len(rows) == TOTAL
             and {r["opaque_id"] for r in rows} == {f"q{n:04d}" for n in range(1, TOTAL + 1)}
             and len({r["case_id"] for r in rows}) == TOTAL, "ALL_443_MAPPING_REQUIRED")
        need(all(type(r["system"]) is bool and type(r["has_followup"]) is bool for r in rows)
             and sum(r["system"] for r in rows) == 23 and self.frozen["denominators"] == {"legal": 420, "system": 23},
             "FIXED_DENOMINATORS_REQUIRED")
        need(self.frozen["expected_case_turns"] == {r["opaque_id"]: 2 if r["has_followup"] else 1 for r in rows}
             and set(self.config["followup_file_sha256s"]) == {r["opaque_id"] for r in rows if r["has_followup"]},
             "EXACT_DUE_TURN_INVENTORY_REQUIRED")
        return rows

    def initial_index(self):
        mapping = self.mapping()
        payloads, inputs = {}, {}
        need(len(set(self.frozen["allowed_candidate_shards"])) == len(self.frozen["allowed_candidate_shards"])
             and set(self.frozen["allowed_candidate_shards"]) == set(self.frozen["input_hashes"]), "SHARD_INVENTORY_CHANGED")
        for shard in self.frozen["allowed_candidate_shards"]:
            need(re.fullmatch(r"shard-\d{2}", shard), "INVALID_SHARD")
            path = self.private / "candidate" / shard / "input.json"
            inputs[shard] = self.json(path, self.frozen["input_hashes"][shard])
            p.day(inputs[shard]["as_of"])
        entries = []
        for row in mapping:
            shard, number, qid = row["shard"], row["number"], row["opaque_id"]
            need(shard in inputs and type(number) is int and 1 <= number <= len(inputs[shard]["cases"]), "MAPPING_POSITION")
            case = inputs[shard]["cases"][number - 1]
            need(set(case) == {"case_id", "question", "attachment_directory", "attachments"}
                 and case["case_id"] == qid and case["attachment_directory"] == "uploads/" + qid
                 and isinstance(case["attachments"], dict) and set(case["attachments"]) == {"files", "extraction"},
                 "CANDIDATE_INPUT_PROJECTION_REQUIRED")
            p.checked(case["question"], p.string(50000))
            payloads[qid] = copy.deepcopy(case)
            entries.append({"mapping": row, "case_input_sha256": p.digest(case),
                "as_of": inputs[shard]["as_of"], "turns": list(range(1, self.frozen["expected_case_turns"][qid] + 1))})
        need(sum(len(v["cases"]) for v in inputs.values()) == TOTAL
             and len({(r["shard"], r["number"]) for r in mapping}) == TOTAL, "EXTRA_OR_DUPLICATE_CANDIDATE")
        return entries, payloads

    def load_index(self):
        marker = self.json(self.marker)
        policy = p.FrozenPolicy(self.r.RUN_ID, self.config["owner_instruction_sha256"], self.config["runtime_sha256"], "EMPTY", EMPTY)
        need(marker == seal(marker) and marker["main_freeze_sha256"] == self.frozen["content_sha256"]
             and marker["main_onepass_sha256"] == self.main_start_sha
             and marker["runtime_sha256"] == self.config["runtime_sha256"] and marker["baseline_sha256"] == EMPTY
             and marker["run_id"] == self.r.RUN_ID and marker["policy_sha256"] == p.digest(policy.manifest())
             and marker["owner_instruction_sha256"] == self.config["owner_instruction_sha256"]
             and marker["global_pre_answer_one_pass"] is True and marker["training"] is False and marker["production"] is False,
             "CASE_ROUTE_START_CHANGED")
        value = self.json(self.root / "RUN-INDEX.json", marker["run_index_file_sha256"])
        need(value == seal(value) and value["main_freeze_sha256"] == self.frozen["content_sha256"]
             and [e["mapping"] for e in value["cases"]] == self.mapping(), "RUN_INDEX_CHANGED")
        self.index, self.start = value, marker
        return value

    def turn_result(self, entry, outcome):
        result = self.from_ref(outcome["result"])
        qid, turn = entry["mapping"]["opaque_id"], outcome["turn"]
        protected = self.root / "protected" / qid
        path = protected / "unseen-route" / f"turn-{turn:04d}" / "RESULT.json"
        core = self.json(path, result["route_result_sha256"])
        need(core == {k: v for k, v in result.items() if k not in ("route_result_sha256", "dispatch")}
             and core["case_id"] == qid and core["turn"] == turn and core["runtime_sha256"] == self.config["runtime_sha256"],
             "CASE_ROUTE_RESULT_CHANGED")
        for name, sha in core["artifacts"].items():
            p.parts(name)
            self.io.read(protected / "unseen-route" / name, sha)
        terminal = self.json(protected / "unseen-route" / f"turn-{turn:04d}" / "TERMINAL.json")
        need(terminal["terminal_sha256"] == core["terminal_sha256"] == outcome["terminal_sha256"]
             and p.digest({k: v for k, v in terminal.items() if k != "terminal_sha256"}) == terminal["terminal_sha256"],
             "EXACT_TERMINAL_CHANGED")
        pack = self.json(protected / "unseen-route" / f"turn-{turn:04d}" / "EvidencePack.json")
        rendered = route_api.rendered_text(terminal, pack)
        review = core["review_candidate"]
        need((rendered is None and review is None) or (review is not None and review["answer"] == rendered
             and review["answer_sha256"] == terminal["rendered_answer_sha256"]
             and review["case_id"] == qid + f":turn-{turn}"), "RENDERED_REVIEW_PROJECTION_CHANGED")
        for export in core["source_exports"] + core["upload_exports"]:
            p.parts(export["relative_path"])
            need(export["relative_path"].startswith("unseen-route/"), "EXPORT_OUTSIDE_OWN_ROUTE")
            self.io.read(protected / export["relative_path"], export["sha256"])
        return result

    def complete(self):
        self.load_index()
        outcome = self.json(self.root / "DISPATCH-OUTCOME.json")
        need(outcome == seal(outcome) and outcome["run_index_sha256"] == self.index["content_sha256"]
             and set(outcome["dispositions"]) == {e["mapping"]["opaque_id"] for e in self.index["cases"]},
             "ALL_CASE_TERMINALS_REQUIRED")
        cases = []
        for entry in self.index["cases"]:
            qid = entry["mapping"]["opaque_id"]
            disposition = self.from_ref(outcome["dispositions"][qid])
            need(disposition == seal(disposition) and disposition["case_id"] == qid
                 and disposition["run_index_sha256"] == self.index["content_sha256"]
                 and [t["turn"] for t in disposition["turns"]] == entry["turns"], "CASE_DISPOSITION_CHANGED")
            for turn in disposition["turns"]:
                if turn.get("result"):
                    self.turn_result(entry, turn)
            cases.append((entry, disposition))
        return outcome, cases


def _stage_uploads(ctx, qid, turn, items, case_root):
    need(len(items) <= 16, "DUE_UPLOAD_LIMIT")
    result, origins = [], []
    for n, (source, sha) in enumerate(items, 1):
        raw = ctx.io.read(source, sha)
        if raw.startswith(b"%PDF-"):
            ext, media = "pdf", "application/pdf"
        elif raw.startswith(b"\x89PNG\r\n\x1a\n"):
            ext, media = "png", "image/png"
        else:
            raise DispatchHold("DUE_UPLOAD_FORMAT_HOLD")
        name = f"turn-{turn:04d}/upload-{n:03d}.{ext}"
        ctx.io.write(case_root / "due-uploads" / name, raw)
        result.append({"upload_id": f"turn-{turn:04d}-upload-{n:03d}", "relative_path": name,
                       "sha256": sha, "media_type": media})
        origins.append({"input_path": source.relative_to(ctx.private).as_posix(), "sha256": sha, "staged_path": name})
    need(len(result) <= 16, "DUE_UPLOAD_LIMIT")
    ctx.io.write(ctx.root / "control" / qid / f"T{turn}-UPLOAD-PROJECTION.json", origins)
    return result


def _first_uploads(ctx, entry, case):
    base = ctx.private / "candidate" / entry["mapping"]["shard"] / case["attachment_directory"]
    items = []
    need(isinstance(case["attachments"]["files"], list) and len(case["attachments"]["files"]) <= 16, "DUE_UPLOAD_LIMIT")
    for record in case["attachments"]["files"]:
        relative = record.get("relative_path", record.get("path"))
        p.parts(relative)
        path = base / relative
        sha = record["sha256"]
        need(ctx.frozen["candidate_inventory"].get(path.relative_to(ctx.private).as_posix()) == sha,
             "UNFROZEN_DUE_UPLOAD")
        items.append((path, sha))
    need(len({path for path, _ in items}) == len(items), "DUPLICATE_DUE_UPLOAD")
    return items


def _release_second(ctx, entry, case, first):
    qid = entry["mapping"]["opaque_id"]
    need(first["turn"] == 1 and first["case_id"] == qid and first["review_candidate"] is not None,
         "T2_REQUIRES_OBSERVED_T1_ANSWER")
    # Open exactly this deferred parent file, only after T1 has been recorded.
    sha = ctx.config["followup_file_sha256s"][qid]
    release = ctx.json(ctx.private / "case-route-inputs" / "followups" / (qid + ".json"), sha)
    _check_release(release)
    need(release["case_id"] == qid and release["mapping_sha256"] == p.digest(entry["mapping"])
         and release["initial_question_sha256"] == p.digest(case["question"].encode()), "T2_MAPPING_CHANGED")
    ctx.io.write(ctx.root / "control" / qid / "T2-RELEASE.json", {
        "release_file_sha256": sha, "mapping_sha256": release["mapping_sha256"],
        "observed_t1_terminal_sha256": first["terminal_sha256"], "question_sha256": p.digest(release["question"].encode()),
        "basis": "PARENT_HOST_RELEASED_EXACT_MAPPED_DUE_FILE_AFTER_OBSERVED_T1"})
    items = [(ctx.private / "case-route-inputs" / "uploads" / qid / item["name"], item["sha256"])
             for item in release["uploads"]]
    return release["question"], items


def _case(ctx, entry, case):
    qid = entry["mapping"]["opaque_id"]
    control, case_root, protected = (ctx.root / name / qid for name in ("control", "cases", "protected"))
    ctx.io.mkdir(control)
    ctx.io.write(control / "START.json", {"run_index_sha256": ctx.index["content_sha256"],
        "case_id": qid, "case_input_sha256": entry["case_input_sha256"], "state": "ATTEMPT_RESERVED"})
    outcomes, host, closed, error = [], None, None, None
    try:
        ctx.io.mkdir(case_root); ctx.io.mkdir(protected)
        c, runtime = ctx.config, ctx.config["runtime_manifest"]
        host = _make_route(host_kwargs={"run_id": ctx.r.RUN_ID, "case_id": qid, "case_root": case_root,
            "protected_root": protected, "mailbox_root": protected / "mailbox",
            "owner_instruction_path": ctx.owner_path, "expected_owner_sha256": c["owner_instruction_sha256"],
            "owner_scope_sha256": c["owner_scope_sha256"], "global_marker_path": ctx.marker,
            "global_marker_sha256": p.digest(ctx.io.read(ctx.marker)), "runtime_manifest": runtime,
            "baseline_created_at": ctx.stamp, "model": runtime["model"], "provider": runtime["provider"]},
            expected_runtime_sha256=c["runtime_sha256"])
        question, items, prior, prior_scopes = case["question"], _first_uploads(ctx, entry, case), None, []
        for turn in entry["turns"]:
            if turn == 2:
                if prior["review_candidate"] is None:
                    outcomes.append({"turn": 2, "state": "WITHHELD_NO_T1_ANSWER", "answer_present": False})
                    break
                question, items = _release_second(ctx, entry, case, prior)
            scopes = own_question_scopes(question)
            scopes["own_history_fallback"] = bool(turn > 1 and not scopes["scopes"])
            if scopes["own_history_fallback"]:
                scopes["scopes"] = prior_scopes
            ctx.io.write(control / f"T{turn}-SCOPE-PROJECTION.json", scopes)
            uploads = _stage_uploads(ctx, qid, turn, items, case_root)
            due = {"schema": route_api.VERSION, "case_id": qid, "turn": turn, "question": question,
                "jurisdictions": scopes["scopes"], "as_of_date": entry["as_of"], "uploads": uploads,
                "previous_terminal_sha256": prior["terminal_sha256"] if prior else None}
            result = host.run_turn(due)
            need(result["case_id"] == qid and result["turn"] == turn, "ROUTE_CASE_CHANGED")
            ctx.io.write(control / f"T{turn}-RESULT.json", result)
            present = result["review_candidate"] is not None
            outcomes.append({"turn": turn, "state": "ANSWER_RECORDED" if present else "HOLD_FINAL_CONSUMED",
                "answer_present": present, "legacy_projection_hold": bool(result["projection_holds"]),
                "result": ctx.ref(control / f"T{turn}-RESULT.json"), "terminal_sha256": result["terminal_sha256"]})
            prior, prior_scopes = result, scopes["scopes"]
    except Exception as exc:
        error = {"type": type(exc).__name__, "code": str(exc) if isinstance(exc, DispatchHold) else "CASE_HOST_OR_ROUTE_HOLD"}
    finally:
        if host is not None:
            try:
                closed = host.close()
                ctx.io.write(control / "CLOSED.json", closed)
            except Exception as exc:
                error = {"type": type(exc).__name__, "code": "CASE_CLOSE_HOLD"}
    first_missing = len(outcomes) + 1
    for turn in entry["turns"][len(outcomes):]:
        outcomes.append({"turn": turn, "state": "HOLD_HOST_ERROR" if turn == first_missing else "WITHHELD_AFTER_ERROR",
                         "answer_present": False})
    disposition = seal({"schema": VERSION, "case_id": qid, "run_index_sha256": ctx.index["content_sha256"],
        "turns": outcomes, "close_receipt": closed, "error": error, "further_answers_allowed": False})
    ctx.io.write(control / "DISPOSITION.json", disposition)
    return disposition


def _finish(ctx):
    refs, states, answers = {}, Counter(), 0
    for entry in ctx.index["cases"]:
        qid = entry["mapping"]["opaque_id"]
        path = ctx.root / "control" / qid / "DISPOSITION.json"
        value = ctx.json(path)
        need(value == seal(value) and value["case_id"] == qid
             and [t["turn"] for t in value["turns"]] == entry["turns"], "MISSING_CASE_DISPOSITION")
        refs[qid] = ctx.ref(path)
        states.update(t["state"] for t in value["turns"])
        answers += sum(t["answer_present"] for t in value["turns"])
    result = seal({"schema": VERSION, "run_index_sha256": ctx.index["content_sha256"], "dispositions": refs,
        "state": "ALL_443_CASES_TERMINALLY_DISPOSED_REVIEW_PENDING", "case_count": TOTAL,
        "denominators": {"legal": 420, "system": 23}, "turn_dispositions": dict(states), "recorded_answers": answers,
        "candidate_batch_cli_used": False, "max_host_threads": WORKERS, "training": False,
        "production": False, "professional_sign_off": False, "actual_parent_validation": "REQUIRED"})
    ctx.io.write(ctx.root / "DISPATCH-OUTCOME.json", result)
    return result


def dispatch_candidate(r, frozen):
    ctx = _Context(r, frozen)
    if ctx.io.exists(ctx.marker):
        result, _ = ctx.complete()
        return {**result, "dispatch": "NO_OP_CASE_ROUTE_COMPLETE"}
    need(not ctx.io.exists(ctx.public / "STATE-TRANSITION-RECEIPT.json"), "TERMINAL_RUN_CLOSED")
    entries, payloads = ctx.initial_index()
    ctx.io.mkdir(ctx.root)  # Existing/uncertain run roots are never adopted.
    with _lease(ctx.root):
        ctx.index = seal({"schema": VERSION, "main_freeze_sha256": frozen["content_sha256"],
            "runtime_sha256": ctx.config["runtime_sha256"], "case_mapping_sha256": frozen["case_mapping_sha256"],
            "cases": entries, "one_pass": True, "max_host_threads": WORKERS})
        index_sha = ctx.io.write(ctx.root / "RUN-INDEX.json", ctx.index)
        policy = p.FrozenPolicy(r.RUN_ID, ctx.config["owner_instruction_sha256"], ctx.config["runtime_sha256"], "EMPTY", EMPTY)
        ctx.start = seal({"schema": VERSION, "run_id": r.RUN_ID, "main_freeze_sha256": frozen["content_sha256"],
            "main_onepass_sha256": ctx.main_start_sha, "runtime_sha256": ctx.config["runtime_sha256"],
            "policy_sha256": p.digest(policy.manifest()), "baseline_sha256": EMPTY,
            "owner_instruction_sha256": ctx.config["owner_instruction_sha256"], "run_index_file_sha256": index_sha,
            "global_pre_answer_one_pass": True, "started_at": datetime.now(UTC).isoformat(), "training": False, "production": False})
        ctx.io.write(ctx.marker, ctx.start)
        with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="case-host") as pool:
            futures = [pool.submit(_case, ctx, entry, payloads[entry["mapping"]["opaque_id"]]) for entry in entries]
            for future in as_completed(futures):
                future.result()  # A failed receipt write prevents a false terminal tally.
        return _finish(ctx)


def close_interrupted(r, frozen):
    """After acquiring the free run lease, classify missing work without retries."""
    ctx = _Context(r, frozen)
    with _lease(ctx.root):
        ctx.load_index()
        if ctx.io.exists(ctx.root / "DISPATCH-OUTCOME.json"):
            return ctx.complete()[0]
        for entry in ctx.index["cases"]:
            qid = entry["mapping"]["opaque_id"]
            control = ctx.root / "control" / qid
            if ctx.io.exists(control / "DISPOSITION.json"):
                continue
            state = "HOLD_INTERRUPTED_UNOBSERVED_TERMINAL" if ctx.io.exists(control / "START.json") else "HOLD_NOT_EXECUTED_AFTER_INTERRUPTION"
            # Parent Tn-RESULT is an already observed route return, unlike orphan
            # role/protocol files. Preserve it for review, without resuming custody.
            turns = []
            for n in entry["turns"]:
                parent_result = control / f"T{n}-RESULT.json"
                if ctx.io.exists(parent_result):
                    saved = ctx.json(parent_result)
                    row = {"turn": n, "terminal_sha256": saved["terminal_sha256"], "result": ctx.ref(parent_result),
                        "answer_present": saved["review_candidate"] is not None,
                        "state": "ANSWER_RECORDED_BEFORE_INTERRUPTION" if saved["review_candidate"] is not None else "HOLD_FINAL_CONSUMED",
                        "legacy_projection_hold": bool(saved["projection_holds"])}
                    ctx.turn_result(entry, row)
                    turns.append(row)
                else:
                    turns.append({"turn": n, "state": state, "answer_present": False})
            ctx.io.write(control / "DISPOSITION.json", seal({"schema": VERSION, "case_id": qid,
                "run_index_sha256": ctx.index["content_sha256"], "turns": turns, "close_receipt": None,
                "error": {"code": state}, "further_answers_allowed": False}))
        return _finish(ctx)


def validate_run(r, frozen):
    return _Context(r, frozen).complete()[0]


def followup_noop(r, frozen):
    result = validate_run(r, frozen)
    return {"stage": "followup", "state": "NO_OP_CASE_ROUTE_FOLLOWUPS_TERMINAL", "new_model_calls": 0,
            "dispatch_outcome_sha256": result["content_sha256"]}


def validate_turn(r, frozen, case_id, turn):
    ctx = _Context(r, frozen)
    _, cases = ctx.complete()
    for entry, case in cases:
        if case["case_id"] == case_id:
            for row in case["turns"]:
                if row["turn"] == turn:
                    return {"disposition": row, "result": ctx.turn_result(entry, row) if row.get("result") else None}
    raise DispatchHold("UNASSIGNED_CASE_TURN")


def final_collect(r, frozen):
    """All denominator slots; explicit HOLDs are never silently filtered out."""
    ctx = _Context(r, frozen)
    summary, cases = ctx.complete()
    return {"summary": summary, "cases": [{"mapping": entry["mapping"], "disposition": disposition,
        "turns": [{"disposition": t, "result": ctx.turn_result(entry, t) if t.get("result") else None}
                  for t in disposition["turns"]]} for entry, disposition in cases]}


def collect_answers(r, frozen, stage):
    """New main final-collection rows, including legacy-metadata-held answers."""
    need(stage in ("candidate", "followup"), "INVALID_ANSWER_STAGE")
    rows = []
    for case in final_collect(r, frozen)["cases"]:
        for turn in case["turns"]:
            value = turn["result"]
            if value is None or value["stage"] != stage or value["review_candidate"] is None:
                continue
            review = value["review_candidate"]
            rows.append({"case_id": value["case_id"], "answer": review["answer"], "answer_sha256": review["answer_sha256"],
                "sources": review["candidate_source_metadata"], "projection_hold": review["projection_hold"],
                "terminal_sha256": value["terminal_sha256"], "protocol_holds": value["protocol_holds"]})
    return rows


def _version_source(ctx, directory, evidence, raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 8_000_000 and isinstance(evidence["text"], str)
         and evidence["text_sha256"] in (p.digest(evidence["text"].encode()), p.digest(evidence["text"]))
         and evidence["status"] == "CAPTURED_NOT_LEGAL_VERIFIED" and p.digest(raw) == evidence["raw_sha256"]
         and is_allowed_source_url(evidence["url"]) and redirect_allowed(evidence["url"], evidence["final_url"]),
         "REVIEW_CAPTURE_BINDING")
    sid = p.digest({"url": evidence["url"], "raw_sha256": evidence["raw_sha256"]})
    row = {**copy.deepcopy(evidence), "source_id": sid}
    path = directory / "sources" / (sid + ".bytes")
    if ctx.io.exists(path):
        ctx.io.read(path, evidence["raw_sha256"])
    else:
        ctx.io.write(path, raw)
    receipt = directory / "source-receipts" / (p.digest(evidence) + ".json")
    if ctx.io.exists(receipt):
        need(ctx.json(receipt) == evidence, "CAPTURE_RECEIPT_CHANGED")
    else:
        ctx.io.write(receipt, evidence)
    return row, {"path": path.relative_to(directory).as_posix(), "sha256": evidence["raw_sha256"]}


def prepare_reviews(r, frozen, *, attach_blind_material):
    ctx = _Context(r, frozen)
    summary, cases = ctx.complete()
    need(callback_sha256(attach_blind_material) == ctx.config["review_material_callback_sha256"], "BLIND_CALLBACK_PIN_CHANGED")
    ledger = ctx.root / "REVIEW-PREPARATION.json"
    if ctx.io.exists(ledger):
        value = ctx.json(ledger)
        need(value == seal(value) and value["dispatch_outcome_sha256"] == summary["content_sha256"], "REVIEW_PREPARATION_CHANGED")
        for ref in value["jobs"]:
            _review_input(ctx, ctx.root / ref["directory"], expected_manifest=ref["sha256"])
        return {**value, "dispatch": "NO_OP_REVIEW_PREPARED"}
    ctx.io.write(ctx.root / "REVIEW-PREPARATION-START.json", {"dispatch_outcome_sha256": summary["content_sha256"],
        "callback_sha256": ctx.config["review_material_callback_sha256"]})
    jobs, held = [], []
    for entry, disposition in cases:
        qid = entry["mapping"]["opaque_id"]
        for turn in disposition["turns"]:
            if not turn.get("result"):
                held.append({"case_id": qid, "turn": turn["turn"], "reason": turn["state"]})
                continue
            result = ctx.turn_result(entry, turn)
            review = copy.deepcopy(result["review_candidate"])
            if review is None:
                held.append({"case_id": qid, "turn": turn["turn"], "reason": "NO_TERMINAL_ANSWER"})
                continue
            directory = ctx.root / "reviews" / f"{qid}-turn-{turn['turn']:02d}"
            ctx.io.mkdir(directory)
            protected = ctx.root / "protected" / qid
            files = {}
            exports = {item["source_id"]: item for item in result["source_exports"]}
            candidate_evidence = []
            for source in review["evidence"]:
                if source.get("kind") == "UNVERIFIED_USER_FACTS_AND_DOCUMENTS":
                    candidate_evidence.append(source)
                    continue
                export = exports[source["source_id"]]
                raw = ctx.io.read(protected / export["relative_path"], export["sha256"])
                evidence, binding = _version_source(ctx, directory, source, raw)
                need(evidence["source_id"] == source["source_id"], "CANDIDATE_SOURCE_VERSION_CHANGED")
                candidate_evidence.append(evidence); files[binding["path"]] = binding["sha256"]
                files["source-receipts/" + p.digest(source) + ".json"] = p.digest(source)
                capture_name = export["relative_path"].removesuffix(".bytes") + ".json"
                artifact_name = capture_name.removeprefix("unseen-route/")
                capture_raw = ctx.io.read(protected / capture_name, result["artifacts"][artifact_name])
                target = "source-captures/" + source["source_id"] + ".json"
                files[target] = ctx.io.write(directory / target, capture_raw)
            for export in result["upload_exports"]:
                p.parts(export["review_relative_path"])
                need(export["review_relative_path"].startswith("due-uploads/turn-"), "REVIEW_UPLOAD_SCOPE")
                raw = ctx.io.read(protected / export["relative_path"], export["sha256"])
                ctx.io.write(directory / export["review_relative_path"], raw)
                files[export["review_relative_path"]] = export["sha256"]
            binding = {"mapping": entry["mapping"], "turn": turn["turn"], "answer_sha256": review["answer_sha256"],
                       "main_freeze_sha256": frozen["content_sha256"]}
            extra = attach_blind_material(copy.deepcopy(binding))
            need(set(extra) == {"binding_sha256", "oracle", "expected_system_assertions", "sources"}
                 and extra["binding_sha256"] == p.digest(binding)
                 and extra["oracle"]["case_id"] == entry["mapping"]["case_id"]
                 and extra["expected_system_assertions"] == extra["oracle"]["system_assertions"], "BLIND_REFERENCE_MAPPING_CHANGED")
            for item in extra["sources"]:
                source, ref = _version_source(ctx, directory, item["evidence"], item["raw"])
                if not any(e["source_id"] == source["source_id"] for e in candidate_evidence):
                    candidate_evidence.append(source)
                else:
                    need(any(e["source_id"] == source["source_id"] and e.get("text") == source["text"]
                             for e in candidate_evidence), "CONFLICTING_SAME_VERSION_TEXT")
                files[ref["path"]] = ref["sha256"]
                files["source-receipts/" + p.digest(item["evidence"]) + ".json"] = p.digest(item["evidence"])
            review.update(case_type="system" if entry["mapping"]["system"] else "legal", oracle=extra["oracle"],
                          expected_system_assertions=extra["expected_system_assertions"], evidence=candidate_evidence)
            files["input.json"] = ctx.io.write(directory / "input.json", {"as_of": entry["as_of"], "cases": [review]})
            files["schema.json"] = ctx.io.write(directory / "schema.json", r.review_schema())
            manifest = seal({"schema": VERSION, "main_freeze_sha256": frozen["content_sha256"],
                "dispatch_outcome_sha256": summary["content_sha256"], "case_id": qid, "turn": turn["turn"],
                "route_result": turn["result"], "terminal_sha256": result["terminal_sha256"],
                "answer_sha256": review["answer_sha256"], "projection_hold": review["projection_hold"],
                "blind_callback_sha256": ctx.config["review_material_callback_sha256"], "blind_binding_sha256": p.digest(binding),
                "oracle_sha256": p.digest(extra["oracle"]), "files": files,
                "actual_reviewer_invocation": "NOT_STARTED", "source_recaptures": 0})
            sha = ctx.io.write(directory / "CASE-ROUTE-REVIEW.json", manifest)
            jobs.append({"directory": directory.relative_to(ctx.root).as_posix(), "sha256": sha})
    value = seal({"schema": VERSION, "dispatch_outcome_sha256": summary["content_sha256"], "jobs": jobs,
        "unanswered_turns": held, "actual_reviewer_invocations": 0, "source_recaptures": 0})
    ctx.io.write(ledger, value)
    return value


def _review_input(ctx, directory, expected_manifest=None):
    safe(directory, ctx.root / "reviews")
    ledger = ctx.json(ctx.root / "REVIEW-PREPARATION.json")
    need(ledger == seal(ledger), "REVIEW_PREPARATION_CHANGED")
    matches = [ref for ref in ledger["jobs"] if ref["directory"] == directory.relative_to(ctx.root).as_posix()]
    need(len(matches) == 1 and (expected_manifest is None or expected_manifest == matches[0]["sha256"]),
         "UNREGISTERED_REVIEW_JOB")
    expected_manifest = matches[0]["sha256"]
    value = ctx.json(directory / "CASE-ROUTE-REVIEW.json", expected_manifest)
    need(value == seal(value) and value["main_freeze_sha256"] == ctx.frozen["content_sha256"], "REVIEW_MANIFEST_CHANGED")
    ctx.load_index()
    outcome = ctx.json(ctx.root / "DISPATCH-OUTCOME.json")
    need(outcome == seal(outcome) and outcome["run_index_sha256"] == ctx.index["content_sha256"]
         and outcome["content_sha256"] == ledger["dispatch_outcome_sha256"] == value["dispatch_outcome_sha256"],
         "REVIEW_DISPATCH_LINEAGE_CHANGED")
    entries = [e for e in ctx.index["cases"] if e["mapping"]["opaque_id"] == value["case_id"]]
    need(len(entries) == 1, "REVIEW_CASE_NOT_ASSIGNED")
    disposition = ctx.from_ref(outcome["dispositions"][value["case_id"]])
    turns = [t for t in disposition["turns"] if t["turn"] == value["turn"]]
    need(len(turns) == 1 and turns[0].get("result") == value["route_result"], "REVIEW_TURN_NOT_OBSERVED")
    observed = ctx.turn_result(entries[0], turns[0])
    for name, sha in value["files"].items():
        p.parts(name)
        ctx.io.read(directory / name, sha)
    payload = ctx.json(directory / "input.json")
    need(len(payload["cases"]) == 1 and payload["cases"][0]["answer_sha256"] == value["answer_sha256"]
         == p.digest(payload["cases"][0]["answer"].encode())
         and observed["review_candidate"] is not None
         and observed["review_candidate"]["answer"] == payload["cases"][0]["answer"]
         and observed["terminal_sha256"] == value["terminal_sha256"], "REVIEW_EXACT_ANSWER_CHANGED")
    return payload["cases"][0]


def review_source_ids(r, frozen, directory):
    ctx = _Context(r, frozen)
    review = _review_input(ctx, Path(directory))
    for e in review["evidence"]:
        if e.get("kind") != "UNVERIFIED_USER_FACTS_AND_DOCUMENTS":
            p.checked(e["source_id"], p.HASH)
    return {e["source_id"] for e in review["evidence"] if e.get("kind") == "UNVERIFIED_USER_FACTS_AND_DOCUMENTS"
            or (e.get("status") == "CAPTURED_NOT_LEGAL_VERIFIED" and
                p.digest(ctx.io.read(Path(directory) / "sources" / (e["source_id"] + ".bytes"))) == e["raw_sha256"])}


def validate_review_output(r, frozen, directory, output):
    """Content gate only; parent must also verify its actual fresh role receipt."""
    import jsonschema
    from backend.app.evaluation.ge_codex_unseen_contracts import validate_review
    ctx = _Context(r, frozen)
    review = _review_input(ctx, Path(directory))
    jsonschema.validate(output, r.review_schema())
    need(len(output["reviews"]) == 1 and output["reviews"][0]["case_id"] == review["case_id"], "REVIEW_TURN_CHANGED")
    return validate_review(output["reviews"][0], review["answer_sha256"], review_source_ids(r, frozen, directory))


def review_job_specs(r, frozen):
    ctx = _Context(r, frozen)
    ledger = ctx.json(ctx.root / "REVIEW-PREPARATION.json")
    need(ledger == seal(ledger), "REVIEW_PREPARATION_CHANGED")
    result = []
    for ref in ledger["jobs"]:
        p.parts(ref["directory"])
        directory = ctx.root / ref["directory"]
        review = _review_input(ctx, directory, ref["sha256"])
        result.append({"directory": str(directory), "case_id": review["case_id"],
            "answer_sha256": review["answer_sha256"], "projection_hold": review["projection_hold"]})
    return result


def validate_review_job(r, frozen, directory):
    """Validate genuine existing r.invoke receipts; never create them here."""
    ctx, directory = _Context(r, frozen), Path(directory)
    review = _review_input(ctx, directory)
    completion = ctx.json(directory / "COMPLETION.json")
    invocation = ctx.json(directory / "INVOCATION.json")
    trusted_base = ctx.private / "receipts" / directory.parent.name
    trusted = ctx.json(trusted_base / (directory.name + ".json"))
    finished = ctx.json(trusted_base / (directory.name + "-complete.json"))
    need(completion["returncode"] == 0 and completion["validation_error"] is None
         and completion["validated_rows"] == 1 and completion["output_present"] is True
         and completion["stage"] == directory.parent.name == "reviews"
         and completion["shard"] == directory.name
         and {k: v for k, v in finished.items() if k != "output_sha256"} == completion,
         "ACTUAL_REVIEW_COMPLETION_REQUIRED")
    prompt_sha = p.digest(r.REVIEW_PROMPT)
    need(prompt_sha == frozen["review_prompt_sha256"] == trusted["prompt_sha256"] == invocation["prompt_sha256"]
         and invocation["fresh_context"] is True and invocation["provider"] == "OPENAI"
         and invocation.get("browse") is False
         and invocation["fence"]["own_input_readable"] is True
         and invocation["fence"]["outside_workspace_file_denied"] is True,
         "ACTUAL_FRESH_REVIEW_INVOCATION_REQUIRED")
    need(trusted["work"] == directory.relative_to(ctx.private).as_posix()
         and trusted["input_sha256"] == invocation["input_sha256"] == p.digest(ctx.io.read(directory / "input.json"))
         and trusted["schema_sha256"] == p.digest(ctx.io.read(directory / "schema.json")), "PROTECTED_REVIEW_INPUT_CHANGED")
    manifest = ctx.json(directory / "CASE-ROUTE-REVIEW.json")
    need(set(manifest["files"]) | {"CASE-ROUTE-REVIEW.json", "INVOCATION.json"}
         <= set(trusted["input_inventory"]), "PROTECTED_REVIEW_INVENTORY_INCOMPLETE")
    for name, sha in trusted["input_inventory"].items():
        p.parts(name)
        ctx.io.read(directory / name, sha)
    output = ctx.json(directory / "output.json", finished["output_sha256"])
    validate_review_output(r, frozen, directory, output)
    need(output["reviews"][0]["case_id"] == review["case_id"], "REVIEW_ID_CHANGED")
    return output


def collect_reviews(r, frozen):
    """Only validated actual completions; missing/failed rows stay denominator HOLDs."""
    ctx = _Context(r, frozen)
    rows = []
    for spec in review_job_specs(r, frozen):
        directory = Path(spec["directory"])
        if not ctx.io.exists(directory / "COMPLETION.json"):
            continue
        completion = ctx.json(directory / "COMPLETION.json")
        if completion.get("returncode") != 0 or completion.get("validation_error") is not None:
            continue
        rows.extend(validate_review_job(r, frozen, directory)["reviews"])
    return rows
