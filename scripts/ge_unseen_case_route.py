"""Persistent own-case adapter; importing this module performs no execution.

Concrete parent API (parent still owns readiness, dispatcher and freeze):

    route = CaseRoute(host_kwargs=kwargs, expected_runtime_sha256=runtime_sha)
    result1 = route.run_turn(due1)
    # Release only the due followup AFTER observing and pinning result1.
    result2 = route.run_turn(due2)

``kwargs`` are the explicit CaseHost constructor arguments, including model and
provider. The parent creates disjoint existing case_root/protected_root, each
named with this opaque case_id, and a mailbox_root UNDER protected_root. Freeze
runtime_manifest including THIS file and run_ge_codex_unseen.py in code_sha256s,
and baseline_created_at as its ISO timestamp; all cases use those same pins. Supply
the already established, host-protected global marker and its exact hash. Never
derive jurisdiction/date from a private mapping/oracle: pass only the values
available to this case, or []/None so the planner must clarify.

DUE_SCHEMA is the only question-bearing input. The parent stages only due upload
bytes at case_root/due-uploads/turn-0001/<name> (or turn-0002), and supplies hashes
in ``uploads``. No fixture specifications, expected extraction, curator/reference
files, other cases, future turns or caller-written history are accepted. Existing
main candidate rows must be projected by the PARENT to this schema, not passed
wholesale. At T2 omit previously supplied uploads; the live host retains their
sealed history. This adapter calls CaseHost.extract_upload on actual bytes; its
existing PDF/OCR runtime dependencies must be installed in the pinned worker.

``serve_case(connection, ...)`` is a multiprocessing.Connection worker target.
It constructs the real CaseHost BEFORE recv(), sends READY, then accepts exactly
{'command':'run_turn','due':DUE_SCHEMA}, {'command':'read_result','turn':N}, or
{'command':'close'}. Keep that worker alive between T1/T2. ParentMailbox remains
the actual parent tool broker: the active parent services its privacy/web files
while this child blocks. There is no alternate CLI browser or fake transport.
Don't pass an entire bank or future-turn iterator to this worker. A process
restart cannot adopt an existing route or retry an uncertain answer attempt.

Each result includes ``answer_output`` in the main's exact ANSWER_SCHEMA shape,
or None when no final exists or source metadata cannot be projected faithfully.
``review_candidate`` supplies the candidate-only portion of prepare_reviews:
exact rendered_answer/plain-UTF8 hash, own user input, captured evidence/metadata.
Raw model answer remains unchanged in the driver terminal. Parent adds
case_type/oracle/system assertions ONLY in the separate blind reviewer context.
Metadata compatibility HOLD never excludes an existing rendered answer from
review_candidate: projection_hold and unknown_source_metadata are explicit,
separate from protocol/legal holds. Parent may consume a new review schema instead
of requiring legacy SOURCE_SCHEMA fields; count every actual answer in review.
Parent must preserve route holds in the denominator, validate this route's
terminal/receipt chain instead of fabricating legacy INVOCATION/COMPLETION, and
copy source_exports and upload_exports to its review store by the supplied hashes.
Upload exports retain earlier own documents for T2 review without resubmitting
them as new due uploads. Call close() before blind scoring (or send 'close').
Do not recapture/replace these bytes or flatten changed versions by URL. Freeze
the new route and consumer checks before any unseen disclosure; do not claim an
older freeze exercised it. No scoring, answer repair, bank seal or execution is
performed by this module outside explicit calls to the API.

The final role has no title/kind/self-audit fields. Metadata comes only from
captured document metadata (UK legislation XML or explicit HTML type metadata),
never guessed from a hostname, search title or a model-written label. Unsupported
metadata, including unclassified PDFs, holds projection without rewriting the
answer. self_audit=[] claims no unperformed audit. complete_substantive_answer is
only a conservative projection of the final status/holds, never a review pass.
Tests use labelled in-memory host doubles; actual parent validation is required.
"""
from __future__ import annotations

import base64
import copy
import threading
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException

from scripts import ge_auto_case_protocol as p
from scripts.ge_auto_role_runtime import safe
from scripts.ge_unseen_sources import is_allowed_source_url, redirect_allowed

ROOT = Path(__file__).resolve().parents[1]
VERSION = "legalbot.ge-unseen-case-route.v1"
EMPTY = p.digest([])
CODE = ("scripts/ge_unseen_case_route.py", "scripts/run_ge_codex_unseen.py")
HOST_KEYS = frozenset(("run_id", "case_id", "case_root", "protected_root", "mailbox_root",
    "owner_instruction_path", "expected_owner_sha256", "owner_scope_sha256",
    "global_marker_path", "global_marker_sha256", "runtime_manifest", "baseline_created_at",
    "model", "provider"))
DUE_SCHEMA = p.obj({"schema": {"const": VERSION}, "case_id": p.ID,
    "turn": {"type": "integer", "minimum": 1, "maximum": 2}, "question": p.string(50000),
    "jurisdictions": p.array(p.string(100), 8), "as_of_date": p.NULL_DAY,
    "previous_terminal_sha256": {"anyOf": [p.HASH, {"const": None}]},
    "uploads": p.array(p.obj({"upload_id": p.ID, "relative_path": p.string(400),
        "sha256": p.HASH, "media_type": {"enum": ["application/pdf", "image/png"]}}), 16)})


class RouteHold(ValueError):
    """Stable codes only; no private question/exception text in diagnostics."""


def need(ok, code):
    if not ok:
        raise RouteHold(code)


def file_sha(path):
    safe(path, ROOT)
    return p.digest(path.read_bytes())


def _actual_host(kwargs):
    # Lazy: schema/projection tests never resolve local model/CLI identities.
    from scripts.ge_auto_case_host import CaseHost
    return CaseHost(**kwargs)


def _kind(value):
    return {"legislation": "LEGISLATION", "act": "LEGISLATION", "statute": "LEGISLATION",
        "regulation": "LEGISLATION", "judgment": "CASE_LAW", "judgement": "CASE_LAW",
        "case law": "CASE_LAW", "official procedure": "OFFICIAL_PROCEDURE",
        "procedure": "OFFICIAL_PROCEDURE", "guidance": "OFFICIAL_GUIDANCE",
        "official guidance": "OFFICIAL_GUIDANCE"}.get(value.strip().casefold())


class _HTMLMetadata(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.titles, self.types, self.current = [], [], None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "title":
            self.current = []
        if tag == "meta" and values.get("name", "").casefold() in ("dc.type", "dcterms.type"):
            self.types.append(values.get("content", ""))

    def handle_data(self, text):
        if self.current is not None:
            self.current.append(text)

    def handle_endtag(self, tag):
        if tag == "title" and self.current is not None:
            self.titles.append("".join(self.current))
            self.current = None


def captured_metadata(raw):
    """Conservative byte-derived title/type; unknown or ambiguous => HOLD."""
    need(isinstance(raw, bytes) and 0 < len(raw) <= 8_000_000, "SOURCE_METADATA_SIZE")
    opening = raw[:100000].lower()
    need(b"<!entity" not in raw.lower(), "SOURCE_METADATA_ENTITY")
    if b"<html" in opening or b"<!doctype html" in opening:
        need(b"<!doctype html [" not in opening, "SOURCE_METADATA_ENTITY")
        html = _HTMLMetadata()
        html.feed(raw.decode("utf-8-sig"))
        titles, kinds = html.titles, [_kind(t) for t in html.types]
        method = "CAPTURE_HTML_TITLE_AND_EXPLICIT_DC_TYPE"
    elif b"<legislation" in opening:
        from defusedxml import ElementTree
        root = ElementTree.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        need(root.tag == "{http://www.legislation.gov.uk/namespaces/legislation}Legislation",
             "SOURCE_METADATA_UNCLASSIFIED_XML")
        titles = ["".join(t.itertext()) for t in root.iter("{http://purl.org/dc/elements/1.1/}title")]
        kinds, method = ["LEGISLATION"], "CAPTURE_UK_LEGISLATION_XML_DC_TITLE_AND_ROOT"
    else:
        raise RouteHold("SOURCE_METADATA_UNAVAILABLE")
    need(titles and len(set(titles)) == 1 and titles[0].strip()
         and kinds and None not in kinds and len(set(kinds)) == 1, "SOURCE_METADATA_MISSING_OR_AMBIGUOUS")
    return {"title": titles[0], "kind": kinds[0], "raw_sha256": p.digest(raw), "method": method}


def _captures(records):
    sources = {}
    for record in records:
        capture = record["capture"]
        p.checked(capture, p.CAPTURE_SCHEMA)
        raw = base64.b64decode(capture["raw_b64"], validate=True)
        sha = p.digest(raw)
        need(0 < len(raw) <= 8_000_000 and sha not in sources, "CAPTURE_SIZE_OR_DUPLICATE")
        urls = [capture["canonical_url"], *capture["redirect_chain"], capture["final_url"]]
        need(all(is_allowed_source_url(u) for u in urls)
             and all(redirect_allowed(a, b) for a, b in zip(urls, urls[1:])), "UNOFFICIAL_CAPTURE")
        parts = {part["part_id"]: part for part in capture["parts"]}
        need(len(parts) == len(capture["parts"]), "DUPLICATE_CAPTURE_PART")
        sources[sha] = {"record": record, "capture": capture, "raw": raw, "parts": parts}
    return sources


def _span(span, sources):
    p.checked(span, p.SPAN)
    need(span["source_sha256"] in sources, "UNOBSERVED_SOURCE")
    source = sources[span["source_sha256"]]
    part = source["parts"].get(span["part_id"])
    need(part is not None and 0 <= span["start"] < span["end"] <= len(part["text"])
         and part["text"][span["start"]:span["end"]] == span["text"], "CAPTURE_QUOTE_CHANGED")
    return source, part


def project_sources(answer, evidence_pack, records):
    """Pure conversion of driver-observed captures and eligible retrieved spans."""
    need(evidence_pack["baseline_sha256"] == EMPTY, "NONEMPTY_BASELINE_DENIED")
    sources = _captures(records)
    entries = evidence_pack["evidence"]
    by_id = {e["proposition"]["proposition_id"]: e for e in entries}
    need(len(entries) == len(by_id), "DUPLICATE_EVIDENCE_PROPOSITION")
    cited = answer["cited_proposition_ids"] if answer else []
    need(len(set(cited)) == len(cited) and set(cited) <= set(by_id), "UNRETRIEVED_CITATION")
    metadata, rows, holds, proofs = {}, [], [], []
    for entry in entries:
        p.checked(entry, p.EVIDENCE)
        prop = entry["proposition"]
        need(entry["origin"] == "CASE_LOCAL" and prop["currentness"]["status"] == "VERIFIED",
             "UNELIGIBLE_EVIDENCE_OR_BASELINE")
        spans = [prop["point"], *prop["conditions"], *prop["context"], *prop["currentness"]["checks"]]
        for span in spans:
            _span(span, sources)
        checks = sorted({sources[s["source_sha256"]]["capture"]["canonical_url"]
                         for s in prop["currentness"]["checks"]})
        need(checks and prop["currentness"]["valid_from"] is not None
             and prop["currentness"]["valid_to"] is not None, "CURRENTNESS_CONTEXT_MISSING")
        if prop["proposition_id"] not in cited:
            continue
        for span in spans:
            source, part = _span(span, sources)
            sha = span["source_sha256"]
            if sha not in metadata:
                try:
                    metadata[sha] = captured_metadata(source["raw"])
                except (ValueError, ParseError, DefusedXmlException) as exc:
                    # Parse failures are local projection holds, never answer retries.
                    code = str(exc) if isinstance(exc, RouteHold) else "SOURCE_METADATA_PARSE_HOLD"
                    metadata[sha] = None
                    holds.append({"source_sha256": sha, "code": code})
            if metadata[sha] is None:
                continue
            row = {"url": source["capture"]["canonical_url"], "title": metadata[sha]["title"],
                "kind": metadata[sha]["kind"], "locator": part["locator"], "quote": span["text"],
                "jurisdiction": prop["jurisdiction"], "relevant_date": prop["as_of_date"],
                "currentness_assessment": "Independently eligible for research at " + prop["as_of_date"]
                    + "; reviewed interval " + prop["currentness"]["valid_from"] + " through "
                    + prop["currentness"]["valid_to"] + "; eligibility receipt " + entry["eligibility_receipt_sha256"],
                "currentness_check_urls": checks}
            if row not in rows:
                rows.append(row)
            proofs.append({"source_metadata_sha256": p.digest(row), "proposition_id": prop["proposition_id"],
                "eligibility_receipt_sha256": entry["eligibility_receipt_sha256"], "span": span,
                "capture_metadata": metadata[sha], "parser_receipt_sha256": source["capture"]["parser_receipt_sha256"]})
    expected = p.retrieved_source_references(entries, {sha: s["capture"] for sha, s in sources.items()})
    need(evidence_pack["source_references"] == expected, "SOURCE_REFERENCE_CHANGED")
    return rows, holds, proofs, sources


def rendered_text(terminal, evidence_pack):
    """Verify the parent's deterministic projection; never replace terminal bytes."""
    raw = terminal["answer"]
    if raw is None:
        need(terminal["rendered_answer"] is None and terminal["rendered_answer_sha256"] is None,
             "RENDERED_ANSWER_WITHOUT_FINAL")
        return None
    text = terminal["rendered_answer"]
    need(isinstance(text, str) and p.digest(text.encode()) == terminal["rendered_answer_sha256"]
         and text == p.render_source_links(raw, evidence_pack["source_references"])
         and terminal["citation_renderer"] == "DETERMINISTIC_SOURCE_LINKS_NOT_OSCOLA_CERTIFIED",
         "RENDERED_ANSWER_CHANGED")
    return text


class CaseRoute:
    """Trusted parent worker object. Never deserialize this from a candidate job."""
    def __init__(self, *, host_kwargs, expected_runtime_sha256):
        need(isinstance(host_kwargs, dict) and set(host_kwargs) == HOST_KEYS, "EXPLICIT_HOST_ARGUMENTS_REQUIRED")
        self.kwargs = copy.deepcopy(host_kwargs)
        for key in ("case_root", "protected_root", "mailbox_root", "owner_instruction_path", "global_marker_path"):
            self.kwargs[key] = Path(self.kwargs[key])
            safe(self.kwargs[key], ROOT)
        self.root, self.protected = self.kwargs["case_root"], self.kwargs["protected_root"]
        self.case_id = self.kwargs["case_id"]
        p.checked(self.case_id, p.ID)
        need(self.root.name == self.case_id == self.protected.name
             and not self.root.is_relative_to(self.protected) and not self.protected.is_relative_to(self.root),
             "EXACT_DISJOINT_CASE_ROOTS_REQUIRED")
        need(self.kwargs["mailbox_root"].is_relative_to(self.protected)
             and self.kwargs["mailbox_root"] != self.protected, "PROTECTED_PARENT_MAILBOX_REQUIRED")
        for key in ("global_marker_path", "owner_instruction_path"):
            need(not self.kwargs[key].is_relative_to(self.root), "HOST_AUTHORITY_INSIDE_CASE_DENIED")
        runtime = self.kwargs["runtime_manifest"]
        p.checked(expected_runtime_sha256, p.HASH)
        need(p.digest(runtime) == expected_runtime_sha256 and runtime["shared_baseline_sources"] == []
             and runtime["training"] is False and runtime["production"] is False, "FROZEN_EMPTY_RUNTIME_REQUIRED")
        stamp = self.kwargs["baseline_created_at"]
        need(isinstance(stamp, datetime) and stamp.tzinfo is not None
             and runtime.get("baseline_created_at") == stamp.isoformat(), "FROZEN_BASELINE_TIMESTAMP_REQUIRED")
        self.runtime_sha = expected_runtime_sha256
        self._pins = {name: runtime["code_sha256s"].get(name) for name in CODE}
        self._check_pins()
        self.store, self.upload_store = p.CaseStore(self.protected), p.CaseStore(self.root / "due-uploads")
        self.prefix = "unseen-route"
        # Exclusive directory reservation prevents restart/adoption even before host creation.
        self.store.mkdir_new(self.prefix)
        self._observed, self._due, self._terminal, self._failed = {}, {}, {}, False
        self._upload_history, self._closed = {}, False
        self._lock = threading.Lock()
        self._put("SESSION.json", {"schema": VERSION, "case_id": self.case_id, "runtime_sha256": self.runtime_sha,
            "global_marker_sha256": self.kwargs["global_marker_sha256"], "baseline_sha256": EMPTY,
            "baseline_created_at": stamp.isoformat(), "root": str(self.root), "protected_root": str(self.protected),
            "parent_mailbox_root": str(self.kwargs["mailbox_root"]), "restart_adoption": False})
        self.host = _actual_host(self.kwargs)
        self._check_host()

    def _check_pins(self):
        need(all(expected and file_sha(ROOT / name) == expected for name, expected in self._pins.items()),
             "ROUTE_OR_MAIN_CODE_PIN_CHANGED")

    def _check_host(self):
        self._check_pins()
        for key in ("global_marker_path", "owner_instruction_path"):
            safe(self.kwargs[key], ROOT)
        raw = self.kwargs["global_marker_path"].read_bytes()
        need(self.host.case_id == self.case_id and self.host.root == self.root
             and self.host.protected == self.protected and self.host.runtime_sha == self.runtime_sha
             and self.host.policy.baseline_sha256 == EMPTY and self.host.policy.baseline_kind == "EMPTY"
             and p.digest(raw) == self.kwargs["global_marker_sha256"], "HOST_CASE_OR_MARKER_CHANGED")
        need(self.host.establish_marker(raw) is True, "HOST_GLOBAL_MARKER_REQUIRED")
        need(p.digest(self.host.owner_bytes()) == self.kwargs["expected_owner_sha256"], "HOST_OWNER_CHANGED")

    def _put(self, name, value):
        raw = value if isinstance(value, bytes) else p.canonical(value)
        self.store.write_new(self.prefix + "/" + name, raw)
        self._observed[name] = p.digest(raw)
        return self._observed[name]

    def _replay(self):
        self._check_host()
        for name, sha in self._observed.items():
            need(p.digest(self.store.read(self.prefix + "/" + name)) == sha, "ROUTE_ARTIFACT_CHANGED")
        for turn, sha in self._terminal.items():
            need(self.host.session.read_terminal(turn)["terminal_sha256"] == sha, "EARLIER_TERMINAL_CHANGED")

    def read_result(self, turn):
        self._replay()
        need(type(turn) is int and turn in self._terminal, "UNOBSERVED_TURN")
        name = f"turn-{turn:04d}/RESULT.json"
        need(name in self._observed, "PROJECTION_INTERRUPTED_NO_RETRY")
        result = p.decode(self.store.read(self.prefix + "/" + name))
        return {**result, "route_result_sha256": self._observed[name]}

    def close(self):
        """Permanently stop due-turn disclosure before the separate blind review."""
        need(self._lock.acquire(blocking=False), "CONCURRENT_TURN_DENIED")
        try:
            self._replay()
            if not self._closed:
                self._put("CLOSED.json", {"case_id": self.case_id, "terminal_sha256s": self._terminal,
                    "further_answers_allowed": False, "blind_scoring_performed": False})
                self._closed = True
            return {"case_id": self.case_id, "closed_receipt_sha256": self._observed["CLOSED.json"]}
        finally:
            self._lock.release()

    def run_turn(self, due):
        need(self._lock.acquire(blocking=False), "CONCURRENT_TURN_DENIED")
        try:
            self._replay()
            need(not self._closed, "CASE_ROUTE_CLOSED")
            p.checked(due, DUE_SCHEMA)
            due = p.decode(p.canonical(due))
            turn = due["turn"]
            need(due["case_id"] == self.case_id, "FOREIGN_CASE_DENIED")
            if turn in self._due:
                need(self._due[turn] == due, "SEALED_DUE_INPUT_CHANGED")
                return {**self.read_result(turn), "dispatch": "NO_OP_COMPLETE"}
            need(not self._failed and turn == len(self._due) + 1, "TURN_ORDER_OR_CONSUMED_FAILURE")
            need(due["previous_terminal_sha256"] == (self._terminal.get(turn - 1) if turn > 1 else None),
                 "PRIOR_TERMINAL_PIN_CHANGED")
            if turn == 2:
                need(self.host.session.read_answer_projection(1) is not None, "FOLLOWUP_WITHOUT_FIRST_ANSWER")
            ids, paths, uploads = set(), set(), []
            for item in due["uploads"]:
                parts = p.parts(item["relative_path"])
                need(len(parts) == 2 and parts[0] == f"turn-{turn:04d}"
                     and item["upload_id"] not in ids and item["relative_path"] not in paths,
                     "UPLOAD_SCOPE_OR_DUPLICATE")
                raw = self.upload_store.read(item["relative_path"])
                need(p.digest(raw) == item["sha256"] and raw
                     and ((item["media_type"] == "application/pdf" and raw.startswith(b"%PDF-"))
                          or (item["media_type"] == "image/png" and raw.startswith(b"\x89PNG\r\n\x1a\n"))),
                     "DUE_UPLOAD_BYTES_CHANGED")
                ids.add(item["upload_id"]); paths.add(item["relative_path"])
            folder = f"turn-{turn:04d}"
            self.store.mkdir_new(self.prefix + "/" + folder)
            self._put(folder + "/DUE.json", due)
            self._due[turn] = due  # An uncertain call is consumed before any extraction/model.
            try:
                for item in due["uploads"]:
                    upload = self.host.extract_upload(path=self.root / "due-uploads" / item["relative_path"],
                        upload_id=item["upload_id"], turn=turn, media_type=item["media_type"])
                    p.checked(upload[0], p.UPLOAD)
                    need(upload[0]["sha256"] == item["sha256"] == p.digest(upload[1].raw)
                         and upload[0]["upload_id"] == item["upload_id"]
                         and upload[0]["media_type"] == item["media_type"]
                         and upload[0]["text_sha256"] == p.digest(upload[0]["text"].encode())
                         and upload[0]["extraction_sha256"] == p.digest(upload[1].extraction_receipt),
                         "ACTUAL_UPLOAD_EXTRACTION_CHANGED")
                    uploads.append(upload)
                observed = self.host.run_turn(question=due["question"], jurisdictions=due["jurisdictions"],
                    as_of_date=due["as_of_date"], uploads=tuple(uploads))
                terminal = self.host.session.read_terminal(turn)
                request = {"schema": p.VERSION, "case_id": self.case_id, "turn": turn,
                    "question": due["question"], "jurisdictions": due["jurisdictions"],
                    "as_of_date": due["as_of_date"], "due_uploads": [u[0] for u in uploads],
                    "history": [{"turn": n, "request_sha256": self.host.session.read_terminal(n)["request_sha256"],
                        "terminal_sha256": self._terminal[n]} for n in range(1, turn)]}
                need(observed["terminal_sha256"] == terminal["terminal_sha256"]
                     and terminal["case_id"] == self.case_id and terminal["turn"] == turn
                     and terminal["request_sha256"] == p.digest(request)
                     and terminal["policy_sha256"] == self.host.policy_sha
                     and p.digest({k: v for k, v in terminal.items() if k != "terminal_sha256"})
                         == terminal["terminal_sha256"], "HOST_TERMINAL_CHANGED")
                self._terminal[turn] = terminal["terminal_sha256"]
                self._put(folder + "/TERMINAL.json", terminal)
                result = self._project(turn, terminal, uploads)
                self._put(folder + "/RESULT.json", result)
                return {**self.read_result(turn), "dispatch": "EXECUTED_CASE_HOST"}
            except Exception as exc:
                self._failed = True
                self._put(folder + "/HOLD.json", {"state": "HOLD_CONSUMED", "exception_type": type(exc).__name__,
                    "reason": str(exc) if isinstance(exc, RouteHold) else "HOST_OR_PROJECTION_FAILED",
                    "answer_retry": False, "artifacts_preserved": True})
                raise
        finally:
            self._lock.release()

    def _project(self, turn, terminal, uploads):
        session, folder = self.host.session, f"turn-{turn:04d}"
        answer = session.read_answer_projection(turn)
        need(answer == terminal["answer"], "ANSWER_PROJECTION_CHANGED")
        if answer is not None:
            p.checked(answer, p.FINAL_SCHEMA)
        pack, records = session.read_evidence_pack(turn), session.read_source_captures(turn)
        text_answer = rendered_text(terminal, pack)
        need(pack["generation_sha256"] == terminal["generation_sha256"], "EVIDENCE_GENERATION_CHANGED")
        rows, holds, proofs, sources = project_sources(answer, pack, records)
        self._put(folder + "/EvidencePack.json", pack)
        self._put(folder + "/SOURCE-PROJECTION.json", {"sources": rows, "holds": holds, "proofs": proofs})
        self.store.mkdir_new(self.prefix + "/" + folder + "/uploads")
        due = self._due[turn]
        due_metadata = []
        for n, (item, upload) in enumerate(zip(due["uploads"], uploads, strict=True), 1):
            name = folder + f"/uploads/{n:02d}.bytes"
            self._put(name, upload[1].raw)
            self._put(folder + f"/uploads/{n:02d}-EXTRACTION.json", upload[1].extraction_receipt)
            native = p.decode(upload[1].extraction_receipt)["extraction_result"]
            due_metadata.append({"file": {"path": item["relative_path"], "sha256": item["sha256"],
                "format": "PDF" if item["media_type"] == "application/pdf" else "PNG",
                "upload_id": item["upload_id"], "turn": turn}, "extraction": native,
                "export": {"upload_id": item["upload_id"], "turn": turn, "relative_path": self.prefix + "/" + name,
                    "review_relative_path": "due-uploads/" + item["relative_path"], "sha256": item["sha256"],
                    "extraction_receipt_sha256": p.digest(upload[1].extraction_receipt)}})
        self._put(folder + "/UPLOAD-METADATA.json", due_metadata)
        self._upload_history[turn] = due_metadata
        self.store.mkdir_new(self.prefix + "/" + folder + "/sources")
        evidence, exports = [], []
        for sha, source in sorted(sources.items()):
            capture = source["capture"]
            # Version-bound ID: two captures of one URL must not overwrite each other.
            sid = p.digest({"url": capture["canonical_url"], "raw_sha256": sha})
            name = folder + "/sources/" + sid + ".bytes"
            self._put(name, source["raw"])
            self._put(folder + "/sources/" + sid + ".json", source["record"])
            text = "\n".join(part["text"] for part in capture["parts"])
            evidence.append({"source_id": sid, "url": capture["canonical_url"], "final_url": capture["final_url"],
                "captured_at": capture["fetched_at"], "status": "CAPTURED_NOT_LEGAL_VERIFIED", "raw_sha256": sha,
                "text": text, "text_sha256": p.digest(text.encode()), "parser_sha256": capture["parser_sha256"],
                "parser_receipt_sha256": capture["parser_receipt_sha256"], "parts": capture["parts"]})
            exports.append({"source_id": sid, "relative_path": self.prefix + "/" + name, "sha256": sha})
        all_uploads = [item for n in range(1, turn + 1) for item in self._upload_history[n]]
        own_input = {"case_id": self.case_id, "question": due["question"],
            "attachment_directory": "due-uploads",
            "attachments": {"files": [item["file"] for item in all_uploads],
                "extraction": [item["extraction"] for item in all_uploads]}}
        if turn > 1:
            own_input["history"] = [{"role": "user", "text": self._due[1]["question"]},
                {"role": "assistant", "text": rendered_text(session.read_terminal(1), session.read_evidence_pack(1))}]
        answer_output, review = None, None
        if answer is not None:
            row = {"case_id": self.case_id, "answer": text_answer, "sources": rows,
                "material_uncertainties": terminal["holds"], "self_audit": [],
                "complete_substantive_answer": answer["status"] == "ANSWER" and not terminal["holds"] and not holds}
            # Import definitions only; never call main filesystem/runner functions.
            from scripts.run_ge_codex_unseen import ANSWER_SCHEMA
            import jsonschema
            proposed = {"answers": [row]}
            jsonschema.validate(proposed, ANSWER_SCHEMA)
            if not holds:
                answer_output = proposed
            review = {"case_id": self.case_id + f":turn-{turn}", "user_input": own_input,
                "answer": text_answer, "answer_sha256": terminal["rendered_answer_sha256"],
                "candidate_source_metadata": rows,
                "projection_hold": bool(holds), "unknown_source_metadata": holds,
                "source_references": pack["source_references"],
                "terminal_sha256": terminal["terminal_sha256"], "protocol_holds": terminal["holds"],
                "evidence": [{"source_id": "USER-" + p.digest(own_input), "kind": "UNVERIFIED_USER_FACTS_AND_DOCUMENTS",
                              "input": own_input, "legal_authority": False}, *evidence],
                "system_harness_status": "NO_EXTRA_TRANSPORT_FAULT_INJECTION_CLAIMED",
                "review_kind": "AI_MODEL_REVIEWER", "professional_sign_off": False}
        return {"schema": VERSION, "case_id": self.case_id, "turn": turn,
            "stage": "candidate" if turn == 1 else "followup", "runtime_sha256": self.runtime_sha,
            "terminal_sha256": terminal["terminal_sha256"], "request_sha256": terminal["request_sha256"],
            "due_sha256": p.digest(due), "state": "PROJECTED_AWAITING_BLIND_REVIEW" if answer_output else "HOLD_PROJECTION",
            "answer_output": answer_output, "review_candidate": review, "source_exports": exports,
            "upload_exports": [item["export"] for item in all_uploads],
            "projection_holds": holds, "protocol_holds": terminal["holds"], "final_attempt_consumed": True,
            "artifacts": dict(self._observed), "candidate_answer_rewritten": False,
            "projected_answer_field": "terminal.rendered_answer",
            "parent_actual_validation": "REQUIRED", "training": False, "production": False}


def run_case_turn(route: CaseRoute, due: dict):
    """Main dispatcher hook; retain this exact object for the followup."""
    need(type(route) is CaseRoute, "LIVE_CASE_ROUTE_REQUIRED")
    return route.run_turn(due)


def serve_case(connection, *, host_kwargs, expected_runtime_sha256):
    """Spawn-safe worker target. Connection and kwargs are protected parent inputs."""
    route = CaseRoute(host_kwargs=host_kwargs, expected_runtime_sha256=expected_runtime_sha256)
    connection.send({"event": "READY", "case_id": route.case_id, "runtime_sha256": route.runtime_sha,
                     "baseline_sha256": EMPTY, "questions_disclosed": 0})
    while True:
        try:
            message = connection.recv()
        except EOFError:
            return  # Never retry/adopt after the IPC owner disappears.
        if message == {"command": "close"}:
            connection.send({"event": "CLOSED", **route.close()})
            return
        try:
            need(isinstance(message, dict), "INVALID_WORKER_MESSAGE")
            if set(message) == {"command", "due"} and message["command"] == "run_turn":
                result = run_case_turn(route, message["due"])
            elif set(message) == {"command", "turn"} and message["command"] == "read_result":
                result = route.read_result(message["turn"])
            else:
                raise RouteHold("INVALID_WORKER_MESSAGE")
            connection.send({"event": "RESULT", "result": result})
        except Exception as exc:
            connection.send({"event": "HOLD", "case_id": route.case_id,
                "reason": str(exc) if isinstance(exc, RouteHold) else "CASE_ROUTE_FAILED",
                "exception_type": type(exc).__name__, "automatic_retry": False})
