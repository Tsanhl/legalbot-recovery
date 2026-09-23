"""Synthetic-only, disk-free sidecar tests. No bank, model, Git or cleanup.

Run with bundled Python, from the workspace:
  python3 -B -m unittest backend.tests.test_ge_unseen_fixture_repair -v
PDF/PNG bytes, originals and failed attempts stay in an in-memory create-only
store for the life of the process. Real Poppler rendering/pypdf extraction and
native OCR are exercised; filesystem syscall tests stub IO, not document QA.
"""

from __future__ import annotations

import copy
import errno
import io
import os
import subprocess
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pypdf import PdfReader

from scripts import ge_unseen_fixture_repair as repair
from scripts import ge_unseen_fixtures as fixtures


class CanonicalAssignmentProjectionTests(unittest.TestCase):
    def test_public_assignment_enrichment_is_bound_but_not_disclosed(self):
        case = {"case_id": "synthetic", "question": "Read this record.",
                "jurisdiction": "England", "relevant_date": "2026-09-05",
                "family": "public-assigned-family", "domain": "public-assigned-domain",
                "uploads": [{"title": "Record", "format": "PDF", "pages": ["Paid £20."]}]}
        projected = repair._projection(case)
        self.assertNotIn("family", projected)
        self.assertNotIn("domain", projected)
        with self.assertRaises(repair.FixtureRepairError):
            repair._projection({**case, "oracle": "forbidden reference"})


class MemoryStore:
    def __init__(self, fs=None, prefix=""):
        self.fs = fs if fs is not None else {"files": {}, "dirs": {""}}
        self.prefix = prefix.strip("/")

    def path(self, name):
        repair._parts(name)
        return "/".join(filter(None, (self.prefix, name)))

    def read_bytes(self, name):
        path = self.path(name)
        if path not in self.fs["files"]:
            raise FileNotFoundError(path)
        return self.fs["files"][path]

    def write_new(self, name, raw):
        path = self.path(name)
        if path in self.fs["files"] or path in self.fs["dirs"]:
            raise FileExistsError(path)
        if path.rpartition("/")[0] not in self.fs["dirs"]:
            raise FileNotFoundError("missing parent")
        self.fs["files"][path] = raw

    def mkdir_new(self, name):
        path = self.path(name)
        if path in self.fs["dirs"] or path in self.fs["files"]:
            raise FileExistsError(path)
        if path.rpartition("/")[0] not in self.fs["dirs"]:
            raise FileNotFoundError("missing parent")
        self.fs["dirs"].add(path)

    @contextmanager
    def _directory(self, parts):
        if self.path("/".join(parts)) not in self.fs["dirs"]:
            raise NotADirectoryError()
        yield 0


def reference(case, text, *, source="uploads/0/pages/0", occurrence=0):
    value = repair._sources(case, int(source.split("/")[1]) + 1 if source.startswith("uploads/") else 1)[source]
    start = -1
    for _ in range(occurrence + 1):
        start = value.index(text, start + 1)
    return {"source": source, "start": start, "end": start + len(text), "text": text}


def example(fmt="PDF"):
    page = ("Public synthetic record. Café e\u0301.\nAccount\nAC-17\nItem\nAmount\nDesk\n£12.50\n"
            "Casey\nRiley\n2026-01-02\nReturn query\nPlease confirm receipt.\n"
            "Casey\n09:10\nParcel received.\nSignature\nSignature area is blank.")
    case = {"case_id": "public-fixture-example", "question": "Can you read my synthetic record?",
            "jurisdiction": "England", "relevant_date": "2026-01-02",
            "follow_up": "SECRET_FUTURE_FACT", "issues_to_research": ["SECRET_RESEARCH_HINT"],
            "expected_behavior": "SECRET_EXPECTATION", "material_missing_facts": ["SECRET_REVIEW_HINT"],
            "uploads": [{"title": "Public fixture", "pages": [page], "format": fmt}]}
    ref = lambda text, **kw: reference(case, text, **kw)
    elements = [
        {"type": "text", "text": ref("Public synthetic record. Café e\u0301.")},
        {"type": "fields", "fields": [{"label": ref("Account"), "value": ref("AC-17")}]},
        {"type": "table", "headers": [ref("Item"), ref("Amount")], "rows": [[ref("Desk"), ref("£12.50")]]},
        {"type": "email", "headers": {"from": ref("Casey"), "to": ref("Riley"),
             "date": ref("2026-01-02"), "subject": ref("Return query")}, "body": [ref("Please confirm receipt.")]},
        {"type": "chat", "messages": [{"sender": ref("Casey", occurrence=1),
             "timestamp": ref("09:10"), "text": ref("Parcel received.")}]},
        {"type": "blank_signature", "label": ref("Signature"), "blank_evidence": ref("Signature area is blank.")},
    ]
    doc = {"document_index": 1, "format": fmt, "elements": elements}
    required = [s for e in elements for s in repair._spans(e) if s != elements[-1]["blank_evidence"]]
    req = {"document_index": 1, "required_blocks": [e["type"] for e in elements],
           "required_spans": required, "required_field_labels": [ref("Account"), ref("Signature")],
           "description_spans": [], "blank_signature_evidence": elements[-1]["blank_evidence"],
           "unavailable_visuals": []}
    return case, [req], [doc]


class FixtureRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Actual old fixture bytes, generated once without filesystem writes.
        cls.old_pdf = fixtures._render_pdf(fixtures._layout({"title": "Old public fixture",
            "format": "PDF", "pages": ["Original author prose document description."]}))

    def prepare(self, case=None, requirements=None, documents=None, *, store=None, name="repair-v1"):
        if case is None:
            case, requirements, documents = example()
        original = MemoryStore()
        raw = self.old_pdf
        if case["uploads"][0]["format"] == "PNG":
            raw = list(fixtures._pdf_pages(raw))[0][2]
        original.write_new("old.bytes", raw)
        manifest = {"case_id": case["case_id"], "raw_case_sha256": repair._sha(repair._json(case)),
                    "files": [{"relative_path": "old.bytes", "sha256": repair._sha(raw),
                               "format": case["uploads"][0]["format"], "document_index": 1}],
                    "extraction": [{"text": "UNTRUSTED_PRIOR_EXTRACTION"}]}
        store = store or MemoryStore()
        case_raw = b" \n" + repair._json(case) + b"\n"
        manifest_raw = b"\n" + repair._json(manifest)
        handle = repair.prepare_repair_job(case_raw, manifest_raw, original, store,
            job_name=name, formatter_context_id="fresh-formatter-01", requirements=requirements,
            review_issues=["PROSE_ONLY"])
        _, payload = repair._job(store, handle)
        output = {"schema": repair.VERSION, "case_id": case["case_id"],
                  "job_binding_sha256": payload["job_binding_sha256"], "status": "FORMATTED",
                  "hold_codes": [], "documents": documents}
        return SimpleNamespace(case=case, requirements=requirements, documents=documents,
            original=original, manifest=manifest, store=store, handle=handle, output=output,
            case_raw=case_raw, manifest_raw=manifest_raw, payload=payload)

    def validate(self, setup, output=None):
        return repair.validate_formatted_output(setup.store, setup.handle,
            repair._json(setup.output if output is None else output))

    def test_job_preserves_exact_bytes_and_one_case_disclosure(self):
        s = self.prepare()
        self.assertEqual(s.store.read_bytes("repair-v1/originals/case.json"), s.case_raw)
        self.assertEqual(s.store.read_bytes("repair-v1/originals/manifest.json"), s.manifest_raw)
        self.assertEqual(s.store.read_bytes("repair-v1/originals/file-0001.bytes"), self.old_pdf)
        self.assertEqual(s.original.read_bytes("old.bytes"), self.old_pdf)
        disclosed = s.store.read_bytes("repair-v1/formatter/input.json")
        for secret in (b"SECRET_", b"UNTRUSTED_PRIOR_EXTRACTION", b"follow_up", b"issues_to_research"):
            self.assertNotIn(secret, disclosed)
        self.assertEqual(s.payload["case"]["question"], s.case["question"])
        self.assertEqual(s.payload["review_issues"], ["PROSE_ONLY"])
        self.assertEqual(self.validate(s)["state"], "VALID_FORMATTING_ONLY")
        self.assertFalse(self.validate(s)["eligible"])

    def test_actual_structured_pdf_and_hashes_and_review_gate(self):
        s = self.prepare()
        before = dict(s.store.fs["files"])
        handle = repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="render-v1")
        result = repair.verify_successor(s.store, handle)
        self.assertEqual(result["state"], "AWAITING_FRESH_REVIEW")
        self.assertFalse(result["eligible"])
        self.assertEqual(result["fresh_review"]["status"], "NOT_STARTED")
        manifest = repair._load(s.store.read_bytes("render-v1/UPLOAD-MANIFEST.json"))
        self.assertEqual(manifest["raw_case_sha256"], repair._sha(repair._json(s.case)))
        self.assertEqual(len(manifest["files"]), len(manifest["extraction"]))
        raw = s.store.read_bytes("render-v1/document-0001.pdf")
        reader = PdfReader(io.BytesIO(raw))
        text = "\n".join(p.extract_text() for p in reader.pages)
        for expected in ("£12.50", "AC-17", "Café e\u0301", "From: Casey", "Parcel received."):
            self.assertIn(expected, text)
        self.assertNotIn("Signature area is blank", text)
        # Actual drawing instructions for table grids and the blank signature line.
        content = b"\n".join(p.get_contents().get_data() for p in reader.pages)
        self.assertIn(b" l S", content)
        self.assertIsNone(reader.get_fields())  # Static synthetic form, no fabricated signed field.
        for extracted in manifest["extraction"]:
            self.assertIsNone(extracted["error"])
            for page in extracted["pages"]:
                raster = s.store.read_bytes("render-v1/" + page["render_relative_path"])
                self.assertEqual(page["page_sha256"], repair._sha(raster))
                self.assertEqual(page["text_sha256"], repair._sha(page["text"].encode()))
                self.assertFalse(page["qa"]["clipping_suspected"])
                self.assertIn(page["extraction_method"], ("pypdf+pdftoppm", "pymupdf"))
        self.assertTrue(all(s.store.fs["files"][k] == v for k, v in before.items()))

    def test_real_png_ocr_is_not_spec_text_or_hidden_pdf_text(self):
        case, _, _ = example("PNG")
        text = "PUBLIC SAMPLE\nReference ALPHA 2468\nBlue folder on shelf three."
        case["uploads"][0]["pages"] = [text]
        ref = reference(case, text)
        req = {"document_index": 1, "required_blocks": ["text"], "required_spans": [ref],
               "required_field_labels": [], "description_spans": [],
               "blank_signature_evidence": None, "unavailable_visuals": []}
        doc = {"document_index": 1, "format": "PNG", "elements": [{"type": "text", "text": ref}]}
        s = self.prepare(case, [req], [doc])
        handle = repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="png-v1")
        result = repair.verify_successor(s.store, handle)
        extraction = repair._load(s.store.read_bytes("png-v1/extraction.json"))[0]
        page = extraction["pages"][0]
        if page["error"]:
            self.assertEqual(result["state"], "HOLD")
            self.assertFalse(extraction["layout_text_roundtrip"])
        else:
            self.assertIn(page["extraction_method"], ("apple_vision", "tesseract"))
            self.assertIn("Reference ALPHA 2468", page["text"])
            self.assertIn("Blue folder", page["text"])
        self.assertFalse(result["eligible"])

    def test_changed_facts_offsets_other_case_and_free_text_hold(self):
        s = self.prepare()
        for mutation, code in (
            (lambda o: o["documents"][0]["elements"][2]["rows"][0][1].update(text="£1250"), "HOLD_FACT_TEXT_CHANGED"),
            (lambda o: o["documents"][0]["elements"][0]["text"].update(start=True), "HOLD_FORMAT_SCHEMA"),
            (lambda o: o["documents"][0]["elements"][0]["text"].update(source="follow_up"), "HOLD_SPAN_SCOPE_OR_OFFSET"),
            (lambda o: o["documents"][0]["elements"][0]["text"].update(source="uploads/1/pages/0"), "HOLD_SPAN_SCOPE_OR_OFFSET"),
            (lambda o: o.update(question="A simpler question"), "HOLD_FORMAT_SCHEMA"),
            (lambda o: o.update(eligible=True), "HOLD_FORMAT_SCHEMA"),
            (lambda o: o.update(case_id="different-case"), "HOLD_OUTPUT_IDENTITY"),
            (lambda o: o["documents"][0].update(format="PNG"), "HOLD_FORMAT_CHANGED"),
        ):
            with self.subTest(code=code):
                output = copy.deepcopy(s.output)
                mutation(output)
                self.assertEqual(self.validate(s, output)["hold_codes"], [code])

    def test_missing_required_structure_fields_and_source_text_hold(self):
        s = self.prepare()
        mutations = [
            lambda o: o["documents"][0]["elements"][3]["headers"].pop("date"),
            lambda o: o["documents"][0]["elements"][4]["messages"][0].pop("timestamp"),
            lambda o: o["documents"][0]["elements"][1]["fields"][0].update(value=None),
            lambda o: o["documents"][0]["elements"][2]["rows"][0].pop(),
            lambda o: o["documents"][0]["elements"].pop(2),
            lambda o: o.update(documents=[]),
        ]
        for mutate in mutations:
            output = copy.deepcopy(s.output)
            mutate(output)
            self.assertEqual(self.validate(s, output)["state"], "HOLD")
        case, reqs, docs = example()
        case["uploads"][0]["pages"][0] += "\nAn additional material fact."
        s = self.prepare(case, reqs, docs)
        self.assertEqual(self.validate(s)["hold_codes"], ["HOLD_ORIGINAL_FACT_TEXT_OMITTED"])

    def test_duplicate_and_split_fact_spans_hold(self):
        s = self.prepare()
        output = copy.deepcopy(s.output)
        output["documents"][0]["elements"].append(copy.deepcopy(output["documents"][0]["elements"][0]))
        self.assertEqual(self.validate(s, output)["hold_codes"], ["HOLD_REUSED_FACT_SPAN"])
        output = copy.deepcopy(s.output)
        amount = output["documents"][0]["elements"][2]["rows"][0][1]
        original = copy.deepcopy(amount)
        amount.update(end=amount["start"] + 3, text="£12")
        output["documents"][0]["elements"].append({"type": "text", "text": {
            **original, "start": original["start"] + 3, "text": ".50"}})
        self.assertEqual(self.validate(s, output)["hold_codes"], ["HOLD_REQUIRED_FACT_MISSING"])

    def test_frozen_description_omission_only_and_unavailable_visuals_hold(self):
        case, reqs, docs = example()
        case["uploads"][0]["pages"][0] += "\nThis is the document layout description."
        reqs[0]["description_spans"] = [reference(case, "This is the document layout description.")]
        s = self.prepare(case, reqs, docs)
        self.assertEqual(self.validate(s)["state"], "VALID_FORMATTING_ONLY")
        reqs[0]["unavailable_visuals"] = ["photo"]
        s = self.prepare(case, reqs, docs)
        self.assertEqual(self.validate(s)["hold_codes"], ["HOLD_UNAVAILABLE_VISUAL"])
        h = repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="held-v1")
        result = repair.verify_successor(s.store, h)
        self.assertEqual(result["state"], "HOLD")
        self.assertFalse(any(k.endswith((".png", ".pdf")) for k in result["files"]))
        case, reqs, docs = example()
        reqs[0]["blank_signature_evidence"] = None
        s = self.prepare(case, reqs, docs)
        self.assertEqual(self.validate(s)["hold_codes"], ["HOLD_SIGNATURE_NOT_EXPLICITLY_BLANK"])
        case, reqs, docs = example()
        case["uploads"][0]["pages"][0] = case["uploads"][0]["pages"][0].replace(
            "Signature area is blank.", "Signature area is not blank.")
        reqs[0]["blank_signature_evidence"] = reference(case, "Signature area is not blank.")
        with self.assertRaisesRegex(repair.FixtureRepairError, "SIGNATURE_NOT_EXPLICITLY_BLANK"):
            self.prepare(case, reqs, docs)

    def test_duplicate_json_and_explicit_hold_preserved_without_render(self):
        s = self.prepare()
        raw = b'{"schema":"a","schema":"b"}'
        self.assertEqual(repair.validate_formatted_output(s.store, s.handle, raw)["hold_codes"],
                         ["HOLD_DUPLICATE_JSON_KEY"])
        s.output.update(status="HOLD", hold_codes=["MISSING_FACT"], documents=[])
        raw = repair._json(s.output)
        with patch.object(repair, "_render_pdf", side_effect=AssertionError("must not render")):
            h = repair.render_successor(s.store, s.handle, raw, successor_name="held-v1")
        self.assertEqual(s.store.read_bytes("held-v1/formatter-output.json"), raw)
        self.assertEqual(repair.verify_successor(s.store, h)["state"], "HOLD")

    def test_no_overwrite_and_partial_attempt_survives(self):
        s = self.prepare()
        before = dict(s.store.fs["files"])
        with self.assertRaises(FileExistsError):
            self.prepare(store=s.store)
        self.assertEqual(before, s.store.fs["files"])
        with patch.object(repair, "_render_pdf", side_effect=ValueError("PRIVATE_ERROR_CONTENT")):
            h = repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="failed-v1")
        result = repair.verify_successor(s.store, h)
        self.assertEqual(result["hold_codes"], ["HOLD_RENDER_FAILED"])
        self.assertNotIn("PRIVATE_ERROR_CONTENT", str(result))
        before = dict(s.store.fs["files"])
        with self.assertRaises(FileExistsError):
            repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="failed-v1")
        self.assertEqual(before, s.store.fs["files"])

    def test_tamper_rejected_for_job_originals_schema_output_and_page(self):
        for path in ("originals/case.json", "originals/manifest.json", "originals/file-0001.bytes",
                     "formatter/input.json", "formatter/schema.json", "formatter/prompt.txt", "job.json"):
            s = self.prepare()
            s.store.fs["files"]["repair-v1/" + path] += b" "
            with self.subTest(path=path), self.assertRaisesRegex(repair.FixtureRepairError, "HASH_MISMATCH"):
                self.validate(s)
        s = self.prepare()
        h = repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="render-v1")
        for path in ("document-0001.pdf", "document-0001-page-0001.png", "formatter-output.json",
                     "extraction.json", "UPLOAD-MANIFEST.json", "result.json"):
            key = "render-v1/" + path
            original = s.store.fs["files"][key]
            s.store.fs["files"][key] = original + b"tampered"
            with self.subTest(path=path), self.assertRaisesRegex(repair.FixtureRepairError, "HASH_MISMATCH"):
                repair.verify_successor(s.store, h)
            s.store.fs["files"][key] = original  # Memory-only simulated corruption, no disk mutation.

    def test_no_oracle_or_review_prose_input(self):
        s = self.prepare()
        for field in ("oracle", "sources", "answer", "cases"):
            case = dict(s.case, **{field: "SECRET"})
            with self.subTest(field=field), self.assertRaisesRegex(repair.FixtureRepairError, "NON_AUTHOR"):
                repair.prepare_repair_job(repair._json(case), s.manifest_raw, s.original, MemoryStore(),
                    job_name="bad", formatter_context_id="fresh", requirements=s.requirements)
        with self.assertRaisesRegex(repair.FixtureRepairError, "NON_FORMATTING_REVIEW"):
            repair.prepare_repair_job(s.case_raw, s.manifest_raw, s.original, MemoryStore(),
                job_name="bad", formatter_context_id="fresh", requirements=s.requirements,
                review_issues=["The correct legal answer is SECRET"])

    def test_traversal_and_absolute_paths_rejected_before_io(self):
        store = repair.DirectoryStore("/synthetic")
        for name in ("../outside", "/outside", "a/../b", "a//b", "./b", "a\\b", "a/.", ""):
            with self.subTest(name=name), patch.object(os, "open") as opened:
                for operation in (store.read_bytes, store.mkdir_new, lambda n: store.write_new(n, b"data")):
                    with self.assertRaises(repair.FixtureRepairError):
                        operation(name)
                opened.assert_not_called()
        s = self.prepare()
        manifest = copy.deepcopy(s.manifest)
        manifest["files"][0]["relative_path"] = "../private"
        original = Mock()
        with self.assertRaisesRegex(repair.FixtureRepairError, "UNSAFE_PATH"):
            repair.prepare_repair_job(s.case_raw, repair._json(manifest), original, MemoryStore(),
                job_name="safe", formatter_context_id="fresh", requirements=s.requirements)
        original.read_bytes.assert_not_called()

    def test_directory_store_exclusive_flags_and_no_follow_every_component(self):
        store = repair.DirectoryStore("/synthetic/root")
        calls = []

        def opened(path, flags, *args, **kwargs):
            calls.append((path, flags, args, kwargs))
            if path == "existing.pdf":
                raise FileExistsError()
            return 100 + len(calls)

        with patch.object(os, "open", side_effect=opened), patch.object(os, "close"):
            with self.assertRaises(FileExistsError):
                store.write_new("job/existing.pdf", b"preserve")
        self.assertEqual([c[0] for c in calls], ["/", "synthetic", "root", "job", "existing.pdf"])
        for _, flags, _, _ in calls:
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertFalse(flags & os.O_TRUNC)
        self.assertTrue(calls[-1][1] & os.O_EXCL)
        self.assertTrue(calls[-1][1] & os.O_CREAT)
        self.assertEqual(calls[-1][2], (0o600,))
        for component in ("synthetic", "root", "job", "leaf"):
            visited = []

            def symlink_open(path, flags, *args, **kwargs):
                visited.append(path)
                self.assertTrue(flags & os.O_NOFOLLOW)
                if path == component:
                    raise OSError(errno.ELOOP, "symlink")
                return 80 + len(visited)

            with patch.object(os, "open", side_effect=symlink_open), patch.object(os, "close"):
                with self.assertRaises(OSError):
                    store.read_bytes("job/leaf")
            self.assertEqual(visited[-1], component)

    def test_table_pagination_actual_extraction_preserves_all_rows(self):
        case, reqs, _ = example()
        lines = ["Reference", "Amount"]
        for i in range(60):
            lines.extend([f"ROW-{i:03d}", f"GBP {i}.25"])
        case["uploads"][0]["pages"] = ["\n".join(lines)]
        refs = [reference(case, line) for line in lines]
        table = {"type": "table", "headers": refs[:2],
                 "rows": [refs[i:i + 2] for i in range(2, len(refs), 2)]}
        doc = {"document_index": 1, "format": "PDF", "elements": [table]}
        reqs[0].update(required_blocks=["table"], required_spans=refs,
                       required_field_labels=[], blank_signature_evidence=None)
        s = self.prepare(case, reqs, [doc])
        h = repair.render_successor(s.store, s.handle, repair._json(s.output), successor_name="pages-v1")
        self.assertEqual(repair.verify_successor(s.store, h)["state"], "AWAITING_FRESH_REVIEW")
        extracted = repair._load(s.store.read_bytes("pages-v1/extraction.json"))[0]
        self.assertGreater(len(extracted["pages"]), 1)
        self.assertTrue(extracted["layout_text_roundtrip"])
        self.assertIn("ROW-059", extracted["pages"][-1]["text"])

    def test_adapter_parent_manifest_bindings_and_held_lookup(self):
        s = self.prepare()
        fs = {"files": {}, "dirs": {"", "synthetic", "synthetic/private"}}

        def directory(root):
            return MemoryStore(fs, str(root))

        private = directory("/synthetic/private")
        for folder in ("fixtures", "fixtures/shard-01", "fixtures/shard-01/case-01"):
            private.mkdir_new(folder)
        original = directory("/synthetic/private/fixtures/shard-01/case-01")
        original.write_new("old.bytes", self.old_pdf)
        original.write_new("UPLOAD-MANIFEST.json", s.manifest_raw)
        r = SimpleNamespace(PRIVATE=Path("/synthetic/private"), safe_path=Mock(),
            completion_recheckable=Mock(return_value=True))
        r.read = lambda path: repair._load(directory(path.parent).read_bytes(path.name))
        work = r.PRIVATE / "fixture-format/shard-01-case-01"
        target = r.PRIVATE / "fixture-repaired/shard-01-case-01"
        with patch.object(repair, "DirectoryStore", side_effect=directory):
            inventory_input = repair.prepare_requirement_input(repair._json(s.case), s.manifest_raw,
                inventory_context_id="fresh-inventory-01", formatter_context_id=work.name,
                review_issues=["PROSE_ONLY"])
            inventory_output = {"schema": repair.REQUIREMENT_VERSION, "case_id": s.case["case_id"],
                "original_binding_sha256": inventory_input["original_binding_sha256"],
                "status": "DRAFT", "hold_codes": [], "requirements": s.requirements}
            repair.prepare_formatter_job(r, work, s.case, r.PRIVATE / "fixtures/shard-01/case-01",
                inventory_input=inventory_input, inventory_output_json=repair._json(inventory_output),
                review_issues=["PROSE_ONLY"])
            input_doc = r.read(work / "input.json")
            output = dict(s.output, job_binding_sha256=input_doc["job_binding_sha256"])
            directory(work).write_new("output.json", repair._json(output))
            self.assertEqual(repair.formatter_input_expected_ids(input_doc), [s.case["case_id"]])
            self.assertEqual(repair.formatter_output_case_ids(output), [s.case["case_id"]])
            self.assertEqual(repair.validate_formatter_job(r, work), output)
            directory(work).write_new("COMPLETION.json", b"{}")
            result = repair.render_formatter_output(r, work)
            self.assertEqual(result["state"], "AWAITING_FRESH_REVIEW")
            manifest = repair.validate_rendered_successor(r, target)
            self.assertEqual(manifest["case_id"], s.case["case_id"])
            self.assertEqual(len(manifest["files"]), len(manifest["extraction"]))
            self.assertFalse(manifest["eligible"])
            self.assertEqual(r.completion_recheckable.call_count, 2)
            completion_path = directory(work).path("COMPLETION.json")
            fs["files"][completion_path] = b'{"tampered":true}'
            with self.assertRaisesRegex(repair.FixtureRepairError, "COMPLETION_NOT_VERIFIED"):
                repair.validate_rendered_successor(r, target)
            fs["files"][completion_path] = b"{}"
            with self.assertRaises(FileExistsError):
                repair.render_formatter_output(r, work)
            raw_path = original.path("old.bytes")
            fs["files"][raw_path] += b"changed"
            with self.assertRaisesRegex(repair.FixtureRepairError, "ORIGINAL_FILE_TAMPERED"):
                repair.validate_rendered_successor(r, target)

    def test_independent_inventory_completeness_binding_and_role_separation(self):
        s = self.prepare()
        payload = repair.prepare_requirement_input(s.case_raw, s.manifest_raw,
            inventory_context_id="inventory-01", formatter_context_id="formatter-02")
        output = {"schema": repair.REQUIREMENT_VERSION, "case_id": s.case["case_id"],
                  "original_binding_sha256": payload["original_binding_sha256"],
                  "status": "DRAFT", "hold_codes": [], "requirements": s.requirements}
        self.assertNotIn("SECRET_", repair._json(payload).decode())
        self.assertEqual(repair.validate_requirement_output(payload, repair._json(output))["state"],
                         "INVENTORY_DRAFT_BOUND")
        destination = MemoryStore()
        handle = repair.prepare_repair_job(s.case_raw, s.manifest_raw, s.original, destination,
            job_name="from-inventory-v1", formatter_context_id="formatter-02",
            inventory_input=payload, inventory_output_json=repair._json(output))
        job, formatted = repair._job(destination, handle)
        self.assertEqual(job["binding"]["inventory_origin"], "SEPARATE_ROLE_DRAFT")
        self.assertEqual(destination.read_bytes("from-inventory-v1/originals/inventory-output.json"),
                         repair._json(output))
        self.assertEqual(formatted["requirements"], s.requirements)
        for mutation, expected in (
            (lambda o: o["requirements"][0]["required_spans"].pop(0), "HOLD_INVENTORY_UNACCOUNTED_TEXT"),
            (lambda o: o["requirements"][0]["description_spans"].append(o["requirements"][0]["required_spans"][0]),
             "HOLD_INVENTORY_FACT_DESCRIPTION_OVERLAP"),
            (lambda o: o.update(status="HOLD", hold_codes=["MISSING_REQUIRED_FIELD"]), "HOLD_INVENTORY_REPORTED"),
            (lambda o: o["requirements"][0]["unavailable_visuals"].append("photo"), "HOLD_UNAVAILABLE_VISUAL"),
            (lambda o: o.update(original_binding_sha256="wrong"), "HOLD_INVENTORY_OUTPUT_BINDING"),
        ):
            bad = copy.deepcopy(output)
            mutation(bad)
            self.assertEqual(repair.validate_requirement_output(payload, repair._json(bad))["hold_codes"], [expected])
        with self.assertRaisesRegex(repair.FixtureRepairError, "CONTEXT_REUSE"):
            repair.prepare_requirement_input(s.case_raw, s.manifest_raw,
                inventory_context_id="same", formatter_context_id="same")
        with self.assertRaisesRegex(repair.FixtureRepairError, "INVENTORY_ORIGINAL_BINDING"):
            repair.prepare_repair_job(s.case_raw, s.manifest_raw, s.original, MemoryStore(),
                job_name="wrong-formatter", formatter_context_id="wrong-context",
                inventory_input=payload, inventory_output_json=repair._json(output))

    def test_schema_prepare_validate_import_without_site_packages(self):
        completed = subprocess.run([sys.executable, "-B", "-S", "-c",
            "from scripts import ge_unseen_fixture_repair as r; "
            "assert r.FORMATTER_SCHEMA == r.format_schema(); "
            "assert r.REQUIREMENT_SCHEMA == r.requirement_schema(); "
            "assert callable(r.validate_rendered_successor); "
            "import sys; assert 'reportlab' not in sys.modules; "
            "assert 'scripts.ge_unseen_fixtures' not in sys.modules"],
            cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=30, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_wrong_adapter_paths_fail_before_any_store_access(self):
        r = SimpleNamespace(PRIVATE=Path("/synthetic/private"), safe_path=Mock())
        with patch.object(repair, "DirectoryStore") as store:
            for function in (repair.validate_rendered_successor, repair.render_formatter_output,
                             repair.validate_formatter_job):
                with self.assertRaisesRegex(repair.FixtureRepairError, "ADAPTER_PATH_MISMATCH"):
                    function(r, Path("/outside/shard-01-case-01"))
            store.assert_not_called()


if __name__ == "__main__":
    unittest.main()
