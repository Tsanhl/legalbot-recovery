"""Public technical fixtures only. All outputs survive; no temporary cleanup.

Run with the bundled Python: -B -m unittest backend.tests.test_ge_unseen_fixtures -v
Each invocation reserves a new tmp/pdfs/ge-fixtures-public-* directory. Nothing
reads bank files, project fixtures, or other tests' data. Artifact authoring must
be announced once by the operator's PDF artifact marker before the initial run.
"""

from __future__ import annotations

import hashlib
import io
import json
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from PIL import Image, ImageDraw
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

from scripts import ge_unseen_fixtures as fixtures


class DiagnosticFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[2]
        cls.output = root / "tmp/pdfs" / ("ge-fixtures-public-" + uuid.uuid4().hex[:12])
        cls.output.mkdir(parents=True, exist_ok=False)
        cls.unicode_text = "Café £12.50 €7.00 — “sample” e\u0301."
        cls.long_token = "X" * 360
        cls.specs = [
            {"title": "Public technical PDF", "format": "PDF", "pages": [
                "PUBLIC TECHNICAL SAMPLE\n" + cls.unicode_text + "\n" + cls.long_token + "\n"
                + "\n".join(f"Line {n:03d}: blue folder on shelf." for n in range(55)),
                "Final source page. Page sequence 2.",
                "",
            ]},
            {"title": "Public technical image", "format": "PNG", "pages": [
                "PUBLIC OCR TECHNICAL SAMPLE\nReference ALPHA 2468\nBlue folder on shelf three.",
                "",
            ]},
        ]
        cls.manifests = fixtures.render_uploads(cls.specs, cls.output / "rendered")
        cls.receipts = fixtures.extract_uploads(cls.manifests, cls.output / "rendered")
        fixtures._write_new(cls.output / "extraction.json", json.dumps(cls.receipts, indent=2).encode())
        # Real image-only PDF, with no hidden text layer.
        buffer = io.BytesIO()
        doc = canvas.Canvas(buffer, pagesize=(595, 842), invariant=1)
        png = (cls.output / "rendered" / cls.manifests[1]["relative_path"]).read_bytes()
        doc.drawImage(ImageReader(io.BytesIO(png)), 0, 0, width=595, height=842)
        doc.showPage()
        doc.save()
        fixtures._write_new(cls.output / "image-only.pdf", buffer.getvalue())
        writer = PdfWriter()
        pdf = cls.output / "rendered" / cls.manifests[0]["relative_path"]
        writer.add_page(PdfReader(io.BytesIO(pdf.read_bytes())).pages[0])
        writer.encrypt("public-technical-test-password")
        with (cls.output / "encrypted.pdf").open("xb") as stream:
            writer.write(stream)
        fixtures._write_new(cls.output / "corrupt.pdf", b"%PDF-1.7\nnot a valid document")
        fixtures._write_new(cls.output / "corrupt.png", b"\x89PNG\r\n\x1a\nnot an image")
        fixtures._write_new(cls.output / "empty.pdf", b"")
        edge = Image.new("RGB", (120, 80), "white")
        ImageDraw.Draw(edge).rectangle((0, 20, 8, 35), fill="black")
        fixtures._write_new(cls.output / "edge.png", fixtures._png_bytes(edge))
        cls.before = {p.relative_to(cls.output).as_posix(): fixtures._sha(p.read_bytes())
                      for p in cls.output.rglob("*") if p.is_file()}
        print("\nRetained public diagnostic outputs:", cls.output)

    def test_pdf_pagination_unicode_and_blank_page_indexes(self):
        manifest, receipt = self.manifests[0], self.receipts[0]
        self.assertGreater(manifest["page_count"], 3)
        self.assertEqual(receipt["page_count"], manifest["page_count"])
        self.assertEqual([p["page_number"] for p in receipt["pages"]],
                         list(range(1, manifest["page_count"] + 1)))
        text = "\n".join(page["text"] for page in receipt["pages"])
        self.assertIn(self.unicode_text, text)
        self.assertIn(self.long_token, "".join(text.split()))
        self.assertIn("Line 054: blue folder on shelf.", text)
        self.assertIn("Final source page. Page sequence 2.", text)
        self.assertEqual(receipt["error"], "BLANK_PAGE")
        self.assertEqual(receipt["pages"][-1]["text"], "")
        for page in receipt["pages"]:
            self.assertIsNone(page["confidence"])
            self.assertFalse(page["qa"]["clipping_suspected"])
            self.assertIn(page["extraction_method"], {"pymupdf", "pypdf+pdftoppm"})
        for page in manifest["qa"]["pages"]:
            self.assertTrue(page["text_roundtrip_matches_layout"])
        self.assertEqual(manifest["qa"]["pages"][-1]["source_page_number"], 3)

    def test_actual_png_ocr_and_one_file_per_page(self):
        manifest, receipt = self.manifests[1], self.receipts[1]
        self.assertEqual(manifest["page_count"], 1)
        self.assertEqual(manifest["document_page_count"], 2)
        self.assertEqual(manifest["document_page_number"], 1)
        page = receipt["pages"][0]
        if not fixtures._tool("tesseract") and sys.platform != "darwin":
            self.assertEqual(page["error"], "OCR_UNAVAILABLE")
            return
        self.assertIsNone(receipt["error"])
        self.assertIn("ALPHA 2468", page["text"])
        self.assertIn("Blue folder", page["text"])
        self.assertIn(page["extraction_method"], {"tesseract", "apple_vision"})
        self.assertGreater(page["confidence"], 0)
        self.assertLessEqual(page["confidence"], 1)
        blank = self.receipts[2]
        self.assertEqual(blank["error"], "BLANK_PAGE")
        self.assertEqual(blank["pages"][0]["text"], "")
        self.assertEqual(blank["pages"][0]["extraction_method"], "none")

    def test_provenance_binds_raw_file_page_raster_and_extracted_text(self):
        for manifest, receipt in zip(self.manifests, self.receipts, strict=True):
            raw = (self.output / "rendered" / manifest["relative_path"]).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest["sha256"])
            self.assertEqual(receipt["file_sha256"], manifest["sha256"])
            for page, qa in zip(receipt["pages"], manifest["qa"]["pages"], strict=True):
                raster = (self.output / "rendered" / qa["render_relative_path"]).read_bytes()
                self.assertEqual(page["page_sha256"], hashlib.sha256(raster).hexdigest())
                self.assertEqual(page["text_sha256"], hashlib.sha256(page["text"].encode()).hexdigest())
                binding = {k: page[k] for k in ("file_sha256", "page_number", "page_sha256")}
                self.assertEqual(page["page_provenance_sha256"], fixtures._json_sha(binding))
            self.assertNotIn("Café", json.dumps(manifest, ensure_ascii=False))
            self.assertNotIn("Reference ALPHA", json.dumps(manifest))

    def test_extraction_ignores_spec_oracle_and_checks_manifest_hash(self):
        poisoned = dict(self.manifests[0], pages=["FABRICATED ORACLE TEXT"], text="FABRICATED ORACLE TEXT")
        result = fixtures.extract_uploads([poisoned], self.output / "rendered")[0]
        self.assertNotIn("FABRICATED", "".join(p["text"] for p in result["pages"]))
        for field, bad_value, error in (("sha256", "0" * 64, "FILE_HASH_MISMATCH"),
                                        ("format", "PNG", "FILE_FORMAT_MISMATCH"),
                                        ("page_count", 200, "FILE_PAGE_COUNT_MISMATCH")):
            invalid = dict(self.manifests[0], **{field: bad_value})
            failed = fixtures.extract_uploads([invalid], self.output / "rendered")[0]
            self.assertEqual(failed["error"], error)
            self.assertEqual(failed["pages"], [])
            self.assertEqual(failed["file_sha256"], self.manifests[0]["sha256"])

    def test_corrupt_blank_encrypted_and_image_only_documents_are_honest(self):
        names = ["corrupt.pdf", "corrupt.png", "empty.pdf", "encrypted.pdf", "image-only.pdf"]
        results = fixtures.extract_uploads(names, self.output)
        for name, result in zip(names, results, strict=True):
            self.assertTrue(result["error"], name)
            self.assertEqual(result["file_sha256"], fixtures._sha((self.output / name).read_bytes()))
        self.assertEqual(results[3]["error"], "ENCRYPTED_PDF")
        self.assertEqual(results[4]["error"], "NO_EXTRACTABLE_TEXT_OCR_REQUIRED")
        self.assertEqual(results[4]["pages"][0]["text"], "")
        self.assertFalse(results[4]["pages"][0]["qa"]["blank"])

    def test_missing_ocr_and_page_errors_keep_indexes_without_inventing_text(self):
        with patch.object(fixtures, "_ocr", side_effect=fixtures.FixtureError("OCR_UNAVAILABLE")):
            receipt = fixtures.extract_uploads([self.manifests[1]], self.output / "rendered")[0]
        self.assertEqual(receipt["error"], "OCR_UNAVAILABLE")
        self.assertEqual(receipt["pages"][0]["text"], "")
        self.assertIsNone(receipt["pages"][0]["confidence"])
        self.assertEqual(receipt["pages"][0]["page_number"], 1)
        simulated_pages = [(1, "", None, "pypdf+pdftoppm", "test", "PDF_PAGE_UNREADABLE"),
                           (2, "", None, "pypdf+pdftoppm", "test", "TOOL_TIMEOUT")]
        with patch.object(fixtures, "_pdf_pages", return_value=iter(simulated_pages)):
            receipt = fixtures.extract_uploads([self.manifests[0]["relative_path"]], self.output / "rendered")[0]
        self.assertEqual([p["page_number"] for p in receipt["pages"]], [1, 2])
        self.assertEqual(receipt["pages"][1]["error"], "TOOL_TIMEOUT")

    def test_clipping_qa_is_read_only_and_contains_no_body(self):
        receipt = fixtures.qa_uploads(["edge.png"], self.output)[0]
        self.assertEqual(receipt["error"], "CLIPPING_SUSPECTED")
        self.assertTrue(receipt["pages"][0]["qa"]["clipping_suspected"])
        qa = fixtures.qa_uploads(self.manifests, self.output / "rendered")
        self.assertTrue(all("text" not in p for item in qa for p in item["pages"]))
        current = {p.relative_to(self.output).as_posix(): fixtures._sha(p.read_bytes())
                   for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(self.before, current)

    def test_collisions_and_invalid_specs_never_modify_existing_outputs(self):
        with self.assertRaises(FileExistsError):
            fixtures.render_uploads(self.specs, self.output / "rendered")
        invalid_specs = [
            {"title": "technical", "format": "GIF", "pages": ["sample"]},
            {"title": "technical", "format": "PDF", "pages": []},
            {"title": "technical", "format": "PDF", "pages": ["\U0010ffff"]},
            {"title": "technical", "format": "PDF", "pages": ["abc\x00"]},
            {"title": "technical", "format": "PDF", "pages": ["مرحبا"]},
        ]
        for spec in invalid_specs:
            with self.assertRaises(fixtures.FixtureError):
                fixtures.render_uploads([spec], self.output / "invalid-never-created")
        self.assertFalse((self.output / "invalid-never-created").exists())
        current = {p.relative_to(self.output).as_posix(): fixtures._sha(p.read_bytes())
                   for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(self.before, current)

    def test_paths_cannot_escape_directory_or_follow_symlinks(self):
        receipts = fixtures.extract_uploads(["../no-access.pdf", "/no-access.pdf", "missing.pdf"], self.output)
        self.assertTrue(all(r["error"] and not r["pages"] for r in receipts))
        # Symlink target is another PUBLIC test output. No external data is used.
        link_dir = self.output / ("links-" + uuid.uuid4().hex[:8])
        link_dir.mkdir()
        (link_dir / "linked.pdf").symlink_to(self.output / "image-only.pdf")
        (link_dir / "directory").symlink_to(self.output / "rendered", target_is_directory=True)
        paths = ["linked.pdf", "directory/" + self.manifests[0]["relative_path"]]
        receipts = fixtures.extract_uploads(paths, link_dir)
        self.assertTrue(all(r["error"] and not r["file_sha256"] for r in receipts))
        with self.assertRaises(fixtures.FixtureError):
            fixtures.render_uploads(self.specs, link_dir / "directory")

    def test_wrap_measures_long_tokens_and_trailing_space(self):
        lines = fixtures._wrap("ABCDE ", lambda value: len(value) * 99)
        self.assertEqual("".join(lines).strip(), "ABCDE")
        self.assertEqual(fixtures.render_uploads([], self.output / "no-op"), [])
        self.assertFalse((self.output / "no-op").exists())

    def test_render_qa_failure_preserves_file_raster_and_failure_receipt(self):
        # Reuse public rendered bytes; deliberately fail a roundtrip check. No
        # additional fixture content or PDF generation is needed for this test.
        target = self.output / ("failed-qa-" + uuid.uuid4().hex[:8])
        original = (self.output / "rendered" / self.manifests[0]["relative_path"]).read_bytes()
        real_inspect = fixtures._inspect

        def wrong_roundtrip(*args, **kwargs):
            receipt, rasters = real_inspect(*args, **kwargs)
            receipt["pages"][0]["text"] = "Simulated extraction mismatch"
            return receipt, rasters

        with patch.object(fixtures, "_render_pdf", return_value=original), \
                patch.object(fixtures, "_inspect", side_effect=wrong_roundtrip), \
                self.assertRaisesRegex(fixtures.FixtureError, "RENDER_TEXT_ROUNDTRIP_MISMATCH"):
            fixtures.render_uploads([self.specs[0]], target)
        self.assertEqual((target / "upload-0001.pdf").read_bytes(), original)
        receipt = json.loads((target / "upload-0001.pdf.qa/receipt.json").read_text())
        self.assertIn("RENDER_TEXT_ROUNDTRIP_MISMATCH", receipt["error"])
        self.assertFalse(receipt["pages"][0]["text_roundtrip_matches_layout"])
        self.assertNotIn("text", receipt["pages"][0])
        self.assertTrue((target / receipt["pages"][0]["render_relative_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
