from __future__ import annotations

import io
import json
import stat
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from backend.app.ingestion import (
    BlockKind,
    ContentAddressedVault,
    DedupeLedger,
    DedupeStatus,
    IngestionOutcomeStatus,
    IngestionPipeline,
    IngestionRequest,
    Jurisdiction,
    MaterialLane,
    ParserRegistry,
    ParseStatus,
    PIIAliaser,
    SourceIdentity,
    StructuralChunker,
    canonical_source_identity,
    private_locator_digest,
)


def _zip_bytes(files: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return output.getvalue()


class ParserContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parsers = ParserRegistry.default()
        self.aliaser = PIIAliaser(b"a deployment-only alias secret")

    def test_markdown_comments_are_a_separate_non_authority_stream(self) -> None:
        parsed = self.parsers.parse(
            b"# Consideration\n\nThe rule in the body.\n\n<!-- private marker -->",
            filename="lecture.md",
            aliaser=self.aliaser,
        )
        self.assertEqual(parsed.status, ParseStatus.READY)
        self.assertNotIn("private marker", " ".join(block.text for block in parsed.body_blocks))
        self.assertEqual([comment.text for comment in parsed.comments], ["private marker"])

        chunks = StructuralChunker(max_chars=300, min_chars=20)
        body = chunks.chunk_body(parsed, document_sha256="a" * 64)
        comments = chunks.chunk_comments(parsed, document_sha256="a" * 64)
        self.assertTrue(body)
        self.assertEqual({chunk.stream for chunk in body}, {"body"})
        self.assertEqual({chunk.stream for chunk in comments}, {"comments"})
        self.assertNotEqual(body[0].chunk_id, comments[0].chunk_id)

    def test_docx_current_view_comments_and_tracked_changes_are_separate(self) -> None:
        namespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        document = f"""<?xml version="1.0" encoding="UTF-8"?>
        <w:document xmlns:w="{namespace}"><w:body>
          <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Contract Law</w:t></w:r></w:p>
          <w:p><w:r><w:t>Current </w:t></w:r>
            <w:del w:id="7" w:author="Alice" w:date="2025-01-01T00:00:00Z"><w:r><w:delText>old rule</w:delText></w:r></w:del>
            <w:ins w:id="8" w:author="Alice"><w:r><w:t>new rule</w:t></w:r></w:ins>
          </w:p>
        </w:body></w:document>"""
        comments = f"""<?xml version="1.0" encoding="UTF-8"?>
        <w:comments xmlns:w="{namespace}">
          <w:comment w:id="3" w:author="Bob"><w:p><w:r><w:t>Explain the ratio.</w:t></w:r></w:p></w:comment>
        </w:comments>"""
        data = _zip_bytes({"word/document.xml": document, "word/comments.xml": comments})

        parsed = self.parsers.parse(data, filename="feedback.docx", aliaser=self.aliaser)

        self.assertEqual(parsed.status, ParseStatus.READY)
        body_text = " ".join(block.text for block in parsed.body_blocks)
        self.assertIn("new rule", body_text)
        self.assertNotIn("old rule", body_text)
        self.assertEqual(parsed.body_blocks[0].kind, BlockKind.TITLE)
        self.assertEqual([comment.text for comment in parsed.comments], ["Explain the ratio."])
        self.assertEqual({revision.operation for revision in parsed.revisions}, {"del", "ins"})
        self.assertNotIn("Alice", {revision.author_alias for revision in parsed.revisions})
        self.assertNotEqual(parsed.comments[0].author_alias, "Bob")

    def test_odt_does_not_duplicate_list_items_or_leak_annotations_into_body(self) -> None:
        content = """<?xml version="1.0" encoding="UTF-8"?>
        <office:document-content
          xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
          xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"
          xmlns:dc="http://purl.org/dc/elements/1.1/">
          <office:body><office:text>
            <text:tracked-changes><text:changed-region text:id="ct1"><text:deletion><text:p>Deleted authority</text:p></text:deletion></text:changed-region></text:tracked-changes>
            <text:h text:outline-level="1">Evidence</text:h>
            <text:p>Visible rule<office:annotation><dc:creator>Carol</dc:creator><text:p>Review this claim</text:p></office:annotation>.</text:p>
            <text:list><text:list-item><text:p>Only once</text:p></text:list-item></text:list>
          </office:text></office:body>
        </office:document-content>"""
        parsed = self.parsers.parse(
            _zip_bytes({"content.xml": content}), filename="notes.odt", aliaser=self.aliaser
        )

        body = [block.text for block in parsed.body_blocks]
        self.assertEqual(parsed.status, ParseStatus.READY)
        self.assertNotIn("Deleted authority", " ".join(body))
        self.assertNotIn("Review this claim", " ".join(body))
        self.assertEqual(body.count("Only once"), 1)
        self.assertEqual(
            next(block.kind for block in parsed.body_blocks if block.text == "Only once"),
            BlockKind.LIST_ITEM,
        )
        self.assertTrue(any("Review this claim" in comment.text for comment in parsed.comments))
        self.assertTrue(any("Deleted authority" in revision.text for revision in parsed.revisions))
        self.assertNotEqual(parsed.comments[0].author_alias, "Carol")

    def test_pdf_encryption_ocr_and_legacy_office_are_quarantine_statuses(self) -> None:
        encrypted = self.parsers.parse(
            b"%PDF-1.7\n1 0 obj<</Encrypt 2 0 R>>endobj", filename="sealed.pdf"
        )
        legacy = self.parsers.parse(b"legacy", filename="slides.ppt")
        unsupported = self.parsers.parse(b"x", filename="archive.pages")
        malformed = self.parsers.parse(b"%PDF-1.7\nnot a real PDF", filename="broken.pdf")
        self.assertEqual(encrypted.status, ParseStatus.ENCRYPTED)
        self.assertEqual(legacy.status, ParseStatus.PARSER_UNAVAILABLE)
        self.assertEqual(unsupported.status, ParseStatus.UNSUPPORTED)
        self.assertEqual(malformed.status, ParseStatus.INVALID)

    def test_pdf_links_are_not_marker_comments(self) -> None:
        from pypdf import PdfWriter
        from pypdf.generic import ArrayObject, DictionaryObject, NameObject, TextStringObject

        writer = PdfWriter()
        page = writer.add_blank_page(width=100, height=100)
        link = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Link"),
                NameObject("/Contents"): TextStringObject("Chapter heading and URL"),
            }
        )
        marker = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Text"),
                NameObject("/Contents"): TextStringObject("Mark 72: strong counterargument."),
            }
        )
        page[NameObject("/Annots")] = ArrayObject(
            [writer._add_object(link), writer._add_object(marker)]
        )
        output = io.BytesIO()
        writer.write(output)

        parsed = self.parsers.parse(output.getvalue(), filename="feedback.pdf")

        self.assertEqual(parsed.status, ParseStatus.OCR_REQUIRED)
        self.assertEqual(
            [comment.text for comment in parsed.comments],
            ["Mark 72: strong counterargument."],
        )

    def test_encrypted_odt_is_reported_without_parsing_ciphertext(self) -> None:
        manifest = """<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"><manifest:file-entry><manifest:encryption-data/></manifest:file-entry></manifest:manifest>"""
        parsed = self.parsers.parse(
            _zip_bytes({"META-INF/manifest.xml": manifest, "content.xml": "ciphertext"}),
            filename="protected.odt",
        )
        self.assertEqual(parsed.status, ParseStatus.ENCRYPTED)

    def test_html_pptx_and_text_contracts(self) -> None:
        html = self.parsers.parse(
            b"<h1>Land</h1><p>Registered title.</p><!-- editorial only -->",
            filename="source.html",
        )
        latin1_html = self.parsers.parse(
            "<h1>Tort</h1><p>Hadley v Baxendale \xa3 damages.</p>".encode("latin-1"),
            filename="judgment.html",
        )
        pptx = self.parsers.parse(
            _zip_bytes(
                {
                    "ppt/slides/slide1.xml": "<p:sld xmlns:p='p' xmlns:a='a'><a:t>Trusts lecture</a:t></p:sld>",
                    "ppt/comments/comment1.xml": "<p:cmLst xmlns:p='p'><p:cm idx='1' dt='2025-01-01'><p:text>Fix citation</p:text></p:cm></p:cmLst>",
                }
            ),
            filename="lecture.pptx",
        )
        text = self.parsers.parse(b"First paragraph.\n\nSecond paragraph.", filename="note.txt")
        self.assertEqual(html.status, ParseStatus.READY)
        self.assertEqual(latin1_html.status, ParseStatus.READY)
        self.assertIn("damages", latin1_html.body_blocks[-1].text)
        self.assertEqual([comment.text for comment in html.comments], ["editorial only"])
        self.assertEqual(pptx.status, ParseStatus.READY)
        self.assertEqual(pptx.body_blocks[0].page, 1)
        self.assertTrue(pptx.comments)
        self.assertEqual(len(text.body_blocks), 2)


class VaultAndPipelineTests(unittest.TestCase):
    def test_content_addressed_vault_and_dual_key_deduplication(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            vault = ContentAddressedVault(root / "vault")
            first = vault.put_bytes(b"immutable bytes")
            second = vault.put_bytes(b"immutable bytes")
            self.assertEqual(first, second)
            self.assertEqual(vault.read_bytes(first.sha256), b"immutable bytes")
            self.assertFalse(first.path.stat().st_mode & stat.S_IWUSR)

            ledger = DedupeLedger(root / "dedupe.json")
            identity = SourceIdentity("doi", "10.1000/example")
            self.assertEqual(ledger.register(identity, first.sha256).status, DedupeStatus.NEW)
            self.assertEqual(
                ledger.register(identity, first.sha256).status,
                DedupeStatus.DUPLICATE_IDENTITY_AND_CONTENT,
            )
            same_bytes = ledger.register(
                SourceIdentity("url", "https://example.test/a"), first.sha256
            )
            self.assertEqual(same_bytes.status, DedupeStatus.DUPLICATE_CONTENT)
            conflict_hash = ContentAddressedVault.digest(b"changed bytes")
            self.assertEqual(
                ledger.register(identity, conflict_hash).status, DedupeStatus.IDENTITY_CONFLICT
            )

    def test_pipeline_stages_canonical_streams_but_never_an_index(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            vault = ContentAddressedVault(root / "vault")
            pipeline = IngestionPipeline(
                vault=vault,
                dedupe_ledger=DedupeLedger(root / "dedupe.json"),
                aliaser=PIIAliaser(b"another deployment secret"),
            )
            request = IngestionRequest(
                filename="topic.md",
                data=b"# Tort\n\nA duty proposition.\n\n<!-- marker is not authority -->",
                source_identity=SourceIdentity("opaque_local", "topic-v1"),
                title="Tort notes",
                source_kind="lecture",
                jurisdiction=Jurisdiction.ENGLAND_WALES,
                material_lane=MaterialLane.LECTURE_NOTE,
                private_locator_digest=private_locator_digest(
                    "/Users/owner/Desktop/Law/topic.md", salt=b"local locator salt"
                ),
            )
            outcome = pipeline.stage(request)
            self.assertEqual(outcome.status, IngestionOutcomeStatus.STAGED)
            self.assertIsNotNone(outcome.objects.body_markdown)
            self.assertIsNotNone(outcome.objects.comments_markdown)
            body = vault.read_bytes(outcome.objects.body_markdown.sha256).decode("utf-8")  # type: ignore[union-attr]
            comments = vault.read_bytes(outcome.objects.comments_markdown.sha256).decode("utf-8")  # type: ignore[union-attr]
            provenance = json.loads(
                vault.read_bytes(outcome.objects.provenance.sha256).decode("utf-8")  # type: ignore[union-attr]
            )
            self.assertNotIn("marker is not authority", body)
            self.assertIn("marker is not authority", comments)
            self.assertNotIn("/Users/owner", json.dumps(provenance))
            self.assertEqual(provenance["streams"]["comments"]["authority"], False)
            self.assertEqual(pipeline.stage(request).status, IngestionOutcomeStatus.DUPLICATE)
            self.assertFalse((root / "index").exists())

    def test_canonical_identities_and_aliases_do_not_expose_private_values(self) -> None:
        doi = canonical_source_identity("doi", "https://doi.org/10.1234/ABC")
        self.assertEqual(doi.canonical_key, "doi:10.1234/abc")
        aliaser = PIIAliaser(b"a sufficiently long secret")
        alias = aliaser.path_alias("/Users/Alice/Desktop/Exam feedback.docx")
        digest = private_locator_digest(
            "/Users/Alice/Desktop/Exam feedback.docx", salt=b"deployment salt"
        )
        self.assertNotIn("Alice", alias)
        self.assertNotIn("Exam", alias)
        self.assertNotIn("Alice", digest)
        self.assertTrue(alias.endswith(".docx"))


if __name__ == "__main__":
    unittest.main()
