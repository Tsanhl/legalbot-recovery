from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path

import pytest

from app.config import Settings
from app.db import SCHEMA, SCHEMA_VERSION, Database
from app.ingestion.chunking import StructuralChunker
from app.ingestion.markdown import CanonicalMarkdownConverter
from app.ingestion.models import (
    Annotation,
    BlockKind,
    DocumentFormat,
    Jurisdiction,
    MaterialLane,
    ParseResult,
    ParseStatus,
    Provenance,
    Revision,
    SourceIdentity,
    StructuralBlock,
)
from app.ingestion.ocr import OcrUnavailableError
from app.ingestion.parsers import (
    DocumentParser,
    ParserRegistry,
    _strip_jstor_access_notice,
    detect_format,
)
from app.ingestion.sanitation import (
    TEXT_SANITATION_SCHEMA,
    has_forbidden_controls,
    sanitize_parse_result,
    sanitize_text,
)
from app.ingestion.service import (
    SOURCE_PROCESSING_COMPONENTS,
    SOURCE_PROCESSING_FINGERPRINT,
    scan_configured_sources,
)
from app.retrieval.service import _approved_chunk_count, _approved_chunk_row_batches


class _DirtyTextParser(DocumentParser):
    document_format = DocumentFormat.TEXT

    def parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
        return ParseResult(
            ParseStatus.READY,
            self.document_format,
            body_blocks=(
                StructuralBlock(
                    0,
                    BlockKind.PARAGRAPH,
                    "Alpha\x00Beta\x01Gamma \x91quoted\x92 \x81end",
                    heading_path=("Control\x02 heading",),
                    metadata={"unsafe\x03key": "unsafe\x04value"},
                ),
            ),
            comments=(Annotation("comment\x05one", "Explain\x06the ratio"),),
            revisions=(Revision("revision\x07one", "insert", "Added\x08qualification"),),
        )


class _RepresentationMatrixRegistry:
    def __init__(self, statuses: dict[str, ParseStatus] | None = None) -> None:
        self.statuses = statuses or {}

    def parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
        status = self.statuses.get(filename, ParseStatus.READY)
        document_format = detect_format(filename)
        if status is not ParseStatus.READY:
            return ParseResult(status, document_format)
        return ParseResult(
            ParseStatus.READY,
            document_format,
            body_blocks=(
                StructuralBlock(
                    0,
                    BlockKind.PARAGRAPH,
                    "A ready, searchable legal representation with supported analysis.",
                ),
            ),
        )


class _UnavailableOcr:
    def process(self, _pdf_bytes: bytes):
        raise OcrUnavailableError("test OCR unavailable")


def test_legislation_xml_parser_preserves_provision_locator_and_omits_metadata() -> None:
    payload = b"""<?xml version='1.0' encoding='UTF-8'?>
    <Legislation xmlns='http://www.legislation.gov.uk/namespaces/legislation'
      xmlns:dc='http://purl.org/dc/elements/1.1/'
      DocumentURI='http://www.legislation.gov.uk/ukpga/2015/15'>
      <Metadata><dc:title>Consumer Rights Act 2015</dc:title>
        <dc:modified>2026-04-15</dc:modified></Metadata>
      <Body><Part DocumentURI='http://www.legislation.gov.uk/ukpga/2015/15/part/1'>
        <Number>PART 1</Number><Title>Consumer contracts for goods</Title>
        <P1 DocumentURI='http://www.legislation.gov.uk/ukpga/2015/15/section/9'>
          <Pnumber>9</Pnumber><P1para><Text>Every contract is to be treated as including a term.</Text></P1para>
        </P1>
      </Part></Body>
    </Legislation>"""

    assert detect_format("ukpga-2015-15.xml") is DocumentFormat.XML
    parsed = ParserRegistry.default().parse(payload, filename="ukpga-2015-15.xml")

    assert parsed.status is ParseStatus.READY
    assert parsed.body_blocks[0].text == "Consumer Rights Act 2015"
    provision = next(block for block in parsed.body_blocks if block.text.startswith("section 9"))
    assert provision.metadata["legal_locator"] == "section 9"
    assert provision.source_anchor == "https://www.legislation.gov.uk/ukpga/2015/15/section/9"
    assert "2026-04-15" not in provision.text


def test_legislation_xml_parser_rejects_entity_declarations() -> None:
    payload = b"<!DOCTYPE x [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]><x>&leak;</x>"
    parsed = ParserRegistry.default().parse(payload, filename="unsafe.xml")
    assert parsed.status is ParseStatus.INVALID


def test_find_case_law_xml_parser_preserves_judgment_paragraph_locators() -> None:
    payload = b"""<?xml version='1.0' encoding='UTF-8'?>
    <akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'
      xmlns:uk='https://caselaw.nationalarchives.gov.uk/akn'>
      <judgment name='judgment'>
        <meta><identification source='#tna'>
          <FRBRWork><FRBRdate date='2024-07-09' name='judgment'/>
            <FRBRname value='Example Trustee v Example Employer'/></FRBRWork>
          <FRBRExpression>
            <FRBRthis value='https://caselaw.nationalarchives.gov.uk/ewca/civ/2024/767'/>
          </FRBRExpression>
        </identification><proprietary source='#tna'>
          <uk:cite>[2024] EWCA Civ 767</uk:cite>
          <uk:parser>private parser metadata</uk:parser>
        </proprietary></meta>
        <header><p>Private header text that is not judgment evidence.</p></header>
        <judgmentBody><decision><level eId='level_1'>
          <heading>Accrued rights</heading>
          <paragraph eId='para_1'><num>1.</num><content><p>
            Exact official paragraph text.<authorialNote>Editorial note.</authorialNote>
          </p></content></paragraph>
        </level></decision></judgmentBody>
      </judgment>
    </akomaNtoso>"""

    parsed = ParserRegistry.default().parse(payload, filename="source-deadbeef.xml")

    assert parsed.status is ParseStatus.READY
    assert parsed.body_blocks[0].text == "Example Trustee v Example Employer"
    paragraph = next(block for block in parsed.body_blocks if block.kind is BlockKind.PARAGRAPH)
    assert paragraph.text == "paragraph 1 Exact official paragraph text."
    assert paragraph.heading_path == (
        "Example Trustee v Example Employer",
        "Accrued rights",
    )
    assert paragraph.source_anchor == (
        "https://caselaw.nationalarchives.gov.uk/ewca/civ/2024/767#para_1"
    )
    assert paragraph.metadata["neutral_citation"] == "[2024] EWCA Civ 767"
    assert paragraph.metadata["judgment_date"] == "2024-07-09"
    durable = "\n".join(block.text for block in parsed.body_blocks)
    assert "Private header text" not in durable
    assert "private parser metadata" not in durable
    assert "Editorial note" not in durable


def test_find_case_law_xml_parser_rejects_untrusted_document_uri() -> None:
    payload = b"""<akomaNtoso xmlns='http://docs.oasis-open.org/legaldocml/ns/akn/3.0'>
      <judgment><meta><identification><FRBRWork>
        <FRBRname value='Unsafe'/></FRBRWork><FRBRExpression>
        <FRBRthis value='https://example.com/ewca/civ/2024/767'/>
      </FRBRExpression></identification></meta>
      <header><neutralCitation>[2024] EWCA Civ 767</neutralCitation></header>
      <judgmentBody><paragraph eId='para_1'><num>1</num><content><p>Text</p>
      </content></paragraph></judgmentBody></judgment>
    </akomaNtoso>"""

    parsed = ParserRegistry.default().parse(payload, filename="unsafe.xml")

    assert parsed.status is ParseStatus.INVALID
    assert parsed.diagnostics == ("official judgment document URI is missing or invalid",)


def _provenance() -> Provenance:
    return Provenance(
        source_identity=SourceIdentity("catalog", f"content-sha256:{'a' * 64}"),
        title="Sanitation fixture",
        source_kind="private_teaching",
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.LECTURE_NOTE,
        content_sha256="a" * 64,
        retrieved_at="2026-08-11T00:00:00+00:00",
    )


def test_forbidden_controls_are_sanitized_across_all_persistable_streams() -> None:
    parsed = ParserRegistry((_DirtyTextParser(),)).parse(b"ignored", filename="fixture.txt")

    assert parsed.body_blocks[0].text == "Alpha Beta Gamma ‘quoted’ end"
    assert parsed.comments[0].text == "Explain the ratio"
    assert parsed.revisions[0].text == "Added qualification"
    assert sanitize_parse_result(parsed) == parsed

    bundle = CanonicalMarkdownConverter().convert(parsed, _provenance())
    chunks = (
        *StructuralChunker().chunk_body(parsed, document_sha256="a" * 64),
        *StructuralChunker().chunk_comments(parsed, document_sha256="a" * 64),
        *StructuralChunker().chunk_revisions(parsed, document_sha256="a" * 64),
    )
    durable_text = "\n".join(
        (bundle.body_markdown, bundle.comments_markdown, bundle.revisions_markdown)
    )
    assert not has_forbidden_controls(durable_text)
    assert all(chunk.text.strip() and not has_forbidden_controls(chunk.text) for chunk in chunks)


def test_cp1252_c1_repairs_are_defined_deterministic_and_schema_versioned() -> None:
    contaminated = "\x80\x85\x81\x91quote\x92\x93text\x94\x96\x97\x9f"
    expected = "€… ‘quote’“text”–—Ÿ"

    assert TEXT_SANITATION_SCHEMA == "legalbot.text-sanitation.v3"
    assert SOURCE_PROCESSING_COMPONENTS["text_sanitation"] == TEXT_SANITATION_SCHEMA
    expected_fingerprint = hashlib.sha256(
        json.dumps(
            SOURCE_PROCESSING_COMPONENTS,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    assert expected_fingerprint == SOURCE_PROCESSING_FINGERPRINT
    assert sanitize_text(contaminated) == expected
    assert sanitize_text(sanitize_text(contaminated)) == expected
    assert not has_forbidden_controls(expected)
    assert has_forbidden_controls(contaminated)


def test_invisible_and_unlisted_format_controls_cannot_hide_word_boundaries() -> None:
    contaminated = (
        "data\u200bprotection co\u00adoperation law\ufeffful word\u2060ing English\u202eעברית"
    )
    expected = "data protection cooperation lawful wording English עברית"

    assert has_forbidden_controls(contaminated)
    assert sanitize_text(contaminated) == expected
    assert sanitize_text(sanitize_text(contaminated)) == expected
    assert not has_forbidden_controls(expected)


def test_control_only_ready_result_becomes_invalid_instead_of_empty_chunk() -> None:
    parsed = sanitize_parse_result(
        ParseResult(
            ParseStatus.READY,
            DocumentFormat.TEXT,
            body_blocks=(StructuralBlock(0, BlockKind.PARAGRAPH, "\x00\x01\x02"),),
        )
    )

    assert parsed.status is ParseStatus.INVALID
    assert parsed.body_blocks == ()
    assert parsed.diagnostics == ("sanitation_empty_body",)
    with pytest.raises(ValueError, match="ready documents"):
        StructuralChunker().chunk_body(parsed, document_sha256="a" * 64)


def test_jstor_access_cleanup_is_exact_bounded_and_preserves_legal_text() -> None:
    notice = (
        "This content downloaded from 192.0.2.10 on Tue, 11 Aug 2026 10:15:00 UTC "
        "All use subject to https://about.jstor.org/terms"
    )
    cleaned, removed = _strip_jstor_access_notice(
        "The ratio and remedy remain substantive.\n" + notice
    )
    assert removed is True
    assert cleaned == "The ratio and remedy remain substantive."

    unmatched = "A judgment discusses JSTOR access and its contractual terms."
    assert _strip_jstor_access_notice(unmatched) == (unmatched, False)
    oversized = (
        "This content downloaded from "
        + "x" * 641
        + " All use subject to https://about.jstor.org/terms"
    )
    assert _strip_jstor_access_notice(oversized) == (oversized, False)
    middle = "A" * 1_100 + notice + "B" * 1_100
    assert _strip_jstor_access_notice(middle) == (middle, False)


def test_processing_change_creates_sanitized_immutable_successor_and_is_idempotent(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "note.md"
    source.write_text(
        "# Doctrine\n\nThe real\x00 legal \x91quoted\x92 proposition remains.",
        encoding="utf-8",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)

    calls = 0
    original_parse = ParserRegistry.parse

    def counting_parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
        nonlocal calls
        calls += 1
        return original_parse(self, data, filename=filename, aliaser=aliaser)

    monkeypatch.setattr(ParserRegistry, "parse", counting_parse)
    scan_configured_sources(settings, database, cipher, "sanitation-v1")
    predecessor = database.fetchone("SELECT id FROM source_versions")
    assert predecessor is not None
    predecessor_id = str(predecessor["id"])
    dirty_text = "The historical\x00 contaminated chunk remains immutable."
    database.execute(
        "UPDATE chunks SET markdown_text=?, text_sha256=? WHERE source_version_id=?",
        (dirty_text, hashlib.sha256(dirty_text.encode()).hexdigest(), predecessor_id),
    )
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?", (predecessor_id,)
    )
    database.execute(
        "UPDATE reviews SET status='approved' WHERE review_type='source_version' AND target_id=?",
        (predecessor_id,),
    )

    next_fingerprint = "b" * 64
    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", next_fingerprint)
    scan_configured_sources(settings, database, cipher, "sanitation-v2")

    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 2
    predecessor = next(row for row in versions if row["id"] == predecessor_id)
    successor = next(row for row in versions if row["id"] != predecessor_id)
    assert predecessor["review_status"] == "approved"
    assert predecessor["superseded_by"] == successor["id"]
    assert predecessor["version_sha256"] == successor["version_sha256"]
    assert successor["processing_fingerprint"] == next_fingerprint
    assert successor["review_status"] == "staged"
    assert _approved_chunk_count(database) == 0
    assert (
        database.fetchone(
            "SELECT markdown_text FROM chunks WHERE source_version_id=?", (predecessor_id,)
        )["markdown_text"]
        == dirty_text
    )

    current_chunks = database.fetchall(
        "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal", (successor["id"],)
    )
    assert current_chunks
    for chunk in current_chunks:
        text = str(chunk["markdown_text"])
        assert text.strip() and not has_forbidden_controls(text)
        assert chunk["text_sha256"] == hashlib.sha256(text.encode()).hexdigest()
        assert chunk["token_count"] == len(re.findall(r"\b[\w'-]+\b", text))
        assert chunk["token_count"] > 0
    metadata = json.loads(successor["metadata_json"])
    assert metadata["selected_chunk_count"] == len(current_chunks)
    assert metadata["processing_fingerprint"] == next_fingerprint
    canonical_path = settings.project_root / successor["canonical_markdown_path"]
    assert not has_forbidden_controls(canonical_path.read_text(encoding="utf-8"))

    stable_snapshot = [tuple(row) for row in current_chunks]
    calls_before_idempotent_scan = calls
    scan_configured_sources(settings, database, cipher, "sanitation-v2-repeat")
    assert calls == calls_before_idempotent_scan
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 2
    assert [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (successor["id"],),
        )
    ] == stable_snapshot


def test_processing_successor_closes_predecessor_pending_review(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    (law / "review.md").write_text("# Doctrine\n\nA supported proposition.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "review-predecessor")
    predecessor = database.fetchone("SELECT id FROM source_versions")
    assert predecessor is not None

    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", "c" * 64)
    scan_configured_sources(settings, database, cipher, "review-successor")

    predecessor_review = database.fetchone(
        "SELECT * FROM reviews WHERE review_type='source_version' AND target_id=?",
        (predecessor["id"],),
    )
    assert predecessor_review is not None
    assert predecessor_review["status"] == "rejected"
    assert predecessor_review["reason"] == (
        "Processing representation superseded; review the current successor"
    )
    assert predecessor_review["decision_note"] == (
        "Superseded by a newer processing representation"
    )
    current_pending = database.fetchall(
        """
        SELECT r.target_id FROM reviews r
        JOIN source_versions sv ON sv.id=r.target_id
        WHERE r.review_type='source_version' AND r.status='pending'
          AND sv.superseded_by IS NULL
        """
    )
    assert len(current_pending) == 1


def test_processing_fingerprint_downgrade_is_refused_without_supersession_cycle(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    (law / "rollback.md").write_text(
        "# Doctrine\n\nA processing-lineage proposition.", encoding="utf-8"
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    fingerprint_a = service.SOURCE_PROCESSING_FINGERPRINT
    fingerprint_b = "d" * 64

    scan_configured_sources(settings, database, cipher, "fingerprint-a")
    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", fingerprint_b)
    scan_configured_sources(settings, database, cipher, "fingerprint-b")
    snapshot = [
        tuple(row)
        for row in database.fetchall(
            "SELECT id, processing_fingerprint, superseded_by FROM source_versions ORDER BY id"
        )
    ]

    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", fingerprint_a)
    rollback = scan_configured_sources(settings, database, cipher, "fingerprint-a-downgrade")
    assert rollback["status"] == "complete"
    assert rollback["statuses"].get("quarantined") == 1

    rows = database.fetchall(
        "SELECT id, processing_fingerprint, superseded_by FROM source_versions ORDER BY id"
    )
    assert [tuple(row) for row in rows] == snapshot
    assert sum(row["superseded_by"] is None for row in rows) == 1
    by_id = {str(row["id"]): row for row in rows}
    for start in by_id:
        seen: set[str] = set()
        current: str | None = start
        while current is not None:
            assert current not in seen
            seen.add(current)
            successor = by_id[current]["superseded_by"]
            current = str(successor) if successor is not None else None
    assert database.fetchall("PRAGMA foreign_key_check") == []
    completed_scan = database.fetchone(
        "SELECT status, error_code FROM source_scans WHERE id='fingerprint-a-downgrade'"
    )
    assert completed_scan is not None
    assert completed_scan["status"] == "complete"
    assert completed_scan["error_code"] is None
    scan_files = database.source_scan_files("fingerprint-a-downgrade")
    assert any(
        row["status"] == "quarantined" and row["reason"] == "processing_policy_rollback_refused"
        for row in scan_files
    )


def test_rollback_refused_file_does_not_abort_a_multi_file_scan(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    (law / "rollback.md").write_text("# Rollback\n\nKept current lineage.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    fingerprint_a = service.SOURCE_PROCESSING_FINGERPRINT
    fingerprint_b = "d" * 64

    scan_configured_sources(settings, database, cipher, "multi-a")
    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", fingerprint_b)
    scan_configured_sources(settings, database, cipher, "multi-b")
    (law / "keep.md").write_text("# Keep\n\nA later independent file.", encoding="utf-8")
    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", fingerprint_a)
    result = scan_configured_sources(settings, database, cipher, "multi-rollback")
    assert result["status"] == "complete"
    assert result["files_accounted"] == result.get("files_accounted")
    accounted = database.fetchone(
        "SELECT expected_file_count, files_accounted, status FROM source_scans WHERE id='multi-rollback'"
    )
    assert accounted is not None
    assert accounted["status"] == "complete"
    assert int(accounted["expected_file_count"]) == int(accounted["files_accounted"]) == 2
    assert result["statuses"].get("quarantined") == 1
    files = database.source_scan_files("multi-rollback")
    assert sum(row["reason"] == "processing_policy_rollback_refused" for row in files) == 1
    assert any(row["status"] != "quarantined" for row in files)


def test_raw_content_revision_supersedes_approved_predecessor_for_same_path(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "revision.md"
    source.write_text("# Version A\n\nThe original proposition.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(settings, database, cipher, "raw-revision-a")
    predecessor = database.fetchone(
        """
        SELECT sv.*, d.representation_group_id, d.content_sha256 AS document_sha256
        FROM source_versions sv JOIN documents d ON d.id=sv.document_id
        """
    )
    assert predecessor is not None
    predecessor_id = str(predecessor["id"])
    representation_group = str(predecessor["representation_group_id"])
    predecessor_chunks = [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (predecessor_id,),
        )
    ]
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?",
        (predecessor_id,),
    )
    database.execute(
        "UPDATE reviews SET status='approved' WHERE review_type='source_version' AND target_id=?",
        (predecessor_id,),
    )
    assert _approved_chunk_count(database) > 0

    source.write_text("# Version B\n\nThe revised and current proposition.", encoding="utf-8")
    scan_configured_sources(settings, database, cipher, "raw-revision-b")

    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 2
    predecessor = next(row for row in versions if row["id"] == predecessor_id)
    successor = next(row for row in versions if row["id"] != predecessor_id)
    assert predecessor["review_status"] == "approved"
    assert predecessor["superseded_by"] == successor["id"]
    assert successor["review_status"] == "staged"
    assert successor["superseded_by"] is None
    assert sum(row["superseded_by"] is None for row in versions) == 1
    assert _approved_chunk_count(database) == 0
    assert list(_approved_chunk_row_batches(database)) == []
    assert (
        database.fetchone(
            """
            SELECT COUNT(*) AS n FROM reviews
            WHERE review_type='source_version' AND target_id=? AND status='pending'
            """,
            (successor["id"],),
        )["n"]
        == 1
    )
    assert [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (predecessor_id,),
        )
    ] == predecessor_chunks
    successor_text = " ".join(
        str(row["markdown_text"])
        for row in database.fetchall(
            "SELECT markdown_text FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (successor["id"],),
        )
    )
    assert "revised and current proposition" in successor_text
    assert "original proposition" not in successor_text

    document = database.fetchone("SELECT * FROM documents")
    assert document is not None
    assert database.fetchone("SELECT COUNT(*) AS n FROM documents")["n"] == 1
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_aliases")["n"] == 1
    assert document["content_sha256"] == successor["version_sha256"]
    assert document["representation_group_id"] == representation_group
    assert document["dedupe_status"] == "duplicate_identity"
    assert document["duplicate_of"] is None
    assert document["retrieval_canonical"] == 1
    assert database.fetchall("PRAGMA foreign_key_check") == []

    version_snapshot = [tuple(row) for row in versions]
    successor_chunk_snapshot = [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (successor["id"],),
        )
    ]
    scan_configured_sources(settings, database, cipher, "raw-revision-b-repeat")
    assert [
        tuple(row)
        for row in database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    ] == version_snapshot
    assert [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (successor["id"],),
        )
    ] == successor_chunk_snapshot


def test_processing_policy_rollback_is_refused_across_raw_content_hashes(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "cross-content-rollback.md"
    source.write_text("# Version A\n\nOriginal content.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    policy_one = service.SOURCE_PROCESSING_FINGERPRINT
    policy_two = "e" * 64

    scan_configured_sources(settings, database, cipher, "policy-one-a")
    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", policy_two)
    scan_configured_sources(settings, database, cipher, "policy-two-a")
    source.write_text("# Version B\n\nNew raw content.", encoding="utf-8")
    scan_configured_sources(settings, database, cipher, "policy-two-b")
    before_versions = [
        tuple(row)
        for row in database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    ]
    before_document = tuple(database.fetchone("SELECT * FROM documents"))
    before_chunks = [tuple(row) for row in database.fetchall("SELECT * FROM chunks ORDER BY id")]

    monkeypatch.setattr(service, "SOURCE_PROCESSING_FINGERPRINT", policy_one)
    rollback = scan_configured_sources(settings, database, cipher, "policy-one-b-rollback")
    assert rollback["status"] == "complete"
    assert rollback["statuses"].get("quarantined") == 1

    assert [
        tuple(row)
        for row in database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    ] == before_versions
    assert tuple(database.fetchone("SELECT * FROM documents")) == before_document
    assert [
        tuple(row) for row in database.fetchall("SELECT * FROM chunks ORDER BY id")
    ] == before_chunks
    current = database.fetchone("SELECT * FROM source_versions WHERE superseded_by IS NULL")
    assert current is not None
    assert current["processing_fingerprint"] == policy_two
    assert database.fetchall("PRAGMA foreign_key_check") == []


def test_ready_content_can_return_as_distinct_staged_restoration_occurrence(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "content-restoration.md"
    original = b"# Version A\n\nThe originally approved proposition."
    source.write_bytes(original)
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(settings, database, cipher, "content-a")
    predecessor = database.fetchone("SELECT * FROM source_versions")
    assert predecessor is not None
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?",
        (predecessor["id"],),
    )
    source.write_text("# Version B\n\nA different current proposition.", encoding="utf-8")
    scan_configured_sources(settings, database, cipher, "content-b")

    source.write_bytes(original)
    scan_configured_sources(settings, database, cipher, "content-a-restored")
    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 3
    current = [row for row in versions if row["superseded_by"] is None]
    assert len(current) == 1
    restoration = current[0]
    assert restoration["id"] != predecessor["id"]
    assert restoration["version_sha256"] == predecessor["version_sha256"]
    assert restoration["review_status"] == "staged"
    restoration_metadata = json.loads(restoration["metadata_json"])
    assert restoration_metadata["content_restoration_occurrence_schema"] == (
        "legalbot.content-restoration-occurrence.v1"
    )
    assert restoration_metadata["content_restoration_from_source_version_id"] != (predecessor["id"])
    assert (
        next(row for row in versions if row["id"] == predecessor["id"])["review_status"]
        == "approved"
    )
    document = database.fetchone("SELECT content_sha256, status FROM documents")
    assert document["content_sha256"] == restoration["version_sha256"]
    assert document["status"] == "private_teaching"
    assert _approved_chunk_count(database) == 0
    _assert_acyclic_source_versions(versions)
    assert database.fetchall("PRAGMA foreign_key_check") == []

    snapshot = [tuple(row) for row in versions]
    scan_configured_sources(settings, database, cipher, "content-a-restored-repeat")
    assert [
        tuple(row)
        for row in database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    ] == snapshot


def test_exact_duplicate_is_re_elected_when_former_canonical_changes_content(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    first = law / "a.md"
    second = law / "b.md"
    original = b"# Shared source\n\nThe original duplicate proposition."
    first.write_bytes(original)
    second.write_bytes(original)
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "duplicates-a")

    canonical = database.fetchone("SELECT id FROM documents WHERE duplicate_of IS NULL")
    assert canonical is not None
    canonical_id = str(canonical["id"])
    first_document = database.fetchone(
        "SELECT document_id FROM source_aliases WHERE path_fingerprint=?",
        (service._path_fingerprint(first),),
    )
    assert first_document is not None
    canonical_path = first if first_document["document_id"] == canonical_id else second
    canonical_version = database.fetchone(
        "SELECT id FROM source_versions WHERE document_id=?", (canonical_id,)
    )
    assert canonical_version is not None
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?",
        (canonical_version["id"],),
    )
    database.execute(
        "UPDATE reviews SET status='approved' WHERE target_id=?",
        (canonical_version["id"],),
    )

    canonical_path.write_text(
        "# Revised source\n\nA materially different proposition.", encoding="utf-8"
    )
    scan_configured_sources(settings, database, cipher, "duplicates-b")
    documents = database.fetchall("SELECT * FROM documents ORDER BY id")
    assert len(documents) == 2
    assert len({row["content_sha256"] for row in documents}) == 2
    assert all(row["duplicate_of"] is None for row in documents)
    assert all(row["status"] == "private_teaching" for row in documents)
    assert all(row["retrieval_canonical"] == 1 for row in documents)
    assert (
        database.fetchone(
            """
            SELECT COUNT(*) AS n FROM documents child
            JOIN documents parent ON parent.id=child.duplicate_of
            WHERE child.content_sha256<>parent.content_sha256
            """
        )["n"]
        == 0
    )
    old_sha_document = next(
        row for row in documents if row["content_sha256"] == hashlib.sha256(original).hexdigest()
    )
    old_sha_version = database.fetchone(
        """
        SELECT sv.id, sv.review_status, r.status AS review_state
        FROM source_versions sv
        LEFT JOIN reviews r
          ON r.target_id=sv.id AND r.review_type='source_version'
        WHERE sv.document_id=? AND sv.superseded_by IS NULL
        """,
        (old_sha_document["id"],),
    )
    assert old_sha_version is not None
    assert old_sha_version["review_status"] == "staged"
    assert old_sha_version["review_state"] == "pending"
    assert _approved_chunk_count(database) == 0
    assert database.fetchall("PRAGMA foreign_key_check") == []


@pytest.mark.parametrize(
    ("first_name", "second_name", "expected_ready_name"),
    (
        ("a.tmp", "b.md", "b.md"),
        ("a.md", "b.tmp", "a.md"),
        (".DS_Store", "b.md", "b.md"),
        ("a.bin", "b.md", "b.md"),
        ("a.pdf", "b.md", "b.md"),
    ),
)
def test_exact_dedupe_prefers_ready_searchable_representation_in_any_order(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
    first_name: str,
    second_name: str,
    expected_ready_name: str,
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    payload = b"# Valid source\n\nA proposition available in a supported representation."
    first = law / first_name
    second = law / second_name
    first.write_bytes(payload)
    second.write_bytes(payload)
    expected_ready = law / expected_ready_name
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(settings, database, cipher, "readiness-election")
    expected_alias = database.fetchone(
        "SELECT document_id FROM source_aliases WHERE path_fingerprint=?",
        (service._path_fingerprint(expected_ready),),
    )
    assert expected_alias is not None
    canonical = database.fetchone("SELECT * FROM documents WHERE duplicate_of IS NULL")
    assert canonical is not None
    assert canonical["id"] == expected_alias["document_id"]
    assert canonical["status"] == "private_teaching"
    assert canonical["searchable_text"] == 1
    assert canonical["retrieval_canonical"] == 1
    duplicate = database.fetchone("SELECT * FROM documents WHERE duplicate_of IS NOT NULL")
    assert duplicate is not None
    assert duplicate["duplicate_of"] == canonical["id"]
    assert duplicate["content_sha256"] == canonical["content_sha256"]
    assert duplicate["retrieval_canonical"] == 0

    source_version = database.fetchone(
        "SELECT * FROM source_versions WHERE document_id=? AND superseded_by IS NULL",
        (canonical["id"],),
    )
    assert source_version is not None
    assert source_version["review_status"] == "staged"
    assert (
        database.fetchone(
            """
            SELECT COUNT(*) AS n FROM reviews
            WHERE review_type='source_version' AND target_id=? AND status='pending'
            """,
            (source_version["id"],),
        )["n"]
        == 1
    )
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM chunks WHERE source_version_id=?",
            (source_version["id"],),
        )["n"]
        > 0
    )
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 1
    assert database.fetchall("PRAGMA foreign_key_check") == []

    document_snapshot = [
        tuple(row)
        for row in database.fetchall(
            """
            SELECT id, content_sha256, status, duplicate_of,
                   retrieval_canonical, searchable_text
            FROM documents ORDER BY id
            """
        )
    ]
    version_snapshot = [
        tuple(row) for row in database.fetchall("SELECT * FROM source_versions ORDER BY id")
    ]
    scan_configured_sources(settings, database, cipher, "readiness-election-repeat")
    assert [
        tuple(row)
        for row in database.fetchall(
            """
            SELECT id, content_sha256, status, duplicate_of,
                   retrieval_canonical, searchable_text
            FROM documents ORDER BY id
            """
        )
    ] == document_snapshot
    assert [
        tuple(row) for row in database.fetchall("SELECT * FROM source_versions ORDER BY id")
    ] == version_snapshot


@pytest.mark.parametrize(
    ("first_folder", "second_folder", "expected_lane", "expected_status"),
    (
        ("A Exam feedback", "Z Cases", "primary_authority", "citable"),
        ("A Cases", "Z Exam feedback", "primary_authority", "citable"),
        ("A Exam feedback", "Z Lectures", "private_teaching", "private_teaching"),
        ("A Lectures", "Z Exam feedback", "private_teaching", "private_teaching"),
        ("A Lectures", "Z Cases", "primary_authority", "citable"),
        ("A Cases", "Z Lectures", "primary_authority", "citable"),
    ),
)
def test_exact_dedupe_preserves_each_semantic_lane_partition(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
    first_folder: str,
    second_folder: str,
    expected_lane: str,
    expected_status: str,
) -> None:
    law = tmp_path / "Law"
    first = law / first_folder
    second = law / second_folder
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    payload = "# Shared text\n\nThis identical content has no independent classification signals."
    (first / "copy.md").write_text(payload, encoding="utf-8")
    (second / "copy.md").write_text(payload, encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(settings, database, cipher, "cross-lane-exact")
    documents = database.fetchall("SELECT * FROM documents ORDER BY created_at, id")
    assert len(documents) == 2
    assert len({row["content_sha256"] for row in documents}) == 1
    assert all(row["duplicate_of"] is None for row in documents)
    assert all(row["retrieval_canonical"] == 1 for row in documents)
    overview = database.admin_overview()
    assert overview["exact_duplicates"] == 1
    assert overview["logical_exact_duplicates"] == 0
    expected = next(row for row in documents if row["lane"] == expected_lane)
    assert expected["status"] == expected_status
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 2
    for document in documents:
        current_version = database.fetchone(
            "SELECT id FROM source_versions WHERE document_id=? AND superseded_by IS NULL",
            (document["id"],),
        )
        assert current_version is not None
        chunk_count = database.fetchone(
            "SELECT COUNT(*) AS n FROM chunks WHERE source_version_id=?",
            (current_version["id"],),
        )["n"]
        if document["lane"] == "assessment_guidance":
            assert chunk_count == 0
        else:
            assert chunk_count > 0
        assert (
            database.fetchone(
                """
                SELECT COUNT(*) AS n FROM reviews
                WHERE review_type='source_version' AND target_id=? AND status='pending'
                """,
                (current_version["id"],),
            )["n"]
            == 1
        )
    assert database.fetchall("PRAGMA foreign_key_check") == []


@pytest.mark.parametrize(
    ("first_folder", "second_folder", "partition_column", "expected_values"),
    (
        (
            "A Contract law Cases",
            "Z Tort law Cases",
            "subject_primary",
            {"contract", "tort"},
        ),
        (
            "A Tort law Cases",
            "Z Contract law Cases",
            "subject_primary",
            {"contract", "tort"},
        ),
        (
            "A Scotland Cases",
            "Z USA Cases",
            "jurisdiction",
            {"Scotland", "United States"},
        ),
        (
            "A USA Cases",
            "Z Scotland Cases",
            "jurisdiction",
            {"Scotland", "United States"},
        ),
    ),
)
def test_exact_dedupe_partitions_subject_and_jurisdiction_in_both_orders(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
    first_folder: str,
    second_folder: str,
    partition_column: str,
    expected_values: set[str],
) -> None:
    law = tmp_path / "Law"
    for folder in (first_folder, second_folder):
        path = law / folder
        path.mkdir(parents=True)
        (path / "copy.md").write_text(
            "# Shared source\n\nThe same bytes require distinct hard routing.",
            encoding="utf-8",
        )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(settings, database, cipher, "semantic-hard-routing")
    documents = database.fetchall("SELECT * FROM documents ORDER BY id")
    assert len(documents) == 2
    assert {str(row[partition_column]) for row in documents} == expected_values
    assert len({row["content_sha256"] for row in documents}) == 1
    assert all(row["lane"] == "primary_authority" for row in documents)
    assert all(row["duplicate_of"] is None for row in documents)
    assert all(row["retrieval_canonical"] == 1 for row in documents)
    assert database.fetchone("SELECT COUNT(*) AS n FROM reviews WHERE status='pending'")["n"] == 2
    assert database.fetchall("PRAGMA foreign_key_check") == []


def test_representation_move_re_elects_canonical_in_old_and_new_groups(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "journals"
    law.mkdir(parents=True)
    first = law / "alpha.md"
    second = law / "beta.md"
    doi = "10.1234/legalbot.matrix"
    first.write_text(
        f"# First article\n\nAbstract\n\nFirst representation. DOI {doi}.",
        encoding="utf-8",
    )
    second.write_text(
        f"# Second article\n\nAbstract\n\nSecond representation. DOI {doi}.",
        encoding="utf-8",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "representation-a")
    initial = database.fetchall("SELECT * FROM documents ORDER BY id")
    assert len({row["representation_group_id"] for row in initial}) == 1
    winner_id = next(str(row["id"]) for row in initial if row["retrieval_canonical"])
    first_document = database.fetchone(
        "SELECT document_id FROM source_aliases WHERE path_fingerprint=?",
        (service._path_fingerprint(first),),
    )
    assert first_document is not None
    winner_path = first if first_document["document_id"] == winner_id else second
    winner_path.write_text(
        "# Revised local note\n\nThis revision has no former public identifier.",
        encoding="utf-8",
    )

    scan_configured_sources(settings, database, cipher, "representation-b")
    groups = database.fetchall(
        """
        SELECT representation_group_id, COUNT(*) AS docs,
               SUM(retrieval_canonical) AS canonicals
        FROM documents WHERE duplicate_of IS NULL
        GROUP BY representation_group_id ORDER BY representation_group_id
        """
    )
    assert len(groups) == 2
    assert all(row["docs"] == 1 and row["canonicals"] == 1 for row in groups)
    assert database.fetchall("PRAGMA foreign_key_check") == []


@pytest.mark.parametrize("target_suffix", ("pdf", "docx", "md"))
@pytest.mark.parametrize(
    ("nonready_status", "expected_document_status"),
    (
        (ParseStatus.UNSUPPORTED, "unsupported"),
        (ParseStatus.ENCRYPTED, "encrypted"),
        (ParseStatus.OCR_REQUIRED, "ocr_required"),
        (ParseStatus.INVALID, "quarantined"),
    ),
)
def test_representation_group_never_prefers_nonready_over_ready_source(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
    target_suffix: str,
    nonready_status: ParseStatus,
    expected_document_status: str,
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    names = ("source.pdf", "source.docx", "source.md")
    for ordinal, name in enumerate(names):
        (law / name).write_bytes(f"ready representation {ordinal}".encode())
    registry = _RepresentationMatrixRegistry()
    monkeypatch.setattr(ParserRegistry, "default", classmethod(lambda _cls: registry))
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(
        settings,
        database,
        cipher,
        "representations-ready",
        ocr_processor=_UnavailableOcr(),
    )
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE superseded_by IS NULL"
    )
    database.execute("UPDATE reviews SET status='approved' WHERE review_type='source_version'")

    target_name = f"source.{target_suffix}"
    target_path = law / target_name
    target_path.write_bytes(f"now {nonready_status.value}".encode())
    registry.statuses[target_name] = nonready_status
    scan_configured_sources(
        settings,
        database,
        cipher,
        "representation-nonready",
        ocr_processor=_UnavailableOcr(),
    )

    target_alias = database.fetchone(
        "SELECT document_id FROM source_aliases WHERE path_fingerprint=?",
        (service._path_fingerprint(target_path),),
    )
    assert target_alias is not None
    target = database.fetchone("SELECT * FROM documents WHERE id=?", (target_alias["document_id"],))
    assert target is not None
    assert target["status"] == expected_document_status
    assert target["retrieval_canonical"] == 0
    canonicals = database.fetchall(
        "SELECT * FROM documents WHERE duplicate_of IS NULL AND retrieval_canonical=1"
    )
    assert len(canonicals) == 1
    assert canonicals[0]["status"] in {
        "citable",
        "private_teaching",
        "assessment_guidance",
    }
    assert canonicals[0]["searchable_text"] == 1
    assert _approved_chunk_count(database) > 0
    assert database.fetchall("PRAGMA foreign_key_check") == []

    stable_documents = [
        tuple(row)
        for row in database.fetchall(
            """
            SELECT id, content_sha256, status, duplicate_of,
                   retrieval_canonical, searchable_text
            FROM documents ORDER BY id
            """
        )
    ]
    scan_configured_sources(
        settings,
        database,
        cipher,
        "representation-nonready-repeat",
        ocr_processor=_UnavailableOcr(),
    )
    assert [
        tuple(row)
        for row in database.fetchall(
            """
            SELECT id, content_sha256, status, duplicate_of,
                   retrieval_canonical, searchable_text
            FROM documents ORDER BY id
            """
        )
    ] == stable_documents


def test_all_nonready_representation_group_has_one_deterministic_fallback(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    statuses = {
        "source.pdf": ParseStatus.OCR_REQUIRED,
        "source.docx": ParseStatus.ENCRYPTED,
        "source.md": ParseStatus.UNSUPPORTED,
        "source.txt": ParseStatus.INVALID,
    }
    for name in statuses:
        (law / name).write_bytes(f"nonready {name}".encode())
    registry = _RepresentationMatrixRegistry(statuses)
    monkeypatch.setattr(ParserRegistry, "default", classmethod(lambda _cls: registry))
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(
        settings,
        database,
        cipher,
        "all-representations-nonready",
        ocr_processor=_UnavailableOcr(),
    )
    documents = database.fetchall("SELECT * FROM documents ORDER BY id")
    assert len(documents) == 4
    canonicals = [row for row in documents if row["retrieval_canonical"]]
    assert len(canonicals) == 1
    assert canonicals[0]["status"] == "ocr_required"
    assert all(row["duplicate_of"] is None for row in documents)
    assert database.fetchall("PRAGMA foreign_key_check") == []


def test_unreadable_raw_revision_gets_nonretrievable_lineage_tombstone(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "unreadable-revision.md"
    source.write_text("# Version A\n\nThe approved original.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "unreadable-a")
    predecessor = database.fetchone("SELECT id FROM source_versions")
    assert predecessor is not None
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?",
        (predecessor["id"],),
    )

    unreadable = b"\xff\xfe\x00\x01"
    source.write_bytes(unreadable)
    scan_configured_sources(settings, database, cipher, "unreadable-b")
    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 2
    historical = next(row for row in versions if row["id"] == predecessor["id"])
    tombstone = next(row for row in versions if row["id"] != predecessor["id"])
    assert historical["superseded_by"] == tombstone["id"]
    assert tombstone["superseded_by"] is None
    assert tombstone["review_status"] == "rejected"
    assert tombstone["version_sha256"] == hashlib.sha256(unreadable).hexdigest()
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM chunks WHERE source_version_id=?",
            (tombstone["id"],),
        )["n"]
        == 0
    )
    document = database.fetchone("SELECT content_sha256, status FROM documents")
    assert document["content_sha256"] == tombstone["version_sha256"]
    assert document["status"] == "quarantined"
    assert _approved_chunk_count(database) == 0

    source.write_text("# Version C\n\nA later readable revision.", encoding="utf-8")
    scan_configured_sources(settings, database, cipher, "unreadable-c")
    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 3
    current = [row for row in versions if row["superseded_by"] is None]
    assert len(current) == 1
    assert current[0]["review_status"] == "staged"
    assert (
        current[0]["version_sha256"]
        == database.fetchone("SELECT content_sha256 FROM documents")["content_sha256"]
    )
    assert tombstone["id"] in {
        row["id"] for row in versions if row["superseded_by"] == current[0]["id"]
    }
    assert historical["id"] not in {row["id"] for row in current}
    assert _approved_chunk_count(database) == 0
    assert database.fetchall("PRAGMA foreign_key_check") == []


@pytest.mark.parametrize(
    ("failure_mode", "expected_reason"),
    (("symlink", "symlink_not_followed"), ("permission", "restricted_access")),
)
def test_transient_pre_read_failure_restores_as_new_staged_occurrence(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
    expected_reason: str,
) -> None:
    import app.ingestion.service as service

    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "transient.md"
    original = b"# Doctrine\n\nThe reviewed source is restored unchanged."
    source.write_bytes(original)
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)

    scan_configured_sources(settings, database, cipher, f"{failure_mode}-ready-a")
    predecessor = database.fetchone("SELECT * FROM source_versions")
    assert predecessor is not None
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?",
        (predecessor["id"],),
    )
    database.execute("UPDATE reviews SET status='approved' WHERE target_id=?", (predecessor["id"],))
    assert _approved_chunk_count(database) > 0

    if failure_mode == "symlink":
        outside = tmp_path / "outside.md"
        outside.write_bytes(original)
        source.unlink()
        source.symlink_to(outside)
        scan_configured_sources(settings, database, cipher, f"{failure_mode}-unavailable-b")
        source.unlink()
        source.write_bytes(original)
    else:
        original_put_file = service._put_file

        def restricted_read(*_args, **_kwargs):
            raise PermissionError("fixture read denied")

        monkeypatch.setattr(service, "_put_file", restricted_read)
        scan_configured_sources(settings, database, cipher, f"{failure_mode}-unavailable-b")
        monkeypatch.setattr(service, "_put_file", original_put_file)

    unavailable_manifest = database.source_scan_files(f"{failure_mode}-unavailable-b")
    assert len(unavailable_manifest) == 1
    assert unavailable_manifest[0]["status"] == "quarantined"
    assert unavailable_manifest[0]["reason"] == expected_reason
    document = database.fetchone("SELECT * FROM documents")
    assert document is not None and document["status"] == "quarantined"
    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 2
    tombstone = next(row for row in versions if row["superseded_by"] is None)
    assert tombstone["review_status"] == "rejected"
    assert json.loads(tombstone["metadata_json"])["availability_tombstone"] is True
    assert predecessor["id"] != tombstone["id"]
    assert (
        next(row for row in versions if row["id"] == predecessor["id"])["superseded_by"]
        == tombstone["id"]
    )
    assert _approved_chunk_count(database) == 0

    restored = scan_configured_sources(settings, database, cipher, f"{failure_mode}-restored-a")
    assert restored["statuses"] == {"private_teaching": 1}
    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 3
    current = [row for row in versions if row["superseded_by"] is None]
    assert len(current) == 1
    recovery = current[0]
    assert recovery["id"] not in {predecessor["id"], tombstone["id"]}
    assert recovery["version_sha256"] == hashlib.sha256(original).hexdigest()
    assert recovery["review_status"] == "staged"
    assert recovery["processing_fingerprint"] != predecessor["processing_fingerprint"]
    recovery_metadata = json.loads(recovery["metadata_json"])
    assert recovery_metadata["recovery_occurrence_schema"] == ("legalbot.recovery-occurrence.v1")
    assert recovery_metadata["recovery_from_source_version_id"] == tombstone["id"]
    assert tombstone["id"] in {
        row["id"] for row in versions if row["superseded_by"] == recovery["id"]
    }
    document = database.fetchone("SELECT * FROM documents")
    assert document["content_sha256"] == recovery["version_sha256"]
    assert document["status"] == "private_teaching"
    assert document["retrieval_canonical"] == 1
    assert _approved_chunk_count(database) == 0
    assert list(_approved_chunk_row_batches(database)) == []
    assert (
        database.fetchone(
            """
            SELECT COUNT(*) AS n FROM reviews
            WHERE review_type='source_version' AND target_id=? AND status='pending'
            """,
            (recovery["id"],),
        )["n"]
        == 1
    )
    restore_manifest = database.source_scan_files(f"{failure_mode}-restored-a")
    assert len(restore_manifest) == 1
    assert restore_manifest[0]["status"] == "private_teaching"
    assert restore_manifest[0]["reason"] is None
    assert restore_manifest[0]["content_sha256"] == recovery["version_sha256"]
    serialized_metadata = json.dumps(
        [json.loads(row["metadata_json"]) for row in versions], sort_keys=True
    )
    assert str(tmp_path) not in serialized_metadata
    _assert_acyclic_source_versions(versions)
    assert database.fetchall("PRAGMA foreign_key_check") == []

    version_snapshot = [tuple(row) for row in versions]
    chunk_snapshot = [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (recovery["id"],),
        )
    ]
    scan_configured_sources(settings, database, cipher, f"{failure_mode}-restored-repeat")
    assert [
        tuple(row)
        for row in database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    ] == version_snapshot
    assert [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal",
            (recovery["id"],),
        )
    ] == chunk_snapshot

    if failure_mode == "symlink":
        outside = tmp_path / "outside-again.md"
        outside.write_bytes(original)
        source.unlink()
        source.symlink_to(outside)
        scan_configured_sources(settings, database, cipher, "symlink-unavailable-again")
        source.unlink()
        source.write_bytes(original)
        scan_configured_sources(settings, database, cipher, "symlink-restored-again")
        repeated_versions = database.fetchall(
            "SELECT * FROM source_versions ORDER BY created_at, id"
        )
        assert len(repeated_versions) == 5
        repeated_current = [row for row in repeated_versions if row["superseded_by"] is None]
        assert len(repeated_current) == 1
        assert repeated_current[0]["review_status"] == "staged"
        assert repeated_current[0]["version_sha256"] == hashlib.sha256(original).hexdigest()
        assert _approved_chunk_count(database) == 0
        _assert_acyclic_source_versions(repeated_versions)
        assert database.fetchall("PRAGMA foreign_key_check") == []


def test_parser_unavailable_revision_can_restore_exact_prior_bytes_without_approval(
    tmp_path: Path, database, cipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "parser-recovery.md"
    original = b"# Version A\n\nThe reviewed original proposition."
    source.write_bytes(original)
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "parser-recovery-a")
    predecessor = database.fetchone("SELECT * FROM source_versions")
    assert predecessor is not None
    database.execute(
        "UPDATE source_versions SET review_status='approved' WHERE id=?",
        (predecessor["id"],),
    )

    source.write_bytes(b"\xff\xfe\x00\x01")
    scan_configured_sources(settings, database, cipher, "parser-recovery-unavailable")
    tombstone = database.fetchone("SELECT * FROM source_versions WHERE superseded_by IS NULL")
    assert tombstone is not None and tombstone["review_status"] == "rejected"

    source.write_bytes(original)
    scan_configured_sources(settings, database, cipher, "parser-recovery-restored")
    versions = database.fetchall("SELECT * FROM source_versions ORDER BY created_at, id")
    assert len(versions) == 3
    current = [row for row in versions if row["superseded_by"] is None]
    assert len(current) == 1
    recovery = current[0]
    assert recovery["version_sha256"] == predecessor["version_sha256"]
    assert recovery["id"] != predecessor["id"]
    assert recovery["review_status"] == "staged"
    assert (
        json.loads(recovery["metadata_json"])["recovery_from_source_version_id"] == tombstone["id"]
    )
    document = database.fetchone("SELECT content_sha256, status FROM documents")
    assert document["content_sha256"] == recovery["version_sha256"]
    assert document["status"] == "private_teaching"
    assert _approved_chunk_count(database) == 0
    _assert_acyclic_source_versions(versions)
    assert database.fetchall("PRAGMA foreign_key_check") == []


def _assert_acyclic_source_versions(versions) -> None:
    by_id = {str(row["id"]): row for row in versions}
    for start in by_id:
        seen: set[str] = set()
        current: str | None = start
        while current is not None:
            assert current not in seen
            seen.add(current)
            successor = by_id[current]["superseded_by"]
            current = str(successor) if successor is not None else None


def test_schema_v6_migration_preserves_legacy_versions_and_chunk_links(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    legacy_schema = SCHEMA.replace(
        "  processing_fingerprint TEXT NOT NULL DEFAULT 'legacy',\n"
        "  superseded_by TEXT REFERENCES source_versions(id),\n",
        "",
    ).replace(
        "  UNIQUE(document_id, version_sha256, processing_fingerprint)",
        "  UNIQUE(document_id, version_sha256)",
    )
    connection = sqlite3.connect(path)
    connection.executescript(legacy_schema)
    connection.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, created_at, updated_at
        ) VALUES ('doc', ?, ?, 'source-legacy.txt', 'text/plain', 'private_teaching', 'now', 'now')
        """,
        ("a" * 64, f"content-sha256:{'a' * 64}"),
    )
    connection.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, metadata_json, created_at
        ) VALUES ('version', 'doc', ?, 'data/vault/objects/sha256/aa/legacy', '{}', 'now')
        """,
        ("a" * 64,),
    )
    connection.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count
        ) VALUES ('chunk', 'version', 0, 'chunk 1', ?, 'Legacy text', 2)
        """,
        (hashlib.sha256(b"Legacy text").hexdigest(),),
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)

    migrated = Database(path)
    migrated.initialize()
    try:
        version = migrated.fetchone("SELECT * FROM source_versions WHERE id='version'")
        assert version is not None
        assert version["processing_fingerprint"] == "legacy"
        assert version["superseded_by"] is None
        assert (
            migrated.fetchone("SELECT source_version_id FROM chunks WHERE id='chunk'")[
                "source_version_id"
            ]
            == "version"
        )
        assert migrated.fetchall("PRAGMA foreign_key_check") == []
    finally:
        migrated.close()


def test_schema_v7_migration_restores_semantic_canonicals_and_reviews(tmp_path: Path) -> None:
    path = tmp_path / "semantic-v6.sqlite3"
    legacy = Database(path)
    legacy.initialize()
    content_sha256 = "a" * 64
    rows = (
        ("primary", "primary_authority", "staged", None, "citable", 1),
        ("official", "official_secondary", "staged", "primary", "duplicate", 0),
        ("scholarship", "scholarship", "approved", "primary", "duplicate", 0),
    )
    with legacy.transaction() as connection:
        connection.execute("DROP INDEX idx_documents_semantic_content_canonical")
        connection.execute("DROP INDEX idx_documents_semantic_retrieval_canonical")
        for ordinal, (
            identifier,
            lane,
            review_status,
            duplicate_of,
            status,
            canonical,
        ) in enumerate(rows):
            connection.execute(
                """
                INSERT INTO documents(
                  id, content_sha256, source_identity_id, representation_group_id,
                  safe_display_name, media_type, status, lane, subject_primary,
                  jurisdiction, duplicate_of, retrieval_canonical, searchable_text,
                  created_at, updated_at
                ) VALUES (?, ?, ?, 'shared-representation', ?, 'text/markdown',
                          ?, ?, 'contract', 'England and Wales', ?, ?, 1, ?, ?)
                """,
                (
                    identifier,
                    content_sha256,
                    f"content-sha256:{content_sha256}",
                    f"source-{identifier}.md",
                    status,
                    lane,
                    duplicate_of,
                    canonical,
                    f"2026-08-11T00:00:0{ordinal}+00:00",
                    f"2026-08-11T00:00:0{ordinal}+00:00",
                ),
            )
            source_version_id = f"version-{identifier}"
            connection.execute(
                """
                INSERT INTO source_versions(
                  id, document_id, version_sha256, canonical_markdown_path,
                  review_status, processing_fingerprint, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, 'legacy-policy', ?, ?)
                """,
                (
                    source_version_id,
                    identifier,
                    content_sha256,
                    f"data/vault/{identifier}",
                    review_status,
                    json.dumps({"parser_status": "ready"}),
                    f"2026-08-11T00:00:0{ordinal}+00:00",
                ),
            )
            connection.execute(
                """
                INSERT INTO chunks(
                  id, source_version_id, ordinal, locator, text_sha256,
                  markdown_text, token_count
                ) VALUES (?, ?, 0, 'chunk 1', ?, ?, 3)
                """,
                (
                    f"chunk-{identifier}",
                    source_version_id,
                    hashlib.sha256(identifier.encode()).hexdigest(),
                    f"Preserved {identifier} chunk",
                ),
            )
        connection.execute(
            """
            INSERT INTO reviews(id, review_type, target_id, status, reason, created_at)
            VALUES ('review-version-primary', 'source_version', 'version-primary',
                    'pending', 'Legacy review', '2026-08-11T00:00:00+00:00')
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX idx_documents_content_sha256_canonical
            ON documents(content_sha256) WHERE duplicate_of IS NULL
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX idx_documents_one_retrieval_canonical
            ON documents(representation_group_id)
            WHERE retrieval_canonical=1 AND duplicate_of IS NULL
              AND representation_group_id IS NOT NULL
            """
        )
        connection.execute("UPDATE schema_meta SET value='6' WHERE key='schema_version'")
    legacy.close()

    migrated = Database(path)
    migrated.initialize()
    try:
        documents = migrated.fetchall("SELECT * FROM documents ORDER BY id")
        assert len(documents) == 3
        assert all(row["duplicate_of"] is None for row in documents)
        assert all(row["status"] == "citable" for row in documents)
        assert all(row["retrieval_canonical"] == 1 for row in documents)
        assert {row["lane"] for row in documents} == {
            "primary_authority",
            "official_secondary",
            "scholarship",
        }
        assert migrated.fetchone("SELECT COUNT(*) AS n FROM chunks")["n"] == 3
        assert (
            migrated.fetchone(
                """
                SELECT COUNT(*) AS n FROM reviews r
                JOIN source_versions sv ON sv.id=r.target_id
                JOIN documents d ON d.id=sv.document_id
                WHERE r.review_type='source_version' AND r.status='pending'
                  AND sv.review_status='staged' AND d.duplicate_of IS NULL
                """
            )["n"]
            == 3
        )
        assert (
            migrated.fetchone(
                "SELECT review_status FROM source_versions WHERE id='version-scholarship'"
            )["review_status"]
            == "staged"
        )
        assert (
            migrated.fetchone(
                """
                SELECT COUNT(*) AS n FROM reviews r
                JOIN source_versions sv ON sv.id=r.target_id
                JOIN documents d ON d.id=sv.document_id
                WHERE r.status='pending' AND d.duplicate_of IS NOT NULL
                """
            )["n"]
            == 0
        )
        indexes = {
            row["name"]
            for row in migrated.fetchall("SELECT name FROM sqlite_master WHERE type='index'")
        }
        assert "idx_documents_semantic_content_canonical" in indexes
        assert "idx_documents_semantic_retrieval_canonical" in indexes
        assert "idx_documents_content_sha256_canonical" not in indexes
        assert "idx_documents_one_retrieval_canonical" not in indexes
        assert migrated.fetchone("SELECT value FROM schema_meta WHERE key='schema_version'")[
            "value"
        ] == str(SCHEMA_VERSION)
        assert migrated.fetchall("PRAGMA foreign_key_check") == []

        snapshot = [tuple(row) for row in documents]
        migrated.initialize()
        assert [
            tuple(row) for row in migrated.fetchall("SELECT * FROM documents ORDER BY id")
        ] == snapshot
        assert migrated.fetchall("PRAGMA foreign_key_check") == []
    finally:
        migrated.close()


def test_schema_v7_migration_quarantines_versionless_canonical_until_rescan(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    law = tmp_path / "Law"
    cases = law / "Cases"
    guidance = law / "Official guidance"
    cases.mkdir(parents=True)
    guidance.mkdir(parents=True)
    payload = "# Shared source\n\nThe same stored bytes have distinct source identities."
    (cases / "copy.md").write_text(payload, encoding="utf-8")
    (guidance / "copy.md").write_text(payload, encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "semantic-v7-seed")

    primary = database.fetchone("SELECT id FROM documents WHERE lane='primary_authority'")
    official = database.fetchone("SELECT id FROM documents WHERE lane='official_secondary'")
    assert primary is not None and official is not None
    official_version = database.fetchone(
        "SELECT id FROM source_versions WHERE document_id=? AND superseded_by IS NULL",
        (official["id"],),
    )
    assert official_version is not None
    with database.transaction() as connection:
        connection.execute("DROP INDEX idx_documents_semantic_content_canonical")
        connection.execute("DROP INDEX idx_documents_semantic_retrieval_canonical")
        connection.execute(
            "DELETE FROM reviews WHERE review_type='source_version' AND target_id=?",
            (official_version["id"],),
        )
        connection.execute("DELETE FROM source_versions WHERE id=?", (official_version["id"],))
        connection.execute(
            """
            UPDATE documents
            SET duplicate_of=?, status='duplicate', retrieval_canonical=0
            WHERE id=?
            """,
            (primary["id"], official["id"]),
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX idx_documents_content_sha256_canonical
            ON documents(content_sha256) WHERE duplicate_of IS NULL
            """
        )
        connection.execute(
            """
            CREATE UNIQUE INDEX idx_documents_one_retrieval_canonical
            ON documents(representation_group_id)
            WHERE retrieval_canonical=1 AND duplicate_of IS NULL
              AND representation_group_id IS NOT NULL
            """
        )
        connection.execute("UPDATE schema_meta SET value='6' WHERE key='schema_version'")
    database.close()

    migrated = Database(tmp_path / "catalog.sqlite3")
    migrated.initialize()
    restored = migrated.fetchone("SELECT * FROM documents WHERE id=?", (official["id"],))
    assert restored is not None
    assert restored["duplicate_of"] is None
    assert restored["status"] == "quarantined"
    assert (
        migrated.fetchone(
            "SELECT COUNT(*) AS n FROM source_versions WHERE document_id=?",
            (official["id"],),
        )["n"]
        == 0
    )
    assert (
        migrated.fetchone(
            """
            SELECT COUNT(*) AS n FROM reviews r
            JOIN source_versions sv ON sv.id=r.target_id
            WHERE r.review_type='source_version' AND r.status='pending'
              AND sv.document_id=?
            """,
            (official["id"],),
        )["n"]
        == 0
    )

    scan_configured_sources(settings, migrated, cipher, "semantic-v7-reparse")
    reparsed = migrated.fetchone("SELECT * FROM documents WHERE id=?", (official["id"],))
    assert reparsed is not None
    assert reparsed["duplicate_of"] is None
    assert reparsed["status"] == "citable"
    current = migrated.fetchone(
        "SELECT * FROM source_versions WHERE document_id=? AND superseded_by IS NULL",
        (official["id"],),
    )
    assert current is not None and current["review_status"] == "staged"
    assert (
        migrated.fetchone(
            """
            SELECT COUNT(*) AS n FROM reviews
            WHERE review_type='source_version' AND target_id=? AND status='pending'
            """,
            (current["id"],),
        )["n"]
        == 1
    )
    assert _approved_chunk_count(migrated) == 0
    version_count = migrated.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"]
    scan_configured_sources(settings, migrated, cipher, "semantic-v7-reparse-repeat")
    assert migrated.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == version_count
    assert migrated.fetchall("PRAGMA foreign_key_check") == []
    migrated.close()
