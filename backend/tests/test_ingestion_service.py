from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from app.config import Settings
from app.ingestion import service
from app.ingestion.models import (
    Annotation,
    BlockKind,
    DocumentFormat,
    ParseResult,
    ParseStatus,
    StructuralBlock,
)
from app.ingestion.ocr import OcrFailedError, OcrResult, OcrUnavailableError
from app.ingestion.parsers import ParserRegistry
from app.ingestion.service import scan_configured_sources


def _docx_with_comment(body_text: str, comment_text: str) -> bytes:
    namespace = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    document = f"""<?xml version="1.0" encoding="UTF-8"?>
    <w:document xmlns:w="{namespace}"><w:body><w:p><w:r><w:t>{body_text}</w:t></w:r></w:p></w:body></w:document>"""
    comments = f"""<?xml version="1.0" encoding="UTF-8"?>
    <w:comments xmlns:w="{namespace}"><w:comment w:id="1" w:author="Marker Name"><w:p><w:r><w:t>{comment_text}</w:t></w:r></w:p></w:comment></w:comments>"""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", document)
        archive.writestr("word/comments.xml", comments)
    return output.getvalue()


def test_linked_resume_reuses_only_hash_verified_current_processing(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "configured sources"
    authority_path = source_root / "Contract law" / "Cases" / "authority.md"
    authority_path.parent.mkdir(parents=True)
    authority_path.write_text(
        "# Example Authority\n\nA proposition supported by the judgment.", encoding="utf-8"
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "resume-seed")
    prior_file = database.source_scan_files("resume-seed")[0]

    descriptors = database.create_source_scan("resume-interrupted", settings.source_roots)
    database.start_source_scan("resume-interrupted", roots_seen=descriptors, expected_file_count=1)
    database.record_source_scan_file(
        "resume-interrupted",
        path_fingerprint=str(prior_file["path_fingerprint"]),
        document_id=str(prior_file["document_id"]),
        status=str(prior_file["status"]),
        content_sha256=str(prior_file["content_sha256"]),
        reason=None,
    )
    assert database.fail_interrupted_source_scans() == ["resume-interrupted"]
    database.resume_source_scan("resume-interrupted", "resume-retry", settings.source_roots)

    def unexpected_reprocess(*_args, **_kwargs):
        raise AssertionError("an exact current v10 source must be hash-reused")

    monkeypatch.setattr(service, "_ingest_file", unexpected_reprocess)
    resumed = scan_configured_sources(settings, database, cipher, "resume-retry")

    assert resumed["status"] == "complete"
    assert resumed["resumed_from_scan_id"] == "resume-interrupted"
    assert resumed["resumed_files_reused"] == 1
    assert resumed["files_accounted"] == 1


def test_linked_resume_reprocesses_changed_bytes(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "configured sources"
    authority_path = source_root / "Contract law" / "Cases" / "authority.md"
    authority_path.parent.mkdir(parents=True)
    authority_path.write_text("# Authority\n\nVersion one.", encoding="utf-8")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "changed-seed")
    prior_file = database.source_scan_files("changed-seed")[0]

    descriptors = database.create_source_scan("changed-interrupted", settings.source_roots)
    database.start_source_scan("changed-interrupted", roots_seen=descriptors, expected_file_count=1)
    database.record_source_scan_file(
        "changed-interrupted",
        path_fingerprint=str(prior_file["path_fingerprint"]),
        document_id=str(prior_file["document_id"]),
        status=str(prior_file["status"]),
        content_sha256=str(prior_file["content_sha256"]),
        reason=None,
    )
    assert database.fail_interrupted_source_scans() == ["changed-interrupted"]
    database.resume_source_scan("changed-interrupted", "changed-retry", settings.source_roots)
    authority_path.write_text("# Authority\n\nVersion two.", encoding="utf-8")

    resumed = scan_configured_sources(settings, database, cipher, "changed-retry")

    assert resumed["status"] == "complete"
    assert resumed["resumed_files_reused"] == 0
    retried_file = database.source_scan_files("changed-retry")[0]
    assert retried_file["content_sha256"] != prior_file["content_sha256"]


def test_linked_resume_rebuilds_missing_canonical_markdown(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "configured sources"
    authority_path = source_root / "Contract law" / "Cases" / "authority.md"
    authority_path.parent.mkdir(parents=True)
    authority_path.write_text(
        "# Example Authority\n\nA proposition supported by the judgment.", encoding="utf-8"
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "missing-canonical-seed")
    prior_file = database.source_scan_files("missing-canonical-seed")[0]
    source_version = database.fetchone(
        "SELECT canonical_markdown_path FROM source_versions WHERE superseded_by IS NULL"
    )
    assert source_version is not None
    canonical_path = tmp_path / str(source_version["canonical_markdown_path"])
    canonical_path.unlink()

    descriptors = database.create_source_scan(
        "missing-canonical-interrupted", settings.source_roots
    )
    database.start_source_scan(
        "missing-canonical-interrupted", roots_seen=descriptors, expected_file_count=1
    )
    database.record_source_scan_file(
        "missing-canonical-interrupted",
        path_fingerprint=str(prior_file["path_fingerprint"]),
        document_id=str(prior_file["document_id"]),
        status=str(prior_file["status"]),
        content_sha256=str(prior_file["content_sha256"]),
        reason=None,
    )
    assert database.fail_interrupted_source_scans() == ["missing-canonical-interrupted"]
    database.resume_source_scan(
        "missing-canonical-interrupted",
        "missing-canonical-retry",
        settings.source_roots,
    )

    resumed = scan_configured_sources(settings, database, cipher, "missing-canonical-retry")

    assert resumed["status"] == "complete"
    assert resumed["resumed_files_reused"] == 0
    assert canonical_path.is_file()
    assert canonical_path.stat().st_size > 0


def test_scan_accounts_every_file_encrypts_aliases_and_separates_feedback(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "configured sources"
    cases = source_root / "Contract law" / "Cases"
    feedback = source_root / "Contract law" / "Exam feedback"
    cases.mkdir(parents=True)
    feedback.mkdir(parents=True)
    authority = b"# Example Authority\n\nConsideration requires a bargained exchange."
    (cases / "authority.md").write_bytes(authority)
    (cases / "duplicate authority.md").write_bytes(authority)
    (feedback / "student feedback.docx").write_bytes(
        _docx_with_comment(
            "STUDENT PROSE MUST NEVER BECOME A RULE OR RETRIEVAL CHUNK.",
            "Mark: 72. Strong analysis and accurate use of authority.",
        )
    )
    (feedback / "ordinary student note.md").write_text(
        "# Student answer\n\nThis body is not marker feedback.", encoding="utf-8"
    )
    (feedback / "marking criteria.md").write_text(
        "# Marking criteria\n\nA first-class answer sustains a supported thesis.", encoding="utf-8"
    )
    (source_root / "unrecognised.bin").write_bytes(b"raw but unsupported")

    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    settings = Settings(project_root=tmp_path, test_mode=True)
    first = scan_configured_sources(settings, database, cipher, "scan-one")

    assert first["files_accounted"] == 6
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_aliases")["n"] == 6
    assert database.fetchone("SELECT COUNT(*) AS n FROM documents")["n"] == 6
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 5
    assert first["statuses"]["duplicate"] == 1
    assert first["statuses"]["unsupported"] == 1
    overview = database.admin_overview()
    assert overview["exact_duplicates"] == 1
    assert overview["annotation_sources"] == 1
    duplicate = database.fetchone(
        "SELECT id, duplicate_of, content_sha256 FROM documents WHERE duplicate_of IS NOT NULL"
    )
    assert duplicate is not None
    assert database.fetchone("SELECT id FROM documents WHERE id=?", (duplicate["duplicate_of"],))
    exact_rows = database.fetchall(
        """
        SELECT d.id, d.duplicate_of, COUNT(sa.id) AS aliases
        FROM documents d LEFT JOIN source_aliases sa ON sa.document_id=d.id
        WHERE d.content_sha256=? GROUP BY d.id ORDER BY d.id
        """,
        (duplicate["content_sha256"],),
    )
    assert len(exact_rows) == 2
    assert sum(int(row["aliases"]) for row in exact_rows) == 2
    assert (
        database.fetchone("SELECT dedupe_status FROM documents WHERE id=?", (duplicate["id"],))[
            "dedupe_status"
        ]
        == "duplicate_content"
    )
    scan = database.fetchone("SELECT * FROM source_scans WHERE id='scan-one'")
    assert scan is not None
    assert scan["status"] == "complete"
    assert scan["expected_file_count"] == scan["files_accounted"] == 6
    assert len(scan["manifest_sha256"]) == 64
    assert len(database.source_scan_files("scan-one")) == 6
    assert str(source_root) not in scan["required_roots_json"]
    assert str(source_root) not in scan["roots_seen_json"]

    aliases = database.fetchall("SELECT encrypted_path FROM source_aliases")
    decrypted = {cipher.decrypt_text(row["encrypted_path"]) for row in aliases}
    assert decrypted == {str(path.absolute()) for path in source_root.rglob("*") if path.is_file()}
    display_names = [
        str(row["safe_display_name"])
        for row in database.fetchall("SELECT safe_display_name FROM documents")
    ]
    assert all(name.startswith("source-") for name in display_names)
    assert all(
        "student" not in name.casefold() and "authority" not in name.casefold()
        for name in display_names
    )

    feedback_version = database.fetchone(
        """
        SELECT sv.id FROM source_versions sv JOIN documents d ON d.id=sv.document_id
        WHERE d.lane='assessment_guidance' AND sv.title LIKE 'source-%.docx'
        """
    )
    assert feedback_version is not None
    feedback_chunks = database.fetchall(
        "SELECT markdown_text, metadata_json FROM chunks WHERE source_version_id=?",
        (feedback_version["id"],),
    )
    assert [row["markdown_text"] for row in feedback_chunks] == [
        "Mark: 72. Strong analysis and accurate use of authority."
    ]
    assert all(json.loads(row["metadata_json"])["stream"] == "comments" for row in feedback_chunks)
    assert "STUDENT PROSE" not in " ".join(str(row["markdown_text"]) for row in feedback_chunks)

    ordinary = database.fetchone(
        """
        SELECT sv.id FROM source_versions sv JOIN documents d ON d.id=sv.document_id
        WHERE d.lane='assessment_guidance' AND sv.canonical_markdown_path LIKE '%'
          AND d.media_type='text/markdown'
        ORDER BY CASE WHEN sv.title LIKE '%marking%' THEN 1 ELSE 0 END, sv.id LIMIT 1
        """
    )
    # Assessment titles are privacy-safe hashes, so identify the two Markdown
    # versions by their chunk counts: ordinary student prose has no chunks;
    # the explicitly named rubric is allowed to retain its body structure.
    assessment_markdown_counts = database.fetchall(
        """
        SELECT sv.id, COUNT(c.id) AS n
        FROM source_versions sv JOIN documents d ON d.id=sv.document_id
        LEFT JOIN chunks c ON c.source_version_id=sv.id
        WHERE d.lane='assessment_guidance' AND d.media_type='text/markdown'
        GROUP BY sv.id ORDER BY n
        """
    )
    assert ordinary is not None
    assert [int(row["n"]) for row in assessment_markdown_counts] == [0, 2]

    rules = database.fetchall("SELECT * FROM rubric_rules")
    assert len(rules) == 2
    assert {row["grade_band"] for row in rules} == {"70+"}
    assert {row["polarity"] for row in rules} == {"positive_pattern"}
    assert "STUDENT PROSE" not in " ".join(str(row["rule_text"]) for row in rules)
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM reviews WHERE review_type='assessment_rule' AND status='pending'"
        )["n"]
        == 2
    )
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM reviews WHERE review_type='source_version' AND status='pending'"
        )["n"]
        == 4
    )

    raw_hashes = {
        json.loads(row["metadata_json"])["raw_object_sha256"]
        for row in database.fetchall("SELECT metadata_json FROM source_versions")
    }
    assert raw_hashes
    for digest in raw_hashes:
        assert (settings.vault_dir / "objects" / "sha256" / digest[:2] / digest).is_file()
    assert (settings.vault_dir / "alias-secret.enc").is_file()

    versions_before = database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"]
    rules_before = database.fetchone("SELECT COUNT(*) AS n FROM rubric_rules")["n"]
    second = scan_configured_sources(settings, database, cipher, "scan-two")
    assert second["files_accounted"] == 6
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == versions_before
    assert database.fetchone("SELECT COUNT(*) AS n FROM rubric_rules")["n"] == rules_before


def test_rescan_preserves_curated_approval_and_reviewed_derived_chunks(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    """A disposable scan must not reinterpret a reviewed evidence layer.

    ``selected_chunk_count`` describes chunks owned by the filesystem parser.
    Reviewed paragraph chunks are a separate, deterministic derivative.  They
    must not make an otherwise idempotent scan look like a persistence defect.
    """

    source_root = tmp_path / "Law" / "Course"
    source_root.mkdir(parents=True)
    (source_root / "judgment.md").write_text(
        "# Judgment\n\n[1] The court states a reviewed proposition.",
        encoding="utf-8",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "reviewed-scan-one")

    source = database.fetchone(
        """
        SELECT d.id AS document_id, sv.id AS source_version_id, sv.metadata_json
        FROM documents d JOIN source_versions sv ON sv.document_id=d.id
        """
    )
    assert source is not None
    source_version_id = str(source["source_version_id"])
    metadata = json.loads(source["metadata_json"])
    metadata.update(
        {
            "identity_verified": True,
            "currentness_verified": False,
            "material_type": "case",
            "official_snapshot": {
                "schema": "legalbot.official-judgment-snapshot.v1",
                "representation_id": "reviewed-representation-1",
            },
            "reviewed_evidence_materialization": {
                "schema": "legalbot.reviewed-judgment-paragraph-chunk.v1",
                "chunk_count": 1,
                "chunk_ids": ["chunk-reviewed-regression"],
            },
        }
    )
    reviewed_text = "1. The court states a reviewed proposition."
    reviewed_metadata = {
        "schema": "legalbot.reviewed-judgment-paragraph-chunk.v1",
        "representation_id": "reviewed-representation-1",
        "legal_role": "holding_ratio",
        "material_claim_support_eligible": True,
    }
    with database.transaction() as connection:
        connection.execute(
            """
            UPDATE documents
            SET lane='primary_authority', status='citable', subject_primary='trusts',
                jurisdiction='England and Wales'
            WHERE id=?
            """,
            (source["document_id"],),
        )
        connection.execute(
            """
            UPDATE source_versions
            SET review_status='approved', stable_identifier='neutral-citation:[2025] UKSC 1',
                metadata_json=?
            WHERE id=?
            """,
            (json.dumps(metadata, ensure_ascii=False, sort_keys=True), source_version_id),
        )
        connection.execute(
            """
            UPDATE reviews SET status='approved'
            WHERE review_type='source_version' AND target_id=?
            """,
            (source_version_id,),
        )
        connection.execute(
            """
            INSERT INTO chunks(
              id,source_version_id,ordinal,heading_path,locator,text_sha256,
              markdown_text,token_count,stream,metadata_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "chunk-reviewed-regression",
                source_version_id,
                1_000_000_001,
                '["Reviewed judgment paragraph"]',
                "[1]",
                hashlib.sha256(reviewed_text.encode("utf-8")).hexdigest(),
                reviewed_text,
                7,
                "body",
                json.dumps(reviewed_metadata, ensure_ascii=False, sort_keys=True),
            ),
        )

    before_source = tuple(
        database.fetchone(
            """
            SELECT d.lane,d.status,d.subject_primary,d.jurisdiction,
                   sv.id,sv.review_status,sv.stable_identifier,sv.metadata_json
            FROM documents d JOIN source_versions sv ON sv.document_id=d.id
            """
        )
    )
    before_chunks = [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal,id",
            (source_version_id,),
        )
    ]
    before_review = tuple(
        database.fetchone(
            """
            SELECT status,reason,decision_note,decided_at FROM reviews
            WHERE review_type='source_version' AND target_id=?
            """,
            (source_version_id,),
        )
    )

    scan_configured_sources(settings, database, cipher, "reviewed-scan-two")

    after_source = tuple(
        database.fetchone(
            """
            SELECT d.lane,d.status,d.subject_primary,d.jurisdiction,
                   sv.id,sv.review_status,sv.stable_identifier,sv.metadata_json
            FROM documents d JOIN source_versions sv ON sv.document_id=d.id
            """
        )
    )
    after_chunks = [
        tuple(row)
        for row in database.fetchall(
            "SELECT * FROM chunks WHERE source_version_id=? ORDER BY ordinal,id",
            (source_version_id,),
        )
    ]
    after_review = tuple(
        database.fetchone(
            """
            SELECT status,reason,decision_note,decided_at FROM reviews
            WHERE review_type='source_version' AND target_id=?
            """,
            (source_version_id,),
        )
    )
    assert after_source == before_source
    assert after_chunks == before_chunks
    assert after_review == before_review
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 1


def test_missing_source_root_is_a_durable_explicit_failure(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    missing = tmp_path / "missing sources"
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(missing))
    settings = Settings(project_root=tmp_path, test_mode=True)

    with pytest.raises(FileNotFoundError, match="root-"):
        scan_configured_sources(settings, database, cipher, "scan-missing")

    row = database.fetchone("SELECT * FROM source_scans WHERE id='scan-missing'")
    assert row is not None
    assert row["status"] == "failed"
    assert row["error_code"] == "missing_source_root"
    assert str(missing) not in row["error_message"]


def test_ocr_derivative_is_hash_linked_and_reparsed(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "Law" / "Cases"
    source_root.mkdir(parents=True)
    original = b"%PDF-original-scanned"
    derivative = b"%PDF-OCR-DERIVATIVE"
    (source_root / "scanned.pdf").write_bytes(original)

    class FakeRegistry:
        def parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
            if data == derivative:
                return ParseResult(
                    ParseStatus.READY,
                    DocumentFormat.PDF,
                    body_blocks=(
                        StructuralBlock(
                            0,
                            BlockKind.PARAGRAPH,
                            "The OCR recovered legal proposition.",
                            page=1,
                        ),
                    ),
                )
            return ParseResult(ParseStatus.OCR_REQUIRED, DocumentFormat.PDF)

    class FakeOcr:
        def process(self, pdf_bytes: bytes) -> OcrResult:
            assert pdf_bytes == original
            return OcrResult(derivative, "fake-ocr", True)

    monkeypatch.setattr(ParserRegistry, "default", classmethod(lambda cls: FakeRegistry()))
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    result = scan_configured_sources(
        settings,
        database,
        cipher,
        "scan-ocr",
        ocr_processor=FakeOcr(),  # type: ignore[arg-type]
    )

    assert result["statuses"] == {"citable": 1}
    row = database.fetchone("SELECT metadata_json FROM source_versions")
    assert row is not None
    metadata = json.loads(row["metadata_json"])
    assert metadata["ocr_engine"] == "fake-ocr"
    assert metadata["ocr_original_sha256"] != metadata["ocr_derivative_sha256"]
    derivative_path = (
        settings.vault_dir
        / "objects"
        / "sha256"
        / metadata["ocr_derivative_sha256"][:2]
        / metadata["ocr_derivative_sha256"]
    )
    assert derivative_path.read_bytes() == derivative


def test_same_stem_pdf_docx_representations_share_group_without_losing_comments(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "Law" / "Cases"
    source_root.mkdir(parents=True)
    (source_root / "authority.pdf").write_bytes(b"%PDF-representation")
    (source_root / "authority.docx").write_bytes(b"PK-docx-representation")

    class FakeRegistry:
        def parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
            comments = (
                (Annotation("comment-1", "Representation-specific annotation retained."),)
                if filename.endswith(".docx")
                else ()
            )
            return ParseResult(
                ParseStatus.READY,
                DocumentFormat.DOCX if filename.endswith(".docx") else DocumentFormat.PDF,
                body_blocks=(
                    StructuralBlock(0, BlockKind.PARAGRAPH, "Shared authority proposition."),
                ),
                comments=comments,
            )

    monkeypatch.setattr(ParserRegistry, "default", classmethod(lambda cls: FakeRegistry()))
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "scan-representations")

    documents = database.fetchall("SELECT * FROM documents ORDER BY media_type")
    assert len(documents) == 2
    assert len({row["source_identity_id"] for row in documents}) == 2
    assert len({row["representation_group_id"] for row in documents}) == 1
    assert all(row["duplicate_of"] is None for row in documents)
    assert {row["dedupe_status"] for row in documents} == {"new", "duplicate_identity"}
    assert str(documents[0]["representation_group_id"]).startswith("local-representation-sha256:")
    canonical = [row for row in documents if row["retrieval_canonical"]]
    assert len(canonical) == 1
    assert canonical[0]["media_type"] == "application/pdf"

    metadata_rows = database.fetchall("SELECT metadata_json FROM source_versions")
    comment_hashes = [json.loads(row["metadata_json"])["comments_sha256"] for row in metadata_rows]
    comment_payloads = [
        (settings.vault_dir / "objects" / "sha256" / digest[:2] / digest).read_text(
            encoding="utf-8"
        )
        for digest in comment_hashes
    ]
    assert any("Representation-specific annotation retained" in text for text in comment_payloads)
    stored_streams = database.fetchall(
        """
        SELECT c.stream, d.media_type FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        ORDER BY d.media_type, c.ordinal
        """
    )
    assert any(row["stream"] == "comments" for row in stored_streams)
    retrieval_bodies = database.fetchall(
        """
        SELECT c.stream, d.media_type FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE d.retrieval_canonical=1 AND c.stream='body'
        """
    )
    assert [(row["stream"], row["media_type"]) for row in retrieval_bodies] == [
        ("body", "application/pdf")
    ]


def test_annotated_feedback_docx_beats_pdf_and_preserves_only_comment_runtime_stream(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "Law" / "Exam feedback"
    source_root.mkdir(parents=True)
    (source_root / "answer.pdf").write_bytes(b"%PDF-feedback")
    (source_root / "answer.docx").write_bytes(b"PK-feedback")

    class FakeRegistry:
        def parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
            comments = (
                (Annotation("comment-1", "Strong first-class counterargument."),)
                if filename.endswith(".docx")
                else ()
            )
            return ParseResult(
                ParseStatus.READY,
                DocumentFormat.DOCX if filename.endswith(".docx") else DocumentFormat.PDF,
                body_blocks=(StructuralBlock(0, BlockKind.PARAGRAPH, "Student answer body."),),
                comments=comments,
            )

    monkeypatch.setattr(ParserRegistry, "default", classmethod(lambda cls: FakeRegistry()))
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "scan-feedback-representations")

    canonical = database.fetchone(
        "SELECT media_type, has_annotations FROM documents WHERE retrieval_canonical=1"
    )
    assert canonical is not None
    assert canonical["media_type"].endswith("wordprocessingml.document")
    assert canonical["has_annotations"] == 1
    eligible = database.fetchall(
        """
        SELECT c.stream, d.media_type FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE d.duplicate_of IS NULL AND (
          (d.retrieval_canonical=1 AND c.stream='body')
          OR (d.lane='assessment_guidance' AND c.stream='comments')
        )
        """
    )
    assert [(row["stream"], row["media_type"]) for row in eligible] == [
        ("comments", canonical["media_type"])
    ]


def test_same_stem_in_different_directories_is_not_over_grouped(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law"
    for directory, body in (("Contract", b"one"), ("Tort", b"two")):
        target = law / directory
        target.mkdir(parents=True)
        (target / "week-1.md").write_bytes(body)

    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(law))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "scan-separate-directories")

    rows = database.fetchall("SELECT representation_group_id FROM documents")
    assert len(rows) == 2
    assert len({row["representation_group_id"] for row in rows}) == 2
    assert database.admin_overview()["source_identity_groups"] == 2
    assert database.admin_overview()["retrieval_canonical_sources"] == 2


def test_idempotent_rescan_migrates_legacy_path_identity_and_preserves_review(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law" / "Cases"
    law.mkdir(parents=True)
    (law / "authority.md").write_text(
        "# Authority\n\nA proposition from [2024] UKSC 7.", encoding="utf-8"
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "scan-before-legacy")
    version = database.fetchone("SELECT id, metadata_json FROM source_versions")
    assert version is not None
    metadata = json.loads(version["metadata_json"])
    metadata["identity_verified"] = True
    database.execute(
        "UPDATE documents SET source_identity_id=?, representation_group_id=NULL, retrieval_canonical=0",
        (f"local-path-sha256:{'9' * 64}",),
    )
    database.execute(
        "UPDATE source_versions SET review_status='approved', metadata_json=? WHERE id=?",
        (json.dumps(metadata), version["id"]),
    )
    versions_before = database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"]
    chunks_before = database.fetchone("SELECT COUNT(*) AS n FROM chunks")["n"]

    scan_configured_sources(settings, database, cipher, "scan-migrate-legacy")
    scan_configured_sources(settings, database, cipher, "scan-after-migration")

    document = database.fetchone("SELECT * FROM documents")
    migrated_version = database.fetchone("SELECT * FROM source_versions")
    assert document is not None and migrated_version is not None
    # A commentary note that merely cites a neutral citation is not a judgment
    # identity. It remains content-addressed until judgment structure is proved.
    assert str(document["source_identity_id"]).startswith("content-sha256:")
    assert str(document["representation_group_id"]).startswith("local-representation-sha256:")
    assert document["retrieval_canonical"] == 1
    assert migrated_version["review_status"] == "approved"
    assert json.loads(migrated_version["metadata_json"])["identity_verified"] is True
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == versions_before
    assert database.fetchone("SELECT COUNT(*) AS n FROM chunks")["n"] == chunks_before


def test_scan_manifest_records_precise_nonready_reason_codes(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    source_root = tmp_path / "Law"
    source_root.mkdir()
    (source_root / ".DS_Store").write_bytes(b"metadata")
    (source_root / "~$draft.docx").write_bytes(b"office-lock")
    (source_root / "source.bin").write_bytes(b"unsupported")
    (source_root / "restricted.pdf").write_bytes(b"%PDF-1.7\n/Encrypt")
    (source_root / "broken.pdf").write_bytes(b"not a pdf")
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))

    result = scan_configured_sources(
        Settings(project_root=tmp_path, test_mode=True), database, cipher, "reason-scan"
    )

    assert result["statuses"] == {"encrypted": 1, "quarantined": 1, "unsupported": 3}
    rows = database.source_scan_files("reason-scan")
    assert sorted(str(row["reason"]) for row in rows) == [
        "encrypted_or_restricted",
        "malformed_or_unreadable",
        "metadata_file_excluded",
        "temporary_file_excluded",
        "unsupported_file_type",
    ]


@pytest.mark.parametrize(
    ("ocr_outcome", "expected_reason"),
    [
        ("unavailable", "ocr_toolchain_unavailable"),
        ("failed", "ocr_processing_failed"),
        ("unreadable", "ocr_output_unreadable"),
    ],
)
def test_scan_manifest_distinguishes_ocr_failure_modes(
    tmp_path: Path,
    database,
    cipher,
    monkeypatch,
    ocr_outcome: str,
    expected_reason: str,
) -> None:
    source_root = tmp_path / "Law"
    source_root.mkdir()
    (source_root / "scan.pdf").write_bytes(b"%PDF-scanned")

    class OcrRegistry:
        def parse(self, data: bytes, *, filename: str, aliaser=None) -> ParseResult:
            return ParseResult(ParseStatus.OCR_REQUIRED, DocumentFormat.PDF)

    class OcrFailure:
        def process(self, pdf_bytes: bytes) -> OcrResult:
            if ocr_outcome == "unavailable":
                raise OcrUnavailableError("private implementation detail")
            if ocr_outcome == "failed":
                raise OcrFailedError("private implementation detail")
            return OcrResult(b"%PDF-still-scanned", "test-ocr", True)

    monkeypatch.setattr(ParserRegistry, "default", classmethod(lambda cls: OcrRegistry()))
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    result = scan_configured_sources(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        cipher,
        f"ocr-{ocr_outcome}",
        ocr_processor=OcrFailure(),  # type: ignore[arg-type]
    )
    assert result["statuses"] == {"ocr_required": 1}
    row = database.source_scan_files(f"ocr-{ocr_outcome}")[0]
    assert row["reason"] == expected_reason
