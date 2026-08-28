from __future__ import annotations

import json
from pathlib import Path

from app.config import Settings
from app.db import utc_iso
from app.ingestion.service import scan_configured_sources
from app.orchestration.uploads import QuestionUploadProcessor
from app.retrieval.service import (
    _approved_chunk_count,
    _approved_chunk_row_batches,
    _approved_source_snapshot,
)


def test_interrupted_document_upsert_is_excluded_everywhere_and_rescan_repairs(
    tmp_path: Path, database, cipher, monkeypatch
) -> None:
    law = tmp_path / "Law" / "Course"
    law.mkdir(parents=True)
    source = law / "identity.md"
    source.write_text(
        "# Reviewed source\n\nA supported proposition for the identity guard.",
        encoding="utf-8",
    )
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(tmp_path / "Law"))
    settings = Settings(project_root=tmp_path, test_mode=True)
    scan_configured_sources(settings, database, cipher, "identity-before-interruption")

    source_version = database.fetchone(
        "SELECT id, version_sha256, metadata_json FROM source_versions"
    )
    assert source_version is not None
    source_version_id = str(source_version["id"])
    original_sha256 = str(source_version["version_sha256"])
    metadata = json.loads(str(source_version["metadata_json"]))
    metadata.update(
        {
            "identity_verified": True,
            "currentness_verified": True,
            "citation_data": {
                "source_type": "case",
                "title": "Identity Guard v Source",
                "neutral_citation": "[2026] UKSC 1",
            },
        }
    )
    database.execute(
        """
        UPDATE source_versions
        SET review_status='approved', stable_identifier=?, metadata_json=?
        WHERE id=?
        """,
        (
            "neutral-citation:[2026] UKSC 1",
            json.dumps(metadata, ensure_ascii=False, sort_keys=True),
            source_version_id,
        ),
    )
    database.execute(
        """
        UPDATE reviews SET status='approved', decided_at=?
        WHERE review_type='source_version' AND target_id=?
        """,
        (utc_iso(), source_version_id),
    )
    database.execute(
        """
        INSERT INTO rubric_rules(
          id, task_type, subject, criterion, polarity, grade_band, rule_text,
          source_version_id, review_status, created_at
        ) VALUES ('identity-rule', 'essay', NULL, 'analysis', 'positive_pattern',
                  '70+', 'Support each material proposition.', ?, 'approved', ?)
        """,
        (source_version_id, utc_iso()),
    )
    processor = QuestionUploadProcessor(
        settings=settings,
        database=database,
        cipher=cipher,
    )

    assert _approved_chunk_count(database) > 0
    assert list(_approved_chunk_row_batches(database))
    assert [
        row["id"]
        for row in database.approved_assessment_rules(task_type="essay", subject="contract")
    ] == ["identity-rule"]
    assert processor._has_reviewed_identity(original_sha256) is True
    assert database.admin_sources()[0]["review_status"] == "approved"

    # Simulate a process interruption after the mutable document row was
    # updated for new bytes but before its immutable source-version successor
    # and chunks were committed.
    interrupted_sha256 = "f" * 64
    assert interrupted_sha256 != original_sha256
    database.execute(
        "UPDATE documents SET content_sha256=? WHERE id=(SELECT document_id FROM source_versions WHERE id=?)",
        (interrupted_sha256, source_version_id),
    )

    assert _approved_chunk_count(database) == 0
    assert list(_approved_chunk_row_batches(database)) == []
    assert _approved_source_snapshot(database).chunk_count == 0
    assert _approved_source_snapshot(database).document_count == 0
    assert database.approved_assessment_rules(task_type="essay", subject="contract") == []
    assert processor._has_reviewed_identity(interrupted_sha256) is False
    assert database.admin_sources()[0]["review_status"] is None

    scan_configured_sources(settings, database, cipher, "identity-repair-rescan")

    repaired = database.fetchone(
        """
        SELECT d.content_sha256, sv.version_sha256, sv.review_status
        FROM documents d JOIN source_versions sv ON sv.document_id=d.id
        WHERE sv.superseded_by IS NULL
        """
    )
    assert repaired is not None
    assert repaired["content_sha256"] == repaired["version_sha256"] == original_sha256
    assert repaired["review_status"] == "approved"
    assert _approved_chunk_count(database) > 0
    assert list(_approved_chunk_row_batches(database))
    assert _approved_source_snapshot(database).chunk_count > 0
    assert _approved_source_snapshot(database).document_count == 1
    assert [
        row["id"]
        for row in database.approved_assessment_rules(task_type="essay", subject="contract")
    ] == ["identity-rule"]
    assert processor._has_reviewed_identity(original_sha256) is True
    assert database.admin_sources()[0]["review_status"] == "approved"
