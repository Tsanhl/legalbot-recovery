from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import pytest

from app.db import Database, utc_iso
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.live_suite_held_span_repair import S14A_SPLICED_PARENT
from app.evaluation.live_suite_tick_draft import (
    apply_contrary_authority_status,
    bind_issue_tick,
    empty_tick_draft,
    lookup_catalogue_spans,
    summarize_tick_draft,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = load_live_evaluation_bundle(
    PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1"
)
S2_TEXT = "The verified statutory proposition."
S2_HASH = hashlib.sha256(S2_TEXT.encode("utf-8")).hexdigest()
S14A_TEXT = "spliced parent text"
S14A_HASH = hashlib.sha256(S14A_TEXT.encode("utf-8")).hexdigest()


def _seed_catalogue(database: Database) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, created_at, updated_at
        ) VALUES ('doc-1', ?, 'identity-1', 'source-a.pdf', 'application/pdf',
                  'citable', 'primary_authority', 'contract', 'England and Wales', ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          currentness_status, review_status, authority_identity_id, created_at
        ) VALUES ('source-version-1', 'doc-1', ?, 'data/vault/aa/source.md',
                  'Example Act 2026', 'current', 'approved', 'ukpga:1980:58', ?)
        """,
        ("b" * 64, now),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count
        )         VALUES (?, 'source-version-1', 0, 's 2', ?,
                  ?, 5)
        """,
        ("chunk-7e5bbeb3dff523f4e7e458a42541455da30e5023", S2_HASH, S2_TEXT),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count
        ) VALUES (?, 'source-version-1', 1, 's 14A', ?,
                  ?, 5)
        """,
        (S14A_SPLICED_PARENT, S14A_HASH, S14A_TEXT),
    )


def test_catalogue_lookup_returns_copyable_identities_and_repair_hint(
    tmp_path: Path, database: Database
) -> None:
    _seed_catalogue(database)
    catalog = tmp_path / "catalog.sqlite3"
    repair = {
        "repairs": [
            {
                "repair_span_id": "repair-span-example",
                "parent_chunk_id": S14A_SPLICED_PARENT,
                "required_sublocator": "s 14A(10) chapeau",
                "text_sha256": "e" * 64,
                "gold_eligible_candidate": True,
            }
        ]
    }
    found = lookup_catalogue_spans(
        catalog_path=catalog,
        authority_identity_id="ukpga:1980:58",
        locator="s 2",
        repair=repair,
    )
    assert found["match_count"] >= 1
    first = found["matches"][0]
    assert first["chunk_id"] == "chunk-7e5bbeb3dff523f4e7e458a42541455da30e5023"
    assert first["source_version_id"] == "source-version-1"
    assert first["legal_locator"] == "s 2"
    assert "markdown_text" not in first
    spliced = lookup_catalogue_spans(
        catalog_path=catalog,
        authority_identity_id="ukpga:1980:58",
        locator="s 14A",
        repair=repair,
    )
    parent = next(item for item in spliced["matches"] if item["chunk_id"] == S14A_SPLICED_PARENT)
    assert parent["use_repair_span"] is True
    assert parent["suggested_repair_spans"][0]["repair_span_id"] == "repair-span-example"


def test_tick_draft_requires_exact_spans_to_qualify(tmp_path: Path, database: Database) -> None:
    _seed_catalogue(database)
    draft = empty_tick_draft(as_of_date=date(2026, 8, 16).isoformat())
    with pytest.raises(ValueError, match="exact spans"):
        bind_issue_tick(
            draft,
            bundle=BUNDLE,
            case_id="live30-q02",
            issue_id="issue-01",
            status="qualified",
        )
    bound = bind_issue_tick(
        draft,
        bundle=BUNDLE,
        case_id="live30-q02",
        issue_id="issue-01",
        status="knowledge_gap",
        span={
            "source_version_id": "source-version-1",
            "chunk_id": "chunk-7e5bbeb3dff523f4e7e458a42541455da30e5023",
            "content_sha256": S2_HASH,
            "legal_locator": "s 2",
        },
        catalog_path=tmp_path / "catalog.sqlite3",
    )
    assert bound["span_exact_match"] is True
    apply_contrary_authority_status(draft, status="reviewed_none")
    progress = summarize_tick_draft(draft)
    assert progress["gap"] == 1
    assert progress["spans_bound"] == 1
    assert progress["wrote_expert_qualification"] is False
    assert progress["overlay_sealable"] is False
