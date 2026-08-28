from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.retrieval.phase2a_frozen_scope import (
    CORPUS_ID,
    EXPECTED_CHUNK_COUNT,
    EXPECTED_SCOPE_CONTENT_SHA256,
    EXPECTED_SOURCE_COUNT,
    load_phase2a_frozen_scope,
    select_phase2a_frozen_scope_rows,
)
from app.retrieval.source_manifest import (
    approved_source_manifest_sha256,
    build_approved_source_manifest,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _ReadOnlyCatalogue:
    def __init__(self) -> None:
        self.connection = sqlite3.connect(
            f"file:{PROJECT_ROOT / 'data/catalog.sqlite3'}?mode=ro", uri=True
        )
        self.connection.row_factory = sqlite3.Row

    def fetchone(self, query: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        return self.connection.execute(query, parameters).fetchone()

    def fetchall(
        self, query: str, parameters: tuple[Any, ...] = ()
    ) -> list[sqlite3.Row]:
        return self.connection.execute(query, parameters).fetchall()

    def close(self) -> None:
        self.connection.close()


@pytest.fixture(scope="module")
def settings() -> Settings:
    return Settings(project_root=PROJECT_ROOT)


@pytest.fixture(scope="module")
def database() -> _ReadOnlyCatalogue:
    value = _ReadOnlyCatalogue()
    yield value
    value.close()


def test_frozen_scope_seal_and_release_boundary_are_exact(settings: Settings) -> None:
    scope = load_phase2a_frozen_scope(settings)
    assert scope["scope_content_sha256"] == EXPECTED_SCOPE_CONTENT_SHA256
    assert scope["source_count"] == EXPECTED_SOURCE_COUNT
    assert scope["chunk_count"] == EXPECTED_CHUNK_COUNT
    assert scope["owner_admitted_source_count"] == 166
    assert scope["answer_release_eligible"] is False
    assert scope["successor_must_remain_non_active"] is True
    assert scope["active_or_previous_write_authorized"] is False
    assert scope["phase2b_authorized"] is False
    assert scope["development30_authorized"] is False


def test_selector_uses_every_exact_source_version_once(
    settings: Settings, database: _ReadOnlyCatalogue
) -> None:
    rows, scope = select_phase2a_frozen_scope_rows(
        database,  # type: ignore[arg-type]
        settings,
        corpus_id=CORPUS_ID,
        max_chunks=None,
        preferred_small_first=False,
    )
    assert scope["scope_content_sha256"] == EXPECTED_SCOPE_CONTENT_SHA256
    assert len(rows) == EXPECTED_SOURCE_COUNT
    assert len({row["source_version_id"] for row in rows}) == EXPECTED_SOURCE_COUNT
    assert sum(row["body_chunk_count"] for row in rows) == EXPECTED_CHUNK_COUNT
    assert all(row["review_status"] == "approved" for row in rows)
    assert all(row["document_status"] == "citable" for row in rows)
    assert all(row["retrieval_canonical"] == 1 for row in rows)


def test_frozen_scope_refuses_chunk_caps_and_reordering(
    settings: Settings, database: _ReadOnlyCatalogue
) -> None:
    with pytest.raises(ValueError, match="cannot be reordered or truncated"):
        select_phase2a_frozen_scope_rows(
            database,  # type: ignore[arg-type]
            settings,
            corpus_id=CORPUS_ID,
            max_chunks=100,
            preferred_small_first=False,
        )
    with pytest.raises(ValueError, match="cannot be reordered or truncated"):
        select_phase2a_frozen_scope_rows(
            database,  # type: ignore[arg-type]
            settings,
            corpus_id=CORPUS_ID,
            max_chunks=None,
            preferred_small_first=True,
        )


def test_successor_manifest_is_exact_and_non_active(
    settings: Settings, database: _ReadOnlyCatalogue
) -> None:
    manifest = build_approved_source_manifest(
        database,  # type: ignore[arg-type]
        settings,
        corpus_id=CORPUS_ID,
    )
    assert manifest["source_count"] == EXPECTED_SOURCE_COUNT
    assert manifest["chunk_count"] == EXPECTED_CHUNK_COUNT
    assert manifest["selection_policy"] == (
        "exact-owner-approved-held-phase2a-successor-scope"
    )
    assert manifest["frozen_scope_content_sha256"] == EXPECTED_SCOPE_CONTENT_SHA256
    assert manifest["answer_release_eligible"] is False
    assert manifest["successor_must_remain_non_active"] is True
    assert manifest["active_or_previous_write_authorized"] is False
    assert manifest["phase2b_authorized"] is False
    assert manifest["development30_authorized"] is False
    assert manifest["manifest_sha256"] == approved_source_manifest_sha256(manifest)
