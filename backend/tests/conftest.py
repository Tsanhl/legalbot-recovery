from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.db import Database, utc_iso
from app.types import EvidenceSpan, MaterialLane


@pytest.fixture
def cipher() -> LocalCipher:
    return LocalCipher(Fernet(Fernet.generate_key()))


@pytest.fixture
def database(tmp_path: Path) -> Database:
    instance = Database(tmp_path / "catalog.sqlite3")
    instance.initialize()
    yield instance
    instance.close()


@pytest.fixture
def evidence(database: Database) -> EvidenceSpan:
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
          currentness_status, review_status, created_at
        ) VALUES ('source-version-1', 'doc-1', ?, 'data/vault/aa/source.md',
                  'Example Act 2026', 'current', 'approved', ?)
        """,
        ("b" * 64, now),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count
        ) VALUES ('chunk-1', 'source-version-1', 0, 's 1', ?,
                  'The verified statutory proposition.', 5)
        """,
        ("c" * 64,),
    )
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at, promoted_at
        ) VALUES ('build-1', 'active', 'data/indexes/build-1', 1, 1, 1,
                  'Qwen/Qwen3-Embedding-0.6B', 'Qwen/Qwen3-Reranker-0.6B', ?, ?)
        """,
        (now, now),
    )
    return EvidenceSpan(
        id="evidence-1",
        source_version_id="source-version-1",
        chunk_id="chunk-1",
        text="The verified statutory proposition.",
        locator="s 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="contract",
        citation_data={
            "source_type": "legislation",
            "title": "Example Act 2026",
            "provision": "s 1",
        },
        canonical_citation="Example Act 2026, s 1",
        currentness_status="current",
        content_sha256="c" * 64,
        index_build_id="build-1",
        canonical_url="https://www.legislation.gov.uk/example",
        retrieval_relevance_score=0.99,
        legal_role="holding_ratio",
        identity_verified=True,
        currentness_verified=True,
    )
