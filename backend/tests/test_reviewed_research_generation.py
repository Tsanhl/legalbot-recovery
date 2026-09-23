from __future__ import annotations

import hashlib
from datetime import date

import pytest

from app.citations.oscola import render_oscola
from app.config import Settings
from app.retrieval.reviewed_research_generation import (
    ReviewedResearchGenerationRetriever,
    register_scoped_development_retrieval_candidate,
)


def _frozen_fixture():
    source_sha256 = "a" * 64
    capture_sha256 = "b" * 64
    text = "section 22 The short-term right to reject is subject to a time limit."
    manifest = {
        "candidate_build_id": "candidate-visible-r1",
        "jurisdiction": "England",
        "as_of_date": "2026-09-05",
        "subject": "consumer-law",
        "source_review_attestation_sha256": "c" * 64,
        "seal_sha256": "d" * 64,
        "sources": [
            {
                "capture_sha256": capture_sha256,
                "source_sha256": source_sha256,
                "source_identity_id": "e" * 64,
                "title": "Consumer Rights Act 2015",
                "canonical_url": "https://www.legislation.gov.uk/ukpga/2015/15/data.xml",
                "source_type": "legislation",
            }
        ],
    }
    rows = (
        {
            "id": "f" * 64,
            "capture_sha256": capture_sha256,
            "text": text,
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "structural_chunk": {
                "chunk_id": f"sha256:{'1' * 64}",
                "ordinal": 22,
                "heading_path": ["PART 1", "CHAPTER 2"],
                "stream": "body",
                "metadata": {
                    "legal_locator": "section 22",
                    "legal_locator_kind": "legislative_provision",
                },
            },
        },
    )
    return manifest, rows


@pytest.mark.asyncio
async def test_candidate_registration_supplies_research_only_evidence_custody(
    tmp_path, database, monkeypatch
):
    settings = Settings(
        project_root=tmp_path,
        development_state_id="ge-qwen-test",
        development_candidate_build_id="candidate-visible-r1",
    )
    manifest, rows = _frozen_fixture()
    monkeypatch.setattr(
        ReviewedResearchGenerationRetriever,
        "_load",
        lambda self: (manifest, rows),
    )

    assert register_scoped_development_retrieval_candidate(settings, database) == 1
    assert register_scoped_development_retrieval_candidate(settings, database) == 1
    assert database.active_index_id() is None

    document = database.fetchone("SELECT * FROM documents")
    version = database.fetchone("SELECT * FROM source_versions")
    chunk = database.fetchone("SELECT * FROM chunks")
    assert document is not None and document["status"] == "quarantined"
    assert document["retrieval_canonical"] == 0
    assert document["searchable_text"] == 0
    assert version is not None and version["review_status"] == "staged"
    assert '"production_admitted":false' in version["metadata_json"]
    assert chunk is not None and chunk["source_version_id"] == version["id"]

    retriever = ReviewedResearchGenerationRetriever(
        settings, settings.development_candidate_build_id
    )
    retriever._receipt_rank = {rows[0]["id"]: 1}
    evidence = await retriever.retrieve(
        query="short term right reject time limit",
        jurisdiction="England",
        subject="consumer-law",
        as_of_date=date(2026, 9, 5),
        limit=1,
    )
    assert len(evidence) == 1
    assert evidence[0].canonical_citation == "Consumer Rights Act 2015, s 22"
    assert evidence[0].canonical_citation == render_oscola(evidence[0].citation_data)
    database.store_evidence([evidence[0].model_dump(mode="json")])
    stored = database.fetchone("SELECT * FROM evidence_spans")
    assert stored is not None
    assert stored["source_version_id"] == version["id"]
    assert stored["chunk_id"] == chunk["id"]
    assert stored["index_build_id"] == settings.development_candidate_build_id


def test_candidate_registration_fails_on_changed_catalogue_identity(
    tmp_path, database, monkeypatch
):
    settings = Settings(
        project_root=tmp_path,
        development_state_id="ge-qwen-test",
        development_candidate_build_id="candidate-visible-r1",
    )
    manifest, rows = _frozen_fixture()
    monkeypatch.setattr(
        ReviewedResearchGenerationRetriever,
        "_load",
        lambda self: (manifest, rows),
    )
    register_scoped_development_retrieval_candidate(settings, database)
    database.execute("UPDATE chunks SET markdown_text='changed'")
    with pytest.raises(RuntimeError, match="chunk identity differs"):
        register_scoped_development_retrieval_candidate(settings, database)
