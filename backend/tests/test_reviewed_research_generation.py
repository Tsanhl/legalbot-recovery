from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import date

import pytest

from app.citations.oscola import render_oscola
from app.config import Settings
from app.retrieval.reviewed_research_generation import (
    ReviewedResearchGenerationRetriever,
    _retain_receipt_context,
    provision_context_rows,
    register_scoped_development_retrieval_candidate,
)


def test_provision_context_preserves_rule_conditions_and_original_hashes():
    _, rows = _frozen_fixture()
    first = deepcopy(rows[0])
    second = deepcopy(first)
    first["text"] = "section 22 The period starts after all these events—"
    first["text_sha256"] = hashlib.sha256(first["text"].encode()).hexdigest()
    second["id"] = "2" * 64
    second["text"] = "section 22 the goods have been delivered."
    second["text_sha256"] = hashlib.sha256(second["text"].encode()).hexdigest()
    second["structural_chunk"]["ordinal"] += 1
    original = deepcopy((first, second))
    parents = provision_context_rows((second, first))
    assert len(parents) == 1
    parent = parents[0]
    assert parent["text"] == first["text"] + "\n" + second["text"]
    assert parent["text_sha256"] == hashlib.sha256(parent["text"].encode()).hexdigest()
    assert parent["structural_chunk"]["chunk_id"].startswith("context:")
    assert (first, second) == original
    second["text"] = "tampered"
    with pytest.raises(RuntimeError, match="child_text_changed"):
        provision_context_rows((first, second))


def test_provision_context_cannot_cross_review_or_source_boundaries():
    _, rows = _frozen_fixture()
    second = deepcopy(rows[0])
    second["id"] = "2" * 64
    second["review_sha256"] = "different-review"
    with pytest.raises(RuntimeError, match="mixed_review_scope"):
        provision_context_rows((*rows, second))
    second["capture_sha256"] = "different-source"
    assert provision_context_rows((*rows, second)) == ()


def test_hosted_selection_keeps_whole_provision_above_local_budget():
    from app.runtime_adapters import select_fully_visible_evidence
    from app.types import EvidenceSpan
    text = "Complete statutory rule with all qualifications. " * 190
    span = EvidenceSpan(
        id="whole-provision", source_version_id="source", chunk_id="chunk",
        text=text.strip(), locator="section 9", lane="primary_authority",
        jurisdiction="England", subject="consumer", content_sha256="a" * 64,
        index_build_id="candidate",
    )
    assert not select_fully_visible_evidence([span]).spans
    hosted = select_fully_visible_evidence([span], char_budget=45000, token_budget=15000)
    assert hosted.spans == (span,)
    assert not hosted.omitted_ids


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


def test_frozen_receipt_retains_reviewed_context_beyond_selected_hits() -> None:
    rows = {"hit": {"id": "hit"}, "context": {"id": "context"}}
    retained: dict[str, dict] = {}
    ranks: dict[str, int] = {}

    _retain_receipt_context(rows, ["hit"], retained, ranks)

    assert set(retained) == {"hit", "context"}
    assert ranks == {"hit": 1}
    with pytest.raises(RuntimeError, match="selection_invalid"):
        _retain_receipt_context(rows, ["missing"], {}, {})
    with pytest.raises(RuntimeError, match="context_conflict"):
        _retain_receipt_context(rows, ["hit"], {"context": {"id": "altered"}}, {})


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


def test_parent_context_registration_keeps_vector_counts_and_unique_ordinals(
    tmp_path, database, monkeypatch
):
    settings = Settings(project_root=tmp_path, development_state_id="ge-qwen-test",
                        development_candidate_build_id="candidate-visible-r1")
    manifest, rows = _frozen_fixture()
    second = deepcopy(rows[0])
    second["id"] = "2" * 64
    second["structural_chunk"]["chunk_id"] = "sha256:" + "3" * 64
    second["structural_chunk"]["ordinal"] += 1
    monkeypatch.setattr(ReviewedResearchGenerationRetriever, "_load",
                        lambda self: (manifest, (*rows, second)))
    assert register_scoped_development_retrieval_candidate(settings, database) == 3
    assert register_scoped_development_retrieval_candidate(settings, database) == 3
    build = database.fetchone("SELECT chunk_count, vector_count FROM index_builds")
    assert build["chunk_count"] == 3
    assert build["vector_count"] == 2
    assert database.active_index_id() is None
