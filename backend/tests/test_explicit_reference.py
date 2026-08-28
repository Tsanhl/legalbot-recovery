from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

import pytest

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.explicit_reference import (
    CandidateLegislationReferenceResolver,
    canonical_legislation_locator,
    legislation_locator_within,
)
from app.retrieval.hybrid import HybridRetriever
from app.retrieval.models import (
    VECTOR_DIMENSIONS,
    IndexedChunk,
    QueryFilters,
    SearchCandidate,
    SearchHit,
    SearchQuery,
)
from app.retrieval.source_manifest import MANIFEST_SCHEMA, approved_source_manifest_sha256


def _manifest(*sources: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "sources": list(sources),
    }
    payload["manifest_sha256"] = approved_source_manifest_sha256(payload)
    return payload


def _source(title: str, identity: str, *, count: int = 12) -> dict[str, object]:
    return {
        "title": title,
        "stable_identifier": identity,
        "body_chunk_count": count,
    }


def _chunk(
    chunk_id: str,
    *,
    source: str,
    locator: str,
    lane: MaterialLane = MaterialLane.PRIMARY_AUTHORITY,
) -> IndexedChunk:
    return IndexedChunk(
        chunk_id=chunk_id,
        text=f"Atomic statutory text for {locator}.",
        vector=(0.0,) * VECTOR_DIMENSIONS,
        jurisdiction=Jurisdiction.UNITED_KINGDOM,
        material_lane=lane,
        subject="trusts",
        review_state="approved",
        source_identity=source,
        content_sha256=(chunk_id.encode().hex() + "0" * 64)[:64],
        title="Example Trustee Act 2031",
        metadata={"locator": locator, "catalog_jurisdiction": "United Kingdom"},
    )


class _ForbiddenEmbedder:
    dimensions = VECTOR_DIMENSIONS

    def embed_query(self, text: str) -> tuple[float, ...]:
        del text
        raise AssertionError("exact statute routing must not invoke embeddings")


class _ForbiddenVector:
    def search(self, value: object, *, filters: QueryFilters, limit: int):
        del value, filters, limit
        raise AssertionError("exact statute routing must not invoke vector retrieval")


class _ReferenceBackend:
    def __init__(self, chunks: Sequence[IndexedChunk]) -> None:
        self.chunks = chunks

    def search(self, text: str, *, filters: QueryFilters, limit: int):
        del text, filters, limit
        raise AssertionError("exact statute routing must not invoke generic lexical search")

    def search_reference(self, reference, *, filters: QueryFilters, limit: int):
        del reference, filters
        return tuple(
            SearchCandidate(chunk, 1.0 / rank, rank, "explicit_reference")
            for rank, chunk in enumerate(self.chunks[:limit], 1)
        )


class _RecordingReranker:
    def __init__(self, injected: IndexedChunk | None = None) -> None:
        self.seen: tuple[str, ...] = ()
        self.injected = injected

    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> Sequence[SearchHit]:
        del query
        self.seen = tuple(hit.chunk.chunk_id for hit in hits)
        reranked = tuple(replace(hit, rerank_score=1.0) for hit in hits)
        if self.injected is not None:
            reranked = (SearchHit(self.injected, 99.0, rerank_score=99.0), *reranked)
        return reranked[:limit]


def test_candidate_manifest_resolves_arbitrary_title_and_section() -> None:
    resolver = CandidateLegislationReferenceResolver.from_manifest(
        _manifest(
            _source(
                "Example Trustee Act 2031",
                "ukpga:2031:7:latest-available@2031-04-05",
            )
        )
    )

    reference = resolver.resolve("What duty is imposed by Example Trustee Act 2031 s. 18(2)?")

    assert reference is not None
    assert reference.source_identity == "ukpga:2031:7:latest-available@2031-04-05"
    assert reference.locator == "section 18(2)"


def test_title_matching_normalises_apostrophes_and_rejects_ambiguity() -> None:
    resolver = CandidateLegislationReferenceResolver.from_manifest(
        _manifest(
            _source(
                "Occupiers’ Liability Act 2031",
                "ukpga:2031:8:latest-available@2031-04-05",
            )
        )
    )

    assert resolver.resolve("Occupiers' Liability Act 2031 section 2") is not None
    assert resolver.resolve("Occupiers' Liability Act 2031 sections 2 and 3") is None
    assert resolver.resolve("Unknown Act 2031 section 2") is None


def test_duplicate_candidate_title_fails_closed() -> None:
    resolver = CandidateLegislationReferenceResolver.from_manifest(
        _manifest(
            _source("Example Act 2031", "ukpga:2031:1:latest-available@2031-04-05"),
            _source("Example Act 2031", "ukpga:2031:2:latest-available@2031-04-05"),
        )
    )

    assert resolver.resolve("Example Act 2031 section 1") is None


def test_manifest_digest_mismatch_is_rejected() -> None:
    manifest = _manifest(_source("Example Act 2031", "ukpga:2031:1:latest-available@2031-04-05"))
    manifest["manifest_sha256"] = "0" * 64

    with pytest.raises(RuntimeError, match="identity is invalid"):
        CandidateLegislationReferenceResolver.from_manifest(manifest)


def test_locator_matching_is_section_bounded() -> None:
    assert canonical_legislation_locator("s 14A(1) chapeau") == "section 14A(1)"
    assert legislation_locator_within("section 14A(1)(b)", "section 14A") is True
    assert legislation_locator_within("section 14", "section 14A") is False
    assert legislation_locator_within("schedule 1", "section 1") is False


def test_exact_reference_route_is_candidate_bound_filtered_and_reranked() -> None:
    source = "ukpga:2031:7:latest-available@2031-04-05"
    resolver = CandidateLegislationReferenceResolver.from_manifest(
        _manifest(_source("Example Trustee Act 2031", source, count=5))
    )
    section = _chunk("section", source=source, locator="section 1")
    descendant = _chunk("descendant", source=source, locator="s 1(1) chapeau")
    wrong_locator = _chunk("schedule", source=source, locator="schedule 1")
    wrong_source = _chunk(
        "wrong-source",
        source="ukpga:2031:8:latest-available@2031-04-05",
        locator="section 1",
    )
    wrong_lane = _chunk(
        "teaching", source=source, locator="section 1", lane=MaterialLane.LECTURE_NOTE
    )
    reranker = _RecordingReranker(injected=wrong_source)
    retriever = HybridRetriever(
        embedder=_ForbiddenEmbedder(),
        lexical_backend=_ReferenceBackend(
            (wrong_locator, wrong_source, wrong_lane, descendant, section)
        ),
        vector_backend=_ForbiddenVector(),
        reranker=reranker,
        reference_resolver=resolver,
    )
    filters = QueryFilters(
        jurisdictions=frozenset({Jurisdiction.UNITED_KINGDOM}),
        material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        exact_jurisdictions=frozenset({"United Kingdom"}),
        review_states=frozenset({"approved"}),
    )

    hits = retriever.search(
        SearchQuery(
            "What duty is set by Example Trustee Act 2031 section 1?",
            filters,
            limit=5,
            candidate_limit=5,
        )
    )

    assert {hit.chunk.chunk_id for hit in hits} == {"section", "descendant"}
    assert set(reranker.seen) == {"section", "descendant"}
    assert retriever.last_workload["route"] == "exact_legislation_reference"
    assert {hit.diagnostics["route"] for hit in hits} == {"exact_legislation_reference"}


def test_resolved_but_missing_section_fails_closed_without_generic_fallback() -> None:
    source = "ukpga:2031:7:latest-available@2031-04-05"
    resolver = CandidateLegislationReferenceResolver.from_manifest(
        _manifest(_source("Example Trustee Act 2031", source, count=1))
    )
    reranker = _RecordingReranker()
    retriever = HybridRetriever(
        embedder=_ForbiddenEmbedder(),
        lexical_backend=_ReferenceBackend(
            (_chunk("schedule", source=source, locator="schedule 1"),)
        ),
        vector_backend=_ForbiddenVector(),
        reranker=reranker,
        reference_resolver=resolver,
    )
    filters = QueryFilters(
        jurisdictions=frozenset({Jurisdiction.UNITED_KINGDOM}),
        material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        review_states=frozenset({"approved"}),
    )

    hits = retriever.search(SearchQuery("Example Trustee Act 2031 section 1", filters, limit=5))

    assert hits == ()
    assert reranker.seen == ()
    assert retriever.last_workload["route"] == "exact_legislation_reference"
