from __future__ import annotations

import unittest
from collections.abc import Sequence
from dataclasses import replace

from backend.app.ingestion import Jurisdiction, MaterialLane
from backend.app.retrieval import (
    VECTOR_DIMENSIONS,
    DeterministicHashEmbedding,
    DeterministicOverlapReranker,
    HybridRetriever,
    IndexedChunk,
    InMemoryBM25Backend,
    InMemoryVectorBackend,
    QueryFilters,
    SearchCandidate,
    SearchHit,
    SearchQuery,
    reciprocal_rank_fusion,
)
from backend.app.retrieval.hybrid import explicit_authority_identity

EMBEDDER = DeterministicHashEmbedding()


def _chunk(
    chunk_id: str,
    text: str,
    *,
    jurisdiction: Jurisdiction = Jurisdiction.ENGLAND_WALES,
    lane: MaterialLane = MaterialLane.PRIMARY_AUTHORITY,
    subject: str = "contract",
    review_state: str = "approved",
    catalog_jurisdiction: str | None = None,
) -> IndexedChunk:
    return IndexedChunk(
        chunk_id=chunk_id,
        text=text,
        vector=EMBEDDER.embed_query(text),
        jurisdiction=jurisdiction,
        material_lane=lane,
        subject=subject,
        review_state=review_state,
        source_identity=f"source:{chunk_id}",
        content_sha256=(chunk_id.encode("utf-8").hex() + "0" * 64)[:64],
        title=f"Source {chunk_id}",
        metadata={"catalog_jurisdiction": catalog_jurisdiction} if catalog_jurisdiction else {},
    )


class _LeakyBackend:
    def __init__(self, chunks: Sequence[IndexedChunk], channel: str) -> None:
        self.chunks = chunks
        self.channel = channel

    def search(
        self, value: object, *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]:
        del value, filters
        return tuple(
            SearchCandidate(chunk, 1.0 / rank, rank, self.channel)
            for rank, chunk in enumerate(self.chunks[:limit], 1)
        )


class _InjectingReranker:
    def __init__(self, injected: IndexedChunk) -> None:
        self.injected = injected

    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> Sequence[SearchHit]:
        del query
        return (SearchHit(self.injected, 999.0, rerank_score=999.0), *hits)[:limit]


class _IdentityBackend(_LeakyBackend):
    def search_identity(
        self, source_identity: str, *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]:
        del filters
        matches = [chunk for chunk in self.chunks if chunk.source_identity == source_identity]
        return tuple(
            SearchCandidate(chunk, 1.0 / rank, rank, "identity")
            for rank, chunk in enumerate(matches[:limit], 1)
        )


class _ForbiddenEmbedder:
    dimensions = VECTOR_DIMENSIONS

    def embed_query(self, text: str) -> tuple[float, ...]:
        del text
        raise AssertionError("identifier-only routing must not invoke embeddings")


class _ForbiddenReranker:
    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> Sequence[SearchHit]:
        del query, hits, limit
        raise AssertionError("identifier-only routing must not invoke reranking")


class HybridRetrievalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.allowed = _chunk("allowed", "Promissory estoppel requires reliance on the promise.")
        self.wrong_jurisdiction = _chunk(
            "comparative",
            "Promissory estoppel reliance authority.",
            jurisdiction=Jurisdiction.COMPARATIVE,
        )
        self.wrong_lane = _chunk(
            "lecture", "Promissory estoppel reliance lecture.", lane=MaterialLane.LECTURE_NOTE
        )
        self.unreviewed = _chunk(
            "unreviewed", "Promissory estoppel reliance new case.", review_state="unreviewed"
        )
        self.filters = QueryFilters(
            jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
            material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
            subjects=frozenset({"contract"}),
            review_states=frozenset({"approved"}),
        )

    def test_embedding_is_deterministic_and_exactly_1024_dimensions(self) -> None:
        first = EMBEDDER.embed_query("Hadley v Baxendale remoteness")
        second = EMBEDDER.embed_query("Hadley v Baxendale remoteness")
        self.assertEqual(len(first), VECTOR_DIMENSIONS)
        self.assertEqual(first, second)

    def test_in_memory_hybrid_search_applies_hard_filters(self) -> None:
        chunks = (self.allowed, self.wrong_jurisdiction, self.wrong_lane, self.unreviewed)
        retriever = HybridRetriever(
            embedder=EMBEDDER,
            lexical_backend=InMemoryBM25Backend(chunks),
            vector_backend=InMemoryVectorBackend(chunks),
            reranker=DeterministicOverlapReranker(),
        )
        hits = retriever.search(
            SearchQuery("promissory estoppel reliance", self.filters, limit=5, candidate_limit=10)
        )
        self.assertEqual([hit.chunk.chunk_id for hit in hits], ["allowed"])
        self.assertIsNotNone(hits[0].lexical_rank)
        self.assertIsNotNone(hits[0].vector_rank)
        self.assertIsNotNone(hits[0].rerank_score)

    def test_explicit_neutral_citation_uses_exact_identity_route(self) -> None:
        identity = "neutral-citation:[2017] UKSC 51"
        authority = replace(self.allowed, source_identity=identity)
        retriever = HybridRetriever(
            embedder=_ForbiddenEmbedder(),
            lexical_backend=_IdentityBackend((authority,), "identity"),
            vector_backend=_LeakyBackend((), "vector"),
            reranker=_ForbiddenReranker(),
        )
        hits = retriever.search(SearchQuery("[2017] UKSC 51", self.filters, limit=5))
        self.assertEqual([hit.chunk.source_identity for hit in hits], [identity])
        self.assertEqual(hits[0].diagnostics["route"], "exact_authority_identity")
        self.assertEqual(retriever.last_timings_ms["rerank"], 0.0)
        self.assertIsNone(explicit_authority_identity("What did [2017] UKSC 51 hold?"))

    def test_filters_are_reapplied_after_unsafe_backends_and_reranker(self) -> None:
        leaked = (self.wrong_jurisdiction, self.wrong_lane, self.unreviewed, self.allowed)
        retriever = HybridRetriever(
            embedder=EMBEDDER,
            lexical_backend=_LeakyBackend(leaked, "lexical"),
            vector_backend=_LeakyBackend(leaked, "vector"),
            reranker=_InjectingReranker(self.wrong_jurisdiction),
        )
        hits = retriever.search(SearchQuery("reliance", self.filters, limit=4, candidate_limit=10))
        self.assertEqual([hit.chunk.chunk_id for hit in hits], ["allowed"])

    def test_exact_jurisdiction_prevents_comparative_pool_contamination(self) -> None:
        united_states = _chunk(
            "us",
            "Constitutional due process authority.",
            jurisdiction=Jurisdiction.COMPARATIVE,
            catalog_jurisdiction="United States",
        )
        canada = _chunk(
            "canada",
            "Constitutional due process authority.",
            jurisdiction=Jurisdiction.COMPARATIVE,
            catalog_jurisdiction="Canada",
        )
        filters = QueryFilters(
            jurisdictions=frozenset({Jurisdiction.COMPARATIVE}),
            material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
            exact_jurisdictions=frozenset({"canada"}),
            subjects=frozenset({"contract"}),
        )
        retriever = HybridRetriever(
            embedder=EMBEDDER,
            lexical_backend=_LeakyBackend((united_states, canada), "lexical"),
            vector_backend=_LeakyBackend((united_states, canada), "vector"),
            reranker=DeterministicOverlapReranker(),
        )

        hits = retriever.search(
            SearchQuery("constitutional due process", filters, limit=5, candidate_limit=10)
        )

        self.assertEqual([hit.chunk.chunk_id for hit in hits], ["canada"])

    def test_rrf_rewards_a_candidate_present_in_both_channels(self) -> None:
        other = _chunk("other", "A different authority")
        lexical = (
            SearchCandidate(self.allowed, 4.0, 1, "lexical"),
            SearchCandidate(other, 3.0, 2, "lexical"),
        )
        vector = (SearchCandidate(self.allowed, 0.8, 3, "vector"),)
        hits = reciprocal_rank_fusion(lexical, vector)
        self.assertEqual(hits[0].chunk.chunk_id, "allowed")
        self.assertEqual(hits[0].lexical_rank, 1)
        self.assertEqual(hits[0].vector_rank, 3)

    def test_query_requires_both_jurisdiction_and_material_lane(self) -> None:
        with self.assertRaises(ValueError):
            SearchQuery(
                "test",
                QueryFilters(
                    jurisdictions=frozenset(),
                    material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
                ),
            ).validate()
        with self.assertRaises(ValueError):
            SearchQuery(
                "test",
                QueryFilters(
                    jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
                    material_lanes=frozenset(),
                ),
            ).validate()


if __name__ == "__main__":
    unittest.main()
