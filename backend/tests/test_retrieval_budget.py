from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.budget import (
    RetrievalBudgetExhausted,
    abort_in_flight_retrieval,
    bind_retrieval_budget,
    raise_if_rerank_work_exceeds_remaining,
    raise_if_retrieval_budget_exhausted,
    remaining_retrieval_seconds,
)
from app.retrieval.hybrid import DeterministicHashEmbedding, HybridRetriever
from app.retrieval.models import IndexedChunk, QueryFilters, SearchCandidate, SearchQuery

EMBEDDER = DeterministicHashEmbedding()


@pytest.fixture(autouse=True)
def _reset_retrieval_budget():
    bind_retrieval_budget(deadline_at=None)
    yield
    bind_retrieval_budget(deadline_at=None)


def test_abort_stops_rerank_batch_loop() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=30))
    seen = 0
    abort_in_flight_retrieval()
    with pytest.raises(RetrievalBudgetExhausted, match="aborted"):
        for start in range(0, 120, 4):
            raise_if_retrieval_budget_exhausted()
            seen += 1
            del start
    assert seen == 0


def test_past_deadline_exhausts_budget() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) - timedelta(seconds=1))
    assert remaining_retrieval_seconds() is not None
    assert remaining_retrieval_seconds() <= 0
    with pytest.raises(RetrievalBudgetExhausted, match="exceeded its bound deadline"):
        raise_if_retrieval_budget_exhausted()


def test_hybrid_search_does_not_swallow_retrieval_budget() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=30))

    class _ExplodingReranker:
        def rerank(self, query: str, hits, *, limit: int):
            del query, hits, limit
            abort_in_flight_retrieval()
            raise_if_retrieval_budget_exhausted()
            raise AssertionError("unreachable")

    chunk = IndexedChunk(
        chunk_id="chunk-1",
        text="A statutory duty arises under the governing Act.",
        vector=EMBEDDER.embed_query("A statutory duty arises under the governing Act."),
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity="source:chunk-1",
        content_sha256="a" * 64,
        title="Example Act",
    )

    class _Backend:
        def search(self, query: object, *, filters: QueryFilters, limit: int):
            del query, filters
            return [SearchCandidate(chunk, 1.0, rank=1, channel="lexical")][:limit]

    retriever = HybridRetriever(
        embedder=EMBEDDER,
        lexical_backend=_Backend(),
        vector_backend=_Backend(),
        reranker=_ExplodingReranker(),
    )
    with pytest.raises(RetrievalBudgetExhausted):
        retriever.search(
            SearchQuery(
                "Does a statutory duty arise under the governing Act?",
                QueryFilters(
                    jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
                    material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
                    review_states=frozenset({"approved"}),
                ),
                limit=5,
                candidate_limit=10,
            )
        )
    assert int(retriever.last_workload["admitted"]) >= 1
    assert int(retriever.last_workload["rerank_input"]) >= 1


@pytest.mark.asyncio
async def test_wait_for_propagates_work_budget_exhaustion() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=300))

    def _too_much_work() -> None:
        raise_if_rerank_work_exceeds_remaining(hit_count=32, ranking_payload_tokens=1024)

    with pytest.raises(RetrievalBudgetExhausted, match="cannot fit"):
        await asyncio.wait_for(asyncio.to_thread(_too_much_work), timeout=300)
