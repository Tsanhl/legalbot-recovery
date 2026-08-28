from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.admission import admit_for_rerank
from app.retrieval.budget import (
    RetrievalBudgetExhausted,
    abort_in_flight_retrieval,
    bind_retrieval_budget,
    estimate_rerank_seconds,
    raise_if_complete_rerank_plan_exceeds_remaining,
    raise_if_rerank_work_exceeds_remaining,
    wait_for_rerank_slot,
)
from app.retrieval.hybrid import (
    DeterministicHashEmbedding,
    HybridRetriever,
    InMemoryBM25Backend,
    InMemoryVectorBackend,
)
from app.retrieval.models import IndexedChunk, QueryFilters, SearchHit, SearchQuery
from app.retrieval.ranking_text import (
    RANKING_REPRESENTATION_VERSION,
    ranking_document_text,
    ranking_texts_leave_evidence_unchanged,
)

EMBEDDER = DeterministicHashEmbedding()


@pytest.fixture(autouse=True)
def _reset_budget():
    bind_retrieval_budget(deadline_at=None)
    yield
    bind_retrieval_budget(deadline_at=None)


def _chunk(
    chunk_id: str,
    text: str,
    *,
    source: str = "source:a",
    locator: str = "",
    title: str = "Sale of Goods Act 1979",
) -> IndexedChunk:
    return IndexedChunk(
        chunk_id=chunk_id,
        text=text,
        vector=EMBEDDER.embed_query(text),
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity=source,
        content_sha256=(chunk_id.encode("utf-8").hex() + "0" * 64)[:64],
        title=title,
        citation="Sale of Goods Act 1979",
        metadata={"locator": locator, "heading_path": ["s.18"]},
    )


def _hit(chunk: IndexedChunk, score: float) -> SearchHit:
    return SearchHit(chunk, score)


def test_rrf_union_can_exceed_channel_limit_but_rerank_cannot() -> None:
    gold = _chunk("gold", "Consideration must move from the promisee.")
    extras = [
        _chunk(f"extra-{index}", f"Tort negligence duty of care {index}", source=f"source:{index}")
        for index in range(12)
    ]
    chunks = (gold, *extras)
    retriever = HybridRetriever(
        embedder=EMBEDDER,
        lexical_backend=InMemoryBM25Backend(chunks),
        vector_backend=InMemoryVectorBackend(chunks),
        reranker=_RecordingReranker(),
    )
    filters = QueryFilters(
        jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
        material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        review_states=frozenset({"approved"}),
    )
    hits = retriever.search(
        SearchQuery(
            "consideration must move from the promisee",
            filters,
            limit=5,
            candidate_limit=8,
            lexical_candidate_limit=8,
            vector_candidate_limit=8,
            rerank_candidate_limit=5,
        )
    )
    assert retriever.last_workload["fused"] >= retriever.last_workload["admitted"]
    assert int(retriever.last_workload["rerank_input"]) <= 5
    assert len(hits) <= 5
    assert "gold" in {hit.chunk.chunk_id for hit in hits}


class _RecordingReranker:
    def __init__(self) -> None:
        self.seen = 0

    def rerank(self, query: str, hits, *, limit: int):
        del query
        self.seen = len(hits)
        return tuple(hits[:limit])


def test_admission_is_deterministic_and_drops_sibling_windows() -> None:
    first = _hit(_chunk("a1", "The same statutory duty " * 20, locator="s.18"), 0.9)
    sibling = _hit(
        _chunk("a2", "The same statutory duty " * 20, locator="s.18"),
        0.8,
    )
    other = _hit(_chunk("b1", "A different authority on consideration.", source="source:b"), 0.7)
    admitted = admit_for_rerank((first, sibling, other), rerank_candidate_limit=10)
    again = admit_for_rerank((first, sibling, other), rerank_candidate_limit=10)
    assert [hit.chunk.chunk_id for hit in admitted] == ["a1", "b1"]
    assert [hit.chunk.chunk_id for hit in again] == ["a1", "b1"]


def test_distinct_atomic_spans_at_same_statutory_locator_survive() -> None:
    duty = _hit(
        _chunk(
            "duty",
            "An occupier owes the common duty of care to visitors.",
            locator="section 2",
        ),
        0.9,
    )
    standard = _hit(
        _chunk(
            "standard",
            "The common duty requires reasonable care for visitor safety.",
            locator="section 2",
        ),
        0.8,
    )

    admitted = admit_for_rerank((duty, standard), rerank_candidate_limit=10)

    assert [hit.chunk.chunk_id for hit in admitted] == ["duty", "standard"]


def test_heavily_overlapping_windows_at_same_coordinate_collapse() -> None:
    first = _hit(
        _chunk(
            "window-a",
            "one two three four five six seven eight nine ten eleven twelve "
            "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty",
            locator="section 18",
        ),
        0.9,
    )
    overlapping = _hit(
        _chunk(
            "window-b",
            "three four five six seven eight nine ten eleven twelve thirteen fourteen "
            "fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo",
            locator="section 18",
        ),
        0.8,
    )

    admitted = admit_for_rerank((first, overlapping), rerank_candidate_limit=10)

    assert [hit.chunk.chunk_id for hit in admitted] == ["window-a"]


def test_gold_required_candidate_survives_certified_cap() -> None:
    gold = _hit(_chunk("gold", "An unpaid seller has a lien on the goods."), 1.0)
    filler = [
        _hit(_chunk(f"n{i}", f"Unrelated filler {i}", source=f"src:{i}"), 0.1) for i in range(30)
    ]
    admitted = admit_for_rerank((gold, *filler), rerank_candidate_limit=5)
    assert admitted[0].chunk.chunk_id == "gold"
    assert len(admitted) == 5


def test_ranking_text_is_bounded_and_evidence_unchanged() -> None:
    long_body = "prefix noise " * 400 + "consideration must move from the promisee " + "tail " * 400
    chunk = _chunk("span", long_body)
    original = chunk.text
    original_hash = chunk.content_sha256
    ranked = ranking_document_text(
        chunk, "consideration must move from the promisee", max_chars=200
    )
    assert len(ranked) <= 200
    assert "consideration" in ranked.casefold()
    assert chunk.text == original
    assert chunk.content_sha256 == original_hash
    assert ranking_texts_leave_evidence_unchanged(
        [_hit(chunk, 1.0)], "consideration must move from the promisee"
    )


def test_query_window_beats_useless_prefix() -> None:
    body = "A" * 400 + " the unpaid seller lien arises under the Act " + "B" * 400
    chunk = _chunk("late", body, title="Act")
    prefix = ranking_document_text(chunk, "unpaid seller lien", max_chars=80, strategy="prefix")
    window = ranking_document_text(
        chunk, "unpaid seller lien", max_chars=400, strategy="query_window"
    )
    assert "lien" in window.casefold()
    del prefix


def test_rerank_work_estimate_is_deterministic() -> None:
    first = estimate_rerank_seconds(hit_count=40, ranking_payload_tokens=1024)
    second = estimate_rerank_seconds(hit_count=40, ranking_payload_tokens=1024)
    assert first == second
    assert first < estimate_rerank_seconds(hit_count=40, ranking_payload_tokens=8192)


def test_known_overbudget_fails_before_inference() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=2))
    called = {"n": 0}

    def fake_infer() -> None:
        called["n"] += 1

    with pytest.raises(RetrievalBudgetExhausted, match="cannot fit"):
        raise_if_rerank_work_exceeds_remaining(hit_count=224, ranking_payload_tokens=8192)
        fake_infer()
    assert called["n"] == 0


def test_measured_cpu_pool_cannot_fit_research_stage() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=300))
    with pytest.raises(RetrievalBudgetExhausted, match="cannot fit"):
        raise_if_rerank_work_exceeds_remaining(hit_count=32, ranking_payload_tokens=1024)


def test_semaphore_wait_respects_abort() -> None:
    slot = threading.Semaphore(0)
    abort_in_flight_retrieval()
    with pytest.raises(RetrievalBudgetExhausted, match="aborted"):
        wait_for_rerank_slot(slot, timeout=0.05)


def test_ranking_representation_version_is_pinned() -> None:
    assert RANKING_REPRESENTATION_VERSION == "title-locator-query-window-v1"


class _ExplodingReranker:
    def rerank(self, query: str, hits, *, limit: int):
        del query, hits, limit
        raise RuntimeError("synthetic qwen failure")


def test_production_rerank_failure_is_fail_closed() -> None:
    gold = _chunk("gold", "Consideration must move from the promisee.")
    leaked = _chunk(
        "leak",
        "A Scottish authority on delict.",
        source="source:scot",
    )
    retriever = HybridRetriever(
        embedder=EMBEDDER,
        lexical_backend=InMemoryBM25Backend((gold, leaked)),
        vector_backend=InMemoryVectorBackend((gold, leaked)),
        reranker=_ExplodingReranker(),
    )
    filters = QueryFilters(
        jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
        material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        review_states=frozenset({"approved"}),
    )
    with pytest.raises(RuntimeError, match="unreranked RRF fallback is forbidden"):
        retriever.search(
            SearchQuery(
                "consideration must move from the promisee",
                filters,
                limit=5,
                candidate_limit=8,
            )
        )
    assert retriever.last_reranker_unavailable is True


def test_two_section_research_plan_fails_closed_before_qwen() -> None:
    bind_retrieval_budget(deadline_at=datetime.now(UTC) + timedelta(seconds=300))
    with pytest.raises(RetrievalBudgetExhausted, match="cannot fit"):
        raise_if_complete_rerank_plan_exceeds_remaining((32, 32), ranking_payload_tokens=1024)


def test_prepare_then_finish_keeps_hard_filters() -> None:
    gold = _chunk("gold", "Consideration must move from the promisee.")
    other = _chunk("other", "Unrelated filler on negligence.", source="source:b")

    class _Passthrough:
        def rerank(self, query: str, hits, *, limit: int):
            del query
            return tuple(hits[:limit])

    retriever = HybridRetriever(
        embedder=EMBEDDER,
        lexical_backend=InMemoryBM25Backend((gold, other)),
        vector_backend=InMemoryVectorBackend((gold, other)),
        reranker=_Passthrough(),
    )
    filters = QueryFilters(
        jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
        material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        review_states=frozenset({"approved"}),
        subjects=frozenset({"contract"}),
    )
    hits = retriever.search(
        SearchQuery(
            "consideration must move from the promisee",
            filters,
            limit=5,
            candidate_limit=8,
        )
    )
    assert retriever.last_reranker_unavailable is False
    assert {hit.chunk.chunk_id for hit in hits} <= {"gold", "other"}


def test_prepare_is_separate_from_qwen_finish() -> None:
    gold = _chunk("gold", "Consideration must move from the promisee.")
    called = {"n": 0}

    class _CountReranker:
        def rerank(self, query: str, hits, *, limit: int):
            called["n"] += 1
            del query
            return tuple(hits[:limit])

    retriever = HybridRetriever(
        embedder=EMBEDDER,
        lexical_backend=InMemoryBM25Backend((gold,)),
        vector_backend=InMemoryVectorBackend((gold,)),
        reranker=_CountReranker(),
    )
    query = SearchQuery(
        "consideration must move from the promisee",
        QueryFilters(
            jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
            material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
            review_states=frozenset({"approved"}),
        ),
        limit=5,
        candidate_limit=8,
    )
    prepared = retriever.prepare(query)
    assert called["n"] == 0
    assert prepared.admitted
    assert prepared.workload_digest
    hits = retriever.finish(prepared)
    assert called["n"] == 1
    assert hits[0].chunk.chunk_id == "gold"
