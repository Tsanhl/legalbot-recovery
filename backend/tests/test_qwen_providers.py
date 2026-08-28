from __future__ import annotations

from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.models import VECTOR_DIMENSIONS, IndexedChunk, SearchHit
from app.retrieval.qwen import QwenEmbeddingProvider, QwenRerankerProvider


class FakeArray(list[float]):
    def tolist(self):
        return list(self)


class FakeEmbeddingModel:
    def encode(self, texts, **kwargs):
        assert kwargs["normalize_embeddings"] is True
        assert kwargs["truncate_dim"] == VECTOR_DIMENSIONS
        return [FakeArray([1.0] + [0.0] * (VECTOR_DIMENSIONS - 1)) for _ in texts]


class FakeCrossEncoder:
    def predict(self, pairs, **kwargs):
        assert kwargs["show_progress_bar"] is False
        return [0.1, 0.9]


def chunk(identifier: str, text: str) -> IndexedChunk:
    return IndexedChunk(
        chunk_id=identifier,
        text=text,
        vector=tuple([1.0] + [0.0] * (VECTOR_DIMENSIONS - 1)),
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity=f"source:{identifier}",
        content_sha256=identifier * 64,
    )


def test_qwen_embedding_contract_is_exactly_1024_dimensions() -> None:
    provider = QwenEmbeddingProvider(model=FakeEmbeddingModel())
    assert len(provider.embed_query("query")) == VECTOR_DIMENSIONS
    assert len(provider.embed_documents(["a", "b"])) == 2


def test_qwen_reranker_orders_by_model_score() -> None:
    hits = [SearchHit(chunk("a", "first"), 0.5), SearchHit(chunk("b", "second"), 0.4)]
    reranked = QwenRerankerProvider(model=FakeCrossEncoder()).rerank("query", hits, limit=2)
    assert [item.chunk.chunk_id for item in reranked] == ["b", "a"]
