from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from importlib import import_module
from typing import Any

from .models import VECTOR_DIMENSIONS, SearchHit, ensure_vector

EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-0.6B"
RERANKER_MODEL = "Qwen/Qwen3-Reranker-0.6B"
LEGAL_RETRIEVAL_INSTRUCTION = (
    "Given a legal research query, retrieve relevant authoritative passages that support "
    "accurate current-law analysis for the specified jurisdiction"
)


class QwenEmbeddingProvider:
    dimensions = VECTOR_DIMENSIONS

    def __init__(
        self,
        model_name: str = EMBEDDING_MODEL,
        *,
        device: str | None = None,
        model: Any | None = None,
    ) -> None:
        self.model_name = model_name
        if model is None:
            sentence_transformers = import_module("sentence_transformers")
            model = sentence_transformers.SentenceTransformer(model_name, device=device)
        self.model = model

    def embed_query(self, text: str) -> tuple[float, ...]:
        vector = self.model.encode(
            [text],
            prompt=f"Instruct: {LEGAL_RETRIEVAL_INSTRUCTION}\nQuery:",
            normalize_embeddings=True,
            truncate_dim=VECTOR_DIMENSIONS,
            show_progress_bar=False,
        )[0]
        return ensure_vector(vector.tolist() if hasattr(vector, "tolist") else vector)

    def embed_documents(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        if not texts:
            return ()
        vectors = self.model.encode(
            list(texts),
            normalize_embeddings=True,
            truncate_dim=VECTOR_DIMENSIONS,
            show_progress_bar=False,
        )
        return tuple(
            ensure_vector(vector.tolist() if hasattr(vector, "tolist") else vector)
            for vector in vectors
        )


class QwenRerankerProvider:
    def __init__(
        self,
        model_name: str = RERANKER_MODEL,
        *,
        device: str | None = None,
        model: Any | None = None,
    ) -> None:
        self.model_name = model_name
        if model is None:
            sentence_transformers = import_module("sentence_transformers")
            model = sentence_transformers.CrossEncoder(
                model_name,
                device=device,
                max_length=8192,
                prompts={"legal": LEGAL_RETRIEVAL_INSTRUCTION},
                default_prompt_name="legal",
            )
        self.model = model

    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> tuple[SearchHit, ...]:
        if not hits:
            return ()
        pairs = [(query, hit.chunk.text) for hit in hits]
        raw_scores = self.model.predict(pairs, show_progress_bar=False)
        rescored = [
            replace(
                hit,
                rerank_score=float(score),
                diagnostics={
                    **hit.diagnostics,
                    "reranker": self.model_name,
                    "instruction": LEGAL_RETRIEVAL_INSTRUCTION,
                },
            )
            for hit, score in zip(hits, raw_scores, strict=True)
        ]
        rescored.sort(
            key=lambda item: (
                -(item.rerank_score or float("-inf")),
                -item.score,
                item.chunk.chunk_id,
            )
        )
        return tuple(rescored[:limit])
