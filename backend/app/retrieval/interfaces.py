"""Database and model protocols; concrete integrations live outside core logic."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Protocol

from .models import IndexedChunk, QueryFilters, SearchCandidate, SearchHit


class QueryEmbedder(Protocol):
    dimensions: int

    def embed_query(self, text: str) -> Sequence[float]: ...

    def embed_documents(self, texts: Sequence[str]) -> Sequence[Sequence[float]]: ...


class LexicalSearchBackend(Protocol):
    def search(
        self, text: str, *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]: ...


class VectorSearchBackend(Protocol):
    def search(
        self, vector: Sequence[float], *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]: ...


class Reranker(Protocol):
    def rerank(
        self, query: str, hits: Sequence[SearchHit], *, limit: int
    ) -> Sequence[SearchHit]: ...


class LanceBuildSession(Protocol):
    """Narrow seam implemented by a real LanceDB integration."""

    def write_chunks(
        self,
        chunks: Iterable[IndexedChunk],
        *,
        on_flush: Callable[[int], None] | None = None,
    ) -> int: ...

    def create_indexes(self) -> None: ...

    def close(self) -> None: ...


class LanceSessionFactory(Protocol):
    def create(self, generation_path: Path) -> LanceBuildSession: ...
