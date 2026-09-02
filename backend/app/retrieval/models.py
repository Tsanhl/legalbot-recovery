"""Retrieval records with mandatory jurisdiction and material-lane metadata."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from ..ingestion.models import Jurisdiction, MaterialLane

VECTOR_DIMENSIONS = 1024


@dataclass(frozen=True, slots=True)
class QueryFilters:
    jurisdictions: frozenset[Jurisdiction]
    material_lanes: frozenset[MaterialLane]
    exact_jurisdictions: frozenset[str] = frozenset()
    subjects: frozenset[str] = frozenset()
    review_states: frozenset[str] = frozenset({"approved"})

    def validate(self) -> None:
        if not self.jurisdictions:
            raise ValueError("at least one jurisdiction is required")
        if not self.material_lanes:
            raise ValueError("at least one material lane is required")
        if any(not value.strip() for value in self.exact_jurisdictions):
            raise ValueError("exact jurisdiction filters cannot be empty")
        if not self.review_states:
            raise ValueError("at least one review state is required")


@dataclass(frozen=True, slots=True)
class SearchQuery:
    text: str
    filters: QueryFilters
    limit: int = 10
    candidate_limit: int = 50
    lexical_candidate_limit: int | None = None
    vector_candidate_limit: int | None = None
    rerank_candidate_limit: int | None = None

    def lexical_limit(self) -> int:
        if self.lexical_candidate_limit is not None:
            return self.lexical_candidate_limit
        return self.candidate_limit

    def vector_limit(self) -> int:
        if self.vector_candidate_limit is not None:
            return self.vector_candidate_limit
        return self.candidate_limit

    def rerank_limit(self) -> int:
        if self.rerank_candidate_limit is not None:
            return self.rerank_candidate_limit
        return self.candidate_limit

    def validate(self) -> None:
        if not self.text.strip():
            raise ValueError("query text is required")
        if self.limit < 1:
            raise ValueError("limit must be at least 1")
        if self.lexical_limit() < self.limit or self.vector_limit() < self.limit:
            raise ValueError("search depth must be at least limit")
        if self.rerank_limit() < self.limit:
            raise ValueError("rerank_candidate_limit must be at least limit")
        self.filters.validate()


@dataclass(frozen=True, slots=True)
class IndexedChunk:
    chunk_id: str
    text: str
    vector: tuple[float, ...]
    jurisdiction: Jurisdiction
    material_lane: MaterialLane
    subject: str
    review_state: str
    source_identity: str
    content_sha256: str
    title: str | None = None
    canonical_url: str | None = None
    citation: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        ensure_vector(self.vector)
        if not self.chunk_id or not self.text.strip() or not self.source_identity:
            raise ValueError("chunk id, text and source identity are required")


@dataclass(frozen=True, slots=True)
class SearchCandidate:
    chunk: IndexedChunk
    score: float
    rank: int
    channel: str


@dataclass(frozen=True, slots=True)
class SearchHit:
    chunk: IndexedChunk
    score: float
    lexical_rank: int | None = None
    vector_rank: int | None = None
    rerank_score: float | None = None
    diagnostics: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RetrievalPlanItem:
    """One research-stage query. Cheap prepare first; Qwen only after the plan fits."""

    query: str
    jurisdiction: str
    subject: str | None
    as_of_date: date
    limit: int = 30
    cacheable: bool = True
    query_rewrite_version: str = "none-v1"
    lexical_depth: int | None = None
    vector_depth: int | None = None
    reranker_candidates: int | None = None


def ensure_vector(vector: Sequence[float]) -> tuple[float, ...]:
    if len(vector) != VECTOR_DIMENSIONS:
        raise ValueError(f"expected {VECTOR_DIMENSIONS}-dimensional vector, received {len(vector)}")
    converted = tuple(float(value) for value in vector)
    if any(not math.isfinite(value) for value in converted):
        raise ValueError("vectors must contain only finite values")
    return converted
