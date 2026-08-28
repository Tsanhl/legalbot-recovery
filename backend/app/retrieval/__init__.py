"""Authority-aware immutable hybrid retrieval interfaces."""

from .filters import chunk_matches, enforce_candidates
from .hybrid import (
    DeterministicHashEmbedding,
    DeterministicOverlapReranker,
    HybridRetriever,
    InMemoryBM25Backend,
    InMemoryVectorBackend,
    reciprocal_rank_fusion,
)
from .interfaces import (
    LanceBuildSession,
    LanceSessionFactory,
    LexicalSearchBackend,
    QueryEmbedder,
    Reranker,
    VectorSearchBackend,
)
from .lancedb import ActiveGeneration, ImmutableLanceRepository, IndexBuildManifest
from .models import (
    VECTOR_DIMENSIONS,
    IndexedChunk,
    QueryFilters,
    SearchCandidate,
    SearchHit,
    SearchQuery,
    ensure_vector,
)

__all__ = [
    "VECTOR_DIMENSIONS",
    "ActiveGeneration",
    "DeterministicHashEmbedding",
    "DeterministicOverlapReranker",
    "HybridRetriever",
    "ImmutableLanceRepository",
    "InMemoryBM25Backend",
    "InMemoryVectorBackend",
    "IndexBuildManifest",
    "IndexedChunk",
    "LanceBuildSession",
    "LanceSessionFactory",
    "LexicalSearchBackend",
    "QueryEmbedder",
    "QueryFilters",
    "Reranker",
    "SearchCandidate",
    "SearchHit",
    "SearchQuery",
    "VectorSearchBackend",
    "chunk_matches",
    "enforce_candidates",
    "ensure_vector",
    "reciprocal_rank_fusion",
]
