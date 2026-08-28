"""Non-negotiable query and post-retrieval filtering."""

from __future__ import annotations

from collections.abc import Iterable

from ..jurisdictions import normalise
from .models import IndexedChunk, QueryFilters, SearchCandidate


def chunk_matches(chunk: IndexedChunk, filters: QueryFilters) -> bool:
    filters.validate()
    return (
        chunk.jurisdiction in filters.jurisdictions
        and (
            not filters.exact_jurisdictions
            or normalise(str(chunk.metadata.get("catalog_jurisdiction") or ""))
            in {normalise(value) for value in filters.exact_jurisdictions}
        )
        and chunk.material_lane in filters.material_lanes
        and (not filters.subjects or chunk.subject in filters.subjects)
        and chunk.review_state in filters.review_states
    )


def enforce_candidates(
    candidates: Iterable[SearchCandidate], filters: QueryFilters
) -> list[SearchCandidate]:
    """Drop backend leaks; callers must never rely on backend filters alone."""

    return [candidate for candidate in candidates if chunk_matches(candidate.chunk, filters)]
