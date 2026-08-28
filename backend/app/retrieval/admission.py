"""Deterministic pre-rerank admission.

Hard legal filters already ran. This module only bounds the expensive Qwen
workload: unique chunks, overlapping sibling windows, per-source diversity,
then a stable top-N by RRF score.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence

from .models import SearchHit

ADMISSION_VERSION = "rrf-content-sibling-source-cap-v2"
DEFAULT_MAX_PER_SOURCE = 8
_ORDINAL = re.compile(r"(?:para(?:graph)?|section|s|art(?:icle)?|cl(?:ause)?)\s*(\d+)", re.I)
_WORD = re.compile(r"[a-z0-9]+")
_SHINGLE_SIZE = 5
_SIBLING_OVERLAP_THRESHOLD = 0.80


def admit_for_rerank(
    hits: Sequence[SearchHit],
    *,
    rerank_candidate_limit: int,
    max_per_source: int = DEFAULT_MAX_PER_SOURCE,
) -> tuple[SearchHit, ...]:
    """Return a deterministic subset of fused hits for expensive reranking."""

    if rerank_candidate_limit < 1:
        raise ValueError("rerank_candidate_limit must be at least 1")
    if max_per_source < 1:
        raise ValueError("max_per_source must be at least 1")
    selected: list[SearchHit] = []
    seen_chunks: set[str] = set()
    per_source: dict[str, int] = defaultdict(int)
    for hit in hits:
        if len(selected) >= rerank_candidate_limit:
            break
        chunk = hit.chunk
        chunk_id = chunk.chunk_id
        if chunk_id in seen_chunks:
            continue
        source = chunk.source_identity
        if per_source[source] >= max_per_source:
            continue
        if any(_overlapping_sibling(chunk, previous.chunk) for previous in selected):
            continue
        selected.append(hit)
        seen_chunks.add(chunk_id)
        per_source[source] += 1
    return tuple(selected)


def _locator(chunk: object) -> str:
    metadata = getattr(chunk, "metadata", {}) or {}
    raw = metadata.get("locator") or metadata.get("legal_locator") or ""
    return str(raw).strip()


def _ordinal(chunk: object) -> int | None:
    metadata = getattr(chunk, "metadata", {}) or {}
    raw = metadata.get("ordinal")
    if isinstance(raw, bool) or not isinstance(raw, int):
        locator = _locator(chunk)
        match = _ORDINAL.search(locator)
        if match is None:
            return None
        return int(match.group(1))
    return int(raw)


def _overlapping_sibling(candidate: object, previous: object) -> bool:
    """Detect overlapping windows without collapsing distinct legal spans.

    A statutory section commonly contains several independently citable chunks
    with the same source, locator and inferred ordinal.  Locator-only admission
    therefore destroys proposition evidence.  Suppression is appropriate only
    when two chunks at the same coordinate also have substantially overlapping
    text, as real sibling windows do.
    """

    if getattr(candidate, "source_identity", None) != getattr(previous, "source_identity", None):
        return False
    candidate_locator = _locator(candidate)
    previous_locator = _locator(previous)
    candidate_ordinal = _ordinal(candidate)
    previous_ordinal = _ordinal(previous)
    if candidate_locator or previous_locator:
        same_coordinate = bool(candidate_locator and candidate_locator == previous_locator)
    else:
        same_coordinate = candidate_ordinal is not None and candidate_ordinal == previous_ordinal
    if not same_coordinate:
        return False
    candidate_words = _WORD.findall(str(getattr(candidate, "text", "")).casefold())
    previous_words = _WORD.findall(str(getattr(previous, "text", "")).casefold())
    if candidate_words == previous_words:
        return True
    candidate_shingles = _shingles(candidate_words)
    previous_shingles = _shingles(previous_words)
    if not candidate_shingles or not previous_shingles:
        return False
    containment = len(candidate_shingles & previous_shingles) / min(
        len(candidate_shingles), len(previous_shingles)
    )
    return containment >= _SIBLING_OVERLAP_THRESHOLD


def _shingles(words: Sequence[str]) -> set[tuple[str, ...]]:
    if len(words) < _SHINGLE_SIZE:
        return {tuple(words)} if words else set()
    return {
        tuple(words[index : index + _SHINGLE_SIZE])
        for index in range(len(words) - _SHINGLE_SIZE + 1)
    }
