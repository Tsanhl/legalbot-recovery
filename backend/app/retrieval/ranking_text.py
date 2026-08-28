"""Disposable ranking representation. Never mutates authoritative chunk text."""

from __future__ import annotations

from collections.abc import Sequence

from .hybrid import _tokens
from .models import IndexedChunk, SearchHit

RANKING_REPRESENTATION_VERSION = "title-locator-query-window-v1"
RANKING_PAYLOAD_MAX_TOKENS = 1024
RANKING_MAX_CHARS = RANKING_PAYLOAD_MAX_TOKENS * 4


def ranking_document_text(
    chunk: IndexedChunk,
    query: str,
    *,
    max_chars: int = RANKING_MAX_CHARS,
    strategy: str = "query_window",
) -> str:
    """Build bounded ranking text without changing ``chunk.text`` or hashes."""

    if max_chars < 1:
        raise ValueError("max_chars must be at least 1")
    header = _header(chunk)
    body = chunk.text
    if strategy == "prefix":
        remainder = max(1, max_chars - len(header) - 1)
        clipped = body[:remainder]
    else:
        clipped = _query_window(body, query, max_chars=max(1, max_chars - len(header) - 1))
    combined = f"{header}\n{clipped}" if header else clipped
    return combined[:max_chars]


def ranking_texts_leave_evidence_unchanged(hits: Sequence[SearchHit], query: str) -> bool:
    originals = [(hit.chunk.text, hit.chunk.content_sha256, hit.chunk.chunk_id) for hit in hits]
    for hit in hits:
        ranking_document_text(hit.chunk, query)
    return originals == [
        (hit.chunk.text, hit.chunk.content_sha256, hit.chunk.chunk_id) for hit in hits
    ]


def _header(chunk: IndexedChunk) -> str:
    metadata = chunk.metadata or {}
    heading = metadata.get("heading_path")
    if isinstance(heading, list | tuple):
        heading_text = " / ".join(str(item) for item in heading if str(item).strip())
    else:
        heading_text = str(heading or "").strip()
    locator = str(metadata.get("locator") or metadata.get("legal_locator") or "").strip()
    parts = [
        str(chunk.title or "").strip(),
        str(chunk.citation or "").strip(),
        locator,
        heading_text,
    ]
    return "\n".join(part for part in parts if part)


def _query_window(text: str, query: str, *, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    terms = [token for token in _tokens(query) if len(token) >= 4]
    lowered = text.casefold()
    best = -1
    for term in terms:
        index = lowered.find(term)
        if index >= 0 and (best < 0 or index < best):
            best = index
    if best < 0:
        return text[:max_chars]
    half = max_chars // 2
    start = max(0, best - half)
    end = min(len(text), start + max_chars)
    start = max(0, end - max_chars)
    return text[start:end]
