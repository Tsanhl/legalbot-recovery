"""Hybrid lexical/vector retrieval with RRF and a pluggable reranker."""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

from .admission import ADMISSION_VERSION, admit_for_rerank
from .budget import (
    RetrievalBudgetExhausted,
    raise_if_complete_rerank_plan_exceeds_remaining,
)
from .explicit_reference import (
    EXPLICIT_REFERENCE_VERSION,
    CandidateLegislationReferenceResolver,
    legislation_locator_within,
)
from .filters import chunk_matches, enforce_candidates
from .interfaces import LexicalSearchBackend, QueryEmbedder, Reranker, VectorSearchBackend
from .models import (
    VECTOR_DIMENSIONS,
    IndexedChunk,
    QueryFilters,
    SearchCandidate,
    SearchHit,
    SearchQuery,
    ensure_vector,
)

RANKING_PAYLOAD_MAX_TOKENS = 1024


@dataclass(frozen=True, slots=True)
class PreparedSearch:
    """Cheap lexical/vector/RRF admission result. Does not run Qwen."""

    query: SearchQuery
    fused: tuple[SearchHit, ...]
    admitted: tuple[SearchHit, ...]
    token_lengths: tuple[int, ...]
    workload_digest: str
    timings_ms: Mapping[str, float]
    skip_rerank: bool = False
    exact_source_identity: str | None = None
    exact_locator: str | None = None

    def rerank_hit_count(self) -> int:
        if self.skip_rerank:
            return 0
        return len(self.admitted)


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+(?:'[a-z0-9]+)?", text.lower())


_NEUTRAL_CITATION_ONLY = re.compile(
    r"^\s*(?P<citation>\[\d{4}\]\s+(?:UKSC|UKPC|EWCA\s+(?:Civ|Crim)|EWHC)\s+\d+)\s*$",
    re.IGNORECASE,
)


def explicit_authority_identity(text: str) -> str | None:
    """Return a stable identity only for an identifier-only legal query."""

    match = _NEUTRAL_CITATION_ONLY.fullmatch(text)
    if match is None:
        return None
    citation = re.sub(r"\s+", " ", match.group("citation")).upper()
    # Preserve the conventional mixed-case court suffixes used by stable IDs.
    citation = citation.replace("EWCA CIV", "EWCA Civ").replace("EWCA CRIM", "EWCA Crim")
    return f"neutral-citation:{citation}"


class DeterministicHashEmbedding:
    """Local test embedding; never advertised as a production semantic model."""

    dimensions = VECTOR_DIMENSIONS

    def embed_query(self, text: str) -> tuple[float, ...]:
        return self._embed(text)

    def embed_documents(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
        return tuple(self._embed(text) for text in texts)

    def _embed(self, text: str) -> tuple[float, ...]:
        values = [0.0] * self.dimensions
        for token in _tokens(text):
            digest = hashlib.blake2b(token.encode("utf-8"), digest_size=16).digest()
            index = int.from_bytes(digest[:8], "big") % self.dimensions
            sign = 1.0 if digest[8] & 1 else -1.0
            values[index] += sign
        norm = math.sqrt(sum(value * value for value in values)) or 1.0
        return tuple(value / norm for value in values)


class InMemoryBM25Backend:
    def __init__(self, chunks: Iterable[IndexedChunk], *, k1: float = 1.5, b: float = 0.75) -> None:
        self.chunks = tuple(chunks)
        self.k1 = k1
        self.b = b
        self._terms = [Counter(_tokens(chunk.text)) for chunk in self.chunks]
        self._lengths = [sum(terms.values()) for terms in self._terms]

    def search(self, text: str, *, filters: QueryFilters, limit: int) -> Sequence[SearchCandidate]:
        eligible = [
            index for index, chunk in enumerate(self.chunks) if chunk_matches(chunk, filters)
        ]
        if not eligible:
            return ()
        query_terms = set(_tokens(text))
        average_length = sum(self._lengths[index] for index in eligible) / len(eligible) or 1.0
        document_frequency = {
            term: sum(1 for index in eligible if self._terms[index].get(term, 0) > 0)
            for term in query_terms
        }
        scored: list[tuple[float, IndexedChunk]] = []
        for index in eligible:
            score = 0.0
            length = self._lengths[index]
            for term in query_terms:
                frequency = self._terms[index].get(term, 0)
                if not frequency:
                    continue
                idf = math.log(
                    1.0
                    + (len(eligible) - document_frequency[term] + 0.5)
                    / (document_frequency[term] + 0.5)
                )
                denominator = frequency + self.k1 * (1 - self.b + self.b * length / average_length)
                score += idf * frequency * (self.k1 + 1) / denominator
            if score > 0:
                scored.append((score, self.chunks[index]))
        scored.sort(key=lambda item: (-item[0], item[1].chunk_id))
        return tuple(
            SearchCandidate(chunk, score, rank, "lexical")
            for rank, (score, chunk) in enumerate(scored[:limit], 1)
        )


class InMemoryVectorBackend:
    def __init__(self, chunks: Iterable[IndexedChunk]) -> None:
        self.chunks = tuple(chunks)
        for chunk in self.chunks:
            chunk.validate()

    def search(
        self, vector: Sequence[float], *, filters: QueryFilters, limit: int
    ) -> Sequence[SearchCandidate]:
        query_vector = ensure_vector(vector)
        query_norm = math.sqrt(sum(value * value for value in query_vector)) or 1.0
        scored: list[tuple[float, IndexedChunk]] = []
        for chunk in self.chunks:
            if not chunk_matches(chunk, filters):
                continue
            vector_norm = math.sqrt(sum(value * value for value in chunk.vector)) or 1.0
            score = sum(
                left * right for left, right in zip(query_vector, chunk.vector, strict=True)
            ) / (query_norm * vector_norm)
            scored.append((score, chunk))
        scored.sort(key=lambda item: (-item[0], item[1].chunk_id))
        return tuple(
            SearchCandidate(chunk, score, rank, "vector")
            for rank, (score, chunk) in enumerate(scored[:limit], 1)
        )


def reciprocal_rank_fusion(
    lexical: Sequence[SearchCandidate],
    vector: Sequence[SearchCandidate],
    *,
    rank_constant: int = 60,
) -> tuple[SearchHit, ...]:
    if rank_constant < 1:
        raise ValueError("rank_constant must be positive")
    scores: defaultdict[str, float] = defaultdict(float)
    chunks: dict[str, IndexedChunk] = {}
    ranks: dict[str, dict[str, int]] = defaultdict(dict)
    for channel, candidates in (("lexical", lexical), ("vector", vector)):
        seen: set[str] = set()
        for candidate in candidates:
            chunk_id = candidate.chunk.chunk_id
            if chunk_id in seen:
                continue
            seen.add(chunk_id)
            chunks[chunk_id] = candidate.chunk
            ranks[chunk_id][channel] = candidate.rank
            scores[chunk_id] += 1.0 / (rank_constant + candidate.rank)
    ordered = sorted(scores, key=lambda chunk_id: (-scores[chunk_id], chunk_id))
    return tuple(
        SearchHit(
            chunks[chunk_id],
            scores[chunk_id],
            lexical_rank=ranks[chunk_id].get("lexical"),
            vector_rank=ranks[chunk_id].get("vector"),
        )
        for chunk_id in ordered
    )


class DeterministicOverlapReranker:
    """Predictable local reranker used by tests and offline diagnostics."""

    def rerank(self, query: str, hits: Sequence[SearchHit], *, limit: int) -> Sequence[SearchHit]:
        query_terms = set(_tokens(query))
        rescored: list[SearchHit] = []
        for hit in hits:
            document_terms = set(_tokens(hit.chunk.text))
            overlap = len(query_terms & document_terms) / max(1, len(query_terms))
            rerank_score = overlap + hit.score
            rescored.append(replace(hit, rerank_score=rerank_score))
        rescored.sort(key=lambda hit: (-(hit.rerank_score or 0.0), -hit.score, hit.chunk.chunk_id))
        return tuple(rescored[:limit])


class HybridRetriever:
    def __init__(
        self,
        *,
        embedder: QueryEmbedder,
        lexical_backend: LexicalSearchBackend,
        vector_backend: VectorSearchBackend,
        reranker: Reranker,
        reference_resolver: CandidateLegislationReferenceResolver | None = None,
    ) -> None:
        if embedder.dimensions != VECTOR_DIMENSIONS:
            raise ValueError(f"embedder must expose {VECTOR_DIMENSIONS} dimensions")
        self.embedder = embedder
        self.lexical_backend = lexical_backend
        self.vector_backend = vector_backend
        self.reranker = reranker
        self.reference_resolver = reference_resolver
        self.last_vector_degraded = False
        self.last_reranker_unavailable = False
        self.last_timings_ms: dict[str, float] = {}
        self.last_workload: dict[str, int | str] = {}

    def search(self, query: SearchQuery) -> tuple[SearchHit, ...]:
        return self.finish(self.prepare(query))

    def prepare(self, query: SearchQuery) -> PreparedSearch:
        """Lexical/vector fusion and admission only. Does not run Qwen."""

        query.validate()
        total_started = time.perf_counter()
        identity = explicit_authority_identity(query.text)
        identity_search = getattr(self.lexical_backend, "search_identity", None)
        if identity is not None and callable(identity_search):
            started = time.perf_counter()
            exact = enforce_candidates(
                identity_search(identity, filters=query.filters, limit=query.limit),
                query.filters,
            )
            lexical_ms = (time.perf_counter() - started) * 1000
            output = tuple(
                SearchHit(
                    candidate.chunk,
                    candidate.score,
                    lexical_rank=candidate.rank,
                    diagnostics={"route": "exact_authority_identity"},
                )
                for candidate in exact
            )
            timings = {
                "query_embedding": 0.0,
                "lexical": round(lexical_ms, 3),
                "vector": 0.0,
                "fusion": 0.0,
                "admission": 0.0,
                "prepare_total": round((time.perf_counter() - total_started) * 1000, 3),
            }
            self.last_workload = {
                "lexical_requested": query.limit,
                "lexical_returned": len(exact),
                "vector_requested": 0,
                "vector_returned": 0,
                "fused": len(output),
                "admitted": len(output),
                "rerank_input": 0,
                "route": "exact_authority_identity",
            }
            digest = hashlib.sha256(
                "|".join((query.text, ",".join(hit.chunk.chunk_id for hit in output))).encode(
                    "utf-8"
                )
            ).hexdigest()
            return PreparedSearch(
                query=query,
                fused=output,
                admitted=output,
                token_lengths=(),
                workload_digest=digest,
                timings_ms=timings,
                skip_rerank=True,
            )
        reference = (
            self.reference_resolver.resolve(query.text)
            if self.reference_resolver is not None
            else None
        )
        if reference is not None:
            reference_search = getattr(self.lexical_backend, "search_reference", None)
            if not callable(reference_search):
                raise RuntimeError("explicit legislation route has no exact-reference backend")
            started = time.perf_counter()
            candidates = enforce_candidates(
                reference_search(reference, filters=query.filters, limit=query.rerank_limit()),
                query.filters,
            )
            reference_exact = tuple(
                candidate
                for candidate in candidates
                if candidate.chunk.source_identity == reference.source_identity
                and legislation_locator_within(_chunk_locator(candidate.chunk), reference.locator)
            )
            lexical_ms = (time.perf_counter() - started) * 1000
            output = tuple(
                SearchHit(
                    candidate.chunk,
                    candidate.score,
                    lexical_rank=candidate.rank,
                    diagnostics={
                        "route": "exact_legislation_reference",
                        "reference_version": EXPLICIT_REFERENCE_VERSION,
                    },
                )
                for candidate in reference_exact[: query.rerank_limit()]
            )
            token_lengths = tuple(
                max(1, min(RANKING_PAYLOAD_MAX_TOKENS, (len(hit.chunk.text) + 3) // 4))
                for hit in output
            )
            timings = {
                "query_embedding": 0.0,
                "lexical": round(lexical_ms, 3),
                "vector": 0.0,
                "fusion": 0.0,
                "admission": 0.0,
                "prepare_total": round((time.perf_counter() - total_started) * 1000, 3),
            }
            self.last_vector_degraded = False
            self.last_workload = {
                "lexical_requested": reference.source_chunk_count,
                "lexical_returned": len(reference_exact),
                "vector_requested": 0,
                "vector_returned": 0,
                "fused": len(output),
                "admitted": len(output),
                "rerank_input": len(output),
                "rerank_candidate_limit": query.rerank_limit(),
                "reference_version": EXPLICIT_REFERENCE_VERSION,
                "route": "exact_legislation_reference",
            }
            digest = hashlib.sha256(
                "|".join(
                    (
                        query.text,
                        reference.manifest_sha256,
                        reference.source_identity,
                        reference.locator,
                        ",".join(hit.chunk.chunk_id for hit in output),
                        ",".join(str(length) for length in token_lengths),
                    )
                ).encode("utf-8")
            ).hexdigest()
            return PreparedSearch(
                query=query,
                fused=output,
                admitted=output,
                token_lengths=token_lengths,
                workload_digest=digest,
                timings_ms=timings,
                skip_rerank=not output,
                exact_source_identity=reference.source_identity,
                exact_locator=reference.locator,
            )
        started = time.perf_counter()
        vector = ensure_vector(self.embedder.embed_query(query.text))
        embed_ms = (time.perf_counter() - started) * 1000
        lexical_requested = query.lexical_limit()
        vector_requested = query.vector_limit()
        started = time.perf_counter()
        lexical = enforce_candidates(
            self.lexical_backend.search(query.text, filters=query.filters, limit=lexical_requested),
            query.filters,
        )
        lexical_ms = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        try:
            semantic = enforce_candidates(
                self.vector_backend.search(vector, filters=query.filters, limit=vector_requested),
                query.filters,
            )
            self.last_vector_degraded = False
        except Exception:
            semantic = []
            self.last_vector_degraded = True
        vector_ms = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        fused = reciprocal_rank_fusion(lexical, semantic)
        fusion_ms = (time.perf_counter() - started) * 1000
        started = time.perf_counter()
        admitted = admit_for_rerank(fused, rerank_candidate_limit=query.rerank_limit())
        admission_ms = (time.perf_counter() - started) * 1000
        if len(admitted) > query.rerank_limit():
            raise RuntimeError("pre-rerank admission exceeded rerank_candidate_limit")
        token_lengths = tuple(
            max(1, min(RANKING_PAYLOAD_MAX_TOKENS, (len(hit.chunk.text) + 3) // 4))
            for hit in admitted
        )
        digest = hashlib.sha256(
            "|".join(
                (
                    query.text,
                    ",".join(hit.chunk.chunk_id for hit in admitted),
                    ",".join(str(length) for length in token_lengths),
                )
            ).encode("utf-8")
        ).hexdigest()
        timings = {
            "query_embedding": round(embed_ms, 3),
            "lexical": round(lexical_ms, 3),
            "vector": round(vector_ms, 3),
            "fusion": round(fusion_ms, 3),
            "admission": round(admission_ms, 3),
            "prepare_total": round((time.perf_counter() - total_started) * 1000, 3),
        }
        self.last_workload = {
            "lexical_requested": lexical_requested,
            "lexical_returned": len(lexical),
            "vector_requested": vector_requested,
            "vector_returned": len(semantic),
            "fused": len(fused),
            "admitted": len(admitted),
            "rerank_input": len(admitted),
            "rerank_candidate_limit": query.rerank_limit(),
            "admission_version": ADMISSION_VERSION,
            "route": "hybrid_rrf",
        }
        from .telemetry import record_retrieval_workload

        record_retrieval_workload(stage="hybrid_search", data=self.last_workload)
        return PreparedSearch(
            query=query,
            fused=tuple(fused),
            admitted=admitted,
            token_lengths=token_lengths,
            workload_digest=digest,
            timings_ms=timings,
        )

    def finish(self, prepared: PreparedSearch) -> tuple[SearchHit, ...]:
        """Expensive Qwen rerank. Call only after the complete research plan is certified."""

        if prepared.skip_rerank:
            timings = dict(prepared.timings_ms)
            timings["rerank"] = 0.0
            timings["total"] = round(float(timings.get("prepare_total", 0.0)), 3)
            self.last_timings_ms = timings
            self.last_reranker_unavailable = False
            return prepared.admitted[: prepared.query.limit]
        raise_if_complete_rerank_plan_exceeds_remaining(
            (prepared.rerank_hit_count(),),
            ranking_payload_tokens=RANKING_PAYLOAD_MAX_TOKENS,
        )
        started = time.perf_counter()
        try:
            reranked = tuple(
                self.reranker.rerank(
                    prepared.query.text, prepared.admitted, limit=prepared.query.limit
                )
            )
            self.last_reranker_unavailable = False
        except RetrievalBudgetExhausted:
            raise
        except Exception as exc:
            self.last_reranker_unavailable = True
            raise RuntimeError(
                "Qwen reranking failed; unreranked RRF fallback is forbidden "
                "for production legal retrieval"
            ) from exc
        rerank_ms = round((time.perf_counter() - started) * 1000, 3)
        timings = dict(prepared.timings_ms)
        timings["rerank"] = rerank_ms
        timings["total"] = round(float(timings.get("prepare_total", 0.0)) + rerank_ms, 3)
        self.last_timings_ms = timings
        filtered = tuple(
            hit
            for hit in reranked
            if chunk_matches(hit.chunk, prepared.query.filters)
            and (
                prepared.exact_source_identity is None
                or (
                    hit.chunk.source_identity == prepared.exact_source_identity
                    and legislation_locator_within(
                        _chunk_locator(hit.chunk), prepared.exact_locator
                    )
                )
            )
        )
        return filtered[: prepared.query.limit]


def _chunk_locator(chunk: IndexedChunk) -> str:
    metadata = chunk.metadata or {}
    return str(metadata.get("locator") or metadata.get("legal_locator") or "").strip()
