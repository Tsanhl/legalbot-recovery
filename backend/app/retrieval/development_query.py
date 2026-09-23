"""Actual query embeddings and causal reranking over an immutable research index.

No source admission, threshold calibration or currentness is implied by a hit.
This bounded local diagnostic consumes the existing pinned inference helpers.
"""

from __future__ import annotations

import gc
import hashlib
import re
from pathlib import Path
from typing import Any

from ..contracts.schema_registry import canonical_json_bytes

_TERM = re.compile(r"[a-z0-9]+")
_SECTION_HINT = re.compile(r"\bsection\s+(\d+[a-z]?)\b", re.IGNORECASE)
_DURATION_HINT = re.compile(r"\b\d+\s+days?\b", re.IGNORECASE)
_COMMON = frozenset({"the", "and", "for", "from", "with", "that", "this", "what", "when", "where", "which", "under", "about"})


def select_reviewed_candidates(
    query: str, vector_hits: list[dict[str, Any]], rows: tuple[dict[str, Any], ...], *, limit: int = 8
) -> list[dict[str, Any]]:
    """Mix actual vector rank with issue words, then cover distinct provisions.

    Only previously reviewed rows may enter the result. A near-duplicate group
    of short statutory fragments must not consume the entire model context.
    Reranking still judges the selected query/document pairs afterwards.
    """

    if not 1 <= limit <= 8:
        raise ValueError("development reranker accepts one to eight candidates")
    by_id = {str(row["id"]): row for row in rows}
    terms = {term for term in _TERM.findall(query.casefold()) if len(term) >= 4 and term not in _COMMON}
    ranked = [hit for hit in vector_hits if str(hit["id"]) in by_id]
    vector_rank = {str(hit["id"]): rank for rank, hit in enumerate(ranked)}

    def lexical(row: dict[str, Any]) -> int:
        text = str(row.get("text") or "").casefold()
        exact_durations = _DURATION_HINT.findall(query)
        return len(terms & set(_TERM.findall(text))) + 5 * sum(
            duration.casefold() in text for duration in exact_durations
        )

    lexical_rows = sorted(rows, key=lambda row: (-lexical(row), vector_rank.get(str(row["id"]), 10_000)))
    pool_ids = {str(hit["id"]) for hit in ranked[:24]}
    pool_ids.update(str(row["id"]) for row in lexical_rows[:12] if lexical(row) > 0)
    pool = [hit for hit in ranked if str(hit["id"]) in pool_ids]
    pool.sort(key=lambda hit: (
        -(lexical(by_id[str(hit["id"])]) * 0.08 + 1 / (1 + vector_rank[str(hit["id"])])),
        vector_rank[str(hit["id"])],
    ))
    chosen: list[dict[str, Any]] = []
    chosen_ids: set[str] = set()
    locators: set[str] = set()
    # An issue planner may supply provision search hints.  They reserve
    # candidate slots but never bypass the reviewed-row filter or reranker.
    for number in dict.fromkeys(_SECTION_HINT.findall(query)):
        locator = f"section {number.casefold()}"
        matching = [
            hit for hit in ranked
            if str(by_id[str(hit["id"])]["structural_chunk"].get("metadata", {}).get("legal_locator") or "").casefold() == locator
        ]
        if not matching or len(chosen) >= limit:
            continue
        best = max(
            matching,
            key=lambda hit: (lexical(by_id[str(hit["id"])]), -vector_rank[str(hit["id"])]),
        )
        chosen.append(best)
        chosen_ids.add(str(best["id"]))
        locators.add(locator)
    for hit in pool:
        locator = str(by_id[str(hit["id"])]["structural_chunk"].get("metadata", {}).get("legal_locator") or hit["id"])
        if locator in locators:
            continue
        chosen.append(hit)
        chosen_ids.add(str(hit["id"]))
        locators.add(locator)
        if len(chosen) >= min(limit, 5):
            break
    for hit in pool:
        if len(chosen) >= limit:
            break
        if str(hit["id"]) not in chosen_ids:
            chosen.append(hit)
            chosen_ids.add(str(hit["id"]))
    return chosen


def query_reviewed_generation(
    query: str, generation_file: Path, rows: tuple[dict[str, Any], ...]
) -> dict[str, Any]:
    import lancedb
    from scripts.ge_auto_research_reranker import PinnedRerankerSession
    from scripts.ge_auto_research_runtime import PinnedEmbeddingSession

    with PinnedEmbeddingSession() as session:
        vector = session.embed_query(query)
        embedding_receipt = session.receipt()
    gc.collect()
    table = lancedb.connect(str(generation_file.parent / "lance" / "authority")).open_table(
        "chunks"
    )
    # Search the persisted vectors, then retain only rows already bound to the
    # reviewed consumer manifest. Search results cannot add unreviewed context.
    hits = table.search(list(vector), vector_column_name="vector").limit(len(table)).to_list()
    by_id = {r["id"]: r for r in rows}
    selected = select_reviewed_candidates(query, hits, rows)
    if selected:
        with PinnedRerankerSession() as reranker:
            scores = reranker.predict([(query, by_id[r["id"]]["text"]) for r in selected])
            rerank_receipt = reranker.receipt()
    else:
        scores, rerank_receipt = [], {"actual_pairs_scored": 0}
    ordered = sorted(zip(selected, scores, strict=True), key=lambda pair: (-pair[1], pair[0]["id"]))
    value = {
        "schema": "legalbot.development-query-trace.v1",
        "query_sha256": hashlib.sha256(query.encode()).hexdigest(),
        "generation_file_sha256": hashlib.sha256(generation_file.read_bytes()).hexdigest(),
        "query_vector": list(vector),
        "embedding": embedding_receipt,
        "vector_hits": [{"id": r["id"], "distance": r.get("_distance")} for r in selected],
        "candidate_selection": "reviewed_vector_lexical_provision_diversity_v1",
        "reranker": rerank_receipt,
        "selected_ids": [r["id"] for r, _ in ordered],
        "ranking_scores": {r["id"]: score for r, score in ordered},
        "source_qualification": "separate_required_check",
        "production_admitted": False,
    }
    return {**value, "sha256": hashlib.sha256(canonical_json_bytes(value)).hexdigest()}
