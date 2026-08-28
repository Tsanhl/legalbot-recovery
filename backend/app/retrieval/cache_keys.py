"""Versioned in-process retrieval cache keys. Never used for final answers."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

RETRIEVAL_CACHE_SCHEMA = "legalbot.retrieval-cache-key.v2"


def retrieval_cache_key(
    *,
    query: str,
    corpus_id: str,
    tenant_visibility: str,
    jurisdiction: str,
    active_build_id: str,
    source_manifest_sha256: str,
    as_of_date: str,
    task_type: str,
    subject: str | None,
    material_lanes: Sequence[str],
    filters: Mapping[str, Any],
    query_rewrite_version: str,
    retrieval_version: str,
    chunker_version: str,
    embedding_version: str,
    reranker_version: str,
    policy_version: str,
    retrieval_config: Mapping[str, Any],
) -> str:
    """Bind one retrieval result to every input that can alter ranked safe IDs."""

    if not query.strip():
        raise ValueError("retrieval-cache query cannot be empty")
    if not active_build_id or not source_manifest_sha256:
        raise ValueError("retrieval-cache ACTIVE build and source manifest are required")
    if not as_of_date or not jurisdiction or not task_type:
        raise ValueError("retrieval-cache legal scope is incomplete")
    if not material_lanes:
        raise ValueError("retrieval-cache material lanes are required")

    payload = {
        "schema": RETRIEVAL_CACHE_SCHEMA,
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "corpus_id": corpus_id,
        "tenant_visibility": tenant_visibility,
        "jurisdiction": jurisdiction,
        "active_build_id": active_build_id,
        "source_manifest_sha256": source_manifest_sha256,
        "as_of_date": as_of_date,
        "task_type": task_type,
        "subject": subject,
        "material_lanes": sorted(set(material_lanes)),
        "filters": dict(filters),
        "query_rewrite_version": query_rewrite_version,
        "retrieval_version": retrieval_version,
        "chunker_version": chunker_version,
        "embedding_version": embedding_version,
        "reranker_version": reranker_version,
        "policy_version": policy_version,
        "retrieval_config": dict(retrieval_config),
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()
