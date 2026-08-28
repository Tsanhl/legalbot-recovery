from __future__ import annotations

import json
from pathlib import Path

from app.retrieval.cache import SafeCachedHit, SafeRetrievalCache, cache_allowed
from app.retrieval.cache_keys import retrieval_cache_key


def _key(*, build: str = "build-a", as_of_date: str = "2026-08-15") -> str:
    return retrieval_cache_key(
        query="What is the limitation period?",
        corpus_id="authority",
        tenant_visibility="owner",
        jurisdiction="England and Wales",
        active_build_id=build,
        source_manifest_sha256="a" * 64,
        as_of_date=as_of_date,
        task_type="problem",
        subject="professional negligence",
        material_lanes=["primary_authority"],
        filters={"review_states": ["approved"]},
        query_rewrite_version="rewrite-v1",
        retrieval_version="hybrid-v1",
        chunker_version="chunker-v1",
        embedding_version="embed-v1",
        reranker_version="rerank-v1",
        policy_version="policy-v1",
        retrieval_config={"limit": 10},
    )


def test_cache_stores_safe_ids_only_and_round_trips(tmp_path: Path) -> None:
    cache = SafeRetrievalCache(tmp_path / "cache")
    key = _key()
    hit = SafeCachedHit("source-version-1", "chunk-1", 1, 0.95)

    cache.put(active_build_id="build-a", key=key, hits=[hit])

    assert cache.get(active_build_id="build-a", key=key) == (hit,)
    serialised = next((tmp_path / "cache").glob("*/*.json")).read_text()
    assert "What is the limitation" not in serialised
    assert "source-version-1" in serialised


def test_cache_corruption_is_a_miss_and_pointer_change_invalidates(tmp_path: Path) -> None:
    cache = SafeRetrievalCache(tmp_path / "cache")
    first_key = _key(build="build-a")
    second_key = _key(build="build-b")
    hit = SafeCachedHit("source-version-1", "chunk-1", 1, 0.5)
    cache.put(active_build_id="build-a", key=first_key, hits=[hit])
    cache.put(active_build_id="build-b", key=second_key, hits=[hit])

    first_path = next(
        path
        for path in (tmp_path / "cache").glob("*/*.json")
        if json.loads(path.read_text())["active_build_id"] == "build-a"
    )
    first_path.write_text("not-json", encoding="utf-8")
    assert cache.get(active_build_id="build-a", key=first_key) is None
    cache.put(active_build_id="build-a", key=first_key, hits=[hit])
    assert cache.invalidate_for_pointer_change(active_build_id="build-b") == 1
    assert cache.get(active_build_id="build-b", key=second_key) == (hit,)


def test_cache_key_separates_legal_date_and_uploads_bypass() -> None:
    assert _key(as_of_date="2026-08-15") != _key(as_of_date="2026-08-16")
    assert cache_allowed(upload_ids=(), online_result=False) is True
    assert cache_allowed(upload_ids=("upload-1",), online_result=False) is False
    assert cache_allowed(upload_ids=(), online_result=True) is False


def test_cache_key_includes_ranking_representation_version() -> None:
    base = {
        "query": "limitation",
        "corpus_id": "authority",
        "tenant_visibility": "owner",
        "jurisdiction": "England and Wales",
        "active_build_id": "build-a",
        "source_manifest_sha256": "a" * 64,
        "as_of_date": "2026-08-15",
        "task_type": "problem",
        "subject": "contract",
        "material_lanes": ["primary_authority"],
        "filters": {"review_states": ["approved"]},
        "query_rewrite_version": "none-v1",
        "retrieval_version": "hybrid-rrf-rerank-v1",
        "chunker_version": "chunker-v1",
        "embedding_version": "embed-v1",
        "reranker_version": "rerank-v1",
        "policy_version": "policy-v1",
    }
    first = retrieval_cache_key(
        **base,
        retrieval_config={"rerank_candidate_limit": 40, "ranking_representation_version": "v1"},
    )
    second = retrieval_cache_key(
        **base,
        retrieval_config={"rerank_candidate_limit": 40, "ranking_representation_version": "v2"},
    )
    assert first != second
