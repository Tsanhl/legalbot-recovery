"""Eight-case retrieval smoke test. Never a promotion benchmark."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database, utc_iso
from ..ingestion.models import MaterialLane
from .ge_generic_read_guard import require_generic_index_read_allowed
from .hybrid import DeterministicHashEmbedding, HybridRetriever
from .lancedb import ImmutableLanceRepository
from .models import QueryFilters, SearchQuery
from .service import (
    PHYSICAL_AUTHORITY_LANE,
    TEST_EMBEDDING_MODEL,
    _embedding_provider,
    _import_lancedb,
    _LanceLexicalBackend,
    _LanceVectorBackend,
    _production_embedding_identity,
    _query_exact_jurisdictions,
    _query_jurisdictions,
    _reranker_provider,
    _TestOverlapReranker,
)

RETRIEVAL_SMOKE_SCHEMA = "legalbot.retrieval-smoke.v1"
OFFLINE_BENCHMARK_SCHEMA = RETRIEVAL_SMOKE_SCHEMA  # compatibility import only

QUERY_CASES: tuple[dict[str, Any], ...] = (
    {
        "id": "exact-statute",
        "kind": "exact_statute",
        "query": "Unfair Contract Terms Act 1977 section 2 negligence liability",
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "expect_hits": True,
        "must_contain": ("unfair", "contract"),
    },
    {
        "id": "case-name",
        "kind": "case_name",
        "query": "Triple Point Technology Inc v PTT Public Company Ltd",
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "expect_hits": True,
        "must_contain": ("triple", "point"),
    },
    {
        "id": "faithful-paraphrase",
        "kind": "faithful_paraphrase",
        "query": "When does a limitation clause survive a serious breach of contract?",
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "expect_hits": True,
        "must_contain": (),
    },
    {
        "id": "mixed-lexical-semantic",
        "kind": "mixed_lexical_semantic",
        "query": "occupier duty of care visitor premises 1957",
        "jurisdiction": "England and Wales",
        "subject": "tort",
        "expect_hits": True,
        "must_contain": ("occup",),
    },
    {
        "id": "negative-out-of-scope",
        "kind": "negative_out_of_scope",
        "query": "Martian mineral rights under the Treaty of Olympus 3099",
        "jurisdiction": "England and Wales",
        "subject": "public_law",
        "expect_hits": False,
        "must_contain": (),
    },
    {
        "id": "wrong-jurisdiction",
        "kind": "wrong_jurisdiction",
        "query": "Unfair Contract Terms Act 1977",
        "jurisdiction": "Scotland",
        "subject": "contract",
        "expect_hits": False,
        "must_contain": (),
        "note": "Scotland is not the indexed England and Wales / UK authority lane for this scoped corpus.",
    },
    {
        "id": "source-span-provenance",
        "kind": "source_span_provenance",
        "query": "Limitation Act 1980 section 2",
        "jurisdiction": "England and Wales",
        "subject": "professional_negligence",
        "expect_hits": True,
        "must_contain": ("limitation",),
        "require_provenance": True,
    },
    {
        "id": "zero-hit-behavior",
        "kind": "zero_hit_behavior",
        "query": "xyzzy-nonexistent-legal-identifier-000",
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "expect_hits": False,
        "must_contain": (),
    },
)


def run_retrieval_smoke(
    settings: Settings,
    database: Database,
    *,
    build_id: str | None,
    destination: Path,
) -> dict[str, Any]:
    """Diagnose stack wiring; fixture success must never imply promotability."""

    repository = ImmutableLanceRepository(settings.index_dir)
    used_fixture = False
    target_id = build_id
    build_path: Path | None = None
    if target_id:
        candidate = repository.builds / target_id
        if (candidate / "lance").exists():
            require_generic_index_read_allowed(
                candidate,
                expected_build_id=target_id,
            )
            build_path = candidate
    if build_path is None:
        used_fixture = True
        build_path = settings.project_root / "tmp" / "offline-retrieval-fixture"
        _write_fixture_lance(build_path, settings)

    embedder = _embedding_provider(
        settings,
        TEST_EMBEDDING_MODEL
        if settings.test_mode or used_fixture
        else _production_embedding_identity(settings),
    )
    reranker = (
        _TestOverlapReranker()
        if settings.test_mode or used_fixture
        else _reranker_provider(
            settings,
            _production_reranker_identity := __import__(
                "app.retrieval.service", fromlist=["_production_reranker_identity"]
            )._production_reranker_identity(settings),
        )
    )
    module = _import_lancedb()
    authority = build_path / "lance" / PHYSICAL_AUTHORITY_LANE
    if not authority.exists():
        authority = build_path / "lance"
    connection = module.connect(str(authority))
    table = connection.open_table("chunks")
    as_of = date(2026, 8, 13)
    results: list[dict[str, Any]] = []
    for case in QUERY_CASES:
        filters = QueryFilters(
            jurisdictions=frozenset(_query_jurisdictions(str(case["jurisdiction"]))),
            material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
            exact_jurisdictions=frozenset(_query_exact_jurisdictions(str(case["jurisdiction"]))),
            subjects=frozenset(),
            review_states=frozenset({"approved"}),
        )
        retriever = HybridRetriever(
            embedder=embedder,
            lexical_backend=_LanceLexicalBackend(table, as_of),
            vector_backend=_LanceVectorBackend(table, as_of),
            reranker=reranker,
        )
        hits = retriever.search(
            SearchQuery(
                str(case["query"]),
                filters,
                limit=10,
                candidate_limit=40,
                rerank_candidate_limit=40,
            )
        )
        texts = " ".join(hit.chunk.text.casefold() for hit in hits)
        must = tuple(case.get("must_contain") or ())
        lexical_ok = all(token in texts for token in must) if hits and must else not must
        provenance_ok = True
        if case.get("require_provenance") and hits:
            provenance_ok = all(
                bool(hit.chunk.source_identity) and bool(hit.chunk.metadata.get("locator"))
                for hit in hits[:3]
            )
        expect_hits = bool(case["expect_hits"])
        passed = (
            (bool(hits) == expect_hits)
            if not expect_hits
            else (bool(hits) and lexical_ok and provenance_ok)
        )
        results.append(
            {
                "id": case["id"],
                "kind": case["kind"],
                "passed": passed,
                "hit_count": len(hits),
                "top_chunk_ids": [hit.chunk.chunk_id for hit in hits[:5]],
                "top_source_identities": [hit.chunk.source_identity for hit in hits[:5]],
                "lexical_ok": lexical_ok,
                "provenance_ok": provenance_ok,
                "note": case.get("note"),
            }
        )
    report = {
        "schema": RETRIEVAL_SMOKE_SCHEMA,
        "purpose": "diagnostic_smoke_only",
        "promotion_eligible": False,
        "created_at": utc_iso(),
        "build_id": target_id,
        "used_fixture": used_fixture,
        "answer_model_invoked": False,
        "cases": results,
        "passed_count": sum(1 for item in results if item["passed"]),
        "case_count": len(results),
        "passed": all(item["passed"] for item in results),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return report


def run_offline_retrieval_benchmark(
    settings: Settings,
    database: Database,
    *,
    build_id: str | None,
    destination: Path,
) -> dict[str, Any]:
    """Deprecated compatibility alias for :func:`run_retrieval_smoke`."""

    return run_retrieval_smoke(settings, database, build_id=build_id, destination=destination)


def _write_fixture_lance(path: Path, settings: Settings) -> None:
    from ..ingestion.models import Jurisdiction, MaterialLane
    from .lancedb import ImmutableLanceRepository
    from .models import IndexedChunk, ensure_vector

    embedder = DeterministicHashEmbedding()
    chunks = [
        IndexedChunk(
            chunk_id="fixture-ucta-s2",
            text="Unfair Contract Terms Act 1977 section 2 restricts exclusion of negligence liability.",
            vector=embedder.embed_query(
                "Unfair Contract Terms Act 1977 section 2 negligence liability"
            ),
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.PRIMARY_AUTHORITY,
            subject="contract",
            review_state="approved",
            source_identity="ukpga:1977:50:enacted",
            content_sha256="a" * 64,
            metadata={
                "locator": "s 2",
                "source_version_id": "fixture-ucta",
                "catalog_lane": "primary_authority",
                "catalog_jurisdiction": "England and Wales",
            },
        ),
        IndexedChunk(
            chunk_id="fixture-triple-point",
            text="Triple Point Technology Inc v PTT Public Company Ltd [2021] UKSC 29 considered liquidated damages.",
            vector=embedder.embed_query("Triple Point Technology Inc v PTT"),
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.PRIMARY_AUTHORITY,
            subject="contract",
            review_state="approved",
            source_identity="neutral-citation:[2021] UKSC 29",
            content_sha256="b" * 64,
            metadata={
                "locator": "[1]",
                "source_version_id": "fixture-uksc",
                "catalog_lane": "primary_authority",
                "catalog_jurisdiction": "England and Wales",
            },
        ),
        IndexedChunk(
            chunk_id="fixture-limitation-s2",
            text="Limitation Act 1980 section 2 provides the limitation period for actions in tort.",
            vector=embedder.embed_query("Limitation Act 1980 section 2"),
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.PRIMARY_AUTHORITY,
            subject="tort",
            review_state="approved",
            source_identity="ukpga:1980:58:enacted",
            content_sha256="c" * 64,
            metadata={
                "locator": "s 2",
                "source_version_id": "fixture-la",
                "catalog_lane": "primary_authority",
                "catalog_jurisdiction": "England and Wales",
            },
        ),
        IndexedChunk(
            chunk_id="fixture-occupiers-1957",
            text="Occupiers' Liability Act 1957 imposes a duty of care on occupiers to visitors.",
            vector=embedder.embed_query("occupier duty of care visitor premises 1957"),
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=MaterialLane.PRIMARY_AUTHORITY,
            subject="tort",
            review_state="approved",
            source_identity="ukpga:1957:31:enacted",
            content_sha256="d" * 64,
            metadata={
                "locator": "s 2",
                "source_version_id": "fixture-ola",
                "catalog_lane": "primary_authority",
                "catalog_jurisdiction": "England and Wales",
            },
        ),
    ]
    repo = ImmutableLanceRepository(path.parent / "fixture-indexes")
    # Write a local fake table JSON the hybrid backends can use if lancedb is absent.
    path.mkdir(parents=True, exist_ok=True)
    (path / "lance" / "authority").mkdir(parents=True, exist_ok=True)
    try:
        from .service import _import_lancedb, _RealLanceSessionFactory

        session = _RealLanceSessionFactory(_import_lancedb()).create(path / "lance")
        session.write_chunks(chunks)
        session.create_indexes()
        session.close()
    except Exception:
        rows = [
            {
                "chunk_id": chunk.chunk_id,
                "text": chunk.text,
                "vector": list(chunk.vector),
                "source_identity": chunk.source_identity,
                "locator": chunk.metadata.get("locator"),
            }
            for chunk in chunks
        ]
        (path / "lance" / "authority" / "rows.json").write_text(json.dumps(rows), encoding="utf-8")
    del settings, ensure_vector, repo
