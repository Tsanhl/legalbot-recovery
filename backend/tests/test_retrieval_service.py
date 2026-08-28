from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from app.config import Settings
from app.db import utc_iso
from app.retrieval import service as retrieval_service
from app.retrieval.service import (
    HybridRetrievalService,
    build_candidate_index,
    promote_candidate_index,
)


def _promote_with_test_only_authority_stub(
    settings: Settings,
    database: Any,
    build_id: str,
) -> dict[str, str]:
    """Exercise post-authorisation promotion infrastructure without minting owner evidence."""

    with patch("app.evaluation.owner_quality_v111_promotion.verify_v111_promotion_for_service"):
        return promote_candidate_index(
            settings,
            database,
            build_id,
            v111_promotion_presentation=object(),
            v111_owner_authorization=object(),
        )


def test_query_subject_aliases_cover_catalogue_taxonomy_without_broad_general_fallback() -> None:
    assert retrieval_service._query_subjects("company") == frozenset(
        {"company", "company and insolvency"}
    )
    assert "employment and business" in retrieval_service._query_subjects("employment")
    assert "eu and internal market" in retrieval_service._query_subjects("eu")
    assert "general" not in retrieval_service._query_subjects("human rights")
    assert retrieval_service._query_subjects("equity and trusts") == frozenset({"trusts"})
    assert retrieval_service._query_subjects("public law") == frozenset(
        {"public and constitutional", "constitutional", "human rights and constitutional"}
    )
    assert {
        "land",
        "trusts",
        "family",
        "company and insolvency",
    } <= retrieval_service._query_subjects("land trusts family property and insolvency")
    assert "general" not in retrieval_service._query_subjects(
        "multi-area artificial intelligence litigation"
    )


class _FakeQuery:
    def __init__(self, rows: list[dict[str, Any]], query: Any, query_type: str) -> None:
        self.rows = rows
        self.query = query
        self.query_type = query_type
        self.maximum = 10

    def where(self, expression: str, *, prefilter: bool) -> _FakeQuery:
        assert expression and prefilter
        return self

    def limit(self, value: int) -> _FakeQuery:
        self.maximum = value
        return self

    def to_list(self) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        if self.query_type == "fts":
            terms = set(re.findall(r"[a-z0-9]+", str(self.query).casefold()))
            for row in self.rows:
                overlap = len(terms & set(re.findall(r"[a-z0-9]+", row["text"].casefold())))
                if overlap:
                    output.append({**row, "_score": float(overlap)})
            output.sort(key=lambda row: (-row["_score"], row["chunk_id"]))
        else:
            query = list(self.query)
            query_norm = math.sqrt(sum(value * value for value in query)) or 1.0
            for row in self.rows:
                vector = row["vector"]
                norm = math.sqrt(sum(value * value for value in vector)) or 1.0
                similarity = sum(
                    left * right for left, right in zip(query, vector, strict=True)
                ) / (query_norm * norm)
                output.append({**row, "_distance": 1.0 - similarity})
            output.sort(key=lambda row: (row["_distance"], row["chunk_id"]))
        return output[: self.maximum]


class _FakeTable:
    def __init__(self, path: Path, rows: list[dict[str, Any]]) -> None:
        self.path = path
        self.rows = rows

    def create_fts_index(self, field: str, *, replace: bool) -> None:
        assert field == "text" and replace
        (self.path / "fts.idx").write_text("fts", encoding="utf-8")

    def create_index(
        self,
        *,
        metric: str,
        num_partitions: int,
        vector_column_name: str,
        index_type: str,
        replace: bool,
    ) -> None:
        assert metric == "cosine"
        assert num_partitions >= 1
        assert vector_column_name == "vector"
        assert index_type == "IVF_FLAT"
        assert replace
        (self.path / "vector.idx").write_text("vector", encoding="utf-8")

    def add(self, rows: list[dict[str, Any]]) -> None:
        self.rows.extend(rows)
        (self.path / "rows.json").write_text(json.dumps(self.rows), encoding="utf-8")
        batches_path = self.path / "write-batches.json"
        batches = json.loads(batches_path.read_text(encoding="utf-8"))
        batches.append(len(rows))
        batches_path.write_text(json.dumps(batches), encoding="utf-8")

    def search(
        self,
        query: Any,
        *,
        query_type: str = "vector",
        fts_columns: list[str] | None = None,
        vector_column_name: str | None = None,
    ) -> _FakeQuery:
        assert fts_columns == ["text"] if query_type == "fts" else vector_column_name == "vector"
        return _FakeQuery(self.rows, query, query_type)


class _FakeConnection:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)

    def create_table(self, name: str, *, data: list[dict[str, Any]], mode: str) -> _FakeTable:
        assert name == "chunks" and mode == "create"
        (self.path / "rows.json").write_text(json.dumps(data), encoding="utf-8")
        (self.path / "write-batches.json").write_text(json.dumps([len(data)]), encoding="utf-8")
        return _FakeTable(self.path, data)

    def open_table(self, name: str) -> _FakeTable:
        assert name == "chunks"
        rows = json.loads((self.path / "rows.json").read_text(encoding="utf-8"))
        return _FakeTable(self.path, rows)


class _FakeLanceDB:
    @staticmethod
    def connect(path: str) -> _FakeConnection:
        return _FakeConnection(Path(path))


def test_real_lancedb_025_session_builds_and_searches_hybrid_indexes(tmp_path: Path) -> None:
    """Exercise the pinned LanceDB API instead of the fake test seam."""

    lancedb = pytest.importorskip("lancedb")
    session = retrieval_service._RealLanceSession(lancedb, tmp_path / "real-lance")
    common_metadata = {
        "source_version_id": "source-version",
        "locator": "para 1",
        "catalog_lane": "primary_authority",
        "catalog_jurisdiction": "England and Wales",
        "citation_data": {"source_type": "case"},
        "identity_verified": True,
        "currentness_verified": True,
    }
    relevant_text = "Consideration requires a bargained exchange of value."
    relevant_sha256 = hashlib.sha256(relevant_text.encode("utf-8")).hexdigest()
    relevant = retrieval_service.IndexedChunk(
        chunk_id="relevant",
        text=relevant_text,
        vector=(1.0,) + (0.0,) * (retrieval_service.VECTOR_DIMENSIONS - 1),
        jurisdiction=retrieval_service.Jurisdiction.ENGLAND_WALES,
        material_lane=retrieval_service.MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity="case:relevant",
        content_sha256=relevant_sha256,
        metadata={**common_metadata, "canonical_chunk_sha256": relevant_sha256},
    )
    unrelated_text = "Saturn has a prominent system of icy rings."
    unrelated_sha256 = hashlib.sha256(unrelated_text.encode("utf-8")).hexdigest()
    unrelated = retrieval_service.IndexedChunk(
        chunk_id="unrelated",
        text=unrelated_text,
        vector=(0.0, 1.0) + (0.0,) * (retrieval_service.VECTOR_DIMENSIONS - 2),
        jurisdiction=retrieval_service.Jurisdiction.ENGLAND_WALES,
        material_lane=retrieval_service.MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity="case:unrelated",
        content_sha256=unrelated_sha256,
        metadata={**common_metadata, "canonical_chunk_sha256": unrelated_sha256},
    )

    assert session.write_chunks((relevant, unrelated)) == 2
    session.create_indexes()
    assert session.table is not None
    lexical = (
        session.table.search("consideration", query_type="fts", fts_columns=["text"])
        .limit(1)
        .to_list()
    )
    vector = (
        session.table.search(list(relevant.vector), vector_column_name="vector").limit(1).to_list()
    )

    assert lexical[0]["chunk_id"] == "relevant"
    assert vector[0]["chunk_id"] == "relevant"
    session.close()


def _seed_chunk(
    database,
    key: str,
    *,
    text: str,
    jurisdiction: str,
    lane: str = "primary_authority",
    subject: str = "contract",
    as_of_date: str | None = None,
) -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT OR IGNORE INTO source_scans(
          id, status, required_roots_json, roots_seen_json,
          expected_file_count, files_accounted, statuses_json,
          manifest_sha256, created_at, started_at, completed_at
        ) VALUES (
          'test-source-scan', 'complete', '["test-root"]', '["test-root"]',
          1, 1, '{"ready":1}', ?, ?, ?, ?
        )
        """,
        ("f" * 64, now, now, now),
    )
    database.execute(
        """
        INSERT OR IGNORE INTO source_scan_files(
          scan_id, path_fingerprint, status, content_sha256
        ) VALUES ('test-source-scan', ?, 'citable', ?)
        """,
        ("e" * 64, "d" * 64),
    )
    document_sha256 = (key.encode().hex() + "0" * 64)[:64]
    metadata = {
        "identity_verified": True,
        "currentness_verified": True,
        "eligible_for_model_use": True,
        "ai_use_policy": "unreviewed",
        "canonical_citation": f"Example {key} [2026] UKSC 1",
        "citation_data": {"source_type": "case", "neutral_citation": "[2026] UKSC 1"},
    }
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, representation_group_id,
          safe_display_name, media_type, status, lane, subject_primary,
          jurisdiction, retrieval_canonical, searchable_text, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, 'text/markdown', 'citable', ?, ?, ?, 1, 1, ?, ?)
        """,
        (
            f"doc-{key}",
            document_sha256,
            f"identity-{key}",
            f"group-{key}",
            f"source-{key}.md",
            lane,
            subject,
            jurisdiction,
            now,
            now,
        ),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          as_of_date, canonical_url, stable_identifier, currentness_status,
          review_status, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'current', 'approved', ?, ?)
        """,
        (
            f"version-{key}",
            f"doc-{key}",
            document_sha256,
            f"data/vault/{key}.md",
            f"Example {key}",
            as_of_date,
            f"https://example.test/{key}",
            f"neutral-citation:{key}",
            json.dumps(metadata),
            now,
        ),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id, source_version_id, ordinal, locator, text_sha256, markdown_text,
          token_count, metadata_json
        ) VALUES (?, ?, 0, 'para 1', ?, ?, ?, '{}')
        """,
        (
            f"chunk-{key}",
            f"version-{key}",
            hashlib.sha256(text.encode("utf-8")).hexdigest(),
            text,
            len(text.split()),
        ),
    )


def _install_fake_lance(monkeypatch) -> None:
    monkeypatch.setattr(retrieval_service, "_import_lancedb", lambda: _FakeLanceDB)
    monkeypatch.setitem(
        sys.modules,
        "lancedb.index",
        SimpleNamespace(IvfFlat=lambda **kwargs: {"type": "ivf_flat", **kwargs}),
    )


def _write_benchmark(
    root: Path,
    *,
    primary_chunk_ids: list[str],
    relevant_chunk_ids: list[str] | None = None,
    query: str = "consideration bargain exchange",
    status: str = "approved",
) -> Path:
    # Legacy fixture builder is test-only; Settings points at v1.1.json.
    path = root / "benchmarks" / "retrieval" / "v1.1.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "schema": "legalbot.retrieval-benchmark.v1",
                "benchmark_id": "legal-core",
                "version": "1.0.0",
                "status": status,
                "queries": [
                    {
                        "id": "contract-consideration",
                        "query": query,
                        "jurisdiction": "England and Wales",
                        "subject": "contract",
                        "as_of_date": "2026-08-11",
                        "primary_must_hit_chunk_ids": primary_chunk_ids,
                        "relevant_chunk_ids": relevant_chunk_ids or [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_candidate_build_promotion_and_hybrid_retrieval_are_fail_closed(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "allowed",
        text="Consideration requires a bargain and an exchange of value.",
        jurisdiction="England and Wales",
    )
    _seed_chunk(
        database,
        "wrong-jurisdiction",
        text="Consideration bargain exchange under American law.",
        jurisdiction="United States",
    )
    _seed_chunk(
        database,
        "teaching",
        text="Consideration bargain lecture summary.",
        jurisdiction="England and Wales",
        lane="private_teaching",
    )
    _seed_chunk(
        database,
        "assessment",
        text="Consideration bargain marker feedback.",
        jurisdiction="England and Wales",
        lane="assessment_guidance",
    )
    _seed_chunk(
        database,
        "future",
        text="Consideration bargain future authority.",
        jurisdiction="England and Wales",
        as_of_date="2099-01-01",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-allowed"])
    _install_fake_lance(monkeypatch)

    built = build_candidate_index(settings, database, "candidate-1")
    assert built["status"] == "candidate"
    build_path = settings.index_dir / "builds" / "candidate-1"
    assert (build_path / "manifest.json").is_file()
    assert json.loads((build_path / "evaluation.json").read_text())["passed"] is True
    report = json.loads((build_path / "retrieval-benchmark-report.json").read_text())
    assert report["metrics"]["primary_recall_at_5"] == 1.0
    assert report["metrics"]["broader_recall_at_10"] == 1.0
    assert report["metrics"]["mrr"] == 1.0
    assert (build_path / "retrieval-benchmark.json").is_file()
    assert (build_path / "seal.json").is_file()
    assert not (settings.index_dir / "ACTIVE.json").exists()

    promoted = _promote_with_test_only_authority_stub(settings, database, "candidate-1")
    assert promoted == {"build_id": "candidate-1", "status": "active"}
    service = HybridRetrievalService(settings, database)
    spans = asyncio.run(
        service.retrieve(
            query="consideration bargain exchange",
            jurisdiction="England and Wales",
            subject="contract",
            as_of_date=__import__("datetime").date(2026, 8, 11),
            limit=10,
        )
    )
    assert service.active_build_id() == "candidate-1"
    assert [span.chunk_id for span in spans] == ["chunk-allowed"]
    assert spans[0].lane == "primary_authority"
    assert spans[0].identity_verified is True
    assert spans[0].currentness_verified is True
    assert spans[0].index_build_id == "candidate-1"
    notes = asyncio.run(
        service.retrieve_issue_spotting_notes(
            query="consideration bargain lecture",
            jurisdiction="England and Wales",
            subject="contract",
            as_of_date=__import__("datetime").date(2026, 8, 11),
        )
    )
    assert [note.chunk_id for note in notes] == ["chunk-teaching"]
    assert notes[0].index_build_id == "candidate-1"
    assert not hasattr(notes[0], "canonical_citation")
    assert all(note.chunk_id not in {span.chunk_id for span in spans} for note in notes)

    # A changed Lance generation cannot be silently searched under the old seal.
    (build_path / "lance" / "rows.json").write_text("[]", encoding="utf-8")
    with pytest.raises(RuntimeError, match="changed after sealing"):
        asyncio.run(
            HybridRetrievalService(settings, database).retrieve(
                query="consideration",
                jurisdiction="England and Wales",
                subject="contract",
                as_of_date=__import__("datetime").date(2026, 8, 11),
            )
        )


def test_pinned_retrieval_hashes_tree_once_and_detects_later_drift(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "verified-capability",
        text="Consideration requires a bargain and an exchange of value.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-verified-capability"])
    _install_fake_lance(monkeypatch)
    build_candidate_index(settings, database, "verified-capability-candidate")

    full_tree_hash_calls = 0
    original_tree_sha256 = retrieval_service._tree_sha256

    def counted_tree_sha256(root: Path) -> str:
        nonlocal full_tree_hash_calls
        full_tree_hash_calls += 1
        return original_tree_sha256(root)

    monkeypatch.setattr(retrieval_service, "_tree_sha256", counted_tree_sha256)
    service = HybridRetrievalService(
        settings,
        database,
        pinned_build_id="verified-capability-candidate",
    )
    request = {
        "query": "consideration bargain exchange",
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "as_of_date": __import__("datetime").date(2026, 8, 11),
    }

    first = asyncio.run(service.retrieve(**request))
    second = asyncio.run(service.retrieve(**request))

    assert [span.chunk_id for span in first] == ["chunk-verified-capability"]
    assert [span.chunk_id for span in second] == ["chunk-verified-capability"]
    assert full_tree_hash_calls == 1

    build_path = settings.index_dir / "builds" / "verified-capability-candidate"
    rows_path = next((build_path / "lance").rglob("rows.json"))
    rows_path.write_bytes(rows_path.read_bytes() + b"\n")

    with pytest.raises(RuntimeError, match="changed after content verification"):
        asyncio.run(service.retrieve(**request))
    assert full_tree_hash_calls == 1


def test_retrieval_cache_key_changes_with_selected_scorer_proof(
    tmp_path: Path, database, monkeypatch
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    service = HybridRetrievalService(settings, database, pinned_build_id="candidate-cache-proof")
    observed_keys: list[str] = []

    class RecordingCache:
        def get(self, *, active_build_id: str, key: str) -> tuple[()]:
            assert active_build_id == "candidate-cache-proof"
            observed_keys.append(key)
            return ()

    monkeypatch.setattr(service, "_retrieval_cache", RecordingCache())
    monkeypatch.setattr(
        service,
        "_runtime",
        lambda *_args, **_kwargs: (object(), object(), SimpleNamespace()),
    )
    build_row = {
        "id": "candidate-cache-proof",
        "corpus_id": "candidate-cache-proof-corpus",
        "chunker_version": "chunker-v1",
        "embedding_model_version": "embedding-v1",
        "embedding_model": "embedding-v1",
        "rerank_version": "reranker-v1",
        "reranker_model": "reranker-v1",
        "policy_sha256": "1" * 64,
    }
    item = retrieval_service.RetrievalPlanItem(
        query="consideration bargain exchange",
        jurisdiction="England and Wales",
        subject="contract",
        as_of_date=__import__("datetime").date(2026, 8, 22),
        limit=5,
    )

    def boundary(*, attestation: str, closure: str) -> Any:
        return retrieval_service._VerifiedRetrievalBoundary(
            capability=retrieval_service._VerifiedBuildCapability(
                build_id="candidate-cache-proof",
                source_manifest_sha256="2" * 64,
                catalogue_binding_sha256="3" * 64,
                tree_metadata_sha256="4" * 64,
                durable_v1_1=True,
                attestation_sha256=attestation,
                scorer_implementation_sha256="5" * 64,
                scorer_closure_aggregate_sha256=closure,
            ),
            build_row=build_row,
        )

    service._prepare_authority_sync(
        item,
        boundary=boundary(attestation="6" * 64, closure="7" * 64),
    )
    service._prepare_authority_sync(
        item,
        boundary=boundary(attestation="8" * 64, closure="7" * 64),
    )
    service._prepare_authority_sync(
        item,
        boundary=boundary(attestation="6" * 64, closure="9" * 64),
    )

    assert len(observed_keys) == 3
    assert len(set(observed_keys)) == 3


def test_retrieval_catalogue_binding_includes_lifecycle_status() -> None:
    candidate = {"id": "candidate-status-fence", "status": "candidate"}
    active = {**candidate, "status": "active"}

    assert retrieval_service._runtime_catalogue_binding_sha256(
        candidate
    ) != retrieval_service._runtime_catalogue_binding_sha256(active)


def test_diagnostic_slice_requires_complete_durable_seal_contract(
    tmp_path: Path,
) -> None:
    from app.retrieval.diagnostic_slice import DIAGNOSTIC_SLICE_BUILD_ID

    settings = Settings(project_root=tmp_path, test_mode=True)
    build_path = settings.index_dir / "builds" / DIAGNOSTIC_SLICE_BUILD_ID
    build_path.mkdir(parents=True)
    row = {"id": DIAGNOSTIC_SLICE_BUILD_ID, "status": "built_unscored"}

    with pytest.raises(RuntimeError, match="lacks the durable sealed-candidate contract"):
        retrieval_service._verify_diagnostic_slice_for_canary(settings, row)

    (build_path / "approved-source-manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="missing a sealed build artefact"):
        retrieval_service._verify_diagnostic_slice_for_canary(settings, row)


def test_empty_optional_physical_lanes_do_not_break_authority_only_runtime(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "authority-only",
        text="Consideration requires a bargain and an exchange of value.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-authority-only"])
    _install_fake_lance(monkeypatch)

    build_candidate_index(settings, database, "authority-only-candidate")
    build_path = settings.index_dir / "builds" / "authority-only-candidate"
    lane_manifest = json.loads(
        (build_path / "lance" / "physical-lanes.json").read_text(encoding="utf-8")
    )
    assert lane_manifest["tables"]["authority"]["row_count"] == 1
    assert lane_manifest["tables"]["teaching"]["row_count"] == 0
    assert lane_manifest["tables"]["assessment"]["row_count"] == 0

    _promote_with_test_only_authority_stub(settings, database, "authority-only-candidate")
    service = HybridRetrievalService(settings, database)
    spans = asyncio.run(
        service.retrieve(
            query="consideration bargain exchange",
            jurisdiction="England and Wales",
            subject="contract",
            as_of_date=__import__("datetime").date(2026, 8, 11),
        )
    )
    notes = asyncio.run(
        service.retrieve_issue_spotting_notes(
            query="consideration lecture summary",
            jurisdiction="England and Wales",
            subject="contract",
            as_of_date=__import__("datetime").date(2026, 8, 11),
        )
    )
    build_row = database.fetchone("SELECT * FROM index_builds WHERE id='authority-only-candidate'")

    assert [span.chunk_id for span in spans] == ["chunk-authority-only"]
    assert notes == ()
    assert build_row is not None
    assert service._runtime("authority-only-candidate", dict(build_row), "assessment") is None


def test_reviewed_material_update_filters_cached_active_evidence_until_resolution(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "update-gate",
        text="Consideration requires a bargain and an exchange of value.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-update-gate"])
    _install_fake_lance(monkeypatch)
    build_candidate_index(settings, database, "update-gate-candidate")
    _promote_with_test_only_authority_stub(settings, database, "update-gate-candidate")

    database.enqueue_research_task(
        task_id="research-update-gate",
        idempotency_key="research-update-gate-idempotency",
        task_type="source_update_check",
        trigger_kind="manual",
        priority_band="high",
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date="2026-08-15",
        query_sha256="a" * 64,
    )
    database.add_source_update_observation(
        observation_id="observation-update-gate",
        task_id="research-update-gate",
        source_id="uk_supreme_court",
        authority_identity_id="neutral-citation:update-gate",
        comparison_state="changed",
        pinned_index_build_id="update-gate-candidate",
        observed_active_build_id="update-gate-candidate",
        baseline_version_sha256="b" * 64,
        remote_content_sha256="c" * 64,
    )
    service = HybridRetrievalService(settings, database)
    arguments = {
        "query": "consideration bargain exchange",
        "jurisdiction": "England and Wales",
        "subject": "contract",
        "as_of_date": __import__("datetime").date(2026, 8, 15),
        "limit": 10,
    }
    # Raw changed bytes are diagnostic only and the hit is cached safely by ID.
    assert [span.chunk_id for span in asyncio.run(service.retrieve(**arguments))] == [
        "chunk-update-gate"
    ]

    database.record_source_update_review(
        "observation-update-gate",
        review_id="review-observation-update-gate",
        review_status="approved",
        materiality_status="material",
        reviewer_ref=f"reviewer:{'d' * 64}",
        review_manifest_sha256="e" * 64,
    )
    assert asyncio.run(service.retrieve(**arguments)) == ()
    assert service.last_retrieval_code == "verified_material_update_unresolved"


def test_promotion_refuses_candidate_after_approved_source_supersession(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "original",
        text="Consideration requires a bargain and an exchange of value.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-original"])
    _install_fake_lance(monkeypatch)

    built = build_candidate_index(settings, database, "stale-source-candidate")
    assert built["status"] == "candidate"
    build_path = settings.index_dir / "builds" / "stale-source-candidate"
    sealed_manifest = json.loads((build_path / "manifest.json").read_text())[
        "source_manifest_sha256"
    ]

    _seed_chunk(
        database,
        "replacement",
        text="A replacement current version states the consideration rule.",
        jurisdiction="England and Wales",
    )
    database.execute(
        "UPDATE source_versions SET superseded_by=? WHERE id=?",
        ("version-replacement", "version-original"),
    )

    current_snapshot = retrieval_service._approved_source_snapshot(database)
    assert current_snapshot.source_manifest_sha256 != sealed_manifest
    with pytest.raises(RuntimeError, match="approved-source manifest is stale"):
        _promote_with_test_only_authority_stub(settings, database, "stale-source-candidate")

    row = database.fetchone(
        "SELECT status, promoted_at FROM index_builds WHERE id='stale-source-candidate'"
    )
    assert row["status"] == "candidate"
    assert row["promoted_at"] is None
    assert database.active_index_id() is None
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_candidate_build_is_refused_while_source_scan_is_queued(tmp_path: Path, database) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    database.create_source_scan("queued-during-build", (source_root,))

    settings = Settings(project_root=tmp_path, test_mode=True)
    with pytest.raises(RuntimeError, match="source scan is queued or running"):
        build_candidate_index(settings, database, "blocked-build")

    assert database.fetchone("SELECT id FROM index_builds WHERE id='blocked-build'") is None
    assert not (settings.index_dir / "builds" / "blocked-build").exists()


def test_candidate_promotion_is_atomically_refused_while_source_scan_is_running(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "scan-race",
        text="Consideration requires a bargain and an exchange of value.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-scan-race"])
    _install_fake_lance(monkeypatch)

    build_candidate_index(settings, database, "active-before-scan")
    _promote_with_test_only_authority_stub(settings, database, "active-before-scan")
    build_candidate_index(settings, database, "candidate-during-scan")
    pointer_path = settings.index_dir / "ACTIVE.json"
    pointer_before = pointer_path.read_bytes()

    source_root = tmp_path / "sources"
    source_root.mkdir()
    roots = database.create_source_scan("running-during-promotion", (source_root,))
    database.start_source_scan("running-during-promotion", roots_seen=roots, expected_file_count=0)

    with pytest.raises(RuntimeError, match="source scan is queued or running"):
        _promote_with_test_only_authority_stub(settings, database, "candidate-during-scan")

    rows = {
        str(row["id"]): row
        for row in database.fetchall(
            "SELECT id, status, promoted_at FROM index_builds "
            "WHERE id IN ('active-before-scan', 'candidate-during-scan')"
        )
    }
    assert rows["active-before-scan"]["status"] == "active"
    assert rows["active-before-scan"]["promoted_at"] is not None
    assert rows["candidate-during-scan"]["status"] == "candidate"
    assert rows["candidate-during-scan"]["promoted_at"] is None
    assert database.active_index_id() == "active-before-scan"
    assert pointer_path.read_bytes() == pointer_before


def test_build_records_failure_when_lancedb_is_unavailable(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "one",
        text="A reviewed legal proposition.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-one"])

    def unavailable() -> Any:
        raise RuntimeError("LanceDB is required; no alternate index backend is permitted")

    monkeypatch.setattr(retrieval_service, "_import_lancedb", unavailable)
    with pytest.raises(RuntimeError, match="no alternate index backend"):
        build_candidate_index(settings, database, "no-lance")
    row = database.fetchone("SELECT * FROM index_builds WHERE id='no-lance'")
    assert row["status"] == "failed"
    assert json.loads(row["metrics_json"])["failure_type"] == "RuntimeError"
    assert database.active_index_id() is None


def test_candidate_build_refuses_unapproved_chunks_before_opening_lancedb(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "staged",
        text="This source is parsed but has not been approved.",
        jurisdiction="England and Wales",
    )
    database.execute("UPDATE source_versions SET review_status='staged'")
    settings = Settings(project_root=tmp_path, test_mode=True)
    opened = False

    def should_not_open() -> Any:
        nonlocal opened
        opened = True
        return _FakeLanceDB

    monkeypatch.setattr(retrieval_service, "_import_lancedb", should_not_open)
    with pytest.raises(ValueError, match="no human-approved chunks"):
        build_candidate_index(settings, database, "unapproved")
    assert opened is False
    assert (
        database.fetchone("SELECT status FROM index_builds WHERE id='unapproved'")["status"]
        == "failed"
    )
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_candidate_build_requires_an_approved_versioned_benchmark_before_lancedb(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "one",
        text="A reviewed legal proposition.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-one"], status="draft")
    opened = False

    def should_not_open() -> Any:
        nonlocal opened
        opened = True
        return _FakeLanceDB

    monkeypatch.setattr(retrieval_service, "_import_lancedb", should_not_open)
    with pytest.raises(ValueError, match="owner-approved"):
        build_candidate_index(settings, database, "draft-benchmark")
    assert opened is False
    assert (
        database.fetchone("SELECT status FROM index_builds WHERE id='draft-benchmark'")["status"]
        == "failed"
    )
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_promotion_rejects_a_changed_retrieval_benchmark_report(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "one",
        text="Consideration bargain exchange authority.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-one"])
    _install_fake_lance(monkeypatch)
    build_candidate_index(settings, database, "tampered-report")
    report_path = (
        settings.index_dir / "builds" / "tampered-report" / "retrieval-benchmark-report.json"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["metrics"]["primary_recall_at_5"] = 0.0
    report_path.chmod(0o644)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(RuntimeError, match="report changed after sealing"):
        _promote_with_test_only_authority_stub(settings, database, "tampered-report")

    assert database.active_index_id() is None
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_candidate_build_fails_with_persisted_report_when_retrieval_gate_misses(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "indexed",
        text="A reviewed but unrelated legal proposition.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(
        tmp_path,
        primary_chunk_ids=["chunk-required-but-absent"],
        query="a unique benchmark query",
    )
    _install_fake_lance(monkeypatch)

    with pytest.raises(RuntimeError, match="promotion gates did not pass"):
        build_candidate_index(settings, database, "missed-benchmark")

    build_path = settings.index_dir / "builds" / "missed-benchmark"
    report = json.loads((build_path / "retrieval-benchmark-report.json").read_text())
    assert report["passed"] is False
    assert report["metrics"]["primary_recall_at_5"] == 0.0
    assert report["metrics"]["broader_recall_at_10"] == 0.0
    assert report["integrity_failures"] == [
        "benchmark expected chunks missing from candidate: chunk-required-but-absent"
    ]
    assert (build_path / "evaluation.json").is_file()
    assert not (build_path / "seal.json").exists()
    row = database.fetchone(
        "SELECT status, metrics_json FROM index_builds WHERE id=?", ("missed-benchmark",)
    )
    assert row["status"] == "failed"
    assert json.loads(row["metrics_json"])["evaluation"]["passed"] is False
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_candidate_embeddings_and_lance_writes_are_bounded_batches(
    tmp_path: Path, database, monkeypatch
) -> None:
    for number in range(5):
        _seed_chunk(
            database,
            f"batch-{number}",
            text=f"Streaming authority batch {number} on consideration bargain exchange.",
            jurisdiction="England and Wales",
        )
    settings = Settings(project_root=tmp_path, test_mode=True)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-batch-0"])
    _install_fake_lance(monkeypatch)
    monkeypatch.setattr(retrieval_service, "INDEX_EMBED_BATCH_SIZE", 2)
    monkeypatch.setattr(retrieval_service, "LANCE_WRITE_BATCH_SIZE", 2)

    delegate = retrieval_service.DeterministicHashEmbedding()

    class RecordingEmbedder:
        dimensions = delegate.dimensions

        def __init__(self) -> None:
            self.document_batch_sizes: list[int] = []

        def embed_query(self, text: str) -> tuple[float, ...]:
            return delegate.embed_query(text)

        def embed_documents(self, texts: list[str]) -> tuple[tuple[float, ...], ...]:
            self.document_batch_sizes.append(len(texts))
            return delegate.embed_documents(texts)

    recorder = RecordingEmbedder()
    monkeypatch.setattr(retrieval_service, "_embedding_provider", lambda *_: recorder)

    built = build_candidate_index(settings, database, "streamed")

    assert built["chunk_count"] == 5
    assert recorder.document_batch_sizes == [2, 2, 1]
    rows = json.loads(
        (
            settings.index_dir / "builds" / "streamed" / "lance" / "authority" / "rows.json"
        ).read_text()
    )
    assert len(rows) == 5
    assert json.loads(
        (
            settings.index_dir
            / "builds"
            / "streamed"
            / "lance"
            / "authority"
            / "write-batches.json"
        ).read_text()
    ) == [2, 2, 1]


def test_lance_prefilter_uses_exact_non_core_jurisdiction_key() -> None:
    filters = retrieval_service.QueryFilters(
        jurisdictions=frozenset({retrieval_service.Jurisdiction.COMPARATIVE}),
        material_lanes=frozenset({retrieval_service.MaterialLane.PRIMARY_AUTHORITY}),
        exact_jurisdictions=frozenset({"canada"}),
    )

    expression = retrieval_service._lance_filter(filters, __import__("datetime").date(2026, 8, 11))

    assert "jurisdiction_key IN ('comparative')" in expression
    assert "catalog_jurisdiction_key IN ('canada')" in expression
    assert "retrieval_eligible = TRUE" in expression


def test_historical_enactment_is_physically_indexed_but_not_answer_retrievable() -> None:
    text = "Historical statutory wording."
    text_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    chunk = retrieval_service.IndexedChunk(
        chunk_id="historical-act",
        text=text,
        vector=(0.0,) * retrieval_service.VECTOR_DIMENSIONS,
        jurisdiction=retrieval_service.Jurisdiction.ENGLAND_WALES,
        material_lane=retrieval_service.MaterialLane.PRIMARY_AUTHORITY,
        subject="contract",
        review_state="approved",
        source_identity="ukpga:1977:50:enacted",
        content_sha256=text_sha256,
        metadata={
            "source_version_id": "historical-source",
            "locator": "s 1",
            "catalog_lane": "primary_authority",
            "catalog_jurisdiction": "England and Wales",
            "citation_data": {"source_type": "legislation"},
            "currentness_status": "historical",
            "identity_verified": True,
            "currentness_verified": True,
            "retrieval_eligible": False,
            "canonical_chunk_sha256": text_sha256,
        },
    )
    row = retrieval_service._indexed_to_lance_row(chunk)
    assert row["retrieval_eligible"] is False


def test_production_retrieval_models_load_only_from_verified_local_stores(
    tmp_path: Path, monkeypatch
) -> None:
    calls: list[tuple[str, str, str]] = []
    embedding_path = tmp_path / "embedding"
    reranker_path = tmp_path / "reranker"
    embedding_path.mkdir()
    reranker_path.mkdir()

    def verified_local_model(
        path: Path,
        repo_id: str,
        revision: str,
        *,
        expected_file_manifest_sha256: str,
    ) -> Path:
        expected = {
            embedding_path: (
                retrieval_service.PINNED_EMBEDDING_REPO,
                retrieval_service.PINNED_EMBEDDING_REVISION,
                retrieval_service.PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
            ),
            reranker_path: (
                retrieval_service.PINNED_RERANKER_REPO,
                retrieval_service.PINNED_RERANKER_REVISION,
                retrieval_service.PINNED_RERANKER_FILE_MANIFEST_SHA256,
            ),
        }
        assert (repo_id, revision, expected_file_manifest_sha256) == expected[path]
        calls.append(("verified", str(path), expected_file_manifest_sha256))
        return path

    class FakeEmbeddingModel:
        def __init__(
            self,
            model_path: str,
            *,
            local_files_only: bool,
            truncate_dim: int,
            model_kwargs: dict[str, str],
        ) -> None:
            assert local_files_only is True
            calls.append(("embedding", model_path, "local-only"))
            assert truncate_dim == 1024
            assert model_kwargs == {"dtype": "float16"}

        def get_sentence_embedding_dimension(self) -> int:
            return 1024

    embedding_module = SimpleNamespace(
        SentenceTransformer=FakeEmbeddingModel,
    )

    class FakeTokenizer:
        pad_token_id = 0
        eos_token_id = 0
        eos_token = "<eos>"
        unk_token_id = -1
        padding_side = "right"

        @classmethod
        def from_pretrained(
            cls, model_path: str, *, local_files_only: bool, padding_side: str
        ) -> FakeTokenizer:
            assert local_files_only is True
            calls.append(("reranker_tokenizer", model_path, "local-only"))
            tokenizer = cls()
            tokenizer.padding_side = padding_side
            return tokenizer

        def convert_tokens_to_ids(self, token: str) -> int:
            return {"no": 10, "yes": 11}[token]

        def encode(self, text: str, *, add_special_tokens: bool) -> list[int]:
            assert text and add_special_tokens is False
            return [1, 2]

    class FakeQwen3ForCausalLM:
        def get_output_embeddings(self) -> object:
            return object()

        def to(self, device: str) -> FakeQwen3ForCausalLM:
            assert device == "cpu"
            return self

        def eval(self) -> FakeQwen3ForCausalLM:
            return self

    class FakeAutoModelForCausalLM:
        @staticmethod
        def from_pretrained(
            model_path: str, *, local_files_only: bool, dtype: str
        ) -> FakeQwen3ForCausalLM:
            assert local_files_only is True
            assert dtype == "auto"
            calls.append(("reranker_causal_lm", model_path, "local-only"))
            return FakeQwen3ForCausalLM()

    class ForbiddenSequenceClassificationFactory:
        @staticmethod
        def from_pretrained(*args: Any, **kwargs: Any) -> None:
            del args, kwargs
            raise AssertionError("an untrained sequence-classification head must never load")

    transformers_module = SimpleNamespace(
        AutoTokenizer=FakeTokenizer,
        AutoModelForCausalLM=FakeAutoModelForCausalLM,
        AutoModelForSequenceClassification=ForbiddenSequenceClassificationFactory,
    )
    torch_module = SimpleNamespace(
        backends=SimpleNamespace(mps=SimpleNamespace(is_available=lambda: False)),
        cuda=SimpleNamespace(is_available=lambda: False),
        device=lambda value: value,
    )

    def import_module(name: str) -> Any:
        return {
            "sentence_transformers": embedding_module,
            "transformers": transformers_module,
            "torch": torch_module,
        }[name]

    monkeypatch.setattr(retrieval_service.importlib, "import_module", import_module)
    monkeypatch.setattr(retrieval_service, "_verified_local_model", verified_local_model)
    monkeypatch.setattr(retrieval_service, "_torch_retrieval_device_name", lambda: "")
    embedding = retrieval_service.QwenEmbeddingProvider(
        retrieval_service.PINNED_EMBEDDING_REPO,
        retrieval_service.PINNED_EMBEDDING_REVISION,
        embedding_path,
    )
    reranker = retrieval_service.QwenRerankerProvider(
        retrieval_service.PINNED_RERANKER_REPO,
        retrieval_service.PINNED_RERANKER_REVISION,
        reranker_path,
    )

    embedding._load()
    runtime = reranker._load()

    assert runtime.tokenizer.padding_side == "left"
    assert runtime.false_token_id == 10
    assert runtime.true_token_id == 11
    assert type(runtime.model).__name__ == "FakeQwen3ForCausalLM"
    assert not hasattr(runtime.model, "score")

    assert calls == [
        (
            "verified",
            str(embedding_path),
            retrieval_service.PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
        ),
        ("embedding", str(embedding_path), "local-only"),
        (
            "verified",
            str(reranker_path),
            retrieval_service.PINNED_RERANKER_FILE_MANIFEST_SHA256,
        ),
        ("reranker_tokenizer", str(reranker_path), "local-only"),
        ("reranker_causal_lm", str(reranker_path), "local-only"),
    ]


def test_production_retrieval_models_refuse_missing_store_before_runtime_import(
    tmp_path: Path, monkeypatch
) -> None:
    imports: list[str] = []

    def forbidden_import(name: str) -> None:
        imports.append(name)
        raise AssertionError("runtime libraries must not load for a missing pinned store")

    monkeypatch.setattr(retrieval_service.importlib, "import_module", forbidden_import)
    providers = (
        retrieval_service.QwenEmbeddingProvider(
            retrieval_service.PINNED_EMBEDDING_REPO,
            retrieval_service.PINNED_EMBEDDING_REVISION,
            tmp_path / "missing-embedding",
        ),
        retrieval_service.QwenRerankerProvider(
            retrieval_service.PINNED_RERANKER_REPO,
            retrieval_service.PINNED_RERANKER_REVISION,
            tmp_path / "missing-reranker",
        ),
    )

    for provider in providers:
        with pytest.raises(RuntimeError, match="pinned local retrieval model is missing"):
            provider._load()

    assert imports == []


def test_production_retrieval_models_refuse_mismatched_store_before_runtime_import(
    tmp_path: Path, monkeypatch
) -> None:
    model_path = tmp_path / "mismatched-model"
    model_path.mkdir()
    (model_path / "retrieval-model.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_repo": "unapproved/retrieval-model",
                "revision": "0" * 40,
                "files": [{"path": "config.json", "size": 2, "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )
    imports: list[str] = []

    def forbidden_import(name: str) -> None:
        imports.append(name)
        raise AssertionError("runtime libraries must not load for a mismatched pinned store")

    monkeypatch.setattr(retrieval_service.importlib, "import_module", forbidden_import)
    providers = (
        retrieval_service.QwenEmbeddingProvider(
            retrieval_service.PINNED_EMBEDDING_REPO,
            retrieval_service.PINNED_EMBEDDING_REVISION,
            model_path,
        ),
        retrieval_service.QwenRerankerProvider(
            retrieval_service.PINNED_RERANKER_REPO,
            retrieval_service.PINNED_RERANKER_REVISION,
            model_path,
        ),
    )

    for provider in providers:
        with pytest.raises(RuntimeError, match="provenance does not match its pin"):
            provider._load()

    assert imports == []


def test_legacy_chunk_id_builder_is_disabled_in_production(
    tmp_path: Path, database, monkeypatch
) -> None:
    _seed_chunk(
        database,
        "pinned",
        text="Pinned consideration bargain exchange authority.",
        jurisdiction="England and Wales",
    )
    settings = Settings(project_root=tmp_path, test_mode=False)
    _write_benchmark(tmp_path, primary_chunk_ids=["chunk-pinned"])
    _install_fake_lance(monkeypatch)
    monkeypatch.setattr(
        retrieval_service,
        "_embedding_provider",
        lambda *_: retrieval_service.DeterministicHashEmbedding(),
    )
    monkeypatch.setattr(
        retrieval_service,
        "_reranker_provider",
        lambda *_: retrieval_service._TestOverlapReranker(),
    )

    with pytest.raises(RuntimeError, match="legacy chunk-ID candidate builder is disabled"):
        build_candidate_index(settings, database, "pinned-models")


def test_causal_reranker_uses_yes_no_logits_left_padding_and_bounded_batches(
    tmp_path: Path, monkeypatch
) -> None:
    class FakeVector:
        def __init__(self, values: list[float]) -> None:
            self.values = values

        def exp(self) -> FakeVector:
            return FakeVector([math.exp(value) for value in self.values])

        def detach(self) -> FakeVector:
            return self

        def float(self) -> FakeVector:
            return self

        def cpu(self) -> FakeVector:
            return self

        def tolist(self) -> list[float]:
            return self.values

    class FakeFinalLogits:
        def __init__(self, rows: list[tuple[float, float]]) -> None:
            self.rows = rows

        def __getitem__(self, key: tuple[slice, int]) -> FakeVector:
            _, token_id = key
            position = {10: 0, 11: 1}[token_id]
            return FakeVector([row[position] for row in self.rows])

    class FakeLogits:
        def __init__(self, rows: list[tuple[float, float]]) -> None:
            self.rows = rows

        def __getitem__(self, key: tuple[slice, int, slice]) -> FakeFinalLogits:
            del key
            return FakeFinalLogits(self.rows)

    class FakeYesNoLogits:
        def __init__(self, rows: list[tuple[float, float]]) -> None:
            self.rows = rows

    class FakeLogProbabilities:
        def __init__(self, rows: list[tuple[float, float]]) -> None:
            self.rows = rows

        def __getitem__(self, key: tuple[slice, int]) -> FakeVector:
            _, position = key
            return FakeVector([row[position] for row in self.rows])

    class FakeInputTensor:
        def __init__(self, rows: list[list[int]]) -> None:
            self.rows = rows

        def to(self, device: str) -> FakeInputTensor:
            assert device == "cpu"
            return self

    class NoGrad:
        def __enter__(self) -> None:
            return None

        def __exit__(self, *args: Any) -> None:
            del args

    class FakeFunctional:
        @staticmethod
        def log_softmax(values: FakeYesNoLogits, *, dim: int) -> FakeLogProbabilities:
            assert dim == 1
            rows: list[tuple[float, float]] = []
            for false_logit, true_logit in values.rows:
                denominator = math.exp(false_logit) + math.exp(true_logit)
                rows.append(
                    (
                        math.log(math.exp(false_logit) / denominator),
                        math.log(math.exp(true_logit) / denominator),
                    )
                )
            return FakeLogProbabilities(rows)

    class FakeTorch:
        nn = SimpleNamespace(functional=FakeFunctional)

        @staticmethod
        def no_grad() -> NoGrad:
            return NoGrad()

        @staticmethod
        def inference_mode() -> NoGrad:
            return NoGrad()

        @staticmethod
        def stack(vectors: list[FakeVector], *, dim: int) -> FakeYesNoLogits:
            assert dim == 1 and len(vectors) == 2
            return FakeYesNoLogits(list(zip(vectors[0].values, vectors[1].values, strict=True)))

    class FakeTokenizer:
        padding_side = "left"

        def __init__(self) -> None:
            self.batch_sizes: list[int] = []

        def __call__(
            self,
            prompts: list[str],
            *,
            padding: bool,
            truncation: str,
            return_attention_mask: bool,
            max_length: int,
        ) -> dict[str, list[list[int]]]:
            assert padding is False
            assert truncation == "longest_first"
            assert return_attention_mask is False
            assert max_length < retrieval_service.RERANK_MAX_LENGTH
            return {
                "input_ids": [
                    [42, 7] if "DIRECTLY_RELEVANT" in prompt else [9] for prompt in prompts
                ]
            }

        def pad(
            self,
            inputs: dict[str, list[list[int]]],
            *,
            padding: bool,
            pad_to_multiple_of: int,
            return_tensors: str,
        ) -> dict[str, Any]:
            assert padding is True
            assert pad_to_multiple_of == retrieval_service.RERANK_PAD_MULTIPLE
            assert return_tensors == "pt"
            rows = inputs["input_ids"]
            self.batch_sizes.append(len(rows))
            width = max(len(row) for row in rows)
            width = ((width + pad_to_multiple_of - 1) // pad_to_multiple_of) * pad_to_multiple_of
            padded = [[0] * (width - len(row)) + row for row in rows]
            assert all(row[-1] == 2 for row in padded)
            return {"input_ids": FakeInputTensor(padded)}

    class FakeQwen3ForCausalLM:
        def __call__(
            self,
            *,
            input_ids: FakeInputTensor,
            use_cache: bool,
            logits_to_keep: int,
        ) -> Any:
            assert use_cache is False
            assert logits_to_keep == 1
            rows = []
            for row in input_ids.rows:
                relevant = 42 in row
                rows.append((-3.0, 3.0) if relevant else (3.0, -3.0))
            return SimpleNamespace(logits=FakeLogits(rows))

    tokenizer = FakeTokenizer()
    runtime = retrieval_service._CausalRerankerRuntime(
        tokenizer=tokenizer,
        model=FakeQwen3ForCausalLM(),
        torch=FakeTorch,
        false_token_id=10,
        true_token_id=11,
        prefix_tokens=(1,),
        suffix_tokens=(2,),
        device="cpu",
    )
    provider = retrieval_service.QwenRerankerProvider(
        retrieval_service.PINNED_RERANKER_REPO,
        retrieval_service.PINNED_RERANKER_REVISION,
        tmp_path / "missing-reranker",
    )
    provider._runtime = runtime
    monkeypatch.setattr(retrieval_service, "RERANK_BATCH_SIZE", 2)

    hits = []
    for number in range(5):
        text = "DIRECTLY_RELEVANT authority" if number in {1, 3} else "unrelated passage"
        chunk = retrieval_service.IndexedChunk(
            chunk_id=f"rerank-{number}",
            text=text,
            vector=(0.0,) * 1024,
            jurisdiction=retrieval_service.Jurisdiction.ENGLAND_WALES,
            material_lane=retrieval_service.MaterialLane.PRIMARY_AUTHORITY,
            subject="contract",
            review_state="approved",
            source_identity=f"source:{number}",
            content_sha256=f"{number:x}" * 64,
        )
        hits.append(retrieval_service.SearchHit(chunk=chunk, score=0.1))

    reranked = provider.rerank("legal query", hits, limit=5)

    assert tokenizer.batch_sizes == [2, 2, 1]
    assert [hit.chunk.chunk_id for hit in reranked[:2]] == ["rerank-1", "rerank-3"]
    assert all((hit.rerank_score or 0) > 0.99 for hit in reranked[:2])
    assert all((hit.rerank_score or 1) < 0.01 for hit in reranked[2:])
