from __future__ import annotations

import json
import unittest
from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

from backend.app.ingestion import Jurisdiction, MaterialLane
from backend.app.retrieval import (
    DeterministicHashEmbedding,
    ImmutableLanceRepository,
    IndexedChunk,
)


def _chunk(chunk_id: str, text: str) -> IndexedChunk:
    return IndexedChunk(
        chunk_id=chunk_id,
        text=text,
        vector=DeterministicHashEmbedding().embed_query(text),
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.PRIMARY_AUTHORITY,
        subject="public_law",
        review_state="approved",
        source_identity=f"neutral_citation:{chunk_id}",
        content_sha256="c" * 64,
    )


class _RecordingSession:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.mkdir(parents=True)
        self.rows: tuple[IndexedChunk, ...] = ()
        self.indexes_created = False
        self.closed = False

    def write_chunks(self, chunks: Iterable[IndexedChunk]) -> int:
        self.rows = tuple(chunks)
        return len(self.rows)

    def create_indexes(self) -> None:
        self.indexes_created = True

    def close(self) -> None:
        self.closed = True


class _RecordingFactory:
    def __init__(self) -> None:
        self.sessions: list[_RecordingSession] = []

    def create(self, generation_path: Path) -> _RecordingSession:
        session = _RecordingSession(generation_path)
        self.sessions.append(session)
        return session


class _CreateOnlyIndexTable:
    def __init__(self) -> None:
        self.indices: list[SimpleNamespace] = []
        self.fts_calls: list[dict[str, Any]] = []
        self.vector_calls: list[dict[str, Any]] = []

    def count_rows(self) -> int:
        return 3

    def list_indices(self) -> list[SimpleNamespace]:
        return list(self.indices)

    def create_fts_index(self, column: str, *, replace: bool) -> None:
        self.fts_calls.append({"column": column, "replace": replace})
        self.indices.append(
            SimpleNamespace(columns=[column], index_type="FTS", name="text_idx")
        )

    def create_index(self, **kwargs: Any) -> None:
        self.vector_calls.append(dict(kwargs))
        self.indices.append(
            SimpleNamespace(columns=["vector"], index_type="IVF_FLAT", name="vector_idx")
        )


class _CreateOnlyIndexModule:
    def __init__(self, table: _CreateOnlyIndexTable) -> None:
        self.table = table

    def connect(self, _path: str) -> _CreateOnlyIndexModule:
        return self

    def table_names(self) -> list[str]:
        return ["chunks"]

    def open_table(self, _name: str) -> _CreateOnlyIndexTable:
        return self.table


class ImmutableLanceRepositoryTests(unittest.TestCase):
    def test_build_is_sealed_immutable_and_promoted_by_atomic_pointer(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            factory = _RecordingFactory()
            manifest = repository.build(
                build_id="build-001",
                chunks=(_chunk("uksc-1", "A reviewed constitutional authority."),),
                embedding_model="test-hash-1024",
                reranker_model="test-reranker",
                source_manifest_sha256="a" * 64,
                session_factory=factory,
            )
            self.assertTrue(manifest.sealed)
            self.assertEqual(manifest.chunk_count, 1)
            self.assertEqual(manifest.vector_dimensions, 1024)
            self.assertTrue(factory.sessions[0].indexes_created)
            self.assertTrue(factory.sessions[0].closed)
            self.assertTrue((repository.builds / "build-001" / "manifest.json").exists())
            self.assertFalse((repository.builds / ".build-001.incomplete").exists())

            active = repository.promote("build-001")
            self.assertEqual(repository.read_active(), active)
            self.assertEqual(active.build_id, "build-001")
            with self.assertRaises(FileExistsError):
                repository.build(
                    build_id="build-001",
                    chunks=(),
                    embedding_model="test-hash-1024",
                    reranker_model="test-reranker",
                    source_manifest_sha256="a" * 64,
                    session_factory=factory,
                )

    def test_compare_and_swap_guard_prevents_stale_promotion(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            factory = _RecordingFactory()
            for build_id in ("one", "two"):
                repository.build(
                    build_id=build_id,
                    chunks=(_chunk(build_id, f"Authority {build_id}"),),
                    embedding_model="test-hash-1024",
                    reranker_model="test-reranker",
                    source_manifest_sha256="b" * 64,
                    session_factory=factory,
                )
            repository.promote("one")
            with self.assertRaises(RuntimeError):
                repository.promote("two", expected_previous="stale")
            self.assertEqual(repository.read_active().build_id, "one")  # type: ignore[union-attr]
            repository.promote("two", expected_previous="one")
            self.assertEqual(repository.read_active().build_id, "two")  # type: ignore[union-attr]

    def test_generic_promote_rejects_held_ge_scope_without_pointer_writes(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            repository.build(
                build_id="held-ge",
                chunks=(_chunk("held-ge", "Held GE material"),),
                embedding_model="test-hash-1024",
                reranker_model="test-reranker",
                source_manifest_sha256="e" * 64,
                session_factory=_RecordingFactory(),
            )
            (repository.builds / "held-ge" / "approved-source-manifest.json").write_text(
                json.dumps(
                    {
                        "selection_policy": "exact-owner-approved-ge-source-versions-and-lanes",
                        "successor_must_remain_non_active": True,
                        "active_or_previous_write_authorized": False,
                        "promotion_authorized": False,
                        "ge_source_scope_content_sha256": "f" * 64,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertFalse(repository.active_pointer.exists())
            self.assertFalse(repository.previous_pointer.exists())
            with self.assertRaisesRegex(PermissionError, "GE held/scope"):
                repository.promote("held-ge")
            self.assertFalse(repository.active_pointer.exists())
            self.assertFalse(repository.previous_pointer.exists())

    def test_generic_rollback_rejects_active_held_ge_and_preserves_pointers(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            factory = _RecordingFactory()
            for build_id in ("ordinary-one", "held-ge-two"):
                repository.build(
                    build_id=build_id,
                    chunks=(_chunk(build_id, f"Authority {build_id}"),),
                    embedding_model="test-hash-1024",
                    reranker_model="test-reranker",
                    source_manifest_sha256="a" * 64,
                    session_factory=factory,
                )
            repository.promote("ordinary-one")
            repository.promote("held-ge-two", expected_previous="ordinary-one")
            (repository.builds / "held-ge-two" / "build-boundary.json").write_text(
                json.dumps(
                    {
                        "schema": "legalbot.index-build-boundary.v1",
                        "build_id": "held-ge-two",
                        "selection_policy": "exact-owner-approved-ge-source-versions-and-lanes",
                        "successor_must_remain_non_active": True,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            active_before = repository.active_pointer.read_bytes()
            previous_before = repository.previous_pointer.read_bytes()
            with self.assertRaisesRegex(PermissionError, "GE held/scope"):
                repository.rollback_build()
            self.assertEqual(repository.active_pointer.read_bytes(), active_before)
            self.assertEqual(repository.previous_pointer.read_bytes(), previous_before)

    def test_invalid_vector_fails_before_sealing_generation(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            factory = _RecordingFactory()
            valid = _chunk("bad", "Bad dimensions")
            invalid = IndexedChunk(
                chunk_id=valid.chunk_id,
                text=valid.text,
                vector=(0.0,),
                jurisdiction=valid.jurisdiction,
                material_lane=valid.material_lane,
                subject=valid.subject,
                review_state=valid.review_state,
                source_identity=valid.source_identity,
                content_sha256=valid.content_sha256,
            )
            with self.assertRaises(ValueError):
                repository.build(
                    build_id="invalid",
                    chunks=(invalid,),
                    embedding_model="bad",
                    reranker_model="bad",
                    source_manifest_sha256="d" * 64,
                    session_factory=factory,
                )
            self.assertFalse((repository.builds / "invalid").exists())
            self.assertTrue((repository.builds / ".invalid.incomplete").exists())
            self.assertTrue(factory.sessions[0].closed)

    def test_prepare_new_staging_refuses_to_delete_incomplete(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            staging = repository.prepare_new_staging("keep-me")
            marker = staging / "hours-of-work.bin"
            marker.write_bytes(b"do-not-delete")
            with self.assertRaises(FileExistsError):
                repository.prepare_staging("keep-me")
            self.assertTrue(marker.is_file())
            archived = repository.archive_incomplete_staging("keep-me")
            self.assertTrue((archived / "hours-of-work.bin").is_file())
            self.assertFalse((repository.builds / ".keep-me.incomplete").exists())

    def test_generic_archive_rejects_held_ge_staging_and_preserves_all_bytes(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            staging = repository.prepare_new_staging("held-ge-staging")
            marker = staging / "hours-of-work.bin"
            marker.write_bytes(b"durable-ge-work")
            (staging / "build-boundary.json").write_text(
                json.dumps(
                    {
                        "schema": "legalbot.index-build-boundary.v1",
                        "build_id": "held-ge-staging",
                        "selection_policy": "exact-owner-approved-ge-source-versions-and-lanes",
                        "ge_held_scope": True,
                        "successor_must_remain_non_active": True,
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PermissionError, "GE held/scope"):
                repository.archive_incomplete_staging("held-ge-staging", stamp="blocked")
            self.assertEqual(marker.read_bytes(), b"durable-ge-work")
            self.assertFalse((repository.builds / "archive").exists())

    def test_resumed_index_creation_never_replaces_existing_derived_indexes(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            lance = Path(directory) / "lance"
            (lance / "authority").mkdir(parents=True)
            table = _CreateOnlyIndexTable()
            module = _CreateOnlyIndexModule(table)

            repository.create_lexical_indexes(lance, module)
            repository.create_lexical_indexes(lance, module)
            repository.create_vector_indexes(lance, module)
            repository.create_vector_indexes(lance, module)

            self.assertEqual(table.fts_calls, [{"column": "text", "replace": False}])
            self.assertEqual(len(table.vector_calls), 1)
            self.assertFalse(table.vector_calls[0]["replace"])
            self.assertEqual(
                sorted(index.index_type for index in table.indices),
                ["FTS", "IVF_FLAT"],
            )

            incompatible = _CreateOnlyIndexTable()
            incompatible.indices.append(
                SimpleNamespace(
                    columns=["vector"],
                    index_type="HNSW",
                    name="vector_idx",
                )
            )
            with self.assertRaisesRegex(RuntimeError, "frozen IVF_FLAT"):
                repository.create_vector_indexes(
                    lance,
                    _CreateOnlyIndexModule(incompatible),
                )
            self.assertEqual(incompatible.vector_calls, [])


if __name__ == "__main__":
    unittest.main()
