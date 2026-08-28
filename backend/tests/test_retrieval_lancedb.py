from __future__ import annotations

import unittest
from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory

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


if __name__ == "__main__":
    unittest.main()
