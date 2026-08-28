from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from backend.app.ingestion import Jurisdiction, MaterialLane
from backend.app.retrieval import DeterministicHashEmbedding, ImmutableLanceRepository, IndexedChunk


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
        self.path.mkdir(parents=True, exist_ok=True)
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
    def create(self, generation_path: Path) -> _RecordingSession:
        return _RecordingSession(generation_path)


class PreviousPointerTests(TestCase):
    def test_promote_writes_previous_and_rollback_restores(self) -> None:
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
            self.assertFalse(repository.previous_pointer.exists())
            repository.promote("two", expected_previous="one")
            self.assertEqual(repository.read_active().build_id, "two")
            self.assertEqual(repository.read_previous().build_id, "one")
            restored = repository.rollback_build()
            self.assertEqual(restored.build_id, "one")
            self.assertEqual(repository.read_active().build_id, "one")
            self.assertEqual(repository.read_previous().build_id, "two")
            self.assertTrue(repository.active_pointer.exists())
            self.assertTrue(repository.previous_pointer.exists())

    def test_rollback_without_previous_is_refused(self) -> None:
        with TemporaryDirectory() as directory:
            repository = ImmutableLanceRepository(Path(directory) / "indexes")
            with self.assertRaises(FileNotFoundError):
                repository.rollback_build()
