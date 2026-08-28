from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from app.retrieval.index_build import IndexBuildContext, _iter_scoped_chunks
from app.retrieval.vector_carry_forward import (
    ChunkIdentity,
    ParentVector,
    ParentVectorBatchReader,
    VectorBuildIdentity,
    VectorCarryForwardError,
    build_vector_reuse_report,
    plan_vector_carry_forward,
    verify_parent_vector_source,
)


def _seal_bytes(**updates: Any) -> bytes:
    payload = {
        "schema": "legalbot.index-seal.v2",
        "build_id": "candidate-parent",
        "manifest_sha256": "1" * 64,
        "lance_tree_sha256": "2" * 64,
    }
    payload.update(updates)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _identities(
    seal_bytes: bytes,
) -> tuple[VectorBuildIdentity, VectorBuildIdentity]:
    common = {
        "embedding_model_revision": "Qwen3-Embedding-0.6B@revision-1",
        "vector_dimensions": 3,
        "vector_dtype": "float32",
        "parser_identity": "legalbot-parser-v1",
        "chunker_identity": "legalbot-chunker-v1",
        "index_schema_version": "legalbot-index-v1",
    }
    parent = VectorBuildIdentity(
        build_id="candidate-parent",
        seal_sha256=hashlib.sha256(seal_bytes).hexdigest(),
        **common,
    )
    child = VectorBuildIdentity(
        build_id="candidate-child",
        seal_sha256="f" * 64,
        **common,
    )
    return parent, child


def test_plan_reuses_only_exact_chunk_hashes_and_classifies_new_candidate() -> None:
    seal = _seal_bytes()
    parent, child = _identities(seal)
    unchanged = ParentVector("chunk-a", "a" * 64, (0.1, 0.2, 0.3))
    changed = ParentVector("chunk-b", "b" * 64, (0.4, 0.5, 0.6))
    removed = ParentVector("chunk-c", "c" * 64, (0.7, 0.8, 0.9))

    plan = plan_vector_carry_forward(
        parent_identity=parent,
        child_identity=child,
        parent_seal_bytes=seal,
        parent_vectors=(removed, unchanged, changed),
        child_chunks=(
            ChunkIdentity("chunk-d", "d" * 64),
            ChunkIdentity("chunk-b", "e" * 64),
            ChunkIdentity("chunk-a", "a" * 64),
        ),
    )

    assert plan.parent_build_id == "candidate-parent"
    assert plan.child_build_id == "candidate-child"
    assert plan.reusable_vectors == (unchanged,)
    assert plan.reusable_vectors[0] is unchanged
    assert plan.unchanged_chunk_ids == ("chunk-a",)
    assert plan.changed_chunks == (ChunkIdentity("chunk-b", "e" * 64),)
    assert plan.new_chunks == (ChunkIdentity("chunk-d", "d" * 64),)
    assert plan.chunks_requiring_embedding == plan.changed_chunks + plan.new_chunks
    assert plan.removed_chunk_ids == ("chunk-c",)
    assert plan.lexical_rebuild_required
    assert plan.child_requires_new_seal
    assert len(plan.plan_sha256) == 64


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("embedding_model_revision", "different-model@revision-2"),
        ("vector_dimensions", 4),
        ("vector_dtype", "float64"),
        ("parser_identity", "different-parser"),
        ("chunker_identity", "different-chunker"),
        ("index_schema_version", "different-index-schema"),
    ],
)
def test_plan_rejects_every_global_identity_mismatch(field: str, value: object) -> None:
    seal = _seal_bytes()
    parent, child = _identities(seal)

    with pytest.raises(VectorCarryForwardError, match=field):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=dataclasses.replace(child, **{field: value}),
            parent_seal_bytes=seal,
            parent_vectors=(),
            child_chunks=(),
        )


def test_plan_rejects_same_candidate_or_bad_parent_vector() -> None:
    seal = _seal_bytes()
    parent, child = _identities(seal)
    with pytest.raises(VectorCarryForwardError, match="new candidate"):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=dataclasses.replace(child, build_id=parent.build_id),
            parent_seal_bytes=seal,
            parent_vectors=(),
            child_chunks=(),
        )

    with pytest.raises(VectorCarryForwardError, match="dimensions"):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=child,
            parent_seal_bytes=seal,
            parent_vectors=(ParentVector("chunk-a", "a" * 64, (0.1, 0.2)),),
            child_chunks=(),
        )


def test_plan_rejects_duplicate_parent_and_child_chunk_ids() -> None:
    seal = _seal_bytes()
    parent, child = _identities(seal)
    record = ParentVector("chunk-a", "a" * 64, (0.1, 0.2, 0.3))
    with pytest.raises(VectorCarryForwardError, match="duplicate parent"):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=child,
            parent_seal_bytes=seal,
            parent_vectors=(record, record),
            child_chunks=(),
        )
    chunk = ChunkIdentity("chunk-a", "a" * 64)
    with pytest.raises(VectorCarryForwardError, match="duplicate child"):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=child,
            parent_seal_bytes=seal,
            parent_vectors=(),
            child_chunks=(chunk, chunk),
        )


def test_parent_seal_bytes_schema_build_and_inner_digests_are_exact() -> None:
    seal = _seal_bytes()
    parent, child = _identities(seal)
    with pytest.raises(VectorCarryForwardError, match="byte digest"):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=child,
            parent_seal_bytes=seal + b"\n",
            parent_vectors=(),
            child_chunks=(),
        )

    for bad_seal, error in (
        (_seal_bytes(schema="legalbot.index-seal.v1"), "schema"),
        (_seal_bytes(build_id="candidate-other"), "build identity"),
        (_seal_bytes(manifest_sha256="not-a-digest"), "manifest_sha256"),
        (_seal_bytes(lance_tree_sha256="not-a-digest"), "lance_tree_sha256"),
    ):
        bad_parent, _ = _identities(bad_seal)
        with pytest.raises(VectorCarryForwardError, match=error):
            plan_vector_carry_forward(
                parent_identity=bad_parent,
                child_identity=child,
                parent_seal_bytes=bad_seal,
                parent_vectors=(),
                child_chunks=(),
            )


def test_parent_seal_rejects_duplicate_json_keys() -> None:
    seal = (
        b'{"schema":"legalbot.index-seal.v2",'
        b'"build_id":"candidate-parent","build_id":"candidate-parent",'
        + f'"manifest_sha256":"{"1" * 64}",'.encode()
        + f'"lance_tree_sha256":"{"2" * 64}"}}'.encode()
    )
    parent, child = _identities(seal)
    with pytest.raises(VectorCarryForwardError, match="unique-key"):
        plan_vector_carry_forward(
            parent_identity=parent,
            child_identity=child,
            parent_seal_bytes=seal,
            parent_vectors=(),
            child_chunks=(),
        )


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()), key=lambda item: item.as_posix()
    ):
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(path)))
    return digest.hexdigest()


def _sealed_parent(tmp_path: Path) -> tuple[Path, str]:
    index_root = tmp_path / "indexes"
    parent = index_root / "builds" / "candidate-parent"
    lane = parent / "lance" / "authority"
    lane.mkdir(parents=True)
    (lane / "generation.bin").write_bytes(b"immutable-vector-generation")
    lane_manifest = {
        "schema": "legalbot.physical-lanes.v1",
        "separated": True,
        "tables": {"authority": {"row_count": 2}},
    }
    (parent / "lance" / "physical-lanes.json").write_text(
        json.dumps(lane_manifest, sort_keys=True), encoding="utf-8"
    )
    manifest = {
        "schema": "legalbot.lance-build.v1",
        "build_id": "candidate-parent",
        "sealed": True,
        "chunk_count": 2,
        "vector_dimensions": 3,
        "embedding_model": "embed-model@revision;dtype=float32",
        "source_manifest_sha256": "a" * 64,
    }
    source = {
        "manifest_sha256": "a" * 64,
        "parser_version": "parser-v1",
        "chunker_version": "chunker-v1",
        "index_schema_version": "index-v1",
    }
    (parent / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    (parent / "approved-source-manifest.json").write_text(
        json.dumps(source, sort_keys=True), encoding="utf-8"
    )
    seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": "candidate-parent",
        "manifest_sha256": _file_sha256(parent / "manifest.json"),
        "source_manifest_file_sha256": _file_sha256(parent / "approved-source-manifest.json"),
        "physical_lane_manifest_sha256": _file_sha256(parent / "lance" / "physical-lanes.json"),
        "lance_tree_sha256": _tree_sha256(parent / "lance"),
    }
    (parent / "seal.json").write_text(json.dumps(seal, sort_keys=True), encoding="utf-8")
    return index_root, _file_sha256(parent / "seal.json")


def test_runtime_parent_verification_batch_lookup_and_report_are_fail_closed(
    tmp_path: Path,
) -> None:
    index_root, seal_sha256 = _sealed_parent(tmp_path)
    source = verify_parent_vector_source(
        index_root=index_root,
        parent_build_id="candidate-parent",
        child_build_id="candidate-child",
        embedding_model_revision="embed-model@revision;dtype=float32",
        vector_dimensions=3,
        vector_dtype="float32",
        parser_identity="parser-v1",
        chunker_identity="chunker-v1",
        index_schema_version="index-v1",
    )
    assert source.identity.seal_sha256 == seal_sha256

    rows = [
        {"chunk_id": "chunk-a", "content_sha256": "a" * 64, "vector": [0.1, 0.2, 0.3]},
        {"chunk_id": "chunk-b", "content_sha256": "b" * 64, "vector": [0.4, 0.5, 0.6]},
    ]

    class Query:
        def search(self):
            return self

        def where(self, _predicate: str, *, prefilter: bool):
            assert prefilter is True
            return self

        def limit(self, _value: int):
            return self

        def to_list(self):
            return rows

    class Connection:
        def open_table(self, name: str):
            assert name == "chunks"
            return Query()

    class Lance:
        @staticmethod
        def connect(_path: str):
            return Connection()

    reader = ParentVectorBatchReader(source, Lance())
    found = reader.lookup(
        (
            ChunkIdentity("chunk-a", "a" * 64),
            ChunkIdentity("chunk-b", "c" * 64),
        )
    )
    assert found == {"chunk-a": (0.1, 0.2, 0.3)}
    report = build_vector_reuse_report(
        parent=source,
        child_build_id="candidate-child",
        eligible_chunk_count=2,
        reused_vector_count=1,
        embedded_vector_count=1,
    )
    assert report.lexical_rebuild_required is True
    assert report.active_write_allowed is False
    assert len(report.seal_sha256) == 64


def test_embedding_stream_calls_embedder_only_for_changed_or_new_chunks(
    database, tmp_path: Path
) -> None:
    from test_index_build_jobs import _seed_authority

    from app.config import Settings

    project = tmp_path / "project"
    project.mkdir()
    _seed_authority(database, project, n_chunks=2)
    ctx = IndexBuildContext(
        settings=Settings(project_root=project, test_mode=True),
        database=database,
        job_id="index-child",
        build_id="candidate-child",
        corpus_id="test-corpus",
        manifest={"locator_allowlists": {}},
        source_ids=("sv-ucta",),
        embedding_model="test-embedding",
        reranker_model="test-reranker",
        build_dir=project / "data/indexes/builds/candidate-child",
        timings={},
        counts={},
    )

    class Embedder:
        def __init__(self) -> None:
            self.texts: list[str] = []

        def embed_documents(self, texts: list[str]):
            self.texts.extend(texts)
            return tuple((9.0, 9.0, 9.0) for _ in texts)

    embedder = Embedder()
    reused_vector = (1.0, 2.0, 3.0)

    def lookup(chunks: list[ChunkIdentity]) -> dict[str, tuple[float, ...]]:
        return {chunks[0].chunk_id: reused_vector}

    counts = {"reused": 0, "embedded": 0}
    output = list(
        _iter_scoped_chunks(
            ctx,
            embedder,
            lambda row, vector: (str(row["chunk_id"]), tuple(vector)),
            lambda row: str(row["markdown_text"]),
            parent_vector_lookup=lookup,
            reuse_counts=counts,
        )
    )

    assert len(output) == 2
    assert output[0][1] == reused_vector
    assert output[1][1] == (9.0, 9.0, 9.0)
    assert len(embedder.texts) == 1
    assert counts == {"reused": 1, "embedded": 1}
