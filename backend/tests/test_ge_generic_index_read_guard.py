from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.db import Database
from app.research.retrieval_attempt import (
    RetrievalAttemptBinding,
    execute_candidate_retrieval_attempt,
)
from app.retrieval.ge_generic_read_guard import require_generic_index_read_allowed
from app.retrieval.offline_benchmark import run_retrieval_smoke
from app.retrieval.retrieval_v1 import run_retrieval_v1
from app.retrieval.source_manifest import approved_source_manifest_sha256
from app.retrieval.vector_carry_forward import verify_parent_vector_source


def _write_json(path: Path, value: dict[str, Any]) -> bytes:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return raw


def _sealed_build(
    project: Path,
    *,
    build_id: str,
    ge_marker: str | None,
) -> Path:
    build = project / "data/indexes/builds" / build_id
    (build / "lance/authority").mkdir(parents=True)
    source: dict[str, Any] = {
        "schema": "legalbot.approved-source-manifest.v1",
        "selection_policy": (
            "exact-owner-approved-ge-source-versions-and-lanes"
            if ge_marker == "source"
            else "synthetic-ordinary-candidate"
        ),
        "sources": [],
    }
    if ge_marker == "source":
        source.update(
            {
                "ge_source_scope_content_sha256": "1" * 64,
                "successor_must_remain_non_active": True,
            }
        )
    source["manifest_sha256"] = approved_source_manifest_sha256(source)
    source_raw = _write_json(build / "approved-source-manifest.json", source)
    manifest = {
        "schema": "legalbot.index-manifest.v2",
        "build_id": build_id,
        "source_manifest_sha256": source["manifest_sha256"],
        "chunk_count": 1,
        "sealed": True,
    }
    manifest_raw = _write_json(build / "manifest.json", manifest)
    seal: dict[str, Any] = {
        "schema": "legalbot.index-seal.v2",
        "build_id": build_id,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "source_manifest_file_sha256": hashlib.sha256(source_raw).hexdigest(),
    }
    if ge_marker == "evaluation":
        evaluation_raw = _write_json(
            build / "evaluation.json",
            {
                "schema": "legalbot.index-evaluation.v2",
                "integrity": {
                    "ge_source_scope_content_sha256": "2" * 64,
                    "successor_must_remain_non_active": True,
                },
            },
        )
        seal["evaluation_sha256"] = hashlib.sha256(evaluation_raw).hexdigest()
    _write_json(build / "seal.json", seal)
    if ge_marker == "boundary":
        _write_json(
            build / "build-boundary.json",
            {
                "schema": "legalbot.index-build-boundary.v1",
                "build_id": build_id,
                "source_manifest_sha256": source["manifest_sha256"],
                "selection_policy": "exact-owner-approved-ge-source-versions-and-lanes",
                "ge_held_scope": True,
                "ge_source_scope_content_sha256": "3" * 64,
                "successor_must_remain_non_active": True,
                "active_or_previous_write_authorized": False,
                "promotion_authorized": False,
            },
        )
    return build


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_guard_preserves_ordinary_candidate_and_rejects_every_ge_marker(
    tmp_path: Path,
) -> None:
    ordinary = _sealed_build(tmp_path, build_id="ordinary-candidate", ge_marker=None)
    require_generic_index_read_allowed(
        ordinary,
        expected_build_id="ordinary-candidate",
    )

    for marker in ("source", "boundary", "evaluation"):
        build_id = f"held-ge-{marker}"
        held = _sealed_build(tmp_path, build_id=build_id, ge_marker=marker)
        before = _snapshot(held)
        with pytest.raises(PermissionError, match="held GE index"):
            require_generic_index_read_allowed(held, expected_build_id=build_id)
        assert _snapshot(held) == before


def test_public_generic_evaluation_and_smoke_paths_reject_ge_before_lance_open(
    tmp_path: Path,
    database: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_id = "held-ge-public-read"
    _sealed_build(tmp_path, build_id=build_id, ge_marker="source")
    settings = Settings(project_root=tmp_path, test_mode=True)
    lance_opened = False

    def forbidden_lance_import() -> object:
        nonlocal lance_opened
        lance_opened = True
        raise AssertionError("Lance must not open for a held GE build")

    import app.retrieval.offline_benchmark as smoke_module
    import app.retrieval.retrieval_v1 as retrieval_v1_module

    monkeypatch.setattr(smoke_module, "_import_lancedb", forbidden_lance_import)
    monkeypatch.setattr(retrieval_v1_module, "_import_lancedb", forbidden_lance_import)
    destination = tmp_path / "smoke.json"
    with pytest.raises(PermissionError, match="held GE index"):
        run_retrieval_smoke(
            settings,
            database,
            build_id=build_id,
            destination=destination,
        )
    with pytest.raises(PermissionError, match="held GE index"):
        run_retrieval_v1(settings, build_id=build_id, splits=("development",))
    assert lance_opened is False
    assert not destination.exists()


def test_research_and_vector_reuse_reject_ge_before_executor_or_lance(
    tmp_path: Path,
) -> None:
    build_id = "held-ge-research-read"
    build = _sealed_build(tmp_path, build_id=build_id, ge_marker="source")
    settings = Settings(project_root=tmp_path, test_mode=True)

    class ForbiddenExecutor:
        called = False

        def __call__(self, _request: object) -> object:
            self.called = True
            raise AssertionError("research executor must not run for held GE")

    executor = ForbiddenExecutor()
    query_sha256 = hashlib.sha256(b"contract").hexdigest()
    with pytest.raises(PermissionError, match="held GE index"):
        execute_candidate_retrieval_attempt(
            settings=settings,
            binding=RetrievalAttemptBinding(
                candidate_build_id=build_id,
                candidate_seal_sha256=hashlib.sha256(
                    (build / "seal.json").read_bytes()
                ).hexdigest(),
                source_manifest_sha256=json.loads(
                    (build / "approved-source-manifest.json").read_text(encoding="utf-8")
                )["manifest_sha256"],
                case_ref=f"case:{'4' * 64}",
                issue_ref=f"issue:{'5' * 64}",
                subject="contract",
                jurisdiction="England and Wales",
                as_of_date=date(2026, 9, 1),
                proposition_sha256="6" * 64,
                query_sha256=query_sha256,
            ),
            canonical_query="contract",
            executor=executor,  # type: ignore[arg-type]
        )
    assert executor.called is False

    with pytest.raises(PermissionError, match="held GE index"):
        verify_parent_vector_source(
            index_root=settings.index_dir,
            parent_build_id=build_id,
            child_build_id="ordinary-child-build",
            embedding_model_revision="model@revision",
            vector_dimensions=1024,
            vector_dtype="float16",
            parser_identity="parser-v1",
            chunker_identity="chunker-v1",
            index_schema_version="index-v1",
        )
