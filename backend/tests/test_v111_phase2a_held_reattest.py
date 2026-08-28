from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.retrieval import phase2a_held_reattest as held


def _report(*, recall_at_5: float = 1.0) -> dict[str, Any]:
    rows = [
        {
            "id": f"query-{number:02d}",
            "gold_span_count": 1,
            "exact_span_recall_at_5": 1.0,
            "wrong_version": False,
            "forbidden_lane": False,
            "private_path_hits": 0,
        }
        for number in range(1, 25)
    ]
    return {
        "schema": "legalbot.offline-retrieval.v1.1",
        "build_id": held.BUILD_ID,
        "answer_model_invoked": False,
        "active_json_written": False,
        "go": True,
        "candidate_gold_binding": {
            "status": "bound",
            "row_count": 24,
            "issues": [],
            "bindings": [{"case_id": row["id"], "status": "bound"} for row in rows],
        },
        "per_query": rows,
        "aggregates": {
            "positive_recall_at_5": recall_at_5,
            "positive_recall_at_10": 0.95,
            "mrr": 0.80,
            "teaching_assessment_hits": 0,
            "private_path_hits": 0,
            "wrong_version_count": 0,
        },
        "split_aggregates": {
            "development": {"go": True},
            "promotion": {"go": True},
        },
    }


def _manifest() -> dict[str, Any]:
    return {
        "schema": "legalbot.approved-source-manifest.v1",
        "corpus_id": held.CORPUS_ID,
        "manifest_sha256": held.EXPECTED_SOURCE_MANIFEST_SHA256,
        "source_count": held.EXPECTED_SOURCE_COUNT,
        "chunk_count": held.EXPECTED_CHUNK_COUNT,
        "selection_policy": "exact-owner-approved-held-phase2a-successor-scope",
        "frozen_scope_content_sha256": held.EXPECTED_SCOPE_CONTENT_SHA256,
        "source_scan_id": held.EXPECTED_SCAN_ID,
        "source_scan_manifest_sha256": held.EXPECTED_SCAN_MANIFEST_SHA256,
        "answer_release_eligible": False,
        "successor_must_remain_non_active": True,
        "active_or_previous_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def test_report_contract_requires_every_quality_gate() -> None:
    metrics = held.validate_held_retrieval_report(_report())
    assert metrics["query_count"] == 24
    assert metrics["positive_recall_at_5"] == 1.0
    assert metrics["positive_recall_at_10"] == 0.95
    assert metrics["mrr"] == 0.80
    assert metrics["mean_exact_span_recall_at_5_advisory"] == 1.0

    with pytest.raises(RuntimeError, match="recall_at_5_equals_1"):
        held.validate_held_retrieval_report(_report(recall_at_5=0.99))


def test_held_manifest_rejects_any_release_authority() -> None:
    held._validate_held_source_manifest(_manifest())
    changed = _manifest()
    changed["answer_release_eligible"] = True
    with pytest.raises(RuntimeError, match="boundary changed"):
        held._validate_held_source_manifest(changed)


def test_held_reattest_writes_evidence_without_catalogue_or_pointer_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = Settings(project_root=tmp_path)
    settings.ensure_runtime_dirs()
    build_path = settings.index_dir / "builds" / held.BUILD_ID
    build_path.mkdir(parents=True)
    (build_path / "seal.json").write_text("{}\n", encoding="utf-8")
    (build_path / "approved-source-manifest.json").write_text(
        json.dumps(_manifest(), sort_keys=True) + "\n", encoding="utf-8"
    )
    settings.index_dir.mkdir(parents=True, exist_ok=True)
    (settings.index_dir / "ACTIVE.json").write_text(
        '{"build_id":"predecessor"}\n', encoding="utf-8"
    )

    row = {
        "id": held.BUILD_ID,
        "corpus_id": held.CORPUS_ID,
        "status": "built_unscored",
        "stage": "built_unscored",
        "path": str(build_path.relative_to(tmp_path)),
        "document_count": held.EXPECTED_SOURCE_COUNT,
        "chunk_count": held.EXPECTED_CHUNK_COUNT,
        "vector_count": held.EXPECTED_CHUNK_COUNT,
        "embedding_model": "embed",
        "reranker_model": "rerank",
        "manifest_sha256": "a" * 64,
        "candidate_manifest_hash": "a" * 64,
        "benchmark_result_json": "{}",
        "failure_reason_code": None,
        "promoted_at": None,
    }

    class ReadOnlyCatalogue:
        calls = 0

        def fetchone(self, query: str, parameters: tuple[Any, ...]) -> dict[str, Any]:
            del query, parameters
            self.calls += 1
            return dict(row)

    database = ReadOnlyCatalogue()
    monkeypatch.setattr(
        held,
        "_verify_durable_candidate_tree",
        lambda _settings, _row: held.EXPECTED_SOURCE_MANIFEST_SHA256,
    )
    destination = settings.evaluation_dir / "held.json"
    result = held.reattest_phase2a_held_successor(
        settings,
        database,  # type: ignore[arg-type]
        benchmark_runner=lambda *_args, **_kwargs: _report(),
        destination=destination,
    )
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert database.calls == 2
    assert result["status"] == "built_unscored"
    assert result["promotion_eligible"] is False
    assert payload["catalogue_attestation_history_written"] is False
    assert payload["candidate_status_written"] is False
    assert payload["active_pointer_written"] is False
    assert json.loads((settings.index_dir / "ACTIVE.json").read_text())["build_id"] == (
        "predecessor"
    )
