"""Non-authorizing retrieval re-attestation for the frozen Phase-2A successor.

This module is deliberately separate from the normal candidate attestation path.
It may evaluate only the one owner-approved held successor, writes no catalogue
attestation selection, and cannot transition the build to ``candidate`` or ACTIVE.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database
from .phase2a_frozen_scope import (
    CORPUS_ID,
    EXPECTED_CHUNK_COUNT,
    EXPECTED_SCAN_ID,
    EXPECTED_SCAN_MANIFEST_SHA256,
    EXPECTED_SCOPE_CONTENT_SHA256,
    EXPECTED_SOURCE_COUNT,
)
from .retrieval_v1 import run_retrieval_v1
from .service import (
    _file_sha256,
    _json_object,
    _verify_durable_candidate_tree,
    _write_new_json,
)

BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
EXPECTED_SOURCE_MANIFEST_SHA256 = "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
SCHEMA = "legalbot.v111.phase2a.held-retrieval-reattestation.v1"
MIN_RECALL_AT_10 = 0.95
MIN_MRR = 0.80
EXPECTED_QUERY_COUNT = 24


def _pointer_snapshot(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise RuntimeError("index pointer must not be a symbolic link")
    if not path.exists():
        return {"exists": False, "sha256": None, "size": None}
    if not path.is_file():
        raise RuntimeError("index pointer is not a regular file")
    return {
        "exists": True,
        "sha256": _file_sha256(path),
        "size": path.stat().st_size,
    }


def _catalogue_snapshot(row: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "id",
        "corpus_id",
        "status",
        "stage",
        "path",
        "document_count",
        "chunk_count",
        "vector_count",
        "embedding_model",
        "reranker_model",
        "manifest_sha256",
        "candidate_manifest_hash",
        "benchmark_result_json",
        "failure_reason_code",
        "promoted_at",
    )
    return {field: row.get(field) for field in fields}


def _validate_held_source_manifest(manifest: Mapping[str, Any]) -> None:
    if (
        manifest.get("schema") != "legalbot.approved-source-manifest.v1"
        or manifest.get("corpus_id") != CORPUS_ID
        or manifest.get("manifest_sha256") != EXPECTED_SOURCE_MANIFEST_SHA256
        or manifest.get("source_count") != EXPECTED_SOURCE_COUNT
        or manifest.get("chunk_count") != EXPECTED_CHUNK_COUNT
        or manifest.get("selection_policy") != "exact-owner-approved-held-phase2a-successor-scope"
        or manifest.get("frozen_scope_content_sha256") != EXPECTED_SCOPE_CONTENT_SHA256
        or manifest.get("source_scan_id") != EXPECTED_SCAN_ID
        or manifest.get("source_scan_manifest_sha256") != EXPECTED_SCAN_MANIFEST_SHA256
        or manifest.get("answer_release_eligible") is not False
        or manifest.get("successor_must_remain_non_active") is not True
        or manifest.get("active_or_previous_write_authorized") is not False
        or manifest.get("phase2b_authorized") is not False
        or manifest.get("development30_authorized") is not False
    ):
        raise RuntimeError("Phase-2A held successor source manifest boundary changed")


def _finite_metric(value: Any, *, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"held retrieval report metric is invalid: {name}") from exc
    if not math.isfinite(number):
        raise RuntimeError(f"held retrieval report metric is non-finite: {name}")
    return number


def validate_held_retrieval_report(
    report: Mapping[str, Any], *, build_id: str = BUILD_ID
) -> dict[str, Any]:
    """Validate the exact 24-query quality contract without granting release status."""

    rows = report.get("per_query")
    binding = report.get("candidate_gold_binding")
    aggregates = report.get("aggregates")
    split_aggregates = report.get("split_aggregates")
    if (
        report.get("schema") != "legalbot.offline-retrieval.v1.1"
        or report.get("build_id") != build_id
        or report.get("answer_model_invoked") is not False
        or report.get("active_json_written") is not False
        or report.get("go") is not True
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_QUERY_COUNT
        or len({str(row.get("id") or "") for row in rows if isinstance(row, Mapping)})
        != EXPECTED_QUERY_COUNT
        or not isinstance(binding, Mapping)
        or binding.get("status") != "bound"
        or binding.get("row_count") != EXPECTED_QUERY_COUNT
        or binding.get("issues") not in ([], ())
        or not isinstance(aggregates, Mapping)
        or not isinstance(split_aggregates, Mapping)
        or set(split_aggregates) != {"development", "promotion"}
        or any(
            not isinstance(value, Mapping) or value.get("go") is not True
            for value in split_aggregates.values()
        )
    ):
        raise RuntimeError("held retrieval report identity or binding gate failed")

    bindings = binding.get("bindings")
    if (
        not isinstance(bindings, list)
        or len(bindings) != EXPECTED_QUERY_COUNT
        or any(not isinstance(item, Mapping) or item.get("status") != "bound" for item in bindings)
    ):
        raise RuntimeError("held retrieval report is not bound 24/24")

    recall_at_5 = _finite_metric(
        aggregates.get("positive_recall_at_5"), name="positive_recall_at_5"
    )
    recall_at_10 = _finite_metric(
        aggregates.get("positive_recall_at_10"), name="positive_recall_at_10"
    )
    mrr = _finite_metric(aggregates.get("mrr"), name="mrr")
    span_rows = [
        row for row in rows if isinstance(row, Mapping) and int(row.get("gold_span_count") or 0) > 0
    ]
    mean_exact_span_recall_at_5 = (
        sum(
            _finite_metric(row.get("exact_span_recall_at_5"), name="exact_span_recall_at_5")
            for row in span_rows
        )
        / len(span_rows)
        if span_rows
        else None
    )
    contamination_clear = (
        int(aggregates.get("teaching_assessment_hits") or 0) == 0
        and int(aggregates.get("private_path_hits") or 0) == 0
        and int(aggregates.get("wrong_version_count") or 0) == 0
        and all(
            isinstance(row, Mapping)
            and row.get("wrong_version") is False
            and row.get("forbidden_lane") is False
            and int(row.get("private_path_hits") or 0) == 0
            for row in rows
        )
    )
    gates = {
        "binding_24_of_24": True,
        "recall_at_5_equals_1": recall_at_5 == 1.0,
        "recall_at_10_at_least_0_95": recall_at_10 >= MIN_RECALL_AT_10,
        "mrr_at_least_0_80": mrr >= MIN_MRR,
        "zero_teaching_private_path_wrong_version_contamination": contamination_clear,
        "every_split_passed": True,
    }
    if not all(gates.values()):
        failed = sorted(name for name, passed in gates.items() if not passed)
        raise RuntimeError("held retrieval quality gates failed: " + ",".join(failed))
    return {
        "query_count": EXPECTED_QUERY_COUNT,
        "binding_count": EXPECTED_QUERY_COUNT,
        "positive_recall_at_5": recall_at_5,
        "positive_recall_at_10": recall_at_10,
        "mrr": mrr,
        "exact_span_case_count": len(span_rows),
        # The frozen 24-query contract gates source/version/locator retrieval.
        # Exact-span recall is preserved as a diagnostic rather than silently
        # adding a new gate to that already owner-frozen benchmark.
        "mean_exact_span_recall_at_5_advisory": mean_exact_span_recall_at_5,
        "teaching_assessment_hits": 0,
        "private_path_hits": 0,
        "wrong_version_count": 0,
        "gates": gates,
    }


def reattest_phase2a_held_successor(
    settings: Settings,
    database: Database,
    *,
    build_id: str = BUILD_ID,
    benchmark_runner: Callable[..., dict[str, Any]] = run_retrieval_v1,
    destination: Path | None = None,
) -> dict[str, Any]:
    """Evaluate the one held successor and emit create-only, non-authorizing evidence."""

    if build_id != BUILD_ID:
        raise ValueError("held re-attestation is pinned to the exact Phase-2A successor")
    row_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if row_value is None:
        raise ValueError("exact Phase-2A held successor does not exist")
    row = dict(row_value)
    before = _catalogue_snapshot(row)
    if (
        before["corpus_id"] != CORPUS_ID
        or before["status"] != "built_unscored"
        or before["stage"] != "built_unscored"
        or int(before["document_count"] or 0) != EXPECTED_SOURCE_COUNT
        or int(before["chunk_count"] or 0) != EXPECTED_CHUNK_COUNT
        or int(before["vector_count"] or 0) != EXPECTED_CHUNK_COUNT
        or before["failure_reason_code"] not in (None, "")
    ):
        raise RuntimeError("exact Phase-2A successor is not a sealed held build")

    build_path = settings.index_dir / "builds" / build_id
    durable_source_manifest_sha256 = _verify_durable_candidate_tree(settings, row)
    source_manifest_path = build_path / "approved-source-manifest.json"
    source_manifest = _json_object(source_manifest_path.read_text(encoding="utf-8"))
    _validate_held_source_manifest(source_manifest)
    if durable_source_manifest_sha256 != EXPECTED_SOURCE_MANIFEST_SHA256:
        raise RuntimeError("sealed Phase-2A source-manifest identity changed")

    pointer_before = {
        "ACTIVE.json": _pointer_snapshot(settings.index_dir / "ACTIVE.json"),
        "PREVIOUS.json": _pointer_snapshot(settings.index_dir / "PREVIOUS.json"),
    }
    report = benchmark_runner(
        settings,
        build_id=build_id,
        splits=("development", "promotion"),
    )
    metrics = validate_held_retrieval_report(report, build_id=build_id)

    after_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if after_value is None or _catalogue_snapshot(dict(after_value)) != before:
        raise RuntimeError("held retrieval evaluation changed the index catalogue")
    pointer_after = {
        "ACTIVE.json": _pointer_snapshot(settings.index_dir / "ACTIVE.json"),
        "PREVIOUS.json": _pointer_snapshot(settings.index_dir / "PREVIOUS.json"),
    }
    if pointer_after != pointer_before:
        raise RuntimeError("held retrieval evaluation changed ACTIVE/PREVIOUS state")

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "build_id": build_id,
        "corpus_id": CORPUS_ID,
        "build_status_before_and_after": "built_unscored",
        "build_stage_before_and_after": "built_unscored",
        "build_seal_sha256": _file_sha256(build_path / "seal.json"),
        "source_manifest_file_sha256": _file_sha256(source_manifest_path),
        "source_manifest_sha256": EXPECTED_SOURCE_MANIFEST_SHA256,
        "frozen_scope_content_sha256": EXPECTED_SCOPE_CONTENT_SHA256,
        "source_scan_id": EXPECTED_SCAN_ID,
        "source_scan_manifest_sha256": EXPECTED_SCAN_MANIFEST_SHA256,
        "catalogue_snapshot_sha256": hashlib.sha256(
            json.dumps(before, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "pointer_snapshot": pointer_before,
        "retrieval_quality_passed": True,
        "metrics": metrics,
        "report": report,
        "answer_model_invoked": False,
        "catalogue_attestation_history_written": False,
        "catalogue_attestation_selection_written": False,
        "candidate_status_written": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
        "promotion_eligible": False,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    output = destination or (
        settings.evaluation_dir / "retrieval" / build_id / "phase2a-held-v1.1-reattestation.json"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    _write_new_json(output, payload)
    return {
        "schema": SCHEMA,
        "build_id": build_id,
        "status": "built_unscored",
        "retrieval_quality_passed": True,
        "promotion_eligible": False,
        "answer_release_eligible": False,
        "attestation_path": str(output.relative_to(settings.project_root)),
        "attestation_sha256": _file_sha256(output),
        "metrics": metrics,
    }
