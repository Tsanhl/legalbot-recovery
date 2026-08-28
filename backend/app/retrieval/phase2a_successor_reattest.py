"""Dynamic, non-authorizing retrieval re-attestation for the Phase-2A successor."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from ..config import Settings
from ..evaluation.live_suite import LiveEvaluationBundle, sealed_sha256
from ..evaluation.phase2a_successor_qualification import (
    CANDIDATE_BINDING_SCHEMA,
    FINAL_OWNER_PACKET_CONTENT_SHA256,
    FINAL_OWNER_RECEIPT_CONTENT_SHA256,
    RETRIEVAL_REATTESTATION_SCHEMA,
    canonical_json,
    sealed,
    source_version_id_set_sha256,
    validate_application_ledger,
    validate_catalogue_snapshot,
    validate_owner_packet,
    validate_owner_receipt,
)
from .retrieval_v1 import run_retrieval_v1
from .service import _verify_durable_candidate_tree
from .source_manifest import approved_source_manifest_sha256

EXPECTED_QUERY_COUNT = 24
MIN_RECALL_AT_10 = 0.95
MIN_MRR = 0.80


class ReadCatalogue(Protocol):
    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Mapping[str, Any] | None: ...


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} is unavailable or symbolic")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is unreadable") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object")
    return value


def _require_pointer_absence(index_dir: Path) -> None:
    for name in ("ACTIVE.json", "PREVIOUS.json"):
        path = index_dir / name
        if path.is_symlink() or path.exists():
            raise RuntimeError(f"Phase-2A successor requires {name} to be absent")


def _catalogue_row_snapshot(row: Mapping[str, Any]) -> dict[str, Any]:
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
        "embedding_model_version",
        "reranker_model",
        "rerank_version",
        "manifest_sha256",
        "candidate_manifest_hash",
        "source_manifest_hash",
        "failure_reason_code",
        "promotion_decision",
        "promoted_at",
    )
    return {field: row.get(field) for field in fields}


def _validate_scan_attestation(attestation: Mapping[str, Any]) -> None:
    if (
        attestation.get("schema") != "legalbot.source-scan-attestation.v1"
        or attestation.get("seal_sha256") != sealed_sha256(attestation)
        or attestation.get("status") != "complete"
        or int(attestation.get("expected_file_count") or 0) < 1
        or attestation.get("expected_file_count") != attestation.get("accounted_file_count")
        or attestation.get("source_root_count") != 3
        or not str(attestation.get("scan_id") or "")
        or not isinstance(attestation.get("manifest_sha256"), str)
        or len(str(attestation.get("manifest_sha256"))) != 64
        or attestation.get("writes_active") is not False
        or attestation.get("writes_o04") is not False
    ):
        raise ValueError("source scan attestation is incomplete or differs")


def _finite(value: Any, *, name: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"retrieval metric is invalid: {name}") from exc
    if not math.isfinite(number):
        raise RuntimeError(f"retrieval metric is non-finite: {name}")
    return number


def validate_successor_retrieval_report(
    report: Mapping[str, Any], *, build_id: str
) -> dict[str, Any]:
    """Validate the frozen 24-query retrieval contract for a dynamic build ID."""

    rows = report.get("per_query")
    binding = report.get("candidate_gold_binding")
    aggregates = report.get("aggregates")
    splits = report.get("split_aggregates")
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
        or not isinstance(splits, Mapping)
        or set(splits) != {"development", "promotion"}
        or any(
            not isinstance(value, Mapping) or value.get("go") is not True
            for value in splits.values()
        )
    ):
        raise RuntimeError("successor retrieval report identity or binding gate failed")
    bindings = binding.get("bindings")
    if (
        not isinstance(bindings, list)
        or len(bindings) != EXPECTED_QUERY_COUNT
        or any(not isinstance(item, Mapping) or item.get("status") != "bound" for item in bindings)
    ):
        raise RuntimeError("successor retrieval report is not bound 24/24")

    recall_at_5 = _finite(aggregates.get("positive_recall_at_5"), name="positive_recall_at_5")
    recall_at_10 = _finite(aggregates.get("positive_recall_at_10"), name="positive_recall_at_10")
    mrr = _finite(aggregates.get("mrr"), name="mrr")
    span_rows = [
        row for row in rows if isinstance(row, Mapping) and int(row.get("gold_span_count") or 0) > 0
    ]
    mean_span_recall = (
        sum(
            _finite(row.get("exact_span_recall_at_5"), name="exact_span_recall_at_5")
            for row in span_rows
        )
        / len(span_rows)
        if span_rows
        else 0.0
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
        raise RuntimeError("successor retrieval quality gates failed: " + ",".join(failed))
    return {
        "query_count": EXPECTED_QUERY_COUNT,
        "binding_count": EXPECTED_QUERY_COUNT,
        "positive_recall_at_5": recall_at_5,
        "positive_recall_at_10": recall_at_10,
        "mrr": mrr,
        "exact_span_case_count": len(span_rows),
        "mean_exact_span_recall_at_5_advisory": mean_span_recall,
        "teaching_assessment_hits": 0,
        "private_path_hits": 0,
        "wrong_version_count": 0,
        "gates": gates,
    }


def inspect_successor_candidate(
    settings: Settings,
    database: ReadCatalogue,
    *,
    bundle: LiveEvaluationBundle,
    build_id: str,
    owner_packet: Mapping[str, Any],
    owner_receipt: Mapping[str, Any],
    application_ledger: Mapping[str, Any],
    scan_attestation: Mapping[str, Any],
    catalogue_snapshot: Mapping[str, Any],
    durable_verifier: Callable[[Settings, Mapping[str, Any]], str] = (
        _verify_durable_candidate_tree
    ),
) -> dict[str, Any]:
    """Bind a sealed successor dynamically without running retrieval."""

    if not build_id or Path(build_id).name != build_id:
        raise ValueError("successor build ID is invalid")
    validate_owner_packet(owner_packet)
    validate_owner_receipt(owner_receipt)
    ledger_sha256, _rows = validate_application_ledger(
        bundle=bundle,
        ledger=application_ledger,
    )
    catalogue_sha256 = validate_catalogue_snapshot(
        catalogue_snapshot,
        application_ledger_content_sha256=ledger_sha256,
    )
    _validate_scan_attestation(scan_attestation)
    _require_pointer_absence(settings.index_dir)
    active_row = database.fetchone("SELECT id FROM index_builds WHERE status='active' LIMIT 1")
    if active_row is not None:
        raise RuntimeError("Phase-2A successor requires no active catalogue build")

    row_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if row_value is None:
        raise ValueError("Phase-2A successor build is unavailable")
    row = dict(row_value)
    snapshot = _catalogue_row_snapshot(row)
    build_path = settings.index_dir / "builds" / build_id
    expected_relative_path = str(build_path.relative_to(settings.project_root))
    if (
        snapshot["id"] != build_id
        or snapshot["status"] != "built_unscored"
        or snapshot["stage"] != "built_unscored"
        or snapshot["path"] != expected_relative_path
        or int(snapshot["document_count"] or 0) < 1
        or int(snapshot["chunk_count"] or 0) < 1
        or snapshot["chunk_count"] != snapshot["vector_count"]
        or snapshot["failure_reason_code"] not in (None, "")
        or snapshot["promoted_at"] is not None
        or snapshot["promotion_decision"] not in (None, "", "not_requested")
    ):
        raise RuntimeError("Phase-2A successor is not one sealed non-active build")

    candidate_manifest_path = build_path / "manifest.json"
    candidate_seal_path = build_path / "seal.json"
    source_manifest_path = build_path / "approved-source-manifest.json"
    candidate_manifest = _json_object(candidate_manifest_path, label="candidate manifest")
    candidate_seal = _json_object(candidate_seal_path, label="candidate seal")
    source_manifest = _json_object(source_manifest_path, label="approved source manifest")
    source_manifest_sha256 = approved_source_manifest_sha256(source_manifest)
    sources = source_manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise RuntimeError("successor source manifest has no sources")
    source_version_ids = [
        str(source.get("source_version_id") or "")
        for source in sources
        if isinstance(source, Mapping)
    ]
    if len(source_version_ids) != len(sources):
        raise RuntimeError("successor source manifest has an invalid source row")
    source_set_sha256 = source_version_id_set_sha256(source_version_ids)
    manifest_source_ids = catalogue_snapshot.get("source_version_ids")
    if not isinstance(manifest_source_ids, list):
        raise RuntimeError("catalogue snapshot source inventory is unavailable")
    chunk_total = sum(int(source.get("body_chunk_count") or 0) for source in sources)
    if (
        source_manifest.get("schema") != "legalbot.approved-source-manifest.v1"
        or source_manifest.get("manifest_sha256") != source_manifest_sha256
        or source_manifest.get("source_count") != len(sources)
        or source_manifest.get("chunk_count") != chunk_total
        or source_manifest.get("source_version_id_set_sha256") != source_set_sha256
        or source_manifest.get("source_scan_reconciled") is not True
        or source_manifest.get("source_scan_id") != scan_attestation.get("scan_id")
        or source_manifest.get("source_scan_manifest_sha256")
        != scan_attestation.get("manifest_sha256")
        or source_manifest.get("phase2a_owner_packet_content_sha256")
        != FINAL_OWNER_PACKET_CONTENT_SHA256
        or source_manifest.get("phase2a_owner_approval_receipt_content_sha256")
        != FINAL_OWNER_RECEIPT_CONTENT_SHA256
        or source_manifest.get("phase2a_owner_application_ledger_content_sha256") != ledger_sha256
        or source_manifest.get("answer_release_eligible") is not False
        or source_manifest.get("successor_must_remain_non_active") is not True
        or source_manifest.get("active_or_previous_write_authorized") is not False
        or source_manifest.get("phase2b_authorized") is not False
        or source_manifest.get("development30_authorized") is not False
        or source_manifest.get("omitted_required_families") not in ([], ())
        or sorted(source_version_ids) != sorted(str(value) for value in manifest_source_ids)
        or catalogue_snapshot.get("source_scan_id") != scan_attestation.get("scan_id")
        or catalogue_snapshot.get("source_scan_manifest_sha256")
        != scan_attestation.get("manifest_sha256")
        or catalogue_snapshot.get("source_count") != len(sources)
        or catalogue_snapshot.get("chunk_count") != chunk_total
    ):
        raise RuntimeError("dynamic successor source/candidate scope differs")
    if (
        candidate_manifest.get("schema") != "legalbot.lance-build.v1"
        or candidate_manifest.get("build_id") != build_id
        or candidate_manifest.get("sealed") is not True
        or candidate_manifest.get("chunk_count") != chunk_total
        or candidate_manifest.get("source_manifest_sha256") != source_manifest_sha256
        or candidate_manifest.get("source_scan_id") != scan_attestation.get("scan_id")
        or candidate_manifest.get("source_scan_manifest_sha256")
        != scan_attestation.get("manifest_sha256")
        or candidate_seal.get("schema") != "legalbot.index-seal.v2"
        or candidate_seal.get("build_id") != build_id
        or candidate_seal.get("manifest_sha256") != _file_sha256(candidate_manifest_path)
        or candidate_seal.get("source_manifest_file_sha256") != _file_sha256(source_manifest_path)
        or candidate_seal.get("source_scan_manifest_sha256")
        != scan_attestation.get("manifest_sha256")
        or snapshot["manifest_sha256"] != _file_sha256(candidate_seal_path)
        or snapshot["candidate_manifest_hash"] != _file_sha256(candidate_seal_path)
        or snapshot["source_manifest_hash"] != source_manifest_sha256
        or int(snapshot["document_count"] or 0) != len(sources)
        or int(snapshot["chunk_count"] or 0) != chunk_total
    ):
        raise RuntimeError("sealed successor manifest/catalogue identities differ")
    durable_sha256 = durable_verifier(settings, row)
    if durable_sha256 != source_manifest_sha256:
        raise RuntimeError("durable successor source-manifest identity differs")

    material = {
        "schema": CANDIDATE_BINDING_SCHEMA,
        "build_id": build_id,
        "corpus_id": snapshot["corpus_id"],
        "build_status": "built_unscored",
        "build_stage": "built_unscored",
        "source_count": len(sources),
        "chunk_count": chunk_total,
        "vector_count": int(snapshot["vector_count"] or 0),
        "candidate_manifest_file_sha256": _file_sha256(candidate_manifest_path),
        "candidate_seal_file_sha256": _file_sha256(candidate_seal_path),
        "source_manifest_sha256": source_manifest_sha256,
        "source_manifest_file_sha256": _file_sha256(source_manifest_path),
        "source_scan_id": scan_attestation["scan_id"],
        "source_scan_manifest_sha256": scan_attestation["manifest_sha256"],
        "source_version_id_set_sha256": source_set_sha256,
        "catalogue_row_sha256": hashlib.sha256(canonical_json(snapshot)).hexdigest(),
        "source_catalogue_snapshot_content_sha256": catalogue_sha256,
        "final_owner_packet_content_sha256": FINAL_OWNER_PACKET_CONTENT_SHA256,
        "final_owner_approval_receipt_content_sha256": (FINAL_OWNER_RECEIPT_CONTENT_SHA256),
        "owner_application_ledger_content_sha256": ledger_sha256,
        "answer_release_eligible": False,
        "successor_must_remain_non_active": True,
        "active_pointer_absent": True,
        "previous_pointer_absent": True,
        "phase2b_authorized": False,
        "promotion_authorized": False,
    }
    return sealed(material)


def run_successor_retrieval_reattestation(
    settings: Settings,
    database: ReadCatalogue,
    *,
    bundle: LiveEvaluationBundle,
    build_id: str,
    owner_packet: Mapping[str, Any],
    owner_receipt: Mapping[str, Any],
    application_ledger: Mapping[str, Any],
    scan_attestation: Mapping[str, Any],
    catalogue_snapshot: Mapping[str, Any],
    benchmark_runner: Callable[..., dict[str, Any]] = run_retrieval_v1,
    durable_verifier: Callable[[Settings, Mapping[str, Any]], str] = (
        _verify_durable_candidate_tree
    ),
) -> dict[str, Any]:
    """Run one read-only retrieval check and prove the candidate did not change."""

    before = inspect_successor_candidate(
        settings,
        database,
        bundle=bundle,
        build_id=build_id,
        owner_packet=owner_packet,
        owner_receipt=owner_receipt,
        application_ledger=application_ledger,
        scan_attestation=scan_attestation,
        catalogue_snapshot=catalogue_snapshot,
        durable_verifier=durable_verifier,
    )
    report = benchmark_runner(
        settings,
        build_id=build_id,
        splits=("development", "promotion"),
    )
    metrics = validate_successor_retrieval_report(report, build_id=build_id)
    after = inspect_successor_candidate(
        settings,
        database,
        bundle=bundle,
        build_id=build_id,
        owner_packet=owner_packet,
        owner_receipt=owner_receipt,
        application_ledger=application_ledger,
        scan_attestation=scan_attestation,
        catalogue_snapshot=catalogue_snapshot,
        durable_verifier=durable_verifier,
    )
    if after != before:
        raise RuntimeError("retrieval re-attestation changed the successor boundary")
    material = {
        "schema": RETRIEVAL_REATTESTATION_SCHEMA,
        "build_id": build_id,
        "candidate_binding_content_sha256": before["artifact_content_sha256"],
        "source_manifest_sha256": before["source_manifest_sha256"],
        "source_scan_id": before["source_scan_id"],
        "source_scan_manifest_sha256": before["source_scan_manifest_sha256"],
        "retrieval_report_content_sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
        "metrics": metrics,
        "retrieval_quality_passed": True,
        "catalogue_written": False,
        "candidate_status_written": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
        "active_pointer_absent_before_and_after": True,
        "previous_pointer_absent_before_and_after": True,
        "answer_model_invoked": False,
        "promotion_eligible": False,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
    }
    return sealed(material)
