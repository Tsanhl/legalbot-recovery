from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.evaluation import phase2a_successor_qualification as qualification
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.phase2a_safe_fallback_qualification import (
    PERFORMANCE_BOND_ROW_ID,
    build_performance_bond_safe_fallback_disposition,
    build_safe_fallback_disposition,
)
from app.evaluation.phase2a_safe_fallback_qualification import (
    ROW_ID as PROJECT_RESCUE_ROW_ID,
)
from app.retrieval import phase2a_successor_reattest as reattest
from app.retrieval.source_manifest import approved_source_manifest_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[2]
OWNER_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
OWNER_PACKET_PATH = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-28-source-delta-safe-fallback-owner-packet-r1/"
    "EXACT-PHASE2A-SOURCE-DELTA-SAFE-FALLBACK-OWNER-PACKET.json"
)
OWNER_RECEIPT_PATH = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1/OWNER-ADOPTION-RECEIPT.json"
)
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
BUILD_ID = "dynamic-phase2a-successor-test"
CLI = PROJECT_ROOT / "scripts/run_v111_phase2a_successor_qualification.py"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _bundle():
    return load_live_evaluation_bundle(BUNDLE_ROOT)


def _application_ledger() -> dict[str, Any]:
    bundle = _bundle()
    project = build_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=(qualification.FINAL_OWNER_PACKET_CONTENT_SHA256),
    )
    performance = build_performance_bond_safe_fallback_disposition(
        bundle=bundle,
        owner_adoption_packet_content_sha256=(qualification.FINAL_OWNER_PACKET_CONTENT_SHA256),
    )
    rows: list[dict[str, Any]] = []
    ordinal = 0
    for case in bundle.registry.cases:
        for issue_number, _label in enumerate(case.must_cover_issues, start=1):
            ordinal += 1
            row_id = f"{case.case_id}:issue-{issue_number:02d}"
            fallback = row_id in qualification.FALLBACK_ROW_IDS
            support = sorted(qualification.SPECIAL_SUPPORT_IDENTITIES.get(row_id, {"a" * 64}))
            if fallback:
                support = []
            material = {
                "ordinal": ordinal,
                "row_id": row_id,
                "resolution_class": (
                    "OWNER_ADOPTED_SAFE_FALLBACK"
                    if fallback
                    else "OWNER_ADOPTED_EXACT_TECHNICAL_SUPPORT"
                ),
                "owner_decision_resolved": True,
                "material_gap": False,
                "technical_support_complete": not fallback,
                "safe_fallback_contract_complete": fallback,
                "support_identity_sha256s": support,
                "retained_release_hold_codes": ["ANSWER_RELEASE_HOLD_RETAINED"],
                "unresolved_hold_codes": [],
                "safe_fallback_disposition": (
                    project
                    if row_id == PROJECT_RESCUE_ROW_ID
                    else performance
                    if row_id == PERFORMANCE_BOND_ROW_ID
                    else None
                ),
            }
            rows.append(qualification.sealed(material, field="record_content_sha256"))
    material = {
        "schema": qualification.APPLICATION_LEDGER_SCHEMA,
        "final_owner_packet_content_sha256": (qualification.FINAL_OWNER_PACKET_CONTENT_SHA256),
        "final_owner_approval_receipt_content_sha256": (
            qualification.FINAL_OWNER_RECEIPT_CONTENT_SHA256
        ),
        "original_owner_receipt_content_sha256": (
            qualification.ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        ),
        "decision_application_complete": True,
        "source_materialization_complete": True,
        "owner_decision_count": 361,
        "prior_technically_ready_row_count": 224,
        "row_count": 585,
        "regular_support_row_count": 583,
        "safe_fallback_row_count": 2,
        "unresolved_owner_decision_count": 0,
        "material_gap_count": 0,
        "rows": rows,
    }
    return qualification.sealed(material)


def _scan_attestation() -> dict[str, Any]:
    value = {
        "schema": "legalbot.source-scan-attestation.v1",
        "scan_id": "dynamic-scan",
        "status": "complete",
        "manifest_sha256": "b" * 64,
        "expected_file_count": 3,
        "accounted_file_count": 3,
        "source_root_count": 3,
        "quarantine_count": 0,
        "quarantine_reason_counts": {},
        "rollback_quarantine_count": 0,
        "quarantine_reason_code": "processing_policy_rollback_refused",
        "completed_at": "2026-08-28T00:00:00+00:00",
        "superseded_scan_ids": [],
        "code_sha": None,
        "writes_active": False,
        "writes_o04": False,
    }
    value["seal_sha256"] = sealed_sha256(value)
    return value


def _catalogue_snapshot(ledger: dict[str, Any]) -> dict[str, Any]:
    source_ids = ["source-version-a", "source-version-b", "source-version-c"]
    material = {
        "schema": qualification.CATALOGUE_SNAPSHOT_SCHEMA,
        "final_owner_packet_content_sha256": (qualification.FINAL_OWNER_PACKET_CONTENT_SHA256),
        "final_owner_approval_receipt_content_sha256": (
            qualification.FINAL_OWNER_RECEIPT_CONTENT_SHA256
        ),
        "owner_application_ledger_content_sha256": ledger["artifact_content_sha256"],
        "source_scan_id": "dynamic-scan",
        "source_scan_manifest_sha256": "b" * 64,
        "source_scan_status": "complete",
        "source_count": 3,
        "approved_source_count": 3,
        "chunk_count": 6,
        "source_version_ids": source_ids,
        "source_version_id_set_sha256": (qualification.source_version_id_set_sha256(source_ids)),
        "unresolved_owner_decision_count": 0,
        "material_gap_count": 0,
    }
    return qualification.sealed(material)


class _Catalogue:
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        if "status='active'" in sql:
            return None
        if "WHERE id=?" in sql and params == (BUILD_ID,):
            return dict(self.row)
        raise AssertionError(f"unexpected query: {sql}")


def _candidate_fixture(
    tmp_path: Path,
) -> tuple[
    Settings,
    _Catalogue,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    settings = Settings(project_root=tmp_path)
    settings.ensure_runtime_dirs()
    ledger = _application_ledger()
    scan = _scan_attestation()
    snapshot = _catalogue_snapshot(ledger)
    build_path = settings.index_dir / "builds" / BUILD_ID
    build_path.mkdir(parents=True)
    source_ids = snapshot["source_version_ids"]
    sources = [
        {
            "source_version_id": source_id,
            "body_chunk_count": 2,
            "document_status": "citable",
        }
        for source_id in source_ids
    ]
    source_manifest = {
        "schema": "legalbot.approved-source-manifest.v1",
        "created_at": "2026-08-28T00:00:00+00:00",
        "corpus_id": "dynamic-phase2a-corpus",
        "source_count": 3,
        "chunk_count": 6,
        "sources": sources,
        "source_version_id_set_sha256": snapshot["source_version_id_set_sha256"],
        "source_scan_id": scan["scan_id"],
        "source_scan_manifest_sha256": scan["manifest_sha256"],
        "source_scan_reconciled": True,
        "phase2a_owner_packet_content_sha256": (qualification.FINAL_OWNER_PACKET_CONTENT_SHA256),
        "phase2a_owner_approval_receipt_content_sha256": (
            qualification.FINAL_OWNER_RECEIPT_CONTENT_SHA256
        ),
        "phase2a_owner_application_ledger_content_sha256": ledger["artifact_content_sha256"],
        "answer_release_eligible": False,
        "successor_must_remain_non_active": True,
        "active_or_previous_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "omitted_required_families": [],
    }
    source_manifest["manifest_sha256"] = approved_source_manifest_sha256(source_manifest)
    source_path = build_path / "approved-source-manifest.json"
    source_path.write_text(json.dumps(source_manifest, sort_keys=True) + "\n", encoding="utf-8")
    candidate_manifest = {
        "schema": "legalbot.lance-build.v1",
        "build_id": BUILD_ID,
        "chunk_count": 6,
        "sealed": True,
        "source_manifest_sha256": source_manifest["manifest_sha256"],
        "source_scan_id": scan["scan_id"],
        "source_scan_manifest_sha256": scan["manifest_sha256"],
    }
    candidate_path = build_path / "manifest.json"
    candidate_path.write_text(
        json.dumps(candidate_manifest, sort_keys=True) + "\n", encoding="utf-8"
    )

    def file_sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    candidate_seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": BUILD_ID,
        "manifest_sha256": file_sha(candidate_path),
        "source_manifest_file_sha256": file_sha(source_path),
        "source_scan_manifest_sha256": scan["manifest_sha256"],
    }
    seal_path = build_path / "seal.json"
    seal_path.write_text(json.dumps(candidate_seal, sort_keys=True) + "\n", encoding="utf-8")
    seal_sha = file_sha(seal_path)
    row = {
        "id": BUILD_ID,
        "corpus_id": "dynamic-phase2a-corpus",
        "status": "built_unscored",
        "stage": "built_unscored",
        "path": str(build_path.relative_to(tmp_path)),
        "document_count": 3,
        "chunk_count": 6,
        "vector_count": 6,
        "embedding_model": "embed",
        "embedding_model_version": "embed-v1",
        "reranker_model": "rerank",
        "rerank_version": "rerank-v1",
        "manifest_sha256": seal_sha,
        "candidate_manifest_hash": seal_sha,
        "source_manifest_hash": source_manifest["manifest_sha256"],
        "failure_reason_code": None,
        "promotion_decision": "not_requested",
        "promoted_at": None,
    }
    return (
        settings,
        _Catalogue(row),
        _load(OWNER_PACKET_PATH),
        _load(OWNER_RECEIPT_PATH),
        ledger,
        scan,
        snapshot,
    )


def _report() -> dict[str, Any]:
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
        "build_id": BUILD_ID,
        "answer_model_invoked": False,
        "active_json_written": False,
        "go": True,
        "candidate_gold_binding": {
            "status": "bound",
            "row_count": 24,
            "issues": [],
            "bindings": [{"status": "bound", "id": row["id"]} for row in rows],
        },
        "per_query": rows,
        "aggregates": {
            "positive_recall_at_5": 1.0,
            "positive_recall_at_10": 1.0,
            "mrr": 0.9,
            "teaching_assessment_hits": 0,
            "private_path_hits": 0,
            "wrong_version_count": 0,
        },
        "split_aggregates": {
            "development": {"go": True},
            "promotion": {"go": True},
        },
    }


def _run_retrieval_fixture(tmp_path: Path):
    settings, database, packet, receipt, ledger, scan, snapshot = _candidate_fixture(tmp_path)
    source_manifest_sha = _load(
        settings.index_dir / "builds" / BUILD_ID / "approved-source-manifest.json"
    )["manifest_sha256"]

    def verifier(_settings: Settings, _row: dict[str, Any]) -> str:
        return str(source_manifest_sha)

    candidate = reattest.inspect_successor_candidate(
        settings,
        database,
        bundle=_bundle(),
        build_id=BUILD_ID,
        owner_packet=packet,
        owner_receipt=receipt,
        application_ledger=ledger,
        scan_attestation=scan,
        catalogue_snapshot=snapshot,
        durable_verifier=verifier,
    )
    retrieval = reattest.run_successor_retrieval_reattestation(
        settings,
        database,
        bundle=_bundle(),
        build_id=BUILD_ID,
        owner_packet=packet,
        owner_receipt=receipt,
        application_ledger=ledger,
        scan_attestation=scan,
        catalogue_snapshot=snapshot,
        benchmark_runner=lambda *_args, **_kwargs: _report(),
        durable_verifier=verifier,
    )
    return packet, receipt, ledger, snapshot, candidate, retrieval


def _reseal_ledger_row(ledger: dict[str, Any], row_id: str) -> None:
    row = next(row for row in ledger["rows"] if row["row_id"] == row_id)
    replacement = qualification.sealed(row, field="record_content_sha256")
    ledger["rows"][ledger["rows"].index(row)] = replacement
    ledger.update(qualification.sealed(ledger))


def test_candidate_preflight_uses_dynamic_counts_and_absent_pointers(tmp_path: Path) -> None:
    packet, receipt, ledger, snapshot, candidate, _retrieval = _run_retrieval_fixture(tmp_path)
    assert qualification.validate_owner_packet(packet) == (
        qualification.FINAL_OWNER_PACKET_CONTENT_SHA256
    )
    assert qualification.validate_owner_receipt(receipt) == (
        qualification.FINAL_OWNER_RECEIPT_CONTENT_SHA256
    )
    assert candidate["source_count"] == 3
    assert candidate["chunk_count"] == candidate["vector_count"] == 6
    assert (
        candidate["owner_application_ledger_content_sha256"] == (ledger["artifact_content_sha256"])
    )
    assert (
        candidate["source_catalogue_snapshot_content_sha256"]
        == (snapshot["artifact_content_sha256"])
    )
    assert candidate["active_pointer_absent"] is True
    assert candidate["previous_pointer_absent"] is True


def test_candidate_preflight_rejects_any_pointer(tmp_path: Path) -> None:
    settings, database, packet, receipt, ledger, scan, snapshot = _candidate_fixture(tmp_path)
    (settings.index_dir / "ACTIVE.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="ACTIVE.json to be absent"):
        reattest.inspect_successor_candidate(
            settings,
            database,
            bundle=_bundle(),
            build_id=BUILD_ID,
            owner_packet=packet,
            owner_receipt=receipt,
            application_ledger=ledger,
            scan_attestation=scan,
            catalogue_snapshot=snapshot,
            durable_verifier=lambda *_args: "c" * 64,
        )


def test_retrieval_report_is_dynamic_but_retains_every_quality_gate() -> None:
    metrics = reattest.validate_successor_retrieval_report(_report(), build_id=BUILD_ID)
    assert metrics["binding_count"] == 24
    assert metrics["positive_recall_at_5"] == 1.0
    failed = _report()
    failed["aggregates"]["wrong_version_count"] = 1
    with pytest.raises(RuntimeError, match="contamination"):
        reattest.validate_successor_retrieval_report(failed, build_id=BUILD_ID)


def test_all585_passes_only_as_583_exact_support_plus_two_safe_fallbacks(
    tmp_path: Path,
) -> None:
    packet, receipt, ledger, snapshot, candidate, retrieval = _run_retrieval_fixture(tmp_path)
    result = qualification.build_successor_all585_qualification(
        bundle=_bundle(),
        owner_packet=packet,
        owner_receipt=receipt,
        application_ledger=ledger,
        catalogue_snapshot=snapshot,
        candidate_binding=candidate,
        retrieval_reattestation=retrieval,
    )
    assert result["status_counts"] == {
        qualification.SAFE_FALLBACK_STATUS: 2,
        qualification.TECHNICAL_PASS_STATUS: 583,
    }
    rows = {row["row_id"]: row for row in result["rows"]}
    assert {
        row_id
        for row_id, row in rows.items()
        if row["qualification_status"] == qualification.SAFE_FALLBACK_STATUS
    } == qualification.FALLBACK_ROW_IDS
    assert result["material_gap_count"] == 0
    assert result["unresolved_owner_decision_count"] == 0
    assert result["phase2a_technical_qualification_passed"] is True
    assert result["answer_release_eligible"] is False
    assert result["phase2b_eligible"] is False


def test_all585_rejects_tampered_safe_fallback_even_when_resealed(tmp_path: Path) -> None:
    packet, receipt, ledger, snapshot, candidate, retrieval = _run_retrieval_fixture(tmp_path)
    changed = copy.deepcopy(ledger)
    row = next(row for row in changed["rows"] if row["row_id"] == PROJECT_RESCUE_ROW_ID)
    row["safe_fallback_disposition"]["user_message"] = "unsafe replacement"
    row["safe_fallback_disposition"] = qualification.sealed(
        row["safe_fallback_disposition"], field="record_content_sha256"
    )
    _reseal_ledger_row(changed, PROJECT_RESCUE_ROW_ID)
    changed_snapshot = qualification.sealed(
        {
            **snapshot,
            "owner_application_ledger_content_sha256": changed["artifact_content_sha256"],
        }
    )
    changed_candidate = qualification.sealed(
        {
            **candidate,
            "owner_application_ledger_content_sha256": changed["artifact_content_sha256"],
            "source_catalogue_snapshot_content_sha256": changed_snapshot["artifact_content_sha256"],
        }
    )
    changed_retrieval = qualification.sealed(
        {
            **retrieval,
            "candidate_binding_content_sha256": changed_candidate["artifact_content_sha256"],
        }
    )
    with pytest.raises(ValueError, match="safe-fallback disposition does not exactly"):
        qualification.build_successor_all585_qualification(
            bundle=_bundle(),
            owner_packet=packet,
            owner_receipt=receipt,
            application_ledger=changed,
            catalogue_snapshot=changed_snapshot,
            candidate_binding=changed_candidate,
            retrieval_reattestation=changed_retrieval,
        )


def test_application_ledger_rejects_missing_semenya_support() -> None:
    ledger = _application_ledger()
    row = next(row for row in ledger["rows"] if row["row_id"] == "live60-q53:issue-04")
    row["support_identity_sha256s"].remove(qualification.SEMENYA_RECORD_CONTENT_SHA256)
    _reseal_ledger_row(ledger, "live60-q53:issue-04")
    with pytest.raises(ValueError, match="special owner-adopted support set is incomplete"):
        qualification.validate_application_ledger(bundle=_bundle(), ledger=ledger)


def test_application_ledger_rejects_one_remaining_material_gap() -> None:
    ledger = _application_ledger()
    row = ledger["rows"][0]
    row["material_gap"] = True
    _reseal_ledger_row(ledger, str(row["row_id"]))
    with pytest.raises(ValueError, match="remains unresolved"):
        qualification.validate_application_ledger(bundle=_bundle(), ledger=ledger)


def test_cli_help_is_non_mutating_and_all_runtime_paths_are_mandatory() -> None:
    result = subprocess.run(
        [sys.executable, str(CLI), "preflight", "--help"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    for option in (
        "--project-root",
        "--catalogue",
        "--bundle-root",
        "--build-id",
        "--owner-packet",
        "--owner-receipt",
        "--application-ledger",
        "--scan-attestation",
        "--catalogue-snapshot",
    ):
        assert option in result.stdout
