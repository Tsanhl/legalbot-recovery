#!/usr/bin/env python3
"""Create the exact deterministic all-585 qualification after held re-attestation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from backend.app.config import settings
from backend.app.db import Database
from backend.app.evaluation.live_suite import load_live_evaluation_bundle
from backend.app.evaluation.phase2a_deterministic_qualification import (
    build_deterministic_all585_qualification,
)
from backend.app.retrieval.phase2a_held_reattest import BUILD_ID

OWNER_ROOT = settings.evaluation_dir / "phase2a-owner-review"
RUN_NAME = "LegalBot-Phase2A-2026-08-27-deterministic-all585-qualification"
RETRIEVAL_RUN_NAME = "LegalBot-Phase2A-2026-08-27-held-retrieval-reattestation-r2"

MATRIX = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate/"
    "COMPLETE-REMEDIATION-MATRIX-585.json"
)
R94 = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-25-r94-consolidated-substantive-owner-batch/"
    "OWNER-SUBSTANTIVE-DECISION-BATCH.json"
)
R95_RECEIPT = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved/"
    "OWNER-APPROVAL-RECEIPT-R94.json"
)
R113 = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved/"
    "REMAINING-MATERIAL-GAPS-364.json"
)
R113_RECEIPT = OWNER_ROOT / (
    "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved/"
    "OWNER-APPROVAL-RECEIPT-R111.json"
)
CROSSWALK = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2/"
    "DETERMINISTIC-EXACT-SPAN-PACKETS-364.json"
)
SOURCE_SCOPE = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-consolidated-source-admission/"
    "FROZEN-SUCCESSOR-SOURCE-SCOPE.json"
)
SOURCE_ADMISSION_PACKAGE = OWNER_ROOT / (
    "LegalBot-Phase2A-2026-08-27-consolidated-source-admission/PACKAGE-INDEX.json"
)
RETRIEVAL = OWNER_ROOT / RETRIEVAL_RUN_NAME / "HELD-RETRIEVAL-REATTESTATION.json"


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required qualification evidence is unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"qualification evidence is not an object: {path.name}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def _write_new_json(path: Path, value: Any) -> None:
    _write_new(path, _canonical_json(value))


def _candidate_identity(database: Database) -> tuple[dict[str, Any], dict[str, Any]]:
    row_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,))
    if row_value is None:
        raise ValueError("held successor candidate is unavailable")
    row = dict(row_value)
    build_path = settings.index_dir / "builds" / BUILD_ID
    seal = _load_object(build_path / "seal.json")
    evaluation = _load_object(build_path / "evaluation.json")
    source_manifest_path = build_path / "approved-source-manifest.json"
    source_manifest = _load_object(source_manifest_path)
    integrity = evaluation.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("held successor integrity report is unavailable")
    identity = {
        "build_id": BUILD_ID,
        "corpus_id": row.get("corpus_id"),
        "status": row.get("status"),
        "stage": row.get("stage"),
        "document_count": int(row.get("document_count") or 0),
        "chunk_count": int(row.get("chunk_count") or 0),
        "vector_count": int(row.get("vector_count") or 0),
        "vector_dimensions": int(integrity.get("vector_dimensions") or 0),
        "embedding_model": row.get("embedding_model"),
        "reranker_model": row.get("reranker_model"),
        "build_seal_sha256": _sha256_file(build_path / "seal.json"),
        "catalogue_manifest_sha256": row.get("manifest_sha256"),
        "candidate_manifest_hash": row.get("candidate_manifest_hash"),
        "source_manifest_file_sha256": _sha256_file(source_manifest_path),
        "source_manifest_sha256": source_manifest.get("manifest_sha256"),
        "lance_tree_sha256": seal.get("lance_tree_sha256"),
        "promotion_eligible": False,
        "answer_release_eligible": False,
        "active_or_previous_written": False,
    }
    return identity, source_manifest


def main() -> None:
    output = OWNER_ROOT / RUN_NAME
    if output.exists():
        raise FileExistsError("deterministic all-585 qualification already exists")
    required = (
        MATRIX,
        R94,
        R95_RECEIPT,
        R113,
        R113_RECEIPT,
        CROSSWALK,
        SOURCE_SCOPE,
        SOURCE_ADMISSION_PACKAGE,
        RETRIEVAL,
    )
    evidence_sha256s = {
        str(path.relative_to(settings.project_root)): _sha256_file(path) for path in required
    }
    database = Database(settings.database_path)
    try:
        database.initialize()
        candidate, source_manifest = _candidate_identity(database)
    finally:
        database.close()
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    result = build_deterministic_all585_qualification(
        bundle=bundle,
        consolidated_matrix=_load_object(MATRIX),
        r94_owner_batch=_load_object(R94),
        r113_remaining_gaps=_load_object(R113),
        deterministic_crosswalk=_load_object(CROSSWALK),
        source_manifest=source_manifest,
        candidate_identity=candidate,
        held_retrieval_reattestation=_load_object(RETRIEVAL),
        evidence_file_sha256s=evidence_sha256s,
    )
    output.mkdir(parents=True)
    qualification_path = output / "DETERMINISTIC-ALL585-QUALIFICATION.json"
    _write_new_json(qualification_path, result)
    summary = {
        "schema": "legalbot.v111.phase2a.deterministic-all585-summary.v1",
        "case_count": result["case_count"],
        "issue_count": result["issue_count"],
        "status_counts": result["status_counts"],
        "candidate_identity": result["candidate_identity"],
        "retrieval_reattestation": result["retrieval_reattestation"],
        "successor_source_holds": result["successor_source_holds"],
        "material_blockers": result["material_blockers"],
        "common_legal_currentness_cutoff": None,
        "phase2a_technical_qualification_passed": False,
        "phase2b_eligible": False,
        "development30_eligible": False,
        "qualification_sha256": _sha256_file(qualification_path),
        "terminal_verdict": result["terminal_verdict"],
    }
    _write_new_json(output / "SUMMARY.json", summary)
    _write_new(
        output / "OUTCOME.txt",
        (str(result["terminal_verdict"]) + "\n").encode("utf-8"),
    )
    files = {
        path.name: {"sha256": _sha256_file(path), "size": path.stat().st_size}
        for path in sorted(output.iterdir())
        if path.is_file()
    }
    package = {
        "schema": "legalbot.v111.phase2a.deterministic-all585-package.v1",
        "status": "COMPLETE_NON_AUTHORIZING_BLOCKED_QUALIFICATION_EVIDENCE",
        "build_id": BUILD_ID,
        "files": files,
        "phase2a_technical_qualification_passed": False,
        "phase2b_eligible": False,
        "development30_eligible": False,
    }
    package["package_content_sha256"] = hashlib.sha256(_canonical_json(package)).hexdigest()
    _write_new_json(output / "PACKAGE-INDEX.json", package)
    sums = "\n".join(
        f"{_sha256_file(path)}  {path.name}"
        for path in sorted(output.iterdir())
        if path.is_file()
    )
    _write_new(output / "SHA256SUMS.txt", (sums + "\n").encode())
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
