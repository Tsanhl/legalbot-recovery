#!/usr/bin/env python3
"""Validate the non-authorizing v1.11 recovery baseline on the current HEAD."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_PATH = PROJECT_ROOT / "docs/status/v111-phase1-recovery-inputs-20260829.json"
MODEL_SPEC_PATH = PROJECT_ROOT / "scripts/model/manifests/qwen3-retrieval-models.json"
QUESTION_RECEIPT_PATH = (
    PROJECT_ROOT / "docs/status/v111-phase2b-question-bank-recovery-receipt-20260829.json"
)


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("recovery baseline input is missing or unsafe")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("recovery baseline input must be an object")
    return value


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("recovery baseline member is missing or unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _model_file_manifest_sha256(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if ".cache" in relative.parts or relative.as_posix() == "retrieval-model.json":
            continue
        if path.is_symlink():
            raise RuntimeError("retrieval model contains a symbolic link")
        if path.is_file():
            records.append(
                {
                    "path": relative.as_posix(),
                    "size": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    return hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _git_head() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def _read_catalogue_row(query: str, parameters: tuple[Any, ...]) -> dict[str, Any]:
    database_path = PROJECT_ROOT / "data/catalog.sqlite3"
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(query, parameters).fetchone()
    finally:
        connection.close()
    if row is None:
        raise RuntimeError("recovery baseline catalogue identity is missing")
    return dict(row)


def _validate_scan(inputs: dict[str, Any]) -> dict[str, int | str]:
    expected = inputs["source_scan"]
    row = _read_catalogue_row("SELECT * FROM source_scans WHERE id=?", (expected["id"],))
    if row["status"] != "complete" or row["error_code"] is not None:
        raise RuntimeError("recovery source scan is not complete")
    exact_fields = (
        "manifest_sha256",
        "expected_file_count",
        "files_accounted",
        "statuses_json",
    )
    for field in exact_fields:
        actual: Any = row[field]
        wanted: Any = expected[field]
        if field == "statuses_json":
            actual = json.loads(str(actual))
            wanted = dict(wanted)
        if actual != wanted:
            raise RuntimeError(f"recovery source scan {field} changed")
    required_roots = json.loads(str(row["required_roots_json"]))
    roots_seen = json.loads(str(row["roots_seen_json"]))
    if required_roots != roots_seen or required_roots != expected["required_roots"]:
        raise RuntimeError("recovery source-root identity changed")
    accounted = _read_catalogue_row(
        "SELECT COUNT(*) AS count FROM source_scan_files WHERE scan_id=?",
        (expected["id"],),
    )
    if int(accounted["count"]) != int(expected["files_accounted"]):
        raise RuntimeError("recovery source scan row accounting changed")
    return {
        "source_scan_id": str(row["id"]),
        "source_scan_file_count": int(row["files_accounted"]),
        "source_scan_root_count": len(required_roots),
    }


def _validate_models(inputs: dict[str, Any]) -> dict[str, int | str]:
    if _sha256_file(MODEL_SPEC_PATH) != inputs["retrieval_models"]["spec_sha256"]:
        raise RuntimeError("retrieval-model specification changed")
    specification = _load_object(MODEL_SPEC_PATH)
    if specification.get("schema_version") != 1:
        raise RuntimeError("retrieval-model specification schema changed")
    expected_models = {item["role"]: item for item in inputs["retrieval_models"]["models"]}
    if set(expected_models) != {"embedding", "reranker"}:
        raise RuntimeError("recovery model input roles changed")
    for model in specification["models"]:
        expected = expected_models[model["role"]]
        for field in ("revision", "file_manifest_sha256"):
            if model[field] != expected[field]:
                raise RuntimeError(f"retrieval {model['role']} identity changed")
        target = PROJECT_ROOT / str(model["directory"])
        if target.is_symlink() or not target.is_dir():
            raise RuntimeError(f"retrieval {model['role']} store is missing or unsafe")
        if any(not (target / str(member)).is_file() for member in model["required_files"]):
            raise RuntimeError(f"retrieval {model['role']} required file is missing")
        if not any(target.glob("*.safetensors")):
            raise RuntimeError(f"retrieval {model['role']} weights are missing")
        config = _load_object(target / "config.json")
        provenance = _load_object(target / "retrieval-model.json")
        if (
            config.get("model_type") != "qwen3"
            or provenance.get("source_repo") != model["source_repo"]
            or provenance.get("revision") != model["revision"]
            or _model_file_manifest_sha256(target) != model["file_manifest_sha256"]
        ):
            raise RuntimeError(f"retrieval {model['role']} store identity changed")
    return {
        "retrieval_model_count": 2,
        "retrieval_model_spec_sha256": inputs["retrieval_models"]["spec_sha256"],
    }


def _validate_candidate(inputs: dict[str, Any], head: str) -> dict[str, int | str]:
    expected = inputs["candidate"]
    build_id = str(expected["build_id"])
    row = _read_catalogue_row("SELECT * FROM index_builds WHERE id=?", (build_id,))
    exact_fields = (
        "status",
        "stage",
        "corpus_id",
        "source_manifest_hash",
        "document_count",
        "chunk_count",
        "vector_count",
    )
    for field in exact_fields:
        if row[field] != expected[field]:
            raise RuntimeError(f"recovery candidate {field} changed")
    if row["status"] != "candidate" or row["stage"] != "candidate":
        raise RuntimeError("recovery candidate is not retrieval-attested")
    if int(row["chunk_count"]) <= 0 or row["chunk_count"] != row["vector_count"]:
        raise RuntimeError("recovery candidate vector parity failed")

    build_root = PROJECT_ROOT / "data/indexes/builds" / build_id
    for member, expected_sha256 in expected["artifact_sha256"].items():
        if _sha256_file(build_root / member) != expected_sha256:
            raise RuntimeError(f"recovery candidate artifact changed: {member}")
    if (PROJECT_ROOT / "data/indexes/ACTIVE.json").exists() or (
        PROJECT_ROOT / "data/indexes/PREVIOUS.json"
    ).exists():
        raise RuntimeError("release pointer exists during recovery baseline validation")

    attestation_path = (
        PROJECT_ROOT / "data/evaluations/retrieval" / build_id / "v1.1-attestation.json"
    )
    attestation = _load_object(attestation_path)
    report = attestation.get("report")
    aggregates = report.get("aggregates") if isinstance(report, dict) else None
    binding = report.get("candidate_gold_binding") if isinstance(report, dict) else None
    if (
        attestation.get("schema") != "legalbot.retrieval-attestation.v1.1"
        or attestation.get("build_id") != build_id
        or attestation.get("integration_sha") != head
        or attestation.get("passed") is not True
        or attestation.get("promotion_eligible") is not True
        or not isinstance(report, dict)
        or report.get("go") is not True
        or report.get("answer_model_invoked") is not False
        or report.get("active_json_written") is not False
        or len(report.get("per_query") or ()) != 24
        or not isinstance(binding, dict)
        or binding.get("bound_count") != 24
        or not isinstance(aggregates, dict)
        or aggregates.get("positive_recall_at_5") != 1.0
        or float(aggregates.get("positive_recall_at_10") or 0) < 0.95
        or float(aggregates.get("mrr") or 0) < 0.8
        or aggregates.get("teaching_assessment_hits") != 0
        or aggregates.get("private_path_hits") != 0
        or aggregates.get("wrong_version_count") != 0
    ):
        raise RuntimeError("recovery retrieval attestation contract failed")
    return {
        "candidate_build_id": build_id,
        "candidate_document_count": int(row["document_count"]),
        "candidate_chunk_count": int(row["chunk_count"]),
        "candidate_vector_count": int(row["vector_count"]),
        "retrieval_case_count": 24,
        "retrieval_attestation_sha256": _sha256_file(attestation_path),
    }


def _validate_question_bank(inputs: dict[str, Any]) -> dict[str, int | str]:
    expected_receipt_sha256 = inputs["question_bank_recovery_receipt_sha256"]
    if _sha256_file(QUESTION_RECEIPT_PATH) != expected_receipt_sha256:
        raise RuntimeError("question-bank recovery receipt changed")
    receipt = _load_object(QUESTION_RECEIPT_PATH)
    if (
        receipt.get("status")
        != "PASS_EXACT_CANONICAL_AND_ZIP_IDENTITIES_RECOVERED_NOT_PHASE2B_AUTHORIZED"
        or receipt.get("authorizing") is not False
    ):
        raise RuntimeError("question-bank recovery receipt is not passing")
    package_root = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
    package_count = 0
    for package in receipt["package_receipts"]:
        run_name = package["run_name"]
        manifest_path = package_root / run_name / "PACKAGE-MANIFEST.json"
        if manifest_path.is_file():
            manifest = _load_object(manifest_path)
            if manifest.get("package_content_sha256") != package["package_content_sha256"]:
                raise RuntimeError(f"question-bank package identity changed: {run_name}")
            package_count += 1
        if "zip_sha256" in package:
            archive = package_root / f"{run_name}.zip"
            if _sha256_file(archive) != package["zip_sha256"]:
                raise RuntimeError(f"question-bank archive identity changed: {run_name}")
    if package_count != 5:
        raise RuntimeError("question-bank recovery package count changed")
    return {
        "question_bank_package_count": package_count,
        "question_bank_recovery_receipt_sha256": expected_receipt_sha256,
    }


def validate_recovery_baseline() -> dict[str, Any]:
    inputs = _load_object(INPUT_PATH)
    if (
        inputs.get("schema") != "legalbot.v111.phase1.recovery-inputs.v1"
        or inputs.get("authorizing") is not False
        or inputs.get("status") != "READY_FOR_INTEGRATION_VERIFICATION"
    ):
        raise RuntimeError("recovery baseline input contract failed")
    head = _git_head()
    result: dict[str, Any] = {
        "schema": "legalbot.v111.recovery-baseline-validation.v1",
        "authorizing": False,
        "git_head": head,
        **_validate_scan(inputs),
        **_validate_models(inputs),
        **_validate_candidate(inputs, head),
        **_validate_question_bank(inputs),
        "active_pointer_present": False,
        "previous_pointer_present": False,
        "passed": True,
    }
    return result


def main() -> int:
    try:
        print(json.dumps(validate_recovery_baseline(), sort_keys=True))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.v111.recovery-baseline-validation.v1",
                    "authorizing": False,
                    "passed": False,
                    "reason_code": type(exc).__name__.casefold(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
