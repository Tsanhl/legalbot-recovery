#!/usr/bin/env python3
"""Reconcile the exact held successor's resume-only catalogue undercount once."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import lance
from backend.app.config import settings
from backend.app.db import Database

BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
JOB_ID = "index-current-law-ew-full-fp16-v111-20260827-phase2a-a"
RUN_NAME = "LegalBot-Phase2A-2026-08-27-successor-resume-metadata-reconciliation"
EXPECTED_SOURCE_COUNT = 251
EXPECTED_CHUNK_COUNT = 222_200
EXPECTED_PREFIX_ROWS = 3_712
EXPECTED_PREFIX_SOURCE_COUNT = 40
EXPECTED_SUFFIX_SOURCE_COUNT = 212
EXPECTED_PREFIX_SUFFIX_OVERLAP = 1
EXPECTED_OMITTED_SOURCE_COUNT = 39
EXPECTED_SOURCE_MANIFEST_SHA256 = "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
EXPECTED_SOURCE_MANIFEST_FILE_SHA256 = (
    "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"
)
EXPECTED_SEAL_FILE_SHA256 = "b7a8dfabcd5b91c4bebe81cba5817ca35a4366dd8855acd24a2aeda7f7d91b13"
EXPECTED_LANCE_TREE_SHA256 = "2f561a0ec55743ad2897ddd59789e0d41eecb465c4c0c4b6e23b7bf304010da3"
EXPECTED_RECOVERY_PACKAGE_SHA256 = (
    "dff790782f5ca2dc880a5fde27f5b5ba7e7cec555b44ad5a031513a1fa7f5c40"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("successor candidate tree contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        file_digest = bytes.fromhex(_sha256_file(path))
        digest.update(len(file_digest).to_bytes(8, "big"))
        digest.update(file_digest)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required regular file is unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"required JSON is not an object: {path.name}")
    return value


def _write_new(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_new_json(path: Path, value: Any) -> None:
    _write_new(path, _pretty_json(value))


def _sealed(value: dict[str, Any], *, field: str) -> dict[str, Any]:
    output = dict(value)
    output[field] = _sha256_bytes(_canonical_json(output))
    return output


def _pointer_snapshot() -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name in ("ACTIVE.json", "PREVIOUS.json"):
        path = settings.index_dir / name
        if path.is_symlink():
            raise RuntimeError("index pointer is a symbolic link")
        output[name] = {
            "exists": path.exists(),
            "sha256": _sha256_file(path) if path.is_file() else None,
        }
    return output


def _catalogue_snapshot(database: Database) -> dict[str, Any]:
    row_value = database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,))
    if row_value is None:
        raise RuntimeError("exact held successor catalogue row is unavailable")
    row = dict(row_value)
    counts = json.loads(str(row.get("counts_json") or "{}"))
    if not isinstance(counts, dict):
        raise RuntimeError("exact held successor counts are not an object")
    return {
        "build_id": str(row.get("id") or ""),
        "corpus_id": str(row.get("corpus_id") or ""),
        "status": str(row.get("status") or ""),
        "stage": str(row.get("stage") or ""),
        "document_count": int(row.get("document_count") or 0),
        "chunk_count": int(row.get("chunk_count") or 0),
        "vector_count": int(row.get("vector_count") or 0),
        "manifest_sha256": str(row.get("manifest_sha256") or ""),
        "candidate_manifest_hash": str(row.get("candidate_manifest_hash") or ""),
        "failure_reason_code": row.get("failure_reason_code"),
        "counts": counts,
        "counts_json_before": str(row.get("counts_json") or "{}"),
    }


def _candidate_snapshot(build_path: Path) -> dict[str, Any]:
    source_manifest_path = build_path / "approved-source-manifest.json"
    seal_path = build_path / "seal.json"
    evaluation_path = build_path / "evaluation.json"
    source_manifest = _load_object(source_manifest_path)
    seal = _load_object(seal_path)
    evaluation = _load_object(evaluation_path)
    sources = source_manifest.get("sources")
    if not isinstance(sources, list):
        raise RuntimeError("held successor source manifest lacks sources")
    manifest_source_ids = [str(item.get("source_version_id") or "") for item in sources]
    manifest_document_ids = [str(item.get("document_id") or "") for item in sources]

    lance_path = build_path / "lance" / "authority" / "chunks.lance"
    dataset = lance.dataset(lance_path)
    table = dataset.to_table(columns=["source_version_id"])
    lance_source_ids = [str(value) for value in table["source_version_id"].to_pylist()]
    prefix_ids = set(lance_source_ids[:EXPECTED_PREFIX_ROWS])
    suffix_ids = set(lance_source_ids[EXPECTED_PREFIX_ROWS:])
    return {
        "candidate_tree_sha256": _tree_sha256(build_path),
        "seal_file_sha256": _sha256_file(seal_path),
        "source_manifest_file_sha256": _sha256_file(source_manifest_path),
        "source_manifest_sha256": source_manifest.get("manifest_sha256"),
        "source_manifest_source_count": source_manifest.get("source_count"),
        "source_manifest_chunk_count": source_manifest.get("chunk_count"),
        "source_manifest_unique_source_version_count": len(set(manifest_source_ids)),
        "source_manifest_unique_document_count": len(set(manifest_document_ids)),
        "lance_row_count": len(lance_source_ids),
        "lance_unique_source_version_count": len(set(lance_source_ids)),
        "lance_source_ids_match_manifest": set(lance_source_ids) == set(manifest_source_ids),
        "resume_prefix_row_count": EXPECTED_PREFIX_ROWS,
        "resume_prefix_unique_source_count": len(prefix_ids),
        "resume_suffix_unique_source_count": len(suffix_ids),
        "resume_prefix_suffix_overlap_source_count": len(prefix_ids & suffix_ids),
        "resume_omitted_source_count": len(set(manifest_source_ids) - suffix_ids),
        "lance_tree_sha256": seal.get("lance_tree_sha256"),
        "evaluation_source_manifest_sha256": (evaluation.get("integrity") or {}).get(
            "source_manifest_sha256"
        ),
        "answer_release_eligible": source_manifest.get("answer_release_eligible"),
        "successor_must_remain_non_active": source_manifest.get("successor_must_remain_non_active"),
    }


def _validate_before(
    catalogue: dict[str, Any], candidate: dict[str, Any], pointers: dict[str, Any]
) -> None:
    counts = catalogue["counts"]
    expected_catalogue = (
        catalogue["build_id"] == BUILD_ID
        and catalogue["status"] == "built_unscored"
        and catalogue["stage"] == "built_unscored"
        and catalogue["document_count"] == EXPECTED_SUFFIX_SOURCE_COUNT
        and catalogue["chunk_count"] == EXPECTED_CHUNK_COUNT
        and catalogue["vector_count"] == EXPECTED_CHUNK_COUNT
        and catalogue["manifest_sha256"] == EXPECTED_SEAL_FILE_SHA256
        and catalogue["candidate_manifest_hash"] == EXPECTED_SEAL_FILE_SHA256
        and catalogue["failure_reason_code"] in (None, "")
        and counts.get("sources") == EXPECTED_SOURCE_COUNT
        and counts.get("documents") == EXPECTED_SUFFIX_SOURCE_COUNT
        and counts.get("chunks_written") == EXPECTED_CHUNK_COUNT
        and counts.get("vectors") == EXPECTED_CHUNK_COUNT
        and counts.get("vectors_reused") == 0
        and counts.get("vectors_embedded") == EXPECTED_CHUNK_COUNT - EXPECTED_PREFIX_ROWS
        and counts.get("successor_must_remain_non_active") is True
        and counts.get("answer_release_eligible") is False
    )
    expected_candidate = (
        candidate["seal_file_sha256"] == EXPECTED_SEAL_FILE_SHA256
        and candidate["source_manifest_file_sha256"] == EXPECTED_SOURCE_MANIFEST_FILE_SHA256
        and candidate["source_manifest_sha256"] == EXPECTED_SOURCE_MANIFEST_SHA256
        and candidate["source_manifest_source_count"] == EXPECTED_SOURCE_COUNT
        and candidate["source_manifest_chunk_count"] == EXPECTED_CHUNK_COUNT
        and candidate["source_manifest_unique_source_version_count"] == EXPECTED_SOURCE_COUNT
        and candidate["source_manifest_unique_document_count"] == EXPECTED_SOURCE_COUNT
        and candidate["lance_row_count"] == EXPECTED_CHUNK_COUNT
        and candidate["lance_unique_source_version_count"] == EXPECTED_SOURCE_COUNT
        and candidate["lance_source_ids_match_manifest"] is True
        and candidate["resume_prefix_unique_source_count"] == EXPECTED_PREFIX_SOURCE_COUNT
        and candidate["resume_suffix_unique_source_count"] == EXPECTED_SUFFIX_SOURCE_COUNT
        and candidate["resume_prefix_suffix_overlap_source_count"] == EXPECTED_PREFIX_SUFFIX_OVERLAP
        and candidate["resume_omitted_source_count"] == EXPECTED_OMITTED_SOURCE_COUNT
        and candidate["lance_tree_sha256"] == EXPECTED_LANCE_TREE_SHA256
        and candidate["evaluation_source_manifest_sha256"] == EXPECTED_SOURCE_MANIFEST_SHA256
        and candidate["answer_release_eligible"] is False
        and candidate["successor_must_remain_non_active"] is True
    )
    if not expected_catalogue or not expected_candidate:
        raise RuntimeError("held successor resume metadata precondition changed")
    if any(value.get("exists") is True for value in pointers.values()):
        raise RuntimeError("ACTIVE or PREVIOUS pointer exists before reconciliation")


def _package_index(root: Path) -> dict[str, Any]:
    files = {
        path.name: {"sha256": _sha256_file(path), "size": path.stat().st_size}
        for path in sorted(root.iterdir())
        if path.is_file() and path.name not in {"PACKAGE-INDEX.json", "SHA256SUMS.txt"}
    }
    return _sealed(
        {
            "schema": "legalbot.v111.phase2a.resume-metadata-reconciliation-package.v1",
            "status": "PASSED_METADATA_ONLY_CANDIDATE_UNCHANGED",
            "build_id": BUILD_ID,
            "files": files,
            "candidate_bytes_changed": False,
            "source_scope_changed": False,
            "source_scan_repeated": False,
            "new_build_created": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
        field="package_content_sha256",
    )


def _write_sums(root: Path) -> None:
    records = [
        f"{_sha256_file(path)}  {path.name}"
        for path in sorted(root.iterdir())
        if path.is_file() and path.name != "SHA256SUMS.txt"
    ]
    _write_new(root / "SHA256SUMS.txt", ("\n".join(records) + "\n").encode())


def main() -> None:
    evidence_root = settings.evaluation_dir / "phase2a-owner-review" / RUN_NAME
    if evidence_root.exists():
        raise FileExistsError("resume metadata reconciliation evidence already exists")
    evidence_root.mkdir(parents=True, mode=0o700)
    build_path = settings.index_dir / "builds" / BUILD_ID
    _write_new_json(
        evidence_root / "INTENT.json",
        {
            "schema": "legalbot.v111.phase2a.resume-metadata-reconciliation-intent.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "expected_recovery_package_content_sha256": EXPECTED_RECOVERY_PACKAGE_SHA256,
            "metadata_only": True,
            "candidate_bytes_change_authorized": False,
            "source_scope_change_authorized": False,
            "source_scan_authorized": False,
            "new_build_authorized": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )

    database = Database(settings.database_path)
    catalogue_mutated = False
    try:
        database.initialize()
        recovery_package = _load_object(
            settings.evaluation_dir
            / "phase2a-owner-review"
            / "LegalBot-Phase2A-2026-08-27-successor-build-recovery-r2"
            / "PACKAGE-INDEX.json"
        )
        if recovery_package.get("package_content_sha256") != EXPECTED_RECOVERY_PACKAGE_SHA256:
            raise RuntimeError("exact recovery package identity changed")

        catalogue_before = _catalogue_snapshot(database)
        candidate_before = _candidate_snapshot(build_path)
        pointers_before = _pointer_snapshot()
        _validate_before(catalogue_before, candidate_before, pointers_before)
        before = {
            "schema": "legalbot.v111.phase2a.resume-metadata-before.v1",
            "catalogue": catalogue_before,
            "candidate": candidate_before,
            "pointers": pointers_before,
        }
        _write_new_json(evidence_root / "BEFORE.json", before)

        corrected_counts = dict(catalogue_before["counts"])
        corrected_counts.update(
            {
                "documents": EXPECTED_SOURCE_COUNT,
                "vectors_embedded": EXPECTED_CHUNK_COUNT,
                "vectors_reused": 0,
                "resume_metadata_reconciled": True,
                "resume_prefix_row_count": EXPECTED_PREFIX_ROWS,
                "resume_prefix_unique_source_count": EXPECTED_PREFIX_SOURCE_COUNT,
                "resume_prefix_suffix_overlap_source_count": EXPECTED_PREFIX_SUFFIX_OVERLAP,
                "resume_omitted_source_count": EXPECTED_OMITTED_SOURCE_COUNT,
            }
        )
        corrected_counts_json = json.dumps(corrected_counts, sort_keys=True)
        with database.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE index_builds
                SET document_count=?, counts_json=?
                WHERE id=? AND status='built_unscored' AND stage='built_unscored'
                  AND document_count=? AND chunk_count=? AND vector_count=?
                  AND manifest_sha256=? AND candidate_manifest_hash=?
                  AND counts_json=? AND failure_reason_code IS NULL
                """,
                (
                    EXPECTED_SOURCE_COUNT,
                    corrected_counts_json,
                    BUILD_ID,
                    EXPECTED_SUFFIX_SOURCE_COUNT,
                    EXPECTED_CHUNK_COUNT,
                    EXPECTED_CHUNK_COUNT,
                    EXPECTED_SEAL_FILE_SHA256,
                    EXPECTED_SEAL_FILE_SHA256,
                    catalogue_before["counts_json_before"],
                ),
            )
            if updated.rowcount != 1:
                raise RuntimeError("exact held successor metadata compare-and-swap failed")
        catalogue_mutated = True

        catalogue_after = _catalogue_snapshot(database)
        candidate_after = _candidate_snapshot(build_path)
        pointers_after = _pointer_snapshot()
        if (
            catalogue_after["document_count"] != EXPECTED_SOURCE_COUNT
            or catalogue_after["counts"].get("documents") != EXPECTED_SOURCE_COUNT
            or catalogue_after["counts"].get("vectors_embedded") != EXPECTED_CHUNK_COUNT
            or catalogue_after["counts"].get("vectors_reused") != 0
            or catalogue_after["counts"].get("resume_metadata_reconciled") is not True
            or candidate_after != candidate_before
            or pointers_after != pointers_before
        ):
            raise RuntimeError("resume metadata reconciliation postcondition failed")

        reconciliation = _sealed(
            {
                "schema": "legalbot.v111.phase2a.resume-metadata-reconciliation.v1",
                "build_id": BUILD_ID,
                "root_cause": (
                    "attempt-2 resumed after a 3712-row exact prefix and initialized "
                    "per-attempt source/vector counters at zero"
                ),
                "catalogue_document_count_before": EXPECTED_SUFFIX_SOURCE_COUNT,
                "catalogue_document_count_after": EXPECTED_SOURCE_COUNT,
                "vectors_embedded_before": EXPECTED_CHUNK_COUNT - EXPECTED_PREFIX_ROWS,
                "vectors_embedded_after": EXPECTED_CHUNK_COUNT,
                "verified_prefix_rows": EXPECTED_PREFIX_ROWS,
                "verified_prefix_unique_source_count": EXPECTED_PREFIX_SOURCE_COUNT,
                "prefix_suffix_overlap_source_count": EXPECTED_PREFIX_SUFFIX_OVERLAP,
                "source_versions_omitted_from_attempt_2_counter": EXPECTED_OMITTED_SOURCE_COUNT,
                "lance_source_version_count": EXPECTED_SOURCE_COUNT,
                "candidate_tree_sha256_before": candidate_before["candidate_tree_sha256"],
                "candidate_tree_sha256_after": candidate_after["candidate_tree_sha256"],
                "candidate_bytes_changed": False,
                "source_scope_changed": False,
                "source_scan_repeated": False,
                "new_build_created": False,
                "active_or_previous_written": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
            field="record_content_sha256",
        )
        _write_new_json(evidence_root / "RECONCILIATION.json", reconciliation)
        _write_new_json(
            evidence_root / "AFTER.json",
            {
                "schema": "legalbot.v111.phase2a.resume-metadata-after.v1",
                "catalogue": catalogue_after,
                "candidate": candidate_after,
                "pointers": pointers_after,
            },
        )
        _write_new(
            evidence_root / "OUTCOME.txt",
            b"PASSED - METADATA RECONCILED; SEALED CANDIDATE BYTES UNCHANGED\n",
        )
        package = _package_index(evidence_root)
        _write_new_json(evidence_root / "PACKAGE-INDEX.json", package)
        _write_sums(evidence_root)
        print(
            json.dumps(
                {
                    "status": package["status"],
                    "build_id": BUILD_ID,
                    "document_count": EXPECTED_SOURCE_COUNT,
                    "vector_count": EXPECTED_CHUNK_COUNT,
                    "candidate_tree_sha256": candidate_after["candidate_tree_sha256"],
                    "package_content_sha256": package["package_content_sha256"],
                    "candidate_bytes_changed": False,
                    "active_or_previous_written": False,
                },
                indent=2,
                sort_keys=True,
            ),
            flush=True,
        )
    except BaseException as exc:
        failure = {
            "schema": "legalbot.v111.phase2a.resume-metadata-failure.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "build_id": BUILD_ID,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "catalogue_mutated_before_failure": catalogue_mutated,
            "candidate_bytes_changed": False,
            "source_scope_changed": False,
            "new_build_created": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        failure["failure_fingerprint"] = _sha256_bytes(_canonical_json(failure))
        failure_path = evidence_root / "FAILURE-REPORT.json"
        if not failure_path.exists():
            _write_new_json(failure_path, failure)
        raise
    finally:
        database.close()


if __name__ == "__main__":
    main()
