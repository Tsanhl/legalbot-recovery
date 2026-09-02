#!/usr/bin/env python3
"""Recover the exact 2026-08-29 Phase-2A build after its lease-loss stop.

The command preserves the old checkpoint, verifies every retained Lance row as
the exact frozen-stream prefix, advances the checkpoint only across those
already committed rows, and requeues the same build for one bounded second
attempt.  It creates no build, source scan, pointer, model answer, or release.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.config import settings
from backend.app.db import Database
from backend.app.retrieval.incomplete_index_audit import (
    audit_incomplete_index,
    load_expected_index_rows,
    read_lance_observations,
)
from backend.app.retrieval.index_recovery import (
    reconcile_embedding_checkpoint_to_observed_prefix,
    resume_lease_lost_index_build,
)
from backend.app.retrieval.lancedb import ImmutableLanceRepository
from backend.app.retrieval.service import _prompt_safe_index_text
from backend.app.retrieval.source_manifest import build_approved_source_manifest

BUILD_ID = "current-law-ew-full-fp16-v111-20260829-recovery-b"
JOB_ID = f"index-{BUILD_ID}"
RUN_NAME = "LegalBot-Phase2A-2026-09-01-recovery-b-resume-r2"
EXPECTED_ATTEMPT_COUNT = 1
EXPECTED_SOURCE_COUNT = 85
EXPECTED_FROZEN_ROWS = 149_855
EXPECTED_CHECKPOINT_ROWS = 21_504
EXPECTED_OBSERVED_ROWS = 22_400
EXPECTED_SOURCE_MANIFEST_SHA256 = (
    "1ab9e139e2d97e2f4b935fb8619a46c98ee257f855ce8f9a99ec309905f7623b"
)
EXPECTED_CHECKPOINT_FILE_SHA256 = (
    "c075e07367dde055a1cf9fef589e5fa579e7d15cbde2d52c2abafe3433c4f227"
)
EXPECTED_CHECKPOINT_SHA256 = "fb1588b8e1e0df34c0a4a74763b726c663392999bcd732e13ad5f1dd94d109e9"
EXPECTED_BEFORE_AUDIT_SHA256 = "26e6ea486600cfee92418cacb4b2c5b5ea4d41dca264a449aac9e27d466318e0"
EXPECTED_BACKUP_RECEIPT_FILE_SHA256 = (
    "6fcd984ff959129f7d61f4583a864343533b6ca7b5338467cdf0dfe1f6c6a689"
)
EXPECTED_BACKUP_SHA256 = "9171cd70fbaa5343391aaee368d588df5f1330b59bbad1dc56fd90f35947f743"
EXPECTED_BACKUP_RECEIPT_CONTENT_SHA256 = (
    "38bc3f6c9e221a09b45ffb167f2389462d81a7b5baa6a97153cb358b75b21c37"
)
WORKFLOW_SECONDS = 86_400


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_new_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value)


def _write_new_json(path: Path, value: Any) -> None:
    _write_new_bytes(path, _canonical_json(value))


def _write_sums(root: Path) -> None:
    rows = [
        f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS.txt"
    ]
    _write_new_bytes(root / "SHA256SUMS.txt", ("\n".join(rows) + "\n").encode())


def _require_backup_receipt() -> dict[str, Any]:
    path = (
        settings.project_root
        / "data/backups/LegalBot-Phase2-2026-09-01-entry/BACKUP-RESTORE-RECEIPT.json"
    )
    if (
        path.is_symlink()
        or not path.is_file()
        or _sha256_file(path) != EXPECTED_BACKUP_RECEIPT_FILE_SHA256
    ):
        raise ValueError("exact fresh backup/restore receipt changed")
    receipt = json.loads(path.read_bytes())
    if (
        receipt.get("schema") != "legalbot.catalogue-backup-restore-receipt.v1"
        or receipt.get("status") != "BACKUP_AND_RESTORE_DRILL_PASSED"
        or (receipt.get("backup") or {}).get("sha256") != EXPECTED_BACKUP_SHA256
        or receipt.get("receipt_content_sha256") != EXPECTED_BACKUP_RECEIPT_CONTENT_SHA256
    ):
        raise ValueError("fresh backup/restore receipt identity is invalid")
    return receipt


def _require_failed_state(database: Database) -> tuple[dict[str, Any], dict[str, Any]]:
    job_row = database.job(JOB_ID)
    build_row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,))
    if job_row is None or build_row is None:
        raise ValueError("exact recovery-b job or build is missing")
    job, build = dict(job_row), dict(build_row)
    if (
        job.get("status") != "failed"
        or job.get("stage") != "failed"
        or int(job.get("attempt_count") or 0) != EXPECTED_ATTEMPT_COUNT
        or job.get("error_code") != "lease_lost"
        or job.get("terminal_reason_code") != "lease_lost"
        or int(job.get("cancel_requested") or 0) != 1
        or job.get("lease_owner") is not None
        or job.get("lease_expires_at") is not None
        or job.get("pinned_index_build_id") != BUILD_ID
        or build.get("status") != "failed"
        or build.get("stage") != "failed"
        or build.get("failure_reason_code") != "lease_lost"
        or build.get("job_id") != JOB_ID
        or build.get("source_manifest_hash") != EXPECTED_SOURCE_MANIFEST_SHA256
        or build.get("promotion_decision") != "blocked_failed"
    ):
        raise ValueError("exact recovery-b lease-loss state changed")
    return job, build


def _package(root: Path, *, status: str) -> dict[str, Any]:
    files = {
        path.relative_to(root).as_posix(): {
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in {"PACKAGE-INDEX.json", "SHA256SUMS.txt"}
    }
    payload = {
        "schema": "legalbot.phase2a.recovery-b-resume-package.v1",
        "run_name": RUN_NAME,
        "status": status,
        "build_id": BUILD_ID,
        "job_id": JOB_ID,
        "files": files,
        "source_scan_repeated": False,
        "new_build_created": False,
        "active_or_previous_written": False,
        "answer_model_run": False,
        "evaluation_run": False,
        "promotion_run": False,
        "live_run": False,
        "deletion_run": False,
    }
    payload["package_content_sha256"] = _sha256_bytes(_canonical_json(payload))
    return payload


def main() -> None:
    root = settings.evaluation_dir / "phase2a-owner-review" / RUN_NAME
    if root.exists():
        raise FileExistsError("exact recovery-b resume evidence already exists")
    root.mkdir(parents=True, mode=0o700)
    _write_new_json(
        root / "INTENT.json",
        {
            "schema": "legalbot.phase2a.recovery-b-resume-intent.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "expected_attempt_count": EXPECTED_ATTEMPT_COUNT,
            "expected_frozen_rows": EXPECTED_FROZEN_ROWS,
            "expected_checkpoint_rows": EXPECTED_CHECKPOINT_ROWS,
            "expected_observed_rows": EXPECTED_OBSERVED_ROWS,
            "workflow_seconds": WORKFLOW_SECONDS,
            "same_build_only": True,
            "source_scan_repeated": False,
            "new_build_created": False,
            "automatic_third_claim": False,
            "active_or_previous_write_authorized": False,
            "answer_model_authorized": False,
            "evaluation_authorized": False,
            "promotion_authorized": False,
            "live_authorized": False,
            "deletion_authorized": False,
        },
    )
    database: Database | None = None
    try:
        backup_receipt = _require_backup_receipt()
        _write_new_json(
            root / "BACKUP-BINDING.json",
            {
                "schema": "legalbot.phase2a.recovery-backup-binding.v1",
                "backup_sha256": backup_receipt["backup"]["sha256"],
                "receipt_content_sha256": backup_receipt["receipt_content_sha256"],
                "restore_drill_passed": True,
            },
        )
        database = Database(settings.database_path)
        database.initialize()
        job, _build = _require_failed_state(database)
        request = json.loads(str(job.get("request_json") or "{}"))
        source_ids = tuple(str(item) for item in request.get("source_version_ids") or ())
        if len(source_ids) != EXPECTED_SOURCE_COUNT or len(set(source_ids)) != len(source_ids):
            raise ValueError("exact frozen source-version order changed")
        manifest = build_approved_source_manifest(
            database,
            settings,
            corpus_id=str(request.get("corpus_id") or ""),
            max_chunks=request.get("max_chunks"),
            preferred_small_first=bool(request.get("preferred_small_first", True)),
        )
        if (
            manifest.get("manifest_sha256") != EXPECTED_SOURCE_MANIFEST_SHA256
            or int(manifest.get("source_count") or 0) != EXPECTED_SOURCE_COUNT
            or int(manifest.get("chunk_count") or 0) != EXPECTED_FROZEN_ROWS
        ):
            raise ValueError("exact frozen source manifest changed")
        staging = ImmutableLanceRepository(settings.index_dir).staging_path(BUILD_ID)
        checkpoint_file = staging / "lance" / "embedding-progress.v1.json"
        checkpoint_before = checkpoint_file.read_bytes()
        if (
            staging.is_symlink()
            or not staging.is_dir()
            or checkpoint_file.is_symlink()
            or _sha256_bytes(checkpoint_before) != EXPECTED_CHECKPOINT_FILE_SHA256
        ):
            raise ValueError("recovery-b checkpoint bytes changed")
        checkpoint_value = json.loads(checkpoint_before)
        if (
            checkpoint_value.get("checkpoint_sha256") != EXPECTED_CHECKPOINT_SHA256
            or int(checkpoint_value.get("completed_row_count") or 0)
            != EXPECTED_CHECKPOINT_ROWS
        ):
            raise ValueError("recovery-b checkpoint identity changed")
        expected_rows = load_expected_index_rows(
            database,
            source_ids=source_ids,
            allowlists=manifest.get("locator_allowlists") or {},
            prompt_safe=_prompt_safe_index_text,
        )
        observed_rows = read_lance_observations(staging)
        before = audit_incomplete_index(settings, database, BUILD_ID)
        _write_new_bytes(root / "EMBEDDING-CHECKPOINT-BEFORE.json", checkpoint_before)
        _write_new_json(root / "ORDERED-PREFIX-AUDIT-BEFORE.json", before)
        if (
            len(expected_rows) != EXPECTED_FROZEN_ROWS
            or len(observed_rows) != EXPECTED_OBSERVED_ROWS
            or before.get("report_sha256") != EXPECTED_BEFORE_AUDIT_SHA256
            or before.get("source_manifest_match") is not True
            or before.get("exact_ordered_prefix") is not True
            or before.get("checkpoint_prefix_match") is not True
            or before.get("checkpoint_reconciliation_required") is not True
            or int((before.get("checkpoint") or {}).get("completed_row_count") or 0)
            != EXPECTED_CHECKPOINT_ROWS
            or int(before.get("uncheckpointed_observed_rows") or 0)
            != EXPECTED_OBSERVED_ROWS - EXPECTED_CHECKPOINT_ROWS
        ):
            raise RuntimeError("recovery-b staging is not the exact recoverable prefix")
        reconciliation = reconcile_embedding_checkpoint_to_observed_prefix(
            settings,
            database,
            BUILD_ID,
            expected_audit_report_sha256=str(before["report_sha256"]),
        )
        _write_new_json(root / "CHECKPOINT-RECONCILIATION.json", reconciliation)
        if (
            reconciliation.get("changed") is not True
            or reconciliation.get("old_completed_row_count") != EXPECTED_CHECKPOINT_ROWS
            or reconciliation.get("new_completed_row_count") != EXPECTED_OBSERVED_ROWS
            or reconciliation.get("uncheckpointed_rows_reconciled")
            != EXPECTED_OBSERVED_ROWS - EXPECTED_CHECKPOINT_ROWS
        ):
            raise RuntimeError("checkpoint reconciliation did not advance exactly once")
        checkpoint_after = checkpoint_file.read_bytes()
        _write_new_bytes(root / "EMBEDDING-CHECKPOINT-AFTER.json", checkpoint_after)
        after = audit_incomplete_index(settings, database, BUILD_ID)
        _write_new_json(root / "ORDERED-PREFIX-AUDIT-AFTER.json", after)
        if (
            after.get("resumable") is not True
            or after.get("exact_ordered_prefix") is not True
            or after.get("checkpoint_prefix_match") is not True
            or after.get("checkpoint_reconciliation_required") is not False
            or int((after.get("checkpoint") or {}).get("completed_row_count") or 0)
            != EXPECTED_OBSERVED_ROWS
        ):
            raise RuntimeError("reconciled checkpoint is not at the exact Lance tail")
        requeue = resume_lease_lost_index_build(
            settings,
            database,
            JOB_ID,
            expected_build_id=BUILD_ID,
            expected_attempt_count=EXPECTED_ATTEMPT_COUNT,
            expected_audit_report_sha256=str(after["report_sha256"]),
            expected_checkpoint_reconciliation_sha256=str(
                reconciliation["checkpoint_reconciliation_sha256"]
            ),
            workflow_seconds=WORKFLOW_SECONDS,
        )
        _write_new_json(root / "EXACT-REQUEUE.json", requeue)
        final_job = database.job(JOB_ID)
        final_build = database.fetchone(
            "SELECT status,stage,failure_reason_code,promotion_decision FROM index_builds WHERE id=?",
            (BUILD_ID,),
        )
        if (
            final_job is None
            or final_build is None
            or final_job["status"] != "queued"
            or int(final_job["attempt_count"] or 0) != EXPECTED_ATTEMPT_COUNT
            or int(final_job["cancel_requested"] or 0) != 0
            or final_job["lease_owner"] is not None
            or final_build["status"] != "queued"
            or final_build["failure_reason_code"] is not None
        ):
            raise RuntimeError("exact recovery-b requeue did not persist safely")
        summary = {
            "schema": "legalbot.phase2a.recovery-b-resume-summary.v1",
            "status": "EXACT_SAME_BUILD_QUEUED_FOR_BOUNDED_SECOND_ATTEMPT",
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "expected_frozen_rows": EXPECTED_FROZEN_ROWS,
            "verified_observed_prefix_rows": EXPECTED_OBSERVED_ROWS,
            "checkpoint_rows_before": EXPECTED_CHECKPOINT_ROWS,
            "checkpoint_rows_after": EXPECTED_OBSERVED_ROWS,
            "workflow_seconds": WORKFLOW_SECONDS,
            "recovery_condition_sha256": requeue["recovery_condition_sha256"],
            "new_build_created": False,
            "source_scan_repeated": False,
            "automatic_third_claim": False,
            "active_or_previous_written": False,
            "answer_model_run": False,
            "evaluation_run": False,
            "promotion_run": False,
            "live_run": False,
            "deletion_run": False,
        }
        _write_new_json(root / "SUMMARY.json", summary)
        _write_new_json(
            root / "PACKAGE-INDEX.json",
            _package(root, status="PASSED_QUEUED_FOR_EXACT_SECOND_ATTEMPT"),
        )
        _write_sums(root)
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    except BaseException as exc:
        failure = {
            "schema": "legalbot.phase2a.recovery-b-resume-failure.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "gate": "phase2a_recovery_b_lease_loss_resume",
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "unchanged_retry_authorized": False,
            "new_build_created": False,
            "source_scan_repeated": False,
            "active_or_previous_written": False,
            "deletion_run": False,
        }
        failure["failure_fingerprint_sha256"] = _sha256_bytes(_canonical_json(failure))
        path = root / "FAILURE-REPORT.json"
        if not path.exists():
            _write_new_json(path, failure)
        raise
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    main()
