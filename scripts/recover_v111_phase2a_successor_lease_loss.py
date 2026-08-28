#!/usr/bin/env python3
"""Recover the exact Phase-2A successor after its first lease-loss stop.

This command performs no scan and creates no new build. It verifies that the
persisted Lance rows are the exact frozen stream prefix, advances the stale
checkpoint across those already-written rows, and requeues the same generation
for one separately invoked second attempt.
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

BUILD_ID = "current-law-ew-full-fp16-v111-20260827-phase2a-a"
JOB_ID = f"index-{BUILD_ID}"
RUN_NAME = "LegalBot-Phase2A-2026-08-27-successor-build-recovery-r2"
ENVIRONMENT_FAILURE_RELATIVE = Path(
    "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2A-2026-08-27-successor-build-recovery-r1/"
    "FAILURE-REPORT.json"
)
EXPECTED_ENVIRONMENT_FAILURE_SHA256 = (
    "5b8e3d56a972d3065797e82d8bffae24fef3745ce06636267714e0fc814da2d6"
)
FAILURE_REPORT_RELATIVE = Path(
    "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2A-2026-08-27-successor-build-runtime-debug-r1/"
    "FAILURE-REPORT.json"
)
EXPECTED_FAILURE_REPORT_SHA256 = "e66f8932da930621c1c28162bbe38105c8244240ebca32e8a86b4920092292fb"
EXPECTED_SOURCE_MANIFEST_SHA256 = "b304ab1223987bf9b57d3e2560413b2f325c16213ae0071a45dface2e10dc206"
EXPECTED_OLD_CHECKPOINT_FILE_SHA256 = (
    "65279d6cf4302e7af65344f7fc5f10dcd3e3c212cfaabbc7dddefda6c32ba295"
)
EXPECTED_CHECKPOINTED_ROWS = 3_072
EXPECTED_OBSERVED_ROWS = 3_712
EXPECTED_FROZEN_ROWS = 222_200
EXPECTED_ATTEMPT_COUNT = 1
EXACT_RECOVERY_WORKFLOW_SECONDS = 86_400


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_new_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(_canonical_json(value))


def _write_new_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(value.encode())


def _package_index(root: Path, *, status: str) -> dict[str, Any]:
    files = {
        path.relative_to(root).as_posix(): {
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name not in {"PACKAGE-INDEX.json", "SHA256SUMS.txt"}
    }
    payload = {
        "schema": "legalbot.v111.phase2a.successor-build-recovery-package.v1",
        "run_name": RUN_NAME,
        "status": status,
        "build_id": BUILD_ID,
        "job_id": JOB_ID,
        "files": files,
        "source_scan_repeated": False,
        "new_build_created": False,
        "active_or_previous_written": False,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    payload["package_content_sha256"] = _sha256_bytes(_canonical_json(payload))
    return payload


def _write_sums(root: Path) -> None:
    records = [
        f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS.txt"
    ]
    _write_new_text(root / "SHA256SUMS.txt", "\n".join(records) + "\n")


def _require_failed_exact_state(database: Database) -> tuple[dict[str, Any], dict[str, Any]]:
    job_row = database.job(JOB_ID)
    build_row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (BUILD_ID,))
    if job_row is None or build_row is None:
        raise ValueError("exact Phase-2A successor job or build is missing")
    job = dict(job_row)
    build = dict(build_row)
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
        raise ValueError("exact Phase-2A lease-loss state changed")
    return job, build


def main() -> None:
    root = settings.evaluation_dir / "phase2a-owner-review" / RUN_NAME
    if root.exists():
        raise FileExistsError("exact successor recovery evidence already exists")
    root.mkdir(parents=True)
    _write_new_json(
        root / "INTENT.json",
        {
            "schema": "legalbot.v111.phase2a.successor-build-recovery-intent.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "expected_attempt_count": EXPECTED_ATTEMPT_COUNT,
            "expected_checkpointed_rows": EXPECTED_CHECKPOINTED_ROWS,
            "expected_observed_rows": EXPECTED_OBSERVED_ROWS,
            "expected_frozen_rows": EXPECTED_FROZEN_ROWS,
            "corrected_environment_failure_sha256": (EXPECTED_ENVIRONMENT_FAILURE_SHA256),
            "same_build_only": True,
            "second_source_scan_authorized": False,
            "planner_or_answer_model_authorized": False,
            "automatic_third_claim": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    database: Database | None = None
    try:
        failure_report = settings.project_root / FAILURE_REPORT_RELATIVE
        environment_failure = settings.project_root / ENVIRONMENT_FAILURE_RELATIVE
        if (
            environment_failure.is_symlink()
            or not environment_failure.is_file()
            or _sha256_file(environment_failure) != EXPECTED_ENVIRONMENT_FAILURE_SHA256
        ):
            raise ValueError("sealed recovery environment failure report changed")
        if (
            failure_report.is_symlink()
            or not failure_report.is_file()
            or _sha256_file(failure_report) != EXPECTED_FAILURE_REPORT_SHA256
        ):
            raise ValueError("sealed first-attempt failure report changed")
        database = Database(settings.database_path)
        database.initialize()
        job, _build = _require_failed_exact_state(database)
        request = json.loads(str(job.get("request_json") or "{}"))
        source_ids = tuple(str(item) for item in request.get("source_version_ids") or ())
        if len(source_ids) != 251 or len(set(source_ids)) != 251:
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
            or int(manifest.get("chunk_count") or 0) != EXPECTED_FROZEN_ROWS
        ):
            raise ValueError("exact frozen source manifest changed")
        staging = ImmutableLanceRepository(settings.index_dir).staging_path(BUILD_ID)
        checkpoint_file = staging / "lance" / "embedding-progress.v1.json"
        if (
            staging.is_symlink()
            or not staging.is_dir()
            or _sha256_file(checkpoint_file) != EXPECTED_OLD_CHECKPOINT_FILE_SHA256
        ):
            raise ValueError("first-attempt incomplete staging checkpoint changed")
        expected_rows = load_expected_index_rows(
            database,
            source_ids=source_ids,
            allowlists=manifest.get("locator_allowlists") or {},
            prompt_safe=_prompt_safe_index_text,
        )
        observed_rows = read_lance_observations(staging)
        before = audit_incomplete_index(
            settings,
            database,
            BUILD_ID,
            expected_rows=expected_rows,
            observed_rows=observed_rows,
        )
        _write_new_json(root / "ORDERED-PREFIX-AUDIT-BEFORE.json", before)
        if (
            len(expected_rows) != EXPECTED_FROZEN_ROWS
            or len(observed_rows) != EXPECTED_OBSERVED_ROWS
            or before.get("source_manifest_match") is not True
            or before.get("exact_ordered_prefix") is not True
            or before.get("checkpoint_prefix_match") is not True
            or before.get("checkpoint_reconciliation_required") is not True
            or int((before.get("checkpoint") or {}).get("completed_row_count") or 0)
            != EXPECTED_CHECKPOINTED_ROWS
            or int(before.get("uncheckpointed_observed_rows") or 0)
            != EXPECTED_OBSERVED_ROWS - EXPECTED_CHECKPOINTED_ROWS
        ):
            raise RuntimeError("first-attempt staging is not the exact recoverable prefix")
        reconciliation = reconcile_embedding_checkpoint_to_observed_prefix(
            staging,
            expected_rows=expected_rows,
            observed_rows=observed_rows,
            expected_build_id=BUILD_ID,
            expected_source_manifest_sha256=EXPECTED_SOURCE_MANIFEST_SHA256,
        )
        _write_new_json(root / "CHECKPOINT-RECONCILIATION.json", reconciliation)
        if (
            reconciliation.get("changed") is not True
            or reconciliation.get("old_completed_row_count") != EXPECTED_CHECKPOINTED_ROWS
            or reconciliation.get("new_completed_row_count") != EXPECTED_OBSERVED_ROWS
        ):
            raise RuntimeError("exact checkpoint reconciliation did not advance once")
        after = audit_incomplete_index(
            settings,
            database,
            BUILD_ID,
            expected_rows=expected_rows,
            observed_rows=observed_rows,
        )
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
            audit_report=after,
            checkpoint_reconciliation=reconciliation,
            workflow_seconds=EXACT_RECOVERY_WORKFLOW_SECONDS,
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
            raise RuntimeError("exact second-attempt requeue did not persist safely")
        summary = {
            "schema": "legalbot.v111.phase2a.successor-build-recovery-summary.v1",
            "status": "EXACT_SAME_BUILD_QUEUED_FOR_BOUNDED_SECOND_ATTEMPT",
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "expected_frozen_rows": EXPECTED_FROZEN_ROWS,
            "verified_observed_prefix_rows": EXPECTED_OBSERVED_ROWS,
            "checkpoint_rows_before": EXPECTED_CHECKPOINTED_ROWS,
            "checkpoint_rows_after": EXPECTED_OBSERVED_ROWS,
            "workflow_seconds": EXACT_RECOVERY_WORKFLOW_SECONDS,
            "recovery_condition_sha256": requeue["recovery_condition_sha256"],
            "source_scan_repeated": False,
            "new_build_created": False,
            "source_bytes_changed": False,
            "source_scope_changed": False,
            "automatic_third_claim": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_new_json(root / "SUMMARY.json", summary)
        _write_new_text(
            root / "OUTCOME.txt",
            "EXACT PHASE 2A SUCCESSOR RECOVERY PASSED - SAME BUILD QUEUED FOR ATTEMPT 2\n",
        )
        package = _package_index(root, status="PASSED_QUEUED_FOR_EXACT_SECOND_ATTEMPT")
        _write_new_json(root / "PACKAGE-INDEX.json", package)
        _write_sums(root)
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    except BaseException as exc:
        fingerprint_material = {
            "gate": "phase2a_successor_lease_loss_recovery",
            "build_id": BUILD_ID,
            "job_id": JOB_ID,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
        }
        failure_path = root / "FAILURE-REPORT.json"
        if not failure_path.exists():
            _write_new_json(
                failure_path,
                {
                    "schema": "legalbot.v111.phase2a.successor-build-recovery-failure.v1",
                    "created_at": datetime.now(UTC).isoformat(),
                    **fingerprint_material,
                    "failure_fingerprint": _sha256_bytes(_canonical_json(fingerprint_material)),
                    "unchanged_retry_authorized": False,
                    "source_scan_repeated": False,
                    "new_build_created": False,
                    "active_or_previous_written": False,
                    "phase2b_authorized": False,
                    "development30_authorized": False,
                },
            )
        if not (root / "OUTCOME.txt").exists():
            _write_new_text(
                root / "OUTCOME.txt",
                "PHASE 2A SUCCESSOR RECOVERY SAFELY STOPPED - DEBUG REQUIRED\n",
            )
        if not (root / "PACKAGE-INDEX.json").exists():
            _write_new_json(
                root / "PACKAGE-INDEX.json",
                _package_index(root, status="SAFELY_STOPPED_DEBUG_REQUIRED"),
            )
        if not (root / "SHA256SUMS.txt").exists():
            _write_sums(root)
        raise
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    main()
