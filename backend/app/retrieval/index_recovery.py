"""Recover a post-hoc embedding timeout and retry/resume index-build jobs."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..config import Settings
from ..db import Database, utc_iso
from ..jobs import deadline_after, policy_for, queue_capacity_for
from ..types import IndexBuildStage, JobStatus, JobType
from .embedding_progress import (
    build_checkpoint,
    checkpoint_path,
    load_checkpoint,
    ordered_stream_digest,
    save_checkpoint,
)
from .incomplete_index_audit import (
    ExpectedIndexRow,
    ObservedIndexRow,
    audit_incomplete_index,
    compare_checkpoint_to_expected_prefix,
    compare_ordered_index_prefix,
    summarize_expected_prefix,
)
from .index_build import IndexBuildConflictError
from .lancedb import ImmutableLanceRepository


def _require_requeue_admission_locked(
    database: Database,
    connection: Any,
    job_id: str,
    *,
    eligible_statuses: frozenset[str],
    workflow_seconds_override: int | None = None,
    allow_cancelled_fence: bool = False,
) -> tuple[Any, str, str, str]:
    """Fence one operator requeue behind the same capacity-1 transaction."""

    row = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None:
        raise ValueError("cannot requeue an unknown index-build job")
    if str(row["job_type"]) != JobType.INDEX_BUILD:
        raise ValueError("only index-build jobs may use index recovery")
    if row["lease_owner"] is not None or row["lease_expires_at"] is not None:
        raise RuntimeError("index-build job is still bound to a worker lease")
    current_status = str(row["status"])
    if current_status not in eligible_statuses:
        raise RuntimeError("index-build job is not eligible for operator requeue")
    if bool(row["cancel_requested"]) and not allow_cancelled_fence:
        raise RuntimeError("cancelled index-build job cannot be requeued")
    Database._require_job_queue_capacity_locked(
        connection,
        job_type=JobType.INDEX_BUILD,
        capacity=queue_capacity_for(JobType.INDEX_BUILD),
        exclude_job_id=job_id,
    )
    policy = policy_for(JobType.INDEX_BUILD)
    workflow_seconds = (
        policy.workflow_seconds
        if workflow_seconds_override is None
        else int(workflow_seconds_override)
    )
    if workflow_seconds < policy.workflow_seconds or workflow_seconds > 86_400:
        raise ValueError("index recovery workflow override is outside the safe range")
    now = utc_iso()
    return (
        row,
        deadline_after(policy.queue_wait_seconds),
        deadline_after(workflow_seconds),
        now,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reconcile_embedding_checkpoint_to_observed_prefix(
    staging: Path,
    *,
    expected_rows: tuple[ExpectedIndexRow, ...],
    observed_rows: tuple[ObservedIndexRow, ...],
    expected_build_id: str,
    expected_source_manifest_sha256: str,
) -> dict[str, Any]:
    """Advance a stale checkpoint only across an exact persisted Lance prefix."""

    checkpoint = load_checkpoint(staging)
    if checkpoint is None:
        raise RuntimeError("checkpoint reconciliation requires a valid existing checkpoint")
    if checkpoint.build_id != expected_build_id:
        raise RuntimeError("checkpoint build identity changed")
    if checkpoint.source_manifest_sha256 != expected_source_manifest_sha256:
        raise RuntimeError("checkpoint source manifest identity changed")
    expected_keys = [
        f"{row.source_version_id}\t{row.ordinal}\t{row.chunk_id}" for row in expected_rows
    ]
    if ordered_stream_digest(expected_keys) != checkpoint.ordered_chunk_stream_sha256:
        raise RuntimeError("checkpoint ordered stream identity changed")
    prefix = compare_ordered_index_prefix(expected_rows, observed_rows)
    if prefix["exact_ordered_prefix"] is not True:
        raise RuntimeError("observed Lance rows are not the exact expected ordered prefix")
    checkpoint_prefix = compare_checkpoint_to_expected_prefix(
        checkpoint,
        expected_rows,
        observed_row_count=len(observed_rows),
    )
    if checkpoint_prefix["checkpoint_prefix_match"] is not True:
        raise RuntimeError("existing checkpoint does not bind its expected ordered prefix")
    if checkpoint.completed_row_count > len(observed_rows):
        raise RuntimeError("checkpoint is ahead of the observed Lance rows")

    old_file_sha256 = _sha256_file(checkpoint_path(staging))
    if checkpoint.completed_row_count == len(observed_rows):
        return {
            "schema": "legalbot.embedding-checkpoint-prefix-reconciliation.v1",
            "changed": False,
            "build_id": expected_build_id,
            "old_completed_row_count": checkpoint.completed_row_count,
            "new_completed_row_count": checkpoint.completed_row_count,
            "uncheckpointed_rows_reconciled": 0,
            "old_checkpoint_sha256": checkpoint.checkpoint_sha256,
            "new_checkpoint_sha256": checkpoint.checkpoint_sha256,
            "old_checkpoint_file_sha256": old_file_sha256,
            "new_checkpoint_file_sha256": old_file_sha256,
            "exact_ordered_prefix": True,
            "source_bytes_changed": False,
            "source_scope_changed": False,
        }

    summary = summarize_expected_prefix(expected_rows, len(observed_rows))
    lane_counts = Counter(
        {str(key): 0 for key in dict(checkpoint.physical_lane_counts)}
    )
    lane_counts.update(summary["physical_lane_counts"])
    reconciled = build_checkpoint(
        build_id=checkpoint.build_id,
        source_manifest_sha256=checkpoint.source_manifest_sha256,
        ordered_chunk_stream_sha256=checkpoint.ordered_chunk_stream_sha256,
        parser_version=checkpoint.parser_version,
        chunker_version=checkpoint.chunker_version,
        index_schema_version=checkpoint.index_schema_version,
        embedding_model=checkpoint.embedding_model,
        dtype=checkpoint.dtype,
        vector_dimensions=checkpoint.vector_dimensions,
        batch_size=checkpoint.batch_size,
        policy_sha256=checkpoint.policy_sha256,
        assessment_bundle_sha256=checkpoint.assessment_bundle_sha256,
        provision_verification_sha256=checkpoint.provision_verification_sha256,
        parent_vector_build_id=checkpoint.parent_vector_build_id,
        parent_vector_seal_sha256=checkpoint.parent_vector_seal_sha256,
        completed_row_count=len(observed_rows),
        last_deterministic_chunk_key=str(summary["last_deterministic_chunk_key"]),
        rolling_digest=str(summary["rolling_digest"]),
        physical_lane_counts=dict(sorted(lane_counts.items())),
    )
    if reconciled.identity_tuple() != checkpoint.identity_tuple():
        raise RuntimeError("reconciled checkpoint changed an immutable identity")
    save_checkpoint(staging, reconciled)
    verified = load_checkpoint(staging)
    if verified is None or asdict(verified) != asdict(reconciled):
        raise RuntimeError("reconciled checkpoint did not persist exactly")
    return {
        "schema": "legalbot.embedding-checkpoint-prefix-reconciliation.v1",
        "changed": True,
        "build_id": expected_build_id,
        "old_completed_row_count": checkpoint.completed_row_count,
        "new_completed_row_count": reconciled.completed_row_count,
        "uncheckpointed_rows_reconciled": (
            reconciled.completed_row_count - checkpoint.completed_row_count
        ),
        "old_checkpoint_sha256": checkpoint.checkpoint_sha256,
        "new_checkpoint_sha256": reconciled.checkpoint_sha256,
        "old_checkpoint_file_sha256": old_file_sha256,
        "new_checkpoint_file_sha256": _sha256_file(checkpoint_path(staging)),
        "exact_ordered_prefix": True,
        "ordered_prefix_rolling_digest": reconciled.rolling_digest,
        "ordered_prefix_last_deterministic_chunk_key": (
            reconciled.last_deterministic_chunk_key
        ),
        "physical_lane_counts": dict(reconciled.physical_lane_counts),
        "source_bytes_changed": False,
        "source_scope_changed": False,
    }


def _queue_for_dedicated_worker_locked(
    connection: Any,
    row: Any,
    *,
    queue_wait_deadline_at: str,
    workflow_deadline_at: str,
    now: str,
    message: str,
    checkpoint: dict[str, Any] | None = None,
) -> None:
    job_id = str(row["id"])
    updated = connection.execute(
        """
        UPDATE jobs
        SET status='queued', stage='queued', progress=0,
            error_code=NULL, terminal_reason_code=NULL, dlq=0,
            heartbeat_at=NULL, queue_wait_deadline_at=?, workflow_deadline_at=?,
            stage_started_at=NULL, stage_deadline_at=NULL,
            model_call_deadline_at=NULL, model_call_token=NULL,
            user_message=?, checkpoint_json=COALESCE(?, checkpoint_json),
            last_progress_at=?, updated_at=?
        WHERE id=? AND job_type='index_build' AND status=?
          AND lease_owner IS NULL AND lease_expires_at IS NULL
          AND cancel_requested=0
        """,
        (
            queue_wait_deadline_at,
            workflow_deadline_at,
            message,
            json.dumps(checkpoint, sort_keys=True) if checkpoint is not None else None,
            now,
            now,
            job_id,
            str(row["status"]),
        ),
    )
    if updated.rowcount != 1:
        raise RuntimeError("index-build requeue admission changed before commit")
    connection.execute(
        """
        INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
        VALUES (?, 'queued', 0, ?, '{"recovery":"dedicated_worker"}', ?)
        """,
        (job_id, message, now),
    )


def recover_index_embedding(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    continue_build: bool = True,
    audit_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Promote a verified complete embedding past a post-hoc stage_timeout.

    Does not rerun embedding, does not call prepare_staging, and never writes ACTIVE.
    """

    from .service import _validate_build_id

    _validate_build_id(build_id)
    report = audit_report or audit_incomplete_index(settings, database, build_id)
    if report.get("embedding_complete") is not True:
        raise RuntimeError("incomplete staging is not an exact complete embedding")
    if report.get("source_manifest_match") is not True:
        raise RuntimeError("source manifest identity does not match the frozen build")
    repository = ImmutableLanceRepository(settings.index_dir)
    repository.open_resumable_staging(build_id)
    if (settings.index_dir / "ACTIVE.json").exists():
        active = database.active_index_id()
        if active == build_id:
            raise RuntimeError("failed index-build must never become ACTIVE")
    with database.transaction() as connection:
        build = connection.execute("SELECT * FROM index_builds WHERE id=?", (build_id,)).fetchone()
        if build is None:
            raise ValueError("index build is not in the catalogue")
        if str(build["status"]) != "failed":
            raise RuntimeError("recovery is only for a failed embedding generation")
        if str(build["failure_reason_code"] or "") != "stage_timeout":
            raise RuntimeError("recovery is only for a post-hoc embedding stage_timeout")
        if str(build["promotion_decision"] or "") == "promoted":
            raise RuntimeError("refusing to recover a promoted generation")
        job_id = str(build["job_id"] or f"index-{build_id}")
        job, queue_deadline, workflow_deadline, now = _require_requeue_admission_locked(
            database,
            connection,
            job_id,
            eligible_statuses=frozenset({JobStatus.FAILED, JobStatus.DLQ}),
        )
        completed_attempt = connection.execute(
            """
            SELECT 1 FROM job_stage_attempts
            WHERE job_id=? AND stage_key=? AND section_key='index' AND status='complete'
            LIMIT 1
            """,
            (job_id, IndexBuildStage.EMBEDDING),
        ).fetchone()
        if completed_attempt is not None:
            raise RuntimeError("embedding stage already has a complete attempt")
        failed_attempt = connection.execute(
            """
            SELECT stage_key FROM job_stage_attempts
            WHERE job_id=? AND status='failed'
            ORDER BY started_at DESC, attempt_number DESC
            LIMIT 1
            """,
            (job_id,),
        ).fetchone()
        if failed_attempt is None or str(failed_attempt["stage_key"]) != IndexBuildStage.EMBEDDING:
            raise RuntimeError("recovery is only for a failed embedding stage")
        timings = json.loads(str(build["stage_timings_json"] or "{}"))
        if not isinstance(timings, dict):
            timings = {}
        original_duration_ms = int((timings.get("embedding") or {}).get("duration_ms") or 0)
        counts = json.loads(str(build["counts_json"] or "{}"))
        if not isinstance(counts, dict):
            counts = {}
        counts["chunks_written"] = int(report["observed_total_rows"])
        counts["vectors"] = int(report["observed_total_rows"])
        counts["documents"] = int(
            report.get("observed_source_version_count")
            or counts.get("documents")
            or counts.get("sources")
            or 0
        )
        counts["lane_counts"] = report.get("observed_rows_per_physical_lane") or {}
        counts["recovered_from_posthoc_stage_timeout"] = True
        counts["audit_report_sha256"] = str(report["report_sha256"])
        attempt_number = int(
            connection.execute(
                """
                SELECT COALESCE(MAX(attempt_number), 0) + 1
                FROM job_stage_attempts
                WHERE job_id=? AND stage_key=? AND section_key='index'
                """,
                (job_id, IndexBuildStage.EMBEDDING),
            ).fetchone()[0]
        )
        metrics = {
            "recovered_from_posthoc_stage_timeout": True,
            "original_duration_ms": original_duration_ms,
            "audit_report_sha256": report["report_sha256"],
            "expected_chunks": report["expected_chunks"],
            "observed_chunks": report["observed_total_rows"],
            "counts": counts,
        }
        connection.execute(
            """
            INSERT INTO job_stage_attempts(
              id,job_id,stage_key,section_key,attempt_number,status,
              encrypted_output,metrics_json,started_at,finished_at
            ) VALUES (?, ?, ?, 'index', ?, 'complete', NULL, ?, ?, ?)
            """,
            (
                str(uuid4()),
                job_id,
                IndexBuildStage.EMBEDDING,
                attempt_number,
                json.dumps(metrics, sort_keys=True),
                now,
                now,
            ),
        )
        timings["embedding"] = {
            "started_at": (timings.get("embedding") or {}).get("started_at"),
            "finished_at": now,
            "duration_ms": original_duration_ms,
            "recovered_from_posthoc_stage_timeout": True,
            "audit_report_sha256": report["report_sha256"],
        }
        updated_build = connection.execute(
            """
            UPDATE index_builds
            SET status='queued', stage=?, failure_reason_code=NULL,
                promotion_decision='not_requested', stage_timings_json=?, counts_json=?
            WHERE id=? AND status='failed'
            """,
            (
                IndexBuildStage.BUILDING_LEXICAL,
                json.dumps(timings, sort_keys=True),
                json.dumps(counts, sort_keys=True),
                build_id,
            ),
        )
        if updated_build.rowcount != 1:
            raise RuntimeError("embedding recovery build transition changed before commit")
        _queue_for_dedicated_worker_locked(
            connection,
            job,
            queue_wait_deadline_at=queue_deadline,
            workflow_deadline_at=workflow_deadline,
            now=now,
            message="Recovered verified embedding; queued for the dedicated index worker",
            checkpoint={
                "build_id": build_id,
                "recovered_from_posthoc_stage_timeout": True,
                "audit_report_sha256": report["report_sha256"],
            },
        )
    result: dict[str, Any] = {
        "build_id": build_id,
        "job_id": job_id,
        "status": JobStatus.QUEUED,
        "recovered": True,
        "embedding_complete": True,
        "audit_report_sha256": report["report_sha256"],
        "original_duration_ms": original_duration_ms,
        "active_written": False,
        "queued_for_dedicated_worker": True,
        "continue_build_requested": bool(continue_build),
    }
    return result


def rearm_index_job_deadlines(
    database: Database,
    job_id: str,
    *,
    status: str = "queued",
) -> dict[str, str]:
    if str(status) != JobStatus.QUEUED:
        raise ValueError("index deadlines may only be rearmed for queued worker execution")
    with database.transaction() as connection:
        row, queue, workflow, now = _require_requeue_admission_locked(
            database,
            connection,
            job_id,
            eligible_statuses=frozenset({JobStatus.QUEUED}),
        )
        _queue_for_dedicated_worker_locked(
            connection,
            row,
            queue_wait_deadline_at=queue,
            workflow_deadline_at=workflow,
            now=now,
            message="Index-build queue deadlines rearmed for the dedicated worker",
        )
    return {
        "queue_wait_deadline_at": queue,
        "workflow_deadline_at": workflow,
        "rearmed_at": now,
    }


def resume_lease_lost_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    expected_build_id: str,
    expected_attempt_count: int,
    audit_report: dict[str, Any],
    checkpoint_reconciliation: dict[str, Any],
    workflow_seconds: int = 86_400,
) -> dict[str, Any]:
    """Requeue the same lease-lost generation after an exact-prefix repair."""

    del settings
    if audit_report.get("source_manifest_match") is not True:
        raise RuntimeError("lease-loss recovery source manifest does not match")
    if audit_report.get("exact_ordered_prefix") is not True:
        raise RuntimeError("lease-loss recovery lacks an exact ordered prefix")
    if audit_report.get("checkpoint_prefix_match") is not True:
        raise RuntimeError("lease-loss recovery checkpoint does not bind the prefix")
    if audit_report.get("checkpoint_reconciliation_required") is True:
        raise RuntimeError("lease-loss recovery checkpoint still trails Lance")
    checkpoint = audit_report.get("checkpoint")
    if not isinstance(checkpoint, dict) or int(checkpoint.get("completed_row_count") or -1) != int(
        audit_report.get("observed_total_rows") or -2
    ):
        raise RuntimeError("lease-loss recovery checkpoint is not at the observed tail")
    if checkpoint_reconciliation.get("exact_ordered_prefix") is not True:
        raise RuntimeError("lease-loss checkpoint reconciliation evidence is invalid")
    if checkpoint_reconciliation.get("build_id") != expected_build_id:
        raise RuntimeError("lease-loss checkpoint reconciliation build changed")
    condition_payload = {
        "schema": "legalbot.index-lease-loss-recovery-condition.v1",
        "job_id": job_id,
        "build_id": expected_build_id,
        "attempt_count_before_requeue": expected_attempt_count,
        "audit_report_sha256": audit_report.get("report_sha256"),
        "checkpoint_sha256": checkpoint.get("checkpoint_sha256"),
        "checkpoint_reconciliation": checkpoint_reconciliation,
        "workflow_seconds": workflow_seconds,
        "heartbeat_method": "critical_lease_first_bounded_sqlite_busy_retry.v1",
    }
    condition_identity = hashlib.sha256(
        json.dumps(
            condition_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    with database.transaction() as connection:
        job, queue_deadline, workflow_deadline, now = _require_requeue_admission_locked(
            database,
            connection,
            job_id,
            eligible_statuses=frozenset({JobStatus.FAILED}),
            workflow_seconds_override=workflow_seconds,
            allow_cancelled_fence=True,
        )
        if int(job["attempt_count"] or 0) != expected_attempt_count:
            raise RuntimeError("lease-loss recovery attempt count changed")
        if str(job["pinned_index_build_id"] or "") != expected_build_id:
            raise RuntimeError("lease-loss recovery pinned build changed")
        if str(job["error_code"] or "") != "lease_lost" or str(
            job["terminal_reason_code"] or ""
        ) != "lease_lost":
            raise RuntimeError("lease-loss recovery terminal reason changed")
        if bool(job["cancel_requested"]):
            cleared = connection.execute(
                """
                UPDATE jobs SET cancel_requested=0
                WHERE id=? AND status='failed' AND error_code='lease_lost'
                  AND terminal_reason_code='lease_lost' AND cancel_requested=1
                  AND lease_owner IS NULL AND lease_expires_at IS NULL
                """,
                (job_id,),
            )
            if cleared.rowcount != 1:
                raise RuntimeError("lease-loss recovery cancellation fence changed")
            job = connection.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if job is None:
                raise RuntimeError("lease-loss recovery job disappeared")
        build = connection.execute(
            "SELECT * FROM index_builds WHERE id=?", (expected_build_id,)
        ).fetchone()
        if build is None:
            raise ValueError("lease-loss recovery build is missing")
        if (
            str(build["status"]) != "failed"
            or str(build["failure_reason_code"] or "") != "lease_lost"
            or str(build["job_id"] or "") != job_id
            or str(build["promotion_decision"] or "") == "promoted"
        ):
            raise RuntimeError("lease-loss recovery build state changed")
        updated = connection.execute(
            """
            UPDATE index_builds
            SET status='queued', stage='queued', failure_reason_code=NULL,
                promotion_decision='not_requested'
            WHERE id=? AND status='failed' AND failure_reason_code='lease_lost'
            """,
            (expected_build_id,),
        )
        if updated.rowcount != 1:
            raise RuntimeError("lease-loss recovery build transition changed before commit")
        _queue_for_dedicated_worker_locked(
            connection,
            job,
            queue_wait_deadline_at=queue_deadline,
            workflow_deadline_at=workflow_deadline,
            now=now,
            message="Exact-prefix lease-loss recovery queued for the dedicated index worker",
            checkpoint={
                "schema": "legalbot.index-lease-loss-recovery.v1",
                "build_id": expected_build_id,
                "recovery_condition_sha256": condition_identity,
                "audit_report_sha256": audit_report["report_sha256"],
                "embedding_checkpoint_sha256": checkpoint["checkpoint_sha256"],
                "attempt_count_before_requeue": expected_attempt_count,
                "automatic_third_claim": False,
            },
        )
    return {
        "schema": "legalbot.index-lease-loss-requeue.v1",
        "job_id": job_id,
        "build_id": expected_build_id,
        "status": JobStatus.QUEUED,
        "attempt_count": expected_attempt_count,
        "queue_wait_deadline_at": queue_deadline,
        "workflow_deadline_at": workflow_deadline,
        "workflow_seconds": workflow_seconds,
        "recovery_condition_sha256": condition_identity,
        "audit_report_sha256": audit_report["report_sha256"],
        "embedding_checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "queued_for_exact_second_attempt": True,
        "automatic_third_claim": False,
        "new_build_created": False,
        "active_written": False,
    }


def resume_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
) -> dict[str, Any]:
    row = database.job(job_id)
    if row is None or str(row["job_type"]) != JobType.INDEX_BUILD:
        raise ValueError("resume-index-build requires a failed or interrupted index job")
    if row["lease_owner"] is not None or row["lease_expires_at"] is not None:
        raise RuntimeError("index-build job is still bound to a worker lease")
    if str(row["status"]) not in {JobStatus.FAILED, JobStatus.DLQ}:
        raise RuntimeError("job is not eligible for index-build resume")
    request = json.loads(str(row["request_json"] or "{}"))
    build_id = str(request["build_id"])
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if build is None:
        raise ValueError("index build is not in the catalogue")
    repository = ImmutableLanceRepository(settings.index_dir)
    staging = repository.staging_path(build_id)
    report: dict[str, Any] | None = None
    if staging.is_dir():
        report = audit_incomplete_index(settings, database, build_id)
        if report.get("checkpoint_reconciliation_required") is True:
            raise RuntimeError(
                "incomplete staging contains exact rows beyond its checkpoint; "
                "reconcile the ordered prefix before resume"
            )
        if report.get("resumable") is not True:
            raise RuntimeError(
                "incomplete staging is not resumable from its exact checkpoint"
            )
    if (
        str(build["status"]) == "failed"
        and str(build["failure_reason_code"] or "") == "stage_timeout"
    ):
        report = report or audit_incomplete_index(settings, database, build_id)
        if report.get("embedding_complete") is True:
            return recover_index_embedding(
                settings, database, build_id, continue_build=True, audit_report=report
            )
        if report.get("checkpoint") is None:
            raise RuntimeError(
                "incomplete staging is not resumable without a progress checkpoint; "
                "archive it explicitly before retry-index-build"
            )
    with database.transaction() as connection:
        current_job, queue_deadline, workflow_deadline, now = _require_requeue_admission_locked(
            database,
            connection,
            job_id,
            eligible_statuses=frozenset({JobStatus.FAILED, JobStatus.DLQ}),
        )
        current_build = connection.execute(
            "SELECT status FROM index_builds WHERE id=?", (build_id,)
        ).fetchone()
        if current_build is None or str(current_build["status"]) != "failed":
            raise RuntimeError("index build is not in a failed resumable state")
        updated_build = connection.execute(
            """
            UPDATE index_builds
            SET status='queued', stage='queued', failure_reason_code=NULL,
                promotion_decision='not_requested'
            WHERE id=? AND status='failed'
            """,
            (build_id,),
        )
        if updated_build.rowcount != 1:
            raise RuntimeError("index-build resume transition changed before commit")
        _queue_for_dedicated_worker_locked(
            connection,
            current_job,
            queue_wait_deadline_at=queue_deadline,
            workflow_deadline_at=workflow_deadline,
            now=now,
            message="Index-build resume queued for the dedicated worker",
        )
    return {
        "job_id": job_id,
        "build_id": build_id,
        "status": JobStatus.QUEUED,
        "queued_for_dedicated_worker": True,
        "active_written": False,
    }


def retry_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    new_build_id: str,
) -> dict[str, Any]:
    from .index_build import enqueue_index_build
    from .service import _validate_build_id

    _validate_build_id(new_build_id)
    row = database.job(job_id)
    if row is None or str(row["job_type"]) != JobType.INDEX_BUILD:
        raise ValueError("retry-index-build requires a terminal index job")
    if str(row["status"]) not in {"failed", "dlq"}:
        raise RuntimeError("retry from scratch is only for a failed index job")
    if row["lease_owner"] is not None or row["lease_expires_at"] is not None:
        raise RuntimeError("index-build job is still bound to a worker lease")
    request = json.loads(str(row["request_json"] or "{}"))
    old_build_id = str(request["build_id"])
    if new_build_id == old_build_id:
        raise ValueError("retry from scratch requires a new build id")
    repository = ImmutableLanceRepository(settings.index_dir)
    staging = repository.builds / f".{old_build_id}.incomplete"
    retry_lineage_sha256 = hashlib.sha256(
        f"legalbot-index-retry-lineage-v1\0{job_id}\0{old_build_id}\0{new_build_id}".encode()
    ).hexdigest()
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id=str(request["corpus_id"]),
        build_id=new_build_id,
        max_chunks=request.get("max_chunks"),
        preferred_small_first=bool(request.get("preferred_small_first", True)),
        skip_embedding=bool(request.get("skip_embedding")),
        reuse_vectors_from_build_id=(
            str(request["reuse_vectors_from_build_id"])
            if request.get("reuse_vectors_from_build_id")
            else None
        ),
        retry_lineage_sha256=retry_lineage_sha256,
    )
    if queued.get("reused"):
        raise IndexBuildConflictError("retry resolved to an existing job instead of a new build")
    return {
        **queued,
        "retried_from_job_id": job_id,
        "retry_lineage_sha256": retry_lineage_sha256,
        "archived_staging": None,
        "old_staging_preserved": staging.exists(),
        "previous_attempts_preserved": True,
    }


def attest_allowed(status: str) -> bool:
    return status == "built_unscored"
