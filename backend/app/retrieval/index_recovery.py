"""Recover a post-hoc embedding timeout and retry/resume index-build jobs."""

from __future__ import annotations

import hashlib
import json
import os
import re
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
    save_checkpoint,
)
from .incomplete_index_audit import (
    AUDIT_SCHEMA,
    GE_SELECTION_POLICY,
    audit_incomplete_index,
)
from .index_build import (
    IndexBuildConflictError,
    IndexBuildContext,
    _require_enqueued_source_manifest_unchanged,
)
from .lancedb import ImmutableLanceRepository
from .source_manifest import (
    build_approved_source_manifest,
    source_version_ids,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_mapping_sha256(
    value: dict[str, Any], *, excluded_keys: frozenset[str] = frozenset()
) -> str:
    """Hash the exact JSON-domain mapping used by the recovery boundary."""

    encoded = json.dumps(
        {key: item for key, item in value.items() if key not in excluded_keys},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_sha256(value: str | None, *, label: str) -> str:
    observed = str(value or "")
    if _SHA256_RE.fullmatch(observed) is None:
        raise ValueError(f"{label} must be an exact SHA-256 digest")
    return observed


def _verified_actual_incomplete_index_audit(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    expected_report_sha256: str | None = None,
) -> dict[str, Any]:
    """Recompute the audit from disk/DB and verify its canonical self identity."""

    report = audit_incomplete_index(settings, database, build_id)
    if not isinstance(report, dict):
        raise RuntimeError("incomplete-index audit did not return an object")
    if report.get("schema") != AUDIT_SCHEMA or report.get("build_id") != build_id:
        raise RuntimeError("incomplete-index audit identity differs from the requested build")
    reported_sha256 = _require_sha256(
        str(report.get("report_sha256") or ""), label="audit report SHA-256"
    )
    recomputed_sha256 = _canonical_mapping_sha256(
        report, excluded_keys=frozenset({"report_sha256"})
    )
    if reported_sha256 != recomputed_sha256:
        raise RuntimeError("incomplete-index audit canonical bytes do not match its digest")
    if expected_report_sha256 is not None:
        expected = _require_sha256(
            expected_report_sha256, label="expected audit report SHA-256"
        )
        if expected != reported_sha256:
            raise RuntimeError("recomputed incomplete-index audit differs from expected digest")
    return report


def _actual_checkpoint_reconciliation(
    report: dict[str, Any], *, expected_build_id: str
) -> dict[str, Any]:
    """Derive exact checkpoint/tail reconciliation solely from the actual audit."""

    if report.get("build_id") != expected_build_id:
        raise RuntimeError("lease-loss audit build identity changed")
    if report.get("source_manifest_match") is not True:
        raise RuntimeError("lease-loss recovery source manifest does not match")
    if report.get("source_version_id_binding_match") is not True:
        raise RuntimeError("lease-loss recovery source-version binding does not match")
    if report.get("source_lane_binding_match") is not True:
        raise RuntimeError("lease-loss recovery source-lane binding does not match")
    if report.get("exact_ordered_prefix") is not True:
        raise RuntimeError("lease-loss recovery lacks an exact ordered prefix")
    if report.get("checkpoint_prefix_match") is not True:
        raise RuntimeError("lease-loss recovery checkpoint does not bind the prefix")
    if report.get("checkpoint_reconciliation_required") is True:
        raise RuntimeError("lease-loss recovery checkpoint still trails Lance")
    checkpoint = report.get("checkpoint")
    observed_count = int(report.get("observed_total_rows") or 0)
    if (
        not isinstance(checkpoint, dict)
        or checkpoint.get("present") is not True
        or int(checkpoint.get("completed_row_count") or -1) != observed_count
    ):
        raise RuntimeError("lease-loss recovery checkpoint is not at the observed tail")
    checkpoint_sha256 = _require_sha256(
        str(checkpoint.get("checkpoint_sha256") or ""),
        label="embedding checkpoint SHA-256",
    )
    payload: dict[str, Any] = {
        "schema": "legalbot.embedding-checkpoint-tail-reconciliation.v1",
        "build_id": expected_build_id,
        "audit_report_sha256": str(report["report_sha256"]),
        "source_manifest_sha256": str(report.get("source_manifest_sha256") or ""),
        "observed_total_rows": observed_count,
        "ordered_prefix_verified_row_count": int(
            report.get("ordered_prefix_verified_row_count") or 0
        ),
        "ordered_prefix_rolling_digest": str(
            report.get("ordered_prefix_rolling_digest") or ""
        ),
        "ordered_prefix_last_deterministic_chunk_key": str(
            report.get("ordered_prefix_last_deterministic_chunk_key") or ""
        ),
        "checkpoint_completed_row_count": int(checkpoint["completed_row_count"]),
        "checkpoint_sha256": checkpoint_sha256,
        "checkpoint_last_deterministic_chunk_key": str(
            checkpoint.get("last_deterministic_chunk_key") or ""
        ),
        "exact_ordered_prefix": True,
        "checkpoint_prefix_match": True,
        "checkpoint_reconciliation_required": False,
    }
    payload["reconciliation_sha256"] = _canonical_mapping_sha256(payload)
    return payload


def _require_checkpoint_unchanged_since_audit(
    settings: Settings, *, build_id: str, report: dict[str, Any]
) -> None:
    repository = ImmutableLanceRepository(settings.index_dir)
    staging = repository.open_resumable_staging(build_id)
    checkpoint = load_checkpoint(staging)
    audited = report.get("checkpoint")
    if (
        checkpoint is None
        or not isinstance(audited, dict)
        or checkpoint.build_id != build_id
        or checkpoint.source_manifest_sha256
        != str(report.get("source_manifest_sha256") or "")
        or checkpoint.checkpoint_sha256 != audited.get("checkpoint_sha256")
        or checkpoint.completed_row_count != audited.get("completed_row_count")
        or checkpoint.last_deterministic_chunk_key
        != audited.get("last_deterministic_chunk_key")
    ):
        raise RuntimeError("embedding checkpoint changed after incomplete-index audit")


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


def _preserve_checkpoint_before_reconciliation(staging: Path, *, file_sha256: str) -> Path:
    """Retain the exact prior checkpoint before the mutable cursor advances."""

    source = checkpoint_path(staging)
    content = source.read_bytes()
    if hashlib.sha256(content).hexdigest() != file_sha256:
        raise RuntimeError("checkpoint changed before preservation")
    history = staging / "lance" / "checkpoint-history"
    if history.exists() and (history.is_symlink() or not history.is_dir()):
        raise RuntimeError("checkpoint history location is unsafe")
    history.mkdir(parents=True, exist_ok=True)
    destination = history / f"embedding-progress.{file_sha256}.json"
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise RuntimeError("preserved checkpoint path is unsafe")
        if destination.read_bytes() != content:
            raise RuntimeError("preserved checkpoint bytes changed")
        return destination
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory_fd = os.open(history, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return destination


def _request_is_ge_successor(request: dict[str, Any]) -> bool:
    return request.get("selection_policy") == GE_SELECTION_POLICY


def _verify_ge_recovery_authorization(
    settings: Settings,
    database: Database,
    *,
    job_id: str,
    decision_id: str,
    decision_content_sha256: str,
) -> tuple[dict[str, Any], str]:
    """Replay the original exact owner decision before any GE recovery write."""

    row = database.job(job_id)
    if row is None or str(row["job_type"]) != JobType.INDEX_BUILD:
        raise ValueError("GE index recovery requires an existing index-build job")
    try:
        request = json.loads(str(row["request_json"] or "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("GE index recovery request is invalid") from exc
    if not isinstance(request, dict) or not _request_is_ge_successor(request):
        raise ValueError("dedicated GE recovery requires a GE successor index job")
    if (
        request.get("ge_index_build_owner_decision_id") != decision_id
        or request.get("ge_index_build_owner_decision_content_sha256")
        != decision_content_sha256
    ):
        raise PermissionError("OWNER_DECISION_REQUIRED:ge_index_recovery_decision_mismatch")
    build_id = str(request.get("build_id") or "")
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if build is None:
        raise ValueError("GE index recovery build is absent")
    manifest = build_approved_source_manifest(
        database,
        settings,
        corpus_id=str(request["corpus_id"]),
        max_chunks=request.get("max_chunks"),
        preferred_small_first=bool(request.get("preferred_small_first")),
    )
    try:
        counts = json.loads(str(build["counts_json"] or "{}"))
    except json.JSONDecodeError:
        counts = {}
    if not isinstance(counts, dict):
        counts = {}
    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id=job_id,
        build_id=build_id,
        corpus_id=str(request["corpus_id"]),
        manifest=manifest,
        source_ids=source_version_ids(manifest),
        embedding_model=str(build["embedding_model"]),
        reranker_model=str(build["reranker_model"]),
        build_dir=settings.index_dir / "builds" / build_id,
        timings={},
        counts=counts,
        release_pointer_snapshot=(
            request.get("release_pointer_snapshot_at_enqueue")
            if isinstance(request.get("release_pointer_snapshot_at_enqueue"), dict)
            else None
        ),
    )
    _require_enqueued_source_manifest_unchanged(ctx, request)
    return request, build_id


def reconcile_embedding_checkpoint_to_observed_prefix(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    expected_audit_report_sha256: str,
) -> dict[str, Any]:
    """Advance only from a freshly audited exact disk/DB prefix."""

    before_report = _verified_actual_incomplete_index_audit(
        settings,
        database,
        build_id,
        expected_report_sha256=expected_audit_report_sha256,
    )
    if before_report.get("build_id") != build_id:
        raise RuntimeError("checkpoint reconciliation audit build changed")
    if (
        before_report.get("source_manifest_match") is not True
        or before_report.get("source_version_id_binding_match") is not True
        or before_report.get("source_lane_binding_match") is not True
    ):
        raise RuntimeError("checkpoint reconciliation source binding changed")
    if before_report.get("exact_ordered_prefix") is not True:
        raise RuntimeError("observed Lance rows are not the exact expected ordered prefix")
    if before_report.get("checkpoint_prefix_match") is not True:
        raise RuntimeError("existing checkpoint does not bind its expected ordered prefix")
    if before_report.get("checkpoint_reconciliation_required") is not True:
        raise RuntimeError("checkpoint reconciliation is not required by the actual audit")

    repository = ImmutableLanceRepository(settings.index_dir)
    staging = repository.open_resumable_staging(build_id)
    checkpoint = load_checkpoint(staging)
    if checkpoint is None:
        raise RuntimeError("checkpoint reconciliation requires a valid existing checkpoint")
    if checkpoint.build_id != build_id:
        raise RuntimeError("checkpoint build identity changed")
    if checkpoint.source_manifest_sha256 != str(
        before_report.get("source_manifest_sha256") or ""
    ):
        raise RuntimeError("checkpoint source manifest identity changed")
    audited_checkpoint = before_report.get("checkpoint")
    if (
        not isinstance(audited_checkpoint, dict)
        or audited_checkpoint.get("checkpoint_sha256") != checkpoint.checkpoint_sha256
        or int(audited_checkpoint.get("completed_row_count") or -1)
        != checkpoint.completed_row_count
        or audited_checkpoint.get("last_deterministic_chunk_key")
        != checkpoint.last_deterministic_chunk_key
    ):
        raise RuntimeError("checkpoint changed after the actual audit")

    observed_row_count = int(before_report.get("observed_total_rows") or 0)
    verified_row_count = int(
        before_report.get("ordered_prefix_verified_row_count") or 0
    )
    if (
        checkpoint.completed_row_count >= observed_row_count
        or verified_row_count != observed_row_count
    ):
        raise RuntimeError("actual audit does not prove a trailing exact checkpoint")
    rolling_digest = _require_sha256(
        str(before_report.get("ordered_prefix_rolling_digest") or ""),
        label="ordered prefix rolling digest",
    )
    last_key = str(before_report.get("ordered_prefix_last_deterministic_chunk_key") or "")
    lane_counts_raw = before_report.get("ordered_prefix_lane_counts")
    if not isinstance(lane_counts_raw, dict):
        raise RuntimeError("actual audit lacks ordered-prefix lane counts")
    lane_counts = {str(key): int(value) for key, value in lane_counts_raw.items()}
    if any(value < 0 for value in lane_counts.values()) or sum(lane_counts.values()) != (
        observed_row_count
    ):
        raise RuntimeError("actual audit ordered-prefix lane counts do not reconcile")

    old_file_sha256 = _sha256_file(checkpoint_path(staging))
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
        completed_row_count=observed_row_count,
        last_deterministic_chunk_key=last_key,
        rolling_digest=rolling_digest,
        physical_lane_counts=dict(sorted(lane_counts.items())),
    )
    if reconciled.identity_tuple() != checkpoint.identity_tuple():
        raise RuntimeError("reconciled checkpoint changed an immutable identity")
    preserved_checkpoint = _preserve_checkpoint_before_reconciliation(
        staging, file_sha256=old_file_sha256
    )
    save_checkpoint(staging, reconciled)
    verified = load_checkpoint(staging)
    if verified is None or asdict(verified) != asdict(reconciled):
        raise RuntimeError("reconciled checkpoint did not persist exactly")

    after_report = _verified_actual_incomplete_index_audit(settings, database, build_id)
    actual_reconciliation = _actual_checkpoint_reconciliation(
        after_report, expected_build_id=build_id
    )
    result = {
        "schema": "legalbot.embedding-checkpoint-prefix-reconciliation.v2",
        "changed": True,
        "build_id": build_id,
        "old_completed_row_count": checkpoint.completed_row_count,
        "new_completed_row_count": reconciled.completed_row_count,
        "uncheckpointed_rows_reconciled": (
            reconciled.completed_row_count - checkpoint.completed_row_count
        ),
        "old_checkpoint_sha256": checkpoint.checkpoint_sha256,
        "new_checkpoint_sha256": reconciled.checkpoint_sha256,
        "old_checkpoint_file_sha256": old_file_sha256,
        "preserved_checkpoint_label": str(preserved_checkpoint.relative_to(staging)),
        "new_checkpoint_file_sha256": _sha256_file(checkpoint_path(staging)),
        "exact_ordered_prefix": True,
        "ordered_prefix_rolling_digest": reconciled.rolling_digest,
        "ordered_prefix_last_deterministic_chunk_key": reconciled.last_deterministic_chunk_key,
        "physical_lane_counts": dict(reconciled.physical_lane_counts),
        "before_audit_report_sha256": before_report["report_sha256"],
        "after_audit_report_sha256": after_report["report_sha256"],
        "checkpoint_reconciliation_sha256": actual_reconciliation[
            "reconciliation_sha256"
        ],
        "source_bytes_changed": False,
        "source_scope_changed": False,
    }
    result["receipt_sha256"] = _canonical_mapping_sha256(result)
    return result


def _queue_for_dedicated_worker_locked(
    connection: Any,
    row: Any,
    *,
    queue_wait_deadline_at: str,
    workflow_deadline_at: str,
    now: str,
    message: str,
    checkpoint: dict[str, Any] | None = None,
    event_payload: dict[str, Any] | None = None,
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
    payload = {"recovery": "dedicated_worker"}
    if event_payload is not None:
        payload.update(event_payload)
    connection.execute(
        """
        INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
        VALUES (?, 'queued', 0, ?, ?, ?)
        """,
        (
            job_id,
            message,
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            now,
        ),
    )


def recover_index_embedding(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    expected_audit_report_sha256: str,
    continue_build: bool = True,
    _ge_decision_id: str | None = None,
    _ge_decision_content_sha256: str | None = None,
) -> dict[str, Any]:
    """Promote a verified complete embedding past a post-hoc stage_timeout.

    Does not rerun embedding, does not call prepare_staging, and never writes ACTIVE.
    """

    from .service import _validate_build_id

    _validate_build_id(build_id)
    bound_build = database.fetchone("SELECT job_id FROM index_builds WHERE id=?", (build_id,))
    if bound_build is not None:
        bound_job_id = str(bound_build["job_id"] or f"index-{build_id}")
        bound_job = database.job(bound_job_id)
        if bound_job is not None:
            try:
                bound_request = json.loads(str(bound_job["request_json"] or "{}"))
            except json.JSONDecodeError as exc:
                raise RuntimeError("index recovery request is invalid") from exc
            if isinstance(bound_request, dict) and _request_is_ge_successor(bound_request):
                if not _ge_decision_id or not _ge_decision_content_sha256:
                    raise PermissionError(
                        "OWNER_DECISION_REQUIRED:use_dedicated_ge_index_recovery"
                    )
                _request, authorized_build_id = _verify_ge_recovery_authorization(
                    settings,
                    database,
                    job_id=bound_job_id,
                    decision_id=_ge_decision_id,
                    decision_content_sha256=_ge_decision_content_sha256,
                )
                if authorized_build_id != build_id:
                    raise RuntimeError("GE index recovery build binding changed")
    report = _verified_actual_incomplete_index_audit(
        settings,
        database,
        build_id,
        expected_report_sha256=expected_audit_report_sha256,
    )
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


def recover_ge_index_embedding(
    settings: Settings,
    database: Database,
    build_id: str,
    *,
    decision_id: str,
    decision_content_sha256: str,
    expected_audit_report_sha256: str,
    continue_build: bool = True,
) -> dict[str, Any]:
    """Recover a GE embedding only after replaying its exact owner decision."""

    build = database.fetchone("SELECT job_id FROM index_builds WHERE id=?", (build_id,))
    if build is None:
        raise ValueError("GE index recovery build is absent")
    result = recover_index_embedding(
        settings,
        database,
        build_id,
        continue_build=continue_build,
        expected_audit_report_sha256=expected_audit_report_sha256,
        _ge_decision_id=decision_id,
        _ge_decision_content_sha256=decision_content_sha256,
    )
    return {
        **result,
        "ge_index_build_owner_decision_id": decision_id,
        "ge_index_build_owner_decision_content_sha256": decision_content_sha256,
        "ge_authorization_replayed": True,
    }


def rearm_index_job_deadlines(
    database: Database,
    job_id: str,
    *,
    status: str = "queued",
    _ge_settings: Settings | None = None,
    _ge_decision_id: str | None = None,
    _ge_decision_content_sha256: str | None = None,
) -> dict[str, str]:
    if str(status) != JobStatus.QUEUED:
        raise ValueError("index deadlines may only be rearmed for queued worker execution")
    observed = database.job(job_id)
    if observed is None:
        raise ValueError("index-build job is absent")
    try:
        observed_request = json.loads(str(observed["request_json"] or "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("index-build recovery request is invalid") from exc
    if isinstance(observed_request, dict) and _request_is_ge_successor(observed_request):
        if (
            _ge_settings is None
            or not _ge_decision_id
            or not _ge_decision_content_sha256
        ):
            raise PermissionError("OWNER_DECISION_REQUIRED:use_dedicated_ge_index_recovery")
        _verify_ge_recovery_authorization(
            _ge_settings,
            database,
            job_id=job_id,
            decision_id=_ge_decision_id,
            decision_content_sha256=_ge_decision_content_sha256,
        )
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


def rearm_ge_index_job_deadlines(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    decision_id: str,
    decision_content_sha256: str,
) -> dict[str, Any]:
    """Rearm a queued GE job only after exact owner-decision replay."""

    result = rearm_index_job_deadlines(
        database,
        job_id,
        _ge_settings=settings,
        _ge_decision_id=decision_id,
        _ge_decision_content_sha256=decision_content_sha256,
    )
    return {
        **result,
        "ge_index_build_owner_decision_id": decision_id,
        "ge_index_build_owner_decision_content_sha256": decision_content_sha256,
        "ge_authorization_replayed": True,
    }


def _persisted_lease_loss_failure_fingerprint(
    connection: Any,
    *,
    job: Any,
    build: Any,
    job_id: str,
    build_id: str,
) -> tuple[dict[str, Any], str]:
    """Bind retry identity to persisted machine fields, never caller counters/prose."""

    latest_failed_attempt = connection.execute(
        """
        SELECT stage_key,section_key,error_code,status
        FROM job_stage_attempts
        WHERE job_id=? AND status='failed'
        ORDER BY attempt_number DESC, started_at DESC, id DESC
        LIMIT 1
        """,
        (job_id,),
    ).fetchone()
    material: dict[str, Any] = {
        "schema": "legalbot.ge-index-lease-loss-failure.v1",
        "job_id": job_id,
        "build_id": build_id,
        "job_status": str(job["status"] or ""),
        "job_stage": str(job["stage"] or ""),
        "job_error_code": str(job["error_code"] or ""),
        "job_terminal_reason_code": str(job["terminal_reason_code"] or ""),
        "build_status": str(build["status"] or ""),
        "build_stage": str(build["stage"] or ""),
        "build_failure_reason_code": str(build["failure_reason_code"] or ""),
        "latest_failed_stage": (
            str(latest_failed_attempt["stage_key"] or "")
            if latest_failed_attempt is not None
            else ""
        ),
        "latest_failed_section": (
            str(latest_failed_attempt["section_key"] or "")
            if latest_failed_attempt is not None
            else ""
        ),
        "latest_failed_error_code": (
            str(latest_failed_attempt["error_code"] or "")
            if latest_failed_attempt is not None
            else ""
        ),
    }
    return material, _canonical_mapping_sha256(material)


def _prior_ge_lease_loss_requeues_with_fingerprint(
    connection: Any, *, job_id: str, fingerprint_sha256: str
) -> tuple[int, int]:
    matching = 0
    total = 0
    rows = connection.execute(
        "SELECT payload_json FROM job_events WHERE job_id=? ORDER BY sequence", (job_id,)
    ).fetchall()
    for row in rows:
        try:
            payload = json.loads(str(row["payload_json"] or "{}"))
        except json.JSONDecodeError:
            continue
        if (
            isinstance(payload, dict)
            and payload.get("schema") == "legalbot.ge-index-lease-loss-requeue-event.v1"
        ):
            total += 1
            if payload.get("failure_fingerprint_sha256") == fingerprint_sha256:
                matching += 1
    return matching, total


def resume_lease_lost_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    expected_build_id: str,
    expected_attempt_count: int,
    expected_audit_report_sha256: str,
    expected_checkpoint_reconciliation_sha256: str,
    workflow_seconds: int = 86_400,
    _ge_decision_id: str | None = None,
    _ge_decision_content_sha256: str | None = None,
) -> dict[str, Any]:
    """Requeue the same lease-lost generation after an exact-prefix repair."""

    observed_job = database.job(job_id)
    if observed_job is None:
        raise ValueError("lease-loss recovery job is absent")
    try:
        observed_request = json.loads(str(observed_job["request_json"] or "{}"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("lease-loss recovery request is invalid") from exc
    if isinstance(observed_request, dict) and _request_is_ge_successor(observed_request):
        if not _ge_decision_id or not _ge_decision_content_sha256:
            raise PermissionError("OWNER_DECISION_REQUIRED:use_dedicated_ge_index_recovery")
        _request, authorized_build_id = _verify_ge_recovery_authorization(
            settings,
            database,
            job_id=job_id,
            decision_id=_ge_decision_id,
            decision_content_sha256=_ge_decision_content_sha256,
        )
        if authorized_build_id != expected_build_id:
            raise RuntimeError("GE lease-loss recovery build binding changed")
    report = _verified_actual_incomplete_index_audit(
        settings,
        database,
        expected_build_id,
        expected_report_sha256=expected_audit_report_sha256,
    )
    checkpoint_reconciliation = _actual_checkpoint_reconciliation(
        report, expected_build_id=expected_build_id
    )
    expected_reconciliation_sha256 = _require_sha256(
        expected_checkpoint_reconciliation_sha256,
        label="expected checkpoint reconciliation SHA-256",
    )
    if checkpoint_reconciliation["reconciliation_sha256"] != expected_reconciliation_sha256:
        raise RuntimeError("recomputed checkpoint reconciliation differs from expected digest")
    checkpoint = report["checkpoint"]
    if not isinstance(checkpoint, dict):  # narrowed by _actual_checkpoint_reconciliation
        raise RuntimeError("lease-loss recovery checkpoint disappeared")
    _require_checkpoint_unchanged_since_audit(
        settings, build_id=expected_build_id, report=report
    )
    with database.transaction() as connection:
        job, queue_deadline, workflow_deadline, now = _require_requeue_admission_locked(
            database,
            connection,
            job_id,
            eligible_statuses=frozenset({JobStatus.FAILED}),
            workflow_seconds_override=workflow_seconds,
            allow_cancelled_fence=True,
        )
        actual_attempt_count = int(job["attempt_count"] or 0)
        if str(job["pinned_index_build_id"] or "") != expected_build_id:
            raise RuntimeError("lease-loss recovery pinned build changed")
        if (
            str(job["error_code"] or "") != "lease_lost"
            or str(job["terminal_reason_code"] or "") != "lease_lost"
        ):
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
        _require_checkpoint_unchanged_since_audit(
            settings, build_id=expected_build_id, report=report
        )
        failure_material, failure_fingerprint = _persisted_lease_loss_failure_fingerprint(
            connection,
            job=job,
            build=build,
            job_id=job_id,
            build_id=expected_build_id,
        )
        (
            prior_same_failure_requeues,
            prior_ge_lease_loss_requeues,
        ) = _prior_ge_lease_loss_requeues_with_fingerprint(
            connection,
            job_id=job_id,
            fingerprint_sha256=failure_fingerprint,
        )
        is_ge_recovery = isinstance(observed_request, dict) and _request_is_ge_successor(
            observed_request
        )
        if is_ge_recovery and (
            prior_same_failure_requeues >= 1 and actual_attempt_count >= 2
        ):
            raise RuntimeError("unchanged_ge_lease_loss_recovery_attempt_limit")
        if is_ge_recovery and actual_attempt_count >= 2 and prior_ge_lease_loss_requeues < 1:
            raise RuntimeError("ge_lease_loss_recovery_history_missing")
        if is_ge_recovery and actual_attempt_count >= 3:
            raise RuntimeError("ge_lease_loss_recovery_attempt_limit")
        if actual_attempt_count != expected_attempt_count:
            raise RuntimeError("lease-loss recovery attempt count changed")
        condition_payload = {
            "schema": "legalbot.index-lease-loss-recovery-condition.v2",
            "job_id": job_id,
            "build_id": expected_build_id,
            "attempt_count_before_requeue": actual_attempt_count,
            "audit_report_sha256": report["report_sha256"],
            "checkpoint_sha256": checkpoint["checkpoint_sha256"],
            "checkpoint_reconciliation_sha256": checkpoint_reconciliation[
                "reconciliation_sha256"
            ],
            "failure_fingerprint_sha256": failure_fingerprint,
            "workflow_seconds": workflow_seconds,
            "heartbeat_method": "critical_lease_first_bounded_sqlite_busy_retry.v1",
        }
        condition_identity = _canonical_mapping_sha256(condition_payload)
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
                "audit_report_sha256": report["report_sha256"],
                "embedding_checkpoint_sha256": checkpoint["checkpoint_sha256"],
                "checkpoint_reconciliation_sha256": checkpoint_reconciliation[
                    "reconciliation_sha256"
                ],
                "failure_fingerprint_sha256": failure_fingerprint,
                "attempt_count_before_requeue": actual_attempt_count,
                "automatic_third_claim": False,
            },
            event_payload={
                "schema": "legalbot.ge-index-lease-loss-requeue-event.v1",
                "failure_fingerprint_sha256": failure_fingerprint,
                "failure_material_sha256": _canonical_mapping_sha256(failure_material),
                "attempt_count_before_requeue": actual_attempt_count,
                "audit_report_sha256": report["report_sha256"],
                "checkpoint_reconciliation_sha256": checkpoint_reconciliation[
                    "reconciliation_sha256"
                ],
            }
            if is_ge_recovery
            else None,
        )
    return {
        "schema": "legalbot.index-lease-loss-requeue.v1",
        "job_id": job_id,
        "build_id": expected_build_id,
        "status": JobStatus.QUEUED,
        "attempt_count": actual_attempt_count,
        "queue_wait_deadline_at": queue_deadline,
        "workflow_deadline_at": workflow_deadline,
        "workflow_seconds": workflow_seconds,
        "recovery_condition_sha256": condition_identity,
        "audit_report_sha256": report["report_sha256"],
        "embedding_checkpoint_sha256": checkpoint["checkpoint_sha256"],
        "checkpoint_reconciliation_sha256": checkpoint_reconciliation[
            "reconciliation_sha256"
        ],
        "failure_fingerprint_sha256": failure_fingerprint,
        "queued_for_exact_second_attempt": True,
        "automatic_third_claim": False,
        "new_build_created": False,
        "active_written": False,
    }


def resume_ge_lease_lost_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    decision_id: str,
    decision_content_sha256: str,
    expected_build_id: str,
    expected_attempt_count: int,
    expected_audit_report_sha256: str,
    expected_checkpoint_reconciliation_sha256: str,
    workflow_seconds: int = 86_400,
) -> dict[str, Any]:
    """Requeue exact-prefix GE lease loss only after owner-decision replay."""

    result = resume_lease_lost_index_build(
        settings,
        database,
        job_id,
        expected_build_id=expected_build_id,
        expected_attempt_count=expected_attempt_count,
        expected_audit_report_sha256=expected_audit_report_sha256,
        expected_checkpoint_reconciliation_sha256=(
            expected_checkpoint_reconciliation_sha256
        ),
        workflow_seconds=workflow_seconds,
        _ge_decision_id=decision_id,
        _ge_decision_content_sha256=decision_content_sha256,
    )
    return {
        **result,
        "ge_index_build_owner_decision_id": decision_id,
        "ge_index_build_owner_decision_content_sha256": decision_content_sha256,
        "ge_authorization_replayed": True,
    }


def resume_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    _ge_decision_id: str | None = None,
    _ge_decision_content_sha256: str | None = None,
) -> dict[str, Any]:
    row = database.job(job_id)
    if row is None or str(row["job_type"]) != JobType.INDEX_BUILD:
        raise ValueError("resume-index-build requires a failed or interrupted index job")
    if row["lease_owner"] is not None or row["lease_expires_at"] is not None:
        raise RuntimeError("index-build job is still bound to a worker lease")
    if str(row["status"]) not in {JobStatus.FAILED, JobStatus.DLQ}:
        raise RuntimeError("job is not eligible for index-build resume")
    request = json.loads(str(row["request_json"] or "{}"))
    if _request_is_ge_successor(request):
        if not _ge_decision_id or not _ge_decision_content_sha256:
            raise PermissionError("OWNER_DECISION_REQUIRED:use_dedicated_ge_index_recovery")
        _request, authorized_build_id = _verify_ge_recovery_authorization(
            settings,
            database,
            job_id=job_id,
            decision_id=_ge_decision_id,
            decision_content_sha256=_ge_decision_content_sha256,
        )
        if authorized_build_id != str(request.get("build_id") or ""):
            raise RuntimeError("GE index resume build binding changed")
    build_id = str(request["build_id"])
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
    if build is None:
        raise ValueError("index build is not in the catalogue")
    repository = ImmutableLanceRepository(settings.index_dir)
    staging = repository.staging_path(build_id)
    report: dict[str, Any] | None = None
    if staging.is_dir():
        report = _verified_actual_incomplete_index_audit(settings, database, build_id)
        if report.get("checkpoint_reconciliation_required") is True:
            raise RuntimeError(
                "incomplete staging contains exact rows beyond its checkpoint; "
                "reconcile the ordered prefix before resume"
            )
        if report.get("resumable") is not True:
            raise RuntimeError("incomplete staging is not resumable from its exact checkpoint")
    if (
        str(build["status"]) == "failed"
        and str(build["failure_reason_code"] or "") == "stage_timeout"
    ):
        report = report or _verified_actual_incomplete_index_audit(
            settings, database, build_id
        )
        if report.get("embedding_complete") is True:
            return recover_index_embedding(
                settings,
                database,
                build_id,
                continue_build=True,
                expected_audit_report_sha256=str(report["report_sha256"]),
                _ge_decision_id=_ge_decision_id,
                _ge_decision_content_sha256=_ge_decision_content_sha256,
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


def resume_ge_successor_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    decision_id: str,
    decision_content_sha256: str,
) -> dict[str, Any]:
    """Resume the same GE generation after exact owner-decision replay."""

    result = resume_index_build(
        settings,
        database,
        job_id,
        _ge_decision_id=decision_id,
        _ge_decision_content_sha256=decision_content_sha256,
    )
    return {
        **result,
        "ge_index_build_owner_decision_id": decision_id,
        "ge_index_build_owner_decision_content_sha256": decision_content_sha256,
        "ge_authorization_replayed": True,
    }


def retry_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    new_build_id: str,
    _ge_original_decision_id: str | None = None,
    _ge_original_decision_content_sha256: str | None = None,
    _ge_new_decision_id: str | None = None,
    _ge_new_decision_content_sha256: str | None = None,
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
    is_ge_successor = _request_is_ge_successor(request)
    if is_ge_successor:
        if not _ge_original_decision_id or not _ge_original_decision_content_sha256:
            raise PermissionError("OWNER_DECISION_REQUIRED:use_dedicated_ge_index_recovery")
        _request, authorized_old_build_id = _verify_ge_recovery_authorization(
            settings,
            database,
            job_id=job_id,
            decision_id=_ge_original_decision_id,
            decision_content_sha256=_ge_original_decision_content_sha256,
        )
        if authorized_old_build_id != str(request.get("build_id") or ""):
            raise RuntimeError("GE index retry predecessor binding changed")
        if not _ge_new_decision_id or not _ge_new_decision_content_sha256:
            raise PermissionError("OWNER_DECISION_REQUIRED:new_ge_retry_build_decision_required")
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
        ge_index_build_owner_decision_id=(
            _ge_new_decision_id if is_ge_successor else None
        ),
        ge_index_build_owner_decision_content_sha256=(
            _ge_new_decision_content_sha256 if is_ge_successor else None
        ),
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


def retry_ge_successor_index_build(
    settings: Settings,
    database: Database,
    job_id: str,
    *,
    new_build_id: str,
    original_decision_id: str,
    original_decision_content_sha256: str,
    new_decision_id: str,
    new_decision_content_sha256: str,
) -> dict[str, Any]:
    """Create a new GE retry only when old and new exact decisions replay."""

    old_request = database.job(job_id)
    if old_request is None:  # pragma: no cover - retried function validates again
        raise ValueError("GE index retry job is absent")
    old_request_value = json.loads(str(old_request["request_json"] or "{}"))
    old_build_id = str(old_request_value.get("build_id") or "")
    result = retry_index_build(
        settings,
        database,
        job_id,
        new_build_id=new_build_id,
        _ge_original_decision_id=original_decision_id,
        _ge_original_decision_content_sha256=original_decision_content_sha256,
        _ge_new_decision_id=new_decision_id,
        _ge_new_decision_content_sha256=new_decision_content_sha256,
    )
    return {
        **result,
        "retried_from_build_id": old_build_id,
        "ge_original_owner_decision_id": original_decision_id,
        "ge_original_owner_decision_content_sha256": (
            original_decision_content_sha256
        ),
        "ge_new_owner_decision_id": new_decision_id,
        "ge_new_owner_decision_content_sha256": new_decision_content_sha256,
        "ge_authorization_replayed": True,
    }


def attest_allowed(status: str) -> bool:
    return status == "built_unscored"
