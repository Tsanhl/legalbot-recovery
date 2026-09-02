"""Durable staged candidate index-build. Promotion is a separate privileged action."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..assessment.guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    canonical_bundle_bytes,
)
from ..config import Settings
from ..db import Database, utc_iso
from ..ingestion.models import MaterialLane
from ..jobs import (
    CHUNKER_VERSION,
    INDEX_SCHEMA_VERSION,
    PARSER_VERSION,
    TERMINAL_STAGE_FAILED,
    TERMINAL_STAGE_TIMEOUT,
    deadline_after,
    index_build_idempotency_key,
    policy_for,
)
from ..observability.events import EventStore, record_index_stage_failure
from ..privacy import PRIVATE_QUESTION_SUMMARY
from ..quality.policy import POLICY_SHA256
from ..types import IndexBuildStage, JobStatus, JobType
from .ge_index_build_authorization import (
    VerifiedGEIndexBuildAuthorization,
    ge_index_build_decision_binding,
    load_verified_ge_index_build_authorization,
)
from .incomplete_index_audit import (
    GE_SELECTION_POLICY,
    SourceLaneBinding,
    parse_source_lane_bindings,
    source_lane_bindings_for_manifest,
)
from .lancedb import ImmutableLanceRepository
from .models import VECTOR_DIMENSIONS, IndexedChunk
from .source_manifest import (
    SCOPED_CORPUS_ID,
    SESSION_SCOPED_CORPUS_ID,
    build_approved_source_manifest,
    chunk_locator_allowed,
    source_version_ids,
    write_approved_source_manifest,
)
from .vector_carry_forward import (
    ChunkIdentity,
    ParentVectorBatchReader,
    VectorCarryForwardError,
    VerifiedParentVectorSource,
    build_vector_reuse_report,
    verify_parent_vector_source,
)

INDEX_BUILD_STAGES: tuple[str, ...] = (
    IndexBuildStage.SCANNING,
    IndexBuildStage.PARSING,
    IndexBuildStage.CHUNKING,
    IndexBuildStage.EMBEDDING,
    IndexBuildStage.BUILDING_LEXICAL,
    IndexBuildStage.BUILDING_VECTOR,
    IndexBuildStage.VALIDATING,
    IndexBuildStage.CANDIDATE,
)

_STAGE_PROGRESS: dict[str, float] = {
    IndexBuildStage.QUEUED: 0.0,
    IndexBuildStage.SCANNING: 0.08,
    IndexBuildStage.PARSING: 0.16,
    IndexBuildStage.CHUNKING: 0.24,
    IndexBuildStage.EMBEDDING: 0.48,
    IndexBuildStage.BUILDING_LEXICAL: 0.62,
    IndexBuildStage.BUILDING_VECTOR: 0.78,
    IndexBuildStage.VALIDATING: 0.90,
    IndexBuildStage.CANDIDATE: 1.0,
    IndexBuildStage.FAILED: 1.0,
}


class IndexBuildConflictError(RuntimeError):
    """A concurrent or identical in-flight build already exists for the idempotency key."""


class IndexBuildStageError(RuntimeError):
    def __init__(self, stage: str, reason_code: str, message: str) -> None:
        self.stage = stage
        self.reason_code = reason_code
        super().__init__(message)


def _ge_expansion_request_fields(
    authorization: VerifiedGEIndexBuildAuthorization,
) -> dict[str, Any]:
    binding = authorization.binding
    return {
        "ge_expansion_mode": binding.expansion_mode,
        "ge_predecessor_build_id": binding.predecessor_build_id,
        "ge_predecessor_index_build_record_sha256": (
            binding.predecessor_index_build_record_sha256
        ),
        "ge_predecessor_seal_sha256": binding.predecessor_seal_sha256,
        "ge_predecessor_build_manifest_sha256": (
            binding.predecessor_build_manifest_sha256
        ),
        "ge_predecessor_source_manifest_file_sha256": (
            binding.predecessor_source_manifest_file_sha256
        ),
        "ge_predecessor_source_manifest_sha256": (
            binding.predecessor_source_manifest_sha256
        ),
        "ge_predecessor_source_version_id_set_sha256": (
            binding.predecessor_source_version_id_set_sha256
        ),
        "ge_predecessor_member_set_sha256": binding.predecessor_member_set_sha256,
        "ge_predecessor_member_sequence_sha256": (
            binding.predecessor_member_sequence_sha256
        ),
        "ge_predecessor_source_count": binding.predecessor_source_count,
        "ge_predecessor_chunk_count": binding.predecessor_chunk_count,
        "ge_added_source_version_id_set_sha256": (
            binding.added_source_version_id_set_sha256
        ),
        "ge_added_member_set_sha256": binding.added_member_set_sha256,
        "ge_added_source_count": binding.added_source_count,
        "ge_added_chunk_count": binding.added_chunk_count,
        "ge_successor_member_set_sha256": binding.successor_member_set_sha256,
        "ge_successor_member_sequence_sha256": (
            binding.successor_member_sequence_sha256
        ),
        "ge_successor_source_count": binding.successor_source_count,
        "ge_successor_chunk_count": binding.successor_chunk_count,
        "ge_preservation_proof_sha256": binding.preservation_proof_sha256,
    }


def _release_pointer_snapshot(settings: Settings) -> dict[str, Any]:
    """Return path-free ACTIVE/PREVIOUS identities without following links."""

    pointers: dict[str, dict[str, Any]] = {}
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    for name in ("ACTIVE.json", "PREVIOUS.json"):
        path = settings.index_dir / name
        try:
            descriptor = os.open(path, os.O_RDONLY | no_follow)
        except FileNotFoundError:
            pointers[name] = {
                "present": False,
                "sha256": None,
                "size": 0,
                "mode": None,
            }
            continue
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) & 0o022
                or before.st_size > 1024 * 1024
            ):
                raise RuntimeError("index release pointer is unsafe")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                block = os.read(descriptor, min(remaining, 64 * 1024))
                if not block:
                    raise RuntimeError("index release pointer was truncated")
                digest.update(block)
                remaining -= len(block)
            after = os.fstat(descriptor)
            lexical = os.stat(path, follow_symlinks=False)
            def identity(item: os.stat_result) -> tuple[int, ...]:
                return (
                    item.st_dev,
                    item.st_ino,
                    item.st_uid,
                    item.st_mode,
                    item.st_size,
                    item.st_mtime_ns,
                    item.st_ctime_ns,
                )
            if identity(before) != identity(after) or identity(before) != identity(lexical):
                raise RuntimeError("index release pointer changed during inspection")
            pointers[name] = {
                "present": True,
                "sha256": digest.hexdigest(),
                "size": before.st_size,
                "mode": stat.S_IMODE(before.st_mode),
            }
        finally:
            os.close(descriptor)
    return {
        "schema": "legalbot.index-release-pointer-snapshot.v1",
        "pointers": pointers,
    }


@contextmanager
def _index_build_execution_lock(settings: Settings, build_id: str) -> Iterator[None]:
    """Serialize every process that can mutate one resumable build directory."""

    repository = ImmutableLanceRepository(settings.index_dir)
    repository._validate_build_id(build_id)
    lock_path = repository.builds / f".{build_id}.worker.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RuntimeError("index_build_execution_lock_unavailable") from exc
    try:
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_nlink != 1
            or identity.st_uid != os.getuid()
            or stat.S_IMODE(identity.st_mode) & 0o077
        ):
            raise RuntimeError("index_build_execution_lock_invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        current = os.lstat(lock_path)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            raise RuntimeError("index_build_execution_lock_replaced")
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@dataclass(slots=True)
class IndexBuildContext:
    settings: Settings
    database: Database
    job_id: str
    build_id: str
    corpus_id: str
    manifest: dict[str, Any]
    source_ids: tuple[str, ...]
    embedding_model: str
    reranker_model: str
    build_dir: Path
    timings: dict[str, dict[str, Any]]
    counts: dict[str, Any]
    reuse_vectors_from_build_id: str | None = None
    parent_vector_seal_sha256: str | None = None
    parent_vector_source: VerifiedParentVectorSource | None = None
    fail_at_stage: str | None = None
    skip_embedding: bool = False
    clock: Callable[[], float] | None = None
    now: Callable[[], datetime] | None = None
    expected_lease_owner: str | None = None
    stage_deadline_at: str | None = None
    release_pointer_snapshot: dict[str, Any] | None = None


def _write_or_verify_index_build_boundary(staging: Path, ctx: IndexBuildContext) -> None:
    """Create the immutable lane boundary before any derived index bytes are written."""

    is_ge = ctx.manifest.get("selection_policy") == GE_SELECTION_POLICY
    payload = {
        "schema": "legalbot.index-build-boundary.v1",
        "build_id": ctx.build_id,
        "source_manifest_sha256": str(ctx.manifest.get("manifest_sha256") or ""),
        "selection_policy": str(ctx.manifest.get("selection_policy") or ""),
        "ge_held_scope": is_ge,
        "ge_source_scope_content_sha256": (
            ctx.manifest.get("ge_source_scope_content_sha256") if is_ge else None
        ),
        "successor_must_remain_non_active": (
            ctx.manifest.get("successor_must_remain_non_active") is True
        ),
        "active_or_previous_write_authorized": (
            ctx.manifest.get("active_or_previous_write_authorized") is True
        ),
        "promotion_authorized": ctx.manifest.get("promotion_authorized") is True,
    }
    expected = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    path = staging / "build-boundary.json"
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "index_build_boundary_changed",
                "incomplete staging build boundary differs from the frozen request",
            )
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(expected)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    directory_fd = os.open(staging, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def enqueue_index_build(
    settings: Settings,
    database: Database,
    *,
    corpus_id: str,
    build_id: str | None = None,
    max_chunks: int | None = None,
    preferred_small_first: bool = False,
    fail_at_stage: str | None = None,
    skip_embedding: bool = False,
    reuse_vectors_from_build_id: str | None = None,
    retry_lineage_sha256: str | None = None,
    ge_index_build_owner_decision_id: str | None = None,
    ge_index_build_owner_decision_content_sha256: str | None = None,
) -> dict[str, Any]:
    """Insert a durable index_build job. Queue carries IDs only, never document bytes."""

    from .service import (
        TEST_EMBEDDING_MODEL,
        TEST_RERANKER_MODEL,
        _production_embedding_identity,
        _production_reranker_identity,
        _validate_build_id,
    )

    settings.ensure_runtime_dirs()
    build_id = build_id or f"idx-{uuid4().hex[:16]}"
    _validate_build_id(build_id)
    from .diagnostic_slice import (
        is_current_law_full_corpus,
        is_diagnostic_slice_build,
        refuse_diagnostic_slice_for_production,
    )

    if is_current_law_full_corpus(corpus_id):
        refuse_diagnostic_slice_for_production(build_id, purpose="full candidate")
    if is_diagnostic_slice_build(build_id):
        existing_slice = database.fetchone(
            "SELECT id, status FROM index_builds WHERE id=? LIMIT 1",
            (build_id,),
        )
        if existing_slice is not None:
            raise IndexBuildConflictError(
                f"index-build {existing_slice['id']} is already {existing_slice['status']} "
                "for this diagnostic slice"
            )
    manifest = build_approved_source_manifest(
        database,
        settings,
        corpus_id=corpus_id,
        max_chunks=max_chunks,
        preferred_small_first=preferred_small_first,
    )
    if not manifest["sources"]:
        raise ValueError("approved legal-source manifest is empty")
    lane_bindings = source_lane_bindings_for_manifest(manifest)
    is_ge_successor = manifest.get("selection_policy") == GE_SELECTION_POLICY
    if is_ge_successor and skip_embedding:
        raise ValueError("ge_successor_skip_embedding_forbidden")
    if is_ge_successor and fail_at_stage is not None:
        raise ValueError("ge_successor_fault_injection_forbidden")
    build_authorization: VerifiedGEIndexBuildAuthorization | None = None
    if is_ge_successor:
        if (
            not ge_index_build_owner_decision_id
            or not ge_index_build_owner_decision_content_sha256
        ):
            raise ValueError("ge_successor_index_build_authorization_required")
        build_authorization = load_verified_ge_index_build_authorization(
            settings,
            database,
            manifest=manifest,
            build_id=build_id,
            decision_id=ge_index_build_owner_decision_id,
            decision_content_sha256=ge_index_build_owner_decision_content_sha256,
        )
    elif (
        ge_index_build_owner_decision_id is not None
        or ge_index_build_owner_decision_content_sha256 is not None
    ):
        raise ValueError("ge_successor_index_build_authorization_for_non_ge_manifest")
    allowed_catalogue_lanes = sorted({binding.catalogue_lane for binding in lane_bindings})
    lane_binding_json = [binding.as_dict() for binding in lane_bindings]
    embedding_model = (
        TEST_EMBEDDING_MODEL if settings.test_mode else _production_embedding_identity(settings)
    )
    reranker_model = (
        TEST_RERANKER_MODEL if settings.test_mode else _production_reranker_identity(settings)
    )
    if reuse_vectors_from_build_id is not None and skip_embedding:
        raise ValueError("vector reuse cannot be combined with skip-embedding")
    if (
        is_ge_successor
        and reuse_vectors_from_build_id is not None
        and build_authorization is not None
        and reuse_vectors_from_build_id
        != build_authorization.binding.predecessor_build_id
    ):
        raise ValueError("ge_successor_vector_parent_must_equal_predecessor")
    parent_vector_source = None
    if reuse_vectors_from_build_id is not None:
        parent_vector_source = verify_parent_vector_source(
            index_root=settings.index_dir,
            parent_build_id=reuse_vectors_from_build_id,
            child_build_id=build_id,
            embedding_model_revision=embedding_model,
            vector_dimensions=VECTOR_DIMENSIONS,
            vector_dtype="float16" if "dtype=float16" in embedding_model else "test",
            parser_identity=PARSER_VERSION,
            chunker_identity=CHUNKER_VERSION,
            index_schema_version=INDEX_SCHEMA_VERSION,
        )
        if (
            is_ge_successor
            and build_authorization is not None
            and parent_vector_source.identity.seal_sha256
            != build_authorization.binding.predecessor_seal_sha256
        ):
            raise ValueError("ge_successor_vector_parent_seal_differed")
    key = index_build_idempotency_key(
        corpus_id=corpus_id,
        approved_source_manifest_hash=str(manifest["manifest_sha256"]),
        parser_version=PARSER_VERSION,
        chunker_version=CHUNKER_VERSION,
        embedding_model_version=embedding_model,
        index_schema_version=INDEX_SCHEMA_VERSION,
        parent_vector_build_id=(
            parent_vector_source.identity.build_id if parent_vector_source is not None else None
        ),
        parent_vector_seal_sha256=(
            parent_vector_source.identity.seal_sha256 if parent_vector_source is not None else None
        ),
    )
    key = f"{key}|{POLICY_SHA256}|{OWNER_ASSESSMENT_BUNDLE.sha256}"
    if is_ge_successor:
        if build_authorization is None:  # pragma: no cover - guarded above
            raise RuntimeError("GE successor authorization disappeared")
        key = (
            f"{key}|ge-successor-index-build:{build_authorization.decision_id}:"
            f"{build_authorization.resolution_content_sha256}:"
            f"{build_authorization.binding.intake_chain_sha256}:"
            f"{build_authorization.binding.preservation_proof_sha256}"
        )
    if retry_lineage_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", retry_lineage_sha256):
            raise ValueError("retry lineage SHA must be a lowercase SHA-256")
        key = f"{key}|retry:{retry_lineage_sha256}"
    existing = database.job_by_idempotency_key(key)
    if existing is not None:
        status = str(existing["status"])
        if status in {"queued", "running"}:
            EventStore.from_settings(settings, database).emit(
                event_type="operational_failure",
                component="index_build",
                stage="queued",
                failure_code="idempotency_conflict",
                source_id=key,
                job_id=str(existing["id"]),
                build_id=str(existing["pinned_index_build_id"] or ""),
                user_or_owner_safe="An identical in-flight index-build already exists.",
                retryable=False,
                blocking=True,
            )
            raise IndexBuildConflictError(
                f"index-build {existing['id']} is already {status} for this idempotency key"
            )
        raise IndexBuildConflictError(
            f"index-build {existing['id']} already {status} for this frozen identity; "
            "use resume-index-build or retry-index-build"
        )
    concurrent = database.fetchone(
        """
        SELECT id, status FROM index_builds
        WHERE idempotency_key=? AND status IN ('queued','building','candidate')
        LIMIT 1
        """,
        (key,),
    )
    if concurrent is not None and str(concurrent["status"]) != "candidate":
        raise IndexBuildConflictError(
            f"index-build {concurrent['id']} is already {concurrent['status']} for this key"
        )
    job_id = f"index-{build_id}"
    policy = policy_for(JobType.INDEX_BUILD)
    expected_path = settings.index_dir / "builds" / build_id
    from .service import _relative_path

    relative_path = _relative_path(settings, expected_path)
    release_pointer_snapshot = _release_pointer_snapshot(settings)
    try:
        database.create_job(
            job_id=job_id,
            encrypted_question=b"",
            question_summary=PRIVATE_QUESTION_SUMMARY,
            request={
                "job_type": JobType.INDEX_BUILD,
                "build_id": build_id,
                "corpus_id": corpus_id,
                "approved_source_manifest_hash": manifest["manifest_sha256"],
                "parser_version": PARSER_VERSION,
                "chunker_version": CHUNKER_VERSION,
                "index_schema_version": INDEX_SCHEMA_VERSION,
                "embedding_model_version": embedding_model,
                "rerank_version": reranker_model,
                "source_version_ids": list(source_version_ids(manifest)),
                "selection_policy": manifest.get("selection_policy"),
                "source_lane_bindings": lane_binding_json,
                "allowed_catalogue_lanes": allowed_catalogue_lanes,
                "max_chunks": max_chunks,
                "preferred_small_first": preferred_small_first,
                **(
                    {"fail_at_stage": fail_at_stage}
                    if not is_ge_successor
                    else {}
                ),
                "skip_embedding": skip_embedding,
                "reuse_vectors_from_build_id": (
                    parent_vector_source.identity.build_id
                    if parent_vector_source is not None
                    else None
                ),
                "parent_vector_seal_sha256": (
                    parent_vector_source.identity.seal_sha256
                    if parent_vector_source is not None
                    else None
                ),
                "authority_lane_only": manifest.get("authority_lane_only") is True,
                "approved_legal_source_lanes_only": (
                    manifest.get("approved_legal_source_lanes_only") is True
                ),
                "successor_must_remain_non_active": (
                    manifest.get("successor_must_remain_non_active") is True
                ),
                "ge_source_scope_content_sha256": manifest.get(
                    "ge_source_scope_content_sha256"
                ),
                "ge_source_scope_owner_approval_digest": manifest.get(
                    "ge_source_scope_owner_approval_digest"
                ),
                "ge_index_build_owner_decision_id": (
                    build_authorization.decision_id
                    if build_authorization is not None
                    else None
                ),
                "ge_index_build_owner_decision_request_sha256": (
                    build_authorization.request_content_sha256
                    if build_authorization is not None
                    else None
                ),
                "ge_index_build_owner_decision_content_sha256": (
                    build_authorization.resolution_content_sha256
                    if build_authorization is not None
                    else None
                ),
                "ge_source_intake_chain_sha256": (
                    build_authorization.binding.intake_chain_sha256
                    if build_authorization is not None
                    else None
                ),
                "ge_source_lane_binding_sha256": (
                    build_authorization.binding.source_lane_binding_sha256
                    if build_authorization is not None
                    else None
                ),
                **(
                    _ge_expansion_request_fields(build_authorization)
                    if build_authorization is not None
                    else {}
                ),
                "policy_sha256": POLICY_SHA256,
                "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
                "retry_lineage_sha256": retry_lineage_sha256,
                "release_pointer_snapshot_at_enqueue": release_pointer_snapshot,
            },
            route="control_plane",
            idempotency_key=key,
            pinned_index_build_id=build_id,
            job_type=JobType.INDEX_BUILD,
            queue_wait_deadline_at=deadline_after(policy.queue_wait_seconds),
            workflow_deadline_at=deadline_after(policy.workflow_seconds),
            index_build_admission={
                "path": relative_path,
                "embedding_model": embedding_model,
                "reranker_model": reranker_model,
                "corpus_id": corpus_id,
                "scoped_corpus_id": corpus_id,
                "source_manifest_hash": str(manifest["manifest_sha256"]),
                "parser_version": PARSER_VERSION,
                "chunker_version": CHUNKER_VERSION,
                "index_schema_version": INDEX_SCHEMA_VERSION,
                "embedding_model_version": embedding_model,
                "rerank_version": reranker_model,
                "policy_sha256": POLICY_SHA256,
                "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
            },
        )
    except sqlite3.IntegrityError as exc:
        raise IndexBuildConflictError(f"index build id already exists: {build_id}") from exc
    dest = settings.data_dir / "review_queue" / f"approved-source-manifest-{corpus_id}.json"
    write_approved_source_manifest(dest, manifest)
    return {
        "job_id": job_id,
        "build_id": build_id,
        "status": "queued",
        "idempotency_key": key,
        "corpus_id": corpus_id,
        "source_manifest_hash": manifest["manifest_sha256"],
        "source_count": manifest["source_count"],
        "chunk_count": manifest["chunk_count"],
        "manifest_path": str(dest.relative_to(settings.project_root)),
        "reused": False,
        "reuse_vectors_from_build_id": (
            parent_vector_source.identity.build_id if parent_vector_source is not None else None
        ),
        "parent_vector_seal_sha256": (
            parent_vector_source.identity.seal_sha256 if parent_vector_source is not None else None
        ),
        "authority_lane_only": manifest.get("authority_lane_only") is True,
        "approved_legal_source_lanes_only": (
            manifest.get("approved_legal_source_lanes_only") is True
        ),
        "allowed_catalogue_lanes": allowed_catalogue_lanes,
        "successor_must_remain_non_active": (
            manifest.get("successor_must_remain_non_active") is True
        ),
        "ge_index_build_owner_decision_id": (
            build_authorization.decision_id if build_authorization is not None else None
        ),
        "ge_index_build_owner_decision_content_sha256": (
            build_authorization.resolution_content_sha256
            if build_authorization is not None
            else None
        ),
        "ge_source_intake_chain_sha256": (
            build_authorization.binding.intake_chain_sha256
            if build_authorization is not None
            else None
        ),
    }


def _require_enqueued_source_manifest_unchanged(
    ctx: IndexBuildContext,
    request: dict[str, Any],
) -> None:
    """Fail before scanning when catalogue changes alter frozen build membership."""

    expected_sha256 = str(request.get("approved_source_manifest_hash") or "")
    expected_source_ids = request.get("source_version_ids")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise IndexBuildStageError(
            IndexBuildStage.QUEUED,
            "source_manifest_binding_invalid",
            "queued index build has no valid frozen source-manifest digest",
        )
    if (
        not isinstance(expected_source_ids, list)
        or any(not isinstance(value, str) or not value for value in expected_source_ids)
        or len(set(expected_source_ids)) != len(expected_source_ids)
    ):
        raise IndexBuildStageError(
            IndexBuildStage.QUEUED,
            "source_manifest_binding_invalid",
            "queued index build has no valid frozen source-version identity list",
        )
    actual_sha256 = str(ctx.manifest.get("manifest_sha256") or "")
    actual_source_ids = list(source_version_ids(ctx.manifest))
    if actual_sha256 != expected_sha256 or actual_source_ids != expected_source_ids:
        raise IndexBuildStageError(
            IndexBuildStage.QUEUED,
            "source_manifest_changed_after_enqueue",
            "approved source manifest changed after index-build admission",
        )
    actual_bindings = source_lane_bindings_for_manifest(ctx.manifest)
    requested_bindings_raw = request.get("source_lane_bindings")
    is_ge_successor = ctx.manifest.get("selection_policy") == GE_SELECTION_POLICY
    if requested_bindings_raw is None and not is_ge_successor:
        # Preserve resumability for authority-only jobs admitted before the
        # explicit lane-binding field was introduced.
        requested_bindings = actual_bindings
    else:
        try:
            requested_bindings = parse_source_lane_bindings(requested_bindings_raw)
        except ValueError as exc:
            raise IndexBuildStageError(
                IndexBuildStage.QUEUED,
                "source_lane_binding_invalid",
                "queued index build has no valid frozen source-lane bindings",
            ) from exc
    requested_allowed_lanes = request.get("allowed_catalogue_lanes")
    actual_allowed_lanes = sorted({binding.catalogue_lane for binding in actual_bindings})
    if requested_allowed_lanes is None and not is_ge_successor:
        requested_allowed_lanes = actual_allowed_lanes
    requested_authority_only = request.get("authority_lane_only")
    requested_approved_legal_only = request.get("approved_legal_source_lanes_only")
    requested_non_active = request.get("successor_must_remain_non_active")
    if not is_ge_successor:
        if requested_authority_only is None:
            requested_authority_only = ctx.manifest.get("authority_lane_only") is True
        if requested_approved_legal_only is None:
            requested_approved_legal_only = (
                ctx.manifest.get("approved_legal_source_lanes_only") is True
            )
        if requested_non_active is None:
            requested_non_active = (
                ctx.manifest.get("successor_must_remain_non_active") is True
            )
    if (
        [binding.as_dict() for binding in requested_bindings]
        != [binding.as_dict() for binding in actual_bindings]
        or requested_allowed_lanes != actual_allowed_lanes
        or requested_authority_only
        is not (ctx.manifest.get("authority_lane_only") is True)
        or requested_approved_legal_only
        is not (ctx.manifest.get("approved_legal_source_lanes_only") is True)
        or requested_non_active
        is not (ctx.manifest.get("successor_must_remain_non_active") is True)
    ):
        raise IndexBuildStageError(
            IndexBuildStage.QUEUED,
            "source_lane_binding_changed_after_enqueue",
            "approved source lane bindings changed after index-build admission",
        )
    if is_ge_successor:
        if "fail_at_stage" in request:
            raise IndexBuildStageError(
                IndexBuildStage.QUEUED,
                "ge_successor_fault_injection_forbidden",
                "GE successor requests cannot carry test-only stage fault injection",
            )
        if bool(request.get("skip_embedding")):
            raise IndexBuildStageError(
                IndexBuildStage.QUEUED,
                "ge_successor_skip_embedding_forbidden",
                "GE successor must build and seal its exact held vector index",
            )
        decision_id = str(request.get("ge_index_build_owner_decision_id") or "")
        decision_content_sha256 = str(
            request.get("ge_index_build_owner_decision_content_sha256") or ""
        )
        try:
            authorization = load_verified_ge_index_build_authorization(
                ctx.settings,
                ctx.database,
                manifest=ctx.manifest,
                build_id=ctx.build_id,
                decision_id=decision_id,
                decision_content_sha256=decision_content_sha256,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            raise IndexBuildStageError(
                IndexBuildStage.QUEUED,
                "ge_successor_index_build_authorization_invalid",
                "GE successor build is not bound to its exact owner gate and source scope",
            ) from exc
        expected_expansion_fields = _ge_expansion_request_fields(authorization)
        requested_vector_parent = request.get("reuse_vectors_from_build_id")
        requested_parent_seal = request.get("parent_vector_seal_sha256")
        if (
            request.get("selection_policy") != GE_SELECTION_POLICY
            or request.get("ge_source_scope_content_sha256")
            != authorization.binding.source_scope_content_sha256
            or request.get("ge_source_scope_owner_approval_digest")
            != authorization.binding.source_scope_owner_approval_sha256
            or request.get("approved_source_manifest_hash")
            != authorization.binding.source_manifest_sha256
            or request.get("ge_index_build_owner_decision_request_sha256")
            != authorization.request_content_sha256
            or request.get("ge_source_intake_chain_sha256")
            != authorization.binding.intake_chain_sha256
            or request.get("ge_source_lane_binding_sha256")
            != authorization.binding.source_lane_binding_sha256
            or any(
                request.get(field) != value
                for field, value in expected_expansion_fields.items()
            )
            or requested_vector_parent
            not in {None, authorization.binding.predecessor_build_id}
            or (
                requested_vector_parent is not None
                and requested_parent_seal
                != authorization.binding.predecessor_seal_sha256
            )
        ):
            raise IndexBuildStageError(
                IndexBuildStage.QUEUED,
                "ge_successor_index_build_authorization_invalid",
                "GE successor owner decision changed after index-build admission",
            )
    elif any(
        request.get(field) not in {None, ""}
        for field in (
            "ge_index_build_owner_decision_id",
            "ge_index_build_owner_decision_request_sha256",
            "ge_index_build_owner_decision_content_sha256",
            "ge_source_intake_chain_sha256",
            "ge_source_lane_binding_sha256",
            "ge_successor_index_build_authorization_digest",
            "ge_expansion_mode",
            "ge_predecessor_build_id",
            "ge_predecessor_index_build_record_sha256",
            "ge_predecessor_seal_sha256",
            "ge_predecessor_build_manifest_sha256",
            "ge_predecessor_source_manifest_file_sha256",
            "ge_predecessor_source_manifest_sha256",
            "ge_predecessor_source_version_id_set_sha256",
            "ge_predecessor_member_set_sha256",
            "ge_predecessor_member_sequence_sha256",
            "ge_predecessor_source_count",
            "ge_predecessor_chunk_count",
            "ge_added_source_version_id_set_sha256",
            "ge_added_member_set_sha256",
            "ge_added_source_count",
            "ge_added_chunk_count",
            "ge_successor_member_set_sha256",
            "ge_successor_member_sequence_sha256",
            "ge_successor_source_count",
            "ge_successor_chunk_count",
            "ge_preservation_proof_sha256",
        )
    ):
        raise IndexBuildStageError(
            IndexBuildStage.QUEUED,
            "ge_successor_index_build_authorization_invalid",
            "GE successor authorization cannot be applied to an ordinary authority build",
        )
    expected_pointer_snapshot = request.get("release_pointer_snapshot_at_enqueue")
    if expected_pointer_snapshot is not None and (
        not isinstance(expected_pointer_snapshot, dict)
        or expected_pointer_snapshot.get("schema")
        != "legalbot.index-release-pointer-snapshot.v1"
        or expected_pointer_snapshot != _release_pointer_snapshot(ctx.settings)
    ):
        raise IndexBuildStageError(
            IndexBuildStage.QUEUED,
            "release_pointer_state_changed_after_enqueue",
            "ACTIVE/PREVIOUS pointer state changed after index-build admission",
        )


def _integrity_source_lane_claims(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return truthful, reproducible lane claims for the sealed evaluation."""

    bindings = source_lane_bindings_for_manifest(manifest)
    catalogue_counts: dict[str, int] = {}
    scope_counts: dict[str, int] = {}
    material_counts: dict[str, int] = {}
    for binding in bindings:
        catalogue_counts[binding.catalogue_lane] = (
            catalogue_counts.get(binding.catalogue_lane, 0) + 1
        )
        scope_counts[binding.scope_lane] = scope_counts.get(binding.scope_lane, 0) + 1
        material_counts[binding.material_lane] = material_counts.get(binding.material_lane, 0) + 1
    return {
        "authority_lane_only": manifest.get("authority_lane_only") is True,
        "approved_legal_source_lanes_only": (
            manifest.get("approved_legal_source_lanes_only") is True
        ),
        "allowed_catalogue_lanes": sorted(catalogue_counts),
        "catalogue_source_counts": dict(sorted(catalogue_counts.items())),
        "scope_source_counts": dict(sorted(scope_counts.items())),
        "material_source_counts": dict(sorted(material_counts.items())),
        "source_lane_bindings": [binding.as_dict() for binding in bindings],
    }


class IndexBuildRunner:
    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database
        self.events = EventStore.from_settings(settings, database)

    async def run(self, job_id: str, *, raise_on_error: bool = True) -> dict[str, Any]:
        del raise_on_error
        return self.run_sync(job_id)

    def run_sync(
        self,
        job_id: str,
        *,
        clock: Callable[[], float] | None = None,
        now: Callable[[], datetime] | None = None,
        expected_lease_owner: str | None = None,
    ) -> dict[str, Any]:
        row = self.database.job(job_id)
        if row is None:
            raise RuntimeError(f"index-build job missing: {job_id}")
        if expected_lease_owner is None and not self.settings.test_mode:
            raise RuntimeError(
                "production index execution requires the dedicated worker's exact lease"
            )
        try:
            request = json.loads(str(row["request_json"]))
            build_id = str(request["build_id"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError("index_build_request_invalid") from exc
        with _index_build_execution_lock(self.settings, build_id):
            if expected_lease_owner is not None and not self.database.job_lease_is_current(
                job_id, expected_lease_owner
            ):
                raise IndexBuildStageError(
                    str(row["stage"] or IndexBuildStage.QUEUED),
                    "lease_lost",
                    "index-build lease ownership changed before execution",
                )
            return self._run_sync_locked(
                job_id,
                clock=clock,
                now=now,
                expected_lease_owner=expected_lease_owner,
            )

    def _run_sync_locked(
        self,
        job_id: str,
        *,
        clock: Callable[[], float] | None = None,
        now: Callable[[], datetime] | None = None,
        expected_lease_owner: str | None = None,
    ) -> dict[str, Any]:
        row = self.database.job(job_id)
        if row is None:
            raise RuntimeError(f"index-build job missing: {job_id}")
        leased_execution = bool(row["lease_owner"])
        if not leased_execution:
            self.database.begin_unleased_index_job_attempt(job_id)
            row = self.database.job(job_id)
            if row is None:  # pragma: no cover - guarded by the transactional begin
                raise RuntimeError(f"index-build job missing after attempt start: {job_id}")
        request = json.loads(row["request_json"])
        build_id = str(request["build_id"])
        corpus_id = str(request["corpus_id"])
        fail_at_stage = request.get("fail_at_stage")
        skip_embedding = bool(request.get("skip_embedding"))
        reuse_vectors_from_build_id = (
            str(request["reuse_vectors_from_build_id"])
            if request.get("reuse_vectors_from_build_id")
            else None
        )
        expected_parent_seal_sha256 = (
            str(request["parent_vector_seal_sha256"])
            if request.get("parent_vector_seal_sha256")
            else None
        )
        max_chunks = request.get("max_chunks")
        preferred_small_first = bool(request.get("preferred_small_first"))
        manifest = build_approved_source_manifest(
            self.database,
            self.settings,
            corpus_id=corpus_id,
            max_chunks=max_chunks,
            preferred_small_first=preferred_small_first,
        )
        from .service import (
            TEST_EMBEDDING_MODEL,
            TEST_RERANKER_MODEL,
            _production_embedding_identity,
            _production_reranker_identity,
        )

        embedding_model = (
            TEST_EMBEDDING_MODEL
            if self.settings.test_mode
            else _production_embedding_identity(self.settings)
        )
        reranker_model = (
            TEST_RERANKER_MODEL
            if self.settings.test_mode
            else _production_reranker_identity(self.settings)
        )
        build_row = self.database.fetchone(
            "SELECT counts_json, stage_timings_json FROM index_builds WHERE id=?",
            (build_id,),
        )
        restored_counts: dict[str, Any] = {
            "sources": int(manifest["source_count"]),
            "chunks_expected": int(manifest["chunk_count"]),
        }
        restored_timings: dict[str, dict[str, Any]] = {}
        if build_row is not None:
            with suppress(TypeError, json.JSONDecodeError):
                restored_counts.update(json.loads(build_row["counts_json"] or "{}"))
            with suppress(TypeError, json.JSONDecodeError):
                restored_timings.update(json.loads(build_row["stage_timings_json"] or "{}"))
        ctx = IndexBuildContext(
            settings=self.settings,
            database=self.database,
            job_id=job_id,
            build_id=build_id,
            corpus_id=corpus_id,
            manifest=manifest,
            source_ids=source_version_ids(manifest),
            embedding_model=embedding_model,
            reranker_model=reranker_model,
            build_dir=self.settings.index_dir / "builds" / build_id,
            timings=restored_timings,
            counts=restored_counts,
            reuse_vectors_from_build_id=reuse_vectors_from_build_id,
            parent_vector_seal_sha256=expected_parent_seal_sha256,
            parent_vector_source=None,
            fail_at_stage=str(fail_at_stage) if fail_at_stage else None,
            skip_embedding=skip_embedding,
            clock=clock,
            now=now,
            expected_lease_owner=expected_lease_owner,
            release_pointer_snapshot=(
                request.get("release_pointer_snapshot_at_enqueue")
                if isinstance(request.get("release_pointer_snapshot_at_enqueue"), dict)
                else None
            ),
        )
        try:
            _require_enqueued_source_manifest_unchanged(ctx, request)
            _require_index_lease_current(ctx, stage=IndexBuildStage.QUEUED)
            _verify_parent_vector_binding(ctx)
            _run_stage(ctx, IndexBuildStage.SCANNING, _stage_scanning)
            _run_stage(ctx, IndexBuildStage.PARSING, _stage_parsing)
            _run_stage(ctx, IndexBuildStage.CHUNKING, _stage_chunking)
            _run_stage(ctx, IndexBuildStage.EMBEDDING, _stage_embedding)
            _run_stage(ctx, IndexBuildStage.BUILDING_LEXICAL, _stage_lexical)
            _run_stage(ctx, IndexBuildStage.BUILDING_VECTOR, _stage_vector)
            _run_stage(ctx, IndexBuildStage.VALIDATING, _stage_validating)
            final_status = self._mark_candidate(ctx)
            return {
                "build_id": build_id,
                "job_id": job_id,
                "status": final_status,
                "corpus_id": corpus_id,
                "counts": ctx.counts,
                "timings": ctx.timings,
            }
        except Exception as exc:
            reason = getattr(exc, "reason_code", TERMINAL_STAGE_FAILED)
            stage = getattr(exc, "stage", str(row["stage"]))
            if reason != "lease_lost":
                self._mark_failed(ctx, stage, reason, exc)
            if not leased_execution:
                self.database.record_unleased_index_job_failure(job_id, error_code=str(reason))
            raise

    def _mark_candidate(self, ctx: IndexBuildContext) -> str:
        omitted = list(ctx.manifest.get("omitted_required_families") or [])
        if omitted:
            raise IndexBuildStageError(
                IndexBuildStage.VALIDATING,
                "required_source_family_truncated",
                "required source family omitted; cannot become CANDIDATE",
            )
        seal_hash = ctx.counts.get("candidate_manifest_hash")
        benchmark = ctx.counts.get("benchmark") or {}
        must_remain_non_active = ctx.manifest.get("successor_must_remain_non_active") is True
        is_candidate = (
            not must_remain_non_active
            and benchmark.get("passed") is True
            and benchmark.get("promotion_eligible") is True
        )
        status = "candidate" if is_candidate else "built_unscored"
        stage = IndexBuildStage.CANDIDATE if is_candidate else IndexBuildStage.BUILT_UNSCORED
        if must_remain_non_active:
            ctx.counts["answer_release_eligible"] = False
            ctx.counts["successor_must_remain_non_active"] = True
            message = (
                "Successor sealed as non-ACTIVE held evidence; answer release, "
                "promotion and later-phase gates remain closed."
            )
        elif is_candidate:
            message = (
                "Candidate sealed. ACTIVE.json was not written. Promotion is a separate "
                "privileged action."
            )
        else:
            message = (
                "Index build completed but is not a candidate until the owner-frozen "
                "benchmark passes."
            )
        if not ctx.skip_embedding:
            _finalize_or_reconcile_candidate(ctx, expected_seal_sha256=str(seal_hash or ""))
        completed_at = utc_iso()
        with self.database.transaction() as conn:
            _require_index_lease_current(ctx, stage=stage, connection=conn)
            build_row = conn.execute(
                "SELECT status FROM index_builds WHERE id=?", (ctx.build_id,)
            ).fetchone()
            if build_row is None or str(build_row["status"]) != "building":
                raise RuntimeError("index_build_candidate_transition_changed")
            updated_build = conn.execute(
                """
                UPDATE index_builds
                SET status=?, stage=?, document_count=?, chunk_count=?, vector_count=?,
                    manifest_sha256=?, candidate_manifest_hash=?, stage_timings_json=?,
                    counts_json=?, benchmark_result_json=?, promotion_decision='not_requested'
                WHERE id=? AND status='building'
                """,
                (
                    status,
                    stage,
                    ctx.counts.get("documents", ctx.counts.get("sources", 0)),
                    ctx.counts.get("chunks_written", 0),
                    ctx.counts.get("vectors", 0),
                    seal_hash,
                    seal_hash,
                    json.dumps(ctx.timings, sort_keys=True),
                    json.dumps(ctx.counts, sort_keys=True),
                    json.dumps(benchmark, sort_keys=True),
                    ctx.build_id,
                ),
            )
            if updated_build.rowcount != 1:
                raise RuntimeError("index_build_candidate_transition_changed")
            job_predicate = ""
            job_parameters: tuple[Any, ...] = ()
            if ctx.expected_lease_owner is not None:
                job_predicate = (
                    " AND lease_owner=? AND lease_expires_at>?"
                    " AND (workflow_deadline_at IS NULL OR workflow_deadline_at>?)"
                    " AND (stage_deadline_at IS NULL OR stage_deadline_at>?)"
                )
                job_parameters = (
                    ctx.expected_lease_owner,
                    completed_at,
                    completed_at,
                    completed_at,
                )
            updated_job = conn.execute(
                f"""
                UPDATE jobs SET status='complete',stage=?,progress=1,user_message=?,
                  checkpoint_json=?,last_progress_at=?,updated_at=?
                WHERE id=? AND status='running' AND cancel_requested=0{job_predicate}
                """,
                (
                    stage,
                    message,
                    json.dumps({"build_id": ctx.build_id, "status": status}, sort_keys=True),
                    completed_at,
                    completed_at,
                    ctx.job_id,
                    *job_parameters,
                ),
            )
            if updated_job.rowcount != 1:
                raise IndexBuildStageError(
                    stage, "lease_lost", "index-build lease changed at candidate publication"
                )
            conn.execute(
                """
                INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
                VALUES (?, ?, 1, ?, '{}', ?)
                """,
                (ctx.job_id, stage, message, completed_at),
            )
        return status

    def _mark_failed(self, ctx: IndexBuildContext, stage: str, reason: str, exc: Exception) -> None:
        from .service import _safe_failure

        failed_at = utc_iso()
        try:
            pointer_snapshot_after_failure = _release_pointer_snapshot(ctx.settings)
            pointer_state_unchanged: bool | None = (
                None
                if ctx.release_pointer_snapshot is None
                else pointer_snapshot_after_failure == ctx.release_pointer_snapshot
            )
            pointer_verification_error = None
        except Exception as pointer_exc:  # preserve the substantive build failure
            pointer_snapshot_after_failure = None
            pointer_state_unchanged = False
            pointer_verification_error = _safe_failure(pointer_exc)
        metrics = {
            "failure_type": type(exc).__name__,
            "failure": _safe_failure(exc),
            "failed_at": failed_at,
            "failed_stage": stage,
            "reason_code": reason,
            "timings": ctx.timings,
            "counts": ctx.counts,
            "release_pointer_snapshot_at_enqueue": ctx.release_pointer_snapshot,
            "release_pointer_snapshot_after_failure": pointer_snapshot_after_failure,
            "release_pointer_state_unchanged": pointer_state_unchanged,
            "release_pointer_verification_error": pointer_verification_error,
        }
        ctx.counts["release_pointer_state_unchanged"] = pointer_state_unchanged
        build_parameters = (
            IndexBuildStage.FAILED,
            reason,
            json.dumps(metrics, ensure_ascii=False, sort_keys=True),
            json.dumps(ctx.timings, sort_keys=True),
            json.dumps(ctx.counts, sort_keys=True),
            ctx.build_id,
        )
        if ctx.expected_lease_owner is None:
            self.database.execute(
                """
                UPDATE index_builds
                SET status='failed', stage=?, failure_reason_code=?, metrics_json=?,
                    stage_timings_json=?, counts_json=?, promotion_decision='blocked_failed'
                WHERE id=? AND status IN ('queued','building','failed')
                """,
                build_parameters,
            )
            cancelled = reason == "cancelled"
            self.database.update_job(
                ctx.job_id,
                status="cancelled" if cancelled else "failed",
                stage="cancelled" if cancelled else IndexBuildStage.FAILED,
                progress=1,
                message=(
                    "Index-build cancelled. ACTIVE.json was not written."
                    if cancelled
                    else "Index-build failed. ACTIVE.json was not written."
                ),
                error_code=reason,
                checkpoint={
                    "build_id": ctx.build_id,
                    "failed_stage": stage,
                    "resumable": not cancelled,
                },
            )
        else:
            cancelled = reason == "cancelled"
            message = (
                "Index-build cancelled. ACTIVE.json was not written."
                if cancelled
                else "Index-build failed. ACTIVE.json was not written."
            )
            checkpoint = json.dumps(
                {
                    "build_id": ctx.build_id,
                    "failed_stage": stage,
                    "resumable": not cancelled,
                },
                sort_keys=True,
            )
            with self.database.transaction() as conn:
                _require_index_lease_current(
                    ctx,
                    stage=stage,
                    connection=conn,
                    allow_cancel_requested=cancelled,
                )
                updated_build = conn.execute(
                    """
                    UPDATE index_builds
                    SET status='failed', stage=?, failure_reason_code=?, metrics_json=?,
                        stage_timings_json=?, counts_json=?, promotion_decision='blocked_failed'
                    WHERE id=? AND status IN ('queued','building','failed')
                    """,
                    build_parameters,
                )
                if updated_build.rowcount != 1:
                    raise RuntimeError("index_build_failure_transition_changed")
                updated_job = conn.execute(
                    """
                    UPDATE jobs SET status=?,stage=?,progress=1,user_message=?,
                      error_code=?,checkpoint_json=?,last_progress_at=?,updated_at=?
                    WHERE id=? AND status='running' AND cancel_requested=?
                      AND lease_owner=? AND lease_expires_at>?
                    """,
                    (
                        "cancelled" if cancelled else "running",
                        "cancelled" if cancelled else IndexBuildStage.FAILED,
                        message,
                        reason,
                        checkpoint,
                        failed_at,
                        failed_at,
                        ctx.job_id,
                        int(cancelled),
                        ctx.expected_lease_owner,
                        failed_at,
                    ),
                )
                if updated_job.rowcount != 1:
                    raise IndexBuildStageError(
                        stage, "lease_lost", "index-build lease changed at failure publication"
                    )
                conn.execute(
                    """
                    INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
                    VALUES (?, ?, 1, ?, '{}', ?)
                    """,
                    (ctx.job_id, IndexBuildStage.FAILED, message, failed_at),
                )
        retryable = reason not in {
            "required_source_family_truncated",
            "private_path_leakage",
            "benchmark_threshold_failure",
            "chunk_embedding_count_mismatch",
            "currentness_metadata_missing",
            "cancelled",
        }
        record_index_stage_failure(
            self.events,
            stage=str(stage),
            reason_code=str(reason),
            message="Index-build stage failed. The generation is not a candidate.",
            job_id=ctx.job_id,
            build_id=ctx.build_id,
            retryable=retryable,
            blocking=True,
            provenance={
                "source_manifest_hash": ctx.manifest.get("manifest_sha256"),
                "embedding_model_version": ctx.embedding_model,
            },
        )


def _finalize_or_reconcile_candidate(
    ctx: IndexBuildContext,
    *,
    expected_seal_sha256: str,
) -> None:
    """Make the staging rename idempotently recoverable across process crashes."""

    from .service import _file_sha256, _verify_durable_candidate_tree

    if not re.fullmatch(r"[0-9a-f]{64}", expected_seal_sha256):
        raise RuntimeError("index_build_finalization_intent_invalid")
    repository = ImmutableLanceRepository(ctx.settings.index_dir)
    staging = repository.builds / f".{ctx.build_id}.incomplete"
    final = repository.builds / ctx.build_id
    if final.exists():
        if staging.exists() or not final.is_dir() or final.is_symlink():
            raise RuntimeError("index_build_finalization_state_ambiguous")
        row = ctx.database.fetchone("SELECT * FROM index_builds WHERE id=?", (ctx.build_id,))
        if row is None:
            raise RuntimeError("index_build_finalization_catalogue_missing")
        replay_row = dict(row)
        replay_row.update(
            {
                "manifest_sha256": expected_seal_sha256,
                "candidate_manifest_hash": expected_seal_sha256,
                "document_count": ctx.counts.get("documents", ctx.counts.get("sources", 0)),
                "chunk_count": ctx.counts.get("chunks_written", 0),
                "vector_count": ctx.counts.get("vectors", 0),
            }
        )
        if getattr(ctx, "manifest", {}).get("selection_policy") == GE_SELECTION_POLICY:
            _verify_held_ge_successor_tree(
                ctx,
                final,
                expected_seal_sha256=expected_seal_sha256,
            )
        else:
            _verify_durable_candidate_tree(ctx.settings, replay_row)
        return
    if not staging.is_dir() or staging.is_symlink():
        raise RuntimeError("index_build_finalization_staging_missing")
    seal_path = staging / "seal.json"
    if not seal_path.is_file() or _file_sha256(seal_path) != expected_seal_sha256:
        raise RuntimeError("index_build_finalization_intent_changed")
    repository.finalize_staging(ctx.build_id)
    finalized_seal = final / "seal.json"
    if not finalized_seal.is_file() or _file_sha256(finalized_seal) != expected_seal_sha256:
        raise RuntimeError("index_build_finalization_rename_changed_bytes")
    if getattr(ctx, "manifest", {}).get("selection_policy") == GE_SELECTION_POLICY:
        _verify_held_ge_successor_tree(
            ctx,
            final,
            expected_seal_sha256=expected_seal_sha256,
        )


def _verify_held_ge_successor_tree(
    ctx: IndexBuildContext,
    final: Path,
    *,
    expected_seal_sha256: str,
) -> None:
    """Verify immutable GE held evidence without opening a live-release path."""

    from .service import (
        PHYSICAL_AUTHORITY_LANE,
        PHYSICAL_LANES,
        _file_sha256,
        _json_object,
        _tree_sha256,
    )

    source_lane_claims = _integrity_source_lane_claims(ctx.manifest)
    if (
        ctx.manifest.get("selection_policy") != GE_SELECTION_POLICY
        or ctx.manifest.get("successor_must_remain_non_active") is not True
        or ctx.manifest.get("answer_release_eligible") is not False
        or ctx.manifest.get("active_or_previous_write_authorized") is not False
        or ctx.manifest.get("promotion_authorized") is not False
    ):
        raise RuntimeError("ge_held_successor_boundary_invalid")
    paths = {
        "manifest": final / "manifest.json",
        "evaluation": final / "evaluation.json",
        "privacy": final / "privacy-report.json",
        "source": final / "approved-source-manifest.json",
        "lane": final / "lance" / "physical-lanes.json",
        "seal": final / "seal.json",
    }
    if final.is_symlink() or not final.is_dir() or any(
        path.is_symlink() or not path.is_file() for path in paths.values()
    ):
        raise RuntimeError("ge_held_successor_tree_incomplete")
    if _file_sha256(paths["seal"]) != expected_seal_sha256:
        raise RuntimeError("ge_held_successor_seal_changed")
    build_manifest = _json_object(paths["manifest"].read_text(encoding="utf-8"))
    evaluation = _json_object(paths["evaluation"].read_text(encoding="utf-8"))
    privacy = _json_object(paths["privacy"].read_text(encoding="utf-8"))
    source = _json_object(paths["source"].read_text(encoding="utf-8"))
    lane_manifest = _json_object(paths["lane"].read_text(encoding="utf-8"))
    seal = _json_object(paths["seal"].read_text(encoding="utf-8"))
    try:
        expansion_binding = ge_index_build_decision_binding(
            ctx.settings,
            ctx.database,
            source,
            build_id=ctx.build_id,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError("ge_held_successor_expansion_proof_invalid") from exc
    lance_tree_sha256 = _tree_sha256(final / "lance")
    integrity = evaluation.get("integrity")
    if not isinstance(integrity, dict):
        raise RuntimeError("ge_held_successor_integrity_missing")
    raw_tables = lane_manifest.get("tables")
    if not isinstance(raw_tables, dict):
        raise RuntimeError("ge_held_successor_lane_manifest_invalid")
    lane_counts = {
        lane: int((raw_tables.get(lane) or {}).get("row_count", -1)) for lane in PHYSICAL_LANES
    }
    chunk_count = int(build_manifest.get("chunk_count") or 0)
    if (
        source != ctx.manifest
        or expansion_binding.expansion_mode != "strict_successor"
        or expansion_binding.successor_source_count
        != int(source.get("source_count") or -1)
        or expansion_binding.successor_chunk_count
        != int(source.get("chunk_count") or -1)
        or expansion_binding.predecessor_source_count < 1
        or expansion_binding.added_source_count < 1
        or expansion_binding.predecessor_source_count
        + expansion_binding.added_source_count
        != expansion_binding.successor_source_count
        or source.get("manifest_sha256") != ctx.manifest.get("manifest_sha256")
        or build_manifest.get("schema") != "legalbot.lance-build.v1"
        or build_manifest.get("build_id") != ctx.build_id
        or build_manifest.get("embedding_model") != ctx.embedding_model
        or build_manifest.get("reranker_model") != ctx.reranker_model
        or build_manifest.get("source_manifest_sha256") != source.get("manifest_sha256")
        or chunk_count < 1
        or seal.get("schema") != "legalbot.index-seal.v2"
        or seal.get("build_id") != ctx.build_id
        or seal.get("promotion") != "not_requested"
        or seal.get("manifest_sha256") != _file_sha256(paths["manifest"])
        or seal.get("evaluation_sha256") != _file_sha256(paths["evaluation"])
        or seal.get("privacy_report_sha256") != _file_sha256(paths["privacy"])
        or seal.get("source_manifest_file_sha256") != _file_sha256(paths["source"])
        or seal.get("physical_lane_manifest_sha256") != _file_sha256(paths["lane"])
        or seal.get("lance_tree_sha256") != lance_tree_sha256
        or evaluation.get("schema") != "legalbot.index-evaluation.v2"
        or evaluation.get("passed") is not True
        or evaluation.get("promotion_eligible") is not False
        or evaluation.get("scoped_corpus_id") != ctx.corpus_id
        or privacy.get("schema") != "legalbot.privacy-report.v1"
        or privacy.get("passed") is not True
        or integrity.get("approved_only") is not True
        or integrity.get("authority_lane_only")
        is not source_lane_claims["authority_lane_only"]
        or integrity.get("approved_legal_source_lanes_only")
        is not source_lane_claims["approved_legal_source_lanes_only"]
        or integrity.get("allowed_catalogue_lanes")
        != source_lane_claims["allowed_catalogue_lanes"]
        or integrity.get("catalogue_source_counts")
        != source_lane_claims["catalogue_source_counts"]
        or integrity.get("scope_source_counts") != source_lane_claims["scope_source_counts"]
        or integrity.get("material_source_counts")
        != source_lane_claims["material_source_counts"]
        or integrity.get("source_lane_bindings") != source_lane_claims["source_lane_bindings"]
        or integrity.get("successor_must_remain_non_active") is not True
        or int(integrity.get("chunk_count") or 0) != chunk_count
        or int(integrity.get("vector_count") or 0) != chunk_count
        or int(integrity.get("vector_dimensions") or 0) != VECTOR_DIMENSIONS
        or integrity.get("source_manifest_sha256") != source.get("manifest_sha256")
        or integrity.get("source_snapshot_stable") is not True
        or integrity.get("lance_tree_sha256") != lance_tree_sha256
        or integrity.get("physical_lane_isolation") is not True
        or integrity.get("physical_lane_counts") != lane_counts
        or lane_manifest.get("schema") != "legalbot.physical-lanes.v1"
        or lane_manifest.get("separated") is not True
        or any(count < 0 for count in lane_counts.values())
        or sum(lane_counts.values()) != chunk_count
        or lane_counts.get(PHYSICAL_AUTHORITY_LANE) != chunk_count
        or any(
            count != 0
            for lane, count in lane_counts.items()
            if lane != PHYSICAL_AUTHORITY_LANE
        )
        or any(not (final / "lance" / lane).is_dir() for lane in PHYSICAL_LANES)
        or any(
            count > 0 and not (final / "lance" / lane / "chunks.lance").exists()
            for lane, count in lane_counts.items()
        )
    ):
        raise RuntimeError("ge_held_successor_tree_verification_failed")
    _verify_held_ge_lance_inventory(
        ctx,
        final,
        chunk_count=chunk_count,
        claimed_lane_counts=lane_counts,
    )
    if (
        ctx.release_pointer_snapshot is not None
        and _release_pointer_snapshot(ctx.settings) != ctx.release_pointer_snapshot
    ):
        raise RuntimeError("ge_held_successor_release_pointer_state_changed")
    repository = ImmutableLanceRepository(ctx.settings.index_dir)
    active = repository.read_active()
    previous = repository.read_previous()
    if (active is not None and active.build_id == ctx.build_id) or (
        previous is not None and previous.build_id == ctx.build_id
    ):
        raise RuntimeError("ge_held_successor_pointer_write_detected")


def _verify_held_ge_lance_inventory(
    ctx: IndexBuildContext,
    final: Path,
    *,
    chunk_count: int,
    claimed_lane_counts: dict[str, int],
) -> None:
    """Open the held table and prove exact chunk/source/lane row parity."""

    from .incomplete_index_audit import (
        compare_index_identities,
        load_expected_index_rows,
        read_lance_observations,
        source_lane_bindings_for_manifest,
    )
    from .service import PHYSICAL_LANES, _prompt_safe_index_text

    lance_root = final / "lance"
    try:
        lane_directories = {
            path.name
            for path in lance_root.iterdir()
            if path.is_dir() and not path.is_symlink()
        }
        if lane_directories != set(PHYSICAL_LANES) or any(
            (lance_root / lane).is_symlink() for lane in PHYSICAL_LANES
        ):
            raise RuntimeError("ge_held_successor_physical_lane_inventory_invalid")
        for lane in PHYSICAL_LANES:
            dataset = lance_root / lane / "chunks.lance"
            claimed = claimed_lane_counts[lane]
            if dataset.is_symlink() or (claimed > 0) is not dataset.is_dir():
                raise RuntimeError("ge_held_successor_physical_lane_inventory_invalid")
        bindings = source_lane_bindings_for_manifest(ctx.manifest)
        if tuple(binding.source_version_id for binding in bindings) != ctx.source_ids:
            raise RuntimeError("ge_held_successor_source_inventory_invalid")
        expected = load_expected_index_rows(
            ctx.database,
            source_ids=ctx.source_ids,
            allowlists=ctx.manifest.get("locator_allowlists") or {},
            prompt_safe=_prompt_safe_index_text,
            source_lane_bindings=bindings,
        )
        observed = read_lance_observations(final)
    except RuntimeError:
        raise
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise RuntimeError("ge_held_successor_lance_inventory_unreadable") from exc

    comparison = compare_index_identities(expected, observed)
    observed_lane_counts = dict.fromkeys(PHYSICAL_LANES, 0)
    for row in observed:
        if row.lane not in observed_lane_counts:
            raise RuntimeError("ge_held_successor_physical_lane_inventory_invalid")
        observed_lane_counts[row.lane] += 1
    bound_source_ids = {binding.source_version_id for binding in bindings}
    expected_source_ids = {row.source_version_id for row in expected}
    observed_source_ids = {row.source_version_id for row in observed}
    if (
        int(ctx.manifest.get("chunk_count") or 0) != chunk_count
        or len(expected) != chunk_count
        or comparison.get("embedding_complete") is not True
        or observed_lane_counts != claimed_lane_counts
        or expected_source_ids != bound_source_ids
        or observed_source_ids != bound_source_ids
    ):
        raise RuntimeError("ge_held_successor_lance_inventory_mismatch")


def _verify_parent_vector_binding(ctx: IndexBuildContext) -> None:
    is_ge_successor = ctx.manifest.get("selection_policy") == GE_SELECTION_POLICY
    predecessor_build_id = str(ctx.manifest.get("ge_predecessor_build_id") or "")
    predecessor_seal_sha256 = str(
        ctx.manifest.get("ge_predecessor_seal_sha256") or ""
    )
    if ctx.reuse_vectors_from_build_id is None:
        if ctx.parent_vector_seal_sha256 is not None:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "parent_vector_binding_incomplete",
                "parent vector seal is present without a parent build identity",
            )
        return
    if is_ge_successor and ctx.reuse_vectors_from_build_id != predecessor_build_id:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "ge_successor_vector_parent_must_equal_predecessor",
            "GE successor vector reuse is restricted to its exact predecessor",
        )
    try:
        parent = verify_parent_vector_source(
            index_root=ctx.settings.index_dir,
            parent_build_id=ctx.reuse_vectors_from_build_id,
            child_build_id=ctx.build_id,
            embedding_model_revision=ctx.embedding_model,
            vector_dimensions=VECTOR_DIMENSIONS,
            vector_dtype="float16" if "dtype=float16" in ctx.embedding_model else "test",
            parser_identity=PARSER_VERSION,
            chunker_identity=CHUNKER_VERSION,
            index_schema_version=INDEX_SCHEMA_VERSION,
        )
    except VectorCarryForwardError as exc:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "parent_vector_identity_mismatch",
            "sealed parent vector identity verification failed",
        ) from exc
    if parent.identity.seal_sha256 != ctx.parent_vector_seal_sha256:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "parent_vector_seal_changed",
            "sealed parent vector identity changed after enqueue",
        )
    if is_ge_successor and parent.identity.seal_sha256 != predecessor_seal_sha256:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "ge_successor_vector_parent_seal_differed",
            "GE successor vector parent is not its exact sealed predecessor",
        )
    ctx.parent_vector_source = parent


def _job_cancel_requested(ctx: IndexBuildContext) -> bool:
    row = ctx.database.job(ctx.job_id)
    return bool(row["cancel_requested"]) if row is not None else False


def _ctx_clock(ctx: IndexBuildContext) -> float:
    return (ctx.clock or time.perf_counter)()


def _ctx_now(ctx: IndexBuildContext) -> datetime:
    if ctx.now is not None:
        return ctx.now()
    return datetime.now(UTC)


def _require_index_lease_current(
    ctx: IndexBuildContext,
    *,
    stage: str,
    connection: Any | None = None,
    allow_cancel_requested: bool = False,
) -> None:
    if ctx.expected_lease_owner is None:
        return
    row = (
        connection.execute(
            "SELECT status,cancel_requested,lease_owner,lease_expires_at FROM jobs WHERE id=?",
            (ctx.job_id,),
        ).fetchone()
        if connection is not None
        else ctx.database.fetchone(
            "SELECT status,cancel_requested,lease_owner,lease_expires_at FROM jobs WHERE id=?",
            (ctx.job_id,),
        )
    )
    lease_current = False
    cancel_requested = False
    if (
        row is not None
        and str(row["status"]) == "running"
        and str(row["lease_owner"] or "") == ctx.expected_lease_owner
        and row["lease_expires_at"] not in (None, "")
    ):
        cancel_requested = bool(row["cancel_requested"])
        try:
            expires_at = datetime.fromisoformat(str(row["lease_expires_at"]))
        except ValueError:
            expires_at = datetime.min.replace(tzinfo=UTC)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        lease_current = expires_at > _ctx_now(ctx)
    if lease_current and cancel_requested and not allow_cancel_requested:
        raise IndexBuildStageError(
            stage,
            "cancelled",
            "index-build cancellation was requested",
        )
    if not lease_current:
        raise IndexBuildStageError(
            stage,
            "lease_lost",
            "index-build lease ownership changed during execution",
        )


def _require_index_stage_deadline(ctx: IndexBuildContext, *, stage: str) -> None:
    from .index_stage_policy import parse_deadline, remaining_seconds

    try:
        deadline = parse_deadline(ctx.stage_deadline_at)
    except (TypeError, ValueError) as exc:
        raise IndexBuildStageError(
            stage,
            "invalid_persisted_deadline",
            "index-build stage deadline is malformed",
        ) from exc
    remaining = remaining_seconds(deadline, now=_ctx_now(ctx))
    if remaining is not None and remaining <= 0:
        raise IndexBuildStageError(
            stage,
            TERMINAL_STAGE_TIMEOUT,
            "index-build stage exceeded its absolute deadline",
        )


def _run_stage(ctx: IndexBuildContext, stage: str, fn: Callable[[IndexBuildContext], None]) -> None:
    from .index_stage_policy import (
        INDEX_STAGE_POLICY_VERSION,
        IndexDeadlineExceeded,
        budget_for,
        raise_if_workflow_expired,
    )

    _require_index_lease_current(ctx, stage=stage)
    job = ctx.database.job(ctx.job_id)
    if job is not None and job["cancel_requested"]:
        raise IndexBuildStageError(stage, "cancelled", "index-build cancelled")
    raise_if_workflow_expired(job, now=_ctx_now(ctx))
    completed = ctx.database.completed_stage_attempt(ctx.job_id, stage, "index")
    if completed is not None:
        _require_index_lease_current(ctx, stage=stage)
        EventStore.from_settings(ctx.settings, ctx.database).emit(
            event_type="warning",
            component="index_build",
            stage=stage,
            failure_code="checkpoint_restore",
            source_id=ctx.build_id,
            job_id=ctx.job_id,
            build_id=ctx.build_id,
            user_or_owner_safe=f"Index-build stage {stage} restored from a durable checkpoint.",
            retryable=False,
            blocking=False,
        )
        return
    started = _ctx_clock(ctx)
    stage_started = utc_iso()
    expected_chunks = int(
        ctx.counts.get("chunks_present") or ctx.counts.get("chunks_expected") or 0
    )
    budget = budget_for(stage, expected_chunks=expected_chunks)
    ctx.database.update_job(
        ctx.job_id,
        status=JobStatus.RUNNING,
        stage=stage,
        progress=_STAGE_PROGRESS[stage],
        message=f"Index-build stage {stage}",
        checkpoint={"build_id": ctx.build_id, "stage": stage},
    )
    ctx.stage_deadline_at = ctx.database.arm_stage_deadline(
        ctx.job_id, seconds=budget.absolute_seconds
    )
    ctx.database.execute(
        """
        UPDATE index_builds SET status='building', stage=?, stage_started_at=?
        WHERE id=?
        """,
        (stage, stage_started, ctx.build_id),
    )
    attempt_id = str(uuid4())
    attempt_number = ctx.database.next_stage_attempt_number(ctx.job_id, stage, "index")
    try:
        if ctx.fail_at_stage == stage:
            raise IndexBuildStageError(stage, "injected_failure", f"injected failure at {stage}")
        _require_index_stage_deadline(ctx, stage=stage)
        fn(ctx)
        _require_index_stage_deadline(ctx, stage=stage)
        _require_index_lease_current(ctx, stage=stage)
        duration_ms = round((_ctx_clock(ctx) - started) * 1000)
        ctx.timings[stage] = {
            "started_at": stage_started,
            "finished_at": utc_iso(),
            "duration_ms": duration_ms,
            "stage_budget_seconds": budget.absolute_seconds,
            "policy_version": INDEX_STAGE_POLICY_VERSION,
        }
        ctx.database.store_stage_attempt(
            attempt_id=attempt_id,
            job_id=ctx.job_id,
            stage_key=stage,
            section_key="index",
            attempt_number=attempt_number,
            status="complete",
            encrypted_output=None,
            metrics={"duration_ms": duration_ms, "counts": ctx.counts},
        )
        ctx.database.execute(
            "UPDATE index_builds SET stage_timings_json=?, counts_json=? WHERE id=?",
            (
                json.dumps(ctx.timings, sort_keys=True),
                json.dumps(ctx.counts, sort_keys=True),
                ctx.build_id,
            ),
        )
    except Exception as exc:
        if getattr(exc, "reason_code", None) == "lease_lost" or (
            ctx.expected_lease_owner is not None
            and not ctx.database.job_lease_is_current(
                ctx.job_id, ctx.expected_lease_owner, now=_ctx_now(ctx)
            )
        ):
            raise IndexBuildStageError(
                stage,
                "lease_lost",
                "index-build lease ownership changed during stage execution",
            ) from exc
        duration_ms = round((_ctx_clock(ctx) - started) * 1000)
        ctx.timings[stage] = {
            "started_at": stage_started,
            "finished_at": utc_iso(),
            "duration_ms": duration_ms,
            "error": type(exc).__name__,
        }
        reason = getattr(exc, "reason_code", type(exc).__name__)
        ctx.database.store_stage_attempt(
            attempt_id=attempt_id,
            job_id=ctx.job_id,
            stage_key=stage,
            section_key="index",
            attempt_number=attempt_number,
            status="failed",
            encrypted_output=None,
            error_code=reason,
            metrics={"duration_ms": duration_ms},
        )
        if isinstance(exc, IndexBuildStageError):
            raise
        if isinstance(exc, IndexDeadlineExceeded):
            raise IndexBuildStageError(stage, exc.reason_code, str(exc)) from exc
        raise IndexBuildStageError(stage, TERMINAL_STAGE_FAILED, str(exc)) from exc


def _stage_scanning(ctx: IndexBuildContext) -> None:
    _require_index_stage_deadline(ctx, stage=IndexBuildStage.SCANNING)
    dest = ctx.settings.data_dir / "review_queue" / f"approved-source-manifest-{ctx.corpus_id}.json"
    digest = write_approved_source_manifest(dest, ctx.manifest)
    if digest != ctx.manifest["manifest_sha256"]:
        ctx.manifest["manifest_sha256"] = digest
    ctx.counts["scan_sources"] = len(ctx.manifest["sources"])
    ctx.counts["scan_chunks"] = int(ctx.manifest["chunk_count"])
    omitted = list(ctx.manifest.get("omitted_required_families") or [])
    ctx.counts["omitted_required_families"] = len(omitted)
    if omitted:
        raise IndexBuildStageError(
            IndexBuildStage.SCANNING,
            "required_source_family_truncated",
            "required source family omitted or truncated by cap: " + ",".join(omitted),
        )
    missing_currentness = [
        str(source.get("stable_identifier") or source.get("source_version_id"))
        for source in ctx.manifest.get("sources") or []
        if not str(source.get("currentness_status") or "").strip()
    ]
    if missing_currentness:
        raise IndexBuildStageError(
            IndexBuildStage.SCANNING,
            "currentness_metadata_missing",
            "approved sources are missing currentness metadata",
        )
    if ctx.counts["scan_sources"] < 1:
        raise IndexBuildStageError(
            IndexBuildStage.SCANNING, "empty_manifest", "no approved authority sources"
        )


def _stage_parsing(ctx: IndexBuildContext) -> None:
    missing = 0
    present = 0
    for source in ctx.manifest["sources"]:
        _require_index_stage_deadline(ctx, stage=IndexBuildStage.PARSING)
        path = ctx.settings.project_root / str(source["canonical_markdown_path"])
        if path.is_file() and path.stat().st_size > 0:
            present += 1
        else:
            missing += 1
    ctx.counts["parsed_present"] = present
    ctx.counts["parsed_missing"] = missing
    if missing:
        raise IndexBuildStageError(
            IndexBuildStage.PARSING,
            "canonical_markdown_missing",
            f"{missing} approved sources lack canonical Markdown",
        )


def _stage_chunking(ctx: IndexBuildContext) -> None:
    placeholders = ",".join("?" * len(ctx.source_ids)) or "''"
    allowlists = ctx.manifest.get("locator_allowlists") or {}
    rows = ctx.database.fetchall(
        f"""
        SELECT sv.stable_identifier, c.locator
        FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        WHERE c.stream='body' AND c.source_version_id IN ({placeholders})
        """,
        ctx.source_ids,
    )
    count = 0
    for row in rows:
        _require_index_stage_deadline(ctx, stage=IndexBuildStage.CHUNKING)
        if chunk_locator_allowed(
            str(row["stable_identifier"]), str(row["locator"] or ""), allowlists
        ):
            count += 1
    ctx.counts["chunks_present"] = count
    if count < 1:
        raise IndexBuildStageError(
            IndexBuildStage.CHUNKING, "no_chunks", "approved sources have no body chunks"
        )


def _completed_prefix_source_ids(
    expected_rows: Sequence[Any], completed_row_count: int
) -> set[str]:
    """Return every source represented by a durably completed ordered prefix."""

    if completed_row_count < 0 or completed_row_count > len(expected_rows):
        raise ValueError("embedding checkpoint exceeds the expected ordered stream")
    return {
        str(row.source_version_id)
        for row in expected_rows[:completed_row_count]
        if str(row.source_version_id)
    }


def _resumed_vector_counts(
    *,
    completed_row_count: int,
    restored_reused_count: int,
    restored_embedded_count: int,
    has_parent_vector_source: bool,
) -> dict[str, int]:
    """Reconcile durable prefix vectors without inventing a reuse split."""

    if min(completed_row_count, restored_reused_count, restored_embedded_count) < 0:
        raise ValueError("embedding resume vector counts cannot be negative")
    if completed_row_count == 0:
        return {
            "reused": restored_reused_count,
            "embedded": restored_embedded_count,
        }
    if not has_parent_vector_source:
        return {"reused": 0, "embedded": completed_row_count}
    if restored_reused_count + restored_embedded_count != completed_row_count:
        raise ValueError("parent-vector resume lacks an exact durable reuse split")
    return {
        "reused": restored_reused_count,
        "embedded": restored_embedded_count,
    }


def _stage_embedding(ctx: IndexBuildContext) -> None:
    from .embedding_progress import (
        EmbeddingIdentityFields,
        build_checkpoint,
        chunk_key,
        identities_match,
        load_checkpoint,
        ordered_stream_digest,
        save_checkpoint,
        update_rolling_digest,
    )
    from .index_stage_policy import (
        EMBEDDING_CHECKPOINT_BATCHES,
        EmbeddingProgressGuard,
        budget_for,
    )
    from .provision_verification import load_provision_verifications
    from .service import (
        INDEX_EMBED_BATCH_SIZE,
        PHYSICAL_LANES,
        _catalogue_row_to_indexed,
        _embedding_provider,
        _import_lancedb,
        _indexed_to_lance_row,
        _prompt_safe_index_text,
        _RealLanceSessionFactory,
        _write_new_bytes,
    )

    if ctx.skip_embedding:
        ctx.counts["chunks_written"] = 0
        ctx.counts["vectors"] = 0
        ctx.counts["embedding_skipped"] = 1
        return
    repository = ImmutableLanceRepository(ctx.settings.index_dir)
    embedder = _embedding_provider(ctx.settings, ctx.embedding_model)
    lancedb_module = _import_lancedb()
    session_factory = _RealLanceSessionFactory(lancedb_module)
    provision_verifications, provision_verification_sha256 = load_provision_verifications(
        ctx.settings.project_root, allow_test_empty=ctx.settings.test_mode
    )
    if provision_verification_sha256 != ctx.manifest.get("provision_verification_sha256"):
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "provision_verification_changed",
            "provision-verification registry changed after the source manifest was frozen",
        )
    from .incomplete_index_audit import load_expected_index_rows

    expected_rows = load_expected_index_rows(
        ctx.database,
        source_ids=ctx.source_ids,
        allowlists=ctx.manifest.get("locator_allowlists") or {},
        prompt_safe=_prompt_safe_index_text,
        source_lane_bindings=source_lane_bindings_for_manifest(ctx.manifest),
    )
    expected_keys = [
        chunk_key(row.source_version_id, row.ordinal, row.chunk_id) for row in expected_rows
    ]
    stream_digest = ordered_stream_digest(expected_keys)
    model = ctx.embedding_model
    dtype = "float16" if "dtype=float16" in model else "test"
    identity: EmbeddingIdentityFields = {
        "build_id": ctx.build_id,
        "source_manifest_sha256": str(ctx.manifest["manifest_sha256"]),
        "ordered_chunk_stream_sha256": stream_digest,
        "parser_version": PARSER_VERSION,
        "chunker_version": CHUNKER_VERSION,
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "embedding_model": model,
        "dtype": dtype,
        "vector_dimensions": VECTOR_DIMENSIONS,
        "batch_size": INDEX_EMBED_BATCH_SIZE,
        "policy_sha256": POLICY_SHA256,
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "provision_verification_sha256": str(provision_verification_sha256),
        "parent_vector_build_id": ctx.reuse_vectors_from_build_id or "",
        "parent_vector_seal_sha256": ctx.parent_vector_seal_sha256 or "",
    }
    incomplete = repository.builds / f".{ctx.build_id}.incomplete"
    after_chunk_key: str | None = None

    @dataclass(slots=True)
    class _Produced:
        n: int = 0
        key: str = ""
        digest: str = ""
        flushes: int = 0

    produced = _Produced()
    if incomplete.exists():
        try:
            checkpoint = load_checkpoint(incomplete)
        except (OSError, TypeError, ValueError) as exc:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "legacy_incomplete_staging",
                "incomplete staging exists without a valid progress checkpoint",
            ) from exc
        if checkpoint is None:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "legacy_incomplete_staging",
                "incomplete staging exists without a valid progress checkpoint",
            )
        if not identities_match(checkpoint, **identity):
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "embedding_identity_mismatch",
                "incomplete staging checkpoint identities do not match this build",
            )
        staging = repository.open_resumable_staging(ctx.build_id)
        after_chunk_key = checkpoint.last_deterministic_chunk_key or None
        produced.n = checkpoint.completed_row_count
        produced.digest = checkpoint.rolling_digest
        produced.key = checkpoint.last_deterministic_chunk_key
    else:
        staging = repository.prepare_new_staging(ctx.build_id)
    _write_or_verify_index_build_boundary(staging, ctx)
    session = session_factory.create(staging / "lance")
    parent_reader = (
        ParentVectorBatchReader(ctx.parent_vector_source, lancedb_module)
        if ctx.parent_vector_source is not None
        else None
    )
    try:
        reuse_counts = _resumed_vector_counts(
            completed_row_count=produced.n,
            restored_reused_count=int(ctx.counts.get("vectors_reused") or 0),
            restored_embedded_count=int(ctx.counts.get("vectors_embedded") or 0),
            has_parent_vector_source=parent_reader is not None,
        )
    except ValueError as exc:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "vector_reuse_progress_unrecoverable",
            str(exc),
        ) from exc
    open_existing = getattr(session, "open_existing", None)
    if callable(open_existing) and produced.n:
        open_existing()
    # A resumed worker skips the checkpointed prefix. Seed the source counter
    # from that exact prefix so final catalogue metadata cannot undercount the
    # sources already present in the immutable Lance candidate.
    seen_sources = _completed_prefix_source_ids(expected_rows, produced.n)
    job = ctx.database.job(ctx.job_id)
    budget = budget_for(IndexBuildStage.EMBEDDING, expected_chunks=len(expected_rows))
    guard = EmbeddingProgressGuard(
        stall_seconds=int(budget.stall_seconds or 1_800),
        clock=lambda: _ctx_clock(ctx),
        now=lambda: _ctx_now(ctx),
        workflow_deadline_at=str(job["workflow_deadline_at"]) if job is not None else None,
        cancel_requested=lambda: _job_cancel_requested(ctx),
        stage_deadline_at=ctx.stage_deadline_at,
    )
    if produced.n:
        guard.note_committed(produced.n)
    guard.check()

    def _qualified(row: Any, vector: Any) -> IndexedChunk:
        return _catalogue_row_to_indexed(
            row,
            vector,
            provision_verifications=provision_verifications,
        )

    def _counted() -> Any:
        for chunk in _iter_scoped_chunks(
            ctx,
            embedder,
            _qualified,
            _prompt_safe_index_text,
            after_chunk_key=after_chunk_key,
            parent_vector_lookup=(parent_reader.lookup if parent_reader is not None else None),
            reuse_counts=reuse_counts,
        ):
            guard.check()
            produced.n += 1
            ctx.counts["vectors_reused"] = reuse_counts["reused"]
            ctx.counts["vectors_embedded"] = reuse_counts["embedded"]
            source_id = str(chunk.metadata.get("source_version_id") or "")
            if source_id:
                seen_sources.add(source_id)
            ordinal_raw = chunk.metadata.get("ordinal")
            produced.key = chunk_key(
                source_id,
                int(ordinal_raw) if ordinal_raw is not None else produced.n,
                chunk.chunk_id,
            )
            produced.digest = update_rolling_digest(
                produced.digest, chunk_id=chunk.chunk_id, content_sha256=chunk.content_sha256
            )
            yield chunk

    def _on_flush(row_count: int) -> None:
        guard.check(committed_row_count=row_count)
        guard.note_committed(row_count)
        produced.flushes += 1
        if produced.flushes % EMBEDDING_CHECKPOINT_BATCHES != 0:
            return
        save_checkpoint(
            staging,
            build_checkpoint(
                **identity,
                completed_row_count=row_count,
                last_deterministic_chunk_key=produced.key,
                rolling_digest=produced.digest,
                physical_lane_counts=getattr(session, "row_counts", {}),
            ),
        )

    try:
        write = session.write_chunks
        try:
            written = write(_counted(), on_flush=_on_flush)
        except TypeError:
            written = write(_counted())
        session.close()
    except Exception:
        session.close()
        if produced.n < 1:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING, "no_embedded_chunks", "embedding produced no chunks"
            ) from None
        raise
    save_checkpoint(
        staging,
        build_checkpoint(
            **identity,
            completed_row_count=written,
            last_deterministic_chunk_key=produced.key,
            rolling_digest=produced.digest,
            physical_lane_counts=getattr(session, "row_counts", {}),
        ),
    )
    ctx.counts["chunks_written"] = written
    ctx.counts["vectors"] = written
    ctx.counts["vectors_reused"] = reuse_counts["reused"]
    ctx.counts["vectors_embedded"] = reuse_counts["embedded"]
    ctx.counts["documents"] = len(seen_sources)
    ctx.counts["physical_lanes"] = len(PHYSICAL_LANES)
    if ctx.parent_vector_source is not None:
        report = build_vector_reuse_report(
            parent=ctx.parent_vector_source,
            child_build_id=ctx.build_id,
            eligible_chunk_count=written,
            reused_vector_count=reuse_counts["reused"],
            embedded_vector_count=reuse_counts["embedded"],
        )
        report_path = staging / "vector-reuse-report.json"
        report_bytes = (
            json.dumps(report.as_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        if report_path.exists():
            if report_path.read_bytes() != report_bytes:
                raise IndexBuildStageError(
                    IndexBuildStage.EMBEDDING,
                    "vector_reuse_report_changed",
                    "existing vector reuse report differs from the resumed build",
                )
        else:
            _write_new_bytes(report_path, report_bytes)
    del _indexed_to_lance_row


def _stage_lexical(ctx: IndexBuildContext) -> None:
    if ctx.skip_embedding:
        ctx.counts["lexical"] = 0
        return
    from .service import _import_lancedb

    repository = ImmutableLanceRepository(ctx.settings.index_dir)
    staging = repository.staging_path(ctx.build_id)
    module = _import_lancedb()
    repository.create_lexical_indexes(staging / "lance", module)
    ctx.counts["lexical"] = 1


def _stage_vector(ctx: IndexBuildContext) -> None:
    if ctx.skip_embedding:
        ctx.counts["vector"] = 0
        return
    from .service import PHYSICAL_LANES, _import_lancedb, _write_new_json

    repository = ImmutableLanceRepository(ctx.settings.index_dir)
    staging = repository.staging_path(ctx.build_id)
    module = _import_lancedb()
    lane_counts = repository.create_vector_indexes(staging / "lance", module)
    _write_new_json(
        staging / "lance" / "physical-lanes.json",
        {
            "schema": "legalbot.physical-lanes.v1",
            "separated": True,
            "tables": {
                lane: {"row_count": int(lane_counts.get(lane, 0))} for lane in PHYSICAL_LANES
            },
        },
    )
    ctx.counts["vector"] = 1
    ctx.counts["lane_counts"] = sum(lane_counts.values())


def _stage_validating(ctx: IndexBuildContext) -> None:
    from ..privacy_audit import build_candidate_privacy_report
    from .service import (
        PHYSICAL_LANES,
        _file_sha256,
        _json_object,
        _tree_sha256,
        _write_new_bytes,
        _write_new_json,
    )

    if ctx.skip_embedding:
        ctx.counts["validation"] = "skipped_embedding"
        ctx.counts["benchmark"] = {"passed": False, "reason": "embedding_skipped"}
        ctx.counts["candidate_manifest_hash"] = hashlib.sha256(
            json.dumps(ctx.manifest, sort_keys=True).encode()
        ).hexdigest()
        return
    repository = ImmutableLanceRepository(ctx.settings.index_dir)
    staging = repository.staging_path(ctx.build_id)
    vector_reuse_report_sha256: str | None = None
    vector_reuse_integrity: dict[str, Any] | None = None
    if ctx.parent_vector_source is not None:
        reuse_path = staging / "vector-reuse-report.json"
        if not reuse_path.is_file():
            raise IndexBuildStageError(
                IndexBuildStage.VALIDATING,
                "vector_reuse_report_missing",
                "vector reuse build has no sealed reuse report",
            )
        expected_reuse = build_vector_reuse_report(
            parent=ctx.parent_vector_source,
            child_build_id=ctx.build_id,
            eligible_chunk_count=int(ctx.counts.get("chunks_written") or 0),
            reused_vector_count=int(ctx.counts.get("vectors_reused") or 0),
            embedded_vector_count=int(ctx.counts.get("vectors_embedded") or 0),
        )
        try:
            observed_reuse = json.loads(reuse_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise IndexBuildStageError(
                IndexBuildStage.VALIDATING,
                "vector_reuse_report_invalid",
                "vector reuse report is not valid JSON",
            ) from exc
        if observed_reuse != expected_reuse.as_dict():
            raise IndexBuildStageError(
                IndexBuildStage.VALIDATING,
                "vector_reuse_report_mismatch",
                "vector reuse report differs from verified execution counts",
            )
        vector_reuse_report_sha256 = _file_sha256(reuse_path)
        vector_reuse_integrity = {
            "report_sha256": vector_reuse_report_sha256,
            "parent_build_id": ctx.parent_vector_source.identity.build_id,
            "parent_seal_sha256": ctx.parent_vector_source.identity.seal_sha256,
            "eligible_chunk_count": expected_reuse.eligible_chunk_count,
            "reused_vector_count": expected_reuse.reused_vector_count,
            "embedded_vector_count": expected_reuse.embedded_vector_count,
            "lexical_rebuilt": True,
        }
    lance_tree = _tree_sha256(staging / "lance")
    lane_manifest_path = staging / "lance" / "physical-lanes.json"
    lane_manifest = _json_object(lane_manifest_path.read_text(encoding="utf-8"))
    raw_tables = lane_manifest.get("tables")
    if not isinstance(raw_tables, dict):
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING, "lane_manifest", "physical lane manifest incomplete"
        )
    lane_counts = {
        lane: int((raw_tables.get(lane) or {}).get("row_count", -1)) for lane in PHYSICAL_LANES
    }
    written = int(ctx.counts.get("chunks_written") or sum(max(0, n) for n in lane_counts.values()))
    ctx.counts["chunks_written"] = written
    ctx.counts["vectors"] = written
    isolation = (
        lane_manifest.get("schema") == "legalbot.physical-lanes.v1"
        and lane_manifest.get("separated") is True
        and all((staging / "lance" / lane).is_dir() for lane in PHYSICAL_LANES)
        and all(count >= 0 for count in lane_counts.values())
        and sum(lane_counts.values()) == written
        and written > 0
    )
    if not isolation:
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING, "lane_isolation", "physical lane isolation failed"
        )
    source_lane_integrity = _integrity_source_lane_claims(ctx.manifest)
    must_remain_non_active = ctx.manifest.get("successor_must_remain_non_active") is True
    expected_chunks = int(
        ctx.counts.get("chunks_present") or ctx.counts.get("chunks_expected") or 0
    )
    written = int(ctx.counts.get("chunks_written") or 0)
    vectors = int(ctx.counts.get("vectors") or 0)
    if written != vectors:
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING,
            "chunk_embedding_count_mismatch",
            "chunk count and embedding count do not match",
        )
    if expected_chunks and written and written != expected_chunks:
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING,
            "chunk_embedding_count_mismatch",
            "written chunks do not match the approved chunk count",
        )
    privacy_report = build_candidate_privacy_report(ctx.settings, ctx.database)
    _write_new_json(staging / "privacy-report.json", privacy_report)
    _write_new_json(staging / "approved-source-manifest.json", ctx.manifest)
    _write_new_bytes(
        staging / "quality-policy.yaml",
        (ctx.settings.project_root / "config/policy.yaml").read_bytes(),
    )
    _write_new_bytes(
        staging / "retrieval-policy.yaml",
        (ctx.settings.project_root / "config/retrieval_policy.yaml").read_bytes(),
    )
    _write_new_bytes(
        staging / "assessment-guidance-bundle.json",
        canonical_bundle_bytes(OWNER_ASSESSMENT_BUNDLE),
    )
    _write_new_bytes(
        staging / "retrieval-benchmark-v1.1.jsonl",
        (ctx.settings.project_root / "benchmarks/retrieval/v1.1.jsonl").read_bytes(),
    )
    _write_new_bytes(
        staging / "retrieval-benchmark-v1.1.freeze.json",
        (ctx.settings.project_root / "benchmarks/retrieval/v1.1.freeze.json").read_bytes(),
    )
    provision_path = ctx.settings.project_root / "config/provision_verification.v1.json"
    if provision_path.is_file():
        provision_bytes = provision_path.read_bytes()
    elif ctx.settings.test_mode:
        from .provision_verification import TEST_EMPTY_BYTES

        provision_bytes = TEST_EMPTY_BYTES
    else:
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING,
            "provision_verification_missing",
            "provision-verification registry is required",
        )
    _write_new_bytes(staging / "provision-verification.v1.json", provision_bytes)
    repository.seal_staging(
        ctx.build_id,
        chunk_count=int(ctx.counts["chunks_written"]),
        embedding_model=ctx.embedding_model,
        reranker_model=ctx.reranker_model,
        source_manifest_sha256=str(ctx.manifest["manifest_sha256"]),
        source_scan_id=str(ctx.manifest.get("source_scan_id") or "") or None,
        source_scan_manifest_sha256=str(ctx.manifest.get("source_scan_manifest_sha256") or "")
        or None,
        finalize=False,
    )
    evaluation = {
        "schema": "legalbot.index-evaluation.v2",
        "passed": isolation,
        "promotion_eligible": (
            isolation and privacy_report.get("passed") is True and not must_remain_non_active
        ),
        "scoped_corpus_id": ctx.corpus_id,
        "integrity": {
            "approved_only": True,
            **source_lane_integrity,
            "successor_must_remain_non_active": must_remain_non_active,
            "chunk_count": ctx.counts["chunks_written"],
            "vector_count": ctx.counts["vectors"],
            "vector_dimensions": VECTOR_DIMENSIONS,
            "source_manifest_sha256": ctx.manifest["manifest_sha256"],
            "source_snapshot_stable": True,
            "lance_tree_sha256": lance_tree,
            "physical_lane_isolation": isolation,
            "physical_lane_counts": lane_counts,
            "source_scan_id": ctx.manifest.get("source_scan_id"),
            "source_scan_manifest_sha256": ctx.manifest.get("source_scan_manifest_sha256"),
            "scan_reconciled": ctx.manifest.get("source_scan_reconciled") is True,
            "vector_reuse": vector_reuse_integrity,
        },
        "privacy": privacy_report,
        "created_at": utc_iso(),
    }
    _write_new_json(staging / "evaluation.json", evaluation)
    if evaluation["passed"] is not True:
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING, "integrity_failed", "candidate integrity failed"
        )
    privacy_findings = (
        (privacy_report.get("finding_counts") or {}) if isinstance(privacy_report, dict) else {}
    )
    if (
        privacy_report.get("passed") is False
        or int(privacy_findings.get("absolute_path_in_index_row") or 0) > 0
    ):
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING,
            "private_path_leakage",
            "candidate privacy audit failed; private path leakage cannot be promoted",
        )
    ctx.counts["promotion_eligible"] = bool(evaluation.get("promotion_eligible"))
    seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": ctx.build_id,
        "manifest_sha256": _file_sha256(staging / "manifest.json"),
        "evaluation_sha256": _file_sha256(staging / "evaluation.json"),
        "privacy_report_sha256": _file_sha256(staging / "privacy-report.json"),
        "source_manifest_file_sha256": _file_sha256(staging / "approved-source-manifest.json"),
        "quality_policy_sha256": _file_sha256(staging / "quality-policy.yaml"),
        "retrieval_policy_sha256": _file_sha256(staging / "retrieval-policy.yaml"),
        "assessment_guidance_sha256": _file_sha256(staging / "assessment-guidance-bundle.json"),
        "retrieval_benchmark_sha256": _file_sha256(staging / "retrieval-benchmark-v1.1.jsonl"),
        "retrieval_freeze_sha256": _file_sha256(staging / "retrieval-benchmark-v1.1.freeze.json"),
        "provision_verification_sha256": _file_sha256(staging / "provision-verification.v1.json"),
        "physical_lane_manifest_sha256": _file_sha256(lane_manifest_path),
        "source_scan_manifest_sha256": ctx.manifest.get("source_scan_manifest_sha256"),
        "lance_tree_sha256": lance_tree,
        "scoped_corpus_id": ctx.corpus_id,
        "sealed_at": utc_iso(),
        "promotion": "not_requested",
    }
    if vector_reuse_report_sha256 is not None and ctx.parent_vector_source is not None:
        seal.update(
            {
                "vector_reuse_report_sha256": vector_reuse_report_sha256,
                "parent_vector_build_id": ctx.parent_vector_source.identity.build_id,
                "parent_vector_seal_sha256": ctx.parent_vector_source.identity.seal_sha256,
            }
        )
    _write_new_json(staging / "seal.json", seal)
    ctx.counts["candidate_manifest_hash"] = _file_sha256(staging / "seal.json")
    ctx.counts["benchmark"] = {
        "passed": False,
        "reason": "owner_approved_retrieval_benchmark_absent",
        "promotion_eligible": False,
    }
    benchmark = ctx.counts.get("benchmark") or {}
    if benchmark.get("ran") is True and benchmark.get("passed") is not True:
        raise IndexBuildStageError(
            IndexBuildStage.VALIDATING,
            "benchmark_threshold_failure",
            "retrieval benchmark threshold failed",
        )


def _iter_scoped_chunks(
    ctx: IndexBuildContext,
    embedder: Any,
    catalogue_row_to_indexed: Callable[..., IndexedChunk],
    prompt_safe: Callable[[Any], str],
    *,
    after_chunk_key: str | None = None,
    parent_vector_lookup: Callable[[list[ChunkIdentity]], dict[str, tuple[float, ...]]]
    | None = None,
    reuse_counts: dict[str, int] | None = None,
) -> Any:
    from .embedding_progress import parse_chunk_key
    from .service import INDEX_EMBED_BATCH_SIZE

    allowlists = ctx.manifest.get("locator_allowlists") or {}
    resume_source: str | None = None
    resume_ordinal = -1
    if after_chunk_key:
        resume_source, resume_ordinal, _chunk_id = parse_chunk_key(after_chunk_key)
        del _chunk_id
    seen_resume_source = resume_source is None
    lane_bindings = {
        binding.source_version_id: binding
        for binding in source_lane_bindings_for_manifest(ctx.manifest)
    }
    select_sql = """
        SELECT
          d.id AS document_id, d.content_sha256 AS document_sha256,
          d.source_identity_id, d.representation_group_id,
          d.retrieval_canonical, d.status AS document_status, d.lane,
          d.subject_primary, d.jurisdiction,
          sv.id AS source_version_id, sv.version_sha256, sv.title,
          sv.author_or_body, sv.source_date, sv.as_of_date, sv.canonical_url,
          sv.created_at AS source_last_updated_at,
          sv.stable_identifier, sv.currentness_status, sv.licence_name,
          sv.licence_url, sv.review_status, sv.metadata_json AS source_metadata_json,
          c.id AS chunk_id, c.ordinal, c.heading_path, c.locator, c.stream,
          c.text_sha256, c.markdown_text, c.metadata_json AS chunk_metadata_json
        FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE c.source_version_id = ?
          AND sv.review_status='approved'
          AND c.stream='body'
          AND d.lane=?
          AND d.status='citable'
          AND d.retrieval_canonical=1
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use')=1
          AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '')<>'prohibited'
          AND c.ordinal > ?
        ORDER BY c.ordinal
        LIMIT ?
        """
    for source_id in ctx.source_ids:
        binding = lane_bindings.get(source_id)
        if binding is None:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "source_lane_binding_missing",
                "approved source has no frozen catalogue-lane binding",
            )
        if resume_source is not None and not seen_resume_source:
            if source_id != resume_source:
                continue
            seen_resume_source = True
            last_ordinal = resume_ordinal
        else:
            last_ordinal = -1
        while True:
            rows = ctx.database.fetchall(
                select_sql,
                (
                    source_id,
                    binding.catalogue_lane,
                    last_ordinal,
                    INDEX_EMBED_BATCH_SIZE,
                ),
            )
            if not rows:
                break
            last_ordinal = int(rows[-1]["ordinal"])
            rows = [
                row
                for row in rows
                if chunk_locator_allowed(
                    str(row["stable_identifier"]), str(row["locator"] or ""), allowlists
                )
            ]
            if not rows:
                continue
            prompt_texts = [prompt_safe(row) for row in rows]
            child_identities = [
                ChunkIdentity(
                    chunk_id=str(row["chunk_id"]),
                    content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
                )
                for row, text in zip(rows, prompt_texts, strict=True)
            ]
            reused = (
                parent_vector_lookup(child_identities) if parent_vector_lookup is not None else {}
            )
            missing_indexes = [
                index
                for index, identity in enumerate(child_identities)
                if identity.chunk_id not in reused
            ]
            embedded = embedder.embed_documents([prompt_texts[index] for index in missing_indexes])
            if len(embedded) != len(missing_indexes):
                raise IndexBuildStageError(
                    IndexBuildStage.EMBEDDING,
                    "embedding_batch_count_mismatch",
                    "embedding provider returned an incomplete changed-chunk batch",
                )
            vectors_by_index = {
                index: vector for index, vector in zip(missing_indexes, embedded, strict=True)
            }
            for index, row in enumerate(rows):
                identity = child_identities[index]
                vector = reused.get(identity.chunk_id)
                if vector is None:
                    vector = vectors_by_index[index]
                    if reuse_counts is not None:
                        reuse_counts["embedded"] = reuse_counts.get("embedded", 0) + 1
                elif reuse_counts is not None:
                    reuse_counts["reused"] = reuse_counts.get("reused", 0) + 1
                indexed = catalogue_row_to_indexed(row, vector)
                yield _apply_source_lane_binding(indexed, binding)
    if resume_source is not None and not seen_resume_source:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "resume_cursor_missing",
            "resume cursor does not match the frozen chunk stream",
        )


def _apply_source_lane_binding(
    chunk: IndexedChunk,
    binding: SourceLaneBinding,
) -> IndexedChunk:
    """Keep GE guidance/procedure labels distinct inside the legal-source table."""

    source_id = str(chunk.metadata.get("source_version_id") or "")
    catalogue_lane = str(chunk.metadata.get("catalog_lane") or "")
    if source_id != binding.source_version_id or catalogue_lane != binding.catalogue_lane:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "source_lane_binding_mismatch",
            "catalogue row departed from its frozen source-lane binding",
        )
    expected_material_lane = MaterialLane(binding.material_lane)
    if binding.scope_lane == "official_procedure":
        if chunk.material_lane not in {
            MaterialLane.PRIMARY_AUTHORITY,
            MaterialLane.OFFICIAL_GUIDANCE,
        }:
            raise IndexBuildStageError(
                IndexBuildStage.EMBEDDING,
                "source_lane_binding_mismatch",
                "official procedure row has an incompatible catalogue material lane",
            )
    elif chunk.material_lane is not expected_material_lane:
        raise IndexBuildStageError(
            IndexBuildStage.EMBEDDING,
            "source_lane_binding_mismatch",
            "catalogue material lane departed from its frozen GE scope label",
        )
    metadata = dict(chunk.metadata)
    metadata["ge_scope_lane"] = binding.scope_lane
    return replace(chunk, material_lane=expected_material_lane, metadata=metadata)


def default_session_corpus_id(*, capped: bool) -> str:
    return SESSION_SCOPED_CORPUS_ID if capped else SCOPED_CORPUS_ID
