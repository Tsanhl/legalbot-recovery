from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.db import JobQueueCapacityError
from app.jobs import INDEX_STAGE_SECONDS, INDEX_WORKFLOW_SECONDS
from app.retrieval.embedding_progress import (
    build_checkpoint,
    chunk_key,
    identities_match,
    load_checkpoint,
    save_checkpoint,
)
from app.retrieval.incomplete_index_audit import (
    ExpectedIndexRow,
    ObservedIndexRow,
    compare_checkpoint_to_expected_prefix,
    compare_index_identities,
    compare_ordered_index_prefix,
)
from app.retrieval.index_build import (
    IndexBuildConflictError,
    IndexBuildContext,
    IndexBuildRunner,
    IndexBuildStageError,
    _completed_prefix_source_ids,
    _resumed_vector_counts,
    _run_stage,
    enqueue_index_build,
)
from app.retrieval.index_recovery import (
    attest_allowed,
    rearm_index_job_deadlines,
    reconcile_embedding_checkpoint_to_observed_prefix,
    recover_index_embedding,
    resume_index_build,
    resume_lease_lost_index_build,
    retry_index_build,
)
from app.retrieval.index_stage_policy import (
    EMBEDDING_STALL_SECONDS,
    EmbeddingProgressGuard,
    IndexDeadlineExceeded,
    embedding_absolute_seconds,
)
from app.retrieval.lancedb import ImmutableLanceRepository
from app.retrieval.models import VECTOR_DIMENSIONS
from app.retrieval.retrieval_v1 import attest_retrieval_v1
from app.types import IndexBuildStage, JobStatus


def _write_packs(project: Path) -> None:
    (project / "config").mkdir(parents=True, exist_ok=True)
    (project / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0", "url": "x"},
                "items": [{"identity": "ukpga/1977/50", "title": "Unfair Contract Terms Act 1977"}],
            }
        ),
        encoding="utf-8",
    )
    (project / "config" / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0"},
                "items": [],
            }
        ),
        encoding="utf-8",
    )


def _seed_authority(database, tmp_path: Path, *, n_chunks: int = 2) -> None:
    from test_index_build_jobs import _seed_authority as seed

    seed(database, tmp_path, n_chunks=n_chunks)


def _settings(tmp_path: Path):
    from app.config import Settings

    return Settings(project_root=tmp_path, test_mode=True)


def _queued_build(database, tmp_path: Path, *, build_id: str, **kwargs):
    project = tmp_path / "project"
    _write_packs(project)
    _seed_authority(database, project, n_chunks=int(kwargs.pop("n_chunks", 2)))
    settings = _settings(project)
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id="test-corpus",
        build_id=build_id,
        skip_embedding=kwargs.pop("skip_embedding", True),
        fail_at_stage=kwargs.pop("fail_at_stage", None),
        **kwargs,
    )
    return settings, queued


def test_embedding_budget_is_stage_specific_not_a_global_two_hour_bump() -> None:
    assert INDEX_STAGE_SECONDS == 7_200
    assert INDEX_WORKFLOW_SECONDS == 43_200
    assert embedding_absolute_seconds(0) == 7_200
    assert embedding_absolute_seconds(149_855) == 44_956
    assert embedding_absolute_seconds(149_855) > INDEX_WORKFLOW_SECONDS
    assert embedding_absolute_seconds(222_200) == 66_660
    assert embedding_absolute_seconds(1_000_000) == 86_400


def test_embedding_progress_exceeding_two_hours_still_completes() -> None:
    clock = {"t": 0.0}
    now = datetime(2026, 8, 18, tzinfo=UTC)
    guard = EmbeddingProgressGuard(
        stall_seconds=EMBEDDING_STALL_SECONDS,
        clock=lambda: clock["t"],
        now=lambda: now,
        workflow_deadline_at=(now + timedelta(hours=12)).isoformat(),
        cancel_requested=lambda: False,
    )
    for rows in (128, 256, 512, 1024):
        clock["t"] += 2_000
        guard.check(committed_row_count=rows)
        guard.note_committed(rows)
    assert clock["t"] == 8_000
    assert clock["t"] > INDEX_STAGE_SECONDS
    guard.check(committed_row_count=1024)


def test_embedding_stall_without_durable_progress_fails() -> None:
    clock = {"t": 0.0}
    now = datetime(2026, 8, 18, tzinfo=UTC)
    guard = EmbeddingProgressGuard(
        stall_seconds=10,
        clock=lambda: clock["t"],
        now=lambda: now,
        workflow_deadline_at=(now + timedelta(hours=12)).isoformat(),
        cancel_requested=lambda: False,
    )
    clock["t"] = 11
    with pytest.raises(IndexDeadlineExceeded, match="no durable progress"):
        guard.check()


def test_workflow_deadline_is_a_hard_boundary() -> None:
    clock = {"t": 0.0}
    now = datetime(2026, 8, 18, tzinfo=UTC)
    guard = EmbeddingProgressGuard(
        stall_seconds=1_800,
        clock=lambda: clock["t"],
        now=lambda: now + timedelta(hours=13),
        workflow_deadline_at=(now + timedelta(hours=12)).isoformat(),
        cancel_requested=lambda: False,
    )
    with pytest.raises(IndexDeadlineExceeded) as exc:
        guard.check(committed_row_count=10)
    assert exc.value.reason_code == "workflow_deadline_exceeded"


def test_completed_stage_is_not_rejected_post_hoc(database, tmp_path) -> None:
    settings, queued = _queued_build(database, tmp_path, build_id="posthoc-ok")
    clock = {"t": 0.0}

    def _long_complete(_ctx: IndexBuildContext) -> None:
        clock["t"] += 10_000

    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id=queued["job_id"],
        build_id="posthoc-ok",
        corpus_id="test-corpus",
        manifest={"manifest_sha256": "a" * 64, "sources": [], "chunk_count": 2},
        source_ids=("sv-ucta",),
        embedding_model="legalbot-test/hash-embedding-1024",
        reranker_model="legalbot-test/hash-reranker",
        build_dir=settings.index_dir / "builds" / "posthoc-ok",
        timings={},
        counts={"chunks_present": 2},
        skip_embedding=True,
        clock=lambda: clock["t"],
        now=lambda: datetime.now(UTC),
    )
    _run_stage(ctx, IndexBuildStage.SCANNING, _long_complete)
    assert clock["t"] > INDEX_STAGE_SECONDS
    attempt = database.completed_stage_attempt(queued["job_id"], "scanning", "index")
    assert attempt is not None
    assert attempt["status"] == "complete"
    assert ctx.timings["scanning"]["duration_ms"] >= 10_000_000


def test_exact_set_comparison_not_count_only() -> None:
    expected = (
        ExpectedIndexRow("chunk-0", "h0", "sv-ucta", 0),
        ExpectedIndexRow("chunk-1", "h1", "sv-ucta", 1),
    )
    swapped = (
        ObservedIndexRow("chunk-0", "h0", "sv-ucta", VECTOR_DIMENSIONS, "authority"),
        ObservedIndexRow("chunk-1", "h1-wrong", "sv-ucta", VECTOR_DIMENSIONS, "authority"),
    )
    same_count = compare_index_identities(expected, swapped)
    assert same_count["observed_total_rows"] == 2
    assert same_count["embedding_complete"] is False
    assert same_count["content_hash_mismatches"] == ["chunk-1"]
    matching = (
        ObservedIndexRow("chunk-0", "h0", "sv-ucta", VECTOR_DIMENSIONS, "authority"),
        ObservedIndexRow("chunk-1", "h1", "sv-ucta", VECTOR_DIMENSIONS, "authority"),
    )
    complete = compare_index_identities(expected, matching)
    assert complete["embedding_complete"] is True
    partial = compare_index_identities(
        expected,
        (ObservedIndexRow("chunk-0", "h0", "sv-ucta", VECTOR_DIMENSIONS, "authority"),),
    )
    assert partial["embedding_complete"] is False
    assert partial["missing_expected_chunk_ids"] == ["chunk-1"]


def test_ordered_prefix_binds_position_lane_dimensions_and_checkpoint() -> None:
    from app.retrieval.embedding_progress import update_rolling_digest

    expected = (
        ExpectedIndexRow("chunk-0", "h0", "source-a", 0),
        ExpectedIndexRow("chunk-1", "h1", "source-a", 1),
        ExpectedIndexRow("chunk-2", "h2", "source-b", 0),
    )
    observed = (
        ObservedIndexRow("chunk-0", "h0", "source-a", VECTOR_DIMENSIONS, "authority"),
        ObservedIndexRow("chunk-1", "h1", "source-a", VECTOR_DIMENSIONS, "authority"),
    )
    prefix = compare_ordered_index_prefix(expected, observed)
    assert prefix["exact_ordered_prefix"] is True
    assert prefix["verified_prefix"]["completed_row_count"] == 2

    checkpoint = build_checkpoint(
        build_id="prefix-build",
        source_manifest_sha256="0" * 64,
        ordered_chunk_stream_sha256="1" * 64,
        parser_version="parser",
        chunker_version="chunker",
        index_schema_version="schema",
        embedding_model="embed",
        dtype="float16",
        vector_dimensions=VECTOR_DIMENSIONS,
        batch_size=8,
        policy_sha256="2" * 64,
        assessment_bundle_sha256="3" * 64,
        provision_verification_sha256="4" * 64,
        completed_row_count=1,
        last_deterministic_chunk_key=chunk_key("source-a", 0, "chunk-0"),
        rolling_digest=update_rolling_digest("", chunk_id="chunk-0", content_sha256="h0"),
        physical_lane_counts={"authority": 1},
    )
    status = compare_checkpoint_to_expected_prefix(
        checkpoint, expected, observed_row_count=len(observed)
    )
    assert status["checkpoint_prefix_match"] is True
    assert status["checkpoint_trails_observed_rows"] is True
    assert status["uncheckpointed_observed_rows"] == 1

    reordered = (observed[1], observed[0])
    mismatch = compare_ordered_index_prefix(expected, reordered)
    assert mismatch["exact_ordered_prefix"] is False
    assert mismatch["prefix_mismatch_count"] >= 1


def test_resumed_source_count_includes_the_completed_ordered_prefix() -> None:
    expected = [
        ExpectedIndexRow("chunk-0", "h0", "source-a", 0),
        ExpectedIndexRow("chunk-1", "h1", "source-a", 1),
        ExpectedIndexRow("chunk-2", "h2", "source-b", 0),
        ExpectedIndexRow("chunk-3", "h3", "source-c", 0),
    ]

    assert _completed_prefix_source_ids(expected, 0) == set()
    assert _completed_prefix_source_ids(expected, 2) == {"source-a"}
    assert _completed_prefix_source_ids(expected, 3) == {"source-a", "source-b"}
    assert _completed_prefix_source_ids(expected, 4) == {
        "source-a",
        "source-b",
        "source-c",
    }
    with pytest.raises(ValueError, match="exceeds the expected ordered stream"):
        _completed_prefix_source_ids(expected, 5)


def test_resumed_vector_counts_include_nonreuse_prefix_and_fail_closed_on_unknown_split() -> None:
    assert _resumed_vector_counts(
        completed_row_count=3_712,
        restored_reused_count=0,
        restored_embedded_count=0,
        has_parent_vector_source=False,
    ) == {"reused": 0, "embedded": 3_712}
    assert _resumed_vector_counts(
        completed_row_count=3_712,
        restored_reused_count=2_000,
        restored_embedded_count=1_712,
        has_parent_vector_source=True,
    ) == {"reused": 2_000, "embedded": 1_712}
    with pytest.raises(ValueError, match="exact durable reuse split"):
        _resumed_vector_counts(
            completed_row_count=3_712,
            restored_reused_count=0,
            restored_embedded_count=0,
            has_parent_vector_source=True,
        )


def test_checkpoint_reconciliation_advances_only_across_exact_prefix(tmp_path: Path) -> None:
    from app.retrieval.embedding_progress import ordered_stream_digest, update_rolling_digest

    expected = (
        ExpectedIndexRow("chunk-0", "h0", "source-a", 0),
        ExpectedIndexRow("chunk-1", "h1", "source-a", 1),
    )
    observed = (
        ObservedIndexRow("chunk-0", "h0", "source-a", VECTOR_DIMENSIONS, "authority"),
        ObservedIndexRow("chunk-1", "h1", "source-a", VECTOR_DIMENSIONS, "authority"),
    )
    staging = tmp_path / ".prefix-build.incomplete"
    first_digest = update_rolling_digest("", chunk_id="chunk-0", content_sha256="h0")
    save_checkpoint(
        staging,
        build_checkpoint(
            build_id="prefix-build",
            source_manifest_sha256="0" * 64,
            ordered_chunk_stream_sha256=ordered_stream_digest(
                [chunk_key(row.source_version_id, row.ordinal, row.chunk_id) for row in expected]
            ),
            parser_version="parser",
            chunker_version="chunker",
            index_schema_version="schema",
            embedding_model="embed",
            dtype="float16",
            vector_dimensions=VECTOR_DIMENSIONS,
            batch_size=8,
            policy_sha256="2" * 64,
            assessment_bundle_sha256="3" * 64,
            provision_verification_sha256="4" * 64,
            completed_row_count=1,
            last_deterministic_chunk_key=chunk_key("source-a", 0, "chunk-0"),
            rolling_digest=first_digest,
            physical_lane_counts={"authority": 1, "teaching": 0, "assessment": 0},
        ),
    )

    result = reconcile_embedding_checkpoint_to_observed_prefix(
        staging,
        expected_rows=expected,
        observed_rows=observed,
        expected_build_id="prefix-build",
        expected_source_manifest_sha256="0" * 64,
    )

    assert result["changed"] is True
    assert result["old_completed_row_count"] == 1
    assert result["new_completed_row_count"] == 2
    assert result["uncheckpointed_rows_reconciled"] == 1
    reconciled = load_checkpoint(staging)
    assert reconciled is not None and reconciled.completed_row_count == 2

    with pytest.raises(RuntimeError, match="exact expected ordered prefix"):
        reconcile_embedding_checkpoint_to_observed_prefix(
            staging,
            expected_rows=expected,
            observed_rows=(observed[1], observed[0]),
            expected_build_id="prefix-build",
            expected_source_manifest_sha256="0" * 64,
        )


def _mark_posthoc_timeout(
    database, build_id: str, job_id: str, *, duration_ms: int = 17_753_428
) -> None:
    database.execute(
        """
        UPDATE index_builds
        SET status='failed', failure_reason_code='stage_timeout',
            promotion_decision='blocked_failed',
            stage_timings_json=?, counts_json=?
        WHERE id=?
        """,
        (
            json.dumps({"embedding": {"duration_ms": duration_ms}}, sort_keys=True),
            json.dumps({"chunks_written": 2, "vectors": 2, "documents": 1}, sort_keys=True),
            build_id,
        ),
    )
    database.update_job(
        job_id,
        status="failed",
        stage="failed",
        progress=1,
        message="Index-build failed. ACTIVE.json was not written.",
        error_code="stage_timeout",
    )


def test_complete_staging_recovers_without_reembedding(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="recover-complete",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    _mark_posthoc_timeout(database, "recover-complete", queued["job_id"])
    staging = settings.index_dir / "builds" / ".recover-complete.incomplete"
    staging.mkdir(parents=True)
    failed_before = database.fetchall(
        "SELECT status, error_code FROM job_stage_attempts WHERE job_id=? AND stage_key='embedding'",
        (queued["job_id"],),
    )
    assert [str(row["status"]) for row in failed_before] == ["failed"]
    report = {
        "embedding_complete": True,
        "source_manifest_match": True,
        "observed_total_rows": 2,
        "expected_chunks": 2,
        "observed_source_version_count": 1,
        "observed_rows_per_physical_lane": {"authority": 2},
        "report_sha256": "a" * 64,
    }
    result = recover_index_embedding(
        settings,
        database,
        "recover-complete",
        continue_build=True,
        audit_report=report,
    )
    assert result["recovered"] is True
    assert result["status"] == "queued"
    assert result["queued_for_dedicated_worker"] is True
    assert result["active_written"] is False
    assert not (settings.index_dir / "ACTIVE.json").exists()
    recovered_job = database.job(queued["job_id"])
    assert recovered_job is not None
    assert recovered_job["status"] == "queued"
    assert recovered_job["lease_owner"] is None
    attempts = database.fetchall(
        """
        SELECT status, attempt_number FROM job_stage_attempts
        WHERE job_id=? AND stage_key='embedding' ORDER BY attempt_number
        """,
        (queued["job_id"],),
    )
    assert [str(row["status"]) for row in attempts] == ["failed", "complete"]
    build = database.fetchone("SELECT * FROM index_builds WHERE id='recover-complete'")
    counts = json.loads(str(build["counts_json"]))
    assert counts["recovered_from_posthoc_stage_timeout"] is True
    assert counts["chunks_written"] == 2


def test_partial_staging_cannot_be_marked_complete(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="recover-partial",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    _mark_posthoc_timeout(database, "recover-partial", queued["job_id"])
    (settings.index_dir / "builds" / ".recover-partial.incomplete").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="not an exact complete embedding"):
        recover_index_embedding(
            settings,
            database,
            "recover-partial",
            continue_build=False,
            audit_report={
                "embedding_complete": False,
                "source_manifest_match": True,
                "observed_total_rows": 1,
                "expected_chunks": 2,
                "report_sha256": "b" * 64,
            },
        )
    assert (settings.index_dir / "builds" / ".recover-partial.incomplete").is_dir()


def test_legacy_incomplete_without_checkpoint_refuses_automatic_resume(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="legacy-incomplete",
        skip_embedding=False,
    )
    staging = settings.index_dir / "builds" / ".legacy-incomplete.incomplete"
    staging.mkdir(parents=True)
    (staging / "keep.bin").write_bytes(b"hours")
    with pytest.raises(IndexBuildStageError) as exc:
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    assert exc.value.reason_code == "legacy_incomplete_staging", repr(exc.value)
    assert (staging / "keep.bin").is_file()


def test_manifest_model_mismatch_refuses_resume(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="mismatch-resume",
        skip_embedding=False,
    )
    staging = settings.index_dir / "builds" / ".mismatch-resume.incomplete"
    staging.mkdir(parents=True)
    save_checkpoint(
        staging,
        build_checkpoint(
            build_id="mismatch-resume",
            source_manifest_sha256="0" * 64,
            ordered_chunk_stream_sha256="1" * 64,
            parser_version="wrong-parser",
            chunker_version="wrong-chunker",
            index_schema_version="wrong-schema",
            embedding_model="wrong-model",
            dtype="float16",
            vector_dimensions=8,
            batch_size=1,
            policy_sha256="2" * 64,
            assessment_bundle_sha256="3" * 64,
            provision_verification_sha256="4" * 64,
            completed_row_count=1,
            last_deterministic_chunk_key=chunk_key("sv-ucta", 0, "chunk-0"),
            rolling_digest="5" * 64,
            physical_lane_counts={"authority": 1},
        ),
    )
    with pytest.raises(IndexBuildStageError) as exc:
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    assert exc.value.reason_code == "embedding_identity_mismatch", repr(exc.value)
    assert (staging / "lance" / "embedding-progress.v1.json").is_file()


def test_embedding_checkpoint_pins_parent_vector_seal() -> None:
    values = {
        "build_id": "child-build",
        "source_manifest_sha256": "0" * 64,
        "ordered_chunk_stream_sha256": "1" * 64,
        "parser_version": "parser-v1",
        "chunker_version": "chunker-v1",
        "index_schema_version": "index-v1",
        "embedding_model": "embed-v1",
        "dtype": "float16",
        "vector_dimensions": 1024,
        "batch_size": 8,
        "policy_sha256": "2" * 64,
        "assessment_bundle_sha256": "3" * 64,
        "provision_verification_sha256": "4" * 64,
        "parent_vector_build_id": "parent-build",
        "parent_vector_seal_sha256": "5" * 64,
    }
    checkpoint = build_checkpoint(
        **values,
        completed_row_count=1,
        last_deterministic_chunk_key=chunk_key("source", 0, "chunk"),
        rolling_digest="6" * 64,
        physical_lane_counts={"authority": 1},
    )
    assert identities_match(checkpoint, **values)
    assert not identities_match(
        checkpoint,
        **{**values, "parent_vector_seal_sha256": "7" * 64},
    )


def test_retry_resets_deadlines_and_preserves_failed_attempts(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="retry-from-a",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    staging = settings.index_dir / "builds" / ".retry-from-a.incomplete"
    staging.mkdir(parents=True)
    (staging / "keep.bin").write_bytes(b"hours")
    old_job = database.job(queued["job_id"])
    database.execute(
        "UPDATE jobs SET workflow_deadline_at=?, queue_wait_deadline_at=? WHERE id=?",
        ("2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", queued["job_id"]),
    )
    with pytest.raises(IndexBuildConflictError):
        enqueue_index_build(
            settings,
            database,
            corpus_id="test-corpus",
            build_id="retry-from-b",
            skip_embedding=True,
        )
    retried = retry_index_build(settings, database, queued["job_id"], new_build_id="retry-from-b")
    assert retried["build_id"] == "retry-from-b"
    assert retried["previous_attempts_preserved"] is True
    assert retried["archived_staging"] is None
    assert retried["old_staging_preserved"] is True
    assert (staging / "keep.bin").read_bytes() == b"hours"
    new_job = database.job(retried["job_id"])
    assert str(new_job["workflow_deadline_at"]) > "2000-01-01"
    assert str(new_job["queue_wait_deadline_at"]) > "2000-01-01"
    old_attempts = database.fetchall(
        "SELECT status FROM job_stage_attempts WHERE job_id=?",
        (queued["job_id"],),
    )
    assert any(str(row["status"]) == "failed" for row in old_attempts)
    assert database.job(queued["job_id"])["idempotency_key"] == old_job["idempotency_key"]
    assert (
        database.fetchone("SELECT idempotency_key FROM index_builds WHERE id='retry-from-a'")[
            "idempotency_key"
        ]
        == old_job["idempotency_key"]
    )
    rearm = rearm_index_job_deadlines(database, retried["job_id"], status=JobStatus.QUEUED)
    assert rearm["workflow_deadline_at"] != "2000-01-01T00:00:00+00:00"


def test_recovery_refuses_foreign_lease_without_partial_mutation(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="recover-foreign-lease",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    _mark_posthoc_timeout(database, "recover-foreign-lease", queued["job_id"])
    (settings.index_dir / "builds" / ".recover-foreign-lease.incomplete").mkdir(parents=True)
    database.execute(
        """
        UPDATE jobs SET lease_owner='foreign-index-worker',
          lease_expires_at='2099-01-01T00:00:00+00:00', heartbeat_at=updated_at
        WHERE id=?
        """,
        (queued["job_id"],),
    )
    attempts_before = database.fetchall(
        "SELECT id,status FROM job_stage_attempts WHERE job_id=? ORDER BY id",
        (queued["job_id"],),
    )
    build_before = dict(
        database.fetchone("SELECT * FROM index_builds WHERE id='recover-foreign-lease'")
    )
    with pytest.raises(RuntimeError, match="worker lease"):
        recover_index_embedding(
            settings,
            database,
            "recover-foreign-lease",
            audit_report={
                "embedding_complete": True,
                "source_manifest_match": True,
                "observed_total_rows": 2,
                "expected_chunks": 2,
                "observed_source_version_count": 1,
                "observed_rows_per_physical_lane": {"authority": 2},
                "report_sha256": "d" * 64,
            },
        )
    job_after = database.job(queued["job_id"])
    assert job_after["status"] == "failed"
    assert job_after["lease_owner"] == "foreign-index-worker"
    assert job_after["lease_expires_at"] == "2099-01-01T00:00:00+00:00"
    assert (
        database.fetchall(
            "SELECT id,status FROM job_stage_attempts WHERE job_id=? ORDER BY id",
            (queued["job_id"],),
        )
        == attempts_before
    )
    assert (
        dict(database.fetchone("SELECT * FROM index_builds WHERE id='recover-foreign-lease'"))
        == build_before
    )


def test_exact_lease_loss_requeue_preserves_build_and_arms_24_hour_boundary(
    database, tmp_path
) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="lease-loss-same-build",
        skip_embedding=False,
    )
    worker_id = "lease-loss-test-worker"
    claimed = database.claim_next_job(worker_id, job_types=("index_build",))
    assert claimed is not None and int(claimed["attempt_count"]) == 1
    assert database.terminalize_owned_index_execution(
        queued["job_id"],
        worker_id,
        reason_code="lease_lost",
        message="Injected lease loss",
    )
    result = resume_lease_lost_index_build(
        settings,
        database,
        queued["job_id"],
        expected_build_id="lease-loss-same-build",
        expected_attempt_count=1,
        audit_report={
            "source_manifest_match": True,
            "exact_ordered_prefix": True,
            "checkpoint_prefix_match": True,
            "checkpoint_reconciliation_required": False,
            "observed_total_rows": 2,
            "checkpoint": {"completed_row_count": 2, "checkpoint_sha256": "a" * 64},
            "report_sha256": "b" * 64,
        },
        checkpoint_reconciliation={
            "build_id": "lease-loss-same-build",
            "exact_ordered_prefix": True,
            "changed": True,
        },
    )

    assert result["queued_for_exact_second_attempt"] is True
    assert result["new_build_created"] is False
    assert result["workflow_seconds"] == 86_400
    job = database.job(queued["job_id"])
    assert job["status"] == "queued"
    assert int(job["attempt_count"]) == 1
    assert datetime.fromisoformat(str(job["workflow_deadline_at"])) > datetime.now(UTC) + timedelta(
        hours=23
    )
    build = database.fetchone(
        "SELECT status,failure_reason_code FROM index_builds WHERE id=?",
        ("lease-loss-same-build",),
    )
    assert build["status"] == "queued"
    assert build["failure_reason_code"] is None


def test_generic_resume_refuses_rows_beyond_checkpoint(
    database, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.retrieval import index_recovery as recovery_module

    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="resume-trailing-checkpoint",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    staging = settings.index_dir / "builds" / ".resume-trailing-checkpoint.incomplete"
    staging.mkdir(parents=True)
    monkeypatch.setattr(
        recovery_module,
        "audit_incomplete_index",
        lambda *_args, **_kwargs: {
            "checkpoint_reconciliation_required": True,
            "resumable": False,
        },
    )

    with pytest.raises(RuntimeError, match="reconcile the ordered prefix"):
        resume_index_build(settings, database, queued["job_id"])


def test_resume_capacity_conflict_rolls_back_build_and_job(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="resume-capacity-target",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    database.create_job(
        job_id="index-capacity-blocker",
        encrypted_question=b"",
        question_summary="Private owner index build",
        request={"job_type": "index_build", "build_id": "capacity-blocker"},
        idempotency_key="capacity-blocker",
        pinned_index_build_id="capacity-blocker",
        job_type="index_build",
    )
    job_before = dict(database.job(queued["job_id"]))
    build_before = dict(
        database.fetchone("SELECT * FROM index_builds WHERE id='resume-capacity-target'")
    )
    with pytest.raises(JobQueueCapacityError, match="index_build_queue_capacity_exhausted"):
        resume_index_build(settings, database, queued["job_id"])
    assert dict(database.job(queued["job_id"])) == job_before
    assert (
        dict(database.fetchone("SELECT * FROM index_builds WHERE id='resume-capacity-target'"))
        == build_before
    )


def test_retry_conflict_preserves_old_staging_and_idempotency(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="retry-conflict-old",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    staging = settings.index_dir / "builds" / ".retry-conflict-old.incomplete"
    staging.mkdir(parents=True)
    (staging / "keep.bin").write_bytes(b"durable-old-staging")
    old_job_key = str(database.job(queued["job_id"])["idempotency_key"])
    old_build_key = str(
        database.fetchone("SELECT idempotency_key FROM index_builds WHERE id='retry-conflict-old'")[
            "idempotency_key"
        ]
    )
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,created_at
        ) VALUES ('retry-conflict-new','failed','data/indexes/builds/retry-conflict-new',
                  'test-embed','test-rerank','2026-08-22T00:00:00+00:00')
        """
    )
    with pytest.raises(IndexBuildConflictError, match="already exists"):
        retry_index_build(
            settings,
            database,
            queued["job_id"],
            new_build_id="retry-conflict-new",
        )
    assert (staging / "keep.bin").read_bytes() == b"durable-old-staging"
    assert database.job(queued["job_id"])["idempotency_key"] == old_job_key
    assert (
        database.fetchone("SELECT idempotency_key FROM index_builds WHERE id='retry-conflict-old'")[
            "idempotency_key"
        ]
        == old_build_key
    )


def test_failed_and_recovered_builds_cannot_write_active(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="no-active",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    assert not (settings.index_dir / "ACTIVE.json").exists()
    _mark_posthoc_timeout(database, "no-active", queued["job_id"])
    (settings.index_dir / "builds" / ".no-active.incomplete").mkdir(parents=True)
    recover_index_embedding(
        settings,
        database,
        "no-active",
        continue_build=True,
        audit_report={
            "embedding_complete": True,
            "source_manifest_match": True,
            "observed_total_rows": 2,
            "expected_chunks": 2,
            "observed_source_version_count": 1,
            "observed_rows_per_physical_lane": {"authority": 2},
            "report_sha256": "c" * 64,
        },
    )
    assert not (settings.index_dir / "ACTIVE.json").exists()
    assert database.active_index_id() is None


def test_attest_index_refuses_failed_and_requires_built_unscored(database, tmp_path) -> None:
    settings = _settings(tmp_path)
    now = "2026-08-18T00:00:00+00:00"
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at
        ) VALUES ('failed-attest', 'failed', 'data/indexes/builds/failed-attest',
                  0, 0, 0, 'embed', 'rerank', ?)
        """,
        (now,),
    )
    assert attest_allowed("failed") is False
    assert attest_allowed("built_unscored") is True
    with pytest.raises(ValueError, match="built_unscored"):
        attest_retrieval_v1(settings, database, build_id="failed-attest")
    database.execute("UPDATE index_builds SET status='candidate' WHERE id='failed-attest'")
    with pytest.raises(ValueError, match="built_unscored"):
        attest_retrieval_v1(settings, database, build_id="failed-attest")


def test_resume_without_checkpoint_refuses_legacy_timeout(database, tmp_path) -> None:
    settings, queued = _queued_build(
        database,
        tmp_path,
        build_id="resume-legacy",
        fail_at_stage="embedding",
        skip_embedding=True,
    )
    with pytest.raises(RuntimeError):
        IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    _mark_posthoc_timeout(database, "resume-legacy", queued["job_id"])
    (settings.index_dir / "builds" / ".resume-legacy.incomplete").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="not resumable"):
        resume_index_build(settings, database, queued["job_id"])
    assert (settings.index_dir / "builds" / ".resume-legacy.incomplete").is_dir()


def test_resume_iterator_skips_committed_chunk(database, tmp_path) -> None:
    from app.retrieval.index_build import _iter_scoped_chunks
    from app.retrieval.service import _catalogue_row_to_indexed, _prompt_safe_index_text
    from app.retrieval.source_manifest import build_approved_source_manifest, source_version_ids

    settings, queued = _queued_build(
        database, tmp_path, build_id="resume-cursor", skip_embedding=True, n_chunks=2
    )
    del queued

    class _Embedder:
        def embed_documents(self, texts: list[str]) -> list[list[float]]:
            return [[0.0] * VECTOR_DIMENSIONS for _ in texts]

    manifest = build_approved_source_manifest(database, settings, corpus_id="test-corpus")
    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id="index-resume-cursor",
        build_id="resume-cursor",
        corpus_id="test-corpus",
        manifest=manifest,
        source_ids=source_version_ids(manifest),
        embedding_model="legalbot-test/hash-embedding-1024",
        reranker_model="legalbot-test/hash-reranker",
        build_dir=settings.index_dir / "builds" / "resume-cursor",
        timings={},
        counts={},
        skip_embedding=True,
    )
    remaining = [
        chunk.chunk_id
        for chunk in _iter_scoped_chunks(
            ctx,
            _Embedder(),
            _catalogue_row_to_indexed,
            _prompt_safe_index_text,
            after_chunk_key=chunk_key("sv-ucta", 0, "chunk-0"),
        )
    ]
    assert remaining == ["chunk-1"]


def test_repository_open_resumable_does_not_create_or_delete(tmp_path: Path) -> None:
    repository = ImmutableLanceRepository(tmp_path / "indexes")
    with pytest.raises(FileNotFoundError):
        repository.open_resumable_staging("missing")
    staging = repository.prepare_new_staging("open-only")
    (staging / "row.bin").write_bytes(b"1")
    opened = repository.open_resumable_staging("open-only")
    assert opened == staging
    assert (staging / "row.bin").read_bytes() == b"1"
