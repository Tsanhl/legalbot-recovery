from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.jobs import (
    ANSWER_MAX_ATTEMPTS,
    CHUNKER_VERSION,
    INDEX_SCHEMA_VERSION,
    PARSER_VERSION,
    index_build_idempotency_key,
    policy_for,
)
from app.orchestration.index_worker import DedicatedIndexWorker
from app.retrieval.cache_keys import retrieval_cache_key
from app.retrieval.index_build import (
    IndexBuildConflictError,
    IndexBuildRunner,
    IndexBuildStageError,
    _finalize_or_reconcile_candidate,
    _run_stage,
    enqueue_index_build,
)
from app.retrieval.source_manifest import build_approved_source_manifest
from app.types import IndexBuildStage, JobType


def _seed_authority(database, tmp_path: Path, *, n_chunks: int = 2) -> None:
    now = "2026-08-13T00:00:00+00:00"
    chunk_text = "Section 2 restricts exclusion of negligence liability."
    markdown = tmp_path / "vault" / "source.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("# Unfair Contract Terms Act 1977\n\nSection 2.", encoding="utf-8")
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-ucta', ?, 'ukpga:1977:50', 'source-ucta.pdf', 'application/pdf',
                  'citable', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id, document_id, version_sha256, canonical_markdown_path, title,
          stable_identifier, currentness_status, licence_name, review_status,
          metadata_json, created_at
        ) VALUES ('sv-ucta', 'doc-ucta', ?, ?, 'Unfair Contract Terms Act 1977',
                  'ukpga:1977:50:enacted', 'historical', 'Open Government Licence v3.0',
                  'approved', ?, ?)
        """,
        (
            "a" * 64,
            str(markdown.relative_to(tmp_path.parent) if False else markdown),
            json.dumps(
                {
                    "eligible_for_model_use": True,
                    "ai_use_policy": "unreviewed",
                    "identity_verified": True,
                    "currentness_verified": False,
                    "citation_data": {"source_type": "legislation"},
                }
            ),
            now,
        ),
    )
    # store a project-relative path
    rel = "data/vault/source.md"
    (tmp_path / "data" / "vault").mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_text("# Unfair Contract Terms Act 1977\n\nSection 2.", encoding="utf-8")
    database.execute(
        "UPDATE source_versions SET canonical_markdown_path=? WHERE id='sv-ucta'",
        (rel,),
    )
    for index in range(n_chunks):
        database.execute(
            """
            INSERT INTO chunks(
              id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count, stream
            ) VALUES (?, 'sv-ucta', ?, 's 2', ?, ?, 12, 'body')
            """,
            (
                f"chunk-{index}",
                index,
                hashlib.sha256(chunk_text.encode("utf-8")).hexdigest(),
                chunk_text,
            ),
        )


def _settings(tmp_path: Path):
    from app.config import Settings

    return Settings(project_root=tmp_path, test_mode=True)


def test_answer_retry_policy_is_three_total_but_never_automatic() -> None:
    assert ANSWER_MAX_ATTEMPTS == 3
    assert policy_for(JobType.ANSWER).max_attempts == 3
    assert policy_for(JobType.INDEX_BUILD).max_attempts >= 2
    assert policy_for(JobType.SCHEDULED_TASK).dlq_after_cap is True
    assert policy_for(JobType.ANSWER).dlq_after_cap is False


def test_production_index_runner_requires_exact_worker_lease(database, tmp_path: Path) -> None:
    database.create_job(
        job_id="production-index-unleased",
        encrypted_question=b"",
        question_summary="Private owner index build",
        request={"job_type": "index_build", "build_id": "production-index-unleased"},
        pinned_index_build_id="production-index-unleased",
        job_type=JobType.INDEX_BUILD,
    )
    settings = Settings(project_root=tmp_path, test_mode=False)

    with pytest.raises(RuntimeError, match="dedicated worker's exact lease"):
        IndexBuildRunner(settings, database).run_sync("production-index-unleased")


def test_idempotency_key_is_stable() -> None:
    first = index_build_idempotency_key(
        corpus_id="ogl-uksc",
        approved_source_manifest_hash="a" * 64,
        parser_version=PARSER_VERSION,
        chunker_version=CHUNKER_VERSION,
        embedding_model_version="embed-v1",
        index_schema_version=INDEX_SCHEMA_VERSION,
    )
    second = index_build_idempotency_key(
        corpus_id="ogl-uksc",
        approved_source_manifest_hash="a" * 64,
        parser_version=PARSER_VERSION,
        chunker_version=CHUNKER_VERSION,
        embedding_model_version="embed-v1",
        index_schema_version=INDEX_SCHEMA_VERSION,
    )
    assert first == second
    assert "ogl-uksc" in first
    reused = index_build_idempotency_key(
        corpus_id="ogl-uksc",
        approved_source_manifest_hash="a" * 64,
        parser_version=PARSER_VERSION,
        chunker_version=CHUNKER_VERSION,
        embedding_model_version="embed-v1",
        index_schema_version=INDEX_SCHEMA_VERSION,
        parent_vector_build_id="parent-build",
        parent_vector_seal_sha256="b" * 64,
    )
    assert reused != first
    assert reused.endswith("parent-build|" + "b" * 64)


def test_duplicate_in_flight_build_is_rejected(database, tmp_path, monkeypatch) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
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
    _seed_authority(database, project)
    settings = _settings(project)
    first = enqueue_index_build(
        settings, database, corpus_id="test-corpus", build_id="build-one", skip_embedding=True
    )
    with pytest.raises(IndexBuildConflictError):
        enqueue_index_build(
            settings, database, corpus_id="test-corpus", build_id="build-two", skip_embedding=True
        )
    assert first["status"] == "queued"


def test_index_aggregate_duplicate_rolls_back_job_even_when_queue_is_full(
    database, tmp_path
) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
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
    _seed_authority(database, project)
    database.create_job(
        job_id="index-capacity-occupant",
        encrypted_question=b"",
        question_summary="Private owner index build",
        request={"job_type": JobType.INDEX_BUILD, "build_id": "capacity-occupant"},
        pinned_index_build_id="capacity-occupant",
        job_type=JobType.INDEX_BUILD,
    )
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,created_at
        ) VALUES ('atomic-conflict', 'failed', 'data/indexes/builds/atomic-conflict',
                  'old-embed', 'old-rerank', ?)
        """,
        (datetime.now(UTC).isoformat(),),
    )

    with pytest.raises(IndexBuildConflictError, match="already exists"):
        enqueue_index_build(
            _settings(project),
            database,
            corpus_id="test-corpus",
            build_id="atomic-conflict",
            skip_embedding=True,
        )

    assert database.job("index-atomic-conflict") is None
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS count FROM job_events WHERE job_id='index-atomic-conflict'"
        )["count"]
        == 0
    )
    assert (
        database.fetchone("SELECT status FROM index_builds WHERE id='atomic-conflict'")["status"]
        == "failed"
    )
    assert database.job("index-capacity-occupant")["status"] == "queued"


def test_stage_failure_injection_never_writes_active(database, tmp_path) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
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
    _seed_authority(database, project)
    settings = _settings(project)
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id="test-corpus",
        build_id="fail-embed",
        fail_at_stage="embedding",
        skip_embedding=False,
    )
    runner = IndexBuildRunner(settings, database)
    with pytest.raises(RuntimeError):
        runner.run_sync(queued["job_id"])
    row = database.fetchone("SELECT * FROM index_builds WHERE id='fail-embed'")
    assert row["status"] == "failed"
    assert row["stage"] == "failed"
    assert not (settings.index_dir / "ACTIVE.json").exists()
    job = database.job(queued["job_id"])
    assert job["status"] == "failed"


def test_leased_index_stage_failure_retries_once_then_stops_on_repeat(database, tmp_path) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
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
    _seed_authority(database, project)
    settings = _settings(project)
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id="test-corpus",
        build_id="leased-repeat-failure",
        fail_at_stage="embedding",
        skip_embedding=False,
    )

    first = database.claim_next_job("index-worker-first", job_types=(JobType.INDEX_BUILD,))
    assert first is not None
    DedicatedIndexWorker(
        settings, database, worker_id="index-worker-first", lease_seconds=60
    )._run_claim(dict(first))
    after_first = database.job(queued["job_id"])
    assert after_first is not None and after_first["status"] == "queued"
    assert int(after_first["attempt_count"]) == 1

    second = database.claim_next_job("index-worker-second", job_types=(JobType.INDEX_BUILD,))
    assert second is not None
    DedicatedIndexWorker(
        settings, database, worker_id="index-worker-second", lease_seconds=60
    )._run_claim(dict(second))
    after_second = database.job(queued["job_id"])
    assert after_second is not None and after_second["status"] == "failed"
    assert int(after_second["attempt_count"]) == 2
    decisions = database.retry_decisions("job", queued["job_id"])
    assert [str(row["decision_action"]) for row in decisions] == ["retry", "stop"]
    assert str(decisions[-1]["decision_reason"]) == "repeated_failure_fingerprint"


def test_leased_index_cancellation_is_terminal_and_never_requeued(database, tmp_path) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
    (project / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {
                    "name": "Open Government Licence",
                    "version": "3.0",
                    "url": "x",
                },
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
    _seed_authority(database, project)
    settings = _settings(project)
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id="test-corpus",
        build_id="leased-cancelled",
        skip_embedding=True,
    )
    claimed = database.claim_next_job("index-worker-cancel", job_types=(JobType.INDEX_BUILD,))
    assert claimed is not None
    assert database.request_cancel_job(queued["job_id"]) is True

    DedicatedIndexWorker(
        settings,
        database,
        worker_id="index-worker-cancel",
        lease_seconds=60,
    )._run_claim(dict(claimed))

    job = database.job(queued["job_id"])
    assert job is not None
    assert job["status"] == "cancelled"
    assert job["stage"] == "cancelled"
    assert job["error_code"] == "cancelled"
    assert database.retry_decisions("job", queued["job_id"]) == []
    build = database.fetchone("SELECT * FROM index_builds WHERE id='leased-cancelled'")
    assert build is not None
    assert build["status"] == "failed"
    assert build["failure_reason_code"] == "cancelled"
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_state_transitions_with_skip_embedding(database, tmp_path) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
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
    _seed_authority(database, project)
    settings = _settings(project)
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id="test-corpus",
        build_id="skip-embed",
        skip_embedding=True,
    )
    result = IndexBuildRunner(settings, database).run_sync(queued["job_id"])
    assert result["status"] == "built_unscored"
    stages = [
        str(row["stage_key"])
        for row in database.fetchall(
            "SELECT stage_key FROM job_stage_attempts WHERE job_id=? AND status='complete' ORDER BY started_at",
            (queued["job_id"],),
        )
    ]
    assert stages == [
        "scanning",
        "parsing",
        "chunking",
        "embedding",
        "building_lexical",
        "building_vector",
        "validating",
    ]
    assert not (settings.index_dir / "ACTIVE.json").exists()
    build = database.fetchone("SELECT * FROM index_builds WHERE id='skip-embed'")
    assert build["status"] == "built_unscored"
    assert build["promotion_decision"] == "not_requested"


def test_phase2a_held_successor_cannot_become_candidate_even_if_benchmark_passes(
    database, tmp_path
) -> None:
    job_id = "phase2a-held-successor"
    worker_id = "phase2a-held-index-worker"
    database.create_job(
        job_id=job_id,
        encrypted_question=b"",
        question_summary="Phase-2A held successor build",
        request={"job_type": "index_build", "build_id": job_id},
        pinned_index_build_id=job_id,
        job_type=JobType.INDEX_BUILD,
    )
    database.execute(
        """
        INSERT INTO index_builds(id,status,path,embedding_model,reranker_model,created_at)
        VALUES (?, 'building', ?, 'test-embed', 'test-rerank', ?)
        """,
        (job_id, f"data/indexes/builds/{job_id}", datetime.now(UTC).isoformat()),
    )
    assert database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,)) is not None
    settings = Settings(project_root=tmp_path, test_mode=True)
    ctx = SimpleNamespace(
        settings=settings,
        database=database,
        job_id=job_id,
        build_id=job_id,
        manifest={
            "omitted_required_families": [],
            "successor_must_remain_non_active": True,
        },
        counts={
            "candidate_manifest_hash": "a" * 64,
            "benchmark": {"passed": True, "promotion_eligible": True},
            "documents": 251,
            "chunks_written": 222_200,
            "vectors": 222_200,
        },
        timings={},
        skip_embedding=True,
        expected_lease_owner=worker_id,
        now=None,
    )

    result = IndexBuildRunner(settings, database)._mark_candidate(ctx)

    assert result == "built_unscored"
    assert ctx.counts["answer_release_eligible"] is False
    assert ctx.counts["successor_must_remain_non_active"] is True
    build = database.fetchone("SELECT * FROM index_builds WHERE id=?", (job_id,))
    assert build is not None and build["status"] == "built_unscored"
    assert build["stage"] == "built_unscored"
    job = database.job(job_id)
    assert job is not None and job["status"] == "complete"
    assert "non-ACTIVE held evidence" in job["user_message"]
    assert not (settings.index_dir / "ACTIVE.json").exists()


def test_answer_job_does_not_auto_retry_after_one_attempt(database, cipher) -> None:
    database.create_job(
        job_id="job-once",
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary="Private encrypted question",
        request={"task_type": "general", "word_target": 500},
        job_type="answer",
    )
    claimed = database.claim_next_job("worker-a")
    assert claimed is not None
    outcome = database.retry_or_fail_job(
        "job-once",
        "worker-a",
        error_code="Boom",
        input_or_condition_changed=False,
        condition_identity_sha256=None,
        retryable=False,
        retry_operation="terminal_answer_worker_stop",
    )
    assert outcome == "system_error"
    row = database.job("job-once")
    assert row["status"] == "system_error"
    assert int(row["attempt_count"]) == 1


def test_new_scheduled_job_is_rejected_and_legacy_replay_is_disabled(database, cipher) -> None:
    with pytest.raises(ValueError, match="not supported"):
        database.create_job(
            job_id="job-sched",
            encrypted_question=b"",
            question_summary="Private encrypted question",
            request={"job_type": "scheduled_task"},
            job_type="scheduled_task",
        )
    database.execute(
        """INSERT INTO jobs(
             id,status,stage,progress,encrypted_question,question_summary,
             request_json,job_type,dlq,created_at,updated_at
           ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            "legacy-scheduled",
            "dlq",
            "failed",
            1,
            b"",
            "Private encrypted question",
            '{"job_type":"scheduled_task"}',
            "scheduled_task",
            1,
            "2026-08-22T00:00:00+00:00",
            "2026-08-22T00:00:00+00:00",
        ),
    )
    assert database.replay_dlq_job("legacy-scheduled") is False


def test_retrieval_cache_key_includes_active_build_and_config() -> None:
    first = retrieval_cache_key(
        query="limitation",
        corpus_id="ogl-uksc",
        tenant_visibility="owner",
        jurisdiction="England and Wales",
        active_build_id="build-a",
        source_manifest_sha256="a" * 64,
        as_of_date="2026-08-15",
        task_type="problem",
        subject="professional negligence",
        material_lanes=["primary_authority"],
        filters={"review_states": ["approved"]},
        query_rewrite_version="rewrite-v1",
        retrieval_version="hybrid-v1",
        chunker_version="chunker-v1",
        embedding_version="embed-v1",
        reranker_version="rerank-v1",
        policy_version="policy-v1",
        retrieval_config={"embedder": "qwen", "limit": 30},
    )
    second = retrieval_cache_key(
        query="limitation",
        corpus_id="ogl-uksc",
        tenant_visibility="owner",
        jurisdiction="England and Wales",
        active_build_id="build-b",
        source_manifest_sha256="a" * 64,
        as_of_date="2026-08-15",
        task_type="problem",
        subject="professional negligence",
        material_lanes=["primary_authority"],
        filters={"review_states": ["approved"]},
        query_rewrite_version="rewrite-v1",
        retrieval_version="hybrid-v1",
        chunker_version="chunker-v1",
        embedding_version="embed-v1",
        reranker_version="rerank-v1",
        policy_version="policy-v1",
        retrieval_config={"embedder": "qwen", "limit": 30},
    )
    assert first != second
    same = retrieval_cache_key(
        query="limitation",
        corpus_id="ogl-uksc",
        tenant_visibility="owner",
        jurisdiction="England and Wales",
        active_build_id="build-a",
        source_manifest_sha256="a" * 64,
        as_of_date="2026-08-15",
        task_type="problem",
        subject="professional negligence",
        material_lanes=["primary_authority"],
        filters={"review_states": ["approved"]},
        query_rewrite_version="rewrite-v1",
        retrieval_version="hybrid-v1",
        chunker_version="chunker-v1",
        embedding_version="embed-v1",
        reranker_version="rerank-v1",
        policy_version="policy-v1",
        retrieval_config={"embedder": "qwen", "limit": 30},
    )
    assert first == same


def test_finalized_candidate_reconciliation_is_idempotent_for_exact_seal_bytes(
    database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    build_id = "reconcile-finalized-build"
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,created_at
        ) VALUES (?, 'building', ?, 'test-embed', 'test-rerank', ?)
        """,
        (
            build_id,
            f"data/indexes/builds/{build_id}",
            datetime.now(UTC).isoformat(),
        ),
    )
    final = settings.index_dir / "builds" / build_id
    final.mkdir(parents=True)
    seal_bytes = b'{"schema":"legalbot.test-finalization-seal.v1"}\n'
    (final / "seal.json").write_bytes(seal_bytes)
    expected_seal = hashlib.sha256(seal_bytes).hexdigest()
    verified_rows: list[dict[str, object]] = []

    def verify_exact_finalized_bytes(_settings: Settings, row: dict[str, object]) -> None:
        assert hashlib.sha256((final / "seal.json").read_bytes()).hexdigest() == expected_seal
        assert row["manifest_sha256"] == expected_seal
        assert row["candidate_manifest_hash"] == expected_seal
        verified_rows.append(row)

    monkeypatch.setattr(
        "app.retrieval.service._verify_durable_candidate_tree",
        verify_exact_finalized_bytes,
    )
    ctx = SimpleNamespace(
        settings=settings,
        database=database,
        build_id=build_id,
        counts={"documents": 3, "chunks_written": 7, "vectors": 7},
    )

    _finalize_or_reconcile_candidate(ctx, expected_seal_sha256=expected_seal)
    _finalize_or_reconcile_candidate(ctx, expected_seal_sha256=expected_seal)

    assert len(verified_rows) == 2
    assert (settings.index_dir / "builds" / f".{build_id}.incomplete").exists() is False
    assert (final / "seal.json").read_bytes() == seal_bytes


def test_index_stage_overrun_cannot_publish_completed_checkpoint(
    database,
    tmp_path: Path,
    cipher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    job_id = "index-stage-overrun"
    build_id = "build-stage-overrun"
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("index control job"),
        question_summary="Private encrypted question",
        request={"job_type": JobType.INDEX_BUILD, "build_id": build_id},
        job_type=JobType.INDEX_BUILD,
    )
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,created_at
        ) VALUES (?, 'queued', ?, 'test-embed', 'test-rerank', ?)
        """,
        (build_id, f"data/indexes/builds/{build_id}", datetime.now(UTC).isoformat()),
    )
    started_at = datetime(2026, 8, 22, 12, tzinfo=UTC)
    state = {"now": started_at, "clock": 0.0}

    def arm_deadline(armed_job_id: str, *, seconds: int) -> str:
        assert armed_job_id == job_id
        deadline = (started_at + timedelta(seconds=seconds)).isoformat()
        database.execute(
            "UPDATE jobs SET stage_started_at=?,stage_deadline_at=? WHERE id=?",
            (started_at.isoformat(), deadline, job_id),
        )
        return deadline

    monkeypatch.setattr(database, "arm_stage_deadline", arm_deadline)
    ctx = SimpleNamespace(
        settings=settings,
        database=database,
        job_id=job_id,
        build_id=build_id,
        counts={},
        timings={},
        expected_lease_owner=None,
        stage_deadline_at=None,
        fail_at_stage=None,
        clock=lambda: state["clock"],
        now=lambda: state["now"],
    )

    def finish_after_absolute_budget(_ctx: object) -> None:
        state["clock"] = 601.0
        state["now"] = started_at + timedelta(seconds=601)

    with pytest.raises(IndexBuildStageError) as stopped:
        _run_stage(ctx, IndexBuildStage.SCANNING, finish_after_absolute_budget)

    assert stopped.value.reason_code == "stage_timeout"
    attempts = database.fetchall(
        "SELECT status,error_code FROM job_stage_attempts "
        "WHERE job_id=? AND stage_key=? ORDER BY attempt_number",
        (job_id, IndexBuildStage.SCANNING),
    )
    assert [(row["status"], row["error_code"]) for row in attempts] == [("failed", "stage_timeout")]
    assert database.completed_stage_attempt(job_id, IndexBuildStage.SCANNING, "index") is None


def test_approved_manifest_builder_is_authority_lane_only(database, tmp_path) -> None:
    project = tmp_path / "project"
    (project / "config").mkdir(parents=True)
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
    _seed_authority(database, project)
    settings = _settings(project)
    manifest = build_approved_source_manifest(database, settings, corpus_id="test-corpus")
    assert manifest["authority_lane_only"] is True
    assert manifest["exclude_find_case_law_full_text"] is True
    assert manifest["source_count"] == 1
