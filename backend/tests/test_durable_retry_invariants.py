from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import app
from app.config import Settings
from app.db import Database, JobQueueCapacityError
from app.orchestration.index_worker import DedicatedIndexWorker
from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.retrieval.index_build import IndexBuildRunner, IndexBuildStageError
from app.types import JobType


def _enqueue_research(database: Database, task_id: str, *, max_attempts: int = 3) -> None:
    database.enqueue_research_task(
        task_id=task_id,
        idempotency_key=f"idem-{task_id}",
        task_type="gap_research",
        trigger_kind="scheduled",
        priority_band="medium",
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date="2026-08-20",
        query_sha256=hashlib.sha256(task_id.encode()).hexdigest(),
        max_attempts=max_attempts,
    )


def _create_index_job(database: Database, job_id: str) -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=b"",
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"job_type": JobType.INDEX_BUILD, "build_id": f"build-{job_id}"},
        job_type=JobType.INDEX_BUILD,
    )


def _create_answer_job(database: Database, job_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at, promoted_at
        ) VALUES ('active-answer-build', 'active', 'data/indexes/active-answer-build',
                  1, 1, 1, 'embed', 'rerank', ?, ?)
        """,
        (now, now),
    )
    database.create_job(
        job_id=job_id,
        encrypted_question=b"encrypted",
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"job_type": JobType.ANSWER, "word_target": 500},
        job_type=JobType.ANSWER,
        pinned_index_build_id="active-answer-build",
    )


def test_research_stops_on_second_semantically_identical_failure_even_if_input_hash_changes(
    database: Database,
) -> None:
    start = datetime(2026, 8, 20, 9, tzinfo=UTC)
    _enqueue_research(database, "research-repeat")

    first = database.claim_research_task("research-worker-a", now=start)
    assert first is not None and int(first["attempt_count"]) == 1
    assert (
        database.retry_or_fail_research_task(
            "research-repeat",
            "research-worker-a",
            reason="official_network_unavailable",
            retryable=True,
            retry_after_seconds=60,
            now=start,
        )
        == "retry_wait"
    )

    # Simulate a legacy/corrupt mutable binding.  It remains recorded for
    # audit, but must not make an identical semantic failure look novel.
    database.execute(
        "UPDATE research_tasks SET query_sha256=? WHERE id='research-repeat'",
        ("b" * 64,),
    )
    second = database.claim_research_task("research-worker-b", now=start + timedelta(seconds=61))
    assert second is not None and int(second["attempt_count"]) == 2
    assert (
        database.retry_or_fail_research_task(
            "research-repeat",
            "research-worker-b",
            reason="official_network_unavailable",
            retryable=True,
            retry_after_seconds=60,
            now=start + timedelta(seconds=61),
        )
        == "failed"
    )

    trace = database.retry_decisions("research", "research-repeat")
    assert [str(row["decision_action"]) for row in trace] == ["retry", "stop"]
    assert str(trace[-1]["decision_reason"]) == "repeated_failure_fingerprint"
    assert trace[0]["failure_fingerprint_sha256"] == trace[1]["failure_fingerprint_sha256"]
    assert trace[0]["input_identity_sha256"] != trace[1]["input_identity_sha256"]
    assert (
        database.claim_research_task("research-worker-c", now=start + timedelta(minutes=3)) is None
    )


def test_research_never_exceeds_three_total_attempts_and_clamps_legacy_rows(
    database: Database,
) -> None:
    start = datetime(2026, 8, 20, 10, tzinfo=UTC)
    _enqueue_research(database, "research-cap")
    for attempt in range(1, 4):
        now = start + timedelta(minutes=attempt - 1)
        claimed = database.claim_research_task(f"research-worker-{attempt}", now=now)
        assert claimed is not None and int(claimed["attempt_count"]) == attempt
        status = database.retry_or_fail_research_task(
            "research-cap",
            f"research-worker-{attempt}",
            reason=f"transient_condition_{attempt}",
            retryable=True,
            retry_after_seconds=30,
            now=now,
        )
    assert status == "failed"
    assert int(database.research_task("research-cap")["attempt_count"]) == 3
    assert len(database.retry_decisions("research", "research-cap")) == 3
    assert (
        database.claim_research_task("research-worker-4", now=start + timedelta(minutes=4)) is None
    )

    _enqueue_research(database, "research-legacy")
    database.execute(
        "UPDATE research_tasks SET max_attempts=5, attempt_count=3 WHERE id='research-legacy'"
    )
    assert (
        database.claim_research_task("research-worker-legacy", now=start + timedelta(minutes=5))
        is None
    )
    legacy = database.research_task("research-legacy")
    assert legacy["status"] == "failed"
    assert legacy["status_reason"] == "retry_cap_exhausted"


def test_index_job_stops_on_second_identical_failure(database: Database) -> None:
    _create_index_job(database, "index-repeat")
    for attempt in (1, 2):
        worker = f"index-worker-{attempt}"
        claimed = database.claim_next_job(worker, job_types=(JobType.INDEX_BUILD,))
        assert claimed is not None and int(claimed["attempt_count"]) == attempt
        status = database.retry_or_fail_job(
            "index-repeat",
            worker,
            error_code="transient_vector_store_failure",
            input_or_condition_changed=True,
            condition_identity_sha256=hashlib.sha256(
                f"repeat-condition-{attempt}".encode()
            ).hexdigest(),
            retry_operation="resume_failed_index_stage",
        )
    assert status == "failed"
    assert int(database.job("index-repeat")["attempt_count"]) == 2
    trace = database.retry_decisions("job", "index-repeat")
    assert [str(row["decision_action"]) for row in trace] == ["retry", "stop"]
    assert str(trace[-1]["decision_reason"]) == "repeated_failure_fingerprint"
    assert database.claim_next_job("index-worker-3", job_types=(JobType.INDEX_BUILD,)) is None


def test_index_worker_invalid_deadline_fails_only_claimed_job(
    database: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _create_index_job(database, "index-invalid-deadline")
    database.execute(
        "UPDATE jobs SET workflow_deadline_at='not-an-iso-deadline' WHERE id=?",
        ("index-invalid-deadline",),
    )
    claimed = database.claim_next_job("index-worker-invalid", job_types=(JobType.INDEX_BUILD,))
    assert claimed is not None

    def unexpected_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise AssertionError("invalid persisted deadline must stop before index execution")

    monkeypatch.setattr(
        "app.orchestration.index_worker.IndexBuildRunner.run_sync",
        unexpected_run,
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    DedicatedIndexWorker(
        settings,
        database,
        worker_id="index-worker-invalid",
        lease_seconds=60,
    )._run_claim(dict(claimed))

    row = database.job("index-invalid-deadline")
    assert row is not None
    assert row["status"] == "failed"
    assert row["error_code"] == "invalid_persisted_deadline"
    assert row["terminal_reason_code"] == "invalid_persisted_deadline"
    assert row["lease_owner"] is None


def test_stale_index_worker_cannot_overwrite_new_lease_owner(
    database: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _create_index_job(database, "index-stale-owner")
    first = database.claim_next_job("index-worker-old", job_types=(JobType.INDEX_BUILD,))
    assert first is not None
    replacement: Any = None

    def lose_lease_during_build(
        _runner: Any,
        job_id: str,
        *,
        clock: Any = None,
        now: Any = None,
        expected_lease_owner: str | None = None,
    ) -> dict[str, Any]:
        del clock, now
        assert job_id == "index-stale-owner"
        assert expected_lease_owner == "index-worker-old"
        database.execute(
            "UPDATE jobs SET lease_expires_at=? WHERE id=?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), job_id),
        )
        nonlocal replacement
        replacement = database.claim_next_job("index-worker-new", job_types=(JobType.INDEX_BUILD,))
        assert replacement is not None
        return {"status": "candidate"}

    monkeypatch.setattr(
        "app.orchestration.index_worker.IndexBuildRunner.run_sync",
        lose_lease_during_build,
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    worker = DedicatedIndexWorker(
        settings,
        database,
        worker_id="index-worker-old",
        lease_seconds=60,
    )
    worker._run_claim(dict(first))

    row = database.job("index-stale-owner")
    assert row is not None
    assert replacement is not None
    assert row["status"] == "running"
    assert row["lease_owner"] == "index-worker-new"
    assert int(row["attempt_count"]) == 2


def test_stale_index_worker_cannot_publish_candidate_after_second_worker_claims(
    database: Database,
    tmp_path: Path,
) -> None:
    job_id = "index-stale-candidate"
    build_id = f"build-{job_id}"
    _create_index_job(database, job_id)
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,created_at
        ) VALUES (?, 'building', ?, 'test-embed', 'test-rerank', ?)
        """,
        (build_id, f"data/indexes/builds/{build_id}", datetime.now(UTC).isoformat()),
    )
    first = database.claim_next_job("index-worker-old", job_types=(JobType.INDEX_BUILD,))
    assert first is not None
    database.execute(
        "UPDATE jobs SET lease_expires_at=? WHERE id=?",
        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), job_id),
    )
    replacement = database.claim_next_job("index-worker-new", job_types=(JobType.INDEX_BUILD,))
    assert replacement is not None

    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    ctx = SimpleNamespace(
        settings=settings,
        database=database,
        job_id=job_id,
        build_id=build_id,
        manifest={"omitted_required_families": []},
        counts={
            "candidate_manifest_hash": "a" * 64,
            "benchmark": {"passed": True, "promotion_eligible": True},
        },
        timings={},
        skip_embedding=True,
        expected_lease_owner="index-worker-old",
        now=None,
    )
    with pytest.raises(IndexBuildStageError) as stopped:
        IndexBuildRunner(settings, database)._mark_candidate(ctx)

    assert stopped.value.reason_code == "lease_lost"
    build = database.fetchone("SELECT status FROM index_builds WHERE id=?", (build_id,))
    job = database.job(job_id)
    assert build is not None and build["status"] == "building"
    assert job is not None and job["status"] == "running"
    assert job["lease_owner"] == "index-worker-new"
    assert int(job["attempt_count"]) == 2


def test_expired_index_owner_leaves_reclaimable_lease(
    database: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job_id = "index-expired-owner"
    _create_index_job(database, job_id)
    first = database.claim_next_job("index-worker-old", job_types=(JobType.INDEX_BUILD,))
    assert first is not None

    def expire_without_successor(
        _runner: Any,
        claimed_job_id: str,
        *,
        clock: Any = None,
        now: Any = None,
        expected_lease_owner: str | None = None,
    ) -> dict[str, Any]:
        del clock, now
        assert claimed_job_id == job_id
        assert expected_lease_owner == "index-worker-old"
        database.execute(
            "UPDATE jobs SET lease_expires_at=? WHERE id=?",
            ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), job_id),
        )
        return {"status": "candidate"}

    monkeypatch.setattr(
        "app.orchestration.index_worker.IndexBuildRunner.run_sync",
        expire_without_successor,
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    DedicatedIndexWorker(
        settings,
        database,
        worker_id="index-worker-old",
        lease_seconds=60,
    )._run_claim(dict(first))

    expired = database.job(job_id)
    assert expired is not None and expired["status"] == "running"
    assert expired["lease_owner"] == "index-worker-old"
    assert expired["lease_expires_at"] is not None
    replacement = database.claim_next_job("index-worker-new", job_types=(JobType.INDEX_BUILD,))
    assert replacement is not None
    assert replacement["lease_owner"] == "index-worker-new"
    assert int(replacement["attempt_count"]) == 2


def test_index_job_never_exceeds_three_total_attempts_or_replays_exhausted_identity(
    database: Database,
) -> None:
    _create_index_job(database, "index-cap")
    for attempt in range(1, 4):
        worker = f"index-cap-worker-{attempt}"
        claimed = database.claim_next_job(worker, job_types=(JobType.INDEX_BUILD,))
        assert claimed is not None and int(claimed["attempt_count"]) == attempt
        status = database.retry_or_fail_job(
            "index-cap",
            worker,
            error_code=f"transient_index_failure_{attempt}",
            input_or_condition_changed=True,
            condition_identity_sha256=hashlib.sha256(
                f"cap-condition-{attempt}".encode()
            ).hexdigest(),
            retry_operation="resume_failed_index_stage",
        )
    assert status == "failed"
    assert int(database.job("index-cap")["attempt_count"]) == 3
    assert len(database.retry_decisions("job", "index-cap")) == 3
    assert database.replay_dlq_job("index-cap") is False
    assert database.claim_next_job("index-cap-worker-4", job_types=(JobType.INDEX_BUILD,)) is None


def test_index_dlq_replay_respects_bounded_queue(database: Database) -> None:
    _create_index_job(database, "index-replay-blocked")
    database.execute(
        """UPDATE jobs SET status='failed',stage='failed',dlq=1,attempt_count=1
           WHERE id='index-replay-blocked'"""
    )
    _create_index_job(database, "index-queue-occupied")

    with pytest.raises(JobQueueCapacityError, match="index_build_queue_capacity_exhausted"):
        database.replay_dlq_job("index-replay-blocked")
    assert database.job("index-replay-blocked")["status"] == "failed"


def test_cancelled_failed_index_job_cannot_replay_into_capacity_one_lane(
    database: Database,
) -> None:
    _create_index_job(database, "index-cancelled-replay")
    database.execute(
        """UPDATE jobs SET status='failed',stage='failed',dlq=1,attempt_count=1
           WHERE id='index-cancelled-replay'"""
    )
    assert database.request_cancel_job("index-cancelled-replay") is True
    cancelled = database.job("index-cancelled-replay")
    assert cancelled is not None
    assert cancelled["status"] == "failed"
    assert int(cancelled["cancel_requested"]) == 1

    assert database.replay_dlq_job("index-cancelled-replay") is False
    rejected = database.job("index-cancelled-replay")
    assert rejected is not None
    assert rejected["status"] == "failed"
    assert int(rejected["cancel_requested"]) == 1

    _create_index_job(database, "index-after-cancelled-replay")
    assert database.job("index-after-cancelled-replay")["status"] == "queued"


def test_answer_owner_resume_respects_bounded_queue(
    database: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _create_answer_job(database, "answer-resume-blocked")
    claimed = database.claim_next_job("answer-resume-worker", job_types=(JobType.ANSWER,))
    assert claimed is not None
    assert (
        database.retry_or_fail_job(
            "answer-resume-blocked",
            "answer-resume-worker",
            error_code="transient_model_failure",
            input_or_condition_changed=True,
            condition_identity_sha256=hashlib.sha256(b"new-model-condition").hexdigest(),
        )
        == "system_error"
    )
    database.create_job(
        job_id="answer-queue-occupied",
        encrypted_question=b"encrypted",
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"job_type": JobType.ANSWER, "word_target": 500},
        job_type=JobType.ANSWER,
        pinned_index_build_id="active-answer-build",
    )
    monkeypatch.setattr("app.jobs.ANSWER_QUEUE_CAPACITY", 1)

    with pytest.raises(JobQueueCapacityError, match="answer_queue_capacity_exhausted"):
        database.resume_answer_job("answer-resume-blocked")
    assert database.job("answer-resume-blocked")["status"] == "system_error"


def test_index_retry_stops_when_the_claimed_recovery_condition_is_reused(
    database: Database,
) -> None:
    _create_index_job(database, "index-condition")
    condition = hashlib.sha256(b"one-failed-stage-checkpoint").hexdigest()

    first = database.claim_next_job("index-condition-worker-1", job_types=(JobType.INDEX_BUILD,))
    assert first is not None
    assert (
        database.retry_or_fail_job(
            "index-condition",
            "index-condition-worker-1",
            error_code="transient_index_failure_a",
            input_or_condition_changed=True,
            condition_identity_sha256=condition,
            retry_operation="resume_failed_index_stage",
        )
        == "queued"
    )

    second = database.claim_next_job("index-condition-worker-2", job_types=(JobType.INDEX_BUILD,))
    assert second is not None
    assert (
        database.retry_or_fail_job(
            "index-condition",
            "index-condition-worker-2",
            error_code="transient_index_failure_b",
            input_or_condition_changed=True,
            condition_identity_sha256=condition,
            retry_operation="resume_failed_index_stage",
        )
        == "failed"
    )
    trace = database.retry_decisions("job", "index-condition")
    assert str(trace[-1]["decision_reason"]) == "retry_condition_unchanged"
    assert int(trace[-1]["condition_changed"]) == 0


def test_synchronous_index_resume_counts_attempts_and_honours_repeat_stop(
    database: Database,
) -> None:
    _create_index_job(database, "index-sync")

    for attempt in (1, 2):
        if attempt > 1:
            database.execute(
                "UPDATE jobs SET status='running', stage='failed' WHERE id='index-sync'"
            )
        assert database.begin_unleased_index_job_attempt("index-sync") == attempt
        database.execute(
            """
            INSERT INTO job_stage_attempts(
              id, job_id, stage_key, section_key, attempt_number, status,
              metrics_json, error_code, started_at, finished_at
            ) VALUES (?, 'index-sync', 'embedding', 'index', ?, 'failed',
                      '{}', 'transient_embedding_failure', ?, ?)
            """,
            (
                f"sync-stage-attempt-{attempt}",
                attempt,
                f"2026-08-20T12:0{attempt}:00+00:00",
                f"2026-08-20T12:0{attempt}:01+00:00",
            ),
        )
        database.execute("UPDATE jobs SET status='failed', stage='failed' WHERE id='index-sync'")
        reason = database.record_unleased_index_job_failure(
            "index-sync", error_code="transient_embedding_failure"
        )

    assert reason == "repeated_failure_fingerprint"
    database.execute("UPDATE jobs SET status='running' WHERE id='index-sync'")
    try:
        database.begin_unleased_index_job_attempt("index-sync")
    except RuntimeError as exc:
        assert "repeated_failure_fingerprint" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("terminal synchronous retry circuit was bypassed")
    assert int(database.job("index-sync")["attempt_count"]) == 2


def test_explicit_answer_resume_preserves_counter_and_cannot_exceed_three_attempts(
    database: Database,
) -> None:
    _create_answer_job(database, "answer-cap")
    for attempt in range(1, 4):
        worker = f"answer-cap-worker-{attempt}"
        claimed = database.claim_next_job(worker, job_types=(JobType.ANSWER,))
        assert claimed is not None and int(claimed["attempt_count"]) == attempt
        status = database.retry_or_fail_job(
            "answer-cap",
            worker,
            error_code=f"transient_answer_condition_{attempt}",
            input_or_condition_changed=True,
            condition_identity_sha256=hashlib.sha256(
                f"answer-condition-{attempt}".encode()
            ).hexdigest(),
            retry_operation="owner_resume_failed_answer_attempt",
        )
        assert status == "system_error"
        if attempt < 3:
            database.execute(
                """
                UPDATE jobs SET stage_started_at=?,stage_deadline_at=?,model_call_deadline_at=?
                WHERE id='answer-cap'
                """,
                ("2000-01-01T00:00:00+00:00",) * 3,
            )
            before = len(database.retry_decisions("job", "answer-cap"))
            assert database.resume_answer_job("answer-cap") is True
            resumed = database.job("answer-cap")
            assert int(resumed["attempt_count"]) == attempt
            assert resumed["stage_started_at"] is None
            assert resumed["stage_deadline_at"] is None
            assert resumed["model_call_deadline_at"] is None
            assert len(database.retry_decisions("job", "answer-cap")) == before
            with pytest.raises(ValueError, match="only a system_error"):
                database.resume_answer_job("answer-cap")
            assert len(database.retry_decisions("job", "answer-cap")) == before

    row = database.job("answer-cap")
    assert row is not None and int(row["attempt_count"]) == 3
    trace = database.retry_decisions("job", "answer-cap")
    assert [int(item["attempt_number"]) for item in trace] == [1, 2, 3]
    assert [str(item["decision_action"]) for item in trace] == ["retry", "retry", "stop"]
    assert str(trace[-1]["decision_reason"]) == "retry_cap_exhausted"
    checkpoint = json.loads(str(row["checkpoint_json"]))
    assert checkpoint["continuation_requires_new_linked_job_identity"] is True
    with pytest.raises(RuntimeError, match="new linked job/version identity"):
        database.resume_answer_job("answer-cap")
    assert database.claim_next_job("answer-cap-worker-4", job_types=(JobType.ANSWER,)) is None


def test_explicit_answer_resume_stops_after_second_identical_semantic_failure(
    database: Database,
) -> None:
    _create_answer_job(database, "answer-repeat")
    for attempt in (1, 2):
        worker = f"answer-repeat-worker-{attempt}"
        claimed = database.claim_next_job(worker, job_types=(JobType.ANSWER,))
        assert claimed is not None and int(claimed["attempt_count"]) == attempt
        assert (
            database.retry_or_fail_job(
                "answer-repeat",
                worker,
                error_code="transient_answer_failure",
                input_or_condition_changed=True,
                condition_identity_sha256=hashlib.sha256(
                    f"answer-repeat-condition-{attempt}".encode()
                ).hexdigest(),
                retry_operation="owner_resume_failed_answer_attempt",
            )
            == "system_error"
        )
        if attempt == 1:
            assert database.resume_answer_job("answer-repeat") is True

    trace = database.retry_decisions("job", "answer-repeat")
    assert [str(item["decision_action"]) for item in trace] == ["retry", "stop"]
    assert str(trace[-1]["decision_reason"]) == "repeated_failure_fingerprint"
    assert trace[0]["failure_fingerprint_sha256"] == trace[1]["failure_fingerprint_sha256"]
    assert int(database.job("answer-repeat")["attempt_count"]) == 2
    checkpoint = json.loads(str(database.job("answer-repeat")["checkpoint_json"]))
    assert checkpoint["continuation_requires_new_linked_job_identity"] is True
    with pytest.raises(RuntimeError, match="new linked job/version identity"):
        database.resume_answer_job("answer-repeat")


@pytest.mark.asyncio
async def test_public_answer_resume_never_resets_or_mints_retry_decisions(
    database: Database,
) -> None:
    _create_answer_job(database, "answer-public-cap")
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=database)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4411))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            for attempt in range(1, 4):
                worker = f"answer-public-worker-{attempt}"
                claimed = database.claim_next_job(worker, job_types=(JobType.ANSWER,))
                assert claimed is not None and int(claimed["attempt_count"]) == attempt
                assert (
                    database.retry_or_fail_job(
                        "answer-public-cap",
                        worker,
                        error_code=f"public_resume_condition_{attempt}",
                        input_or_condition_changed=True,
                        condition_identity_sha256=hashlib.sha256(
                            f"public-resume-condition-{attempt}".encode()
                        ).hexdigest(),
                        retry_operation="owner_resume_failed_answer_attempt",
                    )
                    == "system_error"
                )
                before = database.retry_decisions("job", "answer-public-cap")
                response = await client.post("/api/v1/jobs/answer-public-cap/resume")
                if attempt < 3:
                    assert response.status_code == 200
                    assert response.json()["attempt_count"] == attempt
                    assert response.json()["attempt_counter_reset"] is False
                    duplicate = await client.post("/api/v1/jobs/answer-public-cap/resume")
                    assert duplicate.status_code == 409
                else:
                    assert response.status_code == 409
                assert database.retry_decisions("job", "answer-public-cap") == before
                assert int(database.job("answer-public-cap")["attempt_count"]) == attempt
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


def test_expired_answer_lease_uses_owner_resume_ledger_and_repeat_stop(
    database: Database,
) -> None:
    _create_answer_job(database, "answer-expired-lease")
    first = database.claim_next_job("expired-answer-worker-1", job_types=(JobType.ANSWER,))
    assert first is not None and int(first["attempt_count"]) == 1
    database.execute(
        "UPDATE jobs SET lease_expires_at=? WHERE id='answer-expired-lease'",
        ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(),),
    )
    assert database.claim_next_job("expired-answer-observer-1", job_types=(JobType.ANSWER,)) is None
    first_trace = database.retry_decisions("job", "answer-expired-lease")
    assert [str(item["decision_action"]) for item in first_trace] == ["retry"]
    assert database.resume_answer_job("answer-expired-lease") is True

    second = database.claim_next_job("expired-answer-worker-2", job_types=(JobType.ANSWER,))
    assert second is not None and int(second["attempt_count"]) == 2
    database.execute(
        "UPDATE jobs SET lease_expires_at=? WHERE id='answer-expired-lease'",
        ((datetime.now(UTC) - timedelta(minutes=1)).isoformat(),),
    )
    assert database.claim_next_job("expired-answer-observer-2", job_types=(JobType.ANSWER,)) is None
    trace = database.retry_decisions("job", "answer-expired-lease")
    assert [str(item["decision_action"]) for item in trace] == ["retry", "stop"]
    assert str(trace[-1]["decision_reason"]) == "repeated_failure_fingerprint"
    assert trace[0]["failure_fingerprint_sha256"] == trace[1]["failure_fingerprint_sha256"]
    assert int(database.job("answer-expired-lease")["attempt_count"]) == 2
    with pytest.raises(RuntimeError, match="new linked job/version identity"):
        database.resume_answer_job("answer-expired-lease")
