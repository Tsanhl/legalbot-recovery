from __future__ import annotations

import sqlite3
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from app.config import Settings
from app.jobs import TERMINAL_STAGE_TIMEOUT, deadline_after
from app.orchestration import index_worker as index_worker_module
from app.orchestration.index_worker import DedicatedIndexWorker
from app.orchestration.runner import AnswerRunner
from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.retrieval.index_build import IndexBuildRunner, IndexBuildStageError
from app.types import JobStage, JobType


def _create_answer_job(database: Any, cipher: Any, job_id: str) -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        workflow_deadline_at=deadline_after(3_600),
    )


def _create_index_job(database: Any, job_id: str) -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=b"",
        question_summary="Private index request",
        request={"job_type": "index_build", "build_id": job_id},
        pinned_index_build_id=job_id,
        job_type=JobType.INDEX_BUILD,
        workflow_deadline_at=deadline_after(3_600),
    )


def test_stale_answer_progress_cannot_resurrect_terminal_job(database: Any, cipher: Any) -> None:
    job_id = "answer-terminal-fence"
    _create_answer_job(database, cipher, job_id)
    assert database.claim_next_job("answer-terminal-owner", job_types=(JobType.ANSWER,))
    assert database.update_job(
        job_id,
        status="system_error",
        stage="system_error",
        progress=1,
        message="Workflow deadline stopped the job.",
        error_code="workflow_deadline_exceeded",
    )
    event_count = len(database.job_events(job_id))
    runner = object.__new__(AnswerRunner)
    runner.database = database
    runner.observability = None
    runner._issue_plan_metadata = {}

    with pytest.raises(RuntimeError, match="answer_job_progress_transition_fenced"):
        runner._event(job_id, JobStage.RESEARCHING, 0.2, "Stale progress")

    assert (
        database.update_job(
            job_id,
            status="running",
            stage="drafting",
            progress=0.5,
            message="Another stale update",
        )
        is False
    )
    row = database.job(job_id)
    assert row["status"] == "system_error"
    assert row["stage"] == "system_error"
    assert row["error_code"] == "workflow_deadline_exceeded"
    assert row["user_message"] == "Workflow deadline stopped the job."
    assert len(database.job_events(job_id)) == event_count


def test_index_normal_completion_wins_over_terminal_heartbeat_race(
    database: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job_id = "index-normal-heartbeat-race"
    worker_id = "index-normal-owner"
    _create_index_job(database, job_id)
    claimed = database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,))
    assert claimed is not None

    def complete(
        _runner: Any,
        observed_job_id: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert observed_job_id == job_id
        assert database.update_job(
            job_id,
            status="complete",
            stage="built_unscored",
            progress=1,
            message="Complete",
        )
        return {"status": "built_unscored"}

    class RacingThread:
        def __init__(self, *, args: tuple[Any, ...], name: str, **_kwargs: Any) -> None:
            self.args = args
            self.name = name

        def start(self) -> None:
            if "heartbeat" in self.name:
                self.args[2].set()

        def join(self, timeout: float | None = None) -> None:
            del timeout

    monkeypatch.setattr(index_worker_module.IndexBuildRunner, "run_sync", complete)
    monkeypatch.setattr(index_worker_module.threading, "Thread", RacingThread)
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id=worker_id,
    )

    worker._run_claim(dict(claimed))

    row = database.job(job_id)
    assert row["status"] == "complete"
    assert row["lease_owner"] is None
    assert database.retry_decisions("job", job_id) == []


@pytest.mark.parametrize(
    ("trigger", "expected_code", "expected_status"),
    [
        ("stage", TERMINAL_STAGE_TIMEOUT, "failed"),
        ("workflow", "workflow_deadline_exceeded", "failed"),
        ("cancel", "cancelled", "cancelled"),
    ],
)
def test_index_hard_stop_watchdog_terminalizes_fence_and_calls_terminator(
    database: Any,
    tmp_path: Any,
    trigger: str,
    expected_code: str,
    expected_status: str,
) -> None:
    job_id = f"index-hard-stop-{trigger}"
    worker_id = "index-hard-stop-owner"
    _create_index_job(database, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,)) is not None
    if trigger == "stage":
        database.arm_stage_deadline(job_id, seconds=-1)
    elif trigger == "workflow":
        database.execute(
            "UPDATE jobs SET workflow_deadline_at=? WHERE id=?",
            (deadline_after(-1), job_id),
        )
    else:
        assert database.request_cancel_job(job_id)
    exits: list[int] = []
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id=worker_id,
        watchdog_poll_seconds=0.01,
        hard_stop_terminator=exits.append,
    )
    fired = threading.Event()

    worker._hard_stop_watchdog_loop(job_id, threading.Event(), fired)

    row = database.job(job_id)
    assert fired.is_set()
    assert exits == [70]
    assert row["status"] == expected_status
    assert row["error_code"] == expected_code
    assert row["terminal_reason_code"] == expected_code
    assert row["lease_owner"] is None


@pytest.mark.parametrize("failure_point", ["terminalize", "event"])
def test_index_hard_stop_terminator_survives_reporting_failures(
    database: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    job_id = f"index-hard-stop-reporting-{failure_point}"
    worker_id = "index-hard-stop-reporting-owner"
    _create_index_job(database, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,)) is not None
    database.arm_stage_deadline(job_id, seconds=-1)
    exits: list[int] = []
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id=worker_id,
        watchdog_poll_seconds=0.01,
        hard_stop_terminator=exits.append,
    )

    def reporting_failure(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("injected hard-stop reporting failure")

    if failure_point == "terminalize":
        monkeypatch.setattr(database, "terminalize_owned_index_execution", reporting_failure)
    else:
        monkeypatch.setattr(worker.events, "emit", reporting_failure)
    fired = threading.Event()

    worker._hard_stop_watchdog_loop(job_id, threading.Event(), fired)

    assert fired.is_set()
    assert exits == [70]
    row = database.job(job_id)
    if failure_point == "terminalize":
        assert row["status"] == "running"
        assert row["lease_owner"] == worker_id
    else:
        assert row["status"] == "failed"
        assert row["terminal_reason_code"] == TERMINAL_STAGE_TIMEOUT


def test_index_terminal_completion_never_triggers_hard_stop_or_false_heartbeat_loss(
    database: Any,
    tmp_path: Any,
) -> None:
    job_id = "index-terminal-no-hard-stop"
    worker_id = "index-terminal-owner"
    _create_index_job(database, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,)) is not None
    assert database.update_job(
        job_id,
        status="complete",
        stage="built_unscored",
        progress=1,
        message="Complete",
    )
    exits: list[int] = []
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id=worker_id,
        watchdog_poll_seconds=0.01,
        hard_stop_terminator=exits.append,
    )
    fired = threading.Event()
    lost = threading.Event()

    worker._hard_stop_watchdog_loop(job_id, threading.Event(), fired)

    class OnePoll:
        def wait(self, _seconds: float) -> bool:
            return False

    worker._heartbeat_loop(job_id, OnePoll(), lost)  # type: ignore[arg-type]

    assert not fired.is_set()
    assert not lost.is_set()
    assert exits == []


def test_index_heartbeat_renews_lease_before_locked_best_effort_service_pulse(
    database: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id="heartbeat-order-worker",
    )

    def heartbeat(*_args: Any, **_kwargs: Any) -> bool:
        calls.append("heartbeat")
        return True

    def locked_pulse(*_args: Any, **_kwargs: Any) -> None:
        calls.append("pulse")
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(database, "heartbeat_job", heartbeat)
    monkeypatch.setattr(database, "pulse_service", locked_pulse)

    class OneCycle:
        calls = 0

        def wait(self, _seconds: float) -> bool:
            self.calls += 1
            return self.calls > 1

    lost = threading.Event()
    worker._heartbeat_loop("heartbeat-order-job", OneCycle(), lost)  # type: ignore[arg-type]

    assert calls == ["heartbeat", "pulse"]
    assert not lost.is_set()


def test_index_heartbeat_retries_sqlite_lock_then_renews(
    database: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id="heartbeat-retry-worker",
    )
    outcomes: list[object] = [
        sqlite3.OperationalError("database is locked"),
        sqlite3.OperationalError("database table is locked"),
        True,
    ]

    def heartbeat(*_args: Any, **_kwargs: Any) -> bool:
        outcome = outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return bool(outcome)

    monkeypatch.setattr(database, "heartbeat_job", heartbeat)

    class NoWait:
        def wait(self, _seconds: float) -> bool:
            return False

    assert worker._renew_critical_job_lease("heartbeat-retry-job", NoWait()) == "renewed"  # type: ignore[arg-type]
    assert outcomes == []


def test_index_heartbeat_persistent_lock_and_nonlock_error_fail_closed(
    database: Any,
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = DedicatedIndexWorker(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        worker_id="heartbeat-fail-worker",
    )
    attempts = 0

    def locked(*_args: Any, **_kwargs: Any) -> bool:
        nonlocal attempts
        attempts += 1
        raise sqlite3.OperationalError("database is locked")

    class NoWait:
        def wait(self, _seconds: float) -> bool:
            return False

    monkeypatch.setattr(database, "heartbeat_job", locked)
    assert worker._renew_critical_job_lease("heartbeat-fail-job", NoWait()) == "failed"  # type: ignore[arg-type]
    assert attempts == 6

    monkeypatch.setattr(
        database,
        "heartbeat_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("disk I/O error")
        ),
    )
    assert worker._renew_critical_job_lease("heartbeat-fail-job", NoWait()) == "failed"  # type: ignore[arg-type]


def test_bounded_heartbeat_restores_catalogue_busy_timeout(database: Any) -> None:
    job_id = "bounded-heartbeat-timeout"
    worker_id = "bounded-heartbeat-worker"
    _create_index_job(database, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,)) is not None
    before = int(database.fetchone("PRAGMA busy_timeout")[0])

    assert database.heartbeat_job(
        job_id,
        worker_id,
        lease_seconds=60,
        busy_timeout_ms=5,
    )

    after = int(database.fetchone("PRAGMA busy_timeout")[0])
    assert before == 30_000
    assert after == before


def test_index_candidate_completion_cas_rejects_expired_stage(
    database: Any,
    tmp_path: Any,
) -> None:
    job_id = "index-candidate-expired-stage"
    worker_id = "index-candidate-owner"
    _create_index_job(database, job_id)
    database.execute(
        """
        INSERT INTO index_builds(id,status,path,embedding_model,reranker_model,created_at)
        VALUES (?, 'building', ?, 'test-embed', 'test-rerank', ?)
        """,
        (job_id, f"data/indexes/builds/{job_id}", deadline_after(0)),
    )
    assert database.claim_next_job(worker_id, job_types=(JobType.INDEX_BUILD,)) is not None
    database.arm_stage_deadline(job_id, seconds=-1)
    settings = Settings(project_root=tmp_path, test_mode=True)
    ctx = SimpleNamespace(
        settings=settings,
        database=database,
        job_id=job_id,
        build_id=job_id,
        manifest={"omitted_required_families": []},
        counts={
            "candidate_manifest_hash": "a" * 64,
            "benchmark": {"passed": True, "promotion_eligible": True},
        },
        timings={},
        skip_embedding=True,
        expected_lease_owner=worker_id,
        now=None,
    )

    with pytest.raises(IndexBuildStageError) as stopped:
        IndexBuildRunner(settings, database)._mark_candidate(ctx)

    assert stopped.value.reason_code == "lease_lost"
    assert database.job(job_id)["status"] == "running"
    assert (
        database.fetchone("SELECT status FROM index_builds WHERE id=?", (job_id,))["status"]
        == "building"
    )
