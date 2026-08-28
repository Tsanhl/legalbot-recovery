from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest

from app.evaluation.candidate_completion_runtime import LoopbackCandidateCompletionLauncher
from app.evaluation.evaluation_job_authority import build_completion_nonrelease_job_authority
from app.jobs import TERMINAL_CANCELLED, TERMINAL_STAGE_TIMEOUT, TERMINAL_WORKFLOW, deadline_after
from app.orchestration.direct_controller import (
    DirectControllerExecutionError,
    run_bounded_direct_answer,
)
from app.privacy import PRIVATE_QUESTION_SUMMARY
from app.types import JobType


def _create_answer_job(
    database: Any,
    cipher: Any,
    job_id: str,
    *,
    workflow_deadline_at: str | None = None,
) -> None:
    database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        route="direct",
        workflow_deadline_at=workflow_deadline_at or deadline_after(3_600),
    )


@pytest.mark.asyncio
async def test_direct_controller_rejects_expired_workflow_before_execution(
    database: Any, cipher: Any
) -> None:
    job_id = "direct-workflow-timeout"
    worker_id = "direct-workflow-controller"
    _create_answer_job(database, cipher, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.ANSWER,)) is not None
    database.execute(
        "UPDATE jobs SET workflow_deadline_at=? WHERE id=?",
        (deadline_after(-1), job_id),
    )
    called = False

    async def execute() -> None:
        nonlocal called
        called = True

    with pytest.raises(DirectControllerExecutionError) as failure:
        await run_bounded_direct_answer(
            database=database,
            job_id=job_id,
            execute=execute,
            expected_lease_owner=worker_id,
            poll_seconds=0.01,
        )

    row = database.job(job_id)
    assert failure.value.reason_code == TERMINAL_WORKFLOW
    assert called is False
    assert row["status"] == "system_error"
    assert row["error_code"] == TERMINAL_WORKFLOW
    assert row["cancel_requested"] == 1
    assert row["lease_owner"] is None
    assert database.released_outbox_for_job(job_id) is None


@pytest.mark.asyncio
async def test_direct_controller_rejects_expired_stage_before_execution(
    database: Any, cipher: Any
) -> None:
    job_id = "direct-stage-timeout"
    worker_id = "direct-stage-controller"
    _create_answer_job(database, cipher, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.ANSWER,)) is not None
    database.arm_stage_deadline(job_id, seconds=-1)

    with pytest.raises(DirectControllerExecutionError) as failure:
        await run_bounded_direct_answer(
            database=database,
            job_id=job_id,
            execute=lambda: asyncio.sleep(0),
            expected_lease_owner=worker_id,
            poll_seconds=0.01,
        )

    row = database.job(job_id)
    assert failure.value.reason_code == TERMINAL_STAGE_TIMEOUT
    assert row["status"] == "system_error"
    assert row["error_code"] == TERMINAL_STAGE_TIMEOUT


@pytest.mark.asyncio
async def test_direct_controller_cancellation_cleans_task_and_exact_lease(
    database: Any, cipher: Any
) -> None:
    job_id = "direct-cancel"
    worker_id = "direct-owner-controller"
    _create_answer_job(database, cipher, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.ANSWER,)) is not None
    execution_started = asyncio.Event()
    execution_cleaned = False

    async def execute() -> None:
        nonlocal execution_cleaned
        execution_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            execution_cleaned = True

    async def cancel() -> None:
        await execution_started.wait()
        database.request_cancel_job(job_id)

    cancellation = asyncio.create_task(cancel())
    with pytest.raises(DirectControllerExecutionError) as failure:
        await run_bounded_direct_answer(
            database=database,
            job_id=job_id,
            execute=execute,
            expected_lease_owner=worker_id,
            poll_seconds=0.01,
        )
    await cancellation

    row = database.job(job_id)
    assert failure.value.reason_code == TERMINAL_CANCELLED
    assert execution_cleaned is True
    assert row["status"] == "cancelled"
    assert row["error_code"] == TERMINAL_CANCELLED
    assert row["lease_owner"] is None
    assert database.released_outbox_for_job(job_id) is None


@pytest.mark.asyncio
async def test_direct_controller_exception_terminalizes_and_releases_exact_lease(
    database: Any, cipher: Any
) -> None:
    job_id = "direct-exception"
    worker_id = "direct-owner-controller"
    _create_answer_job(database, cipher, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.ANSWER,)) is not None

    async def execute() -> None:
        raise RuntimeError("private failure detail")

    with pytest.raises(RuntimeError, match="private failure detail"):
        await run_bounded_direct_answer(
            database=database,
            job_id=job_id,
            execute=execute,
            expected_lease_owner=worker_id,
            poll_seconds=0.01,
        )

    row = database.job(job_id)
    assert row["status"] == "system_error"
    assert row["error_code"] == "direct_controller_runtimeerror"
    assert row["lease_owner"] is None
    assert row["answer_id"] is None
    assert row["release_state"] is None
    assert "private failure detail" not in str(row["checkpoint_json"])


@pytest.mark.asyncio
async def test_direct_controller_accepts_terminal_success_under_current_exact_lease(
    database: Any, cipher: Any
) -> None:
    job_id = "direct-success"
    worker_id = "direct-owner-controller"
    _create_answer_job(database, cipher, job_id)
    assert database.claim_next_job(worker_id, job_types=(JobType.ANSWER,)) is not None

    async def execute() -> None:
        database.update_job(
            job_id,
            status="complete",
            stage="complete",
            progress=1,
            message="Complete",
        )

    await run_bounded_direct_answer(
        database=database,
        job_id=job_id,
        execute=execute,
        expected_lease_owner=worker_id,
        poll_seconds=0.01,
    )

    row = database.job(job_id)
    assert row["status"] == "complete"
    assert row["lease_owner"] is None


def test_completion_nonrelease_hold_preserves_controller_failure(
    database: Any, cipher: Any
) -> None:
    job_id = "completion-direct-failure"
    _create_answer_job(database, cipher, job_id)
    database.update_job(
        job_id,
        status="system_error",
        stage="system_error",
        progress=1,
        message="Stopped",
        error_code=TERMINAL_WORKFLOW,
    )
    launcher = object.__new__(LoopbackCandidateCompletionLauncher)
    launcher.database = database

    launcher._hold_nonrelease_job(job_id)

    row = database.job(job_id)
    assert row["status"] == "system_error"
    assert row["error_code"] == TERMINAL_WORKFLOW


def test_exact_controller_claim_excludes_foreign_and_ordinary_workers(
    database: Any, cipher: Any
) -> None:
    job_id = "completion-exact-controller"
    request_sha256 = "a" * 64
    candidate_id = "candidate-completion-test"
    owner = f"candidate-completion-controller-{os.getpid()}-atomic-test"
    authority = build_completion_nonrelease_job_authority(
        run_id="completion-atomic-test",
        case_id="live60-q01",
        request_sha256=request_sha256,
        candidate_build_id=candidate_id,
        runtime_binding_sha256="b" * 64,
    )

    returned_owner = database.create_job(
        job_id=job_id,
        encrypted_question=cipher.encrypt_text("A private question"),
        question_summary=PRIVATE_QUESTION_SUMMARY,
        request={"task_type": "general", "word_target": 500},
        pinned_index_build_id=candidate_id,
        workflow_deadline_at=deadline_after(3_600),
        evaluation_run_id="completion-atomic-test",
        evaluation_case_id="live60-q01",
        evaluation_request_sha256=request_sha256,
        evaluation_authority=authority,
        exact_controller_claim={
            "controller_pid": os.getpid(),
            "worker_id": owner,
            "lease_seconds": 60,
            "authority_sha256": authority["seal_sha256"],
        },
    )

    assert returned_owner == owner
    assert database.claim_next_job("ordinary-answer-worker", job_types=(JobType.ANSWER,)) is None
    current = database.job(job_id)
    assert current["status"] == "running"
    assert current["lease_owner"] == owner
    assert current["attempt_count"] == 1
    assert database.fetchone("SELECT 1 FROM jobs WHERE id=? AND status='queued'", (job_id,)) is None


def test_invalid_exact_controller_identity_rolls_back_admission(database: Any, cipher: Any) -> None:
    job_id = "completion-invalid-controller"
    authority = build_completion_nonrelease_job_authority(
        run_id="completion-invalid-controller-test",
        case_id="live60-q01",
        request_sha256="c" * 64,
        candidate_build_id="candidate-completion-test",
        runtime_binding_sha256="d" * 64,
    )

    with pytest.raises(ValueError, match="exact non-release controller claim is invalid"):
        database.create_job(
            job_id=job_id,
            encrypted_question=cipher.encrypt_text("A private question"),
            question_summary=PRIVATE_QUESTION_SUMMARY,
            request={"task_type": "general", "word_target": 500},
            pinned_index_build_id="candidate-completion-test",
            workflow_deadline_at=deadline_after(3_600),
            evaluation_run_id="completion-invalid-controller-test",
            evaluation_case_id="live60-q01",
            evaluation_request_sha256="c" * 64,
            evaluation_authority=authority,
            exact_controller_claim={
                "controller_pid": os.getpid() + 1,
                "worker_id": "foreign-controller",
                "lease_seconds": 60,
                "authority_sha256": authority["seal_sha256"],
            },
        )

    assert database.job(job_id) is None
