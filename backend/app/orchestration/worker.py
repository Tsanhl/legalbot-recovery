"""Durable, leased local worker for answer jobs only."""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import socket
import time
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, cast

from ..jobs import (
    TERMINAL_CANCELLED,
    TERMINAL_MODEL_TIMEOUT,
    TERMINAL_STAGE_TIMEOUT,
    TERMINAL_WORKFLOW,
    policy_for,
)
from ..observability.events import EventStore
from ..observability.live_tracing import DatabaseOperation, TraceStage
from ..observability.runtime import RuntimeObservability
from ..retrieval.budget import (
    abort_in_flight_retrieval,
    bind_retrieval_budget,
    parse_job_deadline,
)
from ..services import Services
from ..types import JobType
from .uploads import purge_expired_uploads


class DurableAnswerWorker:
    def __init__(
        self,
        services: Services,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 60,
        poll_seconds: float = 0.5,
    ) -> None:
        self.services = services
        self.worker_id = worker_id or f"worker-{socket.gethostname()}-{os.getpid()}"
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_seconds
        self._stop = asyncio.Event()
        self._next_upload_purge_at = 0.0
        self._events: EventStore | None = None
        self.observability = cast(
            RuntimeObservability | None, getattr(self.services, "observability", None)
        )
        if self.observability is not None:
            self.observability.set_component("worker")

    def stop(self) -> None:
        self._stop.set()

    @property
    def events(self) -> EventStore:
        if self._events is None:
            from pathlib import Path as _Path

            settings = getattr(self.services, "settings", None)
            database = self.services.database
            if settings is not None:
                self._events = EventStore.from_settings(settings, database)
            else:
                self._events = EventStore(database, _Path(database.path).parent / "logs")
        return self._events

    async def run_forever(self) -> None:
        while not self._stop.is_set():
            monotonic_now = time.monotonic()
            if monotonic_now >= self._next_upload_purge_at:
                try:
                    purge_expired_uploads(
                        self.services.settings,
                        self.services.database,
                        guard=self.services.deletion_guard,
                    )
                except Exception as exc:
                    # Upload expiry is maintenance, not authority retrieval or
                    # answer generation. Preserve service availability but make
                    # the safe failure visible for owner repair.
                    self.events.emit(
                        event_type="warning",
                        component="worker",
                        stage="upload_retention",
                        failure_code="upload_retention_purge_failed",
                        user_or_owner_safe=(
                            "Encrypted upload retention maintenance failed and will retry."
                        ),
                        internal_detail=type(exc).__name__,
                        retryable=True,
                        blocking=False,
                    )
                finally:
                    self._next_upload_purge_at = monotonic_now + 300.0
                try:
                    conversation_store = getattr(self.services, "conversations", None)
                    if conversation_store is not None:
                        conversation_store.purge_expired()
                except Exception as exc:
                    self.events.emit(
                        event_type="warning",
                        component="worker",
                        stage="conversation_retention",
                        failure_code="conversation_retention_purge_failed",
                        user_or_owner_safe=(
                            "Encrypted conversation retention maintenance failed and will retry."
                        ),
                        internal_detail=type(exc).__name__,
                        retryable=True,
                        blocking=False,
                    )
            self.services.database.pulse_service(
                "answer-worker",
                self.worker_id,
                {"model_concurrency": 1, "retrieval_concurrency": 4, "index_build": False},
            )
            claim_started = time.perf_counter()
            row = self.services.database.claim_next_job(
                self.worker_id,
                lease_seconds=self.lease_seconds,
                job_types=(JobType.ANSWER,),
            )
            if row is None:
                with suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
                continue
            job_id = str(row["id"])
            job_type = str(row["job_type"])
            trace_context = (
                self.observability.record_queue_claim(
                    row, db_duration_seconds=time.perf_counter() - claim_started
                )
                if job_type == JobType.ANSWER and self.observability is not None
                else None
            )

            now = datetime.now(UTC)
            preflight_terminal: dict[str, str] | None = None
            try:
                workflow_deadline = parse_job_deadline(row["workflow_deadline_at"])
                model_deadline = parse_job_deadline(row["model_call_deadline_at"])
                parse_job_deadline(row["stage_deadline_at"])
            except (TypeError, ValueError):
                workflow_deadline = None
                model_deadline = None
                preflight_terminal = {
                    "code": "invalid_persisted_deadline",
                    "message": "The job contains an invalid persisted deadline and was stopped.",
                }
            if (
                preflight_terminal is None
                and workflow_deadline is not None
                and now > workflow_deadline
            ):
                preflight_terminal = {
                    "code": TERMINAL_WORKFLOW,
                    "message": "The job exceeded its whole-workflow deadline.",
                }
            elif preflight_terminal is None and model_deadline is not None and now > model_deadline:
                preflight_terminal = {
                    "code": TERMINAL_MODEL_TIMEOUT,
                    "message": "The job exceeded its persisted model-call deadline.",
                }
            if preflight_terminal is not None:
                self._apply_budget_terminal(job_id, job_type, preflight_terminal)
                terminal_row = self.services.database.job(job_id)
                if (
                    terminal_row is not None
                    and trace_context is not None
                    and self.observability is not None
                ):
                    self.observability.record_terminal(terminal_row)
                release_started = time.perf_counter()
                self.services.database.release_job_lease(job_id, self.worker_id)
                if trace_context is not None and self.observability is not None:
                    self.observability.record_db_duration(
                        trace_context,
                        operation=DatabaseOperation.RELEASE_JOB_LEASE,
                        stage=TraceStage.RELEASE,
                        duration_seconds=time.perf_counter() - release_started,
                    )
                continue
            heartbeat = asyncio.create_task(self._heartbeat(job_id))
            bind_retrieval_budget(deadline_at=workflow_deadline)
            if job_type != JobType.ANSWER:
                raise RuntimeError("answer worker claimed a non-answer job")
            execution: asyncio.Task[Any] = asyncio.create_task(
                self.services.runner.run(job_id, raise_on_error=True)
            )
            budget = asyncio.create_task(
                self._watch_job_budget(job_id, job_type), name=f"budget-{job_id}"
            )
            attempt_count = int(row["attempt_count"] or 0)
            if attempt_count > 1:
                self.events.emit(
                    event_type="warning",
                    component="worker",
                    stage="queued",
                    failure_code="stale_recover",
                    source_id=job_id,
                    job_id=job_id,
                    user_or_owner_safe="A stale leased job was recovered by the durable worker.",
                    retryable=True,
                    blocking=False,
                )
            try:
                done, _pending = await asyncio.wait(
                    {execution, heartbeat, budget},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if budget in done:
                    reason = budget.result()
                    abort_in_flight_retrieval()
                    if execution not in done:
                        execution.cancel()
                        with suppress(asyncio.CancelledError, TimeoutError, Exception):
                            await asyncio.wait_for(execution, timeout=2.0)
                    else:
                        with suppress(Exception):
                            execution.result()
                    if reason.get("code") not in {None, "already_terminal"}:
                        row_now = self.services.database.job(job_id)
                        if row_now is None or str(row_now["status"]) not in {
                            "complete",
                            "cancelled",
                            "system_error",
                            "failed",
                            "held_for_review",
                        }:
                            self._apply_budget_terminal(job_id, job_type, reason)
                    continue
                if heartbeat in done and execution not in done:
                    heartbeat.result()
                    abort_in_flight_retrieval()
                    execution.cancel()
                    with suppress(asyncio.CancelledError):
                        await execution
                    raise RuntimeError("job lease heartbeat stopped unexpectedly")
                await execution
                opened = self.events.open_failure_for_job(job_id)
                if opened is not None:
                    self.events.recover(
                        str(opened["failure_id"]),
                        component="worker",
                        job_id=job_id,
                    )
                terminal_row = self.services.database.job(job_id)
                if (
                    terminal_row is not None
                    and trace_context is not None
                    and self.observability is not None
                ):
                    self.observability.record_terminal(terminal_row)
            except Exception as exc:
                message = str(exc)
                reason_code = str(getattr(exc, "reason_code", "") or "")
                if (
                    reason_code
                    in {
                        "retrieval_deadline_exceeded",
                        "retrieval_aborted",
                        "retrieval_budget_exceeded",
                    }
                    or "retrieval_deadline_exceeded" in message
                    or "retrieval_aborted" in message
                    or "retrieval_deadline" in message
                    or "retrieval_budget_exceeded" in message
                    or "planned rerank work" in message
                ):
                    abort_in_flight_retrieval()
                    row_now = self.services.database.job(job_id)
                    if row_now is None or str(row_now["status"]) not in {
                        "complete",
                        "cancelled",
                        "system_error",
                        "failed",
                        "held_for_review",
                    }:
                        now = datetime.now(UTC)
                        try:
                            workflow = parse_job_deadline(
                                row_now["workflow_deadline_at"] if row_now else None
                            )
                            stage = parse_job_deadline(
                                row_now["stage_deadline_at"] if row_now else None
                            )
                        except (TypeError, ValueError):
                            workflow = stage = None
                        if (
                            reason_code == "retrieval_budget_exceeded"
                            or "planned rerank work" in message
                        ):
                            code = "retrieval_budget_exceeded"
                            note = "Planned rerank work cannot fit the remaining research budget."
                        else:
                            code = TERMINAL_WORKFLOW
                            if stage is not None and now > stage:
                                code = TERMINAL_STAGE_TIMEOUT
                            if workflow is not None and now > workflow:
                                code = TERMINAL_WORKFLOW
                            note = (
                                "The job exceeded its current-stage deadline."
                                if code == TERMINAL_STAGE_TIMEOUT
                                else "The job exceeded its whole-workflow deadline."
                            )
                        self._apply_budget_terminal(
                            job_id,
                            job_type,
                            {"code": code, "message": note},
                        )
                    continue
                policy = policy_for(job_type)
                if "lease was lost" in message or "heartbeat stopped" in message:
                    code = "lease_lost"
                elif "cancel" in message.casefold():
                    code = "cancel"
                elif "timeout" in type(exc).__name__.casefold() or "timeout" in message.casefold():
                    code = "timeout"
                else:
                    code = "crash"
                failure = self._record_job_failure(
                    job_id,
                    job_type,
                    code,
                    "A worker failure was recorded.",
                    retryable=True,
                    terminal=False,
                )
                if trace_context is not None and self.observability is not None:
                    self.observability.record_error(
                        trace_context,
                        stage=TraceStage.RUN,
                        error_code=type(exc).__name__,
                    )
                retry_reason = reason_code or code
                pinned_index_build_id = str(row["pinned_index_build_id"] or "")
                # A later attempt ordinal and the same pinned candidate are not
                # evidence that an input or runtime condition changed.  The
                # durable worker therefore records the failure but cannot
                # spend an automatic retry; an explicitly linked new job or a
                # targeted in-run repair must carry the changed identity.
                answer_condition_changed = False
                answer_condition_identity = hashlib.sha256(
                    (
                        "legalbot-answer-owner-resume-condition-v1\0"
                        f"{job_id}\0{pinned_index_build_id}\0{retry_reason}"
                    ).encode()
                ).hexdigest()
                status = self.services.database.retry_or_fail_job(
                    job_id,
                    self.worker_id,
                    error_code=retry_reason,
                    input_or_condition_changed=answer_condition_changed,
                    condition_identity_sha256=answer_condition_identity,
                    max_attempts=policy.max_attempts,
                    retryable=code != "cancel",
                    retry_operation="owner_resume_failed_answer_attempt",
                )
                failure_id = failure.get("failure_id") if failure else None
                if status == "queued" and failure_id:
                    if trace_context is not None and self.observability is not None:
                        self.observability.record_retry(trace_context, stage=TraceStage.QUEUE)
                    self.events.schedule_retry(
                        str(failure_id),
                        component="worker",
                        stage="queued",
                        failure_code=code,
                        job_id=job_id,
                    )
                elif status in {"failed", "dlq", "system_error"} and failure_id:
                    self.events.exhaust(
                        str(failure_id),
                        component="worker",
                        dlq=status in {"failed", "dlq"} and job_type != JobType.ANSWER,
                        job_id=job_id,
                        failure_code="max_attempts_exhausted",
                    )
                terminal_row = self.services.database.job(job_id)
                if (
                    terminal_row is not None
                    and trace_context is not None
                    and self.observability is not None
                ):
                    self.observability.record_terminal(terminal_row)
            finally:
                abort_in_flight_retrieval()
                budget.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await budget
                execution.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await execution
                heartbeat.cancel()
                with suppress(asyncio.CancelledError, Exception):
                    await heartbeat
                release_started = time.perf_counter()
                self.services.database.release_job_lease(job_id, self.worker_id)
                if trace_context is not None and self.observability is not None:
                    self.observability.record_db_duration(
                        trace_context,
                        operation=DatabaseOperation.RELEASE_JOB_LEASE,
                        stage=TraceStage.RELEASE,
                        duration_seconds=time.perf_counter() - release_started,
                    )
                if self.observability is not None:
                    self.observability.persist_snapshot(force=True)

    async def _watch_job_budget(self, job_id: str, job_type: str) -> dict[str, str]:
        """Terminate in-flight work when cancel or stored deadlines fire."""

        while True:
            await asyncio.sleep(0.25)
            row = self.services.database.job(job_id)
            if row is None:
                return {"code": "already_terminal", "message": "missing"}
            status = str(row["status"])
            if status in {
                "complete",
                "cancelled",
                "system_error",
                "failed",
                "held_for_review",
            }:
                return {"code": "already_terminal", "message": status}
            if bool(row["cancel_requested"]):
                return {
                    "code": TERMINAL_CANCELLED,
                    "message": "The job stopped after an in-flight cancellation request.",
                }
            now = datetime.now(UTC)
            try:
                workflow = parse_job_deadline(str(row["workflow_deadline_at"] or "") or None)
                stage = parse_job_deadline(str(row["stage_deadline_at"] or "") or None)
                model = parse_job_deadline(str(row["model_call_deadline_at"] or "") or None)
            except (TypeError, ValueError):
                return {
                    "code": "invalid_persisted_deadline",
                    "message": "The job contains an invalid persisted deadline and was stopped.",
                }
            if workflow is not None and now > workflow:
                return {
                    "code": TERMINAL_WORKFLOW,
                    "message": "The job exceeded its whole-workflow deadline.",
                }
            if job_type == JobType.ANSWER:
                if stage is not None and now > stage:
                    return {
                        "code": TERMINAL_STAGE_TIMEOUT,
                        "message": "The job exceeded its current-stage deadline.",
                    }
                if model is not None and now > model:
                    return {
                        "code": TERMINAL_MODEL_TIMEOUT,
                        "message": "The job exceeded its persisted model-call deadline.",
                    }

    def _apply_budget_terminal(self, job_id: str, job_type: str, reason: dict[str, str]) -> None:
        code = str(reason.get("code") or "timeout")
        message = str(reason.get("message") or "The job exceeded a bounded deadline.")
        if code == TERMINAL_CANCELLED:
            status, stage = "cancelled", "cancelled"
        elif job_type == JobType.ANSWER:
            status, stage = "system_error", "system_error"
        else:
            status, stage = "failed", "failed"
        self.services.database.update_job(
            job_id,
            status=status,
            stage=stage,
            progress=1,
            message=message,
            error_code=code,
        )
        self.services.database.execute(
            "UPDATE jobs SET terminal_reason_code=? WHERE id=?",
            (code, job_id),
        )
        self._record_job_failure(
            job_id,
            job_type,
            "timeout" if code != TERMINAL_CANCELLED else "cancel",
            message,
            retryable=False,
            terminal=True,
        )

    async def _heartbeat(self, job_id: str) -> None:
        interval = max(2, self.lease_seconds // 3)
        while True:
            await asyncio.sleep(interval)
            started = time.perf_counter()
            if not self.services.database.heartbeat_job(
                job_id, self.worker_id, lease_seconds=self.lease_seconds
            ):
                self.events.emit(
                    event_type="operational_failure",
                    component="worker",
                    stage="running",
                    failure_code="heartbeat",
                    source_id=job_id,
                    job_id=job_id,
                    user_or_owner_safe="The job lease heartbeat was lost.",
                    retryable=True,
                    blocking=True,
                )
                raise RuntimeError("job lease was lost")
            context = (
                self.observability.context_for_job(job_id)
                if self.observability is not None
                else None
            )
            if context is not None and self.observability is not None:
                self.observability.record_db_duration(
                    context,
                    operation=DatabaseOperation.HEARTBEAT_JOB,
                    stage=TraceStage.RUN,
                    duration_seconds=time.perf_counter() - started,
                )

    async def _reject_legacy_scheduled_job(self, job_id: str) -> None:
        """Keep retired scheduled jobs out of the legal-answer execution path."""

        self.services.database.update_job(
            job_id,
            status="dlq",
            stage="system_error",
            progress=1,
            message="Use the dedicated research task queue for scheduled official checks.",
            error_code="scheduled_task_requires_research_queue",
        )
        self.services.database.execute("UPDATE jobs SET dlq=1 WHERE id=?", (job_id,))

    def _record_job_failure(
        self,
        job_id: str,
        job_type: str,
        failure_code: str,
        message: str,
        *,
        retryable: bool,
        terminal: bool,
    ) -> dict[str, Any]:
        from ..observability.events import EventType

        event_type = (
            EventType.TERMINAL_FAILURE.value if terminal else EventType.OPERATIONAL_FAILURE.value
        )
        return self.events.emit(
            event_type=event_type,
            component="worker",
            stage=job_type,
            failure_code=failure_code,
            source_id=job_id,
            job_id=job_id,
            user_or_owner_safe=message,
            retryable=retryable,
            blocking=terminal or failure_code in {"timeout", "lease_lost", "crash"},
        )


async def run_worker(services: Services) -> None:
    worker = DurableAnswerWorker(services)
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(signum, worker.stop)
    try:
        await worker.run_forever()
    finally:
        services.database.close()
