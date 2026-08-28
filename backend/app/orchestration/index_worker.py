"""Dedicated leased worker for durable index-build jobs only.

Long index stages are synchronous by design and must never occupy the answer
worker's asyncio event loop. This worker owns a separate capability lane,
keeps the SQLite lease alive from a small heartbeat thread, and never writes
ACTIVE. Promotion remains a separate privileged operator action.
"""

from __future__ import annotations

import hashlib
import os
import signal
import socket
import sqlite3
import threading
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from ..config import Settings
from ..db import Database
from ..jobs import TERMINAL_STAGE_TIMEOUT, TERMINAL_WORKFLOW, policy_for
from ..observability.events import EventStore, EventType
from ..retrieval.index_build import IndexBuildRunner
from ..types import JobType

_NON_RETRYABLE_INDEX_FAILURES = frozenset(
    {
        "required_source_family_truncated",
        "private_path_leakage",
        "benchmark_threshold_failure",
        "chunk_embedding_count_mismatch",
        "currentness_metadata_missing",
        "cancelled",
    }
)
_TERMINAL_JOB_STATUSES = frozenset(
    {"complete", "held_for_review", "system_error", "failed", "cancelled", "dlq"}
)
_SQLITE_BUSY_MARKERS = ("database is locked", "database table is locked", "database is busy")
_HEARTBEAT_BUSY_TIMEOUT_MS = 5_000
_HEARTBEAT_LOCK_ATTEMPTS = 6


class DedicatedIndexWorker:
    """Single-capability local worker for one index build at a time."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 60,
        poll_seconds: float = 0.5,
        watchdog_poll_seconds: float = 0.25,
        hard_stop_terminator: Callable[[int], Any] | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        self.worker_id = worker_id or f"index-{socket.gethostname()}-{os.getpid()}"
        self.lease_seconds = lease_seconds
        self.poll_seconds = poll_seconds
        if not 0.01 <= watchdog_poll_seconds <= 5.0:
            raise ValueError("index watchdog poll interval is outside the safe range")
        self.watchdog_poll_seconds = watchdog_poll_seconds
        self._hard_stop_terminator = hard_stop_terminator or (
            (lambda _exit_code: None) if settings.test_mode else os._exit
        )
        self._stop = threading.Event()
        self.events = EventStore.from_settings(settings, database)

    def stop(self) -> None:
        self._stop.set()

    def run_forever(self) -> None:
        while not self._stop.is_set():
            self.database.pulse_service(
                "index-worker",
                self.worker_id,
                {"index_build": True, "max_concurrency": 1},
            )
            row = self.database.claim_next_job(
                self.worker_id,
                lease_seconds=self.lease_seconds,
                job_types=(JobType.INDEX_BUILD,),
            )
            if row is None:
                self._stop.wait(self.poll_seconds)
                continue
            self._run_claim(dict(row))

    def _run_claim(self, row: dict[str, Any]) -> None:
        job_id = str(row["id"])
        job_type = str(row["job_type"])
        if job_type != JobType.INDEX_BUILD:
            raise RuntimeError("index worker claimed a non-index job")

        workflow_deadline = row.get("workflow_deadline_at")
        if workflow_deadline:
            try:
                deadline = datetime.fromisoformat(str(workflow_deadline))
            except (TypeError, ValueError):
                self._terminal_preflight(
                    job_id,
                    error_code="invalid_persisted_deadline",
                    message="The index job contained an invalid persisted deadline.",
                )
                self.database.release_job_lease(job_id, self.worker_id)
                return
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)
            if datetime.now(UTC) > deadline:
                self._terminal_timeout(job_id)
                self.database.release_job_lease(job_id, self.worker_id)
                return

        execution_stop = threading.Event()
        heartbeat_lost = threading.Event()
        watchdog_fired = threading.Event()
        heartbeat = threading.Thread(
            target=self._heartbeat_loop,
            args=(job_id, execution_stop, heartbeat_lost),
            name=f"index-heartbeat-{job_id}",
            daemon=True,
        )
        watchdog = threading.Thread(
            target=self._hard_stop_watchdog_loop,
            args=(job_id, execution_stop, watchdog_fired),
            name=f"index-hard-stop-{job_id}",
            daemon=True,
        )
        heartbeat.start()
        watchdog.start()
        try:
            result = IndexBuildRunner(self.settings, self.database).run_sync(
                job_id,
                expected_lease_owner=self.worker_id,
            )
            completed = self.database.job(job_id)
            completed_by_this_worker = (
                completed is not None
                and str(completed["status"]) == "complete"
                and str(completed["lease_owner"] or "") == self.worker_id
            )
            if not completed_by_this_worker and (
                heartbeat_lost.is_set()
                or watchdog_fired.is_set()
                or not self.database.job_lease_is_current(job_id, self.worker_id)
            ):
                raise RuntimeError("index job lease heartbeat was lost")
            if str(result.get("status") or "") not in {"candidate", "built_unscored"}:
                raise RuntimeError("index build returned an unexpected terminal status")
            opened = self.events.open_failure_for_job(job_id)
            if opened is not None:
                self.events.recover(
                    str(opened["failure_id"]),
                    component="index_worker",
                    job_id=job_id,
                )
        except Exception as exc:
            current = self.database.job(job_id)
            status = str(current["status"]) if current is not None else "missing"
            build_id = str(current["pinned_index_build_id"] or "") if current is not None else ""
            build = (
                self.database.fetchone(
                    "SELECT failure_reason_code FROM index_builds WHERE id=?",
                    (build_id,),
                )
                if build_id
                else None
            )
            reason = str(
                (build["failure_reason_code"] if build is not None else None)
                or getattr(exc, "reason_code", None)
                or type(exc).__name__
            )
            retryable = reason not in _NON_RETRYABLE_INDEX_FAILURES
            self.events.emit(
                event_type=(
                    EventType.OPERATIONAL_FAILURE.value
                    if retryable
                    else EventType.TERMINAL_FAILURE.value
                ),
                component="index_worker",
                stage=str(current["stage"] if current is not None else "unknown"),
                failure_code=reason,
                source_id=job_id,
                job_id=job_id,
                build_id=build_id or None,
                user_or_owner_safe="The dedicated index worker recorded a stage failure.",
                internal_detail=type(exc).__name__,
                retryable=retryable,
                blocking=True,
            )
            still_owned = (
                current is not None
                and current["lease_owner"] == self.worker_id
                and self.database.job_lease_is_current(job_id, self.worker_id)
                and status in {"running", "failed"}
            )
            if still_owned:
                failed_stage_attempt = self.database.fetchone(
                    "SELECT id FROM job_stage_attempts "
                    "WHERE job_id=? AND status IN ('failed','interrupted') "
                    "ORDER BY attempt_number DESC LIMIT 1",
                    (job_id,),
                )
                condition_identity = (
                    hashlib.sha256(
                        (
                            "legalbot-index-stage-retry-v1\0" + str(failed_stage_attempt["id"])
                        ).encode()
                    ).hexdigest()
                    if failed_stage_attempt is not None
                    else None
                )
                self.database.retry_or_fail_job(
                    job_id,
                    self.worker_id,
                    error_code=reason,
                    input_or_condition_changed=failed_stage_attempt is not None,
                    condition_identity_sha256=condition_identity,
                    max_attempts=policy_for(JobType.INDEX_BUILD).max_attempts,
                    retryable=retryable,
                    retry_operation="resume_failed_index_stage",
                )
            elif current is not None and current["lease_owner"] not in {None, self.worker_id}:
                # A newer worker owns the durable identity. The stale process may
                # report its safe event, but it cannot change the new owner's job.
                pass
        finally:
            execution_stop.set()
            heartbeat.join(timeout=max(2.0, self.lease_seconds / 3))
            watchdog.join(timeout=max(2.0, self.watchdog_poll_seconds * 4))
            final = self.database.job(job_id)
            if not (
                final is not None
                and str(final["status"]) == "running"
                and str(final["lease_owner"] or "") == self.worker_id
            ):
                self.database.release_job_lease(job_id, self.worker_id)

    def _heartbeat_loop(
        self,
        job_id: str,
        stop: threading.Event,
        lost: threading.Event,
    ) -> None:
        interval = max(2, self.lease_seconds // 4)
        while not stop.wait(interval):
            outcome = self._renew_critical_job_lease(job_id, stop)
            if outcome == "terminal":
                return
            if outcome != "renewed":
                self._record_heartbeat_loss(job_id, lost, failure_code="heartbeat")
                return
            # Service discovery telemetry is non-critical. A transient SQLite
            # writer lock after the exact job lease has renewed must not kill
            # the heartbeat thread or sacrifice the build lease.
            try:
                self.database.pulse_service(
                    "index-worker",
                    self.worker_id,
                    {"index_build": True, "max_concurrency": 1, "busy": True},
                )
            except sqlite3.OperationalError as exc:
                if self._sqlite_busy(exc):
                    continue
                self._record_heartbeat_loss(
                    job_id, lost, failure_code="service_pulse_operational_error"
                )
                return
            except Exception:
                self._record_heartbeat_loss(job_id, lost, failure_code="service_pulse_error")
                return

    @staticmethod
    def _sqlite_busy(exc: sqlite3.OperationalError) -> bool:
        message = str(exc).casefold()
        return any(marker in message for marker in _SQLITE_BUSY_MARKERS)

    def _renew_critical_job_lease(self, job_id: str, stop: threading.Event) -> str:
        for attempt in range(_HEARTBEAT_LOCK_ATTEMPTS):
            try:
                renewed = self.database.heartbeat_job(
                    job_id,
                    self.worker_id,
                    lease_seconds=self.lease_seconds,
                    busy_timeout_ms=_HEARTBEAT_BUSY_TIMEOUT_MS,
                )
            except sqlite3.OperationalError as exc:
                if not self._sqlite_busy(exc):
                    return "failed"
                if attempt + 1 >= _HEARTBEAT_LOCK_ATTEMPTS:
                    return "failed"
                if stop.wait(min(2.0, 0.25 * (2**attempt))):
                    return "terminal"
                continue
            except Exception:
                return "failed"
            if renewed:
                return "renewed"
            try:
                current = self.database.job(job_id)
            except sqlite3.OperationalError as exc:
                if self._sqlite_busy(exc) and attempt + 1 < _HEARTBEAT_LOCK_ATTEMPTS:
                    if stop.wait(min(2.0, 0.25 * (2**attempt))):
                        return "terminal"
                    continue
                return "failed"
            except Exception:
                return "failed"
            if current is not None and str(current["status"]) in _TERMINAL_JOB_STATUSES:
                return "terminal"
            return "failed"
        return "failed"

    def _record_heartbeat_loss(
        self,
        job_id: str,
        lost: threading.Event,
        *,
        failure_code: str,
    ) -> None:
        lost.set()
        with suppress(Exception):
            self.events.emit(
                event_type=EventType.OPERATIONAL_FAILURE.value,
                component="index_worker",
                stage="running",
                failure_code=failure_code,
                source_id=job_id,
                job_id=job_id,
                user_or_owner_safe="The index worker lost its durable job lease.",
                retryable=True,
                blocking=True,
            )

    def _hard_stop_watchdog_loop(
        self,
        job_id: str,
        stop: threading.Event,
        fired: threading.Event,
    ) -> None:
        """Kill the dedicated process if synchronous native work crosses a hard fence."""

        while not stop.wait(self.watchdog_poll_seconds):
            row = self.database.job(job_id)
            if row is not None and str(row["status"]) in {
                "complete",
                "held_for_review",
                "system_error",
                "failed",
                "cancelled",
                "dlq",
            }:
                return
            reason_code: str | None = None
            message = "The index worker lost its exact execution fence."
            if row is None:
                reason_code = "lease_lost"
            else:
                if str(row["lease_owner"] or "") != self.worker_id or row["lease_expires_at"] in (
                    None,
                    "",
                ):
                    reason_code = "lease_lost"
                else:
                    try:
                        lease_expires_at = datetime.fromisoformat(str(row["lease_expires_at"]))
                    except ValueError:
                        lease_expires_at = datetime.min.replace(tzinfo=UTC)
                    if lease_expires_at.tzinfo is None:
                        lease_expires_at = lease_expires_at.replace(tzinfo=UTC)
                    if lease_expires_at <= datetime.now(UTC):
                        reason_code = "lease_lost"
                if reason_code is None and bool(row["cancel_requested"]):
                    reason_code = "cancelled"
                    message = "The index build was hard-stopped after cancellation."
                elif reason_code is None:
                    now = datetime.now(UTC)
                    for column, code, safe_message in (
                        (
                            "workflow_deadline_at",
                            TERMINAL_WORKFLOW,
                            "The index build exceeded its whole-workflow deadline.",
                        ),
                        (
                            "stage_deadline_at",
                            TERMINAL_STAGE_TIMEOUT,
                            "The index build exceeded its current-stage deadline.",
                        ),
                    ):
                        raw_deadline = row[column]
                        if raw_deadline in (None, ""):
                            continue
                        try:
                            deadline = datetime.fromisoformat(str(raw_deadline))
                        except (TypeError, ValueError):
                            reason_code = "invalid_persisted_deadline"
                            message = "The index build contained an invalid persisted deadline."
                            break
                        if deadline.tzinfo is None:
                            deadline = deadline.replace(tzinfo=UTC)
                        if deadline <= now:
                            reason_code = code
                            message = safe_message
                            break
            if reason_code is None:
                continue
            # Once a hard-stop reason is observed, failure to persist or read
            # its catalogue state must bias toward killing this dedicated
            # process. Only a successfully reread, already-committed completion
            # can prove the observation obsolete.
            should_terminate = True
            try:
                terminalized = self.database.terminalize_owned_index_execution(
                    job_id,
                    self.worker_id,
                    reason_code=reason_code,
                    message=message,
                )
                current = self.database.job(job_id)
                should_terminate = (
                    terminalized or current is None or current["status"] != "complete"
                )
            except Exception:
                should_terminate = True
            if should_terminate:
                fired.set()
                try:
                    self.events.emit(
                        event_type=EventType.TERMINAL_FAILURE.value,
                        component="index_worker",
                        stage="hard_stop",
                        failure_code=reason_code,
                        source_id=job_id,
                        job_id=job_id,
                        user_or_owner_safe=message,
                        retryable=False,
                        blocking=True,
                    )
                except Exception:
                    # A full disk, unavailable catalogue or broken projection
                    # cannot be allowed to defeat the hard execution fence.
                    pass
                finally:
                    self._hard_stop_terminator(70)
            return

    def _terminal_timeout(self, job_id: str) -> None:
        self._terminal_preflight(
            job_id,
            error_code=TERMINAL_WORKFLOW,
            message="The index job exceeded its whole-workflow deadline before execution.",
        )

    def _terminal_preflight(self, job_id: str, *, error_code: str, message: str) -> None:
        self.database.terminalize_owned_index_execution(
            job_id,
            self.worker_id,
            reason_code=error_code,
            message=message,
        )


def run_index_worker(settings: Settings) -> None:
    """Run the dedicated index capability until SIGINT or SIGTERM."""

    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    worker = DedicatedIndexWorker(settings, database)

    def stop(_signum: int, _frame: object) -> None:
        worker.stop()

    for signum in (signal.SIGINT, signal.SIGTERM):
        with suppress(ValueError):
            signal.signal(signum, stop)
    try:
        worker.run_forever()
    finally:
        database.close()
