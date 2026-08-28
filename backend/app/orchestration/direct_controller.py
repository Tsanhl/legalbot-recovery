"""Fail-closed execution guard for in-process answer controllers.

The ordinary answer path is supervised by :class:`DurableAnswerWorker`.  A
small number of private certification controllers intentionally run an
``AnswerRunner`` in their own process so they can bind an owned model runtime
and suppress or inspect publication.  Those controllers still need the same
persisted workflow, stage, model-call, cancellation, and lease fences.

This module supplies that supervision without adding another job lifecycle or
an alternative retry mechanism.  It never authorises publication and it never
requeues work.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Coroutine, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn

from ..db import Database, utc_iso
from ..jobs import (
    TERMINAL_CANCELLED,
    TERMINAL_LEASE_LOST,
    TERMINAL_MODEL_TIMEOUT,
    TERMINAL_STAGE_TIMEOUT,
    TERMINAL_WORKFLOW,
)
from ..retrieval.budget import abort_in_flight_retrieval, parse_job_deadline

_TERMINAL_JOB_STATES = frozenset(
    {"complete", "held_for_review", "system_error", "failed", "cancelled", "dlq"}
)
_SAFE_REASON = re.compile(r"[^a-z0-9_]+")


@dataclass(frozen=True, slots=True)
class DirectControllerStop:
    code: str
    message: str
    cancelled: bool = False


class DirectControllerExecutionError(RuntimeError):
    """One direct answer execution stopped under its persisted safety fence."""

    def __init__(self, stop: DirectControllerStop) -> None:
        self.reason_code = stop.code
        self.cancelled = stop.cancelled
        super().__init__(stop.code)


def _safe_exception_code(exc: BaseException) -> str:
    explicit = str(getattr(exc, "reason_code", "") or "").strip().casefold()
    if explicit:
        normalized = _SAFE_REASON.sub("_", explicit).strip("_")
        if normalized:
            return normalized[:120]
    name = _SAFE_REASON.sub("_", type(exc).__name__.casefold()).strip("_")
    return f"direct_controller_{name or 'exception'}"[:120]


def _parse_deadlines(
    row: Mapping[str, Any],
) -> tuple[datetime | None, datetime | None, datetime | None]:
    try:
        return (
            parse_job_deadline(row.get("workflow_deadline_at")),
            parse_job_deadline(row.get("stage_deadline_at")),
            parse_job_deadline(row.get("model_call_deadline_at")),
        )
    except (TypeError, ValueError) as exc:
        raise DirectControllerExecutionError(
            DirectControllerStop(
                "invalid_persisted_deadline",
                "The direct answer job contained an invalid persisted deadline.",
            )
        ) from exc


def _current_stop(
    row: Mapping[str, Any],
    *,
    expected_lease_owner: str,
) -> DirectControllerStop | None:
    if bool(row.get("cancel_requested")):
        return DirectControllerStop(
            TERMINAL_CANCELLED,
            "The direct answer job stopped after a cancellation request.",
            cancelled=True,
        )
    workflow, stage, model = _parse_deadlines(row)
    now = datetime.now(UTC)
    try:
        lease_expires_at = parse_job_deadline(row.get("lease_expires_at"))
    except (TypeError, ValueError):
        lease_expires_at = None
    if (
        str(row.get("lease_owner") or "") != expected_lease_owner
        or lease_expires_at is None
        or lease_expires_at <= now
    ):
        return DirectControllerStop(
            TERMINAL_LEASE_LOST,
            "The direct answer controller lost its exact job lease.",
        )
    if workflow is not None and now > workflow:
        return DirectControllerStop(
            TERMINAL_WORKFLOW,
            "The direct answer job exceeded its whole-workflow deadline.",
        )
    if stage is not None and now > stage:
        return DirectControllerStop(
            TERMINAL_STAGE_TIMEOUT,
            "The direct answer job exceeded its current-stage deadline.",
        )
    if model is not None and now > model:
        return DirectControllerStop(
            TERMINAL_MODEL_TIMEOUT,
            "The direct answer job exceeded its model-call deadline.",
        )
    return None


def _terminalize(
    database: Database,
    job_id: str,
    stop: DirectControllerStop,
    *,
    expected_lease_owner: str,
) -> bool:
    """Atomically make unfinished direct work non-releasable and terminal."""

    stamp = utc_iso()
    status = "cancelled" if stop.cancelled else "system_error"
    stage = "cancelled" if stop.cancelled else "system_error"
    checkpoint = {
        "schema": "legalbot.direct-answer-controller-stop.v1",
        "reason_code": stop.code,
        "resumable": False,
        "publication_allowed": False,
    }
    with database.transaction() as connection:
        row = connection.execute(
            "SELECT status,lease_owner FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if row is None:
            return False
        if row["lease_owner"] != expected_lease_owner:
            return False
        if str(row["status"]) in _TERMINAL_JOB_STATES:
            return False
        released = connection.execute(
            "SELECT 1 FROM release_outbox WHERE job_id=? LIMIT 1", (job_id,)
        ).fetchone()
        if released is not None:
            return False
        updated = connection.execute(
            """
            UPDATE jobs SET status=?,stage=?,progress=1,cancel_requested=1,
              answer_id=NULL,release_state=NULL,error_code=?,terminal_reason_code=?,
              checkpoint_json=?,user_message=?,last_progress_at=?,updated_at=?
            WHERE id=? AND status NOT IN
              ('complete','held_for_review','system_error','failed','cancelled','dlq')
            """,
            (
                status,
                stage,
                stop.code,
                stop.code,
                json.dumps(checkpoint, sort_keys=True, separators=(",", ":")),
                stop.message,
                stamp,
                stamp,
                job_id,
            ),
        )
        if updated.rowcount != 1:
            return False
        connection.execute(
            """
            INSERT INTO job_events(job_id,stage,progress,message,payload_json,created_at)
            VALUES (?, ?, 1, ?, ?, ?)
            """,
            (
                job_id,
                stage,
                stop.message,
                json.dumps(
                    {"direct_controller_stop": stop.code, "publication_allowed": False},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                stamp,
            ),
        )
        return True


async def _watch(
    database: Database,
    job_id: str,
    *,
    expected_lease_owner: str,
    poll_seconds: float,
) -> DirectControllerStop:
    while True:
        row = database.job(job_id)
        if row is None:
            return DirectControllerStop(
                "direct_controller_job_missing",
                "The direct answer job disappeared during execution.",
            )
        status = str(row["status"])
        if status in _TERMINAL_JOB_STATES:
            return DirectControllerStop(
                "already_terminal",
                "The direct answer job reached a terminal state.",
                cancelled=status == "cancelled",
            )
        try:
            stop = _current_stop(
                dict(row),
                expected_lease_owner=expected_lease_owner,
            )
        except DirectControllerExecutionError as exc:
            return DirectControllerStop(exc.reason_code, str(exc))
        if stop is not None:
            return stop
        await asyncio.sleep(poll_seconds)


def _raise_after_terminal_state(database: Database, job_id: str) -> NoReturn:
    row = database.job(job_id)
    code = "direct_controller_job_missing"
    if row is not None:
        status = str(row["status"])
        code = str(
            row["terminal_reason_code"]
            or row["error_code"]
            or (TERMINAL_CANCELLED if status == "cancelled" else "direct_controller_terminal")
        )
    raise DirectControllerExecutionError(
        DirectControllerStop(
            code,
            "The direct answer job stopped before its controller completed.",
            cancelled=bool(row is not None and str(row["status"]) == "cancelled"),
        )
    )


async def run_bounded_direct_answer(
    *,
    database: Database,
    job_id: str,
    execute: Callable[[], Coroutine[Any, Any, None]],
    expected_lease_owner: str,
    poll_seconds: float = 0.05,
) -> None:
    """Run one direct ``AnswerRunner`` under persisted worker-equivalent fences.

    The caller must already own the exact database lease.  Unfinished work is
    terminalized before control returns, and this guard is the lease's sole
    release owner.
    """

    if not 0.01 <= poll_seconds <= 1.0:
        raise ValueError("direct controller poll interval is outside the safe range")
    initial = database.job(job_id)
    if initial is None:
        raise DirectControllerExecutionError(
            DirectControllerStop(
                "direct_controller_job_missing",
                "The direct answer job does not exist.",
            )
        )
    initial_status = str(initial["status"])
    if initial_status in _TERMINAL_JOB_STATES:
        _raise_after_terminal_state(database, job_id)
    try:
        initial_stop = _current_stop(
            dict(initial),
            expected_lease_owner=expected_lease_owner,
        )
    except DirectControllerExecutionError as exc:
        stop = DirectControllerStop(exc.reason_code, str(exc))
        _terminalize(
            database,
            job_id,
            stop,
            expected_lease_owner=expected_lease_owner,
        )
        database.release_job_lease(job_id, expected_lease_owner)
        raise
    if initial_stop is not None:
        _terminalize(
            database,
            job_id,
            initial_stop,
            expected_lease_owner=expected_lease_owner,
        )
        database.release_job_lease(job_id, expected_lease_owner)
        raise DirectControllerExecutionError(initial_stop)

    execution: asyncio.Task[None] = asyncio.create_task(execute(), name=f"direct-answer-{job_id}")
    watcher = asyncio.create_task(
        _watch(
            database,
            job_id,
            expected_lease_owner=expected_lease_owner,
            poll_seconds=poll_seconds,
        ),
        name=f"direct-answer-budget-{job_id}",
    )
    try:
        done, _ = await asyncio.wait({execution, watcher}, return_when=asyncio.FIRST_COMPLETED)
        if execution in done:
            watcher.cancel()
            with suppress(asyncio.CancelledError):
                await watcher
            try:
                await execution
            except asyncio.CancelledError:
                stop = DirectControllerStop(
                    TERMINAL_CANCELLED,
                    "The direct answer execution was cancelled.",
                    cancelled=True,
                )
                _terminalize(
                    database,
                    job_id,
                    stop,
                    expected_lease_owner=expected_lease_owner,
                )
                raise
            except Exception as exc:
                stop = DirectControllerStop(
                    _safe_exception_code(exc),
                    "The direct answer execution failed and was retained as non-release evidence.",
                )
                _terminalize(
                    database,
                    job_id,
                    stop,
                    expected_lease_owner=expected_lease_owner,
                )
                raise

            final = database.job(job_id)
            if final is None:
                raise DirectControllerExecutionError(
                    DirectControllerStop(
                        "direct_controller_job_missing",
                        "The direct answer job disappeared after execution.",
                    )
                )
            # Reject a completion that crossed a persisted deadline even when
            # synchronous work briefly prevented the watcher from being scheduled.
            post_stop = _current_stop(
                dict(final),
                expected_lease_owner=expected_lease_owner,
            )
            if post_stop is not None:
                _terminalize(
                    database,
                    job_id,
                    post_stop,
                    expected_lease_owner=expected_lease_owner,
                )
                raise DirectControllerExecutionError(post_stop)
            if str(final["status"]) not in _TERMINAL_JOB_STATES:
                stop = DirectControllerStop(
                    "direct_controller_incomplete",
                    "The direct answer runner returned without a terminal job state.",
                )
                _terminalize(
                    database,
                    job_id,
                    stop,
                    expected_lease_owner=expected_lease_owner,
                )
                raise DirectControllerExecutionError(stop)
            if str(final["status"]) not in {"complete", "held_for_review"}:
                _raise_after_terminal_state(database, job_id)
            return

        stop = await watcher
        if stop.code == "already_terminal":
            final = database.job(job_id)
            if final is not None and str(final["status"]) in {"complete", "held_for_review"}:
                await execution
                post_stop = _current_stop(
                    dict(final),
                    expected_lease_owner=expected_lease_owner,
                )
                if post_stop is not None:
                    _terminalize(
                        database,
                        job_id,
                        post_stop,
                        expected_lease_owner=expected_lease_owner,
                    )
                    raise DirectControllerExecutionError(post_stop)
                return
            abort_in_flight_retrieval()
            execution.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await execution
            _raise_after_terminal_state(database, job_id)

        _terminalize(
            database,
            job_id,
            stop,
            expected_lease_owner=expected_lease_owner,
        )
        abort_in_flight_retrieval()
        execution.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await execution
        raise DirectControllerExecutionError(stop)
    except asyncio.CancelledError:
        stop = DirectControllerStop(
            TERMINAL_CANCELLED,
            "The direct answer controller was cancelled.",
            cancelled=True,
        )
        _terminalize(
            database,
            job_id,
            stop,
            expected_lease_owner=expected_lease_owner,
        )
        abort_in_flight_retrieval()
        raise
    finally:
        watcher.cancel()
        execution.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await watcher
        with suppress(asyncio.CancelledError, Exception):
            await execution
        database.release_job_lease(job_id, expected_lease_owner)
