"""Cooperative in-flight retrieval budget.

Answer research runs CPU rerank inside ``asyncio.to_thread``. Workflow and
stage deadlines are stored on the job row, but native torch work does not
notice asyncio cancellation. This module is the shared abort/deadline signal
so researching cannot remain non-terminal after those budgets expire.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import UTC, datetime

_LOCK = threading.Lock()
_ABORT = threading.Event()
_DEADLINE_AT: datetime | None = None

# Historical first-live CPU measurement (Q31 run 6): a 32-hit rerank at 1024 payload tokens
# did not finish inside the 300s research stage (~9.4s/hit). Do not assume
# linear/quadratic speedup from the original 8192-token canary.
BASELINE_SECONDS_PER_HIT_AT_1024 = 9.4
RERANK_WORK_SAFETY_MARGIN = 1.2


class RetrievalBudgetExhausted(Exception):
    def __init__(self, reason_code: str, message: str = "") -> None:
        self.reason_code = reason_code
        super().__init__(message or reason_code)


def bind_retrieval_budget(*, deadline_at: datetime | None) -> None:
    global _DEADLINE_AT
    _ABORT.clear()
    with _LOCK:
        _DEADLINE_AT = deadline_at


def tighten_retrieval_deadline(deadline_at: datetime) -> None:
    global _DEADLINE_AT
    with _LOCK:
        current = _DEADLINE_AT
        if current is None or deadline_at < current:
            _DEADLINE_AT = deadline_at


def abort_in_flight_retrieval() -> None:
    _ABORT.set()


def retrieval_deadline_at() -> datetime | None:
    with _LOCK:
        return _DEADLINE_AT


def remaining_retrieval_seconds(*, now: datetime | None = None) -> float | None:
    deadline = retrieval_deadline_at()
    if deadline is None:
        return None
    stamp = now or datetime.now(UTC)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return (deadline - stamp).total_seconds()


def raise_if_retrieval_budget_exhausted() -> None:
    if _ABORT.is_set():
        raise RetrievalBudgetExhausted("retrieval_aborted", "in-flight retrieval was aborted")
    remaining = remaining_retrieval_seconds()
    if remaining is not None and remaining <= 0:
        raise RetrievalBudgetExhausted(
            "retrieval_deadline_exceeded",
            "in-flight retrieval exceeded its bound deadline",
        )


def estimate_rerank_seconds(
    *,
    hit_count: int,
    ranking_payload_tokens: int,
    baseline_seconds_per_hit_at_1024: float = BASELINE_SECONDS_PER_HIT_AT_1024,
    safety_margin: float = RERANK_WORK_SAFETY_MARGIN,
) -> float:
    """Deterministic CPU-work estimate used to fail closed before inference."""

    if hit_count < 0 or ranking_payload_tokens < 1:
        raise ValueError("rerank estimate requires a non-negative hit count")
    scale = ranking_payload_tokens / 1024
    return hit_count * baseline_seconds_per_hit_at_1024 * scale * safety_margin


def raise_if_rerank_work_exceeds_remaining(
    *,
    hit_count: int,
    ranking_payload_tokens: int,
) -> None:
    raise_if_retrieval_budget_exhausted()
    remaining = remaining_retrieval_seconds()
    if remaining is None:
        return
    estimated = estimate_rerank_seconds(
        hit_count=hit_count, ranking_payload_tokens=ranking_payload_tokens
    )
    if estimated > remaining:
        raise RetrievalBudgetExhausted(
            "retrieval_budget_exceeded",
            "planned rerank work cannot fit the remaining research budget",
        )


def raise_if_complete_rerank_plan_exceeds_remaining(
    hit_counts: Sequence[int],
    *,
    ranking_payload_tokens: int,
) -> None:
    """Fail closed on the whole research-stage rerank plan, not one section."""

    raise_if_retrieval_budget_exhausted()
    remaining = remaining_retrieval_seconds()
    if remaining is None:
        return
    estimated = sum(
        estimate_rerank_seconds(hit_count=count, ranking_payload_tokens=ranking_payload_tokens)
        for count in hit_counts
    )
    if estimated > remaining:
        raise RetrievalBudgetExhausted(
            "retrieval_budget_exceeded",
            "planned rerank work cannot fit the remaining research budget",
        )


def wait_for_rerank_slot(semaphore: threading.Semaphore, *, timeout: float = 0.25) -> None:
    """Block for one local inference slot without ignoring cancel/deadline."""

    while True:
        raise_if_retrieval_budget_exhausted()
        if semaphore.acquire(timeout=timeout):
            return


def parse_job_deadline(value: str | None) -> datetime | None:
    if not value:
        return None
    deadline = datetime.fromisoformat(str(value))
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return deadline
