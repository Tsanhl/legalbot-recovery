"""Stage-specific index-build budgets. Embedding is not a two-hour generic stage."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ..jobs import INDEX_WORKFLOW_SECONDS
from ..types import IndexBuildStage

INDEX_STAGE_POLICY_VERSION = "legalbot.index-stage-policy.v1"

SCANNING_SECONDS = 600
PARSING_SECONDS = 1_800
CHUNKING_SECONDS = 3_600
LEXICAL_SECONDS = 3_600
VECTOR_SECONDS = 7_200
VALIDATING_SECONDS = 3_600

# Ordinary jobs retain the existing 12-hour workflow. A separately fenced
# operator recovery may set a longer persisted workflow deadline; the stage
# guard still enforces whichever exact deadline is stored on that job.
WORKFLOW_SECONDS = INDEX_WORKFLOW_SECONDS

# Long embedding budget is derived from expected rows, then capped so it
# cannot exceed the workflow. This is not a silent global 7200s bump.
EMBEDDING_SECONDS_PER_CHUNK = 0.20
EMBEDDING_SAFETY_MARGIN = 1.5
EMBEDDING_FLOOR_SECONDS = 7_200
EMBEDDING_CAP_SECONDS = 86_400
EMBEDDING_STALL_SECONDS = 1_800
EMBEDDING_CHECKPOINT_BATCHES = 8

_ABSOLUTE: dict[str, int] = {
    IndexBuildStage.SCANNING: SCANNING_SECONDS,
    IndexBuildStage.PARSING: PARSING_SECONDS,
    IndexBuildStage.CHUNKING: CHUNKING_SECONDS,
    IndexBuildStage.BUILDING_LEXICAL: LEXICAL_SECONDS,
    IndexBuildStage.BUILDING_VECTOR: VECTOR_SECONDS,
    IndexBuildStage.VALIDATING: VALIDATING_SECONDS,
}


class IndexDeadlineExceeded(RuntimeError):
    def __init__(self, reason_code: str, message: str = "") -> None:
        self.reason_code = reason_code
        super().__init__(message or reason_code)


@dataclass(frozen=True, slots=True)
class IndexStageBudget:
    stage: str
    absolute_seconds: int
    stall_seconds: int | None = None


def embedding_absolute_seconds(expected_chunks: int) -> int:
    if expected_chunks < 0:
        raise ValueError("expected chunk count cannot be negative")
    derived = int(expected_chunks * EMBEDDING_SECONDS_PER_CHUNK * EMBEDDING_SAFETY_MARGIN)
    return min(EMBEDDING_CAP_SECONDS, max(EMBEDDING_FLOOR_SECONDS, derived))


def budget_for(stage: str, *, expected_chunks: int = 0) -> IndexStageBudget:
    if stage == IndexBuildStage.EMBEDDING:
        return IndexStageBudget(
            stage,
            embedding_absolute_seconds(expected_chunks),
            EMBEDDING_STALL_SECONDS,
        )
    absolute = _ABSOLUTE.get(stage)
    if absolute is None:
        return IndexStageBudget(stage, EMBEDDING_FLOOR_SECONDS)
    return IndexStageBudget(stage, absolute)


def parse_deadline(value: str | None) -> datetime | None:
    if not value:
        return None
    deadline = datetime.fromisoformat(str(value))
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return deadline


def remaining_seconds(deadline: datetime | None, *, now: datetime | None = None) -> float | None:
    if deadline is None:
        return None
    stamp = now or datetime.now(UTC)
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    return (deadline - stamp).total_seconds()


def _deadline_value(job: object, key: str) -> str | None:
    raw: object = None
    getter = getattr(job, "get", None)
    if callable(getter):
        raw = getter(key)
    else:
        try:
            raw = job[key]  # type: ignore[index]
        except (KeyError, IndexError, TypeError):
            raw = None
    text = str(raw or "").strip()
    return text or None


def raise_if_workflow_expired(job: object | None, *, now: datetime | None = None) -> None:
    if job is None:
        return
    remaining = remaining_seconds(
        parse_deadline(_deadline_value(job, "workflow_deadline_at")), now=now
    )
    if remaining is not None and remaining <= 0:
        raise IndexDeadlineExceeded(
            "workflow_deadline_exceeded",
            "index-build workflow deadline expired",
        )


class EmbeddingProgressGuard:
    """Refresh the stall clock only when a larger verified row count is committed."""

    def __init__(
        self,
        *,
        stall_seconds: int,
        clock: Callable[[], float],
        now: Callable[[], datetime],
        workflow_deadline_at: str | None,
        cancel_requested: Callable[[], bool],
        stage_deadline_at: str | None = None,
    ) -> None:
        self.stall_seconds = stall_seconds
        self.clock = clock
        self.now = now
        self.workflow_deadline_at = workflow_deadline_at
        self.stage_deadline_at = stage_deadline_at
        self.cancel_requested = cancel_requested
        self.last_progress_at = clock()
        self.last_row_count = 0

    def note_committed(self, row_count: int) -> None:
        if row_count > self.last_row_count:
            self.last_row_count = row_count
            self.last_progress_at = self.clock()

    def check(self, *, committed_row_count: int | None = None) -> None:
        if self.cancel_requested():
            raise IndexDeadlineExceeded("cancelled", "index-build cancelled")
        raise_if_workflow_expired(
            {"workflow_deadline_at": self.workflow_deadline_at},
            now=self.now(),
        )
        stage_remaining = remaining_seconds(
            parse_deadline(self.stage_deadline_at),
            now=self.now(),
        )
        if stage_remaining is not None and stage_remaining <= 0:
            raise IndexDeadlineExceeded(
                "stage_timeout",
                "index-build embedding stage deadline expired",
            )
        if committed_row_count is not None and committed_row_count > self.last_row_count:
            return
        stalled = self.clock() - self.last_progress_at
        if stalled > self.stall_seconds:
            raise IndexDeadlineExceeded(
                "embedding_progress_stalled",
                "embedding made no durable progress within the stall timeout",
            )
