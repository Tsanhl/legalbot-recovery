"""Job-class policies: retry, deadlines, terminal reasons. Not a circuit breaker."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .ingestion.chunking import StructuralChunker
from .ingestion.markdown import CanonicalMarkdownConverter
from .types import JobType

PARSER_VERSION = "legalbot.parser-registry.v1"
CHUNKER_VERSION = StructuralChunker.schema
CANONICAL_MARKDOWN_VERSION = CanonicalMarkdownConverter.schema
# This identity covers the persisted Lance row contract used for build
# idempotency and vector carry-forward.  v2 adds independently bound canonical
# chunk and prompt-view content digests; sealed v1 candidates remain readable
# through the explicit legacy-row path.
INDEX_SCHEMA_VERSION = "legalbot.lance-build.v2"

# One initial answer attempt plus at most two explicit, ledger-authorised
# owner resumes.  The worker still never auto-requeues answer work.
ANSWER_MAX_ATTEMPTS = 3
INDEX_BUILD_MAX_ATTEMPTS = 3
SCHEDULED_MAX_ATTEMPTS = 3

# Admission is bounded independently from execution concurrency. The answer
# worker remains single-consumer, while this ceiling prevents an unbounded
# encrypted backlog from exhausting the local catalogue or owner review path.
ANSWER_QUEUE_CAPACITY = 32
INDEX_BUILD_QUEUE_CAPACITY = 1
SCHEDULED_QUEUE_CAPACITY = 20

ANSWER_QUEUE_WAIT_SECONDS = 120
ANSWER_WORKFLOW_SECONDS = 900
ANSWER_STAGE_SECONDS = 300
ANSWER_MODEL_CALL_SECONDS = 300

INDEX_QUEUE_WAIT_SECONDS = 3_600
INDEX_WORKFLOW_SECONDS = 43_200
INDEX_STAGE_SECONDS = 7_200

SCHEDULED_QUEUE_WAIT_SECONDS = 600
SCHEDULED_WORKFLOW_SECONDS = 1_800
SCHEDULED_STAGE_SECONDS = 600

TERMINAL_QUEUE_WAIT = "queue_wait_deadline_exceeded"
TERMINAL_WORKFLOW = "workflow_deadline_exceeded"
TERMINAL_STAGE_TIMEOUT = "stage_timeout"
TERMINAL_MODEL_TIMEOUT = "model_call_timeout"
TERMINAL_LEASE_LOST = "lease_lost"
TERMINAL_CANCELLED = "cancelled"
TERMINAL_MAX_ATTEMPTS = "max_attempts_exhausted"
TERMINAL_STAGE_FAILED = "index_build_stage_failed"
TERMINAL_DUPLICATE = "duplicate_build_refused"
TERMINAL_USER_RETRY = "user_retry_required"
TERMINAL_UNSAFE = "entirely_unsafe"
TERMINAL_CLARIFY = "clarification_required"


@dataclass(frozen=True, slots=True)
class JobClassPolicy:
    job_type: str
    max_attempts: int
    queue_wait_seconds: int
    workflow_seconds: int
    stage_seconds: int
    model_call_seconds: int | None
    terminal_status: str
    dlq_after_cap: bool


POLICIES: dict[str, JobClassPolicy] = {
    JobType.ANSWER: JobClassPolicy(
        JobType.ANSWER,
        ANSWER_MAX_ATTEMPTS,
        ANSWER_QUEUE_WAIT_SECONDS,
        ANSWER_WORKFLOW_SECONDS,
        ANSWER_STAGE_SECONDS,
        ANSWER_MODEL_CALL_SECONDS,
        "system_error",
        False,
    ),
    JobType.INDEX_BUILD: JobClassPolicy(
        JobType.INDEX_BUILD,
        INDEX_BUILD_MAX_ATTEMPTS,
        INDEX_QUEUE_WAIT_SECONDS,
        INDEX_WORKFLOW_SECONDS,
        INDEX_STAGE_SECONDS,
        None,
        "failed",
        True,
    ),
    JobType.SCHEDULED_TASK: JobClassPolicy(
        JobType.SCHEDULED_TASK,
        SCHEDULED_MAX_ATTEMPTS,
        SCHEDULED_QUEUE_WAIT_SECONDS,
        SCHEDULED_WORKFLOW_SECONDS,
        SCHEDULED_STAGE_SECONDS,
        None,
        "dlq",
        True,
    ),
}


def policy_for(job_type: str | None) -> JobClassPolicy:
    return POLICIES.get(str(job_type or JobType.ANSWER), POLICIES[JobType.ANSWER])


def queue_capacity_for(job_type: str | None) -> int:
    resolved = str(job_type or JobType.ANSWER)
    if resolved == JobType.INDEX_BUILD:
        return INDEX_BUILD_QUEUE_CAPACITY
    if resolved == JobType.SCHEDULED_TASK:
        return SCHEDULED_QUEUE_CAPACITY
    return ANSWER_QUEUE_CAPACITY


def utc_now() -> datetime:
    return datetime.now(UTC)


def deadline_after(seconds: int, *, now: datetime | None = None) -> str:
    stamp = now or utc_now()
    return (stamp + timedelta(seconds=seconds)).isoformat()


def index_build_idempotency_key(
    *,
    corpus_id: str,
    approved_source_manifest_hash: str,
    parser_version: str,
    chunker_version: str,
    embedding_model_version: str,
    index_schema_version: str,
    parent_vector_build_id: str | None = None,
    parent_vector_seal_sha256: str | None = None,
) -> str:
    fields = [
        corpus_id,
        approved_source_manifest_hash,
        parser_version,
        chunker_version,
        embedding_model_version,
        index_schema_version,
    ]
    if parent_vector_build_id is not None or parent_vector_seal_sha256 is not None:
        if not parent_vector_build_id or not parent_vector_seal_sha256:
            raise ValueError("parent vector reuse requires both build and seal identities")
        fields.extend((parent_vector_build_id, parent_vector_seal_sha256))
    return "|".join(fields)
