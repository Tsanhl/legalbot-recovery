"""Privacy-safe append-only tracing for local E2E evaluation.

Spans are an allowlisted contract: identifiers, bounded labels, timestamps,
durations and status only. Legal prose, prompts, source text, SQL, filenames,
paths and arbitrary attributes have no field through which to enter the trace.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

from .live_metrics import WORD_BANDS

TRACE_SCHEMA = "legalbot.safe-trace-span.v1"
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_SAFE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECTION_KEY = re.compile(r"^(?:section-[0-9]{2,3}|direct|global)$")


class TraceLevel(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    FATAL = "fatal"


class TraceOperation(StrEnum):
    RUN = "run"
    JOB = "job"
    STAGE = "stage"
    DATABASE = "database"
    MODEL = "model"
    RETRIEVAL = "retrieval"
    RERANK = "rerank"
    VERIFICATION = "verification"
    RELEASE = "release"
    REVIEW = "review"


class TraceStage(StrEnum):
    RUN = "run"
    INTAKE = "intake"
    ROUTING = "routing"
    QUEUE = "queue"
    RETRIEVAL = "retrieval"
    RERANK = "rerank"
    EVIDENCE_FREEZE = "evidence_freeze"
    GENERATION = "generation"
    VERIFICATION = "verification"
    REPAIR = "repair"
    ASSEMBLY = "assembly"
    RELEASE = "release"
    HUMAN_REVIEW = "human_review"


class TraceStatus(StrEnum):
    RUNNING = "running"
    OK = "ok"
    LIMITED = "limited"
    HELD = "held"
    ERROR = "error"
    CANCELLED = "cancelled"


class DatabaseOperation(StrEnum):
    CLAIM_JOB = "claim_job"
    HEARTBEAT_JOB = "heartbeat_job"
    RELEASE_JOB_LEASE = "release_job_lease"
    READ_JOB = "read_job"
    UPDATE_JOB = "update_job"
    APPEND_JOB_EVENT = "append_job_event"
    STORE_EVIDENCE_PACK = "store_evidence_pack"
    STORE_ANSWER_VERSION = "store_answer_version"
    RELEASE_OUTBOX = "release_outbox"
    STORE_EVALUATION_ISSUE = "store_evaluation_issue"
    STORE_KNOWLEDGE_GAP = "store_knowledge_gap"
    INDEX_READ = "index_read"
    TRANSACTION = "transaction"


def _safe_identifier(value: str | None, *, label: str) -> None:
    if value is not None and not _SAFE_ID.fullmatch(value):
        raise ValueError(f"unsafe {label}")


@dataclass(frozen=True, slots=True)
class TraceSpan:
    schema: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    event_id: str
    timestamp: datetime
    operation: TraceOperation
    stage: TraceStage
    status: TraceStatus
    level: TraceLevel
    duration_ms: float
    run_id: str | None = None
    job_id: str | None = None
    case_id: str | None = None
    route: str | None = None
    word_band: str | None = None
    db_operation: DatabaseOperation | None = None
    section_key: str | None = None
    attempt: int | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if self.schema != TRACE_SCHEMA:
            raise ValueError("unknown safe trace schema")
        for label, value in (
            ("trace_id", self.trace_id),
            ("span_id", self.span_id),
            ("parent_span_id", self.parent_span_id),
            ("event_id", self.event_id),
            ("run_id", self.run_id),
            ("job_id", self.job_id),
            ("case_id", self.case_id),
        ):
            _safe_identifier(value, label=label)
        if self.parent_span_id == self.span_id:
            raise ValueError("span cannot be its own parent")
        if self.timestamp.tzinfo is None:
            raise ValueError("trace timestamp must be timezone-aware")
        if not math.isfinite(self.duration_ms) or self.duration_ms < 0:
            raise ValueError("trace duration must be finite and non-negative")
        if self.route not in {None, "direct", "sectioned", "full_enquiry"}:
            raise ValueError("trace route is not allowlisted")
        if self.word_band is not None and self.word_band not in WORD_BANDS:
            raise ValueError("trace word band is not allowlisted")
        if (self.route is None) != (self.word_band is None):
            raise ValueError("trace route and word band must be supplied together")
        if self.operation is TraceOperation.DATABASE and self.db_operation is None:
            raise ValueError("database spans require a low-cardinality DB operation")
        if self.operation is not TraceOperation.DATABASE and self.db_operation is not None:
            raise ValueError("DB operation label is only valid on database spans")
        if self.section_key is not None and not _SECTION_KEY.fullmatch(self.section_key):
            raise ValueError("section key must be an opaque section identifier")
        if self.attempt is not None and not 1 <= self.attempt <= 100:
            raise ValueError("trace attempt is out of range")
        if self.error_code is not None and not _SAFE_CODE.fullmatch(self.error_code):
            raise ValueError("error code must be a bounded code, not prose")

    @classmethod
    def create(
        cls,
        *,
        trace_id: str,
        event_id: str,
        operation: TraceOperation,
        stage: TraceStage,
        status: TraceStatus,
        level: TraceLevel,
        duration_ms: float,
        parent_span_id: str | None = None,
        span_id: str | None = None,
        timestamp: datetime | None = None,
        run_id: str | None = None,
        job_id: str | None = None,
        case_id: str | None = None,
        route: str | None = None,
        word_band: str | None = None,
        db_operation: DatabaseOperation | None = None,
        section_key: str | None = None,
        attempt: int | None = None,
        error_code: str | None = None,
    ) -> Self:
        return cls(
            schema=TRACE_SCHEMA,
            trace_id=trace_id,
            span_id=span_id or uuid.uuid4().hex,
            parent_span_id=parent_span_id,
            event_id=event_id,
            timestamp=timestamp or datetime.now(UTC),
            operation=operation,
            stage=stage,
            status=status,
            level=level,
            duration_ms=float(duration_ms),
            run_id=run_id,
            job_id=job_id,
            case_id=case_id,
            route=route,
            word_band=word_band,
            db_operation=db_operation,
            section_key=section_key,
            attempt=attempt,
            error_code=error_code,
        )

    def to_safe_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.astimezone(UTC).isoformat()
        # StrEnum values serialize as strings, but converting explicitly keeps
        # the dictionary usable by non-JSON consumers as well.
        for key in ("operation", "stage", "status", "level", "db_operation"):
            if value[key] is not None:
                value[key] = str(value[key])
        assert_safe_trace_payload(value)
        return value


def deterministic_sample(
    level: TraceLevel,
    *,
    trace_id: str,
    event_id: str,
    info_rate: float = 0.10,
    debug_enabled: bool = False,
    debug_rate: float = 0.0,
) -> bool:
    """Deterministically sample by trace/event identity.

    WARN, ERROR and FATAL are always retained. DEBUG is disabled unless both
    explicitly enabled and assigned a positive rate. INFO defaults to 10%.
    """

    _safe_identifier(trace_id, label="trace_id")
    _safe_identifier(event_id, label="event_id")
    for rate, label in ((info_rate, "info rate"), (debug_rate, "debug rate")):
        if not math.isfinite(rate) or not 0 <= rate <= 1:
            raise ValueError(f"{label} must be between zero and one")
    if level in {TraceLevel.WARN, TraceLevel.ERROR, TraceLevel.FATAL}:
        return True
    if level is TraceLevel.DEBUG and not debug_enabled:
        return False
    rate = debug_rate if level is TraceLevel.DEBUG else info_rate
    digest = hashlib.sha256(f"{trace_id}:{event_id}".encode()).digest()
    bucket = int.from_bytes(digest[:8], "big") / 2**64
    return bucket < rate


class SafeTraceWriter:
    """Append sampled spans beneath the local evaluation trace directory."""

    def __init__(
        self,
        trace_root: Path,
        *,
        info_rate: float = 0.10,
        debug_enabled: bool = False,
        debug_rate: float = 0.0,
    ) -> None:
        self.trace_root = trace_root.resolve()
        self.info_rate = info_rate
        self.debug_enabled = debug_enabled
        self.debug_rate = debug_rate
        self.path = self.trace_root / "spans.jsonl"

    @classmethod
    def for_project(
        cls,
        project_root: Path,
        *,
        info_rate: float = 0.10,
        debug_enabled: bool = False,
        debug_rate: float = 0.0,
    ) -> Self:
        root = project_root.resolve()
        trace_root = root / "data" / "evaluations" / "e2e" / "traces"
        if not trace_root.resolve().is_relative_to(root):
            raise ValueError("trace root escapes the project through a symlink")
        return cls(
            trace_root,
            info_rate=info_rate,
            debug_enabled=debug_enabled,
            debug_rate=debug_rate,
        )

    def append(self, span: TraceSpan, *, force: bool = False) -> bool:
        """Append one safe span when sampled, or unconditionally for a sealed run.

        ``force`` is intentionally a call-site decision rather than a field in
        the plaintext span.  The runtime enables it only after validating a
        job's binding to an immutable live-evaluation manifest and case digest.
        This gives each validated evaluation a complete trace graph without weakening
        the default DEBUG-off/INFO-10% production-local policy.
        """

        keep = force or deterministic_sample(
            span.level,
            trace_id=span.trace_id,
            event_id=span.event_id,
            info_rate=self.info_rate,
            debug_enabled=self.debug_enabled,
            debug_rate=self.debug_rate,
        )
        if not keep:
            return False
        self.trace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.trace_root.chmod(0o700)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        payload = (
            json.dumps(span.to_safe_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        try:
            with os.fdopen(descriptor, "ab") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.path.chmod(0o600)
        return True

    def read(self) -> tuple[TraceSpan, ...]:
        if not self.path.exists():
            return ()
        spans: list[TraceSpan] = []
        for line_number, raw in enumerate(
            self.path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
                value["timestamp"] = datetime.fromisoformat(value["timestamp"])
                value["operation"] = TraceOperation(value["operation"])
                value["stage"] = TraceStage(value["stage"])
                value["status"] = TraceStatus(value["status"])
                value["level"] = TraceLevel(value["level"])
                if value.get("db_operation") is not None:
                    value["db_operation"] = DatabaseOperation(value["db_operation"])
                spans.append(TraceSpan(**value))
            except Exception as exc:
                raise ValueError(f"invalid safe trace at line {line_number}") from exc
        return tuple(spans)


def _visit_trace_tree(
    span_id: str,
    *,
    trace_id: str,
    children_by_parent: Mapping[str, tuple[str, ...]],
    visiting: set[str],
    visited: set[str],
) -> int:
    if span_id in visiting:
        raise ValueError(f"trace contains a parent cycle: {trace_id}")
    if span_id in visited:
        return 0
    visiting.add(span_id)
    depth = 1 + max(
        (
            _visit_trace_tree(
                child,
                trace_id=trace_id,
                children_by_parent=children_by_parent,
                visiting=visiting,
                visited=visited,
            )
            for child in children_by_parent.get(span_id, ())
        ),
        default=0,
    )
    visiting.remove(span_id)
    visited.add(span_id)
    return depth


def validate_trace_graph(spans: Iterable[TraceSpan]) -> dict[str, Any]:
    """Validate parent/child identity and cycles for complete unsampled traces."""

    by_trace: defaultdict[str, list[TraceSpan]] = defaultdict(list)
    for span in spans:
        by_trace[span.trace_id].append(span)
    if not by_trace:
        raise ValueError("trace graph is empty")
    summaries: list[dict[str, Any]] = []
    for trace_id, trace_spans in sorted(by_trace.items()):
        by_id = {span.span_id: span for span in trace_spans}
        if len(by_id) != len(trace_spans):
            raise ValueError(f"trace has duplicated span IDs: {trace_id}")
        roots = [span for span in trace_spans if span.parent_span_id is None]
        if len(roots) != 1:
            raise ValueError(f"trace must have exactly one root: {trace_id}")
        for span in trace_spans:
            if span.parent_span_id is not None and span.parent_span_id not in by_id:
                raise ValueError(f"trace has an orphan span: {span.span_id}")

        visiting: set[str] = set()
        visited: set[str] = set()
        children: defaultdict[str, list[str]] = defaultdict(list)
        for span in trace_spans:
            if span.parent_span_id is not None:
                children[span.parent_span_id].append(span.span_id)
        children_by_parent = {
            parent: tuple(sorted(child_ids)) for parent, child_ids in children.items()
        }
        maximum_depth = _visit_trace_tree(
            roots[0].span_id,
            trace_id=trace_id,
            children_by_parent=children_by_parent,
            visiting=visiting,
            visited=visited,
        )
        if len(visited) != len(trace_spans):
            raise ValueError(f"trace contains disconnected spans: {trace_id}")
        summaries.append(
            {
                "trace_id": trace_id,
                "root_span_id": roots[0].span_id,
                "span_count": len(trace_spans),
                "maximum_depth": maximum_depth,
            }
        )
    result = {
        "schema": "legalbot.safe-trace-graph-validation.v1",
        "valid": True,
        "trace_count": len(summaries),
        "traces": summaries,
    }
    assert_safe_trace_payload(result)
    return result


def assert_safe_trace_payload(value: Any, *, key: str | None = None) -> None:
    forbidden_keys = {
        "question",
        "raw_question",
        "answer",
        "source_text",
        "source_id",
        "chunk_id",
        "prompt",
        "sql",
        "path",
        "filename",
        "message",
        "detail",
        "attributes",
        "metadata",
    }
    if key is not None and key.casefold() in forbidden_keys:
        raise ValueError(f"forbidden safe-trace field: {key}")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            assert_safe_trace_payload(child, key=str(child_key))
    elif isinstance(value, list | tuple):
        for child in value:
            assert_safe_trace_payload(child, key=key)
    elif isinstance(value, str):
        lowered = value.casefold()
        if (
            "/users/" in lowered
            or "\\users\\" in lowered
            or "bearer " in lowered
            or "-----begin" in lowered
            or lowered.startswith("sk-")
            or "\n" in value
        ):
            raise ValueError("safe trace contains path-like, secret-like or multiline text")
