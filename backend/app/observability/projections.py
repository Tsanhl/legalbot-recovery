"""Privacy-safe, owner-viewable observability projections.

SQLite and the evaluation artifact tree remain authoritative.  The files
written here are append-only convenience views for local inspection and may
be deleted and rebuilt without changing runtime state.

The projection contract deliberately has no field for questions, answers,
prompts, source text, URLs, filenames, paths or arbitrary diagnostic prose.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from ..config import Settings
from .live_metrics import assert_safe_snapshot
from .live_tracing import TraceLevel, TraceSpan, assert_safe_trace_payload

PROJECTION_EVENT_SCHEMA = "legalbot.owner-event-projection.v1"
PROJECTION_METRIC_SCHEMA = "legalbot.owner-metric-projection.v1"
PROJECTION_RESEARCH_METRIC_SCHEMA = "legalbot.owner-research-metric.v1"
PROJECTION_RESEARCH_TRACE_SCHEMA = "legalbot.owner-research-trace.v1"

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_FORBIDDEN_KEYS = frozenset(
    {
        "question",
        "raw_question",
        "answer",
        "answer_text",
        "prompt",
        "source_text",
        "private_source_text",
        "query",
        "public_query",
        "url",
        "canonical_url",
        "filename",
        "path",
        "absolute_path",
        "sql",
        "message",
        "detail",
        "internal_detail",
        "metadata",
        "attributes",
        "user_or_owner_safe",
        "owner_reason",
        "waived_reason",
    }
)

_EVENT_FIELDS = (
    "schema",
    "event_id",
    "event_type",
    "timestamp",
    "component",
    "stage",
    "failure_code",
    "source_id",
    "fingerprint",
    "severity",
    "retryable",
    "blocking",
    "job_id",
    "build_id",
    "failure_id",
    "parent_failure_id",
    "state",
    "first_event_id",
    "last_event_id",
    "occurrence_count",
    "first_seen",
    "last_seen",
    "closed_at",
    "increment",
)

_RESEARCH_METRICS = frozenset(
    {
        "admissions_total",
        "candidates_total",
        "fetch_duration_seconds",
        "validation_duration_seconds",
        "comparison_duration_seconds",
        "queue_depth",
        "oldest_task_age_seconds",
        "retries_total",
        "terminal_total",
        "worker_utilisation",
    }
)
_RESEARCH_TASK_TYPES = frozenset({"source_update_check", "gap_research", "broad_discovery"})
_RESEARCH_PRIORITIES = frozenset({"high", "medium", "low"})
_RESEARCH_STAGES = frozenset(
    {
        "schedule",
        "admission",
        "queue",
        "worker_claim",
        "fetch",
        "validation",
        "active_comparison",
        "quarantine",
        "stage",
        "review_link",
        "complete",
    }
)
_RESEARCH_STATUSES = frozenset(
    {
        "deferred_capacity",
        "queued",
        "running",
        "retry_wait",
        "review_required",
        "completed",
        "failed",
        "cancelled",
        "ok",
        "error",
        "unchanged",
        "changed",
        "new",
        "withdrawn",
        "unknown",
    }
)


class ProjectionStream(StrEnum):
    LIVE60 = "live60"
    RESEARCH = "research"


def _timestamp(value: datetime | None = None) -> str:
    observed = value or datetime.now(UTC)
    if observed.tzinfo is None:
        raise ValueError("projection timestamp must be timezone-aware")
    return observed.astimezone(UTC).isoformat()


def _safe_id(value: str | None, *, label: str) -> str | None:
    if value is None:
        return None
    if not _SAFE_ID.fullmatch(value):
        raise ValueError(f"unsafe projection {label}")
    return value


def _safe_number(value: float, *, label: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"projection {label} must be finite and non-negative")
    return number


def assert_safe_projection_payload(value: Any, *, key: str | None = None) -> None:
    """Reject fields or values that can carry private/legal prose."""

    if key is not None:
        folded = key.casefold()
        if folded in _FORBIDDEN_KEYS or folded.endswith("_text"):
            raise ValueError(f"forbidden owner projection field: {key}")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            assert_safe_projection_payload(child, key=str(child_key))
    elif isinstance(value, list | tuple):
        for child in value:
            assert_safe_projection_payload(child, key=key)
    elif isinstance(value, str):
        lowered = value.casefold()
        if (
            len(value) > 512
            or "\n" in value
            or "/users/" in lowered
            or "\\users\\" in lowered
            or lowered.startswith("file:")
            or lowered.startswith("sk-")
            or "bearer " in lowered
            or "-----begin" in lowered
        ):
            raise ValueError("owner projection contains path-like, secret-like or prose data")


def deterministic_projection_sample(
    level: TraceLevel,
    *,
    identity: str,
    info_rate: float = 0.10,
    force: bool = False,
    high_priority: bool = False,
) -> bool:
    """Retain severe/high-priority records and deterministically sample INFO."""

    if (
        force
        or high_priority
        or level
        in {
            TraceLevel.WARN,
            TraceLevel.ERROR,
            TraceLevel.FATAL,
        }
    ):
        return True
    if level is TraceLevel.DEBUG:
        return False
    if not math.isfinite(info_rate) or not 0 <= info_rate <= 1:
        raise ValueError("projection INFO rate must be between zero and one")
    _safe_id(identity, label="sampling identity")
    bucket = int.from_bytes(hashlib.sha256(identity.encode()).digest()[:8], "big") / 2**64
    return bucket < info_rate


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    """Append one checked JSON object with cross-process locking."""

    assert_safe_projection_payload(payload)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    encoded = (
        json.dumps(dict(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    try:
        with os.fdopen(descriptor, "ab") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        path.chmod(0o600)


class OwnerProjectionWriter:
    """Write disposable, safe projections beneath ``logs/``."""

    events_root: Path
    metrics_root: Path
    traces_root: Path

    def __init__(self, settings: Settings) -> None:
        root = settings.project_root.resolve()
        self._set_roots(
            root=root,
            events_root=settings.operational_events_dir,
            metrics_root=settings.operational_metrics_dir,
            traces_root=settings.operational_traces_dir,
        )

    @classmethod
    def for_logs_root(cls, logs_root: Path) -> OwnerProjectionWriter:
        """Build a writer for tests/standalone stores that only know ``logs``."""

        instance = cls.__new__(cls)
        root = logs_root.resolve().parent
        instance._set_roots(
            root=root,
            events_root=logs_root / "events",
            metrics_root=logs_root / "metrics",
            traces_root=logs_root / "traces",
        )
        return instance

    def _set_roots(
        self,
        *,
        root: Path,
        events_root: Path,
        metrics_root: Path,
        traces_root: Path,
    ) -> None:
        self.events_root = events_root.resolve()
        self.metrics_root = metrics_root.resolve()
        self.traces_root = traces_root.resolve()
        for path in (self.events_root, self.metrics_root, self.traces_root):
            if not path.is_relative_to(root):
                raise ValueError("owner projection root escapes the project")

    def append_event(self, payload: Mapping[str, Any], *, ledger: bool = False) -> None:
        """Project an event/ledger row without its human or internal prose."""

        projected = {key: payload.get(key) for key in _EVENT_FIELDS if key in payload}
        projected["schema"] = PROJECTION_EVENT_SCHEMA
        projected["projection_kind"] = "failure_ledger" if ledger else "operational_event"
        assert_safe_projection_payload(projected)
        filename = "failure-ledger.jsonl" if ledger else "operational-events.jsonl"
        _append_jsonl(self.events_root / filename, projected)

    def append_live_metric(
        self,
        *,
        component: str,
        snapshot: Mapping[str, Any],
        slo: Mapping[str, Any],
    ) -> None:
        if component not in {"api", "worker"}:
            raise ValueError("projection metric component is not allowlisted")
        assert_safe_snapshot(snapshot)
        assert_safe_snapshot(slo)
        payload = {
            "schema": PROJECTION_METRIC_SCHEMA,
            "stream": ProjectionStream.LIVE60.value,
            "component": component,
            "timestamp": snapshot.get("generated_at") or _timestamp(),
            "snapshot": dict(snapshot),
            "slo": dict(slo),
        }
        _append_jsonl(self.metrics_root / "live60.jsonl", payload)

    def append_live_trace(self, span: TraceSpan) -> None:
        payload = span.to_safe_dict()
        assert_safe_trace_payload(payload)
        _append_jsonl(self.traces_root / "live60.jsonl", payload)

    def append_research_metric(
        self,
        *,
        metric: str,
        value: float,
        event_id: str,
        task_type: str | None = None,
        priority: str | None = None,
        status: str | None = None,
        observed_at: datetime | None = None,
    ) -> None:
        if metric not in _RESEARCH_METRICS:
            raise ValueError("research metric is not allowlisted")
        if task_type is not None and task_type not in _RESEARCH_TASK_TYPES:
            raise ValueError("research task type is not allowlisted")
        if priority is not None and priority not in _RESEARCH_PRIORITIES:
            raise ValueError("research priority is not allowlisted")
        if status is not None and status not in _RESEARCH_STATUSES:
            raise ValueError("research status is not allowlisted")
        payload = {
            "schema": PROJECTION_RESEARCH_METRIC_SCHEMA,
            "stream": ProjectionStream.RESEARCH.value,
            "event_id": _safe_id(event_id, label="metric event ID"),
            "timestamp": _timestamp(observed_at),
            "metric": metric,
            "value": round(_safe_number(value, label="metric value"), 6),
            "task_type": task_type,
            "priority": priority,
            "status": status,
        }
        _append_jsonl(self.metrics_root / "research.jsonl", payload)

    def append_research_trace(
        self,
        *,
        trace_id: str,
        event_id: str,
        stage: str,
        status: str,
        duration_ms: float,
        task_id: str | None = None,
        candidate_id: str | None = None,
        source_id: str | None = None,
        authority_identity_id: str | None = None,
        task_type: str | None = None,
        priority: str | None = None,
        level: TraceLevel = TraceLevel.INFO,
        error_code: str | None = None,
        observed_at: datetime | None = None,
        force: bool = False,
    ) -> bool:
        if stage not in _RESEARCH_STAGES:
            raise ValueError("research trace stage is not allowlisted")
        if status not in _RESEARCH_STATUSES:
            raise ValueError("research trace status is not allowlisted")
        if task_type is not None and task_type not in _RESEARCH_TASK_TYPES:
            raise ValueError("research task type is not allowlisted")
        if priority is not None and priority not in _RESEARCH_PRIORITIES:
            raise ValueError("research priority is not allowlisted")
        if error_code is not None and not _SAFE_CODE.fullmatch(error_code):
            raise ValueError("research error code is unsafe")
        identity = f"{_safe_id(trace_id, label='trace ID')}:{_safe_id(event_id, label='event ID')}"
        if not deterministic_projection_sample(
            level,
            identity=hashlib.sha256(identity.encode()).hexdigest(),
            force=force,
            high_priority=priority == "high",
        ):
            return False
        payload = {
            "schema": PROJECTION_RESEARCH_TRACE_SCHEMA,
            "stream": ProjectionStream.RESEARCH.value,
            "trace_id": trace_id,
            "event_id": event_id,
            "timestamp": _timestamp(observed_at),
            "stage": stage,
            "status": status,
            "level": level.value,
            "duration_ms": round(_safe_number(duration_ms, label="trace duration"), 6),
            "task_id": _safe_id(task_id, label="task ID"),
            "candidate_id": _safe_id(candidate_id, label="candidate ID"),
            "source_id": _safe_id(source_id, label="source ID"),
            "authority_identity_id": _safe_id(authority_identity_id, label="authority identity ID"),
            "task_type": task_type,
            "priority": priority,
            "error_code": error_code,
        }
        _append_jsonl(self.traces_root / "research.jsonl", payload)
        return True


def is_sha256(value: str) -> bool:
    """Small public helper for callers constructing opaque projection IDs."""

    return bool(_SHA256.fullmatch(value))
