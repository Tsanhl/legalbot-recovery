"""Unified structured failure and decision events.

Writes to catalog.sqlite3 (operational_events + failure_ledger) and to
gitignored logs/operational-events.jsonl plus logs/failure-ledger.jsonl.
Public APIs must call public_event_view(); they never receive internal_detail.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from ..config import Settings
from ..db import Database, utc_iso
from ..privacy import contains_absolute_private_path, scrub_pii
from .ledger import (
    CREATE_LEDGER_TABLE_SQL,
    LEDGER_SCHEMA,
    LedgerError,
    LedgerState,
    assert_waive_reason,
)
from .projections import OwnerProjectionWriter

EVENT_SCHEMA = "legalbot.operational-event.v1"
PROVENANCE_SCHEMA = "legalbot.observability-provenance.v1"
RECORDED_GIT_SHA = "af36fcc"
RECORDED_GIT_BRANCH = "checkpoint/2026-08-13-architecture-baseline"

OPERATIONAL_EVENTS_JSONL = "operational-events.jsonl"
FAILURE_LEDGER_JSONL = "failure-ledger.jsonl"

NEVER_PERSIST_KEYS = frozenset(
    {
        "system_prompt",
        "developer_prompt",
        "prompt",
        "chain_of_thought",
        "cot",
        "reasoning",
        "full_answer",
        "answer",
        "answer_text",
        "source_text",
        "private_source_text",
        "secret",
        "api_key",
        "password",
        "token",
        "authorization",
        "absolute_path",
        "private_path",
    }
)

# Normal telemetry has a deliberately smaller vocabulary than arbitrary JSON.
# Sensitive debug prose belongs in an encrypted, retention-bound artifact; it
# is never made safe merely by calling a redaction function.
SAFE_EVENT_CONTEXT_KEYS = frozenset(
    {
        "action",
        "attempt",
        "finding_code",
        "original_fingerprint",
        "original_word_count",
        "post_repair_fingerprint",
        "post_repair_word_count",
        "reason_code",
        "repair_attempt",
    }
)
HASHED_EVENT_CONTEXT_KEYS = frozenset({"owner_reason"})

PUBLIC_EVENT_FIELDS = (
    "schema",
    "event_id",
    "event_type",
    "timestamp",
    "component",
    "stage",
    "failure_code",
    "fingerprint",
    "severity",
    "retryable",
    "blocking",
    "job_id",
    "build_id",
    "failure_id",
    "parent_failure_id",
    "user_or_owner_safe",
    "occurrence_count",
    "first_seen",
    "last_seen",
)


class EventType(StrEnum):
    OPERATIONAL_FAILURE = "operational_failure"
    DATA_QUALITY_FAILURE = "data_quality_failure"
    SOURCE_POLICY_FAILURE = "source_policy_failure"
    PRIVACY_FAILURE = "privacy_failure"
    RETRIEVAL_DEGRADATION = "retrieval_degradation"
    QUALITY_GATE_FAILURE = "quality_gate_failure"
    POLICY_DECISION = "policy_decision"
    RETRY_SCHEDULED = "retry_scheduled"
    RECOVERY_SUCCEEDED = "recovery_succeeded"
    TERMINAL_FAILURE = "terminal_failure"
    DLQ_TRANSITION = "dlq_transition"
    WARNING = "warning"


EVENT_TYPES = tuple(item.value for item in EventType)

OPERATIONAL_FAILURE_TYPES = frozenset(
    {
        EventType.OPERATIONAL_FAILURE.value,
        EventType.DATA_QUALITY_FAILURE.value,
        EventType.SOURCE_POLICY_FAILURE.value,
        EventType.PRIVACY_FAILURE.value,
        EventType.QUALITY_GATE_FAILURE.value,
        EventType.TERMINAL_FAILURE.value,
    }
)

LEDGER_EVENT_TYPES = OPERATIONAL_FAILURE_TYPES | {
    EventType.RETRIEVAL_DEGRADATION.value,
}

RETRIEVAL_CODES = (
    "index_not_ready",
    "retriever_unavailable",
    "zero_hits",
    "filtered_out",
    "wrong_jurisdiction",
    "historical_above_current",
    "expected_authority_missing",
    "incomplete_proposition_span",
    "reranker_unavailable",
    "vector_degraded_lexical_only",
    "official_update_review_pending",
    "verified_material_update_unresolved",
)

POLICY_DECISION_CODES = (
    "clarify",
    "refuse",
    "answer-safe-and-refuse-unsafe",
    "verified_limited:index_not_ready",
    "verified_limited:retrieval_zero_hits",
)

CREATE_EVENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS operational_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  component TEXT NOT NULL,
  stage TEXT,
  failure_code TEXT,
  source_id TEXT,
  fingerprint TEXT NOT NULL,
  severity TEXT,
  retryable INTEGER NOT NULL DEFAULT 0,
  blocking INTEGER NOT NULL DEFAULT 0,
  job_id TEXT,
  build_id TEXT,
  failure_id TEXT,
  parent_failure_id TEXT,
  user_or_owner_safe TEXT NOT NULL,
  internal_detail TEXT,
  provenance_json TEXT NOT NULL DEFAULT '{}',
  context_json TEXT NOT NULL DEFAULT '{}',
  occurrence_count INTEGER NOT NULL DEFAULT 1,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_operational_events_fingerprint
  ON operational_events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_operational_events_type
  ON operational_events(event_type, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_operational_events_failure
  ON operational_events(failure_id);
CREATE INDEX IF NOT EXISTS idx_operational_events_job
  ON operational_events(job_id, last_seen DESC);
"""


class LogWriteError(RuntimeError):
    """Raised when operational JSONL or catalogue event writes fail."""


def failure_fingerprint(
    component: str,
    stage: str | None,
    failure_code: str | None,
    source_id: str | None,
) -> str:
    material = "\0".join(
        (
            str(component or ""),
            str(stage or ""),
            str(failure_code or ""),
            str(source_id or ""),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _read_git_provenance() -> tuple[str, str]:
    from ..config import PROJECT_ROOT

    git_dir = PROJECT_ROOT / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return RECORDED_GIT_SHA, RECORDED_GIT_BRANCH
    if head.startswith("ref:"):
        ref = head.split(" ", 1)[1].strip()
        branch = ref.removeprefix("refs/heads/")
        try:
            sha = (git_dir / ref).read_text(encoding="utf-8").strip()
        except OSError:
            sha = RECORDED_GIT_SHA
        return sha[:12] or RECORDED_GIT_SHA, branch or RECORDED_GIT_BRANCH
    return (head[:12] or RECORDED_GIT_SHA), RECORDED_GIT_BRANCH


def collect_provenance(extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    sha, branch = _read_git_provenance()
    payload: dict[str, Any] = {
        "schema": PROVENANCE_SCHEMA,
        "git_sha": os.getenv("LEGALBOT_GIT_SHA") or sha or RECORDED_GIT_SHA,
        "git_branch": os.getenv("LEGALBOT_GIT_BRANCH") or branch or RECORDED_GIT_BRANCH,
    }
    try:
        from ..jobs import (
            CANONICAL_MARKDOWN_VERSION,
            CHUNKER_VERSION,
            INDEX_SCHEMA_VERSION,
            PARSER_VERSION,
        )

        payload.update(
            {
                "parser_version": PARSER_VERSION,
                "chunker_version": CHUNKER_VERSION,
                "canonical_markdown_version": CANONICAL_MARKDOWN_VERSION,
                "index_schema_version": INDEX_SCHEMA_VERSION,
            }
        )
    except Exception:
        pass
    try:
        from ..quality.policy import POLICY_VERSION

        payload["policy_version"] = POLICY_VERSION
    except Exception:
        pass
    if extra:
        for key, value in extra.items():
            if key.casefold() in NEVER_PERSIST_KEYS:
                continue
            if value is None or value == "":
                continue
            safe_value = sanitize_context(value)
            if isinstance(safe_value, str) and contains_absolute_private_path(safe_value):
                continue
            payload[str(key)] = safe_value
    return payload


def redact_text(value: str, owner_identifiers: Sequence[str] = ()) -> str:
    cleaned = scrub_pii(value, owner_identifiers)
    cleaned = re.sub(r"(?i)requested_secret\s*[:=]\s*\S+", "requested_secret=[REDACTED]", cleaned)
    if contains_absolute_private_path(cleaned):
        cleaned = scrub_pii(cleaned, owner_identifiers)
    return cleaned


def safe_event_identifier(value: str | None) -> str | None:
    """Keep normal IDs readable and replace unsafe labels with a stable digest."""

    if value is None:
        return None
    cleaned = " ".join(str(value).split())
    if not cleaned:
        return None
    if (
        len(cleaned) > 255
        or contains_absolute_private_path(cleaned)
        or cleaned.casefold().startswith("file:")
    ):
        return "id-sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()
    return cleaned


def sanitize_context(value: Any, owner_identifiers: Sequence[str] = (), *, depth: int = 0) -> Any:
    if depth > 8:
        return "[REDACTED]"
    if isinstance(value, str):
        return redact_text(value, owner_identifiers)[:500]
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            folded = key.casefold()
            if folded in NEVER_PERSIST_KEYS or "prompt" in folded:
                continue
            if "secret" in folded or folded in {"api_key", "password", "token"}:
                output[key] = "[REDACTED]"
                continue
            if folded == "requested_secret":
                output[key] = "[REDACTED]"
                continue
            output[redact_text(key, owner_identifiers)] = sanitize_context(
                item, owner_identifiers, depth=depth + 1
            )
        return output
    if isinstance(value, list | tuple):
        return [sanitize_context(item, owner_identifiers, depth=depth + 1) for item in value[:40]]
    if isinstance(value, bool | int | float) or value is None:
        return value
    return redact_text(str(value), owner_identifiers)[:200]


def sanitize_event_context(
    value: Mapping[str, Any], owner_identifiers: Sequence[str] = ()
) -> dict[str, Any]:
    """Project arbitrary caller context onto the fixed operational schema."""

    output: dict[str, Any] = {}
    for raw_key, item in value.items():
        key = str(raw_key).casefold()
        if key in HASHED_EVENT_CONTEXT_KEYS:
            cleaned = redact_text(str(item), owner_identifiers)
            output[f"{key}_sha256"] = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
            continue
        if key not in SAFE_EVENT_CONTEXT_KEYS:
            continue
        safe = sanitize_context(item, owner_identifiers)
        if isinstance(safe, str) and contains_absolute_private_path(safe):
            continue
        output[key] = safe
    return output


def public_event_view(event: Mapping[str, Any]) -> dict[str, Any]:
    view = {field: event.get(field) for field in PUBLIC_EVENT_FIELDS if field in event}
    message = redact_text(str(view.get("user_or_owner_safe") or ""))
    view["user_or_owner_safe"] = message
    encoded = json.dumps(view, ensure_ascii=False)
    if contains_absolute_private_path(encoded) or "/Users/" in encoded:
        raise LogWriteError("public-safe event still contains a private path")
    return view


def event_type_for_index_failure(reason_code: str) -> str:
    code = str(reason_code or "")
    if code in {
        "required_source_family_truncated",
        "required_source_family_omitted",
        "source_policy_failure",
    }:
        return EventType.SOURCE_POLICY_FAILURE.value
    if code in {
        "chunk_embedding_count_mismatch",
        "canonical_markdown_missing",
        "no_chunks",
        "no_embedded_chunks",
        "currentness_metadata_missing",
        "incomplete_source_span",
        "source_span_incomplete",
        "unsupported_material_claim",
    }:
        return EventType.DATA_QUALITY_FAILURE.value
    if code in {"private_path_leakage", "personal_data_leakage", "privacy_failure"}:
        return EventType.PRIVACY_FAILURE.value
    if code in {"benchmark_threshold_failure"}:
        return EventType.DATA_QUALITY_FAILURE.value
    return EventType.OPERATIONAL_FAILURE.value


def policy_decision_code(action: str, reason_code: str | None = None) -> str:
    reason = str(reason_code or "")
    act = str(action or "")
    if act == "clarify" or reason in {
        "missing_user_facts",
        "missing_document",
        "encrypted_or_unreadable_upload",
    }:
        return "clarify"
    if act == "refuse" or reason == "entirely_unsafe":
        return "refuse"
    if act == "mixed" or reason == "mixed_safe_unsafe":
        return "answer-safe-and-refuse-unsafe"
    if reason == "index_not_ready":
        return "verified_limited:index_not_ready"
    if reason in {"healthy_retrieval_zero_hits", "retrieval_zero_hits", "zero_hits"}:
        return "verified_limited:retrieval_zero_hits"
    if act == "verified_limited":
        return f"verified_limited:{reason or 'limited'}"
    return act or "policy_decision"


def quality_failure_code(finding_code: str) -> str:
    mapping = {
        "unsupported_material_law": "unsupported_claim",
        "invented_authority": "unsupported_claim",
        "wrong_authority_identity": "citation_not_found",
        "unrelated_evidence": "span_missing",
        "unsupported_material_fact": "span_missing",
        "non_atomic_material_claim": "claim_scope_invalid",
        "false_quotation": "span_missing",
        "non_authority_lane": "identity_without_proposition",
        "materially_outdated_law": "current_law_fail",
        "historical_legislation_used_as_current_law": "current_law_fail",
        "personal_data_leakage": "privacy",
        "prompt_injection": "privacy",
        "shorter_than_requested": "word_floor",
        "wrong_jurisdiction": "wrong_jurisdiction",
        "wrong_reporter": "wrong_reporter",
    }
    return mapping.get(str(finding_code), str(finding_code))


class EventStore:
    def __init__(
        self,
        database: Database,
        logs_dir: Path,
        *,
        owner_identifiers: Sequence[str] = (),
    ) -> None:
        self.database = database
        self.logs_dir = Path(logs_dir)
        self.owner_identifiers = tuple(owner_identifiers)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.projections = OwnerProjectionWriter.for_logs_root(self.logs_dir)
        self._ensure_tables()

    @classmethod
    def from_settings(cls, settings: Settings, database: Database) -> EventStore:
        return cls(
            database,
            settings.logs_dir,
            owner_identifiers=settings.owner_identifiers,
        )

    def _ensure_tables(self) -> None:
        self.database.executescript(CREATE_EVENTS_TABLE_SQL)
        self.database.executescript(CREATE_LEDGER_TABLE_SQL)

    def require_writable(self, *, component: str, stage: str) -> dict[str, Any]:
        """Fail closed if JSONL or catalogue event writes cannot be completed."""

        return self.emit(
            event_type=EventType.WARNING.value,
            component=component,
            stage=stage,
            failure_code="observability_preflight",
            user_or_owner_safe="Observability log write preflight succeeded.",
            retryable=False,
            blocking=False,
        )

    def emit(
        self,
        *,
        event_type: str,
        component: str,
        user_or_owner_safe: str,
        stage: str | None = None,
        failure_code: str | None = None,
        source_id: str | None = None,
        severity: str | None = None,
        retryable: bool = False,
        blocking: bool = False,
        job_id: str | None = None,
        build_id: str | None = None,
        parent_failure_id: str | None = None,
        failure_id: str | None = None,
        internal_detail: str | None = None,
        provenance: Mapping[str, Any] | None = None,
        context: Mapping[str, Any] | None = None,
        open_ledger: bool | None = None,
    ) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {event_type}")
        now = utc_iso()
        source_id = safe_event_identifier(source_id)
        job_id = safe_event_identifier(job_id)
        build_id = safe_event_identifier(build_id)
        parent_failure_id = safe_event_identifier(parent_failure_id)
        failure_id = safe_event_identifier(failure_id)
        fingerprint = failure_fingerprint(component, stage, failure_code, source_id)
        safe_message = redact_text(user_or_owner_safe, self.owner_identifiers)
        safe_internal = (
            "detail-sha256:"
            + hashlib.sha256(
                redact_text(internal_detail, self.owner_identifiers).encode("utf-8")
            ).hexdigest()
            if internal_detail
            else None
        )
        safe_context = sanitize_event_context(dict(context or {}), self.owner_identifiers)
        proven = collect_provenance(provenance)
        existing = self.database.fetchone(
            "SELECT * FROM operational_events WHERE fingerprint=?", (fingerprint,)
        )
        if existing is not None:
            count = int(existing["occurrence_count"] or 1) + 1
            resolved_failure_id = failure_id or existing["failure_id"]
            try:
                self.database.execute(
                    """
                    UPDATE operational_events
                    SET occurrence_count=?, last_seen=?, timestamp=?,
                        job_id=COALESCE(?, job_id), build_id=COALESCE(?, build_id),
                        parent_failure_id=COALESCE(?, parent_failure_id),
                        failure_id=COALESCE(?, failure_id)
                    WHERE fingerprint=?
                    """,
                    (
                        count,
                        now,
                        now,
                        job_id,
                        build_id,
                        parent_failure_id,
                        resolved_failure_id,
                        fingerprint,
                    ),
                )
            except Exception as exc:
                raise LogWriteError("catalogue operational event increment failed") from exc
            compact = {
                "schema": EVENT_SCHEMA,
                "event_id": str(existing["event_id"]),
                "event_type": event_type,
                "timestamp": now,
                "component": component,
                "stage": stage,
                "failure_code": failure_code,
                "fingerprint": fingerprint,
                "failure_id": resolved_failure_id,
                "occurrence_count": count,
                "first_seen": existing["first_seen"],
                "last_seen": now,
                "increment": True,
            }
            self._append_jsonl(self.logs_dir / OPERATIONAL_EVENTS_JSONL, compact)
            if (open_ledger if open_ledger is not None else event_type in LEDGER_EVENT_TYPES) and (
                resolved_failure_id
            ):
                self._touch_ledger(
                    failure_id=str(resolved_failure_id),
                    fingerprint=fingerprint,
                    event_id=str(existing["event_id"]),
                    event_type=event_type,
                    component=component,
                    stage=stage,
                    failure_code=failure_code,
                    source_id=source_id,
                    job_id=job_id or existing["job_id"],
                    build_id=build_id or existing["build_id"],
                    retryable=retryable,
                    blocking=blocking,
                    parent_failure_id=parent_failure_id,
                    user_or_owner_safe=safe_message,
                    internal_detail=safe_internal,
                    provenance=proven,
                    now=now,
                    increment=True,
                )
            row = self.database.fetchone(
                "SELECT * FROM operational_events WHERE fingerprint=?", (fingerprint,)
            )
            return self._row_to_event(row)
        event_id = f"evt-{uuid4().hex[:16]}"
        resolved_failure_id = failure_id
        should_ledger = open_ledger if open_ledger is not None else event_type in LEDGER_EVENT_TYPES
        if should_ledger:
            resolved_failure_id = resolved_failure_id or f"fail-{uuid4().hex[:16]}"
        payload = {
            "schema": EVENT_SCHEMA,
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": now,
            "component": component,
            "stage": stage,
            "failure_code": failure_code,
            "source_id": source_id,
            "fingerprint": fingerprint,
            "severity": severity,
            "retryable": bool(retryable),
            "blocking": bool(blocking),
            "job_id": job_id,
            "build_id": build_id,
            "failure_id": resolved_failure_id,
            "parent_failure_id": parent_failure_id,
            "user_or_owner_safe": safe_message,
            "internal_detail": safe_internal,
            "provenance": proven,
            "context": safe_context,
            "occurrence_count": 1,
            "first_seen": now,
            "last_seen": now,
        }
        try:
            self.database.execute(
                """
                INSERT INTO operational_events(
                  event_id, event_type, timestamp, component, stage, failure_code,
                  source_id, fingerprint, severity, retryable, blocking, job_id,
                  build_id, failure_id, parent_failure_id, user_or_owner_safe,
                  internal_detail, provenance_json, context_json, occurrence_count,
                  first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    event_id,
                    event_type,
                    now,
                    component,
                    stage,
                    failure_code,
                    source_id,
                    fingerprint,
                    severity,
                    int(bool(retryable)),
                    int(bool(blocking)),
                    job_id,
                    build_id,
                    resolved_failure_id,
                    parent_failure_id,
                    safe_message,
                    safe_internal,
                    json.dumps(proven, sort_keys=True),
                    json.dumps(safe_context, sort_keys=True),
                    now,
                    now,
                ),
            )
        except Exception as exc:
            raise LogWriteError("catalogue operational event insert failed") from exc
        self._append_jsonl(self.logs_dir / OPERATIONAL_EVENTS_JSONL, payload)
        if should_ledger and resolved_failure_id:
            self._touch_ledger(
                failure_id=str(resolved_failure_id),
                fingerprint=fingerprint,
                event_id=event_id,
                event_type=event_type,
                component=component,
                stage=stage,
                failure_code=failure_code,
                source_id=source_id,
                job_id=job_id,
                build_id=build_id,
                retryable=retryable,
                blocking=blocking,
                parent_failure_id=parent_failure_id,
                user_or_owner_safe=safe_message,
                internal_detail=safe_internal,
                provenance=proven,
                now=now,
                increment=False,
            )
        return payload

    def schedule_retry(
        self,
        failure_id: str,
        *,
        component: str,
        stage: str | None = None,
        failure_code: str | None = None,
        job_id: str | None = None,
        build_id: str | None = None,
        user_or_owner_safe: str = "A retry was scheduled for the original failure.",
    ) -> dict[str, Any]:
        row = self.ledger(failure_id)
        event = self.emit(
            event_type=EventType.RETRY_SCHEDULED.value,
            component=component,
            stage=stage or (row["stage"] if row else None),
            failure_code=failure_code or (row["failure_code"] if row else "retry"),
            source_id=f"retry:{failure_id}",
            job_id=job_id or (row["job_id"] if row else None),
            build_id=build_id or (row["build_id"] if row else None),
            parent_failure_id=failure_id,
            failure_id=failure_id,
            user_or_owner_safe=user_or_owner_safe,
            retryable=True,
            blocking=False,
            open_ledger=False,
        )
        self._set_ledger_state(failure_id, LedgerState.RETRYING.value, event["timestamp"])
        return event

    def recover(
        self,
        failure_id: str,
        *,
        component: str,
        user_or_owner_safe: str = "The failure recovered and the ledger row was closed.",
        job_id: str | None = None,
        build_id: str | None = None,
    ) -> dict[str, Any]:
        row = self.ledger(failure_id)
        event = self.emit(
            event_type=EventType.RECOVERY_SUCCEEDED.value,
            component=component,
            stage=row["stage"] if row else None,
            failure_code=row["failure_code"] if row else "recovered",
            source_id=f"recovered:{failure_id}",
            job_id=job_id or (row["job_id"] if row else None),
            build_id=build_id or (row["build_id"] if row else None),
            parent_failure_id=failure_id,
            failure_id=failure_id,
            user_or_owner_safe=user_or_owner_safe,
            open_ledger=False,
        )
        self._set_ledger_state(
            failure_id, LedgerState.RECOVERED.value, event["timestamp"], closed=True
        )
        return event

    def exhaust(
        self,
        failure_id: str,
        *,
        component: str,
        dlq: bool = True,
        user_or_owner_safe: str = "Retries were exhausted; the failure is terminal.",
        job_id: str | None = None,
        build_id: str | None = None,
        failure_code: str | None = None,
    ) -> dict[str, Any]:
        row = self.ledger(failure_id)
        terminal = self.emit(
            event_type=EventType.TERMINAL_FAILURE.value,
            component=component,
            stage=row["stage"] if row else None,
            failure_code=failure_code or (row["failure_code"] if row else "max_attempts_exhausted"),
            source_id=f"terminal:{failure_id}",
            job_id=job_id or (row["job_id"] if row else None),
            build_id=build_id or (row["build_id"] if row else None),
            parent_failure_id=failure_id,
            failure_id=failure_id,
            user_or_owner_safe=user_or_owner_safe,
            retryable=False,
            blocking=True,
            open_ledger=False,
        )
        self._set_ledger_state(
            failure_id, LedgerState.TERMINAL.value, terminal["timestamp"], closed=True
        )
        if dlq:
            self.emit(
                event_type=EventType.DLQ_TRANSITION.value,
                component=component,
                stage=row["stage"] if row else None,
                failure_code="dlq_transition",
                source_id=f"dlq:{failure_id}",
                job_id=job_id or (row["job_id"] if row else None),
                build_id=build_id or (row["build_id"] if row else None),
                parent_failure_id=failure_id,
                failure_id=failure_id,
                user_or_owner_safe="The exhausted job entered the dead-letter queue.",
                retryable=False,
                blocking=True,
                open_ledger=False,
            )
        return terminal

    def waive(self, failure_id: str, *, owner_reason: str, component: str) -> dict[str, Any]:
        reason = assert_waive_reason(owner_reason)
        row = self.ledger(failure_id)
        if row is None:
            raise LedgerError(f"failure {failure_id} is not in the ledger")
        event = self.emit(
            event_type=EventType.WARNING.value,
            component=component,
            stage=row["stage"],
            failure_code="waived",
            source_id=f"waived:{failure_id}",
            failure_id=failure_id,
            parent_failure_id=failure_id,
            user_or_owner_safe="An owner waived this failure with a recorded reason.",
            context={"owner_reason": reason},
            open_ledger=False,
        )
        now = event["timestamp"]
        self.database.execute(
            """
            UPDATE failure_ledger
            SET state=?, last_seen=?, closed_at=?, waived_reason=?, owner_reason=?
            WHERE failure_id=?
            """,
            (LedgerState.WAIVED.value, now, now, reason, reason, failure_id),
        )
        updated = self.ledger(failure_id)
        self._append_jsonl(self.logs_dir / FAILURE_LEDGER_JSONL, self._ledger_payload(updated))
        return event

    def ledger(self, failure_id: str) -> Any:
        return self.database.fetchone(
            "SELECT * FROM failure_ledger WHERE failure_id=?", (failure_id,)
        )

    def open_failure_for_job(self, job_id: str) -> Any:
        return self.database.fetchone(
            """
            SELECT * FROM failure_ledger
            WHERE job_id=? AND state IN ('open','retrying')
            ORDER BY last_seen DESC LIMIT 1
            """,
            (job_id,),
        )

    def operational_failure_count(self) -> int:
        row = self.database.fetchone(
            f"""
            SELECT COALESCE(SUM(occurrence_count), 0) AS n
            FROM operational_events
            WHERE event_type IN ({",".join("?" * len(OPERATIONAL_FAILURE_TYPES))})
            """,
            tuple(sorted(OPERATIONAL_FAILURE_TYPES)),
        )
        return int(row["n"] if row else 0)

    def events(self) -> list[dict[str, Any]]:
        return [
            self._row_to_event(row)
            for row in self.database.fetchall(
                "SELECT * FROM operational_events ORDER BY first_seen, event_id"
            )
        ]

    def ledger_rows(self) -> list[Any]:
        return self.database.fetchall(
            "SELECT * FROM failure_ledger ORDER BY first_seen, failure_id"
        )

    def _touch_ledger(
        self,
        *,
        failure_id: str,
        fingerprint: str,
        event_id: str,
        event_type: str,
        component: str,
        stage: str | None,
        failure_code: str | None,
        source_id: str | None,
        job_id: str | None,
        build_id: str | None,
        retryable: bool,
        blocking: bool,
        parent_failure_id: str | None,
        user_or_owner_safe: str,
        internal_detail: str | None,
        provenance: Mapping[str, Any],
        now: str,
        increment: bool,
    ) -> None:
        del event_type
        existing = self.database.fetchone(
            "SELECT * FROM failure_ledger WHERE failure_id=? OR fingerprint=?",
            (failure_id, fingerprint),
        )
        try:
            if existing is None:
                self.database.execute(
                    """
                    INSERT INTO failure_ledger(
                      failure_id, fingerprint, state, component, stage, failure_code,
                      source_id, job_id, build_id, retryable, blocking, parent_failure_id,
                      first_event_id, last_event_id, occurrence_count, first_seen, last_seen,
                      provenance_json, user_or_owner_safe, internal_detail
                    ) VALUES (?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                    """,
                    (
                        failure_id,
                        fingerprint,
                        component,
                        stage,
                        failure_code,
                        source_id,
                        job_id,
                        build_id,
                        int(bool(retryable)),
                        int(bool(blocking)),
                        parent_failure_id,
                        event_id,
                        event_id,
                        now,
                        now,
                        json.dumps(dict(provenance), sort_keys=True),
                        user_or_owner_safe,
                        internal_detail,
                    ),
                )
            else:
                count = int(existing["occurrence_count"] or 1) + (1 if increment else 0)
                if not increment:
                    count = max(count, 1)
                self.database.execute(
                    """
                    UPDATE failure_ledger
                    SET last_seen=?, last_event_id=?, occurrence_count=?,
                        job_id=COALESCE(?, job_id), build_id=COALESCE(?, build_id),
                        parent_failure_id=COALESCE(?, parent_failure_id)
                    WHERE failure_id=?
                    """,
                    (
                        now,
                        event_id,
                        count,
                        job_id,
                        build_id,
                        parent_failure_id,
                        existing["failure_id"],
                    ),
                )
        except Exception as exc:
            raise LogWriteError("catalogue failure ledger write failed") from exc
        row = self.database.fetchone(
            "SELECT * FROM failure_ledger WHERE failure_id=? OR fingerprint=?",
            (failure_id, fingerprint),
        )
        self._append_jsonl(self.logs_dir / FAILURE_LEDGER_JSONL, self._ledger_payload(row))

    def _set_ledger_state(
        self, failure_id: str, state: str, now: str, *, closed: bool = False
    ) -> None:
        if state not in {item.value for item in LedgerState}:
            raise LedgerError(f"unknown ledger state: {state}")
        self.database.execute(
            """
            UPDATE failure_ledger
            SET state=?, last_seen=?, closed_at=CASE WHEN ? THEN ? ELSE closed_at END
            WHERE failure_id=?
            """,
            (state, now, int(closed), now if closed else None, failure_id),
        )
        row = self.ledger(failure_id)
        if row is not None:
            self._append_jsonl(self.logs_dir / FAILURE_LEDGER_JSONL, self._ledger_payload(row))

    def _append_jsonl(self, path: Path, payload: Mapping[str, Any]) -> None:
        line = json.dumps(dict(payload), ensure_ascii=False, sort_keys=True) + "\n"
        if contains_absolute_private_path(line) or "/Users/" in line:
            line = (
                json.dumps(
                    sanitize_context(dict(payload), self.owner_identifiers),
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n"
            )
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.parent.chmod(0o700)
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(descriptor, "ab") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                handle.write(line.encode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            path.chmod(0o600)
        except OSError as exc:
            raise LogWriteError(f"jsonl write failed: {path.name}") from exc
        # SQLite is authoritative and the historical root-level JSONL remains
        # compatible.  Also emit the smaller, prose-free owner projection.
        if path.parent.resolve() == self.logs_dir.resolve():
            if path.name == OPERATIONAL_EVENTS_JSONL:
                self.projections.append_event(payload)
            elif path.name == FAILURE_LEDGER_JSONL:
                self.projections.append_event(payload, ledger=True)

    def _row_to_event(self, row: Any) -> dict[str, Any]:
        provenance = json.loads(row["provenance_json"] or "{}")
        context = json.loads(row["context_json"] or "{}")
        return {
            "schema": EVENT_SCHEMA,
            "event_id": row["event_id"],
            "event_type": row["event_type"],
            "timestamp": row["timestamp"],
            "component": row["component"],
            "stage": row["stage"],
            "failure_code": row["failure_code"],
            "source_id": row["source_id"],
            "fingerprint": row["fingerprint"],
            "severity": row["severity"],
            "retryable": bool(row["retryable"]),
            "blocking": bool(row["blocking"]),
            "job_id": row["job_id"],
            "build_id": row["build_id"],
            "failure_id": row["failure_id"],
            "parent_failure_id": row["parent_failure_id"],
            "user_or_owner_safe": row["user_or_owner_safe"],
            "internal_detail": row["internal_detail"],
            "provenance": provenance,
            "context": context,
            "occurrence_count": int(row["occurrence_count"] or 1),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
        }

    @staticmethod
    def _ledger_payload(row: Any) -> dict[str, Any]:
        provenance = {}
        try:
            provenance = json.loads(row["provenance_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            provenance = {}
        return {
            "schema": LEDGER_SCHEMA,
            "failure_id": row["failure_id"],
            "fingerprint": row["fingerprint"],
            "state": row["state"],
            "component": row["component"],
            "stage": row["stage"],
            "failure_code": row["failure_code"],
            "source_id": row["source_id"],
            "job_id": row["job_id"],
            "build_id": row["build_id"],
            "retryable": bool(row["retryable"]),
            "blocking": bool(row["blocking"]),
            "owner_reason": row["owner_reason"],
            "parent_failure_id": row["parent_failure_id"],
            "first_event_id": row["first_event_id"],
            "last_event_id": row["last_event_id"],
            "occurrence_count": int(row["occurrence_count"] or 1),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "closed_at": row["closed_at"],
            "waived_reason": row["waived_reason"],
            "provenance": provenance,
            "user_or_owner_safe": row["user_or_owner_safe"],
            "internal_detail": row["internal_detail"],
        }


def record_index_stage_failure(
    store: EventStore,
    *,
    stage: str,
    reason_code: str,
    message: str,
    job_id: str | None = None,
    build_id: str | None = None,
    source_id: str | None = None,
    retryable: bool = False,
    blocking: bool = True,
    provenance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return store.emit(
        event_type=event_type_for_index_failure(reason_code),
        component="index_build",
        stage=stage,
        failure_code=reason_code,
        source_id=source_id or build_id or job_id,
        job_id=job_id,
        build_id=build_id,
        user_or_owner_safe=message,
        internal_detail=message,
        retryable=retryable,
        blocking=blocking,
        severity="blocking" if blocking else "warning",
        provenance=provenance,
    )
