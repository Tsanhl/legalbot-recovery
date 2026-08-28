"""Optional OpenTelemetry bridge to local JSONL.

Default export is privacy-safe local JSONL. No raw question, answer or source
text is permitted. External OTLP endpoints are not configured.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .live_tracing import TraceSpan, assert_safe_trace_payload

OTEL_JSONL_SCHEMA = "legalbot.otel-jsonl-span.v1"
FORBIDDEN_KEYS = frozenset(
    {"question", "answer", "source", "prompt", "markdown_text", "path", "filename"}
)


def otel_available() -> bool:
    try:
        import opentelemetry  # noqa: F401
    except ImportError:
        return False
    return True


def span_to_otel_jsonl(span: TraceSpan) -> dict[str, Any]:
    payload = span.to_safe_dict()
    if FORBIDDEN_KEYS.intersection(payload):
        raise ValueError("otel jsonl payload contained a forbidden field")
    record = {
        "schema": OTEL_JSONL_SCHEMA,
        "name": f"{payload['operation']}.{payload['stage']}",
        "trace_id": payload["trace_id"],
        "span_id": payload["span_id"],
        "parent_span_id": payload["parent_span_id"],
        "timestamp": payload["timestamp"],
        "duration_ms": payload["duration_ms"],
        "status": payload["status"],
        "operation": payload["operation"],
        "stage": payload["stage"],
        "level": payload["level"],
        "run_id": payload.get("run_id"),
        "job_id": payload.get("job_id"),
        "case_id": payload.get("case_id"),
        "route": payload.get("route"),
        "word_band": payload.get("word_band"),
        "exporter": "local_jsonl",
        "external_endpoint": None,
    }
    assert_safe_trace_payload(record)
    return record


def append_otel_jsonl(path: Path, span: TraceSpan) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = span_to_otel_jsonl(span)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def export_safe_spans(path: Path, spans: Mapping[str, Any] | list[TraceSpan]) -> int:
    count = 0
    items = spans if isinstance(spans, list) else []
    for span in items:
        append_otel_jsonl(path, span)
        count += 1
    return count
