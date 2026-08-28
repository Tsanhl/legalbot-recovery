"""Safe operational metrics derived without queries, prompts or source text."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database, utc_iso


def _parse_time(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    weight = position - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


def _distribution(values: list[float]) -> dict[str, float | int | None]:
    return {
        "samples": len(values),
        "p50": _percentile(values, 0.50),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
    }


def build_operational_metrics(database: Database) -> dict[str, Any]:
    """Aggregate the local worker/evaluation ledger into text-free metrics."""

    now = datetime.now(UTC)
    queued = database.fetchall(
        "SELECT status,created_at FROM jobs WHERE status IN ('queued','running')"
    )
    ages = [
        max(0.0, (now - created).total_seconds())
        for row in queued
        if (created := _parse_time(row["created_at"])) is not None
    ]
    stage_durations: dict[str, list[float]] = defaultdict(list)
    generation: list[float] = []
    first_token: list[float] = []
    input_tokens = output_tokens = 0
    peak_memory = 0.0
    for row in database.fetchall(
        "SELECT stage_key,metrics_json FROM job_stage_attempts WHERE status='complete'"
    ):
        try:
            metrics = json.loads(row["metrics_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(metrics, dict):
            continue
        duration = metrics.get("duration_ms")
        if isinstance(duration, int | float):
            stage_durations[str(row["stage_key"])].append(float(duration))
        generation_ms = metrics.get("generation_ms")
        if isinstance(generation_ms, int | float):
            generation.append(float(generation_ms))
        ttft_ms = metrics.get("time_to_first_token_ms")
        if isinstance(ttft_ms, int | float):
            first_token.append(float(ttft_ms))
        input_tokens += int(metrics.get("input_tokens") or 0)
        output_tokens += int(metrics.get("output_tokens") or 0)
        peak_memory = max(peak_memory, float(metrics.get("peak_memory_gb") or 0.0))
    completion_times: list[float] = []
    for row in database.fetchall(
        """
        SELECT created_at,updated_at FROM jobs
        WHERE status IN ('complete','held_for_review','system_error','cancelled')
        """
    ):
        created = _parse_time(row["created_at"])
        updated = _parse_time(row["updated_at"])
        if created is not None and updated is not None:
            completion_times.append(max(0.0, (updated - created).total_seconds() * 1000))
    retries = database.fetchone("SELECT COALESCE(SUM(MAX(attempt_count-1,0)),0) AS n FROM jobs")
    resumes = database.fetchone(
        "SELECT COUNT(*) AS n FROM job_stage_attempts WHERE error_code='worker_lease_expired'"
    )
    duplicate_stage_executions = database.fetchone(
        """
        SELECT COUNT(*) AS n FROM (
          SELECT job_id,stage_key,section_key FROM job_stage_attempts
          WHERE status='complete' GROUP BY job_id,stage_key,section_key HAVING COUNT(*)>1
        )
        """
    )
    worker_heartbeats = database.fetchone(
        "SELECT COUNT(*) AS n FROM service_heartbeats WHERE service_key='answer-worker'"
    )
    queue_by_class = database.job_queue_telemetry()
    return {
        "schema": "legalbot.operational-metrics.v1",
        "created_at": utc_iso(),
        "safe_aggregate_only": True,
        "queue_by_class": queue_by_class,
        "raw_queries_captured": False,
        "source_text_captured": False,
        "queue": {
            "depth": len(queued),
            "oldest_job_age_seconds": round(max(ages), 3) if ages else None,
        },
        "workers": {
            "registered_heartbeats": int(worker_heartbeats["n"]) if worker_heartbeats else 0,
            "utilisation": None,
            "utilisation_note": "Calculated only after a bounded live observation window.",
        },
        "latency_ms": {
            "stages": {
                key: _distribution(values) for key, values in sorted(stage_durations.items())
            },
            "generation": _distribution(generation),
            "time_to_first_token": _distribution(first_token),
            "completion": _distribution(completion_times),
        },
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "peak_memory_gb": peak_memory or None,
        },
        "recovery": {
            "retries": int(retries["n"]) if retries else 0,
            "resumptions": int(resumes["n"]) if resumes else 0,
            "duplicate_completed_stages": (
                int(duplicate_stage_executions["n"]) if duplicate_stage_executions else 0
            ),
            "duplicate_releases": 0,
        },
    }


def write_operational_metrics(settings: Settings, report: dict[str, Any]) -> Path:
    destination = settings.evaluation_dir / "operational-metrics.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination
