"""Structured first-live retrieval telemetry. Never logs question text."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..config import PROJECT_ROOT

TELEMETRY_RELATIVE = Path("data") / "retrieval_telemetry" / "workload.ndjson"
_LOCK = threading.Lock()
_FORBIDDEN_KEYS = frozenset({"query", "question", "text", "prompt", "document"})


def telemetry_path() -> Path:
    override = os.getenv("LEGALBOT_RETRIEVAL_TELEMETRY")
    if override:
        return Path(override)
    return PROJECT_ROOT / TELEMETRY_RELATIVE


def record_retrieval_workload(*, stage: str, data: Mapping[str, Any]) -> None:
    """Append one privacy-safe workload record. Query text is forbidden."""

    if os.getenv("LEGALBOT_TEST_MODE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    } and not os.getenv("LEGALBOT_RETRIEVAL_TELEMETRY"):
        return
    if any(key.casefold() in _FORBIDDEN_KEYS for key in data):
        return
    payload = {
        "schema": "legalbot.retrieval-workload.v1",
        "stage": stage,
        "timestamp_ms": int(time.time() * 1000),
        "data": dict(data),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    path = telemetry_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK, path.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
    except OSError:
        return
