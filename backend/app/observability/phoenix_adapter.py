"""Disabled Phoenix viewer. Phoenix is later-only and never paired with Xerj."""

from __future__ import annotations

from typing import Any

PHOENIX_ADAPTER_SCHEMA = "legalbot.phoenix-adapter.v1"


class PhoenixAdapter:
    """Contract-only local viewer stub. No external telemetry."""

    def __init__(self, *, enabled: bool = False) -> None:
        if enabled:
            raise RuntimeError("Phoenix is not enabled before first live")
        self.enabled = False
        self.schema = PHOENIX_ADAPTER_SCHEMA
        self.external_telemetry = False

    def start(self) -> dict[str, Any]:
        raise RuntimeError("Phoenix viewer is disabled")

    def status(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "enabled": False,
            "external_telemetry": False,
            "raw_question_answer_source_exported": False,
            "external_endpoint": None,
        }
