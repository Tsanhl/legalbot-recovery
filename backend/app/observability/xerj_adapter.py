"""Disabled Xerj sidecar. Xerj is never merged, vendored or enabled before first live."""

from __future__ import annotations

from typing import Any

XERJ_ADAPTER_SCHEMA = "legalbot.xerj-adapter.v1"


class XerjAdapter:
    """Contract-only adapter. No crates, Lance replacement or AutoIndex."""

    def __init__(self, *, enabled: bool = False) -> None:
        if enabled:
            raise RuntimeError("Xerj is not enabled before first live")
        self.enabled = False
        self.schema = XERJ_ADAPTER_SCHEMA
        self.merged = False
        self.vendored = False

    def start(self) -> dict[str, Any]:
        raise RuntimeError("Xerj sidecar is disabled")

    def status(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "enabled": False,
            "merged": False,
            "vendored": False,
            "external_endpoint": None,
        }
