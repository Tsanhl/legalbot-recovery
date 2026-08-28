"""GitHub-safe Live60 V2 status. No private paths, filenames, or source text."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256

STATUS_SCHEMA = "legalbot.live60-v2-status.v1"


def build_live60_v2_status(payload: Mapping[str, Any]) -> dict[str, Any]:
    status = dict(payload)
    status.setdefault("schema", STATUS_SCHEMA)
    status.setdefault("writes_active", False)
    status.setdefault("writes_o04", False)
    status.setdefault("legalbot_is_actually_live", False)
    if status.get("code_sha") and not status.get("implementation_sha"):
        status["implementation_sha"] = status["code_sha"]
    status.setdefault("publisher_identity", "containing_git_commit")
    # Git supplies the containing commit. Do not pretend this JSON knows
    # the SHA of the commit that will later include it.
    status.pop("status_publisher_sha", None)
    status["seal_sha256"] = sealed_sha256(status)
    assert_safe_evaluation_payload(status)
    return status
