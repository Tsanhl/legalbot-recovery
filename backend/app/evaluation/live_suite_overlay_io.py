"""Write a v2 overlay from issue rows without minting ACTIVE or O-04."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle
from .live_suite_overlay_complete import overlay_complete_v2

VERIFIED_DISPOSITIONS = frozenset({"qualified", "limited", "knowledge_gap"})


def overlay_payload_with_issues(
    *,
    issues: Sequence[Mapping[str, Any]],
    bundle: LiveEvaluationBundle,
    issue_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    complete = overlay_complete_v2(
        selected_issues=issues,
        bundle=bundle,
        issue_manifest_sha256=issue_manifest_sha256,
    )
    verified = sum(
        1
        for item in issues
        if str(item.get("final_verification_status") or "") == "VERIFIED"
        and str(item.get("disposition") or "") in VERIFIED_DISPOSITIONS
    )
    payload = {
        **complete,
        "issues": list(issues),
        "v2_verified_selected": verified,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in complete.items() if key != "case_execution"}
    )
    return payload


def write_overlay_with_issues(
    path: Path,
    *,
    issues: Sequence[Mapping[str, Any]],
    bundle: LiveEvaluationBundle,
    issue_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    payload = overlay_payload_with_issues(
        issues=issues,
        bundle=bundle,
        issue_manifest_sha256=issue_manifest_sha256,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload
