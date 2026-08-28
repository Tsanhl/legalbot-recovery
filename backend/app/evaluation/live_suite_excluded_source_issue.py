"""Issue disposition when the bound source stays HOLD or REJECT.

Source exclusion is not issue HOLD forever. If no approved alternative in the
defined source set can safely support the proposition, the issue becomes a
verified knowledge gap.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_gap_verification import seal_gap_verification
from .live_suite_semantic_disposition import (
    DEFAULT_SOURCE_SET_ID,
    DEFAULT_SOURCE_SET_SHA256,
)

EXCLUDED_SOURCE_ISSUE_SCHEMA = "legalbot.excluded-source-issue-resolution.v2"
EXCLUDED_SOURCE_GAP_REASON = "excluded_source_defined_source_set_no_safe_alternative"
REJECTED_SOURCE_GAP_REASON = "rejected_source_defined_source_set_no_safe_alternative"
SOURCE_EFFECTS_GAP_REASON = "source_effects_unresolved_defined_source_set_no_safe_alternative"
Resolution = Literal["alternative_source_bound", "verified_knowledge_gap", "keep_hold"]


def resolve_issue_after_excluded_source(
    issue: Mapping[str, Any],
    *,
    exclusion_kind: Literal["hold", "reject"],
    alternative_approved_source_version_id: str | None = None,
    alternative_exact_spans: Sequence[Mapping[str, Any]] = (),
    defined_source_set_id: str = DEFAULT_SOURCE_SET_ID,
    source_set_manifest_sha256: str = DEFAULT_SOURCE_SET_SHA256,
    as_of_date: str = "2026-08-17",
) -> dict[str, Any]:
    """Bind an approved alternative, or seal a verified knowledge gap."""

    if alternative_approved_source_version_id and alternative_exact_spans:
        issue_update = {
            "disposition": "HOLD",
            "status": "HOLD",
            "final_verification_status": "HOLD",
            "exact_gold_spans": list(alternative_exact_spans),
            "invented_span": False,
            "gap_reason": "source_admitted_semantic_pending",
            "limitation_reason": None,
            "alternative_source_version_id": alternative_approved_source_version_id,
        }
        resolution: Resolution = "alternative_source_bound"
        reason = "alternative_approved_source_bound_semantic_pending"
    else:
        reason = (
            REJECTED_SOURCE_GAP_REASON if exclusion_kind == "reject" else SOURCE_EFFECTS_GAP_REASON
        )
        gap = seal_gap_verification(
            {
                "issue_id": str(issue.get("issue_id") or ""),
                "defined_source_set_id": defined_source_set_id,
                "source_set_manifest_sha256": source_set_manifest_sha256,
                "search_review_method": "deterministic_excluded_source_set_review",
                "coverage_result": "defined_source_set_exhausted",
                "as_of_date": as_of_date,
                "reason_code": reason,
                "review_actor": "deterministic",
            }
        )
        dumped = gap.model_dump(mode="json", by_alias=True)
        issue_update = {
            "disposition": "knowledge_gap",
            "status": "knowledge_gap",
            "final_verification_status": "VERIFIED",
            "exact_gold_spans": [],
            "invented_span": False,
            "gap_reason": reason,
            "gap_verification": dumped,
            "gap_verification_seal_sha256": dumped["seal_sha256"],
            "limitation_reason": None,
        }
        resolution = "verified_knowledge_gap"
    payload = {
        "schema": EXCLUDED_SOURCE_ISSUE_SCHEMA,
        "row_id": issue.get("row_id"),
        "issue_id": issue.get("issue_id"),
        "exclusion_kind": exclusion_kind,
        "resolution": resolution,
        "reason_code": reason,
        "source_hold_does_not_require_issue_hold": True,
        "actor_type": "deterministic",
        "issue_update": issue_update,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "issue_update"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "issue_update"}
    )
    return payload
