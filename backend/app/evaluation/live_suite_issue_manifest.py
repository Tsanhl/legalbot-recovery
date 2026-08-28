"""Canonical V2 issue manifest for the frozen selected 305.

Identities and proof/gap seals only. No source prose, paths, or ACTIVE write.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_overlay_complete import classify_issue_disposition
from .live_suite_path_b import frozen_selected_issue_identities

ISSUE_MANIFEST_SCHEMA = "legalbot.live60-v2-issue-manifest.v1"


def build_issue_manifest_v1(
    *,
    issues: Sequence[Mapping[str, Any]],
    bundle: LiveEvaluationBundle,
) -> dict[str, Any]:
    by_row = {str(item.get("row_id") or ""): item for item in issues}
    rows: list[dict[str, Any]] = []
    for expected in frozen_selected_issue_identities(bundle):
        row_id = expected["row_id"]
        issue = by_row.get(row_id) or {}
        classified = classify_issue_disposition(issue)
        spans = list(issue.get("exact_gold_spans") or issue.get("verified_positive_spans") or ())
        source_version_ids = sorted(
            {
                str(span.get("source_version_id") or "")
                for span in spans
                if isinstance(span, Mapping) and span.get("source_version_id")
            }
        )
        rows.append(
            {
                "row_id": row_id,
                "case_id": expected["case_id"],
                "issue_id": expected["issue_id"],
                "topic_sha256": expected["topic_sha256"],
                "question_sha256": expected["question_sha256"],
                "record_sha256": expected["record_sha256"],
                "disposition": classified["disposition"],
                "verification_status": classified["verification_status"],
                "span_count": len(spans),
                "source_version_ids": source_version_ids,
                "semantic_result_seal_sha256": issue.get("semantic_result_seal_sha256")
                or (
                    (issue.get("semantic_result") or {}).get("seal_sha256")
                    if isinstance(issue.get("semantic_result"), Mapping)
                    else None
                ),
                "gap_verification_seal_sha256": issue.get("gap_verification_seal_sha256")
                or (
                    (issue.get("gap_verification") or {}).get("seal_sha256")
                    if isinstance(issue.get("gap_verification"), Mapping)
                    else None
                ),
                "gap_reason": issue.get("gap_reason"),
                "limitation_reason": issue.get("limitation_reason"),
            }
        )
    verified = sum(1 for item in rows if item["verification_status"] == "VERIFIED")
    payload = {
        "schema": ISSUE_MANIFEST_SCHEMA,
        "selected_total": len(rows),
        "v2_verified_selected": verified,
        "total_hold": len(rows) - verified,
        "frozen_issue_identity_sha256": sealed_sha256(
            {"row_ids": sorted(item["row_id"] for item in rows)}
        ),
        "rows": rows,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "rows"}
    )
    assert_safe_evaluation_payload({key: value for key, value in payload.items() if key != "rows"})
    for item in rows:
        assert_safe_evaluation_payload(item)
    return payload
