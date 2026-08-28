"""Non-promotable early canary against a fully verified selected case.

This path does not require 305/305 overlay completeness. It must not write
ACTIVE, satisfy production Stage A, or create a promotion attestation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from ..retrieval.diagnostic_slice import (
    DIAGNOSTIC_SLICE_BUILD_ID,
    is_diagnostic_slice_build,
)
from .live30 import assert_safe_evaluation_payload
from .live_runtime_separation import early_canary_may_run_before_all_305
from .live_suite import sealed_sha256
from .live_suite_overlay_complete import (
    derive_case_execution_status,
    fully_verified_selected_case_ids,
)

EARLY_CANARY_SCHEMA = "legalbot.live60-early-canary.v1"


def _required_source_version_ids(issues: Sequence[Mapping[str, Any]], case_id: str) -> set[str]:
    required: set[str] = set()
    for item in issues:
        if str(item.get("case_id") or "") != case_id:
            continue
        disposition = str(item.get("disposition") or item.get("status") or "")
        if disposition == "knowledge_gap":
            continue
        for span in item.get("exact_gold_spans") or item.get("verified_positive_spans") or ():
            if isinstance(span, Mapping) and span.get("source_version_id"):
                required.add(str(span["source_version_id"]))
    return required


def plan_early_canary(
    *,
    issues: Sequence[Mapping[str, Any]],
    v2_verified_selected: int,
    diagnostic_slice_build_id: str = DIAGNOSTIC_SLICE_BUILD_ID,
    diagnostic_slice_contains_required_chunks: bool | None = None,
    slice_source_version_ids: Sequence[str] | None = None,
) -> dict[str, Any]:
    case_ids = fully_verified_selected_case_ids(issues)
    permission = early_canary_may_run_before_all_305(
        any_selected_case_fully_verified=bool(case_ids),
        v2_verified_selected=v2_verified_selected,
    )
    slice_ids = set(slice_source_version_ids) if slice_source_version_ids is not None else None
    chosen = None
    contains_required = diagnostic_slice_contains_required_chunks
    if case_ids and slice_ids is not None:

        def _canary_rank(case_id: str) -> tuple[int, int, str]:
            case_issues = [item for item in issues if str(item.get("case_id") or "") == case_id]
            status = derive_case_execution_status(case_issues)
            required = _required_source_version_ids(issues, case_id)
            if status == "generate" and required:
                rank = 0
            elif status == "verified_limited" and required:
                rank = 1
            elif status == "verified_limited":
                rank = 2
            else:
                rank = 3
            return (rank, len(case_issues), case_id)

        covered = [
            case_id
            for case_id in case_ids
            if _required_source_version_ids(issues, case_id) <= slice_ids
        ]
        covered.sort(key=_canary_rank)
        chosen = covered[0] if covered else None
        contains_required = bool(covered)
    elif case_ids:
        chosen = case_ids[0]
    execution_status = None
    if chosen:
        case_issues = [item for item in issues if str(item.get("case_id") or "") == chosen]
        execution_status = derive_case_execution_status(case_issues)
    use_slice = bool(chosen) and contains_required is True
    blockers: list[str] = []
    if not (permission["allowed"] and case_ids):
        blockers.append("no_fully_verified_selected_case")
    elif contains_required is not True:
        blockers.append("diagnostic_slice_missing_required_evidence_chunks")
    payload = {
        "schema": EARLY_CANARY_SCHEMA,
        "allowed": permission["allowed"] and bool(chosen) and use_slice,
        "promotable": False,
        "non_promotable_diagnostic_canary": use_slice,
        "full_30_not_authorized": True,
        "writes_active": False,
        "writes_o04": False,
        "stage_a_production": False,
        "production_readiness": False,
        "fully_verified_selected_case_ids": list(case_ids),
        "canary_case_id": chosen if use_slice else (case_ids[0] if case_ids else None),
        "canary_execution_status": execution_status,
        "canary_build_id": diagnostic_slice_build_id if use_slice else None,
        "diagnostic_slice_is_diagnostic": is_diagnostic_slice_build(diagnostic_slice_build_id),
        "diagnostic_slice_contains_required_chunks": contains_required,
        "blocking_reason_codes": blockers,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload
