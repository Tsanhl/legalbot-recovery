"""V2 overlay completeness from verified dispositions, not 305 positive spans.

V1 ``_full_run_seal_blockers`` remains the audit path that requires 305/305
qualified exact spans. This module is additive. Unreviewed and HOLD still
block completeness. Knowledge gaps may not invent spans or keep a positive
span. VERIFIED is not inferred from ``status=qualified`` plus a span.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_path_b import (
    FULL_RUN_SELECTED_CASE_COUNT,
    FULL_RUN_SELECTED_ISSUE_COUNT,
    frozen_selected_issue_identities,
    selected_generation_case_ids,
)

OVERLAY_COMPLETE_V2_SCHEMA = "legalbot.live60-overlay-complete.v2"
VERIFIED_DISPOSITIONS = frozenset({"qualified", "limited", "knowledge_gap"})
BLOCKING_DISPOSITIONS = frozenset(
    {"unreviewed", "HOLD", "hold", "pending_official_materialisation", "UNREVIEWED"}
)
POSITIVE_SPAN_DISPOSITIONS = frozenset({"qualified", "limited"})
CaseExecutionStatus = Literal["generate", "verified_limited", "held"]


def _issue_disposition(issue: Mapping[str, Any]) -> str:
    status = str(
        issue.get("final_verification_status") or issue.get("verification_status") or ""
    ).strip()
    disposition = str(issue.get("disposition") or issue.get("status") or "unreviewed").strip()
    if disposition in BLOCKING_DISPOSITIONS or status in {
        "HOLD",
        "hold",
        "UNREVIEWED",
        "REQUIRES_SEMANTIC_REVERIFICATION",
    }:
        if disposition == "knowledge_gap" and status == "VERIFIED":
            return "knowledge_gap"
        if disposition in BLOCKING_DISPOSITIONS:
            return disposition
        return "unreviewed"
    if status and status != "VERIFIED":
        return "unreviewed"
    if disposition not in VERIFIED_DISPOSITIONS:
        return "unreviewed"
    return disposition


def _has_positive_span(issue: Mapping[str, Any]) -> bool:
    spans = issue.get("exact_gold_spans") or issue.get("verified_positive_spans") or ()
    return bool(spans)


def _gap_reason(issue: Mapping[str, Any]) -> str:
    return str(
        issue.get("gap_reason") or issue.get("reason_code") or issue.get("limitation_reason") or ""
    ).strip()


def _has_gap_attestation(issue: Mapping[str, Any]) -> bool:
    gap = issue.get("gap_verification")
    if isinstance(gap, Mapping) and str(gap.get("seal_sha256") or ""):
        return True
    return bool(str(issue.get("gap_verification_seal_sha256") or "").strip())


def _has_v2_proof_seal(issue: Mapping[str, Any]) -> bool:
    return bool(
        str(issue.get("semantic_result_seal_sha256") or "").strip()
        or str(issue.get("proof_seal_sha256") or "").strip()
        or (
            isinstance(issue.get("semantic_result"), Mapping)
            and str((issue.get("semantic_result") or {}).get("seal_sha256") or "")
        )
        or (
            isinstance(issue.get("proof"), Mapping)
            and str((issue.get("proof") or {}).get("seal_sha256") or "")
        )
    )


def classify_issue_disposition(issue: Mapping[str, Any]) -> dict[str, Any]:
    """Return the v2 disposition for one selected issue."""

    disposition = _issue_disposition(issue)
    has_span = _has_positive_span(issue)
    reason = _gap_reason(issue)
    blockers: list[str] = []
    if disposition == "qualified":
        if not has_span:
            blockers.append("qualified_requires_verified_positive_span")
        if not _has_v2_proof_seal(issue):
            blockers.append("verified_requires_v2_proof_seal")
    elif disposition == "limited":
        if not has_span:
            blockers.append("limited_requires_verified_positive_span")
        if not str(issue.get("limitation_reason") or reason):
            blockers.append("limited_requires_limitation_reason")
        if not _has_v2_proof_seal(issue):
            blockers.append("verified_requires_v2_proof_seal")
    elif disposition == "knowledge_gap":
        if has_span:
            blockers.append("knowledge_gap_must_not_have_positive_span")
        if issue.get("invented_span") is True:
            blockers.append("knowledge_gap_must_not_invent_span")
        if not reason:
            blockers.append("knowledge_gap_requires_explicit_reason")
        if not _has_gap_attestation(issue):
            blockers.append("knowledge_gap_requires_gap_verification")
    else:
        blockers.append("issue_unreviewed_or_hold")
    payload = {
        "row_id": issue.get("row_id"),
        "case_id": issue.get("case_id"),
        "issue_id": issue.get("issue_id"),
        "disposition": disposition if not blockers else "unreviewed",
        "verification_status": "VERIFIED" if not blockers else "HOLD",
        "has_positive_span": has_span,
        "blocking_reason_codes": blockers,
    }
    return payload


def fully_verified_selected_case_ids(
    issues: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    """Selected cases whose every issue is a verified v2 disposition."""

    by_case: dict[str, list[Mapping[str, Any]]] = {}
    order: list[str] = []
    for issue in issues:
        case_id = str(issue.get("case_id") or "")
        if not case_id:
            continue
        if case_id not in by_case:
            order.append(case_id)
            by_case[case_id] = []
        by_case[case_id].append(issue)
    verified: list[str] = []
    for case_id in order:
        classified = [classify_issue_disposition(item) for item in by_case[case_id]]
        if classified and all(item["verification_status"] == "VERIFIED" for item in classified):
            verified.append(case_id)
    return tuple(verified)


def derive_case_execution_status(
    issues: Sequence[Mapping[str, Any]],
) -> CaseExecutionStatus:
    """Derive generate / verified_limited / held from material issue dispositions.

    One held case must not block the other selected cases. This function is
    per-case only.
    """

    classified = [classify_issue_disposition(issue) for issue in issues]
    if any(item["disposition"] == "unreviewed" for item in classified):
        return "held"
    if not classified:
        return "held"
    if all(item["disposition"] == "qualified" for item in classified):
        return "generate"
    if all(item["disposition"] == "knowledge_gap" for item in classified):
        return "held"
    if any(item["disposition"] == "knowledge_gap" for item in classified):
        if any(item["disposition"] in POSITIVE_SPAN_DISPOSITIONS for item in classified):
            return "verified_limited"
        return "held"
    if any(item["disposition"] == "limited" for item in classified):
        return "verified_limited"
    return "held"


def overlay_complete_v2(
    *,
    selected_issues: Sequence[Mapping[str, Any]],
    selected_cases: Sequence[Mapping[str, Any]] | None = None,
    selected_issue_count: int = FULL_RUN_SELECTED_ISSUE_COUNT,
    selected_case_count: int = FULL_RUN_SELECTED_CASE_COUNT,
    bundle: LiveEvaluationBundle | None = None,
    enforce_frozen_identities: bool = True,
    issue_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """V2 overlay is complete when every selected issue has a verified disposition."""

    classified = [classify_issue_disposition(issue) for issue in selected_issues]
    counts = Counter(item["disposition"] for item in classified)
    qualified = int(counts.get("qualified") or 0)
    limited = int(counts.get("limited") or 0)
    gaps = int(counts.get("knowledge_gap") or 0)
    unreviewed = len(classified) - qualified - limited - gaps
    positive = sum(1 for item in classified if item["disposition"] in POSITIVE_SPAN_DISPOSITIONS)
    derived_cases = selected_cases
    if derived_cases is None:
        seen_cases: list[str] = []
        seen_set: set[str] = set()
        for item in selected_issues:
            case_id = str(item.get("case_id") or "")
            if case_id and case_id not in seen_set:
                seen_set.add(case_id)
                seen_cases.append(case_id)
        derived_cases = [{"case_id": case_id} for case_id in seen_cases]
    case_outcomes: list[dict[str, Any]] = []
    for case in derived_cases:
        case_id = str(case.get("case_id") or "")
        issues = [item for item in selected_issues if str(item.get("case_id") or "") == case_id]
        if not issues:
            issues = list(case.get("issues") or ())
        status = derive_case_execution_status(issues)
        case_outcomes.append({"case_id": case_id, "execution_status": status})
    blockers: list[str] = []
    row_ids = [str(item.get("row_id") or "") for item in selected_issues]
    if len(row_ids) != len(set(row_ids)):
        blockers.append("duplicate_row_ids")
    if len(classified) != selected_issue_count:
        blockers.append("selected_issue_count_not_305")
    observed_cases = {
        str(item.get("case_id") or "") for item in selected_issues if item.get("case_id")
    }
    if bundle is not None and enforce_frozen_identities:
        expected_cases = selected_generation_case_ids(bundle)
        expected_issues = frozen_selected_issue_identities(bundle)
        expected_row_ids = tuple(item["row_id"] for item in expected_issues)
        if tuple(sorted(observed_cases)) != tuple(sorted(expected_cases)):
            blockers.append("frozen_case_identities_mismatch")
        if len(observed_cases) != selected_case_count:
            blockers.append("selected_cases_must_be_the_frozen_30")
        if set(row_ids) != set(expected_row_ids):
            blockers.append("frozen_issue_identities_mismatch")
        by_row = {str(item.get("row_id") or ""): item for item in selected_issues}
        for expected in expected_issues:
            observed = by_row.get(expected["row_id"])
            if observed is None:
                continue
            if str(observed.get("issue_id") or "") != expected["issue_id"]:
                blockers.append("frozen_issue_id_mismatch")
                break
            if (
                observed.get("topic_sha256")
                and str(observed["topic_sha256"]) != expected["topic_sha256"]
            ):
                blockers.append("frozen_topic_identity_mismatch")
                break
            if (
                observed.get("question_sha256")
                and str(observed["question_sha256"]) != expected["question_sha256"]
            ):
                blockers.append("frozen_question_sha_mismatch")
                break
            if (
                observed.get("record_sha256")
                and str(observed["record_sha256"]) != expected["record_sha256"]
            ):
                blockers.append("frozen_record_sha_mismatch")
                break
    elif enforce_frozen_identities:
        if len(observed_cases) == 1 and len(classified) == selected_issue_count:
            blockers.append("frozen_identities_cannot_attach_all_issues_to_one_case")
        if len(observed_cases) != selected_case_count:
            blockers.append("selected_cases_must_be_the_frozen_30")
    if unreviewed:
        blockers.append("unreviewed_or_hold_issues_present")
    if any(item["blocking_reason_codes"] for item in classified):
        blockers.append("disposition_verification_failed")
    complete = not blockers
    frozen_identity_sha = sealed_sha256({"row_ids": sorted(row_ids)})
    authorized_ids = (
        list(selected_generation_case_ids(bundle)) if bundle is not None else sorted(observed_cases)
    )
    payload = {
        "schema": OVERLAY_COMPLETE_V2_SCHEMA,
        "review_overlay_complete": complete,
        "selected_issue_count": len(classified),
        "selected_case_count": len(case_outcomes) or len(observed_cases) or selected_case_count,
        "selected_qualified_issue_count": qualified,
        "selected_limited_issue_count": limited,
        "selected_knowledge_gap_count": gaps,
        "selected_positive_span_issue_count": positive,
        "unreviewed_issue_count": unreviewed,
        "authorized_case_ids": authorized_ids,
        "frozen_issue_identity_sha256": frozen_identity_sha,
        "v1_requires_305_positive_spans": True,
        "v1_overlay_complete": positive == selected_issue_count
        and qualified == selected_issue_count,
        "blocking_reason_codes": blockers,
        "case_execution": case_outcomes,
        "writes_active": False,
        "writes_o04": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    if issue_manifest_sha256:
        payload["issue_manifest_sha256"] = issue_manifest_sha256
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "case_execution"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "case_execution"}
    )
    return payload


def selected_issues_from_reconstruction(
    reconstruction: Mapping[str, Any],
    selected_case_ids: Sequence[str],
) -> list[dict[str, Any]]:
    selected = set(selected_case_ids)
    issues: list[dict[str, Any]] = []
    for case in reconstruction.get("cases") or ():
        if case.get("case_id") not in selected:
            continue
        for issue in case.get("issues") or ():
            payload = dict(issue)
            payload.setdefault("case_id", case.get("case_id"))
            issues.append(payload)
    return issues
