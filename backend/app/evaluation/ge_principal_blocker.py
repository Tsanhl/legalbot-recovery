"""Principal blockers for GE holds. Only MISSING_AUTHORITY triggers source intake."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .ge_hold_reason_router import route_hold

PRINCIPAL_BLOCKERS = (
    "MISSING_AUTHORITY",
    "WRONG_ISSUE_ROUTE",
    "INCOMPLETE_PASSAGE",
    "CURRENTNESS_OR_EXTENT_UNRESOLVED",
    "HISTORICAL_DATE_UNRESOLVED",
    "MISSING_OUTCOME_CHANGING_FACT",
    "COUNTERAUTHORITY_UNRESOLVED",
    "ANSWER_NOT_USER_FACING",
    "EVALUATOR_SYSTEM_ERROR",
)

INTAKE_TRIGGER = "MISSING_AUTHORITY"


def _diagnostic(row: Mapping[str, Any], name: str) -> str:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return ""
    raw = factual.get("diagnostic_checks")
    if not isinstance(raw, Mapping):
        return ""
    item = raw.get(name)
    if isinstance(item, Mapping):
        return str(item.get("outcome") or "")
    return ""


def _check(row: Mapping[str, Any], name: str) -> str:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return ""
    checks = factual.get("checks")
    if isinstance(checks, Mapping):
        return str(checks.get(name) or "")
    return ""


def claim_assurance_state(row: Mapping[str, Any]) -> str:
    evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
    if not evidence:
        return "NOT_REVIEWABLE"
    claim = _check(row, "claim_evidence_support")
    completeness = _diagnostic(row, "passage_completeness")
    relevance = _diagnostic(row, "issue_relevance")
    if claim == "PASS" and completeness == "PASS" and relevance == "PASS":
        return "SUPPORTED"
    if completeness == "PASS" and relevance == "FAIL":
        return "UNSUPPORTED"
    if completeness == "FAIL" and relevance == "PASS":
        return "PARTIALLY_SUPPORTED"
    return "UNSUPPORTED"


def classify_principal_blocker(row: Mapping[str, Any]) -> str:
    factual = row.get("factual_result")
    outcome = ""
    if isinstance(factual, Mapping):
        outcome = str(factual.get("outcome") or "")
    if outcome == "SYSTEM_ERROR":
        return "EVALUATOR_SYSTEM_ERROR"
    if outcome == "FACTUAL_PASS":
        return "NONE"
    rendered = _diagnostic(row, "actual_rendered_answer_quality")
    if rendered == "FAIL":
        return "ANSWER_NOT_USER_FACING"
    if _diagnostic(row, "passage_completeness") == "FAIL":
        return "INCOMPLETE_PASSAGE"
    if _diagnostic(row, "historical_date_applicability") == "FAIL":
        return "HISTORICAL_DATE_UNRESOLVED"
    routed = route_hold(row)
    code = str(routed.get("hold_reason_code") or "")
    if code in {"RETRIEVAL_NO_EVIDENCE", "OFFICIAL_SOURCE_UNAVAILABLE_FAIL_CLOSED"}:
        return "MISSING_AUTHORITY"
    if code == "REJECTED_AUTHORITY_NOT_REQUIRED":
        return "WRONG_ISSUE_ROUTE"
    if code in {"CLAIM_NOT_SUPPORTED", "ANSWER_OVERCLAIMS_EVIDENCE"}:
        if _diagnostic(row, "issue_relevance") == "FAIL":
            return "WRONG_ISSUE_ROUTE"
        return "WRONG_ISSUE_ROUTE"
    if code == "FACT_DEPENDENT_OUTCOME":
        return "MISSING_OUTCOME_CHANGING_FACT"
    if code in {"CURRENTNESS_UNRESOLVED", "LOCATOR_EXTENT_MISMATCH"}:
        return "CURRENTNESS_OR_EXTENT_UNRESOLVED"
    if _check(row, "contradiction_and_counterauthority") == "FAIL":
        return "COUNTERAUTHORITY_UNRESOLVED"
    if code == "JURISDICTION_SCOPE_REVIEW":
        return "CURRENTNESS_OR_EXTENT_UNRESOLVED"
    return "CURRENTNESS_OR_EXTENT_UNRESOLVED"


def intake_authorized(principal_blocker: str) -> bool:
    return principal_blocker == INTAKE_TRIGGER
