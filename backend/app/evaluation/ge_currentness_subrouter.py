"""Subdivide CURRENTNESS_UNRESOLVED without treating it as a dead case."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .ge_locator_gold_overlay import iso_date_from_prompt

CURRENTNESS_SUBREASONS = (
    "CONSOLIDATED_TEXT_DATE_UNVERIFIED",
    "AMENDMENT_EFFECT_UNRESOLVED",
    "COMMENCEMENT_SCOPE_UNRESOLVED",
    "TRANSITIONAL_OR_SAVINGS_REVIEW",
    "HISTORIC_AS_OF_DATE_REVIEW",
    "TERRITORIAL_EXTENT_OR_APPLICATION_REVIEW",
    "REPEAL_OR_SUBSTITUTION_REVIEW",
    "SECONDARY_LEGISLATION_STATUS",
    "PROCEDURAL_RULE_VERSION",
    "CONTRACTUALLY_INCORPORATED_EDITION",
    "CASE_APPEAL_STATUS",
    "CASE_SUBSEQUENT_TREATMENT",
    "LEGISLATIVE_DISPLACEMENT_OF_CASE_RULE",
    "OFFICIAL_SOURCE_COVERAGE_INCOMPLETE",
    # Retained aliases so earlier receipts remain in the closed set.
    "TRANSITIONAL_PROVISION_REVIEW",
    "JURISDICTIONAL_EXTENT_CURRENTNESS",
    "AUTHORITY_STATUS_REVIEW",
)

CURRENTNESS_SUBREASON_ALIASES = {
    "TRANSITIONAL_PROVISION_REVIEW": "TRANSITIONAL_OR_SAVINGS_REVIEW",
    "JURISDICTIONAL_EXTENT_CURRENTNESS": "TERRITORIAL_EXTENT_OR_APPLICATION_REVIEW",
    "AUTHORITY_STATUS_REVIEW": "CASE_SUBSEQUENT_TREATMENT",
}

_JUDGMENT = re.compile(r"\s+v\s+|\[\d{4}]\s+(?:UKSC|UKHL|EWCA|EWHC|UKUT|UKFTT)", re.IGNORECASE)
_SECONDARY = re.compile(
    r"\b(?:regulations? \d{4}|SI \d{4}/\d+|S\.I\.|statutory instrument|commencement order)\b",
    re.IGNORECASE,
)
_PROCEDURAL = re.compile(
    r"\b(?:civil procedure rules|practice direction|\bCPR\b|family procedure rules)\b",
    re.IGNORECASE,
)
_CONTRACTUAL = re.compile(
    r"\b(?:contractually incorporated|ICC Mediation|LCIA |UCP \d+|INCOTERMS?|ISDA |FIDIC )\b",
    re.IGNORECASE,
)
_TRANSITIONAL = re.compile(r"\b(?:transitional|savings provisions?)\b", re.IGNORECASE)
_COMMENCEMENT = re.compile(
    r"\b(?:commencement|coming into force|comes? into force|not yet in force)\b",
    re.IGNORECASE,
)
_REPEAL = re.compile(r"\b(?:repeal(?:ed|s)?|substituted|renumber(?:ed|ing)?)\b", re.IGNORECASE)
_APPEAL = re.compile(r"\b(?:appeal|appealed|overturned|reversed on appeal)\b", re.IGNORECASE)
_PROSPECTIVE = re.compile(
    r"\b(?:prospective|not yet commenced|not yet in force|has not been brought into force)\b",
    re.IGNORECASE,
)


def _evidence(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = row.get("evidence") or []
    return [item for item in raw if isinstance(item, dict)]


def _titles_and_locators(evidence: Sequence[Mapping[str, Any]]) -> str:
    parts = []
    for item in evidence:
        parts.append(str(item.get("title") or ""))
        parts.append(str(item.get("locator") or ""))
        parts.append(str(item.get("quote") or "")[:400])
    return " ".join(parts)


def currentness_analysis_fields(
    row: Mapping[str, Any],
    *,
    evaluation_as_of_date: str = "2026-08-28",
) -> dict[str, Any]:
    evidence = _evidence(row)
    historical = ""
    factual = row.get("factual_result")
    if isinstance(factual, Mapping):
        diagnostic = factual.get("diagnostic_checks")
        if isinstance(diagnostic, Mapping):
            hist = diagnostic.get("historical_date_applicability")
            if isinstance(hist, Mapping):
                historical = str(hist.get("outcome") or "")
    prompt = str(row.get("question") or row.get("prompt") or "")
    required = iso_date_from_prompt(prompt) or evaluation_as_of_date
    retrieved_dates = sorted(
        {
            str(item.get("currentness_reviewed_as_of_date") or "")
            for item in evidence
            if item.get("currentness_reviewed_as_of_date")
        }
    )
    effects = [
        item.get("unapplied_effect_count")
        for item in evidence
        if item.get("unapplied_effect_count") not in {None}
    ]
    extents = sorted({str(item.get("provision_extent_status") or "unknown") for item in evidence})
    pit = sorted({str(item.get("point_in_time_as_at") or "") for item in evidence if item.get("point_in_time_as_at")})
    reason = ""
    if isinstance(factual, Mapping):
        reasons = factual.get("reasons")
        if isinstance(reasons, Mapping):
            reason = str(reasons.get("requested_date_and_currentness") or "")
    return {
        "required_as_of_date": required,
        "retrieved_text_date": retrieved_dates[0] if retrieved_dates else "",
        "retrieved_text_dates": retrieved_dates,
        "latest_checked_amendment": (
            f"unapplied_effect_count={max(int(item) for item in effects)}"
            if effects
            else "unapplied_effect_count_not_recorded"
        ),
        "commencement_position": (
            "historical_point_in_time_required"
            if historical == "FAIL" or pit
            else "not_separately_recorded"
        ),
        "territorial_extent": ",".join(extents) if extents else "unknown",
        "point_in_time_as_at": pit,
        "historical_date_outcome": historical or "NOT_APPLICABLE",
        "unresolved_legal_question": reason
        or "Selected provisions lack owner-signed currentness/extent eligibility through the evaluation as-of date.",
        "candidate_reviewer_decision": "HOLD",
        "evaluation_as_of_date": evaluation_as_of_date,
    }


def classify_currentness_subreason(row: Mapping[str, Any]) -> dict[str, Any]:
    evidence = _evidence(row)
    analysis = currentness_analysis_fields(row)
    blob = _titles_and_locators(evidence)
    prompt = str(row.get("question") or row.get("prompt") or "")
    combined = f"{blob} {prompt}"
    additional: list[str] = []
    titles = [str(item.get("title") or "") for item in evidence]
    has_judgment = any(_JUDGMENT.search(title) for title in titles)
    has_legislation = any(
        re.search(r"\b(?:Act|Regulations|Order|Rules)\b", title) for title in titles
    )
    coverage_incomplete = not evidence or any(
        not item.get("currentness_reviewed_as_of_date") and item.get("currentness_verified") is not True
        for item in evidence
    )

    if analysis["historical_date_outcome"] == "FAIL" or analysis["point_in_time_as_at"]:
        primary = "HISTORIC_AS_OF_DATE_REVIEW"
    elif any(_CONTRACTUAL.search(title) for title in titles):
        primary = "CONTRACTUALLY_INCORPORATED_EDITION"
    elif any(_PROCEDURAL.search(title) for title in titles):
        primary = "PROCEDURAL_RULE_VERSION"
    elif has_judgment and _APPEAL.search(combined):
        primary = "CASE_APPEAL_STATUS"
    elif has_judgment and has_legislation:
        primary = "LEGISLATIVE_DISPLACEMENT_OF_CASE_RULE"
    elif has_judgment:
        primary = "CASE_SUBSEQUENT_TREATMENT"
    elif any(_SECONDARY.search(title) for title in titles):
        primary = "SECONDARY_LEGISLATION_STATUS"
    elif _TRANSITIONAL.search(combined):
        primary = "TRANSITIONAL_OR_SAVINGS_REVIEW"
    elif _COMMENCEMENT.search(combined) or _PROSPECTIVE.search(combined):
        primary = "COMMENCEMENT_SCOPE_UNRESOLVED"
    elif _REPEAL.search(combined):
        primary = "REPEAL_OR_SUBSTITUTION_REVIEW"
    elif any(
        isinstance(item.get("unapplied_effect_count"), int) and item.get("unapplied_effect_count") not in {0}
        for item in evidence
    ):
        primary = "AMENDMENT_EFFECT_UNRESOLVED"
    elif coverage_incomplete:
        primary = "OFFICIAL_SOURCE_COVERAGE_INCOMPLETE"
    elif any(item.get("currentness_verified") is not True for item in evidence) or not evidence:
        primary = "CONSOLIDATED_TEXT_DATE_UNVERIFIED"
    elif any(str(item.get("provision_extent_status") or "") != "verified" for item in evidence):
        primary = "TERRITORIAL_EXTENT_OR_APPLICATION_REVIEW"
    else:
        primary = "CONSOLIDATED_TEXT_DATE_UNVERIFIED"

    def _add(name: str) -> None:
        if name != primary and name not in additional:
            additional.append(name)

    if any(str(item.get("provision_extent_status") or "") != "verified" for item in evidence):
        _add("TERRITORIAL_EXTENT_OR_APPLICATION_REVIEW")
    if any(
        isinstance(item.get("unapplied_effect_count"), int) and item.get("unapplied_effect_count") not in {0}
        for item in evidence
    ):
        _add("AMENDMENT_EFFECT_UNRESOLVED")
    if any(
        item.get("currentness_verified") is not True
        or item.get("full_current_law_verification_eligible") is not True
        for item in evidence
    ):
        _add("CONSOLIDATED_TEXT_DATE_UNVERIFIED")
    if coverage_incomplete:
        _add("OFFICIAL_SOURCE_COVERAGE_INCOMPLETE")
    if any(_PROCEDURAL.search(title) for title in titles):
        _add("PROCEDURAL_RULE_VERSION")
        _add("SECONDARY_LEGISLATION_STATUS")
    if has_judgment:
        _add("CASE_SUBSEQUENT_TREATMENT")
    if _PROSPECTIVE.search(combined):
        _add("COMMENCEMENT_SCOPE_UNRESOLVED")
    if _TRANSITIONAL.search(combined):
        _add("TRANSITIONAL_OR_SAVINGS_REVIEW")
    return {
        "currentness_subreason": primary,
        "currentness_subreasons_additional": additional,
        "currentness_analysis": analysis,
    }
