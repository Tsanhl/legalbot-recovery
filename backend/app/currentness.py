"""Fail-closed present-law qualification for historical case authorities."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from .types import CasePropositionReview

HISTORICAL_CASE_CURRENTNESS_POLICY = "historical-case-treatment-hold-v1"
LATER_TREATMENT_CHECKED = "later_treatment_checked"
LEGISLATION_SOURCE_TYPES = frozenset({"legislation", "statutory_instrument"})


def normalise_currentness_status(value: object) -> str:
    return str(value or "unknown").strip().casefold().replace("-", "_")


def is_case_source(citation_data: Mapping[str, Any]) -> bool:
    return str(citation_data.get("source_type") or "").strip().casefold() == "case"


def is_legislation_source(citation_data: Mapping[str, Any]) -> bool:
    """Treat Acts and statutory instruments as the same currentness family."""

    return (
        str(citation_data.get("source_type") or "").strip().casefold() in LEGISLATION_SOURCE_TYPES
    )


def apply_historical_case_treatment_hold(
    metadata: Mapping[str, Any],
    *,
    policy_version: str = HISTORICAL_CASE_CURRENTNESS_POLICY,
) -> dict[str, Any]:
    """Return metadata that verifies identity but not present-law treatment.

    A historic judgment's official bytes prove its identity and decision-date
    text.  They do not prove that each proposition remains good law.  The hold
    remains until a separately reviewed, issue-specific treatment record sets
    both ``currentness_status=later_treatment_checked`` and
    ``subsequent_treatment_verified=true``.
    """

    output = dict(metadata)
    output.update(
        {
            "currentness_verified": False,
            "currentness_verification_scope": "historical_decision_identity_only",
            "subsequent_treatment_check_required": True,
            "subsequent_treatment_verified": False,
            "present_law_retrieval_eligible": False,
            "present_law_hold_reason": (
                "Issue-specific subsequent treatment has not been reviewed; the "
                "historic judgment may not establish a present-law material proposition"
            ),
            "currentness_policy_version": policy_version,
        }
    )
    return output


def case_present_law_currentness_qualifies(
    *,
    citation_data: Mapping[str, Any],
    currentness_status: object,
    source_metadata: Mapping[str, Any],
    identity_verified: bool = False,
    source_version_id: str | None = None,
    chunk_id: str | None = None,
    legal_locator: str | None = None,
    exact_span_sha256: str | None = None,
    proposition_hash: str | None = None,
    legal_role: str | None = None,
    as_of_date: date | None = None,
    reviews: Sequence[CasePropositionReview] = (),
) -> bool:
    """Qualify only an exact, sealed span/proposition later-treatment review.

    ``source_metadata`` is shared by every paragraph in a judgment.  It cannot
    prove the later treatment of a particular proposition, so source-level
    booleans and ``later_treatment_checked`` labels remain insufficient.  A
    valid review must match every immutable span/proposition coordinate and the
    requested answer date.  Missing or mismatched coordinates fail closed.
    """

    if not is_case_source(citation_data):
        return True
    del currentness_status, source_metadata
    if not (
        identity_verified
        and source_version_id
        and chunk_id
        and legal_locator
        and exact_span_sha256
        and proposition_hash
        and legal_role
        and as_of_date
    ):
        return False
    normal_locator = " ".join(legal_locator.split())
    return any(
        review.qualifies_for_present_law
        and review.source_version_id == source_version_id
        and review.chunk_id == chunk_id
        and review.legal_locator == normal_locator
        and review.exact_span_sha256 == exact_span_sha256
        and review.proposition_hash == proposition_hash
        and review.legal_role == legal_role
        and review.later_treatment_reviewed_as_of_date == as_of_date
        for review in reviews
    )
