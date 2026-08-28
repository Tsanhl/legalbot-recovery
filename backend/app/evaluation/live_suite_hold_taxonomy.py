"""Derive Live60 HOLD taxonomy from artifacts. Counts are never constants."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_overlay_complete import VERIFIED_DISPOSITIONS, classify_issue_disposition

HOLD_TAXONOMY_SCHEMA = "legalbot.live60-hold-taxonomy.v2"
HoldCategory = Literal[
    "VERIFIED_QUALIFIED",
    "VERIFIED_LIMITED",
    "VERIFIED_KNOWLEDGE_GAP",
    "SEMANTIC_HOLD",
    "SEMANTIC_CONTRADICTION_HOLD",
    "SOURCE_ADMITTED_SEMANTIC_PENDING",
    "SOURCE_EFFECTS_HOLD",
    "SOURCE_ADMISSION_REJECTED",
    "OFFICIAL_SOURCE_VERSION_APPROVAL_PENDING",
    "OFFICIAL_MATERIALISATION_PENDING",
    "CURRENTNESS_PENDING",
    "CONTRARY_REVIEW_PENDING",
    "SOURCE_IDENTITY_OR_HASH_FAILURE",
    "OWNER_HELD_SOURCE_VERSION",
    "OWNER_ADJUDICATION_REQUIRED",
    "OTHER_HOLD",
]
HOLD_CATEGORIES: tuple[HoldCategory, ...] = (
    "SEMANTIC_HOLD",
    "SEMANTIC_CONTRADICTION_HOLD",
    "SOURCE_ADMITTED_SEMANTIC_PENDING",
    "SOURCE_EFFECTS_HOLD",
    "SOURCE_ADMISSION_REJECTED",
    "OFFICIAL_SOURCE_VERSION_APPROVAL_PENDING",
    "OFFICIAL_MATERIALISATION_PENDING",
    "CURRENTNESS_PENDING",
    "CONTRARY_REVIEW_PENDING",
    "SOURCE_IDENTITY_OR_HASH_FAILURE",
    "OWNER_HELD_SOURCE_VERSION",
    "OWNER_ADJUDICATION_REQUIRED",
    "OTHER_HOLD",
)
GAP_REASON_CATEGORIES: dict[str, HoldCategory] = {
    "source_admitted_semantic_pending": "SOURCE_ADMITTED_SEMANTIC_PENDING",
    "source_admitted_exact_span_or_semantic_pending": "SOURCE_ADMITTED_SEMANTIC_PENDING",
    "source_admission_operator_hold": "SOURCE_EFFECTS_HOLD",
    "source_effects_hold": "SOURCE_EFFECTS_HOLD",
    "unapplied_effects_unresolved": "SOURCE_EFFECTS_HOLD",
    "source_admission_rejected": "SOURCE_ADMISSION_REJECTED",
    "contradiction_unbound_contrary_authority": "SEMANTIC_CONTRADICTION_HOLD",
    "contradiction_unresolved_no_safe_current_proposition": "SEMANTIC_CONTRADICTION_HOLD",
    "official_bytes_no_approved_catalogue_source_version": (
        "OFFICIAL_SOURCE_VERSION_APPROVAL_PENDING"
    ),
}


def _row_id(issue: Mapping[str, Any]) -> str:
    return str(issue.get("row_id") or "")


def _semantic_result_value(record: Mapping[str, Any] | None) -> str | None:
    if not isinstance(record, Mapping):
        return None
    nested = record.get("semantic_result")
    if isinstance(nested, Mapping) and nested.get("result"):
        return str(nested.get("result"))
    if record.get("result"):
        return str(record.get("result"))
    return None


def _semantic_contradiction(record: Mapping[str, Any] | None) -> bool:
    if not isinstance(record, Mapping):
        return False
    nested = record.get("semantic_result")
    nested_map = nested if isinstance(nested, Mapping) else {}
    if int(nested_map.get("contradiction_count") or 0) > 0:
        return True
    return str(nested_map.get("result") or record.get("result") or "") == "CONTRADICTION"


def operator_confirmation_waiting(*, digest_bound_decision_outstanding: bool) -> bool:
    """True only when a current digest-bound operator token is actually waiting."""

    return bool(digest_bound_decision_outstanding)


def classify_selected_issue(
    issue: Mapping[str, Any],
    *,
    semantic_checkpoint: Mapping[str, Any] | None = None,
    official_candidate_row_ids: set[str] | None = None,
    pending_approval_row_ids: set[str] | None = None,
    currentness_pending_row_ids: set[str] | None = None,
    contrary_pending_row_ids: set[str] | None = None,
    identity_failure_row_ids: set[str] | None = None,
    owner_adjudication_row_ids: set[str] | None = None,
    owner_held_source_version_row_ids: set[str] | None = None,
    source_effects_hold_row_ids: set[str] | None = None,
    source_admission_rejected_row_ids: set[str] | None = None,
    source_admitted_semantic_pending_row_ids: set[str] | None = None,
) -> HoldCategory | Literal["VERIFIED_QUALIFIED", "VERIFIED_LIMITED", "VERIFIED_KNOWLEDGE_GAP"]:
    classified = classify_issue_disposition(issue)
    disposition = str(classified["disposition"])
    row_id = _row_id(issue)
    if classified["verification_status"] == "VERIFIED" and disposition in VERIFIED_DISPOSITIONS:
        if disposition == "qualified":
            return "VERIFIED_QUALIFIED"
        if disposition == "limited":
            return "VERIFIED_LIMITED"
        return "VERIFIED_KNOWLEDGE_GAP"
    if row_id and owner_adjudication_row_ids and row_id in owner_adjudication_row_ids:
        return "OWNER_ADJUDICATION_REQUIRED"
    gap_reason = str(issue.get("gap_reason") or issue.get("limitation_reason") or "")
    if gap_reason in GAP_REASON_CATEGORIES:
        return GAP_REASON_CATEGORIES[gap_reason]
    effects_ids = set(source_effects_hold_row_ids or ()) | set(
        owner_held_source_version_row_ids or ()
    )
    if (
        row_id
        and source_admitted_semantic_pending_row_ids
        and row_id in (source_admitted_semantic_pending_row_ids)
    ):
        return "SOURCE_ADMITTED_SEMANTIC_PENDING"
    if (
        row_id
        and source_admission_rejected_row_ids
        and row_id in (source_admission_rejected_row_ids)
    ):
        return "SOURCE_ADMISSION_REJECTED"
    if row_id and effects_ids and row_id in effects_ids:
        return "SOURCE_EFFECTS_HOLD"
    if _semantic_contradiction(semantic_checkpoint):
        return "SEMANTIC_CONTRADICTION_HOLD"
    semantic_value = _semantic_result_value(semantic_checkpoint)
    if semantic_value in {"unsupported", "knowledge_gap", "HOLD", "limited"}:
        return "SEMANTIC_HOLD"
    if row_id and identity_failure_row_ids and row_id in identity_failure_row_ids:
        return "SOURCE_IDENTITY_OR_HASH_FAILURE"
    if row_id and currentness_pending_row_ids and row_id in currentness_pending_row_ids:
        return "CURRENTNESS_PENDING"
    if row_id and contrary_pending_row_ids and row_id in contrary_pending_row_ids:
        return "CONTRARY_REVIEW_PENDING"
    if row_id and pending_approval_row_ids and row_id in pending_approval_row_ids:
        return "OFFICIAL_SOURCE_VERSION_APPROVAL_PENDING"
    if row_id and official_candidate_row_ids and row_id in official_candidate_row_ids:
        return "OFFICIAL_MATERIALISATION_PENDING"
    return "OTHER_HOLD"


def classify_hold_queue(
    issues: Sequence[Mapping[str, Any]],
    *,
    semantic_checkpoints: Mapping[str, Mapping[str, Any]] | None = None,
    official_candidate_row_ids: set[str] | None = None,
    pending_approval_row_ids: set[str] | None = None,
    currentness_pending_row_ids: set[str] | None = None,
    contrary_pending_row_ids: set[str] | None = None,
    identity_failure_row_ids: set[str] | None = None,
    owner_adjudication_row_ids: set[str] | None = None,
    owner_held_source_version_row_ids: set[str] | None = None,
    source_effects_hold_row_ids: set[str] | None = None,
    source_admission_rejected_row_ids: set[str] | None = None,
    source_admitted_semantic_pending_row_ids: set[str] | None = None,
    digest_bound_operator_decision_outstanding: bool = False,
) -> dict[str, Any]:
    checkpoints = semantic_checkpoints or {}
    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for issue in issues:
        category = classify_selected_issue(
            issue,
            semantic_checkpoint=checkpoints.get(_row_id(issue)),
            official_candidate_row_ids=official_candidate_row_ids,
            pending_approval_row_ids=pending_approval_row_ids,
            currentness_pending_row_ids=currentness_pending_row_ids,
            contrary_pending_row_ids=contrary_pending_row_ids,
            identity_failure_row_ids=identity_failure_row_ids,
            owner_adjudication_row_ids=owner_adjudication_row_ids,
            owner_held_source_version_row_ids=owner_held_source_version_row_ids,
            source_effects_hold_row_ids=source_effects_hold_row_ids,
            source_admission_rejected_row_ids=source_admission_rejected_row_ids,
            source_admitted_semantic_pending_row_ids=source_admitted_semantic_pending_row_ids,
        )
        counts[category] += 1
        rows.append({"row_id": _row_id(issue), "category": category})
    hold_total = sum(int(counts[key]) for key in HOLD_CATEGORIES)
    contradiction = int(counts.get("SEMANTIC_CONTRADICTION_HOLD") or 0)
    semantic_generic = int(counts.get("SEMANTIC_HOLD") or 0)
    payload = {
        "schema": HOLD_TAXONOMY_SCHEMA,
        "selected_total": len(issues),
        "verified_qualified": int(counts.get("VERIFIED_QUALIFIED") or 0),
        "verified_limited": int(counts.get("VERIFIED_LIMITED") or 0),
        "verified_knowledge_gap": int(counts.get("VERIFIED_KNOWLEDGE_GAP") or 0),
        "semantic_hold": semantic_generic + contradiction,
        "semantic_contradiction_hold": contradiction,
        "source_admitted_semantic_pending": int(
            counts.get("SOURCE_ADMITTED_SEMANTIC_PENDING") or 0
        ),
        "source_effects_hold": int(counts.get("SOURCE_EFFECTS_HOLD") or 0),
        "source_admission_rejected": int(counts.get("SOURCE_ADMISSION_REJECTED") or 0),
        "official_source_version_approval_pending": int(
            counts.get("OFFICIAL_SOURCE_VERSION_APPROVAL_PENDING") or 0
        ),
        "official_materialisation_pending": int(
            counts.get("OFFICIAL_MATERIALISATION_PENDING") or 0
        ),
        "currentness_pending": int(counts.get("CURRENTNESS_PENDING") or 0),
        "contrary_review_pending": int(counts.get("CONTRARY_REVIEW_PENDING") or 0),
        "source_identity_or_hash_failure": int(counts.get("SOURCE_IDENTITY_OR_HASH_FAILURE") or 0),
        "owner_adjudication_required": int(counts.get("OWNER_ADJUDICATION_REQUIRED") or 0),
        "owner_held_source_version": int(counts.get("OWNER_HELD_SOURCE_VERSION") or 0),
        "other_hold": int(counts.get("OTHER_HOLD") or 0),
        "total_hold": hold_total,
        "v2_verified_selected": (
            int(counts.get("VERIFIED_QUALIFIED") or 0)
            + int(counts.get("VERIFIED_LIMITED") or 0)
            + int(counts.get("VERIFIED_KNOWLEDGE_GAP") or 0)
        ),
        "owner_confirmation_required": operator_confirmation_waiting(
            digest_bound_decision_outstanding=digest_bound_operator_decision_outstanding
        ),
        "hard_coded_hold_count": False,
        "row_categories": rows,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(
        {key: value for key, value in payload.items() if key != "row_categories"}
    )
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "row_categories"}
    )
    return payload


def issue_state_review_complete(*, hold_count: int, unreviewed_count: int) -> bool:
    return hold_count == 0 and unreviewed_count == 0
