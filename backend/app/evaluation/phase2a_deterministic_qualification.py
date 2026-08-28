"""Deterministic, non-authorizing all-585 Phase-2A qualification evidence."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from typing import Any

from .live_suite import LiveEvaluationBundle

SCHEMA = "legalbot.v111.phase2a.deterministic-all585-qualification.v1"
ROW_SCHEMA = "legalbot.v111.phase2a.deterministic-qualification-row.v1"

TECHNICALLY_READY = "TECHNICALLY_EVIDENCE_READY_FOR_OWNER_ADOPTION"
TECHNICALLY_READY_WITH_NOTE = "TECHNICALLY_READY_WITH_NONMATERIAL_NOTE"
BLOCKED_MATERIAL_GAP = "BLOCKED_MATERIAL_GAP"
OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"
ALLOWED_STATUSES = frozenset(
    {
        TECHNICALLY_READY,
        TECHNICALLY_READY_WITH_NOTE,
        BLOCKED_MATERIAL_GAP,
        OWNER_DECISION_REQUIRED,
    }
)

EXPECTED_RECORDED_PRE_R94 = 137
EXPECTED_R94 = 84
EXPECTED_REMAINING = 364
EXPECTED_PRESERVED_READY = 3
EXPECTED_NO_EXACT_SPAN = 98


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sealed(value: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    payload = dict(value)
    payload[field] = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return payload


def _registry_rows(bundle: LiveEvaluationBundle) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    ordinal = 0
    for case in bundle.registry.cases:
        for issue_number, label in enumerate(case.must_cover_issues, start=1):
            ordinal += 1
            rows.append(
                {
                    "ordinal": ordinal,
                    "row_id": f"{case.case_id}:issue-{issue_number:02d}",
                    "case_id": case.case_id,
                    "issue_id": f"issue-{issue_number:02d}",
                    "issue_label": label,
                    "legal_domain": case.subject,
                }
            )
    if len(rows) != 585 or len({row["row_id"] for row in rows}) != 585:
        raise ValueError("canonical qualification registry is not exactly 60/585")
    return rows


def _row_map(value: Mapping[str, Any], key: str) -> dict[str, Mapping[str, Any]]:
    rows = value.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"qualification input lacks list: {key}")
    output: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError(f"qualification input contains an invalid row: {key}")
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in output:
            raise ValueError(f"qualification input row identity is missing or duplicated: {key}")
        output[row_id] = row
    return output


def _source_hold_summary(source_manifest: Mapping[str, Any]) -> dict[str, Any]:
    sources = source_manifest.get("sources")
    if (
        source_manifest.get("source_count") != 251
        or source_manifest.get("chunk_count") != 222_200
        or source_manifest.get("answer_release_eligible") is not False
        or source_manifest.get("successor_must_remain_non_active") is not True
        or not isinstance(sources, list)
        or len(sources) != 251
    ):
        raise ValueError("all-585 qualification is not bound to the exact held successor scope")
    unverified_currentness = sum(
        not isinstance(source, Mapping) or source.get("currentness_verified") is not True
        for source in sources
    )
    later_treatment_required = sum(
        isinstance(source, Mapping) and source.get("subsequent_treatment_check_required") is True
        for source in sources
    )
    later_treatment_verified = sum(
        isinstance(source, Mapping) and source.get("subsequent_treatment_verified") is True
        for source in sources
    )
    return {
        "source_count": 251,
        "chunk_count": 222_200,
        "currentness_verified_source_count": 251 - unverified_currentness,
        "currentness_unverified_source_count": unverified_currentness,
        "later_treatment_required_source_count": later_treatment_required,
        "later_treatment_verified_source_count": later_treatment_verified,
        "holds_preserved": True,
        "answer_release_eligible": False,
        "successor_must_remain_non_active": True,
    }


def build_deterministic_all585_qualification(
    *,
    bundle: LiveEvaluationBundle,
    consolidated_matrix: Mapping[str, Any],
    r94_owner_batch: Mapping[str, Any],
    r113_remaining_gaps: Mapping[str, Any],
    deterministic_crosswalk: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    candidate_identity: Mapping[str, Any],
    held_retrieval_reattestation: Mapping[str, Any],
    evidence_file_sha256s: Mapping[str, str],
) -> dict[str, Any]:
    """Build a complete truthful matrix without making a substantive legal decision."""

    registry = _registry_rows(bundle)
    registry_ids = {row["row_id"] for row in registry}
    base = _row_map(consolidated_matrix, "rows")
    r94 = _row_map(r94_owner_batch, "candidate_exact_binding_decisions")
    remaining = _row_map(r113_remaining_gaps, "records")
    crosswalk = _row_map(deterministic_crosswalk, "rows")
    recorded = {
        row_id: row
        for row_id, row in base.items()
        if isinstance(row.get("owner_decision"), Mapping)
        and row["owner_decision"].get("status") == "RECORDED_OWNER_PHASE2A_DECISION"
    }
    if (
        set(base) != registry_ids
        or len(recorded) != EXPECTED_RECORDED_PRE_R94
        or len(r94) != EXPECTED_R94
        or len(remaining) != EXPECTED_REMAINING
        or set(remaining) != set(crosswalk)
        or set(recorded).intersection(r94)
        or set(recorded).intersection(remaining)
        or set(r94).intersection(remaining)
        or set(recorded).union(r94, remaining) != registry_ids
    ):
        raise ValueError("all-585 predecessor/approval/gap partition changed")

    preserved_ready = {
        row_id
        for row_id, row in crosswalk.items()
        if row.get("status") == "OWNER_APPROVED_EXACT_BINDINGS_READY_FOR_FINAL_QUALIFICATION"
        and row.get("owner_decision_required") is False
        and row.get("selected_exact_span_id")
    }
    no_exact_span = {
        row_id
        for row_id, row in crosswalk.items()
        if row.get("status") == "NO_DETERMINISTIC_EXACT_SPAN_MATCH_OWNER_RESEARCH_REQUIRED"
    }
    if (
        len(preserved_ready) != EXPECTED_PRESERVED_READY
        or len(no_exact_span) != EXPECTED_NO_EXACT_SPAN
    ):
        raise ValueError("all-585 deterministic exact-span outcome counts changed")

    retrieval_metrics = held_retrieval_reattestation.get("metrics")
    if (
        held_retrieval_reattestation.get("retrieval_quality_passed") is not True
        or held_retrieval_reattestation.get("promotion_eligible") is not False
        or held_retrieval_reattestation.get("answer_release_eligible") is not False
        or held_retrieval_reattestation.get("candidate_status_written") is not False
        or held_retrieval_reattestation.get("active_pointer_written") is not False
        or not isinstance(retrieval_metrics, Mapping)
        or retrieval_metrics.get("query_count") != 24
        or retrieval_metrics.get("binding_count") != 24
    ):
        raise ValueError("all-585 qualification lacks the exact held retrieval proof")
    if (
        candidate_identity.get("status") != "built_unscored"
        or candidate_identity.get("stage") != "built_unscored"
        or candidate_identity.get("document_count") != 251
        or candidate_identity.get("chunk_count") != 222_200
        or candidate_identity.get("vector_count") != 222_200
    ):
        raise ValueError("all-585 qualification candidate identity is not the held successor")

    qualification_rows: list[dict[str, Any]] = []
    for registry_row in registry:
        row_id = str(registry_row["row_id"])
        if row_id in recorded:
            source = recorded[row_id]
            decision = source["owner_decision"]
            status = TECHNICALLY_READY
            basis = {
                "basis_class": "RECORDED_PRE_R94_OWNER_DECISION",
                "owner_outcome": decision.get("owner_outcome"),
                "source_record_content_sha256": source.get("record_content_sha256"),
            }
        elif row_id in r94:
            source = r94[row_id]
            status = TECHNICALLY_READY
            basis = {
                "basis_class": "DIGEST_BOUND_R94_OWNER_APPROVAL",
                "recommended_owner_outcome": source.get("recommended_owner_outcome"),
                "decision_content_sha256": source.get("decision_content_sha256"),
                "exact_span_binding_content_sha256": source.get(
                    "exact_span_binding_content_sha256"
                ),
            }
        else:
            source = crosswalk[row_id]
            if row_id in preserved_ready:
                status = TECHNICALLY_READY
                basis_class = "PRESERVED_OWNER_APPROVED_EXACT_BINDING"
            elif row_id in no_exact_span:
                status = BLOCKED_MATERIAL_GAP
                basis_class = "NO_DETERMINISTIC_EXACT_SPAN_MATCH"
            else:
                status = OWNER_DECISION_REQUIRED
                basis_class = "DETERMINISTIC_OPTIONS_REQUIRE_OWNER_SUBSTANTIVE_SELECTION"
            basis = {
                "basis_class": basis_class,
                "deterministic_packet_status": source.get("status"),
                "source_record_content_sha256": source.get("record_content_sha256"),
                "selected_exact_span_id": source.get("selected_exact_span_id"),
                "candidate_evidence_packet_count": source.get("candidate_count"),
            }
        row_payload = {
            "schema": ROW_SCHEMA,
            **registry_row,
            "qualification_status": status,
            "basis": basis,
            "candidate_build_id": candidate_identity.get("build_id"),
            "candidate_status": "built_unscored",
            "retrieval_reattestation_passed": True,
            "owner_adopted_qualified": False,
            "answer_release_eligible": False,
            "phase2b_authorized": False,
        }
        qualification_rows.append(_sealed(row_payload, field="record_content_sha256"))

    counts = Counter(row["qualification_status"] for row in qualification_rows)
    if set(counts) - ALLOWED_STATUSES or counts != {
        TECHNICALLY_READY: 224,
        BLOCKED_MATERIAL_GAP: 98,
        OWNER_DECISION_REQUIRED: 263,
    }:
        raise ValueError("all-585 deterministic qualification result counts changed")

    case_rows: list[dict[str, Any]] = []
    by_case: dict[str, list[dict[str, Any]]] = {}
    for row in qualification_rows:
        by_case.setdefault(str(row["case_id"]), []).append(row)
    for case in bundle.registry.cases:
        rows = by_case.get(case.case_id, [])
        case_counts = Counter(row["qualification_status"] for row in rows)
        case_rows.append(
            {
                "case_id": case.case_id,
                "issue_count": len(rows),
                "status_counts": dict(sorted(case_counts.items())),
                "all_issues_technically_ready": bool(rows)
                and all(row["qualification_status"] == TECHNICALLY_READY for row in rows),
            }
        )
    if len(case_rows) != 60 or sum(row["issue_count"] for row in case_rows) != 585:
        raise ValueError("all-585 case aggregation changed")

    source_holds = _source_hold_summary(source_manifest)
    material_blockers = [
        {
            "code": "UNRESOLVED_EXACT_SPAN_MATERIAL_GAPS",
            "affected_issue_count": counts[BLOCKED_MATERIAL_GAP],
        },
        {
            "code": "OWNER_SUBSTANTIVE_DECISIONS_REQUIRED",
            "affected_issue_count": counts[OWNER_DECISION_REQUIRED],
        },
        {
            "code": "SUCCESSOR_SOURCE_CURRENTNESS_HOLDS_RETAINED",
            "affected_source_count": source_holds["currentness_unverified_source_count"],
        },
        {
            "code": "SUCCESSOR_LATER_TREATMENT_HOLDS_RETAINED",
            "affected_source_count": source_holds["later_treatment_required_source_count"],
        },
        {
            "code": "SUCCESSOR_INTENTIONALLY_NON_ACTIVE_AND_ANSWER_INELIGIBLE",
            "affected_candidate_count": 1,
        },
    ]
    payload = {
        "schema": SCHEMA,
        "route": "OWNER_ADOPTED_INTERNAL_DETERMINISTIC_ONLY",
        "professional_legal_certification": False,
        "case_count": 60,
        "issue_count": 585,
        "rows": qualification_rows,
        "cases": case_rows,
        "status_counts": dict(sorted(counts.items())),
        "candidate_identity": dict(candidate_identity),
        "retrieval_reattestation": {
            "passed": True,
            "metrics": dict(retrieval_metrics),
            "promotion_eligible": False,
            "answer_release_eligible": False,
        },
        "successor_source_holds": source_holds,
        "material_blockers": material_blockers,
        "common_legal_currentness_cutoff": None,
        "common_cutoff_support_status": "UNSUPPORTABLE_WITH_RETAINED_MATERIAL_HOLDS",
        "phase2a_technical_qualification_passed": False,
        "owner_adoption_of_a_successful_phase2a_digest_available": False,
        "phase2b_eligible": False,
        "development30_eligible": False,
        "answer_model_invoked": False,
        "planner_or_advisory_model_invoked": False,
        "candidate_mutated_by_qualification": False,
        "active_or_previous_written": False,
        "evidence_file_sha256s": dict(sorted(evidence_file_sha256s.items())),
        "terminal_verdict": (
            "PHASE 2A SAFELY STOPPED - PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    return _sealed(payload, field="artifact_content_sha256")
