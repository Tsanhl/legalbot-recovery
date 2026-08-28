"""Read-only semantic routing advisory for the 146 Phase-2A blockers.

The authoritative r3 report deliberately leaves its 461 prose holds
semantically unclassified.  This module adds a non-authorizing human-reviewed
row-level proposal without changing that report or its blocker predicate.

Every row in the r3 set has at least one sealed ``PARTIAL`` or ``NONE`` legal
support component.  Consequently none is a strict matter-information-only
fallback under the already adopted 585-row fallback contract.  The proposal
below distinguishes rows whose remaining dimension is exclusively legal or
policy evidence from rows that also contain a matter, question, analytical, or
hypothetical-input gap.  It never applies a fallback or clears a blocker.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from typing import Any

from .phase2a_successor_qualification import content_sha256, sealed

SCHEMA = "legalbot.v111.phase2a.blocker-semantic-routing-advisory.v1"
ROW_SCHEMA = "legalbot.v111.phase2a.blocker-semantic-routing-row.v1"

R3_REPORT_CONTENT_SHA256 = "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980"
ORIGINAL_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
FALLBACK_ADVISORY_CONTENT_SHA256 = (
    "035316cac6f9559744400bc9db7c05bdf74a85c7d120c59eae5cfc41f0462af8"
)
CASES_FILE_SHA256 = "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
MANIFEST_FILE_SHA256 = "b7a92403c13220e7dbb17d6e72e5342de024b974d425e56494ef92b23ca89072"

EXPECTED_R3_BLOCKER_SET_SHA256 = "b9c03979b9cc4891cc513bc1aa9b768b7fbaf8f80b5ccdbcfbfe227c02faf175"
EXPECTED_FALLBACK_ROW_IDS = frozenset({"live60-q58:issue-09", "live60-q58:issue-14"})

# Human-reviewed against the complete proposition and every raw hold for each
# row, not inferred from the issue label.  These rows have no separate missing
# matter/document or analytical-input dimension in their retained holds.
LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS = frozenset(
    {
        "live30-q06:issue-05",
        "live30-q09:issue-02",
        "live30-q12:issue-06",
        "live30-q27:issue-03",
        "live60-q37:issue-10",
        "live60-q41:issue-02",
        "live60-q48:issue-08",
        "live60-q48:issue-10",
    }
)

# One exact raw-hold witness is retained for every mixed row.  Ordinal 1 is the
# default; these overrides select the clearest matter/question/analytical-input
# sentence where an earlier hold is primarily a source or currentness hold.
NONLEGAL_WITNESS_ORDINAL_OVERRIDES: Mapping[str, int] = {
    "live30-q04:issue-01": 3,
    "live30-q04:issue-06": 2,
    "live30-q05:issue-06": 3,
    "live30-q05:issue-07": 4,
    "live30-q19:issue-01": 3,
    "live30-q19:issue-04": 2,
    "live30-q20:issue-08": 2,
    "live30-q21:issue-03": 3,
    "live30-q22:issue-07": 2,
    "live30-q24:issue-01": 3,
    "live30-q24:issue-08": 3,
    "live30-q25:issue-09": 2,
    "live30-q26:issue-01": 3,
    "live30-q26:issue-02": 3,
    "live30-q26:issue-08": 3,
    "live30-q26:issue-10": 3,
    "live30-q28:issue-05": 3,
    "live30-q29:issue-02": 3,
    "live30-q29:issue-05": 2,
    "live30-q29:issue-07": 2,
    "live30-q29:issue-09": 2,
    "live30-q30:issue-08": 2,
    "live30-q30:issue-14": 3,
    "live30-q30:issue-18": 3,
    "live60-q31:issue-07": 3,
    "live60-q32:issue-04": 3,
    "live60-q34:issue-06": 3,
    "live60-q35:issue-06": 2,
    "live60-q37:issue-06": 2,
    "live60-q38:issue-05": 2,
    "live60-q41:issue-05": 2,
    "live60-q42:issue-03": 2,
    "live60-q42:issue-05": 2,
    "live60-q42:issue-08": 2,
    "live60-q45:issue-03": 2,
    "live60-q45:issue-04": 2,
    "live60-q49:issue-08": 3,
    "live60-q50:issue-04": 2,
    "live60-q50:issue-07": 2,
    "live60-q51:issue-02": 2,
    "live60-q57:issue-01": 2,
}

NO_EXECUTION_FLAGS: Mapping[str, bool] = {
    "owner_decision_applied": False,
    "fallback_eligibility_applied": False,
    "source_admission_authorized": False,
    "source_admitted": False,
    "source_scan_run": False,
    "index_build_run": False,
    "embedding_run": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_run": False,
    "answer_model_run": False,
    "answer_released": False,
    "phase2b_authorized": False,
    "phase2b_run": False,
    "development30_authorized": False,
    "validation30_authorized": False,
    "owner_certification60_authorized": False,
    "promotion_authorized": False,
    "active_pointer_written": False,
    "previous_pointer_written": False,
    "live_activation_authorized": False,
    "training_export_authorized": False,
    "execution_chain_consumed": False,
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_seal(value: Mapping[str, Any], expected: str) -> None:
    if value.get("artifact_content_sha256") != expected:
        raise ValueError("phase2a_semantic_advisory_input_identity_mismatch")
    material = dict(value)
    material.pop("artifact_content_sha256", None)
    if content_sha256(material) != expected:
        raise ValueError("phase2a_semantic_advisory_input_seal_invalid")


def _case_rows(cases_raw: bytes, manifest_raw: bytes) -> dict[str, dict[str, Any]]:
    if _sha256(cases_raw) != CASES_FILE_SHA256:
        raise ValueError("phase2a_semantic_advisory_cases_identity_mismatch")
    if _sha256(manifest_raw) != MANIFEST_FILE_SHA256:
        raise ValueError("phase2a_semantic_advisory_manifest_identity_mismatch")
    rows: dict[str, dict[str, Any]] = {}
    case_count = 0
    ordinal = 0
    for raw_line in cases_raw.decode("utf-8").splitlines():
        case = json.loads(raw_line)
        case_count += 1
        case_id = str(case["case_id"])
        for issue_number, issue_label in enumerate(case["must_cover_issues"], start=1):
            ordinal += 1
            row_id = f"{case_id}:issue-{issue_number:02d}"
            if row_id in rows:
                raise ValueError("phase2a_semantic_advisory_registry_row_duplicate")
            rows[row_id] = {
                "case_id": case_id,
                "issue_id": f"issue-{issue_number:02d}",
                "issue_label": str(issue_label),
                "task_type": str(case["task_type"]),
                "registry_ordinal": ordinal,
                "question_sha256": str(case["question_sha256"]),
                "case_record_sha256": str(case["record_sha256"]),
            }
    if case_count != 60 or len(rows) != 585:
        raise ValueError("phase2a_semantic_advisory_registry_count_mismatch")
    return rows


def _row_set_sha256(row_ids: list[str]) -> str:
    return content_sha256(
        {
            "schema": "legalbot.v111.phase2a.semantic-row-id-set.v1",
            "row_ids": sorted(row_ids),
        }
    )


def build_blocker_semantic_advisory(
    *,
    r3_report: Mapping[str, Any],
    original_packet: Mapping[str, Any],
    fallback_advisory: Mapping[str, Any],
    cases_raw: bytes,
    manifest_raw: bytes,
) -> dict[str, Any]:
    """Build a non-authorizing exact row/digest semantic routing proposal."""

    _require_seal(r3_report, R3_REPORT_CONTENT_SHA256)
    _require_seal(original_packet, ORIGINAL_PACKET_CONTENT_SHA256)
    _require_seal(fallback_advisory, FALLBACK_ADVISORY_CONTENT_SHA256)
    if (
        r3_report.get("blocker_row_id_set_sha256") != EXPECTED_R3_BLOCKER_SET_SHA256
        or r3_report.get("status") != "BLOCKED_BEFORE_SUCCESSOR_QUALIFICATION"
        or r3_report.get("automated_semantic_hold_classification_performed") is not False
    ):
        raise ValueError("phase2a_semantic_advisory_r3_boundary_changed")

    fallback_rows = {
        str(row["row_id"])
        for row in fallback_advisory.get("eligible_rows", [])
        if isinstance(row, Mapping)
    }
    contract = fallback_advisory.get("classification_contract")
    remaining = fallback_advisory.get("remaining_583_row_policy")
    if (
        fallback_rows != EXPECTED_FALLBACK_ROW_IDS
        or not isinstance(contract, Mapping)
        or contract.get("dual_legal_source_and_fact_gap_fallback_prohibited") is not True
        or contract.get("fallback_must_not_hide_a_legal_knowledge_or_source_gap") is not True
        or contract.get(
            "strict_fact_only_requires_no_unresolved_legal_authority_currentness_later_treatment_jurisdiction_or_evidence_identity_blocker"
        )
        is not True
        or not isinstance(remaining, Mapping)
        or remaining.get("automatic_safe_fallback_eligibility") is not False
        or remaining.get("row_count") != 583
    ):
        raise ValueError("phase2a_semantic_advisory_fallback_boundary_changed")

    decisions = original_packet.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != 361:
        raise ValueError("phase2a_semantic_advisory_decision_inventory_changed")
    decision_by_row = {
        str(decision["row_id"]): decision for decision in decisions if isinstance(decision, Mapping)
    }
    if len(decision_by_row) != 361:
        raise ValueError("phase2a_semantic_advisory_decision_identity_duplicate")

    registry = _case_rows(cases_raw, manifest_raw)
    report_rows = r3_report.get("rows")
    if not isinstance(report_rows, list) or len(report_rows) != 146:
        raise ValueError("phase2a_semantic_advisory_r3_row_count_changed")
    report_row_ids = {str(row["row_id"]) for row in report_rows if isinstance(row, Mapping)}
    if len(report_row_ids) != 146 or report_row_ids & fallback_rows:
        raise ValueError("phase2a_semantic_advisory_row_boundary_changed")
    if not report_row_ids >= LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS:
        raise ValueError("phase2a_semantic_advisory_legal_only_rows_missing")

    rows: list[dict[str, Any]] = []
    category_counts: Counter[str] = Counter()
    task_counts: Counter[str] = Counter()
    raw_hold_count = 0
    raw_hold_binding_rows: list[dict[str, Any]] = []
    for report_row in sorted(report_rows, key=lambda value: str(value["row_id"])):
        row_id = str(report_row["row_id"])
        registry_row = registry.get(row_id)
        decision = decision_by_row.get(row_id)
        if registry_row is None or decision is None:
            raise ValueError("phase2a_semantic_advisory_upstream_row_missing")
        if decision.get("decision_content_sha256") != report_row.get("decision_content_sha256"):
            raise ValueError("phase2a_semantic_advisory_decision_binding_changed")

        components = report_row.get("blocking_components")
        holds = report_row.get("unclassified_unresolved_holds")
        if not isinstance(components, list) or not components:
            raise ValueError("phase2a_semantic_advisory_legal_component_missing")
        if any(component.get("support_fit") not in {"PARTIAL", "NONE"} for component in components):
            raise ValueError("phase2a_semantic_advisory_support_fit_changed")
        if not isinstance(holds, list) or not holds:
            raise ValueError("phase2a_semantic_advisory_raw_hold_inventory_missing")
        if any(
            hold.get("classification") != "UNCLASSIFIED_NON_OPERATIVE"
            or hold.get("requires_human_semantic_classification") is not True
            or hold.get("automated_semantic_classification_performed") is not False
            for hold in holds
        ):
            raise ValueError("phase2a_semantic_advisory_r3_hold_boundary_changed")

        task_type = str(registry_row["task_type"])
        task_counts[task_type] += 1
        if row_id in LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS:
            category = "LEGAL_OR_POLICY_EVIDENCE_ONLY"
            nonlegal_witness: dict[str, Any] | None = None
            route = "RESEARCH_OR_BIND_EXACT_LEGAL_OR_POLICY_EVIDENCE"
            nonlegal_dimension = "NONE_IDENTIFIED_AFTER_COMPLETE_HOLD_REVIEW"
        else:
            ordinal = NONLEGAL_WITNESS_ORDINAL_OVERRIDES.get(row_id, 1)
            if ordinal < 1 or ordinal > len(holds):
                raise ValueError("phase2a_semantic_advisory_witness_ordinal_invalid")
            witness = holds[ordinal - 1]
            nonlegal_witness = {
                "hold_ordinal": ordinal,
                "hold_text": witness["hold_text"],
                "hold_text_sha256": witness["hold_text_sha256"],
                "record_content_sha256": witness["record_content_sha256"],
            }
            if task_type == "problem":
                category = "MIXED_LEGAL_EVIDENCE_AND_MATTER_INFORMATION"
                nonlegal_dimension = "MATTER_DOCUMENT_FACT_OR_QUESTION_INFORMATION"
                route = "BIFURCATE_MATTER_INTAKE_FROM_LEGAL_EVIDENCE_REMEDIATION"
            elif task_type == "essay":
                category = "MIXED_LEGAL_EVIDENCE_AND_ANALYTICAL_OR_POLICY_INPUT"
                nonlegal_dimension = "ANALYTICAL_POLICY_EMPIRICAL_OR_HYPOTHETICAL_INPUT"
                route = "RESEARCH_LEGAL_EVIDENCE_AND_RETAIN_ANALYTICAL_INPUT_HOLD"
            else:
                raise ValueError("phase2a_semantic_advisory_unknown_task_type")

        category_counts[category] += 1
        raw_hold_count += len(holds)
        raw_holds = [
            {
                "hold_ordinal": ordinal,
                "hold_text": hold["hold_text"],
                "hold_text_sha256": hold["hold_text_sha256"],
                "record_content_sha256": hold["record_content_sha256"],
                "r3_classification_preserved": hold["classification"],
                "r3_blocker_effect_preserved": "NON_OPERATIVE",
            }
            for ordinal, hold in enumerate(holds, start=1)
        ]
        raw_hold_binding_rows.extend(
            {
                "row_id": row_id,
                "hold_ordinal": hold["hold_ordinal"],
                "hold_text_sha256": hold["hold_text_sha256"],
                "record_content_sha256": hold["record_content_sha256"],
            }
            for hold in raw_holds
        )
        legal_witnesses = [
            {
                "component_ordinal": component["component_ordinal"],
                "proposition_text_sha256": component["proposition_text_sha256"],
                "support_fit": component["support_fit"],
                "deterministic_blocker_reason_code": component["deterministic_blocker_reason_code"],
                "authority_content_sha256s": [
                    authority["authority_content_sha256"]
                    for authority in component.get("authorities", [])
                ],
                "assessment_content_sha256s": [
                    authority["assessment_content_sha256"]
                    for authority in component.get("authorities", [])
                ],
            }
            for component in components
        ]
        row_material = {
            "schema": ROW_SCHEMA,
            "row_id": row_id,
            **registry_row,
            "r3_row_record_content_sha256": report_row["record_content_sha256"],
            "owner_decision_content_sha256": report_row["decision_content_sha256"],
            "semantic_category_proposal": category,
            "nonlegal_dimension_proposal": nonlegal_dimension,
            "proposed_non_authorizing_route": route,
            "existing_safe_fallback_eligible": False,
            "strict_matter_information_only": False,
            "current_fallback_contract_may_clear_row": False,
            "new_exact_owner_supersession_required_for_any_future_fallback": True,
            "fallback_must_not_hide_sealed_partial_or_none_component": True,
            "legal_support_witnesses": legal_witnesses,
            "nonlegal_dimension_witness": nonlegal_witness,
            "all_raw_holds_preserved": raw_holds,
        }
        rows.append(sealed(row_material, field="record_content_sha256"))

    if task_counts != {"problem": 100, "essay": 46}:
        raise ValueError("phase2a_semantic_advisory_task_count_changed")
    expected_categories = {
        "LEGAL_OR_POLICY_EVIDENCE_ONLY": 8,
        "MIXED_LEGAL_EVIDENCE_AND_MATTER_INFORMATION": 99,
        "MIXED_LEGAL_EVIDENCE_AND_ANALYTICAL_OR_POLICY_INPUT": 39,
    }
    if dict(category_counts) != expected_categories or raw_hold_count != 461:
        raise ValueError("phase2a_semantic_advisory_classification_count_changed")

    legal_only = sorted(LEGAL_OR_POLICY_EVIDENCE_ONLY_ROW_IDS)
    mixed_problem = sorted(
        row["row_id"]
        for row in rows
        if row["semantic_category_proposal"] == "MIXED_LEGAL_EVIDENCE_AND_MATTER_INFORMATION"
    )
    mixed_other = sorted(
        row["row_id"]
        for row in rows
        if row["semantic_category_proposal"]
        == "MIXED_LEGAL_EVIDENCE_AND_ANALYTICAL_OR_POLICY_INPUT"
    )
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "READ_ONLY_HUMAN_SEMANTIC_ROUTING_PROPOSAL_NOT_APPLIED",
        "phase_scope": "PHASE_2A_PREQUALIFICATION_ONLY",
        "input_bindings": [
            {
                "kind": "authoritative_r3_prequalification_report",
                "content_sha256": R3_REPORT_CONTENT_SHA256,
                "blocker_row_id_set_sha256": EXPECTED_R3_BLOCKER_SET_SHA256,
            },
            {
                "kind": "upstream_exact_remediation_owner_packet",
                "content_sha256": ORIGINAL_PACKET_CONTENT_SHA256,
            },
            {
                "kind": "adopted_exact_585_fallback_coverage_advisory",
                "content_sha256": FALLBACK_ADVISORY_CONTENT_SHA256,
                "eligible_row_ids": sorted(fallback_rows),
            },
            {
                "kind": "immutable_live60_registry",
                "cases_file_sha256": CASES_FILE_SHA256,
                "manifest_file_sha256": MANIFEST_FILE_SHA256,
            },
        ],
        "classification_method": {
            "row_labels_used_as_semantic_evidence": False,
            "complete_proposition_and_raw_hold_text_reviewed": True,
            "structured_partial_or_none_component_is_legal_evidence_dimension": True,
            "one_exact_raw_hold_witness_bound_for_each_mixed_row": True,
            "all_raw_holds_preserved_verbatim_and_digest_bound": True,
            "r3_hold_classification_and_nonoperative_status_preserved": True,
            "classification_is_advisory_not_owner_decision": True,
        },
        "decisive_fallback_boundary": {
            "existing_exact_fallback_row_ids": sorted(fallback_rows),
            "existing_exact_fallback_rows_disjoint_from_r3_146": True,
            "strict_matter_information_only_row_count_in_r3_146": 0,
            "reason": (
                "Every r3 row retains at least one sealed PARTIAL or NONE legal-support "
                "component, while the adopted 585-row contract prohibits a fallback from "
                "hiding a legal knowledge or source gap."
            ),
            "automatic_new_fallback_eligibility_created": False,
        },
        "counts": {
            "row_count": 146,
            "raw_hold_count": 461,
            "strict_matter_information_only_fallback_candidate_count": 0,
            "legal_or_policy_evidence_only_count": 8,
            "mixed_or_other_count": 138,
            "mixed_legal_and_matter_information_count": 99,
            "mixed_legal_and_analytical_or_policy_input_count": 39,
            "problem_row_count": 100,
            "essay_row_count": 46,
        },
        "row_sets": {
            "strict_matter_information_only": {
                "row_ids": [],
                "row_id_set_sha256": content_sha256(
                    {
                        "schema": "legalbot.v111.phase2a.empty-semantic-row-set.v1",
                        "row_ids": [],
                    }
                ),
            },
            "legal_or_policy_evidence_only": {
                "row_ids": legal_only,
                "row_id_set_sha256": _row_set_sha256(legal_only),
            },
            "mixed_legal_and_matter_information": {
                "row_ids": mixed_problem,
                "row_id_set_sha256": _row_set_sha256(mixed_problem),
            },
            "mixed_legal_and_analytical_or_policy_input": {
                "row_ids": mixed_other,
                "row_id_set_sha256": _row_set_sha256(mixed_other),
            },
        },
        "raw_hold_binding_set_sha256": content_sha256(
            {
                "schema": "legalbot.v111.phase2a.semantic-raw-hold-binding-set.v1",
                "bindings": sorted(
                    raw_hold_binding_rows,
                    key=lambda value: (value["row_id"], value["hold_ordinal"]),
                ),
            }
        ),
        "owner_action_boundary": {
            "current_packet_can_legitimately_treat_any_of_146_as_fallback_pass": False,
            "new_exact_digest_bound_owner_supersession_required": True,
            "research_or_exact_evidence_required_for_every_row_before_substantive_pass": True,
            "matter_intake_can_be_operationally_bifurcated_but_does_not_clear_legal_gap": True,
        },
        "rows": rows,
        **NO_EXECUTION_FLAGS,
    }
    return sealed(payload)
