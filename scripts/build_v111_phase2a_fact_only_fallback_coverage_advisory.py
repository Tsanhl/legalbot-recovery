#!/usr/bin/env python3
"""Build the immutable Phase-2A fact-only fallback coverage advisory.

The builder audits the exact 585-row registry, the blocked 585-row matrix, the
approved 361-decision remediation packet, and the held-nine surviving-support
advisory.  It identifies the complete, closed row set eligible for an exact
matter-information fallback without allowing an essay or legal-source gap to
be hidden by a refusal.

This is create-only advisory scaffolding.  It does not apply an owner decision,
qualify a production row, admit a source, scan, build, embed, write a pointer,
release an answer, or authorize Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.phase2a_safe_fallback_qualification import (  # noqa: E402
    EVIDENCE_REQUIREMENT_STATUS,
    FAILURE_STATUS,
    HUMAN_ESCALATION_CTA,
    MISSING_INFORMATION_CATEGORIES,
    PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256,
    PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES,
    PERFORMANCE_BOND_REASON_CODE,
    PERFORMANCE_BOND_ROW_ID,
    PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
    PERFORMANCE_BOND_UI_CTA,
    QUALIFICATION_STATUS,
    REASON_CODE,
    ROW_ID,
    SAFE_FALLBACK_MESSAGE,
    UI_CTA,
    performance_bond_safe_fallback_contract,
    safe_fallback_contract,
)

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
ORIGINAL_PACKET_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
    / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
HELD9_ADVISORY_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-held9-surviving-support-advisory-r1"
    / "HELD9-SURVIVING-SUPPORT-ADVISORY.json"
)
BLOCKED_MATRIX_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
    / "machine/registries/COMPLETE-REMEDIATION-MATRIX-585.json"
)
CASES_PATH = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/cases.jsonl"
MANIFEST_PATH = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1/manifest.json"
SAFE_FALLBACK_MODULE_PATH = (
    PROJECT_ROOT / "backend/app/evaluation/phase2a_safe_fallback_qualification.py"
)

DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-fact-only-fallback-coverage-advisory-r1"
)
ADVISORY_NAME = "FACT-ONLY-FALLBACK-COVERAGE-ADVISORY-585.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

SCHEMA = "legalbot.v111.phase2a.fact-only-fallback-coverage-advisory.v1"
PACKAGE_SCHEMA = "legalbot.v111.phase2a.fact-only-fallback-coverage-package.v1"
STATUS = "EXACT_585_ROW_FALLBACK_COVERAGE_ADVISORY_READY_NOT_APPLIED"

EXPECTED_INPUTS = {
    "original_packet": {
        "content_sha256": ("93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"),
        "file_sha256": ("992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"),
    },
    "held9_advisory": {
        "content_sha256": ("599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd"),
        "file_sha256": ("2fe8eb506bce8ba455b7dea69d21927bba8fb54e242dba81c4287096a6535ef1"),
    },
    "blocked_matrix": {
        "content_sha256": ("49be0ac00ce72ec4a73c4387d5eef7934f3e72b63f8e80d2947397537cf44e18"),
        "file_sha256": ("3fcc5a695d86f6bf6e252b6edbd226a32f0aece2401efe0df3fff8e0bb809942"),
    },
}

EXPECTED_CASES_FILE_SHA256 = "78a738afd920ff840dcedeb0fd3fd5ca81035f499a0630d351d49e7c6cd3777a"
EXPECTED_MANIFEST_FILE_SHA256 = "b7a92403c13220e7dbb17d6e72e5342de024b974d425e56494ef92b23ca89072"
EXPECTED_SAFE_FALLBACK_MODULE_FILE_SHA256 = (
    "44abb52ee82eb8f6f4cce20cff048948dd7788c4d2a464fcde8f9b2f3c719fb0"
)
EXPECTED_PROJECT_RESCUE_CONTRACT_SHA256 = (
    "ba6c131f06e05bed9f6b6aa5743dc974f3b13618e3af39ffcaaabaf0f84c72f6"
)
EXPECTED_PERFORMANCE_BOND_CONTRACT_SHA256 = (
    "91cbb05fad64d2e26d11e75ff8adbe1b1b9d7fc300abea6785630078e5d2036e"
)

STRICT_FACT_ONLY_ROW_IDS = {ROW_ID}
NO_LEGAL_CLAIM_EXCEPTION_ROW_IDS = {PERFORMANCE_BOND_ROW_ID}
ELIGIBLE_ROW_IDS = STRICT_FACT_ONLY_ROW_IDS | NO_LEGAL_CLAIM_EXCEPTION_ROW_IDS
EXPECTED_HELD9_ROW_IDS = {
    "live30-q22:issue-02",
    "live30-q22:issue-04",
    "live30-q22:issue-06",
    "live60-q51:issue-05",
    "live60-q53:issue-04",
    "live60-q53:issue-11",
    "live60-q56:issue-01",
    "live60-q56:issue-05",
    PERFORMANCE_BOND_ROW_ID,
}

_NO_EXECUTION_FLAGS = {
    "owner_decision_applied": False,
    "production_qualification_run": False,
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
    "promotion_authorized": False,
    "active_pointer_written": False,
    "previous_pointer_written": False,
    "live_activation_authorized": False,
    "training_export_authorized": False,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _seal(value: Mapping[str, Any], field: str = "artifact_content_sha256") -> str:
    material = dict(value)
    material.pop(field, None)
    return _sha256(_canonical_json(material))


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"phase2a_fact_only_fallback_input_not_object:{path.name}")
    return value


def _verify_sealed_input(*, path: Path, content_sha256: str, file_sha256: str) -> dict[str, Any]:
    raw = path.read_bytes()
    if _sha256(raw) != file_sha256:
        raise ValueError(f"phase2a_fact_only_fallback_file_hash_mismatch:{path.name}")
    value = _load_json(path)
    if value.get("artifact_content_sha256") != content_sha256:
        raise ValueError(f"phase2a_fact_only_fallback_content_identity_mismatch:{path.name}")
    if _seal(value) != content_sha256:
        raise ValueError(f"phase2a_fact_only_fallback_content_seal_invalid:{path.name}")
    return value


def _registry_rows() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    if _sha256(CASES_PATH.read_bytes()) != EXPECTED_CASES_FILE_SHA256:
        raise ValueError("phase2a_fact_only_fallback_cases_hash_mismatch")
    if _sha256(MANIFEST_PATH.read_bytes()) != EXPECTED_MANIFEST_FILE_SHA256:
        raise ValueError("phase2a_fact_only_fallback_manifest_hash_mismatch")
    cases: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    ordinal = 0
    for line in CASES_PATH.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        case_id = str(case["case_id"])
        if case_id in cases:
            raise ValueError("phase2a_fact_only_fallback_duplicate_case_id")
        cases[case_id] = case
        for issue_number, issue_label in enumerate(case["must_cover_issues"], start=1):
            ordinal += 1
            rows.append(
                {
                    "row_id": f"{case_id}:issue-{issue_number:02d}",
                    "case_id": case_id,
                    "issue_id": f"issue-{issue_number:02d}",
                    "issue_label": issue_label,
                    "registry_ordinal": ordinal,
                    "task_type": case["task_type"],
                    "question_sha256": case["question_sha256"],
                    "case_record_sha256": case["record_sha256"],
                }
            )
    if len(cases) != 60 or len(rows) != 585:
        raise ValueError("phase2a_fact_only_fallback_registry_count_mismatch")
    if len({row["row_id"] for row in rows}) != 585:
        raise ValueError("phase2a_fact_only_fallback_registry_row_duplicate")
    return rows, cases


def _strict_fact_only_rows(decisions: list[dict[str, Any]]) -> list[str]:
    matches: list[str] = []
    for decision in decisions:
        if decision.get("decision_class") != "OFFICIAL_RESEARCH_RECOMMENDATION":
            continue
        queue = decision.get("source_queue_record")
        research = decision.get("source_research_record")
        if not isinstance(queue, dict) or not isinstance(research, dict):
            continue
        atomic_components = research.get("atomic_components")
        all_authority_lists_empty = bool(atomic_components) and all(
            isinstance(component, dict) and component.get("authorities") == []
            for component in atomic_components
        )
        if all(
            (
                decision.get("recommended_owner_outcome")
                == "RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION",
                decision.get("authority_assessments") == [],
                queue.get("canonical_atomic_proposition") is None,
                queue.get("proposition_status") == "NEEDS_PROPOSITION_SPLIT",
                queue.get("qualification_status") == "BLOCKED_MATERIAL_GAP",
                all_authority_lists_empty,
            )
        ):
            matches.append(str(decision["row_id"]))
    return sorted(matches)


def _eligible_rows(
    *,
    registry_rows: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    held9: dict[str, Any],
) -> list[dict[str, Any]]:
    registry_by_row = {row["row_id"]: row for row in registry_rows}
    decisions_by_row = {str(row["row_id"]): row for row in decisions}
    held9_by_row = {
        str(row["row_id"]): row for row in held9["row_outcomes"] if isinstance(row, dict)
    }

    project_rescue = decisions_by_row[ROW_ID]
    project_rescue_holds = project_rescue["source_research_record"]["unresolved_holds"]
    if project_rescue_holds != [
        "This is an evidence-dependent synthesis, not a standalone legal rule supported by one authority.",
        "The critical consent, safety, notice, cure, termination, bond, insurance, lender, security, cash-runway, insolvency and stakeholder documents and deadlines are absent.",
    ]:
        raise ValueError("phase2a_fact_only_fallback_project_rescue_holds_changed")

    q58 = held9_by_row[PERFORMANCE_BOND_ROW_ID]
    if any(
        (
            q58.get("outcome") != "NO_LEGAL_CLAIM_MATTER_FACT_SUPPLEMENTATION_FALLBACK_ADVISORY",
            q58.get("safe_fallback_eligible") is not True,
            q58.get("safe_fallback_prohibited") is not False,
            q58.get("blocker_class") != "MISSING_MATTER_FACTS",
            q58.get("knowledge_gap_event") is not False,
            q58.get("matter_information_gap_event") is not True,
            q58.get("fallback_releases_material_legal_claim") is not False,
            q58.get("legal_rule_release_prohibited") is not True,
            q58.get("citation_release_prohibited") is not True,
            q58.get("evidence_span_release_prohibited") is not True,
            q58.get("currentness_hold_retained") is not True,
            q58.get("later_treatment_hold_retained") is not True,
        )
    ):
        raise ValueError("phase2a_fact_only_fallback_performance_bond_route_changed")
    expected_requested_material = [
        "Bond instrument and amendments.",
        "Demand, service records and evidence of compliance with demand conditions.",
        "Expiry information.",
        "Underlying contract and termination notices.",
        "Governing-law material.",
        "Fraud evidence.",
        "Urgency and injunction evidence.",
    ]
    if (
        q58.get("requested_material") != expected_requested_material
        or q58.get("safe_fallback_text") != PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE
    ):
        raise ValueError("phase2a_fact_only_fallback_performance_bond_inputs_changed")

    project_contract = safe_fallback_contract()
    performance_contract = performance_bond_safe_fallback_contract()
    if (
        project_contract["contract_content_sha256"] != EXPECTED_PROJECT_RESCUE_CONTRACT_SHA256
        or performance_contract["contract_content_sha256"]
        != EXPECTED_PERFORMANCE_BOND_CONTRACT_SHA256
    ):
        raise ValueError("phase2a_fact_only_fallback_contract_identity_changed")

    return [
        {
            **registry_by_row[ROW_ID],
            "eligibility_class": "STRICT_FACT_ONLY_REMAINING_BLOCKER",
            "reason_code": REASON_CODE,
            "qualification_status_if_exact_owner_adopted_contract_satisfied": (
                QUALIFICATION_STATUS
            ),
            "qualification_status_if_contract_violated": FAILURE_STATUS,
            "contract_content_sha256": project_contract["contract_content_sha256"],
            "required_missing_information_categories": list(MISSING_INFORMATION_CATEGORIES),
            "required_user_message": SAFE_FALLBACK_MESSAGE,
            "required_action": "REQUEST_SUPPLEMENTATION_AND_HUMAN_LEGAL_REVIEW",
            "human_escalation_cta": HUMAN_ESCALATION_CTA,
            "ui_cta": UI_CTA,
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "material_legal_claim_released": False,
            "evidence_requirement_status": EVIDENCE_REQUIREMENT_STATUS,
            "prohibited_outputs": [
                "SUBSTANTIVE_PROJECT_RESCUE_ADVICE",
                "SPECULATIVE_LEGAL_OR_FACTUAL_CONCLUSION",
                "LEGAL_CITATION",
                "EVIDENCE_SPAN",
                "SOURCE_VERSION_BINDING",
                "ANSWER_MODEL_OUTPUT_FOR_THIS_ISSUE",
            ],
            "underlying_legal_source_hold_hidden_by_fallback": False,
            "owner_adoption_required_before_application": True,
        },
        {
            **registry_by_row[PERFORMANCE_BOND_ROW_ID],
            "eligibility_class": "NO_LEGAL_CLAIM_MATTER_FACT_FALLBACK_EXCEPTION",
            "strict_fact_only_in_original_361_packet": False,
            "reason_code": PERFORMANCE_BOND_REASON_CODE,
            "qualification_status_if_exact_owner_adopted_contract_satisfied": (
                QUALIFICATION_STATUS
            ),
            "qualification_status_if_contract_violated": FAILURE_STATUS,
            "contract_content_sha256": performance_contract["contract_content_sha256"],
            "bound_held9_advisory_content_sha256": (PERFORMANCE_BOND_HELD9_ADVISORY_CONTENT_SHA256),
            "required_missing_information_categories": list(
                PERFORMANCE_BOND_MISSING_INFORMATION_CATEGORIES
            ),
            "required_missing_material": expected_requested_material,
            "required_user_message": PERFORMANCE_BOND_SAFE_FALLBACK_MESSAGE,
            "required_action": ("REQUEST_BOND_AND_DEMAND_DOCUMENTS_AND_HUMAN_LEGAL_REVIEW"),
            "human_escalation_cta": HUMAN_ESCALATION_CTA,
            "ui_cta": PERFORMANCE_BOND_UI_CTA,
            "knowledge_gap_event": False,
            "matter_information_gap_event": True,
            "material_legal_claim_released": False,
            "evidence_requirement_status": EVIDENCE_REQUIREMENT_STATUS,
            "excluded_unsupported_components": q58["excluded_unsupported_components"],
            "retained_underlying_holds": {
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "underlying_substantive_answer_not_qualified": True,
            },
            "prohibited_outputs": [
                "PERFORMANCE_BOND_CLASSIFICATION",
                "DEMAND_COMPLIANCE_CONCLUSION",
                "FRAUD_EXCEPTION_CONCLUSION",
                "INJUNCTION_MERITS_CONCLUSION",
                "SHANGHAI_OR_WUHAN_LEGAL_RULE",
                "LEGAL_CITATION",
                "EVIDENCE_SPAN",
                "SOURCE_VERSION_BINDING",
                "ANSWER_MODEL_OUTPUT_FOR_THIS_ISSUE",
            ],
            "owner_adoption_required_before_application": True,
        },
    ]


def _build_advisory() -> dict[str, Any]:
    original = _verify_sealed_input(path=ORIGINAL_PACKET_PATH, **EXPECTED_INPUTS["original_packet"])
    held9 = _verify_sealed_input(path=HELD9_ADVISORY_PATH, **EXPECTED_INPUTS["held9_advisory"])
    blocked = _verify_sealed_input(path=BLOCKED_MATRIX_PATH, **EXPECTED_INPUTS["blocked_matrix"])
    if _sha256(SAFE_FALLBACK_MODULE_PATH.read_bytes()) != EXPECTED_SAFE_FALLBACK_MODULE_FILE_SHA256:
        raise ValueError("phase2a_fact_only_fallback_module_hash_mismatch")

    registry_rows, cases = _registry_rows()
    registry_row_ids = {row["row_id"] for row in registry_rows}
    matrix_rows = blocked.get("rows")
    decisions = original.get("decisions")
    held9_rows = held9.get("row_outcomes")
    if not isinstance(matrix_rows, list) or len(matrix_rows) != 585:
        raise ValueError("phase2a_fact_only_fallback_matrix_count_mismatch")
    if {str(row.get("row_id")) for row in matrix_rows} != registry_row_ids:
        raise ValueError("phase2a_fact_only_fallback_matrix_registry_set_mismatch")
    if not isinstance(decisions, list) or len(decisions) != 361:
        raise ValueError("phase2a_fact_only_fallback_decision_count_mismatch")
    decision_row_ids = {str(row.get("row_id")) for row in decisions}
    if len(decision_row_ids) != 361 or not decision_row_ids < registry_row_ids:
        raise ValueError("phase2a_fact_only_fallback_decision_set_invalid")
    if not isinstance(held9_rows, list) or len(held9_rows) != 9:
        raise ValueError("phase2a_fact_only_fallback_held9_count_mismatch")
    held9_row_ids = {str(row.get("row_id")) for row in held9_rows}
    if held9_row_ids != EXPECTED_HELD9_ROW_IDS:
        raise ValueError("phase2a_fact_only_fallback_held9_set_mismatch")

    strict_matches = _strict_fact_only_rows(decisions)
    if set(strict_matches) != STRICT_FACT_ONLY_ROW_IDS:
        raise ValueError("phase2a_fact_only_fallback_strict_row_set_changed")
    other_held9 = [row for row in held9_rows if str(row["row_id"]) != PERFORMANCE_BOND_ROW_ID]
    if any(
        row.get("safe_fallback_eligible") is not False
        or row.get("safe_fallback_prohibited") is not True
        or row.get("blocker_class")
        not in {"LEGAL_AUTHORITY_GAP", "DUAL_LEGAL_SOURCE_AND_MATTER_FACT_HOLD"}
        for row in other_held9
    ):
        raise ValueError("phase2a_fact_only_fallback_held9_exclusion_changed")

    eligible_rows = _eligible_rows(
        registry_rows=registry_rows,
        decisions=decisions,
        held9=held9,
    )
    if {row["row_id"] for row in eligible_rows} != ELIGIBLE_ROW_IDS:
        raise ValueError("phase2a_fact_only_fallback_eligible_set_changed")

    q58_case = cases["live60-q58"]
    if q58_case.get("task_type") != "problem":
        raise ValueError("phase2a_fact_only_fallback_q58_not_problem")
    direct_count = sum(
        row.get("decision_class") == "DIRECT_EXACT_LOCAL_SPAN_RECOMMENDATION" for row in decisions
    )
    research_count = sum(
        row.get("decision_class") == "OFFICIAL_RESEARCH_RECOMMENDATION" for row in decisions
    )
    if direct_count != 45 or research_count != 316:
        raise ValueError("phase2a_fact_only_fallback_decision_class_count_changed")

    excluded_rows = sorted(registry_row_ids - ELIGIBLE_ROW_IDS)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": STATUS,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "phase_scope": "PHASE2A_ONLY",
        "input_bindings": [
            {
                "kind": key,
                "path": path.relative_to(PROJECT_ROOT).as_posix(),
                **EXPECTED_INPUTS[key],
            }
            for key, path in (
                ("original_packet", ORIGINAL_PACKET_PATH),
                ("held9_advisory", HELD9_ADVISORY_PATH),
                ("blocked_matrix", BLOCKED_MATRIX_PATH),
            )
        ],
        "registry_binding": {
            "case_count": 60,
            "row_count": 585,
            "cases_file_sha256": EXPECTED_CASES_FILE_SHA256,
            "manifest_file_sha256": EXPECTED_MANIFEST_FILE_SHA256,
            "matrix_row_set_matches_registry": True,
        },
        "audit_counts": {
            "registry_row_count": 585,
            "exact_remediation_decision_count": 361,
            "rows_outside_exact_remediation_decision_packet": 224,
            "direct_exact_local_span_decision_count": direct_count,
            "official_research_decision_count": research_count,
            "strict_fact_only_remaining_blocker_row_count": 1,
            "no_legal_claim_matter_fact_exception_row_count": 1,
            "total_safe_fallback_eligible_row_count": 2,
            "safe_fallback_prohibited_or_not_required_row_count": len(excluded_rows),
        },
        "classification_contract": {
            "strict_fact_only_requires_no_unresolved_legal_authority_currentness_later_treatment_jurisdiction_or_evidence_identity_blocker": True,
            "strict_fact_only_row_ids": strict_matches,
            "no_legal_claim_exception_requires_every_unsupported_legal_component_citation_and_span_to_be_excluded": True,
            "no_legal_claim_exception_row_ids": sorted(NO_LEGAL_CLAIM_EXCEPTION_ROW_IDS),
            "essay_fallback_prohibited": True,
            "dual_legal_source_and_fact_gap_fallback_prohibited": True,
            "fallback_must_not_hide_a_legal_knowledge_or_source_gap": True,
            "fallback_pass_is_not_a_substantive_legal_answer_pass": True,
            "row_removal_or_cancellation_prohibited": True,
            "owner_adoption_required_before_application": True,
        },
        "coverage_verdict": {
            "eligible_row_ids": sorted(ELIGIBLE_ROW_IDS),
            "coverage_complete_for_exact_585_row_audit": True,
            "project_rescue_contract_identity_preserved": True,
            "project_rescue_contract_content_sha256": (EXPECTED_PROJECT_RESCUE_CONTRACT_SHA256),
            "performance_bond_contract_added_as_separate_exact_contract": True,
            "performance_bond_contract_content_sha256": (EXPECTED_PERFORMANCE_BOND_CONTRACT_SHA256),
            "qualification_status_only_when_exact_contract_is_adopted_and_satisfied": (
                QUALIFICATION_STATUS
            ),
            "qualification_status_on_any_contract_change": FAILURE_STATUS,
            "production_qualification_performed": False,
        },
        "eligible_rows": eligible_rows,
        "explicit_non_eligible_examples": [
            {
                "row_id": str(row["row_id"]),
                "question_kind": row["question_kind"],
                "blocker_class": row["blocker_class"],
                "safe_fallback_prohibited": True,
                "reason": row.get(
                    "reason",
                    "The sealed advisory identifies a genuine legal-authority gap; a fact fallback cannot replace the missing law.",
                ),
            }
            for row in sorted(other_held9, key=lambda item: str(item["row_id"]))
        ],
        "remaining_583_row_policy": {
            "row_count": len(excluded_rows),
            "row_id_set_sha256": _sha256(_canonical_json(excluded_rows)),
            "automatic_safe_fallback_eligibility": False,
            "reason": (
                "They either have no exact remediation blocker requiring this route or require "
                "legal evidence, legal review, currentness, later-treatment, jurisdiction, "
                "identity, owner decision, or another non-factual resolution."
            ),
        },
        "safe_fallback_module_binding": {
            "path": SAFE_FALLBACK_MODULE_PATH.relative_to(PROJECT_ROOT).as_posix(),
            "file_sha256": EXPECTED_SAFE_FALLBACK_MODULE_FILE_SHA256,
            "project_rescue_contract_content_sha256": (EXPECTED_PROJECT_RESCUE_CONTRACT_SHA256),
            "performance_bond_contract_content_sha256": (EXPECTED_PERFORMANCE_BOND_CONTRACT_SHA256),
        },
        "advisory_effect": "NO_EXECUTION_NO_OWNER_DECISION_NO_PRODUCTION_QUALIFICATION",
        **_NO_EXECUTION_FLAGS,
    }
    payload["artifact_content_sha256"] = _seal(payload)
    return payload


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)


def build(output_root: Path) -> Path:
    advisory = _build_advisory()
    output_root.mkdir(parents=True, exist_ok=False)
    advisory_raw = _pretty_json(advisory)
    advisory_file_sha256 = _sha256(advisory_raw)

    package_material: dict[str, Any] = {
        "schema": PACKAGE_SCHEMA,
        "status": STATUS,
        "advisory_content_sha256": advisory["artifact_content_sha256"],
        "artifacts": [
            {
                "name": ADVISORY_NAME,
                "content_sha256": advisory["artifact_content_sha256"],
                "file_sha256": advisory_file_sha256,
            }
        ],
        "eligible_row_ids": sorted(ELIGIBLE_ROW_IDS),
        "eligible_row_count": 2,
        "owner_adoption_required_before_application": True,
        "advisory_effect": "NO_EXECUTION_NO_OWNER_DECISION_NO_PRODUCTION_QUALIFICATION",
        **_NO_EXECUTION_FLAGS,
    }
    package = {
        **package_material,
        "artifact_content_sha256": _seal(package_material),
    }
    package_raw = _pretty_json(package)
    checksums_raw = (
        f"{advisory_file_sha256}  {ADVISORY_NAME}\n{_sha256(package_raw)}  {PACKAGE_NAME}\n"
    ).encode()

    _write_new(output_root / ADVISORY_NAME, advisory_raw)
    _write_new(output_root / PACKAGE_NAME, package_raw)
    _write_new(output_root / CHECKSUMS_NAME, checksums_raw)
    return output_root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    output_root = args.output_root
    if not output_root.is_absolute():
        output_root = PROJECT_ROOT / output_root
    built = build(output_root)
    print(built)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
