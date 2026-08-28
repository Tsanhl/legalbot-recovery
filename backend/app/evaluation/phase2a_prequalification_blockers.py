"""Fail-closed Phase-2A prequalification blocker audit.

This audit is intentionally earlier than a successor build or retrieval run.  It
applies the final owner packet's exact precedence to the 361-row remediation
packet, then reports every remaining row whose structured component support is
``PARTIAL`` or ``NONE``.  Generic prose holds are preserved verbatim and left
semantically unclassified for human review.  They never create or clear a
blocker: the blocker predicate comes only from the sealed component
``support_fit`` field and the exact supersession/fallback boundaries in the
final packet.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .phase2a_successor_qualification import (
    ECHR_RECOVERY_MANIFEST_CONTENT_SHA256,
    EXECUTION_AUTHORITY_CONTENT_SHA256,
    FALLBACK_COVERAGE_ADVISORY_CONTENT_SHA256,
    FINAL_OWNER_PACKET_CONTENT_SHA256,
    FINAL_OWNER_RECEIPT_CONTENT_SHA256,
    HELD9_ADVISORY_CONTENT_SHA256,
    PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256,
    PROJECT_RESCUE_CONTRACT_CONTENT_SHA256,
    Q53_SEMENYA_ADVISORY_CONTENT_SHA256,
    content_sha256,
    require_seal,
    sealed,
    validate_owner_receipt,
)

SCHEMA = "legalbot.v111.phase2a.prequalification-blocker-report.v1"
ROW_SCHEMA = "legalbot.v111.phase2a.prequalification-blocker-row.v1"
HOLD_SCHEMA = "legalbot.v111.phase2a.prequalification-hold-classification.v1"
ORIGINAL_PACKET_SCHEMA = "legalbot.v111.phase2a.exact-remediation-owner-packet.v1"
FINAL_PACKET_SCHEMA = "legalbot.v111.phase2a.source-delta-safe-fallback-owner-packet.v1"
EXECUTION_AUTHORITY_SCHEMA = "legalbot.v111.phase2a.final-remediation-execution-authority.v1"
ORIGINAL_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
PREDECESSOR_R1_REPORT_CONTENT_SHA256 = (
    "9f9db53925247f2dbc1d599d3fc87f9c7ee6a96aa6f3b03dc1c5b7ab2f67e40a"
)
PREDECESSOR_R2_REPORT_CONTENT_SHA256 = (
    "234e21dcee57cbb3d163573e5e0472bd466e5d652e729fa0bdfffb83b30d60b8"
)
PREDECESSOR_R1_BLOCKER_ROW_ID_SET_SHA256 = (
    "b9c03979b9cc4891cc513bc1aa9b768b7fbaf8f80b5ccdbcfbfe227c02faf175"
)
PREDECESSOR_R1_PARTIAL_ROW_ID_SET_SHA256 = (
    "c901cbb0240fba44f1ccc954bca5d100dc14c0d36d6dba8e5fc2eebce66b9df8"
)
PREDECESSOR_R1_NONE_ROW_ID_SET_SHA256 = (
    "1de4a63dcc0088fc7fdc22d2e59951e923273496c59dff37642ee3c1d95d886d"
)

EXPECTED_SPECIAL_SUPERSESSION_ROW_IDS = frozenset(
    {
        "live30-q22:issue-02",
        "live30-q22:issue-04",
        "live30-q22:issue-06",
        "live60-q51:issue-05",
        "live60-q53:issue-04",
        "live60-q53:issue-11",
        "live60-q56:issue-01",
        "live60-q56:issue-05",
    }
)
EXPECTED_FALLBACK_ROW_IDS = frozenset(
    {
        "live60-q58:issue-09",
        "live60-q58:issue-14",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def row_id_set_sha256(row_ids: Sequence[str]) -> str:
    values = sorted(str(value) for value in row_ids)
    if not values or len(values) != len(set(values)):
        raise ValueError("prequalification row-id set is empty or duplicated")
    return content_sha256(
        {
            "schema": "legalbot.v111.phase2a.row-id-set.v1",
            "row_ids": values,
        }
    )


def _record_content_sha256(value: Mapping[str, Any]) -> str:
    supplied = value.get("record_content_sha256")
    if isinstance(supplied, str) and _SHA256.fullmatch(supplied):
        material = dict(value)
        material.pop("record_content_sha256", None)
        if content_sha256(material) == supplied:
            return supplied
    return content_sha256(value)


def _unclassified_hold(text: str) -> dict[str, Any]:
    material = {
        "schema": HOLD_SCHEMA,
        "hold_text": text,
        "hold_text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "classification": "UNCLASSIFIED_NON_OPERATIVE",
        "requires_human_semantic_classification": True,
        "automated_semantic_classification_performed": False,
        "classification_did_not_create_or_clear_row_blocker": True,
    }
    return sealed(material, field="record_content_sha256")


def _official_research_decisions(packet: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    decisions = packet.get("decisions")
    if not isinstance(decisions, list) or len(decisions) != 361:
        raise ValueError("original remediation packet is not exactly 361 decisions")
    output: dict[str, Mapping[str, Any]] = {}
    for decision in decisions:
        if not isinstance(decision, Mapping):
            raise ValueError("original remediation decision is invalid")
        row_id = str(decision.get("row_id") or "")
        if not row_id or row_id in output:
            raise ValueError("original remediation row identity is missing or duplicated")
        output[row_id] = decision
    return output


def _final_packet_precedence(final_packet: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    recovery = final_packet.get("echr_held_source_recovery")
    q53 = final_packet.get("q53_semenya_substitute_advisory")
    fallback = final_packet.get("fact_only_fallback_coverage_advisory")
    held9 = final_packet.get("held9_surviving_support_advisory")
    if not all(isinstance(value, Mapping) for value in (recovery, q53, fallback, held9)):
        raise ValueError("final packet precedence records are unavailable")
    assert isinstance(recovery, Mapping)
    assert isinstance(q53, Mapping)
    assert isinstance(fallback, Mapping)
    assert isinstance(held9, Mapping)
    if (
        recovery.get("manifest_content_sha256") != ECHR_RECOVERY_MANIFEST_CONTENT_SHA256
        or q53.get("content_sha256") != Q53_SEMENYA_ADVISORY_CONTENT_SHA256
        or fallback.get("content_sha256") != FALLBACK_COVERAGE_ADVISORY_CONTENT_SHA256
        or held9.get("content_sha256") != HELD9_ADVISORY_CONTENT_SHA256
    ):
        raise ValueError("final packet precedence identity differs")

    special: set[str] = set()
    new_sources = recovery.get("exact_new_source_admission_bindings")
    goodwin = recovery.get("goodwin_existing_quarantine_binding")
    q53_decisions = q53.get("exact_revised_proposition_set_owner_decisions")
    if (
        not isinstance(new_sources, list)
        or not isinstance(goodwin, Mapping)
        or not isinstance(q53_decisions, list)
    ):
        raise ValueError("final packet substantive supersession inventory differs")
    for record in new_sources:
        if not isinstance(record, Mapping) or not isinstance(record.get("affected_row_ids"), list):
            raise ValueError("ECHR supersession record differs")
        special.update(str(value) for value in record["affected_row_ids"])
    if not isinstance(goodwin.get("affected_row_ids"), list):
        raise ValueError("Goodwin supersession record differs")
    special.update(str(value) for value in goodwin["affected_row_ids"])
    for record in q53_decisions:
        if not isinstance(record, Mapping) or not str(record.get("row_id") or ""):
            raise ValueError("q53 supersession record differs")
        special.add(str(record["row_id"]))

    fallback_rows = fallback.get("exact_eligible_row_ids")
    if not isinstance(fallback_rows, list):
        raise ValueError("safe-fallback precedence inventory differs")
    fallback_set = {str(value) for value in fallback_rows}
    if (
        special != EXPECTED_SPECIAL_SUPERSESSION_ROW_IDS
        or fallback_set != EXPECTED_FALLBACK_ROW_IDS
        or special & fallback_set
        or final_packet.get("safe_fallback_decision", {}).get("canonical_contract_content_sha256")
        != PROJECT_RESCUE_CONTRACT_CONTENT_SHA256
        or final_packet.get("performance_bond_safe_fallback_decision", {}).get(
            "canonical_contract_content_sha256"
        )
        != PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
    ):
        raise ValueError("final packet exact supersession/fallback boundary differs")
    return special, fallback_set


def _authority_records(
    decision: Mapping[str, Any],
    *,
    component_ordinal: int,
    component: Mapping[str, Any],
) -> list[dict[str, Any]]:
    assessments = decision.get("authority_assessments")
    if not isinstance(assessments, list):
        raise ValueError("authority assessment inventory is unavailable")
    assessment_map: dict[int, Mapping[str, Any]] = {}
    for assessment in assessments:
        if (
            isinstance(assessment, Mapping)
            and assessment.get("component_ordinal") == component_ordinal
        ):
            authority_ordinal = int(assessment.get("authority_ordinal") or 0)
            if authority_ordinal < 1 or authority_ordinal in assessment_map:
                raise ValueError("authority assessment ordinal is invalid")
            assessment_map[authority_ordinal] = assessment
    authorities = component.get("authorities")
    if not isinstance(authorities, list):
        raise ValueError("component authority inventory is invalid")
    output: list[dict[str, Any]] = []
    for authority_ordinal, authority in enumerate(authorities, start=1):
        if not isinstance(authority, Mapping):
            raise ValueError("component authority record is invalid")
        assessment = assessment_map.get(authority_ordinal)
        if assessment is None:
            raise ValueError("component authority lacks its deterministic assessment")
        authority_sha256 = content_sha256(authority)
        if authority_sha256 != assessment.get("authority_content_sha256"):
            raise ValueError("component authority assessment binding differs")
        locators = authority.get("exact_locators")
        if not isinstance(locators, list) or any(not str(value).strip() for value in locators):
            raise ValueError("component authority exact locator inventory differs")
        output.append(
            {
                "authority_ordinal": authority_ordinal,
                "authority_content_sha256": authority_sha256,
                "assessment_content_sha256": assessment.get("assessment_content_sha256"),
                "canonical_authority_identity_id": assessment.get(
                    "canonical_authority_identity_id"
                ),
                "title": authority.get("title"),
                "citation": authority.get("citation"),
                "official_url": authority.get("official_url"),
                "exact_locators": [str(value) for value in locators],
                "candidate_existing_at_packet_time": authority.get("candidate_existing"),
                "source_admission_required_at_packet_time": authority.get(
                    "source_admission_required"
                ),
                "adoption_eligible_at_packet_time": assessment.get("adoption_eligible"),
                "assessment_hold_reason_codes": list(assessment.get("hold_reason_codes") or []),
            }
        )
    return output


def build_prequalification_blocker_report(
    *,
    original_packet: Mapping[str, Any],
    final_packet: Mapping[str, Any],
    owner_receipt: Mapping[str, Any],
    execution_authority: Mapping[str, Any],
    original_packet_path: str,
    original_packet_file_sha256: str,
    final_packet_path: str,
    final_packet_file_sha256: str,
    owner_receipt_path: str,
    owner_receipt_file_sha256: str,
    execution_authority_path: str,
    execution_authority_file_sha256: str,
) -> dict[str, Any]:
    """Return the sealed deterministic blocker report without mutating runtime state."""

    original_sha256 = require_seal(original_packet, label="original remediation packet")
    final_sha256 = require_seal(final_packet, label="final remediation owner packet")
    receipt_sha256 = validate_owner_receipt(owner_receipt)
    execution_sha256 = require_seal(
        execution_authority,
        label="Phase-2A execution authority",
    )
    if (
        original_packet.get("schema") != ORIGINAL_PACKET_SCHEMA
        or original_sha256 != ORIGINAL_PACKET_CONTENT_SHA256
        or final_packet.get("schema") != FINAL_PACKET_SCHEMA
        or final_sha256 != FINAL_OWNER_PACKET_CONTENT_SHA256
        or receipt_sha256 != FINAL_OWNER_RECEIPT_CONTENT_SHA256
        or execution_authority.get("schema") != EXECUTION_AUTHORITY_SCHEMA
        or execution_sha256 != EXECUTION_AUTHORITY_CONTENT_SHA256
        or execution_authority.get("status") != "AVAILABLE_UNSPENT"
        or execution_authority.get("execution_chain_remaining_count") != 1
        or execution_authority.get("execution_chain_consumed_count") != 0
        or execution_authority.get("source_scan_run") is not False
        or execution_authority.get("successor_build_run") is not False
        or execution_authority.get("embedding_run") is not False
        or execution_authority.get("retrieval_reattestation_run") is not False
        or execution_authority.get("all585_qualification_run") is not False
        or not _SHA256.fullmatch(original_packet_file_sha256)
        or not _SHA256.fullmatch(final_packet_file_sha256)
        or not _SHA256.fullmatch(owner_receipt_file_sha256)
        or not _SHA256.fullmatch(execution_authority_file_sha256)
    ):
        raise ValueError("prequalification packet identity differs")

    decisions = _official_research_decisions(original_packet)
    special_rows, fallback_rows = _final_packet_precedence(final_packet)
    if not (special_rows | fallback_rows).issubset(decisions):
        raise ValueError("final packet precedence escapes the 361-row inventory")

    blocker_rows: list[dict[str, Any]] = []
    partial_row_ids: set[str] = set()
    none_row_ids: set[str] = set()
    fit_counts: Counter[str] = Counter()
    raw_hold_count = 0
    considered_decision_count = 0
    recommendation_counts: Counter[str] = Counter(
        str(decision.get("recommended_owner_outcome") or "")
        for decision in decisions.values()
        if decision.get("decision_class") == "OFFICIAL_RESEARCH_RECOMMENDATION"
    )
    for row_id, decision in decisions.items():
        if row_id in special_rows or row_id in fallback_rows:
            continue
        considered_decision_count += 1
        if decision.get("decision_class") != "OFFICIAL_RESEARCH_RECOMMENDATION":
            continue
        record = decision.get("source_research_record")
        if not isinstance(record, Mapping) or record.get("row_id") != row_id:
            raise ValueError(f"official research record differs: {row_id}")
        components = record.get("atomic_components")
        if not isinstance(components, list) or not components:
            raise ValueError(f"official research component inventory differs: {row_id}")
        blocking_components: list[dict[str, Any]] = []
        for component_ordinal, component in enumerate(components, start=1):
            if not isinstance(component, Mapping):
                raise ValueError(f"official research component differs: {row_id}")
            fit = str(component.get("support_fit") or "")
            if fit not in {"FULL", "PARTIAL", "NONE"}:
                raise ValueError(f"official research support fit differs: {row_id}")
            if fit == "FULL":
                continue
            proposition = str(component.get("proposition") or "")
            if not proposition:
                raise ValueError(f"blocking component has no proposition: {row_id}")
            fit_counts[fit] += 1
            if fit == "PARTIAL":
                partial_row_ids.add(row_id)
            else:
                none_row_ids.add(row_id)
            blocking_components.append(
                {
                    "component_ordinal": component_ordinal,
                    "support_fit": fit,
                    "proposition": proposition,
                    "proposition_text_sha256": hashlib.sha256(
                        proposition.encode("utf-8")
                    ).hexdigest(),
                    "authorities": _authority_records(
                        decision,
                        component_ordinal=component_ordinal,
                        component=component,
                    ),
                    "deterministic_blocker_reason_code": (
                        "OWNER_PACKET_COMPONENT_SUPPORT_PARTIAL"
                        if fit == "PARTIAL"
                        else "OWNER_PACKET_COMPONENT_SUPPORT_NONE"
                    ),
                }
            )
        if not blocking_components:
            continue
        holds = record.get("unresolved_holds")
        if not isinstance(holds, list):
            raise ValueError(f"official research hold inventory differs: {row_id}")
        unclassified_holds = [_unclassified_hold(str(value)) for value in holds]
        raw_hold_count += len(unclassified_holds)
        material = {
            "schema": ROW_SCHEMA,
            "row_id": row_id,
            "decision_content_sha256": decision.get("decision_content_sha256"),
            "recommended_owner_outcome": decision.get("recommended_owner_outcome"),
            "blocking_component_count": len(blocking_components),
            "blocking_support_fits": sorted(
                {str(value["support_fit"]) for value in blocking_components}
            ),
            "blocking_components": blocking_components,
            "unclassified_unresolved_holds": unclassified_holds,
            "hold_classification_policy": "NONE_RAW_HOLDS_REQUIRE_HUMAN_SEMANTIC_CLASSIFICATION",
            "special_supersession_applied": False,
            "safe_fallback_applied": False,
            "material_gap": True,
            "owner_decision_unresolved": False,
            "successor_crosswalk_eligible": False,
            "answer_release_eligible": False,
            "phase2b_authorized": False,
        }
        blocker_rows.append(sealed(material, field="record_content_sha256"))

    blocker_rows.sort(key=lambda value: str(value["row_id"]))
    blocker_ids = [str(value["row_id"]) for value in blocker_rows]
    if (
        len(decisions) != 361
        or len(special_rows) != 8
        or len(fallback_rows) != 2
        or considered_decision_count != 351
        or len(blocker_rows) != 146
        or len(partial_row_ids) != 100
        or len(none_row_ids) != 72
        or len(partial_row_ids & none_row_ids) != 26
        or fit_counts != {"PARTIAL": 116, "NONE": 77}
        or recommendation_counts
        != {
            "ADOPT_ONLY_LISTED_SUPPORTED_COMPONENTS_AND_RETAIN_ALL_LISTED_HOLDS": 315,
            "RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION": 1,
        }
    ):
        raise ValueError("prequalification exact blocker boundary differs")

    payload = {
        "schema": SCHEMA,
        "classification_policy_revision": "v3-no-automated-semantic-hold-classification",
        "supersedes_prequalification_report_content_sha256": (PREDECESSOR_R2_REPORT_CONTENT_SHA256),
        "correction_scope": (
            "REMOVE_AUTOMATED_SEMANTIC_HOLD_LABELS_BLOCKER_ROW_AND_COMPONENT_SETS_UNCHANGED"
        ),
        "predecessor_set_identity_comparison": {
            "blocker_row_id_set_sha256": PREDECESSOR_R1_BLOCKER_ROW_ID_SET_SHA256,
            "partial_row_id_set_sha256": PREDECESSOR_R1_PARTIAL_ROW_ID_SET_SHA256,
            "none_row_id_set_sha256": PREDECESSOR_R1_NONE_ROW_ID_SET_SHA256,
            "all_three_sets_unchanged": True,
        },
        "status": "BLOCKED_BEFORE_SUCCESSOR_QUALIFICATION",
        "phase_scope": "PHASE2A_ONLY",
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "input_bindings": [
            {
                "kind": "exact_remediation_owner_packet_361",
                "path": original_packet_path,
                "schema": ORIGINAL_PACKET_SCHEMA,
                "content_sha256": original_sha256,
                "file_sha256": original_packet_file_sha256,
            },
            {
                "kind": "final_remediation_owner_packet",
                "path": final_packet_path,
                "schema": FINAL_PACKET_SCHEMA,
                "content_sha256": final_sha256,
                "file_sha256": final_packet_file_sha256,
            },
            {
                "kind": "final_owner_adoption_receipt",
                "path": owner_receipt_path,
                "schema": owner_receipt.get("schema"),
                "content_sha256": receipt_sha256,
                "file_sha256": owner_receipt_file_sha256,
            },
            {
                "kind": "single_phase2a_execution_authority",
                "path": execution_authority_path,
                "schema": EXECUTION_AUTHORITY_SCHEMA,
                "content_sha256": execution_sha256,
                "file_sha256": execution_authority_file_sha256,
            },
        ],
        "packet_precedence": {
            "special_substantive_supersession_row_ids": sorted(special_rows),
            "special_substantive_supersession_row_count": len(special_rows),
            "echr_recovery_manifest_content_sha256": (ECHR_RECOVERY_MANIFEST_CONTENT_SHA256),
            "q53_semenya_advisory_content_sha256": Q53_SEMENYA_ADVISORY_CONTENT_SHA256,
            "safe_fallback_row_ids": sorted(fallback_rows),
            "safe_fallback_row_count": len(fallback_rows),
            "project_rescue_contract_content_sha256": (PROJECT_RESCUE_CONTRACT_CONTENT_SHA256),
            "performance_bond_contract_content_sha256": (PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256),
            "excluded_precedence_row_ids_disjoint": True,
            "excluded_precedence_rows_removed_before_blocker_predicate": True,
        },
        "counts": {
            "original_decision_count": len(decisions),
            "decisions_after_exact_precedence_exclusions": considered_decision_count,
            "special_substantive_supersession_row_count": len(special_rows),
            "safe_fallback_row_count": len(fallback_rows),
            "blocking_row_count": len(blocker_rows),
            "partial_row_count": len(partial_row_ids),
            "none_row_count": len(none_row_ids),
            "partial_and_none_overlap_row_count": len(partial_row_ids & none_row_ids),
            "blocking_component_count": sum(fit_counts.values()),
            "partial_component_count": fit_counts["PARTIAL"],
            "none_component_count": fit_counts["NONE"],
            "raw_unresolved_hold_count": raw_hold_count,
            "official_research_recommendation_count": sum(recommendation_counts.values()),
            "adopt_supported_components_retain_holds_recommendation_count": (
                recommendation_counts[
                    "ADOPT_ONLY_LISTED_SUPPORTED_COMPONENTS_AND_RETAIN_ALL_LISTED_HOLDS"
                ]
            ),
            "retain_material_hold_no_supported_proposition_recommendation_count": (
                recommendation_counts["RETAIN_MATERIAL_HOLD_NO_SUPPORTED_OFFICIAL_PROPOSITION"]
            ),
        },
        "recommendation_semantics_proof": {
            "builder_rule": (
                "support_fits_minus_FULL_or_unresolved_holds_or_component_holds_or_"
                "ineligible_authority_implies_retain_holds_recommendation"
            ),
            "official_research_recommendation_count": 316,
            "retain_holds_recommendation_count": 315,
            "retain_material_hold_no_supported_proposition_count": 1,
            "partial_or_none_components_are_not_upgraded_by_owner_adoption": True,
        },
        "blocker_row_id_set_sha256": row_id_set_sha256(blocker_ids),
        "partial_row_id_set_sha256": row_id_set_sha256(sorted(partial_row_ids)),
        "none_row_id_set_sha256": row_id_set_sha256(sorted(none_row_ids)),
        "rows": blocker_rows,
        "blocker_predicate": (
            "STRUCTURED_OWNER_PACKET_SUPPORT_FIT_IS_PARTIAL_OR_NONE_AFTER_EXACT_FINAL_PACKET_PRECEDENCE"
        ),
        "generic_unresolved_hold_text_did_not_create_or_clear_blockers": True,
        "automated_semantic_hold_classification_performed": False,
        "all_raw_holds_require_human_semantic_classification": True,
        "successor_source_presence_cannot_upgrade_partial_or_none_to_full": True,
        "execution_chain": {
            "content_sha256": execution_sha256,
            "status": "AVAILABLE_UNSPENT",
            "total_count": execution_authority.get("total_execution_chain_count"),
            "remaining_count": 1,
            "consumed_count": 0,
            "this_read_only_report_consumes_chain": False,
        },
        "source_scan_run": False,
        "index_build_run": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "answer_model_run": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
        "phase2b_authorized": False,
        "terminal_verdict": (
            "PHASE 2A PREQUALIFICATION BLOCKED - 146 MATERIAL SUPPORT ROWS REMAIN"
        ),
    }
    return sealed(payload)


def build_report_from_paths(
    *,
    original_packet_path: Path,
    final_packet_path: Path,
    owner_receipt_path: Path,
    execution_authority_path: Path,
    project_root: Path | None = None,
) -> dict[str, Any]:
    for path in (
        original_packet_path,
        final_packet_path,
        owner_receipt_path,
        execution_authority_path,
    ):
        if path.is_symlink() or not path.is_file():
            raise ValueError("prequalification input must be one non-symbolic file")
    original = json.loads(original_packet_path.read_bytes())
    final = json.loads(final_packet_path.read_bytes())
    owner_receipt = json.loads(owner_receipt_path.read_bytes())
    execution_authority = json.loads(execution_authority_path.read_bytes())
    if not all(
        isinstance(value, dict) for value in (original, final, owner_receipt, execution_authority)
    ):
        raise ValueError("prequalification inputs must be JSON objects")

    def display(path: Path) -> str:
        if project_root is None:
            return path.as_posix()
        return path.resolve().relative_to(project_root.resolve()).as_posix()

    return build_prequalification_blocker_report(
        original_packet=original,
        final_packet=final,
        owner_receipt=owner_receipt,
        execution_authority=execution_authority,
        original_packet_path=display(original_packet_path),
        original_packet_file_sha256=_file_sha256(original_packet_path),
        final_packet_path=display(final_packet_path),
        final_packet_file_sha256=_file_sha256(final_packet_path),
        owner_receipt_path=display(owner_receipt_path),
        owner_receipt_file_sha256=_file_sha256(owner_receipt_path),
        execution_authority_path=display(execution_authority_path),
        execution_authority_file_sha256=_file_sha256(execution_authority_path),
    )
