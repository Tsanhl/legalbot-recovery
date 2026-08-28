"""Dynamic, fail-closed Phase-2A successor qualification.

This module is deliberately independent of the immutable 2026-08-27 blocked
qualification.  It does not contain a source count, chunk count, corpus ID or
build ID.  Those identities must come from the one receipt-bound successor
scan/build chain and must agree across the owner application ledger, source
catalogue snapshot, sealed candidate and retrieval re-attestation.

The qualification is technical and non-authorizing.  It never invokes a
model, writes an index pointer or makes an answer eligible.  Exactly two rows
may pass via the owner-adopted no-legal-claim fallback contracts; all other
rows require exact owner-adopted technical support.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .live_suite import LiveEvaluationBundle
from .phase2a_safe_fallback_qualification import (
    PERFORMANCE_BOND_ROW_ID,
    qualify_performance_bond_safe_fallback_disposition,
    qualify_safe_fallback_disposition,
)
from .phase2a_safe_fallback_qualification import (
    QUALIFICATION_STATUS as SAFE_FALLBACK_STATUS,
)
from .phase2a_safe_fallback_qualification import (
    ROW_ID as PROJECT_RESCUE_ROW_ID,
)

SCHEMA = "legalbot.v111.phase2a.successor-all585-technical-qualification.v1"
ROW_SCHEMA = "legalbot.v111.phase2a.successor-technical-qualification-row.v1"
APPLICATION_LEDGER_SCHEMA = "legalbot.v111.phase2a.final-owner-decision-application.v1"
OWNER_PACKET_SCHEMA = "legalbot.v111.phase2a.source-delta-safe-fallback-owner-packet.v1"
OWNER_RECEIPT_SCHEMA = "legalbot.v111.phase2a.final-remediation-owner-adoption-receipt.v1"
CANDIDATE_BINDING_SCHEMA = "legalbot.v111.phase2a.successor-candidate-binding.v1"
RETRIEVAL_REATTESTATION_SCHEMA = "legalbot.v111.phase2a.successor-retrieval-reattestation.v1"
CATALOGUE_SNAPSHOT_SCHEMA = "legalbot.v111.phase2a.successor-source-catalogue-snapshot.v1"

FINAL_OWNER_PACKET_CONTENT_SHA256 = (
    "fd8034b33ebfb0f6fdd6cedd2426b54e368bff9c20b408f3fbd86fb40b9f1b34"
)
FINAL_OWNER_RECEIPT_CONTENT_SHA256 = (
    "9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa"
)
ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)
EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
PROJECT_RESCUE_CONTRACT_CONTENT_SHA256 = (
    "ba6c131f06e05bed9f6b6aa5743dc974f3b13618e3af39ffcaaabaf0f84c72f6"
)
PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256 = (
    "91cbb05fad64d2e26d11e75ff8adbe1b1b9d7fc300abea6785630078e5d2036e"
)
FALLBACK_COVERAGE_ADVISORY_CONTENT_SHA256 = (
    "035316cac6f9559744400bc9db7c05bdf74a85c7d120c59eae5cfc41f0462af8"
)
HELD9_ADVISORY_CONTENT_SHA256 = "599d7175005c8978757611be0ce837299845c142147ec02828f53ee7620e75fd"
ECHR_RECOVERY_MANIFEST_CONTENT_SHA256 = (
    "f5beba682a629d3a6e0e79be374c0d2a3d6690d45abe467fa40f67879dcb0142"
)
Q53_SEMENYA_ADVISORY_CONTENT_SHA256 = (
    "fea6a74301ba629c03a1813dbc45d83ee030c25d0c53194c0129fd4515adb814"
)

TECHNICAL_PASS_STATUS = "PASS_OWNER_ADOPTED_TECHNICAL_SUPPORT"
FAIL_STATUS = "FAIL_PHASE2A_TECHNICAL_QUALIFICATION"
FALLBACK_ROW_IDS = frozenset({PERFORMANCE_BOND_ROW_ID, PROJECT_RESCUE_ROW_ID})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# These are content identities, not loose title matches.  Each affected row's
# applied ledger entry must carry the relevant identity set.  Additional exact
# support identities are permitted, but none of these may be absent.
KLIMA_RECORD_CONTENT_SHA256 = "b9cc4b3c3d5566bec4f62c374d257d6d286fcd5681bc67d6ec0d810c3903871f"
BIG_BROTHER_RECORD_CONTENT_SHA256 = (
    "201c6c8a088b48eccbe08d527bec182350ca24695496c97170349ca1039cc20d"
)
GOODWIN_RECORD_CONTENT_SHA256 = "be390e6a0f1def7c073f0fae329b56d3e7c4e6acf7610ce6fffef8d15b7da145"
SEMENYA_RECORD_CONTENT_SHA256 = "3ff2126597a311845a212fcb1966cf4b1d5947c46880b2955bf64c9fb51b2160"
CAS_BINDING_CONTENT_SHA256 = "be886d6598acdbbb5c1b32b1fb248cd15543c5ca99cca77304074330f97ddc52"
ARBITRATION_ACT_CONTENT_SHA256 = "2d395c8b88c15104758839b7e586816c67b344fda9def5e091384d4cb1a96eea"

SPECIAL_SUPPORT_IDENTITIES: dict[str, frozenset[str]] = {
    "live30-q22:issue-02": frozenset(
        {ECHR_RECOVERY_MANIFEST_CONTENT_SHA256, KLIMA_RECORD_CONTENT_SHA256}
    ),
    "live30-q22:issue-04": frozenset(
        {ECHR_RECOVERY_MANIFEST_CONTENT_SHA256, KLIMA_RECORD_CONTENT_SHA256}
    ),
    "live30-q22:issue-06": frozenset(
        {ECHR_RECOVERY_MANIFEST_CONTENT_SHA256, KLIMA_RECORD_CONTENT_SHA256}
    ),
    "live60-q51:issue-05": frozenset(
        {ECHR_RECOVERY_MANIFEST_CONTENT_SHA256, GOODWIN_RECORD_CONTENT_SHA256}
    ),
    "live60-q53:issue-04": frozenset(
        {
            Q53_SEMENYA_ADVISORY_CONTENT_SHA256,
            SEMENYA_RECORD_CONTENT_SHA256,
            CAS_BINDING_CONTENT_SHA256,
            ARBITRATION_ACT_CONTENT_SHA256,
        }
    ),
    "live60-q53:issue-11": frozenset(
        {
            Q53_SEMENYA_ADVISORY_CONTENT_SHA256,
            SEMENYA_RECORD_CONTENT_SHA256,
            CAS_BINDING_CONTENT_SHA256,
            ARBITRATION_ACT_CONTENT_SHA256,
        }
    ),
    "live60-q56:issue-01": frozenset(
        {ECHR_RECOVERY_MANIFEST_CONTENT_SHA256, BIG_BROTHER_RECORD_CONTENT_SHA256}
    ),
    "live60-q56:issue-05": frozenset(
        {ECHR_RECOVERY_MANIFEST_CONTENT_SHA256, BIG_BROTHER_RECORD_CONTENT_SHA256}
    ),
}


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def sealed(value: Mapping[str, Any], *, field: str = "artifact_content_sha256") -> dict[str, Any]:
    payload = dict(value)
    payload.pop(field, None)
    payload[field] = content_sha256(payload)
    return payload


def require_seal(
    value: Mapping[str, Any],
    *,
    field: str = "artifact_content_sha256",
    label: str,
) -> str:
    observed = str(value.get(field) or "")
    material = dict(value)
    material.pop(field, None)
    expected = content_sha256(material)
    if not _SHA256.fullmatch(observed) or observed != expected:
        raise ValueError(f"{label} content seal is invalid")
    return observed


def source_version_id_set_sha256(source_version_ids: Sequence[str]) -> str:
    values = sorted(str(value) for value in source_version_ids)
    if not values or len(values) != len(set(values)) or any(not value for value in values):
        raise ValueError("source-version identity set is empty or duplicated")
    return content_sha256(
        {
            "schema": "legalbot.v111.phase2a.source-version-id-set.v1",
            "source_version_ids": values,
        }
    )


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
        raise ValueError("Phase-2A qualification registry is not exactly 60/585")
    return rows


def validate_owner_packet(packet: Mapping[str, Any]) -> str:
    digest = require_seal(packet, label="final owner packet")
    coverage = packet.get("fact_only_fallback_coverage_advisory")
    recovery = packet.get("echr_held_source_recovery")
    q53 = packet.get("q53_semenya_substitute_advisory")
    authority = packet.get("single_remaining_phase2a_execution_authority")
    project_rescue = packet.get("safe_fallback_decision")
    performance_bond = packet.get("performance_bond_safe_fallback_decision")
    if (
        packet.get("schema") != OWNER_PACKET_SCHEMA
        or digest != FINAL_OWNER_PACKET_CONTENT_SHA256
        or not isinstance(coverage, Mapping)
        or coverage.get("content_sha256") != FALLBACK_COVERAGE_ADVISORY_CONTENT_SHA256
        or coverage.get("exact_eligible_row_ids")
        != [PERFORMANCE_BOND_ROW_ID, PROJECT_RESCUE_ROW_ID]
        or coverage.get("remaining_583_rows_not_safe_fallback_eligible") is not True
        or not isinstance(recovery, Mapping)
        or recovery.get("manifest_content_sha256") != ECHR_RECOVERY_MANIFEST_CONTENT_SHA256
        or recovery.get("no_more_mutu_network_attempts") is not True
        or not isinstance(q53, Mapping)
        or q53.get("content_sha256") != Q53_SEMENYA_ADVISORY_CONTENT_SHA256
        or q53.get("mutu_historical_claims_explicitly_excluded") is not True
        or q53.get("mutu_network_path_permanently_stopped") is not True
        or q53.get("semenya_not_described_as_disciplinary") is not True
        or not isinstance(project_rescue, Mapping)
        or project_rescue.get("canonical_contract_content_sha256")
        != PROJECT_RESCUE_CONTRACT_CONTENT_SHA256
        or not isinstance(performance_bond, Mapping)
        or performance_bond.get("canonical_contract_content_sha256")
        != PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256
        or not isinstance(authority, Mapping)
        or authority.get("total_remaining_execution_chain_count") != 1
        or authority.get("successor_must_remain_non_active") is not True
        or authority.get("successor_must_remain_answer_ineligible") is not True
        or packet.get("phase2b_authorized") is not False
        or packet.get("answer_release_authorized") is not False
        or packet.get("active_pointer_write_authorized") is not False
        or packet.get("previous_pointer_write_authorized") is not False
    ):
        raise ValueError("final owner packet contract differs")
    return digest


def validate_owner_receipt(receipt: Mapping[str, Any]) -> str:
    digest = require_seal(receipt, label="final owner-adoption receipt")
    allowed_true = (
        "owner_adoption_recorded",
        "owner_approved",
        "owner_decision_application_authorized",
        "source_admission_authorized",
        "complete_source_scan_authorized",
        "successor_build_authorized",
        "embedding_authorized",
        "retrieval_reattestation_authorized",
        "qualification_authorized",
        "all585_qualification_authorized",
    )
    required_false = (
        "answer_model_authorized",
        "answer_release_authorized",
        "phase2b_authorized",
        "development30_authorized",
        "validation30_authorized",
        "validation30_unsealed",
        "owner_certification60_authorized",
        "promotion_authorized",
        "active_pointer_write_authorized",
        "previous_pointer_write_authorized",
        "live_activation_authorized",
        "training_export_authorized",
        "technical_success_predeclared",
    )
    if (
        receipt.get("schema") != OWNER_RECEIPT_SCHEMA
        or digest != FINAL_OWNER_RECEIPT_CONTENT_SHA256
        or receipt.get("final_owner_packet_content_sha256") != FINAL_OWNER_PACKET_CONTENT_SHA256
        or receipt.get("original_owner_receipt_content_sha256")
        != ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or receipt.get("execution_authority_content_sha256") != EXECUTION_AUTHORITY_CONTENT_SHA256
        or receipt.get("owner_decision_date") != "2026-08-28"
        or receipt.get("execution_chain_count") != 1
        or receipt.get("execution_chain_remaining_count") != 1
        or receipt.get("execution_chain_consumed_count") != 0
        or receipt.get("execution_chain_status") != "AVAILABLE_UNSPENT"
        or any(receipt.get(field) is not True for field in allowed_true)
        or any(receipt.get(field) is not False for field in required_false)
    ):
        raise ValueError("final owner-adoption receipt contract differs")
    return digest


def _row_map(value: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = value.get("rows")
    if not isinstance(rows, list):
        raise ValueError("owner application ledger has no row list")
    output: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("owner application ledger has an invalid row")
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in output:
            raise ValueError("owner application ledger row identity is missing or duplicated")
        require_seal(row, field="record_content_sha256", label=f"application row {row_id}")
        output[row_id] = row
    return output


def validate_application_ledger(
    *,
    bundle: LiveEvaluationBundle,
    ledger: Mapping[str, Any],
) -> tuple[str, dict[str, Mapping[str, Any]]]:
    digest = require_seal(ledger, label="owner application ledger")
    registry = _registry_rows(bundle)
    registry_ids = {str(row["row_id"]) for row in registry}
    rows = _row_map(ledger)
    if (
        ledger.get("schema") != APPLICATION_LEDGER_SCHEMA
        or ledger.get("final_owner_packet_content_sha256") != FINAL_OWNER_PACKET_CONTENT_SHA256
        or ledger.get("final_owner_approval_receipt_content_sha256")
        != FINAL_OWNER_RECEIPT_CONTENT_SHA256
        or ledger.get("original_owner_receipt_content_sha256")
        != ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or ledger.get("decision_application_complete") is not True
        or ledger.get("source_materialization_complete") is not True
        or ledger.get("owner_decision_count") != 361
        or ledger.get("prior_technically_ready_row_count") != 224
        or ledger.get("row_count") != 585
        or ledger.get("regular_support_row_count") != 583
        or ledger.get("safe_fallback_row_count") != 2
        or ledger.get("unresolved_owner_decision_count") != 0
        or ledger.get("material_gap_count") != 0
        or set(rows) != registry_ids
    ):
        raise ValueError("owner application ledger boundary differs")

    observed_fallback: set[str] = set()
    for registry_row in registry:
        row_id = str(registry_row["row_id"])
        row = rows[row_id]
        if (
            row.get("ordinal") != registry_row["ordinal"]
            or row.get("owner_decision_resolved") is not True
            or row.get("material_gap") is not False
            or row.get("unresolved_hold_codes") not in ([], ())
        ):
            raise ValueError(f"Phase-2A row remains unresolved: {row_id}")
        support = row.get("support_identity_sha256s")
        if not isinstance(support, list) or any(
            not isinstance(item, str) or not _SHA256.fullmatch(item) for item in support
        ):
            raise ValueError(f"Phase-2A row support identity list is invalid: {row_id}")
        if len(support) != len(set(support)):
            raise ValueError(f"Phase-2A row support identity list is duplicated: {row_id}")
        if row_id in FALLBACK_ROW_IDS:
            observed_fallback.add(row_id)
            if (
                row.get("resolution_class") != "OWNER_ADOPTED_SAFE_FALLBACK"
                or row.get("technical_support_complete") is not False
                or row.get("safe_fallback_contract_complete") is not True
                or support
                or not isinstance(row.get("safe_fallback_disposition"), Mapping)
            ):
                raise ValueError(f"safe-fallback application row differs: {row_id}")
        else:
            if (
                row.get("resolution_class") != "OWNER_ADOPTED_EXACT_TECHNICAL_SUPPORT"
                or row.get("technical_support_complete") is not True
                or row.get("safe_fallback_contract_complete") is not False
                or not support
                or row.get("safe_fallback_disposition") is not None
            ):
                raise ValueError(f"exact-support application row differs: {row_id}")
            required = SPECIAL_SUPPORT_IDENTITIES.get(row_id, frozenset())
            if not required.issubset(set(support)):
                raise ValueError(f"special owner-adopted support set is incomplete: {row_id}")
    if observed_fallback != FALLBACK_ROW_IDS:
        raise ValueError("exactly two owner-adopted safe-fallback rows are required")
    return digest, rows


def validate_catalogue_snapshot(
    snapshot: Mapping[str, Any],
    *,
    application_ledger_content_sha256: str,
) -> str:
    digest = require_seal(snapshot, label="source catalogue snapshot")
    source_ids = snapshot.get("source_version_ids")
    if not isinstance(source_ids, list):
        raise ValueError("source catalogue snapshot has no source-version inventory")
    expected_set = source_version_id_set_sha256([str(value) for value in source_ids])
    if (
        snapshot.get("schema") != CATALOGUE_SNAPSHOT_SCHEMA
        or snapshot.get("final_owner_packet_content_sha256") != FINAL_OWNER_PACKET_CONTENT_SHA256
        or snapshot.get("final_owner_approval_receipt_content_sha256")
        != FINAL_OWNER_RECEIPT_CONTENT_SHA256
        or snapshot.get("owner_application_ledger_content_sha256")
        != application_ledger_content_sha256
        or snapshot.get("source_version_id_set_sha256") != expected_set
        or snapshot.get("source_count") != len(source_ids)
        or int(snapshot.get("source_count") or 0) < 1
        or int(snapshot.get("chunk_count") or 0) < 1
        or snapshot.get("approved_source_count") != len(source_ids)
        or snapshot.get("unresolved_owner_decision_count") != 0
        or snapshot.get("material_gap_count") != 0
        or snapshot.get("source_scan_status") != "complete"
        or not _SHA256.fullmatch(str(snapshot.get("source_scan_manifest_sha256") or ""))
    ):
        raise ValueError("source catalogue snapshot boundary differs")
    return digest


def _validate_candidate_binding(
    candidate: Mapping[str, Any],
    *,
    application_ledger_content_sha256: str,
    catalogue_snapshot_content_sha256: str,
) -> str:
    digest = require_seal(candidate, label="successor candidate binding")
    if (
        candidate.get("schema") != CANDIDATE_BINDING_SCHEMA
        or not str(candidate.get("build_id") or "")
        or candidate.get("build_status") != "built_unscored"
        or candidate.get("build_stage") != "built_unscored"
        or int(candidate.get("source_count") or 0) < 1
        or int(candidate.get("chunk_count") or 0) < 1
        or candidate.get("chunk_count") != candidate.get("vector_count")
        or candidate.get("final_owner_packet_content_sha256") != FINAL_OWNER_PACKET_CONTENT_SHA256
        or candidate.get("final_owner_approval_receipt_content_sha256")
        != FINAL_OWNER_RECEIPT_CONTENT_SHA256
        or candidate.get("owner_application_ledger_content_sha256")
        != application_ledger_content_sha256
        or candidate.get("source_catalogue_snapshot_content_sha256")
        != catalogue_snapshot_content_sha256
        or candidate.get("answer_release_eligible") is not False
        or candidate.get("successor_must_remain_non_active") is not True
        or candidate.get("active_pointer_absent") is not True
        or candidate.get("previous_pointer_absent") is not True
        or candidate.get("phase2b_authorized") is not False
        or candidate.get("promotion_authorized") is not False
    ):
        raise ValueError("successor candidate binding differs")
    for field in (
        "candidate_manifest_file_sha256",
        "candidate_seal_file_sha256",
        "source_manifest_sha256",
        "source_manifest_file_sha256",
        "source_scan_manifest_sha256",
        "source_version_id_set_sha256",
        "catalogue_row_sha256",
    ):
        if not _SHA256.fullmatch(str(candidate.get(field) or "")):
            raise ValueError(f"successor candidate lacks a valid {field}")
    return digest


def _validate_retrieval_reattestation(
    reattestation: Mapping[str, Any],
    *,
    candidate_binding_content_sha256: str,
    candidate: Mapping[str, Any],
) -> str:
    digest = require_seal(reattestation, label="successor retrieval re-attestation")
    metrics = reattestation.get("metrics")
    if (
        reattestation.get("schema") != RETRIEVAL_REATTESTATION_SCHEMA
        or reattestation.get("build_id") != candidate.get("build_id")
        or reattestation.get("candidate_binding_content_sha256") != candidate_binding_content_sha256
        or reattestation.get("source_manifest_sha256") != candidate.get("source_manifest_sha256")
        or reattestation.get("source_scan_manifest_sha256")
        != candidate.get("source_scan_manifest_sha256")
        or reattestation.get("retrieval_quality_passed") is not True
        or reattestation.get("candidate_status_written") is not False
        or reattestation.get("catalogue_written") is not False
        or reattestation.get("active_pointer_written") is not False
        or reattestation.get("previous_pointer_written") is not False
        or reattestation.get("active_pointer_absent_before_and_after") is not True
        or reattestation.get("previous_pointer_absent_before_and_after") is not True
        or reattestation.get("answer_model_invoked") is not False
        or reattestation.get("promotion_eligible") is not False
        or reattestation.get("answer_release_eligible") is not False
        or reattestation.get("phase2b_authorized") is not False
        or not isinstance(metrics, Mapping)
        or metrics.get("query_count") != 24
        or metrics.get("binding_count") != 24
        or float(metrics.get("positive_recall_at_5") or 0.0) != 1.0
        or float(metrics.get("positive_recall_at_10") or 0.0) < 0.95
        or float(metrics.get("mrr") or 0.0) < 0.80
        or int(metrics.get("teaching_assessment_hits") or 0) != 0
        or int(metrics.get("private_path_hits") or 0) != 0
        or int(metrics.get("wrong_version_count") or 0) != 0
    ):
        raise ValueError("successor retrieval re-attestation differs or failed")
    return digest


def build_successor_all585_qualification(
    *,
    bundle: LiveEvaluationBundle,
    owner_packet: Mapping[str, Any],
    owner_receipt: Mapping[str, Any],
    application_ledger: Mapping[str, Any],
    catalogue_snapshot: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    retrieval_reattestation: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the successful technical result or fail before writing an artefact."""

    packet_sha256 = validate_owner_packet(owner_packet)
    receipt_sha256 = validate_owner_receipt(owner_receipt)
    ledger_sha256, applied_rows = validate_application_ledger(
        bundle=bundle,
        ledger=application_ledger,
    )
    catalogue_sha256 = validate_catalogue_snapshot(
        catalogue_snapshot,
        application_ledger_content_sha256=ledger_sha256,
    )
    candidate_sha256 = _validate_candidate_binding(
        candidate_binding,
        application_ledger_content_sha256=ledger_sha256,
        catalogue_snapshot_content_sha256=catalogue_sha256,
    )
    retrieval_sha256 = _validate_retrieval_reattestation(
        retrieval_reattestation,
        candidate_binding_content_sha256=candidate_sha256,
        candidate=candidate_binding,
    )

    registry = _registry_rows(bundle)
    qualification_rows: list[dict[str, Any]] = []
    for registry_row in registry:
        row_id = str(registry_row["row_id"])
        applied = applied_rows[row_id]
        if row_id == PROJECT_RESCUE_ROW_ID:
            fallback = qualify_safe_fallback_disposition(
                bundle=bundle,
                disposition=applied["safe_fallback_disposition"],
                expected_owner_adoption_packet_content_sha256=packet_sha256,
            )
            status = str(fallback["qualification_status"])
            basis = {
                "basis_class": fallback["basis"]["basis_class"],
                "contract_content_sha256": PROJECT_RESCUE_CONTRACT_CONTENT_SHA256,
                "application_row_content_sha256": applied["record_content_sha256"],
                "safe_fallback_record_content_sha256": fallback["record_content_sha256"],
            }
        elif row_id == PERFORMANCE_BOND_ROW_ID:
            fallback = qualify_performance_bond_safe_fallback_disposition(
                bundle=bundle,
                disposition=applied["safe_fallback_disposition"],
                expected_owner_adoption_packet_content_sha256=packet_sha256,
            )
            status = str(fallback["qualification_status"])
            basis = {
                "basis_class": fallback["basis"]["basis_class"],
                "contract_content_sha256": PERFORMANCE_BOND_CONTRACT_CONTENT_SHA256,
                "application_row_content_sha256": applied["record_content_sha256"],
                "safe_fallback_record_content_sha256": fallback["record_content_sha256"],
            }
        else:
            status = TECHNICAL_PASS_STATUS
            basis = {
                "basis_class": "OWNER_ADOPTED_EXACT_TECHNICAL_SUPPORT",
                "application_row_content_sha256": applied["record_content_sha256"],
                "support_identity_sha256s": list(applied["support_identity_sha256s"]),
                "retained_release_hold_codes": list(
                    applied.get("retained_release_hold_codes") or []
                ),
            }
        row_payload = {
            "schema": ROW_SCHEMA,
            **registry_row,
            "qualification_status": status,
            "basis": basis,
            "candidate_build_id": candidate_binding["build_id"],
            "candidate_binding_content_sha256": candidate_sha256,
            "retrieval_reattestation_content_sha256": retrieval_sha256,
            "owner_decision_resolved": True,
            "material_gap": False,
            "answer_release_eligible": False,
            "phase2b_authorized": False,
        }
        qualification_rows.append(sealed(row_payload, field="record_content_sha256"))

    counts = Counter(row["qualification_status"] for row in qualification_rows)
    if counts != {TECHNICAL_PASS_STATUS: 583, SAFE_FALLBACK_STATUS: 2}:
        raise ValueError("Phase-2A successor did not produce exactly 583+2 passing rows")
    cases: list[dict[str, Any]] = []
    offset = 0
    for case in bundle.registry.cases:
        size = len(case.must_cover_issues)
        rows = qualification_rows[offset : offset + size]
        offset += size
        cases.append(
            {
                "case_id": case.case_id,
                "issue_count": size,
                "all_issues_technically_passed": all(
                    row["qualification_status"] in {TECHNICAL_PASS_STATUS, SAFE_FALLBACK_STATUS}
                    for row in rows
                ),
            }
        )
    if (
        offset != 585
        or len(cases) != 60
        or not all(case["all_issues_technically_passed"] for case in cases)
    ):
        raise ValueError("Phase-2A case aggregation is incomplete")

    payload = {
        "schema": SCHEMA,
        "phase_scope": "PHASE2A_ONLY",
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "case_count": 60,
        "issue_count": 585,
        "rows": qualification_rows,
        "cases": cases,
        "status_counts": dict(sorted(counts.items())),
        "unresolved_owner_decision_count": 0,
        "material_gap_count": 0,
        "safe_fallback_row_ids": sorted(FALLBACK_ROW_IDS),
        "owner_packet_content_sha256": packet_sha256,
        "owner_approval_receipt_content_sha256": receipt_sha256,
        "owner_application_ledger_content_sha256": ledger_sha256,
        "source_catalogue_snapshot_content_sha256": catalogue_sha256,
        "candidate_binding_content_sha256": candidate_sha256,
        "candidate_build_id": candidate_binding["build_id"],
        "source_count": candidate_binding["source_count"],
        "chunk_count": candidate_binding["chunk_count"],
        "vector_count": candidate_binding["vector_count"],
        "source_scan_id": candidate_binding["source_scan_id"],
        "source_scan_manifest_sha256": candidate_binding["source_scan_manifest_sha256"],
        "source_manifest_sha256": candidate_binding["source_manifest_sha256"],
        "retrieval_reattestation_content_sha256": retrieval_sha256,
        "phase2a_technical_qualification_passed": True,
        "successful_phase2a_package_not_yet_adopted": True,
        "successor_non_active": True,
        "answer_release_eligible": False,
        "phase2b_eligible": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "promotion_authorized": False,
        "answer_model_invoked": False,
        "planner_or_advisory_model_invoked": False,
        "candidate_mutated_by_qualification": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
        "active_pointer_absent": True,
        "previous_pointer_absent": True,
        "terminal_verdict": "PHASE 2A TECHNICAL QUALIFICATION PASSED - NON-ACTIVE",
    }
    return sealed(payload)
