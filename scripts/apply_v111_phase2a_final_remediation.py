#!/usr/bin/env python3
"""Apply the exact final Phase-2A owner decisions, fail closed.

``materialize`` copies only the exact adopted representations into an additive
subdirectory of the existing approved Phase-2A source root and seals a ledger.
``finalize-post-scan`` is the only catalogue mutation: after the one authorized
complete scan, it binds exact scanned source versions to the owner ledger in a
single transaction.  Neither command builds, embeds, qualifies, invokes a
model, writes ACTIVE/PREVIOUS, or starts Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.retrieval import phase2a_dynamic_scope

from scripts import build_v111_phase2a_safe_fallback_superseding_owner_packet as packet_builder
from scripts import record_v111_phase2a_exact_remediation_owner_adoption as original_adoption
from scripts import record_v111_phase2a_final_remediation_owner_adoption as final_adoption

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
SOURCE_ROOT = PROJECT_ROOT / "sources/phase2a-approved-2026-08-27"
MATERIALIZED_SUBDIR_NAME = "final-remediation-2026-08-28-r1"
MATERIALIZED_ROOT = SOURCE_ROOT / MATERIALIZED_SUBDIR_NAME
MATERIALIZATION_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-final-remediation-materialized-r1"
)
POST_SCAN_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-final-remediation-owner-applied-r1"
)
CATALOGUE_PATH = PROJECT_ROOT / "data/catalog.sqlite3"

SOURCE_DELTA_ROOT = packet_builder.SOURCE_DELTA_ROOT
FCA_ROOT = packet_builder.FCA_DERIVATION_ROOT
ECHR_R3_ROOT = packet_builder.ECHR_RECOVERY_ROOT
ECHR_R2_ROOT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-echr-held-source-recovery-quarantine-r2"
SEMENYA_ROOT = packet_builder.Q53_SUBSTITUTE_ROOT
ORIGINAL_PACKET_ROOT = original_adoption.DEFAULT_PACKET_ROOT
ORIGINAL_QUARANTINE_ROOT = original_adoption.DEFAULT_QUARANTINE_ROOT
FINAL_APPROVAL_ROOT = final_adoption.DEFAULT_OUTPUT_ROOT
PRIOR_SCOPE_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-consolidated-source-admission"
    / "FROZEN-SUCCESSOR-SOURCE-SCOPE.json"
)

MATERIALIZATION_LEDGER_NAME = "MATERIALIZATION-LEDGER.json"
MATERIALIZATION_PLAN_NAME = "MATERIALIZATION-PLAN.json"
OWNER_APPLICATION_LEDGER_NAME = "OWNER-APPLICATION-LEDGER.json"
PRESTATE_NAME = "CATALOGUE-PRESTATE.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

EXPECTED_FINAL_PACKET_CONTENT_SHA256 = final_adoption.EXPECTED_PACKET_CONTENT_SHA256
EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256 = (
    "9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa"
)
EXPECTED_FINAL_APPROVAL_RECEIPT_FILE_SHA256 = (
    "dcf5f5f33debcbecff17552e074a9c12437d7b8cd77d0879c7d19072156c3383"
)
EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXPECTED_EXECUTION_AUTHORITY_FILE_SHA256 = (
    "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad"
)
EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)
EXPECTED_SOURCE_DELTA_CONTENT_SHA256 = packet_builder.EXPECTED_SOURCE_DELTA_CONTENT_SHA256
EXPECTED_FCA_MANIFEST_CONTENT_SHA256 = (
    packet_builder.EXPECTED_FCA_DERIVATION_MANIFEST_CONTENT_SHA256
)
EXPECTED_ECHR_R3_MANIFEST_CONTENT_SHA256 = (
    packet_builder.EXPECTED_ECHR_RECOVERY_MANIFEST_CONTENT_SHA256
)
EXPECTED_SEMENYA_ADVISORY_CONTENT_SHA256 = (
    packet_builder.EXPECTED_Q53_SUBSTITUTE_ADVISORY_CONTENT_SHA256
)
EXPECTED_ECHR_R2_MANIFEST_CONTENT_SHA256 = (
    "c6672a3f227b9a518ac628861bc1bcaf361d9c29968f20c490f27d3f34592145"
)
EXPECTED_ECHR_R2_MANIFEST_FILE_SHA256 = (
    "e7f23bbe8219370f24ae86e3dab7356bab6ad90fc8a405c92ee1b06f8bd74879"
)
EXPECTED_ECHR_R2_PACKAGE_CONTENT_SHA256 = (
    "d96ca9dd0a0183845d772f255c6d9945cefc5accb9ac56c12f200452c43170ec"
)
EXPECTED_ECHR_R2_PACKAGE_FILE_SHA256 = (
    "c1a72e54d730f9c7a01d43f64baefe349d57f7af37cb36d4ce32a25e77866a72"
)
EXPECTED_GOODWIN_CANONICAL_SHA256 = (
    "01e772d4fbdf84fc1c24f8378d88b798f4cd64da558d1ba38fcfce28f6014abb"
)
EXPECTED_PRIOR_SCOPE_CONTENT_SHA256 = (
    "9c7ee397441eccd00a3b909dc2bdeb6d01d7baf9710bddb966f9d4a04882d84d"
)
EXPECTED_PRIOR_SCOPE_COUNT = 251
EXPECTED_MATERIALIZED_REPRESENTATION_COUNT = 254
EXPECTED_INDEX_REPRESENTATION_COUNT = 250
EXPECTED_PROVENANCE_COMPANION_COUNT = 4
EXPECTED_FINAL_SUCCESSOR_SOURCE_COUNT = 501
EXPECTED_PRIOR_QUALIFICATION_CONTENT_SHA256 = (
    "89b9249618d6c8d7bc64b9eb484c3498975cc0729a598e52c0a7fbc6be2e7db5"
)
EXPECTED_PRIOR_QUALIFICATION_FILE_SHA256 = (
    "4170aa192181c7b9a368af01cf4f813eb6b3417c0c57c58bb7b4f03257727df8"
)
EXPECTED_CONSOLIDATED_MATRIX_CONTENT_SHA256 = (
    "49be0ac00ce72ec4a73c4387d5eef7934f3e72b63f8e80d2947397537cf44e18"
)
EXPECTED_CONSOLIDATED_MATRIX_FILE_SHA256 = (
    "3fcc5a695d86f6bf6e252b6edbd226a32f0aece2401efe0df3fff8e0bb809942"
)
EXPECTED_R95_BINDINGS_CONTENT_SHA256 = (
    "425fd6b41fd80e021df682aab2cbd7b33238d67ababc223a35ec26d5df961a4a"
)
EXPECTED_R95_BINDINGS_FILE_SHA256 = (
    "bebd53fab9f4e9b39abe6ac9a9d582e6d218bd58eefc4bd0bd00c74915ea5042"
)
EXPECTED_PRESERVED_CROSSWALK_CONTENT_SHA256 = (
    "4a65ebcaf0673077cac27f0aa68c8436d46cf513ddab5ac5f630e9b9187433c1"
)
EXPECTED_PRESERVED_CROSSWALK_FILE_SHA256 = (
    "405ebe4d45cdac7600fac9ed57e72a9c97ec2b80402842784e0cd53a8ca55036"
)
EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256 = (
    "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"
)
EXPECTED_ORIGINAL_PACKET_FILE_SHA256 = (
    "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
)
EXPECTED_PRIOR224_ROW_SET_SHA256 = (
    "02feb0f4dcace8e9e43eca96a6920e52a40028652f64fbb211f069844efd3868"
)
EXPECTED_REMEDIATION361_ROW_SET_SHA256 = (
    "1637461e79ebe738308d9a663de9f0c130f1b80589650928e8618d44c8105894"
)
EXPECTED_ALL585_ROW_SET_SHA256 = "0911acf8e441599d289c8ffb552955a2431ebdda25585022970202ea014194d9"
FALLBACK_ROW_CONTRACTS = {
    "live60-q58:issue-09": ("91cbb05fad64d2e26d11e75ff8adbe1b1b9d7fc300abea6785630078e5d2036e"),
    "live60-q58:issue-14": ("ba6c131f06e05bed9f6b6aa5743dc974f3b13618e3af39ffcaaabaf0f84c72f6"),
}
EXPECTED_FALLBACK_ADVISORY_CONTENT_SHA256 = (
    "035316cac6f9559744400bc9db7c05bdf74a85c7d120c59eae5cfc41f0462af8"
)

PRIOR_QUALIFICATION_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-deterministic-all585-qualification"
    / "DETERMINISTIC-ALL585-QUALIFICATION.json"
)
CONSOLIDATED_MATRIX_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
    / "COMPLETE-REMEDIATION-MATRIX-585.json"
)
R95_BINDINGS_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved"
    / "APPROVED-CANDIDATE-BINDINGS-84.json"
)
PRESERVED_CROSSWALK_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-deterministic-exact-span-crosswalk-r2"
    / "DETERMINISTIC-EXACT-SPAN-PACKETS-364.json"
)
ORIGINAL_PACKET_PATH = ORIGINAL_PACKET_ROOT / "EXACT-REMEDIATION-OWNER-PACKET-361.json"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,220}$")
_NO_LATER_EXECUTION = {
    "source_scan_run": False,
    "successor_build_run": False,
    "index_built": False,
    "embedding_run": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_run": False,
    "answer_model_run": False,
    "answer_released": False,
    "phase2b_run": False,
    "development30_run": False,
    "validation30_run": False,
    "promotion_run": False,
    "active_pointer_written": False,
    "previous_pointer_written": False,
    "live_activation_run": False,
    "training_export_run": False,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json(value))


def _seal_record(value: Mapping[str, Any], field: str = "record_content_sha256") -> dict[str, Any]:
    material = dict(value)
    return {**material, field: _sealed(material)}


def _verify_seal(value: Mapping[str, Any], field: str, *, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if _SHA256.fullmatch(supplied) is None or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _load_object(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _require_file(path: Path, digest: str, *, code: str) -> None:
    if path.is_symlink() or not path.is_file() or _sha256_file(path) != digest:
        raise ValueError(code)


def _verify_final_approval() -> tuple[dict[str, Any], dict[str, Any]]:
    receipt_path = FINAL_APPROVAL_ROOT / final_adoption.RECEIPT_NAME
    authority_path = FINAL_APPROVAL_ROOT / final_adoption.AUTHORITY_STATE_NAME
    _require_file(
        receipt_path,
        EXPECTED_FINAL_APPROVAL_RECEIPT_FILE_SHA256,
        code="phase2a_final_apply_owner_receipt_file_invalid",
    )
    _require_file(
        authority_path,
        EXPECTED_EXECUTION_AUTHORITY_FILE_SHA256,
        code="phase2a_final_apply_execution_authority_file_invalid",
    )
    receipt = _load_object(receipt_path, code="phase2a_final_apply_owner_receipt_invalid")
    authority = _load_object(authority_path, code="phase2a_final_apply_execution_authority_invalid")
    if (
        _verify_seal(
            receipt,
            "artifact_content_sha256",
            code="phase2a_final_apply_owner_receipt_seal_invalid",
        )
        != EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
        or _verify_seal(
            authority,
            "artifact_content_sha256",
            code="phase2a_final_apply_execution_authority_seal_invalid",
        )
        != EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
        or receipt.get("final_owner_packet_content_sha256") != EXPECTED_FINAL_PACKET_CONTENT_SHA256
        or receipt.get("original_owner_receipt_content_sha256")
        != EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256
        or receipt.get("execution_chain_status") != "AVAILABLE_UNSPENT"
        or receipt.get("execution_chain_consumed_count") != 0
        or receipt.get("execution_chain_remaining_count") != 1
        or authority.get("status") != "AVAILABLE_UNSPENT"
        or authority.get("execution_chain_consumed_count") != 0
        or authority.get("execution_chain_remaining_count") != 1
        or set(authority.get("stages", {}).values()) != {"NOT_RUN"}
    ):
        raise ValueError("phase2a_final_apply_execution_authority_boundary_invalid")
    for value in (receipt, authority):
        if any(value.get(field) is not expected for field, expected in _NO_LATER_EXECUTION.items()):
            raise ValueError("phase2a_final_apply_later_execution_already_run")
    final_adoption._verify_packet_root(final_adoption.PACKET_ROOT)
    return receipt, authority


def _verify_prior_frozen_scope() -> dict[str, Any]:
    scope = _load_object(PRIOR_SCOPE_PATH, code="phase2a_final_apply_prior_scope_invalid")
    sources = scope.get("sources")
    if (
        _verify_seal(
            scope,
            "scope_content_sha256",
            code="phase2a_final_apply_prior_scope_seal_invalid",
        )
        != EXPECTED_PRIOR_SCOPE_CONTENT_SHA256
        or scope.get("schema") != "legalbot.v111.phase2a.frozen-successor-source-scope.v1"
        or scope.get("status") != "OWNER_APPROVED_HELD_RESEARCH_SCOPE_FROZEN_BUILD_NOT_STARTED"
        or scope.get("answer_release_eligible") is not False
        or scope.get("successor_must_remain_non_active") is not True
        or scope.get("active_or_previous_write_authorized") is not False
        or not isinstance(sources, list)
        or scope.get("source_count") != len(sources)
        or len(sources) != EXPECTED_PRIOR_SCOPE_COUNT
    ):
        raise ValueError("phase2a_final_apply_prior_scope_boundary_invalid")
    source_ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("phase2a_final_apply_prior_scope_source_invalid")
        _verify_seal(
            source,
            "record_content_sha256",
            code="phase2a_final_apply_prior_scope_source_seal_invalid",
        )
        source_id = str(source.get("source_version_id") or "")
        if not source_id or source_id in source_ids:
            raise ValueError("phase2a_final_apply_prior_scope_source_identity_invalid")
        source_ids.add(source_id)
    return scope


def _row_id_set_sha256(row_ids: Sequence[str]) -> str:
    unique = sorted(set(row_ids))
    if len(unique) != len(row_ids) or not all(unique):
        raise ValueError("phase2a_final_apply_row_id_set_invalid")
    return _sha256(
        _canonical_json(
            {
                "schema": "legalbot.v111.phase2a.row-id-set.v1",
                "row_ids": unique,
            }
        )
    )


def _verify_resolver_artifact(
    path: Path,
    *,
    schema: str,
    expected_content_sha256: str,
    expected_file_sha256: str,
    code: str,
) -> dict[str, Any]:
    _require_file(path, expected_file_sha256, code=f"{code}_file_invalid")
    value = _load_object(path, code=f"{code}_invalid")
    if (
        value.get("schema") != schema
        or _verify_seal(
            value,
            "artifact_content_sha256",
            code=f"{code}_seal_invalid",
        )
        != expected_content_sha256
    ):
        raise ValueError(f"{code}_boundary_invalid")
    return value


def _support_crosswalk_requirement() -> dict[str, Any]:
    prior_qualification = _verify_resolver_artifact(
        PRIOR_QUALIFICATION_PATH,
        schema="legalbot.v111.phase2a.deterministic-all585-qualification.v1",
        expected_content_sha256=EXPECTED_PRIOR_QUALIFICATION_CONTENT_SHA256,
        expected_file_sha256=EXPECTED_PRIOR_QUALIFICATION_FILE_SHA256,
        code="phase2a_final_apply_prior_qualification",
    )
    matrix = _verify_resolver_artifact(
        CONSOLIDATED_MATRIX_PATH,
        schema="legalbot.v111.phase2a.consolidated-remediation-matrix.v1",
        expected_content_sha256=EXPECTED_CONSOLIDATED_MATRIX_CONTENT_SHA256,
        expected_file_sha256=EXPECTED_CONSOLIDATED_MATRIX_FILE_SHA256,
        code="phase2a_final_apply_consolidated_matrix",
    )
    r95 = _verify_resolver_artifact(
        R95_BINDINGS_PATH,
        schema="legalbot.v111.phase2a.owner-approved-candidate-bindings-84.v1",
        expected_content_sha256=EXPECTED_R95_BINDINGS_CONTENT_SHA256,
        expected_file_sha256=EXPECTED_R95_BINDINGS_FILE_SHA256,
        code="phase2a_final_apply_r95_bindings",
    )
    preserved = _verify_resolver_artifact(
        PRESERVED_CROSSWALK_PATH,
        schema="legalbot.v111.phase2a.deterministic-exact-span-packets-364.v1",
        expected_content_sha256=EXPECTED_PRESERVED_CROSSWALK_CONTENT_SHA256,
        expected_file_sha256=EXPECTED_PRESERVED_CROSSWALK_FILE_SHA256,
        code="phase2a_final_apply_preserved_crosswalk",
    )
    original_packet = _verify_resolver_artifact(
        ORIGINAL_PACKET_PATH,
        schema="legalbot.v111.phase2a.exact-remediation-owner-packet.v1",
        expected_content_sha256=EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256,
        expected_file_sha256=EXPECTED_ORIGINAL_PACKET_FILE_SHA256,
        code="phase2a_final_apply_original_owner_packet",
    )

    prior_rows = prior_qualification.get("rows")
    matrix_rows = matrix.get("rows")
    r95_records = r95.get("records")
    preserved_rows = preserved.get("rows")
    decisions = original_packet.get("decisions")
    if not all(
        isinstance(value, list)
        for value in (prior_rows, matrix_rows, r95_records, preserved_rows, decisions)
    ):
        raise ValueError("phase2a_final_apply_resolver_inventory_invalid")

    prior_ready_ids = [
        str(item.get("row_id") or "")
        for item in prior_rows
        if isinstance(item, Mapping)
        and item.get("qualification_status") == "TECHNICALLY_EVIDENCE_READY_FOR_OWNER_ADOPTION"
    ]
    recorded_ids = [
        str(item.get("row_id") or "")
        for item in matrix_rows
        if isinstance(item, Mapping)
        and isinstance(item.get("owner_decision"), Mapping)
        and item["owner_decision"].get("status") == "RECORDED_OWNER_PHASE2A_DECISION"
    ]
    r95_ids = [
        str(item.get("source_decision", {}).get("row_id") or "")
        for item in r95_records
        if isinstance(item, Mapping) and isinstance(item.get("source_decision"), Mapping)
    ]
    preserved_ids = [
        str(item.get("row_id") or "")
        for item in preserved_rows
        if isinstance(item, Mapping)
        and item.get("status") == "OWNER_APPROVED_EXACT_BINDINGS_READY_FOR_FINAL_QUALIFICATION"
        and item.get("owner_decision_required") is False
        and item.get("selected_exact_span_id")
    ]
    decision_ids = [
        str(item.get("row_id") or "") for item in decisions if isinstance(item, Mapping)
    ]
    prior_component_ids = [*recorded_ids, *r95_ids, *preserved_ids]
    if (
        len(prior_ready_ids) != 224
        or len(recorded_ids) != 137
        or len(r95_ids) != 84
        or len(preserved_ids) != 3
        or len(decision_ids) != 361
        or set(prior_component_ids) != set(prior_ready_ids)
        or len(set(prior_component_ids)) != 224
        or set(prior_ready_ids) & set(decision_ids)
        or len(set(prior_ready_ids) | set(decision_ids)) != 585
        or _row_id_set_sha256(prior_ready_ids) != EXPECTED_PRIOR224_ROW_SET_SHA256
        or _row_id_set_sha256(decision_ids) != EXPECTED_REMEDIATION361_ROW_SET_SHA256
        or _row_id_set_sha256([*prior_ready_ids, *decision_ids]) != EXPECTED_ALL585_ROW_SET_SHA256
        or not set(FALLBACK_ROW_CONTRACTS).issubset(decision_ids)
    ):
        raise ValueError("phase2a_final_apply_resolver_partition_invalid")

    resolver_specs = (
        (
            "PRIOR_BLOCKED_QUALIFICATION_PARTITION",
            PRIOR_QUALIFICATION_PATH,
            EXPECTED_PRIOR_QUALIFICATION_CONTENT_SHA256,
            EXPECTED_PRIOR_QUALIFICATION_FILE_SHA256,
            "rows",
            224,
        ),
        (
            "PRE_R94_RECORDED_OWNER_DECISIONS",
            CONSOLIDATED_MATRIX_PATH,
            EXPECTED_CONSOLIDATED_MATRIX_CONTENT_SHA256,
            EXPECTED_CONSOLIDATED_MATRIX_FILE_SHA256,
            "rows",
            137,
        ),
        (
            "R95_OWNER_APPROVED_BINDINGS",
            R95_BINDINGS_PATH,
            EXPECTED_R95_BINDINGS_CONTENT_SHA256,
            EXPECTED_R95_BINDINGS_FILE_SHA256,
            "records",
            84,
        ),
        (
            "PRESERVED_READY_EXACT_SPANS",
            PRESERVED_CROSSWALK_PATH,
            EXPECTED_PRESERVED_CROSSWALK_CONTENT_SHA256,
            EXPECTED_PRESERVED_CROSSWALK_FILE_SHA256,
            "rows",
            3,
        ),
        (
            "OWNER_ADOPTED_REMEDIATION_DECISIONS",
            ORIGINAL_PACKET_PATH,
            EXPECTED_ORIGINAL_PACKET_CONTENT_SHA256,
            EXPECTED_ORIGINAL_PACKET_FILE_SHA256,
            "decisions",
            361,
        ),
    )
    resolver_inputs = [
        _seal_record(
            {
                "input_role": role,
                "relative_path": path.relative_to(REVIEW_ROOT).as_posix(),
                "artifact_content_sha256": content_sha,
                "file_sha256": file_sha,
                "inventory_key": inventory_key,
                "selected_row_count": count,
            }
        )
        for role, path, content_sha, file_sha, inventory_key, count in resolver_specs
    ]
    fallback_rows = [
        _seal_record(
            {
                "row_id": row_id,
                "contract_content_sha256": contract_sha,
                "advisory_content_sha256": EXPECTED_FALLBACK_ADVISORY_CONTENT_SHA256,
                "legal_support_reference_count_required": 0,
                "answer_model_output_authorized": False,
            }
        )
        for row_id, contract_sha in sorted(FALLBACK_ROW_CONTRACTS.items())
    ]
    regular_ids = sorted((set(prior_ready_ids) | set(decision_ids)) - set(FALLBACK_ROW_CONTRACTS))
    material = {
        "schema": "legalbot.v111.phase2a.all585-support-crosswalk-requirement.v1",
        "status": "REQUIRED_POST_BUILD_NOT_YET_EVALUATED",
        "required_output_schema": "legalbot.v111.phase2a.all585-support-crosswalk.v1",
        "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
        "prior_evidence_ready_row_count": len(prior_ready_ids),
        "prior_evidence_ready_row_ids": sorted(prior_ready_ids),
        "prior_evidence_ready_row_id_set_sha256": EXPECTED_PRIOR224_ROW_SET_SHA256,
        "owner_remediation_decision_row_count": len(decision_ids),
        "owner_remediation_decision_row_ids": sorted(decision_ids),
        "owner_remediation_decision_row_id_set_sha256": (EXPECTED_REMEDIATION361_ROW_SET_SHA256),
        "all585_row_count": 585,
        "all585_row_id_set_sha256": EXPECTED_ALL585_ROW_SET_SHA256,
        "regular_support_row_count": len(regular_ids),
        "regular_support_row_id_set_sha256": _row_id_set_sha256(regular_ids),
        "safe_fallback_row_count": len(fallback_rows),
        "safe_fallback_rows": fallback_rows,
        "resolver_inputs": resolver_inputs,
        "required_success_conditions": {
            "unresolved_owner_decision_count": 0,
            "material_gap_count": 0,
            "orphan_support_count": 0,
        },
        "successor_source_manifest_binding_required": True,
        "successor_source_version_id_set_binding_required": True,
        "support_resolution_run": False,
        "technical_success_predeclared": False,
        "answer_release_eligible": False,
    }
    return {**material, "record_content_sha256": _sealed(material)}


def _verify_goodwin_r2() -> dict[str, Any]:
    manifest_path = ECHR_R2_ROOT / packet_builder.ECHR_RECOVERY_MANIFEST_NAME
    package_path = ECHR_R2_ROOT / packet_builder.ECHR_RECOVERY_PACKAGE_NAME
    _require_file(
        manifest_path,
        EXPECTED_ECHR_R2_MANIFEST_FILE_SHA256,
        code="phase2a_final_apply_goodwin_manifest_file_invalid",
    )
    _require_file(
        package_path,
        EXPECTED_ECHR_R2_PACKAGE_FILE_SHA256,
        code="phase2a_final_apply_goodwin_package_file_invalid",
    )
    manifest = _load_object(manifest_path, code="phase2a_final_apply_goodwin_manifest_invalid")
    package = _load_object(package_path, code="phase2a_final_apply_goodwin_package_invalid")
    if (
        _verify_seal(
            manifest,
            "manifest_content_sha256",
            code="phase2a_final_apply_goodwin_manifest_seal_invalid",
        )
        != EXPECTED_ECHR_R2_MANIFEST_CONTENT_SHA256
        or _verify_seal(
            package,
            "package_content_sha256",
            code="phase2a_final_apply_goodwin_package_seal_invalid",
        )
        != EXPECTED_ECHR_R2_PACKAGE_CONTENT_SHA256
        or len(manifest.get("records", [])) != 1
    ):
        raise ValueError("phase2a_final_apply_goodwin_contract_invalid")
    record = manifest["records"][0]
    if (
        record.get("record_content_sha256")
        != packet_builder.EXPECTED_ECHR_GOODWIN_RECORD_CONTENT_SHA256
        or record.get("raw_sha256") != packet_builder.EXPECTED_ECHR_GOODWIN_RAW_SHA256
        or record.get("canonical_markdown_sha256") != EXPECTED_GOODWIN_CANONICAL_SHA256
    ):
        raise ValueError("phase2a_final_apply_goodwin_record_invalid")
    _verify_seal(
        record,
        "record_content_sha256",
        code="phase2a_final_apply_goodwin_record_seal_invalid",
    )
    for member_key, digest_key in (
        ("quarantine_member", "raw_sha256"),
        ("canonical_markdown_member", "canonical_markdown_sha256"),
    ):
        member = str(record.get(member_key) or "")
        if Path(member).name != member:
            raise ValueError("phase2a_final_apply_goodwin_member_invalid")
        _require_file(
            ECHR_R2_ROOT / member,
            str(record[digest_key]),
            code="phase2a_final_apply_goodwin_member_invalid",
        )
    return record


def _category(authority_identity_id: str) -> str:
    value = authority_identity_id.casefold()
    if value.startswith(("ukpga:", "uksi:", "eur:")):
        return "Official Legislation"
    if value.startswith("neutral-citation:") or "hudoc.echr.coe.int" in value:
        return "Official Judgments"
    if any(host in value for host in ("sra.org.uk", "tas-cas.org", "fca.org.uk")):
        return "Official Regulations"
    if "gov.uk" in value:
        return "Official Guidance"
    raise ValueError("phase2a_final_apply_authority_category_unresolved")


def _target_name(
    *, ordinal: int, kind: str, digest: str, suffix: str, authority_identity_id: str
) -> str:
    category = _category(authority_identity_id)
    prefix = {
        "ORIGINAL_AUDITED_PASS": "adopted-original",
        "FCA_CANONICAL_MARKDOWN": "adopted-fca",
        "ECHR_CANONICAL_MARKDOWN": "adopted-echr-canonical",
        "ECHR_RAW_PROVENANCE": "adopted-echr-raw",
    }[kind]
    filename = f"{prefix}-{ordinal:04d}-{digest[:20]}{suffix.casefold()}"
    if _SAFE_COMPONENT.fullmatch(filename) is None:
        raise ValueError("phase2a_final_apply_target_name_invalid")
    return f"{category}/{filename}"


def _representation(
    *,
    ordinal: int,
    kind: str,
    authority_identity_id: str,
    proposed_source_version_id: str,
    owner_source_record_id: str,
    owner_source_record_content_sha256: str,
    owner_decision_id: str,
    owner_decision_content_sha256: str,
    input_root_name: str,
    input_member: str,
    content_sha256: str,
    byte_size: int,
    index_eligible: bool,
    raw_provenance_sha256: str | None = None,
) -> dict[str, Any]:
    if (
        _SHA256.fullmatch(content_sha256) is None
        or Path(input_member).name != input_member
        or _SAFE_COMPONENT.fullmatch(input_member) is None
    ):
        raise ValueError("phase2a_final_apply_representation_identity_invalid")
    target = _target_name(
        ordinal=ordinal,
        kind=kind,
        digest=content_sha256,
        suffix=Path(input_member).suffix,
        authority_identity_id=authority_identity_id,
    )
    return _seal_record(
        {
            "ordinal": ordinal,
            "representation_kind": kind,
            "authority_identity_id": authority_identity_id,
            "proposed_source_version_id": proposed_source_version_id,
            "owner_source_record_id": owner_source_record_id,
            "owner_source_record_content_sha256": owner_source_record_content_sha256,
            "owner_decision_id": owner_decision_id,
            "owner_decision_content_sha256": owner_decision_content_sha256,
            "input_artifact_root_name": input_root_name,
            "input_member": input_member,
            "content_sha256": content_sha256,
            "byte_size": byte_size,
            "target_relative_path": target,
            "index_eligible": index_eligible,
            "provenance_only": not index_eligible,
            "raw_provenance_sha256": raw_provenance_sha256,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "citation_hold_retained": True,
            "evidence_span_hold_retained": True,
            "answer_release_eligible": False,
        }
    )


def _input_roots() -> dict[str, Path]:
    return {
        ORIGINAL_QUARANTINE_ROOT.name: ORIGINAL_QUARANTINE_ROOT,
        FCA_ROOT.name: FCA_ROOT,
        ECHR_R3_ROOT.name: ECHR_R3_ROOT,
        ECHR_R2_ROOT.name: ECHR_R2_ROOT,
        SEMENYA_ROOT.name: SEMENYA_ROOT,
    }


def _resolve_input(record: Mapping[str, Any]) -> Path:
    root = _input_roots().get(str(record.get("input_artifact_root_name") or ""))
    member = str(record.get("input_member") or "")
    if root is None or Path(member).name != member or _SAFE_COMPONENT.fullmatch(member) is None:
        raise ValueError("phase2a_final_apply_input_member_invalid")
    path = root / member
    _require_file(
        path,
        str(record.get("content_sha256") or ""),
        code="phase2a_final_apply_input_member_digest_invalid",
    )
    if path.stat().st_size != record.get("byte_size"):
        raise ValueError("phase2a_final_apply_input_member_size_invalid")
    return path


def _verify_original_crosslink(
    *, decision: Mapping[str, Any], record: Mapping[str, Any], proposal: Mapping[str, Any]
) -> None:
    selected = proposal.get("quarantine_representation_binding", {}).get(
        "selected_admission_binding"
    )
    summary_only_fields = {
        "authority_representation_set_complete",
        "eligible_for_owner_packet",
    }
    if (
        not isinstance(selected, Mapping)
        or any(
            record.get(key) != value
            for key, value in selected.items()
            if key not in summary_only_fields
        )
        or selected.get("authority_representation_set_complete") is not True
        or selected.get("eligible_for_owner_packet") is not True
        or selected.get("selected_for_proposed_admission") is not True
        or record.get("raw_sha256") != decision.get("original_raw_sha256")
        or record.get("record_content_sha256") != decision.get("original_record_content_sha256")
        or proposal.get("proposal_content_sha256")
        != decision.get("original_proposal_content_sha256")
        or decision.get("audit_verdict") not in {"PASS", "PASS_WITH_WARNING"}
    ):
        raise ValueError("phase2a_final_apply_original_crosslink_invalid")


def build_materialization_plan() -> dict[str, Any]:
    """Verify every immutable input and return the exact read-only copy plan."""

    receipt, authority = _verify_final_approval()
    prior_scope = _verify_prior_frozen_scope()
    crosswalk_requirement = _support_crosswalk_requirement()
    source_delta = packet_builder._verify_source_delta(SOURCE_DELTA_ROOT)
    original_packet = original_adoption._verify_source_package(ORIGINAL_PACKET_ROOT)
    original_manifest = original_adoption._verify_quarantine(
        ORIGINAL_QUARANTINE_ROOT, packet=original_packet
    )
    fca_manifest, _ = packet_builder._verify_fca_derivation(
        root=FCA_ROOT, source_delta=source_delta
    )
    echr_manifest, _ = packet_builder._verify_echr_recovery(ECHR_R3_ROOT)
    _, semenya_binding, _ = packet_builder._verify_q53_substitute(SEMENYA_ROOT)
    goodwin = _verify_goodwin_r2()

    original_records = {
        str(item.get("record_id")): item
        for item in original_manifest.get("records", [])
        if isinstance(item, dict)
    }
    original_proposals = {
        str(item.get("proposal_id")): item
        for item in original_packet.get("proposed_new_source_admissions", [])
        if isinstance(item, dict)
    }
    representations: list[dict[str, Any]] = []
    ordinal = 0
    for decision in source_delta.get("retained_original_passing_representations", []):
        record = original_records.get(str(decision.get("original_record_id") or ""))
        proposal = original_proposals.get(str(decision.get("original_proposal_id") or ""))
        if record is None or proposal is None:
            raise ValueError("phase2a_final_apply_original_crosslink_missing")
        _verify_original_crosslink(decision=decision, record=record, proposal=proposal)
        ordinal += 1
        member = str(record["quarantine_member"])
        representations.append(
            _representation(
                ordinal=ordinal,
                kind="ORIGINAL_AUDITED_PASS",
                authority_identity_id=str(decision["authority_identity_id"]),
                proposed_source_version_id=str(decision["original_proposed_source_version_id"]),
                owner_source_record_id=str(record["record_id"]),
                owner_source_record_content_sha256=str(record["record_content_sha256"]),
                owner_decision_id=str(decision["decision_id"]),
                owner_decision_content_sha256=str(decision["decision_content_sha256"]),
                input_root_name=ORIGINAL_QUARANTINE_ROOT.name,
                input_member=member,
                content_sha256=str(record["raw_sha256"]),
                byte_size=int(record["bytes"]),
                index_eligible=True,
            )
        )

    for record in fca_manifest.get("records", []):
        ordinal += 1
        member = str(record["derived_member"])
        representations.append(
            _representation(
                ordinal=ordinal,
                kind="FCA_CANONICAL_MARKDOWN",
                authority_identity_id=f"official-url:{record['canonical_url']}",
                proposed_source_version_id=str(record["proposed_source_version_id"]),
                owner_source_record_id=str(record["repair_record_id"]),
                owner_source_record_content_sha256=str(record["record_content_sha256"]),
                owner_decision_id=str(record["source_delta_decision_id"]),
                owner_decision_content_sha256=str(record["source_delta_decision_content_sha256"]),
                input_root_name=FCA_ROOT.name,
                input_member=member,
                content_sha256=str(record["derived_sha256"]),
                byte_size=int(record["derived_bytes"]),
                index_eligible=True,
                raw_provenance_sha256=str(record["raw_sha256"]),
            )
        )

    echr_records = [*echr_manifest["records"], goodwin]
    semenya = _load_object(
        SEMENYA_ROOT / packet_builder.Q53_SUBSTITUTE_ADVISORY_NAME,
        code="phase2a_final_apply_semenya_advisory_invalid",
    )["semenya_source_record"]
    if semenya.get("record_content_sha256") != semenya_binding["record_content_sha256"]:
        raise ValueError("phase2a_final_apply_semenya_crosslink_invalid")
    echr_records.append(semenya)
    for record in echr_records:
        source_root = (
            ECHR_R3_ROOT
            if record in echr_manifest["records"]
            else ECHR_R2_ROOT
            if record is goodwin
            else SEMENYA_ROOT
        )
        raw_member = str(record.get("quarantine_member") or record.get("raw_member") or "")
        canonical_member = str(record["canonical_markdown_member"])
        authority_id = str(record["authority_identity_id"])
        decision_id = f"final-echr-admission-{str(record['record_id']).rsplit('-', 1)[-1]}"
        decision_sha = str(record["record_content_sha256"])
        for kind, member, digest, size, index_eligible in (
            (
                "ECHR_RAW_PROVENANCE",
                raw_member,
                str(record["raw_sha256"]),
                int(record["bytes"]),
                False,
            ),
            (
                "ECHR_CANONICAL_MARKDOWN",
                canonical_member,
                str(record["canonical_markdown_sha256"]),
                int(record["canonical_markdown_bytes"]),
                True,
            ),
        ):
            ordinal += 1
            representations.append(
                _representation(
                    ordinal=ordinal,
                    kind=kind,
                    authority_identity_id=authority_id,
                    proposed_source_version_id=str(record["proposed_source_version_id"]),
                    owner_source_record_id=str(record["record_id"]),
                    owner_source_record_content_sha256=str(record["record_content_sha256"]),
                    owner_decision_id=decision_id,
                    owner_decision_content_sha256=decision_sha,
                    input_root_name=source_root.name,
                    input_member=member,
                    content_sha256=digest,
                    byte_size=size,
                    index_eligible=index_eligible,
                    raw_provenance_sha256=(str(record["raw_sha256"]) if index_eligible else None),
                )
            )

    if (
        len(representations) != EXPECTED_MATERIALIZED_REPRESENTATION_COUNT
        or len({item["content_sha256"] for item in representations})
        != EXPECTED_MATERIALIZED_REPRESENTATION_COUNT
        or sum(item["index_eligible"] for item in representations)
        != EXPECTED_INDEX_REPRESENTATION_COUNT
        or sum(item["provenance_only"] for item in representations)
        != EXPECTED_PROVENANCE_COMPANION_COUNT
        or len({item["target_relative_path"] for item in representations})
        != EXPECTED_MATERIALIZED_REPRESENTATION_COUNT
    ):
        raise ValueError("phase2a_final_apply_representation_set_invalid")
    prior_authorities = {str(item["authority_identity_id"]) for item in prior_scope["sources"]}
    new_authorities = {
        str(item["authority_identity_id"]) for item in representations if item["index_eligible"]
    }
    if (
        len(new_authorities) != EXPECTED_INDEX_REPRESENTATION_COUNT
        or prior_authorities & new_authorities
    ):
        raise ValueError("phase2a_final_apply_prior_new_authority_overlap")
    for record in representations:
        _verify_seal(
            record,
            "record_content_sha256",
            code="phase2a_final_apply_representation_seal_invalid",
        )
        _resolve_input(record)

    existing_hashes: dict[str, list[str]] = {}
    if SOURCE_ROOT.is_symlink() or not SOURCE_ROOT.is_dir():
        raise ValueError("phase2a_final_apply_source_root_invalid")
    for path in SOURCE_ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if MATERIALIZED_ROOT in path.parents:
            continue
        existing_hashes.setdefault(_sha256_file(path), []).append(
            path.relative_to(SOURCE_ROOT).as_posix()
        )
    reused = [item for item in representations if item["content_sha256"] in existing_hashes]
    if reused:
        raise ValueError("phase2a_final_apply_would_duplicate_existing_source_bytes")

    rejected = list(source_delta.get("rejected_defective_original_representations", []))
    unresolved = list(source_delta.get("unresolved_repair_holds", []))
    superseded_old_ids = {
        "quarantine-binding-0a370f8e41122c812c5f26d2",
        "quarantine-binding-678af407a5abea67aa817bee",
        "quarantine-binding-d07fad39256d15a7c6a25893",
    }
    retained_repair_holds = [
        item
        for item in unresolved
        if str(item.get("old_record_id") or "") not in superseded_old_ids
    ]
    if len(rejected) != 16 or len(retained_repair_holds) != 2:
        raise ValueError("phase2a_final_apply_exclusion_set_invalid")
    original_holds = source_delta.get("retained_original_packet_holds")
    if not isinstance(original_holds, Mapping):
        raise ValueError("phase2a_final_apply_original_hold_set_invalid")
    quarantine_holds = original_holds.get("quarantine_source_admission_holds")
    identity_holds = original_holds.get("source_identity_and_admission_holds")
    if (
        not isinstance(quarantine_holds, list)
        or len(quarantine_holds) != 31
        or not isinstance(identity_holds, list)
        or len(identity_holds) != 86
    ):
        raise ValueError("phase2a_final_apply_original_hold_inventory_invalid")

    material = {
        "schema": "legalbot.v111.phase2a.final-remediation-materialization-plan.v1",
        "status": "EXACT_OWNER_ADOPTED_MATERIALIZATION_READY_NOT_RUN",
        "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
        "final_approval_receipt_content_sha256": (EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256),
        "execution_authority_content_sha256": EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256,
        "original_owner_receipt_content_sha256": EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256,
        "source_binding_delta_content_sha256": EXPECTED_SOURCE_DELTA_CONTENT_SHA256,
        "fca_manifest_content_sha256": EXPECTED_FCA_MANIFEST_CONTENT_SHA256,
        "echr_recovery_manifest_content_sha256": EXPECTED_ECHR_R3_MANIFEST_CONTENT_SHA256,
        "semenya_advisory_content_sha256": EXPECTED_SEMENYA_ADVISORY_CONTENT_SHA256,
        "source_root_relative_path": SOURCE_ROOT.relative_to(PROJECT_ROOT).as_posix(),
        "materialized_source_root_relative_path": MATERIALIZED_ROOT.relative_to(
            PROJECT_ROOT
        ).as_posix(),
        "representation_count": len(representations),
        "exact_owner_decision_count": 361,
        "index_eligible_representation_count": sum(
            item["index_eligible"] for item in representations
        ),
        "provenance_companion_count": sum(item["provenance_only"] for item in representations),
        "prior_frozen_scope_content_sha256": EXPECTED_PRIOR_SCOPE_CONTENT_SHA256,
        "prior_frozen_scope_source_count": len(prior_scope["sources"]),
        "prior_source_version_id_set_sha256": (
            phase2a_dynamic_scope._source_version_set_sha256(
                [str(item["source_version_id"]) for item in prior_scope["sources"]]
            )
        ),
        "projected_successor_source_count": (
            len(prior_scope["sources"]) + sum(item["index_eligible"] for item in representations)
        ),
        "support_crosswalk_requirement": crosswalk_requirement,
        "representations": representations,
        "rejected_original_decision_ids": sorted(str(item["decision_id"]) for item in rejected),
        "rejected_original_record_ids": sorted(
            str(item["original_record_id"]) for item in rejected
        ),
        "retained_repair_hold_decision_ids": sorted(
            str(item["decision_id"]) for item in retained_repair_holds
        ),
        "retained_repair_hold_record_ids": sorted(
            str(item["old_record_id"]) for item in retained_repair_holds
        ),
        "retained_original_quarantine_hold_count": len(quarantine_holds),
        "retained_original_identity_admission_hold_count": len(identity_holds),
        "fca_raw_json_materialized": False,
        "mutu_retried": False,
        "ali_riza_retried": False,
        "owner_decisions_applied": False,
        "source_materialized": False,
        "catalogue_mutated": False,
        **_NO_LATER_EXECUTION,
    }
    return {**material, "artifact_content_sha256": _sealed(material)}


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _copy_exclusive(source: Path, target: Path) -> None:
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with source.open("rb") as src, os.fdopen(descriptor, "wb") as dst:
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def _publish_noreplace(staging: Path, output: Path, *, code: str) -> None:
    try:
        os.rename(staging, output)
    except FileExistsError as exc:
        raise ValueError(code) from exc


def materialize_exact_sources(
    *,
    output_root: Path = MATERIALIZATION_OUTPUT_ROOT,
    materialized_root: Path = MATERIALIZED_ROOT,
) -> dict[str, Any]:
    """Apply only the exact copy plan; this is not a scan or catalogue write."""

    plan = build_materialization_plan()
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_final_apply_materialization_output_exists")
    if materialized_root.exists() or materialized_root.is_symlink():
        raise ValueError("phase2a_final_apply_materialized_root_exists")
    if materialized_root.parent.resolve(strict=True) != SOURCE_ROOT.resolve(strict=True):
        raise ValueError("phase2a_final_apply_materialized_root_outside_source_root")

    output_root.parent.mkdir(parents=True, exist_ok=True)
    source_staging = Path(
        tempfile.mkdtemp(prefix=f".{materialized_root.name}.staging-", dir=SOURCE_ROOT)
    )
    evidence_staging = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent)
    )
    os.chmod(source_staging, 0o700)
    os.chmod(evidence_staging, 0o700)
    source_published = False
    evidence_published = False
    try:
        for record in plan["representations"]:
            relative = Path(str(record["target_relative_path"]))
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("phase2a_final_apply_target_path_invalid")
            target = source_staging / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _copy_exclusive(_resolve_input(record), target)
            if (
                _sha256_file(target) != record["content_sha256"]
                or target.stat().st_size != record["byte_size"]
            ):
                raise ValueError("phase2a_final_apply_materialized_copy_invalid")
        copied = [path for path in source_staging.rglob("*") if path.is_file()]
        if len(copied) != EXPECTED_MATERIALIZED_REPRESENTATION_COUNT:
            raise ValueError("phase2a_final_apply_materialized_inventory_invalid")

        ledger_material = {
            **{
                key: value
                for key, value in plan.items()
                if key not in {"schema", "status", "artifact_content_sha256"}
            },
            "schema": "legalbot.v111.phase2a.final-remediation-materialization-ledger.v1",
            "status": "OWNER_DECISIONS_APPLIED_SOURCE_MATERIALIZED_SCAN_NOT_RUN",
            "materialized_file_count": len(copied),
            "owner_decisions_applied": True,
            "source_materialized": True,
            "catalogue_mutated": False,
            **_NO_LATER_EXECUTION,
        }
        ledger = {
            **ledger_material,
            "artifact_content_sha256": _sealed(ledger_material),
        }
        plan_raw = _pretty_json(plan)
        ledger_raw = _pretty_json(ledger)
        artifacts = {
            MATERIALIZATION_LEDGER_NAME: ledger_raw,
            MATERIALIZATION_PLAN_NAME: plan_raw,
        }
        package_material = {
            "schema": "legalbot.v111.phase2a.final-remediation-materialization-package.v1",
            "status": ledger["status"],
            "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
            "final_approval_receipt_content_sha256": (
                EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
            ),
            "materialization_ledger_content_sha256": ledger["artifact_content_sha256"],
            "materialized_source_root_relative_path": ledger[
                "materialized_source_root_relative_path"
            ],
            "artifacts": [
                {"name": name, "file_sha256": _sha256(raw)}
                for name, raw in sorted(artifacts.items())
            ],
            "catalogue_mutated": False,
            **_NO_LATER_EXECUTION,
        }
        package = {
            **package_material,
            "artifact_content_sha256": _sealed(package_material),
        }
        package_raw = _pretty_json(package)
        artifacts[PACKAGE_NAME] = package_raw
        checksums_raw = "".join(
            f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
        ).encode()
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(evidence_staging / name, raw)
        _write_exclusive(evidence_staging / CHECKSUMS_NAME, checksums_raw)
        for path in evidence_staging.iterdir():
            os.chmod(path, 0o600)

        _publish_noreplace(
            source_staging,
            materialized_root,
            code="phase2a_final_apply_materialized_root_race",
        )
        source_published = True
        _publish_noreplace(
            evidence_staging,
            output_root,
            code="phase2a_final_apply_materialization_output_race",
        )
        evidence_published = True
    except BaseException:
        if source_staging.exists():
            shutil.rmtree(source_staging)
        if evidence_staging.exists():
            shutil.rmtree(evidence_staging)
        if source_published and materialized_root.exists():
            shutil.rmtree(materialized_root)
        if evidence_published and output_root.exists():
            shutil.rmtree(output_root)
        raise

    return {
        "status": ledger["status"],
        "output_name": output_root.name,
        "materialized_source_root_relative_path": ledger["materialized_source_root_relative_path"],
        "materialization_ledger_content_sha256": ledger["artifact_content_sha256"],
        "materialization_ledger_file_sha256": _sha256(ledger_raw),
        "materialized_file_count": EXPECTED_MATERIALIZED_REPRESENTATION_COUNT,
        "index_eligible_representation_count": EXPECTED_INDEX_REPRESENTATION_COUNT,
        "source_scan_run": False,
        "successor_build_run": False,
        "embedding_run": False,
        "phase2b_run": False,
    }


def load_materialization_ledger(path: Path, *, expected_content_sha256: str) -> dict[str, Any]:
    ledger = _load_object(path, code="phase2a_final_apply_materialization_ledger_invalid")
    supplied = _verify_seal(
        ledger,
        "artifact_content_sha256",
        code="phase2a_final_apply_materialization_ledger_seal_invalid",
    )
    records = ledger.get("representations")
    crosswalk_requirement = ledger.get("support_crosswalk_requirement")
    if (
        supplied != expected_content_sha256
        or ledger.get("schema")
        != "legalbot.v111.phase2a.final-remediation-materialization-ledger.v1"
        or ledger.get("status") != "OWNER_DECISIONS_APPLIED_SOURCE_MATERIALIZED_SCAN_NOT_RUN"
        or ledger.get("final_owner_packet_content_sha256") != EXPECTED_FINAL_PACKET_CONTENT_SHA256
        or ledger.get("final_approval_receipt_content_sha256")
        != EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
        or ledger.get("original_owner_receipt_content_sha256")
        != EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256
        or ledger.get("owner_decisions_applied") is not True
        or ledger.get("source_materialized") is not True
        or ledger.get("catalogue_mutated") is not False
        or not isinstance(records, list)
        or len(records) != EXPECTED_MATERIALIZED_REPRESENTATION_COUNT
        or sum(item.get("index_eligible") is True for item in records)
        != EXPECTED_INDEX_REPRESENTATION_COUNT
    ):
        raise ValueError("phase2a_final_apply_materialization_ledger_boundary_invalid")
    if not isinstance(crosswalk_requirement, Mapping):
        raise ValueError("phase2a_final_apply_crosswalk_requirement_invalid")
    _verify_seal(
        crosswalk_requirement,
        "record_content_sha256",
        code="phase2a_final_apply_crosswalk_requirement_seal_invalid",
    )
    if (
        crosswalk_requirement.get("schema")
        != "legalbot.v111.phase2a.all585-support-crosswalk-requirement.v1"
        or crosswalk_requirement.get("status") != "REQUIRED_POST_BUILD_NOT_YET_EVALUATED"
        or crosswalk_requirement.get("prior_evidence_ready_row_count") != 224
        or crosswalk_requirement.get("owner_remediation_decision_row_count") != 361
        or crosswalk_requirement.get("all585_row_count") != 585
        or crosswalk_requirement.get("regular_support_row_count") != 583
        or crosswalk_requirement.get("safe_fallback_row_count") != 2
        or crosswalk_requirement.get("support_resolution_run") is not False
        or crosswalk_requirement.get("technical_success_predeclared") is not False
    ):
        raise ValueError("phase2a_final_apply_crosswalk_requirement_boundary_invalid")
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_final_apply_materialization_record_invalid")
        _verify_seal(
            record,
            "record_content_sha256",
            code="phase2a_final_apply_materialization_record_seal_invalid",
        )
        target = PROJECT_ROOT / str(ledger["materialized_source_root_relative_path"])
        target = target / str(record["target_relative_path"])
        _require_file(
            target,
            str(record["content_sha256"]),
            code="phase2a_final_apply_materialized_source_file_invalid",
        )
    return ledger


def _scan_row(
    connection: sqlite3.Connection, scan_id: str, scan_manifest_sha256: str
) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,
               required_roots_json,roots_seen_json
        FROM source_scans WHERE id=?
        """,
        (scan_id,),
    ).fetchone()
    if (
        row is None
        or row["status"] != "complete"
        or row["manifest_sha256"] != scan_manifest_sha256
        or int(row["expected_file_count"] or -1) != int(row["files_accounted"] or -2)
        or row["required_roots_json"] != row["roots_seen_json"]
    ):
        raise ValueError("phase2a_final_apply_source_scan_not_exact_complete")
    return dict(row)


def build_post_scan_plan(
    connection: sqlite3.Connection,
    *,
    materialization_ledger: Mapping[str, Any],
    scan_id: str,
    scan_manifest_sha256: str,
) -> dict[str, Any]:
    """Resolve the exact scanned source versions without mutating the catalogue."""

    connection.row_factory = sqlite3.Row
    scan = _scan_row(connection, scan_id, scan_manifest_sha256)
    bindings: list[dict[str, Any]] = []
    seen_source_versions: set[str] = set()
    for record in materialization_ledger["representations"]:
        rows = connection.execute(
            """
            SELECT ssf.document_id, d.content_sha256,d.status AS document_status,
                   d.lane,d.retrieval_canonical,d.duplicate_of,
                   sv.id AS source_version_id,sv.version_sha256,
                   sv.canonical_markdown_path,sv.review_status,sv.superseded_by,
                   sv.metadata_json,
                   (SELECT COUNT(*) FROM chunks c
                    WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
            FROM source_scan_files ssf
            JOIN documents d ON d.id=ssf.document_id
            JOIN source_versions sv ON sv.document_id=d.id
            WHERE ssf.scan_id=? AND ssf.content_sha256=?
              AND sv.version_sha256=? AND sv.superseded_by IS NULL
            """,
            (scan_id, record["content_sha256"], record["content_sha256"]),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("phase2a_final_apply_scanned_representation_not_unique")
        row = rows[0]
        source_version_id = str(row["source_version_id"])
        chunks = int(row["body_chunk_count"] or 0)
        if source_version_id in seen_source_versions or (record["index_eligible"] and chunks < 1):
            raise ValueError("phase2a_final_apply_scanned_representation_not_ready")
        seen_source_versions.add(source_version_id)
        bindings.append(
            {
                "representation_ordinal": record["ordinal"],
                "owner_representation_record_content_sha256": record["record_content_sha256"],
                "owner_source_record_id": record["owner_source_record_id"],
                "owner_decision_id": record["owner_decision_id"],
                "authority_identity_id": record["authority_identity_id"],
                "content_sha256": record["content_sha256"],
                "source_version_id": source_version_id,
                "document_id": str(row["document_id"]),
                "version_sha256": str(row["version_sha256"]),
                "canonical_markdown_path": str(row["canonical_markdown_path"]),
                "body_chunk_count": chunks,
                "index_eligible": record["index_eligible"],
                "provenance_only": record["provenance_only"],
                "representation_kind": record["representation_kind"],
                "pre_review_status": str(row["review_status"]),
                "pre_document_status": str(row["document_status"]),
                "pre_lane": str(row["lane"]),
                "pre_retrieval_canonical": bool(row["retrieval_canonical"]),
                "pre_duplicate_of": row["duplicate_of"],
            }
        )
    if (
        len(bindings) != EXPECTED_MATERIALIZED_REPRESENTATION_COUNT
        or sum(item["index_eligible"] for item in bindings) != EXPECTED_INDEX_REPRESENTATION_COUNT
    ):
        raise ValueError("phase2a_final_apply_post_scan_binding_set_invalid")
    material = {
        "schema": "legalbot.v111.phase2a.final-remediation-post-scan-plan.v1",
        "status": "EXACT_POST_SCAN_OWNER_APPLICATION_READY_NOT_APPLIED",
        "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
        "final_approval_receipt_content_sha256": (EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256),
        "original_owner_receipt_content_sha256": EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256,
        "materialization_ledger_content_sha256": materialization_ledger["artifact_content_sha256"],
        "source_scan_id": scan_id,
        "source_scan_manifest_sha256": scan_manifest_sha256,
        "source_scan_expected_file_count": int(scan["expected_file_count"]),
        "binding_count": len(bindings),
        "index_eligible_binding_count": sum(item["index_eligible"] for item in bindings),
        "provenance_binding_count": sum(item["provenance_only"] for item in bindings),
        "bindings": bindings,
        "catalogue_mutated": False,
        "owner_decisions_applied": True,
        "source_materialized": True,
        "source_scan_run": True,
        "successor_build_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "phase2b_run": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
    }
    return {**material, "artifact_content_sha256": _sealed(material)}


def _owner_metadata(
    current: str, *, binding: Mapping[str, Any], scan_id: str, scan_manifest_sha256: str
) -> str:
    try:
        metadata = json.loads(current or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("phase2a_final_apply_source_metadata_invalid") from exc
    if not isinstance(metadata, dict):
        raise ValueError("phase2a_final_apply_source_metadata_invalid")
    index_eligible = bool(binding["index_eligible"])
    metadata.update(
        {
            "identity_verified": True,
            "currentness_verified": False,
            "subsequent_treatment_check_required": True,
            "subsequent_treatment_verified": False,
            "citation_rendering_enabled": False,
            "eligible_for_model_use": index_eligible,
            "ai_use_policy": (
                "owner_private_research_only" if index_eligible else "provenance_only"
            ),
            "answer_release_eligible": False,
            "phase2a_final_remediation_owner_admission": {
                "schema": "legalbot.v111.phase2a.final-remediation-owner-admission.v1",
                "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
                "final_approval_receipt_content_sha256": (
                    EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
                ),
                "owner_representation_record_content_sha256": binding[
                    "owner_representation_record_content_sha256"
                ],
                "owner_source_record_id": binding["owner_source_record_id"],
                "source_scan_id": scan_id,
                "source_scan_manifest_sha256": scan_manifest_sha256,
                "index_eligible": index_eligible,
                "provenance_only": not index_eligible,
                "currentness_hold_retained": True,
                "later_treatment_hold_retained": True,
                "citation_hold_retained": True,
                "evidence_span_hold_retained": True,
                "answer_release_eligible": False,
                "phase2b_authorized": False,
            },
        }
    )
    return json.dumps(metadata, ensure_ascii=False, sort_keys=True)


def _apply_post_scan_transaction(
    connection: sqlite3.Connection,
    *,
    plan: Mapping[str, Any],
) -> None:
    decided_at = datetime.now(UTC).isoformat(timespec="seconds")
    connection.execute("BEGIN IMMEDIATE")
    try:
        for binding in plan["bindings"]:
            current = connection.execute(
                "SELECT metadata_json,review_status,superseded_by FROM source_versions WHERE id=?",
                (binding["source_version_id"],),
            ).fetchone()
            if (
                current is None
                or current["superseded_by"] is not None
                or current["review_status"] != "staged"
                or binding["pre_review_status"] != "staged"
            ):
                raise ValueError("phase2a_final_apply_source_changed_before_transaction")
            if binding["index_eligible"]:
                connection.execute(
                    """
                    UPDATE documents SET retrieval_canonical=0
                    WHERE id<>? AND EXISTS(
                      SELECT 1 FROM source_versions sibling
                      WHERE sibling.document_id=documents.id
                        AND sibling.authority_identity_id=?
                    )
                    """,
                    (binding["document_id"], binding["authority_identity_id"]),
                )
                connection.execute(
                    """
                    UPDATE documents
                    SET status='citable',lane='primary_authority',duplicate_of=NULL,
                        retrieval_canonical=1,updated_at=? WHERE id=?
                    """,
                    (decided_at, binding["document_id"]),
                )
            else:
                connection.execute(
                    "UPDATE documents SET retrieval_canonical=0,updated_at=? WHERE id=?",
                    (decided_at, binding["document_id"]),
                )
            metadata_json = _owner_metadata(
                str(current["metadata_json"] or "{}"),
                binding=binding,
                scan_id=str(plan["source_scan_id"]),
                scan_manifest_sha256=str(plan["source_scan_manifest_sha256"]),
            )
            updated = connection.execute(
                """
                UPDATE source_versions
                SET stable_identifier=?,authority_identity_id=?,metadata_json=?,
                    review_status='approved'
                WHERE id=? AND review_status='staged' AND superseded_by IS NULL
                """,
                (
                    binding["authority_identity_id"],
                    binding["authority_identity_id"],
                    metadata_json,
                    binding["source_version_id"],
                ),
            )
            if updated.rowcount != 1:
                raise ValueError("phase2a_final_apply_source_changed_during_transaction")
            pending = connection.execute(
                """
                SELECT id FROM reviews
                WHERE review_type='source_version' AND target_id=? AND status='pending'
                ORDER BY created_at,id
                """,
                (binding["source_version_id"],),
            ).fetchall()
            if len(pending) > 1:
                raise ValueError("phase2a_final_apply_multiple_pending_reviews")
            reason = (
                "Exact owner-adopted Phase-2A final remediation admission; "
                "answer release remains held"
            )
            if pending:
                connection.execute(
                    """
                    UPDATE reviews SET status='approved',reason=?,decision_note='[redacted]',
                        decided_at=? WHERE id=? AND status='pending'
                    """,
                    (reason, decided_at, pending[0]["id"]),
                )
            else:
                review_id = (
                    "review-phase2a-final-"
                    + _sha256(
                        (
                            f"{binding['source_version_id']}\0"
                            f"{EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256}"
                        ).encode()
                    )[:32]
                )
                connection.execute(
                    """
                    INSERT INTO reviews(
                      id,review_type,target_id,status,reason,decision_note,created_at,decided_at
                    ) VALUES (?, 'source_version', ?, 'approved', ?, '[redacted]', ?, ?)
                    """,
                    (
                        review_id,
                        binding["source_version_id"],
                        reason,
                        decided_at,
                        decided_at,
                    ),
                )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def _post_scan_ledger(
    connection: sqlite3.Connection,
    *,
    plan: Mapping[str, Any],
    materialization_ledger: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    included: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    prestate_records: list[dict[str, Any]] = []
    for binding in plan["bindings"]:
        row = connection.execute(
            """
            SELECT sv.id AS source_version_id,sv.document_id,sv.authority_identity_id,
                   sv.version_sha256,sv.canonical_markdown_path,sv.review_status,
                   sv.superseded_by,sv.metadata_json,d.content_sha256,d.status,
                   d.lane,d.retrieval_canonical,d.duplicate_of,
                   (SELECT COUNT(*) FROM chunks c
                    WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.id=?
            """,
            (binding["source_version_id"],),
        ).fetchone()
        if row is None or row["review_status"] != "approved" or row["superseded_by"] is not None:
            raise ValueError("phase2a_final_apply_postcommit_source_invalid")
        metadata = json.loads(row["metadata_json"] or "{}")
        admission = metadata.get("phase2a_final_remediation_owner_admission")
        if (
            not isinstance(admission, dict)
            or admission.get("answer_release_eligible") is not False
            or admission.get("index_eligible") is not binding["index_eligible"]
        ):
            raise ValueError("phase2a_final_apply_postcommit_metadata_invalid")
        prestate_records.append(
            _seal_record(
                {
                    "source_version_id": binding["source_version_id"],
                    "document_id": binding["document_id"],
                    "pre_review_status": binding["pre_review_status"],
                    "pre_document_status": binding["pre_document_status"],
                    "pre_lane": binding["pre_lane"],
                    "pre_retrieval_canonical": binding["pre_retrieval_canonical"],
                    "pre_duplicate_of": binding["pre_duplicate_of"],
                }
            )
        )
        common = {
            "binding_id": (
                "final-remediation-binding-"
                + _sha256(
                    _canonical_json(
                        {
                            "owner_representation_record_content_sha256": binding[
                                "owner_representation_record_content_sha256"
                            ],
                            "source_version_id": str(row["source_version_id"]),
                        }
                    )
                )[:24]
            ),
            "source_version_id": str(row["source_version_id"]),
            "document_id": str(row["document_id"]),
            "authority_identity_id": str(row["authority_identity_id"]),
            "content_sha256": str(row["content_sha256"]),
            "version_sha256": str(row["version_sha256"]),
            "canonical_markdown_path": str(row["canonical_markdown_path"]),
            "body_chunk_count": int(row["body_chunk_count"] or 0),
            "owner_source_record_id": binding["owner_source_record_id"],
            "owner_representation_record_content_sha256": binding[
                "owner_representation_record_content_sha256"
            ],
            "answer_release_eligible_in_successor": False,
            "currentness_hold_retained": True,
            "later_treatment_hold_retained": True,
            "citation_hold_retained": True,
            "evidence_span_hold_retained": True,
        }
        if binding["index_eligible"]:
            if (
                row["status"] != "citable"
                or row["lane"] != "primary_authority"
                or int(row["retrieval_canonical"] or 0) != 1
                or row["duplicate_of"] is not None
                or int(row["body_chunk_count"] or 0) < 1
            ):
                raise ValueError("phase2a_final_apply_included_binding_invalid")
            included.append(
                _seal_record(
                    {
                        **common,
                        "disposition": "INCLUDE_IN_NON_ACTIVE_SUCCESSOR",
                        "candidate_included": True,
                        "source_kind": "OWNER_APPROVED_HELD_RESEARCH_SOURCE",
                    }
                )
            )
        else:
            if int(row["retrieval_canonical"] or 0) != 0:
                raise ValueError("phase2a_final_apply_excluded_binding_invalid")
            excluded.append(
                _seal_record(
                    {
                        **common,
                        "disposition": "HOLD_EXCLUDE",
                        "candidate_included": False,
                        "source_kind": ("OWNER_ADMITTED_PROVENANCE_COMPANION_EXCLUDED_FROM_INDEX"),
                        "exclusion_reason": "RAW_ECHR_COMPANION_CANONICAL_MARKDOWN_SELECTED",
                    }
                )
            )
    if (
        len(included) != EXPECTED_INDEX_REPRESENTATION_COUNT
        or len(excluded) != EXPECTED_PROVENANCE_COMPANION_COUNT
    ):
        raise ValueError("phase2a_final_apply_postcommit_binding_count_invalid")
    included_ids = sorted(item["source_version_id"] for item in included)
    included_set_sha = phase2a_dynamic_scope._source_version_set_sha256(included_ids)
    material = {
        "schema": phase2a_dynamic_scope.APPLICATION_LEDGER_SCHEMA,
        "status": "OWNER_DECISIONS_APPLIED_POST_SCAN_BINDINGS_READY",
        "phase2a_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
        "phase2a_owner_approval_receipt_content_sha256": (
            EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256
        ),
        "original_owner_receipt_content_sha256": EXPECTED_ORIGINAL_RECEIPT_CONTENT_SHA256,
        "execution_authority_content_sha256": EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256,
        "materialization_ledger_content_sha256": materialization_ledger["artifact_content_sha256"],
        "source_scan_id": plan["source_scan_id"],
        "source_scan_manifest_sha256": plan["source_scan_manifest_sha256"],
        "owner_decisions_applied": True,
        "exact_owner_decision_count": 361,
        "unresolved_owner_decision_count": 0,
        "material_gap_status": "NOT_EVALUATED_UNTIL_ALL585_QUALIFICATION",
        "included_binding_count": len(included),
        "included_source_version_ids": included_ids,
        "included_source_version_id_set_sha256": included_set_sha,
        "included_bindings": included,
        "excluded_binding_count": len(excluded),
        "excluded_bindings": excluded,
        "rejected_original_decision_ids": materialization_ledger["rejected_original_decision_ids"],
        "rejected_original_record_ids": materialization_ledger["rejected_original_record_ids"],
        "retained_repair_hold_decision_ids": materialization_ledger[
            "retained_repair_hold_decision_ids"
        ],
        "retained_repair_hold_record_ids": materialization_ledger[
            "retained_repair_hold_record_ids"
        ],
        "retained_original_quarantine_hold_count": materialization_ledger[
            "retained_original_quarantine_hold_count"
        ],
        "retained_original_identity_admission_hold_count": materialization_ledger[
            "retained_original_identity_admission_hold_count"
        ],
        "prior_frozen_scope_content_sha256": EXPECTED_PRIOR_SCOPE_CONTENT_SHA256,
        "prior_frozen_scope_source_count": EXPECTED_PRIOR_SCOPE_COUNT,
        "newly_admitted_index_source_count": len(included),
        "complete_successor_source_count": EXPECTED_FINAL_SUCCESSOR_SOURCE_COUNT,
        "complete_successor_union_policy": "EXACT_PRIOR_251_PLUS_EXACT_NEW_250",
        "support_crosswalk_requirement": materialization_ledger["support_crosswalk_requirement"],
        "source_materialized": True,
        "source_scan_run": True,
        "catalogue_mutated": True,
        "source_admission_applied": True,
        "successor_build_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "answer_model_run": False,
        "answer_release_eligible": False,
        "answer_released": False,
        "successor_must_remain_non_active": True,
        "phase2b_authorized": False,
        "phase2b_run": False,
        "development30_run": False,
        "validation30_run": False,
        "promotion_run": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
        "live_activation_run": False,
        "training_export_run": False,
    }
    ledger = {**material, "artifact_content_sha256": _sealed(material)}
    prestate_material = {
        "schema": "legalbot.v111.phase2a.final-remediation-catalogue-prestate.v1",
        "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
        "source_scan_id": plan["source_scan_id"],
        "record_count": len(prestate_records),
        "records": prestate_records,
    }
    prestate = {
        **prestate_material,
        "artifact_content_sha256": _sealed(prestate_material),
    }
    return ledger, prestate


def finalize_post_scan(
    *,
    catalogue_path: Path,
    materialization_ledger_path: Path,
    materialization_ledger_content_sha256: str,
    scan_id: str,
    scan_manifest_sha256: str,
    output_root: Path = POST_SCAN_OUTPUT_ROOT,
) -> dict[str, Any]:
    """Bind the exact scanned versions and seal the owner-application ledger."""

    _verify_final_approval()
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_final_apply_post_scan_output_exists")
    ledger_input = load_materialization_ledger(
        materialization_ledger_path,
        expected_content_sha256=materialization_ledger_content_sha256,
    )
    if _SHA256.fullmatch(scan_manifest_sha256) is None:
        raise ValueError("phase2a_final_apply_scan_manifest_invalid")
    connection = sqlite3.connect(catalogue_path)
    connection.row_factory = sqlite3.Row
    try:
        plan = build_post_scan_plan(
            connection,
            materialization_ledger=ledger_input,
            scan_id=scan_id,
            scan_manifest_sha256=scan_manifest_sha256,
        )
        _apply_post_scan_transaction(connection, plan=plan)
        ledger, prestate = _post_scan_ledger(
            connection, plan=plan, materialization_ledger=ledger_input
        )
    finally:
        connection.close()

    ledger_raw = _pretty_json(ledger)
    prestate_raw = _pretty_json(prestate)
    artifacts = {
        OWNER_APPLICATION_LEDGER_NAME: ledger_raw,
        PRESTATE_NAME: prestate_raw,
    }
    package_material = {
        "schema": "legalbot.v111.phase2a.owner-application-package.v1",
        "status": ledger["status"],
        "final_owner_packet_content_sha256": EXPECTED_FINAL_PACKET_CONTENT_SHA256,
        "final_approval_receipt_content_sha256": (EXPECTED_FINAL_APPROVAL_RECEIPT_CONTENT_SHA256),
        "owner_application_ledger_content_sha256": ledger["artifact_content_sha256"],
        "included_binding_count": ledger["included_binding_count"],
        "excluded_binding_count": ledger["excluded_binding_count"],
        "artifacts": [
            {"name": name, "file_sha256": _sha256(raw)} for name, raw in sorted(artifacts.items())
        ],
        "successor_build_run": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "phase2b_run": False,
        "active_pointer_written": False,
        "previous_pointer_written": False,
    }
    package = {
        **package_material,
        "artifact_content_sha256": _sealed(package_material),
    }
    package_raw = _pretty_json(package)
    artifacts[PACKAGE_NAME] = package_raw
    checksums_raw = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode()
    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.staging-", dir=output_root.parent))
    os.chmod(staging, 0o700)
    try:
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(staging / name, raw)
        _write_exclusive(staging / CHECKSUMS_NAME, checksums_raw)
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        _publish_noreplace(staging, output_root, code="phase2a_final_apply_post_scan_output_race")
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "status": ledger["status"],
        "output_name": output_root.name,
        "owner_application_ledger_content_sha256": ledger["artifact_content_sha256"],
        "owner_application_ledger_file_sha256": _sha256(ledger_raw),
        "included_binding_count": ledger["included_binding_count"],
        "excluded_binding_count": ledger["excluded_binding_count"],
        "source_scan_id": scan_id,
        "source_scan_manifest_sha256": scan_manifest_sha256,
        "successor_build_run": False,
        "embedding_run": False,
        "phase2b_run": False,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan")
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("--output-root", type=Path, default=MATERIALIZATION_OUTPUT_ROOT)
    materialize.add_argument("--materialized-root", type=Path, default=MATERIALIZED_ROOT)
    finalize = subparsers.add_parser("finalize-post-scan")
    finalize.add_argument("--catalogue", type=Path, required=True)
    finalize.add_argument("--materialization-ledger", type=Path, required=True)
    finalize.add_argument("--materialization-ledger-content-sha256", required=True)
    finalize.add_argument("--scan-id", required=True)
    finalize.add_argument("--scan-manifest-sha256", required=True)
    finalize.add_argument("--output-root", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "plan":
        plan = build_materialization_plan()
        result = {
            "status": plan["status"],
            "plan_content_sha256": plan["artifact_content_sha256"],
            "representation_count": plan["representation_count"],
            "index_eligible_representation_count": plan["index_eligible_representation_count"],
            "provenance_companion_count": plan["provenance_companion_count"],
            "materialized_source_root_relative_path": plan[
                "materialized_source_root_relative_path"
            ],
            "source_materialized": False,
        }
    elif args.command == "materialize":
        result = materialize_exact_sources(
            output_root=args.output_root.resolve(strict=False),
            materialized_root=args.materialized_root.resolve(strict=False),
        )
    else:
        result = finalize_post_scan(
            catalogue_path=args.catalogue.resolve(strict=True),
            materialization_ledger_path=args.materialization_ledger.resolve(strict=True),
            materialization_ledger_content_sha256=args.materialization_ledger_content_sha256,
            scan_id=args.scan_id,
            scan_manifest_sha256=args.scan_manifest_sha256,
            output_root=args.output_root.resolve(strict=False),
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
