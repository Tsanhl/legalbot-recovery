#!/usr/bin/env python3
"""Build the exact, create-only Phase-2A finite-remediation owner packet.

The packet combines three immutable remediation advisories for the exact 146
rows in the r3 prequalification blocker report.  Seventeen rows adopt only the
exact remedy proposed by their cohort advisory.  The other 129 rows retain
their material-gap identity and receive a proposed, row-specific terminal
human-review contract that cannot release a legal claim or invoke an answer
model.

This builder makes no owner decision and performs no source admission, scan,
index build, embedding, retrieval, qualification, pointer write, answer run or
Phase-2B action.  Its output exists only to obtain an exact owner decision.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

OUTPUT_ROOT_NAME = "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r3"
DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / OUTPUT_ROOT_NAME
CONTRACTS_NAME = "EXACT-146-ROW-FINITE-OUTCOME-CONTRACTS.json"
PACKET_NAME = "EXACT-PHASE2A-FINITE-REMEDIATION-OWNER-PACKET.json"
PROMPT_NAME = "OWNER-APPROVAL-PROMPT.txt"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

INPUTS: dict[str, dict[str, str]] = {
    "predecessor_r2_contracts": {
        "root": "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r2",
        "file": "EXACT-146-ROW-FINITE-OUTCOME-CONTRACTS.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "65c08285f9a35e0274f9ea2e621c8a8c45c02ffd14ad942f392df85f06765f5f",
        "file_sha256": "c6675c075f291f750e11408213827f7444e796685cd1966e39bd32465a124539",
    },
    "predecessor_r2_packet": {
        "root": "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r2",
        "file": "EXACT-PHASE2A-FINITE-REMEDIATION-OWNER-PACKET.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "9a84056b160f953f9073809c3519e22317370d04ec30887d0aeb20d2ca24e739",
        "file_sha256": "969d31783707ea406788cc9f265987ef5c95c8901b0b9dbd30b647b99a99f0fc",
    },
    "predecessor_r2_package": {
        "root": "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r2",
        "file": "PACKAGE-MANIFEST.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "dc20078290d785fdab582f40f5ea9d634792a20f7c813c4a202524e4c76bd920",
        "file_sha256": "1e6403def01be089ddb741531cdc0201351dab36e731f20520aafcd86a3371fd",
    },
    "predecessor_r1_contracts": {
        "root": "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r1",
        "file": "EXACT-146-ROW-FINITE-OUTCOME-CONTRACTS.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "97483887e654a76a2c326bde5c730b0afe9ad9c217965fe34b849ab746e81e40",
        "file_sha256": "8d0645796d59547b50f957e3836d266d8fd02c0b3d9fb39ebb7a51b869795f4f",
    },
    "predecessor_r1_packet": {
        "root": "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r1",
        "file": "EXACT-PHASE2A-FINITE-REMEDIATION-OWNER-PACKET.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "e8e2cd116510d75c3afa64263f4d032ece563f2cd7aa0fd949cefe6538e59844",
        "file_sha256": "dc604b0e1b3197e7ab82363988507a0542608517674a26791f2a65b247fe420a",
    },
    "predecessor_r1_package": {
        "root": "LegalBot-Phase2A-2026-08-28-finite-remediation-owner-packet-r1",
        "file": "PACKAGE-MANIFEST.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "d47c9007d251072cd803d52e02c290448743aff23ee621e1292dacee10e5912d",
        "file_sha256": "74501613b40e341b7a14f086e5e9fb467861744eaedd7e8e76b4d8c72fd31acc",
    },
    "prequalification": {
        "root": "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3",
        "file": "PREQUALIFICATION-BLOCKER-REPORT.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980",
        "file_sha256": "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899",
    },
    "prequalification_package": {
        "root": "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3",
        "file": "PACKAGE-MANIFEST.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "f53994654198592d9d8f26698386022a16dec123e035aba2673c8abbf6e7d47e",
        "file_sha256": "ec05e33793e762d7c787a567fb23a85ef7484245e09d3d5807d9bbd59d7ded31",
    },
    "source_ready": {
        "root": "LegalBot-Phase2A-2026-08-28-source-ready-59-corrective-advisory-r5",
        "file": "SOURCE-READY-59-CORRECTIVE-REMEDIATION-ADVISORY-R5.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "6c10fafd5b408cb9433412a1681ec85fe2316e59fab312a3472ca30a67ca32f9",
        "file_sha256": "45481c2fe89efbbb5916c6ddab5d86f6a74fbd02e3263bdd4ee2a9e1a7d48232",
    },
    "source_ready_package": {
        "root": "LegalBot-Phase2A-2026-08-28-source-ready-59-corrective-advisory-r5",
        "file": "PACKAGE-MANIFEST.json",
        "content_field": "manifest_content_sha256",
        "content_sha256": "789a39257e376937916d8b51964277b90fbf59479725d837bc06cf47c05d1ffc",
        "file_sha256": "51a97b526421cff22de834e264a018c3df0c59386418239018968f4206662bee",
    },
    "authorityless": {
        "root": "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r4",
        "file": "AUTHORITYLESS-COHORT-59-REMEDIATION-ADVISORY-R4.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "ac13025b77561fd0b02ab49e3d25f72b2eec137e65fd10aa1360d3725049cb68",
        "file_sha256": "327450b2ce6d71cef38937b5de5eff80c5e2c3b1e6c5188005b29ad708206305",
    },
    "authorityless_package": {
        "root": "LegalBot-Phase2A-2026-08-28-authorityless-cohort-59-remediation-advisory-r4",
        "file": "PACKAGE-MANIFEST.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "78d2ff0e1ef1a2157351e2dd202e8557db960caa64581ec640615fa349e3a41d",
        "file_sha256": "eaa3ca65bd5b1facf7309327a100ff45faf0b4e606d16320b0c5ca61c4bb5e33",
    },
    "held_missing": {
        "root": "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r3",
        "file": "EXACT-28-ROW-SUBSTANTIVE-REMEDIATION-ADVISORY-R3.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "1bb16cf7112a5ea7fcee5d947bea3edf70219278ce4506589ae93888d477978d",
        "file_sha256": "aa2f1b10f712ba4f8799326e6047bbd253b65ee8780547ed121800fac89e5f3d",
    },
    "held_missing_package": {
        "root": "LegalBot-Phase2A-2026-08-28-held-missing-28-substantive-remediation-advisory-r3",
        "file": "PACKAGE-MANIFEST.json",
        "content_field": "package_content_sha256",
        "content_sha256": "1d09e53f484f26cf9938d79458318b3dcbf3d270ce1bfd277d9364458eab99ad",
        "file_sha256": "cbd2b2aec49ee5c4890326c334875f0c233c2938d0495e72d036c5aee3273faa",
    },
    "owner_receipt": {
        "root": "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1",
        "file": "OWNER-ADOPTION-RECEIPT.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa",
        "file_sha256": "dcf5f5f33debcbecff17552e074a9c12437d7b8cd77d0879c7d19072156c3383",
    },
    "execution_authority": {
        "root": "LegalBot-Phase2A-2026-08-28-final-remediation-owner-approved-r1",
        "file": "PHASE2A-EXECUTION-AUTHORITY.json",
        "content_field": "artifact_content_sha256",
        "content_sha256": "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b",
        "file_sha256": "5171ce79007c68484f9854b5188bf7e7af8f880407b6fbad6e3f808d0c7630ad",
    },
}

READY_ROW_IDS_BY_COHORT = {
    "SOURCE_READY_R5": {
        "live30-q16:issue-02",
        "live30-q16:issue-03",
        "live30-q16:issue-04",
        "live30-q18:issue-02",
    },
    "AUTHORITYLESS_R4": {
        "live30-q12:issue-06",
        "live30-q16:issue-06",
        "live30-q30:issue-02",
        "live60-q47:issue-06",
        "live60-q57:issue-05",
        "live60-q58:issue-10",
        "live60-q59:issue-18",
    },
    "HELD_MISSING_R3": {
        "live30-q01:issue-01",
        "live30-q05:issue-07",
        "live60-q46:issue-05",
        "live60-q50:issue-06",
        "live60-q59:issue-15",
        "live60-q59:issue-17",
    },
}

COHORT_INPUT = {
    "SOURCE_READY_R5": "source_ready",
    "AUTHORITYLESS_R4": "authorityless",
    "HELD_MISSING_R3": "held_missing",
}

NO_EXECUTION_FLAGS = {
    "owner_approved": False,
    "owner_adoption_recorded": False,
    "owner_decision_application_authorized": False,
    "owner_decisions_applied": False,
    "owner_outcomes_applied": False,
    "source_delta_decisions_applied": False,
    "safe_fallback_decision_applied": False,
    "evaluation_contract_mutated": False,
    "source_admission_authorized": False,
    "source_admitted": False,
    "complete_source_scan_authorized": False,
    "source_scan_run": False,
    "successor_build_authorized": False,
    "successor_build_run": False,
    "index_build_authorized": False,
    "index_built": False,
    "embedding_authorized": False,
    "embedding_run": False,
    "automatic_indexing": False,
    "automatic_embedding": False,
    "candidate_mutated": False,
    "catalogue_mutated": False,
    "qualification_authorized": False,
    "qualification_run": False,
    "retrieval_reattestation_authorized": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_authorized": False,
    "all585_qualification_run": False,
    "technical_qualification_assigned": False,
    "answer_model_authorized": False,
    "answer_model_run": False,
    "answer_eligible": False,
    "answer_release_authorized": False,
    "answer_release_run": False,
    "answer_released": False,
    "phase2b_authorized": False,
    "phase2b_run": False,
    "development30_authorized": False,
    "development30_run": False,
    "owner_certification60_authorized": False,
    "owner_certification60_run": False,
    "o04_authorized": False,
    "o04_run": False,
    "validation30_authorized": False,
    "validation30_run": False,
    "validation30_unsealed": False,
    "promotion_authorized": False,
    "promotion_run": False,
    "active_pointer_write_authorized": False,
    "active_pointer_written": False,
    "previous_pointer_write_authorized": False,
    "previous_pointer_written": False,
    "live_activation_authorized": False,
    "live_activation_run": False,
    "training_export_authorized": False,
    "training_export_run": False,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ROW_ID_RE = re.compile(r"^(?:live30|live60)-q[0-9]{2}:issue-[0-9]{2}$")
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9+.-])/(?!/)[^\s'\"<>]*")
_HTTP_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _content_sha256(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _seal(value: Mapping[str, Any], field: str = "artifact_content_sha256") -> dict[str, Any]:
    material = dict(value)
    material.pop(field, None)
    return {**material, field: _content_sha256(material)}


def _require_seal(value: Mapping[str, Any], field: str, expected: str, code: str) -> None:
    material = dict(value)
    observed = str(material.pop(field, ""))
    if observed != expected or observed != _content_sha256(material):
        raise ValueError(code)


def _load_inputs(review_root: Path) -> dict[str, dict[str, Any]]:
    resolved_review = review_root.resolve(strict=True)
    output: dict[str, dict[str, Any]] = {}
    for name, spec in INPUTS.items():
        root = resolved_review / spec["root"]
        path = root / spec["file"]
        if (
            root.is_symlink()
            or not root.is_dir()
            or path.is_symlink()
            or not path.is_file()
            or path.resolve(strict=True).parent != root.resolve(strict=True)
            or _file_sha256(path) != spec["file_sha256"]
        ):
            raise ValueError(f"finite_packet_input_file_invalid:{name}")
        try:
            value = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"finite_packet_input_json_invalid:{name}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"finite_packet_input_shape_invalid:{name}")
        _require_seal(
            value,
            spec["content_field"],
            spec["content_sha256"],
            f"finite_packet_input_seal_invalid:{name}",
        )
        output[name] = value
    return output


def _require_embedded_seal(value: Mapping[str, Any], field: str, code: str) -> None:
    observed = str(value.get(field) or "")
    if _SHA256_RE.fullmatch(observed) is None:
        raise ValueError(code)
    material = dict(value)
    material.pop(field, None)
    if observed != _content_sha256(material):
        raise ValueError(code)


def _row_map(rows: Any, *, field: str, expected_count: int, code: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) != expected_count:
        raise ValueError(code)
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(code)
        row_id = str(row.get("row_id") or "")
        if _ROW_ID_RE.fullmatch(row_id) is None or row_id in result:
            raise ValueError(code)
        _require_embedded_seal(row, field, code)
        result[row_id] = row
    return result


def _verify_input_contracts(values: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    report = values["prequalification"]
    if (
        report.get("status") != "BLOCKED_BEFORE_SUCCESSOR_QUALIFICATION"
        or report.get("counts", {}).get("blocking_row_count") != 146
        or report.get("execution_chain", {}).get("status") != "AVAILABLE_UNSPENT"
        or report.get("execution_chain", {}).get("remaining_count") != 1
    ):
        raise ValueError("finite_packet_prequalification_contract_invalid")
    prequal_rows = _row_map(
        report.get("rows"),
        field="record_content_sha256",
        expected_count=146,
        code="finite_packet_prequalification_rows_invalid",
    )
    if (
        values["prequalification_package"].get("report_content_sha256")
        != INPUTS["prequalification"]["content_sha256"]
    ):
        raise ValueError("finite_packet_prequalification_package_binding_invalid")

    source = values["source_ready"]
    authority = values["authorityless"]
    held = values["held_missing"]
    source_rows = _row_map(
        source.get("row_advisories"),
        field="record_content_sha256",
        expected_count=59,
        code="finite_packet_source_rows_invalid",
    )
    authority_rows = _row_map(
        authority.get("row_advisories"),
        field="record_content_sha256",
        expected_count=59,
        code="finite_packet_authority_rows_invalid",
    )
    held_rows = _row_map(
        held.get("rows"),
        field="record_content_sha256",
        expected_count=28,
        code="finite_packet_held_rows_invalid",
    )
    cohort_rows = {
        "SOURCE_READY_R5": source_rows,
        "AUTHORITYLESS_R4": authority_rows,
        "HELD_MISSING_R3": held_rows,
    }
    row_sets = [set(item) for item in cohort_rows.values()]
    if any(
        left & right for index, left in enumerate(row_sets) for right in row_sets[index + 1 :]
    ) or set().union(*row_sets) != set(prequal_rows):
        raise ValueError("finite_packet_cohort_partition_invalid")

    source_ready_observed = set(
        source.get("whole_row_support_ready_for_owner_consideration_ids", [])
    )
    authority_ready_observed = {
        row_id
        for row_id, row in authority_rows.items()
        if row.get("legal_component_coverage_complete_after_exact_action_if_owner_adopted") is True
        and row.get("material_legal_support_gap") is False
    }
    held_ready_observed = {
        row_id
        for row_id, row in held_rows.items()
        if row.get("residual_qualification_blocker_predeclared") is False
    }
    observed = {
        "SOURCE_READY_R5": source_ready_observed,
        "AUTHORITYLESS_R4": authority_ready_observed,
        "HELD_MISSING_R3": held_ready_observed,
    }
    if observed != READY_ROW_IDS_BY_COHORT:
        raise ValueError("finite_packet_ready_row_set_invalid")
    ready = set().union(*observed.values())
    residual = set(prequal_rows) - ready
    if len(ready) != 17 or len(residual) != 129:
        raise ValueError("finite_packet_row_count_boundary_invalid")

    if (
        set(authority.get("residual_material_gap_row_ids", []))
        != set(authority_rows) - authority_ready_observed
        or set(held.get("residual_row_ids", [])) != set(held_rows) - held_ready_observed
        or source.get("counts", {}).get("residual_row_count")
        != len(set(source_rows) - source_ready_observed)
    ):
        raise ValueError("finite_packet_residual_row_set_invalid")
    if (
        values["source_ready_package"].get("advisory_content_sha256")
        != INPUTS["source_ready"]["content_sha256"]
        or values["authorityless_package"].get("advisory_content_sha256")
        != INPUTS["authorityless"]["content_sha256"]
    ):
        raise ValueError("finite_packet_cohort_package_binding_invalid")
    held_artifacts = values["held_missing_package"].get("artifacts")
    if not isinstance(held_artifacts, list) or not any(
        item.get("name") == INPUTS["held_missing"]["file"]
        and item.get("content_sha256") == INPUTS["held_missing"]["content_sha256"]
        and item.get("file_sha256") == INPUTS["held_missing"]["file_sha256"]
        for item in held_artifacts
        if isinstance(item, Mapping)
    ):
        raise ValueError("finite_packet_held_package_binding_invalid")

    authority_record = values["execution_authority"]
    if any(
        (
            authority_record.get("status") != "AVAILABLE_UNSPENT",
            authority_record.get("total_execution_chain_count") != 1,
            authority_record.get("execution_chain_consumed_count") != 0,
            authority_record.get("execution_chain_remaining_count") != 1,
            authority_record.get("new_or_additional_authority_created") is not False,
            authority_record.get("source_scan_run") is not False,
            authority_record.get("successor_build_run") is not False,
            authority_record.get("embedding_run") is not False,
            authority_record.get("retrieval_reattestation_run") is not False,
            authority_record.get("all585_qualification_run") is not False,
        )
    ):
        raise ValueError("finite_packet_execution_authority_not_unspent")
    if (
        values["owner_receipt"].get("execution_authority_content_sha256")
        != INPUTS["execution_authority"]["content_sha256"]
    ):
        raise ValueError("finite_packet_owner_receipt_binding_invalid")
    if (
        values["predecessor_r1_package"].get("packet_content_sha256")
        != INPUTS["predecessor_r1_packet"]["content_sha256"]
        or values["predecessor_r1_package"].get("contracts_content_sha256")
        != INPUTS["predecessor_r1_contracts"]["content_sha256"]
    ):
        raise ValueError("finite_packet_predecessor_r1_binding_invalid")
    if (
        values["predecessor_r2_package"].get("packet_content_sha256")
        != INPUTS["predecessor_r2_packet"]["content_sha256"]
        or values["predecessor_r2_package"].get("contracts_content_sha256")
        != INPUTS["predecessor_r2_contracts"]["content_sha256"]
    ):
        raise ValueError("finite_packet_predecessor_r2_binding_invalid")

    return {
        "prequalification_rows": prequal_rows,
        "cohort_rows": cohort_rows,
        "ready_row_ids": ready,
        "residual_row_ids": residual,
    }


def _walk_values(value: Any, key: str) -> set[str]:
    found: set[str] = set()
    if isinstance(value, Mapping):
        for current_key, nested in value.items():
            if current_key == key and isinstance(nested, str):
                found.add(nested)
            found.update(_walk_values(nested, key))
    elif isinstance(value, list | tuple):
        for nested in value:
            found.update(_walk_values(nested, key))
    return found


def _recommendation_hashes(cohort: str, row: Mapping[str, Any]) -> list[str]:
    if cohort in {"SOURCE_READY_R5", "AUTHORITYLESS_R4"}:
        records = row.get("component_recommendations", [])
    else:
        records = row.get("blocker_recommendations", [])
    digests = {
        str(record["recommendation_content_sha256"])
        for record in records
        if isinstance(record, Mapping) and record.get("recommendation_content_sha256")
    }
    if not digests or any(_SHA256_RE.fullmatch(item) is None for item in digests):
        raise ValueError(f"finite_packet_recommendation_hashes_invalid:{row['row_id']}")
    return sorted(digests)


def _source_action(binding: Mapping[str, Any]) -> str:
    if binding.get("candidate_identity_verified") is True or (
        binding.get("source_version_id") and not binding.get("proposed_source_version_id")
    ):
        return "RETAIN_EXISTING_EXACT_SOURCE_VERSION"
    if binding.get("source_admitted_by_r3") is True:
        return "RETAIN_PREVIOUSLY_ADOPTED_SOURCE_VERSION"
    if binding.get("source_origin") == "EXACT_OWNER_ADOPTED_MATERIALIZATION_PLAN":
        return "MATERIALIZE_AND_ADMIT_EXACT_BOUND_REPRESENTATION"
    if (
        binding.get("proposed_source_version_id")
        or binding.get("source_admission_recommended") is True
    ):
        return "ADMIT_EXACT_BOUND_REPRESENTATION"
    return "RETAIN_EXACT_BOUND_SOURCE_RECORD_NO_NEW_ADMISSION"


def _ready_source_decisions(
    values: Mapping[str, Mapping[str, Any]],
    cohort_rows: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    sources_by_cohort: dict[str, dict[str, Mapping[str, Any]]] = {
        "AUTHORITYLESS_R4": {
            str(item["record_content_sha256"]): item
            for item in values["authorityless"].get("source_byte_bindings", [])
            if isinstance(item, Mapping)
        },
        "HELD_MISSING_R3": {
            str(item["record_content_sha256"]): item
            for item in values["held_missing"].get("source_bindings", [])
            if isinstance(item, Mapping)
        },
    }
    action_precedence = {
        "RETAIN_EXACT_BOUND_SOURCE_RECORD_NO_NEW_ADMISSION": 1,
        "ADMIT_EXACT_BOUND_REPRESENTATION": 2,
        "MATERIALIZE_AND_ADMIT_EXACT_BOUND_REPRESENTATION": 3,
        "RETAIN_PREVIOUSLY_ADOPTED_SOURCE_VERSION": 4,
        "RETAIN_EXISTING_EXACT_SOURCE_VERSION": 5,
    }
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for cohort in ("AUTHORITYLESS_R4", "HELD_MISSING_R3"):
        source_map = sources_by_cohort[cohort]
        for row_id in sorted(READY_ROW_IDS_BY_COHORT[cohort]):
            row = cohort_rows[cohort][row_id]
            for digest in sorted(_walk_values(row, "source_binding_content_sha256")):
                binding = source_map.get(digest)
                if binding is None:
                    raise ValueError(
                        f"finite_packet_ready_source_binding_missing:{row_id}:{digest}"
                    )
                _require_embedded_seal(
                    binding,
                    "record_content_sha256",
                    f"finite_packet_ready_source_binding_seal_invalid:{row_id}:{digest}",
                )
                action = _source_action(binding)
                source_version_id = binding.get("source_version_id") or binding.get(
                    "proposed_source_version_id"
                )
                representation_file_sha256 = binding.get("representation_file_sha256")
                identity = (
                    str(source_version_id or f"binding:{digest}"),
                    str(representation_file_sha256 or f"binding:{digest}"),
                )
                binding_reference = _seal(
                    {
                        "schema": (
                            "legalbot.v111.phase2a.finite-remediation-source-binding-reference.v1"
                        ),
                        "cohort": cohort,
                        "source_binding_record_content_sha256": digest,
                        "cohort_proposed_action": action,
                    },
                    "binding_reference_content_sha256",
                )
                canonical = {
                    str(item)
                    for item in (
                        binding.get("canonical_content_sha256"),
                        binding.get("canonical_object_sha256"),
                    )
                    if _SHA256_RE.fullmatch(str(item or "")) is not None
                }
                normalized = {
                    str(item)
                    for item in (binding.get("normalized_representation_text_sha256"),)
                    if _SHA256_RE.fullmatch(str(item or "")) is not None
                }
                current = by_identity.get(identity)
                if current is None:
                    material = {
                        "schema": "legalbot.v111.phase2a.finite-remediation-source-decision.r3.v1",
                        "cohorts": [cohort],
                        "source_binding_record_content_sha256s": [digest],
                        "binding_record_references": [binding_reference],
                        "authority_identity_ids": [binding.get("authority_identity_id")],
                        "source_version_id": source_version_id,
                        "representation_file_sha256": representation_file_sha256,
                        "canonical_content_sha256s": sorted(canonical),
                        "normalized_representation_text_sha256s": sorted(normalized),
                        "proposed_action": action,
                        "referenced_by_ready_row_ids": [row_id],
                        "answer_release_eligible": False,
                        "owner_adoption_required_before_action": True,
                        "applied": False,
                    }
                else:
                    material = dict(current)
                    material.pop("source_decision_content_sha256", None)
                    material["cohorts"] = sorted({*material["cohorts"], cohort})
                    material["source_binding_record_content_sha256s"] = sorted(
                        {*material["source_binding_record_content_sha256s"], digest}
                    )
                    references = {
                        item["binding_reference_content_sha256"]: item
                        for item in material["binding_record_references"]
                    }
                    references[binding_reference["binding_reference_content_sha256"]] = (
                        binding_reference
                    )
                    material["binding_record_references"] = [
                        references[item] for item in sorted(references)
                    ]
                    material["authority_identity_ids"] = sorted(
                        {
                            *material["authority_identity_ids"],
                            binding.get("authority_identity_id"),
                        }
                    )
                    material["canonical_content_sha256s"] = sorted(
                        {*material["canonical_content_sha256s"], *canonical}
                    )
                    material["normalized_representation_text_sha256s"] = sorted(
                        {*material["normalized_representation_text_sha256s"], *normalized}
                    )
                    material["referenced_by_ready_row_ids"] = sorted(
                        {*material["referenced_by_ready_row_ids"], row_id}
                    )
                    if action_precedence[action] > action_precedence[material["proposed_action"]]:
                        material["proposed_action"] = action
                action = str(material["proposed_action"])
                if action in {
                    "ADMIT_EXACT_BOUND_REPRESENTATION",
                    "MATERIALIZE_AND_ADMIT_EXACT_BOUND_REPRESENTATION",
                } and (
                    _SHA256_RE.fullmatch(str(material["representation_file_sha256"] or "")) is None
                    or not str(material["source_version_id"] or "").strip()
                    or not (
                        material["canonical_content_sha256s"]
                        or material["normalized_representation_text_sha256s"]
                    )
                ):
                    raise ValueError(
                        f"finite_packet_admission_identity_incomplete:{row_id}:{digest}"
                    )
                by_identity[identity] = _seal(material, "source_decision_content_sha256")
    return sorted(
        by_identity.values(),
        key=lambda item: (
            str(item["source_version_id"]),
            str(item["representation_file_sha256"]),
            item["source_decision_content_sha256"],
        ),
    )


def _residual_component_identities(
    cohort: str,
    row: Mapping[str, Any],
    advisory: Mapping[str, Any],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if cohort == "SOURCE_READY_R5":
        for item in row.get("component_recommendations", []):
            action = str(item.get("action") or "")
            if item.get("material_gap_if_exact_contract_adopted") is True or action.startswith(
                "RETAIN_BLOCKER"
            ):
                result.append(
                    {
                        "component_ordinal": item["component_ordinal"],
                        "proposition_text_sha256": item["before_proposition_text_sha256"],
                        "upstream_support_fit": item["upstream_support_fit"],
                        "cohort_recommendation_content_sha256": item[
                            "recommendation_content_sha256"
                        ],
                    }
                )
    elif cohort == "AUTHORITYLESS_R4":
        result = [
            dict(item)
            for item in advisory.get("residual_blocking_components", [])
            if item.get("row_id") == row["row_id"]
        ]
        if not result:
            for hold_kind, field in (
                ("ROW_ISSUE_DIMENSION_COVERAGE_HOLD", "row_issue_dimension_coverage_holds"),
                ("SOURCE_BINDING_MATERIAL_HOLD", "source_binding_material_holds"),
            ):
                for hold in row.get(field, []):
                    _require_embedded_seal(
                        hold,
                        "record_content_sha256",
                        f"finite_packet_authority_residual_hold_seal_invalid:{row['row_id']}",
                    )
                    result.append(
                        {
                            "residual_kind": hold_kind,
                            "hold_code": hold.get("code"),
                            "hold_record_content_sha256": hold["record_content_sha256"],
                        }
                    )
    else:
        for item in row.get("blocker_recommendations", []):
            if item.get("residual_qualification_blocker") is True:
                result.append(
                    {
                        "component_ordinal": item["component_ordinal"],
                        "proposition_text_sha256": item["baseline_proposition_text_sha256"],
                        "upstream_support_fit": item["baseline_support_fit"],
                        "cohort_recommendation_content_sha256": item[
                            "recommendation_content_sha256"
                        ],
                    }
                )
    if not result:
        raise ValueError(f"finite_packet_residual_components_missing:{row['row_id']}")
    return sorted(
        result,
        key=lambda item: (
            int(item.get("component_ordinal", 0)),
            str(item.get("hold_record_content_sha256", "")),
        ),
    )


def _handoff_message(row_id: str) -> str:
    return (
        f"I cannot provide a reliable legal answer to issue {row_id} because the required "
        "legal authority or issue-specific evidence is incomplete. Please provide or verify "
        "every item in the review request and request review by a qualified human legal "
        "professional. No legal conclusion, rule, advice, citation, EvidenceSpan, source "
        "binding, or answer-model output is provided."
    )


def _handoff_contract(
    *,
    row_id: str,
    prequal_row: Mapping[str, Any],
    residual_components: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    requested = [
        {
            "hold_text": item["hold_text"],
            "hold_text_sha256": item["hold_text_sha256"],
            "prequalification_hold_record_content_sha256": item["record_content_sha256"],
            "semantic_classification": "UNCLASSIFIED_NOT_CHANGED_BY_THIS_PACKET",
        }
        for item in prequal_row.get("unclassified_unresolved_holds", [])
    ]
    if not requested:
        raise ValueError(f"finite_packet_review_items_missing:{row_id}")
    message = _handoff_message(row_id)
    material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.strict-legal-gap-human-review-handoff.v1",
        "row_id": row_id,
        "prequalification_row_record_content_sha256": prequal_row["record_content_sha256"],
        "reason_code": "LEGAL_EVIDENCE_OR_REVIEW_GAP",
        "ui_cta_code": "REQUEST_QUALIFIED_HUMAN_LEGAL_REVIEW",
        "knowledge_gap_event": True,
        "matter_information_gap_event": False,
        "matter_information_classification": "NOT_DETERMINED_FROM_UNCLASSIFIED_HOLD_TEXT",
        "requested_review_items": requested,
        "residual_blocking_components": list(residual_components),
        "required_user_message": message,
        "required_user_message_sha256": _sha256(message.encode()),
        "reply_match_mode": "EXACT_UTF8_STRING",
        "offer_qualified_human_legal_review": True,
        "legal_claim_released": False,
        "legal_rule_released": False,
        "legal_advice_released": False,
        "citation_released": False,
        "evidence_span_released": False,
        "source_binding_released": False,
        "answer_model_output_allowed": False,
        "answer_release_eligible": False,
        "material_gap_erased_or_relabelled": False,
        "terminal_route_if_owner_adopted": "SAFE_HANDOFF_NOT_EVIDENCE_SUPPORTED_ANSWER",
        "owner_adoption_required_before_application": True,
        "applied": False,
    }
    return _seal(material, "handoff_contract_content_sha256")


def _row_outcomes(
    values: Mapping[str, Mapping[str, Any]],
    verified: Mapping[str, Any],
    source_decisions: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    prequal_rows = verified["prequalification_rows"]
    cohort_rows = verified["cohort_rows"]
    source_decisions_by_row: dict[str, list[str]] = {}
    for decision in source_decisions:
        for row_id in decision["referenced_by_ready_row_ids"]:
            source_decisions_by_row.setdefault(row_id, []).append(
                decision["source_decision_content_sha256"]
            )
    cohort_by_row = {row_id: cohort for cohort, rows in cohort_rows.items() for row_id in rows}
    outcomes: list[dict[str, Any]] = []
    for row_id in sorted(prequal_rows):
        cohort = cohort_by_row[row_id]
        row = cohort_rows[cohort][row_id]
        input_name = COHORT_INPUT[cohort]
        base: dict[str, Any] = {
            "schema": "legalbot.v111.phase2a.finite-remediation-row-outcome.v1",
            "row_id": row_id,
            "prequalification_row_record_content_sha256": prequal_rows[row_id][
                "record_content_sha256"
            ],
            "cohort": cohort,
            "cohort_advisory_content_sha256": INPUTS[input_name]["content_sha256"],
            "cohort_row_record_content_sha256": row["record_content_sha256"],
            "answer_release_eligible": False,
            "owner_adoption_required_before_application": True,
            "applied": False,
        }
        if row_id in verified["ready_row_ids"]:
            if cohort == "SOURCE_READY_R5":
                kind = "EXACT_MATTER_INFORMATION_NON_ANSWER"
                contracts = [
                    {
                        "reason_code": item["proposed_non_answer_contract"]["reason_code"],
                        "ui_cta_code": item["proposed_non_answer_contract"]["ui_cta_code"],
                        "exact_non_answer_response_sha256": item["proposed_non_answer_contract"][
                            "exact_non_answer_response_sha256"
                        ],
                    }
                    for item in row["component_recommendations"]
                ]
            elif cohort == "AUTHORITYLESS_R4":
                kind = "EXACT_REWRITE_EXCLUSION_OR_MATTER_INTAKE_SPLIT"
                contracts = []
            else:
                kind = "EXACT_SOURCE_BOUND_REMEDIATION_OR_EXCLUSION"
                contracts = []
            base.update(
                {
                    "selected_outcome": "ADOPT_EXACT_COHORT_REMEDIATION",
                    "cohort_remediation_kind": kind,
                    "cohort_recommendation_content_sha256s": _recommendation_hashes(cohort, row),
                    "exact_non_answer_contract_bindings": contracts,
                    "source_decision_content_sha256s": sorted(
                        source_decisions_by_row.get(row_id, [])
                    ),
                    "qualification_effect_if_owner_adopted": (
                        "COHORT_REMEDIATION_APPLIED; SUCCESSOR_TECHNICAL_QUALIFICATION_REQUIRED"
                    ),
                    "technical_success_predeclared": False,
                }
            )
        else:
            residual_components = _residual_component_identities(cohort, row, values[input_name])
            handoff = _handoff_contract(
                row_id=row_id,
                prequal_row=prequal_rows[row_id],
                residual_components=residual_components,
            )
            base.update(
                {
                    "selected_outcome": "STRICT_NO_LEGAL_CLAIM_HUMAN_REVIEW_HANDOFF",
                    "residual_material_gap_retained": True,
                    "partial_cohort_recommendations_not_adopted_by_this_outcome": True,
                    "new_source_admission_for_this_row": False,
                    "handoff_contract": handoff,
                    "qualification_effect_if_owner_adopted": (
                        "SAFE_HANDOFF_CONTRACT_MAY_PASS; ROW_IS_NOT_EVIDENCE_SUPPORTED_OR_ANSWER_ELIGIBLE"
                    ),
                    "technical_success_predeclared": False,
                }
            )
        outcomes.append(_seal(base, "row_outcome_content_sha256"))
    return outcomes


def _validate_no_execution(value: Any) -> None:
    if isinstance(value, Mapping):
        forbidden = {
            "automatic_fallback",
            "blanket_fallback",
            "default_fallback",
            "fallback_all",
            "fallback_all_rows",
            "fallback_by_default",
            "fallback_row_range",
            "fallback_wildcard",
        }
        for key, nested in value.items():
            if key in NO_EXECUTION_FLAGS and nested is not False:
                raise ValueError(f"finite_packet_no_execution_boundary_invalid:{key}")
            if key in forbidden and nested is not False:
                raise ValueError(f"finite_packet_blanket_fallback_prohibited:{key}")
            _validate_no_execution(nested)
    elif isinstance(value, list | tuple):
        for nested in value:
            _validate_no_execution(nested)


def _privacy_check(value: Any) -> None:
    def visit(item: Any, key: str) -> None:
        if isinstance(item, Mapping):
            for nested_key, nested in item.items():
                visit(nested, str(nested_key))
        elif isinstance(item, list | tuple):
            for nested in item:
                visit(nested, key)
        elif isinstance(item, str):
            if _EMAIL_RE.search(item):
                raise ValueError("finite_packet_privacy_email_invalid")
            without_http_urls = _HTTP_URL_RE.sub("", item)
            if _ABSOLUTE_PATH_RE.search(without_http_urls) and key not in {
                "official_url",
                "official_urls",
            }:
                raise ValueError("finite_packet_privacy_absolute_path_invalid")

    visit(value, "value")


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


def _publish_directory_noreplace(staging: Path, output: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    sys_platform = sys.platform
    source = os.fsencode(staging)
    target = os.fsencode(output)
    if sys_platform == "darwin" and hasattr(libc, "renamex_np"):
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        result = fn(source, target, 0x00000004)
    elif sys_platform.startswith("linux") and hasattr(libc, "renameat2"):
        fn = libc.renameat2
        fn.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        fn.restype = ctypes.c_int
        result = fn(-100, source, -100, target, 0x00000001)
    else:
        raise RuntimeError("finite_packet_atomic_noreplace_unavailable")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise ValueError("finite_packet_output_already_exists")
    raise OSError(error_number, "finite_packet_atomic_publish_failed")


def _row_set_sha256(row_ids: Sequence[str]) -> str:
    return _content_sha256(
        {"schema": "legalbot.v111.phase2a.row-id-set.v1", "row_ids": sorted(row_ids)}
    )


def build_packet(
    *,
    review_root: Path = REVIEW_ROOT,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    output_review_root: Path = REVIEW_ROOT,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Create the immutable owner-review packet without applying it."""

    timestamp = created_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("finite_packet_created_at_must_be_timezone_aware")
    output_base = output_review_root.resolve(strict=True)
    output = output_root.parent.resolve(strict=True) / output_root.name
    if output.exists() or output.is_symlink():
        raise ValueError("finite_packet_output_already_exists")
    if not output.name or not output.is_relative_to(output_base):
        raise ValueError("finite_packet_output_outside_review_root")

    values = _load_inputs(review_root)
    verified = _verify_input_contracts(values)
    source_decisions = _ready_source_decisions(values, verified["cohort_rows"])
    outcomes = _row_outcomes(values, verified, source_decisions)
    ready_ids = sorted(verified["ready_row_ids"])
    residual_ids = sorted(verified["residual_row_ids"])

    contracts_material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.finite-remediation-146-row-contracts.v1",
        "status": "EXACT_CREATE_ONLY_OWNER_REVIEW_REQUIRED",
        "created_at": timestamp.astimezone(UTC).isoformat(),
        "phase_scope": "PHASE2A_ONLY",
        "supersedes_r2_contracts_content_sha256": INPUTS["predecessor_r2_contracts"][
            "content_sha256"
        ],
        "also_supersedes_unapproved_r1_contracts_content_sha256": INPUTS[
            "predecessor_r1_contracts"
        ]["content_sha256"],
        "r2_correction_fingerprint": (
            "R2_CROSS_COHORT_DUPLICATE_SOURCE_VERSION_AND_RAW_BYTES_ACTION"
        ),
        "prequalification_report_content_sha256": INPUTS["prequalification"]["content_sha256"],
        "blocker_row_id_set_sha256": values["prequalification"]["blocker_row_id_set_sha256"],
        "row_count": 146,
        "exact_cohort_remediation_row_count": 17,
        "strict_human_review_handoff_row_count": 129,
        "exact_cohort_remediation_row_id_set_sha256": _row_set_sha256(ready_ids),
        "strict_human_review_handoff_row_id_set_sha256": _row_set_sha256(residual_ids),
        "row_outcomes": outcomes,
        "source_decisions": source_decisions,
        "owner_adoption_required_before_any_application": True,
        "technical_success_not_predeclared": True,
        **NO_EXECUTION_FLAGS,
    }
    contracts = _seal(contracts_material)
    contracts_raw = _pretty_json(contracts)

    input_bindings = [
        {
            "kind": name,
            "root_name": spec["root"],
            "file_name": spec["file"],
            "content_sha256": spec["content_sha256"],
            "file_sha256": spec["file_sha256"],
        }
        for name, spec in sorted(INPUTS.items())
    ]
    source_action_counts: dict[str, int] = {}
    for decision in source_decisions:
        action = str(decision["proposed_action"])
        source_action_counts[action] = source_action_counts.get(action, 0) + 1
    packet_material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.finite-remediation-owner-packet.v1",
        "status": "EXACT_OWNER_APPROVAL_REQUIRED_NO_EXECUTION",
        "created_at": timestamp.astimezone(UTC).isoformat(),
        "route": "OWNER_ADOPTED_INTERNAL_PRIVATE_RESEARCH_TOOL",
        "phase_scope": "PHASE2A_ONLY",
        "supersedes_r2_packet_content_sha256": INPUTS["predecessor_r2_packet"]["content_sha256"],
        "also_supersedes_unapproved_r1_packet_content_sha256": INPUTS["predecessor_r1_packet"][
            "content_sha256"
        ],
        "correction_scope": {
            "fingerprint": "R2_CROSS_COHORT_DUPLICATE_SOURCE_VERSION_AND_RAW_BYTES_ACTION",
            "r1_was_create_only_and_not_owner_adopted": True,
            "r1_must_not_be_approved_or_executed": True,
            "r2_was_create_only_and_not_owner_adopted": True,
            "r2_must_not_be_approved_or_executed": True,
            "r3_deduplicates_source_actions_by_source_version_and_raw_byte_identity": True,
            "r3_retains_every_cross_cohort_binding_record_reference": True,
            "row_outcome_partition_unchanged": True,
        },
        "input_bindings": input_bindings,
        "contracts_content_sha256": contracts["artifact_content_sha256"],
        "contracts_file_sha256": _sha256(contracts_raw),
        "counts": {
            "prequalification_blocker_row_count": 146,
            "exact_cohort_remediation_row_count": 17,
            "strict_human_review_handoff_row_count": 129,
            "new_exact_matter_information_non_answer_row_count": 4,
            "exact_rewrite_exclusion_or_matter_intake_split_row_count": 7,
            "exact_source_bound_remediation_or_exclusion_row_count": 6,
            "ready_source_decision_count": len(source_decisions),
            "ready_source_action_counts": source_action_counts,
        },
        "exact_scope_change": {
            "changes_phase2a_evaluation_contract": True,
            "old_no_other_fallback_boundary_superseded_only_for_exact_rows_in_contracts": True,
            "automatic_blanket_range_or_wildcard_handoff": False,
            "material_gaps_erased_relabelled_or_claimed_resolved": False,
            "strict_handoff_can_pass_only_as_safe_route_not_as_evidence_supported_answer": True,
            "knowledge_gap_event_required_for_each_of_129_handoff_rows": True,
            "answer_model_and_all_legal_output_prohibited_for_each_handoff_row": True,
        },
        "source_boundary": {
            "only_source_decisions_sealed_in_contracts_may_be_applied": True,
            "residual_handoff_rows_create_no_new_source_admission": True,
            "raw_or_canonical_bytes_must_match_bound_source_record_before_action": True,
            "mismatch_requires_stop_without_substitution": True,
        },
        "single_existing_execution_chain": {
            "execution_authority_content_sha256": INPUTS["execution_authority"]["content_sha256"],
            "total_count": 1,
            "consumed_count": 0,
            "remaining_count": 1,
            "status": "AVAILABLE_UNSPENT",
            "this_packet_consumes_chain": False,
            "this_packet_creates_second_chain": False,
        },
        "future_execution_if_exactly_owner_adopted": {
            "apply_only_exact_146_row_contracts": True,
            "apply_only_exact_source_decisions": True,
            "one_complete_source_scan": True,
            "one_non_active_successor_build_and_embedding": True,
            "one_retrieval_reattestation": True,
            "one_all585_technical_qualification": True,
            "answer_run_or_release": False,
            "phase2b": False,
            "development30": False,
            "validation30": False,
            "promotion_or_pointer_write": False,
            "technical_success_predeclared": False,
            "stop_on_contract_violation_or_remaining_unclassified_outcome": True,
        },
        "owner_adoption_required_before_any_application_or_execution": True,
        "packet_builder_effect": "CREATE_ONLY_NO_EXECUTION",
        **NO_EXECUTION_FLAGS,
    }
    packet = _seal(packet_material)
    packet_raw = _pretty_json(packet)

    prompt = f"""I approve exact Phase-2A finite-remediation R3 owner packet content SHA-256
`{packet["artifact_content_sha256"]}` and exact 146-row outcome-contract content SHA-256
`{contracts["artifact_content_sha256"]}` in full.

I understand that this R3 supersedes non-authorizing R2 packet `{INPUTS["predecessor_r2_packet"]["content_sha256"]}` and non-authorizing R1 packet `{INPUTS["predecessor_r1_packet"]["content_sha256"]}`; neither R1 nor R2 is approved, and neither may be executed.

I adopt only the 17 exact cohort-remediation row outcomes and only the exact source decisions sealed in that contract artifact. I also adopt the 129 row-specific `STRICT_NO_LEGAL_CLAIM_HUMAN_REVIEW_HANDOFF` contracts as an explicit Phase-2A evaluation-contract supersession. Those 129 rows remain recorded as legal-evidence or review gaps; they may pass only as safe terminal handoffs, never as evidence-supported or answer-eligible rows. Each must emit reason code `LEGAL_EVIDENCE_OR_REVIEW_GAP`, UI CTA `REQUEST_QUALIFIED_HUMAN_LEGAL_REVIEW`, `knowledge_gap_event=true`, and its exact byte-for-byte response. It must release no legal conclusion, rule, advice, citation, EvidenceSpan, source binding or answer-model output. No wildcard, range, default or blanket handoff is authorized.

I authorize Codex to use the one existing unspent Phase-2A execution chain bound by `{INPUTS["execution_authority"]["content_sha256"]}` to apply only these exact decisions; materialize or admit only source records whose sealed proposed action requires it and only after exact byte/content/source-version verification; run one complete source scan; build and embed one non-ACTIVE and answer-ineligible successor; run one retrieval re-attestation; and run one all-585 technical qualification. This creates no second execution chain.

Technical success is not predeclared. Any contract mismatch, source-identity mismatch, unclassified row outcome, retrieval failure or all-585 failure must stop the workflow and be reported honestly. This approval does not authorize an answer-model run or answer release, Phase 2B, Development 30, Validation 30, Owner Certification 60, promotion, ACTIVE/PREVIOUS writes, live activation or training export.

Owner typed name:
Decision date:
"""
    prompt_raw = prompt.encode()

    package_material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.finite-remediation-owner-package.v1",
        "status": "EXACT_OWNER_APPROVAL_REQUIRED_NO_EXECUTION",
        "packet_content_sha256": packet["artifact_content_sha256"],
        "contracts_content_sha256": contracts["artifact_content_sha256"],
        "row_count": 146,
        "exact_cohort_remediation_row_count": 17,
        "strict_human_review_handoff_row_count": 129,
        "supersedes_r2_packet_content_sha256": INPUTS["predecessor_r2_packet"]["content_sha256"],
        "supersedes_r2_contracts_content_sha256": INPUTS["predecessor_r2_contracts"][
            "content_sha256"
        ],
        "also_supersedes_unapproved_r1_packet_content_sha256": INPUTS["predecessor_r1_packet"][
            "content_sha256"
        ],
        "artifacts": [
            {
                "name": CONTRACTS_NAME,
                "content_sha256": contracts["artifact_content_sha256"],
                "file_sha256": _sha256(contracts_raw),
            },
            {
                "name": PACKET_NAME,
                "content_sha256": packet["artifact_content_sha256"],
                "file_sha256": _sha256(packet_raw),
            },
            {"name": PROMPT_NAME, "file_sha256": _sha256(prompt_raw)},
        ],
        "single_existing_execution_chain_preserved": True,
        "packet_builder_effect": "CREATE_ONLY_NO_EXECUTION",
        **NO_EXECUTION_FLAGS,
    }
    package = _seal(package_material)
    package_raw = _pretty_json(package)
    artifacts = {
        CONTRACTS_NAME: contracts_raw,
        PACKET_NAME: packet_raw,
        PROMPT_NAME: prompt_raw,
        PACKAGE_NAME: package_raw,
    }
    checksums_raw = "".join(
        f"{_sha256(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode()

    _validate_no_execution([contracts, packet, package])
    _privacy_check([contracts, packet, package, prompt])

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent))
    os.chmod(staging, 0o700)
    try:
        for name, raw in sorted(artifacts.items()):
            _write_exclusive(staging / name, raw)
        _write_exclusive(staging / CHECKSUMS_NAME, checksums_raw)
        for path in staging.iterdir():
            os.chmod(path, 0o600)
        _publish_directory_noreplace(staging, output)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise

    return {
        "status": packet["status"],
        "output_name": output.name,
        "packet_content_sha256": packet["artifact_content_sha256"],
        "packet_file_sha256": _sha256(packet_raw),
        "contracts_content_sha256": contracts["artifact_content_sha256"],
        "contracts_file_sha256": _sha256(contracts_raw),
        "package_content_sha256": package["artifact_content_sha256"],
        "package_file_sha256": _sha256(package_raw),
        "owner_approval_prompt_file_sha256": _sha256(prompt_raw),
        "row_count": 146,
        "exact_cohort_remediation_row_count": 17,
        "strict_human_review_handoff_row_count": 129,
        "source_decision_count": len(source_decisions),
        "execution_chain_consumed": False,
        "source_scan_run": False,
        "index_built": False,
        "embedding_run": False,
        "retrieval_reattestation_run": False,
        "all585_qualification_run": False,
        "phase2b_run": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    result = build_packet(output_root=args.output_root.resolve(strict=False))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
