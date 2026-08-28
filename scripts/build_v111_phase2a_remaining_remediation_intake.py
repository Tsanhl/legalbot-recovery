#!/usr/bin/env python3
"""Seal the post-blocked Phase-2A remediation intake without taking decisions.

This builder is deliberately non-authorizing.  It binds the final blocked
delivery, normalises the remaining issue/source/policy queues, records known
integrity discrepancies, and stops before legal judgment, source admission,
indexing, embedding, a successor build, or Phase 2B.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
BLOCKED_ROOT = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
MACHINE_ROOT = BLOCKED_ROOT / "machine"
DEFAULT_OUTPUT = OWNER_ROOT / "LegalBot-Phase2A-2026-08-27-remaining-remediation-intake-r1"

EXPECTED_BLOCKED_DELIVERY_SHA256 = (
    "b72f7c14740ad1624cb0a86cf0da070a3349203369001a92d6f2c6f467d6d1d2"
)
EXPECTED_STATUS_COUNTS = {
    "BLOCKED_MATERIAL_GAP": 98,
    "OWNER_DECISION_REQUIRED": 263,
    "TECHNICALLY_EVIDENCE_READY_FOR_OWNER_ADOPTION": 224,
}


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required immutable input unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"required immutable input is not an object: {path.name}")
    return value


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(data)


def _write_new_json(path: Path, value: Any) -> None:
    _write_new(path, _canonical_json(value))


def _sealed(payload: dict[str, Any], *, field: str) -> dict[str, Any]:
    result = dict(payload)
    result[field] = _sha256_bytes(_canonical_json(result))
    return result


def _relative(path: Path) -> str:
    return str(path.relative_to(PROJECT_ROOT))


def _row_map(value: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    rows = value.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"input list missing: {key}")
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"invalid row in: {key}")
        row_id = str(row.get("row_id") or "")
        if not row_id or row_id in output:
            raise ValueError(f"missing or duplicate row identity in: {key}")
        output[row_id] = row
    return output


def _candidate_summary(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "authority_identity_id": candidate.get("authority_identity_id"),
        "source_version_id": candidate.get("source_version_id"),
        "stable_identifier": candidate.get("stable_identifier"),
        "canonical_citation": candidate.get("canonical_citation"),
        "title": candidate.get("title"),
        "locator": candidate.get("locator"),
        "span_bundle_sha256": candidate.get("span_bundle_sha256"),
        "full_span_text_sha256": candidate.get("full_span_text_sha256"),
        "candidate_record_content_sha256": candidate.get("candidate_record_content_sha256"),
        "identity_verified": candidate.get("identity_verified"),
        "currentness_verified": candidate.get("currentness_verified"),
        "later_treatment_review_required": candidate.get("later_treatment_review_required"),
        "already_in_sealed_candidate": candidate.get("already_in_sealed_candidate"),
    }


def _issue_queue_record(qualification: dict[str, Any], crosswalk: dict[str, Any]) -> dict[str, Any]:
    candidates = crosswalk.get("candidate_evidence_packets")
    if not isinstance(candidates, list):
        candidates = []
    payload = {
        "schema": "legalbot.v111.phase2a.remaining-issue-work.v1",
        "ordinal": qualification["ordinal"],
        "row_id": qualification["row_id"],
        "case_id": qualification["case_id"],
        "issue_id": qualification["issue_id"],
        "legal_domain": qualification["legal_domain"],
        "issue_label": qualification["issue_label"],
        "qualification_status": qualification["qualification_status"],
        "qualification_record_content_sha256": qualification["record_content_sha256"],
        "crosswalk_status": crosswalk.get("status"),
        "crosswalk_record_content_sha256": crosswalk.get("record_content_sha256"),
        "deterministic_work_class": crosswalk.get("deterministic_work_class"),
        "atomic_proposition": crosswalk.get("atomic_proposition"),
        "issue_terms": crosswalk.get("issue_terms") or [],
        "candidate_count": len(candidates),
        "candidate_evidence": [
            _candidate_summary(candidate) for candidate in candidates if isinstance(candidate, dict)
        ],
        "required_next_action": (
            "RESEARCH_AND_FREEZE_EXACT_PROPOSITION_SPAN"
            if qualification["qualification_status"] == "BLOCKED_MATERIAL_GAP"
            else "OWNER_SELECT_OR_REJECT_PROPOSITION_SPAN"
        ),
        "owner_outcome": None,
        "answer_release_eligible": False,
        "phase2b_authorized": False,
    }
    return _sealed(payload, field="record_content_sha256")


def _group_source_units(
    sources: list[dict[str, Any]],
    candidate_rows_by_authority: dict[str, set[str]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for source in sources:
        grouped[str(source["authority_identity_id"])].append(source)
    units: list[dict[str, Any]] = []
    for authority_id, representations in sorted(grouped.items()):
        representations = sorted(representations, key=lambda item: str(item["source_version_id"]))
        later_required = any(
            item.get("subsequent_treatment_check_required") is True
            and item.get("subsequent_treatment_verified") is not True
            for item in representations
        )
        currentness_unverified = any(
            item.get("currentness_verified") is not True for item in representations
        )
        if not later_required and not currentness_unverified:
            continue
        if later_required:
            queue_class = "JUDGMENT_LATER_TREATMENT_AND_CURRENTNESS"
        else:
            queue_class = "LEGISLATION_CURRENTNESS"
        payload = {
            "schema": "legalbot.v111.phase2a.remaining-source-work.v1",
            "authority_identity_id": authority_id,
            "title": representations[0].get("title"),
            "queue_class": queue_class,
            "representation_count": len(representations),
            "source_version_ids": [item["source_version_id"] for item in representations],
            "version_sha256s": [item["version_sha256"] for item in representations],
            "canonical_urls": sorted({str(item.get("canonical_url")) for item in representations}),
            "source_dates": sorted(
                {str(item.get("source_date") or "") for item in representations}
            ),
            "currentness_unverified": currentness_unverified,
            "later_treatment_required": later_required,
            "candidate_pending_row_ids": sorted(
                candidate_rows_by_authority.get(authority_id, set())
            ),
            "bulk_find_case_law_search_authorized": False,
            "targeted_review_must_follow_proposition_selection": later_required,
            "owner_outcome": None,
            "answer_release_eligible": False,
            "phase2b_authorized": False,
        }
        units.append(_sealed(payload, field="record_content_sha256"))
    return units


def build_intake(*, output_root: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    if output_root.exists():
        raise FileExistsError("remaining-remediation intake output already exists")

    receipt_path = BLOCKED_ROOT / "FINAL-DELIVERY-RECEIPT-r2.json"
    qualification_path = MACHINE_ROOT / ("qualification/DETERMINISTIC-ALL585-QUALIFICATION.json")
    crosswalk_path = MACHINE_ROOT / "crosswalk/DETERMINISTIC-EXACT-SPAN-PACKETS-364.json"
    source_manifest_path = MACHINE_ROOT / "candidate/approved-source-manifest.json"
    mismatch_path = MACHINE_ROOT / (
        "registries/COMPLETE-LEGISLATION-BYTE-MISMATCH-REGISTER-65.json"
    )
    effects_path = MACHINE_ROOT / ("registries/COMPLETE-LEGISLATIVE-EFFECT-REGISTER-1896.json")
    legacy_later_path = MACHINE_ROOT / (
        "registries/COMPLETE-JUDGMENT-LATER-TREATMENT-REGISTER-20.json"
    )
    candidate_manifest_path = MACHINE_ROOT / "candidate/manifest.json"
    candidate_seal_path = MACHINE_ROOT / "candidate/seal.json"
    candidate_evaluation_path = MACHINE_ROOT / "candidate/evaluation.json"

    required_paths = (
        receipt_path,
        qualification_path,
        crosswalk_path,
        source_manifest_path,
        mismatch_path,
        effects_path,
        legacy_later_path,
        candidate_manifest_path,
        candidate_seal_path,
        candidate_evaluation_path,
    )
    bindings = {_relative(path): _sha256_file(path) for path in required_paths}

    receipt = _load_object(receipt_path)
    if (
        receipt.get("final_delivery_content_sha256") != EXPECTED_BLOCKED_DELIVERY_SHA256
        or receipt.get("phase2a_technical_qualification_passed") is not False
        or receipt.get("phase2b_authorized") is not False
    ):
        raise ValueError("blocked delivery receipt identity or gate state changed")

    qualification = _load_object(qualification_path)
    qualification_rows = _row_map(qualification, "rows")
    if (
        len(qualification_rows) != 585
        or qualification.get("status_counts") != EXPECTED_STATUS_COUNTS
        or qualification.get("phase2a_technical_qualification_passed") is not False
    ):
        raise ValueError("final all-585 blocked partition changed")
    crosswalk = _load_object(crosswalk_path)
    crosswalk_rows = _row_map(crosswalk, "rows")
    pending_ids = {
        row_id
        for row_id, row in qualification_rows.items()
        if row["qualification_status"] in {"OWNER_DECISION_REQUIRED", "BLOCKED_MATERIAL_GAP"}
    }
    if len(pending_ids) != 361 or not pending_ids.issubset(crosswalk_rows):
        raise ValueError("remaining issue queue does not bind to the exact crosswalk")

    issue_queue = [
        _issue_queue_record(qualification_rows[row_id], crosswalk_rows[row_id])
        for row_id in sorted(pending_ids, key=lambda item: int(qualification_rows[item]["ordinal"]))
    ]
    candidate_rows_by_authority: dict[str, set[str]] = defaultdict(set)
    for row in issue_queue:
        for candidate in row["candidate_evidence"]:
            authority_id = candidate.get("authority_identity_id")
            if authority_id:
                candidate_rows_by_authority[str(authority_id)].add(str(row["row_id"]))

    source_manifest = _load_object(source_manifest_path)
    sources = source_manifest.get("sources")
    if (
        not isinstance(sources, list)
        or source_manifest.get("source_count") != 251
        or len(sources) != 251
        or source_manifest.get("chunk_count") != 222_200
    ):
        raise ValueError("held successor source manifest changed")
    source_units = _group_source_units(sources, candidate_rows_by_authority)
    source_unit_counts = Counter(unit["queue_class"] for unit in source_units)
    if source_unit_counts != {
        "JUDGMENT_LATER_TREATMENT_AND_CURRENTNESS": 133,
        "LEGISLATION_CURRENTNESS": 51,
    }:
        raise ValueError("deduplicated remaining source work counts changed")

    mismatch = _load_object(mismatch_path)
    mismatch_records = mismatch.get("records")
    if not isinstance(mismatch_records, list) or len(mismatch_records) != 65:
        raise ValueError("legislation representation-mismatch queue changed")
    mismatch_queue = [
        {
            "ordinal": row.get("ordinal"),
            "source_version_id": row.get("byte_mismatch_record", {}).get("source_version_id"),
            "authority_identity_id": row.get("byte_mismatch_record", {}).get("authority_identity"),
            "title": row.get("byte_mismatch_record", {}).get("title"),
            "classification": row.get("byte_mismatch_record", {})
            .get("comparison", {})
            .get("classification"),
            "advisory_recommendation": row.get("advisory_recommendation"),
            "record_content_sha256": row.get("record_content_sha256"),
            "owner_decision_status": row.get("owner_decision_status"),
        }
        for row in mismatch_records
    ]

    effects = _load_object(effects_path)
    effect_rows = effects.get("effects")
    if not isinstance(effect_rows, list):
        raise ValueError("legislative-effect register changed")
    pending_effects = [
        row
        for row in effect_rows
        if row.get("owner_decision_status") == "PENDING_EXPLICIT_OWNER_DECISION"
    ]
    if len(pending_effects) != 516:
        raise ValueError("pending legislative-effect queue changed")
    effect_queue = [
        {
            "ordinal": row.get("ordinal"),
            "effect_id": row.get("effect_record", {}).get("effect_id"),
            "authority_identity_id": row.get("effect_record", {}).get("authority_identity"),
            "affected_provisions": row.get("effect_record", {}).get("affected_provisions"),
            "affecting_uri": row.get("effect_record", {}).get("affecting_uri"),
            "disposition": row.get("effect_record", {}).get("disposition"),
            "blocks_common_cutoff": row.get("effect_record", {}).get("blocks_common_cutoff"),
            "advisory_recommendation": row.get("advisory_recommendation"),
            "record_content_sha256": row.get("record_content_sha256"),
        }
        for row in pending_effects
    ]

    legacy_later = _load_object(legacy_later_path)
    legacy_later_records = legacy_later.get("records")
    if not isinstance(legacy_later_records, list) or len(legacy_later_records) != 20:
        raise ValueError("legacy later-treatment subset changed")

    _load_object(candidate_manifest_path)
    _load_object(candidate_seal_path)
    candidate_evaluation = _load_object(candidate_evaluation_path)
    actual_candidate_manifest_file_sha = _sha256_file(candidate_manifest_path)
    actual_candidate_seal_file_sha = _sha256_file(candidate_seal_path)
    privacy_checked = candidate_evaluation.get("privacy", {}).get("checked", {})
    integrity = candidate_evaluation.get("integrity", {})

    intake = {
        "schema": "legalbot.v111.phase2a.remaining-remediation-intake.v1",
        "route": "OWNER_ADOPTED_INTERNAL_DETERMINISTIC_ONLY",
        "blocked_delivery_content_sha256": EXPECTED_BLOCKED_DELIVERY_SHA256,
        "input_file_sha256s": dict(sorted(bindings.items())),
        "issue_scope": {
            "total_issue_count": 585,
            "preserved_evidence_ready_count": 224,
            "owner_decision_required_count": 263,
            "material_exact_span_gap_count": 98,
            "remaining_issue_work_count": len(issue_queue),
            "records": issue_queue,
        },
        "source_scope": {
            "held_successor_source_version_count": 251,
            "held_successor_authority_identity_count": len(
                {str(source["authority_identity_id"]) for source in sources}
            ),
            "deduplicated_currentness_authority_count": len(source_units),
            "judgment_later_treatment_authority_count": source_unit_counts[
                "JUDGMENT_LATER_TREATMENT_AND_CURRENTNESS"
            ],
            "legislation_currentness_authority_count": source_unit_counts[
                "LEGISLATION_CURRENTNESS"
            ],
            "records": source_units,
        },
        "policy_and_representation_scope": {
            "pending_legislative_effect_count": len(effect_queue),
            "pending_legislative_effect_records": effect_queue,
            "pending_legislation_representation_mismatch_count": len(mismatch_queue),
            "pending_legislation_representation_mismatch_records": mismatch_queue,
            "legacy_judgment_later_treatment_subset_count": len(legacy_later_records),
            "legacy_judgment_later_treatment_subset_sha256s": [
                row.get("record_content_sha256") for row in legacy_later_records
            ],
        },
        "known_integrity_findings": [
            {
                "code": "CANDIDATE_IDENTITY_FIELD_NAMES_BIND_SEAL_NOT_MANIFEST",
                "actual_candidate_manifest_file_sha256": actual_candidate_manifest_file_sha,
                "actual_candidate_seal_file_sha256": actual_candidate_seal_file_sha,
                "final_candidate_identity_candidate_manifest_hash": qualification.get(
                    "candidate_identity", {}
                ).get("candidate_manifest_hash"),
                "repair_required_before_successful_delivery": True,
            },
            {
                "code": "PRIVACY_CHECKED_CHUNK_COUNT_EXCEEDS_PHYSICAL_CANDIDATE_BY_8",
                "privacy_checked_approved_index_chunks": privacy_checked.get(
                    "approved_index_chunks"
                ),
                "privacy_checked_candidate_eligible_index_chunks": privacy_checked.get(
                    "candidate_eligible_index_chunks"
                ),
                "physical_candidate_chunk_count": integrity.get("chunk_count"),
                "repair_required_before_successful_delivery": True,
            },
            {
                "code": "BLOCKED_MACHINE_PACKAGE_OMITS_REFERENCED_SOURCE_SCAN_MANIFEST_BYTES",
                "referenced_source_scan_manifest_sha256": integrity.get(
                    "source_scan_manifest_sha256"
                ),
                "repair_required_before_successful_delivery": True,
            },
            {
                "code": "BLOCKED_CANDIDATE_WAS_NOT_BUILT_FROM_CLEAN_HEAD",
                "retroactive_relabel_prohibited": True,
                "new_clean_head_build_requires_new_owner_authority": True,
                "repair_required_before_successful_delivery": True,
            },
        ],
        "execution_constraints": {
            "planner_or_answer_model_calls_authorized": False,
            "bulk_find_case_law_computational_analysis_authorized": False,
            "targeted_official_source_research_authorized": True,
            "automatic_source_admission": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "source_scan_authorized": False,
            "successor_candidate_build_authorized": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
        "next_gate": ("EXACT_DIGEST_BOUND_OWNER_DECISIONS_AND_ANY_NEW_SOURCE_ADMISSIONS"),
        "status": "REMAINING_REMEDIATION_INTAKE_READY_NON_AUTHORIZING",
    }
    intake = _sealed(intake, field="artifact_content_sha256")

    output_root.mkdir(parents=True)
    intake_path = output_root / "REMAINING-REMEDIATION-INTAKE.json"
    _write_new_json(intake_path, intake)
    outcome = (
        "PHASE 2A REMEDIATION INTAKE READY - OWNER DECISIONS, OFFICIAL-SOURCE "
        "RESEARCH AND CURRENTNESS WORK REMAIN; NO BUILD OR PHASE 2B AUTHORIZED\n"
    )
    _write_new(output_root / "OUTCOME.txt", outcome.encode("utf-8"))

    package = {
        "schema": "legalbot.v111.phase2a.remaining-remediation-intake-package.v1",
        "status": "COMPLETE_NON_AUTHORIZING_INTAKE",
        "blocked_delivery_content_sha256": EXPECTED_BLOCKED_DELIVERY_SHA256,
        "intake_artifact_content_sha256": intake["artifact_content_sha256"],
        "files": {
            path.name: {"sha256": _sha256_file(path), "size": path.stat().st_size}
            for path in sorted(output_root.iterdir())
            if path.is_file()
        },
        "source_admission_authorized": False,
        "source_scan_authorized": False,
        "successor_candidate_build_authorized": False,
        "phase2b_authorized": False,
    }
    package = _sealed(package, field="package_content_sha256")
    _write_new_json(output_root / "PACKAGE-INDEX.json", package)
    sums = "\n".join(
        f"{_sha256_file(path)}  {path.name}"
        for path in sorted(output_root.iterdir())
        if path.is_file()
    )
    _write_new(output_root / "SHA256SUMS.txt", (sums + "\n").encode("utf-8"))
    return intake


def main() -> None:
    intake = build_intake()
    summary = {
        "artifact_content_sha256": intake["artifact_content_sha256"],
        "remaining_issue_work_count": intake["issue_scope"]["remaining_issue_work_count"],
        "deduplicated_currentness_authority_count": intake["source_scope"][
            "deduplicated_currentness_authority_count"
        ],
        "pending_legislative_effect_count": intake["policy_and_representation_scope"][
            "pending_legislative_effect_count"
        ],
        "pending_legislation_representation_mismatch_count": intake[
            "policy_and_representation_scope"
        ]["pending_legislation_representation_mismatch_count"],
        "status": intake["status"],
    }
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
