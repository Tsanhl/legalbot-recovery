#!/usr/bin/env python3
"""Reconcile the exact remaining 537 Phase-2A issue rows.

This create-only command replaces an undifferentiated arithmetic remainder
with a row-level evidence-state inventory.  It does not infer propositions,
qualify issues, admit sources, mutate a candidate, or authorize Phase 2B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

MATRIX_SCHEMA = "legalbot.v111-phase2a-remediation-matrix.v1"
RECONCILIATION_SCHEMA = "legalbot.v111.phase2a.historical-candidate-span-reconciliation.v1"
APPROVED_SCHEMA = "legalbot.v111.phase2a.internal-proposition-span-approved-package.v1"
OWNER_REVIEWED_SCHEMA = "legalbot.v111.phase2a.owner-reviewed-issues.v1"
HISTORICAL_SCHEMA = "legalbot.live60.owner-reviewed-search-answers.v1"

EXPECTED_MATRIX_COUNT = 585
EXPECTED_HISTORICAL_COUNT = 293
EXPECTED_APPROVED_COUNT = 48
EXPECTED_REMAINING_COUNT = 537
EXPECTED_CORRECTION_QUEUE_COUNT = 89
EXPECTED_KEEP_GAP_COUNT = 156
EXPECTED_NO_HISTORICAL_COUNT = 292
EXPECTED_HISTORICAL_FILE_SHA256 = "e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d"

DETERMINISTIC_STATUS = "DETERMINISTIC_CANDIDATE_COMPONENTS_LOCATED_OWNER_REVIEW_REQUIRED"
KEEP_GAP_STATUS = "NO_OPERATIVE_TEXT_KEEP_GAP"
CORRECTION_QUEUE_STATUSES = frozenset(
    {
        "NO_EXACT_CANDIDATE_TEXT_COMPONENT",
        "NO_MATCHING_SOURCE_IN_SEALED_CANDIDATE",
        "PARTIAL_CANDIDATE_COMPONENTS_OWNER_REVIEW_REQUIRED",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_remaining_inventory_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_remaining_inventory_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _index_unique(
    values: Sequence[Mapping[str, Any]], *, key: str, code: str
) -> dict[str, Mapping[str, Any]]:
    indexed: dict[str, Mapping[str, Any]] = {}
    for value in values:
        identifier = str(value.get(key) or "")
        if not identifier or identifier in indexed:
            raise ValueError(code)
        indexed[identifier] = value
    return indexed


def _evidence_state(status: str | None) -> tuple[str, str]:
    if status in CORRECTION_QUEUE_STATUSES:
        return (
            "CONCRETE_STAGING_PROPOSITION_REQUIRES_OFFICIAL_REBINDING",
            "VERIFY_EXACT_PROPOSITION_AGAINST_FRESH_OFFICIAL_SOURCE_AND_CANDIDATE",
        )
    if status == KEEP_GAP_STATUS:
        return (
            "HISTORICAL_REVIEW_KEPT_GAP_NO_SAFE_OPERATIVE_SPAN",
            "PERFORM_NEW_PROPOSITION_RESEARCH_AND_CURRENTNESS_REVIEW",
        )
    if status is None:
        return (
            "NO_HISTORICAL_PROPOSITION_PACKET",
            "CREATE_FIRST_PROPOSITION_SOURCE_VERSION_AND_EXACT_SPAN_PACKET",
        )
    raise ValueError("phase2a_remaining_inventory_unexpected_historical_status")


def build_inventory(
    *,
    matrix_path: Path,
    reconciliation_path: Path,
    approved_path: Path,
    owner_reviewed_path: Path,
    historical_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    """Build the sealed row-level remainder without changing any gate state."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_remaining_inventory_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_remaining_inventory_output_mode_invalid")

    matrix = _load_object(matrix_path)
    reconciliation = _load_object(reconciliation_path)
    approved = _load_object(approved_path)
    owner_reviewed = _load_object(owner_reviewed_path)
    historical = _load_object(historical_path)

    matrix_sha256 = _verify_seal(
        matrix, "artifact_sha256", "phase2a_remaining_inventory_matrix_seal_invalid"
    )
    reconciliation_sha256 = _verify_seal(
        reconciliation,
        "artifact_content_sha256",
        "phase2a_remaining_inventory_reconciliation_seal_invalid",
    )
    approved_sha256 = _verify_seal(
        approved,
        "approved_package_content_sha256",
        "phase2a_remaining_inventory_approved_seal_invalid",
    )
    owner_reviewed_sha256 = _verify_seal(
        owner_reviewed,
        "artifact_content_sha256",
        "phase2a_remaining_inventory_owner_reviewed_seal_invalid",
    )

    matrix_rows = matrix.get("rows")
    reconciliation_records = reconciliation.get("records")
    approved_decisions = approved.get("decisions")
    owner_reviewed_rows = owner_reviewed.get("rows")
    historical_records = historical.get("records")
    if (
        matrix.get("schema") != MATRIX_SCHEMA
        or matrix.get("row_count") != EXPECTED_MATRIX_COUNT
        or not isinstance(matrix_rows, list)
        or len(matrix_rows) != EXPECTED_MATRIX_COUNT
        or reconciliation.get("schema") != RECONCILIATION_SCHEMA
        or reconciliation.get("record_count") != EXPECTED_HISTORICAL_COUNT
        or not isinstance(reconciliation_records, list)
        or len(reconciliation_records) != EXPECTED_HISTORICAL_COUNT
        or approved.get("schema") != APPROVED_SCHEMA
        or approved.get("item_count") != EXPECTED_APPROVED_COUNT
        or not isinstance(approved_decisions, list)
        or len(approved_decisions) != EXPECTED_APPROVED_COUNT
        or owner_reviewed.get("schema") != OWNER_REVIEWED_SCHEMA
        or owner_reviewed.get("record_count") != EXPECTED_MATRIX_COUNT
        or not isinstance(owner_reviewed_rows, list)
        or len(owner_reviewed_rows) != EXPECTED_MATRIX_COUNT
        or historical.get("schema") != HISTORICAL_SCHEMA
        or not isinstance(historical_records, list)
        or len(historical_records) != EXPECTED_HISTORICAL_COUNT
    ):
        raise ValueError("phase2a_remaining_inventory_input_boundary_invalid")

    historical_file_sha256 = _sha256_file(historical_path)
    historical_is_authoritative = historical_file_sha256 == EXPECTED_HISTORICAL_FILE_SHA256
    matrix_by_row = _index_unique(
        matrix_rows, key="row_id", code="phase2a_remaining_inventory_matrix_duplicate"
    )
    reconciliation_by_row = _index_unique(
        reconciliation_records,
        key="row_id",
        code="phase2a_remaining_inventory_reconciliation_duplicate",
    )
    approved_by_row = _index_unique(
        approved_decisions,
        key="row_id",
        code="phase2a_remaining_inventory_approved_duplicate",
    )
    owner_reviewed_by_row = _index_unique(
        owner_reviewed_rows,
        key="row_id",
        code="phase2a_remaining_inventory_owner_reviewed_duplicate",
    )
    historical_by_row = _index_unique(
        historical_records,
        key="issue_key",
        code="phase2a_remaining_inventory_historical_duplicate",
    )
    matrix_ids = set(matrix_by_row)
    if (
        not set(reconciliation_by_row).issubset(matrix_ids)
        or not set(approved_by_row).issubset(matrix_ids)
        or set(owner_reviewed_by_row) != matrix_ids
        or set(historical_by_row) != set(reconciliation_by_row)
    ):
        raise ValueError("phase2a_remaining_inventory_row_identity_mismatch")

    for row_id, decision in approved_by_row.items():
        record = reconciliation_by_row.get(row_id)
        if (
            record is None
            or record.get("match_status") != DETERMINISTIC_STATUS
            or decision.get("status") != "OWNER_APPROVED_INTERNAL_RESEARCH_TOOL_BINDING"
            or decision.get("phase2b_authorized") is not False
            or decision.get("development30_authorized") is not False
        ):
            raise ValueError("phase2a_remaining_inventory_approved_binding_invalid")

    rows: list[dict[str, Any]] = []
    correction_queue: list[dict[str, Any]] = []
    evidence_state_counts: Counter[str] = Counter()
    baseline_status_counts: Counter[str] = Counter()
    historical_match_status_counts: Counter[str] = Counter()
    for row_id, matrix_row in matrix_by_row.items():
        if row_id in approved_by_row:
            continue
        reconciliation_record = reconciliation_by_row.get(row_id)
        historical_record = historical_by_row.get(row_id)
        match_status = (
            str(reconciliation_record.get("match_status"))
            if reconciliation_record is not None
            else None
        )
        if (reconciliation_record is None) != (historical_record is None):
            raise ValueError("phase2a_remaining_inventory_historical_join_invalid")
        if reconciliation_record is not None and (
            reconciliation_record.get("historical_staging_record_sha256")
            != _sealed(historical_record)
        ):
            raise ValueError("phase2a_remaining_inventory_historical_record_seal_invalid")

        evidence_state, correction_path = _evidence_state(match_status)
        owner_row = owner_reviewed_by_row[row_id]
        if owner_row.get("owner_review", {}).get("status") != "OWNER_REQUESTED_MORE_EVIDENCE":
            raise ValueError("phase2a_remaining_inventory_owner_request_missing")
        material = {
            "ordinal": matrix_row.get("ordinal"),
            "row_id": row_id,
            "case_id": matrix_row.get("case_id"),
            "issue_id": matrix_row.get("issue_id"),
            "issue_label": matrix_row.get("issue_label"),
            "issue_label_sha256": matrix_row.get("issue_label_sha256"),
            "legal_domain": matrix_row.get("legal_domain"),
            "task_type": matrix_row.get("task_type"),
            "baseline_primary_status": matrix_row.get("baseline_primary_status"),
            "determined_defects": matrix_row.get("determined_defects"),
            "evidence_state": evidence_state,
            "correction_path": correction_path,
            "historical_match_status": match_status,
            "owner_more_evidence_request_sha256": owner_row.get("owner_review", {}).get(
                "owner_decision_sha256"
            ),
            "candidate_change_authorized": False,
            "source_admission_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        row = {**material, "record_content_sha256": _sealed(material)}
        rows.append(row)
        evidence_state_counts[evidence_state] += 1
        baseline_status_counts[str(matrix_row.get("baseline_primary_status"))] += 1
        historical_match_status_counts[match_status or "NO_HISTORICAL_RECORD"] += 1

        if match_status in CORRECTION_QUEUE_STATUSES:
            queue_material = {
                "ordinal": len(correction_queue) + 1,
                "row_id": row_id,
                "canonical_issue_label_sha256": matrix_row.get("issue_label_sha256"),
                "historical_staging_record_sha256": reconciliation_record.get(
                    "historical_staging_record_sha256"
                ),
                "historical_reconciliation_record_content_sha256": (
                    reconciliation_record.get("record_content_sha256")
                ),
                "match_status": match_status,
                "question": historical_record.get("question"),
                "proposed_exact_proposition_text": historical_record.get("operative_text"),
                "official_source_title": historical_record.get("source_title"),
                "official_source_type": historical_record.get("source_type"),
                "official_citation": historical_record.get("citation"),
                "official_legal_locator": historical_record.get("legal_locator"),
                "official_source_url": historical_record.get("official_source_url"),
                "candidate_spans_already_located": reconciliation_record.get("candidate_spans", []),
                "required_action": correction_path,
                "staging_is_authoritative": False,
                "owner_decision_required_after_deterministic_verification": True,
                "automatic_source_admission": False,
                "automatic_candidate_mutation": False,
            }
            if not str(queue_material["proposed_exact_proposition_text"] or "").strip():
                raise ValueError("phase2a_remaining_inventory_correction_text_missing")
            correction_queue.append(
                {**queue_material, "record_content_sha256": _sealed(queue_material)}
            )

    rows.sort(key=lambda item: int(item["ordinal"]))
    if (
        len(rows) != EXPECTED_REMAINING_COUNT
        or len(correction_queue) != EXPECTED_CORRECTION_QUEUE_COUNT
        or evidence_state_counts["HISTORICAL_REVIEW_KEPT_GAP_NO_SAFE_OPERATIVE_SPAN"]
        != EXPECTED_KEEP_GAP_COUNT
        or evidence_state_counts["NO_HISTORICAL_PROPOSITION_PACKET"] != EXPECTED_NO_HISTORICAL_COUNT
        or baseline_status_counts
        != Counter({"GOLD_OR_CASE_DEFECT": 467, "MATERIAL_CANDIDATE_COVERAGE_GAP": 70})
    ):
        raise ValueError("phase2a_remaining_inventory_count_invariant_failed")

    inventory_material = {
        "schema": "legalbot.v111.phase2a.remaining-issue-inventory.v1",
        "status": "ROW_LEVEL_REMAINDER_RECONCILED_NOT_QUALIFIED",
        "source_remediation_matrix_content_sha256": matrix_sha256,
        "source_historical_reconciliation_content_sha256": reconciliation_sha256,
        "source_approved_package_content_sha256": approved_sha256,
        "source_owner_reviewed_issues_content_sha256": owner_reviewed_sha256,
        "historical_staging_file_sha256": historical_file_sha256,
        "historical_staging_expected_file_sha256": EXPECTED_HISTORICAL_FILE_SHA256,
        "historical_staging_is_authoritative": historical_is_authoritative,
        "row_count": len(rows),
        "evidence_state_counts": dict(sorted(evidence_state_counts.items())),
        "baseline_status_counts": dict(sorted(baseline_status_counts.items())),
        "historical_match_status_counts": dict(sorted(historical_match_status_counts.items())),
        "rows": rows,
        "owner_approval_required_after_evidence_prepared": True,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    inventory = {
        **inventory_material,
        "artifact_content_sha256": _sealed(inventory_material),
    }
    queue_material = {
        "schema": "legalbot.v111.phase2a.official-rebinding-queue.v1",
        "status": "DETERMINISTIC_VERIFICATION_REQUIRED_NOT_OWNER_DECISIONS",
        "source_remaining_inventory_content_sha256": inventory["artifact_content_sha256"],
        "item_count": len(correction_queue),
        "items": correction_queue,
        "official_primary_sources_only": True,
        "quarantine_required": True,
        "owner_decision_required_after_verification": True,
        "automatic_source_admission": False,
        "automatic_candidate_mutation": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    queue = {**queue_material, "artifact_content_sha256": _sealed(queue_material)}
    progress_material = {
        "schema": "legalbot.v111.phase2a.corrected-progress.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES",
        "canonical_issue_count": EXPECTED_MATRIX_COUNT,
        "owner_adopted_internal_binding_count": EXPECTED_APPROVED_COUNT,
        "remaining_issue_count": EXPECTED_REMAINING_COUNT,
        "remaining_issue_breakdown": {
            "concrete_staging_proposition_official_rebinding_required": 89,
            "historical_keep_gap_new_research_required": 156,
            "no_historical_proposition_packet": 292,
        },
        "remaining_baseline_breakdown": {
            "gold_or_case_defect": 467,
            "possible_material_candidate_coverage_gap": 70,
        },
        "all585_technical_qualification_passed": False,
        "common_currentness_cutoff_supportable": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "next_action": "DETERMINISTICALLY_VERIFY_89_CONCRETE_STAGING_PROPOSITIONS",
    }
    progress = {**progress_material, "progress_content_sha256": _sealed(progress_material)}

    artifacts = {
        "REMAINING-537-BLOCKER-INVENTORY.json": inventory,
        "NEXT-OFFICIAL-REBINDING-QUEUE-89.json": queue,
        "PHASE2A-CORRECTED-PROGRESS.json": progress,
    }
    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        (
            "PHASE 2A REMAINDER RECONCILED — 89 OFFICIAL REBINDINGS, 156 NEW "
            "RESEARCH GAPS, 292 FIRST-PACKET GAPS; PHASE 2B NOT AUTHORIZED\n"
        ).encode(),
    )
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "remaining_inventory_content_sha256": inventory["artifact_content_sha256"],
        "official_rebinding_queue_content_sha256": queue["artifact_content_sha256"],
        "progress_content_sha256": progress["progress_content_sha256"],
        "remaining_issue_count": len(rows),
        "official_rebinding_queue_count": len(correction_queue),
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.remaining-inventory-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--historical-reconciliation", required=True, type=Path)
    parser.add_argument("--approved-package", required=True, type=Path)
    parser.add_argument("--owner-reviewed-issues", required=True, type=Path)
    parser.add_argument("--historical-staging", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = build_inventory(
            matrix_path=args.matrix.resolve(strict=True),
            reconciliation_path=args.historical_reconciliation.resolve(strict=True),
            approved_path=args.approved_package.resolve(strict=True),
            owner_reviewed_path=args.owner_reviewed_issues.resolve(strict=True),
            historical_path=args.historical_staging.resolve(strict=True),
            output_root=args.output_root.resolve(),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
