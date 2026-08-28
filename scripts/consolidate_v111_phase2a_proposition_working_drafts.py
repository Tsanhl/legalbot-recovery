#!/usr/bin/env python3
"""Consolidate validated proposition drafts without applying legal decisions."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
validator = importlib.import_module(
    "scripts.validate_v111_phase2a_proposition_working_drafts"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def _expected_pending_rows() -> dict[str, dict[str, Any]]:
    qualification = json.loads(validator.DEFAULT_QUALIFICATION.read_text())
    return {
        row["row_id"]: row
        for row in qualification["rows"]
        if row["qualification_status"] in validator.PENDING_STATUSES
    }


def consolidate(
    draft_paths: list[Path],
    *,
    require_complete: bool = False,
) -> dict[str, Any]:
    if not draft_paths:
        raise ValueError("at least one proposition draft is required")
    expected = _expected_pending_rows()
    records_by_id: dict[str, dict[str, Any]] = {}
    input_files: dict[str, dict[str, Any]] = {}
    status_counts: Counter[str] = Counter()
    fit_counts: Counter[str] = Counter()
    selected_source_versions: set[str] = set()
    selected_authorities: set[str] = set()

    for path in sorted(draft_paths, key=lambda item: str(item)):
        validation = validator.validate_draft(path)
        draft = json.loads(path.read_text())
        input_files[str(path)] = {
            "sha256": _sha256_file(path),
            "record_count": validation["record_count"],
            "scope_case_ids": draft["scope_case_ids"],
        }
        for record in draft["records"]:
            row_id = record["row_id"]
            if row_id in records_by_id:
                raise ValueError(f"duplicate row across proposition drafts: {row_id}")
            records_by_id[row_id] = record
            status_counts[record["proposition_status"]] += 1
            fit_counts[record["local_evidence_fit"]] += 1
            for evidence in record["selected_local_evidence"]:
                selected_source_versions.add(evidence["source_version_id"])
                selected_authorities.add(evidence["authority_identity_id"])

    extra = sorted(set(records_by_id) - set(expected))
    if extra:
        raise ValueError(f"drafts contain rows outside final pending scope: {extra}")
    missing = sorted(
        set(expected) - set(records_by_id), key=lambda row_id: expected[row_id]["ordinal"]
    )
    if require_complete and missing:
        raise ValueError(f"proposition reconciliation incomplete: {len(missing)} rows")
    missing_by_case: dict[str, list[str]] = defaultdict(list)
    for row_id in missing:
        missing_by_case[expected[row_id]["case_id"]].append(row_id)

    artifact = {
        "schema": "legalbot.v111.phase2a.proposition-reconciliation-working-ledger.v1",
        "status": (
            "COMPLETE_NON_AUTHORIZING_WORKING_LEDGER"
            if not missing
            else "PARTIAL_NON_AUTHORIZING_WORKING_LEDGER"
        ),
        "expected_pending_row_count": len(expected),
        "covered_row_count": len(records_by_id),
        "missing_row_count": len(missing),
        "missing_row_ids": missing,
        "missing_by_case": dict(sorted(missing_by_case.items())),
        "proposition_status_counts": dict(sorted(status_counts.items())),
        "local_evidence_fit_counts": dict(sorted(fit_counts.items())),
        "selected_local_source_version_count": len(selected_source_versions),
        "selected_local_source_version_ids": sorted(selected_source_versions),
        "selected_local_authority_count": len(selected_authorities),
        "selected_local_authority_ids": sorted(selected_authorities),
        "input_draft_files": input_files,
        "records": [
            records_by_id[row_id]
            for row_id in sorted(
                records_by_id, key=lambda item: expected[item]["ordinal"]
            )
        ],
        "automatic_source_admission": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
    }
    return _sealed(artifact, "artifact_content_sha256")


def write_new(path: Path, artifact: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(_canonical_json(artifact))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("drafts", nargs="+", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    artifact = consolidate(args.drafts, require_complete=args.require_complete)
    if args.output is not None:
        write_new(args.output, artifact)
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "covered_row_count": artifact["covered_row_count"],
                "missing_row_count": artifact["missing_row_count"],
                "status": artifact["status"],
            },
            indent=2,
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
