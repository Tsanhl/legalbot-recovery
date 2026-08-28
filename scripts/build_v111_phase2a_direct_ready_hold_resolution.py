#!/usr/bin/env python3
"""Consolidate exact advisory dependencies for all 45 direct-ready rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKING_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
)
DEFAULT_DIRECT = WORKING_ROOT / "DIRECT-READY-OWNER-ADVISORY-45.json"
DEFAULT_FOUR = WORKING_ROOT / "DIRECT-HOLD-LATER-TREATMENT-ADVISORY-4.json"
DEFAULT_UBER_UNISON = (
    WORKING_ROOT / "UBER-UNISON-LATER-TREATMENT-ADVISORY-4-ROWS-r2.json"
)
DEFAULT_OUTPUT = WORKING_ROOT / "DIRECT-READY-HOLD-RESOLUTION-ADVISORY-45.json"
EXPECTED_DIRECT_SHA256 = (
    "e4e953696db26f7a3175501a0c37a6ec12d8f6f815a53e0caeaeff02ecaf049c"
)
EXPECTED_FOUR_SHA256 = (
    "aa16cd9a6dab3f593aa973bb36c895956cd9eeb30d87077c1f139cc10ba833ca"
)
EXPECTED_UBER_UNISON_SHA256 = (
    "ebbf44e7f7ac8a340f5f60d07b7676ce0f980326e4fddebe5a2e94ca59a50175"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sealed(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _load_sealed(path: Path, *, expected: str, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{code}_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{code}_must_be_object")
    supplied = str(value.get("artifact_content_sha256") or "")
    material = dict(value)
    material.pop("artifact_content_sha256", None)
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != expected
        or supplied != _sealed(material)
    ):
        raise ValueError(f"{code}_seal_invalid")
    return value


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _target_by_row(artifact: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for target in artifact.get("records", []):
        if not isinstance(target, Mapping):
            raise ValueError("phase2a_direct_resolution_target_invalid")
        for row_id in target.get("row_ids", []):
            if row_id in result:
                raise ValueError("phase2a_direct_resolution_duplicate_target_row")
            result[str(row_id)] = {
                "target_neutral_citation": target.get("target_neutral_citation"),
                "recommended_owner_outcome": target.get("recommended_owner_outcome"),
                "record_content_sha256": target.get("record_content_sha256"),
                "candidate_reviews": target.get("candidate_reviews"),
                "search_sha256": target.get("search_sha256"),
                "targeted_search_is_exhaustive": target.get(
                    "search_evidence", {}
                ).get("targeted_search_is_exhaustive"),
                "absence_of_other_hits_proves_no_later_treatment": target.get(
                    "search_evidence", {}
                ).get("absence_of_other_hits_proves_no_later_treatment"),
            }
    return result


def build_resolution(
    *, direct_path: Path, four_path: Path, uber_unison_path: Path, output_path: Path
) -> dict[str, Any]:
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("phase2a_direct_resolution_output_already_exists")
    direct = _load_sealed(
        direct_path,
        expected=EXPECTED_DIRECT_SHA256,
        code="phase2a_direct_resolution_direct",
    )
    four = _load_sealed(
        four_path,
        expected=EXPECTED_FOUR_SHA256,
        code="phase2a_direct_resolution_four",
    )
    uber_unison = _load_sealed(
        uber_unison_path,
        expected=EXPECTED_UBER_UNISON_SHA256,
        code="phase2a_direct_resolution_uber_unison",
    )
    targeted = {**_target_by_row(four), **_target_by_row(uber_unison)}
    expected_targeted_rows = {
        "live30-q09:issue-07",
        "live30-q11:issue-02",
        "live30-q27:issue-02",
        "live30-q27:issue-08",
        "live60-q31:issue-01",
        "live60-q31:issue-02",
        "live60-q38:issue-07",
        "live60-q60:issue-04",
    }
    if set(targeted) != expected_targeted_rows:
        raise ValueError("phase2a_direct_resolution_targeted_scope_invalid")

    records: list[dict[str, Any]] = []
    held_count = 0
    for row in direct.get("records", []):
        if not isinstance(row, Mapping):
            raise ValueError("phase2a_direct_resolution_row_invalid")
        row_id = str(row.get("row_id") or "")
        held = bool(
            row.get("currentness_hold_present")
            or row.get("later_treatment_hold_present")
        )
        dependencies = list(row.get("supporting_advisory_dependencies") or [])
        if held:
            held_count += 1
            if row_id in targeted:
                dependencies.append(targeted[row_id])
            if not dependencies:
                raise ValueError("phase2a_direct_resolution_held_row_dependency_missing")
            status = "EXACT_OWNER_DECISION_READY_WITH_HOLD_ADVISORY"
        else:
            status = "EXACT_OWNER_DECISION_READY_NO_ADDITIONAL_HOLD"
        material = {
            "schema": "legalbot.v111.phase2a.direct-ready-hold-resolution-row.v1",
            "row_id": row_id,
            "canonical_atomic_proposition": row.get("canonical_atomic_proposition"),
            "source_direct_advisory_record_content_sha256": row.get(
                "record_content_sha256"
            ),
            "selected_local_evidence": row.get("selected_local_evidence"),
            "original_currentness_hold_present": row.get("currentness_hold_present"),
            "original_later_treatment_hold_present": row.get(
                "later_treatment_hold_present"
            ),
            "supporting_advisory_dependencies": dependencies,
            "advisory_resolution_status": status,
            "recommended_owner_outcome": row.get("recommended_owner_outcome")
            or (
                targeted.get(row_id, {}).get("recommended_owner_outcome")
                if row_id in targeted
                else "ADOPT_EXACT_PROPOSITION_AND_BOUND_LOCAL_SPANS"
            ),
            "owner_outcome": None,
            "hold_cleared": False,
            "technical_qualification_assigned": False,
        }
        records.append({**material, "record_content_sha256": _sealed(material)})
    if len(records) != 45 or held_count != 11:
        raise ValueError("phase2a_direct_resolution_count_invalid")
    if any(not row["supporting_advisory_dependencies"] for row in records if row["original_currentness_hold_present"] or row["original_later_treatment_hold_present"]):
        raise ValueError("phase2a_direct_resolution_dependency_incomplete")
    material = {
        "schema": "legalbot.v111.phase2a.direct-ready-hold-resolution-advisory.v1",
        "status": "ALL_45_EXACT_OWNER_DECISION_READY_NOT_ADOPTED",
        "source_ceiling_date": "2026-08-14",
        "source_direct_advisory_content_sha256": EXPECTED_DIRECT_SHA256,
        "source_direct_hold_treatment_content_sha256": EXPECTED_FOUR_SHA256,
        "source_uber_unison_treatment_content_sha256": EXPECTED_UBER_UNISON_SHA256,
        "record_count": len(records),
        "no_additional_hold_row_count": 34,
        "held_row_with_exact_advisory_count": held_count,
        "held_row_missing_advisory_count": 0,
        "records": records,
        "owner_decisions_applied": False,
        "holds_cleared": False,
        "automatic_source_admission": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "active_pointer_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
    }
    result = {**material, "artifact_content_sha256": _sealed(material)}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_exclusive(output_path, _pretty_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--direct", type=Path, default=DEFAULT_DIRECT)
    parser.add_argument("--four", type=Path, default=DEFAULT_FOUR)
    parser.add_argument("--uber-unison", type=Path, default=DEFAULT_UBER_UNISON)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_resolution(
        direct_path=args.direct,
        four_path=args.four,
        uber_unison_path=args.uber_unison,
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "record_count": result["record_count"],
                "held_row_with_exact_advisory_count": result[
                    "held_row_with_exact_advisory_count"
                ],
                "artifact_content_sha256": result["artifact_content_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
