#!/usr/bin/env python3
"""Build the post-r113 364-row work ledger without planner-model output."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
for root in (PROJECT_ROOT, BACKEND_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from scripts import apply_seminar_source_owner_approval as seminar_approval  # noqa: E402
from scripts import plan_v111_phase2a_material_gap_research as planner  # noqa: E402

REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
CHOICE_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-deterministic-only-owner-authorized"
    / "OWNER-CHOICE-RECEIPT.json"
)
AUDIT_INVENTORY_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-planner-cap-corrective-audit-v2"
    / "OVER-CAP-ROW-INVENTORY.json"
)
R102_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r102-post-r101-research-routing"
    / "POST-R101-RESEARCH-ROUTING-364.json"
)
R113_GAPS_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
    / "REMAINING-MATERIAL-GAPS-364.json"
)
R113_MAPPINGS_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
    / "APPROVED-MAPPING-DISPOSITIONS-26.json"
)
R113_ADMISSIONS_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r113-post-r110-owner-approved"
    / "CUMULATIVE-APPROVED-SOURCE-ADMISSIONS-25.json"
)
R71_PATH = planner.DEFAULT_TRIAGE
SOURCE_142_RECEIPT_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-approved"
    / "OWNER-APPROVAL-RECEIPT.json"
)
DEFAULT_OUTPUT = REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-deterministic-only-work-ledger"

EXPECTED = {
    CHOICE_PATH: (
        "receipt_content_sha256",
        "65b0077105c94f965908d6b0b236c51ddccbb30a159912f2f9d0f67ad717001b",
    ),
    AUDIT_INVENTORY_PATH: (
        "artifact_content_sha256",
        "f1a96c25dbc76a64c6e336efa9152a89d8513375589911477a170707106c9321",
    ),
    R102_PATH: (
        "artifact_content_sha256",
        "eef0de2cfb5e1be2ab9279c4acbe064f288cdfa24418d1d444b1d6830d18af0b",
    ),
    R113_GAPS_PATH: (
        "artifact_content_sha256",
        "513c58f6eac13d9c51c99efe657d7809158392687143edd67a6b9832e4ecbb34",
    ),
    R113_MAPPINGS_PATH: (
        "artifact_content_sha256",
        "07cc94b7191fc24ae2fdb6f1c3ce9347fd6aba3024314842bafd99ba4828272a",
    ),
    R113_ADMISSIONS_PATH: (
        "artifact_content_sha256",
        "667fa9cb36188740fa28b0d4e0970ec71c82dcb123505f07584ea678bae9c32d",
    ),
    R71_PATH: (
        "artifact_content_sha256",
        "d813a1fdc1b9b6f2d6c67b0ac2c113af696343cc8c619355c74ee8654beca475",
    ),
    SOURCE_142_RECEIPT_PATH: (
        "approval_receipt_content_sha256",
        "878a1d2582a07c40dda7b5311aa22970885f78437e5f3d39109e667b9a6be7f9",
    ),
}


def _verified(path: Path) -> dict[str, Any]:
    value = planner._load_object(path)
    field, expected = EXPECTED[path]
    if path == SOURCE_142_RECEIPT_PATH:
        observed = seminar_approval._verify_seal(
            value,
            field,
            f"phase2a_deterministic_ledger_{path.name}_seal_invalid",
            expected,
        )
    else:
        observed = planner._verify_seal(
            value,
            field,
            f"phase2a_deterministic_ledger_{path.name}_seal_invalid",
        )
    if observed != expected:
        raise ValueError(f"phase2a_deterministic_ledger_{path.name}_identity_changed")
    return value


def _records(value: Mapping[str, Any], key: str, expected: int, code: str) -> list[dict[str, Any]]:
    rows = value.get(key)
    if (
        not isinstance(rows, list)
        or len(rows) != expected
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ValueError(code)
    return [dict(row) for row in rows]


def _work_class(route: str) -> str:
    if route == "OWNER_NONMATERIAL_OR_GOLD_SCOPE_REVIEW":
        return "OWNER_GOLD_SCOPE_DECISION_PACKET"
    if route == "EFFECTIVE_OUTSIDE_SOURCE_QUARANTINE_AND_PROPOSITION_REVIEW":
        return "CROSSWALK_APPROVED_SOURCE_OR_PREPARE_NEW_ADMISSION"
    if route == "R94_REJECTED_STALE_AUTHORITY_PLAN_RESEARCH_RESET":
        return "DETERMINISTIC_OFFICIAL_SOURCE_SEARCH_OR_GOLD_REPAIR"
    if route == "SCENARIO_AWARE_IN_CANDIDATE_RECOVERY_OR_GOLD_REPAIR":
        return "DETERMINISTIC_CANDIDATE_LOCATOR_SEARCH_OR_GOLD_REPAIR"
    if route == "SCENARIO_AWARE_AUTHORITY_RESEARCH_OR_GOLD_REPAIR":
        return "DETERMINISTIC_OFFICIAL_AUTHORITY_SEARCH_OR_GOLD_REPAIR"
    return "VERIFY_EXISTING_EXACT_SPAN_AND_CURRENTNESS"


def build_ledger(output_root: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_deterministic_ledger_output_exists")
    choice = _verified(CHOICE_PATH)
    over_cap_artifact = _verified(AUDIT_INVENTORY_PATH)
    r102 = _verified(R102_PATH)
    r113_gaps = _verified(R113_GAPS_PATH)
    r113_mappings = _verified(R113_MAPPINGS_PATH)
    r113_admissions = _verified(R113_ADMISSIONS_PATH)
    r71 = _verified(R71_PATH)
    source_142_receipt = _verified(SOURCE_142_RECEIPT_PATH)
    if (
        choice.get("selected_methodology") != "DETERMINISTIC_ONLY_PATH"
        or choice.get("further_planner_or_advisory_model_invocations_authorized") is not False
        or r102.get("row_count") != 364
        or r113_gaps.get("record_count") != 364
        or r71.get("row_count") != 448
        or r113_mappings.get("record_count") != 26
        or r113_admissions.get("record_count") != 25
        or source_142_receipt.get("source_authority_count") != 142
        or source_142_receipt.get("source_scan_started") is not False
    ):
        raise ValueError("phase2a_deterministic_ledger_input_boundary_invalid")

    routes = _records(r102, "rows", 364, "phase2a_deterministic_routes_invalid")
    gaps = _records(
        r113_gaps,
        "records",
        364,
        "phase2a_deterministic_remaining_gaps_invalid",
    )
    triage_rows = _records(r71, "rows", 448, "phase2a_deterministic_triage_rows_invalid")
    mappings = _records(
        r113_mappings,
        "records",
        26,
        "phase2a_deterministic_mapping_rows_invalid",
    )
    admissions = _records(
        r113_admissions,
        "records",
        25,
        "phase2a_deterministic_admission_rows_invalid",
    )
    over_cap = _records(
        over_cap_artifact,
        "records",
        38,
        "phase2a_deterministic_over_cap_rows_invalid",
    )
    by_gap = {str(row["row_id"]): row for row in gaps}
    by_triage = {str(row["row_id"]): row for row in triage_rows}
    over_cap_ids = {str(row["row_id"]) for row in over_cap}
    mappings_by_row: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in mappings:
        decision = record["source_decision"]
        mappings_by_row[str(decision["row_id"])].append(record)
    admissions_by_row: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in admissions:
        for row_id in record.get("affected_row_ids", []):
            admissions_by_row[str(row_id)].append(record)

    output_rows: list[dict[str, Any]] = []
    work_counts: Counter[str] = Counter()
    for route_record in sorted(routes, key=lambda item: str(item["row_id"])):
        row_id = str(route_record["row_id"])
        gap = by_gap.get(row_id)
        triage = by_triage.get(row_id)
        if gap is None or triage is None:
            raise ValueError("phase2a_deterministic_ledger_row_join_missing")
        route = str(route_record["route"])
        work_class = _work_class(route)
        work_counts[work_class] += 1
        effective = set(route_record.get("effective_planned_authority_ids", []))
        locator_hints = []
        for authority in triage.get("planned_authorities", []):
            authority_id = str(authority["authority_identity_id"])
            if authority_id not in effective:
                continue
            locator_hints.append(
                {
                    "authority_identity_id": authority_id,
                    "locator_hint": authority.get("locator_hint"),
                    "in_exact_candidate_manifest": authority.get("in_exact_candidate_manifest"),
                    "source_version_ids": [
                        str(item["source_version_id"])
                        for item in authority.get("catalogue_records", [])
                    ],
                }
            )
        owner_mappings = [
            {
                "owner_outcome": record["owner_outcome"],
                "mapped_authority_identity_id": record["source_decision"][
                    "mapped_authority_identity_id"
                ],
                "replacement_authority_identity_ids": record["source_decision"][
                    "replacement_authority_identity_ids"
                ],
                "exact_binding_content_sha256s": [
                    str(item["binding_content_sha256"])
                    for item in record["source_decision"]["exact_proposition_bindings"]
                ],
            }
            for record in mappings_by_row.get(row_id, [])
        ]
        owner_admissions = [
            {
                "source_authority_identity_id": record["source_authority_identity_id"],
                "source_admission_content_sha256": record["source_admission_content_sha256"],
            }
            for record in admissions_by_row.get(row_id, [])
        ]
        material = {
            "schema": "legalbot.v111.phase2a.deterministic-work-ledger-row.v1",
            "row_id": row_id,
            "case_id": triage["case_id"],
            "issue_label": triage["issue_label"],
            "legal_domain": triage["legal_domain"],
            "triage_class": triage["triage_class"],
            "source_route": route,
            "deterministic_work_class": work_class,
            "remaining_gap_reason": gap["gap_reason"],
            "effective_planned_authority_ids": sorted(effective),
            "effective_outside_candidate_authority_ids": sorted(
                route_record.get("effective_outside_candidate_authority_ids", [])
            ),
            "deterministic_locator_hints": locator_hints,
            "owner_approved_mapping_dispositions": owner_mappings,
            "owner_approved_source_admissions": owner_admissions,
            "planner_attempt_cap_breached": row_id in over_cap_ids,
            "planner_output_consumed": False,
            "atomic_proposition_status": "OWNER_REVIEW_PACKET_REQUIRED",
            "exact_span_status": "PENDING_DETERMINISTIC_VERIFICATION",
            "source_142_crosswalk_status": "PENDING_CANONICAL_IDENTITY_AND_CONTENT_SHA",
            "technical_qualification_assigned": False,
        }
        output_rows.append({**material, "record_content_sha256": planner._sealed(material)})
    if (
        len(output_rows) != 364
        or len({row["row_id"] for row in output_rows}) != 364
        or sum(row["planner_attempt_cap_breached"] for row in output_rows) != 38
        or any(row["planner_output_consumed"] is not False for row in output_rows)
    ):
        raise ValueError("phase2a_deterministic_ledger_output_invariant_failed")
    material = {
        "schema": "legalbot.v111.phase2a.deterministic-only-work-ledger-364.v1",
        "status": "DETERMINISTIC_ONLY_LEDGER_READY_EXACT_SPAN_WORK_REQUIRED",
        "source_owner_choice_receipt_content_sha256": choice["receipt_content_sha256"],
        "source_corrective_inventory_content_sha256": over_cap_artifact["artifact_content_sha256"],
        "source_r102_content_sha256": r102["artifact_content_sha256"],
        "source_r113_gaps_content_sha256": r113_gaps["artifact_content_sha256"],
        "source_r113_mappings_content_sha256": r113_mappings["artifact_content_sha256"],
        "source_r113_admissions_content_sha256": r113_admissions["artifact_content_sha256"],
        "source_r71_content_sha256": r71["artifact_content_sha256"],
        "source_142_approval_receipt_content_sha256": source_142_receipt[
            "approval_receipt_content_sha256"
        ],
        "row_count": len(output_rows),
        "planner_attempt_cap_breached_row_count": 38,
        "planner_output_consumed_row_count": 0,
        "deterministic_work_class_counts": dict(sorted(work_counts.items())),
        "rows": output_rows,
        "owner_decisions_applied": True,
        "new_owner_decisions_created": False,
        "new_source_admissions_created": False,
        "source_scan_started": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": planner._sealed(material)}
    exclusion_material = {
        "schema": "legalbot.v111.phase2a.planner-output-exclusion-38.v1",
        "row_count": len(over_cap),
        "row_ids": sorted(over_cap_ids),
        "all_r114_r119_planner_output_consumed": False,
        "over_cap_results_admissible_as_substantive_evidence": False,
        "source_inventory_content_sha256": over_cap_artifact["artifact_content_sha256"],
    }
    exclusion = {
        **exclusion_material,
        "artifact_content_sha256": planner._sealed(exclusion_material),
    }
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_deterministic_ledger_output_mode_invalid")
    planner._write_exclusive(
        output_root / "DETERMINISTIC-WORK-LEDGER-364.json",
        planner._pretty_json(artifact),
    )
    planner._write_exclusive(
        output_root / "PLANNER-OUTPUT-EXCLUSION-38.json",
        planner._pretty_json(exclusion),
    )
    outcome = (
        "364-ROW DETERMINISTIC-ONLY WORK LEDGER READY. NO PLANNER OUTPUT WAS "
        "CONSUMED. EXACT-SPAN AND SOURCE CROSSWALK WORK REMAINS. PHASE 2B AND "
        "DEVELOPMENT 30 REMAIN GATED.\n"
    )
    planner._write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    names = (
        "DETERMINISTIC-WORK-LEDGER-364.json",
        "OUTCOME.txt",
        "PLANNER-OUTPUT-EXCLUSION-38.json",
    )
    checksums = "".join(f"{planner._sha256_file(output_root / name)}  {name}\n" for name in names)
    planner._write_exclusive(output_root / "SHA256SUMS.txt", checksums.encode())
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_ledger(args.output_root.resolve())
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "row_count": result["row_count"],
                "deterministic_work_class_counts": result["deterministic_work_class_counts"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
