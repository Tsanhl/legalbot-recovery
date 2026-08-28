#!/usr/bin/env python3
"""Reconcile r101 findings with r94 owner decisions and route remaining work.

The r101 candidate-only advisory must not overwrite owner-approved r94
bindings or reintroduce authority mappings the owner already rejected.  This
create-only pass produces the exact 364-row post-r94 research ledger used by
the next Phase-2A remediation steps.  It performs no source retrieval,
admission, indexing, candidate mutation, qualification, or gate transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R101_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r101-deterministic-held-gap-resolution"
    / "COMPLETE-EXACT-SPAN-ADVISORY-361.json"
)
R98D_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-26-r98d-candidate-recovery"
    / "CANDIDATE-RECOVERY-361.json"
)
R96_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r96-approved-binding-reconciliation"
R96_READY_PATH = R96_ROOT / "TARGET-DATE-EVIDENCE-READY-ROWS-3.json"
R96_RETAINED_PATH = R96_ROOT / "RETAINED-DIRECT-OR-PARTIAL-GAPS-5.json"
R71_PATH = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r71-gap-triage" / "ISSUE-GAP-TRIAGE-448.json"
R86_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r86-issue-source-rehoming-review"
    / "OWNER-ISSUE-SOURCE-ADMISSION-BATCH.json"
)
R95_UKSC_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved"
    / "APPROVED-UKSC-SOURCE-REVIEWS-5.json"
)
DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r102-post-r101-research-routing"

EXPECTED_IDENTITIES = {
    R101_PATH: (
        "artifact_content_sha256",
        "9009b675ee4341391d31dd249c0e2a8f7ca964f7c44d9ee69c579303c5511ee0",
        "322fb6645923810ad16a93139e8f617fcff80961d430b2e492e665b064f8d97c",
    ),
    R98D_PATH: (
        "artifact_content_sha256",
        "ad1d23ce7feabbd8936eb083fe678be2028f4723b60ffb8b42228a220de02ebf",
        "94d729a2eb802b05b25c36d0f8a9bd7a5b7095cfac885e1ec11a8712a937c3f6",
    ),
    R96_READY_PATH: (
        "artifact_content_sha256",
        "8c7bcebacb7a1c06cdcc9408a85fb97f48c0415f1c05265a97d49396f58b87f9",
        "9de27a5fb550cda323d63a1ef2ccb08994b352a8eb0e5f5ffed3e58d107c0dd2",
    ),
    R96_RETAINED_PATH: (
        "artifact_content_sha256",
        "5fa395cc3a9f52463eaec682dc3f61592fe8d00d23fd008022527eb957004fa3",
        "4f5649726566fa64f25016941b5786d457119a645cefbc57fca6e49d92f271ea",
    ),
    R71_PATH: (
        "artifact_content_sha256",
        "d813a1fdc1b9b6f2d6c67b0ac2c113af696343cc8c619355c74ee8654beca475",
        "1e453c34e939a1d733bdcbae2243bf0bee4050b98ecb2220cd71628c46623f50",
    ),
    R86_PATH: (
        "artifact_content_sha256",
        "623836f3882d6c921920adb8af32bb8bd9cf3836bfb9ed20cdd4095fc627d9b3",
        "0bccf1b8afac72761947aa505f4209dbd77172a5dfdf00d192d262a73bc110c1",
    ),
    R95_UKSC_PATH: (
        "artifact_content_sha256",
        "3fb57743fa655344de0c233320d042a5e4428f28f6034500920d5f3fedabffc5",
        "9990df3852416330f7b593300dcfdd0abad0a606fcbb8695403d0545def08269",
    ),
}
EXPECTED_ROUTE_COUNTS = {
    "EFFECTIVE_OUTSIDE_SOURCE_QUARANTINE_AND_PROPOSITION_REVIEW": 20,
    "NEW_DIRECT_BINDING_CURRENTNESS_REVIEW_BEFORE_OWNER_BATCH": 33,
    "NEW_PARTIAL_BINDING_ADDITIONAL_EVIDENCE": 4,
    "OWNER_NONMATERIAL_OR_GOLD_SCOPE_REVIEW": 5,
    "R94_OWNER_APPROVED_DIRECT_BINDING_CURRENTNESS_REVIEW": 3,
    "R94_OWNER_APPROVED_PARTIAL_ADDITIONAL_EVIDENCE": 1,
    "R94_OWNER_APPROVED_PARTIAL_PLUS_NEW_DIRECT_REVIEW": 1,
    "R94_OWNER_APPROVED_TARGET_DATE_READY": 3,
    "R94_REJECTED_STALE_AUTHORITY_PLAN_RESEARCH_RESET": 7,
    "SCENARIO_AWARE_AUTHORITY_RESEARCH_OR_GOLD_REPAIR": 189,
    "SCENARIO_AWARE_IN_CANDIDATE_RECOVERY_OR_GOLD_REPAIR": 98,
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_r102_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r102_input_must_be_object")
    return value


def _load_verified(path: Path) -> dict[str, Any]:
    field, expected_content, expected_file = EXPECTED_IDENTITIES[path]
    if _sha256_file(path) != expected_file:
        raise ValueError("phase2a_r102_input_file_digest_invalid")
    value = _load_object(path)
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != expected_content
        or supplied != _sealed(material)
    ):
        raise ValueError("phase2a_r102_input_content_seal_invalid")
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


def _records(value: Mapping[str, Any], key: str, expected: int, code: str) -> list[dict[str, Any]]:
    records = value.get(key)
    if (
        not isinstance(records, list)
        or len(records) != expected
        or any(not isinstance(item, dict) for item in records)
    ):
        raise ValueError(code)
    return [dict(item) for item in records]


def _authority_id(neutral_citation: str) -> str:
    return f"neutral-citation:{neutral_citation}"


def _route_row(
    *,
    finding: Mapping[str, Any],
    recovery: Mapping[str, Any],
    triage: Mapping[str, Any],
    retained: Mapping[str, Any] | None,
    rejected_authorities: set[str],
) -> str:
    assessment = str(finding["assessment"])
    if retained is not None:
        status = str(retained["reconciliation_status"])
        if "DIRECT_BINDING" in status:
            return "R94_OWNER_APPROVED_DIRECT_BINDING_CURRENTNESS_REVIEW"
        if assessment == "DIRECT_EXACT_SPAN_ADVISORY":
            return "R94_OWNER_APPROVED_PARTIAL_PLUS_NEW_DIRECT_REVIEW"
        return "R94_OWNER_APPROVED_PARTIAL_ADDITIONAL_EVIDENCE"
    if assessment == "DIRECT_EXACT_SPAN_ADVISORY":
        return "NEW_DIRECT_BINDING_CURRENTNESS_REVIEW_BEFORE_OWNER_BATCH"
    if assessment == "PARTIAL_EXACT_SPAN_ADVISORY":
        return "NEW_PARTIAL_BINDING_ADDITIONAL_EVIDENCE"
    original_outside = [
        str(item) for item in recovery.get("planned_authority_ids_outside_candidate", [])
    ]
    effective_outside = [item for item in original_outside if item not in rejected_authorities]
    triage_class = str(triage["triage_class"])
    if triage_class == "NONMATERIAL_OR_ANALYTICAL_DIMENSION_REVIEW":
        return "OWNER_NONMATERIAL_OR_GOLD_SCOPE_REVIEW"
    if effective_outside:
        return "EFFECTIVE_OUTSIDE_SOURCE_QUARANTINE_AND_PROPOSITION_REVIEW"
    if original_outside and all(item in rejected_authorities for item in original_outside):
        return "R94_REJECTED_STALE_AUTHORITY_PLAN_RESEARCH_RESET"
    if triage_class == "CANDIDATE_LOCATOR_OR_GOLD_DEFINITION_REPAIR":
        return "SCENARIO_AWARE_IN_CANDIDATE_RECOVERY_OR_GOLD_REPAIR"
    return "SCENARIO_AWARE_AUTHORITY_RESEARCH_OR_GOLD_REPAIR"


def build_routing(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r102_output_already_exists")
    r101 = _load_verified(R101_PATH)
    r98d = _load_verified(R98D_PATH)
    ready_artifact = _load_verified(R96_READY_PATH)
    retained_artifact = _load_verified(R96_RETAINED_PATH)
    r71 = _load_verified(R71_PATH)
    r86 = _load_verified(R86_PATH)
    r95_uksc = _load_verified(R95_UKSC_PATH)
    boundary_fields = (
        "technical_qualification_assigned",
        "candidate_mutated",
        "phase2b_authorized",
        "development30_authorized",
    )
    if (
        r101.get("row_count") != 361
        or r101.get("remaining_held_row_count") != 0
        or any(r101.get(field) is not False for field in boundary_fields)
        or r98d.get("row_count") != 361
        or any(r98d.get(field) is not False for field in boundary_fields)
        or r71.get("row_count") != 448
        or any(r71.get(field) is not False for field in boundary_fields)
    ):
        raise ValueError("phase2a_r102_input_boundary_invalid")

    findings = _records(r101, "findings", 361, "phase2a_r102_r101_rows_invalid")
    recoveries = _records(r98d, "rows", 361, "phase2a_r102_r98d_rows_invalid")
    triage_rows = _records(r71, "rows", 448, "phase2a_r102_r71_rows_invalid")
    ready = _records(ready_artifact, "records", 3, "phase2a_r102_ready_rows_invalid")
    retained_rows = _records(retained_artifact, "records", 5, "phase2a_r102_retained_rows_invalid")
    by_recovery = {str(item["row_id"]): item for item in recoveries}
    by_triage = {str(item["row_id"]): item for item in triage_rows}
    by_retained = {str(item["row_id"]): item for item in retained_rows}
    if len(by_recovery) != 361 or len(by_triage) != 448 or len(by_retained) != 5:
        raise ValueError("phase2a_r102_row_identity_collision")

    approved_rejection_hashes = {
        str(item)
        for decision in _records(
            r95_uksc,
            "records",
            5,
            "phase2a_r102_r95_uksc_records_invalid",
        )
        for item in decision["source_decision"]["rejected_mapping_content_sha256s"]
    }
    rejected_by_row: dict[str, set[str]] = defaultdict(set)
    observed_rejection_hashes: set[str] = set()
    source_reviews = r86.get("source_reviews")
    if not isinstance(source_reviews, list) or len(source_reviews) != 5:
        raise ValueError("phase2a_r102_r86_source_reviews_invalid")
    for review in source_reviews:
        for rejection in review.get("rejected_mappings", []):
            rejection_hash = str(rejection["rejection_content_sha256"])
            if rejection_hash not in approved_rejection_hashes:
                continue
            observed_rejection_hashes.add(rejection_hash)
            rejected_by_row[str(rejection["row_id"])].add(
                _authority_id(str(rejection["neutral_citation"]))
            )
    if observed_rejection_hashes != approved_rejection_hashes:
        raise ValueError("phase2a_r102_approved_rejection_mapping_incomplete")

    output_rows: list[dict[str, Any]] = []
    route_counts: Counter[str] = Counter()
    outside_authority_rows: dict[str, list[str]] = defaultdict(list)
    for ready_row in ready:
        row_id = str(ready_row["row_id"])
        material = {
            "schema": "legalbot.v111.phase2a.post-r101-research-route-row.v1",
            "row_id": row_id,
            "route": "R94_OWNER_APPROVED_TARGET_DATE_READY",
            "r94_owner_approval_bound": True,
            "r101_assessment": None,
            "r71_triage_class": None,
            "r94_rejected_planned_authority_ids": [],
            "effective_planned_authority_ids": [],
            "effective_outside_candidate_authority_ids": [],
            "remaining_dependency": ready_row.get("remaining_dependency"),
            "owner_decision_required": False,
            "technical_qualification_assigned": False,
        }
        output_rows.append({**material, "record_content_sha256": _sealed(material)})
        route_counts[material["route"]] += 1

    for finding in findings:
        row_id = str(finding["row_id"])
        recovery = by_recovery.get(row_id)
        triage = by_triage.get(row_id)
        if recovery is None or triage is None:
            raise ValueError("phase2a_r102_row_join_missing")
        rejected = rejected_by_row.get(row_id, set())
        planned = [str(item) for item in recovery.get("planned_authority_ids", [])]
        outside = [
            str(item) for item in recovery.get("planned_authority_ids_outside_candidate", [])
        ]
        effective_planned = [item for item in planned if item not in rejected]
        effective_outside = [item for item in outside if item not in rejected]
        retained = by_retained.get(row_id)
        route = _route_row(
            finding=finding,
            recovery=recovery,
            triage=triage,
            retained=retained,
            rejected_authorities=rejected,
        )
        if retained is None:
            for authority_id in effective_outside:
                outside_authority_rows[authority_id].append(row_id)
        material = {
            "schema": "legalbot.v111.phase2a.post-r101-research-route-row.v1",
            "row_id": row_id,
            "route": route,
            "r94_owner_approval_bound": retained is not None,
            "r94_reconciliation_status": (
                retained.get("reconciliation_status") if retained else None
            ),
            "r101_assessment": finding["assessment"],
            "r101_finding_sha256": _sealed(finding),
            "r71_triage_class": triage["triage_class"],
            "r94_rejected_planned_authority_ids": sorted(rejected),
            "effective_planned_authority_ids": effective_planned,
            "effective_inside_candidate_source_identities": recovery.get(
                "planned_source_identities_in_candidate", []
            ),
            "effective_outside_candidate_authority_ids": effective_outside,
            "remaining_dependency": (retained.get("remaining_dependency") if retained else route),
            "owner_decision_required": True,
            "technical_qualification_assigned": False,
        }
        output_rows.append({**material, "record_content_sha256": _sealed(material)})
        route_counts[route] += 1

    if (
        len(output_rows) != 364
        or len({item["row_id"] for item in output_rows}) != 364
        or dict(sorted(route_counts.items())) != EXPECTED_ROUTE_COUNTS
    ):
        raise ValueError("phase2a_r102_route_inventory_invalid")
    outside_records = [
        {
            "authority_identity_id": authority_id,
            "affected_row_count": len(sorted(set(row_ids))),
            "affected_row_ids": sorted(set(row_ids)),
            "retrieval_status": "OFFICIAL_PRIMARY_SOURCE_QUARANTINE_REQUIRED",
            "source_admission_authorized": False,
        }
        for authority_id, row_ids in sorted(outside_authority_rows.items())
    ]
    if (
        len(outside_records) != 16
        or sum(item["affected_row_count"] for item in outside_records) != 26
    ):
        raise ValueError("phase2a_r102_outside_source_inventory_invalid")

    material = {
        "schema": "legalbot.v111.phase2a.post-r101-research-routing-364.v1",
        "status": "POST_R101_RESEARCH_SCOPE_RECONCILED_OWNER_DECISIONS_UNCHANGED",
        "source_r101_content_sha256": r101["artifact_content_sha256"],
        "source_r98d_content_sha256": r98d["artifact_content_sha256"],
        "source_r96_ready_content_sha256": ready_artifact["artifact_content_sha256"],
        "source_r96_retained_content_sha256": retained_artifact["artifact_content_sha256"],
        "source_r71_content_sha256": r71["artifact_content_sha256"],
        "source_r86_content_sha256": r86["artifact_content_sha256"],
        "source_r95_uksc_content_sha256": r95_uksc["artifact_content_sha256"],
        "row_count": len(output_rows),
        "route_counts": dict(sorted(route_counts.items())),
        "r94_approved_rejected_mapping_count": len(approved_rejection_hashes),
        "outside_source_research_authority_count": len(outside_records),
        "outside_source_research_row_link_count": sum(
            item["affected_row_count"] for item in outside_records
        ),
        "outside_source_research_authorities": outside_records,
        "rows": sorted(output_rows, key=lambda item: item["row_id"]),
        "owner_decisions_applied": False,
        "new_owner_decisions_created": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r102_output_mode_invalid")
    files = {
        "POST-R101-RESEARCH-ROUTING-364.json": _pretty_json(artifact),
        "OUTSIDE-SOURCE-RESEARCH-SCOPE-16.json": _pretty_json(
            {
                "schema": "legalbot.v111.phase2a.outside-source-research-scope-16.v1",
                "record_count": len(outside_records),
                "records": outside_records,
                "source_admission_authorized": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
        ),
        "OUTCOME.txt": (
            b"POST-R101 RESEARCH ROUTING RECONCILED. NO NEW OWNER DECISION, "
            b"SOURCE ADMISSION, INDEXING, PHASE 2B, OR DEVELOPMENT 30.\n"
        ),
    }
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    sums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in sorted(files))
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode("utf-8"))
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    artifact = build_routing(args.output_root)
    print(
        json.dumps(
            {
                "artifact_content_sha256": artifact["artifact_content_sha256"],
                "row_count": artifact["row_count"],
                "route_counts": artifact["route_counts"],
                "outside_source_research_authority_count": artifact[
                    "outside_source_research_authority_count"
                ],
                "phase2b_authorized": artifact["phase2b_authorized"],
                "development30_authorized": artifact["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
