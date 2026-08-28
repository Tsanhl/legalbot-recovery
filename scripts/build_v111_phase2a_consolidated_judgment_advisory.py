#!/usr/bin/env python3
"""Consolidate all 20 judgment advisories and nine source proposals."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_REGISTER = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
    / "COMPLETE-JUDGMENT-LATER-TREATMENT-REGISTER-20.json"
)
NO_RELIANCE = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r54-no-reliance-judgment-advisory"
    / "NO-585-RELIANCE-JUDGMENT-ADVISORY-6.json"
)
ORIGINAL_RELATIONSHIPS = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r55-targeted-treatment-advisory"
    / "TARGETED-LATER-TREATMENT-RELATIONSHIPS-ADVISORY-5.json"
)
ADDITIONAL_RELATIONSHIPS = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r58-additional-treatment-advisory"
    / "ADDITIONAL-LATER-TREATMENT-RELATIONSHIPS-ADVISORY-5.json"
)
BOUNDED_SEARCH_LOG = PROJECT_ROOT / "config/phase2a_bounded_judgment_search_log.2026-08-25.v1.json"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r59-consolidated-judgment-advisory"
)

EXPECTED_DIGESTS = {
    "base": "f59c682b1162300fed741a226758d04492a9d39f796e336fca1788e019c336a4",
    "no_reliance": "b4092b9479f59b6b29c133f6b99e2526550957060ff8facf9ad4b92622c68026",
    "original": "e6d6cfecd46577ac62f8b301184b27a698b444afd5151c2f7d3c237ccc927524",
    "additional": "e35406b3bfebadec733017ef6577cbafc2a3868e84f91d878520f8e208214f66",
}
EXPECTED_NO_LEAD_CITATIONS = {
    "[2016] UKSC 47",
    "[2017] UKSC 51",
    "[2024] UKSC 36",
    "[2024] UKSC 43",
    "[2025] UKSC 26",
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_consolidated_judgment_input_not_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_consolidated_judgment_input_not_object")
    return value


def _verify_seal(value: Mapping[str, Any], *, expected: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop("artifact_content_sha256", ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material) or supplied != expected:
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


def _validate_bounded_log(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    records = value.get("records")
    if (
        value.get("schema") != "legalbot.v111.phase2a.bounded-judgment-search-log.v1"
        or value.get("as_of_date") != "2026-08-14"
        or value.get("record_count") != 5
        or value.get("search_is_exhaustive") is not False
        or value.get("absence_of_candidate_proves_no_later_treatment") is not False
        or value.get("source_admission_authorized") is not False
        or value.get("phase2b_authorized") is not False
        or value.get("development30_authorized") is not False
        or not isinstance(records, list)
        or len(records) != 5
    ):
        raise ValueError("phase2a_consolidated_judgment_search_boundary_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if (
            not isinstance(record, dict)
            or record.get("neutral_citation") not in EXPECTED_NO_LEAD_CITATIONS
            or record.get("candidate_later_treatment_leads_identified") != []
            or record.get("proposed_owner_outcome") != "NO_MATERIAL_LATER_TREATMENT_IDENTIFIED"
            or not isinstance(record.get("queries"), list)
            or len(record["queries"]) != 2
        ):
            raise ValueError("phase2a_consolidated_judgment_search_record_invalid")
        source_version_id = str(record.get("source_version_id") or "")
        if not source_version_id.startswith("source-version-") or source_version_id in by_id:
            raise ValueError("phase2a_consolidated_judgment_search_identity_invalid")
        by_id[source_version_id] = record
    if {record["neutral_citation"] for record in by_id.values()} != EXPECTED_NO_LEAD_CITATIONS:
        raise ValueError("phase2a_consolidated_judgment_search_coverage_invalid")
    return by_id


def _relationship_records(value: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = value.get("records")
    if not isinstance(records, list):
        raise ValueError("phase2a_consolidated_judgment_relationship_records_invalid")
    result: list[dict[str, Any]] = []
    for record in records:
        if (
            not isinstance(record, dict)
            or record.get("owner_outcome") is not None
            or record.get("owner_decision_required") is not True
            or record.get("proposition_level_materiality_approved") is not False
            or record.get("source_admitted") is not False
            or record.get("indexed") is not False
            or record.get("embedded") is not False
            or record.get("candidate_mutated") is not False
            or record.get("phase2b_authorized") is not False
            or record.get("development30_authorized") is not False
        ):
            raise ValueError("phase2a_consolidated_judgment_relationship_boundary_invalid")
        result.append(record)
    return result


def _source_admission_proposals(
    relationships: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in relationships:
        grouped[str(row["source_lead_content_sha256"])].append(row)
    if len(grouped) != 9:
        raise ValueError("phase2a_consolidated_judgment_source_proposal_count_invalid")
    proposals: list[dict[str, Any]] = []
    for source_digest, rows in sorted(
        grouped.items(), key=lambda item: str(item[1][0]["candidate_neutral_citation"])
    ):
        identities = {
            (
                str(row["candidate_neutral_citation"]),
                str(row["candidate_case_name"]),
                str(row["candidate_judgment_date"]),
                str(row["court_weight"]),
            )
            for row in rows
        }
        if len(identities) != 1 or not _SHA256.fullmatch(source_digest):
            raise ValueError("phase2a_consolidated_judgment_source_identity_invalid")
        citation, name, judgment_date, court_weight = identities.pop()
        relationships_for_source = sorted(
            [
                {
                    "target_neutral_citation": str(row["target_neutral_citation"]),
                    "advisory_relationship": str(row["advisory_relationship"]),
                    "recommended_owner_outcome": str(row["recommended_owner_outcome"]),
                    "relationship_record_content_sha256": str(row["record_content_sha256"]),
                }
                for row in rows
            ],
            key=lambda row: (row["target_neutral_citation"], row["advisory_relationship"]),
        )
        material = {
            "schema": "legalbot.v111.phase2a.judgment-source-admission-proposal.v1",
            "proposal_id": f"judgment-source-proposal-{source_digest[:16]}",
            "source_lead_content_sha256": source_digest,
            "candidate_neutral_citation": citation,
            "candidate_case_name": name,
            "candidate_judgment_date": judgment_date,
            "court_weight": court_weight,
            "proposition_level_relationships": relationships_for_source,
            "advisory_recommendation": (
                "ADMIT_ONLY_FOR_OWNER_APPROVED_PROPOSITION_LEVEL_LATER_TREATMENT_USE"
            ),
            "owner_source_admission_outcome": None,
            "owner_decision_required": True,
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        proposals.append({**material, "proposal_content_sha256": _sealed(material)})
    return proposals


def build_consolidated_judgment_advisory(
    *,
    base_path: Path,
    no_reliance_path: Path,
    original_relationships_path: Path,
    additional_relationships_path: Path,
    bounded_search_log_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_consolidated_judgment_output_already_exists")
    base = _load_object(base_path)
    no_reliance = _load_object(no_reliance_path)
    original = _load_object(original_relationships_path)
    additional = _load_object(additional_relationships_path)
    source_digests = {
        "base": _verify_seal(base, expected=EXPECTED_DIGESTS["base"], code="base_seal_invalid"),
        "no_reliance": _verify_seal(
            no_reliance,
            expected=EXPECTED_DIGESTS["no_reliance"],
            code="no_reliance_seal_invalid",
        ),
        "original": _verify_seal(
            original,
            expected=EXPECTED_DIGESTS["original"],
            code="original_relationships_seal_invalid",
        ),
        "additional": _verify_seal(
            additional,
            expected=EXPECTED_DIGESTS["additional"],
            code="additional_relationships_seal_invalid",
        ),
    }
    base_records = base.get("records")
    if (
        not isinstance(base_records, list)
        or len(base_records) != 20
        or base.get("pending_owner_decision_count") != 20
        or base.get("source_admission_authorized") is not False
        or base.get("candidate_mutated") is not False
        or base.get("phase2b_authorized") is not False
        or base.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_consolidated_judgment_base_boundary_invalid")

    no_reliance_rows = no_reliance.get("judgment_recommendations")
    if not isinstance(no_reliance_rows, list) or len(no_reliance_rows) != 6:
        raise ValueError("phase2a_consolidated_judgment_no_reliance_invalid")
    excluded_by_id: dict[str, dict[str, Any]] = {}
    for row in no_reliance_rows:
        if (
            not isinstance(row, dict)
            or row.get("owner_outcome") is not None
            or row.get("source_admitted") is not False
        ):
            raise ValueError("phase2a_consolidated_judgment_no_reliance_boundary_invalid")
        excluded_by_id[str(row["source_version_id"])] = row
    if len(excluded_by_id) != 6:
        raise ValueError("phase2a_consolidated_judgment_no_reliance_coverage_invalid")

    relationship_rows = [
        *_relationship_records(original),
        *_relationship_records(additional),
    ]
    relationships_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in relationship_rows:
        relationships_by_target[str(row["target_neutral_citation"])].append(row)
    search_log = _load_object(bounded_search_log_path)
    search_by_id = _validate_bounded_log(search_log)

    consolidated: list[dict[str, Any]] = []
    category_counts: dict[str, int] = defaultdict(int)
    for base_row in base_records:
        if not isinstance(base_row, dict) or not isinstance(base_row.get("judgment_record"), dict):
            raise ValueError("phase2a_consolidated_judgment_base_record_invalid")
        judgment = base_row["judgment_record"]
        source_version_id = str(judgment.get("source_version_id") or "")
        citation = str(judgment.get("neutral_citation") or "")
        relation_rows = relationships_by_target.get(citation, [])
        exclusion = excluded_by_id.get(source_version_id)
        search = search_by_id.get(source_version_id)
        categories_present = sum(
            value is not None and value != [] for value in (exclusion, relation_rows, search)
        )
        if categories_present != 1:
            raise ValueError("phase2a_consolidated_judgment_category_coverage_invalid")
        if exclusion is not None:
            category = "NO_585_PROPOSITION_RELIANCE"
            recommendation = "EXCLUDE_BECAUSE_NO_585_PROPOSITION_RELIANCE"
            evidence = {"no_reliance_record_content_sha256": exclusion["record_content_sha256"]}
        elif relation_rows:
            category = "EXACT_LATER_TREATMENT_RELATIONSHIP_IDENTIFIED"
            if citation == "[2021] UKSC 20":
                recommendation = "AFFIRMED"
                material_note = "LIMITED_CHECKLIST_USE_OUTSIDE_SCOPE_OF_DUTY_CONTEXT"
            else:
                outcomes = {str(row["recommended_owner_outcome"]) for row in relation_rows}
                if len(outcomes) != 1:
                    raise ValueError("phase2a_consolidated_judgment_relationship_outcome_conflict")
                recommendation = outcomes.pop()
                material_note = None
            evidence = {
                "relationship_record_content_sha256s": sorted(
                    str(row["record_content_sha256"]) for row in relation_rows
                ),
                "advisory_relationships": sorted(
                    str(row["advisory_relationship"]) for row in relation_rows
                ),
                "material_note": material_note,
            }
        else:
            category = "BOUNDED_OFFICIAL_SEARCH_NO_MATERIAL_LEAD_IDENTIFIED"
            recommendation = "NO_MATERIAL_LATER_TREATMENT_IDENTIFIED"
            evidence = {
                "bounded_search_record_sha256": _sealed(search),
                "search_is_exhaustive": False,
                "absence_proves_no_later_treatment": False,
            }
        material = {
            "schema": "legalbot.v111.phase2a.consolidated-judgment-advisory-row.v1",
            "ordinal": base_row["ordinal"],
            "source_version_id": source_version_id,
            "neutral_citation": citation,
            "title": str(judgment.get("title") or ""),
            "total_585_proposition_reference_count": (
                int(judgment.get("approved_137_row_reference_count") or 0)
                + int(judgment.get("unresolved_502_row_reference_count") or 0)
            ),
            "advisory_category": category,
            "advisory_evidence": evidence,
            "recommended_owner_outcome": recommendation,
            "allowed_owner_outcomes": base_row["owner_decision_options"],
            "owner_outcome": None,
            "owner_comments": None,
            "owner_decision_required": True,
            "targeted_search_is_exhaustive": False,
            "technical_qualification_assigned": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        consolidated.append({**material, "record_content_sha256": _sealed(material)})
        category_counts[category] += 1

    if len(consolidated) != 20 or {row["ordinal"] for row in consolidated} != set(range(1, 21)):
        raise ValueError("phase2a_consolidated_judgment_final_coverage_invalid")
    source_proposals = _source_admission_proposals(relationship_rows)
    material = {
        "schema": "legalbot.v111.phase2a.consolidated-judgment-advisory.v1",
        "status": "ALL_20_JUDGMENT_ADVISORIES_AND_9_SOURCE_PROPOSALS_READY_FOR_CONSOLIDATED_OWNER_BATCH",
        "source_artifact_content_sha256s": source_digests,
        "bounded_search_log_file_sha256": _sha256_file(bounded_search_log_path),
        "record_count": len(consolidated),
        "records": consolidated,
        "category_counts": dict(sorted(category_counts.items())),
        "source_admission_proposal_count": len(source_proposals),
        "source_admission_proposals": source_proposals,
        "pending_judgment_owner_decision_count": 20,
        "pending_source_admission_owner_decision_count": 9,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_consolidated_judgment_output_mode_invalid")
    name = "CONSOLIDATED-JUDGMENT-ADVISORY-20-AND-SOURCE-PROPOSALS-9.json"
    _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        "ALL 20 JUDGMENT ADVISORIES AND NINE UNIQUE PROPOSITION-LEVEL SOURCE "
        "PROPOSALS ARE READY FOR THE LATER CONSOLIDATED OWNER BATCH. NO OWNER "
        "DECISION OR SOURCE ADMISSION HAS BEEN APPLIED. PHASE 2B AND DEVELOPMENT "
        "30 ARE NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    sums = "".join(
        f"{_sha256_file(output_root / item)}  {item}\n" for item in (name, "OUTCOME.txt")
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return artifact


def _failure_fingerprint(exc: BaseException) -> str:
    return _sha256(f"{type(exc).__name__}:{exc}".encode())


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=BASE_REGISTER)
    parser.add_argument("--no-reliance", type=Path, default=NO_RELIANCE)
    parser.add_argument("--original", type=Path, default=ORIGINAL_RELATIONSHIPS)
    parser.add_argument("--additional", type=Path, default=ADDITIONAL_RELATIONSHIPS)
    parser.add_argument("--search-log", type=Path, default=BOUNDED_SEARCH_LOG)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    output_root = args.output_root.resolve()
    try:
        result = build_consolidated_judgment_advisory(
            base_path=args.base.resolve(strict=True),
            no_reliance_path=args.no_reliance.resolve(strict=True),
            original_relationships_path=args.original.resolve(strict=True),
            additional_relationships_path=args.additional.resolve(strict=True),
            bounded_search_log_path=args.search_log.resolve(strict=True),
            output_root=output_root,
        )
    except Exception as exc:
        if not output_root.exists():
            output_root.mkdir(parents=True, mode=0o700)
        if output_root.is_dir() and not (output_root / "FAILURE.json").exists():
            failure = {
                "schema": "legalbot.v111.phase2a.consolidated-judgment-failure.v1",
                "status": "FAILED_DIAGNOSTICS_PERSISTED_BEFORE_EXIT",
                "failure_type": type(exc).__name__,
                "failure_message": str(exc),
                "failure_fingerprint": _failure_fingerprint(exc),
                "affected_stage": "PHASE2A_CONSOLIDATED_JUDGMENT_ADVISORY",
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            _write_exclusive(output_root / "FAILURE.json", _pretty_json(failure))
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "artifact_content_sha256": result["artifact_content_sha256"],
                "record_count": result["record_count"],
                "source_admission_proposal_count": result["source_admission_proposal_count"],
                "owner_decisions_applied": result["owner_decisions_applied"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
                "output_root": str(output_root),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
