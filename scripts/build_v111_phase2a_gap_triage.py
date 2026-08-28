#!/usr/bin/env python3
"""Build a sealed deterministic triage of the complete 448 issue advisories."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import build_v111_phase2a_authority_plan_advisory as planner  # noqa: E402
from scripts import resolve_v111_phase2a_authority_plan_locators as locator  # noqa: E402
from scripts import verify_v111_phase2a_exact_semantic_spans_advisory as verifier  # noqa: E402

OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
R49_PATH = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r49-safe-subset-approved"
    / "REMAINING-SUBSTANTIVE-OWNER-DECISIONS-478.json"
)
R50_PATH = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r50-authority-plan-advisory"
    / "ADVISORY-AUTHORITY-PLANS-448.json"
)
R70_PATH = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r70-complete-issue-advisory-448"
    / "COMPLETE-ISSUE-ADVISORY-448.json"
)
CATALOGUE_PATH = PROJECT_ROOT / "data/catalog.sqlite3"
CASES_PATH = planner.DEFAULT_CASES
OUTPUT_ROOT = OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r71-gap-triage"
OUTPUT_PATH = OUTPUT_ROOT / "ISSUE-GAP-TRIAGE-448.json"

EXPECTED_R49_CONTENT_SHA256 = planner.EXPECTED_REMAINING_CONTENT_SHA256
EXPECTED_R50_CONTENT_SHA256 = "f53537cb5b050547cb01282fbc8314c7e66dbf51e5e6407963336397fe59cd77"
EXPECTED_R70_CONTENT_SHA256 = "a022848094a5e4ef27f97b6c245c992f1d311509163d084ecc7ed3aa021def58"
FCL_HOST = "caselaw.nationalarchives.gov.uk"
LEGISLATION_HOST = "www.legislation.gov.uk"
TARGET_CEILING_DATE = "2026-08-14"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOCATOR_SEGMENTS = frozenset(
    {"article", "chapter", "part", "regulation", "rule", "schedule", "section"}
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


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
        raise ValueError("phase2a_gap_triage_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_gap_triage_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


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


def _load_cases() -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for line in CASES_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        case_id = str(value.get("case_id") or "")
        if not case_id or case_id in cases:
            raise ValueError("phase2a_gap_triage_case_registry_invalid")
        cases[case_id] = value
    if len(cases) != 60:
        raise ValueError("phase2a_gap_triage_case_count_invalid")
    return cases


def _catalogue_urls(
    connection: sqlite3.Connection, authority_ids: set[str]
) -> dict[str, list[dict[str, Any]]]:
    if not authority_ids:
        return {}
    placeholders = ",".join("?" for _ in authority_ids)
    rows = connection.execute(
        f"""
        SELECT sv.authority_identity_id, sv.id, sv.title, sv.canonical_url,
               sv.currentness_status, sv.review_status, d.status, d.lane
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.authority_identity_id IN ({placeholders})
          AND sv.review_status='approved'
          AND d.status='citable'
          AND d.lane='primary_authority'
        ORDER BY sv.authority_identity_id, sv.created_at DESC, sv.id
        """,
        tuple(sorted(authority_ids)),
    ).fetchall()
    by_id: dict[str, list[dict[str, Any]]] = {}
    seen: dict[str, set[tuple[str, str]]] = {}
    for row in rows:
        authority_id = str(row["authority_identity_id"] or "")
        url = str(row["canonical_url"] or "")
        source_id = str(row["id"] or "")
        identity = (source_id, url)
        if identity in seen.setdefault(authority_id, set()):
            continue
        seen[authority_id].add(identity)
        by_id.setdefault(authority_id, []).append(
            {
                "source_version_id": source_id,
                "title": str(row["title"] or ""),
                "canonical_url": url,
                "canonical_host": (urlparse(url).hostname or "").casefold(),
                "currentness_status": str(row["currentness_status"] or ""),
            }
        )
    return by_id


def _canonical_legislation_identity(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if (parsed.hostname or "").casefold() != LEGISLATION_HOST:
        raise ValueError("phase2a_gap_triage_legislation_host_invalid")
    parts = [part for part in parsed.path.split("/") if part]
    stop = next(
        (index for index, part in enumerate(parts) if part.casefold() in _LOCATOR_SEGMENTS),
        len(parts),
    )
    authority_parts = parts[:stop]
    locator_parts = parts[stop:]
    if len(authority_parts) < 3 or authority_parts[0] not in {
        "eur",
        "ukpga",
        "uksi",
    }:
        raise ValueError("phase2a_gap_triage_legislation_identity_invalid")
    return ":".join(authority_parts), "/".join(locator_parts)


def _local_official_snapshots(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT sv.id, sv.authority_identity_id, sv.title, sv.version_sha256,
               sv.as_of_date, sv.currentness_status, sv.canonical_url,
               sv.licence_name, sv.metadata_json
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND d.status='citable'
          AND d.lane='primary_authority'
          AND sv.authority_identity_id LIKE 'local-path-sha256:%'
          AND sv.canonical_url LIKE 'https://www.legislation.gov.uk/%'
          AND COALESCE(json_extract(sv.metadata_json, '$.identity_verified'), 0)=1
          AND COALESCE(json_extract(sv.metadata_json, '$.currentness_verified'), 0)=1
        ORDER BY sv.title, sv.canonical_url, sv.id
        """
    ).fetchall()
    snapshots: list[dict[str, Any]] = []
    for row in rows:
        url = str(row["canonical_url"] or "")
        authority_id, locator_text = _canonical_legislation_identity(url)
        as_of_date = str(row["as_of_date"] or "") or None
        material = {
            "schema": "legalbot.v111.phase2a.local-official-snapshot-proposal.v1",
            "staging_source_version_id": str(row["id"]),
            "staging_authority_identity_id": str(row["authority_identity_id"]),
            "proposed_canonical_authority_identity_id": authority_id,
            "title": str(row["title"] or ""),
            "canonical_url": url,
            "locator": locator_text,
            "version_sha256": str(row["version_sha256"] or ""),
            "as_of_date": as_of_date,
            "post_target_ceiling_snapshot": bool(as_of_date and as_of_date > TARGET_CEILING_DATE),
            "temporal_equivalence_to_target_required": True,
            "eligible_as_target_date_evidence": False,
            "currentness_status": str(row["currentness_status"] or ""),
            "licence_name": str(row["licence_name"] or ""),
            "identity_rebinding_required": True,
            "owner_proposition_level_admission_required": True,
            "admitted": False,
        }
        snapshots.append({**material, "record_content_sha256": _sealed(material)})
    if len(snapshots) != 45:
        raise ValueError("phase2a_gap_triage_local_snapshot_count_changed")
    return snapshots


def main() -> None:
    if OUTPUT_ROOT.exists() or OUTPUT_ROOT.is_symlink():
        raise ValueError("phase2a_gap_triage_output_already_exists")
    r49 = _load_object(R49_PATH)
    r50 = _load_object(R50_PATH)
    r70 = _load_object(R70_PATH)
    r49_digest = _verify_seal(r49, "artifact_content_sha256", "phase2a_gap_triage_r49_invalid")
    r50_digest = _verify_seal(r50, "artifact_content_sha256", "phase2a_gap_triage_r50_invalid")
    r70_digest = _verify_seal(r70, "artifact_content_sha256", "phase2a_gap_triage_r70_invalid")
    if (
        r49_digest != EXPECTED_R49_CONTENT_SHA256
        or r50_digest != EXPECTED_R50_CONTENT_SHA256
        or r70_digest != EXPECTED_R70_CONTENT_SHA256
        or r49.get("category_counts", {}).get("issue") != 448
        or r50.get("issue_count") != 448
        or r70.get("issue_count") != 448
        or r70.get("held_row_count") != 0
        or r70.get("owner_decisions_applied") is not False
    ):
        raise ValueError("phase2a_gap_triage_source_boundary_invalid")
    if _sha256_file(CATALOGUE_PATH) != locator.EXPECTED_CATALOGUE_FILE_SHA256:
        raise ValueError("phase2a_gap_triage_catalogue_identity_changed")

    issue_items = [item for item in r49["items"] if item.get("category") == "issue"]
    issues = {str(item["item_id"]): item for item in issue_items}
    plans = {str(item["row_id"]): item for item in r50["plans"]}
    findings = {str(item["row_id"]): item for item in r70["findings"]}
    if len(issues) != 448 or set(issues) != set(plans) or set(issues) != set(findings):
        raise ValueError("phase2a_gap_triage_row_coverage_invalid")
    candidate_sources, candidate_manifest_digest, candidate_manifest_file = (
        verifier._load_candidate_manifest(verifier.DEFAULT_CANDIDATE_MANIFEST)
    )
    candidate_authorities = {
        str(source["authority_identity_id"]) for source in candidate_sources.values()
    }
    selected_authorities = {
        str(selection["authority_id"])
        for plan in plans.values()
        for selection in plan.get("selections", [])
    }
    connection = sqlite3.connect(f"file:{CATALOGUE_PATH.resolve()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        source_urls = _catalogue_urls(connection, selected_authorities)
        local_snapshots = _local_official_snapshots(connection)
    finally:
        connection.close()

    cases = _load_cases()
    rows: list[dict[str, Any]] = []
    classes: Counter[str] = Counter()
    fcl_rows = 0
    for row_id in issues:
        issue = issues[row_id]
        plan = plans[row_id]
        finding = findings[row_id]
        selections = []
        outside_authorities: list[str] = []
        fcl_only_authorities: list[str] = []
        for selection in plan.get("selections", []):
            authority_id = str(selection["authority_id"])
            in_candidate = authority_id in candidate_authorities
            catalog_records = source_urls.get(authority_id, [])
            hosts = {
                str(record["canonical_host"])
                for record in catalog_records
                if record.get("canonical_host")
            }
            fcl_only = bool(hosts) and hosts == {FCL_HOST}
            if not in_candidate:
                outside_authorities.append(authority_id)
            if fcl_only:
                fcl_only_authorities.append(authority_id)
            selections.append(
                {
                    "authority_identity_id": authority_id,
                    "locator_hint": str(selection.get("locator_hint") or ""),
                    "in_exact_candidate_manifest": in_candidate,
                    "catalogue_records": catalog_records[:3],
                    "find_case_law_full_text_only": fcl_only,
                }
            )

        assessment = str(finding["assessment"])
        if assessment in {
            "DIRECT_EXACT_SPAN_ADVISORY",
            "PARTIAL_EXACT_SPAN_ADVISORY",
        }:
            triage_class = "EXACT_CANDIDATE_BINDING_READY_FOR_OWNER_DECISION"
            required_action = "OWNER_REVIEW_ATOMIC_PROPOSITION_AND_EXACT_SPAN"
        elif plan.get("assessment") == "NONMATERIAL":
            triage_class = "NONMATERIAL_OR_ANALYTICAL_DIMENSION_REVIEW"
            required_action = "OWNER_CONFIRM_NONMATERIAL_OR_REQUIRE_ATOMIC_DECOMPOSITION"
        elif plan.get("assessment") == "GAP":
            triage_class = "UNRESOLVED_SOURCE_PLAN_GAP"
            required_action = "ADVISORY_SOURCE_PLANNING_AND_OFFICIAL_SOURCE_RESEARCH"
        elif outside_authorities:
            triage_class = "KNOWN_SOURCE_OUTSIDE_EXACT_CANDIDATE"
            required_action = "VERIFY_SOURCE_RIGHTS_CURRENTNESS_AND_EXACT_PROPOSITION"
        else:
            triage_class = "CANDIDATE_LOCATOR_OR_GOLD_DEFINITION_REPAIR"
            required_action = "BROADER_EXACT_LOCATOR_SEARCH_OR_ATOMIC_GOLD_CORRECTION"
        if fcl_only_authorities:
            fcl_rows += 1
        classes[triage_class] += 1
        case_id = str(issue["case_id"])
        row_material = {
            "schema": "legalbot.v111.phase2a.issue-gap-triage-row.v1",
            "row_id": row_id,
            "case_id": case_id,
            "legal_domain": str(issue["legal_domain"]),
            "issue_label": str(issue["issue_label"]),
            "case_question_sha256": _sha256(
                str(cases[case_id].get("question") or "").encode("utf-8")
            ),
            "r70_assessment": assessment,
            "r50_plan_assessment": str(plan.get("assessment") or ""),
            "triage_class": triage_class,
            "required_next_action": required_action,
            "planned_authorities": selections,
            "outside_candidate_authority_ids": sorted(set(outside_authorities)),
            "find_case_law_full_text_only_authority_ids": sorted(set(fcl_only_authorities)),
            "find_case_law_computational_analysis_permitted": False,
            "owner_decision_required": True,
            "owner_outcome": None,
            "source_admitted": False,
            "technical_qualification_assigned": False,
        }
        rows.append({**row_material, "record_content_sha256": _sealed(row_material)})

    if dict(sorted(classes.items())) != {
        "CANDIDATE_LOCATOR_OR_GOLD_DEFINITION_REPAIR": 126,
        "EXACT_CANDIDATE_BINDING_READY_FOR_OWNER_DECISION": 84,
        "KNOWN_SOURCE_OUTSIDE_EXACT_CANDIDATE": 33,
        "NONMATERIAL_OR_ANALYTICAL_DIMENSION_REVIEW": 5,
        "UNRESOLVED_SOURCE_PLAN_GAP": 200,
    }:
        raise ValueError("phase2a_gap_triage_class_counts_changed")

    material = {
        "schema": "legalbot.v111.phase2a.issue-gap-triage-448.v1",
        "status": "DETERMINISTIC_TRIAGE_COMPLETE_RESEARCH_AND_OWNER_DECISIONS_REQUIRED",
        "source_r49_content_sha256": r49_digest,
        "source_r50_content_sha256": r50_digest,
        "source_r70_content_sha256": r70_digest,
        "source_candidate_manifest_sha256": candidate_manifest_digest,
        "source_candidate_manifest_file_sha256": candidate_manifest_file,
        "source_catalogue_file_sha256": locator.EXPECTED_CATALOGUE_FILE_SHA256,
        "source_cases_file_sha256": _sha256_file(CASES_PATH),
        "target_ceiling_date": TARGET_CEILING_DATE,
        "row_count": len(rows),
        "triage_class_counts": dict(sorted(classes.items())),
        "find_case_law_affected_row_count": fcl_rows,
        "find_case_law_computational_analysis_licence_evidence_sha256": None,
        "find_case_law_full_text_excluded_from_further_automated_review": True,
        "local_official_snapshot_count": len(local_snapshots),
        "local_official_snapshots": local_snapshots,
        "rows": rows,
        "owner_decisions_applied": False,
        "technical_qualification_assigned": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    OUTPUT_ROOT.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(OUTPUT_ROOT.stat().st_mode) != 0o700:
        raise ValueError("phase2a_gap_triage_output_mode_invalid")
    _write_exclusive(OUTPUT_PATH, _pretty_json(artifact))
    _write_exclusive(
        OUTPUT_ROOT / "OUTCOME.txt",
        b"DETERMINISTIC 448-ROW TRIAGE COMPLETE. RESEARCH AND OWNER DECISIONS REMAIN REQUIRED.\n",
    )
    names = [OUTPUT_PATH.name, "OUTCOME.txt"]
    sums = "".join(f"{_sha256_file(OUTPUT_ROOT / name)}  {name}\n" for name in names).encode()
    _write_exclusive(OUTPUT_ROOT / "SHA256SUMS.txt", sums)
    print(
        json.dumps(
            {
                key: artifact[key]
                for key in (
                    "artifact_content_sha256",
                    "row_count",
                    "triage_class_counts",
                    "find_case_law_affected_row_count",
                    "local_official_snapshot_count",
                )
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
