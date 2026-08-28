#!/usr/bin/env python3
"""Build the fail-closed seminar-source owner decision packet.

The packet records the owner's Option-B route selection, proposes exact
per-source metadata bindings, and exposes every remaining legal-currentness
hold.  It does not approve a source, update the catalogue, build an index, or
authorize any later release phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_OUTPUT_ROOT = OWNER_REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-packet"
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"

JUDGMENT_REPORT = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-uk-judgments-round2-2026-08-26-verification.json"
)
LEGISLATION_REPORT = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-legislation-round2-2026-08-26-verification.json"
)
EWHC_REPORT = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-ewhc-divisions-2026-08-26-verification.json"
)
PENSIONS_JUDGMENT_REPORT = (
    PROJECT_ROOT / "data/review_queue/pensions-seminar-gap-judgments-2026-08-26-verification.json"
)
JUDGMENT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_uk_judgments_round2.2026-08-26.v1.json"
)
LEGISLATION_MANIFESTS = (
    PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v1.json",
    PROJECT_ROOT
    / "config/seminar_gap_official_legislation_round2.2026-08-26.v2-enacted-repair.json",
    PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v3-pdf-repair.json",
)
EWHC_MANIFEST = PROJECT_ROOT / "config/seminar_gap_official_ewhc_divisions.2026-08-26.v1.json"
FCL_MANIFEST = PROJECT_ROOT / "config/seminar_gap_official_fcl_search_recovery.2026-08-26.v1.json"
TITLE_RESOLUTION = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-title-resolution-2026-08-26.json"
)
ALIAS_RECONCILIATION = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-alias-reconciliation-2026-08-26.json"
)
PRIORITY_QUEUE = PROJECT_ROOT / "data/reports/seminar-gap-priority-queue-2026-08-26-v4.json"

EXPECTED_OWNER_STATEMENT = (
    "I choose Option B — OWNER_ADOPTED_INTERNAL for my private research tool. "
    "I authorize Codex to prepare the exact per-source currentness, later-treatment, "
    "jurisdiction, subject-binding and source-admission owner packet for the technically "
    "verified seminar sources. Exclude all OCR-held, unresolved, unmapped and unconfirmed "
    "sources. This does not yet authorize ACTIVE, promotion, Phase 2B, Development 30, "
    "Validation 30 or live activation."
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROHIBITED_OUTPUT = re.compile(r"(?:/users/|file:|\\x00)", re.IGNORECASE)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(material: Mapping[str, Any]) -> str:
    return _sha256(_canonical_json(dict(material)))


def _sealed_artifact(
    schema: str,
    material: Mapping[str, Any],
    *,
    digest_field: str = "artifact_content_sha256",
) -> dict[str, Any]:
    payload = {"schema": schema, **dict(material)}
    return {**payload, digest_field: _sealed(payload)}


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("seminar_owner_packet_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("seminar_owner_packet_input_must_be_object")
    return value


def _verify_report(
    path: Path,
    *,
    schema: str,
    pass_field: str,
) -> dict[str, Any]:
    report = _load_object(path)
    if report.get("schema") != schema or report.get(pass_field) is not True:
        raise ValueError("seminar_owner_packet_verification_report_invalid")
    material = dict(report)
    supplied = str(material.pop("report_content_sha256", ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sha256(_canonical_json(material)):
        raise ValueError("seminar_owner_packet_verification_report_seal_invalid")
    for field in (
        "automatic_source_admission",
        "automatic_indexing",
        "automatic_embedding",
        "candidate_mutated",
        "active_pointer_written",
        "development30_authorized",
        "validation30_authorized",
        "live_activation_authorized",
    ):
        if field in report and report[field] is not False:
            raise ValueError("seminar_owner_packet_report_authority_boundary_invalid")
    return report


def _write_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _normalise_legislation_identity(value: str) -> str:
    parsed = urlparse(value.strip())
    path = parsed.path if parsed.scheme else value.strip()
    parts = [part for part in path.split("/") if part]
    if parts and parts[0] == "id":
        parts = parts[1:]
    return "/".join(parts).casefold()


def _legislation_stable_identifier(
    authority_identity: str,
    *,
    currentness_status: str,
    as_of_date: str,
) -> str:
    parts = _normalise_legislation_identity(authority_identity).split("/")
    if len(parts) < 3 or parts[0] not in {"ukpga", "uksi"}:
        raise ValueError("seminar_owner_packet_legislation_identity_invalid")
    stem = ":".join(parts)
    if currentness_status == "downloaded_latest_available_snapshot_unreviewed":
        return f"{stem}:latest-available@{as_of_date}"
    if currentness_status == "official_enacted_snapshot_unreviewed":
        return f"{stem}:enacted"
    raise ValueError("seminar_owner_packet_legislation_currentness_status_invalid")


def _record_sha(record: Mapping[str, Any]) -> str:
    material = dict(record)
    material.pop("record_content_sha256", None)
    return _sealed(material)


def _catalogue_rows(
    catalogue_path: Path,
    content_hashes: Sequence[str],
) -> dict[str, dict[str, Any]]:
    if catalogue_path.is_symlink() or not catalogue_path.is_file():
        raise ValueError("seminar_owner_packet_catalogue_invalid")
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        active = connection.execute(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ).fetchone()
        if active is not None:
            raise ValueError("seminar_owner_packet_requires_no_active_source_scan")
        placeholders = ",".join("?" for _ in content_hashes)
        rows = connection.execute(
            f"""
            SELECT sv.id AS source_version_id,
                   sv.version_sha256,
                   sv.review_status,
                   sv.currentness_status,
                   sv.stable_identifier,
                   sv.authority_identity_id,
                   sv.title,
                   d.status AS document_status,
                   d.lane,
                   d.subject_primary,
                   d.jurisdiction,
                   d.retrieval_canonical,
                   COUNT(c.id) AS chunk_count,
                   COALESCE(SUM(c.token_count), 0) AS token_count
              FROM source_versions sv
              JOIN documents d ON d.id=sv.document_id
         LEFT JOIN chunks c ON c.source_version_id=sv.id AND c.stream='body'
             WHERE sv.superseded_by IS NULL
               AND sv.version_sha256 IN ({placeholders})
          GROUP BY sv.id, d.id
          ORDER BY sv.version_sha256, sv.id
            """,
            tuple(content_hashes),
        ).fetchall()
    finally:
        connection.close()
    grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        grouped[str(row["version_sha256"])].append(row)
    selected: dict[str, dict[str, Any]] = {}
    for content_hash in content_hashes:
        matches = grouped.get(content_hash, [])
        if len(matches) != 1:
            raise ValueError("seminar_owner_packet_current_source_version_not_exact")
        row = matches[0]
        if (
            row["review_status"] != "staged"
            or row["document_status"] != "citable"
            or row["lane"] != "primary_authority"
            or int(row["retrieval_canonical"] or 0) != 1
            or int(row["chunk_count"] or 0) < 1
        ):
            raise ValueError("seminar_owner_packet_source_not_staged_citable_canonical")
        selected[content_hash] = dict(row)
    return selected


def _source_version_payload(
    row: Mapping[str, Any],
    *,
    content_sha256: str,
) -> dict[str, Any]:
    return {
        "source_version_id": str(row["source_version_id"]),
        "content_sha256": content_sha256,
        "version_sha256": str(row["version_sha256"]),
        "review_status": str(row["review_status"]),
        "catalogue_currentness_status": str(row["currentness_status"]),
        "chunk_count": int(row["chunk_count"]),
        "token_count": int(row["token_count"]),
        "retrieval_canonical": True,
    }


def _case_record(
    *,
    report_record: Mapping[str, Any],
    manifest_target: Mapping[str, Any],
    catalogue_row: Mapping[str, Any],
    origin: str,
) -> dict[str, Any]:
    citation = str(report_record["authority_identity"])
    content_hash = str(report_record["content_sha256"])
    if (
        report_record.get("technical_verification_passed") is not True
        or report_record.get("technical_holds") not in (None, [])
        or str(manifest_target.get("content_sha256")) != content_hash
        or str(manifest_target.get("authority_identity")) != citation
    ):
        raise ValueError("seminar_owner_packet_case_record_invalid")
    title = str(manifest_target.get("source_title") or report_record.get("source_title") or "")
    official_url = str(manifest_target.get("official_url") or "")
    if not title or not official_url.startswith("https://caselaw.nationalarchives.gov.uk/"):
        raise ValueError("seminar_owner_packet_case_official_identity_invalid")
    proposed_subject = str(
        report_record.get("catalogue", {}).get("subject_primary")
        or catalogue_row.get("subject_primary")
        or "general"
    )
    teaching_subjects = sorted(
        {
            str(item)
            for item in (
                manifest_target.get("presentation_subjects")
                or manifest_target.get("subjects")
                or []
            )
        }
    )
    material = {
        "source_key": f"official-judgment:{citation.casefold()}",
        "source_family": "official_judgment",
        "origin": origin,
        "title": title,
        "official_identity": citation,
        "official_canonical_url": official_url,
        "proposed_stable_identifier": f"neutral-citation:{citation}",
        "selected_source_version": _source_version_payload(
            catalogue_row,
            content_sha256=content_hash,
        ),
        "technical_verification": {
            "passed": True,
            "official_xml_identity_exact": True,
            "verification_record_content_sha256": _record_sha(report_record),
        },
        "jurisdiction_binding": {
            "proposed_value": str(
                report_record.get("expected_jurisdiction") or "England and Wales"
            ),
            "basis": "official_neutral_citation_and_official_xml",
            "owner_outcome": None,
        },
        "subject_binding": {
            "proposed_primary": proposed_subject,
            "teaching_labels_advisory_only": teaching_subjects,
            "basis": "catalogue_classification_v10_owner_binding_required",
            "owner_outcome": None,
        },
        "currentness": {
            "status": "JUDGMENT_TEXT_SNAPSHOT_CURRENTNESS_NOT_CONSOLIDATED",
            "currentness_verified": False,
            "full_current_law_verification_eligible": False,
            "owner_outcome": None,
        },
        "later_treatment": {
            "applicable": True,
            "status": "OWNER_REVIEW_REQUIRED_NO_OFFICIAL_CITATOR_CONCLUSION_RECORDED",
            "verified": False,
            "owner_outcome": None,
        },
        "source_admission": {
            "proposed_owner_outcome": ("ADMIT_TO_PRIVATE_RESEARCH_INDEX_WITH_LATER_TREATMENT_HOLD"),
            "owner_outcome": None,
            "authorized": False,
            "answer_release_eligible": False,
        },
        "indexing_authorized": False,
        "embedding_authorized": False,
    }
    return {**material, "record_content_sha256": _sealed(material)}


def _legislation_record(
    *,
    authority: Mapping[str, Any],
    representation: Mapping[str, Any],
    manifest_target: Mapping[str, Any],
    catalogue_row: Mapping[str, Any],
    as_of_date: str,
) -> dict[str, Any]:
    identity = str(authority["authority_identity"])
    content_hash = str(representation["content_sha256"])
    if (
        authority.get("retrieval_ready") is not True
        or representation.get("technical_integrity_passed") is not True
        or representation.get("expected_catalogue_status") != "citable"
        or str(manifest_target.get("content_sha256")) != content_hash
        or _normalise_legislation_identity(str(manifest_target.get("authority_identity")))
        != _normalise_legislation_identity(identity)
    ):
        raise ValueError("seminar_owner_packet_legislation_record_invalid")
    title = str(manifest_target.get("source_title") or "")
    snapshot_status = str(manifest_target.get("currentness_status") or "")
    official_identity_path = _normalise_legislation_identity(identity)
    stable_identifier = _legislation_stable_identifier(
        identity,
        currentness_status=snapshot_status,
        as_of_date=as_of_date,
    )
    canonical_url = f"https://www.legislation.gov.uk/id/{official_identity_path}"
    teaching_subjects = sorted(
        {str(item) for item in manifest_target.get("presentation_subjects", [])}
    )
    proposed_subject = str(
        representation.get("catalogue", {}).get("subject_primary")
        or catalogue_row.get("subject_primary")
        or "general"
    )
    material = {
        "source_key": f"official-legislation:{official_identity_path}",
        "source_family": "legislation",
        "origin": "seminar_gap_official_legislation_round2",
        "title": title,
        "official_identity": identity,
        "official_canonical_url": canonical_url,
        "official_snapshot_url": str(representation["representation_identity"]),
        "proposed_stable_identifier": stable_identifier,
        "selected_source_version": _source_version_payload(
            catalogue_row,
            content_sha256=content_hash,
        ),
        "technical_verification": {
            "passed": True,
            "official_identity_exact": True,
            "verification_record_content_sha256": _record_sha(representation),
        },
        "jurisdiction_binding": {
            "proposed_value": "United Kingdom legislation",
            "territorial_extent_status": "OWNER_REVIEW_REQUIRED",
            "owner_outcome": None,
        },
        "subject_binding": {
            "proposed_primary": proposed_subject,
            "teaching_labels_advisory_only": teaching_subjects,
            "basis": "catalogue_classification_v10_owner_binding_required",
            "owner_outcome": None,
        },
        "currentness": {
            "snapshot_status": snapshot_status,
            "review_target_date": as_of_date,
            "currentness_verified": False,
            "extent_effects_verified": False,
            "full_current_law_verification_eligible": False,
            "owner_outcome": None,
        },
        "later_treatment": {
            "applicable": False,
            "status": "NOT_APPLICABLE_USE_CURRENTNESS_EXTENT_EFFECTS_REVIEW",
            "verified": False,
            "owner_outcome": None,
        },
        "source_admission": {
            "proposed_owner_outcome": (
                "ADMIT_TO_PRIVATE_RESEARCH_INDEX_WITH_CURRENTNESS_EXTENT_EFFECTS_HOLD"
            ),
            "owner_outcome": None,
            "authorized": False,
            "answer_release_eligible": False,
        },
        "indexing_authorized": False,
        "embedding_authorized": False,
    }
    return {**material, "record_content_sha256": _sealed(material)}


def _initial_legislation_identities(manifests: Sequence[Mapping[str, Any]]) -> set[str]:
    initial: set[str] = set()
    first = manifests[0]
    for item in first.get("targets", []):
        initial.add(_normalise_legislation_identity(str(item["authority_identity"])))
    for item in first.get("already_catalogued", []):
        initial.add(_normalise_legislation_identity(str(item["canonical_url"])))
    for item in manifests[1].get("targets", []):
        initial.add(_normalise_legislation_identity(str(item["authority_identity"])))
    if len(initial) != 75:
        raise ValueError("seminar_owner_packet_initial_legislation_identity_count_changed")
    return initial


def _build_exclusions(
    *,
    legislation_report: Mapping[str, Any],
    legislation_manifests: Sequence[Mapping[str, Any]],
    ewhc_manifest: Mapping[str, Any],
    fcl_manifest: Mapping[str, Any],
    title_resolution: Mapping[str, Any],
    alias_reconciliation: Mapping[str, Any],
) -> dict[str, Any]:
    ocr = [
        {
            "official_identity": str(item["authority_identity"]),
            "reason_code": str(item["hold_reason"]),
        }
        for item in legislation_report["authorities"]
        if item.get("retrieval_ready") is not True
    ]
    if len(ocr) != 1 or ocr[0]["reason_code"] != "OCR_TOOLCHAIN_UNAVAILABLE":
        raise ValueError("seminar_owner_packet_ocr_exclusion_changed")

    ewhc_unresolved = [
        {
            "official_identity": str(item["authority_identity"]),
            "reason_code": str(item["reason_code"]),
            "subjects": sorted(str(value) for value in item.get("subjects", [])),
        }
        for item in ewhc_manifest["still_unresolved"]
    ]
    fcl_unresolved = [
        {
            "official_identity": str(item["authority_identity"]),
            "reason_code": str(item["reason_code"]),
            "subjects": sorted(str(value) for value in item.get("subjects", [])),
        }
        for item in fcl_manifest["still_unresolved"]
    ]

    parent_unresolved = [
        item
        for item in title_resolution["records"]
        if item.get("resolution_status") == "UNRESOLVED_RESEARCH_REQUIRED"
    ]
    alias_rows = list(alias_reconciliation["records"])
    alias_references = {str(item["extracted_reference"]) for item in alias_rows}
    unmapped_parent = [
        {
            "extracted_reference": str(item["extracted_reference"]),
            "extracted_reference_sha256": str(item["extracted_reference_sha256"]),
            "subjects": sorted(str(value) for value in item.get("presentation_subjects", [])),
            "reason_code": "NO_EXACT_OFFICIAL_IDENTITY_OR_BOUNDED_ALIAS",
        }
        for item in parent_unresolved
        if str(item["extracted_reference"]) not in alias_references
    ]
    alias_not_found = [
        {
            "extracted_reference": str(item["extracted_reference"]),
            "subjects": sorted(str(value) for value in item.get("presentation_subjects", [])),
            "reason_code": "OFFICIAL_ALIAS_NOT_FOUND_RESEARCH_REQUIRED",
        }
        for item in alias_rows
        if item.get("resolution_status") == "OFFICIAL_ALIAS_NOT_FOUND_RESEARCH_REQUIRED"
    ]
    unmapped = sorted(
        [*unmapped_parent, *alias_not_found],
        key=lambda item: item["extracted_reference"].casefold(),
    )

    initial_identities = _initial_legislation_identities(legislation_manifests)
    aliases_by_identity: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in alias_rows:
        if item.get("resolution_status") != (
            "OFFICIAL_ALIAS_EXACT_MATCH_OWNER_INTENT_CONFIRMATION_REQUIRED"
        ):
            continue
        matches = item.get("official_exact_matches") or []
        if len(matches) != 1:
            raise ValueError("seminar_owner_packet_alias_exact_match_not_exact")
        identity = _normalise_legislation_identity(str(matches[0]["canonical_url"]))
        aliases_by_identity[identity].append(item)
    unconfirmed_aliases = []
    for identity in sorted(set(aliases_by_identity) - initial_identities):
        rows = aliases_by_identity[identity]
        match = rows[0]["official_exact_matches"][0]
        unconfirmed_aliases.append(
            {
                "official_identity": identity,
                "official_title": str(match["official_title"]),
                "official_canonical_url": str(match["canonical_url"]),
                "seminar_references": sorted({str(item["extracted_reference"]) for item in rows}),
                "subjects": sorted(
                    {
                        str(subject)
                        for item in rows
                        for subject in item.get("presentation_subjects", [])
                    }
                ),
                "reason_code": "OWNER_SEMINAR_INTENT_CONFIRMATION_REQUIRED",
            }
        )

    noncitable_representations = [
        {
            "official_identity": str(item["authority_identity"]),
            "representation_identity": str(item["representation_identity"]),
            "content_sha256": str(item["content_sha256"]),
            "reason_code": "QUARANTINED_NONCITABLE_REPRESENTATION",
        }
        for item in legislation_report["representations"]
        if item.get("expected_catalogue_status") == "quarantined"
        and str(item["authority_identity"]) != ocr[0]["official_identity"]
    ]

    counts = {
        "ocr_held_authority_count": len(ocr),
        "ewhc_unresolved_count": len(ewhc_unresolved),
        "fcl_unavailable_count": len(fcl_unresolved),
        "legislation_unmapped_or_not_exact_count": len(unmapped),
        "unconfirmed_alias_identity_count": len(unconfirmed_aliases),
        "noncitable_representation_count": len(noncitable_representations),
    }
    if counts != {
        "ocr_held_authority_count": 1,
        "ewhc_unresolved_count": 4,
        "fcl_unavailable_count": 40,
        "legislation_unmapped_or_not_exact_count": 21,
        "unconfirmed_alias_identity_count": 38,
        "noncitable_representation_count": 3,
    }:
        raise ValueError("seminar_owner_packet_exclusion_counts_changed")
    return _sealed_artifact(
        "legalbot.v111.seminar-source-exclusions.v1",
        {
            "status": "EXCLUDED_FROM_PACKET_SOURCE_ADMISSION_SCOPE",
            "counts": counts,
            "ocr_held_authorities": ocr,
            "ewhc_unresolved": sorted(ewhc_unresolved, key=lambda item: item["official_identity"]),
            "fcl_unavailable": sorted(fcl_unresolved, key=lambda item: item["official_identity"]),
            "legislation_unmapped_or_not_exact": unmapped,
            "unconfirmed_alias_identities": unconfirmed_aliases,
            "noncitable_representations": sorted(
                noncitable_representations,
                key=lambda item: (item["official_identity"], item["representation_identity"]),
            ),
            "source_admission_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
        },
    )


def _input_bindings(paths: Iterable[Path]) -> list[dict[str, Any]]:
    bindings = []
    for path in sorted(paths, key=lambda item: item.name):
        bindings.append(
            {
                "name": path.name,
                "file_sha256": _sha256_file(path),
                "byte_count": path.stat().st_size,
            }
        )
    return bindings


def _assert_output_safe(value: Any) -> None:
    raw = _canonical_json(value).decode("utf-8")
    if _PROHIBITED_OUTPUT.search(raw):
        raise ValueError("seminar_owner_packet_prohibited_path_or_uri")


def build_package(
    *,
    output_root: Path,
    catalogue_path: Path,
    recorded_at: datetime,
) -> dict[str, Any]:
    if recorded_at.tzinfo is None:
        raise ValueError("seminar_owner_packet_recorded_at_naive")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("seminar_owner_packet_output_already_exists")

    judgment_report = _verify_report(
        JUDGMENT_REPORT,
        schema="legalbot.seminar-gap-uk-judgment-verification.v1",
        pass_field="technical_verification_passed",
    )
    legislation_report = _verify_report(
        LEGISLATION_REPORT,
        schema="legalbot.seminar-gap-official-legislation-verification.v1",
        pass_field="technical_integrity_passed",
    )
    ewhc_report = _verify_report(
        EWHC_REPORT,
        schema="legalbot.seminar-gap-official-ewhc-division-verification.v1",
        pass_field="technical_verification_passed",
    )
    pensions_report = _verify_report(
        PENSIONS_JUDGMENT_REPORT,
        schema="legalbot.pensions-seminar-gap-judgment-verification.v1",
        pass_field="technical_verification_passed",
    )
    judgment_manifest = _load_object(JUDGMENT_MANIFEST)
    legislation_manifests = [_load_object(path) for path in LEGISLATION_MANIFESTS]
    ewhc_manifest = _load_object(EWHC_MANIFEST)
    fcl_manifest = _load_object(FCL_MANIFEST)
    title_resolution = _load_object(TITLE_RESOLUTION)
    alias_reconciliation = _load_object(ALIAS_RECONCILIATION)
    priority_queue = _load_object(PRIORITY_QUEUE)

    if judgment_report["summary"] != {
        "target_count": 95,
        "technical_pass_count": 95,
        "technical_failure_count": 0,
        "later_treatment_hold_count": 95,
        "source_admission_hold_count": 95,
        "metadata_hold_count": 95,
        "subject_binding_hold_count": 58,
        "chunk_count": 10584,
        "token_count": 1164941,
    }:
        raise ValueError("seminar_owner_packet_judgment_summary_changed")
    if (
        legislation_report["summary"]["authority_count"] != 44
        or legislation_report["summary"]["retrieval_ready_authority_count"] != 43
    ):
        raise ValueError("seminar_owner_packet_legislation_summary_changed")
    if ewhc_report["summary"] != {
        "staged_target_count": 3,
        "technical_pass_count": 3,
        "technical_failure_count": 0,
        "already_catalogued_count": 1,
        "still_unresolved_count": 4,
        "chunk_count": 326,
        "token_count": 33665,
    }:
        raise ValueError("seminar_owner_packet_ewhc_summary_changed")
    expected_queue_counts = {
        "official_uk_judgments_staged": 95,
        "official_uk_judgments_technical_passed": 95,
        "official_legislation_identities_newly_staged": 44,
        "official_legislation_identities_retrieval_ready": 43,
        "official_legislation_identities_ocr_held": 1,
        "ewhc_division_newly_staged": 3,
        "ewhc_division_already_catalogued": 1,
        "ewhc_division_identity_incomplete": 4,
        "find_case_law_exact_endpoint_unresolved": 40,
        "legislation_rows_still_unmapped_or_not_exact": 21,
        "additional_unique_official_alias_candidates": 38,
    }
    if any(
        priority_queue["summary"].get(key) != expected
        for key, expected in expected_queue_counts.items()
    ):
        raise ValueError("seminar_owner_packet_priority_queue_counts_changed")

    judgment_targets = {str(item["content_sha256"]): item for item in judgment_manifest["targets"]}
    ewhc_targets = {str(item["content_sha256"]): item for item in ewhc_manifest["targets"]}
    legislation_targets = {
        str(item["content_sha256"]): item
        for manifest in legislation_manifests
        for item in manifest.get("targets", [])
    }
    pensions_records = {str(item["content_sha256"]): item for item in pensions_report["records"]}

    selected_legislation: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for authority in legislation_report["authorities"]:
        if authority.get("retrieval_ready") is not True:
            continue
        candidates = [
            item
            for item in legislation_report["representations"]
            if item["authority_identity"] == authority["authority_identity"]
            and item.get("expected_catalogue_status") == "citable"
            and item.get("technical_integrity_passed") is True
        ]
        if len(candidates) != 1:
            raise ValueError("seminar_owner_packet_legislation_citable_representation_not_exact")
        selected_legislation.append((authority, candidates[0]))

    existing_ewhc = list(ewhc_manifest["already_catalogued"])
    if len(existing_ewhc) != 1:
        raise ValueError("seminar_owner_packet_existing_ewhc_count_changed")

    selected_hashes = [str(item["content_sha256"]) for item in judgment_report["records"]]
    selected_hashes.extend(
        str(representation["content_sha256"]) for _, representation in selected_legislation
    )
    selected_hashes.extend(str(item["content_sha256"]) for item in ewhc_report["records"])
    selected_hashes.append(str(existing_ewhc[0]["content_sha256"]))
    if len(selected_hashes) != 142 or len(set(selected_hashes)) != 142:
        raise ValueError("seminar_owner_packet_selected_content_hashes_not_exact")
    catalogue = _catalogue_rows(catalogue_path, selected_hashes)

    records: list[dict[str, Any]] = []
    for item in judgment_report["records"]:
        content_hash = str(item["content_sha256"])
        target = judgment_targets.get(content_hash)
        if target is None:
            raise ValueError("seminar_owner_packet_judgment_manifest_binding_missing")
        records.append(
            _case_record(
                report_record=item,
                manifest_target=target,
                catalogue_row=catalogue[content_hash],
                origin="seminar_gap_uk_judgments_round2",
            )
        )
    for authority, representation in selected_legislation:
        content_hash = str(representation["content_sha256"])
        target = legislation_targets.get(content_hash)
        if target is None:
            raise ValueError("seminar_owner_packet_legislation_manifest_binding_missing")
        records.append(
            _legislation_record(
                authority=authority,
                representation=representation,
                manifest_target=target,
                catalogue_row=catalogue[content_hash],
                as_of_date="2026-08-26",
            )
        )
    for item in ewhc_report["records"]:
        content_hash = str(item["content_sha256"])
        target = ewhc_targets.get(content_hash)
        if target is None:
            raise ValueError("seminar_owner_packet_ewhc_manifest_binding_missing")
        records.append(
            _case_record(
                report_record=item,
                manifest_target=target,
                catalogue_row=catalogue[content_hash],
                origin="seminar_gap_ewhc_division_resolution",
            )
        )
    existing = existing_ewhc[0]
    existing_hash = str(existing["content_sha256"])
    pensions_record = pensions_records.get(existing_hash)
    if pensions_record is None:
        raise ValueError("seminar_owner_packet_existing_ewhc_verification_missing")
    records.append(
        _case_record(
            report_record=pensions_record,
            manifest_target={
                **existing,
                "source_title": pensions_record["source_title"],
                "presentation_subjects": existing.get("subjects", []),
            },
            catalogue_row=catalogue[existing_hash],
            origin="already_catalogued_pensions_judgment_pack",
        )
    )
    records.sort(key=lambda item: item["source_key"])
    if len(records) != 142 or len({item["source_key"] for item in records}) != 142:
        raise ValueError("seminar_owner_packet_source_records_not_unique")
    family_counts = {
        family: sum(item["source_family"] == family for item in records)
        for family in {str(item["source_family"]) for item in records}
    }
    if family_counts != {"legislation": 43, "official_judgment": 99}:
        raise ValueError("seminar_owner_packet_source_family_counts_changed")

    exclusions = _build_exclusions(
        legislation_report=legislation_report,
        legislation_manifests=legislation_manifests,
        ewhc_manifest=ewhc_manifest,
        fcl_manifest=fcl_manifest,
        title_resolution=title_resolution,
        alias_reconciliation=alias_reconciliation,
    )

    inputs = (
        JUDGMENT_REPORT,
        LEGISLATION_REPORT,
        EWHC_REPORT,
        PENSIONS_JUDGMENT_REPORT,
        JUDGMENT_MANIFEST,
        *LEGISLATION_MANIFESTS,
        EWHC_MANIFEST,
        FCL_MANIFEST,
        TITLE_RESOLUTION,
        ALIAS_RECONCILIATION,
        PRIORITY_QUEUE,
    )
    recorded = recorded_at.astimezone(UTC).isoformat(timespec="seconds")
    receipt = _sealed_artifact(
        "legalbot.v111.seminar-source-owner-route-receipt.v1",
        {
            "status": "OWNER_ROUTE_SELECTED_PACKET_PREPARATION_ONLY",
            "owner_route": ("OWNER_ADOPTED_INTERNAL_RESEARCH_TOOL_NOT_PROFESSIONAL_CERTIFICATION"),
            "owner_statement": EXPECTED_OWNER_STATEMENT,
            "owner_statement_sha256": _sha256((EXPECTED_OWNER_STATEMENT + "\n").encode("utf-8")),
            "owner_decision_date": "2026-08-27",
            "recorded_at": recorded,
            "packet_preparation_authorized": True,
            "source_admission_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
            "candidate_build_authorized": False,
            "active_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "promotion_or_live_authorized": False,
        },
        digest_field="receipt_content_sha256",
    )

    decision_batch = _sealed_artifact(
        "legalbot.v111.seminar-source-owner-decision-batch.v1",
        {
            "status": "EXACT_OWNER_DECISIONS_REQUIRED_NO_SOURCE_ADMISSION_NO_EMBEDDING",
            "owner_route_receipt_content_sha256": receipt["receipt_content_sha256"],
            "input_bindings": _input_bindings(inputs),
            "excluded_sources_content_sha256": exclusions["artifact_content_sha256"],
            "source_authority_count": len(records),
            "source_family_counts": family_counts,
            "pending_jurisdiction_binding_count": len(records),
            "pending_subject_binding_count": len(records),
            "pending_case_later_treatment_count": family_counts["official_judgment"],
            "pending_legislation_currentness_extent_effects_count": family_counts["legislation"],
            "pending_source_admission_count": len(records),
            "records": records,
            "advisory_only": True,
            "legal_correctness_certified": False,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
            "candidate_mutated": False,
            "active_pointer_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "promotion_or_live_authorized": False,
        },
        digest_field="owner_decision_batch_content_sha256",
    )

    approval_payload = _sealed_artifact(
        "legalbot.v111.seminar-source-owner-approval-payload.v1",
        {
            "status": "EXACT_OWNER_APPROVAL_REQUIRED_BEFORE_SOURCE_ADMISSION_OR_EMBEDDING",
            "owner_route_receipt_content_sha256": receipt["receipt_content_sha256"],
            "owner_decision_batch_content_sha256": decision_batch[
                "owner_decision_batch_content_sha256"
            ],
            "excluded_sources_content_sha256": exclusions["artifact_content_sha256"],
            "approval_scope_if_explicitly_owner_approved": {
                "source_authority_count": len(records),
                "adopt_each_proposed_metadata_binding": True,
                "source_admission_for_private_research_index": True,
                "retain_currentness_and_later_treatment_holds": True,
                "answer_release_eligible": False,
                "one_full_source_scan_authorized": True,
                "one_successor_candidate_build_and_embedding_authorized": True,
                "successor_must_remain_non_active": True,
            },
            "expressly_not_authorized": [
                "ACTIVE_OR_PREVIOUS_WRITE",
                "PROMOTION",
                "PHASE_2B",
                "DEVELOPMENT_30",
                "VALIDATION_30",
                "LIVE_ACTIVATION",
                "TRAINING_EXPORT",
            ],
            "owner_approved": False,
            "source_admission_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
            "candidate_build_authorized": False,
        },
        digest_field="owner_approval_payload_content_sha256",
    )

    for artifact in (receipt, exclusions, decision_batch, approval_payload):
        _assert_output_safe(artifact)

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("seminar_owner_packet_output_mode_invalid")
    statement_name = "OWNER-AUTHORIZATION-VERBATIM.txt"
    receipt_name = "OWNER-AUTHORIZATION-RECEIPT.json"
    exclusions_name = "EXCLUDED-SOURCES.json"
    decision_name = "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json"
    approval_name = "OWNER-APPROVAL-PAYLOAD.json"
    outcome_name = "OUTCOME.txt"
    _write_exclusive(
        output_root / statement_name,
        (EXPECTED_OWNER_STATEMENT + "\n").encode("utf-8"),
    )
    _write_exclusive(output_root / receipt_name, _pretty_json(receipt))
    _write_exclusive(output_root / exclusions_name, _pretty_json(exclusions))
    _write_exclusive(output_root / decision_name, _pretty_json(decision_batch))
    _write_exclusive(output_root / approval_name, _pretty_json(approval_payload))
    outcome = (
        "SEMINAR SOURCE OWNER PACKET READY — EXACT OWNER APPROVAL REQUIRED BEFORE "
        "SOURCE ADMISSION, SCAN, EMBEDDING OR SUCCESSOR BUILD\n"
        f"OWNER APPROVAL PAYLOAD DIGEST: "
        f"{approval_payload['owner_approval_payload_content_sha256']}\n"
    )
    _write_exclusive(output_root / outcome_name, outcome.encode("utf-8"))

    indexed_names = (
        statement_name,
        receipt_name,
        exclusions_name,
        decision_name,
        approval_name,
        outcome_name,
    )
    file_entries = [
        {
            "name": name,
            "byte_count": (output_root / name).stat().st_size,
            "file_sha256": _sha256_file(output_root / name),
        }
        for name in indexed_names
    ]
    package_index = _sealed_artifact(
        "legalbot.v111.seminar-source-owner-package-index.v1",
        {
            "status": "IMMUTABLE_NON_AUTHORIZING_OWNER_REVIEW_PACKAGE",
            "created_at": recorded,
            "owner_approval_payload_content_sha256": approval_payload[
                "owner_approval_payload_content_sha256"
            ],
            "file_count": len(file_entries),
            "files": file_entries,
            "source_admission_authorized": False,
            "embedding_authorized": False,
            "candidate_mutated": False,
            "active_pointer_written": False,
        },
        digest_field="package_index_content_sha256",
    )
    _assert_output_safe(package_index)
    index_name = "PACKAGE-INDEX.json"
    _write_exclusive(output_root / index_name, _pretty_json(package_index))
    checksum_names = (*indexed_names, index_name)
    checksums = "".join(f"{_sha256_file(output_root / name)}  {name}\n" for name in checksum_names)
    _write_exclusive(output_root / "SHA256SUMS.txt", checksums.encode("utf-8"))
    return {
        "output_root": output_root,
        "source_authority_count": len(records),
        "source_family_counts": family_counts,
        "exclusion_counts": exclusions["counts"],
        "owner_decision_batch_content_sha256": decision_batch[
            "owner_decision_batch_content_sha256"
        ],
        "owner_approval_payload_content_sha256": approval_payload[
            "owner_approval_payload_content_sha256"
        ],
        "package_index_content_sha256": package_index["package_index_content_sha256"],
        "source_admission_authorized": False,
        "embedding_authorized": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()
    recorded_at = datetime.fromisoformat(args.recorded_at)
    result = build_package(
        output_root=args.output_root,
        catalogue_path=args.catalogue,
        recorded_at=recorded_at,
    )
    printable = {key: value for key, value in result.items() if key != "output_root"}
    printable["output_root"] = str(result["output_root"])
    print(json.dumps(printable, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
