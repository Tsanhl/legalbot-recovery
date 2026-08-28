#!/usr/bin/env python3
"""Apply the exact owner-approved Phase-2A source scope, create-only.

The command binds the immutable 166-authority staging artifact to the final
reconciled source scan, records owner-held research-index admissions, and
writes one frozen successor scope containing the 85-source predecessor plus
the 166 newly admitted authorities.  It never builds or promotes an index and
keeps every newly admitted source answer-release ineligible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.app.retrieval.source_manifest import approved_source_manifest_sha256

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
CATALOGUE_PATH = PROJECT_ROOT / "data/catalog.sqlite3"
STAGING_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-consolidated-source-staging"
)
STAGING_PATH = STAGING_ROOT / "CONSOLIDATED-SOURCE-STAGING.json"
STAGING_PACKAGE_PATH = STAGING_ROOT / "PACKAGE-INDEX.json"
SEMINAR_BATCH_PATH = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-seminar-source-owner-packet"
    / "SEMINAR-SOURCE-OWNER-DECISION-BATCH.json"
)
PREDECESSOR_ROOT = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260818-a"
)
PREDECESSOR_MANIFEST_PATH = PREDECESSOR_ROOT / "approved-source-manifest.json"
OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-27-consolidated-source-admission"
)
SCOPE_FILENAME = "FROZEN-SUCCESSOR-SOURCE-SCOPE.json"

CORPUS_ID = "current-law-ew-full-phase2a-held-20260827-v1"
EXPECTED_STAGING_ARTIFACT_SHA256 = (
    "edd0c6e6a0e26ee776193ceb9256a8a2f5dbc92520dc5ad2346e012e0941e68c"
)
EXPECTED_STAGING_PACKAGE_SHA256 = (
    "27878c829734d9244555f2b8177a82dc8fbe61dd2a12fe9d7cad8255104c7a21"
)
EXPECTED_SEMINAR_BATCH_SHA256 = (
    "6b2fc70e2c15e706bc26034aed7c6940b28b4220f66a7b0fbd28b97a0f53c8b6"
)
EXPECTED_SEMINAR_OWNER_PAYLOAD_SHA256 = (
    "20e21e43aefc6348db5344782ddc3ab9d41a05c2c19aeb24b58a3fcd02371c73"
)
EXPECTED_SEMINAR_OWNER_RECEIPT_SHA256 = (
    "878a1d2582a07c40dda7b5311aa22970885f78437e5f3d39109e667b9a6be7f9"
)
EXPECTED_PRIOR_25_SHA256 = (
    "667fa9cb36188740fa28b0d4e0970ec71c82dcb123505f07584ea678bae9c32d"
)
EXPECTED_PREDECESSOR_MANIFEST_SHA256 = (
    "d2c1434fd5fc44d4f2f7e4f7629293f646bb28ed9b8466687feb6c470ea53ac0"
)
EXPECTED_SCAN_ID = "18dded91dadf9fa0"
EXPECTED_SCAN_MANIFEST_SHA256 = (
    "fb6e0d82ff205e74052aa0f536049702e84c8af86624305f5fa03e19eb6e820d"
)
EXPECTED_ADMITTED_COUNT = 166
EXPECTED_PREDECESSOR_COUNT = 85
EXPECTED_SCOPE_COUNT = 251
EXPECTED_NEW_FAMILY_COUNTS = {"legislation": 51, "official_judgment": 115}
EXPECTED_SCOPE_FAMILY_COUNTS = {"legislation": 116, "official_judgment": 135}

OGL_NAME = "Open Government Licence v3.0"
OGL_URL = "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/"
OJL_NAME = "Open Justice Licence v2.0"
OJL_URL = "https://caselaw.nationalarchives.gov.uk/open-justice-licence/version/2"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_MARKER = ":latest-available@"


def _canonical_json(value: Any, *, newline: bool = True) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return (raw + ("\n" if newline else "")).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required admission input is unavailable: {path.name}")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"required admission input is not an object: {path.name}")
    return value


def _verify_seal(
    value: Mapping[str, Any], field: str, expected: str, *, newline: bool = True
) -> None:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != expected
        or supplied != _sha256_bytes(_canonical_json(material, newline=newline))
    ):
        raise ValueError(f"sealed admission input changed: {field}")


def _source_family(authority_identity_id: str) -> str:
    if authority_identity_id.startswith("neutral-citation:"):
        return "official_judgment"
    if authority_identity_id.startswith(("ukpga:", "uksi:")):
        return "legislation"
    raise ValueError(f"unsupported authority identity: {authority_identity_id}")


def _stable_identifier(
    authority_identity_id: str, seminar_record: Mapping[str, Any] | None
) -> str:
    if seminar_record is None:
        return authority_identity_id
    proposed = str(seminar_record.get("proposed_stable_identifier") or "")
    if _source_family(authority_identity_id) == "official_judgment":
        if proposed != authority_identity_id:
            raise ValueError("seminar judgment stable identity changed")
        return proposed
    marker_index = proposed.find(_SNAPSHOT_MARKER)
    if marker_index < 0:
        raise ValueError("seminar legislation snapshot identity is missing")
    return authority_identity_id + proposed[marker_index:]


def _licence_profile(
    authority_identity_id: str, source_family: str, canonical_url: str
) -> tuple[str, str, str]:
    if source_family == "legislation":
        return OGL_NAME, OGL_URL, "official_legislation_registry_ogl_v3"
    citation = authority_identity_id.casefold()
    if "caselaw.nationalarchives.gov.uk" in canonical_url.casefold() or any(
        marker in citation for marker in (" ewhc ", " ewca ")
    ):
        return OJL_NAME, OJL_URL, "find_case_law_open_justice_licence_v2"
    return OGL_NAME, OGL_URL, "official_uk_court_ogl_v3"


def _jurisdiction(authority_identity_id: str, source_family: str) -> str:
    if source_family == "legislation":
        return "United Kingdom"
    citation = authority_identity_id.casefold()
    if " ewhc " in citation or " ewca " in citation:
        return "England and Wales"
    return "United Kingdom"


def _seminar_records() -> dict[tuple[str, str], dict[str, Any]]:
    batch = _load_object(SEMINAR_BATCH_PATH)
    _verify_seal(
        batch,
        "owner_decision_batch_content_sha256",
        EXPECTED_SEMINAR_BATCH_SHA256,
        newline=False,
    )
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for record in batch.get("records", []):
        if not isinstance(record, dict):
            raise ValueError("seminar source record is invalid")
        selected = record.get("selected_source_version")
        if not isinstance(selected, dict):
            raise ValueError("seminar source version binding is invalid")
        authority = str(record.get("proposed_stable_identifier") or "")
        authority = authority.split(_SNAPSHOT_MARKER, 1)[0]
        content_sha256 = str(selected.get("content_sha256") or "")
        key = (authority.casefold(), content_sha256)
        if key in result or not _SHA256.fullmatch(content_sha256):
            raise ValueError("seminar source binding is duplicated or invalid")
        result[key] = record
    if len(result) != 142:
        raise ValueError("seminar source binding count changed")
    return result


def _load_staging() -> dict[str, Any]:
    staging = _load_object(STAGING_PATH)
    _verify_seal(
        staging,
        "artifact_content_sha256",
        EXPECTED_STAGING_ARTIFACT_SHA256,
    )
    package = _load_object(STAGING_PACKAGE_PATH)
    _verify_seal(
        package,
        "package_content_sha256",
        EXPECTED_STAGING_PACKAGE_SHA256,
    )
    if (
        package.get("artifact_content_sha256") != EXPECTED_STAGING_ARTIFACT_SHA256
        or staging.get("consolidated_source_count") != EXPECTED_ADMITTED_COUNT
        or staging.get("source_family_counts") != EXPECTED_NEW_FAMILY_COUNTS
        or staging.get("seminar_owner_payload_content_sha256")
        != EXPECTED_SEMINAR_OWNER_PAYLOAD_SHA256
        or staging.get("seminar_owner_decision_batch_content_sha256")
        != EXPECTED_SEMINAR_BATCH_SHA256
        or staging.get("cumulative_prior_source_approval_content_sha256")
        != EXPECTED_PRIOR_25_SHA256
        or staging.get("automatic_indexing") is not False
        or staging.get("automatic_embedding") is not False
        or staging.get("phase2b_authorized") is not False
    ):
        raise ValueError("consolidated staging authority boundary changed")
    return staging


def _load_predecessor() -> dict[str, Any]:
    manifest = _load_object(PREDECESSOR_MANIFEST_PATH)
    if (
        approved_source_manifest_sha256(manifest)
        != EXPECTED_PREDECESSOR_MANIFEST_SHA256
        or manifest.get("manifest_sha256") != EXPECTED_PREDECESSOR_MANIFEST_SHA256
        or manifest.get("source_count") != EXPECTED_PREDECESSOR_COUNT
        or len(manifest.get("sources", [])) != EXPECTED_PREDECESSOR_COUNT
    ):
        raise ValueError("sealed predecessor source manifest changed")
    return manifest


def _verify_final_scan(connection: sqlite3.Connection) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,
               required_roots_json,roots_seen_json,completed_at
        FROM source_scans ORDER BY created_at DESC LIMIT 1
        """
    ).fetchone()
    if (
        row is None
        or row["id"] != EXPECTED_SCAN_ID
        or row["status"] != "complete"
        or row["manifest_sha256"] != EXPECTED_SCAN_MANIFEST_SHA256
        or int(row["expected_file_count"] or -1) != 3848
        or int(row["files_accounted"] or -2) != 3848
        or row["required_roots_json"] != row["roots_seen_json"]
    ):
        raise ValueError("final consolidated source scan is not exact and reconciled")
    actual = connection.execute(
        "SELECT COUNT(*) AS n FROM source_scan_files WHERE scan_id=?",
        (EXPECTED_SCAN_ID,),
    ).fetchone()
    if actual is None or int(actual["n"] or -1) != 3848:
        raise ValueError("final consolidated source scan file ledger is incomplete")
    return dict(row)


def _choose_source_version(
    connection: sqlite3.Connection, *, authority_identity_id: str, content_sha256: str
) -> sqlite3.Row:
    rows = connection.execute(
        """
        SELECT sv.id AS source_version_id,sv.document_id,sv.version_sha256,
               sv.canonical_markdown_path,sv.title,sv.source_date,sv.as_of_date,
               sv.canonical_url,sv.stable_identifier,sv.currentness_status,
               sv.licence_name,sv.licence_url,sv.review_status,sv.metadata_json,
               sv.created_at,d.status AS document_status,d.lane,d.subject_primary,
               d.jurisdiction,d.content_sha256,d.duplicate_of,d.retrieval_canonical,
               d.representation_group_id,
               (SELECT COUNT(*) FROM chunks c
                 WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
        FROM documents d JOIN source_versions sv ON sv.document_id=d.id
        WHERE d.content_sha256=? AND sv.superseded_by IS NULL
        ORDER BY
          CASE
            WHEN d.status='citable' AND d.retrieval_canonical=1
                 AND sv.review_status='staged' THEN 0
            WHEN sv.review_status='staged' THEN 1
            WHEN d.status='citable' AND d.retrieval_canonical=1
                 AND sv.review_status='approved' THEN 2
            ELSE 3
          END,
          CASE WHEN json_extract(sv.metadata_json,'$.scan_id')=? THEN 0 ELSE 1 END,
          sv.created_at DESC,sv.id DESC
        """,
        (content_sha256, EXPECTED_SCAN_ID),
    ).fetchall()
    if not rows:
        raise ValueError(f"approved authority has no current source version: {authority_identity_id}")
    selected = rows[0]
    if (
        selected["review_status"] != "staged"
        or int(selected["body_chunk_count"] or 0) < 1
        or selected["document_status"] not in {"citable", "duplicate"}
        or str(selected["lane"] or "") != "primary_authority"
        or selected["version_sha256"] != content_sha256
    ):
        raise ValueError(f"approved authority is not mechanically admissible: {authority_identity_id}")
    markdown_path = PROJECT_ROOT / str(selected["canonical_markdown_path"] or "")
    if not markdown_path.is_file() or markdown_path.stat().st_size < 1:
        raise ValueError(f"approved authority lacks canonical Markdown: {authority_identity_id}")
    return selected


def _predecessor_records(
    connection: sqlite3.Connection, manifest: Mapping[str, Any]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source in manifest.get("sources", []):
        source_version_id = str(source.get("source_version_id") or "")
        row = connection.execute(
            """
            SELECT sv.id,sv.version_sha256,sv.review_status,sv.canonical_markdown_path,
                   d.id AS document_id,d.content_sha256,d.status,d.lane,
                   d.retrieval_canonical,
                   (SELECT COUNT(*) FROM chunks c
                     WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.id=?
            """,
            (source_version_id,),
        ).fetchone()
        if (
            row is None
            or row["review_status"] != "approved"
            or row["status"] != "citable"
            or row["lane"] != "primary_authority"
            or int(row["retrieval_canonical"] or 0) != 1
            or row["content_sha256"] != source.get("content_sha256")
            or row["version_sha256"] != source.get("version_sha256")
            or int(row["body_chunk_count"] or 0) != int(source.get("body_chunk_count") or -1)
        ):
            raise ValueError("sealed predecessor source no longer verifies")
        records.append(
            {
                "source_kind": "SEALED_PREDECESSOR_SOURCE",
                "source_version_id": source_version_id,
                "document_id": str(row["document_id"]),
                "authority_identity_id": str(source.get("authority_identity_id") or ""),
                "stable_identifier": str(source.get("stable_identifier") or ""),
                "content_sha256": str(row["content_sha256"]),
                "version_sha256": str(row["version_sha256"]),
                "canonical_markdown_path": str(row["canonical_markdown_path"]),
                "body_chunk_count": int(row["body_chunk_count"]),
                "approval_origins": [
                    f"SEALED_PREDECESSOR_MANIFEST:{EXPECTED_PREDECESSOR_MANIFEST_SHA256}"
                ],
                "retained_hold_codes": [],
                "answer_release_eligible_in_successor": False,
                "full_current_law_verification_eligible_before_successor": bool(
                    source.get("full_current_law_verification_eligible")
                ),
            }
        )
    return records


def build_plan() -> dict[str, Any]:
    staging = _load_staging()
    predecessor = _load_predecessor()
    seminar = _seminar_records()
    connection = sqlite3.connect(f"file:{CATALOGUE_PATH}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        scan = _verify_final_scan(connection)
        predecessor_records = _predecessor_records(connection, predecessor)
        admitted: list[dict[str, Any]] = []
        for record in staging.get("records", []):
            authority_identity_id = str(record.get("authority_identity_id") or "")
            content_sha256 = str(record.get("content_sha256") or "")
            source_family = _source_family(authority_identity_id)
            seminar_record = seminar.get((authority_identity_id.casefold(), content_sha256))
            source = _choose_source_version(
                connection,
                authority_identity_id=authority_identity_id,
                content_sha256=content_sha256,
            )
            stable_identifier = _stable_identifier(authority_identity_id, seminar_record)
            canonical_url = str(record.get("official_canonical_url") or "")
            licence_name, licence_url, rights_basis = _licence_profile(
                authority_identity_id, source_family, canonical_url
            )
            currentness_status = (
                "historical"
                if source_family == "official_judgment"
                else "latest_available_revised_snapshot"
            )
            admitted.append(
                {
                    "source_kind": "OWNER_APPROVED_HELD_RESEARCH_SOURCE",
                    "source_version_id": str(source["source_version_id"]),
                    "document_id": str(source["document_id"]),
                    "authority_identity_id": authority_identity_id,
                    "source_family": source_family,
                    "stable_identifier": stable_identifier,
                    "content_sha256": content_sha256,
                    "version_sha256": str(source["version_sha256"]),
                    "canonical_markdown_path": str(source["canonical_markdown_path"]),
                    "body_chunk_count": int(source["body_chunk_count"]),
                    "title": str(record.get("title") or source["title"] or authority_identity_id),
                    "canonical_url": canonical_url,
                    "source_date": source["source_date"],
                    "as_of_date": source["as_of_date"],
                    "currentness_status": currentness_status,
                    "jurisdiction": _jurisdiction(authority_identity_id, source_family),
                    "licence_name": licence_name,
                    "licence_url": licence_url,
                    "rights_basis": rights_basis,
                    "approval_origins": sorted(set(record.get("approval_origins") or [])),
                    "retained_hold_codes": sorted(
                        set(record.get("retained_hold_codes") or [])
                    ),
                    "pre_admission_document_status": str(source["document_status"]),
                    "pre_admission_retrieval_canonical": bool(
                        source["retrieval_canonical"]
                    ),
                    "pre_admission_review_status": str(source["review_status"]),
                    "requires_canonical_switch": not (
                        source["document_status"] == "citable"
                        and int(source["retrieval_canonical"] or 0) == 1
                    ),
                    "answer_release_eligible": False,
                    "currentness_verified": False,
                    "technical_qualification_assigned": False,
                }
            )
        if len(admitted) != EXPECTED_ADMITTED_COUNT:
            raise ValueError("admitted authority count changed")
        if len({item["source_version_id"] for item in admitted}) != len(admitted):
            raise ValueError("admitted source version selection is not unique")
        family_counts = dict(sorted(Counter(item["source_family"] for item in admitted).items()))
        if family_counts != EXPECTED_NEW_FAMILY_COUNTS:
            raise ValueError("admitted source family counts changed")
        scope_sources = [*predecessor_records, *admitted]
        if len(scope_sources) != EXPECTED_SCOPE_COUNT:
            raise ValueError("successor source scope count changed")
        scope_family_counts = dict(
            sorted(
                Counter(
                    _source_family(str(item["authority_identity_id"]))
                    for item in scope_sources
                ).items()
            )
        )
        if scope_family_counts != EXPECTED_SCOPE_FAMILY_COUNTS:
            raise ValueError("successor source family counts changed")
        material = {
            "schema": "legalbot.v111.phase2a.consolidated-source-admission-plan.v1",
            "status": "EXACT_OWNER_APPROVED_HELD_SOURCE_ADMISSIONS_READY",
            "corpus_id": CORPUS_ID,
            "source_scan_id": scan["id"],
            "source_scan_manifest_sha256": scan["manifest_sha256"],
            "staging_artifact_content_sha256": EXPECTED_STAGING_ARTIFACT_SHA256,
            "staging_package_content_sha256": EXPECTED_STAGING_PACKAGE_SHA256,
            "seminar_owner_payload_content_sha256": (
                EXPECTED_SEMINAR_OWNER_PAYLOAD_SHA256
            ),
            "seminar_owner_approval_receipt_content_sha256": (
                EXPECTED_SEMINAR_OWNER_RECEIPT_SHA256
            ),
            "seminar_owner_decision_batch_content_sha256": (
                EXPECTED_SEMINAR_BATCH_SHA256
            ),
            "prior_25_source_approval_content_sha256": EXPECTED_PRIOR_25_SHA256,
            "predecessor_source_manifest_sha256": (
                EXPECTED_PREDECESSOR_MANIFEST_SHA256
            ),
            "predecessor_source_count": len(predecessor_records),
            "admitted_source_count": len(admitted),
            "successor_source_count": len(scope_sources),
            "admitted_source_family_counts": family_counts,
            "successor_source_family_counts": scope_family_counts,
            "canonical_switch_count": sum(
                item["requires_canonical_switch"] for item in admitted
            ),
            "successor_body_chunk_count": sum(
                int(item["body_chunk_count"]) for item in scope_sources
            ),
            "admitted_sources": admitted,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "source_admission_applied": False,
            "candidate_build_started": False,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        material["artifact_content_sha256"] = _sha256_bytes(_canonical_json(material))
        return material
    finally:
        connection.close()


def _prestate(connection: sqlite3.Connection, plan: Mapping[str, Any]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for item in plan["admitted_sources"]:
        row = connection.execute(
            """
            SELECT sv.id AS source_version_id,sv.stable_identifier,
                   sv.authority_identity_id,sv.currentness_status,sv.review_status,
                   sv.licence_name,sv.licence_url,sv.metadata_json,
                   d.id AS document_id,d.status,d.duplicate_of,d.retrieval_canonical,
                   d.lane,d.jurisdiction
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.id=?
            """,
            (item["source_version_id"],),
        ).fetchone()
        if row is None:
            raise ValueError("source version disappeared before admission")
        material = dict(row)
        metadata = str(material.pop("metadata_json") or "{}")
        material["metadata_sha256"] = _sha256_bytes(metadata.encode("utf-8"))
        material["authority_identity_id_expected"] = item["authority_identity_id"]
        records.append(material)
    payload = {
        "schema": "legalbot.v111.phase2a.consolidated-source-admission-prestate.v1",
        "record_count": len(records),
        "records": records,
    }
    payload["artifact_content_sha256"] = _sha256_bytes(_canonical_json(payload))
    return payload


def _owner_metadata(item: Mapping[str, Any], current: str) -> str:
    try:
        metadata = json.loads(current or "{}")
    except json.JSONDecodeError as exc:
        raise ValueError("source metadata is invalid") from exc
    if not isinstance(metadata, dict):
        raise ValueError("source metadata is not an object")
    source_family = str(item["source_family"])
    metadata.update(
        {
            "identity_verified": True,
            "currentness_verified": False,
            "currentness_applicable": True,
            "authority_eligible": True,
            "citation_rendering_enabled": False,
            "canonical_citation": None,
            "eligible_for_model_use": True,
            "ai_use_policy": "owner_private_research_only",
            "answer_release_eligible": False,
            "subsequent_treatment_check_required": source_family
            == "official_judgment",
            "subsequent_treatment_verified": False,
            "provision_extent_status": (
                "unverified" if source_family == "legislation" else "not_applicable"
            ),
            "phase2a_owner_held_source_admission": {
                "schema": "legalbot.v111.phase2a.owner-held-source-admission.v1",
                "authority_identity_id": item["authority_identity_id"],
                "content_sha256": item["content_sha256"],
                "source_scan_id": EXPECTED_SCAN_ID,
                "source_scan_manifest_sha256": EXPECTED_SCAN_MANIFEST_SHA256,
                "staging_artifact_content_sha256": EXPECTED_STAGING_ARTIFACT_SHA256,
                "approval_origins": list(item["approval_origins"]),
                "retained_hold_codes": list(item["retained_hold_codes"]),
                "rights_basis": item["rights_basis"],
                "currentness_verified": False,
                "answer_release_eligible": False,
                "phase2b_authorized": False,
            },
        }
    )
    return json.dumps(metadata, ensure_ascii=False, sort_keys=True)


def _apply_catalogue(connection: sqlite3.Connection, plan: Mapping[str, Any]) -> None:
    decided_at = datetime.now(UTC).isoformat(timespec="seconds")
    connection.execute("BEGIN IMMEDIATE")
    try:
        for item in plan["admitted_sources"]:
            source_version_id = str(item["source_version_id"])
            source = connection.execute(
                "SELECT metadata_json,document_id,review_status,superseded_by "
                "FROM source_versions WHERE id=?",
                (source_version_id,),
            ).fetchone()
            if (
                source is None
                or source["review_status"] != "staged"
                or source["superseded_by"] is not None
                or source["document_id"] != item["document_id"]
            ):
                raise ValueError("source version changed before owner-held admission")
            document = connection.execute(
                "SELECT representation_group_id FROM documents WHERE id=?",
                (item["document_id"],),
            ).fetchone()
            if document is None:
                raise ValueError("source document changed before owner-held admission")
            # Representation groups are parser-derived and can contain an
            # unrelated authority when a judgment mentions another neutral
            # citation before its own.  Canonical switching is therefore
            # bounded by the owner-approved authority identity, never by the
            # whole representation group.
            connection.execute(
                """
                UPDATE documents SET retrieval_canonical=0
                WHERE id<>? AND EXISTS (
                  SELECT 1 FROM source_versions sibling
                  WHERE sibling.document_id=documents.id
                    AND sibling.authority_identity_id=?
                )
                """,
                (item["document_id"], item["authority_identity_id"]),
            )
            connection.execute(
                """
                UPDATE documents
                SET status='citable',lane='primary_authority',duplicate_of=NULL,
                    retrieval_canonical=1,jurisdiction=?,updated_at=?
                WHERE id=?
                """,
                (item["jurisdiction"], decided_at, item["document_id"]),
            )
            metadata_json = _owner_metadata(item, str(source["metadata_json"] or "{}"))
            connection.execute(
                """
                UPDATE source_versions
                SET stable_identifier=?,authority_identity_id=?,title=?,canonical_url=?,
                    currentness_status=?,licence_name=?,licence_url=?,metadata_json=?,
                    review_status='approved'
                WHERE id=? AND review_status='staged' AND superseded_by IS NULL
                """,
                (
                    item["stable_identifier"],
                    item["authority_identity_id"],
                    item["title"],
                    item["canonical_url"] or None,
                    item["currentness_status"],
                    item["licence_name"],
                    item["licence_url"],
                    metadata_json,
                    source_version_id,
                ),
            )
            pending = connection.execute(
                """
                SELECT id FROM reviews
                WHERE review_type='source_version' AND target_id=? AND status='pending'
                ORDER BY created_at,id
                """,
                (source_version_id,),
            ).fetchall()
            if len(pending) > 1:
                raise ValueError("multiple pending source reviews prevent exact admission")
            reason = (
                "Exact owner-approved Phase-2A private research-index admission; "
                f"scope={EXPECTED_STAGING_ARTIFACT_SHA256}; answer release remains held"
            )
            if pending:
                connection.execute(
                    """
                    UPDATE reviews SET status='approved',reason=?,decision_note='[redacted]',
                        decided_at=? WHERE id=? AND status='pending'
                    """,
                    (reason, decided_at, pending[0]["id"]),
                )
            else:
                review_id = "review-phase2a-held-" + _sha256_bytes(
                    f"{source_version_id}\0{EXPECTED_STAGING_ARTIFACT_SHA256}".encode()
                )[:32]
                connection.execute(
                    """
                    INSERT INTO reviews(
                      id,review_type,target_id,status,reason,decision_note,created_at,decided_at
                    ) VALUES (?, 'source_version', ?, 'approved', ?, '[redacted]', ?, ?)
                    """,
                    (review_id, source_version_id, reason, decided_at, decided_at),
                )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def _scope(
    connection: sqlite3.Connection,
    plan: Mapping[str, Any],
    predecessor: Mapping[str, Any],
) -> dict[str, Any]:
    predecessor_records = _predecessor_records(connection, predecessor)
    admitted_records: list[dict[str, Any]] = []
    for item in plan["admitted_sources"]:
        row = connection.execute(
            """
            SELECT sv.id AS source_version_id,sv.document_id,sv.stable_identifier,
                   sv.authority_identity_id,sv.version_sha256,sv.review_status,
                   sv.canonical_markdown_path,sv.metadata_json,
                   d.content_sha256,d.status,d.lane,d.retrieval_canonical,
                   (SELECT COUNT(*) FROM chunks c
                     WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.id=?
            """,
            (item["source_version_id"],),
        ).fetchone()
        if (
            row is None
            or row["review_status"] != "approved"
            or row["status"] != "citable"
            or row["lane"] != "primary_authority"
            or int(row["retrieval_canonical"] or 0) != 1
            or row["content_sha256"] != item["content_sha256"]
            or row["stable_identifier"] != item["stable_identifier"]
            or row["authority_identity_id"] != item["authority_identity_id"]
        ):
            raise ValueError("owner-held source admission did not verify")
        metadata = json.loads(row["metadata_json"] or "{}")
        owner_binding = metadata.get("phase2a_owner_held_source_admission")
        if (
            not isinstance(owner_binding, dict)
            or owner_binding.get("answer_release_eligible") is not False
            or metadata.get("currentness_verified") is not False
        ):
            raise ValueError("owner-held source release boundary did not verify")
        material = {
            "source_kind": "OWNER_APPROVED_HELD_RESEARCH_SOURCE",
            "source_version_id": str(row["source_version_id"]),
            "document_id": str(row["document_id"]),
            "authority_identity_id": str(row["authority_identity_id"]),
            "stable_identifier": str(row["stable_identifier"]),
            "content_sha256": str(row["content_sha256"]),
            "version_sha256": str(row["version_sha256"]),
            "canonical_markdown_path": str(row["canonical_markdown_path"]),
            "body_chunk_count": int(row["body_chunk_count"]),
            "approval_origins": list(item["approval_origins"]),
            "retained_hold_codes": list(item["retained_hold_codes"]),
            "answer_release_eligible_in_successor": False,
            "full_current_law_verification_eligible_before_successor": False,
        }
        material["record_content_sha256"] = _sha256_bytes(_canonical_json(material))
        admitted_records.append(material)
    records: list[dict[str, Any]] = []
    for source in predecessor_records:
        material = dict(source)
        material["record_content_sha256"] = _sha256_bytes(_canonical_json(material))
        records.append(material)
    records.extend(sorted(admitted_records, key=lambda item: item["authority_identity_id"]))
    if len(records) != EXPECTED_SCOPE_COUNT or len(
        {item["source_version_id"] for item in records}
    ) != EXPECTED_SCOPE_COUNT:
        raise ValueError("frozen successor source scope is not exact")
    family_counts = dict(
        sorted(
            Counter(
                _source_family(str(item["authority_identity_id"])) for item in records
            ).items()
        )
    )
    if family_counts != EXPECTED_SCOPE_FAMILY_COUNTS:
        raise ValueError("frozen successor source family counts changed")
    material = {
        "schema": "legalbot.v111.phase2a.frozen-successor-source-scope.v1",
        "status": "OWNER_APPROVED_HELD_RESEARCH_SCOPE_FROZEN_BUILD_NOT_STARTED",
        "corpus_id": CORPUS_ID,
        "source_scan_id": EXPECTED_SCAN_ID,
        "source_scan_manifest_sha256": EXPECTED_SCAN_MANIFEST_SHA256,
        "staging_artifact_content_sha256": EXPECTED_STAGING_ARTIFACT_SHA256,
        "staging_package_content_sha256": EXPECTED_STAGING_PACKAGE_SHA256,
        "seminar_owner_payload_content_sha256": EXPECTED_SEMINAR_OWNER_PAYLOAD_SHA256,
        "seminar_owner_approval_receipt_content_sha256": (
            EXPECTED_SEMINAR_OWNER_RECEIPT_SHA256
        ),
        "seminar_owner_decision_batch_content_sha256": (
            EXPECTED_SEMINAR_BATCH_SHA256
        ),
        "prior_25_source_approval_content_sha256": EXPECTED_PRIOR_25_SHA256,
        "predecessor_build_id": PREDECESSOR_ROOT.name,
        "predecessor_source_manifest_sha256": EXPECTED_PREDECESSOR_MANIFEST_SHA256,
        "predecessor_source_count": EXPECTED_PREDECESSOR_COUNT,
        "owner_admitted_source_count": EXPECTED_ADMITTED_COUNT,
        "source_count": len(records),
        "source_family_counts": family_counts,
        "chunk_count": sum(int(item["body_chunk_count"]) for item in records),
        "sources": records,
        "selection_policy": "exact-owner-approved-held-phase2a-successor-scope",
        "answer_release_eligible": False,
        "successor_must_remain_non_active": True,
        "common_legal_currentness_cutoff": None,
        "source_admission_applied": True,
        "candidate_build_started": False,
        "active_or_previous_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    material["scope_content_sha256"] = _sha256_bytes(_canonical_json(material))
    return material


def _write_exclusive(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def apply_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if OUTPUT_ROOT.exists() or OUTPUT_ROOT.is_symlink():
        raise ValueError("consolidated source admission output already exists")
    predecessor = _load_predecessor()
    connection = sqlite3.connect(CATALOGUE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    temporary = Path(
        tempfile.mkdtemp(prefix=".phase2a-source-admission-", dir=OUTPUT_ROOT.parent)
    )
    try:
        prestate = _prestate(connection, plan)
        _write_exclusive(temporary / "SOURCE-ADMISSION-PLAN.json", _pretty_json(dict(plan)))
        _write_exclusive(temporary / "CATALOGUE-PRESTATE.json", _pretty_json(prestate))
        _apply_catalogue(connection, plan)
        scope = _scope(connection, plan, predecessor)
        _write_exclusive(temporary / SCOPE_FILENAME, _pretty_json(scope))
        outcome = (
            "PHASE 2A EXACT OWNER-HELD SOURCE ADMISSIONS APPLIED — SUCCESSOR BUILD NOT STARTED\n"
            f"FROZEN SCOPE DIGEST: {scope['scope_content_sha256']}\n"
            "ANSWER RELEASE, ACTIVE/PREVIOUS, PHASE 2B AND DEVELOPMENT 30 REMAIN CLOSED\n"
        ).encode()
        _write_exclusive(temporary / "OUTCOME.txt", outcome)
        indexed_names = (
            "SOURCE-ADMISSION-PLAN.json",
            "CATALOGUE-PRESTATE.json",
            SCOPE_FILENAME,
            "OUTCOME.txt",
        )
        entries = {
            name: {
                "sha256": _sha256_file(temporary / name),
                "bytes": (temporary / name).stat().st_size,
            }
            for name in indexed_names
        }
        package = {
            "schema": "legalbot.v111.phase2a.consolidated-source-admission-package.v1",
            "status": "EXACT_OWNER_HELD_SOURCE_SCOPE_FROZEN_BUILD_NOT_STARTED",
            "source_admission_plan_content_sha256": plan["artifact_content_sha256"],
            "frozen_scope_content_sha256": scope["scope_content_sha256"],
            "file_count": len(entries),
            "files": entries,
            "source_count": scope["source_count"],
            "chunk_count": scope["chunk_count"],
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "candidate_build_started": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        package["package_content_sha256"] = _sha256_bytes(_canonical_json(package))
        _write_exclusive(temporary / "PACKAGE-INDEX.json", _pretty_json(package))
        sums = "".join(
            f"{_sha256_file(path)}  {path.name}\n"
            for path in sorted(temporary.iterdir())
            if path.is_file()
        )
        _write_exclusive(temporary / "SHA256SUMS.txt", sums.encode("utf-8"))
        os.rename(temporary, OUTPUT_ROOT)
        return {
            "source_count": scope["source_count"],
            "chunk_count": scope["chunk_count"],
            "canonical_switch_count": plan["canonical_switch_count"],
            "scope_content_sha256": scope["scope_content_sha256"],
            "package_content_sha256": package["package_content_sha256"],
        }
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply exact owner-held admissions and create the frozen scope",
    )
    args = parser.parse_args()
    plan = build_plan()
    result: dict[str, Any] = {
        "apply": bool(args.apply),
        "status": plan["status"],
        "admitted_source_count": plan["admitted_source_count"],
        "successor_source_count": plan["successor_source_count"],
        "successor_body_chunk_count": plan["successor_body_chunk_count"],
        "canonical_switch_count": plan["canonical_switch_count"],
        "artifact_content_sha256": plan["artifact_content_sha256"],
        "candidate_build_started": False,
        "phase2b_authorized": False,
    }
    if args.apply:
        result.update(apply_plan(plan))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
