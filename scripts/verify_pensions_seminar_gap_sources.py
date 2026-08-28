#!/usr/bin/env python3
"""Verify the staged Pensions seminar-gap source pack without admitting it.

This verifier is deliberately non-authorising.  It proves byte identity, official
XML identity, clean-room scan coverage, catalogue linkage, and chunk presence.
It never approves legal currentness, source review, candidate membership,
embedding, promotion, or live activation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "config/pensions_seminar_gap_official_sources.2026-08-26.v1.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/review_queue/pensions-seminar-gap-2026-08-26-verification.json"
)
EXPECTED_MANIFEST_SCHEMA = "legalbot.pensions-seminar-gap-official-source-plan.v1"
REPORT_SCHEMA = "legalbot.pensions-seminar-gap-source-verification.v1"
DC = "http://purl.org/dc/elements/1.1/"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("verification_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("verification_input_must_be_object")
    return value


def _safe_output(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    raw += b"\n"
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


def _normalise_official_identity(value: str) -> str:
    return value.strip().replace("https://", "http://").rstrip("/")


def _expected_identifier(authority_identity: str) -> str:
    parts = authority_identity.split(":")
    if len(parts) != 3 or not all(parts):
        raise ValueError("authority_identity_invalid")
    return f"http://www.legislation.gov.uk/{parts[0]}/{parts[1]}/{parts[2]}"


def _xml_identity(path: Path) -> tuple[str, str]:
    root = ET.parse(path).getroot()
    title = root.find(f".//{{{DC}}}title")
    identifier = root.find(f".//{{{DC}}}identifier")
    if title is None or identifier is None:
        raise ValueError("official_xml_identity_missing")
    return ("".join(title.itertext()).strip(), "".join(identifier.itertext()).strip())


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{path.resolve()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    return connection


def _validate_manifest_boundary(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema") != EXPECTED_MANIFEST_SCHEMA:
        raise ValueError("source_manifest_schema_invalid")
    required_false = (
        "automatic_source_admission",
        "automatic_currentness_approval",
        "automatic_gold_change",
        "automatic_indexing",
        "automatic_embedding",
        "candidate_mutation_authorized",
        "active_promotion_authorized",
        "phase2b_authorized",
        "development30_authorized",
        "validation30_authorized",
        "live_activation_authorized",
    )
    if any(manifest.get(field) is not False for field in required_false):
        raise ValueError("source_manifest_authority_boundary_invalid")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("source_manifest_target_inventory_invalid")


def _technical_holds(record: Mapping[str, Any]) -> list[str]:
    checks = record["checks"]
    return sorted(key for key, passed in checks.items() if passed is not True)


def verify(
    *,
    manifest_path: Path,
    source_root: Path,
    catalogue_path: Path,
) -> dict[str, Any]:
    manifest = _load_object(manifest_path)
    _validate_manifest_boundary(manifest)
    source_root_resolved = source_root.resolve(strict=True)
    connection = _read_only_connection(catalogue_path)
    try:
        active_scan_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM source_scans WHERE status IN ('queued','running')"
            ).fetchone()[0]
        )
        scan = connection.execute(
            """
            SELECT id, status, expected_file_count, files_accounted,
                   manifest_sha256, created_at, completed_at
              FROM source_scans
             WHERE status='complete'
             ORDER BY created_at DESC
             LIMIT 1
            """
        ).fetchone()
        if scan is None:
            raise ValueError("complete_source_scan_missing")

        records: list[dict[str, Any]] = []
        seen_authorities: set[str] = set()
        seen_hashes: set[str] = set()
        for raw in manifest["targets"]:
            if not isinstance(raw, dict):
                raise ValueError("source_manifest_target_invalid")
            authority_identity = str(raw.get("authority_identity") or "")
            expected_hash = str(raw.get("content_sha256") or "")
            relative_path = str(raw.get("source_root_relative_path") or "")
            if (
                authority_identity in seen_authorities
                or expected_hash in seen_hashes
                or len(expected_hash) != 64
                or not relative_path
            ):
                raise ValueError("source_manifest_target_identity_invalid")
            seen_authorities.add(authority_identity)
            seen_hashes.add(expected_hash)

            source_path = (source_root_resolved / relative_path).resolve(strict=True)
            source_path.relative_to(source_root_resolved)
            regular_non_symlink = source_path.is_file() and not source_path.is_symlink()
            source_bytes = source_path.read_bytes()
            actual_hash = _sha256_bytes(source_bytes)
            actual_title, actual_identifier = _xml_identity(source_path)
            expected_identifier = _expected_identifier(authority_identity)

            catalogue_rows = connection.execute(
                """
                SELECT d.id AS document_id, d.status AS document_status,
                       d.lane, d.subject_primary, d.jurisdiction,
                       d.retrieval_canonical, sv.id AS source_version_id,
                       sv.title, sv.version_sha256, sv.stable_identifier,
                       sv.canonical_url, sv.currentness_status,
                       sv.review_status, sv.superseded_by,
                       COALESCE(json_extract(
                           sv.metadata_json, '$.currentness_verified'
                       ), 0) AS currentness_verified,
                       COUNT(c.id) AS chunk_count,
                       SUM(CASE WHEN trim(c.markdown_text)='' THEN 1 ELSE 0 END)
                           AS empty_chunk_count,
                       SUM(c.token_count) AS token_count
                  FROM documents d
                  JOIN source_versions sv ON sv.document_id=d.id
             LEFT JOIN chunks c ON c.source_version_id=sv.id
                 WHERE d.content_sha256=? AND sv.superseded_by IS NULL
              GROUP BY d.id, sv.id
                """,
                (expected_hash,),
            ).fetchall()
            row = catalogue_rows[0] if len(catalogue_rows) == 1 else None
            scan_rows = connection.execute(
                """
                SELECT status, document_id
                  FROM source_scan_files
                 WHERE scan_id=? AND content_sha256=?
                """,
                (scan["id"], expected_hash),
            ).fetchall()
            scan_row = scan_rows[0] if len(scan_rows) == 1 else None

            checks = {
                "catalogue_exact_single_current_source_version": row is not None,
                "catalogue_citable": row is not None and row["document_status"] == "citable",
                "catalogue_primary_authority_lane": row is not None
                and row["lane"] == "primary_authority",
                "catalogue_retrieval_canonical": row is not None
                and int(row["retrieval_canonical"] or 0) == 1,
                "catalogue_version_hash_exact": row is not None
                and row["version_sha256"] == expected_hash,
                "chunks_present_and_nonempty": row is not None
                and int(row["chunk_count"] or 0) > 0
                and int(row["empty_chunk_count"] or 0) == 0,
                "file_byte_count_exact": len(source_bytes) == int(raw["byte_count"]),
                "file_hash_exact": actual_hash == expected_hash,
                "file_regular_non_symlink": regular_non_symlink,
                "latest_scan_exact_hash_accounted_citable": scan_row is not None
                and scan_row["status"] == "citable",
                "latest_scan_document_link_exact": scan_row is not None
                and row is not None
                and scan_row["document_id"] == row["document_id"],
                "official_xml_identifier_exact": _normalise_official_identity(
                    actual_identifier
                )
                == _normalise_official_identity(expected_identifier),
                "official_xml_title_exact": actual_title == raw["source_title"],
            }
            record: dict[str, Any] = {
                "authority_identity": authority_identity,
                "source_title": raw["source_title"],
                "source_root_relative_path": relative_path,
                "content_sha256": expected_hash,
                "checks": checks,
                "catalogue": {
                    "chunk_count": int(row["chunk_count"] or 0) if row else 0,
                    "currentness_status": row["currentness_status"] if row else None,
                    "currentness_verified": bool(row["currentness_verified"]) if row else False,
                    "jurisdiction": row["jurisdiction"] if row else None,
                    "review_status": row["review_status"] if row else None,
                    "subject_primary": row["subject_primary"] if row else None,
                    "token_count": int(row["token_count"] or 0) if row else 0,
                },
                "currentness_gate": "OWNER_REVIEW_REQUIRED",
                "technical_holds": [],
            }
            record["technical_holds"] = _technical_holds(record)
            record["technical_verification_passed"] = not record["technical_holds"]
            records.append(record)

        technical_failures = sum(
            1 for record in records if not record["technical_verification_passed"]
        )
        owner_currentness_holds = sum(
            1
            for record in records
            if record["catalogue"]["currentness_verified"] is not True
            or record["catalogue"]["review_status"] != "approved"
        )
        report: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "source_plan_version": manifest["version"],
            "source_plan_content_sha256": _sha256_bytes(_canonical_json(manifest)),
            "latest_complete_scan": {
                "scan_id": scan["id"],
                "status": scan["status"],
                "expected_file_count": scan["expected_file_count"],
                "files_accounted": scan["files_accounted"],
                "manifest_sha256": scan["manifest_sha256"],
                "created_at": scan["created_at"],
                "completed_at": scan["completed_at"],
            },
            "summary": {
                "target_count": len(records),
                "technical_pass_count": len(records) - technical_failures,
                "technical_failure_count": technical_failures,
                "owner_currentness_hold_count": owner_currentness_holds,
                "chunk_count": sum(record["catalogue"]["chunk_count"] for record in records),
                "token_count": sum(record["catalogue"]["token_count"] for record in records),
                "active_scan_count": active_scan_count,
            },
            "records": records,
            "technical_verification_passed": technical_failures == 0
            and active_scan_count == 0,
            "release_state": "STAGED_TECHNICALLY_VERIFIED_OWNER_CURRENTNESS_REQUIRED",
            "owner_actions_required": [
                "verify_exact_official_identity_and_legal_currentness",
                "approve_or_reject_source_admission",
                "approve_any_candidate_membership_change",
                "run_existing_release_gates_before_any_active_promotion",
            ],
            "automatic_source_admission": False,
            "automatic_currentness_approval": False,
            "automatic_gold_change": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "active_pointer_written": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "live_activation_authorized": False,
        }
        report["report_content_sha256"] = _sha256_bytes(_canonical_json(report))
        return report
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Technically verify the staged Pensions seminar-gap source pack."
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = verify(
        manifest_path=args.manifest,
        source_root=args.source_root,
        catalogue_path=args.catalogue,
    )
    _safe_output(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["technical_verification_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
