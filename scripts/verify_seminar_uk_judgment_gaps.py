#!/usr/bin/env python3
"""Verify the cross-subject seminar UK judgment pack without admitting it."""

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

from app.ingestion.models import BlockKind, ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_uk_judgments_round2.2026-08-26.v1.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-uk-judgments-round2-2026-08-26-verification.json"
)
EXPECTED_SCHEMA = "legalbot.seminar-gap-official-uk-judgment-plan.v1"
REPORT_SCHEMA = "legalbot.seminar-gap-uk-judgment-verification.v1"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(root: ET.Element | None, name: str) -> ET.Element | None:
    if root is None:
        return None
    return next((item for item in root.iter() if _local_name(item.tag) == name), None)


def _attr(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return str(value).strip()
    return ""


def _text(element: ET.Element | None) -> str:
    return " ".join("".join(element.itertext()).split()) if element is not None else ""


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("uk_judgment_verification_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("uk_judgment_verification_input_must_be_object")
    return value


def _write_exclusive(path: Path, value: Any) -> None:
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


def _validate_boundary(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("uk_judgment_gap_manifest_schema_invalid")
    required_false = (
        "automatic_source_admission",
        "automatic_currentness_approval",
        "automatic_later_treatment_approval",
        "automatic_gold_change",
        "automatic_indexing",
        "automatic_embedding",
        "candidate_mutation_authorized",
        "active_promotion_authorized",
        "development30_authorized",
        "validation30_authorized",
        "live_activation_authorized",
    )
    if any(manifest.get(field) is not False for field in required_false):
        raise ValueError("uk_judgment_gap_manifest_authority_boundary_invalid")
    if not isinstance(manifest.get("targets"), list) or not manifest["targets"]:
        raise ValueError("uk_judgment_gap_manifest_target_inventory_invalid")


def _xml_identity(raw: bytes) -> tuple[str, str, str]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("uk_judgment_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    if _local_name(root.tag) != "akomaNtoso":
        raise ValueError("uk_judgment_xml_root_invalid")
    judgment = _first(root, "judgment")
    work = _first(judgment, "FRBRWork")
    expression = _first(judgment, "FRBRExpression")
    proprietary = _first(judgment, "proprietary")
    title = _attr(_first(work, "FRBRname"), "value")
    citation = _text(_first(proprietary, "cite"))
    uri = _attr(_first(expression, "FRBRthis"), "value")
    return title, citation, uri


def verify(
    *,
    manifest_path: Path,
    source_root: Path,
    catalogue_path: Path,
) -> dict[str, Any]:
    manifest = _load_object(manifest_path)
    _validate_boundary(manifest)
    source_root_resolved = source_root.resolve(strict=True)
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    parser = ParserRegistry.default()
    try:
        active_scan_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM source_scans WHERE status IN ('queued','running')"
            ).fetchone()[0]
        )
        if active_scan_count:
            raise ValueError("uk_judgment_verification_requires_frozen_catalogue")
        scan = connection.execute(
            """
            SELECT id, status, expected_file_count, files_accounted,
                   manifest_sha256, created_at, completed_at
              FROM source_scans
             WHERE status='complete'
             ORDER BY created_at DESC LIMIT 1
            """
        ).fetchone()
        if scan is None:
            raise ValueError("complete_source_scan_missing")

        records: list[dict[str, Any]] = []
        seen_citations: set[str] = set()
        seen_hashes: set[str] = set()
        for target in manifest["targets"]:
            citation = str(target.get("authority_identity") or "")
            expected_hash = str(target.get("content_sha256") or "")
            relative_path = str(target.get("source_root_relative_path") or "")
            if (
                not citation
                or citation in seen_citations
                or expected_hash in seen_hashes
                or len(expected_hash) != 64
                or not relative_path
            ):
                raise ValueError("uk_judgment_gap_manifest_target_invalid")
            seen_citations.add(citation)
            seen_hashes.add(expected_hash)
            source_path = (source_root_resolved / relative_path).resolve(strict=True)
            source_path.relative_to(source_root_resolved)
            raw = source_path.read_bytes()
            actual_title, actual_citation, actual_uri = _xml_identity(raw)
            parsed = parser.parse(raw, filename=source_path.name)
            paragraphs = [
                block for block in parsed.body_blocks if block.kind is BlockKind.PARAGRAPH
            ]

            rows = connection.execute(
                """
                SELECT d.id AS document_id, d.status AS document_status,
                       d.lane, d.subject_primary, d.jurisdiction,
                       d.retrieval_canonical, sv.id AS source_version_id,
                       sv.version_sha256, sv.stable_identifier,
                       sv.canonical_url, sv.currentness_status, sv.review_status,
                       COALESCE(json_extract(
                           sv.metadata_json, '$.currentness_verified'
                       ), 0) AS currentness_verified,
                       json_extract(sv.metadata_json, '$.classification_schema')
                           AS classification_schema,
                       COUNT(c.id) AS chunk_count,
                       SUM(CASE WHEN trim(c.markdown_text)='' THEN 1 ELSE 0 END)
                           AS empty_chunk_count,
                       SUM(CASE WHEN c.markdown_text LIKE '%/Users/%' THEN 1 ELSE 0 END)
                           AS path_leak_chunk_count,
                       SUM(c.token_count) AS token_count
                  FROM documents d
                  JOIN source_versions sv ON sv.document_id=d.id
             LEFT JOIN chunks c ON c.source_version_id=sv.id
                 WHERE d.content_sha256=? AND sv.superseded_by IS NULL
              GROUP BY d.id, sv.id
                """,
                (expected_hash,),
            ).fetchall()
            row = rows[0] if len(rows) == 1 else None
            scan_rows = connection.execute(
                """
                SELECT status, document_id FROM source_scan_files
                 WHERE scan_id=? AND content_sha256=?
                """,
                (scan["id"], expected_hash),
            ).fetchall()
            scan_row = scan_rows[0] if len(scan_rows) == 1 else None
            expected_uri = str(target["official_url"]).removesuffix("/data.xml")
            checks = {
                "catalogue_citable": row is not None and row["document_status"] == "citable",
                "catalogue_exact_single_current_source_version": row is not None,
                "catalogue_primary_authority_lane": row is not None
                and row["lane"] == "primary_authority",
                "catalogue_retrieval_canonical": row is not None
                and int(row["retrieval_canonical"] or 0) == 1,
                "catalogue_version_hash_exact": row is not None
                and row["version_sha256"] == expected_hash,
                "catalogue_classification_schema_v10": row is not None
                and row["classification_schema"] == "legalbot.content-classification.v10",
                "chunks_present_nonempty_path_free": row is not None
                and int(row["chunk_count"] or 0) > 0
                and int(row["empty_chunk_count"] or 0) == 0
                and int(row["path_leak_chunk_count"] or 0) == 0,
                "file_byte_count_exact": len(raw) == int(target["byte_count"]),
                "file_hash_exact": _sha256(raw) == expected_hash,
                "file_regular_non_symlink": source_path.is_file() and not source_path.is_symlink(),
                "latest_scan_exact_hash_accounted_citable": scan_row is not None
                and scan_row["status"] == "citable",
                "latest_scan_document_link_exact": scan_row is not None
                and row is not None
                and scan_row["document_id"] == row["document_id"],
                "official_xml_citation_exact": actual_citation == citation,
                "official_xml_title_exact": actual_title == target["source_title"],
                "official_xml_uri_exact": actual_uri == expected_uri,
                "runtime_parser_ready_with_paragraphs": parsed.status is ParseStatus.READY
                and bool(paragraphs),
                "runtime_parser_anchors_official": bool(paragraphs)
                and all(
                    str(block.source_anchor or "").startswith(expected_uri) for block in paragraphs
                ),
            }
            technical_holds = sorted(name for name, passed in checks.items() if passed is not True)
            metadata_holds: list[str] = []
            expected_jurisdiction = str(target["jurisdiction_expected"])
            actual_jurisdiction = str(row["jurisdiction"] or "") if row else ""
            if actual_jurisdiction != expected_jurisdiction:
                metadata_holds.append("catalogue_jurisdiction_owner_correction_required")
            if row is None or row["canonical_url"] != expected_uri:
                metadata_holds.append("official_canonical_url_owner_binding_required")
            if row is None or not str(row["stable_identifier"] or "").startswith(
                "neutral-citation:"
            ):
                metadata_holds.append("neutral_citation_stable_identifier_owner_binding_required")
            presentation_subjects = sorted(str(value) for value in target["presentation_subjects"])
            actual_subject = str(row["subject_primary"] or "") if row else ""
            if presentation_subjects and actual_subject not in presentation_subjects:
                metadata_holds.append("catalogue_subject_owner_binding_required")

            records.append(
                {
                    "authority_identity": citation,
                    "source_title": target["source_title"],
                    "source_root_relative_path": relative_path,
                    "content_sha256": expected_hash,
                    "checks": checks,
                    "technical_holds": technical_holds,
                    "technical_verification_passed": not technical_holds,
                    "metadata_holds": sorted(metadata_holds),
                    "expected_jurisdiction": expected_jurisdiction,
                    "presentation_subjects": presentation_subjects,
                    "catalogue": {
                        "chunk_count": int(row["chunk_count"] or 0) if row else 0,
                        "currentness_status": row["currentness_status"] if row else None,
                        "currentness_verified": bool(row["currentness_verified"]) if row else False,
                        "jurisdiction": actual_jurisdiction or None,
                        "review_status": row["review_status"] if row else None,
                        "subject_primary": actual_subject or None,
                        "token_count": int(row["token_count"] or 0) if row else 0,
                    },
                    "later_treatment_gate": "OWNER_REVIEW_REQUIRED",
                    "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                }
            )

        technical_failures = sum(not record["technical_verification_passed"] for record in records)
        report: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "source_plan_version": manifest["version"],
            "source_plan_content_sha256": _sha256(_canonical_json(manifest)),
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
                "later_treatment_hold_count": len(records),
                "source_admission_hold_count": len(records),
                "metadata_hold_count": sum(bool(record["metadata_holds"]) for record in records),
                "subject_binding_hold_count": sum(
                    "catalogue_subject_owner_binding_required" in record["metadata_holds"]
                    for record in records
                ),
                "chunk_count": sum(record["catalogue"]["chunk_count"] for record in records),
                "token_count": sum(record["catalogue"]["token_count"] for record in records),
            },
            "records": records,
            "unresolved_references": manifest["unresolved_references"],
            "technical_verification_passed": technical_failures == 0,
            "release_state": "STAGED_TECHNICALLY_VERIFIED_OWNER_REVIEW_REQUIRED",
            "automatic_source_admission": False,
            "automatic_later_treatment_approval": False,
            "automatic_gold_change": False,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_mutated": False,
            "active_pointer_written": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "live_activation_authorized": False,
        }
        report["report_content_sha256"] = _sha256(_canonical_json(report))
        return report
    finally:
        connection.close()


def main() -> int:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    arguments.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    arguments.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = arguments.parse_args()
    report = verify(
        manifest_path=args.manifest,
        source_root=args.source_root,
        catalogue_path=args.catalogue,
    )
    _write_exclusive(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["technical_verification_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
