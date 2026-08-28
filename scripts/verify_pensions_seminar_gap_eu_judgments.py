#!/usr/bin/env python3
"""Verify staged Pensions EU judgments without admitting or embedding them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.ingestion.models import ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/pensions_seminar_gap_official_eu_judgments.2026-08-26.v1.json"
)
DEFAULT_PARENT_PLAN = (
    PROJECT_ROOT / "config/pensions_seminar_gap_official_judgments.2026-08-26.v2.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/review_queue/pensions-seminar-gap-eu-judgments-2026-08-26-verification-v2.json"
)
PRIOR_FAILED_REPORT = (
    PROJECT_ROOT
    / "data/review_queue/pensions-seminar-gap-eu-judgments-2026-08-26-verification.json"
)
EXPECTED_SCHEMA = "legalbot.pensions-seminar-gap-official-eu-judgment-plan.v1"
REPORT_SCHEMA = "legalbot.pensions-seminar-gap-eu-judgment-verification.v2"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("eu_judgment_verification_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("eu_judgment_verification_input_must_be_object")
    return value


def _write_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _validate_boundary(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("eu_judgment_manifest_schema_invalid")
    required_false = (
        "automatic_source_admission",
        "automatic_currentness_approval",
        "automatic_later_treatment_approval",
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
        raise ValueError("eu_judgment_manifest_authority_boundary_invalid")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("eu_judgment_manifest_target_inventory_invalid")


def _official_stream_identity_present(raw: bytes, celex: str) -> bool:
    text = raw.decode("utf-8", errors="replace")
    legacy = celex.replace("CJ", "J")
    return bool(
        re.search(
            rf"(?<![0-9A-Z])(?:{re.escape(celex)}|{re.escape(legacy)})(?![0-9A-Z])",
            text,
            re.I,
        )
    )


def verify(
    *,
    manifest_path: Path,
    parent_plan_path: Path,
    source_root: Path,
    catalogue_path: Path,
) -> dict[str, Any]:
    manifest = _load_object(manifest_path)
    _validate_boundary(manifest)
    parent_raw = parent_plan_path.read_bytes()
    parent_expected = str(manifest["parent_uk_judgment_plan"]["file_sha256"])
    if _sha256(parent_raw) != parent_expected:
        raise ValueError("parent_uk_judgment_plan_hash_mismatch")
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
        seen_celex: set[str] = set()
        seen_hashes: set[str] = set()
        for target in manifest["targets"]:
            celex = str(target.get("celex") or "")
            authority = str(target.get("authority_identity") or "")
            expected_hash = str(target.get("content_sha256") or "")
            relative_path = str(target.get("source_root_relative_path") or "")
            if (
                not re.fullmatch(r"6\d{4}CJ\d{4}", celex)
                or celex in seen_celex
                or expected_hash in seen_hashes
                or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
                or not relative_path
                or not authority
            ):
                raise ValueError("eu_judgment_manifest_target_invalid")
            seen_celex.add(celex)
            seen_hashes.add(expected_hash)
            source_path = (source_root_resolved / relative_path).resolve(strict=True)
            source_path.relative_to(source_root_resolved)
            raw = source_path.read_bytes()
            parsed = parser.parse(raw, filename=source_path.name)
            parsed_text = "\n".join(block.text for block in parsed.body_blocks)

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
            official_url = str(target.get("official_url") or "")
            expected_official_url = (
                f"https://publications.europa.eu/resource/celex/{celex}.ENG.html"
            )

            checks = {
                "catalogue_citable": row is not None and row["document_status"] == "citable",
                "catalogue_exact_single_current_source_version": row is not None,
                "catalogue_primary_authority_lane": row is not None
                and row["lane"] == "primary_authority",
                "catalogue_retrieval_canonical": row is not None
                and int(row["retrieval_canonical"] or 0) == 1,
                "catalogue_version_hash_exact": row is not None
                and row["version_sha256"] == expected_hash,
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
                "official_stream_celex_identity_present": _official_stream_identity_present(
                    raw, celex
                ),
                "official_url_exact": official_url == expected_official_url,
                "runtime_parser_ready_with_body": parsed.status is ParseStatus.READY
                and bool(parsed.body_blocks),
                "runtime_parser_block_count_exact": len(parsed.body_blocks)
                == int(target["runtime_parser_block_count"]),
                "runtime_parser_character_count_exact": len(parsed_text)
                == int(target["runtime_parser_character_count"]),
            }
            technical_holds = sorted(name for name, passed in checks.items() if passed is not True)
            metadata_holds: list[str] = []
            actual_jurisdiction = str(row["jurisdiction"] or "") if row else ""
            if actual_jurisdiction != "European Union":
                metadata_holds.append("catalogue_jurisdiction_owner_correction_required")
            if row is None or row["canonical_url"] != expected_official_url:
                metadata_holds.append("official_canonical_url_owner_binding_required")
            if row is None or row["stable_identifier"] != f"celex:{celex.casefold()}":
                metadata_holds.append("celex_stable_identifier_owner_binding_required")

            records.append(
                {
                    "authority_identity": authority,
                    "celex": celex,
                    "source_title": target["source_title"],
                    "source_root_relative_path": relative_path,
                    "content_sha256": expected_hash,
                    "checks": checks,
                    "technical_holds": technical_holds,
                    "technical_verification_passed": not technical_holds,
                    "metadata_holds": sorted(metadata_holds),
                    "expected_jurisdiction": "European Union",
                    "catalogue": {
                        "chunk_count": int(row["chunk_count"] or 0) if row else 0,
                        "currentness_status": row["currentness_status"] if row else None,
                        "currentness_verified": bool(row["currentness_verified"]) if row else False,
                        "jurisdiction": actual_jurisdiction or None,
                        "review_status": row["review_status"] if row else None,
                        "subject_primary": row["subject_primary"] if row else None,
                        "token_count": int(row["token_count"] or 0) if row else 0,
                    },
                    "later_treatment_gate": "OWNER_REVIEW_REQUIRED",
                    "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                }
            )

        technical_failures = sum(not record["technical_verification_passed"] for record in records)
        report: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "verification_repair": {
                "reason_code": "official_stream_celex_token_locator_broadened",
                "supersedes_failed_report": PRIOR_FAILED_REPORT.name,
                "supersedes_failed_report_sha256": (
                    _sha256(PRIOR_FAILED_REPORT.read_bytes())
                    if PRIOR_FAILED_REPORT.is_file()
                    else None
                ),
            },
            "source_plan_version": manifest["version"],
            "source_plan_content_sha256": _sha256(_canonical_json(manifest)),
            "parent_uk_judgment_plan_file_sha256": parent_expected,
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
                "jurisdiction_correction_hold_count": sum(
                    "catalogue_jurisdiction_owner_correction_required" in record["metadata_holds"]
                    for record in records
                ),
                "chunk_count": sum(record["catalogue"]["chunk_count"] for record in records),
                "token_count": sum(record["catalogue"]["token_count"] for record in records),
                "active_scan_count": active_scan_count,
            },
            "records": records,
            "technical_verification_passed": technical_failures == 0 and active_scan_count == 0,
            "release_state": "STAGED_TECHNICALLY_VERIFIED_OWNER_REVIEW_REQUIRED",
            "automatic_source_admission": False,
            "automatic_later_treatment_approval": False,
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
        report["report_content_sha256"] = _sha256(_canonical_json(report))
        return report
    finally:
        connection.close()


def main() -> int:
    arguments = argparse.ArgumentParser(
        description="Technically verify staged Pensions EU seminar-gap judgments."
    )
    arguments.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    arguments.add_argument("--parent-plan", type=Path, default=DEFAULT_PARENT_PLAN)
    arguments.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    arguments.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    arguments.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = arguments.parse_args()
    report = verify(
        manifest_path=args.manifest,
        parent_plan_path=args.parent_plan,
        source_root=args.source_root,
        catalogue_path=args.catalogue,
    )
    _write_exclusive(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["technical_verification_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
