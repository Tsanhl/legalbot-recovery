#!/usr/bin/env python3
"""Recover and seal the committed Phase-2A admission without replaying it.

The original 166-source transaction committed successfully, but its post-
commit verifier found one canonical flag cleared by an unrelated authority in
the same parser-derived representation group.  This command verifies all 166
committed owner bindings, repairs exactly that one metadata flag, freezes the
251-source successor scope, and writes create-only evidence.  It never scans,
changes source bytes/chunks, builds an index, or opens a later-phase gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts import apply_v111_phase2a_consolidated_source_admissions as admissions

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEBUG_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-consolidated-source-admission-debug-r1"
)
FAILURE_REPORT_PATH = DEBUG_ROOT / "FAILURE-REPORT.json"
OUTPUT_ROOT = admissions.OUTPUT_ROOT

EXPECTED_FAILURE_REPORT_SHA256 = (
    "8905d6e8e9a9ba6b8b04051bffca7548f77b3a95a4530b92b0d2a703a87b8677"
)
EXPECTED_ORIGINAL_PLAN_SHA256 = (
    "ce8f9a6272d0522ae6e87366f6cc4123f097c647a3a170e59e5d7fe10be01755"
)
TARGET_AUTHORITY = "neutral-citation:[2024] UKSC 30"
TARGET_CONTENT_SHA256 = (
    "0263cac5554811683262d7c388cc08deaa5c3cd9acd7db0a58a510840137381b"
)
TARGET_DOCUMENT_ID = "document-f67a0b2122bad710a41b861b71e37af2e9339046"
TARGET_SOURCE_VERSION_ID = "source-version-84b3799159ad7e00b3259d7af5cd18b3cb5393bb"
COMPETING_AUTHORITY = "neutral-citation:[2025] EWCA Civ 99"
COMPETING_DOCUMENT_ID = "document-5b0a73ba777750c64b56218b9afd8db410cadc4b"
SHARED_REPRESENTATION_GROUP = (
    "neutral-citation-sha256:e9fa8be170aedb0c98b1d584fac708be43658cd65737526bd81424c67ee72eb9"
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


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


def _verify_failure_report() -> dict[str, Any]:
    if (
        FAILURE_REPORT_PATH.is_symlink()
        or not FAILURE_REPORT_PATH.is_file()
        or _sha256_file(FAILURE_REPORT_PATH) != EXPECTED_FAILURE_REPORT_SHA256
    ):
        raise ValueError("sealed source-admission failure report changed")
    value = json.loads(FAILURE_REPORT_PATH.read_bytes())
    if (
        not isinstance(value, dict)
        or value.get("root_cause", {}).get("status") != "ESTABLISHED"
        or value.get("source_bytes_changed") is not False
        or value.get("source_scope_changed") is not False
    ):
        raise ValueError("source-admission failure report boundary changed")
    return value


def _committed_records(
    connection: sqlite3.Connection, staging: Mapping[str, Any]
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for staged in staging.get("records", []):
        authority = str(staged.get("authority_identity_id") or "")
        content_sha256 = str(staged.get("content_sha256") or "")
        rows = connection.execute(
            """
            SELECT sv.id AS source_version_id,sv.document_id,sv.stable_identifier,
                   sv.authority_identity_id,sv.version_sha256,sv.review_status,
                   sv.superseded_by,sv.canonical_markdown_path,sv.metadata_json,
                   d.content_sha256,d.status,d.lane,d.retrieval_canonical,
                   d.representation_group_id,
                   (SELECT COUNT(*) FROM chunks c
                     WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.authority_identity_id=? AND d.content_sha256=?
              AND json_extract(
                    sv.metadata_json,
                    '$.phase2a_owner_held_source_admission.staging_artifact_content_sha256'
                  )=?
            """,
            (
                authority,
                content_sha256,
                admissions.EXPECTED_STAGING_ARTIFACT_SHA256,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("committed owner-held source binding is not unique")
        row = rows[0]
        if (
            row["review_status"] != "approved"
            or row["superseded_by"] is not None
            or row["status"] != "citable"
            or row["lane"] != "primary_authority"
            or row["content_sha256"] != content_sha256
            or row["version_sha256"] != content_sha256
            or int(row["body_chunk_count"] or 0) < 1
        ):
            raise ValueError("committed owner-held source state changed")
        metadata = json.loads(row["metadata_json"] or "{}")
        owner_binding = metadata.get("phase2a_owner_held_source_admission")
        if (
            not isinstance(owner_binding, dict)
            or owner_binding.get("authority_identity_id") != authority
            or owner_binding.get("content_sha256") != content_sha256
            or owner_binding.get("source_scan_id") != admissions.EXPECTED_SCAN_ID
            or sorted(owner_binding.get("approval_origins") or [])
            != sorted(staged.get("approval_origins") or [])
            or sorted(owner_binding.get("retained_hold_codes") or [])
            != sorted(staged.get("retained_hold_codes") or [])
            or owner_binding.get("answer_release_eligible") is not False
            or metadata.get("currentness_verified") is not False
            or metadata.get("answer_release_eligible") is not False
        ):
            raise ValueError("committed owner-held release boundary changed")
        markdown_path = PROJECT_ROOT / str(row["canonical_markdown_path"] or "")
        if not markdown_path.is_file() or markdown_path.stat().st_size < 1:
            raise ValueError("committed owner-held canonical Markdown is unavailable")
        review_count = connection.execute(
            """
            SELECT COUNT(*) AS n FROM reviews
            WHERE review_type='source_version' AND target_id=? AND status='approved'
              AND reason LIKE 'Exact owner-approved Phase-2A private research-index admission;%'
            """,
            (row["source_version_id"],),
        ).fetchone()
        if review_count is None or int(review_count["n"] or 0) != 1:
            raise ValueError("committed owner-held source review is not exact")
        records.append(
            {
                "source_version_id": str(row["source_version_id"]),
                "document_id": str(row["document_id"]),
                "authority_identity_id": authority,
                "stable_identifier": str(row["stable_identifier"]),
                "content_sha256": content_sha256,
                "version_sha256": str(row["version_sha256"]),
                "canonical_markdown_path": str(row["canonical_markdown_path"]),
                "body_chunk_count": int(row["body_chunk_count"]),
                "retrieval_canonical": bool(row["retrieval_canonical"]),
                "representation_group_id": str(row["representation_group_id"] or ""),
                "approval_origins": sorted(staged.get("approval_origins") or []),
                "retained_hold_codes": sorted(staged.get("retained_hold_codes") or []),
                "answer_release_eligible": False,
            }
        )
    if len(records) != admissions.EXPECTED_ADMITTED_COUNT:
        raise ValueError("committed owner-held source count changed")
    if len({item["source_version_id"] for item in records}) != len(records):
        raise ValueError("committed owner-held source versions are duplicated")
    return records


def build_recovery_plan() -> dict[str, Any]:
    failure = _verify_failure_report()
    staging = admissions._load_staging()
    predecessor = admissions._load_predecessor()
    connection = sqlite3.connect(
        f"file:{admissions.CATALOGUE_PATH}?mode=ro", uri=True
    )
    connection.row_factory = sqlite3.Row
    try:
        scan = admissions._verify_final_scan(connection)
        records = _committed_records(connection, staging)
        predecessor_records = admissions._predecessor_records(connection, predecessor)
        noncanonical = [
            item for item in records if item["retrieval_canonical"] is not True
        ]
        if noncanonical and {
            (item["authority_identity_id"], item["document_id"])
            for item in noncanonical
        } != {(TARGET_AUTHORITY, TARGET_DOCUMENT_ID)}:
            raise ValueError("unexpected committed canonical state")
        target = next(
            item for item in records if item["source_version_id"] == TARGET_SOURCE_VERSION_ID
        )
        if (
            target["content_sha256"] != TARGET_CONTENT_SHA256
            or target["representation_group_id"] != SHARED_REPRESENTATION_GROUP
        ):
            raise ValueError("targeted recovery identity changed")
        competitor = connection.execute(
            """
            SELECT sv.authority_identity_id,d.retrieval_canonical,d.representation_group_id
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE d.id=? AND sv.authority_identity_id=? AND sv.review_status='approved'
            LIMIT 1
            """,
            (COMPETING_DOCUMENT_ID, COMPETING_AUTHORITY),
        ).fetchone()
        if (
            competitor is None
            or int(competitor["retrieval_canonical"] or 0) != 1
            or competitor["representation_group_id"] != SHARED_REPRESENTATION_GROUP
        ):
            raise ValueError("unrelated canonical competitor state changed")
        successor_chunk_count = sum(
            int(item["body_chunk_count"])
            for item in [*predecessor_records, *records]
        )
        if successor_chunk_count != 222_200:
            raise ValueError("recovered successor chunk scope changed")
        material = {
            "schema": "legalbot.v111.phase2a.source-admission-recovery-plan.v1",
            "status": (
                "TARGETED_ONE_ROW_METADATA_REPAIR_READY"
                if noncanonical
                else "COMMITTED_ADMISSION_ALREADY_VERIFIED"
            ),
            "failure_fingerprint": failure["failure_fingerprint"],
            "failure_report_sha256": EXPECTED_FAILURE_REPORT_SHA256,
            "original_admission_plan_content_sha256": EXPECTED_ORIGINAL_PLAN_SHA256,
            "source_scan_id": scan["id"],
            "source_scan_manifest_sha256": scan["manifest_sha256"],
            "staging_artifact_content_sha256": (
                admissions.EXPECTED_STAGING_ARTIFACT_SHA256
            ),
            "committed_source_count": len(records),
            "committed_review_count": len(records),
            "predecessor_source_count": len(predecessor_records),
            "successor_source_count": len(predecessor_records) + len(records),
            "successor_body_chunk_count": successor_chunk_count,
            "repair_required_count": len(noncanonical),
            "repair_document_ids": [item["document_id"] for item in noncanonical],
            "target_document_id": TARGET_DOCUMENT_ID,
            "target_source_version_id": TARGET_SOURCE_VERSION_ID,
            "target_authority_identity_id": TARGET_AUTHORITY,
            "competing_document_id": COMPETING_DOCUMENT_ID,
            "competing_authority_identity_id": COMPETING_AUTHORITY,
            "shared_representation_group_id": SHARED_REPRESENTATION_GROUP,
            "source_bytes_changed": False,
            "chunks_changed": False,
            "source_scan_repeated": False,
            "source_scope_changed": False,
            "admission_transaction_replayed": False,
            "candidate_build_started": False,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "committed_sources": records,
        }
        material["artifact_content_sha256"] = _sha256_bytes(_canonical_json(material))
        return material
    finally:
        connection.close()


def apply_recovery(plan: Mapping[str, Any]) -> dict[str, Any]:
    if plan.get("status") != "TARGETED_ONE_ROW_METADATA_REPAIR_READY":
        raise ValueError("targeted source-admission recovery is not required")
    if OUTPUT_ROOT.exists() or OUTPUT_ROOT.is_symlink():
        raise ValueError("source-admission evidence output already exists")
    connection = sqlite3.connect(admissions.CATALOGUE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    temporary = Path(
        tempfile.mkdtemp(prefix=".phase2a-source-admission-recovery-", dir=OUTPUT_ROOT.parent)
    )
    output_renamed = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        target = connection.execute(
            """
            SELECT sv.authority_identity_id,sv.review_status,d.content_sha256,
                   d.retrieval_canonical,d.representation_group_id
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.id=? AND d.id=?
            """,
            (TARGET_SOURCE_VERSION_ID, TARGET_DOCUMENT_ID),
        ).fetchone()
        if (
            target is None
            or target["authority_identity_id"] != TARGET_AUTHORITY
            or target["review_status"] != "approved"
            or target["content_sha256"] != TARGET_CONTENT_SHA256
            or int(target["retrieval_canonical"] or 0) != 0
            or target["representation_group_id"] != SHARED_REPRESENTATION_GROUP
        ):
            raise ValueError("targeted canonical repair precondition changed")
        connection.execute(
            "UPDATE documents SET retrieval_canonical=1 WHERE id=? AND retrieval_canonical=0",
            (TARGET_DOCUMENT_ID,),
        )
        if int(connection.execute("SELECT changes() AS n").fetchone()["n"]) != 1:
            raise ValueError("targeted canonical repair did not affect exactly one row")
        staging = admissions._load_staging()
        committed = _committed_records(connection, staging)
        if any(item["retrieval_canonical"] is not True for item in committed):
            raise ValueError("targeted canonical repair did not verify all admissions")
        predecessor = admissions._load_predecessor()
        scope = admissions._scope(
            connection, {"admitted_sources": committed}, predecessor
        )
        scope.pop("scope_content_sha256", None)
        scope["admission_recovery_failure_report_sha256"] = (
            EXPECTED_FAILURE_REPORT_SHA256
        )
        scope["original_admission_plan_content_sha256"] = EXPECTED_ORIGINAL_PLAN_SHA256
        scope["admission_transaction_replayed"] = False
        scope["targeted_metadata_repair_count"] = 1
        scope["scope_content_sha256"] = _sha256_bytes(_canonical_json(scope))
        outcome = (
            "PHASE 2A EXACT OWNER-HELD SOURCE ADMISSIONS VERIFIED — FROZEN SCOPE READY\n"
            f"FROZEN SCOPE DIGEST: {scope['scope_content_sha256']}\n"
            "One canonical metadata flag was repaired; source bytes, chunks and scan scope were unchanged.\n"
            "NO ADMISSION REPLAY; BUILD NOT STARTED; PHASE 2B AND DEVELOPMENT 30 REMAIN CLOSED.\n"
        ).encode()
        files = {
            "SOURCE-ADMISSION-RECOVERY-PLAN.json": _pretty_json(dict(plan)),
            admissions.SCOPE_FILENAME: _pretty_json(scope),
            "OUTCOME.txt": outcome,
        }
        for name, raw in files.items():
            _write_exclusive(temporary / name, raw)
        entries = {
            name: {
                "sha256": _sha256_file(temporary / name),
                "bytes": (temporary / name).stat().st_size,
            }
            for name in sorted(files)
        }
        package = {
            "schema": "legalbot.v111.phase2a.consolidated-source-admission-package.v1",
            "status": "EXACT_OWNER_HELD_SOURCE_SCOPE_FROZEN_BUILD_NOT_STARTED",
            "failure_report_sha256": EXPECTED_FAILURE_REPORT_SHA256,
            "original_admission_plan_content_sha256": EXPECTED_ORIGINAL_PLAN_SHA256,
            "recovery_plan_content_sha256": plan["artifact_content_sha256"],
            "frozen_scope_content_sha256": scope["scope_content_sha256"],
            "file_count": len(entries),
            "files": entries,
            "source_count": scope["source_count"],
            "chunk_count": scope["chunk_count"],
            "source_bytes_changed": False,
            "source_scan_repeated": False,
            "source_scope_changed": False,
            "admission_transaction_replayed": False,
            "targeted_metadata_repair_count": 1,
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
        output_renamed = True
        connection.commit()
        return {
            "status": package["status"],
            "source_count": scope["source_count"],
            "chunk_count": scope["chunk_count"],
            "targeted_metadata_repair_count": 1,
            "frozen_scope_content_sha256": scope["scope_content_sha256"],
            "package_content_sha256": package["package_content_sha256"],
            "candidate_build_started": False,
            "phase2b_authorized": False,
        }
    except BaseException:
        if connection.in_transaction:
            connection.rollback()
        if output_renamed and OUTPUT_ROOT.exists():
            shutil.rmtree(OUTPUT_ROOT)
        elif temporary.exists():
            shutil.rmtree(temporary)
        raise
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Repair one canonical flag and seal the already committed admission",
    )
    args = parser.parse_args()
    plan = build_recovery_plan()
    result: dict[str, Any] = {
        "apply": bool(args.apply),
        "status": plan["status"],
        "committed_source_count": plan["committed_source_count"],
        "successor_source_count": plan["successor_source_count"],
        "successor_body_chunk_count": plan["successor_body_chunk_count"],
        "repair_required_count": plan["repair_required_count"],
        "artifact_content_sha256": plan["artifact_content_sha256"],
        "admission_transaction_replayed": False,
        "candidate_build_started": False,
        "phase2b_authorized": False,
    }
    if args.apply:
        result.update(apply_recovery(plan))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
