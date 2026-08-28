"""Privacy-safe source-scan attestation. Failed scans cannot override complete ones."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from ..db import Database
from ..evaluation.live30 import assert_safe_evaluation_payload
from ..evaluation.live_suite import sealed_sha256

SCAN_ATTESTATION_SCHEMA = "legalbot.source-scan-attestation.v1"
ROLLBACK_QUARANTINE_REASON = "processing_policy_rollback_refused"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def latest_complete_reconciled_scan(database: Database) -> dict[str, Any] | None:
    """Return the newest complete reconciled scan. Failed scans never win."""

    row = database.fetchone(
        """
        SELECT id, status, expected_file_count, files_accounted, manifest_sha256,
               completed_at, created_at, error_code
        FROM source_scans
        WHERE status='complete'
        ORDER BY completed_at DESC, created_at DESC
        LIMIT 1
        """
    )
    if row is None:
        return None
    expected = int(row["expected_file_count"] or 0)
    accounted = int(row["files_accounted"] or 0)
    if expected != accounted or expected < 1:
        return None
    actual = database.fetchone(
        "SELECT COUNT(*) AS n FROM source_scan_files WHERE scan_id=?",
        (row["id"],),
    )
    if actual is None or int(actual["n"]) != expected:
        return None
    return {
        "scan_id": str(row["id"]),
        "status": "complete",
        "expected_file_count": expected,
        "files_accounted": accounted,
        "manifest_sha256": str(row["manifest_sha256"] or ""),
        "completed_at": row["completed_at"],
    }


def scan_quarantine_counts(database: Database, scan_id: str) -> dict[str, int]:
    rows = database.fetchall(
        """
        SELECT reason, COUNT(*) AS n
        FROM source_scan_files
        WHERE scan_id=? AND status='quarantined'
        GROUP BY reason
        """,
        (scan_id,),
    )
    return {str(row["reason"] or ""): int(row["n"]) for row in rows}


def source_root_count(database: Database, scan_id: str) -> int:
    row = database.fetchone(
        "SELECT required_roots_json FROM source_scans WHERE id=?",
        (scan_id,),
    )
    if row is None:
        return 0
    try:
        roots = json.loads(row["required_roots_json"] or "[]")
    except (TypeError, json.JSONDecodeError):
        return 0
    return len(roots) if isinstance(roots, list) else 0


def superseded_failed_scan_ids(database: Database, *, complete_scan_id: str) -> tuple[str, ...]:
    rows = database.fetchall(
        """
        SELECT id FROM source_scans
        WHERE status='failed' AND id<>?
        ORDER BY created_at
        """,
        (complete_scan_id,),
    )
    return tuple(str(row["id"]) for row in rows)


def build_scan_attestation(
    database: Database,
    *,
    scan_id: str,
    code_sha: str | None = None,
) -> dict[str, Any]:
    latest = latest_complete_reconciled_scan(database)
    if latest is None or latest["scan_id"] != scan_id:
        raise ValueError("scan is not the latest complete reconciled source scan")
    row = database.fetchone("SELECT * FROM source_scans WHERE id=?", (scan_id,))
    if row is None:
        raise ValueError("source scan is missing")
    try:
        statuses = json.loads(row["statuses_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        statuses = {}
    quarantine = scan_quarantine_counts(database, scan_id)
    payload = {
        "schema": SCAN_ATTESTATION_SCHEMA,
        "scan_id": scan_id,
        "status": "complete",
        "manifest_sha256": str(row["manifest_sha256"] or ""),
        "expected_file_count": int(row["expected_file_count"] or 0),
        "accounted_file_count": int(row["files_accounted"] or 0),
        "source_root_count": source_root_count(database, scan_id),
        "quarantine_count": int((statuses or {}).get("quarantined") or 0),
        "quarantine_reason_counts": quarantine,
        "rollback_quarantine_count": int(quarantine.get(ROLLBACK_QUARANTINE_REASON) or 0),
        "quarantine_reason_code": ROLLBACK_QUARANTINE_REASON,
        "completed_at": row["completed_at"],
        "superseded_scan_ids": list(superseded_failed_scan_ids(database, complete_scan_id=scan_id)),
        "code_sha": code_sha,
        "writes_active": False,
        "writes_o04": False,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    assert_safe_evaluation_payload(payload)
    return payload


def catalogue_state_sha256(database: Database) -> str:
    """Digest catalogue identities that owner packs may bind to, never path bytes."""

    row = database.fetchone(
        """
        SELECT
          (SELECT COUNT(*) FROM source_versions) AS source_versions,
          (SELECT COUNT(*) FROM documents) AS documents,
          (SELECT COUNT(*) FROM chunks) AS chunks,
          (SELECT COUNT(*) FROM reviews WHERE status='pending') AS pending_reviews
        """
    )
    payload = {
        "source_versions": int(row["source_versions"] if row else 0),
        "documents": int(row["documents"] if row else 0),
        "chunks": int(row["chunks"] if row else 0),
        "pending_reviews": int(row["pending_reviews"] if row else 0),
    }
    encoded = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return _sha256_bytes(encoded)


def _mapping_field(item: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = item.get(name) if hasattr(item, "get") else None
        if value is None:
            try:
                value = item[name]
            except (KeyError, IndexError, TypeError):
                value = None
        if value:
            return str(value)
    return ""


def selected_sources_exclude_quarantine(sources: Sequence[Mapping[str, Any]]) -> None:
    leaked = [
        _mapping_field(item, "source_version_id", "id")
        for item in sources
        if _mapping_field(item, "document_status", "status") == "quarantined"
    ]
    if leaked:
        raise ValueError("quarantined source versions cannot enter a candidate manifest")
