#!/usr/bin/env python3
"""Approve only reconciled official Quistclose sources after a fresh full scan.

The command is a dry run unless ``--apply`` is supplied.  It never builds or
promotes an index.  A completed scan must have been created after the bounded
download report and must account for every one of the seven pinned hashes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.citations.oscola import render_oscola  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

from scripts.import_quistclose_authority_pack import (  # noqa: E402
    REPORT_SCHEMA,
    SCHEMA,
    _canonical_sha256,
    validate_manifest,
    verify_representation_payload,
)
from scripts.materialize_quistclose_evidence import (  # noqa: E402
    materialize_reviewed_chunks,
)

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "quistclose_authority_pack.json"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "quistclose-authority-download.json"
DEFAULT_APPROVAL_REPORT = (
    PROJECT_ROOT / "data" / "review_queue" / "quistclose-authority-approval.json"
)
POLICY = "legalbot.verified-official-quistclose-authorities.v1"
# A fresh scan may conservatively place an HTML judgment in a non-authority
# lane.  That classification is precisely what this independently reviewed
# pack is allowed to correct.  Parse/security failures remain excluded.
ACCEPTABLE_SCAN_STATUSES = {
    "citable",
    "private_teaching",
    "assessment_guidance",
    "duplicate",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--approval-report", type=Path, default=DEFAULT_APPROVAL_REPORT)
    parser.add_argument("--apply", action="store_true")
    return parser


def _parse_time(value: object, field: str) -> datetime:
    raw = str(value or "").strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"{field} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def require_fresh_complete_scan(database: Any, report: dict[str, Any]) -> Any:
    """Return the qualifying latest scan or fail closed.

    This helper is intentionally independent of the concrete Database class so
    the temporal/reconciliation gate can be tested without the owner database.
    """

    if database.fetchone(
        "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
    ):
        raise ValueError("source scan is active; approval requires a frozen catalogue")
    scan = database.fetchone(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,created_at,completed_at
        FROM source_scans WHERE status='complete'
        ORDER BY completed_at DESC, created_at DESC LIMIT 1
        """
    )
    if scan is None:
        raise ValueError("no complete source scan exists")
    downloaded_at = _parse_time(report.get("downloaded_at"), "downloaded_at")
    if _parse_time(scan["created_at"], "scan.created_at") <= downloaded_at:
        raise ValueError("latest complete source scan was not created after this download")
    if _parse_time(scan["completed_at"], "scan.completed_at") <= downloaded_at:
        raise ValueError("latest complete source scan did not finish after this download")
    expected = int(scan["expected_file_count"])
    accounted = int(scan["files_accounted"])
    if expected != accounted or expected < 1:
        raise ValueError("latest complete source scan is not exactly reconciled")
    if not re.fullmatch(r"[0-9a-f]{64}", str(scan["manifest_sha256"] or "")):
        raise ValueError("latest complete source scan has no sealed manifest SHA-256")
    rows = database.fetchall(
        "SELECT content_sha256,status FROM source_scan_files WHERE scan_id=?",
        (scan["id"],),
    )
    expected_hashes = {str(item["sha256"]) for item in report["items"]}
    observed: dict[str, set[str]] = {}
    for row in rows:
        digest = str(row["content_sha256"] or "")
        if digest in expected_hashes:
            observed.setdefault(digest, set()).add(str(row["status"]))
    missing = sorted(expected_hashes - set(observed))
    bad_status = sorted(
        digest
        for digest, statuses in observed.items()
        if not statuses or not (statuses & ACCEPTABLE_SCAN_STATUSES)
    )
    if missing or bad_status:
        raise ValueError(
            "fresh scan did not safely account for all pack files: "
            f"missing={len(missing)}, unsafe_status={len(bad_status)}"
        )
    return scan


def _approval(
    item: dict[str, Any], local: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    citation_data = {
        "source_type": "case",
        "case_name": str(item["case_name"]),
        "neutral_citation": str(item["neutral_citation"]),
        "decision_date": str(item["decision_date"]),
    }
    canonical_citation = render_oscola(citation_data)
    licence = manifest["licences"][item["licence_id"]]
    return {
        "identity_verified": True,
        # This trusted workflow verifies only the historic snapshot identity;
        # present-law currentness remains false by construction.
        "currentness_verified": False,
        "stable_identifier": str(item["authority_id"]),
        "as_of_date": item["decision_date"],
        "currentness_status": "historical",
        "material_type": "case",
        "citation_data": citation_data,
        "canonical_citation": canonical_citation,
        "canonical_url": item["official_case_url"],
        "licence_name": f"{licence['name']} v{licence['version']}",
        "licence_url": licence["url"],
        "identity_title": item["case_name"],
        "download_sha256": local["sha256"],
    }


def _safe_source_path(relative_path: object) -> Path:
    value = str(relative_path or "")
    if not value or Path(value).is_absolute():
        raise ValueError("download report source path must be project-relative")
    path = (PROJECT_ROOT / value).resolve()
    allowed = (PROJECT_ROOT / "sources" / "materials-2026-08-12" / "Official Quistclose").resolve()
    try:
        path.relative_to(allowed)
    except ValueError as exc:
        raise ValueError("download report source path escaped the official pack") from exc
    return path


def _load_pack(
    manifest_path: Path, report_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, tuple[dict[str, Any], dict[str, Any]]]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    representations = validate_manifest(manifest)
    if manifest.get("schema") != SCHEMA or report.get("schema") != REPORT_SCHEMA:
        raise ValueError("unsupported Quistclose manifest or download report")
    if report.get("manifest_version") != manifest.get("version"):
        raise ValueError("Quistclose report and manifest versions differ")
    if report.get("manifest_sha256") != _canonical_sha256(manifest):
        raise ValueError("Quistclose report is not bound to the reviewed manifest")
    downloaded = {str(value["representation_id"]): value for value in report.get("items", [])}
    if len(downloaded) != 7 or set(downloaded) != set(representations):
        raise ValueError("Quistclose report and manifest do not reconcile exactly")
    for representation_id, (item, representation) in representations.items():
        local = downloaded[representation_id]
        expected = {
            "authority_id": item["authority_id"],
            "case_id": item["case_id"],
            "case_name": item["case_name"],
            "neutral_citation": item["neutral_citation"],
            "decision_date": item["decision_date"],
            "representation_id": representation_id,
            "official_case_url": item["official_case_url"],
            "official_representation_url": representation["official_url"],
            "licence_id": item["licence_id"],
            "sha256": representation["sha256"],
            "bytes": representation["bytes"],
        }
        if any(local.get(key) != value for key, value in expected.items()):
            raise ValueError(f"download report identity differs for {representation_id}")
        path = _safe_source_path(local.get("relative_path"))
        if not path.is_file():
            raise ValueError(f"downloaded source is missing for {representation_id}")
        data = path.read_bytes()
        verify_representation_payload(item, representation, data)
        report_passages = local.get("reviewed_passages")
        manifest_passages = [
            {
                "locator": passage["locator"],
                "legal_role": passage["legal_role"],
                "issues": passage["issues"],
                "review_note": passage["review_note"],
            }
            for passage in item["reviewed_passages"]
            if passage["representation_id"] == representation_id
        ]
        if report_passages != manifest_passages:
            raise ValueError("reviewed legal-role metadata differs from the manifest")
    return manifest, report, representations


def _classification_target() -> dict[str, str]:
    return {
        "lane": "primary_authority",
        "status": "citable",
        "subject": "trusts",
        "jurisdiction": "England and Wales",
    }


def main() -> None:
    args = _parser().parse_args()
    manifest, report, representations = _load_pack(args.manifest, args.report)
    downloaded = {str(value["representation_id"]): value for value in report["items"]}
    database = Database(Settings().database_path)
    database.initialize()
    ready: list[dict[str, Any]] = []
    holds: list[dict[str, Any]] = []
    corrections: list[dict[str, Any]] = []
    approved_now = 0
    already_approved = 0
    materialization: dict[str, Any] | None = None
    try:
        scan = require_fresh_complete_scan(database, report)
        for representation_id, (item, representation) in representations.items():
            local = downloaded[representation_id]
            rows = database.fetchall(
                """
                SELECT d.id AS document_id,d.lane,d.status,d.subject_primary,d.jurisdiction,
                       d.retrieval_canonical,sv.id AS source_version_id,
                       sv.review_status AS source_review_status,sv.stable_identifier,
                       sv.metadata_json,
                       (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) chunk_count,
                       (SELECT group_concat(c.markdown_text,' ') FROM chunks c
                        WHERE c.source_version_id=sv.id) local_text
                FROM documents d
                JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                WHERE d.content_sha256=? AND d.duplicate_of IS NULL
                """,
                (local["sha256"],),
            )
            reasons: list[str] = []
            row = rows[0] if len(rows) == 1 else None
            review_id: str | None = None
            if row is None:
                reasons.append("catalogue_identity_not_unique")
            else:
                review = database.fetchone(
                    """
                    SELECT id,status FROM reviews
                    WHERE review_type='source_version' AND target_id=?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (row["source_version_id"],),
                )
                text = str(row["local_text"] or "")
                if int(row["retrieval_canonical"]) != 1:
                    reasons.append("not_canonical_representation")
                if int(row["chunk_count"]) < 1:
                    reasons.append("no_chunks")
                if row["source_review_status"] == "staged":
                    if review is None or review["status"] != "pending":
                        reasons.append("source_review_not_actionable")
                    else:
                        review_id = str(review["id"])
                elif row["source_review_status"] == "approved":
                    if str(row["stable_identifier"] or "") != item["authority_id"]:
                        reasons.append("approved_under_different_authority_identity")
                else:
                    reasons.append("source_review_not_actionable")
                if len(text.strip()) < 100:
                    reasons.append("insufficient_retrieval_text")
                if "/Users/" in text or prompt_injection_hits(text):
                    reasons.append("unsafe_retrieval_text")
            if reasons or row is None:
                holds.append({"representation_id": representation_id, "reasons": reasons})
            else:
                ready.append(
                    {
                        "row": row,
                        "review_id": review_id,
                        "item": item,
                        "representation": representation,
                        "local": local,
                    }
                )
        if holds:
            output = {
                "apply": args.apply,
                "ready": len(ready),
                "holds": holds,
                "scan_id": scan["id"],
                "result": "stopped_without_approval",
            }
            print(json.dumps(output, indent=2, sort_keys=True))
            raise SystemExit("Quistclose approval stopped: resolve every hold")
        if args.apply:
            cipher = LocalCipher.from_local_key(create=False)
            note = cipher.encrypt_text(
                f"{POLICY}: official identity, pinned bytes, licence and conservative legal-role metadata verified; subsequent treatment remains issue-specific"
            )
            for entry in ready:
                row = entry["row"]
                item = entry["item"]
                representation = entry["representation"]
                local = entry["local"]
                target = _classification_target()
                previous = {
                    "lane": str(row["lane"] or ""),
                    "status": str(row["status"] or ""),
                    "subject": str(row["subject_primary"] or ""),
                    "jurisdiction": str(row["jurisdiction"] or ""),
                }
                if previous != target:
                    corrections.append(
                        {
                            "representation_id": representation["representation_id"],
                            "from": previous,
                            "to": target,
                        }
                    )
                    database.execute(
                        "UPDATE documents SET lane=?,status=?,subject_primary=?,jurisdiction=? WHERE id=?",
                        (
                            target["lane"],
                            target["status"],
                            target["subject"],
                            target["jurisdiction"],
                            row["document_id"],
                        ),
                    )
                if row["source_review_status"] == "staged":
                    review_id = entry["review_id"]
                    if not review_id or not database.decide_review(
                        review_id,
                        "approved",
                        None,
                        _approval(item, local, manifest),
                        encrypted_note=note,
                        trusted_case_snapshot_approval=True,
                    ):
                        raise RuntimeError("Quistclose review changed during approval")
                    approved_now += 1
                else:
                    already_approved += 1
                current = database.fetchone(
                    "SELECT metadata_json FROM source_versions WHERE id=?",
                    (row["source_version_id"],),
                )
                metadata = json.loads(current["metadata_json"] or "{}")
                if not isinstance(metadata, dict):
                    raise RuntimeError("source metadata is not an object")
                licence = manifest["licences"][item["licence_id"]]
                metadata["official_snapshot"] = {
                    "schema": "legalbot.official-judgment-snapshot.v1",
                    "publisher": item["publisher"],
                    "authority_id": item["authority_id"],
                    "case_id": item["case_id"],
                    "representation_id": representation["representation_id"],
                    "download_sha256": local["sha256"],
                    "decision_date": item["decision_date"],
                    "source_pack_version": manifest["version"],
                    "source_pack_manifest_sha256": report["manifest_sha256"],
                    "source_scan_manifest_sha256": scan["manifest_sha256"],
                    "treatment_qualification": (
                        "Historical judgment identity is verified; an expert must check "
                        "subsequent treatment for the live issue"
                    ),
                }
                metadata["reviewed_legal_passages"] = local["reviewed_passages"]
                metadata["legal_role_scheme"] = "holding_ratio_or_obiter_conservative_v1"
                metadata["licence_attribution"] = licence["required_attribution"]
                database.execute(
                    """
                    UPDATE source_versions
                    SET authority_identity_id=?,metadata_json=?
                    WHERE id=?
                    """,
                    (
                        item["authority_id"],
                        json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                        row["source_version_id"],
                    ),
                )
            materialization = materialize_reviewed_chunks(
                database,
                manifest=manifest,
                download_report=report,
                representations=representations,
                apply=True,
                source_scan_manifest_sha256=str(scan["manifest_sha256"]),
            )
        approval_report = {
            "schema": "legalbot.quistclose-authority-approval-report.v1",
            "policy": POLICY,
            "apply": args.apply,
            "manifest_version": manifest["version"],
            "manifest_sha256": report["manifest_sha256"],
            "source_scan_id": scan["id"],
            "source_scan_manifest_sha256": scan["manifest_sha256"],
            "representations_ready": len(ready),
            "approved_now": approved_now,
            "already_approved": already_approved,
            "holds": [],
            "classification_corrections": corrections,
            "indexing_status": "not_built_or_promoted",
            "reviewed_evidence_materialization": (
                {
                    "derived_chunk_schema": materialization["derived_chunk_schema"],
                    "paragraph_chunks": materialization["paragraph_chunks"],
                    "holding_ratio_chunks": materialization["holding_ratio_chunks"],
                    "obiter_chunks": materialization["obiter_chunks"],
                    "materialization_sha256": materialization["materialization_sha256"],
                    "evidence_span_state": materialization["evidence_span_state"],
                }
                if materialization is not None
                else {"status": "not_applied_in_dry_run"}
            ),
            "approval_scope": (
                "identity, licence, historical decision snapshot and reviewed passage roles; "
                "runtime present-law currentness remains false until subsequent treatment is "
                "bound to exact EvidenceSpan and proposition hashes"
            ),
            "present_law_currentness_verified": False,
            "subsequent_treatment_check_required": True,
            "created_at": datetime.now(UTC).isoformat(),
        }
        args.approval_report.parent.mkdir(parents=True, exist_ok=True)
        args.approval_report.write_text(
            json.dumps(approval_report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "apply": args.apply,
                    "approved_now": approved_now,
                    "already_approved": already_approved,
                    "ready": len(ready),
                    "holds": 0,
                    "index_built_or_promoted": False,
                    "scan_manifest_sha256": scan["manifest_sha256"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
