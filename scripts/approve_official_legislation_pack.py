#!/usr/bin/env python3
"""Verify and approve only the downloaded official as-enacted legislation pack."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "official_legislation_pack.json"
DEFAULT_REPORT = (
    PROJECT_ROOT / "data" / "review_queue" / "official-legislation-download-2026-08-12.json"
)
APPROVAL_POLICY = "legalbot.official-as-enacted-approval.v1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--apply", action="store_true")
    return parser


def _stable_identifier(identity: str) -> str:
    return f"{':'.join(identity.split('/'))}:enacted"


def _source_approval(item: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    identity = str(item["identity"])
    title = str(item["title"])
    citation_data: dict[str, Any]
    if identity.startswith("uksi/"):
        _, year, number = identity.split("/")
        citation_data = {
            "source_type": "statutory_instrument",
            "title": title,
            "instrument_number": f"SI {year}/{number}",
        }
    else:
        citation_data = {"source_type": "legislation", "title": title}
    licence = manifest["licence"]
    return {
        "identity_verified": True,
        "currentness_verified": True,
        "stable_identifier": _stable_identifier(identity),
        "as_of_date": date.today().isoformat(),
        "currentness_status": "historical",
        "material_type": "legislation",
        "citation_data": citation_data,
        "canonical_url": f"https://www.legislation.gov.uk/{identity}/contents/enacted",
        "licence_name": f"{licence['name']} v{licence['version']}",
        "licence_url": licence["url"],
    }


def main() -> None:
    args = _parser().parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if manifest.get("schema") != "legalbot.official-legislation-pack.v1":
        raise SystemExit("unsupported official legislation manifest")
    if report.get("schema") != "legalbot.official-legislation-download-report.v1":
        raise SystemExit("unsupported official legislation download report")
    if report.get("manifest_version") != manifest.get("version"):
        raise SystemExit("download report does not match the reviewed manifest")

    report_by_identity = {str(item["identity"]): item for item in report["items"]}
    if len(report_by_identity) != len(report["items"]):
        raise SystemExit("download report contains duplicate legislation identities")
    if set(report_by_identity) != {str(item["identity"]) for item in manifest["items"]}:
        raise SystemExit("download report identities do not exactly match the reviewed manifest")
    database = Database(Settings().database_path)
    database.initialize()
    ready: list[tuple[Any, dict[str, Any]]] = []
    holds: list[dict[str, Any]] = []
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued', 'running') LIMIT 1"
        ):
            raise SystemExit("source scan is active; approval requires a frozen catalogue")
        for item in manifest["items"]:
            identity = str(item["identity"])
            downloaded = report_by_identity.get(identity)
            reasons: list[str] = []
            if downloaded is None or not re.fullmatch(
                r"[0-9a-f]{64}", str(downloaded.get("sha256") or "")
            ):
                reasons.append("missing_verified_download")
                rows: list[Any] = []
            else:
                if downloaded.get("title") != item["title"]:
                    reasons.append("download_title_mismatch")
                if downloaded.get("status") not in {"downloaded", "already_present"}:
                    reasons.append("download_not_verified")
                if downloaded.get("representation") not in {
                    "official_as_enacted_pdf",
                    "official_as_enacted_html",
                }:
                    reasons.append("wrong_representation")
                rows = database.fetchall(
                    """
                    SELECT d.id AS document_id, d.lane, d.jurisdiction, d.status,
                           d.retrieval_canonical, sv.id AS source_version_id,
                           sv.review_status AS source_review_status, sv.metadata_json,
                           r.id AS review_id, r.status AS card_status,
                           (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) AS chunk_count,
                           (SELECT group_concat(c.markdown_text, ' ') FROM chunks c
                            WHERE c.source_version_id=sv.id) AS local_text
                    FROM documents d
                    JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                    LEFT JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
                    WHERE d.content_sha256=?
                    """,
                    (downloaded["sha256"],),
                )
            if len(rows) != 1:
                reasons.append("catalogue_identity_not_unique")
            row = rows[0] if len(rows) == 1 else None
            metadata = json.loads(row["metadata_json"] or "{}") if row is not None else {}
            if row is not None:
                if row["lane"] != "primary_authority":
                    reasons.append("wrong_lane")
                if row["jurisdiction"] != "United Kingdom":
                    reasons.append("wrong_jurisdiction")
                if row["status"] not in {"citable", "duplicate"}:
                    reasons.append("source_not_citable")
                if int(row["chunk_count"]) < 1:
                    reasons.append("no_searchable_chunks")
                if metadata.get("classification_confidence") not in {"medium", "high"}:
                    reasons.append("classification_not_reviewable")
                if metadata.get("material_type_candidate") not in {"legislation", "rule"}:
                    reasons.append("not_legislation_or_rule_candidate")
                if row["source_review_status"] not in {"staged", "approved"}:
                    reasons.append("source_review_not_actionable")
                if row["card_status"] not in {"pending", "approved"}:
                    reasons.append("review_not_actionable")
                local_text = str(row["local_text"] or "")
                title_terms = {
                    value.casefold() for value in re.findall(r"[A-Za-z]{4,}", str(item["title"]))
                }
                if (
                    title_terms
                    and len(
                        title_terms & set(re.findall(r"[a-z]{4,}", local_text[:20_000].casefold()))
                    )
                    / len(title_terms)
                    < 0.8
                ):
                    reasons.append("local_title_mismatch")
                if "/Users/" in local_text or prompt_injection_hits(local_text):
                    reasons.append("unsafe_retrieval_text")
            result = {
                "identity": identity,
                "decision": "approve" if not reasons else "hold",
                "reasons": reasons,
            }
            if reasons or row is None:
                holds.append(result)
                continue
            ready.append((row, item))

        if holds:
            print(json.dumps({"ready": len(ready), "holds": holds}, indent=2, sort_keys=True))
            raise SystemExit("official legislation approval stopped: resolve all holds first")
        if args.apply:
            for row, item in ready:
                if row["source_review_status"] == "approved" and row["card_status"] == "approved":
                    continue
                database.decide_review(
                    str(row["review_id"]),
                    "approved",
                    f"{APPROVAL_POLICY}: exact official manifest, identity, title, OGL source and local text verified; historical legislation only",
                    _source_approval(item, manifest),
                )
        print(
            json.dumps({"apply": args.apply, "approved_or_ready": len(ready), "holds": 0}, indent=2)
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
