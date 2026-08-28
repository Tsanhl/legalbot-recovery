#!/usr/bin/env python3
"""Approve only the two independently identified Quistclose journal articles."""

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

from backend.app.citations.oscola import render_oscola  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "trusts_scholarship_pack.json"
APPROVAL_POLICY = "legalbot.verified-quistclose-scholarship.v1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--apply", action="store_true")
    return parser


def main() -> None:
    args = _parser().parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("schema") != "legalbot.scholarship-pack.v1":
        raise SystemExit("unsupported scholarship manifest")
    if len(manifest.get("items", [])) != 2:
        raise SystemExit("the reviewed Quistclose pack must contain exactly two items")

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
            render_oscola(item["citation_data"])
            rows = database.fetchall(
                """
                SELECT d.lane, d.status, sv.id AS source_version_id,
                       sv.review_status AS source_review_status, sv.metadata_json,
                       r.id AS review_id, r.status AS card_status,
                       (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id)
                         AS chunk_count,
                       (SELECT group_concat(c.markdown_text, ' ') FROM chunks c
                        WHERE c.source_version_id=sv.id) AS local_text
                FROM documents d
                JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                LEFT JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
                WHERE d.content_sha256=? AND d.lane='scholarship'
                  AND d.subject_primary='trusts' AND d.retrieval_canonical=1
                """,
                (item["sha256"],),
            )
            reasons: list[str] = []
            row = rows[0] if len(rows) == 1 else None
            if row is None:
                reasons.append("catalogue_identity_not_unique")
            else:
                metadata = json.loads(row["metadata_json"] or "{}")
                if row["lane"] != "scholarship":
                    reasons.append("wrong_lane")
                if row["status"] not in {"citable", "duplicate"}:
                    reasons.append("source_not_citable")
                if int(row["chunk_count"]) < 1:
                    reasons.append("no_searchable_chunks")
                if metadata.get("material_type_candidate") != "journal":
                    reasons.append("not_journal")
                if row["source_review_status"] not in {"staged", "approved"}:
                    reasons.append("source_review_not_actionable")
                if row["card_status"] not in {"pending", "approved"}:
                    reasons.append("review_not_actionable")
                local_text = str(row["local_text"] or "")
                title_tokens = set(
                    re.findall(r"[a-z0-9]+", str(item["citation_data"]["title"]).casefold())
                )
                local_tokens = set(re.findall(r"[a-z0-9]+", local_text[:20_000].casefold()))
                if not title_tokens or len(title_tokens & local_tokens) / len(title_tokens) < 0.9:
                    reasons.append("title_not_verified_in_source")
                if "/Users/" in local_text or prompt_injection_hits(local_text):
                    reasons.append("unsafe_retrieval_text")
            result = {
                "stable_identifier": item["stable_identifier"],
                "decision": "approve" if not reasons else "hold",
                "reasons": reasons,
            }
            if reasons or row is None:
                holds.append(result)
            else:
                ready.append((row, item))

        if holds:
            print(json.dumps({"ready": len(ready), "holds": holds}, indent=2, sort_keys=True))
            raise SystemExit("scholarship approval stopped: resolve all holds first")
        if args.apply:
            for row, item in ready:
                if row["source_review_status"] == "approved" and row["card_status"] == "approved":
                    continue
                database.decide_review(
                    str(row["review_id"]),
                    "approved",
                    f"{APPROVAL_POLICY}: publisher identity verified; scholarship only",
                    {
                        "identity_verified": True,
                        "currentness_verified": True,
                        "stable_identifier": item["stable_identifier"],
                        "as_of_date": date.today().isoformat(),
                        "currentness_status": "historical",
                        "material_type": "journal",
                        "citation_data": item["citation_data"],
                        "canonical_url": item["canonical_url"],
                        "licence_name": item["licence_name"],
                        **({"licence_url": item["licence_url"]} if item.get("licence_url") else {}),
                    },
                )
        print(
            json.dumps({"apply": args.apply, "approved_or_ready": len(ready), "holds": 0}, indent=2)
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
