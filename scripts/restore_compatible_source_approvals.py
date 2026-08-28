#!/usr/bin/env python3
"""Carry reviewed source identity metadata across a compatible processing-only version."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

POLICY = "legalbot.compatible-processing-approval-carry-forward.v1"
ALLOWED_TYPES = {
    "primary_authority": {"case", "legislation", "rule"},
    "official_secondary": {"official_guidance"},
    "scholarship": {"journal", "book"},
    "private_teaching": {"lecture", "tutorial", "seminar", "course_note"},
    "assessment_guidance": {"assessment", "rubric", "marker_feedback"},
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    return parser


def _approval(row: Any, metadata: dict[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "identity_verified": metadata.get("identity_verified"),
        "currentness_verified": metadata.get("currentness_verified"),
        "stable_identifier": row["old_stable_identifier"],
        "as_of_date": row["old_as_of_date"],
        "currentness_status": row["old_currentness_status"],
        "material_type": metadata.get("material_type"),
        "citation_data": metadata.get("citation_data", {}),
    }
    for key, column in (
        ("canonical_url", "old_canonical_url"),
        ("licence_name", "old_licence_name"),
        ("licence_url", "old_licence_url"),
    ):
        if row[column]:
            value[key] = row[column]
    if metadata.get("identity_title"):
        value["identity_title"] = metadata["identity_title"]
    return value


def main() -> None:
    args = _parser().parse_args()
    database = Database(Settings().database_path)
    database.initialize()
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued', 'running') LIMIT 1"
        ):
            raise SystemExit("source scan is active; carry-forward requires a frozen catalogue")
        rows = database.fetchall(
            """
            SELECT d.lane, d.status, current.id AS current_id,
                   current.version_sha256 AS current_version_sha256,
                   current.metadata_json AS current_metadata_json,
                   review.id AS review_id,
                   old.id AS old_id, old.version_sha256 AS old_version_sha256,
                   old.stable_identifier AS old_stable_identifier,
                   old.as_of_date AS old_as_of_date,
                   old.canonical_url AS old_canonical_url,
                   old.currentness_status AS old_currentness_status,
                   old.licence_name AS old_licence_name,
                   old.licence_url AS old_licence_url,
                   old.metadata_json AS old_metadata_json,
                   (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=current.id)
                     AS chunk_count,
                   (SELECT group_concat(c.markdown_text, ' ') FROM chunks c
                    WHERE c.source_version_id=current.id) AS local_text
            FROM source_versions current
            JOIN documents d ON d.id=current.document_id
            JOIN reviews review ON review.review_type='source_version'
              AND review.target_id=current.id AND review.status='pending'
            JOIN source_versions old ON old.id=(
              SELECT candidate.id FROM source_versions candidate
              WHERE candidate.document_id=current.document_id
                AND candidate.version_sha256=current.version_sha256
                AND candidate.review_status='approved'
                AND candidate.id<>current.id
              ORDER BY candidate.created_at DESC, candidate.id DESC LIMIT 1
            )
            WHERE current.superseded_by IS NULL AND current.review_status='staged'
            ORDER BY current.id
            """
        )
        ready: list[tuple[Any, dict[str, Any]]] = []
        holds: Counter[str] = Counter()
        for row in rows:
            reasons: list[str] = []
            current_metadata = json.loads(row["current_metadata_json"] or "{}")
            old_metadata = json.loads(row["old_metadata_json"] or "{}")
            reviewed_type = str(old_metadata.get("material_type") or "").casefold()
            candidate_type = str(current_metadata.get("material_type_candidate") or "").casefold()
            allowed = ALLOWED_TYPES.get(str(row["lane"]), set())
            if row["current_version_sha256"] != row["old_version_sha256"]:
                reasons.append("source_bytes_changed")
            if reviewed_type not in allowed:
                reasons.append("reviewed_type_incompatible_with_current_lane")
            if (
                current_metadata.get("classification_confidence") == "high"
                and reviewed_type != candidate_type
            ):
                reasons.append("high_confidence_material_type_changed")
            if row["status"] not in {
                "citable",
                "private_teaching",
                "assessment_guidance",
                "duplicate",
            }:
                reasons.append("current_source_not_searchable")
            if int(row["chunk_count"]) < 1:
                reasons.append("no_current_chunks")
            local_text = str(row["local_text"] or "")
            if "/Users/" in local_text or prompt_injection_hits(local_text):
                reasons.append("unsafe_current_retrieval_text")
            if reasons:
                holds.update(reasons)
                continue
            ready.append((row, old_metadata))

        if args.apply:
            for row, metadata in ready:
                changed = database.decide_review(
                    str(row["review_id"]),
                    "approved",
                    f"{POLICY}: unchanged source bytes and compatible reviewed lane/type",
                    _approval(row, metadata),
                )
                if not changed:
                    raise RuntimeError("current source review changed during carry-forward")
        print(
            json.dumps(
                {
                    "apply": args.apply,
                    "approved_or_ready": len(ready),
                    "holds": sum(holds.values()),
                    "hold_reasons": dict(sorted(holds.items())),
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
