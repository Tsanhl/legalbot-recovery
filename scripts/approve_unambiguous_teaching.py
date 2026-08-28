#!/usr/bin/env python3
"""Apply the owner's collection-level approval to unambiguous teaching sources."""

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
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

POLICY = "legalbot.owner-unambiguous-private-teaching.v1"
ALLOWED_TYPES = {"lecture", "tutorial", "seminar", "course_note"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    return parser


def main() -> None:
    args = _parser().parse_args()
    database = Database(Settings().database_path)
    database.initialize()
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ):
            raise SystemExit("source scan is active; approval requires a frozen catalogue")
        rows = database.fetchall(
            """
            SELECT sv.id,sv.version_sha256,sv.metadata_json,r.id AS review_id,
                   (SELECT group_concat(c.markdown_text,' ') FROM chunks c
                    WHERE c.source_version_id=sv.id) AS local_text,
                   (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) AS chunk_count
            FROM source_versions sv
            JOIN documents d ON d.id=sv.document_id
            JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
                           AND r.status='pending'
            WHERE sv.superseded_by IS NULL AND sv.review_status='staged'
              AND d.lane='private_teaching' AND d.status='private_teaching'
            ORDER BY sv.id
            """
        )
        ready: list[tuple[Any, dict[str, object]]] = []
        holds: Counter[str] = Counter()
        for row in rows:
            metadata = json.loads(row["metadata_json"] or "{}")
            material_type = str(metadata.get("material_type_candidate") or "")
            reasons: list[str] = []
            if metadata.get("classification_confidence") != "high":
                reasons.append("classification_not_high_confidence")
            if material_type not in ALLOWED_TYPES:
                reasons.append("unsupported_teaching_type")
            if metadata.get("ai_use_policy") == "prohibited":
                reasons.append("ai_use_prohibited")
            if metadata.get("eligible_for_model_use") is False:
                reasons.append("not_eligible_for_model_use")
            if int(row["chunk_count"]) < 1:
                reasons.append("no_chunks")
            if prompt_injection_hits(str(row["local_text"] or "")):
                reasons.append("document_safety_pattern")
            if reasons:
                holds.update(reasons)
                continue
            digest = str(row["version_sha256"])
            ready.append(
                (
                    row,
                    {
                        "identity_verified": True,
                        "currentness_verified": False,
                        "stable_identifier": f"content-sha256:{digest}",
                        "identity_title": f"Private teaching source {digest[:12]}",
                        "currentness_status": "not_applicable",
                        "material_type": material_type,
                        "citation_data": {},
                    },
                )
            )
        if args.apply:
            cipher = LocalCipher.from_local_key(create=False)
            encrypted_note = cipher.encrypt_text(
                f"{POLICY}: owner authorised unambiguous private teaching for isolated issue spotting"
            )
            for row, approval in ready:
                if not database.decide_review(
                    str(row["review_id"]),
                    "approved",
                    None,
                    approval,
                    encrypted_note=encrypted_note,
                ):
                    raise RuntimeError("teaching review changed during collection approval")
        print(
            json.dumps(
                {
                    "schema": "legalbot.unambiguous-teaching-approval.v1",
                    "policy": POLICY,
                    "apply": args.apply,
                    "approved_or_ready": len(ready),
                    "held": sum(holds.values()),
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
