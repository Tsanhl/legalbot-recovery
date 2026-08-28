#!/usr/bin/env python3
"""Remove duplicate/noncanonical representations from the actionable review queue."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database, utc_iso  # noqa: E402

POLICY = "legalbot.noncanonical-source-review-cleanup.v1"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    database = Database(settings.database_path)
    database.initialize()
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ):
            raise SystemExit("source scan is active; queue cleanup requires a frozen catalogue")
        rows = database.fetchall(
            """
            SELECT sv.id,d.lane,d.status,d.retrieval_canonical
            FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.superseded_by IS NULL AND sv.review_status='staged'
              AND (d.status='duplicate' OR d.retrieval_canonical=0)
            ORDER BY sv.id
            """
        )
        by_lane = Counter(str(row["lane"]) for row in rows)
        if args.apply and rows:
            cipher = LocalCipher.from_local_key(create=False)
            note = cipher.encrypt_text(
                f"{POLICY}: representation is duplicate or noncanonical; review the canonical source only"
            )
            now = utc_iso()
            ids = [str(row["id"]) for row in rows]
            with database.transaction() as connection:
                connection.executemany(
                    "UPDATE source_versions SET review_status='rejected' WHERE id=?",
                    [(value,) for value in ids],
                )
                connection.executemany(
                    """
                    UPDATE reviews SET status='rejected', decision_note='[encrypted]',
                      encrypted_decision_note=?, decided_at=?
                    WHERE review_type='source_version' AND target_id=? AND status='pending'
                    """,
                    [(note, now, value) for value in ids],
                )
        report = {
            "schema": "legalbot.noncanonical-source-review-cleanup.v1",
            "policy": POLICY,
            "apply": args.apply,
            "rejected_or_ready": len(rows),
            "by_lane": dict(sorted(by_lane.items())),
        }
        destination = settings.data_dir / "review_queue" / "noncanonical-sources-finalized.json"
        if args.apply:
            destination.write_text(
                json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            report["report"] = str(destination.relative_to(PROJECT_ROOT))
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        database.close()


if __name__ == "__main__":
    main()
