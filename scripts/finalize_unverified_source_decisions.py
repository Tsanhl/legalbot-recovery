#!/usr/bin/env python3
"""Fail closed on canonical source records left unverified after evidence checks.

This utility never approves a source.  It is intended to run only after the
official legislation, official case-identity, Crossref, licensed collection
and high-confidence teaching verifiers.  Every remaining record is retained
immutably but rejected from the promotable retrieval corpus with a typed,
encrypted reason.
"""

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

POLICY = "legalbot.fail-closed-unverified-source-finalisation.v1"


def _reason(lane: str, status: str, retrieval_canonical: int) -> tuple[str, str]:
    if status == "duplicate" or not retrieval_canonical:
        return (
            "noncanonical_representation",
            "Duplicate or noncanonical representation; only the elected canonical may be reviewed",
        )
    if lane == "private_teaching":
        return (
            "ambiguous_private_teaching",
            "Reusable private-teaching identity was not established by the high-confidence verifier",
        )
    if lane == "primary_authority":
        return (
            "unverified_primary_authority",
            "Authority identity, jurisdiction, currentness, rights or citation metadata remains unverified",
        )
    if lane == "official_secondary":
        return (
            "unverified_official_secondary",
            "Official identity, edition/currentness, rights or citation metadata remains unverified",
        )
    if lane == "scholarship":
        return (
            "unverified_scholarship",
            "Bibliographic identity, jurisdiction, rights or citation metadata remains unverified",
        )
    return (
        "ineligible_lane",
        "Record is not eligible for a promotable legal or isolated private-teaching lane",
    )


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
            raise SystemExit("source scan is active; finalisation requires a frozen catalogue")
        rows = database.fetchall(
            """
            SELECT sv.id AS source_version_id,d.lane,d.status,d.retrieval_canonical,
                   r.id AS review_id,r.status AS review_status
            FROM source_versions sv
            JOIN documents d ON d.id=sv.document_id
            LEFT JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
            WHERE sv.superseded_by IS NULL AND sv.review_status='staged'
            ORDER BY sv.id
            """
        )
        counts: Counter[str] = Counter()
        decisions: list[tuple[str, str, str | None, str]] = []
        for row in rows:
            code, reason = _reason(
                str(row["lane"] or ""),
                str(row["status"] or ""),
                int(row["retrieval_canonical"] or 0),
            )
            counts[code] += 1
            decisions.append(
                (
                    str(row["source_version_id"]),
                    code,
                    str(row["review_id"]) if row["review_id"] else None,
                    reason,
                )
            )
        if args.apply and decisions:
            cipher = LocalCipher.from_local_key(create=False)
            encrypted_notes = {
                code: cipher.encrypt_text(f"{POLICY}: {reason}") for _, code, _, reason in decisions
            }
            now = utc_iso()
            with database.transaction() as connection:
                connection.executemany(
                    "UPDATE source_versions SET review_status='rejected' WHERE id=? AND review_status='staged'",
                    [(source_version_id,) for source_version_id, _, _, _ in decisions],
                )
                connection.executemany(
                    """
                    UPDATE reviews SET status='rejected',decision_note='[encrypted]',
                      encrypted_decision_note=?,decided_at=?
                    WHERE id=? AND status='pending'
                    """,
                    [
                        (encrypted_notes[code], now, review_id)
                        for _, code, review_id, _ in decisions
                        if review_id is not None
                    ],
                )
        report = {
            "schema": "legalbot.unverified-source-finalisation-report.v1",
            "policy": POLICY,
            "apply": args.apply,
            "rejected_or_ready": len(decisions),
            "by_reason": dict(sorted(counts.items())),
            "remaining_staged_after_apply": (
                int(
                    database.fetchone(
                        "SELECT COUNT(*) AS n FROM source_versions WHERE superseded_by IS NULL AND review_status='staged'"
                    )["n"]
                )
                if args.apply
                else None
            ),
        }
        if args.apply:
            destination = settings.data_dir / "review_queue" / "unverified-sources-finalized.json"
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
