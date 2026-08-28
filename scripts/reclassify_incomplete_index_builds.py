#!/usr/bin/env python3
"""Reclassify builds called candidates before the promotion contract existed."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.observability.events import EventStore  # noqa: E402


def main() -> None:
    settings = Settings()
    database = Database(settings.database_path)
    database.initialize()
    events = EventStore.from_settings(settings, database)
    changed: list[str] = []
    for row in database.fetchall("SELECT id FROM index_builds WHERE status='candidate'"):
        build_id = str(row["id"])
        build = settings.index_dir / "builds" / build_id
        benchmark_files = (
            build / "retrieval-benchmark.json",
            build / "retrieval-benchmark-report.json",
        )
        if all(path.is_file() for path in benchmark_files):
            continue
        database.execute(
            """
            UPDATE index_builds
            SET status='built_unscored', stage='built_unscored',
                promotion_decision='blocked_missing_owner_frozen_benchmark'
            WHERE id=? AND status='candidate'
            """,
            (build_id,),
        )
        events.emit(
            event_type="policy_decision",
            component="index_build",
            stage="candidate_audit",
            failure_code="candidate_missing_benchmark_reclassified",
            source_id=build_id,
            build_id=build_id,
            user_or_owner_safe=(
                "A sealed diagnostic build was reclassified as built-unscored; "
                "ACTIVE.json was not touched."
            ),
            retryable=False,
            blocking=True,
            open_ledger=False,
        )
        changed.append(build_id)
    database.close()
    print(f"reclassified={len(changed)}")


if __name__ == "__main__":
    main()
