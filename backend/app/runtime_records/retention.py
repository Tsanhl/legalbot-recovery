"""Retention cleanup for runtime records. Dry-run by default; never during Live60."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from ..db import Database
from ..deletion_guard import (
    DeletionAuthorization,
    DeletionBlockedError,
    DeletionGuard,
    DeletionObjectClass,
)

DEFAULT_RETENTION_PATH = Path("config/retention.yaml")


def load_retention_config(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("retention config must be a mapping")
    return payload


def cleanup_runtime_records(
    database: Database,
    config: Mapping[str, Any],
    *,
    dry_run: bool = True,
    live60_in_progress: bool = False,
    guard: DeletionGuard | None = None,
    authorization: DeletionAuthorization | None = None,
) -> dict[str, Any]:
    if live60_in_progress:
        return {
            "schema": "legalbot.runtime-retention-cleanup.v1",
            "ran": False,
            "dry_run": dry_run,
            "reason": "never_during_live60",
            "deleted": {},
        }
    tables = {
        "runtime_feedback": int(config.get("feedback_days") or 90),
        "runtime_incidents": int(config.get("incident_days") or 180),
        "runtime_curation": int(config.get("curation_days") or 365),
    }
    deleted: dict[str, int] = {}
    for table, days in tables.items():
        sql = (
            f"SELECT COUNT(*) FROM {table} WHERE created_at < datetime('now', ?)"
            if table != "runtime_curation"
            else "SELECT COUNT(*) FROM runtime_curation WHERE updated_at < datetime('now', ?)"
        )
        row = database.fetchone(sql, (f"-{days} day",))
        count = int(row[0]) if row is not None else 0
        deleted[table] = count
        if not dry_run and count and authorization is not None:
            date_column = "updated_at" if table == "runtime_curation" else "created_at"
            rows = database.fetchall(
                f"SELECT id FROM {table} WHERE {date_column} < datetime('now', ?)",
                (f"-{days} day",),
            )
            for row in rows:
                identifier = str(row["id"])
                try:
                    (guard or DeletionGuard()).require(
                        object_class=DeletionObjectClass.RUNTIME_RECORD,
                        object_id=identifier,
                        authorization=authorization,
                    )
                except DeletionBlockedError:
                    continue
                database.execute(f"DELETE FROM {table} WHERE id=?", (identifier,))
    if not dry_run:
        database._connection.commit()
    return {
        "schema": "legalbot.runtime-retention-cleanup.v1",
        "ran": not dry_run and authorization is not None,
        "dry_run": dry_run,
        "reason": None if dry_run or authorization is not None else "owner_authorization_missing",
        "deleted": deleted,
    }
