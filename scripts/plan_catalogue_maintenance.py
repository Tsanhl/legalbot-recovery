#!/usr/bin/env python3
"""Produce a read-only catalogue-maintenance preflight; never delete or compact."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.observability.storage_capacity import build_storage_capacity_snapshot  # noqa: E402


def _load_policy() -> dict[str, object]:
    value = json.loads(
        (PROJECT_ROOT / "config/catalogue_maintenance_policy.v1.json").read_text(
            encoding="utf-8"
        )
    )
    if not isinstance(value, dict) or value.get("schema") != "legalbot.catalogue-maintenance-policy.v1":
        raise ValueError("catalogue maintenance policy is invalid")
    return value


def _open_process_count(path: Path) -> int:
    lsof = shutil.which("lsof")
    if lsof is None:
        raise RuntimeError("lsof is required")
    result = subprocess.run(
        [lsof, "-t", "--", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError("catalogue process inspection failed")
    return len(set(result.stdout.split()))


def build_plan(settings: Settings, *, now: datetime | None = None) -> dict[str, object]:
    stamp = (now or datetime.now(UTC)).astimezone(UTC)
    policy = _load_policy()
    catalogue = settings.database_path.resolve(strict=True)
    connection = sqlite3.connect(f"file:{catalogue}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        active_jobs = int(
            connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')"
            ).fetchone()[0]
        )
        active_builds = int(
            connection.execute(
                "SELECT COUNT(*) FROM index_builds WHERE status='active'"
            ).fetchone()[0]
        )
        active_scans = int(
            connection.execute(
                "SELECT COUNT(*) FROM source_scans WHERE status='running'"
            ).fetchone()[0]
        )
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        freelist_count = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
    finally:
        connection.close()
    storage = build_storage_capacity_snapshot(settings, now=stamp)
    local = stamp.astimezone(ZoneInfo(str(policy["timezone"])))
    window = policy["weekly_window"]
    assert isinstance(window, dict)
    start_hour, start_minute = map(int, str(window["start_local"]).split(":"))
    end_hour, end_minute = map(int, str(window["end_local"]).split(":"))
    local_minutes = local.hour * 60 + local.minute
    within_window = (
        local.strftime("%A") == window["weekday"]
        and start_hour * 60 + start_minute <= local_minutes < end_hour * 60 + end_minute
    )
    restore_age = storage["backups"]["latest_restore_drill_age_seconds"]
    preconditions = policy["preconditions"]
    assert isinstance(preconditions, dict)
    checks = {
        "within_maintenance_window": within_window,
        "zero_open_catalogue_processes": _open_process_count(catalogue) == 0,
        "zero_active_jobs": active_jobs == 0,
        "zero_active_builds": active_builds == 0,
        "zero_active_scans": active_scans == 0,
        "recent_backup_restore_drill": (
            restore_age is not None
            and float(restore_age)
            <= int(preconditions["maximum_backup_restore_receipt_age_seconds"])
        ),
    }
    return {
        "schema": "legalbot.catalogue-maintenance-plan.v1",
        "generated_at": stamp.isoformat(),
        "authorizing": False,
        "observe_only": True,
        "execution_performed": False,
        "eligible_for_separately_approved_execution": all(checks.values()),
        "checks": checks,
        "catalogue": {
            "size_bytes": catalogue.stat().st_size,
            "page_count": page_count,
            "freelist_count": freelist_count,
            "freelist_ratio": round(freelist_count / max(1, page_count), 8),
            "chunk_classification_query_executed": False,
        },
        "policy": policy,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    plan = build_plan(Settings(project_root=PROJECT_ROOT))
    encoded = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        output = args.out.absolute()
        if output.exists() or not output.parent.is_dir():
            raise ValueError("maintenance plan output must be one new file")
        output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
