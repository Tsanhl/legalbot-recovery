from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.config import Settings
from app.observability.storage_capacity import build_storage_capacity_snapshot


def _policy(root: Path) -> None:
    target = root / "config/storage_capacity_policy.v1.json"
    target.parent.mkdir(parents=True)
    target.write_text(
        json.dumps(
            {
                "schema": "legalbot.storage-capacity-policy.v1",
                "authorizing": False,
                "automatic_deletion_allowed": False,
                "disk": {"warning_free_bytes": 1, "critical_free_bytes": 1},
                "backups": {
                    "warning_total_bytes": 100,
                    "critical_total_bytes": 200,
                    "warning_full_backup_count": 2,
                    "critical_full_backup_count": 3,
                    "warning_latest_age_seconds": 100,
                    "critical_latest_age_seconds": 200,
                    "warning_restore_drill_age_seconds": 100,
                    "critical_restore_drill_age_seconds": 200,
                },
            }
        )
    )


def test_missing_backup_and_restore_drill_are_critical(tmp_path: Path) -> None:
    _policy(tmp_path)
    (tmp_path / "data").mkdir()
    snapshot = build_storage_capacity_snapshot(
        Settings(project_root=tmp_path, test_mode=True),
        now=datetime(2026, 8, 28, tzinfo=UTC),
    )
    assert snapshot["status"] == "critical"
    assert "catalogue_backup_missing" in snapshot["critical_codes"]
    assert "restore_drill_missing" in snapshot["critical_codes"]
    assert snapshot["automatic_deletion_allowed"] is False
