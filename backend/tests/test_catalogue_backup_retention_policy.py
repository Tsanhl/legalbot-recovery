from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_backup_retention_is_recoverable_and_keeps_two() -> None:
    policy = json.loads(
        (ROOT / "config/catalogue_backup_retention.v1.json").read_text(encoding="utf-8")
    )
    assert policy["automatic_deletion_allowed"] is False
    assert policy["minimum_full_backups_after_prune"] >= 2
    assert policy["retain_newest_full_backups"] >= 2
    assert policy["require_newest_restore_drill_passed"] is True
    assert policy["recoverable_trash_required"] is True


def test_retention_script_never_permanently_deletes() -> None:
    source = (ROOT / "scripts/apply_catalogue_backup_retention.py").read_text(encoding="utf-8")
    assert "shutil.rmtree" not in source
    assert "unlink(" not in source
    assert '"permanent_deletion_performed": False' in source
