"""Privacy-safe disk and catalogue-backup capacity observations."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import Settings

POLICY_PATH = Path("config/storage_capacity_policy.v1.json")


def _utc(value: datetime | None) -> datetime:
    stamp = value or datetime.now(UTC)
    if stamp.tzinfo is None:
        raise ValueError("capacity snapshot time must be timezone-aware")
    return stamp.astimezone(UTC)


def _load_policy(settings: Settings) -> dict[str, Any]:
    path = settings.project_root / POLICY_PATH
    if not path.is_file():
        path = Path(__file__).resolve().parents[3] / POLICY_PATH
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != "legalbot.storage-capacity-policy.v1"
        or value.get("authorizing") is not False
        or value.get("automatic_deletion_allowed") is not False
    ):
        raise ValueError("storage-capacity policy is invalid")
    return value


def _parse_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _receipt_time(path: Path) -> tuple[datetime | None, bool]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, False
    if not isinstance(value, dict):
        return None, False
    status = str(value.get("status") or "")
    restore_passed = status in {
        "BACKUP_AND_RESTORE_DRILL_PASSED",
        "BACKUP_RECOVERED_AND_RESTORE_DRILL_PASSED",
    }
    return _parse_timestamp(value.get("finished_at")), restore_passed


def build_storage_capacity_snapshot(
    settings: Settings,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return counts, sizes, ages and reason codes without exposing local paths."""

    stamp = _utc(now)
    policy = _load_policy(settings)
    disk_root = settings.data_dir if settings.data_dir.is_dir() else settings.project_root
    disk = shutil.disk_usage(disk_root)
    backup_root = settings.data_dir / "backups"
    backup_files = (
        tuple(
            sorted(
                (
                    member / "catalog.sqlite3"
                    for member in backup_root.iterdir()
                    if member.is_dir() and not member.is_symlink()
                ),
                key=lambda item: item.parent.name,
            )
        )
        if backup_root.is_dir()
        else ()
    )
    backup_files = tuple(path for path in backup_files if path.is_file() and not path.is_symlink())
    total_backup_bytes = sum(path.stat().st_size for path in backup_files)
    receipt_times: list[datetime] = []
    restore_times: list[datetime] = []
    for directory in (path.parent for path in backup_files):
        for name in ("BACKUP-RESTORE-RECEIPT.json", "backup-receipt.json"):
            receipt = directory / name
            if not receipt.is_file() or receipt.is_symlink():
                continue
            receipt_time, restore_passed = _receipt_time(receipt)
            if receipt_time is not None:
                receipt_times.append(receipt_time)
                if restore_passed:
                    restore_times.append(receipt_time)
            break
    latest_age = max(0.0, (stamp - max(receipt_times)).total_seconds()) if receipt_times else None
    restore_age = max(0.0, (stamp - max(restore_times)).total_seconds()) if restore_times else None
    disk_policy = policy["disk"]
    backup_policy = policy["backups"]
    warnings: list[str] = []
    critical: list[str] = []
    if disk.free < int(disk_policy["critical_free_bytes"]):
        critical.append("disk_free_critical")
    elif disk.free < int(disk_policy["warning_free_bytes"]):
        warnings.append("disk_free_warning")
    if total_backup_bytes >= int(backup_policy["critical_total_bytes"]):
        critical.append("backup_bytes_critical")
    elif total_backup_bytes >= int(backup_policy["warning_total_bytes"]):
        warnings.append("backup_bytes_warning")
    if len(backup_files) >= int(backup_policy["critical_full_backup_count"]):
        critical.append("backup_count_critical")
    elif len(backup_files) >= int(backup_policy["warning_full_backup_count"]):
        warnings.append("backup_count_warning")
    if latest_age is None:
        critical.append("catalogue_backup_missing")
    elif latest_age >= int(backup_policy["critical_latest_age_seconds"]):
        critical.append("catalogue_backup_stale_critical")
    elif latest_age >= int(backup_policy["warning_latest_age_seconds"]):
        warnings.append("catalogue_backup_stale_warning")
    if restore_age is None:
        critical.append("restore_drill_missing")
    elif restore_age >= int(backup_policy["critical_restore_drill_age_seconds"]):
        critical.append("restore_drill_stale_critical")
    elif restore_age >= int(backup_policy["warning_restore_drill_age_seconds"]):
        warnings.append("restore_drill_stale_warning")
    return {
        "schema": "legalbot.storage-capacity-snapshot.v1",
        "generated_at": stamp.isoformat(),
        "authorizing": False,
        "automatic_deletion_allowed": False,
        "status": "critical" if critical else ("warning" if warnings else "ok"),
        "warning_codes": warnings,
        "critical_codes": critical,
        "disk": {
            "total_bytes": disk.total,
            "used_bytes": disk.used,
            "free_bytes": disk.free,
        },
        "backups": {
            "full_backup_count": len(backup_files),
            "total_bytes": total_backup_bytes,
            "latest_age_seconds": round(latest_age, 3) if latest_age is not None else None,
            "latest_restore_drill_age_seconds": (
                round(restore_age, 3) if restore_age is not None else None
            ),
        },
    }
