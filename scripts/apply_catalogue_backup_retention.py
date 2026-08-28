#!/usr/bin/env python3
"""Verify old catalogue backups and move policy-expired copies to recoverable Trash."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKUP_ROOT = PROJECT_ROOT / "data/backups"
POLICY_PATH = PROJECT_ROOT / "config/catalogue_backup_retention.v1.json"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,159}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _timestamp(value: object) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _private_write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


@dataclass(frozen=True, slots=True)
class BackupRecord:
    name: str
    finished_at: datetime
    backup_sha256: str
    size: int
    receipt_name: str
    receipt_sha256: str
    restore_drill_passed: bool


def _record(directory: Path) -> BackupRecord:
    if (
        not directory.is_dir()
        or directory.is_symlink()
        or _SAFE_NAME.fullmatch(directory.name) is None
    ):
        raise RuntimeError("backup directory identity is unsafe")
    backup = directory / "catalog.sqlite3"
    if not backup.is_file() or backup.is_symlink():
        raise RuntimeError("backup payload is missing or unsafe")
    receipt = directory / "BACKUP-RESTORE-RECEIPT.json"
    if not receipt.is_file():
        receipt = directory / "backup-receipt.json"
    value = json.loads(receipt.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("authorizing") is not False:
        raise RuntimeError("backup receipt is invalid")
    backup_value = value.get("backup")
    if not isinstance(backup_value, dict):
        raise RuntimeError("backup receipt has no payload binding")
    expected_sha256 = str(backup_value.get("sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise RuntimeError("backup receipt digest is invalid")
    metadata = backup.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise RuntimeError("backup payload is not one private owner file")
    observed_sha256 = _sha256(backup)
    if observed_sha256 != expected_sha256:
        raise RuntimeError("backup payload digest differs from its receipt")
    status = str(value.get("status") or "")
    return BackupRecord(
        name=directory.name,
        finished_at=_timestamp(value["finished_at"]),
        backup_sha256=observed_sha256,
        size=metadata.st_size,
        receipt_name=receipt.name,
        receipt_sha256=_sha256(receipt),
        restore_drill_passed=status
        in {
            "BACKUP_AND_RESTORE_DRILL_PASSED",
            "BACKUP_RECOVERED_AND_RESTORE_DRILL_PASSED",
        },
    )


def _load_policy() -> dict[str, Any]:
    value = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != "legalbot.catalogue-backup-retention-policy.v1"
        or value.get("authorizing") is not False
        or value.get("automatic_deletion_allowed") is not False
        or value.get("recoverable_trash_required") is not True
    ):
        raise RuntimeError("catalogue backup retention policy is invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-out", type=Path, required=True)
    parser.add_argument("--trash-root", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    policy = _load_policy()
    output = args.evidence_out.absolute()
    if output.exists() or output.parent.resolve(strict=True) != (
        PROJECT_ROOT / "data/evaluations/operations"
    ).resolve(strict=True):
        raise ValueError("evidence output must be one new operations directory")
    trash_root = args.trash_root.resolve(strict=True)
    trash_metadata = trash_root.stat(follow_symlinks=False)
    if (
        trash_root.name != ".Trash"
        or trash_root.is_symlink()
        or not trash_root.is_dir()
        or trash_metadata.st_uid != os.getuid()
    ):
        raise ValueError("trash root is not the current owner's macOS Trash")
    records = sorted(
        (_record(path) for path in BACKUP_ROOT.iterdir() if path.is_dir()),
        key=lambda item: (item.finished_at, item.name),
        reverse=True,
    )
    retain_count = int(policy["retain_newest_full_backups"])
    minimum = int(policy["minimum_full_backups_after_prune"])
    if len(records) < minimum or retain_count < minimum:
        raise RuntimeError("retention policy would keep too few backups")
    retained = records[:retain_count]
    expired = records[retain_count:]
    if not retained[0].restore_drill_passed:
        raise RuntimeError("newest backup has no successful restore drill")
    plan: dict[str, Any] = {
        "schema": "legalbot.catalogue-backup-prune-plan.v1",
        "authorizing": False,
        "automatic_deletion": False,
        "execution_requested": bool(args.execute),
        "policy_sha256": _sha256(POLICY_PATH),
        "retained": [
            {
                "name": item.name,
                "finished_at": item.finished_at.isoformat(),
                "backup_sha256": item.backup_sha256,
                "size": item.size,
                "receipt_name": item.receipt_name,
                "receipt_sha256": item.receipt_sha256,
                "restore_drill_passed": item.restore_drill_passed,
            }
            for item in retained
        ],
        "expired": [
            {
                "name": item.name,
                "finished_at": item.finished_at.isoformat(),
                "backup_sha256": item.backup_sha256,
                "size": item.size,
                "receipt_name": item.receipt_name,
                "receipt_sha256": item.receipt_sha256,
                "reason_code": "older_than_two_verified_full_backups",
            }
            for item in expired
        ],
        "expired_count": len(expired),
        "recoverable_bytes": sum(item.size for item in expired),
    }
    plan["plan_content_sha256"] = hashlib.sha256(_canonical(plan)).hexdigest()
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    plan_path = output / "PRUNE-PLAN.json"
    _private_write(plan_path, json.dumps(plan, indent=2, sort_keys=True).encode() + b"\n")
    if not args.execute:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    trash_directory = Path(
        tempfile.mkdtemp(prefix="LegalBot-catalogue-backups-20260828-", dir=trash_root)
    )
    trash_directory.chmod(0o700)
    moved: list[str] = []
    try:
        for item in expired:
            source = BACKUP_ROOT / item.name
            destination = trash_directory / item.name
            if destination.exists():
                raise RuntimeError("trash destination collision")
            os.replace(source, destination)
            moved.append(item.name)
    except Exception:
        failure = {
            "schema": "legalbot.catalogue-backup-prune-failure.v1",
            "authorizing": False,
            "moved_before_stop": moved,
            "trash_directory_name": trash_directory.name,
        }
        _private_write(
            output / "FAILURE.json",
            json.dumps(failure, indent=2, sort_keys=True).encode() + b"\n",
        )
        raise
    result = {
        "schema": "legalbot.catalogue-backup-prune-result.v1",
        "authorizing": False,
        "status": "MOVED_TO_RECOVERABLE_TRASH",
        "plan_content_sha256": plan["plan_content_sha256"],
        "moved_names": moved,
        "moved_count": len(moved),
        "moved_bytes": sum(item.size for item in expired),
        "retained_names": [item.name for item in retained],
        "trash_directory_name": trash_directory.name,
        "recoverable_until_trash_is_emptied": True,
        "permanent_deletion_performed": False,
        "catalogue_mutated": False,
        "active_or_previous_written": False,
    }
    result["result_content_sha256"] = hashlib.sha256(_canonical(result)).hexdigest()
    result_path = output / "PRUNE-RESULT.json"
    _private_write(result_path, json.dumps(result, indent=2, sort_keys=True).encode() + b"\n")
    sums = (
        f"{_sha256(plan_path)}  {plan_path.name}\n"
        f"{_sha256(result_path)}  {result_path.name}\n"
    ).encode()
    _private_write(output / "SHA256SUMS.txt", sums)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
