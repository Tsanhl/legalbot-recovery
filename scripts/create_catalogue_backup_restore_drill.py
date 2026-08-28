#!/usr/bin/env python3
"""Create a non-authorizing catalogue backup and prove that it can be restored."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_BACKUP_ROOT = PROJECT_ROOT / "data/backups"
RECEIPT_SCHEMA = "legalbot.catalogue-backup-restore-receipt.v1"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(PROJECT_ROOT):
        raise ValueError("receipt path escaped the project")
    return resolved.relative_to(PROJECT_ROOT).as_posix()


def _sidecars(catalogue: Path) -> list[str]:
    return [
        suffix
        for suffix in ("-wal", "-shm", "-journal")
        if Path(f"{catalogue}{suffix}").exists()
    ]


def _open_processes(catalogue: Path) -> tuple[int, ...]:
    lsof = shutil.which("lsof")
    if lsof is None:
        raise RuntimeError("lsof is required for the no-open-process precondition")
    result = subprocess.run(
        [lsof, "-t", "--", str(catalogue)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError("catalogue process inspection failed")
    try:
        return tuple(sorted({int(item) for item in result.stdout.split()}))
    except ValueError as exc:
        raise RuntimeError("catalogue process inspection returned an invalid PID") from exc


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _count(connection: sqlite3.Connection, sql: str) -> int:
    row = connection.execute(sql).fetchone()
    if row is None:
        raise RuntimeError("catalogue count query returned no row")
    return int(row[0])


def _writer_state(connection: sqlite3.Connection) -> dict[str, int]:
    checks = {
        "active_jobs": (
            "jobs",
            "SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')",
        ),
        "active_builds": (
            "index_builds",
            "SELECT COUNT(*) FROM index_builds WHERE status='active'",
        ),
        "active_scans": (
            "source_scans",
            "SELECT COUNT(*) FROM source_scans WHERE status='running'",
        ),
    }
    return {
        label: _count(connection, sql) if _table_exists(connection, table) else 0
        for label, (table, sql) in checks.items()
    }


def _logical_state(connection: sqlite3.Connection) -> dict[str, Any]:
    tables = (
        "documents",
        "source_versions",
        "chunks",
        "index_builds",
        "jobs",
        "retrieval_attestation_history",
        "retrieval_attestation_selections",
        "conversation_sessions",
        "conversation_messages",
    )
    counts = {
        table: _count(connection, f'SELECT COUNT(*) FROM "{table}"')
        for table in tables
        if _table_exists(connection, table)
    }
    pragmas = {}
    for name in ("application_id", "page_size", "user_version"):
        row = connection.execute(f"PRAGMA {name}").fetchone()
        pragmas[name] = int(row[0]) if row is not None else None
    schema_rows = tuple(
        tuple("" if value is None else str(value) for value in row)
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name, tbl_name, sql
            """
        )
    )
    state: dict[str, Any] = {
        "counts": counts,
        "pragmas": pragmas,
        "schema_sha256": hashlib.sha256(_canonical_json(schema_rows)).hexdigest(),
    }
    state["content_sha256"] = hashlib.sha256(_canonical_json(state)).hexdigest()
    return state


def _integrity(connection: sqlite3.Connection) -> tuple[str, int]:
    rows = tuple(str(row[0]) for row in connection.execute("PRAGMA integrity_check"))
    if rows != ("ok",):
        raise RuntimeError("restored catalogue integrity_check failed")
    foreign_keys = tuple(connection.execute("PRAGMA foreign_key_check"))
    if foreign_keys:
        raise RuntimeError("restored catalogue foreign_key_check failed")
    return rows[0], len(foreign_keys)


def _create_sqlite_backup(source: sqlite3.Connection, destination: Path) -> None:
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    target = sqlite3.connect(destination)
    try:
        source.backup(target, pages=4096)
        target.commit()
    finally:
        target.close()
    destination.chmod(0o600)


def _git_state() -> dict[str, Any]:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    porcelain = git("status", "--porcelain=v1")
    return {
        "branch": git("branch", "--show-current"),
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "dirty": bool(porcelain),
        "dirty_entry_count": len(porcelain.splitlines()),
    }


def _write_private_create_only(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def create_backup_and_restore_drill(catalogue: Path, output: Path) -> dict[str, Any]:
    catalogue = catalogue.resolve(strict=True)
    if catalogue.is_symlink() or not catalogue.is_file():
        raise ValueError("catalogue must be one existing regular file")
    output = output.absolute()
    backup_root = DEFAULT_BACKUP_ROOT.resolve(strict=True)
    if output.parent.resolve(strict=True) != backup_root or output.exists():
        raise ValueError("output must be one new direct child of data/backups")
    sidecars_before = _sidecars(catalogue)
    open_processes = _open_processes(catalogue)
    if sidecars_before or open_processes:
        raise RuntimeError("backup requires no SQLite sidecars and no open process")

    started_at = _utc_now()
    source_sha256_before = _sha256(catalogue)
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    backup_path = output / "catalog.sqlite3"
    restore_path = output / ".restore-drill.sqlite3"
    source = sqlite3.connect(f"file:{catalogue}?mode=ro&immutable=1", uri=True)
    try:
        source.execute("PRAGMA query_only=ON")
        writer_state = _writer_state(source)
        if any(writer_state.values()):
            raise RuntimeError("catalogue has active writer work")
        source_state = _logical_state(source)
        _create_sqlite_backup(source, backup_path)
    finally:
        source.close()

    source_sha256_after = _sha256(catalogue)
    if source_sha256_before != source_sha256_after:
        raise RuntimeError("catalogue bytes changed during backup")
    if _sidecars(catalogue):
        raise RuntimeError("SQLite sidecar appeared during backup")

    backup = sqlite3.connect(f"file:{backup_path}?mode=ro&immutable=1", uri=True)
    try:
        backup.execute("PRAGMA query_only=ON")
        backup_state = _logical_state(backup)
        _create_sqlite_backup(backup, restore_path)
    finally:
        backup.close()
    if source_state != backup_state:
        raise RuntimeError("backup logical state differs from source snapshot")

    restored = sqlite3.connect(f"file:{restore_path}?mode=ro&immutable=1", uri=True)
    try:
        restored.execute("PRAGMA query_only=ON")
        integrity, foreign_key_violations = _integrity(restored)
        restored_state = _logical_state(restored)
    finally:
        restored.close()
    if restored_state != backup_state:
        raise RuntimeError("restored catalogue logical state differs from backup")
    restored_sha256 = _sha256(restore_path)
    restore_size = restore_path.stat().st_size
    restore_path.unlink()

    backup_metadata = backup_path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(backup_metadata.st_mode)
        or stat.S_IMODE(backup_metadata.st_mode) != 0o600
        or backup_metadata.st_uid != os.getuid()
        or backup_metadata.st_nlink != 1
    ):
        raise RuntimeError("backup is not one private owner file")

    finished_at = _utc_now()
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "authorizing": False,
        "status": "BACKUP_AND_RESTORE_DRILL_PASSED",
        "started_at": started_at,
        "finished_at": finished_at,
        "git": _git_state(),
        "preconditions": {
            "open_process_count": len(open_processes),
            "sqlite_sidecars": sidecars_before,
            **writer_state,
        },
        "source": {
            "relative_path": _relative(catalogue),
            "sha256_before": source_sha256_before,
            "sha256_after": source_sha256_after,
            "size": catalogue.stat().st_size,
            "logical_state": source_state,
        },
        "backup": {
            "relative_path": _relative(backup_path),
            "sha256": _sha256(backup_path),
            "size": backup_metadata.st_size,
            "mode": oct(stat.S_IMODE(backup_metadata.st_mode)),
            "method": "sqlite_online_backup_api",
        },
        "restore_drill": {
            "executed": True,
            "isolated_restore_file_retained": False,
            "restored_sha256": restored_sha256,
            "restored_size": restore_size,
            "integrity_check": integrity,
            "foreign_key_violation_count": foreign_key_violations,
            "logical_state": restored_state,
        },
        "release_effect": {
            "catalogue_mutated": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "promotion_authorized": False,
            "live_authorized": False,
        },
    }
    receipt["receipt_content_sha256"] = hashlib.sha256(_canonical_json(receipt)).hexdigest()
    receipt_path = output / "BACKUP-RESTORE-RECEIPT.json"
    _write_private_create_only(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n")
    sums = (
        f"{_sha256(receipt_path)}  {receipt_path.name}\n"
        f"{receipt['backup']['sha256']}  {backup_path.name}\n"
    ).encode()
    _write_private_create_only(output / "SHA256SUMS.txt", sums)
    return receipt


def finalize_existing_backup(catalogue: Path, output: Path) -> dict[str, Any]:
    """Resume the one preserved backup without performing another source copy."""

    catalogue = catalogue.resolve(strict=True)
    output = output.resolve(strict=True)
    if output.parent != DEFAULT_BACKUP_ROOT.resolve(strict=True):
        raise ValueError("output must be one direct child of data/backups")
    backup_path = output / "catalog.sqlite3"
    receipt_path = output / "BACKUP-RESTORE-RECEIPT.json"
    restore_path = output / ".restore-drill.sqlite3"
    if (
        not backup_path.is_file()
        or backup_path.is_symlink()
        or receipt_path.exists()
        or restore_path.exists()
    ):
        raise ValueError("existing backup is not resumable")
    sidecars = _sidecars(catalogue)
    open_processes = _open_processes(catalogue)
    if sidecars or open_processes:
        raise RuntimeError("finalization requires no SQLite sidecars and no open process")

    started_at = _utc_now()
    source = sqlite3.connect(f"file:{catalogue}?mode=ro&immutable=1", uri=True)
    backup = sqlite3.connect(f"file:{backup_path}?mode=ro&immutable=1", uri=True)
    try:
        source.execute("PRAGMA query_only=ON")
        backup.execute("PRAGMA query_only=ON")
        writer_state = _writer_state(source)
        if any(writer_state.values()):
            raise RuntimeError("catalogue has active writer work")
        source_state = _logical_state(source)
        backup_state = _logical_state(backup)
        if source_state != backup_state:
            raise RuntimeError("preserved backup no longer matches the catalogue logical state")
        _create_sqlite_backup(backup, restore_path)
    finally:
        backup.close()
        source.close()

    restored = sqlite3.connect(f"file:{restore_path}?mode=ro&immutable=1", uri=True)
    try:
        restored.execute("PRAGMA query_only=ON")
        integrity, foreign_key_violations = _integrity(restored)
        restored_state = _logical_state(restored)
    finally:
        restored.close()
    if restored_state != backup_state:
        raise RuntimeError("restored catalogue logical state differs from preserved backup")

    source_sha256 = _sha256(catalogue)
    backup_sha256 = _sha256(backup_path)
    restored_sha256 = _sha256(restore_path)
    restored_size = restore_path.stat().st_size
    restore_path.unlink()
    backup_metadata = backup_path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(backup_metadata.st_mode)
        or stat.S_IMODE(backup_metadata.st_mode) != 0o600
        or backup_metadata.st_uid != os.getuid()
        or backup_metadata.st_nlink != 1
    ):
        raise RuntimeError("backup is not one private owner file")

    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "authorizing": False,
        "status": "BACKUP_RECOVERED_AND_RESTORE_DRILL_PASSED",
        "started_at": started_at,
        "finished_at": _utc_now(),
        "git": _git_state(),
        "attempt_history": [
            {
                "attempt": 1,
                "status": "STOPPED_BEFORE_COPY",
                "reason_code": "ORPHAN_ZERO_WAL_AND_SHM_PRECONDITION",
                "backup_payload_created": False,
            },
            {
                "attempt": 2,
                "status": "COPY_PRESERVED_VERIFICATION_STOPPED",
                "reason_code": "READ_CONNECTION_RECREATED_EMPTY_WAL_AND_SHM",
                "backup_payload_created": True,
            },
            {
                "attempt": "resume-finalize",
                "status": "PASSED_WITHOUT_ANOTHER_SOURCE_COPY",
                "reason_code": None,
                "backup_payload_created": False,
            },
        ],
        "preconditions": {
            "open_process_count": len(open_processes),
            "sqlite_sidecars": sidecars,
            **writer_state,
        },
        "source": {
            "relative_path": _relative(catalogue),
            "sha256_at_finalize": source_sha256,
            "size": catalogue.stat().st_size,
            "logical_state": source_state,
        },
        "backup": {
            "relative_path": _relative(backup_path),
            "sha256": backup_sha256,
            "size": backup_metadata.st_size,
            "mode": oct(stat.S_IMODE(backup_metadata.st_mode)),
            "method": "preserved_sqlite_online_backup_from_attempt_2",
            "source_copy_repeated_during_finalize": False,
        },
        "restore_drill": {
            "executed": True,
            "isolated_restore_file_retained": False,
            "restored_sha256": restored_sha256,
            "restored_size": restored_size,
            "integrity_check": integrity,
            "foreign_key_violation_count": foreign_key_violations,
            "logical_state": restored_state,
        },
        "recovery_disclosure": {
            "continuous_source_sha256_before_and_after_available": False,
            "catalogue_and_backup_logical_state_equal_at_finalize": True,
            "third_source_copy_prohibited_by_repeated_failure_stop_policy": True,
        },
        "release_effect": {
            "catalogue_mutated": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
            "promotion_authorized": False,
            "live_authorized": False,
        },
    }
    receipt["receipt_content_sha256"] = hashlib.sha256(_canonical_json(receipt)).hexdigest()
    _write_private_create_only(
        receipt_path,
        json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n",
    )
    sums = (
        f"{_sha256(receipt_path)}  {receipt_path.name}\n"
        f"{backup_sha256}  {backup_path.name}\n"
    ).encode()
    _write_private_create_only(output / "SHA256SUMS.txt", sums)
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--finalize-existing",
        action="store_true",
        help="resume one preserved backup without another source copy",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.finalize_existing:
            receipt = finalize_existing_backup(args.catalogue, args.out)
        else:
            receipt = create_backup_and_restore_drill(args.catalogue, args.out)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "legalbot.catalogue-backup-restore-stop.v1",
                    "status": "STOPPED",
                    "reason_code": type(exc).__name__,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "schema": receipt["schema"],
                "status": receipt["status"],
                "receipt_content_sha256": receipt["receipt_content_sha256"],
                "backup_sha256": receipt["backup"]["sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
