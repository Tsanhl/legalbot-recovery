"""Narrow immutable reader for request-generation catalogue evidence."""

from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast


def _private_regular(metadata: os.stat_result, *, label: str) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise RuntimeError(f"{label} must be one private owner file")


class ExistingCatalogueReadDatabase:
    """SQLite ``immutable=1`` view after an exact no-WAL path check."""

    def __init__(
        self,
        *,
        path: Path,
        connection: sqlite3.Connection,
        directory_descriptor: int,
        database_descriptor: int,
        lock_descriptor: int,
        directory_identity: tuple[int, int, int, int, int, int],
        database_identity: tuple[int, int, int, int, int, int, int],
    ) -> None:
        self.path = path
        self._connection = connection
        self._directory_descriptor = directory_descriptor
        self._database_descriptor = database_descriptor
        self._lock_descriptor = lock_descriptor
        self._directory_identity = directory_identity
        self._database_identity = database_identity
        self._lock = threading.RLock()

    def _require_current_identity(self) -> None:
        if self.path.parent.resolve(strict=True) != self.path.parent:
            raise RuntimeError("catalogue read ancestor became a symbolic link")
        directory = os.stat(self.path.parent, follow_symlinks=False)
        database = os.stat(self.path, follow_symlinks=False)
        pinned_database = os.fstat(self._database_descriptor)
        _private_regular(database, label="catalogue")
        _private_regular(pinned_database, label="pinned catalogue")
        if (
            (
                directory.st_dev,
                directory.st_ino,
                directory.st_uid,
                directory.st_mode,
                directory.st_mtime_ns,
                directory.st_ctime_ns,
            )
            != self._directory_identity
            or (
                database.st_dev,
                database.st_ino,
                database.st_uid,
                database.st_mode,
                database.st_size,
                database.st_mtime_ns,
                database.st_ctime_ns,
            )
            != self._database_identity
            or (
                pinned_database.st_dev,
                pinned_database.st_ino,
                pinned_database.st_uid,
                pinned_database.st_mode,
                pinned_database.st_size,
                pinned_database.st_mtime_ns,
                pinned_database.st_ctime_ns,
            )
            != self._database_identity
        ):
            raise RuntimeError("catalogue read path identity changed")
        for suffix in ("-wal", "-journal"):
            sidecar = Path(f"{self.path}{suffix}")
            try:
                sidecar_metadata = os.stat(sidecar, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(sidecar_metadata.st_mode) or sidecar_metadata.st_size != 0:
                raise RuntimeError("catalogue read requires a checkpointed database")

    def fetchone(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            self._require_current_identity()
            row = cast(sqlite3.Row | None, self._connection.execute(sql, params).fetchone())
            self._require_current_identity()
            return row

    def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            self._require_current_identity()
            rows = list(self._connection.execute(sql, params).fetchall())
            self._require_current_identity()
            return rows

    def total_changes(self) -> int:
        with self._lock:
            self._require_current_identity()
            value = int(self._connection.total_changes)
            self._require_current_identity()
            return value

    def backup(self, target: sqlite3.Connection) -> None:
        """Copy through the pinned handle with immediate before/after identity checks."""

        with self._lock:
            self._require_current_identity()
            self._connection.backup(target)
            self._require_current_identity()

    def close(self) -> None:
        try:
            with self._lock:
                self._connection.close()
        finally:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_descriptor)
                os.close(self._database_descriptor)
                os.close(self._directory_descriptor)


def open_existing_catalogue_read_database(
    path: Path,
    *,
    exclusive_lock: bool = False,
) -> ExistingCatalogueReadDatabase:
    """Open an existing, checkpointed catalogue without writable SQLite state.

    A successful re-attestation must be closed/checkpointed first: any non-empty
    WAL or rollback journal is rejected because SQLite ``immutable=1`` cannot
    safely incorporate concurrent or uncheckpointed sidecar state.
    """

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure existing-catalogue read is unavailable")
    absolute = path.absolute()
    if absolute.parent.resolve(strict=True) != absolute.parent:
        raise RuntimeError("catalogue read ancestors must not be symbolic links")
    directory_descriptor = os.open(
        absolute.parent,
        os.O_RDONLY | directory_flag | no_follow,
    )
    lock_descriptor = -1
    database_descriptor = -1
    connection: sqlite3.Connection | None = None
    try:
        lock_descriptor = os.open(
            ".catalog-initialize.lock",
            os.O_RDONLY | no_follow,
            dir_fd=directory_descriptor,
        )
        _private_regular(os.fstat(lock_descriptor), label="catalogue lock")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX if exclusive_lock else fcntl.LOCK_SH)
        directory = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid():
            raise RuntimeError("catalogue read directory identity is invalid")
        database_descriptor = os.open(
            absolute.name,
            os.O_RDONLY | no_follow,
            dir_fd=directory_descriptor,
        )
        database = os.fstat(database_descriptor)
        _private_regular(database, label="catalogue")
        lexical_database = os.stat(
            absolute.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            database.st_dev,
            database.st_ino,
            database.st_uid,
            database.st_mode,
            database.st_size,
            database.st_mtime_ns,
            database.st_ctime_ns,
        ) != (
            lexical_database.st_dev,
            lexical_database.st_ino,
            lexical_database.st_uid,
            lexical_database.st_mode,
            lexical_database.st_size,
            lexical_database.st_mtime_ns,
            lexical_database.st_ctime_ns,
        ):
            raise RuntimeError("catalogue read path identity changed")
        for suffix in ("-wal", "-journal"):
            sidecar_name = f"{absolute.name}{suffix}"
            try:
                sidecar = os.stat(
                    sidecar_name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(sidecar.st_mode) or sidecar.st_size != 0:
                raise RuntimeError("catalogue read requires a checkpointed database")
        directory_identity = (
            directory.st_dev,
            directory.st_ino,
            directory.st_uid,
            directory.st_mode,
            directory.st_mtime_ns,
            directory.st_ctime_ns,
        )
        database_identity = (
            database.st_dev,
            database.st_ino,
            database.st_uid,
            database.st_mode,
            database.st_size,
            database.st_mtime_ns,
            database.st_ctime_ns,
        )
        connection = sqlite3.connect(
            f"file:/dev/fd/{database_descriptor}?mode=ro&immutable=1",
            uri=True,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        reader = ExistingCatalogueReadDatabase(
            path=absolute,
            connection=connection,
            directory_descriptor=directory_descriptor,
            database_descriptor=database_descriptor,
            lock_descriptor=lock_descriptor,
            directory_identity=directory_identity,
            database_identity=database_identity,
        )
        reader._require_current_identity()
        return reader
    except Exception:
        if connection is not None:
            connection.close()
        if lock_descriptor >= 0:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
        if database_descriptor >= 0:
            os.close(database_descriptor)
        os.close(directory_descriptor)
        raise


__all__ = ["ExistingCatalogueReadDatabase", "open_existing_catalogue_read_database"]
