"""Descriptor-pinned access to an exact v1.11 owner-private root."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .v111_decision_generation import private_root_identity


def _filesystem_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_uid, value.st_mode


def open_exact_private_root_descriptor(
    root: Path,
    *,
    project_root: Path,
    expected_identity_sha256: str | None = None,
) -> tuple[int, str]:
    """Open one exact root and keep its filesystem instance descriptor-pinned.

    Callers must close the returned descriptor.  The before/after identity and
    path checks prevent a pathname swap from redirecting a later child access.
    """

    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure owner private root access is unavailable")
    identity_before = private_root_identity(root, project_root=project_root)
    descriptor = os.open(root, os.O_RDONLY | directory_flag | no_follow)
    try:
        metadata = os.fstat(descriptor)
        path_before = os.stat(root, follow_symlinks=False)
        identity_after = private_root_identity(root, project_root=project_root)
        path_after = os.stat(root, follow_symlinks=False)
        filesystem_identity = _filesystem_identity(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or filesystem_identity != _filesystem_identity(path_before)
            or filesystem_identity != _filesystem_identity(path_after)
            or identity_before != identity_after
            or (expected_identity_sha256 is not None and identity_after != expected_identity_sha256)
        ):
            raise RuntimeError("owner private root differs from its exact binding")
        return descriptor, identity_after
    except BaseException:
        os.close(descriptor)
        raise


def require_exact_private_root_descriptor_current(
    descriptor: int,
    *,
    root: Path,
    project_root: Path,
    expected_identity_sha256: str,
) -> None:
    """Require an open descriptor to remain the exact currently named root."""

    try:
        held_identity = _filesystem_identity(os.fstat(descriptor))
    except OSError as exc:
        raise RuntimeError("owner private root descriptor is unavailable") from exc
    current_descriptor, current_identity = open_exact_private_root_descriptor(
        root,
        project_root=project_root,
        expected_identity_sha256=expected_identity_sha256,
    )
    try:
        if (
            current_identity != expected_identity_sha256
            or _filesystem_identity(os.fstat(current_descriptor)) != held_identity
        ):
            raise RuntimeError("owner private root changed during exact access")
    finally:
        os.close(current_descriptor)


__all__ = [
    "open_exact_private_root_descriptor",
    "require_exact_private_root_descriptor_current",
]
