"""Metadata-only snapshot-current guard for owner-canary answer release.

The authoritative owner-canary replay performs content hashing and other
expensive checks before SQLite takes its ``IMMEDIATE`` release transaction.
This module detects ordinary replay-to-commit mutations with a much cheaper,
bounded check.  It binds the exact Git-tracked integration membership
and HEAD plus no-follow ``lstat`` identities for those inputs, the sealed
candidate tree, the fixed answer-model tree and the private review workspace.

This is deliberately a *snapshot-current* guarantee.  It is not a claim of a
filesystem-wide atomic snapshot: the final check performs no content reads or
hashing and the filesystem is not locked against a hostile writer after an
individual metadata observation.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import time
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from ..config import Settings


OWNER_CANARY_RELEASE_SNAPSHOT_RECHECK_BUDGET_SECONDS = 1.0

_TRUSTED_GIT = Path("/usr/bin/git")
_TRUSTED_GIT_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
}
_SAFE_BUILD_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

SnapshotScope = Literal[
    "tracked_integration",
    "candidate_build",
    "fixed_model",
    "private_review_workspace",
    "runtime_object",
    "active_pointer",
]
SnapshotKind = Literal["directory", "regular_file", "absent"]


@dataclass(frozen=True, slots=True, repr=False)
class OwnerCanaryReleaseSnapshotPlan:
    """Raw, in-memory roots used by the bounded release recheck."""

    project_root: Path
    candidate_build_root: Path
    fixed_model_root: Path
    private_review_workspace_root: Path
    runtime_object_root: Path
    active_pointer_path: Path | None = None
    runtime_object_relative_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RawPathLstatSnapshot:
    """One no-follow path identity with directory membership where relevant."""

    scope: SnapshotScope
    relative_path: str
    kind: SnapshotKind
    directory_entries: tuple[str, ...]
    device: int
    inode: int
    uid: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    content_sha256: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class OwnerCanaryReleaseFilesystemSnapshot:
    """Opaque-capability payload; never serialize or persist this object."""

    plan: OwnerCanaryReleaseSnapshotPlan
    integration_head_sha: str
    tracked_relative_paths: tuple[str, ...]
    entries: tuple[RawPathLstatSnapshot, ...]
    regular_file_count: int
    directory_count: int


@dataclass(frozen=True, slots=True)
class OwnerCanaryReleaseSnapshotRecheck:
    """Safe in-memory benchmark result for the final metadata recheck."""

    regular_file_count: int
    directory_count: int
    elapsed_seconds: float


def build_owner_canary_release_snapshot_plan(
    *,
    settings: Settings,
    private_review_root: Path,
    review_date: date,
    run_id: str,
    candidate_build_id: str,
) -> OwnerCanaryReleaseSnapshotPlan:
    """Build fixed raw roots without resolving or following filesystem links."""

    if not _SAFE_RUN_ID.fullmatch(run_id) or not _SAFE_BUILD_ID.fullmatch(candidate_build_id):
        raise RuntimeError("owner_canary_release_snapshot_identity_invalid")
    project_root = _absolute_raw_path(settings.project_root)
    private_root = _absolute_raw_path(private_review_root)
    if private_root == project_root or private_root.is_relative_to(project_root):
        raise RuntimeError("owner_canary_release_snapshot_private_root_invalid")
    return OwnerCanaryReleaseSnapshotPlan(
        project_root=project_root,
        candidate_build_root=(project_root / "data" / "indexes" / "builds" / candidate_build_id),
        fixed_model_root=project_root / "models" / "runtime" / "Qwen3.5-9B-4bit",
        private_review_workspace_root=private_root / review_date.isoformat() / run_id,
        runtime_object_root=_absolute_raw_path(settings.runtime_object_dir),
        active_pointer_path=project_root / "data" / "indexes" / "ACTIVE.json",
    )


def bind_owner_canary_release_runtime_objects(
    plan: OwnerCanaryReleaseSnapshotPlan,
    relative_paths: tuple[str, ...],
) -> OwnerCanaryReleaseSnapshotPlan:
    """Bind only DB-referenced encrypted object members into the snapshot."""

    if type(plan) is not OwnerCanaryReleaseSnapshotPlan:
        raise RuntimeError("owner_canary_release_snapshot_plan_invalid")
    paths = tuple(sorted(relative_paths))
    if len(paths) != len(set(paths)):
        raise RuntimeError("owner_canary_release_runtime_object_membership_invalid")
    for value in paths:
        pure = PurePosixPath(value)
        if (
            pure.is_absolute()
            or not pure.parts
            or pure.suffix != ".enc"
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise RuntimeError("owner_canary_release_runtime_object_membership_invalid")
    return replace(plan, runtime_object_relative_paths=paths)


def capture_owner_canary_release_filesystem_snapshot(
    plan: OwnerCanaryReleaseSnapshotPlan,
) -> OwnerCanaryReleaseFilesystemSnapshot:
    """Capture one exact metadata snapshot without reading file contents."""

    if type(plan) is not OwnerCanaryReleaseSnapshotPlan:
        raise RuntimeError("owner_canary_release_snapshot_plan_invalid")
    integration_head_sha, tracked_paths = _tracked_integration_identity(plan.project_root)
    entries = [*_capture_tracked_inputs(plan.project_root, tracked_paths)]
    entries.extend(_capture_tree("candidate_build", plan.candidate_build_root))
    entries.extend(_capture_tree("fixed_model", plan.fixed_model_root))
    entries.extend(_capture_tree("private_review_workspace", plan.private_review_workspace_root))
    active_pointer_path = plan.active_pointer_path or (
        plan.project_root / "data" / "indexes" / "ACTIVE.json"
    )
    entries.append(_capture_active_pointer(active_pointer_path))
    if plan.runtime_object_relative_paths:
        runtime_directories = {"."}
        for relative_path in plan.runtime_object_relative_paths:
            pure = PurePosixPath(relative_path)
            runtime_directories.update(
                "." if str(parent) == "." else parent.as_posix() for parent in pure.parents
            )
        for relative_path in sorted(
            runtime_directories, key=lambda value: (value.count("/"), value)
        ):
            entries.append(
                _raw_directory_snapshot(
                    "runtime_object",
                    relative_path,
                    _join_relative(plan.runtime_object_root, relative_path),
                )
            )
    for relative_path in plan.runtime_object_relative_paths:
        path = _join_relative(plan.runtime_object_root, relative_path)
        entries.append(
            _raw_lstat(
                "runtime_object",
                relative_path,
                path,
                expected_kind="regular_file",
                content_sha256=_regular_file_sha256_no_follow(path),
            )
        )
    snapshot_entries = tuple(entries)
    return OwnerCanaryReleaseFilesystemSnapshot(
        plan=plan,
        integration_head_sha=integration_head_sha,
        tracked_relative_paths=tracked_paths,
        entries=snapshot_entries,
        regular_file_count=sum(entry.kind == "regular_file" for entry in snapshot_entries),
        directory_count=sum(entry.kind == "directory" for entry in snapshot_entries),
    )


def require_identical_owner_canary_release_snapshots(
    before: OwnerCanaryReleaseFilesystemSnapshot,
    after: OwnerCanaryReleaseFilesystemSnapshot,
) -> OwnerCanaryReleaseFilesystemSnapshot:
    """Accept only field-for-field-equivalent metadata around full replay."""

    if (
        type(before) is not OwnerCanaryReleaseFilesystemSnapshot
        or type(after) is not OwnerCanaryReleaseFilesystemSnapshot
        or before != after
    ):
        raise RuntimeError("owner_canary_release_snapshot_changed_during_replay")
    return after


def require_owner_canary_release_snapshot_current(
    expected: OwnerCanaryReleaseFilesystemSnapshot,
) -> OwnerCanaryReleaseSnapshotRecheck:
    """Recheck a fixed snapshot using metadata only and a strict time budget."""

    if type(expected) is not OwnerCanaryReleaseFilesystemSnapshot:
        raise RuntimeError("owner_canary_release_snapshot_capability_invalid")
    started = time.perf_counter()
    observed_head, observed_tracked = _tracked_integration_identity(expected.plan.project_root)
    if (
        observed_head != expected.integration_head_sha
        or observed_tracked != expected.tracked_relative_paths
    ):
        raise RuntimeError("owner_canary_release_snapshot_not_current")
    for entry in expected.entries:
        observed = _snapshot_expected_path(expected.plan, entry)
        if observed != entry:
            raise RuntimeError("owner_canary_release_snapshot_not_current")
    elapsed = time.perf_counter() - started
    if elapsed > OWNER_CANARY_RELEASE_SNAPSHOT_RECHECK_BUDGET_SECONDS:
        raise RuntimeError("owner_canary_release_snapshot_recheck_budget_exceeded")
    return OwnerCanaryReleaseSnapshotRecheck(
        regular_file_count=expected.regular_file_count,
        directory_count=expected.directory_count,
        elapsed_seconds=elapsed,
    )


def _absolute_raw_path(path: Path) -> Path:
    if not path.is_absolute():
        raise RuntimeError("owner_canary_release_snapshot_root_invalid")
    # ``normpath`` is lexical; unlike ``resolve`` it does not follow a symlink.
    return Path(os.path.normpath(os.fspath(path)))


def _trusted_git_command(project_root: Path, *arguments: str) -> bytes:
    try:
        git_stat = os.lstat(_TRUSTED_GIT)
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_git_unavailable") from None
    if not stat.S_ISREG(git_stat.st_mode) or git_stat.st_uid != 0 or not git_stat.st_mode & 0o111:
        raise RuntimeError("owner_canary_release_snapshot_git_unavailable")
    try:
        completed = subprocess.run(
            [
                str(_TRUSTED_GIT),
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                str(project_root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            env=_TRUSTED_GIT_ENV,
            timeout=0.75,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("owner_canary_release_snapshot_git_failed") from None
    if completed.returncode != 0:
        raise RuntimeError("owner_canary_release_snapshot_git_failed")
    return completed.stdout


def _tracked_integration_identity(project_root: Path) -> tuple[str, tuple[str, ...]]:
    root_snapshot = _raw_lstat("tracked_integration", ".", project_root, expected_kind="directory")
    if root_snapshot.kind != "directory":  # pragma: no cover - fixed by expected_kind
        raise RuntimeError("owner_canary_release_snapshot_root_invalid")
    head = (
        _trusted_git_command(project_root, "rev-parse", "--verify", "HEAD")
        .decode("ascii", errors="strict")
        .strip()
    )
    if not _GIT_SHA.fullmatch(head):
        raise RuntimeError("owner_canary_release_snapshot_git_failed")
    raw_paths = _trusted_git_command(project_root, "ls-files", "-z", "--", ".")
    members = raw_paths.split(b"\0")
    if not members or members[-1] != b"":
        raise RuntimeError("owner_canary_release_snapshot_git_failed")
    paths = tuple(sorted(os.fsdecode(value) for value in members[:-1]))
    if not paths or len(paths) != len(set(paths)):
        raise RuntimeError("owner_canary_release_snapshot_tracked_membership_invalid")
    for value in paths:
        pure = PurePosixPath(value)
        if (
            pure.is_absolute()
            or not pure.parts
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise RuntimeError("owner_canary_release_snapshot_tracked_membership_invalid")
    return head, paths


def _capture_tracked_inputs(
    project_root: Path, tracked_paths: tuple[str, ...]
) -> tuple[RawPathLstatSnapshot, ...]:
    directories: set[str] = {"."}
    for relative_path in tracked_paths:
        pure = PurePosixPath(relative_path)
        for parent in pure.parents:
            if str(parent) == ".":
                directories.add(".")
                break
            directories.add(parent.as_posix())
    snapshots: list[RawPathLstatSnapshot] = []
    for relative_path in sorted(directories, key=lambda value: (value.count("/"), value)):
        path = _join_relative(project_root, relative_path)
        snapshots.append(_raw_directory_snapshot("tracked_integration", relative_path, path))
    for relative_path in tracked_paths:
        snapshots.append(
            _raw_lstat(
                "tracked_integration",
                relative_path,
                _join_relative(project_root, relative_path),
                expected_kind="regular_file",
            )
        )
    return tuple(snapshots)


def _capture_tree(
    scope: Literal["candidate_build", "fixed_model", "private_review_workspace"],
    root: Path,
) -> tuple[RawPathLstatSnapshot, ...]:
    snapshots: list[RawPathLstatSnapshot] = []
    pending: list[tuple[str, Path]] = [(".", root)]
    while pending:
        relative_path, path = pending.pop()
        directory = _raw_directory_snapshot(scope, relative_path, path)
        members = directory.directory_entries
        snapshots.append(directory)
        child_directories: list[tuple[str, Path]] = []
        for name in members:
            child_relative = name if relative_path == "." else f"{relative_path}/{name}"
            child_path = path / name
            child = _raw_lstat(scope, child_relative, child_path)
            if child.kind == "directory":
                child_directories.append((child_relative, child_path))
            else:
                snapshots.append(child)
        pending.extend(reversed(child_directories))
    return tuple(snapshots)


def _snapshot_expected_path(
    plan: OwnerCanaryReleaseSnapshotPlan,
    expected: RawPathLstatSnapshot,
) -> RawPathLstatSnapshot:
    if expected.scope == "active_pointer":
        active_pointer_path = plan.active_pointer_path or (
            plan.project_root / "data" / "indexes" / "ACTIVE.json"
        )
        return _capture_active_pointer(active_pointer_path, content_sha256=expected.content_sha256)
    roots = {
        "tracked_integration": plan.project_root,
        "candidate_build": plan.candidate_build_root,
        "fixed_model": plan.fixed_model_root,
        "private_review_workspace": plan.private_review_workspace_root,
        "runtime_object": plan.runtime_object_root,
    }
    root = roots[expected.scope]
    path = _join_relative(root, expected.relative_path)
    if expected.kind == "directory":
        return _raw_directory_snapshot(expected.scope, expected.relative_path, path)
    if expected.kind == "absent":  # pragma: no cover - active pointer handled above
        raise RuntimeError("owner_canary_release_snapshot_path_type_invalid")
    return _raw_lstat(
        expected.scope,
        expected.relative_path,
        path,
        expected_kind=expected.kind,
        content_sha256=expected.content_sha256,
    )


def _join_relative(root: Path, relative_path: str) -> Path:
    if relative_path == ".":
        return root
    return root.joinpath(*PurePosixPath(relative_path).parts)


def _raw_directory_snapshot(
    scope: SnapshotScope,
    relative_path: str,
    path: Path,
) -> RawPathLstatSnapshot:
    before = _raw_lstat(scope, relative_path, path, expected_kind="directory")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_directory_invalid") from None
    try:
        opened_before = os.fstat(descriptor)
        if _stat_identity(opened_before) != _snapshot_identity(before):
            raise RuntimeError("owner_canary_release_snapshot_directory_invalid")
        names = tuple(sorted(os.listdir(descriptor)))
        opened_after = os.fstat(descriptor)
        if _stat_identity(opened_after) != _snapshot_identity(before):
            raise RuntimeError("owner_canary_release_snapshot_directory_invalid")
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_directory_invalid") from None
    finally:
        os.close(descriptor)
    if any(name in {"", ".", ".."} or "/" in name or "\0" in name for name in names):
        raise RuntimeError("owner_canary_release_snapshot_directory_invalid")
    after = _raw_lstat(scope, relative_path, path, expected_kind="directory")
    if before != after:
        raise RuntimeError("owner_canary_release_snapshot_directory_invalid")
    return replace(before, directory_entries=names)


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_uid),
        int(value.st_mode),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _snapshot_identity(
    value: RawPathLstatSnapshot,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.device,
        value.inode,
        value.uid,
        value.mode,
        value.size,
        value.mtime_ns,
        value.ctime_ns,
    )


def _raw_lstat(
    scope: SnapshotScope,
    relative_path: str,
    path: Path,
    *,
    expected_kind: SnapshotKind | None = None,
    directory_entries: tuple[str, ...] = (),
    content_sha256: str | None = None,
) -> RawPathLstatSnapshot:
    try:
        observed = os.lstat(path)
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_path_invalid") from None
    if stat.S_ISDIR(observed.st_mode):
        kind: SnapshotKind = "directory"
    elif stat.S_ISREG(observed.st_mode):
        kind = "regular_file"
    else:
        # This rejects symbolic links, sockets, FIFOs and device nodes without
        # ever following them to a target.
        raise RuntimeError("owner_canary_release_snapshot_path_type_invalid")
    if expected_kind is not None and kind != expected_kind:
        raise RuntimeError("owner_canary_release_snapshot_path_type_invalid")
    if kind != "directory" and directory_entries:
        raise RuntimeError("owner_canary_release_snapshot_directory_invalid")
    return RawPathLstatSnapshot(
        scope=scope,
        relative_path=relative_path,
        kind=kind,
        directory_entries=directory_entries,
        device=int(observed.st_dev),
        inode=int(observed.st_ino),
        uid=int(observed.st_uid),
        mode=int(observed.st_mode),
        size=int(observed.st_size),
        mtime_ns=int(observed.st_mtime_ns),
        ctime_ns=int(observed.st_ctime_ns),
        content_sha256=content_sha256,
    )


def _capture_active_pointer(
    path: Path, *, content_sha256: str | None = None
) -> RawPathLstatSnapshot:
    """Bind exact ACTIVE bytes when present, and exact absence otherwise."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return RawPathLstatSnapshot(
            scope="active_pointer",
            relative_path="ACTIVE.json",
            kind="absent",
            directory_entries=(),
            device=0,
            inode=0,
            uid=0,
            mode=0,
            size=0,
            mtime_ns=0,
            ctime_ns=0,
            content_sha256=None,
        )
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_path_invalid") from None
    digest = content_sha256
    if digest is None:
        digest = _regular_file_sha256_no_follow(path)
    return _raw_lstat(
        "active_pointer",
        "ACTIVE.json",
        path,
        expected_kind="regular_file",
        content_sha256=digest,
    )


def _regular_file_sha256_no_follow(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        before = os.lstat(path)
        descriptor = os.open(path, flags)
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_path_invalid") from None
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or _stat_identity(opened_before) != (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_uid),
            int(before.st_mode),
            int(before.st_size),
            int(before.st_mtime_ns),
            int(before.st_ctime_ns),
        ):
            raise RuntimeError("owner_canary_release_snapshot_path_invalid")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        if _stat_identity(os.fstat(descriptor)) != _stat_identity(opened_before):
            raise RuntimeError("owner_canary_release_snapshot_path_invalid")
    except OSError:
        raise RuntimeError("owner_canary_release_snapshot_path_invalid") from None
    finally:
        os.close(descriptor)
    if _stat_identity(os.lstat(path)) != _stat_identity(before):
        raise RuntimeError("owner_canary_release_snapshot_path_invalid")
    return digest.hexdigest()
