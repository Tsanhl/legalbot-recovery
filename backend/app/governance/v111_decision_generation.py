"""Exact, create-only inputs for the remaining v1.11 owner policy choices.

The helpers in this module only build sealed requests.  They never create a
resolution, key, policy, model process, pointer, or owner authority.  Request
identities are derived from the current committed implementation and the
specific runtime/root they govern so an older request cannot silently drift
forward.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from .owner_stop import (
    OwnerDecisionRequest,
    OwnerDecisionResolution,
    require_owner_resolution,
    seal_owner_decision_request,
)

_GIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

MEMORY_DECISION_OPTIONS: dict[str, tuple[int, int]] = {
    "max-12884901888-min-3221225472": (12_884_901_888, 3_221_225_472),
    "max-10737418240-min-4294967296": (10_737_418_240, 4_294_967_296),
}
MEMORY_DECISION_SCOPE_PREFIX = "completion-memory"
PRIVACY_DECISION_OPTIONS = (
    "approve-owner-private-nonsynced-root",
    "select-different-private-root",
    "defer-and-keep-closed",
)
_VERIFIED_PRIVATE_ROOT_TOKEN = object()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def _sealed_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def _require_lexical_no_symlink_path(path: Path) -> None:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("private path must be absolute and contain no symbolic links")
    current = path
    while True:
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise ValueError("private path ancestors must not be symbolic links")
        if current == current.parent:
            return
        current = current.parent


def read_private_owner_decision_member(
    owner_decision_root: Path,
    decision_id: str,
    filename: str,
) -> bytes:
    """Read one 0600 decision member through no-follow directory descriptors."""

    if _SAFE_ID.fullmatch(decision_id) is None or filename not in {
        "request.json",
        "resolution.json",
    }:
        raise ValueError("owner decision member is invalid")
    _require_lexical_no_symlink_path(owner_decision_root)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure owner decision read is unavailable")
    root_fd = os.open(owner_decision_root, os.O_RDONLY | directory_flag | no_follow)
    decision_fd = -1
    member_fd = -1
    try:
        root_before = os.fstat(root_fd)
        root_path_before = os.stat(owner_decision_root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_before.st_mode)
            or root_before.st_uid != os.getuid()
            or stat.S_IMODE(root_before.st_mode) != 0o700
        ):
            raise RuntimeError("owner decision root is not private")
        decision_fd = os.open(
            decision_id,
            os.O_RDONLY | directory_flag | no_follow,
            dir_fd=root_fd,
        )
        decision_before = os.fstat(decision_fd)
        decision_path_before = os.stat(
            decision_id,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(decision_before.st_mode)
            or decision_before.st_uid != os.getuid()
            or stat.S_IMODE(decision_before.st_mode) != 0o700
        ):
            raise RuntimeError("owner decision directory is not private")
        member_fd = os.open(filename, os.O_RDONLY | no_follow, dir_fd=decision_fd)
        member_before = os.fstat(member_fd)
        if (
            not stat.S_ISREG(member_before.st_mode)
            or member_before.st_uid != os.getuid()
            or stat.S_IMODE(member_before.st_mode) != 0o600
            or member_before.st_nlink != 1
            or member_before.st_size > 4 * 1024 * 1024
        ):
            raise RuntimeError("owner decision member is not private")
        blocks: list[bytes] = []
        remaining = member_before.st_size
        while remaining:
            block = os.read(member_fd, min(remaining, 1024 * 1024))
            if not block:
                raise RuntimeError("owner decision member was truncated")
            blocks.append(block)
            remaining -= len(block)
        member_after = os.fstat(member_fd)
        member_path = os.stat(filename, dir_fd=decision_fd, follow_symlinks=False)
        decision_after = os.fstat(decision_fd)
        decision_path_after = os.stat(
            decision_id,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
        root_after = os.fstat(root_fd)
        root_path_after = os.stat(owner_decision_root, follow_symlinks=False)
        _require_lexical_no_symlink_path(owner_decision_root)

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        def directory_identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            identity(member_before) != identity(member_after)
            or identity(member_before) != identity(member_path)
            or directory_identity(decision_before) != directory_identity(decision_after)
            or directory_identity(decision_before) != directory_identity(decision_path_before)
            or directory_identity(decision_before) != directory_identity(decision_path_after)
            or directory_identity(root_before) != directory_identity(root_after)
            or directory_identity(root_before) != directory_identity(root_path_before)
            or directory_identity(root_before) != directory_identity(root_path_after)
        ):
            raise RuntimeError("owner decision member changed during read")
        return b"".join(blocks)
    finally:
        if member_fd >= 0:
            os.close(member_fd)
        if decision_fd >= 0:
            os.close(decision_fd)
        os.close(root_fd)


def _read_git_admin_file(path: Path, *, label: str) -> bytes:
    """Read one small owner-controlled Git metadata file without following links."""

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise RuntimeError("secure Git metadata inspection is unavailable")
    descriptor = os.open(path, os.O_RDONLY | no_follow)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) not in {0o600, 0o644}
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > 4096
        ):
            raise RuntimeError(f"{label} is unsafe")
        blocks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, remaining)
            if not block:
                raise RuntimeError(f"{label} was truncated")
            blocks.append(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        lexical = os.stat(path, follow_symlinks=False)

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if identity(before) != identity(after) or identity(before) != identity(lexical):
            raise RuntimeError(f"{label} changed during inspection")
        return b"".join(blocks)
    finally:
        os.close(descriptor)


def _trusted_git_directory(root: Path) -> Path:
    """Resolve a direct repository or one exact linked-worktree admin directory."""

    marker = root / ".git"
    if marker.is_symlink():
        raise RuntimeError("owner decision request Git marker is unsafe")
    if marker.is_dir():
        metadata = marker.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RuntimeError("owner decision request Git directory is unsafe")
        return marker
    marker_bytes = _read_git_admin_file(marker, label="linked-worktree Git marker")
    try:
        marker_text = marker_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError("linked-worktree Git marker is invalid") from exc
    match = re.fullmatch(r"gitdir: (/[^\r\n\x00]+)\n?", marker_text)
    if match is None:
        raise RuntimeError("linked-worktree Git marker is invalid")
    git_directory = Path(match.group(1))
    if (
        not git_directory.is_absolute()
        or git_directory.resolve(strict=True) != git_directory
        or git_directory.is_symlink()
        or not git_directory.is_dir()
    ):
        raise RuntimeError("linked-worktree Git directory is unsafe")
    metadata = git_directory.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise RuntimeError("linked-worktree Git directory is unsafe")
    if git_directory.parent.name != "worktrees":
        raise RuntimeError("linked-worktree Git directory is not an admin worktree")
    common_directory = git_directory.parent.parent
    if (
        common_directory.name != ".git"
        or common_directory.resolve(strict=True) != common_directory
        or common_directory.is_symlink()
        or not common_directory.is_dir()
        or common_directory.stat().st_uid != os.getuid()
        or stat.S_IMODE(common_directory.stat().st_mode) & 0o022
    ):
        raise RuntimeError("linked-worktree common Git directory is unsafe")
    if _read_git_admin_file(git_directory / "commondir", label="Git common-dir pointer") not in {
        b"../..",
        b"../..\n",
    }:
        raise RuntimeError("linked-worktree common Git directory differs")
    expected_back_pointer = f"{marker}\n".encode()
    if (
        _read_git_admin_file(git_directory / "gitdir", label="Git worktree back-pointer")
        != expected_back_pointer
    ):
        raise RuntimeError("linked-worktree Git back-pointer differs")
    return git_directory


def _parse_head_tree(
    payload: bytes,
    *,
    object_id_length: int,
) -> dict[bytes, tuple[bytes, bytes]]:
    entries: dict[bytes, tuple[bytes, bytes]] = {}
    for record in payload.split(b"\x00"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, object_type, object_id = header.split(b" ")
        except ValueError as exc:
            raise RuntimeError("owner decision request HEAD tree is invalid") from exc
        if (
            not path
            or path in entries
            or object_type != b"blob"
            or mode not in {b"100644", b"100755", b"120000"}
            or len(object_id) != object_id_length
            or re.fullmatch(rb"[0-9a-f]+", object_id) is None
        ):
            raise RuntimeError("owner decision request HEAD tree is unsupported")
        entries[path] = (mode, object_id)
    return entries


def _parse_index_tree(
    payload: bytes,
    *,
    object_id_length: int,
) -> dict[bytes, tuple[bytes, bytes]]:
    entries: dict[bytes, tuple[bytes, bytes]] = {}
    for record in payload.split(b"\x00"):
        if not record:
            continue
        try:
            header, path = record.split(b"\t", 1)
            mode, object_id, stage = header.split(b" ")
        except ValueError as exc:
            raise RuntimeError("owner decision request Git index is invalid") from exc
        if (
            not path
            or path in entries
            or stage != b"0"
            or mode not in {b"100644", b"100755", b"120000"}
            or len(object_id) != object_id_length
            or re.fullmatch(rb"[0-9a-f]+", object_id) is None
        ):
            raise RuntimeError("owner decision request Git index is unsupported")
        entries[path] = (mode, object_id)
    return entries


def _raw_worktree_blob_id(
    root_descriptor: int,
    path: bytes,
    *,
    expected_mode: bytes,
    object_format: str,
) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure raw worktree verification is unavailable")
    parts = path.split(b"/")
    if any(part in {b"", b".", b".."} for part in parts) or parts[0] == b".git":
        raise RuntimeError("owner decision request tracked path is invalid")
    parent = os.dup(root_descriptor)
    member = -1

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    try:
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | directory_flag | no_follow,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
            if not stat.S_ISDIR(os.fstat(parent).st_mode):
                raise RuntimeError("owner decision request tracked ancestor is invalid")
        before_path = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if expected_mode == b"120000":
            if not stat.S_ISLNK(before_path.st_mode):
                raise RuntimeError("owner decision request tracked type differs from HEAD")
            target = os.readlink(parts[-1], dir_fd=parent)
            if not isinstance(target, bytes):
                target = os.fsencode(target)
            after_path = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            if identity(before_path) != identity(after_path):
                raise RuntimeError("owner decision request tracked link changed during read")
            content_length = len(target)
            digest = hashlib.new(object_format)
            digest.update(f"blob {content_length}\0".encode("ascii"))
            digest.update(target)
            return digest.hexdigest().encode("ascii")
        member = os.open(parts[-1], os.O_RDONLY | no_follow, dir_fd=parent)
        before = os.fstat(member)
        expected_executable = expected_mode == b"100755"
        if (
            not stat.S_ISREG(before.st_mode)
            or bool(stat.S_IMODE(before.st_mode) & 0o111) != expected_executable
            or identity(before) != identity(before_path)
        ):
            raise RuntimeError("owner decision request tracked type or mode differs from HEAD")
        digest = hashlib.new(object_format)
        digest.update(f"blob {before.st_size}\0".encode("ascii"))
        remaining = before.st_size
        while remaining:
            block = os.read(member, min(remaining, 1024 * 1024))
            if not block:
                raise RuntimeError("owner decision request tracked file was truncated")
            digest.update(block)
            remaining -= len(block)
        if os.read(member, 1):
            raise RuntimeError("owner decision request tracked file grew during read")
        after = os.fstat(member)
        after_path = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if identity(before) != identity(after) or identity(before) != identity(after_path):
            raise RuntimeError("owner decision request tracked file changed during read")
        return digest.hexdigest().encode("ascii")
    finally:
        if member >= 0:
            os.close(member)
        os.close(parent)


def _require_raw_head_worktree(
    root: Path,
    *,
    head_entries: Mapping[bytes, tuple[bytes, bytes]],
    object_format: str,
) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure raw worktree verification is unavailable")
    root_descriptor = os.open(root, os.O_RDONLY | directory_flag | no_follow)
    try:
        before = os.fstat(root_descriptor)
        for path, (mode, expected_object_id) in sorted(head_entries.items()):
            observed = _raw_worktree_blob_id(
                root_descriptor,
                path,
                expected_mode=mode,
                object_format=object_format,
            )
            if observed != expected_object_id:
                raise RuntimeError("owner decision request tracked bytes differ from HEAD")
        after = os.fstat(root_descriptor)
        lexical = os.stat(root, follow_symlinks=False)

        def directory_identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                value.st_mode,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if directory_identity(before) != directory_identity(after) or directory_identity(
            before
        ) != directory_identity(lexical):
            raise RuntimeError("owner decision request worktree changed during verification")
    finally:
        os.close(root_descriptor)


def require_exact_clean_head(project_root: Path, expected_sha: str) -> str:
    """Return HEAD only when it is the exact supplied commit and the tree is clean."""

    if _GIT_SHA.fullmatch(expected_sha) is None:
        raise ValueError("integration SHA is invalid")
    root = project_root.resolve(strict=True)
    git = Path("/usr/bin/git")
    if git.is_symlink() or not git.is_file() or git.stat().st_uid != 0:
        raise RuntimeError("trusted system Git executable is unavailable")
    git_directory = _trusted_git_directory(root)
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    git_prefix = [
        str(git),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.filemode=true",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
        "-c",
        "core.symlinks=true",
        "--git-dir",
        str(git_directory),
        "--work-tree",
        str(root),
    ]
    reported_git_directory = subprocess.run(
        [*git_prefix, "rev-parse", "--absolute-git-dir"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    if reported_git_directory != str(git_directory):
        raise RuntimeError("owner decision request Git directory cross-check differs")
    reported_common_directory = subprocess.run(
        [*git_prefix, "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    common_directory = Path(reported_common_directory)
    expected_common_directory = (
        git_directory.parent.parent if git_directory.parent.name == "worktrees" else git_directory
    )
    if (
        common_directory != expected_common_directory
        or common_directory.resolve(strict=True) != common_directory
        or common_directory.is_symlink()
        or not common_directory.is_dir()
        or common_directory.stat().st_uid != os.getuid()
        or stat.S_IMODE(common_directory.stat().st_mode) & 0o022
    ):
        raise RuntimeError("owner decision request Git common directory differs")
    replacement_refs = subprocess.run(
        [*git_prefix, "for-each-ref", "--format=%(refname)", "refs/replace/"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    if replacement_refs:
        raise RuntimeError("owner decision request rejects Git replacement refs")
    try:
        os.lstat(common_directory / "info/grafts")
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("owner decision request rejects Git graft metadata")
    object_format = subprocess.run(
        [*git_prefix, "rev-parse", "--show-object-format"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    if object_format not in {"sha1", "sha256"}:
        raise RuntimeError("owner decision request Git object format is unsupported")
    object_id_length = 40 if object_format == "sha1" else 64
    index_entries = subprocess.run(
        [*git_prefix, "ls-files", "-v", "-z"],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    if any(not entry.startswith(b"H ") for entry in index_entries.split(b"\x00") if entry):
        raise RuntimeError("owner decision request rejects nonstandard Git index flags")
    resolved = subprocess.run(
        [*git_prefix, "rev-parse", "--verify", f"{expected_sha}^{{commit}}"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    )
    head = subprocess.run(
        [*git_prefix, "rev-parse", "--verify", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    head_tree_payload = subprocess.run(
        [*git_prefix, "ls-tree", "-r", "-z", "--full-tree", expected_sha],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    index_tree_payload = subprocess.run(
        [*git_prefix, "ls-files", "--stage", "-z"],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    head_entries = _parse_head_tree(
        head_tree_payload,
        object_id_length=object_id_length,
    )
    index_entries_by_path = _parse_index_tree(
        index_tree_payload,
        object_id_length=object_id_length,
    )
    untracked = subprocess.run(
        [
            *git_prefix,
            "ls-files",
            "--others",
            "--exclude=!.gitignore",
            "--exclude-per-directory=.gitignore",
            "-z",
        ],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    final_index_entries = subprocess.run(
        [*git_prefix, "ls-files", "-v", "-z"],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    if resolved.returncode != 0 or resolved.stdout.strip() != expected_sha or head != expected_sha:
        raise RuntimeError("owner decision request requires exact integration HEAD")
    if untracked:
        raise RuntimeError("owner decision request requires a clean integration tree")
    if index_entries_by_path != head_entries:
        raise RuntimeError("owner decision request Git index differs from HEAD")
    if final_index_entries != index_entries:
        raise RuntimeError("owner decision request Git index changed during verification")
    final_index_tree_payload = subprocess.run(
        [*git_prefix, "ls-files", "--stage", "-z"],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    if final_index_tree_payload != index_tree_payload:
        raise RuntimeError("owner decision request Git index changed during verification")
    final_head = subprocess.run(
        [*git_prefix, "rev-parse", "--verify", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    if final_head != head:
        raise RuntimeError("owner decision request HEAD changed during verification")
    _require_raw_head_worktree(
        root,
        head_entries=head_entries,
        object_format=object_format,
    )
    # Raw hashing can be long enough for a concurrent writer to alter Git
    # metadata or add a nested untracked member after that directory was
    # visited.  Re-observe every non-worktree input after the raw scan; the
    # caller receives authority only for one coherent final state.
    post_raw_head = subprocess.run(
        [*git_prefix, "rev-parse", "--verify", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    post_raw_index_entries = subprocess.run(
        [*git_prefix, "ls-files", "-v", "-z"],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    post_raw_index_tree = subprocess.run(
        [*git_prefix, "ls-files", "--stage", "-z"],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    post_raw_untracked = subprocess.run(
        [
            *git_prefix,
            "ls-files",
            "--others",
            "--exclude=!.gitignore",
            "--exclude-per-directory=.gitignore",
            "-z",
        ],
        check=True,
        capture_output=True,
        text=False,
        env=environment,
        shell=False,
    ).stdout
    post_raw_replacement_refs = subprocess.run(
        [*git_prefix, "for-each-ref", "--format=%(refname)", "refs/replace/"],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        shell=False,
    ).stdout.strip()
    if post_raw_head != head:
        raise RuntimeError("owner decision request HEAD changed during raw verification")
    if post_raw_index_entries != index_entries or post_raw_index_tree != index_tree_payload:
        raise RuntimeError("owner decision request Git index changed during raw verification")
    if post_raw_untracked:
        raise RuntimeError("owner decision request worktree changed during raw verification")
    if post_raw_replacement_refs:
        raise RuntimeError("owner decision request rejects Git replacement refs")
    try:
        os.lstat(common_directory / "info/grafts")
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError("owner decision request rejects Git graft metadata")
    return head


def completion_memory_decision_id(
    *,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    runtime_binding_sha256: str,
    integration_sha: str,
    host_physical_memory_bytes: int,
    trusted_model_identity_file_sha256: str,
    trusted_toolchain_identity_file_sha256: str,
) -> str:
    """Derive the one request ID for an exact completion runtime and host."""

    if (
        _SAFE_ID.fullmatch(candidate_build_id) is None
        or any(
            _SHA256.fullmatch(value) is None
            for value in (
                candidate_manifest_sha256,
                runtime_binding_sha256,
                trusted_model_identity_file_sha256,
                trusted_toolchain_identity_file_sha256,
            )
        )
        or _GIT_SHA.fullmatch(integration_sha) is None
        or isinstance(host_physical_memory_bytes, bool)
        or host_physical_memory_bytes < 1
    ):
        raise ValueError("completion memory decision binding is invalid")
    identity = _sealed_sha256(
        {
            "schema": "legalbot.v111-completion-memory-decision-identity.v1",
            "candidate_build_id": candidate_build_id,
            "candidate_manifest_sha256": candidate_manifest_sha256,
            "runtime_binding_sha256": runtime_binding_sha256,
            "integration_sha": integration_sha,
            "host_physical_memory_bytes": host_physical_memory_bytes,
            "trusted_model_identity_file_sha256": trusted_model_identity_file_sha256,
            "trusted_toolchain_identity_file_sha256": (trusted_toolchain_identity_file_sha256),
            "bounded_options": {
                key: list(value) for key, value in sorted(MEMORY_DECISION_OPTIONS.items())
            },
        }
    )
    return f"v111-completion-memory-{identity[:20]}"


def build_completion_memory_decision_request(
    *,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    runtime_binding_sha256: str,
    integration_sha: str,
    host_physical_memory_bytes: int,
    trusted_model_identity_file_sha256: str,
    trusted_toolchain_identity_file_sha256: str,
    created_at: datetime,
) -> OwnerDecisionRequest:
    """Build the exact memory-envelope request without selecting an option."""

    decision_id = completion_memory_decision_id(
        candidate_build_id=candidate_build_id,
        candidate_manifest_sha256=candidate_manifest_sha256,
        runtime_binding_sha256=runtime_binding_sha256,
        integration_sha=integration_sha,
        host_physical_memory_bytes=host_physical_memory_bytes,
        trusted_model_identity_file_sha256=trusted_model_identity_file_sha256,
        trusted_toolchain_identity_file_sha256=trusted_toolchain_identity_file_sha256,
    )
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("completion memory decision timestamp must be timezone-aware")
    suffix = decision_id.rsplit("-", 1)[-1]
    return seal_owner_decision_request(
        decision_id=decision_id,
        category="policy",
        scope_id=f"{MEMORY_DECISION_SCOPE_PREFIX}:{suffix}",
        reason_codes=(
            "MEMORY_ENVELOPE_OWNER_SELECTION_REQUIRED",
            "EXACT_RUNTIME_AND_HOST_BINDING_REQUIRED",
            "NO_MEMORY_THRESHOLD_MAY_BE_INFERRED",
        ),
        evidence=(
            {
                "evidence_id": "candidate-manifest",
                "kind": "candidate_manifest",
                "sha256": candidate_manifest_sha256,
                "summary_code": "EXACT_COMPLETION_CANDIDATE",
            },
            {
                "evidence_id": "completion-runtime-binding",
                "kind": "runtime_binding",
                "sha256": runtime_binding_sha256,
                "summary_code": "EXACT_COMPLETION_RUNTIME",
            },
            {
                "evidence_id": "trusted-model-identity-file",
                "kind": "committed_artifact",
                "sha256": trusted_model_identity_file_sha256,
                "summary_code": "EXACT_TRUSTED_MODEL_IDENTITY",
            },
            {
                "evidence_id": "trusted-toolchain-identity-file",
                "kind": "committed_artifact",
                "sha256": trusted_toolchain_identity_file_sha256,
                "summary_code": "EXACT_TRUSTED_TOOLCHAIN_IDENTITY",
            },
            {
                "evidence_id": "host-physical-memory",
                "kind": "host_memory_profile",
                "sha256": hashlib.sha256(
                    str(host_physical_memory_bytes).encode("ascii")
                ).hexdigest(),
                "summary_code": "EXACT_HOST_PHYSICAL_MEMORY",
            },
            {
                "evidence_id": "integration-commit",
                "kind": "integration_commit",
                "sha256": hashlib.sha256(integration_sha.encode("ascii")).hexdigest(),
                "summary_code": "EXACT_INTEGRATION_COMMIT",
            },
        ),
        options=(
            {
                "option_id": "max-12884901888-min-3221225472",
                "outcome_code": "SET_MAX_12_GIB_MIN_3_GIB",
                "recommended": True,
                "consequence_codes": (
                    "CONSERVATIVE_LOCAL_ENVELOPE",
                    "STOP_IF_MAXIMUM_OR_HEADROOM_BOUND_CROSSED",
                ),
            },
            {
                "option_id": "max-10737418240-min-4294967296",
                "outcome_code": "SET_MAX_10_GIB_MIN_4_GIB",
                "recommended": False,
                "consequence_codes": (
                    "STRICTER_LOCAL_ENVELOPE",
                    "GREATER_FALSE_STOP_RISK",
                ),
            },
        ),
        blocked_actions=(
            "candidate-completion-preflight",
            "model-runtime-launch",
            "authoritative-development-canary",
            "v111-normal-live-readiness",
        ),
        created_at=created_at,
    )


def _private_root_filesystem_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
    )


def _private_root_location_identity(root: Path) -> str:
    """Bind exact lexical location and ancestors without serializing their names."""

    _require_lexical_no_symlink_path(root)
    ancestors: list[dict[str, int]] = []
    current = root.parent
    depth = 0
    while True:
        metadata = os.lstat(current)
        ancestors.append(
            {
                "depth": depth,
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "owner_uid": metadata.st_uid,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        )
        if current == current.parent:
            break
        current = current.parent
        depth += 1
    path_digest = hashlib.sha256(
        b"legalbot.v111-private-root-lexical-location.v1\x00" + os.fsencode(os.fspath(root))
    ).hexdigest()
    return _sealed_sha256(
        {
            "schema": "legalbot.v111-private-root-location-identity.v1",
            "lexical_path_sha256": path_digest,
            "ancestor_chain": ancestors,
        }
    )


def _private_root_identity_from_metadata(
    metadata: os.stat_result,
    *,
    location_identity_sha256: str,
) -> str:
    return _sealed_sha256(
        {
            "schema": "legalbot.v111-operational-private-root-identity.v2",
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "owner_uid": metadata.st_uid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "location_identity_sha256": location_identity_sha256,
        }
    )


def _open_private_root_descriptor(
    root: Path,
    *,
    project_root: Path,
) -> tuple[int, str, tuple[int, int, int, int]]:
    _require_lexical_no_symlink_path(root)
    location_before = _private_root_location_identity(root)
    resolved = root
    project = project_root.resolve(strict=True)
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise RuntimeError("secure owner private root inspection is unavailable")
    descriptor = os.open(resolved, os.O_RDONLY | directory_flag | no_follow)
    try:
        metadata = os.fstat(descriptor)
        lexical = os.lstat(resolved)
        _require_lexical_no_symlink_path(root)
        location_after = _private_root_location_identity(root)
        lexical_after = os.lstat(resolved)
        observed = _private_root_filesystem_identity(metadata)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or observed
            != (
                lexical.st_dev,
                lexical.st_ino,
                lexical.st_uid,
                lexical.st_mode,
            )
            or observed
            != (
                lexical_after.st_dev,
                lexical_after.st_ino,
                lexical_after.st_uid,
                lexical_after.st_mode,
            )
            or resolved == project
            or resolved.is_relative_to(project)
            or location_before != location_after
        ):
            raise ValueError("owner private root is not an external 0700 directory")
        return (
            descriptor,
            _private_root_identity_from_metadata(
                metadata,
                location_identity_sha256=location_after,
            ),
            observed,
        )
    except Exception:
        os.close(descriptor)
        raise


def private_root_identity(root: Path, *, project_root: Path) -> str:
    """Return a path-free identity for one existing external private directory."""

    descriptor, identity, _filesystem_identity = _open_private_root_descriptor(
        root,
        project_root=project_root,
    )
    os.close(descriptor)
    return identity


def canary_output_privacy_decision_id(
    *,
    root_identity_sha256: str,
    runtime_implementation_sha256: str,
    integration_sha: str,
) -> str:
    if (
        _SHA256.fullmatch(root_identity_sha256) is None
        or _SHA256.fullmatch(runtime_implementation_sha256) is None
        or _GIT_SHA.fullmatch(integration_sha) is None
    ):
        raise ValueError("canary output privacy decision binding is invalid")
    identity = _sealed_sha256(
        {
            "schema": "legalbot.v111-canary-output-privacy-decision-identity.v1",
            "root_identity_sha256": root_identity_sha256,
            "runtime_implementation_sha256": runtime_implementation_sha256,
            "integration_sha": integration_sha,
            "option_ids": list(PRIVACY_DECISION_OPTIONS),
        }
    )
    return f"v111-canary-output-privacy-{identity[:20]}"


def build_canary_output_privacy_decision_request(
    *,
    root_identity_sha256: str,
    runtime_implementation_sha256: str,
    integration_sha: str,
    created_at: datetime,
) -> OwnerDecisionRequest:
    """Build the exact path-free request for an already observed external root."""

    decision_id = canary_output_privacy_decision_id(
        root_identity_sha256=root_identity_sha256,
        runtime_implementation_sha256=runtime_implementation_sha256,
        integration_sha=integration_sha,
    )
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("privacy decision timestamp must be timezone-aware")
    suffix = decision_id.rsplit("-", 1)[-1]
    return seal_owner_decision_request(
        decision_id=decision_id,
        category="policy",
        scope_id=f"canary-output-root:{suffix}",
        reason_codes=(
            "EXACT_PRIVATE_OUTPUT_ROOT_OWNER_APPROVAL_REQUIRED",
            "SYNC_AND_ENCRYPTION_STATE_IS_OWNER_ATTESTED",
            "READABLE_CANARY_OUTPUT_MUST_NOT_ENTER_CLOUD_SYNC",
        ),
        evidence=(
            {
                "evidence_id": "private-root-identity",
                "kind": "private_root_identity",
                "sha256": root_identity_sha256,
                "summary_code": "EXACT_EXTERNAL_0700_ROOT",
            },
            {
                "evidence_id": "canary-runtime-implementation",
                "kind": "runtime_implementation",
                "sha256": runtime_implementation_sha256,
                "summary_code": "EXACT_CANARY_OUTPUT_RUNTIME",
            },
            {
                "evidence_id": "integration-commit",
                "kind": "integration_commit",
                "sha256": hashlib.sha256(integration_sha.encode("ascii")).hexdigest(),
                "summary_code": "EXACT_INTEGRATION_COMMIT",
            },
        ),
        options=(
            {
                "option_id": "approve-owner-private-nonsynced-root",
                "outcome_code": "APPROVE_EXACT_PRIVATE_NONSYNCED_ROOT",
                "recommended": True,
                "consequence_codes": (
                    "OWNER_ATTESTS_ROOT_ENCRYPTED_AND_NONSYNCED",
                    "BIND_ROOT_BY_LOCATION_AND_FILESYSTEM_IDENTITY",
                    "KEEP_READABLE_OUTPUT_OUTSIDE_PROJECT",
                ),
            },
            {
                "option_id": "select-different-private-root",
                "outcome_code": "SELECT_AND_REBIND_DIFFERENT_PRIVATE_ROOT",
                "recommended": False,
                "consequence_codes": (
                    "CURRENT_ROOT_NOT_AUTHORIZED",
                    "NEW_EXACT_REQUEST_REQUIRED",
                ),
            },
            {
                "option_id": "defer-and-keep-closed",
                "outcome_code": "KEEP_CANARY_OUTPUT_CLOSED",
                "recommended": False,
                "consequence_codes": ("NO_AUTHORITATIVE_CANARY",),
            },
        ),
        blocked_actions=(
            "authoritative-development-canary",
            "authoritative-holdout-canary",
            "review-docx-export",
            "normal-owner-only-live",
        ),
        created_at=created_at,
    )


class VerifiedCanaryOutputPrivateRoot:
    """Pinned root capability issued only after a trusted owner-signature check."""

    __slots__ = (
        "_closed",
        "_directory_descriptor",
        "_filesystem_identity",
        "_project_root",
        "_root",
        "_token",
        "request_seal_sha256",
        "resolution_seal_sha256",
        "root_identity_sha256",
    )

    def __init__(
        self,
        *,
        root: Path,
        project_root: Path,
        directory_descriptor: int,
        filesystem_identity: tuple[int, int, int, int],
        root_identity_sha256: str,
        request_seal_sha256: str,
        resolution_seal_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_PRIVATE_ROOT_TOKEN:
            raise TypeError("trusted canary output private-root verification required")
        self.root_identity_sha256 = root_identity_sha256
        self.request_seal_sha256 = request_seal_sha256
        self.resolution_seal_sha256 = resolution_seal_sha256
        self._root = root
        self._project_root = project_root
        self._directory_descriptor = directory_descriptor
        self._filesystem_identity = filesystem_identity
        self._closed = False
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedCanaryOutputPrivateRoot>"

    def _require_current(self) -> None:
        if self._closed:
            raise RuntimeError("canary output private-root capability is closed")
        try:
            metadata = os.fstat(self._directory_descriptor)
            current_identity = private_root_identity(
                self._root,
                project_root=self._project_root,
            )
        except (OSError, RuntimeError, ValueError):
            raise RuntimeError("canary output private root changed after verification") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _private_root_filesystem_identity(metadata) != self._filesystem_identity
            or current_identity != self.root_identity_sha256
        ):
            raise RuntimeError("canary output private root changed after verification")

    @staticmethod
    def _parts(relative_parts: tuple[str, ...]) -> tuple[str, ...]:
        if not relative_parts or any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", part) is None
            for part in relative_parts
        ):
            raise ValueError("canary output relative path is invalid")
        return relative_parts

    def create_private_directory(self, relative_parts: tuple[str, ...]) -> None:
        """Create/open 0700 descendants through the pinned approved root only."""

        parts = self._parts(relative_parts)
        self._require_current()
        no_follow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if no_follow is None or directory_flag is None:
            raise RuntimeError("secure canary output creation is unavailable")
        descriptor = os.dup(self._directory_descriptor)
        try:
            for part in parts:
                with suppress(FileExistsError):
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                child = os.open(
                    part,
                    os.O_RDONLY | directory_flag | no_follow,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise RuntimeError("canary output directory is not private")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._require_current()

    def write_create_only(self, relative_parts: tuple[str, ...], data: bytes) -> None:
        """Write one 0600 member fd-relative to the still-pinned approved root.

        The owner UID is a trusted local boundary: detected rename/replacement
        races are removed through the still-open parent descriptor, but a
        malicious same-UID actor that races after the final identity check is
        outside this local owner-only filesystem contract.
        """

        parts = self._parts(relative_parts)
        if not isinstance(data, bytes) or len(data) > 64 * 1024 * 1024:
            raise ValueError("canary output payload is invalid")
        self._require_current()
        no_follow = getattr(os, "O_NOFOLLOW", None)
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if no_follow is None or directory_flag is None:
            raise RuntimeError("secure canary output creation is unavailable")
        parent = os.dup(self._directory_descriptor)
        member = -1
        created = False
        try:
            for part in parts[:-1]:
                child = os.open(
                    part,
                    os.O_RDONLY | directory_flag | no_follow,
                    dir_fd=parent,
                )
                os.close(parent)
                parent = child
                metadata = os.fstat(parent)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise RuntimeError("canary output directory is not private")
            member = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow,
                0o600,
                dir_fd=parent,
            )
            created = True
            view = memoryview(data)
            written = 0
            while written < len(view):
                count = os.write(member, view[written:])
                if count < 1:
                    raise RuntimeError("canary output write was truncated")
                written += count
            os.fsync(member)
            metadata = os.fstat(member)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
                or metadata.st_size != len(data)
            ):
                raise RuntimeError("canary output member is not private")
            os.close(member)
            member = -1
            os.fsync(parent)
            self._require_current()
        except Exception:
            if member >= 0:
                os.close(member)
            if created:
                with suppress(OSError):
                    os.unlink(parts[-1], dir_fd=parent)
            raise
        finally:
            os.close(parent)

    def close(self) -> None:
        if not self._closed:
            os.close(self._directory_descriptor)
            self._closed = True


def _verify_trusted_canary_output_privacy_signature(
    _request: OwnerDecisionRequest,
    _resolution: OwnerDecisionResolution,
) -> None:
    """Bootstrap seam; self-sealed JSON never authorizes readable output."""

    from ..evaluation.owner_quality_canary_authorization import OwnerDecisionRequired

    raise OwnerDecisionRequired("trusted_canary_output_privacy_verifier_missing")


def load_verified_canary_output_private_root(
    *,
    root: Path,
    project_root: Path,
    owner_decision_root: Path,
    runtime_implementation_sha256: str,
    integration_sha: str,
) -> VerifiedCanaryOutputPrivateRoot:
    """Map a signed path-free decision back to the exact caller-supplied root.

    The request and resolution remain descriptive until the trusted signature
    seam succeeds.  Recomputing the filesystem identity after that check makes
    path substitution, directory replacement, and stale request reuse fail.
    """

    root_identity = private_root_identity(root, project_root=project_root)
    decision_id = canary_output_privacy_decision_id(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256=runtime_implementation_sha256,
        integration_sha=integration_sha,
    )
    try:
        request = OwnerDecisionRequest.model_validate_json(
            read_private_owner_decision_member(owner_decision_root, decision_id, "request.json")
        )
        resolution = OwnerDecisionResolution.model_validate_json(
            read_private_owner_decision_member(owner_decision_root, decision_id, "resolution.json")
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise PermissionError("OWNER_DECISION_REQUIRED") from exc
    expected = build_canary_output_privacy_decision_request(
        root_identity_sha256=root_identity,
        runtime_implementation_sha256=runtime_implementation_sha256,
        integration_sha=integration_sha,
        created_at=request.created_at,
    )
    if request != expected:
        raise PermissionError("OWNER_DECISION_REQUIRED")
    try:
        verified = require_owner_resolution(request, resolution)
    except PermissionError as exc:
        raise PermissionError("OWNER_DECISION_REQUIRED") from exc
    if verified.selected_option_id != "approve-owner-private-nonsynced-root":
        raise PermissionError("OWNER_DECISION_REQUIRED")
    _verify_trusted_canary_output_privacy_signature(request, verified)
    # Re-resolve after signature verification to close replacement during the
    # potentially interactive/hardware-backed verification boundary.
    descriptor, final_root_identity, filesystem_identity = _open_private_root_descriptor(
        root,
        project_root=project_root,
    )
    if final_root_identity != root_identity:
        os.close(descriptor)
        raise RuntimeError("canary output private root changed during verification")
    try:
        return VerifiedCanaryOutputPrivateRoot(
            root=root,
            project_root=project_root,
            directory_descriptor=descriptor,
            filesystem_identity=filesystem_identity,
            root_identity_sha256=root_identity,
            request_seal_sha256=request.seal_sha256,
            resolution_seal_sha256=verified.seal_sha256,
            _token=_VERIFIED_PRIVATE_ROOT_TOKEN,
        )
    except Exception:
        os.close(descriptor)
        raise


__all__ = [
    "MEMORY_DECISION_OPTIONS",
    "MEMORY_DECISION_SCOPE_PREFIX",
    "PRIVACY_DECISION_OPTIONS",
    "VerifiedCanaryOutputPrivateRoot",
    "build_canary_output_privacy_decision_request",
    "build_completion_memory_decision_request",
    "canary_output_privacy_decision_id",
    "completion_memory_decision_id",
    "load_verified_canary_output_private_root",
    "private_root_identity",
    "read_private_owner_decision_member",
    "require_exact_clean_head",
]
