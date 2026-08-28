"""Fail-closed POSIX I/O for private, create-only evaluation artifacts.

All traversal below is anchored by an already-open directory descriptor.  A
pathname is never checked and then reopened for the operation that matters.
This is intentionally POSIX-only: owner-quality canary review is a local
macOS/Linux workflow and must stop when ``dir_fd``/``O_NOFOLLOW`` semantics are
not available.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int):
        raise RuntimeError(f"private artifact I/O requires {name}")
    return value


_O_DIRECTORY = _required_flag("O_DIRECTORY")
_O_NOFOLLOW = _required_flag("O_NOFOLLOW")
_O_CLOEXEC = int(getattr(os, "O_CLOEXEC", 0))
_DIRECTORY_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC


def _component(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\x00" in value:
        raise ValueError("private artifact path contains an unsafe component")
    return value


def _parts(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(_component(str(value)) for value in values)


def _directory_fd(path: Path) -> int:
    try:
        descriptor = os.open(os.fspath(path.absolute()), _DIRECTORY_FLAGS)
    except OSError as exc:
        raise ValueError("private artifact anchor is missing or unsafe") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("private artifact anchor is not a directory")
    return descriptor


@contextmanager
def open_directory_at(
    anchor: Path,
    relative_parts: Sequence[str] = (),
    *,
    create: bool = False,
    private_mode: int | None = None,
) -> Iterator[int]:
    """Open one no-follow directory chain and yield its final descriptor."""

    parts = _parts(relative_parts)
    current = _directory_fd(anchor)
    try:
        for part in parts:
            if create:
                with suppress(FileExistsError):
                    os.mkdir(part, mode=private_mode or 0o700, dir_fd=current)
            try:
                following = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise ValueError(
                    "private artifact directory chain is missing, unsafe, or contains a symlink"
                ) from exc
            os.close(current)
            current = following
            metadata = os.fstat(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("private artifact path component is not a directory")
            if private_mode is not None:
                os.fchmod(current, private_mode)
        yield current
    finally:
        os.close(current)


def create_private_directory_at(
    anchor: Path,
    relative_parts: Sequence[str],
    *,
    exist_ok: bool,
) -> None:
    """Create the final 0700 directory without following any path component."""

    parts = _parts(relative_parts)
    if not parts:
        raise ValueError("private directory requires a relative component")
    with open_directory_at(anchor, parts[:-1], create=True, private_mode=0o700) as parent_fd:
        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            if not exist_ok:
                raise FileExistsError("private artifact directory already exists") from None
        try:
            child_fd = os.open(parts[-1], _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise ValueError("private artifact directory is unsafe or a symlink") from exc
        try:
            if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                raise ValueError("private artifact component is not a directory")
            os.fchmod(child_fd, 0o700)
        finally:
            os.close(child_fd)


def write_create_only_at(directory_fd: int, name: str, payload: bytes) -> None:
    """Create one 0600 regular file relative to a verified directory fd."""

    safe_name = _component(name)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(safe_name, _CREATE_FLAGS, 0o600, dir_fd=directory_fd)
        created = True
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("private artifact destination is not a regular file")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short private artifact write")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except FileExistsError:
        raise
    except Exception:
        if created:
            with suppress(OSError):
                os.unlink(safe_name, dir_fd=directory_fd)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_private_file_at(anchor: Path, relative_parts: Sequence[str], payload: bytes) -> None:
    parts = _parts(relative_parts)
    if not parts:
        raise ValueError("private artifact file requires a relative name")
    with open_directory_at(anchor, parts[:-1]) as parent_fd:
        if stat.S_IMODE(os.fstat(parent_fd).st_mode) != 0o700:
            raise ValueError("private artifact parent must have mode 0700")
        write_create_only_at(parent_fd, parts[-1], payload)


def _read_open_descriptor(descriptor: int) -> bytes:
    """Read one regular descriptor and prove its identity stayed stable."""

    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("private artifact is not a regular file")
    chunks: list[bytes] = []
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        chunks.append(block)
    data = b"".join(chunks)
    if len(data) != metadata.st_size:
        raise ValueError("private artifact changed while it was read")
    final = os.fstat(descriptor)
    if (
        final.st_dev != metadata.st_dev
        or final.st_ino != metadata.st_ino
        or final.st_size != metadata.st_size
        or final.st_mtime_ns != metadata.st_mtime_ns
        or final.st_ctime_ns != metadata.st_ctime_ns
    ):
        raise ValueError("private artifact identity changed while it was read")
    return data


@contextmanager
def open_file_at(
    directory_fd: int, name: str, *, required_mode: int | None = 0o600
) -> Iterator[int]:
    """Yield one verified no-follow regular child descriptor."""

    safe_name = _component(name)
    try:
        descriptor = os.open(safe_name, _READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise ValueError("private artifact file is missing or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("private artifact is not a regular file")
        if required_mode is not None and stat.S_IMODE(metadata.st_mode) != required_mode:
            raise ValueError("private artifact file is not owner-private")
        yield descriptor
        final = os.fstat(descriptor)
        if (
            final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
            or final.st_size != metadata.st_size
            or final.st_mtime_ns != metadata.st_mtime_ns
            or final.st_ctime_ns != metadata.st_ctime_ns
        ):
            raise ValueError("private artifact identity changed while it was open")
    finally:
        os.close(descriptor)


def read_file_at(directory_fd: int, name: str, *, required_mode: int | None = 0o600) -> bytes:
    """Read and validate one file through the same no-follow descriptor."""

    with open_file_at(directory_fd, name, required_mode=required_mode) as descriptor:
        return _read_open_descriptor(descriptor)


def set_file_mode_at(directory_fd: int, name: str, mode: int = 0o600) -> None:
    """Set a regular no-follow child file's mode through its open descriptor."""

    safe_name = _component(name)
    descriptor = os.open(safe_name, _READ_FLAGS, dir_fd=directory_fd)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("private artifact is not a regular file")
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def read_private_file_at(
    anchor: Path,
    relative_parts: Sequence[str],
    *,
    required_parent_mode: int | None = 0o700,
    required_file_mode: int | None = 0o600,
) -> bytes:
    parts = _parts(relative_parts)
    if not parts:
        raise ValueError("private artifact file requires a relative name")
    with open_directory_at(anchor, parts[:-1]) as parent_fd:
        if (
            required_parent_mode is not None
            and stat.S_IMODE(os.fstat(parent_fd).st_mode) != required_parent_mode
        ):
            raise ValueError("private artifact parent must have mode 0700")
        return read_file_at(parent_fd, parts[-1], required_mode=required_file_mode)


@contextmanager
def open_private_file_at(
    anchor: Path,
    relative_parts: Sequence[str],
    *,
    required_parent_mode: int | None = 0o700,
    required_file_mode: int | None = 0o600,
) -> Iterator[tuple[int, bytes]]:
    """Yield a retained descriptor plus the exact bytes read from that descriptor."""

    parts = _parts(relative_parts)
    if not parts:
        raise ValueError("private artifact file requires a relative name")
    with open_directory_at(anchor, parts[:-1]) as parent_fd:
        if (
            required_parent_mode is not None
            and stat.S_IMODE(os.fstat(parent_fd).st_mode) != required_parent_mode
        ):
            raise ValueError("private artifact parent must have mode 0700")
        with open_file_at(
            parent_fd,
            parts[-1],
            required_mode=required_file_mode,
        ) as descriptor:
            data = _read_open_descriptor(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            yield descriptor, data


def list_directory_at(anchor: Path, relative_parts: Sequence[str]) -> tuple[str, ...]:
    with open_directory_at(anchor, relative_parts) as directory_fd:
        return tuple(sorted(str(name) for name in os.listdir(directory_fd)))


def unlink_file_at(anchor: Path, relative_parts: Sequence[str], *, missing_ok: bool) -> None:
    parts = _parts(relative_parts)
    if not parts:
        raise ValueError("private artifact file requires a relative name")
    with open_directory_at(anchor, parts[:-1]) as parent_fd:
        try:
            os.unlink(parts[-1], dir_fd=parent_fd)
        except FileNotFoundError:
            if not missing_ok:
                raise
