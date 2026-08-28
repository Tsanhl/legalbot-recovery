"""Fail-closed observation of the owner-pinned v1.11 Ed25519 public key.

The key is provisioned by the owner outside the repository as either exactly
32 raw Ed25519 public-key bytes or a PEM public key.  This module neither
creates keys nor grants authority.  It records a path-free identity and uses
the owner-decision package's canonical raw-key digest helper so signature
verification and preparation diagnostics cannot disagree about key identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .v111_exact_private_root import (
    open_exact_private_root_descriptor,
    require_exact_private_root_descriptor_current,
)
from .v111_owner_decision_package import public_key_sha256
from .v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
    require_external_nonsynced_path_configuration,
)

OWNER_PUBLIC_KEY_OBSERVATION_SCHEMA = "legalbot.v111-owner-public-key-observation.v1"
_MAX_OWNER_PUBLIC_KEY_BYTES = 4096


def _sealed_sha256(value: object) -> str:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class OwnerPublicKeyObservation:
    """Path-free identity of one existing private Ed25519 public-key file."""

    identity_sha256: str
    public_key_sha256: str
    parent_root_identity_sha256: str
    public_key_path: Path = field(repr=False, compare=False)
    authorizing: Literal[False] = False


@dataclass(frozen=True, slots=True)
class PinnedOwnerPublicKey:
    """Observed public verification bytes; never an owner-authority capability."""

    observation: OwnerPublicKeyObservation
    public_key_bytes: bytes = field(repr=False, compare=False)
    authorizing: Literal[False] = False


def _file_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_owner_public_key_path(
    path: Path,
    *,
    project_root: Path,
) -> tuple[OwnerPublicKeyObservation, bytes]:
    key_path = require_external_nonsynced_path_configuration(
        path,
        project_root=project_root,
    )
    if key_path.name in {"", ".", ".."}:
        raise Phase2PreparationStop("owner_public_key_path_invalid")
    parent = key_path.parent
    try:
        parent_descriptor, parent_identity = open_exact_private_root_descriptor(
            parent,
            project_root=project_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise Phase2PreparationStop("owner_public_key_parent_not_private") from exc

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        os.close(parent_descriptor)
        raise Phase2PreparationStop("owner_public_key_secure_read_unavailable")

    member_descriptor = -1
    try:
        member_descriptor = os.open(
            key_path.name,
            os.O_RDONLY | no_follow,
            dir_fd=parent_descriptor,
        )
        before = os.fstat(member_descriptor)
        path_before = os.stat(
            key_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_OWNER_PUBLIC_KEY_BYTES
            or _file_identity(before) != _file_identity(path_before)
        ):
            raise Phase2PreparationStop("owner_public_key_identity_invalid")

        blocks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(member_descriptor, min(remaining, 4096))
            if not block:
                raise Phase2PreparationStop("owner_public_key_changed_during_read")
            blocks.append(block)
            remaining -= len(block)
        if os.read(member_descriptor, 1):
            raise Phase2PreparationStop("owner_public_key_changed_during_read")
        key_bytes = b"".join(blocks)

        after = os.fstat(member_descriptor)
        path_after = os.stat(
            key_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if _file_identity(before) != _file_identity(after) or _file_identity(
            before
        ) != _file_identity(path_after):
            raise Phase2PreparationStop("owner_public_key_changed_during_read")
        try:
            require_exact_private_root_descriptor_current(
                parent_descriptor,
                root=parent,
                project_root=project_root,
                expected_identity_sha256=parent_identity,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise Phase2PreparationStop("owner_public_key_parent_changed") from exc
    except Phase2PreparationStop:
        raise
    except OSError as exc:
        raise Phase2PreparationStop("owner_public_key_not_provisioned") from exc
    finally:
        if member_descriptor >= 0:
            os.close(member_descriptor)
        os.close(parent_descriptor)

    try:
        canonical_key_sha256 = public_key_sha256(key_bytes)
    except (TypeError, ValueError) as exc:
        raise Phase2PreparationStop("owner_public_key_invalid") from exc

    lexical_path_sha256 = hashlib.sha256(
        b"legalbot.v111-owner-public-key-path.v1\x00" + os.fsencode(key_path)
    ).hexdigest()
    identity = _sealed_sha256(
        {
            "schema": OWNER_PUBLIC_KEY_OBSERVATION_SCHEMA,
            "lexical_path_sha256": lexical_path_sha256,
            "parent_root_identity_sha256": parent_identity,
            "device": before.st_dev,
            "inode": before.st_ino,
            "owner_uid": before.st_uid,
            "mode": stat.S_IMODE(before.st_mode),
            "link_count": before.st_nlink,
            "size": before.st_size,
            "file_sha256": hashlib.sha256(key_bytes).hexdigest(),
            "public_key_sha256": canonical_key_sha256,
        }
    )
    return (
        OwnerPublicKeyObservation(
            identity_sha256=identity,
            public_key_sha256=canonical_key_sha256,
            parent_root_identity_sha256=parent_identity,
            public_key_path=key_path,
        ),
        key_bytes,
    )


def observe_owner_public_key(
    settings: Phase2LocalConfiguration,
) -> OwnerPublicKeyObservation:
    """Observe a pinned raw/PEM key file without exposing or retaining bytes."""

    if settings.owner_public_key_path is None:
        raise Phase2PreparationStop("owner_public_key_not_provisioned")
    observation, _key_bytes = _read_owner_public_key_path(
        settings.owner_public_key_path,
        project_root=settings.project_root,
    )
    return observation


def load_pinned_owner_public_key(
    settings: Phase2LocalConfiguration,
) -> PinnedOwnerPublicKey:
    """Load only the key at the configured, external, securely observed path."""

    if settings.owner_public_key_path is None:
        raise Phase2PreparationStop("owner_public_key_not_provisioned")
    observation, key_bytes = _read_owner_public_key_path(
        settings.owner_public_key_path,
        project_root=settings.project_root,
    )
    return PinnedOwnerPublicKey(
        observation=observation,
        public_key_bytes=key_bytes,
    )


def require_owner_public_key(
    settings: Phase2LocalConfiguration,
) -> OwnerPublicKeyObservation:
    """Remain closed until a signed package binds this exact observation."""

    observe_owner_public_key(settings)
    raise Phase2PreparationStop("trusted_phase2_owner_decision_package_verifier_missing")


__all__ = [
    "OWNER_PUBLIC_KEY_OBSERVATION_SCHEMA",
    "OwnerPublicKeyObservation",
    "PinnedOwnerPublicKey",
    "load_pinned_owner_public_key",
    "observe_owner_public_key",
    "require_owner_public_key",
]
