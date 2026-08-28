from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.governance import v111_owner_public_key as key_module
from app.governance.v111_owner_decision_package import public_key_sha256
from app.governance.v111_owner_public_key import (
    load_pinned_owner_public_key,
    observe_owner_public_key,
    require_owner_public_key,
)
from app.governance.v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _test_public_key_bytes() -> tuple[bytes, bytes]:
    # RFC 8032 test-vector public key.  No private key is created or retained.
    raw = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    public_key = Ed25519PublicKey.from_public_bytes(raw)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return raw, pem


def _key_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize("encoding", ["raw", "pem"])
def test_owner_public_key_observation_uses_package_canonical_digest(
    tmp_path: Path,
    encoding: str,
) -> None:
    project = _private_directory(tmp_path / "project")
    key_root = _private_directory(tmp_path / "owner-key")
    raw, pem = _test_public_key_bytes()
    key_bytes = raw if encoding == "raw" else pem
    key_path = _key_file(key_root / f"owner.{encoding}", key_bytes)
    settings = Phase2LocalConfiguration(
        project_root=project,
        owner_public_key_path=key_path,
    )

    observation = observe_owner_public_key(settings)
    pinned = load_pinned_owner_public_key(settings)

    assert observation.public_key_sha256 == public_key_sha256(raw)
    assert pinned.observation == observation
    assert pinned.public_key_bytes == key_bytes
    assert key_bytes.hex() not in repr(pinned)
    assert pinned.authorizing is False
    assert len(observation.identity_sha256) == 64
    assert len(observation.parent_root_identity_sha256) == 64
    assert observation.authorizing is False
    assert str(key_path) not in repr(observation)
    assert raw.hex() not in repr(observation)
    with pytest.raises(Phase2PreparationStop) as exc_info:
        require_owner_public_key(settings)
    assert exc_info.value.reason_code == "trusted_phase2_owner_decision_package_verifier_missing"


def test_owner_public_key_missing_invalid_or_unsafe_fails_closed(tmp_path: Path) -> None:
    project = _private_directory(tmp_path / "project")
    with pytest.raises(Phase2PreparationStop) as missing:
        observe_owner_public_key(Phase2LocalConfiguration(project_root=project))
    assert missing.value.reason_code == "owner_public_key_not_provisioned"

    inside_root = _private_directory(project / "owner-key")
    inside = _key_file(inside_root / "owner.raw", _test_public_key_bytes()[0])
    with pytest.raises(Phase2PreparationStop) as project_local:
        observe_owner_public_key(
            Phase2LocalConfiguration(project_root=project, owner_public_key_path=inside)
        )
    assert project_local.value.reason_code == "phase2_external_path_inside_project"

    key_root = _private_directory(tmp_path / "outside-owner-key")
    invalid = _key_file(key_root / "invalid.pem", b"not an Ed25519 public key")
    with pytest.raises(Phase2PreparationStop) as invalid_key:
        observe_owner_public_key(
            Phase2LocalConfiguration(project_root=project, owner_public_key_path=invalid)
        )
    assert invalid_key.value.reason_code == "owner_public_key_invalid"

    invalid.write_bytes(_test_public_key_bytes()[0])
    invalid.chmod(0o644)
    with pytest.raises(Phase2PreparationStop) as bad_mode:
        observe_owner_public_key(
            Phase2LocalConfiguration(project_root=project, owner_public_key_path=invalid)
        )
    assert bad_mode.value.reason_code == "owner_public_key_identity_invalid"


def test_owner_public_key_read_stays_on_one_root_descriptor_during_swap_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _private_directory(tmp_path / "project")
    configured_root = _private_directory(tmp_path / "configured-key-root")
    replacement_root = _private_directory(tmp_path / "replacement-key-root")
    saved_root = tmp_path / "saved-key-root"
    raw, _pem = _test_public_key_bytes()
    replacement_raw = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    key_path = _key_file(configured_root / "owner.raw", raw)
    _key_file(replacement_root / "owner.raw", replacement_raw)
    settings = Phase2LocalConfiguration(project_root=project, owner_public_key_path=key_path)
    original_open = key_module.open_exact_private_root_descriptor
    original_require = key_module.require_exact_private_root_descriptor_current
    swapped = False

    def swap_after_open(*args: object, **kwargs: object) -> tuple[int, str]:
        nonlocal swapped
        descriptor, identity = original_open(*args, **kwargs)  # type: ignore[arg-type]
        configured_root.rename(saved_root)
        replacement_root.rename(configured_root)
        swapped = True
        return descriptor, identity

    def restore_before_replay(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        configured_root.rename(replacement_root)
        saved_root.rename(configured_root)
        swapped = False
        original_require(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(key_module, "open_exact_private_root_descriptor", swap_after_open)
    monkeypatch.setattr(
        key_module,
        "require_exact_private_root_descriptor_current",
        restore_before_replay,
    )
    try:
        pinned = load_pinned_owner_public_key(settings)
    finally:
        if swapped:
            configured_root.rename(replacement_root)
            saved_root.rename(configured_root)

    assert pinned.public_key_bytes == raw
    assert pinned.observation.public_key_sha256 == public_key_sha256(raw)
