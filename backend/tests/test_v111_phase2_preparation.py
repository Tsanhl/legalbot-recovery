from __future__ import annotations

from pathlib import Path

import pytest

from app.governance import v111_phase2_preparation as preparation
from app.governance.v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
    configured_phase2_review_roots,
    observe_phase2_review_root_set,
    phase2_preparation_status,
    require_verified_phase2_review_root_set,
)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _settings(
    project: Path,
    roots: tuple[Path, Path, Path],
) -> Phase2LocalConfiguration:
    return Phase2LocalConfiguration(
        project_root=project,
        development_review_root=roots[0],
        sealed_validation_review_root=roots[1],
        live_review_root=roots[2],
        model_socket_path=None,
        local_session_secret_path=None,
    )


def test_phase2_configuration_loads_environment_without_creating_resources(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project-does-not-need-to-exist"
    development = tmp_path / "development-does-not-exist"
    validation = tmp_path / "validation-does-not-exist"
    live = tmp_path / "live-does-not-exist"
    socket_path = tmp_path / "model-does-not-exist.sock"
    session_secret = tmp_path / "session-secret-does-not-exist"
    public_key = tmp_path / "owner-public-key-does-not-exist"
    configuration = Phase2LocalConfiguration.from_environment(
        project_root=project,
        environ={
            "LEGALBOT_HOST": "127.0.0.1",
            "LEGALBOT_PORT": "9888",
            "LEGALBOT_DEVELOPMENT_REVIEW_ROOT": str(development),
            "LEGALBOT_SEALED_VALIDATION_REVIEW_ROOT": str(validation),
            "LEGALBOT_LIVE_REVIEW_ROOT": str(live),
            "LEGALBOT_MODEL_SOCKET_PATH": str(socket_path),
            "LEGALBOT_LOCAL_SESSION_SECRET_PATH": str(session_secret),
            "LEGALBOT_OWNER_PUBLIC_KEY_PATH": str(public_key),
        },
    )

    assert configuration == Phase2LocalConfiguration(
        project_root=project,
        bind_host="127.0.0.1",
        port=9888,
        development_review_root=development,
        sealed_validation_review_root=validation,
        live_review_root=live,
        model_socket_path=socket_path,
        local_session_secret_path=session_secret,
        owner_public_key_path=public_key,
    )
    assert all(
        not path.exists()
        for path in (
            project,
            development,
            validation,
            live,
            socket_path,
            session_secret,
            public_key,
        )
    )


def test_phase2_status_is_path_free_closed_and_noncreating(tmp_path: Path) -> None:
    project = _private_directory(tmp_path / "project")
    roots = (
        tmp_path / "development-owner-review",
        tmp_path / "sealed-validation-owner-review",
        tmp_path / "live-owner-review",
    )
    settings = _settings(project, roots)

    assert configured_phase2_review_roots(settings) == {
        "development": roots[0],
        "sealed_validation": roots[1],
        "live": roots[2],
    }
    status = phase2_preparation_status(settings)

    assert status["schema"] == "legalbot.v111-phase2-preparation-status.v1"
    assert status["authorizing"] is False
    assert status["phase2_ready"] is False
    assert status["created_resources"] is False
    assert set(status["resource_identities"]) == {"local_owner_request_policy_sha256"}
    assert len(status["resource_identities"]["local_owner_request_policy_sha256"]) == 64
    assert set(status["blocking_reason_codes"]) == {
        "local_session_secret_not_provisioned",
        "owner_public_key_not_provisioned",
        "phase2_review_root_identity_unavailable",
        "private_model_endpoint_not_configured",
        "private_model_socket_not_provisioned",
        "trusted_phase2_owner_decision_package_verifier_missing",
    }
    assert all(not root.exists() for root in roots)
    assert all(str(root) not in str(status) for root in roots)


def test_three_existing_roots_are_distinct_but_still_not_authority(tmp_path: Path) -> None:
    project = _private_directory(tmp_path / "project")
    roots = tuple(
        _private_directory(tmp_path / name)
        for name in ("development-review", "sealed-validation-review", "live-review")
    )
    settings = _settings(project, roots)  # type: ignore[arg-type]

    observation = observe_phase2_review_root_set(settings)

    identities = {
        observation.development_root_identity_sha256,
        observation.sealed_validation_root_identity_sha256,
        observation.live_root_identity_sha256,
    }
    assert len(identities) == 3
    assert observation.authorizing is False
    assert len(observation.root_set_identity_sha256) == 64
    with pytest.raises(Phase2PreparationStop) as exc_info:
        require_verified_phase2_review_root_set(settings)
    assert exc_info.value.reason_code == "trusted_phase2_owner_decision_package_verifier_missing"


def test_equal_nested_and_known_sync_roots_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _private_directory(tmp_path / "project")
    shared = tmp_path / "shared"
    equal = Phase2LocalConfiguration(
        project_root=project,
        development_review_root=shared,
        sealed_validation_review_root=shared,
        live_review_root=tmp_path / "live",
    )
    with pytest.raises(Phase2PreparationStop) as equal_error:
        configured_phase2_review_roots(equal)
    assert equal_error.value.reason_code == "phase2_review_roots_not_isolated"

    nested = Phase2LocalConfiguration(
        project_root=project,
        development_review_root=shared,
        sealed_validation_review_root=shared / "validation",
        live_review_root=tmp_path / "live",
    )
    with pytest.raises(Phase2PreparationStop) as nested_error:
        configured_phase2_review_roots(nested)
    assert nested_error.value.reason_code == "phase2_review_roots_not_isolated"

    sync_root = tmp_path / "synthetic-cloud-sync"
    monkeypatch.setattr(preparation, "_known_sync_roots", lambda: (sync_root,))
    synced = Phase2LocalConfiguration(
        project_root=project,
        development_review_root=sync_root / "development",
        sealed_validation_review_root=tmp_path / "validation",
        live_review_root=tmp_path / "live",
    )
    with pytest.raises(Phase2PreparationStop) as sync_error:
        configured_phase2_review_roots(synced)
    assert sync_error.value.reason_code == "phase2_external_path_known_sync_location"


def test_missing_live_root_keeps_all_three_lane_boundary_closed(tmp_path: Path) -> None:
    project = _private_directory(tmp_path / "project")
    settings = Phase2LocalConfiguration(
        project_root=project,
        development_review_root=tmp_path / "development",
        sealed_validation_review_root=tmp_path / "validation",
        live_review_root=None,
    )
    with pytest.raises(Phase2PreparationStop) as exc_info:
        configured_phase2_review_roots(settings)
    assert exc_info.value.reason_code == "phase2_review_roots_not_provisioned"
