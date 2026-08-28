from __future__ import annotations

import socket
import tempfile
from collections.abc import Iterator
from pathlib import Path
from shutil import rmtree

import pytest

from app.governance.v111_decision_generation import private_root_identity
from app.governance.v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
)
from app.model_runtime import private_uds_transport as uds_module
from app.model_runtime.private_uds_transport import (
    PRIVATE_MODEL_UDS_TRANSPORT_POLICY,
    PRIVATE_MODEL_UNIX_ENDPOINT_POLICY,
    VerifiedPrivateModelTransport,
    build_private_uds_httpx_transport,
    observe_private_model_endpoint_intent,
    observe_private_model_socket,
    require_private_model_transport,
)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _synthetic_socket(path: Path) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
    path.chmod(0o600)


@pytest.fixture
def short_tmp_path() -> Iterator[Path]:
    root = Path(tempfile.mkdtemp(prefix="lb-uds-", dir="/private/tmp"))
    root.chmod(0o700)
    try:
        yield root
    finally:
        rmtree(root)


def test_private_socket_is_observed_without_connection_or_authority(
    short_tmp_path: Path,
) -> None:
    project = _private_directory(short_tmp_path / "project")
    socket_root = _private_directory(short_tmp_path / "private-model-transport")
    socket_path = socket_root / "model.sock"
    _synthetic_socket(socket_path)
    settings = Phase2LocalConfiguration(project_root=project, model_socket_path=socket_path)

    observation = observe_private_model_socket(settings)

    assert len(observation.identity_sha256) == 64
    assert len(observation.parent_root_identity_sha256) == 64
    assert observation.authorizing is False
    assert str(socket_path) not in repr(observation)
    with pytest.raises(Phase2PreparationStop) as exc_info:
        require_private_model_transport(settings)
    assert exc_info.value.reason_code == "trusted_phase2_owner_decision_package_verifier_missing"


def test_endpoint_intent_is_deterministic_path_free_and_does_not_create_socket(
    short_tmp_path: Path,
) -> None:
    project = _private_directory(short_tmp_path / "project")
    socket_root = _private_directory(short_tmp_path / "private-model-endpoint")
    socket_path = socket_root / "model.sock"
    settings = Phase2LocalConfiguration(project_root=project, model_socket_path=socket_path)

    first = observe_private_model_endpoint_intent(settings)
    second = observe_private_model_endpoint_intent(settings)

    assert first == second
    assert first.authorizing is False
    assert len(first.identity_sha256) == 64
    assert len(first.lexical_socket_path_sha256) == 64
    assert first.parent_root_identity_sha256 == private_root_identity(
        socket_root,
        project_root=project,
    )
    assert len(first.endpoint_policy_sha256) == 64
    assert len(first.transport_policy_sha256) == 64
    assert str(socket_path) not in repr(first)
    assert str(socket_root) not in repr(first)
    assert not socket_path.exists()
    assert PRIVATE_MODEL_UNIX_ENDPOINT_POLICY.address_family == "AF_UNIX"
    assert PRIVATE_MODEL_UNIX_ENDPOINT_POLICY.socket_type == "SOCK_STREAM"
    assert PRIVATE_MODEL_UNIX_ENDPOINT_POLICY.required_parent_mode_octal == "0700"
    assert PRIVATE_MODEL_UNIX_ENDPOINT_POLICY.required_socket_mode_octal == "0600"
    assert PRIVATE_MODEL_UDS_TRANSPORT_POLICY.uds_only is True
    assert PRIVATE_MODEL_UDS_TRANSPORT_POLICY.network_fallback_allowed is False
    assert PRIVATE_MODEL_UDS_TRANSPORT_POLICY.trust_env is False
    assert PRIVATE_MODEL_UDS_TRANSPORT_POLICY.retries == 0


def test_endpoint_intent_is_stable_across_socket_instances_and_binds_exact_path(
    short_tmp_path: Path,
) -> None:
    project = _private_directory(short_tmp_path / "project")
    socket_root = _private_directory(short_tmp_path / "private-model-endpoint")
    socket_path = socket_root / "model.sock"
    settings = Phase2LocalConfiguration(project_root=project, model_socket_path=socket_path)

    absent = observe_private_model_endpoint_intent(settings)
    _synthetic_socket(socket_path)
    first_instance = observe_private_model_socket(settings)
    present = observe_private_model_endpoint_intent(settings)
    socket_path.unlink()
    _synthetic_socket(socket_path)
    replacement_instance = observe_private_model_socket(settings)
    replaced = observe_private_model_endpoint_intent(settings)

    assert absent == present == replaced
    assert first_instance.parent_root_identity_sha256 == absent.parent_root_identity_sha256
    assert replacement_instance.parent_root_identity_sha256 == absent.parent_root_identity_sha256

    alternate = observe_private_model_endpoint_intent(
        Phase2LocalConfiguration(
            project_root=project,
            model_socket_path=socket_root / "alternate.sock",
        )
    )
    assert alternate.parent_root_identity_sha256 == absent.parent_root_identity_sha256
    assert alternate.lexical_socket_path_sha256 != absent.lexical_socket_path_sha256
    assert alternate.identity_sha256 != absent.identity_sha256

    lexical_alias = socket_root / ".." / socket_root.name / socket_path.name
    with pytest.raises(Phase2PreparationStop) as noncanonical:
        observe_private_model_endpoint_intent(
            Phase2LocalConfiguration(project_root=project, model_socket_path=lexical_alias)
        )
    assert noncanonical.value.reason_code == "private_model_socket_path_invalid"


def test_endpoint_intent_requires_safe_existing_external_parent(
    short_tmp_path: Path,
) -> None:
    project = _private_directory(short_tmp_path / "project")

    with pytest.raises(Phase2PreparationStop) as not_configured:
        observe_private_model_endpoint_intent(Phase2LocalConfiguration(project_root=project))
    assert not_configured.value.reason_code == "private_model_endpoint_not_configured"

    with pytest.raises(Phase2PreparationStop) as missing_parent:
        observe_private_model_endpoint_intent(
            Phase2LocalConfiguration(
                project_root=project,
                model_socket_path=short_tmp_path / "missing" / "model.sock",
            )
        )
    assert missing_parent.value.reason_code == "private_model_socket_parent_not_private"

    permissive_parent = _private_directory(short_tmp_path / "permissive-parent")
    permissive_parent.chmod(0o755)
    with pytest.raises(Phase2PreparationStop) as wrong_parent_mode:
        observe_private_model_endpoint_intent(
            Phase2LocalConfiguration(
                project_root=project,
                model_socket_path=permissive_parent / "model.sock",
            )
        )
    assert wrong_parent_mode.value.reason_code == "private_model_socket_parent_not_private"

    with pytest.raises(Phase2PreparationStop) as project_local:
        observe_private_model_endpoint_intent(
            Phase2LocalConfiguration(
                project_root=project,
                model_socket_path=_private_directory(project / "transport") / "model.sock",
            )
        )
    assert project_local.value.reason_code == "phase2_external_path_inside_project"


def test_endpoint_intent_rejects_symlinked_parent_or_socket_path(
    short_tmp_path: Path,
) -> None:
    project = _private_directory(short_tmp_path / "project")
    socket_root = _private_directory(short_tmp_path / "socket-root")
    parent_alias = short_tmp_path / "socket-root-alias"
    parent_alias.symlink_to(socket_root, target_is_directory=True)

    with pytest.raises(Phase2PreparationStop) as symlinked_parent:
        observe_private_model_endpoint_intent(
            Phase2LocalConfiguration(
                project_root=project,
                model_socket_path=parent_alias / "model.sock",
            )
        )
    assert symlinked_parent.value.reason_code == "phase2_external_path_unsafe"

    target = socket_root / "target.sock"
    alias = socket_root / "alias.sock"
    alias.symlink_to(target)
    with pytest.raises(Phase2PreparationStop) as symlinked_socket:
        observe_private_model_endpoint_intent(
            Phase2LocalConfiguration(project_root=project, model_socket_path=alias)
        )
    assert symlinked_socket.value.reason_code == "phase2_external_path_unsafe"


def test_private_socket_missing_inside_project_and_wrong_mode_fail_closed(
    short_tmp_path: Path,
) -> None:
    project = _private_directory(short_tmp_path / "project")
    with pytest.raises(Phase2PreparationStop) as missing:
        observe_private_model_socket(
            Phase2LocalConfiguration(project_root=project, model_socket_path=None)
        )
    assert missing.value.reason_code == "private_model_socket_not_provisioned"

    inside = _private_directory(project / "transport") / "model.sock"
    _synthetic_socket(inside)
    with pytest.raises(Phase2PreparationStop) as project_local:
        observe_private_model_socket(
            Phase2LocalConfiguration(project_root=project, model_socket_path=inside)
        )
    assert project_local.value.reason_code == "phase2_external_path_inside_project"

    outside_root = _private_directory(short_tmp_path / "outside-transport")
    wrong_mode = outside_root / "model.sock"
    _synthetic_socket(wrong_mode)
    wrong_mode.chmod(0o644)
    with pytest.raises(Phase2PreparationStop) as unsafe_mode:
        observe_private_model_socket(
            Phase2LocalConfiguration(project_root=project, model_socket_path=wrong_mode)
        )
    assert unsafe_mode.value.reason_code == "private_model_socket_identity_invalid"


def test_socket_symlink_and_forged_transport_are_rejected(short_tmp_path: Path) -> None:
    project = _private_directory(short_tmp_path / "project")
    socket_root = _private_directory(short_tmp_path / "socket-root")
    target = socket_root / "target.sock"
    _synthetic_socket(target)
    alias = socket_root / "alias.sock"
    alias.symlink_to(target)
    with pytest.raises(Phase2PreparationStop):
        observe_private_model_socket(
            Phase2LocalConfiguration(project_root=project, model_socket_path=alias)
        )

    observation = observe_private_model_socket(
        Phase2LocalConfiguration(project_root=project, model_socket_path=target)
    )
    with pytest.raises(TypeError, match="trusted private model transport"):
        VerifiedPrivateModelTransport(
            observation=observation,
            project_root=project,
            package_sha256="1" * 64,
            _token=object(),
        )
    with pytest.raises(RuntimeError, match="was not verified"):
        build_private_uds_httpx_transport(object())

    verified = VerifiedPrivateModelTransport(
        observation=observation,
        project_root=project,
        package_sha256="1" * 64,
        _token=uds_module._VERIFIED_PRIVATE_MODEL_TRANSPORT_TOKEN,
    )
    with pytest.raises(AttributeError, match="immutable"):
        verified.package_sha256 = "2" * 64
    with pytest.raises(AttributeError, match="immutable"):
        verified._observation = observation
    with pytest.raises(Phase2PreparationStop) as connect_time_gap:
        build_private_uds_httpx_transport(verified)
    assert (
        connect_time_gap.value.reason_code
        == "private_model_exact_connect_time_identity_enforcement_missing"
    )
