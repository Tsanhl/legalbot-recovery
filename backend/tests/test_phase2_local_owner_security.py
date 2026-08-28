from __future__ import annotations

from pathlib import Path

import pytest

from app.api import local_owner_security as security_module
from app.api.local_owner_security import (
    LocalRequestSecurityError,
    VerifiedLocalOwnerSecurity,
    configured_literal_loopback_request_policy,
    derive_local_session_tokens,
    literal_loopback_request_policy,
    observe_local_session_secret,
    require_local_owner_security,
    validate_literal_loopback_request,
    verify_local_owner_request,
)
from app.governance.v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path


def _secret_file(path: Path, value: bytes = b"s" * 32) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def test_secret_is_observed_but_signed_package_still_required(tmp_path: Path) -> None:
    project = _private_directory(tmp_path / "project")
    secret_root = _private_directory(tmp_path / "owner-session")
    secret_path = _secret_file(secret_root / "session-secret")
    settings = Phase2LocalConfiguration(
        project_root=project,
        local_session_secret_path=secret_path,
    )

    observation = observe_local_session_secret(settings)

    assert len(observation.identity_sha256) == 64
    assert observation.authorizing is False
    assert str(secret_path) not in repr(observation)
    assert (b"s" * 32).decode() not in repr(observation)
    capability = VerifiedLocalOwnerSecurity(
        observation=observation,
        policy=literal_loopback_request_policy(8777),
        secret=b"s" * 32,
        package_sha256="1" * 64,
        _token=security_module._VERIFIED_LOCAL_OWNER_SECURITY_TOKEN,
    )
    with pytest.raises(AttributeError, match="immutable"):
        capability._secret = b"x" * 32
    with pytest.raises(AttributeError, match="immutable"):
        capability.package_sha256 = "2" * 64
    with pytest.raises(Phase2PreparationStop) as exc_info:
        require_local_owner_security(settings)
    assert exc_info.value.reason_code == "trusted_phase2_owner_decision_package_verifier_missing"


def test_literal_127_session_and_csrf_policy(tmp_path: Path) -> None:
    del tmp_path
    secret = bytes(range(32))
    tokens = derive_local_session_tokens(secret, bytes(range(32, 64)))
    policy = literal_loopback_request_policy(8777)

    assert tokens.session_token not in repr(tokens)
    assert tokens.csrf_token not in repr(tokens)
    assert (
        configured_literal_loopback_request_policy(
            Phase2LocalConfiguration(bind_host="127.0.0.1", port=8777)
        )
        == policy
    )
    assert len(policy.identity_sha256) == 64

    validate_literal_loopback_request(
        policy=policy,
        secret=secret,
        client_host="127.0.0.1",
        host_header="127.0.0.1:8777",
        origin_header="http://127.0.0.1:8777",
        fetch_site_header="same-origin",
        method="POST",
        session_token=tokens.session_token,
        csrf_token=tokens.csrf_token,
    )
    validate_literal_loopback_request(
        policy=policy,
        secret=secret,
        client_host="127.0.0.1",
        host_header="127.0.0.1:8777",
        origin_header=None,
        fetch_site_header="none",
        method="GET",
        session_token=tokens.session_token,
        csrf_token=None,
    )


@pytest.mark.parametrize(
    ("overrides", "reason_code"),
    [
        ({"client_host": "::1"}, "local_owner_client_not_literal_loopback"),
        ({"host_header": "localhost:8777"}, "local_owner_host_header_invalid"),
        ({"origin_header": "http://localhost:8777"}, "local_owner_origin_invalid"),
        ({"fetch_site_header": "cross-site"}, "local_owner_cross_site_request_refused"),
        ({"origin_header": None}, "local_owner_mutation_origin_proof_missing"),
        ({"fetch_site_header": "same-site"}, "local_owner_mutation_origin_proof_missing"),
        ({"session_token": None}, "local_owner_session_missing"),
        ({"csrf_token": "0" * 64}, "local_owner_session_or_csrf_invalid"),
    ],
)
def test_local_request_policy_rejects_non_exact_boundaries(
    overrides: dict[str, str | None],
    reason_code: str,
) -> None:
    secret = bytes(range(32))
    tokens = derive_local_session_tokens(secret, bytes(range(32, 64)))
    values: dict[str, str | None] = {
        "client_host": "127.0.0.1",
        "host_header": "127.0.0.1:8777",
        "origin_header": "http://127.0.0.1:8777",
        "fetch_site_header": "same-origin",
        "session_token": tokens.session_token,
        "csrf_token": tokens.csrf_token,
    }
    values.update(overrides)
    with pytest.raises(LocalRequestSecurityError) as exc_info:
        validate_literal_loopback_request(
            policy=literal_loopback_request_policy(8777),
            secret=secret,
            client_host=str(values["client_host"]),
            host_header=str(values["host_header"]),
            origin_header=values["origin_header"],
            fetch_site_header=values["fetch_site_header"],
            method="POST",
            session_token=values["session_token"],
            csrf_token=values["csrf_token"],
        )
    assert exc_info.value.reason_code == reason_code


def test_secret_location_permissions_and_forged_capability_fail_closed(
    tmp_path: Path,
) -> None:
    project = _private_directory(tmp_path / "project")
    with pytest.raises(Phase2PreparationStop) as missing:
        observe_local_session_secret(Phase2LocalConfiguration(project_root=project))
    assert missing.value.reason_code == "local_session_secret_not_provisioned"

    inside_root = _private_directory(project / "secret-root")
    inside = _secret_file(inside_root / "session-secret")
    with pytest.raises(Phase2PreparationStop) as project_local:
        observe_local_session_secret(
            Phase2LocalConfiguration(project_root=project, local_session_secret_path=inside)
        )
    assert project_local.value.reason_code == "phase2_external_path_inside_project"

    outside_root = _private_directory(tmp_path / "outside-secret")
    unsafe = _secret_file(outside_root / "session-secret")
    unsafe.chmod(0o644)
    with pytest.raises(Phase2PreparationStop) as bad_mode:
        observe_local_session_secret(
            Phase2LocalConfiguration(project_root=project, local_session_secret_path=unsafe)
        )
    assert bad_mode.value.reason_code == "local_session_secret_identity_invalid"

    with pytest.raises(TypeError, match="trusted local owner security"):
        VerifiedLocalOwnerSecurity(
            observation=object(),  # type: ignore[arg-type]
            policy=literal_loopback_request_policy(8777),
            secret=b"x" * 32,
            package_sha256="1" * 64,
            _token=object(),
        )
    with pytest.raises(LocalRequestSecurityError) as forged:
        verify_local_owner_request(
            object(),
            client_host="127.0.0.1",
            host_header="127.0.0.1:8777",
            origin_header=None,
            fetch_site_header="none",
            method="GET",
            session_token=None,
            csrf_token=None,
        )
    assert forged.value.reason_code == "local_owner_security_authority_not_verified"


def test_noncanonical_or_unbounded_session_tokens_fail_closed() -> None:
    secret = bytes(range(32))
    policy = literal_loopback_request_policy(8777)

    for session_token in ("not-a-token", "a" * 1_000_000):
        with pytest.raises(LocalRequestSecurityError) as exc_info:
            validate_literal_loopback_request(
                policy=policy,
                secret=secret,
                client_host="127.0.0.1",
                host_header="127.0.0.1:8777",
                origin_header=None,
                fetch_site_header="none",
                method="GET",
                session_token=session_token,
                csrf_token=None,
            )
        assert exc_info.value.reason_code == "local_owner_session_invalid"


def test_nonliteral_server_bind_is_not_phase2_eligible() -> None:
    with pytest.raises(Phase2PreparationStop) as exc_info:
        configured_literal_loopback_request_policy(Phase2LocalConfiguration(bind_host="0.0.0.0"))
    assert exc_info.value.reason_code == "local_owner_bind_not_literal_loopback"


def test_session_secret_read_stays_on_one_root_descriptor_during_swap_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _private_directory(tmp_path / "project")
    configured_root = _private_directory(tmp_path / "configured-session-root")
    replacement_root = _private_directory(tmp_path / "replacement-session-root")
    saved_root = tmp_path / "saved-session-root"
    secret_path = _secret_file(configured_root / "session-secret", b"a" * 32)
    _secret_file(replacement_root / "session-secret", b"b" * 32)
    settings = Phase2LocalConfiguration(
        project_root=project,
        local_session_secret_path=secret_path,
    )
    baseline = observe_local_session_secret(settings)
    original_open = security_module.open_exact_private_root_descriptor
    original_require = security_module.require_exact_private_root_descriptor_current
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

    monkeypatch.setattr(security_module, "open_exact_private_root_descriptor", swap_after_open)
    monkeypatch.setattr(
        security_module,
        "require_exact_private_root_descriptor_current",
        restore_before_replay,
    )
    try:
        attacked = observe_local_session_secret(settings)
    finally:
        if swapped:
            configured_root.rename(replacement_root)
            saved_root.rename(configured_root)

    assert attacked == baseline
