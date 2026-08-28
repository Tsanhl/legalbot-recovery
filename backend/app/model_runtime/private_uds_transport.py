"""Private Unix-domain-socket transport preparation for the owner model.

The functions in this module separately observe stable endpoint intent and an
already-provisioned socket instance, then prepare an httpx UDS transport. They
never create a socket, start a model process, or mint production authority.
Only a future trusted verifier for the signed Phase-2 owner package may
construct ``VerifiedPrivateModelTransport``.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

import httpx

from ..governance.immutable_capability import ImmutableOpaqueCapability
from ..governance.v111_decision_generation import private_root_identity
from ..governance.v111_phase2_preparation import (
    Phase2LocalConfiguration,
    Phase2PreparationStop,
    require_external_nonsynced_path_configuration,
)

PRIVATE_MODEL_SOCKET_OBSERVATION_SCHEMA = "legalbot.private-model-socket-observation.v1"
PRIVATE_MODEL_ENDPOINT_INTENT_SCHEMA = "legalbot.private-model-uds-endpoint-intent.v1"
PRIVATE_MODEL_TRANSPORT_SCHEMA = "legalbot.private-model-uds-transport.v1"

_VERIFIED_PRIVATE_MODEL_TRANSPORT_TOKEN = object()


def _sealed_sha256(value: object) -> str:
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class PrivateModelUnixEndpointPolicy:
    """Frozen requirements for any socket instance satisfying the intent."""

    address_family: Literal["AF_UNIX"] = "AF_UNIX"
    socket_type: Literal["SOCK_STREAM"] = "SOCK_STREAM"
    filesystem_namespace_required: Literal[True] = True
    abstract_namespace_allowed: Literal[False] = False
    required_owner: Literal["current_effective_uid"] = "current_effective_uid"
    required_parent_mode_octal: Literal["0700"] = "0700"
    required_socket_mode_octal: Literal["0600"] = "0600"
    required_link_count: Literal[1] = 1


@dataclass(frozen=True, slots=True)
class PrivateModelUdsTransportPolicy:
    """Frozen no-fallback transport settings used by the future gateway."""

    implementation: Literal["httpx.AsyncHTTPTransport"] = "httpx.AsyncHTTPTransport"
    uds_only: Literal[True] = True
    network_fallback_allowed: Literal[False] = False
    trust_env: Literal[False] = False
    retries: Literal[0] = 0
    max_connections: Literal[1] = 1
    max_keepalive_connections: Literal[1] = 1


PRIVATE_MODEL_UNIX_ENDPOINT_POLICY = PrivateModelUnixEndpointPolicy()
PRIVATE_MODEL_UDS_TRANSPORT_POLICY = PrivateModelUdsTransportPolicy()


@dataclass(frozen=True, slots=True)
class PrivateModelEndpointIntentObservation:
    """Stable, path-free identity for one configured private UDS endpoint.

    This is an observation of configuration and policy, not of a live socket
    instance. Its identity deliberately excludes the socket inode, device,
    timestamps, and current existence so a safe socket restart does not change
    the endpoint intent.
    """

    identity_sha256: str
    lexical_socket_path_sha256: str
    parent_root_identity_sha256: str
    endpoint_policy_sha256: str
    transport_policy_sha256: str
    authorizing: Literal[False] = False


def _socket_lexical_path_sha256(path: Path) -> str:
    return hashlib.sha256(
        b"legalbot.private-model-socket-path.v1\x00" + os.fsencode(path)
    ).hexdigest()


def observe_private_model_endpoint_intent(
    settings: Phase2LocalConfiguration,
) -> PrivateModelEndpointIntentObservation:
    """Observe stable endpoint intent without creating or opening the socket.

    The configured lexical path is hashed before resolution. The returned
    hidden path is the separately safety-checked resolved location. The direct
    parent must already be an exact external owner-only (0700) root.
    """

    configured = settings.model_socket_path
    if configured is None:
        raise Phase2PreparationStop("private_model_endpoint_not_configured")
    lexical_path = configured.expanduser()
    socket_path = require_external_nonsynced_path_configuration(
        lexical_path,
        project_root=settings.project_root,
    )
    if (
        lexical_path != socket_path
        or len(os.fsencode(socket_path)) > 103
        or socket_path.name in {"", ".", ".."}
    ):
        raise Phase2PreparationStop("private_model_socket_path_invalid")
    try:
        parent_identity_before = private_root_identity(
            socket_path.parent,
            project_root=settings.project_root,
        )
        # A second complete observation closes the parent-replacement window.
        parent_identity_after = private_root_identity(
            socket_path.parent,
            project_root=settings.project_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise Phase2PreparationStop("private_model_socket_parent_not_private") from exc
    if parent_identity_before != parent_identity_after:
        raise Phase2PreparationStop("private_model_socket_parent_changed")
    rechecked_path = require_external_nonsynced_path_configuration(
        lexical_path,
        project_root=settings.project_root,
    )
    if rechecked_path != socket_path:
        raise Phase2PreparationStop("private_model_socket_parent_changed")

    lexical_path_sha256 = _socket_lexical_path_sha256(lexical_path)
    endpoint_policy = asdict(PRIVATE_MODEL_UNIX_ENDPOINT_POLICY)
    transport_policy = asdict(PRIVATE_MODEL_UDS_TRANSPORT_POLICY)
    endpoint_policy_sha256 = _sealed_sha256(endpoint_policy)
    transport_policy_sha256 = _sealed_sha256(transport_policy)
    identity = _sealed_sha256(
        {
            "schema": PRIVATE_MODEL_ENDPOINT_INTENT_SCHEMA,
            "lexical_socket_path_sha256": lexical_path_sha256,
            "parent_root_identity_sha256": parent_identity_after,
            "endpoint_policy": endpoint_policy,
            "transport_policy": transport_policy,
            "authorizing": False,
        }
    )
    return PrivateModelEndpointIntentObservation(
        identity_sha256=identity,
        lexical_socket_path_sha256=lexical_path_sha256,
        parent_root_identity_sha256=parent_identity_after,
        endpoint_policy_sha256=endpoint_policy_sha256,
        transport_policy_sha256=transport_policy_sha256,
    )


@dataclass(frozen=True, slots=True)
class PrivateModelSocketObservation:
    """Path-free public identity plus a hidden local path for later replay."""

    identity_sha256: str
    parent_root_identity_sha256: str
    socket_path: Path = field(repr=False, compare=False)
    authorizing: Literal[False] = False


def _observe_socket_path(
    path: Path,
    *,
    project_root: Path,
) -> PrivateModelSocketObservation:
    socket_path = require_external_nonsynced_path_configuration(
        path,
        project_root=project_root,
    )
    if len(os.fsencode(socket_path)) > 103 or socket_path.name in {"", ".", ".."}:
        raise Phase2PreparationStop("private_model_socket_path_invalid")
    parent = socket_path.parent
    try:
        parent_identity_before = private_root_identity(parent, project_root=project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise Phase2PreparationStop("private_model_socket_parent_not_private") from exc
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise Phase2PreparationStop("private_model_socket_secure_observation_unavailable")
    try:
        descriptor = os.open(parent, os.O_RDONLY | directory_flag | no_follow)
    except OSError as exc:
        raise Phase2PreparationStop("private_model_socket_parent_not_private") from exc
    try:
        before = os.stat(socket_path.name, dir_fd=descriptor, follow_symlinks=False)
        after = os.stat(socket_path.name, dir_fd=descriptor, follow_symlinks=False)
    except OSError as exc:
        raise Phase2PreparationStop("private_model_socket_not_provisioned") from exc
    finally:
        os.close(descriptor)
    identity_fields = (
        before.st_dev,
        before.st_ino,
        before.st_uid,
        before.st_mode,
        before.st_nlink,
    )
    if (
        not stat.S_ISSOCK(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 1
        or identity_fields
        != (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_nlink)
    ):
        raise Phase2PreparationStop("private_model_socket_identity_invalid")
    try:
        parent_identity_after = private_root_identity(parent, project_root=project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise Phase2PreparationStop("private_model_socket_parent_changed") from exc
    if parent_identity_before != parent_identity_after:
        raise Phase2PreparationStop("private_model_socket_parent_changed")
    lexical_path_sha256 = _socket_lexical_path_sha256(socket_path)
    identity = _sealed_sha256(
        {
            "schema": PRIVATE_MODEL_SOCKET_OBSERVATION_SCHEMA,
            "lexical_path_sha256": lexical_path_sha256,
            "parent_root_identity_sha256": parent_identity_after,
            "device": before.st_dev,
            "inode": before.st_ino,
            "owner_uid": before.st_uid,
            "mode": stat.S_IMODE(before.st_mode),
            "link_count": before.st_nlink,
            # stat(2) proves a Unix socket, but not its stream/datagram kind
            # without connecting.  Observation deliberately does not connect.
            "socket_type": "unix_domain",
        }
    )
    return PrivateModelSocketObservation(
        identity_sha256=identity,
        parent_root_identity_sha256=parent_identity_after,
        socket_path=socket_path,
    )


def observe_private_model_socket(
    settings: Phase2LocalConfiguration,
) -> PrivateModelSocketObservation:
    """Observe a configured existing socket without connecting to it."""

    if settings.model_socket_path is None:
        raise Phase2PreparationStop("private_model_socket_not_provisioned")
    return _observe_socket_path(
        settings.model_socket_path,
        project_root=settings.project_root,
    )


class VerifiedPrivateModelTransport(ImmutableOpaqueCapability):
    """Opaque capability reserved for the future signed-package verifier."""

    __slots__ = ("_observation", "_project_root", "_token", "package_sha256")

    def __init__(
        self,
        *,
        observation: PrivateModelSocketObservation,
        project_root: Path,
        package_sha256: str,
        _token: object,
    ) -> None:
        if _token is not _VERIFIED_PRIVATE_MODEL_TRANSPORT_TOKEN:
            raise TypeError("trusted private model transport verification required")
        self._observation = observation
        self._project_root = project_root
        self.package_sha256 = package_sha256
        self._token = _token

    def __repr__(self) -> str:
        return "<VerifiedPrivateModelTransport>"

    def _require_current(self) -> None:
        current = _observe_socket_path(
            self._observation.socket_path,
            project_root=self._project_root,
        )
        if current.identity_sha256 != self._observation.identity_sha256:
            raise RuntimeError("private model socket changed after verification")


def require_private_model_transport(
    settings: Phase2LocalConfiguration,
) -> VerifiedPrivateModelTransport:
    """Fail after technical observation until signed-package verification exists."""

    observe_private_model_socket(settings)
    raise Phase2PreparationStop("trusted_phase2_owner_decision_package_verifier_missing")


def build_private_uds_httpx_transport(value: object) -> httpx.AsyncHTTPTransport:
    """Remain closed until the exact observed socket is pinned at connect time.

    ``httpx`` accepts only a socket pathname and opens it later, leaving a
    replacement window after observation.  Phase-2 preparation therefore does
    not expose a usable transport until the production connector can verify the
    exact socket instance during every connection.
    """

    if (
        type(value) is not VerifiedPrivateModelTransport
        or value._token is not _VERIFIED_PRIVATE_MODEL_TRANSPORT_TOKEN
    ):
        raise RuntimeError("private model transport authority was not verified")
    value._require_current()
    raise Phase2PreparationStop("private_model_exact_connect_time_identity_enforcement_missing")


__all__ = [
    "PRIVATE_MODEL_ENDPOINT_INTENT_SCHEMA",
    "PRIVATE_MODEL_SOCKET_OBSERVATION_SCHEMA",
    "PRIVATE_MODEL_TRANSPORT_SCHEMA",
    "PRIVATE_MODEL_UDS_TRANSPORT_POLICY",
    "PRIVATE_MODEL_UNIX_ENDPOINT_POLICY",
    "PrivateModelEndpointIntentObservation",
    "PrivateModelSocketObservation",
    "PrivateModelUdsTransportPolicy",
    "PrivateModelUnixEndpointPolicy",
    "VerifiedPrivateModelTransport",
    "build_private_uds_httpx_transport",
    "observe_private_model_endpoint_intent",
    "observe_private_model_socket",
    "require_private_model_transport",
]
