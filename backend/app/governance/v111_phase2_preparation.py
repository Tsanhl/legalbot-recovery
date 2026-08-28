"""Non-authorizing technical boundaries required before v1.11 Phase 2.

This module records path-free identities for the three owner-private output
roots.  It deliberately does not implement, create, or accept an owner
decision package.  A technically valid directory is configuration, not
authority; every production loader remains closed until the future trusted
signature verifier binds these exact identities.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict

from .v111_decision_generation import private_root_identity
from .v111_owner_decision_package import review_root_set_identity_sha256

PHASE2_PREPARATION_STATUS_SCHEMA = "legalbot.v111-phase2-preparation-status.v1"
PHASE2_REVIEW_ROOT_SET_SCHEMA = "legalbot.v111-phase2-review-root-set.v1"

Phase2ReviewLane = Literal["development", "sealed_validation", "live"]
_LANES: tuple[Phase2ReviewLane, ...] = ("development", "sealed_validation", "live")
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Phase2PreparationStop(RuntimeError):
    """Safe reason-code exception for a boundary that is not yet authorized."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class Phase2PreparationStatus(TypedDict):
    schema: str
    authorizing: Literal[False]
    phase2_ready: Literal[False]
    resource_identities: dict[str, str]
    blocking_reason_codes: list[str]
    created_resources: Literal[False]
    model_invoked: Literal[False]
    evaluation_executed: Literal[False]
    promotion_executed: Literal[False]
    live_activated: Literal[False]


@dataclass(frozen=True, slots=True)
class Phase2LocalConfiguration:
    """Phase-2-only local resources, isolated from runtime/scorer settings.

    Loading configuration observes environment strings only.  It never creates
    any referenced path, key, secret, socket, or authorization artifact.
    """

    project_root: Path = _PROJECT_ROOT
    bind_host: str = "127.0.0.1"
    port: int = 8777
    development_review_root: Path | None = None
    sealed_validation_review_root: Path | None = None
    live_review_root: Path | None = None
    model_socket_path: Path | None = None
    local_session_secret_path: Path | None = None
    owner_public_key_path: Path | None = None

    def __post_init__(self) -> None:
        if isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("Phase-2 local owner request port is invalid")

    @classmethod
    def from_environment(
        cls,
        *,
        project_root: Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> Phase2LocalConfiguration:
        """Read the dedicated Phase-2 configuration without mutating state."""

        source = os.environ if environ is None else environ

        def optional_path(name: str) -> Path | None:
            value = source.get(name, "").strip()
            return Path(value).expanduser() if value else None

        port_text = source.get("LEGALBOT_PORT", "8777").strip()
        return cls(
            project_root=_PROJECT_ROOT if project_root is None else project_root,
            bind_host=source.get("LEGALBOT_HOST", "127.0.0.1").strip(),
            port=int(port_text),
            development_review_root=optional_path("LEGALBOT_DEVELOPMENT_REVIEW_ROOT"),
            sealed_validation_review_root=optional_path("LEGALBOT_SEALED_VALIDATION_REVIEW_ROOT"),
            live_review_root=optional_path("LEGALBOT_LIVE_REVIEW_ROOT"),
            model_socket_path=optional_path("LEGALBOT_MODEL_SOCKET_PATH"),
            local_session_secret_path=optional_path("LEGALBOT_LOCAL_SESSION_SECRET_PATH"),
            owner_public_key_path=optional_path("LEGALBOT_OWNER_PUBLIC_KEY_PATH"),
        )


@dataclass(frozen=True, slots=True)
class Phase2ReviewRootSetObservation:
    """Path-free, non-authorizing observation of three exact directories."""

    development_root_identity_sha256: str
    sealed_validation_root_identity_sha256: str
    live_root_identity_sha256: str
    root_set_identity_sha256: str
    authorizing: Literal[False] = False

    def identity_for(self, lane: Phase2ReviewLane) -> str:
        if lane == "development":
            return self.development_root_identity_sha256
        if lane == "sealed_validation":
            return self.sealed_validation_root_identity_sha256
        if lane == "live":
            return self.live_root_identity_sha256
        raise ValueError("Phase-2 review lane is unsupported")


def _has_symlinked_existing_component(path: Path) -> bool:
    current = path
    while True:
        if current.is_symlink():
            return True
        if current == current.parent:
            return False
        current = current.parent


def _known_sync_roots() -> tuple[Path, ...]:
    home = Path.home()
    return (
        home / "Library" / "CloudStorage",
        home / "Library" / "Mobile Documents",
        home / "Dropbox",
        home / "OneDrive",
        home / "Google Drive",
        home / "Box",
    )


def require_external_nonsynced_path_configuration(
    path: Path,
    *,
    project_root: Path,
) -> Path:
    """Reject locations that are relative, project-local, symlinked, or known-sync.

    Absence from a known sync location is only a technical negative check.  The
    positive assertion that a root is not synchronized remains an owner claim
    that the signed Phase-2 decision package must make later.
    """

    candidate = path.expanduser()
    if not candidate.is_absolute() or _has_symlinked_existing_component(candidate):
        raise Phase2PreparationStop("phase2_external_path_unsafe")
    resolved = candidate.resolve(strict=False)
    project = project_root.resolve(strict=False)
    if resolved == project or resolved.is_relative_to(project):
        raise Phase2PreparationStop("phase2_external_path_inside_project")
    for sync_root in _known_sync_roots():
        sync = sync_root.resolve(strict=False)
        if resolved == sync or resolved.is_relative_to(sync):
            raise Phase2PreparationStop("phase2_external_path_known_sync_location")
    return resolved


def configured_phase2_review_roots(
    settings: Phase2LocalConfiguration,
) -> dict[Phase2ReviewLane, Path]:
    """Return three configured paths without creating or approving any directory."""

    configured = {
        "development": settings.development_review_root,
        "sealed_validation": settings.sealed_validation_review_root,
        "live": settings.live_review_root,
    }
    if any(configured[lane] is None for lane in _LANES):
        raise Phase2PreparationStop("phase2_review_roots_not_provisioned")
    roots: dict[Phase2ReviewLane, Path] = {
        lane: require_external_nonsynced_path_configuration(
            configured[lane],  # type: ignore[arg-type]
            project_root=settings.project_root,
        )
        for lane in _LANES
    }
    values = tuple(roots[lane] for lane in _LANES)
    if len(set(values)) != len(values) or any(
        left.is_relative_to(right) for left in values for right in values if left != right
    ):
        raise Phase2PreparationStop("phase2_review_roots_not_isolated")
    return roots


def observe_phase2_review_root_set(
    settings: Phase2LocalConfiguration,
) -> Phase2ReviewRootSetObservation:
    """Observe exact existing 0700 identities without granting write authority."""

    roots = configured_phase2_review_roots(settings)
    try:
        identities = {
            lane: private_root_identity(
                roots[lane],
                project_root=settings.project_root,
            )
            for lane in _LANES
        }
    except (OSError, RuntimeError, ValueError) as exc:
        raise Phase2PreparationStop("phase2_review_root_identity_unavailable") from exc
    if len(set(identities.values())) != len(_LANES):
        raise Phase2PreparationStop("phase2_review_root_identities_not_distinct")
    root_set = review_root_set_identity_sha256(
        development_review_root_identity_sha256=identities["development"],
        sealed_validation_review_root_identity_sha256=identities["sealed_validation"],
        live_review_root_identity_sha256=identities["live"],
    )
    return Phase2ReviewRootSetObservation(
        development_root_identity_sha256=identities["development"],
        sealed_validation_root_identity_sha256=identities["sealed_validation"],
        live_root_identity_sha256=identities["live"],
        root_set_identity_sha256=root_set,
    )


def require_verified_phase2_review_root_set(
    settings: Phase2LocalConfiguration,
) -> Phase2ReviewRootSetObservation:
    """Keep real review output closed until the future signed-package verifier."""

    observe_phase2_review_root_set(settings)
    raise Phase2PreparationStop("trusted_phase2_owner_decision_package_verifier_missing")


def phase2_preparation_status(
    settings: Phase2LocalConfiguration,
) -> Phase2PreparationStatus:
    """Return path-free preparation diagnostics; never an activation authority."""

    blockers: list[str] = ["trusted_phase2_owner_decision_package_verifier_missing"]
    identities: dict[str, str] = {}
    try:
        roots = observe_phase2_review_root_set(settings)
        identities["review_root_set_identity_sha256"] = roots.root_set_identity_sha256
    except Phase2PreparationStop as exc:
        blockers.append(exc.reason_code)

    from ..api.local_owner_security import (
        configured_literal_loopback_request_policy,
        observe_local_session_secret,
    )
    from ..model_runtime.private_uds_transport import (
        observe_private_model_endpoint_intent,
        observe_private_model_socket,
    )
    from .v111_owner_public_key import observe_owner_public_key

    try:
        secret = observe_local_session_secret(settings)
        identities["session_secret_identity_sha256"] = secret.identity_sha256
    except Phase2PreparationStop as exc:
        blockers.append(exc.reason_code)
    try:
        local_policy = configured_literal_loopback_request_policy(settings)
        identities["local_owner_request_policy_sha256"] = local_policy.identity_sha256
    except Phase2PreparationStop as exc:
        blockers.append(exc.reason_code)
    try:
        endpoint_intent = observe_private_model_endpoint_intent(settings)
        identities["model_endpoint_intent_identity_sha256"] = endpoint_intent.identity_sha256
    except Phase2PreparationStop as exc:
        blockers.append(exc.reason_code)
    try:
        model_socket = observe_private_model_socket(settings)
        identities["model_socket_identity_sha256"] = model_socket.identity_sha256
    except Phase2PreparationStop as exc:
        blockers.append(exc.reason_code)
    try:
        owner_public_key = observe_owner_public_key(settings)
        identities["owner_public_key_identity_sha256"] = owner_public_key.identity_sha256
        identities["owner_public_key_sha256"] = owner_public_key.public_key_sha256
    except Phase2PreparationStop as exc:
        blockers.append(exc.reason_code)
    return {
        "schema": PHASE2_PREPARATION_STATUS_SCHEMA,
        "authorizing": False,
        "phase2_ready": False,
        "resource_identities": identities,
        "blocking_reason_codes": sorted(set(blockers)),
        "created_resources": False,
        "model_invoked": False,
        "evaluation_executed": False,
        "promotion_executed": False,
        "live_activated": False,
    }


__all__ = [
    "PHASE2_PREPARATION_STATUS_SCHEMA",
    "PHASE2_REVIEW_ROOT_SET_SCHEMA",
    "Phase2LocalConfiguration",
    "Phase2PreparationStatus",
    "Phase2PreparationStop",
    "Phase2ReviewRootSetObservation",
    "configured_phase2_review_roots",
    "observe_phase2_review_root_set",
    "phase2_preparation_status",
    "require_external_nonsynced_path_configuration",
    "require_verified_phase2_review_root_set",
]
