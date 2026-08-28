#!/usr/bin/env python3
"""Fail-closed preflight and dependency health checks for the first live run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import time
from collections.abc import Mapping
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, NoReturn, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.candidate_completion_authority import (  # noqa: E402
    isolated_model_python_arguments,
    load_trusted_model_identity,
    resolve_verified_model_toolchain,
    sanitized_model_launch_environment,
)
from app.evaluation.candidate_completion_runtime import (  # noqa: E402
    _verify_model_artifact_manifest,
)
from app.evaluation.owner_quality_normal_live_readiness import (  # noqa: E402
    owner_quality_normal_live_readiness_status,
    owner_quality_normal_live_release_authority,
)
from app.model_runtime.config import (  # noqa: E402
    DEFAULT_CONTEXT_TOKENS,
    DEFAULT_KV_CACHE_BITS,
    DEFAULT_KV_GROUP_SIZE,
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_PREFILL_STEP_SIZE,
    PINNED_RUNTIME_REPO,
    PINNED_RUNTIME_REVISION,
)
from app.retrieval.service import (  # noqa: E402
    PHYSICAL_ASSESSMENT_LANE,
    PHYSICAL_AUTHORITY_LANE,
    PHYSICAL_TEACHING_LANE,
    _physical_lane_row_count,
    _verify_sealed_build,
)


class ReadinessError(RuntimeError):
    """A safe, owner-visible reason the live runtime must not start."""


class _ReadinessDatabase(Protocol):
    def close(self) -> None: ...

    def transaction(self) -> AbstractContextManager[sqlite3.Connection]: ...

    def normal_live_readiness_state(self) -> sqlite3.Row | Mapping[str, Any] | None: ...


_FORBIDDEN_FIRST_LIVE_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "LEGALBOT_ADAPTER_PATH",
        "LEGALBOT_LORA_PATH",
        "LEGALBOT_MODEL_ADAPTER_PATH",
        "LEGALBOT_MODEL_CLEAR_CACHE",
        "LEGALBOT_MODEL_CONTEXT_TOKENS",
        "LEGALBOT_MODEL_EAGER_LOAD",
        "LEGALBOT_MODEL_KV_BITS",
        "LEGALBOT_MODEL_KV_GROUP_SIZE",
        "LEGALBOT_MODEL_MAX_BODY_BYTES",
        "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS",
        "LEGALBOT_MODEL_PATH",
        "LEGALBOT_MODEL_PREFILL_STEP_SIZE",
    }
)

_PINNED_MODEL_RELATIVE_PATH = Path("models/runtime/Qwen3.5-9B-4bit")


def validate_first_live_profile(settings: Settings) -> None:
    parsed_model = urlsplit(settings.model_url)
    if settings.live_profile != FIRST_LIVE_LOCAL_ONLY_PROFILE:
        raise ReadinessError("the launcher is not using the first-live local-only profile")
    if (
        settings.online_default != "local_only"
        or settings.official_research_enabled
        or settings.xerj_enabled
        or settings.phoenix_enabled
        or settings.model_id != PINNED_RUNTIME_REPO
    ):
        raise ReadinessError("online official research is not disabled for first-live evaluation")
    if not settings.evaluation_forbids_online_research:
        raise ReadinessError("online-research evaluation guard is not active")
    if (
        settings.host != "127.0.0.1"
        or settings.port != 8777
        or parsed_model.scheme != "http"
        or parsed_model.hostname != "127.0.0.1"
        or parsed_model.port != 8778
        or parsed_model.username is not None
        or parsed_model.password is not None
        or parsed_model.path not in {"", "/"}
        or parsed_model.query
        or parsed_model.fragment
        or os.environ.get("LEGALBOT_MODEL_HOST", "127.0.0.1") != "127.0.0.1"
        or os.environ.get("LEGALBOT_MODEL_PORT", "8778") != "8778"
        or any(name in os.environ for name in _FORBIDDEN_FIRST_LIVE_ENVIRONMENT)
        or any(
            name.startswith("LEGALBOT_") and ("ADAPTER" in name.upper() or "LORA" in name.upper())
            for name in os.environ
        )
    ):
        raise ReadinessError("the first-live runtime settings are not the exact local contract")


def validate_pinned_model_artifacts(settings: Settings) -> dict[str, Any]:
    """Re-hash the fixed non-symlink model root against the tracked allowlist."""

    model_root = settings.project_root / _PINNED_MODEL_RELATIVE_PATH
    try:
        resolved_project = settings.project_root.resolve(strict=True)
        resolved_model = model_root.resolve(strict=True)
        resolved_model.relative_to(resolved_project)
    except (OSError, ValueError) as exc:
        raise ReadinessError("the pinned first-live model root is unavailable") from exc
    if model_root.is_symlink() or resolved_model != model_root:
        raise ReadinessError("the pinned first-live model root cannot be a symlink")
    try:
        trusted_identity = load_trusted_model_identity(resolved_project)
        _verify_model_artifact_manifest(model_root, trusted_identity)
    except RuntimeError as exc:
        raise ReadinessError("the pinned first-live model identity failed verification") from exc
    return trusted_identity


def validate_normal_live_authority(
    settings: Settings, *, database: _ReadinessDatabase
) -> dict[str, Any]:
    """Require exact v1.11 artifacts plus the admitted active DB generation."""

    status = owner_quality_normal_live_readiness_status(
        settings.project_root,
        database=database,  # type: ignore[arg-type]
        settings=settings,
    )
    if status.get("normal_live_ready") is not True:
        reasons = status.get("blocking_reason_codes")
        reason = (
            str(reasons[0])
            if isinstance(reasons, list) and reasons
            else "owner_quality_normal_live_not_verified"
        )
        raise ReadinessError(f"v1.11 normal-live authority is blocked: {reason}")
    try:
        authority = owner_quality_normal_live_release_authority(
            settings.project_root,
            database=database,  # type: ignore[arg-type]
            settings=settings,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ReadinessError("v1.11 normal-live release authority replay failed") from exc
    state = database.normal_live_readiness_state()
    if (
        state is None
        or not bool(state["active"])
        or state["generation_sha256"] != authority.get("readiness_generation_sha256")
        or state["authority_sha256"] != authority.get("seal_sha256")
        or state["candidate_build_id"] != authority.get("candidate_build_id")
    ):
        raise ReadinessError("v1.11 normal-live DB generation is absent, stale, or revoked")
    return authority


def _read_active_pointer(settings: Settings) -> dict[str, Any]:
    pointer_path = settings.index_dir / "ACTIVE.json"
    try:
        payload = json.loads(pointer_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReadinessError("ACTIVE index pointer is missing") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ReadinessError("ACTIVE index pointer is unreadable") from exc
    build_id = payload.get("build_id") if isinstance(payload, dict) else None
    manifest_sha256 = payload.get("manifest_sha256") if isinstance(payload, dict) else None
    if not isinstance(build_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", build_id
    ):
        raise ReadinessError("ACTIVE index pointer contains an invalid build id")
    if not isinstance(manifest_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise ReadinessError("ACTIVE index pointer contains an invalid manifest digest")
    manifest_path = settings.index_dir / "builds" / build_id / "manifest.json"
    try:
        actual_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ReadinessError("ACTIVE index manifest is unavailable") from exc
    if actual_sha256 != manifest_sha256:
        raise ReadinessError("ACTIVE index pointer does not match its immutable manifest")
    return dict(payload)


def validate_active_build(settings: Settings, *, verify_seal: bool = True) -> dict[str, Any]:
    """Verify the pointer, catalogue, seal and physical-lane readiness read-only."""

    if not settings.database_path.is_file():
        raise ReadinessError("catalogue database is missing")
    pointer = _read_active_pointer(settings)
    database_uri = f"{settings.database_path.resolve().as_uri()}?mode=ro"
    try:
        connection = sqlite3.connect(database_uri, uri=True)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM index_builds WHERE status='active' "
            "ORDER BY promoted_at DESC, created_at DESC"
        ).fetchall()
    except sqlite3.Error as exc:
        raise ReadinessError("catalogue database cannot verify the ACTIVE build") from exc
    finally:
        if "connection" in locals():
            connection.close()
    if len(rows) != 1:
        raise ReadinessError("catalogue must contain exactly one active index build")
    row = dict(rows[0])
    build_id = str(pointer["build_id"])
    if str(row.get("id") or "") != build_id:
        raise ReadinessError("ACTIVE pointer and catalogue active build disagree")
    expected_build_path = (settings.index_dir / "builds" / build_id).resolve()
    configured_path = Path(str(row.get("path") or ""))
    if not configured_path.is_absolute():
        configured_path = settings.project_root / configured_path
    if configured_path.resolve() != expected_build_path:
        raise ReadinessError("catalogue active build path is not the immutable build path")
    if verify_seal:
        catalogue = Database(settings.database_path)
        try:
            _verify_sealed_build(settings, catalogue, row)
        except Exception as exc:
            raise ReadinessError("ACTIVE build failed immutable seal verification") from exc
        finally:
            catalogue.close()
    try:
        lane_counts = {
            lane: _physical_lane_row_count(settings, build_id, lane)
            for lane in (
                PHYSICAL_AUTHORITY_LANE,
                PHYSICAL_TEACHING_LANE,
                PHYSICAL_ASSESSMENT_LANE,
            )
        }
    except (RuntimeError, ValueError) as exc:
        raise ReadinessError("ACTIVE build physical lane manifest is invalid") from exc
    if lane_counts[PHYSICAL_AUTHORITY_LANE] < 1:
        raise ReadinessError("ACTIVE build has no authority retrieval rows")
    if not (expected_build_path / "lance" / PHYSICAL_AUTHORITY_LANE).is_dir():
        raise ReadinessError("ACTIVE build authority retrieval table is missing")
    return {"build_id": build_id, "lane_counts": lane_counts}


def validate_first_live_startup_authority(
    settings: Settings,
    *,
    database: _ReadinessDatabase,
    verify_seal: bool = True,
    verify_model_artifacts: bool = True,
) -> dict[str, Any]:
    """Reconcile settings, ACTIVE and the current admitted v1.11 generation."""

    validate_first_live_profile(settings)
    active = validate_active_build(settings, verify_seal=verify_seal)
    authority = validate_normal_live_authority(settings, database=database)
    if authority.get("candidate_build_id") != active["build_id"]:
        raise ReadinessError("v1.11 authority and ACTIVE candidate disagree")
    # Hash the multi-gigabyte model only after every cheap policy, ACTIVE and
    # owner-authority check passes. A missing judgment must stop without doing
    # expensive technical work.
    model_identity = validate_pinned_model_artifacts(settings) if verify_model_artifacts else None
    return {
        "build_id": active["build_id"],
        "lane_counts": active["lane_counts"],
        "authority_seal_sha256": authority["seal_sha256"],
        "readiness_generation_sha256": authority["readiness_generation_sha256"],
        "trusted_model_identity_sha256": (
            str(model_identity["seal_sha256"]) if model_identity is not None else None
        ),
    }


def guarded_first_live_model_exec(
    settings: Settings,
    *,
    database: _ReadinessDatabase,
) -> NoReturn:
    """Verify the fixed launch boundary, then stop pending owned-runtime authority.

    Revocation uses the same SQLite write domain for the final check. This
    command is only for ordinary first-live service; evaluation launchers keep
    their separate non-release contracts.
    """

    _require_model_port_available()
    # Complete the expensive immutable-artifact and installed-toolchain replay
    # before taking the readiness write lock.  A revoke during this work wins;
    # the final in-transaction authority replay below then prevents ``exec``.
    validate_first_live_startup_authority(
        settings,
        database=database,
        verify_seal=True,
        verify_model_artifacts=True,
    )
    try:
        toolchain = resolve_verified_model_toolchain(
            settings.project_root,
            ambient_environment={"PATH": os.environ.get("PATH", "")},
        )
        launch_nonce = secrets.token_hex(32)
        pycache_root = (
            settings.data_dir
            / "runtime"
            / "model-pycache"
            / hashlib.sha256(launch_nonce.encode("ascii")).hexdigest()
        )
        environment = sanitized_model_launch_environment(
            project_root=settings.project_root,
            private_pycache_root=pycache_root,
            launch_nonce=launch_nonce,
            values={
                "LEGALBOT_MODEL_MODE": "mlx",
                "LEGALBOT_MODEL_HOST": "127.0.0.1",
                "LEGALBOT_MODEL_PORT": "8778",
                "LEGALBOT_MODEL_ID": PINNED_RUNTIME_REPO,
                "LEGALBOT_MODEL_REVISION": PINNED_RUNTIME_REVISION,
                "LEGALBOT_MODEL_PATH": str(settings.project_root / _PINNED_MODEL_RELATIVE_PATH),
                "LEGALBOT_MODEL_CONTEXT_TOKENS": str(DEFAULT_CONTEXT_TOKENS),
                "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS": str(DEFAULT_MAX_OUTPUT_TOKENS),
                "LEGALBOT_MODEL_PREFILL_STEP_SIZE": str(DEFAULT_PREFILL_STEP_SIZE),
                "LEGALBOT_MODEL_KV_BITS": str(DEFAULT_KV_CACHE_BITS),
                "LEGALBOT_MODEL_KV_GROUP_SIZE": str(DEFAULT_KV_GROUP_SIZE),
                "LEGALBOT_MODEL_CLEAR_CACHE": "true",
            },
        )
        _expected_command = (
            str(toolchain.python_executable),
            *isolated_model_python_arguments(
                settings.project_root,
                private_pycache_root=pycache_root,
            ),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ReadinessError("the fixed first-live model toolchain failed verification") from exc
    with database.transaction():
        _require_model_port_available()
        validate_first_live_startup_authority(
            settings,
            database=database,
            verify_seal=True,
            # The full model hash just completed.  Reconcile the mutable DB
            # generation and ACTIVE pointer under one write lock immediately
            # before replacing this process with the model runtime.
            verify_model_artifacts=False,
        )
        del _expected_command, environment
        # A model process cannot become ordinary-service authority merely by
        # inheriting a self-sealed nonce or reporting the expected strings.
        # The reusable owned-runtime capability must attest exact child PID,
        # descendant listener, nonce, model/toolchain bytes and adapter absence,
        # then bind its admitted generation into every readiness and release
        # replay.  Until that capability is integrated, stopping here is the
        # only safe ordinary-service behavior.
        raise ReadinessError(
            "TECHNICAL_IMPLEMENTATION_REQUIRED:first_live_owned_model_runtime_authority_missing"
        )


def _require_model_port_available() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 8778))
    except OSError as exc:
        raise ReadinessError("the fixed first-live model port is already occupied") from exc
    finally:
        listener.close()


def _health_payload(base_url: str, timeout_seconds: float = 2.0) -> dict[str, Any]:
    request = Request(
        f"{base_url.rstrip('/')}/api/v1/health",
        headers={"Accept": "application/json"},
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        if response.status != 200:
            raise ReadinessError("runtime health endpoint returned a non-success status")
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ReadinessError("runtime health endpoint returned an invalid payload")
    return payload


def validate_health_payload(payload: dict[str, Any], expected_build_id: str) -> None:
    missing = [
        field
        for field in ("database_ready", "worker_ready", "model_ready")
        if payload.get(field) is not True
    ]
    if missing:
        raise ReadinessError("runtime dependencies are not ready: " + ", ".join(sorted(missing)))
    if payload.get("active_index") != expected_build_id:
        raise ReadinessError("runtime health does not report the verified ACTIVE build")
    if payload.get("status") != "ready":
        raise ReadinessError("runtime health status is not ready")


def wait_for_runtime_health(
    base_url: str, expected_build_id: str, *, timeout_seconds: float
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    last_reason = "runtime health endpoint is unavailable"
    while time.monotonic() < deadline:
        try:
            payload = _health_payload(base_url)
            validate_health_payload(payload, expected_build_id)
            return payload
        except (ReadinessError, HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_reason = str(exc) or last_reason
            time.sleep(0.25)
    raise ReadinessError(f"runtime did not become ready before timeout: {last_reason}")


def _settings(project_root: str) -> Settings:
    return Settings(project_root=Path(project_root).resolve())


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--project-root", default=str(PROJECT_ROOT))
    wait_health = commands.add_parser("wait-health")
    wait_health.add_argument("--project-root", default=str(PROJECT_ROOT))
    wait_health.add_argument("--base-url", default="http://127.0.0.1:8777")
    wait_health.add_argument("--timeout", type=float, default=60.0)
    launch_model = commands.add_parser("launch-model")
    launch_model.add_argument("--project-root", default=str(PROJECT_ROOT))
    args = parser.parse_args()
    database: Database | None = None
    try:
        settings = _settings(args.project_root)
        validate_first_live_profile(settings)
        # Check ACTIVE before opening the catalogue wrapper so a missing path
        # cannot be created as a side effect of a failed startup.
        validate_active_build(settings, verify_seal=args.command in {"preflight", "launch-model"})
        database = Database(settings.database_path)
        if args.command == "launch-model":
            guarded_first_live_model_exec(
                settings,
                database=database,
            )
        active = validate_first_live_startup_authority(
            settings,
            database=database,
            verify_seal=args.command == "preflight",
            verify_model_artifacts=args.command == "preflight",
        )
        if args.command == "wait-health":
            wait_for_runtime_health(
                args.base_url,
                str(active["build_id"]),
                timeout_seconds=max(1.0, min(args.timeout, 120.0)),
            )
            # Do not print ready after an emergency revoke that raced health.
            active = validate_first_live_startup_authority(
                settings,
                database=database,
                verify_seal=False,
                verify_model_artifacts=False,
            )
        print(
            json.dumps(
                {
                    "status": "ready",
                    "profile": settings.live_profile,
                    "active_build_id": active["build_id"],
                    "online_research_enabled": settings.official_research_enabled,
                    "lane_counts": active["lane_counts"],
                    "normal_live_authority_sha256": active["authority_seal_sha256"],
                    "readiness_generation_sha256": active["readiness_generation_sha256"],
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ReadinessError, RuntimeError, sqlite3.Error, ValueError) as exc:
        print(f"LegalBot-New runtime readiness failed: {exc}", file=sys.stderr)
        return 2
    finally:
        if database is not None:
            database.close()


if __name__ == "__main__":
    raise SystemExit(main())
