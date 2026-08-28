"""Owned, re-attested model sidecar authority for the owner-quality 30/30 lanes.

The completion preflight proves an earlier isolated model instance.  This module
owns the distinct sidecar used by a real development or blind-holdout run and
keeps release authority live only while that exact process, listener, model,
toolchain and owner memory envelope remain valid.

No answer or question content is written here.  The create-only artifacts are
safe identities, process/memory measurements and before/after case checkpoints.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..config import Settings
from ..db import Database
from ..model_runtime.config import PINNED_RUNTIME_REPO, PINNED_RUNTIME_REVISION
from .candidate_completion_authority import (
    MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
    MEMORY_MEASUREMENT_METHOD,
    MEMORY_SAMPLE_INTERVAL_SECONDS,
    LoadedCompletionMemoryPolicy,
    VerifiedModelToolchain,
    WorkflowMemorySampler,
    _process_memory_snapshot,
    attest_owned_listener,
    host_available_memory_bytes,
    isolated_model_python_arguments,
    load_trusted_model_identity,
    resolve_verified_model_toolchain,
    sanitized_model_launch_environment,
    write_create_only_private_safe_json,
)
from .candidate_completion_runtime import (
    _verify_model_artifact_manifest,
    build_local_completion_runtime_binding,
    validate_completion_launcher_settings,
)
from .live_suite import sealed_sha256
from .nonrelease_artifacts import verify_sealed_artifact
from .owner_quality_canary_authorization import OwnerDecisionRequired
from .sealed_candidate import SealedCandidateIdentity

OWNED_RUNTIME_START_SCHEMA = "legalbot.owner-canary-owned-runtime-start.v1"
OWNED_RUNTIME_CHECKPOINT_SCHEMA = "legalbot.owner-canary-owned-runtime-checkpoint.v1"
OWNED_RUNTIME_END_SCHEMA = "legalbot.owner-canary-owned-runtime-end.v1"
OWNED_RUNTIME_FAILURE_SCHEMA = "legalbot.owner-canary-owned-runtime-failure.v1"
OWNED_RUNTIME_START_FILENAME = "owned-runtime-start.json"
OWNED_RUNTIME_END_FILENAME = "owned-runtime-end.json"
OWNED_RUNTIME_FAILURE_FILENAME = "owned-runtime-failure.json"
OWNED_RUNTIME_CHECKPOINT_DIRNAME = "owned-runtime-checkpoints"
OWNER_CANARY_MODEL_HOST = "127.0.0.1"
OWNER_CANARY_MODEL_PORT = 8778

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_RUN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_ACTIVE_TOKEN = object()
_ENDED_TOKEN = object()
_ACTIVE_RUNTIME_LOCK = threading.Lock()
_ACTIVE_RUNTIMES: dict[str, OwnerCanaryOwnedModelRuntime] = {}


def require_owner_canary_exclusive_model_transport_resolution() -> None:
    """Keep authoritative inference closed until the owner selects transport.

    A loopback listener proves host/process ownership, but the current model
    service cannot prove that every generation request came from this canary
    controller.  Adding a session credential would be an auth change prohibited
    by the clean-room policy without a new approval phase.  This stop therefore
    occurs before artifact checks, port probing, process spawn, or model output.
    """

    raise OwnerDecisionRequired("owner_canary_exclusive_model_transport_unresolved")


def verify_owner_canary_runtime_atomic_release(authority: Mapping[str, Any]) -> None:
    """Fast same-process guard used only inside the SQLite release transaction.

    The expensive artifact/model/toolchain replay happens before the IMMEDIATE
    transaction.  This guard closes the remaining monitor-failure race without
    filesystem, network, hashing, or database work while that transaction is
    held.
    """

    run_id = str(authority.get("run_id") or "")
    with _ACTIVE_RUNTIME_LOCK:
        runtime = _ACTIVE_RUNTIMES.get(run_id)
    if runtime is None:
        raise RuntimeError("owner_canary_owned_runtime_controller_not_active")
    runtime._verify_atomic_release(authority)


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("owned_runtime_identity_file_missing")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _clean_integration_sha(project_root: Path) -> str:
    from ..retrieval.retrieval_reattest import _clean_integration_sha as clean_sha

    return clean_sha(project_root)


def _safe_runtime_file(root: Path, filename: str) -> Path:
    path = root / "safe-metrics" / filename
    if (
        root.is_symlink()
        or not root.is_dir()
        or path.is_symlink()
        or not path.is_file()
        or path.stat().st_mode & 0o777 != 0o600
    ):
        raise RuntimeError("owner_canary_owned_runtime_artifact_missing")
    return path


def _load_sealed(path: Path, schema: str) -> dict[str, Any]:
    if (
        path.is_symlink()
        or not path.is_file()
        or path.stat().st_mode & 0o777 != 0o600
        or path.parent.is_symlink()
        or not path.parent.is_dir()
        or path.parent.stat().st_mode & 0o777 != 0o700
    ):
        raise RuntimeError("owner_canary_owned_runtime_artifact_invalid")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("owner_canary_owned_runtime_artifact_invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError("owner_canary_owned_runtime_artifact_invalid")
    try:
        return verify_sealed_artifact(value, schema=schema)
    except ValueError as exc:
        raise RuntimeError("owner_canary_owned_runtime_artifact_invalid") from exc


def _model_root(settings: Settings) -> Path:
    root = settings.project_root / "models/runtime/Qwen3.5-9B-4bit"
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("model_artifact_identity_mismatch")
    return root


def _validate_fixed_settings(settings: Settings) -> None:
    host, port = validate_completion_launcher_settings(settings)
    if (
        host != OWNER_CANARY_MODEL_HOST
        or port != OWNER_CANARY_MODEL_PORT
        or settings.model_url != f"http://{OWNER_CANARY_MODEL_HOST}:{OWNER_CANARY_MODEL_PORT}"
        or settings.model_id != PINNED_RUNTIME_REPO
        or os.environ.get("LEGALBOT_MODEL_ADAPTER_PATH", "").strip()
    ):
        raise RuntimeError("owner_canary_owned_runtime_settings_invalid")


def load_owner_canary_runtime_binding_and_memory_policy(
    *,
    settings: Settings,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
) -> tuple[dict[str, Any], LoadedCompletionMemoryPolicy]:
    """Recompute the exact completion-bound runtime and load owner memory authority."""

    from ..observability.live_metrics import load_slo_policy
    from .candidate_completion_authority import load_completion_memory_policy

    slo_path = settings.observability_slo_path
    if slo_path.is_symlink() or not slo_path.is_file():
        raise RuntimeError("owner_canary_slo_policy_invalid")
    slo = load_slo_policy(slo_path)
    binding = build_local_completion_runtime_binding(
        settings=settings,
        candidate=candidate,
        slo_policy_id=slo.policy_id,
        slo_policy_sha256=_file_sha256(slo_path),
        integration_sha=integration_sha,
    )
    policy = load_completion_memory_policy(
        settings.completion_memory_policy_path,
        owner_decision_root=settings.owner_decision_root,
        candidate=candidate,
        runtime_binding=binding,
        integration_sha=integration_sha,
    )
    return binding, policy


def _policy_identity(memory_policy: LoadedCompletionMemoryPolicy) -> tuple[Any, str]:
    if type(memory_policy) is not LoadedCompletionMemoryPolicy:
        raise RuntimeError("completion_memory_policy_not_loader_verified")
    policy = memory_policy.policy
    return policy, memory_policy.source_file_sha256


def _enforce_memory(
    memory_policy: LoadedCompletionMemoryPolicy,
    *,
    peak_combined_working_set_bytes: int,
    minimum_host_available_memory_bytes: int,
    maximum_observed_sample_interval_seconds: float,
) -> None:
    policy, _ = _policy_identity(memory_policy)
    if peak_combined_working_set_bytes > policy.max_peak_combined_working_set_bytes:
        raise RuntimeError("memory_working_set_exceeds_owner_ceiling")
    if minimum_host_available_memory_bytes < policy.minimum_host_available_memory_bytes:
        raise RuntimeError("memory_headroom_below_owner_minimum")
    if maximum_observed_sample_interval_seconds > MEMORY_MAX_SAMPLE_INTERVAL_SECONDS:
        raise RuntimeError("memory_sampling_interval_exceeded")


def _memory_payload(sampler: WorkflowMemorySampler) -> dict[str, Any]:
    return {
        "measurement_method": MEMORY_MEASUREMENT_METHOD,
        "sampling_interval_seconds": MEMORY_SAMPLE_INTERVAL_SECONDS,
        "maximum_allowed_sample_interval_seconds": MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
        "sample_count": sampler.sample_count,
        "maximum_observed_sample_interval_seconds": round(
            sampler.maximum_observed_sample_interval_seconds, 6
        ),
        "maximum_sampling_jitter_seconds": round(sampler.maximum_sampling_jitter_seconds, 6),
        "controller_sampled_peak_rss_bytes": sampler.controller_peak_rss_bytes,
        "owned_sidecar_tree_sampled_peak_rss_bytes": sampler.sidecar_peak_rss_bytes,
        "sampled_peak_combined_working_set_bytes": (sampler.peak_combined_working_set_bytes),
        "minimum_sampled_host_available_memory_bytes": (
            sampler.minimum_host_available_memory_bytes or 0
        ),
    }


def _assert_memory_payload(
    value: Mapping[str, Any], memory_policy: LoadedCompletionMemoryPolicy
) -> None:
    if (
        value.get("measurement_method") != MEMORY_MEASUREMENT_METHOD
        or value.get("sampling_interval_seconds") != MEMORY_SAMPLE_INTERVAL_SECONDS
        or value.get("maximum_allowed_sample_interval_seconds")
        != MEMORY_MAX_SAMPLE_INTERVAL_SECONDS
        or not isinstance(value.get("sample_count"), int)
        or int(value["sample_count"]) < 1
    ):
        raise RuntimeError("owner_canary_owned_runtime_memory_invalid")
    _enforce_memory(
        memory_policy,
        peak_combined_working_set_bytes=int(
            value.get("sampled_peak_combined_working_set_bytes") or 0
        ),
        minimum_host_available_memory_bytes=int(
            value.get("minimum_sampled_host_available_memory_bytes") or 0
        ),
        maximum_observed_sample_interval_seconds=float(
            value.get("maximum_observed_sample_interval_seconds") or 0.0
        ),
    )


def _assert_cumulative_memory(prior: Mapping[str, Any], current: Mapping[str, Any]) -> None:
    nondecreasing = (
        "sample_count",
        "maximum_observed_sample_interval_seconds",
        "maximum_sampling_jitter_seconds",
        "controller_sampled_peak_rss_bytes",
        "owned_sidecar_tree_sampled_peak_rss_bytes",
        "sampled_peak_combined_working_set_bytes",
    )
    if any(float(current.get(key) or 0) < float(prior.get(key) or 0) for key in nondecreasing):
        raise RuntimeError("owner_canary_owned_runtime_memory_not_cumulative")
    if int(current.get("minimum_sampled_host_available_memory_bytes") or 0) > int(
        prior.get("minimum_sampled_host_available_memory_bytes") or 0
    ):
        raise RuntimeError("owner_canary_owned_runtime_memory_not_cumulative")


class OwnerCanaryOwnedRuntimeStart(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-owned-runtime-start.v1"] = Field(
        default="legalbot.owner-canary-owned-runtime-start.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    lane: Literal["development", "blind_holdout"]
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    privacy_root_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    completion_preflight_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_source_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_model_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_model_file_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_toolchain_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    installed_environment_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_python_runtime_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    venv_control_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launcher_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_runtime_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    launch_argv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_id: Literal["mlx-community/Qwen3.5-9B-4bit"]
    model_revision: Literal["8b2b98c00a6b4d291155e4890773ca8f769aee53"]
    model_host: Literal["127.0.0.1"]
    model_port: Literal[8778]
    launched_pid: int = Field(ge=1)
    owned_process_group_id: int = Field(ge=1)
    launch_nonce: str = Field(pattern=r"^[0-9a-f]{64}$")
    owned_listener_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_instance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorized_case_ids: tuple[str, ...]
    startup_memory: dict[str, Any]
    adapter_present: Literal[False]
    proxy_environment_inherited: Literal[False]
    local_only: Literal[True]
    public_traffic_allowed: Literal[False]
    writes_active: Literal[False]
    writes_o04: Literal[False]
    synthetic_non_authoritative: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_and_sealed(self) -> Self:
        if (
            len(self.authorized_case_ids) != 30
            or len(set(self.authorized_case_ids)) != 30
            or any(not _CASE_ID.fullmatch(case_id) for case_id in self.authorized_case_ids)
            or self.owned_process_group_id != self.launched_pid
            or self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True))
        ):
            raise ValueError("owner-canary owned runtime start is invalid")
        return self


class OwnerCanaryOwnedRuntimeCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-owned-runtime-checkpoint.v1"] = Field(
        default="legalbot.owner-canary-owned-runtime-checkpoint.v1", alias="schema"
    )
    run_id: str
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    sequence_number: int = Field(ge=1, le=30)
    phase: Literal["before_case", "after_case"]
    start_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_instance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owned_listener_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory: dict[str, Any]
    model_artifact_rehashed: Literal[True]
    toolchain_rehashed: Literal[True]
    integration_reverified: Literal[True]
    release_authority_active: Literal[True]
    frontier_generation: int = Field(ge=1, le=61)
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_and_sealed(self) -> Self:
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary owned runtime checkpoint seal differs")
        return self


class OwnerCanaryOwnedRuntimeEnd(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-owned-runtime-end.v1"] = Field(
        default="legalbot.owner-canary-owned-runtime-end.v1", alias="schema"
    )
    run_id: str
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    start_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_instance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    memory_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_ids: tuple[str, ...]
    before_checkpoint_seal_sha256s: tuple[str, ...]
    after_checkpoint_seal_sha256s: tuple[str, ...]
    checkpoint_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    full_run_memory: dict[str, Any]
    final_owned_listener_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_artifact_rehashed_after_run: Literal[True]
    toolchain_rehashed_after_run: Literal[True]
    integration_reverified_after_run: Literal[True]
    owned_process_stopped: Literal[True]
    memory_monitor_active_through_process_exit: Literal[True]
    owned_process_group_and_nonce_lineage_absent_after_stop: Literal[True]
    shutdown_controller_and_host_sampled: Literal[True]
    successful_end: Literal[True]
    synthetic_non_authoritative: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def complete_and_sealed(self) -> Self:
        if (
            len(self.case_ids) != 30
            or len(self.before_checkpoint_seal_sha256s) != 30
            or len(self.after_checkpoint_seal_sha256s) != 30
            or len(set(self.case_ids)) != 30
            or self.checkpoint_set_sha256
            != sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-owned-runtime-checkpoint-set.v1",
                    "case_ids": list(self.case_ids),
                    "before": list(self.before_checkpoint_seal_sha256s),
                    "after": list(self.after_checkpoint_seal_sha256s),
                }
            )
            or self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True))
        ):
            raise ValueError("owner-canary owned runtime end is incomplete")
        return self


@dataclass(frozen=True, slots=True, init=False)
class VerifiedActiveOwnerCanaryRuntime:
    start: OwnerCanaryOwnedRuntimeStart
    before_checkpoint: OwnerCanaryOwnedRuntimeCheckpoint
    _token: object

    def __init__(
        self,
        *,
        start: OwnerCanaryOwnedRuntimeStart,
        before_checkpoint: OwnerCanaryOwnedRuntimeCheckpoint,
        token: object,
    ) -> None:
        if token is not _ACTIVE_TOKEN:
            raise RuntimeError("owner_canary_owned_runtime_not_verified")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "before_checkpoint", before_checkpoint)
        object.__setattr__(self, "_token", token)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedEndedOwnerCanaryRuntime:
    start: OwnerCanaryOwnedRuntimeStart
    end: OwnerCanaryOwnedRuntimeEnd
    checkpoints: tuple[OwnerCanaryOwnedRuntimeCheckpoint, ...]
    _token: object

    def __init__(
        self,
        *,
        start: OwnerCanaryOwnedRuntimeStart,
        end: OwnerCanaryOwnedRuntimeEnd,
        checkpoints: tuple[OwnerCanaryOwnedRuntimeCheckpoint, ...],
        token: object,
    ) -> None:
        if token is not _ENDED_TOKEN:
            raise RuntimeError("owner_canary_owned_runtime_end_not_verified")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)
        object.__setattr__(self, "checkpoints", checkpoints)
        object.__setattr__(self, "_token", token)


def require_verified_active_owner_canary_runtime(
    value: object,
) -> VerifiedActiveOwnerCanaryRuntime:
    if type(value) is not VerifiedActiveOwnerCanaryRuntime or value._token is not _ACTIVE_TOKEN:
        raise RuntimeError("owner_canary_owned_runtime_not_verified")
    return value


def require_verified_ended_owner_canary_runtime(
    value: object,
) -> VerifiedEndedOwnerCanaryRuntime:
    if type(value) is not VerifiedEndedOwnerCanaryRuntime or value._token is not _ENDED_TOKEN:
        raise RuntimeError("owner_canary_owned_runtime_end_not_verified")
    return value


def _verify_static_bindings(
    *,
    settings: Settings,
    workspace_root: Path,
    start: OwnerCanaryOwnedRuntimeStart,
    candidate: SealedCandidateIdentity,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    workspace_seal_sha256: str,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    completion_preflight_result_sha256: str,
    require_live_process: bool = True,
) -> VerifiedModelToolchain:
    _validate_fixed_settings(settings)
    policy, policy_source_sha = _policy_identity(memory_policy)
    toolchain = resolve_verified_model_toolchain(settings.project_root)
    trusted_model = load_trusted_model_identity(settings.project_root)
    _verify_model_artifact_manifest(_model_root(settings), trusted_model)
    toolchain_binding = toolchain.safe_binding()
    expected = (
        authorization_seal_sha256,
        canary_manifest_seal_sha256,
        workspace_seal_sha256,
        candidate.build_id,
        candidate.candidate_manifest_sha256,
        _clean_integration_sha(settings.project_root),
        completion_preflight_result_sha256,
        str(runtime_binding.get("seal_sha256") or ""),
        policy.seal_sha256,
        policy_source_sha,
        str(trusted_model["seal_sha256"]),
        str(trusted_model["file_manifest_sha256"]),
        str(toolchain_binding["trusted_toolchain_identity_sha256"]),
        str(toolchain_binding["installed_environment_manifest_sha256"]),
        str(toolchain_binding["base_python_runtime_manifest_sha256"]),
        str(toolchain_binding["venv_control_manifest_sha256"]),
        _file_sha256(Path(__file__)),
        _file_sha256(settings.project_root / "backend/app/model_runtime/adapters.py"),
    )
    observed = (
        start.authorization_seal_sha256,
        start.canary_manifest_seal_sha256,
        start.workspace_seal_sha256,
        start.candidate_build_id,
        start.candidate_manifest_sha256,
        start.integration_sha,
        start.completion_preflight_result_sha256,
        start.runtime_binding_sha256,
        start.memory_policy_sha256,
        start.memory_policy_source_file_sha256,
        start.trusted_model_identity_sha256,
        start.trusted_model_file_manifest_sha256,
        start.trusted_toolchain_identity_sha256,
        start.installed_environment_manifest_sha256,
        start.base_python_runtime_manifest_sha256,
        start.venv_control_manifest_sha256,
        start.launcher_implementation_sha256,
        start.model_runtime_implementation_sha256,
    )
    if observed != expected:
        raise RuntimeError("owner_canary_owned_runtime_binding_mismatch")
    _assert_memory_payload(start.startup_memory, memory_policy)
    expected_privacy_root_sha256 = sealed_sha256(
        {
            "schema": "legalbot.owner-canary-private-output-root.v1",
            "resolved_root": str(workspace_root_for_privacy(settings, start.run_id, start.lane)),
        }
    )
    if start.privacy_root_sha256 != expected_privacy_root_sha256:
        raise RuntimeError("owner_canary_owned_runtime_privacy_root_mismatch")
    _verify_launch_argv_binding(
        settings=settings,
        workspace_root=workspace_root,
        start=start,
        toolchain=toolchain,
    )
    if require_live_process:
        _verify_owned_process_command(
            settings=settings,
            workspace_root=workspace_root,
            start=start,
            toolchain=toolchain,
        )
    return toolchain


def workspace_root_for_privacy(
    settings: Settings,
    run_id: str,
    lane: Literal["development", "blind_holdout"],
) -> Path:
    """Return the configured privacy root without persisting its absolute path."""

    del run_id
    from .owner_quality_canary_runtime import configured_authoritative_canary_output_root

    return configured_authoritative_canary_output_root(settings, lane).resolve(strict=True)


def _expected_launch_argv(
    *,
    settings: Settings,
    workspace_root: Path,
    start: OwnerCanaryOwnedRuntimeStart,
    toolchain: VerifiedModelToolchain,
) -> tuple[str, ...]:
    # The private cache path is derived from the workspace root and nonce by the
    # verifier caller; only its digest enters the safe attestation.
    private_pycache = (
        workspace_root
        / "safe-metrics"
        / "owned-runtime-pycache"
        / hashlib.sha256(start.launch_nonce.encode()).hexdigest()
    )
    return (
        str(toolchain.python_executable),
        *isolated_model_python_arguments(
            settings.project_root,
            private_pycache_root=private_pycache,
        ),
    )


def _verify_owned_process_command(
    *,
    settings: Settings,
    workspace_root: Path,
    start: OwnerCanaryOwnedRuntimeStart,
    toolchain: VerifiedModelToolchain,
) -> None:
    expected = _expected_launch_argv(
        settings=settings,
        workspace_root=workspace_root,
        start=start,
        toolchain=toolchain,
    )
    ps_path = toolchain.system_tools.get("ps")
    if ps_path is None:
        raise RuntimeError("owner_canary_owned_runtime_process_unverifiable")
    try:
        completed = subprocess.run(
            [str(ps_path), "-ww", "-p", str(start.launched_pid), "-o", "command="],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C"},
        )
        observed = tuple(shlex.split(completed.stdout.strip()))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise RuntimeError("owner_canary_owned_runtime_process_unverifiable") from exc
    if observed != expected:
        raise RuntimeError("owner_canary_owned_runtime_argv_mismatch")
    try:
        observed_group = os.getpgid(start.launched_pid)
    except (OSError, ProcessLookupError) as exc:
        raise RuntimeError("owner_canary_owned_runtime_process_unverifiable") from exc
    if observed_group != start.owned_process_group_id:
        raise RuntimeError("owner_canary_owned_runtime_process_group_changed")


def _process_group_members(*, ps_path: Path, process_group_id: int) -> tuple[int, ...]:
    try:
        completed = subprocess.run(
            [str(ps_path), "-axo", "pid=,pgid="],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("owner_canary_owned_runtime_process_group_unverifiable") from exc
    members: list[int] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or not all(field.isdigit() for field in fields):
            continue
        pid, group_id = (int(field) for field in fields)
        if group_id == process_group_id:
            members.append(pid)
    return tuple(sorted(members))


def _verify_launch_argv_binding(
    *,
    settings: Settings,
    workspace_root: Path,
    start: OwnerCanaryOwnedRuntimeStart,
    toolchain: VerifiedModelToolchain,
) -> None:
    expected = _expected_launch_argv(
        settings=settings,
        workspace_root=workspace_root,
        start=start,
        toolchain=toolchain,
    )
    if start.launch_argv_sha256 != sealed_sha256(
        {"schema": "legalbot.owner-canary-owned-runtime-argv.v1", "argv": list(expected)}
    ):
        raise RuntimeError("owner_canary_owned_runtime_argv_mismatch")


def _verify_health(start: OwnerCanaryOwnedRuntimeStart, runtime_binding: Mapping[str, Any]) -> None:
    try:
        with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
            response = client.get(
                f"http://{OWNER_CANARY_MODEL_HOST}:{OWNER_CANARY_MODEL_PORT}/api/v1/health"
            )
        payload = response.json()
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        raise RuntimeError("owner_canary_owned_runtime_health_invalid") from exc
    if (
        response.status_code != 200
        or not isinstance(payload, Mapping)
        or payload.get("status") != "ok"
        or payload.get("backend") != "mlx_lm"
        or payload.get("model_id") != start.model_id
        or payload.get("model_loaded") is not True
        or payload.get("stub_mode") is not False
        or payload.get("memory_profile") != runtime_binding.get("model_runtime_profile")
    ):
        raise RuntimeError("owner_canary_owned_runtime_health_invalid")


def load_active_owner_canary_runtime(
    *,
    settings: Settings,
    workspace_root: Path,
    case_id: str,
    candidate: SealedCandidateIdentity,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    workspace_seal_sha256: str,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    completion_preflight_result_sha256: str,
    database: Database,
) -> VerifiedActiveOwnerCanaryRuntime:
    """Re-attest the active process/listener immediately before admission/release."""

    if not _CASE_ID.fullmatch(case_id):
        raise RuntimeError("owner_canary_owned_runtime_case_invalid")
    failure = workspace_root / "safe-metrics" / OWNED_RUNTIME_FAILURE_FILENAME
    ended = workspace_root / "safe-metrics" / OWNED_RUNTIME_END_FILENAME
    if failure.exists() or ended.exists():
        raise RuntimeError("owner_canary_owned_runtime_not_active")
    start = OwnerCanaryOwnedRuntimeStart.model_validate(
        _load_sealed(
            _safe_runtime_file(workspace_root, OWNED_RUNTIME_START_FILENAME),
            OWNED_RUNTIME_START_SCHEMA,
        )
    )
    toolchain = _verify_static_bindings(
        settings=settings,
        workspace_root=workspace_root,
        start=start,
        candidate=candidate,
        authorization_seal_sha256=authorization_seal_sha256,
        canary_manifest_seal_sha256=canary_manifest_seal_sha256,
        workspace_seal_sha256=workspace_seal_sha256,
        runtime_binding=runtime_binding,
        memory_policy=memory_policy,
        completion_preflight_result_sha256=completion_preflight_result_sha256,
    )
    sequence = start.authorized_case_ids.index(case_id) + 1
    before_path = (
        workspace_root
        / "safe-metrics"
        / OWNED_RUNTIME_CHECKPOINT_DIRNAME
        / f"{sequence:02d}-{case_id}-before.json"
    )
    before = OwnerCanaryOwnedRuntimeCheckpoint.model_validate(
        _load_sealed(before_path, OWNED_RUNTIME_CHECKPOINT_SCHEMA)
    )
    if (
        before.run_id != start.run_id
        or before.case_id != case_id
        or before.sequence_number != sequence
        or before.phase != "before_case"
        or before.start_attestation_sha256 != start.seal_sha256
        or before.runtime_instance_sha256 != start.runtime_instance_sha256
        or before.memory_policy_sha256 != start.memory_policy_sha256
    ):
        raise RuntimeError("owner_canary_owned_runtime_checkpoint_mismatch")
    _assert_memory_payload(before.memory, memory_policy)
    checkpoint_root = before_path.parent
    expected_names: list[str] = []
    for prior_sequence, prior_case_id in enumerate(
        start.authorized_case_ids[: sequence - 1], start=1
    ):
        expected_names.extend(
            (
                f"{prior_sequence:02d}-{prior_case_id}-before.json",
                f"{prior_sequence:02d}-{prior_case_id}-after.json",
            )
        )
    expected_names.append(f"{sequence:02d}-{case_id}-before.json")
    members = tuple(sorted(checkpoint_root.iterdir(), key=lambda path: path.name))
    if tuple(path.name for path in members) != tuple(sorted(expected_names)) or any(
        path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600
        for path in members
    ):
        raise RuntimeError("owner_canary_owned_runtime_frontier_artifacts_invalid")
    session = database.owner_canary_runtime_session(start.run_id)
    if (
        session is None
        or session["status"] != "active"
        or session["authorization_sha256"] != start.authorization_seal_sha256
        or session["start_attestation_sha256"] != start.seal_sha256
        or session["runtime_instance_sha256"] != start.runtime_instance_sha256
        or session["candidate_build_id"] != start.candidate_build_id
        or session["memory_policy_sha256"] != start.memory_policy_sha256
        or int(session["next_sequence"]) != sequence
        or session["active_case_id"] != case_id
        or session["active_before_checkpoint_sha256"] != before.seal_sha256
        or int(session["frontier_generation"]) != before.frontier_generation
        or int(session["controller_pid"]) != os.getpid()
        or datetime.fromisoformat(str(session["lease_expires_at"])) <= datetime.now(UTC)
    ):
        raise RuntimeError("owner_canary_owned_runtime_frontier_changed")
    listener = attest_owned_listener(
        launched_pid=start.launched_pid,
        port=OWNER_CANARY_MODEL_PORT,
        nonce=start.launch_nonce,
    )
    if listener != before.owned_listener_proof_sha256:
        raise RuntimeError("owner_canary_owned_runtime_listener_changed")
    if listener != start.owned_listener_proof_sha256:
        raise RuntimeError("owner_canary_owned_runtime_listener_changed")
    _verify_health(start, runtime_binding)
    fresh = WorkflowMemorySampler(
        owned_sidecar_pid=start.launched_pid,
        launch_nonce=start.launch_nonce,
        owned_listener_proof_sha256=listener,
        system_tools=toolchain.system_tools,
    )
    fresh.sample()
    _enforce_memory(
        memory_policy,
        peak_combined_working_set_bytes=fresh.peak_combined_working_set_bytes,
        minimum_host_available_memory_bytes=(fresh.minimum_host_available_memory_bytes or 0),
        maximum_observed_sample_interval_seconds=(fresh.maximum_observed_sample_interval_seconds),
    )
    # Rehash the trusted system-tool manifest as part of every replay.
    if toolchain.safe_binding()["trusted_toolchain_identity_sha256"] != (
        start.trusted_toolchain_identity_sha256
    ):
        raise RuntimeError("owner_canary_owned_runtime_toolchain_changed")
    # Close races with a concurrent failure/end/frontier advance after the
    # expensive model/toolchain/health checks.
    final_session = database.owner_canary_runtime_session(start.run_id)
    if (
        failure.exists()
        or ended.exists()
        or final_session is None
        or final_session["status"] != "active"
        or final_session["active_case_id"] != case_id
        or final_session["active_before_checkpoint_sha256"] != before.seal_sha256
        or int(final_session["frontier_generation"]) != before.frontier_generation
        or int(final_session["controller_pid"]) != os.getpid()
        or datetime.fromisoformat(str(final_session["lease_expires_at"])) <= datetime.now(UTC)
    ):
        raise RuntimeError("owner_canary_owned_runtime_frontier_changed")
    return VerifiedActiveOwnerCanaryRuntime(
        start=start,
        before_checkpoint=before,
        token=_ACTIVE_TOKEN,
    )


def load_ended_owner_canary_runtime(
    *,
    settings: Settings,
    workspace_root: Path,
    candidate: SealedCandidateIdentity,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    workspace_seal_sha256: str,
    runtime_binding: Mapping[str, Any],
    memory_policy: LoadedCompletionMemoryPolicy,
    completion_preflight_result_sha256: str,
    expected_case_ids: Sequence[str],
    database: Database,
) -> VerifiedEndedOwnerCanaryRuntime:
    """Strictly replay one successful historical owned-runtime artifact set."""

    failure = workspace_root / "safe-metrics" / OWNED_RUNTIME_FAILURE_FILENAME
    if failure.exists():
        raise RuntimeError("owner_canary_owned_runtime_failed")
    start = OwnerCanaryOwnedRuntimeStart.model_validate(
        _load_sealed(
            _safe_runtime_file(workspace_root, OWNED_RUNTIME_START_FILENAME),
            OWNED_RUNTIME_START_SCHEMA,
        )
    )
    end = OwnerCanaryOwnedRuntimeEnd.model_validate(
        _load_sealed(
            _safe_runtime_file(workspace_root, OWNED_RUNTIME_END_FILENAME),
            OWNED_RUNTIME_END_SCHEMA,
        )
    )
    _verify_static_bindings(
        settings=settings,
        workspace_root=workspace_root,
        start=start,
        candidate=candidate,
        authorization_seal_sha256=authorization_seal_sha256,
        canary_manifest_seal_sha256=canary_manifest_seal_sha256,
        workspace_seal_sha256=workspace_seal_sha256,
        runtime_binding=runtime_binding,
        memory_policy=memory_policy,
        completion_preflight_result_sha256=completion_preflight_result_sha256,
        require_live_process=False,
    )
    case_ids = tuple(expected_case_ids)
    if start.authorized_case_ids != case_ids or end.case_ids != case_ids:
        raise RuntimeError("owner_canary_owned_runtime_case_set_mismatch")
    checkpoints: list[OwnerCanaryOwnedRuntimeCheckpoint] = []
    before_seals: list[str] = []
    after_seals: list[str] = []
    checkpoint_root = workspace_root / "safe-metrics" / OWNED_RUNTIME_CHECKPOINT_DIRNAME
    members = tuple(sorted(checkpoint_root.iterdir(), key=lambda path: path.name))
    expected_names: list[str] = []
    prior_memory: Mapping[str, Any] = start.startup_memory
    for sequence, case_id in enumerate(case_ids, start=1):
        for phase, suffix in (("before_case", "before"), ("after_case", "after")):
            name = f"{sequence:02d}-{case_id}-{suffix}.json"
            expected_names.append(name)
            checkpoint = OwnerCanaryOwnedRuntimeCheckpoint.model_validate(
                _load_sealed(checkpoint_root / name, OWNED_RUNTIME_CHECKPOINT_SCHEMA)
            )
            if (
                checkpoint.run_id != start.run_id
                or checkpoint.case_id != case_id
                or checkpoint.sequence_number != sequence
                or checkpoint.phase != phase
                or checkpoint.start_attestation_sha256 != start.seal_sha256
                or checkpoint.runtime_instance_sha256 != start.runtime_instance_sha256
                or checkpoint.memory_policy_sha256 != start.memory_policy_sha256
                or checkpoint.owned_listener_proof_sha256 != start.owned_listener_proof_sha256
                or checkpoint.frontier_generation
                != (sequence * 2 - 1 if phase == "before_case" else sequence * 2)
            ):
                raise RuntimeError("owner_canary_owned_runtime_checkpoint_mismatch")
            _assert_memory_payload(checkpoint.memory, memory_policy)
            _assert_cumulative_memory(prior_memory, checkpoint.memory)
            prior_memory = checkpoint.memory
            checkpoints.append(checkpoint)
            (before_seals if phase == "before_case" else after_seals).append(checkpoint.seal_sha256)
    if tuple(path.name for path in members) != tuple(sorted(expected_names)):
        raise RuntimeError("owner_canary_owned_runtime_checkpoint_set_mismatch")
    if (
        end.run_id != start.run_id
        or end.authorization_seal_sha256 != start.authorization_seal_sha256
        or end.canary_manifest_seal_sha256 != start.canary_manifest_seal_sha256
        or end.workspace_seal_sha256 != start.workspace_seal_sha256
        or end.candidate_build_id != start.candidate_build_id
        or end.candidate_manifest_sha256 != start.candidate_manifest_sha256
        or end.integration_sha != start.integration_sha
        or end.start_attestation_sha256 != start.seal_sha256
        or end.runtime_instance_sha256 != start.runtime_instance_sha256
        or end.memory_policy_sha256 != start.memory_policy_sha256
        or end.before_checkpoint_seal_sha256s != tuple(before_seals)
        or end.after_checkpoint_seal_sha256s != tuple(after_seals)
        or end.final_owned_listener_proof_sha256 != start.owned_listener_proof_sha256
    ):
        raise RuntimeError("owner_canary_owned_runtime_end_mismatch")
    _assert_memory_payload(end.full_run_memory, memory_policy)
    _assert_cumulative_memory(prior_memory, end.full_run_memory)
    session = database.owner_canary_runtime_session(start.run_id)
    if (
        session is None
        or session["status"] != "ended"
        or session["authorization_sha256"] != start.authorization_seal_sha256
        or session["start_attestation_sha256"] != start.seal_sha256
        or session["runtime_instance_sha256"] != start.runtime_instance_sha256
        or session["memory_policy_sha256"] != start.memory_policy_sha256
        or int(session["next_sequence"]) != 31
        or int(session["frontier_generation"]) != 61
        or session["active_case_id"] is not None
        or session["end_attestation_sha256"] != end.seal_sha256
    ):
        raise RuntimeError("owner_canary_owned_runtime_end_frontier_invalid")
    return VerifiedEndedOwnerCanaryRuntime(
        start=start,
        end=end,
        checkpoints=tuple(checkpoints),
        token=_ENDED_TOKEN,
    )


class _MemoryMonitor:
    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        nonce: str,
        memory_policy: LoadedCompletionMemoryPolicy,
        toolchain: VerifiedModelToolchain,
        on_failure: Any,
        on_sample: Any | None = None,
        phase: Literal["startup", "workflow"],
        owned_process_group_id: int,
    ) -> None:
        self.process = process
        self.memory_policy = memory_policy
        self.on_failure = on_failure
        self.on_sample = on_sample
        self.owned_process_group_id = owned_process_group_id
        self.sampler = WorkflowMemorySampler(
            owned_sidecar_pid=process.pid,
            launch_nonce=nonce,
            phase=phase,
            system_tools=toolchain.system_tools,
        )
        self._stop = threading.Event()
        self._expected_process_exit = threading.Event()
        self._shutdown_group_owned = False
        self._thread = threading.Thread(
            target=self._run,
            name=f"owner-canary-{phase}-memory",
            daemon=True,
        )
        self._sample_lock = threading.Lock()

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        deadline = time.monotonic()
        try:
            while not self._stop.is_set():
                if not self.sample_now():
                    break
                if self.on_sample is not None:
                    self.on_sample()
                deadline += MEMORY_SAMPLE_INTERVAL_SECONDS
                self._stop.wait(max(0.0, deadline - time.monotonic()))
        except BaseException as exc:  # monitor failure must invalidate the whole run
            self.on_failure(exc)

    def sample_now(self) -> bool:
        with self._sample_lock:
            try:
                self.sampler.sample()
            except RuntimeError as exc:
                if (
                    self._expected_process_exit.is_set()
                    and self.process.poll() is not None
                    and exc.args
                    and exc.args[0] == "owned_sidecar_process_missing"
                ):
                    rows, owned_pids = self._shutdown_snapshot()
                    if not owned_pids:
                        return False
                    self._record_shutdown_sample(rows=rows, owned_pids=owned_pids)
                    return True
                raise
            _enforce_memory(
                self.memory_policy,
                peak_combined_working_set_bytes=(self.sampler.peak_combined_working_set_bytes),
                minimum_host_available_memory_bytes=(
                    self.sampler.minimum_host_available_memory_bytes or 0
                ),
                maximum_observed_sample_interval_seconds=(
                    self.sampler.maximum_observed_sample_interval_seconds
                ),
            )
        return True

    def _shutdown_snapshot(
        self,
    ) -> tuple[tuple[tuple[int, int, int], ...], frozenset[int]]:
        rows, group_members, nonce_matches = self._raw_shutdown_snapshot()
        if not group_members.issubset(nonce_matches):
            raise RuntimeError("owned_sidecar_nonce_mismatch")
        return rows, frozenset(group_members | nonce_matches)

    def _raw_shutdown_snapshot(
        self,
    ) -> tuple[
        tuple[tuple[int, int, int], ...],
        frozenset[int],
        frozenset[int],
    ]:
        ps_path = self.sampler.system_tools.get("ps")
        if ps_path is None:
            raise RuntimeError("memory_measurement_tool_identity_invalid")
        rows, nonce_matches = _process_memory_snapshot(
            nonce=self.sampler.launch_nonce,
            ps_path=ps_path,
        )
        group_members = frozenset(
            _process_group_members(
                ps_path=ps_path,
                process_group_id=self.owned_process_group_id,
            )
        )
        return rows, group_members, nonce_matches

    def _record_shutdown_sample(
        self,
        *,
        rows: tuple[tuple[int, int, int], ...],
        owned_pids: frozenset[int],
    ) -> None:
        by_pid = {pid: rss for pid, _, rss in rows}
        if not owned_pids.issubset(by_pid):
            raise RuntimeError("memory_measurement_unavailable")
        controller = by_pid.get(os.getpid())
        if controller is None:
            raise RuntimeError("memory_measurement_unavailable")
        available = host_available_memory_bytes(
            vm_stat_path=self.sampler.system_tools.get("vm_stat")
        )
        sampled_at = time.monotonic()
        previous = self.sampler._last_sample_monotonic
        if previous is not None:
            observed_interval = sampled_at - previous
            self.sampler.maximum_observed_sample_interval_seconds = max(
                self.sampler.maximum_observed_sample_interval_seconds,
                observed_interval,
            )
            self.sampler.maximum_sampling_jitter_seconds = max(
                self.sampler.maximum_sampling_jitter_seconds,
                max(0.0, observed_interval - self.sampler.interval_seconds),
            )
        self.sampler._last_sample_monotonic = sampled_at
        sidecar = sum(by_pid[pid] for pid in owned_pids)
        self.sampler.controller_peak_rss_bytes = max(
            self.sampler.controller_peak_rss_bytes,
            controller,
        )
        self.sampler.sidecar_peak_rss_bytes = max(
            self.sampler.sidecar_peak_rss_bytes,
            sidecar,
        )
        self.sampler.peak_combined_working_set_bytes = max(
            self.sampler.peak_combined_working_set_bytes,
            controller + sidecar,
        )
        self.sampler.minimum_host_available_memory_bytes = min(
            self.sampler.minimum_host_available_memory_bytes
            if self.sampler.minimum_host_available_memory_bytes is not None
            else available,
            available,
        )
        self.sampler.sample_count += 1
        _enforce_memory(
            self.memory_policy,
            peak_combined_working_set_bytes=(self.sampler.peak_combined_working_set_bytes),
            minimum_host_available_memory_bytes=(
                self.sampler.minimum_host_available_memory_bytes or 0
            ),
            maximum_observed_sample_interval_seconds=(
                self.sampler.maximum_observed_sample_interval_seconds
            ),
        )

    def begin_owned_process_shutdown(self) -> None:
        """Signal termination before allowing the exact parent disappearance."""

        with self._sample_lock:
            if self.process.poll() is not None:
                raise RuntimeError("owner_canary_owned_runtime_process_stopped_early")
            try:
                if os.getpgid(self.process.pid) != self.owned_process_group_id:
                    raise RuntimeError("owner_canary_owned_runtime_process_group_changed")
                self._shutdown_group_owned = True
                os.killpg(self.owned_process_group_id, signal.SIGTERM)
            except ProcessLookupError as exc:
                raise RuntimeError("owner_canary_owned_runtime_process_stopped_early") from exc
            self._expected_process_exit.set()

    def kill_remaining_owned_lineage(self, *, timeout_seconds: float = 15.0) -> None:
        """Kill and verify every remaining process-group/nonce lineage member."""

        deadline = time.monotonic() + timeout_seconds
        while True:
            with self._sample_lock:
                _, group_members, nonce_matches = self._raw_shutdown_snapshot()
                group_trusted = self._shutdown_group_owned or group_members.issubset(nonce_matches)
                owned_pids = frozenset(
                    nonce_matches | (group_members if group_trusted else frozenset())
                )
            if not owned_pids:
                self._shutdown_group_owned = False
                return
            if group_members and group_trusted:
                with suppress(ProcessLookupError):
                    os.killpg(self.owned_process_group_id, signal.SIGKILL)
            for pid in owned_pids:
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
            if time.monotonic() >= deadline:
                raise RuntimeError("owner_canary_owned_process_tree_not_stopped")
            time.sleep(0.05)

    def force_stop_owned_lineage(self) -> bool:
        """Best-effort failure cleanup that cannot mint successful authority."""

        self._expected_process_exit.set()
        process = self.process
        if process.poll() is None:
            try:
                if os.getpgid(process.pid) == self.owned_process_group_id:
                    self._shutdown_group_owned = True
                    os.killpg(self.owned_process_group_id, signal.SIGTERM)
                else:
                    process.terminate()
            except OSError:
                with suppress(ProcessLookupError):
                    process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if self._shutdown_group_owned:
                    with suppress(ProcessLookupError):
                        os.killpg(self.owned_process_group_id, signal.SIGKILL)
                with suppress(ProcessLookupError):
                    process.kill()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
        cleanup_confirmed = False
        try:
            self.kill_remaining_owned_lineage(timeout_seconds=5)
            with self._sample_lock:
                _, group_members, nonce_matches = self._raw_shutdown_snapshot()
            group_trusted = self._shutdown_group_owned or group_members.issubset(nonce_matches)
            cleanup_confirmed = not nonce_matches and (not group_members or not group_trusted)
        except BaseException:
            cleanup_confirmed = False
        self._stop.set()
        if threading.current_thread() is not self._thread and self._thread.ident is not None:
            self._thread.join(timeout=5)
            cleanup_confirmed = cleanup_confirmed and not self._thread.is_alive()
        return cleanup_confirmed

    def confirm_owned_process_stopped(self) -> None:
        """Prove the nonce-bound process tree is gone and sample the host once more."""

        if self.process.poll() is None:
            raise RuntimeError("owner_canary_owned_process_still_running")
        with self._sample_lock:
            rows, owned_pids = self._shutdown_snapshot()
            if owned_pids:
                raise RuntimeError("owner_canary_owned_process_tree_not_stopped")
            self._record_shutdown_sample(rows=rows, owned_pids=owned_pids)

    def payload(self) -> dict[str, Any]:
        with self._sample_lock:
            return _memory_payload(self.sampler)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("owner_canary_memory_monitor_stop_timeout")
        if self.sampler.sample_count < 1:
            raise RuntimeError("owner_canary_memory_measurement_missing")


class OwnerCanaryOwnedModelRuntime:
    """Production-only owner of one model process for one exact serial 30 run."""

    def __init__(
        self,
        *,
        settings: Settings,
        workspace_root: Path,
        workspace_seal_sha256: str,
        privacy_root_sha256: str,
        run_id: str,
        lane: Literal["development", "blind_holdout"],
        authorization_seal_sha256: str,
        canary_manifest_seal_sha256: str,
        candidate: SealedCandidateIdentity,
        integration_sha: str,
        completion_preflight_result_sha256: str,
        runtime_binding: Mapping[str, Any],
        memory_policy: LoadedCompletionMemoryPolicy,
        database: Database,
        authorized_case_ids: Sequence[str],
        startup_timeout_seconds: float = 900.0,
    ) -> None:
        if (
            not _SAFE_RUN.fullmatch(run_id)
            or tuple(authorized_case_ids) != tuple(dict.fromkeys(authorized_case_ids))
            or len(tuple(authorized_case_ids)) != 30
        ):
            raise RuntimeError("owner_canary_owned_runtime_contract_invalid")
        self.settings = settings
        self.workspace_root = workspace_root
        self.workspace_seal_sha256 = workspace_seal_sha256
        self.privacy_root_sha256 = privacy_root_sha256
        self.run_id = run_id
        self.lane = lane
        self.authorization_seal_sha256 = authorization_seal_sha256
        self.canary_manifest_seal_sha256 = canary_manifest_seal_sha256
        self.candidate = candidate
        self.integration_sha = integration_sha
        self.completion_preflight_result_sha256 = completion_preflight_result_sha256
        self.runtime_binding = dict(runtime_binding)
        self.memory_policy = memory_policy
        self.database = database
        self.authorized_case_ids = tuple(authorized_case_ids)
        self.startup_timeout_seconds = startup_timeout_seconds
        self.process: subprocess.Popen[bytes] | None = None
        self.toolchain: VerifiedModelToolchain | None = None
        self.start_attestation: OwnerCanaryOwnedRuntimeStart | None = None
        self.monitor: _MemoryMonitor | None = None
        self.nonce: str | None = None
        self.process_group_id: int | None = None
        self._failure: BaseException | None = None
        self._before: list[OwnerCanaryOwnedRuntimeCheckpoint] = []
        self._after: list[OwnerCanaryOwnedRuntimeCheckpoint] = []
        self._pending_case: str | None = None
        self._ended = False
        self._ending = False
        self._activated = False
        self._lock = threading.RLock()
        self._last_heartbeat_monotonic = 0.0

    @property
    def safe_metrics_root(self) -> Path:
        return self.workspace_root / "safe-metrics"

    @property
    def ended(self) -> bool:
        return self._ended

    def _record_failure(self, exc: BaseException) -> None:
        with self._lock:
            if self._failure is not None:
                return
            self._failure = exc
            with _ACTIVE_RUNTIME_LOCK:
                if _ACTIVE_RUNTIMES.get(self.run_id) is self:
                    _ACTIVE_RUNTIMES.pop(self.run_id, None)
            reason = (
                str(exc.args[0])
                if isinstance(exc, RuntimeError) and exc.args
                else type(exc).__name__.casefold()
            )
            # Revoke the transactional release frontier first.  Process-group
            # cleanup never depends on the fallible artifact write.
            cleanup_confirmed = False
            try:
                start = self.start_attestation
                if self._activated and start is not None:
                    self.database.revoke_owner_canary_runtime_session(
                        self.run_id,
                        start_attestation_sha256=start.seal_sha256,
                        runtime_instance_sha256=start.runtime_instance_sha256,
                    )
            finally:
                try:
                    cleanup_confirmed = self._stop_owned_process_lineage()
                except BaseException:
                    cleanup_confirmed = False
            payload = {
                "schema": OWNED_RUNTIME_FAILURE_SCHEMA,
                "run_id": self.run_id,
                "authorization_seal_sha256": self.authorization_seal_sha256,
                "start_attestation_sha256": (
                    self.start_attestation.seal_sha256 if self.start_attestation else None
                ),
                "reason_code": re.sub(r"[^a-z0-9._:-]+", "_", reason.casefold())[:128],
                "successful_end_created": False,
                "release_authority_revoked": True,
                "owned_process_cleanup_confirmed": cleanup_confirmed,
            }
            payload["seal_sha256"] = sealed_sha256(payload)
            failure_path = self.safe_metrics_root / OWNED_RUNTIME_FAILURE_FILENAME
            if not failure_path.exists():
                write_create_only_private_safe_json(failure_path, payload)

    def _stop_owned_process_lineage(self) -> bool:
        monitor = self.monitor
        if monitor is not None:
            return monitor.force_stop_owned_lineage()
        process = self.process
        process_group_id = self.process_group_id
        if process is None:
            return True
        group_owned = False
        if process.poll() is None:
            if process_group_id is not None:
                try:
                    group_owned = os.getpgid(process.pid) == process_group_id
                except OSError:
                    group_owned = False
            if group_owned and process_group_id is not None:
                with suppress(ProcessLookupError):
                    os.killpg(process_group_id, signal.SIGTERM)
            else:
                with suppress(ProcessLookupError):
                    process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if group_owned and process_group_id is not None:
                    with suppress(ProcessLookupError):
                        os.killpg(process_group_id, signal.SIGKILL)
                with suppress(ProcessLookupError):
                    process.kill()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
        toolchain = self.toolchain
        nonce = self.nonce
        if process_group_id is None or toolchain is None or nonce is None:
            return process.poll() is not None
        ps_path = toolchain.system_tools.get("ps")
        if ps_path is None:
            return False
        deadline = time.monotonic() + 5
        while True:
            try:
                _, nonce_matches = _process_memory_snapshot(
                    nonce=nonce,
                    ps_path=ps_path,
                )
                group_members = frozenset(
                    _process_group_members(
                        ps_path=ps_path,
                        process_group_id=process_group_id,
                    )
                )
            except BaseException:
                return False
            group_trusted = group_owned or group_members.issubset(nonce_matches)
            owned_pids = frozenset(
                nonce_matches | (group_members if group_trusted else frozenset())
            )
            if process.poll() is not None and not owned_pids:
                return True
            if group_members and group_trusted:
                with suppress(ProcessLookupError):
                    os.killpg(process_group_id, signal.SIGKILL)
            for pid in owned_pids:
                if pid in nonce_matches:
                    with suppress(ProcessLookupError):
                        os.kill(pid, signal.SIGKILL)
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def _raise_if_failed(self) -> None:
        if self._failure is not None:
            raise RuntimeError("owner_canary_owned_runtime_failed") from self._failure

    def _heartbeat(self, *, force: bool = False, lease_seconds: int = 5) -> None:
        start = self.start_attestation
        now = time.monotonic()
        if start is None or (not force and now - self._last_heartbeat_monotonic < 1.0):
            return
        self.database.heartbeat_owner_canary_runtime_session(
            run_id=self.run_id,
            start_attestation_sha256=start.seal_sha256,
            runtime_instance_sha256=start.runtime_instance_sha256,
            controller_pid=os.getpid(),
            lease_seconds=lease_seconds,
        )
        self._last_heartbeat_monotonic = now

    def _verify_atomic_release(self, authority: Mapping[str, Any]) -> None:
        """Check only in-memory/process facts; never block on DB or artifact IO."""

        start = self.start_attestation
        process = self.process
        if (
            self._failure is not None
            or self._ended
            or self._ending
            or start is None
            or process is None
            or process.poll() is not None
            or self._pending_case != authority.get("case_id")
            or start.seal_sha256 != authority.get("owned_runtime_start_attestation_sha256")
            or start.runtime_instance_sha256 != authority.get("owned_runtime_instance_sha256")
            or start.memory_policy_sha256 != authority.get("owned_runtime_memory_policy_sha256")
            or not self._before
            or self._before[-1].seal_sha256
            != authority.get("owned_runtime_before_checkpoint_sha256")
            or self._before[-1].frontier_generation
            != authority.get("owned_runtime_frontier_generation")
        ):
            raise RuntimeError("owner_canary_owned_runtime_atomic_guard_failed")

    def assert_active_case(self, case_id: str) -> None:
        """Refuse plaintext capture after any concurrent monitor failure."""

        start = self.start_attestation
        if start is None:
            raise RuntimeError("owner_canary_owned_runtime_not_active")
        self._verify_atomic_release(
            {
                "case_id": case_id,
                "owned_runtime_start_attestation_sha256": start.seal_sha256,
                "owned_runtime_instance_sha256": start.runtime_instance_sha256,
                "owned_runtime_memory_policy_sha256": start.memory_policy_sha256,
                "owned_runtime_before_checkpoint_sha256": (
                    self._before[-1].seal_sha256 if self._before else ""
                ),
                "owned_runtime_frontier_generation": (
                    self._before[-1].frontier_generation if self._before else -1
                ),
            }
        )

    @staticmethod
    def _port_open() -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.25)
            return probe.connect_ex((OWNER_CANARY_MODEL_HOST, OWNER_CANARY_MODEL_PORT)) == 0

    def _health(self) -> str | None:
        process = self.process
        if process is None or process.poll() is not None or self.nonce is None:
            return None
        try:
            with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
                response = client.get(
                    f"http://{OWNER_CANARY_MODEL_HOST}:{OWNER_CANARY_MODEL_PORT}/api/v1/health"
                )
            payload = response.json()
        except (httpx.HTTPError, TypeError, ValueError):
            return None
        if (
            response.status_code != 200
            or not isinstance(payload, Mapping)
            or payload.get("status") != "ok"
            or payload.get("backend") != "mlx_lm"
            or payload.get("model_id") != PINNED_RUNTIME_REPO
            or payload.get("model_loaded") is not True
            or payload.get("stub_mode") is not False
            or payload.get("memory_profile") != self.runtime_binding.get("model_runtime_profile")
        ):
            return None
        return attest_owned_listener(
            launched_pid=process.pid,
            port=OWNER_CANARY_MODEL_PORT,
            nonce=self.nonce,
        )

    def start(self) -> OwnerCanaryOwnedRuntimeStart:
        require_owner_canary_exclusive_model_transport_resolution()
        _validate_fixed_settings(self.settings)
        if self.process is not None or self._ended:
            raise RuntimeError("owner_canary_owned_runtime_already_started")
        if self._port_open():
            raise RuntimeError("owner_canary_model_port_preclaimed")
        if _clean_integration_sha(self.settings.project_root) != self.integration_sha:
            raise RuntimeError("owner_canary_owned_runtime_integration_mismatch")
        policy, source_sha = _policy_identity(self.memory_policy)
        trusted_model = load_trusted_model_identity(self.settings.project_root)
        _verify_model_artifact_manifest(_model_root(self.settings), trusted_model)
        toolchain = resolve_verified_model_toolchain(self.settings.project_root)
        toolchain_binding = toolchain.safe_binding()
        runtime_toolchain = self.runtime_binding.get("model_toolchain")
        if (
            self.runtime_binding.get("seal_sha256") is None
            or not isinstance(runtime_toolchain, Mapping)
            or toolchain_binding != runtime_toolchain
        ):
            raise RuntimeError("owner_canary_owned_runtime_binding_mismatch")
        nonce = os.urandom(32).hex()
        pycache = (
            self.safe_metrics_root
            / "owned-runtime-pycache"
            / hashlib.sha256(nonce.encode()).hexdigest()
        )
        profile = self.runtime_binding.get("model_runtime_profile")
        if not isinstance(profile, Mapping):
            raise RuntimeError("owner_canary_owned_runtime_profile_invalid")
        environment = sanitized_model_launch_environment(
            project_root=self.settings.project_root,
            private_pycache_root=pycache,
            launch_nonce=nonce,
            values={
                "LEGALBOT_MODEL_MODE": "mlx",
                "LEGALBOT_MODEL_HOST": OWNER_CANARY_MODEL_HOST,
                "LEGALBOT_MODEL_PORT": str(OWNER_CANARY_MODEL_PORT),
                "LEGALBOT_MODEL_ID": PINNED_RUNTIME_REPO,
                "LEGALBOT_MODEL_REVISION": PINNED_RUNTIME_REVISION,
                "LEGALBOT_MODEL_PATH": str(_model_root(self.settings)),
                "LEGALBOT_MODEL_CONTEXT_TOKENS": str(profile["context_window_tokens"]),
                "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS": str(profile["max_output_tokens"]),
                "LEGALBOT_MODEL_PREFILL_STEP_SIZE": str(profile["prefill_step_size"]),
                "LEGALBOT_MODEL_KV_BITS": str(profile["kv_cache_bits"]),
                "LEGALBOT_MODEL_KV_GROUP_SIZE": str(profile["kv_group_size"]),
                "LEGALBOT_MODEL_CLEAR_CACHE": (
                    "true" if profile["clear_cache_after_request"] else "false"
                ),
            },
        )
        launch_argv = (
            str(toolchain.python_executable),
            *isolated_model_python_arguments(
                self.settings.project_root,
                private_pycache_root=pycache,
            ),
        )
        process = subprocess.Popen(
            launch_argv,
            cwd=self.settings.project_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        # Install the intended session identity immediately so every
        # post-Popen failure path can kill the group and nonce lineage.
        self.process = process
        self.process_group_id = process.pid
        self.toolchain = toolchain
        self.nonce = nonce
        try:
            process_group_id = os.getpgid(process.pid)
            if process_group_id != process.pid:
                raise RuntimeError("owner_canary_owned_runtime_process_group_unverifiable")
            self.process_group_id = process_group_id
            startup = _MemoryMonitor(
                process=process,
                nonce=nonce,
                memory_policy=self.memory_policy,
                toolchain=toolchain,
                on_failure=self._record_failure,
                phase="startup",
                owned_process_group_id=process_group_id,
            )
            self.monitor = startup
            startup.start()
        except BaseException as exc:
            self._record_failure(exc)
            self.abort()
            raise
        listener: str | None = None
        deadline = time.monotonic() + self.startup_timeout_seconds
        try:
            while time.monotonic() < deadline:
                self._raise_if_failed()
                listener = self._health()
                if listener is not None:
                    break
                if process.poll() is not None:
                    raise RuntimeError("owner_canary_model_sidecar_start_failed")
                time.sleep(0.25)
            if listener is None:
                raise RuntimeError("owner_canary_model_sidecar_start_timeout")
            startup_memory = startup.payload()
            _assert_memory_payload(startup_memory, self.memory_policy)
            instance = sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-owned-runtime-instance.v1",
                    "run_id": self.run_id,
                    "candidate_build_id": self.candidate.build_id,
                    "runtime_binding_sha256": self.runtime_binding["seal_sha256"],
                    "launch_nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
                    "owned_listener_proof_sha256": listener,
                    "launched_pid": process.pid,
                }
            )
            material: dict[str, Any] = {
                "schema": OWNED_RUNTIME_START_SCHEMA,
                "run_id": self.run_id,
                "lane": self.lane,
                "authorization_seal_sha256": self.authorization_seal_sha256,
                "canary_manifest_seal_sha256": self.canary_manifest_seal_sha256,
                "workspace_seal_sha256": self.workspace_seal_sha256,
                "privacy_root_sha256": self.privacy_root_sha256,
                "candidate_build_id": self.candidate.build_id,
                "candidate_manifest_sha256": self.candidate.candidate_manifest_sha256,
                "integration_sha": self.integration_sha,
                "completion_preflight_result_sha256": (self.completion_preflight_result_sha256),
                "runtime_binding_sha256": self.runtime_binding["seal_sha256"],
                "memory_policy_sha256": policy.seal_sha256,
                "memory_policy_source_file_sha256": source_sha,
                "trusted_model_identity_sha256": trusted_model["seal_sha256"],
                "trusted_model_file_manifest_sha256": trusted_model["file_manifest_sha256"],
                "trusted_toolchain_identity_sha256": (
                    toolchain_binding["trusted_toolchain_identity_sha256"]
                ),
                "installed_environment_manifest_sha256": (
                    toolchain_binding["installed_environment_manifest_sha256"]
                ),
                "base_python_runtime_manifest_sha256": (
                    toolchain_binding["base_python_runtime_manifest_sha256"]
                ),
                "venv_control_manifest_sha256": (toolchain_binding["venv_control_manifest_sha256"]),
                "launcher_implementation_sha256": _file_sha256(Path(__file__)),
                "model_runtime_implementation_sha256": _file_sha256(
                    self.settings.project_root / "backend/app/model_runtime/adapters.py"
                ),
                "launch_argv_sha256": sealed_sha256(
                    {
                        "schema": "legalbot.owner-canary-owned-runtime-argv.v1",
                        "argv": list(launch_argv),
                    }
                ),
                "model_id": PINNED_RUNTIME_REPO,
                "model_revision": PINNED_RUNTIME_REVISION,
                "model_host": OWNER_CANARY_MODEL_HOST,
                "model_port": OWNER_CANARY_MODEL_PORT,
                "launched_pid": process.pid,
                "owned_process_group_id": process_group_id,
                "launch_nonce": nonce,
                "owned_listener_proof_sha256": listener,
                "runtime_instance_sha256": instance,
                "authorized_case_ids": list(self.authorized_case_ids),
                "startup_memory": startup_memory,
                "adapter_present": False,
                "proxy_environment_inherited": False,
                "local_only": True,
                "public_traffic_allowed": False,
                "writes_active": False,
                "writes_o04": False,
                "synthetic_non_authoritative": False,
            }
            material["seal_sha256"] = sealed_sha256(material)
            start = OwnerCanaryOwnedRuntimeStart.model_validate(material)
            write_create_only_private_safe_json(
                self.safe_metrics_root / OWNED_RUNTIME_START_FILENAME,
                start.model_dump(mode="json", by_alias=True),
            )
            self.start_attestation = start
            self.database.activate_owner_canary_runtime_session(
                run_id=self.run_id,
                authorization_sha256=self.authorization_seal_sha256,
                start_attestation_sha256=start.seal_sha256,
                runtime_instance_sha256=start.runtime_instance_sha256,
                candidate_build_id=self.candidate.build_id,
                memory_policy_sha256=start.memory_policy_sha256,
                controller_pid=os.getpid(),
            )
            self._activated = True
            self._heartbeat()
            # Continue the exact same sampler/thread from process spawn through
            # all 30 workflows; only the bound startup snapshot is frozen here.
            startup.on_sample = self._heartbeat
            with _ACTIVE_RUNTIME_LOCK:
                if self.run_id in _ACTIVE_RUNTIMES:
                    raise RuntimeError("owner_canary_owned_runtime_controller_conflict")
                _ACTIVE_RUNTIMES[self.run_id] = self
            return start
        except BaseException as exc:
            self._record_failure(exc)
            self.abort()
            raise

    def _checkpoint(
        self, *, case_id: str, phase: Literal["before_case", "after_case"]
    ) -> OwnerCanaryOwnedRuntimeCheckpoint:
        self._raise_if_failed()
        start = self.start_attestation
        monitor = self.monitor
        if start is None or monitor is None or self.process is None or self.nonce is None:
            raise RuntimeError("owner_canary_owned_runtime_not_active")
        if case_id not in self.authorized_case_ids:
            raise RuntimeError("owner_canary_owned_runtime_case_invalid")
        sequence = self.authorized_case_ids.index(case_id) + 1
        if phase == "before_case":
            if sequence != len(self._before) + 1 or self._pending_case is not None:
                raise RuntimeError("owner_canary_owned_runtime_case_order_invalid")
        elif self._pending_case != case_id or len(self._after) + 1 != sequence:
            raise RuntimeError("owner_canary_owned_runtime_case_order_invalid")
        listener = self._health()
        if listener is None:
            raise RuntimeError("owner_canary_owned_runtime_listener_changed")
        trusted_model = load_trusted_model_identity(self.settings.project_root)
        _verify_model_artifact_manifest(_model_root(self.settings), trusted_model)
        toolchain = resolve_verified_model_toolchain(self.settings.project_root)
        if self.toolchain is None or toolchain.safe_binding() != self.toolchain.safe_binding():
            raise RuntimeError("owner_canary_owned_runtime_toolchain_changed")
        if _clean_integration_sha(self.settings.project_root) != self.integration_sha:
            raise RuntimeError("owner_canary_owned_runtime_integration_changed")
        memory = monitor.payload()
        _assert_memory_payload(memory, self.memory_policy)
        session = self.database.owner_canary_runtime_session(self.run_id)
        if (
            session is None
            or session["status"] != "active"
            or int(session["next_sequence"]) != sequence
            or (phase == "before_case" and session["active_case_id"] is not None)
            or (phase == "after_case" and session["active_case_id"] != case_id)
        ):
            raise RuntimeError("owner_canary_runtime_frontier_conflict")
        frontier_generation = int(session["frontier_generation"]) + 1
        material: dict[str, Any] = {
            "schema": OWNED_RUNTIME_CHECKPOINT_SCHEMA,
            "run_id": self.run_id,
            "case_id": case_id,
            "sequence_number": sequence,
            "phase": phase,
            "start_attestation_sha256": start.seal_sha256,
            "runtime_instance_sha256": start.runtime_instance_sha256,
            "owned_listener_proof_sha256": listener,
            "memory_policy_sha256": start.memory_policy_sha256,
            "memory": memory,
            "model_artifact_rehashed": True,
            "toolchain_rehashed": True,
            "integration_reverified": True,
            "release_authority_active": True,
            "frontier_generation": frontier_generation,
        }
        material["seal_sha256"] = sealed_sha256(material)
        checkpoint = OwnerCanaryOwnedRuntimeCheckpoint.model_validate(material)
        suffix = "before" if phase == "before_case" else "after"
        write_create_only_private_safe_json(
            self.safe_metrics_root
            / OWNED_RUNTIME_CHECKPOINT_DIRNAME
            / f"{sequence:02d}-{case_id}-{suffix}.json",
            checkpoint.model_dump(mode="json", by_alias=True),
        )
        if phase == "before_case":
            observed_generation = self.database.advance_owner_canary_runtime_before_case(
                run_id=self.run_id,
                sequence_number=sequence,
                case_id=case_id,
                checkpoint_sha256=checkpoint.seal_sha256,
                start_attestation_sha256=start.seal_sha256,
                runtime_instance_sha256=start.runtime_instance_sha256,
            )
            self._before.append(checkpoint)
            self._pending_case = case_id
        else:
            before_checkpoint = self._before[-1]
            observed_generation = self.database.advance_owner_canary_runtime_after_case(
                run_id=self.run_id,
                sequence_number=sequence,
                case_id=case_id,
                before_checkpoint_sha256=before_checkpoint.seal_sha256,
                start_attestation_sha256=start.seal_sha256,
                runtime_instance_sha256=start.runtime_instance_sha256,
            )
            self._after.append(checkpoint)
            self._pending_case = None
        if observed_generation != frontier_generation:
            raise RuntimeError("owner_canary_runtime_frontier_conflict")
        return checkpoint

    def before_case(self, case_id: str) -> OwnerCanaryOwnedRuntimeCheckpoint:
        try:
            return self._checkpoint(case_id=case_id, phase="before_case")
        except BaseException as exc:
            self._record_failure(exc)
            raise

    def after_case(self, case_id: str) -> OwnerCanaryOwnedRuntimeCheckpoint:
        try:
            return self._checkpoint(case_id=case_id, phase="after_case")
        except BaseException as exc:
            self._record_failure(exc)
            raise

    def finish(self) -> VerifiedEndedOwnerCanaryRuntime:
        try:
            self._raise_if_failed()
            self._ending = True
            start = self.start_attestation
            monitor = self.monitor
            process = self.process
            if (
                start is None
                or monitor is None
                or process is None
                or self.nonce is None
                or self._pending_case is not None
                or tuple(item.case_id for item in self._before) != self.authorized_case_ids
                or tuple(item.case_id for item in self._after) != self.authorized_case_ids
            ):
                raise RuntimeError("owner_canary_owned_runtime_run_incomplete")
            listener = self._health()
            if listener is None:
                raise RuntimeError("owner_canary_owned_runtime_listener_changed")
            trusted_model = load_trusted_model_identity(self.settings.project_root)
            _verify_model_artifact_manifest(_model_root(self.settings), trusted_model)
            end_toolchain = resolve_verified_model_toolchain(self.settings.project_root)
            if (
                self.toolchain is None
                or end_toolchain.safe_binding() != self.toolchain.safe_binding()
            ):
                raise RuntimeError("owner_canary_owned_runtime_toolchain_changed")
            if _clean_integration_sha(self.settings.project_root) != self.integration_sha:
                raise RuntimeError("owner_canary_owned_runtime_integration_changed")
            self._raise_if_failed()
            listener = self._health()
            if listener is None:
                raise RuntimeError("owner_canary_owned_runtime_listener_changed")
            # Reserve a bounded completion lease while the already-verified
            # sidecar is stopped and the create-only end artifact is fsynced.
            # An expired generation cannot be renewed by the DB method.
            self._heartbeat(force=True, lease_seconds=90)
            if not monitor.sample_now():
                raise RuntimeError("owner_canary_owned_runtime_process_stopped_early")
            monitor.begin_owned_process_shutdown()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(monitor.owned_process_group_id, signal.SIGKILL)
                process.wait(timeout=15)
            monitor.kill_remaining_owned_lineage()
            monitor.stop()
            self._raise_if_failed()
            monitor.confirm_owned_process_stopped()
            if self._port_open():
                raise RuntimeError("owner_canary_owned_runtime_listener_not_stopped")
            memory = monitor.payload()
            _assert_memory_payload(memory, self.memory_policy)
            before = tuple(item.seal_sha256 for item in self._before)
            after = tuple(item.seal_sha256 for item in self._after)
            checkpoint_set = sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-owned-runtime-checkpoint-set.v1",
                    "case_ids": list(self.authorized_case_ids),
                    "before": list(before),
                    "after": list(after),
                }
            )
            material: dict[str, Any] = {
                "schema": OWNED_RUNTIME_END_SCHEMA,
                "run_id": self.run_id,
                "authorization_seal_sha256": self.authorization_seal_sha256,
                "canary_manifest_seal_sha256": self.canary_manifest_seal_sha256,
                "workspace_seal_sha256": self.workspace_seal_sha256,
                "candidate_build_id": self.candidate.build_id,
                "candidate_manifest_sha256": self.candidate.candidate_manifest_sha256,
                "integration_sha": self.integration_sha,
                "start_attestation_sha256": start.seal_sha256,
                "runtime_instance_sha256": start.runtime_instance_sha256,
                "memory_policy_sha256": start.memory_policy_sha256,
                "case_ids": list(self.authorized_case_ids),
                "before_checkpoint_seal_sha256s": list(before),
                "after_checkpoint_seal_sha256s": list(after),
                "checkpoint_set_sha256": checkpoint_set,
                "full_run_memory": memory,
                "final_owned_listener_proof_sha256": listener,
                "model_artifact_rehashed_after_run": True,
                "toolchain_rehashed_after_run": True,
                "integration_reverified_after_run": True,
                "owned_process_stopped": True,
                "memory_monitor_active_through_process_exit": True,
                "owned_process_group_and_nonce_lineage_absent_after_stop": True,
                "shutdown_controller_and_host_sampled": True,
                "successful_end": True,
                "synthetic_non_authoritative": False,
            }
            material["seal_sha256"] = sealed_sha256(material)
            end = OwnerCanaryOwnedRuntimeEnd.model_validate(material)
            write_create_only_private_safe_json(
                self.safe_metrics_root / OWNED_RUNTIME_END_FILENAME,
                end.model_dump(mode="json", by_alias=True),
            )
            self.database.complete_owner_canary_runtime_session(
                run_id=self.run_id,
                start_attestation_sha256=start.seal_sha256,
                runtime_instance_sha256=start.runtime_instance_sha256,
                end_attestation_sha256=end.seal_sha256,
            )
            with _ACTIVE_RUNTIME_LOCK:
                if _ACTIVE_RUNTIMES.get(self.run_id) is self:
                    _ACTIVE_RUNTIMES.pop(self.run_id, None)
            self._ended = True
            self.monitor = None
            return load_ended_owner_canary_runtime(
                settings=self.settings,
                workspace_root=self.workspace_root,
                candidate=self.candidate,
                authorization_seal_sha256=self.authorization_seal_sha256,
                canary_manifest_seal_sha256=self.canary_manifest_seal_sha256,
                workspace_seal_sha256=self.workspace_seal_sha256,
                runtime_binding=self.runtime_binding,
                memory_policy=self.memory_policy,
                completion_preflight_result_sha256=(self.completion_preflight_result_sha256),
                expected_case_ids=self.authorized_case_ids,
                database=self.database,
            )
        except BaseException as exc:
            self._record_failure(exc)
            self.abort()
            raise

    def abort(self) -> None:
        if self.start_attestation is not None and not self._ended and self._failure is None:
            self._record_failure(RuntimeError("owner_canary_serial_run_aborted"))
        elif not self._ended:
            with suppress(BaseException):
                self._stop_owned_process_lineage()
        self.monitor = None
