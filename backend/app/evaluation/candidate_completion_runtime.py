"""Private launcher for the candidate completion preflight.

This launcher deliberately does not construct FastAPI, a durable answer
worker, or any public listener.  It opens the existing catalogue, pins one
sealed candidate directly, starts only the loopback model sidecar, and runs an
``AnswerRunner`` whose release boundary is replaced by a no-op assertion.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from ..assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from ..crypto import LocalCipher
from ..db import Database
from ..model_runtime.config import (
    PINNED_RUNTIME_REPO,
    PINNED_RUNTIME_REVISION,
    SafeMemoryConfig,
)
from ..observability.live_metrics import load_slo_policy
from ..orchestration.classifier import CLASSIFIER_VERSION, classify_task
from ..orchestration.direct_controller import run_bounded_direct_answer
from ..orchestration.retry_policy import normalise_failure_reason_code
from ..orchestration.routing import ROUTER_VERSION, decide_route
from ..orchestration.runner import AnswerRunner
from ..quality.ai_evidence_reviewer import (
    AI_EVIDENCE_REVIEWER_ROLE,
    AIEvidenceAdjudication,
    AIEvidenceReviewResult,
    ai_evidence_reviewer_prompt_sha256,
    ai_evidence_reviewer_toolchain_sha256,
)
from ..quality.policy import POLICY_SHA256, POLICY_VERSION
from ..retrieval.budget import bind_retrieval_budget
from ..retrieval.models import RetrievalPlanItem
from ..retrieval.pinned_factory import PinnedRetrieverFactory
from ..runtime_adapters import PROMPT_VERSION, LoopbackModelGateway
from ..types import JobType, OnlineMode, QuestionRequest, ReleaseState, TaskType
from .candidate_completion_authority import (
    MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
    MEMORY_MEASUREMENT_METHOD,
    MEMORY_MEASUREMENT_SCHEMA,
    MEMORY_SAMPLE_INTERVAL_SECONDS,
    CompletionIsolation,
    CompletionMemoryPolicy,
    LoadedCompletionMemoryPolicy,
    VerifiedModelToolchain,
    WorkflowMemorySampler,
    attest_owned_listener,
    isolated_model_python_arguments,
    load_trusted_model_identity,
    resolve_verified_model_toolchain,
    sanitized_model_launch_environment,
    trusted_model_toolchain_binding,
    trusted_system_tool,
    write_create_only_private_safe_json,
)
from .candidate_completion_preflight import (
    CompletionWorkflowObservation,
    completion_runtime_binding,
)
from .live_suite import LiveQuestionCase, sealed_sha256
from .nonrelease_artifacts import sealed_safe_payload
from .quality_implementation_identity import quality_implementation_identities
from .sealed_candidate import SealedCandidateIdentity


def _file_sha256(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("runtime_identity_source_missing")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_model_artifact_manifest(model_root: Path, trusted_identity: Mapping[str, Any]) -> None:
    """Re-hash every pinned model file before a measured model instance starts."""

    provenance_path = model_root / "runtime-model.json"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("model_artifact_manifest_invalid") from exc
    if _file_sha256(provenance_path) != trusted_identity.get("runtime_model_sha256"):
        raise RuntimeError("model_artifact_manifest_invalid")
    if not isinstance(provenance, Mapping) or (
        provenance.get("source_repo") != PINNED_RUNTIME_REPO
        or provenance.get("revision") != PINNED_RUNTIME_REVISION
        or provenance.get("post_trained") is not True
        or provenance.get("quantization_bits") != 4
    ):
        raise RuntimeError("model_artifact_manifest_invalid")
    records = provenance.get("files")
    if not isinstance(records, list) or not records:
        raise RuntimeError("model_artifact_manifest_invalid")
    if sealed_sha256(
        {
            "schema": "legalbot.trusted-model-file-manifest.v1",
            "files": records,
        }
    ) != trusted_identity.get("file_manifest_sha256"):
        raise RuntimeError("model_artifact_manifest_invalid")
    expected_names: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise RuntimeError("model_artifact_manifest_invalid")
        name = str(record.get("path") or "")
        digest = str(record.get("sha256") or "")
        size = record.get("size")
        if (
            not re.fullmatch(r"[A-Za-z0-9._-]{1,127}", name)
            or name in {".", "..", "runtime-model.json"}
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 1
            or name in expected_names
        ):
            raise RuntimeError("model_artifact_manifest_invalid")
        path = model_root / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size:
            raise RuntimeError("model_artifact_identity_mismatch")
        if _stream_sha256(path) != digest:
            raise RuntimeError("model_artifact_identity_mismatch")
        expected_names.add(name)
    actual_names = {
        path.name
        for path in model_root.iterdir()
        if path.is_file() and path.name != "runtime-model.json"
    }
    if actual_names != expected_names:
        raise RuntimeError("model_artifact_identity_mismatch")


def _clean_integration_sha(project_root: Path, *, expected_sha: str | None = None) -> str:
    """Require the literal HEAD and every raw tracked byte to match exactly."""

    if expected_sha is None:
        git = str(trusted_system_tool("git", project_root=project_root))
        expected_sha = subprocess.run(
            [git, "--no-replace-objects", "rev-parse", "--verify", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1",
            },
        ).stdout.strip()
    from ..governance.v111_decision_generation import require_exact_clean_head

    return require_exact_clean_head(project_root, expected_sha)


def _runtime_failure_reason(exc: BaseException) -> str:
    if isinstance(exc, RuntimeError) and exc.args:
        explicit = str(exc.args[0]).strip().casefold().replace("-", "_")
        if re.fullmatch(r"[a-z0-9][a-z0-9._:-]{0,127}", explicit):
            return explicit
    return normalise_failure_reason_code(type(exc).__name__)


def _enforce_startup_memory_policy(
    policy: CompletionMemoryPolicy,
    *,
    sampled_peak_combined_working_set_bytes: int,
    minimum_sampled_host_available_memory_bytes: int,
    maximum_observed_sample_interval_seconds: float,
) -> None:
    """Stop after model load evidence and before constructing ``AnswerRunner``."""

    if sampled_peak_combined_working_set_bytes > int(policy.max_peak_combined_working_set_bytes):
        raise RuntimeError("memory_working_set_exceeds_owner_ceiling")
    if minimum_sampled_host_available_memory_bytes < int(
        policy.minimum_host_available_memory_bytes
    ):
        raise RuntimeError("memory_headroom_below_owner_minimum")
    if maximum_observed_sample_interval_seconds > MEMORY_MAX_SAMPLE_INTERVAL_SECONDS:
        raise RuntimeError("memory_sampling_interval_exceeded")


def build_local_completion_runtime_binding(
    *,
    settings: Settings,
    candidate: SealedCandidateIdentity,
    slo_policy_id: str,
    slo_policy_sha256: str,
    integration_sha: str,
) -> dict[str, Any]:
    """Derive the exact runtime identities from local tracked bytes."""

    implementations = quality_implementation_identities(project_root=settings.project_root)
    runtime_adapter = settings.project_root / "backend/app/runtime_adapters.py"
    model_runtime_adapter = settings.project_root / "backend/app/model_runtime/adapters.py"
    retry_implementation = settings.project_root / "backend/app/orchestration/retry_policy.py"
    trusted_model_identity = load_trusted_model_identity(settings.project_root)
    artifact_metadata_sha256 = sealed_sha256(
        {
            "schema": "legalbot.model-artifact-metadata-identity.v1",
            "runtime_model_sha256": trusted_model_identity["runtime_model_sha256"],
            "file_manifest_sha256": trusted_model_identity["file_manifest_sha256"],
            "trusted_identity_seal_sha256": trusted_model_identity["seal_sha256"],
        }
    )
    memory_profile = SafeMemoryConfig.from_env().to_dict()
    model_toolchain = trusted_model_toolchain_binding(settings.project_root)
    return completion_runtime_binding(
        candidate=candidate,
        model_id=settings.model_id,
        model_revision=PINNED_RUNTIME_REVISION,
        model_version=f"{settings.model_id}@{PINNED_RUNTIME_REVISION[:12]}",
        model_runtime_implementation_sha256=_file_sha256(model_runtime_adapter),
        launcher_implementation_sha256=_file_sha256(Path(__file__)),
        authority_implementation_sha256=_file_sha256(
            settings.project_root / "backend/app/evaluation/candidate_completion_authority.py"
        ),
        model_artifact_metadata_sha256=artifact_metadata_sha256,
        trusted_model_identity_sha256=str(trusted_model_identity["seal_sha256"]),
        model_toolchain=model_toolchain,
        model_runtime_profile=memory_profile,
        draft_prompt_version=PROMPT_VERSION,
        draft_prompt_implementation_sha256=_file_sha256(runtime_adapter),
        quality_policy_version=POLICY_VERSION,
        quality_policy_sha256=POLICY_SHA256,
        standards_bundle_version=OWNER_ASSESSMENT_BUNDLE.version,
        standards_bundle_sha256=OWNER_ASSESSMENT_BUNDLE.sha256,
        reviewer_role=AI_EVIDENCE_REVIEWER_ROLE,
        reviewer_prompt_sha256=ai_evidence_reviewer_prompt_sha256(),
        reviewer_policy_sha256=POLICY_SHA256,
        reviewer_toolchain_sha256=ai_evidence_reviewer_toolchain_sha256(),
        reviewer_implementation_sha256=implementations.ai_reviewer_sha256,
        retry_implementation_sha256=_file_sha256(retry_implementation),
        slo_policy_id=slo_policy_id,
        slo_policy_sha256=slo_policy_sha256,
        integration_sha=integration_sha,
    )


def validate_completion_launcher_settings(settings: Settings) -> tuple[str, int]:
    """Reject any configuration that could serve or research beyond loopback."""

    try:
        app_address = ipaddress.ip_address(settings.host)
    except ValueError as exc:
        raise RuntimeError("non_loopback_runtime") from exc
    parsed = urlparse(settings.model_url)
    try:
        model_address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise RuntimeError("non_loopback_runtime") from exc
    if (
        not app_address.is_loopback
        or not model_address.is_loopback
        or parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimeError("non_loopback_runtime")
    if settings.live_profile != FIRST_LIVE_LOCAL_ONLY_PROFILE:
        raise RuntimeError("first_live_local_only_profile_required")
    if settings.online_default != str(OnlineMode.LOCAL_ONLY) or settings.official_research_enabled:
        raise RuntimeError("online_research_enabled")
    if settings.test_mode:
        raise RuntimeError("substantive_model_required")
    if settings.model_id != PINNED_RUNTIME_REPO:
        raise RuntimeError("model_identity_mismatch")
    if os.environ.get("LEGALBOT_MODEL_ADAPTER_PATH", "").strip():
        raise RuntimeError("unapproved_model_adapter_configured")
    port = parsed.port or 80
    if not 1 <= port <= 65_535:
        raise RuntimeError("non_loopback_runtime")
    return str(model_address), port


class _CacheStateRetriever:
    """Pinned retriever whose legal-query cache policy is explicit per sample."""

    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.cache_bypass = True

    def active_build_id(self) -> str | None:
        value = self.delegate.active_build_id()
        return str(value) if value is not None else None

    async def retrieve_issue_spotting_notes(self, **kwargs: Any) -> Any:
        return await self.delegate.retrieve_issue_spotting_notes(**kwargs)

    async def retrieve(self, **kwargs: Any) -> Any:
        kwargs["cacheable"] = False if self.cache_bypass else bool(kwargs.get("cacheable", True))
        return await self.delegate.retrieve(**kwargs)

    async def retrieve_certified_plan(self, requests: Sequence[RetrievalPlanItem]) -> Any:
        if self.cache_bypass:
            requests = tuple(replace(item, cacheable=False) for item in requests)
        return await self.delegate.retrieve_certified_plan(requests)

    def close(self) -> None:
        close = getattr(self.delegate, "close", None)
        if callable(close):
            close()


class _FixedCandidateRetrieverFactory:
    """A single explicit candidate factory that never reads ``ACTIVE``."""

    def __init__(self, build_id: str, retriever: _CacheStateRetriever) -> None:
        self.build_id = build_id
        self.retriever = retriever

    def for_build(self, build_id: str) -> _CacheStateRetriever:
        if build_id != self.build_id:
            raise RuntimeError("candidate_identity_mismatch")
        return self.retriever


class _NonReleaseAnswerRunner(AnswerRunner):
    """Run every gate but suppress the sole database release boundary."""

    def __init__(
        self,
        *,
        completion_candidate_build_id: str,
        completion_runtime_binding_sha256: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._completion_candidate_build_id = completion_candidate_build_id
        self._completion_runtime_binding_sha256 = completion_runtime_binding_sha256
        self.suppressed_release_attempts: list[tuple[str, str]] = []

    def _require_normal_live_for_ordinary_job(
        self,
        row: Any,
        *,
        answer_id: str | None = None,
        owner_canary_publication_phase: Literal["pre_release", "released"] | None = None,
    ) -> str:
        if answer_id is not None or owner_canary_publication_phase is not None:
            raise RuntimeError("completion_nonrelease_publication_phase_forbidden")
        from .evaluation_job_authority import (
            verify_completion_nonrelease_job_authority,
        )

        return verify_completion_nonrelease_job_authority(
            row,
            expected_candidate_build_id=self._completion_candidate_build_id,
            expected_runtime_binding_sha256=self._completion_runtime_binding_sha256,
        )

    def _mark_released(
        self, answer_id: str, release: ReleaseState, *, job_id: str | None = None
    ) -> None:
        answer = self.database.answer(answer_id)
        if answer is None:
            raise KeyError(answer_id)
        release_job_id = job_id or str(answer["job_id"])
        row = self.database.job(release_job_id)
        if row is None or str(answer["job_id"]) != release_job_id:
            raise RuntimeError("completion_nonrelease_job_identity_mismatch")
        self._require_normal_live_for_ordinary_job(row)
        self.suppressed_release_attempts.append((answer_id, str(release)))


def _exact_verified_full_suppression(
    attempts: Sequence[tuple[str, str]], *, start: int, final_answer_id: str | None
) -> bool:
    """Require the only new release call to target this exact verified answer."""

    if start < 0 or start > len(attempts) or final_answer_id is None:
        return False
    return list(attempts[start:]) == [(final_answer_id, str(ReleaseState.VERIFIED_FULL))]


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _event_stage_timings(database: Database, job_id: str) -> dict[str, float]:
    rows = database.job_events(job_id)
    job = database.job(job_id)
    terminal = _parse_timestamp(job["updated_at"]) if job is not None else None
    timings: dict[str, float] = {
        "retrieval": 0.0,
        "drafting": 0.0,
        "verification": 0.0,
        "reviewer": 0.0,
        "repair": 0.0,
        "assembly": 0.0,
    }
    mapping = {
        "researching": "retrieval",
        "qualifying_evidence": "retrieval",
        "drafting": "drafting",
        "verifying": "verification",
        "repairing": "repair",
        "assembling": "assembly",
    }
    for index, row in enumerate(rows):
        started = _parse_timestamp(row["created_at"])
        ended = (
            _parse_timestamp(rows[index + 1]["created_at"]) if index + 1 < len(rows) else terminal
        )
        key = mapping.get(str(row["stage"]))
        if key and started is not None and ended is not None and ended >= started:
            timings[key] += (ended - started).total_seconds()
    return {key: round(value, 6) for key, value in timings.items()}


def _stage_metrics(database: Database, job_id: str) -> tuple[int, int, int, float | None, int]:
    input_tokens = output_tokens = 0
    ttft_ms: float | None = None
    model_allocator_peak_bytes = 0
    complete_count = 0
    for row in database.fetchall(
        """
        SELECT stage_key,metrics_json FROM job_stage_attempts
        WHERE job_id=? AND status='complete' ORDER BY started_at,id
        """,
        (job_id,),
    ):
        complete_count += 1
        try:
            metrics = json.loads(str(row["metrics_json"] or "{}"))
        except json.JSONDecodeError:
            continue
        if not isinstance(metrics, Mapping):
            continue
        input_tokens += int(metrics.get("input_tokens") or 0)
        output_tokens += int(metrics.get("output_tokens") or 0)
        observed_ttft = metrics.get("time_to_first_token_ms")
        if ttft_ms is None and isinstance(observed_ttft, int | float):
            ttft_ms = float(observed_ttft)
        peak_gb = metrics.get("peak_memory_gb")
        if isinstance(peak_gb, int | float) and float(peak_gb) >= 0:
            model_allocator_peak_bytes = max(
                model_allocator_peak_bytes, round(float(peak_gb) * 1024**3)
            )
    return input_tokens, output_tokens, complete_count, ttft_ms, model_allocator_peak_bytes


class LoopbackCandidateCompletionLauncher:
    """Own a fresh loopback model instance and a non-release pinned runner."""

    def __init__(
        self,
        *,
        settings: Settings,
        candidate: SealedCandidateIdentity,
        run_id: str,
        runtime_binding: Mapping[str, Any],
        memory_policy: LoadedCompletionMemoryPolicy,
        isolation_root: Path,
        model_start_timeout_seconds: float = 900,
    ) -> None:
        self.base_settings = settings
        self.settings: Any = settings
        self.candidate = candidate
        self.run_id = run_id
        self.runtime_binding = dict(runtime_binding)
        if type(memory_policy) is not LoadedCompletionMemoryPolicy:
            raise RuntimeError("completion_memory_policy_not_loader_verified")
        self.memory_policy = memory_policy
        self.isolation_root = isolation_root
        self.model_start_timeout_seconds = model_start_timeout_seconds
        self.database: Database | None = None
        self.cipher: LocalCipher | None = None
        self._isolation: CompletionIsolation | None = None
        self._launcher_start_attestation: dict[str, Any] | None = None
        self._launcher_end_attestation: dict[str, Any] | None = None
        self._trusted_model_identity: dict[str, Any] | None = None
        self._verified_toolchain: VerifiedModelToolchain | None = None
        self._sidecar: asyncio.subprocess.Process | None = None
        self._retriever: _CacheStateRetriever | None = None
        self._runner: _NonReleaseAnswerRunner | None = None
        self._model: LoopbackModelGateway | None = None
        self._instance_sha256: str | None = None
        self._cold_proof_sha256: str | None = None
        self._launch_nonce: str | None = None
        self._owned_listener_proof_sha256: str | None = None
        self._startup_memory_measurement: dict[str, Any] | None = None
        self._current_case_id: str | None = None
        self._model_host, self._model_port = validate_completion_launcher_settings(settings)

    async def __aenter__(self) -> LoopbackCandidateCompletionLauncher:
        if not self.base_settings.database_path.is_file():
            raise RuntimeError("catalogue_missing")
        if self.runtime_binding.get("candidate_build_id") != self.candidate.build_id:
            raise RuntimeError("runtime_binding_mismatch")
        integration_sha = _clean_integration_sha(
            self.base_settings.project_root,
            expected_sha=str(self.runtime_binding.get("integration_sha") or ""),
        )
        slo_policy = load_slo_policy(self.base_settings.observability_slo_path)
        slo_policy_sha256 = _file_sha256(self.base_settings.observability_slo_path)
        expected_binding = build_local_completion_runtime_binding(
            settings=self.base_settings,
            candidate=self.candidate,
            slo_policy_id=slo_policy.policy_id,
            slo_policy_sha256=slo_policy_sha256,
            integration_sha=integration_sha,
        )
        if expected_binding != self.runtime_binding:
            raise RuntimeError("runtime_binding_mismatch")
        self._verified_toolchain = resolve_verified_model_toolchain(self.base_settings.project_root)
        toolchain_binding = self._verified_toolchain.safe_binding()
        if toolchain_binding != self.runtime_binding.get("model_toolchain"):
            raise RuntimeError("runtime_binding_mismatch")
        self._trusted_model_identity = load_trusted_model_identity(self.base_settings.project_root)
        _verify_model_artifact_manifest(
            self.base_settings.project_root / "models/runtime/Qwen3.5-9B-4bit",
            self._trusted_model_identity,
        )
        self._isolation = CompletionIsolation.create(
            base_settings=self.base_settings,
            candidate=self.candidate,
            run_id=self.run_id,
            root=self.isolation_root,
            integration_sha=integration_sha,
        )
        self.settings = self._isolation.settings
        self.database = self._isolation.database
        self._launcher_start_attestation = self._isolation.start_attestation(
            runtime_binding_sha256=str(self.runtime_binding["seal_sha256"]),
            launcher_implementation_sha256=_file_sha256(Path(__file__)),
            trusted_model_identity_sha256=str(self._trusted_model_identity["seal_sha256"]),
            trusted_toolchain_identity_sha256=str(self._verified_toolchain.identity["seal_sha256"]),
            installed_environment_manifest_sha256=str(
                toolchain_binding["installed_environment_manifest_sha256"]
            ),
            base_python_runtime_manifest_sha256=str(
                toolchain_binding["base_python_runtime_manifest_sha256"]
            ),
            venv_control_manifest_sha256=str(toolchain_binding["venv_control_manifest_sha256"]),
        )
        self.cipher = LocalCipher.from_local_key(create=False)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        await self._stop_owned_sidecar()
        self._close_retriever()
        isolation = self._isolation
        if isolation is not None:
            try:
                if self._launcher_end_attestation is None:
                    await self.production_end_attestation()
            finally:
                isolation.close()
                self._isolation = None
                self.database = None

    def production_start_attestation(self) -> dict[str, Any]:
        if self._launcher_start_attestation is None or self._isolation is None:
            raise RuntimeError("production_launcher_not_entered")
        if self._launcher_end_attestation is not None:
            raise RuntimeError("production_launcher_already_finalized")
        return dict(self._launcher_start_attestation)

    async def production_end_attestation(self) -> dict[str, Any]:
        if self._launcher_end_attestation is not None:
            return dict(self._launcher_end_attestation)
        if self._isolation is None:
            raise RuntimeError("production_launcher_not_entered")
        await self._stop_owned_sidecar()
        self._close_retriever()
        if self._trusted_model_identity is None:
            raise RuntimeError("trusted_model_identity_invalid")
        if self._verified_toolchain is None:
            raise RuntimeError("trusted_model_toolchain_identity_invalid")
        _verify_model_artifact_manifest(
            self.base_settings.project_root / "models/runtime/Qwen3.5-9B-4bit",
            self._trusted_model_identity,
        )
        end_toolchain = resolve_verified_model_toolchain(self.base_settings.project_root)
        if end_toolchain.safe_binding() != self._verified_toolchain.safe_binding():
            raise RuntimeError("model_runtime_toolchain_changed_during_preflight")
        isolation_attestation = self._isolation.verify_end(
            current_integration_sha=_clean_integration_sha(
                self.base_settings.project_root,
                expected_sha=str(self.runtime_binding.get("integration_sha") or ""),
            ),
            runtime_binding_sha256=str(self.runtime_binding["seal_sha256"]),
        )
        self._launcher_end_attestation = sealed_safe_payload(
            {
                **isolation_attestation,
                "model_artifact_rehashed_after_run": True,
                "trusted_model_identity_sha256": self._trusted_model_identity["seal_sha256"],
                "trusted_toolchain_identity_sha256": end_toolchain.identity["seal_sha256"],
                "installed_environment_manifest_sha256": (
                    end_toolchain.installed_environment_manifest_sha256
                ),
                "base_python_runtime_manifest_sha256": (
                    end_toolchain.base_python_runtime_manifest_sha256
                ),
                "venv_control_manifest_sha256": (end_toolchain.venv_control_manifest_sha256),
                "model_toolchain_rehashed_after_run": True,
                "base_python_runtime_rehashed_after_run": True,
                "venv_control_rehashed_after_run": True,
            }
        )
        return dict(self._launcher_end_attestation)

    async def _health(self) -> bool:
        try:
            async with httpx.AsyncClient(
                timeout=5,
                trust_env=False,
                follow_redirects=False,
            ) as client:
                response = await client.get(
                    f"http://{self._model_host}:{self._model_port}/api/v1/health"
                )
            payload = response.json()
        except (httpx.HTTPError, TypeError, ValueError):
            return False
        valid = bool(
            response.status_code == 200
            and isinstance(payload, Mapping)
            and payload.get("status") == "ok"
            and payload.get("backend") == "mlx_lm"
            and payload.get("model_id") == self.settings.model_id
            and payload.get("model_loaded") is True
            and payload.get("stub_mode") is False
            and payload.get("memory_profile") == self.runtime_binding.get("model_runtime_profile")
        )
        if not valid:
            return False
        process = self._sidecar
        nonce = self._launch_nonce
        if process is None or nonce is None:
            raise RuntimeError("model_socket_owner_unverifiable")
        self._owned_listener_proof_sha256 = attest_owned_listener(
            launched_pid=process.pid,
            port=self._model_port,
            nonce=nonce,
        )
        return True

    async def _model_port_open(self) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._model_host, self._model_port), timeout=1
            )
        except (OSError, TimeoutError):
            return False
        del reader
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
        return True

    async def _stop_owned_sidecar(self) -> None:
        process = self._sidecar
        self._sidecar = None
        if process is None or process.returncode is not None:
            self._launch_nonce = None
            self._owned_listener_proof_sha256 = None
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=15)
        except TimeoutError:
            process.kill()
            await process.wait()
        self._launch_nonce = None
        self._owned_listener_proof_sha256 = None

    def _close_retriever(self) -> None:
        if self._retriever is not None:
            self._retriever.close()
        self._retriever = None
        self._runner = None
        self._model = None
        self._current_case_id = None

    async def _fresh_runtime_for_case(self, case_id: str) -> None:
        await self._stop_owned_sidecar()
        self._close_retriever()
        self._startup_memory_measurement = None
        if await self._model_port_open():
            # This launcher cannot prove or reset an unowned process on the
            # model port and therefore cannot call its state cold.
            raise RuntimeError("cold_model_restart_unavailable")

        launch_nonce = os.urandom(32).hex()
        self._launch_nonce = launch_nonce
        toolchain = resolve_verified_model_toolchain(self.settings.project_root)
        if (
            self._verified_toolchain is None
            or toolchain.safe_binding() != self._verified_toolchain.safe_binding()
        ):
            raise RuntimeError("model_runtime_toolchain_changed_during_preflight")
        profile = self.runtime_binding["model_runtime_profile"]
        private_pycache_root = (
            self.isolation_root / "pycache" / hashlib.sha256(launch_nonce.encode()).hexdigest()
        )
        environment = sanitized_model_launch_environment(
            project_root=self.settings.project_root,
            private_pycache_root=private_pycache_root,
            launch_nonce=launch_nonce,
            values={
                "LEGALBOT_MODEL_MODE": "mlx",
                "LEGALBOT_MODEL_HOST": self._model_host,
                "LEGALBOT_MODEL_PORT": str(self._model_port),
                "LEGALBOT_MODEL_ID": self.settings.model_id,
                "LEGALBOT_MODEL_REVISION": PINNED_RUNTIME_REVISION,
                "LEGALBOT_MODEL_PATH": str(
                    self.settings.project_root / "models/runtime/Qwen3.5-9B-4bit"
                ),
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
        process = await asyncio.create_subprocess_exec(
            str(toolchain.python_executable),
            *isolated_model_python_arguments(
                self.settings.project_root,
                private_pycache_root=private_pycache_root,
            ),
            cwd=self.settings.project_root,
            env=environment,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        self._sidecar = process
        startup_sampler = WorkflowMemorySampler(
            owned_sidecar_pid=process.pid,
            launch_nonce=launch_nonce,
            phase="startup",
            system_tools=toolchain.system_tools,
        )
        startup_failure: BaseException | None = None
        memory_task: asyncio.Task[None] | None = None
        started = time.monotonic()
        try:
            startup_sampler.sample()
            memory_task = asyncio.create_task(
                startup_sampler.run(), name=f"completion-startup-memory-{case_id}"
            )
            while not await self._health():
                if process.returncode is not None:
                    raise RuntimeError("model_sidecar_start_failed")
                if await self._model_port_open():
                    attest_owned_listener(
                        launched_pid=process.pid,
                        port=self._model_port,
                        nonce=launch_nonce,
                    )
                if time.monotonic() - started > self.model_start_timeout_seconds:
                    raise RuntimeError("model_sidecar_start_timeout")
                await asyncio.sleep(1)
        except Exception as exc:
            startup_failure = exc
        finally:
            startup_sampler.stop()
            if memory_task is not None:
                try:
                    await memory_task
                    if process.returncode is None:
                        startup_sampler.sample()
                except Exception as exc:
                    startup_failure = startup_failure or exc

        self._startup_memory_measurement = sealed_safe_payload(
            {
                "schema": MEMORY_MEASUREMENT_SCHEMA,
                "phase": "startup",
                "case_id": case_id,
                "candidate_build_id": self.candidate.build_id,
                "runtime_binding_sha256": self.runtime_binding["seal_sha256"],
                "launch_nonce_sha256": hashlib.sha256(launch_nonce.encode()).hexdigest(),
                "owned_listener_proof_sha256": self._owned_listener_proof_sha256,
                "method": MEMORY_MEASUREMENT_METHOD,
                "sampling_interval_seconds": MEMORY_SAMPLE_INTERVAL_SECONDS,
                "maximum_allowed_sample_interval_seconds": (MEMORY_MAX_SAMPLE_INTERVAL_SECONDS),
                "sample_count": startup_sampler.sample_count,
                "maximum_observed_sample_interval_seconds": round(
                    startup_sampler.maximum_observed_sample_interval_seconds, 6
                ),
                "maximum_sampling_jitter_seconds": round(
                    startup_sampler.maximum_sampling_jitter_seconds, 6
                ),
                "controller_sampled_peak_rss_bytes": (startup_sampler.controller_peak_rss_bytes),
                "owned_sidecar_tree_sampled_peak_rss_bytes": (
                    startup_sampler.sidecar_peak_rss_bytes
                ),
                "sampled_peak_combined_working_set_bytes": (
                    startup_sampler.peak_combined_working_set_bytes
                ),
                "minimum_sampled_host_available_memory_bytes": (
                    startup_sampler.minimum_host_available_memory_bytes or 0
                ),
            }
        )
        assert self._isolation is not None
        write_create_only_private_safe_json(
            self._isolation.root
            / "startup-memory"
            / f"{case_id}-{hashlib.sha256(launch_nonce.encode()).hexdigest()[:16]}.json",
            self._startup_memory_measurement,
        )
        if startup_failure is not None:
            raise startup_failure
        policy = self.memory_policy.policy
        try:
            _enforce_startup_memory_policy(
                policy,
                sampled_peak_combined_working_set_bytes=(
                    startup_sampler.peak_combined_working_set_bytes
                ),
                minimum_sampled_host_available_memory_bytes=(
                    startup_sampler.minimum_host_available_memory_bytes or 0
                ),
                maximum_observed_sample_interval_seconds=(
                    startup_sampler.maximum_observed_sample_interval_seconds
                ),
            )
        except RuntimeError:
            await self._stop_owned_sidecar()
            raise

        if self._owned_listener_proof_sha256 is None:
            raise RuntimeError("model_socket_owner_unverifiable")
        start_identity = {
            "schema": "legalbot.candidate-completion-fresh-model-instance.v1",
            "case_id": case_id,
            "model_id": self.settings.model_id,
            "model_revision": PINNED_RUNTIME_REVISION,
            "runtime_binding_sha256": self.runtime_binding["seal_sha256"],
            "start_nonce_sha256": hashlib.sha256(launch_nonce.encode()).hexdigest(),
            "owned_listener_proof_sha256": self._owned_listener_proof_sha256,
        }
        self._instance_sha256 = sealed_sha256(start_identity)
        self._cold_proof_sha256 = sealed_sha256(
            {
                **start_identity,
                "runtime_instance_sha256": self._instance_sha256,
                "health_model_identity_verified": True,
                "launcher_owned_process": True,
                "launcher_owned_listener": True,
                "retrieval_cache_bypassed_for_cold": True,
            }
        )
        assert self.database is not None and self.cipher is not None
        factory = PinnedRetrieverFactory(self.settings, self.database)
        pinned = factory.for_build(self.candidate.build_id)
        self._retriever = _CacheStateRetriever(pinned)
        fixed_factory = _FixedCandidateRetrieverFactory(self.candidate.build_id, self._retriever)
        self._model = LoopbackModelGateway(self.settings)
        self._runner = _NonReleaseAnswerRunner(
            completion_candidate_build_id=self.candidate.build_id,
            completion_runtime_binding_sha256=str(self.runtime_binding["seal_sha256"]),
            settings=self.settings,
            database=self.database,
            cipher=self.cipher,
            retriever=self._retriever,
            model=self._model,
            observability=None,
            retriever_factory=fixed_factory,
        )
        self._current_case_id = case_id

    async def run_workflow(
        self,
        *,
        case: LiveQuestionCase,
        band: Any,
        as_of_date: date,
        sample_kind: Literal["cold", "warm"],
        sample_ordinal: int,
        attempt_number: int,
        runtime_binding_sha256: str,
    ) -> CompletionWorkflowObservation:
        if runtime_binding_sha256 != self.runtime_binding.get("seal_sha256"):
            raise RuntimeError("runtime_binding_mismatch")
        if self._isolation is None:
            raise RuntimeError("production_launcher_not_entered")
        self._isolation.verify_isolated_candidate(full_tree=sample_kind == "cold")
        if sample_kind == "cold":
            # Every cold retry also receives a genuinely fresh owned process.
            await self._fresh_runtime_for_case(case.case_id)
        elif self._current_case_id != case.case_id or self._sidecar is None:
            raise RuntimeError("cold_model_restart_unavailable")
        assert (
            self.database is not None
            and self.cipher is not None
            and self._retriever is not None
            and self._runner is not None
            and self._sidecar is not None
            and self._instance_sha256 is not None
            and self._cold_proof_sha256 is not None
            and self._launch_nonce is not None
            and self._owned_listener_proof_sha256 is not None
            and self._startup_memory_measurement is not None
            and self._verified_toolchain is not None
        )
        if not await self._health():
            raise RuntimeError("model_socket_owner_unverifiable")
        self._retriever.cache_bypass = sample_kind == "cold"
        runner = self._runner
        release_attempt_start = len(runner.suppressed_release_attempts)
        job_id = f"completion-preflight-{uuid4().hex}"
        request = QuestionRequest(
            question=case.question,
            task_type=TaskType.AUTO,
            jurisdiction=case.jurisdiction,
            as_of_date=as_of_date,
            word_target=case.word_target,
            online_mode=OnlineMode.LOCAL_ONLY,
            upload_ids=[],
        )
        task_type = classify_task(case.question, request.task_type)
        route = decide_route(case.question, case.word_target, task_type)
        if route.route != case.expected_research_route or route.route != band.route:
            raise RuntimeError("route_identity_mismatch")
        admitted_at = datetime.now(UTC)
        workflow_deadline = admitted_at + timedelta(
            seconds=float(band.targets_p95_seconds["completion_seconds"])
        )
        request_sha256 = sealed_sha256(
            {
                "schema": "legalbot.candidate-completion-request.v1",
                "run_id": self.run_id,
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "sample_kind": sample_kind,
                "sample_ordinal": sample_ordinal,
                "attempt_number": attempt_number,
                "runtime_binding_sha256": runtime_binding_sha256,
            }
        )
        execution_run_id = f"completion-preflight-{request_sha256[:24]}"
        controller_worker_id = (
            f"candidate-completion-controller-{os.getpid()}-{request_sha256[:24]}"
        )
        controller_lease_seconds = (
            math.ceil(float(band.targets_p95_seconds["completion_seconds"])) + 120
        )
        if controller_lease_seconds > 12 * 60 * 60:
            raise RuntimeError("candidate_completion_controller_lease_exceeds_bound")
        from .evaluation_job_authority import build_completion_nonrelease_job_authority

        sampler = WorkflowMemorySampler(
            owned_sidecar_pid=self._sidecar.pid,
            launch_nonce=self._launch_nonce,
            owned_listener_proof_sha256=self._owned_listener_proof_sha256,
            system_tools=self._verified_toolchain.system_tools,
        )
        sampler.sample()
        authority = build_completion_nonrelease_job_authority(
            run_id=execution_run_id,
            case_id=case.case_id,
            request_sha256=request_sha256,
            candidate_build_id=self.candidate.build_id,
            runtime_binding_sha256=runtime_binding_sha256,
        )
        claimed_owner = self.database.create_job(
            job_id=job_id,
            encrypted_question=self.cipher.encrypt_text(case.question),
            question_summary="Private encrypted question",
            request=request.model_dump(mode="json", exclude={"question"}),
            route=route.route,
            route_reasons=route.reasons,
            idempotency_key=f"completion-preflight:{request_sha256}",
            pinned_index_build_id=self.candidate.build_id,
            job_type=JobType.ANSWER,
            queue_wait_deadline_at=workflow_deadline.isoformat(),
            workflow_deadline_at=workflow_deadline.isoformat(),
            model_call_deadline_at=None,
            evaluation_run_id=execution_run_id,
            evaluation_case_id=case.case_id,
            evaluation_request_sha256=request_sha256,
            evaluation_authority=authority,
            trace_full_retention=False,
            word_target=case.word_target,
            exact_controller_claim={
                "controller_pid": os.getpid(),
                "worker_id": controller_worker_id,
                "lease_seconds": controller_lease_seconds,
                "authority_sha256": authority["seal_sha256"],
            },
        )
        if claimed_owner != controller_worker_id:
            raise RuntimeError("candidate_completion_exact_controller_claim_refused")
        memory_task = asyncio.create_task(sampler.run(), name=f"completion-memory-{job_id}")
        started = time.perf_counter()
        failure: BaseException | None = None
        bind_retrieval_budget(deadline_at=workflow_deadline)
        try:
            await run_bounded_direct_answer(
                database=self.database,
                job_id=job_id,
                execute=lambda: runner.run(job_id, raise_on_error=True),
                expected_lease_owner=controller_worker_id,
            )
        except Exception as exc:
            failure = exc
        finally:
            bind_retrieval_budget(deadline_at=None)
            sampler.stop()
            try:
                await memory_task
                sampler.sample()
            except Exception as exc:
                failure = failure or exc
            try:
                if not await self._health():
                    raise RuntimeError("model_socket_owner_unverifiable")
                self._isolation.verify_isolated_candidate(full_tree=False)
            except Exception as exc:
                failure = exc
        completion_seconds = max(0.0, time.perf_counter() - started)
        try:
            return self._collect_observation(
                job_id=job_id,
                case=case,
                band=band,
                sample_kind=sample_kind,
                sample_ordinal=sample_ordinal,
                attempt_number=attempt_number,
                completion_seconds=completion_seconds,
                failure=failure,
                release_attempt_start=release_attempt_start,
                controller_peak_rss_bytes=sampler.controller_peak_rss_bytes,
                sidecar_peak_rss_bytes=sampler.sidecar_peak_rss_bytes,
                peak_combined_working_set_bytes=(sampler.peak_combined_working_set_bytes),
                minimum_host_available_memory_bytes=(
                    sampler.minimum_host_available_memory_bytes or 0
                ),
                memory_sample_count=sampler.sample_count,
                memory_max_observed_sample_interval_seconds=(
                    sampler.maximum_observed_sample_interval_seconds
                ),
                memory_max_sampling_jitter_seconds=(sampler.maximum_sampling_jitter_seconds),
            )
        finally:
            self._hold_nonrelease_job(job_id)

    def _collect_observation(
        self,
        *,
        job_id: str,
        case: LiveQuestionCase,
        band: Any,
        sample_kind: Literal["cold", "warm"],
        sample_ordinal: int,
        attempt_number: int,
        completion_seconds: float,
        failure: BaseException | None,
        release_attempt_start: int,
        controller_peak_rss_bytes: int,
        sidecar_peak_rss_bytes: int,
        peak_combined_working_set_bytes: int,
        minimum_host_available_memory_bytes: int,
        memory_sample_count: int,
        memory_max_observed_sample_interval_seconds: float,
        memory_max_sampling_jitter_seconds: float,
    ) -> CompletionWorkflowObservation:
        assert (
            self.database is not None
            and self._runner is not None
            and self._startup_memory_measurement is not None
        )
        job = self.database.job(job_id)
        answers = self.database.answer_versions(job_id)
        final = None
        if job is not None and job["answer_id"]:
            final = self.database.answer(str(job["answer_id"]))
        outbox = self.database.released_outbox_for_job(job_id)
        answer_release_state_present = any(row["release_state"] for row in answers)
        public_release_written = outbox is not None
        quality = (
            self.database.fetchone(
                """
                SELECT * FROM quality_reports WHERE answer_version_id=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (str(final["id"]),),
            )
            if final is not None
            else None
        )
        evidence_count = material_claim_count = 0
        if final is not None:
            evidence = self.database.fetchone(
                """
                SELECT COUNT(DISTINCT ce.evidence_id) AS evidence_count,
                       COUNT(DISTINCT CASE WHEN c.material=1 THEN c.id END)
                         AS material_claim_count
                FROM claims c LEFT JOIN claim_evidence ce ON ce.claim_id=c.id
                WHERE c.answer_version_id=?
                """,
                (str(final["id"]),),
            )
            if evidence is not None:
                evidence_count = int(evidence["evidence_count"] or 0)
                material_claim_count = int(evidence["material_claim_count"] or 0)

        stage_timings = _event_stage_timings(self.database, job_id)
        input_tokens, output_tokens, _, ttft_ms, model_allocator_peak_bytes = _stage_metrics(
            self.database, job_id
        )
        ai_review: AIEvidenceReviewResult | None = None
        ai_adjudication: AIEvidenceAdjudication | None = None
        standards_avoidance_passed = False
        hard_quality_gates_passed = False
        quality_release_state: str | None = None
        hard_finding = True
        identities_match = False
        if quality is not None:
            quality_release_state = str(quality["release_state"] or "") or None
            try:
                findings = json.loads(str(quality["findings_json"] or "[]"))
            except json.JSONDecodeError:
                findings = []
            hard_finding = any(
                isinstance(item, Mapping) and item.get("severity") == "hard_blocker"
                for item in findings
            )
            try:
                if quality["ai_evidence_review_json"]:
                    ai_review = AIEvidenceReviewResult.model_validate_json(
                        str(quality["ai_evidence_review_json"])
                    )
                if quality["ai_evidence_adjudication_json"]:
                    ai_adjudication = AIEvidenceAdjudication.model_validate_json(
                        str(quality["ai_evidence_adjudication_json"])
                    )
                if quality["assessment_standards_json"]:
                    from ..assessment.standards_scoring import AssessmentStandardsReport

                    standards = AssessmentStandardsReport.model_validate_json(
                        str(quality["assessment_standards_json"])
                    )
                    standards_avoidance_passed = (
                        standards.bundle_version == OWNER_ASSESSMENT_BUNDLE.version
                        and standards.bundle_sha256 == OWNER_ASSESSMENT_BUNDLE.sha256
                        and standards.avoidance_passed
                    )
            except (TypeError, ValueError):
                ai_review = None
                ai_adjudication = None
                standards_avoidance_passed = False

        reviewer_seconds = 0.0
        if ai_review is not None:
            reviewer_seconds = (
                sum(trace.duration_ms for trace in ai_review.invocation_traces) / 1000
            )
            input_tokens += sum(
                int(trace.input_token_count or 0) for trace in ai_review.invocation_traces
            )
            output_tokens += sum(
                int(trace.output_token_count or 0) for trace in ai_review.invocation_traces
            )
        stage_timings["reviewer"] = round(reviewer_seconds, 6)
        expected_model_version = str(self.runtime_binding["model_version"])
        identities_match = bool(
            job is not None
            and job["pinned_index_build_id"] == self.candidate.build_id
            and job["route"] == case.expected_research_route
            and job["worker_prompt_version"] == PROMPT_VERSION
            and job["worker_router_version"] == ROUTER_VERSION
            and job["worker_classifier_version"] == CLASSIFIER_VERSION
            and job["worker_policy_sha256"] == POLICY_SHA256
            and job["assessment_bundle_sha256"] == OWNER_ASSESSMENT_BUNDLE.sha256
            and final is not None
            and final["index_build_id"] == self.candidate.build_id
            and final["model_version"] == expected_model_version
            and ai_review is not None
            and ai_review.model_id == self.settings.model_id
            and ai_review.model_version == expected_model_version
            and ai_review.prompt_sha256 == ai_evidence_reviewer_prompt_sha256()
            and ai_review.policy_sha256 == POLICY_SHA256
            and ai_review.toolchain_sha256 == ai_evidence_reviewer_toolchain_sha256()
        )
        ai_passed = bool(
            ai_review is not None
            and ai_review.passed
            and ai_adjudication is not None
            and ai_adjudication.passed
        )
        release_attempted = _exact_verified_full_suppression(
            self._runner.suppressed_release_attempts,
            start=release_attempt_start,
            final_answer_id=str(final["id"]) if final is not None else None,
        )
        hard_quality_gates_passed = bool(
            quality is not None
            and bool(quality["evidence_passed"])
            and quality_release_state == "verified_full"
            and not hard_finding
            and ai_passed
            and standards_avoidance_passed
            and identities_match
            and release_attempted
        )
        word_tolerance_passed = bool(
            final is not None
            and round(case.word_target * 0.95)
            <= int(final["word_count"])
            <= round(case.word_target * 1.05)
        )
        reason_code: str | None = None
        if public_release_written:
            reason_code = "public_release_attempted"
        elif answer_release_state_present:
            reason_code = "answer_release_state_present"
        elif failure is not None:
            reason_code = _runtime_failure_reason(failure)
        elif (
            controller_peak_rss_bytes < 1
            or sidecar_peak_rss_bytes < 1
            or peak_combined_working_set_bytes < 1
            or minimum_host_available_memory_bytes < 1
            or memory_sample_count < 1
            or memory_max_observed_sample_interval_seconds > MEMORY_MAX_SAMPLE_INTERVAL_SECONDS
        ):
            reason_code = (
                "memory_sampling_interval_exceeded"
                if memory_max_observed_sample_interval_seconds > MEMORY_MAX_SAMPLE_INTERVAL_SECONDS
                else "memory_measurement_unavailable"
            )
        elif not identities_match:
            reason_code = "runtime_binding_mismatch"
        elif evidence_count < 1 or material_claim_count < 1:
            reason_code = "evidence_empty"
        elif not standards_avoidance_passed:
            reason_code = "standards_identity_mismatch"
        elif not ai_passed:
            reason_code = "reviewer_identity_mismatch"
        elif not word_tolerance_passed:
            reason_code = "word_tolerance_failed"
        elif not hard_quality_gates_passed:
            reason_code = "hard_quality_gate_failed"
        status: Literal["succeeded", "failed"] = "succeeded" if reason_code is None else "failed"
        return CompletionWorkflowObservation(
            case_id=case.case_id,
            question_sha256=case.question_sha256,
            sample_kind=sample_kind,
            sample_ordinal=sample_ordinal,
            attempt_number=attempt_number,
            route=case.expected_research_route,
            word_target=case.word_target,
            slo_band_id=band.id,
            runtime_binding_sha256=str(self.runtime_binding["seal_sha256"]),
            runtime_instance_sha256=self._instance_sha256,
            cold_launch_proof_sha256=self._cold_proof_sha256,
            candidate_build_id=self.candidate.build_id,
            model_version=expected_model_version,
            model_state=(
                "verified_fresh_instance" if sample_kind == "cold" else "warm_same_instance"
            ),
            retrieval_cache_state=(
                "bypassed" if sample_kind == "cold" else "enabled_state_unobserved"
            ),
            status=status,
            failure_reason_code=reason_code,
            completion_seconds=round(completion_seconds, 6),
            stage_timings_seconds=stage_timings,
            reviewer_phase_seconds=round(reviewer_seconds, 6),
            ttft_observed=ttft_ms is not None,
            time_to_first_token_seconds=(round(ttft_ms / 1000, 6) if ttft_ms is not None else None),
            controller_peak_rss_bytes=controller_peak_rss_bytes,
            sidecar_peak_rss_bytes=sidecar_peak_rss_bytes,
            model_allocator_peak_bytes=model_allocator_peak_bytes or None,
            peak_combined_working_set_bytes=peak_combined_working_set_bytes,
            minimum_host_available_memory_bytes=minimum_host_available_memory_bytes,
            memory_sample_count=memory_sample_count,
            memory_max_observed_sample_interval_seconds=round(
                memory_max_observed_sample_interval_seconds, 6
            ),
            memory_max_sampling_jitter_seconds=round(memory_max_sampling_jitter_seconds, 6),
            startup_controller_peak_rss_bytes=int(
                self._startup_memory_measurement["controller_sampled_peak_rss_bytes"]
            ),
            startup_sidecar_peak_rss_bytes=int(
                self._startup_memory_measurement["owned_sidecar_tree_sampled_peak_rss_bytes"]
            ),
            startup_peak_combined_working_set_bytes=int(
                self._startup_memory_measurement["sampled_peak_combined_working_set_bytes"]
            ),
            startup_minimum_host_available_memory_bytes=int(
                self._startup_memory_measurement["minimum_sampled_host_available_memory_bytes"]
            ),
            startup_memory_sample_count=int(self._startup_memory_measurement["sample_count"]),
            startup_memory_max_observed_sample_interval_seconds=float(
                self._startup_memory_measurement["maximum_observed_sample_interval_seconds"]
            ),
            startup_memory_max_sampling_jitter_seconds=float(
                self._startup_memory_measurement["maximum_sampling_jitter_seconds"]
            ),
            startup_memory_measurement_sha256=str(self._startup_memory_measurement["seal_sha256"]),
            input_token_count=input_tokens,
            output_token_count=output_tokens,
            total_token_count=input_tokens + output_tokens,
            evidence_span_count=evidence_count,
            material_claim_count=material_claim_count,
            quality_release_state=quality_release_state,
            hard_quality_gates_passed=hard_quality_gates_passed,
            ai_evidence_reviewer_passed=ai_passed,
            standards_avoidance_passed=standards_avoidance_passed,
            word_tolerance_passed=word_tolerance_passed,
            public_release_written=public_release_written,
            answer_release_state_present=answer_release_state_present,
            plaintext_prose_written=False,
            encrypted_prose_retained=bool(answers),
        )

    def _hold_nonrelease_job(self, job_id: str) -> None:
        assert self.database is not None
        if self.database.released_outbox_for_job(job_id) is not None:
            return
        job = self.database.job(job_id)
        if job is None or str(job["status"]) in {
            "system_error",
            "cancelled",
            "failed",
            "dlq",
        }:
            return
        if str(job["status"]) not in {"complete", "held_for_review"}:
            self.database.update_job(
                job_id,
                status="system_error",
                stage="system_error",
                progress=1,
                message="The non-release completion controller ended without a terminal result.",
                error_code="direct_controller_incomplete",
                checkpoint={
                    "schema": "legalbot.direct-answer-controller-stop.v1",
                    "reason_code": "direct_controller_incomplete",
                    "resumable": False,
                    "publication_allowed": False,
                },
            )
            self.database.execute(
                "UPDATE jobs SET terminal_reason_code=? WHERE id=?",
                ("direct_controller_incomplete", job_id),
            )
            return
        self.database.execute(
            """
            UPDATE jobs SET status='held_for_review', stage='held_for_review',
              answer_id=NULL, release_state=NULL,
              error_code='candidate_completion_preflight_nonrelease',
              user_message='Private non-release completion preflight retained encrypted output.',
              checkpoint_json=?, updated_at=? WHERE id=?
            """,
            (
                json.dumps(
                    {
                        "schema": "legalbot.candidate-completion-nonrelease-hold.v1",
                        "writes_release": False,
                    },
                    sort_keys=True,
                ),
                datetime.now(UTC).isoformat(),
                job_id,
            ),
        )
