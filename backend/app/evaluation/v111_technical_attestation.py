"""Typed, replayable technical evidence for the v1.11 promotion boundary.

The JSON written here is deliberately *not* an authority by itself.  A
successful run returns a process-local, unforgeable-by-data capability.  The
strict loader accepts only that capability, replays Stage A, re-hashes the
current integration/toolchains/lockfiles, and re-opens every create-only
artifact before issuing the capability consumed by promotion code.

This module never promotes or rolls back an index, starts a model, runs Stage
A, or writes ACTIVE/O-04.  The rollback member proves only that the existing
atomic implementation and its pre-promotion pointer preconditions are ready;
the post-promotion rollback drill remains a later operational gate.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from cryptography.fernet import Fernet

from ..config import Settings
from ..db import Database
from ..governance.owner_stop import (
    OwnerDecisionRequest,
    OwnerDecisionResolution,
    OwnerDecisionStore,
    require_owner_resolution,
    seal_owner_decision_request,
)
from ..retrieval.lancedb import ImmutableLanceRepository
from ..retrieval.retrieval_reattest import _clean_integration_sha
from ..retrieval.service import (
    _promote_candidate_index_locked,
    promote_candidate_index,
    rollback_active_index,
)
from .candidate_completion_authority import load_trusted_toolchain_identity
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_gold import LiveSuiteExpertQualification
from .live_suite_stage_a_v2_runner import (
    STAGE_A_RUNNER_POLICY_SHA256,
    STAGE_A_SCORER_IDENTITY_SHA256,
    load_verified_stage_a_v2_artifact_set,
)
from .nonrelease_artifacts import (
    CreateOnlyRunDirectory,
    sealed_safe_payload,
    verify_sealed_artifact,
)
from .owner_quality_canary import All60CaseQualification
from .sealed_candidate import SealedCandidateIdentity, load_sealed_candidate_identity
from .secure_artifact_io import read_private_file_at

TECHNICAL_RUN_SCHEMA = "legalbot.v111-technical-run.v1"
TECHNICAL_INTENT_SCHEMA = "legalbot.v111-technical-check-intent.v1"
TECHNICAL_OUTCOME_SCHEMA = "legalbot.v111-technical-check-outcome.v1"
TECHNICAL_STAGE_A_SCHEMA = "legalbot.v111-stage-a-scorer-reattestation.v1"
TECHNICAL_ROLLBACK_SCHEMA = "legalbot.v111-rollback-plan-readiness.v1"
TECHNICAL_FINAL_SCHEMA = "legalbot.v111-technical-attestation.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:+()/-]{0,127}$")
_RUN_TOKEN = object()
_VERIFIED_TOKEN = object()
_INTEGRATION_ROOT = Path(__file__).resolve().parents[3]

_TRUSTED_UV = Path("/Library/Frameworks/Python.framework/Versions/3.13/bin/uv")
_TRUSTED_NODE = Path("/usr/local/bin/node")
_TRUSTED_NPM_CLI = Path("/usr/local/lib/node_modules/npm/bin/npm-cli.js")
_TRUSTED_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
_NETWORK_DENY_PROFILE = "(version 1) (allow default) (deny network*)"


@dataclass(frozen=True, slots=True)
class StageAReplayInputs:
    """Authoritative inputs required to replay the exact passing Stage A set."""

    output_root: Path
    run_id: str
    bundle: LiveEvaluationBundle
    all60_qualification: All60CaseQualification
    expert_qualification: LiveSuiteExpertQualification
    as_of_date: date
    completion_preflight_verified_result_sha256: str


@dataclass(frozen=True, slots=True)
class _CheckSpec:
    ordinal: int
    check_id: str
    executor_id: str
    cwd_id: str
    arguments: tuple[str, ...]
    timeout_seconds: int

    def safe_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "check_id": self.check_id,
            "executor_id": self.executor_id,
            "cwd_id": self.cwd_id,
            "arguments": list(self.arguments),
            "timeout_seconds": self.timeout_seconds,
        }


# These are the complete accepted commands.  No public API accepts an argv,
# executable, cwd, shell fragment, environment, or check subset.
FIXED_CHECK_MATRIX: Final[tuple[_CheckSpec, ...]] = (
    _CheckSpec(
        1,
        "python_full_suite",
        "uv",
        "project",
        ("run", "--isolated", "--offline", "--frozen", "pytest"),
        10_800,
    ),
    _CheckSpec(
        2,
        "python_ruff",
        "uv",
        "project",
        ("run", "--isolated", "--offline", "--frozen", "ruff", "check", "backend", "scripts"),
        1_800,
    ),
    _CheckSpec(
        3,
        "python_ruff_format",
        "uv",
        "project",
        (
            "run",
            "--isolated",
            "--offline",
            "--frozen",
            "ruff",
            "format",
            "--check",
            "backend",
            "scripts",
        ),
        1_800,
    ),
    _CheckSpec(
        4,
        "python_static_baseline",
        "uv",
        "project",
        (
            "run",
            "--isolated",
            "--offline",
            "--frozen",
            "python",
            "scripts/ci/check_static_baseline.py",
        ),
        3_600,
    ),
    _CheckSpec(
        5,
        "workflow_security",
        "uv",
        "project",
        (
            "run",
            "--isolated",
            "--offline",
            "--frozen",
            "python",
            "scripts/security/check_workflow_policy.py",
        ),
        600,
    ),
    _CheckSpec(
        6,
        "clean_room",
        "uv",
        "project",
        ("run", "--isolated", "--offline", "--frozen", "python", "scripts/check_clean_room.py"),
        1_800,
    ),
    _CheckSpec(
        7,
        "live60_verify",
        "uv",
        "project",
        (
            "run",
            "--isolated",
            "--offline",
            "--frozen",
            "python",
            "scripts/live_evaluation_suite.py",
            "verify",
        ),
        1_800,
    ),
    _CheckSpec(
        8,
        "web_clean_install",
        "npm",
        "web",
        ("ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"),
        3_600,
    ),
    _CheckSpec(9, "web_lint", "npm", "web", ("run", "lint", "--offline"), 1_800),
    _CheckSpec(10, "web_test", "npm", "web", ("test", "--offline"), 3_600),
    _CheckSpec(11, "web_build", "npm", "web", ("run", "build", "--offline"), 1_800),
    _CheckSpec(
        12, "web_audit", "npm", "web", ("audit", "--offline", "--audit-level=high", "--json"), 1_800
    ),
    _CheckSpec(13, "repository_secret_scan", "internal_repository_secret_scan", "project", (), 600),
    _CheckSpec(14, "repository_diff_check", "git", "project", ("diff", "--check", "HEAD"), 600),
)

FIXED_CHECK_MATRIX_SHA256 = sealed_sha256(
    {
        "schema": "legalbot.v111-fixed-technical-check-matrix.v1",
        "checks": [item.safe_dict() for item in FIXED_CHECK_MATRIX],
        "shell": "never",
        "network": "sandbox_denied_and_offline_flags",
        "retry_count": 0,
    }
)

_LOCK_ARTIFACTS: Final[tuple[str, ...]] = (
    ".github/workflows/ci.yml",
    ".github/workflows/security.yml",
    "config/ci-static-baseline.json",
    "config/completion_preflight_toolchain_identity.json",
    "pyproject.toml",
    "scripts/check_clean_room.py",
    "scripts/ci/check_static_baseline.py",
    "scripts/live_evaluation_suite.py",
    "scripts/security/check_workflow_policy.py",
    "uv.lock",
    "web/package-lock.json",
    "web/package.json",
)

_SECRET_PATTERNS: Final[tuple[re.Pattern[bytes], ...]] = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(
        rb"(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\b"
        rb"\s*[:=]\s*['\"][^'\"\r\n]{12,}['\"]"
    ),
)


@dataclass(frozen=True, slots=True)
class _Toolchain:
    uv: Path
    node: Path
    npm_cli: Path
    sandbox_exec: Path
    git: Path
    binding: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _Context:
    integration_sha: str
    candidate_binding: Mapping[str, Any]
    stage_a_binding: Mapping[str, Any]
    toolchain: _Toolchain
    lock_binding: Mapping[str, Any]
    state_binding: Mapping[str, Any]
    rollback_binding: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _ExecutionObservation:
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_byte_count: int
    stderr_byte_count: int
    stdout_line_count: int
    stderr_line_count: int
    semantic_counts: Mapping[str, int]


class CompletedV111TechnicalRun:
    """Opaque handle proving outcomes came from this module's live executor."""

    __slots__ = ("_final", "_manifest", "_outcomes", "_run_id", "_run_root", "_token")

    def __init__(
        self,
        *,
        run_id: str,
        run_root: Path,
        manifest: Mapping[str, Any],
        outcomes: Sequence[Mapping[str, Any]],
        final: Mapping[str, Any],
        _token: object,
    ) -> None:
        if _token is not _RUN_TOKEN:
            raise TypeError("v111_technical_run_requires_live_runner")
        self._run_id = run_id
        self._run_root = run_root
        self._manifest = MappingProxyType(dict(manifest))
        self._outcomes = tuple(MappingProxyType(dict(item)) for item in outcomes)
        self._final = MappingProxyType(dict(final))
        self._token = _token

    @property
    def run_id(self) -> str:
        return self._run_id


class VerifiedV111TechnicalAttestation:
    """Opaque capability issued only after strict current-state replay."""

    __slots__ = ("_attestation", "_run_root", "_token")

    def __init__(self, *, run_root: Path, attestation: Mapping[str, Any], _token: object) -> None:
        if _token is not _VERIFIED_TOKEN:
            raise TypeError("v111_technical_attestation_requires_strict_loader")
        self._run_root = run_root
        self._attestation = MappingProxyType(dict(attestation))
        self._token = _token

    @property
    def run_directory(self) -> Path:
        return self._run_root

    @property
    def attestation(self) -> Mapping[str, Any]:
        return self._attestation

    @property
    def seal_sha256(self) -> str:
        return str(self._attestation["seal_sha256"])

    @property
    def run_id(self) -> str:
        return str(self._attestation["run_id"])

    @property
    def integration_sha(self) -> str:
        return str(self._attestation["integration_sha"])

    @property
    def candidate_build_id(self) -> str:
        return str(self._attestation["candidate_build_id"])


def require_verified_v111_technical_attestation(
    value: object,
) -> VerifiedV111TechnicalAttestation:
    """Reject parsed JSON, paths, subclasses, and caller-created lookalikes."""

    if type(value) is not VerifiedV111TechnicalAttestation or value._token is not _VERIFIED_TOKEN:
        raise TypeError("v111_technical_attestation_capability_not_loader_verified")
    return value


def _file_sha256(value: Path) -> str:
    if value.is_symlink() or not value.is_file():
        raise RuntimeError("technical_attestation_identity_file_missing_or_unsafe")
    digest = hashlib.sha256()
    with value.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _trusted_executable(
    value: Path, *, expected_sha256: str | None, root_owned: bool
) -> tuple[Path, str]:
    if value.is_symlink() or not value.is_file():
        raise RuntimeError("technical_attestation_tool_missing_or_unsafe")
    metadata = value.stat()
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("technical_attestation_tool_is_mutable")
    if root_owned and metadata.st_uid != 0:
        raise RuntimeError("technical_attestation_system_tool_not_root_owned")
    digest = _file_sha256(value)
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeError("technical_attestation_tool_identity_mismatch")
    return value, digest


def _run_version(argv: Sequence[str], *, environment: Mapping[str, str]) -> str:
    completed = subprocess.run(
        list(argv),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(environment),
        shell=False,
    )
    value = completed.stdout.strip()
    if (
        completed.returncode != 0
        or not value
        or "\n" in value
        or not _SAFE_VERSION.fullmatch(value)
    ):
        raise RuntimeError("technical_attestation_tool_version_invalid")
    return value


def _base_environment(*, scratch_root: Path, encryption_key: str | None = None) -> dict[str, str]:
    home = scratch_root / "home"
    temporary = scratch_root / "tmp"
    uv_cache = scratch_root / "uv-cache"
    npm_cache = scratch_root / "npm-cache"
    for directory in (home, temporary, uv_cache, npm_cache):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    environment = {
        "PATH": "/Library/Frameworks/Python.framework/Versions/3.13/bin:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "LANG": "C",
        "LC_ALL": "C",
        "CI": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "UV_CACHE_DIR": str(uv_cache),
        "UV_ISOLATED": "1",
        "UV_OFFLINE": "1",
        "UV_NO_PROGRESS": "1",
        "npm_config_cache": str(npm_cache),
        "npm_config_offline": "true",
        "npm_config_update_notifier": "false",
        "npm_config_fund": "false",
        "LEGALBOT_HOST": "127.0.0.1",
        "LEGALBOT_PORT": "8777",
        "LEGALBOT_MODEL_URL": "http://127.0.0.1:8778",
        "LEGALBOT_ONLINE_MODE": "local_only",
        "LEGALBOT_OFFICIAL_RESEARCH_ENABLED": "false",
        "LEGALBOT_XERJ_ENABLED": "false",
        "LEGALBOT_PHOENIX_ENABLED": "false",
        "LEGALBOT_TEST_MODE": "1",
    }
    if encryption_key is not None:
        environment["LEGALBOT_ENCRYPTION_KEY_B64"] = encryption_key
    return environment


def _resolve_toolchain(project_root: Path, *, scratch_root: Path) -> _Toolchain:
    _require_trusted_python_matrix_environment(project_root)
    trusted = load_trusted_toolchain_identity(project_root)
    uv, uv_digest = _trusted_executable(
        _TRUSTED_UV,
        expected_sha256=str(trusted["uv_executable_sha256"]),
        root_owned=False,
    )
    node, node_digest = _trusted_executable(_TRUSTED_NODE, expected_sha256=None, root_owned=True)
    npm_cli, npm_digest = _trusted_executable(
        _TRUSTED_NPM_CLI, expected_sha256=None, root_owned=True
    )
    sandbox_exec, sandbox_digest = _trusted_executable(
        _TRUSTED_SANDBOX_EXEC, expected_sha256=None, root_owned=True
    )
    git, git_digest = _trusted_executable(
        Path("/usr/bin/git"), expected_sha256=None, root_owned=True
    )
    version_environment = _base_environment(scratch_root=scratch_root)
    uv_version = _run_version((str(uv), "--version"), environment=version_environment)
    node_version = _run_version((str(node), "--version"), environment=version_environment)
    npm_version = _run_version(
        (str(node), str(npm_cli), "--version"), environment=version_environment
    )
    if uv_version != trusted.get("uv_version"):
        raise RuntimeError("technical_attestation_uv_version_mismatch")
    if not re.fullmatch(r"v24\.[0-9]+\.[0-9]+", node_version):
        raise RuntimeError("technical_attestation_requires_node_24")
    if not re.fullmatch(r"11\.[0-9]+\.[0-9]+", npm_version):
        raise RuntimeError("technical_attestation_requires_npm_11")
    binding = sealed_safe_payload(
        {
            "schema": "legalbot.v111-technical-toolchain.v1",
            "trusted_python_toolchain_sha256": trusted["seal_sha256"],
            "uv_sha256": uv_digest,
            "uv_version": uv_version,
            "node_sha256": node_digest,
            "node_version": node_version,
            "npm_cli_sha256": npm_digest,
            "npm_version": npm_version,
            "sandbox_exec_sha256": sandbox_digest,
            "git_sha256": git_digest,
            "network_policy_sha256": hashlib.sha256(_NETWORK_DENY_PROFILE.encode()).hexdigest(),
            "environment_policy": "authored_allowlist_no_ambient_values",
        }
    )
    return _Toolchain(uv, node, npm_cli, sandbox_exec, git, binding)


def _require_trusted_python_matrix_environment(project_root: Path) -> None:
    """Refuse the ignored mutable project virtualenv as technical evidence.

    A future implementation must create a fresh isolated environment from a
    tracked, hash-verified offline artifact store.  Hashing the current
    ignored ``.venv`` would let a pre-existing forged pytest/Ruff/mypy
    executable attest itself, so it is intentionally not accepted here.
    """

    if not (project_root / "uv.lock").is_file():
        raise RuntimeError("technical_attestation_python_lock_missing")
    raise RuntimeError(
        "TECHNICAL_IMPLEMENTATION_REQUIRED:trusted_offline_python_matrix_environment_missing"
    )


def _lock_binding(project_root: Path) -> dict[str, Any]:
    members: list[dict[str, str]] = []
    for artifact_id in _LOCK_ARTIFACTS:
        member = project_root / artifact_id
        if member.resolve() != member.absolute() or not member.resolve().is_relative_to(
            project_root.resolve()
        ):
            raise RuntimeError("technical_attestation_lock_member_is_unsafe")
        members.append({"artifact_id": artifact_id, "sha256": _file_sha256(member)})
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-technical-lock-set.v1",
            "members": members,
            "member_count": len(members),
        }
    )


def _pointer_binding(settings: Settings, pointer_id: str) -> dict[str, Any]:
    if pointer_id not in {"active", "previous"}:
        raise ValueError("technical pointer ID is invalid")
    member = settings.index_dir / ("ACTIVE.json" if pointer_id == "active" else "PREVIOUS.json")
    if member.is_symlink():
        raise RuntimeError("technical_attestation_pointer_is_symlink")
    if not member.exists():
        return {"pointer_id": pointer_id, "state": "missing"}
    try:
        raw = member.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("technical_attestation_pointer_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "build_id",
        "manifest_sha256",
        "promoted_at",
    }:
        raise RuntimeError("technical_attestation_pointer_schema_invalid")
    build_id = str(payload["build_id"])
    manifest_sha256 = str(payload["manifest_sha256"])
    promoted_at = str(payload["promoted_at"])
    if not _SAFE_ID.fullmatch(build_id) or not _SHA256.fullmatch(manifest_sha256):
        raise RuntimeError("technical_attestation_pointer_identity_invalid")
    try:
        parsed_time = datetime.fromisoformat(promoted_at)
    except ValueError as exc:
        raise RuntimeError("technical_attestation_pointer_timestamp_invalid") from exc
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise RuntimeError("technical_attestation_pointer_timestamp_invalid")
    manifest = settings.index_dir / "builds" / build_id / "manifest.json"
    if _file_sha256(manifest) != manifest_sha256:
        raise RuntimeError("technical_attestation_pointer_manifest_mismatch")
    return {
        "pointer_id": pointer_id,
        "state": "present",
        "build_id": build_id,
        "manifest_sha256": manifest_sha256,
        "pointer_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _catalogue_binding(
    *, settings: Settings, database: Database, candidate: SealedCandidateIdentity
) -> dict[str, Any]:
    reloaded = load_sealed_candidate_identity(
        settings=settings, database=database, candidate_build_id=candidate.build_id
    )
    if reloaded != candidate or candidate.status != "candidate":
        raise RuntimeError("technical_attestation_candidate_changed_or_not_candidate")
    rows = database.fetchall(
        """
        SELECT id,status,document_count,chunk_count,vector_count,embedding_model,
               reranker_model,manifest_sha256,corpus_id,scoped_corpus_id,
               source_manifest_hash,parser_version,chunker_version,index_schema_version,
               embedding_model_version,rerank_version,stage,candidate_manifest_hash,
               promotion_decision,policy_sha256,assessment_bundle_sha256
        FROM index_builds ORDER BY id
        """
    )
    normalized_rows = [dict(row) for row in rows]
    active_rows = [str(row["id"]) for row in normalized_rows if row["status"] == "active"]
    if len(active_rows) > 1:
        raise RuntimeError("technical_attestation_catalogue_has_multiple_active_builds")
    active_pointer = _pointer_binding(settings, "active")
    previous_pointer = _pointer_binding(settings, "previous")
    pointer_active = (
        str(active_pointer["build_id"]) if active_pointer["state"] == "present" else None
    )
    catalogue_active = active_rows[0] if active_rows else None
    if pointer_active != catalogue_active:
        raise RuntimeError("technical_attestation_active_pointer_catalogue_mismatch")
    previous_catalogue_status = "none"
    if previous_pointer["state"] == "present":
        previous_build_id = str(previous_pointer["build_id"])
        previous_matches = [
            str(row["status"]) for row in normalized_rows if str(row["id"]) == previous_build_id
        ]
        if len(previous_matches) != 1 or previous_matches[0] not in {
            "candidate",
            "superseded",
        }:
            raise RuntimeError("technical_attestation_previous_pointer_catalogue_mismatch")
        previous_catalogue_status = previous_matches[0]
    job_count_row = database.fetchone(
        "SELECT COUNT(*) AS count FROM jobs WHERE status IN ('queued','running')"
    )
    scan_count_row = database.fetchone(
        "SELECT COUNT(*) AS count FROM source_scans WHERE status IN ('queued','running')"
    )
    if job_count_row is None or scan_count_row is None:
        raise RuntimeError("technical_attestation_catalogue_count_unavailable")
    queued_job_count = int(job_count_row["count"])
    queued_scan_count = int(scan_count_row["count"])
    if queued_job_count or queued_scan_count:
        raise RuntimeError("technical_attestation_catalogue_is_not_quiescent")
    catalogue_sha256 = sealed_sha256(
        {
            "schema": "legalbot.v111-index-catalogue-snapshot.v1",
            "rows": normalized_rows,
        }
    )
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-candidate-active-catalogue-state.v1",
            "candidate": candidate.safe_dict(),
            "active_pointer": active_pointer,
            "previous_pointer": previous_pointer,
            "catalogue_row_count": len(normalized_rows),
            "catalogue_sha256": catalogue_sha256,
            "catalogue_active_build_id": catalogue_active or "none",
            "previous_catalogue_status": previous_catalogue_status,
            "queued_job_count": queued_job_count,
            "queued_source_scan_count": queued_scan_count,
        }
    )


def _stage_a_binding(
    *, candidate: SealedCandidateIdentity, stage_a: StageAReplayInputs, integration_sha: str
) -> dict[str, Any]:
    if (
        not _SAFE_ID.fullmatch(stage_a.run_id)
        or not _SHA256.fullmatch(stage_a.completion_preflight_verified_result_sha256)
        or stage_a.completion_preflight_verified_result_sha256 == "0" * 64
    ):
        raise ValueError("technical_attestation_stage_a_input_invalid")
    result = load_verified_stage_a_v2_artifact_set(
        output_root=stage_a.output_root,
        run_id=stage_a.run_id,
        bundle=stage_a.bundle,
        candidate=candidate,
        all60_qualification=stage_a.all60_qualification,
        expert_qualification=stage_a.expert_qualification,
        as_of_date=stage_a.as_of_date,
        code_revision=integration_sha,
        completion_preflight_verified_result_sha256=(
            stage_a.completion_preflight_verified_result_sha256
        ),
    )
    expected = {
        "run_id": stage_a.run_id,
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "suite_manifest_seal_sha256": stage_a.bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": stage_a.bundle.registry.canonical_sha256,
        "run_plan_sha256": stage_a.bundle.manifest.run_plan_sha256,
        "all60_qualification_seal_sha256": stage_a.all60_qualification.seal_sha256,
        "expert_qualification_seal_sha256": stage_a.expert_qualification.seal_sha256,
        "completion_preflight_verified_result_sha256": (
            stage_a.completion_preflight_verified_result_sha256
        ),
        "completion_preflight_authoritative": True,
        "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
        "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
        "code_revision": integration_sha,
        "completed_checkpoint_count": 585,
        "issue_count": 585,
        "timeout_count": 0,
        "worker_failure_count": 0,
        "hard_failure_count": 0,
        "run_status": "passed",
        "stage_a_passed": True,
        "authorization_eligible": True,
    }
    if any(result.get(key) != value for key, value in expected.items()):
        raise RuntimeError("technical_attestation_stage_a_replay_mismatch")
    return sealed_safe_payload(
        {
            "schema": TECHNICAL_STAGE_A_SCHEMA,
            "run_id": stage_a.run_id,
            "result_seal_sha256": result["seal_sha256"],
            "checkpoint_set_sha256": result["checkpoint_set_sha256"],
            "issue_identity_set_sha256": result["issue_identity_set_sha256"],
            "scorer_identity_sha256": STAGE_A_SCORER_IDENTITY_SHA256,
            "runner_policy_sha256": STAGE_A_RUNNER_POLICY_SHA256,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "suite_manifest_seal_sha256": stage_a.bundle.manifest.seal_sha256,
            "suite_registry_canonical_sha256": stage_a.bundle.registry.canonical_sha256,
            "all60_qualification_seal_sha256": stage_a.all60_qualification.seal_sha256,
            "completion_preflight_verified_result_sha256": (
                stage_a.completion_preflight_verified_result_sha256
            ),
            "integration_sha": integration_sha,
            "derived_status": "strict_replay_passed",
        }
    )


def _implementation_hash(value: Callable[..., Any]) -> str:
    return hashlib.sha256(inspect.getsource(value).encode("utf-8")).hexdigest()


def _rollback_implementation_binding() -> dict[str, str]:
    """Return the current exact implementation identities used by rollback proof."""

    return {
        "promote_candidate_index_sha256": _implementation_hash(promote_candidate_index),
        "promote_locked_sha256": _implementation_hash(_promote_candidate_index_locked),
        "rollback_active_index_sha256": _implementation_hash(rollback_active_index),
        "repository_promote_sha256": _implementation_hash(ImmutableLanceRepository.promote),
        "repository_rollback_sha256": _implementation_hash(ImmutableLanceRepository.rollback_build),
        "atomic_replace_sha256": _implementation_hash(ImmutableLanceRepository._atomic_replace),
    }


def _rollback_decision_state_binding(
    *, settings: Settings, database: Database, candidate: SealedCandidateIdentity
) -> dict[str, Any]:
    reloaded = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=candidate.build_id,
    )
    if reloaded != candidate or candidate.status != "candidate":
        raise RuntimeError("first_live_rollback_candidate_identity_invalid")
    active = _pointer_binding(settings, "active")
    previous = _pointer_binding(settings, "previous")
    active_rows = database.fetchall("SELECT id FROM index_builds WHERE status='active' ORDER BY id")
    catalogue_active_ids = [str(row["id"]) for row in active_rows]
    if len(catalogue_active_ids) > 1:
        raise RuntimeError("first_live_rollback_catalogue_has_multiple_active_builds")
    pointer_active = str(active.get("build_id") or "") if active["state"] == "present" else None
    catalogue_active = catalogue_active_ids[0] if catalogue_active_ids else None
    if pointer_active != catalogue_active:
        raise RuntimeError("first_live_rollback_active_pointer_catalogue_mismatch")
    prior_rows = database.fetchall(
        """
        SELECT id,status,manifest_sha256 FROM index_builds
        WHERE id<>? AND status IN ('candidate','superseded') ORDER BY id
        """,
        (candidate.build_id,),
    )
    prior_material = [
        {
            "build_id": str(row["id"]),
            "status": str(row["status"]),
            "manifest_sha256": str(row["manifest_sha256"] or ""),
        }
        for row in prior_rows
    ]
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-first-live-rollback-decision-state.v1",
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "active_pointer": active,
            "previous_pointer": previous,
            "catalogue_active_build_id": catalogue_active or "none",
            "prior_catalogue_build_count": len(prior_material),
            "prior_catalogue_build_set_sha256": sealed_sha256(
                {
                    "schema": "legalbot.v111-prior-rollback-catalogue-set.v1",
                    "members": prior_material,
                }
            ),
        }
    )


def _first_live_rollback_policy_sha256() -> str:
    implementation = {
        "promote_locked_sha256": _implementation_hash(_promote_candidate_index_locked),
        "rollback_active_index_sha256": _implementation_hash(rollback_active_index),
        "repository_promote_sha256": _implementation_hash(ImmutableLanceRepository.promote),
        "repository_rollback_sha256": _implementation_hash(ImmutableLanceRepository.rollback_build),
        "atomic_replace_sha256": _implementation_hash(ImmutableLanceRepository._atomic_replace),
    }
    return sealed_sha256(
        {
            "schema": "legalbot.v111-first-live-rollback-strategy-policy.v1",
            "strategies": [
                "restore-verified-no-active-state",
                "select-explicit-prior-rollback-candidate",
                "defer-and-keep-closed",
            ],
            "implementation": implementation,
            "matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
        }
    )


def _first_live_rollback_decision_id(
    *,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
    state_binding: Mapping[str, Any],
) -> str:
    policy_sha256 = _first_live_rollback_policy_sha256()
    identity = sealed_sha256(
        {
            "schema": "legalbot.v111-first-live-rollback-decision-identity.v1",
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "state_seal_sha256": state_binding["seal_sha256"],
            "policy_sha256": policy_sha256,
            "integration_sha": integration_sha,
        }
    )
    return f"v111-first-live-rollback-{identity[:20]}"


def build_first_live_rollback_decision_request(
    *,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
    state_binding: Mapping[str, Any],
    created_at: datetime,
) -> OwnerDecisionRequest:
    """Build the exact owner stop for first promotion with no rollback target."""

    if (
        candidate.status != "candidate"
        or not _GIT_SHA.fullmatch(integration_sha)
        or created_at.tzinfo is None
        or created_at.utcoffset() is None
        or state_binding.get("schema") != "legalbot.v111-first-live-rollback-decision-state.v1"
        or state_binding.get("candidate_build_id") != candidate.build_id
        or state_binding.get("candidate_manifest_sha256") != candidate.candidate_manifest_sha256
        or state_binding.get("seal_sha256") != sealed_sha256(state_binding)
    ):
        raise ValueError("first-live rollback decision binding is invalid")
    active = state_binding.get("active_pointer")
    previous = state_binding.get("previous_pointer")
    if (
        not isinstance(active, Mapping)
        or active.get("state") != "missing"
        or not isinstance(previous, Mapping)
        or previous.get("state") != "missing"
    ):
        raise ValueError("first-live no-ACTIVE rollback decision is not applicable")
    policy_sha256 = _first_live_rollback_policy_sha256()
    decision_id = _first_live_rollback_decision_id(
        candidate=candidate,
        integration_sha=integration_sha,
        state_binding=state_binding,
    )
    suffix = decision_id.rsplit("-", 1)[-1]
    return seal_owner_decision_request(
        decision_id=decision_id,
        category="promotion",
        scope_id=f"first-live-rollback:{suffix}",
        reason_codes=(
            "FIRST_LIVE_ROLLBACK_TARGET_POLICY_REQUIRED",
            "ACTIVE_POINTER_CURRENTLY_ABSENT",
            "PREVIOUS_POINTER_NOT_YET_CREATED_BY_PROMOTION",
            "NO_ROLLBACK_BEHAVIOUR_MAY_BE_INFERRED",
        ),
        evidence=(
            {
                "evidence_id": "candidate-manifest",
                "kind": "candidate_manifest",
                "sha256": candidate.candidate_manifest_sha256,
                "summary_code": "EXACT_FIRST_PROMOTION_CANDIDATE",
            },
            {
                "evidence_id": "pointer-catalogue-state",
                "kind": "pointer_catalogue_state",
                "sha256": str(state_binding["seal_sha256"]),
                "summary_code": "ACTIVE_AND_PREVIOUS_STATE_REPLAYED",
            },
            {
                "evidence_id": "rollback-strategy-policy",
                "kind": "rollback_strategy_policy",
                "sha256": policy_sha256,
                "summary_code": "BOUNDED_FIRST_PROMOTION_STRATEGIES",
            },
            {
                "evidence_id": "integration-commit",
                "kind": "integration_commit",
                "sha256": hashlib.sha256(integration_sha.encode("ascii")).hexdigest(),
                "summary_code": "EXACT_TECHNICAL_GATE_COMMIT",
            },
        ),
        options=(
            {
                "option_id": "restore-verified-no-active-state",
                "outcome_code": "RESTORE_VERIFIED_NO_ACTIVE_STATE_ATOMICALLY",
                "recommended": True,
                "consequence_codes": (
                    "REQUIRE_TYPED_ATOMIC_NO_ACTIVE_RECOVERY",
                    "RESTORE_PRE_PROMOTION_CATALOGUE_STATUSES",
                    "REVOKE_NORMAL_LIVE_AUTHORITY",
                    "PRESERVE_ALL_SEALED_BUILDS",
                    "REQUIRE_POST_PROMOTION_DRILL",
                ),
            },
            {
                "option_id": "select-explicit-prior-rollback-candidate",
                "outcome_code": "OWNER_SELECTS_EXPLICIT_PRIOR_ROLLBACK_TARGET",
                "recommended": False,
                "consequence_codes": (
                    "REQUIRE_SEPARATELY_VERIFIED_PRIOR_BUILD",
                    "NO_PRIOR_TARGET_CURRENTLY_APPROVED",
                ),
            },
            {
                "option_id": "defer-and-keep-closed",
                "outcome_code": "KEEP_FIRST_PROMOTION_CLOSED",
                "recommended": False,
                "consequence_codes": ("NO_ACTIVE_PROMOTION",),
            },
        ),
        blocked_actions=(
            "v111_technical_attestation",
            "active_promotion",
            "rollback_readiness_claim",
            "o04_authorization",
            "normal_live",
        ),
        created_at=created_at,
    )


def write_first_live_rollback_decision_request(
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
    created_at: datetime | None = None,
) -> tuple[OwnerDecisionRequest, Path]:
    """Create the request once; never create a resolution or change a pointer."""

    state = _rollback_decision_state_binding(
        settings=settings,
        database=database,
        candidate=candidate,
    )
    request = build_first_live_rollback_decision_request(
        candidate=candidate,
        integration_sha=integration_sha,
        state_binding=state,
        created_at=created_at or datetime.now(UTC),
    )
    from ..governance.v111_decision_generation import require_exact_clean_head

    if (
        _rollback_decision_state_binding(
            settings=settings,
            database=database,
            candidate=candidate,
        )
        != state
    ):
        raise RuntimeError("first_live_rollback_state_changed_before_request_write")
    require_exact_clean_head(settings.project_root, integration_sha)
    destination = OwnerDecisionStore(settings.owner_decision_root).write_request(request)
    return request, destination


def _require_trusted_first_live_rollback_strategy(
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    integration_sha: str,
) -> None:
    """Replay the bounded decision but reject self-sealed owner authority."""

    state = _rollback_decision_state_binding(
        settings=settings,
        database=database,
        candidate=candidate,
    )
    decision_id = _first_live_rollback_decision_id(
        candidate=candidate,
        integration_sha=integration_sha,
        state_binding=state,
    )
    parts = ("data", "evaluations", "owner-decisions", decision_id)
    try:
        request = OwnerDecisionRequest.model_validate_json(
            read_private_file_at(settings.project_root, (*parts, "request.json"))
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise RuntimeError(
            "OWNER_DECISION_REQUIRED:first_live_rollback_target_policy_unresolved"
        ) from exc
    expected_request = build_first_live_rollback_decision_request(
        candidate=candidate,
        integration_sha=integration_sha,
        state_binding=state,
        created_at=request.created_at,
    )
    if request != expected_request:
        raise RuntimeError("OWNER_DECISION_REQUIRED:first_live_rollback_request_binding_invalid")
    try:
        resolution = OwnerDecisionResolution.model_validate_json(
            read_private_file_at(settings.project_root, (*parts, "resolution.json"))
        )
        verified = require_owner_resolution(request, resolution)
    except (FileNotFoundError, OSError, ValueError, PermissionError) as exc:
        raise RuntimeError(
            "OWNER_DECISION_REQUIRED:first_live_rollback_target_policy_unresolved"
        ) from exc
    if verified.selected_option_id == "defer-and-keep-closed":
        raise RuntimeError("OWNER_DECISION_REQUIRED:first_live_rollback_deferred")
    if (
        verified.selected_option_id == "select-explicit-prior-rollback-candidate"
        and state.get("prior_catalogue_build_count") == 0
    ):
        raise RuntimeError("OWNER_DECISION_REQUIRED:prior_rollback_target_unavailable")
    # Generic self-seals do not prove that the owner made this selection.  The
    # shared trusted-signature policy must be implemented before either
    # substantive strategy can authorize technical evidence.
    raise RuntimeError("OWNER_DECISION_REQUIRED:trusted_owner_decision_signature_verifier_missing")


def _rollback_binding(
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    state_binding: Mapping[str, Any],
    integration_sha: str,
) -> dict[str, Any]:
    active = state_binding.get("active_pointer")
    previous = state_binding.get("previous_pointer")
    if not isinstance(active, Mapping) or active.get("state") != "present":
        _require_trusted_first_live_rollback_strategy(
            settings=settings,
            database=database,
            candidate=candidate,
            integration_sha=integration_sha,
        )
        raise AssertionError("trusted first-live rollback strategy returned unexpectedly")
    active_build_id = str(active.get("build_id") or "")
    active_manifest = str(active.get("manifest_sha256") or "")
    if (
        active_build_id == candidate.build_id
        or not _SAFE_ID.fullmatch(active_build_id)
        or not _SHA256.fullmatch(active_manifest)
        or state_binding.get("catalogue_active_build_id") != active_build_id
    ):
        raise RuntimeError("technical_rollback_plan_active_precondition_invalid")
    if not isinstance(previous, Mapping) or previous.get("state") not in {"missing", "present"}:
        raise RuntimeError("technical_rollback_plan_previous_pointer_invalid")
    if previous.get("state") == "present" and state_binding.get(
        "previous_catalogue_status"
    ) not in {"candidate", "superseded"}:
        raise RuntimeError("technical_rollback_plan_previous_catalogue_precondition_invalid")
    implementation = _rollback_implementation_binding()
    return sealed_safe_payload(
        {
            "schema": TECHNICAL_ROLLBACK_SCHEMA,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "candidate_status": candidate.status,
            "current_active_build_id": active_build_id,
            "current_active_manifest_sha256": active_manifest,
            "current_active_pointer_sha256": active["pointer_sha256"],
            "current_previous_state": previous["state"],
            "current_previous_pointer_sha256": previous.get("pointer_sha256", "0" * 64),
            "expected_previous_after_promotion_build_id": active_build_id,
            "expected_previous_after_promotion_manifest_sha256": active_manifest,
            "pointer_schema_fields": ["build_id", "manifest_sha256", "promoted_at"],
            "promotion_operation_id": "owner_quality_v111_atomic_promotion_v1",
            "promotion_arguments": [
                "promote",
                "--presentation",
                "verified-presentation-capability",
                "--owner-authorization",
                "trusted-owner-authorization-capability",
            ],
            "rollback_operation_id": "catalogue_pointer_atomic_rollback_v1",
            "rollback_arguments": ["rollback"],
            "implementation": implementation,
            "post_promotion_drill_status": "not_executed_by_pre_promotion_plan",
        }
    )


def _capture_context(
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: StageAReplayInputs,
    expected_integration_sha: str,
    scratch_root: Path,
) -> _Context:
    if settings.project_root.resolve() != _INTEGRATION_ROOT:
        raise RuntimeError("technical_attestation_project_root_mismatch")
    if stage_a.output_root.resolve() != (settings.evaluation_dir / "stage-a-v2").resolve():
        raise RuntimeError("technical_attestation_stage_a_root_mismatch")
    if (
        stage_a.bundle.root.resolve()
        != (settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1").resolve()
    ):
        raise RuntimeError("technical_attestation_live60_bundle_root_mismatch")
    integration_sha = _clean_integration_sha(settings.project_root)
    if integration_sha != expected_integration_sha or not _GIT_SHA.fullmatch(integration_sha):
        raise RuntimeError("technical_attestation_integration_sha_mismatch")
    state = _catalogue_binding(settings=settings, database=database, candidate=candidate)
    rollback = _rollback_binding(
        settings=settings,
        database=database,
        candidate=candidate,
        state_binding=state,
        integration_sha=integration_sha,
    )
    stage_a_binding = _stage_a_binding(
        candidate=candidate, stage_a=stage_a, integration_sha=integration_sha
    )
    toolchain = _resolve_toolchain(settings.project_root, scratch_root=scratch_root)
    locks = _lock_binding(settings.project_root)
    return _Context(
        integration_sha=integration_sha,
        candidate_binding=MappingProxyType(candidate.safe_dict()),
        stage_a_binding=MappingProxyType(stage_a_binding),
        toolchain=toolchain,
        lock_binding=MappingProxyType(locks),
        state_binding=MappingProxyType(state),
        rollback_binding=MappingProxyType(rollback),
    )


def _context_binding(context: _Context) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": "legalbot.v111-technical-context.v1",
            "integration_sha": context.integration_sha,
            "candidate": dict(context.candidate_binding),
            "stage_a_seal_sha256": context.stage_a_binding["seal_sha256"],
            "toolchain_seal_sha256": context.toolchain.binding["seal_sha256"],
            "lock_set_seal_sha256": context.lock_binding["seal_sha256"],
            "state_seal_sha256": context.state_binding["seal_sha256"],
            "rollback_plan_seal_sha256": context.rollback_binding["seal_sha256"],
        }
    )


def _resolved_argv(spec: _CheckSpec, toolchain: _Toolchain) -> list[str]:
    if spec.executor_id == "uv":
        inner = [str(toolchain.uv), *spec.arguments]
    elif spec.executor_id == "npm":
        inner = [str(toolchain.node), str(toolchain.npm_cli), *spec.arguments]
    elif spec.executor_id == "git":
        inner = [str(toolchain.git), *spec.arguments]
    else:
        raise RuntimeError("technical_attestation_executor_not_external")
    return [str(toolchain.sandbox_exec), "-p", _NETWORK_DENY_PROFILE, *inner]


def _semantic_counts(check_id: str, stdout: bytes, stderr: bytes) -> dict[str, int]:
    combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    counts: dict[str, int] = {}
    if check_id == "python_full_suite":
        names = ("passed", "failed", "skipped", "xfailed", "xpassed", "errors")
        counts.update(dict.fromkeys(names, 0))
        summary_matches = re.findall(
            r"(?m)^=+\s+([^=\r\n]*\b(?:passed|failed|errors?)\b[^=\r\n]*)\s+=+\s*$",
            combined,
        )
        counts["summary_match_count"] = len(summary_matches)
        if len(summary_matches) == 1:
            normalized: dict[str, list[int]] = {name: [] for name in names}
            for value, raw_name in re.findall(
                r"(?:^|[,\s])(\d+)\s+(passed|failed|skipped|xfailed|xpassed|errors?)"
                r"(?=\s|,|$)",
                summary_matches[0],
            ):
                name = "errors" if raw_name in {"error", "errors"} else raw_name
                normalized[name].append(int(value))
            if any(len(token_values) > 1 for token_values in normalized.values()):
                counts["summary_match_count"] = 0
            else:
                for name, token_values in normalized.items():
                    counts[name] = token_values[0] if token_values else 0
    elif check_id == "python_ruff":
        counts["success_marker_count"] = combined.count("All checks passed!")
    elif check_id == "python_ruff_format":
        formatted = re.search(r"(\d+) files? already formatted", combined)
        counts["already_formatted_file_count"] = int(formatted.group(1)) if formatted else 0
        counts["would_reformat_count"] = len(re.findall(r"Would reformat:", combined))
    elif check_id == "python_static_baseline":
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            counts["static_json_invalid"] = 1
        else:
            baseline = payload.get("baseline") if isinstance(payload, Mapping) else None
            ruff = baseline.get("ruff") if isinstance(baseline, Mapping) else None
            mypy = baseline.get("mypy") if isinstance(baseline, Mapping) else None
            values = {
                "ruff_error_count": payload.get("ruff_error_count"),
                "mypy_error_count": payload.get("mypy_error_count"),
                "mypy_file_count": payload.get("mypy_file_count"),
                "ruff_max_error_count": ruff.get("max_error_count")
                if isinstance(ruff, Mapping)
                else None,
                "mypy_max_error_count": mypy.get("max_error_count")
                if isinstance(mypy, Mapping)
                else None,
                "mypy_max_file_count": mypy.get("max_file_count")
                if isinstance(mypy, Mapping)
                else None,
            }
            for name, value in values.items():
                counts[name] = value if isinstance(value, int) and value >= 0 else -1
    elif check_id == "workflow_security":
        counts["success_marker_count"] = combined.count("workflow security scan passed")
    elif check_id == "clean_room":
        counts["success_marker_count"] = combined.count("Clean-room check passed:")
    elif check_id == "live60_verify":
        lines = [line.strip() for line in combined.splitlines() if line.strip()]
        counts["sha256_line_count"] = sum(bool(_SHA256.fullmatch(line)) for line in lines)
        counts["nonempty_line_count"] = len(lines)
    elif check_id == "web_clean_install":
        installed = re.search(r"added\s+(\d+)\s+packages?", combined)
        counts["installed_package_count"] = int(installed.group(1)) if installed else 0
    elif check_id == "web_lint":
        counts["npm_script_marker_count"] = len(
            re.findall(r">\s+legalbot-new-web@0\.1\.0\s+lint", combined)
        )
        counts["eslint_command_marker_count"] = len(
            re.findall(r">\s+eslint \.\s*(?:\r?\n|$)", combined)
        )
    elif check_id == "web_test":
        passed = re.search(r"# pass\s+(\d+)", combined)
        failed = re.search(r"# fail\s+(\d+)", combined)
        tests = re.search(r"# tests\s+(\d+)", combined)
        counts["node_pass_count"] = int(passed.group(1)) if passed else 0
        counts["node_fail_count"] = int(failed.group(1)) if failed else -1
        counts["node_test_count"] = int(tests.group(1)) if tests else 0
        counts["npm_script_marker_count"] = len(
            re.findall(r">\s+legalbot-new-web@0\.1\.0\s+test", combined)
        )
    elif check_id == "web_build":
        counts["npm_script_marker_count"] = len(
            re.findall(r">\s+legalbot-new-web@0\.1\.0\s+build", combined)
        )
        counts["vite_build_marker_count"] = len(re.findall(r"✓ built in ", combined))
    elif check_id == "web_audit" and stdout:
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            counts["audit_json_invalid"] = 1
        else:
            metadata = payload.get("metadata") if isinstance(payload, Mapping) else None
            vulnerabilities = (
                metadata.get("vulnerabilities") if isinstance(metadata, Mapping) else None
            )
            required = ("critical", "high", "moderate", "low", "info", "total")
            if isinstance(vulnerabilities, Mapping) and set(vulnerabilities) == set(required):
                for severity in required:
                    value = vulnerabilities.get(severity)
                    counts[severity] = (
                        value
                        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
                        else -1
                    )
    elif check_id == "repository_secret_scan" and stdout:
        try:
            payload = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            counts["secret_scan_json_invalid"] = 1
        else:
            for name in ("finding_count", "scanned_byte_count", "scanned_member_count"):
                value = payload.get(name) if isinstance(payload, Mapping) else None
                counts[name] = value if isinstance(value, int) and value >= 0 else -1
    return counts


def _require_semantic_pass(
    *, check_id: str, counts: Mapping[str, Any], outcome: Mapping[str, Any]
) -> None:
    """Require a parseable, check-specific success result in addition to exit zero."""

    expected_keys: dict[str, frozenset[str]] = {
        "python_full_suite": frozenset(
            {"passed", "failed", "skipped", "xfailed", "xpassed", "errors", "summary_match_count"}
        ),
        "python_ruff": frozenset({"success_marker_count"}),
        "python_ruff_format": frozenset({"already_formatted_file_count", "would_reformat_count"}),
        "python_static_baseline": frozenset(
            {
                "ruff_error_count",
                "mypy_error_count",
                "mypy_file_count",
                "ruff_max_error_count",
                "mypy_max_error_count",
                "mypy_max_file_count",
            }
        ),
        "workflow_security": frozenset({"success_marker_count"}),
        "clean_room": frozenset({"success_marker_count"}),
        "live60_verify": frozenset({"sha256_line_count", "nonempty_line_count"}),
        "web_clean_install": frozenset({"installed_package_count"}),
        "web_lint": frozenset({"npm_script_marker_count", "eslint_command_marker_count"}),
        "web_test": frozenset(
            {"node_pass_count", "node_fail_count", "node_test_count", "npm_script_marker_count"}
        ),
        "web_build": frozenset({"npm_script_marker_count", "vite_build_marker_count"}),
        "web_audit": frozenset({"critical", "high", "moderate", "low", "info", "total"}),
        "repository_secret_scan": frozenset(
            {"finding_count", "scanned_byte_count", "scanned_member_count"}
        ),
        "repository_diff_check": frozenset(),
    }
    expected = expected_keys.get(check_id)
    if expected is None or set(counts) != expected:
        raise ValueError("technical attestation semantic result schema is invalid")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in counts.values()):
        raise ValueError("technical attestation semantic result count is invalid")
    valid = False
    if check_id == "python_full_suite":
        valid = (
            counts["passed"] > 0
            and counts["failed"] == 0
            and counts["errors"] == 0
            and counts["summary_match_count"] == 1
        )
    elif check_id in {"python_ruff", "workflow_security", "clean_room"}:
        valid = counts["success_marker_count"] == 1
    elif check_id == "python_ruff_format":
        valid = counts["already_formatted_file_count"] > 0 and counts["would_reformat_count"] == 0
    elif check_id == "python_static_baseline":
        valid = (
            min(counts.values()) >= 0
            and counts["ruff_error_count"] <= counts["ruff_max_error_count"]
            and counts["mypy_error_count"] <= counts["mypy_max_error_count"]
            and counts["mypy_file_count"] <= counts["mypy_max_file_count"]
        )
    elif check_id == "live60_verify":
        valid = counts["sha256_line_count"] == 1 and counts["nonempty_line_count"] == 1
    elif check_id == "web_clean_install":
        valid = counts["installed_package_count"] > 0
    elif check_id == "web_lint":
        valid = counts["npm_script_marker_count"] == counts["eslint_command_marker_count"] == 1
    elif check_id == "web_test":
        valid = (
            counts["npm_script_marker_count"] == 1
            and counts["node_test_count"] > 0
            and counts["node_pass_count"] == counts["node_test_count"]
            and counts["node_fail_count"] == 0
        )
    elif check_id == "web_build":
        valid = counts["npm_script_marker_count"] == counts["vite_build_marker_count"] == 1
    elif check_id == "web_audit":
        valid = (
            min(counts.values()) >= 0
            and counts["critical"] == counts["high"] == 0
            and counts["total"]
            == sum(counts[name] for name in ("critical", "high", "moderate", "low", "info"))
        )
    elif check_id == "repository_secret_scan":
        valid = (
            counts["finding_count"] == 0
            and counts["scanned_byte_count"] > 0
            and counts["scanned_member_count"] > 0
        )
    elif check_id == "repository_diff_check":
        valid = outcome.get("stdout_byte_count") == outcome.get("stderr_byte_count") == 0
    if not valid:
        raise ValueError("technical attestation semantic result did not pass")


def _tracked_repository_members(
    project_root: Path, toolchain: _Toolchain, environment: Mapping[str, str]
) -> tuple[Path, ...]:
    completed = subprocess.run(
        [str(toolchain.git), "-C", str(project_root), "ls-files", "-z", "--", "."],
        check=False,
        capture_output=True,
        timeout=60,
        env=dict(environment),
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("technical_attestation_repository_inventory_failed")
    members: list[Path] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("technical_attestation_repository_inventory_invalid") from exc
        raw_member = project_root / relative
        try:
            raw_stat = raw_member.lstat()
        except OSError as exc:
            raise RuntimeError("technical_attestation_repository_inventory_invalid") from exc
        if stat.S_ISLNK(raw_stat.st_mode) or not stat.S_ISREG(raw_stat.st_mode):
            raise RuntimeError("technical_attestation_repository_inventory_invalid")
        member = raw_member.resolve()
        if not member.is_relative_to(project_root.resolve()) or not member.is_file():
            raise RuntimeError("technical_attestation_repository_inventory_invalid")
        members.append(member)
    return tuple(members)


def _execute_repository_secret_scan(
    *, project_root: Path, toolchain: _Toolchain, environment: Mapping[str, str]
) -> tuple[int, bytes, bytes]:
    members = _tracked_repository_members(project_root, toolchain, environment)
    finding_count = 0
    scanned_bytes = 0
    for member in members:
        raw = member.read_bytes()
        scanned_bytes += len(raw)
        for pattern in _SECRET_PATTERNS:
            finding_count += len(pattern.findall(raw))
    safe_summary = json.dumps(
        {
            "finding_count": finding_count,
            "scanned_byte_count": scanned_bytes,
            "scanned_member_count": len(members),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return (0 if finding_count == 0 else 1), safe_summary, b""


def _execute_check(
    *,
    spec: _CheckSpec,
    settings: Settings,
    toolchain: _Toolchain,
    scratch_root: Path,
) -> _ExecutionObservation:
    encryption_key = Fernet.generate_key().decode("ascii")
    environment = _base_environment(scratch_root=scratch_root, encryption_key=encryption_key)
    if spec.executor_id == "internal_repository_secret_scan":
        exit_code, stdout, stderr = _execute_repository_secret_scan(
            project_root=settings.project_root,
            toolchain=toolchain,
            environment=environment,
        )
    else:
        cwd = settings.project_root if spec.cwd_id == "project" else settings.project_root / "web"
        try:
            completed = subprocess.run(
                _resolved_argv(spec, toolchain),
                cwd=cwd,
                check=False,
                capture_output=True,
                timeout=spec.timeout_seconds,
                env=environment,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
            stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        else:
            exit_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
    return _ExecutionObservation(
        exit_code=exit_code,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_byte_count=len(stdout),
        stderr_byte_count=len(stderr),
        stdout_line_count=stdout.count(b"\n"),
        stderr_line_count=stderr.count(b"\n"),
        semantic_counts=MappingProxyType(_semantic_counts(spec.check_id, stdout, stderr)),
    )


def _intent(*, run_id: str, spec: _CheckSpec, manifest_seal_sha256: str) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": TECHNICAL_INTENT_SCHEMA,
            "run_id": run_id,
            "ordinal": spec.ordinal,
            "check_id": spec.check_id,
            "check_contract": spec.safe_dict(),
            "matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
            "run_manifest_seal_sha256": manifest_seal_sha256,
            "attempt_number": 1,
            "retry_count": 0,
        }
    )


def _outcome(
    *, run_id: str, spec: _CheckSpec, intent: Mapping[str, Any], observed: _ExecutionObservation
) -> dict[str, Any]:
    return sealed_safe_payload(
        {
            "schema": TECHNICAL_OUTCOME_SCHEMA,
            "run_id": run_id,
            "ordinal": spec.ordinal,
            "check_id": spec.check_id,
            "intent_seal_sha256": intent["seal_sha256"],
            "exit_code": observed.exit_code,
            "stdout_sha256": observed.stdout_sha256,
            "stderr_sha256": observed.stderr_sha256,
            "stdout_byte_count": observed.stdout_byte_count,
            "stderr_byte_count": observed.stderr_byte_count,
            "stdout_line_count": observed.stdout_line_count,
            "stderr_line_count": observed.stderr_line_count,
            "semantic_counts": dict(observed.semantic_counts),
            "attempt_number": 1,
            "retry_count": 0,
        }
    )


def _artifact_name(kind: str, spec: _CheckSpec) -> str:
    if kind not in {"intents", "outcomes"}:
        raise ValueError("technical artifact kind is invalid")
    return f"{kind}/{spec.ordinal:02d}-{spec.check_id}.json"


def _expected_run_root(settings: Settings, run_id: str) -> Path:
    if not _SAFE_RUN_ID.fullmatch(run_id):
        raise ValueError("technical attestation run ID is invalid")
    return (settings.evaluation_dir / "v111-technical-attestations" / run_id).resolve()


def run_v111_technical_attestation_create_only(
    *,
    run_id: str,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: StageAReplayInputs,
    expected_integration_sha: str,
) -> CompletedV111TechnicalRun:
    """Execute the exact matrix once and return a non-persistable live handle."""

    if not _SAFE_RUN_ID.fullmatch(run_id) or not _GIT_SHA.fullmatch(expected_integration_sha):
        raise ValueError("technical attestation run binding is invalid")
    output_root = settings.evaluation_dir / "v111-technical-attestations"
    output_root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_root.parent.chmod(0o700)
    with tempfile.TemporaryDirectory(prefix=".technical-scratch-", dir=output_root.parent) as raw:
        scratch_root = Path(raw)
        scratch_root.chmod(0o700)
        start = _capture_context(
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=expected_integration_sha,
            scratch_root=scratch_root,
        )
        writer = CreateOnlyRunDirectory(root=output_root, run_id=run_id, resume=False)
        stage_a_artifact = dict(start.stage_a_binding)
        rollback_artifact = dict(start.rollback_binding)
        writer.write_json("stage-a-scorer-reattestation.json", stage_a_artifact)
        writer.write_json("rollback-plan-readiness.json", rollback_artifact)
        context_binding = _context_binding(start)
        manifest = sealed_safe_payload(
            {
                "schema": TECHNICAL_RUN_SCHEMA,
                "run_id": run_id,
                "integration_sha": start.integration_sha,
                "candidate_build_id": candidate.build_id,
                "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
                "matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
                "checks": [item.safe_dict() for item in FIXED_CHECK_MATRIX],
                "context": context_binding,
                "stage_a_attestation_seal_sha256": stage_a_artifact["seal_sha256"],
                "rollback_plan_seal_sha256": rollback_artifact["seal_sha256"],
                "execution_policy": "serial_once_no_retry_no_shell_network_denied",
                "raw_output_persisted": False,
                "writes_active": False,
                "writes_o04": False,
                "starts_model": False,
            }
        )
        writer.write_json("run-manifest.json", manifest)
        outcomes: list[dict[str, Any]] = []
        for spec in FIXED_CHECK_MATRIX:
            intent = _intent(
                run_id=run_id,
                spec=spec,
                manifest_seal_sha256=str(manifest["seal_sha256"]),
            )
            writer.write_json(_artifact_name("intents", spec), intent)
            observed = _execute_check(
                spec=spec,
                settings=settings,
                toolchain=start.toolchain,
                scratch_root=scratch_root,
            )
            outcome = _outcome(run_id=run_id, spec=spec, intent=intent, observed=observed)
            writer.write_json(_artifact_name("outcomes", spec), outcome)
            outcomes.append(outcome)
        end = _capture_context(
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=expected_integration_sha,
            scratch_root=scratch_root,
        )
        if _context_binding(end) != context_binding:
            raise RuntimeError("technical_attestation_context_changed_during_matrix")
        final = sealed_safe_payload(
            {
                "schema": TECHNICAL_FINAL_SCHEMA,
                "run_id": run_id,
                "integration_sha": start.integration_sha,
                "candidate_build_id": candidate.build_id,
                "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
                "run_manifest_seal_sha256": manifest["seal_sha256"],
                "matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
                "outcome_seal_sha256s": [item["seal_sha256"] for item in outcomes],
                "outcome_count": len(outcomes),
                "context_seal_sha256": context_binding["seal_sha256"],
                "stage_a_attestation_seal_sha256": stage_a_artifact["seal_sha256"],
                "rollback_plan_seal_sha256": rollback_artifact["seal_sha256"],
                "terminal_state": "matrix_completed",
                "post_promotion_drill_status": "not_part_of_pre_promotion_attestation",
            }
        )
        writer.write_json("final-attestation.json", final)
    return CompletedV111TechnicalRun(
        run_id=run_id,
        run_root=writer.path,
        manifest=manifest,
        outcomes=outcomes,
        final=final,
        _token=_RUN_TOKEN,
    )


def _require_private_exact_inventory(run_root: Path) -> None:
    expected_files = {
        "run-manifest.json",
        "stage-a-scorer-reattestation.json",
        "rollback-plan-readiness.json",
        "final-attestation.json",
        *(_artifact_name("intents", item) for item in FIXED_CHECK_MATRIX),
        *(_artifact_name("outcomes", item) for item in FIXED_CHECK_MATRIX),
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    if run_root.is_symlink() or not run_root.is_dir():
        raise ValueError("technical attestation run directory is missing or unsafe")
    root_metadata = run_root.stat()
    if root_metadata.st_uid != os.getuid() or stat.S_IMODE(root_metadata.st_mode) & 0o077:
        raise ValueError("technical attestation run directory is not private")
    for member in run_root.rglob("*"):
        relative = member.relative_to(run_root).as_posix()
        metadata = member.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise ValueError("technical attestation inventory contains an unsafe member")
        if member.is_dir():
            observed_directories.add(relative)
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ValueError("technical attestation directory is not private")
        elif member.is_file():
            observed_files.add(relative)
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ValueError("technical attestation artifact is not private")
        else:
            raise ValueError("technical attestation inventory contains a special member")
    if observed_files != expected_files or observed_directories != {"intents", "outcomes"}:
        raise ValueError("technical attestation artifact inventory is not exact")


def load_verified_v111_technical_attestation(
    completed_run: object,
    *,
    settings: Settings,
    database: Database,
    candidate: SealedCandidateIdentity,
    stage_a: StageAReplayInputs,
    expected_integration_sha: str,
) -> VerifiedV111TechnicalAttestation:
    """Replay one live run and issue the only promotion-consumable capability."""

    if (
        type(completed_run) is not CompletedV111TechnicalRun
        or completed_run._token is not _RUN_TOKEN
    ):
        raise TypeError("v111_technical_attestation_requires_live_runner_capability")
    run = completed_run
    expected_root = _expected_run_root(settings, run.run_id)
    if run._run_root != expected_root:
        raise ValueError("technical attestation run root is not canonical")
    _require_private_exact_inventory(expected_root)
    writer = CreateOnlyRunDirectory(root=expected_root.parent, run_id=run.run_id, resume=True)
    manifest = verify_sealed_artifact(
        writer.read_json("run-manifest.json"), schema=TECHNICAL_RUN_SCHEMA
    )
    if manifest != dict(run._manifest):
        raise ValueError("technical attestation manifest differs from live runner")
    with tempfile.TemporaryDirectory(prefix=".technical-replay-", dir=expected_root.parent) as raw:
        scratch_root = Path(raw)
        scratch_root.chmod(0o700)
        current = _capture_context(
            settings=settings,
            database=database,
            candidate=candidate,
            stage_a=stage_a,
            expected_integration_sha=expected_integration_sha,
            scratch_root=scratch_root,
        )
    context_binding = _context_binding(current)
    expected_manifest = sealed_safe_payload(
        {
            "schema": TECHNICAL_RUN_SCHEMA,
            "run_id": run.run_id,
            "integration_sha": current.integration_sha,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
            "checks": [item.safe_dict() for item in FIXED_CHECK_MATRIX],
            "context": context_binding,
            "stage_a_attestation_seal_sha256": current.stage_a_binding["seal_sha256"],
            "rollback_plan_seal_sha256": current.rollback_binding["seal_sha256"],
            "execution_policy": "serial_once_no_retry_no_shell_network_denied",
            "raw_output_persisted": False,
            "writes_active": False,
            "writes_o04": False,
            "starts_model": False,
        }
    )
    if manifest != expected_manifest:
        raise ValueError("technical attestation current integration context changed")
    stage_a_artifact = verify_sealed_artifact(
        writer.read_json("stage-a-scorer-reattestation.json"),
        schema=TECHNICAL_STAGE_A_SCHEMA,
    )
    rollback_artifact = verify_sealed_artifact(
        writer.read_json("rollback-plan-readiness.json"),
        schema=TECHNICAL_ROLLBACK_SCHEMA,
    )
    if stage_a_artifact != dict(current.stage_a_binding) or rollback_artifact != dict(
        current.rollback_binding
    ):
        raise ValueError("technical scorer or rollback proof changed")
    outcome_seals: list[str] = []
    for index, spec in enumerate(FIXED_CHECK_MATRIX):
        intent = verify_sealed_artifact(
            writer.read_json(_artifact_name("intents", spec)), schema=TECHNICAL_INTENT_SCHEMA
        )
        expected_intent = _intent(
            run_id=run.run_id,
            spec=spec,
            manifest_seal_sha256=str(manifest["seal_sha256"]),
        )
        if intent != expected_intent:
            raise ValueError("technical attestation check intent is not the fixed command")
        outcome = verify_sealed_artifact(
            writer.read_json(_artifact_name("outcomes", spec)), schema=TECHNICAL_OUTCOME_SCHEMA
        )
        live_outcome = dict(run._outcomes[index])
        if outcome != live_outcome:
            raise ValueError("technical attestation outcome differs from live execution")
        if (
            outcome.get("run_id") != run.run_id
            or outcome.get("ordinal") != spec.ordinal
            or outcome.get("check_id") != spec.check_id
            or outcome.get("intent_seal_sha256") != intent["seal_sha256"]
            or outcome.get("attempt_number") != 1
            or outcome.get("retry_count") != 0
            or outcome.get("exit_code") != 0
        ):
            raise ValueError("technical attestation check did not pass exactly once")
        for digest_key in ("stdout_sha256", "stderr_sha256"):
            if not _SHA256.fullmatch(str(outcome.get(digest_key) or "")):
                raise ValueError("technical attestation output digest is invalid")
        for count_key in (
            "stdout_byte_count",
            "stderr_byte_count",
            "stdout_line_count",
            "stderr_line_count",
        ):
            count = outcome.get(count_key)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("technical attestation output count is invalid")
        semantic_counts = outcome.get("semantic_counts")
        if not isinstance(semantic_counts, Mapping):
            raise ValueError("technical attestation semantic result is missing")
        _require_semantic_pass(
            check_id=spec.check_id,
            counts=semantic_counts,
            outcome=outcome,
        )
        if spec.check_id == "live60_verify":
            expected_suite_seal = str(
                current.stage_a_binding.get("suite_manifest_seal_sha256") or ""
            )
            expected_stdout_sha256 = hashlib.sha256(
                f"{expected_suite_seal}\n".encode("ascii")
            ).hexdigest()
            if (
                not _SHA256.fullmatch(expected_suite_seal)
                or outcome.get("stdout_sha256") != expected_stdout_sha256
                or outcome.get("stderr_byte_count") != 0
            ):
                raise ValueError("technical Live60 verifier output is not the bound suite seal")
        outcome_seals.append(str(outcome["seal_sha256"]))
    final = verify_sealed_artifact(
        writer.read_json("final-attestation.json"), schema=TECHNICAL_FINAL_SCHEMA
    )
    expected_final = sealed_safe_payload(
        {
            "schema": TECHNICAL_FINAL_SCHEMA,
            "run_id": run.run_id,
            "integration_sha": current.integration_sha,
            "candidate_build_id": candidate.build_id,
            "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
            "run_manifest_seal_sha256": manifest["seal_sha256"],
            "matrix_sha256": FIXED_CHECK_MATRIX_SHA256,
            "outcome_seal_sha256s": outcome_seals,
            "outcome_count": len(outcome_seals),
            "context_seal_sha256": context_binding["seal_sha256"],
            "stage_a_attestation_seal_sha256": stage_a_artifact["seal_sha256"],
            "rollback_plan_seal_sha256": rollback_artifact["seal_sha256"],
            "terminal_state": "matrix_completed",
            "post_promotion_drill_status": "not_part_of_pre_promotion_attestation",
        }
    )
    if final != expected_final or final != dict(run._final):
        raise ValueError("technical final attestation differs from strict replay")
    return VerifiedV111TechnicalAttestation(
        run_root=expected_root,
        attestation=final,
        _token=_VERIFIED_TOKEN,
    )


__all__ = [
    "FIXED_CHECK_MATRIX_SHA256",
    "CompletedV111TechnicalRun",
    "StageAReplayInputs",
    "VerifiedV111TechnicalAttestation",
    "build_first_live_rollback_decision_request",
    "load_verified_v111_technical_attestation",
    "require_verified_v111_technical_attestation",
    "run_v111_technical_attestation_create_only",
    "write_first_live_rollback_decision_request",
]
