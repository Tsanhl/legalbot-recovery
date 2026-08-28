"""Non-authorizing, reproducible verification for the v1.11 Integration Baseline."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from .live_suite import sealed_sha256

INTEGRATION_VERIFICATION_SCHEMA = "legalbot.v111-integration-verification-report.v1"
CHECK_OUTCOME_SCHEMA = "legalbot.v111-integration-verification-check.v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")


@dataclass(frozen=True, slots=True)
class CheckSpec:
    check_id: str
    cwd_id: str
    argv: tuple[str, ...]
    timeout_seconds: int

    def safe_dict(self, ordinal: int) -> dict[str, Any]:
        return {
            "ordinal": ordinal,
            "check_id": self.check_id,
            "cwd_id": self.cwd_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
        }


CHECK_MATRIX: Final[tuple[CheckSpec, ...]] = (
    CheckSpec(
        "integration_records",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "python",
            "scripts/validate_v111_integration_records.py",
        ),
        600,
    ),
    CheckSpec(
        "python_dependency_sync", "project", ("uv", "sync", "--frozen", "--all-extras"), 3_600
    ),
    CheckSpec(
        "python_ruff",
        "project",
        ("uv", "run", "--frozen", "--all-extras", "ruff", "check", "backend", "scripts"),
        1_800,
    ),
    CheckSpec(
        "python_ruff_format",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "ruff",
            "format",
            "--check",
            "backend",
            "scripts",
        ),
        1_800,
    ),
    CheckSpec(
        "python_mypy_full",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "mypy",
            "backend/app",
            "--no-incremental",
        ),
        3_600,
    ),
    CheckSpec(
        "python_static_baseline",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "python",
            "scripts/ci/check_static_baseline.py",
        ),
        3_600,
    ),
    CheckSpec(
        "python_full_suite",
        "project",
        ("uv", "run", "--frozen", "--all-extras", "pytest"),
        10_800,
    ),
    CheckSpec(
        "immutable_live60_verify",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "python",
            "scripts/live_evaluation_suite.py",
            "verify",
        ),
        1_800,
    ),
    CheckSpec(
        "clean_room",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "python",
            "scripts/check_clean_room.py",
        ),
        1_800,
    ),
    CheckSpec(
        "workflow_security",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "python",
            "scripts/security/check_workflow_policy.py",
        ),
        600,
    ),
    CheckSpec(
        "workflow_and_artifact_drift",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "pytest",
            "-q",
            "backend/tests/test_github_workflow_pins.py",
            "backend/tests/test_live60_current_contract_drift.py",
        ),
        1_800,
    ),
    CheckSpec(
        "repository_content_scan",
        "project",
        (
            "uv",
            "run",
            "--frozen",
            "--all-extras",
            "python",
            "scripts/security/check_repository_content.py",
        ),
        1_800,
    ),
    CheckSpec(
        "web_clean_install",
        "web",
        ("npm", "ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund"),
        3_600,
    ),
    CheckSpec("web_lint", "web", ("npm", "run", "lint", "--offline"), 1_800),
    CheckSpec("web_test", "web", ("npm", "test", "--offline"), 3_600),
    CheckSpec("web_build", "web", ("npm", "run", "build", "--offline"), 1_800),
    CheckSpec(
        "web_high_severity_audit",
        "web",
        ("npm", "audit", "--offline", "--audit-level=high", "--json"),
        1_800,
    ),
    CheckSpec("repository_diff_check", "project", ("git", "diff", "--check", "HEAD"), 600),
)

CHECK_MATRIX_SHA256 = sealed_sha256(
    {
        "schema": "legalbot.v111-integration-verification-matrix.v1",
        "checks": [spec.safe_dict(index) for index, spec in enumerate(CHECK_MATRIX, start=1)],
        "retry_count": 0,
        "shell": False,
        "authorizing": False,
    }
)

LOCK_MEMBERS: Final[tuple[str, ...]] = (
    ".node-version",
    ".python-version",
    "model-runtime/uv.lock",
    "pyproject.toml",
    "uv.lock",
    "web/package-lock.json",
    "web/package.json",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("integration verification identity file is missing or unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(project_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("integration verification Git observation failed")
    return completed.stdout.strip()


def _clean_status(project_root: Path) -> tuple[bool, str]:
    raw = subprocess.run(
        ["git", "status", "--porcelain=v2", "--untracked-files=all", "-z"],
        cwd=project_root,
        check=True,
        capture_output=True,
        timeout=60,
        shell=False,
    ).stdout
    return not raw, _sha256_bytes(raw)


def _safe_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key]
        for key in ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR")
        if key in os.environ
    }
    environment.update(
        {
            "CI": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "UV_NO_PROGRESS": "1",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "LEGALBOT_HOST": "127.0.0.1",
            "LEGALBOT_PORT": "8777",
            "LEGALBOT_MODEL_URL": "http://127.0.0.1:8778",
            "LEGALBOT_ONLINE_MODE": "local_only",
            "LEGALBOT_OFFICIAL_RESEARCH_ENABLED": "false",
            "LEGALBOT_XERJ_ENABLED": "false",
            "LEGALBOT_PHOENIX_ENABLED": "false",
            "LEGALBOT_TEST_MODE": "1",
        }
    )
    return environment


def _tool_version(argv: Sequence[str], environment: Mapping[str, str]) -> str:
    completed = subprocess.run(
        list(argv),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=dict(environment),
        shell=False,
    )
    value = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not value or "\n" in value:
        raise RuntimeError("integration verification tool version is unavailable")
    return value[:128]


def _runtime_binding(project_root: Path, environment: Mapping[str, str]) -> dict[str, Any]:
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("integration verification requires Python 3.13")
    if (project_root / ".python-version").read_text(encoding="utf-8").strip() != "3.13":
        raise RuntimeError("integration verification Python selector mismatch")
    if (project_root / ".node-version").read_text(encoding="utf-8").strip() != "24":
        raise RuntimeError("integration verification Node selector mismatch")
    executable_ids: dict[str, str] = {}
    for tool in ("git", "node", "npm", "uv"):
        resolved = shutil.which(tool, path=environment.get("PATH"))
        if resolved is None:
            raise RuntimeError("integration verification tool is missing")
        executable_ids[f"{tool}_sha256"] = _file_sha256(Path(resolved).resolve())
    node_version = _tool_version(("node", "--version"), environment)
    if re.fullmatch(r"v24\.[0-9]+\.[0-9]+", node_version) is None:
        raise RuntimeError("integration verification requires Node 24")
    return {
        "schema": "legalbot.v111-integration-runtime-binding.v1",
        "python_version": _tool_version((sys.executable, "--version"), environment),
        "uv_version": _tool_version(("uv", "--version"), environment),
        "node_version": node_version,
        "npm_version": _tool_version(("npm", "--version"), environment),
        **executable_ids,
        "environment_policy": "allowlisted-no-credential-forwarding",
        "test_mode": True,
        "network_mode": "local-only-application; package-commands-use-frozen-or-offline-flags",
    }


def _lock_binding(project_root: Path) -> dict[str, Any]:
    members = [
        {"path": member, "sha256": _file_sha256(project_root / member)} for member in LOCK_MEMBERS
    ]
    return {
        "schema": "legalbot.v111-integration-lock-binding.v1",
        "members": members,
        "member_count": len(members),
        "aggregate_sha256": sealed_sha256(
            {"schema": "legalbot.v111-integration-lock-set.v1", "members": members}
        ),
    }


def _semantic_counts(check_id: str, stdout: bytes, stderr: bytes) -> dict[str, int]:
    text = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    counts: dict[str, int] = {}
    pytest_match = re.search(r"(?P<passed>[0-9]+) passed", text)
    failed_match = re.search(r"(?P<failed>[0-9]+) failed", text)
    mypy_match = re.search(r"Success: no issues found in (?P<files>[0-9]+) source files", text)
    if pytest_match:
        counts["pytest_passed"] = int(pytest_match.group("passed"))
    if failed_match:
        counts["pytest_failed"] = int(failed_match.group("failed"))
    if mypy_match:
        counts["mypy_source_files"] = int(mypy_match.group("files"))
        counts["mypy_errors"] = 0
    if "All checks passed!" in text:
        counts["ruff_errors"] = 0
    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = None
    if isinstance(payload, dict):
        for key in (
            "archive_file_count",
            "ledger_entry_count",
            "private_path_hit_count",
            "release_artifact_count",
            "secret_hit_count",
            "tracked_member_count",
        ):
            value = payload.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                counts[key] = value
        metadata = payload.get("metadata")
        vulnerabilities = metadata.get("vulnerabilities") if isinstance(metadata, dict) else None
        if isinstance(vulnerabilities, dict):
            for severity in ("low", "moderate", "high", "critical", "total"):
                value = vulnerabilities.get(severity)
                if isinstance(value, int):
                    counts[f"audit_{severity}"] = value
    if check_id == "repository_diff_check" and not stdout and not stderr:
        counts["diff_errors"] = 0
    return counts


def _run_check(
    spec: CheckSpec,
    *,
    ordinal: int,
    project_root: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    cwd = project_root if spec.cwd_id == "project" else project_root / "web"
    command_identity = sealed_sha256(
        {
            "schema": "legalbot.v111-integration-command-identity.v1",
            **spec.safe_dict(ordinal),
            "environment_policy": "allowlisted-no-credential-forwarding",
        }
    )
    started_at = datetime.now(UTC)
    timed_out = False
    try:
        completed = subprocess.run(
            list(spec.argv),
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=spec.timeout_seconds,
            env=dict(environment),
            shell=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = bytes(exc.stdout or b"")
        stderr = bytes(exc.stderr or b"")
    finished_at = datetime.now(UTC)
    return {
        "schema": CHECK_OUTCOME_SCHEMA,
        "ordinal": ordinal,
        "check_id": spec.check_id,
        "command_identity_sha256": command_identity,
        "cwd_id": spec.cwd_id,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout_sha256": _sha256_bytes(stdout),
        "stderr_sha256": _sha256_bytes(stderr),
        "stdout_byte_count": len(stdout),
        "stderr_byte_count": len(stderr),
        "semantic_counts": _semantic_counts(spec.check_id, stdout, stderr),
        "passed": exit_code == 0 and not timed_out,
    }


def _safe_output_path(project_root: Path, run_id: str) -> Path:
    if _SAFE_RUN_ID.fullmatch(run_id) is None:
        raise ValueError("integration verification run ID is invalid")
    output_root = (project_root / "data/evaluations/integration-verification").resolve()
    output = (output_root / run_id / "report.json").resolve()
    if not output.is_relative_to(output_root):
        raise ValueError("integration verification output escaped its private root")
    return output


def _write_create_only_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    path.parent.chmod(0o700)
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError("integration verification report permissions are unsafe")


def run_integration_verification(
    *,
    project_root: Path,
    run_id: str,
    expected_head: str | None = None,
) -> dict[str, Any]:
    root = project_root.resolve()
    output = _safe_output_path(root, run_id)
    clean_before, status_before_sha256 = _clean_status(root)
    if not clean_before:
        raise RuntimeError("integration verification requires an exact clean HEAD")
    start_head = _git(root, "rev-parse", "HEAD")
    start_tree = _git(root, "rev-parse", "HEAD^{tree}")
    if not _GIT_SHA.fullmatch(start_head) or not _GIT_SHA.fullmatch(start_tree):
        raise RuntimeError("integration verification Git identity is invalid")
    if expected_head is not None and start_head != expected_head:
        raise RuntimeError("integration verification HEAD differs from expected")
    branch = _git(root, "branch", "--show-current")
    if branch != "codex/release-v111-integration":
        raise RuntimeError("integration verification is on the wrong branch")
    environment = _safe_environment()
    runtime = _runtime_binding(root, environment)
    locks = _lock_binding(root)
    started_at = datetime.now(UTC)
    checks = [
        _run_check(
            spec,
            ordinal=ordinal,
            project_root=root,
            environment=environment,
        )
        for ordinal, spec in enumerate(CHECK_MATRIX, start=1)
    ]
    finished_at = datetime.now(UTC)
    end_head = _git(root, "rev-parse", "HEAD")
    end_tree = _git(root, "rev-parse", "HEAD^{tree}")
    clean_after, status_after_sha256 = _clean_status(root)
    end_locks = _lock_binding(root)
    exact_snapshot = (
        start_head == end_head and start_tree == end_tree and locks == end_locks and clean_after
    )
    passed = all(check["passed"] is True for check in checks) and exact_snapshot
    report: dict[str, Any] = {
        "schema": INTEGRATION_VERIFICATION_SCHEMA,
        "authorizing": False,
        "purpose": "integration-baseline-verification-only",
        "run_id": run_id,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 6),
        "git": {
            "branch": branch,
            "commit": start_head,
            "tree": start_tree,
            "end_commit": end_head,
            "end_tree": end_tree,
            "expected_head": expected_head,
            "clean_before": clean_before,
            "clean_after": clean_after,
            "status_before_sha256": status_before_sha256,
            "status_after_sha256": status_after_sha256,
            "exact_snapshot_passed": exact_snapshot,
        },
        "runtime": runtime,
        "locks": locks,
        "check_matrix_sha256": CHECK_MATRIX_SHA256,
        "check_count": len(checks),
        "checks": checks,
        "failed_check_ids": [check["check_id"] for check in checks if check["passed"] is not True],
        "prohibited_actions": {
            "answer_model_invoked": False,
            "runtime_sanity_executed": False,
            "all60_executed": False,
            "stage_a_executed": False,
            "promotion_executed": False,
            "active_written": False,
            "o04_written": False,
            "live_activated": False,
        },
        "passed": passed,
        "status": "passed" if passed else "failed",
    }
    report["report_sha256"] = sealed_sha256(report)
    if not _SHA256.fullmatch(str(report["report_sha256"])):
        raise RuntimeError("integration verification report digest is invalid")
    _write_create_only_report(output, report)
    return report
