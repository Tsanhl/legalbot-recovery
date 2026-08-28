"""Fail-closed authority and isolation primitives for completion preflight.

This module deliberately contains no answer or retrieval execution.  It pins
the locally installed model to a tracked identity, validates the owner-set
memory envelope, proves ownership of the model listener, and creates an
isolated catalogue/object namespace before the substantive runtime starts.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..config import Settings
from ..db import Database
from ..governance.existing_catalogue_read import (
    ExistingCatalogueReadDatabase,
    open_existing_catalogue_read_database,
)
from ..governance.owner_stop import (
    OwnerDecisionRequest,
    OwnerDecisionResolution,
    require_owner_resolution,
)
from ..governance.v111_decision_generation import (
    MEMORY_DECISION_OPTIONS,
    build_completion_memory_decision_request,
    completion_memory_decision_id,
    read_private_owner_decision_member,
    require_exact_clean_head,
)
from ..model_runtime.config import PINNED_RUNTIME_REPO, PINNED_RUNTIME_REVISION
from .live_suite import sealed_sha256
from .nonrelease_artifacts import safe_json_bytes, sealed_safe_payload, verify_sealed_artifact
from .owner_quality_canary_authorization import OwnerDecisionRequired
from .sealed_candidate import SealedCandidateIdentity, load_sealed_candidate_identity

TRUSTED_MODEL_IDENTITY_SCHEMA = "legalbot.completion-trusted-model-identity.v1"
TRUSTED_TOOLCHAIN_IDENTITY_SCHEMA = "legalbot.completion-trusted-toolchain-identity.v3"
MEMORY_POLICY_SCHEMA = "legalbot.completion-memory-policy.v2"
LAUNCHER_START_SCHEMA = "legalbot.completion-launcher-start-attestation.v1"
LAUNCHER_END_SCHEMA = "legalbot.completion-launcher-end-attestation.v1"
MEMORY_MEASUREMENT_SCHEMA = "legalbot.completion-memory-measurement.v2"
MEMORY_SAMPLE_INTERVAL_SECONDS = 0.1
MEMORY_MAX_SAMPLE_INTERVAL_SECONDS = 0.25
MEMORY_MEASUREMENT_METHOD = "owned_process_tree_os_rss_and_host_available_sampled_100ms"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_MEMORY_POLICY_LOAD_TOKEN = object()
_AUTHORITY_PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PYTHON_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv[1]);"
    "runpy.run_module('app.model_runtime',run_name='__main__')"
)
MODEL_PYTHON_ARGV_POLICY_SHA256 = sealed_sha256(
    {
        "schema": "legalbot.completion-model-python-argv.v1",
        "interpreter": "verified_model_virtualenv_python",
        "arguments": [
            "-I",
            "-B",
            "-u",
            "-X",
            "pycache_prefix=<fresh-private-empty-directory>",
            "-c",
            MODEL_PYTHON_BOOTSTRAP,
            "<clean-integration-root>/backend",
        ],
        "cwd_importable": False,
        "user_site_importable": False,
        "ambient_python_environment_used": False,
    }
)

_FORBIDDEN_LAUNCH_ENVIRONMENT_NAMES = frozenset(
    {
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "LEGALBOT_MODEL_ADAPTER_PATH",
        "NO_PROXY",
        "PIP_CONFIG_FILE",
        "PIP_INDEX_URL",
        "PIP_EXTRA_INDEX_URL",
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
        "PYTHONWARNINGS",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "UV_CONFIG_FILE",
        "UV_ENV_FILE",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_INDEX_URL",
        "UV_PROJECT",
        "UV_PROJECT_ENVIRONMENT",
        "UV_PYTHON",
    }
)
_FORBIDDEN_LAUNCH_ENVIRONMENT_PREFIXES = ("DYLD_", "LD_")
_LAUNCH_ENVIRONMENT_POLICY = {
    "schema": "legalbot.completion-model-launch-environment-policy.v1",
    "ambient_values_inherited": [],
    "ambient_forbidden_names": sorted(_FORBIDDEN_LAUNCH_ENVIRONMENT_NAMES),
    "ambient_forbidden_prefixes": list(_FORBIDDEN_LAUNCH_ENVIRONMENT_PREFIXES),
    "path_used_for_discovery_only": True,
    "path_inherited_by_child": False,
    "proxy_environment_inherited": False,
    "pythonpath_is_launcher_authored": False,
    "python_isolated_mode": True,
    "python_no_bytecode_mode": True,
    "python_unbuffered_mode": True,
    "model_python_argv_policy_sha256": MODEL_PYTHON_ARGV_POLICY_SHA256,
    "bytecode_cache_policy": "isolated_mode_plus_no_bytecode",
    "execution_mediator": "none_direct_verified_venv_python",
    "uv_used_for_launch": False,
    "uv_flags": [],
}
LAUNCH_ENVIRONMENT_POLICY_SHA256 = sealed_sha256(_LAUNCH_ENVIRONMENT_POLICY)


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("trusted_identity_source_missing")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_trusted_model_identity(project_root: Path) -> dict[str, Any]:
    """Load the tracked model allowlist; the clean Git SHA authenticates its bytes."""

    path = project_root / "config/completion_preflight_model_identity.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("trusted_model_identity_invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("trusted_model_identity_invalid")
    try:
        verified = verify_sealed_artifact(payload, schema=TRUSTED_MODEL_IDENTITY_SCHEMA)
    except ValueError as exc:
        raise RuntimeError("trusted_model_identity_invalid") from exc
    if (
        verified.get("model_id") != PINNED_RUNTIME_REPO
        or verified.get("model_revision") != PINNED_RUNTIME_REVISION
        or verified.get("post_trained") is not True
        or verified.get("quantization_bits") != 4
        or not _SHA256.fullmatch(str(verified.get("runtime_model_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("file_manifest_sha256") or ""))
    ):
        raise RuntimeError("trusted_model_identity_invalid")
    verified["tracked_identity_file_sha256"] = _file_sha256(path)
    return verified


def load_trusted_toolchain_identity(project_root: Path) -> dict[str, Any]:
    """Load the tracked uv/Python/lock/package allowlist."""

    path = project_root / "config/completion_preflight_toolchain_identity.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("trusted_model_toolchain_identity_invalid") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("trusted_model_toolchain_identity_invalid")
    try:
        verified = verify_sealed_artifact(payload, schema=TRUSTED_TOOLCHAIN_IDENTITY_SCHEMA)
    except ValueError as exc:
        raise RuntimeError("trusted_model_toolchain_identity_invalid") from exc
    packages = verified.get("locked_packages")
    system_tools = verified.get("system_tools")
    if (
        not _SHA256.fullmatch(str(verified.get("uv_executable_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("python_executable_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("model_runtime_lock_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("model_runtime_pyproject_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("locked_package_set_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("installed_environment_manifest_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("base_python_runtime_manifest_sha256") or ""))
        or not _SHA256.fullmatch(str(verified.get("venv_control_manifest_sha256") or ""))
        or verified.get("launch_environment_policy_sha256") != LAUNCH_ENVIRONMENT_POLICY_SHA256
        or verified.get("python_major_minor") != "3.13"
        or not re.fullmatch(r"3\.13\.[0-9]+", str(verified.get("python_version_info") or ""))
        or not isinstance(packages, list)
        or not packages
        or not _SHA256.fullmatch(str(verified.get("system_tool_set_sha256") or ""))
        or not isinstance(system_tools, list)
        or not system_tools
    ):
        raise RuntimeError("trusted_model_toolchain_identity_invalid")
    normalized: list[dict[str, str]] = []
    for package in packages:
        if not isinstance(package, Mapping):
            raise RuntimeError("trusted_model_toolchain_identity_invalid")
        name = str(package.get("name") or "").casefold().replace("_", "-")
        version = str(package.get("version") or "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", name) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.+!-]{0,127}", version
        ):
            raise RuntimeError("trusted_model_toolchain_identity_invalid")
        normalized.append({"name": name, "version": version})
    if normalized != sorted(normalized, key=lambda item: item["name"]):
        raise RuntimeError("trusted_model_toolchain_identity_invalid")
    expected_package_digest = sealed_sha256(
        {
            "schema": "legalbot.completion-locked-package-set.v1",
            "packages": normalized,
        }
    )
    if expected_package_digest != verified["locked_package_set_sha256"]:
        raise RuntimeError("trusted_model_toolchain_identity_invalid")
    normalized_tools: list[dict[str, str]] = []
    for tool in system_tools:
        if not isinstance(tool, Mapping):
            raise RuntimeError("trusted_model_toolchain_identity_invalid")
        tool_id = str(tool.get("tool_id") or "")
        absolute_path = str(tool.get("system_location") or "")
        digest = str(tool.get("sha256") or "")
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", tool_id)
            or not Path(absolute_path).is_absolute()
            or not _SHA256.fullmatch(digest)
        ):
            raise RuntimeError("trusted_model_toolchain_identity_invalid")
        normalized_tools.append(
            {"tool_id": tool_id, "system_location": absolute_path, "sha256": digest}
        )
    if (
        normalized_tools != sorted(normalized_tools, key=lambda item: item["tool_id"])
        or platform.system() != "Darwin"
        or sealed_sha256(
            {
                "schema": "legalbot.completion-system-tool-set.v1",
                "platform": "Darwin",
                "tools": normalized_tools,
            }
        )
        != verified["system_tool_set_sha256"]
    ):
        raise RuntimeError("trusted_model_toolchain_identity_invalid")
    lock_path = project_root / "model-runtime/uv.lock"
    pyproject_path = project_root / "model-runtime/pyproject.toml"
    if (
        _file_sha256(lock_path) != verified["model_runtime_lock_sha256"]
        or _file_sha256(pyproject_path) != verified["model_runtime_pyproject_sha256"]
    ):
        raise RuntimeError("trusted_model_toolchain_identity_invalid")
    verified["tracked_identity_file_sha256"] = _file_sha256(path)
    return verified


def trusted_system_tool(tool_id: str, *, project_root: Path) -> Path:
    """Resolve one tracked root-owned OS helper without consulting ``PATH``."""

    trusted = load_trusted_toolchain_identity(project_root)
    records = {
        str(record["tool_id"]): record
        for record in cast(list[dict[str, str]], trusted["system_tools"])
    }
    record = records.get(tool_id)
    if record is None:
        raise RuntimeError("trusted_system_tool_missing")
    path = Path(record["system_location"])
    try:
        metadata = path.stat()
    except OSError as exc:
        raise RuntimeError("trusted_system_tool_missing") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or _file_sha256(path) != record["sha256"]
    ):
        raise RuntimeError("trusted_system_tool_identity_mismatch")
    return path


@dataclass(frozen=True, slots=True)
class VerifiedModelToolchain:
    """Exact executable and pre-installed locked environment admitted for launch."""

    uv_executable: Path
    python_executable: Path
    identity: Mapping[str, Any]
    installed_environment_manifest_sha256: str
    base_python_runtime_manifest_sha256: str
    venv_control_manifest_sha256: str
    system_tools: Mapping[str, Path]

    def safe_binding(self) -> dict[str, Any]:
        return {
            "trusted_toolchain_identity_sha256": self.identity["seal_sha256"],
            "uv_executable_sha256": self.identity["uv_executable_sha256"],
            "python_executable_sha256": self.identity["python_executable_sha256"],
            "model_runtime_lock_sha256": self.identity["model_runtime_lock_sha256"],
            "model_runtime_pyproject_sha256": self.identity["model_runtime_pyproject_sha256"],
            "locked_package_set_sha256": self.identity["locked_package_set_sha256"],
            "launch_environment_policy_sha256": self.identity["launch_environment_policy_sha256"],
            "installed_environment_manifest_sha256": (self.installed_environment_manifest_sha256),
            "base_python_runtime_manifest_sha256": (self.base_python_runtime_manifest_sha256),
            "venv_control_manifest_sha256": self.venv_control_manifest_sha256,
            "system_tool_set_sha256": self.identity["system_tool_set_sha256"],
        }


def _validate_ambient_model_launch_environment(environment: Mapping[str, str]) -> None:
    poisoned = sorted(
        name
        for name, value in environment.items()
        if value
        and (
            name in _FORBIDDEN_LAUNCH_ENVIRONMENT_NAMES
            or any(name.startswith(prefix) for prefix in _FORBIDDEN_LAUNCH_ENVIRONMENT_PREFIXES)
        )
    )
    if poisoned:
        raise RuntimeError("model_launch_environment_poisoned")


def _installed_package_inventory(environment_root: Path) -> tuple[list[dict[str, str]], str]:
    site_roots = tuple(environment_root.glob("lib/python3.13/site-packages"))
    if len(site_roots) != 1 or not site_roots[0].is_dir() or site_roots[0].is_symlink():
        raise RuntimeError("model_runtime_environment_invalid")
    site_root = site_roots[0]
    packages: list[dict[str, str]] = []
    verified_file_rows: list[dict[str, str | int]] = []
    covered_paths: dict[Path, tuple[str, int]] = {}
    for metadata_path in sorted(site_root.glob("*.dist-info/METADATA")):
        if metadata_path.is_symlink() or not metadata_path.is_file():
            raise RuntimeError("model_runtime_environment_invalid")
        name = version = ""
        for line in metadata_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("Name: ") and not name:
                name = line[6:].strip().casefold().replace("_", "-")
            elif line.startswith("Version: ") and not version:
                version = line[9:].strip()
            if name and version:
                break
        if not name or not version:
            raise RuntimeError("model_runtime_environment_invalid")
        record_path = metadata_path.parent / "RECORD"
        if record_path.is_symlink() or not record_path.is_file():
            raise RuntimeError("model_runtime_environment_invalid")
        packages.append({"name": name, "version": version})
        try:
            rows = list(csv.reader(record_path.read_text(encoding="utf-8").splitlines()))
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            raise RuntimeError("model_runtime_environment_invalid") from exc
        if not rows:
            raise RuntimeError("model_runtime_environment_invalid")
        record_self_seen = False
        for row in rows:
            if len(row) != 3 or not row[0]:
                raise RuntimeError("model_runtime_environment_invalid")
            relative = Path(row[0])
            if relative.is_absolute():
                raise RuntimeError("model_runtime_environment_invalid")
            unresolved = site_root / relative
            try:
                target = unresolved.resolve(strict=True)
                target.relative_to(environment_root.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise RuntimeError("model_runtime_environment_invalid") from exc
            if unresolved.is_symlink() or not target.is_file():
                raise RuntimeError("model_runtime_environment_invalid")
            target_relative = target.relative_to(environment_root.resolve(strict=True)).as_posix()
            if target == record_path.resolve(strict=True):
                if row[1] or row[2]:
                    raise RuntimeError("model_runtime_environment_invalid")
                record_self_seen = True
                observed_record = (_file_sha256(target), target.stat().st_size)
                previous = covered_paths.setdefault(target, observed_record)
                if previous != observed_record:
                    raise RuntimeError("model_runtime_installed_file_mismatch")
                verified_file_rows.append(
                    {
                        "path": target_relative,
                        "sha256": observed_record[0],
                        "size": observed_record[1],
                    }
                )
                continue
            if not row[1].startswith("sha256=") or not row[2].isdigit():
                raise RuntimeError("model_runtime_environment_invalid")
            encoded = row[1][len("sha256=") :]
            try:
                expected_digest = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            except (ValueError, TypeError) as exc:
                raise RuntimeError("model_runtime_environment_invalid") from exc
            if len(expected_digest) != 32:
                raise RuntimeError("model_runtime_environment_invalid")
            observed_digest = bytes.fromhex(_file_sha256(target))
            observed_size = target.stat().st_size
            if observed_digest != expected_digest or observed_size != int(row[2]):
                raise RuntimeError("model_runtime_installed_file_mismatch")
            observed_file = (observed_digest.hex(), observed_size)
            previous = covered_paths.setdefault(target, observed_file)
            if previous != observed_file:
                raise RuntimeError("model_runtime_installed_file_mismatch")
            verified_file_rows.append(
                {
                    "path": target_relative,
                    "sha256": observed_digest.hex(),
                    "size": observed_size,
                }
            )
        if not record_self_seen:
            raise RuntimeError("model_runtime_environment_invalid")
    packages.sort(key=lambda item: item["name"])
    if len({item["name"] for item in packages}) != len(packages):
        raise RuntimeError("model_runtime_environment_invalid")
    unaccounted = []
    for path in site_root.rglob("*"):
        if path.is_dir():
            continue
        if path.is_symlink():
            raise RuntimeError("model_runtime_environment_invalid")
        resolved = path.resolve(strict=True)
        if resolved in covered_paths:
            continue
        if path.suffix == ".pyc":
            raise RuntimeError("model_runtime_executable_bytecode_refused")
        # uv's virtualenv bootstrap is not a wheel distribution. Its exact
        # bytes are still included in the tracked package-tree seal below.
        if path.relative_to(site_root).as_posix() in {"_virtualenv.py", "_virtualenv.pth"}:
            unaccounted.append(
                {
                    "path": resolved.relative_to(environment_root.resolve(strict=True)).as_posix(),
                    "sha256": _file_sha256(resolved),
                    "size": resolved.stat().st_size,
                }
            )
            continue
        raise RuntimeError("model_runtime_unexpected_installed_file")
    manifest_sha256 = sealed_sha256(
        {
            "schema": "legalbot.completion-installed-model-environment.v2",
            "verified_files": sorted(
                [*verified_file_rows, *unaccounted], key=lambda item: str(item["path"])
            ),
        }
    )
    return packages, manifest_sha256


def _venv_control_manifest(
    environment_root: Path,
    *,
    expected_base_python: Path,
    expected_python_version: str,
    expected_uv_version: str,
) -> tuple[Path, str]:
    """Seal the venv selector that controls interpreter and import roots."""

    if environment_root.is_symlink() or not environment_root.is_dir():
        raise RuntimeError("model_runtime_environment_invalid")
    resolved_environment = environment_root.resolve(strict=True)
    config_path = resolved_environment / "pyvenv.cfg"
    if config_path.is_symlink() or not config_path.is_file():
        raise RuntimeError("model_runtime_venv_control_invalid")
    try:
        fields: dict[str, str] = {}
        for raw_line in config_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = raw_line.partition("=")
            if not separator or not key.strip() or key.strip() in fields:
                raise ValueError
            fields[key.strip()] = value.strip()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError("model_runtime_venv_control_invalid") from exc
    uv_match = re.fullmatch(r"uv ([0-9]+\.[0-9]+\.[0-9]+)(?: .*)?", expected_uv_version)
    expected_fields = {
        "home": str(expected_base_python.parent),
        "implementation": "CPython",
        "uv": uv_match.group(1) if uv_match is not None else "",
        "version_info": expected_python_version,
        "include-system-site-packages": "false",
        "prompt": "legalbot-model-runtime",
    }
    if fields != expected_fields:
        raise RuntimeError("model_runtime_venv_control_invalid")

    launcher_contract = (
        ("bin/python", str(expected_base_python), "base_python"),
        ("bin/python3", "python", "base_python"),
        ("bin/python3.13", "python", "base_python"),
    )
    launchers: list[dict[str, str | int]] = []
    for relative, expected_raw_target, target_code in launcher_contract:
        launcher = resolved_environment / relative
        try:
            metadata = launcher.lstat()
            raw_target = os.readlink(launcher)
            resolved_target = launcher.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("model_runtime_venv_launcher_invalid") from exc
        if (
            not launcher.is_symlink()
            or raw_target != expected_raw_target
            or resolved_target != expected_base_python
        ):
            raise RuntimeError("model_runtime_venv_launcher_invalid")
        launchers.append(
            {
                "path": relative,
                "raw_target_code": target_code if relative == "bin/python" else raw_target,
                "resolved_target_sha256": _file_sha256(resolved_target),
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
        )
    config_metadata = config_path.stat()
    manifest_sha256 = sealed_sha256(
        {
            "schema": "legalbot.completion-model-venv-control.v1",
            "pyvenv_config_sha256": _file_sha256(config_path),
            "pyvenv_config_size": config_metadata.st_size,
            "pyvenv_config_mode": stat.S_IMODE(config_metadata.st_mode),
            "pyvenv_config_uid": config_metadata.st_uid,
            "pyvenv_config_gid": config_metadata.st_gid,
            "include_system_site_packages": False,
            "python_version_info": expected_python_version,
            "launchers": launchers,
        }
    )
    return resolved_environment / "bin/python", manifest_sha256


def _base_python_runtime_manifest(runtime_root: Path) -> str:
    """Seal every non-wheel byte the admitted base interpreter can execute.

    The model virtualenv deliberately has no access to the base interpreter's
    ``site-packages`` and launches with a fresh private bytecode-cache prefix.
    Everything else that can participate in interpreter bootstrap or a stdlib
    import is included: the launcher, framework/shared libraries, stdlib
    source/data, extension modules, bundled frameworks, and code signature.
    Absolute host paths are never included in the safe digest.
    """

    try:
        resolved_root = runtime_root.resolve(strict=True)
    except OSError as exc:
        raise RuntimeError("base_python_runtime_invalid") from exc
    if resolved_root.is_symlink() or not resolved_root.is_dir():
        raise RuntimeError("base_python_runtime_invalid")

    required_files = (
        resolved_root / "Python",
        resolved_root / "bin/python3.13",
        resolved_root / "_CodeSignature/CodeResources",
    )
    required_trees = (
        resolved_root / "lib/python3.13",
        resolved_root / "Frameworks",
    )
    for path in (*required_files, *required_trees):
        if not path.exists():
            raise RuntimeError("base_python_runtime_invalid")

    selected: set[Path] = set(required_files)
    for tree in required_trees:
        selected.update(tree.rglob("*"))
    lib_root = resolved_root / "lib"
    selected.update(
        path
        for path in lib_root.iterdir()
        if path.is_symlink() or (path.is_file() and path.suffix == ".dylib")
    )

    rows: list[dict[str, str | int]] = []
    for path in sorted(selected, key=lambda value: value.as_posix()):
        try:
            relative = path.relative_to(resolved_root)
        except ValueError as exc:
            raise RuntimeError("base_python_runtime_invalid") from exc
        if "site-packages" in relative.parts or "__pycache__" in relative.parts:
            continue
        if relative.suffix == ".pyc":
            raise RuntimeError("base_python_runtime_executable_bytecode_refused")
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            raw_target = os.readlink(path)
            lexical_target = Path(os.path.normpath(str(path.parent / raw_target)))
            try:
                lexical_relative = lexical_target.relative_to(resolved_root).as_posix()
            except ValueError as exc:
                raise RuntimeError("base_python_runtime_external_link_refused") from exc
            try:
                resolved_target = path.resolve(strict=True)
                target_relative = resolved_target.relative_to(resolved_root).as_posix()
                target_state = "resolved_internal"
            except FileNotFoundError:
                target_relative = lexical_relative
                target_state = "broken_internal"
            except (OSError, ValueError) as exc:
                raise RuntimeError("base_python_runtime_external_link_refused") from exc
            rows.append(
                {
                    "kind": "symlink",
                    "path": relative.as_posix(),
                    "target": raw_target,
                    "resolved_target": target_relative,
                    "target_state": target_state,
                    "mode": mode,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            )
        elif path.is_file():
            rows.append(
                {
                    "kind": "file",
                    "path": relative.as_posix(),
                    "sha256": _file_sha256(path),
                    "size": metadata.st_size,
                    "mode": mode,
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            )
        elif not path.is_dir():
            raise RuntimeError("base_python_runtime_special_file_refused")
    import_zip = resolved_root / "lib/python313.zip"
    if import_zip.is_symlink() or (import_zip.exists() and not import_zip.is_file()):
        raise RuntimeError("base_python_runtime_import_zip_invalid")
    if import_zip.exists():
        zip_metadata = import_zip.stat()
        rows.append(
            {
                "kind": "file",
                "path": "lib/python313.zip",
                "sha256": _file_sha256(import_zip),
                "size": zip_metadata.st_size,
                "mode": stat.S_IMODE(zip_metadata.st_mode),
                "uid": zip_metadata.st_uid,
                "gid": zip_metadata.st_gid,
            }
        )
    else:
        rows.append({"kind": "absent", "path": "lib/python313.zip"})
    rows.sort(key=lambda row: str(row["path"]))
    required_relative = {path.relative_to(resolved_root).as_posix() for path in required_files}
    observed_files = {str(row["path"]) for row in rows if row.get("kind") == "file"}
    if not required_relative.issubset(observed_files) or len(rows) < 4:
        raise RuntimeError("base_python_runtime_invalid")
    return sealed_sha256(
        {
            "schema": "legalbot.completion-base-python-runtime-tree.v1",
            "python_major_minor": "3.13",
            "site_packages_included": False,
            "default_bytecode_cache_included": False,
            "private_bytecode_cache_required": True,
            "files": rows,
        }
    )


def resolve_verified_model_toolchain(
    project_root: Path,
    *,
    ambient_environment: Mapping[str, str] | None = None,
) -> VerifiedModelToolchain:
    """Resolve through PATH once, then pin/re-hash absolute executable bytes."""

    environment = dict(os.environ if ambient_environment is None else ambient_environment)
    _validate_ambient_model_launch_environment(environment)
    trusted = load_trusted_toolchain_identity(project_root)
    discovered = shutil.which("uv", path=environment.get("PATH", ""))
    if not discovered:
        raise RuntimeError("trusted_uv_executable_missing")
    uv_executable = Path(discovered).resolve(strict=True)
    if (
        not uv_executable.is_file()
        or _file_sha256(uv_executable) != trusted["uv_executable_sha256"]
    ):
        raise RuntimeError("trusted_uv_executable_mismatch")
    python_link = project_root / "model-runtime/.venv/bin/python"
    if not python_link.exists() or not python_link.is_file():
        raise RuntimeError("model_runtime_environment_missing")
    base_python_executable = python_link.resolve(strict=True)
    if (
        not base_python_executable.is_file()
        or _file_sha256(base_python_executable) != trusted["python_executable_sha256"]
    ):
        raise RuntimeError("trusted_python_executable_mismatch")
    runtime_root = base_python_executable.parent.parent
    if base_python_executable != runtime_root / "bin/python3.13":
        raise RuntimeError("base_python_runtime_invalid")
    base_runtime_manifest_sha256 = _base_python_runtime_manifest(runtime_root)
    if base_runtime_manifest_sha256 != trusted["base_python_runtime_manifest_sha256"]:
        raise RuntimeError("base_python_runtime_bytes_mismatch")
    packages, environment_manifest_sha256 = _installed_package_inventory(
        project_root / "model-runtime/.venv"
    )
    if packages != trusted["locked_packages"]:
        raise RuntimeError("model_runtime_locked_packages_mismatch")
    if environment_manifest_sha256 != trusted["installed_environment_manifest_sha256"]:
        raise RuntimeError("model_runtime_installed_bytes_mismatch")
    venv_python_executable, venv_control_manifest_sha256 = _venv_control_manifest(
        project_root / "model-runtime/.venv",
        expected_base_python=base_python_executable,
        expected_python_version=str(trusted["python_version_info"]),
        expected_uv_version=str(trusted["uv_version"]),
    )
    if venv_control_manifest_sha256 != trusted["venv_control_manifest_sha256"]:
        raise RuntimeError("model_runtime_venv_control_mismatch")
    system_tools = {
        record["tool_id"]: trusted_system_tool(record["tool_id"], project_root=project_root)
        for record in cast(list[dict[str, str]], trusted["system_tools"])
    }
    return VerifiedModelToolchain(
        uv_executable=uv_executable,
        python_executable=venv_python_executable,
        identity=trusted,
        installed_environment_manifest_sha256=environment_manifest_sha256,
        base_python_runtime_manifest_sha256=base_runtime_manifest_sha256,
        venv_control_manifest_sha256=venv_control_manifest_sha256,
        system_tools=system_tools,
    )


def trusted_model_toolchain_binding(
    project_root: Path,
    *,
    ambient_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Bind tracked expectations while refusing a PATH-shadowed uv binary."""

    environment = dict(os.environ if ambient_environment is None else ambient_environment)
    _validate_ambient_model_launch_environment(environment)
    trusted = load_trusted_toolchain_identity(project_root)
    discovered = shutil.which("uv", path=environment.get("PATH", ""))
    if not discovered:
        raise RuntimeError("trusted_uv_executable_missing")
    executable = Path(discovered).resolve(strict=True)
    if not executable.is_file() or _file_sha256(executable) != trusted["uv_executable_sha256"]:
        raise RuntimeError("trusted_uv_executable_mismatch")
    for record in cast(list[dict[str, str]], trusted["system_tools"]):
        trusted_system_tool(record["tool_id"], project_root=project_root)
    return {
        "trusted_toolchain_identity_sha256": str(trusted["seal_sha256"]),
        "uv_executable_sha256": str(trusted["uv_executable_sha256"]),
        "python_executable_sha256": str(trusted["python_executable_sha256"]),
        "model_runtime_lock_sha256": str(trusted["model_runtime_lock_sha256"]),
        "model_runtime_pyproject_sha256": str(trusted["model_runtime_pyproject_sha256"]),
        "locked_package_set_sha256": str(trusted["locked_package_set_sha256"]),
        "launch_environment_policy_sha256": str(trusted["launch_environment_policy_sha256"]),
        "installed_environment_manifest_sha256": str(
            trusted["installed_environment_manifest_sha256"]
        ),
        "base_python_runtime_manifest_sha256": str(trusted["base_python_runtime_manifest_sha256"]),
        "venv_control_manifest_sha256": str(trusted["venv_control_manifest_sha256"]),
        "system_tool_set_sha256": str(trusted["system_tool_set_sha256"]),
    }


def sanitized_model_launch_environment(
    *,
    project_root: Path,
    private_pycache_root: Path,
    launch_nonce: str,
    values: Mapping[str, str],
) -> dict[str, str]:
    """Construct the complete child environment; inherit no caller-controlled values."""

    isolated_model_python_arguments(
        project_root,
        private_pycache_root=private_pycache_root,
    )
    if not re.fullmatch(r"[0-9a-f]{64}", launch_nonce):
        raise RuntimeError("model_launch_nonce_invalid")
    permitted = {
        "LEGALBOT_MODEL_MODE",
        "LEGALBOT_MODEL_HOST",
        "LEGALBOT_MODEL_PORT",
        "LEGALBOT_MODEL_ID",
        "LEGALBOT_MODEL_REVISION",
        "LEGALBOT_MODEL_PATH",
        "LEGALBOT_MODEL_CONTEXT_TOKENS",
        "LEGALBOT_MODEL_MAX_OUTPUT_TOKENS",
        "LEGALBOT_MODEL_PREFILL_STEP_SIZE",
        "LEGALBOT_MODEL_KV_BITS",
        "LEGALBOT_MODEL_KV_GROUP_SIZE",
        "LEGALBOT_MODEL_CLEAR_CACHE",
    }
    if set(values) != permitted or any("\x00" in value for value in values.values()):
        raise RuntimeError("model_launch_environment_invalid")
    if private_pycache_root.exists():
        if private_pycache_root.is_symlink() or any(private_pycache_root.iterdir()):
            raise RuntimeError("model_launch_pycache_not_fresh")
    else:
        private_pycache_root.mkdir(parents=True, mode=0o700)
    private_pycache_root.chmod(0o700)
    return {
        **dict(values),
        "LEGALBOT_COMPLETION_LAUNCH_NONCE": launch_nonce,
        "TOKENIZERS_PARALLELISM": "false",
        "UV_OFFLINE": "1",
        "UV_LOCKED": "1",
        "UV_NO_SYNC": "1",
        "UV_NO_ENV_FILE": "1",
        "UV_NO_MANAGED_PYTHON": "1",
        "UV_NO_PYTHON_DOWNLOADS": "1",
    }


def isolated_model_python_arguments(
    project_root: Path,
    *,
    private_pycache_root: Path,
) -> tuple[str, ...]:
    """Return the exact isolated Python argv admitted by the tracked policy."""

    try:
        resolved_root = project_root.resolve(strict=True)
        backend_root = (resolved_root / "backend").resolve(strict=True)
        backend_root.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise RuntimeError("model_python_bootstrap_path_invalid") from exc
    entrypoint = backend_root / "app/model_runtime/__main__.py"
    if backend_root.is_symlink() or entrypoint.is_symlink() or not entrypoint.is_file():
        raise RuntimeError("model_python_bootstrap_path_invalid")
    if (
        not private_pycache_root.is_absolute()
        or "\x00" in str(private_pycache_root)
        or private_pycache_root.is_symlink()
    ):
        raise RuntimeError("model_launch_pycache_invalid")
    return (
        "-I",
        "-B",
        "-u",
        "-X",
        f"pycache_prefix={private_pycache_root}",
        "-c",
        MODEL_PYTHON_BOOTSTRAP,
        str(backend_root),
    )


class CompletionMemoryPolicy(BaseModel):
    """Owner-set, candidate/runtime-bound memory safety envelope.

    There is intentionally no default for either byte threshold.  Missing
    policy is an owner stop, never an inferred technical value.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.completion-memory-policy.v2"] = Field(
        default="legalbot.completion-memory-policy.v2", alias="schema"
    )
    policy_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    runtime_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    measurement_schema: Literal["legalbot.completion-memory-measurement.v2"] = (
        "legalbot.completion-memory-measurement.v2"
    )
    host_physical_memory_bytes: int = Field(ge=1)
    max_peak_combined_working_set_bytes: int = Field(ge=1)
    minimum_host_available_memory_bytes: int = Field(ge=1)
    owner_decision_id: str = Field(pattern=r"^v111-completion-memory-[0-9a-f]{20}$")
    owner_decision_request_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_decision_resolution_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    owner_selected_option_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    created_at: datetime
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="before")
    @classmethod
    def seal_and_envelope_are_valid(cls, value: Any) -> Any:
        if not isinstance(value, Mapping) or value.get("seal_sha256") != sealed_sha256(value):
            raise ValueError("completion memory policy seal mismatch")
        return value

    @model_validator(mode="after")
    def envelope_fits_bound_host(self) -> CompletionMemoryPolicy:
        if (
            self.max_peak_combined_working_set_bytes + self.minimum_host_available_memory_bytes
            > self.host_physical_memory_bytes
        ):
            raise ValueError("completion memory envelope exceeds its bound host")
        return self


class LoadedCompletionMemoryPolicy:
    """A policy admitted only through the private-file loader."""

    __slots__ = ("policy", "source_file_sha256")

    def __init__(
        self,
        *,
        policy: CompletionMemoryPolicy,
        source_file_sha256: str,
        token: object,
    ) -> None:
        if token is not _MEMORY_POLICY_LOAD_TOKEN or not _SHA256.fullmatch(source_file_sha256):
            raise RuntimeError("completion_memory_policy_not_loader_verified")
        self.policy = policy
        self.source_file_sha256 = source_file_sha256


def host_physical_memory_bytes() -> int:
    if platform.system() == "Darwin":
        try:
            completed = subprocess.run(
                [
                    str(trusted_system_tool("sysctl", project_root=_AUTHORITY_PROJECT_ROOT)),
                    "-n",
                    "hw.memsize",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
                env={"LC_ALL": "C"},
            )
            observed = int(completed.stdout.strip())
            if observed > 0:
                return observed
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    if platform.system() == "Linux":
        try:
            observed = int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
            if observed > 0:
                return observed
        except (OSError, ValueError):
            pass
    raise RuntimeError("host_memory_identity_unavailable")


def _read_owner_decision_artifact(
    path: Path,
    model: type[OwnerDecisionRequest] | type[OwnerDecisionResolution],
) -> OwnerDecisionRequest | OwnerDecisionResolution:
    try:
        value = json.loads(
            read_private_owner_decision_member(path.parents[1], path.parent.name, path.name).decode(
                "utf-8"
            )
        )
        return model.model_validate(value)
    except FileNotFoundError as exc:
        raise OwnerDecisionRequired("completion_memory_owner_resolution_missing") from exc
    except (OSError, RuntimeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("completion_memory_owner_decision_invalid") from exc


def load_completion_memory_policy(
    path: Path,
    *,
    owner_decision_root: Path,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
    integration_sha: str,
) -> LoadedCompletionMemoryPolicy:
    """Load an owner-private policy or stop with ``OWNER_DECISION_REQUIRED``."""

    if not path.exists():
        raise OwnerDecisionRequired("completion_memory_policy_missing")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("completion_memory_policy_storage_invalid")
    parent = path.parent
    if parent.is_symlink() or not parent.is_dir() or stat.S_IMODE(parent.stat().st_mode) != 0o700:
        raise RuntimeError("completion_memory_policy_storage_invalid")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                raise RuntimeError("completion_memory_policy_storage_invalid")
            policy_bytes = handle.read()
        raw = json.loads(policy_bytes.decode("utf-8"))
        policy = CompletionMemoryPolicy.model_validate(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("completion_memory_policy_invalid") from exc
    expected = (
        candidate.build_id,
        candidate.candidate_manifest_sha256,
        str(runtime_binding.get("seal_sha256") or ""),
        integration_sha,
    )
    observed = (
        policy.candidate_build_id,
        policy.candidate_manifest_sha256,
        policy.runtime_binding_sha256,
        policy.integration_sha,
    )
    if observed != expected:
        raise RuntimeError("completion_memory_policy_binding_mismatch")
    if policy.host_physical_memory_bytes != host_physical_memory_bytes():
        raise RuntimeError("completion_memory_policy_host_mismatch")
    host_memory = host_physical_memory_bytes()
    model_identity_file_sha256 = _file_sha256(
        _AUTHORITY_PROJECT_ROOT / "config/completion_preflight_model_identity.json"
    )
    toolchain_identity_file_sha256 = _file_sha256(
        _AUTHORITY_PROJECT_ROOT / "config/completion_preflight_toolchain_identity.json"
    )
    decision_id = completion_memory_decision_id(
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        runtime_binding_sha256=str(runtime_binding.get("seal_sha256") or ""),
        integration_sha=integration_sha,
        host_physical_memory_bytes=host_memory,
        trusted_model_identity_file_sha256=model_identity_file_sha256,
        trusted_toolchain_identity_file_sha256=toolchain_identity_file_sha256,
    )
    request_value = _read_owner_decision_artifact(
        owner_decision_root / decision_id / "request.json", OwnerDecisionRequest
    )
    resolution_value = _read_owner_decision_artifact(
        owner_decision_root / decision_id / "resolution.json",
        OwnerDecisionResolution,
    )
    if not isinstance(request_value, OwnerDecisionRequest) or not isinstance(
        resolution_value, OwnerDecisionResolution
    ):
        raise RuntimeError("completion_memory_owner_decision_invalid")
    try:
        resolution = require_owner_resolution(request_value, resolution_value)
    except PermissionError as exc:
        raise OwnerDecisionRequired("completion_memory_owner_resolution_missing") from exc
    request_options = {option.option_id: option for option in request_value.options}
    selected_thresholds = MEMORY_DECISION_OPTIONS.get(resolution.selected_option_id)
    expected_request = build_completion_memory_decision_request(
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        runtime_binding_sha256=str(runtime_binding.get("seal_sha256") or ""),
        integration_sha=integration_sha,
        host_physical_memory_bytes=host_memory,
        trusted_model_identity_file_sha256=model_identity_file_sha256,
        trusted_toolchain_identity_file_sha256=toolchain_identity_file_sha256,
        created_at=request_value.created_at,
    )
    if (
        request_value != expected_request
        or set(request_options) != set(MEMORY_DECISION_OPTIONS)
        or request_options["max-12884901888-min-3221225472"].recommended is not True
        or selected_thresholds is None
        or policy.owner_decision_id != request_value.decision_id
        or policy.owner_decision_request_seal_sha256 != request_value.seal_sha256
        or policy.owner_decision_resolution_seal_sha256 != resolution.seal_sha256
        or policy.owner_selected_option_id != resolution.selected_option_id
        or (
            policy.max_peak_combined_working_set_bytes,
            policy.minimum_host_available_memory_bytes,
        )
        != selected_thresholds
    ):
        raise RuntimeError("completion_memory_owner_decision_binding_mismatch")
    _verify_trusted_owner_memory_signature(request_value, resolution)
    return LoadedCompletionMemoryPolicy(
        policy=policy,
        source_file_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        token=_MEMORY_POLICY_LOAD_TOKEN,
    )


def _verify_trusted_owner_memory_signature(
    _request: OwnerDecisionRequest,
    _resolution: OwnerDecisionResolution,
) -> None:
    """Bootstrap seam; a self-sealed resolution is never memory authority."""

    raise OwnerDecisionRequired("trusted_owner_memory_signature_verifier_missing")


def _require_current_completion_memory_materialization(
    *,
    settings: Settings,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
    integration_sha: str,
    host_memory: int,
    model_identity_file_sha256: str,
    toolchain_identity_file_sha256: str,
) -> None:
    """Replay every mutable request input after signature and before policy write."""

    if settings.project_root.resolve(strict=True) != _AUTHORITY_PROJECT_ROOT.resolve(strict=True):
        raise RuntimeError("completion_memory_materializer_project_root_mismatch")
    if host_physical_memory_bytes() != host_memory:
        raise RuntimeError("completion_memory_materializer_host_changed")
    if (
        _file_sha256(settings.project_root / "config/completion_preflight_model_identity.json")
        != model_identity_file_sha256
        or _file_sha256(
            settings.project_root / "config/completion_preflight_toolchain_identity.json"
        )
        != toolchain_identity_file_sha256
    ):
        raise RuntimeError("completion_memory_materializer_identity_files_changed")
    reloaded_candidate = load_readonly_sealed_candidate(
        settings=settings,
        candidate_build_id=candidate.build_id,
    )
    if reloaded_candidate != candidate:
        raise RuntimeError("completion_memory_materializer_candidate_changed")
    from ..observability.live_metrics import load_slo_policy
    from .candidate_completion_runtime import build_local_completion_runtime_binding

    slo = load_slo_policy(settings.observability_slo_path)
    current_runtime_binding = build_local_completion_runtime_binding(
        settings=settings,
        candidate=reloaded_candidate,
        slo_policy_id=slo.policy_id,
        slo_policy_sha256=_file_sha256(settings.observability_slo_path),
        integration_sha=integration_sha,
    )
    if current_runtime_binding != runtime_binding:
        raise RuntimeError("completion_memory_materializer_runtime_changed")


def materialize_completion_memory_policy(
    *,
    settings: Settings,
    destination: Path,
    owner_decision_root: Path,
    candidate: SealedCandidateIdentity,
    runtime_binding: Mapping[str, Any],
    integration_sha: str,
    created_at: datetime,
) -> CompletionMemoryPolicy:
    """Create one exact policy only after the trusted owner-signature seam passes."""

    if candidate.status != "candidate":
        raise ValueError("completion memory materializer requires the sealed candidate")
    runtime_sha256 = str(runtime_binding.get("seal_sha256") or "")
    if runtime_sha256 != sealed_sha256(runtime_binding):
        raise ValueError("completion memory runtime binding is invalid")
    host_memory = host_physical_memory_bytes()
    model_identity_file_sha256 = _file_sha256(
        _AUTHORITY_PROJECT_ROOT / "config/completion_preflight_model_identity.json"
    )
    toolchain_identity_file_sha256 = _file_sha256(
        _AUTHORITY_PROJECT_ROOT / "config/completion_preflight_toolchain_identity.json"
    )
    decision_id = completion_memory_decision_id(
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        runtime_binding_sha256=runtime_sha256,
        integration_sha=integration_sha,
        host_physical_memory_bytes=host_memory,
        trusted_model_identity_file_sha256=model_identity_file_sha256,
        trusted_toolchain_identity_file_sha256=toolchain_identity_file_sha256,
    )
    request = _read_owner_decision_artifact(
        owner_decision_root / decision_id / "request.json", OwnerDecisionRequest
    )
    resolution = _read_owner_decision_artifact(
        owner_decision_root / decision_id / "resolution.json", OwnerDecisionResolution
    )
    if not isinstance(request, OwnerDecisionRequest) or not isinstance(
        resolution, OwnerDecisionResolution
    ):
        raise RuntimeError("completion_memory_owner_decision_invalid")
    expected_request = build_completion_memory_decision_request(
        candidate_build_id=candidate.build_id,
        candidate_manifest_sha256=candidate.candidate_manifest_sha256,
        runtime_binding_sha256=runtime_sha256,
        integration_sha=integration_sha,
        host_physical_memory_bytes=host_memory,
        trusted_model_identity_file_sha256=model_identity_file_sha256,
        trusted_toolchain_identity_file_sha256=toolchain_identity_file_sha256,
        created_at=request.created_at,
    )
    if request != expected_request:
        raise RuntimeError("completion_memory_owner_decision_binding_mismatch")
    try:
        verified = require_owner_resolution(request, resolution)
    except PermissionError as exc:
        raise OwnerDecisionRequired("completion_memory_owner_resolution_missing") from exc
    thresholds = MEMORY_DECISION_OPTIONS.get(verified.selected_option_id)
    if thresholds is None:
        raise RuntimeError("completion_memory_owner_decision_binding_mismatch")
    _verify_trusted_owner_memory_signature(request, verified)
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("completion memory policy timestamp must be timezone-aware")
    material: dict[str, Any] = {
        "schema": MEMORY_POLICY_SCHEMA,
        "policy_id": f"completion-memory-policy-{decision_id.rsplit('-', 1)[-1]}",
        "candidate_build_id": candidate.build_id,
        "candidate_manifest_sha256": candidate.candidate_manifest_sha256,
        "runtime_binding_sha256": runtime_sha256,
        "integration_sha": integration_sha,
        "measurement_schema": MEMORY_MEASUREMENT_SCHEMA,
        "host_physical_memory_bytes": host_memory,
        "max_peak_combined_working_set_bytes": thresholds[0],
        "minimum_host_available_memory_bytes": thresholds[1],
        "owner_decision_id": decision_id,
        "owner_decision_request_seal_sha256": request.seal_sha256,
        "owner_decision_resolution_seal_sha256": verified.seal_sha256,
        "owner_selected_option_id": verified.selected_option_id,
        "created_at": created_at.isoformat(),
    }
    material["seal_sha256"] = sealed_sha256(material)
    policy = CompletionMemoryPolicy.model_validate(material)
    _require_current_completion_memory_materialization(
        settings=settings,
        candidate=candidate,
        runtime_binding=runtime_binding,
        integration_sha=integration_sha,
        host_memory=host_memory,
        model_identity_file_sha256=model_identity_file_sha256,
        toolchain_identity_file_sha256=toolchain_identity_file_sha256,
    )
    require_exact_clean_head(settings.project_root, integration_sha)
    write_create_only_private_safe_json(
        destination,
        policy.model_dump(mode="json", by_alias=True),
    )
    return policy


def verify_launcher_attestation(
    value: Mapping[str, Any],
    *,
    schema: str,
    run_id: str,
    candidate: SealedCandidateIdentity,
    runtime_binding_sha256: str,
    integration_sha: str,
    trusted_model_identity_sha256: str | None = None,
    trusted_toolchain_identity_sha256: str | None = None,
    installed_environment_manifest_sha256: str | None = None,
    base_python_runtime_manifest_sha256: str | None = None,
    venv_control_manifest_sha256: str | None = None,
    launcher_implementation_sha256: str | None = None,
    verified_start_attestation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        payload = verify_sealed_artifact(value, schema=schema)
    except ValueError as exc:
        raise RuntimeError("production_launcher_attestation_invalid") from exc
    if (
        payload.get("run_id") != run_id
        or payload.get("candidate_build_id") != candidate.build_id
        or payload.get("candidate_manifest_sha256") != candidate.candidate_manifest_sha256
        or payload.get("runtime_binding_sha256") != runtime_binding_sha256
        or payload.get("local_only") is not True
        or payload.get("public_traffic_allowed") is not False
        or payload.get("writes_active") is not False
        or payload.get("writes_o04") is not False
        or payload.get("real_catalogue_write_count") != 0
    ):
        raise RuntimeError("production_launcher_attestation_invalid")
    if schema == LAUNCHER_START_SCHEMA:
        if (
            payload.get("integration_sha_start") != integration_sha
            or payload.get("trusted_model_identity_sha256") != trusted_model_identity_sha256
            or payload.get("trusted_toolchain_identity_sha256") != trusted_toolchain_identity_sha256
            or not _SHA256.fullmatch(installed_environment_manifest_sha256 or "")
            or payload.get("installed_environment_manifest_sha256")
            != installed_environment_manifest_sha256
            or payload.get("base_python_runtime_manifest_sha256")
            != base_python_runtime_manifest_sha256
            or payload.get("base_python_runtime_rehashed_before_launch") is not True
            or payload.get("venv_control_manifest_sha256") != venv_control_manifest_sha256
            or payload.get("venv_control_rehashed_before_launch") is not True
            or payload.get("model_toolchain_rehashed_before_launch") is not True
            or payload.get("offline_locked_no_sync_launch") is not True
            or payload.get("child_environment_sanitized") is not True
            or payload.get("direct_verified_venv_python_launch") is not True
            or payload.get("candidate_copy_on_write") is not True
            or payload.get("candidate_copy_read_only") is not True
            or not _SHA256.fullmatch(str(payload.get("isolated_candidate_tree_sha256") or ""))
            or payload.get("isolated_candidate_reverified_before_launch") is not True
            or payload.get("evaluation_database_isolated") is not True
            or payload.get("runtime_objects_isolated") is not True
            or payload.get("retrieval_candidate_pinned") is not True
            or payload.get("model_artifact_rehashed_before_launch") is not True
            or payload.get("launcher_implementation_sha256") != launcher_implementation_sha256
        ):
            raise RuntimeError("production_launcher_attestation_invalid")
    elif schema == LAUNCHER_END_SCHEMA:
        start = verified_start_attestation
        if (
            not isinstance(start, Mapping)
            or start.get("schema") != LAUNCHER_START_SCHEMA
            or start.get("run_id") != run_id
            or start.get("candidate_build_id") != candidate.build_id
            or start.get("runtime_binding_sha256") != runtime_binding_sha256
            or payload.get("integration_sha_start") != integration_sha
            or payload.get("integration_sha_end") != integration_sha
            or payload.get("git_sha_unchanged") is not True
            or payload.get("git_worktree_clean_start_end") is not True
            or payload.get("real_catalogue_unchanged") is not True
            or payload.get("candidate_unchanged") is not True
            or payload.get("isolated_candidate_tree_unchanged") is not True
            or payload.get("isolated_candidate_reverified_after_run") is not True
            or payload.get("isolated_candidate_tree_sha256_start")
            != payload.get("isolated_candidate_tree_sha256_end")
            or not _SHA256.fullmatch(str(payload.get("isolated_candidate_tree_sha256_end") or ""))
            or payload.get("active_pointer_unchanged") is not True
            or payload.get("evaluation_database_isolated") is not True
            or payload.get("runtime_objects_isolated") is not True
            or payload.get("model_artifact_rehashed_after_run") is not True
            or payload.get("trusted_model_identity_sha256") != trusted_model_identity_sha256
            or payload.get("trusted_toolchain_identity_sha256") != trusted_toolchain_identity_sha256
            or not _SHA256.fullmatch(installed_environment_manifest_sha256 or "")
            or payload.get("installed_environment_manifest_sha256")
            != installed_environment_manifest_sha256
            or payload.get("installed_environment_manifest_sha256")
            != start.get("installed_environment_manifest_sha256")
            or payload.get("base_python_runtime_manifest_sha256")
            != base_python_runtime_manifest_sha256
            or payload.get("base_python_runtime_rehashed_after_run") is not True
            or payload.get("venv_control_manifest_sha256") != venv_control_manifest_sha256
            or payload.get("venv_control_rehashed_after_run") is not True
            or payload.get("model_toolchain_rehashed_after_run") is not True
            or payload.get("isolated_candidate_tree_sha256_start")
            != start.get("isolated_candidate_tree_sha256")
            or payload.get("real_catalogue_data_version_start")
            != start.get("real_catalogue_data_version_start")
            or payload.get("real_catalogue_data_version_start")
            != payload.get("real_catalogue_data_version_end")
            or payload.get("real_catalogue_outbox_sha256_start")
            != start.get("real_catalogue_outbox_sha256_start")
            or payload.get("real_catalogue_outbox_sha256_start")
            != payload.get("real_catalogue_outbox_sha256_end")
            or payload.get("active_pointer_present_start")
            != start.get("active_pointer_present_start")
            or payload.get("active_pointer_present_start")
            != payload.get("active_pointer_present_end")
            or payload.get("active_pointer_sha256_start")
            != start.get("active_pointer_sha256_start")
            or payload.get("active_pointer_sha256_start")
            != payload.get("active_pointer_sha256_end")
        ):
            raise RuntimeError("production_launcher_attestation_invalid")
    else:
        raise RuntimeError("production_launcher_attestation_invalid")
    return payload


def listener_belongs_to_launch(
    *,
    launched_pid: int,
    listener_pids: Sequence[int],
    parent_by_pid: Mapping[int, int],
    nonce_matching_pids: frozenset[int],
) -> bool:
    """Require every listener to be a nonce-bearing child of this exact launch."""

    if launched_pid < 1 or not listener_pids:
        return False
    for listener_pid in listener_pids:
        if listener_pid < 1 or listener_pid not in nonce_matching_pids:
            return False
        current = listener_pid
        visited: set[int] = set()
        while current not in visited and current > 0:
            if current == launched_pid:
                break
            visited.add(current)
            current = int(parent_by_pid.get(current, 0))
        else:
            return False
        if current != launched_pid:
            return False
    return True


def listener_endpoints_are_loopback(endpoints: Sequence[str], *, port: int) -> bool:
    if not endpoints:
        return False
    for endpoint in endpoints:
        address, separator, observed_port = endpoint.rpartition(":")
        address = address.strip("[]")
        if not separator or observed_port != str(port) or address not in {"127.0.0.1", "::1"}:
            return False
    return True


def _listener_records(port: int) -> tuple[tuple[int, str], ...]:
    command = str(trusted_system_tool("lsof", project_root=_AUTHORITY_PROJECT_ROOT))
    try:
        completed = subprocess.run(
            [command, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fpn"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("model_socket_owner_unverifiable") from exc
    if completed.returncode not in {0, 1}:
        raise RuntimeError("model_socket_owner_unverifiable")
    output: list[tuple[int, str]] = []
    current_pid: int | None = None
    for line in completed.stdout.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current_pid = int(line[1:])
        elif line.startswith("n") and current_pid is not None:
            output.append((current_pid, line[1:]))
        elif line:
            raise RuntimeError("model_socket_owner_unverifiable")
    return tuple(sorted(set(output)))


def _parent_process_map() -> dict[int, int]:
    try:
        completed = subprocess.run(
            [
                str(trusted_system_tool("ps", project_root=_AUTHORITY_PROJECT_ROOT)),
                "-axo",
                "pid=,ppid=",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("model_socket_owner_unverifiable") from exc
    output: dict[int, int] = {}
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and all(field.isdigit() for field in fields):
            output[int(fields[0])] = int(fields[1])
    return output


def _process_has_launch_nonce(pid: int, nonce: str) -> bool:
    marker = f"LEGALBOT_COMPLETION_LAUNCH_NONCE={nonce}"
    if platform.system() == "Linux":
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError:
            return False
        return marker.encode() in raw.split(b"\0")
    try:
        completed = subprocess.run(
            [
                str(trusted_system_tool("ps", project_root=_AUTHORITY_PROJECT_ROOT)),
                "eww",
                "-p",
                str(pid),
                "-o",
                "command=",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # The command line is examined in memory only and never included in an artifact.
    return marker in completed.stdout.split()


def attest_owned_listener(*, launched_pid: int, port: int, nonce: str) -> str:
    listener_records = _listener_records(port)
    listeners = tuple(sorted({pid for pid, _ in listener_records}))
    endpoints = tuple(endpoint for _, endpoint in listener_records)
    if not listener_endpoints_are_loopback(endpoints, port=port):
        raise RuntimeError("model_listener_not_exclusively_loopback")
    parents = _parent_process_map()
    nonce_matches = frozenset(pid for pid in listeners if _process_has_launch_nonce(pid, nonce))
    if not listener_belongs_to_launch(
        launched_pid=launched_pid,
        listener_pids=listeners,
        parent_by_pid=parents,
        nonce_matching_pids=nonce_matches,
    ):
        raise RuntimeError("model_socket_owner_unverifiable")
    return sealed_sha256(
        {
            "schema": "legalbot.completion-owned-listener-proof.v1",
            "launched_pid_nonce_sha256": hashlib.sha256(
                f"{launched_pid}:{nonce}".encode()
            ).hexdigest(),
            "listener_pid_nonce_sha256s": [
                hashlib.sha256(f"{pid}:{nonce}".encode()).hexdigest() for pid in listeners
            ],
            "listener_count": len(listeners),
            "listener_endpoint_sha256s": [
                hashlib.sha256(endpoint.encode()).hexdigest() for endpoint in endpoints
            ],
            "exclusive_loopback_listener": True,
            "loopback_port": port,
        }
    )


def current_process_rss_bytes() -> int:
    if platform.system() == "Linux":
        try:
            resident_pages = int(Path("/proc/self/statm").read_text().split()[1])
            return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError):
            pass
    try:
        completed = subprocess.run(
            [
                str(trusted_system_tool("ps", project_root=_AUTHORITY_PROJECT_ROOT)),
                "-o",
                "rss=",
                "-p",
                str(os.getpid()),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C"},
        )
        return int(completed.stdout.strip()) * 1024
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise RuntimeError("memory_measurement_unavailable") from exc


def _process_rss_rows(*, ps_path: Path | None = None) -> tuple[tuple[int, int, int], ...]:
    """Return PID, PPID and RSS bytes; ``ps rss`` is KiB on macOS and Linux."""

    try:
        completed = subprocess.run(
            [
                str(
                    ps_path
                    if ps_path is not None
                    else trusted_system_tool("ps", project_root=_AUTHORITY_PROJECT_ROOT)
                ),
                "-axo",
                "pid=,ppid=,rss=",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("memory_measurement_unavailable") from exc
    rows: list[tuple[int, int, int]] = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or not all(field.isdigit() for field in fields):
            continue
        rows.append((int(fields[0]), int(fields[1]), int(fields[2]) * 1024))
    if not rows:
        raise RuntimeError("memory_measurement_unavailable")
    return tuple(rows)


def _process_memory_snapshot(
    *, nonce: str, ps_path: Path
) -> tuple[tuple[tuple[int, int, int], ...], frozenset[int]]:
    """Collect RSS, ancestry and nonce evidence with one trusted ``ps`` call."""

    try:
        completed = subprocess.run(
            [str(ps_path), "eww", "-axo", "pid=,ppid=,rss=,command="],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("memory_measurement_unavailable") from exc
    marker = f"LEGALBOT_COMPLETION_LAUNCH_NONCE={nonce}"
    rows: list[tuple[int, int, int]] = []
    nonce_matches: set[int] = set()
    for line in completed.stdout.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) < 3 or not all(field.isdigit() for field in fields[:3]):
            continue
        pid, ppid, rss_kib = (int(field) for field in fields[:3])
        rows.append((pid, ppid, rss_kib * 1024))
        if len(fields) == 4 and marker in fields[3].split():
            nonce_matches.add(pid)
    if not rows:
        raise RuntimeError("memory_measurement_unavailable")
    return tuple(rows), frozenset(nonce_matches)


def owned_process_tree_rss_bytes(
    *,
    launched_pid: int,
    rows: Sequence[tuple[int, int, int]],
    nonce_matching_pids: frozenset[int],
) -> int:
    by_pid = {pid: (ppid, rss_bytes) for pid, ppid, rss_bytes in rows}
    if launched_pid not in by_pid:
        raise RuntimeError("owned_sidecar_process_missing")
    owned = {launched_pid}
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _) in by_pid.items():
            if ppid in owned and pid not in owned:
                owned.add(pid)
                changed = True
    if not owned.issubset(nonce_matching_pids):
        raise RuntimeError("owned_sidecar_nonce_mismatch")
    total = sum(by_pid[pid][1] for pid in owned)
    if total < 1:
        raise RuntimeError("memory_measurement_unavailable")
    return total


def owned_sidecar_rss_bytes(*, launched_pid: int, nonce: str) -> int:
    rows = _process_rss_rows()
    parent_by_pid = {pid: ppid for pid, ppid, _ in rows}
    candidate_pids = {
        pid
        for pid, _, _ in rows
        if pid == launched_pid or _is_process_descendant(pid, launched_pid, parent_by_pid)
    }
    nonce_matches = frozenset(
        pid for pid in candidate_pids if _process_has_launch_nonce(pid, nonce)
    )
    return owned_process_tree_rss_bytes(
        launched_pid=launched_pid,
        rows=rows,
        nonce_matching_pids=nonce_matches,
    )


def _is_process_descendant(pid: int, ancestor: int, parent_by_pid: Mapping[int, int]) -> bool:
    current = pid
    visited: set[int] = set()
    while current > 0 and current not in visited:
        if current == ancestor:
            return True
        visited.add(current)
        current = int(parent_by_pid.get(current, 0))
    return False


def host_available_memory_bytes(*, vm_stat_path: Path | None = None) -> int:
    if platform.system() == "Linux":
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
    if platform.system() == "Darwin":
        try:
            completed = subprocess.run(
                [
                    str(
                        vm_stat_path
                        if vm_stat_path is not None
                        else trusted_system_tool("vm_stat", project_root=_AUTHORITY_PROJECT_ROOT)
                    )
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
                env={"LC_ALL": "C"},
            )
            header, *lines = completed.stdout.splitlines()
            match = re.search(r"page size of ([0-9]+) bytes", header)
            if match is None:
                raise ValueError
            pages: dict[str, int] = {}
            for line in lines:
                key, separator, value = line.partition(":")
                if separator:
                    pages[key] = int(value.strip().rstrip("."))
            available_pages = sum(
                pages.get(key, 0) for key in ("Pages free", "Pages inactive", "Pages speculative")
            )
            if available_pages > 0:
                return available_pages * int(match.group(1))
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    raise RuntimeError("memory_measurement_unavailable")


class WorkflowMemorySampler:
    """Sample distinct controller/owned-sidecar RSS with explicit precision."""

    def __init__(
        self,
        *,
        owned_sidecar_pid: int,
        launch_nonce: str,
        owned_listener_proof_sha256: str | None = None,
        phase: Literal["startup", "workflow"] = "workflow",
        interval_seconds: float = MEMORY_SAMPLE_INTERVAL_SECONDS,
        system_tools: Mapping[str, Path] | None = None,
    ) -> None:
        if (
            owned_sidecar_pid < 1
            or (
                owned_listener_proof_sha256 is not None
                and not _SHA256.fullmatch(owned_listener_proof_sha256)
            )
            or not re.fullmatch(r"[0-9a-f]{64}", launch_nonce)
            or interval_seconds <= 0
            or interval_seconds > MEMORY_SAMPLE_INTERVAL_SECONDS
        ):
            raise RuntimeError("memory_measurement_identity_invalid")
        self.owned_sidecar_pid = owned_sidecar_pid
        self.launch_nonce = launch_nonce
        self.owned_listener_proof_sha256 = owned_listener_proof_sha256
        self.phase = phase
        self.interval_seconds = interval_seconds
        self.system_tools = dict(system_tools or {})
        if set(self.system_tools) and not {"ps", "vm_stat"}.issubset(self.system_tools):
            raise RuntimeError("memory_measurement_tool_identity_invalid")
        self.controller_peak_rss_bytes = 0
        self.sidecar_peak_rss_bytes = 0
        self.peak_combined_working_set_bytes = 0
        self.minimum_host_available_memory_bytes: int | None = None
        self.sample_count = 0
        self.maximum_observed_sample_interval_seconds = 0.0
        self.maximum_sampling_jitter_seconds = 0.0
        self._last_sample_monotonic: float | None = None
        self._stop = False

    def sample(self) -> None:
        sampled_at = time.monotonic()
        ps_path = self.system_tools.get("ps") or trusted_system_tool(
            "ps", project_root=_AUTHORITY_PROJECT_ROOT
        )
        rows, nonce_matches = _process_memory_snapshot(nonce=self.launch_nonce, ps_path=ps_path)
        by_pid = {pid: rss for pid, _, rss in rows}
        controller = by_pid.get(os.getpid())
        if controller is None:
            raise RuntimeError("memory_measurement_unavailable")
        sidecar = owned_process_tree_rss_bytes(
            launched_pid=self.owned_sidecar_pid,
            rows=rows,
            nonce_matching_pids=nonce_matches,
        )
        available = host_available_memory_bytes(vm_stat_path=self.system_tools.get("vm_stat"))
        self.controller_peak_rss_bytes = max(self.controller_peak_rss_bytes, controller)
        self.sidecar_peak_rss_bytes = max(self.sidecar_peak_rss_bytes, sidecar)
        self.peak_combined_working_set_bytes = max(
            self.peak_combined_working_set_bytes, controller + sidecar
        )
        self.sample_count += 1
        if self._last_sample_monotonic is not None:
            observed_interval = sampled_at - self._last_sample_monotonic
            self.maximum_observed_sample_interval_seconds = max(
                self.maximum_observed_sample_interval_seconds, observed_interval
            )
            self.maximum_sampling_jitter_seconds = max(
                self.maximum_sampling_jitter_seconds,
                max(0.0, observed_interval - self.interval_seconds),
            )
        self._last_sample_monotonic = sampled_at
        if self.minimum_host_available_memory_bytes is None:
            self.minimum_host_available_memory_bytes = available
        else:
            self.minimum_host_available_memory_bytes = min(
                self.minimum_host_available_memory_bytes, available
            )

    async def run(self) -> None:
        import asyncio

        next_deadline = time.monotonic()
        while not self._stop:
            await asyncio.to_thread(self.sample)
            next_deadline += self.interval_seconds
            await asyncio.sleep(max(0.0, next_deadline - time.monotonic()))

    def stop(self) -> None:
        self._stop = True


def load_readonly_sealed_candidate(
    *, settings: Settings, candidate_build_id: str
) -> SealedCandidateIdentity:
    """Verify a candidate without opening the real catalogue in writable mode."""

    catalogue = open_existing_catalogue_read_database(settings.database_path)
    try:
        return load_sealed_candidate_identity(
            settings=settings,
            database=catalogue,  # type: ignore[arg-type]
            candidate_build_id=candidate_build_id,
        )
    finally:
        catalogue.close()


def _outbox_digest(catalogue: ExistingCatalogueReadDatabase) -> str:
    rows = catalogue.fetchall(
        """SELECT id,job_id,answer_id,release_state,idempotency_key,status,
                  created_at,published_at FROM release_outbox ORDER BY id"""
    )
    return sealed_sha256(
        {
            "schema": "legalbot.release-outbox-snapshot.v1",
            "rows": [dict(row) for row in rows],
        }
    )


def _pointer_snapshot(index_dir: Path) -> tuple[bool, str | None]:
    path = index_dir / "ACTIVE.json"
    if not path.exists():
        return False, None
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("active_pointer_storage_invalid")
    return True, _file_sha256(path)


def _create_private_directory(path: Path) -> None:
    if path.exists():
        raise FileExistsError("completion preflight isolation directory already exists")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.mkdir(mode=0o700)


def write_create_only_private_safe_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Write one sealed/safe runtime checkpoint without overwrite semantics."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    if path.parent.is_symlink() or path.is_symlink():
        raise RuntimeError("private_checkpoint_storage_invalid")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(safe_json_bytes(payload))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    path.chmod(0o600)


def _sqlite_backup_create_only(source: ExistingCatalogueReadDatabase, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    target = sqlite3.connect(destination)
    try:
        source.backup(target)
        target.commit()
    finally:
        target.close()
    destination.chmod(0o600)


def _copy_tree_reflink_only(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir() or destination.exists():
        raise RuntimeError("candidate_isolation_source_invalid")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if platform.system() == "Darwin":
        command = [
            str(trusted_system_tool("cp", project_root=_AUTHORITY_PROJECT_ROOT)),
            "-cR",
            str(source),
            str(destination),
        ]
    elif platform.system() == "Linux":
        command = [
            str(trusted_system_tool("cp", project_root=_AUTHORITY_PROJECT_ROOT)),
            "-a",
            "--reflink=always",
            str(source),
            str(destination),
        ]
    else:
        raise RuntimeError("candidate_copy_on_write_unavailable")
    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            timeout=1800,
            env={"LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("candidate_copy_on_write_unavailable") from exc


def _make_tree_read_only(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("candidate_isolation_source_invalid")
    for current_root, directories, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(current_root)
        for name in files:
            path = current / name
            if path.is_symlink():
                raise RuntimeError("candidate_isolation_symlink_refused")
            path.chmod(0o400)
        for name in directories:
            path = current / name
            if path.is_symlink():
                raise RuntimeError("candidate_isolation_symlink_refused")
            path.chmod(0o500)
        current.chmod(0o500)


def candidate_tree_sha256(root: Path) -> str:
    """Hash every isolated retrieval byte and reject links or writable members."""

    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("isolated_candidate_tree_invalid")
    records: list[dict[str, str | int]] = []
    for current_root, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        current = Path(current_root)
        if current.is_symlink() or stat.S_IMODE(current.stat().st_mode) & 0o222:
            raise RuntimeError("isolated_candidate_tree_mutation_detected")
        for name in sorted(directories):
            path = current / name
            if path.is_symlink():
                raise RuntimeError("isolated_candidate_tree_invalid")
        for name in sorted(files):
            path = current / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("isolated_candidate_tree_invalid")
            metadata = path.stat()
            if stat.S_IMODE(metadata.st_mode) & 0o222:
                raise RuntimeError("isolated_candidate_tree_mutation_detected")
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": metadata.st_size,
                    "sha256": _file_sha256(path),
                }
            )
    if not records:
        raise RuntimeError("isolated_candidate_tree_invalid")
    return sealed_sha256({"schema": "legalbot.isolated-candidate-tree.v1", "files": records})


class IsolatedEvaluationSettings:
    """Delegate immutable configuration while redirecting every runtime write."""

    def __init__(self, base: Settings, root: Path) -> None:
        self._base = base
        self._root = root

    def __getattr__(self, name: str) -> Any:
        return getattr(self._base, name)

    @property
    def data_dir(self) -> Path:
        return self._root / "data"

    @property
    def database_path(self) -> Path:
        return self._root / "evaluation-catalog.sqlite3"

    @property
    def index_dir(self) -> Path:
        return self._root / "indexes"

    @property
    def answer_dir(self) -> Path:
        return self.data_dir / "answers"

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def gap_queue_dir(self) -> Path:
        return self.data_dir / "review_queue/gaps"

    @property
    def runtime_object_dir(self) -> Path:
        return self.data_dir / "runtime_objects"

    @property
    def retrieval_cache_dir(self) -> Path:
        return self.data_dir / "retrieval_cache"

    @property
    def logs_dir(self) -> Path:
        return self._root / "logs"

    @property
    def operational_events_dir(self) -> Path:
        return self.logs_dir / "events"

    @property
    def operational_metrics_dir(self) -> Path:
        return self.logs_dir / "metrics"

    @property
    def operational_traces_dir(self) -> Path:
        return self.logs_dir / "traces"

    def ensure_runtime_dirs(self) -> None:
        for path in (
            self.data_dir,
            self.index_dir,
            self.answer_dir,
            self.upload_dir,
            self.gap_queue_dir,
            self.runtime_object_dir,
            self.retrieval_cache_dir,
            self.logs_dir,
            self.operational_events_dir,
            self.operational_metrics_dir,
            self.operational_traces_dir,
        ):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)


@dataclass(slots=True)
class CompletionIsolation:
    """One real-catalogue guard plus one mutable private evaluation copy."""

    base_settings: Settings
    settings: IsolatedEvaluationSettings
    candidate: SealedCandidateIdentity
    run_id: str
    root: Path
    real_catalogue: ExistingCatalogueReadDatabase
    database: Database
    integration_sha: str
    initial_data_version: int
    initial_total_changes: int
    initial_outbox_sha256: str
    initial_active_present: bool
    initial_active_sha256: str | None
    initial_eval_database_sha256: str
    initial_isolated_candidate_tree_sha256: str
    _verified_end: dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        *,
        base_settings: Settings,
        candidate: SealedCandidateIdentity,
        run_id: str,
        root: Path,
        integration_sha: str,
    ) -> CompletionIsolation:
        if not _SAFE_ID.fullmatch(run_id) or not _GIT_SHA.fullmatch(integration_sha):
            raise ValueError("completion isolation identity is invalid")
        allowed_root = (base_settings.evaluation_dir / "completion-preflight-runtime").resolve(
            strict=False
        )
        requested = root.resolve(strict=False)
        try:
            relative = requested.relative_to(allowed_root)
        except ValueError as exc:
            raise ValueError("completion isolation must use the private evaluation root") from exc
        if (
            root.name != run_id
            or len(relative.parts) != 2
            or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", relative.parts[0])
        ):
            raise ValueError("completion isolation path contract is invalid")
        _create_private_directory(root)
        real = open_existing_catalogue_read_database(base_settings.database_path)
        database: Database | None = None
        try:
            observed = load_sealed_candidate_identity(
                settings=base_settings,
                database=real,  # type: ignore[arg-type]
                candidate_build_id=candidate.build_id,
            )
            if observed != candidate:
                raise RuntimeError("candidate_identity_mismatch")
            data_version = int(real.fetchone("PRAGMA data_version")[0])  # type: ignore[index]
            total_changes = real.total_changes()
            outbox_sha256 = _outbox_digest(real)
            active_present, active_sha256 = _pointer_snapshot(base_settings.index_dir)

            isolated = IsolatedEvaluationSettings(base_settings, root)
            isolated.ensure_runtime_dirs()
            _sqlite_backup_create_only(real, isolated.database_path)
            initial_eval_sha256 = _file_sha256(isolated.database_path)

            source_build = base_settings.index_dir / "builds" / candidate.build_id
            target_build = isolated.index_dir / "builds" / candidate.build_id
            _copy_tree_reflink_only(source_build, target_build)
            isolated_seal_path = target_build / "seal.json"
            if isolated_seal_path.is_symlink() or not isolated_seal_path.is_file():
                raise RuntimeError("candidate_isolation_source_invalid")
            try:
                seal = json.loads(isolated_seal_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("candidate_isolation_source_invalid") from exc
            parent_id = str(seal.get("parent_vector_build_id") or "")
            if parent_id:
                if not _SAFE_ID.fullmatch(parent_id):
                    raise RuntimeError("candidate_isolation_source_invalid")
                source_parent_seal = base_settings.index_dir / "builds" / parent_id / "seal.json"
                if source_parent_seal.is_symlink() or not source_parent_seal.is_file():
                    raise RuntimeError("candidate_isolation_source_invalid")
                target_parent = isolated.index_dir / "builds" / parent_id
                target_parent.mkdir(parents=True, mode=0o700)
                destination = target_parent / "seal.json"
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(source_parent_seal.read_bytes())
            _make_tree_read_only(target_build)
            if parent_id:
                _make_tree_read_only(isolated.index_dir / "builds" / parent_id)
            (isolated.index_dir / "builds").chmod(0o500)
            isolated_tree_sha256 = candidate_tree_sha256(isolated.index_dir / "builds")

            database = Database(isolated.database_path)
            relative_build_path = str(
                target_build.resolve().relative_to(base_settings.project_root.resolve())
            )
            database.execute(
                "UPDATE index_builds SET path=? WHERE id=?",
                (relative_build_path, candidate.build_id),
            )
            isolated_observed = load_sealed_candidate_identity(
                settings=isolated,  # type: ignore[arg-type]
                database=database,
                candidate_build_id=candidate.build_id,
            )
            if isolated_observed != candidate:
                raise RuntimeError("candidate_identity_mismatch")
            return cls(
                base_settings=base_settings,
                settings=isolated,
                candidate=candidate,
                run_id=run_id,
                root=root,
                real_catalogue=real,
                database=database,
                integration_sha=integration_sha,
                initial_data_version=data_version,
                initial_total_changes=total_changes,
                initial_outbox_sha256=outbox_sha256,
                initial_active_present=active_present,
                initial_active_sha256=active_sha256,
                initial_eval_database_sha256=initial_eval_sha256,
                initial_isolated_candidate_tree_sha256=isolated_tree_sha256,
            )
        except Exception:
            if database is not None:
                database.close()
            real.close()
            raise

    def start_attestation(
        self,
        *,
        runtime_binding_sha256: str,
        launcher_implementation_sha256: str,
        trusted_model_identity_sha256: str,
        trusted_toolchain_identity_sha256: str,
        installed_environment_manifest_sha256: str,
        base_python_runtime_manifest_sha256: str,
        venv_control_manifest_sha256: str,
    ) -> dict[str, Any]:
        return sealed_safe_payload(
            {
                "schema": LAUNCHER_START_SCHEMA,
                "run_id": self.run_id,
                "candidate_build_id": self.candidate.build_id,
                "candidate_manifest_sha256": self.candidate.candidate_manifest_sha256,
                "runtime_binding_sha256": runtime_binding_sha256,
                "integration_sha_start": self.integration_sha,
                "launcher_implementation_sha256": launcher_implementation_sha256,
                "trusted_model_identity_sha256": trusted_model_identity_sha256,
                "trusted_toolchain_identity_sha256": trusted_toolchain_identity_sha256,
                "installed_environment_manifest_sha256": (installed_environment_manifest_sha256),
                "base_python_runtime_manifest_sha256": (base_python_runtime_manifest_sha256),
                "venv_control_manifest_sha256": venv_control_manifest_sha256,
                "evaluation_database_backup_sha256": self.initial_eval_database_sha256,
                "real_catalogue_data_version_start": self.initial_data_version,
                "real_catalogue_outbox_sha256_start": self.initial_outbox_sha256,
                "active_pointer_present_start": self.initial_active_present,
                "active_pointer_sha256_start": self.initial_active_sha256,
                "candidate_copy_on_write": True,
                "candidate_copy_read_only": True,
                "isolated_candidate_tree_sha256": (self.initial_isolated_candidate_tree_sha256),
                "isolated_candidate_reverified_before_launch": True,
                "evaluation_database_isolated": True,
                "runtime_objects_isolated": True,
                "retrieval_candidate_pinned": True,
                "model_artifact_rehashed_before_launch": True,
                "model_toolchain_rehashed_before_launch": True,
                "base_python_runtime_rehashed_before_launch": True,
                "venv_control_rehashed_before_launch": True,
                "offline_locked_no_sync_launch": True,
                "child_environment_sanitized": True,
                "direct_verified_venv_python_launch": True,
                "local_only": True,
                "public_traffic_allowed": False,
                "writes_active": False,
                "writes_o04": False,
                "real_catalogue_write_count": 0,
            }
        )

    def verify_end(
        self, *, current_integration_sha: str, runtime_binding_sha256: str
    ) -> dict[str, Any]:
        if self._verified_end is not None:
            return dict(self._verified_end)
        if current_integration_sha != self.integration_sha:
            raise RuntimeError("integration_sha_changed_during_preflight")
        data_version_row = self.real_catalogue.fetchone("PRAGMA data_version")
        if data_version_row is None:
            raise RuntimeError("real_catalogue_mutation_detected")
        data_version = int(data_version_row[0])
        total_changes = self.real_catalogue.total_changes()
        outbox_sha256 = _outbox_digest(self.real_catalogue)
        active_present, active_sha256 = _pointer_snapshot(self.base_settings.index_dir)
        observed = load_sealed_candidate_identity(
            settings=self.base_settings,
            database=self.real_catalogue,  # type: ignore[arg-type]
            candidate_build_id=self.candidate.build_id,
        )
        isolated_observed = load_sealed_candidate_identity(
            settings=self.settings,  # type: ignore[arg-type]
            database=self.database,
            candidate_build_id=self.candidate.build_id,
        )
        isolated_tree_sha256 = candidate_tree_sha256(self.settings.index_dir / "builds")
        unchanged = (
            data_version == self.initial_data_version
            and total_changes == self.initial_total_changes == 0
            and outbox_sha256 == self.initial_outbox_sha256
            and active_present == self.initial_active_present
            and active_sha256 == self.initial_active_sha256
            and observed == self.candidate
            and isolated_observed == self.candidate
            and isolated_tree_sha256 == self.initial_isolated_candidate_tree_sha256
        )
        if not unchanged:
            raise RuntimeError("real_catalogue_candidate_or_active_mutation_detected")
        self._verified_end = sealed_safe_payload(
            {
                "schema": LAUNCHER_END_SCHEMA,
                "run_id": self.run_id,
                "candidate_build_id": self.candidate.build_id,
                "candidate_manifest_sha256": self.candidate.candidate_manifest_sha256,
                "runtime_binding_sha256": runtime_binding_sha256,
                "integration_sha_start": self.integration_sha,
                "integration_sha_end": current_integration_sha,
                "git_sha_unchanged": True,
                "git_worktree_clean_start_end": True,
                "real_catalogue_data_version_start": self.initial_data_version,
                "real_catalogue_data_version_end": data_version,
                "real_catalogue_outbox_sha256_start": self.initial_outbox_sha256,
                "real_catalogue_outbox_sha256_end": outbox_sha256,
                "real_catalogue_unchanged": True,
                "candidate_unchanged": True,
                "isolated_candidate_tree_sha256_start": (
                    self.initial_isolated_candidate_tree_sha256
                ),
                "isolated_candidate_tree_sha256_end": isolated_tree_sha256,
                "isolated_candidate_tree_unchanged": True,
                "isolated_candidate_reverified_after_run": True,
                "active_pointer_present_start": self.initial_active_present,
                "active_pointer_present_end": active_present,
                "active_pointer_sha256_start": self.initial_active_sha256,
                "active_pointer_sha256_end": active_sha256,
                "active_pointer_unchanged": True,
                "evaluation_database_isolated": True,
                "runtime_objects_isolated": True,
                "local_only": True,
                "public_traffic_allowed": False,
                "writes_active": False,
                "writes_o04": False,
                "real_catalogue_write_count": 0,
            }
        )
        return dict(self._verified_end)

    def verify_isolated_candidate(self, *, full_tree: bool) -> None:
        observed = load_sealed_candidate_identity(
            settings=self.settings,  # type: ignore[arg-type]
            database=self.database,
            candidate_build_id=self.candidate.build_id,
        )
        if observed != self.candidate:
            raise RuntimeError("isolated_candidate_mutation_detected")
        if full_tree and (
            candidate_tree_sha256(self.settings.index_dir / "builds")
            != self.initial_isolated_candidate_tree_sha256
        ):
            raise RuntimeError("isolated_candidate_mutation_detected")

    def close(self) -> None:
        self.database.close()
        self.real_catalogue.close()
