#!/usr/bin/env python3
"""Plan or create the isolated OCR environment. Dry-run is the default."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = PROJECT_ROOT / "config" / "ocr-toolchain.json"


def load_manifest(path: Path = MANIFEST_PATH) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if value.get("schema") != "legalbot.ocr-toolchain.v1":
        raise RuntimeError("Unsupported OCR toolchain manifest")
    return value, raw


def build_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    environment = manifest["environment"]
    prefix = _confined_project_path(environment["prefix"])
    root_prefix = _confined_project_path(environment["root_prefix"])
    packages = list(environment["packages"])
    python_packages = list(environment["python_packages"])
    command = [
        "micromamba",
        "--no-rc",
        "create",
        "--yes",
        "--prefix",
        str(prefix),
        "--override-channels",
        "--channel",
        "conda-forge",
        "--strict-channel-priority",
        *packages,
    ]
    return {
        "mode": "dry-run",
        "mutates_system": False,
        "prefix": str(prefix.relative_to(PROJECT_ROOT)),
        "root_prefix": str(root_prefix.relative_to(PROJECT_ROOT)),
        "resolver_version": manifest["resolver"]["version"],
        "resolver_asset_url": manifest["resolver"]["asset_url"],
        "resolver_sha256": manifest["resolver"]["sha256"],
        "packages": packages,
        "python_packages": python_packages,
        "command": command,
    }


def execute_plan(
    manifest: dict[str, Any],
    raw_manifest: bytes,
    *,
    micromamba: str | None,
) -> Path:
    plan = build_plan(manifest)
    binary = _resolve_micromamba(micromamba)
    required_version = str(plan["resolver_version"])
    required_sha256 = str(plan["resolver_sha256"])
    if not re.fullmatch(r"[0-9a-f]{64}", required_sha256):
        raise RuntimeError("The pinned micromamba SHA-256 is invalid")
    if _file_sha256(binary) != required_sha256:
        raise RuntimeError("The selected micromamba binary failed SHA-256 verification")
    version = _run_public_version([str(binary), "--version"], env=_resolver_env(binary))
    if version.split()[0] != required_version:
        raise RuntimeError(
            f"micromamba {required_version} is required; selected binary reports {version!r}"
        )

    prefix = _confined_project_path(str(plan["prefix"]))
    root_prefix = _confined_project_path(str(plan["root_prefix"]))
    if prefix.exists() and prefix.is_symlink():
        raise RuntimeError("Refusing a symlinked OCR environment prefix")
    if root_prefix.exists() and root_prefix.is_symlink():
        raise RuntimeError("Refusing a symlinked micromamba root prefix")
    root_prefix.mkdir(parents=True, exist_ok=True, mode=0o700)

    command = list(plan["command"])
    command[0] = str(binary)
    result = subprocess.run(
        command,
        capture_output=True,
        check=False,
        env=_resolver_env(binary, root_prefix=root_prefix),
        stdin=subprocess.DEVNULL,
        timeout=1_800,
    )
    if result.returncode != 0:
        raise RuntimeError(f"OCR environment creation failed (exit {result.returncode})")

    python_packages = [str(item) for item in plan["python_packages"]]
    pip_result = subprocess.run(
        [
            str(prefix / "bin" / "python"),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--index-url",
            "https://pypi.org/simple",
            *python_packages,
        ],
        capture_output=True,
        check=False,
        env=_python_package_env(prefix),
        stdin=subprocess.DEVNULL,
        timeout=600,
    )
    if pip_result.returncode != 0:
        raise RuntimeError(f"OCR Python package installation failed (exit {pip_result.returncode})")

    bin_dir = prefix / "bin"
    required = tuple(str(item) for item in manifest["environment"]["required_binaries"])
    missing = [name for name in required if not _is_executable(bin_dir / name)]
    if missing:
        raise RuntimeError("OCR environment is incomplete: required executables are missing")

    tool_versions = {
        "ocrmypdf": _run_public_version([str(bin_dir / "ocrmypdf"), "--version"]),
        "tesseract": _run_public_version([str(bin_dir / "tesseract"), "--version"]),
        "ghostscript": _run_public_version([str(bin_dir / "gs"), "--version"]),
    }
    explicit = subprocess.run(
        [str(binary), "--no-rc", "list", "--explicit", "--prefix", str(prefix)],
        capture_output=True,
        check=False,
        env=_resolver_env(binary, root_prefix=root_prefix),
        stdin=subprocess.DEVNULL,
        timeout=120,
        text=True,
    )
    if explicit.returncode != 0:
        raise RuntimeError("Could not record the resolved OCR package lock")
    lock = [line for line in explicit.stdout.splitlines() if line.startswith("https://")]
    pip_freeze = subprocess.run(
        [str(prefix / "bin" / "python"), "-m", "pip", "freeze", "--all"],
        capture_output=True,
        check=False,
        env=_python_package_env(prefix),
        stdin=subprocess.DEVNULL,
        timeout=120,
        text=True,
    )
    if pip_freeze.returncode != 0:
        raise RuntimeError("Could not record the resolved OCR Python package lock")
    provenance = {
        "schema": "legalbot.ocr-provenance.v1",
        "created_at": datetime.now(UTC).isoformat(),
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "resolver": {"name": "micromamba", "version": version.split()[0]},
        "tool_versions": tool_versions,
        "explicit_packages": lock,
        "python_packages": [
            line
            for line in pip_freeze.stdout.splitlines()
            if line and not line.startswith("#") and " @ file:" not in line
        ],
    }
    provenance_path = prefix / "legalbot-provenance.json"
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return provenance_path


def _confined_project_path(relative: str) -> Path:
    candidate = (PROJECT_ROOT / relative).resolve()
    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise RuntimeError("OCR tool paths must remain inside this project") from exc
    return candidate


def _resolve_micromamba(selected: str | None) -> Path:
    candidate = selected or os.environ.get("LEGALBOT_MICROMAMBA") or shutil.which("micromamba")
    if not candidate:
        raise RuntimeError(
            "micromamba is not available; provide a verified binary with --micromamba"
        )
    path = Path(candidate).expanduser().resolve()
    if not _is_executable(path):
        raise RuntimeError("The selected micromamba binary is not executable")
    return path


def _resolver_env(binary: Path, *, root_prefix: Path | None = None) -> dict[str, str]:
    env = {
        "LANG": "C",
        "LC_ALL": "C",
        "MAMBA_NO_BANNER": "1",
        "PATH": f"{binary.parent}:/usr/bin:/bin",
    }
    if root_prefix is not None:
        env["MAMBA_ROOT_PREFIX"] = str(root_prefix)
    return env


def _python_package_env(prefix: Path) -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{prefix / 'bin'}:/usr/bin:/bin",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "PYTHONNOUSERSITE": "1",
    }


def _run_public_version(command: list[str], env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        check=False,
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=30,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("A required OCR tool did not report its version")
    output = result.stdout or result.stderr
    first_line = output.splitlines()[0].strip() if output else ""
    if not first_line:
        raise RuntimeError("A required OCR tool returned an empty version")
    return first_line


def _is_executable(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="create the ignored project-local environment (default: print the plan only)",
    )
    parser.add_argument(
        "--micromamba",
        help="path to a separately downloaded and verified micromamba 2.8.1 binary",
    )
    args = parser.parse_args(argv)
    try:
        manifest, raw = load_manifest()
        plan = build_plan(manifest)
        if not args.execute:
            print(json.dumps(plan, indent=2))
            return 0
        provenance = execute_plan(manifest, raw, micromamba=args.micromamba)
        print(f"OCR toolchain ready; provenance: {provenance.relative_to(PROJECT_ROOT)}")
        return 0
    except (OSError, RuntimeError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"OCR toolchain setup stopped safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
