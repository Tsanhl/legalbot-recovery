#!/usr/bin/env python3
"""Download the pinned post-trained MLX model through a conservative path.

The command is a dry run unless ``--execute`` is supplied. Execution requires
Python 3.13, disables Xet before importing huggingface_hub, uses one worker,
downloads into a resumable staging directory, validates the 4-bit artifact,
and only then promotes it into ``models/runtime``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from .common import atomic_write_json, file_manifest
except ImportError:  # Direct script execution.
    from common import atomic_write_json, file_manifest

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROJECT_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_SPEC = SCRIPT_DIR / "manifests" / "qwen3.5-9b-runtime.json"


def load_spec(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload["download"] != {"disable_xet": True, "max_workers": 1}:
        raise ValueError("runtime manifest must require disabled Xet and one worker")
    if payload["quantization_bits"] != 4 or payload["post_trained"] is not True:
        raise ValueError("runtime model must be a post-trained 4-bit artifact")
    revision = payload.get("revision", "")
    if len(revision) != 40 or any(char not in "0123456789abcdef" for char in revision):
        raise ValueError("runtime revision must be a full 40-character commit SHA")
    return payload


def require_python_313() -> None:
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError(
            "model downloads must run under Python 3.13; "
            f"current interpreter is {sys.version_info.major}.{sys.version_info.minor}"
        )


def validate_download(path: Path, spec: dict[str, Any]) -> None:
    for filename in spec["required_files"]:
        if not (path / filename).is_file():
            raise FileNotFoundError(f"download is missing required file: {filename}")
    if not any(path.glob("*.safetensors")):
        raise FileNotFoundError("download contains no SafeTensors weights")
    config = json.loads((path / "config.json").read_text(encoding="utf-8"))
    quantization = config.get("quantization") or config.get("quantization_config", {})
    if config.get("model_type") != "qwen3_5":
        raise ValueError("downloaded model_type is not qwen3_5")
    if quantization.get("bits") != spec["quantization_bits"]:
        raise ValueError("downloaded model is not the pinned 4-bit artifact")


def execute_download(
    *,
    spec: dict[str, Any],
    project_root: Path,
    snapshot_download: Callable[..., Any] | None = None,
) -> Path:
    target = project_root.resolve() / spec["runtime_directory"]
    if target.exists():
        validate_download(target, spec)
        provenance = json.loads((target / "runtime-model.json").read_text(encoding="utf-8"))
        if (
            provenance.get("source_repo") != spec["source_repo"]
            or provenance.get("revision") != spec["revision"]
        ):
            raise ValueError("existing runtime artifact does not match the pin")
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.parent / f".{target.name}.staging"
    lock = target.parent / f".{target.name}.download.lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise RuntimeError(f"another model download may be active: {lock}") from exc

    try:
        staging.mkdir(exist_ok=True)
        if snapshot_download is None:
            os.environ["HF_HUB_DISABLE_XET"] = "1"
            os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
            # Large model shards regularly exceed the hub client's 10-second
            # default during CDN pauses. The staging directory remains
            # resumable, so use conservative timeouts instead of restarting.
            os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "600")
            os.environ.setdefault("HF_HUB_ETAG_TIMEOUT", "60")
            from huggingface_hub import snapshot_download as hub_snapshot_download

            snapshot_download = hub_snapshot_download
        snapshot_download(
            repo_id=spec["source_repo"],
            revision=spec["revision"],
            local_dir=str(staging),
            max_workers=1,
        )
        validate_download(staging, spec)
        provenance = {
            "schema_version": 1,
            "source_repo": spec["source_repo"],
            "revision": spec["revision"],
            "post_trained": True,
            "quantization_bits": 4,
            "downloaded_at": datetime.now(UTC).isoformat(),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}",
            "hf_hub_disable_xet": True,
            "max_workers": 1,
            "files": file_manifest(staging),
        }
        atomic_write_json(staging / "runtime-model.json", provenance)
        os.rename(staging, target)
        return target
    finally:
        lock.rmdir()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=DEFAULT_PROJECT_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_SPEC)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="perform the pinned download; otherwise only print the plan",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    spec = load_spec(args.manifest)
    target = args.project_root.resolve() / spec["runtime_directory"]
    print(
        json.dumps(
            {
                "mode": "execute" if args.execute else "dry-run",
                "repo": spec["source_repo"],
                "revision": spec["revision"],
                "target": str(target),
                "python_required": "3.13",
                "hf_hub_disable_xet": True,
                "max_workers": 1,
                "download_timeout_seconds": 600,
            },
            indent=2,
            sort_keys=True,
        )
    )
    if not args.execute:
        return 0
    require_python_313()
    result = execute_download(spec=spec, project_root=args.project_root)
    print(f"Pinned runtime model ready: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
