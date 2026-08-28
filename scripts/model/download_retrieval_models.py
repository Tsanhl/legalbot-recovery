#!/usr/bin/env python3
"""Download both pinned Qwen retrieval models through resumable staging paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from .common import atomic_write_json, file_manifest, sha256_file
except ImportError:  # Direct script execution.
    from common import atomic_write_json, file_manifest, sha256_file

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROJECT_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_SPEC = SCRIPT_DIR / "manifests" / "qwen3-retrieval-models.json"


def load_spec(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported retrieval-model manifest")
    if payload.get("download") != {"disable_xet": True, "max_workers": 1}:
        raise ValueError("retrieval downloads must disable Xet and use one worker")
    models = payload.get("models")
    if not isinstance(models, list) or {item.get("role") for item in models} != {
        "embedding",
        "reranker",
    }:
        raise ValueError("manifest must pin one embedding model and one reranker")
    for item in models:
        revision = str(item.get("revision", ""))
        if len(revision) != 40 or any(char not in "0123456789abcdef" for char in revision):
            raise ValueError("each retrieval model requires a full commit SHA")
        if not str(item.get("source_repo", "")).startswith("Qwen/Qwen3-"):
            raise ValueError("only the approved Qwen3 retrieval repositories are allowed")
        if item.get("role") == "embedding" and item.get("dimensions") != 1024:
            raise ValueError("the embedding model must be pinned to 1,024 dimensions")
        file_manifest_sha256 = str(item.get("file_manifest_sha256") or "")
        if len(file_manifest_sha256) != 64 or any(
            char not in "0123456789abcdef" for char in file_manifest_sha256
        ):
            raise ValueError("each retrieval model requires a tracked file-manifest SHA-256")
    return payload


def _recursive_file_manifest(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if ".cache" in relative.parts or relative.as_posix() == "retrieval-model.json":
            continue
        if path.is_symlink():
            raise ValueError("retrieval model contains a symbolic link")
        if not path.is_file():
            continue
        records.append(
            {
                "path": relative.as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return records


def _file_manifest_sha256(records: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _validate(path: Path, item: Mapping[str, Any]) -> None:
    for filename in item["required_files"]:
        if not (path / str(filename)).is_file():
            raise FileNotFoundError(f"retrieval model is missing required file: {filename}")
    if not any(path.glob("*.safetensors")):
        raise FileNotFoundError("retrieval model contains no SafeTensors weights")
    config = json.loads((path / "config.json").read_text(encoding="utf-8"))
    if config.get("model_type") != "qwen3":
        raise ValueError("retrieval artifact is not a Qwen3 model")


def download_one(
    *,
    item: Mapping[str, Any],
    project_root: Path,
    snapshot_download: Callable[..., Any] | None = None,
) -> Path:
    injected_downloader = snapshot_download is not None
    target = project_root.resolve() / str(item["directory"])
    provenance_path = target / "retrieval-model.json"
    if target.exists():
        _validate(target, item)
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        if (
            provenance.get("source_repo") != item["source_repo"]
            or provenance.get("revision") != item["revision"]
        ):
            raise ValueError("existing retrieval artifact does not match the manifest pin")
        if _file_manifest_sha256(_recursive_file_manifest(target)) != item["file_manifest_sha256"]:
            raise ValueError("existing retrieval model differs from the tracked file manifest")
        return target

    target.parent.mkdir(parents=True, exist_ok=True)
    staging = target.parent / f".{target.name}.staging"
    lock = target.parent / f".{target.name}.download.lock"
    try:
        lock.mkdir()
    except FileExistsError as exc:
        raise RuntimeError(f"another retrieval model download may be active: {lock}") from exc
    try:
        staging.mkdir(exist_ok=True)
        if snapshot_download is None:
            os.environ["HF_HUB_DISABLE_XET"] = "1"
            os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
            os.environ.setdefault("HF_HUB_DOWNLOAD_TIMEOUT", "600")
            os.environ.setdefault("HF_HUB_ETAG_TIMEOUT", "60")
            from huggingface_hub import snapshot_download as hub_snapshot_download

            snapshot_download = hub_snapshot_download
        snapshot_download(
            repo_id=item["source_repo"],
            revision=item["revision"],
            local_dir=str(staging),
            max_workers=1,
        )
        _validate(staging, item)
        recursive_files = _recursive_file_manifest(staging)
        recursive_digest = _file_manifest_sha256(recursive_files)
        if not injected_downloader and recursive_digest != item["file_manifest_sha256"]:
            raise ValueError("downloaded retrieval model differs from the tracked file manifest")
        atomic_write_json(
            staging / "retrieval-model.json",
            {
                "schema_version": 1,
                "role": item["role"],
                "source_repo": item["source_repo"],
                "revision": item["revision"],
                "dimensions": item.get("dimensions"),
                "downloaded_at": datetime.now(UTC).isoformat(),
                "python": f"{sys.version_info.major}.{sys.version_info.minor}",
                "hf_hub_disable_xet": True,
                "max_workers": 1,
                "files": file_manifest(staging),
                "recursive_file_manifest_sha256": recursive_digest,
            },
        )
        os.rename(staging, target)
        return target
    finally:
        lock.rmdir()


def require_python_313() -> None:
    if sys.version_info[:2] != (3, 13):
        raise RuntimeError("retrieval model downloads require Python 3.13")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=DEFAULT_PROJECT_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    spec = load_spec(args.manifest)
    plan = [
        {
            "role": item["role"],
            "repo": item["source_repo"],
            "revision": item["revision"],
            "target": str((args.project_root / item["directory"]).resolve()),
        }
        for item in spec["models"]
    ]
    print(json.dumps({"mode": "execute" if args.execute else "dry-run", "models": plan}, indent=2))
    if not args.execute:
        return 0
    require_python_313()
    for item in spec["models"]:
        ready = download_one(item=item, project_root=args.project_root)
        print(f"Pinned {item['role']} model ready: {ready}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
