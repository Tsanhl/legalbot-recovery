#!/usr/bin/env python3
"""Verify and non-destructively archive the already-downloaded Base shards.

The default mode only verifies and prints a plan. Passing ``--execute`` copies
(or APFS-clones) verified inputs into ``models/archive``. It never moves,
renames, truncates, or deletes anything in the source directory.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .common import atomic_write_json, sha256_file
except ImportError:  # Direct script execution.
    from common import atomic_write_json, sha256_file

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROJECT_ROOT = SCRIPT_DIR.parents[1]
DEFAULT_SOURCE = DEFAULT_PROJECT_ROOT / "models" / "archive" / "Qwen3.5-9B-Base"
DEFAULT_SPEC = SCRIPT_DIR / "manifests" / "qwen3.5-9b-base-recovery.json"


@dataclass(frozen=True, slots=True)
class ShardSpec:
    filename: str
    size: int
    sha256: str


def load_spec(path: Path) -> tuple[dict[str, Any], tuple[ShardSpec, ...]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    shards = tuple(ShardSpec(**item) for item in payload["shards"])
    if len(shards) != 4 or len({item.filename for item in shards}) != 4:
        raise ValueError("recovery manifest must describe exactly four unique shards")
    return payload, shards


def locate_shard(source: Path, spec: ShardSpec) -> Path:
    final_path = source / spec.filename
    if final_path.is_file():
        return final_path
    download_cache = source / ".cache" / "huggingface" / "download"
    candidates = sorted(
        path for path in download_cache.glob("*.incomplete") if spec.sha256 in path.name
    )
    if len(candidates) != 1:
        raise FileNotFoundError(
            f"expected one cached candidate for {spec.filename}; found {len(candidates)}"
        )
    return candidates[0]


def verify_shard(path: Path, spec: ShardSpec) -> dict[str, Any]:
    actual_size = path.stat().st_size
    if actual_size != spec.size:
        raise ValueError(f"size mismatch for {path}: expected {spec.size}, got {actual_size}")
    actual_hash = sha256_file(path)
    if actual_hash != spec.sha256:
        raise ValueError(f"SHA-256 mismatch for {path}: expected {spec.sha256}, got {actual_hash}")
    return {
        "source_path": str(path),
        "filename": spec.filename,
        "size": actual_size,
        "sha256": actual_hash,
    }


def verify_source(
    source: Path, manifest: dict[str, Any], shards: tuple[ShardSpec, ...]
) -> tuple[list[dict[str, Any]], list[Path]]:
    if not source.is_dir():
        raise FileNotFoundError(f"source directory does not exist: {source}")
    metadata_paths: list[Path] = []
    for name in manifest["required_metadata"]:
        path = source / name
        if not path.is_file():
            raise FileNotFoundError(f"required metadata file is missing: {path}")
        metadata_paths.append(path)
    verified = [verify_shard(locate_shard(source, item), item) for item in shards]
    return verified, metadata_paths


def clone_or_copy(source: Path, destination: Path) -> None:
    """Prefer an APFS clone while preserving a portable, non-destructive fallback."""
    result = subprocess.run(
        ["cp", "-c", "-p", str(source), str(destination)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        shutil.copy2(source, destination)


def recover(
    *,
    source: Path,
    destination: Path,
    manifest: dict[str, Any],
    shards: tuple[ShardSpec, ...],
    copier: Callable[[Path, Path], None] = clone_or_copy,
    verified_source: tuple[list[dict[str, Any]], list[Path]] | None = None,
) -> Path:
    verified, metadata_paths = verified_source or verify_source(source, manifest, shards)
    if destination.exists():
        raise FileExistsError(f"archive destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.parent / f".{destination.name}.recovering"
    if staging.exists():
        raise FileExistsError(
            f"recovery staging directory already exists; inspect it manually: {staging}"
        )
    staging.mkdir()

    for path in metadata_paths:
        copier(path, staging / path.name)
    for record in verified:
        copier(Path(record["source_path"]), staging / record["filename"])

    destination_records: list[dict[str, Any]] = []
    for item in shards:
        record = verify_shard(staging / item.filename, item)
        record.pop("source_path", None)
        destination_records.append(record)
    archive_manifest = {
        "schema_version": 1,
        "source_repo": manifest["source_repo"],
        "revision": manifest["revision"],
        "source_directory": str(source.resolve()),
        "archival_only": True,
        "runtime_eligible": False,
        "source_was_modified": False,
        "shards": destination_records,
    }
    atomic_write_json(staging / "archive-manifest.json", archive_manifest)
    os.rename(staging, destination)
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--project-root", type=Path, default=DEFAULT_PROJECT_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_SPEC)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="copy verified files; without this flag the command is verify-only",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    manifest, shards = load_spec(args.manifest)
    destination = args.project_root.resolve() / manifest["archive_directory"]
    verified, metadata_paths = verify_source(args.source.resolve(), manifest, shards)
    print(
        json.dumps(
            {
                "mode": "execute" if args.execute else "verify-only",
                "source": str(args.source.resolve()),
                "destination": str(destination),
                "source_will_be_modified": False,
                "verified_shards": verified,
            },
            indent=2,
            sort_keys=True,
        )
    )
    if args.execute:
        recovered = recover(
            source=args.source.resolve(),
            destination=destination,
            manifest=manifest,
            shards=shards,
            verified_source=(verified, metadata_paths),
        )
        print(f"Archive created without modifying the source: {recovered}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
