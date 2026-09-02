"""Fail-closed boundary for generic reads of immutable index generations.

General Enquiry successor indexes remain held evidence.  Generic benchmarks,
research helpers, vector reuse, and live/dev retrieval must never open their
Lance tables; only :mod:`ge_evaluation_index` may do so after its exact opaque
capability replay.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..contracts import load_json_strict
from .source_manifest import MANIFEST_SCHEMA, approved_source_manifest_sha256

GE_SELECTION_POLICY = "exact-owner-approved-ge-source-versions-and-lanes"

_BUILD_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CONTROL_BYTES = 16 * 1024 * 1024


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _strict_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"generic index read requires an immutable {label}")
    size = path.stat().st_size
    if size < 2 or size > _MAX_CONTROL_BYTES:
        raise RuntimeError(f"generic index read {label} size is invalid")
    raw = path.read_bytes()
    try:
        value = load_json_strict(raw)
    except ValueError as exc:
        raise RuntimeError(f"generic index read {label} is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"generic index read {label} is not an object")
    return value, raw


def _marks_ge_held(value: Mapping[str, Any]) -> bool:
    return bool(
        value.get("selection_policy") == GE_SELECTION_POLICY
        or value.get("ge_held_scope") is True
        or _SHA256.fullmatch(str(value.get("ge_source_scope_content_sha256") or ""))
    )


def require_generic_index_read_allowed(
    build_path: Path,
    *,
    expected_build_id: str,
) -> None:
    """Validate one sealed ordinary build and reject every held GE identity.

    This function is intentionally read-only.  It must run before a generic
    caller imports a model provider, invokes a callback/executor, or opens a
    Lance connection.
    """

    if _BUILD_ID.fullmatch(expected_build_id) is None:
        raise ValueError("generic index read build identity is invalid")
    if (
        build_path.name != expected_build_id
        or build_path.is_symlink()
        or not build_path.is_dir()
        or build_path.parent.is_symlink()
    ):
        raise RuntimeError("generic index read build root is unsafe")
    try:
        if build_path.resolve(strict=True) != build_path.parent.resolve(strict=True) / expected_build_id:
            raise RuntimeError("generic index read build root escaped its immutable parent")
    except OSError as exc:
        raise RuntimeError("generic index read build root is unavailable") from exc

    boundary_path = build_path / "build-boundary.json"
    if boundary_path.exists() or boundary_path.is_symlink():
        boundary, _raw = _strict_object(boundary_path, label="build boundary")
        if (
            boundary.get("schema") != "legalbot.index-build-boundary.v1"
            or boundary.get("build_id") != expected_build_id
        ):
            raise RuntimeError("generic index read build boundary identity differs")
        if _marks_ge_held(boundary):
            raise PermissionError("held GE index is unavailable to generic read paths")

    source_path = build_path / "approved-source-manifest.json"
    source, source_raw = _strict_object(source_path, label="approved source manifest")
    try:
        source_sha256 = approved_source_manifest_sha256(source)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("generic index read source manifest cannot be canonicalized") from exc
    if (
        source.get("schema") != MANIFEST_SCHEMA
        or source.get("manifest_sha256") != source_sha256
    ):
        raise RuntimeError("generic index read source manifest seal differs")
    if _marks_ge_held(source):
        raise PermissionError("held GE index is unavailable to generic read paths")

    manifest_path = build_path / "manifest.json"
    manifest, manifest_raw = _strict_object(manifest_path, label="build manifest")
    if (
        manifest.get("schema")
        not in {"legalbot.lance-build.v1", "legalbot.index-manifest.v2"}
        or manifest.get("build_id") != expected_build_id
        or manifest.get("sealed") is not True
        or manifest.get("source_manifest_sha256") != source_sha256
    ):
        raise RuntimeError("generic index read build manifest identity differs")

    seal_path = build_path / "seal.json"
    seal, _seal_raw = _strict_object(seal_path, label="build seal")
    if (
        seal.get("schema") != "legalbot.index-seal.v2"
        or seal.get("build_id") != expected_build_id
        or seal.get("manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest()
        or seal.get("source_manifest_file_sha256")
        != hashlib.sha256(source_raw).hexdigest()
    ):
        raise RuntimeError("generic index read seal does not bind the exact manifests")

    evaluation_path = build_path / "evaluation.json"
    if evaluation_path.exists() or evaluation_path.is_symlink():
        evaluation, evaluation_raw = _strict_object(evaluation_path, label="index evaluation")
        if seal.get("evaluation_sha256") != hashlib.sha256(evaluation_raw).hexdigest():
            raise RuntimeError("generic index read seal does not bind the exact evaluation")
        integrity = evaluation.get("integrity")
        if isinstance(integrity, Mapping) and _marks_ge_held(integrity):
            raise PermissionError("held GE index is unavailable to generic read paths")

    # Re-read the exact files after validation so a concurrent replacement
    # cannot turn an ordinary identity into a held GE identity before return.
    if (
        _file_sha256(source_path) != hashlib.sha256(source_raw).hexdigest()
        or _file_sha256(manifest_path) != hashlib.sha256(manifest_raw).hexdigest()
        or _file_sha256(seal_path) != hashlib.sha256(_seal_raw).hexdigest()
    ):
        raise RuntimeError("generic index read control files changed during verification")


__all__ = ["GE_SELECTION_POLICY", "require_generic_index_read_allowed"]
