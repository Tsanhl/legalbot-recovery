"""Mandatory split-derivation verification before owner-review intake actions."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from ..config import Settings
from ..db import Database
from .all60_qualification import EXACT_ALL60_FILENAME
from .canary_review_workspace import CanaryReviewWorkspace
from .live_suite import load_live_evaluation_bundle
from .owner_quality_canary import (
    load_verified_owner_quality_canary_manifest,
    owner_quality_manifest_bytes,
)
from .owner_quality_canary_intake import load_owner_review_workspace
from .sealed_candidate import load_sealed_candidate_identity


def _private_file(path: Path, *, label: str) -> bytes:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError(f"owner-review {label} is missing or unsafe")
    return path.read_bytes()


def load_verified_owner_review_workspace(
    root: Path,
    *,
    project_root: Path,
) -> CanaryReviewWorkspace:
    """Open an intake workspace only after recomputing its exact 30/30 split.

    The workspace seal and a self-sealed sample manifest are not accepted as
    proof of sampling. This entry point loads the exact sealed candidate and
    all60 v3 qualification, invokes the authoritative split loader, and then
    reconciles the canonical bytes to the workspace bindings.
    """

    project = project_root.resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    expected_parent = project / "data/evaluations/canary-output-review"
    if not resolved_root.is_relative_to(expected_parent):
        raise ValueError("owner-review workspace is outside the fixed local review root")
    workspace = load_owner_review_workspace(resolved_root)
    sample_path = resolved_root / "sample-manifest.json"
    qualification_path = resolved_root / EXACT_ALL60_FILENAME
    sample_before = _private_file(sample_path, label="sample manifest")
    _private_file(qualification_path, label="exact all60 qualification")

    settings = Settings(project_root=project)
    database = Database(settings.database_path)
    try:
        candidate = load_sealed_candidate_identity(
            settings=settings,
            database=database,
            candidate_build_id=workspace.manifest.candidate_build_id,
        )
        bundle = load_live_evaluation_bundle(
            project / "benchmarks/evaluation/live-evaluation-60-v1"
        )
        manifest = load_verified_owner_quality_canary_manifest(
            sample_path,
            bundle=bundle,
            candidate=candidate,
            qualification_path=qualification_path,
        )
    finally:
        database.close()

    canonical = owner_quality_manifest_bytes(manifest)
    sample_after = _private_file(sample_path, label="sample manifest")
    expected_case_ids = (
        manifest.development_case_ids
        if workspace.manifest.lane == "development"
        else manifest.blind_holdout_case_ids
    )
    if (
        sample_before != sample_after
        or sample_after != canonical
        or workspace.manifest.canary_manifest_id != manifest.manifest_id
        or workspace.manifest.canary_manifest_seal_sha256 != manifest.seal_sha256
        or workspace.manifest.canary_manifest_file_sha256 != hashlib.sha256(canonical).hexdigest()
        or workspace.manifest.candidate_build_id != manifest.candidate_build_id
        or workspace.manifest.candidate_manifest_sha256 != manifest.candidate_manifest_sha256
        or workspace.manifest.expected_case_ids != expected_case_ids
    ):
        raise ValueError("owner-review workspace contains a favorable sample redraw")
    return workspace
