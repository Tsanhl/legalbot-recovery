from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from app.evaluation.canary_review_workspace import (
    CanaryReviewWorkspace,
    CanaryReviewWorkspaceManifest,
)
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.owner_quality_canary import (
    ALL60_QUALIFICATION_SCHEMA,
    All60CaseQualification,
    freeze_owner_quality_canary_manifest,
    owner_quality_manifest_bytes,
)
from app.evaluation.owner_quality_canary_intake_verification import (
    load_verified_owner_review_workspace,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _contracts(root: Path) -> tuple[CanaryReviewWorkspace, Any]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    case_ids = tuple(case.case_id for case in bundle.registry.cases)
    qualification_value: dict[str, Any] = {
        "schema": ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": "candidate-v111",
        "case_count": 60,
        "case_ids": list(case_ids),
        "qualified_case_ids": list(case_ids),
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    qualification_value["seal_sha256"] = sealed_sha256(qualification_value)
    qualification = All60CaseQualification.model_validate(qualification_value)
    manifest = freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="a" * 64,
        qualification=qualification,
    )
    workspace_manifest = CanaryReviewWorkspaceManifest.model_construct(
        run_id="owner-run-001",
        lane="development",
        canary_manifest_id=manifest.manifest_id,
        canary_manifest_seal_sha256=manifest.seal_sha256,
        canary_manifest_file_sha256=hashlib.sha256(
            owner_quality_manifest_bytes(manifest)
        ).hexdigest(),
        candidate_build_id=manifest.candidate_build_id,
        candidate_manifest_sha256=manifest.candidate_manifest_sha256,
        expected_case_ids=manifest.development_case_ids,
    )
    return CanaryReviewWorkspace(root=root, manifest=workspace_manifest), manifest


def test_intake_workspace_invokes_verified_split_loader_and_rejects_redraw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "data/evaluations/canary-output-review/2026-08-20/owner-run-001"
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    workspace, manifest = _contracts(root)
    sample = root / "sample-manifest.json"
    sample.write_bytes(owner_quality_manifest_bytes(manifest))
    sample.chmod(0o600)
    qualification = root / "all60-qualification.json"
    qualification.write_text("verified by mandatory loader stub\n", encoding="utf-8")
    qualification.chmod(0o600)

    calls: list[Path] = []

    class _Database:
        def __init__(self, _path: Path) -> None:
            pass

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_intake_verification.load_owner_review_workspace",
        lambda _root: workspace,
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_intake_verification.Database", _Database
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_intake_verification.load_sealed_candidate_identity",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_intake_verification.load_live_evaluation_bundle",
        lambda _path: object(),
    )

    def _verified(path: Path, **_kwargs: Any) -> Any:
        calls.append(path)
        return manifest

    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_intake_verification.load_verified_owner_quality_canary_manifest",
        _verified,
    )
    assert (
        load_verified_owner_review_workspace(root, project_root=tmp_path).manifest
        == workspace.manifest
    )
    assert calls == [sample]

    redraw_manifest = workspace.manifest.model_copy(
        update={"expected_case_ids": tuple(reversed(manifest.development_case_ids))}
    )
    redraw_workspace = CanaryReviewWorkspace(root=root, manifest=redraw_manifest)
    monkeypatch.setattr(
        "app.evaluation.owner_quality_canary_intake_verification.load_owner_review_workspace",
        lambda _root: redraw_workspace,
    )
    with pytest.raises(ValueError, match="favorable sample redraw"):
        load_verified_owner_review_workspace(root, project_root=tmp_path)
