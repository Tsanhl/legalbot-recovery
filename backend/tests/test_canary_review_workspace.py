from __future__ import annotations

import json
import stat
from datetime import date
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation.canary_review_workspace import (
    CANARY_REVIEW_CATEGORIES,
    REQUIRED_RELEASE_GATES,
    CanaryReviewWorkspaceManifest,
    create_canary_review_workspace,
)
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.owner_quality_canary import (
    ALL60_QUALIFICATION_SCHEMA,
    All60CaseQualification,
    freeze_owner_quality_canary_manifest,
)
from app.evaluation.secure_artifact_io import write_create_only_at
from app.text_metrics import word_count

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _canary_manifest():
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    case_ids = [case.case_id for case in bundle.registry.cases]
    value = {
        "schema": ALL60_QUALIFICATION_SCHEMA,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": "candidate-v111",
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": case_ids,
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    value["seal_sha256"] = sealed_sha256(value)
    qualification = All60CaseQualification.model_validate(value)
    return freeze_owner_quality_canary_manifest(
        bundle=bundle,
        candidate_build_id="candidate-v111",
        candidate_manifest_sha256="a" * 64,
        qualification=qualification,
    )


def _workspace(tmp_path: Path):
    return create_canary_review_workspace(
        project_root=tmp_path,
        review_date=date(2026, 8, 20),
        run_id="development-run-001",
        lane="development",
        canary_manifest=_canary_manifest(),
        runtime_run_manifest_sha256="f" * 64,
    )


def test_workspace_is_dated_private_sealed_and_create_only(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)

    assert workspace.root == (
        tmp_path / "data/evaluations/canary-output-review/2026-08-20/development-run-001"
    )
    assert stat.S_IMODE(workspace.root.stat().st_mode) == 0o700
    assert all((workspace.root / category).is_dir() for category in CANARY_REVIEW_CATEGORIES)
    assert all(
        stat.S_IMODE((workspace.root / category).stat().st_mode) == 0o700
        for category in CANARY_REVIEW_CATEGORIES
    )
    for name in ("workspace-manifest.json", "sample-manifest.json"):
        assert stat.S_IMODE((workspace.root / name).stat().st_mode) == 0o600
    CanaryReviewWorkspaceManifest.model_validate_json(
        (workspace.root / "workspace-manifest.json").read_bytes()
    )
    encoded = (workspace.root / "sample-manifest.json").read_text()
    assert '"question"' not in encoded
    assert '"subject"' not in encoded
    assert str(tmp_path) not in encoded

    with pytest.raises(FileExistsError, match="already exists"):
        _workspace(tmp_path)


def test_workspace_refuses_symlinks_and_unsafe_machine_projections(
    tmp_path: Path,
) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "data").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        _workspace(tmp_path)

    clean_root = tmp_path / "clean"
    clean_root.mkdir()
    workspace = _workspace(clean_root)
    with pytest.raises(ValueError, match="filename"):
        workspace.write_safe_json(
            category="safe-metrics", filename="../escape.json", value={"count": 1}
        )
    with pytest.raises(ValueError, match="forbidden plaintext"):
        workspace.write_safe_json(
            category="safe-metrics",
            filename="metrics.json",
            value={"question": "private"},
        )


def test_only_fully_gated_answers_are_readable_and_held_data_is_encrypted(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    case_id = workspace.manifest.expected_case_ids[0]
    failed_gates = {gate: True for gate in REQUIRED_RELEASE_GATES}
    failed_gates["currentness"] = False
    with pytest.raises(ValueError, match="failed hard gate"):
        workspace.write_released_answer(
            case_id=case_id, content="A released answer.", release_gates=failed_gates
        )

    gates = {gate: True for gate in REQUIRED_RELEASE_GATES}
    answer_path, attestation_path = workspace.write_released_answer(
        case_id=case_id,
        content="A fully evidence-bound released answer.",
        release_gates=gates,
    )
    assert answer_path.read_text() == "A fully evidence-bound released answer."
    assert json.loads(attestation_path.read_text())["all_required_release_gates_passed"]
    assert stat.S_IMODE(answer_path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        workspace.write_released_answer(
            case_id=case_id,
            content="A second answer must not overwrite the first.",
            release_gates=gates,
        )

    second_workspace_root = tmp_path / "canonical-word-count"
    second_workspace_root.mkdir()
    second_workspace = _workspace(second_workspace_root)
    hyphenated = "State-of-the-art counsel’s evidence-bound analysis."
    _answer, attestation = second_workspace.write_released_answer(
        case_id=second_workspace.manifest.expected_case_ids[0],
        content=hyphenated,
        release_gates=gates,
    )
    assert json.loads(attestation.read_text())["word_count"] == word_count(hyphenated)

    cipher = LocalCipher(Fernet(Fernet.generate_key()))
    private_draft = b"held private draft"
    encrypted_path, sidecar_path = workspace.write_encrypted_projection(
        category="held-drafts",
        artifact_id="held-draft-001",
        content=private_draft,
        cipher=cipher,
        case_id=case_id,
    )
    assert encrypted_path.read_bytes() != private_draft
    assert cipher.decrypt_bytes(encrypted_path.read_bytes()) == private_draft
    assert private_draft.decode() not in sidecar_path.read_text()
    assert stat.S_IMODE(encrypted_path.stat().st_mode) == 0o600


def test_fd_relative_write_cannot_be_redirected_by_parent_swap(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    original = workspace.root / "safe-metrics"
    retained = workspace.root / "safe-metrics-retained"
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)

    with workspace.open_private_directory("safe-metrics") as directory_fd:
        original.rename(retained)
        original.symlink_to(outside, target_is_directory=True)
        write_create_only_at(directory_fd, "race-proof.json", b'{"safe":true}\n')

    assert (retained / "race-proof.json").read_bytes() == b'{"safe":true}\n'
    assert not (outside / "race-proof.json").exists()
    with pytest.raises(ValueError, match="symlink"):
        workspace.write_safe_json(
            category="safe-metrics",
            filename="redirected.json",
            value={"safe": True},
        )
    assert not tuple(outside.iterdir())
