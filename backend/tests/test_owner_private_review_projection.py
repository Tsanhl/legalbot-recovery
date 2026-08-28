from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, cast

import pytest

from app.evaluation.live_suite import sealed_sha256
from app.evaluation.owner_private_review_projection import (
    OWNER_PRIVATE_REVIEW_COMPLETE_SCHEMA,
    OWNER_PRIVATE_REVIEW_PROJECTION_SCHEMA,
    OwnerPrivateReviewRecord,
    project_owner_private_review,
)


def _private_root(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _records(count: int) -> list[OwnerPrivateReviewRecord]:
    return [
        OwnerPrivateReviewRecord(
            record_id=f"case-{index:02d}",
            question=f"Question {index}?",
            answer=f"Answer {index} with reviewed evidence.",
        )
        for index in range(1, count + 1)
    ]


def test_development_projection_is_readable_private_and_non_authorizing(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    private_root = _private_root(tmp_path / "private")

    result = project_owner_private_review(
        private_root=private_root,
        project_root=project_root,
        phase="phase-2-development",
        release_id="development-cycle-01",
        authority_sha256="a" * 64,
        records=_records(30),
        synthetic_unverified_test_only=True,
    )

    output = private_root / result.relative_directory
    assert result.record_count == 30
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE((output / "00-OWNER-REVIEW-INDEX.md").stat().st_mode) == 0o600
    assert (output / "cases/01-case-01/QUESTION.md").read_text().endswith("Question 1?\n")
    assert (
        (output / "cases/01-case-01/ANSWER.md")
        .read_text()
        .endswith("Answer 1 with reviewed evidence.\n")
    )
    assert "Status: not reviewed" in (output / "cases/01-case-01/OWNER-NOTES.md").read_text()

    manifest = json.loads((output / "projection-manifest.json").read_bytes())
    assert manifest["schema"] == OWNER_PRIVATE_REVIEW_PROJECTION_SCHEMA
    assert manifest["record_count"] == 30
    assert manifest["authorizing"] is False
    assert manifest["sealed_validation_output"] is False
    assert manifest["seal_sha256"] == sealed_sha256(manifest)
    complete = json.loads((output / "PROJECTION-COMPLETE.json").read_bytes())
    assert complete["schema"] == OWNER_PRIVATE_REVIEW_COMPLETE_SCHEMA
    assert complete["manifest_sha256"] == result.manifest_sha256
    assert complete["seal_sha256"] == sealed_sha256(complete)


def test_projection_refuses_overwrite_wrong_lane_and_private_paths(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    private_root = _private_root(tmp_path / "private")
    arguments: dict[str, Any] = {
        "private_root": private_root,
        "project_root": project_root,
        "phase": "phase-3-live",
        "release_id": "live-review-01",
        "authority_sha256": "b" * 64,
        "records": _records(1),
        "synthetic_unverified_test_only": True,
    }
    project_owner_private_review(**arguments)
    with pytest.raises(FileExistsError):
        project_owner_private_review(**arguments)

    with pytest.raises(ValueError, match="sealed or unknown"):
        project_owner_private_review(
            **{**arguments, "phase": cast(Any, "sealed-validation"), "release_id": "invalid-lane"}
        )
    with pytest.raises(ValueError, match="absolute private path"):
        project_owner_private_review(
            **{
                **arguments,
                "release_id": "private-path",
                "records": [
                    OwnerPrivateReviewRecord(
                        record_id="case-private",
                        question="Read /Users/Owner/private.pdf",
                        answer="No.",
                    )
                ],
            }
        )


def test_development_projection_requires_exactly_thirty_before_writing(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    private_root = _private_root(tmp_path / "private")

    with pytest.raises(ValueError, match="exactly 30"):
        project_owner_private_review(
            private_root=private_root,
            project_root=project_root,
            phase="phase-2-development",
            release_id="short-development",
            authority_sha256="c" * 64,
            records=_records(29),
            synthetic_unverified_test_only=True,
        )

    assert tuple(private_root.iterdir()) == ()


def test_projection_refuses_real_input_without_strict_verifier(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    private_root = _private_root(tmp_path / "private")

    with pytest.raises(RuntimeError, match="trusted owner-review package verification"):
        project_owner_private_review(
            private_root=private_root,
            project_root=project_root,
            phase="phase-3-live",
            release_id="not-authorized",
            authority_sha256="d" * 64,
            records=_records(1),
        )

    assert tuple(private_root.iterdir()) == ()


def test_projection_refuses_symlinked_private_root_ancestor(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    real_parent = _private_root(tmp_path / "real-parent")
    private_root = _private_root(real_parent / "private")
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlinked ancestor"):
        project_owner_private_review(
            private_root=linked_parent / "private",
            project_root=project_root,
            phase="phase-3-live",
            release_id="unsafe-root",
            authority_sha256="e" * 64,
            records=_records(1),
            synthetic_unverified_test_only=True,
        )

    assert tuple(private_root.iterdir()) == ()
