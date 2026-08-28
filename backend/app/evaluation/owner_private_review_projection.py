"""Readable, non-authorizing projection scaffolding for owner review.

The immutable evaluation/runtime packages remain the authority.  This module
only projects already-bound question/answer pairs into a private directory so
the owner can review one case at a time.  It deliberately has no sealed-
validation mode: validation output must stay inside its gated runner until the
one-pass policy permits disclosure.  Phase 1 permits synthetic projection tests
only; real inputs remain blocked until a typed strict upstream-package verifier
and signed lane-specific root are implemented in Phase 2.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ..privacy import contains_absolute_private_path
from .live_suite import sealed_sha256
from .secure_artifact_io import create_private_directory_at, write_private_file_at

OWNER_PRIVATE_REVIEW_PROJECTION_SCHEMA = "legalbot.owner-private-review-projection.v1"
OWNER_PRIVATE_REVIEW_COMPLETE_SCHEMA = "legalbot.owner-private-review-projection-complete.v1"

OwnerReviewPhase = Literal["phase-2-development", "phase-3-live"]

_SAFE_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class OwnerPrivateReviewRecord:
    """One exact question/answer pair already bound by upstream authority."""

    record_id: str
    question: str
    answer: str


@dataclass(frozen=True, slots=True)
class OwnerPrivateReviewProjection:
    """Identity of one complete readable projection."""

    relative_directory: str
    manifest_sha256: str
    complete_sha256: str
    record_count: int


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _markdown(title: str, body: str) -> bytes:
    return f"# {title}\n\n{body.rstrip()}\n".encode()


def _validate_private_root(*, private_root: Path, project_root: Path) -> None:
    if not private_root.is_absolute() or private_root.is_symlink() or not private_root.is_dir():
        raise ValueError("owner-review root is missing, relative, or unsafe")
    if any(component.is_symlink() for component in (private_root, *private_root.parents)):
        raise ValueError("owner-review root has a symlinked ancestor")
    resolved = private_root.resolve(strict=True)
    project = project_root.resolve(strict=True)
    if resolved == project or resolved.is_relative_to(project):
        raise ValueError("owner-review root must be outside the project worktree")
    if stat.S_IMODE(resolved.stat().st_mode) != 0o700:
        raise ValueError("owner-review root must have mode 0700")


def _validate_records(
    *, phase: OwnerReviewPhase, records: Sequence[OwnerPrivateReviewRecord]
) -> tuple[OwnerPrivateReviewRecord, ...]:
    if phase not in {"phase-2-development", "phase-3-live"}:
        raise ValueError("sealed or unknown owner-review phase is not projectable")
    frozen = tuple(records)
    if phase == "phase-2-development" and len(frozen) != 30:
        raise ValueError("Development owner review requires exactly 30 records")
    if phase == "phase-3-live" and not frozen:
        raise ValueError("live owner review requires at least one record")
    identifiers: set[str] = set()
    for record in frozen:
        if not _SAFE_ID.fullmatch(record.record_id):
            raise ValueError("owner-review record identity is unsafe")
        if record.record_id in identifiers:
            raise ValueError("owner-review record identities must be unique")
        identifiers.add(record.record_id)
        if not record.question.strip() or not record.answer.strip():
            raise ValueError("owner-review question and answer must be non-empty")
        if contains_absolute_private_path(record.question) or contains_absolute_private_path(
            record.answer
        ):
            raise ValueError("owner-review content contains an absolute private path")
    return frozen


def project_owner_private_review(
    *,
    private_root: Path,
    project_root: Path,
    phase: OwnerReviewPhase,
    release_id: str,
    authority_sha256: str,
    records: Sequence[OwnerPrivateReviewRecord],
    synthetic_unverified_test_only: bool = False,
) -> OwnerPrivateReviewProjection:
    """Test the create-only projection layout with explicitly synthetic input.

    Phase 1 deliberately has no real-input entry point. ``authority_sha256`` is
    only a synthetic fixture identity here: this function does not verify it and
    cannot approve, promote, unseal, or release anything. Phase 2 must replace
    this guard with a typed strict verifier bound to the signed lane root before
    any real Development or live record is projected.
    """

    if not synthetic_unverified_test_only:
        raise RuntimeError("trusted owner-review package verification is not implemented")
    _validate_private_root(private_root=private_root, project_root=project_root)
    if not _SAFE_ID.fullmatch(release_id):
        raise ValueError("owner-review release identity is unsafe")
    if not _SHA256.fullmatch(authority_sha256):
        raise ValueError("owner-review authority digest is invalid")
    frozen = _validate_records(phase=phase, records=records)

    directory = f"{phase}-{release_id}"
    create_private_directory_at(private_root, (directory,), exist_ok=False)
    create_private_directory_at(private_root, (directory, "cases"), exist_ok=False)

    manifest_records: list[dict[str, Any]] = []
    index_lines = [
        "# LegalBot owner review index",
        "",
        "This is a readable, non-authorizing projection of an immutable upstream package.",
        "Owner notes are working notes until separately captured by a signed owner decision.",
        "",
    ]
    for ordinal, record in enumerate(frozen, start=1):
        case_directory = f"{ordinal:02d}-{record.record_id}"
        case_parts = (directory, "cases", case_directory)
        create_private_directory_at(private_root, case_parts, exist_ok=False)
        question_bytes = _markdown("Question", record.question)
        answer_bytes = _markdown("Answer", record.answer)
        notes_bytes = (
            b"# Owner review notes\n\n"
            b"Status: not reviewed\n\n"
            b"## What is correct\n\n"
            b"\n\n## What needs correction\n\n"
            b"\n\n## Owner decision or feedback\n\n"
        )
        write_private_file_at(private_root, (*case_parts, "QUESTION.md"), question_bytes)
        write_private_file_at(private_root, (*case_parts, "ANSWER.md"), answer_bytes)
        write_private_file_at(private_root, (*case_parts, "OWNER-NOTES.md"), notes_bytes)
        manifest_records.append(
            {
                "ordinal": ordinal,
                "record_id": record.record_id,
                "question_sha256": hashlib.sha256(question_bytes).hexdigest(),
                "answer_sha256": hashlib.sha256(answer_bytes).hexdigest(),
                "question_text_sha256": _text_sha256(record.question),
                "answer_text_sha256": _text_sha256(record.answer),
            }
        )
        index_lines.extend(
            [
                f"## {ordinal:02d} — {record.record_id}",
                "",
                f"- [Question](cases/{case_directory}/QUESTION.md)",
                f"- [Answer](cases/{case_directory}/ANSWER.md)",
                f"- [Owner notes](cases/{case_directory}/OWNER-NOTES.md)",
                "",
            ]
        )

    manifest: dict[str, Any] = {
        "schema": OWNER_PRIVATE_REVIEW_PROJECTION_SCHEMA,
        "phase": phase,
        "release_id": release_id,
        "authority_sha256": authority_sha256,
        "record_count": len(manifest_records),
        "records": manifest_records,
        "authorizing": False,
        "sealed_validation_output": False,
        "synthetic_unverified_input": True,
    }
    manifest["seal_sha256"] = sealed_sha256(manifest)
    manifest_bytes = _canonical_json(manifest)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    write_private_file_at(private_root, (directory, "projection-manifest.json"), manifest_bytes)
    write_private_file_at(
        private_root,
        (directory, "00-OWNER-REVIEW-INDEX.md"),
        "\n".join(index_lines).encode(),
    )

    complete: dict[str, Any] = {
        "schema": OWNER_PRIVATE_REVIEW_COMPLETE_SCHEMA,
        "phase": phase,
        "release_id": release_id,
        "manifest_sha256": manifest_sha256,
        "record_count": len(manifest_records),
        "authorizing": False,
    }
    complete["seal_sha256"] = sealed_sha256(complete)
    complete_bytes = _canonical_json(complete)
    write_private_file_at(private_root, (directory, "PROJECTION-COMPLETE.json"), complete_bytes)
    return OwnerPrivateReviewProjection(
        relative_directory=directory,
        manifest_sha256=manifest_sha256,
        complete_sha256=hashlib.sha256(complete_bytes).hexdigest(),
        record_count=len(manifest_records),
    )
