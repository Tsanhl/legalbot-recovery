"""Locally derive the exact quality implementation identities used by canaries.

These identities bind authorization to tracked implementation bytes.  They are
not caller assertions and they deliberately change when any covered source
module changes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final, NamedTuple

from .live_suite import sealed_sha256

QUALITY_IMPLEMENTATION_IDENTITY_SCHEMA: Final = "legalbot.owner-quality-implementation-identity.v1"

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_AI_REVIEWER_PATH = Path("backend/app/quality/ai_evidence_reviewer.py")
_EVALUATOR_PATH = Path("backend/app/quality/evaluator.py")
_STANDARDS_SCORER_PATH = Path("backend/app/assessment/standards_scoring.py")


class QualityImplementationIdentities(NamedTuple):
    ai_reviewer_sha256: str
    evaluator_sha256: str
    standards_scorer_sha256: str
    combined_sha256: str


def _tracked_file_sha256(relative_path: Path, *, project_root: Path) -> str:
    path = project_root / relative_path
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("quality implementation source is missing or unsafe")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quality_implementation_identities(
    *, project_root: Path = _PROJECT_ROOT
) -> QualityImplementationIdentities:
    """Return identities computed from local source bytes, never caller input."""

    ai_reviewer = _tracked_file_sha256(_AI_REVIEWER_PATH, project_root=project_root)
    evaluator = _tracked_file_sha256(_EVALUATOR_PATH, project_root=project_root)
    standards = _tracked_file_sha256(_STANDARDS_SCORER_PATH, project_root=project_root)
    combined = sealed_sha256(
        {
            "schema": QUALITY_IMPLEMENTATION_IDENTITY_SCHEMA,
            "ai_reviewer": {
                "path": _AI_REVIEWER_PATH.as_posix(),
                "sha256": ai_reviewer,
            },
            "evaluator": {
                "path": _EVALUATOR_PATH.as_posix(),
                "sha256": evaluator,
            },
            "standards_scorer": {
                "path": _STANDARDS_SCORER_PATH.as_posix(),
                "sha256": standards,
            },
        }
    )
    return QualityImplementationIdentities(
        ai_reviewer_sha256=ai_reviewer,
        evaluator_sha256=evaluator,
        standards_scorer_sha256=standards,
        combined_sha256=combined,
    )
