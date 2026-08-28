from __future__ import annotations

from pathlib import Path

from app.config import Settings
from app.retrieval.subject_readiness import SubjectReadinessService


def test_subject_readiness_is_diagnostic_and_empty_without_active(
    tmp_path: Path, database: object
) -> None:
    settings = Settings(project_root=tmp_path)
    settings.ensure_runtime_dirs()

    snapshot = SubjectReadinessService(settings, database).snapshot()  # type: ignore[arg-type]

    assert snapshot.build_id is None
    assert snapshot.source_manifest_sha256 is None
    assert snapshot.diagnostic_only is True
    assert snapshot.subjects == ()
