from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.config import Settings
from app.readiness import _a2_seal_is_valid, _candidate_integrity


def _write(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a2_readiness_validates_the_canonical_seal_location(tmp_path: Path) -> None:
    manifest = tmp_path / "data/evaluation/a2-intentional-abstention/manifest.jsonl"
    suite = tmp_path / "benchmarks/evaluation/v1/draft-suite.jsonl"
    summary = tmp_path / "data/evaluation/a2-intentional-abstention/summary.json"
    manifest_hash = _write(manifest, '{"id":"a2-001"}\n')
    suite_hash = _write(suite, '{"id":"a2-001"}\n')
    summary_hash = _write(summary, '{"case_count":1}\n')
    seal = {
        "schema": "legalbot.a2-batch-seal.v1",
        "status": "SEALED",
        "canonical_manifest_path": str(manifest.relative_to(tmp_path)),
        "canonical_manifest_sha256": manifest_hash,
        "suite_path": str(suite.relative_to(tmp_path)),
        "suite_file_sha256": suite_hash,
        "summary_path": str(summary.relative_to(tmp_path)),
        "summary_sha256": summary_hash,
    }
    seal_path = tmp_path / "data/evaluation/a2-intentional-abstention/seal.json"
    _write(seal_path, json.dumps(seal))

    assert _a2_seal_is_valid(Settings(project_root=tmp_path)) is True

    summary.write_text('{"case_count":2}\n', encoding="utf-8")
    assert _a2_seal_is_valid(Settings(project_root=tmp_path)) is False


def test_readiness_uses_sealed_evaluation_for_durable_candidate(
    tmp_path: Path, monkeypatch
) -> None:
    settings = Settings(project_root=tmp_path)
    build = settings.index_dir / "builds/durable-candidate"
    _write(build / "approved-source-manifest.json", "{}\n")
    _write(
        build / "evaluation.json",
        json.dumps(
            {
                "passed": True,
                "integrity": {"physical_lane_isolation": True},
            }
        ),
    )
    verified: list[str] = []
    monkeypatch.setattr(
        "app.retrieval.service._verify_sealed_build",
        lambda _settings, _database, row: verified.append(str(row["id"])),
    )

    assert _candidate_integrity(
        settings,
        object(),
        {
            "id": "durable-candidate",
            "metrics_json": json.dumps({"evaluation": {"passed": False}}),
        },
    ) == (True, True)
    assert verified == ["durable-candidate"]


def test_readiness_fails_closed_when_durable_seal_verification_fails(
    tmp_path: Path, monkeypatch
) -> None:
    settings = Settings(project_root=tmp_path)
    build = settings.index_dir / "builds/durable-candidate"
    _write(build / "approved-source-manifest.json", "{}\n")
    _write(
        build / "evaluation.json",
        json.dumps(
            {
                "passed": True,
                "integrity": {"physical_lane_isolation": True},
            }
        ),
    )

    def fail_verification(_settings, _database, _row) -> None:
        raise RuntimeError("changed seal")

    monkeypatch.setattr("app.retrieval.service._verify_sealed_build", fail_verification)

    assert _candidate_integrity(
        settings,
        object(),
        {"id": "durable-candidate", "metrics_json": "{}"},
    ) == (False, False)
