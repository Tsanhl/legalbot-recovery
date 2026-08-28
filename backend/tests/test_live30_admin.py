from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.api.main import app
from app.crypto import LocalCipher
from app.evaluation.live30 import (
    Live30RunStore,
    RunProvenance,
    SensitiveArtifactKind,
    load_live30_suite,
)
from app.evaluation.live30_admin import (
    Live30AdminIntegrityError,
    Live30AdminReader,
)

REGISTRY = (
    Path(__file__).resolve().parents[2]
    / "benchmarks"
    / "evaluation"
    / "live-evaluation-30-v1"
    / "cases.jsonl"
)


def _created_store(tmp_path: Path, cipher: LocalCipher) -> tuple[Live30RunStore, str]:
    suite = load_live30_suite(REGISTRY)
    store = Live30RunStore(tmp_path, cipher)
    run_id = "live30-admin-fixture"
    store.create_run(
        run_id=run_id,
        suite=suite,
        provenance=RunProvenance(
            git_sha="abcdef0",
            git_dirty=False,
            model_version="fixture-model",
            index_build_id="fixture-build",
            prompt_version="fixture-prompt",
            router_version="fixture-router",
            classifier_version="fixture-classifier",
            policy_sha256="a" * 64,
            assessment_rules_sha256="b" * 64,
        ),
        as_of_date=date(2026, 8, 14),
    )
    return store, run_id


def _outcome(
    *,
    run_id: str,
    case_id: str,
    released: bool,
    artifact_id: str | None = None,
    answer_sha256: str | None = None,
) -> dict[str, object]:
    return {
        "schema": "legalbot.live30-execution-outcome.v1",
        "run_id": run_id,
        "case_id": case_id,
        "pass_number": 1,
        "job_id": f"job-{case_id}",
        "trace_id": f"trace-{case_id}",
        "status": "completed" if released else "held",
        "release_state": "verified_full" if released else "held",
        "released": released,
        "privacy_passed": True,
        "evidence_passed": released,
        "answer_artifact_id": artifact_id,
        "answer_sha256": answer_sha256,
        "word_count": 5 if released else None,
        "word_target": 1_000,
        "word_target_within_tolerance": False if released else None,
        "word_target_delta": -995 if released else None,
        "route": "sectioned",
        "assessment_bundle_sha256": "b" * 64,
        "assessment_rule_ids": ["structure.issue_spotting"],
        "triggered_assessment_rule_ids": [],
        "evidence": [],
        "rubric": [],
        "repairs": [],
        "failure_codes": [] if released else ["held_for_review"],
        "completion_duration_ms": 10,
    }


def test_empty_admin_feed_is_explicit_and_safe(tmp_path: Path, cipher: LocalCipher) -> None:
    reader = Live30AdminReader(Live30RunStore(tmp_path, cipher))

    assert reader.list_runs() == {"items": [], "invalid_run_count": 0}


def test_created_run_renders_all_thirty_as_not_run(tmp_path: Path, cipher: LocalCipher) -> None:
    store, run_id = _created_store(tmp_path, cipher)
    reader = Live30AdminReader(store)

    listing = reader.list_runs()
    assert len(listing["items"]) == 1
    assert listing["items"][0]["status"] == "not_started"
    detail = reader.run_detail(run_id)
    assert len(detail["cases"]) == 30
    assert {item["status"] for item in detail["cases"]} == {"not_run"}
    assert all("question" not in item for item in detail["cases"])


def test_only_released_digest_checked_answer_can_be_decrypted(
    tmp_path: Path, cipher: LocalCipher
) -> None:
    store, run_id = _created_store(tmp_path, cipher)
    reader = Live30AdminReader(store)
    content = "A short released fixture answer."
    artifact_id = "answer-released-fixture"
    store.store_sensitive_artifact(
        run_id=run_id,
        case_id="live30-q01",
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id=artifact_id,
        content=content,
    )
    store.store_safe_case_pass_json(
        run_id=run_id,
        case_id="live30-q01",
        pass_number=1,
        value=_outcome(
            run_id=run_id,
            case_id="live30-q01",
            released=True,
            artifact_id=artifact_id,
            answer_sha256=hashlib.sha256(content.encode()).hexdigest(),
        ),
    )

    answer = reader.released_answer(run_id=run_id, case_id="live30-q01", pass_number=1)
    assert answer["content"] == content
    assert answer["release_state"] == "verified_full"


def test_held_answer_artifact_is_never_decrypted_by_owner_feed(
    tmp_path: Path, cipher: LocalCipher
) -> None:
    store, run_id = _created_store(tmp_path, cipher)
    artifact_id = "answer-held-fixture"
    store.store_sensitive_artifact(
        run_id=run_id,
        case_id="live30-q02",
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id=artifact_id,
        content="This held draft must remain encrypted.",
    )
    store.store_safe_case_pass_json(
        run_id=run_id,
        case_id="live30-q02",
        pass_number=1,
        value=_outcome(
            run_id=run_id,
            case_id="live30-q02",
            released=False,
            artifact_id=artifact_id,
        ),
    )

    with pytest.raises(PermissionError, match="not a released"):
        Live30AdminReader(store).released_answer(run_id=run_id, case_id="live30-q02", pass_number=1)


def test_owner_detail_projects_only_safe_durable_repair_attempt_fields(
    tmp_path: Path, cipher: LocalCipher
) -> None:
    class RepairDatabase:
        @staticmethod
        def fetchall(sql: str, parameters: tuple[str]) -> list[dict[str, object]]:
            assert "encrypted_output" not in sql
            assert parameters == ("job-live30-q01",)
            return [
                {
                    "id": "repair-attempt-01",
                    "stage_key": "repair-01",
                    "section_key": "section-01",
                    "status": "complete",
                    "attempt_number": 1,
                    "error_code": None,
                }
            ]

    store, run_id = _created_store(tmp_path, cipher)
    store.store_safe_case_pass_json(
        run_id=run_id,
        case_id="live30-q01",
        pass_number=1,
        value=_outcome(run_id=run_id, case_id="live30-q01", released=False),
    )

    detail = Live30AdminReader(store, database=RepairDatabase()).run_detail(run_id)
    repairs = detail["cases"][0]["passes"][0]["repairs"]
    assert repairs == [
        {
            "repair_id": "repair-attempt-01",
            "section_id": "section-01",
            "reason_code": "quality_repair",
            "status": "complete",
            "attempt_count": 1,
        }
    ]


def test_released_answer_digest_mismatch_fails_closed(tmp_path: Path, cipher: LocalCipher) -> None:
    store, run_id = _created_store(tmp_path, cipher)
    artifact_id = "answer-tampered-fixture"
    store.store_sensitive_artifact(
        run_id=run_id,
        case_id="live30-q03",
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id=artifact_id,
        content="Changed content.",
    )
    store.store_safe_case_pass_json(
        run_id=run_id,
        case_id="live30-q03",
        pass_number=1,
        value=_outcome(
            run_id=run_id,
            case_id="live30-q03",
            released=True,
            artifact_id=artifact_id,
            answer_sha256="c" * 64,
        ),
    )

    with pytest.raises(Live30AdminIntegrityError, match="digest"):
        Live30AdminReader(store).released_answer(run_id=run_id, case_id="live30-q03", pass_number=1)


@pytest.mark.asyncio
async def test_owner_api_returns_an_explicit_empty_run_state(
    tmp_path: Path, cipher: LocalCipher
) -> None:
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=SimpleNamespace(project_root=tmp_path, owner_identifiers=[]),
        cipher=cipher,
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get("/api/v1/admin/live-evaluations")
        assert response.status_code == 200
        assert response.json() == {"items": [], "invalid_run_count": 0}
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_index_build_admin_dto_does_not_expose_local_path() -> None:
    class BuildDatabase:
        @staticmethod
        def admin_index_builds() -> list[dict[str, object]]:
            return [
                {
                    "id": "candidate-safe-id",
                    "status": "candidate",
                    "path": "/Users/owner/private/index",
                    "metrics_json": "{}",
                }
            ]

    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(database=BuildDatabase())
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get("/api/v1/admin/index-builds")
        assert response.status_code == 200
        assert response.json()["items"] == [
            {"id": "candidate-safe-id", "status": "candidate", "metrics": {}}
        ]
        assert "/Users/" not in response.text
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
