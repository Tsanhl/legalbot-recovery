from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet

from app.api.main import app
from app.crypto import LocalCipher
from app.evaluation.live30 import RunProvenance, SensitiveArtifactKind
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.live_suite_admin import (
    LiveSuiteAdminIntegrityError,
    LiveSuiteAdminReader,
)
from app.evaluation.live_suite_execute import Live60ExecutionOutcome
from app.evaluation.live_suite_store import LiveSuiteRunStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _prepared(tmp_path: Path) -> tuple[LiveSuiteRunStore, LiveSuiteAdminReader]:
    store = LiveSuiteRunStore(tmp_path / "project", LocalCipher(Fernet(Fernet.generate_key())))
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    store.create_run(
        run_id="live60-admin-test",
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="f" * 40,
            git_dirty=False,
            model_version="qwen-test",
            index_build_id="candidate-live60-admin",
            policy_sha256="1" * 64,
            assessment_rules_sha256="2" * 64,
        ),
        admitted_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    return store, LiveSuiteAdminReader(store)


def _gate_report_sha256(store: LiveSuiteRunStore, *, case_id: str) -> str:
    path = store.store_safe_case_json(
        run_id="live60-admin-test",
        case_id=case_id,
        filename="quality.json",
        value={
            "schema": "legalbot.live60-release-gate-report.v1",
            "run_id": "live60-admin-test",
            "case_id": case_id,
            "gates": {
                "privacy": True,
                "evidence": True,
                "currentness": True,
                "jurisdiction": True,
                "citation": True,
                "injection": True,
                "oscola": True,
            },
        },
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_admin_lists_manifest_derived_live60_counts_and_all_cases(
    tmp_path: Path,
) -> None:
    store, reader = _prepared(tmp_path)
    legacy = store.runs_root / "legacy-live30"
    legacy.mkdir(mode=0o700)
    (legacy / "manifest.json").write_text(
        json.dumps({"schema": "legalbot.e2e-run-manifest.v1"}), encoding="utf-8"
    )

    listed = reader.list_runs()
    assert listed["invalid_run_count"] == 0
    assert listed["skipped_legacy_run_count"] == 1
    assert len(listed["items"]) == 1
    summary = listed["items"][0]
    assert summary["expected_case_count"] == 60
    assert summary["expected_total_word_target"] == 215_000
    assert summary["selected_generation_case_count"] == 30
    assert summary["selected_generation_total_word_target"] == 114_000
    assert summary["coverage_only_case_count"] == 30

    detail = reader.run_detail("live60-admin-test")
    assert len(detail["cases"]) == 60
    q01 = detail["cases"][0]
    q02 = detail["cases"][1]
    assert q01["case_id"] == "live30-q01"
    assert q01["disposition"] == "coverage_only_not_selected"
    assert q01["status"] == "coverage_only_not_selected"
    assert q02["disposition"] == "generate_once"
    assert q02["status"] == "not_run"


def test_admin_decrypts_only_digest_and_hard_gate_passed_released_answer(
    tmp_path: Path,
) -> None:
    store, reader = _prepared(tmp_path)
    answer = "A released synthetic evaluation answer."
    artifact_id = "answer-live60-admin"
    store.store_sensitive_artifact(
        run_id="live60-admin-test",
        case_id="live30-q02",
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id=artifact_id,
        content=answer,
    )
    outcome = Live60ExecutionOutcome(
        outcome_id="outcome-live60-admin",
        run_id="live60-admin-test",
        case_id="live30-q02",
        pass_number=1,
        run_plan_disposition="generate_once",
        requested_word_target=1_000,
        expected_research_route="sectioned",
        terminal_state="released",
        released=True,
        answer_artifact_id=artifact_id,
        answer_sha256=hashlib.sha256(answer.encode()).hexdigest(),
        word_count=len(answer.split()),
        privacy_passed=True,
        evidence_passed=True,
        currentness_passed=True,
        jurisdiction_passed=True,
        citation_passed=True,
        injection_passed=True,
        oscola_passed=True,
        release_gate_report_sha256=_gate_report_sha256(store, case_id="live30-q02"),
        completed_at=datetime(2026, 8, 15, 9, 0, tzinfo=UTC),
    )
    store.store_safe_case_json(
        run_id="live60-admin-test",
        case_id="live30-q02",
        filename="outcome.json",
        value=outcome.model_dump(mode="json", by_alias=True),
    )

    visible = reader.released_answer(
        run_id="live60-admin-test", case_id="live30-q02", pass_number=1
    )
    assert visible["content"] == answer
    assert visible["release_state"] == "verified_full"
    with pytest.raises(LiveSuiteAdminIntegrityError):
        reader.released_answer(run_id="live60-admin-test", case_id="live30-q02", pass_number=2)


def test_admin_rechecks_owner_identifier_before_display(tmp_path: Path) -> None:
    store, _reader = _prepared(tmp_path)
    reader = LiveSuiteAdminReader(store, owner_identifiers=("private-owner-canary",))
    answer = "A released answer containing private-owner-canary."
    artifact_id = "answer-live60-private"
    store.store_sensitive_artifact(
        run_id="live60-admin-test",
        case_id="live30-q02",
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id=artifact_id,
        content=answer,
    )
    outcome = Live60ExecutionOutcome(
        outcome_id="outcome-live60-private",
        run_id="live60-admin-test",
        case_id="live30-q02",
        pass_number=1,
        run_plan_disposition="generate_once",
        requested_word_target=1_000,
        expected_research_route="sectioned",
        terminal_state="released",
        released=True,
        answer_artifact_id=artifact_id,
        answer_sha256=hashlib.sha256(answer.encode()).hexdigest(),
        word_count=len(answer.split()),
        privacy_passed=True,
        evidence_passed=True,
        currentness_passed=True,
        jurisdiction_passed=True,
        citation_passed=True,
        injection_passed=True,
        oscola_passed=True,
        release_gate_report_sha256=_gate_report_sha256(store, case_id="live30-q02"),
        completed_at=datetime(2026, 8, 15, 9, 0, tzinfo=UTC),
    )
    store.store_safe_case_json(
        run_id="live60-admin-test",
        case_id="live30-q02",
        filename="outcome.json",
        value=outcome.model_dump(mode="json", by_alias=True),
    )

    with pytest.raises(PermissionError):
        reader.released_answer(run_id="live60-admin-test", case_id="live30-q02", pass_number=1)


@pytest.mark.asyncio
async def test_owner_api_dispatches_v2_run_without_breaking_legacy_reader(
    tmp_path: Path,
) -> None:
    store, _reader = _prepared(tmp_path)
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=SimpleNamespace(
            project_root=store.project_root,
            owner_identifiers=(),
        ),
        cipher=store.cipher,
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8777",
        ) as client:
            listing = await client.get("/api/v1/admin/live-evaluations")
            detail = await client.get("/api/v1/admin/live-evaluations/live60-admin-test")
        assert listing.status_code == 200
        assert listing.json()["invalid_run_count"] == 0
        assert listing.json()["items"][0]["expected_case_count"] == 60
        assert detail.status_code == 200
        assert len(detail.json()["cases"]) == 60
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_owner_api_never_decrypts_superseded_released_answer_artifact(
    tmp_path: Path,
) -> None:
    store, _reader = _prepared(tmp_path)
    plaintext = "SUPERSEDED PRIVATE LEGACY ANSWER MUST STAY ENCRYPTED"
    artifact_id = "answer-superseded-api"
    store.store_sensitive_artifact(
        run_id="live60-admin-test",
        case_id="live30-q02",
        kind=SensitiveArtifactKind.ANSWER,
        artifact_id=artifact_id,
        content=plaintext,
    )
    outcome = Live60ExecutionOutcome(
        outcome_id="outcome-superseded-api",
        run_id="live60-admin-test",
        case_id="live30-q02",
        pass_number=1,
        run_plan_disposition="generate_once",
        requested_word_target=1_000,
        expected_research_route="sectioned",
        terminal_state="released",
        released=True,
        answer_artifact_id=artifact_id,
        answer_sha256=hashlib.sha256(plaintext.encode()).hexdigest(),
        word_count=len(plaintext.split()),
        privacy_passed=True,
        evidence_passed=True,
        currentness_passed=True,
        jurisdiction_passed=True,
        citation_passed=True,
        injection_passed=True,
        oscola_passed=True,
        release_gate_report_sha256=_gate_report_sha256(store, case_id="live30-q02"),
        completed_at=datetime(2026, 8, 15, 9, 0, tzinfo=UTC),
    )
    store.store_safe_case_json(
        run_id="live60-admin-test",
        case_id="live30-q02",
        filename="outcome.json",
        value=outcome.model_dump(mode="json", by_alias=True),
    )
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=SimpleNamespace(project_root=store.project_root, owner_identifiers=()),
        cipher=store.cipher,
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1:8777",
        ) as client:
            response = await client.get(
                "/api/v1/admin/live-evaluations/live60-admin-test/cases/live30-q02/passes/1/answer"
            )
        assert response.status_code == 503
        assert response.json()["detail"] == (
            "TECHNICAL_IMPLEMENTATION_REQUIRED:"
            "superseded_evaluation_release_content_certification_missing"
        )
        assert plaintext not in response.text
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous
