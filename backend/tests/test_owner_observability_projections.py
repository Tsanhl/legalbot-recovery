from __future__ import annotations

import json
import multiprocessing
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.config import Settings
from app.crypto import LocalCipher
from app.db import Database
from app.evaluation.live30 import RunProvenance
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.live_suite_store import LiveSuiteRunStore
from app.observability.events import EventStore, EventType
from app.observability.live_tracing import TraceLevel
from app.observability.projections import (
    OwnerProjectionWriter,
    assert_safe_projection_payload,
)
from app.observability.runtime import RuntimeObservability


def _policy_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "observability_slo.yaml"


def _append_projection_rows(root: str, worker: int, count: int) -> None:
    settings = Settings(project_root=Path(root), official_research_enabled=False)
    writer = OwnerProjectionWriter(settings)
    for offset in range(count):
        writer.append_research_metric(
            metric="candidates_total",
            value=1,
            event_id=f"metric-{worker:02d}-{offset:03d}",
            task_type="source_update_check",
            priority="medium",
            status="completed",
        )


def test_event_projection_is_prose_free_and_keeps_legacy_view(
    tmp_path: Path, database: Database
) -> None:
    store = EventStore(database, tmp_path / "logs")
    store.emit(
        event_type=EventType.OPERATIONAL_FAILURE.value,
        component="research_worker",
        stage="fetch",
        failure_code="remote_timeout",
        source_id="official-source-01",
        severity="error",
        retryable=True,
        blocking=False,
        user_or_owner_safe="A detailed owner-facing explanation is kept outside the projection.",
        internal_detail="private debugging prose",
    )

    legacy = tmp_path / "logs" / "operational-events.jsonl"
    projection = tmp_path / "logs" / "events" / "operational-events.jsonl"
    assert legacy.is_file()
    payload = json.loads(projection.read_text(encoding="utf-8"))
    assert payload["schema"] == "legalbot.owner-event-projection.v1"
    assert payload["failure_code"] == "remote_timeout"
    assert "user_or_owner_safe" not in payload
    assert "internal_detail" not in payload
    assert "private debugging prose" not in projection.read_text(encoding="utf-8")
    assert stat.S_IMODE(projection.stat().st_mode) == 0o600
    assert stat.S_IMODE(projection.parent.stat().st_mode) == 0o700
    ledger_projection = tmp_path / "logs" / "events" / "failure-ledger.jsonl"
    ledger_payload = json.loads(ledger_projection.read_text(encoding="utf-8"))
    assert ledger_payload["projection_kind"] == "failure_ledger"
    assert "user_or_owner_safe" not in ledger_payload
    assert "internal_detail" not in ledger_payload


def test_research_projection_sampling_and_safe_contract(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, official_research_enabled=False)
    settings.ensure_runtime_dirs()
    writer = OwnerProjectionWriter(settings)

    assert writer.append_research_trace(
        trace_id="trace-research-high",
        event_id="event-research-high",
        stage="fetch",
        status="running",
        duration_ms=2.5,
        task_id="research-task-high",
        source_id="official-source-01",
        priority="high",
        level=TraceLevel.INFO,
    )
    assert writer.append_research_trace(
        trace_id="trace-research-error",
        event_id="event-research-error",
        stage="validation",
        status="failed",
        duration_ms=4,
        task_id="research-task-error",
        priority="low",
        level=TraceLevel.ERROR,
        error_code="mime_invalid",
    )

    retained = 0
    for index in range(1_000):
        retained += int(
            writer.append_research_trace(
                trace_id=f"trace-routine-{index:04d}",
                event_id=f"event-routine-{index:04d}",
                stage="active_comparison",
                status="unchanged",
                duration_ms=1,
                task_id=f"research-routine-{index:04d}",
                priority="medium",
                level=TraceLevel.INFO,
            )
        )
    assert 80 <= retained <= 120

    path = settings.operational_traces_dir / "research.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == retained + 2
    assert all(row["stream"] == "research" for row in rows)
    assert not any("question" in json.dumps(row).casefold() for row in rows)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700

    with pytest.raises(ValueError, match="forbidden owner projection field"):
        assert_safe_projection_payload({"raw_question": "do not persist"})
    with pytest.raises(ValueError, match="unsafe projection source ID"):
        writer.append_research_trace(
            trace_id="trace-safe",
            event_id="event-safe",
            stage="fetch",
            status="running",
            duration_ms=1,
            source_id="source with prose",
            priority="high",
        )


def test_metric_projection_append_is_cross_process_safe(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, official_research_enabled=False)
    settings.ensure_runtime_dirs()
    context = multiprocessing.get_context("fork")
    workers = [
        context.Process(target=_append_projection_rows, args=(str(tmp_path), index, 25))
        for index in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)
        assert worker.exitcode == 0

    path = settings.operational_metrics_dir / "research.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 100
    assert len({row["event_id"] for row in rows}) == 100
    assert all(row["schema"] == "legalbot.owner-research-metric.v1" for row in rows)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_manifest_driven_live60_binding_and_full_owner_projection(tmp_path: Path) -> None:
    config_root = tmp_path / "config"
    config_root.mkdir()
    shutil.copy2(_policy_path(), config_root / "observability_slo.yaml")
    settings = Settings(project_root=tmp_path, official_research_enabled=False)
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    try:
        run_id = "live60-run-001"
        case_id = "live60-q31"
        project_root = Path(__file__).resolve().parents[2]
        bundle = load_live_evaluation_bundle(
            project_root / "benchmarks/evaluation/live-evaluation-60-v1"
        )
        question = bundle.registry.case(case_id).question
        LiveSuiteRunStore(tmp_path, LocalCipher(Fernet(Fernet.generate_key()))).create_run(
            run_id=run_id,
            bundle=bundle,
            provenance=RunProvenance(
                git_sha="a" * 40,
                git_dirty=False,
                model_version="test-model",
                index_build_id="test-index",
                prompt_version="test-prompt",
                router_version="test-router",
                classifier_version="test-classifier",
                policy_sha256="1" * 64,
                assessment_rules_sha256="2" * 64,
            ),
            admitted_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
        )

        runtime = RuntimeObservability(settings, database)
        runtime.writer.info_rate = 0
        runtime.validate_live_evaluation_binding(run_id, case_id, question)
        database.create_job(
            job_id="job-live60-q31",
            encrypted_question=b"encrypted",
            question_summary="Encrypted evaluation question",
            request={"task_type": "problem", "word_target": 1_000},
            route="sectioned",
            evaluation_run_id=run_id,
            evaluation_case_id=case_id,
            trace_full_retention=True,
            word_target=1_000,
        )
        row = database.job("job-live60-q31")
        assert row is not None
        runtime.record_intake(row)

        trace_projection = settings.operational_traces_dir / "live60.jsonl"
        projected = [
            json.loads(line) for line in trace_projection.read_text(encoding="utf-8").splitlines()
        ]
        assert projected[0]["case_id"] == case_id
        assert projected[0]["trace_id"] == row["trace_id"]
        assert question not in trace_projection.read_text(encoding="utf-8")

        metric_projection = settings.operational_metrics_dir / "live60.jsonl"
        metric = json.loads(metric_projection.read_text(encoding="utf-8").splitlines()[-1])
        assert metric["stream"] == "live60"
        assert metric["snapshot"]["schema"] == "legalbot.live-metrics-snapshot.v1"
        assert metric["slo"]["schema"] == "legalbot.observability-slo-evaluation.v1"
        assert stat.S_IMODE(trace_projection.stat().st_mode) == 0o600
        assert stat.S_IMODE(metric_projection.stat().st_mode) == 0o600
    finally:
        database.close()
