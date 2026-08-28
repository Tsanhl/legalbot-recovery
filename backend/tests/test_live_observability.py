from __future__ import annotations

import hashlib
import json
import shutil
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.config import Settings
from app.db import Database
from app.observability.live_metrics import (
    HISTOGRAM_LABELS,
    LiveMetrics,
    assert_safe_snapshot,
    assess_progress_freshness,
    evaluate_slo,
    load_slo_policy,
    percentile,
)
from app.observability.live_tracing import (
    DatabaseOperation,
    SafeTraceWriter,
    TraceLevel,
    TraceOperation,
    TraceSpan,
    TraceStage,
    TraceStatus,
    assert_safe_trace_payload,
    deterministic_sample,
    validate_trace_graph,
)
from app.observability.runtime import RuntimeObservability


def _policy_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "observability_slo.yaml"


def _span(
    *,
    span_id: str,
    parent_span_id: str | None,
    operation: TraceOperation = TraceOperation.STAGE,
    db_operation: DatabaseOperation | None = None,
    level: TraceLevel = TraceLevel.INFO,
) -> TraceSpan:
    return TraceSpan.create(
        trace_id="trace-live30-001",
        event_id=f"event-{span_id}",
        span_id=span_id,
        parent_span_id=parent_span_id,
        operation=operation,
        stage=TraceStage.RETRIEVAL,
        status=TraceStatus.OK,
        level=level,
        duration_ms=12.5,
        run_id="run-live30-001",
        job_id="job-live30-001",
        case_id="live30-q01",
        route="sectioned",
        word_band="sectioned_1000_2000",
        db_operation=db_operation,
        section_key="section-01",
        attempt=1,
    )


def test_info_sampling_is_deterministic_near_ten_percent_and_severity_safe() -> None:
    first = [
        deterministic_sample(
            TraceLevel.INFO,
            trace_id=f"trace-{index:05d}",
            event_id=f"event-{index:05d}",
        )
        for index in range(10_000)
    ]
    second = [
        deterministic_sample(
            TraceLevel.INFO,
            trace_id=f"trace-{index:05d}",
            event_id=f"event-{index:05d}",
        )
        for index in range(10_000)
    ]
    assert first == second
    assert 0.08 <= sum(first) / len(first) <= 0.12
    assert not deterministic_sample(
        TraceLevel.DEBUG, trace_id="trace-debug", event_id="event-debug"
    )
    for level in (TraceLevel.WARN, TraceLevel.ERROR, TraceLevel.FATAL):
        assert deterministic_sample(level, trace_id="trace-severe", event_id=f"event-{level.value}")


def test_metrics_reject_high_cardinality_and_trace_rejects_sensitive_prose() -> None:
    metrics = LiveMetrics()
    with pytest.raises(ValueError, match="high-cardinality"):
        metrics.increment(
            "jobs_started_total",
            labels={
                "route": "sectioned",
                "word_band": "sectioned_1000_2000",
                "trace_id": "trace-private",
            },
        )
    with pytest.raises(ValueError, match="error code"):
        TraceSpan.create(
            trace_id="trace-private",
            event_id="event-private",
            operation=TraceOperation.STAGE,
            stage=TraceStage.GENERATION,
            status=TraceStatus.ERROR,
            level=TraceLevel.ERROR,
            duration_ms=1,
            error_code="secret at /Users/owner/private.txt",
        )
    with pytest.raises(ValueError, match="forbidden safe-trace field"):
        assert_safe_trace_payload({"raw_question": "private"})
    with pytest.raises(ValueError, match="forbidden metric snapshot field"):
        assert_safe_snapshot({"source_text": "private"})


def test_parent_child_trace_graph_and_append_only_safe_writer(tmp_path: Path) -> None:
    root = _span(span_id="span-root", parent_span_id=None, level=TraceLevel.WARN)
    child = _span(
        span_id="span-child",
        parent_span_id=root.span_id,
        operation=TraceOperation.DATABASE,
        db_operation=DatabaseOperation.INDEX_READ,
        level=TraceLevel.WARN,
    )
    grandchild = _span(
        span_id="span-grandchild",
        parent_span_id=child.span_id,
        level=TraceLevel.WARN,
    )
    report = validate_trace_graph((root, child, grandchild))
    assert report["valid"] is True
    assert report["traces"][0]["maximum_depth"] == 3

    writer = SafeTraceWriter(tmp_path / "data" / "evaluations" / "e2e" / "traces")
    assert writer.append(root)
    assert writer.append(child)
    assert writer.append(grandchild)
    assert writer.read() == (root, child, grandchild)
    assert stat.S_IMODE(writer.path.stat().st_mode) == 0o600
    payload = writer.path.read_text()
    assert len(payload.splitlines()) == 3
    assert "/Users/" not in payload
    assert "question" not in payload
    assert all(json.loads(line)["schema"] for line in payload.splitlines())

    orphan = _span(span_id="span-orphan", parent_span_id="span-missing")
    with pytest.raises(ValueError, match="orphan"):
        validate_trace_graph((root, orphan))


def test_force_retention_bypasses_info_sampling_only_when_runtime_requests_it(
    tmp_path: Path,
) -> None:
    writer = SafeTraceWriter(tmp_path / "traces", info_rate=0)
    root = _span(span_id="span-forced-root", parent_span_id=None)
    assert writer.append(root) is False
    assert writer.append(root, force=True) is True
    assert writer.read() == (root,)


def test_progress_freshness_transitions_to_stale_then_stuck() -> None:
    policy = load_slo_policy(_policy_path())
    assert policy.policy_id == "local-e2e-provisional-v2"
    assert policy.calibration_suite_id == "live-evaluation-60-v1"
    now = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
    fresh = assess_progress_freshness(
        policy,
        route="full_enquiry",
        word_target=8_000,
        last_progress_at=now - timedelta(seconds=100),
        now=now,
    )
    stale = assess_progress_freshness(
        policy,
        route="full_enquiry",
        word_target=8_000,
        last_progress_at=now - timedelta(seconds=600),
        now=now,
    )
    stuck = assess_progress_freshness(
        policy,
        route="full_enquiry",
        word_target=8_000,
        last_progress_at=now - timedelta(seconds=901),
        now=now,
    )
    assert (fresh.state, stale.state, stuck.state) == ("fresh", "stale", "stuck")


def test_percentiles_and_histogram_snapshot_are_deterministic() -> None:
    values = [float(value) for value in range(1, 101)]
    assert percentile(values, 0.50) == 50.5
    assert percentile(values, 0.95) == 95.05
    assert percentile(values, 0.99) == 99.01

    metrics = LiveMetrics()
    labels = {"route": "sectioned", "word_band": "sectioned_1000_2000"}
    for value in values:
        metrics.observe("retrieval_seconds", labels=labels, value=value)
    row = metrics.snapshot(generated_at=datetime(2026, 8, 14, tzinfo=UTC))["histograms"][0]
    assert (row["p50"], row["p95"], row["p99"]) == (50.5, 95.05, 99.01)


def test_provisional_slo_evaluation_covers_stages_queue_success_and_error_budget() -> None:
    policy = load_slo_policy(_policy_path())
    assert policy.external_sla is False
    assert policy.provisional is True
    assert policy.baseline_calibrated is False
    assert policy.enforcement == "observe_only"
    assert policy.sampling["info_rate"] == 0.10
    assert policy.sampling["debug_enabled"] is False
    assert policy.minimum_successful_runs_per_band == 3

    metrics = LiveMetrics()
    labels = {"route": "sectioned", "word_band": "sectioned_1000_2000"}
    metrics.set_gauge("queue_depth", labels={"scope": "local"}, value=1)
    metrics.set_gauge("oldest_job_age_seconds", labels={"scope": "local"}, value=10)
    metrics.set_gauge("progress_age_seconds", labels=labels, value=30)
    for metric in HISTOGRAM_LABELS:
        for value in (1, 2, 3, 4, 5):
            metrics.observe(metric, labels=labels, value=value)
    for _ in range(19):
        metrics.increment("jobs_terminal_total", labels={**labels, "status": "success"})
    metrics.increment("jobs_terminal_total", labels={**labels, "status": "held_for_review"})
    snapshot = metrics.snapshot(generated_at=datetime(2026, 8, 14, tzinfo=UTC))
    report = evaluate_slo(snapshot, policy)
    assert report["gate_eligible"] is False
    assert report["evaluation_complete"] is True
    assert report["within_provisional_targets"] is True
    success = next(check for check in report["checks"] if check["metric"] == "success_rate")
    budget = next(check for check in report["checks"] if check["metric"] == "error_budget_fraction")
    assert success["observed"] == pytest.approx(0.95)
    assert budget["observed"] == pytest.approx(0.05)

    metrics.set_gauge("queue_depth", labels={"scope": "local"}, value=9)
    breached = evaluate_slo(metrics.snapshot(), policy)
    assert breached["evaluation_complete"] is True
    assert breached["within_provisional_targets"] is False


def test_slo_does_not_claim_a_percentile_result_from_one_latency_sample() -> None:
    policy = load_slo_policy(_policy_path())
    metrics = LiveMetrics()
    labels = {"route": "sectioned", "word_band": "sectioned_1000_2000"}
    metrics.observe("generation_seconds", labels=labels, value=1.0)

    report = evaluate_slo(metrics.snapshot(), policy)
    generation = next(
        check
        for check in report["checks"]
        if check["metric"] == "generation_seconds" and check["scope"] == "sectioned_1000_2000"
    )
    assert generation["state"] == "insufficient_samples"
    assert generation["samples"] == 1
    assert generation["minimum_samples"] == policy.minimum_latency_samples
    assert generation["successful_runs"] == 0
    assert generation["minimum_successful_runs"] == 3
    assert generation["passed"] is None
    assert report["evaluation_complete"] is False
    assert report["within_provisional_targets"] is False


def test_slo_policy_resolves_overlapping_word_ranges_by_route() -> None:
    policy = load_slo_policy(_policy_path())
    assert policy.band_for(route="sectioned", word_target=4_000).id == "sectioned_2001_5000"
    assert policy.band_for(route="full_enquiry", word_target=4_000).id == "full_enquiry_3000_5000"
    with pytest.raises(ValueError, match="does not resolve"):
        policy.band_for(route="direct", word_target=5_000)


def test_runtime_live30_binding_full_trace_metrics_and_safe_bottleneck(
    tmp_path: Path,
) -> None:
    config_root = tmp_path / "config"
    config_root.mkdir()
    shutil.copy2(_policy_path(), config_root / "observability_slo.yaml")
    settings = Settings(project_root=tmp_path, official_research_enabled=False)
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    try:
        question = "A sufficiently difficult but private legal evaluation question."
        digest = hashlib.sha256(question.encode()).hexdigest()
        run_id = "live30-run-001"
        case_id = "live30-q01"
        case_root = settings.e2e_observability_dir / "runs" / run_id / "cases" / case_id
        case_root.mkdir(parents=True)
        (case_root.parents[1] / "manifest.json").write_text(
            json.dumps(
                {
                    "run_id": run_id,
                    "suite_id": "live-evaluation-30-v1",
                    "split": "development_live",
                    "purpose": "evaluation_only",
                    "eligible_for_training": False,
                    "training_export_allowed": False,
                    "case_count": 30,
                }
            )
        )
        (case_root / "case.json").write_text(
            json.dumps(
                {
                    "case_id": case_id,
                    "question_sha256": digest,
                    "purpose": "evaluation_only",
                    "eligible_for_training": False,
                    "training_export_allowed": False,
                }
            )
        )

        runtime = RuntimeObservability(settings, database)
        runtime.writer.info_rate = 0
        runtime.validate_live30_binding(run_id, case_id, question)
        with pytest.raises(ValueError, match="question does not match"):
            runtime.validate_live30_binding(run_id, case_id, question + " changed")

        database.create_job(
            job_id="job-live30-q01",
            encrypted_question=b"encrypted-not-plaintext",
            question_summary="Private encrypted question",
            request={"task_type": "problem", "word_target": 1_000},
            route="sectioned",
            evaluation_run_id=run_id,
            evaluation_case_id=case_id,
            trace_full_retention=True,
            word_target=1_000,
        )
        row = database.job("job-live30-q01")
        assert row is not None
        assert row["trace_id"].startswith("trace-")
        assert row["trace_root_span_id"].startswith("span-")
        assert row["last_progress_at"]
        context = runtime.context_from_row(row)
        runtime.record_intake(row)
        runtime.record_duration(
            context,
            metric="retrieval_seconds",
            duration_seconds=0.4,
            operation=TraceOperation.RETRIEVAL,
            stage=TraceStage.RETRIEVAL,
            section_key="section-01",
        )
        runtime.record_duration(
            context,
            metric="rerank_seconds",
            duration_seconds=0.2,
            operation=TraceOperation.RERANK,
            stage=TraceStage.RERANK,
            section_key="section-01",
        )
        runtime.record_model_metrics(
            context,
            model_metrics={
                "input_tokens": 120,
                "output_tokens": 80,
                "generation_ms": 2_000,
                "time_to_first_token_ms": 250,
                "peak_memory_gb": 4.5,
            },
            wall_duration_seconds=9,
            stage=TraceStage.GENERATION,
            section_key="section-01",
        )
        runtime.record_duration(
            context,
            metric="verification_seconds",
            duration_seconds=0.3,
            operation=TraceOperation.VERIFICATION,
            stage=TraceStage.VERIFICATION,
            section_key="section-01",
        )
        runtime.record_duration(
            context,
            metric=None,
            duration_seconds=0.1,
            operation=TraceOperation.MODEL,
            stage=TraceStage.REPAIR,
            section_key="section-01",
        )
        database.update_job(
            context.job_id,
            status="complete",
            stage="complete",
            progress=1,
            message="safe status",
            release_state="verified_full",
        )
        terminal = database.job(context.job_id)
        assert terminal is not None
        runtime.record_terminal(terminal)

        retained = tuple(
            span for span in runtime.writer.read() if span.trace_id == context.trace_id
        )
        assert len(retained) >= 7
        assert validate_trace_graph(retained)["valid"] is True
        summary = runtime.trace_summary(context.job_id)
        assert summary["trace_retention"] == "full"
        assert summary["longest_span"]["stage"] == "generation"
        assert summary["longest_span"]["section_key"] == "section-01"
        safe_text = json.dumps(summary)
        assert question not in safe_text
        assert "/Users/" not in safe_text

        snapshot = runtime.metrics.snapshot()
        histogram = {row["metric"]: row for row in snapshot["histograms"]}
        # The sidecar generation duration is used once; the 9-second wall
        # duration remains visible only in the trace span.
        assert histogram["generation_seconds"]["count"] == 1
        assert histogram["generation_seconds"]["p50"] == 2.0
        assert histogram["time_to_first_token_seconds"]["p50"] == 0.25
        assert histogram["peak_memory_gb"]["p50"] == 4.5
        counters = {row["metric"]: row["value"] for row in snapshot["counters"]}
        assert counters["model_input_tokens_total"] == 120
        assert counters["model_output_tokens_total"] == 80
    finally:
        database.close()
