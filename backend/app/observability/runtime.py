"""Runtime integration for privacy-safe local E2E metrics and traces.

Only identifiers, bounded taxonomy values, timestamps, durations and status
cross this boundary. Questions, answers, prompts, source text, original names,
paths and arbitrary diagnostic prose are intentionally absent from every API.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database
from .live_metrics import (
    LiveMetrics,
    SLOPolicy,
    assert_safe_snapshot,
    assess_progress_freshness,
    evaluate_slo,
    load_slo_policy,
)
from .live_tracing import (
    DatabaseOperation,
    SafeTraceWriter,
    TraceLevel,
    TraceOperation,
    TraceSpan,
    TraceStage,
    TraceStatus,
)
from .projections import OwnerProjectionWriter

_SAFE_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_LIVE_CASE_ID = re.compile(r"^(?:live30-q(?:0[1-9]|[12][0-9]|30)|live60-q(?:3[1-9]|[45][0-9]|60))$")
_SAFE_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_COMPONENTS = frozenset({"api", "worker"})
_TERMINAL_JOB_STATUSES = frozenset(
    {"complete", "held_for_review", "system_error", "failed", "dlq", "cancelled"}
)


@dataclass(frozen=True, slots=True)
class JobTraceContext:
    trace_id: str
    root_span_id: str
    job_id: str
    run_id: str | None
    case_id: str | None
    route: str
    word_target: int
    word_band: str
    full_retention: bool
    attempt: int


_CURRENT_CONTEXT: ContextVar[JobTraceContext | None] = ContextVar(
    "legalbot_observability_context", default=None
)


def _utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _safe_error_class(code: str | None) -> str:
    lowered = (code or "").casefold()
    if "timeout" in lowered or "deadline" in lowered:
        return "timeout"
    if "model" in lowered:
        return "model_unavailable"
    if "retriev" in lowered or "index" in lowered or "rerank" in lowered:
        return "retrieval_unavailable"
    if "schema" in lowered or "json" in lowered or "validation" in lowered:
        return "schema_invalid"
    if "privacy" in lowered or "pii" in lowered or "injection" in lowered:
        return "privacy"
    if "quality" in lowered or "evidence" in lowered or "citation" in lowered:
        return "quality_gate"
    if "database" in lowered or "sqlite" in lowered or "lock" in lowered:
        return "database"
    if "storage" in lowered or "object" in lowered or "disk" in lowered:
        return "storage"
    return "unknown"


def _trace_stage(stage: str) -> TraceStage:
    value = stage.casefold()
    mapping = {
        "queued": TraceStage.QUEUE,
        "researching": TraceStage.RETRIEVAL,
        "qualifying_evidence": TraceStage.EVIDENCE_FREEZE,
        "drafting": TraceStage.GENERATION,
        "verifying": TraceStage.VERIFICATION,
        "repairing": TraceStage.REPAIR,
        "assembling": TraceStage.ASSEMBLY,
        "complete": TraceStage.RELEASE,
        "limited": TraceStage.RELEASE,
        "held_for_review": TraceStage.RELEASE,
        "system_error": TraceStage.RELEASE,
        "cancelled": TraceStage.RELEASE,
    }
    return mapping.get(value, TraceStage.RUN)


def _metric_stage(stage: TraceStage) -> str:
    if stage in {TraceStage.RUN, TraceStage.HUMAN_REVIEW}:
        return "release"
    return stage.value


def _opaque_section_key(value: str | None) -> str | None:
    if value is None:
        return None
    if re.fullmatch(r"section-[0-9]{2,3}", value):
        return value
    return "direct"


def _terminal_metric_status(row: Mapping[str, Any]) -> str:
    status = str(row.get("status") or "")
    release = str(row.get("release_state") or "")
    if status == "complete":
        return "verified_limited" if release == "verified_limited" else "success"
    if status == "held_for_review":
        return "held_for_review"
    if status == "cancelled":
        return "cancelled"
    return "system_error"


def _atomic_safe_json(path: Path, value: Mapping[str, Any]) -> None:
    assert_safe_snapshot(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)


class RuntimeObservability:
    """One process-local metric registry plus a shared append-only trace sink."""

    def __init__(
        self,
        settings: Settings,
        database: Database,
        *,
        component: str = "api",
    ) -> None:
        if component not in _COMPONENTS:
            raise ValueError("observability component is not allowlisted")
        self.settings = settings
        self.database = database
        self.component = component
        self.policy: SLOPolicy = load_slo_policy(settings.observability_slo_path)
        self.metrics = LiveMetrics()
        sampling = self.policy.sampling
        self.writer = SafeTraceWriter.for_project(
            settings.project_root,
            info_rate=float(sampling["info_rate"]),
            debug_enabled=bool(sampling["debug_enabled"]),
            debug_rate=float(sampling["debug_rate"]),
        )
        self.projections = OwnerProjectionWriter(settings)
        self._last_snapshot_at = 0.0

    def set_component(self, component: str) -> None:
        if component not in _COMPONENTS:
            raise ValueError("observability component is not allowlisted")
        self.component = component
        if component == "worker":
            # Replace a possibly stale pre-crash worker snapshot immediately,
            # even when the restarted worker has no job to claim yet.
            self.metrics.set_gauge("workers_busy", labels={"worker_kind": "model"}, value=0)
            self.persist_snapshot(force=True)

    def _word_band(self, route: str, word_target: int) -> str:
        try:
            return self.policy.band_for(route=route, word_target=word_target).id
        except ValueError:
            # Non-suite questions can route by issue complexity outside the
            # provisional live-30 bands. Keep telemetry bounded without
            # changing routing or claiming that the target fell in the band.
            if route == "direct":
                return "direct_0100_1200"
            if route == "sectioned":
                return "sectioned_1000_2000" if word_target <= 2_000 else "sectioned_2001_5000"
            return "full_enquiry_3000_5000" if word_target <= 5_000 else "full_enquiry_5001_10000"

    def context_from_row(self, row: Mapping[str, Any] | sqlite3.Row) -> JobTraceContext:
        value = dict(row)
        route = str(value.get("route") or "direct")
        if route not in {"direct", "sectioned", "full_enquiry"}:
            route = "direct"
        word_target = int(value.get("word_target") or 1_500)
        return JobTraceContext(
            trace_id=str(value["trace_id"]),
            root_span_id=str(value["trace_root_span_id"]),
            job_id=str(value["id"]),
            run_id=(str(value["evaluation_run_id"]) if value.get("evaluation_run_id") else None),
            case_id=(str(value["evaluation_case_id"]) if value.get("evaluation_case_id") else None),
            route=route,
            word_target=word_target,
            word_band=self._word_band(route, word_target),
            full_retention=bool(value.get("trace_full_retention")),
            attempt=max(1, int(value.get("attempt_count") or 1)),
        )

    def context_for_job(self, job_id: str) -> JobTraceContext | None:
        row = self.database.job(job_id)
        return self.context_from_row(row) if row is not None else None

    @contextmanager
    def bind(self, context: JobTraceContext | None) -> Iterator[None]:
        token = _CURRENT_CONTEXT.set(context)
        try:
            yield
        finally:
            _CURRENT_CONTEXT.reset(token)

    @staticmethod
    def current_context() -> JobTraceContext | None:
        return _CURRENT_CONTEXT.get()

    def validate_live_evaluation_binding(self, run_id: str, case_id: str, question: str) -> None:
        """Validate a manifest-driven run/case digest before full retention.

        Live30 remains accepted as immutable history.  Live60 run manifests
        may contain both the preserved ``live30-q01`` through ``live30-q30``
        lineage and the new ``live60-q31`` through ``live60-q60`` records.
        """

        if not _SAFE_RUN_ID.fullmatch(run_id) or not _LIVE_CASE_ID.fullmatch(case_id):
            raise ValueError("invalid live evaluation identity")
        runs_root = (self.settings.e2e_observability_dir / "runs").resolve()
        run_root = (runs_root / run_id).resolve()
        if not run_root.is_relative_to(runs_root):
            raise ValueError("live evaluation identity escaped the run root")
        manifest_path = run_root / "manifest.json"
        case_path = run_root / "cases" / case_id / "case.json"
        if not manifest_path.is_file() or not case_path.is_file():
            raise ValueError("unknown live evaluation run or case")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        case = json.loads(case_path.read_text(encoding="utf-8"))
        suite_id = str(manifest.get("suite_id") or "")
        suite_contract_valid = True
        case_contract_valid = True
        if suite_id == "live-evaluation-30-v1":
            identity_matches_suite = case_id.startswith("live30-")
            expected_case_count = 30
        elif suite_id == "live-evaluation-60-v1":
            identity_matches_suite = bool(_LIVE_CASE_ID.fullmatch(case_id))
            expected_case_count = 60
            suite_path = run_root / "suite-manifest.json"
            plan_path = run_root / "generation-run-plan.json"
            if not suite_path.is_file() or not plan_path.is_file():
                raise ValueError("manifest-driven live evaluation snapshots are missing")
            from ..evaluation.live_suite import (
                LiveGenerationRunPlan,
                LiveSuiteManifest,
            )

            suite = LiveSuiteManifest.model_validate_json(suite_path.read_bytes())
            plan = LiveGenerationRunPlan.model_validate_json(plan_path.read_bytes())
            suite_contract_valid = bool(
                manifest.get("schema") == "legalbot.live-evaluation-run-manifest.v2"
                and manifest.get("suite_manifest_seal_sha256") == suite.seal_sha256
                and manifest.get("run_plan_seal_sha256") == plan.seal_sha256
                and suite.split == "development_live"
                and suite.purpose == "evaluation_only"
                and suite.eligible_for_training is False
                and suite.training_export_allowed is False
                and plan.purpose == "evaluation_only"
                and plan.eligible_for_training is False
                and plan.training_export_allowed is False
                and any(item.case_id == case_id for item in plan.cases)
            )
            case_contract_valid = bool(
                case.get("schema") == "legalbot.e2e-safe-case.v2"
                and case.get("disposition") in {"generate_once", "coverage_only_not_selected"}
            )
        else:
            identity_matches_suite = False
            expected_case_count = -1
        legacy_contract_fields_valid = (
            bool(
                manifest.get("split") == "development_live"
                and case.get("purpose") == "evaluation_only"
                and case.get("eligible_for_training") is False
                and case.get("training_export_allowed") is False
            )
            if suite_id == "live-evaluation-30-v1"
            else True
        )
        if (
            manifest.get("run_id") != run_id
            or not identity_matches_suite
            or not suite_contract_valid
            or not case_contract_valid
            or not legacy_contract_fields_valid
            or manifest.get("purpose") != "evaluation_only"
            or manifest.get("eligible_for_training") is not False
            or manifest.get("training_export_allowed") is not False
            or int(manifest.get("case_count", 0)) != expected_case_count
            or case.get("case_id") != case_id
        ):
            raise ValueError("live evaluation manifest contract is invalid")
        observed = hashlib.sha256(question.encode("utf-8")).hexdigest()
        if case.get("question_sha256") != observed:
            raise ValueError("question does not match the immutable live evaluation case")

    def validate_live30_binding(self, run_id: str, case_id: str, question: str) -> None:
        """Compatibility alias for sealed Live30 callers."""

        self.validate_live_evaluation_binding(run_id, case_id, question)

    def _append_span(
        self,
        context: JobTraceContext,
        *,
        operation: TraceOperation,
        stage: TraceStage,
        status: TraceStatus,
        level: TraceLevel,
        duration_seconds: float,
        db_operation: DatabaseOperation | None = None,
        section_key: str | None = None,
        error_code: str | None = None,
        root: bool = False,
    ) -> bool:
        safe_code = error_code if error_code and _SAFE_CODE.fullmatch(error_code) else None
        span = TraceSpan.create(
            trace_id=context.trace_id,
            span_id=context.root_span_id if root else None,
            parent_span_id=None if root else context.root_span_id,
            event_id=f"event-{uuid.uuid4().hex}",
            operation=operation,
            stage=stage,
            status=status,
            level=level,
            duration_ms=max(0.0, float(duration_seconds)) * 1_000,
            run_id=context.run_id,
            job_id=context.job_id,
            case_id=context.case_id,
            route=context.route,
            word_band=context.word_band,
            db_operation=db_operation,
            section_key=_opaque_section_key(section_key),
            attempt=context.attempt,
            error_code=safe_code,
        )
        retained = self.writer.append(span, force=context.full_retention)
        if retained:
            # The evaluation trace file above is authoritative.  This second
            # append is a disposable owner-viewable projection.
            self.projections.append_live_trace(span)
        return retained

    def record_intake(self, row: Mapping[str, Any]) -> None:
        context = self.context_from_row(row)
        labels = {"route": context.route, "word_band": context.word_band}
        self.metrics.increment("jobs_started_total", labels=labels)
        self._append_span(
            context,
            operation=TraceOperation.JOB,
            stage=TraceStage.INTAKE,
            status=TraceStatus.RUNNING,
            level=TraceLevel.INFO,
            duration_seconds=0,
            root=True,
        )
        self.persist_snapshot()

    def record_duration(
        self,
        context: JobTraceContext,
        *,
        metric: str | None,
        duration_seconds: float,
        operation: TraceOperation,
        stage: TraceStage,
        section_key: str | None = None,
        status: TraceStatus = TraceStatus.OK,
        level: TraceLevel = TraceLevel.INFO,
        error_code: str | None = None,
    ) -> None:
        labels = {"route": context.route, "word_band": context.word_band}
        if metric is not None:
            self.metrics.observe(metric, labels=labels, value=max(0, duration_seconds))
        self._append_span(
            context,
            operation=operation,
            stage=stage,
            status=status,
            level=level,
            duration_seconds=duration_seconds,
            section_key=section_key,
            error_code=error_code,
        )
        self.persist_snapshot()

    def record_db_duration(
        self,
        context: JobTraceContext,
        *,
        operation: DatabaseOperation,
        stage: TraceStage,
        duration_seconds: float,
        level: TraceLevel = TraceLevel.INFO,
        error_code: str | None = None,
    ) -> None:
        self._append_span(
            context,
            operation=TraceOperation.DATABASE,
            stage=stage,
            status=TraceStatus.ERROR if error_code else TraceStatus.OK,
            level=level,
            duration_seconds=duration_seconds,
            db_operation=operation,
            error_code=error_code,
        )

    def record_model_metrics(
        self,
        context: JobTraceContext,
        *,
        model_metrics: Mapping[str, Any] | None,
        wall_duration_seconds: float,
        stage: TraceStage,
        section_key: str,
    ) -> None:
        """Record one model call once, preferring sidecar generation timing.

        The span duration remains end-to-end wall time. ``generation_seconds``
        uses the sidecar's generation duration when supplied and otherwise the
        wall time; it is never recorded through both paths for the same call.
        """

        values = dict(model_metrics or {})
        labels = {"route": context.route, "word_band": context.word_band}

        def number(key: str) -> float | None:
            try:
                value = float(values[key])
            except (KeyError, TypeError, ValueError):
                return None
            return value if math.isfinite(value) and value >= 0 else None

        reported_generation_ms = number("generation_ms")
        generation_seconds = (
            reported_generation_ms / 1_000
            if reported_generation_ms is not None and reported_generation_ms > 0
            else max(0.0, wall_duration_seconds)
        )
        self.metrics.observe("generation_seconds", labels=labels, value=generation_seconds)

        for key, counter, histogram in (
            ("input_tokens", "model_input_tokens_total", "model_input_tokens"),
            ("output_tokens", "model_output_tokens_total", "model_output_tokens"),
        ):
            observed = number(key)
            if observed is not None:
                self.metrics.increment(counter, labels=labels, amount=observed)
                self.metrics.observe(histogram, labels=labels, value=observed)

        ttft_ms = number("time_to_first_token_ms")
        if ttft_ms is None:
            ttft_ms = number("ttft_ms")
        if ttft_ms is not None:
            self.metrics.observe(
                "time_to_first_token_seconds", labels=labels, value=ttft_ms / 1_000
            )
        peak_memory = number("peak_memory_gb")
        if peak_memory is not None:
            self.metrics.observe("peak_memory_gb", labels=labels, value=peak_memory)

        self._append_span(
            context,
            operation=TraceOperation.MODEL,
            stage=stage,
            status=TraceStatus.OK,
            level=TraceLevel.INFO,
            duration_seconds=wall_duration_seconds,
            section_key=section_key,
        )
        self.persist_snapshot()

    def record_progress(
        self,
        context: JobTraceContext,
        *,
        stage: str,
        db_duration_seconds: float | None = None,
    ) -> None:
        trace_stage = _trace_stage(stage)
        self.metrics.increment(
            "progress_events_total",
            labels={"route": context.route, "stage": _metric_stage(trace_stage)},
        )
        self.metrics.set_gauge(
            "progress_age_seconds",
            labels={"route": context.route, "word_band": context.word_band},
            value=0,
        )
        if db_duration_seconds is not None:
            self.record_db_duration(
                context,
                operation=DatabaseOperation.UPDATE_JOB,
                stage=trace_stage,
                duration_seconds=db_duration_seconds,
            )
        self.persist_snapshot()

    def record_queue_claim(
        self,
        row: Mapping[str, Any] | sqlite3.Row,
        *,
        db_duration_seconds: float,
    ) -> JobTraceContext:
        context = self.context_from_row(row)
        wait_seconds = max(0.0, (datetime.now(UTC) - _utc(str(row["created_at"]))).total_seconds())
        self.record_duration(
            context,
            metric="queue_wait_seconds",
            duration_seconds=wait_seconds,
            operation=TraceOperation.STAGE,
            stage=TraceStage.QUEUE,
        )
        self.record_db_duration(
            context,
            operation=DatabaseOperation.CLAIM_JOB,
            stage=TraceStage.QUEUE,
            duration_seconds=db_duration_seconds,
        )
        self.metrics.set_gauge("workers_busy", labels={"worker_kind": "model"}, value=1)
        return context

    def record_error(
        self,
        context: JobTraceContext,
        *,
        stage: TraceStage,
        error_code: str,
        duration_seconds: float = 0,
    ) -> None:
        safe_code = error_code if _SAFE_CODE.fullmatch(error_code) else "unknown_error"
        self.metrics.increment(
            "stage_errors_total",
            labels={
                "route": context.route,
                "stage": _metric_stage(stage),
                "error_class": _safe_error_class(safe_code),
            },
        )
        self._append_span(
            context,
            operation=TraceOperation.STAGE,
            stage=stage,
            status=TraceStatus.ERROR,
            level=TraceLevel.ERROR,
            duration_seconds=duration_seconds,
            error_code=safe_code,
        )
        self.persist_snapshot()

    def record_retry(self, context: JobTraceContext, *, stage: TraceStage) -> None:
        self.metrics.increment(
            "retries_total",
            labels={"route": context.route, "stage": _metric_stage(stage)},
        )

    def record_terminal(self, row: Mapping[str, Any] | sqlite3.Row) -> None:
        value = dict(row)
        if str(value.get("status")) not in _TERMINAL_JOB_STATUSES:
            return
        context = self.context_from_row(value)
        metric_status = _terminal_metric_status(value)
        labels = {"route": context.route, "word_band": context.word_band}
        self.metrics.increment("jobs_terminal_total", labels={**labels, "status": metric_status})
        if str(value.get("release_state") or "") in {
            "verified_full",
            "verified_concise",
            "verified_limited",
        }:
            self.metrics.increment(
                "releases_total", labels={"route": context.route, "status": metric_status}
            )
        completion = max(
            0.0, (datetime.now(UTC) - _utc(str(value.get("created_at") or ""))).total_seconds()
        )
        self.metrics.observe("completion_seconds", labels=labels, value=completion)
        self._append_span(
            context,
            operation=TraceOperation.JOB,
            stage=TraceStage.RELEASE,
            status=(
                TraceStatus.OK
                if metric_status in {"success", "verified_limited"}
                else TraceStatus.CANCELLED
                if metric_status == "cancelled"
                else TraceStatus.HELD
                if metric_status == "held_for_review"
                else TraceStatus.ERROR
            ),
            level=(
                TraceLevel.INFO
                if metric_status in {"success", "verified_limited", "cancelled"}
                else TraceLevel.ERROR
            ),
            # Completion latency is already a histogram. A terminal event is
            # zero-duration so it cannot masquerade as the slowest stage in
            # the per-job bottleneck view.
            duration_seconds=0,
            error_code=(
                str(value.get("error_code"))
                if metric_status == "system_error" and value.get("error_code")
                else None
            ),
        )
        self.metrics.set_gauge("workers_busy", labels={"worker_kind": "model"}, value=0)
        self.persist_snapshot(force=True)

    def _refresh_gauges(self) -> None:
        queue = self.database.job_queue_telemetry().get("by_class", {}).get("answer", {})
        self.metrics.set_gauge(
            "queue_depth", labels={"scope": "local"}, value=float(queue.get("queue_depth") or 0)
        )
        self.metrics.set_gauge(
            "oldest_job_age_seconds",
            labels={"scope": "local"},
            value=float(queue.get("oldest_age_seconds") or 0),
        )
        self.metrics.clear_gauge_metric("progress_age_seconds")
        maximum: dict[tuple[str, str], float] = {}
        now = datetime.now(UTC)
        for row in self.database.observability_jobs(active_only=True):
            context = self.context_from_row(row)
            age = max(
                0.0, (now - _utc(str(row["last_progress_at"] or row["updated_at"]))).total_seconds()
            )
            key = (context.route, context.word_band)
            maximum[key] = max(age, maximum.get(key, 0.0))
        for (route, word_band), age in maximum.items():
            self.metrics.set_gauge(
                "progress_age_seconds",
                labels={"route": route, "word_band": word_band},
                value=age,
            )

    def persist_snapshot(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_snapshot_at < 0.25:
            return
        self._refresh_gauges()
        snapshot = self.metrics.snapshot()
        slo = evaluate_slo(snapshot, self.policy)
        _atomic_safe_json(
            self.settings.live_metrics_dir / f"snapshot-{self.component}.json", snapshot
        )
        _atomic_safe_json(self.settings.live_metrics_dir / f"slo-{self.component}.json", slo)
        # Source snapshots are committed first.  The JSONL line is a derived
        # owner view and can be rebuilt or discarded independently.
        self.projections.append_live_metric(
            component=self.component,
            snapshot=snapshot,
            slo=slo,
        )
        self._last_snapshot_at = now

    def admin_view(self) -> dict[str, Any]:
        """Return a fixed safe DTO for the loopback-only admin endpoint."""

        self.persist_snapshot(force=True)
        snapshots: list[dict[str, Any]] = []
        slo_evaluations: list[dict[str, Any]] = []
        for component in sorted(_COMPONENTS):
            snapshot_path = self.settings.live_metrics_dir / f"snapshot-{component}.json"
            slo_path = self.settings.live_metrics_dir / f"slo-{component}.json"
            if snapshot_path.is_file():
                value = json.loads(snapshot_path.read_text(encoding="utf-8"))
                assert_safe_snapshot(value)
                snapshots.append({"component": component, "snapshot": value})
            if slo_path.is_file():
                value = json.loads(slo_path.read_text(encoding="utf-8"))
                assert_safe_snapshot(value)
                slo_evaluations.append({"component": component, "evaluation": value})

        active_jobs: list[dict[str, Any]] = []
        now = datetime.now(UTC)
        for row in self.database.observability_jobs(active_only=True):
            context = self.context_from_row(row)
            last_progress = _utc(str(row["last_progress_at"] or row["updated_at"]))
            try:
                progress = assess_progress_freshness(
                    self.policy,
                    route=context.route,
                    word_target=context.word_target,
                    last_progress_at=last_progress,
                    now=now,
                )
                progress_state = progress.state
                progress_age = progress.age_seconds
            except ValueError:
                progress_state = "unbanded"
                progress_age = round(max(0.0, (now - last_progress).total_seconds()), 6)
            active_jobs.append(
                {
                    "job_id": context.job_id,
                    "trace_id": context.trace_id,
                    "run_id": context.run_id,
                    "case_id": context.case_id,
                    "status": str(row["status"]),
                    "stage": str(row["stage"]),
                    "progress": float(row["progress"]),
                    "route": context.route,
                    "word_target": context.word_target,
                    "word_band": context.word_band,
                    "trace_retention": "full" if context.full_retention else "sampled",
                    "last_progress_at": last_progress.isoformat(),
                    "progress_age_seconds": progress_age,
                    "progress_state": progress_state,
                    "attempt": context.attempt,
                }
            )
        return {
            "schema": "legalbot.admin-observability.v1",
            "policy": {
                "policy_id": self.policy.policy_id,
                "internal_only": True,
                "external_sla": self.policy.external_sla,
                "provisional": self.policy.provisional,
                "baseline_calibrated": self.policy.baseline_calibrated,
                "enforcement": self.policy.enforcement,
                "default_sampling": "debug_off_info_10_warn_error_fatal_100",
                "live_evaluation_retention": ("full_after_manifest_and_question_digest_validation"),
                "live30_retention": "full_after_manifest_and_digest_validation",
            },
            "snapshots": snapshots,
            "slo_evaluations": slo_evaluations,
            "active_jobs": active_jobs,
        }

    def trace_summary(self, job_id: str) -> dict[str, Any]:
        """Summarise a job's retained safe spans without exposing trace storage."""

        row = self.database.job(job_id)
        if row is None:
            raise LookupError("unknown job")
        context = self.context_from_row(row)
        spans = sorted(
            (span for span in self.writer.read() if span.trace_id == context.trace_id),
            key=lambda span: (span.timestamp, span.span_id),
        )
        ordered = [
            {
                "sequence": index,
                "timestamp": span.timestamp.astimezone(UTC).isoformat(),
                "operation": span.operation.value,
                "stage": span.stage.value,
                "section_key": span.section_key,
                "duration_ms": round(span.duration_ms, 3),
                "status": span.status.value,
                "level": span.level.value,
                "db_operation": span.db_operation.value if span.db_operation else None,
                "attempt": span.attempt,
                "error_code": span.error_code,
            }
            for index, span in enumerate(spans, start=1)
        ]
        totals: dict[str, float] = {}
        for span in spans:
            key = span.stage.value
            totals[key] = totals.get(key, 0.0) + span.duration_ms
        stage_totals = [
            {"stage": stage, "duration_ms": round(duration, 3)}
            for stage, duration in sorted(totals.items(), key=lambda item: (-item[1], item[0]))
        ]
        longest = max(spans, key=lambda span: span.duration_ms, default=None)
        return {
            "schema": "legalbot.admin-trace-summary.v1",
            "job_id": context.job_id,
            "trace_id": context.trace_id,
            "run_id": context.run_id,
            "case_id": context.case_id,
            "trace_retention": "full" if context.full_retention else "sampled",
            "span_count": len(spans),
            "spans": ordered,
            "stage_totals": stage_totals,
            "bottleneck_stage": stage_totals[0] if stage_totals else None,
            "longest_span": (
                {
                    "operation": longest.operation.value,
                    "stage": longest.stage.value,
                    "section_key": longest.section_key,
                    "duration_ms": round(longest.duration_ms, 3),
                    "status": longest.status.value,
                    "db_operation": longest.db_operation.value if longest.db_operation else None,
                }
                if longest is not None
                else None
            ),
        }
