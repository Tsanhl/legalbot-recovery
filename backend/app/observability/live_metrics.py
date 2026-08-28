"""Low-cardinality local-live metrics and provisional SLO evaluation.

The registry is deliberately dependency-light and process-local. Runtime code
may periodically persist or expose ``snapshot()``; this module never records a
question, answer, source text, filename, filesystem path or per-user label.
"""

from __future__ import annotations

import math
import threading
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

COUNTER_LABELS: dict[str, frozenset[str]] = {
    "jobs_started_total": frozenset({"route", "word_band"}),
    "jobs_terminal_total": frozenset({"route", "word_band", "status"}),
    "stage_errors_total": frozenset({"route", "stage", "error_class"}),
    "retries_total": frozenset({"route", "stage"}),
    "releases_total": frozenset({"route", "status"}),
    "progress_events_total": frozenset({"route", "stage"}),
    "model_input_tokens_total": frozenset({"route", "word_band"}),
    "model_output_tokens_total": frozenset({"route", "word_band"}),
}
GAUGE_LABELS: dict[str, frozenset[str]] = {
    "queue_depth": frozenset({"scope"}),
    "oldest_job_age_seconds": frozenset({"scope"}),
    "progress_age_seconds": frozenset({"route", "word_band"}),
    "workers_busy": frozenset({"worker_kind"}),
}
HISTOGRAM_LABELS: dict[str, frozenset[str]] = {
    "queue_wait_seconds": frozenset({"route", "word_band"}),
    "retrieval_seconds": frozenset({"route", "word_band"}),
    "rerank_seconds": frozenset({"route", "word_band"}),
    "generation_seconds": frozenset({"route", "word_band"}),
    "verification_seconds": frozenset({"route", "word_band"}),
    "release_seconds": frozenset({"route", "word_band"}),
    "completion_seconds": frozenset({"route", "word_band"}),
    "time_to_first_token_seconds": frozenset({"route", "word_band"}),
}
MODEL_HISTOGRAM_LABELS: dict[str, frozenset[str]] = {
    "model_input_tokens": frozenset({"route", "word_band"}),
    "model_output_tokens": frozenset({"route", "word_band"}),
    "peak_memory_gb": frozenset({"route", "word_band"}),
}
ALL_HISTOGRAM_LABELS = {**HISTOGRAM_LABELS, **MODEL_HISTOGRAM_LABELS}

WORD_BANDS = frozenset(
    {
        "direct_0100_1200",
        "sectioned_1000_2000",
        "sectioned_2001_5000",
        "full_enquiry_3000_5000",
        "full_enquiry_5001_10000",
    }
)
LABEL_VALUES: dict[str, frozenset[str]] = {
    "route": frozenset({"direct", "sectioned", "full_enquiry"}),
    "word_band": WORD_BANDS,
    "status": frozenset(
        {
            "success",
            "verified_limited",
            "held_for_review",
            "system_error",
            "cancelled",
        }
    ),
    "stage": frozenset(
        {
            "intake",
            "routing",
            "queue",
            "retrieval",
            "rerank",
            "evidence_freeze",
            "generation",
            "verification",
            "repair",
            "assembly",
            "release",
        }
    ),
    "error_class": frozenset(
        {
            "timeout",
            "model_unavailable",
            "retrieval_unavailable",
            "schema_invalid",
            "storage",
            "database",
            "privacy",
            "quality_gate",
            "unknown",
        }
    ),
    "scope": frozenset({"local"}),
    "worker_kind": frozenset({"model", "retrieval", "verification"}),
}

_FORBIDDEN_KEYS = frozenset(
    {
        "trace_id",
        "event_id",
        "job_id",
        "case_id",
        "user_id",
        "source_id",
        "chunk_id",
        "question",
        "raw_question",
        "answer",
        "source_text",
        "prompt",
        "path",
        "filename",
        "section_key",
    }
)


def percentile(values: Sequence[float], fraction: float) -> float | None:
    """Return a deterministic linearly interpolated percentile."""

    if not values:
        return None
    if not 0 <= fraction <= 1:
        raise ValueError("percentile fraction must be between zero and one")
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 6)
    weight = position - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 6)


def _validate_number(value: float, *, label: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{label} must be a finite non-negative number")
    return number


def _normalise_labels(
    metric: str,
    labels: Mapping[str, str],
    contract: Mapping[str, frozenset[str]],
) -> tuple[tuple[str, str], ...]:
    expected = contract.get(metric)
    if expected is None:
        raise ValueError(f"metric is not allowlisted: {metric}")
    supplied = frozenset(labels)
    if supplied != expected:
        forbidden = sorted(supplied & _FORBIDDEN_KEYS)
        if forbidden:
            raise ValueError(f"high-cardinality or sensitive labels are forbidden: {forbidden}")
        raise ValueError(f"labels for {metric} must be exactly {sorted(expected)}")
    normalised: list[tuple[str, str]] = []
    for key in sorted(labels):
        value = str(labels[key])
        allowed = LABEL_VALUES[key]
        if value not in allowed:
            raise ValueError(f"label value is not allowlisted: {key}={value}")
        normalised.append((key, value))
    return tuple(normalised)


@dataclass(slots=True)
class _Histogram:
    samples: deque[float]
    count: int = 0
    total: float = 0.0
    minimum: float | None = None
    maximum: float | None = None

    def observe(self, value: float) -> None:
        self.samples.append(value)
        self.count += 1
        self.total += value
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)


class LiveMetrics:
    """Thread-safe, bounded, low-cardinality in-process metric accumulator."""

    def __init__(self, *, histogram_sample_limit: int = 50_000) -> None:
        if histogram_sample_limit < 100:
            raise ValueError("histogram sample limit must be at least 100")
        self._sample_limit = histogram_sample_limit
        self._counters: defaultdict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(
            float
        )
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._histograms: dict[tuple[str, tuple[tuple[str, str], ...]], _Histogram] = {}
        self._lock = threading.RLock()

    def increment(
        self,
        metric: str,
        *,
        labels: Mapping[str, str],
        amount: float = 1,
    ) -> None:
        value = _validate_number(amount, label="counter increment")
        key = (metric, _normalise_labels(metric, labels, COUNTER_LABELS))
        with self._lock:
            self._counters[key] += value

    def set_gauge(
        self,
        metric: str,
        *,
        labels: Mapping[str, str],
        value: float,
    ) -> None:
        number = _validate_number(value, label="gauge")
        key = (metric, _normalise_labels(metric, labels, GAUGE_LABELS))
        with self._lock:
            self._gauges[key] = number

    def clear_gauge_metric(self, metric: str) -> None:
        """Remove stale label series before rebuilding an instantaneous gauge."""

        if metric not in GAUGE_LABELS:
            raise ValueError(f"gauge metric is not allowlisted: {metric}")
        with self._lock:
            self._gauges = {key: value for key, value in self._gauges.items() if key[0] != metric}

    def observe(
        self,
        metric: str,
        *,
        labels: Mapping[str, str],
        value: float,
    ) -> None:
        number = _validate_number(value, label="histogram observation")
        key = (metric, _normalise_labels(metric, labels, ALL_HISTOGRAM_LABELS))
        with self._lock:
            histogram = self._histograms.get(key)
            if histogram is None:
                histogram = _Histogram(deque(maxlen=self._sample_limit))
                self._histograms[key] = histogram
            histogram.observe(number)

    def snapshot(self, *, generated_at: datetime | None = None) -> dict[str, Any]:
        timestamp = generated_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise ValueError("snapshot timestamp must be timezone-aware")
        with self._lock:
            counters = [
                {
                    "metric": metric,
                    "labels": dict(labels),
                    "value": round(value, 6),
                }
                for (metric, labels), value in sorted(self._counters.items())
            ]
            gauges = [
                {
                    "metric": metric,
                    "labels": dict(labels),
                    "value": round(value, 6),
                }
                for (metric, labels), value in sorted(self._gauges.items())
            ]
            histograms: list[dict[str, Any]] = []
            for (metric, labels), histogram in sorted(self._histograms.items()):
                samples = list(histogram.samples)
                histograms.append(
                    {
                        "metric": metric,
                        "labels": dict(labels),
                        "count": histogram.count,
                        "sample_count": len(samples),
                        "sum": round(histogram.total, 6),
                        "min": histogram.minimum,
                        "max": histogram.maximum,
                        "p50": percentile(samples, 0.50),
                        "p95": percentile(samples, 0.95),
                        "p99": percentile(samples, 0.99),
                    }
                )
        snapshot = {
            "schema": "legalbot.live-metrics-snapshot.v1",
            "generated_at": timestamp.astimezone(UTC).isoformat(),
            "window": "process_lifetime_with_bounded_recent_percentile_samples",
            "counters": counters,
            "gauges": gauges,
            "histograms": histograms,
        }
        assert_safe_snapshot(snapshot)
        return snapshot


@dataclass(frozen=True, slots=True)
class SLOBand:
    id: str
    route: str
    word_min: int
    word_max: int
    progress_freshness_seconds: float
    progress_stuck_seconds: float
    targets_p95_seconds: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class SLOPolicy:
    policy_id: str
    calibration_suite_id: str
    external_sla: bool
    provisional: bool
    baseline_calibrated: bool
    enforcement: str
    minimum_successful_runs_per_band: int
    minimum_latency_samples: int
    minimum_terminal_samples: int
    sampling: Mapping[str, Any]
    queue: Mapping[str, float | str]
    success: Mapping[str, Any]
    bands: tuple[SLOBand, ...]

    def band_for(self, *, route: str, word_target: int) -> SLOBand:
        matches = [
            band
            for band in self.bands
            if band.route == route and band.word_min <= word_target <= band.word_max
        ]
        if len(matches) != 1:
            raise ValueError(
                f"route/word target does not resolve to one SLO band: {route}/{word_target}"
            )
        return matches[0]

    def band_by_id(self, band_id: str) -> SLOBand:
        matches = [band for band in self.bands if band.id == band_id]
        if len(matches) != 1:
            raise ValueError(f"unknown or duplicated SLO band: {band_id}")
        return matches[0]


def _required_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    return value


def load_slo_policy(path: Path) -> SLOPolicy:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    root = _required_mapping(payload, label="SLO policy")
    if root.get("schema") != "legalbot.observability-slo.v1":
        raise ValueError("unknown observability SLO schema")
    classification = _required_mapping(root.get("classification"), label="classification")
    if (
        classification.get("internal_only") is not True
        or classification.get("external_sla") is not False
    ):
        raise ValueError("observability targets must remain internal and not an SLA")
    if classification.get("provisional") is not True:
        raise ValueError("v1 observability targets must remain explicitly provisional")
    if classification.get("baseline_calibrated") is not False:
        raise ValueError("v1 cannot claim baseline calibration")
    if classification.get("enforcement") != "observe_only":
        raise ValueError("uncalibrated targets must be observe-only")
    calibration = _required_mapping(root.get("calibration"), label="calibration")
    policy_id = str(root["policy_id"])
    calibration_suite_id = str(calibration.get("suite_id") or "")
    expected_suite = {
        "local-e2e-provisional-v1": "live-evaluation-30-v1",
        "local-e2e-provisional-v2": "live-evaluation-60-v1",
    }.get(policy_id)
    if expected_suite is None or calibration_suite_id != expected_suite:
        raise ValueError("provisional SLO policy is bound to the wrong evaluation suite")
    minimum_successful_runs_per_band = int(calibration["minimum_successful_runs_per_band"])
    minimum_latency_samples = int(calibration["minimum_latency_observations_per_metric_band"])
    minimum_terminal_samples = int(calibration["minimum_terminal_samples_per_band"])
    if minimum_successful_runs_per_band < 1:
        raise ValueError("latency baselines require at least one successful run per band")
    if minimum_latency_samples < 3:
        raise ValueError("latency percentiles require at least three observations per metric")
    if minimum_terminal_samples < minimum_successful_runs_per_band:
        raise ValueError("terminal sample minimum cannot be below the successful-run minimum")
    sampling = _required_mapping(root.get("sampling"), label="sampling")
    expected_sampling = {
        "debug_enabled": False,
        "debug_rate": 0.0,
        "info_rate": 0.10,
        "warn_rate": 1.0,
        "error_rate": 1.0,
        "fatal_rate": 1.0,
        "deterministic_key": "trace_id_and_event_id",
    }
    if dict(sampling) != expected_sampling:
        raise ValueError("v1 sampling must be DEBUG off, INFO 10%, and WARN+ 100%")
    queue = _required_mapping(root.get("queue"), label="queue")
    success = _required_mapping(root.get("success"), label="success")
    raw_bands = root.get("route_word_bands")
    if not isinstance(raw_bands, list) or not raw_bands:
        raise ValueError("route_word_bands must be a non-empty list")
    bands: list[SLOBand] = []
    for raw_band in raw_bands:
        value = _required_mapping(raw_band, label="route-word band")
        targets = _required_mapping(value.get("targets_p95_seconds"), label="targets")
        missing_targets = frozenset(HISTOGRAM_LABELS) - frozenset(targets)
        if missing_targets:
            raise ValueError(f"SLO band omits latency targets: {sorted(missing_targets)}")
        band = SLOBand(
            id=str(value["id"]),
            route=str(value["route"]),
            word_min=int(value["word_min"]),
            word_max=int(value["word_max"]),
            progress_freshness_seconds=_validate_number(
                value["progress_freshness_seconds"], label="progress freshness"
            ),
            progress_stuck_seconds=_validate_number(
                value["progress_stuck_seconds"], label="progress stuck"
            ),
            targets_p95_seconds={
                str(metric): _validate_number(target, label=f"{metric} target")
                for metric, target in targets.items()
            },
        )
        if band.id not in WORD_BANDS or band.route not in LABEL_VALUES["route"]:
            raise ValueError("SLO band identity or route is not allowlisted")
        if band.word_min > band.word_max:
            raise ValueError("SLO band word range is reversed")
        if band.progress_freshness_seconds >= band.progress_stuck_seconds:
            raise ValueError("stuck threshold must exceed progress freshness threshold")
        bands.append(band)
    if len({band.id for band in bands}) != len(bands):
        raise ValueError("SLO band IDs are duplicated")
    return SLOPolicy(
        policy_id=policy_id,
        calibration_suite_id=calibration_suite_id,
        external_sla=bool(classification["external_sla"]),
        provisional=bool(classification["provisional"]),
        baseline_calibrated=bool(classification["baseline_calibrated"]),
        enforcement=str(classification["enforcement"]),
        minimum_successful_runs_per_band=minimum_successful_runs_per_band,
        minimum_latency_samples=minimum_latency_samples,
        minimum_terminal_samples=minimum_terminal_samples,
        sampling=dict(sampling),
        queue={
            str(key): float(value) if key != "scope" else str(value) for key, value in queue.items()
        },
        success=dict(success),
        bands=tuple(bands),
    )


@dataclass(frozen=True, slots=True)
class ProgressAssessment:
    band_id: str
    state: str
    age_seconds: float
    freshness_seconds: float
    stuck_seconds: float


def assess_progress_freshness(
    policy: SLOPolicy,
    *,
    route: str,
    word_target: int,
    last_progress_at: datetime,
    now: datetime | None = None,
) -> ProgressAssessment:
    observed_at = now or datetime.now(UTC)
    if last_progress_at.tzinfo is None or observed_at.tzinfo is None:
        raise ValueError("progress timestamps must be timezone-aware")
    age = (observed_at - last_progress_at).total_seconds()
    if age < 0:
        raise ValueError("last progress timestamp is in the future")
    band = policy.band_for(route=route, word_target=word_target)
    if age <= band.progress_freshness_seconds:
        state = "fresh"
    elif age <= band.progress_stuck_seconds:
        state = "stale"
    else:
        state = "stuck"
    return ProgressAssessment(
        band_id=band.id,
        state=state,
        age_seconds=round(age, 6),
        freshness_seconds=band.progress_freshness_seconds,
        stuck_seconds=band.progress_stuck_seconds,
    )


def _rows_by_metric(
    snapshot: Mapping[str, Any], collection: str
) -> dict[str, list[Mapping[str, Any]]]:
    grouped: defaultdict[str, list[Mapping[str, Any]]] = defaultdict(list)
    rows = snapshot.get(collection)
    if not isinstance(rows, list):
        raise ValueError(f"snapshot {collection} must be a list")
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("metric"), str):
            raise ValueError(f"snapshot {collection} row is invalid")
        grouped[str(row["metric"])].append(row)
    return dict(grouped)


def evaluate_slo(snapshot: Mapping[str, Any], policy: SLOPolicy) -> dict[str, Any]:
    """Evaluate provisional targets without turning them into a promotion gate."""

    assert_safe_snapshot(snapshot)
    gauges = _rows_by_metric(snapshot, "gauges")
    counters = _rows_by_metric(snapshot, "counters")
    histograms = _rows_by_metric(snapshot, "histograms")
    checks: list[dict[str, Any]] = []

    queue_targets = {
        "queue_depth": float(policy.queue["depth_critical"]),
        "oldest_job_age_seconds": float(policy.queue["oldest_job_age_critical_seconds"]),
    }
    for metric, target in queue_targets.items():
        rows = gauges.get(metric, [])
        local = [row for row in rows if row.get("labels") == {"scope": "local"}]
        if not local:
            checks.append(
                {"metric": metric, "scope": "local", "state": "not_evaluated", "passed": None}
            )
            continue
        observed = max(float(row["value"]) for row in local)
        checks.append(
            {
                "metric": metric,
                "scope": "local",
                "state": "evaluated",
                "observed": observed,
                "threshold": target,
                "passed": observed <= target,
            }
        )

    successful_terminal_statuses = frozenset(
        str(value) for value in policy.success["successful_terminal_statuses"]
    )
    successful_runs: defaultdict[tuple[str, str], float] = defaultdict(float)
    for row in counters.get("jobs_terminal_total", []):
        labels = _required_mapping(row.get("labels"), label="terminal labels")
        status = str(labels["status"])
        if status in successful_terminal_statuses:
            successful_runs[(str(labels["route"]), str(labels["word_band"]))] += float(row["value"])

    for metric in HISTOGRAM_LABELS:
        for row in histograms.get(metric, []):
            labels = _required_mapping(row.get("labels"), label="histogram labels")
            band = policy.band_by_id(str(labels["word_band"]))
            route = str(labels["route"])
            if route != band.route:
                raise ValueError("histogram route conflicts with its word band")
            p95_observed = row.get("p95")
            sample_count = int(row.get("sample_count") or 0)
            successful_run_count = successful_runs[(route, band.id)]
            enough = (
                sample_count >= policy.minimum_latency_samples
                and successful_run_count >= policy.minimum_successful_runs_per_band
            )
            target = float(band.targets_p95_seconds[metric])
            checks.append(
                {
                    "metric": metric,
                    "scope": band.id,
                    "state": (
                        "evaluated"
                        if enough and p95_observed is not None
                        else "insufficient_samples"
                        if p95_observed is not None
                        else "not_evaluated"
                    ),
                    "samples": sample_count,
                    "minimum_samples": policy.minimum_latency_samples,
                    "successful_runs": successful_run_count,
                    "minimum_successful_runs": policy.minimum_successful_runs_per_band,
                    "observed_p95": p95_observed,
                    "threshold_p95": target,
                    "passed": None
                    if p95_observed is None or not enough
                    else float(p95_observed) <= target,
                }
            )

    for row in gauges.get("progress_age_seconds", []):
        labels = _required_mapping(row.get("labels"), label="progress labels")
        band = policy.band_by_id(str(labels["word_band"]))
        if str(labels["route"]) != band.route:
            raise ValueError("progress route conflicts with its word band")
        age = float(row["value"])
        state = (
            "fresh"
            if age <= band.progress_freshness_seconds
            else "stale"
            if age <= band.progress_stuck_seconds
            else "stuck"
        )
        checks.append(
            {
                "metric": "progress_age_seconds",
                "scope": band.id,
                "state": state,
                "observed": age,
                "threshold": band.progress_freshness_seconds,
                "stuck_threshold": band.progress_stuck_seconds,
                "passed": state == "fresh",
            }
        )

    terminal_groups: defaultdict[tuple[str, str], defaultdict[str, float]] = defaultdict(
        lambda: defaultdict(float)
    )
    for row in counters.get("jobs_terminal_total", []):
        labels = _required_mapping(row.get("labels"), label="terminal labels")
        terminal_groups[(str(labels["route"]), str(labels["word_band"]))][
            str(labels["status"])
        ] += float(row["value"])
    successful = successful_terminal_statuses
    errors = frozenset(str(value) for value in policy.success["error_terminal_statuses"])
    excluded = frozenset(str(value) for value in policy.success["excluded_terminal_statuses"])
    minimum_success = float(policy.success["minimum_success_rate"])
    error_budget = float(policy.success["error_budget_fraction"])
    for (route, band_id), statuses in sorted(terminal_groups.items()):
        policy.band_by_id(band_id)
        denominator = sum(count for status, count in statuses.items() if status not in excluded)
        success_count = sum(statuses[status] for status in successful)
        error_count = sum(statuses[status] for status in errors)
        enough = denominator >= policy.minimum_terminal_samples
        success_rate = success_count / denominator if denominator else None
        error_fraction = error_count / denominator if denominator else None
        checks.append(
            {
                "metric": "success_rate",
                "scope": band_id,
                "route": route,
                "state": "evaluated" if enough else "insufficient_samples",
                "samples": denominator,
                "minimum_samples": policy.minimum_terminal_samples,
                "observed": success_rate,
                "threshold": minimum_success,
                "passed": None
                if not enough
                else bool(success_rate is not None and success_rate >= minimum_success),
            }
        )
        checks.append(
            {
                "metric": "error_budget_fraction",
                "scope": band_id,
                "route": route,
                "state": "evaluated" if enough else "insufficient_samples",
                "samples": denominator,
                "observed": error_fraction,
                "threshold": error_budget,
                "passed": None
                if not enough
                else bool(error_fraction is not None and error_fraction <= error_budget),
            }
        )

    active_band_ids = {
        str(check["scope"]) for check in checks if str(check.get("scope")) in WORD_BANDS
    }
    for band_id in sorted(active_band_ids):
        observed_metrics = {
            str(check["metric"])
            for check in checks
            if check.get("scope") == band_id and str(check.get("metric")) in HISTOGRAM_LABELS
        }
        for missing_metric in sorted(frozenset(HISTOGRAM_LABELS) - observed_metrics):
            checks.append(
                {
                    "metric": missing_metric,
                    "scope": band_id,
                    "state": "not_evaluated",
                    "passed": None,
                }
            )

    evaluated = [check for check in checks if check.get("passed") is not None]
    evaluation_complete = bool(checks) and all(check.get("passed") is not None for check in checks)
    result = {
        "schema": "legalbot.observability-slo-evaluation.v1",
        "policy_id": policy.policy_id,
        "internal_only": True,
        "external_sla": policy.external_sla,
        "provisional": policy.provisional,
        "baseline_calibrated": policy.baseline_calibrated,
        "enforcement": policy.enforcement,
        "gate_eligible": bool(
            not policy.external_sla
            and not policy.provisional
            and policy.baseline_calibrated
            and policy.enforcement != "observe_only"
        ),
        "evaluation_complete": evaluation_complete,
        "within_provisional_targets": evaluation_complete
        and bool(evaluated)
        and all(bool(check["passed"]) for check in evaluated),
        "checks": checks,
    }
    assert_safe_snapshot(result)
    return result


def assert_safe_snapshot(value: Any, *, key: str | None = None) -> None:
    """Fail if a metric/SLO snapshot contains sensitive or high-cardinality fields."""

    if key is not None and key.casefold() in _FORBIDDEN_KEYS:
        raise ValueError(f"forbidden metric snapshot field: {key}")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            assert_safe_snapshot(child, key=str(child_key))
    elif isinstance(value, list | tuple):
        for child in value:
            assert_safe_snapshot(child, key=key)
    elif isinstance(value, str) and ("/Users/" in value or "\\Users\\" in value or "\n" in value):
        raise ValueError("metric snapshot contains path-like or multiline text")
