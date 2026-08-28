"""Fail-honest readiness gates for the current architecture.

Readiness is intentionally split into independent source, retrieval,
candidate, promotion, debug-E2E and answer-quality gates.  An ACTIVE index is
an owner serving decision, not evidence that a candidate was promotable.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from collections.abc import Mapping
from contextlib import suppress
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from .config import Settings
from .db import Database, utc_iso
from .evaluation.live_runtime_separation import (
    classify_live_and_live60_state,
    split_readiness_blocking_gates,
)
from .privacy_audit import build_candidate_privacy_report
from .quality.policy import POLICY_SHA256, POLICY_VERSION, PRODUCT_JURISDICTION

LIVE30_REGISTRY = Path("benchmarks/evaluation/live-evaluation-30-v1/cases.jsonl")
LIVE30_MANIFEST = Path("benchmarks/evaluation/live-evaluation-30-v1/manifest.json")
LIVE60_ROOT = Path("benchmarks/evaluation/live-evaluation-60-v1")
READINESS_GATES = Path("data/evaluations/e2e/gates")
ROLLBACK_DRILL_SCHEMA = "legalbot.rollback-drill-result.v1"
BROWSER_RECOVERY_SCHEMA = "legalbot.browser-recovery-drill-result.v3"
CALIBRATION_SEAL_SCHEMA = "legalbot.blind-human-calibration-seal.v1"
BLIND_CALIBRATION_THRESHOLDS: dict[str, int | float] = {
    "unique_cases_minimum": 20,
    "subjects_minimum": 5,
    "independent_reviewers_minimum": 2,
    "double_review_fraction_minimum": 0.20,
    "human_70_plus_minimum": 5,
    "human_below_70_minimum": 5,
    "pass_fail_agreement_minimum": 0.85,
    "mean_absolute_score_error_maximum": 10.0,
    "dangerous_false_passes_maximum": 0,
}


def _local_today() -> date:
    # The product's current-law scope is England and Wales.  The run-admission
    # contract therefore uses the Europe/London calendar date even when the
    # localhost owner is operating from another timezone.
    return datetime.now(ZoneInfo("Europe/London")).date()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _approved_legal_source_state(row: Any) -> str:
    """Classify source-review approval without overstating serving eligibility.

    ``approved`` can intentionally preserve identity-only catalogue records.
    Model-use rights remain an independent, explicit boolean.  Case-law
    currentness is proposition/span scoped, so a rights-qualified judgment is
    reported as proposition-gated rather than falsely failing (or passing) a
    document-level currentness test.
    """

    try:
        metadata = json.loads(row["metadata_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        return "unqualified"
    if not isinstance(metadata, dict):
        return "unqualified"
    if (
        metadata.get("eligible_for_model_use") is not True
        or metadata.get("ai_use_policy") == "prohibited"
    ):
        return "rights_excluded_catalogue_only"
    citation = metadata.get("citation_data")
    if not (
        metadata.get("identity_verified") is True
        and isinstance(citation, dict)
        and citation
        and row["stable_identifier"]
        and row["jurisdiction"]
    ):
        return "unqualified"
    if str(citation.get("source_type") or "").casefold() == "case":
        return "case_proposition_currentness_gated"
    if metadata.get("currentness_verified") is not True:
        return "unqualified"
    return "qualified"


def _a2_seal_is_valid(settings: Settings) -> bool:
    """Validate the separately sealed A2 behaviour/abstention batch."""

    seal_path = settings.data_dir / "evaluation" / "a2-intentional-abstention" / "seal.json"
    try:
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if seal.get("schema") != "legalbot.a2-batch-seal.v1" or seal.get("status") != "SEALED":
        return False
    artefacts = (
        ("canonical_manifest_path", "canonical_manifest_sha256"),
        ("suite_path", "suite_file_sha256"),
        ("summary_path", "summary_sha256"),
    )
    for path_key, digest_key in artefacts:
        relative = seal.get(path_key)
        expected = seal.get(digest_key)
        if not isinstance(relative, str) or not isinstance(expected, str):
            return False
        path = (settings.project_root / relative).resolve()
        try:
            path.relative_to(settings.project_root.resolve())
        except ValueError:
            return False
        if not path.is_file() or _file_sha256(path) != expected:
            return False
    return True


def _candidate_integrity(settings: Settings, database: Database, row: Any) -> tuple[bool, bool]:
    """Read integrity from the artefact that is authoritative for the build.

    Durable v1.1 candidates deliberately keep the large, immutable integrity
    evaluation in the sealed build directory.  ``metrics_json`` records build
    attempts and failures and is not the durable candidate's source of truth.
    Older candidates retain the legacy embedded evaluation for audit
    compatibility.
    """

    build_path = settings.index_dir / "builds" / str(row["id"])
    if (build_path / "approved-source-manifest.json").is_file():
        try:
            from .retrieval.service import _verify_sealed_build

            # Do not report a copied or modified evaluation as passing merely
            # because its JSON says so.  Verify every sealed artefact first.
            _verify_sealed_build(settings, database, dict(row))
            evaluation = json.loads((build_path / "evaluation.json").read_text(encoding="utf-8"))
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError):
            return False, False
    else:
        try:
            metrics = json.loads(row["metrics_json"] or "{}")
            evaluation = metrics.get("evaluation") or {}
        except (TypeError, json.JSONDecodeError):
            return False, False

    integrity = evaluation.get("integrity") or {}
    return (
        evaluation.get("passed") is True,
        integrity.get("physical_lane_isolation") is True,
    )


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON artefact is not an object")
    return value


def _canonical_self_seal(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    payload = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_self_sealed_result(path: Path, *, schema: str) -> dict[str, Any] | None:
    """Load a privacy-safe, self-sealed gate result or fail closed.

    These gate files are written only by the corresponding drill.  A boolean
    in a readiness report is never evidence by itself: the result must have a
    valid schema, evaluation-only policy, immutable digest and explicit pass.
    """

    try:
        from .evaluation.live30 import assert_safe_evaluation_payload

        value = _read_json_object(path)
        assert_safe_evaluation_payload(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if (
        value.get("schema") != schema
        or value.get("purpose") != "evaluation_only"
        or value.get("eligible_for_training") is not False
        or value.get("training_export_allowed") is not False
        or value.get("passed") is not True
        or value.get("seal_sha256") != _canonical_self_seal(value)
    ):
        return None
    return value


def _live30_registry_status(settings: Settings) -> tuple[dict[str, Any], Any | None]:
    from .evaluation.live30 import (
        EXPECTED_CASE_IDS,
        EXPECTED_TOTAL_WORD_TARGET,
        STRATIFIED_SAMPLE_IDS,
        load_live30_suite,
    )

    registry = settings.project_root / LIVE30_REGISTRY
    manifest_path = settings.project_root / LIVE30_MANIFEST
    try:
        suite = load_live30_suite(registry)
        manifest = _read_json_object(manifest_path)
        expected_manifest = suite.manifest()
        manifest_matches = manifest == expected_manifest
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return (
            {
                "passed": False,
                "suite_id": "live-evaluation-30-v1",
                "registry_valid": False,
                "manifest_matches_registry": False,
                "case_count": 0,
                "total_word_target": 0,
                "planned_terminal_outcomes": 0,
                "error_code": type(exc).__name__,
            },
            None,
        )
    planned = suite.case_count + 2 * len(STRATIFIED_SAMPLE_IDS)
    passed = bool(
        manifest_matches
        and tuple(case.case_id for case in suite.cases) == EXPECTED_CASE_IDS
        and suite.case_count == 30
        and suite.total_word_target == EXPECTED_TOTAL_WORD_TARGET
        and planned == 48
    )
    return (
        {
            "passed": passed,
            "suite_id": "live-evaluation-30-v1",
            "registry_valid": True,
            "manifest_matches_registry": manifest_matches,
            "case_count": suite.case_count,
            "total_word_target": suite.total_word_target,
            "planned_terminal_outcomes": planned,
            "suite_file_sha256": suite.file_sha256,
            "suite_canonical_sha256": suite.canonical_sha256,
            "stratified_sample_case_count": len(STRATIFIED_SAMPLE_IDS),
            "error_code": None,
        },
        suite,
    )


def _live60_registry_status(settings: Settings) -> tuple[dict[str, Any], Any | None]:
    """Validate the Live60 registry, lineage and exact single-pass run plan.

    The Live60 directory is a successor decision contract, not a replacement
    for the immutable Live30 inputs.  Its loader independently revalidates the
    original registry and manifest before accepting the first 30 records.
    """

    from .evaluation.live_suite import load_live_evaluation_bundle

    root = settings.project_root / LIVE60_ROOT
    try:
        bundle = load_live_evaluation_bundle(root)
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return (
            {
                "passed": False,
                "suite_id": "live-evaluation-60-v1",
                "registry_valid": False,
                "case_count": 0,
                "total_word_target": 0,
                "generation_case_count": 0,
                "generation_total_word_target": 0,
                "coverage_only_case_count": 0,
                "single_pass_outcome_count": 0,
                "stability_repeat_count": None,
                "accepted_baseline_status": None,
                "error_code": type(exc).__name__,
            },
            None,
        )
    selected = tuple(
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    )
    coverage_only = tuple(
        item.case_id
        for item in bundle.run_plan.cases
        if item.disposition == "coverage_only_not_selected"
    )
    outcome_count = sum(item.pass_count for item in bundle.run_plan.cases)
    passed = bool(
        bundle.manifest.accepted_baseline_status == "no_go"
        and bundle.manifest.owner_promotion_required is True
        and bundle.manifest.live_authorization_required is True
        and bundle.manifest.expert_annotation_required_before_scoring is True
        and bundle.manifest.expert_reviewers_required == 1
        and bundle.registry.case_count == 60
        and bundle.registry.total_word_target == 215_000
        and bundle.run_plan.generation_case_count == 30
        and bundle.run_plan.generation_total_word_target == 114_000
        and len(selected) == 30
        and len(coverage_only) == 30
        and outcome_count == 30
        and bundle.run_plan.stability_repeats == 0
        and all(item.pass_count in {0, 1} for item in bundle.run_plan.cases)
        and all(len(case_ids) == 10 for case_ids in bundle.run_plan.annexes.values())
    )
    return (
        {
            "passed": passed,
            "suite_id": bundle.manifest.suite_id,
            "registry_valid": True,
            "case_count": bundle.registry.case_count,
            "total_word_target": bundle.registry.total_word_target,
            "generation_case_count": bundle.run_plan.generation_case_count,
            "generation_total_word_target": (bundle.run_plan.generation_total_word_target),
            "coverage_only_case_count": len(coverage_only),
            "single_pass_outcome_count": outcome_count,
            "stability_repeat_count": bundle.run_plan.stability_repeats,
            "selected_case_ids": list(selected),
            "coverage_only_case_ids": list(coverage_only),
            "annexes": {key: list(case_ids) for key, case_ids in bundle.run_plan.annexes.items()},
            "suite_file_sha256": bundle.registry.file_sha256,
            "suite_canonical_sha256": bundle.registry.canonical_sha256,
            "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
            "run_plan_id": bundle.run_plan.run_plan_id,
            "run_plan_file_sha256": bundle.manifest.run_plan_sha256,
            "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
            "accepted_baseline_status": bundle.manifest.accepted_baseline_status,
            "error_code": None,
        },
        bundle,
    )


def _current_law_candidate_status(
    settings: Settings,
    database: Database,
    row: Any | None,
    *,
    as_of_date: date,
) -> dict[str, Any]:
    from .assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
    from .retrieval.source_manifest import approved_source_manifest_sha256

    result: dict[str, Any] = {
        "passed": False,
        "candidate_exists": row is not None,
        "build_id": str(row["id"]) if row is not None else None,
        "catalogue_status": str(row["status"]) if row is not None else None,
        "required_as_of_date": as_of_date.isoformat(),
        "current_law_as_of_date": None,
        "current_date_snapshot": False,
        "integrity_passed": False,
        "physical_lane_isolation_passed": False,
        "retrieval_v1_1_passed": False,
        "policy_sha256_bound": False,
        "assessment_bundle_sha256_bound": False,
        "source_manifest_digest_bound": False,
        "error_code": None,
    }
    if row is None:
        return result
    result["policy_sha256_bound"] = str(row["policy_sha256"] or "") == POLICY_SHA256
    result["assessment_bundle_sha256_bound"] = (
        str(row["assessment_bundle_sha256"] or "") == OWNER_ASSESSMENT_BUNDLE.sha256
    )
    try:
        integrity, lanes = _candidate_integrity(settings, database, row)
        result["integrity_passed"] = integrity
        result["physical_lane_isolation_passed"] = lanes
        benchmark = json.loads(row["benchmark_result_json"] or "{}")
        if not isinstance(benchmark, dict):
            raise ValueError("benchmark result is not an object")
        result["retrieval_v1_1_passed"] = bool(
            benchmark.get("passed") is True and benchmark.get("promotion_eligible") is True
        )
        source_manifest = _read_json_object(
            settings.index_dir / "builds" / str(row["id"]) / "approved-source-manifest.json"
        )
        observed_date = str(source_manifest.get("current_law_as_of_date") or "")
        result["current_law_as_of_date"] = observed_date or None
        result["current_date_snapshot"] = observed_date == as_of_date.isoformat()
        manifest_digest = approved_source_manifest_sha256(source_manifest)
        result["source_manifest_digest_bound"] = bool(
            source_manifest.get("manifest_sha256") == manifest_digest
            and str(row["source_manifest_hash"] or "") == manifest_digest
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        result["error_code"] = type(exc).__name__
    required = (
        "integrity_passed",
        "physical_lane_isolation_passed",
        "retrieval_v1_1_passed",
        "policy_sha256_bound",
        "assessment_bundle_sha256_bound",
        "source_manifest_digest_bound",
        "current_date_snapshot",
    )
    result["passed"] = all(result[key] is True for key in required)
    return result


def _stage_a_payload_status(
    coverage: Mapping[str, Any],
    *,
    run_id: str,
    qualification_sha256: str,
    artifact_sha256: str | None = None,
) -> dict[str, Any]:
    from .evaluation.live30 import EXPECTED_CASE_IDS
    from .evaluation.live30_execute import _enforce_stage_a_thresholds

    result: dict[str, Any] = {
        "passed": False,
        "present": True,
        "run_id": run_id,
        "coverage_artifact_sha256": artifact_sha256,
        "ranking_metric_state": coverage.get("ranking_metric_state"),
        "scored_issue_count": 0,
        "route_pass_count": 0,
        "subject_routing_pass_count": 0,
        "recall_at_5": None,
        "recall_at_10": None,
        "mrr": None,
        "ndcg_at_10": None,
        "exact_span_recall": None,
        "contrary_authority_recall": None,
        "thresholds": {
            "recall_at_5_minimum": 1.0,
            "recall_at_10_minimum": 0.95,
            "mrr_minimum": 0.8,
        },
        "error_code": None,
    }
    try:
        required_metrics: dict[str, float] = {}
        for key in (
            "recall_at_5",
            "recall_at_10",
            "mrr",
            "ndcg_at_10",
            "exact_span_recall",
            "contrary_authority_recall",
        ):
            value = coverage.get(key)
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError("Stage A metric is absent")
            metric = float(value)
            if not math.isfinite(metric) or not 0.0 <= metric <= 1.0:
                raise ValueError("Stage A metric is invalid")
            required_metrics[key] = metric
        if (
            coverage.get("schema") != "legalbot.live30-coverage-summary.v2"
            or coverage.get("run_id") != run_id
            or coverage.get("case_ids") != list(EXPECTED_CASE_IDS)
            or int(coverage.get("case_count") or 0) != 30
            or int(coverage.get("route_pass_count") or 0) != 30
            or int(coverage.get("subject_routing_pass_count") or 0) != 30
            or coverage.get("ranking_metric_state")
            != "evaluated_against_sealed_qualifying_issue_gold"
            or coverage.get("expert_qualification_sha256") != qualification_sha256
            or coverage.get("generation_started") is not False
        ):
            raise ValueError("Stage A identity or coverage contract is invalid")
        _enforce_stage_a_thresholds(coverage)
        result.update(
            {
                "passed": True,
                "scored_issue_count": int(coverage.get("scored_issue_count") or 0),
                "route_pass_count": int(coverage.get("route_pass_count") or 0),
                "subject_routing_pass_count": int(coverage.get("subject_routing_pass_count") or 0),
                **required_metrics,
            }
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _live60_stage_a_payload_status(
    coverage: Mapping[str, Any],
    *,
    run_id: str,
    qualification_sha256: str,
    index_build_id: str,
    bundle: Any,
    artifact_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate exact Live60 coverage and the owner-approved ranking gates."""

    expected_ids = tuple(case.case_id for case in bundle.registry.cases)
    selected_ids = tuple(
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    )
    coverage_only_ids = tuple(
        item.case_id
        for item in bundle.run_plan.cases
        if item.disposition == "coverage_only_not_selected"
    )
    result: dict[str, Any] = {
        "passed": False,
        "present": True,
        "run_id": run_id,
        "index_build_id": coverage.get("index_build_id"),
        "coverage_artifact_sha256": artifact_sha256,
        "ranking_metric_state": coverage.get("ranking_metric_state"),
        "case_count": 0,
        "selected_generation_case_count": 0,
        "coverage_only_case_count": 0,
        "scored_issue_count": 0,
        "route_pass_count": 0,
        "subject_routing_pass_count": 0,
        "recall_at_5": None,
        "recall_at_10": None,
        "mrr": None,
        "ndcg_at_10": None,
        "exact_span_recall": None,
        "contrary_authority_recall": None,
        "filter_violation_count": None,
        "thresholds": {
            "recall_at_5_minimum": 1.0,
            "recall_at_10_minimum": 0.95,
            "mrr_minimum": 0.8,
            "filter_violation_maximum": 0,
        },
        "error_code": None,
    }
    try:
        required_metrics: dict[str, float] = {}
        for key in (
            "recall_at_5",
            "recall_at_10",
            "mrr",
            "ndcg_at_10",
            "exact_span_recall",
            "contrary_authority_recall",
        ):
            value = coverage.get(key)
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError("Stage A metric is absent")
            metric = float(value)
            if not math.isfinite(metric) or not 0.0 <= metric <= 1.0:
                raise ValueError("Stage A metric is invalid")
            required_metrics[key] = metric
        qualification_counts = coverage.get("qualification_status_counts")
        if not isinstance(qualification_counts, dict) or any(
            key not in {"qualified", "limited", "knowledge_gap"}
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for key, value in qualification_counts.items()
        ):
            raise ValueError("expert case-disposition counts are invalid")
        if (
            coverage.get("schema") != "legalbot.live-coverage-summary.v3"
            or coverage.get("run_id") != run_id
            or coverage.get("suite_id") != bundle.manifest.suite_id
            or tuple(coverage.get("case_ids") or ()) != expected_ids
            or int(coverage.get("case_count") or 0) != 60
            or int(coverage.get("route_pass_count") or 0) != 60
            or int(coverage.get("subject_routing_pass_count") or 0) != 60
            or tuple(coverage.get("coverage_only_not_selected_case_ids") or ()) != coverage_only_ids
            or int(coverage.get("selected_generation_case_count") or 0) != 30
            or set(coverage.get("selected_generation_eligible_case_ids") or ()) - set(selected_ids)
            or sum(qualification_counts.values()) != 60
            or coverage.get("ranking_metric_state")
            != "evaluated_against_sealed_qualifying_issue_gold"
            or coverage.get("expert_qualification_sha256") != qualification_sha256
            or coverage.get("index_build_id") != index_build_id
            or coverage.get("stage_a_evaluated") is not True
            or coverage.get("stage_a_passed") is not True
            or coverage.get("generation_started") is not False
            or int(coverage.get("filter_violation_count") or 0) != 0
        ):
            raise ValueError("Live60 Stage A identity or coverage contract is invalid")
        if (
            required_metrics["recall_at_5"] < 1.0
            or required_metrics["recall_at_10"] < 0.95
            or required_metrics["mrr"] < 0.8
            or int(coverage.get("scored_issue_count") or 0) <= 0
        ):
            raise RuntimeError("Live60 Stage A retrieval threshold failed")
        result.update(
            {
                "passed": True,
                "case_count": 60,
                "selected_generation_case_count": 30,
                "coverage_only_case_count": 30,
                "scored_issue_count": int(coverage.get("scored_issue_count") or 0),
                "route_pass_count": 60,
                "subject_routing_pass_count": 60,
                "filter_violation_count": 0,
                "qualification_status_counts": dict(qualification_counts),
                **required_metrics,
            }
        )
    except (RuntimeError, TypeError, ValueError) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _matching_live30_run(
    settings: Settings,
    suite: Any | None,
    *,
    build_id: str | None,
    as_of_date: date,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Find the newest valid sealed expert overlay and its Stage A result."""

    overlay_status: dict[str, Any] = {
        "passed": False,
        "present": False,
        "sealed": False,
        "run_id": None,
        "index_build_id": None,
        "as_of_date": None,
        "seal_sha256": None,
        "candidate_binding_matches": False,
        "current_date_binding_matches": False,
        "case_status_counts": {},
        "exact_gold_span_count": 0,
        "invalid_matching_run_count": 0,
        "error_code": None,
    }
    stage_a_status: dict[str, Any] = {
        "passed": False,
        "present": False,
        "run_id": None,
        "coverage_artifact_sha256": None,
        "ranking_metric_state": None,
        "scored_issue_count": 0,
        "route_pass_count": 0,
        "subject_routing_pass_count": 0,
        "recall_at_5": None,
        "recall_at_10": None,
        "mrr": None,
        "ndcg_at_10": None,
        "exact_span_recall": None,
        "contrary_authority_recall": None,
        "thresholds": {
            "recall_at_5_minimum": 1.0,
            "recall_at_10_minimum": 0.95,
            "mrr_minimum": 0.8,
        },
        "error_code": None,
    }
    if suite is None:
        overlay_status["error_code"] = "InvalidSuite"
        return overlay_status, stage_a_status

    from .evaluation.live30 import E2ERunManifest
    from .evaluation.live30_gold import load_expert_qualification

    runs_root = settings.evaluation_dir / "e2e" / "runs"
    candidates: list[tuple[datetime, Path, Any]] = []
    if runs_root.is_dir():
        for run_root in runs_root.iterdir():
            try:
                resolved = run_root.resolve()
                resolved.relative_to(runs_root.resolve())
                manifest = E2ERunManifest.model_validate_json(
                    (resolved / "manifest.json").read_bytes()
                )
            except (OSError, UnicodeError, TypeError, ValueError):
                continue
            if (
                manifest.suite_canonical_sha256 != suite.canonical_sha256
                or manifest.suite_file_sha256 != suite.file_sha256
                or manifest.as_of_date != as_of_date
            ):
                continue
            if build_id is not None and manifest.provenance.index_build_id != build_id:
                continue
            candidates.append((manifest.created_at, resolved, manifest))

    for _created_at, run_root, manifest in sorted(candidates, reverse=True):
        overlay_status["present"] = (run_root / "expert-qualification.json").is_file()
        try:
            qualification = load_expert_qualification(
                run_root / "expert-qualification.json",
                suite=suite,
                index_build_id=str(manifest.provenance.index_build_id or ""),
                as_of_date=manifest.as_of_date,
            )
        except (OSError, TypeError, ValueError):
            overlay_status["invalid_matching_run_count"] += 1
            continue
        status_counts = Counter(case.status for case in qualification.cases)
        overlay_status.update(
            {
                "passed": bool(
                    build_id
                    and qualification.index_build_id == build_id
                    and qualification.as_of_date == as_of_date
                ),
                "present": True,
                "sealed": True,
                "run_id": manifest.run_id,
                "index_build_id": qualification.index_build_id,
                "as_of_date": qualification.as_of_date.isoformat(),
                "seal_sha256": qualification.seal_sha256,
                "candidate_binding_matches": qualification.index_build_id == build_id,
                "current_date_binding_matches": qualification.as_of_date == as_of_date,
                "case_status_counts": dict(sorted(status_counts.items())),
                "exact_gold_span_count": sum(
                    len(case.exact_gold_spans) for case in qualification.cases
                ),
                "error_code": None,
            }
        )
        coverage_path = run_root / "coverage-summary.json"
        stage_a_status["present"] = coverage_path.is_file()
        try:
            coverage = _read_json_object(coverage_path)
            stage_a_status = _stage_a_payload_status(
                coverage,
                run_id=manifest.run_id,
                qualification_sha256=qualification.seal_sha256,
                artifact_sha256=_file_sha256(coverage_path),
            )
        except (
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            stage_a_status["error_code"] = type(exc).__name__
        return overlay_status, stage_a_status

    if candidates:
        overlay_status["error_code"] = "NoValidSealedQualification"
    return overlay_status, stage_a_status


def _matching_live60_run(
    settings: Settings,
    bundle: Any | None,
    *,
    build_id: str | None,
    as_of_date: date,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Find the newest candidate-bound Live60 overlay and Stage A result."""

    overlay_status: dict[str, Any] = {
        "passed": False,
        "present": False,
        "sealed": False,
        "run_id": None,
        "index_build_id": None,
        "as_of_date": None,
        "seal_sha256": None,
        "candidate_binding_matches": False,
        "current_date_binding_matches": False,
        "case_count": 0,
        "case_status_counts": {},
        "issue_disposition_counts": {},
        "all_issues_dispositioned": False,
        "exact_gold_span_count": 0,
        "invalid_matching_run_count": 0,
        "error_code": None,
    }
    stage_a_status: dict[str, Any] = {
        "passed": False,
        "present": False,
        "run_id": None,
        "coverage_artifact_sha256": None,
        "ranking_metric_state": None,
        "case_count": 0,
        "selected_generation_case_count": 0,
        "coverage_only_case_count": 0,
        "scored_issue_count": 0,
        "route_pass_count": 0,
        "subject_routing_pass_count": 0,
        "recall_at_5": None,
        "recall_at_10": None,
        "mrr": None,
        "ndcg_at_10": None,
        "exact_span_recall": None,
        "contrary_authority_recall": None,
        "filter_violation_count": None,
        "thresholds": {
            "recall_at_5_minimum": 1.0,
            "recall_at_10_minimum": 0.95,
            "mrr_minimum": 0.8,
            "filter_violation_maximum": 0,
        },
        "error_code": None,
    }
    if bundle is None:
        overlay_status["error_code"] = "InvalidSuite"
        return overlay_status, stage_a_status

    from .evaluation.live_suite_gold import load_suite_expert_qualification
    from .evaluation.live_suite_store import LiveSuiteRunManifest

    runs_root = settings.evaluation_dir / "e2e" / "runs"
    candidates: list[tuple[datetime, Path, Any]] = []
    if runs_root.is_dir():
        for run_root in runs_root.iterdir():
            try:
                resolved = run_root.resolve()
                resolved.relative_to(runs_root.resolve())
                manifest = LiveSuiteRunManifest.model_validate_json(
                    (resolved / "manifest.json").read_bytes()
                )
                if (
                    manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
                    or manifest.suite_registry_file_sha256 != bundle.registry.file_sha256
                    or manifest.suite_registry_canonical_sha256 != bundle.registry.canonical_sha256
                    or manifest.run_plan_file_sha256 != bundle.manifest.run_plan_sha256
                    or manifest.run_plan_seal_sha256 != bundle.run_plan.seal_sha256
                    or manifest.as_of_date != as_of_date.isoformat()
                ):
                    continue
                if build_id is not None and manifest.provenance.index_build_id != build_id:
                    continue
                candidates.append((manifest.created_at, resolved, manifest))
            except (OSError, UnicodeError, TypeError, ValueError):
                continue

    for _created_at, run_root, manifest in sorted(candidates, reverse=True):
        overlay_path = run_root / "expert-qualification.json"
        overlay_status["present"] = overlay_path.is_file()
        try:
            qualification = load_suite_expert_qualification(
                overlay_path,
                bundle=bundle,
                index_build_id=str(manifest.provenance.index_build_id or ""),
                as_of_date=as_of_date,
            )
        except (OSError, TypeError, ValueError):
            overlay_status["invalid_matching_run_count"] += 1
            continue
        case_counts = Counter(case.status for case in qualification.cases)
        issue_counts = Counter(
            issue.status for case in qualification.cases for issue in case.issues
        )
        expected_issue_count = sum(len(case.must_cover_issues) for case in bundle.registry.cases)
        all_dispositioned = bool(
            sum(issue_counts.values()) == expected_issue_count
            and set(issue_counts).issubset({"qualified", "limited", "knowledge_gap"})
        )
        overlay_status.update(
            {
                "passed": bool(
                    build_id
                    and qualification.index_build_id == build_id
                    and qualification.as_of_date == as_of_date
                    and len(qualification.cases) == 60
                    and all_dispositioned
                ),
                "present": True,
                "sealed": True,
                "run_id": manifest.run_id,
                "index_build_id": qualification.index_build_id,
                "as_of_date": qualification.as_of_date.isoformat(),
                "seal_sha256": qualification.seal_sha256,
                "candidate_binding_matches": qualification.index_build_id == build_id,
                "current_date_binding_matches": qualification.as_of_date == as_of_date,
                "case_count": len(qualification.cases),
                "case_status_counts": dict(sorted(case_counts.items())),
                "issue_disposition_counts": dict(sorted(issue_counts.items())),
                "all_issues_dispositioned": all_dispositioned,
                "exact_gold_span_count": sum(
                    len(case.exact_gold_spans) for case in qualification.cases
                ),
                "error_code": None,
            }
        )
        coverage_path = run_root / "coverage-summary.json"
        stage_a_status["present"] = coverage_path.is_file()
        try:
            coverage = _read_json_object(coverage_path)
            stage_a_status = _live60_stage_a_payload_status(
                coverage,
                run_id=manifest.run_id,
                qualification_sha256=qualification.seal_sha256,
                index_build_id=qualification.index_build_id,
                bundle=bundle,
                artifact_sha256=_file_sha256(coverage_path),
            )
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            stage_a_status["error_code"] = type(exc).__name__
        return overlay_status, stage_a_status

    if candidates:
        overlay_status["error_code"] = "NoValidSealedQualification"
    return overlay_status, stage_a_status


def _owner_promotion_status(
    settings: Settings,
    database: Database,
    *,
    build_id: str | None,
) -> dict[str, Any]:
    from .retrieval.lancedb import ImmutableLanceRepository

    result: dict[str, Any] = {
        "passed": False,
        "owner_promoted_active": False,
        "active_pointer_catalogue_reconciled": False,
        "active_index_build_id": None,
        "promoted_at": None,
        "error_code": None,
    }
    if build_id is None:
        return result
    try:
        pointer = ImmutableLanceRepository(settings.index_dir).read_active()
        row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
        database_active = database.active_index_id()
        reconciled = bool(
            pointer is not None
            and pointer.build_id == build_id
            and database_active == build_id
            and row is not None
            and str(row["status"]) == "active"
        )
        promoted_at = row["promoted_at"] if row is not None else None
        result.update(
            {
                "passed": bool(reconciled and promoted_at),
                "owner_promoted_active": bool(reconciled and promoted_at),
                "active_pointer_catalogue_reconciled": reconciled,
                "active_index_build_id": database_active,
                "promoted_at": str(promoted_at) if promoted_at else None,
            }
        )
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _rollback_drill_status(
    settings: Settings,
    database: Database,
    *,
    active_build_id: str | None,
    as_of_date: date,
) -> dict[str, Any]:
    from .retrieval.lancedb import ImmutableLanceRepository

    result: dict[str, Any] = {
        "passed": False,
        "present": False,
        "active_build_id": active_build_id,
        "previous_build_id": None,
        "artifact_sha256": None,
        "error_code": None,
    }
    path = settings.project_root / READINESS_GATES / "rollback-drill.json"
    payload = _load_self_sealed_result(path, schema=ROLLBACK_DRILL_SCHEMA)
    if payload is None:
        result["present"] = path.is_file()
        if result["present"]:
            result["error_code"] = "InvalidOrUnsealedDrill"
        return result
    result["present"] = True
    result["artifact_sha256"] = _file_sha256(path)
    try:
        repository = ImmutableLanceRepository(settings.index_dir)
        active = repository.read_active()
        previous = repository.read_previous()
        active_row = (
            database.fetchone("SELECT status FROM index_builds WHERE id=?", (active.build_id,))
            if active is not None
            else None
        )
        previous_row = (
            database.fetchone("SELECT status FROM index_builds WHERE id=?", (previous.build_id,))
            if previous is not None
            else None
        )
        result["previous_build_id"] = previous.build_id if previous else None
        checks = (
            payload.get("as_of_date") == as_of_date.isoformat(),
            payload.get("promotion_observed") is True,
            payload.get("rollback_observed") is True,
            payload.get("active_pointer_catalogue_reconciled") is True,
            payload.get("previous_pointer_catalogue_reconciled") is True,
            payload.get("build_seals_verified") is True,
            active is not None,
            previous is not None,
            active_build_id is not None,
            payload.get("rollback_restored_build_id") == active_build_id,
            payload.get("final_active_build_id") == active_build_id,
            payload.get("final_previous_build_id") == previous.build_id
            if previous is not None
            else False,
            active.build_id == active_build_id if active is not None else False,
            active_row is not None and str(active_row["status"]) == "active",
            previous_row is not None and str(previous_row["status"]) in {"superseded", "candidate"},
        )
        result["passed"] = all(checks)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _browser_recovery_status(
    settings: Settings,
    database: Database,
    *,
    active_build_id: str | None,
    suite_canonical_sha256: str | None,
    as_of_date: date,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "passed": False,
        "present": False,
        "job_id": None,
        "trace_id": None,
        "artifact_sha256": None,
        "error_code": None,
    }
    path = settings.project_root / READINESS_GATES / "browser-recovery-drill.json"
    payload = _load_self_sealed_result(path, schema=BROWSER_RECOVERY_SCHEMA)
    if payload is None:
        result["present"] = path.is_file()
        if result["present"]:
            result["error_code"] = "InvalidOrUnsealedDrill"
        return result
    result["present"] = True
    result["artifact_sha256"] = _file_sha256(path)
    job_id = str(payload.get("job_id") or "")
    trace_id = str(payload.get("trace_id") or "")
    result["job_id"] = job_id or None
    result["trace_id"] = trace_id or None
    try:
        from .assessment.guidance_bundle import OWNER_ASSESSMENT_BUNDLE
        from .evaluation.browser_recovery import (
            ordinary_drill_request_fingerprint,
            sealed_build_source_manifest,
        )
        from .orchestration.classifier import CLASSIFIER_VERSION
        from .orchestration.routing import ROUTER_VERSION
        from .retrieval.lancedb import ImmutableLanceRepository
        from .runtime_adapters import PROMPT_VERSION

        job = database.fetchone(
            """
            SELECT id, status, pinned_index_build_id, trace_id, answer_id,
                   encrypted_question, request_json, route, word_target,
                   job_type, evaluation_run_id, evaluation_case_id,
                   evaluation_request_sha256, trace_full_retention,
                   worker_prompt_version, worker_router_version,
                   worker_classifier_version, worker_policy_sha256,
                   assessment_bundle_sha256
            FROM jobs WHERE id=?
            """,
            (job_id,),
        )
        outbox = database.fetchall(
            """
            SELECT answer_id, release_state, status, published_at
            FROM release_outbox WHERE job_id=?
            """,
            (job_id,),
        )
        answer = (
            database.fetchone(
                """
                SELECT id, model_version, policy_sha256, index_build_id, word_count
                FROM answer_versions WHERE id=?
                """,
                (str(job["answer_id"]),),
            )
            if job is not None and job["answer_id"]
            else None
        )
        case_run_links = database.fetchall(
            "SELECT id FROM evaluation_case_runs WHERE job_id=?", (job_id,)
        )
        repository = ImmutableLanceRepository(settings.index_dir)
        pointer = repository.read_active()
        source_manifest_sha256 = (
            sealed_build_source_manifest(
                repository,
                active_build_id=str(active_build_id),
                active_manifest_sha256=pointer.manifest_sha256,
            )
            if pointer is not None and active_build_id is not None
            else None
        )
        request: dict[str, Any] | None = None
        request_fingerprint: str | None = None
        if job is not None:
            decoded = json.loads(str(job["request_json"] or "{}"))
            if not isinstance(decoded, dict):
                raise ValueError("browser drill request is not an object")
            request = decoded
            request_fingerprint = ordinary_drill_request_fingerprint(
                encrypted_question=bytes(job["encrypted_question"]),
                request=request,
                route=str(job["route"] or ""),
                word_target=int(job["word_target"] or 0),
                active_build_id=str(active_build_id or ""),
            )
        checks = (
            payload.get("as_of_date") == as_of_date.isoformat(),
            payload.get("active_build_id") == active_build_id,
            payload.get("suite_canonical_sha256") == suite_canonical_sha256,
            payload.get("drill_job_kind") == "ordinary_local_answer",
            payload.get("counts_as_live60_selected_outcome") is False,
            payload.get("live60_evaluation_binding_absent") is True,
            int(payload.get("live60_case_run_link_count") or 0) == 0,
            payload.get("request_fingerprint_sha256") == request_fingerprint,
            payload.get("route") == (str(job["route"] or "") if job is not None else None),
            int(payload.get("word_target") or 0)
            == (int(job["word_target"] or 0) if job is not None else -1),
            payload.get("model_version") == settings.model_id,
            payload.get("active_manifest_sha256")
            == (pointer.manifest_sha256 if pointer is not None else None),
            payload.get("source_manifest_sha256") == source_manifest_sha256,
            payload.get("prompt_version") == PROMPT_VERSION,
            payload.get("router_version") == ROUTER_VERSION,
            payload.get("classifier_version") == CLASSIFIER_VERSION,
            payload.get("policy_sha256") == POLICY_SHA256,
            payload.get("assessment_bundle_sha256") == OWNER_ASSESSMENT_BUNDLE.sha256,
            payload.get("real_browser") is True,
            payload.get("loopback_only") is True,
            int(payload.get("online_adapter_call_count") or 0) == 0,
            payload.get("page_reloaded_while_running") is True,
            payload.get("same_job_recovered_after_reload") is True,
            payload.get("progress_resumed") is True,
            payload.get("terminal_state_visible") is True,
            payload.get("no_indefinite_spinner") is True,
            payload.get("exactly_one_release") is True,
            payload.get("privacy_passed") is True,
            job is not None,
            str(job["status"]) == "complete" if job is not None else False,
            str(job["job_type"] or "") == "answer" if job is not None else False,
            not job["evaluation_run_id"] if job is not None else False,
            not job["evaluation_case_id"] if job is not None else False,
            not job["evaluation_request_sha256"] if job is not None else False,
            int(job["trace_full_retention"] or 0) == 0 if job is not None else False,
            len(case_run_links) == 0,
            str(job["pinned_index_build_id"] or "") == active_build_id
            if job is not None
            else False,
            str(job["trace_id"] or "") == trace_id if job is not None else False,
            bool(job["answer_id"]) if job is not None else False,
            len(outbox) == 1,
            str(outbox[0]["status"]) == "published" if len(outbox) == 1 else False,
            str(outbox[0]["answer_id"]) == str(job["answer_id"])
            if len(outbox) == 1 and job is not None
            else False,
            answer is not None,
            str(answer["model_version"] or "") == settings.model_id
            if answer is not None
            else False,
            str(answer["policy_sha256"] or "") == POLICY_SHA256 if answer is not None else False,
            str(answer["index_build_id"] or "") == active_build_id if answer is not None else False,
            str(job["worker_prompt_version"] or "") == PROMPT_VERSION if job is not None else False,
            str(job["worker_router_version"] or "") == ROUTER_VERSION if job is not None else False,
            str(job["worker_classifier_version"] or "") == CLASSIFIER_VERSION
            if job is not None
            else False,
            str(job["worker_policy_sha256"] or "") == POLICY_SHA256 if job is not None else False,
            str(job["assessment_bundle_sha256"] or "") == OWNER_ASSESSMENT_BUNDLE.sha256
            if job is not None
            else False,
            request is not None and request.get("as_of_date") == as_of_date.isoformat(),
        )
        result["passed"] = all(checks)
    except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _live60_authorization_status(
    settings: Settings,
    *,
    registry_status: Mapping[str, Any],
    run_id: str | None,
    active_build_id: str | None,
) -> dict[str, Any]:
    """Validate owner decision O-04 without allowing code to self-authorise.

    Technical readiness deliberately precedes this decision.  The artifact
    binds the owner authorisation to one already-created run, one immutable
    build and the exact 30-outcome, zero-repeat Live60 run-plan digest.
    """

    result: dict[str, Any] = {
        "passed": False,
        "present": False,
        "decision_code": "O-04",
        "run_id": run_id,
        "active_build_id": active_build_id,
        "artifact_sha256": None,
        "error_code": None,
    }
    if not run_id:
        return result
    path = settings.evaluation_dir / "e2e" / "runs" / run_id / "execution-authorization.json"
    result["present"] = path.is_file()
    if not path.is_file():
        return result
    result["artifact_sha256"] = _file_sha256(path)
    try:
        from .evaluation.live_suite_execute import Live60ExecutionAuthorization

        authorization = Live60ExecutionAuthorization.model_validate_json(path.read_bytes())
        checks = (
            authorization.run_id == run_id,
            authorization.active_build_id == active_build_id,
            authorization.suite_id == "live-evaluation-60-v1",
            authorization.suite_manifest_seal_sha256
            == registry_status.get("suite_manifest_seal_sha256"),
            authorization.run_plan_seal_sha256 == registry_status.get("run_plan_seal_sha256"),
            list(authorization.authorized_case_ids) == registry_status.get("selected_case_ids"),
            authorization.authorized_pass_count == 1,
            authorization.local_only is True,
            authorization.online_research_allowed is False,
            authorization.readiness_ready is True,
            authorization.readiness_blocker_count == 0,
            authorization.o04_authorization_ref.startswith("o04:"),
            bool(active_build_id),
        )
        result["passed"] = all(checks)
        if not result["passed"]:
            result["error_code"] = "AuthorizationBindingMismatch"
    except (OSError, TypeError, ValueError) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _blind_calibration_status(settings: Settings) -> dict[str, Any]:
    result: dict[str, Any] = {
        "claim_permitted": False,
        "report_present": False,
        "report_passed": False,
        "seal_valid": False,
        "report_sha256": None,
        "error_code": None,
    }
    report_path = settings.evaluation_dir / "calibration" / "blind-human-report.json"
    seal_path = settings.evaluation_dir / "calibration" / "blind-human-report.seal.json"
    result["report_present"] = report_path.is_file()
    try:
        report = _read_json_object(report_path)
        seal = _load_self_sealed_result(seal_path, schema=CALIBRATION_SEAL_SCHEMA)
        report_sha = _file_sha256(report_path)
        result["report_sha256"] = report_sha
        metrics = report.get("metrics")
        thresholds = report.get("thresholds")
        if not isinstance(metrics, dict) or not isinstance(thresholds, dict):
            raise ValueError("calibration metrics or thresholds are missing")
        recalculated = bool(
            int(metrics["unique_cases"]) >= int(thresholds["unique_cases_minimum"])
            and int(metrics["subjects"]) >= int(thresholds["subjects_minimum"])
            and int(metrics["independent_reviewers"])
            >= int(thresholds["independent_reviewers_minimum"])
            and float(metrics["double_review_fraction"])
            >= float(thresholds["double_review_fraction_minimum"])
            and int(metrics["human_70_plus"]) >= int(thresholds["human_70_plus_minimum"])
            and int(metrics["human_below_70"]) >= int(thresholds["human_below_70_minimum"])
            and float(metrics["pass_fail_agreement"])
            >= float(thresholds["pass_fail_agreement_minimum"])
            and float(metrics["mean_absolute_score_error"])
            <= float(thresholds["mean_absolute_score_error_maximum"])
            and int(metrics["dangerous_false_passes"])
            <= int(thresholds["dangerous_false_passes_maximum"])
        )
        report_passed = bool(
            report.get("schema") == "legalbot.blind-human-calibration-report.v1"
            and report.get("purpose") == "evaluation_only"
            and report.get("eligible_for_training") is False
            and report.get("training_export_allowed") is False
            and report.get("passed") is True
            and thresholds == BLIND_CALIBRATION_THRESHOLDS
            and recalculated
        )
        seal_valid = bool(
            seal is not None
            and seal.get("status") == "SEALED"
            and seal.get("report_sha256") == report_sha
        )
        result.update(
            {
                "claim_permitted": report_passed and seal_valid,
                "report_passed": report_passed,
                "seal_valid": seal_valid,
            }
        )
    except (
        KeyError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        result["error_code"] = type(exc).__name__
    return result


def _first_live_profile_status(settings: Settings) -> dict[str, Any]:
    from .config import FIRST_LIVE_LOCAL_ONLY_PROFILE

    model_host = (urlsplit(settings.model_url).hostname or "").casefold()
    loopback = {"127.0.0.1", "localhost", "::1"}
    checks = {
        "first_live_profile_selected": (settings.live_profile == FIRST_LIVE_LOCAL_ONLY_PROFILE),
        "api_loopback_only": settings.host.casefold() in loopback,
        "model_loopback_only": model_host in loopback,
        "online_mode_local_only": settings.online_default == "local_only",
        "official_research_disabled": settings.official_research_enabled is False,
        "online_adapter_attempt_is_fatal": settings.evaluation_forbids_online_research,
    }
    return {"passed": all(checks.values()), **checks}


def _build_readiness_report_v5(settings: Settings, database: Database) -> dict[str, Any]:
    """Build the current readiness report with fail-closed suite selection.

    Blind 70+ calibration is deliberately a claim gate rather than a live-run
    gate.  A controlled development evaluation may run without making that
    claim, but it may not run without exact registry, evidence, Stage A,
    promotion, rollback, browser-recovery, local-only and privacy gates.  When
    the Live60 contract is present it cannot silently fall back to Live30.
    """

    def count(sql: str, parameters: tuple[Any, ...] = ()) -> int:
        row = database.fetchone(sql, parameters)
        return int(row["n"] if row else 0)

    today = _local_today()
    latest_scan = database.fetchone(
        """SELECT id,status,expected_file_count,files_accounted,manifest_sha256,completed_at
           FROM source_scans ORDER BY created_at DESC LIMIT 1"""
    )
    scan_internal = bool(
        latest_scan
        and latest_scan["status"] == "complete"
        and int(latest_scan["expected_file_count"]) == int(latest_scan["files_accounted"])
        and latest_scan["manifest_sha256"]
    )
    source_files_seen = 0
    source_files_newer = 0
    completed_at: float | None = None
    if latest_scan and latest_scan["completed_at"]:
        with suppress(ValueError):
            completed_at = datetime.fromisoformat(str(latest_scan["completed_at"])).timestamp()
    for root in settings.source_roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            source_files_seen += 1
            try:
                if completed_at is not None and path.stat().st_mtime > completed_at:
                    source_files_newer += 1
            except OSError:
                source_files_newer += 1
    roots_unchanged = bool(
        completed_at is not None
        and latest_scan
        and source_files_seen == int(latest_scan["expected_file_count"])
        and source_files_newer == 0
    )
    pending_sources = count(
        """SELECT COUNT(*) n FROM source_versions sv JOIN documents d ON d.id=sv.document_id
           WHERE sv.superseded_by IS NULL AND sv.review_status='staged'
             AND d.retrieval_canonical=1 AND d.duplicate_of IS NULL"""
    )
    approved_legal = database.fetchall(
        """SELECT d.jurisdiction,sv.stable_identifier,sv.currentness_status,sv.metadata_json
           FROM source_versions sv JOIN documents d ON d.id=sv.document_id
           WHERE sv.superseded_by IS NULL AND sv.review_status='approved'
             AND d.retrieval_canonical=1 AND d.duplicate_of IS NULL
             AND d.lane IN ('primary_authority','official_secondary','scholarship')"""
    )
    unqualified = 0
    rights_excluded_catalogue_only = 0
    case_proposition_currentness_gated = 0
    runtime_eligible_approved_legal = 0
    revised_snapshot_count = 0
    revised_with_unapplied = 0
    extent_unverified = 0
    for row in approved_legal:
        source_state = _approved_legal_source_state(row)
        if source_state == "rights_excluded_catalogue_only":
            rights_excluded_catalogue_only += 1
        else:
            runtime_eligible_approved_legal += 1
        if source_state == "case_proposition_currentness_gated":
            case_proposition_currentness_gated += 1
        elif source_state == "unqualified":
            unqualified += 1
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            metadata = {}
        if ":latest-available@" in str(row["stable_identifier"] or ""):
            revised_snapshot_count += 1
            official = metadata.get("official_snapshot")
            official = official if isinstance(official, dict) else {}
            if int(official.get("unapplied_effect_count") or 0) > 0:
                revised_with_unapplied += 1
            if metadata.get("provision_extent_status") not in {
                "england_and_wales_verified",
                "uk_with_england_wales_verified",
            }:
                extent_unverified += 1
    privacy = build_candidate_privacy_report(settings, database)
    source_gate = {
        "scan_reconciled": scan_internal and roots_unchanged,
        "source_decisions_complete": pending_sources == 0,
        "approved_legal_sources_qualified": unqualified == 0,
        "privacy_passed": privacy.get("passed") is True,
    }

    benchmark_pointer = settings.retrieval_benchmark_path
    benchmark_status = "missing"
    benchmark_case_count = 0
    if benchmark_pointer.is_file():
        try:
            pointer = _read_json_object(benchmark_pointer)
            benchmark_status = str(pointer.get("status") or "invalid")
            benchmark_case_count = int(pointer.get("case_count") or 0)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            benchmark_status = "invalid"
    freeze_valid = False
    freeze_error: str | None = None
    try:
        from .retrieval.retrieval_v1 import verify_owner_freeze

        verify_owner_freeze(
            settings.project_root,
            settings.project_root / "benchmarks" / "retrieval" / "v1.1.jsonl",
        )
        freeze_valid = True
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        freeze_error = type(exc).__name__
    a2_valid = _a2_seal_is_valid(settings)
    retrieval_gate = {
        "v1_1_has_24_rows": benchmark_case_count == 24,
        "v1_1_owner_frozen": freeze_valid,
    }

    live60_selected = (settings.project_root / LIVE60_ROOT).exists()
    if live60_selected:
        registry_status, suite = _live60_registry_status(settings)
        evaluation_contract = "live60"
    else:
        registry_status, suite = _live30_registry_status(settings)
        evaluation_contract = "live30"
    latest_build = database.fetchone("SELECT * FROM index_builds ORDER BY created_at DESC LIMIT 1")
    selected_candidate = database.fetchone(
        """SELECT * FROM index_builds
           WHERE status IN ('candidate','active')
           ORDER BY created_at DESC LIMIT 1"""
    )
    candidate_status = _current_law_candidate_status(
        settings, database, selected_candidate, as_of_date=today
    )
    selected_build_id = candidate_status.get("build_id")
    build_id = str(selected_build_id) if selected_build_id else None
    if live60_selected:
        overlay_status, stage_a_status = _matching_live60_run(
            settings,
            suite,
            build_id=build_id,
            as_of_date=today,
        )
    else:
        overlay_status, stage_a_status = _matching_live30_run(
            settings,
            suite,
            build_id=build_id,
            as_of_date=today,
        )
    promotion_status = _owner_promotion_status(settings, database, build_id=build_id)
    rollback_status = _rollback_drill_status(
        settings,
        database,
        active_build_id=(
            str(promotion_status["active_index_build_id"])
            if promotion_status.get("active_index_build_id")
            else None
        ),
        as_of_date=today,
    )
    browser_status = _browser_recovery_status(
        settings,
        database,
        active_build_id=(
            str(promotion_status["active_index_build_id"])
            if promotion_status.get("active_index_build_id")
            else None
        ),
        suite_canonical_sha256=(
            str(registry_status["suite_canonical_sha256"])
            if registry_status.get("suite_canonical_sha256")
            else None
        ),
        as_of_date=today,
    )
    first_live_profile = _first_live_profile_status(settings)
    calibration_status = _blind_calibration_status(settings)
    live_authorization = (
        _live60_authorization_status(
            settings,
            registry_status=registry_status,
            run_id=(str(overlay_status["run_id"]) if overlay_status.get("run_id") else None),
            active_build_id=(
                str(promotion_status["active_index_build_id"])
                if promotion_status.get("active_index_build_id")
                else None
            ),
        )
        if live60_selected
        else {
            "passed": False,
            "present": False,
            "decision_code": "O-04",
            "not_applicable_to_legacy_live30": True,
        }
    )

    duplicate_model = settings.project_root / "Qwen3.5-9B-Base"
    runtime_model = settings.project_root / "models/runtime/Qwen3.5-9B-4bit"
    archive_model = settings.project_root / "models/archive/Qwen3.5-9B-Base"
    adapters_root = settings.project_root / "models" / "adapters"
    fine_tuned_adapter_present = bool(adapters_root.is_dir() and any(adapters_root.iterdir()))
    hard_gates = {
        "source_registry": all(source_gate.values()),
        "retrieval_v1_1_specification": all(retrieval_gate.values()),
        "a2_behavior_gold_separately_sealed": a2_valid,
        f"{evaluation_contract}_registry_integrity": (registry_status["passed"] is True),
        "current_date_candidate": candidate_status["passed"] is True,
        "sealed_expert_overlay": overlay_status["passed"] is True,
        "stage_a_coverage_and_thresholds": stage_a_status["passed"] is True,
        "owner_promoted_active": promotion_status["passed"] is True,
        "active_previous_rollback_drill": rollback_status["passed"] is True,
        "real_browser_recovery_drill": browser_status["passed"] is True,
        "first_live_local_only_profile": first_live_profile["passed"] is True,
        "runtime_model_present": runtime_model.is_dir(),
    }
    all_hard_gates = all(hard_gates.values())
    if all_hard_gates:
        readiness_status = "ready"
    elif promotion_status["passed"] is True:
        readiness_status = "degraded"
    else:
        readiness_status = "not_ready"
    gate_split = split_readiness_blocking_gates(hard_gates)
    serving_index_present = promotion_status["passed"] is True
    overlay_passed = overlay_status["passed"] is True
    live_runtime_separation = classify_live_and_live60_state(
        serving_index_present=serving_index_present,
        previous_approved_active_present=serving_index_present,
        runtime_eligible_approved_source_count=runtime_eligible_approved_legal,
        path_b_selected_qualified_with_spans=305 if overlay_passed else 0,
        overlay_sealed=overlay_passed,
        overlay_blockers=()
        if overlay_passed
        else ("selected_issues_missing_positive_exact_spans",),
        degraded=readiness_status == "degraded",
        operator_promoted=promotion_status["passed"] is True,
        candidate_build_present=False,
    )

    report: dict[str, Any] = {
        "schema": (
            "legalbot.production-readiness.v6"
            if live60_selected
            else "legalbot.production-readiness.v5"
        ),
        "created_at": utc_iso(),
        "as_of_date": today.isoformat(),
        "status": readiness_status,
        "ready": readiness_status == "ready",
        "degraded": readiness_status == "degraded",
        "authoritative_architecture": "docs/CURRENT_STATE.md",
        "product_scope": PRODUCT_JURISDICTION,
        "quality_policy_version": POLICY_VERSION,
        "quality_policy_sha256": POLICY_SHA256,
        "hard_gates": hard_gates,
        "blocking_gates": sorted(key for key, passed in hard_gates.items() if not passed),
        "runtime_blocking_gates": gate_split["runtime_blocking_gates"],
        "live60_benchmark_blocking_gates": gate_split["live60_benchmark_blocking_gates"],
        "live_runtime_separation": live_runtime_separation,
        "evaluation_candidate_state": live_runtime_separation["evaluation_candidate_state"],
        "production_promotion_state": live_runtime_separation["production_promotion_state"],
        "evaluation_requires_owner_promoted_active": False,
        "evaluation_requires_o04": False,
        "source_registry": {
            "passed": all(source_gate.values()),
            **source_gate,
            "latest_scan": dict(latest_scan) if latest_scan else None,
            "source_files_seen": source_files_seen,
            "source_files_newer_than_scan": source_files_newer,
            "pending_source_decisions": pending_sources,
            "approved_legal_sources": len(approved_legal),
            "runtime_eligible_approved_legal_sources": (runtime_eligible_approved_legal),
            "rights_excluded_catalogue_only_sources": (rights_excluded_catalogue_only),
            "case_proposition_currentness_gated_sources": (case_proposition_currentness_gated),
            "unqualified_approved_legal_sources": unqualified,
            "latest_available_revised_snapshots": revised_snapshot_count,
            "snapshots_with_unapplied_effects": revised_with_unapplied,
            "legislation_sources_without_provision_extent_verification": extent_unverified,
            "privacy": privacy,
        },
        "retrieval_specification": {
            "passed": all(retrieval_gate.values()),
            **retrieval_gate,
            "benchmark_status": benchmark_status,
            "benchmark_case_count": benchmark_case_count,
            "freeze_error": freeze_error,
            "a2_is_not_retrieval_gold": True,
            "old_v1_promotion_eligible": False,
        },
        "behavior_gold": {
            "passed": a2_valid,
            "a2_separately_sealed": a2_valid,
            "used_as_live_answer_gold": False,
            "used_as_live30_answer_gold": False,
        },
        "live_evaluation_contract": evaluation_contract,
        "live_evaluation_registry": registry_status,
        "current_law_candidate": {
            **candidate_status,
            "source_registry_passed": all(source_gate.values()),
            "retrieval_specification_passed": all(retrieval_gate.values()),
            "latest_build": (
                {
                    "id": latest_build["id"],
                    "status": latest_build["status"],
                    "stage": latest_build["stage"],
                }
                if latest_build
                else None
            ),
        },
        "expert_qualification": overlay_status,
        "stage_a": stage_a_status,
        "owner_promotion": promotion_status,
        "operational_drills": {
            "passed": rollback_status["passed"] is True and browser_status["passed"] is True,
            "rollback": rollback_status,
            "browser_recovery": browser_status,
        },
        "first_live_runtime_profile": first_live_profile,
        "blind_70_calibration": {
            **calibration_status,
            "separate_from_live_evaluation_readiness": True,
            "automated_academic_score_is_advisory": True,
            "consistent_70_plus_claim_allowed": calibration_status["claim_permitted"],
        },
        "debug_e2e": {
            "ready": all_hard_gates,
            "authorised": (
                all_hard_gates
                and (live_authorization["passed"] is True if live60_selected else True)
            ),
            "local_model_and_active_index_only": first_live_profile["passed"],
            "online_research_disabled_for_first_run": first_live_profile[
                "official_research_disabled"
            ],
            "browser_recovery_passed": browser_status["passed"],
            "rollback_drill_passed": rollback_status["passed"],
        },
        "assessment_guidance": {
            "approved_assessment_rules": count(
                "SELECT COUNT(*) n FROM rubric_rules WHERE review_status='approved'"
            ),
            "staged_assessment_rules": count(
                "SELECT COUNT(*) n FROM rubric_rules WHERE review_status='staged'"
            ),
            "automated_academic_score_is_advisory": True,
        },
        "model_and_storage": {
            "duplicate_root_model_absent": not duplicate_model.exists(),
            "runtime_4bit_present": runtime_model.is_dir(),
            "recovery_archive_present": archive_model.is_dir(),
            "fine_tuned_adapter_present": fine_tuned_adapter_present,
            "fine_tuning_performed": fine_tuned_adapter_present,
        },
        "knowledge_gaps": {
            "open_runtime_gaps": count(
                "SELECT COUNT(*) n FROM knowledge_gaps WHERE status<>'resolved'"
            ),
            "coverage_is_proven_only_by_executable_evaluation": True,
        },
        "live_run_authorization": live_authorization,
        "real_e2e_authorised": (
            all_hard_gates and (live_authorization["passed"] is True if live60_selected else True)
        ),
        "consistent_70_plus_claim_allowed": calibration_status["claim_permitted"],
    }
    # Preserve the sealed Live30 report shape for legacy fixtures and archived
    # consumers.  Live60 reports expose the new explicit key and never pretend
    # to be the historical three-pass strategy.
    report[f"{evaluation_contract}_registry"] = registry_status
    return report


def build_readiness_report(settings: Settings, database: Database) -> dict[str, Any]:
    """Return technical readiness plus authoritative v1.11 normal-live status.

    The historical ``ready`` field remains the pre-holdout technical/operations
    result consumed by legacy drills.  It is explicitly not authority for
    LegalBot v1.11 normal live; callers must require ``normal_live_ready``.
    """

    from .evaluation.owner_quality_normal_live_readiness import (
        owner_quality_normal_live_readiness_status,
    )

    report = _build_readiness_report_v5(settings, database)
    owner_quality = owner_quality_normal_live_readiness_status(
        settings.project_root,
        database=database,
        settings=settings,
    )
    report["legacy_technical_ready"] = report.get("ready") is True
    report["ready_scope"] = "legacy_pre_holdout_technical_and_operational_only"
    report["legacy_ready_is_not_v111_normal_live"] = True
    report["normal_live_readiness_v111"] = owner_quality
    report["normal_live_ready"] = owner_quality["normal_live_ready"] is True
    report["normal_live_blocking_gates"] = list(owner_quality["blocking_reason_codes"])
    report["normal_live_authorised"] = owner_quality["normal_live_ready"] is True
    return report


def write_readiness_report(settings: Settings, report: dict[str, Any]) -> Path:
    destination = settings.data_dir / "reports" / "production-readiness.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination
