from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from app.config import Settings
from app.db import Database
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_execute import Live60ExecutionAuthorization
from app.readiness import (
    _live60_authorization_status,
    _live60_registry_status,
    _live60_stage_a_payload_status,
    build_readiness_report,
)

ROOT = Path(__file__).resolve().parents[2]


def _copy_live60_contract(tmp_path: Path) -> Settings:
    evaluation = tmp_path / "benchmarks/evaluation"
    evaluation.mkdir(parents=True)
    shutil.copytree(
        ROOT / "benchmarks/evaluation/live-evaluation-30-v1",
        evaluation / "live-evaluation-30-v1",
    )
    shutil.copytree(
        ROOT / "benchmarks/evaluation/live-evaluation-60-v1",
        evaluation / "live-evaluation-60-v1",
    )
    return Settings(project_root=tmp_path)


def test_live60_readiness_validates_lineage_and_exact_single_pass_plan(
    tmp_path: Path,
) -> None:
    settings = _copy_live60_contract(tmp_path)

    status, bundle = _live60_registry_status(settings)

    assert bundle is not None
    assert status["passed"] is True
    assert status["case_count"] == 60
    assert status["total_word_target"] == 215_000
    assert status["generation_case_count"] == 30
    assert status["generation_total_word_target"] == 114_000
    assert status["coverage_only_case_count"] == 30
    assert status["single_pass_outcome_count"] == 30
    assert status["stability_repeat_count"] == 0
    assert all(len(case_ids) == 10 for case_ids in status["annexes"].values())

    plan_path = tmp_path / "benchmarks/evaluation/live-evaluation-60-v1/generation-run-plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["stability_repeats"] = 1
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    changed, changed_bundle = _live60_registry_status(settings)
    assert changed_bundle is None
    assert changed["passed"] is False


def test_live60_stage_a_requires_all60_dispositions_and_exact_plan_lists() -> None:
    bundle = load_live_evaluation_bundle(ROOT / "benchmarks/evaluation/live-evaluation-60-v1")
    qualification_sha = "a" * 64
    coverage_only = [
        item.case_id
        for item in bundle.run_plan.cases
        if item.disposition == "coverage_only_not_selected"
    ]
    selected = [
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    ]
    payload: dict[str, object] = {
        "schema": "legalbot.live-coverage-summary.v3",
        "run_id": "live60-stage-a-test",
        "suite_id": "live-evaluation-60-v1",
        "case_count": 60,
        "case_ids": [case.case_id for case in bundle.registry.cases],
        "coverage_only_not_selected_case_ids": coverage_only,
        "selected_generation_case_count": 30,
        "selected_generation_eligible_case_ids": selected[:20],
        "route_pass_count": 60,
        "subject_routing_pass_count": 60,
        "qualification_status_counts": {
            "qualified": 45,
            "limited": 10,
            "knowledge_gap": 5,
        },
        "ranking_metric_state": "evaluated_against_sealed_qualifying_issue_gold",
        "expert_qualification_sha256": qualification_sha,
        "index_build_id": "candidate-live60-test",
        "scored_issue_count": 120,
        "recall_at_5": 1.0,
        "recall_at_10": 0.95,
        "mrr": 0.8,
        "ndcg_at_10": 0.9,
        "exact_span_recall": 0.9,
        "contrary_authority_recall": 1.0,
        "filter_violation_count": 0,
        "stage_a_evaluated": True,
        "stage_a_passed": True,
        "generation_started": False,
    }

    status = _live60_stage_a_payload_status(
        payload,
        run_id="live60-stage-a-test",
        qualification_sha256=qualification_sha,
        index_build_id="candidate-live60-test",
        bundle=bundle,
        artifact_sha256="b" * 64,
    )
    assert status["passed"] is True
    assert status["case_count"] == 60
    assert status["coverage_only_case_count"] == 30

    payload["qualification_status_counts"] = {"qualified": 59}
    failed = _live60_stage_a_payload_status(
        payload,
        run_id="live60-stage-a-test",
        qualification_sha256=qualification_sha,
        index_build_id="candidate-live60-test",
        bundle=bundle,
    )
    assert failed["passed"] is False
    assert failed["error_code"] == "ValueError"


def test_live60_report_stays_no_go_and_o04_is_separate(tmp_path: Path, monkeypatch) -> None:
    settings = _copy_live60_contract(tmp_path)
    source_root = tmp_path / "sources"
    source_root.mkdir()
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    database = Database(settings.database_path)
    database.initialize()
    try:
        report = build_readiness_report(settings, database)
    finally:
        database.close()

    assert report["schema"] == "legalbot.production-readiness.v6"
    assert report["live_evaluation_contract"] == "live60"
    assert report["live60_registry"]["passed"] is True
    assert report["status"] == "not_ready"
    assert report["live_run_authorization"]["passed"] is False
    assert report["real_e2e_authorised"] is False
    assert "sealed_expert_overlay" in report["blocking_gates"]
    assert "sealed_expert_overlay" in report["live60_benchmark_blocking_gates"]
    assert "sealed_expert_overlay" not in report["runtime_blocking_gates"]
    assert "stage_a_coverage_and_thresholds" not in report["runtime_blocking_gates"]
    assert "selected_issues_missing_positive_exact_spans" not in report["runtime_blocking_gates"]
    separation = report["live_runtime_separation"]
    assert separation["runtime_blocked_by_path_b_span_gap"] is False
    assert separation["live60_overlay_status"] == "UNSEALED"
    assert separation["live60_promotion_status"] == "HOLD"
    assert separation["runtime_status"] == "NOT_SERVING"


def test_live60_authorization_rejects_wrong_bindings_and_tampered_seal(
    tmp_path: Path,
) -> None:
    settings = _copy_live60_contract(tmp_path)
    status, bundle = _live60_registry_status(settings)
    assert bundle is not None
    run_id = "live60-auth-test"
    selected = list(status["selected_case_ids"])
    path = settings.evaluation_dir / "e2e" / "runs" / run_id / "execution-authorization.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    def write(value: dict[str, object]) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")

    base: dict[str, object] = {
        "schema": "legalbot.live60-execution-authorization.v1",
        "authorization_id": "authorization-live60-auth-test",
        "run_id": run_id,
        "suite_id": "live-evaluation-60-v1",
        "suite_manifest_seal_sha256": status["suite_manifest_seal_sha256"],
        "run_plan_seal_sha256": status["run_plan_seal_sha256"],
        "active_build_id": "candidate-live60-auth",
        "owner_promotion_ref": "promotion:" + "3" * 64,
        "rollback_repromotion_report_sha256": "4" * 64,
        "browser_recovery_report_sha256": "5" * 64,
        "readiness_report_sha256": "6" * 64,
        "readiness_ready": True,
        "readiness_blocker_count": 0,
        "o04_authorization_ref": "o04:" + "7" * 64,
        "local_only": True,
        "online_research_allowed": False,
        "authorized_pass_count": 1,
        "authorized_case_ids": selected,
        "issued_at": datetime(2026, 8, 15, 8, 30, tzinfo=UTC).isoformat().replace("+00:00", "Z"),
        "owner_ref": "owner:" + "8" * 64,
    }
    sealed = {**base, "seal_sha256": sealed_sha256(base)}
    Live60ExecutionAuthorization.model_validate(sealed)
    write(sealed)
    matched = _live60_authorization_status(
        settings,
        registry_status=status,
        run_id=run_id,
        active_build_id="candidate-live60-auth",
    )
    assert matched["present"] is True
    assert matched["passed"] is True

    wrong_run = _live60_authorization_status(
        settings,
        registry_status=status,
        run_id="live60-other-run",
        active_build_id="candidate-live60-auth",
    )
    assert wrong_run["passed"] is False

    wrong_build = _live60_authorization_status(
        settings,
        registry_status=status,
        run_id=run_id,
        active_build_id="other-build",
    )
    assert wrong_build["passed"] is False
    assert wrong_build["error_code"] == "AuthorizationBindingMismatch"

    wrong_ids = {**base, "authorized_case_ids": [*selected[1:], "live60-q99"]}
    write({**wrong_ids, "seal_sha256": sealed_sha256(wrong_ids)})
    wrong_cases = _live60_authorization_status(
        settings,
        registry_status=status,
        run_id=run_id,
        active_build_id="candidate-live60-auth",
    )
    assert wrong_cases["passed"] is False

    tampered = {**sealed, "seal_sha256": "0" * 64}
    write(tampered)
    broken = _live60_authorization_status(
        settings,
        registry_status=status,
        run_id=run_id,
        active_build_id="candidate-live60-auth",
    )
    assert broken["passed"] is False
    assert broken["error_code"] in {"ValueError", "ValidationError"}
