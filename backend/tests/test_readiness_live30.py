from __future__ import annotations

import json
import shutil
from datetime import date
from pathlib import Path

from app.config import Settings
from app.db import Database
from app.evaluation.live30 import EXPECTED_CASE_IDS
from app.readiness import (
    BROWSER_RECOVERY_SCHEMA,
    CALIBRATION_SEAL_SCHEMA,
    ROLLBACK_DRILL_SCHEMA,
    _approved_legal_source_state,
    _blind_calibration_status,
    _browser_recovery_status,
    _canonical_self_seal,
    _live30_registry_status,
    _load_self_sealed_result,
    _rollback_drill_status,
    _stage_a_payload_status,
    build_readiness_report,
)

ROOT = Path(__file__).resolve().parents[2]


def test_source_readiness_separates_rights_exclusions_and_case_span_currentness() -> None:
    base = {
        "stable_identifier": "neutral-citation:[2021] UKSC 29",
        "jurisdiction": "England and Wales",
    }
    rights_held = {
        **base,
        "metadata_json": json.dumps(
            {
                "identity_verified": True,
                "currentness_verified": False,
                "eligible_for_model_use": False,
                "ai_use_policy": "metadata_only_pending_rights_review",
                "citation_data": {"source_type": "case"},
            }
        ),
    }
    proposition_gated = {
        **base,
        "metadata_json": json.dumps(
            {
                "identity_verified": True,
                "currentness_verified": False,
                "eligible_for_model_use": True,
                "ai_use_policy": "unreviewed",
                "citation_data": {"source_type": "case"},
            }
        ),
    }
    unqualified_legislation = {
        "stable_identifier": "ukpga:2026:1:latest-available@2026-08-14",
        "jurisdiction": "United Kingdom",
        "metadata_json": json.dumps(
            {
                "identity_verified": True,
                "currentness_verified": False,
                "eligible_for_model_use": True,
                "ai_use_policy": "unreviewed",
                "citation_data": {"source_type": "legislation"},
            }
        ),
    }

    assert _approved_legal_source_state(rights_held) == "rights_excluded_catalogue_only"
    assert _approved_legal_source_state(proposition_gated) == "case_proposition_currentness_gated"
    assert _approved_legal_source_state(unqualified_legislation) == "unqualified"


def _write_self_sealed(path: Path, value: dict[str, object]) -> None:
    value["seal_sha256"] = _canonical_self_seal(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _copy_live30_registry(tmp_path: Path) -> Settings:
    source = ROOT / "benchmarks/evaluation/live-evaluation-30-v1"
    destination = tmp_path / "benchmarks/evaluation/live-evaluation-30-v1"
    destination.mkdir(parents=True)
    shutil.copyfile(source / "cases.jsonl", destination / "cases.jsonl")
    shutil.copyfile(source / "manifest.json", destination / "manifest.json")
    return Settings(project_root=tmp_path)


def test_live30_readiness_validates_registry_and_immutable_manifest(
    tmp_path: Path,
) -> None:
    settings = _copy_live30_registry(tmp_path)

    status, suite = _live30_registry_status(settings)

    assert suite is not None
    assert status["passed"] is True
    assert status["case_count"] == 30
    assert status["total_word_target"] == 115_000
    assert status["planned_terminal_outcomes"] == 48

    manifest_path = tmp_path / "benchmarks/evaluation/live-evaluation-30-v1/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["case_count"] = 29
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    changed, _suite = _live30_registry_status(settings)
    assert changed["registry_valid"] is True
    assert changed["manifest_matches_registry"] is False
    assert changed["passed"] is False


def test_stage_a_readiness_uses_the_execution_thresholds_and_exact_bindings() -> None:
    qualification_sha = "a" * 64
    payload: dict[str, object] = {
        "schema": "legalbot.live30-coverage-summary.v2",
        "run_id": "live30-stage-a-test",
        "case_count": 30,
        "case_ids": list(EXPECTED_CASE_IDS),
        "route_pass_count": 30,
        "subject_routing_pass_count": 30,
        "ranking_metric_state": "evaluated_against_sealed_qualifying_issue_gold",
        "expert_qualification_sha256": qualification_sha,
        "scored_issue_count": 30,
        "recall_at_5": 1.0,
        "recall_at_10": 0.95,
        "mrr": 0.8,
        "ndcg_at_10": 0.9,
        "exact_span_recall": 0.85,
        "contrary_authority_recall": 1.0,
        "generation_started": False,
    }

    passing = _stage_a_payload_status(
        payload,
        run_id="live30-stage-a-test",
        qualification_sha256=qualification_sha,
        artifact_sha256="b" * 64,
    )
    assert passing["passed"] is True
    assert passing["coverage_artifact_sha256"] == "b" * 64

    payload["recall_at_5"] = 0.99
    below_gate = _stage_a_payload_status(
        payload,
        run_id="live30-stage-a-test",
        qualification_sha256=qualification_sha,
    )
    assert below_gate["passed"] is False
    assert below_gate["error_code"] == "RuntimeError"

    payload["recall_at_5"] = 1.0
    wrong_gold = _stage_a_payload_status(
        payload,
        run_id="live30-stage-a-test",
        qualification_sha256="c" * 64,
    )
    assert wrong_gold["passed"] is False
    assert wrong_gold["error_code"] == "ValueError"


def test_gate_result_requires_a_valid_self_seal(tmp_path: Path) -> None:
    path = tmp_path / "gate.json"
    value: dict[str, object] = {
        "schema": "legalbot.test-gate.v1",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "passed": True,
        "observed": True,
    }
    _write_self_sealed(path, value)
    assert _load_self_sealed_result(path, schema="legalbot.test-gate.v1") is not None

    value["observed"] = False
    path.write_text(json.dumps(value), encoding="utf-8")
    assert _load_self_sealed_result(path, schema="legalbot.test-gate.v1") is None


def test_blind_70_claim_needs_both_a_passing_report_and_seal(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path)
    calibration = settings.evaluation_dir / "calibration"
    report_path = calibration / "blind-human-report.json"
    report = {
        "schema": "legalbot.blind-human-calibration-report.v1",
        "passed": True,
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "thresholds": {
            "unique_cases_minimum": 20,
            "subjects_minimum": 5,
            "independent_reviewers_minimum": 2,
            "double_review_fraction_minimum": 0.2,
            "human_70_plus_minimum": 5,
            "human_below_70_minimum": 5,
            "pass_fail_agreement_minimum": 0.85,
            "mean_absolute_score_error_maximum": 10.0,
            "dangerous_false_passes_maximum": 0,
        },
        "metrics": {
            "unique_cases": 20,
            "subjects": 5,
            "independent_reviewers": 2,
            "double_review_fraction": 0.2,
            "human_70_plus": 10,
            "human_below_70": 10,
            "pass_fail_agreement": 0.9,
            "mean_absolute_score_error": 5.0,
            "dangerous_false_passes": 0,
        },
    }
    calibration.mkdir(parents=True)
    report_path.write_text(json.dumps(report), encoding="utf-8")

    unsealed = _blind_calibration_status(settings)
    assert unsealed["report_passed"] is True
    assert unsealed["seal_valid"] is False
    assert unsealed["claim_permitted"] is False

    seal: dict[str, object] = {
        "schema": CALIBRATION_SEAL_SCHEMA,
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "status": "SEALED",
        "passed": True,
        "report_sha256": unsealed["report_sha256"],
    }
    _write_self_sealed(calibration / "blind-human-report.seal.json", seal)
    sealed = _blind_calibration_status(settings)
    assert sealed["seal_valid"] is True
    assert sealed["claim_permitted"] is True


def test_missing_live_artifacts_report_not_ready_without_legacy_240_gate(
    tmp_path: Path, monkeypatch
) -> None:
    settings = _copy_live30_registry(tmp_path)
    source_root = tmp_path / "sources"
    source_root.mkdir()
    monkeypatch.setenv("LEGALBOT_SOURCE_ROOTS", str(source_root))
    database = Database(settings.database_path)
    database.initialize()
    try:
        report = build_readiness_report(settings, database)
    finally:
        database.close()

    assert report["schema"] == "legalbot.production-readiness.v5"
    assert report["status"] == "not_ready"
    assert report["ready"] is False
    assert report["real_e2e_authorised"] is False
    assert report["live30_registry"]["passed"] is True
    assert report["live30_registry"]["planned_terminal_outcomes"] == 48
    assert report["expert_qualification"]["passed"] is False
    assert report["stage_a"]["passed"] is False
    assert report["operational_drills"]["rollback"]["passed"] is False
    assert report["operational_drills"]["browser_recovery"]["passed"] is False
    assert "answer_quality_evidence" not in report


def test_tampered_rollback_and_browser_drill_seals_fail_closed(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path)
    settings.ensure_runtime_dirs()
    database = Database(settings.database_path)
    database.initialize()
    try:
        rollback_path = tmp_path / "data/evaluations/e2e/gates/rollback-drill.json"
        browser_path = tmp_path / "data/evaluations/e2e/gates/browser-recovery-drill.json"
        for path, schema in (
            (rollback_path, ROLLBACK_DRILL_SCHEMA),
            (browser_path, BROWSER_RECOVERY_SCHEMA),
        ):
            value: dict[str, object] = {
                "schema": schema,
                "purpose": "evaluation_only",
                "eligible_for_training": False,
                "training_export_allowed": False,
                "passed": True,
            }
            _write_self_sealed(path, value)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["seal_sha256"] = "0" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")
        as_of = date(2026, 8, 16)
        rollback = _rollback_drill_status(
            settings, database, active_build_id="build-1", as_of_date=as_of
        )
        browser = _browser_recovery_status(
            settings,
            database,
            active_build_id="build-1",
            suite_canonical_sha256="a" * 64,
            as_of_date=as_of,
        )
        assert rollback["passed"] is False
        assert rollback["error_code"] == "InvalidOrUnsealedDrill"
        assert browser["passed"] is False
        assert browser["error_code"] == "InvalidOrUnsealedDrill"
    finally:
        database.close()
