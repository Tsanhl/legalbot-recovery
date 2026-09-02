from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError

from app.contracts import ContractSchemaRegistry, LegacySchemaRejectedError, seal_contract
from app.evaluation.ge_visible_harness import (
    FACTUAL_CHECKS,
    QUALITY_DIMENSION_MAX,
    VisibleGEHarnessError,
    VisibleGEPack,
    VisibleGERunBindings,
    build_case_result,
    build_completed_visible_ge_run,
    quality_outcome,
    validate_case_result,
)
from app.evaluation.selected_persistence import SelectedEvaluationRunStore
from app.orchestration.object_store import EncryptedObjectStore

ROOT = Path.cwd()
PACK = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"


def test_visible_pack_keeps_exact_331_denominator_and_never_admits_unseen() -> None:
    pack = VisibleGEPack.load(PACK)
    assert len(pack.cases) == 331
    assert [case.ordinal for case in pack.cases] == list(range(1, 332))
    assert sum("STRESS" in case.lane for case in pack.cases) == 25
    assert all(case.raw["unseen_eligible"] is False for case in pack.cases)
    assert all(case.raw["training_export_eligible"] is False for case in pack.cases)
    assert len(pack.review_worksheet()) == 331
    assert len(pack.system_scenarios) == 32
    assert len({case.case_id for case in pack.system_scenarios}) == 32
    assert len(pack.system_review_worksheet()) == 32
    assert all(row["terminal_state"] == "NOT_RUN" for row in pack.system_review_worksheet())


def test_quality_threshold_also_requires_critical_dimension_floors() -> None:
    scores = dict(QUALITY_DIMENSION_MAX)
    total, outcome = quality_outcome(scores)
    assert total == 100
    assert outcome == "EXCEEDS_70_STANDARD"
    scores["legal_and_factual_accuracy"] = 17.0
    scores["issue_coverage_and_reasoning"] = 15.0
    total, outcome = quality_outcome(scores)
    assert total >= 70
    assert outcome == "MATERIAL_IMPROVEMENT_REQUIRED"


def test_factual_hold_cannot_receive_quality_score() -> None:
    pack = VisibleGEPack.load(PACK)
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    checks["claim_evidence_support"] = "FAIL"
    now = datetime(2026, 9, 1, tzinfo=UTC)
    with pytest.raises(VisibleGEHarnessError, match="cannot run"):
        build_case_result(
            registry=registry,
            run_id="ge-visible-test-run",
            case=pack.cases[0],
            job_id="job-ge-1",
            release_id=None,
            factual_checks=checks,
            factual_report_sha256="a" * 64,
            quality_scores={name: maximum for name, maximum in QUALITY_DIMENSION_MAX.items()},
            quality_report_sha256="b" * 64,
            root_cause_layers=["retrieval"],
            review_decision_sha256=None,
            started_at=now,
            completed_at=now + timedelta(seconds=1),
        )
    result = build_case_result(
        registry=registry,
        run_id="ge-visible-test-run",
        case=pack.cases[0],
        job_id="job-ge-1",
        release_id=None,
        factual_checks=checks,
        factual_report_sha256="a" * 64,
        quality_scores=None,
        quality_report_sha256=None,
        root_cause_layers=["retrieval"],
        review_decision_sha256=None,
        started_at=now,
        completed_at=now + timedelta(seconds=1),
    )
    assert result["terminal_state"] == "held"
    assert result["factual_outcome"] == "FACTUAL_HOLD"
    assert result["quality_outcome"] == "NOT_ELIGIBLE"
    assert result["quality_score"] is None


def test_selected_v2_binds_exact_review_rows_and_rejects_downgrade_or_aggregate_forgery() -> None:
    pack = VisibleGEPack.load(PACK)
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    scores = dict(QUALITY_DIMENSION_MAX)
    now = datetime(2026, 9, 1, tzinfo=UTC)
    result = build_case_result(
        registry=registry,
        run_id="ge-visible-v2-binding",
        case=pack.cases[0],
        job_id="job-ge-v2-binding",
        release_id="release-ge-v2-binding",
        factual_checks=checks,
        factual_report_sha256="1" * 64,
        quality_scores=scores,
        quality_report_sha256="2" * 64,
        root_cause_layers=(),
        review_decision_sha256="3" * 64,
        started_at=now,
        completed_at=now + timedelta(seconds=1),
    )
    assert result["schema"] == "legalbot.evaluation-case-result.v2"
    assert [row["check_id"] for row in result["factual_checks"]] == list(
        FACTUAL_CHECKS
    )
    assert [row["dimension_id"] for row in result["quality_dimensions"]] == list(
        QUALITY_DIMENSION_MAX
    )

    downgraded = seal_contract(
        {
            **{key: value for key, value in result.items() if key != "content_sha256"},
            "schema": "legalbot.evaluation-case-result.v1",
        }
    )
    with pytest.raises(LegacySchemaRejectedError):
        registry.validate_new(downgraded)

    missing_checks = seal_contract(
        {
            key: value
            for key, value in result.items()
            if key not in {"content_sha256", "factual_checks"}
        }
    )
    with pytest.raises(ValidationError):
        registry.validate_new(missing_checks)

    reordered = seal_contract(
        {
            **{key: value for key, value in result.items() if key != "content_sha256"},
            "factual_checks": list(reversed(result["factual_checks"])),
        }
    )
    with pytest.raises(ValidationError):
        registry.validate_new(reordered)

    forged_aggregate = seal_contract(
        {
            **{key: value for key, value in result.items() if key != "content_sha256"},
            "quality_score": 99.0,
        }
    )
    with pytest.raises(VisibleGEHarnessError, match="aggregate differs"):
        validate_case_result(
            registry=registry,
            result=forged_aggregate,
            case=pack.cases[0],
            run_id="ge-visible-v2-binding",
        )


def test_completed_run_reconciles_and_persists_all_331_results_without_omission(
    tmp_path, database, cipher
) -> None:
    pack = VisibleGEPack.load(PACK)
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    now = datetime(2026, 9, 1, tzinfo=UTC)
    checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    scores = dict(QUALITY_DIMENSION_MAX)
    results = [
        build_case_result(
            registry=registry,
            run_id="ge-visible-complete-run",
            case=case,
            job_id=f"job-{case.ordinal:03d}",
            release_id=f"release-{case.ordinal:03d}",
            factual_checks=checks,
            factual_report_sha256="a" * 64,
            quality_scores=scores,
            quality_report_sha256="b" * 64,
            root_cause_layers=[],
            review_decision_sha256="c" * 64,
            started_at=now,
            completed_at=now + timedelta(seconds=1),
        )
        for case in pack.cases
    ]
    bindings = VisibleGERunBindings(
        authorization_sha256="1" * 64,
        candidate_sha256="2" * 64,
        runtime_config_sha256="3" * 64,
        gold_currentness_decision_sha256="4" * 64,
        private_root_capability_sha256="5" * 64,
        exposure_ledger_sha256="6" * 64,
        model_sha256="7" * 64,
        prompt_sha256="8" * 64,
        renderer_sha256="9" * 64,
        validator_bundle_sha256="a" * 64,
        resource_policy_sha256="b" * 64,
    )
    run = build_completed_visible_ge_run(
        registry=registry,
        pack=pack,
        run_id="ge-visible-complete-run",
        case_results=results,
        bindings=bindings,
        started_at=now,
        completed_at=now + timedelta(minutes=10),
    )
    assert run["case_result_count"] == 331
    assert run["result_counts"] == {
        "completed": 331,
        "held": 0,
        "system_error": 0,
        "cancelled": 0,
        "ineligible": 0,
    }
    assert run["run_validity"] == "PASS"

    store = SelectedEvaluationRunStore(
        database=database,
        objects=EncryptedObjectStore(tmp_path / "evaluation_objects", database, cipher),
        registry=registry,
    )
    persisted = store.persist_completed_visible_ge(
        pack=pack,
        evaluation_run=run,
        case_results=results,
    )
    assert (
        store.persist_completed_visible_ge(
            pack=pack,
            evaluation_run=run,
            case_results=results,
        )
        == persisted
    )
    assert store.load_completed_visible_ge("ge-visible-complete-run") == persisted
    assert len(persisted.case_object_keys) == 331
    conflicting_run = dict(run)
    conflicting_run["candidate_sha256"] = "d" * 64
    with pytest.raises(RuntimeError, match="different digest"):
        store.persist_completed_visible_ge(
            pack=pack,
            evaluation_run=conflicting_run,
            case_results=results,
        )
    assert database.fetchone("SELECT COUNT(*) AS n FROM evaluation_runs")["n"] == 0
    with pytest.raises(sqlite3.IntegrityError, match="run contract is immutable"):
        database.execute(
            "UPDATE selected_evaluation_run_contracts SET run_validity='PASS' "
            "WHERE run_id='ge-visible-complete-run'"
        )

    with pytest.raises(VisibleGEHarnessError, match="exactly 331"):
        build_completed_visible_ge_run(
            registry=registry,
            pack=pack,
            run_id="ge-visible-complete-run",
            case_results=results[:-1],
            bindings=bindings,
            started_at=now,
            completed_at=now + timedelta(minutes=10),
        )
