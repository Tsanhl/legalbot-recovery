from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from app.crypto import LocalCipher
from app.evaluation.live30 import RunProvenance, SensitiveArtifactKind
from app.evaluation.live_suite import (
    LiveEvaluationBundle,
    load_live_evaluation_bundle,
    sealed_sha256,
)
from app.evaluation.live_suite_execute import (
    Live60ExecutionAuthorization,
    Live60ExecutionOutcome,
    finalize_single_pass_outcomes,
    record_terminal_outcome,
    verify_execution_prerequisites,
)
from app.evaluation.live_suite_store import LiveSuiteRunStore

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _prepared(
    tmp_path: Path,
) -> tuple[LiveSuiteRunStore, LiveEvaluationBundle, Path, list[str]]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    store = LiveSuiteRunStore(tmp_path / "project", LocalCipher(Fernet(Fernet.generate_key())))
    run_id = "live60-authorized-test"
    store.create_run(
        run_id=run_id,
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="e" * 40,
            git_dirty=False,
            index_build_id="candidate-live60-authorized",
            policy_sha256="1" * 64,
            assessment_rules_sha256="2" * 64,
        ),
        admitted_at=datetime(2026, 8, 15, 8, 0, tzinfo=UTC),
    )
    selected = [
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    ]
    store.store_safe_run_json(
        run_id=run_id,
        filename="coverage-summary.json",
        value={
            "schema": "legalbot.live-coverage-summary.v3",
            "run_id": run_id,
            "suite_id": bundle.manifest.suite_id,
            "index_build_id": "candidate-live60-authorized",
            "case_count": 60,
            "case_ids": [case.case_id for case in bundle.registry.cases],
            "selected_generation_eligible_case_ids": [selected[0]],
            "ranking_metric_state": "evaluated_against_sealed_qualifying_issue_gold",
            "expert_qualification_sha256": "3" * 64,
            "recall_at_5": 1.0,
            "recall_at_10": 0.97,
            "mrr": 0.85,
            "filter_violation_count": 0,
            "route_pass_count": 60,
            "subject_routing_pass_count": 60,
            "stage_a_evaluated": True,
            "stage_a_passed": True,
            "generation_started": False,
        },
    )
    authorization_value = {
        "schema": "legalbot.live60-execution-authorization.v1",
        "authorization_id": "authorization-live60-test",
        "run_id": run_id,
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
        "active_build_id": "candidate-live60-authorized",
        "owner_promotion_ref": "promotion:" + "4" * 64,
        "rollback_repromotion_report_sha256": "5" * 64,
        "browser_recovery_report_sha256": "6" * 64,
        "readiness_report_sha256": "7" * 64,
        "readiness_ready": True,
        "readiness_blocker_count": 0,
        "o04_authorization_ref": "o04:" + "8" * 64,
        "local_only": True,
        "online_research_allowed": False,
        "authorized_pass_count": 1,
        "authorized_case_ids": selected,
        "issued_at": "2026-08-15T08:30:00Z",
        "owner_ref": "owner:" + "9" * 64,
    }
    authorization_value["seal_sha256"] = sealed_sha256(authorization_value)
    authorization_path = tmp_path / "authorization.json"
    authorization_path.write_text(json.dumps(authorization_value, sort_keys=True), encoding="utf-8")
    return store, bundle, authorization_path, selected


def test_execution_preflight_requires_all_owner_and_stage_a_gates(tmp_path: Path) -> None:
    store, bundle, authorization_path, selected = _prepared(tmp_path)
    preflight = verify_execution_prerequisites(
        store=store,
        bundle=bundle,
        run_id="live60-authorized-test",
        authorization_path=authorization_path,
    )

    assert preflight.generated_case_ids == tuple(selected)
    assert preflight.evidence_ready_case_ids == (selected[0],)
    assert preflight.limited_or_held_case_ids == tuple(selected[1:])

    value = json.loads(authorization_path.read_text())
    value["online_research_allowed"] = True
    value["seal_sha256"] = sealed_sha256(value)
    authorization_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValidationError):
        verify_execution_prerequisites(
            store=store,
            bundle=bundle,
            run_id="live60-authorized-test",
            authorization_path=authorization_path,
        )


def test_single_pass_outcomes_are_exactly_selected_once(tmp_path: Path) -> None:
    store, bundle, authorization_path, selected = _prepared(tmp_path)
    preflight = verify_execution_prerequisites(
        store=store,
        bundle=bundle,
        run_id="live60-authorized-test",
        authorization_path=authorization_path,
    )
    completed_at = datetime(2026, 8, 15, 9, 0, tzinfo=UTC)
    for index, case_id in enumerate(selected):
        case = bundle.registry.case(case_id)
        if index == 0:
            answer = "Evidence-qualified released answer."
            artifact_id = "answer-selected-01"
            store.store_sensitive_artifact(
                run_id=preflight.run_manifest.run_id,
                case_id=case_id,
                kind=SensitiveArtifactKind.ANSWER,
                artifact_id=artifact_id,
                content=answer,
            )
            terminal_state: Literal["released", "verified_limited", "held", "system_error"] = (
                "released"
            )
            released = True
            answer_sha = hashlib.sha256(answer.encode()).hexdigest()
            word_count = len(answer.split())
        else:
            artifact_id = None
            terminal_state = "held"
            released = False
            answer_sha = None
            word_count = None
        outcome = Live60ExecutionOutcome(
            outcome_id=f"outcome-selected-{index + 1:02d}",
            run_id=preflight.run_manifest.run_id,
            case_id=case_id,
            pass_number=1,
            run_plan_disposition="generate_once",
            requested_word_target=case.word_target,
            expected_research_route=case.expected_research_route,
            terminal_state=terminal_state,
            released=released,
            answer_artifact_id=artifact_id,
            answer_sha256=answer_sha,
            word_count=word_count,
            privacy_passed=released,
            evidence_passed=released,
            currentness_passed=released,
            jurisdiction_passed=released,
            citation_passed=released,
            injection_passed=released,
            oscola_passed=released,
            release_gate_report_sha256=("a" * 64 if released else None),
            completed_at=completed_at,
        )
        record_terminal_outcome(
            store=store,
            bundle=bundle,
            preflight=preflight,
            outcome=outcome,
        )

    aggregate = finalize_single_pass_outcomes(
        store=store,
        bundle=bundle,
        run_id=preflight.run_manifest.run_id,
    )
    assert aggregate["case_count"] == 30
    assert aggregate["pass_count"] == 1
    assert aggregate["stability_repeats"] == 0
    assert aggregate["released_case_ids"] == [selected[0]]
    assert len(aggregate["coverage_only_not_selected_case_ids"]) == 30


def test_coverage_only_case_cannot_receive_an_outcome(tmp_path: Path) -> None:
    store, bundle, authorization_path, _selected = _prepared(tmp_path)
    preflight = verify_execution_prerequisites(
        store=store,
        bundle=bundle,
        run_id="live60-authorized-test",
        authorization_path=authorization_path,
    )
    case = bundle.registry.case("live30-q01")
    outcome = Live60ExecutionOutcome(
        outcome_id="outcome-forbidden-coverage-case",
        run_id=preflight.run_manifest.run_id,
        case_id=case.case_id,
        pass_number=1,
        run_plan_disposition="generate_once",
        requested_word_target=case.word_target,
        expected_research_route=case.expected_research_route,
        terminal_state="held",
        released=False,
        privacy_passed=False,
        evidence_passed=False,
        currentness_passed=False,
        jurisdiction_passed=False,
        citation_passed=False,
        injection_passed=False,
        oscola_passed=False,
        completed_at=datetime(2026, 8, 15, 9, 0, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="coverage-only"):
        record_terminal_outcome(
            store=store,
            bundle=bundle,
            preflight=preflight,
            outcome=outcome,
        )


def test_authorization_schema_rejects_missing_o04() -> None:
    with pytest.raises(ValidationError):
        Live60ExecutionAuthorization.model_validate(
            {
                "schema": "legalbot.live60-execution-authorization.v1",
                "authorization_id": "missing-o04",
            }
        )
