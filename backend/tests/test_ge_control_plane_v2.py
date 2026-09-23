from __future__ import annotations

from pathlib import Path

from app.contracts.schema_registry import ContractSchemaRegistry
from app.evaluation.ge_authority_roles import rejected_route_must_not_stop_case
from app.evaluation.ge_control_plane_v2 import CASE_FAIL_CLOSED, control_plane_v2
from app.evaluation.ge_principal_blocker import classify_principal_blocker, intake_authorized
from app.evaluation.ge_proposition_receipts import build_proposition_receipt
from app.evaluation.ge_run_lineage import (
    build_effective_source_set,
    build_run_lineage,
    empty_historical_r1_track,
    empty_r2_track,
)


def test_case_hold_keeps_phase_active_and_is_not_gold() -> None:
    plane = control_plane_v2(
        case_results=[
            {"case_id": "pass:1", "factual_result": {"outcome": "FACTUAL_PASS"}, "evidence": [{}]},
            {
                "case_id": "hold:1",
                "factual_result": {"outcome": "FACTUAL_HOLD"},
                "evidence": [{"quote": "text"}],
                "improvement_reasons": ["currentness_unresolved"],
            },
        ],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert plane["phase_execution_state"] == "ACTIVE"
    assert plane["run_execution_state"] == "COMPLETE_WITH_CASE_HOLDS"
    assert plane["overall_progress"] is True
    assert plane["case_local_hold_sets_phase_progress_false"] is False
    assert plane["answer_legal_gold"] is False
    assert plane["training_gold"] is False
    assert plane["downstream_gates"]["qualified_legal_review"] == "NOT_STARTED"
    assert plane["locator_evaluation_label"] == "OWNER_ADOPTED_LOCATOR_EVALUATION_DECISION"
    assert plane["run_id"] == "UNBOUND"
    assert plane["controller_id"] == "UNBOUND"
    assert plane["authority"]["status"] == "NOT_RECORDED"
    assert plane["blockers"][0]["scope"] == "CASE"
    assert plane["blockers"][0]["case_id"] == "hold:1"
    assert plane["qualified_human_review_required"] is True
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    registry.validate_new(plane)


def test_missing_authority_is_case_fail_closed_not_hard_stop() -> None:
    row = {
        "case_id": "gap:1",
        "factual_result": {"outcome": "FACTUAL_HOLD"},
        "evidence": [],
        "known_missing_primary_authorities": ["Example Missing Act 2001"],
        "improvement_reasons": ["fail_closed_missing_primary"],
    }
    plane = control_plane_v2(
        case_results=[row],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
    )
    assert plane["phase_execution_state"] == "ACTIVE"
    assert plane["case_assurance_counts"][CASE_FAIL_CLOSED] == 1
    assert plane["global_hard_stop"] is False
    blocker = classify_principal_blocker(row)
    assert intake_authorized(blocker) is True


def test_rejected_cable_route_does_not_stop_case_174() -> None:
    assert (
        rejected_route_must_not_stop_case(
            "Cable & Wireless plc v IBM United Kingdom Ltd",
            alternative_official_route_present=True,
        )
        is True
    )


def test_proposition_receipt_cannot_set_gold_or_review() -> None:
    receipt = build_proposition_receipt(
        source_version_id="staged-example",
        official_bytes_sha256="a" * 64,
        canonical_sha256="b" * 64,
        locator="section 29(7)",
        proposition_id="prop-example",
        proposition_text="A duty applies in the stated circumstances.",
        evidence_span_ids=["span-1"],
        evidence_span_sha256s=["c" * 64],
        ai_research_recommendation="APPROVE",
        owner_adoption="APPROVE",
        decision="APPROVE",
        locator_evaluation_approved=True,
        title="Equality Act 2010",
    )
    assert receipt["qualified_legal_review"] is False
    assert receipt["answer_legal_gold"] is False
    assert receipt["training_gold"] is False
    assert receipt["proposition_qualified"] is False
    assert receipt["source_runtime_admitted"] is False
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    registry.validate_new(receipt)


def test_run_lineage_and_effective_source_set_validate(tmp_path: Path) -> None:
    lineage = build_run_lineage(
        historical_r1=empty_historical_r1_track(),
        new_r2=empty_r2_track(),
    )
    assert lineage["tracks"]["historical_r1_rescored_under_r2_evaluator"]["present"] is False
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    registry.validate_new(lineage)
    source_set = build_effective_source_set(project_root=tmp_path)
    registry.validate_new(source_set)
    assert source_set["admitted"] is False
    assert source_set["live_catalogue_insert"] is False
