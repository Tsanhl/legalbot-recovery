from __future__ import annotations

import math
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from backend.tests.ge_coverage_test_support import authorize_test_coverage
from jsonschema.exceptions import ValidationError

from app.contracts.schema_registry import (
    CANONICALIZATION_ID,
    CanonicalJSONError,
    ContractSchemaRegistry,
    LegacySchemaRejectedError,
    canonical_json_bytes,
    content_sha256,
    load_json_strict,
)
from app.evaluation import ge_coverage_authorization as coverage_owner_auth
from app.evaluation.ge_improvement_loop import (
    GEDiagnosticCaseDraft,
    build_completed_system_run,
    build_coverage_audit,
    build_cycle_assessment,
    build_diagnostic_case_result,
    build_system_case_result,
    build_visible_diagnostic_supplement,
    required_ge_coverage_cells,
)
from app.evaluation.ge_visible_harness import (
    FACTUAL_CHECKS,
    QUALITY_DIMENSION_MAX,
    VisibleGEPack,
    VisibleGERunBindings,
    build_case_result,
    build_completed_visible_ge_run,
)

ROOT = Path.cwd()
GE_PACK = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"


@pytest.fixture(autouse=True)
def trusted_coverage_test_seam(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        coverage_owner_auth,
        "_verify_trusted_ge_coverage_authorization_signature",
        lambda _request, _resolution: None,
    )


def _job_event() -> dict[str, object]:
    return {
        "schema": "legalbot.job-event.v1",
        "event_id": "event-abc",
        "job_id": "job-abc",
        "sequence": 1,
        "event": "progress",
        "emitted_at": "2026-09-01T00:00:00Z",
        "data": {
            "stage": "retrieval",
            "progress": 0.4,
            "message_code": "retrieval.running",
            "status": "running",
            "release_state": None,
            "answer_id": None,
            "release_sha256": None,
            "status_url": "/api/v1/jobs/job-abc",
            "release_id": None,
            "terminal_kind": None,
            "reset_from_sequence": None,
        },
        "attempt_id": "attempt-abc",
        "lease_generation": 1,
    }


def test_selected_registry_has_canonical_manifest_and_validates_new_event() -> None:
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    assert registry.manifest["canonicalization"] == CANONICALIZATION_ID
    assert len(registry.selected_schema_names) == 20
    assert len(registry.manifest_sha256) == 64
    registry.validate_new(_job_event())


def test_canonical_digest_is_order_independent_and_strict_json() -> None:
    left = {"schema": "x", "nested": {"b": 2, "a": 1}}
    right = {"nested": {"a": 1, "b": 2}, "schema": "x"}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert content_sha256(left) == content_sha256(right)
    with pytest.raises(CanonicalJSONError, match="duplicate"):
        load_json_strict('{"schema":"x","schema":"y"}')
    with pytest.raises(CanonicalJSONError, match="non-finite"):
        canonical_json_bytes({"value": math.inf})


def test_new_write_rejects_legacy_and_unknown_properties() -> None:
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    with pytest.raises(LegacySchemaRejectedError):
        registry.validate_new({"schema": "legalbot.query-plan.v1"}, verify_digest=False)
    event = _job_event()
    event["unexpected"] = True
    with pytest.raises(ValidationError):
        registry.validate_new(event)


def _real_ge_contracts(
    registry: ContractSchemaRegistry,
    authority_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    pack = VisibleGEPack.load(GE_PACK)
    started_at = datetime(2026, 9, 1, 9, tzinfo=UTC)
    visible_run_id = "ge-visible-schema-registry"
    factual_checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    quality_scores = dict(QUALITY_DIMENSION_MAX)
    visible_results = tuple(
        build_case_result(
            registry=registry,
            run_id=visible_run_id,
            case=case,
            job_id=f"job-schema-{case.ordinal:03d}",
            release_id=f"release-schema-{case.ordinal:03d}",
            factual_checks=factual_checks,
            factual_report_sha256="1" * 64,
            quality_scores=quality_scores,
            quality_report_sha256="2" * 64,
            root_cause_layers=(),
            review_decision_sha256="3" * 64,
            started_at=started_at,
            completed_at=started_at + timedelta(seconds=1),
        )
        for case in pack.cases
    )
    bindings = VisibleGERunBindings(
        authorization_sha256="4" * 64,
        candidate_sha256="5" * 64,
        runtime_config_sha256="6" * 64,
        gold_currentness_decision_sha256="7" * 64,
        private_root_capability_sha256="8" * 64,
        exposure_ledger_sha256="9" * 64,
        model_sha256="a" * 64,
        prompt_sha256="b" * 64,
        renderer_sha256="c" * 64,
        validator_bundle_sha256="d" * 64,
        resource_policy_sha256="e" * 64,
    )
    visible_run = build_completed_visible_ge_run(
        registry=registry,
        pack=pack,
        run_id=visible_run_id,
        case_results=visible_results,
        bindings=bindings,
        started_at=started_at,
        completed_at=started_at + timedelta(minutes=15),
    )

    system_run_id = "ge-system-schema-registry"
    system_results = tuple(
        build_system_case_result(
            run_id=system_run_id,
            scenario=scenario,
            expected_behaviour_checks={
                str(criterion): True for criterion in scenario.raw["expected_behaviour"]
            },
            prohibited_behaviour_observed={
                str(criterion): False for criterion in scenario.raw["prohibited_behaviour"]
            },
            system_report_sha256="f" * 64,
            root_cause_layers=(),
            started_at=started_at + timedelta(minutes=16),
            completed_at=started_at + timedelta(minutes=17),
        )
        for scenario in pack.system_scenarios
    )
    repair_manifest_sha256 = "0" * 64
    system_run = build_completed_system_run(
        pack=pack,
        visible_run=visible_run,
        repair_manifest_sha256=repair_manifest_sha256,
        run_id=system_run_id,
        case_results=system_results,
        started_at=started_at + timedelta(minutes=16),
        completed_at=started_at + timedelta(minutes=25),
    )

    _predecision, coverage_authorization, coverage_manifest = authorize_test_coverage(
        root=authority_root,
        pack=pack,
        manifest_id="ge-schema-coverage-manifest",
        cells=required_ge_coverage_cells(pack=pack),
        proposed_at=started_at,
    )
    coverage_audit = build_coverage_audit(
        pack=pack,
        coverage_manifest=coverage_manifest,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=None,
        audited_at=started_at + timedelta(minutes=26),
    )
    cells_by_id = {
        str(row["coverage_cell_id"]): row for row in coverage_manifest["cells"]
    }
    diagnostic_drafts = tuple(
        GEDiagnosticCaseDraft(
            diagnostic_case_id=f"GE-DIAG-SCHEMA-{ordinal:03d}",
            scenario_family_id=str(
                cells_by_id[str(gap["coverage_cell_id"])]["scenario_family_id"]
            ),
            prompt=f"What should I check for {gap['coverage_domain_id']}?",
            rationale=f"Covers exact missing domain {gap['coverage_domain_id']}.",
            primary_jurisdiction="England and Wales",
            legal_currentness_cutoff=date(2026, 9, 1),
            question_version_sha256=str(ordinal) * 64,
            legal_currentness_review_sha256="789abc"[ordinal - 1] * 64,
            gold_review_sha256="defabc"[ordinal - 1] * 64,
            source_diagnosis_ids=(),
            coverage_cell_id=str(gap["coverage_cell_id"]),
            coverage_gap_fingerprint_sha256=str(gap["gap_fingerprint_sha256"]),
        )
        for ordinal, gap in enumerate(coverage_audit["missing_cells"], start=1)
    )
    diagnostic_pack = build_visible_diagnostic_supplement(
        pack=pack,
        pack_id="ge-schema-diagnostic-pack",
        linked_cycle_id="ge-schema-loop:cycle:1",
        visible_run=visible_run,
        repair_manifest_sha256=repair_manifest_sha256,
        coverage_audit=coverage_audit,
        cases=diagnostic_drafts,
        source_diagnoses=(),
        created_at=started_at + timedelta(minutes=27),
    )
    diagnostic_results = tuple(
        build_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=case,
            factual_checks=factual_checks,
            factual_report_sha256="2" * 64,
            quality_scores=quality_scores,
            quality_report_sha256="3" * 64,
            root_cause_layers=(),
            relevant_change_at=started_at + timedelta(minutes=27),
            started_at=started_at + timedelta(minutes=28),
            completed_at=started_at + timedelta(minutes=29),
        )
        for case in diagnostic_pack["cases"]
    )
    closed_coverage_audit = build_coverage_audit(
        pack=pack,
        coverage_manifest=coverage_manifest,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=diagnostic_pack,
        audited_at=started_at + timedelta(minutes=30),
    )
    assessment = build_cycle_assessment(
        loop_id="ge-schema-loop",
        cycle_number=1,
        registry=registry,
        pack=pack,
        visible_run=visible_run,
        visible_results=visible_results,
        system_run=system_run,
        system_results=system_results,
        repair_manifest_sha256=repair_manifest_sha256,
        diagnoses=(),
        coverage_audit=closed_coverage_audit,
        coverage_authorization=coverage_authorization,
        diagnostic_supplement=diagnostic_pack,
        diagnostic_results=diagnostic_results,
        unseen_opened=False,
        assessed_at=started_at + timedelta(hours=1),
    )
    return system_results[0], system_run, diagnostic_pack, diagnostic_results[0], assessment


def test_selected_registry_validates_real_ge_loop_builder_outputs(tmp_path: Path) -> None:
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    contracts = _real_ge_contracts(registry, tmp_path)
    assert tuple(value["schema"] for value in contracts) == (
        "legalbot.ge-system-case-result.v1",
        "legalbot.ge-system-run.v1",
        "legalbot.ge-visible-diagnostic-supplement.v1",
        "legalbot.ge-diagnostic-case-result.v1",
        "legalbot.ge-cycle-assessment.v2",
    )
    for value in contracts:
        registry.validate_new(value)
    assessment = contracts[-1]
    assert "actions_performed" not in assessment
    assert all(
        action is False
        for action in assessment["assessment_builder_actions_performed"].values()
    )
    assert assessment["coverage_audit_sha256"] == assessment["coverage_audit"][
        "content_sha256"
    ]
    assert assessment["missing_coverage_cell_count"] == 0
    assert assessment["exit_checks"]["no_missing_coverage_areas"] is True


def test_ge_contract_digest_and_unknown_property_fail_closed(tmp_path: Path) -> None:
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    system_case, _system_run, _pack, _result, assessment = _real_ge_contracts(
        registry, tmp_path
    )
    digest_changed = dict(system_case)
    digest_changed["system_report_sha256"] = "0" * 64
    with pytest.raises(CanonicalJSONError, match="does not match"):
        registry.validate_new(digest_changed)
    unexpected = dict(assessment)
    unexpected["unexpected"] = True
    with pytest.raises(ValidationError):
        registry.validate_new(unexpected, verify_digest=False)
