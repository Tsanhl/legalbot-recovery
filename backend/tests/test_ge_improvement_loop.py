from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from backend.tests.ge_coverage_test_support import authorize_test_coverage

from app.config import Settings
from app.contracts import ContractSchemaRegistry, seal_contract
from app.evaluation import ge_coverage_authorization as coverage_owner_auth
from app.evaluation import ge_cycle_owner_authorization as cycle_owner_auth
from app.evaluation.ge_coverage_authorization import (
    VerifiedGECoverageAuthorization,
    build_ge_coverage_decision_request,
    ge_coverage_decision_binding,
    ge_coverage_decision_id,
    load_verified_ge_coverage_authorization,
)
from app.evaluation.ge_cycle_owner_authorization import (
    VerifiedGECycleOwnerAuthorization,
    build_ge_cycle_owner_decision_request,
    ge_cycle_owner_decision_binding,
    ge_cycle_owner_decision_id,
    load_verified_ge_cycle_owner_authorization,
)
from app.evaluation.ge_improvement_loop import (
    GEDiagnosisInput,
    GEDiagnosticCaseDraft,
    GEImprovementLoopError,
    build_completed_system_run,
    build_coverage_audit,
    build_coverage_cell_manifest,
    build_coverage_topology_predecision,
    build_cycle_assessment,
    build_cycle_owner_acceptance,
    build_diagnosis,
    build_diagnostic_case_result,
    build_official_research_intent,
    build_successor_candidate_plan,
    build_system_case_result,
    build_visible_diagnostic_supplement,
    build_weight_training_option,
    required_ge_coverage_cells,
    validate_completed_system_run,
    validate_cycle_assessment,
    validate_diagnosis,
    validate_diagnostic_case_result,
    validate_visible_diagnostic_supplement,
)
from app.evaluation.ge_visible_harness import (
    FACTUAL_CHECKS,
    QUALITY_DIMENSION_MAX,
    VisibleGEPack,
    VisibleGERunBindings,
    build_case_result,
    build_completed_visible_ge_run,
)
from app.governance.owner_stop import OwnerDecisionStore, seal_owner_decision_resolution

ROOT = Path.cwd()
PACK_PATH = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"


@dataclass(frozen=True)
class _CycleFixture:
    pack: VisibleGEPack
    registry: ContractSchemaRegistry
    visible_run: dict[str, Any]
    visible_results: tuple[dict[str, Any], ...]
    system_run: dict[str, Any]
    system_results: tuple[dict[str, Any], ...]
    bindings: VisibleGERunBindings
    repair_sha256: str
    started_at: datetime
    coverage_authorization: VerifiedGECoverageAuthorization
    coverage_manifest: dict[str, Any]
    open_coverage_audit: dict[str, Any]
    diagnostic_pack: dict[str, Any]
    diagnostic_results: tuple[dict[str, Any], ...]
    closed_coverage_audit: dict[str, Any]


def _bindings(*, candidate: str, config: str) -> VisibleGERunBindings:
    return VisibleGERunBindings(
        authorization_sha256="1" * 64,
        candidate_sha256=candidate * 64,
        runtime_config_sha256=config * 64,
        gold_currentness_decision_sha256="4" * 64,
        private_root_capability_sha256="5" * 64,
        exposure_ledger_sha256="6" * 64,
        model_sha256="7" * 64,
        prompt_sha256="8" * 64,
        renderer_sha256="9" * 64,
        validator_bundle_sha256="a" * 64,
        resource_policy_sha256="b" * 64,
    )


def _build_cycle_fixture(
    *,
    pack: VisibleGEPack,
    registry: ContractSchemaRegistry,
    suffix: str,
    candidate: str,
    config: str,
    repair: str,
    started_at: datetime,
    cycle_number: int,
    authority_root: Path,
) -> _CycleFixture:
    run_id = f"ge-visible-{suffix}"
    bindings = _bindings(candidate=candidate, config=config)
    factual = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    quality = dict(QUALITY_DIMENSION_MAX)
    visible_results = tuple(
        build_case_result(
            registry=registry,
            run_id=run_id,
            case=case,
            job_id=f"job-{suffix}-{case.ordinal:03d}",
            release_id=f"release-{suffix}-{case.ordinal:03d}",
            factual_checks=factual,
            factual_report_sha256="c" * 64,
            quality_scores=quality,
            quality_report_sha256="d" * 64,
            root_cause_layers=[],
            review_decision_sha256="e" * 64,
            started_at=started_at,
            completed_at=started_at + timedelta(seconds=1),
        )
        for case in pack.cases
    )
    visible_run = build_completed_visible_ge_run(
        registry=registry,
        pack=pack,
        run_id=run_id,
        case_results=visible_results,
        bindings=bindings,
        started_at=started_at,
        completed_at=started_at + timedelta(minutes=15),
    )
    system_run_id = f"ge-system-{suffix}"
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
            root_cause_layers=[],
            started_at=started_at + timedelta(minutes=16),
            completed_at=started_at + timedelta(minutes=17),
        )
        for scenario in pack.system_scenarios
    )
    system_run = build_completed_system_run(
        pack=pack,
        visible_run=visible_run,
        repair_manifest_sha256=repair * 64,
        run_id=system_run_id,
        case_results=system_results,
        started_at=started_at + timedelta(minutes=16),
        completed_at=started_at + timedelta(minutes=25),
    )
    cells = required_ge_coverage_cells(pack=pack)
    _predecision, coverage_authorization, coverage_manifest = authorize_test_coverage(
        root=authority_root,
        pack=pack,
        manifest_id=f"ge-required-coverage-{suffix}",
        cells=cells,
        proposed_at=started_at,
    )
    open_coverage_audit = build_coverage_audit(
        pack=pack,
        coverage_manifest=coverage_manifest,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=None,
        audited_at=started_at + timedelta(minutes=1),
    )
    missing_cells = open_coverage_audit["missing_cells"]
    manifest_cells = {
        str(row["coverage_cell_id"]): row for row in coverage_manifest["cells"]
    }
    drafts = tuple(
        GEDiagnosticCaseDraft(
            diagnostic_case_id=f"GE-DIAG-{suffix.upper()}-{ordinal:03d}",
            scenario_family_id=str(
                manifest_cells[str(missing["coverage_cell_id"])]["scenario_family_id"]
            ),
            prompt=f"What should I check for this {missing['coverage_domain_id']} issue?",
            rationale=f"Covers exact missing domain {missing['coverage_domain_id']}.",
            primary_jurisdiction="England and Wales",
            legal_currentness_cutoff=date(2026, 9, 1),
            question_version_sha256=f"{ordinal:x}" * 64,
            legal_currentness_review_sha256=f"{ordinal + 6:x}" * 64,
            gold_review_sha256="defabc"[ordinal - 1] * 64,
            source_diagnosis_ids=(),
            coverage_cell_id=str(missing["coverage_cell_id"]),
            coverage_gap_fingerprint_sha256=str(
                missing["gap_fingerprint_sha256"]
            ),
        )
        for ordinal, missing in enumerate(missing_cells, start=1)
    )
    diagnostic_pack = build_visible_diagnostic_supplement(
        pack=pack,
        pack_id=f"ge-diagnostic-pack-{suffix}",
        linked_cycle_id=f"ge-loop-test:cycle:{cycle_number}",
        visible_run=visible_run,
        repair_manifest_sha256=repair * 64,
        coverage_audit=open_coverage_audit,
        cases=drafts,
        source_diagnoses=(),
        created_at=started_at + timedelta(minutes=26),
    )
    diagnostic_results = tuple(
        build_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=case,
            factual_checks=dict.fromkeys(FACTUAL_CHECKS, "PASS"),
            factual_report_sha256="1" * 64,
            quality_scores=dict(QUALITY_DIMENSION_MAX),
            quality_report_sha256="2" * 64,
            root_cause_layers=(),
            relevant_change_at=started_at + timedelta(minutes=26),
            started_at=started_at + timedelta(minutes=30),
            completed_at=started_at + timedelta(minutes=31),
        )
        for case in diagnostic_pack["cases"]
    )
    closed_coverage_audit = build_coverage_audit(
        pack=pack,
        coverage_manifest=coverage_manifest,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=diagnostic_pack,
        audited_at=started_at + timedelta(minutes=32),
    )
    return _CycleFixture(
        pack=pack,
        registry=registry,
        visible_run=visible_run,
        visible_results=visible_results,
        system_run=system_run,
        system_results=system_results,
        bindings=bindings,
        repair_sha256=repair * 64,
        started_at=started_at,
        coverage_authorization=coverage_authorization,
        coverage_manifest=coverage_manifest,
        open_coverage_audit=open_coverage_audit,
        diagnostic_pack=diagnostic_pack,
        diagnostic_results=diagnostic_results,
        closed_coverage_audit=closed_coverage_audit,
    )


@pytest.fixture(scope="module")
def pack() -> VisibleGEPack:
    return VisibleGEPack.load(PACK_PATH)


@pytest.fixture(scope="module")
def registry() -> ContractSchemaRegistry:
    return ContractSchemaRegistry.from_project_root(ROOT)


@pytest.fixture(scope="module", autouse=True)
def trusted_coverage_test_seam() -> Any:
    patcher = pytest.MonkeyPatch()
    patcher.setattr(
        coverage_owner_auth,
        "_verify_trusted_ge_coverage_authorization_signature",
        lambda _request, _resolution: None,
    )
    yield
    patcher.undo()


@pytest.fixture(scope="module")
def first_cycle(
    pack: VisibleGEPack,
    registry: ContractSchemaRegistry,
    tmp_path_factory: pytest.TempPathFactory,
) -> _CycleFixture:
    return _build_cycle_fixture(
        pack=pack,
        registry=registry,
        suffix="cycle-one",
        candidate="2",
        config="3",
        repair="c",
        started_at=datetime(2026, 9, 1, 9, tzinfo=UTC),
        cycle_number=1,
        authority_root=tmp_path_factory.mktemp("ge-coverage-authority-one"),
    )


@pytest.fixture(scope="module")
def second_cycle(
    pack: VisibleGEPack,
    registry: ContractSchemaRegistry,
    tmp_path_factory: pytest.TempPathFactory,
) -> _CycleFixture:
    return _build_cycle_fixture(
        pack=pack,
        registry=registry,
        suffix="cycle-two",
        candidate="3",
        config="4",
        repair="d",
        started_at=datetime(2026, 9, 1, 12, tzinfo=UTC),
        cycle_number=2,
        authority_root=tmp_path_factory.mktemp("ge-coverage-authority-two"),
    )


_DEFAULT = object()


def _assessment(
    fixture: _CycleFixture,
    *,
    cycle_number: int = 1,
    diagnoses: tuple[dict[str, Any], ...] = (),
    coverage_audit: Any = _DEFAULT,
    coverage_authorization: VerifiedGECoverageAuthorization | None = None,
    diagnostic_pack: Any = _DEFAULT,
    diagnostic_results: Any = _DEFAULT,
    previous: dict[str, Any] | None = None,
    change_applied_at: datetime | None = None,
    owner_acceptance: dict[str, Any] | None = None,
    owner_authorization: VerifiedGECycleOwnerAuthorization | None = None,
    unseen_opened: bool = False,
    system_run: dict[str, Any] | None = None,
    assessed_at: datetime | None = None,
) -> dict[str, Any]:
    if diagnostic_pack is _DEFAULT:
        resolved_diagnostic_pack = (
            fixture.diagnostic_pack if coverage_audit is _DEFAULT else None
        )
    else:
        resolved_diagnostic_pack = diagnostic_pack
    if diagnostic_results is _DEFAULT:
        resolved_diagnostic_results = (
            fixture.diagnostic_results
            if resolved_diagnostic_pack is fixture.diagnostic_pack
            else ()
        )
    else:
        resolved_diagnostic_results = diagnostic_results
    if coverage_audit is _DEFAULT:
        resolved_coverage_audit = _baseline_closed_coverage_audit(
            fixture,
            diagnostic_pack=resolved_diagnostic_pack,
        )
    else:
        resolved_coverage_audit = coverage_audit
    resolved_coverage_authorization = (
        coverage_authorization or fixture.coverage_authorization
    )
    return build_cycle_assessment(
        loop_id="ge-loop-test",
        cycle_number=cycle_number,
        registry=fixture.registry,
        pack=fixture.pack,
        visible_run=fixture.visible_run,
        visible_results=fixture.visible_results,
        system_run=system_run or fixture.system_run,
        system_results=fixture.system_results,
        repair_manifest_sha256=fixture.repair_sha256,
        diagnoses=diagnoses,
        coverage_audit=resolved_coverage_audit,
        coverage_authorization=resolved_coverage_authorization,
        diagnostic_supplement=resolved_diagnostic_pack,
        diagnostic_results=resolved_diagnostic_results,
        unseen_opened=unseen_opened,
        assessed_at=assessed_at or fixture.started_at + timedelta(hours=1),
        previous_assessment=previous,
        change_applied_at=change_applied_at,
        owner_acceptance=owner_acceptance,
        owner_authorization=owner_authorization,
    )


def _baseline_closed_coverage_audit(
    fixture: _CycleFixture,
    *,
    diagnostic_pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if diagnostic_pack is None:
        return fixture.open_coverage_audit
    if diagnostic_pack is fixture.diagnostic_pack:
        return fixture.closed_coverage_audit
    return build_coverage_audit(
        pack=fixture.pack,
        coverage_manifest=fixture.coverage_manifest,
        coverage_authorization=fixture.coverage_authorization,
        existing_diagnostic_pack=diagnostic_pack,
        audited_at=fixture.started_at + timedelta(minutes=32),
    )


def _coverage_and_diagnostic_pack(
    fixture: _CycleFixture,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return fixture.open_coverage_audit, fixture.diagnostic_pack


def test_system_32_and_diagnostic_custody_remain_outside_fixed_331(
    first_cycle: _CycleFixture,
) -> None:
    validate_completed_system_run(
        pack=first_cycle.pack,
        visible_run=first_cycle.visible_run,
        system_run=first_cycle.system_run,
        system_results=first_cycle.system_results,
        repair_manifest_sha256=first_cycle.repair_sha256,
    )
    assert first_cycle.system_run["result_count"] == 32
    assert first_cycle.system_run["counts"] == {
        "PASS": 32,
        "FAIL": 0,
        "SYSTEM_ERROR": 0,
    }
    assert first_cycle.system_run["fixed_visible_denominator"] == 331
    assert first_cycle.system_run["system_cases_separate_from_visible_denominator"] is True

    audit, diagnostic_pack = _coverage_and_diagnostic_pack(first_cycle)
    validate_visible_diagnostic_supplement(
        pack=first_cycle.pack,
        diagnostic_pack=diagnostic_pack,
        visible_run=first_cycle.visible_run,
        repair_manifest_sha256=first_cycle.repair_sha256,
    )
    assert audit["unseen_inspected"] is False
    assert audit["missing_cell_count"] == 6
    missing_area_assessment = _assessment(first_cycle, coverage_audit=audit)
    assert missing_area_assessment["status"] == "IMPROVEMENT_REQUIRED"
    assert "MISSING_GE_COVERAGE_AREAS" in missing_area_assessment["blockers"]
    assert missing_area_assessment["exit_checks"]["no_missing_coverage_areas"] is False
    assert diagnostic_pack["case_count"] == 6
    row = diagnostic_pack["cases"][0]
    assert row["joins_fixed_visible_denominator"] is False
    assert row["permanently_ineligible_for_unseen_validation"] is True
    assert row["permanently_ineligible_for_training"] is True
    assert row["diagnostic_provenance_kind"] == "COVERAGE_ONLY"
    assert row["source_diagnosis_ids"] == []
    assert row["source_diagnosis_manifest"] == []
    prompt_projection = row["prompt_only_projection"]
    assert prompt_projection["prompt"] == row["prompt"]
    assert prompt_projection["contains_rationale"] is False
    assert prompt_projection["contains_gold"] is False
    assert prompt_projection["contains_diagnosis"] is False
    assert "rationale" not in prompt_projection
    assert "gold_review_sha256" not in prompt_projection
    closed_audit = first_cycle.closed_coverage_audit
    assert closed_audit["missing_cell_count"] == 0

    required_cells = list(required_ge_coverage_cells(pack=first_cycle.pack))
    housing_index = next(
        index
        for index, cell in enumerate(required_cells)
        if cell.coverage_domain_id == "public:housing"
    )
    aliased_cells = list(required_cells)
    aliased_cells[housing_index] = replace(
        aliased_cells[housing_index], topic="land-law"
    )
    with pytest.raises(GEImprovementLoopError, match="cannot alias"):
        build_coverage_topology_predecision(
            pack=first_cycle.pack,
            manifest_id="ge-coverage-topic-alias",
            cells=aliased_cells,
            proposed_at=first_cycle.started_at,
        )

    duplicate_assignment_cells = [
        *required_cells,
        replace(
            required_cells[housing_index],
            coverage_cell_id="ge-coverage-public-housing-extra",
            breadth_anchor=False,
            issue="second-housing-cell",
            assigned_case_ids=(first_cycle.pack.cases[0].case_id,),
        ),
    ]
    duplicate_assignment_cells[0] = replace(
        duplicate_assignment_cells[0],
        assigned_case_ids=(first_cycle.pack.cases[0].case_id,),
    )
    with pytest.raises(GEImprovementLoopError, match="more than one approved"):
        build_coverage_topology_predecision(
            pack=first_cycle.pack,
            manifest_id="ge-coverage-duplicate-assignment",
            cells=duplicate_assignment_cells,
            proposed_at=first_cycle.started_at,
        )

    with pytest.raises(PermissionError, match="verifier_issued_ge_coverage_proof_required"):
        build_coverage_cell_manifest(
            predecision=first_cycle.coverage_manifest["coverage_predecision"],
            authorization="3" * 64,  # type: ignore[arg-type]
        )

    with pytest.raises(GEImprovementLoopError, match="bind exactly one"):
        build_visible_diagnostic_supplement(
            pack=first_cycle.pack,
            pack_id="ge-diagnostic-pack-bad",
            linked_cycle_id="ge-loop-test:cycle:1",
            visible_run=first_cycle.visible_run,
            repair_manifest_sha256=first_cycle.repair_sha256,
            coverage_audit=audit,
            cases=(
                GEDiagnosticCaseDraft(
                    diagnostic_case_id="GE-DIAG-001",
                    scenario_family_id="GE-FAM-HOUSING-GAP",
                    prompt="A diagnostic prompt",
                    rationale="A diagnostic reason",
                    primary_jurisdiction="England and Wales",
                    legal_currentness_cutoff=date(2026, 9, 1),
                    question_version_sha256="5" * 64,
                    legal_currentness_review_sha256="6" * 64,
                    gold_review_sha256="7" * 64,
                    source_diagnosis_ids=(),
                    coverage_cell_id="coverage-cell-new-area",
                    coverage_gap_fingerprint_sha256="0" * 64,
                ),
            ),
            source_diagnoses=(),
            created_at=first_cycle.started_at + timedelta(minutes=26),
        )


def test_coverage_authority_rejects_narrow_substituted_and_stale_topologies(
    first_cycle: _CycleFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cells = list(required_ge_coverage_cells(pack=first_cycle.pack))
    with pytest.raises(GEImprovementLoopError, match="omits required domains"):
        build_coverage_topology_predecision(
            pack=first_cycle.pack,
            manifest_id="ge-coverage-narrow",
            cells=cells[:-1],
            proposed_at=first_cycle.started_at,
        )

    renamed = list(cells)
    renamed[-1] = replace(
        renamed[-1], coverage_domain_id="public:consumer-rights", topic="consumer-rights"
    )
    with pytest.raises(GEImprovementLoopError, match="renamed, aliased"):
        build_coverage_topology_predecision(
            pack=first_cycle.pack,
            manifest_id="ge-coverage-renamed-domain",
            cells=renamed,
            proposed_at=first_cycle.started_at,
        )

    duplicated = list(cells)
    duplicated[-1] = replace(
        duplicated[-1],
        coverage_domain_id="public:housing",
        topic="housing",
        coverage_cell_id="ge-coverage-public-housing-second-anchor",
        issue="duplicate-housing-anchor",
    )
    with pytest.raises(GEImprovementLoopError, match="omits required domains"):
        build_coverage_topology_predecision(
            pack=first_cycle.pack,
            manifest_id="ge-coverage-duplicated-domain",
            cells=duplicated,
            proposed_at=first_cycle.started_at,
        )

    reordered_predecision = build_coverage_topology_predecision(
        pack=first_cycle.pack,
        manifest_id="ge-required-coverage-cycle-one",
        cells=[cells[1], cells[0], *cells[2:]],
        proposed_at=first_cycle.started_at,
    )
    with pytest.raises(PermissionError, match="verifier_issued_ge_coverage_proof_required"):
        build_coverage_cell_manifest(
            predecision=reordered_predecision,
            authorization=first_cycle.coverage_authorization,
        )

    substituted = list(cells)
    substituted[-1] = replace(substituted[-1], issue="substituted-consumer-cell")
    substituted_predecision = build_coverage_topology_predecision(
        pack=first_cycle.pack,
        manifest_id="ge-required-coverage-cycle-one",
        cells=substituted,
        proposed_at=first_cycle.started_at,
    )
    with pytest.raises(PermissionError, match="verifier_issued_ge_coverage_proof_required"):
        build_coverage_cell_manifest(
            predecision=substituted_predecision,
            authorization=first_cycle.coverage_authorization,
        )

    predecision = build_coverage_topology_predecision(
        pack=first_cycle.pack,
        manifest_id="ge-coverage-production-fail-closed",
        cells=cells,
        proposed_at=first_cycle.started_at,
    )
    binding = ge_coverage_decision_binding(predecision)
    request = build_ge_coverage_decision_request(
        binding=binding,
        created_at=first_cycle.started_at + timedelta(seconds=1),
    )
    settings = Settings(project_root=tmp_path / "production-seam")
    settings.evaluation_dir.mkdir(parents=True, mode=0o700)
    settings.evaluation_dir.chmod(0o700)
    store = OwnerDecisionStore(settings.owner_decision_root)
    store.write_request(request)
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id=coverage_owner_auth.GE_COVERAGE_APPROVE_OPTION,
        owner_ref=f"owner:{'4' * 64}",
        decided_at=first_cycle.started_at + timedelta(seconds=2),
    )
    store.write_resolution(resolution)
    monkeypatch.setattr(
        coverage_owner_auth,
        "_verify_trusted_ge_coverage_authorization_signature",
        lambda _request, _resolution: (_ for _ in ()).throw(
            PermissionError(
                "OWNER_DECISION_REQUIRED:trusted_ge_coverage_authorization_verifier_missing"
            )
        ),
    )
    with pytest.raises(
        PermissionError,
        match="trusted_ge_coverage_authorization_verifier_missing",
    ):
        load_verified_ge_coverage_authorization(
            settings,
            predecision=predecision,
            decision_id=ge_coverage_decision_id(binding),
            decision_content_sha256=resolution.seal_sha256,
        )

    stale_settings = Settings(project_root=tmp_path / "stale-decision")
    stale_settings.evaluation_dir.mkdir(parents=True, mode=0o700)
    stale_settings.evaluation_dir.chmod(0o700)
    stale_store = OwnerDecisionStore(stale_settings.owner_decision_root)
    stale_store.write_request(request)
    stale_resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id=coverage_owner_auth.GE_COVERAGE_APPROVE_OPTION,
        owner_ref=f"owner:{'5' * 64}",
        decided_at=first_cycle.started_at,
    )
    stale_store.write_resolution(stale_resolution)
    with pytest.raises(PermissionError, match="ge_coverage_not_authorized"):
        load_verified_ge_coverage_authorization(
            stale_settings,
            predecision=predecision,
            decision_id=ge_coverage_decision_id(binding),
            decision_content_sha256=stale_resolution.seal_sha256,
        )


def test_diagnostic_source_run_review_and_change_custody_fail_closed(
    first_cycle: _CycleFixture,
    second_cycle: _CycleFixture,
) -> None:
    _audit, diagnostic_pack = _coverage_and_diagnostic_pack(first_cycle)
    with pytest.raises(
        GEImprovementLoopError,
        match="source run, execution, candidate, or repair binding differs",
    ):
        validate_visible_diagnostic_supplement(
            pack=first_cycle.pack,
            diagnostic_pack=diagnostic_pack,
            visible_run=second_cycle.visible_run,
            repair_manifest_sha256=second_cycle.repair_sha256,
        )

    diagnostic_case = diagnostic_pack["cases"][0]
    with pytest.raises(
        GEImprovementLoopError,
        match="did not start after its diagnostic question change",
    ):
        build_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=diagnostic_case,
            factual_checks=dict.fromkeys(FACTUAL_CHECKS, "PASS"),
            factual_report_sha256="1" * 64,
            quality_scores=dict(QUALITY_DIMENSION_MAX),
            quality_report_sha256="2" * 64,
            root_cause_layers=(),
            relevant_change_at=first_cycle.started_at + timedelta(minutes=30),
            started_at=first_cycle.started_at + timedelta(minutes=30),
            completed_at=first_cycle.started_at + timedelta(minutes=31),
        )

    result = build_diagnostic_case_result(
        diagnostic_pack=diagnostic_pack,
        diagnostic_case=diagnostic_case,
        factual_checks=dict.fromkeys(FACTUAL_CHECKS, "PASS"),
        factual_report_sha256="1" * 64,
        quality_scores=dict(QUALITY_DIMENSION_MAX),
        quality_report_sha256="2" * 64,
        root_cause_layers=(),
        relevant_change_at=first_cycle.started_at + timedelta(minutes=26),
        started_at=first_cycle.started_at + timedelta(minutes=30),
        completed_at=first_cycle.started_at + timedelta(minutes=31),
    )
    substituted = seal_contract(
        {
            **{key: value for key, value in result.items() if key != "content_sha256"},
            "gold_review_sha256": "8" * 64,
        }
    )
    with pytest.raises(GEImprovementLoopError, match="deterministic replay differs"):
        validate_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=diagnostic_case,
            result=substituted,
        )


def test_diagnosis_derived_diagnostic_rejects_orphaned_cycle_lineage(
    first_cycle: _CycleFixture,
    tmp_path: Path,
) -> None:
    fixed_case = first_cycle.pack.cases[0]
    diagnostic_case_id = "GE-DIAG-DERIVED-001"
    cells = list(required_ge_coverage_cells(pack=first_cycle.pack))
    housing_index = next(
        index
        for index, cell in enumerate(cells)
        if cell.coverage_domain_id == "public:housing"
    )
    cells[housing_index] = replace(
        cells[housing_index],
        issue="failure-derived-follow-up",
        scenario_family_id=fixed_case.scenario_family_id,
        assigned_case_ids=(diagnostic_case_id,),
    )
    _predecision, coverage_authorization, coverage = authorize_test_coverage(
        root=tmp_path,
        pack=first_cycle.pack,
        manifest_id="ge-coverage-diagnosis-derived",
        cells=cells,
        proposed_at=first_cycle.started_at,
    )
    audit = build_coverage_audit(
        pack=first_cycle.pack,
        coverage_manifest=coverage,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=None,
        audited_at=first_cycle.started_at + timedelta(minutes=25),
    )
    failed_checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    failed_checks["claim_evidence_support"] = "FAIL"
    source_result = build_case_result(
        registry=first_cycle.registry,
        run_id=str(first_cycle.visible_run["run_id"]),
        case=fixed_case,
        job_id="job-diagnostic-source-lineage",
        release_id=None,
        factual_checks=failed_checks,
        factual_report_sha256="2" * 64,
        quality_scores=None,
        quality_report_sha256=None,
        root_cause_layers=("retrieval",),
        review_decision_sha256="3" * 64,
        started_at=first_cycle.started_at,
        completed_at=first_cycle.started_at + timedelta(seconds=1),
    )
    source_diagnosis = build_diagnosis(
        GEDiagnosisInput(
            diagnosis_id="diagnosis-diagnostic-source-lineage",
            case_id=fixed_case.case_id,
            case_kind="visible",
            failure_class="factual",
            scenario_family_id=fixed_case.scenario_family_id,
            case_version_sha256=fixed_case.record_sha256,
            materiality="material",
            finding_sha256="4" * 64,
        ),
        diagnosed_result=source_result,
    )
    coverage_cells = {
        str(row["coverage_cell_id"]): row for row in coverage["cells"]
    }
    drafts: list[GEDiagnosticCaseDraft] = []
    for ordinal, missing in enumerate(audit["missing_cells"], start=1):
        is_housing = missing["coverage_domain_id"] == "public:housing"
        case_id = diagnostic_case_id if is_housing else f"GE-DIAG-DERIVED-{ordinal:03d}"
        bound_cell = coverage_cells[str(missing["coverage_cell_id"])]
        drafts.append(
            GEDiagnosticCaseDraft(
                diagnostic_case_id=case_id,
                scenario_family_id=str(bound_cell["scenario_family_id"]),
                prompt=f"What extra facts should I check for {missing['coverage_domain_id']}?",
                rationale=f"Exercises exact coverage for {missing['coverage_domain_id']}.",
                primary_jurisdiction="England and Wales",
                legal_currentness_cutoff=date(2026, 9, 1),
                question_version_sha256="5" * 64,
                legal_currentness_review_sha256="6" * 64,
                gold_review_sha256="7" * 64,
                source_diagnosis_ids=(
                    (str(source_diagnosis["diagnosis_id"]),) if is_housing else ()
                ),
                coverage_cell_id=str(missing["coverage_cell_id"]),
                coverage_gap_fingerprint_sha256=str(
                    missing["gap_fingerprint_sha256"]
                ),
            )
        )
    diagnostic_pack = build_visible_diagnostic_supplement(
        pack=first_cycle.pack,
        pack_id="ge-diagnostic-derived-pack",
        linked_cycle_id="ge-loop-test:cycle:1",
        visible_run=first_cycle.visible_run,
        repair_manifest_sha256=first_cycle.repair_sha256,
        coverage_audit=audit,
        cases=tuple(drafts),
        source_diagnoses=(source_diagnosis,),
        created_at=first_cycle.started_at + timedelta(minutes=26),
    )
    diagnostic_case = diagnostic_pack["cases"][0]
    assert diagnostic_case["diagnostic_provenance_kind"] == "DIAGNOSIS_DERIVED"
    results = tuple(
        build_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=case,
            factual_checks=dict.fromkeys(FACTUAL_CHECKS, "PASS"),
            factual_report_sha256="8" * 64,
            quality_scores=dict(QUALITY_DIMENSION_MAX),
            quality_report_sha256="9" * 64,
            root_cause_layers=(),
            relevant_change_at=first_cycle.started_at + timedelta(minutes=26),
            started_at=first_cycle.started_at + timedelta(minutes=30),
            completed_at=first_cycle.started_at + timedelta(minutes=31),
        )
        for case in diagnostic_pack["cases"]
    )
    closed_audit = build_coverage_audit(
        pack=first_cycle.pack,
        coverage_manifest=coverage,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=diagnostic_pack,
        audited_at=first_cycle.started_at + timedelta(minutes=32),
    )
    with pytest.raises(
        GEImprovementLoopError,
        match="source diagnosis does not reconcile to this cycle",
    ):
        _assessment(
            first_cycle,
            diagnoses=(),
            coverage_audit=closed_audit,
            coverage_authorization=coverage_authorization,
            diagnostic_pack=diagnostic_pack,
            diagnostic_results=results,
        )


def test_source_gap_requires_retrieval_proposition_and_query_evidence(
    first_cycle: _CycleFixture,
) -> None:
    case = first_cycle.pack.cases[0]
    checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    checks["claim_evidence_support"] = "FAIL"
    result = build_case_result(
        registry=first_cycle.registry,
        run_id=str(first_cycle.visible_run["run_id"]),
        case=case,
        job_id="job-source-gap",
        release_id=None,
        factual_checks=checks,
        factual_report_sha256="1" * 64,
        quality_scores=None,
        quality_report_sha256=None,
        root_cause_layers=["source_currentness", "retrieval"],
        review_decision_sha256="e" * 64,
        started_at=first_cycle.started_at,
        completed_at=first_cycle.started_at + timedelta(seconds=1),
    )
    base = dict(
        diagnosis_id="diagnosis-source-gap-001",
        case_id=case.case_id,
        case_kind="visible",
        failure_class="factual",
        scenario_family_id=case.scenario_family_id,
        case_version_sha256=case.record_sha256,
        materiality="material",
        finding_sha256="1" * 64,
        knowledge_or_source_gap=True,
        subject="Possession notice requirements",
        jurisdiction="England and Wales",
        as_of_date=date(2026, 9, 1),
        retrieval_query_sha256="2" * 64,
        proposition_sha256="3" * 64,
    )
    with pytest.raises(GEImprovementLoopError, match="lacks query"):
        build_diagnosis(GEDiagnosisInput(**base), diagnosed_result=result)

    diagnosis = build_diagnosis(
        GEDiagnosisInput(
            **base,
            retrieval_attempt_artifact_sha256="4" * 64,
        ),
        diagnosed_result=result,
    )
    assert diagnosis["root_cause_layers"] == ["retrieval", "source_currentness"]
    assert diagnosis["failed_check_ids"] == ["factual:claim_evidence_support"]
    reordered_result = seal_contract(
        {
            **{key: value for key, value in result.items() if key != "content_sha256"},
            "root_cause_layers": ["retrieval", "source_currentness"],
        }
    )
    reordered_diagnosis = build_diagnosis(
        GEDiagnosisInput(
            **{
                **base,
                "diagnosis_id": "diagnosis-source-gap-reordered",
                "retrieval_attempt_artifact_sha256": "4" * 64,
            }
        ),
        diagnosed_result=reordered_result,
    )
    assert (
        reordered_diagnosis["failure_fingerprint_sha256"]
        == diagnosis["failure_fingerprint_sha256"]
    )
    validate_diagnosis(diagnosis)
    intent = build_official_research_intent(
        diagnosis=diagnosis,
        diagnosed_result=result,
        candidate_build_id="candidate-build-ge-gap",
    )
    assert intent["effect"] == "RESEARCH_CONTROL_PLANE_INTAKE_ONLY"
    assert intent["network_action_performed"] is False
    assert intent["source_admission_authorized"] is False
    assert intent["successor_candidate_state"] == "NON_ACTIVE"
    assert intent["promotion_authorized"] is False

    plan = build_successor_candidate_plan(
        plan_id="ge-successor-plan-one",
        baseline_candidate_sha256="5" * 64,
        successor_candidate_sha256="6" * 64,
        official_research_intents=(intent,),
        source_version_manifest_sha256="7" * 64,
        chunk_manifest_sha256="8" * 64,
        embedding_manifest_sha256="9" * 64,
        created_at=first_cycle.started_at,
    )
    assert plan["candidate_state"] == "NON_ACTIVE"
    assert plan["index_policy"] == "CREATE_NEW_VERSION_ONLY"
    assert plan["active_pointer_write_authorized"] is False


def test_any_change_requires_fresh_full_331_plus_32_rerun(
    first_cycle: _CycleFixture,
    second_cycle: _CycleFixture,
) -> None:
    cycle_one = _assessment(first_cycle)
    assert cycle_one["status"] == "AWAITING_OWNER_ACCEPTANCE"

    stale_system_run = build_completed_system_run(
        pack=first_cycle.pack,
        visible_run=first_cycle.visible_run,
        repair_manifest_sha256="d" * 64,
        run_id=str(first_cycle.system_run["run_id"]),
        case_results=first_cycle.system_results,
        started_at=first_cycle.started_at + timedelta(minutes=16),
        completed_at=first_cycle.started_at + timedelta(minutes=25),
    )
    stale = build_cycle_assessment(
        loop_id="ge-loop-test",
        cycle_number=2,
        registry=first_cycle.registry,
        pack=first_cycle.pack,
        visible_run=first_cycle.visible_run,
        visible_results=first_cycle.visible_results,
        system_run=stale_system_run,
        system_results=first_cycle.system_results,
        repair_manifest_sha256="d" * 64,
        diagnoses=(),
        coverage_audit=first_cycle.open_coverage_audit,
        coverage_authorization=first_cycle.coverage_authorization,
        diagnostic_supplement=None,
        diagnostic_results=(),
        unseen_opened=False,
        assessed_at=first_cycle.started_at + timedelta(hours=3),
        previous_assessment=cycle_one,
        change_applied_at=first_cycle.started_at + timedelta(hours=2),
    )
    assert stale["status"] == "FULL_RERUN_REQUIRED"
    assert "FULL_331_PLUS_32_RERUN_REQUIRED" in stale["blockers"]

    fresh = _assessment(
        second_cycle,
        cycle_number=2,
        previous=cycle_one,
        change_applied_at=datetime(2026, 9, 1, 11, 30, tzinfo=UTC),
    )
    assert fresh["status"] == "AWAITING_OWNER_ACCEPTANCE"
    assert fresh["full_331_plus_32_rerun_required"] is False


def test_exit_requires_diagnostics_unseen_custody_and_explicit_owner_acceptance(
    first_cycle: _CycleFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _audit, diagnostic_pack = _coverage_and_diagnostic_pack(first_cycle)
    with pytest.raises(GEImprovementLoopError, match="every accumulated diagnostic"):
        _assessment(first_cycle, diagnostic_pack=diagnostic_pack, diagnostic_results=())
    diagnostic_results = first_cycle.diagnostic_results
    predecision = _assessment(
        first_cycle,
        diagnostic_pack=diagnostic_pack,
        diagnostic_results=diagnostic_results,
    )
    assert predecision["status"] == "AWAITING_OWNER_ACCEPTANCE"
    assert predecision["visible_factual_pass_count"] == 331
    assert predecision["visible_quality_70_and_critical_floor_pass_count"] == 331
    assert predecision["system_pass_count"] == 32
    assert predecision["diagnostic_pass_count"] == 6

    binding = ge_cycle_owner_decision_binding(predecision)
    with pytest.raises(ValueError, match="predates_predecision"):
        build_ge_cycle_owner_decision_request(
            binding=binding,
            created_at=first_cycle.started_at + timedelta(minutes=59),
        )
    request = build_ge_cycle_owner_decision_request(
        binding=binding,
        created_at=first_cycle.started_at + timedelta(hours=1, minutes=30),
    )
    settings = Settings(project_root=tmp_path)
    settings.evaluation_dir.mkdir(parents=True, mode=0o700)
    settings.evaluation_dir.chmod(0o700)
    decision_store = OwnerDecisionStore(settings.owner_decision_root)
    decision_store.write_request(request)
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id=cycle_owner_auth.GE_CYCLE_ACCEPT_OPTION,
        owner_ref=f"owner:{'3' * 64}",
        decided_at=first_cycle.started_at + timedelta(hours=2),
    )
    decision_store.write_resolution(resolution)
    with pytest.raises(
        PermissionError,
        match="trusted_ge_cycle_owner_authorization_verifier_missing",
    ):
        load_verified_ge_cycle_owner_authorization(
            settings,
            predecision=predecision,
            decision_id=ge_cycle_owner_decision_id(binding),
            decision_content_sha256=resolution.seal_sha256,
        )
    monkeypatch.setattr(
        cycle_owner_auth,
        "_verify_trusted_ge_cycle_owner_authorization_signature",
        lambda _request, _resolution: None,
    )
    authorization = load_verified_ge_cycle_owner_authorization(
        settings,
        predecision=predecision,
        decision_id=ge_cycle_owner_decision_id(binding),
        decision_content_sha256=resolution.seal_sha256,
    )
    acceptance = build_cycle_owner_acceptance(authorization=authorization)
    assert (
        acceptance["predecision_assessment_sha256"]
        == predecision["content_sha256"]
    )
    assert acceptance["owner_request_sha256"] == request.seal_sha256
    with pytest.raises(GEImprovementLoopError, match="predates its owner acceptance"):
        _assessment(
            first_cycle,
            diagnostic_pack=diagnostic_pack,
            diagnostic_results=diagnostic_results,
            owner_acceptance=acceptance,
            owner_authorization=authorization,
        )
    completed = _assessment(
        first_cycle,
        diagnostic_pack=diagnostic_pack,
        diagnostic_results=diagnostic_results,
        owner_acceptance=acceptance,
        owner_authorization=authorization,
        assessed_at=first_cycle.started_at + timedelta(hours=2, minutes=1),
    )
    validate_cycle_assessment(completed)
    assert completed["status"] == "GE_COMPLETE_OWNER_ACCEPTED"
    assert all(completed["exit_checks"].values())

    with pytest.raises(PermissionError, match="verifier_issued_ge_cycle_proof_required"):
        _assessment(
            first_cycle,
            diagnostic_pack=diagnostic_pack,
            diagnostic_results=diagnostic_results,
            owner_acceptance=acceptance,
        )
    mismatched = seal_contract(
        {
            **{key: value for key, value in acceptance.items() if key != "content_sha256"},
            "decision_basis_sha256": "4" * 64,
        }
    )
    with pytest.raises(GEImprovementLoopError, match="does not bind"):
        _assessment(
            first_cycle,
            diagnostic_pack=diagnostic_pack,
            diagnostic_results=diagnostic_results,
            owner_acceptance=mismatched,
            owner_authorization=authorization,
            assessed_at=first_cycle.started_at + timedelta(hours=2, minutes=1),
        )

    breached = _assessment(first_cycle, unseen_opened=True)
    assert breached["status"] == "IMPROVEMENT_REQUIRED"
    assert "UNSEEN_CUSTODY_BREACH" in breached["blockers"]
    with pytest.raises(ValueError, match="not_ready_for_owner_acceptance"):
        ge_cycle_owner_decision_binding(breached)


def test_repeated_failure_fingerprint_stops_after_second_repaired_full_run(
    first_cycle: _CycleFixture,
    second_cycle: _CycleFixture,
) -> None:
    def failed_fixture(base: _CycleFixture, *, finding: str) -> tuple[_CycleFixture, dict[str, Any]]:
        checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
        checks["claim_evidence_support"] = "FAIL"
        case = base.pack.cases[0]
        held = build_case_result(
            registry=base.registry,
            run_id=str(base.visible_run["run_id"]),
            case=case,
            job_id=f"job-held-{finding}",
            release_id=None,
            factual_checks=checks,
            factual_report_sha256=finding * 64,
            quality_scores=None,
            quality_report_sha256=None,
            root_cause_layers=["retrieval"],
            review_decision_sha256="e" * 64,
            started_at=base.started_at,
            completed_at=base.started_at + timedelta(seconds=1),
        )
        results = list(base.visible_results)
        results[0] = held
        visible_run = build_completed_visible_ge_run(
            registry=base.registry,
            pack=base.pack,
            run_id=str(base.visible_run["run_id"]),
            case_results=results,
            bindings=base.bindings,
            started_at=base.started_at,
            completed_at=base.started_at + timedelta(minutes=15),
        )
        failed = _CycleFixture(
            pack=base.pack,
            registry=base.registry,
            visible_run=visible_run,
            visible_results=tuple(results),
            system_run=base.system_run,
            system_results=base.system_results,
            bindings=base.bindings,
            repair_sha256=base.repair_sha256,
            started_at=base.started_at,
            coverage_authorization=base.coverage_authorization,
            coverage_manifest=base.coverage_manifest,
            open_coverage_audit=base.open_coverage_audit,
            diagnostic_pack=base.diagnostic_pack,
            diagnostic_results=base.diagnostic_results,
            closed_coverage_audit=base.closed_coverage_audit,
        )
        diagnosis = build_diagnosis(
            GEDiagnosisInput(
                diagnosis_id=f"diagnosis-repeat-{finding}",
                case_id=case.case_id,
                case_kind="visible",
                failure_class="factual",
                scenario_family_id=case.scenario_family_id,
                case_version_sha256=case.record_sha256,
                materiality="material",
                finding_sha256=finding * 64,
            ),
            diagnosed_result=held,
        )
        return failed, diagnosis

    failed_one, diagnosis_one = failed_fixture(first_cycle, finding="1")
    first = _assessment(
        failed_one,
        diagnoses=(diagnosis_one,),
        coverage_audit=failed_one.open_coverage_audit,
        diagnostic_pack=None,
        diagnostic_results=(),
    )
    fingerprint = diagnosis_one["failure_fingerprint_sha256"]
    assert first["failure_fingerprint_attempt_counts"][fingerprint] == 1

    with pytest.raises(
        GEImprovementLoopError,
        match="unchanged execution and repair cannot retry a still-open failure",
    ):
        _assessment(
            failed_one,
            cycle_number=2,
            diagnoses=(diagnosis_one,),
            previous=first,
            coverage_audit=failed_one.open_coverage_audit,
            diagnostic_pack=None,
            diagnostic_results=(),
        )

    failed_two, diagnosis_two = failed_fixture(second_cycle, finding="2")
    assert diagnosis_two["failure_fingerprint_sha256"] == fingerprint
    second = _assessment(
        failed_two,
        cycle_number=2,
        diagnoses=(diagnosis_two,),
        previous=first,
        change_applied_at=datetime(2026, 9, 1, 11, 30, tzinfo=UTC),
        coverage_audit=failed_two.open_coverage_audit,
        diagnostic_pack=None,
        diagnostic_results=(),
    )
    assert second["status"] == "STOP_REPEATED_FINGERPRINT"
    assert second["failure_fingerprint_attempt_counts"][fingerprint] == 2
    assert second["automatic_retry_allowed"] is False
    assert second["next_action"] == "OWNER_REVIEW_NO_AUTOMATIC_RETRY"


def test_weight_training_is_separate_and_rejects_evaluation_unseen_or_user_content(
    first_cycle: _CycleFixture,
) -> None:
    option = build_weight_training_option(
        option_id="ge-training-option-one",
        owner_authorization_sha256="1" * 64,
        corpus_manifest_sha256="2" * 64,
        rights_review_sha256="3" * 64,
        privacy_review_sha256="4" * 64,
        contains_evaluation_content=False,
        contains_unseen_content=False,
        contains_user_content=False,
        created_at=first_cycle.started_at,
    )
    assert option["execution_performed"] is False
    with pytest.raises(GEImprovementLoopError, match="cannot contain"):
        build_weight_training_option(
            option_id="ge-training-option-contaminated",
            owner_authorization_sha256="1" * 64,
            corpus_manifest_sha256="2" * 64,
            rights_review_sha256="3" * 64,
            privacy_review_sha256="4" * 64,
            contains_evaluation_content=True,
            contains_unseen_content=False,
            contains_user_content=False,
            created_at=first_cycle.started_at,
        )
