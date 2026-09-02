from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from backend.tests.ge_coverage_test_support import authorize_test_coverage

from app.config import Settings
from app.contracts import ContractSchemaRegistry, canonical_json_bytes, seal_contract
from app.crypto import LocalCipher
from app.db import Database
from app.evaluation import ge_coverage_authorization as coverage_owner_auth
from app.evaluation import ge_cycle_owner_authorization as cycle_owner_auth
from app.evaluation.ge_coverage_authorization import VerifiedGECoverageAuthorization
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
    build_completed_system_run,
    build_coverage_audit,
    build_cycle_assessment,
    build_cycle_owner_acceptance,
    build_diagnosis,
    build_diagnostic_case_result,
    build_system_case_result,
    build_visible_diagnostic_supplement,
    required_ge_coverage_cells,
)
from app.evaluation.ge_loop_persistence import GEImprovementLoopStore
from app.evaluation.ge_visible_harness import (
    FACTUAL_CHECKS,
    QUALITY_DIMENSION_MAX,
    VisibleGEPack,
    VisibleGERunBindings,
    build_case_result,
    build_completed_visible_ge_run,
)
from app.evaluation.selected_persistence import SelectedEvaluationRunStore
from app.governance.owner_stop import OwnerDecisionStore, seal_owner_decision_resolution
from app.orchestration.object_store import EncryptedObjectStore

ROOT = Path(__file__).resolve().parents[2]
PACK_PATH = ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"


@dataclass(frozen=True, slots=True)
class _RunArtifacts:
    pack: VisibleGEPack
    registry: ContractSchemaRegistry
    visible_run: dict[str, Any]
    visible_results: tuple[dict[str, Any], ...]
    system_run: dict[str, Any]
    system_results: tuple[dict[str, Any], ...]
    repair_manifest_sha256: str
    started_at: datetime


@dataclass(frozen=True, slots=True)
class _CycleArtifacts:
    diagnostic_pack: dict[str, Any]
    diagnostic_results: tuple[dict[str, Any], ...]
    diagnoses: tuple[dict[str, Any], ...]
    assessment: dict[str, Any]
    coverage_authorization: VerifiedGECoverageAuthorization
    owner_acceptance: dict[str, Any] | None
    owner_authorization: VerifiedGECycleOwnerAuthorization | None


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


def _bindings() -> VisibleGERunBindings:
    return VisibleGERunBindings(
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


@pytest.fixture(scope="module")
def artifacts() -> _RunArtifacts:
    pack = VisibleGEPack.load(PACK_PATH)
    registry = ContractSchemaRegistry.from_project_root(ROOT)
    started_at = datetime(2026, 9, 1, 9, tzinfo=UTC)
    visible_run_id = "ge-visible-persistence-test"
    visible_results = tuple(
        build_case_result(
            registry=registry,
            run_id=visible_run_id,
            case=case,
            job_id=f"job-persistence-{case.ordinal:03d}",
            release_id=f"release-persistence-{case.ordinal:03d}",
            factual_checks=dict.fromkeys(FACTUAL_CHECKS, "PASS"),
            factual_report_sha256="c" * 64,
            quality_scores=dict(QUALITY_DIMENSION_MAX),
            quality_report_sha256="d" * 64,
            root_cause_layers=(),
            review_decision_sha256="e" * 64,
            started_at=started_at,
            completed_at=started_at + timedelta(seconds=1),
        )
        for case in pack.cases
    )
    visible_run = build_completed_visible_ge_run(
        registry=registry,
        pack=pack,
        run_id=visible_run_id,
        case_results=visible_results,
        bindings=_bindings(),
        started_at=started_at,
        completed_at=started_at + timedelta(minutes=15),
    )
    system_run_id = "ge-system-persistence-test"
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
    return _RunArtifacts(
        pack=pack,
        registry=registry,
        visible_run=visible_run,
        visible_results=visible_results,
        system_run=system_run,
        system_results=system_results,
        repair_manifest_sha256=repair_manifest_sha256,
        started_at=started_at,
    )


def _seed_store(
    *,
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    artifacts: _RunArtifacts,
) -> tuple[GEImprovementLoopStore, EncryptedObjectStore]:
    objects = EncryptedObjectStore(tmp_path / "ge_loop_objects", database, cipher)
    SelectedEvaluationRunStore(
        database=database,
        objects=objects,
        registry=artifacts.registry,
    ).persist_completed_visible_ge(
        pack=artifacts.pack,
        evaluation_run=artifacts.visible_run,
        case_results=artifacts.visible_results,
    )
    store = GEImprovementLoopStore(database=database, objects=objects)
    store.persist_system_run(
        pack=artifacts.pack,
        visible_run=artifacts.visible_run,
        system_run=artifacts.system_run,
        system_results=artifacts.system_results,
        repair_manifest_sha256=artifacts.repair_manifest_sha256,
    )
    return store, objects


def _build_cycle(
    artifacts: _RunArtifacts,
    *,
    loop_id: str,
    pack_id: str,
    failing: bool,
    authority_root: Path,
) -> _CycleArtifacts:
    _predecision, coverage_authorization, coverage = authorize_test_coverage(
        root=authority_root,
        pack=artifacts.pack,
        manifest_id=f"{pack_id}-coverage-manifest",
        cells=required_ge_coverage_cells(pack=artifacts.pack),
        proposed_at=artifacts.started_at,
    )
    audit = build_coverage_audit(
        pack=artifacts.pack,
        coverage_manifest=coverage,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=None,
        audited_at=artifacts.started_at + timedelta(minutes=26),
    )
    cells_by_id = {
        str(row["coverage_cell_id"]): row for row in coverage["cells"]
    }
    drafts = tuple(
        GEDiagnosticCaseDraft(
            diagnostic_case_id=f"{pack_id}-case-{ordinal:03d}",
            scenario_family_id=str(
                cells_by_id[str(missing["coverage_cell_id"])]["scenario_family_id"]
            ),
            prompt=f"What should I check for {missing['coverage_domain_id']}?",
            rationale=f"Covers exact missing domain {missing['coverage_domain_id']}.",
            primary_jurisdiction="England and Wales",
            legal_currentness_cutoff=date(2026, 9, 1),
            question_version_sha256=str(ordinal) * 64,
            legal_currentness_review_sha256="789abc"[ordinal - 1] * 64,
            gold_review_sha256="defabc"[ordinal - 1] * 64,
            source_diagnosis_ids=(),
            coverage_cell_id=str(missing["coverage_cell_id"]),
            coverage_gap_fingerprint_sha256=str(
                missing["gap_fingerprint_sha256"]
            ),
        )
        for ordinal, missing in enumerate(audit["missing_cells"], start=1)
    )
    diagnostic_pack = build_visible_diagnostic_supplement(
        pack=artifacts.pack,
        pack_id=pack_id,
        linked_cycle_id=f"{loop_id}:cycle:1",
        visible_run=artifacts.visible_run,
        repair_manifest_sha256=artifacts.repair_manifest_sha256,
        coverage_audit=audit,
        cases=drafts,
        source_diagnoses=(),
        created_at=artifacts.started_at + timedelta(minutes=27),
    )
    closed_coverage_audit = build_coverage_audit(
        pack=artifacts.pack,
        coverage_manifest=coverage,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=diagnostic_pack,
        audited_at=artifacts.started_at + timedelta(minutes=27, seconds=30),
    )
    diagnostic_results = tuple(
        build_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=diagnostic_case,
            factual_checks={
                **dict.fromkeys(FACTUAL_CHECKS, "PASS"),
                **(
                    {"claim_evidence_support": "FAIL"}
                    if failing and ordinal == 1
                    else {}
                ),
            },
            factual_report_sha256="2" * 64,
            quality_scores=(
                None if failing and ordinal == 1 else dict(QUALITY_DIMENSION_MAX)
            ),
            quality_report_sha256=(
                None if failing and ordinal == 1 else "3" * 64
            ),
            root_cause_layers=(
                ("retrieval",) if failing and ordinal == 1 else ()
            ),
            relevant_change_at=artifacts.started_at + timedelta(minutes=27),
            started_at=artifacts.started_at + timedelta(minutes=28),
            completed_at=artifacts.started_at + timedelta(minutes=29),
        )
        for ordinal, diagnostic_case in enumerate(
            diagnostic_pack["cases"], start=1
        )
    )
    diagnoses: tuple[dict[str, Any], ...]
    if failing:
        diagnoses = (
            build_diagnosis(
                GEDiagnosisInput(
                    diagnosis_id=f"{pack_id}-diagnosis",
                    case_id=str(diagnostic_pack["cases"][0]["diagnostic_case_id"]),
                    case_kind="diagnostic",
                    failure_class="factual",
                    scenario_family_id=str(
                        diagnostic_pack["cases"][0]["scenario_family_id"]
                    ),
                    case_version_sha256=str(
                        diagnostic_pack["cases"][0]["content_sha256"]
                    ),
                    materiality="material",
                    finding_sha256="4" * 64,
                ),
                diagnosed_result=diagnostic_results[0],
            ),
        )
    else:
        diagnoses = ()
    predecision = build_cycle_assessment(
        loop_id=loop_id,
        cycle_number=1,
        registry=artifacts.registry,
        pack=artifacts.pack,
        visible_run=artifacts.visible_run,
        visible_results=artifacts.visible_results,
        system_run=artifacts.system_run,
        system_results=artifacts.system_results,
        repair_manifest_sha256=artifacts.repair_manifest_sha256,
        diagnoses=diagnoses,
        coverage_audit=closed_coverage_audit,
        coverage_authorization=coverage_authorization,
        diagnostic_supplement=diagnostic_pack,
        diagnostic_results=diagnostic_results,
        unseen_opened=False,
        assessed_at=artifacts.started_at + timedelta(hours=1),
    )
    return _CycleArtifacts(
        diagnostic_pack=diagnostic_pack,
        diagnostic_results=diagnostic_results,
        diagnoses=diagnoses,
        assessment=predecision,
        coverage_authorization=coverage_authorization,
        owner_acceptance=None,
        owner_authorization=None,
    )


def _authorize_cycle(
    cycle: _CycleArtifacts,
    artifacts: _RunArtifacts,
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> _CycleArtifacts:
    binding = ge_cycle_owner_decision_binding(cycle.assessment)
    request = build_ge_cycle_owner_decision_request(
        binding=binding,
        created_at=artifacts.started_at + timedelta(hours=1, minutes=30),
    )
    settings = Settings(project_root=tmp_path)
    settings.evaluation_dir.mkdir(parents=True, mode=0o700)
    settings.evaluation_dir.chmod(0o700)
    store = OwnerDecisionStore(settings.owner_decision_root)
    store.write_request(request)
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id=cycle_owner_auth.GE_CYCLE_ACCEPT_OPTION,
        owner_ref=f"owner:{'6' * 64}",
        decided_at=artifacts.started_at + timedelta(hours=2),
    )
    store.write_resolution(resolution)
    with pytest.raises(
        PermissionError,
        match="trusted_ge_cycle_owner_authorization_verifier_missing",
    ):
        load_verified_ge_cycle_owner_authorization(
            settings,
            predecision=cycle.assessment,
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
        predecision=cycle.assessment,
        decision_id=ge_cycle_owner_decision_id(binding),
        decision_content_sha256=resolution.seal_sha256,
    )
    acceptance = build_cycle_owner_acceptance(authorization=authorization)
    assessment = build_cycle_assessment(
        loop_id=str(cycle.assessment["loop_id"]),
        cycle_number=int(cycle.assessment["cycle_number"]),
        registry=artifacts.registry,
        pack=artifacts.pack,
        visible_run=artifacts.visible_run,
        visible_results=artifacts.visible_results,
        system_run=artifacts.system_run,
        system_results=artifacts.system_results,
        repair_manifest_sha256=artifacts.repair_manifest_sha256,
        diagnoses=cycle.diagnoses,
        coverage_audit=cycle.assessment["coverage_audit"],
        coverage_authorization=cycle.coverage_authorization,
        diagnostic_supplement=cycle.diagnostic_pack,
        diagnostic_results=cycle.diagnostic_results,
        unseen_opened=False,
        assessed_at=authorization.decided_at + timedelta(seconds=1),
        owner_acceptance=acceptance,
        owner_authorization=authorization,
    )
    return _CycleArtifacts(
        diagnostic_pack=cycle.diagnostic_pack,
        diagnostic_results=cycle.diagnostic_results,
        diagnoses=cycle.diagnoses,
        assessment=assessment,
        coverage_authorization=cycle.coverage_authorization,
        owner_acceptance=acceptance,
        owner_authorization=authorization,
    )


def _persist_cycle(
    store: GEImprovementLoopStore,
    artifacts: _RunArtifacts,
    cycle: _CycleArtifacts,
):
    return store.persist_cycle(
        pack=artifacts.pack,
        assessment=cycle.assessment,
        diagnoses=cycle.diagnoses,
        diagnostic_pack=cycle.diagnostic_pack,
        diagnostic_results=cycle.diagnostic_results,
        owner_acceptance=cycle.owner_acceptance,
        coverage_authorization=cycle.coverage_authorization,
        owner_authorization=cycle.owner_authorization,
    )


def test_encrypted_round_trip_covers_system_diagnostics_diagnoses_and_acceptance(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    artifacts: _RunArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, objects = _seed_store(
        tmp_path=tmp_path, database=database, cipher=cipher, artifacts=artifacts
    )
    persisted_system, loaded_system, loaded_system_results = store.load_system_run(
        pack=artifacts.pack,
        visible_run=artifacts.visible_run,
        run_id=str(artifacts.system_run["run_id"]),
        repair_manifest_sha256=artifacts.repair_manifest_sha256,
    )
    assert loaded_system == artifacts.system_run
    assert loaded_system_results == artifacts.system_results
    assert len(persisted_system.case_object_keys) == 32
    assert (
        store.persist_system_run(
            pack=artifacts.pack,
            visible_run=artifacts.visible_run,
            system_run=artifacts.system_run,
            system_results=artifacts.system_results,
            repair_manifest_sha256=artifacts.repair_manifest_sha256,
        )
        == persisted_system
    )

    failed = _build_cycle(
        artifacts,
        loop_id="ge-loop-persistence-failed",
        pack_id="ge-diagnostic-persistence-failed",
        failing=True,
        authority_root=tmp_path,
    )
    failed_persisted = _persist_cycle(store, artifacts, failed)
    (
        failed_replayed,
        failed_assessment,
        failed_diagnoses,
        failed_results,
        failed_acceptance,
    ) = store.load_cycle(
        pack=artifacts.pack,
        assessment_id=str(failed.assessment["assessment_id"]),
    )
    assert failed_replayed == failed_persisted
    assert failed_assessment == failed.assessment
    assert failed_diagnoses == failed.diagnoses
    assert failed_results == failed.diagnostic_results
    assert failed_acceptance is None
    assert len(failed_replayed.diagnosis_object_keys) == 1

    completed = _build_cycle(
        artifacts,
        loop_id="ge-loop-persistence-complete",
        pack_id="ge-diagnostic-persistence-complete",
        failing=False,
        authority_root=tmp_path,
    )
    completed = _authorize_cycle(
        completed,
        artifacts,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    completed_persisted = _persist_cycle(store, artifacts, completed)
    (
        completed_replayed,
        completed_assessment,
        completed_diagnoses,
        completed_results,
        completed_acceptance,
    ) = store.load_cycle(
        pack=artifacts.pack,
        assessment_id=str(completed.assessment["assessment_id"]),
    )
    assert completed_replayed == completed_persisted
    assert completed_assessment == completed.assessment
    assert completed_diagnoses == ()
    assert completed_results == completed.diagnostic_results
    assert completed_acceptance == completed.owner_acceptance
    assert completed_assessment["status"] == "GE_COMPLETE_OWNER_ACCEPTED"
    assert _persist_cycle(store, artifacts, completed) == completed_persisted
    assert store.load_cycle(str(completed.assessment["assessment_id"])) == (
        completed_replayed,
        completed_assessment,
        completed_diagnoses,
        completed_results,
        completed_acceptance,
    )

    encrypted_paths = tuple(objects.root.rglob("*.enc"))
    assert len(encrypted_paths) >= 371
    sensitive_plaintext = b"I received a possession notice today"
    assert all(sensitive_plaintext not in path.read_bytes() for path in encrypted_paths)
    assert (
        database.fetchone("SELECT COUNT(*) AS n FROM selected_ge_system_case_contracts")["n"] == 32
    )
    assert database.fetchone("SELECT COUNT(*) AS n FROM ge_cycle_diagnosis_contracts")["n"] == 1
    assert (
        database.fetchone("SELECT COUNT(*) AS n FROM ge_diagnostic_case_result_contracts")["n"] == 12
    )
    assert (
        database.fetchone("SELECT COUNT(*) AS n FROM ge_cycle_owner_acceptance_contracts")["n"] == 1
    )


def test_persistence_rejects_forged_projection_and_hash_only_owner_acceptance(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    artifacts: _RunArtifacts,
) -> None:
    store, _objects = _seed_store(
        tmp_path=tmp_path, database=database, cipher=cipher, artifacts=artifacts
    )
    failed = _build_cycle(
        artifacts,
        loop_id="ge-loop-persistence-forged-complete",
        pack_id="ge-diagnostic-persistence-forged-complete",
        failing=True,
        authority_root=tmp_path,
    )
    assert failed.assessment["status"] == "IMPROVEMENT_REQUIRED"
    assert failed.assessment["open_material_diagnosis_count"] == 1
    assert failed.assessment["diagnostic_pass_count"] == 5
    owner_acceptance = seal_contract(
            {
                "schema": "legalbot.ge-cycle-owner-acceptance.v1",
                "owner_decision_id": "ge-forged-complete-owner-acceptance",
                "decision": "ACCEPT",
                "decision_basis_sha256": failed.assessment["decision_basis_sha256"],
                "predecision_assessment_sha256": failed.assessment["content_sha256"],
                "owner_request_sha256": "b" * 64,
                "authorization_sha256": "a" * 64,
            "unseen_opened": False,
            "decided_at": (artifacts.started_at + timedelta(hours=2)).isoformat(),
        }
    )
    forged = seal_contract(
        {
            **{
                key: value
                for key, value in failed.assessment.items()
                if key != "content_sha256"
            },
            "status": "GE_COMPLETE_OWNER_ACCEPTED",
            "blockers": [],
            "exit_checks": {
                key: True for key in failed.assessment["exit_checks"]
            },
            "owner_acceptance_sha256": owner_acceptance["content_sha256"],
        }
    )

    # A self-consistent digest and the public JSON Schema are insufficient:
    # persistence must recompute the decision from the exact stored 331 + 32.
    artifacts.registry.validate_new(forged)
    with pytest.raises(PermissionError, match="verifier_issued_ge_cycle_proof_required"):
        store.persist_cycle(
            pack=artifacts.pack,
            assessment=forged,
            diagnoses=failed.diagnoses,
            diagnostic_pack=failed.diagnostic_pack,
            diagnostic_results=failed.diagnostic_results,
            owner_acceptance=owner_acceptance,
            coverage_authorization=failed.coverage_authorization,
        )

    forged_awaiting = seal_contract(
        {
            **{
                key: value
                for key, value in failed.assessment.items()
                if key != "content_sha256"
            },
            "status": "AWAITING_OWNER_ACCEPTANCE",
            "blockers": [],
            "exit_checks": {
                key: key != "explicit_owner_acceptance"
                for key in failed.assessment["exit_checks"]
            },
        }
    )
    artifacts.registry.validate_new(forged_awaiting)
    with pytest.raises(
        RuntimeError,
        match="GE cycle persisted-artifact reconstruction replay artifact differs",
    ):
        store.persist_cycle(
            pack=artifacts.pack,
            assessment=forged_awaiting,
            diagnoses=failed.diagnoses,
            diagnostic_pack=failed.diagnostic_pack,
            diagnostic_results=failed.diagnostic_results,
            owner_acceptance=None,
            coverage_authorization=failed.coverage_authorization,
        )
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM ge_cycle_assessment_contracts"
        )["n"]
        == 0
    )
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM ge_visible_diagnostic_supplement_contracts"
        )["n"]
        == 0
    )


def test_identity_collisions_and_child_substitution_fail_closed(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    artifacts: _RunArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _objects = _seed_store(
        tmp_path=tmp_path, database=database, cipher=cipher, artifacts=artifacts
    )
    conflicting_system = build_completed_system_run(
        pack=artifacts.pack,
        visible_run=artifacts.visible_run,
        repair_manifest_sha256=artifacts.repair_manifest_sha256,
        run_id=str(artifacts.system_run["run_id"]),
        case_results=artifacts.system_results,
        started_at=artifacts.started_at + timedelta(minutes=16),
        completed_at=artifacts.started_at + timedelta(minutes=26),
    )
    with pytest.raises(RuntimeError, match="identity has a different digest"):
        store.persist_system_run(
            pack=artifacts.pack,
            visible_run=artifacts.visible_run,
            system_run=conflicting_system,
            system_results=artifacts.system_results,
            repair_manifest_sha256=artifacts.repair_manifest_sha256,
        )

    failed = _build_cycle(
        artifacts,
        loop_id="ge-loop-persistence-collision",
        pack_id="ge-diagnostic-persistence-collision",
        failing=True,
        authority_root=tmp_path,
    )
    _persist_cycle(store, artifacts, failed)
    conflicting_pack = seal_contract(
        {
            **{
                key: value
                for key, value in failed.diagnostic_pack.items()
                if key != "content_sha256"
            },
            "created_at": (artifacts.started_at + timedelta(minutes=30)).isoformat(),
        }
    )
    with pytest.raises(RuntimeError, match="identity has a different digest"):
        store.persist_diagnostic_pack(
            pack=artifacts.pack,
            diagnostic_pack=conflicting_pack,
            visible_run=artifacts.visible_run,
            repair_manifest_sha256=artifacts.repair_manifest_sha256,
        )

    conflicting_assessment = seal_contract(
        {
            **{key: value for key, value in failed.assessment.items() if key != "content_sha256"},
            "assessed_at": (artifacts.started_at + timedelta(hours=3)).isoformat(),
        }
    )
    with pytest.raises(RuntimeError, match="identity has a different digest"):
        store.persist_cycle(
            pack=artifacts.pack,
            assessment=conflicting_assessment,
            diagnoses=failed.diagnoses,
            diagnostic_pack=failed.diagnostic_pack,
            diagnostic_results=failed.diagnostic_results,
            owner_acceptance=None,
            coverage_authorization=failed.coverage_authorization,
        )

    replay = store.load_cycle(
        pack=artifacts.pack,
        assessment_id=str(failed.assessment["assessment_id"]),
    )
    substituted_diagnosis = dict(replay[2][0])
    substituted_diagnosis["finding_sha256"] = "9" * 64

    def substituted_load_cycle(
        assessment_id: str, *, pack: VisibleGEPack | None = None
    ) -> tuple[
        Any,
        dict[str, Any],
        tuple[dict[str, Any], ...],
        tuple[dict[str, Any], ...],
        dict[str, Any] | None,
    ]:
        assert pack is artifacts.pack
        assert assessment_id == failed.assessment["assessment_id"]
        return replay[0], replay[1], (substituted_diagnosis,), replay[3], replay[4]

    monkeypatch.setattr(store, "load_cycle", substituted_load_cycle)
    with pytest.raises(RuntimeError, match="diagnosis idempotent replay artifacts differ"):
        _persist_cycle(store, artifacts, failed)


def test_schema_31_ge_rows_reject_every_update_and_delete_attempt(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    artifacts: _RunArtifacts,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _objects = _seed_store(
        tmp_path=tmp_path, database=database, cipher=cipher, artifacts=artifacts
    )
    failed = _build_cycle(
        artifacts,
        loop_id="ge-loop-persistence-trigger-failed",
        pack_id="ge-diagnostic-persistence-trigger-failed",
        failing=True,
        authority_root=tmp_path,
    )
    completed = _build_cycle(
        artifacts,
        loop_id="ge-loop-persistence-trigger-complete",
        pack_id="ge-diagnostic-persistence-trigger-complete",
        failing=False,
        authority_root=tmp_path,
    )
    completed = _authorize_cycle(
        completed,
        artifacts,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
    )
    _persist_cycle(store, artifacts, failed)
    _persist_cycle(store, artifacts, completed)

    update_attempts = (
        "UPDATE selected_ge_system_run_contracts SET run_validity=run_validity",
        "UPDATE selected_ge_system_case_contracts SET outcome=outcome",
        "UPDATE ge_visible_diagnostic_supplement_contracts SET case_count=case_count",
        "UPDATE ge_cycle_assessment_contracts SET status=status",
        "UPDATE ge_cycle_diagnosis_contracts SET status=status",
        "UPDATE ge_diagnostic_case_result_contracts SET factual_outcome=factual_outcome",
        "UPDATE ge_cycle_owner_acceptance_contracts SET owner_decision_id=owner_decision_id",
    )
    delete_attempts = (
        "DELETE FROM selected_ge_system_run_contracts",
        "DELETE FROM selected_ge_system_case_contracts",
        "DELETE FROM ge_visible_diagnostic_supplement_contracts",
        "DELETE FROM ge_cycle_assessment_contracts",
        "DELETE FROM ge_cycle_diagnosis_contracts",
        "DELETE FROM ge_diagnostic_case_result_contracts",
        "DELETE FROM ge_cycle_owner_acceptance_contracts",
    )
    protected_counts = {
        table: int(database.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"])
        for table in (
            "selected_ge_system_run_contracts",
            "selected_ge_system_case_contracts",
            "ge_visible_diagnostic_supplement_contracts",
            "ge_cycle_assessment_contracts",
            "ge_cycle_diagnosis_contracts",
            "ge_diagnostic_case_result_contracts",
            "ge_cycle_owner_acceptance_contracts",
        )
    }
    for statement in update_attempts:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            database.execute(statement)
    for statement in delete_attempts:
        with pytest.raises(sqlite3.IntegrityError, match="cannot be deleted"):
            database.execute(statement)
    assert {
        table: int(database.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"])
        for table in protected_counts
    } == protected_counts
    assert all(count > 0 for count in protected_counts.values())
    assert canonical_json_bytes(failed.assessment) != canonical_json_bytes(completed.assessment)
