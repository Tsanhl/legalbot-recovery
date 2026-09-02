"""Immutable encrypted persistence for the General Enquiry improvement loop."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..contracts import ContractSchemaRegistry, canonical_json_bytes, content_sha256
from ..db import Database, utc_iso
from ..orchestration.object_store import EncryptedObjectStore
from .ge_coverage_authorization import VerifiedGECoverageAuthorization
from .ge_cycle_owner_authorization import (
    VerifiedGECycleOwnerAuthorization,
    build_verified_cycle_owner_acceptance,
    require_verified_cycle_owner_authorization,
)
from .ge_improvement_loop import (
    build_coverage_audit,
    build_cycle_assessment,
    validate_completed_system_run,
    validate_cycle_assessment,
    validate_diagnosis,
    validate_diagnostic_case_result,
    validate_visible_diagnostic_supplement,
)
from .ge_visible_harness import SYSTEM_SCENARIO_COUNT, VisibleGEPack
from .selected_persistence import SelectedEvaluationRunStore


@dataclass(frozen=True, slots=True)
class PersistedGESystemRun:
    run_id: str
    run_sha256: str
    linked_visible_run_id: str
    run_object_key: str
    case_object_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PersistedGEDiagnosticPack:
    pack_id: str
    pack_sha256: str
    object_key: str
    case_count: int


@dataclass(frozen=True, slots=True)
class PersistedGECycle:
    assessment_id: str
    assessment_sha256: str
    loop_id: str
    cycle_number: int
    status: str
    assessment_object_key: str
    diagnosis_object_keys: tuple[str, ...]
    diagnostic_result_object_keys: tuple[str, ...]
    owner_acceptance_object_key: str | None


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _evaluation_run_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sealed_sha256(value: Mapping[str, Any], *, label: str) -> str:
    supplied = str(value.get("content_sha256") or "")
    if _HEX64.fullmatch(supplied) is None or content_sha256(value) != supplied:
        raise RuntimeError(f"{label} content digest differs")
    return supplied


def _require_exact_artifact(
    persisted: Mapping[str, Any], incoming: Mapping[str, Any], *, label: str
) -> None:
    if canonical_json_bytes(persisted) != canonical_json_bytes(incoming):
        raise RuntimeError(f"{label} replay artifact differs")


def _require_exact_artifact_sequence(
    persisted: Sequence[Mapping[str, Any]],
    incoming: Sequence[Mapping[str, Any]],
    *,
    label: str,
) -> None:
    if len(persisted) != len(incoming) or any(
        canonical_json_bytes(stored) != canonical_json_bytes(supplied)
        for stored, supplied in zip(persisted, incoming, strict=True)
    ):
        raise RuntimeError(f"{label} replay artifacts differ")


def _diagnosis_manifest(diagnoses: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "diagnosis_id": diagnosis["diagnosis_id"],
            "case_id": diagnosis["case_id"],
            "failure_class": diagnosis["failure_class"],
            "failure_code": diagnosis["failure_code"],
            "failed_check_ids": diagnosis["failed_check_ids"],
            "failure_fingerprint_sha256": diagnosis["failure_fingerprint_sha256"],
            "status": diagnosis["status"],
            "materiality": diagnosis["materiality"],
            "knowledge_or_source_gap": diagnosis["knowledge_or_source_gap"],
            "content_sha256": diagnosis["content_sha256"],
        }
        for diagnosis in diagnoses
    ]


def _diagnostic_result_manifest(
    results: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "diagnostic_case_id": result["diagnostic_case_id"],
            "result_id": result["result_id"],
            "content_sha256": result["content_sha256"],
        }
        for result in results
    ]


def _validated_owner_acceptance_sha256(
    value: Mapping[str, Any],
    *,
    decision_basis_sha256: str,
    label: str,
    owner_authorization: VerifiedGECycleOwnerAuthorization | None = None,
    require_authorization: bool = False,
) -> str:
    supplied = _sealed_sha256(value, label=label)
    if (
        value.get("schema") != "legalbot.ge-cycle-owner-acceptance.v1"
        or value.get("decision") != "ACCEPT"
        or value.get("decision_basis_sha256") != decision_basis_sha256
        or value.get("unseen_opened") is not False
        or _HEX64.fullmatch(
            str(value.get("predecision_assessment_sha256") or "")
        )
        is None
        or _HEX64.fullmatch(str(value.get("owner_request_sha256") or "")) is None
        or _HEX64.fullmatch(str(value.get("authorization_sha256") or "")) is None
        or not str(value.get("owner_decision_id") or "")
    ):
        raise RuntimeError(f"{label} custody differs")
    try:
        datetime.fromisoformat(str(value.get("decided_at") or ""))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{label} is invalid") from exc
    if require_authorization or owner_authorization is not None:
        authorization = require_verified_cycle_owner_authorization(
            owner_authorization,
            decision_basis_sha256=decision_basis_sha256,
        )
        expected = build_verified_cycle_owner_acceptance(authorization)
        if canonical_json_bytes(expected) != canonical_json_bytes(value):
            raise RuntimeError(f"{label} verifier-issued replay differs")
    return supplied


def _validate_assessment_coverage_audit(
    *,
    pack: VisibleGEPack | None,
    assessment: Mapping[str, Any],
    diagnostic_pack: Mapping[str, Any] | None,
    coverage_authorization: VerifiedGECoverageAuthorization | None = None,
    require_authorization: bool = False,
) -> None:
    raw_audit = assessment.get("coverage_audit")
    if not isinstance(raw_audit, Mapping):
        raise RuntimeError("GE cycle coverage audit is missing")
    audit_sha256 = _sealed_sha256(raw_audit, label="GE cycle coverage audit")
    raw_manifest = raw_audit.get("coverage_manifest")
    if not isinstance(raw_manifest, Mapping):
        raise RuntimeError("GE cycle coverage manifest is missing")
    if require_authorization and coverage_authorization is None:
        raise RuntimeError("verifier-issued GE coverage authorization is required")
    if pack is not None and coverage_authorization is not None:
        try:
            expected = build_coverage_audit(
                pack=pack,
                coverage_manifest=raw_manifest,
                coverage_authorization=coverage_authorization,
                existing_diagnostic_pack=diagnostic_pack,
                audited_at=datetime.fromisoformat(str(raw_audit.get("audited_at") or "")),
                unseen_opened=False,
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError("GE cycle coverage audit is invalid") from exc
        _require_exact_artifact(expected, raw_audit, label="GE cycle coverage audit deterministic")
    basis = assessment.get("decision_basis")
    if not isinstance(basis, Mapping):
        raise RuntimeError("GE cycle decision basis is missing")
    coverage_bindings = {
        "coverage_manifest_sha256": "coverage_manifest_sha256",
        "coverage_predecision_sha256": "coverage_predecision_sha256",
        "coverage_breadth_policy_id": "breadth_policy_id",
        "coverage_breadth_policy_sha256": "breadth_policy_sha256",
        "coverage_required_domain_set_sha256": "required_domain_set_sha256",
        "coverage_cell_manifest_sha256": "cell_manifest_sha256",
        "coverage_cell_order_sha256": "cell_order_sha256",
        "coverage_topology_sha256": "topology_sha256",
        "coverage_owner_request_sha256": "owner_request_sha256",
        "coverage_owner_resolution_sha256": "owner_resolution_sha256",
    }
    if (
        assessment.get("coverage_audit_sha256") != audit_sha256
        or basis.get("coverage_audit_sha256") != audit_sha256
        or assessment.get("missing_coverage_cell_count") != raw_audit.get("missing_cell_count")
        or basis.get("missing_coverage_cell_count") != raw_audit.get("missing_cell_count")
    ):
        raise RuntimeError("GE cycle coverage audit binding differs")
    for assessment_key, audit_key in coverage_bindings.items():
        if (
            assessment.get(assessment_key) != raw_audit.get(audit_key)
            or basis.get(assessment_key) != raw_audit.get(audit_key)
        ):
            raise RuntimeError("GE cycle coverage authority binding differs")


class GEImprovementLoopStore:
    """Persist and replay non-authorizing GE loop artifacts without substitution."""

    def __init__(
        self,
        *,
        database: Database,
        objects: EncryptedObjectStore,
        registry: ContractSchemaRegistry | None = None,
    ) -> None:
        self.database = database
        self.objects = objects
        self.registry = registry or ContractSchemaRegistry.from_project_root(
            Path(__file__).resolve().parents[3]
        )

    def persist_system_run(
        self,
        *,
        pack: VisibleGEPack,
        visible_run: Mapping[str, Any],
        system_run: Mapping[str, Any],
        system_results: Sequence[Mapping[str, Any]],
        repair_manifest_sha256: str,
    ) -> PersistedGESystemRun:
        validate_completed_system_run(
            pack=pack,
            visible_run=visible_run,
            system_run=system_run,
            system_results=system_results,
            repair_manifest_sha256=repair_manifest_sha256,
        )
        run_id = str(system_run["run_id"])
        run_sha256 = _sealed_sha256(system_run, label="GE system run")
        visible_run_id = str(system_run["linked_visible_run_id"])
        visible_sha256 = _evaluation_run_sha256(visible_run)
        selected_visible = self.database.fetchone(
            "SELECT run_sha256 FROM selected_evaluation_run_contracts WHERE run_id=?",
            (visible_run_id,),
        )
        if selected_visible is None or str(selected_visible["run_sha256"]) != visible_sha256:
            raise RuntimeError("GE system run lacks its exact persisted visible run")
        existing = self.database.fetchone(
            "SELECT run_sha256 FROM selected_ge_system_run_contracts WHERE run_id=?",
            (run_id,),
        )
        if existing is not None:
            if str(existing["run_sha256"]) != run_sha256:
                raise RuntimeError("GE system run identity has a different digest")
            persisted, stored_run, stored_results = self.load_system_run(
                pack=pack,
                visible_run=visible_run,
                run_id=run_id,
                repair_manifest_sha256=repair_manifest_sha256,
            )
            _require_exact_artifact(stored_run, system_run, label="GE system run idempotent")
            _require_exact_artifact_sequence(
                stored_results,
                system_results,
                label="GE system result idempotent",
            )
            return persisted

        run_object_key = self.objects.put_json(
            namespace="ge_system_run",
            value=system_run,
            metadata={"run_id": run_id, "run_sha256": run_sha256},
            ttl_days=None,
        )
        case_object_keys = tuple(
            self.objects.put_json(
                namespace="ge_system_case_result",
                value=result,
                metadata={
                    "run_id": run_id,
                    "system_case_id": str(result["system_case_id"]),
                    "result_sha256": str(result["content_sha256"]),
                },
                ttl_days=None,
            )
            for result in system_results
        )
        created_at = utc_iso()
        with self.database.transaction() as conn:
            if (
                conn.execute(
                    "SELECT 1 FROM selected_ge_system_run_contracts WHERE run_id=?", (run_id,)
                ).fetchone()
                is not None
            ):
                raise RuntimeError("GE system run raced with another writer")
            conn.execute(
                """
                INSERT INTO selected_ge_system_run_contracts(
                  run_id,run_sha256,linked_visible_run_id,candidate_sha256,
                  system_manifest_sha256,system_order_sha256,result_manifest_sha256,
                  result_count,run_validity,run_object_key,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run_id,
                    run_sha256,
                    visible_run_id,
                    str(system_run["candidate_sha256"]),
                    str(system_run["system_manifest_sha256"]),
                    str(system_run["system_order_sha256"]),
                    str(system_run["result_manifest_sha256"]),
                    int(system_run["result_count"]),
                    str(system_run["run_validity"]),
                    run_object_key,
                    created_at,
                ),
            )
            for result, object_key in zip(system_results, case_object_keys, strict=True):
                conn.execute(
                    """
                    INSERT INTO selected_ge_system_case_contracts(
                      run_id,ordinal,system_case_id,result_id,result_sha256,outcome,
                      object_key,created_at
                    ) VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        run_id,
                        int(result["ordinal"]),
                        str(result["system_case_id"]),
                        str(result["result_id"]),
                        str(result["content_sha256"]),
                        str(result["outcome"]),
                        object_key,
                        created_at,
                    ),
                )
        return PersistedGESystemRun(
            run_id=run_id,
            run_sha256=run_sha256,
            linked_visible_run_id=visible_run_id,
            run_object_key=run_object_key,
            case_object_keys=case_object_keys,
        )

    def load_system_run(
        self,
        *,
        pack: VisibleGEPack,
        visible_run: Mapping[str, Any],
        run_id: str,
        repair_manifest_sha256: str,
    ) -> tuple[PersistedGESystemRun, dict[str, Any], tuple[dict[str, Any], ...]]:
        row = self.database.fetchone(
            "SELECT * FROM selected_ge_system_run_contracts WHERE run_id=?", (run_id,)
        )
        cases = self.database.fetchall(
            "SELECT * FROM selected_ge_system_case_contracts WHERE run_id=? ORDER BY ordinal",
            (run_id,),
        )
        if row is None or len(cases) != SYSTEM_SCENARIO_COUNT:
            raise RuntimeError("persisted GE system run is incomplete")
        run = self.objects.get_json(str(row["run_object_key"]))
        results = tuple(self.objects.get_json(str(case["object_key"])) for case in cases)
        validate_completed_system_run(
            pack=pack,
            visible_run=visible_run,
            system_run=run,
            system_results=results,
            repair_manifest_sha256=repair_manifest_sha256,
        )
        visible_sha256 = _evaluation_run_sha256(visible_run)
        selected_visible = self.database.fetchone(
            "SELECT run_sha256 FROM selected_evaluation_run_contracts WHERE run_id=?",
            (str(run["linked_visible_run_id"]),),
        )
        if selected_visible is None or str(selected_visible["run_sha256"]) != visible_sha256:
            raise RuntimeError("persisted GE system run lacks its exact visible run")
        run_sha256 = _sealed_sha256(run, label="persisted GE system run")
        if (
            run_sha256 != str(row["run_sha256"])
            or run["run_id"] != run_id
            or run["linked_visible_run_id"] != row["linked_visible_run_id"]
            or run["candidate_sha256"] != row["candidate_sha256"]
            or run["system_manifest_sha256"] != row["system_manifest_sha256"]
            or run["system_order_sha256"] != row["system_order_sha256"]
            or run["result_manifest_sha256"] != row["result_manifest_sha256"]
            or int(run["result_count"]) != int(row["result_count"])
            or run["run_validity"] != row["run_validity"]
        ):
            raise RuntimeError("persisted GE system run binding differs")
        object_keys: list[str] = []
        for ordinal, (case, result) in enumerate(zip(cases, results, strict=True), start=1):
            if (
                int(case["ordinal"]) != ordinal
                or result["ordinal"] != ordinal
                or result["system_case_id"] != case["system_case_id"]
                or result["result_id"] != case["result_id"]
                or result["content_sha256"] != case["result_sha256"]
                or result["outcome"] != case["outcome"]
            ):
                raise RuntimeError("persisted GE system result binding differs")
            object_keys.append(str(case["object_key"]))
        return (
            PersistedGESystemRun(
                run_id=run_id,
                run_sha256=run_sha256,
                linked_visible_run_id=str(row["linked_visible_run_id"]),
                run_object_key=str(row["run_object_key"]),
                case_object_keys=tuple(object_keys),
            ),
            run,
            results,
        )

    def persist_diagnostic_pack(
        self,
        *,
        pack: VisibleGEPack,
        diagnostic_pack: Mapping[str, Any],
        visible_run: Mapping[str, Any],
        repair_manifest_sha256: str,
    ) -> PersistedGEDiagnosticPack:
        validate_visible_diagnostic_supplement(
            pack=pack,
            diagnostic_pack=diagnostic_pack,
            visible_run=visible_run,
            repair_manifest_sha256=repair_manifest_sha256,
        )
        pack_id = str(diagnostic_pack["pack_id"])
        pack_sha256 = _sealed_sha256(diagnostic_pack, label="GE diagnostic pack")
        existing = self.database.fetchone(
            "SELECT * FROM ge_visible_diagnostic_supplement_contracts WHERE pack_id=?",
            (pack_id,),
        )
        if existing is not None:
            if str(existing["pack_sha256"]) != pack_sha256:
                raise RuntimeError("GE diagnostic pack identity has a different digest")
            persisted, stored_value = self.load_diagnostic_pack(
                pack=pack,
                pack_id=pack_id,
                visible_run=visible_run,
                repair_manifest_sha256=repair_manifest_sha256,
            )
            _require_exact_artifact(
                stored_value, diagnostic_pack, label="GE diagnostic pack idempotent"
            )
            return persisted
        object_key = self.objects.put_json(
            namespace="ge_diagnostic_pack",
            value=diagnostic_pack,
            metadata={"pack_id": pack_id, "pack_sha256": pack_sha256},
            ttl_days=None,
        )
        self.database.execute(
            """
            INSERT INTO ge_visible_diagnostic_supplement_contracts(
              pack_id,pack_sha256,linked_cycle_id,fixed_pack_manifest_sha256,
              case_manifest_sha256,case_count,object_key,created_at
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                pack_id,
                pack_sha256,
                str(diagnostic_pack["linked_cycle_id"]),
                str(diagnostic_pack["fixed_pack_manifest_sha256"]),
                str(diagnostic_pack["case_manifest_sha256"]),
                int(diagnostic_pack["case_count"]),
                object_key,
                utc_iso(),
            ),
        )
        return PersistedGEDiagnosticPack(
            pack_id=pack_id,
            pack_sha256=pack_sha256,
            object_key=object_key,
            case_count=int(diagnostic_pack["case_count"]),
        )

    def load_diagnostic_pack(
        self,
        *,
        pack: VisibleGEPack,
        pack_id: str,
        visible_run: Mapping[str, Any],
        repair_manifest_sha256: str,
    ) -> tuple[PersistedGEDiagnosticPack, dict[str, Any]]:
        row = self.database.fetchone(
            "SELECT * FROM ge_visible_diagnostic_supplement_contracts WHERE pack_id=?",
            (pack_id,),
        )
        if row is None:
            raise KeyError(pack_id)
        value = self.objects.get_json(str(row["object_key"]))
        validate_visible_diagnostic_supplement(
            pack=pack,
            diagnostic_pack=value,
            visible_run=visible_run,
            repair_manifest_sha256=repair_manifest_sha256,
        )
        pack_sha256 = _sealed_sha256(value, label="persisted GE diagnostic pack")
        if (
            value["pack_id"] != pack_id
            or pack_sha256 != row["pack_sha256"]
            or value["linked_cycle_id"] != row["linked_cycle_id"]
            or value["fixed_pack_manifest_sha256"] != row["fixed_pack_manifest_sha256"]
            or value["case_manifest_sha256"] != row["case_manifest_sha256"]
            or int(value["case_count"]) != int(row["case_count"])
        ):
            raise RuntimeError("persisted GE diagnostic pack binding differs")
        return (
            PersistedGEDiagnosticPack(
                pack_id=pack_id,
                pack_sha256=pack_sha256,
                object_key=str(row["object_key"]),
                case_count=int(row["case_count"]),
            ),
            value,
        )

    def _load_persisted_visible_run(
        self, *, run_id: str
    ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
        """Load the exact immutable 331-result run selected by persistence."""

        persisted = SelectedEvaluationRunStore(
            database=self.database,
            objects=self.objects,
            registry=self.registry,
        ).load_completed_visible_ge(run_id)
        run = self.objects.get_json(persisted.run_object_key)
        results = tuple(self.objects.get_json(key) for key in persisted.case_object_keys)
        if _evaluation_run_sha256(run) != persisted.run_sha256:
            raise RuntimeError("persisted selected evaluation run replay digest differs")
        return run, results

    def persist_cycle(
        self,
        *,
        pack: VisibleGEPack,
        assessment: Mapping[str, Any],
        diagnoses: Sequence[Mapping[str, Any]],
        diagnostic_pack: Mapping[str, Any] | None,
        diagnostic_results: Sequence[Mapping[str, Any]],
        owner_acceptance: Mapping[str, Any] | None,
        coverage_authorization: VerifiedGECoverageAuthorization,
        owner_authorization: VerifiedGECycleOwnerAuthorization | None = None,
        successor_candidate_plan: Mapping[str, Any] | None = None,
        change_applied_at: datetime | None = None,
    ) -> PersistedGECycle:
        validate_cycle_assessment(assessment)
        self.registry.validate_new(assessment)
        assessment_id = str(assessment["assessment_id"])
        assessment_sha256 = _sealed_sha256(assessment, label="GE cycle assessment")
        if len(diagnoses) != int(assessment["diagnosis_count"]):
            raise RuntimeError("GE cycle diagnosis count differs")
        for diagnosis in diagnoses:
            validate_diagnosis(diagnosis)
        diagnosis_manifest_sha256 = hashlib.sha256(
            canonical_json_bytes(_diagnosis_manifest(diagnoses))
        ).hexdigest()
        if diagnosis_manifest_sha256 != assessment["diagnosis_manifest_sha256"]:
            raise RuntimeError("GE cycle diagnosis manifest differs")
        diagnostic_result_manifest_sha256 = hashlib.sha256(
            canonical_json_bytes(_diagnostic_result_manifest(diagnostic_results))
        ).hexdigest()
        if diagnostic_result_manifest_sha256 != assessment["diagnostic_result_manifest_sha256"]:
            raise RuntimeError("GE diagnostic result manifest differs")

        persisted_visible, persisted_visible_results = self._load_persisted_visible_run(
            run_id=str(assessment["visible_run_id"])
        )
        if (
            _evaluation_run_sha256(persisted_visible) != assessment["visible_run_sha256"]
            or persisted_visible.get("run_id") != assessment["visible_run_id"]
            or persisted_visible.get("candidate_sha256") != assessment["candidate_sha256"]
        ):
            raise RuntimeError("GE cycle persisted visible-run binding differs")

        (
            persisted_system,
            persisted_system_run,
            persisted_system_results,
        ) = self.load_system_run(
            pack=pack,
            visible_run=persisted_visible,
            run_id=str(assessment["system_run_id"]),
            repair_manifest_sha256=str(assessment["repair_manifest_sha256"]),
        )
        if (
            persisted_system.run_sha256 != assessment["system_run_sha256"]
            or persisted_system.linked_visible_run_id != assessment["visible_run_id"]
            or persisted_system_run.get("candidate_sha256") != assessment["candidate_sha256"]
        ):
            raise RuntimeError("GE cycle lacks its exact persisted system run")

        pack_id: str | None = None
        diagnostic_pack_sha256: str | None = None
        if diagnostic_pack is None:
            if assessment.get("diagnostic_pack_sha256") is not None or diagnostic_results:
                raise RuntimeError("GE cycle diagnostic pack binding differs")
        else:
            validate_visible_diagnostic_supplement(
                pack=pack,
                diagnostic_pack=diagnostic_pack,
                visible_run=persisted_visible,
                repair_manifest_sha256=str(assessment["repair_manifest_sha256"]),
            )
            diagnostic_pack_sha256 = _sealed_sha256(
                diagnostic_pack, label="GE diagnostic pack"
            )
            if assessment.get("diagnostic_pack_sha256") != diagnostic_pack_sha256:
                raise RuntimeError("GE cycle diagnostic pack digest differs")
            raw_cases = diagnostic_pack.get("cases")
            if not isinstance(raw_cases, list) or len(diagnostic_results) != len(raw_cases):
                raise RuntimeError("GE cycle diagnostic result count differs")
            pack_id = str(diagnostic_pack["pack_id"])
            for ordinal, (case, result) in enumerate(
                zip(raw_cases, diagnostic_results, strict=True), start=1
            ):
                if not isinstance(case, Mapping):
                    raise RuntimeError("GE diagnostic case is invalid")
                validate_diagnostic_case_result(
                    diagnostic_pack=diagnostic_pack,
                    diagnostic_case=case,
                    result=result,
                )
                if (
                    result.get("diagnostic_pack_id") != pack_id
                    or result.get("diagnostic_case_id") != case.get("diagnostic_case_id")
                    or result.get("diagnostic_case_sha256") != case.get("content_sha256")
                    or result.get("ordinal") != ordinal
                    or _sealed_sha256(result, label="GE diagnostic result")
                    != result.get("content_sha256")
                ):
                    raise RuntimeError("GE cycle diagnostic result binding differs")

        _validate_assessment_coverage_audit(
            pack=pack,
            assessment=assessment,
            diagnostic_pack=diagnostic_pack,
            coverage_authorization=coverage_authorization,
            require_authorization=True,
        )

        acceptance_sha256 = assessment.get("owner_acceptance_sha256")
        if owner_acceptance is None:
            if acceptance_sha256 is not None or owner_authorization is not None:
                raise RuntimeError("GE cycle owner acceptance object is missing")
        else:
            observed_acceptance_sha256 = _validated_owner_acceptance_sha256(
                owner_acceptance,
                decision_basis_sha256=str(assessment["decision_basis_sha256"]),
                label="GE owner acceptance",
                owner_authorization=owner_authorization,
                require_authorization=True,
            )
            if observed_acceptance_sha256 != acceptance_sha256 or owner_acceptance.get(
                "decision_basis_sha256"
            ) != assessment.get("decision_basis_sha256"):
                raise RuntimeError("GE cycle owner acceptance binding differs")

        predecessor_sha256 = assessment.get("predecessor_assessment_sha256")
        previous_assessment: Mapping[str, Any] | None = None
        if predecessor_sha256 is not None:
            predecessor = self.database.fetchone(
                "SELECT assessment_id,loop_id,cycle_number FROM ge_cycle_assessment_contracts "
                "WHERE assessment_sha256=?",
                (str(predecessor_sha256),),
            )
            if (
                predecessor is None
                or predecessor["loop_id"] != assessment["loop_id"]
                or int(predecessor["cycle_number"]) != int(assessment["cycle_number"]) - 1
            ):
                raise RuntimeError("GE cycle predecessor is not persisted")
            (
                _persisted_predecessor,
                loaded_predecessor,
                _predecessor_diagnoses,
                _predecessor_results,
                _predecessor_acceptance,
            ) = self.load_cycle(str(predecessor["assessment_id"]), pack=pack)
            if loaded_predecessor.get("content_sha256") != predecessor_sha256:
                raise RuntimeError("GE cycle predecessor replay digest differs")
            self.registry.validate_new(loaded_predecessor)
            previous_assessment = loaded_predecessor
        elif int(assessment["cycle_number"]) != 1:
            raise RuntimeError("later GE cycle has no persisted predecessor")

        unseen_opened = assessment.get("unseen_opened")
        if type(unseen_opened) is not bool:
            raise RuntimeError("GE cycle unseen-custody state is invalid")
        try:
            assessed_at = datetime.fromisoformat(str(assessment.get("assessed_at") or ""))
            expected_assessment = build_cycle_assessment(
                loop_id=str(assessment["loop_id"]),
                cycle_number=int(assessment["cycle_number"]),
                registry=self.registry,
                pack=pack,
                visible_run=persisted_visible,
                visible_results=persisted_visible_results,
                system_run=persisted_system_run,
                system_results=persisted_system_results,
                repair_manifest_sha256=str(assessment["repair_manifest_sha256"]),
                diagnoses=diagnoses,
                coverage_audit=assessment["coverage_audit"],
                coverage_authorization=coverage_authorization,
                diagnostic_supplement=diagnostic_pack,
                diagnostic_results=diagnostic_results,
                unseen_opened=unseen_opened,
                assessed_at=assessed_at,
                successor_candidate_plan=successor_candidate_plan,
                previous_assessment=previous_assessment,
                change_applied_at=change_applied_at,
                owner_acceptance=owner_acceptance,
                owner_authorization=owner_authorization,
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError("GE cycle persisted-artifact reconstruction failed") from exc
        _require_exact_artifact(
            expected_assessment,
            assessment,
            label="GE cycle persisted-artifact reconstruction",
        )

        existing = self.database.fetchone(
            "SELECT assessment_sha256 FROM ge_cycle_assessment_contracts WHERE assessment_id=?",
            (assessment_id,),
        )
        if existing is not None:
            if str(existing["assessment_sha256"]) != assessment_sha256:
                raise RuntimeError("GE cycle identity has a different digest")
            (
                persisted,
                stored_assessment,
                stored_diagnoses,
                stored_results,
                stored_acceptance,
            ) = self.load_cycle(assessment_id, pack=pack)
            _require_exact_artifact(
                stored_assessment, assessment, label="GE cycle assessment idempotent"
            )
            _require_exact_artifact_sequence(
                stored_diagnoses,
                diagnoses,
                label="GE cycle diagnosis idempotent",
            )
            _require_exact_artifact_sequence(
                stored_results,
                diagnostic_results,
                label="GE diagnostic result idempotent",
            )
            if (stored_acceptance is None) != (owner_acceptance is None):
                raise RuntimeError("GE owner acceptance idempotent replay differs")
            if stored_acceptance is not None and owner_acceptance is not None:
                _require_exact_artifact(
                    stored_acceptance,
                    owner_acceptance,
                    label="GE owner acceptance idempotent",
                )
            return persisted

        if diagnostic_pack is not None:
            persisted_pack = self.persist_diagnostic_pack(
                pack=pack,
                diagnostic_pack=diagnostic_pack,
                visible_run=persisted_visible,
                repair_manifest_sha256=str(assessment["repair_manifest_sha256"]),
            )
            if (
                persisted_pack.pack_id != pack_id
                or persisted_pack.pack_sha256 != diagnostic_pack_sha256
            ):
                raise RuntimeError("GE cycle persisted diagnostic pack binding differs")

        assessment_object_key = self.objects.put_json(
            namespace="ge_cycle_assessment",
            value=assessment,
            metadata={
                "assessment_id": assessment_id,
                "assessment_sha256": assessment_sha256,
            },
            ttl_days=None,
        )
        diagnosis_object_keys = tuple(
            self.objects.put_json(
                namespace="ge_cycle_diagnosis",
                value=diagnosis,
                metadata={
                    "assessment_id": assessment_id,
                    "diagnosis_id": str(diagnosis["diagnosis_id"]),
                    "diagnosis_sha256": str(diagnosis["content_sha256"]),
                },
                ttl_days=None,
            )
            for diagnosis in diagnoses
        )
        diagnostic_result_object_keys = tuple(
            self.objects.put_json(
                namespace="ge_diagnostic_result",
                value=result,
                metadata={
                    "assessment_id": assessment_id,
                    "diagnostic_case_id": str(result["diagnostic_case_id"]),
                    "result_sha256": str(result["content_sha256"]),
                },
                ttl_days=None,
            )
            for result in diagnostic_results
        )
        acceptance_object_key = (
            self.objects.put_json(
                namespace="ge_cycle_owner_acceptance",
                value=owner_acceptance,
                metadata={
                    "assessment_id": assessment_id,
                    "acceptance_sha256": str(owner_acceptance["content_sha256"]),
                },
                ttl_days=None,
            )
            if owner_acceptance is not None
            else None
        )
        created_at = utc_iso()
        with self.database.transaction() as conn:
            if (
                conn.execute(
                    "SELECT 1 FROM ge_cycle_assessment_contracts WHERE assessment_id=?",
                    (assessment_id,),
                ).fetchone()
                is not None
            ):
                raise RuntimeError("GE cycle assessment raced with another writer")
            conn.execute(
                """
                INSERT INTO ge_cycle_assessment_contracts(
                  assessment_id,assessment_sha256,loop_id,cycle_number,
                  predecessor_assessment_sha256,status,visible_run_id,system_run_id,
                  evaluated_candidate_sha256,diagnosis_count,diagnosis_manifest_sha256,
                  open_material_diagnosis_count,diagnostic_supplement_sha256,
                  decision_basis_sha256,owner_acceptance_sha256,object_key,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    assessment_id,
                    assessment_sha256,
                    str(assessment["loop_id"]),
                    int(assessment["cycle_number"]),
                    predecessor_sha256,
                    str(assessment["status"]),
                    str(assessment["visible_run_id"]),
                    str(assessment["system_run_id"]),
                    str(assessment["candidate_sha256"]),
                    int(assessment["diagnosis_count"]),
                    str(assessment["diagnosis_manifest_sha256"]),
                    int(assessment["open_material_diagnosis_count"]),
                    assessment.get("diagnostic_pack_sha256"),
                    str(assessment["decision_basis_sha256"]),
                    acceptance_sha256,
                    assessment_object_key,
                    created_at,
                ),
            )
            for ordinal, (diagnosis, object_key) in enumerate(
                zip(diagnoses, diagnosis_object_keys, strict=True), start=1
            ):
                conn.execute(
                    """
                    INSERT INTO ge_cycle_diagnosis_contracts(
                      assessment_id,ordinal,diagnosis_id,diagnosis_sha256,
                      failure_fingerprint_sha256,case_id,case_kind,failure_class,
                      materiality,status,object_key,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        assessment_id,
                        ordinal,
                        str(diagnosis["diagnosis_id"]),
                        str(diagnosis["content_sha256"]),
                        str(diagnosis["failure_fingerprint_sha256"]),
                        str(diagnosis["case_id"]),
                        str(diagnosis["case_kind"]),
                        str(diagnosis["failure_class"]),
                        str(diagnosis["materiality"]),
                        str(diagnosis["status"]),
                        object_key,
                        created_at,
                    ),
                )
            if pack_id is not None:
                for result, object_key in zip(
                    diagnostic_results, diagnostic_result_object_keys, strict=True
                ):
                    conn.execute(
                        """
                        INSERT INTO ge_diagnostic_case_result_contracts(
                          assessment_id,pack_id,ordinal,diagnostic_case_id,result_sha256,
                          factual_outcome,quality_outcome,object_key,created_at
                        ) VALUES (?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            assessment_id,
                            pack_id,
                            int(result["ordinal"]),
                            str(result["diagnostic_case_id"]),
                            str(result["content_sha256"]),
                            str(result["factual_outcome"]),
                            str(result["quality_outcome"]),
                            object_key,
                            created_at,
                        ),
                    )
            if owner_acceptance is not None and acceptance_object_key is not None:
                conn.execute(
                    """
                    INSERT INTO ge_cycle_owner_acceptance_contracts(
                      assessment_id,owner_decision_id,acceptance_sha256,
                      decision_basis_sha256,object_key,created_at
                    ) VALUES (?,?,?,?,?,?)
                    """,
                    (
                        assessment_id,
                        str(owner_acceptance["owner_decision_id"]),
                        str(owner_acceptance["content_sha256"]),
                        str(owner_acceptance["decision_basis_sha256"]),
                        acceptance_object_key,
                        created_at,
                    ),
                )
        return PersistedGECycle(
            assessment_id=assessment_id,
            assessment_sha256=assessment_sha256,
            loop_id=str(assessment["loop_id"]),
            cycle_number=int(assessment["cycle_number"]),
            status=str(assessment["status"]),
            assessment_object_key=assessment_object_key,
            diagnosis_object_keys=diagnosis_object_keys,
            diagnostic_result_object_keys=diagnostic_result_object_keys,
            owner_acceptance_object_key=acceptance_object_key,
        )

    def load_cycle(
        self, assessment_id: str, *, pack: VisibleGEPack | None = None
    ) -> tuple[
        PersistedGECycle,
        dict[str, Any],
        tuple[dict[str, Any], ...],
        tuple[dict[str, Any], ...],
        dict[str, Any] | None,
    ]:
        row = self.database.fetchone(
            "SELECT * FROM ge_cycle_assessment_contracts WHERE assessment_id=?",
            (assessment_id,),
        )
        if row is None:
            raise KeyError(assessment_id)
        diagnosis_rows = self.database.fetchall(
            "SELECT * FROM ge_cycle_diagnosis_contracts WHERE assessment_id=? ORDER BY ordinal",
            (assessment_id,),
        )
        result_rows = self.database.fetchall(
            "SELECT * FROM ge_diagnostic_case_result_contracts "
            "WHERE assessment_id=? ORDER BY ordinal",
            (assessment_id,),
        )
        acceptance_row = self.database.fetchone(
            "SELECT * FROM ge_cycle_owner_acceptance_contracts WHERE assessment_id=?",
            (assessment_id,),
        )
        assessment = self.objects.get_json(str(row["object_key"]))
        validate_cycle_assessment(assessment)
        assessment_sha256 = _sealed_sha256(assessment, label="persisted GE cycle")
        if (
            assessment_sha256 != row["assessment_sha256"]
            or assessment["assessment_id"] != assessment_id
            or assessment["status"] != row["status"]
            or assessment["loop_id"] != row["loop_id"]
            or int(assessment["cycle_number"]) != int(row["cycle_number"])
            or assessment.get("predecessor_assessment_sha256")
            != row["predecessor_assessment_sha256"]
            or assessment["visible_run_id"] != row["visible_run_id"]
            or assessment["system_run_id"] != row["system_run_id"]
            or assessment["candidate_sha256"] != row["evaluated_candidate_sha256"]
            or int(assessment["diagnosis_count"]) != int(row["diagnosis_count"])
            or assessment["diagnosis_manifest_sha256"] != row["diagnosis_manifest_sha256"]
            or int(assessment["open_material_diagnosis_count"])
            != int(row["open_material_diagnosis_count"])
            or assessment.get("diagnostic_pack_sha256") != row["diagnostic_supplement_sha256"]
            or assessment["decision_basis_sha256"] != row["decision_basis_sha256"]
            or assessment.get("owner_acceptance_sha256") != row["owner_acceptance_sha256"]
        ):
            raise RuntimeError("persisted GE cycle binding differs")
        selected_visible = self.database.fetchone(
            "SELECT run_sha256 FROM selected_evaluation_run_contracts WHERE run_id=?",
            (str(assessment["visible_run_id"]),),
        )
        selected_system = self.database.fetchone(
            "SELECT run_sha256,linked_visible_run_id,candidate_sha256 "
            "FROM selected_ge_system_run_contracts WHERE run_id=?",
            (str(assessment["system_run_id"]),),
        )
        if (
            selected_visible is None
            or selected_visible["run_sha256"] != assessment["visible_run_sha256"]
            or selected_system is None
            or selected_system["run_sha256"] != assessment["system_run_sha256"]
            or selected_system["linked_visible_run_id"] != assessment["visible_run_id"]
            or selected_system["candidate_sha256"] != assessment["candidate_sha256"]
        ):
            raise RuntimeError("persisted GE cycle selected-run binding differs")
        persisted_visible_run: Mapping[str, Any] | None = None
        if pack is not None:
            persisted_visible_run, _persisted_visible_results = (
                self._load_persisted_visible_run(
                    run_id=str(assessment["visible_run_id"])
                )
            )
        predecessor_sha256 = assessment.get("predecessor_assessment_sha256")
        if predecessor_sha256 is not None:
            predecessor = self.database.fetchone(
                "SELECT loop_id,cycle_number FROM ge_cycle_assessment_contracts "
                "WHERE assessment_sha256=?",
                (str(predecessor_sha256),),
            )
            if (
                predecessor is None
                or predecessor["loop_id"] != assessment["loop_id"]
                or int(predecessor["cycle_number"]) != int(assessment["cycle_number"]) - 1
            ):
                raise RuntimeError("persisted GE cycle predecessor binding differs")
        elif int(assessment["cycle_number"]) != 1:
            raise RuntimeError("persisted later GE cycle has no predecessor")
        diagnoses = tuple(
            self.objects.get_json(str(diagnosis_row["object_key"]))
            for diagnosis_row in diagnosis_rows
        )
        for ordinal, (diagnosis_row, diagnosis) in enumerate(
            zip(diagnosis_rows, diagnoses, strict=True), start=1
        ):
            validate_diagnosis(diagnosis)
            if (
                int(diagnosis_row["ordinal"]) != ordinal
                or diagnosis["diagnosis_id"] != diagnosis_row["diagnosis_id"]
                or diagnosis["content_sha256"] != diagnosis_row["diagnosis_sha256"]
                or diagnosis["failure_fingerprint_sha256"]
                != diagnosis_row["failure_fingerprint_sha256"]
                or diagnosis["case_id"] != diagnosis_row["case_id"]
                or diagnosis["case_kind"] != diagnosis_row["case_kind"]
                or diagnosis["failure_class"] != diagnosis_row["failure_class"]
                or diagnosis["materiality"] != diagnosis_row["materiality"]
                or diagnosis["status"] != diagnosis_row["status"]
            ):
                raise RuntimeError("persisted GE diagnosis binding differs")
        manifest_sha256 = hashlib.sha256(
            canonical_json_bytes(_diagnosis_manifest(diagnoses))
        ).hexdigest()
        if (
            len(diagnoses) != int(assessment["diagnosis_count"])
            or manifest_sha256 != assessment["diagnosis_manifest_sha256"]
        ):
            raise RuntimeError("persisted GE diagnosis manifest differs")

        diagnostic_results = tuple(
            self.objects.get_json(str(result_row["object_key"])) for result_row in result_rows
        )
        loaded_diagnostic_pack: Mapping[str, Any] | None = None
        diagnostic_pack_sha256 = assessment.get("diagnostic_pack_sha256")
        if diagnostic_pack_sha256 is None:
            if result_rows:
                raise RuntimeError("persisted GE diagnostic results lack a pack")
        else:
            pack_row = self.database.fetchone(
                "SELECT * FROM ge_visible_diagnostic_supplement_contracts WHERE pack_sha256=?",
                (str(diagnostic_pack_sha256),),
            )
            if pack_row is None:
                raise RuntimeError("persisted GE cycle diagnostic pack is missing")
            diagnostic_pack = self.objects.get_json(str(pack_row["object_key"]))
            loaded_diagnostic_pack = diagnostic_pack
            if pack is not None:
                if persisted_visible_run is None:
                    raise RuntimeError("persisted GE diagnostic source run is missing")
                validate_visible_diagnostic_supplement(
                    pack=pack,
                    diagnostic_pack=diagnostic_pack,
                    visible_run=persisted_visible_run,
                    repair_manifest_sha256=str(assessment["repair_manifest_sha256"]),
                )
            observed_pack_sha256 = _sealed_sha256(
                diagnostic_pack, label="persisted GE diagnostic pack"
            )
            persisted_pack = PersistedGEDiagnosticPack(
                pack_id=str(pack_row["pack_id"]),
                pack_sha256=str(pack_row["pack_sha256"]),
                object_key=str(pack_row["object_key"]),
                case_count=int(pack_row["case_count"]),
            )
            raw_cases = diagnostic_pack.get("cases")
            if (
                observed_pack_sha256 != persisted_pack.pack_sha256
                or persisted_pack.pack_sha256 != diagnostic_pack_sha256
                or diagnostic_pack.get("pack_id") != persisted_pack.pack_id
                or diagnostic_pack.get("fixed_pack_manifest_sha256")
                != assessment["fixed_pack_manifest_sha256"]
                or diagnostic_pack.get("fixed_pack_manifest_sha256")
                != pack_row["fixed_pack_manifest_sha256"]
                or diagnostic_pack.get("fixed_case_manifest_sha256")
                != assessment["fixed_case_manifest_sha256"]
                or diagnostic_pack.get("fixed_case_order_sha256")
                != assessment["fixed_case_order_sha256"]
                or diagnostic_pack.get("case_manifest_sha256") != pack_row["case_manifest_sha256"]
                or diagnostic_pack.get("case_count") != persisted_pack.case_count
                or diagnostic_pack.get("linked_cycle_id") != assessment["cycle_id"]
                or diagnostic_pack.get("linked_cycle_id") != pack_row["linked_cycle_id"]
                or not isinstance(raw_cases, list)
                or len(raw_cases) != len(result_rows)
            ):
                raise RuntimeError("persisted GE cycle diagnostic pack binding differs")
            for ordinal, (result_row, diagnostic_case, result) in enumerate(
                zip(result_rows, raw_cases, diagnostic_results, strict=True), start=1
            ):
                if not isinstance(diagnostic_case, Mapping):
                    raise RuntimeError("persisted GE diagnostic case is invalid")
                validate_diagnostic_case_result(
                    diagnostic_pack=diagnostic_pack,
                    diagnostic_case=diagnostic_case,
                    result=result,
                )
                if (
                    int(result_row["ordinal"]) != ordinal
                    or int(result["ordinal"]) != ordinal
                    or result_row["pack_id"] != persisted_pack.pack_id
                    or result["diagnostic_pack_id"] != persisted_pack.pack_id
                    or _sealed_sha256(result, label="persisted GE diagnostic result")
                    != result_row["result_sha256"]
                    or result["diagnostic_case_id"] != result_row["diagnostic_case_id"]
                    or result["diagnostic_case_id"] != diagnostic_case["diagnostic_case_id"]
                    or result["factual_outcome"] != result_row["factual_outcome"]
                    or result["quality_outcome"] != result_row["quality_outcome"]
                ):
                    raise RuntimeError("persisted GE diagnostic result binding differs")
        _validate_assessment_coverage_audit(
            pack=pack,
            assessment=assessment,
            diagnostic_pack=loaded_diagnostic_pack,
        )
        result_manifest_sha256 = hashlib.sha256(
            canonical_json_bytes(_diagnostic_result_manifest(diagnostic_results))
        ).hexdigest()
        if result_manifest_sha256 != assessment["diagnostic_result_manifest_sha256"]:
            raise RuntimeError("persisted GE diagnostic result manifest differs")

        owner_acceptance = (
            self.objects.get_json(str(acceptance_row["object_key"]))
            if acceptance_row is not None
            else None
        )
        if owner_acceptance is None:
            if assessment.get("owner_acceptance_sha256") is not None:
                raise RuntimeError("persisted GE owner acceptance is missing")
            acceptance_object_key = None
        else:
            if acceptance_row is None:
                raise RuntimeError("persisted GE owner acceptance row is missing")
            acceptance_sha256 = _validated_owner_acceptance_sha256(
                owner_acceptance,
                decision_basis_sha256=str(assessment["decision_basis_sha256"]),
                label="persisted GE owner acceptance",
            )
            if (
                acceptance_sha256 != acceptance_row["acceptance_sha256"]
                or acceptance_sha256 != assessment.get("owner_acceptance_sha256")
                or owner_acceptance["owner_decision_id"] != acceptance_row["owner_decision_id"]
                or owner_acceptance["decision_basis_sha256"] != assessment["decision_basis_sha256"]
                or owner_acceptance["decision_basis_sha256"]
                != acceptance_row["decision_basis_sha256"]
            ):
                raise RuntimeError("persisted GE owner acceptance binding differs")
            acceptance_object_key = str(acceptance_row["object_key"])
        persisted = PersistedGECycle(
            assessment_id=assessment_id,
            assessment_sha256=assessment_sha256,
            loop_id=str(row["loop_id"]),
            cycle_number=int(row["cycle_number"]),
            status=str(row["status"]),
            assessment_object_key=str(row["object_key"]),
            diagnosis_object_keys=tuple(str(value["object_key"]) for value in diagnosis_rows),
            diagnostic_result_object_keys=tuple(str(value["object_key"]) for value in result_rows),
            owner_acceptance_object_key=acceptance_object_key,
        )
        return persisted, assessment, diagnoses, diagnostic_results, owner_acceptance


__all__ = [
    "GEImprovementLoopStore",
    "PersistedGECycle",
    "PersistedGEDiagnosticPack",
    "PersistedGESystemRun",
]
