"""Deterministic, non-authorizing General Enquiry improvement-loop artifacts.

This module deliberately has no network, model, database, catalogue, index, or
promotion adapter.  It reconciles the fixed visible GE evaluation, its separate
system-behaviour suite, evidence-backed diagnoses, diagnostic-only questions,
and the gates for a later full rerun.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Literal

from ..contracts import ContractSchemaRegistry, canonical_json_bytes, seal_contract
from .ge_coverage_authorization import (
    GE_COVERAGE_BREADTH_POLICY_ID,
    GE_EXISTING_TOPIC_IDS,
    GE_PUBLIC_ACCESS_DOMAIN_IDS,
    GE_REQUIRED_COVERAGE_DOMAIN_IDS,
    VerifiedGECoverageAuthorization,
    ge_coverage_breadth_policy,
    ge_coverage_decision_binding,
    ge_required_domain_set_sha256,
    require_verified_ge_coverage_authorization,
)
from .ge_cycle_owner_authorization import (
    VerifiedGECycleOwnerAuthorization,
    build_verified_cycle_owner_acceptance,
    require_verified_cycle_owner_authorization,
)
from .ge_visible_harness import (
    FACTUAL_CHECKS,
    QUALITY_CRITICAL_FLOORS,
    QUALITY_DIMENSION_MAX,
    SYSTEM_SCENARIO_COUNT,
    VISIBLE_CASE_COUNT,
    VisibleGEPack,
    VisibleGESystemScenario,
    factual_gate_passes,
    quality_outcome,
    validate_case_result,
)

ROOT_CAUSE_LAYERS: tuple[str, ...] = (
    "source_currentness",
    "retrieval",
    "matter_facts",
    "prompt_code",
    "validation_renderer",
    "gold_rubric",
    "model_capability",
    "system_execution",
)

_ROOT_CAUSE_SET = frozenset(ROOT_CAUSE_LAYERS)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$")
_FAILURE_CLASSES = frozenset({"factual", "quality", "system"})
_MATERIALITIES = frozenset({"material", "potentially_material", "non_material"})
_DIAGNOSIS_STATES = frozenset({"open", "resolved"})
_PASSING_QUALITY = frozenset({"MEETS_70_STANDARD", "EXCEEDS_70_STANDARD"})
_TAXONOMY_SEPARATOR = re.compile(r"[^a-z0-9]+")
_EXECUTION_HASH_FIELDS: tuple[str, ...] = (
    "authorization_sha256",
    "candidate_sha256",
    "runtime_config_sha256",
    "gold_currentness_decision_sha256",
    "private_root_capability_sha256",
    "exposure_ledger_sha256",
    "model_sha256",
    "prompt_sha256",
    "renderer_sha256",
    "validator_bundle_sha256",
    "resource_policy_sha256",
    "contract_pack_sha256",
    "schema_selection_sha256",
    "scoring_policy_sha256",
    "factual_gate_policy_sha256",
    "quality_gate_policy_sha256",
)


class GEImprovementLoopError(ValueError):
    """A GE loop artifact or custody boundary is invalid."""


FailureClass = Literal["factual", "quality", "system"]
Materiality = Literal["material", "potentially_material", "non_material"]
DiagnosisState = Literal["open", "resolved"]


@dataclass(frozen=True, slots=True)
class GEDiagnosisInput:
    diagnosis_id: str
    case_id: str
    case_kind: Literal["visible", "system", "diagnostic"]
    failure_class: FailureClass
    scenario_family_id: str
    case_version_sha256: str
    materiality: Materiality
    finding_sha256: str
    status: DiagnosisState = "open"
    resolution_evidence_sha256: str | None = None
    knowledge_or_source_gap: bool = False
    subject: str | None = None
    jurisdiction: str | None = None
    as_of_date: date | None = None
    retrieval_query_sha256: str | None = None
    proposition_sha256: str | None = None
    retrieval_attempt_artifact_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class GEDiagnosticCaseDraft:
    diagnostic_case_id: str
    scenario_family_id: str
    prompt: str
    rationale: str
    primary_jurisdiction: str
    legal_currentness_cutoff: date
    question_version_sha256: str
    legal_currentness_review_sha256: str
    gold_review_sha256: str
    source_diagnosis_ids: tuple[str, ...]
    coverage_cell_id: str
    coverage_gap_fingerprint_sha256: str


@dataclass(frozen=True, slots=True)
class GECoverageCell:
    coverage_cell_id: str
    coverage_domain_id: str
    breadth_anchor: bool
    topic: str
    issue: str
    scenario_family_id: str
    urgency: Literal["routine", "time_sensitive", "urgent"]
    safety: Literal["ordinary", "safety_sensitive"]
    currentness: Literal["stable", "currentness_sensitive"]
    system_behaviour: Literal["answer", "system"]
    assigned_case_ids: tuple[str, ...]


def _taxonomy_token(value: Any) -> str:
    """Normalize owner-visible taxonomy text without semantic guessing."""

    return _TAXONOMY_SEPARATOR.sub("-", str(value or "").strip().casefold()).strip("-")


def _visible_coverage_profile(case: Any) -> Mapping[str, Any] | None:
    raw = case.raw
    dimensions = raw.get("proposed_dimensions")
    issue_tags = raw.get("issue_tags")
    if not isinstance(dimensions, Mapping) or not isinstance(issue_tags, list):
        return None
    urgency = {
        "none": "routine",
        "time_sensitive": "time_sensitive",
        "immediate": "urgent",
    }.get(str(dimensions.get("urgency") or ""))
    safety = {
        "ordinary": "ordinary",
        "emergency": "safety_sensitive",
        "refusal": "safety_sensitive",
    }.get(str(dimensions.get("safety") or ""))
    raw_currentness = str(dimensions.get("currentness") or "")
    temporal_status = str(raw.get("temporal_status") or "")
    currentness = (
        "stable"
        if raw_currentness == "fact_dependent"
        and temporal_status in {"IN_FORCE", "NOT_APPLICABLE"}
        else "currentness_sensitive"
    )
    if urgency is None or safety is None:
        return None
    return {
        "topic": _taxonomy_token(raw.get("topic_id")),
        "issues": frozenset(_taxonomy_token(value) for value in issue_tags),
        "scenario_family_id": str(case.scenario_family_id),
        "urgency": urgency,
        "safety": safety,
        "currentness": currentness,
        "system_behaviour": "answer",
    }


def _system_coverage_profile(scenario: VisibleGESystemScenario) -> Mapping[str, Any]:
    category = _taxonomy_token(scenario.category)
    return {
        "topic": category,
        "issues": frozenset({_taxonomy_token(scenario.raw.get("title"))}),
        "scenario_family_id": f"system:{category}",
        "urgency": (
            "urgent"
            if category == "safety-pair"
            else "time_sensitive" if category == "currentness" else "routine"
        ),
        "safety": "safety_sensitive" if category == "safety-pair" else "ordinary",
        "currentness": (
            "currentness_sensitive" if category == "currentness" else "stable"
        ),
        "system_behaviour": "system",
    }


def _profile_matches_cell(*, profile: Mapping[str, Any], cell: Mapping[str, Any]) -> bool:
    issues = profile.get("issues")
    return (
        isinstance(issues, frozenset)
        and _taxonomy_token(cell.get("topic")) == profile.get("topic")
        and _taxonomy_token(cell.get("issue")) in issues
        and cell.get("scenario_family_id") == profile.get("scenario_family_id")
        and cell.get("urgency") == profile.get("urgency")
        and cell.get("safety") == profile.get("safety")
        and cell.get("currentness") == profile.get("currentness")
        and cell.get("system_behaviour") == profile.get("system_behaviour")
    )


def _require_id(value: Any, *, label: str) -> str:
    result = str(value or "")
    if not _SAFE_ID.fullmatch(result):
        raise GEImprovementLoopError(f"{label} is invalid")
    return result


def _require_hash(value: Any, *, label: str) -> str:
    result = str(value or "")
    if not _HEX64.fullmatch(result):
        raise GEImprovementLoopError(f"{label} must be a lowercase SHA-256 digest")
    return result


def _require_timestamp(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise GEImprovementLoopError(f"{label} must be timezone-aware")
    return value


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise GEImprovementLoopError(f"{label} is not an ISO date-time") from exc
    return _require_timestamp(parsed, label=label)


def _require_self_sealed(value: Mapping[str, Any], *, label: str) -> None:
    claimed = _require_hash(value.get("content_sha256"), label=f"{label} content digest")
    material = dict(value)
    material.pop("content_sha256", None)
    actual = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    if actual != claimed:
        raise GEImprovementLoopError(f"{label} content digest differs")


def _object_sha256(value: Mapping[str, Any]) -> str:
    """Digest an externally selected object that is not self-sealed."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _validate_root_causes(
    values: Sequence[str], *, required: bool, label: str
) -> tuple[str, ...]:
    result = tuple(str(value) for value in values)
    if required and not result:
        raise GEImprovementLoopError(f"{label} requires a root-cause layer")
    if len(result) > 8 or len(result) != len(set(result)):
        raise GEImprovementLoopError(f"{label} root-cause layers are duplicated or excessive")
    unknown = set(result).difference(_ROOT_CAUSE_SET)
    if unknown:
        raise GEImprovementLoopError(f"{label} uses an unknown root-cause layer")
    return result


def _canonical_diagnosis_causes(values: Sequence[str]) -> tuple[str, ...]:
    """Treat diagnosis causes as a set so caller order cannot alter identity."""

    return tuple(sorted(_validate_root_causes(values, required=True, label="diagnosis")))


def _validate_failed_check_ids(values: Sequence[str]) -> tuple[str, ...]:
    identifiers = tuple(sorted(str(value) for value in values))
    if not identifiers:
        raise GEImprovementLoopError("diagnosis requires an actual failed check")
    if len(identifiers) != len(set(identifiers)):
        raise GEImprovementLoopError("diagnosis failed-check identities are duplicated")
    for identifier in identifiers:
        _require_id(identifier, label="diagnosis failed-check identity")
    return identifiers


def _system_check_id(*, kind: str, criterion: str) -> str:
    criterion_sha256 = hashlib.sha256(
        canonical_json_bytes({"criterion": criterion})
    ).hexdigest()
    return f"system:{kind}:{criterion_sha256}"


def _factual_check_map(result: Mapping[str, Any]) -> dict[str, str]:
    raw = result.get("factual_checks")
    if isinstance(raw, Mapping):
        checks = {str(name): str(value) for name, value in raw.items()}
    elif isinstance(raw, list):
        if not all(isinstance(row, Mapping) for row in raw):
            raise GEImprovementLoopError("diagnosed factual-check evidence is invalid")
        identities = [str(row.get("check_id") or "") for row in raw]
        if identities != list(FACTUAL_CHECKS):
            raise GEImprovementLoopError(
                "diagnosed factual-check order or identity differs"
            )
        checks = {
            str(row["check_id"]): str(row["outcome"])
            for row in raw
        }
    else:
        raise GEImprovementLoopError("diagnosed factual-check evidence is absent")
    if set(checks) != set(FACTUAL_CHECKS):
        raise GEImprovementLoopError("diagnosed factual-check set differs")
    return checks


def _quality_dimension_map(result: Mapping[str, Any]) -> dict[str, float]:
    raw = result.get("quality_dimensions")
    if isinstance(raw, Mapping):
        try:
            dimensions = {str(name): float(value) for name, value in raw.items()}
        except (TypeError, ValueError) as exc:
            raise GEImprovementLoopError(
                "diagnosed quality-dimension evidence is invalid"
            ) from exc
    elif isinstance(raw, list):
        if not all(isinstance(row, Mapping) for row in raw):
            raise GEImprovementLoopError(
                "diagnosed quality-dimension evidence is invalid"
            )
        try:
            dimensions = {
                str(row["dimension_id"]): float(row["score"])
                for row in raw
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise GEImprovementLoopError(
                "diagnosed quality-dimension evidence is invalid"
            ) from exc
    else:
        raise GEImprovementLoopError("diagnosed quality-dimension evidence is absent")
    expected_dimensions = tuple(QUALITY_DIMENSION_MAX)
    if set(dimensions) != set(expected_dimensions):
        raise GEImprovementLoopError("diagnosed quality-dimension set differs")
    if isinstance(raw, list) and [
        str(row.get("dimension_id") or "") for row in raw
    ] != list(expected_dimensions):
        raise GEImprovementLoopError(
            "diagnosed quality-dimension order or identity differs"
        )
    return dimensions


def _actual_failed_check_ids(
    *, failure_class: FailureClass, result: Mapping[str, Any]
) -> tuple[str, ...]:
    """Derive stable failure identities from the reviewed result, never caller prose."""

    if failure_class == "factual":
        checks = _factual_check_map(result)
        failed = [
            f"factual:{name}"
            for name in FACTUAL_CHECKS
            if checks.get(name) == "FAIL"
        ]
        if factual_gate_passes(checks) or result.get("factual_outcome") != "FACTUAL_HOLD" or not failed:
            raise GEImprovementLoopError(
                "diagnosis is not backed by an actual factual-check failure"
            )
        return _validate_failed_check_ids(failed)

    if failure_class == "quality":
        if (
            result.get("factual_outcome") != "FACTUAL_PASS"
            or result.get("quality_outcome") in _PASSING_QUALITY
        ):
            raise GEImprovementLoopError(
                "diagnosis is not backed by an actual quality-check failure"
            )
        score = result.get("quality_score")
        dimensions = _quality_dimension_map(result)
        if (
            not isinstance(score, int | float)
            or isinstance(score, bool)
        ):
            raise GEImprovementLoopError("diagnosed quality checks are invalid")
        expected_score, expected_outcome = quality_outcome(dimensions)
        if float(score) != expected_score or result.get("quality_outcome") != expected_outcome:
            raise GEImprovementLoopError(
                "diagnosed quality aggregate differs from its exact dimensions"
            )
        failed = []
        if float(score) < 70.0:
            failed.append("quality:overall_70_standard")
        for name, floor in QUALITY_CRITICAL_FLOORS.items():
            value = dimensions.get(name)
            if (
                not isinstance(value, int | float)
                or isinstance(value, bool)
            ):
                raise GEImprovementLoopError("diagnosed quality dimension is invalid")
            if float(value) < float(floor):
                failed.append(f"quality:critical_floor:{name}")
        if not failed:
            raise GEImprovementLoopError(
                "quality outcome has no reproducible failed threshold"
            )
        return _validate_failed_check_ids(failed)

    if failure_class == "system":
        outcome = result.get("outcome")
        if outcome == "SYSTEM_ERROR":
            return ("system:execution_error",)
        if outcome != "FAIL":
            raise GEImprovementLoopError(
                "diagnosis is not backed by an actual system-check failure"
            )
        expected_rows = result.get("expected_behaviour_checks")
        prohibited_rows = result.get("prohibited_behaviour_checks")
        if not isinstance(expected_rows, list) or not isinstance(prohibited_rows, list):
            raise GEImprovementLoopError("diagnosed system checks are invalid")
        failed = []
        for row in expected_rows:
            if not isinstance(row, Mapping) or type(row.get("met")) is not bool:
                raise GEImprovementLoopError("diagnosed expected-behaviour check is invalid")
            if row["met"] is False:
                failed.append(
                    _system_check_id(kind="expected", criterion=str(row.get("criterion") or ""))
                )
        for row in prohibited_rows:
            if not isinstance(row, Mapping) or type(row.get("observed")) is not bool:
                raise GEImprovementLoopError("diagnosed prohibited-behaviour check is invalid")
            if row["observed"] is True:
                failed.append(
                    _system_check_id(
                        kind="prohibited", criterion=str(row.get("criterion") or "")
                    )
                )
        return _validate_failed_check_ids(failed)

    raise GEImprovementLoopError("diagnosis failure class is invalid")


def _canonical_failure_code(
    *, failure_class: FailureClass, failed_check_ids: Sequence[str]
) -> str:
    failed = _validate_failed_check_ids(failed_check_ids)
    digest = hashlib.sha256(
        canonical_json_bytes({"failure_class": failure_class, "failed_check_ids": list(failed)})
    ).hexdigest()
    return f"{failure_class}:failed-check-set:{digest}"


def _failure_fingerprint_sha256(
    *,
    case_id: str,
    case_kind: str,
    case_version_sha256: str,
    scenario_family_id: str,
    failure_class: str,
    failed_check_ids: Sequence[str],
    root_cause_layers: Sequence[str],
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.ge-failure-fingerprint.v2",
                "case_id": case_id,
                "case_kind": case_kind,
                "case_version_sha256": case_version_sha256,
                "scenario_family_id": scenario_family_id,
                "failure_class": failure_class,
                "failed_check_ids": list(_validate_failed_check_ids(failed_check_ids)),
                "root_cause_layers": list(_canonical_diagnosis_causes(root_cause_layers)),
            }
        )
    ).hexdigest()


def _visible_execution_material(visible_run: Mapping[str, Any]) -> dict[str, str]:
    material: dict[str, str] = {}
    for name in _EXECUTION_HASH_FIELDS:
        material[name] = _require_hash(visible_run.get(name), label=name)
    return material


def _execution_identity_sha256(
    visible_run: Mapping[str, Any], *, repair_manifest_sha256: str
) -> str:
    material: dict[str, Any] = {
        "schema": "legalbot.ge-cycle-execution-identity.v1",
        **_visible_execution_material(visible_run),
        "repair_manifest_sha256": _require_hash(
            repair_manifest_sha256, label="repair manifest digest"
        ),
    }
    return hashlib.sha256(canonical_json_bytes(material)).hexdigest()


def _assert_fixed_visible_run(
    *,
    registry: ContractSchemaRegistry,
    pack: VisibleGEPack,
    visible_run: Mapping[str, Any],
    case_results: Sequence[Mapping[str, Any]],
) -> None:
    registry.validate_new(visible_run)
    if (
        visible_run.get("lane") != "visible_development"
        or visible_run.get("question_mode") != "general_enquiry"
        or visible_run.get("run_status") != "completed"
        or visible_run.get("run_validity") != "PASS"
        or visible_run.get("case_count") != VISIBLE_CASE_COUNT
        or visible_run.get("case_result_count") != VISIBLE_CASE_COUNT
        or visible_run.get("case_manifest_sha256") != pack.case_manifest_sha256
        or visible_run.get("case_order_sha256") != pack.case_order_sha256
        or visible_run.get("input_projection_sha256") != pack.input_projection_sha256
    ):
        raise GEImprovementLoopError("visible run is not the exact fixed 331-case pack")
    if len(case_results) != VISIBLE_CASE_COUNT:
        raise GEImprovementLoopError("visible result set is not exactly 331 cases")
    seen: set[str] = set()
    for case, result in zip(pack.cases, case_results, strict=True):
        validate_case_result(
            registry=registry,
            result=result,
            case=case,
            run_id=str(visible_run.get("run_id") or ""),
        )
        _require_self_sealed(result, label="visible case result")
        if (
            result.get("run_id") != visible_run.get("run_id")
            or result.get("case_id") != case.case_id
            or result.get("case_version_sha256") != case.record_sha256
            or result.get("scenario_family_id") != case.scenario_family_id
            or result.get("ordinal") != case.ordinal
        ):
            raise GEImprovementLoopError("visible result identity or order differs")
        result_id = _require_id(result.get("result_id"), label="visible result ID")
        if result_id in seen:
            raise GEImprovementLoopError("visible result identity is duplicated")
        seen.add(result_id)


def build_system_case_result(
    *,
    run_id: str,
    scenario: VisibleGESystemScenario,
    expected_behaviour_checks: Mapping[str, bool] | None,
    prohibited_behaviour_observed: Mapping[str, bool] | None,
    system_report_sha256: str,
    root_cause_layers: Sequence[str],
    started_at: datetime,
    completed_at: datetime,
    execution_error: bool = False,
) -> dict[str, Any]:
    """Seal one separate, unscored system-behaviour result."""

    _require_id(run_id, label="system run ID")
    started = _require_timestamp(started_at, label="system result start")
    completed = _require_timestamp(completed_at, label="system result completion")
    if completed < started:
        raise GEImprovementLoopError("system result completed before it started")
    report_sha256 = _require_hash(system_report_sha256, label="system report digest")
    expected = tuple(str(value) for value in scenario.raw["expected_behaviour"])
    prohibited = tuple(str(value) for value in scenario.raw["prohibited_behaviour"])
    if execution_error:
        if expected_behaviour_checks is not None or prohibited_behaviour_observed is not None:
            raise GEImprovementLoopError("system error cannot claim behaviour checks")
        causes = _validate_root_causes(
            root_cause_layers, required=True, label="system execution error"
        )
        if "system_execution" not in causes:
            raise GEImprovementLoopError("system execution error needs system_execution cause")
        outcome = "SYSTEM_ERROR"
        expected_rows: list[dict[str, Any]] = []
        prohibited_rows: list[dict[str, Any]] = []
    else:
        if expected_behaviour_checks is None or prohibited_behaviour_observed is None:
            raise GEImprovementLoopError("completed system result needs every behaviour check")
        if set(expected_behaviour_checks) != set(expected):
            raise GEImprovementLoopError("expected-behaviour check set differs")
        if set(prohibited_behaviour_observed) != set(prohibited):
            raise GEImprovementLoopError("prohibited-behaviour check set differs")
        if any(type(value) is not bool for value in expected_behaviour_checks.values()):
            raise GEImprovementLoopError("expected-behaviour results must be booleans")
        if any(type(value) is not bool for value in prohibited_behaviour_observed.values()):
            raise GEImprovementLoopError("prohibited-behaviour observations must be booleans")
        passed = all(expected_behaviour_checks.values()) and not any(
            prohibited_behaviour_observed.values()
        )
        causes = _validate_root_causes(
            root_cause_layers, required=not passed, label="system behaviour failure"
        )
        if passed and causes:
            raise GEImprovementLoopError("passing system result cannot claim a root cause")
        outcome = "PASS" if passed else "FAIL"
        expected_rows = [
            {"criterion": criterion, "met": expected_behaviour_checks[criterion]}
            for criterion in expected
        ]
        prohibited_rows = [
            {"criterion": criterion, "observed": prohibited_behaviour_observed[criterion]}
            for criterion in prohibited
        ]
    return seal_contract(
        {
            "schema": "legalbot.ge-system-case-result.v1",
            "result_id": f"system-result-{run_id}-{scenario.ordinal:02d}",
            "run_id": run_id,
            "system_case_id": scenario.case_id,
            "system_case_sha256": scenario.record_sha256,
            "ordinal": scenario.ordinal,
            "category": scenario.category,
            "outcome": outcome,
            "expected_behaviour_checks": expected_rows,
            "prohibited_behaviour_checks": prohibited_rows,
            "system_report_sha256": report_sha256,
            "root_cause_layers": list(causes),
            "scored_in_fixed_visible_denominator": False,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
        }
    )


def validate_system_case_result(
    *,
    result: Mapping[str, Any],
    scenario: VisibleGESystemScenario,
    run_id: str,
) -> None:
    """Replay one system result from its reviewed criterion values."""

    _require_self_sealed(result, label="system case result")
    expected_rows = result.get("expected_behaviour_checks")
    prohibited_rows = result.get("prohibited_behaviour_checks")
    causes_raw = result.get("root_cause_layers")
    if not isinstance(expected_rows, list) or not isinstance(prohibited_rows, list):
        raise GEImprovementLoopError("system behaviour checks are invalid")
    if not isinstance(causes_raw, list):
        raise GEImprovementLoopError("system result root causes are invalid")
    outcome = str(result.get("outcome") or "")
    if outcome == "SYSTEM_ERROR":
        expected: Mapping[str, bool] | None = None
        prohibited: Mapping[str, bool] | None = None
        execution_error = True
    else:
        try:
            expected = {
                str(row["criterion"]): bool(row["met"])
                for row in expected_rows
                if isinstance(row, Mapping) and type(row.get("met")) is bool
            }
            prohibited = {
                str(row["criterion"]): bool(row["observed"])
                for row in prohibited_rows
                if isinstance(row, Mapping) and type(row.get("observed")) is bool
            }
        except KeyError as exc:
            raise GEImprovementLoopError("system behaviour check fields are invalid") from exc
        if len(expected) != len(expected_rows) or len(prohibited) != len(prohibited_rows):
            raise GEImprovementLoopError("system behaviour check values are invalid")
        execution_error = False
    expected_result = build_system_case_result(
        run_id=run_id,
        scenario=scenario,
        expected_behaviour_checks=expected,
        prohibited_behaviour_observed=prohibited,
        system_report_sha256=str(result.get("system_report_sha256") or ""),
        root_cause_layers=tuple(str(value) for value in causes_raw),
        started_at=_parse_timestamp(result.get("started_at"), label="system result start"),
        completed_at=_parse_timestamp(
            result.get("completed_at"), label="system result completion"
        ),
        execution_error=execution_error,
    )
    if canonical_json_bytes(expected_result) != canonical_json_bytes(result):
        raise GEImprovementLoopError("system case result deterministic replay differs")


def build_completed_system_run(
    *,
    pack: VisibleGEPack,
    visible_run: Mapping[str, Any],
    repair_manifest_sha256: str,
    run_id: str,
    case_results: Sequence[Mapping[str, Any]],
    started_at: datetime,
    completed_at: datetime,
    candidate_state: Literal["NON_ACTIVE"] = "NON_ACTIVE",
) -> dict[str, Any]:
    """Reconcile all 32 system scenarios without changing the 331 denominator."""

    _require_id(run_id, label="system run ID")
    if candidate_state != "NON_ACTIVE":
        raise GEImprovementLoopError("GE successor/evaluation candidates must remain non-ACTIVE")
    started = _require_timestamp(started_at, label="system run start")
    completed = _require_timestamp(completed_at, label="system run completion")
    if completed < started:
        raise GEImprovementLoopError("system run completed before it started")
    if len(pack.system_scenarios) != SYSTEM_SCENARIO_COUNT or len(case_results) != SYSTEM_SCENARIO_COUNT:
        raise GEImprovementLoopError("completed system run must contain exactly 32 results")
    result_ids: set[str] = set()
    outcomes: Counter[str] = Counter()
    manifest: list[dict[str, Any]] = []
    for scenario, result in zip(pack.system_scenarios, case_results, strict=True):
        validate_system_case_result(result=result, scenario=scenario, run_id=run_id)
        if (
            result.get("schema") != "legalbot.ge-system-case-result.v1"
            or result.get("run_id") != run_id
            or result.get("system_case_id") != scenario.case_id
            or result.get("system_case_sha256") != scenario.record_sha256
            or result.get("ordinal") != scenario.ordinal
            or result.get("category") != scenario.category
            or result.get("scored_in_fixed_visible_denominator") is not False
        ):
            raise GEImprovementLoopError("system result identity or custody differs")
        result_id = _require_id(result.get("result_id"), label="system result ID")
        if result_id in result_ids:
            raise GEImprovementLoopError("system result identity is duplicated")
        result_ids.add(result_id)
        outcome = str(result.get("outcome") or "")
        if outcome not in {"PASS", "FAIL", "SYSTEM_ERROR"}:
            raise GEImprovementLoopError("system result outcome is invalid")
        outcomes[outcome] += 1
        manifest.append(
            {
                "ordinal": scenario.ordinal,
                "system_case_id": scenario.case_id,
                "result_id": result_id,
                "content_sha256": result["content_sha256"],
                "outcome": outcome,
            }
        )
    return seal_contract(
        {
            "schema": "legalbot.ge-system-run.v1",
            "run_id": run_id,
            "linked_visible_run_id": _require_id(
                visible_run.get("run_id"), label="visible run ID"
            ),
            "candidate_sha256": _require_hash(
                visible_run.get("candidate_sha256"), label="candidate digest"
            ),
            "fixed_visible_denominator": VISIBLE_CASE_COUNT,
            "system_case_count": SYSTEM_SCENARIO_COUNT,
            "system_cases_separate_from_visible_denominator": True,
            "system_manifest_sha256": pack.system_manifest_sha256,
            "system_order_sha256": pack.system_order_sha256,
            "result_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(manifest)
            ).hexdigest(),
            "result_count": SYSTEM_SCENARIO_COUNT,
            "counts": {
                "PASS": outcomes["PASS"],
                "FAIL": outcomes["FAIL"],
                "SYSTEM_ERROR": outcomes["SYSTEM_ERROR"],
            },
            "run_validity": "PASS" if outcomes["SYSTEM_ERROR"] == 0 else "FAIL",
            "visible_execution_identity_sha256": _execution_identity_sha256(
                visible_run, repair_manifest_sha256=repair_manifest_sha256
            ),
            "repair_manifest_sha256": _require_hash(
                repair_manifest_sha256, label="repair manifest digest"
            ),
            "candidate_state": candidate_state,
            "promotion_authorized": False,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
        }
    )


def _build_diagnosis_record(
    value: GEDiagnosisInput,
    *,
    result_sha256: str,
    failed_check_ids: Sequence[str],
    root_cause_layers: Sequence[str],
) -> dict[str, Any]:
    """Build the diagnosis record from result-derived, replayable material."""

    diagnosis_id = _require_id(value.diagnosis_id, label="diagnosis ID")
    case_id = _require_id(value.case_id, label="diagnosis case ID")
    if value.case_kind not in {"visible", "system", "diagnostic"}:
        raise GEImprovementLoopError("diagnosis case kind is invalid")
    if value.failure_class not in _FAILURE_CLASSES:
        raise GEImprovementLoopError("diagnosis failure class is invalid")
    failed_checks = _validate_failed_check_ids(failed_check_ids)
    failure_code = _canonical_failure_code(
        failure_class=value.failure_class, failed_check_ids=failed_checks
    )
    scenario_family_id = _require_id(
        value.scenario_family_id, label="diagnosis scenario family ID"
    )
    case_version_sha256 = _require_hash(
        value.case_version_sha256, label="diagnosed case-version digest"
    )
    if value.case_kind == "system" and value.failure_class != "system":
        raise GEImprovementLoopError("system cases require system failure classification")
    if value.failure_class == "system" and value.case_kind != "system":
        raise GEImprovementLoopError("system failure classification requires a system case")
    causes = _canonical_diagnosis_causes(root_cause_layers)
    if value.failure_class == "system" and "system_execution" not in causes:
        raise GEImprovementLoopError("system diagnosis needs system_execution cause")
    if value.materiality not in _MATERIALITIES:
        raise GEImprovementLoopError("diagnosis materiality is invalid")
    if value.status not in _DIAGNOSIS_STATES:
        raise GEImprovementLoopError("diagnosis status is invalid")
    finding_sha256 = _require_hash(value.finding_sha256, label="diagnosis finding digest")
    result_digest = _require_hash(result_sha256, label="diagnosed result digest")
    if value.status == "resolved":
        resolution_sha256 = _require_hash(
            value.resolution_evidence_sha256, label="diagnosis resolution digest"
        )
    elif value.resolution_evidence_sha256 is not None:
        raise GEImprovementLoopError("open diagnosis cannot claim resolution evidence")
    else:
        resolution_sha256 = None

    research_binding: dict[str, Any] | None = None
    research_values = (
        value.subject,
        value.jurisdiction,
        value.as_of_date,
        value.retrieval_query_sha256,
        value.proposition_sha256,
        value.retrieval_attempt_artifact_sha256,
    )
    if value.knowledge_or_source_gap:
        if not {"source_currentness", "retrieval"}.intersection(causes):
            raise GEImprovementLoopError(
                "knowledge/source gap must classify source_currentness or retrieval"
            )
        if any(item is None for item in research_values):
            raise GEImprovementLoopError(
                "knowledge/source gap lacks query, proposition, or retrieval-attempt evidence"
            )
        subject = str(value.subject or "").strip()
        jurisdiction = str(value.jurisdiction or "").strip()
        if not subject or not jurisdiction or len(subject) > 200 or len(jurisdiction) > 80:
            raise GEImprovementLoopError("knowledge/source gap research scope is invalid")
        research_binding = {
            "subject": subject,
            "jurisdiction": jurisdiction,
            "as_of_date": value.as_of_date.isoformat() if value.as_of_date else "",
            "retrieval_query_sha256": _require_hash(
                value.retrieval_query_sha256, label="retrieval query digest"
            ),
            "proposition_sha256": _require_hash(
                value.proposition_sha256, label="proposition digest"
            ),
            "retrieval_attempt_artifact_sha256": _require_hash(
                value.retrieval_attempt_artifact_sha256,
                label="retrieval-attempt artifact digest",
            ),
        }
    elif any(item is not None for item in research_values):
        raise GEImprovementLoopError("non-source diagnosis cannot carry research scope")

    failure_fingerprint_sha256 = _failure_fingerprint_sha256(
        case_id=case_id,
        case_kind=value.case_kind,
        case_version_sha256=case_version_sha256,
        scenario_family_id=scenario_family_id,
        failure_class=value.failure_class,
        failed_check_ids=failed_checks,
        root_cause_layers=causes,
    )

    return seal_contract(
        {
            "schema": "legalbot.ge-cycle-diagnosis.v1",
            "diagnosis_id": diagnosis_id,
            "case_id": case_id,
            "case_kind": value.case_kind,
            "failure_class": value.failure_class,
            "failure_code": failure_code,
            "failed_check_ids": list(failed_checks),
            "scenario_family_id": scenario_family_id,
            "case_version_sha256": case_version_sha256,
            "failure_fingerprint_sha256": failure_fingerprint_sha256,
            "root_cause_layers": list(causes),
            "materiality": value.materiality,
            "finding_sha256": finding_sha256,
            "result_sha256": result_digest,
            "status": value.status,
            "resolution_evidence_sha256": resolution_sha256,
            "knowledge_or_source_gap": value.knowledge_or_source_gap,
            "research_binding": research_binding,
        }
    )


def build_diagnosis(
    value: GEDiagnosisInput, *, diagnosed_result: Mapping[str, Any]
) -> dict[str, Any]:
    """Classify one failure from the exact reviewed result and canonical cause set."""

    _require_self_sealed(diagnosed_result, label="diagnosed result")
    expected_result_schema = {
        "visible": "legalbot.evaluation-case-result.v2",
        "system": "legalbot.ge-system-case-result.v1",
        "diagnostic": "legalbot.ge-diagnostic-case-result.v1",
    }.get(value.case_kind)
    if diagnosed_result.get("schema") != expected_result_schema:
        raise GEImprovementLoopError(
            "diagnosis requires the exact selected result schema; aggregate or legacy "
            "results are forbidden"
        )
    failed_check_ids = _actual_failed_check_ids(
        failure_class=value.failure_class, result=diagnosed_result
    )
    causes_raw = diagnosed_result.get("root_cause_layers")
    if not isinstance(causes_raw, list):
        raise GEImprovementLoopError("diagnosed result root causes are invalid")
    diagnosis = _build_diagnosis_record(
        value,
        result_sha256=_require_hash(
            diagnosed_result.get("content_sha256"), label="diagnosed result digest"
        ),
        failed_check_ids=failed_check_ids,
        root_cause_layers=tuple(str(value) for value in causes_raw),
    )
    _assert_diagnosis_matches_failure(diagnosis, diagnosed_result)
    return diagnosis


def validate_diagnosis(diagnosis: Mapping[str, Any]) -> None:
    """Replay one diagnosis, including its stable failure fingerprint."""

    _require_self_sealed(diagnosis, label="diagnosis")
    if diagnosis.get("schema") != "legalbot.ge-cycle-diagnosis.v1":
        raise GEImprovementLoopError("diagnosis schema differs")
    binding_raw = diagnosis.get("research_binding")
    binding = binding_raw if isinstance(binding_raw, Mapping) else None
    try:
        as_of = date.fromisoformat(str(binding["as_of_date"])) if binding else None
        causes_raw = diagnosis.get("root_cause_layers")
        failed_checks_raw = diagnosis.get("failed_check_ids")
        if not isinstance(causes_raw, list) or not isinstance(failed_checks_raw, list):
            raise TypeError
        expected = _build_diagnosis_record(
            GEDiagnosisInput(
                diagnosis_id=str(diagnosis["diagnosis_id"]),
                case_id=str(diagnosis["case_id"]),
                case_kind=str(diagnosis["case_kind"]),  # type: ignore[arg-type]
                failure_class=str(diagnosis["failure_class"]),  # type: ignore[arg-type]
                scenario_family_id=str(diagnosis["scenario_family_id"]),
                case_version_sha256=str(diagnosis["case_version_sha256"]),
                materiality=str(diagnosis["materiality"]),  # type: ignore[arg-type]
                finding_sha256=str(diagnosis["finding_sha256"]),
                status=str(diagnosis["status"]),  # type: ignore[arg-type]
                resolution_evidence_sha256=(
                    str(diagnosis["resolution_evidence_sha256"])
                    if diagnosis.get("resolution_evidence_sha256") is not None
                    else None
                ),
                knowledge_or_source_gap=diagnosis.get("knowledge_or_source_gap") is True,
                subject=str(binding["subject"]) if binding else None,
                jurisdiction=str(binding["jurisdiction"]) if binding else None,
                as_of_date=as_of,
                retrieval_query_sha256=(
                    str(binding["retrieval_query_sha256"]) if binding else None
                ),
                proposition_sha256=(
                    str(binding["proposition_sha256"]) if binding else None
                ),
                retrieval_attempt_artifact_sha256=(
                    str(binding["retrieval_attempt_artifact_sha256"])
                    if binding
                    else None
                ),
            ),
            result_sha256=str(diagnosis["result_sha256"]),
            failed_check_ids=tuple(str(value) for value in failed_checks_raw),
            root_cause_layers=tuple(str(value) for value in causes_raw),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GEImprovementLoopError("diagnosis fields are invalid") from exc
    if canonical_json_bytes(expected) != canonical_json_bytes(diagnosis):
        raise GEImprovementLoopError("diagnosis deterministic replay differs")


def _assert_diagnosis_matches_failure(
    diagnosis: Mapping[str, Any], result: Mapping[str, Any]
) -> None:
    _require_self_sealed(result, label="diagnosed result")
    if diagnosis.get("result_sha256") != result.get("content_sha256"):
        raise GEImprovementLoopError("diagnosis result evidence differs")
    case_kind = str(diagnosis.get("case_kind") or "")
    expected_result_schema = {
        "visible": "legalbot.evaluation-case-result.v2",
        "system": "legalbot.ge-system-case-result.v1",
        "diagnostic": "legalbot.ge-diagnostic-case-result.v1",
    }.get(case_kind)
    if result.get("schema") != expected_result_schema:
        raise GEImprovementLoopError(
            "diagnosed result schema is legacy, aggregate-only, or mismatched"
        )
    case_id_field = "system_case_id" if case_kind == "system" else (
        "diagnostic_case_id" if case_kind == "diagnostic" else "case_id"
    )
    if diagnosis.get("case_id") != result.get(case_id_field):
        raise GEImprovementLoopError("diagnosis case identity differs")
    case_version_field = {
        "visible": "case_version_sha256",
        "system": "system_case_sha256",
        "diagnostic": "diagnostic_case_sha256",
    }.get(case_kind)
    if (
        case_version_field is None
        or diagnosis.get("case_version_sha256") != result.get(case_version_field)
    ):
        raise GEImprovementLoopError("diagnosis case-version identity differs")
    failure_class = str(diagnosis.get("failure_class") or "")
    if failure_class not in _FAILURE_CLASSES:
        raise GEImprovementLoopError("diagnosis failure class is invalid")
    expected_failed_checks = _actual_failed_check_ids(
        failure_class=failure_class,  # type: ignore[arg-type]
        result=result,
    )
    failed_checks_raw = diagnosis.get("failed_check_ids")
    if not isinstance(failed_checks_raw, list):
        raise GEImprovementLoopError("diagnosis failed-check identities are invalid")
    failed_checks = _validate_failed_check_ids(
        tuple(str(value) for value in failed_checks_raw)
    )
    if failed_checks != expected_failed_checks:
        raise GEImprovementLoopError(
            "diagnosis failed-check identities differ from the reviewed result"
        )
    expected_failure_code = _canonical_failure_code(
        failure_class=failure_class,  # type: ignore[arg-type]
        failed_check_ids=expected_failed_checks,
    )
    if diagnosis.get("failure_code") != expected_failure_code:
        raise GEImprovementLoopError(
            "diagnosis failure code is not derived from the reviewed failed checks"
        )
    result_causes_raw = result.get("root_cause_layers")
    diagnosis_causes_raw = diagnosis.get("root_cause_layers")
    if not isinstance(result_causes_raw, list) or not isinstance(
        diagnosis_causes_raw, list
    ):
        raise GEImprovementLoopError("diagnosis root-cause evidence is invalid")
    if _canonical_diagnosis_causes(
        tuple(str(value) for value in diagnosis_causes_raw)
    ) != _canonical_diagnosis_causes(
        tuple(str(value) for value in result_causes_raw)
    ):
        raise GEImprovementLoopError(
            "diagnosis root-cause set differs from the reviewed result"
        )


def build_official_research_intent(
    *,
    diagnosis: Mapping[str, Any],
    diagnosed_result: Mapping[str, Any],
    candidate_build_id: str,
) -> dict[str, Any]:
    """Convert a proved source gap into a staging-only official-research intent."""

    validate_diagnosis(diagnosis)
    if (
        diagnosis.get("schema") != "legalbot.ge-cycle-diagnosis.v1"
        or diagnosis.get("knowledge_or_source_gap") is not True
        or diagnosis.get("status") != "open"
    ):
        raise GEImprovementLoopError("only an open knowledge/source diagnosis emits research")
    _assert_diagnosis_matches_failure(diagnosis, diagnosed_result)
    binding = diagnosis.get("research_binding")
    if not isinstance(binding, Mapping):
        raise GEImprovementLoopError("source diagnosis has no research binding")
    query_sha256 = _require_hash(binding.get("retrieval_query_sha256"), label="query digest")
    proposition_sha256 = _require_hash(
        binding.get("proposition_sha256"), label="proposition digest"
    )
    attempt_sha256 = _require_hash(
        binding.get("retrieval_attempt_artifact_sha256"),
        label="retrieval-attempt artifact digest",
    )
    build_id = _require_id(candidate_build_id, label="candidate build ID")
    diagnosis_id = _require_id(diagnosis.get("diagnosis_id"), label="diagnosis ID")
    return seal_contract(
        {
            "schema": "legalbot.ge-official-research-intent.v1",
            "intent_id": f"research-{diagnosis_id}",
            "task_type": "gap_research",
            "source_scope": "OFFICIAL_SOURCES_ONLY",
            "candidate_build_id": build_id,
            "case_id": _require_id(diagnosis.get("case_id"), label="case ID"),
            "issue_id": diagnosis_id,
            "subject": str(binding.get("subject") or ""),
            "jurisdiction": str(binding.get("jurisdiction") or ""),
            "as_of_date": str(binding.get("as_of_date") or ""),
            "retrieval_query_sha256": query_sha256,
            "proposition_sha256": proposition_sha256,
            "retrieval_attempt_artifact_sha256": attempt_sha256,
            "effect": "RESEARCH_CONTROL_PLANE_INTAKE_ONLY",
            "network_action_performed": False,
            "source_admission_authorized": False,
            "successor_candidate_state": "NON_ACTIVE",
            "promotion_authorized": False,
        }
    )


def _build_coverage_cell_rows(
    *, pack: VisibleGEPack, cells: Sequence[GECoverageCell]
) -> list[dict[str, Any]]:
    observed_topics = {str(case.raw.get("topic_id") or "") for case in pack.cases}
    if observed_topics != set(GE_EXISTING_TOPIC_IDS):
        raise GEImprovementLoopError(
            "fixed GE pack topic inventory differs from the breadth policy"
        )
    seen: set[str] = set()
    assigned_globally: set[str] = set()
    dimension_signatures: set[tuple[str, ...]] = set()
    breadth_anchors: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    for ordinal, cell in enumerate(cells, start=1):
        cell_id = _require_id(cell.coverage_cell_id, label="coverage cell ID")
        if cell_id in seen:
            raise GEImprovementLoopError("coverage cell identity is duplicated")
        seen.add(cell_id)
        domain_id = _require_id(
            cell.coverage_domain_id, label="coverage domain ID"
        )
        if domain_id not in GE_REQUIRED_COVERAGE_DOMAIN_IDS:
            raise GEImprovementLoopError(
                "coverage domain is renamed, aliased, or outside the breadth policy"
            )
        if type(cell.breadth_anchor) is not bool:
            raise GEImprovementLoopError("coverage breadth-anchor flag is invalid")
        if cell.breadth_anchor:
            breadth_anchors[domain_id] += 1
        topic = cell.topic.strip()
        issue = cell.issue.strip()
        if not topic or not issue:
            raise GEImprovementLoopError("coverage cell topic and issue are required")
        expected_topic = domain_id.split(":", 1)[1]
        if _taxonomy_token(topic) != expected_topic:
            raise GEImprovementLoopError(
                "coverage topic cannot alias a different required domain"
            )
        family_id = _require_id(cell.scenario_family_id, label="coverage family ID")
        if cell.urgency not in {"routine", "time_sensitive", "urgent"}:
            raise GEImprovementLoopError("coverage urgency is invalid")
        if cell.safety not in {"ordinary", "safety_sensitive"}:
            raise GEImprovementLoopError("coverage safety is invalid")
        if cell.currentness not in {"stable", "currentness_sensitive"}:
            raise GEImprovementLoopError("coverage currentness is invalid")
        if cell.system_behaviour not in {"answer", "system"}:
            raise GEImprovementLoopError("coverage behaviour lane is invalid")
        assigned = tuple(
            _require_id(case_id, label="assigned coverage case ID")
            for case_id in cell.assigned_case_ids
        )
        if len(assigned) != len(set(assigned)):
            raise GEImprovementLoopError("assigned coverage case identity is duplicated")
        if assigned_globally.intersection(assigned):
            raise GEImprovementLoopError(
                "one case cannot close more than one approved coverage cell"
            )
        assigned_globally.update(assigned)
        dimension_signature = (
            domain_id,
            _taxonomy_token(topic),
            _taxonomy_token(issue),
            family_id,
            cell.urgency,
            cell.safety,
            cell.currentness,
            cell.system_behaviour,
        )
        if dimension_signature in dimension_signatures:
            raise GEImprovementLoopError("coverage topology dimension is duplicated")
        dimension_signatures.add(dimension_signature)
        rows.append(
            seal_contract(
                {
                    "schema": "legalbot.ge-coverage-cell.v1",
                    "coverage_cell_id": cell_id,
                    "ordinal": ordinal,
                    "coverage_domain_id": domain_id,
                    "breadth_anchor": cell.breadth_anchor,
                    "topic": topic,
                    "issue": issue,
                    "scenario_family_id": family_id,
                    "urgency": cell.urgency,
                    "safety": cell.safety,
                    "currentness": cell.currentness,
                    "system_behaviour": cell.system_behaviour,
                    "assigned_case_ids": list(assigned),
                }
            )
        )
    missing_anchors = [
        domain_id
        for domain_id in GE_REQUIRED_COVERAGE_DOMAIN_IDS
        if breadth_anchors[domain_id] == 0
    ]
    duplicate_anchors = sorted(
        domain_id for domain_id, count in breadth_anchors.items() if count > 1
    )
    if missing_anchors:
        raise GEImprovementLoopError(
            f"coverage breadth floor omits required domains: {missing_anchors}"
        )
    if duplicate_anchors:
        raise GEImprovementLoopError(
            f"coverage breadth anchors duplicate required domains: {duplicate_anchors}"
        )
    return rows


def required_ge_coverage_cells(
    *,
    pack: VisibleGEPack,
    public_assignment_ids: Mapping[str, Sequence[str]] | None = None,
) -> tuple[GECoverageCell, ...]:
    """Build the fixed 17-topic plus six-public-domain breadth anchors."""

    public_assignments = public_assignment_ids or {}
    if set(public_assignments).difference(GE_PUBLIC_ACCESS_DOMAIN_IDS):
        raise GEImprovementLoopError("public coverage assignment domain is unknown")
    cells: list[GECoverageCell] = []
    for topic_id in GE_EXISTING_TOPIC_IDS:
        case = next(
            (row for row in pack.cases if row.raw.get("topic_id") == topic_id),
            None,
        )
        if case is None:
            raise GEImprovementLoopError(
                f"fixed GE pack lacks breadth-policy topic: {topic_id}"
            )
        profile = _visible_coverage_profile(case)
        issue_tags = case.raw.get("issue_tags")
        if profile is None or not isinstance(issue_tags, list) or not issue_tags:
            raise GEImprovementLoopError(
                f"fixed GE topic lacks a coverage profile: {topic_id}"
            )
        cells.append(
            GECoverageCell(
                coverage_cell_id=f"ge-coverage-topic-{topic_id}",
                coverage_domain_id=f"topic:{topic_id}",
                breadth_anchor=True,
                topic=topic_id,
                issue=str(issue_tags[0]),
                scenario_family_id=case.scenario_family_id,
                urgency=str(profile["urgency"]),  # type: ignore[arg-type]
                safety=str(profile["safety"]),  # type: ignore[arg-type]
                currentness=str(profile["currentness"]),  # type: ignore[arg-type]
                system_behaviour="answer",
                assigned_case_ids=(case.case_id,),
            )
        )
    for domain_id in GE_PUBLIC_ACCESS_DOMAIN_IDS:
        cells.append(
            GECoverageCell(
                coverage_cell_id=f"ge-coverage-public-{domain_id}",
                coverage_domain_id=f"public:{domain_id}",
                breadth_anchor=True,
                topic=domain_id,
                issue=f"dedicated-public-access-{domain_id}",
                scenario_family_id=f"ge-family-public-{domain_id}",
                urgency="routine",
                safety="ordinary",
                currentness="currentness_sensitive",
                system_behaviour="answer",
                assigned_case_ids=tuple(
                    str(value) for value in public_assignments.get(domain_id, ())
                ),
            )
        )
    return tuple(cells)


def build_coverage_topology_predecision(
    *,
    pack: VisibleGEPack,
    manifest_id: str,
    cells: Sequence[GECoverageCell],
    proposed_at: datetime,
) -> dict[str, Any]:
    """Seal an exact breadth-complete topology that still lacks owner authority."""

    resolved_manifest_id = _require_id(manifest_id, label="coverage manifest ID")
    rows = _build_coverage_cell_rows(pack=pack, cells=cells)
    policy = ge_coverage_breadth_policy()
    cell_manifest = [
        {
            "ordinal": row["ordinal"],
            "coverage_cell_id": row["coverage_cell_id"],
            "coverage_domain_id": row["coverage_domain_id"],
            "breadth_anchor": row["breadth_anchor"],
            "content_sha256": row["content_sha256"],
        }
        for row in rows
    ]
    cell_order = [
        {
            "ordinal": row["ordinal"],
            "coverage_cell_id": row["coverage_cell_id"],
            "coverage_domain_id": row["coverage_domain_id"],
        }
        for row in rows
    ]
    return seal_contract(
        {
            "schema": "legalbot.ge-coverage-topology-predecision.v1",
            "manifest_id": resolved_manifest_id,
            "authorization_state": "AWAITING_OWNER_ACCEPTANCE",
            "breadth_policy_id": GE_COVERAGE_BREADTH_POLICY_ID,
            "breadth_policy_sha256": policy["content_sha256"],
            "required_domain_ids": list(GE_REQUIRED_COVERAGE_DOMAIN_IDS),
            "required_domain_set_sha256": ge_required_domain_set_sha256(),
            "breadth_floor_satisfied": True,
            "cell_count": len(rows),
            "cell_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(cell_manifest)
            ).hexdigest(),
            "cell_order_sha256": hashlib.sha256(
                canonical_json_bytes(cell_order)
            ).hexdigest(),
            "topology_sha256": hashlib.sha256(
                canonical_json_bytes(
                    {
                        "schema": "legalbot.ge-coverage-topology.v1",
                        "breadth_policy_sha256": policy["content_sha256"],
                        "required_domain_set_sha256": ge_required_domain_set_sha256(),
                        "cells": rows,
                    }
                )
            ).hexdigest(),
            "cells": rows,
            "owner_decision_id": None,
            "owner_request_sha256": None,
            "owner_resolution_sha256": None,
            "unseen_inspected": False,
            "training_export_authorized": False,
            "proposed_at": _require_timestamp(
                proposed_at, label="coverage topology proposal time"
            ).isoformat(),
        }
    )


def build_coverage_cell_manifest(
    *,
    predecision: Mapping[str, Any],
    authorization: VerifiedGECoverageAuthorization,
) -> dict[str, Any]:
    """Project verifier-issued authority into the exact approved topology."""

    binding = ge_coverage_decision_binding(predecision)
    verified = require_verified_ge_coverage_authorization(
        authorization, predecision_sha256=binding.predecision_sha256
    )
    if verified.binding != binding:
        raise PermissionError(
            "OWNER_DECISION_REQUIRED:ge_coverage_authorization_binding_mismatch"
        )
    proposed_at = _parse_timestamp(
        predecision.get("proposed_at"), label="coverage topology proposal time"
    )
    if verified.decided_at < proposed_at:
        raise GEImprovementLoopError("coverage decision predates its exact topology")
    return seal_contract(
        {
            "schema": "legalbot.ge-coverage-cell-manifest.v2",
            "manifest_id": binding.manifest_id,
            "coverage_predecision_sha256": binding.predecision_sha256,
            "coverage_predecision": dict(predecision),
            "breadth_policy_id": binding.breadth_policy_id,
            "breadth_policy_sha256": binding.breadth_policy_sha256,
            "required_domain_ids": list(GE_REQUIRED_COVERAGE_DOMAIN_IDS),
            "required_domain_set_sha256": binding.required_domain_set_sha256,
            "cell_manifest_sha256": binding.cell_manifest_sha256,
            "cell_order_sha256": binding.cell_order_sha256,
            "topology_sha256": binding.topology_sha256,
            "owner_decision_id": verified.decision_id,
            "owner_request_sha256": verified.request_content_sha256,
            "owner_resolution_sha256": verified.resolution_content_sha256,
            "owner_approval_sha256": verified.resolution_content_sha256,
            "cell_count": binding.cell_count,
            "cells": list(predecision["cells"]),
            "approved_at": verified.decided_at.isoformat(),
            "unseen_eligible": False,
            "training_export_eligible": False,
        }
    )


def validate_coverage_cell_manifest(
    *,
    coverage_manifest: Mapping[str, Any],
    authorization: VerifiedGECoverageAuthorization | None,
) -> None:
    _require_self_sealed(coverage_manifest, label="coverage manifest")
    predecision = coverage_manifest.get("coverage_predecision")
    if (
        coverage_manifest.get("schema") != "legalbot.ge-coverage-cell-manifest.v2"
        or not isinstance(predecision, Mapping)
    ):
        raise GEImprovementLoopError("coverage manifest schema or predecision differs")
    verified = require_verified_ge_coverage_authorization(
        authorization,
        predecision_sha256=_require_hash(
            coverage_manifest.get("coverage_predecision_sha256"),
            label="coverage predecision digest",
        ),
    )
    expected = build_coverage_cell_manifest(
        predecision=predecision, authorization=verified
    )
    if canonical_json_bytes(expected) != canonical_json_bytes(coverage_manifest):
        raise GEImprovementLoopError(
            "coverage manifest differs from verifier-issued exact topology"
        )


def build_coverage_audit(
    *,
    pack: VisibleGEPack,
    coverage_manifest: Mapping[str, Any],
    coverage_authorization: VerifiedGECoverageAuthorization,
    existing_diagnostic_pack: Mapping[str, Any] | None,
    audited_at: datetime,
    unseen_opened: bool = False,
) -> dict[str, Any]:
    """Compare approved coverage cells with visible 331, system 32, and diagnostics."""

    if unseen_opened:
        raise GEImprovementLoopError("coverage audit cannot inspect or depend on unseen cases")
    validate_coverage_cell_manifest(
        coverage_manifest=coverage_manifest,
        authorization=coverage_authorization,
    )
    raw_cells = coverage_manifest.get("cells")
    if not isinstance(raw_cells, list) or len(raw_cells) != coverage_manifest.get("cell_count"):
        raise GEImprovementLoopError("coverage manifest cell count differs")
    universe = {case.case_id for case in pack.cases}
    universe.update(scenario.case_id for scenario in pack.system_scenarios)
    visible_profiles = {
        case.case_id: _visible_coverage_profile(case) for case in pack.cases
    }
    system_profiles = {
        scenario.case_id: _system_coverage_profile(scenario)
        for scenario in pack.system_scenarios
    }
    diagnostic_cases: dict[str, Mapping[str, Any]] = {}
    diagnostic_pack_sha256: str | None = None
    if existing_diagnostic_pack is not None:
        diagnostic_pack_sha256, diagnostic_ids = _validate_supplement(
            pack=pack, supplement=existing_diagnostic_pack
        )
        universe.update(diagnostic_ids)
        raw_diagnostic_cases = existing_diagnostic_pack.get("cases")
        if not isinstance(raw_diagnostic_cases, list):
            raise GEImprovementLoopError("diagnostic coverage cases are invalid")
        diagnostic_cases = {
            str(row["diagnostic_case_id"]): row
            for row in raw_diagnostic_cases
            if isinstance(row, Mapping)
        }
    rows: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for cell in raw_cells:
        if not isinstance(cell, Mapping):
            raise GEImprovementLoopError("coverage cell is not an object")
        _require_self_sealed(cell, label="coverage cell")
        assigned_raw = cell.get("assigned_case_ids")
        if not isinstance(assigned_raw, list):
            raise GEImprovementLoopError("coverage cell assignments are invalid")
        assigned = [str(case_id) for case_id in assigned_raw]
        gap_fingerprint = hashlib.sha256(
            canonical_json_bytes(
                {
                    "schema": "legalbot.ge-coverage-gap-fingerprint.v1",
                    "coverage_manifest_sha256": coverage_manifest["content_sha256"],
                    "coverage_cell_id": cell["coverage_cell_id"],
                    "coverage_cell_sha256": cell["content_sha256"],
                }
            )
        ).hexdigest()
        diagnostic_for_cell = sorted(
            case_id
            for case_id, diagnostic_case in diagnostic_cases.items()
            if diagnostic_case.get("coverage_cell_id") == cell.get("coverage_cell_id")
        )
        covered: list[str] = []
        for case_id in [*assigned, *diagnostic_for_cell]:
            if case_id not in universe:
                continue
            profile = visible_profiles.get(case_id) or system_profiles.get(case_id)
            if profile is not None and _profile_matches_cell(profile=profile, cell=cell):
                covered.append(case_id)
                continue
            diagnostic_case = diagnostic_cases.get(case_id)
            if (
                diagnostic_case is not None
                and cell.get("system_behaviour") == "answer"
                and diagnostic_case.get("coverage_cell_id") == cell.get("coverage_cell_id")
                and diagnostic_case.get("coverage_gap_fingerprint_sha256") == gap_fingerprint
                and diagnostic_case.get("scenario_family_id")
                == cell.get("scenario_family_id")
            ):
                covered.append(case_id)
        covered = sorted(set(covered))
        missing_cell = not covered
        rows.append(
            {
                "coverage_cell_id": cell["coverage_cell_id"],
                "coverage_domain_id": cell["coverage_domain_id"],
                "coverage_cell_sha256": cell["content_sha256"],
                "covered_case_ids": covered,
                "assigned_case_ids": assigned,
                "missing": missing_cell,
                "gap_fingerprint_sha256": gap_fingerprint if missing_cell else None,
            }
        )
        if missing_cell:
            missing.append(
                {
                    "coverage_cell_id": str(cell["coverage_cell_id"]),
                    "coverage_domain_id": str(cell["coverage_domain_id"]),
                    "gap_fingerprint_sha256": gap_fingerprint,
                    "assigned_case_ids": assigned,
                }
            )
    return seal_contract(
        {
            "schema": "legalbot.ge-coverage-audit.v2",
            "coverage_manifest_sha256": coverage_manifest["content_sha256"],
            "coverage_predecision_sha256": coverage_manifest[
                "coverage_predecision_sha256"
            ],
            "breadth_policy_id": coverage_manifest["breadth_policy_id"],
            "breadth_policy_sha256": coverage_manifest["breadth_policy_sha256"],
            "required_domain_set_sha256": coverage_manifest[
                "required_domain_set_sha256"
            ],
            "cell_manifest_sha256": coverage_manifest["cell_manifest_sha256"],
            "cell_order_sha256": coverage_manifest["cell_order_sha256"],
            "topology_sha256": coverage_manifest["topology_sha256"],
            "owner_decision_id": coverage_manifest["owner_decision_id"],
            "owner_request_sha256": coverage_manifest["owner_request_sha256"],
            "owner_resolution_sha256": coverage_manifest[
                "owner_resolution_sha256"
            ],
            # Carry the approved topology so a later cycle can replay this
            # audit without trusting an unbound side file.
            "coverage_manifest": dict(coverage_manifest),
            "fixed_pack_manifest_sha256": pack.pack_manifest_sha256,
            "visible_case_count_reviewed": VISIBLE_CASE_COUNT,
            "system_case_count_reviewed": SYSTEM_SCENARIO_COUNT,
            "diagnostic_pack_sha256": diagnostic_pack_sha256,
            "unseen_inspected": False,
            "cell_results": rows,
            "missing_cell_count": len(missing),
            "missing_cells": missing,
            "audited_at": _require_timestamp(
                audited_at, label="coverage audit time"
            ).isoformat(),
        }
    )


def build_visible_diagnostic_supplement(
    *,
    pack: VisibleGEPack,
    pack_id: str,
    linked_cycle_id: str,
    visible_run: Mapping[str, Any],
    repair_manifest_sha256: str,
    coverage_audit: Mapping[str, Any],
    cases: Sequence[GEDiagnosticCaseDraft],
    source_diagnoses: Sequence[Mapping[str, Any]],
    created_at: datetime,
) -> dict[str, Any]:
    """Seal new visible diagnostic questions outside the fixed 331 denominator."""

    _require_id(pack_id, label="diagnostic pack ID")
    _require_id(linked_cycle_id, label="linked cycle ID")
    _require_self_sealed(coverage_audit, label="coverage audit")
    if (
        coverage_audit.get("schema") != "legalbot.ge-coverage-audit.v2"
        or coverage_audit.get("fixed_pack_manifest_sha256") != pack.pack_manifest_sha256
        or coverage_audit.get("unseen_inspected") is not False
    ):
        raise GEImprovementLoopError("diagnostic pack coverage audit differs")
    missing_raw = coverage_audit.get("missing_cells")
    if not isinstance(missing_raw, list):
        raise GEImprovementLoopError("coverage audit missing-cell set is invalid")
    manifest_raw = coverage_audit.get("coverage_manifest")
    manifest_cells_raw = (
        manifest_raw.get("cells") if isinstance(manifest_raw, Mapping) else None
    )
    if not isinstance(manifest_cells_raw, list):
        raise GEImprovementLoopError("coverage audit approved topology is unavailable")
    manifest_cells = {
        str(row["coverage_cell_id"]): row
        for row in manifest_cells_raw
        if isinstance(row, Mapping)
    }
    missing = {
        str(row["coverage_cell_id"]): (
            str(row["gap_fingerprint_sha256"]),
            tuple(str(value) for value in row.get("assigned_case_ids", [])),
            manifest_cells.get(str(row["coverage_cell_id"])),
        )
        for row in missing_raw
        if isinstance(row, Mapping)
    }
    created = _require_timestamp(created_at, label="diagnostic supplement creation")
    audit_time = _parse_timestamp(
        coverage_audit.get("audited_at"), label="diagnostic coverage audit time"
    )
    visible_completed = _parse_timestamp(
        visible_run.get("completed_at"), label="diagnostic source visible-run completion"
    )
    if created < audit_time or created < visible_completed:
        raise GEImprovementLoopError(
            "diagnostic supplement predates its coverage audit or source visible run"
        )
    source_run_id = _require_id(
        visible_run.get("run_id"), label="diagnostic source visible-run ID"
    )
    source_run_sha256 = _object_sha256(visible_run)
    source_candidate_sha256 = _require_hash(
        visible_run.get("candidate_sha256"), label="diagnostic source candidate digest"
    )
    source_repair_sha256 = _require_hash(
        repair_manifest_sha256, label="diagnostic source repair-manifest digest"
    )
    source_execution_sha256 = _execution_identity_sha256(
        visible_run, repair_manifest_sha256=source_repair_sha256
    )
    source_diagnosis_by_id: dict[str, Mapping[str, Any]] = {}
    for diagnosis in source_diagnoses:
        validate_diagnosis(diagnosis)
        diagnosis_id = _require_id(
            diagnosis.get("diagnosis_id"), label="source diagnosis ID"
        )
        if diagnosis_id in source_diagnosis_by_id:
            raise GEImprovementLoopError("diagnostic source identity is duplicated")
        source_diagnosis_by_id[diagnosis_id] = diagnosis
    fixed_ids = {case.case_id for case in pack.cases}
    fixed_ids.update(scenario.case_id for scenario in pack.system_scenarios)
    seen: set[str] = set()
    prompt_fingerprints: set[str] = set()
    referenced_diagnosis_ids: set[str] = set()
    rows: list[dict[str, Any]] = []
    for ordinal, draft in enumerate(cases, start=1):
        case_id = _require_id(draft.diagnostic_case_id, label="diagnostic case ID")
        family_id = _require_id(draft.scenario_family_id, label="scenario family ID")
        if case_id in fixed_ids or case_id in seen:
            raise GEImprovementLoopError("diagnostic case identity collides or is duplicated")
        seen.add(case_id)
        prompt = draft.prompt.strip()
        rationale = draft.rationale.strip()
        jurisdiction = draft.primary_jurisdiction.strip()
        if not prompt or not rationale or not jurisdiction:
            raise GEImprovementLoopError("diagnostic case text and jurisdiction are required")
        prompt_fingerprint = hashlib.sha256(
            canonical_json_bytes(
                {
                    "prompt": " ".join(prompt.casefold().split()),
                    "rationale": " ".join(rationale.casefold().split()),
                }
            )
        ).hexdigest()
        if prompt_fingerprint in prompt_fingerprints:
            raise GEImprovementLoopError(
                "one diagnostic question cannot close more than one coverage cell"
            )
        prompt_fingerprints.add(prompt_fingerprint)
        diagnosis_ids = tuple(
            _require_id(value, label="source diagnosis ID")
            for value in draft.source_diagnosis_ids
        )
        if len(diagnosis_ids) != len(set(diagnosis_ids)):
            raise GEImprovementLoopError("diagnostic source identity is duplicated")
        diagnosis_manifest: list[dict[str, str]] = []
        for diagnosis_id in diagnosis_ids:
            source_diagnosis = source_diagnosis_by_id.get(diagnosis_id)
            if source_diagnosis is None:
                raise GEImprovementLoopError(
                    "diagnostic source diagnosis is outside the supplied cycle evidence"
                )
            if source_diagnosis.get("scenario_family_id") != family_id:
                raise GEImprovementLoopError(
                    "diagnostic source diagnosis scenario family differs"
                )
            referenced_diagnosis_ids.add(diagnosis_id)
            diagnosis_manifest.append(
                {
                    "diagnosis_id": diagnosis_id,
                    "case_id": str(source_diagnosis["case_id"]),
                    "failure_fingerprint_sha256": str(
                        source_diagnosis["failure_fingerprint_sha256"]
                    ),
                    "content_sha256": str(source_diagnosis["content_sha256"]),
                }
            )
        coverage_cell_id = _require_id(
            draft.coverage_cell_id, label="diagnostic coverage cell ID"
        )
        gap_fingerprint = _require_hash(
            draft.coverage_gap_fingerprint_sha256,
            label="diagnostic coverage-gap fingerprint",
        )
        missing_binding = missing.get(coverage_cell_id)
        bound_cell = missing_binding[2] if missing_binding is not None else None
        if (
            missing_binding is None
            or missing_binding[0] != gap_fingerprint
            or (missing_binding[1] and case_id not in missing_binding[1])
            or not isinstance(bound_cell, Mapping)
            or bound_cell.get("scenario_family_id") != family_id
            or bound_cell.get("system_behaviour") != "answer"
        ):
            raise GEImprovementLoopError(
                "diagnostic draft must bind exactly one audited missing coverage cell"
            )
        question_version_sha256 = _require_hash(
            draft.question_version_sha256,
            label="diagnostic question-version digest",
        )
        legal_currentness_review_sha256 = _require_hash(
            draft.legal_currentness_review_sha256,
            label="diagnostic legal-currentness review digest",
        )
        gold_review_sha256 = _require_hash(
            draft.gold_review_sha256, label="diagnostic gold-review digest"
        )
        prompt_only_projection = seal_contract(
            {
                "schema": "legalbot.ge-diagnostic-prompt-projection.v1",
                "diagnostic_case_id": case_id,
                "question_type": "GENERAL_ENQUIRY",
                "prompt": prompt,
                "primary_jurisdiction": jurisdiction,
                "legal_currentness_cutoff": (
                    draft.legal_currentness_cutoff.isoformat()
                ),
                "question_version_sha256": question_version_sha256,
                "contains_rationale": False,
                "contains_gold": False,
                "contains_diagnosis": False,
                "unseen_content": False,
            }
        )
        case_material: dict[str, Any] = {
            "schema": "legalbot.ge-visible-diagnostic-case.v1",
            "diagnostic_case_id": case_id,
            "ordinal": ordinal,
            "scenario_family_id": family_id,
            "question_type": "GENERAL_ENQUIRY",
            "prompt": prompt,
            "rationale": rationale,
            "primary_jurisdiction": jurisdiction,
            "legal_currentness_cutoff": draft.legal_currentness_cutoff.isoformat(),
            "question_version_sha256": question_version_sha256,
            "prompt_only_projection": prompt_only_projection,
            "prompt_only_projection_sha256": prompt_only_projection["content_sha256"],
            "legal_currentness_review_sha256": legal_currentness_review_sha256,
            "gold_review_sha256": gold_review_sha256,
            "diagnostic_provenance_kind": (
                "DIAGNOSIS_DERIVED" if diagnosis_ids else "COVERAGE_ONLY"
            ),
            "source_diagnosis_ids": list(diagnosis_ids),
            "source_diagnosis_manifest": diagnosis_manifest,
            "source_diagnosis_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(diagnosis_manifest)
            ).hexdigest(),
            "coverage_cell_id": coverage_cell_id,
            "coverage_gap_fingerprint_sha256": gap_fingerprint,
            "usage_role": "VISIBLE_DIAGNOSTIC_SUPPLEMENT_ONLY",
            "joins_fixed_visible_denominator": False,
            "permanently_ineligible_for_unseen_validation": True,
            "unseen_eligible": False,
            "permanently_ineligible_for_training": True,
            "training_export_eligible": False,
            "user_content": False,
        }
        rows.append(seal_contract(case_material))
    if referenced_diagnosis_ids != set(source_diagnosis_by_id):
        raise GEImprovementLoopError(
            "supplied source diagnoses do not exactly match diagnostic references"
        )
    case_manifest = [
        {
            "ordinal": row["ordinal"],
            "diagnostic_case_id": row["diagnostic_case_id"],
            "content_sha256": row["content_sha256"],
        }
        for row in rows
    ]
    covered_gap_cells = [str(row["coverage_cell_id"]) for row in rows]
    if len(covered_gap_cells) != len(set(covered_gap_cells)):
        raise GEImprovementLoopError(
            "one coverage cell cannot be closed by duplicate diagnostic questions"
        )
    if set(covered_gap_cells) != set(missing):
        raise GEImprovementLoopError(
            "diagnostic pack must cover every audited missing coverage cell"
        )
    coverage_gap_manifest = [
        {
            "coverage_cell_id": cell_id,
            "gap_fingerprint_sha256": binding[0],
        }
        for cell_id, binding in sorted(missing.items())
    ]
    source_diagnosis_manifest = [
        {
            "diagnosis_id": diagnosis_id,
            "content_sha256": str(source_diagnosis_by_id[diagnosis_id]["content_sha256"]),
        }
        for diagnosis_id in sorted(source_diagnosis_by_id)
    ]
    return seal_contract(
        {
            "schema": "legalbot.ge-visible-diagnostic-supplement.v1",
            "pack_id": pack_id,
            "linked_cycle_id": linked_cycle_id,
            "source_visible_run_id": source_run_id,
            "source_visible_run_sha256": source_run_sha256,
            "source_execution_identity_sha256": source_execution_sha256,
            "source_candidate_sha256": source_candidate_sha256,
            "source_repair_manifest_sha256": source_repair_sha256,
            "fixed_pack_manifest_sha256": pack.pack_manifest_sha256,
            "fixed_case_manifest_sha256": pack.case_manifest_sha256,
            "fixed_case_order_sha256": pack.case_order_sha256,
            "fixed_visible_denominator": VISIBLE_CASE_COUNT,
            "system_case_count_separate": SYSTEM_SCENARIO_COUNT,
            "coverage_audit_sha256": coverage_audit["content_sha256"],
            "coverage_gap_count": len(coverage_gap_manifest),
            "coverage_gap_manifest": coverage_gap_manifest,
            "coverage_gap_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(coverage_gap_manifest)
            ).hexdigest(),
            "source_diagnosis_count": len(source_diagnosis_manifest),
            "source_diagnosis_manifest": source_diagnosis_manifest,
            "source_diagnosis_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(source_diagnosis_manifest)
            ).hexdigest(),
            "case_count": len(rows),
            "case_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(case_manifest)
            ).hexdigest(),
            "joins_fixed_visible_denominator": False,
            "unseen_eligible": False,
            "training_export_eligible": False,
            "cases": rows,
            "created_at": created.isoformat(),
        }
    )


def build_diagnostic_case_result(
    *,
    diagnostic_pack: Mapping[str, Any],
    diagnostic_case: Mapping[str, Any],
    factual_checks: Mapping[str, str],
    factual_report_sha256: str,
    quality_scores: Mapping[str, float] | None,
    quality_report_sha256: str | None,
    root_cause_layers: Sequence[str],
    relevant_change_at: datetime,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, Any]:
    """Seal one factual-first diagnostic result outside every fixed denominator."""

    _require_self_sealed(diagnostic_pack, label="diagnostic pack")
    _require_self_sealed(diagnostic_case, label="diagnostic case")
    raw_cases = diagnostic_pack.get("cases")
    if not isinstance(raw_cases, list) or not any(
        isinstance(row, Mapping)
        and row.get("content_sha256") == diagnostic_case.get("content_sha256")
        for row in raw_cases
    ):
        raise GEImprovementLoopError("diagnostic case is not a member of the pack")
    if (
        diagnostic_case.get("joins_fixed_visible_denominator") is not False
        or diagnostic_case.get("permanently_ineligible_for_unseen_validation") is not True
        or diagnostic_case.get("permanently_ineligible_for_training") is not True
    ):
        raise GEImprovementLoopError("diagnostic case custody differs")
    started = _require_timestamp(started_at, label="diagnostic result start")
    completed = _require_timestamp(completed_at, label="diagnostic result completion")
    if completed < started:
        raise GEImprovementLoopError("diagnostic result completed before it started")
    pack_created = _parse_timestamp(
        diagnostic_pack.get("created_at"), label="diagnostic pack creation"
    )
    supplied_change = _require_timestamp(
        relevant_change_at, label="diagnostic relevant change time"
    )
    effective_change = max(pack_created, supplied_change)
    if started <= effective_change:
        raise GEImprovementLoopError(
            "diagnostic result did not start after its diagnostic question change"
        )
    factual_pass = factual_gate_passes(factual_checks)
    if factual_pass:
        if quality_scores is None or quality_report_sha256 is None:
            raise GEImprovementLoopError("passing diagnostic needs quality review")
        score, quality = quality_outcome(quality_scores)
        factual = "FACTUAL_PASS"
    else:
        if quality_scores is not None or quality_report_sha256 is not None:
            raise GEImprovementLoopError("held diagnostic cannot receive quality scoring")
        score = None
        quality = "NOT_ELIGIBLE"
        factual = "FACTUAL_HOLD"
    causes = _validate_root_causes(
        root_cause_layers,
        required=(not factual_pass or quality not in _PASSING_QUALITY),
        label="diagnostic result",
    )
    if factual_pass and quality in _PASSING_QUALITY and causes:
        raise GEImprovementLoopError("passing diagnostic cannot claim a root cause")
    return seal_contract(
        {
            "schema": "legalbot.ge-diagnostic-case-result.v1",
            "result_id": (
                f"diagnostic-result-{diagnostic_pack['pack_id']}-"
                f"{int(diagnostic_case['ordinal']):03d}"
            ),
            "diagnostic_pack_id": diagnostic_pack["pack_id"],
            "diagnostic_case_id": diagnostic_case["diagnostic_case_id"],
            "diagnostic_case_sha256": diagnostic_case["content_sha256"],
            "ordinal": diagnostic_case["ordinal"],
            "source_visible_run_id": _require_id(
                diagnostic_pack.get("source_visible_run_id"),
                label="diagnostic source visible-run ID",
            ),
            "source_visible_run_sha256": _require_hash(
                diagnostic_pack.get("source_visible_run_sha256"),
                label="diagnostic source visible-run digest",
            ),
            "source_execution_identity_sha256": _require_hash(
                diagnostic_pack.get("source_execution_identity_sha256"),
                label="diagnostic source execution-identity digest",
            ),
            "source_candidate_sha256": _require_hash(
                diagnostic_pack.get("source_candidate_sha256"),
                label="diagnostic source candidate digest",
            ),
            "source_repair_manifest_sha256": _require_hash(
                diagnostic_pack.get("source_repair_manifest_sha256"),
                label="diagnostic source repair-manifest digest",
            ),
            "question_version_sha256": _require_hash(
                diagnostic_case.get("question_version_sha256"),
                label="diagnostic question-version digest",
            ),
            "prompt_only_projection_sha256": _require_hash(
                diagnostic_case.get("prompt_only_projection_sha256"),
                label="diagnostic prompt-only projection digest",
            ),
            "legal_currentness_review_sha256": _require_hash(
                diagnostic_case.get("legal_currentness_review_sha256"),
                label="diagnostic legal-currentness review digest",
            ),
            "gold_review_sha256": _require_hash(
                diagnostic_case.get("gold_review_sha256"),
                label="diagnostic gold-review digest",
            ),
            "diagnostic_provenance_kind": diagnostic_case.get(
                "diagnostic_provenance_kind"
            ),
            "source_diagnosis_ids": list(
                diagnostic_case.get("source_diagnosis_ids", [])
            ),
            "source_diagnosis_manifest_sha256": _require_hash(
                diagnostic_case.get("source_diagnosis_manifest_sha256"),
                label="diagnostic source-diagnosis manifest digest",
            ),
            "relevant_change_at": effective_change.isoformat(),
            "factual_checks": dict(factual_checks),
            "factual_report_sha256": _require_hash(
                factual_report_sha256, label="diagnostic factual report digest"
            ),
            "factual_outcome": factual,
            "quality_dimensions": dict(quality_scores) if quality_scores is not None else None,
            "quality_report_sha256": (
                _require_hash(quality_report_sha256, label="diagnostic quality report digest")
                if quality_report_sha256 is not None
                else None
            ),
            "quality_score": score,
            "quality_outcome": quality,
            "root_cause_layers": list(causes),
            "scored_in_fixed_visible_denominator": False,
            "scored_in_system_denominator": False,
            "unseen_eligible": False,
            "training_export_eligible": False,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
        }
    )


def validate_diagnostic_case_result(
    *,
    diagnostic_pack: Mapping[str, Any],
    diagnostic_case: Mapping[str, Any],
    result: Mapping[str, Any],
) -> None:
    """Replay one diagnostic result, including factual-first quality scoring."""

    _require_self_sealed(result, label="diagnostic case result")
    factual_raw = result.get("factual_checks")
    quality_raw = result.get("quality_dimensions")
    causes_raw = result.get("root_cause_layers")
    if not isinstance(factual_raw, Mapping) or not isinstance(causes_raw, list):
        raise GEImprovementLoopError("diagnostic result review fields are invalid")
    if quality_raw is not None and not isinstance(quality_raw, Mapping):
        raise GEImprovementLoopError("diagnostic quality dimensions are invalid")
    try:
        factual = {str(name): str(value) for name, value in factual_raw.items()}
        quality = (
            {str(name): float(value) for name, value in quality_raw.items()}
            if isinstance(quality_raw, Mapping)
            else None
        )
    except (TypeError, ValueError) as exc:
        raise GEImprovementLoopError("diagnostic review values are invalid") from exc
    expected = build_diagnostic_case_result(
        diagnostic_pack=diagnostic_pack,
        diagnostic_case=diagnostic_case,
        factual_checks=factual,
        factual_report_sha256=str(result.get("factual_report_sha256") or ""),
        quality_scores=quality,
        quality_report_sha256=(
            str(result["quality_report_sha256"])
            if result.get("quality_report_sha256") is not None
            else None
        ),
        root_cause_layers=tuple(str(value) for value in causes_raw),
        relevant_change_at=_parse_timestamp(
            result.get("relevant_change_at"),
            label="diagnostic relevant change time",
        ),
        started_at=_parse_timestamp(result.get("started_at"), label="diagnostic result start"),
        completed_at=_parse_timestamp(
            result.get("completed_at"), label="diagnostic result completion"
        ),
    )
    if canonical_json_bytes(expected) != canonical_json_bytes(result):
        raise GEImprovementLoopError("diagnostic case result deterministic replay differs")


def build_successor_candidate_plan(
    *,
    plan_id: str,
    baseline_candidate_sha256: str,
    successor_candidate_sha256: str,
    official_research_intents: Sequence[Mapping[str, Any]],
    source_version_manifest_sha256: str,
    chunk_manifest_sha256: str,
    embedding_manifest_sha256: str,
    created_at: datetime,
    candidate_state: Literal["NON_ACTIVE"] = "NON_ACTIVE",
) -> dict[str, Any]:
    """Bind a create-new source/chunk/embedding successor without activating it."""

    _require_id(plan_id, label="successor plan ID")
    if candidate_state != "NON_ACTIVE":
        raise GEImprovementLoopError("successor candidate must remain non-ACTIVE")
    baseline = _require_hash(baseline_candidate_sha256, label="baseline candidate digest")
    successor = _require_hash(successor_candidate_sha256, label="successor candidate digest")
    if successor == baseline:
        raise GEImprovementLoopError("successor candidate must have a new identity")
    intent_manifest: list[dict[str, str]] = []
    seen: set[str] = set()
    for intent in official_research_intents:
        _require_self_sealed(intent, label="official research intent")
        if (
            intent.get("schema") != "legalbot.ge-official-research-intent.v1"
            or intent.get("source_scope") != "OFFICIAL_SOURCES_ONLY"
            or intent.get("network_action_performed") is not False
            or intent.get("successor_candidate_state") != "NON_ACTIVE"
            or intent.get("promotion_authorized") is not False
        ):
            raise GEImprovementLoopError("successor plan contains an unsafe research intent")
        intent_id = _require_id(intent.get("intent_id"), label="research intent ID")
        if intent_id in seen:
            raise GEImprovementLoopError("research intent identity is duplicated")
        seen.add(intent_id)
        intent_manifest.append(
            {"intent_id": intent_id, "content_sha256": str(intent["content_sha256"])}
        )
    return seal_contract(
        {
            "schema": "legalbot.ge-successor-candidate-plan.v1",
            "plan_id": plan_id,
            "baseline_candidate_sha256": baseline,
            "successor_candidate_sha256": successor,
            "candidate_state": candidate_state,
            "source_version_manifest_sha256": _require_hash(
                source_version_manifest_sha256, label="source-version manifest digest"
            ),
            "chunk_manifest_sha256": _require_hash(
                chunk_manifest_sha256, label="chunk manifest digest"
            ),
            "embedding_manifest_sha256": _require_hash(
                embedding_manifest_sha256, label="embedding manifest digest"
            ),
            "research_intent_manifest": intent_manifest,
            "index_policy": "CREATE_NEW_VERSION_ONLY",
            "active_pointer_write_authorized": False,
            "promotion_authorized": False,
            "created_at": _require_timestamp(
                created_at, label="successor plan creation"
            ).isoformat(),
        }
    )


def build_weight_training_option(
    *,
    option_id: str,
    owner_authorization_sha256: str,
    corpus_manifest_sha256: str,
    rights_review_sha256: str,
    privacy_review_sha256: str,
    contains_evaluation_content: bool,
    contains_unseen_content: bool,
    contains_user_content: bool,
    created_at: datetime,
) -> dict[str, Any]:
    """Prepare, but never execute, a separately authorized clean training option."""

    _require_id(option_id, label="training option ID")
    if contains_evaluation_content or contains_unseen_content or contains_user_content:
        raise GEImprovementLoopError(
            "weight training corpus cannot contain evaluation, unseen, or user content"
        )
    return seal_contract(
        {
            "schema": "legalbot.ge-weight-training-option.v1",
            "option_id": option_id,
            "owner_authorization_sha256": _require_hash(
                owner_authorization_sha256, label="weight-training owner authorization"
            ),
            "corpus_manifest_sha256": _require_hash(
                corpus_manifest_sha256, label="training corpus manifest digest"
            ),
            "rights_review_sha256": _require_hash(
                rights_review_sha256, label="training rights review digest"
            ),
            "privacy_review_sha256": _require_hash(
                privacy_review_sha256, label="training privacy review digest"
            ),
            "contains_evaluation_content": False,
            "contains_unseen_content": False,
            "contains_user_content": False,
            "execution_performed": False,
            "created_at": _require_timestamp(
                created_at, label="training option creation"
            ).isoformat(),
        }
    )


def _validate_system_run(
    *,
    pack: VisibleGEPack,
    visible_run: Mapping[str, Any],
    system_run: Mapping[str, Any],
    system_results: Sequence[Mapping[str, Any]],
    repair_manifest_sha256: str,
) -> None:
    _require_self_sealed(system_run, label="system run")
    if (
        system_run.get("schema") != "legalbot.ge-system-run.v1"
        or system_run.get("linked_visible_run_id") != visible_run.get("run_id")
        or system_run.get("candidate_sha256") != visible_run.get("candidate_sha256")
        or system_run.get("fixed_visible_denominator") != VISIBLE_CASE_COUNT
        or system_run.get("system_case_count") != SYSTEM_SCENARIO_COUNT
        or system_run.get("result_count") != SYSTEM_SCENARIO_COUNT
        or system_run.get("system_cases_separate_from_visible_denominator") is not True
        or system_run.get("system_manifest_sha256") != pack.system_manifest_sha256
        or system_run.get("system_order_sha256") != pack.system_order_sha256
        or system_run.get("candidate_state") != "NON_ACTIVE"
        or system_run.get("promotion_authorized") is not False
        or system_run.get("repair_manifest_sha256") != repair_manifest_sha256
        or system_run.get("visible_execution_identity_sha256")
        != _execution_identity_sha256(
            visible_run, repair_manifest_sha256=repair_manifest_sha256
        )
    ):
        raise GEImprovementLoopError("system run binding or custody differs")
    if len(system_results) != SYSTEM_SCENARIO_COUNT:
        raise GEImprovementLoopError("system result set is not exactly 32 cases")
    result_manifest: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for scenario, result in zip(pack.system_scenarios, system_results, strict=True):
        validate_system_case_result(
            result=result,
            scenario=scenario,
            run_id=str(system_run.get("run_id") or ""),
        )
        if (
            result.get("run_id") != system_run.get("run_id")
            or result.get("system_case_id") != scenario.case_id
            or result.get("system_case_sha256") != scenario.record_sha256
            or result.get("ordinal") != scenario.ordinal
            or result.get("scored_in_fixed_visible_denominator") is not False
        ):
            raise GEImprovementLoopError("system result identity or order differs")
        outcome = str(result.get("outcome") or "")
        if outcome not in {"PASS", "FAIL", "SYSTEM_ERROR"}:
            raise GEImprovementLoopError("system result outcome is invalid")
        counts[outcome] += 1
        result_manifest.append(
            {
                "ordinal": scenario.ordinal,
                "system_case_id": scenario.case_id,
                "result_id": result["result_id"],
                "content_sha256": result["content_sha256"],
                "outcome": outcome,
            }
        )
    expected_validity = "PASS" if counts["SYSTEM_ERROR"] == 0 else "FAIL"
    if system_run.get("result_manifest_sha256") != hashlib.sha256(
        canonical_json_bytes(result_manifest)
    ).hexdigest() or system_run.get("counts") != {
        "PASS": counts["PASS"],
        "FAIL": counts["FAIL"],
        "SYSTEM_ERROR": counts["SYSTEM_ERROR"],
    } or system_run.get("run_validity") != expected_validity:
        raise GEImprovementLoopError("system run result reconciliation differs")


def validate_completed_system_run(
    *,
    pack: VisibleGEPack,
    visible_run: Mapping[str, Any],
    system_run: Mapping[str, Any],
    system_results: Sequence[Mapping[str, Any]],
    repair_manifest_sha256: str,
) -> None:
    """Public replay validator for one immutable 32-case system run."""

    _validate_system_run(
        pack=pack,
        visible_run=visible_run,
        system_run=system_run,
        system_results=system_results,
        repair_manifest_sha256=_require_hash(
            repair_manifest_sha256, label="repair manifest digest"
        ),
    )


def _validate_diagnoses(
    *,
    diagnoses: Sequence[Mapping[str, Any]],
    visible_results: Sequence[Mapping[str, Any]],
    system_results: Sequence[Mapping[str, Any]],
    diagnostic_results: Mapping[str, Mapping[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    set[tuple[str, str]],
    int,
    list[dict[str, str]],
    tuple[str, ...],
]:
    visible = {str(result["case_id"]): result for result in visible_results}
    system = {str(result["system_case_id"]): result for result in system_results}
    seen: set[str] = set()
    manifest: list[dict[str, Any]] = []
    classified: set[tuple[str, str]] = set()
    open_material = 0
    gap_manifest: list[dict[str, str]] = []
    open_fingerprints: list[str] = []
    for diagnosis in diagnoses:
        validate_diagnosis(diagnosis)
        diagnosis_id = _require_id(diagnosis.get("diagnosis_id"), label="diagnosis ID")
        if diagnosis_id in seen:
            raise GEImprovementLoopError("diagnosis identity is duplicated")
        seen.add(diagnosis_id)
        case_id = _require_id(diagnosis.get("case_id"), label="diagnosis case ID")
        case_kind = str(diagnosis.get("case_kind") or "")
        failure_class = str(diagnosis.get("failure_class") or "")
        failure_code = _require_id(
            diagnosis.get("failure_code"), label="diagnosis failure code"
        )
        failed_checks_raw = diagnosis.get("failed_check_ids")
        if not isinstance(failed_checks_raw, list):
            raise GEImprovementLoopError("diagnosis failed-check identities are invalid")
        failed_check_ids = _validate_failed_check_ids(
            tuple(str(value) for value in failed_checks_raw)
        )
        scenario_family_id = _require_id(
            diagnosis.get("scenario_family_id"), label="diagnosis scenario family ID"
        )
        case_version_sha256 = _require_hash(
            diagnosis.get("case_version_sha256"), label="diagnosed case-version digest"
        )
        root_causes_raw = diagnosis.get("root_cause_layers")
        if not isinstance(root_causes_raw, list):
            raise GEImprovementLoopError("diagnosis root-cause layers are invalid")
        root_causes = _canonical_diagnosis_causes(
            [str(value) for value in root_causes_raw]
        )
        _require_hash(diagnosis.get("finding_sha256"), label="diagnosis finding digest")
        expected_failure_code = _canonical_failure_code(
            failure_class=failure_class,  # type: ignore[arg-type]
            failed_check_ids=failed_check_ids,
        )
        if failure_code != expected_failure_code:
            raise GEImprovementLoopError("diagnosis failure code differs")
        expected_fingerprint = _failure_fingerprint_sha256(
            case_id=case_id,
            case_kind=case_kind,
            case_version_sha256=case_version_sha256,
            scenario_family_id=scenario_family_id,
            failure_class=failure_class,
            failed_check_ids=failed_check_ids,
            root_cause_layers=root_causes,
        )
        fingerprint = _require_hash(
            diagnosis.get("failure_fingerprint_sha256"), label="failure fingerprint"
        )
        if fingerprint != expected_fingerprint:
            raise GEImprovementLoopError("diagnosis failure fingerprint differs")
        result: Mapping[str, Any] | None
        if case_kind == "visible":
            result = visible.get(case_id)
        elif case_kind == "system":
            result = system.get(case_id)
        elif case_kind == "diagnostic":
            result = diagnostic_results.get(case_id)
        else:
            raise GEImprovementLoopError("diagnosis points outside the reviewed GE custody")
        if result is None:
            raise GEImprovementLoopError("diagnosis has no reviewed result in GE custody")
        _assert_diagnosis_matches_failure(diagnosis, result)
        if failure_class not in _FAILURE_CLASSES:
            raise GEImprovementLoopError("diagnosis failure class differs")
        classified.add((case_id, failure_class))
        if (
            diagnosis.get("status") == "open"
            and diagnosis.get("materiality") in {"material", "potentially_material"}
        ):
            open_material += 1
        if diagnosis.get("status") == "open":
            open_fingerprints.append(fingerprint)
        if diagnosis.get("knowledge_or_source_gap") is True:
            gap_manifest.append(
                {
                    "diagnosis_id": diagnosis_id,
                    "case_id": case_id,
                    "content_sha256": str(diagnosis["content_sha256"]),
                }
            )
        manifest.append(
            {
                "diagnosis_id": diagnosis_id,
                "case_id": case_id,
                "failure_class": failure_class,
                "failure_code": failure_code,
                "failed_check_ids": list(failed_check_ids),
                "failure_fingerprint_sha256": fingerprint,
                "status": diagnosis.get("status"),
                "materiality": diagnosis.get("materiality"),
                "knowledge_or_source_gap": diagnosis.get("knowledge_or_source_gap"),
                "content_sha256": diagnosis["content_sha256"],
            }
        )
    return manifest, classified, open_material, gap_manifest, tuple(sorted(set(open_fingerprints)))


def _validate_supplement(
    *, pack: VisibleGEPack, supplement: Mapping[str, Any] | None
) -> tuple[str | None, set[str]]:
    if supplement is None:
        return None, set()
    _require_self_sealed(supplement, label="diagnostic supplement")
    if (
        supplement.get("schema") != "legalbot.ge-visible-diagnostic-supplement.v1"
        or supplement.get("fixed_pack_manifest_sha256") != pack.pack_manifest_sha256
        or supplement.get("fixed_case_manifest_sha256") != pack.case_manifest_sha256
        or supplement.get("fixed_case_order_sha256") != pack.case_order_sha256
        or supplement.get("fixed_visible_denominator") != VISIBLE_CASE_COUNT
        or supplement.get("system_case_count_separate") != SYSTEM_SCENARIO_COUNT
        or supplement.get("joins_fixed_visible_denominator") is not False
        or supplement.get("unseen_eligible") is not False
        or supplement.get("training_export_eligible") is not False
    ):
        raise GEImprovementLoopError("diagnostic supplement custody differs")
    _require_id(supplement.get("pack_id"), label="diagnostic pack ID")
    _require_id(supplement.get("linked_cycle_id"), label="linked cycle ID")
    _require_id(
        supplement.get("source_visible_run_id"),
        label="diagnostic source visible-run ID",
    )
    for field, label in (
        ("source_visible_run_sha256", "source visible-run digest"),
        ("source_execution_identity_sha256", "source execution-identity digest"),
        ("source_candidate_sha256", "source candidate digest"),
        ("source_repair_manifest_sha256", "source repair-manifest digest"),
    ):
        _require_hash(supplement.get(field), label=f"diagnostic {label}")
    _require_hash(supplement.get("coverage_audit_sha256"), label="coverage audit digest")
    raw_gaps = supplement.get("coverage_gap_manifest")
    if not isinstance(raw_gaps, list) or len(raw_gaps) != supplement.get("coverage_gap_count"):
        raise GEImprovementLoopError("diagnostic coverage-gap manifest differs")
    if supplement.get("coverage_gap_manifest_sha256") != hashlib.sha256(
        canonical_json_bytes(raw_gaps)
    ).hexdigest():
        raise GEImprovementLoopError("diagnostic coverage-gap manifest digest differs")
    source_diagnosis_manifest_raw = supplement.get("source_diagnosis_manifest")
    if (
        not isinstance(source_diagnosis_manifest_raw, list)
        or len(source_diagnosis_manifest_raw)
        != supplement.get("source_diagnosis_count")
        or supplement.get("source_diagnosis_manifest_sha256")
        != hashlib.sha256(
            canonical_json_bytes(source_diagnosis_manifest_raw)
        ).hexdigest()
    ):
        raise GEImprovementLoopError("diagnostic source-diagnosis manifest differs")
    pack_source_diagnoses: dict[str, str] = {}
    for item in source_diagnosis_manifest_raw:
        if not isinstance(item, Mapping):
            raise GEImprovementLoopError("diagnostic source diagnosis is not an object")
        diagnosis_id = _require_id(
            item.get("diagnosis_id"), label="source diagnosis ID"
        )
        diagnosis_sha256 = _require_hash(
            item.get("content_sha256"), label="source diagnosis content digest"
        )
        if diagnosis_id in pack_source_diagnoses:
            raise GEImprovementLoopError("diagnostic source identity is duplicated")
        pack_source_diagnoses[diagnosis_id] = diagnosis_sha256
    gap_bindings: dict[str, str] = {}
    for raw_gap in raw_gaps:
        if not isinstance(raw_gap, Mapping):
            raise GEImprovementLoopError("diagnostic coverage gap is not an object")
        cell_id = _require_id(raw_gap.get("coverage_cell_id"), label="coverage cell ID")
        fingerprint = _require_hash(
            raw_gap.get("gap_fingerprint_sha256"), label="coverage-gap fingerprint"
        )
        if cell_id in gap_bindings:
            raise GEImprovementLoopError("diagnostic coverage cell is duplicated")
        gap_bindings[cell_id] = fingerprint
    raw_cases = supplement.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) != supplement.get("case_count"):
        raise GEImprovementLoopError("diagnostic supplement case count differs")
    ids: set[str] = set()
    covered_cells: set[str] = set()
    prompt_fingerprints: set[str] = set()
    referenced_source_diagnoses: dict[str, str] = {}
    manifest: list[dict[str, Any]] = []
    fixed_ids = {case.case_id for case in pack.cases}
    fixed_ids.update(scenario.case_id for scenario in pack.system_scenarios)
    for row in raw_cases:
        if not isinstance(row, Mapping):
            raise GEImprovementLoopError("diagnostic supplement case is not an object")
        _require_self_sealed(row, label="diagnostic case")
        if (
            row.get("joins_fixed_visible_denominator") is not False
            or row.get("permanently_ineligible_for_unseen_validation") is not True
            or row.get("unseen_eligible") is not False
            or row.get("permanently_ineligible_for_training") is not True
            or row.get("training_export_eligible") is not False
            or row.get("user_content") is not False
        ):
            raise GEImprovementLoopError("diagnostic case custody differs")
        case_id = _require_id(row.get("diagnostic_case_id"), label="diagnostic case ID")
        if case_id in ids or case_id in fixed_ids:
            raise GEImprovementLoopError("diagnostic case identity collides or is duplicated")
        coverage_cell_id = _require_id(
            row.get("coverage_cell_id"), label="diagnostic coverage cell ID"
        )
        if coverage_cell_id in covered_cells:
            raise GEImprovementLoopError(
                "one coverage cell cannot be closed by duplicate diagnostic questions"
            )
        covered_cells.add(coverage_cell_id)
        _require_hash(
            row.get("coverage_gap_fingerprint_sha256"),
            label="diagnostic coverage-gap fingerprint",
        )
        if gap_bindings.get(str(row["coverage_cell_id"])) != row.get(
            "coverage_gap_fingerprint_sha256"
        ):
            raise GEImprovementLoopError("diagnostic case coverage-gap binding differs")
        prompt_fingerprint = hashlib.sha256(
            canonical_json_bytes(
                {
                    "prompt": " ".join(str(row.get("prompt") or "").casefold().split()),
                    "rationale": " ".join(
                        str(row.get("rationale") or "").casefold().split()
                    ),
                }
            )
        ).hexdigest()
        if prompt_fingerprint in prompt_fingerprints:
            raise GEImprovementLoopError(
                "one diagnostic question cannot close more than one coverage cell"
            )
        prompt_fingerprints.add(prompt_fingerprint)
        prompt_projection = row.get("prompt_only_projection")
        if not isinstance(prompt_projection, Mapping):
            raise GEImprovementLoopError("diagnostic prompt-only projection is missing")
        _require_self_sealed(prompt_projection, label="diagnostic prompt-only projection")
        question_version_sha256 = _require_hash(
            row.get("question_version_sha256"),
            label="diagnostic question-version digest",
        )
        if (
            prompt_projection.get("schema")
            != "legalbot.ge-diagnostic-prompt-projection.v1"
            or prompt_projection.get("diagnostic_case_id") != case_id
            or prompt_projection.get("question_type") != "GENERAL_ENQUIRY"
            or prompt_projection.get("prompt") != row.get("prompt")
            or prompt_projection.get("primary_jurisdiction")
            != row.get("primary_jurisdiction")
            or prompt_projection.get("legal_currentness_cutoff")
            != row.get("legal_currentness_cutoff")
            or prompt_projection.get("question_version_sha256")
            != question_version_sha256
            or prompt_projection.get("contains_rationale") is not False
            or prompt_projection.get("contains_gold") is not False
            or prompt_projection.get("contains_diagnosis") is not False
            or prompt_projection.get("unseen_content") is not False
            or row.get("prompt_only_projection_sha256")
            != prompt_projection.get("content_sha256")
        ):
            raise GEImprovementLoopError("diagnostic prompt-only projection differs")
        _require_hash(
            row.get("legal_currentness_review_sha256"),
            label="diagnostic legal-currentness review digest",
        )
        _require_hash(
            row.get("gold_review_sha256"), label="diagnostic gold-review digest"
        )
        diagnosis_ids_raw = row.get("source_diagnosis_ids")
        diagnosis_manifest_raw = row.get("source_diagnosis_manifest")
        if not isinstance(diagnosis_ids_raw, list) or not isinstance(
            diagnosis_manifest_raw, list
        ):
            raise GEImprovementLoopError("diagnostic source-diagnosis custody differs")
        diagnosis_ids = [
            _require_id(value, label="source diagnosis ID")
            for value in diagnosis_ids_raw
        ]
        if len(diagnosis_ids) != len(set(diagnosis_ids)):
            raise GEImprovementLoopError("diagnostic source identity is duplicated")
        provenance_kind = row.get("diagnostic_provenance_kind")
        if (provenance_kind, bool(diagnosis_ids)) not in {
            ("COVERAGE_ONLY", False),
            ("DIAGNOSIS_DERIVED", True),
        }:
            raise GEImprovementLoopError("diagnostic provenance kind differs")
        if (
            len(diagnosis_manifest_raw) != len(diagnosis_ids)
            or row.get("source_diagnosis_manifest_sha256")
            != hashlib.sha256(
                canonical_json_bytes(diagnosis_manifest_raw)
            ).hexdigest()
        ):
            raise GEImprovementLoopError("diagnostic source-diagnosis manifest differs")
        case_manifest_ids: list[str] = []
        for item in diagnosis_manifest_raw:
            if not isinstance(item, Mapping):
                raise GEImprovementLoopError(
                    "diagnostic source diagnosis is not an object"
                )
            diagnosis_id = _require_id(
                item.get("diagnosis_id"), label="source diagnosis ID"
            )
            diagnosis_sha256 = _require_hash(
                item.get("content_sha256"), label="source diagnosis content digest"
            )
            _require_id(item.get("case_id"), label="source diagnosis case ID")
            _require_hash(
                item.get("failure_fingerprint_sha256"),
                label="source diagnosis failure fingerprint",
            )
            if pack_source_diagnoses.get(diagnosis_id) != diagnosis_sha256:
                raise GEImprovementLoopError(
                    "diagnostic source diagnosis differs from the pack manifest"
                )
            if (
                diagnosis_id in referenced_source_diagnoses
                and referenced_source_diagnoses[diagnosis_id] != diagnosis_sha256
            ):
                raise GEImprovementLoopError("diagnostic source identity is duplicated")
            referenced_source_diagnoses[diagnosis_id] = diagnosis_sha256
            case_manifest_ids.append(diagnosis_id)
        if case_manifest_ids != diagnosis_ids:
            raise GEImprovementLoopError("diagnostic source diagnosis order differs")
        ids.add(case_id)
        manifest.append(
            {
                "ordinal": row["ordinal"],
                "diagnostic_case_id": case_id,
                "content_sha256": row["content_sha256"],
            }
        )
    if supplement.get("case_manifest_sha256") != hashlib.sha256(
        canonical_json_bytes(manifest)
    ).hexdigest():
        raise GEImprovementLoopError("diagnostic pack case manifest differs")
    if covered_cells != set(gap_bindings):
        raise GEImprovementLoopError("diagnostic pack does not cover every audited gap")
    if referenced_source_diagnoses != pack_source_diagnoses:
        raise GEImprovementLoopError(
            "diagnostic source diagnoses do not reconcile with the pack manifest"
        )
    return str(supplement["content_sha256"]), ids


def validate_visible_diagnostic_supplement(
    *,
    pack: VisibleGEPack,
    diagnostic_pack: Mapping[str, Any],
    visible_run: Mapping[str, Any],
    repair_manifest_sha256: str,
) -> None:
    """Public custody validator for an immutable diagnostic-only pack."""

    _validate_supplement(pack=pack, supplement=diagnostic_pack)
    _validate_diagnostic_execution_binding(
        diagnostic_pack=diagnostic_pack,
        visible_run=visible_run,
        repair_manifest_sha256=repair_manifest_sha256,
    )


def _validate_diagnostic_execution_binding(
    *,
    diagnostic_pack: Mapping[str, Any] | None,
    visible_run: Mapping[str, Any],
    repair_manifest_sha256: str,
) -> None:
    if diagnostic_pack is None:
        return
    repair_sha256 = _require_hash(
        repair_manifest_sha256, label="diagnostic repair-manifest digest"
    )
    expected = {
        "source_visible_run_id": visible_run.get("run_id"),
        "source_visible_run_sha256": _object_sha256(visible_run),
        "source_execution_identity_sha256": _execution_identity_sha256(
            visible_run, repair_manifest_sha256=repair_sha256
        ),
        "source_candidate_sha256": visible_run.get("candidate_sha256"),
        "source_repair_manifest_sha256": repair_sha256,
    }
    if any(diagnostic_pack.get(field) != value for field, value in expected.items()):
        raise GEImprovementLoopError(
            "diagnostic pack source run, execution, candidate, or repair binding differs"
        )


def _validate_diagnostic_source_diagnoses(
    *,
    diagnostic_pack: Mapping[str, Any] | None,
    diagnoses: Sequence[Mapping[str, Any]],
) -> None:
    if diagnostic_pack is None:
        return
    cycle_diagnoses: dict[str, Mapping[str, Any]] = {}
    for diagnosis in diagnoses:
        diagnosis_id = _require_id(
            diagnosis.get("diagnosis_id"), label="cycle diagnosis ID"
        )
        if diagnosis_id in cycle_diagnoses:
            raise GEImprovementLoopError("cycle diagnosis identity is duplicated")
        cycle_diagnoses[diagnosis_id] = diagnosis
    raw_cases = diagnostic_pack.get("cases")
    if not isinstance(raw_cases, list):
        raise GEImprovementLoopError("diagnostic pack cases are invalid")
    for case in raw_cases:
        if not isinstance(case, Mapping):
            raise GEImprovementLoopError("diagnostic case is not an object")
        ids_raw = case.get("source_diagnosis_ids")
        manifest_raw = case.get("source_diagnosis_manifest")
        if not isinstance(ids_raw, list) or not isinstance(manifest_raw, list):
            raise GEImprovementLoopError("diagnostic source-diagnosis custody differs")
        ids = [str(value) for value in ids_raw]
        if case.get("diagnostic_provenance_kind") == "COVERAGE_ONLY":
            if ids or manifest_raw:
                raise GEImprovementLoopError(
                    "coverage-only diagnostic cannot claim a source diagnosis"
                )
            continue
        if case.get("diagnostic_provenance_kind") != "DIAGNOSIS_DERIVED" or not ids:
            raise GEImprovementLoopError("diagnostic provenance kind differs")
        for diagnosis_id, source in zip(ids, manifest_raw, strict=True):
            if not isinstance(source, Mapping):
                raise GEImprovementLoopError(
                    "diagnostic source diagnosis is not an object"
                )
            cycle_diagnosis = cycle_diagnoses.get(diagnosis_id)
            if (
                cycle_diagnosis is None
                or source.get("diagnosis_id") != diagnosis_id
                or source.get("content_sha256")
                != cycle_diagnosis.get("content_sha256")
                or source.get("failure_fingerprint_sha256")
                != cycle_diagnosis.get("failure_fingerprint_sha256")
                or source.get("case_id") != cycle_diagnosis.get("case_id")
                or case.get("scenario_family_id")
                != cycle_diagnosis.get("scenario_family_id")
            ):
                raise GEImprovementLoopError(
                    "diagnostic source diagnosis does not reconcile to this cycle"
                )


def _validate_diagnostic_results(
    *,
    diagnostic_pack: Mapping[str, Any] | None,
    diagnostic_results: Sequence[Mapping[str, Any]],
    relevant_change_at: datetime | None,
) -> tuple[dict[str, Mapping[str, Any]], int, set[tuple[str, str]]]:
    if diagnostic_pack is None:
        if diagnostic_results:
            raise GEImprovementLoopError("diagnostic results have no bound diagnostic pack")
        return {}, 0, set()
    raw_cases = diagnostic_pack.get("cases")
    if not isinstance(raw_cases, list) or len(diagnostic_results) != len(raw_cases):
        raise GEImprovementLoopError("every accumulated diagnostic needs exactly one result")
    by_id: dict[str, Mapping[str, Any]] = {}
    passing = 0
    failed_pairs: set[tuple[str, str]] = set()
    pack_created = _parse_timestamp(
        diagnostic_pack.get("created_at"), label="diagnostic pack creation"
    )
    effective_change = max(
        pack_created,
        (
            _require_timestamp(
                relevant_change_at, label="diagnostic relevant change time"
            )
            if relevant_change_at is not None
            else pack_created
        ),
    )
    for raw_case, result in zip(raw_cases, diagnostic_results, strict=True):
        if not isinstance(raw_case, Mapping):
            raise GEImprovementLoopError("diagnostic case is not an object")
        validate_diagnostic_case_result(
            diagnostic_pack=diagnostic_pack,
            diagnostic_case=raw_case,
            result=result,
        )
        case_id = _require_id(raw_case.get("diagnostic_case_id"), label="diagnostic case ID")
        if (
            result.get("schema") != "legalbot.ge-diagnostic-case-result.v1"
            or result.get("diagnostic_pack_id") != diagnostic_pack.get("pack_id")
            or result.get("diagnostic_case_id") != case_id
            or result.get("diagnostic_case_sha256") != raw_case.get("content_sha256")
            or result.get("ordinal") != raw_case.get("ordinal")
            or result.get("scored_in_fixed_visible_denominator") is not False
            or result.get("scored_in_system_denominator") is not False
            or result.get("unseen_eligible") is not False
            or result.get("training_export_eligible") is not False
            or result.get("source_visible_run_id")
            != diagnostic_pack.get("source_visible_run_id")
            or result.get("source_visible_run_sha256")
            != diagnostic_pack.get("source_visible_run_sha256")
            or result.get("source_execution_identity_sha256")
            != diagnostic_pack.get("source_execution_identity_sha256")
            or result.get("source_candidate_sha256")
            != diagnostic_pack.get("source_candidate_sha256")
            or result.get("source_repair_manifest_sha256")
            != diagnostic_pack.get("source_repair_manifest_sha256")
            or result.get("question_version_sha256")
            != raw_case.get("question_version_sha256")
            or result.get("prompt_only_projection_sha256")
            != raw_case.get("prompt_only_projection_sha256")
            or result.get("legal_currentness_review_sha256")
            != raw_case.get("legal_currentness_review_sha256")
            or result.get("gold_review_sha256") != raw_case.get("gold_review_sha256")
            or result.get("diagnostic_provenance_kind")
            != raw_case.get("diagnostic_provenance_kind")
            or result.get("source_diagnosis_ids")
            != raw_case.get("source_diagnosis_ids")
            or result.get("source_diagnosis_manifest_sha256")
            != raw_case.get("source_diagnosis_manifest_sha256")
            or _parse_timestamp(
                result.get("relevant_change_at"),
                label="diagnostic relevant change time",
            )
            != effective_change
            or _parse_timestamp(
                result.get("started_at"), label="diagnostic result start"
            )
            <= effective_change
        ):
            raise GEImprovementLoopError("diagnostic result identity or custody differs")
        if case_id in by_id:
            raise GEImprovementLoopError("diagnostic result identity is duplicated")
        by_id[case_id] = result
        score = result.get("quality_score")
        if (
            result.get("factual_outcome") == "FACTUAL_PASS"
            and result.get("quality_outcome") in _PASSING_QUALITY
            and isinstance(score, int | float)
            and not isinstance(score, bool)
            and float(score) >= 70.0
        ):
            passing += 1
        elif result.get("factual_outcome") != "FACTUAL_PASS":
            failed_pairs.add((case_id, "factual"))
        else:
            failed_pairs.add((case_id, "quality"))
    return by_id, passing, failed_pairs


def _validate_owner_acceptance(
    acceptance: Mapping[str, Any],
    *,
    decision_basis_sha256: str,
    assessed_at: datetime,
    owner_authorization: VerifiedGECycleOwnerAuthorization | None,
) -> str:
    authorization = require_verified_cycle_owner_authorization(
        owner_authorization,
        decision_basis_sha256=decision_basis_sha256,
    )
    expected = build_verified_cycle_owner_acceptance(authorization)
    if authorization.decided_at > assessed_at:
        raise GEImprovementLoopError(
            "GE completed assessment predates its owner acceptance"
        )
    _require_self_sealed(acceptance, label="GE owner acceptance")
    if (
        acceptance.get("schema") != "legalbot.ge-cycle-owner-acceptance.v1"
        or acceptance.get("decision") != "ACCEPT"
        or acceptance.get("decision_basis_sha256") != decision_basis_sha256
        or acceptance.get("unseen_opened") is not False
    ):
        raise GEImprovementLoopError("GE owner acceptance does not bind this closed basis")
    _require_id(acceptance.get("owner_decision_id"), label="owner decision ID")
    _require_hash(acceptance.get("authorization_sha256"), label="owner authorization digest")
    _parse_timestamp(acceptance.get("decided_at"), label="owner acceptance time")
    if canonical_json_bytes(expected) != canonical_json_bytes(acceptance):
        raise GEImprovementLoopError(
            "GE owner acceptance differs from verifier-issued authority"
        )
    return str(acceptance["content_sha256"])


def build_cycle_owner_acceptance(
    *, authorization: VerifiedGECycleOwnerAuthorization
) -> dict[str, Any]:
    """Project an opaque verifier-issued owner proof into the stored contract."""

    return build_verified_cycle_owner_acceptance(authorization)


def _validate_cycle_coverage_audit(
    *,
    pack: VisibleGEPack,
    coverage_audit: Mapping[str, Any],
    coverage_authorization: VerifiedGECoverageAuthorization,
    diagnostic_supplement: Mapping[str, Any] | None,
) -> tuple[str, int, dict[str, Any]]:
    """Replay the approved visible-only coverage audit bound to this cycle."""

    _require_self_sealed(coverage_audit, label="GE coverage audit")
    coverage_manifest = coverage_audit.get("coverage_manifest")
    if not isinstance(coverage_manifest, Mapping):
        raise GEImprovementLoopError("GE coverage audit lacks its approved topology")
    audited_at = _parse_timestamp(
        coverage_audit.get("audited_at"), label="GE coverage audit time"
    )
    expected = build_coverage_audit(
        pack=pack,
        coverage_manifest=coverage_manifest,
        coverage_authorization=coverage_authorization,
        existing_diagnostic_pack=diagnostic_supplement,
        audited_at=audited_at,
        unseen_opened=False,
    )
    if canonical_json_bytes(expected) != canonical_json_bytes(coverage_audit):
        raise GEImprovementLoopError("GE coverage audit deterministic replay differs")
    missing_count = coverage_audit.get("missing_cell_count")
    if (
        coverage_audit.get("fixed_pack_manifest_sha256") != pack.pack_manifest_sha256
        or coverage_audit.get("visible_case_count_reviewed") != VISIBLE_CASE_COUNT
        or coverage_audit.get("system_case_count_reviewed") != SYSTEM_SCENARIO_COUNT
        or coverage_audit.get("unseen_inspected") is not False
        or not isinstance(missing_count, int)
        or isinstance(missing_count, bool)
        or missing_count < 0
    ):
        raise GEImprovementLoopError("GE coverage audit custody or counts differ")
    binding = {
        "coverage_manifest_sha256": str(coverage_audit["coverage_manifest_sha256"]),
        "coverage_predecision_sha256": str(
            coverage_audit["coverage_predecision_sha256"]
        ),
        "coverage_breadth_policy_id": str(coverage_audit["breadth_policy_id"]),
        "coverage_breadth_policy_sha256": str(
            coverage_audit["breadth_policy_sha256"]
        ),
        "coverage_required_domain_set_sha256": str(
            coverage_audit["required_domain_set_sha256"]
        ),
        "coverage_cell_manifest_sha256": str(
            coverage_audit["cell_manifest_sha256"]
        ),
        "coverage_cell_order_sha256": str(coverage_audit["cell_order_sha256"]),
        "coverage_topology_sha256": str(coverage_audit["topology_sha256"]),
        "coverage_owner_request_sha256": str(
            coverage_audit["owner_request_sha256"]
        ),
        "coverage_owner_resolution_sha256": str(
            coverage_audit["owner_resolution_sha256"]
        ),
    }
    return str(coverage_audit["content_sha256"]), missing_count, binding


def build_cycle_assessment(
    *,
    loop_id: str,
    cycle_number: int,
    registry: ContractSchemaRegistry,
    pack: VisibleGEPack,
    visible_run: Mapping[str, Any],
    visible_results: Sequence[Mapping[str, Any]],
    system_run: Mapping[str, Any],
    system_results: Sequence[Mapping[str, Any]],
    repair_manifest_sha256: str,
    diagnoses: Sequence[Mapping[str, Any]],
    coverage_audit: Mapping[str, Any],
    coverage_authorization: VerifiedGECoverageAuthorization,
    diagnostic_supplement: Mapping[str, Any] | None,
    diagnostic_results: Sequence[Mapping[str, Any]],
    unseen_opened: bool,
    assessed_at: datetime,
    successor_candidate_plan: Mapping[str, Any] | None = None,
    previous_assessment: Mapping[str, Any] | None = None,
    change_applied_at: datetime | None = None,
    owner_acceptance: Mapping[str, Any] | None = None,
    owner_authorization: VerifiedGECycleOwnerAuthorization | None = None,
) -> dict[str, Any]:
    """Assess one cycle and fail closed until every GE exit gate is satisfied."""

    resolved_loop_id = _require_id(loop_id, label="GE loop ID")
    if cycle_number < 1:
        raise GEImprovementLoopError("GE cycle number must be positive")
    cycle_id = f"{resolved_loop_id}:cycle:{cycle_number}"
    assessed = _require_timestamp(assessed_at, label="cycle assessment time")
    repair_sha256 = _require_hash(repair_manifest_sha256, label="repair manifest digest")
    evaluated_candidate_sha256 = _require_hash(
        visible_run.get("candidate_sha256"), label="evaluated candidate digest"
    )
    predecessor_assessment_sha256: str | None = None
    if previous_assessment is None:
        if cycle_number != 1:
            raise GEImprovementLoopError("later GE cycle requires its exact predecessor")
    else:
        _require_self_sealed(previous_assessment, label="previous cycle assessment")
        if (
            previous_assessment.get("schema") != "legalbot.ge-cycle-assessment.v2"
            or previous_assessment.get("loop_id") != resolved_loop_id
            or previous_assessment.get("cycle_number") != cycle_number - 1
        ):
            raise GEImprovementLoopError("GE cycle predecessor binding differs")
        predecessor_assessment_sha256 = str(previous_assessment["content_sha256"])

    baseline_candidate_sha256 = evaluated_candidate_sha256
    successor_candidate_sha256: str | None = None
    successor_plan_sha256: str | None = None
    if successor_candidate_plan is not None:
        _require_self_sealed(successor_candidate_plan, label="successor candidate plan")
        if (
            successor_candidate_plan.get("schema")
            != "legalbot.ge-successor-candidate-plan.v1"
            or successor_candidate_plan.get("candidate_state") != "NON_ACTIVE"
            or successor_candidate_plan.get("promotion_authorized") is not False
            or successor_candidate_plan.get("active_pointer_write_authorized") is not False
        ):
            raise GEImprovementLoopError("successor candidate plan is unsafe")
        baseline_candidate_sha256 = _require_hash(
            successor_candidate_plan.get("baseline_candidate_sha256"),
            label="baseline candidate digest",
        )
        successor_candidate_sha256 = _require_hash(
            successor_candidate_plan.get("successor_candidate_sha256"),
            label="successor candidate digest",
        )
        if successor_candidate_sha256 != evaluated_candidate_sha256:
            raise GEImprovementLoopError("visible run did not evaluate the planned successor")
        successor_plan_sha256 = str(successor_candidate_plan["content_sha256"])
    _assert_fixed_visible_run(
        registry=registry,
        pack=pack,
        visible_run=visible_run,
        case_results=visible_results,
    )
    _validate_system_run(
        pack=pack,
        visible_run=visible_run,
        system_run=system_run,
        system_results=system_results,
        repair_manifest_sha256=repair_sha256,
    )
    supplement_sha256, _diagnostic_case_ids = _validate_supplement(
        pack=pack, supplement=diagnostic_supplement
    )
    _validate_diagnostic_execution_binding(
        diagnostic_pack=diagnostic_supplement,
        visible_run=visible_run,
        repair_manifest_sha256=repair_sha256,
    )
    if (
        diagnostic_supplement is not None
        and diagnostic_supplement.get("linked_cycle_id") != cycle_id
    ):
        raise GEImprovementLoopError("diagnostic pack is linked to another cycle")
    (
        coverage_audit_sha256,
        missing_coverage_cell_count,
        coverage_binding,
    ) = _validate_cycle_coverage_audit(
        pack=pack,
        coverage_audit=coverage_audit,
        coverage_authorization=coverage_authorization,
        diagnostic_supplement=diagnostic_supplement,
    )
    diagnostic_result_map, diagnostic_pass, diagnostic_failed = (
        _validate_diagnostic_results(
            diagnostic_pack=diagnostic_supplement,
            diagnostic_results=diagnostic_results,
            relevant_change_at=change_applied_at,
        )
    )
    (
        diagnosis_manifest,
        classified,
        open_material,
        gap_manifest,
        open_fingerprints,
    ) = _validate_diagnoses(
        diagnoses=diagnoses,
        visible_results=visible_results,
        system_results=system_results,
        diagnostic_results=diagnostic_result_map,
    )
    _validate_diagnostic_source_diagnoses(
        diagnostic_pack=diagnostic_supplement,
        diagnoses=diagnoses,
    )

    blockers: list[str] = []
    visible_factual_pass = 0
    visible_quality_pass = 0
    failed_pairs: set[tuple[str, str]] = set()
    for result in visible_results:
        case_id = str(result["case_id"])
        if result.get("terminal_state") == "completed" and result.get("factual_outcome") == "FACTUAL_PASS":
            visible_factual_pass += 1
            score = result.get("quality_score")
            if (
                result.get("quality_outcome") in _PASSING_QUALITY
                and isinstance(score, int | float)
                and not isinstance(score, bool)
                and float(score) >= 70.0
            ):
                visible_quality_pass += 1
            else:
                failed_pairs.add((case_id, "quality"))
        else:
            failed_pairs.add((case_id, "factual"))
    system_pass = 0
    for result in system_results:
        if result.get("outcome") == "PASS":
            system_pass += 1
        else:
            failed_pairs.add((str(result["system_case_id"]), "system"))
    failed_pairs.update(diagnostic_failed)
    if failed_pairs.difference(classified):
        blockers.append("UNDIAGNOSED_FAILURE")
    if visible_factual_pass != VISIBLE_CASE_COUNT:
        blockers.append("VISIBLE_FACTUAL_GATE_NOT_CLOSED")
    if visible_quality_pass != VISIBLE_CASE_COUNT:
        blockers.append("VISIBLE_70_STANDARD_NOT_CLOSED")
    if system_pass != SYSTEM_SCENARIO_COUNT:
        blockers.append("SYSTEM_SUITE_NOT_CLOSED")
    diagnostic_case_count = len(diagnostic_result_map)
    if diagnostic_pass != diagnostic_case_count:
        blockers.append("DIAGNOSTIC_SUPPLEMENT_NOT_CLOSED")
    if open_material:
        blockers.append("OPEN_MATERIAL_DIAGNOSIS_OR_GAP")
    if missing_coverage_cell_count:
        blockers.append("MISSING_GE_COVERAGE_AREAS")
    if unseen_opened:
        blockers.append("UNSEEN_CUSTODY_BREACH")

    execution_identity = _execution_identity_sha256(
        visible_run, repair_manifest_sha256=repair_sha256
    )
    full_rerun_required = False
    execution_changed = False
    fresh_changed_rerun = False
    third_attempt_forbidden = False
    if previous_assessment is not None:
        execution_changed = (
            previous_assessment.get("execution_identity_sha256") != execution_identity
        )
        if previous_assessment.get("status") == "STOP_REPEATED_FINGERPRINT":
            third_attempt_forbidden = True
            blockers.append("THIRD_AUTOMATIC_ATTEMPT_FORBIDDEN")
        if execution_changed:
            full_rerun_required = True
            if change_applied_at is not None:
                changed_at = _require_timestamp(change_applied_at, label="change application time")
                visible_started = _parse_timestamp(
                    visible_run.get("started_at"), label="visible run start"
                )
                system_started = _parse_timestamp(
                    system_run.get("started_at"), label="system run start"
                )
                if (
                    visible_started >= changed_at
                    and system_started >= changed_at
                    and visible_run.get("run_id") != previous_assessment.get("visible_run_id")
                    and system_run.get("run_id") != previous_assessment.get("system_run_id")
                ):
                    full_rerun_required = False
                    fresh_changed_rerun = True
            if full_rerun_required:
                blockers.append("FULL_331_PLUS_32_RERUN_REQUIRED")

    previous_attempt_counts_raw = (
        previous_assessment.get("failure_fingerprint_attempt_counts", {})
        if previous_assessment is not None
        else {}
    )
    if not isinstance(previous_attempt_counts_raw, Mapping):
        raise GEImprovementLoopError("previous failure-attempt counts are invalid")
    previous_open_fingerprints: set[str] = set()
    if previous_assessment is not None:
        previous_open_raw = previous_assessment.get("open_failure_fingerprints")
        if not isinstance(previous_open_raw, list):
            raise GEImprovementLoopError(
                "previous open failure-fingerprint set is invalid"
            )
        previous_open_fingerprints = {
            _require_hash(value, label="previous open failure fingerprint")
            for value in previous_open_raw
        }
        unchanged_still_open = previous_open_fingerprints.intersection(
            open_fingerprints
        )
        if unchanged_still_open and not execution_changed:
            raise GEImprovementLoopError(
                "unchanged execution and repair cannot retry a still-open failure "
                f"fingerprint: {sorted(unchanged_still_open)[0]}"
            )
    failure_attempt_counts: dict[str, int] = {}
    for raw_fingerprint, raw_count in previous_attempt_counts_raw.items():
        fingerprint = _require_hash(
            raw_fingerprint, label="previous failure fingerprint"
        )
        if not isinstance(raw_count, int) or isinstance(raw_count, bool) or raw_count < 1:
            raise GEImprovementLoopError("previous failure-attempt count is invalid")
        failure_attempt_counts[fingerprint] = raw_count
    repeated_fingerprints: list[str] = []
    for fingerprint in sorted(set(open_fingerprints)):
        prior = int(previous_attempt_counts_raw.get(fingerprint, 0))
        count = prior + 1 if previous_assessment is None or fresh_changed_rerun else max(prior, 1)
        failure_attempt_counts[fingerprint] = count
        if count >= 2 and fresh_changed_rerun:
            repeated_fingerprints.append(fingerprint)
    repeated_stop = bool(repeated_fingerprints) or third_attempt_forbidden
    if repeated_fingerprints:
        blockers.append("REPEATED_FAILURE_FINGERPRINT_AFTER_REPAIR")

    blocker_values = sorted(set(blockers))
    diagnosis_manifest_sha256 = hashlib.sha256(
        canonical_json_bytes(diagnosis_manifest)
    ).hexdigest()
    gap_manifest_sha256 = hashlib.sha256(canonical_json_bytes(gap_manifest)).hexdigest()
    diagnostic_result_manifest_sha256 = hashlib.sha256(
        canonical_json_bytes(
            [
                {
                    "diagnostic_case_id": result["diagnostic_case_id"],
                    "result_id": result["result_id"],
                    "content_sha256": result["content_sha256"],
                }
                for result in diagnostic_results
            ]
        )
    ).hexdigest()
    decision_basis = seal_contract(
        {
            "schema": "legalbot.ge-cycle-decision-basis.v1",
            "loop_id": resolved_loop_id,
            "cycle_id": cycle_id,
            "cycle_number": cycle_number,
            "predecessor_assessment_sha256": predecessor_assessment_sha256,
            "fixed_pack_manifest_sha256": pack.pack_manifest_sha256,
            "fixed_case_manifest_sha256": pack.case_manifest_sha256,
            "fixed_case_order_sha256": pack.case_order_sha256,
            "fixed_visible_denominator": VISIBLE_CASE_COUNT,
            "system_case_count_separate": SYSTEM_SCENARIO_COUNT,
            "visible_run_sha256": _object_sha256(visible_run),
            "system_run_sha256": str(system_run["content_sha256"]),
            "execution_identity_sha256": execution_identity,
            "baseline_candidate_sha256": baseline_candidate_sha256,
            "evaluated_candidate_sha256": evaluated_candidate_sha256,
            "successor_candidate_sha256": successor_candidate_sha256,
            "successor_candidate_plan_sha256": successor_plan_sha256,
            "repair_manifest_sha256": repair_sha256,
            "diagnosis_manifest_sha256": diagnosis_manifest_sha256,
            "gap_manifest_sha256": gap_manifest_sha256,
            "diagnostic_pack_sha256": supplement_sha256,
            "coverage_audit_sha256": coverage_audit_sha256,
            **coverage_binding,
            "missing_coverage_cell_count": missing_coverage_cell_count,
            "diagnostic_result_manifest_sha256": diagnostic_result_manifest_sha256,
            "visible_factual_pass_count": visible_factual_pass,
            "visible_quality_70_and_critical_floor_pass_count": visible_quality_pass,
            "system_pass_count": system_pass,
            "diagnostic_pass_count": diagnostic_pass,
            "diagnostic_case_count": diagnostic_case_count,
            "open_material_diagnosis_count": open_material,
            "repeated_failure_fingerprints": repeated_fingerprints,
            "failure_fingerprint_attempt_counts": failure_attempt_counts,
            "open_failure_fingerprints": list(open_fingerprints),
            "unseen_opened": unseen_opened,
            "blockers_before_owner_acceptance": blocker_values,
        }
    )
    decision_basis_sha256 = str(decision_basis["content_sha256"])
    acceptance_sha256: str | None = None
    if owner_acceptance is not None:
        acceptance_sha256 = _validate_owner_acceptance(
            owner_acceptance,
            decision_basis_sha256=decision_basis_sha256,
            assessed_at=assessed,
            owner_authorization=owner_authorization,
        )
    elif owner_authorization is not None:
        raise GEImprovementLoopError(
            "verifier-issued owner authority lacks its exact acceptance projection"
        )

    if repeated_stop:
        status = "STOP_REPEATED_FINGERPRINT"
    elif blocker_values:
        status = (
            "FULL_RERUN_REQUIRED"
            if "FULL_331_PLUS_32_RERUN_REQUIRED" in blocker_values
            else "IMPROVEMENT_REQUIRED"
        )
    elif acceptance_sha256 is None:
        status = "AWAITING_OWNER_ACCEPTANCE"
    else:
        status = "GE_COMPLETE_OWNER_ACCEPTED"

    return seal_contract(
        {
            "schema": "legalbot.ge-cycle-assessment.v2",
            "assessment_id": f"ge-cycle-{decision_basis_sha256[:24]}",
            "loop_id": resolved_loop_id,
            "cycle_id": cycle_id,
            "cycle_number": cycle_number,
            "predecessor_assessment_sha256": predecessor_assessment_sha256,
            "status": status,
            "fixed_pack_manifest_sha256": pack.pack_manifest_sha256,
            "fixed_case_manifest_sha256": pack.case_manifest_sha256,
            "fixed_case_order_sha256": pack.case_order_sha256,
            "fixed_visible_denominator": VISIBLE_CASE_COUNT,
            "system_case_count_separate": SYSTEM_SCENARIO_COUNT,
            "visible_run_id": visible_run["run_id"],
            "visible_run_sha256": _object_sha256(visible_run),
            "system_run_id": system_run["run_id"],
            "system_run_sha256": system_run["content_sha256"],
            "execution_identity_sha256": execution_identity,
            "repair_manifest_sha256": repair_sha256,
            "candidate_sha256": evaluated_candidate_sha256,
            "baseline_candidate_sha256": baseline_candidate_sha256,
            "successor_candidate_sha256": successor_candidate_sha256,
            "successor_candidate_plan_sha256": successor_plan_sha256,
            "candidate_state": "NON_ACTIVE",
            "promotion_authorized": False,
            "visible_factual_pass_count": visible_factual_pass,
            "visible_quality_70_and_critical_floor_pass_count": visible_quality_pass,
            "quality_critical_floors": dict(QUALITY_CRITICAL_FLOORS),
            "system_pass_count": system_pass,
            "diagnostic_case_count": diagnostic_case_count,
            "diagnostic_pass_count": diagnostic_pass,
            "diagnosis_count": len(diagnosis_manifest),
            "diagnosis_manifest_sha256": diagnosis_manifest_sha256,
            "gap_count": len(gap_manifest),
            "gap_manifest_sha256": gap_manifest_sha256,
            "open_material_diagnosis_count": open_material,
            "diagnostic_pack_sha256": supplement_sha256,
            "coverage_audit_sha256": coverage_audit_sha256,
            **coverage_binding,
            "coverage_audit": dict(coverage_audit),
            "missing_coverage_cell_count": missing_coverage_cell_count,
            "diagnostic_result_manifest_sha256": diagnostic_result_manifest_sha256,
            "diagnostic_cases_join_fixed_denominator": False,
            "unseen_opened": unseen_opened,
            "full_331_plus_32_rerun_required": full_rerun_required,
            "failure_fingerprint_attempt_counts": failure_attempt_counts,
            "open_failure_fingerprints": list(open_fingerprints),
            "repeated_failure_fingerprints": repeated_fingerprints,
            "automatic_retry_allowed": not repeated_stop,
            "next_action": (
                "OWNER_REVIEW_NO_AUTOMATIC_RETRY"
                if repeated_stop
                else "FOLLOW_STATUS_AND_EXIT_CHECKS"
            ),
            "blockers": blocker_values,
            "exit_checks": {
                "exact_fixed_visible_pack": True,
                "all_331_factual_pass": visible_factual_pass == VISIBLE_CASE_COUNT,
                "all_331_meet_70_and_critical_floors": (
                    visible_quality_pass == VISIBLE_CASE_COUNT
                ),
                "all_32_system_pass": system_pass == SYSTEM_SCENARIO_COUNT,
                "all_diagnostics_pass": diagnostic_pass == diagnostic_case_count,
                "no_open_material_diagnoses_or_gaps": open_material == 0,
                "no_missing_coverage_areas": missing_coverage_cell_count == 0,
                "full_changed_binding_rerun_complete": not full_rerun_required,
                "unseen_unopened": not unseen_opened,
                "explicit_owner_acceptance": acceptance_sha256 is not None,
            },
            "decision_basis": decision_basis,
            "decision_basis_sha256": decision_basis_sha256,
            "owner_acceptance_sha256": acceptance_sha256,
            "weight_training_policy": {
                "separate_owner_authorization_required": True,
                "evaluation_content_allowed": False,
                "unseen_content_allowed": False,
                "user_content_allowed": False,
                "training_performed_by_assessment": False,
            },
            # This builder is deliberately pure.  The evaluated cycle may bind
            # separately sealed model, research, catalogue, chunking, embedding,
            # or index evidence; this field describes only this assessment call
            # and must not be read as an execution-history claim for the cycle.
            "assessment_builder_actions_performed": {
                "network": False,
                "model": False,
                "catalogue_write": False,
                "chunking": False,
                "embedding": False,
                "index_write": False,
                "promotion": False,
                "training": False,
                "unseen_run": False,
            },
            "assessed_at": assessed.isoformat(),
        }
    )


def validate_cycle_assessment(assessment: Mapping[str, Any]) -> None:
    """Validate the immutable public shape used by later persistence."""

    _require_self_sealed(assessment, label="GE cycle assessment")
    status = str(assessment.get("status") or "")
    if (
        assessment.get("schema") != "legalbot.ge-cycle-assessment.v2"
        or status
        not in {
            "IMPROVEMENT_REQUIRED",
            "FULL_RERUN_REQUIRED",
            "AWAITING_OWNER_ACCEPTANCE",
            "GE_COMPLETE_OWNER_ACCEPTED",
            "STOP_REPEATED_FINGERPRINT",
        }
        or assessment.get("fixed_visible_denominator") != VISIBLE_CASE_COUNT
        or assessment.get("system_case_count_separate") != SYSTEM_SCENARIO_COUNT
        or assessment.get("candidate_state") != "NON_ACTIVE"
        or assessment.get("promotion_authorized") is not False
        or not isinstance(assessment.get("cycle_number"), int)
        or int(assessment["cycle_number"]) < 1
    ):
        raise GEImprovementLoopError("GE cycle assessment public shape differs")
    _require_id(assessment.get("loop_id"), label="GE loop ID")
    _require_id(assessment.get("cycle_id"), label="GE cycle ID")
    _require_hash(assessment.get("candidate_sha256"), label="candidate digest")
    _require_hash(assessment.get("visible_run_sha256"), label="visible run digest")
    _require_hash(assessment.get("system_run_sha256"), label="system run digest")
    _require_hash(assessment.get("repair_manifest_sha256"), label="repair manifest digest")
    coverage_audit_sha256 = _require_hash(
        assessment.get("coverage_audit_sha256"), label="coverage audit digest"
    )
    _require_hash(assessment.get("decision_basis_sha256"), label="decision basis digest")
    coverage_audit = assessment.get("coverage_audit")
    if not isinstance(coverage_audit, Mapping):
        raise GEImprovementLoopError("GE coverage audit is missing")
    _require_self_sealed(coverage_audit, label="GE coverage audit")
    if (
        coverage_audit.get("content_sha256") != coverage_audit_sha256
        or coverage_audit.get("missing_cell_count")
        != assessment.get("missing_coverage_cell_count")
    ):
        raise GEImprovementLoopError("GE coverage audit binding differs")
    basis = assessment.get("decision_basis")
    if not isinstance(basis, Mapping):
        raise GEImprovementLoopError("GE decision basis is missing")
    _require_self_sealed(basis, label="GE decision basis")
    if (
        basis.get("content_sha256") != assessment.get("decision_basis_sha256")
        or basis.get("coverage_audit_sha256") != coverage_audit_sha256
        or basis.get("missing_coverage_cell_count")
        != assessment.get("missing_coverage_cell_count")
    ):
        raise GEImprovementLoopError("GE decision basis digest differs")
    exit_checks = assessment.get("exit_checks")
    if not isinstance(exit_checks, Mapping) or any(
        type(value) is not bool for value in exit_checks.values()
    ):
        raise GEImprovementLoopError("GE exit checks are invalid")
    actions = assessment.get("assessment_builder_actions_performed")
    if not isinstance(actions, Mapping) or any(value is not False for value in actions.values()):
        raise GEImprovementLoopError("GE assessment performed a prohibited action")
    if status == "GE_COMPLETE_OWNER_ACCEPTED" and (
        assessment.get("owner_acceptance_sha256") is None
        or not all(bool(value) for value in exit_checks.values())
    ):
        raise GEImprovementLoopError("GE completion lacks every exit gate")
    if status == "STOP_REPEATED_FINGERPRINT" and (
        assessment.get("automatic_retry_allowed") is not False
        or not assessment.get("repeated_failure_fingerprints")
    ):
        raise GEImprovementLoopError("repeated-fingerprint stop is not fail-closed")


__all__ = [
    "ROOT_CAUSE_LAYERS",
    "GECoverageCell",
    "GEDiagnosisInput",
    "GEDiagnosticCaseDraft",
    "GEImprovementLoopError",
    "build_completed_system_run",
    "build_coverage_audit",
    "build_coverage_cell_manifest",
    "build_cycle_assessment",
    "build_cycle_owner_acceptance",
    "build_diagnosis",
    "build_diagnostic_case_result",
    "build_official_research_intent",
    "build_successor_candidate_plan",
    "build_system_case_result",
    "build_visible_diagnostic_supplement",
    "build_weight_training_option",
    "validate_completed_system_run",
    "validate_cycle_assessment",
    "validate_diagnosis",
    "validate_diagnostic_case_result",
    "validate_system_case_result",
    "validate_visible_diagnostic_supplement",
]
