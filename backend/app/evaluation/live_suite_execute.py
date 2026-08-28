"""Fail-closed authorization and outcome contracts for Live60 generation.

This module does not invoke the model.  It prevents a future executor from
starting unless Stage A, owner promotion, rollback, browser recovery, readiness
and O-04 are bound to the same run and candidate.  It also enforces exactly one
terminal outcome for each of the 30 selected cases and none for coverage-only
cases.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .browser_recovery import (
    BROWSER_RECOVERY_RELATIVE_PATH,
    verify_browser_recovery_drill,
)
from .live30 import SensitiveArtifactKind
from .live_suite import LiveEvaluationBundle, sealed_sha256
from .live_suite_store import LiveSuiteRunManifest, LiveSuiteRunStore

AUTHORIZATION_SCHEMA = "legalbot.live60-execution-authorization.v1"
OUTCOME_SCHEMA = "legalbot.live60-execution-outcome.v1"
AGGREGATE_SCHEMA = "legalbot.live60-execution-aggregate.v1"


def _reject_browser_drill_as_selected_outcome(*, project_root: Path, job_id: str | None) -> None:
    """Keep the ordinary pre-O-04 drill outside all selected outcomes."""

    if job_id is None:
        return
    drill_path = project_root / BROWSER_RECOVERY_RELATIVE_PATH
    if not drill_path.is_file():
        return
    drill = verify_browser_recovery_drill(drill_path)
    if job_id == drill.job_id:
        raise ValueError("the ordinary browser drill cannot count as a Live60 outcome")


class Live60ExecutionAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-execution-authorization.v1"] = Field(
        default="legalbot.live60-execution-authorization.v1", alias="schema"
    )
    authorization_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    suite_id: Literal["live-evaluation-60-v1"]
    suite_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_plan_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    active_build_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    owner_promotion_ref: str = Field(pattern=r"^promotion:[0-9a-f]{64}$")
    rollback_repromotion_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    browser_recovery_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    readiness_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    readiness_ready: Literal[True]
    readiness_blocker_count: Literal[0]
    o04_authorization_ref: str = Field(pattern=r"^o04:[0-9a-f]{64}$")
    local_only: Literal[True]
    online_research_allowed: Literal[False]
    authorized_pass_count: Literal[1]
    authorized_case_ids: tuple[str, ...]
    issued_at: datetime
    owner_ref: str = Field(pattern=r"^owner:[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def authorization_is_sealed_and_unique(self) -> Self:
        if len(self.authorized_case_ids) != 30 or len(set(self.authorized_case_ids)) != 30:
            raise ValueError("O-04 must authorize exactly 30 unique cases")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("execution authorization seal does not match its contents")
        return self


class Live60ExecutionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live60-execution-outcome.v1"] = Field(
        default="legalbot.live60-execution-outcome.v1", alias="schema"
    )
    outcome_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    pass_number: Literal[1]
    run_plan_disposition: Literal["generate_once"]
    requested_word_target: int = Field(ge=1_000, le=10_000)
    expected_research_route: Literal["sectioned", "full_enquiry"]
    terminal_state: Literal["released", "verified_limited", "held", "system_error"]
    runtime_release_state: (
        Literal["verified_full", "verified_concise", "verified_limited"] | None
    ) = None
    released: bool
    job_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    trace_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_artifact_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    answer_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    word_count: int | None = Field(default=None, ge=0)
    privacy_passed: bool
    evidence_passed: bool
    currentness_passed: bool
    jurisdiction_passed: bool
    citation_passed: bool
    injection_passed: bool
    oscola_passed: bool
    release_gate_report_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    issue_ids: tuple[str, ...] = ()
    knowledge_gap_ids: tuple[str, ...] = ()
    failure_codes: tuple[str, ...] = ()
    completion_duration_ms: int | None = Field(default=None, ge=0)
    completed_at: datetime

    @model_validator(mode="after")
    def release_state_is_consistent(self) -> Self:
        if self.released != (self.terminal_state in {"released", "verified_limited"}):
            raise ValueError("outcome release flag disagrees with terminal state")
        if self.released:
            if not self.answer_artifact_id or not self.answer_sha256 or self.word_count is None:
                raise ValueError("released outcome requires an exact answer artifact")
            if not all(
                (
                    self.privacy_passed,
                    self.evidence_passed,
                    self.currentness_passed,
                    self.jurisdiction_passed,
                    self.citation_passed,
                    self.injection_passed,
                    self.oscola_passed,
                )
            ):
                raise ValueError("released outcome requires every hard release gate")
            if self.release_gate_report_sha256 is None:
                raise ValueError("released outcome requires a release-gate report digest")
            if self.runtime_release_state is not None:
                expected_terminal = (
                    "verified_limited"
                    if self.runtime_release_state == "verified_limited"
                    else "released"
                )
                if self.terminal_state != expected_terminal:
                    raise ValueError("runtime release state disagrees with the terminal outcome")
        elif self.answer_artifact_id is not None or self.answer_sha256 is not None:
            raise ValueError("held/error outcome must not expose an answer artifact")
        elif self.runtime_release_state is not None:
            raise ValueError("held/error outcome cannot claim a public runtime release")
        return self


@dataclass(frozen=True, slots=True)
class Live60ExecutionPreflight:
    run_manifest: LiveSuiteRunManifest
    authorization: Any
    generated_case_ids: tuple[str, ...]
    evidence_ready_case_ids: tuple[str, ...]
    limited_or_held_case_ids: tuple[str, ...]
    limited_case_ids: tuple[str, ...] = ()
    held_case_ids: tuple[str, ...] = ()


def _selected_case_ids(bundle: LiveEvaluationBundle) -> tuple[str, ...]:
    return tuple(
        item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
    )


def live60_evaluation_request_sha256(
    *,
    bundle: LiveEvaluationBundle,
    preflight: Live60ExecutionPreflight,
    case_id: str,
    route: str,
) -> str:
    """Digest every immutable field accepted by the Live60 question API."""

    case = bundle.registry.case(case_id)
    material = {
        "schema": "legalbot.live60-api-admission-request.v1",
        "run_id": preflight.run_manifest.run_id,
        "case_id": case_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
        "authorization_seal_sha256": preflight.authorization.seal_sha256,
        "active_build_id": preflight.authorization.active_build_id,
        "question_sha256": case.question_sha256,
        "task_type": case.task_type,
        "jurisdiction": case.jurisdiction,
        "as_of_date": preflight.run_manifest.as_of_date,
        "word_target": case.word_target,
        "online_mode": "local_only",
        "upload_ids": [],
        "route": route,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def live60_evaluation_request_sha256_v2(
    *,
    bundle: LiveEvaluationBundle,
    authorization: Any,
    case_id: str,
    route: str,
) -> str:
    """Digest the immutable V2 evaluation admission request, pinned to a candidate."""

    case = bundle.registry.case(case_id)
    material = {
        "schema": "legalbot.live60-api-admission-request.v2",
        "evaluation_run_id": authorization.evaluation_run_id,
        "case_id": case_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "run_plan_seal_sha256": bundle.run_plan.seal_sha256,
        "authorization_seal_sha256": authorization.seal_sha256,
        "candidate_build_id": authorization.candidate_build_id,
        "overlay_seal_sha256": authorization.overlay_seal_sha256,
        "stage_a_result_sha256": authorization.stage_a_result_sha256,
        "question_sha256": case.question_sha256,
        "task_type": case.task_type,
        "jurisdiction": case.jurisdiction,
        "as_of_date": authorization.as_of_date,
        "word_target": case.word_target,
        "online_mode": "local_only",
        "upload_ids": [],
        "route": route,
        "writes_active": False,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def load_execution_authorization(
    path: Path,
    *,
    bundle: LiveEvaluationBundle,
    run_manifest: LiveSuiteRunManifest,
) -> Live60ExecutionAuthorization:
    if not path.is_file():
        raise ValueError("O-04 execution authorization is missing")
    authorization = Live60ExecutionAuthorization.model_validate_json(path.read_bytes())
    if authorization.run_id != run_manifest.run_id:
        raise ValueError("authorization is bound to a different run")
    if authorization.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256:
        raise ValueError("authorization is bound to a different suite")
    if authorization.run_plan_seal_sha256 != bundle.run_plan.seal_sha256:
        raise ValueError("authorization is bound to a different run plan")
    if authorization.active_build_id != run_manifest.provenance.index_build_id:
        raise ValueError("authorization is bound to a different ACTIVE candidate")
    if authorization.authorized_case_ids != _selected_case_ids(bundle):
        raise ValueError("authorization case list differs from the sealed run plan")
    return authorization


def verify_execution_prerequisites(
    *,
    store: LiveSuiteRunStore,
    bundle: LiveEvaluationBundle,
    run_id: str,
    authorization_path: Path,
    require_sealed_case_artifacts: bool = False,
) -> Live60ExecutionPreflight:
    manifest = store.load_run_manifest(run_id)
    if manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256:
        raise ValueError("run is bound to a different suite")
    if manifest.run_plan_seal_sha256 != bundle.run_plan.seal_sha256:
        raise ValueError("run is bound to a different generation plan")
    authorization = load_execution_authorization(
        authorization_path, bundle=bundle, run_manifest=manifest
    )
    if require_sealed_case_artifacts:
        expected_authorization_path = (
            store._run_path(run_id) / "execution-authorization.json"
        ).resolve()
        if authorization_path.resolve() != expected_authorization_path:
            raise ValueError("O-04 must be stored inside the immutable run directory")
        from .live_suite import admission_as_of_date

        if admission_as_of_date(authorization.issued_at).isoformat() != manifest.as_of_date:
            raise ValueError("O-04 was issued on a different Europe/London legal date")
    coverage = store.load_safe_run_json(run_id=run_id, filename="coverage-summary.json")
    expected_cases = [case.case_id for case in bundle.registry.cases]
    if (
        coverage.get("schema") != "legalbot.live-coverage-summary.v3"
        or coverage.get("suite_id") != bundle.manifest.suite_id
        or coverage.get("case_count") != bundle.registry.case_count
        or coverage.get("case_ids") != expected_cases
        or coverage.get("stage_a_evaluated") is not True
        or coverage.get("stage_a_passed") is not True
        or coverage.get("generation_started") is not False
    ):
        raise ValueError("Stage A coverage is incomplete or failed")
    recall_at_5 = coverage.get("recall_at_5")
    recall_at_10 = coverage.get("recall_at_10")
    mrr = coverage.get("mrr")
    if (
        not isinstance(recall_at_5, int | float)
        or float(recall_at_5) != 1.0
        or not isinstance(recall_at_10, int | float)
        or float(recall_at_10) < 0.95
        or not isinstance(mrr, int | float)
        or float(mrr) < 0.8
        or coverage.get("filter_violation_count") != 0
        or coverage.get("route_pass_count") != bundle.registry.case_count
        or coverage.get("subject_routing_pass_count") != bundle.registry.case_count
        or coverage.get("ranking_metric_state") != "evaluated_against_sealed_qualifying_issue_gold"
        or not isinstance(coverage.get("expert_qualification_sha256"), str)
    ):
        raise ValueError("Stage A metric gates are inconsistent with a passing result")
    if coverage.get("index_build_id") != manifest.provenance.index_build_id:
        raise ValueError("Stage A coverage used a different candidate build")
    if require_sealed_case_artifacts:
        from datetime import date

        from .live_suite_gold import load_suite_expert_qualification

        qualification = load_suite_expert_qualification(
            store._run_path(run_id) / "expert-qualification.json",
            bundle=bundle,
            index_build_id=str(manifest.provenance.index_build_id or ""),
            as_of_date=date.fromisoformat(manifest.as_of_date),
        )
        if qualification.seal_sha256 != coverage.get("expert_qualification_sha256"):
            raise ValueError("Stage A differs from the sealed qualification")
    selected = _selected_case_ids(bundle)
    ready_value = coverage.get("selected_generation_eligible_case_ids")
    if not isinstance(ready_value, list) or any(not isinstance(item, str) for item in ready_value):
        raise ValueError("Stage A eligible-case list is invalid")
    ready = tuple(case_id for case_id in selected if case_id in ready_value)
    if set(ready_value) - set(selected):
        raise ValueError("Stage A enabled a coverage-only case")
    limited = tuple(case_id for case_id in selected if case_id not in ready)
    raw_limited = coverage.get("deterministic_limited_case_ids", [])
    raw_held = coverage.get("deterministic_held_case_ids", [])
    if not isinstance(raw_limited, list) or any(not isinstance(item, str) for item in raw_limited):
        raise ValueError("Stage A limited-case list is invalid")
    if not isinstance(raw_held, list) or any(not isinstance(item, str) for item in raw_held):
        raise ValueError("Stage A held-case list is invalid")
    listed_limited = tuple(case_id for case_id in selected if case_id in raw_limited)
    listed_held = tuple(case_id for case_id in selected if case_id in raw_held)
    if (set(raw_limited) | set(raw_held)) - set(selected):
        raise ValueError("Stage A classified a coverage-only case for generation")
    if set(listed_limited) & set(listed_held):
        raise ValueError("Stage A classified a case as both limited and held")
    if raw_limited or raw_held:
        if set(listed_limited) | set(listed_held) != set(limited):
            raise ValueError("Stage A non-generation dispositions are incomplete")
    else:
        # Compatibility for early v3 fixtures. Real Stage A outputs always
        # persist the two explicit deterministic disposition lists.
        listed_held = limited
    if require_sealed_case_artifacts:
        for item in bundle.run_plan.cases:
            case_coverage = store.load_safe_case_json(
                run_id=run_id,
                case_id=item.case_id,
                filename="coverage.json",
            )
            expected_eligible = item.case_id in ready
            expected_outcome = (
                "coverage_only_not_selected"
                if item.disposition == "coverage_only_not_selected"
                else "generate"
                if expected_eligible
                else "limited"
                if item.case_id in listed_limited
                else "held"
            )
            if (
                case_coverage.get("schema") != "legalbot.live-coverage.v3"
                or case_coverage.get("run_id") != run_id
                or case_coverage.get("case_id") != item.case_id
                or case_coverage.get("run_plan_disposition") != item.disposition
                or case_coverage.get("selected_generation_eligible") is not expected_eligible
                or case_coverage.get("deterministic_outcome") != expected_outcome
            ):
                raise ValueError("per-case Stage A disposition differs from the sealed run summary")
    return Live60ExecutionPreflight(
        run_manifest=manifest,
        authorization=authorization,
        generated_case_ids=selected,
        evidence_ready_case_ids=ready,
        limited_or_held_case_ids=limited,
        limited_case_ids=listed_limited,
        held_case_ids=listed_held,
    )


def record_terminal_outcome(
    *,
    store: LiveSuiteRunStore,
    bundle: LiveEvaluationBundle,
    preflight: Live60ExecutionPreflight,
    outcome: Live60ExecutionOutcome,
) -> Path:
    _reject_browser_drill_as_selected_outcome(
        project_root=store.project_root,
        job_id=outcome.job_id,
    )
    if outcome.run_id != preflight.run_manifest.run_id:
        raise ValueError("outcome is bound to another run")
    if outcome.case_id not in preflight.generated_case_ids:
        raise ValueError("coverage-only case cannot receive a generation outcome")
    case = bundle.registry.case(outcome.case_id)
    if (
        outcome.requested_word_target != case.word_target
        or outcome.expected_research_route != case.expected_research_route
    ):
        raise ValueError("outcome differs from the immutable question contract")
    if (
        outcome.case_id in preflight.limited_or_held_case_ids
        and outcome.terminal_state == "released"
    ):
        raise ValueError("evidence-limited case cannot release a full answer")
    if outcome.released:
        assert outcome.answer_artifact_id is not None
        assert outcome.answer_sha256 is not None
        answer = store.load_sensitive_artifact(
            run_id=outcome.run_id,
            case_id=outcome.case_id,
            kind=SensitiveArtifactKind.ANSWER,
            artifact_id=outcome.answer_artifact_id,
        )
        if hashlib.sha256(answer.encode("utf-8")).hexdigest() != outcome.answer_sha256:
            raise ValueError("terminal outcome answer digest is incorrect")
    return store.store_safe_case_json(
        run_id=outcome.run_id,
        case_id=outcome.case_id,
        filename="outcome.json",
        value=outcome.model_dump(mode="json", by_alias=True),
    )


def finalize_single_pass_outcomes(
    *,
    store: LiveSuiteRunStore,
    bundle: LiveEvaluationBundle,
    run_id: str,
) -> dict[str, Any]:
    selected = _selected_case_ids(bundle)
    run_manifest = store.load_run_manifest(run_id)
    if (
        run_manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or run_manifest.run_plan_seal_sha256 != bundle.run_plan.seal_sha256
    ):
        raise ValueError("run finalization is bound to another suite or plan")
    for item in bundle.run_plan.cases:
        if item.disposition != "coverage_only_not_selected":
            continue
        if (store._case_path(run_id, item.case_id) / "outcome.json").exists():
            raise ValueError("coverage-only case has an illegal generation outcome")
    outcomes: list[Live60ExecutionOutcome] = []
    for case_id in selected:
        path = store._case_path(run_id, case_id) / "outcome.json"
        if not path.is_file():
            raise ValueError("selected case has no terminal outcome")
        outcome = Live60ExecutionOutcome.model_validate_json(path.read_bytes())
        _reject_browser_drill_as_selected_outcome(
            project_root=store.project_root,
            job_id=outcome.job_id,
        )
        if outcome.run_id != run_id or outcome.case_id != case_id:
            raise ValueError("terminal outcome identity differs from its location")
        outcomes.append(outcome)
    if len({outcome.outcome_id for outcome in outcomes}) != len(outcomes):
        raise ValueError("terminal outcome IDs are duplicated")
    terminal_counts = Counter(outcome.terminal_state for outcome in outcomes)
    aggregate: dict[str, Any] = {
        "schema": AGGREGATE_SCHEMA,
        "run_id": run_id,
        "suite_id": bundle.manifest.suite_id,
        "run_plan_id": bundle.run_plan.run_plan_id,
        "case_count": 30,
        "pass_count": 1,
        "stability_repeats": 0,
        "case_ids": list(selected),
        "coverage_only_not_selected_case_ids": [
            item.case_id
            for item in bundle.run_plan.cases
            if item.disposition == "coverage_only_not_selected"
        ],
        "terminal_state_counts": dict(sorted(terminal_counts.items())),
        "released_case_ids": [outcome.case_id for outcome in outcomes if outcome.released],
        "held_or_error_case_ids": [outcome.case_id for outcome in outcomes if not outcome.released],
        "complete": True,
        "evaluation_only": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    aggregate_path = store._run_path(run_id) / "aggregate-metrics.json"
    if aggregate_path.is_file():
        existing = store.load_safe_run_json(run_id=run_id, filename="aggregate-metrics.json")
        if existing != aggregate:
            raise ValueError("immutable run aggregate differs from terminal outcomes")
        return existing
    store.store_safe_run_json(run_id=run_id, filename="aggregate-metrics.json", value=aggregate)
    return aggregate
