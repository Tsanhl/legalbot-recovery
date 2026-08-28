"""Fail-closed localhost execution and finalisation for live-evaluation-30-v1.

This module makes no index or source decisions.  It will submit questions only
after a sealed expert overlay, a passing 30-case coverage result and the exact
promoted ACTIVE build reconcile.  It captures released prose only in encrypted
artifacts; normal outcomes, indexes, logs and review manifests contain safe
identifiers and metrics.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..assessment.guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    budget_assessment_guidance,
)
from ..config import Settings
from ..db import Database
from ..jurisdictions import compatible
from ..legal_roles import MATERIAL_CASE_ROLES, REPORT_LEGAL_ROLES
from ..privacy import contains_absolute_private_path
from ..retrieval.service import HybridRetrievalService
from ..retrieval.source_manifest import approved_source_manifest_sha256
from ..text_metrics import word_count
from .live30 import (
    EXPECTED_CASE_IDS,
    STRATIFIED_SAMPLE_IDS,
    E2ERunEvent,
    Live30RunStore,
    LiveEvaluationCase,
    LiveEvaluationSuite,
    RunEventType,
    RunStage,
    RunStatus,
    SensitiveArtifactKind,
    assert_safe_evaluation_payload,
)
from .live30_gold import load_expert_qualification
from .review_docx import (
    LiveReviewCase,
    LiveReviewExport,
    SafeEvidenceRecord,
    SafeGapRecord,
    SafeMetric,
    SafeRepairRecord,
    SafeRubricResult,
)

EXECUTION_OUTCOME_SCHEMA = "legalbot.live30-execution-outcome.v1"
RUN_PRIVACY_SCHEMA = "legalbot.live30-run-privacy-report.v1"
PUBLIC_RELEASES = frozenset({"verified_full", "verified_concise", "verified_limited"})
TERMINAL_JOB_STATES = frozenset(
    {"complete", "held_for_review", "system_error", "cancelled", "failed", "dlq"}
)
STAGE_A_RECALL_AT_5_MIN = 1.0
STAGE_A_RECALL_AT_10_MIN = 0.95
STAGE_A_MRR_MIN = 0.8


class LocalEvaluationClient(Protocol):
    async def get(self, url: str, **kwargs: Any) -> Any: ...
    async def post(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class ExecutionPreflight:
    run_id: str
    base_url: str
    index_build_id: str
    model_version: str
    policy_sha256: str
    assessment_bundle_sha256: str
    qualification_sha256: str
    owner_identifiers: tuple[str, ...]
    generation_eligible_case_ids: tuple[str, ...]
    limited_case_ids: tuple[str, ...] = ()
    knowledge_gap_case_ids: tuple[str, ...] = ()
    held_case_ids: tuple[str, ...] = ()


class ExecutionOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: str = Field(default=EXECUTION_OUTCOME_SCHEMA, alias="schema")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    case_id: str = Field(pattern=r"^live30-q(?:0[1-9]|[12][0-9]|30)$")
    pass_number: int = Field(ge=1, le=3)
    job_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    trace_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    status: Literal["completed", "held", "system_error", "cancelled"]
    release_state: Literal[
        "verified_full",
        "verified_concise",
        "verified_limited",
        "held",
        "not_released",
        "privacy_failed",
        "evidence_failed",
    ]
    released: bool
    privacy_passed: bool
    evidence_passed: bool
    answer_artifact_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    answer_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    word_count: int | None = Field(default=None, ge=0, le=100_000)
    word_target: int = Field(ge=1_000, le=10_000)
    word_target_within_tolerance: bool | None = None
    word_target_delta: int | None = None
    route: Literal["direct", "sectioned", "full_enquiry"]
    model_version: str | None = None
    index_build_id: str | None = None
    policy_version: str | None = None
    assessment_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_rule_ids: tuple[str, ...]
    triggered_assessment_rule_ids: tuple[str, ...] = ()
    evidence: tuple[SafeEvidenceRecord, ...] = ()
    rubric: tuple[SafeRubricResult, ...] = ()
    repairs: tuple[SafeRepairRecord, ...] = ()
    issue_ids: tuple[str, ...] = ()
    knowledge_gap_ids: tuple[str, ...] = ()
    failure_codes: tuple[str, ...] = ()
    completion_duration_ms: int = Field(ge=0)

    @field_validator("model_version", "index_build_id", "policy_version")
    @classmethod
    def version_is_safe(cls, value: str | None) -> str | None:
        if value is not None and ("\n" in value or contains_absolute_private_path(value)):
            raise ValueError("runtime version contains prohibited metadata")
        return value

    @model_validator(mode="after")
    def release_contract_is_consistent(self) -> ExecutionOutcome:
        public = self.release_state in PUBLIC_RELEASES
        if public != self.released:
            raise ValueError("outcome released flag disagrees with release state")
        if public and (
            self.status != "completed"
            or not self.privacy_passed
            or not self.evidence_passed
            or not self.answer_artifact_id
            or not self.answer_sha256
            or self.word_count is None
        ):
            raise ValueError("released outcome did not pass its capture gates")
        return self


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"required live-evaluation artifact is missing: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"live-evaluation artifact is not an object: {path.name}")
    assert_safe_evaluation_payload(value)
    return value


def _normal_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("live evaluation API must be an uncredentialed loopback HTTP origin")
    return value.rstrip("/")


def _validate_current_law_manifest(
    source_manifest: Mapping[str, Any],
    *,
    expected_sha256: str,
    run_as_of_date: str,
) -> dict[str, Mapping[str, Any]]:
    observed_sha256 = str(source_manifest.get("manifest_sha256") or "")
    if (
        observed_sha256 != expected_sha256
        or approved_source_manifest_sha256(source_manifest) != expected_sha256
    ):
        raise RuntimeError("ACTIVE approved-source manifest digest is inconsistent")
    if str(source_manifest.get("current_law_as_of_date") or "") != run_as_of_date:
        raise RuntimeError("ACTIVE current-law snapshot date differs from the run date")
    sources = source_manifest.get("sources")
    if not isinstance(sources, list):
        raise RuntimeError("ACTIVE approved-source manifest sources are invalid")
    return {
        str(item.get("source_version_id") or ""): item
        for item in sources
        if isinstance(item, Mapping) and item.get("source_version_id")
    }


def _gold_source_is_current_for_run(source: Mapping[str, Any], *, run_as_of_date: str) -> bool:
    # A judgment's immutable ``as_of_date`` may be its decision date. Current
    # law is instead bound to the separate later-treatment/currentness review.
    return bool(
        str(source.get("currentness_reviewed_as_of_date") or "") == run_as_of_date
        and source.get("full_current_law_verification_eligible") is True
    )


def _enforce_stage_a_thresholds(coverage: Mapping[str, Any]) -> None:
    """Apply the owner-approved ranking gates to qualifying issue gold only."""

    scored_issue_count = coverage.get("scored_issue_count")
    if (
        isinstance(scored_issue_count, bool)
        or not isinstance(scored_issue_count, int)
        or scored_issue_count <= 0
    ):
        raise RuntimeError("Stage A has no annotated qualifying issues to score")
    required_metrics = (
        "recall_at_5",
        "recall_at_10",
        "mrr",
        "ndcg_at_10",
        "exact_span_recall",
        "contrary_authority_recall",
    )
    metrics: dict[str, float] = {}
    for key in required_metrics:
        observed = coverage.get(key)
        if isinstance(observed, bool) or not isinstance(observed, int | float):
            raise RuntimeError("sealed Stage A retrieval metrics are incomplete")
        metric = float(observed)
        if not math.isfinite(metric) or not 0.0 <= metric <= 1.0:
            raise RuntimeError("sealed Stage A retrieval metrics are outside [0, 1]")
        metrics[key] = metric
    if metrics["recall_at_5"] < STAGE_A_RECALL_AT_5_MIN:
        raise RuntimeError("Stage A Recall@5 is below the required 1.0")
    if metrics["recall_at_10"] < STAGE_A_RECALL_AT_10_MIN:
        raise RuntimeError("Stage A Recall@10 is below the required 0.95")
    if metrics["mrr"] < STAGE_A_MRR_MIN:
        raise RuntimeError("Stage A MRR is below the required 0.8")


def verify_execution_prerequisites(
    *,
    project_root: Path,
    store: Live30RunStore,
    suite: LiveEvaluationSuite,
    run_id: str,
    base_url: str,
) -> ExecutionPreflight:
    """Verify immutable filesystem gold and the exact promoted ACTIVE runtime."""

    manifest = store.load_run_manifest(run_id)
    if manifest.suite_canonical_sha256 != suite.canonical_sha256:
        raise RuntimeError("run is bound to a different live-30 suite")
    provenance = manifest.provenance
    required_versions = (
        provenance.model_version,
        provenance.index_build_id,
        provenance.prompt_version,
        provenance.router_version,
        provenance.classifier_version,
        provenance.policy_sha256,
        provenance.assessment_rules_sha256,
    )
    if any(value is None for value in required_versions):
        raise RuntimeError("run provenance is incomplete; execution is blocked")
    if provenance.git_dirty:
        raise RuntimeError("controlled live evaluation requires a clean committed checkpoint")

    run_root = store.runs_root / run_id
    build_id = cast(str, provenance.index_build_id)
    qualification = load_expert_qualification(
        run_root / "expert-qualification.json",
        suite=suite,
        index_build_id=build_id,
        as_of_date=manifest.as_of_date,
    )
    coverage = _load_json_object(run_root / "coverage-summary.json")
    if (
        coverage.get("schema") != "legalbot.live30-coverage-summary.v2"
        or coverage.get("case_ids") != list(EXPECTED_CASE_IDS)
        or int(coverage.get("case_count") or 0) != 30
        or coverage.get("ranking_metric_state") != "evaluated_against_sealed_qualifying_issue_gold"
        or coverage.get("expert_qualification_sha256") != qualification.seal_sha256
        or coverage.get("generation_started") is not False
    ):
        raise RuntimeError("coverage and sealed issue dispositions do not reconcile")
    expected_scored_issue_count = sum(
        issue.status == "qualified"
        for case_qualification in qualification.cases
        for issue in case_qualification.issues
    )
    if coverage.get("scored_issue_count") != expected_scored_issue_count:
        raise RuntimeError("Stage A denominator differs from sealed qualifying issue dispositions")
    _enforce_stage_a_thresholds(coverage)
    generation_eligible_case_ids: list[str] = []
    limited_case_ids: list[str] = []
    knowledge_gap_case_ids: list[str] = []
    held_case_ids: list[str] = []
    for case_id in EXPECTED_CASE_IDS:
        case_coverage = _load_json_object(run_root / "cases" / case_id / "coverage.json")
        if (
            case_coverage.get("schema") != "legalbot.live30-coverage.v2"
            or case_coverage.get("case_id") != case_id
        ):
            raise RuntimeError("per-case coverage identity is invalid")
        qualification_status = case_coverage.get("expert_qualification_status")
        case_qualification = qualification.case(case_id)
        expected_case_scored_issues = sum(
            issue.status == "qualified" for issue in case_qualification.issues
        )
        if (
            qualification_status != case_qualification.status
            or case_coverage.get("scored_issue_count") != expected_case_scored_issues
        ):
            raise RuntimeError("per-case expert qualification disposition is invalid")
        generation_eligible = case_coverage.get("generation_eligible") is True
        expected_outcome = (
            "generate"
            if generation_eligible
            else "limited"
            if qualification_status == "limited"
            else "held"
        )
        if case_coverage.get("deterministic_outcome") != expected_outcome:
            raise RuntimeError("per-case deterministic coverage outcome is invalid")
        if generation_eligible:
            if qualification_status != "qualified":
                raise RuntimeError("non-qualified case was marked generation eligible")
            generation_eligible_case_ids.append(case_id)
        elif qualification_status == "limited":
            limited_case_ids.append(case_id)
        elif qualification_status == "knowledge_gap":
            knowledge_gap_case_ids.append(case_id)
        else:
            held_case_ids.append(case_id)

    settings = Settings(project_root=project_root.resolve())
    database = Database(settings.database_path)
    database.initialize()
    try:
        row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
        if row is None or str(row["status"]) != "active":
            raise RuntimeError("run candidate is not the promoted ACTIVE build")
        active = HybridRetrievalService(settings, database).active_build_id()
        if active != build_id:
            raise RuntimeError("ACTIVE pointer/catalogue identity differs from the run")
        if str(row["policy_sha256"] or "") != provenance.policy_sha256:
            raise RuntimeError("ACTIVE quality policy differs from the run manifest")
        if str(row["assessment_bundle_sha256"] or "") != provenance.assessment_rules_sha256:
            raise RuntimeError("ACTIVE assessment bundle differs from the run manifest")
        source_manifest_path = (
            settings.index_dir / "builds" / build_id / "approved-source-manifest.json"
        )
        try:
            source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("ACTIVE approved-source manifest is missing or invalid") from exc
        if not isinstance(source_manifest, dict):
            raise RuntimeError("ACTIVE approved-source manifest is not an object")
        manifest_sources = _validate_current_law_manifest(
            source_manifest,
            expected_sha256=str(row["source_manifest_hash"] or ""),
            run_as_of_date=manifest.as_of_date.isoformat(),
        )
        for case_qualification in qualification.cases:
            for gold in case_qualification.exact_gold_spans:
                source = database.fetchone(
                    """
                    SELECT sv.review_status, sv.authority_identity_id, d.source_identity_id
                    FROM source_versions sv
                    JOIN documents d ON d.id=sv.document_id
                    WHERE sv.id=?
                    """,
                    (gold.source_version_id,),
                )
                if source is None or str(source["review_status"]) != "approved":
                    raise RuntimeError("expert gold names a missing or unapproved source version")
                if str(source["source_identity_id"] or "") != gold.stable_source_id:
                    raise RuntimeError("expert gold stable source ID and source version disagree")
                if (
                    gold.legal_authority_id is not None
                    and str(source["authority_identity_id"] or "") != gold.legal_authority_id
                ):
                    raise RuntimeError("expert gold legal authority ID and source version disagree")
                frozen_source = manifest_sources.get(gold.source_version_id)
                if frozen_source is None:
                    raise RuntimeError("expert gold source is absent from the ACTIVE manifest")
                if gold.source_type == "case" and gold.legal_role in MATERIAL_CASE_ROLES:
                    review = gold.case_currentness_review
                    if (
                        review is None
                        or not review.qualifies_for_present_law
                        or review.later_treatment_reviewed_as_of_date != manifest.as_of_date
                    ):
                        raise RuntimeError(
                            "expert case gold lacks an exact run-date proposition review"
                        )
                elif gold.source_type != "case" and not _gold_source_is_current_for_run(
                    frozen_source,
                    run_as_of_date=manifest.as_of_date.isoformat(),
                ):
                    raise RuntimeError(
                        "expert gold lacks run-date currentness, extent or effect verification"
                    )
    finally:
        database.close()
    return ExecutionPreflight(
        run_id=run_id,
        base_url=_normal_base_url(base_url),
        index_build_id=build_id,
        model_version=cast(str, provenance.model_version),
        policy_sha256=provenance.policy_sha256,
        assessment_bundle_sha256=provenance.assessment_rules_sha256,
        qualification_sha256=qualification.seal_sha256,
        owner_identifiers=tuple(settings.owner_identifiers),
        generation_eligible_case_ids=tuple(generation_eligible_case_ids),
        limited_case_ids=tuple(limited_case_ids),
        knowledge_gap_case_ids=tuple(knowledge_gap_case_ids),
        held_case_ids=tuple(held_case_ids),
    )


def _json_response(response: Any, *, expected: Sequence[int]) -> dict[str, Any]:
    status_code = int(getattr(response, "status_code", 0))
    if status_code not in expected:
        raise RuntimeError(f"localhost API returned unexpected status {status_code}")
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("localhost API returned a non-object response")
    return value


def _safe_evidence_records(
    payload: Mapping[str, Any], *, requested_jurisdiction: str
) -> tuple[SafeEvidenceRecord, ...]:
    raw_claims = payload.get("claims")
    raw_evidence = payload.get("evidence")
    claims: list[Any] = raw_claims if isinstance(raw_claims, list) else []
    evidence: list[Any] = raw_evidence if isinstance(raw_evidence, list) else []
    supported: set[str] = set()
    for claim in claims:
        if not isinstance(claim, Mapping) or not bool(claim.get("material")):
            continue
        if str(claim.get("verification_status")) not in {"verified", "supported", "passed"}:
            continue
        ids = claim.get("evidence_ids")
        if isinstance(ids, list):
            supported.update(str(item) for item in ids)
    records: list[SafeEvidenceRecord] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        evidence_id = str(item.get("id") or "")
        source_version_id = str(item.get("source_version_id") or "")
        if not evidence_id or not source_version_id:
            raise RuntimeError("released evidence omitted a stable identity")
        identity_verified = item.get("identity_verified") is True
        currentness_verified = item.get("currentness_verified") is True
        currentness_status = str(item.get("currentness_status") or "unknown")
        if currentness_status == "historical":
            currentness_state = "historical"
        elif not currentness_verified:
            currentness_state = "unverified"
        elif currentness_status == "latest_available_revised_snapshot":
            currentness_state = "latest_available_revised_snapshot"
        elif currentness_status == "not_applicable":
            currentness_state = "not_applicable"
        elif currentness_status in {"later_treatment_checked", "point_in_time"}:
            currentness_state = "verified_current"
        else:
            currentness_state = "unverified"
        legal_role = str(item.get("legal_role") or "unclassified")
        if legal_role not in REPORT_LEGAL_ROLES:
            legal_role = "unclassified"
        raw_citation = item.get("citation_data")
        citation_data: Mapping[str, Any] = raw_citation if isinstance(raw_citation, Mapping) else {}
        source_jurisdiction = str(item.get("jurisdiction") or "")
        jurisdiction_state = (
            "verified"
            if source_jurisdiction
            and compatible(
                requested_jurisdiction,
                source_jurisdiction,
                citation_data,
            )
            else "unverified"
        )
        locator = " ".join(str(item.get("locator") or "").split())
        if not locator:
            raise RuntimeError("released evidence omitted its legal locator")
        records.append(
            SafeEvidenceRecord(
                evidence_span_id=evidence_id,
                stable_source_id=source_version_id,
                legal_locator=locator,
                legal_role=cast(Any, legal_role),
                identity_state="verified" if identity_verified else "unverified",
                support_state="supported" if evidence_id in supported else "partial",
                currentness_state=cast(Any, currentness_state),
                jurisdiction_state=cast(Any, jurisdiction_state),
            )
        )
    return tuple(records)


def _material_evidence_is_qualified(records: Sequence[SafeEvidenceRecord]) -> bool:
    supported = tuple(item for item in records if item.support_state == "supported")
    return bool(supported) and all(
        item.identity_state == "verified"
        and item.currentness_state
        in {
            "verified_current",
            "latest_available_revised_snapshot",
            "not_applicable",
        }
        and item.jurisdiction_state in {"verified", "not_applicable"}
        for item in supported
    )


def _has_material_claims(payload: Mapping[str, Any]) -> bool:
    claims = payload.get("claims")
    return bool(
        isinstance(claims, list)
        and any(isinstance(item, Mapping) and item.get("material") is True for item in claims)
    )


def _privacy_failure(answer: str, owner_identifiers: Sequence[str]) -> bool:
    folded = answer.casefold()
    return contains_absolute_private_path(answer) or any(
        identifier.strip() and identifier.casefold() in folded for identifier in owner_identifiers
    )


def _selected_assessment_rule_ids(case: LiveEvaluationCase) -> tuple[str, ...]:
    guidance = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type=case.task_type,
        subject=case.subject,
        max_characters=1_800,
    )
    return tuple(item.rule_id for item in guidance.selected_rules)


def _triggered_assessment_rule_ids(
    case: LiveEvaluationCase, quality: Mapping[str, Any]
) -> tuple[str, ...]:
    raw = quality.get("findings_json")
    try:
        findings = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        findings = []
    if not isinstance(findings, list):
        return ()
    criteria: set[str] = set()
    authority_codes = {
        "unsupported_material_law",
        "wrong_authority_identity",
        "non_authority_lane",
        "wrong_jurisdiction",
        "unverified_case_legal_role",
        "unrelated_evidence",
        "unsupported_material_fact",
        "non_atomic_material_claim",
        "false_quotation",
    }
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        code = str(finding.get("code") or "")
        if code in authority_codes:
            criteria.add("authority_accuracy")
        elif code == "rubric_cap_missing_application":
            criteria.add("application")
        elif code == "rubric_cap_missing_remedies":
            criteria.add("remedies")
        elif code == "rubric_cap_missing_thesis":
            criteria.add("thesis")
        elif code == "rubric_cap_missing_scholarship":
            criteria.add("scholarship")
        elif code == "material_contradiction":
            criteria.add("analysis")
        elif code.startswith("rubric_reason_"):
            criterion = code.removeprefix("rubric_reason_")
            if criterion:
                criteria.add(criterion)
    guidance = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type=case.task_type,
        subject=case.subject,
        max_characters=1_800,
    )
    return tuple(
        rule.rule_id
        for rule in guidance.selected_rules
        if rule.anti_pattern is not None and rule.criterion in criteria
    )


class Live30Executor:
    def __init__(
        self,
        *,
        store: Live30RunStore,
        suite: LiveEvaluationSuite,
        preflight: ExecutionPreflight,
        client: LocalEvaluationClient,
        poll_interval_seconds: float = 2.0,
        case_timeout_seconds: float = 14_400.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.store = store
        self.suite = suite
        self.preflight = preflight
        self.client = client
        self.poll_interval_seconds = poll_interval_seconds
        self.case_timeout_seconds = case_timeout_seconds
        self.sleep = sleep

    async def verify_api_health(self) -> None:
        value = _json_response(
            await self.client.get(f"{self.preflight.base_url}/api/v1/health"),
            expected=(200,),
        )
        if (
            value.get("status") != "ready"
            or value.get("worker_ready") is not True
            or value.get("model_ready") is not True
            or value.get("active_index") != self.preflight.index_build_id
            or value.get("model_id") != self.preflight.model_version
        ):
            raise RuntimeError("localhost API/model/worker identities are not ready for this run")

    async def execute(
        self, *, pass_number: int, stability_sample: bool = False
    ) -> tuple[ExecutionOutcome, ...]:
        if pass_number not in {1, 2, 3}:
            raise ValueError("live-30 pass number must be 1, 2 or 3")
        if stability_sample != (pass_number in {2, 3}):
            raise ValueError("passes 2 and 3 are restricted to the frozen stability sample")
        await self.verify_api_health()
        selected = set(STRATIFIED_SAMPLE_IDS) if stability_sample else set(EXPECTED_CASE_IDS)
        outcomes: list[ExecutionOutcome] = []
        for case in self.suite.cases:
            if case.case_id in selected:
                outcomes.append(await self._execute_case(case, pass_number=pass_number))
        return tuple(outcomes)

    async def _execute_case(
        self, case: LiveEvaluationCase, *, pass_number: int
    ) -> ExecutionOutcome:
        existing = self.store.load_safe_case_pass_json(
            run_id=self.preflight.run_id,
            case_id=case.case_id,
            pass_number=pass_number,
        )
        if existing is not None:
            outcome = ExecutionOutcome.model_validate(existing)
            if (
                outcome.run_id != self.preflight.run_id
                or outcome.case_id != case.case_id
                or outcome.pass_number != pass_number
            ):
                raise RuntimeError("stored pass outcome identity check failed")
            return outcome
        started = time.monotonic()
        if case.case_id not in self.preflight.generation_eligible_case_ids:
            failure_code = (
                "expert_qualification_limited"
                if case.case_id in self.preflight.limited_case_ids
                else "expert_qualification_knowledge_gap"
                if case.case_id in self.preflight.knowledge_gap_case_ids
                else "coverage_not_generation_eligible"
            )
            return self._store_nonrelease(
                case,
                pass_number=pass_number,
                job_id=None,
                trace_id=None,
                status="held",
                failure_code=failure_code,
                started=started,
            )
        job_id: str | None = None
        trace_id: str | None = None
        self.store.record_case_status(
            run_id=self.preflight.run_id,
            case_id=case.case_id,
            status=RunStatus.QUEUED,
        )
        self.store.record_event(
            E2ERunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=datetime.now(UTC),
                run_id=self.preflight.run_id,
                case_id=case.case_id,
                event_type=RunEventType.CASE_STARTED,
                stage=RunStage.INTAKE,
                status=RunStatus.QUEUED,
                attempt=pass_number,
            )
        )
        safe_failure_code = "question_admission_failed"
        try:
            idempotency = hashlib.sha256(
                f"{self.preflight.run_id}\0{case.case_id}\0{pass_number}".encode()
            ).hexdigest()
            accepted = _json_response(
                await self.client.post(
                    f"{self.preflight.base_url}/api/v1/questions",
                    headers={
                        "X-Evaluation-Run-ID": self.preflight.run_id,
                        "X-Evaluation-Case-ID": case.case_id,
                        "X-Idempotency-Key": f"live30-{idempotency[:40]}",
                    },
                    json={
                        "question": case.question,
                        "task_type": case.task_type,
                        "jurisdiction": case.jurisdiction,
                        "as_of_date": self.store.load_run_manifest(
                            self.preflight.run_id
                        ).as_of_date.isoformat(),
                        "word_target": case.word_target,
                        "online_mode": "local_only",
                        "upload_ids": [],
                    },
                ),
                expected=(202,),
            )
            job_id = str(accepted.get("job_id") or "")
            if not job_id:
                raise RuntimeError("question admission omitted the job identity")
            safe_failure_code = "job_poll_failed"
            terminal: dict[str, Any] | None = None
            while time.monotonic() - started < self.case_timeout_seconds:
                observed = _json_response(
                    await self.client.get(f"{self.preflight.base_url}/api/v1/jobs/{job_id}"),
                    expected=(200,),
                )
                trace_id = str(observed.get("trace_id") or "") or None
                if str(observed.get("status")) in TERMINAL_JOB_STATES:
                    terminal = observed
                    break
                await self.sleep(self.poll_interval_seconds)
            if terminal is None:
                await self.client.post(f"{self.preflight.base_url}/api/v1/jobs/{job_id}/cancel")
                return self._store_nonrelease(
                    case,
                    pass_number=pass_number,
                    job_id=job_id,
                    trace_id=trace_id,
                    status="system_error",
                    failure_code="evaluation_poll_timeout",
                    started=started,
                )
            if terminal.get("status") != "complete":
                status_value = str(terminal.get("status"))
                return self._store_nonrelease(
                    case,
                    pass_number=pass_number,
                    job_id=job_id,
                    trace_id=trace_id,
                    status=(
                        "held"
                        if status_value == "held_for_review"
                        else "cancelled"
                        if status_value == "cancelled"
                        else "system_error"
                    ),
                    failure_code=(
                        "held_for_review"
                        if status_value == "held_for_review"
                        else "job_cancelled"
                        if status_value == "cancelled"
                        else "system_error"
                    ),
                    started=started,
                )
            release_state = str(terminal.get("release_state") or "")
            answer_id = str(terminal.get("answer_id") or "")
            safe_failure_code = "terminal_release_invalid"
            if release_state not in PUBLIC_RELEASES or not answer_id:
                raise RuntimeError("completed job has no public terminal release")
            safe_failure_code = "answer_capture_failed"
            answer = _json_response(
                await self.client.get(f"{self.preflight.base_url}/api/v1/answers/{answer_id}"),
                expected=(200,),
            )
            if (
                answer.get("job_id") != job_id
                or answer.get("release_state") != release_state
                or answer.get("index_build_id") != self.preflight.index_build_id
            ):
                raise RuntimeError("released answer identities differ from the frozen run")
            content = answer.get("content")
            if not isinstance(content, str) or not content.strip():
                raise RuntimeError("released answer content is missing")
            raw_quality = answer.get("quality")
            quality: Mapping[str, Any] = raw_quality if isinstance(raw_quality, Mapping) else {}
            privacy_passed = not _privacy_failure(content, self.preflight.owner_identifiers)
            safe_failure_code = "evidence_capture_failed"
            evidence_payload = _json_response(
                await self.client.get(
                    f"{self.preflight.base_url}/api/v1/answers/{answer_id}/evidence"
                ),
                expected=(200,),
            )
            evidence_records = _safe_evidence_records(
                evidence_payload,
                requested_jurisdiction=case.jurisdiction,
            )
            evidence_passed = bool(
                quality.get("evidence_passed")
                and (
                    _material_evidence_is_qualified(evidence_records)
                    or (
                        release_state == "verified_limited"
                        and not _has_material_claims(evidence_payload)
                    )
                )
            )
            safe_failure_code = "artifact_capture_failed"
            artifact_id = (
                "answer-"
                + hashlib.sha256(f"{answer_id}\0pass-{pass_number}".encode()).hexdigest()[:24]
            )
            try:
                self.store.store_sensitive_artifact(
                    run_id=self.preflight.run_id,
                    case_id=case.case_id,
                    kind=SensitiveArtifactKind.ANSWER,
                    artifact_id=artifact_id,
                    content=content,
                )
            except FileExistsError:
                existing_content = self.store.load_sensitive_artifact(
                    run_id=self.preflight.run_id,
                    case_id=case.case_id,
                    kind=SensitiveArtifactKind.ANSWER,
                    artifact_id=artifact_id,
                )
                if existing_content != content:
                    raise RuntimeError("immutable answer artifact content changed") from None
            failure_codes: list[str] = []
            if not privacy_passed:
                failure_codes.append("released_answer_privacy_failure")
            if not evidence_passed:
                failure_codes.append("released_answer_evidence_failure")
            computed_words = word_count(content)
            try:
                raw_word_count = answer.get("word_count")
                if raw_word_count is None:
                    raise ValueError("missing word count")
                api_words = int(raw_word_count)
            except (TypeError, ValueError):
                api_words = -1
            if api_words != computed_words:
                failure_codes.append("answer_word_count_mismatch")
            tolerance = max(1, round(case.word_target * 0.05))
            word_target_delta = computed_words - case.word_target
            word_target_within_tolerance = abs(word_target_delta) <= tolerance
            if not word_target_within_tolerance:
                failure_codes.append("word_target_outside_tolerance")
            effective_release = (
                release_state
                if privacy_passed and evidence_passed
                else "privacy_failed"
                if not privacy_passed
                else "evidence_failed"
            )
            released = effective_release in PUBLIC_RELEASES
            if released:
                safe_failure_code = "released_answer_write_failed"
                try:
                    self.store.store_released_answer(
                        run_id=self.preflight.run_id,
                        case_id=case.case_id,
                        pass_number=pass_number,
                        content=content,
                    )
                except FileExistsError:
                    if (
                        self.store.load_released_answer(
                            run_id=self.preflight.run_id,
                            case_id=case.case_id,
                            pass_number=pass_number,
                        )
                        != content
                    ):
                        raise RuntimeError("immutable released answer content changed") from None
            safe_failure_code = "outcome_validation_failed"
            selected_rule_ids = _selected_assessment_rule_ids(case)
            triggered_rule_ids = _triggered_assessment_rule_ids(case, quality)
            outcome = ExecutionOutcome(
                run_id=self.preflight.run_id,
                case_id=case.case_id,
                pass_number=pass_number,
                job_id=job_id,
                trace_id=trace_id,
                status="completed" if released else "held",
                release_state=cast(Any, effective_release),
                released=released,
                privacy_passed=privacy_passed,
                evidence_passed=evidence_passed,
                answer_artifact_id=artifact_id,
                answer_sha256=hashlib.sha256(content.encode()).hexdigest(),
                word_count=computed_words,
                word_target=case.word_target,
                word_target_within_tolerance=word_target_within_tolerance,
                word_target_delta=word_target_delta,
                route=cast(Any, case.expected_research_route),
                model_version=str(answer.get("model_version") or "") or None,
                index_build_id=str(answer.get("index_build_id") or "") or None,
                policy_version=str(answer.get("policy_version") or "") or None,
                assessment_bundle_sha256=self.preflight.assessment_bundle_sha256,
                assessment_rule_ids=selected_rule_ids,
                triggered_assessment_rule_ids=triggered_rule_ids,
                evidence=evidence_records,
                rubric=(
                    SafeRubricResult(
                        criterion_id="automated_academic_score",
                        score=float(quality.get("academic_score") or 0),
                        status="advisory",
                        assessment_rule_ids=triggered_rule_ids,
                        verification_signal="automated_lint_not_blind_calibration",
                    ),
                ),
                failure_codes=tuple(failure_codes),
                completion_duration_ms=round((time.monotonic() - started) * 1_000),
            )
            return self._persist_outcome(case, outcome)
        except Exception:
            return self._store_nonrelease(
                case,
                pass_number=pass_number,
                job_id=job_id,
                trace_id=trace_id,
                status="system_error",
                failure_code=safe_failure_code,
                started=started,
            )

    def _store_nonrelease(
        self,
        case: LiveEvaluationCase,
        *,
        pass_number: int,
        job_id: str | None,
        trace_id: str | None,
        status: Literal["held", "system_error", "cancelled"],
        failure_code: str,
        started: float,
    ) -> ExecutionOutcome:
        outcome = ExecutionOutcome(
            run_id=self.preflight.run_id,
            case_id=case.case_id,
            pass_number=pass_number,
            job_id=job_id,
            trace_id=trace_id,
            status=status,
            release_state="held" if status == "held" else "not_released",
            released=False,
            privacy_passed=True,
            evidence_passed=False,
            word_target=case.word_target,
            word_target_within_tolerance=None,
            word_target_delta=None,
            route=cast(Any, case.expected_research_route),
            assessment_bundle_sha256=self.preflight.assessment_bundle_sha256,
            assessment_rule_ids=_selected_assessment_rule_ids(case),
            triggered_assessment_rule_ids=(),
            failure_codes=(failure_code,),
            completion_duration_ms=round((time.monotonic() - started) * 1_000),
        )
        return self._persist_outcome(case, outcome)

    def _persist_outcome(
        self, case: LiveEvaluationCase, outcome: ExecutionOutcome
    ) -> ExecutionOutcome:
        issue_ids: list[str] = []
        for failure_code in outcome.failure_codes:
            issue_id = (
                "issue-"
                + hashlib.sha256(
                    (
                        f"{outcome.run_id}\0{outcome.case_id}\0"
                        f"{outcome.pass_number}\0{failure_code}"
                    ).encode()
                ).hexdigest()[:20]
            )
            issue_ids.append(issue_id)
            self.store.append_safe_run_index(
                run_id=self.preflight.run_id,
                index_name="issues",
                value={
                    "schema": "legalbot.live30-safe-issue.v1",
                    "issue_id": issue_id,
                    "run_id": outcome.run_id,
                    "case_id": outcome.case_id,
                    "pass_number": outcome.pass_number,
                    "job_id": outcome.job_id,
                    "trace_id": outcome.trace_id,
                    "category": failure_code,
                    "affected_layer": (
                        "answer_quality"
                        if failure_code
                        in {
                            "answer_word_count_mismatch",
                            "word_target_outside_tolerance",
                        }
                        else "execution"
                    ),
                    "severity": (
                        "repairable"
                        if failure_code
                        in {
                            "answer_word_count_mismatch",
                            "word_target_outside_tolerance",
                        }
                        else "hard"
                    ),
                    "root_cause": "pending_triage",
                    "corrective_action": "pending_owner_or_engineering_review",
                    "regression_status": "regression_case_required",
                    "status": "open",
                },
            )
        knowledge_gap_ids: list[str] = []
        gap_index_path = self.store.runs_root / self.preflight.run_id / "knowledge-gaps/index.jsonl"
        if gap_index_path.is_file():
            for raw in gap_index_path.read_text(encoding="utf-8").splitlines():
                try:
                    existing_gap = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(existing_gap, dict)
                    and existing_gap.get("case_id") == outcome.case_id
                    and isinstance(existing_gap.get("gap_id"), str)
                ):
                    knowledge_gap_ids.append(str(existing_gap["gap_id"]))
        runtime_gap_reason = (
            "verified_limited_evidence_scope"
            if outcome.release_state == "verified_limited"
            else "released_answer_evidence_failure"
            if outcome.release_state == "evidence_failed"
            else None
        )
        if runtime_gap_reason is not None:
            gap_id = (
                "gap-"
                + hashlib.sha256(
                    (
                        f"{outcome.run_id}\0{outcome.case_id}\0"
                        f"{outcome.pass_number}\0{runtime_gap_reason}"
                    ).encode()
                ).hexdigest()[:20]
            )
            knowledge_gap_ids.append(gap_id)
            self.store.append_safe_run_index(
                run_id=self.preflight.run_id,
                index_name="knowledge-gaps",
                value={
                    "schema": "legalbot.live30-safe-gap.v1",
                    "gap_id": gap_id,
                    "run_id": outcome.run_id,
                    "case_id": outcome.case_id,
                    "pass_number": outcome.pass_number,
                    "job_id": outcome.job_id,
                    "trace_id": outcome.trace_id,
                    "reason_code": runtime_gap_reason,
                    "category": "evidence_coverage",
                    "severity": "high",
                    "status": "open",
                },
            )
        outcome = outcome.model_copy(
            update={
                "issue_ids": tuple(issue_ids),
                "knowledge_gap_ids": tuple(dict.fromkeys(knowledge_gap_ids)),
            }
        )
        self.store.store_safe_case_pass_json(
            run_id=self.preflight.run_id,
            case_id=case.case_id,
            pass_number=outcome.pass_number,
            value=outcome.model_dump(mode="json", by_alias=True),
        )
        if outcome.release_state == "verified_limited":
            status = RunStatus.VERIFIED_LIMITED
        elif outcome.status == "completed":
            status = RunStatus.COMPLETE
        elif outcome.status == "held":
            status = RunStatus.HELD_FOR_REVIEW
        elif outcome.status == "cancelled":
            status = RunStatus.CANCELLED
        else:
            status = RunStatus.SYSTEM_ERROR
        self.store.record_case_status(
            run_id=self.preflight.run_id,
            case_id=case.case_id,
            status=status,
            artifact_id=outcome.answer_artifact_id,
        )
        self.store.record_event(
            E2ERunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=datetime.now(UTC),
                run_id=self.preflight.run_id,
                case_id=case.case_id,
                event_type=(
                    RunEventType.CASE_COMPLETED
                    if outcome.status == "completed"
                    else RunEventType.CASE_FAILED
                ),
                stage=RunStage.RELEASE,
                status=status,
                duration_ms=outcome.completion_duration_ms,
                attempt=outcome.pass_number,
                artifact_id=outcome.answer_artifact_id,
                error_code=(outcome.failure_codes[0] if outcome.failure_codes else None),
            )
        )
        return outcome


def _safe_gaps(run_root: Path, case_id: str) -> tuple[SafeGapRecord, ...]:
    path = run_root / "knowledge-gaps" / "index.jsonl"
    if not path.is_file():
        return ()
    result: list[SafeGapRecord] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("case_id") != case_id:
            continue
        result.append(
            SafeGapRecord(
                gap_id=str(value["gap_id"]),
                category=str(value.get("reason_code") or "knowledge_gap").replace("-", "_"),
                severity="high",
                status="open",
            )
        )
    return tuple(result)


def _run_plaintext_privacy_report(
    *, store: Live30RunStore, suite: LiveEvaluationSuite, run_id: str
) -> dict[str, Any]:
    run_root = store.runs_root / run_id
    findings: Counter[str] = Counter()
    checked = 0
    for path in sorted(run_root.rglob("*")):
        if not path.is_file() or path.suffix not in {".json", ".jsonl", ".md"}:
            continue
        checked += 1
        value = path.read_text(encoding="utf-8")
        if contains_absolute_private_path(value):
            findings["absolute_path_in_plaintext_evaluation_artifact"] += 1
        if any(case.question in value for case in suite.cases):
            findings["question_in_plaintext_evaluation_artifact"] += 1
    operational_files: set[Path] = set(store.logs_root.rglob("*.json")) | set(
        store.logs_root.rglob("*.jsonl")
    )
    e2e_root = store.project_root / "data/evaluations/e2e"
    for subdirectory in ("metrics", "traces"):
        root = e2e_root / subdirectory
        if root.is_dir():
            operational_files.update(root.rglob("*.json"))
            operational_files.update(root.rglob("*.jsonl"))
    owner_identifiers = tuple(Settings(project_root=store.project_root).owner_identifiers)
    for path in sorted(operational_files):
        if not path.is_file():
            continue
        checked += 1
        value = path.read_text(encoding="utf-8")
        if any(case.question in value for case in suite.cases):
            findings["question_in_normal_log"] += 1
        if contains_absolute_private_path(value):
            findings["absolute_path_in_normal_log"] += 1
        if any(
            identifier.strip() and identifier.casefold() in value.casefold()
            for identifier in owner_identifiers
        ):
            findings["owner_identifier_in_normal_log"] += 1
    return {
        "schema": RUN_PRIVACY_SCHEMA,
        "run_id": run_id,
        "passed": not findings,
        "zero_tolerance": True,
        "checked_plaintext_artifact_count": checked,
        "finding_counts": dict(sorted(findings.items())),
    }


def finalize_review_export(
    *, store: Live30RunStore, suite: LiveEvaluationSuite, run_id: str
) -> LiveReviewExport:
    """Finalize only after the planned 30 + 9 + 9 terminal outcomes exist."""

    manifest = store.load_run_manifest(run_id)
    run_root = store.runs_root / run_id
    planned: dict[tuple[str, int], ExecutionOutcome] = {}
    for case in suite.cases:
        required_passes = (1, 2, 3) if case.case_id in STRATIFIED_SAMPLE_IDS else (1,)
        for pass_number in required_passes:
            value = store.load_safe_case_pass_json(
                run_id=run_id,
                case_id=case.case_id,
                pass_number=pass_number,
            )
            if value is None:
                raise RuntimeError("review export requires all 48 planned terminal outcomes")
            outcome = ExecutionOutcome.model_validate(value)
            if (
                outcome.run_id != run_id
                or outcome.case_id != case.case_id
                or outcome.pass_number != pass_number
            ):
                raise RuntimeError("planned outcome identity check failed")
            planned[(case.case_id, pass_number)] = outcome
    outcomes = tuple(planned.values())
    pass_one = tuple(planned[(case.case_id, 1)] for case in suite.cases)
    privacy_report = _run_plaintext_privacy_report(store=store, suite=suite, run_id=run_id)
    store.store_safe_run_json(
        run_id=run_id,
        filename="run-privacy-report.json",
        value=privacy_report,
    )
    review_cases: list[LiveReviewCase] = []
    by_id = {item.case_id: item for item in pass_one}
    for case in suite.cases:
        outcome = by_id[case.case_id]
        case_passes = tuple(
            planned[(case.case_id, number)]
            for number in ((1, 2, 3) if case.case_id in STRATIFIED_SAMPLE_IDS else (1,))
        )
        academic_scores = tuple(
            item.score
            for observed in case_passes
            for item in observed.rubric
            if item.criterion_id == "automated_academic_score" and item.score is not None
        )
        measured_words = tuple(
            item.word_count for item in case_passes if item.word_count is not None
        )
        case_metrics: list[SafeMetric] = [
            SafeMetric(
                metric_id="completion_duration_ms",
                value=outcome.completion_duration_ms,
                unit="ms",
                gate="advisory",
            ),
            SafeMetric(
                metric_id="planned_pass_count",
                value=len(case_passes),
                unit="passes",
                gate="pass",
            ),
        ]
        if len(case_passes) == 3:
            case_metrics.extend(
                (
                    SafeMetric(
                        metric_id="stability.average_academic_score",
                        value=(
                            round(sum(academic_scores) / len(academic_scores), 4)
                            if academic_scores
                            else None
                        ),
                        unit="score",
                        gate="advisory" if academic_scores else "not_scored",
                    ),
                    SafeMetric(
                        metric_id="stability.worst_academic_score",
                        value=min(academic_scores) if academic_scores else None,
                        unit="score",
                        gate="advisory" if academic_scores else "not_scored",
                    ),
                    SafeMetric(
                        metric_id="stability.word_count_range",
                        value=(max(measured_words) - min(measured_words))
                        if measured_words
                        else None,
                        unit="words",
                        gate="advisory" if measured_words else "not_scored",
                    ),
                )
            )
        review_cases.append(
            LiveReviewCase(
                case_id=case.case_id,
                ordinal=case.ordinal,
                case_status=cast(
                    Any,
                    "completed"
                    if outcome.status == "completed"
                    else "held"
                    if outcome.status == "held"
                    else "cancelled"
                    if outcome.status == "cancelled"
                    else "failed",
                ),
                release_state=cast(Any, outcome.release_state),
                released=outcome.released,
                privacy_passed=outcome.privacy_passed,
                evidence_passed=outcome.evidence_passed,
                question_sha256=case.question_sha256,
                answer_artifact_id=outcome.answer_artifact_id,
                answer_sha256=outcome.answer_sha256,
                subject=case.subject,
                task_type=cast(Any, case.task_type),
                jurisdiction=case.jurisdiction,
                as_of_date=manifest.as_of_date.isoformat(),
                word_target=case.word_target,
                word_count=outcome.word_count,
                research_route=cast(Any, case.expected_research_route),
                drafting_route=cast(Any, case.expected_drafting_route),
                assessment_bundle_sha256=outcome.assessment_bundle_sha256,
                assessment_rule_ids=outcome.assessment_rule_ids,
                evidence=outcome.evidence,
                rubric=outcome.rubric,
                repairs=outcome.repairs,
                gaps=_safe_gaps(run_root, case.case_id),
                metrics=tuple(case_metrics),
                failure_codes=outcome.failure_codes,
            )
        )
    counts = Counter(item.release_state for item in pass_one)
    stability_outcomes = tuple(
        planned[(case_id, pass_number)]
        for case_id in STRATIFIED_SAMPLE_IDS
        for pass_number in (1, 2, 3)
    )
    stability_scores = tuple(
        item.score
        for outcome in stability_outcomes
        for item in outcome.rubric
        if item.criterion_id == "automated_academic_score" and item.score is not None
    )
    authority_stable = 0
    locator_stable = 0
    for case_id in STRATIFIED_SAMPLE_IDS:
        sample = tuple(planned[(case_id, number)] for number in (1, 2, 3))
        source_sets = tuple(
            frozenset(
                item.stable_source_id
                for item in outcome.evidence
                if item.support_state == "supported"
            )
            for outcome in sample
        )
        locator_sets = tuple(
            frozenset(
                (item.stable_source_id, item.legal_locator)
                for item in outcome.evidence
                if item.support_state == "supported"
            )
            for outcome in sample
        )
        authority_stable += int(source_sets[0] == source_sets[1] == source_sets[2])
        locator_stable += int(locator_sets[0] == locator_sets[1] == locator_sets[2])
    aggregate = (
        SafeMetric(metric_id="case_count", value=30, unit="cases", gate="pass"),
        SafeMetric(
            metric_id="planned_outcome_count",
            value=len(outcomes),
            unit="outcomes",
            gate="pass" if len(outcomes) == 48 else "fail",
        ),
        SafeMetric(
            metric_id="released_case_count",
            value=sum(item.released for item in pass_one),
            unit="cases",
            gate="advisory",
        ),
        SafeMetric(
            metric_id="held_or_failed_case_count",
            value=30 - sum(item.released for item in pass_one),
            unit="cases",
            gate="advisory",
        ),
        SafeMetric(
            metric_id="verified_limited_count",
            value=counts.get("verified_limited", 0),
            unit="cases",
            gate="advisory",
        ),
        SafeMetric(
            metric_id="stability.average_academic_score",
            value=(
                round(sum(stability_scores) / len(stability_scores), 4)
                if stability_scores
                else None
            ),
            unit="score",
            gate="advisory" if stability_scores else "not_scored",
        ),
        SafeMetric(
            metric_id="stability.worst_academic_score",
            value=min(stability_scores) if stability_scores else None,
            unit="score",
            gate="advisory" if stability_scores else "not_scored",
        ),
        SafeMetric(
            metric_id="stability.release_rate",
            value=round(
                sum(item.released for item in stability_outcomes) / len(stability_outcomes),
                8,
            ),
            unit="ratio",
            gate="advisory",
        ),
        SafeMetric(
            metric_id="stability.authority_set_rate",
            value=round(authority_stable / len(STRATIFIED_SAMPLE_IDS), 8),
            unit="ratio",
            gate="advisory",
        ),
        SafeMetric(
            metric_id="stability.locator_set_rate",
            value=round(locator_stable / len(STRATIFIED_SAMPLE_IDS), 8),
            unit="ratio",
            gate="advisory",
        ),
        SafeMetric(
            metric_id="stability.conclusion_consistency",
            value=None,
            unit="ratio",
            gate="not_scored",
        ),
    )
    store.store_safe_run_json(
        run_id=run_id,
        filename="aggregate-metrics.json",
        value={
            "schema": "legalbot.live30-execution-aggregate.v1",
            "run_id": run_id,
            "planned_outcome_count": len(outcomes),
            "pass_one_case_count": len(pass_one),
            "stability_outcome_count": len(stability_outcomes),
            "metrics": [item.model_dump(mode="json") for item in aggregate],
        },
    )
    manifest_bytes = (run_root / "manifest.json").read_bytes()
    review = LiveReviewExport(
        run_id=run_id,
        run_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        generated_at=datetime.now(UTC),
        run_status="completed",
        privacy_report_passed=bool(privacy_report["passed"]),
        cases=tuple(review_cases),
        aggregate_metrics=aggregate,
    )
    store.store_safe_run_json(
        run_id=run_id,
        filename="review-export.json",
        value=review.model_dump(mode="json", by_alias=True),
    )
    store.record_event(
        E2ERunEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(UTC),
            run_id=run_id,
            event_type=RunEventType.RUN_COMPLETED,
            stage=RunStage.RUN,
            status=RunStatus.COMPLETE,
        )
    )
    return review


async def execute_with_httpx(
    *,
    store: Live30RunStore,
    suite: LiveEvaluationSuite,
    preflight: ExecutionPreflight,
    pass_number: int,
    stability_sample: bool,
    case_timeout_seconds: float,
) -> tuple[ExecutionOutcome, ...]:
    timeout = httpx.Timeout(connect=5, read=30, write=30, pool=5)
    async with httpx.AsyncClient(
        base_url=preflight.base_url,
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        executor = Live30Executor(
            store=store,
            suite=suite,
            preflight=preflight,
            client=cast(LocalEvaluationClient, client),
            case_timeout_seconds=case_timeout_seconds,
        )
        return await executor.execute(pass_number=pass_number, stability_sample=stability_sample)
