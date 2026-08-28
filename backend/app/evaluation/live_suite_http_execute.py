"""Real, fail-closed localhost executor for the sealed Live60 run plan.

Nothing in this module creates gold, promotes an index, authorises O-04 or
enables online research.  It consumes those immutable decisions, submits only
the 30 ``generate_once`` cases, and persists one terminal outcome per selected
case.  The same idempotency key is reused after an executor restart, so a
partially observed API job is resumed rather than duplicated.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

import httpx

from ..citations.oscola import CitationMetadataError, render_oscola
from ..config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from ..db import Database
from ..privacy import contains_absolute_private_path, prompt_injection_hits
from ..quality.ai_evidence_reviewer import AIEvidenceAdjudication, AIEvidenceReviewResult
from ..quality.policy import HARD_BLOCKER_CODES
from ..retrieval.lancedb import ImmutableLanceRepository
from ..retrieval.source_manifest import approved_source_manifest_sha256
from ..text_metrics import word_count
from .live30 import (
    RunEventType,
    RunStage,
    RunStatus,
    SensitiveArtifactKind,
    assert_safe_evaluation_payload,
)
from .live30_execute import (
    PUBLIC_RELEASES,
    TERMINAL_JOB_STATES,
    _has_material_claims,
    _json_response,
    _privacy_failure,
    _safe_evidence_records,
    _selected_assessment_rule_ids,
    _triggered_assessment_rule_ids,
)
from .live_suite import LiveEvaluationBundle, LiveQuestionCase, admission_as_of_date
from .live_suite_execute import (
    Live60ExecutionOutcome,
    Live60ExecutionPreflight,
    finalize_single_pass_outcomes,
    live60_evaluation_request_sha256,
    live60_evaluation_request_sha256_v2,
    record_terminal_outcome,
)
from .live_suite_store import LiveSuiteRunEvent, LiveSuiteRunStore
from .review_docx import (
    LiveReviewCase,
    LiveReviewExport,
    SafeAdvisoryAIReview,
    SafeEvidenceRecord,
    SafeGapRecord,
    SafeMetric,
    SafeRubricResult,
)

RUN_PRIVACY_SCHEMA = "legalbot.live60-run-privacy-report.v1"
SLO_EVALUATION_SCHEMA = "legalbot.observability-slo-evaluation.v1"


def persist_live60_slo_evaluation(*, store: LiveSuiteRunStore, run_id: str) -> dict[str, Any]:
    """Write the allowlisted run SLO snapshot without promoting it to a gate."""

    project_root = store.project_root
    api_present = (
        project_root / "data" / "evaluations" / "e2e" / "metrics" / "slo-api.json"
    ).is_file()
    worker_present = (
        project_root / "data" / "evaluations" / "e2e" / "metrics" / "slo-worker.json"
    ).is_file()
    payload: dict[str, Any] = {
        "schema": SLO_EVALUATION_SCHEMA,
        "run_id": run_id,
        "suite_id": "live-evaluation-60-v1",
        "observe_only": True,
        "api_snapshot_present": api_present,
        "worker_snapshot_present": worker_present,
        "evaluation_state": (
            "runtime_snapshots_recorded"
            if api_present or worker_present
            else "runtime_snapshots_absent"
        ),
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    existing_path = store._run_path(run_id) / "slo-evaluation.json"
    if existing_path.is_file():
        return store.load_safe_run_json(run_id=run_id, filename="slo-evaluation.json")
    store.store_safe_run_json(run_id=run_id, filename="slo-evaluation.json", value=payload)
    return payload


RELEASE_GATE_SCHEMA = "legalbot.live60-release-gate-report.v1"
_RESUMABLE_JOB_STATES = frozenset({"system_error", "failed", "dlq"})
_CITATION_FAILURE_CODES = frozenset(
    {
        "invented_authority",
        "wrong_authority_identity",
        "false_quotation",
        "unverified_case_legal_role",
    }
)


class LocalEvaluationClient(Protocol):
    async def get(self, url: str, **kwargs: Any) -> Any: ...

    async def post(self, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class Live60RuntimeBinding:
    """Runtime identities rechecked immediately before any API admission."""

    run_id: str
    base_url: str
    index_build_id: str
    model_version: str
    prompt_version: str
    router_version: str
    classifier_version: str
    policy_sha256: str
    assessment_bundle_sha256: str
    as_of_date: date
    owner_identifiers: tuple[str, ...]
    readiness_report_sha256: str
    rollback_report_sha256: str
    browser_recovery_report_sha256: str
    evaluation_mode: bool = False


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        raise ValueError("Live60 execution requires an uncredentialed loopback HTTP origin")
    return value.rstrip("/")


def _read_safe_object(path: Path, *, label: str, telemetry_safe: bool = True) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"{label} is missing")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not an object")
    if telemetry_safe:
        assert_safe_evaluation_payload(value)
    return value


def verify_live60_runtime_bindings(
    *,
    project_root: Path,
    bundle: LiveEvaluationBundle,
    preflight: Live60ExecutionPreflight,
    base_url: str,
    legal_date: date | None = None,
) -> Live60RuntimeBinding:
    """Reconcile O-04 with the real ACTIVE runtime and readiness artifacts.

    This read-only check deliberately does not regenerate readiness or mutate
    ACTIVE.  O-04 must name the exact bytes already reviewed by the owner.
    """

    settings = Settings(project_root=project_root.resolve())
    manifest = preflight.run_manifest
    authorization = preflight.authorization
    expected_date = legal_date or admission_as_of_date()
    run_date = date.fromisoformat(manifest.as_of_date)
    if run_date != expected_date:
        raise RuntimeError(
            "the Europe/London run date changed; current-law checks and O-04 must be resealed"
        )
    if (
        manifest.suite_manifest_seal_sha256 != bundle.manifest.seal_sha256
        or manifest.run_plan_seal_sha256 != bundle.run_plan.seal_sha256
    ):
        raise RuntimeError("runtime run manifest differs from the sealed Live60 contract")
    provenance = manifest.provenance
    required = (
        provenance.model_version,
        provenance.index_build_id,
        provenance.prompt_version,
        provenance.router_version,
        provenance.classifier_version,
        provenance.policy_sha256,
        provenance.assessment_rules_sha256,
    )
    if any(value is None for value in required) or provenance.git_dirty:
        raise RuntimeError("Live60 requires a complete clean-checkpoint provenance record")
    if provenance.index_build_id != authorization.active_build_id:
        raise RuntimeError("O-04 and the run manifest name different candidates")
    if settings.live_profile != FIRST_LIVE_LOCAL_ONLY_PROFILE:
        raise RuntimeError("first Live60 execution requires the first-live local-only profile")
    if (
        settings.online_default != "local_only"
        or settings.official_research_enabled
        or not settings.evaluation_forbids_online_research
    ):
        raise RuntimeError("online research is not disabled for the first Live60 execution")

    readiness_path = settings.data_dir / "reports" / "production-readiness.json"
    rollback_path = settings.project_root / "data/evaluations/e2e/gates/rollback-drill.json"
    browser_path = settings.project_root / "data/evaluations/e2e/gates/browser-recovery-drill.json"
    readiness = _read_safe_object(readiness_path, label="production readiness report")
    if _sha256_file(readiness_path) != authorization.readiness_report_sha256:
        raise RuntimeError("O-04 names a different readiness report")
    if (
        readiness.get("schema") != "legalbot.production-readiness.v6"
        or readiness.get("ready") is not True
        or readiness.get("status") != "ready"
        or readiness.get("blocking_gates") != []
        or readiness.get("as_of_date") != run_date.isoformat()
        or readiness.get("live_evaluation_contract") != "live60"
    ):
        raise RuntimeError("the O-04-bound readiness report is not technically ready")
    for path, expected_sha, label in (
        (
            rollback_path,
            authorization.rollback_repromotion_report_sha256,
            "rollback/re-promotion report",
        ),
        (
            browser_path,
            authorization.browser_recovery_report_sha256,
            "browser recovery report",
        ),
    ):
        _read_safe_object(path, label=label)
        if _sha256_file(path) != expected_sha:
            raise RuntimeError(f"O-04 names a different {label}")

    build_id = provenance.index_build_id
    database = Database(settings.database_path)
    database.initialize()
    try:
        row = database.fetchone("SELECT * FROM index_builds WHERE id=?", (build_id,))
        pointer = ImmutableLanceRepository(settings.index_dir).read_active()
        if (
            row is None
            or str(row["status"]) != "active"
            or not row["promoted_at"]
            or database.active_index_id() != build_id
            or pointer is None
            or pointer.build_id != build_id
        ):
            raise RuntimeError("the owner-promoted candidate is not the reconciled ACTIVE build")
        if str(row["policy_sha256"] or "") != provenance.policy_sha256:
            raise RuntimeError("ACTIVE quality policy differs from the run")
        if str(row["assessment_bundle_sha256"] or "") != provenance.assessment_rules_sha256:
            raise RuntimeError("ACTIVE assessment bundle differs from the run")
        source_manifest_path = (
            settings.index_dir / "builds" / build_id / "approved-source-manifest.json"
        )
        source_manifest = _read_safe_object(
            source_manifest_path,
            label="ACTIVE approved-source manifest",
            telemetry_safe=False,
        )
        observed_manifest_sha = str(source_manifest.get("manifest_sha256") or "")
        if (
            observed_manifest_sha != str(row["source_manifest_hash"] or "")
            or approved_source_manifest_sha256(source_manifest) != observed_manifest_sha
            or source_manifest.get("current_law_as_of_date") != run_date.isoformat()
        ):
            raise RuntimeError("ACTIVE source manifest is stale or has an invalid digest")
    finally:
        database.close()

    return Live60RuntimeBinding(
        run_id=manifest.run_id,
        base_url=_normal_base_url(base_url),
        index_build_id=build_id,
        model_version=cast(str, provenance.model_version),
        prompt_version=cast(str, provenance.prompt_version),
        router_version=cast(str, provenance.router_version),
        classifier_version=cast(str, provenance.classifier_version),
        policy_sha256=provenance.policy_sha256,
        assessment_bundle_sha256=provenance.assessment_rules_sha256,
        as_of_date=run_date,
        owner_identifiers=tuple(settings.owner_identifiers),
        readiness_report_sha256=authorization.readiness_report_sha256,
        rollback_report_sha256=authorization.rollback_repromotion_report_sha256,
        browser_recovery_report_sha256=authorization.browser_recovery_report_sha256,
    )


def refuse_silent_active_fallback(
    *,
    evaluation_candidate_build_id: str,
    active_build_id: str | None,
    retrieval_build_id: str | None = None,
) -> None:
    """Refuse retrieving ACTIVE when the evaluation pin is a different candidate.

    A production ACTIVE pointer may exist. Evaluation still retrieves the
    authorised candidate. Fallback is only the retrieval identity, not the
    mere presence of ACTIVE.
    """

    if not evaluation_candidate_build_id:
        raise RuntimeError("evaluation requires a pinned candidate_build_id")
    del active_build_id
    if retrieval_build_id is not None and retrieval_build_id != evaluation_candidate_build_id:
        raise RuntimeError("evaluation must not silently fall back to ACTIVE")


def _quality_findings(quality: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    raw = quality.get("findings_json")
    try:
        values = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise RuntimeError("released quality findings are malformed") from exc
    if not isinstance(values, list):
        raise RuntimeError("released quality findings are missing")
    output: list[dict[str, str]] = []
    for item in values:
        if not isinstance(item, Mapping):
            continue
        code = str(item.get("code") or "").strip().casefold().replace("-", "_")
        severity = str(item.get("severity") or "").strip().casefold().replace("-", "_")
        gate = str(item.get("gate") or "").strip().casefold().replace("-", "_")
        if code and all(character.isalnum() or character in "._:" for character in code):
            output.append({"code": code, "severity": severity, "gate": gate})
    return tuple(output)


def _safe_advisory_ai_review(quality: Mapping[str, Any]) -> SafeAdvisoryAIReview:
    """Project sealed reviewer records into a prose-free owner-review summary."""

    review_raw = quality.get("ai_evidence_review_json")
    adjudication_raw = quality.get("ai_evidence_adjudication_json")
    if review_raw in (None, "") and adjudication_raw in (None, ""):
        return SafeAdvisoryAIReview(status="not_run")
    if review_raw in (None, "") or adjudication_raw in (None, ""):
        raise RuntimeError("released AI advisory review topology is incomplete")
    try:
        review_value = json.loads(review_raw) if isinstance(review_raw, str) else review_raw
        adjudication_value = (
            json.loads(adjudication_raw) if isinstance(adjudication_raw, str) else adjudication_raw
        )
        review = AIEvidenceReviewResult.model_validate(review_value)
        adjudication = AIEvidenceAdjudication.model_validate(adjudication_value)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("released AI advisory review is malformed") from exc
    if (
        adjudication.review_id != review.review_id
        or adjudication.review_seal_sha256 != review.seal_sha256
        or review.reviewer_execution_mode != "separate_verification_pass_same_model_adapter"
        or review.model_independent is not False
        or review.advisory_recommendations_only is not True
        or review.can_decide_or_adopt is not False
        or review.can_admit_sources is not False
        or review.can_authorize_gates is not False
        or adjudication.advisory_recommendations_only is not True
        or adjudication.can_authorize_gates is not False
    ):
        raise RuntimeError("released AI advisory review authority boundary is invalid")
    recommendation_codes = tuple(
        dict.fromkeys(code for claim in adjudication.claims for code in claim.blocking_reason_codes)
    )
    flagged = sum(not claim.passed for claim in adjudication.claims)
    if not recommendation_codes:
        recommendation_codes = ("all_claims_recommended_supported",)
    return SafeAdvisoryAIReview(
        status="available",
        review_sha256=review.seal_sha256,
        recommendation_codes=recommendation_codes,
        flagged_claim_count=flagged,
        owner_review_required=bool(flagged),
    )


def _supported_evidence(records: Sequence[SafeEvidenceRecord]) -> tuple[SafeEvidenceRecord, ...]:
    return tuple(item for item in records if item.support_state == "supported")


def _oscola_metadata_passes(payload: Mapping[str, Any], *, supported_ids: frozenset[str]) -> bool:
    raw_evidence = payload.get("evidence")
    if not isinstance(raw_evidence, list):
        return not supported_ids
    observed: set[str] = set()
    for item in raw_evidence:
        if not isinstance(item, Mapping):
            continue
        evidence_id = str(item.get("id") or "")
        if evidence_id not in supported_ids:
            continue
        observed.add(evidence_id)
        metadata = item.get("citation_data")
        locator = str(item.get("locator") or "") or None
        canonical = str(item.get("canonical_citation") or "").strip()
        if not isinstance(metadata, Mapping) or not metadata:
            if not canonical:
                return False
            continue
        try:
            rendered = render_oscola(metadata, locator)
        except (CitationMetadataError, TypeError, ValueError):
            return False
        if not rendered.strip():
            return False
    return observed == set(supported_ids)


def _safe_failure_code(value: str) -> str:
    cleaned = value.strip().casefold().replace("-", "_")
    if not cleaned or any(not (character.isalnum() or character in "._:") for character in cleaned):
        return "unclassified_execution_failure"
    return cleaned[:128]


class Live60Executor:
    """Serial, restart-safe executor for the one-pass selected Live60 cases."""

    def __init__(
        self,
        *,
        store: LiveSuiteRunStore,
        bundle: LiveEvaluationBundle,
        preflight: Live60ExecutionPreflight,
        runtime: Live60RuntimeBinding,
        client: LocalEvaluationClient,
        poll_interval_seconds: float = 2.0,
        case_timeout_seconds: float = 14_400.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        legal_date_provider: Callable[[], date] = admission_as_of_date,
        max_checkpoint_resumes: int = 1,
    ) -> None:
        if runtime.run_id != preflight.run_manifest.run_id:
            raise ValueError("runtime binding belongs to another run")
        if max_checkpoint_resumes not in {0, 1}:
            raise ValueError("Live60 permits at most one digest-checked checkpoint resume")
        if runtime.evaluation_mode:
            candidate = getattr(preflight.authorization, "candidate_build_id", None)
            if candidate and runtime.index_build_id != candidate:
                raise ValueError("runtime binding belongs to another evaluation candidate")
            refuse_silent_active_fallback(
                evaluation_candidate_build_id=runtime.index_build_id,
                active_build_id=getattr(preflight.authorization, "active_build_id", None),
            )
        elif runtime.index_build_id != preflight.authorization.active_build_id:
            raise ValueError("runtime binding belongs to another ACTIVE build")
        self.store = store
        self.bundle = bundle
        self.preflight = preflight
        self.runtime = runtime
        self.client = client
        self.poll_interval_seconds = poll_interval_seconds
        self.case_timeout_seconds = case_timeout_seconds
        self.sleep = sleep
        self.legal_date_provider = legal_date_provider
        self.max_checkpoint_resumes = max_checkpoint_resumes

    def _assert_run_date(self) -> None:
        if self.legal_date_provider() != self.runtime.as_of_date:
            raise RuntimeError(
                "Europe/London date changed during Live60; stop and reseal current-law inputs"
            )

    async def verify_api_health(self) -> None:
        self._assert_run_date()
        value = _json_response(
            await self.client.get(f"{self.runtime.base_url}/api/v1/health"),
            expected=(200,),
        )
        identities_match = (
            value.get("worker_ready") is True
            and value.get("model_ready") is True
            and value.get("model_id") == self.runtime.model_version
            and value.get("prompt_version") == self.runtime.prompt_version
            and value.get("router_version") == self.runtime.router_version
            and value.get("classifier_version") == self.runtime.classifier_version
            and value.get("policy_sha256") == self.runtime.policy_sha256
            and value.get("assessment_bundle_sha256") == self.runtime.assessment_bundle_sha256
        )
        if self.runtime.evaluation_mode:
            if not identities_match:
                raise RuntimeError("localhost API/model/worker identities are not evaluation-ready")
            return
        if (
            value.get("status") != "ready"
            or not identities_match
            or value.get("active_index") != self.runtime.index_build_id
        ):
            raise RuntimeError("localhost API/model/worker identities are not Live60-ready")

    async def execute(self) -> tuple[Live60ExecutionOutcome, ...]:
        await self.verify_api_health()
        selected = set(self.preflight.generated_case_ids)
        outcomes: list[Live60ExecutionOutcome] = []
        for case in self.bundle.registry.cases:
            if case.case_id not in selected:
                continue
            self._assert_run_date()
            outcomes.append(await self._execute_case(case))
        if tuple(outcome.case_id for outcome in outcomes) != self.preflight.generated_case_ids:
            raise RuntimeError("executor order differs from the immutable run plan")
        return tuple(outcomes)

    def _existing_outcome(self, case_id: str) -> Live60ExecutionOutcome | None:
        try:
            value = self.store.load_safe_case_json(
                run_id=self.runtime.run_id,
                case_id=case_id,
                filename="outcome.json",
            )
        except FileNotFoundError:
            return None
        outcome = Live60ExecutionOutcome.model_validate(value)
        if outcome.run_id != self.runtime.run_id or outcome.case_id != case_id:
            raise RuntimeError("stored terminal outcome identity is invalid")
        self._ensure_outcome_indexes(outcome)
        return outcome

    async def _execute_case(self, case: LiveQuestionCase) -> Live60ExecutionOutcome:
        existing = self._existing_outcome(case.case_id)
        if existing is not None:
            return existing
        started = time.monotonic()
        if case.case_id not in self.preflight.evidence_ready_case_ids:
            reason = (
                "expert_qualification_limited"
                if case.case_id in self.preflight.limited_case_ids
                else "expert_qualification_or_retrieval_held"
            )
            return self._store_nonrelease(
                case,
                job_id=None,
                trace_id=None,
                terminal_state="held",
                failure_code=reason,
                started=started,
                knowledge_gap=True,
            )

        self.store.record_case_status(
            run_id=self.runtime.run_id,
            case=case,
            disposition="generate_once",
            status=RunStatus.QUEUED,
            timestamp=datetime.now(UTC),
        )
        self.store.record_event(
            LiveSuiteRunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=datetime.now(UTC),
                run_id=self.runtime.run_id,
                case_id=case.case_id,
                event_type=RunEventType.CASE_STARTED,
                stage=RunStage.INTAKE,
                status=RunStatus.QUEUED,
                attempt=1,
            )
        )
        job_id: str | None = None
        trace_id: str | None = None
        safe_failure = "question_admission_failed"
        try:
            question_date, encrypted_case = self.store.load_encrypted_question(
                run_id=self.runtime.run_id, case_id=case.case_id
            )
            if question_date != self.runtime.as_of_date or encrypted_case != case:
                raise RuntimeError("encrypted question differs from the frozen run")
            idempotency = hashlib.sha256(
                f"{self.runtime.run_id}\0{case.case_id}\0pass-1".encode()
            ).hexdigest()
            accepted = _json_response(
                await self.client.post(
                    f"{self.runtime.base_url}/api/v1/questions",
                    headers={
                        "X-Evaluation-Run-ID": self.runtime.run_id,
                        "X-Evaluation-Case-ID": case.case_id,
                        "X-Idempotency-Key": f"live60-{idempotency[:40]}",
                    },
                    json={
                        "question": encrypted_case.question,
                        "task_type": encrypted_case.task_type,
                        "jurisdiction": encrypted_case.jurisdiction,
                        "as_of_date": self.runtime.as_of_date.isoformat(),
                        "word_target": encrypted_case.word_target,
                        "online_mode": "local_only",
                        "upload_ids": [],
                    },
                ),
                expected=(202,),
            )
            job_id = str(accepted.get("job_id") or "")
            if not job_id:
                raise RuntimeError("question admission omitted the job identity")
            safe_failure = "job_poll_failed"
            terminal, trace_id = await self._poll_terminal(
                job_id=job_id,
                started=started,
                trace_id=trace_id,
            )
            if terminal is None:
                await self.client.post(f"{self.runtime.base_url}/api/v1/jobs/{job_id}/cancel")
                return self._store_nonrelease(
                    case,
                    job_id=job_id,
                    trace_id=trace_id,
                    terminal_state="system_error",
                    failure_code="evaluation_poll_timeout",
                    started=started,
                )
            self._assert_terminal_job_binding(case, terminal)
            if terminal.get("status") != "complete":
                state = str(terminal.get("status") or "system_error")
                return self._store_nonrelease(
                    case,
                    job_id=job_id,
                    trace_id=trace_id,
                    terminal_state="held" if state == "held_for_review" else "system_error",
                    failure_code=("held_for_review" if state == "held_for_review" else state),
                    started=started,
                )
            safe_failure = "released_answer_capture_failed"
            return await self._capture_released_case(
                case=case,
                terminal=terminal,
                job_id=job_id,
                trace_id=trace_id,
                started=started,
            )
        except Exception:
            return self._store_nonrelease(
                case,
                job_id=job_id,
                trace_id=trace_id,
                terminal_state="system_error",
                failure_code=safe_failure,
                started=started,
            )

    def _assert_terminal_job_binding(
        self, case: LiveQuestionCase, terminal: Mapping[str, Any]
    ) -> None:
        expected_request_sha = (
            live60_evaluation_request_sha256_v2(
                bundle=self.bundle,
                authorization=self.preflight.authorization,
                case_id=case.case_id,
                route=case.expected_research_route,
            )
            if self.runtime.evaluation_mode
            else live60_evaluation_request_sha256(
                bundle=self.bundle,
                preflight=self.preflight,
                case_id=case.case_id,
                route=case.expected_research_route,
            )
        )
        if (
            terminal.get("route") != case.expected_research_route
            or terminal.get("word_target") != case.word_target
            or terminal.get("as_of_date") != self.runtime.as_of_date.isoformat()
            or terminal.get("pinned_index_build_id") != self.runtime.index_build_id
            or terminal.get("evaluation_request_sha256") != expected_request_sha
            or terminal.get("worker_prompt_version") != self.runtime.prompt_version
            or terminal.get("worker_router_version") != self.runtime.router_version
            or terminal.get("worker_classifier_version") != self.runtime.classifier_version
            or terminal.get("worker_policy_sha256") != self.runtime.policy_sha256
            or terminal.get("assessment_bundle_sha256") != self.runtime.assessment_bundle_sha256
        ):
            raise RuntimeError("answer job differs from its sealed Live60 runtime request")

    async def _poll_terminal(
        self,
        *,
        job_id: str,
        started: float,
        trace_id: str | None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        resumes = 0
        while time.monotonic() - started < self.case_timeout_seconds:
            self._assert_run_date()
            observed = _json_response(
                await self.client.get(f"{self.runtime.base_url}/api/v1/jobs/{job_id}"),
                expected=(200,),
            )
            trace_id = str(observed.get("trace_id") or "") or trace_id
            status = str(observed.get("status") or "")
            if status in _RESUMABLE_JOB_STATES and resumes < self.max_checkpoint_resumes:
                response = await self.client.post(
                    f"{self.runtime.base_url}/api/v1/jobs/{job_id}/resume"
                )
                if int(getattr(response, "status_code", 0)) == 200:
                    resumes += 1
                    await self.sleep(self.poll_interval_seconds)
                    continue
            if status in TERMINAL_JOB_STATES:
                return observed, trace_id
            await self.sleep(self.poll_interval_seconds)
        return None, trace_id

    async def _capture_released_case(
        self,
        *,
        case: LiveQuestionCase,
        terminal: Mapping[str, Any],
        job_id: str,
        trace_id: str | None,
        started: float,
    ) -> Live60ExecutionOutcome:
        runtime_release = str(terminal.get("release_state") or "")
        answer_id = str(terminal.get("answer_id") or "")
        if runtime_release not in PUBLIC_RELEASES or not answer_id:
            raise RuntimeError("completed job has no public release")
        answer = _json_response(
            await self.client.get(f"{self.runtime.base_url}/api/v1/answers/{answer_id}"),
            expected=(200,),
        )
        if (
            answer.get("job_id") != job_id
            or answer.get("release_state") != runtime_release
            or answer.get("index_build_id") != self.runtime.index_build_id
            or answer.get("model_version") != self.runtime.model_version
            or answer.get("route") != case.expected_research_route
            or answer.get("as_of_date") != self.runtime.as_of_date.isoformat()
            or answer.get("word_target") != case.word_target
            or answer.get("evaluation_request_sha256")
            != (
                live60_evaluation_request_sha256_v2(
                    bundle=self.bundle,
                    authorization=self.preflight.authorization,
                    case_id=case.case_id,
                    route=case.expected_research_route,
                )
                if self.runtime.evaluation_mode
                else live60_evaluation_request_sha256(
                    bundle=self.bundle,
                    preflight=self.preflight,
                    case_id=case.case_id,
                    route=case.expected_research_route,
                )
            )
            or answer.get("prompt_version") != self.runtime.prompt_version
            or answer.get("router_version") != self.runtime.router_version
            or answer.get("classifier_version") != self.runtime.classifier_version
            or answer.get("runtime_policy_sha256") != self.runtime.policy_sha256
            or answer.get("assessment_bundle_sha256") != self.runtime.assessment_bundle_sha256
        ):
            raise RuntimeError("released answer identities differ from the frozen runtime")
        content = answer.get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("released answer content is missing")
        artifact_id = (
            "answer-"
            + hashlib.sha256(
                f"{self.runtime.run_id}\0{case.case_id}\0{answer_id}\0pass-1".encode()
            ).hexdigest()[:24]
        )
        # Capture public API prose into the encrypted evaluation vault before
        # inspecting secondary reports.  If a later gate is malformed or
        # fails, the prose remains private and the terminal outcome exposes no
        # artifact identifier.
        self._store_answer_artifact(case_id=case.case_id, artifact_id=artifact_id, content=content)
        raw_quality = answer.get("quality")
        quality: Mapping[str, Any] = raw_quality if isinstance(raw_quality, Mapping) else {}
        if (
            str(quality.get("policy_sha256") or "") != self.runtime.policy_sha256
            or str(quality.get("release_state") or "") != runtime_release
        ):
            raise RuntimeError("released quality report differs from the frozen policy")
        evidence_payload = _json_response(
            await self.client.get(f"{self.runtime.base_url}/api/v1/answers/{answer_id}/evidence"),
            expected=(200,),
        )
        evidence_records = _safe_evidence_records(
            evidence_payload, requested_jurisdiction=case.jurisdiction
        )
        supported = _supported_evidence(evidence_records)
        no_material_law = not _has_material_claims(evidence_payload)
        limited_without_material_law = runtime_release == "verified_limited" and no_material_law
        findings = _quality_findings(quality)
        advisory_ai_review = _safe_advisory_ai_review(quality)
        hard_codes = {
            item["code"]
            for item in findings
            if item["severity"] == "hard_blocker" or item["code"] in HARD_BLOCKER_CODES
        }
        privacy_passed = not _privacy_failure(content, self.runtime.owner_identifiers)
        injection_passed = (
            not prompt_injection_hits(content) and "prompt_injection" not in hard_codes
        )
        identity_passed = bool(supported) and all(
            item.identity_state == "verified" for item in supported
        )
        currentness_passed = bool(supported) and all(
            item.currentness_state
            in {
                "verified_current",
                "latest_available_revised_snapshot",
                "not_applicable",
            }
            for item in supported
        )
        jurisdiction_passed = bool(supported) and all(
            item.jurisdiction_state in {"verified", "not_applicable"} for item in supported
        )
        if limited_without_material_law:
            identity_passed = currentness_passed = jurisdiction_passed = True
        evidence_passed = bool(
            quality.get("evidence_passed")
            and not hard_codes
            and identity_passed
            and currentness_passed
            and jurisdiction_passed
        )
        supported_ids = frozenset(item.evidence_span_id for item in supported)
        oscola_passed = (
            _oscola_metadata_passes(evidence_payload, supported_ids=supported_ids)
            if supported_ids
            else limited_without_material_law
        )
        citation_passed = bool(
            oscola_passed and identity_passed and not (_CITATION_FAILURE_CODES & hard_codes)
        )
        computed_words = word_count(content)
        try:
            raw_word_count = answer.get("word_count")
            if raw_word_count is None:
                raise ValueError("missing word count")
            api_words = int(raw_word_count)
        except (TypeError, ValueError):
            api_words = -1
        tolerance = max(1, round(case.word_target * 0.05))
        failure_codes: list[str] = []
        if api_words != computed_words:
            failure_codes.append("answer_word_count_mismatch")
        if abs(computed_words - case.word_target) > tolerance:
            failure_codes.append("word_target_outside_tolerance")
        if not privacy_passed:
            failure_codes.append("released_answer_privacy_failure")
        if not injection_passed:
            failure_codes.append("released_answer_injection_failure")
        if not evidence_passed:
            failure_codes.append("released_answer_evidence_failure")
        if not citation_passed:
            failure_codes.append("released_answer_citation_failure")

        selected_rules = _selected_assessment_rule_ids(cast(Any, case))
        triggered_rules = _triggered_assessment_rule_ids(cast(Any, case), quality)
        gates = {
            "privacy": privacy_passed,
            "evidence": evidence_passed,
            "currentness": currentness_passed,
            "jurisdiction": jurisdiction_passed,
            "citation": citation_passed,
            "injection": injection_passed,
            "oscola": oscola_passed,
        }
        report = {
            "schema": RELEASE_GATE_SCHEMA,
            "run_id": self.runtime.run_id,
            "case_id": case.case_id,
            "job_id": job_id,
            "trace_id": trace_id,
            "answer_id": answer_id,
            "runtime_release_state": runtime_release,
            "index_build_id": self.runtime.index_build_id,
            "model_version": self.runtime.model_version,
            "policy_sha256": self.runtime.policy_sha256,
            "assessment_bundle_sha256": self.runtime.assessment_bundle_sha256,
            "assessment_rule_ids": list(selected_rules),
            "triggered_assessment_rule_ids": list(triggered_rules),
            "quality_finding_codes": [item["code"] for item in findings],
            "hard_failure_codes": sorted(hard_codes),
            "gates": gates,
            "word_target": case.word_target,
            "word_count": computed_words,
            "word_target_within_tolerance": abs(computed_words - case.word_target) <= tolerance,
            "evidence": [item.model_dump(mode="json") for item in evidence_records],
            "academic_score": float(quality.get("academic_score") or 0.0),
            "advisory_ai_review": advisory_ai_review.model_dump(mode="json"),
        }
        report_path = self._store_release_report(case.case_id, report)
        all_hard_gates = all(gates.values())
        released = all_hard_gates
        terminal_state: Literal["released", "verified_limited", "held", "system_error"] = (
            "verified_limited"
            if released and runtime_release == "verified_limited"
            else "released"
            if released
            else "held"
        )
        issue_ids = tuple(self._issue_id(case.case_id, code) for code in failure_codes)
        gap_ids = (
            (self._gap_id(case.case_id, "verified_limited_evidence_scope"),)
            if runtime_release == "verified_limited"
            else ()
        )
        outcome = Live60ExecutionOutcome(
            outcome_id=self._outcome_id(case.case_id),
            run_id=self.runtime.run_id,
            case_id=case.case_id,
            pass_number=1,
            run_plan_disposition="generate_once",
            requested_word_target=case.word_target,
            expected_research_route=case.expected_research_route,
            terminal_state=terminal_state,
            runtime_release_state=cast(Any, runtime_release) if released else None,
            released=released,
            job_id=job_id,
            trace_id=trace_id,
            answer_artifact_id=artifact_id if released else None,
            answer_sha256=(
                hashlib.sha256(content.encode("utf-8")).hexdigest() if released else None
            ),
            word_count=computed_words if released else None,
            privacy_passed=privacy_passed,
            evidence_passed=evidence_passed,
            currentness_passed=currentness_passed,
            jurisdiction_passed=jurisdiction_passed,
            citation_passed=citation_passed,
            injection_passed=injection_passed,
            oscola_passed=oscola_passed,
            release_gate_report_sha256=(
                hashlib.sha256(report_path.read_bytes()).hexdigest() if released else None
            ),
            issue_ids=issue_ids,
            knowledge_gap_ids=gap_ids,
            failure_codes=tuple(failure_codes),
            completion_duration_ms=round((time.monotonic() - started) * 1_000),
            completed_at=datetime.now(UTC),
        )
        return self._persist_outcome(case, outcome)

    def _store_answer_artifact(self, *, case_id: str, artifact_id: str, content: str) -> None:
        try:
            self.store.store_sensitive_artifact(
                run_id=self.runtime.run_id,
                case_id=case_id,
                kind=SensitiveArtifactKind.ANSWER,
                artifact_id=artifact_id,
                content=content,
            )
        except FileExistsError:
            existing = self.store.load_sensitive_artifact(
                run_id=self.runtime.run_id,
                case_id=case_id,
                kind=SensitiveArtifactKind.ANSWER,
                artifact_id=artifact_id,
            )
            if existing != content:
                raise RuntimeError("immutable encrypted answer artifact changed") from None

    def _store_release_report(self, case_id: str, report: dict[str, Any]) -> Path:
        try:
            return self.store.store_safe_case_json(
                run_id=self.runtime.run_id,
                case_id=case_id,
                filename="quality.json",
                value=report,
            )
        except FileExistsError:
            existing = self.store.load_safe_case_json(
                run_id=self.runtime.run_id,
                case_id=case_id,
                filename="quality.json",
            )
            if existing != report:
                raise RuntimeError("immutable release-gate report changed") from None
            return self.store._case_path(self.runtime.run_id, case_id) / "quality.json"

    def _store_nonrelease(
        self,
        case: LiveQuestionCase,
        *,
        job_id: str | None,
        trace_id: str | None,
        terminal_state: Literal["held", "system_error"],
        failure_code: str,
        started: float,
        knowledge_gap: bool = False,
    ) -> Live60ExecutionOutcome:
        code = _safe_failure_code(failure_code)
        issue_id = self._issue_id(case.case_id, code)
        gap_ids = (
            (self._gap_id(case.case_id, code),)
            if knowledge_gap or code.startswith("expert_qualification")
            else ()
        )
        outcome = Live60ExecutionOutcome(
            outcome_id=self._outcome_id(case.case_id),
            run_id=self.runtime.run_id,
            case_id=case.case_id,
            pass_number=1,
            run_plan_disposition="generate_once",
            requested_word_target=case.word_target,
            expected_research_route=case.expected_research_route,
            terminal_state=terminal_state,
            released=False,
            job_id=job_id,
            trace_id=trace_id,
            privacy_passed=False,
            evidence_passed=False,
            currentness_passed=False,
            jurisdiction_passed=False,
            citation_passed=False,
            injection_passed=False,
            oscola_passed=False,
            issue_ids=(issue_id,),
            knowledge_gap_ids=gap_ids,
            failure_codes=(code,),
            completion_duration_ms=round((time.monotonic() - started) * 1_000),
            completed_at=datetime.now(UTC),
        )
        return self._persist_outcome(case, outcome)

    def _outcome_id(self, case_id: str) -> str:
        return (
            "outcome-"
            + hashlib.sha256(f"{self.runtime.run_id}\0{case_id}\0pass-1".encode()).hexdigest()[:24]
        )

    def _issue_id(self, case_id: str, code: str) -> str:
        return (
            "issue-"
            + hashlib.sha256(f"{self.runtime.run_id}\0{case_id}\0{code}".encode()).hexdigest()[:20]
        )

    def _gap_id(self, case_id: str, code: str) -> str:
        return (
            "gap-"
            + hashlib.sha256(f"{self.runtime.run_id}\0{case_id}\0{code}".encode()).hexdigest()[:20]
        )

    def _persist_outcome(
        self, case: LiveQuestionCase, outcome: Live60ExecutionOutcome
    ) -> Live60ExecutionOutcome:
        if outcome.released:
            report_path = self.store._case_path(self.runtime.run_id, case.case_id) / "quality.json"
            if (
                not report_path.is_file()
                or hashlib.sha256(report_path.read_bytes()).hexdigest()
                != outcome.release_gate_report_sha256
            ):
                raise RuntimeError("released outcome is not bound to its gate report")
        try:
            record_terminal_outcome(
                store=self.store,
                bundle=self.bundle,
                preflight=self.preflight,
                outcome=outcome,
            )
        except FileExistsError:
            existing = self._existing_outcome(case.case_id)
            if existing is None:
                raise
            return existing
        self._ensure_outcome_indexes(outcome)
        status = (
            RunStatus.COMPLETE
            if outcome.terminal_state == "released"
            else RunStatus.VERIFIED_LIMITED
            if outcome.terminal_state == "verified_limited"
            else RunStatus.HELD_FOR_REVIEW
            if outcome.terminal_state == "held"
            else RunStatus.SYSTEM_ERROR
        )
        self.store.record_case_status(
            run_id=self.runtime.run_id,
            case=case,
            disposition="generate_once",
            status=status,
            timestamp=outcome.completed_at,
        )
        self.store.record_event(
            LiveSuiteRunEvent(
                event_id=uuid.uuid4().hex,
                timestamp=outcome.completed_at,
                run_id=self.runtime.run_id,
                case_id=case.case_id,
                event_type=(
                    RunEventType.CASE_COMPLETED if outcome.released else RunEventType.CASE_FAILED
                ),
                stage=RunStage.RELEASE,
                status=status,
                duration_ms=outcome.completion_duration_ms,
                attempt=1,
                artifact_id=outcome.answer_artifact_id,
                error_code=(outcome.failure_codes[0] if outcome.failure_codes else None),
            )
        )
        return outcome

    def _ensure_outcome_indexes(self, outcome: Live60ExecutionOutcome) -> None:
        issues = self.store.load_safe_run_index(run_id=self.runtime.run_id, index_name="issues")
        existing_issue_ids = {str(item.get("issue_id")) for item in issues}
        for issue_id, code in zip(outcome.issue_ids, outcome.failure_codes, strict=False):
            if issue_id in existing_issue_ids:
                continue
            self.store.append_safe_run_index(
                run_id=self.runtime.run_id,
                index_name="issues",
                value={
                    "schema": "legalbot.live60-safe-issue.v1",
                    "issue_id": issue_id,
                    "run_id": outcome.run_id,
                    "case_id": outcome.case_id,
                    "job_id": outcome.job_id,
                    "trace_id": outcome.trace_id,
                    "category": code,
                    "affected_layer": (
                        "answer_quality"
                        if code in {"answer_word_count_mismatch", "word_target_outside_tolerance"}
                        else "execution"
                    ),
                    "severity": (
                        "repairable"
                        if code in {"answer_word_count_mismatch", "word_target_outside_tolerance"}
                        else "hard"
                    ),
                    "status": "open",
                },
            )
        gaps = self.store.load_safe_run_index(
            run_id=self.runtime.run_id, index_name="knowledge-gaps"
        )
        existing_gap_ids = {str(item.get("gap_id")) for item in gaps}
        for gap_id in outcome.knowledge_gap_ids:
            if gap_id in existing_gap_ids:
                continue
            self.store.append_safe_run_index(
                run_id=self.runtime.run_id,
                index_name="knowledge-gaps",
                value={
                    "schema": "legalbot.live60-safe-gap.v1",
                    "gap_id": gap_id,
                    "run_id": outcome.run_id,
                    "case_id": outcome.case_id,
                    "category": "evidence_coverage",
                    "severity": "high",
                    "status": "open",
                    "reason_code": (
                        "verified_limited_evidence_scope"
                        if outcome.terminal_state == "verified_limited"
                        else outcome.failure_codes[0]
                        if outcome.failure_codes
                        else "verified_limited_evidence_scope"
                    ),
                },
            )


def _safe_gap_records(
    store: LiveSuiteRunStore, *, run_id: str, case_id: str
) -> tuple[SafeGapRecord, ...]:
    output: list[SafeGapRecord] = []
    for item in store.load_safe_run_index(run_id=run_id, index_name="knowledge-gaps"):
        if item.get("case_id") != case_id:
            continue
        gap_id = str(item.get("gap_id") or "")
        if not gap_id:
            continue
        category = _safe_failure_code(
            str(item.get("category") or item.get("reason_code") or "knowledge_gap")
        )
        status = str(item.get("status") or "open").replace("-", "_")
        if status not in {
            "open",
            "triaged",
            "source_needed",
            "metadata_currentness_needed",
            "retrieval_fix_needed",
            "accepted_out_of_scope",
            "resolved",
            "regression_verified",
        }:
            status = "open"
        output.append(
            SafeGapRecord(
                gap_id=gap_id,
                category=category,
                severity=cast(Any, str(item.get("severity") or "high")),
                status=cast(Any, status),
            )
        )
    return tuple(output)


def _run_privacy_report(
    *,
    store: LiveSuiteRunStore,
    bundle: LiveEvaluationBundle,
    run_id: str,
    owner_identifiers: Sequence[str],
) -> dict[str, Any]:
    findings: Counter[str] = Counter()
    checked = 0
    roots = (store._run_path(run_id), store.project_root / "logs")
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in {".json", ".jsonl", ".md"}:
                continue
            checked += 1
            value = path.read_text(encoding="utf-8")
            if contains_absolute_private_path(value):
                findings["absolute_private_path_in_plaintext_artifact"] += 1
            if any(case.question in value for case in bundle.registry.cases):
                findings["raw_question_in_plaintext_artifact"] += 1
            folded = value.casefold()
            if any(
                identifier.strip() and identifier.casefold() in folded
                for identifier in owner_identifiers
            ):
                findings["owner_identifier_in_plaintext_artifact"] += 1
    return {
        "schema": RUN_PRIVACY_SCHEMA,
        "run_id": run_id,
        "passed": not findings,
        "zero_tolerance": True,
        "checked_plaintext_artifact_count": checked,
        "finding_counts": dict(sorted(findings.items())),
    }


def finalize_live60_review_export(
    *,
    store: LiveSuiteRunStore,
    bundle: LiveEvaluationBundle,
    run_id: str,
    owner_identifiers: Sequence[str] = (),
) -> LiveReviewExport:
    """Idempotently finalize 60 coverage records and 30 one-pass outcomes."""

    aggregate = finalize_single_pass_outcomes(store=store, bundle=bundle, run_id=run_id)
    manifest = store.load_run_manifest(run_id)
    run_root = store._run_path(run_id)
    privacy_path = run_root / "run-privacy-report.json"
    privacy = _run_privacy_report(
        store=store,
        bundle=bundle,
        run_id=run_id,
        owner_identifiers=owner_identifiers,
    )
    if privacy_path.is_file():
        existing_privacy = store.load_safe_run_json(
            run_id=run_id, filename="run-privacy-report.json"
        )
        if existing_privacy.get("passed") is not True or privacy["passed"] is not True:
            raise RuntimeError("Live60 plaintext privacy scan failed")
        # The number of checked files can increase after review-export.json is
        # created.  Zero-tolerance findings, rather than the file count, are
        # the immutable safety decision.
        privacy = existing_privacy
    else:
        store.store_safe_run_json(run_id=run_id, filename="run-privacy-report.json", value=privacy)
    if not privacy["passed"]:
        raise RuntimeError("Live60 plaintext privacy scan failed; review export is blocked")

    cases: list[LiveReviewCase] = []
    selected = set(aggregate["case_ids"])
    dispositions = {item.case_id: item.disposition for item in bundle.run_plan.cases}
    for case in bundle.registry.cases:
        coverage = store.load_safe_case_json(
            run_id=run_id, case_id=case.case_id, filename="coverage.json"
        )
        outcome: Live60ExecutionOutcome | None = None
        if case.case_id in selected:
            outcome = Live60ExecutionOutcome.model_validate(
                store.load_safe_case_json(
                    run_id=run_id, case_id=case.case_id, filename="outcome.json"
                )
            )
        quality: dict[str, Any] = {}
        if (run_root / "cases" / case.case_id / "quality.json").is_file():
            quality = store.load_safe_case_json(
                run_id=run_id, case_id=case.case_id, filename="quality.json"
            )
        evidence = tuple(
            SafeEvidenceRecord.model_validate(item)
            for item in quality.get("evidence", [])
            if isinstance(item, Mapping)
        )
        rule_ids = tuple(str(item) for item in quality.get("assessment_rule_ids", []))
        triggered = tuple(str(item) for item in quality.get("triggered_assessment_rule_ids", []))
        metrics: list[SafeMetric] = []
        if outcome is not None and outcome.completion_duration_ms is not None:
            metrics.append(
                SafeMetric(
                    metric_id="completion_duration_ms",
                    value=outcome.completion_duration_ms,
                    unit="ms",
                    gate="advisory",
                )
            )
        metrics.append(
            SafeMetric(
                metric_id="run_plan_outcome_count",
                value=1 if outcome is not None else 0,
                unit="outcomes",
                gate="pass",
            )
        )
        released = bool(outcome and outcome.released)
        release_state = (
            cast(Any, outcome.runtime_release_state)
            if released and outcome is not None
            else "held"
            if outcome is not None and outcome.terminal_state == "held"
            else "not_released"
        )
        cases.append(
            LiveReviewCase(
                case_id=case.case_id,
                ordinal=case.ordinal,
                run_plan_disposition=cast(Any, dispositions[case.case_id]),
                run_plan_outcome_count=1 if outcome is not None else 0,
                coverage_status=str(coverage.get("coverage_status") or "covered"),
                case_status=cast(
                    Any,
                    "completed"
                    if outcome is None or outcome.released
                    else "held"
                    if outcome.terminal_state == "held"
                    else "failed",
                ),
                release_state=cast(Any, release_state),
                released=released,
                privacy_passed=bool(outcome.privacy_passed) if outcome else False,
                evidence_passed=bool(outcome.evidence_passed) if outcome else False,
                question_sha256=case.question_sha256,
                answer_artifact_id=(outcome.answer_artifact_id if outcome else None),
                answer_sha256=(outcome.answer_sha256 if outcome else None),
                subject=case.subject,
                task_type=cast(Any, case.task_type),
                jurisdiction=case.jurisdiction,
                as_of_date=manifest.as_of_date,
                word_target=case.word_target,
                word_count=(outcome.word_count if outcome else None),
                research_route=case.expected_research_route,
                drafting_route=case.expected_drafting_route,
                assessment_bundle_sha256=(
                    manifest.provenance.assessment_rules_sha256 if released else None
                ),
                assessment_rule_ids=rule_ids if released else (),
                evidence=evidence if released else (),
                rubric=(
                    (
                        SafeRubricResult(
                            criterion_id="automated_academic_score",
                            score=float(quality.get("academic_score") or 0.0),
                            status="advisory",
                            assessment_rule_ids=triggered,
                            verification_signal="automated_lint_not_blind_calibration",
                        ),
                    )
                    if released
                    else ()
                ),
                gaps=_safe_gap_records(store, run_id=run_id, case_id=case.case_id),
                advisory_ai_review=(
                    SafeAdvisoryAIReview.model_validate(quality["advisory_ai_review"])
                    if isinstance(quality.get("advisory_ai_review"), Mapping)
                    else None
                ),
                metrics=tuple(metrics),
                failure_codes=(outcome.failure_codes if outcome else ()),
            )
        )
    review = LiveReviewExport(
        schema="legalbot.live-review-export.v2",
        run_id=run_id,
        run_manifest_sha256=hashlib.sha256((run_root / "manifest.json").read_bytes()).hexdigest(),
        generated_at=max(
            (
                outcome.completed_at
                for outcome in (
                    Live60ExecutionOutcome.model_validate(
                        store.load_safe_case_json(
                            run_id=run_id, case_id=case_id, filename="outcome.json"
                        )
                    )
                    for case_id in aggregate["case_ids"]
                )
            ),
            default=manifest.created_at,
        ),
        run_status="completed",
        privacy_report_passed=bool(privacy.get("passed") is True),
        expected_case_count=60,
        run_plan_id=manifest.run_plan_id,
        run_plan_file_sha256=manifest.run_plan_file_sha256,
        run_plan_seal_sha256=manifest.run_plan_seal_sha256,
        cases=tuple(cases),
        aggregate_metrics=(
            SafeMetric(metric_id="case_count", value=60, unit="cases", gate="pass"),
            SafeMetric(
                metric_id="selected_generation_case_count",
                value=30,
                unit="cases",
                gate="pass",
            ),
            SafeMetric(
                metric_id="released_case_count",
                value=len(aggregate["released_case_ids"]),
                unit="cases",
                gate="advisory",
            ),
        ),
    )
    review_path = run_root / "review-export.json"
    review_value = review.model_dump(mode="json", by_alias=True)
    if review_path.is_file():
        existing = store.load_safe_run_json(run_id=run_id, filename="review-export.json")
        if existing != review_value:
            raise RuntimeError("immutable Live60 review export differs from outcomes")
        persist_live60_slo_evaluation(store=store, run_id=run_id)
        return LiveReviewExport.model_validate(existing)
    store.store_safe_run_json(run_id=run_id, filename="review-export.json", value=review_value)
    store.record_event(
        LiveSuiteRunEvent(
            event_id=uuid.uuid4().hex,
            timestamp=review.generated_at,
            run_id=run_id,
            event_type=RunEventType.RUN_COMPLETED,
            stage=RunStage.RUN,
            status=RunStatus.COMPLETE,
        )
    )
    persist_live60_slo_evaluation(store=store, run_id=run_id)
    return review


async def execute_live60_with_httpx(
    *,
    store: LiveSuiteRunStore,
    bundle: LiveEvaluationBundle,
    preflight: Live60ExecutionPreflight,
    runtime: Live60RuntimeBinding,
    case_timeout_seconds: float,
) -> tuple[Live60ExecutionOutcome, ...]:
    timeout = httpx.Timeout(connect=5, read=30, write=30, pool=5)
    async with httpx.AsyncClient(
        base_url=runtime.base_url,
        timeout=timeout,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        return await Live60Executor(
            store=store,
            bundle=bundle,
            preflight=preflight,
            runtime=runtime,
            client=cast(LocalEvaluationClient, client),
            case_timeout_seconds=case_timeout_seconds,
        ).execute()
