from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import re
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from contextvars import ContextVar
from datetime import date, datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4
from zoneinfo import ZoneInfo

from ..assessment.guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    BudgetedAssessmentGuidance,
    budget_assessment_guidance,
)
from ..citations.oscola import render_answer
from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database
from ..jurisdictions import compatible
from ..observability.live_tracing import (
    DatabaseOperation,
    TraceLevel,
    TraceOperation,
    TraceStage,
    TraceStatus,
)
from ..observability.runtime import RuntimeObservability
from ..privacy import prompt_injection_hits, scrub_pii
from ..quality.ai_evidence_reviewer import (
    adjudicate_ai_evidence_review,
    invoke_ai_evidence_reviewer,
)
from ..quality.evaluator import QualityEvaluator
from ..quality.evidence import (
    evidence_span_eligible_for_drafting,
    is_citable_authority_lane,
)
from ..quality.policy import POLICY_SHA256, POLICY_VERSION
from ..text_metrics import word_count
from ..types import (
    AnswerRoute,
    EvidenceSpan,
    IssuePlan,
    IssueSpottingNote,
    JobStage,
    JobStatus,
    KnowledgeGap,
    QualityFinding,
    QualityReport,
    QuestionRequest,
    ReleaseState,
    Severity,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
    UploadContextSpan,
)
from .behavior import (
    BehaviorDecision,
    BehaviorSignals,
    FailureReasonCode,
    looks_like_missing_document,
    question_is_entirely_unsafe,
    route_behavior,
)
from .classifier import (
    CLASSIFIER_VERSION,
    classify_subject,
    classify_subjects,
    classify_task,
)
from .contracts import AnswerModel, EvidenceRetriever, ModelDraft
from .gaps import GapQueue
from .issues import build_issue_plan
from .object_store import EncryptedObjectStore
from .retry_policy import (
    decide_retry,
    failure_fingerprint,
    is_deterministic_safety_failure,
)
from .routing import ROUTER_VERSION, SectionTask, build_section_tasks
from .subject_routing_audit import build_subject_routing_audit
from .targeted_repair import failed_section_scope, verify_targeted_structured_repair
from .teaching_verify import render_teaching_notes_view, run_teaching_verify_cite_flow
from .uploads import QuestionUploadProcessor, UploadPreparation

MAX_MERGED_EVIDENCE = 60
_JOB_RETRIEVER: ContextVar[EvidenceRetriever | None] = ContextVar(
    "legalbot_job_retriever", default=None
)


class JobCancellationRequested(RuntimeError):
    """Internal control signal after a durable cancellation checkpoint."""


# Bump whenever the model-visible drafting contract changes. Together with the
# configured model identity this prevents an owner resume from silently reusing
# a checkpoint produced under different generation instructions or weights.
DRAFT_CHECKPOINT_PROMPT_VERSION = "evidence-first-section-draft-v5"
REPAIR_CHECKPOINT_PROMPT_VERSION = "evidence-first-targeted-repair-v3"
NORMAL_LIVE_CONTENT_CERTIFICATION_STOP = (
    "TECHNICAL_IMPLEMENTATION_REQUIRED:normal_live_release_content_certification_missing"
)
SUPERSEDED_EVALUATION_CONTENT_CERTIFICATION_STOP = (
    "TECHNICAL_IMPLEMENTATION_REQUIRED:superseded_evaluation_release_content_certification_missing"
)


def evidence_pack_sha256(evidence_payload: object) -> str:
    """Canonical digest used by both checkpoint production and release replay."""

    return hashlib.sha256(
        json.dumps(evidence_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def draft_checkpoint_input_sha256(
    *,
    question: str,
    task_type: TaskType,
    jurisdiction: str,
    as_of_date: date,
    word_target: int,
    pack_digest: str,
    assessment_rules: Sequence[str],
    upload_context: Sequence[UploadContextSpan],
    assessment_bundle_sha256: str,
    model_id: str,
) -> str:
    """Canonical identity of every model-visible draft checkpoint input."""

    from ..runtime_adapters import (
        DRAFT_SYSTEM_PROMPT_SHA256,
        GENERATION_CONFIG_SHA256,
        STRUCTURED_DRAFT_SCHEMA_SHA256,
    )

    assessment_rules_sha256 = hashlib.sha256(
        json.dumps(
            list(assessment_rules),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    upload_context_sha256 = hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in upload_context],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    return hashlib.sha256(
        json.dumps(
            {
                "question_sha256": hashlib.sha256(question.encode()).hexdigest(),
                "task_type": str(task_type),
                "jurisdiction": jurisdiction,
                "as_of_date": as_of_date.isoformat(),
                "word_target": word_target,
                "pack_digest": pack_digest,
                "assessment_rules_sha256": assessment_rules_sha256,
                "upload_context_sha256": upload_context_sha256,
                "policy_version": POLICY_VERSION,
                "assessment_bundle_sha256": assessment_bundle_sha256,
                "model_id": model_id,
                "prompt_contract_version": DRAFT_CHECKPOINT_PROMPT_VERSION,
                "prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
                "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
                "generation_config_sha256": GENERATION_CONFIG_SHA256,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()


def repair_checkpoint_input_sha256s(
    *,
    question: str,
    prior: StructuredDraft,
    failed_sections: Sequence[str],
    repair_plan_sections: Sequence[str],
    findings: Sequence[QualityFinding],
    evidence: Mapping[str, EvidenceSpan],
    word_target: int,
    upload_context: Sequence[UploadContextSpan],
    repair_round: int,
    section_key: str,
    assessment_bundle_sha256: str,
    model_id: str,
) -> tuple[str, str]:
    """Canonical identities for repair evidence and complete model input."""

    from ..runtime_adapters import (
        DRAFT_SYSTEM_PROMPT_SHA256,
        GENERATION_CONFIG_SHA256,
        STRUCTURED_DRAFT_SCHEMA_SHA256,
    )

    evidence_payload = {
        key: value.model_dump(mode="json") for key, value in sorted(evidence.items())
    }
    evidence_digest = hashlib.sha256(
        json.dumps(
            evidence_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    prior_digest = hashlib.sha256(
        json.dumps(
            prior.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    findings_digest = hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in findings],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    upload_context_digest = hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in upload_context],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    input_digest = hashlib.sha256(
        json.dumps(
            {
                "question_sha256": hashlib.sha256(question.encode("utf-8")).hexdigest(),
                "prior_structured_sha256": prior_digest,
                "failed_sections": list(failed_sections),
                "repair_plan_sections": list(repair_plan_sections),
                "findings_sha256": findings_digest,
                "evidence_pack_sha256": evidence_digest,
                "upload_context_sha256": upload_context_digest,
                "word_target": word_target,
                "repair_round": repair_round,
                "section_key": section_key,
                "policy_version": POLICY_VERSION,
                "policy_sha256": POLICY_SHA256,
                "assessment_bundle_sha256": assessment_bundle_sha256,
                "model_id": model_id,
                "prompt_contract_version": REPAIR_CHECKPOINT_PROMPT_VERSION,
                "prompt_sha256": DRAFT_SYSTEM_PROMPT_SHA256,
                "structured_draft_schema_sha256": STRUCTURED_DRAFT_SCHEMA_SHA256,
                "generation_config_sha256": GENERATION_CONFIG_SHA256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return input_digest, evidence_digest


def unified_diff(before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="previous",
            tofile="next",
        )
    )


def _quality_failure_identity_sha256(findings: Sequence[QualityFinding]) -> str:
    """Stable semantic identity for a quality failure across repair versions."""

    return hashlib.sha256(
        json.dumps(
            sorted(
                {
                    (
                        str(item.gate),
                        str(item.code),
                        str(item.section_id or ""),
                    )
                    for item in findings
                }
            ),
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _bind_model_draft_context(
    candidate: ModelDraft,
    *,
    task_type: TaskType | str,
    jurisdiction: str,
    as_of_date: date,
    preserve_structure_from: StructuredDraft | None = None,
) -> ModelDraft:
    """Replace model-controlled context and close non-claim prose bypasses.

    Every model-authored sentence that can reach the renderer lives in a claim
    and is evidence-dispositioned.  The model's ``material`` flag is never an
    authority boundary.  Titles, headings and limitations are either fixed
    application text or, during repair, copied byte-for-byte from the already
    canonical parent.
    """

    prior_headings = (
        {section.id: section.heading for section in preserve_structure_from.sections}
        if preserve_structure_from is not None
        else {}
    )
    sections = [
        section.model_copy(
            update={
                "heading": prior_headings.get(section.id, f"Analysis {position}"),
                "claims": [claim.model_copy(update={"material": True}) for claim in section.claims],
            }
        )
        for position, section in enumerate(candidate.structured.sections, start=1)
    ]

    structured = candidate.structured.model_copy(
        update={
            "title": (
                preserve_structure_from.title
                if preserve_structure_from is not None
                else "Evidence-first legal analysis"
            ),
            "task_type": task_type,
            "jurisdiction": jurisdiction,
            "as_of_date": as_of_date,
            "sections": sections,
            "limitations": (
                preserve_structure_from.limitations if preserve_structure_from is not None else []
            ),
        }
    )
    return ModelDraft(
        raw_text=candidate.raw_text,
        structured=structured,
        rubric_scores=candidate.rubric_scores,
        model_version=candidate.model_version,
        metrics=candidate.metrics,
    )


def _section_retrieval_subject(
    heading: str,
    *,
    whole_question_subject: str | None,
    recognised_subjects: Sequence[str],
) -> str | None:
    """Choose a safe per-section filter, broadening composite unknowns."""

    heading_subject = classify_subject(heading)
    if heading_subject is not None:
        return heading_subject
    if len(recognised_subjects) > 1:
        return None
    return whole_question_subject


class AnswerRunner:
    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        cipher: LocalCipher,
        retriever: EvidenceRetriever,
        model: AnswerModel,
        observability: RuntimeObservability | None = None,
        retriever_factory: Any | None = None,
        conversations: Any | None = None,
        query_rewriter: Any | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        self.cipher = cipher
        self._default_retriever = retriever
        self.retriever_factory = retriever_factory
        self.model = model
        self.observability = observability
        self.conversations = conversations
        self.query_rewriter = query_rewriter
        self.evaluator = QualityEvaluator(
            database,
            enforce_retrieval_threshold=not settings.test_mode,
        )
        self.gaps = GapQueue(settings.gap_queue_dir, cipher)
        self.uploads = QuestionUploadProcessor(
            settings=settings,
            database=database,
            cipher=cipher,
        )
        self.objects = EncryptedObjectStore(settings.runtime_object_dir, database, cipher)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._issue_plan_metadata: dict[str, dict[str, object]] = {}
        from ..observability.events import EventStore

        self.events = EventStore.from_settings(settings, database)

    @property
    def retriever(self) -> EvidenceRetriever:
        return _JOB_RETRIEVER.get() or self._default_retriever

    @retriever.setter
    def retriever(self, value: EvidenceRetriever) -> None:
        self._default_retriever = value

    def _require_normal_live_for_ordinary_job(
        self,
        row: Any,
        *,
        answer_id: str | None = None,
        owner_canary_publication_phase: Literal["pre_release", "released"] | None = None,
    ) -> object:
        """Replay evaluation authority or enforce the exact v1.11 live graph."""

        evaluation_values = (
            row["evaluation_run_id"],
            row["evaluation_case_id"],
            row["evaluation_request_sha256"],
            row["evaluation_authority_json"],
            row["evaluation_authority_sha256"],
        )
        if any(value not in (None, "") for value in evaluation_values):
            if not all(value not in (None, "") for value in evaluation_values):
                raise RuntimeError("evaluation_job_authority_incomplete")
            from ..evaluation.evaluation_job_authority import (
                replay_evaluation_job_authority,
            )

            request_data = json.loads(str(row["request_json"] or "{}"))
            if not isinstance(request_data, dict):
                raise RuntimeError("evaluation_job_request_invalid")
            authority_value = json.loads(str(row["evaluation_authority_json"] or "{}"))
            if (
                not isinstance(authority_value, dict)
                or authority_value.get("lane") != "owner_quality_canary"
            ):
                raise RuntimeError(SUPERSEDED_EVALUATION_CONTENT_CERTIFICATION_STOP)
            request_data["question"] = self.cipher.decrypt_text(row["encrypted_question"])
            request = QuestionRequest.model_validate(request_data)
            return replay_evaluation_job_authority(
                settings=self.settings,
                database=self.database,
                cipher=self.cipher,
                row=row,
                payload=request,
                answer_id=answer_id,
                owner_canary_publication_phase=owner_canary_publication_phase,
            )
        raise RuntimeError(NORMAL_LIVE_CONTENT_CERTIFICATION_STOP)

    def schedule(self, job_id: str) -> None:
        task = self._tasks.get(job_id)
        if task and not task.done():
            return
        self._tasks[job_id] = asyncio.create_task(self.run(job_id), name=f"answer-{job_id}")

    async def run(self, job_id: str, *, raise_on_error: bool = False) -> None:
        row = self.database.job(job_id)
        if row is None:
            return
        pin = row["pinned_index_build_id"]
        token = None
        if self.retriever_factory is not None:
            if not pin:
                raise RuntimeError("answer job is missing pinned_index_build_id")
            token = _JOB_RETRIEVER.set(self.retriever_factory.for_build(str(pin)))
        elif pin:
            default_pin = getattr(self._default_retriever, "_pinned_build_id", None)
            serving = self.database.active_index_id()
            if default_pin is not None and str(pin) != str(default_pin):
                raise RuntimeError("answer job pinned build differs from the runner retriever")
            if default_pin is None and serving and str(pin) != str(serving):
                raise RuntimeError(
                    "evaluation job cannot use an ACTIVE-following retriever without a pinned factory"
                )
        try:
            await self._run_bound(job_id, raise_on_error=raise_on_error)
        finally:
            if token is not None:
                _JOB_RETRIEVER.reset(token)

    async def _run_bound(self, job_id: str, *, raise_on_error: bool = False) -> None:
        row = self.database.job(job_id)
        if row is None:
            return
        from ..runtime_adapters import PROMPT_VERSION

        self.database.bind_job_runtime_identity(
            job_id,
            prompt_version=PROMPT_VERSION,
            router_version=ROUTER_VERSION,
            classifier_version=CLASSIFIER_VERSION,
            policy_sha256=POLICY_SHA256,
        )
        trace_context = (
            self.observability.context_from_row(row) if self.observability is not None else None
        )
        try:
            # Recovery is also a serving transition.  An ordinary pre-v1.11
            # outbox must not be promoted back to complete while normal-live
            # readiness is absent or stale.
            self._require_normal_live_for_ordinary_job(row)
        except Exception as exc:
            if raise_on_error:
                raise
            stop_reason = str(exc)
            terminal_reason = (
                stop_reason.removeprefix("TECHNICAL_IMPLEMENTATION_REQUIRED:")
                if stop_reason.startswith("TECHNICAL_IMPLEMENTATION_REQUIRED:")
                else "owner_quality_normal_live_not_verified"
            )
            self.database.update_job(
                job_id,
                status=JobStatus.ERROR,
                stage=JobStage.ERROR,
                progress=0,
                message="Answer generation is stopped by the current release certification gate",
                error_code=type(exc).__name__,
            )
            self.database.execute(
                "UPDATE jobs SET terminal_reason_code=? WHERE id=?",
                (terminal_reason, job_id),
            )
            return
        published = self.database.released_outbox_for_job(job_id)
        if published is not None:
            self.database.update_job(
                job_id,
                status=JobStatus.COMPLETE,
                stage=(
                    JobStage.LIMITED
                    if published["release_state"] == ReleaseState.VERIFIED_LIMITED
                    else JobStage.COMPLETE
                ),
                progress=1,
                message=self._release_message(ReleaseState(str(published["release_state"]))),
                answer_id=str(published["answer_id"]),
                release_state=str(published["release_state"]),
                checkpoint={
                    "answer_id": str(published["answer_id"]),
                    "outbox_recovered": True,
                },
            )
            return
        if str(row["status"]) in {JobStatus.COMPLETE, JobStatus.HELD} and row["answer_id"]:
            return
        try:
            if self.observability is None:
                question = self.cipher.decrypt_text(row["encrypted_question"])
                request_data = json.loads(row["request_json"])
                request_data["question"] = question
                request = QuestionRequest.model_validate(request_data)
                await self._run(job_id, question, request)
            else:
                with self.observability.bind(trace_context):
                    question = self.cipher.decrypt_text(row["encrypted_question"])
                    request_data = json.loads(row["request_json"])
                    request_data["question"] = question
                    request = QuestionRequest.model_validate(request_data)
                    await self._run(job_id, question, request)
        except JobCancellationRequested:
            return
        except Exception as exc:  # operational boundary: checkpoint remains resumable
            if self.observability is not None and trace_context is not None:
                self.observability.record_error(
                    trace_context,
                    stage=TraceStage.RUN,
                    error_code=type(exc).__name__,
                )
            if raise_on_error:
                raise
            self.database.update_job(
                job_id,
                status=JobStatus.ERROR,
                stage=JobStage.ERROR,
                progress=1,
                message=(
                    "The local job stopped because a model, index, storage or parsing operation failed. "
                    "The encrypted draft and checkpoint were retained for resume."
                ),
                error_code=type(exc).__name__,
                checkpoint=self._checkpoint(
                    job_id, {"resumable": True, "error_type": type(exc).__name__}
                ),
            )
        finally:
            self._issue_plan_metadata.pop(job_id, None)

    async def _conversation_query_with_checkpoint(
        self,
        *,
        job_id: str,
        question: str,
        request: QuestionRequest,
    ) -> Any:
        from ..conversations import (
            QUERY_REWRITE_VERSION,
            ConversationQueryRewriter,
            ConversationRewriteResult,
            JsonRewriteModel,
        )

        disabled = ConversationQueryRewriter(
            cast(JsonRewriteModel, self.model),
            enabled=False,
            owner_identifiers=self.settings.owner_identifiers,
        )
        if request.conversation_id is None:
            return await disabled.rewrite(question=question, history=())
        row = self.database.job(job_id)
        if row is None:
            raise RuntimeError("conversation rewrite job no longer exists")
        if row["evaluation_run_id"] is not None or row["evaluation_case_id"] is not None:
            raise RuntimeError("evaluation jobs cannot use conversation query rewriting")
        if self.conversations is None:
            raise RuntimeError("conversation query rewriting requires encrypted conversation storage")
        window = self.conversations.window(request.conversation_id)
        history = tuple(item for item in window.messages if item.job_id != job_id)
        input_digest = hashlib.sha256(
            json.dumps(
                {
                    "question_sha256": hashlib.sha256(question.encode()).hexdigest(),
                    "history": [
                        {
                            "id": item.id,
                            "ordinal": item.ordinal,
                            "role": item.role,
                            "content_sha256": item.content_sha256,
                        }
                        for item in history
                    ],
                    "version": QUERY_REWRITE_VERSION,
                    "enabled": bool(self.settings.conversation_query_rewrite_enabled),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        completed = self.database.completed_stage_attempt(
            job_id, "query-rewrite", "conversation"
        )
        if completed is not None:
            if str(completed["input_digest"] or "") != input_digest:
                raise RuntimeError("completed conversation rewrite differs from frozen inputs")
            if not completed["output_object_key"]:
                raise RuntimeError("completed conversation rewrite has no encrypted output")
            value = self.objects.get_json(str(completed["output_object_key"]))
            if (
                value.get("schema") != "legalbot.conversation-query-rewrite-checkpoint.v1"
                or value.get("job_id") != job_id
                or value.get("input_digest") != input_digest
            ):
                raise RuntimeError("conversation rewrite checkpoint identity mismatch")
            return ConversationRewriteResult(
                query=str(value["query"]),
                status=str(value["status"]),  # type: ignore[arg-type]
                version=str(value["version"]),
                input_sha256=str(value["input_sha256"]),
                output_sha256=str(value["output_sha256"]),
                used_message_ids=tuple(str(item) for item in value["used_message_ids"]),
                reason_code=(str(value["reason_code"]) if value.get("reason_code") else None),
            )

        attempt_id = str(uuid4())
        self.database.store_stage_attempt(
            attempt_id=attempt_id,
            job_id=job_id,
            stage_key="query-rewrite",
            section_key="conversation",
            attempt_number=self.database.next_stage_attempt_number(
                job_id, "query-rewrite", "conversation"
            ),
            status="running",
            encrypted_output=None,
            input_digest=input_digest,
        )
        rewriter = self.query_rewriter or disabled
        try:
            result = await rewriter.rewrite(question=question, history=history)
            output = {
                "schema": "legalbot.conversation-query-rewrite-checkpoint.v1",
                "job_id": job_id,
                "input_digest": input_digest,
                "query": result.query,
                "status": result.status,
                "version": result.version,
                "input_sha256": result.input_sha256,
                "output_sha256": result.output_sha256,
                "used_message_ids": list(result.used_message_ids),
                "reason_code": result.reason_code,
                "conversation_is_evidence": False,
            }
            output_key = self.objects.put_json(
                namespace="conversation_query_rewrites",
                value=output,
                metadata={
                    "purpose": "encrypted_non_evidence_query_rewrite",
                    "input_digest": input_digest,
                    "version": result.version,
                    "conversation_is_evidence": False,
                },
            )
            self.database.finish_stage_attempt(
                attempt_id,
                status="complete",
                encrypted_output=None,
                output_object_key=output_key,
                metrics=result.safe_metadata(),
            )
            return result
        except Exception as exc:
            self.database.finish_stage_attempt(
                attempt_id,
                status="failed",
                encrypted_output=None,
                error_code=type(exc).__name__,
            )
            raise

    async def _run(self, job_id: str, question: str, request: QuestionRequest) -> None:
        rewrite = await self._conversation_query_with_checkpoint(
            job_id=job_id,
            question=question,
            request=request,
        )
        question = rewrite.query
        task_type = classify_task(question, request.task_type)
        subject = classify_subject(question)
        as_of = request.as_of_date or datetime.now(ZoneInfo("Europe/London")).date()
        upload_preparation = await asyncio.to_thread(
            self.uploads.prepare,
            job_id=job_id,
            upload_ids=request.upload_ids,
            question=question,
            jurisdiction=request.jurisdiction,
            subject=subject,
        )
        index_ready = True
        retriever_available = True
        try:
            index_ready = self.retriever.active_build_id() is not None
        except Exception:
            retriever_available = False
            index_ready = False
        upload_text = " ".join(upload_preparation.review_reasons).casefold()
        early = route_behavior(
            BehaviorSignals(
                question=question,
                jurisdiction=request.jurisdiction,
                upload_unreadable=any(
                    token in upload_text
                    for token in (
                        "unreadable",
                        "could not be used",
                        "invalid",
                        "unsupported",
                    )
                ),
                upload_encrypted="encrypted" in upload_text,
                index_ready=index_ready,
                retriever_available=retriever_available,
                unsafe_question=question_is_entirely_unsafe(question),
            )
        )
        if early.reason_code in {
            FailureReasonCode.OUTSIDE_PRODUCT_JURISDICTION,
            FailureReasonCode.ENTIRELY_UNSAFE,
            FailureReasonCode.ENCRYPTED_OR_UNREADABLE_UPLOAD,
            FailureReasonCode.MISSING_USER_FACTS,
            FailureReasonCode.INDEX_NOT_READY,
            FailureReasonCode.RETRIEVER_UNAVAILABLE,
        }:
            await self._release_behavior(job_id, request, task_type, as_of, early)
            return
        self._event(
            job_id,
            JobStage.RESEARCHING,
            0.08,
            "Spotting possible issues from approved private teaching material",
        )
        raw_notes = [
            *upload_preparation.issue_notes,
            *list(
                await self.retriever.retrieve_issue_spotting_notes(
                    query=question,
                    jurisdiction=request.jurisdiction,
                    subject=subject,
                    as_of_date=as_of,
                    limit=8,
                )
            ),
        ]
        safe_notes, unsafe_notes = self._screen_issue_notes(raw_notes)
        issue_plan = build_issue_plan(
            question=question,
            jurisdiction=request.jurisdiction,
            subject=subject,
            notes=safe_notes,
            owner_identifiers=self.settings.owner_identifiers,
            unsafe_notes_excluded=len(unsafe_notes),
        )
        self.database.bind_job_issue_plan_proposition_keys(job_id, issue_plan.proposition_keys)
        issue_metadata = issue_plan.safe_metadata()
        issue_metadata["conversation_query_rewrite"] = rewrite.safe_metadata()
        if upload_preparation.uploads_considered:
            issue_metadata.update(
                {
                    "uploads_considered": upload_preparation.uploads_considered,
                    "upload_context_count": len(upload_preparation.contexts),
                    "upload_review_required": upload_preparation.needs_review,
                }
            )
        issue_metadata["subject_routing"] = build_subject_routing_audit(classify_subjects(question))
        self._issue_plan_metadata[job_id] = issue_metadata
        if self._stop_if_cancelled(job_id):
            return
        row = self.database.job(job_id)
        route = AnswerRoute(str(row["route"])) if row is not None else AnswerRoute.DIRECT
        if route != AnswerRoute.DIRECT:
            await self._run_sectioned(
                job_id=job_id,
                question=question,
                request=request,
                task_type=task_type,
                subject=subject,
                as_of=as_of,
                issue_plan=issue_plan,
                upload_preparation=upload_preparation,
                route=route,
                query_rewrite_version=rewrite.version,
            )
            return
        self._event(
            job_id,
            JobStage.RESEARCHING,
            0.12,
            "Searching the approved legal source build",
        )
        retrieval_started = time.perf_counter()
        evidence_batches = await self._retrieve_research_plan(
            items=tuple((query, subject) for query in issue_plan.queries),
            jurisdiction=request.jurisdiction,
            as_of=as_of,
            cacheable=not bool(request.upload_ids),
            query_rewrite_version=rewrite.version,
        )
        retrieval_duration = time.perf_counter() - retrieval_started
        if self.observability is not None:
            context = self.observability.context_for_job(job_id)
            if context is not None:
                self.observability.record_duration(
                    context,
                    metric="retrieval_seconds",
                    duration_seconds=retrieval_duration,
                    operation=TraceOperation.RETRIEVAL,
                    stage=TraceStage.RETRIEVAL,
                    section_key="direct",
                )
        self.database.store_stage_attempt(
            attempt_id=str(uuid4()),
            job_id=job_id,
            stage_key="retrieval",
            section_key="all-issues",
            attempt_number=self.database.next_stage_attempt_number(
                job_id, "retrieval", "all-issues"
            ),
            status="complete",
            encrypted_output=None,
            metrics={
                "duration_ms": round(retrieval_duration * 1000),
                "query_count": len(issue_plan.queries),
                "candidate_count": sum(len(items) for items in evidence_batches),
            },
        )
        evidence = self._dedupe_legal_evidence(evidence_batches)

        searches: list[dict[str, str]] = []
        rejections: list[str] = []
        # Official-source discovery is a separate durable control-plane task.
        # It may be queued only after this immutable answer snapshot ends as
        # limited/held; it never injects newly fetched bytes into the current
        # answer or bypasses the owner-promoted ACTIVE authority store.

        if not evidence:
            retrieval_failure_code = getattr(
                self.retriever, "last_retrieval_code", None
            )
            post = route_behavior(
                BehaviorSignals(
                    question=question,
                    index_ready=True,
                    retriever_available=True,
                    retrieval_attempted=True,
                    retrieval_hit_count=0,
                    missing_named_document=looks_like_missing_document(question, 0),
                    retrieval_failure_code=(
                        str(retrieval_failure_code)
                        if retrieval_failure_code is not None
                        else None
                    ),
                )
            )
            gap = KnowledgeGap(
                id=str(uuid4()),
                job_id=job_id,
                missing_proposition=scrub_pii(question),
                jurisdiction=request.jurisdiction,
                subject=subject,
                searches_attempted=searches,
                rejection_reasons=[
                    *(rejections or ["No qualifying source span was available"]),
                    *upload_preparation.review_reasons,
                    post.reason_code.value,
                ],
            )
            gap_file = self.gaps.persist(gap)
            self._store_gap(gap, gap_file)
            await self._release_behavior(job_id, request, task_type, as_of, post, gap=gap)
            return

        if upload_preparation.needs_review:
            self._persist_upload_review_gap(
                job_id=job_id,
                jurisdiction=request.jurisdiction,
                subject=subject,
                preparation=upload_preparation,
            )

        self._event(
            job_id,
            JobStage.QUALIFYING,
            0.32,
            "Verifying source identity, jurisdiction and currentness",
        )
        identity_qualified = [
            span
            for span in evidence
            if evidence_span_eligible_for_drafting(span, as_of_date=as_of, database=self.database)
            and compatible(request.jurisdiction, span.jurisdiction, span.citation_data)
        ]
        unsafe_source_ids = {
            span.source_version_id
            for span in identity_qualified
            if prompt_injection_hits(
                json.dumps(
                    {
                        "text": span.text,
                        "locator": span.locator,
                        "canonical_citation": span.canonical_citation,
                        "citation_data": span.citation_data,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        }
        for source_version_id in sorted(unsafe_source_ids):
            self.database.queue_document_safety_review(source_version_id)
        qualified = [
            span
            for span in identity_qualified
            if not prompt_injection_hits(
                json.dumps(
                    {
                        "text": span.text,
                        "locator": span.locator,
                        "canonical_citation": span.canonical_citation,
                        "citation_data": span.citation_data,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
        ]
        if not qualified:
            post = route_behavior(
                BehaviorSignals(
                    question=question,
                    index_ready=True,
                    retriever_available=True,
                    retrieval_attempted=True,
                    retrieval_hit_count=len(evidence),
                    qualifying_evidence_count=0,
                    mixed_unsafe_remainder=bool(unsafe_source_ids),
                    unsafe_question=bool(unsafe_source_ids),
                )
            )
            gap = KnowledgeGap(
                id=str(uuid4()),
                job_id=job_id,
                missing_proposition=scrub_pii(question),
                jurisdiction=request.jurisdiction,
                subject=subject,
                searches_attempted=searches,
                rejection_reasons=(
                    [
                        "Retrieved evidence was excluded before model prompting because it "
                        "contained document-borne instruction patterns"
                    ]
                    if unsafe_source_ids
                    else [
                        "Retrieved candidates failed identity, currentness or jurisdiction checks"
                    ]
                ),
            )
            gap_file = self.gaps.persist(gap)
            self._store_gap(gap, gap_file)
            await self._release_behavior(job_id, request, task_type, as_of, post, gap=gap)
            return

        self.database.store_evidence([item.model_dump(mode="json") for item in qualified])
        self._record_teaching_verify_cite(job_id, issue_plan, qualified)
        if self._stop_if_cancelled(job_id):
            return
        self._event(
            job_id,
            JobStage.DRAFTING,
            0.46,
            "Drafting claims bound to verified evidence IDs",
        )
        # ``Record`` serialises ``StrEnum`` fields as their values, so requests
        # validated by Pydantic may expose a plain string at runtime.
        assessment_guidance = self._assessment_guidance(task_type, subject)
        candidate = await self._draft_with_checkpoint(
            job_id=job_id,
            section_key="whole-answer",
            question=question,
            task_type=task_type,
            jurisdiction=request.jurisdiction,
            as_of_date=as_of,
            word_target=request.word_target,
            evidence=qualified,
            assessment_rules=assessment_guidance.instructions,
            assessment_bundle_sha256=assessment_guidance.bundle_sha256,
            upload_context=upload_preparation.contexts,
        )
        if upload_preparation.needs_review:
            candidate = candidate.__class__(
                raw_text=candidate.raw_text,
                structured=candidate.structured.model_copy(
                    update={
                        "limitations": [
                            *candidate.structured.limitations,
                            "One or more attached materials were used only as non-authoritative context; their legal-source identity or processing status remains in the review queue.",
                        ]
                    }
                ),
                rubric_scores=candidate.rubric_scores,
                model_version=candidate.model_version,
                metrics=candidate.metrics,
            )
        version_number = self.database.next_answer_version_number(job_id)
        raw_id = str(uuid4())
        self.database.store_answer_version(
            answer_id=raw_id,
            job_id=job_id,
            version_number=version_number,
            version_kind="raw_model",
            encrypted_content=self.cipher.encrypt_text(candidate.raw_text),
            word_count=word_count(candidate.raw_text),
            policy_version=POLICY_VERSION,
            model_version=candidate.model_version,
            index_build_id=self.retriever.active_build_id(),
        )
        evidence_by_id = {item.id: item for item in qualified}
        final = await self._verify_and_repair(
            job_id=job_id,
            question=question,
            request=request,
            candidate=candidate,
            evidence_by_id=evidence_by_id,
            version_number=self.database.next_answer_version_number(job_id),
            parent_id=raw_id,
            parent_text=candidate.raw_text,
            subject=subject,
            upload_context=upload_preparation.contexts,
        )
        self.database.update_job(
            job_id,
            status=JobStatus.HELD
            if final[1] == ReleaseState.HELD_FOR_REVIEW
            else JobStatus.COMPLETE,
            stage=JobStage.HELD
            if final[1] == ReleaseState.HELD_FOR_REVIEW
            else (
                JobStage.LIMITED if final[1] == ReleaseState.VERIFIED_LIMITED else JobStage.COMPLETE
            ),
            progress=1,
            message=self._release_message(final[1]),
            answer_id=final[0],
            release_state=final[1],
            checkpoint=self._checkpoint(job_id, {"answer_id": final[0], "release_state": final[1]}),
        )

    async def _draft_with_checkpoint(
        self,
        *,
        job_id: str,
        section_key: str,
        question: str,
        task_type: TaskType,
        jurisdiction: str,
        as_of_date: date,
        word_target: int,
        evidence: Sequence[EvidenceSpan],
        assessment_rules: Sequence[str],
        assessment_bundle_sha256: str,
        upload_context: Sequence[UploadContextSpan] = (),
    ) -> ModelDraft:
        active_build = self.retriever.active_build_id()
        if not active_build:
            raise RuntimeError("a frozen active index is required before answer generation")
        evidence_payload = [item.model_dump(mode="json") for item in evidence]
        pack_digest = evidence_pack_sha256(evidence_payload)
        self.database.bind_job_assessment_bundle(job_id, assessment_bundle_sha256)
        evidence_object_key = self.objects.put_json(
            namespace="evidence_packs",
            value={
                "job_id": job_id,
                "section_key": section_key,
                "evidence": evidence_payload,
            },
            metadata={
                "purpose": "durable_evidence_pack",
                "pack_digest": pack_digest,
                "index_build_id": active_build,
            },
            ttl_days=None,
        )
        freeze_db_started = time.perf_counter()
        self.database.freeze_evidence_pack(
            pack_id=f"pack-{hashlib.sha256(f'{job_id}:{section_key}'.encode()).hexdigest()[:40]}",
            job_id=job_id,
            section_key=section_key,
            digest=pack_digest,
            index_build_id=active_build,
            source_ids=[item.source_version_id for item in evidence],
            # Schema v12 stored a second encrypted copy in SQLite. New packs
            # keep only the object key/digest there; the object store is the
            # canonical encrypted payload. The non-null empty blob preserves
            # backwards schema compatibility without duplicating private text.
            encrypted_payload=b"",
            object_key=evidence_object_key,
        )
        if self.observability is not None:
            context = self.observability.context_for_job(job_id)
            if context is not None:
                self.observability.record_db_duration(
                    context,
                    operation=DatabaseOperation.STORE_EVIDENCE_PACK,
                    stage=TraceStage.EVIDENCE_FREEZE,
                    duration_seconds=time.perf_counter() - freeze_db_started,
                )
        input_digest = draft_checkpoint_input_sha256(
            question=question,
            task_type=task_type,
            jurisdiction=jurisdiction,
            as_of_date=as_of_date,
            word_target=word_target,
            pack_digest=pack_digest,
            assessment_rules=assessment_rules,
            upload_context=upload_context,
            assessment_bundle_sha256=assessment_bundle_sha256,
            model_id=self.settings.model_id,
        )
        completed = self.database.completed_stage_attempt(job_id, "draft", section_key)
        if completed is not None:
            if completed["input_digest"] != input_digest:
                raise RuntimeError("completed draft checkpoint does not match frozen inputs")
            if completed["output_object_key"]:
                value = self.objects.get_json(str(completed["output_object_key"]))
            elif completed["encrypted_output"]:
                # Backwards-compatible read for pre-v13 checkpoints.
                value = json.loads(self.cipher.decrypt_text(completed["encrypted_output"]))
            else:
                raise RuntimeError("completed draft checkpoint has no durable output")
            restored = ModelDraft(
                raw_text=str(value["raw_text"]),
                structured=StructuredDraft.model_validate(value["structured"]),
                rubric_scores={str(k): float(v) for k, v in value["rubric_scores"].items()},
                model_version=str(value["model_version"]),
                metrics=dict(value.get("metrics") or {}),
            )
            return _bind_model_draft_context(
                restored,
                task_type=task_type,
                jurisdiction=jurisdiction,
                as_of_date=as_of_date,
            )
        attempt = self.database.fetchone(
            "SELECT COUNT(*) AS n FROM job_stage_attempts WHERE job_id=? AND stage_key='draft' AND section_key=?",
            (job_id, section_key),
        )
        attempt_number = int(attempt["n"]) + 1 if attempt is not None else 1
        attempt_id = str(uuid4())
        self.database.store_stage_attempt(
            attempt_id=attempt_id,
            job_id=job_id,
            stage_key="draft",
            section_key=section_key,
            attempt_number=attempt_number,
            status="running",
            encrypted_output=None,
            input_digest=input_digest,
            evidence_pack_digest=pack_digest,
        )
        generation_started = time.perf_counter()
        try:
            self._raise_if_cancelled(job_id)
            from ..jobs import ANSWER_MODEL_CALL_SECONDS

            call_token, _ = self.database.arm_model_call_deadline(
                job_id, seconds=ANSWER_MODEL_CALL_SECONDS
            )
            try:
                async with asyncio.timeout(ANSWER_MODEL_CALL_SECONDS):
                    candidate = await self.model.draft(
                        question=question,
                        task_type=task_type,
                        jurisdiction=jurisdiction,
                        as_of_date=as_of_date,
                        word_target=word_target,
                        evidence=evidence,
                        assessment_rules=assessment_rules,
                        upload_context=upload_context,
                    )
            finally:
                if not self.database.clear_model_call_deadline(job_id, call_token=call_token):
                    raise RuntimeError("model-call deadline ownership changed during draft")
            self._raise_if_cancelled(job_id)
            candidate = _bind_model_draft_context(
                candidate,
                task_type=task_type,
                jurisdiction=jurisdiction,
                as_of_date=as_of_date,
            )
        except Exception as exc:
            self.database.finish_stage_attempt(
                attempt_id,
                status="failed",
                encrypted_output=None,
                error_code=type(exc).__name__,
            )
            if self.observability is not None:
                context = self.observability.context_for_job(job_id)
                if context is not None:
                    duration = time.perf_counter() - generation_started
                    self.observability.record_duration(
                        context,
                        metric="generation_seconds",
                        duration_seconds=duration,
                        operation=TraceOperation.MODEL,
                        stage=TraceStage.GENERATION,
                        section_key=section_key,
                        status=TraceStatus.ERROR,
                        level=TraceLevel.ERROR,
                        error_code=type(exc).__name__,
                    )
                    self.observability.record_error(
                        context,
                        stage=TraceStage.GENERATION,
                        error_code=type(exc).__name__,
                        duration_seconds=duration,
                    )
            raise
        if self.observability is not None:
            context = self.observability.context_for_job(job_id)
            if context is not None:
                self.observability.record_model_metrics(
                    context,
                    model_metrics=candidate.metrics,
                    wall_duration_seconds=time.perf_counter() - generation_started,
                    stage=TraceStage.GENERATION,
                    section_key=section_key,
                )
        output = {
            "raw_text": candidate.raw_text,
            "structured": candidate.structured.model_dump(mode="json"),
            "rubric_scores": candidate.rubric_scores,
            "model_version": candidate.model_version,
            "metrics": candidate.metrics or {},
        }
        output_object_key = self.objects.put_json(
            namespace="draft_checkpoints",
            value={"job_id": job_id, "section_key": section_key, **output},
            metadata={
                "purpose": "encrypted_resume_checkpoint",
                "input_digest": input_digest,
                "assessment_bundle_sha256": assessment_bundle_sha256,
            },
        )
        self.database.finish_stage_attempt(
            attempt_id,
            status="complete",
            encrypted_output=None,
            output_object_key=output_object_key,
            metrics=candidate.metrics,
        )
        return candidate

    async def _repair_with_checkpoint(
        self,
        *,
        job_id: str,
        repair_round: int,
        section_key: str,
        question: str,
        prior: StructuredDraft,
        failed_sections: Sequence[str],
        repair_plan_sections: Sequence[str],
        findings: Sequence[QualityFinding],
        evidence: Mapping[str, EvidenceSpan],
        word_target: int,
        upload_context: Sequence[UploadContextSpan] = (),
    ) -> tuple[ModelDraft, bool]:
        """Run or reuse one digest-bound encrypted targeted-repair call.

        The round is part of the stage identity, so the first and second
        bounded repairs cannot shadow one another. A completed checkpoint is
        reusable only when every model-visible and policy input is identical.
        The boolean result reports whether the model call was reused.
        """

        if not 1 <= repair_round <= 99:
            raise ValueError("repair round is outside the bounded checkpoint range")
        if not section_key:
            raise ValueError("repair checkpoint requires a section key")
        job = self.database.job(job_id)
        if job is None:
            raise RuntimeError("repair checkpoint job no longer exists")
        assessment_bundle_sha256 = str(job["assessment_bundle_sha256"] or "")
        if not re.fullmatch(r"[0-9a-f]{64}", assessment_bundle_sha256):
            raise RuntimeError("repair checkpoint has no immutable assessment bundle")

        input_digest, evidence_pack_digest = repair_checkpoint_input_sha256s(
            question=question,
            prior=prior,
            failed_sections=failed_sections,
            repair_plan_sections=repair_plan_sections,
            findings=findings,
            evidence=evidence,
            word_target=word_target,
            upload_context=upload_context,
            repair_round=repair_round,
            section_key=section_key,
            assessment_bundle_sha256=assessment_bundle_sha256,
            model_id=self.settings.model_id,
        )
        stage_key = f"repair-{repair_round:02d}"
        completed = self.database.completed_stage_attempt(job_id, stage_key, section_key)
        if completed is not None:
            if (
                str(completed["input_digest"] or "") != input_digest
                or str(completed["evidence_pack_digest"] or "") != evidence_pack_digest
            ):
                raise RuntimeError("completed repair checkpoint does not match frozen inputs")
            if not completed["output_object_key"]:
                raise RuntimeError("completed repair checkpoint has no encrypted output object")
            value = self.objects.get_json(str(completed["output_object_key"]))
            expected = (
                "legalbot.repair-checkpoint.v1",
                job_id,
                stage_key,
                section_key,
                repair_round,
                input_digest,
                evidence_pack_digest,
            )
            observed = (
                value.get("schema"),
                value.get("job_id"),
                value.get("stage_key"),
                value.get("section_key"),
                value.get("repair_round"),
                value.get("input_digest"),
                value.get("evidence_pack_digest"),
            )
            if observed != expected:
                raise RuntimeError("encrypted repair checkpoint identity validation failed")
            output = value.get("output")
            if not isinstance(output, Mapping):
                raise RuntimeError("encrypted repair checkpoint output is invalid")
            restored = ModelDraft(
                raw_text=str(output["raw_text"]),
                structured=StructuredDraft.model_validate(output["structured"]),
                rubric_scores={
                    str(key): float(score) for key, score in dict(output["rubric_scores"]).items()
                },
                model_version=str(output["model_version"]),
                metrics=dict(output.get("metrics") or {}),
            )
            restored = _bind_model_draft_context(
                restored,
                task_type=prior.task_type,
                jurisdiction=prior.jurisdiction,
                as_of_date=prior.as_of_date,
                preserve_structure_from=prior,
            )
            verify_targeted_structured_repair(
                prior=prior,
                repaired=restored.structured,
                failed_sections=failed_sections,
                findings=findings,
            )
            return restored, True

        attempt_id = str(uuid4())
        self.database.store_stage_attempt(
            attempt_id=attempt_id,
            job_id=job_id,
            stage_key=stage_key,
            section_key=section_key,
            attempt_number=self.database.next_stage_attempt_number(job_id, stage_key, section_key),
            status="running",
            encrypted_output=None,
            input_digest=input_digest,
            evidence_pack_digest=evidence_pack_digest,
        )
        repair_started = time.perf_counter()
        try:
            self._raise_if_cancelled(job_id)
            from ..jobs import ANSWER_MODEL_CALL_SECONDS

            call_token, _ = self.database.arm_model_call_deadline(
                job_id, seconds=ANSWER_MODEL_CALL_SECONDS
            )
            try:
                async with asyncio.timeout(ANSWER_MODEL_CALL_SECONDS):
                    repaired = await self.model.repair(
                        question=question,
                        prior=prior,
                        failed_sections=failed_sections,
                        findings=findings,
                        evidence=evidence,
                        word_target=word_target,
                        upload_context=upload_context,
                    )
            finally:
                if not self.database.clear_model_call_deadline(job_id, call_token=call_token):
                    raise RuntimeError("model-call deadline ownership changed during repair")
            self._raise_if_cancelled(job_id)
            repaired = _bind_model_draft_context(
                repaired,
                task_type=prior.task_type,
                jurisdiction=prior.jurisdiction,
                as_of_date=prior.as_of_date,
                preserve_structure_from=prior,
            )
            verify_targeted_structured_repair(
                prior=prior,
                repaired=repaired.structured,
                failed_sections=failed_sections,
                findings=findings,
            )
        except Exception as exc:
            self.database.finish_stage_attempt(
                attempt_id,
                status="failed",
                encrypted_output=None,
                error_code=type(exc).__name__,
            )
            if self.observability is not None:
                context = self.observability.context_for_job(job_id)
                if context is not None:
                    duration = time.perf_counter() - repair_started
                    self.observability.record_duration(
                        context,
                        metric=None,
                        duration_seconds=duration,
                        operation=TraceOperation.MODEL,
                        stage=TraceStage.REPAIR,
                        section_key=section_key,
                        status=TraceStatus.ERROR,
                        level=TraceLevel.ERROR,
                        error_code=type(exc).__name__,
                    )
                    self.observability.record_error(
                        context,
                        stage=TraceStage.REPAIR,
                        error_code=type(exc).__name__,
                        duration_seconds=duration,
                    )
            raise
        if self.observability is not None:
            context = self.observability.context_for_job(job_id)
            if context is not None:
                self.observability.record_model_metrics(
                    context,
                    model_metrics=repaired.metrics,
                    wall_duration_seconds=time.perf_counter() - repair_started,
                    stage=TraceStage.REPAIR,
                    section_key=section_key,
                )
        output = {
            "raw_text": repaired.raw_text,
            "structured": repaired.structured.model_dump(mode="json"),
            "rubric_scores": repaired.rubric_scores,
            "model_version": repaired.model_version,
            "metrics": repaired.metrics or {},
        }
        output_object_key = self.objects.put_json(
            namespace="repair_checkpoints",
            value={
                "schema": "legalbot.repair-checkpoint.v1",
                "job_id": job_id,
                "stage_key": stage_key,
                "section_key": section_key,
                "repair_round": repair_round,
                "input_digest": input_digest,
                "evidence_pack_digest": evidence_pack_digest,
                "output": output,
            },
            metadata={
                "purpose": "encrypted_resume_checkpoint",
                "input_digest": input_digest,
                "evidence_pack_digest": evidence_pack_digest,
                "policy_sha256": POLICY_SHA256,
                "assessment_bundle_sha256": assessment_bundle_sha256,
                "model_id_sha256": hashlib.sha256(
                    self.settings.model_id.encode("utf-8")
                ).hexdigest(),
                "prompt_contract_version": REPAIR_CHECKPOINT_PROMPT_VERSION,
            },
        )
        self.database.finish_stage_attempt(
            attempt_id,
            status="complete",
            encrypted_output=None,
            output_object_key=output_object_key,
            metrics=repaired.metrics,
        )
        return repaired, False

    async def _retrieve_research_plan(
        self,
        *,
        items: Sequence[tuple[str, str | None]],
        jurisdiction: str,
        as_of: date,
        cacheable: bool,
        query_rewrite_version: str = "none-v1",
    ) -> tuple[Sequence[EvidenceSpan], ...]:
        """Prepare every research query, then rerank only if the whole plan fits."""

        plan = getattr(self.retriever, "retrieve_certified_plan", None)
        if callable(plan):
            from ..retrieval.models import RetrievalPlanItem

            return tuple(
                await plan(
                    tuple(
                        RetrievalPlanItem(
                            query=query,
                            jurisdiction=jurisdiction,
                            subject=subject,
                            as_of_date=as_of,
                            limit=30,
                            cacheable=cacheable,
                            query_rewrite_version=query_rewrite_version,
                        )
                        for query, subject in items
                    )
                )
            )
        batches = await asyncio.gather(
            *(
                self.retriever.retrieve(
                    query=query,
                    jurisdiction=jurisdiction,
                    subject=subject,
                    as_of_date=as_of,
                    limit=30,
                    cacheable=cacheable,
                )
                for query, subject in items
            )
        )
        return tuple(batches)

    async def _run_sectioned(
        self,
        *,
        job_id: str,
        question: str,
        request: QuestionRequest,
        task_type: TaskType,
        subject: str | None,
        as_of: date,
        issue_plan: IssuePlan,
        upload_preparation: UploadPreparation,
        route: AnswerRoute,
        query_rewrite_version: str,
    ) -> None:
        tasks = build_section_tasks(
            question=question, word_target=request.word_target, issue_plan=issue_plan
        )
        recognised_subjects = classify_subjects(question)
        self._issue_plan_metadata[job_id]["route"] = route.value
        self._issue_plan_metadata[job_id]["section_count"] = len(tasks)
        self._issue_plan_metadata[job_id]["subject_routing"] = build_subject_routing_audit(
            recognised_subjects
        )
        section_queries = tuple(
            (
                task,
                # Prefer an explicit section-domain heading. For a genuinely
                # composite question, an unclassified heading must search across
                # all approved subjects rather than inherit one whole-question
                # label and silently exclude the other legal domains.
                _section_retrieval_subject(
                    task.heading,
                    whole_question_subject=subject,
                    recognised_subjects=recognised_subjects,
                ),
            )
            for task in tasks
        )
        self._event(
            job_id,
            JobStage.RESEARCHING,
            0.16,
            f"Researching {len(tasks)} bounded sections against the frozen legal index",
        )
        retrieval_started = time.perf_counter()
        found_batches = await self._retrieve_research_plan(
            items=tuple((task.query, section_subject) for task, section_subject in section_queries),
            jurisdiction=request.jurisdiction,
            as_of=as_of,
            cacheable=not bool(request.upload_ids),
            query_rewrite_version=query_rewrite_version,
        )
        plan_ms = round((time.perf_counter() - retrieval_started) * 1000)
        retrieval_results = tuple(
            (
                task,
                self._qualified_evidence(found, request.jurisdiction, as_of_date=as_of),
                plan_ms,
                section_subject,
            )
            for (task, section_subject), found in zip(section_queries, found_batches, strict=True)
        )
        for task, evidence, duration_ms, retrieval_subject in retrieval_results:
            if self.observability is not None:
                context = self.observability.context_for_job(job_id)
                if context is not None:
                    self.observability.record_duration(
                        context,
                        metric="retrieval_seconds",
                        duration_seconds=duration_ms / 1_000,
                        operation=TraceOperation.RETRIEVAL,
                        stage=TraceStage.RETRIEVAL,
                        section_key=task.key,
                    )
            self.database.store_stage_attempt(
                attempt_id=str(uuid4()),
                job_id=job_id,
                stage_key="retrieval",
                section_key=task.key,
                attempt_number=self.database.next_stage_attempt_number(
                    job_id, "retrieval", task.key
                ),
                status="complete",
                encrypted_output=None,
                metrics={
                    "duration_ms": duration_ms,
                    "candidate_count": len(evidence),
                    "retrieval_subject": retrieval_subject or "broad_all_approved",
                    "certified_plan": True,
                },
            )
        uncovered = [
            task for task, evidence, _duration, _subject in retrieval_results if not evidence
        ]
        if uncovered:
            gap = KnowledgeGap(
                id=str(uuid4()),
                job_id=job_id,
                missing_proposition=(
                    "Evidence coverage for one or more planned long-form sections: "
                    + ", ".join(task.heading for task in uncovered)
                ),
                jurisdiction=request.jurisdiction,
                subject=subject,
                rejection_reasons=["At least one required section had no qualified evidence"],
            )
            path = self.gaps.persist(gap)
            self._store_gap(gap, path)
            retrieval_failure_code = getattr(
                self.retriever, "last_retrieval_code", None
            )
            if retrieval_failure_code in {
                "relevance_threshold_policy_not_frozen",
                "no_threshold_qualified_evidence",
            }:
                decision = route_behavior(
                    BehaviorSignals(
                        question=question,
                        retrieval_attempted=True,
                        retrieval_hit_count=1,
                        qualifying_evidence_count=0,
                        retrieval_failure_code=str(retrieval_failure_code),
                    )
                )
                await self._release_behavior(
                    job_id, request, task_type, as_of, decision, gap=gap
                )
            else:
                await self._release_no_source(job_id, request, task_type, as_of, gap)
            return
        all_evidence = self._dedupe_legal_evidence(
            [items for _, items, _duration, _subject in retrieval_results]
        )
        self.database.store_evidence([item.model_dump(mode="json") for item in all_evidence])
        self._record_teaching_verify_cite(job_id, issue_plan, all_evidence)
        assessment_guidance = self._assessment_guidance(task_type, subject)
        candidates: list[tuple[SectionTask, ModelDraft, list[EvidenceSpan]]] = []
        for index, (task, evidence, _duration, _subject) in enumerate(retrieval_results, start=1):
            if self._stop_if_cancelled(job_id):
                return
            self._event(
                job_id,
                JobStage.DRAFTING,
                0.30 + 0.38 * (index - 1) / max(1, len(tasks)),
                f"Drafting section {index} of {len(tasks)} from its frozen evidence pack",
            )
            candidate = await self._draft_with_checkpoint(
                job_id=job_id,
                section_key=task.key,
                # Put the section instruction before the scenario so the model
                # gateway's bounded question view cannot truncate the focus.
                question=f"Draft only this section: {task.heading}.\n\nQuestion: {question}",
                task_type=task_type,
                jurisdiction=request.jurisdiction,
                as_of_date=as_of,
                word_target=task.word_target,
                evidence=evidence,
                assessment_rules=assessment_guidance.instructions,
                assessment_bundle_sha256=assessment_guidance.bundle_sha256,
                upload_context=upload_preparation.contexts,
            )
            candidates.append((task, candidate, evidence))

        assembled = self._assemble_sections(
            task_type=task_type,
            jurisdiction=request.jurisdiction,
            as_of=as_of,
            candidates=candidates,
        )
        self._event(job_id, JobStage.ASSEMBLING, 0.72, "Assembling verified section drafts")
        raw = render_answer(assembled, {item.id: item for item in all_evidence}).markdown
        raw_id = str(uuid4())
        self.database.store_answer_version(
            answer_id=raw_id,
            job_id=job_id,
            version_number=self.database.next_answer_version_number(job_id),
            version_kind="sectioned_assembly",
            encrypted_content=self.cipher.encrypt_text(raw),
            word_count=word_count(raw),
            policy_version=POLICY_VERSION,
            model_version=candidates[0][1].model_version,
            index_build_id=self.retriever.active_build_id(),
        )
        combined = ModelDraft(
            raw_text=raw,
            structured=assembled,
            rubric_scores=self._mean_rubric([item[1] for item in candidates]),
            model_version=candidates[0][1].model_version,
            metrics=self._aggregate_model_metrics([item[1] for item in candidates]),
        )
        final = await self._verify_and_repair(
            job_id=job_id,
            question=question,
            request=request,
            candidate=combined,
            evidence_by_id={item.id: item for item in all_evidence},
            version_number=self.database.next_answer_version_number(job_id),
            parent_id=raw_id,
            parent_text=raw,
            subject=subject,
            upload_context=upload_preparation.contexts,
            section_evidence_by_id={
                task.key: {item.id: item for item in pack} for task, _candidate, pack in candidates
            },
        )
        self.database.update_job(
            job_id,
            status=JobStatus.HELD
            if final[1] == ReleaseState.HELD_FOR_REVIEW
            else JobStatus.COMPLETE,
            stage=JobStage.HELD
            if final[1] == ReleaseState.HELD_FOR_REVIEW
            else (
                JobStage.LIMITED if final[1] == ReleaseState.VERIFIED_LIMITED else JobStage.COMPLETE
            ),
            progress=1,
            message=self._release_message(final[1]),
            answer_id=final[0],
            release_state=final[1],
            checkpoint=self._checkpoint(job_id, {"answer_id": final[0], "release_state": final[1]}),
        )

    def _qualified_evidence(
        self,
        evidence: Sequence[EvidenceSpan],
        jurisdiction: str,
        *,
        as_of_date: date,
    ) -> list[EvidenceSpan]:
        qualified: list[EvidenceSpan] = []
        for span in evidence:
            if not (
                evidence_span_eligible_for_drafting(
                    span, as_of_date=as_of_date, database=self.database
                )
                and compatible(jurisdiction, span.jurisdiction, span.citation_data)
            ):
                continue
            document_view = json.dumps(
                {
                    "text": span.text,
                    "locator": span.locator,
                    "canonical_citation": span.canonical_citation,
                    "citation_data": span.citation_data,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            if prompt_injection_hits(document_view):
                self.database.queue_document_safety_review(span.source_version_id)
                continue
            qualified.append(span)
        return qualified

    def _assessment_guidance(
        self, task_type: TaskType, subject: str | None
    ) -> BudgetedAssessmentGuidance:
        """Select immutable 70+/60/50 guidance with atomic whole-rule budgeting.

        The previously approved marker-derived rows are excluded pending the
        owner provenance review.  This avoids injecting student-specific,
        mismatched or mixed-polarity feedback while retaining explicit positive
        repairs for every lower-band anti-pattern.
        """

        return budget_assessment_guidance(
            OWNER_ASSESSMENT_BUNDLE,
            task_type=str(task_type),
            subject=subject,
            max_characters=1_800,
        )

    def _assessment_rules(self, task_type: TaskType, subject: str | None) -> list[str]:
        """Compatibility view for diagnostics and existing tests."""

        return list(self._assessment_guidance(task_type, subject).instructions)

    @staticmethod
    def _assemble_sections(
        *,
        task_type: TaskType,
        jurisdiction: str,
        as_of: date,
        candidates: Sequence[tuple[SectionTask, ModelDraft, Sequence[EvidenceSpan]]],
    ) -> StructuredDraft:
        sections: list[StructuredSectionDraft] = []
        seen_claims: set[str] = set()
        for position, (task, candidate, pack) in enumerate(candidates, start=1):
            allowed = {item.id for item in pack}
            claims: list[StructuredClaimDraft] = []
            for source_section in candidate.structured.sections:
                for claim in source_section.claims:
                    normalised = " ".join(claim.text.casefold().split())
                    if normalised in seen_claims:
                        continue
                    seen_claims.add(normalised)
                    evidence_ids = [item for item in claim.evidence_ids if item in allowed]
                    claims.append(
                        claim.model_copy(
                            update={
                                "id": f"{task.key}-{claim.id}",
                                "evidence_ids": evidence_ids,
                            }
                        )
                    )
            sections.append(
                StructuredSectionDraft(
                    id=task.key,
                    heading=f"Analysis {position}",
                    claims=claims,
                )
            )
        return StructuredDraft(
            title="Evidence-first legal analysis",
            task_type=task_type,
            jurisdiction=jurisdiction,
            as_of_date=as_of,
            sections=sections,
            # Model-authored limitations are never rendered outside the claim
            # evidence contract.  Application-owned deterministic limitations
            # may be added by the caller after assembly when required.
            limitations=[],
        )

    @staticmethod
    def _mean_rubric(candidates: Sequence[ModelDraft]) -> dict[str, float]:
        keys = {key for candidate in candidates for key in candidate.rubric_scores}
        return {
            key: sum(item.rubric_scores.get(key, 0.0) for item in candidates) / len(candidates)
            for key in keys
        }

    @staticmethod
    def _aggregate_model_metrics(candidates: Sequence[ModelDraft]) -> dict[str, object]:
        metrics = [item.metrics or {} for item in candidates]
        return {
            "calls": len(metrics),
            "input_tokens": sum(int(item.get("input_tokens", 0)) for item in metrics),
            "output_tokens": sum(int(item.get("output_tokens", 0)) for item in metrics),
            "generation_ms": sum(int(item.get("generation_ms", 0)) for item in metrics),
            "peak_memory_gb": max(
                (float(item.get("peak_memory_gb") or 0.0) for item in metrics),
                default=0.0,
            ),
        }

    async def _verify_and_repair(
        self,
        *,
        job_id: str,
        question: str,
        request: QuestionRequest,
        candidate: ModelDraft,
        evidence_by_id: Mapping[str, EvidenceSpan],
        version_number: int,
        parent_id: str,
        parent_text: str,
        subject: str | None = None,
        upload_context: Sequence[UploadContextSpan] = (),
        section_evidence_by_id: Mapping[str, Mapping[str, EvidenceSpan]] | None = None,
    ) -> tuple[str, ReleaseState]:
        current = candidate
        attempts = 0
        prior_failure_fingerprints: list[str] = []
        while True:
            self._raise_if_cancelled(job_id)
            self._event(
                job_id,
                JobStage.VERIFYING,
                min(0.64 + attempts * 0.12, 0.86),
                "Verifying every material claim",
            )
            verification_started = time.perf_counter()
            rendered = render_answer(current.structured, evidence_by_id)
            answer_id = str(uuid4())
            report = self.evaluator.evaluate(
                answer_version_id=answer_id,
                draft=current.structured,
                rendered_text=rendered.markdown,
                evidence_by_id=evidence_by_id,
                word_count=rendered.word_count,
                word_target=request.word_target,
                rubric_scores=current.rubric_scores,
                question=question,
                subject=subject,
            )
            deterministic_hard_codes = tuple(
                sorted(
                    {
                        item.code
                        for item in report.findings
                        if item.severity == Severity.HARD_BLOCKER
                        and is_deterministic_safety_failure(item.code)
                    }
                )
            )
            if not self.settings.test_mode and not deterministic_hard_codes:
                from ..jobs import ANSWER_MODEL_CALL_SECONDS

                call_token, _ = self.database.arm_model_call_deadline(
                    job_id, seconds=ANSWER_MODEL_CALL_SECONDS
                )
                try:
                    async with asyncio.timeout(ANSWER_MODEL_CALL_SECONDS):
                        review = await invoke_ai_evidence_reviewer(
                            model=self.model,
                            draft=current.structured,
                            evidence_by_id=evidence_by_id,
                            model_id=self.settings.model_id,
                            model_version=current.model_version,
                            policy_sha256=POLICY_SHA256,
                        )
                finally:
                    if not self.database.clear_model_call_deadline(job_id, call_token=call_token):
                        raise RuntimeError(
                            "model-call deadline ownership changed during evidence review"
                        )
                self._raise_if_cancelled(job_id)
                adjudication = adjudicate_ai_evidence_review(review)
                claim_sections = {
                    claim.id: section.id
                    for section in current.structured.sections
                    for claim in section.claims
                }
                ai_findings = [
                    QualityFinding(
                        gate="ai_evidence_review",
                        code=item.blocking_reason_codes[0],
                        message=(
                            "The separate-pass advisory AI reviewer flagged this material "
                            "claim against its frozen EvidenceSpans for fail-closed owner review."
                        ),
                        severity=Severity.HARD_BLOCKER,
                        section_id=claim_sections.get(item.claim_id),
                        claim_id=item.claim_id,
                        corrective_action=(
                            "Narrow only the affected claim and submit the new version "
                                "for a fresh advisory evidence review."
                            if item.requires_targeted_narrowing
                            else "Remove the claim or bind qualifying frozen evidence before a fresh review."
                        ),
                    )
                    for item in adjudication.claims
                    if not item.passed
                ]
                report = report.model_copy(
                    update={
                        "ai_evidence_review": review.model_dump(mode="json", by_alias=True),
                        "ai_evidence_adjudication": adjudication.model_dump(
                            mode="json", by_alias=True
                        ),
                        "findings": [*report.findings, *ai_findings],
                        "evidence_passed": report.evidence_passed and adjudication.passed,
                        "release_state": (
                            report.release_state
                            if adjudication.passed
                            else ReleaseState.HELD_FOR_REVIEW
                        ),
                    }
                )
            if self.observability is not None:
                context = self.observability.context_for_job(job_id)
                if context is not None:
                    self.observability.record_duration(
                        context,
                        metric="verification_seconds",
                        duration_seconds=time.perf_counter() - verification_started,
                        operation=TraceOperation.VERIFICATION,
                        stage=TraceStage.VERIFICATION,
                        section_key="direct",
                        status=(
                            TraceStatus.OK
                            if report.release_state == ReleaseState.VERIFIED_FULL
                            else TraceStatus.LIMITED
                        ),
                    )
            self._log_quality_report(
                job_id=job_id,
                report=report,
                original_fingerprint=hashlib.sha256(parent_text.encode("utf-8")).hexdigest(),
                post_fingerprint=hashlib.sha256(rendered.markdown.encode("utf-8")).hexdigest(),
                original_words=word_count(parent_text),
                post_words=rendered.word_count,
                repair_attempt=attempts,
            )
            answer_store_started = time.perf_counter()
            self.database.store_answer_version(
                answer_id=answer_id,
                job_id=job_id,
                version_number=version_number,
                version_kind="structured" if attempts == 0 else "targeted_repair",
                encrypted_content=self.cipher.encrypt_text(rendered.markdown),
                word_count=rendered.word_count,
                policy_version=POLICY_VERSION,
                model_version=current.model_version,
                index_build_id=self.retriever.active_build_id(),
                parent_version_id=parent_id,
                encrypted_diff_from_parent=self.cipher.encrypt_text(
                    unified_diff(parent_text, rendered.markdown)
                ),
            )
            if self.observability is not None:
                context = self.observability.context_for_job(job_id)
                if context is not None:
                    self.observability.record_db_duration(
                        context,
                        operation=DatabaseOperation.STORE_ANSWER_VERSION,
                        stage=TraceStage.VERIFICATION,
                        duration_seconds=time.perf_counter() - answer_store_started,
                    )
            claim_rows = []
            blocker_by_claim: dict[str, list[str]] = {}
            for finding in report.findings:
                if finding.claim_id and finding.severity == Severity.HARD_BLOCKER:
                    blocker_by_claim.setdefault(finding.claim_id, []).append(finding.message)
            for section in current.structured.sections:
                for claim in section.claims:
                    reasons = blocker_by_claim.get(claim.id, [])
                    claim_rows.append(
                        {
                            **claim.model_dump(mode="json"),
                            "encrypted_text": self.cipher.encrypt_text(claim.text),
                            "section_id": section.id,
                            "verification_status": (
                                "not_material"
                                if not claim.material
                                else "failed"
                                if reasons
                                else "verified"
                            ),
                            "verification_reason": " ".join(reasons) or None,
                        }
                    )
            self.database.store_claims(answer_id, claim_rows)
            self.database.store_quality_report(
                report.model_dump(mode="json"),
                POLICY_VERSION,
                encrypted_source_draft=self.cipher.encrypt_text(
                    json.dumps(current.structured.model_dump(mode="json"), sort_keys=True)
                ),
            )

            repairable = [item for item in report.findings if item.severity == Severity.REPAIRABLE]
            hard = [item for item in report.findings if item.severity == Severity.HARD_BLOCKER]
            if report.release_state == ReleaseState.VERIFIED_FULL:
                self._mark_released(answer_id, report.release_state)
                return answer_id, report.release_state
            # A repair may legitimately replace a failed claim and therefore
            # mint a new model claim ID.  Claim IDs are not a semantic change
            # in the failure: using them here lets the model spend another
            # retry on the same gate/code/section defect.  Keep the circuit
            # identity stable across versioned claim lineage and bind it only
            # to deterministic gate facts plus the stable section scope.
            failure_identity_sha256 = _quality_failure_identity_sha256((*hard, *repairable))
            quality_fingerprint = failure_fingerprint(
                stage="quality_verification",
                reason_code="quality_gate_failed",
                scope_id=job_id,
                identity_digests=(failure_identity_sha256,),
            )
            failed_sections = list(
                failed_section_scope(
                    prior=current.structured,
                    findings=(*hard, *repairable),
                )
            )
            retry = decide_retry(
                attempt_number=attempts + 1,
                failure_reason_code=(
                    deterministic_hard_codes[0]
                    if deterministic_hard_codes
                    else "quality_gate_failed"
                ),
                failure_fingerprint_sha256=quality_fingerprint,
                prior_failure_fingerprints=prior_failure_fingerprints,
                deterministic_safety=bool(deterministic_hard_codes),
                retryable=not deterministic_hard_codes,
                # The only retry operation below is a targeted claim/section
                # repair that must create a new version and explicit diff.
                input_or_condition_changed=bool(failed_sections),
            )
            if not retry.should_retry:
                self.events.emit(
                    event_type="quality_gate_failure",
                    component="quality",
                    stage="circuit_breaker",
                    failure_code=retry.reason,
                    source_id=job_id,
                    job_id=job_id,
                    user_or_owner_safe=("Targeted repair stopped under the bounded retry circuit."),
                    retryable=False,
                    blocking=True,
                    context={
                        "failure_fingerprint": quality_fingerprint,
                        "attempt": attempts + 1,
                    },
                )
                return self._release_gate_status(
                    job_id=job_id,
                    request=request,
                    task_type=current.structured.task_type,
                    as_of=current.structured.as_of_date,
                    parent_id=answer_id,
                )
            if (
                report.release_state
                in {ReleaseState.VERIFIED_CONCISE, ReleaseState.VERIFIED_LIMITED}
                and attempts >= 1
            ):
                return self._release_gate_status(
                    job_id=job_id,
                    request=request,
                    task_type=current.structured.task_type,
                    as_of=current.structured.as_of_date,
                    parent_id=answer_id,
                )

            if not failed_sections:
                # A global non-safety limitation (for example an academic score
                # below the still-uncalibrated 70 target) has no safe targeted
                # scope and must never trigger a whole-answer rewrite.
                if not hard and report.release_state in {
                    ReleaseState.VERIFIED_CONCISE,
                    ReleaseState.VERIFIED_LIMITED,
                }:
                    return self._release_gate_status(
                        job_id=job_id,
                        request=request,
                        task_type=current.structured.task_type,
                        as_of=current.structured.as_of_date,
                        parent_id=answer_id,
                    )
                return self._release_gate_status(
                    job_id=job_id,
                    request=request,
                    task_type=current.structured.task_type,
                    as_of=current.structured.as_of_date,
                    parent_id=answer_id,
                )
            prior_failure_fingerprints.append(quality_fingerprint)
            self._event(
                job_id,
                JobStage.REPAIRING,
                0.76,
                "Repairing only the failed claim or section; verified prose is retained",
            )
            try:
                self._raise_if_cancelled(job_id)
                if request.word_target > 3_000:
                    repaired = await self._repair_longform_sections(
                        job_id=job_id,
                        question=question,
                        prior=current,
                        failed_sections=failed_sections,
                        findings=report.findings,
                        evidence_by_id=evidence_by_id,
                        section_evidence_by_id=section_evidence_by_id or {},
                        word_target=request.word_target,
                        upload_context=upload_context,
                        repair_round=attempts + 1,
                    )
                else:
                    repaired, _reused = await self._repair_with_checkpoint(
                        job_id=job_id,
                        repair_round=attempts + 1,
                        section_key="direct",
                        question=question,
                        prior=current.structured,
                        failed_sections=failed_sections,
                        repair_plan_sections=failed_sections,
                        findings=report.findings,
                        evidence=evidence_by_id,
                        word_target=request.word_target,
                        upload_context=upload_context,
                    )
                self._raise_if_cancelled(job_id)
            except JobCancellationRequested:
                raise
            except Exception:
                self.events.emit(
                    event_type="quality_gate_failure",
                    component="quality",
                    stage="repairing",
                    failure_code="repair_failed" if attempts < 2 else "repair_exhausted",
                    source_id=job_id,
                    job_id=job_id,
                    user_or_owner_safe="Targeted repair failed; full answer text was not logged.",
                    context={
                        "original_fingerprint": hashlib.sha256(
                            parent_text.encode("utf-8")
                        ).hexdigest(),
                        "attempt": attempts,
                    },
                    retryable=attempts < 2,
                    blocking=True,
                )
                # Never fall back to filtering/rebuilding the complete draft.
                # That path could drop unaffected sections and add prose
                # without satisfying the exact targeted-repair contract.
                return self._release_gate_status(
                    job_id=job_id,
                    request=request,
                    task_type=current.structured.task_type,
                    as_of=current.structured.as_of_date,
                    parent_id=answer_id,
                )
            parent_id, parent_text = answer_id, rendered.markdown
            current = repaired
            attempts += 1
            version_number += 1

    async def _repair_longform_sections(
        self,
        *,
        question: str,
        prior: ModelDraft,
        failed_sections: Sequence[str],
        findings: Sequence[QualityFinding],
        evidence_by_id: Mapping[str, EvidenceSpan],
        section_evidence_by_id: Mapping[str, Mapping[str, EvidenceSpan]],
        word_target: int,
        upload_context: Sequence[UploadContextSpan],
        job_id: str | None = None,
        repair_round: int = 1,
    ) -> ModelDraft:
        """Repair long answers one frozen section at a time.

        Passing the complete multi-thousand-word draft back through an 8k model
        context is neither bounded nor resumable. Each call receives one section
        and its original frozen evidence pack; unfailed sections are merged back
        byte-for-byte at the structured-data boundary.
        """

        sections = list(prior.structured.sections)
        section_positions = {section.id: index for index, section in enumerate(sections)}
        per_section_target = max(500, min(700, round(word_target / max(1, len(sections)))))
        generated: list[ModelDraft] = []
        for section_id in failed_sections:
            position = section_positions.get(section_id)
            if position is None:
                raise RuntimeError("long-form repair named an unknown section")
            section = sections[position]
            claim_ids = {claim.id for claim in section.claims}
            scoped_findings = [
                item
                for item in findings
                if item.section_id == section_id or item.claim_id in claim_ids
            ]
            pack = dict(section_evidence_by_id.get(section_id) or {})
            if not pack:
                cited = {item for claim in section.claims for item in claim.evidence_ids}
                pack = {key: value for key, value in evidence_by_id.items() if key in cited}
            scoped = prior.structured.model_copy(update={"sections": [section]})
            model_question = f"{question}\n\nRepair only this section: {section.heading}."
            if job_id is None:
                repaired = await self.model.repair(
                    question=model_question,
                    prior=scoped,
                    failed_sections=[section_id],
                    findings=scoped_findings,
                    evidence=pack,
                    word_target=per_section_target,
                    upload_context=upload_context,
                )
                reused = False
            else:
                repaired, reused = await self._repair_with_checkpoint(
                    job_id=job_id,
                    repair_round=repair_round,
                    section_key=section_id,
                    question=model_question,
                    prior=scoped,
                    failed_sections=[section_id],
                    repair_plan_sections=failed_sections,
                    findings=scoped_findings,
                    evidence=pack,
                    word_target=per_section_target,
                    upload_context=upload_context,
                )
            replacement = next(
                (item for item in repaired.structured.sections if item.id == section_id),
                repaired.structured.sections[0] if len(repaired.structured.sections) == 1 else None,
            )
            if replacement is None:
                raise RuntimeError("long-form repair did not return the requested section")
            sections[position] = replacement.model_copy(update={"id": section_id})
            if not reused:
                generated.append(repaired)

        structured = prior.structured.model_copy(update={"sections": sections})
        metrics = dict(prior.metrics or {})
        metrics["bounded_repair_calls"] = int(metrics.get("bounded_repair_calls", 0)) + len(
            generated
        )
        metrics["repair_checkpoint_reuses"] = int(metrics.get("repair_checkpoint_reuses", 0)) + (
            len(failed_sections) - len(generated)
        )
        return ModelDraft(
            raw_text=render_answer(structured, evidence_by_id).markdown,
            structured=structured,
            rubric_scores=prior.rubric_scores,
            model_version=generated[-1].model_version if generated else prior.model_version,
            metrics=metrics,
        )

    async def _release_behavior(
        self,
        job_id: str,
        request: QuestionRequest,
        task_type: TaskType,
        as_of: date,
        decision: BehaviorDecision,
        gap: KnowledgeGap | None = None,
    ) -> None:
        """Store a deterministic pre-model outcome without publishing it."""

        from ..observability.events import policy_decision_code

        self.events.emit(
            event_type="policy_decision",
            component="a2_policy",
            stage="behavior",
            failure_code=policy_decision_code(str(decision.action), str(decision.reason_code)),
            source_id=job_id,
            job_id=job_id,
            user_or_owner_safe=decision.user_message,
            retryable=False,
            blocking=False,
            context={
                "reason_code": str(decision.reason_code),
                "action": str(decision.action),
            },
            open_ledger=False,
        )
        kind = {
            FailureReasonCode.ENTIRELY_UNSAFE: "refusal",
            FailureReasonCode.OUTSIDE_PRODUCT_JURISDICTION: "clarification",
            FailureReasonCode.MISSING_USER_FACTS: "clarification",
            FailureReasonCode.MISSING_DOCUMENT: "clarification",
            FailureReasonCode.ENCRYPTED_OR_UNREADABLE_UPLOAD: "clarification",
            FailureReasonCode.INDEX_NOT_READY: "infrastructure_status",
            FailureReasonCode.RETRIEVER_UNAVAILABLE: "infrastructure_status",
        }.get(decision.reason_code, "evidence_status")
        draft = StructuredDraft(
            title="Verified research status",
            task_type=task_type,
            jurisdiction=request.jurisdiction,
            as_of_date=as_of,
            sections=[
                StructuredSectionDraft(
                    id="supported-status",
                    heading="Supported response",
                    claims=[
                        StructuredClaimDraft(
                            id=str(uuid4()),
                            text=decision.user_message,
                            evidence_ids=[],
                            material=False,
                            kind=kind,
                        )
                    ],
                )
            ],
            limitations=list(decision.limitations),
        )
        rendered = render_answer(draft, {})
        answer_id = str(uuid4())
        self.database.store_answer_version(
            answer_id=answer_id,
            job_id=job_id,
            version_number=self.database.next_answer_version_number(job_id),
            version_kind=f"behavior_{decision.reason_code.value}",
            encrypted_content=self.cipher.encrypt_text(rendered.markdown),
            word_count=rendered.word_count,
            release_state=None,
            policy_version=POLICY_VERSION,
            model_version="not-invoked",
            index_build_id=(
                None
                if decision.reason_code
                in {
                    FailureReasonCode.INDEX_NOT_READY,
                    FailureReasonCode.RETRIEVER_UNAVAILABLE,
                }
                else self.retriever.active_build_id()
            ),
            purge_after_days=None,
        )
        report = self.evaluator.evaluate(
            answer_version_id=answer_id,
            draft=draft,
            rendered_text=rendered.markdown,
            evidence_by_id={},
            word_count=rendered.word_count,
            word_target=request.word_target,
            rubric_scores={},
        ).model_copy(update={"release_state": ReleaseState.HELD_FOR_REVIEW})
        self.database.store_claims(
            answer_id,
            [
                {
                    **draft.sections[0].claims[0].model_dump(mode="json"),
                    "encrypted_text": self.cipher.encrypt_text(draft.sections[0].claims[0].text),
                    "section_id": draft.sections[0].id,
                    "verification_status": "not_material",
                }
            ],
        )
        self.database.store_quality_report(report.model_dump(mode="json"), POLICY_VERSION)
        self.database.release_answer_once(answer_id, str(ReleaseState.HELD_FOR_REVIEW))
        checkpoint = {
            "answer_id": answer_id,
            "failure_reason_code": decision.reason_code.value,
            "invoke_model": False,
        }
        if gap is not None:
            checkpoint["gap_id"] = gap.id
        self.database.update_job(
            job_id,
            status=JobStatus.HELD,
            stage=JobStage.HELD,
            progress=1,
            message=decision.user_message,
            answer_id=answer_id,
            release_state=ReleaseState.HELD_FOR_REVIEW,
            error_code=decision.reason_code.value,
            checkpoint=self._checkpoint(job_id, checkpoint),
        )

    async def _release_no_source(
        self,
        job_id: str,
        request: QuestionRequest,
        task_type: TaskType,
        as_of: date,
        gap: KnowledgeGap,
    ) -> None:
        draft = StructuredDraft(
            title="Verified research status",
            task_type=task_type,
            jurisdiction=request.jurisdiction,
            as_of_date=as_of,
            sections=[
                StructuredSectionDraft(
                    id="supported-status",
                    heading="Supported response",
                    claims=[
                        StructuredClaimDraft(
                            id=str(uuid4()),
                            text=(
                                "I cannot responsibly state the requested legal proposition from the currently approved evidence set"
                            ),
                            evidence_ids=[],
                            material=False,
                            kind="evidence_status",
                        )
                    ],
                )
            ],
            limitations=[
                "A review item was created for qualifying official evidence; no general web commentary was substituted for binding law."
            ],
        )
        rendered = render_answer(draft, {})
        answer_id = str(uuid4())
        self.database.store_answer_version(
            answer_id=answer_id,
            job_id=job_id,
            version_number=self.database.next_answer_version_number(job_id),
            version_kind="verified_supported_portion",
            encrypted_content=self.cipher.encrypt_text(rendered.markdown),
            word_count=rendered.word_count,
            release_state=None,
            policy_version=POLICY_VERSION,
            model_version="not-invoked",
            index_build_id=self.retriever.active_build_id(),
            purge_after_days=None,
        )
        report = self.evaluator.evaluate(
            answer_version_id=answer_id,
            draft=draft,
            rendered_text=rendered.markdown,
            evidence_by_id={},
            word_count=rendered.word_count,
            word_target=request.word_target,
            rubric_scores={},
        ).model_copy(update={"release_state": ReleaseState.HELD_FOR_REVIEW})
        self.database.store_claims(
            answer_id,
            [
                {
                    **draft.sections[0].claims[0].model_dump(mode="json"),
                    "encrypted_text": self.cipher.encrypt_text(draft.sections[0].claims[0].text),
                    "section_id": draft.sections[0].id,
                    "verification_status": "not_material",
                }
            ],
        )
        self.database.store_quality_report(report.model_dump(mode="json"), POLICY_VERSION)
        self.database.release_answer_once(answer_id, str(ReleaseState.HELD_FOR_REVIEW))
        self.database.update_job(
            job_id,
            status=JobStatus.HELD,
            stage=JobStage.HELD,
            progress=1,
            message=(
                "The answer remains held because the approved evidence set is incomplete; "
                "the exact evidence gap was queued for review."
            ),
            answer_id=answer_id,
            release_state=ReleaseState.HELD_FOR_REVIEW,
            checkpoint=self._checkpoint(job_id, {"answer_id": answer_id, "gap_id": gap.id}),
        )

    def _release_gate_status(
        self,
        *,
        job_id: str,
        request: QuestionRequest,
        task_type: TaskType,
        as_of: date,
        parent_id: str,
    ) -> tuple[str, ReleaseState]:
        draft = StructuredDraft(
            title="Completed verification status",
            task_type=task_type,
            jurisdiction=request.jurisdiction,
            as_of_date=as_of,
            sections=[
                StructuredSectionDraft(
                    id="verification-status",
                    heading="Verification outcome",
                    claims=[
                        StructuredClaimDraft(
                            id=str(uuid4()),
                            text=(
                                "The requested answer completed drafting and bounded repair, but no substantive version passed every evidence and privacy release gate"
                            ),
                            evidence_ids=[],
                            material=False,
                            kind="verification_status",
                        )
                    ],
                )
            ],
            limitations=[
                "The encrypted held draft remains available to the owner together with its named quality findings; unsupported legal prose was not exposed as verified advice."
            ],
        )
        rendered = render_answer(draft, {})
        answer_id = str(uuid4())
        self.database.store_answer_version(
            answer_id=answer_id,
            job_id=job_id,
            version_number=self.database.next_answer_version_number(job_id),
            version_kind="terminal_verification_status",
            encrypted_content=self.cipher.encrypt_text(rendered.markdown),
            word_count=rendered.word_count,
            policy_version=POLICY_VERSION,
            model_version="deterministic-gate",
            index_build_id=self.retriever.active_build_id(),
            parent_version_id=parent_id,
            purge_after_days=None,
        )
        report = self.evaluator.evaluate(
            answer_version_id=answer_id,
            draft=draft,
            rendered_text=rendered.markdown,
            evidence_by_id={},
            word_count=rendered.word_count,
            word_target=request.word_target,
            rubric_scores={},
        ).model_copy(update={"release_state": ReleaseState.HELD_FOR_REVIEW})
        self.database.store_claims(
            answer_id,
            [
                {
                    **draft.sections[0].claims[0].model_dump(mode="json"),
                    "encrypted_text": self.cipher.encrypt_text(draft.sections[0].claims[0].text),
                    "section_id": "verification-status",
                    "verification_status": "not_material",
                }
            ],
        )
        self.database.store_quality_report(report.model_dump(mode="json"), POLICY_VERSION)
        self.database.release_answer_once(answer_id, str(ReleaseState.HELD_FOR_REVIEW))
        return answer_id, ReleaseState.HELD_FOR_REVIEW

    def _mark_released(
        self, answer_id: str, release: ReleaseState, *, job_id: str | None = None
    ) -> None:
        answer = self.database.answer(answer_id)
        if answer is None:
            raise KeyError(answer_id)
        release_job_id = job_id or str(answer["job_id"])
        release_job = self.database.job(release_job_id)
        if release_job is None or str(answer["job_id"]) != release_job_id:
            raise RuntimeError("answer release job identity differs")
        self._raise_if_cancelled(release_job_id)
        from ..evaluation.evaluation_job_authority import (
            verified_evaluation_release_authority_sha256,
        )

        evaluation_values = (
            release_job["evaluation_run_id"],
            release_job["evaluation_case_id"],
            release_job["evaluation_request_sha256"],
            release_job["evaluation_authority_json"],
            release_job["evaluation_authority_sha256"],
        )
        evaluation_bound = any(value not in (None, "") for value in evaluation_values)
        if evaluation_bound and not all(value not in (None, "") for value in evaluation_values):
            raise RuntimeError("evaluation_job_authority_incomplete")
        evaluation_authority_sha256 = (
            str(release_job["evaluation_authority_sha256"]) if evaluation_bound else None
        )
        normal_live_authority = None
        evaluation_verifier = None
        if evaluation_authority_sha256 is not None:

            def replay_evaluation_authority() -> object:
                current_job = self.database.job(release_job_id)
                current_answer = self.database.answer(answer_id)
                if current_job is None or current_answer is None:
                    raise RuntimeError("evaluation release records disappeared")
                try:
                    durable_authority = json.loads(
                        str(current_job["evaluation_authority_json"] or "")
                    )
                except json.JSONDecodeError as exc:
                    raise RuntimeError("evaluation release authority is invalid") from exc
                owner_phase: Literal["pre_release", "released"] | None = None
                if (
                    isinstance(durable_authority, dict)
                    and durable_authority.get("lane") == "owner_quality_canary"
                ):
                    released_rows = self.database.fetchall(
                        "SELECT id FROM release_outbox WHERE job_id=? ORDER BY id",
                        (release_job_id,),
                    )
                    owner_phase = (
                        "released"
                        if str(current_job["answer_id"] or "") == answer_id
                        and str(current_answer["release_state"] or "") == "verified_full"
                        and len(released_rows) == 1
                        else "pre_release"
                    )
                replayed = self._require_normal_live_for_ordinary_job(
                    current_job,
                    answer_id=answer_id,
                    owner_canary_publication_phase=owner_phase,
                )
                if (
                    verified_evaluation_release_authority_sha256(replayed)
                    != evaluation_authority_sha256
                ):
                    raise RuntimeError("evaluation release authority lane changed")
                return replayed

            evaluation_verifier = replay_evaluation_authority
        else:
            release_authority = self._require_normal_live_for_ordinary_job(release_job)
            normal_live_authority = (
                release_authority if isinstance(release_authority, dict) else None
            )
        normal_live_verifier = None
        if normal_live_authority is not None:
            from ..evaluation.owner_quality_normal_live_readiness import (
                owner_quality_normal_live_release_authority,
            )

            def replay_normal_live_authority() -> dict[str, Any]:
                return owner_quality_normal_live_release_authority(
                    self.settings.project_root,
                    database=self.database,
                    settings=self.settings,
                )

            normal_live_verifier = replay_normal_live_authority
        started = time.perf_counter()
        self.database.release_answer_once(
            answer_id,
            str(release),
            expected_evaluation_authority_sha256=evaluation_authority_sha256,
            evaluation_authority_verifier=evaluation_verifier,
            normal_live_authority=normal_live_authority,
            normal_live_authority_verifier=normal_live_verifier,
        )
        # Conversation projection is deliberately downstream of the atomic
        # release.  Evaluation jobs have no ordinary conversation binding;
        # ordinary owner-only jobs are projected idempotently if configured.
        if self.conversations is not None:
            try:
                self.conversations.append_released_answer(release_job_id)
            except Exception as exc:
                failure_fingerprint_sha256 = hashlib.sha256(
                    f"conversation-projection-v1\0{type(exc).__name__}\0{exc}".encode()
                ).hexdigest()
                with suppress(Exception):
                    self.database.execute(
                        """
                        INSERT INTO job_events(
                          job_id,stage,progress,message,payload_json,created_at
                        ) VALUES (?, 'complete', 1, ?, ?, ?)
                        """,
                        (
                            release_job_id,
                            "The verified answer was released, but conversation-history projection requires repair.",
                            json.dumps(
                                {
                                    "failure_code": "conversation_projection_failed",
                                    "failure_fingerprint_sha256": failure_fingerprint_sha256,
                                    "answer_release_rolled_back": False,
                                },
                                sort_keys=True,
                            ),
                            datetime.now(ZoneInfo("UTC")).isoformat(),
                        ),
                    )
        duration = time.perf_counter() - started
        if self.observability is None:
            return
        context = self.observability.context_for_job(release_job_id)
        if context is None:
            return
        self.observability.record_db_duration(
            context,
            operation=DatabaseOperation.RELEASE_OUTBOX,
            stage=TraceStage.RELEASE,
            duration_seconds=duration,
        )
        self.observability.record_duration(
            context,
            metric="release_seconds",
            duration_seconds=duration,
            operation=TraceOperation.RELEASE,
            stage=TraceStage.RELEASE,
            status=(
                TraceStatus.HELD
                if release == ReleaseState.HELD_FOR_REVIEW
                else TraceStatus.LIMITED
                if release == ReleaseState.VERIFIED_LIMITED
                else TraceStatus.OK
            ),
        )

    def _event(self, job_id: str, stage: JobStage, progress: float, message: str) -> None:
        started = time.perf_counter()
        row = self.database.job(job_id)
        previous_stage = str(row["stage"]) if row is not None else ""
        transitioned = self.database.update_job(
            job_id,
            status=JobStatus.RUNNING,
            stage=stage,
            progress=progress,
            message=message,
            checkpoint=self._checkpoint(job_id, {"stage": stage, "progress": progress}),
        )
        if not transitioned:
            current = self.database.job(job_id)
            if current is not None and (
                bool(current["cancel_requested"]) or str(current["status"]) == JobStatus.CANCELLED
            ):
                raise JobCancellationRequested(job_id)
            raise RuntimeError("answer_job_progress_transition_fenced")
        if previous_stage != str(stage):
            from ..jobs import policy_for
            from ..retrieval.budget import (
                parse_job_deadline,
                tighten_retrieval_deadline,
            )

            job_type = str(row["job_type"]) if row is not None else "answer"
            deadline = self.database.arm_stage_deadline(
                job_id, seconds=policy_for(job_type).stage_seconds
            )
            parsed = parse_job_deadline(deadline)
            if parsed is not None:
                tighten_retrieval_deadline(parsed)
        if self.observability is not None:
            context = self.observability.context_for_job(job_id)
            if context is not None:
                self.observability.record_progress(
                    context,
                    stage=str(stage),
                    db_duration_seconds=time.perf_counter() - started,
                )

    def _stop_if_cancelled(self, job_id: str) -> bool:
        row = self.database.job(job_id)
        if row is None or not bool(row["cancel_requested"]):
            return False
        self.database.update_job(
            job_id,
            status=JobStatus.CANCELLED,
            stage=JobStage.CANCELLED,
            progress=1,
            message="The job stopped safely after its last encrypted checkpoint.",
            checkpoint=self._checkpoint(job_id, {"cancelled": True}),
        )
        return True

    def _raise_if_cancelled(self, job_id: str) -> None:
        if self._stop_if_cancelled(job_id):
            raise JobCancellationRequested(job_id)

    def _checkpoint(self, job_id: str, values: Mapping[str, object]) -> dict[str, object]:
        checkpoint = dict(values)
        metadata = self._issue_plan_metadata.get(job_id)
        if metadata is not None:
            checkpoint["issue_plan"] = metadata
        return checkpoint

    def _persist_upload_review_gap(
        self,
        *,
        job_id: str,
        jurisdiction: str,
        subject: str | None,
        preparation: UploadPreparation,
    ) -> None:
        gap = KnowledgeGap(
            id=str(uuid4()),
            job_id=job_id,
            missing_proposition="Qualification of attached material for answer use",
            jurisdiction=jurisdiction,
            subject=subject,
            searches_attempted=[],
            rejection_reasons=list(preparation.review_reasons),
        )
        path = self.gaps.persist(gap)
        self._store_gap(gap, path)

    def _store_gap(self, gap: KnowledgeGap, path: Path) -> None:
        proposition = gap.missing_proposition
        proposition_sha256 = hashlib.sha256(proposition.encode("utf-8")).hexdigest()
        existing_gap = self.database.fetchone(
            "SELECT job_id,proposition_sha256 FROM knowledge_gaps WHERE id=?",
            (gap.id,),
        )
        if existing_gap is None:
            self.database.store_gap(
                gap.model_dump(mode="json"),
                str(path.relative_to(self.settings.project_root)),
                encrypted_missing_proposition=self.cipher.encrypt_text(proposition),
                proposition_sha256=proposition_sha256,
            )
        elif (
            str(existing_gap["job_id"]) != gap.job_id
            or str(existing_gap["proposition_sha256"]) != proposition_sha256
        ):
            raise RuntimeError("knowledge gap identity conflict")
        # Mirror every actual answer-time gap into the unified owner inbox.
        # Only opaque IDs and the proposition digest are projected; the
        # proposition, searches and rejection prose remain in encrypted gap
        # storage. Replaying the same gap is strictly idempotent.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", gap.id) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", gap.job_id
        ):
            raise ValueError("knowledge gap contains an unsafe owner-inbox reference")
        fingerprint = f"knowledge-gap:{gap.id}"
        existing = self.database.fetchone(
            "SELECT id,category,job_id,knowledge_gap_id FROM refinements WHERE fingerprint=?",
            (fingerprint,),
        )
        if existing is None:
            digest = hashlib.sha256(f"legalbot-gap-refinement-v1\0{gap.id}".encode()).hexdigest()
            self.database.create_refinement(
                refinement_id=f"refinement-gap-{digest[:40]}",
                fingerprint=fingerprint,
                category="missing",
                scope="source",
                priority=90,
                origin="answer_runner",
                job_id=gap.job_id,
                knowledge_gap_id=gap.id,
                safe_target={
                    "job_id": gap.job_id,
                    "knowledge_gap_id": gap.id,
                    "proposition_sha256": proposition_sha256,
                },
            )
        elif any(
            (
                str(existing["category"]) != "missing",
                str(existing["job_id"]) != gap.job_id,
                str(existing["knowledge_gap_id"]) != gap.id,
            )
        ):
            raise RuntimeError("knowledge gap refinement identity conflict")

    def _screen_issue_notes(
        self, notes: Sequence[IssueSpottingNote]
    ) -> tuple[list[IssueSpottingNote], list[IssueSpottingNote]]:
        safe: list[IssueSpottingNote] = []
        unsafe: list[IssueSpottingNote] = []
        for note in notes:
            if prompt_injection_hits(note.text):
                unsafe.append(note)
                self.database.queue_document_safety_review(note.source_version_id)
            else:
                safe.append(note)
        return safe, unsafe

    @staticmethod
    def _dedupe_legal_evidence(
        batches: Sequence[Sequence[EvidenceSpan]],
    ) -> list[EvidenceSpan]:
        output: list[EvidenceSpan] = []
        seen: set[tuple[str, str]] = set()
        for batch in batches:
            for span in batch:
                if not is_citable_authority_lane(span):
                    continue
                key = (span.source_version_id, span.chunk_id)
                if key in seen:
                    continue
                seen.add(key)
                output.append(span)
                if len(output) >= MAX_MERGED_EVIDENCE:
                    return output
        return output

    def _record_teaching_verify_cite(
        self,
        job_id: str,
        issue_plan: IssuePlan,
        authority_evidence: Sequence[EvidenceSpan],
    ) -> None:
        """Persist authority verification outcomes for teaching-spotted issues.

        Teaching is used only for internal issue spotting. Persisted items keep
        verify statuses in metadata; notes_view is knowledge-card style
        (what/authority) from taxonomy + authority excerpts when available.
        OSCOLA and evidence IDs come exclusively from authority lanes.
        """

        flow = run_teaching_verify_cite_flow(
            issue_plan=issue_plan,
            authority_evidence=authority_evidence,
        )
        metadata = self._issue_plan_metadata.setdefault(job_id, issue_plan.safe_metadata())
        payload = flow.safe_metadata()
        payload["notes_view"] = render_teaching_notes_view(flow)
        metadata["teaching_verify_cite"] = payload
        status_counts = flow.safe_metadata().get("status_counts") or {}
        if status_counts:
            self._event(
                job_id,
                JobStage.QUALIFYING,
                0.40,
                (
                    "Teaching issue-spotting verified against authority lanes: "
                    + ", ".join(f"{key}={value}" for key, value in sorted(status_counts.items()))
                ),
            )

    def _log_quality_report(
        self,
        *,
        job_id: str,
        report: QualityReport,
        original_fingerprint: str,
        post_fingerprint: str,
        original_words: int,
        post_words: int,
        repair_attempt: int,
    ) -> None:
        from ..observability.events import quality_failure_code

        if report.release_state == ReleaseState.HELD_FOR_REVIEW:
            self.events.emit(
                event_type="quality_gate_failure",
                component="quality",
                stage="release",
                failure_code="release_refused",
                source_id=job_id,
                job_id=job_id,
                user_or_owner_safe="Release was refused by the quality gates.",
                retryable=True,
                blocking=True,
            )
        for finding in report.findings:
            if finding.severity == Severity.INFORMATIONAL:
                continue
            self.events.emit(
                event_type="quality_gate_failure",
                component="quality",
                stage=finding.gate,
                failure_code=quality_failure_code(finding.code),
                source_id=finding.claim_id or job_id,
                job_id=job_id,
                user_or_owner_safe=finding.message,
                retryable=finding.severity != Severity.HARD_BLOCKER,
                blocking=finding.severity == Severity.HARD_BLOCKER,
                context={
                    "original_fingerprint": original_fingerprint,
                    "post_repair_fingerprint": post_fingerprint,
                    "original_word_count": original_words,
                    "post_repair_word_count": post_words,
                    "repair_attempt": repair_attempt,
                    "finding_code": finding.code,
                },
            )

    @staticmethod
    def _release_message(release: ReleaseState) -> str:
        messages = {
            ReleaseState.VERIFIED_FULL: (
                "Evidence, citation, jurisdiction and privacy gates passed; "
                "academic guidance checks are advisory pending blind calibration."
            ),
            ReleaseState.VERIFIED_CONCISE: "Evidence passed; the verified answer is shorter than requested.",
            ReleaseState.VERIFIED_LIMITED: "The supported answer was released with precise limitations.",
            ReleaseState.HELD_FOR_REVIEW: "A substantive evidence or privacy defect remains; the answer is held with named corrective actions.",
            ReleaseState.SYSTEM_ERROR: "The local operation stopped and can be resumed from its checkpoint.",
        }
        return messages[release]
