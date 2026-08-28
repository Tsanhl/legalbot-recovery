"""Production owner-quality canary admission and owned-runtime execution.

The authoritative runner has no injectable case callback.  It owns the exact
model sidecar and executes production admission, ``AnswerRunner`` and durable
projection in the same verified controller process.  The legacy HTTP adapter
is retained only for explicitly synthetic tests and cannot mint a v1.11 final
package usable by promotion or readiness.

Development is candidate-pinned and deliberately independent of ``ACTIVE``.
Blind holdout is refused until the exact ACTIVE/operations/O-04 graph and a
trusted owner-signature verifier exist.
"""

from __future__ import annotations

import asyncio
import difflib
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, Self, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..assessment.guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    budget_assessment_guidance,
)
from ..assessment.standards_scoring import (
    AssessmentStandardsReport,
    score_applicable_standards,
)
from ..citations.oscola import render_answer, render_oscola
from ..config import Settings
from ..crypto import LocalCipher
from ..db import Database, require_release_outbox_schema_contract
from ..model_runtime.config import PINNED_RUNTIME_MODEL_VERSION, PINNED_RUNTIME_REPO
from ..observability.live_metrics import load_slo_policy
from ..orchestration.classifier import CLASSIFIER_VERSION, classify_task
from ..orchestration.direct_controller import run_bounded_direct_answer
from ..orchestration.retry_policy import (
    decide_retry,
    failure_fingerprint,
    is_deterministic_safety_failure,
)
from ..orchestration.routing import ROUTER_VERSION, build_section_tasks, decide_route
from ..orchestration.runner import (
    REPAIR_CHECKPOINT_PROMPT_VERSION,
    AnswerRunner,
    _quality_failure_identity_sha256,
    draft_checkpoint_input_sha256,
    evidence_pack_sha256,
    repair_checkpoint_input_sha256s,
)
from ..orchestration.targeted_repair import (
    failed_section_scope,
    verify_targeted_structured_repair,
)
from ..privacy import contains_absolute_private_path, prompt_injection_hits
from ..quality.ai_evidence_reviewer import (
    AIEvidenceAdjudication,
    adjudicate_ai_evidence_review,
    ai_evidence_reviewer_prompt_sha256,
    ai_evidence_reviewer_toolchain_sha256,
    freeze_material_claims,
    frozen_claim_bundle_sha256,
    load_persisted_ai_evidence_review,
)
from ..quality.draft_identity import source_draft_sha256
from ..quality.evaluator import QualityEvaluator
from ..quality.policy import HARD_BLOCKER_CODES, POLICY_SHA256, POLICY_VERSION
from ..retrieval.pinned_factory import PinnedRetrieverFactory
from ..runtime_adapters import PROMPT_VERSION, LoopbackModelGateway
from ..types import (
    CasePropositionReview,
    EvidenceSpan,
    IssuePlan,
    JobType,
    MaterialLane,
    OnlineMode,
    QualityFinding,
    QuestionRequest,
    Severity,
    StructuredDraft,
    TaskType,
)
from .all60_ai_review_batch import (
    VerifiedAll60AIReviewBatch,
    load_verified_all60_ai_review_batch,
    require_verified_all60_ai_review_batch,
)
from .all60_evidence_review import verify_runtime_candidate_evidence_spans
from .all60_qualification import (
    ALL60_REPLAY_BATCH_ROOT_NAME,
    ALL60_REPLAY_EXPERT_FILENAME,
    EXACT_ALL60_FILENAME,
    ExactAll60Qualification,
    load_replayed_exact_all60_qualification,
)
from .canary_review_workspace import (
    CanaryReviewWorkspace,
    CanaryReviewWorkspaceManifest,
    create_canary_review_workspace,
)
from .live_suite import LiveEvaluationBundle, load_live_evaluation_bundle, sealed_sha256
from .live_suite_gold import LiveSuiteExpertQualification, load_suite_expert_qualification
from .owner_quality_canary import (
    OwnerQualityCanaryManifest,
    load_verified_owner_quality_canary_manifest,
    owner_quality_manifest_bytes,
)
from .owner_quality_canary_artifacts import (
    DETERMINISTIC_RELEASE_GATES,
    seal_owner_canary_deterministic_gate_report,
    seal_owner_canary_evidence_bundle,
    seal_owner_canary_release_attestation,
)
from .owner_quality_canary_authorization import (
    OwnerCanaryAuthorization,
    OwnerDecisionRequired,
    OwnerQualityDevelopmentAuthorization,
    OwnerQualityHoldoutAuthorization,
    load_owner_canary_authorization,
    replay_authorization_completion_preflight,
    replay_authorization_stage_a,
    verify_authorization_manifest,
)
from .owner_quality_canary_circuit import (
    OwnerCanaryAttemptRequest,
    OwnerCanaryCaseAttemptResult,
    _request,
    seal_owner_canary_case_result,
)
from .owner_quality_canary_projection import (
    OwnerCanaryGapDisposition,
    OwnerCanaryReviewExecution,
    execute_owner_quality_canary_review,
)
from .owner_quality_owned_model_runtime import (
    OwnerCanaryOwnedModelRuntime,
    OwnerCanaryOwnedRuntimeCheckpoint,
    VerifiedActiveOwnerCanaryRuntime,
    VerifiedEndedOwnerCanaryRuntime,
    load_active_owner_canary_runtime,
    load_ended_owner_canary_runtime,
    load_owner_canary_runtime_binding_and_memory_policy,
    require_owner_canary_exclusive_model_transport_resolution,
    require_verified_active_owner_canary_runtime,
    require_verified_ended_owner_canary_runtime,
)
from .sealed_candidate import SealedCandidateIdentity, load_sealed_candidate_identity

OWNER_CANARY_RUNTIME_AUTH_FILENAME = "execution-authorization.json"
OWNER_CANARY_STAGE_A_DIRNAME = "stage-a-v2"
OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME = "completion-preflight"
OWNER_CANARY_RUNTIME_REPORT_SCHEMA = "legalbot.owner-canary-runtime-release-report.v2"
OWNER_CANARY_RUNTIME_ENVELOPE_SCHEMA = "legalbot.owner-canary-runtime-attempt-envelope.v2"
OWNER_CANARY_CONTENT_GRAPH_SCHEMA = "legalbot.owner-canary-content-graph.v1"

_SAFE_RUN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_RELEASES = frozenset({"verified_full"})
_TERMINAL_JOB_STATES = frozenset(
    {"complete", "held_for_review", "system_error", "cancelled", "failed", "dlq"}
)
_QUOTE_FAILURE_CODES = frozenset(
    {"false_quotation", "invented_authority", "wrong_authority_identity"}
)
_VERIFIED_OWNER_CANARY_CONTENT_GRAPH_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class VerifiedOwnerCanaryContentGraph:
    """Opaque proof of one stable, semantically verified canary DB graph.

    Only digests and safe row counts cross the verifier boundary.  In
    particular, encrypted questions, answers, source drafts, claims, gaps and
    stage outputs can never be recovered from this capability or its repr.
    """

    graph_sha256: str
    answer_sha256: str
    job_id: str
    answer_id: str
    row_count: int
    release_state: str
    word_count: int
    material_claim_count: int
    evidence_span_count: int
    all_material_claims_evidence_bound: bool
    standards_avoidance_passed: bool
    ai_review_invocation_ids_sha256: str
    ai_review_invocation_count: int
    model_stage_attempt_ids_sha256: str
    model_stage_attempt_count: int
    runtime_object_relative_paths_sha256: str
    runtime_object_count: int
    _runtime_object_relative_paths: tuple[str, ...]
    _candidate_catalogue_status: str
    _token: object

    def __init__(
        self,
        *,
        graph_sha256: str,
        answer_sha256: str,
        job_id: str,
        answer_id: str,
        row_count: int,
        release_state: str,
        word_count: int,
        material_claim_count: int,
        evidence_span_count: int,
        all_material_claims_evidence_bound: bool,
        standards_avoidance_passed: bool,
        ai_review_invocation_ids_sha256: str,
        ai_review_invocation_count: int,
        model_stage_attempt_ids_sha256: str,
        model_stage_attempt_count: int,
        runtime_object_relative_paths_sha256: str,
        runtime_object_count: int,
        _runtime_object_relative_paths: tuple[str, ...],
        _candidate_catalogue_status: str,
        _token: object,
    ) -> None:
        if (
            _token is not _VERIFIED_OWNER_CANARY_CONTENT_GRAPH_TOKEN
            or not _SHA256.fullmatch(graph_sha256)
            or not _SHA256.fullmatch(answer_sha256)
            or not job_id
            or not answer_id
            or row_count < 1
            or release_state != "verified_full"
            or word_count < 1
            or material_claim_count < 1
            or evidence_span_count < 1
            or all_material_claims_evidence_bound is not True
            or standards_avoidance_passed is not True
            or not _SHA256.fullmatch(ai_review_invocation_ids_sha256)
            or ai_review_invocation_count < material_claim_count
            or not _SHA256.fullmatch(model_stage_attempt_ids_sha256)
            or model_stage_attempt_count < 1
            or not _SHA256.fullmatch(runtime_object_relative_paths_sha256)
            or runtime_object_count < 2
            or len(_runtime_object_relative_paths) != runtime_object_count
            or tuple(sorted(_runtime_object_relative_paths)) != _runtime_object_relative_paths
            or len(set(_runtime_object_relative_paths)) != runtime_object_count
            or _candidate_catalogue_status not in {"candidate", "active"}
        ):
            raise ValueError("verified owner-canary content graph is invalid")
        object.__setattr__(self, "graph_sha256", graph_sha256)
        object.__setattr__(self, "answer_sha256", answer_sha256)
        object.__setattr__(self, "job_id", job_id)
        object.__setattr__(self, "answer_id", answer_id)
        object.__setattr__(self, "row_count", row_count)
        object.__setattr__(self, "release_state", release_state)
        object.__setattr__(self, "word_count", word_count)
        object.__setattr__(self, "material_claim_count", material_claim_count)
        object.__setattr__(self, "evidence_span_count", evidence_span_count)
        object.__setattr__(
            self,
            "all_material_claims_evidence_bound",
            all_material_claims_evidence_bound,
        )
        object.__setattr__(self, "standards_avoidance_passed", standards_avoidance_passed)
        object.__setattr__(self, "ai_review_invocation_ids_sha256", ai_review_invocation_ids_sha256)
        object.__setattr__(self, "ai_review_invocation_count", ai_review_invocation_count)
        object.__setattr__(self, "model_stage_attempt_ids_sha256", model_stage_attempt_ids_sha256)
        object.__setattr__(self, "model_stage_attempt_count", model_stage_attempt_count)
        object.__setattr__(
            self,
            "runtime_object_relative_paths_sha256",
            runtime_object_relative_paths_sha256,
        )
        object.__setattr__(self, "runtime_object_count", runtime_object_count)
        object.__setattr__(self, "_runtime_object_relative_paths", _runtime_object_relative_paths)
        object.__setattr__(self, "_candidate_catalogue_status", _candidate_catalogue_status)
        object.__setattr__(self, "_token", _token)

    def __repr__(self) -> str:
        return "<VerifiedOwnerCanaryContentGraph>"


@dataclass(frozen=True, slots=True)
class _OwnerCanaryContentGraphSnapshot:
    graph_sha256: str
    job_id: str
    answer_id: str
    row_count: int


def _content_graph_value(value: Any) -> dict[str, Any]:
    """Frame SQLite values without type/NULL ambiguity or BLOB disclosure."""

    if value is None:
        return {"type": "null"}
    if isinstance(value, bytes):
        return {
            "type": "blob",
            "byte_length": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if isinstance(value, str):
        return {"type": "text", "value": value}
    if isinstance(value, int):
        return {"type": "integer", "value": str(value)}
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RuntimeError("owner_canary_content_graph_nonfinite_float")
        return {"type": "float64", "value": value.hex()}
    raise TypeError("owner-canary content graph contains an unsupported SQLite value")


def _content_graph_rows(
    connection: sqlite3.Connection,
    *,
    table: str,
    columns: Sequence[str],
    sql: str,
    params: Sequence[Any],
) -> tuple[dict[str, Any], ...]:
    rows = connection.execute(sql, tuple(params)).fetchall()
    return tuple(
        {
            "table": table,
            "columns": list(columns),
            "values": [_content_graph_value(row[column]) for column in columns],
        }
        for row in rows
    )


def capture_owner_canary_content_graph(
    connection: sqlite3.Connection,
    *,
    job_id: str,
    answer_id: str,
    candidate_build_id: str,
    case_id: str,
    as_of_date: date,
) -> _OwnerCanaryContentGraphSnapshot:
    """Hash the exact bounded DB closure used by one canary release.

    Publication-mutated fields are intentionally absent.  The release
    transaction recomputes this same graph before its first write and stores
    the digest beside the independently verified plaintext answer digest.
    """

    job_columns = (
        "id",
        "encrypted_question",
        "question_summary",
        "request_json",
        "error_code",
        "route",
        "route_reasons_json",
        "attempt_count",
        "idempotency_key",
        "cancel_requested",
        "pinned_index_build_id",
        "job_type",
        "terminal_reason_code",
        "dlq",
        "evaluation_run_id",
        "evaluation_case_id",
        "evaluation_request_sha256",
        "evaluation_authority_json",
        "evaluation_authority_sha256",
        "normal_live_authority_sha256",
        "worker_prompt_version",
        "worker_router_version",
        "worker_classifier_version",
        "worker_policy_sha256",
        "assessment_bundle_sha256",
        "issue_plan_proposition_keys_json",
        "trace_id",
        "trace_root_span_id",
        "word_target",
        "created_at",
    )
    answer_columns = (
        "id",
        "job_id",
        "version_number",
        "version_kind",
        "encrypted_content",
        "word_count",
        "parent_version_id",
        "diff_from_parent",
        "encrypted_diff_from_parent",
        "policy_version",
        "model_version",
        "index_build_id",
        "created_at",
        "policy_sha256",
    )
    quality_columns = (
        "id",
        "answer_version_id",
        "evidence_passed",
        "academic_score",
        "rubric_scores_json",
        "findings_json",
        "release_state",
        "policy_version",
        "created_at",
        "policy_sha256",
        "ai_evidence_review_json",
        "ai_evidence_adjudication_json",
        "assessment_standards_json",
        "encrypted_source_draft",
    )
    claim_columns = (
        "id",
        "answer_version_id",
        "model_claim_id",
        "section_id",
        "ordinal",
        "claim_text",
        "encrypted_claim_text",
        "material",
        "proposition_hash",
        "verification_status",
        "verification_reason",
    )
    evidence_columns = (
        "id",
        "source_version_id",
        "chunk_id",
        "span_text",
        "locator",
        "lane",
        "jurisdiction",
        "subject",
        "citation_data_json",
        "canonical_citation",
        "currentness_status",
        "content_sha256",
        "index_build_id",
        "canonical_url",
        "entailment_score",
        "retrieval_relevance_score",
        "retrieval_route",
        "retrieval_threshold",
        "retrieval_threshold_policy_sha256",
        "retrieval_threshold_qualified",
        "retrieval_qualification_reason",
        "legal_role",
        "unapplied_effect_count",
        "provision_extent_status",
        "identity_verified",
        "currentness_verified",
        "case_currentness_reviews_json",
        "case_currentness_manifest_seals_json",
        "created_at",
    )
    graph_rows: list[dict[str, Any]] = []

    def add(
        table: str,
        columns: Sequence[str],
        sql: str,
        params: Sequence[Any] = (),
    ) -> None:
        graph_rows.extend(
            _content_graph_rows(
                connection,
                table=table,
                columns=columns,
                sql=sql,
                params=params,
            )
        )

    add(
        "jobs",
        job_columns,
        f"SELECT {','.join(job_columns)} FROM jobs WHERE id=? ORDER BY id",
        (job_id,),
    )
    add(
        "answer_versions",
        answer_columns,
        f"SELECT {','.join(answer_columns)} FROM answer_versions "
        "WHERE job_id=? ORDER BY version_number,id",
        (job_id,),
    )
    add(
        "quality_reports",
        quality_columns,
        f"SELECT qr.{',qr.'.join(quality_columns)} FROM quality_reports qr "
        "JOIN answer_versions av ON av.id=qr.answer_version_id "
        "WHERE av.job_id=? ORDER BY av.version_number,qr.created_at,qr.id",
        (job_id,),
    )
    add(
        "claims",
        claim_columns,
        f"SELECT c.{',c.'.join(claim_columns)} FROM claims c "
        "JOIN answer_versions av ON av.id=c.answer_version_id "
        "WHERE av.job_id=? ORDER BY av.version_number,c.ordinal,c.id",
        (job_id,),
    )
    link_columns = ("claim_id", "evidence_id", "ordinal")
    add(
        "claim_evidence",
        link_columns,
        "SELECT ce.claim_id,ce.evidence_id,ce.ordinal FROM claim_evidence ce "
        "JOIN claims c ON c.id=ce.claim_id "
        "JOIN answer_versions av ON av.id=c.answer_version_id "
        "WHERE av.job_id=? ORDER BY av.version_number,c.ordinal,ce.ordinal,ce.evidence_id",
        (job_id,),
    )
    add(
        "evidence_spans",
        evidence_columns,
        f"SELECT DISTINCT es.{',es.'.join(evidence_columns)} FROM evidence_spans es "
        "JOIN claim_evidence ce ON ce.evidence_id=es.id "
        "JOIN claims c ON c.id=ce.claim_id "
        "JOIN answer_versions av ON av.id=c.answer_version_id "
        "WHERE av.job_id=? ORDER BY es.id",
        (job_id,),
    )
    source_columns = (
        "id",
        "document_id",
        "authority_identity_id",
        "version_sha256",
        "as_of_date",
        "stable_identifier",
        "currentness_status",
        "review_status",
        "processing_fingerprint",
        "superseded_by",
        "metadata_json",
        "created_at",
    )
    add(
        "source_versions",
        source_columns,
        f"SELECT DISTINCT sv.{',sv.'.join(source_columns)} FROM source_versions sv "
        "JOIN evidence_spans es ON es.source_version_id=sv.id "
        "JOIN claim_evidence ce ON ce.evidence_id=es.id "
        "JOIN claims c ON c.id=ce.claim_id "
        "JOIN answer_versions av ON av.id=c.answer_version_id "
        "WHERE av.job_id=? ORDER BY sv.id",
        (job_id,),
    )
    stage_columns = (
        "id",
        "job_id",
        "stage_key",
        "section_key",
        "attempt_number",
        "status",
        "input_digest",
        "evidence_pack_digest",
        "encrypted_output",
        "output_object_key",
        "metrics_json",
        "error_code",
        "started_at",
        "finished_at",
    )
    add(
        "job_stage_attempts",
        stage_columns,
        f"SELECT {','.join(stage_columns)} FROM job_stage_attempts "
        "WHERE job_id=? ORDER BY stage_key,section_key,attempt_number,id",
        (job_id,),
    )
    evidence_pack_columns = (
        "id",
        "job_id",
        "section_key",
        "digest",
        "index_build_id",
        "source_ids_json",
        "encrypted_payload",
        "object_key",
        "created_at",
    )
    add(
        "evidence_packs",
        evidence_pack_columns,
        f"SELECT {','.join(evidence_pack_columns)} FROM evidence_packs "
        "WHERE job_id=? ORDER BY section_key,id",
        (job_id,),
    )
    runtime_columns = (
        "object_key",
        "namespace",
        "content_sha256",
        "relative_path",
        "byte_size",
        "metadata_json",
        "expires_at",
        "created_at",
    )
    add(
        "runtime_objects",
        runtime_columns,
        f"SELECT ro.{',ro.'.join(runtime_columns)} FROM runtime_objects ro "
        "WHERE ro.object_key IN ("
        "SELECT output_object_key FROM job_stage_attempts "
        "WHERE job_id=? AND output_object_key IS NOT NULL "
        "UNION SELECT object_key FROM evidence_packs "
        "WHERE job_id=? AND object_key IS NOT NULL) ORDER BY ro.object_key",
        (job_id, job_id),
    )
    retry_columns = (
        "sequence",
        "lane",
        "work_id",
        "attempt_number",
        "stage_code",
        "failure_reason_code",
        "failure_fingerprint_sha256",
        "input_identity_sha256",
        "condition_identity_sha256",
        "decision_action",
        "decision_reason",
        "retries_remaining",
        "retry_operation",
        "condition_changed",
        "created_at",
    )
    add(
        "retry_decisions",
        retry_columns,
        f"SELECT {','.join(retry_columns)} FROM retry_decisions "
        "WHERE work_id=? ORDER BY lane,attempt_number,sequence",
        (job_id,),
    )
    gap_columns = (
        "id",
        "job_id",
        "missing_proposition",
        "encrypted_missing_proposition",
        "proposition_sha256",
        "jurisdiction",
        "subject",
        "searches_json",
        "rejection_reasons_json",
        "review_file",
        "status",
        "created_at",
        "resolved_at",
    )
    add(
        "knowledge_gaps",
        gap_columns,
        f"SELECT {','.join(gap_columns)} FROM knowledge_gaps WHERE job_id=? ORDER BY id",
        (job_id,),
    )
    research_gap_columns = (
        "id",
        "fingerprint_sha256",
        "candidate_build_id",
        "source_manifest_sha256",
        "case_id",
        "issue_id",
        "subject",
        "jurisdiction",
        "as_of_date",
        "attempted_retrieval_sha256",
        "materiality",
        "detail_sha256",
        "encrypted_detail",
        "status",
        "created_at",
        "updated_at",
        "resolved_at",
    )
    add(
        "research_gap_bindings",
        research_gap_columns,
        f"SELECT {','.join(research_gap_columns)} FROM research_gap_bindings "
        "WHERE candidate_build_id=? AND case_id=? ORDER BY issue_id,id",
        (candidate_build_id, case_id),
    )
    index_columns = (
        "id",
        "path",
        "document_count",
        "chunk_count",
        "vector_count",
        "embedding_model",
        "reranker_model",
        "manifest_sha256",
        "metrics_json",
        "created_at",
        "corpus_id",
        "scoped_corpus_id",
        "source_manifest_hash",
        "parser_version",
        "chunker_version",
        "index_schema_version",
        "embedding_model_version",
        "rerank_version",
        "candidate_manifest_hash",
        "benchmark_result_json",
        "counts_json",
        "policy_sha256",
        "assessment_bundle_sha256",
    )
    add(
        "index_builds",
        index_columns,
        f"SELECT {','.join(index_columns)} FROM index_builds WHERE id=? ORDER BY id",
        (candidate_build_id,),
    )
    selection_columns = ("build_id", "attestation_id", "selected_at")
    add(
        "retrieval_attestation_selections",
        selection_columns,
        f"SELECT {','.join(selection_columns)} FROM retrieval_attestation_selections "
        "WHERE build_id=? ORDER BY build_id",
        (candidate_build_id,),
    )
    attestation_columns = (
        "id",
        "build_id",
        "attestation_path",
        "attestation_sha256",
        "schema_version",
        "prior_attestation_path",
        "prior_attestation_sha256",
        "build_seal_sha256",
        "source_manifest_sha256",
        "embedding_model",
        "reranker_model",
        "quality_policy_sha256",
        "assessment_bundle_sha256",
        "retrieval_policy_sha256",
        "benchmark_sha256",
        "freeze_manifest_sha256",
        "scorer_version",
        "scorer_implementation_sha256",
        "integration_sha",
        "created_at",
    )
    add(
        "retrieval_attestation_history",
        attestation_columns,
        f"SELECT rah.{',rah.'.join(attestation_columns)} "
        "FROM retrieval_attestation_history rah "
        "JOIN retrieval_attestation_selections ras ON ras.attestation_id=rah.id "
        "WHERE ras.build_id=? ORDER BY rah.id",
        (candidate_build_id,),
    )
    observation_columns = (
        "id",
        "task_id",
        "candidate_id",
        "source_id",
        "authority_identity_id",
        "pinned_index_build_id",
        "pinned_source_manifest_sha256",
        "observed_active_build_id",
        "baseline_version_sha256",
        "remote_content_sha256",
        "comparison_state",
        "stale_active",
        "scope_kind",
        "legal_locator",
        "proposition_sha256",
        "materiality_status",
        "review_status",
        "review_id",
        "reviewer_ref",
        "review_manifest_sha256",
        "safe_detail_json",
        "created_at",
    )
    observation_predicate = """
        suo.pinned_index_build_id=?
        OR (rt.pinned_index_build_id=? AND rt.as_of_date=?)
        OR suo.authority_identity_id IN (
          SELECT DISTINCT sv.authority_identity_id FROM source_versions sv
          JOIN evidence_spans es ON es.source_version_id=sv.id
          JOIN claim_evidence ce ON ce.evidence_id=es.id
          JOIN claims c ON c.id=ce.claim_id
          JOIN answer_versions av ON av.id=c.answer_version_id
          WHERE av.job_id=? AND sv.authority_identity_id IS NOT NULL
        )
        OR suo.source_id IN (
          SELECT DISTINCT d.source_identity_id FROM documents d
          JOIN source_versions sv ON sv.document_id=d.id
          JOIN evidence_spans es ON es.source_version_id=sv.id
          JOIN claim_evidence ce ON ce.evidence_id=es.id
          JOIN claims c ON c.id=ce.claim_id
          JOIN answer_versions av ON av.id=c.answer_version_id
          WHERE av.job_id=?
        )
    """
    observation_params = (
        candidate_build_id,
        candidate_build_id,
        as_of_date.isoformat(),
        job_id,
        job_id,
    )
    add(
        "source_update_observations",
        observation_columns,
        f"SELECT DISTINCT suo.{',suo.'.join(observation_columns)} "
        "FROM source_update_observations suo "
        "JOIN research_tasks rt ON rt.id=suo.task_id "
        f"WHERE {observation_predicate} ORDER BY suo.id",
        observation_params,
    )
    resolution_columns = (
        "id",
        "observation_id",
        "resolved_by_build_id",
        "source_manifest_sha256",
        "resolution_kind",
        "authority_identity_id",
        "legal_locator",
        "proposition_sha256",
        "evidence_sha256",
        "reviewer_ref",
        "created_at",
    )
    add(
        "source_update_resolution_events",
        resolution_columns,
        f"SELECT DISTINCT sure.{',sure.'.join(resolution_columns)} "
        "FROM source_update_resolution_events sure "
        "JOIN source_update_observations suo ON suo.id=sure.observation_id "
        "JOIN research_tasks rt ON rt.id=suo.task_id "
        f"WHERE sure.resolved_by_build_id=? OR {observation_predicate} ORDER BY sure.id",
        (candidate_build_id, *observation_params),
    )
    material: dict[str, Any] = {
        "schema": OWNER_CANARY_CONTENT_GRAPH_SCHEMA,
        "release_outbox_schema_contract_sha256": require_release_outbox_schema_contract(connection),
        "job_id": job_id,
        "answer_id": answer_id,
        "candidate_build_id": candidate_build_id,
        "case_id": case_id,
        "as_of_date": as_of_date.isoformat(),
        "rows": graph_rows,
    }
    return _OwnerCanaryContentGraphSnapshot(
        graph_sha256=sealed_sha256(material),
        job_id=job_id,
        answer_id=answer_id,
        row_count=len(graph_rows),
    )


def require_verified_owner_canary_content_graph(value: object) -> VerifiedOwnerCanaryContentGraph:
    if (
        type(value) is not VerifiedOwnerCanaryContentGraph
        or value._token is not _VERIFIED_OWNER_CANARY_CONTENT_GRAPH_TOKEN
    ):
        raise RuntimeError("owner-canary content graph was not semantically verified")
    return value


def require_owner_canary_content_graph_runtime_object_paths(
    capability: object, relative_paths: Sequence[str]
) -> VerifiedOwnerCanaryContentGraph:
    """Bind the semantic DB snapshot to the exact filesystem object plan."""

    verified = require_verified_owner_canary_content_graph(capability)
    observed = tuple(sorted(str(value) for value in relative_paths))
    if len(observed) != len(set(observed)) or observed != verified._runtime_object_relative_paths:
        raise RuntimeError("owner_canary_runtime_object_snapshot_membership_changed")
    return verified


def owner_canary_idempotency_key(attempt_request_seal_sha256: str) -> str:
    """Return the one exact public idempotency key for a sealed attempt."""

    if not _SHA256.fullmatch(attempt_request_seal_sha256):
        raise ValueError("owner-canary request seal is invalid")
    return (
        "owner-canary-"
        + hashlib.sha256(attempt_request_seal_sha256.encode("ascii")).hexdigest()[:40]
    )


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
        raise ValueError("owner canary requires an uncredentialed loopback HTTP origin")
    return value.rstrip("/")


def configured_authoritative_canary_output_root(
    settings: Settings,
    lane: Literal["development", "blind_holdout"],
) -> Path:
    """Select one lane-specific root without treating configuration as approval."""

    if lane not in {"development", "blind_holdout"}:
        raise ValueError("owner-canary review-root lane is unsupported")
    development = settings.development_review_root
    sealed_validation = settings.sealed_validation_review_root
    if development is None or sealed_validation is None:
        raise OwnerDecisionRequired("canary_output_privacy_owner_decision_unresolved")
    project_root = settings.project_root.resolve(strict=False)
    roots = tuple(value.expanduser() for value in (development, sealed_validation))
    resolved: list[Path] = []
    for root in roots:
        if not root.is_absolute() or root.is_symlink():
            raise OwnerDecisionRequired("canary_output_root_not_proven_non_synced")
        candidate = root.resolve(strict=False)
        if candidate == project_root or candidate.is_relative_to(project_root):
            raise OwnerDecisionRequired("canary_output_root_not_proven_non_synced")
        resolved.append(candidate)
    if resolved[0].is_relative_to(resolved[1]) or resolved[1].is_relative_to(resolved[0]):
        raise OwnerDecisionRequired("canary_output_lane_roots_not_isolated")
    return resolved[0] if lane == "development" else resolved[1]


def require_authoritative_canary_output_root(
    settings: Settings,
    lane: Literal["development", "blind_holdout"] | None = None,
) -> Path:
    """Stop until the owner approves the exact lane-specific private root."""

    if lane is None:
        raise OwnerDecisionRequired("owner_canary_review_root_lane_required")
    configured_authoritative_canary_output_root(settings, lane)
    # OwnerDecisionResolution v1 is self-sealed JSON and carries no trusted
    # signature or approved-root digest.  It therefore cannot yet authorize
    # readable output even when a path is configured.
    raise OwnerDecisionRequired("trusted_canary_output_privacy_verifier_missing")


def _safe_json(response: Any, *, expected: Sequence[int]) -> dict[str, Any]:
    status_code = int(getattr(response, "status_code", 0))
    if status_code not in expected:
        raise RuntimeError(f"owner-canary HTTP operation failed with status {status_code}")
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError("owner-canary HTTP response is not an object")
    return value


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runtime_implementation_sha256() -> str:
    return _file_sha256(Path(__file__))


def _load_json_object(path: Path, *, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError(f"{label} is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


@dataclass(frozen=True, slots=True)
class OwnerCanaryRuntimeContext:
    root: Path
    workspace_manifest: CanaryReviewWorkspaceManifest
    manifest: OwnerQualityCanaryManifest
    authorization: OwnerCanaryAuthorization
    bundle: LiveEvaluationBundle
    candidate: SealedCandidateIdentity
    as_of_date: date


@dataclass(frozen=True, slots=True)
class OwnerCanaryAdmissionBinding:
    request_sha256: str
    review_date: date
    lane: Literal["development", "blind_holdout"]
    run_id: str
    case_id: str
    attempt_number: int
    input_revision_sha256: str
    attempt_request_seal_sha256: str
    candidate_build_id: str
    authorization_seal_sha256: str
    expected_route: str
    as_of_date: date
    owned_runtime_start_attestation_sha256: str
    owned_runtime_instance_sha256: str
    owned_runtime_memory_policy_sha256: str
    owned_runtime_before_checkpoint_sha256: str
    owned_runtime_frontier_generation: int
    owned_runtime_state: Literal["active", "ended"]
    context: OwnerCanaryRuntimeContext
    writes_active: bool = False


class OwnerCanaryRuntimeReleaseReport(BaseModel):
    """Safe durable-runtime identity used as the source release report."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-runtime-release-report.v2"] = Field(
        default="legalbot.owner-canary-runtime-release-report.v2", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    attempt_number: int = Field(ge=1, le=3)
    input_revision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integration_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    job_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    quality_report_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    runtime_release_state: Literal["verified_full"]
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    word_count: int = Field(ge=1)
    answer_workflow_attempt_count: int = Field(ge=1, le=3)
    targeted_repair_version_count: int = Field(ge=0, le=2)
    versioned_repair_chain_verified: Literal[True]
    configured_model_id: str = Field(min_length=1, max_length=255)
    answer_model_version: str = Field(min_length=1, max_length=255)
    prompt_version: str = Field(min_length=1, max_length=255)
    router_version: str = Field(min_length=1, max_length=255)
    classifier_version: str = Field(min_length=1, max_length=255)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_adjudication_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standards_report_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_identity_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gate_inputs: dict[str, bool]
    gate_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    persisted_quality_report: Literal[True]
    candidate_pin_reconciled: Literal[True]
    authoritative_db_projection: bool
    synthetic_non_authoritative: bool
    owned_runtime_start_attestation_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    owned_runtime_instance_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    owned_runtime_memory_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    owned_runtime_before_checkpoint_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    owned_runtime_frontier_generation: int | None = Field(default=None, ge=1, le=61)
    plaintext_question_included: Literal[False]
    plaintext_answer_included: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def report_is_positive_and_sealed(self) -> Self:
        if tuple(self.deterministic_gate_inputs) != DETERMINISTIC_RELEASE_GATES or not all(
            self.deterministic_gate_inputs.values()
        ):
            raise ValueError("owner-canary runtime report has a failed deterministic gate")
        if self.authoritative_db_projection == self.synthetic_non_authoritative:
            raise ValueError("owner-canary runtime authority marker is inconsistent")
        if self.authoritative_db_projection and any(
            value is None
            for value in (
                self.owned_runtime_start_attestation_sha256,
                self.owned_runtime_instance_sha256,
                self.owned_runtime_memory_policy_sha256,
                self.owned_runtime_before_checkpoint_sha256,
                self.owned_runtime_frontier_generation,
            )
        ):
            raise ValueError("authoritative owner-canary report lacks owned runtime authority")
        if self.seal_sha256 != sealed_sha256(
            self.model_dump(mode="json", by_alias=True, exclude_none=True)
        ):
            raise ValueError("owner-canary runtime report seal does not match")
        return self


class OwnerCanaryRuntimeAttemptEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-runtime-attempt-envelope.v2"] = Field(
        default="legalbot.owner-canary-runtime-attempt-envelope.v2", alias="schema"
    )
    runtime_report: OwnerCanaryRuntimeReleaseReport
    attempt_result: OwnerCanaryCaseAttemptResult
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def envelope_is_exact_and_sealed(self) -> Self:
        report = self.runtime_report
        result = self.attempt_result
        expected = {
            "run_id": report.run_id,
            "authorization_seal_sha256": report.authorization_seal_sha256,
            "canary_manifest_seal_sha256": report.canary_manifest_seal_sha256,
            "case_id": report.case_id,
            "attempt_number": report.attempt_number,
            "input_revision_sha256": report.input_revision_sha256,
            "candidate_build_id": report.candidate_build_id,
            "candidate_manifest_sha256": report.candidate_manifest_sha256,
            "job_id": report.job_id,
            "answer_version_id": report.answer_version_id,
            "answer_sha256": report.answer_sha256,
            "word_count": report.word_count,
        }
        if not result.released or any(
            getattr(result, key) != value for key, value in expected.items()
        ):
            raise ValueError("owner-canary runtime envelope bindings differ")
        if (
            result.ai_review is None
            or result.ai_adjudication is None
            or result.standards_report is None
            or result.deterministic_gate_report is None
            or result.release_attestation is None
            or result.ai_review.seal_sha256 != report.ai_review_seal_sha256
            or result.ai_adjudication.seal_sha256 != report.ai_adjudication_seal_sha256
            or result.standards_report.seal_sha256 != report.standards_report_seal_sha256
            or result.deterministic_gate_report.source_release_report_sha256 != report.seal_sha256
            or result.release_attestation.source_release_report_sha256 != report.seal_sha256
        ):
            raise ValueError("owner-canary runtime report differs from release artifacts")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary runtime envelope seal does not match")
        return self


def load_verified_all60_batch_for_owner_runtime(
    *,
    settings: Settings,
    bundle: LiveEvaluationBundle,
    candidate: SealedCandidateIdentity,
    expert: LiveSuiteExpertQualification,
    qualification: ExactAll60Qualification,
    integration_sha: str,
    evaluation_root: Path,
) -> VerifiedAll60AIReviewBatch:
    """Replay the owned reviewer process and ledgers for one v3 qualification."""

    from .candidate_completion_authority import load_completion_memory_policy
    from .candidate_completion_runtime import build_local_completion_runtime_binding

    if candidate.status not in {"candidate", "active"}:
        raise ValueError("all-60 reviewer replay candidate status is ineligible")
    replay_candidate = (
        candidate if candidate.status == "candidate" else replace(candidate, status="candidate")
    )
    slo_path = settings.observability_slo_path
    if slo_path.is_symlink() or not slo_path.is_file():
        raise RuntimeError("all60_reviewer_slo_policy_invalid")
    slo_policy = load_slo_policy(slo_path)
    runtime_binding = build_local_completion_runtime_binding(
        settings=settings,
        candidate=replay_candidate,
        slo_policy_id=slo_policy.policy_id,
        slo_policy_sha256=hashlib.sha256(slo_path.read_bytes()).hexdigest(),
        integration_sha=integration_sha,
    )
    memory_policy = load_completion_memory_policy(
        settings.completion_memory_policy_path,
        owner_decision_root=settings.owner_decision_root,
        candidate=replay_candidate,
        runtime_binding=runtime_binding,
        integration_sha=integration_sha,
    )
    verified = load_verified_all60_ai_review_batch(
        evaluation_root=evaluation_root,
        run_date=qualification.ai_review_batch_run_date,
        run_id=qualification.ai_review_batch_run_id,
        bundle=bundle,
        candidate=replay_candidate,
        expert=expert,
        required_as_of_date=qualification.as_of_date,
        runtime_binding=runtime_binding,
        memory_policy=memory_policy,
        candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
    )
    if (
        verified.attestation.seal_sha256 != qualification.ai_review_batch_attestation_seal_sha256
        or verified.manifest_seal_sha256 != qualification.ai_review_batch_manifest_seal_sha256
        or verified.checkpoint_set_sha256 != qualification.ai_review_batch_checkpoint_set_sha256
        or verified.invocation_intent_ledger_sha256
        != qualification.ai_review_batch_intent_ledger_sha256
        or verified.invocation_outcome_ledger_sha256
        != qualification.ai_review_batch_outcome_ledger_sha256
        or verified.launcher_start_attestation_sha256
        != qualification.ai_review_batch_launcher_start_sha256
        or verified.launcher_end_attestation_sha256
        != qualification.ai_review_batch_launcher_end_sha256
    ):
        raise ValueError("all-60 qualification differs from verified reviewer batch")
    return verified


def _copy_verified_all60_batch_to_workspace(
    *,
    workspace: CanaryReviewWorkspace,
    qualification: ExactAll60Qualification,
    ai_review_batch: object,
) -> None:
    verified = require_verified_all60_ai_review_batch(ai_review_batch)
    source_run = verified.checkpoint_directory.parent
    expected_suffix = (
        ALL60_REPLAY_BATCH_ROOT_NAME,
        qualification.ai_review_batch_run_date.isoformat(),
        qualification.ai_review_batch_run_id,
    )
    if tuple(source_run.parts[-3:]) != expected_suffix:
        raise ValueError("all-60 reviewer batch source path differs")
    destination_prefix = ("safe-metrics", *expected_suffix)
    for depth in range(2, len(destination_prefix) + 1):
        workspace.create_private_directory(*destination_prefix[:depth], exist_ok=False)
    members = tuple(
        sorted(
            source_run.rglob("*"),
            key=lambda item: (len(item.relative_to(source_run).parts), item.as_posix()),
        )
    )
    if not members:
        raise ValueError("all-60 reviewer batch source is empty")
    for member in members:
        relative = member.relative_to(source_run)
        metadata = member.lstat()
        target_parts = (*destination_prefix, *relative.parts)
        if member.is_symlink():
            raise ValueError("all-60 reviewer batch contains a symlink")
        if member.is_dir():
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("all-60 reviewer batch directory is unsafe")
            workspace.create_private_directory(*target_parts, exist_ok=False)
            continue
        if (
            not member.is_file()
            or member.suffix != ".json"
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("all-60 reviewer batch file is unsafe")
        workspace.write_private_bytes(*target_parts, payload=member.read_bytes())


def register_owner_canary_runtime_authorization(
    *,
    settings: Settings,
    workspace: CanaryReviewWorkspace,
    manifest: OwnerQualityCanaryManifest,
    authorization_path: Path,
    qualification_path: Path,
    expert_qualification_path: Path | None,
    ai_review_batch: object | None,
    synthetic_non_authoritative: bool,
) -> Path:
    """Copy exact safe authorization bytes into the create-only runtime workspace."""

    destination = workspace.root / OWNER_CANARY_RUNTIME_AUTH_FILENAME
    raw = authorization_path.read_bytes()
    authorization = load_owner_canary_authorization(
        authorization_path,
        manifest=manifest,
    )
    if (
        workspace.read_private_bytes("sample-manifest.json")
        != owner_quality_manifest_bytes(manifest)
        or authorization.run_id != workspace.manifest.run_id
        or authorization.lane != workspace.manifest.lane
        or authorization.seal_sha256 != workspace.manifest.runtime_run_manifest_sha256
    ):
        raise ValueError("owner-canary runtime authorization differs from workspace")
    workspace.write_private_bytes(OWNER_CANARY_RUNTIME_AUTH_FILENAME, payload=raw)
    workspace.write_private_bytes(EXACT_ALL60_FILENAME, payload=qualification_path.read_bytes())
    if synthetic_non_authoritative:
        return destination
    if expert_qualification_path is None or ai_review_batch is None:
        raise ValueError("authoritative owner canary requires all-60 replay evidence")
    workspace.write_private_bytes(
        "safe-metrics",
        ALL60_REPLAY_EXPERT_FILENAME,
        payload=expert_qualification_path.read_bytes(),
    )
    qualification = ExactAll60Qualification.model_validate_json(qualification_path.read_bytes())
    _copy_verified_all60_batch_to_workspace(
        workspace=workspace,
        qualification=qualification,
        ai_review_batch=ai_review_batch,
    )
    if not authorization.completion_preflight_authoritative:
        raise OwnerDecisionRequired("authoritative_completion_preflight_required")
    completion_source = settings.evaluation_dir / authorization.completion_preflight_artifact_ref
    if completion_source.is_symlink() or not completion_source.is_dir():
        raise ValueError("authoritative completion-preflight artifact set is missing")
    completion_members = tuple(
        sorted(
            completion_source.rglob("*"),
            key=lambda item: (len(item.relative_to(completion_source).parts), item.as_posix()),
        )
    )
    if not completion_members:
        raise ValueError("authoritative completion-preflight artifact set is empty")
    workspace.create_private_directory(
        "safe-metrics", OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME, exist_ok=False
    )
    workspace.create_private_directory(
        "safe-metrics",
        OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME,
        completion_source.name,
        exist_ok=False,
    )
    for member in completion_members:
        relative = member.relative_to(completion_source)
        metadata = member.lstat()
        target_parts = (
            "safe-metrics",
            OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME,
            completion_source.name,
            *relative.parts,
        )
        if member.is_symlink():
            raise ValueError("authoritative completion-preflight contains a symlink")
        if member.is_dir():
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise ValueError("authoritative completion-preflight directory is unsafe")
            workspace.create_private_directory(*target_parts, exist_ok=False)
            continue
        if (
            not member.is_file()
            or member.suffix != ".json"
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("authoritative completion-preflight file is unsafe")
        workspace.write_private_bytes(*target_parts, payload=member.read_bytes())
    stage_a_run = (
        settings.evaluation_dir / OWNER_CANARY_STAGE_A_DIRNAME / authorization.stage_a_run_id
    )
    manifest_file = stage_a_run / "run-manifest.json"
    result_file = stage_a_run / "stage-a-result.json"
    checkpoint_root = stage_a_run / "checkpoints"
    checkpoint_members = (
        tuple(sorted(checkpoint_root.iterdir(), key=lambda item: item.name))
        if checkpoint_root.is_dir() and not checkpoint_root.is_symlink()
        else ()
    )
    if (
        stage_a_run.is_symlink()
        or not stage_a_run.is_dir()
        or manifest_file.is_symlink()
        or not manifest_file.is_file()
        or result_file.is_symlink()
        or not result_file.is_file()
        or len(checkpoint_members) != 585
        or any(member.is_symlink() or not member.is_file() for member in checkpoint_members)
    ):
        raise ValueError("authoritative owner canary Stage A artifact set is incomplete")
    workspace.create_private_directory("safe-metrics", OWNER_CANARY_STAGE_A_DIRNAME, exist_ok=False)
    workspace.create_private_directory(
        "safe-metrics",
        OWNER_CANARY_STAGE_A_DIRNAME,
        authorization.stage_a_run_id,
        exist_ok=False,
    )
    workspace.create_private_directory(
        "safe-metrics",
        OWNER_CANARY_STAGE_A_DIRNAME,
        authorization.stage_a_run_id,
        "checkpoints",
        exist_ok=False,
    )
    workspace.write_private_bytes(
        "safe-metrics",
        OWNER_CANARY_STAGE_A_DIRNAME,
        authorization.stage_a_run_id,
        "run-manifest.json",
        payload=manifest_file.read_bytes(),
    )
    workspace.write_private_bytes(
        "safe-metrics",
        OWNER_CANARY_STAGE_A_DIRNAME,
        authorization.stage_a_run_id,
        "stage-a-result.json",
        payload=result_file.read_bytes(),
    )
    for member in checkpoint_members:
        workspace.write_private_bytes(
            "safe-metrics",
            OWNER_CANARY_STAGE_A_DIRNAME,
            authorization.stage_a_run_id,
            "checkpoints",
            member.name,
            payload=member.read_bytes(),
        )
    return destination


def load_owner_canary_runtime_context(
    *,
    settings: Settings,
    database: Database,
    review_date: date,
    run_id: str,
    lane: Literal["development", "blind_holdout"] | None = None,
) -> OwnerCanaryRuntimeContext:
    if lane is None:
        raise OwnerDecisionRequired("owner_canary_review_root_lane_required")
    base = require_authoritative_canary_output_root(settings, lane)
    if not _SAFE_RUN.fullmatch(run_id):
        raise ValueError("owner-canary runtime run identity is invalid")
    root = base / review_date.isoformat() / run_id
    base = base.resolve()
    resolved = root.resolve()
    if not resolved.is_relative_to(base) or root.is_symlink() or not root.is_dir():
        raise ValueError("owner-canary runtime workspace is missing or unsafe")
    if stat.S_IMODE(root.stat().st_mode) != 0o700:
        raise ValueError("owner-canary runtime workspace is not owner-private")
    workspace_manifest = CanaryReviewWorkspaceManifest.model_validate_json(
        (root / "workspace-manifest.json").read_bytes()
    )
    if workspace_manifest.lane != lane:
        raise ValueError("owner-canary runtime workspace is in another review-root lane")
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    candidate = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=workspace_manifest.candidate_build_id,
    )
    qualification_path = root / EXACT_ALL60_FILENAME
    manifest = load_verified_owner_quality_canary_manifest(
        root / "sample-manifest.json",
        bundle=bundle,
        candidate=candidate,
        qualification_path=qualification_path,
    )
    authorization_path = root / OWNER_CANARY_RUNTIME_AUTH_FILENAME
    if (
        authorization_path.is_symlink()
        or not authorization_path.is_file()
        or stat.S_IMODE(authorization_path.stat().st_mode) != 0o600
    ):
        raise ValueError("owner-canary runtime authorization is missing or unsafe")
    authorization = load_owner_canary_authorization(authorization_path, manifest=manifest)
    _require_clean_authorized_integration(settings=settings, authorization=authorization)
    supplied_qualification = ExactAll60Qualification.model_validate_json(
        qualification_path.read_bytes()
    )
    from .live_suite_path_b import load_default_v2_repair

    expert_qualification = load_suite_expert_qualification(
        root / "safe-metrics" / ALL60_REPLAY_EXPERT_FILENAME,
        bundle=bundle,
        index_build_id=candidate.build_id,
        as_of_date=supplied_qualification.as_of_date,
        catalog_path=settings.database_path,
        repair=load_default_v2_repair(settings.project_root),
    )
    ai_review_batch = load_verified_all60_batch_for_owner_runtime(
        settings=settings,
        bundle=bundle,
        candidate=candidate,
        expert=expert_qualification,
        qualification=supplied_qualification,
        integration_sha=authorization.integration_sha,
        evaluation_root=root / "safe-metrics",
    )
    replayed_qualification = load_replayed_exact_all60_qualification(
        qualification_path,
        bundle=bundle,
        candidate=candidate,
        candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
        expert_qualification_path=root / "safe-metrics" / ALL60_REPLAY_EXPERT_FILENAME,
        ai_review_batch=ai_review_batch,
        catalog_path=settings.database_path,
        project_root=settings.project_root,
        integration_sha=authorization.integration_sha,
    )
    if manifest.qualification_seal_sha256 != replayed_qualification.seal_sha256:
        raise ValueError("owner-canary runtime all-60 replay binding differs")
    if expert_qualification.as_of_date != replayed_qualification.as_of_date:
        raise ValueError("owner-canary runtime expert currentness date differs")
    replay_authorization_stage_a(
        settings=settings,
        authorization=authorization,
        bundle=bundle,
        candidate=candidate,
        qualification=replayed_qualification,
        expert_qualification=expert_qualification,
        output_root=root / "safe-metrics" / OWNER_CANARY_STAGE_A_DIRNAME,
    )
    replay_authorization_completion_preflight(
        settings=settings,
        authorization=authorization,
        candidate=candidate,
        run_dir=(
            root
            / "safe-metrics"
            / OWNER_CANARY_COMPLETION_PREFLIGHT_DIRNAME
            / Path(authorization.completion_preflight_artifact_ref).name
        ),
    )
    if (
        workspace_manifest.run_id != run_id
        or workspace_manifest.review_date != review_date
        or workspace_manifest.runtime_run_manifest_sha256 != authorization.seal_sha256
        or workspace_manifest.canary_manifest_seal_sha256 != manifest.seal_sha256
        or workspace_manifest.lane != authorization.lane
        or workspace_manifest.expected_case_ids != authorization.authorized_case_ids
    ):
        raise ValueError("owner-canary runtime workspace bindings differ")
    if (
        bundle.manifest.seal_sha256 != manifest.suite_manifest_seal_sha256
        or bundle.registry.canonical_sha256 != manifest.suite_registry_canonical_sha256
    ):
        raise ValueError("owner-canary runtime suite differs from manifest")
    return OwnerCanaryRuntimeContext(
        root=root,
        workspace_manifest=workspace_manifest,
        manifest=manifest,
        authorization=authorization,
        bundle=bundle,
        candidate=candidate,
        as_of_date=replayed_qualification.as_of_date,
    )


def _verify_lane_runtime_prerequisites(
    *,
    settings: Settings,
    database: Database,
    manifest: OwnerQualityCanaryManifest,
    authorization: OwnerCanaryAuthorization,
    synthetic_non_authoritative: bool = False,
    require_owned_runtime: bool = True,
) -> None:
    verify_authorization_manifest(authorization, manifest)
    candidate = load_sealed_candidate_identity(
        settings=settings,
        database=database,
        candidate_build_id=authorization.candidate_build_id,
    )
    if candidate.candidate_manifest_sha256 != authorization.candidate_manifest_sha256:
        raise ValueError("owner-canary runtime candidate manifest differs")
    if synthetic_non_authoritative:
        if authorization.completion_preflight_authoritative:
            raise ValueError("synthetic canary cannot claim authoritative completion preflight")
    else:
        replay_authorization_completion_preflight(
            settings=settings,
            authorization=authorization,
            candidate=candidate,
        )
        if require_owned_runtime:
            # A caller without an exact workspace/case frontier cannot mint
            # active release authority from the earlier completion preflight.
            raise OwnerDecisionRequired("authoritative_owner_canary_owned_model_runtime_required")
    if isinstance(authorization, OwnerQualityDevelopmentAuthorization):
        return
    if not isinstance(authorization, OwnerQualityHoldoutAuthorization):
        raise ValueError("owner-canary runtime authorization lane is unsupported")
    active_path = settings.index_dir / "ACTIVE.json"
    active = _load_json_object(active_path, label="owner-canary holdout ACTIVE pointer")
    if (
        active.get("build_id") != authorization.active_build_id
        or authorization.active_build_id != authorization.candidate_build_id
        or database.active_index_id() != authorization.candidate_build_id
    ):
        raise ValueError("blind holdout requires the exact reconciled ACTIVE candidate")
    # A self-sealed O-04 record is not a trusted owner signature.  Keep the
    # runtime gate closed until the owner selects/configures a verifier.
    raise OwnerDecisionRequired("trusted_owner_o04_signature_verifier_missing")


def _require_clean_authorized_integration(
    *, settings: Settings, authorization: OwnerCanaryAuthorization
) -> str:
    from ..governance.v111_decision_generation import require_exact_clean_head

    try:
        return require_exact_clean_head(
            settings.project_root,
            authorization.integration_sha,
        )
    except RuntimeError as exc:
        raise ValueError("owner-canary runtime integration differs from authorization") from exc


def validate_owner_canary_api_admission(
    *,
    settings: Settings,
    database: Database,
    review_date: date,
    run_id: str,
    lane: Literal["development", "blind_holdout"] | None = None,
    case_id: str,
    attempt_number: int,
    input_revision_sha256: str,
    attempt_request_seal_sha256: str,
    raw_idempotency_key: str,
    payload: QuestionRequest,
    _context: OwnerCanaryRuntimeContext | None = None,
    historical_ended_runtime: bool = False,
    _ended_runtime_capability: VerifiedEndedOwnerCanaryRuntime | None = None,
) -> OwnerCanaryAdmissionBinding:
    """Validate exact owner-quality HTTP admission and return its candidate pin."""

    if lane is None:
        raise OwnerDecisionRequired("owner_canary_review_root_lane_required")
    if not _CASE_ID.fullmatch(case_id) or not 1 <= attempt_number <= 3:
        raise ValueError("owner-canary case or attempt identity is invalid")
    if attempt_number != 1:
        raise ValueError(
            "owner-canary permits one immutable submission per run/case; "
            "targeted repairs occur as versioned answer revisions"
        )
    if not _SHA256.fullmatch(input_revision_sha256) or not _SHA256.fullmatch(
        attempt_request_seal_sha256
    ):
        raise ValueError("owner-canary attempt digest is invalid")
    context = _context or load_owner_canary_runtime_context(
        settings=settings,
        database=database,
        review_date=review_date,
        run_id=run_id,
        lane=lane,
    )
    if (
        context.workspace_manifest.review_date != review_date
        or context.authorization.run_id != run_id
    ):
        raise ValueError("owner-canary supplied runtime context differs")
    _require_clean_authorized_integration(
        settings=settings,
        authorization=context.authorization,
    )
    _verify_lane_runtime_prerequisites(
        settings=settings,
        database=database,
        manifest=context.manifest,
        authorization=context.authorization,
        require_owned_runtime=False,
    )
    authorization = context.authorization
    if case_id not in authorization.authorized_case_ids:
        raise ValueError("case is outside the authorized owner-canary lane")
    case = context.bundle.registry.case(case_id)
    source_manifest = _load_json_object(
        settings.index_dir
        / "builds"
        / authorization.candidate_build_id
        / "approved-source-manifest.json",
        label="owner-canary approved-source manifest",
    )
    sequence_number = authorization.authorized_case_ids.index(case_id) + 1
    expected_request = _request(
        authorization=authorization,
        manifest=context.manifest,
        case_id=case_id,
        sequence_number=sequence_number,
        attempt_number=attempt_number,
        word_target=case.word_target,
        input_revision_sha256=input_revision_sha256,
    )
    if expected_request.seal_sha256 != attempt_request_seal_sha256:
        raise ValueError("owner-canary attempt request seal differs")
    if raw_idempotency_key != owner_canary_idempotency_key(expected_request.seal_sha256):
        raise ValueError("owner-canary idempotency key differs from the exact request seal")
    if (
        hashlib.sha256(payload.question.encode("utf-8")).hexdigest() != case.question_sha256
        or str(payload.task_type) != case.task_type
        or payload.jurisdiction != case.jurisdiction
        or payload.as_of_date is None
        or source_manifest.get("current_law_as_of_date") != payload.as_of_date.isoformat()
        or payload.word_target != case.word_target
        or str(payload.online_mode) != "local_only"
        or payload.upload_ids
    ):
        raise ValueError("owner-canary request fields differ from the immutable case")
    task_type = classify_task(payload.question, payload.task_type)
    route = decide_route(payload.question, payload.word_target, task_type).route.value
    if route != case.expected_research_route:
        raise ValueError("owner-canary server route differs from the sealed case")
    runtime_binding, memory_policy = load_owner_canary_runtime_binding_and_memory_policy(
        settings=settings,
        candidate=context.candidate,
        integration_sha=authorization.integration_sha,
    )
    runtime_capability: VerifiedActiveOwnerCanaryRuntime | VerifiedEndedOwnerCanaryRuntime
    if historical_ended_runtime:
        runtime_capability = (
            load_ended_owner_canary_runtime(
                settings=settings,
                workspace_root=context.root,
                candidate=context.candidate,
                authorization_seal_sha256=authorization.seal_sha256,
                canary_manifest_seal_sha256=context.manifest.seal_sha256,
                workspace_seal_sha256=context.workspace_manifest.seal_sha256,
                runtime_binding=runtime_binding,
                memory_policy=memory_policy,
                completion_preflight_result_sha256=(
                    authorization.completion_preflight_verified_result_sha256
                ),
                expected_case_ids=authorization.authorized_case_ids,
                database=database,
            )
            if _ended_runtime_capability is None
            else require_verified_ended_owner_canary_runtime(_ended_runtime_capability)
        )
        if (
            runtime_capability.start.run_id != authorization.run_id
            or runtime_capability.start.authorization_seal_sha256 != authorization.seal_sha256
            or runtime_capability.end.case_ids != authorization.authorized_case_ids
        ):
            raise ValueError("owner-canary ended runtime capability differs")
        start = runtime_capability.start
        before_checkpoint = next(
            item
            for item in runtime_capability.checkpoints
            if item.case_id == case_id and item.phase == "before_case"
        )
        # This field records the state under which the immutable job admission
        # was minted.  Historical replay separately proves that the same
        # before-case checkpoint belongs to the exact successful end graph; it
        # must not rewrite the persisted admission fact to ``ended``.
        runtime_state: Literal["active", "ended"] = "active"
    else:
        runtime_capability = load_active_owner_canary_runtime(
            settings=settings,
            workspace_root=context.root,
            case_id=case_id,
            candidate=context.candidate,
            authorization_seal_sha256=authorization.seal_sha256,
            canary_manifest_seal_sha256=context.manifest.seal_sha256,
            workspace_seal_sha256=context.workspace_manifest.seal_sha256,
            runtime_binding=runtime_binding,
            memory_policy=memory_policy,
            completion_preflight_result_sha256=(
                authorization.completion_preflight_verified_result_sha256
            ),
            database=database,
        )
        active = require_verified_active_owner_canary_runtime(runtime_capability)
        start = active.start
        before_checkpoint = active.before_checkpoint
        runtime_state = "active"
    request_sha = sealed_sha256(
        {
            "schema": "legalbot.owner-canary-http-admission.v1",
            "attempt_request_seal_sha256": expected_request.seal_sha256,
            "authorization_seal_sha256": authorization.seal_sha256,
            "canary_manifest_seal_sha256": context.manifest.seal_sha256,
            "candidate_build_id": authorization.candidate_build_id,
            "candidate_manifest_sha256": authorization.candidate_manifest_sha256,
            "question_sha256": case.question_sha256,
            "route": route,
            "task_type": case.task_type,
            "jurisdiction": case.jurisdiction,
            "as_of_date": payload.as_of_date.isoformat(),
            "word_target": case.word_target,
            "online_mode": "local_only",
        }
    )
    return OwnerCanaryAdmissionBinding(
        request_sha256=request_sha,
        review_date=review_date,
        lane=lane,
        run_id=run_id,
        case_id=case_id,
        attempt_number=attempt_number,
        input_revision_sha256=input_revision_sha256,
        attempt_request_seal_sha256=expected_request.seal_sha256,
        candidate_build_id=authorization.candidate_build_id,
        authorization_seal_sha256=authorization.seal_sha256,
        expected_route=route,
        as_of_date=payload.as_of_date,
        owned_runtime_start_attestation_sha256=start.seal_sha256,
        owned_runtime_instance_sha256=start.runtime_instance_sha256,
        owned_runtime_memory_policy_sha256=start.memory_policy_sha256,
        owned_runtime_before_checkpoint_sha256=before_checkpoint.seal_sha256,
        owned_runtime_frontier_generation=before_checkpoint.frontier_generation,
        owned_runtime_state=runtime_state,
        context=context,
    )


def _parse_json_column(value: Any, *, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or ""))
    except json.JSONDecodeError as exc:
        raise ValueError(f"persisted {label} is invalid") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"persisted {label} is not an object")
    return parsed


def _canonical_persisted_release_findings(
    findings: Sequence[QualityFinding],
) -> list[dict[str, Any]]:
    """Remove only the one exact non-authoritative model-rubric marker."""

    canonical_rubric_marker = QualityFinding(
        gate="academic_rubric",
        code="model_rubric_ignored",
        message=(
            "Model-supplied rubric values were ignored; the academic score was "
            "computed independently from observable structure and verified evidence."
        ),
        severity=Severity.INFORMATIONAL,
    ).model_dump(mode="json")
    markers = [
        item.model_dump(mode="json") for item in findings if item.code == "model_rubric_ignored"
    ]
    if (
        len(markers) > 1
        or (markers and markers[0] != canonical_rubric_marker)
        or any(item.severity == Severity.HARD_BLOCKER for item in findings)
    ):
        raise ValueError("owner-canary persisted quality blockers are not canonical")
    return [
        item.model_dump(mode="json") for item in findings if item.code != "model_rubric_ignored"
    ]


def derive_owner_canary_gap_inventory(
    *,
    database: Database,
    authorization: OwnerCanaryAuthorization,
    bundle: LiveEvaluationBundle,
    qualification: ExactAll60Qualification,
) -> dict[str, tuple[OwnerCanaryGapDisposition, ...]]:
    """Derive the complete safe gap view; callers cannot inject a favorable empty map."""

    case_ids = authorization.authorized_case_ids
    placeholders = ",".join("?" for _ in case_ids)
    rows = database.fetchall(
        f"""
        SELECT id,candidate_build_id,source_manifest_sha256,case_id,issue_id,
               subject,jurisdiction,as_of_date,attempted_retrieval_sha256,
               materiality,detail_sha256,encrypted_detail,status
        FROM research_gap_bindings
        WHERE candidate_build_id=? AND case_id IN ({placeholders})
        ORDER BY case_id,issue_id,id
        """,
        (authorization.candidate_build_id, *case_ids),
    )
    exact_issues = {(item.case_id, item.issue_id) for item in qualification.issue_bindings}
    by_case: dict[str, list[OwnerCanaryGapDisposition]] = {case_id: [] for case_id in case_ids}
    seen_ids: set[str] = set()
    for row in rows:
        case_id = str(row["case_id"] or "")
        issue_id = str(row["issue_id"] or "")
        case = bundle.registry.case(case_id)
        gap_id = str(row["id"] or "")
        if (
            gap_id in seen_ids
            or (case_id, issue_id) not in exact_issues
            or str(row["candidate_build_id"] or "") != authorization.candidate_build_id
            or str(row["source_manifest_sha256"] or "")
            != qualification.candidate_source_manifest_sha256
            or str(row["as_of_date"] or "") != qualification.as_of_date.isoformat()
            or str(row["jurisdiction"] or "") != case.jurisdiction
            or str(row["subject"] or "") != case.subject
            or row["encrypted_detail"] in (None, b"")
            or not _SHA256.fullmatch(str(row["attempted_retrieval_sha256"] or ""))
            or not _SHA256.fullmatch(str(row["detail_sha256"] or ""))
        ):
            raise ValueError("owner-canary durable knowledge-gap binding differs")
        seen_ids.add(gap_id)
        materiality = str(row["materiality"] or "")
        material = materiality in {"material", "potentially_material"}
        durable_status = str(row["status"] or "")
        status_value: Literal[
            "resolved_in_candidate",
            "owner_decision_required",
            "staged_official_material",
            "not_material",
        ]
        if not material:
            status_value = "not_material"
        elif durable_status == "resolved_in_candidate":
            status_value = "resolved_in_candidate"
        elif durable_status == "staged_official_material":
            status_value = "staged_official_material"
        else:
            status_value = "owner_decision_required"
        by_case[case_id].append(
            OwnerCanaryGapDisposition(
                gap_id=gap_id,
                issue_id=issue_id,
                status=status_value,
                material=material,
            )
        )
    return {case_id: tuple(values) for case_id, values in by_case.items()}


def _evidence_span_from_row(row: Any) -> EvidenceSpan:
    """Rebuild the exact model-visible EvidenceSpan persisted in SQLite."""

    reviews_raw = json.loads(str(row["case_currentness_reviews_json"] or "[]"))
    seals_raw = json.loads(str(row["case_currentness_manifest_seals_json"] or "[]"))
    return EvidenceSpan(
        id=str(row["id"]),
        source_version_id=str(row["source_version_id"]),
        chunk_id=str(row["chunk_id"]),
        text=str(row["span_text"]),
        locator=str(row["locator"]),
        lane=MaterialLane(str(row["lane"])),
        jurisdiction=str(row["jurisdiction"]),
        subject=str(row["subject"]),
        citation_data=json.loads(str(row["citation_data_json"] or "{}")),
        canonical_citation=str(row["canonical_citation"] or "") or None,
        currentness_status=str(row["currentness_status"]),
        content_sha256=str(row["content_sha256"]),
        index_build_id=str(row["index_build_id"]),
        canonical_url=str(row["canonical_url"] or "") or None,
        retrieval_relevance_score=(
            float(row["retrieval_relevance_score"])
            if row["retrieval_relevance_score"] is not None
            else None
        ),
        retrieval_route=str(row["retrieval_route"] or "") or None,
        retrieval_threshold=(
            float(row["retrieval_threshold"])
            if row["retrieval_threshold"] is not None
            else None
        ),
        retrieval_threshold_policy_sha256=(
            str(row["retrieval_threshold_policy_sha256"] or "") or None
        ),
        retrieval_threshold_qualified=(
            bool(row["retrieval_threshold_qualified"])
            if row["retrieval_threshold_qualified"] is not None
            else None
        ),
        retrieval_qualification_reason=(
            str(row["retrieval_qualification_reason"] or "") or None
        ),
        legal_role=str(row["legal_role"] or "unclassified"),
        unapplied_effect_count=(
            int(row["unapplied_effect_count"])
            if row["unapplied_effect_count"] is not None
            else None
        ),
        provision_extent_status=str(row["provision_extent_status"] or "unverified"),
        identity_verified=bool(row["identity_verified"]),
        currentness_verified=bool(row["currentness_verified"]),
        case_currentness_reviews=tuple(
            CasePropositionReview.model_validate(item) for item in reviews_raw
        ),
        case_currentness_manifest_seals=tuple(str(item) for item in seals_raw),
    )


def _frozen_evidence(
    database: Database,
    cipher: LocalCipher,
    answer_id: str,
    *,
    require_verified_claims: bool = True,
) -> tuple[
    dict[str, EvidenceSpan],
    dict[str, tuple[str, ...]],
    tuple[str, ...],
    dict[str, str],
]:
    claims = database.fetchall(
        "SELECT * FROM claims WHERE answer_version_id=? ORDER BY ordinal", (answer_id,)
    )
    links = database.fetchall(
        """
        SELECT c.model_claim_id, ce.evidence_id, ce.ordinal
        FROM claim_evidence ce JOIN claims c ON c.id=ce.claim_id
        WHERE c.answer_version_id=? ORDER BY c.ordinal, ce.ordinal
        """,
        (answer_id,),
    )
    rows = database.fetchall(
        """
        SELECT DISTINCT es.* FROM evidence_spans es
        JOIN claim_evidence ce ON ce.evidence_id=es.id
        JOIN claims c ON c.id=ce.claim_id
        WHERE c.answer_version_id=? ORDER BY es.id
        """,
        (answer_id,),
    )
    evidence = {str(row["id"]): _evidence_span_from_row(row) for row in rows}
    by_claim: dict[str, list[str]] = {}
    for row in links:
        by_claim.setdefault(str(row["model_claim_id"]), []).append(str(row["evidence_id"]))
    if not claims:
        raise ValueError("owner-canary answer has no dispositioned material claims")
    if any(not bool(row["material"]) for row in claims):
        raise ValueError("owner-canary model claim materiality cannot bypass evidence disposition")
    material_rows = tuple(claims)
    if require_verified_claims and any(
        str(row["verification_status"] or "") != "verified" for row in material_rows
    ):
        raise ValueError("owner-canary answer contains an undispositioned material claim")
    claim_texts: dict[str, str] = {}
    for row in material_rows:
        claim_id = str(row["model_claim_id"] or "")
        encrypted = row["encrypted_claim_text"]
        if not claim_id or encrypted is None or str(row["claim_text"] or ""):
            raise ValueError("owner-canary material claim storage is not encrypted and exact")
        text = cipher.decrypt_text(bytes(encrypted))
        if not text.strip() or claim_id in claim_texts:
            raise ValueError("owner-canary material claim plaintext is missing or duplicated")
        claim_texts[claim_id] = text
    material_claim_ids = tuple(str(row["model_claim_id"]) for row in material_rows)
    return (
        evidence,
        {key: tuple(value) for key, value in by_claim.items()},
        material_claim_ids,
        claim_texts,
    )


def _deterministic_citations(evidence: Mapping[str, EvidenceSpan]) -> dict[str, str]:
    output: dict[str, str] = {}
    for evidence_id, span in evidence.items():
        citation = render_oscola(span.citation_data, span.locator)
        citation = " ".join(citation.split())
        if not citation:
            raise ValueError("owner-canary evidence has no deterministic citation")
        output[evidence_id] = citation
    return output


@dataclass(frozen=True, slots=True)
class _ReplayedOwnerCanaryVersionQuality:
    draft: StructuredDraft
    content: str
    evidence: dict[str, EvidenceSpan]
    claim_evidence: dict[str, tuple[str, ...]]
    material_claim_ids: tuple[str, ...]
    claim_texts: dict[str, str]
    frozen_claims: tuple[Any, ...]
    review: Any | None
    adjudication: AIEvidenceAdjudication | None
    standards: AssessmentStandardsReport
    deterministic_quality: Any
    persisted_findings: tuple[QualityFinding, ...]
    rendered: Any


def _load_owner_canary_runtime_object(
    *,
    database: Database,
    cipher: LocalCipher,
    runtime_object_root: Path,
    object_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Open one referenced encrypted object without following its final link."""

    rows = database.fetchall(
        "SELECT * FROM runtime_objects WHERE object_key=? ORDER BY object_key",
        (object_key,),
    )
    if len(rows) != 1:
        raise RuntimeError("owner_canary_runtime_object_identity_missing")
    row = rows[0]
    namespace = str(row["namespace"] or "")
    digest = str(row["content_sha256"] or "")
    relative = str(row["relative_path"] or "")
    expected_relative = f"{namespace}/{digest[:2]}/{digest}.enc"
    pure = PurePosixPath(relative)
    if (
        not _SHA256.fullmatch(digest)
        or re.fullmatch(r"[A-Za-z0-9_-]+", namespace) is None
        or object_key != f"{namespace}:{digest}"
        or relative != expected_relative
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise RuntimeError("owner_canary_runtime_object_identity_invalid")
    root = Path(os.path.normpath(os.fspath(runtime_object_root)))
    if not root.is_absolute():
        raise RuntimeError("owner_canary_runtime_object_root_invalid")
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    file_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        file_flags |= os.O_NOFOLLOW
    opened_directories: list[int] = []
    descriptor: int | None = None
    try:
        current_directory = os.open(root, directory_flags)
        opened_directories.append(current_directory)
        if not stat.S_ISDIR(os.fstat(current_directory).st_mode):
            raise RuntimeError("owner_canary_runtime_object_root_invalid")
        for component in pure.parts[:-1]:
            current_directory = os.open(
                component,
                directory_flags,
                dir_fd=current_directory,
            )
            opened_directories.append(current_directory)
            if not stat.S_ISDIR(os.fstat(current_directory).st_mode):
                raise RuntimeError("owner_canary_runtime_object_path_invalid")
        before = os.stat(pure.parts[-1], dir_fd=current_directory, follow_symlinks=False)
        descriptor = os.open(pure.parts[-1], file_flags, dir_fd=current_directory)
    except OSError:
        for directory in reversed(opened_directories):
            os.close(directory)
        raise RuntimeError("owner_canary_runtime_object_file_missing") from None
    except RuntimeError:
        for directory in reversed(opened_directories):
            os.close(directory)
        raise
    if descriptor is None:  # pragma: no cover - guarded by the open above
        raise RuntimeError("owner_canary_runtime_object_file_missing")
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_mode & 0o777) != 0o600
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > 64 * 1024 * 1024
        ):
            raise RuntimeError("owner_canary_runtime_object_file_invalid")
        encrypted = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            encrypted.extend(chunk)
        if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise RuntimeError("owner_canary_runtime_object_file_changed")
    except OSError:
        raise RuntimeError("owner_canary_runtime_object_file_invalid") from None
    finally:
        os.close(descriptor)
    try:
        after = os.stat(pure.parts[-1], dir_fd=current_directory, follow_symlinks=False)
    finally:
        for directory in reversed(opened_directories):
            os.close(directory)
    if (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_ctime_ns,
    ):
        raise RuntimeError("owner_canary_runtime_object_file_changed")
    try:
        plaintext = cipher.decrypt_text(bytes(encrypted)).encode("utf-8")
        value = json.loads(plaintext)
        metadata = json.loads(str(row["metadata_json"] or ""))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError("owner_canary_runtime_object_payload_invalid") from exc
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if (
        not isinstance(value, dict)
        or not isinstance(metadata, dict)
        or canonical != plaintext
        or len(plaintext) != int(row["byte_size"])
        or hashlib.sha256(plaintext).hexdigest() != digest
    ):
        raise RuntimeError("owner_canary_runtime_object_content_mismatch")
    return value, metadata


def _model_checkpoint_output(value: Mapping[str, Any]) -> tuple[str, StructuredDraft, str]:
    if set(value) != {"raw_text", "structured", "rubric_scores", "model_version", "metrics"}:
        raise RuntimeError("owner_canary_model_checkpoint_output_shape_invalid")
    if not isinstance(value["raw_text"], str) or not isinstance(value["rubric_scores"], dict):
        raise RuntimeError("owner_canary_model_checkpoint_output_shape_invalid")
    if not isinstance(value["metrics"], dict) or not isinstance(value["model_version"], str):
        raise RuntimeError("owner_canary_model_checkpoint_output_shape_invalid")
    return (
        str(value["raw_text"]),
        StructuredDraft.model_validate(value["structured"]),
        str(value["model_version"]),
    )


def _verify_owner_canary_model_checkpoint_lineage(
    *,
    database: Database,
    cipher: LocalCipher,
    runtime_object_root: Path,
    job: Any,
    answer_rows: Sequence[Any],
    replayed_by_answer: Mapping[str, _ReplayedOwnerCanaryVersionQuality],
    question: str,
    subject: str | None,
    word_target: int,
    candidate: SealedCandidateIdentity,
    candidate_build_root: Path,
    required_as_of_date: date,
) -> tuple[str, ...]:
    """Replay every terminal model checkpoint into the versioned answer chain."""

    job_id = str(job["id"])
    attempts = database.fetchall(
        """
        SELECT * FROM job_stage_attempts
        WHERE job_id=? AND (
          stage_key='draft' OR stage_key GLOB 'repair-[0-9][0-9]'
          OR output_object_key IS NOT NULL
        )
        ORDER BY stage_key,section_key,attempt_number,id
        """,
        (job_id,),
    )
    if not attempts:
        raise RuntimeError("owner_canary_model_stage_attempt_lineage_incomplete")
    groups: dict[tuple[str, str], list[Any]] = {}
    for attempt in attempts:
        stage_key = str(attempt["stage_key"] or "")
        if stage_key != "draft" and re.fullmatch(r"repair-[0-9]{2}", stage_key) is None:
            raise RuntimeError("owner_canary_unknown_stage_output_object")
        groups.setdefault((stage_key, str(attempt["section_key"] or "")), []).append(attempt)
    retry_rows = database.fetchall(
        "SELECT * FROM retry_decisions WHERE lane='job' AND work_id=? ORDER BY attempt_number",
        (job_id,),
    )
    failed_transitions: list[tuple[Any, Any]] = []
    completed: dict[tuple[str, str], Any] = {}
    for identity, rows in groups.items():
        if not 1 <= len(rows) <= 3 or tuple(int(item["attempt_number"]) for item in rows) != tuple(
            range(1, len(rows) + 1)
        ):
            raise RuntimeError("owner_canary_model_stage_attempt_sequence_invalid")
        terminal = rows[-1]
        prior = rows[:-1]
        if (
            str(terminal["status"] or "") != "complete"
            or terminal["output_object_key"] in (None, "")
            or terminal["encrypted_output"] not in (None, b"")
            or terminal["finished_at"] in (None, "")
            or terminal["error_code"] not in (None, "")
            or any(
                str(item["status"] or "") not in {"failed", "interrupted"}
                or item["output_object_key"] not in (None, "")
                or item["encrypted_output"] not in (None, b"")
                or item["error_code"] in (None, "")
                or item["finished_at"] in (None, "")
                for item in prior
            )
        ):
            raise RuntimeError("owner_canary_model_stage_attempt_terminal_invalid")
        failed_transitions.extend(zip(prior, rows[1:], strict=True))
        completed[identity] = terminal
    # The current durable answer worker never produces a retry transition for
    # evaluation-bound jobs: its answer retry decision is stop-only and the
    # manual resume endpoint rejects evaluation authority.  Accepting an
    # invented stage-level retry ledger here would certify a history that no
    # production controller can create.  Until a dedicated sealed producer is
    # implemented, the only exact replayable topology is one successful model
    # attempt per stage and one overall job attempt.
    if failed_transitions or retry_rows or int(job["attempt_count"] or 0) != 1:
        raise RuntimeError("owner_canary_model_stage_retry_lineage_invalid")

    draft_completions = {
        section: row for (stage, section), row in completed.items() if stage == "draft"
    }
    repair_stages = {stage for stage, _section in completed if stage != "draft"}
    targeted_count = len(answer_rows) - 2
    if not draft_completions or repair_stages != {
        f"repair-{round_number:02d}" for round_number in range(1, targeted_count + 1)
    }:
        raise RuntimeError("owner_canary_model_stage_topology_invalid")

    pack_rows = database.fetchall(
        "SELECT * FROM evidence_packs WHERE job_id=? ORDER BY section_key,id", (job_id,)
    )
    if len(pack_rows) != len(draft_completions):
        raise RuntimeError("owner_canary_draft_evidence_pack_topology_invalid")
    packs: dict[str, tuple[Any, dict[str, Any], tuple[EvidenceSpan, ...]]] = {}
    all_pack_evidence: dict[str, EvidenceSpan] = {}
    for pack in pack_rows:
        section_key = str(pack["section_key"] or "")
        if section_key in packs or section_key not in draft_completions:
            raise RuntimeError("owner_canary_draft_evidence_pack_topology_invalid")
        if (
            pack["object_key"] in (None, "")
            or not str(pack["object_key"]).startswith("evidence_packs:")
            or bytes(pack["encrypted_payload"] or b"") != b""
        ):
            raise RuntimeError("owner_canary_draft_evidence_pack_storage_invalid")
        payload, metadata = _load_owner_canary_runtime_object(
            database=database,
            cipher=cipher,
            runtime_object_root=runtime_object_root,
            object_key=str(pack["object_key"]),
        )
        if set(payload) != {"job_id", "section_key", "evidence"} or (
            payload.get("job_id"),
            payload.get("section_key"),
        ) != (job_id, section_key):
            raise RuntimeError("owner_canary_draft_evidence_pack_payload_invalid")
        evidence_payload = payload.get("evidence")
        if not isinstance(evidence_payload, list) or not evidence_payload:
            raise RuntimeError("owner_canary_draft_evidence_pack_payload_invalid")
        try:
            evidence_spans = tuple(EvidenceSpan.model_validate(item) for item in evidence_payload)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("owner_canary_draft_evidence_pack_payload_invalid") from exc
        if len({item.id for item in evidence_spans}) != len(evidence_spans):
            raise RuntimeError("owner_canary_draft_evidence_pack_payload_invalid")
        placeholders = ",".join("?" for _ in evidence_spans)
        durable_rows = database.fetchall(
            f"SELECT * FROM evidence_spans WHERE id IN ({placeholders}) ORDER BY id",
            tuple(item.id for item in evidence_spans),
        )
        durable = {str(row["id"]): _evidence_span_from_row(row) for row in durable_rows}
        if len(durable) != len(evidence_spans) or any(
            durable.get(item.id) != item for item in evidence_spans
        ):
            raise RuntimeError("owner_canary_draft_evidence_pack_durable_span_mismatch")
        for item in evidence_spans:
            prior_item = all_pack_evidence.setdefault(item.id, item)
            if prior_item != item:
                raise RuntimeError("owner_canary_draft_evidence_pack_span_conflict")
        pack_digest = evidence_pack_sha256(evidence_payload)
        source_ids = tuple(sorted({item.source_version_id for item in evidence_spans}))
        if (
            pack_digest != str(pack["digest"] or "")
            or str(pack["index_build_id"] or "") != str(job["pinned_index_build_id"] or "")
            or json.loads(str(pack["source_ids_json"] or "[]")) != list(source_ids)
            or metadata
            != {
                "purpose": "durable_evidence_pack",
                "pack_digest": pack_digest,
                "index_build_id": str(job["pinned_index_build_id"]),
            }
        ):
            raise RuntimeError("owner_canary_draft_evidence_pack_binding_invalid")
        packs[section_key] = (pack, payload, evidence_spans)

    verify_runtime_candidate_evidence_spans(
        candidate=candidate,
        candidate_build_root=candidate_build_root,
        evidence=tuple(all_pack_evidence.values()),
        required_as_of_date=required_as_of_date,
    )

    draft_outputs: dict[str, tuple[str, StructuredDraft, str]] = {}
    for section_key, attempt in draft_completions.items():
        pack, _pack_payload, _pack_spans = packs[section_key]
        if str(attempt["evidence_pack_digest"] or "") != str(pack["digest"]):
            raise RuntimeError("owner_canary_draft_stage_evidence_binding_invalid")
        if not str(attempt["output_object_key"] or "").startswith("draft_checkpoints:"):
            raise RuntimeError("owner_canary_draft_checkpoint_namespace_invalid")
        payload, metadata = _load_owner_canary_runtime_object(
            database=database,
            cipher=cipher,
            runtime_object_root=runtime_object_root,
            object_key=str(attempt["output_object_key"]),
        )
        if set(payload) != {
            "job_id",
            "section_key",
            "raw_text",
            "structured",
            "rubric_scores",
            "model_version",
            "metrics",
        } or (payload.get("job_id"), payload.get("section_key")) != (job_id, section_key):
            raise RuntimeError("owner_canary_draft_checkpoint_payload_invalid")
        output = _model_checkpoint_output(
            {key: payload[key] for key in payload if key not in {"job_id", "section_key"}}
        )
        if output[2] != PINNED_RUNTIME_MODEL_VERSION or metadata != {
            "purpose": "encrypted_resume_checkpoint",
            "input_digest": str(attempt["input_digest"]),
            "assessment_bundle_sha256": str(job["assessment_bundle_sha256"]),
        }:
            raise RuntimeError("owner_canary_draft_checkpoint_binding_invalid")
        draft_outputs[section_key] = output

    raw_answer = answer_rows[0]
    structured = replayed_by_answer[str(answer_rows[1]["id"])].draft
    assessment_rules = budget_assessment_guidance(
        OWNER_ASSESSMENT_BUNDLE,
        task_type=str(structured.task_type),
        subject=subject,
        max_characters=1_800,
    ).instructions
    raw_content = cipher.decrypt_text(bytes(raw_answer["encrypted_content"]))
    if str(raw_answer["version_kind"] or "") == "raw_model":
        if set(draft_outputs) != {"whole-answer"}:
            raise RuntimeError("owner_canary_direct_draft_checkpoint_topology_invalid")
        section_key, (raw_text, checkpoint_draft, model_version) = next(iter(draft_outputs.items()))
        pack, _payload, pack_spans = packs[section_key]
        expected_input = draft_checkpoint_input_sha256(
            question=question,
            task_type=structured.task_type,
            jurisdiction=structured.jurisdiction,
            as_of_date=structured.as_of_date,
            word_target=word_target,
            pack_digest=str(pack["digest"]),
            assessment_rules=assessment_rules,
            upload_context=(),
            assessment_bundle_sha256=str(job["assessment_bundle_sha256"]),
            model_id=PINNED_RUNTIME_REPO,
        )
        allowed = {item.id for item in pack_spans}
        if (
            raw_text != raw_content
            or checkpoint_draft != structured
            or model_version != str(raw_answer["model_version"])
            or str(draft_completions[section_key]["input_digest"] or "") != expected_input
            or any(
                evidence_id not in allowed
                for section in checkpoint_draft.sections
                for claim in section.claims
                for evidence_id in claim.evidence_ids
            )
        ):
            raise RuntimeError("owner_canary_direct_draft_checkpoint_lineage_invalid")
    elif str(raw_answer["version_kind"] or "") == "sectioned_assembly":
        try:
            proposition_keys = json.loads(str(job["issue_plan_proposition_keys_json"] or "[]"))
            if not isinstance(proposition_keys, list) or any(
                not isinstance(value, str) for value in proposition_keys
            ):
                raise TypeError
            issue_plan = IssuePlan(
                jurisdiction=structured.jurisdiction,
                subject=None,
                proposition_keys=proposition_keys,
                queries=[],
                notes_considered=0,
                notes_used=0,
                unsafe_notes_excluded=0,
            )
            section_tasks = build_section_tasks(
                question=question,
                word_target=word_target,
                issue_plan=issue_plan,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError("owner_canary_sectioned_issue_plan_invalid") from exc
        tasks_by_key = {item.key: item for item in section_tasks}
        if set(draft_outputs) != set(tasks_by_key) or set(draft_outputs) != {
            section.id for section in structured.sections
        }:
            raise RuntimeError("owner_canary_sectioned_checkpoint_topology_invalid")
        seen: set[str] = set()
        assembled_sections = []
        for position, target in enumerate(structured.sections, start=1):
            _raw, section_candidate, model_version = draft_outputs[target.id]
            task = tasks_by_key[target.id]
            pack, _pack_payload, pack_spans = packs[target.id]
            allowed = {item.id for item in pack_spans}
            expected_input = draft_checkpoint_input_sha256(
                question=f"Draft only this section: {task.heading}.\n\nQuestion: {question}",
                task_type=structured.task_type,
                jurisdiction=structured.jurisdiction,
                as_of_date=structured.as_of_date,
                word_target=task.word_target,
                pack_digest=str(pack["digest"]),
                assessment_rules=assessment_rules,
                upload_context=(),
                assessment_bundle_sha256=str(job["assessment_bundle_sha256"]),
                model_id=PINNED_RUNTIME_REPO,
            )
            claims = []
            for source_section in section_candidate.sections:
                for claim in source_section.claims:
                    if any(item not in allowed for item in claim.evidence_ids):
                        raise RuntimeError(
                            "owner_canary_sectioned_checkpoint_claim_evidence_invalid"
                        )
                    normalised = " ".join(claim.text.casefold().split())
                    if normalised in seen:
                        continue
                    seen.add(normalised)
                    claims.append(
                        claim.model_copy(
                            update={
                                "id": f"{target.id}-{claim.id}",
                                "evidence_ids": [
                                    evidence_id
                                    for evidence_id in claim.evidence_ids
                                    if evidence_id in allowed
                                ],
                            }
                        )
                    )
            if (
                target.heading != f"Analysis {position}"
                or model_version != str(raw_answer["model_version"])
                or target.claims != claims
                or str(draft_completions[target.id]["input_digest"] or "") != expected_input
            ):
                raise RuntimeError("owner_canary_sectioned_checkpoint_assembly_invalid")
            assembled_sections.append(target)
        if (
            raw_content
            != render_answer(
                structured, replayed_by_answer[str(answer_rows[1]["id"])].evidence
            ).markdown
        ):
            raise RuntimeError("owner_canary_sectioned_checkpoint_answer_invalid")
    else:
        raise RuntimeError("owner_canary_model_checkpoint_answer_kind_invalid")

    for round_number, target in enumerate(answer_rows[2:], start=1):
        stage = f"repair-{round_number:02d}"
        stage_rows = {
            section: row for (stage_key, section), row in completed.items() if stage_key == stage
        }
        target_draft = replayed_by_answer[str(target["id"])].draft
        parent = replayed_by_answer[str(answer_rows[round_number]["id"])]
        failed_sections = failed_section_scope(
            prior=parent.draft, findings=parent.persisted_findings
        )
        if not stage_rows or set(stage_rows) not in ({"direct"}, set(failed_sections)):
            raise RuntimeError("owner_canary_repair_checkpoint_topology_invalid")
        repaired_sections = {section.id: section for section in parent.draft.sections}
        for section_key, attempt in stage_rows.items():
            if not str(attempt["output_object_key"] or "").startswith("repair_checkpoints:"):
                raise RuntimeError("owner_canary_repair_checkpoint_namespace_invalid")
            if section_key == "direct":
                repair_question = question
                repair_prior = parent.draft
                repair_findings = parent.persisted_findings
                repair_evidence = dict(all_pack_evidence)
                repair_word_target = word_target
                repair_failed_sections = failed_sections
            else:
                parent_section = next(
                    (item for item in parent.draft.sections if item.id == section_key), None
                )
                if parent_section is None:
                    raise RuntimeError("owner_canary_repair_checkpoint_section_invalid")
                claim_ids = {claim.id for claim in parent_section.claims}
                repair_question = (
                    f"{question}\n\nRepair only this section: {parent_section.heading}."
                )
                repair_prior = parent.draft.model_copy(update={"sections": [parent_section]})
                repair_findings = tuple(
                    item
                    for item in parent.persisted_findings
                    if item.section_id == section_key or item.claim_id in claim_ids
                )
                repair_evidence = {item.id: item for item in packs[section_key][2]}
                if not repair_evidence:
                    cited = {
                        evidence_id
                        for claim in parent_section.claims
                        for evidence_id in claim.evidence_ids
                    }
                    repair_evidence = {
                        key: value for key, value in all_pack_evidence.items() if key in cited
                    }
                repair_word_target = max(
                    500,
                    min(700, round(word_target / max(1, len(parent.draft.sections)))),
                )
                repair_failed_sections = (section_key,)
            expected_input, expected_evidence = repair_checkpoint_input_sha256s(
                question=repair_question,
                prior=repair_prior,
                failed_sections=repair_failed_sections,
                repair_plan_sections=failed_sections,
                findings=repair_findings,
                evidence=repair_evidence,
                word_target=repair_word_target,
                upload_context=(),
                repair_round=round_number,
                section_key=section_key,
                assessment_bundle_sha256=str(job["assessment_bundle_sha256"]),
                model_id=PINNED_RUNTIME_REPO,
            )
            if (
                str(attempt["input_digest"] or "") != expected_input
                or str(attempt["evidence_pack_digest"] or "") != expected_evidence
            ):
                raise RuntimeError("owner_canary_repair_checkpoint_input_binding_invalid")
            payload, metadata = _load_owner_canary_runtime_object(
                database=database,
                cipher=cipher,
                runtime_object_root=runtime_object_root,
                object_key=str(attempt["output_object_key"]),
            )
            if set(payload) != {
                "schema",
                "job_id",
                "stage_key",
                "section_key",
                "repair_round",
                "input_digest",
                "evidence_pack_digest",
                "output",
            } or (
                payload.get("schema"),
                payload.get("job_id"),
                payload.get("stage_key"),
                payload.get("section_key"),
                payload.get("repair_round"),
                payload.get("input_digest"),
                payload.get("evidence_pack_digest"),
            ) != (
                "legalbot.repair-checkpoint.v1",
                job_id,
                stage,
                section_key,
                round_number,
                str(attempt["input_digest"]),
                str(attempt["evidence_pack_digest"]),
            ):
                raise RuntimeError("owner_canary_repair_checkpoint_payload_invalid")
            output_value = payload["output"]
            if not isinstance(output_value, dict):
                raise RuntimeError("owner_canary_repair_checkpoint_output_invalid")
            _raw, repaired, model_version = _model_checkpoint_output(output_value)
            if model_version != PINNED_RUNTIME_MODEL_VERSION or model_version != str(
                target["model_version"]
            ):
                raise RuntimeError("owner_canary_repair_checkpoint_model_invalid")
            if any(
                evidence_id not in repair_evidence
                for repaired_section in repaired.sections
                for claim in repaired_section.claims
                for evidence_id in claim.evidence_ids
            ):
                raise RuntimeError("owner_canary_repair_checkpoint_evidence_invalid")
            if section_key == "direct":
                if repaired != target_draft:
                    raise RuntimeError("owner_canary_repair_checkpoint_answer_invalid")
            else:
                if len(repaired.sections) != 1 or repaired.sections[0].id != section_key:
                    raise RuntimeError("owner_canary_repair_checkpoint_section_invalid")
                repaired_sections[section_key] = repaired.sections[0]
            if metadata != {
                "purpose": "encrypted_resume_checkpoint",
                "input_digest": expected_input,
                "evidence_pack_digest": expected_evidence,
                "policy_sha256": POLICY_SHA256,
                "assessment_bundle_sha256": str(job["assessment_bundle_sha256"]),
                "model_id_sha256": hashlib.sha256(PINNED_RUNTIME_REPO.encode("utf-8")).hexdigest(),
                "prompt_contract_version": REPAIR_CHECKPOINT_PROMPT_VERSION,
            }:
                raise RuntimeError("owner_canary_repair_checkpoint_metadata_invalid")
        if set(stage_rows) != {"direct"} and target_draft != parent.draft.model_copy(
            update={"sections": [repaired_sections[item.id] for item in parent.draft.sections]}
        ):
            raise RuntimeError("owner_canary_repair_checkpoint_assembly_invalid")

    return tuple(str(row["id"]) for row in completed.values())


def _canonical_persisted_version_findings(
    findings: Sequence[QualityFinding],
) -> list[dict[str, Any]]:
    """Remove only the exact informational model-rubric marker.

    A model rubric is deliberately not persisted, so replay cannot know
    whether it was supplied.  The runner records one fixed informational
    marker in that case.  No other finding (including hard blockers) may be
    caller-selected or omitted.
    """

    canonical_marker = QualityFinding(
        gate="academic_rubric",
        code="model_rubric_ignored",
        message=(
            "Model-supplied rubric values were ignored; the academic score was "
            "computed independently from observable structure and verified evidence."
        ),
        severity=Severity.INFORMATIONAL,
    ).model_dump(mode="json")
    markers = [
        item.model_dump(mode="json") for item in findings if item.code == "model_rubric_ignored"
    ]
    if len(markers) > 1 or (markers and markers[0] != canonical_marker):
        raise ValueError("owner-canary persisted model-rubric marker is not canonical")
    return [
        item.model_dump(mode="json") for item in findings if item.code != "model_rubric_ignored"
    ]


def _replay_owner_canary_version_quality(
    *,
    database: Database,
    cipher: LocalCipher,
    answer: Any,
    quality: Any,
    question: str,
    subject: str | None,
    word_target: int,
    expected_task_type: TaskType,
    expected_jurisdiction: str,
    expected_as_of_date: date,
    require_ai_when_eligible: bool,
) -> _ReplayedOwnerCanaryVersionQuality:
    """Replay one frozen answer version without trusting its quality row."""

    answer_id = str(answer["id"])
    if (
        str(quality["answer_version_id"] or "") != answer_id
        or str(quality["policy_version"] or "") != POLICY_VERSION
        or str(quality["policy_sha256"] or "") != POLICY_SHA256
        or quality["encrypted_source_draft"] is None
    ):
        raise ValueError("owner-canary version quality identity differs")
    try:
        draft = StructuredDraft.model_validate_json(
            cipher.decrypt_text(bytes(quality["encrypted_source_draft"]))
        )
    except Exception as exc:
        raise ValueError("owner-canary version source draft is invalid") from exc
    if (
        draft.title != "Evidence-first legal analysis"
        or draft.limitations
        or draft.task_type != expected_task_type
        or draft.jurisdiction != expected_jurisdiction
        or draft.as_of_date != expected_as_of_date
        or any(
            section.heading != f"Analysis {position}"
            for position, section in enumerate(draft.sections, start=1)
        )
        or any(not claim.material for section in draft.sections for claim in section.claims)
    ):
        raise ValueError("owner-canary version escaped the structured claim contract")

    evidence, claim_evidence, material_claim_ids, claim_texts = _frozen_evidence(
        database,
        cipher,
        answer_id,
        require_verified_claims=False,
    )
    frozen_claims = freeze_material_claims(draft=draft, evidence_by_id=evidence)
    rendered = render_answer(draft, evidence)
    content = cipher.decrypt_text(bytes(answer["encrypted_content"]))
    persisted_claim_rows = database.fetchall(
        "SELECT * FROM claims WHERE answer_version_id=? ORDER BY ordinal,id",
        (answer_id,),
    )
    flattened_claims = tuple(
        (ordinal, section.id, claim)
        for ordinal, (section, claim) in enumerate(
            (section, claim) for section in draft.sections for claim in section.claims
        )
    )
    exact_claim_projection = len(persisted_claim_rows) == len(flattened_claims) and all(
        int(row["ordinal"]) == ordinal
        and str(row["model_claim_id"] or "") == claim.id
        and str(row["section_id"] or "") == section_id
        and bool(row["material"]) is claim.material
        and (str(row["proposition_hash"]) if row["proposition_hash"] is not None else None)
        == claim.proposition_hash
        and str(row["claim_text"] or "") == ""
        and row["encrypted_claim_text"] is not None
        and cipher.decrypt_text(bytes(row["encrypted_claim_text"])) == claim.text
        for row, (ordinal, section_id, claim) in zip(
            persisted_claim_rows, flattened_claims, strict=True
        )
    )
    persisted_links = database.fetchall(
        """
        SELECT c.model_claim_id,ce.evidence_id,ce.ordinal
        FROM claim_evidence ce JOIN claims c ON c.id=ce.claim_id
        WHERE c.answer_version_id=? ORDER BY c.ordinal,ce.ordinal,ce.evidence_id
        """,
        (answer_id,),
    )
    expected_links = tuple(
        (claim.id, evidence_id, evidence_ordinal)
        for _ordinal, _section_id, claim in flattened_claims
        for evidence_ordinal, evidence_id in enumerate(claim.evidence_ids)
    )
    exact_link_projection = len(persisted_links) == len(expected_links) and all(
        (
            str(row["model_claim_id"]),
            str(row["evidence_id"]),
            int(row["ordinal"]),
        )
        == expected
        for row, expected in zip(persisted_links, expected_links, strict=True)
    )
    if (
        rendered.markdown != content
        or rendered.word_count != int(answer["word_count"])
        or not exact_claim_projection
        or not exact_link_projection
        or tuple(item.identity.claim_id for item in frozen_claims) != material_claim_ids
        or any(claim_texts.get(item.identity.claim_id) != item.claim_text for item in frozen_claims)
    ):
        raise ValueError("owner-canary version draft, answer or frozen claims differ")

    deterministic = QualityEvaluator(
        database, enforce_retrieval_threshold=True
    ).evaluate(
        answer_version_id=answer_id,
        draft=draft,
        rendered_text=rendered.markdown,
        evidence_by_id=evidence,
        word_count=rendered.word_count,
        word_target=word_target,
        rubric_scores={},
        question=question,
        subject=subject,
    )
    try:
        findings_raw = json.loads(str(quality["findings_json"] or ""))
        rubric_raw = json.loads(str(quality["rubric_scores_json"] or ""))
        if not isinstance(findings_raw, list) or not isinstance(rubric_raw, dict):
            raise TypeError("quality fields have the wrong shape")
        persisted_findings = tuple(QualityFinding.model_validate(item) for item in findings_raw)
        standards = AssessmentStandardsReport.model_validate(
            _parse_json_column(quality["assessment_standards_json"], label="standards report")
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("owner-canary persisted version quality is invalid") from exc

    expected_standards = AssessmentStandardsReport.model_validate(
        deterministic.assessment_standards
    )
    deterministic_findings = tuple(
        item for item in deterministic.findings if item.code != "model_rubric_ignored"
    )
    deterministic_hard_codes = tuple(
        sorted(
            {
                item.code
                for item in deterministic_findings
                if item.severity == Severity.HARD_BLOCKER
                and is_deterministic_safety_failure(item.code)
            }
        )
    )
    review_raw = quality["ai_evidence_review_json"]
    adjudication_raw = quality["ai_evidence_adjudication_json"]
    if (review_raw is None) != (adjudication_raw is None):
        raise ValueError("owner-canary version AI review topology is incomplete")
    review = None
    adjudication = None
    ai_findings: tuple[QualityFinding, ...] = ()
    if review_raw is not None:
        if deterministic_hard_codes:
            raise ValueError("owner-canary deterministic safety failure invoked AI review")
        review = load_persisted_ai_evidence_review(
            _parse_json_column(review_raw, label="AI review")
        )
        adjudication = AIEvidenceAdjudication.model_validate(
            _parse_json_column(adjudication_raw, label="AI adjudication")
        )
        expected_adjudication = adjudicate_ai_evidence_review(review)
        reviewed_claim_ids = tuple(item.claim_id for item in review.claims)
        if (
            adjudication != expected_adjudication
            or source_draft_sha256(draft) != review.source_draft_sha256
            or frozen_claim_bundle_sha256(frozen_claims) != review.frozen_claim_bundle_sha256
            or reviewed_claim_ids != material_claim_ids
            or review.material_claim_count != len(material_claim_ids)
            or review.prompt_sha256 != ai_evidence_reviewer_prompt_sha256()
            or review.policy_sha256 != POLICY_SHA256
            or review.toolchain_sha256 != ai_evidence_reviewer_toolchain_sha256()
            or review.model_id != PINNED_RUNTIME_REPO
            or review.model_version != PINNED_RUNTIME_MODEL_VERSION
            or any(
                (
                    verdict.claim_sha256,
                    verdict.evidence_span_ids,
                    verdict.evidence_bundle_sha256,
                )
                != (
                    frozen.identity.claim_sha256,
                    frozen.identity.evidence_span_ids,
                    frozen.identity.evidence_bundle_sha256,
                )
                for verdict, frozen in zip(review.claims, frozen_claims, strict=True)
            )
            or any(
                tuple(claim.evidence_span_ids) != claim_evidence.get(claim.claim_id, ())
                for claim in review.claims
            )
        ):
            raise ValueError("owner-canary version AI review binding differs")
        claim_sections = {
            claim.id: section.id for section in draft.sections for claim in section.claims
        }
        ai_findings = tuple(
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
        )
    elif require_ai_when_eligible and not deterministic_hard_codes:
        raise ValueError("owner-canary eligible version lacks advisory AI review")

    expected_findings = [
        item.model_dump(mode="json") for item in (*deterministic_findings, *ai_findings)
    ]
    persisted_canonical = _canonical_persisted_version_findings(persisted_findings)
    expected_evidence_passed = bool(deterministic.evidence_passed) and (
        adjudication is None or adjudication.passed
    )
    expected_release_state = (
        str(deterministic.release_state)
        if adjudication is None or adjudication.passed
        else "held_for_review"
    )
    if (
        standards != expected_standards
        or float(quality["academic_score"] or 0.0) != deterministic.academic_score
        or rubric_raw != deterministic.rubric_scores
        or bool(quality["evidence_passed"]) != expected_evidence_passed
        or str(quality["release_state"] or "") != expected_release_state
        or persisted_canonical != expected_findings
    ):
        raise ValueError("owner-canary persisted version findings differ from replay")

    claim_rows = database.fetchall(
        "SELECT model_claim_id,verification_status,verification_reason "
        "FROM claims WHERE answer_version_id=? ORDER BY ordinal,id",
        (answer_id,),
    )
    blockers_by_claim: dict[str, list[str]] = {}
    for finding in (*deterministic_findings, *ai_findings):
        if finding.claim_id and finding.severity == Severity.HARD_BLOCKER:
            blockers_by_claim.setdefault(finding.claim_id, []).append(finding.message)
    if any(
        str(row["verification_status"] or "")
        != ("failed" if blockers_by_claim.get(str(row["model_claim_id"])) else "verified")
        or str(row["verification_reason"] or "")
        != " ".join(blockers_by_claim.get(str(row["model_claim_id"]), ()))
        for row in claim_rows
    ):
        raise ValueError("owner-canary claim dispositions differ from replayed blockers")

    return _ReplayedOwnerCanaryVersionQuality(
        draft=draft,
        content=content,
        evidence=evidence,
        claim_evidence=claim_evidence,
        material_claim_ids=material_claim_ids,
        claim_texts=claim_texts,
        frozen_claims=frozen_claims,
        review=review,
        adjudication=adjudication,
        standards=standards,
        deterministic_quality=deterministic,
        persisted_findings=persisted_findings,
        rendered=rendered,
    )


def _verify_targeted_repair_chain(
    *,
    database: Database,
    cipher: LocalCipher,
    job: Any,
    answer_id: str,
    question: str | None = None,
    subject: str | None = None,
    word_target: int | None = None,
    expected_task_type: TaskType | None = None,
    expected_jurisdiction: str | None = None,
    expected_as_of_date: date | None = None,
    require_ai_when_eligible: bool = False,
    runtime_object_root: Path | None = None,
    candidate: SealedCandidateIdentity | None = None,
    candidate_build_root: Path | None = None,
) -> int:
    """Verify initial answer plus at most two targeted, diffed repair versions."""

    if not 1 <= int(job["attempt_count"] or 0) <= 3:
        raise ValueError("owner-canary answer workflow exceeded its bounded attempt circuit")
    rows = database.fetchall(
        "SELECT * FROM answer_versions WHERE job_id=? ORDER BY version_number, id",
        (str(job["id"]),),
    )
    by_id = {str(row["id"]): row for row in rows}
    kinds = tuple(str(row["version_kind"] or "") for row in rows)
    if (
        not 2 <= len(rows) <= 4
        or answer_id not in by_id
        or len(by_id) != len(rows)
        or tuple(int(row["version_number"]) for row in rows) != tuple(range(1, len(rows) + 1))
        or str(rows[-1]["id"]) != answer_id
        or rows[0]["parent_version_id"] is not None
        or kinds[0] not in {"raw_model", "sectioned_assembly"}
        or kinds[1] != "structured"
        or any(kind != "targeted_repair" for kind in kinds[2:])
        or any(
            str(row["policy_version"] or "") != POLICY_VERSION
            or str(row["policy_sha256"] or "") != POLICY_SHA256
            or str(row["model_version"] or "") != PINNED_RUNTIME_MODEL_VERSION
            or str(row["index_build_id"] or "") != str(job["pinned_index_build_id"] or "")
            for row in rows
        )
        or any(
            str(row["parent_version_id"] or "") != str(rows[position - 1]["id"])
            for position, row in enumerate(rows[1:], start=1)
        )
    ):
        raise ValueError("owner-canary answer version inventory is incomplete or duplicated")
    targeted = tuple(rows[2:])
    quality_rows = database.fetchall(
        """
        SELECT qr.* FROM quality_reports qr
        JOIN answer_versions av ON av.id=qr.answer_version_id
        WHERE av.job_id=? ORDER BY av.version_number,qr.created_at,qr.id
        """,
        (str(job["id"]),),
    )
    qualities_by_answer: dict[str, list[Any]] = {}
    for quality in quality_rows:
        qualities_by_answer.setdefault(str(quality["answer_version_id"]), []).append(quality)
    if qualities_by_answer.get(str(rows[0]["id"]), []) or any(
        len(qualities_by_answer.get(str(row["id"]), [])) != 1 for row in rows[1:]
    ):
        raise ValueError("owner-canary answer quality topology is ambiguous")
    first_quality = qualities_by_answer[str(rows[1]["id"])][0]
    if first_quality["encrypted_source_draft"] is None:
        raise ValueError("owner-canary structured version lacks its source draft")
    try:
        first_draft = StructuredDraft.model_validate_json(
            cipher.decrypt_text(bytes(first_quality["encrypted_source_draft"]))
        )
        request_material = json.loads(str(job["request_json"] or "{}"))
        if not isinstance(request_material, dict):
            raise TypeError("job request is not an object")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("owner-canary repair inputs are invalid") from exc
    replay_question = question
    if replay_question is None:
        if job["encrypted_question"] is None:
            raise ValueError("owner-canary repair question is unavailable")
        replay_question = cipher.decrypt_text(bytes(job["encrypted_question"]))
    replay_word_target = int(
        word_target
        if word_target is not None
        else job["word_target"] or request_material.get("word_target") or 0
    )
    if replay_word_target < 1:
        raise ValueError("owner-canary repair word target is invalid")
    replayed_by_answer: dict[str, _ReplayedOwnerCanaryVersionQuality] = {}
    for version in rows[1:]:
        version_id = str(version["id"])
        replayed_by_answer[version_id] = _replay_owner_canary_version_quality(
            database=database,
            cipher=cipher,
            answer=version,
            quality=qualities_by_answer[version_id][0],
            question=replay_question,
            subject=subject,
            word_target=replay_word_target,
            expected_task_type=expected_task_type or first_draft.task_type,
            expected_jurisdiction=expected_jurisdiction or first_draft.jurisdiction,
            expected_as_of_date=expected_as_of_date or first_draft.as_of_date,
            require_ai_when_eligible=require_ai_when_eligible,
        )
    ancestors: set[str] = set()
    cursor = by_id[answer_id]
    while cursor["parent_version_id"] is not None:
        parent_id = str(cursor["parent_version_id"])
        parent = by_id.get(parent_id)
        if parent is None or parent_id in ancestors:
            raise ValueError("owner-canary answer repair ancestry is invalid")
        ancestors.add(parent_id)
        cursor = parent
    if any(str(row["id"]) != answer_id and str(row["id"]) not in ancestors for row in targeted):
        raise ValueError("owner-canary targeted repair is outside the released version chain")
    if runtime_object_root is not None:
        if candidate is None or candidate_build_root is None or expected_as_of_date is None:
            raise RuntimeError("owner_canary_model_checkpoint_candidate_binding_missing")
        _verify_owner_canary_model_checkpoint_lineage(
            database=database,
            cipher=cipher,
            runtime_object_root=runtime_object_root,
            job=job,
            answer_rows=rows,
            replayed_by_answer=replayed_by_answer,
            question=replay_question,
            subject=subject,
            word_target=replay_word_target,
            candidate=candidate,
            candidate_build_root=candidate_build_root,
            required_as_of_date=expected_as_of_date,
        )
    prior_failure_fingerprints: list[str] = []
    for repair_number, row in enumerate(targeted, start=1):
        parent = by_id.get(str(row["parent_version_id"] or ""))
        encrypted_diff = row["encrypted_diff_from_parent"]
        if parent is None or encrypted_diff is None or str(row["diff_from_parent"] or ""):
            raise ValueError("owner-canary targeted repair lacks an encrypted parent diff")
        before = cipher.decrypt_text(bytes(parent["encrypted_content"]))
        after = cipher.decrypt_text(bytes(row["encrypted_content"]))
        expected_diff = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile="previous-version",
                tofile="new-version",
            )
        )
        if before == after or cipher.decrypt_text(bytes(encrypted_diff)) != expected_diff:
            raise ValueError("owner-canary targeted repair diff or changed input is invalid")
        if int(row["version_number"]) != int(parent["version_number"]) + 1:
            raise ValueError("owner-canary targeted repair version sequence is invalid")
        prior_quality = qualities_by_answer[str(parent["id"])][0]
        prior_replay = replayed_by_answer[str(parent["id"])]
        repaired_replay = replayed_by_answer[str(row["id"])]
        prior_draft = prior_replay.draft
        repaired_draft = repaired_replay.draft
        prior_findings = prior_replay.persisted_findings
        failed_sections = failed_section_scope(
            prior=prior_draft,
            findings=prior_findings,
        )
        hard = tuple(item for item in prior_findings if item.severity == Severity.HARD_BLOCKER)
        repairable = tuple(item for item in prior_findings if item.severity == Severity.REPAIRABLE)
        deterministic_hard_codes = tuple(
            sorted({item.code for item in hard if is_deterministic_safety_failure(item.code)})
        )
        failure_identity_sha256 = _quality_failure_identity_sha256((*hard, *repairable))
        quality_fingerprint = failure_fingerprint(
            stage="quality_verification",
            reason_code="quality_gate_failed",
            scope_id=str(job["id"]),
            identity_digests=(failure_identity_sha256,),
        )
        retry = decide_retry(
            attempt_number=repair_number,
            failure_reason_code=(
                deterministic_hard_codes[0] if deterministic_hard_codes else "quality_gate_failed"
            ),
            failure_fingerprint_sha256=quality_fingerprint,
            prior_failure_fingerprints=prior_failure_fingerprints,
            deterministic_safety=bool(deterministic_hard_codes),
            retryable=not deterministic_hard_codes,
            input_or_condition_changed=bool(failed_sections),
        )
        if (
            not retry.should_retry
            or not (hard or repairable)
            or (
                repair_number > 1
                and str(prior_quality["release_state"] or "")
                in {"verified_concise", "verified_limited"}
            )
        ):
            raise ValueError("owner-canary targeted repair violates its retry circuit")
        verify_targeted_structured_repair(
            prior=prior_draft,
            repaired=repaired_draft,
            failed_sections=failed_sections,
            findings=prior_findings,
        )
        prior_failure_fingerprints.append(quality_fingerprint)
    return len(targeted)


def _verify_owner_canary_runtime_semantic_core(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    binding: OwnerCanaryAdmissionBinding,
    answer_id: str,
    publication_phase: Literal["pre_release", "released"],
) -> OwnerCanaryRuntimeAttemptEnvelope:
    """Replay one deterministic semantic contract on either side of publication."""

    answer = database.answer(answer_id)
    job = database.job_by_evaluation_binding(binding.run_id, binding.case_id)
    quality_rows = database.fetchall(
        "SELECT * FROM quality_reports WHERE answer_version_id=? ORDER BY created_at,id",
        (answer_id,),
    )
    if answer is None or job is None or len(quality_rows) != 1:
        raise ValueError("owner-canary released durable records are incomplete")
    quality = quality_rows[0]
    authorization = binding.context.authorization
    candidate_status_row = database.fetchone(
        "SELECT status FROM index_builds WHERE id=?", (authorization.candidate_build_id,)
    )
    if candidate_status_row is None:
        raise ValueError("owner-canary candidate catalogue identity is unavailable")
    candidate_status = str(candidate_status_row["status"] or "")
    active_path = settings.index_dir / "ACTIVE.json"
    if active_path.is_symlink():
        raise ValueError("owner-canary ACTIVE pointer is unsafe")
    active_pointer: dict[str, Any] | None = None
    if active_path.exists():
        active_pointer = _load_json_object(
            active_path, label="owner-canary publication ACTIVE pointer"
        )
    if isinstance(authorization, OwnerQualityDevelopmentAuthorization):
        if candidate_status != "candidate" or (
            active_pointer is not None
            and active_pointer.get("build_id") == authorization.candidate_build_id
        ):
            raise ValueError("development canary candidate is no longer non-ACTIVE")
    elif isinstance(authorization, OwnerQualityHoldoutAuthorization):
        if (
            candidate_status != "active"
            or active_pointer is None
            or active_pointer.get("build_id") != authorization.candidate_build_id
            or authorization.active_build_id != authorization.candidate_build_id
        ):
            raise ValueError("holdout canary ACTIVE candidate is not exact")
    else:  # pragma: no cover - discriminated authorization union
        raise ValueError("owner-canary authorization phase is invalid")
    _require_clean_authorized_integration(settings=settings, authorization=authorization)
    from .evaluation_job_authority import load_job_authority

    durable_authority = load_job_authority(job)
    manifest = binding.context.manifest
    case = binding.context.bundle.registry.case(binding.case_id)
    qualification_path = binding.context.root / EXACT_ALL60_FILENAME
    if qualification_path.is_symlink() or not qualification_path.is_file():
        raise ValueError("owner-canary exact qualification is unavailable")
    qualification = ExactAll60Qualification.model_validate_json(qualification_path.read_bytes())
    gap_inventory = derive_owner_canary_gap_inventory(
        database=database,
        authorization=authorization,
        bundle=binding.context.bundle,
        qualification=qualification,
    )
    if any(
        item.material and item.status != "resolved_in_candidate"
        for item in gap_inventory[binding.case_id]
    ) or database.fetchall(
        "SELECT id FROM knowledge_gaps WHERE job_id=? ORDER BY created_at,id",
        (str(job["id"]),),
    ):
        raise ValueError("owner-canary release contains unresolved research uncertainty")
    content = cipher.decrypt_text(bytes(answer["encrypted_content"]))
    answer_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    persisted_answer_release_state = str(answer["release_state"] or "")
    release_state = "verified_full"
    outbox_rows = database.fetchall(
        "SELECT * FROM release_outbox WHERE job_id=? ORDER BY id", (str(job["id"]),)
    )
    expected_release_key = hashlib.sha256(f"release-v1\0{job['id']}".encode()).hexdigest()
    expected_trace_id, expected_trace_root_span_id = Database._job_trace_ids(str(job["id"]))
    if publication_phase == "pre_release":
        publication_state_valid = (
            str(job["status"] or "") == "running"
            and str(job["stage"] or "") == "verifying"
            and job["answer_id"] is None
            and job["release_state"] is None
            and answer["release_state"] is None
            and len(outbox_rows) == 0
        )
    elif publication_phase == "released":
        publication_state_valid = (
            str(job["answer_id"] or "") == answer_id
            and str(job["status"] or "") == "complete"
            and str(job["stage"] or "") == "complete"
            and float(job["progress"] or 0.0) == 1.0
            and str(job["release_state"] or "") == persisted_answer_release_state
            and persisted_answer_release_state == release_state
            and len(outbox_rows) == 1
            and str(outbox_rows[0]["answer_id"] or "") == answer_id
            and str(outbox_rows[0]["release_state"] or "") == release_state
            and str(outbox_rows[0]["idempotency_key"] or "") == expected_release_key
            and str(outbox_rows[0]["status"] or "") == "published"
            and str(outbox_rows[0]["release_audience"] or "") == "owner_evaluation"
            and outbox_rows[0]["published_at"] is not None
            and str(outbox_rows[0]["evaluation_authority_sha256"] or "")
            == str(job["evaluation_authority_sha256"] or "")
            and outbox_rows[0]["normal_live_authority_sha256"] in (None, "")
        )
    else:
        raise ValueError("owner-canary publication phase is invalid")
    if (
        str(answer["job_id"]) != str(job["id"])
        or not publication_state_valid
        or bool(job["cancel_requested"])
        or str(job["job_type"] or "") != "answer"
        or job["normal_live_authority_sha256"] not in (None, "")
        or str(job["trace_id"] or "") != expected_trace_id
        or str(job["trace_root_span_id"] or "") != expected_trace_root_span_id
        or job["terminal_reason_code"] is not None
        or job["error_code"] is not None
        or str(job["evaluation_request_sha256"] or "") != binding.request_sha256
        or durable_authority.get("schema") != "legalbot.persisted-evaluation-job-authority.v1"
        or durable_authority.get("lane") != "owner_quality_canary"
        or durable_authority.get("mode") != "candidate_pinned_evaluation_release"
        or durable_authority.get("release_allowed") is not True
        or durable_authority.get("run_id") != binding.run_id
        or durable_authority.get("case_id") != binding.case_id
        or durable_authority.get("request_sha256") != binding.request_sha256
        or durable_authority.get("candidate_build_id") != binding.candidate_build_id
        or durable_authority.get("authorization_seal_sha256") != binding.authorization_seal_sha256
        or durable_authority.get("owned_runtime_start_attestation_sha256")
        != binding.owned_runtime_start_attestation_sha256
        or durable_authority.get("owned_runtime_instance_sha256")
        != binding.owned_runtime_instance_sha256
        or durable_authority.get("owned_runtime_memory_policy_sha256")
        != binding.owned_runtime_memory_policy_sha256
        or durable_authority.get("owned_runtime_before_checkpoint_sha256")
        != binding.owned_runtime_before_checkpoint_sha256
        or durable_authority.get("owned_runtime_frontier_generation")
        != binding.owned_runtime_frontier_generation
        or str(job["pinned_index_build_id"] or "") != authorization.candidate_build_id
        or str(answer["index_build_id"] or "") != authorization.candidate_build_id
        or release_state not in _PUBLIC_RELEASES
        or str(quality["release_state"]) != release_state
        or str(quality["answer_version_id"] or "") != answer_id
        or str(quality["policy_version"] or "") != POLICY_VERSION
        or str(quality["policy_sha256"] or "") != POLICY_SHA256
        or str(job["worker_prompt_version"] or "") != PROMPT_VERSION
        or str(job["worker_router_version"] or "") != ROUTER_VERSION
        or str(job["worker_classifier_version"] or "") != CLASSIFIER_VERSION
        or str(job["worker_policy_sha256"] or "") != POLICY_SHA256
        or str(job["assessment_bundle_sha256"] or "") != OWNER_ASSESSMENT_BUNDLE.sha256
        or settings.model_id != PINNED_RUNTIME_REPO
        or authorization.policy_bindings.answer_model_id != PINNED_RUNTIME_REPO
        or authorization.policy_bindings.answer_model_version != PINNED_RUNTIME_MODEL_VERSION
        or str(answer["model_version"] or "") != PINNED_RUNTIME_MODEL_VERSION
    ):
        raise ValueError("owner-canary durable runtime identities differ")
    review = load_persisted_ai_evidence_review(
        _parse_json_column(quality["ai_evidence_review_json"], label="AI review")
    )
    adjudication = AIEvidenceAdjudication.model_validate(
        _parse_json_column(quality["ai_evidence_adjudication_json"], label="AI adjudication")
    )
    standards = AssessmentStandardsReport.model_validate(
        _parse_json_column(quality["assessment_standards_json"], label="standards report")
    )
    encrypted_source_draft = quality["encrypted_source_draft"]
    if encrypted_source_draft is None:
        raise ValueError("owner-canary quality report lacks its encrypted source draft")
    source_draft = StructuredDraft.model_validate_json(
        cipher.decrypt_text(bytes(encrypted_source_draft))
    )
    if (
        source_draft.title != "Evidence-first legal analysis"
        or source_draft.limitations
        or any(
            section.heading != f"Analysis {position}"
            for position, section in enumerate(source_draft.sections, start=1)
        )
        or any(not claim.material for section in source_draft.sections for claim in section.claims)
    ):
        raise ValueError("owner-canary model-authored prose escaped the claim disposition contract")
    evidence, claim_evidence, material_claim_ids, claim_texts = _frozen_evidence(
        database, cipher, answer_id
    )
    frozen_claims = freeze_material_claims(
        draft=source_draft,
        evidence_by_id=evidence,
    )
    rendered = render_answer(source_draft, evidence)
    expected_adjudication = adjudicate_ai_evidence_review(review)
    expected_standards = score_applicable_standards(
        draft=source_draft,
        question=case.question,
        subject=case.subject,
        evidence_by_id=evidence,
        supported_claim_ids=material_claim_ids,
    )
    deterministic_quality = QualityEvaluator(
        database, enforce_retrieval_threshold=True
    ).evaluate(
        answer_version_id=answer_id,
        draft=source_draft,
        rendered_text=rendered.markdown,
        evidence_by_id=evidence,
        word_count=rendered.word_count,
        word_target=case.word_target,
        rubric_scores={},
        question=case.question,
        subject=case.subject,
    )
    try:
        persisted_findings = json.loads(str(quality["findings_json"] or ""))
        persisted_rubric_scores = json.loads(str(quality["rubric_scores_json"] or ""))
    except json.JSONDecodeError as exc:
        raise ValueError("owner-canary persisted deterministic quality data is invalid") from exc
    if not isinstance(persisted_findings, list) or not isinstance(persisted_rubric_scores, dict):
        raise ValueError("owner-canary persisted deterministic quality shape is invalid")
    try:
        parsed_persisted_findings = tuple(
            QualityFinding.model_validate(item) for item in persisted_findings
        )
    except Exception as exc:
        raise ValueError("owner-canary persisted quality finding is invalid") from exc
    # The model's self-rubric is ignored by policy.  Its presence is recorded
    # only as one exact informational marker and is not otherwise persisted, so
    # it cannot be reconstructed.  A code-only exception would let a mutated
    # hard blocker hide under the marker's code.
    expected_findings = [
        item.model_dump(mode="json")
        for item in deterministic_quality.findings
        if item.code != "model_rubric_ignored"
    ]
    persisted_release_findings = _canonical_persisted_release_findings(parsed_persisted_findings)
    reviewed_claim_ids = tuple(item.claim_id for item in review.claims)
    if (
        not review.passed
        or not adjudication.passed
        or not standards.avoidance_passed
        or adjudication != expected_adjudication
        or standards != expected_standards
        or int(quality["evidence_passed"] or 0) != int(deterministic_quality.evidence_passed)
        or float(quality["academic_score"] or 0.0) != deterministic_quality.academic_score
        or persisted_rubric_scores != deterministic_quality.rubric_scores
        or persisted_release_findings != expected_findings
        or str(quality["release_state"] or "") != str(deterministic_quality.release_state)
        or rendered.markdown != content
        or rendered.word_count != int(answer["word_count"])
        or source_draft.task_type != case.task_type
        or source_draft.jurisdiction != case.jurisdiction
        or source_draft.as_of_date != binding.as_of_date
        or source_draft_sha256(source_draft) != review.source_draft_sha256
        or frozen_claim_bundle_sha256(frozen_claims) != review.frozen_claim_bundle_sha256
        or reviewed_claim_ids != material_claim_ids
        or tuple(item.identity.claim_id for item in frozen_claims) != material_claim_ids
        or any(claim_texts.get(item.identity.claim_id) != item.claim_text for item in frozen_claims)
        or any(
            (
                verdict.claim_sha256,
                verdict.evidence_span_ids,
                verdict.evidence_bundle_sha256,
            )
            != (
                frozen.identity.claim_sha256,
                frozen.identity.evidence_span_ids,
                frozen.identity.evidence_bundle_sha256,
            )
            for verdict, frozen in zip(review.claims, frozen_claims, strict=True)
        )
        or any(
            tuple(claim.evidence_span_ids) != claim_evidence.get(claim.claim_id, ())
            for claim in review.claims
        )
        or standards.source_draft_sha256 != review.source_draft_sha256
        or standards.question_sha256 != case.question_sha256
        or standards.bundle_version != OWNER_ASSESSMENT_BUNDLE.version
        or standards.bundle_sha256 != authorization.policy_bindings.standards_bundle_sha256
        or review.prompt_sha256 != ai_evidence_reviewer_prompt_sha256()
        or review.prompt_sha256 != authorization.policy_bindings.ai_reviewer_prompt_sha256
        or review.policy_sha256 != POLICY_SHA256
        or review.policy_sha256 != authorization.policy_bindings.ai_reviewer_policy_sha256
        or review.toolchain_sha256 != ai_evidence_reviewer_toolchain_sha256()
        or review.toolchain_sha256 != authorization.policy_bindings.ai_reviewer_toolchain_sha256
        or review.model_id != PINNED_RUNTIME_REPO
        or review.model_version != PINNED_RUNTIME_MODEL_VERSION
    ):
        raise ValueError("owner-canary AI, standards or claim-evidence bindings differ")
    citations = _deterministic_citations(evidence)
    evidence_bundle = seal_owner_canary_evidence_bundle(
        run_id=binding.run_id,
        authorization_seal_sha256=authorization.seal_sha256,
        canary_manifest_seal_sha256=manifest.seal_sha256,
        case_id=binding.case_id,
        candidate_build_id=authorization.candidate_build_id,
        candidate_manifest_sha256=authorization.candidate_manifest_sha256,
        job_id=str(job["id"]),
        answer_version_id=answer_id,
        jurisdiction=case.jurisdiction,
        as_of_date=binding.as_of_date,
        ai_review=review,
        evidence_by_id=evidence,
        deterministic_citations=citations,
    )
    if (
        evidence_bundle.relevance_threshold_policy_sha256
        != authorization.policy_bindings.relevance_threshold_policy_sha256
    ):
        raise ValueError("owner-canary relevance-threshold policy differs from authorization")
    finding_codes = {item.code for item in deterministic_quality.findings}
    material_bound = bool(reviewed_claim_ids) and all(
        claim_evidence.get(claim_id) for claim_id in reviewed_claim_ids
    )
    evidence_values = tuple(evidence.values())
    within_words = (
        math.ceil(case.word_target * 0.95)
        <= int(answer["word_count"])
        <= math.floor(case.word_target * 1.05)
    )
    gate_inputs = {
        "citation_binding": material_bound and set(citations) == set(evidence),
        "currentness": bool(evidence_values)
        and all(item.currentness_verified for item in evidence_values),
        "evidence_binding": material_bound,
        "evidence_identity": bool(evidence_values)
        and all(item.identity_verified for item in evidence_values),
        "jurisdiction": bool(evidence_values)
        and all(item.jurisdiction == case.jurisdiction for item in evidence_values),
        "material_claim_disposition": review.passed and adjudication.passed,
        "privacy": not contains_absolute_private_path(content)
        and not any(
            identifier.casefold() in content.casefold()
            for identifier in settings.owner_identifiers
            if identifier.strip()
        ),
        "prompt_injection": not prompt_injection_hits(content)
        and not any(prompt_injection_hits(item.text) for item in evidence_values),
        "quotation_accuracy": not bool(finding_codes & _QUOTE_FAILURE_CODES),
        "retrieval_relevance": bool(evidence_values)
        and all(
            item.retrieval_threshold_qualified is True
            and item.retrieval_relevance_score is not None
            and item.retrieval_threshold is not None
            and item.retrieval_relevance_score >= item.retrieval_threshold
            and item.retrieval_threshold_policy_sha256 is not None
            for item in evidence_values
        )
        and len(
            {
                item.retrieval_threshold_policy_sha256
                for item in evidence_values
            }
        )
        == 1,
        "source_lane": bool(evidence_values)
        and all(
            str(item.lane) in {"primary_authority", "official_secondary", "scholarship"}
            for item in evidence_values
        ),
        "word_target": within_words,
    }
    if finding_codes & HARD_BLOCKER_CODES or not all(gate_inputs.values()):
        raise ValueError("owner-canary deterministic release inputs contain a hard failure")
    targeted_repair_count = _verify_targeted_repair_chain(
        database=database,
        cipher=cipher,
        job=job,
        answer_id=answer_id,
        question=case.question,
        subject=case.subject,
        word_target=case.word_target,
        expected_task_type=TaskType(case.task_type),
        expected_jurisdiction=case.jurisdiction,
        expected_as_of_date=binding.as_of_date,
        require_ai_when_eligible=True,
        runtime_object_root=settings.runtime_object_dir,
        candidate=binding.context.candidate,
        candidate_build_root=(settings.index_dir / "builds" / authorization.candidate_build_id),
    )
    report_material: dict[str, Any] = {
        "schema": OWNER_CANARY_RUNTIME_REPORT_SCHEMA,
        "run_id": binding.run_id,
        "authorization_seal_sha256": authorization.seal_sha256,
        "canary_manifest_seal_sha256": manifest.seal_sha256,
        "case_id": binding.case_id,
        "attempt_number": binding.attempt_number,
        "input_revision_sha256": binding.input_revision_sha256,
        "candidate_build_id": authorization.candidate_build_id,
        "candidate_manifest_sha256": authorization.candidate_manifest_sha256,
        "integration_sha": authorization.integration_sha,
        "job_id": str(job["id"]),
        "answer_version_id": answer_id,
        "quality_report_id": str(quality["id"]),
        "runtime_release_state": release_state,
        "answer_sha256": answer_sha,
        "word_count": int(answer["word_count"]),
        "answer_workflow_attempt_count": int(job["attempt_count"]),
        "targeted_repair_version_count": targeted_repair_count,
        "versioned_repair_chain_verified": True,
        "configured_model_id": PINNED_RUNTIME_REPO,
        "answer_model_version": str(answer["model_version"]),
        "prompt_version": str(job["worker_prompt_version"]),
        "router_version": str(job["worker_router_version"]),
        "classifier_version": str(job["worker_classifier_version"]),
        "policy_sha256": POLICY_SHA256,
        "assessment_bundle_sha256": OWNER_ASSESSMENT_BUNDLE.sha256,
        "ai_review_seal_sha256": review.seal_sha256,
        "ai_adjudication_seal_sha256": adjudication.seal_sha256,
        "standards_report_seal_sha256": standards.seal_sha256,
        "evidence_identity_set_sha256": sealed_sha256(
            {"evidence_span_ids": list(evidence_bundle.evidence_span_ids)}
        ),
        "deterministic_gate_inputs": gate_inputs,
        "gate_implementation_sha256": _runtime_implementation_sha256(),
        "persisted_quality_report": True,
        "candidate_pin_reconciled": True,
        "authoritative_db_projection": True,
        "synthetic_non_authoritative": False,
        "owned_runtime_start_attestation_sha256": (binding.owned_runtime_start_attestation_sha256),
        "owned_runtime_instance_sha256": binding.owned_runtime_instance_sha256,
        "owned_runtime_memory_policy_sha256": (binding.owned_runtime_memory_policy_sha256),
        "owned_runtime_before_checkpoint_sha256": (binding.owned_runtime_before_checkpoint_sha256),
        "owned_runtime_frontier_generation": (binding.owned_runtime_frontier_generation),
        "plaintext_question_included": False,
        "plaintext_answer_included": False,
    }
    report_material["seal_sha256"] = sealed_sha256(report_material)
    report = OwnerCanaryRuntimeReleaseReport.model_validate(report_material)
    gate_report = seal_owner_canary_deterministic_gate_report(
        run_id=binding.run_id,
        authorization_seal_sha256=authorization.seal_sha256,
        canary_manifest_seal_sha256=manifest.seal_sha256,
        case_id=binding.case_id,
        candidate_build_id=authorization.candidate_build_id,
        candidate_manifest_sha256=authorization.candidate_manifest_sha256,
        job_id=str(job["id"]),
        answer_version_id=answer_id,
        answer_sha256=answer_sha,
        requested_word_target=case.word_target,
        word_count=int(answer["word_count"]),
        evidence_bundle=evidence_bundle,
        source_release_report_sha256=report.seal_sha256,
        gate_implementation_sha256=report.gate_implementation_sha256,
        passed_gates=gate_inputs,
    )
    release = seal_owner_canary_release_attestation(
        answer_artifact_id=answer_id,
        runtime_release_state=cast(Any, release_state),
        evidence_bundle=evidence_bundle,
        deterministic_gate_report=gate_report,
    )
    result_id = (
        "owner-attempt-"
        + hashlib.sha256(
            f"{binding.run_id}\0{binding.case_id}\0{binding.attempt_number}\0{job['id']}\0{answer_id}".encode()
        ).hexdigest()[:32]
    )
    result = seal_owner_canary_case_result(
        result_id=result_id,
        run_id=binding.run_id,
        authorization_seal_sha256=authorization.seal_sha256,
        canary_manifest_seal_sha256=manifest.seal_sha256,
        case_id=binding.case_id,
        attempt_number=binding.attempt_number,
        input_revision_sha256=binding.input_revision_sha256,
        candidate_build_id=authorization.candidate_build_id,
        candidate_manifest_sha256=authorization.candidate_manifest_sha256,
        job_id=str(job["id"]),
        answer_version_id=answer_id,
        answer_artifact_id=answer_id,
        released=True,
        answer_sha256=answer_sha,
        word_count=int(answer["word_count"]),
        ai_review=review,
        ai_adjudication=adjudication,
        standards_report=standards,
        evidence_bundle=evidence_bundle,
        deterministic_gate_report=gate_report,
        release_attestation=release,
    )
    envelope_material: dict[str, Any] = {
        "schema": OWNER_CANARY_RUNTIME_ENVELOPE_SCHEMA,
        "runtime_report": report.model_dump(mode="json", by_alias=True),
        "attempt_result": result.model_dump(mode="json", by_alias=True),
    }
    envelope_material["seal_sha256"] = sealed_sha256(envelope_material)
    return OwnerCanaryRuntimeAttemptEnvelope.model_validate(envelope_material)


def verify_owner_canary_runtime_content_graph(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    binding: OwnerCanaryAdmissionBinding,
    answer_id: str,
    publication_phase: Literal["pre_release", "released"],
    connection: sqlite3.Connection | None = None,
) -> tuple[VerifiedOwnerCanaryContentGraph, OwnerCanaryRuntimeAttemptEnvelope]:
    """Verify graph A, the shared semantic core, then identical graph B."""

    def verify_in_snapshot(
        active_connection: sqlite3.Connection,
        snapshot_database: Database,
    ) -> tuple[VerifiedOwnerCanaryContentGraph, OwnerCanaryRuntimeAttemptEnvelope]:
        job = active_connection.execute(
            "SELECT id FROM jobs WHERE evaluation_run_id=? AND evaluation_case_id=?",
            (binding.run_id, binding.case_id),
        ).fetchall()
        if len(job) != 1:
            raise RuntimeError("owner_canary_content_graph_job_identity_invalid")
        job_id = str(job[0]["id"])
        before = capture_owner_canary_content_graph(
            active_connection,
            job_id=job_id,
            answer_id=answer_id,
            candidate_build_id=binding.candidate_build_id,
            case_id=binding.case_id,
            as_of_date=binding.as_of_date,
        )
        envelope = _verify_owner_canary_runtime_semantic_core(
            settings=settings,
            database=snapshot_database,
            cipher=cipher,
            binding=binding,
            answer_id=answer_id,
            publication_phase=publication_phase,
        )
        after = capture_owner_canary_content_graph(
            active_connection,
            job_id=job_id,
            answer_id=answer_id,
            candidate_build_id=binding.candidate_build_id,
            case_id=binding.case_id,
            as_of_date=binding.as_of_date,
        )
        if before != after:
            raise RuntimeError("owner_canary_content_graph_changed_during_semantic_replay")
        if before.row_count < 3 or before.answer_id != answer_id:
            raise RuntimeError("owner_canary_content_graph_incomplete")
        review = envelope.attempt_result.ai_review
        standards = envelope.attempt_result.standards_report
        evidence_bundle = envelope.attempt_result.evidence_bundle
        if review is None or standards is None or evidence_bundle is None:
            raise RuntimeError("owner_canary_content_graph_semantic_result_incomplete")
        stage_attempts = active_connection.execute(
            """
            SELECT id,stage_key,status FROM job_stage_attempts
            WHERE job_id=? AND (stage_key='draft' OR stage_key GLOB 'repair-[0-9][0-9]')
            ORDER BY stage_key,section_key,attempt_number,id
            """,
            (job_id,),
        ).fetchall()
        complete_stage_attempts = tuple(
            row for row in stage_attempts if row["status"] == "complete"
        )
        if not complete_stage_attempts:
            raise RuntimeError("owner_canary_model_stage_attempt_lineage_incomplete")
        stage_attempt_ids = tuple(str(row["id"]) for row in complete_stage_attempts)
        runtime_object_rows = active_connection.execute(
            """
            SELECT DISTINCT ro.relative_path
            FROM runtime_objects ro
            WHERE ro.object_key IN (
              SELECT output_object_key FROM job_stage_attempts
              WHERE job_id=? AND output_object_key IS NOT NULL
              UNION
              SELECT object_key FROM evidence_packs
              WHERE job_id=? AND object_key IS NOT NULL
            )
            ORDER BY ro.relative_path
            """,
            (job_id, job_id),
        ).fetchall()
        runtime_object_relative_paths = tuple(
            str(row["relative_path"]) for row in runtime_object_rows
        )
        candidate_status_rows = active_connection.execute(
            "SELECT status FROM index_builds WHERE id=?",
            (binding.candidate_build_id,),
        ).fetchall()
        if (
            len(candidate_status_rows) != 1
            or len(runtime_object_relative_paths) < 2
            or len(runtime_object_relative_paths) != len(set(runtime_object_relative_paths))
        ):
            raise RuntimeError("owner_canary_content_graph_runtime_identity_incomplete")
        ai_invocation_ids = tuple(review.invocation_ids)
        capability = VerifiedOwnerCanaryContentGraph(
            graph_sha256=before.graph_sha256,
            answer_sha256=envelope.runtime_report.answer_sha256,
            job_id=job_id,
            answer_id=answer_id,
            row_count=before.row_count,
            release_state=envelope.runtime_report.runtime_release_state,
            word_count=envelope.runtime_report.word_count,
            material_claim_count=review.material_claim_count,
            evidence_span_count=len(evidence_bundle.evidence_span_ids),
            all_material_claims_evidence_bound=all(
                bool(item.evidence_span_ids) for item in review.claims
            ),
            standards_avoidance_passed=standards.avoidance_passed,
            ai_review_invocation_ids_sha256=sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-ai-review-invocation-set.v1",
                    "invocation_ids": list(ai_invocation_ids),
                }
            ),
            ai_review_invocation_count=len(ai_invocation_ids),
            model_stage_attempt_ids_sha256=sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-model-stage-attempt-set.v1",
                    "stage_attempt_ids": list(stage_attempt_ids),
                }
            ),
            model_stage_attempt_count=len(stage_attempt_ids),
            runtime_object_relative_paths_sha256=sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-runtime-object-relative-path-set.v1",
                    "relative_paths": list(runtime_object_relative_paths),
                }
            ),
            runtime_object_count=len(runtime_object_relative_paths),
            _runtime_object_relative_paths=runtime_object_relative_paths,
            _candidate_catalogue_status=str(candidate_status_rows[0]["status"] or ""),
            _token=_VERIFIED_OWNER_CANARY_CONTENT_GRAPH_TOKEN,
        )
        if publication_phase == "released":
            outbox = active_connection.execute(
                "SELECT * FROM release_outbox WHERE job_id=? ORDER BY id", (job_id,)
            ).fetchall()
            if (
                len(outbox) != 1
                or outbox[0]["answer_id"] != answer_id
                or outbox[0]["owner_canary_content_graph_sha256"] != capability.graph_sha256
                or outbox[0]["answer_sha256"] != capability.answer_sha256
            ):
                raise RuntimeError("owner_canary_released_content_binding_invalid")
        return capability, envelope

    if connection is not None:
        return verify_in_snapshot(connection, database.snapshot_view(connection))
    with database.detached_read_snapshot() as (snapshot_database, snapshot_connection):
        return verify_in_snapshot(snapshot_connection, snapshot_database)


def require_owner_canary_content_graph_current(
    connection: sqlite3.Connection,
    *,
    capability: object,
    candidate_build_id: str,
    case_id: str,
    as_of_date: date,
    job_id: str,
    answer_id: str,
) -> VerifiedOwnerCanaryContentGraph:
    """Recompute the bounded graph in an existing atomic transaction."""

    verified = require_verified_owner_canary_content_graph(capability)
    if verified.job_id != job_id or verified.answer_id != answer_id:
        raise RuntimeError("owner_canary_content_graph_release_identity_changed")
    current = capture_owner_canary_content_graph(
        connection,
        job_id=job_id,
        answer_id=answer_id,
        candidate_build_id=candidate_build_id,
        case_id=case_id,
        as_of_date=as_of_date,
    )
    candidate_status = connection.execute(
        "SELECT status FROM index_builds WHERE id=?", (candidate_build_id,)
    ).fetchall()
    if (
        current.graph_sha256 != verified.graph_sha256
        or current.row_count != verified.row_count
        or len(candidate_status) != 1
        or str(candidate_status[0]["status"] or "") != verified._candidate_catalogue_status
    ):
        raise RuntimeError("owner_canary_content_graph_changed_before_release")
    return verified


def build_owner_canary_runtime_attempt_envelope(
    *,
    settings: Settings,
    database: Database,
    cipher: LocalCipher,
    binding: OwnerCanaryAdmissionBinding,
    answer_id: str,
) -> OwnerCanaryRuntimeAttemptEnvelope:
    """Project one released durable answer through the shared exact verifier."""

    _capability, envelope = verify_owner_canary_runtime_content_graph(
        settings=settings,
        database=database,
        cipher=cipher,
        binding=binding,
        answer_id=answer_id,
        publication_phase="released",
    )
    return envelope


class OwnerCanaryHTTPClient(Protocol):
    def get(self, url: str, **kwargs: Any) -> Any: ...

    def post(self, url: str, **kwargs: Any) -> Any: ...


class OwnerQualityHTTPRuntimeAdapter:
    """Real callback implementation backed only by the localhost answer API."""

    def __init__(
        self,
        *,
        client: OwnerCanaryHTTPClient,
        base_url: str,
        review_date: date,
        authorization: OwnerCanaryAuthorization,
        manifest: OwnerQualityCanaryManifest,
        bundle: LiveEvaluationBundle,
        workspace: CanaryReviewWorkspace,
        legal_date: date,
        completion_ceiling_seconds_by_case: Mapping[str, float],
        poll_interval_seconds: float,
        case_timeout_seconds: float,
        settings: Settings,
        database: Database,
        cipher: LocalCipher,
        synthetic_non_authoritative: bool,
    ) -> None:
        self.client = client
        self.base_url = _normal_base_url(base_url)
        self.review_date = review_date
        self.authorization = authorization
        self.manifest = manifest
        self.bundle = bundle
        self.workspace = workspace
        self.legal_date = legal_date
        self.settings = settings
        self.database = database
        self.cipher = cipher
        self.synthetic_non_authoritative = synthetic_non_authoritative
        if synthetic_non_authoritative and not settings.test_mode:
            raise ValueError("synthetic owner-canary adapter requires explicit test mode")
        ceilings = {
            str(case_id): float(seconds)
            for case_id, seconds in completion_ceiling_seconds_by_case.items()
        }
        if set(ceilings) != set(authorization.authorized_case_ids) or any(
            not math.isfinite(seconds) or seconds <= 0 for seconds in ceilings.values()
        ):
            raise ValueError("owner-canary completion ceilings are incomplete or invalid")
        self.completion_ceiling_seconds_by_case = ceilings
        self.poll_interval_seconds = max(0.01, poll_interval_seconds)
        self.case_timeout_seconds = max(1.0, case_timeout_seconds)
        self._answers: dict[str, bytes] = {}
        self._runtime_identity: tuple[str, ...] | None = None

    def verify_health(self) -> None:
        health = _safe_json(self.client.get(f"{self.base_url}/api/v1/health"), expected=(200,))
        identity = (
            str(health.get("model_id") or ""),
            str(health.get("prompt_version") or ""),
            str(health.get("router_version") or ""),
            str(health.get("classifier_version") or ""),
            str(health.get("policy_sha256") or ""),
            str(health.get("assessment_bundle_sha256") or ""),
        )
        if (
            health.get("worker_ready") is not True
            or health.get("model_ready") is not True
            or identity
            != (
                self.settings.model_id,
                PROMPT_VERSION,
                ROUTER_VERSION,
                CLASSIFIER_VERSION,
                POLICY_SHA256,
                OWNER_ASSESSMENT_BUNDLE.sha256,
            )
        ):
            raise RuntimeError("localhost model/worker identities are not owner-canary ready")
        self._runtime_identity = identity

    def _headers(self, request: OwnerCanaryAttemptRequest) -> dict[str, str]:
        return {
            "X-Owner-Canary-Review-Date": self.review_date.isoformat(),
            "X-Owner-Canary-Lane": self.authorization.lane,
            "X-Owner-Canary-Run-ID": request.run_id,
            "X-Owner-Canary-Case-ID": request.case_id,
            "X-Owner-Canary-Attempt": str(request.attempt_number),
            "X-Owner-Canary-Input-Revision": request.input_revision_sha256,
            "X-Owner-Canary-Request-Seal": request.seal_sha256,
            "X-Idempotency-Key": owner_canary_idempotency_key(request.seal_sha256),
        }

    def execute_attempt(self, request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        if self._runtime_identity is None:
            raise RuntimeError("owner-canary runtime health was not verified")
        if request.attempt_number != 1:
            raise RuntimeError(
                "owner-canary whole-answer resubmission is forbidden; use a new run identity"
            )
        case = self.bundle.registry.case(request.case_id)
        headers = self._headers(request)
        payload = QuestionRequest(
            question=case.question,
            task_type=TaskType(case.task_type),
            jurisdiction=case.jurisdiction,
            as_of_date=self.legal_date,
            word_target=case.word_target,
            online_mode=OnlineMode.LOCAL_ONLY,
            upload_ids=[],
        )
        accepted = _safe_json(
            self.client.post(
                f"{self.base_url}/api/v1/questions",
                headers=headers,
                json=payload.model_dump(mode="json"),
            ),
            expected=(202,),
        )
        job_id = str(accepted.get("job_id") or "")
        if not job_id:
            raise RuntimeError("owner-canary admission omitted job identity")
        deadline = time.monotonic() + min(
            self.case_timeout_seconds,
            self.completion_ceiling_seconds_by_case[request.case_id],
        )
        terminal: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            observed = _safe_json(
                self.client.get(
                    f"{self.base_url}/api/v1/jobs/{job_id}",
                    headers=headers,
                ),
                expected=(200,),
            )
            if str(observed.get("status") or "") in _TERMINAL_JOB_STATES:
                terminal = observed
                break
            time.sleep(self.poll_interval_seconds)
        if terminal is None:
            _safe_json(
                self.client.post(f"{self.base_url}/api/v1/jobs/{job_id}/cancel"),
                expected=(200, 202),
            )
            cancellation_deadline = time.monotonic() + 30.0
            while time.monotonic() < cancellation_deadline:
                stopped = _safe_json(
                    self.client.get(
                        f"{self.base_url}/api/v1/jobs/{job_id}",
                        headers=headers,
                    ),
                    expected=(200,),
                )
                if str(stopped.get("status") or "") == "cancelled":
                    terminal = stopped
                    break
                if str(stopped.get("status") or "") in _TERMINAL_JOB_STATES:
                    raise RuntimeError(
                        "owner-canary timeout did not terminate as a confirmed cancellation"
                    )
                time.sleep(self.poll_interval_seconds)
            if terminal is None:
                raise RuntimeError("owner-canary cancellation confirmation timed out")
            durable = self.database.job(job_id)
            if (
                durable is None
                or str(durable["status"] or "") != "cancelled"
                or durable["answer_id"] is not None
                or durable["release_state"] is not None
                or self.database.released_outbox_for_job(job_id) is not None
            ):
                raise RuntimeError("owner-canary cancellation left releasable durable state")
            return self._nonrelease(request, job_id=job_id, code="owner_canary_poll_timeout")
        if (
            terminal.get("pinned_index_build_id") != self.authorization.candidate_build_id
            or terminal.get("evaluation_request_sha256") is None
        ):
            raise RuntimeError("owner-canary terminal job differs from candidate pin")
        answer_id = str(terminal.get("answer_id") or "")
        if terminal.get("status") != "complete" or not answer_id:
            return self._nonrelease(
                request,
                job_id=job_id,
                code="owner_canary_runtime_nonrelease",
            )
        envelope_value = _safe_json(
            self.client.get(
                f"{self.base_url}/api/v1/owner-canary/answers/{answer_id}/attempt-result",
                headers=headers,
            ),
            expected=(200,),
        )
        envelope = OwnerCanaryRuntimeAttemptEnvelope.model_validate(envelope_value)
        if envelope.attempt_result.job_id != job_id:
            raise RuntimeError("owner-canary runtime result belongs to another job")
        answer = _safe_json(
            self.client.get(
                f"{self.base_url}/api/v1/answers/{answer_id}",
                headers=headers,
            ),
            expected=(200,),
        )
        content = answer.get("content")
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("owner-canary released answer content is missing")
        raw = content.encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != envelope.attempt_result.answer_sha256:
            raise RuntimeError("owner-canary released answer differs from attempt result")
        if self.synthetic_non_authoritative:
            if (
                envelope.runtime_report.authoritative_db_projection
                or not envelope.runtime_report.synthetic_non_authoritative
            ):
                raise RuntimeError("synthetic owner-canary result has an invalid authority marker")
        else:
            binding = validate_owner_canary_api_admission(
                settings=self.settings,
                database=self.database,
                review_date=self.review_date,
                run_id=request.run_id,
                lane=self.authorization.lane,
                case_id=request.case_id,
                attempt_number=request.attempt_number,
                input_revision_sha256=request.input_revision_sha256,
                attempt_request_seal_sha256=request.seal_sha256,
                raw_idempotency_key=headers["X-Idempotency-Key"],
                payload=payload,
            )
            local_envelope = build_owner_canary_runtime_attempt_envelope(
                settings=self.settings,
                database=self.database,
                cipher=self.cipher,
                binding=binding,
                answer_id=answer_id,
            )
            if local_envelope != envelope:
                raise RuntimeError("loopback envelope differs from local durable projection")
            if (
                not envelope.runtime_report.authoritative_db_projection
                or envelope.runtime_report.synthetic_non_authoritative
                or envelope.runtime_report.configured_model_id != PINNED_RUNTIME_REPO
                or envelope.runtime_report.answer_model_version != PINNED_RUNTIME_MODEL_VERSION
            ):
                raise RuntimeError("owner-canary durable runtime authority is not exact")
        runtime_identity = (
            str(envelope.runtime_report.configured_model_id),
            envelope.runtime_report.prompt_version,
            envelope.runtime_report.router_version,
            envelope.runtime_report.classifier_version,
            envelope.runtime_report.policy_sha256,
            envelope.runtime_report.assessment_bundle_sha256,
        )
        if runtime_identity != self._runtime_identity:
            raise RuntimeError("owner-canary runtime identities changed after health check")
        self.workspace.write_safe_json(
            category="safe-metrics",
            filename=f"{request.case_id}-runtime-attempt-{request.attempt_number}.json",
            value=envelope.runtime_report.model_dump(mode="json", by_alias=True),
        )
        artifact_id = envelope.attempt_result.answer_artifact_id
        if artifact_id is None:
            raise RuntimeError("owner-canary released result omitted its answer artifact")
        self._answers[artifact_id] = raw
        return envelope.attempt_result

    def _nonrelease(
        self, request: OwnerCanaryAttemptRequest, *, job_id: str, code: str
    ) -> OwnerCanaryCaseAttemptResult:
        return seal_owner_canary_case_result(
            result_id="owner-attempt-"
            + hashlib.sha256(f"{request.seal_sha256}\0{job_id}\0{code}".encode()).hexdigest()[:32],
            run_id=request.run_id,
            authorization_seal_sha256=request.authorization_seal_sha256,
            canary_manifest_seal_sha256=request.canary_manifest_seal_sha256,
            case_id=request.case_id,
            attempt_number=request.attempt_number,
            input_revision_sha256=request.input_revision_sha256,
            candidate_build_id=self.authorization.candidate_build_id,
            candidate_manifest_sha256=self.authorization.candidate_manifest_sha256,
            job_id=job_id,
            released=False,
            worker_hard_failure_code=code,
            failure_reason_codes=(code,),
        )

    def load_answer(self, answer_artifact_id: str) -> bytes:
        try:
            return self._answers[answer_artifact_id]
        except KeyError as exc:
            raise ValueError(
                "owner-canary answer artifact was not captured by this runtime"
            ) from exc


class OwnerQualityDirectRuntimeAdapter:
    """Authoritative in-process production adapter under one owned model session.

    The legacy HTTP adapter remains useful only for explicitly synthetic tests.
    Authoritative 30/30 execution admits the exact production job contract,
    executes the real ``AnswerRunner`` in this verified controller process, and
    relies on the DB-held owned-runtime frontier at the atomic release boundary.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        database: Database,
        cipher: LocalCipher,
        review_date: date,
        legal_date: date,
        authorization: OwnerCanaryAuthorization,
        manifest: OwnerQualityCanaryManifest,
        bundle: LiveEvaluationBundle,
        workspace: CanaryReviewWorkspace,
        owned_runtime: OwnerCanaryOwnedModelRuntime,
        completion_ceiling_seconds_by_case: Mapping[str, float],
    ) -> None:
        if settings.test_mode:
            raise RuntimeError("authoritative owner canary refuses test mode")
        self.settings = settings
        self.database = database
        self.cipher = cipher
        self.review_date = review_date
        self.legal_date = legal_date
        self.authorization = authorization
        self.manifest = manifest
        self.bundle = bundle
        self.workspace = workspace
        self.owned_runtime = owned_runtime
        self.completion_ceiling_seconds_by_case = {
            str(case_id): float(seconds)
            for case_id, seconds in completion_ceiling_seconds_by_case.items()
        }
        if set(self.completion_ceiling_seconds_by_case) != set(
            authorization.authorized_case_ids
        ) or any(
            not math.isfinite(value) or value <= 0
            for value in self.completion_ceiling_seconds_by_case.values()
        ):
            raise ValueError("owner-canary completion ceilings are incomplete")
        factory = PinnedRetrieverFactory(settings, database)
        pinned = factory.for_build(authorization.candidate_build_id)
        self._retriever = pinned
        self._runner = AnswerRunner(
            settings=settings,
            database=database,
            cipher=cipher,
            retriever=pinned,
            model=LoopbackModelGateway(settings),
            observability=None,
            retriever_factory=factory,
        )
        self._answers: dict[str, bytes] = {}

    def execute_attempt(self, request: OwnerCanaryAttemptRequest) -> OwnerCanaryCaseAttemptResult:
        if request.attempt_number != 1:
            raise RuntimeError("owner-canary whole-answer retry is forbidden")
        before = self.owned_runtime.before_case(request.case_id)
        case = self.bundle.registry.case(request.case_id)
        payload = QuestionRequest(
            question=case.question,
            task_type=TaskType(case.task_type),
            jurisdiction=case.jurisdiction,
            as_of_date=self.legal_date,
            word_target=case.word_target,
            online_mode=OnlineMode.LOCAL_ONLY,
            upload_ids=[],
        )
        binding = validate_owner_canary_api_admission(
            settings=self.settings,
            database=self.database,
            review_date=self.review_date,
            run_id=request.run_id,
            lane=self.authorization.lane,
            case_id=request.case_id,
            attempt_number=request.attempt_number,
            input_revision_sha256=request.input_revision_sha256,
            attempt_request_seal_sha256=request.seal_sha256,
            raw_idempotency_key=owner_canary_idempotency_key(request.seal_sha256),
            payload=payload,
        )
        if (
            binding.owned_runtime_before_checkpoint_sha256 != before.seal_sha256
            or binding.owned_runtime_frontier_generation != before.frontier_generation
        ):
            raise RuntimeError("owner-canary active frontier changed before admission")
        from ..jobs import deadline_after, policy_for
        from .evaluation_job_authority import build_evaluation_job_authority

        authority = build_evaluation_job_authority(binding)
        task_type = classify_task(payload.question, payload.task_type)
        route = decide_route(payload.question, payload.word_target, task_type)
        if route.route.value != case.expected_research_route:
            raise RuntimeError("owner-canary direct runtime route changed")
        job_id = "owner-canary-job-" + hashlib.sha256(request.seal_sha256.encode()).hexdigest()[:32]
        if self.database.job_by_evaluation_binding(request.run_id, request.case_id) is not None:
            raise RuntimeError("owner-canary direct runtime case is not create-only")
        answer_policy = policy_for(JobType.ANSWER)
        ceiling = math.ceil(self.completion_ceiling_seconds_by_case[request.case_id])
        controller_worker_id = self.database.create_job(
            job_id=job_id,
            encrypted_question=self.cipher.encrypt_text(payload.question),
            question_summary="Private encrypted question",
            request=payload.model_dump(mode="json", exclude={"question"}),
            route=route.route,
            route_reasons=route.reasons,
            idempotency_key=owner_canary_idempotency_key(request.seal_sha256),
            pinned_index_build_id=self.authorization.candidate_build_id,
            job_type=JobType.ANSWER,
            queue_wait_deadline_at=deadline_after(answer_policy.queue_wait_seconds),
            workflow_deadline_at=deadline_after(ceiling),
            model_call_deadline_at=None,
            evaluation_run_id=request.run_id,
            evaluation_case_id=request.case_id,
            evaluation_request_sha256=binding.request_sha256,
            evaluation_authority=authority,
            trace_full_retention=True,
            word_target=payload.word_target,
            owner_canary_controller_claim={
                "controller_pid": os.getpid(),
                "before_checkpoint_sha256": before.seal_sha256,
                "frontier_generation": before.frontier_generation,
                "lease_seconds": min(12 * 60 * 60, ceiling + 120),
            },
        )
        if controller_worker_id is None:
            raise RuntimeError("owner-canary controller job claim was not created")
        try:
            asyncio.run(
                run_bounded_direct_answer(
                    database=self.database,
                    job_id=job_id,
                    execute=lambda: self._runner.run(job_id, raise_on_error=True),
                    expected_lease_owner=controller_worker_id,
                )
            )
        except Exception as exc:
            self.owned_runtime.assert_active_case(request.case_id)
            failed = self.database.job(job_id)
            if (
                failed is None
                or str(failed["status"]) not in {"system_error", "cancelled", "failed", "dlq"}
                or failed["answer_id"] is not None
                or failed["release_state"] is not None
                or self.database.released_outbox_for_job(job_id) is not None
            ):
                raise RuntimeError("owner-canary direct controller did not fail closed") from exc
            code = str(
                failed["terminal_reason_code"]
                or failed["error_code"]
                or getattr(exc, "reason_code", "")
                or "owner_canary_runtime_nonrelease"
            )
            if re.fullmatch(r"[a-z0-9_]{1,120}", code) is None:
                code = "owner_canary_runtime_nonrelease"
            return self._nonrelease(request, job_id=job_id, code=code)
        self.owned_runtime.assert_active_case(request.case_id)
        job = self.database.job(job_id)
        if job is None or job["status"] != "complete" or job["answer_id"] in (None, ""):
            return self._nonrelease(
                request,
                job_id=job_id,
                code="owner_canary_runtime_nonrelease",
            )
        answer_id = str(job["answer_id"])
        envelope = build_owner_canary_runtime_attempt_envelope(
            settings=self.settings,
            database=self.database,
            cipher=self.cipher,
            binding=binding,
            answer_id=answer_id,
        )
        if (
            envelope.runtime_report.owned_runtime_start_attestation_sha256
            != before.start_attestation_sha256
            or envelope.runtime_report.owned_runtime_instance_sha256
            != before.runtime_instance_sha256
            or envelope.runtime_report.owned_runtime_before_checkpoint_sha256 != before.seal_sha256
            or envelope.runtime_report.runtime_release_state != "verified_full"
            or envelope.attempt_result.standards_report is None
            or not envelope.attempt_result.standards_report.avoidance_passed
        ):
            raise RuntimeError("owner-canary direct runtime report is not release-safe")
        answer = self.database.answer(answer_id)
        if answer is None:
            raise RuntimeError("owner-canary direct runtime answer disappeared")
        self.owned_runtime.assert_active_case(request.case_id)
        raw = self.cipher.decrypt_text(bytes(answer["encrypted_content"])).encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != envelope.attempt_result.answer_sha256:
            raise RuntimeError("owner-canary direct runtime answer digest differs")
        self.workspace.write_safe_json(
            category="safe-metrics",
            filename=f"{request.case_id}-runtime-attempt-1.json",
            value=envelope.runtime_report.model_dump(mode="json", by_alias=True),
        )
        artifact_id = envelope.attempt_result.answer_artifact_id
        if artifact_id is None:
            raise RuntimeError("owner-canary direct runtime answer artifact is missing")
        self._answers[artifact_id] = raw
        return envelope.attempt_result

    def _nonrelease(
        self, request: OwnerCanaryAttemptRequest, *, job_id: str, code: str
    ) -> OwnerCanaryCaseAttemptResult:
        return seal_owner_canary_case_result(
            result_id="owner-direct-nonrelease-"
            + hashlib.sha256(f"{request.seal_sha256}\0{job_id}\0{code}".encode()).hexdigest()[:32],
            run_id=request.run_id,
            authorization_seal_sha256=request.authorization_seal_sha256,
            canary_manifest_seal_sha256=request.canary_manifest_seal_sha256,
            case_id=request.case_id,
            attempt_number=request.attempt_number,
            input_revision_sha256=request.input_revision_sha256,
            candidate_build_id=self.authorization.candidate_build_id,
            candidate_manifest_sha256=self.authorization.candidate_manifest_sha256,
            job_id=job_id,
            released=False,
            worker_hard_failure_code=code,
            failure_reason_codes=(code,),
        )

    def mark_projected(self, case_id: str) -> OwnerCanaryOwnedRuntimeCheckpoint:
        """Advance DB frontier only after the readable projection has passed."""

        return self.owned_runtime.after_case(case_id)

    def load_answer(self, answer_artifact_id: str) -> bytes:
        try:
            return self._answers[answer_artifact_id]
        except KeyError as exc:
            raise ValueError("owner-canary answer was not captured in this session") from exc

    def close(self) -> None:
        close = getattr(self._retriever, "close", None)
        if callable(close):
            close()


def owner_canary_initial_input_revisions(
    *, authorization: OwnerCanaryAuthorization, manifest: OwnerQualityCanaryManifest
) -> dict[str, str]:
    return {
        case_id: sealed_sha256(
            {
                "schema": "legalbot.owner-canary-initial-input-revision.v1",
                "authorization_seal_sha256": authorization.seal_sha256,
                "canary_manifest_seal_sha256": manifest.seal_sha256,
                "candidate_build_id": authorization.candidate_build_id,
                "candidate_manifest_sha256": authorization.candidate_manifest_sha256,
                "case_id": case_id,
                "retry_policy_sha256": authorization.policy_bindings.retry_policy_sha256,
            }
        )
        for case_id in authorization.authorized_case_ids
    }


def _execute_owner_quality_canary_with_client(
    *,
    settings: Settings,
    cipher: LocalCipher,
    manifest_path: Path,
    qualification_path: Path,
    authorization_path: Path,
    review_date: date,
    legal_date: date,
    base_url: str,
    client: OwnerCanaryHTTPClient,
    expert_qualification_path: Path | None = None,
    gap_inventory_by_case: Mapping[str, Sequence[OwnerCanaryGapDisposition | Mapping[str, Any]]]
    | None = None,
    poll_interval_seconds: float = 2.0,
    case_timeout_seconds: float = 10_800.0,
    synthetic_non_authoritative: bool = False,
) -> OwnerCanaryReviewExecution:
    """Drive the complete owner-quality lane without an injected case callback."""

    authoritative_review_root: Path | None = None
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    database = Database(settings.database_path)
    database.initialize()
    try:
        if synthetic_non_authoritative and not settings.test_mode:
            raise ValueError("synthetic owner-canary transport requires explicit test mode")
        manifest_hint = _load_json_object(manifest_path, label="owner-canary sample manifest")
        candidate_build_id = str(manifest_hint.get("candidate_build_id") or "")
        candidate = load_sealed_candidate_identity(
            settings=settings,
            database=database,
            candidate_build_id=candidate_build_id,
        )
        manifest = load_verified_owner_quality_canary_manifest(
            manifest_path,
            bundle=bundle,
            candidate=candidate,
            qualification_path=qualification_path,
        )
        authorization = load_owner_canary_authorization(authorization_path, manifest=manifest)
        authoritative_review_root = (
            settings.canary_review_root
            if synthetic_non_authoritative
            else require_authoritative_canary_output_root(settings, authorization.lane)
        )
        authoritative_gaps: dict[str, tuple[OwnerCanaryGapDisposition, ...]] | None = None
        ai_review_batch: VerifiedAll60AIReviewBatch | None = None
        if not synthetic_non_authoritative:
            _require_clean_authorized_integration(settings=settings, authorization=authorization)
            if expert_qualification_path is None:
                raise ValueError("authoritative owner canary requires all-60 replay evidence")
            supplied_qualification = ExactAll60Qualification.model_validate_json(
                qualification_path.read_bytes()
            )
            from .live_suite_path_b import load_default_v2_repair

            expert = load_suite_expert_qualification(
                expert_qualification_path,
                bundle=bundle,
                index_build_id=candidate.build_id,
                as_of_date=supplied_qualification.as_of_date,
                catalog_path=settings.database_path,
                repair=load_default_v2_repair(settings.project_root),
            )
            ai_review_batch = load_verified_all60_batch_for_owner_runtime(
                settings=settings,
                bundle=bundle,
                candidate=candidate,
                expert=expert,
                qualification=supplied_qualification,
                integration_sha=authorization.integration_sha,
                evaluation_root=settings.evaluation_dir,
            )
            replayed = load_replayed_exact_all60_qualification(
                qualification_path,
                bundle=bundle,
                candidate=candidate,
                candidate_build_root=settings.index_dir / "builds" / candidate.build_id,
                expert_qualification_path=expert_qualification_path,
                ai_review_batch=ai_review_batch,
                catalog_path=settings.database_path,
                project_root=settings.project_root,
                integration_sha=authorization.integration_sha,
            )
            if replayed.seal_sha256 != manifest.qualification_seal_sha256:
                raise ValueError("owner-canary manifest differs from replayed all-60 evidence")
            if expert.as_of_date != replayed.as_of_date:
                raise ValueError("owner-canary expert currentness date differs")
            replay_authorization_stage_a(
                settings=settings,
                authorization=authorization,
                bundle=bundle,
                candidate=candidate,
                qualification=replayed,
                expert_qualification=expert,
            )
            authoritative_gaps = derive_owner_canary_gap_inventory(
                database=database,
                authorization=authorization,
                bundle=bundle,
                qualification=replayed,
            )
            material_gap_statuses = {
                item.status
                for values in authoritative_gaps.values()
                for item in values
                if item.material and item.status != "resolved_in_candidate"
            }
            if "owner_decision_required" in material_gap_statuses:
                raise OwnerDecisionRequired("owner_canary_material_gap_owner_decision_required")
            if "staged_official_material" in material_gap_statuses:
                raise OwnerDecisionRequired(
                    "owner_canary_staged_material_candidate_rebuild_required"
                )
        _verify_lane_runtime_prerequisites(
            settings=settings,
            database=database,
            manifest=manifest,
            authorization=authorization,
            synthetic_non_authoritative=synthetic_non_authoritative,
            require_owned_runtime=False,
        )
        workspace = create_canary_review_workspace(
            project_root=settings.project_root,
            review_root=authoritative_review_root,
            review_date=review_date,
            run_id=authorization.run_id,
            lane=authorization.lane,
            canary_manifest=manifest,
            runtime_run_manifest_sha256=authorization.seal_sha256,
        )
        register_owner_canary_runtime_authorization(
            settings=settings,
            workspace=workspace,
            manifest=manifest,
            authorization_path=authorization_path,
            qualification_path=qualification_path,
            expert_qualification_path=expert_qualification_path,
            ai_review_batch=ai_review_batch,
            synthetic_non_authoritative=synthetic_non_authoritative,
        )
        slo_policy = load_slo_policy(settings.observability_slo_path)
        ceilings = {
            case_id: float(
                slo_policy.band_for(
                    route=bundle.registry.case(case_id).expected_research_route,
                    word_target=bundle.registry.case(case_id).word_target,
                ).targets_p95_seconds["completion_seconds"]
            )
            for case_id in authorization.authorized_case_ids
        }
        owned_runtime: OwnerCanaryOwnedModelRuntime | None = None
        direct_adapter: OwnerQualityDirectRuntimeAdapter | None = None
        http_adapter: OwnerQualityHTTPRuntimeAdapter | None = None
        if synthetic_non_authoritative:
            gaps = gap_inventory_by_case or {
                case_id: () for case_id in authorization.authorized_case_ids
            }
        else:
            if gap_inventory_by_case is not None or authoritative_gaps is None:
                raise ValueError(
                    "authoritative owner canary gap inventory must be derived from durable state"
                )
            gaps = authoritative_gaps
        if synthetic_non_authoritative:
            http_adapter = OwnerQualityHTTPRuntimeAdapter(
                client=client,
                base_url=base_url,
                review_date=review_date,
                authorization=authorization,
                manifest=manifest,
                bundle=bundle,
                workspace=workspace,
                legal_date=legal_date,
                completion_ceiling_seconds_by_case=ceilings,
                poll_interval_seconds=poll_interval_seconds,
                case_timeout_seconds=case_timeout_seconds,
                settings=settings,
                database=database,
                cipher=cipher,
                synthetic_non_authoritative=True,
            )
            http_adapter.verify_health()
            adapter: OwnerQualityHTTPRuntimeAdapter | OwnerQualityDirectRuntimeAdapter = (
                http_adapter
            )
        else:
            runtime_binding, memory_policy = load_owner_canary_runtime_binding_and_memory_policy(
                settings=settings,
                candidate=candidate,
                integration_sha=authorization.integration_sha,
            )
            privacy_root = require_authoritative_canary_output_root(
                settings, authorization.lane
            ).resolve(strict=True)
            privacy_root_sha256 = sealed_sha256(
                {
                    "schema": "legalbot.owner-canary-private-output-root.v1",
                    "resolved_root": str(privacy_root),
                }
            )
            owned_runtime = OwnerCanaryOwnedModelRuntime(
                settings=settings,
                workspace_root=workspace.root,
                workspace_seal_sha256=workspace.manifest.seal_sha256,
                privacy_root_sha256=privacy_root_sha256,
                run_id=authorization.run_id,
                lane=authorization.lane,
                authorization_seal_sha256=authorization.seal_sha256,
                canary_manifest_seal_sha256=manifest.seal_sha256,
                candidate=candidate,
                integration_sha=authorization.integration_sha,
                completion_preflight_result_sha256=(
                    authorization.completion_preflight_verified_result_sha256
                ),
                runtime_binding=runtime_binding,
                memory_policy=memory_policy,
                database=database,
                authorized_case_ids=authorization.authorized_case_ids,
            )
            owned_runtime.start()
            try:
                direct_adapter = OwnerQualityDirectRuntimeAdapter(
                    settings=settings,
                    database=database,
                    cipher=cipher,
                    review_date=review_date,
                    legal_date=legal_date,
                    authorization=authorization,
                    manifest=manifest,
                    bundle=bundle,
                    workspace=workspace,
                    owned_runtime=owned_runtime,
                    completion_ceiling_seconds_by_case=ceilings,
                )
            except BaseException:
                owned_runtime.abort()
                raise
            adapter = direct_adapter
        try:
            execution = execute_owner_quality_canary_review(
                authorization=authorization,
                manifest=manifest,
                bundle=bundle,
                workspace=workspace,
                cipher=cipher,
                initial_input_revision_sha256_by_case=owner_canary_initial_input_revisions(
                    authorization=authorization, manifest=manifest
                ),
                case_callback=adapter.execute_attempt,
                answer_loader=adapter.load_answer,
                gap_inventory_by_case=gaps,
                case_projected_callback=(
                    direct_adapter.mark_projected if direct_adapter is not None else None
                ),
                owned_runtime_finalizer=(
                    owned_runtime.finish if owned_runtime is not None else None
                ),
                synthetic_non_authoritative=synthetic_non_authoritative,
            )
            if not synthetic_non_authoritative:
                _require_clean_authorized_integration(
                    settings=settings, authorization=authorization
                )
            return execution
        except BaseException:
            if owned_runtime is not None:
                owned_runtime.abort()
            raise
        finally:
            if direct_adapter is not None:
                direct_adapter.close()
            if owned_runtime is not None and not owned_runtime.ended:
                owned_runtime.abort()
    finally:
        database.close()


def execute_owner_quality_canary_with_httpx(
    *,
    settings: Settings,
    cipher: LocalCipher,
    manifest_path: Path,
    qualification_path: Path,
    expert_qualification_path: Path,
    authorization_path: Path,
    review_date: date,
    legal_date: date,
    base_url: str,
    case_timeout_seconds: float,
) -> OwnerCanaryReviewExecution:
    """Legacy HTTP transport retained only for synthetic non-authoritative tests."""

    raise OwnerDecisionRequired("authoritative_owner_canary_http_transport_non_authoritative")


class _ForbiddenOwnerCanaryHTTPClient:
    def get(self, url: str, **kwargs: Any) -> Any:
        del url, kwargs
        raise RuntimeError("authoritative owner canary cannot use ambient HTTP")

    def post(self, url: str, **kwargs: Any) -> Any:
        del url, kwargs
        raise RuntimeError("authoritative owner canary cannot use ambient HTTP")


def execute_owner_quality_canary_with_owned_runtime(
    *,
    settings: Settings,
    cipher: LocalCipher,
    manifest_path: Path,
    qualification_path: Path,
    expert_qualification_path: Path,
    authorization_path: Path,
    review_date: date,
    legal_date: date,
    case_timeout_seconds: float,
) -> OwnerCanaryReviewExecution:
    """Production entry: one controller, real runner, and one owned model sidecar."""

    # This owner-policy boundary precedes privacy-root lookup, qualification
    # replay, workspace creation, process launch, inference and output.
    require_owner_canary_exclusive_model_transport_resolution()
    return _execute_owner_quality_canary_with_client(
        settings=settings,
        cipher=cipher,
        manifest_path=manifest_path,
        qualification_path=qualification_path,
        expert_qualification_path=expert_qualification_path,
        authorization_path=authorization_path,
        review_date=review_date,
        legal_date=legal_date,
        base_url="http://127.0.0.1:8777",
        client=_ForbiddenOwnerCanaryHTTPClient(),
        case_timeout_seconds=case_timeout_seconds,
    )
