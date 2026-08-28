"""Typed contracts for the durable, staging-only research control plane."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from typing import Any


class ResearchTaskType(StrEnum):
    SOURCE_UPDATE_CHECK = "source_update_check"
    GAP_RESEARCH = "gap_research"
    BROAD_DISCOVERY = "broad_discovery"


class ResearchTrigger(StrEnum):
    ENQUIRY = "enquiry"
    SCHEDULED = "scheduled"
    MANUAL = "manual"


class ResearchPriority(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ResearchTaskStatus(StrEnum):
    STAGING_SYNC = "staging_sync"
    DEFERRED_CAPACITY = "deferred_capacity"
    QUEUED = "queued"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    REVIEW_REQUIRED = "review_required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ResearchCandidateStatus(StrEnum):
    DETECTED = "detected"
    FETCHED = "fetched"
    QUARANTINED = "quarantined"
    SYSTEM_VERIFIED = "system_verified"
    EXPERT_REVIEW = "expert_review"
    SOURCE_INTAKE_PENDING = "source_intake_pending"
    REJECTED = "rejected"


class SourceUpdateState(StrEnum):
    UNCHANGED = "unchanged"
    CHANGED = "changed"
    NEW = "new"
    WITHDRAWN = "withdrawn"
    UNKNOWN = "unknown"


class RefinementCategory(StrEnum):
    DEBUG = "debug"
    MISSING = "missing"
    ANSWER_FEEDBACK = "answer_feedback"


OWNER_DECISION_REQUIRED = "OWNER_DECISION_REQUIRED"


class GapMateriality(StrEnum):
    MATERIAL = "material"
    POTENTIALLY_MATERIAL = "potentially_material"
    NON_MATERIAL = "non_material"


@dataclass(frozen=True, slots=True)
class ResearchGapBindingRequest:
    """Privacy-safe identity plus encrypted detail for one research gap."""

    candidate_build_id: str
    case_id: str
    issue_id: str
    subject: str
    jurisdiction: str
    as_of_date: date
    retrieval_query_sha256: str
    proposition_sha256: str
    retrieval_attempt_artifact_sha256: str
    materiality: GapMateriality
    detail: str


@dataclass(frozen=True, slots=True)
class ResearchTaskRequest:
    task_type: ResearchTaskType
    trigger: ResearchTrigger
    priority: ResearchPriority
    subject: str
    jurisdiction: str
    as_of_date: date
    source_id: str | None = None
    authority_identity_id: str | None = None
    source_locator: str | None = None
    knowledge_gap_id: str | None = None
    answer_id: str | None = None
    answer_job_id: str | None = None
    refinement_id: str | None = None
    public_query: str | None = None
    query_sha256: str | None = None
    idempotency_key: str | None = None
    staging_only: bool = False


@dataclass(frozen=True, slots=True)
class ResearchCandidateDraft:
    source_id: str
    source_identity: str
    canonical_url: str
    metadata_sha256: str
    content_sha256: str | None = None
    content_object_key: str | None = None
    status: ResearchCandidateStatus = ResearchCandidateStatus.DETECTED
    rights_state: str = "unreviewed"
    safe_metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SourceUpdateDraft:
    source_id: str
    authority_identity_id: str
    comparison_state: SourceUpdateState
    baseline_version_sha256: str | None
    remote_content_sha256: str | None
    observed_active_build_id: str | None
    stale_active: bool
    scope_kind: str = "authority"
    legal_locator: str | None = None
    proposition_sha256: str | None = None
    safe_detail: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ResearchDispatchResult:
    candidates: tuple[ResearchCandidateDraft, ...] = ()
    updates: tuple[SourceUpdateDraft, ...] = ()
    requires_review: bool = True
    safe_reason: str = "official_candidate_requires_review"
    owner_decision_required: bool = False
