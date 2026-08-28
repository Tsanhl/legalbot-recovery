from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(UTC)


class TaskType(StrEnum):
    AUTO = "auto"
    ESSAY = "essay"
    PROBLEM = "problem"
    GENERAL = "general"


class OnlineMode(StrEnum):
    AUTO = "auto"
    ALWAYS = "always"
    LOCAL_ONLY = "local_only"


class AnswerRoute(StrEnum):
    DIRECT = "direct"
    SECTIONED = "sectioned"
    FULL_ENQUIRY = "full_enquiry"


class MaterialLane(StrEnum):
    PRIMARY_AUTHORITY = "primary_authority"
    OFFICIAL_SECONDARY = "official_secondary"
    SCHOLARSHIP = "scholarship"
    PRIVATE_TEACHING = "private_teaching"
    ASSESSMENT_GUIDANCE = "assessment_guidance"


class DocumentStatus(StrEnum):
    CITABLE = "citable"
    PRIVATE_TEACHING = "private_teaching"
    ASSESSMENT_GUIDANCE = "assessment_guidance"
    DUPLICATE = "duplicate"
    OCR_REQUIRED = "ocr_required"
    ENCRYPTED = "encrypted"
    UNSUPPORTED = "unsupported"
    QUARANTINED = "quarantined"


class ReviewStatus(StrEnum):
    STAGED = "staged"
    APPROVED = "approved"
    REJECTED = "rejected"


class JobType(StrEnum):
    ANSWER = "answer"
    INDEX_BUILD = "index_build"
    SCHEDULED_TASK = "scheduled_task"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    HELD = "held_for_review"
    ERROR = "system_error"
    FAILED = "failed"
    DLQ = "dlq"
    CANCELLED = "cancelled"


class IndexBuildStage(StrEnum):
    QUEUED = "queued"
    SCANNING = "scanning"
    PARSING = "parsing"
    CHUNKING = "chunking"
    EMBEDDING = "embedding"
    BUILDING_LEXICAL = "building_lexical"
    BUILDING_VECTOR = "building_vector"
    VALIDATING = "validating"
    BUILT_UNSCORED = "built_unscored"
    CANDIDATE = "candidate"
    FAILED = "failed"


class JobStage(StrEnum):
    QUEUED = "queued"
    RESEARCHING = "researching"
    QUALIFYING = "qualifying_evidence"
    DRAFTING = "drafting"
    VERIFYING = "verifying"
    REPAIRING = "repairing"
    ASSEMBLING = "assembling"
    COMPLETE = "complete"
    LIMITED = "limited"
    HELD = "held_for_review"
    ERROR = "system_error"
    CANCELLED = "cancelled"


class ReleaseState(StrEnum):
    VERIFIED_FULL = "verified_full"
    VERIFIED_CONCISE = "verified_concise"
    VERIFIED_LIMITED = "verified_limited"
    HELD_FOR_REVIEW = "held_for_review"
    SYSTEM_ERROR = "system_error"


class Severity(StrEnum):
    HARD_BLOCKER = "hard_blocker"
    REPAIRABLE = "repairable"
    INFORMATIONAL = "informational"


class TeachingVerifyStatus(StrEnum):
    """Discriminators for the teaching → verify → cite runtime flow."""

    TEACHING_SUGGESTION = "teaching_suggestion"
    VERIFIED = "verified"
    PARTLY_VERIFIED = "partly_verified"
    CONTRADICTED = "contradicted"
    NOT_FOUND = "not_found"


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


CASE_PROPOSITION_REVIEW_SCHEMA = "legalbot.case-proposition-currentness-review.v1"
CASE_PROPOSITION_CURRENT_STATUSES = frozenset({"confirmed_current", "qualified_current"})
CASE_PROPOSITION_REVIEWER_ROLES = frozenset(
    {
        "england_wales_qualified_barrister",
        "england_wales_qualified_legal_academic",
        "england_wales_qualified_legal_expert",
        "england_wales_qualified_solicitor",
        "legal_reviewer",
    }
)
FORBIDDEN_MACHINE_REVIEWER_ROLES = frozenset({"ai", "model", "assistant"})
_CASE_REVIEW_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_CASE_REVIEW_SAFE_LOCATOR = re.compile(r"^[^\n\r]{1,255}$")
_CASE_REVIEW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CASE_REVIEWER_REF = re.compile(r"^reviewer:[0-9a-f]{64}$")


def case_proposition_review_sha256(value: dict[str, Any]) -> str:
    """Return the canonical seal for a privacy-safe proposition review."""

    material = dict(value)
    material.pop("seal_sha256", None)
    encoded = (
        json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class CasePropositionReview(Record):
    """Exact later-treatment review for one case-law proposition and span.

    Source-level case approval proves identity and rights only.  This separate,
    immutable record is intentionally narrow: it binds a proposition to one
    source version, locator, exact span hash, legal role and review date.
    Reviewer references are opaque hashes, never names or owner identifiers.
    """

    model_config = ConfigDict(
        extra="forbid", use_enum_values=True, frozen=True, populate_by_name=True
    )

    schema_name: str = Field(default=CASE_PROPOSITION_REVIEW_SCHEMA, alias="schema")
    source_version_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    chunk_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    legal_locator: str
    exact_span_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposition_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    legal_role: Literal["holding_ratio", "binding_legal_rule"]
    later_treatment_reviewed_as_of_date: date
    later_treatment_status: Literal[
        "confirmed_current",
        "qualified_current",
        "not_current",
        "uncertain_hold",
    ]
    contrary_or_limiting_authority_ids: tuple[str, ...]
    reviewer_role: Literal[
        "england_wales_qualified_barrister",
        "england_wales_qualified_legal_academic",
        "england_wales_qualified_legal_expert",
        "england_wales_qualified_solicitor",
        "legal_reviewer",
    ]
    reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    review_scope: Literal["ordinary", "critical", "disputed"] = "ordinary"
    second_review_status: Literal["not_required", "pending", "confirmed", "disagreed"] = (
        "not_required"
    )
    second_reviewer_ref: str | None = Field(default=None, pattern=r"^reviewer:[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("legal_locator")
    @classmethod
    def locator_is_safe(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not _CASE_REVIEW_SAFE_LOCATOR.fullmatch(cleaned):
            raise ValueError("case review locator is empty, multiline or too long")
        lowered = cleaned.casefold()
        if "/users/" in lowered or "\\users\\" in lowered or lowered.startswith("file:"):
            raise ValueError("case review locator contains prohibited path metadata")
        return cleaned

    @field_validator("contrary_or_limiting_authority_ids")
    @classmethod
    def authority_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _CASE_REVIEW_SAFE_ID.fullmatch(value) for value in values):
            raise ValueError("case review contrary-authority IDs must be safe stable IDs")
        if len(values) != len(set(values)):
            raise ValueError("case review contrary-authority IDs are duplicated")
        return values

    @model_validator(mode="after")
    def review_is_consistent_and_sealed(self) -> Self:
        if self.reviewer_role not in CASE_PROPOSITION_REVIEWER_ROLES:
            raise ValueError("case review has an unsupported reviewer qualification role")
        if not _CASE_REVIEWER_REF.fullmatch(self.reviewer_ref):
            raise ValueError("case review reviewer reference is not privacy-safe")
        if self.later_treatment_status == "qualified_current" and not (
            self.contrary_or_limiting_authority_ids
        ):
            raise ValueError("qualified-current case review must bind limiting authority")
        if self.review_scope in {"critical", "disputed"} and (
            self.second_review_status != "confirmed" or self.second_reviewer_ref is None
        ):
            raise ValueError("critical or disputed case review requires confirmed second review")
        if self.second_review_status == "confirmed":
            if self.second_reviewer_ref is None:
                raise ValueError("confirmed second review requires a reviewer reference")
            if self.second_reviewer_ref == self.reviewer_ref:
                raise ValueError("case review second reviewer must be independent")
        elif self.second_reviewer_ref is not None:
            raise ValueError("unconfirmed second review cannot carry a reviewer reference")
        material = self.model_dump(mode="json", by_alias=True)
        if not _CASE_REVIEW_SHA256.fullmatch(
            self.seal_sha256
        ) or self.seal_sha256 != case_proposition_review_sha256(material):
            raise ValueError("case proposition review seal does not match its contents")
        return self

    @property
    def qualifies_for_present_law(self) -> bool:
        if self.later_treatment_status not in CASE_PROPOSITION_CURRENT_STATUSES:
            return False
        if self.second_review_status in {"pending", "disagreed"}:
            return False
        return self.review_scope == "ordinary" or self.second_review_status == "confirmed"


class Document(Record):
    id: str
    content_sha256: str
    source_identity_id: str
    safe_display_name: str
    media_type: str
    status: DocumentStatus
    lane: MaterialLane | None = None
    subject_primary: str | None = None
    subject_secondary: list[str] = Field(default_factory=list)
    jurisdiction: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class SourceVersion(Record):
    id: str
    document_id: str
    authority_identity_id: str | None = None
    version_sha256: str
    canonical_markdown_path: str
    title: str | None = None
    author_or_body: str | None = None
    source_date: date | None = None
    as_of_date: date | None = None
    canonical_url: str | None = None
    stable_identifier: str | None = None
    currentness_status: str = "unknown"
    licence_name: str | None = None
    licence_url: str | None = None
    review_status: ReviewStatus = ReviewStatus.STAGED
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class EvidenceSpan(Record):
    id: str
    source_version_id: str
    chunk_id: str
    text: str
    locator: str
    lane: MaterialLane
    jurisdiction: str
    subject: str
    citation_data: dict[str, Any] = Field(default_factory=dict)
    canonical_citation: str | None = None
    currentness_status: str = "unknown"
    content_sha256: str
    index_build_id: str
    canonical_url: str | None = None
    retrieval_relevance_score: float | None = None
    retrieval_route: str | None = None
    retrieval_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    retrieval_threshold_policy_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    retrieval_threshold_qualified: bool | None = None
    retrieval_qualification_reason: str | None = Field(
        default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$"
    )
    legal_role: str = "unclassified"
    unapplied_effect_count: int | None = None
    provision_extent_status: str = "unverified"
    identity_verified: bool = False
    currentness_verified: bool = False
    case_currentness_reviews: tuple[CasePropositionReview, ...] = ()
    case_currentness_manifest_seals: tuple[str, ...] = ()

    @field_validator("case_currentness_manifest_seals")
    @classmethod
    def case_manifest_seals_are_valid_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _CASE_REVIEW_SHA256.fullmatch(value) for value in values):
            raise ValueError("case currentness manifest seal is invalid")
        if len(values) != len(set(values)):
            raise ValueError("case currentness manifest seals are duplicated")
        return values


class IssueSpottingNote(Record):
    """Private teaching excerpt used only to discover possible legal issues."""

    id: str
    source_version_id: str
    chunk_id: str
    text: str
    jurisdiction: str
    subject: str
    content_sha256: str
    index_build_id: str


class UploadContextSpan(Record):
    """Transient, non-authoritative context parsed from a question upload.

    These records are intentionally not ``EvidenceSpan`` objects.  They have
    no citation identity, currentness assertion or index-build provenance and
    therefore cannot be bound to a material legal claim.
    """

    id: str
    text: str
    lane: MaterialLane
    locator: str
    subject: str | None = None
    jurisdiction: str
    context_only: bool = True


class IssuePlan(Record):
    """Transient deterministic query expansion; never legal evidence."""

    jurisdiction: str
    subject: str | None = None
    proposition_keys: list[str] = Field(default_factory=list, max_length=6)
    queries: list[str] = Field(default_factory=list, max_length=4)
    notes_considered: int = Field(ge=0)
    notes_used: int = Field(ge=0)
    unsafe_notes_excluded: int = Field(ge=0)

    def safe_metadata(self) -> dict[str, Any]:
        """Return persistence-safe counters and fixed taxonomy keys, never private prose."""

        return {
            "jurisdiction": self.jurisdiction,
            "subject": self.subject,
            "proposition_keys": list(self.proposition_keys),
            "query_count": len(self.queries),
            "notes_considered": self.notes_considered,
            "notes_used": self.notes_used,
            "unsafe_notes_excluded": self.unsafe_notes_excluded,
        }


class TeachingFlowItem(Record):
    """One internal teaching suggestion or authority-lane verification outcome.

    Internal ``teaching_suggestion`` items never carry evidence IDs or OSCOLA
    citations and are not persisted in user-facing notes. Verified /
    partly_verified / contradicted / not_found items may cite only primary,
    official-secondary or scholarship ``EvidenceSpan`` records.
    """

    proposition_key: str
    label: str
    teaching_summary: str
    status: TeachingVerifyStatus
    evidence_ids: list[str] = Field(default_factory=list, max_length=12)
    citations: list[str] = Field(default_factory=list, max_length=12)
    reason: str | None = None

    def safe_view(self) -> dict[str, Any]:
        """Persistence-safe view: taxonomy labels and authority cites only."""

        return {
            "proposition_key": self.proposition_key,
            "label": self.label,
            "teaching_summary": self.teaching_summary,
            "status": str(self.status),
            "evidence_ids": list(self.evidence_ids),
            "citations": list(self.citations),
            "reason": self.reason,
        }


_USER_FACING_TEACHING_STATUSES = frozenset(
    {
        TeachingVerifyStatus.VERIFIED,
        TeachingVerifyStatus.PARTLY_VERIFIED,
        TeachingVerifyStatus.CONTRADICTED,
        TeachingVerifyStatus.NOT_FOUND,
        "verified",
        "partly_verified",
        "contradicted",
        "not_found",
    }
)


class TeachingVerifyCiteFlow(Record):
    """Bounded teaching issue-spotting plus authority verification results."""

    items: list[TeachingFlowItem] = Field(default_factory=list, max_length=24)

    def user_facing_items(self) -> list[TeachingFlowItem]:
        """Verification outcomes only; never surface ``teaching_suggestion``."""

        return [item for item in self.items if item.status in _USER_FACING_TEACHING_STATUSES]

    def render_notes_view(self) -> str:
        """Knowledge-card notes: key - label / what / authority.

        Verify statuses stay in metadata only; the user-facing notes view is
        extracted knowledge, not teaching-verify jargon.
        """

        lines = ["notes"]
        for item in self.user_facing_items():
            what = " ".join((item.teaching_summary or "").split()).strip()
            if not what:
                what = f"{item.label}: a mapped legal issue requiring the governing tests and authorities."
            cites = [cite.strip() for cite in item.citations if cite and cite.strip()]
            authority = "; ".join(cites) if cites else "none in current authority set"
            lines.append("")
            lines.append(f"{item.proposition_key} - {item.label}")
            lines.append(f"what: {what}")
            lines.append(f"authority: {authority}")
        return "\n".join(lines).rstrip() + "\n"

    def safe_metadata(self) -> dict[str, Any]:
        user_items = self.user_facing_items()
        counts: dict[str, int] = {}
        for item in user_items:
            key = str(item.status)
            counts[key] = counts.get(key, 0) + 1
        return {
            "item_count": len(user_items),
            "status_counts": counts,
            "proposition_keys": list(dict.fromkeys(item.proposition_key for item in user_items)),
            "items": [item.safe_view() for item in user_items],
            "notes_view": self.render_notes_view(),
        }


class Claim(Record):
    id: str
    answer_version_id: str
    section_id: str
    text: str
    material: bool = True
    evidence_ids: list[str] = Field(default_factory=list)
    verification_status: str = "pending"
    verification_reason: str | None = None
    proposition_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class AnswerVersion(Record):
    id: str
    job_id: str
    version_number: int
    version_kind: str
    content: str
    word_count: int
    release_state: ReleaseState | None = None
    parent_version_id: str | None = None
    diff_from_parent: str | None = None
    policy_version: str
    model_version: str
    index_build_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class QualityFinding(Record):
    gate: str
    code: str
    message: str
    severity: Severity
    section_id: str | None = None
    claim_id: str | None = None
    corrective_action: str | None = None


class QualityReport(Record):
    id: str
    answer_version_id: str
    evidence_passed: bool
    academic_score: float
    raw_academic_score: float | None = None
    rubric_scores: dict[str, float] = Field(default_factory=dict)
    rubric_reasons: dict[str, str] = Field(default_factory=dict)
    rubric_caps: list[str] = Field(default_factory=list)
    ai_evidence_review: dict[str, Any] | None = None
    ai_evidence_adjudication: dict[str, Any] | None = None
    assessment_standards: dict[str, Any] | None = None
    findings: list[QualityFinding] = Field(default_factory=list)
    release_state: ReleaseState
    created_at: datetime = Field(default_factory=utc_now)


class KnowledgeGap(Record):
    id: str
    job_id: str
    missing_proposition: str
    jurisdiction: str
    subject: str | None = None
    searches_attempted: list[dict[str, Any]] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)
    status: str = "open"
    created_at: datetime = Field(default_factory=utc_now)


class StructuredClaimDraft(Record):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    text: str = Field(min_length=1, max_length=20_000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=24)
    material: bool = True
    kind: str = Field(default="legal_proposition", min_length=1, max_length=127)
    proposition_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("evidence_ids")
    @classmethod
    def evidence_ids_are_safe_unique(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) for value in values):
            raise ValueError("claim evidence IDs must be safe stable identifiers")
        if len(values) != len(set(values)):
            raise ValueError("claim evidence IDs must be unique")
        return values


class StructuredSectionDraft(Record):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    heading: str = Field(min_length=1, max_length=500)
    claims: list[StructuredClaimDraft] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def claim_ids_are_unique(self) -> Self:
        identifiers = [claim.id for claim in self.claims]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("claim IDs must be unique within a section")
        return self


class StructuredDraft(Record):
    title: str = Field(min_length=1, max_length=500)
    task_type: TaskType
    jurisdiction: str = Field(min_length=2, max_length=120)
    as_of_date: date
    sections: list[StructuredSectionDraft] = Field(min_length=1, max_length=50)
    limitations: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def section_and_claim_ids_are_globally_unique(self) -> Self:
        section_ids = [section.id for section in self.sections]
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("section IDs must be unique")
        claim_ids = [claim.id for section in self.sections for claim in section.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("claim IDs must be unique across the draft")
        return self


class RenderedAnswer(Record):
    markdown: str
    word_count: int
    evidence_ids: list[str]


class QuestionRequest(Record):
    question: str = Field(min_length=3, max_length=30_000)
    task_type: TaskType = TaskType.AUTO
    jurisdiction: str = Field(default="England and Wales", max_length=120)
    as_of_date: date | None = None
    word_target: int = Field(default=1_500, ge=100, le=10_000)
    online_mode: OnlineMode = OnlineMode.LOCAL_ONLY
    upload_ids: list[str] = Field(default_factory=list, max_length=20)
    conversation_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$",
    )


class QuestionAccepted(Record):
    job_id: str
    status: JobStatus
    stage: JobStage
    events_url: str
    conversation_id: str | None = None


class KnowledgeUpdateWebhookRequest(Record):
    event_type: Literal["knowledge_gap", "source_changed", "project_clarification"]
    subject: str = Field(min_length=1, max_length=80)
    jurisdiction: str = Field(default="England and Wales", min_length=1, max_length=80)
    source_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    authority_identity_id: str | None = Field(default=None, min_length=3, max_length=255)
    knowledge_gap_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,254}$",
    )
    source_date: date | None = None
    as_of_date: date | None = None
    observed_at: datetime = Field(default_factory=utc_now)
    query_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    safe_payload: dict[str, Any] = Field(default_factory=dict)
    detail: str | None = Field(default=None, max_length=20_000)


class SourceApprovalMetadata(Record):
    identity_verified: bool
    currentness_verified: bool | None = None
    stable_identifier: str = Field(min_length=1, max_length=500)
    identity_title: str | None = Field(default=None, min_length=1, max_length=500)
    as_of_date: date | None = None
    currentness_status: str = Field(min_length=1, max_length=40)
    material_type: str = Field(min_length=1, max_length=40)
    citation_data: dict[str, Any] = Field(default_factory=dict)
    canonical_url: str | None = Field(default=None, max_length=2_000)
    licence_name: str | None = Field(default=None, max_length=300)
    licence_url: str | None = Field(default=None, max_length=2_000)


class ReviewDecisionRequest(Record):
    note: str | None = Field(default=None, max_length=2_000)
    source_approval: SourceApprovalMetadata | None = None


class EvaluationIssueRequest(Record):
    category: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    severity: str = Field(pattern=r"^(low|medium|high|critical)$")
    affected_layer: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    expected_ids: list[str] = Field(default_factory=list, max_length=100)
    observed_ids: list[str] = Field(default_factory=list, max_length=100)
    note: str | None = Field(default=None, max_length=4_000)


class AnswerFeedbackRequest(Record):
    rating: Literal["helpful", "partly_helpful", "not_helpful"]
    category: Literal[
        "accuracy",
        "currentness",
        "authority",
        "citation",
        "completeness",
        "application",
        "structure",
        "clarity",
        "length",
        "privacy",
        "other",
    ]
    scope: Literal["answer", "section", "claim", "evidence"] = "answer"
    target_id: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=4_000)
    idempotency_key: str = Field(min_length=16, max_length=255)


class RefinementTransitionRequest(Record):
    to_status: Literal[
        "triaged",
        "source_needed",
        "metadata_currentness_needed",
        "retrieval_fix_needed",
        "accepted_out_of_scope",
        "resolved",
        "regression_verified",
    ]
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    root_cause: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{1,119}$")
    repair_version: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$")
    regression_case_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$"
    )
    resolution_evidence_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$"
    )
    resolution_evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    note: str | None = Field(default=None, max_length=4_000)

    @model_validator(mode="after")
    def resolution_evidence_is_complete(self) -> Self:
        if (self.resolution_evidence_id is None) != (self.resolution_evidence_sha256 is None):
            raise ValueError("resolution evidence ID and SHA-256 must be supplied together")
        return self


class ResearchCheckNowRequest(Record):
    task_type: Literal["source_update_check", "gap_research", "broad_discovery"]
    priority: Literal["high", "medium", "low"] = "medium"
    subject: str = Field(min_length=2, max_length=120)
    source_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{2,63}$")
    authority_identity_id: str | None = Field(default=None, max_length=500)
    knowledge_gap_id: str | None = Field(default=None, max_length=255)
    idempotency_key: str | None = Field(default=None, min_length=16, max_length=255)


class ResearchCandidateReviewRequest(Record):
    decision: Literal["accept_for_source_intake", "reject"]
    rights_state: Literal["verified", "metadata_only", "licensed", "rejected"]
    identity_review_state: Literal["candidate_matched", "ambiguous", "rejected"]
    currentness_review_state: Literal[
        "verified",
        "requires_source_review",
        "metadata_only",
        "not_applicable",
        "rejected",
    ]
    reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    review_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SourceUpdateReviewRequest(Record):
    materiality_status: Literal["non_material", "material", "unknown"]
    review_status: Literal["approved", "rejected", "not_required"]
    scope_kind: Literal["authority", "proposition"] = "authority"
    legal_locator: str | None = Field(default=None, max_length=500)
    proposition_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")
    review_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SourceUpdateResolutionRequest(Record):
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_ref: str = Field(pattern=r"^reviewer:[0-9a-f]{64}$")


class JobView(Record):
    id: str
    status: JobStatus
    stage: JobStage
    progress: float = Field(ge=0, le=1)
    question_summary: str
    answer_id: str | None = None
    release_state: ReleaseState | None = None
    message: str | None = None
    route: AnswerRoute
    word_target: int
    as_of_date: date | None = None
    pinned_index_build_id: str | None = None
    evaluation_request_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    worker_prompt_version: str | None = None
    worker_router_version: str | None = None
    worker_classifier_version: str | None = None
    worker_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    assessment_bundle_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    trace_id: str
    last_progress_at: datetime
    created_at: datetime
    updated_at: datetime


class EvidenceView(Record):
    answer_id: str
    claims: list[Claim]
    evidence: list[EvidenceSpan]


class HealthView(Record):
    status: str
    api_version: str
    owner_only: bool = True
    database_ready: bool
    worker_ready: bool = False
    active_index: str | None = None
    model_ready: bool
    model_id: str
    prompt_version: str
    router_version: str
    classifier_version: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assessment_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasons: list[str] = Field(default_factory=list)


class ObservabilityAdminView(Record):
    schema_name: str = Field(alias="schema")
    policy: dict[str, Any]
    snapshots: list[dict[str, Any]]
    slo_evaluations: list[dict[str, Any]]
    active_jobs: list[dict[str, Any]]


class ObservabilityTraceView(Record):
    schema_name: str = Field(alias="schema")
    job_id: str
    trace_id: str
    run_id: str | None = None
    case_id: str | None = None
    trace_retention: str
    span_count: int = Field(ge=0)
    spans: list[dict[str, Any]]
    stage_totals: list[dict[str, Any]]
    bottleneck_stage: dict[str, Any] | None = None
    longest_span: dict[str, Any] | None = None
