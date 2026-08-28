"""Sealed, prose-free advisory AI review against frozen evidence.

The model returns only claim IDs, verdicts, reason codes and cited evidence
IDs.  All identities and digests in the durable result are recomputed locally.
The current reviewer is a separate verification pass through the same configured
model adapter used by drafting.  It is not model-independent and has no power to
decide, adopt, admit a source or authorize a gate.  Its negative or uncertain
recommendations may raise a fail-closed owner-review hold; its positive
recommendations can never override deterministic or owner-controlled gates.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..privacy import contains_absolute_private_path, prompt_injection_hits
from ..prompt_templates import (
    AI_EVIDENCE_REVIEWER_TEMPLATE_NAME,
    AI_EVIDENCE_REVIEWER_TEMPLATE_SHA256,
    prompt_template_text,
)
from ..types import EvidenceSpan, StructuredDraft
from .draft_identity import SOURCE_DRAFT_IDENTITY_SCHEMA, source_draft_sha256

AI_EVIDENCE_REVIEW_SCHEMA = "legalbot.ai-evidence-review.v5"
AI_EVIDENCE_ADJUDICATION_SCHEMA = "legalbot.ai-evidence-adjudication.v2"
AI_EVIDENCE_REVIEWER_ROLE = "ai_evidence_reviewer"
AI_EVIDENCE_REVIEW_TOOLCHAIN_VERSION = "legalbot.ai-evidence-review-toolchain.v5"
AI_REVIEWER_EXECUTION_MODE = "separate_verification_pass_same_model_adapter"
FROZEN_CLAIM_BUNDLE_SCHEMA = "legalbot.frozen-material-claim-bundle.v2"
AI_EVIDENCE_INVOCATION_TRACE_SCHEMA = "legalbot.ai-evidence-invocation-trace.v1"
AI_EVIDENCE_CLAIM_CHECKPOINT_SCHEMA = "legalbot.ai-evidence-claim-checkpoint.v1"

MAX_REVIEW_INVOCATION_DURATION_MS = 86_400_000
MAX_REVIEW_INVOCATION_TOKENS = 10_000_000
MAX_REVIEW_CHECKPOINT_BYTES = 1_000_000


class AIEvidenceReviewVersionGateError(ValueError):
    """A persisted review schema cannot enter the current release path."""


ReviewVerdict = Literal[
    "supported",
    "partially_supported",
    "unsupported",
    "contradicted",
    "uncertain",
    "not_reviewable",
]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_REASON = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_VERDICTS = frozenset(
    {
        "supported",
        "partially_supported",
        "unsupported",
        "contradicted",
        "uncertain",
        "not_reviewable",
    }
)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sealed_sha256(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("seal_sha256", None)
    return hashlib.sha256(_canonical_json(material)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def ai_evidence_reviewer_prompt_text() -> str:
    """Return the exact tracked reviewer prompt."""

    return prompt_template_text(AI_EVIDENCE_REVIEWER_TEMPLATE_NAME)


def ai_evidence_reviewer_prompt_sha256() -> str:
    """Bind review provenance to the exact tracked prompt bytes."""

    return AI_EVIDENCE_REVIEWER_TEMPLATE_SHA256


def ai_evidence_reviewer_toolchain_sha256() -> str:
    """Return the stable identity of the local validation/adjudication toolchain."""

    return hashlib.sha256(
        _canonical_json(
            {
                "schema": AI_EVIDENCE_REVIEW_TOOLCHAIN_VERSION,
                "review_schema": AI_EVIDENCE_REVIEW_SCHEMA,
                "adjudication_schema": AI_EVIDENCE_ADJUDICATION_SCHEMA,
                "source_draft_identity_schema": SOURCE_DRAFT_IDENTITY_SCHEMA,
                "frozen_claim_bundle_schema": FROZEN_CLAIM_BUNDLE_SCHEMA,
                "invocation_trace_schema": AI_EVIDENCE_INVOCATION_TRACE_SCHEMA,
                "claim_checkpoint_schema": AI_EVIDENCE_CLAIM_CHECKPOINT_SCHEMA,
                "prompt_sha256": ai_evidence_reviewer_prompt_sha256(),
                "deterministic_gates_override_ai": True,
                "advisory_recommendations_only": True,
                "model_independent": False,
                "can_authorize_gates": False,
                "may_raise_fail_closed_owner_review_hold": True,
                "only_supported_passes": True,
                "resume": "sealed_create_only_claim_checkpoint",
            }
        )
    ).hexdigest()


class FrozenClaimReviewIdentity(BaseModel):
    """Locally derived identity for one material claim and its bound spans."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    claim_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_span_ids: tuple[str, ...]
    evidence_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evidence_span_ids")
    @classmethod
    def evidence_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_ID.fullmatch(value) for value in values):
            raise ValueError("claim review contains an invalid evidence ID")
        if len(values) != len(set(values)):
            raise ValueError("claim review contains duplicate evidence IDs")
        return values


@dataclass(frozen=True, slots=True)
class FrozenClaimReviewInput:
    """Transient reviewer input. Claim and evidence prose is never serialised here."""

    identity: FrozenClaimReviewIdentity
    claim_text: str
    evidence: tuple[EvidenceSpan, ...]

    def model_payload(self) -> dict[str, Any]:
        """Return the bounded model payload containing only this frozen material."""

        return {
            "claim_id": self.identity.claim_id,
            "claim_sha256": self.identity.claim_sha256,
            "claim_text": self.claim_text,
            "evidence": [
                {
                    "evidence_id": span.id,
                    "source_version_id": span.source_version_id,
                    "chunk_id": span.chunk_id,
                    "content_sha256": span.content_sha256,
                    "text_sha256": _text_sha256(span.text),
                    "text": span.text,
                    "locator": span.locator,
                    "lane": str(span.lane),
                    "jurisdiction": span.jurisdiction,
                    "currentness_status": span.currentness_status,
                    "index_build_id": span.index_build_id,
                    "retrieval_route": span.retrieval_route,
                    "retrieval_relevance_score": span.retrieval_relevance_score,
                    "retrieval_threshold": span.retrieval_threshold,
                    "retrieval_threshold_policy_sha256": (span.retrieval_threshold_policy_sha256),
                    "retrieval_threshold_qualified": (span.retrieval_threshold_qualified),
                }
                for span in self.evidence
            ],
        }


def _evidence_identity(span: EvidenceSpan) -> dict[str, Any]:
    return {
        "evidence_id": span.id,
        "source_version_id": span.source_version_id,
        "chunk_id": span.chunk_id,
        "content_sha256": span.content_sha256,
        "text_sha256": _text_sha256(span.text),
        "locator": span.locator,
        "lane": str(span.lane),
        "jurisdiction": span.jurisdiction,
        "currentness_status": span.currentness_status,
        "index_build_id": span.index_build_id,
        "retrieval_route": span.retrieval_route,
        "retrieval_relevance_score": span.retrieval_relevance_score,
        "retrieval_threshold": span.retrieval_threshold,
        "retrieval_threshold_policy_sha256": (span.retrieval_threshold_policy_sha256),
        "retrieval_threshold_qualified": span.retrieval_threshold_qualified,
        "identity_verified": span.identity_verified,
        "currentness_verified": span.currentness_verified,
    }


def freeze_material_claims(
    *,
    draft: StructuredDraft,
    evidence_by_id: Mapping[str, EvidenceSpan],
) -> tuple[FrozenClaimReviewInput, ...]:
    """Freeze all material claims and reject missing or mutable evidence identities."""

    output: list[FrozenClaimReviewInput] = []
    observed_claim_ids: set[str] = set()
    for section in draft.sections:
        for claim in section.claims:
            if not claim.material:
                continue
            if contains_absolute_private_path(claim.text):
                raise ValueError("material claim contains prohibited path metadata")
            if claim.id in observed_claim_ids:
                raise ValueError("material claim IDs must be unique")
            observed_claim_ids.add(claim.id)
            spans: list[EvidenceSpan] = []
            for evidence_id in claim.evidence_ids:
                span = evidence_by_id.get(evidence_id)
                if span is None:
                    raise ValueError(
                        "material claim references evidence outside its frozen snapshot"
                    )
                if span.id != evidence_id:
                    raise ValueError(
                        "evidence map key differs from the frozen EvidenceSpan identity"
                    )
                identity_values = (
                    span.id,
                    span.source_version_id,
                    span.chunk_id,
                    span.index_build_id,
                )
                if any(not _SAFE_ID.fullmatch(value) for value in identity_values):
                    raise ValueError("frozen EvidenceSpan contains an unsafe identity")
                if any(
                    contains_absolute_private_path(value)
                    for value in (span.text, span.locator, span.jurisdiction)
                ):
                    raise ValueError("frozen EvidenceSpan contains prohibited path metadata")
                if prompt_injection_hits(span.text):
                    raise ValueError("frozen EvidenceSpan failed prompt-injection safety")
                if not span.identity_verified or not span.currentness_verified:
                    raise ValueError(
                        "frozen EvidenceSpan has not passed deterministic identity/currentness"
                    )
                if span.jurisdiction != draft.jurisdiction:
                    raise ValueError("frozen EvidenceSpan jurisdiction differs from the draft")
                if str(span.lane) in {"private_teaching", "assessment_guidance"}:
                    raise ValueError("non-authority material cannot enter AI evidence review")
                spans.append(span)
            if len({span.id for span in spans}) != len(spans):
                raise ValueError("material claim binds the same EvidenceSpan more than once")
            claim_sha256 = _text_sha256(claim.text)
            identity_material: dict[str, Any] = {
                "schema": "legalbot.frozen-claim-review-identity.v1",
                "claim_id": claim.id,
                "claim_sha256": claim_sha256,
                "evidence": [_evidence_identity(span) for span in spans],
            }
            identity = FrozenClaimReviewIdentity(
                claim_id=claim.id,
                claim_sha256=claim_sha256,
                evidence_span_ids=tuple(span.id for span in spans),
                evidence_bundle_sha256=hashlib.sha256(
                    _canonical_json(identity_material)
                ).hexdigest(),
            )
            output.append(
                FrozenClaimReviewInput(
                    identity=identity,
                    claim_text=claim.text,
                    evidence=tuple(spans),
                )
            )
    return tuple(output)


def _frozen_claim_identity_row(value: Any) -> dict[str, Any]:
    identity = getattr(value, "identity", value)
    return {
        "claim_id": identity.claim_id,
        "claim_sha256": identity.claim_sha256,
        "evidence_span_ids": list(identity.evidence_span_ids),
        "evidence_bundle_sha256": identity.evidence_bundle_sha256,
    }


def frozen_claim_bundle_sha256(claims: Sequence[Any]) -> str:
    """Digest only the ordered frozen material-claim/evidence identities."""

    return hashlib.sha256(
        _canonical_json(
            {
                "schema": FROZEN_CLAIM_BUNDLE_SCHEMA,
                "claims": [_frozen_claim_identity_row(item) for item in claims],
            }
        )
    ).hexdigest()


def frozen_draft_sha256(claims: Sequence[FrozenClaimReviewInput]) -> str:
    """Compatibility name for the frozen-claim bundle digest.

    New code should use :func:`frozen_claim_bundle_sha256`; this digest is not
    the identity of the complete StructuredDraft.
    """

    return frozen_claim_bundle_sha256(claims)


def _assert_frozen_claims_bind_source_draft(
    *,
    source_draft: StructuredDraft,
    frozen_claims: Sequence[FrozenClaimReviewInput],
) -> None:
    source_claims = tuple(
        claim for section in source_draft.sections for claim in section.claims if claim.material
    )
    if len(source_claims) != len(frozen_claims):
        raise ValueError("frozen claims do not cover the complete source draft")
    for claim, frozen in zip(source_claims, frozen_claims, strict=True):
        if (
            claim.id != frozen.identity.claim_id
            or _text_sha256(claim.text) != frozen.identity.claim_sha256
            or tuple(claim.evidence_ids) != frozen.identity.evidence_span_ids
            or claim.text != frozen.claim_text
        ):
            raise ValueError("frozen claim identity differs from the source draft")


class ClaimEvidenceVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    claim_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_span_ids: tuple[str, ...]
    evidence_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verdict: ReviewVerdict
    reason_codes: tuple[str, ...] = ()
    cited_evidence_ids: tuple[str, ...] = ()

    @field_validator("evidence_span_ids", "cited_evidence_ids")
    @classmethod
    def evidence_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_ID.fullmatch(value) for value in values):
            raise ValueError("AI evidence verdict contains an invalid evidence ID")
        if len(values) != len(set(values)):
            raise ValueError("AI evidence verdict contains duplicate evidence IDs")
        return values

    @field_validator("reason_codes")
    @classmethod
    def reason_codes_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_REASON.fullmatch(value) for value in values):
            raise ValueError("AI evidence verdict reason must be a safe machine code")
        if len(values) != len(set(values)):
            raise ValueError("AI evidence verdict contains duplicate reason codes")
        return values

    @model_validator(mode="after")
    def citations_and_verdict_are_fail_closed(self) -> Self:
        if not set(self.cited_evidence_ids).issubset(self.evidence_span_ids):
            raise ValueError("AI reviewer cited evidence outside the frozen claim binding")
        if self.verdict in {"supported", "partially_supported"} and not (self.cited_evidence_ids):
            raise ValueError("a positive AI verdict requires cited frozen evidence")
        return self


def _safe_model_identity(value: str) -> str:
    cleaned = " ".join(value.split())
    lowered = cleaned.casefold()
    if (
        not cleaned
        or "\n" in value
        or contains_absolute_private_path(value)
        or "/users/" in lowered
        or "\\users\\" in lowered
        or lowered.startswith("file:")
    ):
        raise ValueError("AI reviewer model identity is unsafe")
    return cleaned


class AIReviewerInvocationTrace(BaseModel):
    """Prose-free timing/usage identity for one exact claim invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.ai-evidence-invocation-trace.v1"] = Field(
        default="legalbot.ai-evidence-invocation-trace.v1", alias="schema"
    )
    claim_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    invocation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    duration_ms: int = Field(ge=0, le=MAX_REVIEW_INVOCATION_DURATION_MS)
    input_token_count: int | None = Field(default=None, ge=0, le=MAX_REVIEW_INVOCATION_TOKENS)
    output_token_count: int | None = Field(default=None, ge=0, le=MAX_REVIEW_INVOCATION_TOKENS)
    timing_source: Literal["local_monotonic", "transport", "deterministic_zero"]
    resumed_from_checkpoint: bool = False
    checkpoint_seal_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("duration_ms", "input_token_count", "output_token_count", mode="before")
    @classmethod
    def counters_are_strict_integers(cls, value: Any) -> Any:
        if value is None:
            return value
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("AI reviewer timing/token counters must be integers")
        return value

    @model_validator(mode="after")
    def checkpoint_resume_is_bound(self) -> Self:
        if self.resumed_from_checkpoint and self.checkpoint_seal_sha256 is None:
            raise ValueError("resumed AI reviewer trace must bind its checkpoint seal")
        if self.timing_source == "deterministic_zero" and self.duration_ms != 0:
            raise ValueError("deterministic AI reviewer timing must be zero")
        if self.seal_sha256 != _sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("AI reviewer invocation trace seal does not match its contents")
        return self


def seal_ai_reviewer_invocation_trace(
    *,
    claim_id: str,
    invocation_id: str,
    duration_ms: int,
    input_token_count: int | None = None,
    output_token_count: int | None = None,
    timing_source: Literal["local_monotonic", "transport", "deterministic_zero"],
    resumed_from_checkpoint: bool = False,
    checkpoint_seal_sha256: str | None = None,
) -> AIReviewerInvocationTrace:
    """Seal safe timing/token counters without retaining model prose."""

    material: dict[str, Any] = {
        "schema": AI_EVIDENCE_INVOCATION_TRACE_SCHEMA,
        "claim_id": claim_id,
        "invocation_id": invocation_id,
        "duration_ms": duration_ms,
        "input_token_count": input_token_count,
        "output_token_count": output_token_count,
        "timing_source": timing_source,
        "resumed_from_checkpoint": resumed_from_checkpoint,
        "checkpoint_seal_sha256": checkpoint_seal_sha256,
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return AIReviewerInvocationTrace.model_validate(material)


def _reseal_ai_reviewer_invocation_trace(
    trace: AIReviewerInvocationTrace,
    *,
    resumed_from_checkpoint: bool,
    checkpoint_seal_sha256: str | None,
) -> AIReviewerInvocationTrace:
    return seal_ai_reviewer_invocation_trace(
        claim_id=trace.claim_id,
        invocation_id=trace.invocation_id,
        duration_ms=trace.duration_ms,
        input_token_count=trace.input_token_count,
        output_token_count=trace.output_token_count,
        timing_source=trace.timing_source,
        resumed_from_checkpoint=resumed_from_checkpoint,
        checkpoint_seal_sha256=checkpoint_seal_sha256,
    )


class AIReviewerClaimCheckpoint(BaseModel):
    """One completed claim decision, safe to persist outside release output."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.ai-evidence-claim-checkpoint.v1"] = Field(
        default="legalbot.ai-evidence-claim-checkpoint.v1", alias="schema"
    )
    checkpoint_id: str = Field(pattern=r"^ai-claim-checkpoint-[0-9a-f]{24}$")
    source_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_claim_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim_identity: FrozenClaimReviewIdentity
    model_id: str = Field(min_length=1, max_length=255)
    model_version: str = Field(min_length=1, max_length=255)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: ClaimEvidenceVerdict
    invocation_trace: AIReviewerInvocationTrace
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("model_id", "model_version")
    @classmethod
    def model_identity_is_safe(cls, value: str) -> str:
        return _safe_model_identity(value)

    @model_validator(mode="after")
    def checkpoint_is_exact_and_sealed(self) -> Self:
        identity = self.claim_identity
        decision_identity = (
            self.decision.claim_id,
            self.decision.claim_sha256,
            self.decision.evidence_span_ids,
            self.decision.evidence_bundle_sha256,
        )
        expected_identity = (
            identity.claim_id,
            identity.claim_sha256,
            identity.evidence_span_ids,
            identity.evidence_bundle_sha256,
        )
        if decision_identity != expected_identity:
            raise ValueError("AI reviewer checkpoint decision identity differs from its claim")
        if (
            self.invocation_trace.claim_id != identity.claim_id
            or self.invocation_trace.resumed_from_checkpoint
            or self.invocation_trace.checkpoint_seal_sha256 is not None
        ):
            raise ValueError("AI reviewer checkpoint invocation trace is invalid")
        expected_id = _claim_checkpoint_id(
            source_draft_sha256=self.source_draft_sha256,
            frozen_claim_bundle_sha256=self.frozen_claim_bundle_sha256,
            claim_identity=identity,
            invocation_id=self.invocation_trace.invocation_id,
            model_id=self.model_id,
            model_version=self.model_version,
            prompt_sha256=self.prompt_sha256,
            policy_sha256=self.policy_sha256,
            toolchain_sha256=self.toolchain_sha256,
        )
        if self.checkpoint_id != expected_id:
            raise ValueError("AI reviewer checkpoint identity does not match its provenance")
        if self.seal_sha256 != _sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("AI reviewer checkpoint seal does not match its contents")
        return self


def _claim_checkpoint_id(
    *,
    source_draft_sha256: str,
    frozen_claim_bundle_sha256: str,
    claim_identity: FrozenClaimReviewIdentity,
    invocation_id: str,
    model_id: str,
    model_version: str,
    prompt_sha256: str,
    policy_sha256: str,
    toolchain_sha256: str,
) -> str:
    identity_material: dict[str, Any] = {
        "schema": "legalbot.ai-evidence-claim-checkpoint-identity.v1",
        "source_draft_sha256": source_draft_sha256,
        "frozen_claim_bundle_sha256": frozen_claim_bundle_sha256,
        "claim_identity": claim_identity.model_dump(mode="json"),
        "invocation_id": invocation_id,
        "model_id": model_id,
        "model_version": model_version,
        "prompt_sha256": prompt_sha256,
        "policy_sha256": policy_sha256,
        "toolchain_sha256": toolchain_sha256,
    }
    return (
        "ai-claim-checkpoint-" + hashlib.sha256(_canonical_json(identity_material)).hexdigest()[:24]
    )


def _claim_verdict_from_model_row(
    *,
    frozen: FrozenClaimReviewInput,
    row: Mapping[str, Any],
) -> ClaimEvidenceVerdict:
    verdict_value = str(row.get("verdict") or "not_reviewable")
    verdict: ReviewVerdict = verdict_value if verdict_value in _VERDICTS else "not_reviewable"  # type: ignore[assignment]
    raw_reasons = row.get("reason_codes") or ()
    raw_cited = row.get("cited_evidence_ids") or ()
    if not isinstance(raw_reasons, Sequence) or isinstance(raw_reasons, str | bytes | bytearray):
        raise ValueError("AI reviewer reason codes must be an array")
    if not isinstance(raw_cited, Sequence) or isinstance(raw_cited, str | bytes | bytearray):
        raise ValueError("AI reviewer cited evidence IDs must be an array")
    reason_codes = tuple(str(value) for value in raw_reasons)
    if verdict_value not in _VERDICTS:
        reason_codes = tuple(dict.fromkeys((*reason_codes, "invalid_model_verdict")))
    return ClaimEvidenceVerdict(
        claim_id=frozen.identity.claim_id,
        claim_sha256=frozen.identity.claim_sha256,
        evidence_span_ids=frozen.identity.evidence_span_ids,
        evidence_bundle_sha256=frozen.identity.evidence_bundle_sha256,
        verdict=verdict,
        reason_codes=reason_codes,
        cited_evidence_ids=tuple(str(value) for value in raw_cited),
    )


def _model_row_from_verdict(verdict: ClaimEvidenceVerdict) -> dict[str, Any]:
    return {
        "claim_id": verdict.claim_id,
        "verdict": verdict.verdict,
        "reason_codes": list(verdict.reason_codes),
        "cited_evidence_ids": list(verdict.cited_evidence_ids),
    }


def seal_ai_reviewer_claim_checkpoint(
    *,
    source_draft_sha256: str,
    frozen_claim_bundle_sha256: str,
    frozen_claim: FrozenClaimReviewInput,
    decision: ClaimEvidenceVerdict,
    invocation_trace: AIReviewerInvocationTrace,
    model_id: str,
    model_version: str,
    policy_sha256: str,
    toolchain_sha256: str,
) -> AIReviewerClaimCheckpoint:
    """Seal one completed machine decision for create-only resume storage."""

    if any(
        not _SHA256.fullmatch(digest)
        for digest in (
            source_draft_sha256,
            frozen_claim_bundle_sha256,
            policy_sha256,
            toolchain_sha256,
        )
    ):
        raise ValueError("AI reviewer checkpoint provenance digest is invalid")
    expected_prompt = ai_evidence_reviewer_prompt_sha256()
    checkpoint_id = _claim_checkpoint_id(
        source_draft_sha256=source_draft_sha256,
        frozen_claim_bundle_sha256=frozen_claim_bundle_sha256,
        claim_identity=frozen_claim.identity,
        invocation_id=invocation_trace.invocation_id,
        model_id=model_id,
        model_version=model_version,
        prompt_sha256=expected_prompt,
        policy_sha256=policy_sha256,
        toolchain_sha256=toolchain_sha256,
    )
    material: dict[str, Any] = {
        "schema": AI_EVIDENCE_CLAIM_CHECKPOINT_SCHEMA,
        "checkpoint_id": checkpoint_id,
        "source_draft_sha256": source_draft_sha256,
        "frozen_claim_bundle_sha256": frozen_claim_bundle_sha256,
        "claim_identity": frozen_claim.identity.model_dump(mode="json"),
        "model_id": model_id,
        "model_version": model_version,
        "prompt_sha256": expected_prompt,
        "policy_sha256": policy_sha256,
        "toolchain_sha256": toolchain_sha256,
        "decision": decision.model_dump(mode="json"),
        "invocation_trace": invocation_trace.model_dump(mode="json", by_alias=True),
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return AIReviewerClaimCheckpoint.model_validate(material)


class AIEvidenceReviewerCheckpointStore:
    """Private, create-only files for a contiguous prefix of completed claims."""

    def __init__(self, directory: Path, *, resume: bool) -> None:
        if directory.exists() or directory.is_symlink():
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError("AI reviewer checkpoint directory is invalid")
            if not resume:
                raise FileExistsError("AI reviewer checkpoint directory already exists")
            if stat.S_IMODE(directory.stat().st_mode) != 0o700:
                raise PermissionError("AI reviewer checkpoint directory must be mode 0700")
        else:
            directory.mkdir(parents=True, mode=0o700)
            directory.chmod(0o700)
        self.directory = directory.resolve()

    @staticmethod
    def _name(ordinal: int, claim: FrozenClaimReviewInput) -> str:
        if ordinal < 1 or ordinal > 9999:
            raise ValueError("AI reviewer claim ordinal is out of range")
        opaque_claim = hashlib.sha256(claim.identity.claim_id.encode("utf-8")).hexdigest()[:24]
        return f"{ordinal:04d}-{opaque_claim}.json"

    def prepare(self, claims: Sequence[FrozenClaimReviewInput]) -> None:
        expected = [self._name(index, claim) for index, claim in enumerate(claims, start=1)]
        members = sorted(self.directory.iterdir(), key=lambda item: item.name)
        observed: list[str] = []
        for member in members:
            metadata = member.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > MAX_REVIEW_CHECKPOINT_BYTES
            ):
                raise ValueError("AI reviewer checkpoint set contains an invalid member")
            observed.append(member.name)
        if observed != expected[: len(observed)]:
            raise ValueError("AI reviewer checkpoints are not a contiguous exact-claim prefix")

    def read(
        self,
        *,
        ordinal: int,
        claim: FrozenClaimReviewInput,
    ) -> AIReviewerClaimCheckpoint | None:
        path = self.directory / self._name(ordinal, claim)
        if not path.exists():
            return None
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_REVIEW_CHECKPOINT_BYTES
        ):
            raise ValueError("AI reviewer checkpoint file is invalid")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("AI reviewer checkpoint file is unreadable") from exc
        if not isinstance(value, Mapping):
            raise ValueError("AI reviewer checkpoint must be a JSON object")
        return AIReviewerClaimCheckpoint.model_validate(value)

    def write(
        self, *, ordinal: int, claim: FrozenClaimReviewInput, checkpoint: AIReviewerClaimCheckpoint
    ) -> None:
        path = self.directory / self._name(ordinal, claim)
        payload = _canonical_json(checkpoint.model_dump(mode="json", by_alias=True))
        if len(payload) > MAX_REVIEW_CHECKPOINT_BYTES:
            raise ValueError("AI reviewer checkpoint exceeds its safe byte limit")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        path.chmod(0o600)


class AIEvidenceReviewResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.ai-evidence-review.v5"] = Field(
        default="legalbot.ai-evidence-review.v5", alias="schema"
    )
    review_id: str = Field(pattern=r"^ai-review-[0-9a-f]{24}$")
    reviewer_role: Literal["ai_evidence_reviewer"] = "ai_evidence_reviewer"
    reviewer_execution_mode: Literal["separate_verification_pass_same_model_adapter"] = (
        "separate_verification_pass_same_model_adapter"
    )
    model_independent: Literal[False] = False
    advisory_recommendations_only: Literal[True] = True
    can_decide_or_adopt: Literal[False] = False
    can_admit_sources: Literal[False] = False
    can_authorize_gates: Literal[False] = False
    may_raise_fail_closed_owner_review_hold: Literal[True] = True
    invocation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    invocation_ids: tuple[str, ...]
    invocation_traces: tuple[AIReviewerInvocationTrace, ...]
    model_id: str = Field(min_length=1, max_length=255)
    model_version: str = Field(min_length=1, max_length=255)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    toolchain_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_claim_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    material_claim_count: int = Field(ge=0)
    claims: tuple[ClaimEvidenceVerdict, ...]
    all_material_claims_reviewed: Literal[True] = True
    passed: bool
    chain_of_thought: Literal[None] = None
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("model_id", "model_version")
    @classmethod
    def model_identity_is_safe(cls, value: str) -> str:
        return _safe_model_identity(value)

    @model_validator(mode="after")
    def result_is_complete_and_sealed(self) -> Self:
        if any(not _SAFE_ID.fullmatch(value) for value in self.invocation_ids):
            raise ValueError("AI evidence review contains an invalid invocation ID")
        if len(self.invocation_ids) != len(set(self.invocation_ids)):
            raise ValueError("AI evidence review contains duplicate invocation IDs")
        if self.material_claim_count and len(self.invocation_ids) != self.material_claim_count:
            raise ValueError("AI evidence review must bind one invocation per material claim")
        if not self.material_claim_count and self.invocation_ids:
            raise ValueError("claim-free AI evidence review cannot record model invocations")
        if len(self.invocation_traces) != self.material_claim_count:
            raise ValueError("AI evidence review must bind one trace per material claim")
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("AI evidence review contains duplicate claims")
        if self.material_claim_count != len(self.claims):
            raise ValueError("AI evidence review does not cover every material claim")
        trace_bindings = tuple(
            (trace.claim_id, trace.invocation_id) for trace in self.invocation_traces
        )
        expected_trace_bindings = tuple(zip(claim_ids, self.invocation_ids, strict=True))
        if trace_bindings != expected_trace_bindings:
            raise ValueError("AI evidence review trace identities differ from its claims")
        if self.frozen_claim_bundle_sha256 != frozen_claim_bundle_sha256(self.claims):
            raise ValueError("AI evidence review frozen-claim bundle digest does not match")
        expected_pass = all(claim.verdict == "supported" for claim in self.claims)
        if self.passed != expected_pass:
            raise ValueError("AI evidence review pass flag disagrees with claim verdicts")
        if self.seal_sha256 != _sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("AI evidence review seal does not match its contents")
        return self


def load_persisted_ai_evidence_review(
    value: Mapping[str, Any],
) -> AIEvidenceReviewResult:
    """Load only a current review; legacy records require a fresh invocation.

    Earlier versions are deliberately not upgraded. Version 2 has no per-claim
    sealed invocation traces, and version 3 does not record that the reviewer is
    an advisory separate pass through the same model adapter. Synthesising either
    provenance fact would silently change an already persisted review.
    """

    schema = value.get("schema")
    if schema in {
        "legalbot.ai-evidence-review.v2",
        "legalbot.ai-evidence-review.v3",
        "legalbot.ai-evidence-review.v4",
    }:
        raise AIEvidenceReviewVersionGateError(
            "legacy AI evidence review is non-releasable; fresh v5 review required"
        )
    if schema != AI_EVIDENCE_REVIEW_SCHEMA:
        raise AIEvidenceReviewVersionGateError(
            "AI evidence review schema is unsupported by the current release gate"
        )
    return AIEvidenceReviewResult.model_validate(value)


def _model_claim_rows(value: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    if set(value) != {"claims"}:
        raise ValueError("AI evidence reviewer returned fields outside its contract")
    raw = value.get("claims")
    if not isinstance(raw, Sequence) or isinstance(raw, str | bytes | bytearray):
        raise ValueError("AI evidence reviewer returned no claim-decision array")
    rows: list[Mapping[str, Any]] = []
    allowed = {"claim_id", "verdict", "reason_codes", "cited_evidence_ids"}
    for item in raw:
        if not isinstance(item, Mapping):
            raise ValueError("AI evidence reviewer returned a non-object claim decision")
        if set(item) != allowed:
            raise ValueError("AI evidence claim decision differs from its exact contract")
        rows.append(item)
    return tuple(rows)


def seal_ai_evidence_review(
    *,
    model_output: Mapping[str, Any],
    source_draft: StructuredDraft,
    frozen_claims: Sequence[FrozenClaimReviewInput],
    invocation_id: str,
    invocation_ids: Sequence[str] | None = None,
    invocation_traces: Sequence[AIReviewerInvocationTrace] | None = None,
    model_id: str,
    model_version: str,
    policy_sha256: str,
    toolchain_sha256: str,
    prompt_sha256: str | None = None,
) -> AIEvidenceReviewResult:
    """Validate model decisions and add only locally recomputed identities/digests."""

    if not _SAFE_ID.fullmatch(invocation_id):
        raise ValueError("AI reviewer invocation identity is invalid")
    for digest in (policy_sha256, toolchain_sha256):
        if not _SHA256.fullmatch(digest):
            raise ValueError("AI reviewer provenance digest is invalid")
    expected_prompt = ai_evidence_reviewer_prompt_sha256()
    if prompt_sha256 is not None and prompt_sha256 != expected_prompt:
        raise ValueError("AI reviewer prompt digest differs from tracked bytes")
    _assert_frozen_claims_bind_source_draft(
        source_draft=source_draft,
        frozen_claims=frozen_claims,
    )

    expected = {item.identity.claim_id: item for item in frozen_claims}
    if len(expected) != len(frozen_claims):
        raise ValueError("frozen AI review input contains duplicate claim IDs")
    rows = _model_claim_rows(model_output)
    if len(rows) != len(expected):
        raise ValueError("AI reviewer must disposition every material claim exactly once")
    observed_ids = [str(item.get("claim_id") or "") for item in rows]
    if len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(expected):
        raise ValueError("AI reviewer claim identities differ from the frozen draft")

    verdicts: list[ClaimEvidenceVerdict] = []
    by_id = {str(item.get("claim_id")): item for item in rows}
    for frozen in frozen_claims:
        verdicts.append(
            _claim_verdict_from_model_row(
                frozen=frozen,
                row=by_id[frozen.identity.claim_id],
            )
        )

    source_draft_sha = source_draft_sha256(source_draft)
    frozen_bundle_sha = frozen_claim_bundle_sha256(frozen_claims)
    bound_invocations = tuple(invocation_ids or ((invocation_id,) if frozen_claims else ()))
    if invocation_traces is None:
        bound_traces = tuple(
            seal_ai_reviewer_invocation_trace(
                claim_id=frozen.identity.claim_id,
                invocation_id=bound_invocation,
                duration_ms=0,
                input_token_count=None,
                output_token_count=None,
                timing_source="deterministic_zero",
            )
            for frozen, bound_invocation in zip(
                frozen_claims,
                bound_invocations,
                strict=True,
            )
        )
    else:
        bound_traces = tuple(invocation_traces)
    material: dict[str, Any] = {
        "schema": AI_EVIDENCE_REVIEW_SCHEMA,
        "review_id": "ai-review-"
        + hashlib.sha256(
            (
                f"{invocation_id}\0{source_draft_sha}\0{frozen_bundle_sha}\0{expected_prompt}"
            ).encode()
        ).hexdigest()[:24],
        "reviewer_role": AI_EVIDENCE_REVIEWER_ROLE,
        "reviewer_execution_mode": AI_REVIEWER_EXECUTION_MODE,
        "model_independent": False,
        "advisory_recommendations_only": True,
        "can_decide_or_adopt": False,
        "can_admit_sources": False,
        "can_authorize_gates": False,
        "may_raise_fail_closed_owner_review_hold": True,
        "invocation_id": invocation_id,
        "invocation_ids": list(bound_invocations),
        "invocation_traces": [
            trace.model_dump(mode="json", by_alias=True) for trace in bound_traces
        ],
        "model_id": model_id,
        "model_version": model_version,
        "prompt_sha256": expected_prompt,
        "policy_sha256": policy_sha256,
        "toolchain_sha256": toolchain_sha256,
        "source_draft_sha256": source_draft_sha,
        "frozen_claim_bundle_sha256": frozen_bundle_sha,
        "material_claim_count": len(verdicts),
        "claims": [item.model_dump(mode="json") for item in verdicts],
        "all_material_claims_reviewed": True,
        "passed": all(item.verdict == "supported" for item in verdicts),
        "chain_of_thought": None,
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return AIEvidenceReviewResult.model_validate(material)


def _transport_metric(
    metrics: Mapping[str, Any],
    key: str,
    *,
    maximum: int,
) -> int | None:
    if key not in metrics or metrics[key] is None:
        return None
    value = metrics[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise ValueError(f"AI reviewer transport {key} is outside its bounded integer contract")
    return int(value)


def _parse_reviewer_transport_response(
    response: Any,
    *,
    claim_id: str,
    local_duration_ms: int,
) -> tuple[str, Mapping[str, Any], AIReviewerInvocationTrace]:
    if not isinstance(response, tuple) or len(response) not in {2, 3}:
        raise ValueError("AI evidence reviewer returned an invalid invocation envelope")
    invocation_id = response[0]
    parsed = response[1]
    if not isinstance(invocation_id, str) or not isinstance(parsed, Mapping):
        raise ValueError("AI evidence reviewer returned an invalid invocation")
    metrics: Mapping[str, Any] = {}
    if len(response) == 3:
        raw_metrics = response[2]
        if not isinstance(raw_metrics, Mapping):
            raise ValueError("AI reviewer transport metrics must be a machine object")
        allowed_metrics = {"duration_ms", "input_tokens", "output_tokens"}
        if not set(raw_metrics).issubset(allowed_metrics):
            raise ValueError("AI reviewer transport metrics differ from their exact contract")
        metrics = raw_metrics
    reported_duration = _transport_metric(
        metrics,
        "duration_ms",
        maximum=MAX_REVIEW_INVOCATION_DURATION_MS,
    )
    trace = seal_ai_reviewer_invocation_trace(
        claim_id=claim_id,
        invocation_id=invocation_id,
        duration_ms=(local_duration_ms if reported_duration is None else reported_duration),
        input_token_count=_transport_metric(
            metrics,
            "input_tokens",
            maximum=MAX_REVIEW_INVOCATION_TOKENS,
        ),
        output_token_count=_transport_metric(
            metrics,
            "output_tokens",
            maximum=MAX_REVIEW_INVOCATION_TOKENS,
        ),
        timing_source="transport" if reported_duration is not None else "local_monotonic",
    )
    return invocation_id, parsed, trace


def _verify_checkpoint_binding(
    checkpoint: AIReviewerClaimCheckpoint,
    *,
    source_draft_sha256: str,
    frozen_claim_bundle_sha256: str,
    frozen_claim: FrozenClaimReviewInput,
    model_id: str,
    model_version: str,
    policy_sha256: str,
    toolchain_sha256: str,
) -> None:
    if (
        checkpoint.source_draft_sha256 != source_draft_sha256
        or checkpoint.frozen_claim_bundle_sha256 != frozen_claim_bundle_sha256
        or checkpoint.claim_identity != frozen_claim.identity
        or checkpoint.model_id != _safe_model_identity(model_id)
        or checkpoint.model_version != _safe_model_identity(model_version)
        or checkpoint.prompt_sha256 != ai_evidence_reviewer_prompt_sha256()
        or checkpoint.policy_sha256 != policy_sha256
        or checkpoint.toolchain_sha256 != toolchain_sha256
    ):
        raise ValueError("AI reviewer checkpoint binding differs from the exact review input")


async def invoke_ai_evidence_reviewer(
    *,
    model: Any,
    draft: StructuredDraft,
    evidence_by_id: Mapping[str, EvidenceSpan],
    model_id: str,
    model_version: str,
    policy_sha256: str,
    checkpoint_store: AIEvidenceReviewerCheckpointStore | None = None,
) -> AIEvidenceReviewResult:
    """Invoke the distinct reviewer prompt and seal only locally derived identities.

    A missing or malformed reviewer is an operational failure. Callers must
    fail closed; this function never fabricates a passing review or falls back
    to the drafting prompt.
    """

    frozen = freeze_material_claims(draft=draft, evidence_by_id=evidence_by_id)
    source_draft_sha = source_draft_sha256(draft)
    frozen_bundle_sha = frozen_claim_bundle_sha256(frozen)
    toolchain_sha = ai_evidence_reviewer_toolchain_sha256()
    if checkpoint_store is not None:
        checkpoint_store.prepare(frozen)
    invocation_ids: list[str] = []
    claim_rows: list[Mapping[str, Any]] = []
    invocation_traces: list[AIReviewerInvocationTrace] = []
    for ordinal, claim in enumerate(frozen, start=1):
        checkpoint = (
            checkpoint_store.read(ordinal=ordinal, claim=claim)
            if checkpoint_store is not None
            else None
        )
        if checkpoint is not None:
            _verify_checkpoint_binding(
                checkpoint,
                source_draft_sha256=source_draft_sha,
                frozen_claim_bundle_sha256=frozen_bundle_sha,
                frozen_claim=claim,
                model_id=model_id,
                model_version=model_version,
                policy_sha256=policy_sha256,
                toolchain_sha256=toolchain_sha,
            )
            invocation_ids.append(checkpoint.invocation_trace.invocation_id)
            claim_rows.append(_model_row_from_verdict(checkpoint.decision))
            invocation_traces.append(
                _reseal_ai_reviewer_invocation_trace(
                    checkpoint.invocation_trace,
                    resumed_from_checkpoint=True,
                    checkpoint_seal_sha256=checkpoint.seal_sha256,
                )
            )
            continue
        if not hasattr(model, "invoke_json"):
            raise RuntimeError("AI evidence reviewer transport is unavailable")
        user_payload = {
            "schema": "legalbot.ai-evidence-review-input.v1",
            "source_draft_sha256": source_draft_sha,
            "frozen_claim_bundle_sha256": frozen_bundle_sha,
            "material_claim_count": 1,
            "claims": [claim.model_payload()],
            "proposer_confidence": None,
            "chain_of_thought": None,
        }
        started = time.perf_counter()
        response = await model.invoke_json(
            system_prompt=ai_evidence_reviewer_prompt_text(),
            user_payload=user_payload,
            mode="semantic_verify",
        )
        local_duration_ms = round((time.perf_counter() - started) * 1_000)
        if local_duration_ms < 0 or local_duration_ms > MAX_REVIEW_INVOCATION_DURATION_MS:
            raise ValueError("AI reviewer local invocation timing is outside its bound")
        invocation_id, parsed, trace = _parse_reviewer_transport_response(
            response,
            claim_id=claim.identity.claim_id,
            local_duration_ms=local_duration_ms,
        )
        rows = _model_claim_rows(parsed)
        if len(rows) != 1 or str(rows[0].get("claim_id") or "") != claim.identity.claim_id:
            raise ValueError("AI reviewer claim identity differs from its frozen input")
        decision = _claim_verdict_from_model_row(frozen=claim, row=rows[0])
        checkpoint_seal: str | None = None
        if checkpoint_store is not None:
            sealed_checkpoint = seal_ai_reviewer_claim_checkpoint(
                source_draft_sha256=source_draft_sha,
                frozen_claim_bundle_sha256=frozen_bundle_sha,
                frozen_claim=claim,
                decision=decision,
                invocation_trace=trace,
                model_id=model_id,
                model_version=model_version,
                policy_sha256=policy_sha256,
                toolchain_sha256=toolchain_sha,
            )
            checkpoint_store.write(
                ordinal=ordinal,
                claim=claim,
                checkpoint=sealed_checkpoint,
            )
            checkpoint_seal = sealed_checkpoint.seal_sha256
        invocation_ids.append(invocation_id)
        claim_rows.append(_model_row_from_verdict(decision))
        invocation_traces.append(
            _reseal_ai_reviewer_invocation_trace(
                trace,
                resumed_from_checkpoint=False,
                checkpoint_seal_sha256=checkpoint_seal,
            )
        )

    if invocation_ids:
        aggregate_invocation_id = invocation_ids[0]
        if len(invocation_ids) > 1:
            aggregate_invocation_id = (
                "review-batch-"
                + hashlib.sha256(_canonical_json({"invocation_ids": invocation_ids})).hexdigest()[
                    :24
                ]
            )
    else:
        aggregate_invocation_id = "review-empty-" + source_draft_sha[:24]
    return seal_ai_evidence_review(
        model_output={"claims": claim_rows},
        source_draft=draft,
        frozen_claims=frozen,
        invocation_id=aggregate_invocation_id,
        invocation_ids=invocation_ids,
        invocation_traces=invocation_traces,
        model_id=model_id,
        model_version=model_version,
        policy_sha256=policy_sha256,
        toolchain_sha256=toolchain_sha,
    )


class ClaimEvidenceAdjudication(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    verdict: ReviewVerdict
    passed: bool
    blocking_reason_codes: tuple[str, ...] = ()
    requires_targeted_narrowing: bool = False
    requires_fresh_review: bool = False

    @field_validator("blocking_reason_codes")
    @classmethod
    def blocking_codes_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_REASON.fullmatch(value) for value in values):
            raise ValueError("AI evidence adjudication blocker is not a safe code")
        if len(values) != len(set(values)):
            raise ValueError("AI evidence adjudication blockers are duplicated")
        return values

    @model_validator(mode="after")
    def verdict_behavior_is_exact(self) -> Self:
        expected_blocker = {
            "partially_supported": "ai_review_partially_supported",
            "unsupported": "ai_review_unsupported",
            "contradicted": "ai_review_contradicted",
            "uncertain": "ai_review_uncertain",
            "not_reviewable": "ai_review_not_reviewable",
        }.get(self.verdict)
        if expected_blocker is None:
            expected: tuple[bool, tuple[str, ...], bool, bool] = (
                True,
                (),
                False,
                False,
            )
        elif self.verdict == "partially_supported":
            expected = (False, (expected_blocker,), True, True)
        else:
            expected = (False, (expected_blocker,), False, False)
        observed = (
            self.passed,
            self.blocking_reason_codes,
            self.requires_targeted_narrowing,
            self.requires_fresh_review,
        )
        if observed != expected:
            raise ValueError("AI evidence adjudication does not implement its verdict")
        return self


class AIEvidenceAdjudication(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.ai-evidence-adjudication.v2"] = Field(
        default="legalbot.ai-evidence-adjudication.v2", alias="schema"
    )
    review_id: str = Field(pattern=r"^ai-review-[0-9a-f]{24}$")
    review_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gates_override_ai: Literal[True] = True
    advisory_recommendations_only: Literal[True] = True
    can_authorize_gates: Literal[False] = False
    may_raise_fail_closed_owner_review_hold: Literal[True] = True
    deterministic_blocking_reason_codes: tuple[str, ...] = ()
    claims: tuple[ClaimEvidenceAdjudication, ...]
    passed: bool
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("deterministic_blocking_reason_codes")
    @classmethod
    def deterministic_codes_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_REASON.fullmatch(value) for value in values):
            raise ValueError("deterministic blocker must be a safe machine code")
        if len(values) != len(set(values)):
            raise ValueError("deterministic blockers are duplicated")
        return values

    @model_validator(mode="after")
    def adjudication_is_consistent_and_sealed(self) -> Self:
        claim_ids = tuple(item.claim_id for item in self.claims)
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("AI evidence adjudication contains duplicate claims")
        expected = not self.deterministic_blocking_reason_codes and all(
            item.passed for item in self.claims
        )
        if self.passed != expected:
            raise ValueError("AI evidence adjudication pass flag is inconsistent")
        if self.seal_sha256 != _sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("AI evidence adjudication seal does not match its contents")
        return self


_VERDICT_BLOCKERS: dict[str, str] = {
    "partially_supported": "ai_review_partially_supported",
    "unsupported": "ai_review_unsupported",
    "contradicted": "ai_review_contradicted",
    "uncertain": "ai_review_uncertain",
    "not_reviewable": "ai_review_not_reviewable",
}


def adjudicate_ai_evidence_review(
    review: AIEvidenceReviewResult,
    *,
    deterministic_blocking_reason_codes: Sequence[str] = (),
) -> AIEvidenceAdjudication:
    """Convert advisory concerns into fail-closed holds, never positive authority."""

    deterministic = tuple(dict.fromkeys(deterministic_blocking_reason_codes))
    claims: list[ClaimEvidenceAdjudication] = []
    for item in review.claims:
        partial = item.verdict == "partially_supported"
        blocker = _VERDICT_BLOCKERS.get(item.verdict)
        claims.append(
            ClaimEvidenceAdjudication(
                claim_id=item.claim_id,
                verdict=item.verdict,
                passed=blocker is None,
                blocking_reason_codes=(blocker,) if blocker else (),
                requires_targeted_narrowing=partial,
                requires_fresh_review=partial,
            )
        )
    material: dict[str, Any] = {
        "schema": AI_EVIDENCE_ADJUDICATION_SCHEMA,
        "review_id": review.review_id,
        "review_seal_sha256": review.seal_sha256,
        "deterministic_gates_override_ai": True,
        "advisory_recommendations_only": True,
        "can_authorize_gates": False,
        "may_raise_fail_closed_owner_review_hold": True,
        "deterministic_blocking_reason_codes": list(deterministic),
        "claims": [item.model_dump(mode="json") for item in claims],
        "passed": not deterministic and all(item.passed for item in claims),
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return AIEvidenceAdjudication.model_validate(material)
