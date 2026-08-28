"""Positive, sealed runtime artifacts required by an owner-canary release.

These contracts contain only safe identities and deterministic dispositions.
They never contain answer, question, claim or source prose.  The circuit uses
them to reject callback booleans that are not bound to the exact runtime job,
answer version, evidence bundle and release-gate report.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..privacy import contains_absolute_private_path, prompt_injection_hits
from ..quality.ai_evidence_reviewer import AIEvidenceReviewResult
from ..quality.evidence import is_citable_authority_lane
from ..types import EvidenceSpan
from .live_suite import canonical_json, sealed_sha256

EVIDENCE_BUNDLE_SCHEMA = "legalbot.owner-canary-evidence-bundle.v1"
DETERMINISTIC_GATE_REPORT_SCHEMA = "legalbot.owner-canary-deterministic-gates.v1"
RELEASE_ATTESTATION_SCHEMA = "legalbot.owner-canary-release-attestation.v1"
CASE_PROJECTION_RECEIPT_SCHEMA = "legalbot.owner-canary-case-projection-receipt.v1"

DETERMINISTIC_RELEASE_GATES = (
    "citation_binding",
    "currentness",
    "evidence_binding",
    "evidence_identity",
    "jurisdiction",
    "material_claim_disposition",
    "privacy",
    "prompt_injection",
    "quotation_accuracy",
    "retrieval_relevance",
    "source_lane",
    "word_target",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_CASE_ID = re.compile(r"^(?:live30|live60)-q[0-9]{2}$")
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OwnerCanaryEvidenceIdentity(BaseModel):
    """Prose-free identity of one frozen EvidenceSpan and deterministic cite."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_span_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    source_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    chunk_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    text_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    locator: str = Field(min_length=1, max_length=255)
    lane: Literal["primary_authority", "official_secondary", "scholarship"]
    jurisdiction: str = Field(min_length=2, max_length=120)
    currentness_status: str = Field(min_length=1, max_length=127)
    index_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    retrieval_route: Literal[
        "exact_authority_identity",
        "exact_legislation_reference",
        "hybrid_rrf",
    ]
    retrieval_relevance_score: float = Field(ge=0.0, le=1.0)
    retrieval_threshold: float = Field(ge=0.0, le=1.0)
    retrieval_threshold_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_threshold_qualified: Literal[True]
    identity_verified: Literal[True]
    currentness_verified: Literal[True]
    citable_authority_lane: Literal[True]
    prompt_injection_safe: Literal[True]
    deterministic_citation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("locator", "jurisdiction", "currentness_status")
    @classmethod
    def safe_labels(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned or contains_absolute_private_path(cleaned):
            raise ValueError("evidence identity contains unsafe metadata")
        return cleaned

    def frozen_claim_identity_row(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_span_id,
            "source_version_id": self.source_version_id,
            "chunk_id": self.chunk_id,
            "content_sha256": self.content_sha256,
            "text_sha256": self.text_sha256,
            "locator": self.locator,
            "lane": self.lane,
            "jurisdiction": self.jurisdiction,
            "currentness_status": self.currentness_status,
            "index_build_id": self.index_build_id,
            "retrieval_route": self.retrieval_route,
            "retrieval_relevance_score": self.retrieval_relevance_score,
            "retrieval_threshold": self.retrieval_threshold,
            "retrieval_threshold_policy_sha256": (self.retrieval_threshold_policy_sha256),
            "retrieval_threshold_qualified": self.retrieval_threshold_qualified,
            "identity_verified": self.identity_verified,
            "currentness_verified": self.currentness_verified,
        }


def _claim_evidence_bundle_sha256(
    *,
    claim_id: str,
    claim_sha256: str,
    evidence: Sequence[OwnerCanaryEvidenceIdentity],
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "schema": "legalbot.frozen-claim-review-identity.v1",
                "claim_id": claim_id,
                "claim_sha256": claim_sha256,
                "evidence": [item.frozen_claim_identity_row() for item in evidence],
            }
        )
    ).hexdigest()


def _evidence_bundle_identity_sha256(
    *,
    source_draft_sha256: str,
    frozen_claim_bundle_sha256: str,
    relevance_threshold_policy_sha256: str,
    claim_evidence_bundle_sha256s: Mapping[str, str],
    evidence: Sequence[OwnerCanaryEvidenceIdentity],
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "schema": "legalbot.owner-canary-evidence-bundle-identity.v1",
                "source_draft_sha256": source_draft_sha256,
                "frozen_claim_bundle_sha256": frozen_claim_bundle_sha256,
                "relevance_threshold_policy_sha256": (relevance_threshold_policy_sha256),
                "claim_evidence_bundle_sha256s": dict(claim_evidence_bundle_sha256s),
                "evidence": [item.model_dump(mode="json") for item in evidence],
            }
        )
    ).hexdigest()


class OwnerCanaryEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-evidence-bundle.v1"] = Field(
        default="legalbot.owner-canary-evidence-bundle.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    jurisdiction: str = Field(min_length=2, max_length=120)
    as_of_date: date
    source_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_claim_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    relevance_threshold_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    claim_evidence_bundle_sha256s: dict[str, str]
    evidence_span_ids: tuple[str, ...]
    evidence: tuple[OwnerCanaryEvidenceIdentity, ...]
    evidence_bundle_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    all_material_claim_evidence_bound: Literal[True]
    all_evidence_identity_verified: Literal[True]
    all_evidence_currentness_verified: Literal[True]
    all_evidence_citable: Literal[True]
    all_evidence_prompt_safe: Literal[True]
    all_evidence_relevance_qualified: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("evidence_span_ids")
    @classmethod
    def evidence_ids_are_safe_unique(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or any(not _SAFE_ID.fullmatch(value) for value in values):
            raise ValueError("evidence bundle needs safe evidence identities")
        if len(values) != len(set(values)):
            raise ValueError("evidence bundle contains duplicate evidence identities")
        return values

    @model_validator(mode="after")
    def evidence_bundle_is_complete_and_sealed(self) -> Self:
        if self.evidence_span_ids != tuple(item.evidence_span_id for item in self.evidence):
            raise ValueError("evidence bundle order differs from its identity list")
        if set(self.claim_evidence_bundle_sha256s) == set() or any(
            not _SAFE_ID.fullmatch(key) or not _SHA256.fullmatch(value)
            for key, value in self.claim_evidence_bundle_sha256s.items()
        ):
            raise ValueError("evidence bundle contains invalid claim identities")
        if any(
            item.retrieval_threshold_policy_sha256 != self.relevance_threshold_policy_sha256
            or item.retrieval_threshold_qualified is not True
            or item.retrieval_relevance_score < item.retrieval_threshold
            for item in self.evidence
        ):
            raise ValueError("evidence bundle contains an unqualified relevance decision")
        expected_identity = _evidence_bundle_identity_sha256(
            source_draft_sha256=self.source_draft_sha256,
            frozen_claim_bundle_sha256=self.frozen_claim_bundle_sha256,
            relevance_threshold_policy_sha256=(self.relevance_threshold_policy_sha256),
            claim_evidence_bundle_sha256s=self.claim_evidence_bundle_sha256s,
            evidence=self.evidence,
        )
        if self.evidence_bundle_identity_sha256 != expected_identity:
            raise ValueError("evidence bundle identity digest does not match")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary evidence bundle seal does not match")
        return self


def seal_owner_canary_evidence_bundle(
    *,
    run_id: str,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    case_id: str,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    job_id: str,
    answer_version_id: str,
    jurisdiction: str,
    as_of_date: date,
    ai_review: AIEvidenceReviewResult,
    evidence_by_id: Mapping[str, EvidenceSpan],
    deterministic_citations: Mapping[str, str],
) -> OwnerCanaryEvidenceBundle:
    """Recompute a positive evidence identity from actual frozen EvidenceSpans."""

    if not ai_review.passed or not ai_review.claims:
        raise ValueError("positive evidence bundle requires a passing material-claim review")
    ordered_ids = tuple(
        dict.fromkeys(
            evidence_id for claim in ai_review.claims for evidence_id in claim.evidence_span_ids
        )
    )
    if set(evidence_by_id) != set(ordered_ids) or set(deterministic_citations) != set(ordered_ids):
        raise ValueError("evidence/citation inputs differ from the reviewed frozen bundle")
    threshold_policy_digests = {
        span.retrieval_threshold_policy_sha256 for span in evidence_by_id.values()
    }
    if len(threshold_policy_digests) != 1 or None in threshold_policy_digests:
        raise ValueError("evidence bundle requires one frozen relevance-threshold policy")
    relevance_threshold_policy_sha256 = str(next(iter(threshold_policy_digests)))
    evidence_rows: list[OwnerCanaryEvidenceIdentity] = []
    for evidence_id in ordered_ids:
        span = evidence_by_id[evidence_id]
        citation = " ".join(deterministic_citations[evidence_id].split())
        lane = str(span.lane)
        if (
            span.id != evidence_id
            or span.index_build_id != candidate_build_id
            or span.jurisdiction != jurisdiction
            or lane not in {"primary_authority", "official_secondary", "scholarship"}
            or not span.identity_verified
            or not span.currentness_verified
            or not is_citable_authority_lane(span)
            or prompt_injection_hits(span.text)
            or not citation
            or span.retrieval_route
            not in {
                "exact_authority_identity",
                "exact_legislation_reference",
                "hybrid_rrf",
            }
            or span.retrieval_relevance_score is None
            or span.retrieval_threshold is None
            or span.retrieval_threshold_qualified is not True
            or span.retrieval_relevance_score < span.retrieval_threshold
            or span.retrieval_threshold_policy_sha256 != relevance_threshold_policy_sha256
            or any(
                contains_absolute_private_path(value)
                for value in (span.text, span.locator, span.jurisdiction, citation)
            )
        ):
            raise ValueError("evidence bundle contains an ineligible frozen EvidenceSpan")
        evidence_rows.append(
            OwnerCanaryEvidenceIdentity(
                evidence_span_id=span.id,
                source_version_id=span.source_version_id,
                chunk_id=span.chunk_id,
                content_sha256=span.content_sha256,
                text_sha256=_text_sha256(span.text),
                locator=span.locator,
                lane=cast(
                    Literal["primary_authority", "official_secondary", "scholarship"],
                    lane,
                ),
                jurisdiction=span.jurisdiction,
                currentness_status=span.currentness_status,
                index_build_id=span.index_build_id,
                retrieval_route=cast(
                    Literal[
                        "exact_authority_identity",
                        "exact_legislation_reference",
                        "hybrid_rrf",
                    ],
                    span.retrieval_route,
                ),
                retrieval_relevance_score=span.retrieval_relevance_score,
                retrieval_threshold=span.retrieval_threshold,
                retrieval_threshold_policy_sha256=(relevance_threshold_policy_sha256),
                retrieval_threshold_qualified=True,
                identity_verified=True,
                currentness_verified=True,
                citable_authority_lane=True,
                prompt_injection_safe=True,
                deterministic_citation_sha256=_text_sha256(citation),
            )
        )
    by_id = {item.evidence_span_id: item for item in evidence_rows}
    claim_bundles: dict[str, str] = {}
    for claim in ai_review.claims:
        computed = _claim_evidence_bundle_sha256(
            claim_id=claim.claim_id,
            claim_sha256=claim.claim_sha256,
            evidence=tuple(by_id[evidence_id] for evidence_id in claim.evidence_span_ids),
        )
        if computed != claim.evidence_bundle_sha256:
            raise ValueError("evidence bundle differs from the AI-reviewed claim identity")
        claim_bundles[claim.claim_id] = computed
    identity_sha = _evidence_bundle_identity_sha256(
        source_draft_sha256=ai_review.source_draft_sha256,
        frozen_claim_bundle_sha256=ai_review.frozen_claim_bundle_sha256,
        relevance_threshold_policy_sha256=relevance_threshold_policy_sha256,
        claim_evidence_bundle_sha256s=claim_bundles,
        evidence=evidence_rows,
    )
    material: dict[str, Any] = {
        "schema": EVIDENCE_BUNDLE_SCHEMA,
        "run_id": run_id,
        "authorization_seal_sha256": authorization_seal_sha256,
        "canary_manifest_seal_sha256": canary_manifest_seal_sha256,
        "case_id": case_id,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "job_id": job_id,
        "answer_version_id": answer_version_id,
        "jurisdiction": jurisdiction,
        "as_of_date": as_of_date.isoformat(),
        "source_draft_sha256": ai_review.source_draft_sha256,
        "frozen_claim_bundle_sha256": ai_review.frozen_claim_bundle_sha256,
        "relevance_threshold_policy_sha256": relevance_threshold_policy_sha256,
        "claim_evidence_bundle_sha256s": claim_bundles,
        "evidence_span_ids": list(ordered_ids),
        "evidence": [item.model_dump(mode="json") for item in evidence_rows],
        "evidence_bundle_identity_sha256": identity_sha,
        "all_material_claim_evidence_bound": True,
        "all_evidence_identity_verified": True,
        "all_evidence_currentness_verified": True,
        "all_evidence_citable": True,
        "all_evidence_prompt_safe": True,
        "all_evidence_relevance_qualified": True,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerCanaryEvidenceBundle.model_validate(material)


class OwnerCanaryDeterministicGateReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-deterministic-gates.v1"] = Field(
        default="legalbot.owner-canary-deterministic-gates.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_word_target: int = Field(ge=1_000, le=10_000)
    word_count: int = Field(ge=1)
    evidence_bundle_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    relevance_threshold_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_release_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    gate_implementation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    gates: dict[str, bool]
    hard_failure_codes: tuple[()] = ()
    positive: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def deterministic_gates_are_exact_positive_and_sealed(self) -> Self:
        if tuple(self.gates) != DETERMINISTIC_RELEASE_GATES or not all(self.gates.values()):
            raise ValueError("deterministic release gates are incomplete or failed")
        minimum = math.ceil(self.requested_word_target * 0.95)
        maximum = math.floor(self.requested_word_target * 1.05)
        if not minimum <= self.word_count <= maximum or not self.gates["word_target"]:
            raise ValueError("deterministic word gate differs from canonical tolerance")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("deterministic release-gate report seal does not match")
        return self


def seal_owner_canary_deterministic_gate_report(
    *,
    run_id: str,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    case_id: str,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    job_id: str,
    answer_version_id: str,
    answer_sha256: str,
    requested_word_target: int,
    word_count: int,
    evidence_bundle: OwnerCanaryEvidenceBundle,
    source_release_report_sha256: str,
    gate_implementation_sha256: str,
    passed_gates: Mapping[str, bool],
) -> OwnerCanaryDeterministicGateReport:
    gates = {key: bool(passed_gates.get(key, False)) for key in DETERMINISTIC_RELEASE_GATES}
    gates["word_target"] = (
        math.ceil(requested_word_target * 0.95)
        <= word_count
        <= math.floor(requested_word_target * 1.05)
    )
    if set(passed_gates) != set(DETERMINISTIC_RELEASE_GATES):
        raise ValueError("source deterministic gate set differs from the exact policy")
    material: dict[str, Any] = {
        "schema": DETERMINISTIC_GATE_REPORT_SCHEMA,
        "run_id": run_id,
        "authorization_seal_sha256": authorization_seal_sha256,
        "canary_manifest_seal_sha256": canary_manifest_seal_sha256,
        "case_id": case_id,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "job_id": job_id,
        "answer_version_id": answer_version_id,
        "answer_sha256": answer_sha256,
        "requested_word_target": requested_word_target,
        "word_count": word_count,
        "evidence_bundle_seal_sha256": evidence_bundle.seal_sha256,
        "relevance_threshold_policy_sha256": (evidence_bundle.relevance_threshold_policy_sha256),
        "source_release_report_sha256": source_release_report_sha256,
        "gate_implementation_sha256": gate_implementation_sha256,
        "gates": gates,
        "hard_failure_codes": [],
        "positive": True,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerCanaryDeterministicGateReport.model_validate(material)


class OwnerCanaryReleaseAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-release-attestation.v1"] = Field(
        default="legalbot.owner-canary-release-attestation.v1", alias="schema"
    )
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_artifact_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    runtime_release_state: Literal["verified_full"]
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_word_target: int = Field(ge=1_000, le=10_000)
    word_count: int = Field(ge=1)
    evidence_bundle_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    relevance_threshold_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gate_report_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_release_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    positive_release: Literal[True]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def positive_release_is_word_bound_and_sealed(self) -> Self:
        if (
            not math.ceil(self.requested_word_target * 0.95)
            <= self.word_count
            <= math.floor(self.requested_word_target * 1.05)
        ):
            raise ValueError("positive release is outside the canonical word tolerance")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("release attestation seal does not match")
        return self


def seal_owner_canary_release_attestation(
    *,
    answer_artifact_id: str,
    runtime_release_state: Literal["verified_full"],
    evidence_bundle: OwnerCanaryEvidenceBundle,
    deterministic_gate_report: OwnerCanaryDeterministicGateReport,
) -> OwnerCanaryReleaseAttestation:
    binding_fields = (
        "run_id",
        "authorization_seal_sha256",
        "canary_manifest_seal_sha256",
        "case_id",
        "candidate_build_id",
        "candidate_manifest_sha256",
        "job_id",
        "answer_version_id",
    )
    if any(
        getattr(evidence_bundle, field) != getattr(deterministic_gate_report, field)
        for field in binding_fields
    ):
        raise ValueError("release gate and evidence bundle identities differ")
    if deterministic_gate_report.evidence_bundle_seal_sha256 != evidence_bundle.seal_sha256:
        raise ValueError("release gate names another evidence bundle")
    if (
        deterministic_gate_report.relevance_threshold_policy_sha256
        != evidence_bundle.relevance_threshold_policy_sha256
    ):
        raise ValueError("release gate names another relevance-threshold policy")
    material: dict[str, Any] = {
        "schema": RELEASE_ATTESTATION_SCHEMA,
        **{field: getattr(evidence_bundle, field) for field in binding_fields},
        "answer_artifact_id": answer_artifact_id,
        "runtime_release_state": runtime_release_state,
        "answer_sha256": deterministic_gate_report.answer_sha256,
        "requested_word_target": deterministic_gate_report.requested_word_target,
        "word_count": deterministic_gate_report.word_count,
        "evidence_bundle_seal_sha256": evidence_bundle.seal_sha256,
        "relevance_threshold_policy_sha256": (evidence_bundle.relevance_threshold_policy_sha256),
        "deterministic_gate_report_seal_sha256": deterministic_gate_report.seal_sha256,
        "source_release_report_sha256": deterministic_gate_report.source_release_report_sha256,
        "positive_release": True,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return OwnerCanaryReleaseAttestation.model_validate(material)


def verify_positive_release_artifacts(
    *,
    run_id: str,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    case_id: str,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    job_id: str,
    answer_version_id: str,
    answer_sha256: str,
    word_count: int,
    ai_review: AIEvidenceReviewResult,
    evidence_bundle: OwnerCanaryEvidenceBundle,
    deterministic_gate_report: OwnerCanaryDeterministicGateReport,
    release_attestation: OwnerCanaryReleaseAttestation,
) -> None:
    """Reconcile all positive artifacts instead of trusting a released boolean."""

    expected = {
        "run_id": run_id,
        "authorization_seal_sha256": authorization_seal_sha256,
        "canary_manifest_seal_sha256": canary_manifest_seal_sha256,
        "case_id": case_id,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "job_id": job_id,
        "answer_version_id": answer_version_id,
        "answer_sha256": answer_sha256,
        "word_count": word_count,
    }
    for artifact in (evidence_bundle, deterministic_gate_report, release_attestation):
        for field, value in expected.items():
            if hasattr(artifact, field) and getattr(artifact, field) != value:
                raise ValueError("positive release artifact differs from the attempt result")
    expected_claim_bundles = {
        claim.claim_id: claim.evidence_bundle_sha256 for claim in ai_review.claims
    }
    if (
        evidence_bundle.source_draft_sha256 != ai_review.source_draft_sha256
        or evidence_bundle.frozen_claim_bundle_sha256 != ai_review.frozen_claim_bundle_sha256
        or evidence_bundle.claim_evidence_bundle_sha256s != expected_claim_bundles
        or deterministic_gate_report.evidence_bundle_seal_sha256 != evidence_bundle.seal_sha256
        or release_attestation.evidence_bundle_seal_sha256 != evidence_bundle.seal_sha256
        or release_attestation.deterministic_gate_report_seal_sha256
        != deterministic_gate_report.seal_sha256
        or release_attestation.source_release_report_sha256
        != deterministic_gate_report.source_release_report_sha256
        or deterministic_gate_report.relevance_threshold_policy_sha256
        != evidence_bundle.relevance_threshold_policy_sha256
        or release_attestation.relevance_threshold_policy_sha256
        != evidence_bundle.relevance_threshold_policy_sha256
    ):
        raise ValueError("positive release artifacts are not mutually bound")


class OwnerCanaryCaseProjectionReceipt(BaseModel):
    """Prose-free receipt for one fully written owner-review case package."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.owner-canary-case-projection-receipt.v1"] = Field(
        default="legalbot.owner-canary-case-projection-receipt.v1", alias="schema"
    )
    workspace_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    authorization_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    canary_manifest_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_id: str = Field(pattern=r"^(?:live30|live60)-q[0-9]{2}$")
    candidate_build_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    candidate_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    job_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_version_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    answer_artifact_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    attempt_result_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    answer_byte_count: int = Field(ge=1)
    word_count: int = Field(ge=1)
    release_projection_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    standards_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    gap_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    metrics_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retry_projection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_bundle_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_review_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ai_adjudication_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_invocation_trace_seal_sha256s: tuple[str, ...] = ()
    reviewer_total_duration_ms: int = Field(ge=0)
    reviewer_total_input_tokens: int = Field(ge=0)
    reviewer_total_output_tokens: int = Field(ge=0)
    reviewer_token_counts_complete: bool
    standards_report_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    deterministic_gate_report_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_attestation_seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authoritative_answer_recomputed: Literal[True]
    privacy_passed: Literal[True]
    positive_artifacts_reverified: Literal[True]
    plaintext_question_included: Literal[False]
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def receipt_is_sealed(self) -> Self:
        if any(
            not _SHA256.fullmatch(value) for value in self.reviewer_invocation_trace_seal_sha256s
        ) or len(self.reviewer_invocation_trace_seal_sha256s) != len(
            set(self.reviewer_invocation_trace_seal_sha256s)
        ):
            raise ValueError("owner-canary receipt has invalid reviewer trace identities")
        if self.seal_sha256 != sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("owner-canary projection receipt seal does not match")
        return self


def verify_case_projection_receipt(
    *,
    receipt: OwnerCanaryCaseProjectionReceipt,
    workspace_seal_sha256: str,
    attempt_result_seal_sha256: str,
    run_id: str,
    authorization_seal_sha256: str,
    canary_manifest_seal_sha256: str,
    case_id: str,
    candidate_build_id: str,
    candidate_manifest_sha256: str,
    job_id: str,
    answer_version_id: str,
    answer_artifact_id: str,
    answer_sha256: str,
    word_count: int,
    evidence_bundle_seal_sha256: str,
    ai_review_seal_sha256: str,
    ai_adjudication_seal_sha256: str,
    standards_report_seal_sha256: str,
    deterministic_gate_report_seal_sha256: str,
    release_attestation_seal_sha256: str,
) -> None:
    expected: dict[str, str | int] = {
        "workspace_seal_sha256": workspace_seal_sha256,
        "attempt_result_seal_sha256": attempt_result_seal_sha256,
        "run_id": run_id,
        "authorization_seal_sha256": authorization_seal_sha256,
        "canary_manifest_seal_sha256": canary_manifest_seal_sha256,
        "case_id": case_id,
        "candidate_build_id": candidate_build_id,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "job_id": job_id,
        "answer_version_id": answer_version_id,
        "answer_artifact_id": answer_artifact_id,
        "answer_sha256": answer_sha256,
        "word_count": word_count,
        "evidence_bundle_seal_sha256": evidence_bundle_seal_sha256,
        "ai_review_seal_sha256": ai_review_seal_sha256,
        "ai_adjudication_seal_sha256": ai_adjudication_seal_sha256,
        "standards_report_seal_sha256": standards_report_seal_sha256,
        "deterministic_gate_report_seal_sha256": deterministic_gate_report_seal_sha256,
        "release_attestation_seal_sha256": release_attestation_seal_sha256,
    }
    if any(getattr(receipt, field) != value for field, value in expected.items()):
        raise ValueError("owner-canary projection receipt differs from the runtime result")
