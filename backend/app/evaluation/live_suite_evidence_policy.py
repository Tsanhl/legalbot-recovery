"""Actor-neutral v2 evidence verification policy.

Gold is a proof bundle that passes policy. Human approval with a broken hash
is HOLD. An AI claim without mechanical+semantic proof is HOLD. There is no
``ai_confidence`` gold field. V1 identity-as-truth readers remain loadable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .live30 import assert_safe_evaluation_payload
from .live_suite import sealed_sha256
from .live_suite_semantic_result import SemanticVerificationResultV2
from .live_suite_span_accuracy import check_user_span_exact_match
from .prompt_templates import SEMANTIC_VERIFIER_TEMPLATE_SHA256

EVIDENCE_POLICY_V2_SCHEMA = "legalbot.evidence-verification-policy.v2"
EXPERT_QUALIFICATION_V2_SCHEMA = "legalbot.live-expert-qualification.v2"
REVIEW_ATTESTATION_V2_SCHEMA = "legalbot.review-attestation.v2"
CURRENTNESS_REVIEW_V2_SCHEMA = "legalbot.case-proposition-currentness-review.v2"
CONTRARY_REVIEW_V2_SCHEMA = "legalbot.contrary-authority-review.v2"
PROOF_BUNDLE_SCHEMA = "legalbot.evidence-proof-bundle.v2"

ActorType = Literal["human", "ai", "hybrid", "deterministic"]
EvidenceRole = Literal[
    "evidence_reviewer",
    "legal_reviewer",
    "currentness_reviewer",
    "contrary_authority_reviewer",
    "semantic_verifier",
    "adjudicator",
]
VerificationMethod = Literal[
    "exact_mechanical",
    "ai_evidence_verification",
    "human_attestation",
    "hybrid",
    "multi_verifier_consensus",
]
FinalVerificationStatus = Literal["VERIFIED", "HOLD"]

# Prompt hashes are computed from tracked template bytes. Re-exported so
# existing callers keep a stable import path.


class ActorProvenanceV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actor_type: ActorType
    actor_ref: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    role: EvidenceRole
    verification_method: VerificationMethod
    model_id: str | None = None
    model_version: str | None = None
    policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    prompt_template_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    toolchain_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_set_id: str | None = None
    invocation_id: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._:-]{2,127}$")
    chain_of_thought: Literal[None] = None

    @model_validator(mode="after")
    def ai_records_toolchain(self) -> Self:
        if self.actor_type == "ai":
            required = (
                self.model_id,
                self.model_version,
                self.policy_sha256,
                self.prompt_template_sha256,
                self.toolchain_sha256,
                self.source_set_id,
                self.invocation_id,
            )
            if any(item is None for item in required):
                raise ValueError("AI provenance must record model, policy and invocation")
        return self


class ReviewAttestationV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.review-attestation.v2"] = Field(
        default="legalbot.review-attestation.v2", alias="schema"
    )
    actor: ActorProvenanceV2
    issue_id: str
    attestation: Literal["supported", "unsupported", "knowledge_gap", "limited"]
    independent_of_proposer: bool
    second_attestation_required: bool = False
    second_attestation_present: bool = False
    notes_code: str | None = Field(default=None, pattern=r"^[a-z0-9._:-]{1,80}$")


class CurrentnessReviewV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.case-proposition-currentness-review.v2"] = Field(
        default="legalbot.case-proposition-currentness-review.v2", alias="schema"
    )
    actor: ActorProvenanceV2
    status: Literal["confirmed_current", "qualified_current", "HOLD"]
    limiting_authority_ids: tuple[str, ...] = ()
    as_of_date: str

    @model_validator(mode="after")
    def qualified_current_has_limits(self) -> Self:
        if self.status == "qualified_current" and not self.limiting_authority_ids:
            raise ValueError("qualified_current still needs limiting-authority IDs")
        return self


class ContraryAuthorityReviewV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.contrary-authority-review.v2"] = Field(
        default="legalbot.contrary-authority-review.v2", alias="schema"
    )
    actor: ActorProvenanceV2
    status: Literal[
        "reviewed_none_in_defined_source_set",
        "reviewed_and_bound",
        "unresolved",
        "HOLD",
    ]
    defined_source_set_id: str
    means_english_law_has_no_contrary_authority: Literal[False] = False
    bound_contrary_span_count: int = Field(ge=0)
    critical_or_disputed: bool = False
    independent_second_attestation: bool = False

    @model_validator(mode="after")
    def contrary_is_named_set_only(self) -> Self:
        if self.means_english_law_has_no_contrary_authority:
            raise ValueError("contrary review must not claim no English authority exists")
        if self.status == "reviewed_and_bound" and self.bound_contrary_span_count < 1:
            raise ValueError("reviewed_and_bound requires a contrary span")
        if (
            self.critical_or_disputed
            and not self.independent_second_attestation
            and self.status != "HOLD"
        ):
            raise ValueError("critical or disputed contrary review needs a second attestation")
        return self


class EvidenceProofBundleV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.evidence-proof-bundle.v2"] = Field(
        default="legalbot.evidence-proof-bundle.v2", alias="schema"
    )
    exact_mechanical_passed: bool
    semantic_verifier_passed: bool
    currentness_passed: bool | None = None
    contrary_passed: bool | None = None
    identity_passed: bool
    hash_passed: bool
    locator_passed: bool
    jurisdiction_passed: bool
    semantic_passed: bool
    verification_coverage: float = Field(ge=0.0, le=1.0)
    unresolved_check_count: int = Field(ge=0)
    unsupported_claim_count: int = Field(ge=0)
    contradiction_count: int = Field(ge=0)
    proposer: ActorProvenanceV2
    verifier: ActorProvenanceV2
    currentness: CurrentnessReviewV2 | None = None
    contrary: ContraryAuthorityReviewV2 | None = None
    attestation: ReviewAttestationV2 | None = None
    span_count: int = Field(ge=0)
    invented_span: Literal[False] = False

    @model_validator(mode="after")
    def proposer_cannot_self_approve(self) -> Self:
        if (
            self.proposer.invocation_id
            and self.verifier.invocation_id
            and self.proposer.invocation_id == self.verifier.invocation_id
        ):
            raise ValueError("proposer invocation cannot stamp approval")
        if (
            self.proposer.prompt_template_sha256
            and self.verifier.prompt_template_sha256
            and self.proposer.prompt_template_sha256 == self.verifier.prompt_template_sha256
            and self.verifier.role == "semantic_verifier"
        ):
            raise ValueError("semantic verifier must use a different prompt template")
        return self


class LiveExpertQualificationV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.live-expert-qualification.v2"] = Field(
        default="legalbot.live-expert-qualification.v2", alias="schema"
    )
    suite_id: Literal["live-evaluation-60-v1"]
    policy_schema: Literal["legalbot.evidence-verification-policy.v2"]
    as_of_date: str
    purpose: Literal["evaluation_only"]
    eligible_for_training: Literal[False] = False
    training_export_allowed: Literal[False] = False
    index_build_id: str
    proof: EvidenceProofBundleV2
    disposition: Literal["qualified", "limited", "knowledge_gap"]
    final_verification_status: FinalVerificationStatus
    issue_id: str
    case_id: str
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def gold_is_proof_based(self) -> Self:
        if self.final_verification_status == "VERIFIED":
            proof = self.proof
            if not (proof.exact_mechanical_passed or self.disposition == "knowledge_gap"):
                raise ValueError("VERIFIED positive gold requires exact mechanical match")
            if self.disposition == "knowledge_gap" and proof.invented_span:
                raise ValueError("knowledge_gap must not invent a span")
            if (
                proof.verification_coverage != 1.0
                or proof.unresolved_check_count != 0
                or proof.unsupported_claim_count != 0
                or proof.contradiction_count != 0
            ):
                raise ValueError("VERIFIED requires complete unresolved-check-free coverage")
        dumped = self.model_dump(mode="json", by_alias=True)
        if self.seal_sha256 != sealed_sha256(dumped):
            raise ValueError("v2 qualification seal does not match its contents")
        return self


def _confidence_only_gold(payload: Mapping[str, Any]) -> bool:
    if "ai_confidence" in payload:
        return True
    proof = payload.get("proof")
    if not isinstance(proof, Mapping):
        return "ai_confidence" in payload and not payload.get("exact_mechanical_passed")
    required = (
        proof.get("exact_mechanical_passed"),
        proof.get("semantic_verifier_passed"),
        proof.get("hash_passed"),
        proof.get("locator_passed"),
    )
    return payload.get("ai_confidence") is not None and not all(required)


def evaluate_proof_bundle(
    *,
    proof: EvidenceProofBundleV2,
    disposition: str,
    currentness_required: bool = False,
    contrary_required: bool = False,
    human_attestation: bool = False,
) -> dict[str, Any]:
    """Return VERIFIED or HOLD from the proof bundle. Never from identity or confidence."""

    blockers: list[str] = []
    if proof.proposer.invocation_id == proof.verifier.invocation_id:
        blockers.append("self_approve_forbidden")
    if disposition in {"qualified", "limited"}:
        if not proof.exact_mechanical_passed or not proof.hash_passed:
            blockers.append("exact_hash_or_locator_failed")
        if not proof.semantic_verifier_passed or not proof.semantic_passed:
            blockers.append("semantic_verifier_failed")
        if proof.span_count < 1:
            blockers.append("positive_disposition_requires_span")
        if disposition == "limited" and proof.attestation is None:
            blockers.append("limited_requires_limitation_attestation")
    if disposition == "knowledge_gap":
        if proof.invented_span or proof.span_count > 0:
            blockers.append("knowledge_gap_must_not_invent_span")
        if proof.attestation is None or proof.attestation.attestation != "knowledge_gap":
            blockers.append("knowledge_gap_requires_explicit_attestation")
    if currentness_required and proof.currentness_passed is not True:
        blockers.append("currentness_unresolved")
    if contrary_required and proof.contrary_passed is not True:
        blockers.append("contrary_unresolved")
    if proof.contrary is not None and proof.contrary.status in {"unresolved", "HOLD"}:
        blockers.append("contrary_unresolved")
    if (
        proof.verification_coverage != 1.0
        or proof.unresolved_check_count != 0
        or proof.unsupported_claim_count != 0
        or proof.contradiction_count != 0
    ):
        blockers.append("verification_coverage_incomplete")
    if human_attestation and not proof.hash_passed:
        blockers.append("human_attestation_cannot_override_hash_failure")
    status: FinalVerificationStatus = "HOLD" if blockers else "VERIFIED"
    limited_from_contrary = (
        status == "HOLD"
        and "contrary_unresolved" in blockers
        and proof.span_count >= 1
        and proof.exact_mechanical_passed
    )
    payload = {
        "schema": EVIDENCE_POLICY_V2_SCHEMA,
        "final_verification_status": status,
        "disposition": "limited"
        if limited_from_contrary and disposition in {"qualified", "limited"}
        else disposition,
        "blocking_reason_codes": blockers,
        "verification_coverage": proof.verification_coverage,
        "unresolved_check_count": proof.unresolved_check_count,
        "unsupported_claim_count": proof.unsupported_claim_count,
        "contradiction_count": proof.contradiction_count,
        "ai_confidence_gold_field": False,
        "identity_is_not_truth": True,
        "writes_active": False,
    }
    assert_safe_evaluation_payload(payload)
    return payload


def hold_confidence_only_claim(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Confidence or identity without a proof bundle cannot become gold."""

    return {
        "schema": EVIDENCE_POLICY_V2_SCHEMA,
        "final_verification_status": "HOLD",
        "blocking_reason_codes": ["confidence_or_identity_is_not_gold"],
        "ai_confidence_gold_field": "ai_confidence" in payload,
        "writes_active": False,
    }


def run_semantic_verifier(
    *,
    proposer: ActorProvenanceV2,
    verifier: ActorProvenanceV2,
    semantic_result: SemanticVerificationResultV2 | None = None,
    claims_supported: bool | None = None,
    contradiction_count: int = 0,
    unsupported_claim_count: int = 0,
) -> dict[str, Any]:
    """Independent semantic check. A caller boolean cannot mint VERIFIED gold."""

    blockers: list[str] = []
    if verifier.role != "semantic_verifier":
        blockers.append("semantic_role_required")
    if proposer.invocation_id == verifier.invocation_id:
        blockers.append("self_approve_forbidden")
    if proposer.prompt_template_sha256 == verifier.prompt_template_sha256:
        blockers.append("semantic_template_must_differ")
    if semantic_result is None:
        blockers.append("sealed_semantic_result_required")
        if claims_supported is True:
            blockers.append("caller_boolean_cannot_create_verified_gold")
    else:
        if semantic_result.verifier_invocation_id == proposer.invocation_id:
            blockers.append("self_approve_forbidden")
        if semantic_result.verifier_prompt_sha256 != SEMANTIC_VERIFIER_TEMPLATE_SHA256:
            blockers.append("semantic_prompt_hash_mismatch")
        if not semantic_result.passed:
            blockers.append("semantic_claims_unsupported")
        contradiction_count = semantic_result.contradiction_count
        unsupported_claim_count = semantic_result.unsupported_claim_count
    if contradiction_count or unsupported_claim_count:
        blockers.append("semantic_contradiction_or_unsupported_claim")
    payload = {
        "schema": "legalbot.semantic-verifier-result.v2",
        "passed": not blockers,
        "blocking_reason_codes": blockers,
        "private_chain_of_thought": False,
        "ai_confidence_gold_field": False,
        "sealed_result": semantic_result is not None,
    }
    assert_safe_evaluation_payload(payload)
    return payload


def derive_mechanical_facts(reports: Sequence[Mapping[str, Any]]) -> dict[str, bool]:
    """Derive identity/hash/locator/jurisdiction from exact-match reports."""

    if not reports:
        return {
            "identity_passed": False,
            "hash_passed": False,
            "locator_passed": False,
            "jurisdiction_passed": False,
            "exact_mechanical_passed": False,
        }
    identity = all(item.get("identity_passed") is True for item in reports)
    hashes = all(item.get("hash_passed") is True for item in reports)
    locator = all(item.get("locator_passed") is True for item in reports)
    jurisdiction = all(item.get("jurisdiction_passed") is True for item in reports)
    exact = all(item.get("exact_match") is True for item in reports)
    return {
        "identity_passed": identity and exact,
        "hash_passed": hashes and exact,
        "locator_passed": locator and exact,
        "jurisdiction_passed": jurisdiction and exact,
        "exact_mechanical_passed": exact and identity and hashes and locator,
    }


def verify_spans_mechanical(
    spans: Sequence[Mapping[str, Any]],
    *,
    catalog_path: Any | None = None,
    repair: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the existing fail-closed exact-match verifier on every span."""

    reports: list[dict[str, Any]] = []
    for span in spans:
        reports.append(
            check_user_span_exact_match(
                chunk_id=str(span["chunk_id"]),
                content_sha256=str(span["content_sha256"]),
                legal_locator=str(span["legal_locator"]),
                source_version_id=span.get("source_version_id"),
                catalog_path=catalog_path,
                repair=repair,
                legal_authority_id=span.get("legal_authority_id"),
                legal_role=span.get("legal_role"),
                jurisdiction=span.get("jurisdiction"),
                source_type=span.get("source_type"),
                stable_source_id=span.get("stable_source_id"),
            )
        )
    facts = derive_mechanical_facts(reports)
    payload = {
        "passed": facts["exact_mechanical_passed"],
        "span_count": len(reports),
        "reports": reports,
        **facts,
    }
    return payload


def run_evidence_pipeline(
    *,
    disposition: str,
    proposer: ActorProvenanceV2,
    verifier: ActorProvenanceV2,
    spans: Sequence[Mapping[str, Any]] = (),
    exact_mechanical_passed: bool | None = None,
    semantic_claims_supported: bool | None = None,
    semantic_result: SemanticVerificationResultV2 | None = None,
    _test_only_semantic_result: SemanticVerificationResultV2 | None = None,
    currentness: CurrentnessReviewV2 | None = None,
    contrary: ContraryAuthorityReviewV2 | None = None,
    attestation: ReviewAttestationV2 | None = None,
    currentness_required: bool = False,
    contrary_required: bool = False,
    catalog_path: Any | None = None,
    repair: Mapping[str, Any] | None = None,
    human_attestation: bool = False,
    incoming_payload: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """proposer → exact-match → independent semantic → currentness/contrary → VERIFIED|HOLD."""

    if incoming_payload is not None and _confidence_only_gold(incoming_payload):
        return hold_confidence_only_claim(incoming_payload)
    sealed_semantic = semantic_result or _test_only_semantic_result
    if spans:
        mechanical = verify_spans_mechanical(spans, catalog_path=catalog_path, repair=repair)
        facts = derive_mechanical_facts(mechanical["reports"])
        mechanical_passed = facts["exact_mechanical_passed"]
        identity_passed = facts["identity_passed"]
        hash_passed = facts["hash_passed"]
        locator_passed = facts["locator_passed"]
        jurisdiction_passed = facts["jurisdiction_passed"]
    elif disposition == "knowledge_gap":
        mechanical_passed = True
        identity_passed = True
        hash_passed = True
        locator_passed = True
        jurisdiction_passed = True
    else:
        mechanical_passed = False
        identity_passed = False
        hash_passed = False
        locator_passed = False
        jurisdiction_passed = False
    if exact_mechanical_passed is False:
        mechanical_passed = False
        hash_passed = False
    if (
        exact_mechanical_passed is True
        and disposition != "knowledge_gap"
        and not (spans and mechanical_passed)
    ):
        mechanical_passed = False
        identity_passed = False
        hash_passed = False
        locator_passed = False
        jurisdiction_passed = False
    if disposition == "knowledge_gap" and sealed_semantic is None:
        semantic = {
            "passed": proposer.invocation_id != verifier.invocation_id,
            "blocking_reason_codes": (
                ["self_approve_forbidden"]
                if proposer.invocation_id == verifier.invocation_id
                else []
            ),
        }
    else:
        semantic = run_semantic_verifier(
            proposer=proposer,
            verifier=verifier,
            semantic_result=sealed_semantic,
            claims_supported=semantic_claims_supported,
        )
    proof = EvidenceProofBundleV2(
        exact_mechanical_passed=mechanical_passed if disposition != "knowledge_gap" else True,
        semantic_verifier_passed=semantic["passed"] is True,
        currentness_passed=None if currentness is None else currentness.status != "HOLD",
        contrary_passed=None if contrary is None else contrary.status not in {"unresolved", "HOLD"},
        identity_passed=identity_passed if disposition != "knowledge_gap" else True,
        hash_passed=hash_passed if disposition != "knowledge_gap" else True,
        locator_passed=locator_passed if disposition != "knowledge_gap" else True,
        jurisdiction_passed=jurisdiction_passed if disposition != "knowledge_gap" else True,
        semantic_passed=semantic["passed"] is True,
        verification_coverage=1.0
        if semantic["passed"] and (mechanical_passed or disposition == "knowledge_gap")
        else 0.0,
        unresolved_check_count=0
        if not semantic["blocking_reason_codes"]
        and (mechanical_passed or disposition == "knowledge_gap")
        else 1,
        unsupported_claim_count=0
        if sealed_semantic is None
        else sealed_semantic.unsupported_claim_count,
        contradiction_count=0 if sealed_semantic is None else sealed_semantic.contradiction_count,
        proposer=proposer,
        verifier=verifier,
        currentness=currentness,
        contrary=contrary,
        attestation=attestation,
        span_count=0 if disposition == "knowledge_gap" else len(spans),
        invented_span=False,
    )
    return evaluate_proof_bundle(
        proof=proof,
        disposition=disposition,
        currentness_required=currentness_required,
        contrary_required=contrary_required,
        human_attestation=human_attestation,
    )
