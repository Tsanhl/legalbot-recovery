from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING
from uuid import uuid4

from ..assessment.standards_scoring import score_applicable_standards
from ..currentness import is_legislation_source
from ..jurisdictions import compatible
from ..legal_roles import MATERIAL_CASE_ROLES
from ..privacy import prompt_injection_hits, scrub_pii
from ..types import (
    EvidenceSpan,
    QualityFinding,
    QualityReport,
    ReleaseState,
    Severity,
    StructuredClaimDraft,
    StructuredDraft,
    TaskType,
)
from .academic import AcademicRubricScorer
from .evidence import (
    currentness_qualifies_for_answer,
    false_quotations,
    is_citable_authority_lane,
    is_substantively_related,
    non_atomic_material_claim_reasons,
    unsupported_material_facts,
)
from .policy import COMMON, OVERLAYS, decide_release

if TYPE_CHECKING:
    from ..db import Database

_NEGATION = {"not", "no", "cannot", "can't", "never", "neither", "without"}
_CONTRADICTION_STOP = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "because",
    "by",
    "for",
    "from",
    "if",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "was",
    "were",
    "will",
    "with",
    "would",
}


class QualityEvaluator:
    """Independent gates; it reports defects and never mutates or deletes answer prose."""

    def __init__(
        self,
        database: Database | None = None,
        *,
        enforce_retrieval_threshold: bool = False,
    ) -> None:
        self.academic = AcademicRubricScorer()
        self.database = database
        self.enforce_retrieval_threshold = enforce_retrieval_threshold

    def evaluate(
        self,
        *,
        answer_version_id: str,
        draft: StructuredDraft,
        rendered_text: str,
        evidence_by_id: Mapping[str, EvidenceSpan],
        word_count: int,
        word_target: int,
        rubric_scores: Mapping[str, float] | None = None,
        question: str | None = None,
        subject: str | None = None,
    ) -> QualityReport:
        findings: list[QualityFinding] = []
        current_law_limits = False
        material_claims = [
            claim for section in draft.sections for claim in section.claims if claim.material
        ]
        for _first, second in self._contradictory_claims(material_claims):
            findings.append(
                QualityFinding(
                    gate="answer_consistency",
                    code="material_contradiction",
                    message="Two materially similar claims take conflicting affirmative and negative positions.",
                    severity=Severity.HARD_BLOCKER,
                    claim_id=second.id,
                    corrective_action=(
                        "Reconcile the conflict expressly, distinguish the factual or legal premise, "
                        "or retain only the supported conclusion."
                    ),
                )
            )

        for section in draft.sections:
            for claim in section.claims:
                if not claim.material:
                    continue
                atomicity_reasons = non_atomic_material_claim_reasons(claim.text)
                if atomicity_reasons:
                    findings.append(
                        QualityFinding(
                            gate="claim_atomicity",
                            code="non_atomic_material_claim",
                            message=(
                                "A material claim contains multiple independently assertable "
                                "propositions. One citation set cannot establish every clause."
                            ),
                            severity=Severity.HARD_BLOCKER,
                            section_id=section.id,
                            claim_id=claim.id,
                            corrective_action=(
                                "Split the claim into one proposition per material claim and bind "
                                "each new claim to its exact supporting spans."
                            ),
                        )
                    )
                if not claim.evidence_ids:
                    findings.append(
                        QualityFinding(
                            gate="claim_evidence",
                            code="unsupported_material_law",
                            message="A material legal proposition has no verified source span.",
                            severity=Severity.HARD_BLOCKER,
                            section_id=section.id,
                            claim_id=claim.id,
                            corrective_action="Remove the unsupported proposition or bind qualifying official evidence.",
                        )
                    )
                    continue
                bound_spans: list[EvidenceSpan] = []
                for evidence_id in claim.evidence_ids:
                    span = evidence_by_id.get(evidence_id)
                    if span is None:
                        findings.append(
                            QualityFinding(
                                gate="claim_evidence",
                                code="wrong_authority_identity",
                                message="A claim refers to an evidence identity absent from its frozen snapshot.",
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action="Retrieve the span again and persist its stable source identity.",
                            )
                        )
                        continue
                    bound_spans.append(span)
                    if self.enforce_retrieval_threshold and not (
                        span.retrieval_threshold_qualified is True
                        and span.retrieval_relevance_score is not None
                        and span.retrieval_route
                        in {
                            "exact_authority_identity",
                            "exact_legislation_reference",
                            "hybrid_rrf",
                        }
                        and span.retrieval_threshold is not None
                        and span.retrieval_threshold_policy_sha256 is not None
                        and span.retrieval_relevance_score >= span.retrieval_threshold
                    ):
                        findings.append(
                            QualityFinding(
                                gate="retrieval_relevance",
                                code="no_threshold_qualified_evidence",
                                message=(
                                    "A material claim is bound to evidence that did not pass "
                                    "the exact frozen route-specific relevance policy."
                                ),
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Retrieve and rerank against the frozen policy, then bind "
                                    "only an exact-route match or a semantic hit at or above "
                                    "its calibrated threshold."
                                ),
                            )
                        )
                    if not is_citable_authority_lane(span):
                        findings.append(
                            QualityFinding(
                                gate="claim_evidence",
                                code="non_authority_lane",
                                message=(
                                    "A material legal claim is bound to a non-authority lane "
                                    "(for example private teaching or assessment guidance). "
                                    "Teaching material cannot satisfy a material legal claim."
                                ),
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Remove the teaching or assessment span and bind only "
                                    "primary, official-secondary or scholarship evidence."
                                ),
                            )
                        )
                    if not compatible(draft.jurisdiction, span.jurisdiction, span.citation_data):
                        findings.append(
                            QualityFinding(
                                gate="jurisdiction",
                                code="wrong_jurisdiction",
                                message=f"Evidence jurisdiction {span.jurisdiction!r} does not match the answer jurisdiction.",
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action="Replace it with qualifying authority for the selected jurisdiction.",
                            )
                        )
                    if not span.identity_verified:
                        findings.append(
                            QualityFinding(
                                gate="authority_identity",
                                code="wrong_authority_identity",
                                message="Authority identity has not passed deterministic verification.",
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action="Verify the canonical identifier and citation metadata.",
                            )
                        )
                    source_type = str(span.citation_data.get("source_type") or "").casefold()
                    is_case = source_type == "case"
                    material_update_blocked = False
                    if self.database is not None:
                        from ..research.material_updates import MaterialUpdateGate

                        update_assessment = MaterialUpdateGate(self.database).assess(
                            span, proposition_hash=claim.proposition_hash
                        )
                        material_update_blocked = bool(update_assessment.blocked_observation_ids)
                        if material_update_blocked:
                            findings.append(
                                QualityFinding(
                                    gate="currentness",
                                    code="reviewed_material_update_unresolved",
                                    message=(
                                        "An expert-reviewed material official-source update "
                                        "affects this authority or proposition, but the frozen "
                                        "evidence is not bound to its reviewed, newly promoted "
                                        "resolution."
                                    ),
                                    severity=Severity.HARD_BLOCKER,
                                    section_id=section.id,
                                    claim_id=claim.id,
                                    corrective_action=(
                                        "Review and ingest the updated authority, evaluate a new "
                                        "candidate, have the owner promote it, and bind the exact "
                                        "ACTIVE resolution before release."
                                    ),
                                )
                            )
                    if material_update_blocked:
                        pass
                    elif is_case and not currentness_qualifies_for_answer(
                        span,
                        proposition_hash=claim.proposition_hash,
                        as_of_date=draft.as_of_date,
                    ):
                        findings.append(
                            QualityFinding(
                                gate="currentness",
                                code="case_subsequent_treatment_unverified",
                                message=(
                                    "No exact sealed span/proposition review qualifies this "
                                    "judgment for present-law use on the answer date."
                                ),
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Complete a later-treatment review bound to the exact "
                                    "EvidenceSpan and proposition hashes, with any required "
                                    "independent second review."
                                ),
                            )
                        )
                    elif not is_case and not span.currentness_verified:
                        findings.append(
                            QualityFinding(
                                gate="currentness",
                                code="materially_outdated_law",
                                message="Currentness is not verified for a material legal source.",
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Check the official current version, commencement and "
                                    "outstanding effects."
                                ),
                            )
                        )
                    elif not is_case and not currentness_qualifies_for_answer(span):
                        findings.append(
                            QualityFinding(
                                gate="currentness",
                                code="historical_legislation_used_as_current_law",
                                message=(
                                    "Historical or as-enacted legislation cannot establish "
                                    "the current consolidated provision."
                                ),
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Replace it with an official point-in-time provision whose "
                                    "extent, commencement and outstanding effects are verified."
                                ),
                            )
                        )
                    if (
                        is_legislation_source(span.citation_data)
                        and span.currentness_status.casefold().replace("-", "_")
                        == "latest_available_revised_snapshot"
                        and (
                            (span.unapplied_effect_count or 0) > 0
                            or span.provision_extent_status
                            not in {
                                "england_and_wales_verified",
                                "uk_with_england_wales_verified",
                            }
                        )
                    ):
                        current_law_limits = True
                        findings.append(
                            QualityFinding(
                                gate="currentness",
                                code="current_law_verification_limited",
                                message=(
                                    "The latest-available snapshot has material/unknown "
                                    "unapplied effects or lacks provision-level E&W extent verification."
                                ),
                                # A latest-available snapshot with material or
                                # unknown unapplied effects, or without the
                                # exact E&W extent proof, cannot support a
                                # released present-law proposition.  This is a
                                # deterministic currentness failure; a prose
                                # limitation does not turn the underlying
                                # material claim into verified law.
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Verify extent, commencement and relevant unapplied effects, "
                                    "or remove the affected material claim."
                                ),
                            )
                        )
                    if source_type == "case" and span.legal_role not in MATERIAL_CASE_ROLES:
                        findings.append(
                            QualityFinding(
                                gate="case_legal_role",
                                code="unverified_case_legal_role",
                                message=(
                                    "The judgment passage is not classified as holding/ratio; "
                                    "it may be facts, submissions, procedure, obiter or dissent."
                                ),
                                severity=Severity.HARD_BLOCKER,
                                section_id=section.id,
                                claim_id=claim.id,
                                corrective_action=(
                                    "Bind a reviewed holding/ratio span or qualify/remove the proposition."
                                ),
                            )
                        )
                unrelated = [
                    span.id
                    for span in bound_spans
                    if not is_substantively_related(claim.text, span)
                ]
                if unrelated:
                    findings.append(
                        QualityFinding(
                            gate="claim_evidence",
                            code="unrelated_evidence",
                            message=(
                                "A material claim is not substantively related to every bound "
                                "source span. Evidence IDs alone do not establish support."
                            ),
                            severity=Severity.HARD_BLOCKER,
                            section_id=section.id,
                            claim_id=claim.id,
                            corrective_action=(
                                "Bind a span that states the proposition or rewrite the claim to "
                                "the proposition the source actually supports."
                            ),
                        )
                    )
                unsupported_facts = unsupported_material_facts(claim.text, bound_spans)
                if unsupported_facts:
                    fact_kinds = ", ".join(sorted({fact.kind for fact in unsupported_facts}))
                    findings.append(
                        QualityFinding(
                            gate="claim_evidence",
                            code="unsupported_material_fact",
                            message=(
                                "A material claim contains a typed fact absent from every exact "
                                f"bound evidence span ({fact_kinds})."
                            ),
                            severity=Severity.HARD_BLOCKER,
                            section_id=section.id,
                            claim_id=claim.id,
                            corrective_action=(
                                "Correct or remove the unsupported date, amount, percentage, "
                                "duration or provision identifier, or bind the exact supporting span."
                            ),
                        )
                    )
                unsupported_quotes = false_quotations(claim.text, bound_spans)
                if unsupported_quotes:
                    findings.append(
                        QualityFinding(
                            gate="quotation_accuracy",
                            code="false_quotation",
                            message=(
                                "Quoted wording does not occur verbatim in any bound evidence span."
                            ),
                            severity=Severity.HARD_BLOCKER,
                            section_id=section.id,
                            claim_id=claim.id,
                            corrective_action=(
                                "Remove quotation marks, paraphrase accurately, or bind the exact "
                                "source passage."
                            ),
                        )
                    )

        if rendered_text != scrub_pii(rendered_text):
            findings.append(
                QualityFinding(
                    gate="privacy",
                    code="personal_data_leakage",
                    message="The rendered answer contains personal data or a local absolute path.",
                    severity=Severity.HARD_BLOCKER,
                    corrective_action="Redact the identifier and regenerate only the affected claim.",
                )
            )
        if prompt_injection_hits(rendered_text):
            findings.append(
                QualityFinding(
                    gate="document_safety",
                    code="prompt_injection",
                    message="Document-borne instruction text leaked into the answer.",
                    severity=Severity.HARD_BLOCKER,
                    corrective_action="Quarantine the source segment and rebuild the affected claim.",
                )
            )

        blocked_claim_ids = {
            item.claim_id
            for item in findings
            if item.claim_id and item.severity == Severity.HARD_BLOCKER
        }
        supported_claim_ids = [
            claim.id
            for claim in material_claims
            if claim.id not in blocked_claim_ids and claim.evidence_ids
        ]
        academic = self.academic.score(
            draft=draft,
            evidence_by_id=evidence_by_id,
            supported_claim_ids=supported_claim_ids,
        )
        # Assessment standards are a release-quality policy, never legal
        # evidence.  Preserve the independent evidence disposition even when
        # an applicable lower-band avoidance rule blocks publication.
        evidence_hard_blocker = any(item.severity == Severity.HARD_BLOCKER for item in findings)
        standards = score_applicable_standards(
            draft=draft,
            question=question or draft.title,
            subject=subject,
            evidence_by_id=evidence_by_id,
            supported_claim_ids=supported_claim_ids,
        )
        if not standards.avoidance_passed:
            findings.append(
                QualityFinding(
                    gate="assessment_standards",
                    code="applicable_avoidance_standard_failed",
                    message=(
                        "One or more applicable 50-59 or 60-69 avoidance rules "
                        "failed deterministic scoring."
                    ),
                    severity=Severity.HARD_BLOCKER,
                    corrective_action=(
                        "Hold the answer and address the failed avoidance rules in a "
                        "new explicitly scoped version before fresh verification."
                    ),
                )
            )
        if rubric_scores:
            findings.append(
                QualityFinding(
                    gate="academic_rubric",
                    code="model_rubric_ignored",
                    message=(
                        "Model-supplied rubric values were ignored; the academic score was "
                        "computed independently from observable structure and verified evidence."
                    ),
                    severity=Severity.INFORMATIONAL,
                )
            )
        weights = {
            item.key: item.weight
            for item in (
                *COMMON,
                *OVERLAYS[
                    draft.task_type if draft.task_type != TaskType.AUTO else TaskType.GENERAL
                ],
            )
        }
        for key, reason in academic.reasons.items():
            findings.append(
                QualityFinding(
                    gate="academic_rubric",
                    code=f"rubric_reason_{key}",
                    message=f"{academic.scores[key]:.2f}/{weights[key]:.0f}: {reason}",
                    severity=Severity.INFORMATIONAL,
                )
            )
        for cap in academic.caps:
            findings.append(
                QualityFinding(
                    gate="academic_rubric",
                    code=cap.code,
                    message=f"{cap.reason} Overall mark capped at {cap.maximum:.0f}.",
                    severity=Severity.REPAIRABLE,
                    corrective_action=cap.corrective_action,
                )
            )
        scores = academic.scores
        academic_score = academic.score
        hard_blocker = any(item.severity == Severity.HARD_BLOCKER for item in findings)
        evidence_passed = not evidence_hard_blocker
        release = decide_release(
            hard_blocker=hard_blocker,
            evidence_passed=evidence_passed,
            academic_score=academic_score,
            word_count=word_count,
            word_target=word_target,
            has_gaps=bool(draft.limitations) or current_law_limits,
        )

        if word_count < max(100, int(word_target * 0.8)):
            findings.append(
                QualityFinding(
                    gate="requested_length",
                    code="shorter_than_requested",
                    message=f"The verified answer has {word_count} words against a target of {word_target}.",
                    severity=Severity.REPAIRABLE,
                    corrective_action="Expand analysis without removing any verified substantive prose.",
                )
            )
        if academic_score < 70 and release != ReleaseState.HELD_FOR_REVIEW:
            findings.append(
                QualityFinding(
                    gate="academic_quality",
                    code="academic_score_below_target",
                    message=f"The automated advisory academic score is {academic_score:.1f}; the 70+ drafting target is not met.",
                    severity=Severity.REPAIRABLE,
                    corrective_action="Repair only the lowest-scoring section and preserve verified sections.",
                )
            )

        return QualityReport(
            id=str(uuid4()),
            answer_version_id=answer_version_id,
            evidence_passed=evidence_passed,
            academic_score=academic_score,
            raw_academic_score=academic.raw_score,
            rubric_scores=scores,
            rubric_reasons=academic.reasons,
            rubric_caps=[cap.code for cap in academic.caps],
            assessment_standards=standards.model_dump(mode="json", by_alias=True),
            findings=findings,
            release_state=release,
        )

    @staticmethod
    def _contradictory_claims(
        claims: list[StructuredClaimDraft],
    ) -> list[tuple[StructuredClaimDraft, StructuredClaimDraft]]:
        output: list[tuple[StructuredClaimDraft, StructuredClaimDraft]] = []
        features: list[tuple[StructuredClaimDraft, set[str], bool]] = []
        for claim in claims:
            tokens = {
                token
                for token in re.findall(r"[a-z]+", claim.text.casefold())
                if token not in _CONTRADICTION_STOP and token not in _NEGATION
            }
            negative = bool(set(re.findall(r"[a-z']+", claim.text.casefold())) & _NEGATION)
            features.append((claim, tokens, negative))
        for index, (first, first_tokens, first_negative) in enumerate(features):
            for second, second_tokens, second_negative in features[index + 1 :]:
                if first_negative == second_negative or not first_tokens or not second_tokens:
                    continue
                overlap = len(first_tokens & second_tokens) / len(first_tokens | second_tokens)
                if overlap >= 0.72:
                    output.append((first, second))
        return output
