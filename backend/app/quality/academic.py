"""Independent deterministic 70+ rubric based on observable answer structure."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ..types import EvidenceSpan, MaterialLane, StructuredClaimDraft, StructuredDraft, TaskType
from .evidence import substantive_tokens
from .policy import COMMON, OVERLAYS

REASONING_RE = re.compile(
    r"(?i)\b(?:although|because|consequently|given that|however|on (?:these|the) facts|"
    r"therefore|this means|whereas|while|yet)\b"
)
POSITION_RE = re.compile(
    r"(?i)\b(?:argues?|contends?|better view|concludes?|prefers?|should|supports? the view)\b"
)
QUALIFICATION_RE = re.compile(
    r"(?i)\b(?:although|but|depends|however|nevertheless|subject to|unless|while|yet)\b"
)
UNCERTAINTY_RE = re.compile(
    r"(?i)\b(?:depends|evidence gap|limited|may|uncertain|unclear|unless)\b"
)
APPLICATION_RE = re.compile(
    r"(?i)\b(?:applying|because|given that|here,|likely|on (?:these|the) facts|therefore)\b"
)
CONTRAST_RE = re.compile(
    r"(?i)\b(?:although|conversely|however|nevertheless|on the other hand|yet)\b"
)


@dataclass(frozen=True, slots=True)
class CriterionAssessment:
    key: str
    points: float
    reason: str


@dataclass(frozen=True, slots=True)
class RubricCap:
    code: str
    maximum: float
    reason: str
    corrective_action: str


@dataclass(frozen=True, slots=True)
class AcademicAssessment:
    scores: dict[str, float]
    reasons: dict[str, str]
    caps: tuple[RubricCap, ...]
    raw_score: float
    score: float


@dataclass(frozen=True, slots=True)
class _Features:
    draft: StructuredDraft
    evidence: Mapping[str, EvidenceSpan]
    supported_claim_ids: frozenset[str]
    all_claims: tuple[StructuredClaimDraft, ...]
    material_claims: tuple[StructuredClaimDraft, ...]
    full_text: str
    headings: tuple[str, ...]

    @property
    def support_ratio(self) -> float:
        if not self.material_claims:
            return 0.0
        supported = sum(claim.id in self.supported_claim_ids for claim in self.material_claims)
        return supported / len(self.material_claims)

    @property
    def supported_sources(self) -> tuple[EvidenceSpan, ...]:
        identifiers = {
            evidence_id
            for claim in self.material_claims
            if claim.id in self.supported_claim_ids
            for evidence_id in claim.evidence_ids
        }
        return tuple(self.evidence[item] for item in identifiers if item in self.evidence)


class AcademicRubricScorer:
    """Scores observable features only; model-supplied rubric values are never accepted."""

    def score(
        self,
        *,
        draft: StructuredDraft,
        evidence_by_id: Mapping[str, EvidenceSpan],
        supported_claim_ids: Sequence[str],
    ) -> AcademicAssessment:
        task = draft.task_type if draft.task_type != TaskType.AUTO else TaskType.GENERAL
        claims = tuple(claim for section in draft.sections for claim in section.claims)
        features = _Features(
            draft=draft,
            evidence=evidence_by_id,
            supported_claim_ids=frozenset(supported_claim_ids),
            all_claims=claims,
            material_claims=tuple(claim for claim in claims if claim.material),
            full_text=" ".join(
                f"{section.heading} {' '.join(claim.text for claim in section.claims)}"
                for section in draft.sections
            ),
            headings=tuple(section.heading.casefold().strip() for section in draft.sections),
        )
        weights = {item.key: item.weight for item in (*COMMON, *OVERLAYS[task])}
        fractions, reasons, caps = self._common(features)
        if task == TaskType.ESSAY:
            overlay_fractions, overlay_reasons, overlay_caps = self._essay(features)
        elif task == TaskType.PROBLEM:
            overlay_fractions, overlay_reasons, overlay_caps = self._problem(features)
        else:
            overlay_fractions, overlay_reasons, overlay_caps = self._general(features)
        fractions.update(overlay_fractions)
        reasons.update(overlay_reasons)
        caps.extend(overlay_caps)
        scores = {
            key: round(weights[key] * max(0.0, min(1.0, fractions.get(key, 0.0))), 2)
            for key in weights
        }
        raw = round(sum(scores.values()), 1)
        capped = min([raw, *(cap.maximum for cap in caps)])
        return AcademicAssessment(
            scores=scores,
            reasons=reasons,
            caps=tuple(caps),
            raw_score=raw,
            score=round(capped, 1),
        )

    def _common(
        self, features: _Features
    ) -> tuple[dict[str, float], dict[str, str], list[RubricCap]]:
        sources = features.supported_sources
        authority_fraction = features.support_ratio
        if sources and features.support_ratio == 1:
            authority_fraction = min(
                1.0,
                0.8
                + (0.1 if len({span.source_version_id for span in sources}) >= 2 else 0.0)
                + (
                    0.1
                    if any(span.lane == MaterialLane.PRIMARY_AUTHORITY for span in sources)
                    else 0.0
                ),
            )
        developed = [
            claim for claim in features.material_claims if 12 <= _word_count(claim.text) <= 180
        ]
        reasoned = [claim for claim in developed if REASONING_RE.search(claim.text)]
        developed_ratio = len(developed) / max(1, len(features.material_claims))
        reasoned_ratio = len(reasoned) / max(1, len(features.material_claims))
        diversity = _lexical_diversity(features.full_text)
        analysis_fraction = (
            0.30 * features.support_ratio
            + 0.25 * developed_ratio
            + 0.25 * reasoned_ratio
            + 0.20 * min(1.0, diversity / 0.42)
        )

        section_count = len(features.draft.sections)
        nonempty = sum(bool(section.claims) for section in features.draft.sections)
        distinct_headings = len(set(features.headings)) == len(features.headings)
        first_is_intro = bool(features.headings) and _heading_has(
            features.headings[0], "answer", "introduction", "issues", "overview", "thesis"
        )
        last_is_close = bool(features.headings) and _heading_has(
            features.headings[-1], "conclusion", "outcome", "synthesis", "next steps"
        )
        organisation_fraction = (
            (0.30 if section_count >= 3 else 0.15 if section_count == 2 else 0.0)
            + (0.20 if distinct_headings and section_count >= 2 else 0.0)
            + (0.15 if first_is_intro else 0.0)
            + (0.15 if last_is_close else 0.0)
            + (0.20 * nonempty / max(1, section_count))
        )

        sentence_lengths = _sentence_lengths(features.full_text)
        disciplined_sentences = (
            sum(8 <= length <= 40 for length in sentence_lengths) / len(sentence_lengths)
            if sentence_lengths
            else 0.0
        )
        unique_claims = len(
            {" ".join(claim.text.casefold().split()) for claim in features.all_claims}
        )
        claim_uniqueness = unique_claims / max(1, len(features.all_claims))
        bounded_claims = sum(_word_count(claim.text) <= 180 for claim in features.all_claims) / max(
            1, len(features.all_claims)
        )
        precision_fraction = (
            0.40 * min(1.0, diversity / 0.42)
            + 0.25 * disciplined_sentences
            + 0.20 * claim_uniqueness
            + 0.15 * bounded_claims
        )
        return (
            {
                "authority_accuracy": authority_fraction,
                "analysis": analysis_fraction,
                "organisation": organisation_fraction,
                "precision": precision_fraction,
            },
            {
                "authority_accuracy": (
                    f"{len(features.supported_claim_ids)}/{len(features.material_claims)} material "
                    f"claims passed independent support checks across {len(sources)} bound sources."
                ),
                "analysis": (
                    f"{len(developed)}/{len(features.material_claims)} material claims were developed "
                    f"and {len(reasoned)} contained an observable reasoning step; lexical diversity "
                    f"was {diversity:.2f}."
                ),
                "organisation": (
                    f"The answer used {section_count} non-duplicative sections with "
                    f"{nonempty} populated sections; opening/closing structure was assessed directly."
                ),
                "precision": (
                    f"Disciplined sentence ratio was {disciplined_sentences:.2f}, claim uniqueness "
                    f"was {claim_uniqueness:.2f}, and lexical diversity was {diversity:.2f}."
                ),
            },
            [],
        )

    def _essay(
        self, features: _Features
    ) -> tuple[dict[str, float], dict[str, str], list[RubricCap]]:
        first_claim = features.all_claims[0] if features.all_claims else None
        thesis_location = bool(features.headings) and _heading_has(
            features.headings[0], "introduction", "overview", "thesis"
        )
        thesis_position = bool(first_claim and POSITION_RE.search(first_claim.text))
        thesis_qualified = bool(first_claim and QUALIFICATION_RE.search(first_claim.text))
        thesis_developed = bool(first_claim and 15 <= _word_count(first_claim.text) <= 120)
        thesis_fraction = (
            0.30 * thesis_location
            + 0.35 * thesis_position
            + 0.20 * thesis_qualified
            + 0.15 * thesis_developed
        )

        scholarship_claims = [
            claim
            for claim in features.material_claims
            if any(
                evidence_id in features.evidence
                and features.evidence[evidence_id].lane == MaterialLane.SCHOLARSHIP
                for evidence_id in claim.evidence_ids
            )
            and claim.id in features.supported_claim_ids
        ]
        scholarship_sources = {
            evidence_id
            for claim in scholarship_claims
            for evidence_id in claim.evidence_ids
            if evidence_id in features.evidence
            and features.evidence[evidence_id].lane == MaterialLane.SCHOLARSHIP
        }
        critical_scholarship = sum(
            bool(CONTRAST_RE.search(claim.text) or REASONING_RE.search(claim.text))
            for claim in scholarship_claims
        )
        scholarship_fraction = min(
            1.0,
            (0.55 if scholarship_sources else 0.0)
            + (0.15 if len(scholarship_sources) >= 2 else 0.0)
            + (0.20 if critical_scholarship else 0.0)
            + (0.10 if len(scholarship_claims) >= 2 else 0.0),
        )

        contrast_claims = [claim for claim in features.all_claims if CONTRAST_RE.search(claim.text)]
        counter_section = any(
            _heading_has(item, "counter", "critique", "objection") for item in features.headings
        )
        counter_fraction = min(
            1.0,
            0.40 * counter_section
            + 0.35 * min(1.0, len(contrast_claims) / 2)
            + 0.25 * (len(features.all_claims) >= 4),
        )
        synthesis_fraction = _synthesis_fraction(features)

        caps: list[RubricCap] = []
        if thesis_fraction < 0.65:
            caps.append(
                RubricCap(
                    code="rubric_cap_missing_thesis",
                    maximum=69,
                    reason="The essay lacks an identifiable, qualified thesis in its opening.",
                    corrective_action="State a contestable position and its qualification in the opening section.",
                )
            )
        if not scholarship_sources:
            caps.append(
                RubricCap(
                    code="rubric_cap_missing_scholarship",
                    maximum=69,
                    reason="No verified scholarship span is critically integrated into the essay.",
                    corrective_action="Engage at least one verified scholarly source and explain its bearing on the thesis.",
                )
            )
        return (
            {
                "thesis": thesis_fraction,
                "scholarship": scholarship_fraction,
                "counterargument": counter_fraction,
                "synthesis": synthesis_fraction,
            },
            {
                "thesis": "Opening location, a contestable position, qualification and development were each checked.",
                "scholarship": (
                    f"{len(scholarship_claims)} supported claims used {len(scholarship_sources)} "
                    f"verified scholarship sources; {critical_scholarship} showed critical treatment."
                ),
                "counterargument": (
                    f"Counterargument section present={counter_section}; {len(contrast_claims)} "
                    "distinct claims used contrastive reasoning."
                ),
                "synthesis": "The final section was checked for a developed conclusion that synthesises the position.",
            },
            caps,
        )

    def _problem(
        self, features: _Features
    ) -> tuple[dict[str, float], dict[str, str], list[RubricCap]]:
        first_claim_count = len(features.draft.sections[0].claims) if features.draft.sections else 0
        issue_heading = bool(features.headings) and _heading_has(
            features.headings[0], "issues", "parties", "roadmap"
        )
        issue_fraction = min(1.0, 0.55 * issue_heading + 0.45 * min(1.0, first_claim_count / 2))
        applications = [
            claim
            for claim in features.material_claims
            if APPLICATION_RE.search(claim.text) and claim.id in features.supported_claim_ids
        ]
        application_sections = sum(
            any(claim in applications for claim in section.claims)
            for section in features.draft.sections
        )
        application_fraction = min(
            1.0,
            0.50 * min(1.0, len(applications) / 2)
            + 0.25 * min(1.0, application_sections / 2)
            + 0.25 * (features.support_ratio == 1),
        )
        contrast_claims = [claim for claim in features.all_claims if CONTRAST_RE.search(claim.text)]
        counter_fraction = min(
            1.0,
            0.65 * min(1.0, len(contrast_claims) / 2)
            + 0.35
            * any(_heading_has(item, "counter", "alternative") for item in features.headings),
        )
        remedy_sections = [
            section
            for section in features.draft.sections
            if _heading_has(section.heading.casefold(), "procedure", "relief", "remedies", "remedy")
        ]
        remedy_claims = [claim for section in remedy_sections for claim in section.claims]
        supported_remedies = [
            claim
            for claim in remedy_claims
            if not claim.material or claim.id in features.supported_claim_ids
        ]
        remedies_fraction = min(
            1.0,
            0.45 * bool(remedy_sections)
            + 0.35 * bool(supported_remedies)
            + 0.20 * (len(supported_remedies) >= 2),
        )
        caps: list[RubricCap] = []
        if len(applications) < 2:
            caps.append(
                RubricCap(
                    code="rubric_cap_missing_application",
                    maximum=59,
                    reason="The problem answer lacks sustained, evidence-supported application to facts.",
                    corrective_action="Apply each governing rule to the material facts and rank the competing outcomes.",
                )
            )
        if not supported_remedies:
            caps.append(
                RubricCap(
                    code="rubric_cap_missing_remedies",
                    maximum=69,
                    reason="The problem answer does not address supported remedies or procedure.",
                    corrective_action="Add a remedies/procedure section grounded in qualifying authority.",
                )
            )
        return (
            {
                "issue_map": issue_fraction,
                "application": application_fraction,
                "counterargument": counter_fraction,
                "remedies": remedies_fraction,
            },
            {
                "issue_map": f"Opening issue-map heading present={issue_heading}; it contained {first_claim_count} mapped claims.",
                "application": (
                    f"{len(applications)} supported application claims appeared across "
                    f"{application_sections} sections."
                ),
                "counterargument": f"{len(contrast_claims)} claims addressed a competing analysis.",
                "remedies": (
                    f"{len(remedy_sections)} remedies/procedure sections contained "
                    f"{len(supported_remedies)} supported or practical claims."
                ),
            },
            caps,
        )

    def _general(
        self, features: _Features
    ) -> tuple[dict[str, float], dict[str, str], list[RubricCap]]:
        first_claim = features.all_claims[0] if features.all_claims else None
        direct_heading = bool(features.headings) and _heading_has(
            features.headings[0], "answer", "overview", "short answer"
        )
        direct_supported = bool(
            first_claim
            and (not first_claim.material or first_claim.id in features.supported_claim_ids)
        )
        direct_developed = bool(first_claim and 8 <= _word_count(first_claim.text) <= 120)
        direct_fraction = 0.35 * direct_heading + 0.35 * direct_supported + 0.30 * direct_developed

        limitation_sections = [
            section
            for section in features.draft.sections
            if _heading_has(section.heading.casefold(), "assumption", "limitation", "uncertainty")
        ]
        uncertainty_claims = [
            claim for claim in features.all_claims if UNCERTAINTY_RE.search(claim.text)
        ]
        limitations_fraction = min(
            1.0,
            0.40 * bool(limitation_sections)
            + 0.30 * bool(uncertainty_claims)
            + 0.30 * bool(features.draft.limitations),
        )
        next_sections = [
            section
            for section in features.draft.sections
            if _heading_has(section.heading.casefold(), "action", "next step", "practical")
        ]
        next_claims = [claim for section in next_sections for claim in section.claims]
        next_fraction = min(
            1.0,
            0.50 * bool(next_sections)
            + 0.30 * bool(next_claims)
            + 0.20 * any(_word_count(claim.text) >= 8 for claim in next_claims),
        )
        synthesis_fraction = _synthesis_fraction(features)
        return (
            {
                "direct_answer": direct_fraction,
                "limitations": limitations_fraction,
                "next_steps": next_fraction,
                "synthesis": synthesis_fraction,
            },
            {
                "direct_answer": (
                    f"Direct-answer heading present={direct_heading}; opening claim support="
                    f"{direct_supported} and developed={direct_developed}."
                ),
                "limitations": (
                    f"{len(limitation_sections)} limitations sections, {len(uncertainty_claims)} "
                    f"uncertainty claims and {len(features.draft.limitations)} explicit limitations were found."
                ),
                "next_steps": f"{len(next_sections)} practical-next-step sections contained {len(next_claims)} claims.",
                "synthesis": "The final section was checked for a developed synthesis or conclusion.",
            },
            [],
        )


def _heading_has(heading: str, *needles: str) -> bool:
    return any(needle in heading for needle in needles)


def _word_count(text: str) -> int:
    return len(re.findall(r"\b[\w’'-]+\b", text))


def _sentence_lengths(text: str) -> tuple[int, ...]:
    return tuple(
        count
        for sentence in re.split(r"[.!?]+", text)
        if (count := _word_count(sentence.strip())) > 0
    )


def _lexical_diversity(text: str) -> float:
    tokens = substantive_tokens(text)
    return len(set(tokens)) / len(tokens) if tokens else 0.0


def _synthesis_fraction(features: _Features) -> float:
    if not features.draft.sections:
        return 0.0
    final = features.draft.sections[-1]
    close_heading = _heading_has(final.heading.casefold(), "conclusion", "outcome", "synthesis")
    developed = any(12 <= _word_count(claim.text) <= 150 for claim in final.claims)
    reasoned = any(
        REASONING_RE.search(claim.text) or POSITION_RE.search(claim.text) for claim in final.claims
    )
    return 0.40 * close_heading + 0.30 * developed + 0.30 * reasoned
