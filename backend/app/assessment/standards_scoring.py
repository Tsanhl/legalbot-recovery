"""Deterministically score every applicable rule in the sealed 16-rule bundle.

Assessment guidance is drafting policy, never legal authority. The scorer uses
observable answer structure and already-dispositioned claim/evidence identities;
it cannot make a legal-fact finding or override any evidence release gate.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..quality.draft_identity import source_draft_sha256
from ..types import EvidenceSpan, StructuredDraft
from .guidance_bundle import (
    OWNER_ASSESSMENT_BUNDLE,
    AssessmentGuidanceBundle,
    AssessmentGuidanceRule,
    applicable_guidance_rules,
)

STANDARDS_REPORT_SCHEMA = "legalbot.assessment-standards-report.v2"

_REASONING = re.compile(
    r"(?i)\b(?:although|because|consequently|given that|however|on (?:these|the) facts|"
    r"therefore|this means|whereas|while|yet)\b"
)
_APPLICATION = re.compile(
    r"(?i)\b(?:applying|because|given that|here|likely|on (?:these|the) facts|therefore)\b"
)
_COMPARISON = re.compile(
    r"(?i)\b(?:although|compare|conversely|distinguish|however|in contrast|tension|whereas|yet)\b"
)
_POSITION = re.compile(
    r"(?i)\b(?:argue|better view|conclude|contend|prefer|should|support(?:s|ed)? the view)\b"
)
_QUALIFICATION = re.compile(
    r"(?i)\b(?:although|but|depends|however|nevertheless|subject to|unless|while|yet)\b"
)
_ALTERNATIVE = re.compile(
    r"(?i)\b(?:alternative|competing|depends|missing fact|more likely|less likely|stronger|weaker)\b"
)
_ELEMENT = re.compile(r"(?i)\b(?:defence|element|exception|limb|requirement|test)\b")
_LONG_QUOTE = re.compile(r"[\"“][^\"”]{180,}[\"”]")
_WORD = re.compile(r"[a-z][a-z'-]{2,}")
_STOP = frozenset(
    {
        "about",
        "after",
        "also",
        "answer",
        "before",
        "could",
        "from",
        "have",
        "into",
        "legal",
        "question",
        "should",
        "that",
        "their",
        "there",
        "these",
        "this",
        "under",
        "what",
        "when",
        "where",
        "which",
        "with",
        "would",
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


def _ratio(numerator: int | float, denominator: int | float) -> float:
    return max(0.0, min(1.0, float(numerator) / max(1.0, float(denominator))))


def _tokens(value: str) -> frozenset[str]:
    return frozenset(token for token in _WORD.findall(value.casefold()) if token not in _STOP)


class AssessmentStandardScore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str
    grade_band: Literal["70+", "60-69", "50-59"]
    criterion: str
    score: float = Field(ge=0, le=100)
    passed: bool
    avoidance_rule: bool
    anti_pattern_triggered: bool
    reason_codes: tuple[str, ...]

    @model_validator(mode="after")
    def disposition_is_consistent(self) -> Self:
        if self.avoidance_rule != (self.grade_band != "70+"):
            raise ValueError("standards score avoidance identity is inconsistent")
        if self.anti_pattern_triggered and not self.avoidance_rule:
            raise ValueError("70+ target cannot be marked as an avoidance anti-pattern")
        if self.avoidance_rule and self.passed == self.anti_pattern_triggered:
            raise ValueError("standards pass and anti-pattern disposition disagree")
        if not self.reason_codes or len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("standards score requires unique reason codes")
        return self


class AssessmentStandardsReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["legalbot.assessment-standards-report.v2"] = Field(
        default="legalbot.assessment-standards-report.v2", alias="schema"
    )
    bundle_version: str
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_draft_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_type: str
    subject: str | None
    applicable_rule_count: int = Field(ge=1)
    scores: tuple[AssessmentStandardScore, ...]
    avoidance_passed: bool
    quality_target_met: bool
    legal_authority: Literal[False] = False
    seal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def report_is_complete_and_sealed(self) -> Self:
        if self.applicable_rule_count != len(self.scores):
            raise ValueError("standards report does not cover every applicable rule")
        if len({item.rule_id for item in self.scores}) != len(self.scores):
            raise ValueError("standards report contains duplicate rules")
        expected_avoidance = all(item.passed for item in self.scores if item.avoidance_rule)
        expected_quality = all(item.passed for item in self.scores if not item.avoidance_rule)
        if self.avoidance_passed != expected_avoidance:
            raise ValueError("standards avoidance aggregate is inconsistent")
        if self.quality_target_met != expected_quality:
            raise ValueError("standards quality aggregate is inconsistent")
        if self.seal_sha256 != _sealed_sha256(self.model_dump(mode="json", by_alias=True)):
            raise ValueError("standards report seal does not match its contents")
        return self


def _observable_features(
    *,
    draft: StructuredDraft,
    question: str,
    evidence_by_id: Mapping[str, EvidenceSpan],
    supported_claim_ids: Sequence[str],
) -> dict[str, float]:
    material = tuple(
        claim for section in draft.sections for claim in section.claims if claim.material
    )
    supported = frozenset(supported_claim_ids)
    full_text = " ".join(
        f"{section.heading} {' '.join(claim.text for claim in section.claims)}"
        for section in draft.sections
    )
    question_tokens = _tokens(question)
    answer_tokens = _tokens(full_text)
    question_alignment = _ratio(len(question_tokens & answer_tokens), len(question_tokens))
    support_ratio = _ratio(sum(claim.id in supported for claim in material), len(material))
    reasoned_ratio = _ratio(
        sum(bool(_REASONING.search(claim.text)) for claim in material), len(material)
    )
    application_ratio = _ratio(
        sum(bool(_APPLICATION.search(claim.text)) for claim in material), len(material)
    )
    compare_ratio = _ratio(
        sum(bool(_COMPARISON.search(claim.text)) for claim in material),
        min(2, len(material)),
    )
    element_ratio = _ratio(
        sum(bool(_ELEMENT.search(claim.text)) for claim in material),
        min(2, len(material)),
    )
    alternative_ratio = _ratio(
        sum(bool(_ALTERNATIVE.search(claim.text)) for claim in material),
        min(2, len(material)),
    )
    first = material[0].text if material else ""
    thesis = (
        0.40 * bool(_POSITION.search(first))
        + 0.25 * bool(_QUALIFICATION.search(first))
        + 0.35 * question_alignment
    )
    source_count = len(
        {
            evidence_by_id[evidence_id].source_version_id
            for claim in material
            if claim.id in supported
            for evidence_id in claim.evidence_ids
            if evidence_id in evidence_by_id
        }
    )
    authority_synthesis = min(1.0, 0.55 * compare_ratio + 0.45 * min(1.0, source_count / 2))
    section_coverage = min(1.0, len([s for s in draft.sections if s.claims]) / 3)
    issue_spotting = 0.45 * section_coverage + 0.35 * question_alignment + 0.20 * element_ratio
    conclusion = draft.sections[-1] if draft.sections else None
    conclusion_text = " ".join(claim.text for claim in conclusion.claims) if conclusion else ""
    synthesis = float(
        bool(_REASONING.search(conclusion_text) or _COMPARISON.search(conclusion_text))
    )
    quotation_discipline = 0.0 if _LONG_QUOTE.search(full_text) else 1.0
    return {
        "support": support_ratio,
        "analysis": 0.55 * reasoned_ratio + 0.45 * support_ratio,
        "reasoning": reasoned_ratio,
        "application": 0.60 * application_ratio + 0.40 * support_ratio,
        "authority": 0.65 * support_ratio + 0.35 * authority_synthesis,
        "authority_synthesis": authority_synthesis,
        "issue_spotting": issue_spotting,
        "thesis": thesis,
        "question_alignment": question_alignment,
        "alternatives": alternative_ratio,
        "elements": element_ratio,
        "synthesis": synthesis,
        "quotation_discipline": quotation_discipline,
    }


def _rule_score(rule: AssessmentGuidanceRule, features: Mapping[str, float]) -> float:
    explicit: dict[str, float] = {
        "owner-universal-supported-analysis-v1": features["analysis"],
        "owner-universal-authority-at-claim-v1": features["support"],
        "owner-universal-unsupported-conclusion-v1": features["reasoning"],
        "owner-universal-omitted-issue-v1": features["issue_spotting"],
        "owner-problem-issue-application-v1": features["application"],
        "owner-problem-ranked-outcomes-v1": features["alternatives"],
        "owner-problem-partial-test-v1": features["elements"],
        "owner-problem-conclusory-application-v1": features["application"],
        "owner-essay-thesis-synthesis-v1": (features["thesis"] + features["synthesis"]) / 2,
        "owner-essay-authority-synthesis-v1": features["authority_synthesis"],
        "owner-essay-description-only-v1": features["analysis"],
        "owner-essay-quotation-dump-v1": features["quotation_discipline"],
        "assessment-canonical-case-synthesis-v1": features["authority_synthesis"],
        "owner-amended-criminal-element-defence-v2": features["elements"],
        "owner-amended-question-engagement-v2": features["question_alignment"],
        "assessment-canonical-timely-authority-support-v1": features["support"],
    }
    if rule.rule_id not in explicit:
        raise ValueError(f"sealed assessment rule has no scoring implementation: {rule.rule_id}")
    return round(100 * max(0.0, min(1.0, explicit[rule.rule_id])), 2)


def score_applicable_standards(
    *,
    draft: StructuredDraft,
    question: str,
    subject: str | None,
    evidence_by_id: Mapping[str, EvidenceSpan],
    supported_claim_ids: Sequence[str],
    bundle: AssessmentGuidanceBundle = OWNER_ASSESSMENT_BUNDLE,
) -> AssessmentStandardsReport:
    """Score the complete applicable set and return a prose-free sealed report."""

    task_type = str(draft.task_type)
    rules = applicable_guidance_rules(bundle, task_type=task_type, subject=subject)
    if not rules:
        raise ValueError("sealed standards bundle has no applicable rules")
    features = _observable_features(
        draft=draft,
        question=question,
        evidence_by_id=evidence_by_id,
        supported_claim_ids=supported_claim_ids,
    )
    scores: list[dict[str, Any]] = []
    for rule in rules:
        score = _rule_score(rule, features)
        threshold = 70.0 if rule.grade_band == "70+" else 65.0
        passed = score >= threshold
        scores.append(
            {
                "rule_id": rule.rule_id,
                "grade_band": rule.grade_band,
                "criterion": rule.criterion,
                "score": score,
                "passed": passed,
                "avoidance_rule": rule.grade_band != "70+",
                "anti_pattern_triggered": rule.grade_band != "70+" and not passed,
                "reason_codes": (
                    f"observable_{rule.criterion}_pass"
                    if passed
                    else f"observable_{rule.criterion}_below_threshold",
                ),
            }
        )
    draft_sha = source_draft_sha256(draft)
    material: dict[str, Any] = {
        "schema": STANDARDS_REPORT_SCHEMA,
        "bundle_version": bundle.version,
        "bundle_sha256": bundle.sha256,
        "source_draft_sha256": draft_sha,
        "question_sha256": hashlib.sha256(question.encode("utf-8")).hexdigest(),
        "task_type": task_type,
        "subject": subject,
        "applicable_rule_count": len(scores),
        "scores": scores,
        "avoidance_passed": all(item["passed"] for item in scores if item["avoidance_rule"]),
        "quality_target_met": all(item["passed"] for item in scores if not item["avoidance_rule"]),
        "legal_authority": False,
    }
    material["seal_sha256"] = _sealed_sha256(material)
    return AssessmentStandardsReport.model_validate(material)
