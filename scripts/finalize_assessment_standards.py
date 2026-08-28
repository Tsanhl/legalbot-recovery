#!/usr/bin/env python3
"""Replace raw marker fragments with reusable, owner-authorised standards."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.assessment.rules import (  # noqa: E402
    assessment_standard_privacy_issues,
    is_owner_style_reusable_standard,
)
from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database, utc_iso  # noqa: E402

POLICY = "legalbot.owner-assessment-standard-cleanup.v1"

# Each rule is a reusable writing/evaluation standard derived from an actual
# marker pattern.  No case proposition, student fact, grade fragment or owner
# identifier is carried into the canonical text.  subject=NULL means the rule
# is a cross-subject owner standard (see approved_assessment_rules matcher).
CANONICAL_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "assessment-canonical-accurate-application-v1",
        "source_rule_id": "assessment-rule-8af8eeb98566d7622b9193707b540a2a045d3048",
        "task_type": None,
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Apply each governing rule accurately and explicitly to the material facts; "
            "distinguish facts that support different outcomes rather than stating a conclusory result."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-analytical-comparison-v1",
        "source_rule_id": "assessment-rule-102d130f92a6dae0caf9eb8522fbe565b14616db",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Make comparisons analytically: identify the relevant similarity or difference "
            "and explain why it affects the legal argument or conclusion."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-authoritative-engagement-v1",
        "source_rule_id": "assessment-rule-102d130f92a6dae0caf9eb8522fbe565b14616db",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Engage directly with the relevant and authoritative cases and materials, "
            "explaining their significance rather than merely listing or describing them."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-citation-consistency-v1",
        "source_rule_id": "assessment-rule-cd306ce39869ef585c522ec03d29d0b0d34fa92b",
        "task_type": None,
        "criterion": "citation_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Use accurate and consistent citations at the point of each material proposition, "
            "with a verifiable authority identity and pinpoint where the source permits one."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-clarity-concision-v1",
        "source_rule_id": "assessment-rule-17088c6356f6310da240c9dd3e8cad3463f13286",
        "task_type": None,
        "criterion": "precision",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Express the analysis in clear, concise sentences while retaining enough "
            "reasoning for the reader to follow each conclusion."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-coherent-structure-v1",
        "source_rule_id": "assessment-rule-102d130f92a6dae0caf9eb8522fbe565b14616db",
        "task_type": "essay",
        "criterion": "organisation",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Use a clear structure in which each section advances an identifiable point "
            "and contributes to the answer's overall argument."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-doctrinal-precision-v1",
        "source_rule_id": "assessment-rule-62ccca81c560bd5645a46e605788a7a30365b7e9",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State the governing test, exception and remedy with doctrinal precision, and "
            "distinguish adjacent legal concepts where confusing them would change the outcome."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-ranked-outcomes-v1",
        "source_rule_id": "assessment-rule-8af8eeb98566d7622b9193707b540a2a045d3048",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain competing applications of the governing rules and state ranked likely "
            "outcomes, noting any missing fact that would change the advice."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-remedy-advice-v1",
        "source_rule_id": "assessment-rule-73b981246ce7d058e3a20c5d6b913a008fa6b259",
        "task_type": "problem",
        "criterion": "remedies",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Where the question seeks advice, identify available remedies and any "
            "procedural or evidential precondition before giving a proportionate conclusion."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-scholarship-integration-v1",
        "source_rule_id": "assessment-rule-2dc9660e4223800df02f519ed5cf187e5a9e409f",
        "task_type": "essay",
        "criterion": "scholarship",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Integrate relevant academic views and empirical or statistical material into "
            "the analysis, explaining how each source supports, qualifies, or challenges the argument."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-thesis-counterargument-v1",
        "source_rule_id": "assessment-rule-b69f5db3e1b6827a10733d3367f45652863cc4fc",
        "task_type": None,
        "criterion": "counterargument",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Sustain a clear thesis throughout the answer and test it against the strongest "
            "contrary argument or limiting authority before reaching the conclusion."
        ),
        "remediation_text": None,
    },
    {
        "id": "assessment-canonical-inferential-link-v1",
        "source_rule_id": "assessment-rule-1d9705c980d28350870922786f93430b8307b06f",
        "task_type": None,
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not assert that a proposition proves a conclusion without explaining the "
            "connecting reasoning."
        ),
        "remediation_text": (
            "Add the missing inferential step and show why the cited rule or fact supports "
            "the stated conclusion."
        ),
    },
    {
        "id": "assessment-canonical-section-depth-v1",
        "source_rule_id": "assessment-rule-102d130f92a6dae0caf9eb8522fbe565b14616db",
        "task_type": None,
        "criterion": "organisation",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not fragment the answer into sections too brief to sustain a reasoned point; "
            "develop each material issue to a supported conclusion."
        ),
        "remediation_text": (
            "Merge or expand thin sections so each material issue reaches a supported "
            "intermediate conclusion."
        ),
    },
    {
        "id": "assessment-canonical-timely-authority-support-v1",
        "source_rule_id": "assessment-rule-1d9705c980d28350870922786f93430b8307b06f",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Support each material proposition with appropriate authority at the point where "
            "it is made; do not postpone essential references until a later section."
        ),
        "remediation_text": (
            "Add the relevant primary or approved secondary authority beside the material "
            "proposition and explain its relevance."
        ),
    },
    {
        "id": "assessment-canonical-case-synthesis-v1",
        "source_rule_id": "assessment-rule-0515a8d4b3595f3d87e095cb661df096742feba6",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not discuss key authorities as isolated summaries; explain the relationship "
            "between the cases and make that synthesis central to the essay argument."
        ),
        "remediation_text": (
            "Compare the material cases, identify agreement or tension between them, and "
            "explain how their relationship supports the thesis."
        ),
    },
    {
        "id": "assessment-canonical-complete-issue-coverage-v1",
        "source_rule_id": "assessment-rule-73b981246ce7d058e3a20c5d6b913a008fa6b259",
        "task_type": None,
        "criterion": "issue_spotting",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not omit a material element, defence, remedy or alternative classification "
            "raised by the facts; address it or explain expressly why it is ruled out."
        ),
        "remediation_text": (
            "Create an issue checklist from the question, then add a supported conclusion or "
            "express exclusion for every material item."
        ),
    },
    {
        "id": "assessment-canonical-explicit-reasoning-v1",
        "source_rule_id": "assessment-rule-2a506def86233effdc377999f4954d178b4243d4",
        "task_type": None,
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not compress the reasoning so far that the conclusion is difficult to follow; "
            "state the intermediate legal inference and explain how it leads to the result."
        ),
        "remediation_text": (
            "Expand the reasoning chain: identify the rule, the relevant fact or premise, "
            "the inference drawn, and the resulting conclusion."
        ),
    },
    {
        "id": "assessment-canonical-meaningful-headings-v1",
        "source_rule_id": "assessment-rule-0515a8d4b3595f3d87e095cb661df096742feba6",
        "task_type": None,
        "criterion": "organisation",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Avoid generic headings; each heading should identify the substantive issue or "
            "argumentative function of its section."
        ),
        "remediation_text": (
            "Rewrite headings so that a reader can understand the section's legal issue or "
            "argumentative purpose from the heading alone."
        ),
    },
    {
        "id": "assessment-canonical-problem-pacing-v1",
        "source_rule_id": "assessment-rule-73b981246ce7d058e3a20c5d6b913a008fa6b259",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not rush through a problem scenario; allocate analysis to each material "
            "claim, offence or defence before moving on."
        ),
        "remediation_text": (
            "Slow the walk-through: for each party and issue, state the test, apply the "
            "facts, then conclude before advancing."
        ),
    },
    {
        "id": "assessment-canonical-question-engagement-v1",
        "source_rule_id": "assessment-rule-5f2f371e9b3687092bebb7207c562915a3edf94f",
        "task_type": None,
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not write a legally relevant but question-neutral discussion; make every "
            "section advance an answer to the precise problem or proposition set."
        ),
        "remediation_text": (
            "State the answer's controlling proposition, then connect each section's conclusion "
            "back to that proposition."
        ),
    },
    {
        "id": "assessment-canonical-scope-discipline-v1",
        "source_rule_id": "assessment-rule-5f2f371e9b3687092bebb7207c562915a3edf94f",
        "task_type": None,
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not spend scarce words on topics outside the question's scope at the expense "
            "of the issues that determine the answer."
        ),
        "remediation_text": (
            "Cut out-of-scope material and reallocate the words to the issues that decide "
            "the question."
        ),
    },
    {
        "id": "assessment-canonical-tort-negligence-structure-v1",
        "source_rule_id": "assessment-rule-8af8eeb98566d7622b9193707b540a2a045d3048",
        "subject": "tort",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "For negligence analysis, state the governing duty, breach, causation and "
            "remoteness tests before applying each to the material facts."
        ),
        "remediation_text": (
            "Map duty, breach, causation and remoteness in order; state each test, apply "
            "the material facts, then conclude before moving on."
        ),
    },
    {
        "id": "assessment-canonical-trusts-classification-v1",
        "source_rule_id": "assessment-rule-62ccca81c560bd5645a46e605788a7a30365b7e9",
        "subject": "trusts",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State the correct classification of the trust or equitable claim before "
            "applying formalities, constitution and remedial consequences."
        ),
        "remediation_text": (
            "Identify the claim type first, then apply the formalities, constitution and "
            "remedy analysis that follow from that classification."
        ),
    },
    {
        "id": "assessment-canonical-criminal-element-defence-v1",
        "source_rule_id": "assessment-rule-73b981246ce7d058e3a20c5d6b913a008fa6b259",
        "subject": "criminal",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not leave an offence element or available defence unaddressed; conclude on "
            "each element or explain expressly why it is ruled out."
        ),
        "remediation_text": (
            "Create an element-and-defence checklist for each offence, then conclude or "
            "expressly exclude every item before ending the analysis."
        ),
    },
    {
        "id": "assessment-canonical-eu-quote-engagement-v1",
        "source_rule_id": "assessment-rule-5f2f371e9b3687092bebb7207c562915a3edf94f",
        "subject": "eu and internal market",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not summarise case law without embedding it in an answer to the set "
            "proposition or quotation."
        ),
        "remediation_text": (
            "State how each authority advances, qualifies or challenges the set "
            "proposition or quotation before moving to the next case."
        ),
    },
)

# Cross-subject candidates stay proposed-only until the owner promotes them. Never auto-applied.
PROPOSED_GENERAL_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "assessment-proposed-general-irac-map-v1",
        "subject": None,
        "task_type": "problem",
        "criterion": "organisation",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Map issues for each party first, then state the governing rule, apply the material facts, and conclude before the next issue."
        ),
        "remediation_text": (
            "Create a short issue map, then apply rule, facts and conclusion for each material issue in order."
        ),
        "rationale": "Problem-method theme across Y2/Y3 feedback: incomplete IRAC/ILAC sequencing.",
    },
    {
        "id": "assessment-proposed-general-essay-roadmap-v1",
        "subject": None,
        "task_type": "essay",
        "criterion": "organisation",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State a brief roadmap that answers the set proposition and identifies the sequence of supporting sections."
        ),
        "remediation_text": (
            "Rewrite the introduction so it answers the question and previews the analytical path rather than listing topics."
        ),
        "rationale": "Essay-instruction pattern: introductions that catalogue topics without answering the set question.",
    },
    {
        "id": "assessment-proposed-general-pinpoint-authority-v1",
        "subject": None,
        "task_type": None,
        "criterion": "citation_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Support each material proposition with pinpointed primary or approved secondary authority at the point the proposition is made."
        ),
        "remediation_text": (
            "Add a pinpoint paragraph or page reference beside each material claim and test that the source supports it."
        ),
        "rationale": "General feedback theme: marks lost where pinpointing is missing or copied unchecked.",
    },
    {
        "id": "assessment-proposed-general-hierarchy-authority-v1",
        "subject": None,
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Use the highest available domestic court authority for a proposition, and explain when a lower decision has been overruled or qualified."
        ),
        "remediation_text": (
            "Identify the status of each cited decision and revise any superseded authority before relying on it."
        ),
        "rationale": "Authority hierarchy theme in module general feedback.",
    },
    {
        "id": "assessment-proposed-general-missing-facts-assumptions-v1",
        "subject": None,
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify ambiguous or missing facts expressly, state the assumption used, and explain how a different assumption would change the advice."
        ),
        "remediation_text": (
            "Add a short assumptions paragraph for each material gap before applying the governing rule."
        ),
        "rationale": "Problem-question theme: marks turn on stated assumptions about incomplete facts.",
    },
    {
        "id": "assessment-proposed-general-short-clear-prose-v1",
        "subject": None,
        "task_type": None,
        "criterion": "precision",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Express the analysis in short sentences and short paragraphs so each legal step remains readable under word limits."
        ),
        "remediation_text": (
            "Revise long sentences and padded paragraphs while retaining the reasoning chain."
        ),
        "rationale": "Writing-style checklist theme from essay risk-management materials.",
    },
    {
        "id": "assessment-proposed-general-oscola-discipline-v1",
        "subject": None,
        "task_type": "essay",
        "criterion": "citation_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Use the required citation style consistently in footnotes and bibliography, with pinpoints where the source permits them."
        ),
        "remediation_text": (
            "Add a citation checklist pass for footnotes, bibliography order and pinpoints before submission."
        ),
        "rationale": "Cross-module theme: avoidable citation-style mark loss.",
    },
    {
        "id": "assessment-proposed-general-reform-opinion-grounded-v1",
        "subject": None,
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain any reform opinion through doctrine, competing arguments and practical consequences rather than assertion alone."
        ),
        "remediation_text": (
            "Support each reform claim with authority or evidence and address the strongest contrary argument."
        ),
        "rationale": "Essay-instruction pattern from assessment criteria and medicine essay guidance.",
    },
    {
        "id": "assessment-proposed-general-description-trap-v1",
        "subject": None,
        "task_type": None,
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not stop at a descriptive summary of principles; explain how those principles decide the issue raised by the question."
        ),
        "remediation_text": (
            "Add the application or evaluative step that answers the question after stating each principle."
        ),
        "rationale": "Common mid-band pattern: accurate description without decisive analysis.",
    },
    {
        "id": "assessment-proposed-general-partial-test-v1",
        "subject": None,
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not apply a truncated legal test; state every material element or condition before concluding on liability or validity."
        ),
        "remediation_text": (
            "Expand the full statutory or common-law test and conclude on each element against the facts."
        ),
        "rationale": "Land and problem feedback theme: overlooked elements in multi-part tests.",
    },
    {
        "id": "assessment-proposed-general-quote-dump-v1",
        "subject": None,
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not paste long quotations or case narratives in place of reasoned engagement with the set proposition."
        ),
        "remediation_text": (
            "Cut quotation blocks and explain the holding, its limits, and how it advances or challenges the thesis."
        ),
        "rationale": "Essay-instruction anti-pattern across modules.",
    },
    {
        "id": "assessment-proposed-general-generic-headings-problem-v1",
        "subject": None,
        "task_type": "problem",
        "criterion": "organisation",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Avoid generic problem headings such as Issue or Application; identify the party, claim or statutory gateway being decided."
        ),
        "remediation_text": (
            "Rewrite each heading with the concrete legal issue and party so the structure doubles as an issue checklist."
        ),
        "rationale": "Problem-structure theme reinforcing meaningful headings for advice answers.",
    },
    {
        "id": "assessment-proposed-general-unchecked-secondary-pinpoint-v1",
        "subject": None,
        "task_type": None,
        "criterion": "citation_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not rely on pinpoints copied from secondary sources without testing that the primary source supports the proposition."
        ),
        "remediation_text": (
            "Identify the cited primary source, support the pinpoint, and revise the claim if the support is weaker or different."
        ),
        "rationale": "General feedback warning against unverified borrowed pinpoints.",
    },
    {
        "id": "assessment-proposed-general-conclusion-confidence-v1",
        "subject": None,
        "task_type": None,
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State a clear conclusion that follows from the preceding analysis, and rank alternatives only where the law or facts are unsettled."
        ),
        "remediation_text": (
            "Express an intermediate conclusion for each material issue tied to the rules and facts already discussed."
        ),
        "rationale": "Risk-management theme: conclusions must flow from earlier reasoning.",
    },
    {
        "id": "assessment-proposed-general-syllabus-scope-v1",
        "subject": None,
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not chase adjacent topics outside the examinable syllabus when the set question can be answered within module materials."
        ),
        "remediation_text": (
            "Cut out-of-syllabus digressions and expand the examinable authorities that decide the question."
        ),
        "rationale": "Exam-instruction theme: wide reading still bounded by syllabus exclusions.",
    },
)

# Subject-scoped candidates stay proposed-only until the owner confirms the Law-folder marker evidence and subject labels. They are never auto-applied.
PROPOSED_SUBJECT_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "assessment-proposed-pensions-statute-deed-interaction-v1",
        "subject": "pensions",
        "task_type": "problem",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Distinguish statutory meanings from trust-deed definitions, and apply deed construction before importing statutory vocabulary by analogy."
        ),
        "remediation_text": (
            "State whether a term is defined in the deed or only in statute, then apply the controlling instrument to the facts."
        ),
        "rationale": "Pensions formative general feedback: statutory definitions do not auto-apply to deeds.",
    },
    {
        "id": "assessment-proposed-pensions-amendment-power-v1",
        "subject": "pensions",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify the amendment power, any fetter, and any statutory restriction protecting subsisting rights before advising on benefit changes."
        ),
        "remediation_text": (
            "Map the analysis as power scope, fetter, statutory restriction, then consultation or process requirements."
        ),
        "rationale": "Pensions problem theme: amendment power and statutory overlays decide outcomes.",
    },
    {
        "id": "assessment-proposed-pensions-trustee-purpose-investment-v1",
        "subject": "pensions",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State the scheme purpose and statutory activity limits before explaining whether trustees may consider non-financial factors."
        ),
        "remediation_text": (
            "Explain the purpose constraint first, then test whether non-financial factors can be considered within that frame."
        ),
        "rationale": "Pensions summative theme on trustee investment and non-financial factors.",
    },
    {
        "id": "assessment-proposed-pensions-authority-hierarchy-v1",
        "subject": "pensions",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Use Supreme Court and Court of Appeal pension authorities ahead of first-instance or ombudsman determinations unless distinguishing on facts."
        ),
        "remediation_text": (
            "Explain any reliance on lower determinations and support the proposition with the highest binding level available."
        ),
        "rationale": "Pensions feedback theme on court hierarchy and ombudsman use.",
    },
    {
        "id": "assessment-proposed-pensions-missing-process-facts-v1",
        "subject": "pensions",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not assume consent, certificates or consultation occurred when the facts are silent; state the assumption and the process consequence."
        ),
        "remediation_text": (
            "Identify each missing process fact, state an express assumption, and explain how the advice changes if the assumption fails."
        ),
        "rationale": "Pensions summative theme: missing process facts affect amendment and equality analysis.",
    },
    {
        "id": "assessment-proposed-pensions-equalisation-shortcut-v1",
        "subject": "pensions",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not treat equalisation or amendment rules as a single automatic uplift; explain statute, deed and amendment timing on the facts."
        ),
        "remediation_text": (
            "Map the timeline of deed amendments and statutory overlays before stating any benefit figure or legality conclusion."
        ),
        "rationale": "Pensions summative common error pattern around equalisation and amendment timing.",
    },
    {
        "id": "assessment-proposed-pensions-conflicted-trustee-v1",
        "subject": "pensions",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not ignore conflicts of interest or improper purpose when trustees decide benefits; address authorising deed wording and remaining review grounds."
        ),
        "remediation_text": (
            "Add conflict, purpose and relevant-factor analysis after identifying who may lawfully receive payment."
        ),
        "rationale": "Pensions formative theme on trustee decision challenges.",
    },
    {
        "id": "assessment-proposed-pensions-ombudsman-jurisdiction-v1",
        "subject": "pensions",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify Pensions Ombudsman standing and jurisdiction from the claimant's relationship to the scheme before advising a complaint route."
        ),
        "remediation_text": (
            "State the standing gateway and explain whether the ombudsman route is open on the assumed facts."
        ),
        "rationale": "Pensions formative theme on ombudsman access and standing expansions.",
    },
    {
        "id": "assessment-proposed-competition-market-definition-first-v1",
        "subject": "competition",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify the relevant product and geographic market, and the theory of harm, before explaining dominance or restrictive effects."
        ),
        "remediation_text": (
            "State market definition and theory of harm, then apply the abuse or agreement analysis to that frame."
        ),
        "rationale": "Competition formative/essay pattern: market definition precedes abuse analysis.",
    },
    {
        "id": "assessment-proposed-competition-effects-not-labels-v1",
        "subject": "competition",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain competitive effects and objective justification with authority, rather than applying abuse labels to conduct alone."
        ),
        "remediation_text": (
            "State the foreclosure or exploitation theory for each contested practice and address any objective justification on the facts."
        ),
        "rationale": "Competition materials emphasise effects-based reasoning over conclusory labels.",
    },
    {
        "id": "assessment-proposed-competition-primary-eu-authority-v1",
        "subject": "competition",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Engage the governing Treaty provisions and leading Union judgments, explaining how later cases refine earlier abuse or agreement tests."
        ),
        "remediation_text": (
            "Compare the material authorities and explain how their relationship develops the applicable test."
        ),
        "rationale": "Competition formative packs centre on primary EU case law engagement.",
    },
    {
        "id": "assessment-proposed-competition-case-summary-trap-v1",
        "subject": "competition",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not summarise landmark competition judgments in isolation; explain their relationship as central to the set proposition."
        ),
        "remediation_text": (
            "Compare the material cases and explain how their relationship supports or limits the thesis."
        ),
        "rationale": "Cross-cutting essay AVOID adapted to competition authorities.",
    },
    {
        "id": "assessment-proposed-competition-policy-without-doctrine-v1",
        "subject": "competition",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not advance privacy, fairness or industrial-policy claims without applying the legal test for restriction, abuse or merger control."
        ),
        "remediation_text": (
            "Support each policy claim through the doctrinal gateway and authority before concluding."
        ),
        "rationale": "Competition essays risk policy discussion detaching from legal tests.",
    },
    {
        "id": "assessment-proposed-competition-remedy-or-commitment-v1",
        "subject": "competition",
        "task_type": "essay",
        "criterion": "remedies",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify the available competition remedy or commitment structure and its legal basis before explaining enforcement effectiveness."
        ),
        "remediation_text": (
            "State the remedy or commitment tool, apply its legal gateway, and explain effectiveness criteria on the facts or policy scenario."
        ),
        "rationale": "Competition enforcement essays need remedy architecture, not infringement labels alone.",
    },
    {
        "id": "assessment-proposed-pil-gateway-select-v1",
        "subject": "private international law",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify a concrete jurisdiction, choice-of-law or judgments gateway and sustain a thesis about how English PIL should develop for that gateway."
        ),
        "remediation_text": (
            "State the gateway in the introduction and support it in every section and the conclusion."
        ),
        "rationale": "PIL formative asks for focused development of one PIL gateway.",
    },
    {
        "id": "assessment-proposed-pil-instrument-precision-v1",
        "subject": "private international law",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify the applicable convention, regulation or common-law rule with precision, and explain when retained or assimilated rules still control."
        ),
        "remediation_text": (
            "State the controlling instrument for each issue and explain any post-Brexit status qualification before applying it."
        ),
        "rationale": "PIL doctrine turns on choosing the correct conflicts instrument.",
    },
    {
        "id": "assessment-proposed-pil-commercial-reality-v1",
        "subject": "private international law",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Test proposed PIL reforms against cross-border commercial practice and fundamental conflicts principles, not convenience alone."
        ),
        "remediation_text": (
            "Explain commercial predictability and doctrinal coherence for each reform claim with supporting authority."
        ),
        "rationale": "PIL formative framing on commercial responsiveness and principle.",
    },
    {
        "id": "assessment-proposed-pil-forum-shopping-assertion-v1",
        "subject": "private international law",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not treat forum shopping as inherently illegitimate or beneficial without applying the governing stay, service or jurisdiction test."
        ),
        "remediation_text": (
            "Apply the relevant jurisdiction or stay framework before explaining the force of forum-choice rhetoric."
        ),
        "rationale": "PIL materials foreground jurisdiction tests over slogans.",
    },
    {
        "id": "assessment-proposed-pil-unscoped-survey-v1",
        "subject": "private international law",
        "task_type": "essay",
        "criterion": "organisation",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not survey jurisdiction, choice of law and judgments in one short essay; sustain one gateway to a supported conclusion."
        ),
        "remediation_text": (
            "Cut the survey and expand a single gateway with authorities and a clear thesis."
        ),
        "rationale": "PIL formative word limits reward focused gateway essays.",
    },
    {
        "id": "assessment-proposed-pil-authority-currency-v1",
        "subject": "private international law",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not rely on pre-instrument common-law rhetoric where a later convention or regulation supplies the governing test."
        ),
        "remediation_text": (
            "Identify whether the common-law case remains persuasive history or has been displaced by the instrument in force."
        ),
        "rationale": "PIL essays must track instrument supersession carefully.",
    },
    {
        "id": "assessment-proposed-commercial-title-risk-map-v1",
        "subject": "commercial",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Map who has property in the goods, who bears risk, and which nemo dat or statutory exception may pass title before advising on remedies."
        ),
        "remediation_text": (
            "Create a title-and-risk timeline, then apply the Sale of Goods and nemo dat gateways to each claimant."
        ),
        "rationale": "Commercial teaching and exams centre on title, risk and nemo dat sequencing.",
    },
    {
        "id": "assessment-proposed-commercial-statutory-implied-terms-v1",
        "subject": "commercial",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State the applicable implied term or quality gateway, any exclusion controls, and the buyer or seller remedy ladder before concluding."
        ),
        "remediation_text": (
            "Identify the statutory section, test exclusion validity, then apply the proportionate remedy on the facts."
        ),
        "rationale": "Commercial problem pattern: implied terms, exclusions and remedies.",
    },
    {
        "id": "assessment-proposed-commercial-agency-authority-v1",
        "subject": "commercial",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Distinguish actual, apparent and usual authority, and explain which third-party protections follow from the facts."
        ),
        "remediation_text": (
            "Identify the agent's authority first, then explain principal liability and available remedies."
        ),
        "rationale": "Commercial agency issues recur in problem scenarios.",
    },
    {
        "id": "assessment-proposed-commercial-rot-without-priority-v1",
        "subject": "commercial",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not stop after identifying a retention-of-title clause; explain registration, attachment and competing claims that affect priority."
        ),
        "remediation_text": (
            "Test effectiveness against the buyer, sub-buyer and any secured creditor after spotting the clause."
        ),
        "rationale": "Commercial ROT answers often under-analyse priority consequences.",
    },
    {
        "id": "assessment-proposed-commercial-remedy-skip-v1",
        "subject": "commercial",
        "task_type": "problem",
        "criterion": "remedies",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not conclude on breach without identifying available rejection, damages or other commercial remedies and their preconditions."
        ),
        "remediation_text": (
            "Add the remedy ladder and any acceptance or mitigation facts before the final advice."
        ),
        "rationale": "Commercial exams expect remedy conclusions, not breach labels alone.",
    },
    {
        "id": "assessment-proposed-commercial-nemo-dat-exceptions-v1",
        "subject": "commercial",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Apply nemo dat as the starting point, then test each statutory exception against the precise facts rather than asserting an exception by label."
        ),
        "remediation_text": (
            "State nemo dat, identify possible exceptions, and apply the factual preconditions of each exception before concluding on title."
        ),
        "rationale": "Commercial teaching repeatedly drills nemo dat exception preconditions.",
    },
    {
        "id": "assessment-proposed-land-registration-priority-v1",
        "subject": "land",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify whether each interest is legal or equitable, whether registration or protection was completed, and who is bound under the Land Registration Act framework."
        ),
        "remediation_text": (
            "State formality, registration or protection status for each interest, then apply priority against the purchaser on the facts."
        ),
        "rationale": "Land formative feedforward: registration and priority drive outcomes.",
    },
    {
        "id": "assessment-proposed-land-issue-isolation-v1",
        "subject": "land",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify each proprietary claim and the facts that support or undermine it before applying the governing statutory or common-law test."
        ),
        "remediation_text": (
            "Create an interest list with supporting facts first, then apply each claim to a conclusion."
        ),
        "rationale": "Land formative success pattern: isolating interests and pertinent principles.",
    },
    {
        "id": "assessment-proposed-land-actual-occupation-engagement-v1",
        "subject": "land",
        "task_type": "problem",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Engage the leading authorities on actual occupation where overriding interests are in issue, and apply them to the concrete facts."
        ),
        "remediation_text": (
            "State the occupation test, compare material authorities, and apply the occupation evidence before concluding on priority."
        ),
        "rationale": "Land feedback highlights strong use of occupation authorities.",
    },
    {
        "id": "assessment-proposed-land-partial-lra-test-v1",
        "subject": "land",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not apply a partial Land Registration Act test; address formality, registration or notice, and priority consequences as a complete sequence."
        ),
        "remediation_text": (
            "Expand the full registration sequence for each interest rather than jumping to a binding conclusion."
        ),
        "rationale": "Land formative AVOID: overlooked elements such as completion by registration.",
    },
    {
        "id": "assessment-proposed-land-description-only-v1",
        "subject": "land",
        "task_type": "problem",
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not offer only a basic description of land-law principles; apply them to the disposition and competing interests on the facts."
        ),
        "remediation_text": (
            "Cut textbook summaries and explain interest-by-interest application with ranked outcomes."
        ),
        "rationale": "Land formative weak pattern: superficial description without fact application.",
    },
    {
        "id": "assessment-proposed-land-easement-formality-v1",
        "subject": "land",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify easement creation formality, legal versus equitable status, and registration or notice consequences before advising who is bound."
        ),
        "remediation_text": (
            "Apply grant formality, registration completion, and priority against the disponee in that order."
        ),
        "rationale": "Land formative example pattern on express easements and registration.",
    },
    {
        "id": "assessment-proposed-contract-formation-sequence-v1",
        "subject": "contract",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Apply offer, acceptance, consideration and intention in sequence, and distinguish formation defects from later vitiation or breach issues."
        ),
        "remediation_text": (
            "Address formation first, then apply terms, vitiation, breach and remedies only as raised by the facts."
        ),
        "rationale": "Contract problem method: keep formation logically prior to remedies.",
    },
    {
        "id": "assessment-proposed-contract-term-classification-v1",
        "subject": "contract",
        "task_type": "problem",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify term classification, incorporation and any exclusion controls before explaining termination or damages consequences."
        ),
        "remediation_text": (
            "State how the term was incorporated and classified, then apply the remedy consequences to the breach facts."
        ),
        "rationale": "Contract teaching emphasises terms and exclusion analysis before remedies.",
    },
    {
        "id": "assessment-proposed-contract-remedy-fit-v1",
        "subject": "contract",
        "task_type": "problem",
        "criterion": "remedies",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Apply remedies that fit the breach and loss claimed, explaining causation, remoteness and any duty to mitigate where relevant."
        ),
        "remediation_text": (
            "Identify the breach, then apply damages or specific-performance controls to the claimant's loss on the facts."
        ),
        "rationale": "Contract problems reward remedy-fit analysis.",
    },
    {
        "id": "assessment-proposed-contract-issue-merge-v1",
        "subject": "contract",
        "task_type": "problem",
        "criterion": "organisation",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not merge formation, vitiation and breach into one undifferentiated discussion; distinguish the gateways that change the outcome."
        ),
        "remediation_text": (
            "Rewrite sections by gateway and conclude on each before combining advice."
        ),
        "rationale": "Contract answers lose clarity when gateways are collapsed.",
    },
    {
        "id": "assessment-proposed-contract-authority-list-v1",
        "subject": "contract",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not list classic contract cases without explaining how each advances the thesis on doctrine or reform."
        ),
        "remediation_text": (
            "Compare the authorities around the essay proposition rather than narrating case histories."
        ),
        "rationale": "Contract essay AVOID mirroring general case-synthesis failures.",
    },
    {
        "id": "assessment-proposed-contract-exclusion-controls-v1",
        "subject": "contract",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not accept an exclusion clause at face value; test incorporation, construction and statutory controls before denying a remedy."
        ),
        "remediation_text": (
            "Add incorporation, construction and unfair-terms analysis before concluding that liability is excluded."
        ),
        "rationale": "Contract problems commonly under-test exclusion clauses.",
    },
    {
        "id": "assessment-proposed-medicine-capacity-sequence-v1",
        "subject": "law and medicine",
        "task_type": "problem",
        "criterion": "application",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Apply present capacity first, then any advance refusal or proxy, then best-interests analysis under the Mental Capacity Act framework."
        ),
        "remediation_text": (
            "Map capacity, advance-decision validity and applicability, then apply best-interests factors before advising."
        ),
        "rationale": "Law-and-medicine exam issues teaching: capacity then advance refusal then best interests.",
    },
    {
        "id": "assessment-proposed-medicine-consent-lawful-basis-v1",
        "subject": "law and medicine",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify the lawful basis for each intervention—consent, parental responsibility, necessity or statutory authority—before explaining ethics labels."
        ),
        "remediation_text": (
            "State the legal gateway for each patient and procedure, then use ethics only to illuminate that gateway."
        ),
        "rationale": "Medicine problem method: legal basis precedes ethical commentary.",
    },
    {
        "id": "assessment-proposed-medicine-justify-statutory-claims-v1",
        "subject": "law and medicine",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State what a cited statutory provision requires and explain how it supports the autonomy, best-interests or reform claim being made."
        ),
        "remediation_text": (
            "Expand bare section numbers into a short statement of operative words and their effect on the argument."
        ),
        "rationale": "Medicine essay guidance: justify legal points; do not assert section effects.",
    },
    {
        "id": "assessment-proposed-medicine-ethics-without-law-v1",
        "subject": "law and medicine",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not answer a law-and-medicine essay with ethics alone; integrate doctrine, leading cases and reform arguments that answer the set question."
        ),
        "remediation_text": (
            "Support each ethical claim with the governing legal materials and competing reform views."
        ),
        "rationale": "Medicine assessment criteria require legal synthesis, not ethics freewriting.",
    },
    {
        "id": "assessment-proposed-medicine-wrong-question-v1",
        "subject": "law and medicine",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not substitute a preferred topic for the set quotation or reform proposition; identify limited examples that still answer the question asked."
        ),
        "remediation_text": (
            "State the set proposition, select two or three fitting examples, and support each section back to that proposition."
        ),
        "rationale": "Medicine exam advice: answer the question set, not a preferred substitute.",
    },
    {
        "id": "assessment-proposed-medicine-policy-as-statute-v1",
        "subject": "law and medicine",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not treat clinical policy as if it were primary legislation; distinguish statute, case law and policy when stating what the law requires."
        ),
        "remediation_text": (
            "Identify each source as statute, case or policy and revise the strength of the claim accordingly."
        ),
        "rationale": "Medicine essay feedback theme on conflating policy with legal prohibition.",
    },
    {
        "id": "assessment-proposed-medicine-child-consent-gateway-v1",
        "subject": "law and medicine",
        "task_type": "problem",
        "criterion": "issue_spotting",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Distinguish Gillick competence, parental responsibility and court powers for child patients before concluding on lawful treatment."
        ),
        "remediation_text": (
            "Address child capacity, parental consent and any need for court authorisation on the facts in turn."
        ),
        "rationale": "Medicine exam issues teaching on child treatment consent gateways.",
    },
    {
        "id": "assessment-proposed-icm-doctrine-framework-v1",
        "subject": "international commercial mediation",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Engage the governing domestic authorities and international instruments that control enforceability, confidentiality or costs sanctions."
        ),
        "remediation_text": (
            "Identify the controlling instrument or leading case for each claim before explaining reform."
        ),
        "rationale": "ICM summative materials centre on Singapore Convention and leading ADR authorities.",
    },
    {
        "id": "assessment-proposed-icm-enforceability-analysis-v1",
        "subject": "international commercial mediation",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain when a mediated settlement is enforceable and which refusal or misconduct grounds may defeat enforcement."
        ),
        "remediation_text": (
            "Map enforceability requirements and defences with authority rather than describing mediation benefits alone."
        ),
        "rationale": "ICM essay pattern: enforceability and defences, not ADR advocacy.",
    },
    {
        "id": "assessment-proposed-icm-confidentiality-limits-v1",
        "subject": "international commercial mediation",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State the legal limits of mediation confidentiality and without-prejudice protection where they affect advice or enforcement."
        ),
        "remediation_text": (
            "Distinguish confidentiality, privilege and statutory disclosure duties before concluding."
        ),
        "rationale": "ICM reading emphasises confidentiality boundaries.",
    },
    {
        "id": "assessment-proposed-icm-benefits-catalogue-v1",
        "subject": "international commercial mediation",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not catalogue the general benefits of mediation without answering the enforceability, regulation or reform question set."
        ),
        "remediation_text": (
            "Cut generic ADR praise and rewrite the essay around the legal proposition and authorities."
        ),
        "rationale": "ICM weak essays drift into mediation advocacy.",
    },
    {
        "id": "assessment-proposed-icm-instrument-blur-v1",
        "subject": "international commercial mediation",
        "task_type": None,
        "criterion": "authority_accuracy",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not blur soft-law guidance, domestic case management powers and treaty enforcement rules as if they had the same legal force."
        ),
        "remediation_text": (
            "Identify each source's legal status and apply only the instruments that govern the issue."
        ),
        "rationale": "ICM materials mix domestic ADR case law with treaty regimes.",
    },
    {
        "id": "assessment-proposed-icm-costs-sanctions-link-v1",
        "subject": "international commercial mediation",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain unreasonable refusal to mediate through domestic costs-sanctions authorities linked to the facts or reform claim with precision."
        ),
        "remediation_text": (
            "State the costs-sanctions test and apply it to the scenario or reform proposal."
        ),
        "rationale": "ICM authorities include leading costs-sanctions mediation cases.",
    },
    {
        "id": "assessment-proposed-dissertation-research-question-v1",
        "subject": "dissertation",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "State a precise research question and sustain a thesis that answers it with structured chapters rather than a loose topic survey."
        ),
        "remediation_text": (
            "Revise the research question until each chapter has an identifiable contribution to the answer."
        ),
        "rationale": "Dissertation core-elements materials emphasise research-question discipline.",
    },
    {
        "id": "assessment-proposed-dissertation-method-transparency-v1",
        "subject": "dissertation",
        "task_type": "essay",
        "criterion": "organisation",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain the doctrinal, comparative or empirical method used and the limits of that method for the conclusions drawn."
        ),
        "remediation_text": (
            "Add a methods subsection that states sources, selection criteria and limitations."
        ),
        "rationale": "Dissertation expectations include method transparency.",
    },
    {
        "id": "assessment-proposed-dissertation-literature-synthesis-v1",
        "subject": "dissertation",
        "task_type": "essay",
        "criterion": "scholarship",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Integrate scholarship and primary materials to advance the thesis; do not leave literature as an unintegrated annotated catalogue."
        ),
        "remediation_text": (
            "Compare sources by argumentative function and explain agreement, tension and gaps."
        ),
        "rationale": "Dissertation quality turns on synthesis, not bibliography length.",
    },
    {
        "id": "assessment-proposed-dissertation-unanswered-rq-v1",
        "subject": "dissertation",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not end chapters with description that never returns to the research question or contested claim."
        ),
        "remediation_text": (
            "Express an intermediate conclusion in each chapter that advances the overall thesis."
        ),
        "rationale": "Dissertation AVOID: topic tours without answers.",
    },
    {
        "id": "assessment-proposed-dissertation-ethics-omission-v1",
        "subject": "dissertation",
        "task_type": "essay",
        "criterion": "organisation",
        "polarity": "error_to_avoid",
        "grade_band": "60-69",
        "rule_text": (
            "Do not ignore research-ethics and source-rights constraints where the project uses personal data, interviews or restricted materials."
        ),
        "remediation_text": (
            "State the ethics and rights position early and sustain methods within the approved envelope."
        ),
        "rationale": "Dissertation folders include ethics confirmation as a process constraint.",
    },
    {
        "id": "assessment-proposed-biolaw-regulatory-instrument-v1",
        "subject": "biolaw",
        "task_type": "essay",
        "criterion": "authority_accuracy",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Identify the governing data-protection or biolaw instrument and explain how its operative requirements apply to the technology or practice discussed."
        ),
        "remediation_text": (
            "State the instrument and map each material claim to a specific requirement, exception or enforcement consequence."
        ),
        "rationale": "Biolaw formative work centres on GDPR and related governance instruments.",
    },
    {
        "id": "assessment-proposed-biolaw-rights-risk-balance-v1",
        "subject": "biolaw",
        "task_type": "essay",
        "criterion": "analysis",
        "polarity": "positive_pattern",
        "grade_band": "70+",
        "rule_text": (
            "Explain claimed innovation benefits against identifiable legal risks and rights impacts with supporting authority."
        ),
        "remediation_text": (
            "Identify the correlated legal risk for each benefit claim and explain the doctrinal control that addresses it."
        ),
        "rationale": "Biolaw essays require rights-risk analysis, not technology description.",
    },
    {
        "id": "assessment-proposed-biolaw-policy-paper-drift-v1",
        "subject": "biolaw",
        "task_type": "essay",
        "criterion": "thesis",
        "polarity": "error_to_avoid",
        "grade_band": "50-59",
        "rule_text": (
            "Do not write a policy brief that never applies the governing legal framework to the set formative or summative question."
        ),
        "remediation_text": (
            "Rewrite around the legal question and use policy only to test doctrinal effectiveness."
        ),
        "rationale": "Biolaw formative risk: policy tone without legal application.",
    },
)


def _validate_rule_pack(records: tuple[dict[str, Any], ...], *, label: str) -> None:
    for record in records:
        text = str(record["rule_text"])
        if not is_owner_style_reusable_standard(text):
            issues = assessment_standard_privacy_issues(text)
            raise SystemExit(
                f"{label} rule failed privacy/generalisation gate: {record['id']} {issues}"
            )
        remediation = record.get("remediation_text")
        if remediation and not is_owner_style_reusable_standard(str(remediation)):
            raise SystemExit(f"{label} remediation failed gate: {record['id']}")


def _validate_canonical_rules() -> None:
    _validate_rule_pack(CANONICAL_RULES, label="canonical")
    _validate_rule_pack(PROPOSED_GENERAL_RULES, label="proposed-general")
    _validate_rule_pack(PROPOSED_SUBJECT_RULES, label="proposed-subject")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--propose-report",
        type=Path,
        default=PROJECT_ROOT / "docs/reports/proposed-assessment-standards-2026-08-13.md",
        help="Write the privacy-safe proposed standards pack (always safe; no DB writes).",
    )
    return parser


def _write_propose_report(path: Path, *, existing_ids: set[str]) -> dict[str, Any]:
    additive = [r for r in CANONICAL_RULES if r["id"] not in existing_ids]
    lines = [
        "# Proposed assessment standards — 13 August 2026",
        "",
        "Privacy-safe candidate DO / AVOID rules derived from marker patterns already in",
        "the LegalBot assessment catalogue (and cross-checked against Law-folder feedback",
        "themes). Raw marker sentences are **not** reproduced. Student names, emails,",
        "marker personal details, file paths and institutional person identifiers are excluded.",
        "",
        "Source policy: **70+ → positive_pattern (DO)**; **60–69 / 50–59 → error_to_avoid",
        "(AVOID)** after human review. This pack does **not** fine-tune weights, unlock",
        "Find Case Law, or fabricate expert gold.",
        "",
        "## Currently approved owner standards (live catalogue)",
        "",
        f"Approved canonical rows at report generation: **{len(existing_ids)}**.",
        "",
    ]
    for record in CANONICAL_RULES:
        if record["id"] not in existing_ids:
            continue
        polarity = "DO" if record["polarity"] == "positive_pattern" else "AVOID"
        lines.extend(
            [
                f"### {record['id']}",
                "",
                f"- Band: `{record['grade_band']}` · Polarity: **{polarity}** · "
                f"Criterion: `{record['criterion']}` · "
                f"Task: `{record['task_type'] or 'any'}` · Subject: `general/NULL`",
                f"- Rule: {record['rule_text']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Additive general rules ready for owner finalize (`--apply`)",
            "",
            "These match already-established owner-style patterns, pass the privacy /",
            "generalisation gate, and are included in `CANONICAL_RULES`. They insert only",
            "when the owner runs `python scripts/finalize_assessment_standards.py --apply`.",
            "",
        ]
    )
    if not additive:
        lines.append(
            "_No additive rules pending; catalogue already contains the full canonical set._"
        )
        lines.append("")
    for record in additive:
        polarity = "DO" if record["polarity"] == "positive_pattern" else "AVOID"
        lines.extend(
            [
                f"### {record['id']}",
                "",
                f"- Band: `{record['grade_band']}` · Polarity: **{polarity}** · "
                f"Criterion: `{record['criterion']}` · "
                f"Task: `{record.get('task_type') or 'any'}` · Subject: `{record.get('subject') or 'NULL (cross-subject)'}`",
                f"- Rule: {record['rule_text']}",
                f"- Rationale: fills a recurring marker gap not covered by the prior "
                f"{len(existing_ids)}-rule set; text is owner-generalised (not raw PDF prose).",
                "",
            ]
        )
    lines.extend(
        [
            "## Proposed general rules (approval required — not auto-inserted)",
            "",
            "Cross-subject candidates in `PROPOSED_GENERAL_RULES`. Not applied by `--apply`.",
            "",
        ]
    )
    if not PROPOSED_GENERAL_RULES:
        lines.append("_No proposed general rules pending._")
        lines.append("")
    for record in PROPOSED_GENERAL_RULES:
        polarity = "DO" if record["polarity"] == "positive_pattern" else "AVOID"
        lines.extend(
            [
                f"### {record['id']}",
                "",
                f"- Band: `{record['grade_band']}` · Polarity: **{polarity}** · "
                f"Criterion: `{record['criterion']}` · "
                f"Task: `{record.get('task_type') or 'any'}` · Subject: `NULL (cross-subject)`",
                f"- Rule: {record['rule_text']}",
                f"- Rationale: {record.get('rationale', 'Law-folder theme; owner approval required.')}",
                "",
            ]
        )
    lines.extend(
        [
            "## Subject-scoped proposals (approval required — not auto-inserted)",
            "",
            "Fail closed: subject labels and Law-folder evidence need owner confirmation",
            "before these enter `rubric_rules` as approved. See also",
            "`docs/reports/proposed-assessment-standards-from-law-folder-2026-08-13.md`.",
            "",
        ]
    )
    for record in PROPOSED_SUBJECT_RULES:
        polarity = "DO" if record["polarity"] == "positive_pattern" else "AVOID"
        lines.extend(
            [
                f"### {record['id']}",
                "",
                f"- Band: `{record['grade_band']}` · Polarity: **{polarity}** · "
                f"Criterion: `{record['criterion']}` · "
                f"Task: `{record['task_type'] or 'any'}` · Subject: `{record['subject']}`",
                f"- Rule: {record['rule_text']}",
                f"- Rationale: {record['rationale']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Owner next actions",
            "",
            "1. Review this pack for accuracy and privacy.",
            "2. Dry-run: `python scripts/finalize_assessment_standards.py` (JSON summary).",
            "3. Apply additive general rules: "
            "`python scripts/finalize_assessment_standards.py --apply`.",
            "4. To approve more Law-folder feedback: ingest/review assessment_guidance "
            "sources, then add further owner-generalised entries to `CANONICAL_RULES` "
            "(or promote selected `PROPOSED_SUBJECT_RULES`) — never mass-approve raw PDF text.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "propose_report": str(path.relative_to(PROJECT_ROOT)),
        "additive_general_count": len(additive),
        "proposed_general_count": len(PROPOSED_GENERAL_RULES),
        "subject_proposed_count": len(PROPOSED_SUBJECT_RULES),
        "canonical_total": len(CANONICAL_RULES),
        "law_folder_propose_report": "docs/reports/proposed-assessment-standards-from-law-folder-2026-08-13.md",
    }


def main() -> None:
    args = _parser().parse_args()
    _validate_canonical_rules()
    settings = Settings()
    database = Database(settings.database_path)
    database.initialize()
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ):
            raise SystemExit(
                "source scan is active; assessment cleanup requires a frozen catalogue"
            )
        existing_canonical = {
            str(row["id"])
            for row in database.fetchall(
                "SELECT id FROM rubric_rules WHERE id LIKE 'assessment-canonical-%' AND review_status='approved'"
            )
        }
        propose_meta = _write_propose_report(args.propose_report, existing_ids=existing_canonical)
        extracted = database.fetchall(
            """
            SELECT id,review_status FROM rubric_rules
            WHERE id NOT LIKE 'assessment-canonical-%' AND review_status IN ('approved','staged')
            ORDER BY id
            """
        )
        all_extracted = database.fetchall(
            """
            SELECT id FROM rubric_rules WHERE id NOT LIKE 'assessment-canonical-%'
            ORDER BY id
            """
        )
        all_assessment_sources = database.fetchall(
            """
            SELECT sv.id,sv.review_status FROM source_versions sv
            JOIN documents d ON d.id=sv.document_id
            WHERE sv.superseded_by IS NULL AND d.lane='assessment_guidance'
            ORDER BY sv.id
            """
        )
        assessment_sources = database.fetchall(
            """
            SELECT sv.id FROM source_versions sv JOIN documents d ON d.id=sv.document_id
            WHERE sv.superseded_by IS NULL AND d.lane='assessment_guidance'
              AND sv.review_status IN ('approved','staged')
            ORDER BY sv.id
            """
        )
        sources: dict[str, Any] = {}
        for record in CANONICAL_RULES:
            row = database.fetchone(
                "SELECT source_version_id FROM rubric_rules WHERE id=?",
                (record["source_rule_id"],),
            )
            if row is not None:
                sources[str(record["id"])] = row["source_version_id"]
        report = {
            "schema": "legalbot.assessment-standard-cleanup.v1",
            "policy": POLICY,
            "apply": args.apply,
            "raw_active_rules_rejected_or_ready": len(extracted),
            "raw_extracted_rule_total": len(all_extracted),
            "raw_extracted_rule_id_manifest_sha256": hashlib.sha256(
                "\n".join(str(row["id"]) for row in all_extracted).encode()
            ).hexdigest(),
            "canonical_rules_added_or_present": len(CANONICAL_RULES),
            "canonical_rule_ids": [str(record["id"]) for record in CANONICAL_RULES],
            "assessment_sources_rejected_or_ready": len(assessment_sources),
            "assessment_source_total": len(all_assessment_sources),
            **propose_meta,
        }
        if not args.apply:
            print(json.dumps(report, indent=2, sort_keys=True))
            return

        missing_provenance = [rid for rid in report["canonical_rule_ids"] if rid not in sources]
        if missing_provenance:
            raise RuntimeError(f"canonical rule provenance is missing: {missing_provenance}")

        cipher = LocalCipher.from_local_key(create=False)
        note = cipher.encrypt_text(
            f"{POLICY}: raw marker prose rejected; only reusable owner-authorised standard retained"
        )
        now = utc_iso()
        with database.transaction() as connection:
            for record in CANONICAL_RULES:
                source_version_id = sources[str(record["id"])]
                connection.execute(
                    """
                    INSERT INTO rubric_rules(
                      id,task_type,subject,criterion,polarity,grade_band,rule_text,
                      remediation_text,source_version_id,review_status,created_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,'approved',?)
                    ON CONFLICT(id) DO UPDATE SET
                      task_type=excluded.task_type,
                      subject=excluded.subject,
                      criterion=excluded.criterion, polarity=excluded.polarity,
                      grade_band=excluded.grade_band, rule_text=excluded.rule_text,
                      remediation_text=excluded.remediation_text,
                      source_version_id=excluded.source_version_id,
                      review_status='approved'
                    """,
                    (
                        record["id"],
                        record.get("task_type"),
                        record.get("subject"),
                        record["criterion"],
                        record["polarity"],
                        record["grade_band"],
                        record["rule_text"],
                        record["remediation_text"],
                        source_version_id,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO reviews(
                      id,review_type,target_id,status,reason,decision_note,
                      encrypted_decision_note,created_at,decided_at
                    ) VALUES (?, 'assessment_rule', ?, 'approved', ?, '[encrypted]', ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET status='approved',
                      reason=excluded.reason, decision_note='[encrypted]',
                      encrypted_decision_note=excluded.encrypted_decision_note,
                      decided_at=excluded.decided_at
                    """,
                    (
                        f"review-{record['id']}",
                        record["id"],
                        "Reusable assessment standard derived from marker evidence",
                        note,
                        now,
                        now,
                    ),
                )
            connection.execute(
                """
                UPDATE rubric_rules SET review_status='rejected'
                WHERE id NOT LIKE 'assessment-canonical-%'
                  AND review_status IN ('approved','staged')
                """
            )
            connection.execute(
                """
                UPDATE reviews SET status='rejected', decision_note='[encrypted]',
                  encrypted_decision_note=?, decided_at=?
                WHERE review_type='assessment_rule'
                  AND target_id NOT LIKE 'assessment-canonical-%'
                  AND status IN ('approved','pending')
                """,
                (note, now),
            )
            connection.execute(
                """
                UPDATE source_versions SET review_status='rejected'
                WHERE superseded_by IS NULL AND id IN (
                  SELECT sv.id FROM source_versions sv JOIN documents d ON d.id=sv.document_id
                  WHERE d.lane='assessment_guidance'
                )
                """
            )
            connection.execute(
                """
                UPDATE reviews SET status='rejected', decision_note='[encrypted]',
                  encrypted_decision_note=?, decided_at=?
                WHERE review_type='source_version' AND target_id IN (
                  SELECT sv.id FROM source_versions sv JOIN documents d ON d.id=sv.document_id
                  WHERE sv.superseded_by IS NULL AND d.lane='assessment_guidance'
                ) AND status IN ('approved','pending')
                """,
                (note, now),
            )
        policy_rejected = 0
        for row in database.fetchall(
            """
            SELECT encrypted_decision_note FROM reviews
            WHERE review_type='assessment_rule'
              AND target_id NOT LIKE 'assessment-canonical-%'
              AND status='rejected' AND encrypted_decision_note IS NOT NULL
            """
        ):
            try:
                if cipher.decrypt_text(row["encrypted_decision_note"]).startswith(POLICY):
                    policy_rejected += 1
            except Exception:
                continue
        report["raw_rules_rejected_by_policy"] = policy_rejected
        report["assessment_sources_rejected"] = sum(
            1
            for row in database.fetchall(
                """
                SELECT sv.review_status FROM source_versions sv
                JOIN documents d ON d.id=sv.document_id
                WHERE sv.superseded_by IS NULL AND d.lane='assessment_guidance'
                """
            )
            if row["review_status"] == "rejected"
        )
        report["approved_canonical_after_apply"] = len(
            database.fetchall(
                "SELECT id FROM rubric_rules WHERE id LIKE 'assessment-canonical-%' AND review_status='approved'"
            )
        )
        destination = settings.data_dir / "review_queue" / "assessment-standards-finalized.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {**report, "report": str(destination.relative_to(PROJECT_ROOT))},
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
