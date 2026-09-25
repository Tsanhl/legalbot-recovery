"""Immutable, privacy-safe assessment guidance for answer drafting.

The bundle in this module is owner-authored policy.  It is deliberately not
represented as extracted marker feedback and it is never legal authority.  A
separate loader admits reviewed feedback-derived records only when they are
approved and their provenance passes the deterministic checks below.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

from .rules import assessment_standard_privacy_issues

BUNDLE_SCHEMA = "legalbot.assessment-guidance-bundle.v1"
BUNDLE_VERSION = "owner-law-folder-2026-09-25.1"
# Version the sealed owner-decision manifest (the five marker rules) was applied to.
DECISION_MANIFEST_BUNDLE_VERSION = "owner-standards-2026-08-14.1"
OWNER_DECISION_MANIFEST_SHA256 = "be5916d6e3e40febb3819d1529df6f6ab4055de98baf275f8361b0fc31dda9a2"
OWNER_VERIFICATION_SIGNAL = "owner_authored_policy_v1"
OWNER_APPROVED_MARKER_SIGNAL = "owner_approved_marker_mapping_v1"
MARKER_POSITIVE_SIGNAL = "marker_positive_exact_v1"
MARKER_REPAIR_SIGNAL = "marker_repair_exact_v1"

ALLOWED_GRADE_BANDS = frozenset({"70+", "60-69", "50-59"})
ALLOWED_TASK_TYPES = frozenset({"any", "essay", "problem", "general"})
ALLOWED_VERIFICATION_SIGNALS = frozenset(
    {
        OWNER_VERIFICATION_SIGNAL,
        OWNER_APPROVED_MARKER_SIGNAL,
        MARKER_POSITIVE_SIGNAL,
        MARKER_REPAIR_SIGNAL,
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SCORE_FRAGMENT_RE = re.compile(
    r"(?i)(?:\bq(?:uestion)?\s*\d+\s*[:.)-]?\s*\d{2}\b|"
    r"\b(?:mark|grade|score)\s*[:=-]?\s*\d{2}\b|\b\d{2}\s*%\b|"
    r"\b(?:excellent|v(?:ery)?\s+good|good)\s+\d+\b)"
)
_STUDENT_FACT_RE = re.compile(
    r"(?i)(?:\b[A-Z][’']s\s+(?:refusal|claim|argument|answer|conduct)\b|"
    r"\bpart\s+[a-z]\)|\bthe\s+(?:student|candidate|author)\b|\byou\b|\byour\b)"
)
_VAGUE_OR_HEADING_RE = re.compile(
    r"(?i)^\s*(?:analysis|application|argument|authority|conclusion|discussion|"
    r"essay|excellent|feedback|good|introduction|organisation|remedies|structure|"
    r"very good|v good)(?:\s+\d+)?\s*[.:;!-]*\s*$"
)
_SUBSTANTIVE_LAW_RE = re.compile(
    r"""(?ix)(?:
        \[[12]\d{3}\]\s+(?:UKSC|UKHL|EWCA|EWHC|UKPC)\s+\d+ |
        \b[A-Z][A-Za-z&' -]+\s+Act\s+(?:18|19|20)\d{2}\b |
        \bsection\s+\d+[A-Za-z]?(?:\([^)]*\))?\s+(?:provides|requires|means)\b |
        \b(?:claimant|defendant|prosecution)\s+must\s+prove\b
    )"""
)
_POSITIVE_FEEDBACK_RE = re.compile(
    r"(?i)\b(?:accurate|clear|coherent|compelling|critical|effective|excellent|"
    r"good|insightful|persuasive|precise|relevant|sophisticated|strong|thorough|"
    r"very well|well[- ](?:argued|structured|supported|written))\b"
)
_NEGATIVE_FEEDBACK_RE = re.compile(
    r"(?i)\b(?:could have|does not|fails? to|inaccurate|incomplete|insufficient|"
    r"lack(?:s|ing)?|limited|missing|needs?|not enough|should|too (?:brief|"
    r"descriptive|general|limited|vague)|unclear|underdeveloped|unsupported|weak|"
    r"wrong)\b|\bmore (?:analysis|authority|detail|discussion|evaluation|precision|"
    r"support)\b"
)

_CRITERION_MARKERS: dict[str, tuple[str, ...]] = {
    "analysis": ("analysis", "reason", "infer", "explain", "relationship", "compare"),
    "application": ("apply", "application", "fact", "scenario"),
    "authority_accuracy": ("authority", "case", "statute", "law", "citation", "reference"),
    "citation_accuracy": ("citation", "reference", "pinpoint", "footnote"),
    "counterargument": ("counter", "contrary", "alternative"),
    "issue_spotting": ("issue", "element", "defence", "offence", "claim"),
    "organisation": ("organisation", "structure", "section", "heading", "roadmap"),
    "precision": ("precise", "clarity", "clear", "concise", "sentence"),
    "remedies": ("remedy", "remedies", "damages", "relief"),
    "scholarship": ("scholar", "journal", "academic", "literature"),
    "thesis": ("thesis", "argument", "question", "title", "proposition"),
}

_SUBJECT_MARKERS: dict[str, tuple[str, ...]] = {
    "contract": ("contract", "implied term", "remedies for breach"),
    "criminal": ("offence", "mens rea", "intention", "defence"),
    "tort": ("negligence", "duty of care", "remoteness"),
    "trusts": ("trust", "fiduciary", "equitable"),
}


def _normalise(text: str) -> str:
    return " ".join(text.split())


def source_span_sha256(text: str) -> str:
    """Hash a normalised provenance span without retaining its raw prose."""

    return hashlib.sha256(_normalise(text).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AssessmentGuidanceRule:
    rule_id: str
    source_span_hash: str
    grade_band: str
    criterion: str
    task_type: str
    subject: str | None
    positive_target: str
    anti_pattern: str | None
    repair_action: str
    verification_signal: str

    def canonical_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AssessmentGuidanceBundle:
    schema: str
    version: str
    decision_manifest_sha256: str
    rules: tuple[AssessmentGuidanceRule, ...]

    @property
    def sha256(self) -> str:
        return bundle_sha256(self)


@dataclass(frozen=True, slots=True)
class BudgetedAssessmentGuidance:
    bundle_sha256: str
    selected_rules: tuple[AssessmentGuidanceRule, ...]
    instructions: tuple[str, ...]
    omitted_rule_ids: tuple[str, ...]
    character_count: int


def _owner_source_material(
    *,
    rule_id: str,
    grade_band: str,
    criterion: str,
    task_type: str,
    positive_target: str,
    anti_pattern: str | None,
    repair_action: str,
) -> str:
    """Canonical owner-policy source record bound by ``source_span_hash``."""

    return "\n".join(
        (
            rule_id,
            grade_band,
            criterion,
            task_type,
            positive_target,
            anti_pattern or "",
            repair_action,
        )
    )


def _owner_rule(
    rule_id: str,
    *,
    grade_band: str,
    criterion: str,
    task_type: str,
    subject: str | None = None,
    positive_target: str,
    anti_pattern: str | None,
    repair_action: str,
) -> AssessmentGuidanceRule:
    material = _owner_source_material(
        rule_id=rule_id,
        grade_band=grade_band,
        criterion=criterion,
        task_type=task_type,
        positive_target=positive_target,
        anti_pattern=anti_pattern,
        repair_action=repair_action,
    )
    return AssessmentGuidanceRule(
        rule_id=rule_id,
        source_span_hash=source_span_sha256(material),
        grade_band=grade_band,
        criterion=criterion,
        task_type=task_type,
        subject=subject,
        positive_target=positive_target,
        anti_pattern=anti_pattern,
        repair_action=repair_action,
        verification_signal=OWNER_VERIFICATION_SIGNAL,
    )


def _owner_approved_marker_rule(
    rule_id: str,
    *,
    source_span_hash: str,
    grade_band: str,
    criterion: str,
    task_type: str,
    positive_target: str,
    anti_pattern: str,
    repair_action: str,
) -> AssessmentGuidanceRule:
    """Build a rule whose exact marker mapping was approved in the sealed manifest.

    The raw marker comment is deliberately absent.  The bundle is instead bound
    to the privacy-safe owner-decision manifest, which records the source span
    hash and the activated structured rule.
    """

    return AssessmentGuidanceRule(
        rule_id=rule_id,
        source_span_hash=source_span_hash,
        grade_band=grade_band,
        criterion=criterion,
        task_type=task_type,
        subject=None,
        positive_target=positive_target,
        anti_pattern=anti_pattern,
        repair_action=repair_action,
        verification_signal=OWNER_APPROVED_MARKER_SIGNAL,
    )


# Approved by the owner on 2026-09-25 from docs/system-design/LAW_FOLDER_ANSWER_GUIDE.md;
# each rule id names its guide section (u/e/p/g) or anti-pattern (a).
OWNER_AUTHORED_RULES: tuple[AssessmentGuidanceRule, ...] = (
    _owner_rule(
        'law-u1-answer-exact-question-v1',
        grade_band='70+', criterion='thesis', task_type='any',
        positive_target='Answer the exact question set from the first line to the last; every section advances an answer to the precise statement, party or outcome asked about.',
        anti_pattern=None,
        repair_action='Reconnect each affected section conclusion to the precise question without changing verified propositions.',
    ),
    _owner_rule(
        'law-u2-clear-defended-position-v1',
        grade_band='70+', criterion='analysis', task_type='any',
        positive_target='Take a clear position on each issue and defend it with reasons; decide the point wherever the evidence allows.',
        anti_pattern=None,
        repair_action='Replace undecided or hedged wording with a reasoned conclusion on the affected issue.',
    ),
    _owner_rule(
        'law-u3-counterargument-then-position-v1',
        grade_band='70+', criterion='counterargument', task_type='any',
        positive_target='Present the strongest counterargument, dissent or alternative interpretation, then explain why the chosen position is better.',
        anti_pattern=None,
        repair_action='Add the strongest opposing view on the affected issue and resolve it.',
    ),
    _owner_rule(
        'law-u4-authority-at-point-v1',
        grade_band='70+', criterion='authority_accuracy', task_type='any',
        positive_target='Support each material legal proposition where it is made with the precise provision or the controlling highest-court authority in the evidence pack, and each evaluative or empirical claim with a supporting source.',
        anti_pattern=None,
        repair_action='Bind qualifying evidence beside the affected claim or narrow the claim to its support.',
    ),
    _owner_rule(
        'law-u7-exact-authority-v1',
        grade_band='70+', criterion='authority_accuracy', task_type='any',
        positive_target='Represent authority exactly: distinguish ratio from obiter and majority from dissent, and keep the precise formulation of any test.',
        anti_pattern=None,
        repair_action='Correct the description of the affected authority to match the evidence exactly.',
    ),
    _owner_rule(
        'law-u8-secondary-sources-v1',
        grade_band='70+', criterion='scholarship', task_type='any',
        positive_target='Use academic and official secondary sources from the evidence pack to carry evaluation; group like-minded authors and contrast opposing scholarly views.',
        anti_pattern=None,
        repair_action='Add the relevant scholarly view from the evidence pack to the affected evaluative point.',
    ),
    _owner_rule(
        'law-u9-depth-where-it-counts-v1',
        grade_band='70+', criterion='organisation', task_type='any',
        positive_target='Give settled or preliminary points one or two sentences and spend the word budget on disputed or complex issues; develop fewer points fully rather than many briefly.',
        anti_pattern=None,
        repair_action='Compress the settled point and reallocate words to the most complex live issue.',
    ),
    _owner_rule(
        'law-u12-use-word-budget-v1',
        grade_band='70+', criterion='organisation', task_type='any',
        positive_target='Use the requested word range fully with substantive analysis and no padding.',
        anti_pattern=None,
        repair_action='Expand the thinnest material analysis or cut repetition until the answer sits within the requested range.',
    ),
    _owner_rule(
        'law-u13-precise-terms-no-contradiction-v1',
        grade_band='70+', criterion='precision', task_type='any',
        positive_target='Use legal terms in their legal meaning, keep supplied facts exact and keep every conclusion consistent with the others.',
        anti_pattern=None,
        repair_action='Correct the imprecise term or reconcile the contradictory conclusions.',
    ),
    _owner_rule(
        'law-u14-explain-support-v1',
        grade_band='70+', criterion='analysis', task_type='any',
        positive_target='Explain how each authority supports the point it is cited for; citations never replace argument.',
        anti_pattern=None,
        repair_action='Add the missing explanatory step linking the evidence to the conclusion.',
    ),
    _owner_rule(
        'law-u15-clear-academic-prose-v1',
        grade_band='70+', criterion='precision', task_type='any',
        positive_target='Write clear, concise academic prose in short sentences and short paragraphs, without contractions, colloquialisms or bullet-point argument.',
        anti_pattern=None,
        repair_action='Rewrite the affected passage as concise continuous prose.',
    ),
    _owner_rule(
        'law-a-descriptive-not-analytical-v1',
        grade_band='60-69', criterion='thesis', task_type='any',
        positive_target='Analyse the statement or question throughout rather than reviewing the topic.',
        anti_pattern='Describing the law or topic without analysing the statement or question set until the final section.',
        repair_action='Restructure the affected section around the question and state what it shows about the answer.',
    ),
    _owner_rule(
        'law-a-fence-sitting-v1',
        grade_band='60-69', criterion='analysis', task_type='any',
        positive_target='Reach a reasoned conclusion on each live issue.',
        anti_pattern='Leaving live issues undecided or asserting outcomes with words such as clearly or likely instead of reasoning.',
        repair_action='Replace the assertion with the reasoning and a definite conclusion.',
    ),
    _owner_rule(
        'law-a-missing-controlling-authority-v1',
        grade_band='50-59', criterion='authority_accuracy', task_type='any',
        positive_target='Engage the controlling authority that goes to the heart of the issue, at the highest available court level.',
        anti_pattern='Omitting the controlling authority, citing a lower court where an appellate decision exists, or naming a statute without its operative provision.',
        repair_action='Replace or add the controlling authority and its operative provision from the evidence pack.',
    ),
    _owner_rule(
        'law-a-case-law-only-v1',
        grade_band='50-59', criterion='scholarship', task_type='any',
        positive_target='Support evaluative claims with scholarly and official secondary sources as well as primary law.',
        anti_pattern='Relying on primary sources alone for evaluative, empirical or reform claims.',
        repair_action='Add the relevant secondary source to each affected evaluative claim.',
    ),
    _owner_rule(
        'law-e1-thesis-led-introduction-v1',
        grade_band='70+', criterion='thesis', task_type='essay',
        positive_target='Open with a focused introduction that defines key terms, states the thesis the essay defends and names the two or three issues used to defend it.',
        anti_pattern=None,
        repair_action='Rewrite the introduction so it states the thesis and the issues that support it.',
    ),
    _owner_rule(
        'law-e3-synthesis-not-summary-v1',
        grade_band='70+', criterion='analysis', task_type='essay',
        positive_target="Synthesise rather than summarise: compare authorities and scholarship, test a doctrine's claimed purposes against its operation, and draw analogies, flaws and own examples.",
        anti_pattern=None,
        repair_action='Replace the affected summary with comparison and evaluation that advances the thesis.',
    ),
    _owner_rule(
        'law-e4-context-and-reform-v1',
        grade_band='70+', criterion='analysis', task_type='essay',
        positive_target='Engage the economic, social and political context and defend a persuasive view on effectiveness and reform, including its trade-offs.',
        anti_pattern=None,
        repair_action='Add the missing context or reform evaluation with its trade-offs.',
    ),
    _owner_rule(
        'law-e6-conclusion-answers-question-v1',
        grade_band='70+', criterion='thesis', task_type='essay',
        positive_target='Explain any chosen focus and end with a conclusion that answers the question and follows from the analysis.',
        anti_pattern=None,
        repair_action='Rewrite the conclusion so it answers the question from the analysis made.',
    ),
    _owner_rule(
        'law-p1-structure-by-party-v1',
        grade_band='70+', criterion='organisation', task_type='problem',
        positive_target='Structure the answer by party or claim following the question, open each section with a one-line finding and omit generic introductions and conclusions.',
        anti_pattern=None,
        repair_action='Reorganise the affected material under the relevant party or claim heading.',
    ),
    _owner_rule(
        'law-p2-spot-every-issue-v1',
        grade_band='70+', criterion='issue_spotting', task_type='problem',
        positive_target='Treat each right, act, document and interest in the facts as a potential issue and address every live issue separately.',
        anti_pattern=None,
        repair_action='Add the omitted live issue as its own analysis.',
    ),
    _owner_rule(
        'law-p3-full-test-applied-v1',
        grade_band='70+', criterion='application', task_type='problem',
        positive_target='State every element of each legal test, including exceptions, and apply each element to specific facts before concluding.',
        anti_pattern=None,
        repair_action='Add the missing element or exception and apply it to the facts.',
    ),
    _owner_rule(
        'law-p5-state-assumptions-v1',
        grade_band='70+', criterion='application', task_type='problem',
        positive_target='Identify missing or ambiguous facts, state a reasonable assumption for each and apply it consistently.',
        anti_pattern=None,
        repair_action='State the assumption for the missing fact and align every dependent conclusion with it.',
    ),
    _owner_rule(
        'law-p6-strongest-route-first-v1',
        grade_band='70+', criterion='remedies', task_type='problem',
        positive_target='Lead with the strongest legal route, then consider every materially available alternative route, defence and remedy.',
        anti_pattern=None,
        repair_action='Reorder routes by strength and add the omitted material alternative or remedy.',
    ),
    _owner_rule(
        'law-p8-case-parallels-v1',
        grade_band='70+', criterion='application', task_type='problem',
        positive_target='Draw parallels with or distinguish the facts of decided cases, and resolve issues by elimination where the facts allow.',
        anti_pattern=None,
        repair_action='Compare the facts of the relevant authority with the scenario for the affected issue.',
    ),
    _owner_rule(
        'law-a-partial-test-restated-facts-v1',
        grade_band='50-59', criterion='application', task_type='problem',
        positive_target='Apply every element of the full test to the specific facts.',
        anti_pattern='Applying a partial test, overlooking exceptions, or restating the facts instead of applying the law to them.',
        repair_action='Add the omitted element and apply it to the facts.',
    ),
    _owner_rule(
        'law-g1-direct-practical-answer-v1',
        grade_band='70+', criterion='thesis', task_type='general',
        positive_target='Give the direct answer first, then the decisive conditions and deadlines, practical next steps and the missing facts that would change the outcome.',
        anti_pattern=None,
        repair_action='Move the direct answer first and add the missing condition, step or outcome-changing fact.',
    ),
)

OWNER_DECISION_RULES: tuple[AssessmentGuidanceRule, ...] = (
    _owner_approved_marker_rule(
        "assessment-canonical-case-synthesis-v1",
        source_span_hash=("869dca10c23de859655330298e2e678160aa91f30b5ae9c66f80cf10241ca586"),
        grade_band="50-59",
        criterion="authority_accuracy",
        task_type="essay",
        positive_target=(
            "Compare the material cases, identify agreement or tension between them, "
            "and explain how their relationship supports the thesis."
        ),
        anti_pattern=(
            "Do not discuss key authorities as isolated summaries; explain the relationship "
            "between the cases and make that synthesis central to the essay argument."
        ),
        repair_action=(
            "Compare the material cases, identify agreement or tension between them, "
            "and explain how their relationship supports the thesis."
        ),
    ),
    _owner_rule(
        "owner-amended-criminal-element-defence-v2",
        grade_band="50-59",
        criterion="issue_spotting",
        task_type="problem",
        subject="criminal",
        positive_target=(
            "For each materially arguable offence, checklist its elements and factually "
            "raised defences; address every live item and expressly exclude only material "
            "alternatives. Do not add remote offences or defences merely to complete a "
            "generic list."
        ),
        anti_pattern=(
            "Do not omit an element of an offence materially raised by the facts, or a "
            "defence reasonably arising on the facts. Conclude on each live item or "
            "explain why it is not satisfied."
        ),
        repair_action=(
            "Build an offence-by-offence checklist, add a supported conclusion for each "
            "factually live element and defence, remove remote generic items, and repair "
            "only the affected section."
        ),
    ),
    _owner_rule(
        "owner-amended-question-engagement-v2",
        grade_band="50-59",
        criterion="thesis",
        task_type="any",
        positive_target=(
            "State the controlling thesis or issue-by-issue answer, then connect each "
            "section's conclusion to the precise question, party and outcome requested."
        ),
        anti_pattern=(
            "Do not write a legally relevant but question-neutral discussion; make every "
            "section advance an answer to the precise problem or proposition set."
        ),
        repair_action=(
            "Rewrite the controlling thesis or issue-by-issue answer and reconnect each "
            "affected section conclusion to the precise question, party and requested "
            "outcome without changing verified legal propositions."
        ),
    ),
    _owner_approved_marker_rule(
        "assessment-canonical-timely-authority-support-v1",
        source_span_hash=("66b9db83516fa629e5d7cf425a16e077d4ef44d644635d8c01d48f3a6fa4799b"),
        grade_band="60-69",
        criterion="authority_accuracy",
        task_type="any",
        positive_target=(
            "Add the relevant primary or approved secondary authority beside the material "
            "proposition and explain its relevance."
        ),
        anti_pattern=(
            "Support each material proposition with appropriate authority at the point where "
            "it is made; do not postpone essential references until a later section."
        ),
        repair_action=(
            "Add the relevant primary or approved secondary authority beside the material "
            "proposition and explain its relevance."
        ),
    ),
)

OWNER_ASSESSMENT_BUNDLE = AssessmentGuidanceBundle(
    schema=BUNDLE_SCHEMA,
    version=BUNDLE_VERSION,
    decision_manifest_sha256=OWNER_DECISION_MANIFEST_SHA256,
    rules=(*OWNER_AUTHORED_RULES, *OWNER_DECISION_RULES),
)


def bundle_sha256(bundle: AssessmentGuidanceBundle) -> str:
    payload = {
        "schema": bundle.schema,
        "version": bundle.version,
        "decision_manifest_sha256": bundle.decision_manifest_sha256,
        "rules": [rule.canonical_record() for rule in bundle.rules],
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def canonical_bundle_bytes(bundle: AssessmentGuidanceBundle) -> bytes:
    """Return the exact sealable deployment representation of a bundle."""

    payload = {
        "schema": bundle.schema,
        "version": bundle.version,
        "decision_manifest_sha256": bundle.decision_manifest_sha256,
        "bundle_sha256": bundle.sha256,
        "rules": [rule.canonical_record() for rule in bundle.rules],
    }
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _text_validation_issues(text: str) -> set[str]:
    issues = set(assessment_standard_privacy_issues(text))
    normalised = _normalise(text)
    if _SCORE_FRAGMENT_RE.search(normalised):
        issues.add("score_fragment")
    if _STUDENT_FACT_RE.search(normalised):
        issues.add("student_specific_fact")
    if len(normalised) < 24 or _VAGUE_OR_HEADING_RE.fullmatch(normalised):
        issues.add("vague_or_heading")
    if _SUBSTANTIVE_LAW_RE.search(normalised):
        issues.add("substantive_law")
    return issues


def _detected_subjects(text: str) -> set[str]:
    lowered = text.casefold()
    return {
        subject
        for subject, markers in _SUBJECT_MARKERS.items()
        if any(marker in lowered for marker in markers)
    }


def validate_guidance_rule(
    rule: AssessmentGuidanceRule,
    *,
    source_span_text: str | None = None,
    review_status: str = "approved",
    owner_decision_manifest_sha256: str | None = None,
) -> tuple[str, ...]:
    """Return deterministic rejection codes without echoing sensitive prose."""

    issues: set[str] = set()
    if review_status != "approved":
        issues.add("review_not_approved")
    if not rule.rule_id or not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,127}", rule.rule_id):
        issues.add("invalid_rule_id")
    if not _SHA256_RE.fullmatch(rule.source_span_hash):
        issues.add("invalid_source_span_hash")
    if rule.grade_band not in ALLOWED_GRADE_BANDS:
        issues.add("invalid_grade_band")
    if rule.task_type not in ALLOWED_TASK_TYPES:
        issues.add("invalid_task_type")
    if rule.verification_signal not in ALLOWED_VERIFICATION_SIGNALS:
        issues.add("invalid_verification_signal")
    if rule.grade_band == "70+" and rule.anti_pattern:
        issues.add("positive_rule_has_anti_pattern")
    if rule.grade_band != "70+" and not rule.anti_pattern:
        issues.add("repair_rule_missing_anti_pattern")
    if not rule.repair_action:
        issues.add("missing_repair_action")
    for value in (rule.positive_target, rule.anti_pattern or "", rule.repair_action):
        if value:
            issues.update(_text_validation_issues(value))

    if rule.verification_signal == OWNER_VERIFICATION_SIGNAL:
        expected = source_span_sha256(
            _owner_source_material(
                rule_id=rule.rule_id,
                grade_band=rule.grade_band,
                criterion=rule.criterion,
                task_type=rule.task_type,
                positive_target=rule.positive_target,
                anti_pattern=rule.anti_pattern,
                repair_action=rule.repair_action,
            )
        )
        if expected != rule.source_span_hash:
            issues.add("mismatched_provenance")
        return tuple(sorted(issues))

    if rule.verification_signal == OWNER_APPROVED_MARKER_SIGNAL:
        if owner_decision_manifest_sha256 != OWNER_DECISION_MANIFEST_SHA256:
            issues.add("missing_or_stale_owner_decision_manifest")
        return tuple(sorted(issues))

    if source_span_text is None:
        issues.add("missing_source_span")
        return tuple(sorted(issues))
    if source_span_sha256(source_span_text) != rule.source_span_hash:
        issues.add("source_span_hash_mismatch")
    source_issues = _text_validation_issues(source_span_text)
    issues.update(f"source_{item}" for item in source_issues)
    positive = bool(_POSITIVE_FEEDBACK_RE.search(source_span_text))
    negative = bool(_NEGATIVE_FEEDBACK_RE.search(source_span_text))
    if positive and negative:
        issues.add("mixed_unsplit_feedback")
    if rule.verification_signal == MARKER_POSITIVE_SIGNAL and (not positive or negative):
        issues.add("mismatched_polarity")
    if rule.verification_signal == MARKER_REPAIR_SIGNAL and (not negative or positive):
        issues.add("mismatched_polarity")
    criterion_markers = _CRITERION_MARKERS.get(rule.criterion, ())
    if criterion_markers and not any(
        marker in source_span_text.casefold() for marker in criterion_markers
    ):
        issues.add("mismatched_provenance")
    source_subjects = _detected_subjects(source_span_text)
    if rule.subject and source_subjects and rule.subject.casefold() not in source_subjects:
        issues.add("mismatched_subject_provenance")
    return tuple(sorted(issues))


def validate_bundle(bundle: AssessmentGuidanceBundle) -> tuple[str, ...]:
    issues: list[str] = []
    if bundle.schema != BUNDLE_SCHEMA:
        issues.append("invalid_bundle_schema")
    if not bundle.version:
        issues.append("missing_bundle_version")
    if bundle.decision_manifest_sha256 != OWNER_DECISION_MANIFEST_SHA256:
        issues.append("missing_or_stale_owner_decision_manifest")
    ids = [rule.rule_id for rule in bundle.rules]
    if len(ids) != len(set(ids)):
        issues.append("duplicate_rule_id")
    for rule in bundle.rules:
        issues.extend(
            f"{rule.rule_id}:{code}"
            for code in validate_guidance_rule(
                rule,
                owner_decision_manifest_sha256=bundle.decision_manifest_sha256,
            )
        )
    return tuple(issues)


def instruction_for_rule(rule: AssessmentGuidanceRule) -> str:
    scope = f"{rule.task_type}/{rule.subject or 'all-subjects'}"
    if rule.grade_band == "70+":
        return (
            f"70+ target [{scope}; {rule.criterion}; {rule.rule_id}]: "
            f"{rule.positive_target} Repair: {rule.repair_action}"
        )
    return (
        f"{rule.grade_band} anti-pattern [{scope}; {rule.criterion}; {rule.rule_id}]: "
        f"{rule.anti_pattern} Target: {rule.positive_target} Repair: {rule.repair_action}"
    )


def compact_instruction_for_rule(rule: AssessmentGuidanceRule) -> str:
    """Short drafting form for small local models; scoring keeps the full form."""
    if rule.grade_band == "70+":
        return f"Target: {rule.positive_target}"
    return f"Avoid: {rule.anti_pattern}"


def _eligible_rules(
    rules: Sequence[AssessmentGuidanceRule], *, task_type: str, subject: str | None
) -> list[AssessmentGuidanceRule]:
    normalized_subject = _normalise(subject or "").casefold()
    eligible = [
        rule
        for rule in rules
        if rule.task_type in {"any", task_type}
        and (
            rule.subject is None
            or _normalise(rule.subject).casefold() in {"", "general", normalized_subject}
        )
    ]
    return sorted(
        eligible,
        key=lambda rule: (
            0 if rule.subject and _normalise(rule.subject).casefold() == normalized_subject else 1,
            0 if rule.task_type == task_type else 1,
            rule.rule_id,
        ),
    )


def applicable_guidance_rules(
    bundle: AssessmentGuidanceBundle,
    *,
    task_type: str,
    subject: str | None,
) -> tuple[AssessmentGuidanceRule, ...]:
    """Return every sealed rule applicable to an answer, without prompt budgeting.

    Drafting may use an atomic, context-budgeted subset. Scoring and canary
    review use this complete applicable set so an omitted prompt rule cannot
    silently disappear from evaluation.
    """

    return tuple(_eligible_rules(bundle.rules, task_type=task_type, subject=subject))


def budget_assessment_guidance(
    bundle: AssessmentGuidanceBundle,
    *,
    task_type: str,
    subject: str | None,
    max_characters: int,
    compact: bool = False,
) -> BudgetedAssessmentGuidance:
    """Select complete rules only; an over-budget rule is omitted, never cut."""

    if max_characters < 0:
        raise ValueError("max_characters must be non-negative")
    render = compact_instruction_for_rule if compact else instruction_for_rule
    eligible = _eligible_rules(bundle.rules, task_type=task_type, subject=subject)
    positives = [rule for rule in eligible if rule.grade_band == "70+"]
    repairs = [rule for rule in eligible if rule.grade_band != "70+"]
    interleaved: list[AssessmentGuidanceRule] = []
    for index in range(max(len(positives), len(repairs))):
        if index < len(positives):
            interleaved.append(positives[index])
        if index < len(repairs):
            interleaved.append(repairs[index])

    # Reserve one complete target and one complete repair when a balanced pair
    # fits. A long first target must not crowd all corrective guidance out.
    pairs = [(a, b) for a in positives for b in repairs
             if len(render(a)) + len(render(b)) <= max_characters]
    if pairs:
        a, b = pairs[0]
        interleaved = [a, b, *(r for r in interleaved if r not in (a, b))]
    selected: list[AssessmentGuidanceRule] = []
    instructions: list[str] = []
    omitted: list[str] = []
    used = 0
    for rule in interleaved:
        instruction = render(rule)
        if used + len(instruction) > max_characters:
            omitted.append(rule.rule_id)
            continue
        selected.append(rule)
        instructions.append(instruction)
        used += len(instruction)
    return BudgetedAssessmentGuidance(
        bundle_sha256=bundle.sha256,
        selected_rules=tuple(selected),
        instructions=tuple(instructions),
        omitted_rule_ids=tuple(omitted),
        character_count=used,
    )


def verified_rules_from_reviewed_records(
    records: Iterable[Mapping[str, Any]],
) -> tuple[AssessmentGuidanceRule, ...]:
    """Load approved records only; staged/rejected records cannot reach prompts."""

    accepted: list[AssessmentGuidanceRule] = []
    for record in records:
        if str(record.get("review_status") or "") != "approved":
            continue
        rule = AssessmentGuidanceRule(
            rule_id=str(record["rule_id"]),
            source_span_hash=str(record["source_span_hash"]),
            grade_band=str(record["grade_band"]),
            criterion=str(record["criterion"]),
            task_type=str(record.get("task_type") or "any"),
            subject=(str(record["subject"]) if record.get("subject") else None),
            positive_target=str(record["positive_target"]),
            anti_pattern=(str(record["anti_pattern"]) if record.get("anti_pattern") else None),
            repair_action=str(record["repair_action"]),
            verification_signal=str(record["verification_signal"]),
        )
        issues = validate_guidance_rule(
            rule,
            source_span_text=(
                str(record["source_span_text"]) if record.get("source_span_text") else None
            ),
            review_status="approved",
        )
        if issues:
            raise ValueError(
                f"approved assessment guidance failed validation: {rule.rule_id} {issues}"
            )
        accepted.append(rule)
    return tuple(accepted)


assert not validate_bundle(OWNER_ASSESSMENT_BUNDLE)
