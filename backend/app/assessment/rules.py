from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from ..ingestion.models import Annotation, StructuralBlock
from ..privacy import scrub_pii

ASSESSMENT_RULE_SCHEMA = "legalbot.assessment-rules.v2"


class GradeBand(StrEnum):
    SEVENTY_PLUS = "70+"
    SIXTY = "60-69"
    FIFTY = "50-59"
    UNKNOWN = "unknown"


class RulePolarity(StrEnum):
    POSITIVE = "positive_pattern"
    AVOID = "error_to_avoid"


@dataclass(frozen=True, slots=True)
class AssessmentRule:
    id: str
    task_type: str | None
    subject: str | None
    criterion: str
    polarity: RulePolarity
    grade_band: GradeBand
    rule_text: str
    remediation_text: str | None
    source_comment_id: str
    review_status: str = "staged"


GRADE_PATTERNS = (
    re.compile(r"(?i)\b(?:mark|grade|score)\s*[:=-]?\s*(\d{2})(?:\s*%)?\b"),
    re.compile(r"(?i)\b(\d{2})\s*%(?!\w)"),
    re.compile(r"(?i)\b(5\d|6\d|7\d|8\d|9\d)\s*(?:[-–]\s*\d{2}|\+)\b"),
)

CRITERIA: dict[str, tuple[str, ...]] = {
    "authority_accuracy": ("authority", "case", "statute", "law", "citation"),
    "analysis": ("analysis", "analyse", "reasoning", "explain why"),
    "application": ("apply", "application", "facts", "scenario"),
    "thesis": ("thesis", "argument", "position"),
    "scholarship": ("scholar", "journal", "academic", "literature"),
    "counterargument": ("counter", "alternative", "however", "critique"),
    "structure": ("structure", "organisation", "paragraph", "signpost"),
    "conclusion": ("conclusion", "conclude", "outcome"),
    "remedies": ("remedy", "remedies", "damages", "procedure"),
}

_POSITIVE_SIGNALS = re.compile(
    r"(?i)\b(?:accurate|clear|coherent|compelling|critical|effective|excellent|good|"
    r"insightful|persuasive|precise|relevant|sophisticated|sound|strong|thorough|"
    r"very well|well[- ](?:argued|structured|supported|written))\b"
)
_NEGATIVE_SIGNALS = re.compile(
    r"(?i)\b(?:confus(?:ed|ing)|could have|does not|error|fails? to|inaccurate|"
    r"incomplete|insufficient|lack(?:s|ing)?|limited|missing|needs?|not enough|"
    r"should|too (?:brief|descriptive|general|limited|much|vague)|unclear|"
    r"underdeveloped|unsupported|weak|wrong)\b|\bmore (?:analysis|authority|detail|"
    r"discussion|evaluation|precision|support)\b"
)
_FEEDBACK_START = re.compile(
    r"(?i)\b(?:final\s+grade|grademark\s+report|grading\s+form|"
    r"feedback\s*(?:&|and)\s*feedforward|formative(?:\s+\d+)?\s*:\s*feedback|"
    r"formative\s+feedback|examiner\s+comments?|marker\s+feedback)\b"
)
_SECTION_SPLIT = re.compile(
    r"(?=\b(?:Q(?:uestion)?\s*\d+|Part\s+[a-z])\s*[:.)-]?\s*(?:[5-9]\d(?:\s*%)?)?)",
    re.IGNORECASE,
)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z])")


def _evaluation_polarity(text: str) -> RulePolarity | None:
    positive = bool(_POSITIVE_SIGNALS.search(text))
    negative = bool(_NEGATIVE_SIGNALS.search(text))
    if positive == negative:
        return None
    return RulePolarity.POSITIVE if positive else RulePolarity.AVOID


def _polarity_matches_band(polarity: RulePolarity, band: GradeBand) -> bool:
    return (band is GradeBand.SEVENTY_PLUS and polarity is RulePolarity.POSITIVE) or (
        band in {GradeBand.SIXTY, GradeBand.FIFTY} and polarity is RulePolarity.AVOID
    )


class FeedbackBodyExtractor:
    """Extract evaluator prose after an explicit feedback boundary.

    Turnitin-style PDFs can contain the complete student answer before the
    GradeMark report.  This extractor never exposes that prefix and only emits
    sentences that contain an unambiguous evaluative signal.
    """

    @staticmethod
    def _feedback_blocks(
        blocks: tuple[StructuralBlock, ...],
    ) -> tuple[StructuralBlock, ...]:
        start = next(
            (index for index, block in enumerate(blocks) if _FEEDBACK_START.search(block.text)),
            None,
        )
        if start is None:
            return ()
        return blocks[start:]

    def grade_text(self, blocks: tuple[StructuralBlock, ...]) -> str | None:
        feedback_blocks = self._feedback_blocks(blocks)
        if not feedback_blocks:
            return None
        return "\n".join(block.text for block in feedback_blocks)

    def extract(self, blocks: tuple[StructuralBlock, ...]) -> tuple[Annotation, ...]:
        feedback_blocks = self._feedback_blocks(blocks)
        if not feedback_blocks:
            return ()

        annotations: list[Annotation] = []
        for block in feedback_blocks:
            cleaned = " ".join(scrub_pii(block.text).split())
            for section in _SECTION_SPLIT.split(cleaned):
                section_band = explicit_grade_band(section)
                for sentence in _SENTENCE_SPLIT.split(section):
                    text = sentence.strip(" -\t\r\n")
                    if len(text) < 12 or _evaluation_polarity(text) is None:
                        continue
                    digest = hashlib.sha256(f"{block.ordinal}\0{text}".encode()).hexdigest()
                    annotations.append(
                        Annotation(
                            annotation_id=f"feedback-body-{digest[:32]}",
                            text=text,
                            page=block.page,
                            metadata={
                                "feedback_body": True,
                                **(
                                    {"grade_band": section_band.value}
                                    if section_band is not GradeBand.UNKNOWN
                                    else {}
                                ),
                            },
                        )
                    )
        return tuple(annotations)


def explicit_grade_band(text: str) -> GradeBand:
    for pattern in GRADE_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        mark = int(match.group(1))
        if mark >= 70:
            return GradeBand.SEVENTY_PLUS
        if mark >= 60:
            return GradeBand.SIXTY
        if mark >= 50:
            return GradeBand.FIFTY
    lowered = text.casefold().replace("-", " ")
    if "first class" in lowered or "distinction" in lowered:
        return GradeBand.SEVENTY_PLUS
    if "upper second" in lowered or "2:1" in lowered:
        return GradeBand.SIXTY
    if "lower second" in lowered or "2:2" in lowered:
        return GradeBand.FIFTY
    return GradeBand.UNKNOWN


def explicit_grade_bands(text: str) -> frozenset[GradeBand]:
    bands: set[GradeBand] = set()
    for pattern in GRADE_PATTERNS:
        for match in pattern.finditer(text):
            mark = int(match.group(1))
            if mark >= 70:
                bands.add(GradeBand.SEVENTY_PLUS)
            elif mark >= 60:
                bands.add(GradeBand.SIXTY)
            elif mark >= 50:
                bands.add(GradeBand.FIFTY)
    lowered = text.casefold().replace("-", " ")
    if "first class" in lowered or "distinction" in lowered:
        bands.add(GradeBand.SEVENTY_PLUS)
    if "upper second" in lowered or "2:1" in lowered:
        bands.add(GradeBand.SIXTY)
    if "lower second" in lowered or "2:2" in lowered:
        bands.add(GradeBand.FIFTY)
    return frozenset(bands)


def numeric_grade_bands(text: str) -> frozenset[GradeBand]:
    bands: set[GradeBand] = set()
    for pattern in GRADE_PATTERNS:
        for match in pattern.finditer(text):
            mark = int(match.group(1))
            if mark >= 70:
                bands.add(GradeBand.SEVENTY_PLUS)
            elif mark >= 60:
                bands.add(GradeBand.SIXTY)
            elif mark >= 50:
                bands.add(GradeBand.FIFTY)
    return frozenset(bands)


def criterion_for(text: str) -> str:
    lowered = text.casefold()
    scored = [
        (sum(marker in lowered for marker in markers), criterion)
        for criterion, markers in CRITERIA.items()
    ]
    score, criterion = max(scored, default=(0, "general_quality"))
    return criterion if score else "general_quality"


def task_for(text: str) -> str | None:
    lowered = text.casefold()
    if any(marker in lowered for marker in ("problem question", "scenario", "apply to the facts")):
        return "problem"
    if any(marker in lowered for marker in ("essay", "thesis", "critical argument")):
        return "essay"
    return None


class FeedbackRuleExtractor:
    """Accepts marker comments only; it has no API for student-answer body text."""

    def extract(
        self,
        comments: tuple[Annotation, ...],
        *,
        subject: str | None,
        document_grade_text: str | None = None,
    ) -> tuple[AssessmentRule, ...]:
        document_bands = numeric_grade_bands(document_grade_text or "")
        document_band = (
            next(iter(document_bands)) if len(document_bands) == 1 else GradeBand.UNKNOWN
        )
        rules: list[AssessmentRule] = []
        for comment in comments:
            text = " ".join(comment.text.split())
            if len(text) < 12:
                continue
            band = explicit_grade_band(text)
            metadata_band = comment.metadata.get("grade_band")
            if band == GradeBand.UNKNOWN and isinstance(metadata_band, str):
                try:
                    band = GradeBand(metadata_band)
                except ValueError:
                    band = GradeBand.UNKNOWN
            if band == GradeBand.UNKNOWN:
                band = document_band
            if band == GradeBand.UNKNOWN:
                continue
            polarity = _evaluation_polarity(text)
            if polarity is None or not _polarity_matches_band(polarity, band):
                continue
            rule_id = hashlib.sha256(
                "\0".join(
                    (
                        comment.annotation_id,
                        subject or "general",
                        criterion_for(text),
                        band.value,
                        text,
                    )
                ).encode("utf-8")
            ).hexdigest()
            rules.append(
                AssessmentRule(
                    id=f"assessment-rule-{rule_id[:40]}",
                    task_type=task_for(text),
                    subject=subject,
                    criterion=criterion_for(text),
                    polarity=polarity,
                    grade_band=band,
                    rule_text=text,
                    remediation_text=(
                        None
                        if polarity is RulePolarity.POSITIVE
                        else "Revise the affected section to correct this marker-identified weakness; preserve verified legal propositions."
                    ),
                    source_comment_id=comment.annotation_id,
                )
            )
        return tuple(rules)


class RubricRuleExtractor:
    """Extract staged rules only from a file explicitly classified as a rubric."""

    def extract(
        self, blocks: tuple[StructuralBlock, ...], *, subject: str | None
    ) -> tuple[AssessmentRule, ...]:
        rules: list[AssessmentRule] = []
        for block in blocks:
            text = " ".join(block.text.split())
            band = explicit_grade_band(text)
            if len(text) < 12 or band == GradeBand.UNKNOWN:
                continue
            positive = band == GradeBand.SEVENTY_PLUS
            source_id = f"rubric-block-{block.ordinal}"
            rule_id = hashlib.sha256(
                "\0".join(
                    (source_id, subject or "general", criterion_for(text), band.value, text)
                ).encode("utf-8")
            ).hexdigest()
            rules.append(
                AssessmentRule(
                    id=f"assessment-rule-{rule_id[:40]}",
                    task_type=task_for(text),
                    subject=subject,
                    criterion=criterion_for(text),
                    polarity=RulePolarity.POSITIVE if positive else RulePolarity.AVOID,
                    grade_band=band,
                    rule_text=text,
                    remediation_text=(
                        None
                        if positive
                        else "Revise the affected section to meet this explicit marking criterion; preserve verified legal propositions."
                    ),
                    source_comment_id=source_id,
                )
            )
        return tuple(rules)


_STUDENT_DIRECTED_RE = re.compile(
    r"(?i)\b(?:you wrote|your essay|your answer|your work|this student|the student|"
    r"dear student|well done|congratulations)\b"
)
_ADMINISTRATIVE_FEEDBACK_RE = re.compile(
    r"(?i)\b(?:email me|don'?t hesitate|grademark|turnitin|2nd marker|second marker|"
    r"feed\s*forward|grading form|please contact)\b"
)
_QUESTION_LOCAL_RE = re.compile(
    r"(?i)\b(?:Q(?:uestion)?\s*\d+|Part\s+[a-z]\))\b.*\b(?:\d{2}\s*%|mark\s*\d{2}|you )|"
    r"\b(?:in essay Q\d|on page \d+)\b"
)
_URL_OR_FILENAME_RE = re.compile(r"(?i)\bhttps?://|\bwww\.|\.(?:pdf|docx?|html?)\b")
_OWNER_STYLE_RE = re.compile(
    r"(?i)\b(?:do not|avoid|apply|state|use|sustain|engage|integrate|explain|support|"
    r"distinguish|address|identify|test|make|create|express|add|revise|expand|merge|"
    r"cut|rewrite|compare|slow|map|rank)\b"
)


def assessment_standard_privacy_issues(
    text: str, owner_identifiers: Sequence[str] = ()
) -> tuple[str, ...]:
    """Return opaque issue codes for candidate standard text; never echo substrings."""

    issues: list[str] = []
    cleaned = scrub_pii(text, owner_identifiers)
    if cleaned != text:
        issues.append("pii_or_local_path")
    if _STUDENT_DIRECTED_RE.search(text):
        issues.append("student_directed")
    if _ADMINISTRATIVE_FEEDBACK_RE.search(text):
        issues.append("administrative_feedback")
    if _QUESTION_LOCAL_RE.search(text):
        issues.append("question_local")
    if _URL_OR_FILENAME_RE.search(text):
        issues.append("url_or_filename")
    if re.search(r"(?i)\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", text) and re.search(
        r"(?i)\b(?:student|marker|author|candidate)\b", text
    ):
        issues.append("person_reference")
    return tuple(issues)


def is_owner_style_reusable_standard(text: str, owner_identifiers: Sequence[str] = ()) -> bool:
    """True only for generalised, privacy-safe owner-authorised standard prose."""

    # Fail closed on the raw candidate before any scrubbing can hide identifiers.
    if assessment_standard_privacy_issues(text, owner_identifiers):
        return False
    normalised = " ".join(scrub_pii(text, owner_identifiers).split())
    if len(normalised) < 40 or len(normalised) > 320:
        return False
    if not _OWNER_STYLE_RE.search(normalised):
        return False
    # Reject TOC / heading fragments and bare book labels.
    return not re.match(r"^(?:\(?\d+\)|[A-Z]\.|[ivx]+\)|\([a-z]\))\s+", normalised)


def generalise_assessment_standard_text(
    text: str, owner_identifiers: Sequence[str] = ()
) -> str | None:
    """Return scrubbed text only when it already reads as a reusable standard."""

    if not is_owner_style_reusable_standard(text, owner_identifiers):
        return None
    return " ".join(scrub_pii(text, owner_identifiers).split())


GENERAL_SEVENTY_RULES: dict[str, tuple[str, ...]] = {
    "essay": (
        "State a qualified thesis that directly answers the question and sustain it throughout.",
        "Use accurate primary authority and critically engage with relevant scholarship.",
        "Test the thesis against counterarguments, policy implications and doctrinal uncertainty.",
        "Synthesize the analysis into a reasoned conclusion rather than repeating earlier points.",
    ),
    "problem": (
        "Map the parties and issues before applying each primary rule to the material facts.",
        "Explain competing applications, evidential uncertainty and ranked likely outcomes.",
        "Address available remedies, procedure and any fact needed before firmer advice is possible.",
    ),
    "general": (
        "Answer the question directly, identify assumptions and support material law with authority.",
        "Explain important limits and uncertainty, then give proportionate practical next steps.",
    ),
}


def general_seventy_rules(task_type: str) -> tuple[str, ...]:
    """Return the reviewed policy baseline inherited by subjects without bespoke feedback."""

    return GENERAL_SEVENTY_RULES.get(task_type, GENERAL_SEVENTY_RULES["general"])
