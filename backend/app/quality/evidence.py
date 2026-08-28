"""Conservative, dependency-free checks between claims and frozen evidence spans."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from itertools import pairwise
from typing import TYPE_CHECKING

from ..currentness import (
    case_present_law_currentness_qualifies,
    is_case_source,
    is_legislation_source,
    normalise_currentness_status,
)
from ..types import EvidenceSpan, MaterialLane

if TYPE_CHECKING:
    from ..db import Database

CITABLE_AUTHORITY_LANES = frozenset(
    {
        MaterialLane.PRIMARY_AUTHORITY.value,
        MaterialLane.OFFICIAL_SECONDARY.value,
        MaterialLane.SCHOLARSHIP.value,
    }
)


def is_citable_authority_lane(span: EvidenceSpan) -> bool:
    """True only for lanes that may support material legal claims and OSCOLA."""

    return str(span.lane) in CITABLE_AUTHORITY_LANES


TOKEN_RE = re.compile(r"[a-z][a-z'-]*|\d+(?:\.\d+)*")
QUOTE_RE = re.compile(
    r'"(?P<double>[^"\n]{2,})"|“(?P<curly_double>[^”\n]{2,})”|'
    r"‘(?P<curly_single>[^’\n]{2,})’|(?<![A-Za-z0-9])'(?P<single>[^'\n]{4,})'"
    r"(?![A-Za-z0-9])"
)

_MONTHS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}
_MONTH_PATTERN = "|".join(_MONTHS)
_DATE_PATTERNS = (
    re.compile(r"\b(?P<year>(?:19|20)\d{2})-(?P<month>0?[1-9]|1[0-2])-(?P<day>0?[1-9]|[12]\d|3[01])\b"),
    re.compile(r"\b(?P<day>0?[1-9]|[12]\d|3[01])/(?P<month>0?[1-9]|1[0-2])/(?P<year>(?:19|20)\d{2})\b"),
    re.compile(
        rf"\b(?P<day>0?[1-9]|[12]\d|3[01])\s+(?P<month_name>{_MONTH_PATTERN})\s+(?P<year>(?:19|20)\d{{2}})\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?P<month_name>{_MONTH_PATTERN})\s+(?P<day>0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?(?:,)?\s+(?P<year>(?:19|20)\d{{2}})\b",
        re.IGNORECASE,
    ),
)
_NUMBER = r"(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?"
_AMOUNT_PREFIX_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<currency>GBP|USD|EUR|£|\$|€)\s*(?P<number>{_NUMBER})\s*(?P<scale>thousand|million|billion|k|m|bn)?\b",
    re.IGNORECASE,
)
_AMOUNT_SUFFIX_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<number>{_NUMBER})\s*(?P<scale>thousand|million|billion|k|m|bn)?\s*(?P<currency>pounds?|sterling|dollars?|euros?)\b",
    re.IGNORECASE,
)
_PERCENT_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<number>{_NUMBER})\s*(?:%|per\s+cent\b|percent\b)",
    re.IGNORECASE,
)
_DURATION_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?P<number>{_NUMBER})(?:\s+|-)"
    rf"(?:(?P<modifier>working|business|calendar)(?:\s+|-))?"
    rf"(?P<unit>seconds?|minutes?|hours?|days?|weeks?|months?|years?)\b",
    re.IGNORECASE,
)
_PROVISION_LABEL = (
    r"subsections?|sections?|ss|s|regulations?|regs?|articles?|arts?|"
    r"paragraphs?|paras?|schedules?|schs?|rules?"
)
_PROVISION_ATOM = (
    r"(?:\d+[A-Za-z]?(?:\.\d+)*(?:\([0-9A-Za-z]+\))*|"
    r"\([0-9A-Za-z]+\)(?:\([0-9A-Za-z]+\))*)"
)
_PROVISION_RANGE = (
    rf"{_PROVISION_ATOM}(?:\s*(?:-|–|—|to)\s*{_PROVISION_ATOM})?"
)
_PROVISION_SERIES_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    rf"(?P<label>{_PROVISION_LABEL})"
    r"\.?\s*"
    rf"(?P<series>{_PROVISION_RANGE}(?:\s*(?:,\s*(?:(?:and|or)\s+)?|(?:and|or|&)\s+){_PROVISION_RANGE})*)",
    re.IGNORECASE,
)
_PROVISION_ITEM_RE = re.compile(_PROVISION_RANGE, re.IGNORECASE)
_CLAUSE_PREDICATE_RE = re.compile(
    r"\b(?:is|are|was|were|has|have|had|must|may|can|cannot|shall|will|should|would|could|"
    r"does|do|did|applies?|requires?|permits?|prohibits?|provides?|holds?|limits?|imposes?|"
    r"creates?|allows?|excludes?|includes?|entitles?|prevents?|governs?|means?|states?)\b",
    re.IGNORECASE,
)
_EXPLICIT_SUBJECT_RE = re.compile(
    r"^\s*(?:the|a|an|it|they|he|she|this|that|claimants?|defendants?|part(?:y|ies)|court|"
    r"tribunal|section|subsection|regulation|article|paragraph|rule|schedule|act|contract|clause|"
    r"authority|provision)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class MaterialFact:
    """One typed fact whose value must occur in frozen supporting evidence."""

    kind: str
    normalized_value: str
    matched_text: str

    @property
    def identity(self) -> tuple[str, str]:
        return self.kind, self.normalized_value


def _decimal_text(raw: str, scale: str | None = None) -> str | None:
    try:
        value = Decimal(raw.replace(",", ""))
    except InvalidOperation:
        return None
    multiplier = {
        "thousand": Decimal(1_000),
        "k": Decimal(1_000),
        "million": Decimal(1_000_000),
        "m": Decimal(1_000_000),
        "billion": Decimal(1_000_000_000),
        "bn": Decimal(1_000_000_000),
    }.get((scale or "").casefold(), Decimal(1))
    rendered = format(value * multiplier, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _currency_code(raw: str) -> str:
    return {
        "£": "GBP",
        "gbp": "GBP",
        "pound": "GBP",
        "pounds": "GBP",
        "sterling": "GBP",
        "$": "USD",
        "usd": "USD",
        "dollar": "USD",
        "dollars": "USD",
        "€": "EUR",
        "eur": "EUR",
        "euro": "EUR",
        "euros": "EUR",
    }[raw.casefold()]


def _date_value(match: re.Match[str]) -> str | None:
    month_name = match.groupdict().get("month_name")
    month = _MONTHS[month_name.casefold()] if month_name else int(match.group("month"))
    try:
        return date(int(match.group("year")), month, int(match.group("day"))).isoformat()
    except ValueError:
        return None


def extract_material_facts(text: str) -> tuple[MaterialFact, ...]:
    """Extract normalized dates, amounts, percentages, durations and provisions."""

    found: list[tuple[int, MaterialFact]] = []
    for pattern in _DATE_PATTERNS:
        for match in pattern.finditer(text):
            normalized = _date_value(match)
            if normalized is not None:
                found.append((match.start(), MaterialFact("date", normalized, match.group(0))))
    for pattern in (_AMOUNT_PREFIX_RE, _AMOUNT_SUFFIX_RE):
        for match in pattern.finditer(text):
            number = _decimal_text(match.group("number"), match.groupdict().get("scale"))
            if number is not None:
                value = f"{_currency_code(match.group('currency'))}:{number}"
                found.append((match.start(), MaterialFact("amount", value, match.group(0))))
    for match in _PERCENT_RE.finditer(text):
        number = _decimal_text(match.group("number"))
        if number is not None:
            found.append((match.start(), MaterialFact("percentage", number, match.group(0))))
    for match in _DURATION_RE.finditer(text):
        number = _decimal_text(match.group("number"))
        if number is None:
            continue
        unit = match.group("unit").casefold().removesuffix("s")
        modifier = (match.group("modifier") or "ordinary").casefold()
        found.append(
            (match.start(), MaterialFact("duration", f"{number}:{modifier}:{unit}", match.group(0)))
        )
    labels = {
        "s": "section",
        "ss": "section",
        "section": "section",
        "sections": "section",
        "subsection": "subsection",
        "subsections": "subsection",
        "reg": "regulation",
        "regs": "regulation",
        "regulation": "regulation",
        "regulations": "regulation",
        "art": "article",
        "arts": "article",
        "article": "article",
        "articles": "article",
        "para": "paragraph",
        "paras": "paragraph",
        "paragraph": "paragraph",
        "paragraphs": "paragraph",
        "sch": "schedule",
        "schs": "schedule",
        "schedule": "schedule",
        "schedules": "schedule",
        "rule": "rule",
        "rules": "rule",
    }
    for match in _PROVISION_SERIES_RE.finditer(text):
        label = labels[match.group("label").casefold()]
        series = match.group("series")
        for item in _PROVISION_ITEM_RE.finditer(series):
            identifier = item.group(0).casefold()
            identifier = re.sub(r"\s*(?:-|–|—|to)\s*", "-", identifier)
            identifier = re.sub(r"\s+", "", identifier)
            parenthetical = re.fullmatch(r"\(([0-9a-z]+)\)((?:\([0-9a-z]+\))*)", identifier)
            if parenthetical:
                identifier = parenthetical.group(1) + parenthetical.group(2)
            found.append(
                (
                    match.start("series") + item.start(),
                    MaterialFact(
                        "provision",
                        f"{label}:{identifier}",
                        f"{match.group('label')} {item.group(0)}",
                    ),
                )
            )

    output: list[MaterialFact] = []
    seen: set[tuple[str, str]] = set()
    for _position, fact in sorted(found, key=lambda item: (item[0], item[1].kind)):
        if fact.identity not in seen:
            seen.add(fact.identity)
            output.append(fact)
    return tuple(output)


def unsupported_material_facts(
    claim_text: str, spans: Sequence[EvidenceSpan]
) -> tuple[MaterialFact, ...]:
    """Return typed claim facts absent from every exact bound span and locator."""

    supported = {
        fact.identity
        for span in spans
        for fact in extract_material_facts(f"{span.text}\n{span.locator}")
    }
    return tuple(
        fact for fact in extract_material_facts(claim_text) if fact.identity not in supported
    )


def non_atomic_material_claim_reasons(text: str) -> tuple[str, ...]:
    """Identify obvious multi-proposition claims without treating lists of elements as clauses."""

    reasons: list[str] = []
    sentences = [
        item.strip()
        for item in re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])|[\r\n]+", text.strip())
        if item.strip()
    ]
    if len(sentences) > 1:
        reasons.append("multiple_sentences")
    if ";" in text:
        reasons.append("semicolon_joined_propositions")
    for match in re.finditer(
        r"\b(?:and|or|but|whereas|while|however)\b", text, re.IGNORECASE
    ):
        left = text[: match.start()]
        right = text[match.end() :]
        if (
            _CLAUSE_PREDICATE_RE.search(left)
            and _CLAUSE_PREDICATE_RE.search(right)
            and (
                _EXPLICIT_SUBJECT_RE.search(right)
                or _CLAUSE_PREDICATE_RE.match(right.lstrip())
            )
        ):
            reasons.append("coordinated_independent_clauses")
            break
    return tuple(dict.fromkeys(reasons))

# Removing generic prose terms prevents a draft from laundering an unrelated
# span merely by repeating words such as "analysis", "law" or "evidence".
STOP_WORDS = frozenset(
    {
        "a",
        "about",
        "after",
        "again",
        "against",
        "all",
        "also",
        "an",
        "analysis",
        "and",
        "answer",
        "any",
        "are",
        "as",
        "at",
        "authority",
        "be",
        "because",
        "been",
        "before",
        "being",
        "between",
        "both",
        "but",
        "by",
        "can",
        "case",
        "claim",
        "could",
        "did",
        "do",
        "does",
        "each",
        "either",
        "evidence",
        "for",
        "from",
        "further",
        "had",
        "has",
        "have",
        "having",
        "he",
        "her",
        "here",
        "hers",
        "him",
        "his",
        "how",
        "however",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "itself",
        "law",
        "legal",
        "may",
        "more",
        "most",
        "no",
        "nor",
        "not",
        "of",
        "on",
        "only",
        "or",
        "other",
        "our",
        "out",
        "over",
        "proposition",
        "same",
        "she",
        "should",
        "so",
        "source",
        "such",
        "than",
        "that",
        "the",
        "their",
        "theirs",
        "them",
        "then",
        "there",
        "therefore",
        "these",
        "they",
        "this",
        "those",
        "through",
        "to",
        "under",
        "very",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "whether",
        "which",
        "while",
        "who",
        "will",
        "with",
        "would",
        "you",
    }
)

CONCEPT_EQUIVALENTS = {
    "applicable": "apply",
    "application": "apply",
    "applied": "apply",
    "applies": "apply",
    "authorisation": "authorise",
    "authorised": "authorise",
    "breached": "breach",
    "breaches": "breach",
    "disclosed": "disclose",
    "disclosure": "disclose",
    "enforceability": "enforce",
    "enforceable": "enforce",
    "enforced": "enforce",
    "liability": "liable",
    "must": "require",
    "necessary": "require",
    "necessity": "require",
    "owed": "owe",
    "owing": "owe",
    "permission": "permit",
    "permitted": "permit",
    "prohibition": "prohibit",
    "prohibited": "prohibit",
    "requirement": "require",
    "requirements": "require",
    "required": "require",
    "requires": "require",
    "revocation": "revoke",
    "revoked": "revoke",
    "shall": "require",
}


def _canonical_token(token: str) -> str:
    equivalent = CONCEPT_EQUIVALENTS.get(token)
    if equivalent:
        return equivalent
    if token.isdigit() or re.fullmatch(r"\d+(?:\.\d+)+", token):
        return token
    if len(token) > 5 and token.endswith("ing"):
        return token[:-3]
    if len(token) > 4 and token.endswith("ed"):
        return token[:-2]
    if len(token) > 4 and token.endswith("es"):
        return token[:-2]
    if len(token) > 3 and token.endswith("s"):
        return token[:-1]
    return token


def substantive_tokens(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return tuple(
        _canonical_token(token)
        for token in TOKEN_RE.findall(normalized)
        if token not in STOP_WORDS and (len(token) >= 3 or token[0].isdigit())
    )


def _bigrams(tokens: Sequence[str]) -> set[tuple[str, str]]:
    return set(pairwise(tokens))


def is_substantively_related(claim_text: str, span: EvidenceSpan) -> bool:
    """Deterministic lexical screen only; this does not prove entailment."""

    claim = substantive_tokens(claim_text)
    source = substantive_tokens(f"{span.text}\n{span.locator}")
    if not claim or not source:
        return False
    if _bigrams(claim) & _bigrams(source):
        return True
    shared = set(claim) & set(source)
    if len(shared) >= 3:
        return True
    smaller = min(len(set(claim)), len(set(source)))
    if len(shared) >= 2 and len(shared) / max(1, smaller) >= 0.2:
        return True
    shared_numbers = {token for token in shared if token[0].isdigit()}
    shared_words = {token for token in shared if not token[0].isdigit()}
    return bool(shared_numbers and shared_words)


def quoted_passages(text: str) -> tuple[str, ...]:
    passages: list[str] = []
    for match in QUOTE_RE.finditer(text):
        value = next((group for group in match.groups() if group is not None), "").strip()
        if value:
            passages.append(value)
    return tuple(passages)


def _normalized_passage(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(re.findall(r"[a-z0-9]+", normalized))


def false_quotations(claim_text: str, spans: Sequence[EvidenceSpan]) -> tuple[str, ...]:
    """Return quoted passages that do not occur verbatim in any bound span."""

    sources = tuple(_normalized_passage(span.text) for span in spans)
    unsupported: list[str] = []
    for passage in quoted_passages(claim_text):
        normalized = _normalized_passage(passage)
        if normalized and not any(normalized in source for source in sources):
            unsupported.append(passage)
    return tuple(unsupported)


def all_bound_spans_support(claim_text: str, spans: Sequence[EvidenceSpan]) -> bool:
    return (
        bool(spans)
        and all(is_substantively_related(claim_text, span) for span in spans)
        and not unsupported_material_facts(claim_text, spans)
        and not non_atomic_material_claim_reasons(claim_text)
        and not false_quotations(claim_text, spans)
    )


def currentness_qualifies_for_answer(
    span: EvidenceSpan,
    *,
    proposition_hash: str | None = None,
    as_of_date: date | None = None,
    database: Database | None = None,
) -> bool:
    """Reject unqualified historical authorities as evidence of current law.

    A reviewed historical journal can still provide secondary analysis, but an
    original enactment is not a current consolidated provision.  Historical
    legislation therefore remains available for catalogue/history work while
    being excluded from answer evidence until a point-in-time source is added.
    """

    status = normalise_currentness_status(span.currentness_status)
    if is_case_source(span.citation_data):
        qualifies = case_present_law_currentness_qualifies(
            citation_data=span.citation_data,
            currentness_status=span.currentness_status,
            source_metadata={},
            identity_verified=span.identity_verified,
            source_version_id=span.source_version_id,
            chunk_id=span.chunk_id,
            legal_locator=span.locator,
            exact_span_sha256=span.content_sha256,
            proposition_hash=proposition_hash,
            legal_role=span.legal_role,
            as_of_date=as_of_date,
            reviews=span.case_currentness_reviews,
        )
    else:
        qualifies = not (
            is_legislation_source(span.citation_data)
            and status in {"historical", "historical_as_enacted", "as_enacted"}
        )
    if not qualifies:
        return False
    if database is not None:
        from ..research.material_updates import MaterialUpdateGate

        if (
            not MaterialUpdateGate(database)
            .assess(span, proposition_hash=proposition_hash)
            .qualified
        ):
            return False
    return True


def evidence_span_eligible_for_drafting(
    span: EvidenceSpan,
    *,
    as_of_date: date,
    database: Database | None = None,
) -> bool:
    """Check whether a span may enter the model's evidence prompt.

    Case-law prompts receive only spans with at least one exact, sealed review
    for the run date.  Final release is stricter: each generated material claim
    must echo the specific reviewed ``proposition_hash`` it relies upon.
    """

    if not span.identity_verified:
        return False
    if not is_case_source(span.citation_data):
        return span.currentness_verified and currentness_qualifies_for_answer(
            span, database=database
        )
    return any(
        currentness_qualifies_for_answer(
            span,
            proposition_hash=review.proposition_hash,
            as_of_date=as_of_date,
            database=database,
        )
        for review in span.case_currentness_reviews
    )
