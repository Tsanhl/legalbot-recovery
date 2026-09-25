"""Deterministic private-teaching issue spotting without authority leakage."""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..privacy import prompt_injection_hits, scrub_pii
from ..types import IssuePlan, IssueSpottingNote

MAX_NOTES = 8
MAX_NOTE_CHARS = 4_000
MAX_PROPOSITIONS = 6
MAX_QUERIES = 5
MAX_QUERY_CHARS = 1_200
# Up to this many issue queries come from knowledge-lane law-and-rules notes:
# their section heading plus the authorities they name (never the note prose),
# so the citable statutes and cases are retrieved from the authority index.
MAX_KNOWLEDGE_QUERIES = 2
MAX_QUERY_AUTHORITIES = 4
_CASE_NAME = re.compile(
    r"\b((?:R \(\w+\) v |Re |)[A-Z][\w.'&-]*(?: (?:and|of|the|&|[A-Z][\w.'&()-]*)){0,5}"
    r"(?: v [A-Z][\w.'&-]*(?: (?:and|of|the|&|[A-Z][\w.'&()-]*)){0,5})?)"
    r" [\[(](\d{4})[\])](?: \d+)? ?(UKSC|UKHL|UKPC|EWCA Civ|EWCA Crim|EWHC|AC|QB|KB|Ch|Fam|WLR|All ER|Crim LR|Cr App R|Lloyd's Rep)?"
)
_STATUTE = re.compile(
    r"\b((?:[A-Z][\w()'-]*|of|and|the|for|in) (?:[\w()'-]+ ){0,8}Act \d{4})"
    r"(?:,? (?:s|ss|art|Sch) ?[\w().–-]+)?"
)
_EU_CASE = re.compile(r"\b([A-Z][\w.'-]*(?: [A-Z(][\w.'()-]*){0,4}) \((C-\d+/\d+|\d+/\d+)")
_LEAD_WORDS = frozenset({
    "In", "The", "See", "Under", "A", "An", "Contrast", "Compare", "Following", "Applying",
    "Approved", "Also", "Cf", "And", "Both", "Held", "Per", "Unlike", "After", "Before",
})
_TREATY = re.compile(r"\bArt(?:icle)?s? \d+(?:\(\d+\))? (?:TFEU|TEU|ECHR)\b")

# Only fixed legal taxonomy labels may leave the private-note lane.  Names,
# quotations and free-form teaching prose can never become query expansions.
_LEGAL_CONCEPTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("offer_acceptance", "offer and acceptance", ("offer", "acceptance")),
    ("consideration", "consideration", ("consideration", "bargained-for exchange")),
    ("intention", "intention to create legal relations", ("legal relations", "intention")),
    ("contract_terms", "contract terms and incorporation", ("contract term", "incorporation")),
    ("misrepresentation", "misrepresentation", ("misrepresentation",)),
    ("duress", "duress", ("economic duress", "duress")),
    ("undue_influence", "undue influence", ("undue influence",)),
    ("frustration", "frustration", ("frustration",)),
    ("duty_of_care", "duty of care", ("duty of care", "neighbour principle")),
    ("breach", "breach of duty", ("breach of duty", "standard of care")),
    ("factual_causation", "factual causation", ("factual causation", "but for")),
    ("legal_causation", "legal causation", ("legal causation", "novus actus")),
    ("remoteness", "remoteness", ("remoteness", "reasonably foreseeable")),
    ("defences", "applicable defences", ("defence", "contributory negligence")),
    ("remedies", "remedies", ("remedy", "remedies", "damages", "injunction")),
    ("limitation", "limitation periods", ("limitation period", "time bar")),
    ("proprietary_estoppel", "proprietary estoppel", ("proprietary estoppel",)),
    ("resulting_trust", "resulting trust", ("resulting trust",)),
    ("constructive_trust", "constructive trust", ("constructive trust",)),
    ("quistclose_trust", "Quistclose trust", ("quistclose", "specified purpose")),
    ("certainty_intention", "certainty of intention", ("certainty of intention",)),
    ("certainty_subject", "certainty of subject matter", ("certainty of subject",)),
    ("certainty_objects", "certainty of objects", ("certainty of objects",)),
    (
        "constitution",
        "constitution of trusts and imperfect gifts",
        ("constitution", "imperfect gift"),
    ),
    ("tracing", "tracing and mixed funds", ("tracing", "mixed bank account")),
    ("fiduciary_duty", "fiduciary duty", ("fiduciary duty",)),
    ("actus_reus", "actus reus", ("actus reus",)),
    ("mens_rea", "mens rea", ("mens rea", "recklessness", "intention")),
    ("procedural_fairness", "procedural fairness", ("procedural fairness", "natural justice")),
    ("legitimate_expectation", "legitimate expectation", ("legitimate expectation",)),
    ("proportionality", "proportionality", ("proportionality",)),
    ("standing", "standing", ("standing", "sufficient interest")),
    ("judicial_review_ground", "grounds of judicial review", ("judicial review", "illegality")),
    ("jurisdiction", "jurisdiction", ("jurisdiction",)),
    ("choice_of_law", "choice of law", ("choice of law", "applicable law")),
    ("dominance", "abuse of dominance", ("dominance", "abuse of dominant")),
    ("anticompetitive_agreement", "anti-competitive agreement", ("anti-competitive", "cartel")),
    ("lawful_basis", "data-processing lawful basis", ("lawful basis", "data processing")),
    ("unfair_dismissal", "unfair dismissal", ("unfair dismissal",)),
    (
        "indirect_discrimination",
        "indirect discrimination and justification",
        ("indirect discrimination",),
    ),
    ("reasonable_adjustments", "reasonable adjustments", ("reasonable adjustment",)),
    ("victimisation", "victimisation", ("victimisation",)),
    (
        "directors_duties",
        "directors' duties and conflicts",
        ("director's duty", "directors' duties", "conflict of interest"),
    ),
    ("derivative_claim", "derivative claims", ("derivative claim",)),
    ("unfair_prejudice", "unfair prejudice", ("unfair prejudice",)),
    ("testamentary_capacity", "testamentary capacity", ("testamentary capacity",)),
    ("knowledge_approval", "knowledge and approval", ("knowledge and approval",)),
    (
        "consumer_quality",
        "consumer satisfactory quality and fitness",
        ("satisfactory quality", "fitness for purpose"),
    ),
    (
        "consumer_remedies",
        "consumer repair, replacement, rejection, refund timing and return costs",
        ("repair", "replacement", "right to reject"),
    ),
    (
        "consumer_refund",
        "consumer refund deadline, collection and return costs",
        ("refund timing", "refund deadline", "returning rejected goods"),
    ),
    (
        "consumer_rejection_period",
        "consumer short-term rejection period 30 days from delivery and exceptions",
        ("short-term right to reject", "rejection period"),
    ),
)

# Search hints only: the retrieved provision must still pass identity,
# point-in-time and claim-support review before it can be cited.
_ENGLAND_CONSUMER_SOURCE_HINTS = {
    "consumer_quality": ("section 9",),
    "consumer_remedies": ("section 19", "section 20", "section 22", "section 23"),
    "consumer_refund": ("section 20",),
    "consumer_rejection_period": ("section 22",),
}


def build_issue_plan(
    *,
    question: str,
    jurisdiction: str,
    subject: str | None,
    notes: Sequence[IssueSpottingNote],
    owner_identifiers: Sequence[str] = (),
    unsafe_notes_excluded: int = 0,
) -> IssuePlan:
    """Map screened teaching notes to fixed concepts and bounded legal queries."""

    selected_notes = tuple(notes[:MAX_NOTES])
    safe_texts: list[str] = []
    for note in selected_notes:
        text = scrub_pii(note.text[:MAX_NOTE_CHARS], owner_identifiers)
        if text.strip() and not prompt_injection_hits(text):
            safe_texts.append(_normalise(text))
    safe_full_question = scrub_pii(question, owner_identifiers).strip()
    # The user's own question is the primary issue signal. Teaching notes may
    # add fixed taxonomy labels, but the route must still work when no teaching
    # note is retrieved.
    combined = "\n".join([_normalise(safe_full_question), *safe_texts])
    propositions: list[tuple[str, str]] = []
    # People describe a failed product; they need not name its legal test.
    # This proposes research topics only, never decides that a consumer remedy
    # applies. Do not export private-note prose or infer the jurisdiction.
    retail_context = (subject or "").startswith("consumer") or (
        "personal use" in combined and any(word in combined for word in ("retailer", "shop", "trader", "bought"))
    )
    product_failure = any(_contains_phrase(combined, phrase) for phrase in (
        "fault", "faulty", "defect", "defective", "broken", "shut down",
        "stopped working", "does not work", "doesn't work", "not working",
    ))
    if retail_context and product_failure:
        propositions.extend((key, label) for key, label, _ in _LEGAL_CONCEPTS
                            if key in _ENGLAND_CONSUMER_SOURCE_HINTS)
    for key, label, patterns in _LEGAL_CONCEPTS:
        if key not in {item[0] for item in propositions} and any(_contains_phrase(combined, pattern) for pattern in patterns):
            propositions.append((key, label))
        if len(propositions) >= MAX_PROPOSITIONS:
            break

    safe_question = _bounded_query_excerpt(safe_full_question, MAX_QUERY_CHARS)
    queries = [safe_question] if safe_question else []
    knowledge_queries = _knowledge_queries(
        selected_notes, jurisdiction=jurisdiction, subject=subject,
        owner_identifiers=owner_identifiers,
    )
    taxonomy_limit = MAX_QUERIES - min(len(knowledge_queries), MAX_KNOWLEDGE_QUERIES)
    for key, label in propositions:
        # Repeating the entire question in every expansion lets its dominant
        # issue drown out the other issues in vector search. The original query
        # already carries case context; each extra query probes one fixed legal
        # concept while jurisdiction/date filters remain enforced downstream.
        safe_jurisdiction = scrub_pii(jurisdiction, owner_identifiers)
        expanded = f"{safe_jurisdiction} {subject or ''}. Legal issue: {label}.".strip()
        if (
            jurisdiction in {"England", "England and Wales", "Wales"}
            and retail_context
            and key in _ENGLAND_CONSUMER_SOURCE_HINTS
        ):
            locators = ", ".join(_ENGLAND_CONSUMER_SOURCE_HINTS[key])
            expanded += f" Verify Consumer Rights Act 2015 {locators}."
        if expanded and expanded not in queries:
            queries.append(expanded)
        if len(queries) >= taxonomy_limit:
            break
    for query in knowledge_queries:
        if len(queries) >= MAX_QUERIES:
            break
        if query not in queries:
            queries.append(query)
    if not queries:
        queries = [question[:MAX_QUERY_CHARS]]
    return IssuePlan(
        jurisdiction=jurisdiction,
        subject=subject,
        proposition_keys=[key for key, _ in propositions],
        queries=queries,
        notes_considered=len(selected_notes) + unsafe_notes_excluded,
        notes_used=len(safe_texts),
        unsafe_notes_excluded=unsafe_notes_excluded,
    )


def note_authorities(text: str) -> list[str]:
    """Statutes, treaty articles and cases named in a law-and-rules note."""

    found: list[str] = []
    for match in _STATUTE.finditer(text):
        found.append(" ".join(match.group(0).split()).rstrip(".,;"))
    for match in _TREATY.finditer(text):
        found.append(match.group(0))
    for match in _CASE_NAME.finditer(text):
        words = match.group(1).split()
        while words and words[0] in _LEAD_WORDS:
            words = words[1:]
        if words:
            found.append(f"{' '.join(words)} [{match.group(2)}]")
    for match in _EU_CASE.finditer(text):
        words = match.group(1).split()
        while words and words[0] in _LEAD_WORDS:
            words = words[1:]
        if words:
            found.append(f"{' '.join(words)} ({match.group(2)})")
    output: list[str] = []
    for item in found:
        if item not in output:
            output.append(item)
    return output


def _knowledge_queries(
    notes: Sequence[IssueSpottingNote],
    *,
    jurisdiction: str,
    subject: str | None,
    owner_identifiers: Sequence[str],
) -> list[str]:
    output: list[str] = []
    for note in notes:
        if not note.source_version_id.startswith("knowledge-"):
            continue
        text = scrub_pii(note.text[:MAX_NOTE_CHARS], owner_identifiers)
        if not text.strip() or prompt_injection_hits(text):
            continue
        first, _, body = text.partition("\n")
        heading = first.split(" — ")[-1].strip()
        authorities = note_authorities(body)[:MAX_QUERY_AUTHORITIES]
        if not heading or not authorities:
            continue
        query = (
            f"{scrub_pii(jurisdiction, owner_identifiers)} {subject or note.subject}. "
            f"Legal issue: {heading}. Authorities: {'; '.join(authorities)}."
        )
        query = _bounded_query_excerpt(query, MAX_QUERY_CHARS)
        if query not in output:
            output.append(query)
        if len(output) >= MAX_KNOWLEDGE_QUERIES:
            break
    return output


def _bounded_query_excerpt(value: str, limit: int) -> str:
    """Keep both the opening instruction and later facts inside a fixed budget."""

    clean = " ".join(value.split())
    if len(clean) <= limit:
        return clean
    if limit < 20:
        return clean[:limit]
    head = (limit - 5) // 2
    tail = limit - 5 - head
    return f"{clean[:head]} […] {clean[-tail:]}"


def _normalise(value: str) -> str:
    return " ".join(value.casefold().split())


def _contains_phrase(text: str, phrase: str) -> bool:
    pattern = r"(?<![a-z0-9])" + re.escape(phrase.casefold()) + r"(?![a-z0-9])"
    return re.search(pattern, text) is not None


def concept_label(key: str) -> str | None:
    """Return the fixed taxonomy label for a proposition key, if known."""

    for concept_key, label, _patterns in _LEGAL_CONCEPTS:
        if concept_key == key:
            return label
    return None


def concept_entries(keys: Sequence[str]) -> list[tuple[str, str]]:
    """Map selected proposition keys to their fixed labels, preserving order."""

    labels = {concept_key: label for concept_key, label, _patterns in _LEGAL_CONCEPTS}
    output: list[tuple[str, str]] = []
    for key in keys:
        label = labels.get(key)
        if label is not None:
            output.append((key, label))
    return output
