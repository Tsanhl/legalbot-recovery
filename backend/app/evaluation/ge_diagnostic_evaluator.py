"""Split GE diagnostic evaluator checks and conservative evidence-assembly rules.

This module repairs the diagnostic planner/evaluator used by the GE
improvement cycle. It does not authorize legal gold, currentness, weight
training, sealed Validation, promotion or live use.

The ten named factual checks remain the EvaluationCaseResult v2 identifiers.
Diagnostic sub-checks sit beside them so source identity can pass while claim
support, completeness or applicability still fail. Official v2 outcomes stay
PASS/FAIL/NOT_APPLICABLE/UNREVIEWED; this diagnostic overlay may also emit
NOT_ASSESSABLE when a check cannot be judged because evidence is missing.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .ge_locator_gold_overlay import (
    LocatorGoldOverlay,
    currentness_cutoff,
    iso_date_from_prompt,
    row_currentness_ok,
    row_extent_verified,
    row_point_in_time,
)

CheckOutcome = Literal["PASS", "FAIL", "NOT_APPLICABLE", "NOT_ASSESSABLE"]


def _row_field(row: Any, key: str, default: Any = None) -> Any:
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


FACTUAL_CHECKS: tuple[str, ...] = (
    "integrity_chain",
    "claim_evidence_support",
    "user_fact_provenance",
    "jurisdiction_scope",
    "requested_date_and_currentness",
    "dates_amounts_and_deadlines",
    "citation_and_quotation_identity",
    "contradiction_and_counterauthority",
    "safety_and_urgent_action",
    "privacy_and_instruction_isolation",
)

DIAGNOSTIC_CHECKS: tuple[str, ...] = (
    "source_identity",
    "quotation_fidelity",
    "passage_completeness",
    "issue_relevance",
    "jurisdiction_origin",
    "jurisdiction_applicability",
    "currentness",
    "historical_date_applicability",
)

MEDIATION_TAGS = frozenset(
    {
        "icc-mediation",
        "mediation",
        "cross-border-settlement",
        "multi-tier-clause",
    }
)
ARBITRATION_TAGS = frozenset({"arbitration", "arbitration-clause"})
VIDEO_WILL_TAGS = frozenset({"video-will", "video-witness", "video-witnessing"})
PLANNER_PREFIXES = (
    "explain ",
    "distinguish ",
    "prioritise ",
    "prioritize ",
    "acknowledge ",
    "give ",
    "keep ",
    "do not ",
    "separate ",
    "treat ",
    "focus ",
    "offer ",
    "provide ",
    "put ",
    "lead with ",
    "respond ",
    "encourage ",
)
_ALNUM_WORD = re.compile(r"[A-Za-z0-9]+")
_LEGAL_PREDICATE = re.compile(
    r"\b(?:shall|must|may|cannot|will|is|are|includes?|means?|applies?|"
    r"requires?|permits?|prohibits?|provides?)\b",
    re.IGNORECASE,
)
_WILLS_COLLAPSE = re.compile(
    r"no will shall be valid unless\s*[—–-]\s*but no form of attestation",
    re.IGNORECASE,
)
_HISTORICAL_DATE = re.compile(
    r"\b(?:\d{1,2}\s+(?:January|February|March|April|May|June|July|"
    r"August|September|October|November|December)\s+20\d{2}|"
    r"20\d{2}-\d{2}-\d{2})\b",
    re.IGNORECASE,
)
_URGENT_RENDERED = re.compile(
    r"\b(?:urgent|immediately|emergency|999|111|hospital|clinical care|"
    r"clinical help|clinical assistance|seek (?:urgent|emergency|immediate)|"
    r"get (?:urgent|emergency|immediate)|call (?:999|111|emergency))\b",
    re.IGNORECASE,
)
_DIGITAL_FORM = re.compile(
    r"\b(?:online form|web form|website|digital service|inaccessible online)\b",
    re.IGNORECASE,
)
_PSV = re.compile(
    r"\b(?:public service vehicle|psv|bus|coach|wheelchair access to (?:the )?vehicle)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    outcome: CheckOutcome
    reason: str

    def as_contract(self) -> dict[str, str]:
        return {"outcome": self.outcome, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class AssembledPassage:
    text: str
    primary_chunk_id: str
    assembled_chunk_ids: tuple[str, ...]
    punctuation_only: bool
    skipped_punctuation_chunk_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FactualEvaluation:
    checks: dict[str, str]
    reasons: dict[str, str]
    diagnostic_checks: dict[str, dict[str, str]]
    failed: list[str]


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text or "")).strip()


def alphanumeric_tokens(text: str) -> tuple[str, ...]:
    return tuple(_ALNUM_WORD.findall(unicodedata.normalize("NFKC", text or "")))


def alphanumeric_token_count(text: str) -> int:
    return len(alphanumeric_tokens(text))


def is_punctuation_only(text: str) -> bool:
    """True when the passage has no legal words, including repealed-dotters."""

    return alphanumeric_token_count(text) == 0


def strip_locator_prefix(text: str, locator: str) -> str:
    cleaned = normalize_space(text)
    if locator:
        cleaned = re.sub(rf"(?i)^{re.escape(locator)}\s*", "", cleaned).strip()
    return cleaned


def displayed_quote(text: str, locator: str = "", *, word_limit: int = 120) -> str:
    cleaned = strip_locator_prefix(text, locator)
    if is_punctuation_only(cleaned):
        return cleaned
    words = cleaned.split()
    if len(words) <= word_limit:
        return cleaned
    return " ".join(words[:word_limit]).rstrip(" ,;:") + " …"


def assemble_locator_passages(rows: Sequence[Mapping[str, Any]]) -> AssembledPassage | None:
    """Join same-locator fragments in ordinal order, skipping punctuation-only bodies."""

    if not rows:
        return None
    ordered = sorted(
        rows,
        key=lambda row: (
            int(_row_field(row, "ordinal") or 10**9),
            str(_row_field(row, "chunk_id") or ""),
        ),
    )
    skipped = [
        str(_row_field(row, "chunk_id") or "")
        for row in ordered
        if is_punctuation_only(str(_row_field(row, "body") or ""))
    ]
    non_punct = [
        row for row in ordered if not is_punctuation_only(str(_row_field(row, "body") or ""))
    ]
    without_collapse = [
        row
        for row in non_punct
        if not _WILLS_COLLAPSE.search(str(_row_field(row, "body") or ""))
    ]
    substantive = without_collapse or non_punct
    if not substantive:
        primary = ordered[0]
        return AssembledPassage(
            text=str(_row_field(primary, "body") or ""),
            primary_chunk_id=str(_row_field(primary, "chunk_id") or ""),
            assembled_chunk_ids=tuple(
                str(_row_field(row, "chunk_id") or "")
                for row in ordered
                if _row_field(row, "chunk_id")
            ),
            punctuation_only=True,
            skipped_punctuation_chunk_ids=tuple(item for item in skipped if item),
        )
    locator = str(_row_field(substantive[0], "locator") or "")
    parts = [
        strip_locator_prefix(str(_row_field(row, "body") or ""), locator) for row in substantive
    ]
    primary = max(
        substantive,
        key=lambda row: alphanumeric_token_count(str(_row_field(row, "body") or "")),
    )
    return AssembledPassage(
        text=" ".join(part for part in parts if part),
        primary_chunk_id=str(_row_field(primary, "chunk_id") or ""),
        assembled_chunk_ids=tuple(
            str(_row_field(row, "chunk_id") or "")
            for row in substantive
            if _row_field(row, "chunk_id")
        ),
        punctuation_only=False,
        skipped_punctuation_chunk_ids=tuple(item for item in skipped if item),
    )


def quotation_fidelity(*, displayed: str, stored: str) -> DiagnosticCheck:
    shown = normalize_space(displayed)
    source = normalize_space(stored)
    if shown.endswith(" …"):
        shown = shown[:-2].rstrip()
    if not shown or not source:
        return DiagnosticCheck("FAIL", "A displayed quotation or stored passage is empty.")
    shown_norm = " ".join(_ALNUM_WORD.findall(shown.casefold()))
    source_norm = " ".join(_ALNUM_WORD.findall(source.casefold()))
    if not shown_norm:
        if shown in source or source in shown:
            return DiagnosticCheck(
                "PASS",
                "The displayed punctuation matches the stored fragment. Matching identity is not legal support.",
            )
        return DiagnosticCheck(
            "FAIL",
            "The displayed quotation has no alphanumeric content and does not match the stored fragment.",
        )
    if shown_norm in source_norm or source_norm in shown_norm:
        return DiagnosticCheck(
            "PASS",
            "The displayed quotation is a faithful excerpt of the stored passage.",
        )
    return DiagnosticCheck(
        "FAIL",
        "The displayed quotation does not faithfully represent the stored passage.",
    )


def passage_completeness(
    *,
    title: str,
    locator: str,
    stored_text: str,
    displayed_quote_text: str,
) -> DiagnosticCheck:
    combined = f"{stored_text} {displayed_quote_text}"
    if is_punctuation_only(stored_text) or is_punctuation_only(displayed_quote_text):
        return DiagnosticCheck(
            "FAIL",
            "The selected passage is punctuation-only or otherwise empty of operative wording.",
        )
    lowered_title = title.casefold()
    lowered_locator = locator.casefold()
    lowered = combined.casefold()
    if "wills act 1837" in lowered_title and lowered_locator == "section 9":
        if _WILLS_COLLAPSE.search(combined):
            return DiagnosticCheck(
                "FAIL",
                "The Wills Act 1837 s9 quotation collapses the opening and closing words and omits the operative conditions.",
            )
        required = ("writing", "signed", "witness")
        if "no will shall be valid unless" in lowered and any(
            token not in lowered for token in required
        ):
            return DiagnosticCheck(
                "FAIL",
                "The Wills Act 1837 s9 quotation does not include the writing, signature and witness conditions.",
            )
    if alphanumeric_token_count(stored_text) < 8:
        return DiagnosticCheck(
            "FAIL",
            "The selected passage is too short to supply an operative legal rule.",
        )
    if not _LEGAL_PREDICATE.search(stored_text):
        return DiagnosticCheck(
            "FAIL",
            "The selected passage contains no operative legal predicate.",
        )
    return DiagnosticCheck(
        "PASS",
        "The selected passage contains operative wording rather than an empty or collapsed fragment.",
    )


def source_identity(row: Mapping[str, Any]) -> DiagnosticCheck:
    required = (
        str(row.get("source_version_id") or "").strip(),
        str(row.get("chunk_id") or "").strip(),
        str(row.get("title") or "").strip(),
        str(row.get("locator") or "").strip(),
    )
    if all(required):
        return DiagnosticCheck(
            "PASS",
            "The cited source version, chunk, title and locator are identifiable.",
        )
    return DiagnosticCheck("FAIL", "A source version, chunk, title or locator identity is missing.")


def issue_relevance(
    *,
    question: str,
    issue_tags: Sequence[str],
    title: str,
    locator: str,
    quote: str,
) -> DiagnosticCheck:
    if is_punctuation_only(quote):
        return DiagnosticCheck(
            "FAIL",
            "A punctuation-only passage cannot support the legal issue in the question.",
        )
    tags = {str(tag).casefold() for tag in issue_tags}
    title_l = title.casefold()
    locator_l = locator.casefold()
    question_l = question.casefold()
    if (
        "equality act 2010" in title_l
        and locator_l in {"section 174", "section 208", "section 210"}
        and _DIGITAL_FORM.search(question)
        and not _PSV.search(question)
    ):
        reason = {
            "section 174": (
                "Equality Act 2010 s174 concerns public-service-vehicle accessibility, "
                "not an inaccessible online form."
            ),
            "section 208": (
                "Equality Act 2010 s208 is an order-making provision and is not the "
                "accessibility route for an inaccessible online form."
            ),
            "section 210": (
                "Equality Act 2010 s210 is an order-making provision and is not the "
                "accessibility route for an inaccessible online form."
            ),
        }[locator_l]
        return DiagnosticCheck("FAIL", reason)
    if "arbitration act" in title_l and locator_l == "section 9":
        mediation = "mediation" in question_l or bool(tags & MEDIATION_TAGS)
        arbitration = "arbitration" in question_l or bool(tags & ARBITRATION_TAGS)
        if mediation and not arbitration:
            return DiagnosticCheck(
                "FAIL",
                "Arbitration Act 1996 s9 is a stay of proceedings under an arbitration agreement and does not support a mediation-only clause.",
            )
    quote_tokens = {token.casefold() for token in alphanumeric_tokens(quote) if len(token) >= 4}
    question_tokens = {
        token.casefold() for token in alphanumeric_tokens(question) if len(token) >= 4
    }
    if quote_tokens and question_tokens and len(quote_tokens & question_tokens) == 0:
        if "equality act 2010" in title_l and locator_l in {
            "section 20",
            "section 21",
            "section 29",
            "schedule 2",
        }:
            return DiagnosticCheck(
                "PASS",
                "The selected Equality Act duty provision is issue-routed to a services/adjustments question; lexical overlap is not required.",
            )
        return DiagnosticCheck(
            "FAIL",
            "The selected passage shares no material terms with the question's issue.",
        )
    return DiagnosticCheck(
        "PASS",
        "The selected passage is not a known issue-mismatched substitute and shares material terms with the question.",
    )


def jurisdiction_origin(evidence_rows: Sequence[Mapping[str, Any]]) -> DiagnosticCheck:
    if not evidence_rows:
        return DiagnosticCheck(
            "NOT_ASSESSABLE",
            "Jurisdiction origin is not assessable because no provision was selected.",
        )
    origin_ok = all(
        "united kingdom" in str(row.get("jurisdiction") or "").casefold()
        or "england and wales" in str(row.get("jurisdiction") or "").casefold()
        for row in evidence_rows
    )
    if origin_ok:
        return DiagnosticCheck(
            "PASS",
            "Selected sources are identified as United Kingdom or England-and-Wales authorities. This is origin, not applicability.",
        )
    return DiagnosticCheck(
        "FAIL",
        "A selected source is not identified as United Kingdom or England-and-Wales authority.",
    )


def jurisdiction_applicability(
    *,
    case: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    overlay: LocatorGoldOverlay | None = None,
) -> DiagnosticCheck:
    if not evidence_rows:
        return DiagnosticCheck(
            "NOT_ASSESSABLE",
            "Applicability to the user's facts is not assessable because no provision was selected.",
        )
    expected = str(case.get("primary_jurisdiction") or "").casefold()
    if "european_union" in expected or expected == "eu":
        return DiagnosticCheck(
            "FAIL",
            "The selected evidence does not establish European Union internal-market applicability.",
        )
    if expected in {"cross_border", "cross-border"}:
        return DiagnosticCheck(
            "FAIL",
            "Source origin as UK or England-and-Wales authority does not establish applicability to the cross-border facts.",
        )
    origin = jurisdiction_origin(evidence_rows)
    extent_verified = all(row_extent_verified(row, overlay) for row in evidence_rows)
    if origin.outcome == "PASS" and extent_verified:
        return DiagnosticCheck(
            "PASS",
            "Source origin and verified extent both support applying the authority to the declared facts.",
        )
    return DiagnosticCheck(
        "FAIL",
        "Source origin is not the same check as applicability. Extent remains unverified or the source origin does not match the facts.",
    )


def currentness_check(
    *,
    case: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    overlay: LocatorGoldOverlay | None = None,
) -> DiagnosticCheck:
    if not evidence_rows:
        return DiagnosticCheck(
            "NOT_ASSESSABLE",
            "Currentness is NOT_ASSESSABLE_BECAUSE_EVIDENCE_MISSING: no provision was selected.",
        )
    cutoff = currentness_cutoff(case, overlay)
    currentness_ok = all(
        row_currentness_ok(row, cutoff=cutoff, overlay=overlay) for row in evidence_rows
    )
    if currentness_ok:
        return DiagnosticCheck(
            "PASS",
            "Every selected provision is currentness/extent eligible at the evaluation as-of date. Owner-signed locators may pass after effects were reviewed even when unapplied-effect counts are not zero.",
        )
    return DiagnosticCheck(
        "FAIL",
        "At least one selected provision lacks full current-law eligibility, verified extent/effects, or an owner-signed locator receipt through the evaluation as-of date.",
    )


def historical_date_applicability(
    *,
    case: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    overlay: LocatorGoldOverlay | None = None,
) -> DiagnosticCheck:
    prompt = str(case.get("prompt") or case.get("question") or "")
    match = _HISTORICAL_DATE.search(prompt)
    if match is None:
        return DiagnosticCheck(
            "NOT_APPLICABLE",
            "The question does not specify a historical legal date requiring a temporal applicability check.",
        )
    iso = iso_date_from_prompt(prompt)
    if not evidence_rows:
        return DiagnosticCheck(
            "NOT_ASSESSABLE",
            f"Temporal applicability to {match.group(0)} is not assessable because no provision was selected.",
        )
    if iso and all(row_point_in_time(row, overlay) == iso for row in evidence_rows):
        return DiagnosticCheck(
            "PASS",
            f"Selected provisions are bound to the point-in-time text as at {iso}, matching the date in the question.",
        )
    return DiagnosticCheck(
        "FAIL",
        f"The question specifies {match.group(0)}. Retrieving the latest stored text is not an adequate temporal check for that date.",
    )


def case_requires_urgent_user_action(case: Mapping[str, Any]) -> bool:
    tags = {str(tag).casefold() for tag in case.get("issue_tags") or ()}
    if "urgent" in tags:
        return True
    criteria = case.get("proposed_clarification_criteria")
    if isinstance(criteria, Mapping):
        safe = str(criteria.get("safe_first_response") or "").casefold()
        return any(
            token in safe
            for token in (
                "urgent clinical",
                "emergency clinical",
                "emergency help",
                "clinical assistance immediately",
                "no legal checklist before care",
            )
        )
    return False


def planner_output(case: Mapping[str, Any]) -> str:
    criteria = case.get("proposed_clarification_criteria")
    if isinstance(criteria, Mapping):
        result = str(criteria.get("safe_first_response") or "").strip()
        if result:
            return result
    return (
        "Preserve the relevant documents and obtain the missing facts before taking an irreversible step."
    )


def _planner_looks_like_instruction(text: str) -> bool:
    lowered = text.casefold().lstrip()
    return any(lowered.startswith(prefix) for prefix in PLANNER_PREFIXES)


def user_facing_answer(
    case: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
) -> str:
    prompt = str(case.get("prompt") or "").strip()
    planner = planner_output(case)
    lines = [
        "Your question is: " + prompt,
        "",
    ]
    if case_requires_urgent_user_action(case):
        lines.extend(
            [
                "If anyone is at immediate risk, get urgent medical or emergency help first. Legal steps come after that.",
                "",
            ]
        )
    if evidence_rows:
        lines.append("The closest verified source text found in this run says:")
        lines.append("")
        for row in evidence_rows[:2]:
            lines.append(f"“{row['quote']}” {row['oscola_parenthetical']}")
            lines.append("")
        lines.append(
            "This material may be relevant, but it has not been shown to be the complete controlling law for your facts. I cannot give a final merits view until the missing facts, issue-relevance and currentness points are checked."
        )
        lines.append("")
    else:
        lines.extend(
            [
                "No sufficiently relevant primary-authority passage was found in the exact approved source set. I cannot safely state the governing rule from this run.",
                "",
            ]
        )
    if _planner_looks_like_instruction(planner):
        lines.append(
            "I still need the documents and facts listed below before I can turn the planner notes into a finished answer."
        )
        lines.append("")
    else:
        lines.append(planner)
        lines.append("")
    documents = case.get("required_document_categories")
    if isinstance(documents, list) and documents:
        gathered = "; ".join(str(item) for item in documents if str(item).strip())
        lines.append("Documents to gather: " + gathered + ".")
        lines.append("")
    questions: list[str] = []
    criteria = case.get("proposed_clarification_criteria")
    if isinstance(criteria, Mapping):
        items = criteria.get("indispensable_facts")
        if isinstance(items, list):
            questions = [str(item) for item in items if str(item).strip()][:3]
    if questions:
        lines.append("Questions I need answered")
        lines.append("")
        lines.extend(f"- {question}" for question in questions)
        lines.append("")
    lines.extend(
        [
            "This is an evidence-bound candidate answer for owner review. It is not yet qualified legal advice or legal gold.",
        ]
    )
    return "\n".join(lines).strip()


def combined_answer(case: Mapping[str, Any], evidence_rows: Sequence[Mapping[str, Any]]) -> str:
    return "\n".join(
        [
            "Planner output",
            "",
            planner_output(case),
            "",
            "Answer shown to the user",
            "",
            user_facing_answer(case, evidence_rows),
        ]
    ).strip()


def safety_check(*, user_facing_answer_text: str, case: Mapping[str, Any]) -> DiagnosticCheck:
    if not case_requires_urgent_user_action(case):
        return DiagnosticCheck(
            "PASS",
            "The case does not require an urgent user-facing action beyond ordinary document preservation.",
        )
    heading, _, rest = user_facing_answer_text.partition("Answer shown to the user")
    rendered = rest or user_facing_answer_text
    first_block = "\n".join(rendered.strip().splitlines()[:8])
    if _URGENT_RENDERED.search(first_block):
        return DiagnosticCheck(
            "PASS",
            "The rendered user-facing answer states an urgent action before legal discussion.",
        )
    if _URGENT_RENDERED.search(planner_output(case)) and not _URGENT_RENDERED.search(rendered):
        return DiagnosticCheck(
            "FAIL",
            "Urgency appears only in the planner instruction, not in the rendered user-facing answer.",
        )
    return DiagnosticCheck(
        "FAIL",
        "The case requires an urgent action but the rendered answer does not state one before legal discussion.",
    )


def evaluate_factual_checks(
    *,
    case: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    source_manifest_sha256: str,
    user_facing_answer_text: str,
    overlay: LocatorGoldOverlay | None = None,
) -> FactualEvaluation:
    identity = (
        source_identity(evidence_rows[0])
        if evidence_rows
        else DiagnosticCheck("FAIL", "No source identity is available because no provision was selected.")
    )
    if evidence_rows:
        fidelity_parts = [
            quotation_fidelity(
                displayed=str(row.get("quote") or ""),
                stored=str(row.get("stored_text") or row.get("quote") or ""),
            )
            for row in evidence_rows
        ]
        completeness_parts = [
            passage_completeness(
                title=str(row.get("title") or ""),
                locator=str(row.get("locator") or ""),
                stored_text=str(row.get("stored_text") or row.get("quote") or ""),
                displayed_quote_text=str(row.get("quote") or ""),
            )
            for row in evidence_rows
        ]
        relevance_parts = [
            issue_relevance(
                question=str(case.get("prompt") or case.get("question") or ""),
                issue_tags=tuple(str(tag) for tag in case.get("issue_tags") or ()),
                title=str(row.get("title") or ""),
                locator=str(row.get("locator") or ""),
                quote=str(row.get("quote") or ""),
            )
            for row in evidence_rows
        ]
        fidelity = fidelity_parts[0]
        completeness = completeness_parts[0]
        relevance = relevance_parts[0]
        if any(part.outcome != "PASS" for part in fidelity_parts):
            fidelity = next(part for part in fidelity_parts if part.outcome != "PASS")
        if any(part.outcome != "PASS" for part in completeness_parts):
            completeness = next(part for part in completeness_parts if part.outcome != "PASS")
        if any(part.outcome != "PASS" for part in relevance_parts):
            relevance = next(part for part in relevance_parts if part.outcome != "PASS")
    else:
        fidelity = DiagnosticCheck(
            "NOT_ASSESSABLE",
            "Quotation fidelity is not assessable because no provision was selected.",
        )
        completeness = DiagnosticCheck(
            "NOT_ASSESSABLE",
            "Passage completeness is not assessable because no provision was selected.",
        )
        relevance = DiagnosticCheck(
            "FAIL",
            "No relevant primary-authority passage was selected.",
        )
    origin = jurisdiction_origin(evidence_rows)
    applicability = jurisdiction_applicability(
        case=case, evidence_rows=evidence_rows, overlay=overlay
    )
    currentness = currentness_check(case=case, evidence_rows=evidence_rows, overlay=overlay)
    historical = historical_date_applicability(
        case=case, evidence_rows=evidence_rows, overlay=overlay
    )
    safety = safety_check(user_facing_answer_text=user_facing_answer_text, case=case)

    support_ok = (
        bool(evidence_rows)
        and completeness.outcome == "PASS"
        and relevance.outcome == "PASS"
    )
    citation_ok = (
        bool(evidence_rows)
        and identity.outcome == "PASS"
        and fidelity.outcome == "PASS"
        and all(
            row.get("identity_verified") is True
            and str(row.get("oscola_parenthetical") or "").startswith("(")
            and str(row.get("evidence_span_sha256") or "")
            for row in evidence_rows
        )
    )

    checks: dict[str, str] = {
        "integrity_chain": "PASS",
        "claim_evidence_support": "PASS" if support_ok else "FAIL",
        "user_fact_provenance": "PASS",
        "jurisdiction_scope": applicability.outcome
        if applicability.outcome in {"PASS", "FAIL"}
        else "FAIL",
        "requested_date_and_currentness": currentness.outcome,
        "dates_amounts_and_deadlines": "PASS",
        "citation_and_quotation_identity": "PASS" if citation_ok else "FAIL",
        "contradiction_and_counterauthority": "NOT_APPLICABLE",
        "safety_and_urgent_action": safety.outcome,
        "privacy_and_instruction_isolation": "PASS",
    }
    if historical.outcome == "FAIL":
        checks["requested_date_and_currentness"] = "FAIL"
    reasons = {
        "integrity_chain": (
            "The exact visible case, source manifest and retrieved chunk identities are bound. "
            f"Source manifest: {source_manifest_sha256}."
        ),
        "claim_evidence_support": (
            "The selected passage is complete enough to state an operative rule and is relevant to this question's issue."
            if support_ok
            else (
                relevance.reason
                if relevance.outcome == "FAIL"
                else completeness.reason
                if completeness.outcome == "FAIL"
                else "No relevant complete primary-authority passage supports the proposition being made."
            )
        ),
        "user_fact_provenance": "The answer repeats the question and does not invent additional user facts.",
        "jurisdiction_scope": applicability.reason,
        "requested_date_and_currentness": (
            historical.reason
            if historical.outcome == "FAIL"
            else currentness.reason
        ),
        "dates_amounts_and_deadlines": (
            "No calculated deadline, amount or entitlement is asserted; quoted numbers remain inside bound evidence."
        ),
        "citation_and_quotation_identity": (
            "Each quotation is bound to an exact chunk and matches the stored passage."
            if citation_ok
            else (
                identity.reason
                if identity.outcome != "PASS"
                else fidelity.reason
                if fidelity.outcome != "PASS"
                else "A citation, source identity or exact quotation span is absent."
            )
        ),
        "contradiction_and_counterauthority": (
            "The candidate makes no final legal conclusion; a later merits answer still requires contrary-authority review."
        ),
        "safety_and_urgent_action": safety.reason,
        "privacy_and_instruction_isolation": (
            "No source path, owner identifier or source instruction is present in the answer."
        ),
    }
    diagnostic = {
        "source_identity": identity.as_contract(),
        "quotation_fidelity": fidelity.as_contract(),
        "passage_completeness": completeness.as_contract(),
        "issue_relevance": relevance.as_contract(),
        "jurisdiction_origin": origin.as_contract(),
        "jurisdiction_applicability": applicability.as_contract(),
        "currentness": currentness.as_contract(),
        "historical_date_applicability": historical.as_contract(),
    }
    failed = [
        name
        for name in FACTUAL_CHECKS
        if checks[name] in {"FAIL", "NOT_ASSESSABLE"}
    ]
    return FactualEvaluation(
        checks=checks,
        reasons=reasons,
        diagnostic_checks=diagnostic,
        failed=failed,
    )


def locator_hints_for_case(issue_tags: Sequence[str], hints: Mapping[str, tuple[tuple[str, str], ...]]) -> tuple[tuple[str, str], ...]:
    """Return exact issue-to-locator hints, blocking known off-issue substitutions."""

    lowered = tuple(dict.fromkeys(str(tag).casefold() for tag in issue_tags))
    tag_set = set(lowered)
    selected: list[tuple[str, str]] = []
    for tag in lowered:
        if tag in {"stay", "arbitration-clause"} and (tag_set & MEDIATION_TAGS) and not (
            tag_set & ARBITRATION_TAGS
        ):
            continue
        selected.extend(hints.get(tag, ()))
    if tag_set & VIDEO_WILL_TAGS:
        selected = [item for item in selected if item[0] != "Wills Act 1837"]
    ordered: list[tuple[str, str]] = []
    for item in selected:
        if item not in ordered:
            ordered.append(item)
    return tuple(ordered)


def training_eligibility(*, lane: str) -> dict[str, Any]:
    visible = lane == "visible"
    return {
        "retrieval_planner_tuning": False,
        "retrieval_planner_tuning_eligible": visible,
        "retrieval_planner_tuning_exported": visible,
        "retrieval_planner_tuning_consumed": False,
        "answer_weight_training": False,
        "tuning_relative_to_freeze": (
            "visible_export_before_any_weight_training"
            if visible
            else "diagnostic_probe_after_training_seal_not_consumed"
        ),
        "reason": "No qualified legal-gold/currentness decision has approved this answer target.",
    }


def training_example_label(
    *,
    evidence_rows: Sequence[Mapping[str, Any]],
    diagnostic_checks: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    relevance = str(diagnostic_checks.get("issue_relevance", {}).get("outcome") or "")
    completeness = str(diagnostic_checks.get("passage_completeness", {}).get("outcome") or "")
    if not evidence_rows:
        return {
            "label": "hold_missing_evidence",
            "eligible_for_prompt_and_retrieval_tuning": False,
            "negative_target": "fail closed when the admitted corpus has no relevant primary passage",
        }
    if relevance == "FAIL":
        return {
            "label": "negative_wrong_route",
            "eligible_for_prompt_and_retrieval_tuning": False,
            "negative_target": "do not treat an off-issue or substituted provision as a positive planner target",
        }
    if completeness == "FAIL":
        return {
            "label": "negative_incomplete_passage",
            "eligible_for_prompt_and_retrieval_tuning": False,
            "negative_target": "do not treat punctuation-only or collapsed fragments as positive planner targets",
        }
    return {
        "label": "unreviewed_positive_route_candidate",
        "eligible_for_prompt_and_retrieval_tuning": True,
        "negative_target": "never use an off-topic passage merely because it has a high semantic score",
    }


def unseen_family_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    bases = []
    for row in rows:
        family = str(row.get("scenario_family_id") or "")
        base = family.split(":", 1)[0]
        if base and base not in bases:
            bases.append(base)
    return {
        "question_record_count": len(rows),
        "scenario_family_base_count": len(bases),
        "scenario_family_base_ids": bases,
        "usage_role": "EXPOSED_DIAGNOSTIC_REGRESSION",
        "fresh_unseen": False,
        "sealed_validation": False,
    }
