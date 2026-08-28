"""Teaching → verify → cite flow over private teaching and authority lanes.

Private teaching may only issue-spot. This module turns screened ``IssuePlan``
taxonomy keys into internal teaching suggestions, then checks each suggestion
against already-retrieved primary / official / scholarship evidence. Persisted
items keep internal verify statuses in metadata; the user-facing ``notes_view``
is knowledge-card style (``what`` + ``authority``) extracted from the taxonomy
and authority-backed text when available.

Teaching prose is never rephrased into a citable corpus and never satisfies a
material legal claim. Teaching is never cited as authority; OSCOLA is never
invented.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..citations.oscola import CitationMetadataError, render_oscola
from ..quality.evidence import (
    is_citable_authority_lane,
    is_substantively_related,
    substantive_tokens,
)
from ..types import (
    EvidenceSpan,
    IssuePlan,
    TeachingFlowItem,
    TeachingVerifyCiteFlow,
    TeachingVerifyStatus,
)
from .issues import concept_entries

_NEGATION = frozenset({"not", "no", "cannot", "can't", "never", "neither", "without", "unless"})
_SUMMARY_TEMPLATE = (
    "{label_cap} is the legal issue concerned with the governing tests, "
    "elements and authorities that determine when it arises on the facts."
)
_MAX_WHAT_CHARS = 320


def teaching_summary_for(label: str) -> str:
    """Fixed, taxonomy-bound working definition — never private lecture prose."""

    cleaned = " ".join(label.split()).strip() or "this issue"
    label_cap = cleaned[:1].upper() + cleaned[1:]
    return _SUMMARY_TEMPLATE.format(label_cap=label_cap)


def knowledge_what_for(label: str, authority_spans: Sequence[EvidenceSpan] = ()) -> str:
    """Prefer a citable authority excerpt for ``what``; else taxonomy definition."""

    for span in authority_spans:
        excerpt = " ".join((span.text or "").split()).strip()
        if len(excerpt) < 24:
            continue
        if len(excerpt) > _MAX_WHAT_CHARS:
            trimmed = excerpt[: _MAX_WHAT_CHARS - 1].rsplit(" ", 1)[0].rstrip(",;:")
            excerpt = f"{trimmed}…" if trimmed else excerpt[: _MAX_WHAT_CHARS - 1] + "…"
        return excerpt
    return teaching_summary_for(label)


def build_teaching_suggestions(issue_plan: IssuePlan) -> list[TeachingFlowItem]:
    """Emit internal ``teaching_suggestion`` items for each selected taxonomy key."""

    items: list[TeachingFlowItem] = []
    for key, label in concept_entries(issue_plan.proposition_keys):
        items.append(
            TeachingFlowItem(
                proposition_key=key,
                label=label,
                teaching_summary=teaching_summary_for(label),
                status=TeachingVerifyStatus.TEACHING_SUGGESTION,
                evidence_ids=[],
                citations=[],
                reason="Derived from the issue taxonomy only.",
            )
        )
    return items


def authority_citation(span: EvidenceSpan) -> str | None:
    """Deterministic OSCOLA from an authority span; never invent a cite."""

    if not is_citable_authority_lane(span):
        return None
    if span.canonical_citation and span.canonical_citation.strip():
        return span.canonical_citation.strip()
    if not span.citation_data:
        return None
    try:
        return render_oscola(span.citation_data, span.locator)
    except CitationMetadataError:
        try:
            return render_oscola(span.citation_data)
        except CitationMetadataError:
            return None


def _tokens(text: str) -> set[str]:
    return set(substantive_tokens(text))


def _has_negation(text: str) -> bool:
    words = set(re.findall(r"[a-z']+", text.casefold()))
    return bool(words & _NEGATION)


def _contradicts(proposition: str, span: EvidenceSpan) -> bool:
    """Heuristic contradiction: shared substance with opposite polarity."""

    prop_tokens = _tokens(proposition)
    span_tokens = _tokens(span.text)
    if not prop_tokens or not span_tokens:
        return False
    overlap = len(prop_tokens & span_tokens) / len(prop_tokens | span_tokens)
    if overlap < 0.28:
        return False
    return _has_negation(span.text) != _has_negation(proposition)


def _strong_support(proposition: str, span: EvidenceSpan) -> bool:
    claim = substantive_tokens(proposition)
    source = substantive_tokens(f"{span.text}\n{span.locator}")
    if not claim or not source:
        return False
    shared = set(claim) & set(source)
    if len(shared) >= 3:
        return True
    smaller = min(len(set(claim)), len(set(source)))
    return len(shared) >= 2 and len(shared) / max(1, smaller) >= 0.34


def verify_teaching_suggestions(
    suggestions: Sequence[TeachingFlowItem],
    authority_evidence: Sequence[EvidenceSpan],
) -> list[TeachingFlowItem]:
    """Verify teaching suggestions against citable authority spans only."""

    authority = [span for span in authority_evidence if is_citable_authority_lane(span)]
    results: list[TeachingFlowItem] = []
    for suggestion in suggestions:
        proposition = suggestion.label
        related = [
            span
            for span in authority
            if is_substantively_related(proposition, span)
            or is_substantively_related(suggestion.teaching_summary, span)
        ]
        contradicting = [span for span in authority if _contradicts(proposition, span)]
        if contradicting and not related:
            cites = [
                citation
                for span in contradicting
                if (citation := authority_citation(span)) is not None
            ]
            results.append(
                TeachingFlowItem(
                    proposition_key=suggestion.proposition_key,
                    label=suggestion.label,
                    teaching_summary=knowledge_what_for(suggestion.label, contradicting[:8]),
                    status=TeachingVerifyStatus.CONTRADICTED,
                    evidence_ids=[span.id for span in contradicting[:8]],
                    citations=list(dict.fromkeys(cites))[:8],
                    reason="Authority material appears to contradict this issue.",
                )
            )
            continue
        if not related:
            results.append(
                TeachingFlowItem(
                    proposition_key=suggestion.proposition_key,
                    label=suggestion.label,
                    teaching_summary=knowledge_what_for(suggestion.label),
                    status=TeachingVerifyStatus.NOT_FOUND,
                    evidence_ids=[],
                    citations=[],
                    reason=(
                        "No qualifying primary, official or scholarship span supported this issue."
                    ),
                )
            )
            continue
        strong = [span for span in related if _strong_support(proposition, span)]
        chosen = strong or related
        cites = [citation for span in chosen if (citation := authority_citation(span)) is not None]
        if contradicting or not strong:
            status = TeachingVerifyStatus.PARTLY_VERIFIED
            reason = (
                "Authority support is only partial, mixed with contrary material, "
                "or lexically weak relative to this issue."
                if contradicting
                else "Authority support is only partial relative to this issue."
            )
        else:
            status = TeachingVerifyStatus.VERIFIED
            reason = "Qualifying authority spans substantiate this issue."
        results.append(
            TeachingFlowItem(
                proposition_key=suggestion.proposition_key,
                label=suggestion.label,
                teaching_summary=knowledge_what_for(suggestion.label, chosen[:8]),
                status=status,
                evidence_ids=[span.id for span in chosen[:8]],
                citations=list(dict.fromkeys(cites))[:8],
                reason=reason,
            )
        )
    return results


def render_teaching_notes_view(flow: TeachingVerifyCiteFlow) -> str:
    """Render knowledge-card notes extracted from taxonomy + authority.

    Format::

        notes

        <proposition_key> - <label>
        what: <authority excerpt or taxonomy-bound definition>
        authority: <OSCOLA cite(s) or "none in current authority set">
    """

    return flow.render_notes_view()


def run_teaching_verify_cite_flow(
    *,
    issue_plan: IssuePlan,
    authority_evidence: Sequence[EvidenceSpan],
) -> TeachingVerifyCiteFlow:
    """Compose internal teaching suggestions then persist verification outcomes only."""

    suggestions = build_teaching_suggestions(issue_plan)
    verifications = verify_teaching_suggestions(suggestions, authority_evidence)
    # User-facing / persisted items are verification outcomes only.
    # teaching_suggestion remains an internal discriminator used during verify.
    return TeachingVerifyCiteFlow(items=list(verifications))


def teaching_chunks_cannot_satisfy_material_claim(
    claim_text: str, spans: Sequence[EvidenceSpan]
) -> bool:
    """True when every bound span is a non-authority lane (fails closed)."""

    del claim_text
    if not spans:
        return True
    return not any(is_citable_authority_lane(span) for span in spans)
