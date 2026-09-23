"""Targeted Kajima paragraph 29/30 mediation-family delta.

Discovery of an attachable locator is not execution. Attachment runs only on
``TARGETED_MEDIATION_FAMILY``. Attachable is not attached, not claim-support
PASS, not FACTUAL_PASS, and not qualified-review approval.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .ge_diagnostic_evaluator import (
    combined_answer,
    evaluate_factual_checks,
    issue_relevance,
    locator_hints_for_case,
    passage_completeness,
    training_eligibility,
    user_facing_answer,
)
from .ge_factual_gap_fill import sidecar_packs
from .ge_hold_reason_router import CASE_174, QUALIFIED_LEGAL_REVIEW_QUEUE, dependency_hash
from .ge_locator_gold_overlay import normalize_locator, titles_equivalent
from .ge_phase2_progress import NO_OP_UNCHANGED_CASE_INPUTS

TARGETED_MEDIATION_FAMILY = "TARGETED_MEDIATION_FAMILY"
ATTACHABLE_PENDING_TARGETED_FAMILY = "ATTACHABLE_PENDING_TARGETED_FAMILY"
PENDING_TARGETED_FAMILY = "PENDING_TARGETED_FAMILY"
PENDING_TARGETED_MEDIATION_FAMILY = "PENDING_TARGETED_MEDIATION_FAMILY"
OUTSIDE_TARGETED_MEDIATION_FAMILY = "OUTSIDE_TARGETED_MEDIATION_FAMILY"
MEDIATION_TOPIC = "international-commercial-mediation"
KAJIMA_TITLE = "Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd"
KAJIMA_NEW_LOCATORS = frozenset({"paragraph 29", "paragraph 30"})
PARAGRAPH_29 = "paragraph 29"
PARAGRAPH_30 = "paragraph 30"
ICC_TITLE = "ICC Mediation Rules (contractually incorporated edition)"
OHPEN_TITLE = "Ohpen Operations UK Ltd v Invesco Fund Managers Ltd"
CHURCHILL_TITLE = "Churchill v Merthyr Tydfil County Borough Council"
CPR_TITLE = "The Civil Procedure Rules 1998"
SENIOR_COURTS_TITLE = "Senior Courts Act 1981"

# HEAD retrieval hints had Kajima paragraph 1 on icc-mediation only, and no
# paragraph 29/30 on mediation or multi-tier-clause.
PREVIOUS_KAJIMA_29_30_HINTS: tuple[tuple[str, str], ...] = ()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def is_kajima_title(title: str) -> bool:
    return titles_equivalent(title, KAJIMA_TITLE) or "kajima" in str(title or "").casefold()


def is_kajima_paragraph_29_or_30(title: str, locator: str) -> bool:
    if not is_kajima_title(title):
        return False
    pin = normalize_locator(locator)
    return pin in KAJIMA_NEW_LOCATORS or pin in {"para 29", "para 30"}


def _canonical_kajima_locator(locator: str) -> str:
    pin = normalize_locator(locator)
    if pin in {"paragraph 29", "para 29"}:
        return PARAGRAPH_29
    if pin in {"paragraph 30", "para 30"}:
        return PARAGRAPH_30
    return pin


def kajima_29_30_hints(
    issue_tags: Sequence[str],
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
) -> tuple[tuple[str, str], ...]:
    selected = locator_hints_for_case(issue_tags, locator_hints)
    return tuple(
        (title, locator)
        for title, locator in selected
        if is_kajima_paragraph_29_or_30(title, locator)
    )


def hint_dependency_hash(
    row: Mapping[str, Any],
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
) -> str:
    hints = [
        {"title": title, "locator": locator}
        for title, locator in kajima_29_30_hints(tuple(row.get("issue_tags") or ()), locator_hints)
    ]
    return _sha({"case_id": str(row.get("case_id") or ""), "kajima_29_30_hints": hints})


def kajima_29_30_hint_dependency_changed(
    row: Mapping[str, Any],
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
) -> bool:
    if str(row.get("topic_id") or "") != MEDIATION_TOPIC:
        return False
    current = kajima_29_30_hints(tuple(row.get("issue_tags") or ()), locator_hints)
    return bool(current) and current != PREVIOUS_KAJIMA_29_30_HINTS


def derive_kajima_29_30_affected_case_ids(
    rows: Sequence[Mapping[str, Any]],
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
) -> tuple[str, ...]:
    affected: list[str] = []
    for row in rows:
        case_id = str(row.get("case_id") or "")
        if not case_id:
            continue
        if kajima_29_30_hint_dependency_changed(row, locator_hints):
            affected.append(case_id)
    return tuple(dict.fromkeys(affected))


def _question(row: Mapping[str, Any]) -> str:
    return str(row.get("question") or row.get("prompt") or "")


def kajima_29_in_scope(question: str, issue_tags: Sequence[str]) -> tuple[bool, str]:
    """Kajima 29 is a contractual DRP condition-precedent finding, not interim relief."""

    q = str(question or "").casefold()
    tags = {str(tag).casefold() for tag in issue_tags}
    if "interim-relief" in tags or "protect assets" in q or "moving assets" in q:
        if "icc-mediation" not in tags and "multi-tier-clause" not in tags:
            return False, "beyond_kajima_dispute_resolution_scope_interim_relief"
    if "multi-tier-clause" in tags or "icc-mediation" in tags:
        return True, "contractual_multi_tier_or_icc_condition_precedent"
    if "will not cooperate" in q or "negotiation first" in q:
        return True, "multi_tier_non_cooperation"
    if "mediate before" in q or "icc mediation before" in q:
        return True, "contractual_adr_before_court"
    return False, "proposition_outside_kajima_ratio"


def interim_relief_only(question: str, issue_tags: Sequence[str]) -> bool:
    tags = {str(tag).casefold() for tag in issue_tags}
    if "icc-mediation" in tags or "multi-tier-clause" in tags:
        return False
    q = str(question or "").casefold()
    return "interim-relief" in tags or "protect assets" in q or "moving assets" in q


def _is_icc_article_5_title(title: str, locator: str) -> bool:
    pin = normalize_locator(locator)
    return pin == "article 5" and (
        titles_equivalent(title, ICC_TITLE) or "icc mediation" in str(title or "").casefold()
    )


def _is_cpr_adr_case_management(title: str, locator: str) -> bool:
    if not titles_equivalent(title, CPR_TITLE):
        return False
    pin = normalize_locator(locator)
    return re.match(r"^rule (1|3|44)(\s|$)", pin) is not None


def _is_interim_relief_locator(title: str, locator: str) -> bool:
    pin = normalize_locator(locator)
    if titles_equivalent(title, CPR_TITLE) and pin.startswith("rule 25"):
        return True
    return titles_equivalent(title, SENIOR_COURTS_TITLE) and pin == "section 37"


def mediation_family_locator_allowed(
    title: str,
    locator: str,
    question: str,
    issue_tags: Sequence[str],
) -> tuple[bool, str]:
    """Family attach discipline. Attachable is not automatic attach."""

    if is_kajima_paragraph_29_or_30(title, locator):
        pin = normalize_locator(locator)
        if pin in {"paragraph 30", "para 30"}:
            return False, "kajima_paragraph_30_procedural"
        return kajima_29_in_scope(question, issue_tags)
    if not interim_relief_only(question, issue_tags):
        return True, "not_interim_relief_only"
    if _is_interim_relief_locator(title, locator):
        return True, "interim_relief_locator"
    if _is_icc_article_5_title(title, locator):
        return False, "beyond_kajima_dispute_resolution_scope_interim_relief"
    if _is_cpr_adr_case_management(title, locator):
        return False, "beyond_kajima_dispute_resolution_scope_interim_relief"
    lowered = str(title or "").casefold()
    if (
        titles_equivalent(title, OHPEN_TITLE)
        or titles_equivalent(title, CHURCHILL_TITLE)
        or "ohpen" in lowered
        or "churchill" in lowered
        or is_kajima_title(title)
    ):
        return False, "beyond_kajima_dispute_resolution_scope_interim_relief"
    return True, "not_mediation_family_authority"


def filter_attached_evidence_rows(
    evidence: Sequence[Mapping[str, Any]],
    *,
    question: str,
    issue_tags: Sequence[str],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Drop incomplete, off-issue, or out-of-scope attached locators."""

    from .ge_diagnostic_evaluator import displayed_quote, issue_relevance, passage_completeness

    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, str]] = []
    tags = tuple(str(tag) for tag in issue_tags)
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("title") or "")
        locator = str(item.get("locator") or "")
        stored = str(item.get("stored_text") or item.get("quote") or "")
        quote = str(item.get("quote") or "") or displayed_quote(stored, locator)
        allowed, reason = mediation_family_locator_allowed(title, locator, question, tags)
        if not allowed:
            dropped.append({"title": title, "locator": locator, "reason": reason})
            continue
        completeness = passage_completeness(
            title=title,
            locator=locator,
            stored_text=stored,
            displayed_quote_text=quote,
        )
        if completeness.outcome != "PASS":
            dropped.append(
                {"title": title, "locator": locator, "reason": f"completeness={completeness.outcome}"}
            )
            continue
        relevance = issue_relevance(
            question=question,
            issue_tags=tags,
            title=title,
            locator=locator,
            quote=quote,
        )
        if relevance.outcome != "PASS":
            dropped.append(
                {"title": title, "locator": locator, "reason": f"issue_relevance={relevance.outcome}"}
            )
            continue
        kept.append(dict(item))
    return kept, dropped


def _paragraph_role(locator: str) -> str:
    pin = _canonical_kajima_locator(locator)
    if pin == PARAGRAPH_29:
        return "OPERATIVE"
    if pin == PARAGRAPH_30:
        return "PROCEDURAL"
    return "CONTEXTUAL"


def _paragraph_proposition(locator: str) -> str:
    pin = _canonical_kajima_locator(locator)
    if pin == PARAGRAPH_29:
        return (
            "The first-instance court found that the contractual dispute-resolution "
            "procedure gave rise to a condition precedent, with court recourse only "
            "to the extent not finally resolved pursuant to that procedure."
        )
    if pin == PARAGRAPH_30:
        return (
            "The first-instance court found that the dispute-resolution procedure "
            "was not enforceable; that finding is Ground 1 of the appeal."
        )
    return ""


def decide_kajima_attachment(
    row: Mapping[str, Any],
    *,
    title: str,
    locator: str,
    stored_text: str,
) -> dict[str, Any]:
    case_id = str(row.get("case_id") or "")
    question = _question(row)
    tags = tuple(str(tag) for tag in row.get("issue_tags") or ())
    pin = _canonical_kajima_locator(locator)
    role = _paragraph_role(pin)
    paragraph_prop = _paragraph_proposition(pin)
    candidate_prop = f"Answer proposition for: {question[:220]}" if question else ""
    claim_id = f"{case_id}:kajima-{pin.replace(' ', '-')}"
    relevance = issue_relevance(
        question=question,
        issue_tags=tags,
        title=title,
        locator=pin,
        quote=stored_text,
    )
    completeness = passage_completeness(
        title=title,
        locator=pin,
        stored_text=stored_text,
        displayed_quote_text=stored_text,
    )
    in_scope, scope_reason = kajima_29_in_scope(question, tags)
    decision = "REFUSE"
    support = "DOES_NOT_SUPPORT"
    refuse_reason = ""
    additional = True
    if pin == PARAGRAPH_30:
        refuse_reason = (
            "procedural_history_unenforceability_appeal_ground;"
            f"completeness={completeness.outcome};issue_relevance={relevance.outcome}"
        )
    elif not in_scope:
        refuse_reason = scope_reason
    elif completeness.outcome != "PASS":
        refuse_reason = f"passage_completeness_{completeness.outcome}"
    elif relevance.outcome != "PASS":
        refuse_reason = f"issue_relevance_{relevance.outcome}"
    else:
        decision = "ATTACH"
        support = "SUPPORTS"
        additional = case_id == CASE_174
        refuse_reason = ""
    return {
        "case_id": case_id,
        "claim_id": claim_id,
        "exact_candidate_answer_proposition": candidate_prop,
        "exact_kajima_paragraph": pin,
        "proposition_expressed_by_paragraph": paragraph_prop,
        "entailment_support_decision": support,
        "paragraph_role": role,
        "additional_authority_required": additional if decision == "ATTACH" else True,
        "in_scope": in_scope,
        "scope_reason": scope_reason,
        "issue_relevance": relevance.outcome,
        "passage_completeness": completeness.outcome,
        "decision": decision,
        "refuse_reason": refuse_reason,
        "qualified_legal_review": "NOT_STARTED",
        "answer_gold": "NOT_STARTED",
        "attach_executed": False,
    }


def execute_kajima_attachments(
    *,
    route: str,
    rows: Sequence[Mapping[str, Any]] | None = None,
    decisions: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Apply accepted attachments only on the targeted mediation-family route."""

    if route != TARGETED_MEDIATION_FAMILY:
        return {
            "attach_executed": False,
            "attachment_executed": False,
            "refused_reason": OUTSIDE_TARGETED_MEDIATION_FAMILY,
            "accepted_case_ids": [],
            "rows": [],
            "decisions": list(decisions or []),
        }
    applied: list[str] = []
    for item in decisions or ():
        if item.get("decision") == "ATTACH":
            applied.append(str(item.get("case_id") or ""))
    return {
        "attach_executed": bool(applied),
        "attachment_executed": bool(applied),
        "refused_reason": "",
        "accepted_case_ids": list(dict.fromkeys(applied)),
        "rows": list(rows or []),
        "decisions": list(decisions or []),
    }


def load_kajima_locator_chunks(project_root: Path) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for pack in sidecar_packs(project_root):
        path = pack / "chunks.sqlite3"
        if not path.is_file():
            continue
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            for pin in (PARAGRAPH_29, PARAGRAPH_30):
                row = connection.execute(
                    """
                    SELECT chunk_id, source_version_id, title, locator, body, ordinal
                    FROM chunk_meta
                    WHERE lower(title) LIKE '%kajima%'
                      AND lower(locator) = ?
                    ORDER BY ordinal, chunk_id
                    """,
                    (pin,),
                ).fetchone()
                if row is None:
                    continue
                found[pin] = {
                    "chunk_id": str(row["chunk_id"]),
                    "source_version_id": str(row["source_version_id"]),
                    "title": str(row["title"] or KAJIMA_TITLE),
                    "locator": str(row["locator"] or pin),
                    "body": str(row["body"] or "").strip(),
                    "ordinal": int(row["ordinal"] or 0),
                }
        finally:
            connection.close()
        if PARAGRAPH_29 in found and PARAGRAPH_30 in found:
            break
    return found


def build_kajima_evidence_row(
    chunk: Mapping[str, Any],
    *,
    source_meta: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    from scripts.run_ge_retrieval_training_cycle import _evidence_from_row, _evidence_row

    meta = dict(source_meta or {})
    locator = _canonical_kajima_locator(str(chunk.get("locator") or ""))
    sqlite_row = {
        "chunk_id": chunk["chunk_id"],
        "source_version_id": chunk["source_version_id"],
        "title": chunk.get("title") or KAJIMA_TITLE,
        "locator": locator,
        "body": chunk["body"],
    }
    evidence = _evidence_from_row(sqlite_row, meta=meta, rank=-100.0)
    return _evidence_row(evidence)


def _is_icc_article_5(item: Mapping[str, Any]) -> bool:
    title = str(item.get("title") or "")
    locator = normalize_locator(str(item.get("locator") or ""))
    return titles_equivalent(title, ICC_TITLE) and locator == "article 5"


def _is_kajima_paragraph_1(item: Mapping[str, Any]) -> bool:
    locator = normalize_locator(str(item.get("locator") or ""))
    return is_kajima_title(str(item.get("title") or "")) and locator in {
        "paragraph 1",
        "para 1",
    }


def apply_kajima_evidence_plan(
    row: Mapping[str, Any],
    *,
    accepted_locators: Sequence[str],
    kajima_rows: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Return repaired evidence and a drop/replace log. Does not attach paragraph 30."""

    existing = [dict(item) for item in row.get("evidence") or [] if isinstance(item, dict)]
    notes: list[dict[str, str]] = []
    accepted = {_canonical_kajima_locator(item) for item in accepted_locators}
    accepted.discard(PARAGRAPH_30)

    planned = list(existing)
    if PARAGRAPH_29 in accepted:
        if str(row.get("case_id") or "") == CASE_174:
            replaced = False
            next_rows: list[dict[str, Any]] = []
            for item in planned:
                if _is_kajima_paragraph_1(item):
                    next_rows.append(dict(kajima_rows[PARAGRAPH_29]))
                    replaced = True
                    notes.append(
                        {
                            "action": "REBIND",
                            "from_locator": str(item.get("locator") or ""),
                            "to_locator": PARAGRAPH_29,
                            "reason": "replace_non_holding_paragraph_1_with_paragraph_29",
                        }
                    )
                else:
                    next_rows.append(item)
            if not replaced:
                next_rows.append(dict(kajima_rows[PARAGRAPH_29]))
                notes.append(
                    {
                        "action": "ATTACH",
                        "from_locator": "",
                        "to_locator": PARAGRAPH_29,
                        "reason": "attach_paragraph_29",
                    }
                )
            ordered: list[dict[str, Any]] = []
            kajima_29_row = None
            for item in next_rows:
                if is_kajima_title(str(item.get("title") or "")) and _canonical_kajima_locator(
                    str(item.get("locator") or "")
                ) == PARAGRAPH_29:
                    kajima_29_row = item
                else:
                    ordered.append(item)
            if kajima_29_row is not None:
                insert_at = 1 if ordered else 0
                ordered.insert(insert_at, kajima_29_row)
            planned = ordered
        else:
            next_rows = []
            question = str(row.get("question") or row.get("prompt") or "")
            tags = tuple(str(tag) for tag in row.get("issue_tags") or ())
            for item in planned:
                if _is_icc_article_5(item):
                    relevance = issue_relevance(
                        question=question,
                        issue_tags=tags,
                        title=str(item.get("title") or ""),
                        locator=str(item.get("locator") or ""),
                        quote=str(item.get("quote") or item.get("stored_text") or ""),
                    )
                    if relevance.outcome != "PASS":
                        notes.append(
                            {
                                "action": "DROP",
                                "from_locator": "article 5",
                                "to_locator": "",
                                "reason": "off_issue_icc_article_5_fails_issue_relevance",
                            }
                        )
                        continue
                next_rows.append(item)
            next_rows.append(dict(kajima_rows[PARAGRAPH_29]))
            notes.append(
                {
                    "action": "ATTACH",
                    "from_locator": "",
                    "to_locator": PARAGRAPH_29,
                    "reason": "attach_paragraph_29_condition_precedent",
                }
            )
            planned = next_rows
    return planned, notes


def rebuild_case_result(
    old: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    *,
    visible_case: Mapping[str, Any],
    overlay: Any,
    source_manifest_sha256: str,
) -> dict[str, Any]:
    from scripts.run_ge_retrieval_training_cycle import _sealed

    case = {
        **dict(visible_case),
        "case_id": old.get("case_id"),
        "question_id": old.get("case_id"),
        "topic_id": old.get("topic_id"),
        "issue_tags": list(old.get("issue_tags") or []),
        "question": old.get("question"),
        "prompt": visible_case.get("prompt") or old.get("question"),
        "planner_output": old.get("planner_output") or visible_case.get("first_response") or "",
    }
    answer = combined_answer(case, evidence_rows)
    rendered = user_facing_answer(case, evidence_rows)
    evaluation = evaluate_factual_checks(
        case=case,
        evidence_rows=evidence_rows,
        source_manifest_sha256=source_manifest_sha256,
        user_facing_answer_text=rendered,
        overlay=overlay,
    )
    failed = list(evaluation.failed)
    factual_outcome = "FACTUAL_PASS" if not failed else "FACTUAL_HOLD"
    improvement = [f"factual:{name}" for name in failed]
    quality = {
        "eligible": False,
        "score": None,
        "outcome": "NOT_ELIGIBLE" if factual_outcome != "FACTUAL_PASS" else "PENDING_QUALIFIED_REVIEW",
        "reason": (
            "Quality scoring is prohibited while a material factual check fails or case validity remains fact-dependent."
            if factual_outcome != "FACTUAL_PASS"
            else "Automated structure passed; qualified legal review is still required before a 70+ decision."
        ),
    }
    if str(old.get("case_id") or "") == CASE_174 and factual_outcome == "FACTUAL_PASS":
        raise RuntimeError("case 174 jurisdiction-scope hold must not convert to FACTUAL_PASS")
    rebuilt = dict(old)
    rebuilt.update(
        {
            "answer": answer,
            "user_facing_answer": rendered,
            "evidence": list(evidence_rows),
            "factual_result": {
                "outcome": factual_outcome,
                "checks": dict(evaluation.checks),
                "reasons": dict(evaluation.reasons),
                "diagnostic_checks": dict(evaluation.diagnostic_checks),
                "progression": dict(evaluation.progression),
                "locator_materiality": list(evaluation.locator_materiality),
            },
            "quality_70_plus": quality,
            "improvement_reasons": improvement,
            "training_eligibility": training_eligibility(lane=str(old.get("lane") or "visible")),
            "non_authorizing": {
                "qualified_legal_review": False,
                "legal_gold": False,
                "sealed_validation": False,
                "promotion": False,
                "live": False,
            },
        }
    )
    rebuilt.pop("content_sha256", None)
    sealed = _sealed(rebuilt)
    titles = " ".join(
        str(item.get("title") or "") for item in evidence_rows if isinstance(item, dict)
    ).casefold()
    if str(old.get("case_id") or "") == CASE_174:
        if "cable & wireless" in titles:
            raise RuntimeError("case 174 must not receive Cable & Wireless")
        if "arbitration act 1996" in titles:
            raise RuntimeError("case 174 must not receive Arbitration Act 1996")
        if sealed["factual_result"]["outcome"] != "FACTUAL_HOLD":
            raise RuntimeError("case 174 must remain FACTUAL_HOLD")
        if sealed["factual_result"]["checks"].get("jurisdiction_scope") != "FAIL":
            raise RuntimeError("case 174 must remain jurisdiction-scope FAIL")
    return sealed


def mediation_family_noop_row(case_id: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "result": NO_OP_UNCHANGED_CASE_INPUTS,
        "next_route": QUALIFIED_LEGAL_REVIEW_QUEUE,
        "attach_executed": False,
    }
