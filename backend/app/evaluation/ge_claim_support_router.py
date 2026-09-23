"""Proposition-level routing for remaining CLAIM_NOT_SUPPORTED cases.

This does not reopen locator review, run generic topic retrieval, or mark
qualified legal review complete. Mechanical action is allowed only where a
deterministic hinted locator can be attached or an over-claim can be
constrained without a new legal route.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from .ge_diagnostic_evaluator import locator_hints_for_case
from .ge_hold_reason_router import (
    CASE_008,
    CASE_174,
    CASE_312,
    QUALIFIED_LEGAL_REVIEW_QUEUE,
    dependency_hash,
)
from .ge_kajima_mediation_family import (
    ATTACHABLE_PENDING_TARGETED_FAMILY,
    MEDIATION_TOPIC,
    PENDING_TARGETED_FAMILY,
    TARGETED_MEDIATION_FAMILY,
    is_kajima_paragraph_29_or_30,
)
from .ge_locator_gold_overlay import normalize_locator, titles_equivalent
from .ge_phase2_progress import NO_OP_UNCHANGED_CASE_INPUTS

CLAIM_FAILURE_CLASSES = (
    "EVIDENCE_SELECTION_DEFECT",
    "LOCATOR_TOO_NARROW",
    "ANSWER_OVERCLAIMS_EVIDENCE",
    "ANSWER_USES_WRONG_LEGAL_ROUTE",
    "CURRENTNESS_REVIEW_REQUIRED",
    "JURISDICTION_REVIEW_REQUIRED",
    "EVALUATOR_FALSE_NEGATIVE",
    "GENUINELY_UNSUPPORTED_PROPOSITION",
)

MECHANICAL_CLASSES = frozenset(
    {
        "EVIDENCE_SELECTION_DEFECT",
        "LOCATOR_TOO_NARROW",
        "ANSWER_OVERCLAIMS_EVIDENCE",
    }
)

GENERIC_ISSUE_TAGS = frozenset(
    {
        "urgent",
        "false-premise",
        "material-dates",
        "limitation",
        "remedies",
        "procedure",
        "jurisdiction",
        "evidence",
        "england-and-wales",
        "uk",
    }
)

_WRONG_ROUTE_LOCATORS = {
    ("equality act 2010", "section 174"),
    ("equality act 2010", "section 208"),
    ("equality act 2010", "section 210"),
    ("arbitration act 1996", "section 9"),
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def case_input_hash(row: Mapping[str, Any]) -> str:
    evidence = row.get("evidence") or []
    spans = []
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict):
                spans.append(
                    {
                        "source_version_id": str(item.get("source_version_id") or ""),
                        "chunk_id": str(item.get("chunk_id") or ""),
                        "locator": str(item.get("locator") or ""),
                        "evidence_span_sha256": str(item.get("evidence_span_sha256") or ""),
                    }
                )
    payload = {
        "case_id": str(row.get("case_id") or ""),
        "answer": str(row.get("answer") or ""),
        "user_facing_answer": str(row.get("user_facing_answer") or ""),
        "checks": (row.get("factual_result") or {}).get("checks")
        if isinstance(row.get("factual_result"), Mapping)
        else {},
        "spans": spans,
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _diagnostic(row: Mapping[str, Any], name: str) -> dict[str, str]:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return {}
    raw = factual.get("diagnostic_checks")
    if not isinstance(raw, Mapping):
        return {}
    item = raw.get(name)
    if isinstance(item, Mapping):
        return {
            "outcome": str(item.get("outcome") or ""),
            "reason": str(item.get("reason") or ""),
        }
    return {}


def _check(row: Mapping[str, Any], name: str) -> str:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return ""
    checks = factual.get("checks")
    if isinstance(checks, Mapping):
        return str(checks.get(name) or "")
    return ""


def _locator_aliases(locator: str) -> set[str]:
    text = normalize_locator(locator)
    aliases = {text}
    if text.startswith("para "):
        aliases.add("paragraph " + text[5:])
    if text.startswith("paragraph "):
        aliases.add("para " + text[10:])
    return {item for item in aliases if item}


def _locators_match(left: str, right: str) -> bool:
    return bool(_locator_aliases(left) & _locator_aliases(right))


def _issue_tags(row: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        str(tag)
        for tag in row.get("issue_tags") or ()
        if str(tag).casefold() not in GENERIC_ISSUE_TAGS
    )


def _hint_matches_evidence(
    hints: Sequence[tuple[str, str]],
    evidence: Sequence[Mapping[str, Any]],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    matched: list[tuple[str, str]] = []
    unmatched: list[tuple[str, str]] = []
    for title, locator in hints:
        hit = False
        for item in evidence:
            if titles_equivalent(title, str(item.get("title") or "")) and _locators_match(
                locator, str(item.get("locator") or "")
            ):
                hit = True
                break
        if hit:
            matched.append((title, locator))
        else:
            unmatched.append((title, locator))
    return matched, unmatched


def _wrong_route(evidence: Sequence[Mapping[str, Any]], row: Mapping[str, Any]) -> bool:
    question = str(row.get("question") or row.get("prompt") or "").casefold()
    tags = {tag.casefold() for tag in _issue_tags(row)}
    for item in evidence:
        title = str(item.get("title") or "").casefold()
        locator = normalize_locator(str(item.get("locator") or ""))
        if (title, locator) in _WRONG_ROUTE_LOCATORS:
            return True
        if "cable & wireless" in title:
            return True
        if "arbitration act" in title and locator == "section 9":
            if "mediation" in question or "icc" in question or "mediation" in " ".join(tags):
                if "arbitration" not in question and "arbitration" not in tags:
                    return True
    return False


def _required_authority_type(row: Mapping[str, Any]) -> str:
    tags = ", ".join(_issue_tags(row)) or "issue tags absent"
    return f"Primary England-and-Wales authority matching: {tags}"


def _propositions(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
    claims: list[dict[str, Any]] = []
    question = str(row.get("question") or row.get("prompt") or "")
    answer = str(row.get("user_facing_answer") or row.get("answer") or "")
    answer_span = answer[:500] if answer else question[:500]
    first = next((item for item in evidence if isinstance(item, dict)), {})
    claims.append(
        {
            "claim_id": f"{row.get('case_id')}:answer-1",
            "exact_answer_span": answer_span,
            "normalized_legal_proposition": (
                f"Answer proposition for: {question[:220]}"
                if question
                else answer_span[:240]
            ),
            "required_type_of_authority": _required_authority_type(row),
            "retrieved_locator": str(first.get("locator") or ""),
            "retrieved_title": str(first.get("title") or ""),
            "supporting_evidence_span": {
                "source_version_id": str(first.get("source_version_id") or ""),
                "chunk_id": str(first.get("chunk_id") or ""),
                "locator": str(first.get("locator") or ""),
                "quote": str(first.get("quote") or ""),
                "evidence_span_sha256": str(first.get("evidence_span_sha256") or ""),
            }
            if first
            else {},
        }
    )
    for index, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote") or "").strip()
        claims.append(
            {
                "claim_id": f"{row.get('case_id')}:evidence-{index}",
                "exact_answer_span": answer_span,
                "normalized_legal_proposition": (
                    f"The retrieved passage at {item.get('title')} {item.get('locator')} "
                    f"is offered as support for: {question[:180]}"
                ),
                "required_type_of_authority": _required_authority_type(row),
                "retrieved_locator": str(item.get("locator") or ""),
                "retrieved_title": str(item.get("title") or ""),
                "supporting_evidence_span": {
                    "source_version_id": str(item.get("source_version_id") or ""),
                    "chunk_id": str(item.get("chunk_id") or ""),
                    "locator": str(item.get("locator") or ""),
                    "quote": quote,
                    "evidence_span_sha256": str(item.get("evidence_span_sha256") or ""),
                },
            }
        )
    return claims


def classify_claim_case(
    row: Mapping[str, Any],
    *,
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
    topic_sources: Mapping[str, tuple[str, ...]] | None = None,
    attempt_count: int = 2,
    previous_input_hash: str | None = None,
) -> dict[str, Any]:
    case_id = str(row.get("case_id") or "")
    evidence = [item for item in (row.get("evidence") or []) if isinstance(item, dict)]
    tags = _issue_tags(row)
    hints = locator_hints_for_case(tags, locator_hints)
    matched, unmatched = _hint_matches_evidence(hints, evidence)
    relevance = _diagnostic(row, "issue_relevance")
    completeness = _diagnostic(row, "passage_completeness")
    fidelity = _diagnostic(row, "quotation_fidelity")
    currentness = _check(row, "requested_date_and_currentness")
    jurisdiction = _check(row, "jurisdiction_scope")
    current_hash = case_input_hash(row)
    unchanged = bool(previous_input_hash) and previous_input_hash == current_hash

    if case_id in {CASE_008, CASE_174, CASE_312}:
        code = (
            "JURISDICTION_REVIEW_REQUIRED"
            if case_id == CASE_174
            else "GENUINELY_UNSUPPORTED_PROPOSITION"
            if case_id == CASE_312
            else "EVALUATOR_FALSE_NEGATIVE"
        )
        mechanical = False
        action = "NO_MECHANICAL_RERUN"
        review_action = "INCLUDE_IN_QUALIFIED_REVIEW_PACKET"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif _wrong_route(evidence, row):
        code = "ANSWER_USES_WRONG_LEGAL_ROUTE"
        mechanical = False
        action = "NO_GENERIC_RETRIEVAL"
        review_action = "SUBSTANTIVE_ROUTE_REVIEW"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif fidelity.get("outcome") == "FAIL":
        code = "ANSWER_OVERCLAIMS_EVIDENCE"
        mechanical = True
        action = "CONSTRAIN_CANDIDATE_ANSWER"
        review_action = "REVIEW_CONSTRAINED_PATCH_NOT_GOLD"
        status = "RUNNABLE"
        nxt = "CLAIM_LEVEL_MECHANICAL_REPAIR"
    elif completeness.get("outcome") == "FAIL":
        code = "LOCATOR_TOO_NARROW"
        mechanical = True
        action = "ASSEMBLE_OR_WIDEN_OPERATIVE_LOCATOR"
        review_action = "NONE_UNLESS_ASSEMBLY_FAILS"
        status = "RUNNABLE"
        nxt = "CLAIM_LEVEL_MECHANICAL_REPAIR"
    elif unmatched and hints:
        if topic_sources is None:
            attachable = list(unmatched)
        else:
            allowed = tuple(topic_sources.get(str(row.get("topic_id") or ""), ()))
            attachable = [
                (title, locator)
                for title, locator in unmatched
                if any(titles_equivalent(title, name) or title == name for name in allowed)
            ]
        if attachable:
            unmatched = attachable
            code = "EVIDENCE_SELECTION_DEFECT"
            mechanical = True
            action = "ATTACH_HINTED_LOCATOR"
            review_action = "NONE_UNLESS_ATTACH_FAILS"
            status = "RUNNABLE"
            nxt = "CLAIM_LEVEL_MECHANICAL_REPAIR"
        else:
            code = "ANSWER_USES_WRONG_LEGAL_ROUTE"
            mechanical = False
            action = "NO_DETERMINISTIC_ON_TOPIC_LOCATOR"
            review_action = "SUBSTANTIVE_ROUTE_REVIEW"
            status = "EXHAUSTED"
            nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif matched and relevance.get("outcome") == "FAIL":
        code = "EVALUATOR_FALSE_NEGATIVE"
        mechanical = False
        action = "NO_GENERIC_RETRIEVAL"
        review_action = "ASSESS_WHETHER_HINTED_LOCATOR_SUPPORTS_THE_ISSUE"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif relevance.get("outcome") == "FAIL":
        code = "GENUINELY_UNSUPPORTED_PROPOSITION"
        mechanical = False
        action = "NO_DETERMINISTIC_LOCATOR"
        review_action = "SELECT_OR_REJECT_THE_PROPOSITION"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif currentness in {"FAIL", "NOT_ASSESSABLE"}:
        code = "CURRENTNESS_REVIEW_REQUIRED"
        mechanical = False
        action = "NO_GENERIC_RETRIEVAL"
        review_action = "CURRENTNESS_PACKET"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif jurisdiction == "FAIL":
        code = "JURISDICTION_REVIEW_REQUIRED"
        mechanical = False
        action = "NO_GENERIC_RETRIEVAL"
        review_action = "JURISDICTION_PACKET"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    else:
        code = "GENUINELY_UNSUPPORTED_PROPOSITION"
        mechanical = False
        action = "NO_GENERIC_RETRIEVAL"
        review_action = "QUALIFIED_REVIEW"
        status = "EXHAUSTED"
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE

    if unchanged and status == "RUNNABLE":
        status = "EXHAUSTED"
        mechanical = False
        action = NO_OP_UNCHANGED_CASE_INPUTS
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
        review_action = "UNCHANGED_INPUTS_MOVE_TO_QUALIFIED_REVIEW"

    if code not in MECHANICAL_CLASSES:
        mechanical = False
        if status == "RUNNABLE":
            status = "EXHAUSTED"
            nxt = QUALIFIED_LEGAL_REVIEW_QUEUE

    attachable_hints = (
        [{"title": title, "locator": locator} for title, locator in unmatched]
        if action == "ATTACH_HINTED_LOCATOR"
        else []
    )
    locator_candidate_status = "NOT_ATTACHABLE"
    mechanical_execution_status = "NOT_QUEUED"
    attach_executed = False
    case_status = status
    if action == "ATTACH_HINTED_LOCATOR" and mechanical:
        locator_candidate_status = "ATTACHABLE"
        kajima_family = str(row.get("topic_id") or "") == MEDIATION_TOPIC and any(
            is_kajima_paragraph_29_or_30(str(item["title"]), str(item["locator"]))
            for item in attachable_hints
        )
        if kajima_family:
            nxt = TARGETED_MEDIATION_FAMILY
            mechanical_execution_status = PENDING_TARGETED_FAMILY
            case_status = ATTACHABLE_PENDING_TARGETED_FAMILY
        else:
            mechanical_execution_status = "PENDING_CLAIM_LEVEL_REPAIR"

    secondary: list[str] = []
    if currentness in {"FAIL", "NOT_ASSESSABLE"} and code != "CURRENTNESS_REVIEW_REQUIRED":
        secondary.append("CURRENTNESS_REVIEW_REQUIRED")
    if jurisdiction == "FAIL" and code != "JURISDICTION_REVIEW_REQUIRED":
        secondary.append("JURISDICTION_REVIEW_REQUIRED")

    propositions = _propositions(row)
    for item in propositions:
        item["entailment_support_result"] = "FAIL"
        item["failure_reason"] = (
            relevance.get("reason")
            or completeness.get("reason")
            or fidelity.get("reason")
            or "The selected passage does not support the proposition."
        )
        item["failure_class"] = code

    candidate_patch = ""
    if code == "ANSWER_OVERCLAIMS_EVIDENCE":
        quotes = [str(item.get("quote") or "") for item in evidence if item.get("quote")]
        candidate_patch = (
            "Constrained candidate (not gold): repeat only the bound quotations below and "
            "state that they have not been shown to be the complete controlling law. "
            + " ".join(f"“{quote}”" for quote in quotes[:2])
        )

    return {
        "case_id": case_id,
        "topic": str(row.get("topic_id") or ""),
        "subtopic": str(row.get("scenario_family_id") or ""),
        "issue_tags": list(tags),
        "factual_status": str((row.get("factual_result") or {}).get("outcome") or "")
        if isinstance(row.get("factual_result"), Mapping)
        else "",
        "claim_support_status": _check(row, "claim_evidence_support") or "FAIL",
        "failure_class": code,
        "secondary_classes": secondary,
        "machine_repairable": mechanical,
        "mechanical_status": status,
        "terminal_for_mechanical_route": not mechanical,
        "terminal_for_entire_pipeline": False,
        "qualified_review_ready": not mechanical,
        "proposed_mechanical_action": action,
        "proposed_legal_review_action": review_action,
        "next_route": nxt,
        "locator_candidate_status": locator_candidate_status,
        "mechanical_execution_status": mechanical_execution_status,
        "attach_executed": attach_executed,
        "qualified_legal_review": "NOT_STARTED",
        "answer_gold": "NOT_STARTED",
        "case_status": case_status,
        "attachable_hints": attachable_hints,
        "matched_hints": [{"title": title, "locator": locator} for title, locator in matched],
        "candidate_constrained_answer": candidate_patch,
        "candidate_is_not_answer_gold": True,
        "propositions": propositions,
        "dependency_hash": dependency_hash(row),
        "case_input_hash": current_hash,
        "last_attempt_hash": str(row.get("content_sha256") or current_hash),
        "attempt_count": attempt_count,
        "unchanged_inputs": unchanged,
        "no_generic_retrieval": True,
        "automatic_reopen_cable_and_wireless": False,
        "automatic_reopen_arbitration_act_s9": False,
        "named_case_invariant": case_id in {CASE_008, CASE_174, CASE_312},
    }


def route_claim_cases(
    rows: Sequence[Mapping[str, Any]],
    *,
    locator_hints: Mapping[str, tuple[tuple[str, str], ...]],
    topic_sources: Mapping[str, tuple[str, ...]] | None = None,
    previous_hashes: Mapping[str, str] | None = None,
    attempt_count: int = 2,
) -> dict[str, Any]:
    prior = previous_hashes or {}
    classified = [
        classify_claim_case(
            row,
            locator_hints=locator_hints,
            topic_sources=topic_sources,
            attempt_count=attempt_count,
            previous_input_hash=prior.get(str(row.get("case_id") or "")),
        )
        for row in rows
    ]
    mechanical = [item for item in classified if item["machine_repairable"] is True]
    exhausted = [item for item in classified if item["machine_repairable"] is not True]
    repaired = [
        item["case_id"]
        for item in classified
        if item["proposed_mechanical_action"] in {"ATTACH_HINTED_LOCATOR", "CONSTRAIN_CANDIDATE_ANSWER"}
        and item["mechanical_status"] == "RUNNABLE"
    ]
    runnable_ids = [item["case_id"] for item in mechanical]
    return {
        "schema": "legalbot.ge-claim-level-support-manifest.v1",
        "case_count": len(classified),
        "rows": classified,
        "counts_by_failure_class": dict(sorted(Counter(item["failure_class"] for item in classified).items())),
        "mechanically_repaired_case_ids": repaired,
        "moved_to_qualified_review_case_ids": [item["case_id"] for item in exhausted],
        "remaining_changed_input_runnable_count": len(mechanical),
        "runnable_case_ids": runnable_ids,
        "case_status": {item["case_id"]: item["case_status"] for item in classified},
        "attachment_executed": False,
        "attach_executed": False,
        "factual_status_unchanged": True,
        "claim_support_status_unchanged": True,
        "frozen_baseline_unchanged": True,
        "exhausted_case_ids": [item["case_id"] for item in exhausted],
        "no_generic_retrieval": True,
    }
