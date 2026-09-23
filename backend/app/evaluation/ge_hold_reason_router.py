"""Route GE FACTUAL_HOLD cases without reopening locator review."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .ge_currentness_subrouter import classify_currentness_subreason
from .ge_diagnostic_evaluator import VIDEO_WILL_TAGS
from .ge_phase2_progress import TERMINAL_HOLD

HOLD_REASON_CODES = (
    "RETRIEVAL_NO_EVIDENCE",
    "LOCATOR_EXTENT_MISMATCH",
    "CURRENTNESS_UNRESOLVED",
    "CLAIM_NOT_SUPPORTED",
    "ANSWER_OVERCLAIMS_EVIDENCE",
    "JURISDICTION_SCOPE_REVIEW",
    "FACT_DEPENDENT_OUTCOME",
    "QUALIFIED_LEGAL_REVIEW_REQUIRED",
    "OFFICIAL_SOURCE_UNAVAILABLE_FAIL_CLOSED",
    "REJECTED_AUTHORITY_NOT_REQUIRED",
)

CASE_008 = "administrative-law:cp-d08"
CASE_174 = "international-commercial-mediation:cp-d01"
CASE_312 = "wills-and-estates:cp-d02"

MECHANICAL_REPAIR = "MECHANICAL_REPAIR"
QUALIFIED_LEGAL_REVIEW_QUEUE = "QUALIFIED_LEGAL_REVIEW_QUEUE"
FACT_INPUT_OR_REVIEW_QUEUE = "FACT_INPUT_OR_REVIEW_QUEUE"
FAIL_CLOSED_QUEUE = "FAIL_CLOSED"
FROZEN_REGRESSION = "FROZEN_REGRESSION"
NO_RERUN = "NO_AUTOMATIC_RERUN"


def _failed_checks(row: Mapping[str, Any]) -> tuple[str, ...]:
    factual = row.get("factual_result")
    checks: Mapping[str, Any] = {}
    if isinstance(factual, Mapping):
        raw = factual.get("checks")
        if isinstance(raw, Mapping):
            checks = raw
    return tuple(
        name for name, outcome in checks.items() if outcome in {"FAIL", "NOT_ASSESSABLE"}
    )


def _diagnostic(row: Mapping[str, Any], name: str) -> str:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return ""
    raw = factual.get("diagnostic_checks")
    if not isinstance(raw, Mapping):
        return ""
    item = raw.get(name)
    if isinstance(item, Mapping):
        return str(item.get("outcome") or "")
    return ""


def _reason(row: Mapping[str, Any], name: str) -> str:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return ""
    reasons = factual.get("reasons")
    if isinstance(reasons, Mapping):
        return str(reasons.get(name) or "")
    return ""


def _check(row: Mapping[str, Any], name: str) -> str:
    factual = row.get("factual_result")
    if not isinstance(factual, Mapping):
        return ""
    checks = factual.get("checks")
    if isinstance(checks, Mapping):
        return str(checks.get(name) or "")
    return ""


def _tags(row: Mapping[str, Any]) -> set[str]:
    return {str(tag).casefold() for tag in row.get("issue_tags") or ()}


def _evidence_titles(row: Mapping[str, Any]) -> str:
    evidence = row.get("evidence") or []
    if not isinstance(evidence, list):
        return ""
    return " ".join(str(item.get("title") or "") for item in evidence if isinstance(item, dict)).casefold()


def dependency_hash(row: Mapping[str, Any]) -> str:
    evidence = row.get("evidence") or []
    spans: list[dict[str, str]] = []
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
        "case_version_id": str(row.get("case_version_id") or ""),
        "factual_status": str((row.get("factual_result") or {}).get("outcome") or "")
        if isinstance(row.get("factual_result"), Mapping)
        else "",
        "checks": (row.get("factual_result") or {}).get("checks")
        if isinstance(row.get("factual_result"), Mapping)
        else {},
        "spans": spans,
        "improvement_reasons": list(row.get("improvement_reasons") or []),
    }
    return hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def route_hold(row: Mapping[str, Any], *, attempt_count: int = 1) -> dict[str, Any]:
    case_id = str(row.get("case_id") or "")
    evidence = row.get("evidence") if isinstance(row.get("evidence"), list) else []
    evidence_present = bool(evidence)
    claim = _check(row, "claim_evidence_support")
    factual = ""
    if isinstance(row.get("factual_result"), Mapping):
        factual = str(row["factual_result"].get("outcome") or "")
    titles = _evidence_titles(row)
    improvement = [str(item) for item in row.get("improvement_reasons") or []]
    missing = [str(item) for item in row.get("known_missing_primary_authorities") or []]

    if case_id == CASE_174:
        code = "JURISDICTION_SCOPE_REVIEW"
        detail = (
            "Claim-support PASS on ICC article 5, Ohpen, Kajima and Churchill. "
            "Only the cross-border jurisdiction-scope issue remains. Cable & Wireless "
            "must not be restored to the mandatory route."
        )
        machine = False
        review = True
        facts = False
        terminal = TERMINAL_HOLD
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif case_id == CASE_312 or "case_validity:video_will_sequence_fact_dependent" in improvement or (
        _tags(row) & VIDEO_WILL_TAGS and claim == "PASS"
    ):
        code = "FACT_DEPENDENT_OUTCOME"
        detail = (
            "The 15 January 2024 formality bundle was retrieved. Ultimate validity "
            "depends on the signing and witnessing sequence, not on further retrieval."
        )
        machine = False
        review = True
        facts = True
        terminal = TERMINAL_HOLD
        nxt = FACT_INPUT_OR_REVIEW_QUEUE
    elif "cable & wireless" in titles:
        code = "REJECTED_AUTHORITY_NOT_REQUIRED"
        detail = "Cable & Wireless is rejected from the mandatory evidence route and is not a missing identifier."
        machine = False
        review = False
        facts = False
        terminal = TERMINAL_HOLD
        nxt = NO_RERUN
    elif any("cable" in name.casefold() for name in missing) and not evidence_present:
        code = "REJECTED_AUTHORITY_NOT_REQUIRED"
        detail = "A rejected non-mandatory authority is not a missing official identifier."
        machine = False
        review = False
        facts = False
        terminal = TERMINAL_HOLD
        nxt = NO_RERUN
    elif not evidence_present:
        code = "RETRIEVAL_NO_EVIDENCE"
        detail = _reason(row, "claim_evidence_support") or "No relevant primary-authority passage was selected."
        machine = True
        review = False
        facts = False
        terminal = "RUNNABLE"
        nxt = MECHANICAL_REPAIR
    elif _diagnostic(row, "quotation_fidelity") == "FAIL":
        code = "ANSWER_OVERCLAIMS_EVIDENCE"
        detail = _reason(row, "citation_and_quotation_identity")
        machine = True
        review = False
        facts = False
        terminal = "RUNNABLE"
        nxt = MECHANICAL_REPAIR
    elif claim != "PASS":
        if "extent" in _reason(row, "jurisdiction_scope").casefold() and _diagnostic(row, "issue_relevance") == "PASS":
            code = "LOCATOR_EXTENT_MISMATCH"
        else:
            code = "CLAIM_NOT_SUPPORTED"
        detail = _reason(row, "claim_evidence_support")
        machine = True
        review = False
        facts = False
        terminal = "RUNNABLE"
        nxt = MECHANICAL_REPAIR
    elif "cross-border" in _reason(row, "jurisdiction_scope").casefold() or "european union" in _reason(
        row, "jurisdiction_scope"
    ).casefold():
        code = "JURISDICTION_SCOPE_REVIEW"
        detail = _reason(row, "jurisdiction_scope")
        machine = False
        review = True
        facts = False
        terminal = TERMINAL_HOLD
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif _check(row, "requested_date_and_currentness") in {"FAIL", "NOT_ASSESSABLE"}:
        code = "CURRENTNESS_UNRESOLVED"
        detail = _reason(row, "requested_date_and_currentness")
        machine = False
        review = True
        facts = False
        terminal = TERMINAL_HOLD
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    elif _check(row, "jurisdiction_scope") == "FAIL":
        code = "JURISDICTION_SCOPE_REVIEW"
        detail = _reason(row, "jurisdiction_scope")
        machine = False
        review = True
        facts = False
        terminal = TERMINAL_HOLD
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE
    else:
        code = "QUALIFIED_LEGAL_REVIEW_REQUIRED"
        detail = "Mechanical evidence checks passed; remaining hold is a legal-judgment issue."
        machine = False
        review = True
        facts = False
        terminal = TERMINAL_HOLD
        nxt = QUALIFIED_LEGAL_REVIEW_QUEUE

    dep = dependency_hash(row)
    topic = str(row.get("topic_id") or "")
    family = str(row.get("scenario_family_id") or "")
    mechanical_terminal = not machine
    currentness_fields: dict[str, Any] = {}
    if code == "CURRENTNESS_UNRESOLVED":
        currentness_fields = classify_currentness_subreason(row)
    return {
        "case_id": case_id,
        "topic": topic,
        "subtopic": family,
        "evidence_present": evidence_present,
        "claim_support_status": claim or "FAIL",
        "factual_status": factual or "FACTUAL_HOLD",
        "hold_reason_code": code,
        "hold_reason_detail": detail,
        "terminal_or_runnable": terminal,
        "machine_repairable": machine,
        "mechanical_status": "RUNNABLE" if machine else "EXHAUSTED",
        "qualified_legal_review_required": review,
        "qualified_review_ready": mechanical_terminal,
        "fact_input_required": facts,
        "terminal_for_retrieval": mechanical_terminal,
        "terminal_for_mechanical_route": mechanical_terminal,
        "terminal_for_entire_pipeline": False,
        "next_route": nxt,
        "dependency_hash": dep,
        "last_attempt_hash": str(row.get("content_sha256") or dep),
        "attempt_count": attempt_count,
        "failed_checks": list(_failed_checks(row)),
        "named_case_invariant": case_id in {CASE_008, CASE_174, CASE_312},
        "automatic_reopen_cable_and_wireless": False,
        "automatic_reopen_arbitration_act_s9": False,
        "conditional_answer_potentially_approvable": code == "FACT_DEPENDENT_OUTCOME",
        **currentness_fields,
    }


def freeze_pass_case(row: Mapping[str, Any]) -> dict[str, Any]:
    dep = dependency_hash(row)
    case_id = str(row.get("case_id") or "")
    return {
        "case_id": case_id,
        "factual_status": "FACTUAL_PASS",
        "hold_reason_code": None,
        "named_case_invariant": case_id == CASE_008,
        "next_route": QUALIFIED_LEGAL_REVIEW_QUEUE,
        "machine_repairable": False,
        "mechanical_status": "FROZEN",
        "qualified_review_ready": True,
        "qualified_legal_review_required": True,
        "terminal_for_mechanical_route": True,
        "terminal_for_entire_pipeline": False,
        "dependency_hash": dep,
        "last_attempt_hash": str(row.get("content_sha256") or dep),
        "rerun_unless_dependency_changes": False,
        "frozen_regression": True,
        "locked_route_note": (
            "Equality Act 2010 ss 20, 21, 29, Schedule 2 paragraphs 1-2, and "
            "SI 2018/952 regulation 12."
            if case_id == CASE_008
            else "Freeze FACTUAL_PASS unless the dependency hash changes. Factual PASS is not answer gold."
        ),
    }


def load_targeted_repair_case_ids(path: Path) -> list[str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("targeted repair queue is not an object")
    rows = raw.get("case_ids") or raw.get("targeted_repair_case_ids") or []
    if not isinstance(rows, list):
        raise ValueError("targeted repair case_ids are invalid")
    return [str(item) for item in rows if str(item).strip()]


def route_results(
    rows: Sequence[Mapping[str, Any]],
    *,
    attempt_count: int = 1,
    attempt_counts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    holds: list[dict[str, Any]] = []
    frozen: list[dict[str, Any]] = []
    counts = attempt_counts or {}
    for row in rows:
        factual = row.get("factual_result")
        outcome = ""
        if isinstance(factual, Mapping):
            outcome = str(factual.get("outcome") or "")
        case_id = str(row.get("case_id") or "")
        attempts = int(counts.get(case_id, attempt_count))
        if outcome == "FACTUAL_PASS":
            frozen.append(freeze_pass_case(row))
            continue
        holds.append(route_hold(row, attempt_count=attempts))
    reason_counts = Counter(item["hold_reason_code"] for item in holds)
    route_counts = Counter(item["next_route"] for item in holds)
    runnable = [item["case_id"] for item in holds if item["machine_repairable"] is True]
    terminal_mechanical = [item["case_id"] for item in holds if item["terminal_for_mechanical_route"] is True]
    review_ready = [item["case_id"] for item in frozen] + [
        item["case_id"] for item in holds if item.get("qualified_review_ready") is True
    ]
    return {
        "hold_count": len(holds),
        "factual_pass_count": len(frozen),
        "holds": holds,
        "frozen_pass_cases": frozen,
        "counts_by_hold_reason_code": dict(sorted(reason_counts.items())),
        "counts_by_next_route": dict(sorted(route_counts.items())),
        "runnable_queue_count": len(runnable),
        "terminal_queue_count": len(terminal_mechanical),
        "terminal_for_mechanical_route_count": len(terminal_mechanical),
        "terminal_for_entire_pipeline_count": 0,
        "qualified_review_ready_count": len(review_ready),
        "qualified_review_ready_case_ids": review_ready,
        "runnable_case_ids": runnable,
        "terminal_case_ids": terminal_mechanical,
        "targeted_repair_case_ids": runnable,
    }
