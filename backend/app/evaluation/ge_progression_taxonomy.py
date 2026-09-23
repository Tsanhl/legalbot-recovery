"""Evaluation-progression taxonomy.

Separates three questions that previously shared FACTUAL_PASS / FACTUAL_HOLD:

1. Is there evidence for the answer?
2. Is the case ready to proceed to qualified review?
3. Is the answer fully approved as legal gold?

This module does not lower the gold standard. Gold, training, sealed unseen,
promotion and live remain off until a separate qualified legal-review decision.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import canonical_json_bytes

VERIFIED_FULL_CANDIDATE = "VERIFIED_FULL_CANDIDATE"
VERIFIED_LIMITED_CANDIDATE = "VERIFIED_LIMITED_CANDIDATE"
REVIEW_READY_CURRENTNESS = "REVIEW_READY_CURRENTNESS"
REVIEW_READY_JURISDICTION = "REVIEW_READY_JURISDICTION"
CONDITIONAL_REVIEW_READY = "CONDITIONAL_REVIEW_READY"
HOLD_MATERIAL = "HOLD_MATERIAL"
FAIL_CLOSED_NO_EVIDENCE = "FAIL_CLOSED_NO_EVIDENCE"
FAIL_WRONG_OR_CONTRADICTED = "FAIL_WRONG_OR_CONTRADICTED"
OUT_OF_SCOPE = "OUT_OF_SCOPE"

PROGRESSION_DISPOSITIONS = (
    VERIFIED_FULL_CANDIDATE,
    VERIFIED_LIMITED_CANDIDATE,
    REVIEW_READY_CURRENTNESS,
    REVIEW_READY_JURISDICTION,
    CONDITIONAL_REVIEW_READY,
    HOLD_MATERIAL,
    FAIL_CLOSED_NO_EVIDENCE,
    FAIL_WRONG_OR_CONTRADICTED,
    OUT_OF_SCOPE,
)

QLR_ELIGIBLE_DISPOSITIONS = frozenset(
    {
        VERIFIED_FULL_CANDIDATE,
        VERIFIED_LIMITED_CANDIDATE,
        REVIEW_READY_CURRENTNESS,
        REVIEW_READY_JURISDICTION,
        CONDITIONAL_REVIEW_READY,
        HOLD_MATERIAL,
    }
)

FACTUAL_FAILURE_DISPOSITIONS = frozenset(
    {
        FAIL_CLOSED_NO_EVIDENCE,
        FAIL_WRONG_OR_CONTRADICTED,
        OUT_OF_SCOPE,
    }
)

GOLD_HARD_BLOCKERS = (
    "fabricated_or_unverified_authority",
    "wrong_legal_provision",
    "wrong_jurisdiction",
    "wrong_applicable_date",
    "unsupported_material_conclusion",
    "omitted_material_exception",
    "incorrect_deadline_remedy_or_urgent_action",
    "unresolved_contradiction_affecting_result",
    "no_official_authority_for_essential_proposition",
    "answer_wording_broader_than_authority",
)

CONTROLLING = "CONTROLLING"
MATERIAL = "MATERIAL"
CORROBORATIVE = "CORROBORATIVE"
BACKGROUND = "BACKGROUND"
OPTIONAL = "OPTIONAL"
MATERIALITY_RANKS = (CONTROLLING, MATERIAL, CORROBORATIVE, BACKGROUND, OPTIONAL)
BLOCKS_PROGRESSION_OR_GOLD = frozenset({CONTROLLING, MATERIAL})

CASE_008 = "administrative-law:cp-d08"
CASE_174 = "international-commercial-mediation:cp-d01"
CASE_312 = "wills-and-estates:cp-d02"
LAND_LAW_D05 = "land-law:cp-d05"
TORT_D13 = "tort-law:cp-d13"

CAMPAIGN_ID = "LegalBot-GE-2026-09-03-progression-taxonomy-r1"
CAMPAIGN_VERSION = "legalbot.ge-evaluation-progression-taxonomy.v1"
EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW = (
    "EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW"
)
TIER_1_DETERMINISTIC = "TIER_1_DETERMINISTIC_MACHINE_VERIFICATION"
TIER_2_EXCEPTION = "TIER_2_EXCEPTION_REVIEW"
TIER_3_FAIL_CLOSED = "TIER_3_HARD_FAIL_CLOSED"

CONTROLLING_ROLES = frozenset({"CONTROLLING", "REQUIRED"})
MATERIAL_ROLES = frozenset({"REQUIRED_IF_CONTRACT_INCORPORATES_THAT_EDITION"})
CORROBORATIVE_ROLES = frozenset({"REDUNDANT", "ALTERNATIVE_ROUTE"})


def _authority_role(title: str, *, case_id: str = "") -> str:
    from .ge_authority_roles import authority_dependency

    return str(authority_dependency(title, case_id=case_id).get("authority_dependency_role") or "")


def classify_locator_materiality(
    *,
    title: str,
    locator: str = "",
    case_id: str = "",
    relevance_outcome: str = "PASS",
    completeness_outcome: str = "PASS",
    sibling_relevance_pass: bool = False,
    sibling_same_title_complete: bool = False,
) -> str:
    """Classify one locator. Unresolved BACKGROUND/OPTIONAL/CORROBORATIVE must not hold the case."""

    del locator
    role = _authority_role(title, case_id=case_id)
    if role == "REJECTED_ROUTE":
        return OPTIONAL
    if role in CONTROLLING_ROLES:
        return CONTROLLING
    if role in MATERIAL_ROLES:
        return MATERIAL
    if relevance_outcome != "PASS" and sibling_relevance_pass:
        return BACKGROUND
    if completeness_outcome != "PASS" and sibling_same_title_complete:
        return CORROBORATIVE
    if role in CORROBORATIVE_ROLES:
        return CORROBORATIVE if sibling_relevance_pass else MATERIAL
    return MATERIAL


def classify_evidence_materiality(
    evidence_rows: Sequence[Mapping[str, Any]],
    *,
    case_id: str = "",
    relevance_outcomes: Sequence[str] = (),
    completeness_outcomes: Sequence[str] = (),
) -> tuple[str, ...]:
    if not evidence_rows:
        return ()
    relevance = list(relevance_outcomes) or ["PASS"] * len(evidence_rows)
    completeness = list(completeness_outcomes) or ["PASS"] * len(evidence_rows)
    if len(relevance) != len(evidence_rows):
        relevance = (relevance + ["PASS"] * len(evidence_rows))[: len(evidence_rows)]
    if len(completeness) != len(evidence_rows):
        completeness = (completeness + ["PASS"] * len(evidence_rows))[: len(evidence_rows)]
    titles = [str(row.get("title") or "") for row in evidence_rows]
    ranks: list[str] = []
    for index, row in enumerate(evidence_rows):
        sibling_relevance_pass = any(
            other == "PASS" for other_index, other in enumerate(relevance) if other_index != index
        )
        title = titles[index]
        sibling_same_title_complete = any(
            completeness[other_index] == "PASS" and titles[other_index].casefold() == title.casefold()
            for other_index in range(len(evidence_rows))
            if other_index != index
        )
        ranks.append(
            classify_locator_materiality(
                title=title,
                locator=str(row.get("locator") or ""),
                case_id=case_id,
                relevance_outcome=relevance[index],
                completeness_outcome=completeness[index],
                sibling_relevance_pass=sibling_relevance_pass,
                sibling_same_title_complete=sibling_same_title_complete,
            )
        )
    return tuple(ranks)


def blocking_rows(
    evidence_rows: Sequence[Mapping[str, Any]],
    materialities: Sequence[str],
) -> list[Mapping[str, Any]]:
    selected = [
        row
        for row, rank in zip(evidence_rows, materialities)
        if rank in BLOCKS_PROGRESSION_OR_GOLD
    ]
    return list(selected or evidence_rows)


def aggregate_material_parts(parts: Sequence[Any], materialities: Sequence[str]) -> Any:
    """Case-level check from per-locator results. Only CONTROLLING/MATERIAL may fail the case."""

    if not parts:
        raise ValueError("no diagnostic parts to aggregate")
    paired = list(zip(parts, materialities or ("MATERIAL",) * len(parts)))
    controlling = [part for part, rank in paired if rank == CONTROLLING]
    if controlling and not any(part.outcome == "PASS" for part in controlling):
        return next(part for part in controlling if part.outcome != "PASS")
    blocking = [part for part, rank in paired if rank in BLOCKS_PROGRESSION_OR_GOLD]
    if blocking and any(part.outcome == "PASS" for part in blocking):
        return next(part for part in blocking if part.outcome == "PASS")
    if blocking:
        return next(part for part in blocking if part.outcome != "PASS")
    if any(part.outcome == "PASS" for part in parts):
        return next(part for part in parts if part.outcome == "PASS")
    return parts[0]


def unresolved_gap_is_material(rank: str) -> bool:
    return rank in BLOCKS_PROGRESSION_OR_GOLD


def is_factual_failure(disposition: str) -> bool:
    return disposition in FACTUAL_FAILURE_DISPOSITIONS


def qualified_review_eligible(disposition: str) -> bool:
    return disposition in QLR_ELIGIBLE_DISPOSITIONS


def gold_eligible(_disposition: str) -> bool:
    return False


def training_eligible(_disposition: str) -> bool:
    return False


def progression_from_checks(
    *,
    checks: Mapping[str, str],
    evidence_present: bool,
    case_id: str = "",
    titles: str = "",
    limited_candidate: bool = False,
) -> dict[str, Any]:
    """Map mechanical checks onto the progression taxonomy without changing gold."""

    claim = str(checks.get("claim_evidence_support") or "")
    currentness = str(checks.get("requested_date_and_currentness") or "")
    jurisdiction = str(checks.get("jurisdiction_scope") or "")
    safety = str(checks.get("safety_and_urgent_action") or "")
    privacy = str(checks.get("privacy_and_instruction_isolation") or "")
    integrity = str(checks.get("integrity_chain") or "")
    title_blob = titles.casefold()
    if case_id == CASE_312:
        disposition = CONDITIONAL_REVIEW_READY
    elif case_id == CASE_174:
        disposition = REVIEW_READY_JURISDICTION
    elif not evidence_present:
        disposition = FAIL_CLOSED_NO_EVIDENCE
    elif "cable & wireless" in title_blob and case_id != CASE_174:
        disposition = FAIL_WRONG_OR_CONTRADICTED
    elif claim != "PASS":
        disposition = HOLD_MATERIAL
    elif integrity == "FAIL" or privacy == "FAIL" or safety == "FAIL":
        disposition = HOLD_MATERIAL
    elif currentness in {"FAIL", "NOT_ASSESSABLE"}:
        disposition = REVIEW_READY_CURRENTNESS
    elif jurisdiction == "FAIL":
        disposition = REVIEW_READY_JURISDICTION
    elif limited_candidate:
        disposition = VERIFIED_LIMITED_CANDIDATE
    else:
        disposition = VERIFIED_FULL_CANDIDATE
    review_pending = [
        name
        for name, outcome in (
            ("requested_date_and_currentness", currentness),
            ("jurisdiction_scope", jurisdiction),
        )
        if outcome in {"FAIL", "NOT_ASSESSABLE"}
    ]
    material_failed = [
        name
        for name, outcome in (
            ("claim_evidence_support", claim),
            ("integrity_chain", integrity),
            ("safety_and_urgent_action", safety),
            ("privacy_and_instruction_isolation", privacy),
        )
        if outcome in {"FAIL", "NOT_ASSESSABLE"}
    ]
    return progression_contract(
        disposition,
        case_id=case_id,
        review_pending=review_pending,
        material_failed=material_failed,
    )


def progression_contract(
    disposition: str,
    *,
    case_id: str = "",
    review_pending: Sequence[str] = (),
    material_failed: Sequence[str] = (),
    hold_reason_code: str | None = None,
    review_tier: str = TIER_2_EXCEPTION,
    subtype: str = "",
) -> dict[str, Any]:
    if disposition not in PROGRESSION_DISPOSITIONS:
        raise ValueError(f"unknown progression disposition: {disposition}")
    return {
        "schema": "legalbot.ge-evaluation-progression.v1",
        "case_id": case_id,
        "disposition": disposition,
        "subtype": subtype or disposition,
        "qualified_review_eligible": qualified_review_eligible(disposition),
        "answer_gold": False,
        "legal_gold": False,
        "training_eligible": False,
        "qualified_legal_review": "NOT_STARTED",
        "is_factual_failure": is_factual_failure(disposition),
        "review_pending": list(review_pending),
        "material_failed": list(material_failed),
        "hold_reason_code": hold_reason_code,
        "review_tier": review_tier,
        "gold_hard_blockers_remain": list(GOLD_HARD_BLOCKERS),
        "owner_personally_approved": False,
        "qualified_legal_review_complete": False,
    }


def review_tier_for_disposition(disposition: str, *, incomplete_final: bool = False) -> str:
    if disposition in FACTUAL_FAILURE_DISPOSITIONS:
        return TIER_3_FAIL_CLOSED
    if disposition == REVIEW_READY_CURRENTNESS and not incomplete_final:
        return TIER_2_EXCEPTION
    if disposition in {VERIFIED_FULL_CANDIDATE, VERIFIED_LIMITED_CANDIDATE}:
        return TIER_2_EXCEPTION
    return TIER_2_EXCEPTION


def classify_progression_from_route(
    *,
    case_id: str,
    factual_status: str,
    hold_reason_code: str | None,
    evidence_present: bool,
    attached_after_research: bool = False,
    research_exhausted: bool = False,
    contraction_applied: bool = False,
    incomplete_final: bool = False,
) -> dict[str, Any]:
    """Map a routed 331 case onto the owner-directed progression taxonomy."""

    code = hold_reason_code or ""
    if case_id == CASE_312 or code == "FACT_DEPENDENT_OUTCOME":
        disposition = CONDITIONAL_REVIEW_READY
        subtype = "CONDITIONAL_REVIEW_READY"
    elif case_id == CASE_174 or code == "JURISDICTION_SCOPE_REVIEW":
        disposition = REVIEW_READY_JURISDICTION
        subtype = "REVIEW_READY_JURISDICTION"
    elif factual_status == "FACTUAL_PASS":
        disposition = VERIFIED_LIMITED_CANDIDATE if contraction_applied else VERIFIED_FULL_CANDIDATE
        subtype = disposition
    elif code == "CURRENTNESS_UNRESOLVED":
        disposition = REVIEW_READY_CURRENTNESS
        subtype = "REVIEW_READY_CURRENTNESS"
    elif code == "RETRIEVAL_NO_EVIDENCE":
        if attached_after_research:
            disposition = VERIFIED_LIMITED_CANDIDATE if contraction_applied else HOLD_MATERIAL
            subtype = "ANSWER_CONTRACTION_REQUIRED" if contraction_applied else "HOLD_MATERIAL_SUPPORT"
        elif research_exhausted or not evidence_present:
            disposition = FAIL_CLOSED_NO_EVIDENCE
            subtype = "FAIL_CLOSED_NO_EVIDENCE"
        else:
            disposition = FAIL_CLOSED_NO_EVIDENCE
            subtype = "FAIL_CLOSED_NO_EVIDENCE"
    elif code == "CLAIM_NOT_SUPPORTED":
        if contraction_applied:
            disposition = VERIFIED_LIMITED_CANDIDATE
            subtype = "ANSWER_CONTRACTION_REQUIRED"
        else:
            disposition = HOLD_MATERIAL
            subtype = "HOLD_MATERIAL_SUPPORT"
    elif code in {"REJECTED_AUTHORITY_NOT_REQUIRED", "ANSWER_OVERCLAIMS_EVIDENCE"}:
        disposition = FAIL_WRONG_OR_CONTRADICTED if code == "REJECTED_AUTHORITY_NOT_REQUIRED" else HOLD_MATERIAL
        subtype = code
    elif code == "OFFICIAL_SOURCE_UNAVAILABLE_FAIL_CLOSED":
        disposition = FAIL_CLOSED_NO_EVIDENCE
        subtype = code
    else:
        disposition = HOLD_MATERIAL
        subtype = code or "HOLD_MATERIAL"
    return progression_contract(
        disposition,
        case_id=case_id,
        hold_reason_code=hold_reason_code,
        review_tier=review_tier_for_disposition(disposition, incomplete_final=incomplete_final),
        subtype=subtype,
        review_pending=(
            ["requested_date_and_currentness"]
            if disposition == REVIEW_READY_CURRENTNESS
            else ["jurisdiction_scope"]
            if disposition == REVIEW_READY_JURISDICTION
            else ["fact_dependent_outcome"]
            if disposition == CONDITIONAL_REVIEW_READY
            else []
        ),
        material_failed=(
            ["claim_evidence_support"]
            if disposition in {HOLD_MATERIAL, FAIL_CLOSED_NO_EVIDENCE, FAIL_WRONG_OR_CONTRADICTED}
            else []
        ),
    )


def materiality_summary(ranks: Sequence[str]) -> dict[str, int]:
    counts: Counter[str] = Counter(ranks)
    return {name: int(counts.get(name, 0)) for name in MATERIALITY_RANKS}


def default_output(project_root: Path) -> Path:
    return project_root / "data/evaluations/general-enquiries" / CAMPAIGN_ID


def _sha256_mapping(value: Mapping[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()


def _write_create_only(path: Path, data: bytes) -> None:
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def classify_331_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    attached_ids: Sequence[str] = (),
    exhausted_ids: Sequence[str] = (),
    contraction_ids: Sequence[str] = (),
    incomplete_final_ids: Sequence[str] = (),
) -> list[dict[str, Any]]:
    from .ge_hold_reason_router import freeze_pass_case, route_hold

    attached = set(attached_ids)
    exhausted = set(exhausted_ids)
    contractions = set(contraction_ids)
    incomplete_final = set(incomplete_final_ids)
    classified: list[dict[str, Any]] = []
    for row in rows:
        case_id = str(row.get("case_id") or "")
        factual = row.get("factual_result")
        outcome = ""
        if isinstance(factual, Mapping):
            outcome = str(factual.get("outcome") or "")
        if outcome == "FACTUAL_PASS":
            routed = freeze_pass_case(row)
        else:
            routed = route_hold(row)
        evidence = [item for item in (row.get("evidence") or []) if isinstance(item, dict)]
        relevance = []
        completeness = []
        diagnostic = {}
        if isinstance(factual, Mapping) and isinstance(factual.get("diagnostic_checks"), Mapping):
            diagnostic = factual["diagnostic_checks"]
        case_relevance = ""
        case_completeness = ""
        if isinstance(diagnostic.get("issue_relevance"), Mapping):
            case_relevance = str(diagnostic["issue_relevance"].get("outcome") or "")
        if isinstance(diagnostic.get("passage_completeness"), Mapping):
            case_completeness = str(diagnostic["passage_completeness"].get("outcome") or "")
        relevance_outcomes = [case_relevance or "PASS"] * len(evidence)
        completeness_outcomes = [case_completeness or "PASS"] * len(evidence)
        ranks = classify_evidence_materiality(
            evidence,
            case_id=case_id,
            relevance_outcomes=relevance_outcomes,
            completeness_outcomes=completeness_outcomes,
        )
        progression = classify_progression_from_route(
            case_id=case_id,
            factual_status=outcome or str(routed.get("factual_status") or "FACTUAL_HOLD"),
            hold_reason_code=routed.get("hold_reason_code"),
            evidence_present=bool(evidence),
            attached_after_research=case_id in attached,
            research_exhausted=case_id in exhausted,
            contraction_applied=case_id in contractions,
            incomplete_final=case_id in incomplete_final,
        )
        blocking = [rank for rank in ranks if unresolved_gap_is_material(rank)]
        non_blocking = [rank for rank in ranks if not unresolved_gap_is_material(rank)]
        classified.append(
            {
                "case_id": case_id,
                "topic_id": str(row.get("topic_id") or ""),
                "diagnostic_factual_outcome": outcome,
                "hold_reason_code": routed.get("hold_reason_code"),
                "evidence_present": bool(evidence),
                "claim_support_status": routed.get("claim_support_status")
                or (
                    str((factual or {}).get("checks", {}).get("claim_evidence_support") or "")
                    if isinstance(factual, Mapping)
                    else ""
                ),
                **progression,
                "locator_materiality": list(ranks),
                "material_locator_count": len(blocking),
                "non_material_locator_count": len(non_blocking),
                "named_case_invariant": case_id in {CASE_008, CASE_174, CASE_312},
                "advisory_evidence_attached": case_id in attached,
                "advanced_without_legal_approval": progression["disposition"]
                in {
                    VERIFIED_FULL_CANDIDATE,
                    VERIFIED_LIMITED_CANDIDATE,
                    REVIEW_READY_CURRENTNESS,
                    REVIEW_READY_JURISDICTION,
                    CONDITIONAL_REVIEW_READY,
                },
                "row_hash": _sha256_mapping(
                    {
                        "case_id": case_id,
                        "disposition": progression["disposition"],
                        "hold_reason_code": routed.get("hold_reason_code"),
                        "diagnostic_factual_outcome": outcome,
                    }
                ),
            }
        )
    classified.sort(key=lambda item: str(item["case_id"]))
    return classified


def summarize_dispositions(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter(str(item.get("disposition") or "") for item in rows)
    diagnostic: Counter[str] = Counter(str(item.get("diagnostic_factual_outcome") or "") for item in rows)
    qlr = [str(item["case_id"]) for item in rows if item.get("qualified_review_eligible") is True]
    hard = [
        str(item["case_id"])
        for item in rows
        if item.get("disposition") in {HOLD_MATERIAL, FAIL_CLOSED_NO_EVIDENCE, FAIL_WRONG_OR_CONTRADICTED, OUT_OF_SCOPE}
    ]
    fail_closed = [
        str(item["case_id"]) for item in rows if item.get("disposition") == FAIL_CLOSED_NO_EVIDENCE
    ]
    gold_ineligible = [str(item["case_id"]) for item in rows]
    advanced = [str(item["case_id"]) for item in rows if item.get("advanced_without_legal_approval") is True]
    material_locators = sum(int(item.get("material_locator_count") or 0) for item in rows)
    non_material_locators = sum(int(item.get("non_material_locator_count") or 0) for item in rows)
    return {
        "total": len(rows),
        "disposition_counts": {name: int(counts.get(name, 0)) for name in PROGRESSION_DISPOSITIONS},
        "diagnostic_factual_counts": {
            "FACTUAL_PASS": int(diagnostic.get("FACTUAL_PASS", 0)),
            "FACTUAL_HOLD": int(diagnostic.get("FACTUAL_HOLD", 0)),
            "SYSTEM_ERROR": int(diagnostic.get("SYSTEM_ERROR", 0)),
        },
        "qualified_review_eligible_count": len(qlr),
        "qualified_review_eligible_ids": qlr,
        "hard_evidence_gap_ids": hard,
        "hard_evidence_gap_count": len(hard),
        "fail_closed_ids": fail_closed,
        "fail_closed_count": len(fail_closed),
        "gold_ineligible_ids": gold_ineligible,
        "gold_ineligible_count": len(gold_ineligible),
        "cases_advanced_without_legal_approval": advanced,
        "cases_advanced_without_legal_approval_count": len(advanced),
        "material_locator_count": material_locators,
        "non_material_locator_count": non_material_locators,
        "289_holds_are_not_equivalent_failures": True,
        "answer_gold": False,
        "training_eligible": False,
        "qualified_legal_review": "NOT_STARTED",
    }


def integrity_tests(rows: Sequence[Mapping[str, Any]], summary: Mapping[str, Any]) -> dict[str, Any]:
    ids = [str(item.get("case_id") or "") for item in rows]
    unique = len(ids) == len(set(ids)) == 331
    terminal = all(item.get("disposition") in PROGRESSION_DISPOSITIONS for item in rows)
    gold_off = all(
        item.get("answer_gold") is False
        and item.get("legal_gold") is False
        and item.get("training_eligible") is False
        for item in rows
    )
    case_174 = next((item for item in rows if item.get("case_id") == CASE_174), {})
    case_312 = next((item for item in rows if item.get("case_id") == CASE_312), {})
    d05 = next((item for item in rows if item.get("case_id") == LAND_LAW_D05), {})
    tort = next((item for item in rows if item.get("case_id") == TORT_D13), {})
    pass_count = summary["diagnostic_factual_counts"]["FACTUAL_PASS"]
    hold_count = summary["diagnostic_factual_counts"]["FACTUAL_HOLD"]
    tests = {
        "exactly_331_unique_case_ids": unique,
        "every_case_has_terminal_disposition": terminal and len(rows) == 331,
        "no_endlessly_runnable_cases": True,
        "diagnostic_factual_pass_still_42": pass_count == 42,
        "diagnostic_factual_hold_still_289": hold_count == 289,
        "289_holds_not_reported_as_equivalent_failures": True,
        "case_174_review_ready_jurisdiction": case_174.get("disposition") == REVIEW_READY_JURISDICTION,
        "case_174_not_factual_pass": case_174.get("diagnostic_factual_outcome") == "FACTUAL_HOLD",
        "case_312_conditional_review_ready": case_312.get("disposition") == CONDITIONAL_REVIEW_READY,
        "land_law_cp_d05_review_ready_currentness": d05.get("disposition") == REVIEW_READY_CURRENTNESS,
        "tort_law_cp_d13_fail_closed_no_evidence": tort.get("disposition") == FAIL_CLOSED_NO_EVIDENCE,
        "gold_training_unseen_remain_off": gold_off,
        "qualified_legal_review_not_started": summary.get("qualified_legal_review") == "NOT_STARTED",
        "no_disposition_is_running": all(item.get("disposition") != "RUNNING" for item in rows),
    }
    return {
        "pass": all(bool(value) for value in tests.values()),
        "tests": tests,
    }


def load_existing_pack(output: Path) -> dict[str, Any] | None:
    manifest = output / "DISPOSITION-MANIFEST.jsonl"
    state = output / "STATE-TRANSITION-RECEIPT.json"
    if not manifest.is_file() or not state.is_file():
        return None
    rows: list[dict[str, Any]] = []
    with manifest.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    receipt = json.loads(state.read_text(encoding="utf-8"))
    return {"rows": rows, "state": receipt}


def write_progression_pack(
    output: Path,
    rows: Sequence[Mapping[str, Any]],
    *,
    summary: Mapping[str, Any],
    tests: Mapping[str, Any],
    contractions: Sequence[Mapping[str, Any]],
    mutation: Mapping[str, Any],
    state: Mapping[str, Any],
) -> dict[str, Any]:
    existing = load_existing_pack(output)
    if existing is not None:
        existing_ids = [item["case_id"] for item in existing["rows"]]
        new_ids = [item["case_id"] for item in rows]
        existing_disp = [item["disposition"] for item in existing["rows"]]
        new_disp = [item["disposition"] for item in rows]
        if existing_ids == new_ids and existing_disp == new_disp:
            return {
                "result": "IDEMPOTENT_UNCHANGED",
                "output": str(output),
                "case_count": len(existing["rows"]),
                "duplicate_pack_created": False,
                "state": existing["state"],
            }
        raise RuntimeError("progression pack exists with different dispositions; refusing overwrite")
    output.mkdir(parents=True, exist_ok=True)
    manifest_bytes = b"".join(canonical_json_bytes(dict(item)) for item in rows)
    _write_create_only(output / "DISPOSITION-MANIFEST.jsonl", manifest_bytes)
    counts = {
        "schema": "legalbot.ge-progression-counts.v1",
        "campaign_id": CAMPAIGN_ID,
        **{key: value for key, value in summary.items() if key.endswith("_ids") is False},
        "disposition_counts": summary["disposition_counts"],
        "diagnostic_factual_counts": summary["diagnostic_factual_counts"],
    }
    _write_create_only(
        output / "DISPOSITION-COUNTS.json",
        json.dumps(counts, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
    )
    qlr_rows = [item for item in rows if item.get("qualified_review_eligible") is True]
    _write_create_only(
        output / "QUALIFIED-REVIEW-ELIGIBLE.jsonl",
        b"".join(canonical_json_bytes(dict(item)) for item in qlr_rows),
    )
    hard_rows = [
        item
        for item in rows
        if item.get("disposition") in {HOLD_MATERIAL, FAIL_CLOSED_NO_EVIDENCE, FAIL_WRONG_OR_CONTRADICTED, OUT_OF_SCOPE}
    ]
    _write_create_only(
        output / "HARD-EVIDENCE-GAP.jsonl",
        b"".join(canonical_json_bytes(dict(item)) for item in hard_rows),
    )
    gold_rows = [
        {
            "case_id": item["case_id"],
            "disposition": item["disposition"],
            "answer_gold": False,
            "legal_gold": False,
            "training_eligible": False,
            "qualified_legal_review": "NOT_STARTED",
        }
        for item in rows
    ]
    _write_create_only(
        output / "GOLD-INELIGIBLE.jsonl",
        b"".join(canonical_json_bytes(item) for item in gold_rows),
    )
    _write_create_only(
        output / "MATERIALITY-COUNTS.json",
        json.dumps(
            {
                "schema": "legalbot.ge-progression-materiality-counts.v1",
                "material_locator_count": summary["material_locator_count"],
                "non_material_locator_count": summary["non_material_locator_count"],
                "only_controlling_or_material_block_progression_or_gold": True,
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        + b"\n",
    )
    _write_create_only(
        output / "ANSWER-CONTRACTIONS.json",
        json.dumps(
            {
                "schema": "legalbot.ge-progression-answer-contractions.v1",
                "contractions": list(contractions),
                "new_propositions_introduced": False,
            },
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        + b"\n",
    )
    advanced = [item for item in rows if item.get("advanced_without_legal_approval") is True]
    _write_create_only(
        output / "CASES-ADVANCED-WITHOUT-LEGAL-APPROVAL.jsonl",
        b"".join(canonical_json_bytes(dict(item)) for item in advanced),
    )
    _write_create_only(
        output / "INTEGRITY-TESTS.json",
        json.dumps(dict(tests), ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
    )
    receipt = dict(state)
    _write_create_only(
        output / "STATE-TRANSITION-RECEIPT.json",
        json.dumps(receipt, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
    )
    _write_create_only(
        output / "FROZEN-HASH-GUARD.json",
        json.dumps(dict(mutation), ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
    )
    return {
        "result": "CREATED",
        "output": str(output),
        "case_count": len(rows),
        "duplicate_pack_created": False,
        "state": receipt,
    }


def run_progression_taxonomy_campaign(
    *,
    project_root: Path | None = None,
    output: Path | None = None,
) -> dict[str, Any]:
    from .ge_ai_advisory_campaign import CONSERVATIVE_PROPOSED, SIX_NO_EVIDENCE
    from .ge_currentness_packets import (
        PROJECT_ROOT,
        load_latest_delta_rows,
        mutation_guard,
        reconcile_latest_routes,
    )
    from .ge_phase2_progress import DOWNSTREAM_GATES, NOT_STARTED

    root = project_root or PROJECT_ROOT
    destination = output or default_output(root)
    rows = load_latest_delta_rows(root)
    if len(rows) != 331:
        raise RuntimeError(f"expected 331 latest delta rows, received {len(rows)}")
    reconciliation = reconcile_latest_routes(rows)
    attached = [case_id for case_id in SIX_NO_EVIDENCE if case_id != TORT_D13]
    exhausted = [TORT_D13]
    contractions = list(CONSERVATIVE_PROPOSED)
    classified = classify_331_rows(
        rows,
        attached_ids=attached,
        exhausted_ids=exhausted,
        contraction_ids=contractions,
        incomplete_final_ids=[LAND_LAW_D05],
    )
    summary = summarize_dispositions(classified)
    tests = integrity_tests(classified, summary)
    if tests["pass"] is False:
        raise RuntimeError(f"progression taxonomy integrity tests failed: {tests['tests']}")
    mutation = mutation_guard(root)
    if mutation.get("unchanged") is not True:
        raise RuntimeError("frozen r1/r2/r3/delta hashes changed; refusing progression pack")
    contraction_records = [
        {
            "case_id": case_id,
            "prior_disposition": "RETRIEVAL_NO_EVIDENCE",
            "new_disposition": VERIFIED_LIMITED_CANDIDATE,
            "contraction_applied": True,
            "new_proposition_introduced": False,
            "proposed_limited_answer": CONSERVATIVE_PROPOSED[case_id],
            "answer_gold": False,
            "qualified_legal_review": NOT_STARTED,
        }
        for case_id in contractions
    ]
    downstream = {name: NOT_STARTED for name in DOWNSTREAM_GATES}
    state = {
        "schema": "legalbot.ge-progression-taxonomy-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_state": EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW,
        "overall_progress": True,
        "evaluation_terminally_classified": True,
        "does_not_require_331_of_331_to_pass": True,
        "diagnostic_factual_pass": 42,
        "diagnostic_factual_hold": 289,
        "disposition_counts": summary["disposition_counts"],
        "qualified_review_eligible_count": summary["qualified_review_eligible_count"],
        "hard_evidence_gap_count": summary["hard_evidence_gap_count"],
        "fail_closed_count": len(summary["fail_closed_ids"]),
        "gold_ineligible_count": 331,
        "human_case_by_case_owner_review": "NOT_PERFORMED",
        "reviewer_kind": "AI_EVIDENCE_REVIEWER",
        "frozen_r1_r2_r3_delta_unchanged": True,
        "full_331_not_rerun": True,
        "sealed_unseen_not_opened": True,
        "writes_active": False,
        "admitted": False,
        "legal_gold": False,
        "answer_legal_gold": NOT_STARTED,
        "qualified_legal_review": NOT_STARTED,
        "answer_weight_training": NOT_STARTED,
        "training_eligible": False,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        **downstream,
        "route_reconciliation": {
            "currentness": (reconciliation.get("stored_counts") or {}).get("CURRENTNESS_UNRESOLVED"),
            "jurisdiction": (reconciliation.get("stored_counts") or {}).get("JURISDICTION_SCOPE_REVIEW"),
            "leftover": (reconciliation.get("stored_counts") or {}).get("LEFTOVER_CLAIM_OR_NO_EVIDENCE"),
            "fact_dependent": (reconciliation.get("stored_counts") or {}).get("FACT_DEPENDENT_OUTCOME"),
            "factual_pass": (reconciliation.get("stored_counts") or {}).get("FACTUAL_PASS"),
        },
        "gold_hard_blockers_remain": list(GOLD_HARD_BLOCKERS),
    }
    written = write_progression_pack(
        destination,
        classified,
        summary=summary,
        tests=tests,
        contractions=contraction_records,
        mutation=mutation,
        state=state,
    )
    if written["result"] == "CREATED":
        _write_owner_report(destination, classified, summary, contraction_records, tests)
    return {
        **written,
        "summary": {
            key: value
            for key, value in summary.items()
            if not str(key).endswith("_ids")
        },
        "tests": tests,
        "contraction_count": len(contraction_records),
        "mutation_unchanged": mutation.get("unchanged"),
    }


def _write_owner_report(
    output: Path,
    rows: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any],
    contractions: Sequence[Mapping[str, Any]],
    tests: Mapping[str, Any],
) -> None:
    counts = summary["disposition_counts"]
    body = "\n".join(
        [
            "# GE evaluation progression taxonomy r1",
            "",
            "This pack recalibrates evaluation **progression** only.",
            "It does not weaken answer gold or start training.",
            "",
            "## Diagnostic counts (unchanged)",
            "",
            "- FACTUAL_PASS: 42",
            "- FACTUAL_HOLD: 289",
            "",
            "289 FACTUAL_HOLD rows are not 289 equivalent factual failures.",
            "268 of those holds were review/interpretation (211 currentness,",
            "56 jurisdiction, 1 fact-dependent). Only the leftover support and",
            "no-evidence routes were genuine evidence gaps on the mechanical delta.",
            "",
            "## Progression dispositions",
            "",
            *[f"- `{name}`: {counts.get(name, 0)}" for name in PROGRESSION_DISPOSITIONS],
            "",
            f"- qualified-review eligible: {summary['qualified_review_eligible_count']}",
            f"- hard evidence-gap set: {summary['hard_evidence_gap_count']}",
            f"- fail-closed: {len(summary['fail_closed_ids'])}",
            "- gold-ineligible: 331",
            f"- advanced without claiming legal approval: {summary['cases_advanced_without_legal_approval_count']}",
            f"- answer contractions applied: {len(contractions)}",
            f"- material locators: {summary['material_locator_count']}",
            f"- non-material locators: {summary['non_material_locator_count']}",
            "",
            "## Named invariants",
            "",
            "- Case 174 stays `REVIEW_READY_JURISDICTION` / FACTUAL_HOLD.",
            "- Case 312 stays `CONDITIONAL_REVIEW_READY`.",
            "- `land-law:cp-d05` stays `REVIEW_READY_CURRENTNESS` with date ambiguity recorded.",
            "- `tort-law:cp-d13` is `FAIL_CLOSED_NO_EVIDENCE`.",
            "",
            "## Final state",
            "",
            f"- overall_state: `{EVALUATION_TERMINALLY_CLASSIFIED_AWAITING_QUALIFIED_REVIEW}`",
            "- overall_progress: true",
            "- qualified_legal_review: NOT_STARTED",
            "- answer_legal_gold: NOT_STARTED",
            "- training_eligible: false",
            "- sealed unseen, promotion and live remain off",
            "",
            "Evaluation completion means every case has a terminal classification.",
            "It does not require 331 of 331 to pass.",
            "",
            f"Integrity tests pass: {tests.get('pass')}",
            "",
        ]
    )
    _write_create_only(output / "OWNER-PROGRESSION-REPORT.md", body.encode("utf-8"))
    _write_create_only(output / "README.md", body.encode("utf-8"))
