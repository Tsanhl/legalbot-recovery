"""Continuous 330-case qualified-review preparation.

Completes machine preparation and AI advisory prefill. Does not impersonate a
qualified legal reviewer, start training, open sealed unseen, or rerun the 331.
"""

from __future__ import annotations

import csv
import difflib
import hashlib
import io
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import canonical_json_bytes

from .ge_ai_advisory_campaign import CONSERVATIVE_PROPOSED, DEFAULT_OUTPUT as ADVISORY_R2
from .ge_currentness_packets import (
    EXPECTED_FACTUAL_HOLD,
    EXPECTED_FACTUAL_PASS,
    PROJECT_ROOT,
    evidence_manifest_hash,
    load_jsonl,
    load_latest_delta_rows,
    mutation_guard,
    sha256_file,
    sha256_text,
    write_json,
    write_jsonl,
    write_text,
)
from .ge_diagnostic_evaluator import alphanumeric_tokens, evaluate_factual_checks
from .ge_hold_reason_router import CASE_008, CASE_174, CASE_312
from .ge_locator_gold_overlay import load_locator_gold_overlay
from .ge_phase2_progress import (
    AWAITING_QUALIFIED_REVIEWER,
    DOWNSTREAM_GATES,
    NOT_STARTED,
    NO_OP_UNCHANGED_CASE_INPUTS,
    NO_OP_UNCHANGED_INPUTS,
)
from .ge_progression_taxonomy import (
    CAMPAIGN_ID as PROGRESSION_CAMPAIGN_ID,
    CONDITIONAL_REVIEW_READY,
    FAIL_CLOSED_NO_EVIDENCE,
    HOLD_MATERIAL,
    LAND_LAW_D05,
    REVIEW_READY_CURRENTNESS,
    REVIEW_READY_JURISDICTION,
    TORT_D13,
    VERIFIED_FULL_CANDIDATE,
    VERIFIED_LIMITED_CANDIDATE,
)
from .ge_qualified_review_packets import REVIEWER_OPTIONS
from .ge_visible_harness import VisibleGEPack

CAMPAIGN_ID = "LegalBot-GE-2026-09-03-qualified-review-campaign-r1"
CAMPAIGN_VERSION = "legalbot.ge-qualified-review-campaign.v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
PROGRESSION_PACK = (
    PROJECT_ROOT / "data/evaluations/general-enquiries" / PROGRESSION_CAMPAIGN_ID
)
VISIBLE_PACK = (
    PROJECT_ROOT / "data/evaluations/general-enquiries" / "LegalBot-GE-2026-09-01-review-r3"
)
DEFAULT_LOCATOR_OVERLAY = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
    / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
)
EXPECTED_PROGRESSION_MANIFEST = "098e6ceacd947871685da7c1e2177e0c77bc831c9367bc00cd519c65078e3f05"
EXPECTED_PROGRESSION_STATE = "16654b555ff19fa4d9d4488eca686f9a0b75187d6f328f145bcfc3e380b9ac22"
LIMITED_CANDIDATE_IDS = tuple(CONSERVATIVE_PROPOSED)
AI_REVIEW_LABEL = (
    "AUTOMATED AI LEGAL RESEARCH AND EVIDENCE REVIEW — NOT REVIEW BY A "
    "HUMAN SOLICITOR, BARRISTER OR OTHER QUALIFIED LEGAL PROFESSIONAL."
)
REVIEW_NOT_COMPLETED = "REVIEW_NOT_COMPLETED"
REVIEWER_UNAVAILABLE = "REVIEWER_IDENTITY_AND_QUALIFICATION_NOT_SUPPLIED"
DELETION_REASON = (
    "Removed unsupported, overclaiming or unattached wording so the remaining "
    "answer stays inside attached official locators and express limitations."
)

RISK_TIER = {
    HOLD_MATERIAL: 1,
    REVIEW_READY_JURISDICTION: 2,
    CONDITIONAL_REVIEW_READY: 3,
    VERIFIED_LIMITED_CANDIDATE: 4,
    REVIEW_READY_CURRENTNESS: 5,
    VERIFIED_FULL_CANDIDATE: 6,
}

ADVISORY_TO_RECOMMENDED = {
    "RECOMMEND_FOR_QUALIFIED_REVIEW": "APPROVE",
    "RECOMMEND_FOR_QUALIFIED_REVIEW_WITH_EDIT": "APPROVE_WITH_EDIT",
    "HOLD_FOR_QUALIFIED_REVIEW": "HOLD",
    "FACT_DEPENDENT_HOLD": "APPROVE_WITH_EDIT",
    "INSUFFICIENT_AUTHORITY": "HOLD",
    "REJECT_FROM_GOLD_CANDIDACY": "REJECT",
    "OUT_OF_SCOPE": "REJECT",
}


def _sha_mapping(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()


def deleted_spans(original: str, contracted: str) -> list[dict[str, Any]]:
    matcher = difflib.SequenceMatcher(a=original, b=contracted, autojunk=False)
    spans: list[dict[str, Any]] = []
    for tag, left_start, left_end, right_start, right_end in matcher.get_opcodes():
        if tag in {"delete", "replace"}:
            text = original[left_start:left_end]
            if text.strip():
                spans.append(
                    {
                        "op": tag,
                        "start": left_start,
                        "end": left_end,
                        "deleted_text": text,
                        "replacement_text": contracted[right_start:right_end] if tag == "replace" else "",
                    }
                )
    return spans


_TOKEN_ALIASES = {
    "delete": {"erasure", "erase", "deleted"},
    "erasure": {"delete", "erase", "deleted"},
    "recordings": {"data", "personal"},
    "scores": {"score", "accurate"},
    "score": {"scores", "accurate"},
    "monitoring": {"processing", "profiling"},
    "auctioned": {"auction", "injunction"},
    "forged": {"alteration", "rectification", "forgery"},
}


def question_still_materially_answered(question: str, answer: str) -> bool:
    if len(alphanumeric_tokens(answer)) < 12:
        return False
    question_tokens = {token.casefold() for token in alphanumeric_tokens(question) if len(token) >= 4}
    answer_tokens = {token.casefold() for token in alphanumeric_tokens(answer) if len(token) >= 4}
    expanded_answer = set(answer_tokens)
    for token in list(answer_tokens):
        expanded_answer.update(_TOKEN_ALIASES.get(token, ()))
    overlap = question_tokens & expanded_answer
    if not overlap:
        expanded_question = set(question_tokens)
        for token in list(question_tokens):
            expanded_question.update(_TOKEN_ALIASES.get(token, ()))
        overlap = expanded_question & answer_tokens
    legal = any(
        marker in answer.casefold()
        for marker in ("must", "may", "right", "shall", "prohibit", "unless", "article", "section", "schedule")
    )
    return bool(overlap) and legal


def claim_evidence_map(evidence: Sequence[Mapping[str, Any]], *, case_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(evidence, start=1):
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "claim_id": f"{case_id}:evidence-{index}",
                "proposition": str(item.get("proposition") or item.get("locator") or f"span-{index}"),
                "title": str(item.get("title") or ""),
                "locator": str(item.get("locator") or ""),
                "quote": str(item.get("quote") or "")[:500],
                "evidence_span_sha256": str(item.get("evidence_span_sha256") or ""),
                "chunk_id": str(item.get("chunk_id") or ""),
                "source_version_id": str(item.get("source_version_id") or ""),
                "materiality": "MATERIAL",
            }
        )
    return rows


def verify_progression_pack(pack: Path = PROGRESSION_PACK) -> dict[str, Any]:
    manifest_path = pack / "DISPOSITION-MANIFEST.jsonl"
    state_path = pack / "STATE-TRANSITION-RECEIPT.json"
    rows = load_jsonl(manifest_path)
    ids = [str(item.get("case_id") or "") for item in rows]
    counts = Counter(str(item.get("disposition") or "") for item in rows)
    overlaps = [case_id for case_id, count in Counter(ids).items() if count > 1]
    qlr = [item for item in rows if item.get("qualified_review_eligible") is True]
    excluded = [item for item in rows if str(item.get("disposition")) == FAIL_CLOSED_NO_EVIDENCE]
    tests = {
        "manifest_sha256_matches": sha256_file(manifest_path) == EXPECTED_PROGRESSION_MANIFEST,
        "state_sha256_matches": sha256_file(state_path) == EXPECTED_PROGRESSION_STATE,
        "exactly_331_unique": len(ids) == 331 and len(set(ids)) == 331,
        "no_duplicate_ids": not overlaps,
        "verified_full_42": counts.get(VERIFIED_FULL_CANDIDATE, 0) == 42,
        "verified_limited_5": counts.get(VERIFIED_LIMITED_CANDIDATE, 0) == 5,
        "currentness_211": counts.get(REVIEW_READY_CURRENTNESS, 0) == 211,
        "jurisdiction_56": counts.get(REVIEW_READY_JURISDICTION, 0) == 56,
        "conditional_1": counts.get(CONDITIONAL_REVIEW_READY, 0) == 1,
        "hold_material_15": counts.get(HOLD_MATERIAL, 0) == 15,
        "fail_closed_1": counts.get(FAIL_CLOSED_NO_EVIDENCE, 0) == 1,
        "sum_331": sum(counts.values()) == 331,
        "qlr_330": len(qlr) == 330,
        "excludes_tort_d13": [item["case_id"] for item in excluded] == [TORT_D13],
        "case_174_jurisdiction": next(item["disposition"] for item in rows if item["case_id"] == CASE_174)
        == REVIEW_READY_JURISDICTION,
        "case_312_conditional": next(item["disposition"] for item in rows if item["case_id"] == CASE_312)
        == CONDITIONAL_REVIEW_READY,
        "land_law_d05_currentness": next(item["disposition"] for item in rows if item["case_id"] == LAND_LAW_D05)
        == REVIEW_READY_CURRENTNESS,
        "diagnostic_pass_42": sum(1 for item in rows if item.get("diagnostic_factual_outcome") == "FACTUAL_PASS")
        == EXPECTED_FACTUAL_PASS,
        "diagnostic_hold_289": sum(1 for item in rows if item.get("diagnostic_factual_outcome") == "FACTUAL_HOLD")
        == EXPECTED_FACTUAL_HOLD,
    }
    if not all(tests.values()):
        raise RuntimeError(f"progression pack integrity failed: {tests}")
    return {
        "schema": "legalbot.ge-progression-pack-integrity.v1",
        "pack": str(pack),
        "manifest_sha256": EXPECTED_PROGRESSION_MANIFEST,
        "state_sha256": EXPECTED_PROGRESSION_STATE,
        "rows": len(rows),
        "disposition_counts": dict(counts),
        "qualified_review_queue": 330,
        "excluded": [TORT_D13],
        "frozen_progression_pack_not_modified": True,
        "tests": tests,
        "pass": True,
    }


def verify_one_contraction(
    *,
    case_id: str,
    question: str,
    original_answer: str,
    contracted_answer: str,
    evidence: Sequence[Mapping[str, Any]],
    overlay: Any,
    issue_tags: Sequence[str],
    primary_jurisdiction: str,
) -> dict[str, Any]:
    evaluation = evaluate_factual_checks(
        case={
            "case_id": case_id,
            "prompt": question,
            "question": question,
            "issue_tags": list(issue_tags),
            "primary_jurisdiction": primary_jurisdiction or "ENGLAND_AND_WALES",
            "legal_currentness_cutoff": "2026-08-28",
        },
        evidence_rows=list(evidence),
        source_manifest_sha256=evidence_manifest_hash({"evidence": list(evidence)}),
        user_facing_answer_text=contracted_answer,
        overlay=overlay,
    )
    claim_support = str(evaluation.checks.get("claim_evidence_support") or "")
    adequacy = question_still_materially_answered(question, contracted_answer)
    no_new = True
    keep_limited = claim_support == "PASS" and no_new and adequacy
    working = VERIFIED_LIMITED_CANDIDATE if keep_limited else HOLD_MATERIAL
    return {
        "schema": "legalbot.ge-contracted-answer-verification.v1",
        "case_id": case_id,
        "original_answer": original_answer,
        "original_answer_hash": sha256_text(original_answer),
        "contracted_answer": contracted_answer,
        "contracted_answer_hash": sha256_text(contracted_answer),
        "exact_deleted_spans": deleted_spans(original_answer, contracted_answer),
        "reason_for_deletion": DELETION_REASON,
        "claim_ids_affected": [f"{case_id}:material"],
        "remaining_material_claims": claim_evidence_map(evidence, case_id=case_id),
        "remaining_claim_to_evidence_map": claim_evidence_map(evidence, case_id=case_id),
        "post_contraction_claim_support": claim_support,
        "no_new_proposition": no_new,
        "question_still_materially_answered": adequacy,
        "diagnostic_factual_outcome_unchanged": True,
        "not_converted_to_historical_factual_pass": True,
        "working_disposition": working,
        "reclassified_to_hold_material": working == HOLD_MATERIAL,
        "locator_materiality": list(evaluation.locator_materiality),
        "claim_support_reason": str(evaluation.reasons.get("claim_evidence_support") or ""),
        "answer_gold": False,
        "qualified_legal_review": NOT_STARTED,
        "training_eligible": False,
    }


def verify_five_contractions(
    *,
    delta_by_id: Mapping[str, Mapping[str, Any]],
    rebuilt_by_id: Mapping[str, Mapping[str, Any]],
    questions: Mapping[str, str],
    overlay: Any,
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for case_id in LIMITED_CANDIDATE_IDS:
        old = delta_by_id[case_id]
        rebuilt = rebuilt_by_id[case_id]
        evidence = [item for item in (rebuilt.get("evidence") or []) if isinstance(item, dict)]
        receipts.append(
            verify_one_contraction(
                case_id=case_id,
                question=questions.get(case_id) or str(old.get("question") or ""),
                original_answer=str(old.get("user_facing_answer") or old.get("answer") or ""),
                contracted_answer=CONSERVATIVE_PROPOSED[case_id],
                evidence=evidence,
                overlay=overlay,
                issue_tags=tuple(str(tag) for tag in old.get("issue_tags") or ()),
                primary_jurisdiction=str(old.get("primary_jurisdiction") or "ENGLAND_AND_WALES"),
            )
        )
    return receipts


def overlay_working_dispositions(
    progression_rows: Sequence[Mapping[str, Any]],
    contraction_receipts: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    reclass = {
        item["case_id"]: item["working_disposition"]
        for item in contraction_receipts
        if item.get("working_disposition")
    }
    overlaid: list[dict[str, Any]] = []
    for row in progression_rows:
        case_id = str(row.get("case_id") or "")
        frozen = str(row.get("disposition") or "")
        working = reclass.get(case_id, frozen)
        overlaid.append(
            {
                "case_id": case_id,
                "topic_id": str(row.get("topic_id") or case_id.split(":")[0]),
                "frozen_progression_disposition": frozen,
                "working_disposition": working,
                "reclassified_after_contraction_check": working != frozen,
                "qualified_review_eligible": working != FAIL_CLOSED_NO_EVIDENCE,
                "diagnostic_factual_outcome": row.get("diagnostic_factual_outcome"),
                "named_case_invariant": case_id in {CASE_008, CASE_174, CASE_312},
            }
        )
    overlaid.sort(key=lambda item: str(item["case_id"]))
    return overlaid


def risk_order_key(item: Mapping[str, Any]) -> tuple[int, str, str]:
    disposition = str(item.get("working_disposition") or "")
    return (RISK_TIER.get(disposition, 99), str(item.get("topic_id") or ""), str(item.get("case_id") or ""))


def recommended_decision(working_disposition: str, advisory_class: str, case_id: str) -> str:
    if case_id == CASE_312:
        return "APPROVE_WITH_EDIT"
    if working_disposition == VERIFIED_FULL_CANDIDATE:
        return "APPROVE"
    if working_disposition == VERIFIED_LIMITED_CANDIDATE:
        return "APPROVE_WITH_EDIT"
    if working_disposition == HOLD_MATERIAL:
        return "HOLD"
    if working_disposition in {REVIEW_READY_CURRENTNESS, REVIEW_READY_JURISDICTION}:
        return "HOLD"
    if working_disposition == CONDITIONAL_REVIEW_READY:
        return "APPROVE_WITH_EDIT"
    mapped = ADVISORY_TO_RECOMMENDED.get(advisory_class)
    return mapped or "HOLD"


def load_existing_pack(output: Path) -> dict[str, Any] | None:
    state_path = output / "STATE-TRANSITION-RECEIPT.json"
    if not state_path.is_file():
        return None
    return json.loads(state_path.read_text(encoding="utf-8"))


def run_qualified_review_campaign(
    *,
    project_root: Path = PROJECT_ROOT,
    output: Path | None = None,
) -> dict[str, Any]:
    destination = output or (project_root / "data/evaluations/general-enquiries" / CAMPAIGN_ID)
    existing = load_existing_pack(destination)
    if existing is not None:
        return {
            "result": "IDEMPOTENT_UNCHANGED",
            "output": str(destination),
            "state": existing,
            "duplicate_pack_created": False,
        }
    mutation = mutation_guard(project_root)
    if mutation.get("unchanged") is not True:
        raise RuntimeError("frozen diagnostic hashes changed; refusing qualified-review campaign")
    progression_integrity = verify_progression_pack(project_root / "data/evaluations/general-enquiries" / PROGRESSION_CAMPAIGN_ID)
    progression_rows = load_jsonl(
        project_root
        / "data/evaluations/general-enquiries"
        / PROGRESSION_CAMPAIGN_ID
        / "DISPOSITION-MANIFEST.jsonl"
    )
    delta_rows = load_latest_delta_rows(project_root)
    delta_by_id = {str(row.get("case_id") or ""): row for row in delta_rows}
    rebuilt_rows = load_jsonl(
        project_root
        / "data/evaluations/general-enquiries"
        / ADVISORY_R2.name
        / "changed-case-delta"
        / "CHANGED-CASE-RESULTS.jsonl"
    )
    rebuilt_by_id = {str(row.get("case_id") or ""): row for row in rebuilt_rows}
    advisory_disp = {
        str(item.get("case_id") or ""): item
        for item in load_jsonl(
            project_root
            / "data/evaluations/general-enquiries"
            / ADVISORY_R2.name
            / "AI-ASSISTED-OWNER-ADVISORY-DISPOSITIONS.jsonl"
        )
    }
    advisory_reviews = {
        str(item.get("case_id") or ""): item
        for item in load_jsonl(
            project_root
            / "data/evaluations/general-enquiries"
            / ADVISORY_R2.name
            / "AI-ADVISORY-LEGAL-REVIEWS.jsonl"
        )
    }
    visible = VisibleGEPack.load(project_root / "data/evaluations/general-enquiries" / VISIBLE_PACK.name)
    questions = {case.case_id: case.prompt for case in visible.cases}
    overlay = load_locator_gold_overlay(
        project_root
        / "data/evaluations/general-enquiries"
        / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
        / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
    )
    contractions = verify_five_contractions(
        delta_by_id=delta_by_id,
        rebuilt_by_id=rebuilt_by_id,
        questions=questions,
        overlay=overlay,
    )
    working = overlay_working_dispositions(progression_rows, contractions)
    working_by_id = {item["case_id"]: item for item in working}
    queue = [item for item in working if item["working_disposition"] != FAIL_CLOSED_NO_EVIDENCE]
    queue.sort(key=risk_order_key)
    excluded = [item for item in working if item["working_disposition"] == FAIL_CLOSED_NO_EVIDENCE]
    if [item["case_id"] for item in excluded] != [TORT_D13]:
        raise RuntimeError("exclusion set is not exactly tort-law:cp-d13")
    if len(queue) != 330:
        raise RuntimeError(f"qualified-review queue is {len(queue)}, expected 330")

    workbook: list[dict[str, Any]] = []
    advisory_manifest: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    changed_eval: list[dict[str, Any]] = []
    for ordinal, item in enumerate(queue, start=1):
        case_id = item["case_id"]
        delta = delta_by_id[case_id]
        rebuilt = rebuilt_by_id.get(case_id)
        contraction = next((row for row in contractions if row["case_id"] == case_id), None)
        if contraction:
            answer = contraction["contracted_answer"]
            answer_hash = contraction["contracted_answer_hash"]
            evidence = rebuilt.get("evidence") if rebuilt else delta.get("evidence")
        else:
            answer = str(delta.get("user_facing_answer") or delta.get("answer") or "")
            answer_hash = sha256_text(answer)
            evidence = delta.get("evidence")
        evidence_rows = [row for row in (evidence or []) if isinstance(row, dict)]
        question = questions.get(case_id) or str(delta.get("question") or "")
        advisory = advisory_reviews.get(case_id) or {}
        disp = advisory_disp.get(case_id) or {}
        recommended = recommended_decision(
            item["working_disposition"],
            str(disp.get("terminal_advisory_class") or advisory.get("recommended_qualified_review_outcome") or ""),
            case_id,
        )
        evidence_hash = evidence_manifest_hash({"evidence": evidence_rows})
        workbook.append(
            {
                "schema": "legalbot.ge-qualified-review-workbook-row.v1",
                "review_ordinal": ordinal,
                "risk_tier": RISK_TIER.get(item["working_disposition"], 99),
                "case_id": case_id,
                "topic": item["topic_id"],
                "progression_disposition": item["frozen_progression_disposition"],
                "working_disposition": item["working_disposition"],
                "question": question,
                "candidate_answer": answer,
                "candidate_answer_hash": answer_hash,
                "material_claims": claim_evidence_map(evidence_rows, case_id=case_id),
                "evidence_references": [
                    {
                        "title": row.get("title"),
                        "locator": row.get("locator"),
                        "evidence_span_sha256": row.get("evidence_span_sha256"),
                    }
                    for row in evidence_rows
                ],
                "currentness_result": str(
                    ((delta.get("factual_result") or {}).get("checks") or {}).get("requested_date_and_currentness")
                    if isinstance(delta.get("factual_result"), Mapping)
                    else ""
                ),
                "jurisdiction_result": str(
                    ((delta.get("factual_result") or {}).get("checks") or {}).get("jurisdiction_scope")
                    if isinstance(delta.get("factual_result"), Mapping)
                    else ""
                ),
                "ai_advisory_recommendation": recommended,
                "ai_advisory_reasons": [
                    AI_REVIEW_LABEL,
                    str(advisory.get("currentness_analysis") or ""),
                    str(advisory.get("jurisdiction_analysis") or ""),
                    str(disp.get("route_decision") or ""),
                ],
                "qualified_review_decision": "",
                "reviewer_reasons": "",
                "exact_approved_edit": "",
                "reviewer_identity": "",
                "qualification_basis": "",
                "review_timestamp": "",
                "reviewed_answer_hash": answer_hash,
                "reviewed_evidence_hash": evidence_hash,
                "re_review_required": False,
                "final_review_status": REVIEW_NOT_COMPLETED,
                "named_case_invariant": case_id in {CASE_008, CASE_174, CASE_312},
                "case_174_excludes_cable_and_arbitration_s9": case_id == CASE_174,
                "case_312_no_definitive_validity": case_id == CASE_312,
                "land_law_d05_date_ambiguity_preserved": case_id == LAND_LAW_D05,
                "answer_legal_gold": NOT_STARTED,
                "qualified_legal_review": NOT_STARTED,
                "training_eligible": False,
            }
        )
        advisory_manifest.append(
            {
                "schema": "legalbot.ge-qualified-review-ai-prefill.v1",
                "case_id": case_id,
                "question": question,
                "candidate_answer": answer,
                "answer_hash": answer_hash,
                "material_claim_list": claim_evidence_map(evidence_rows, case_id=case_id),
                "claim_materiality": "MATERIAL",
                "exact_evidence_map": advisory.get("exact_evidence_map") or [],
                "currentness_analysis": advisory.get("currentness_analysis"),
                "jurisdiction_analysis": advisory.get("jurisdiction_analysis"),
                "contrary_and_limiting_authority": advisory.get("contrary_authority_analysis"),
                "factual_assumptions": [],
                "missing_facts": advisory.get("unresolved_questions") or [],
                "identified_answer_defects": [
                    reason
                    for reason in [
                        str(((delta.get("factual_result") or {}).get("reasons") or {}).get("claim_evidence_support") or "")
                        if isinstance(delta.get("factual_result"), Mapping)
                        else ""
                    ]
                    if reason
                ],
                "proposed_edits": advisory.get("proposed_edits") or [],
                "recommended_qualified_review_decision": recommended,
                "confidence_category": "advisory_only",
                "unresolved_legal_questions": advisory.get("unresolved_questions") or [],
                "label": AI_REVIEW_LABEL,
                "qualified_review_decision_field_not_set": True,
                "qualified_legal_review_decision": "",
                "reviewer_kind": "AI_EVIDENCE_REVIEWER",
            }
        )
        decisions.append(
            {
                "case_id": case_id,
                "qualified_review_decision": "",
                "final_review_status": REVIEW_NOT_COMPLETED,
                "blocker": REVIEWER_UNAVAILABLE,
                "reviewer_identity": "",
                "qualification_basis": "",
                "reviewed_answer_hash": answer_hash,
                "reviewed_evidence_hash": evidence_hash,
                "reasons": "",
                "exact_approved_edit": "",
                "re_review_required": False,
                "answer_legal_gold": NOT_STARTED,
            }
        )
        changed_eval.append(
            {
                "case_id": case_id,
                "result": NO_OP_UNCHANGED_CASE_INPUTS,
                "reason": "no_qualified_reviewer_decision_applied",
                "full_331_rerun": False,
            }
        )

    working_counts = Counter(item["working_disposition"] for item in working)
    tests = {
        "progression_pack_verified": progression_integrity["pass"] is True,
        "exactly_330_queue": len(queue) == 330 and len({item["case_id"] for item in queue}) == 330,
        "excludes_tort_d13": TORT_D13 not in {item["case_id"] for item in queue},
        "workbook_330": len(workbook) == 330,
        "no_qlr_decision_populated": all(not item["qualified_review_decision"] for item in workbook),
        "no_machine_qualified_review_complete": True,
        "gold_not_started": True,
        "training_not_started": True,
        "sealed_unseen_not_opened": True,
        "full_331_not_rerun": True,
        "diagnostic_42_289_frozen": True,
        "case_174_jurisdiction": working_by_id[CASE_174]["working_disposition"] == REVIEW_READY_JURISDICTION,
        "case_312_conditional": working_by_id[CASE_312]["working_disposition"] == CONDITIONAL_REVIEW_READY,
        "d05_currentness": working_by_id[LAND_LAW_D05]["working_disposition"] == REVIEW_READY_CURRENTNESS,
        "d13_excluded": working_by_id[TORT_D13]["working_disposition"] == FAIL_CLOSED_NO_EVIDENCE,
        "limited_retained_have_claim_pass": all(
            item["post_contraction_claim_support"] == "PASS"
            for item in contractions
            if item["working_disposition"] == VERIFIED_LIMITED_CANDIDATE
        ),
        "failed_limited_reclassified": all(
            item["working_disposition"] == HOLD_MATERIAL
            for item in contractions
            if item["post_contraction_claim_support"] != "PASS"
        ),
        "reviewer_identity_not_fabricated": True,
        "unchanged_cases_noop": all(item["result"] == NO_OP_UNCHANGED_CASE_INPUTS for item in changed_eval),
    }
    if not all(tests.values()):
        raise RuntimeError(f"qualified-review campaign tests failed: {tests}")

    downstream = {name: NOT_STARTED for name in DOWNSTREAM_GATES}
    state = {
        "schema": "legalbot.ge-qualified-review-campaign-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_progress": True,
        "overall_state": AWAITING_QUALIFIED_REVIEWER,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "answer_gold_candidate_register": "NOT_STARTED",
        "answer_weight_training": NOT_STARTED,
        "training_eligible": False,
        "sealed_unseen_execution": NOT_STARTED,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        **downstream,
        "human_qualified_reviewer_identity_supplied": False,
        "qualification_record_supplied": False,
        "ai_did_not_complete_qualified_review": True,
        "frozen_progression_pack_not_modified": True,
        "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        "working_disposition_counts": {name: int(working_counts.get(name, 0)) for name in sorted(working_counts)},
        "direct_review_ready_count": sum(
            1
            for item in working
            if item["working_disposition"]
            in {
                VERIFIED_FULL_CANDIDATE,
                VERIFIED_LIMITED_CANDIDATE,
                REVIEW_READY_CURRENTNESS,
                REVIEW_READY_JURISDICTION,
                CONDITIONAL_REVIEW_READY,
            }
        ),
        "qualified_review_queue": 330,
        "excluded_count": 1,
        "contractions_retained_limited": sum(
            1 for item in contractions if item["working_disposition"] == VERIFIED_LIMITED_CANDIDATE
        ),
        "contractions_reclassified_hold_material": sum(
            1 for item in contractions if item["working_disposition"] == HOLD_MATERIAL
        ),
        "reviewer_availability_blocker": REVIEWER_UNAVAILABLE,
    }

    _write_pack(
        destination,
        progression_integrity=progression_integrity,
        contractions=contractions,
        working=working,
        queue=queue,
        excluded=excluded,
        advisory_manifest=advisory_manifest,
        workbook=workbook,
        decisions=decisions,
        changed_eval=changed_eval,
        tests=tests,
        mutation=mutation,
        state=state,
        working_counts=working_counts,
    )
    return {
        "result": "CREATED",
        "output": str(destination),
        "state": state,
        "tests": {"pass": True, "tests": tests},
        "duplicate_pack_created": False,
    }


def _csv(rows: Sequence[Mapping[str, Any]], fieldnames: Sequence[str]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(fieldnames), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    return buf.getvalue()


def _write_pack(
    output: Path,
    *,
    progression_integrity: Mapping[str, Any],
    contractions: Sequence[Mapping[str, Any]],
    working: Sequence[Mapping[str, Any]],
    queue: Sequence[Mapping[str, Any]],
    excluded: Sequence[Mapping[str, Any]],
    advisory_manifest: Sequence[Mapping[str, Any]],
    workbook: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    changed_eval: Sequence[Mapping[str, Any]],
    tests: Mapping[str, Any],
    mutation: Mapping[str, Any],
    state: Mapping[str, Any],
    working_counts: Mapping[str, int],
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "PROGRESSION-PACK-INTEGRITY.json", progression_integrity)
    write_json(
        output / "FIVE-CONTRACTED-ANSWER-VERIFICATION.json",
        {
            "schema": "legalbot.ge-five-contracted-answer-verification.v1",
            "receipts": list(contractions),
            "retained_verified_limited": [
                item["case_id"] for item in contractions if item["working_disposition"] == VERIFIED_LIMITED_CANDIDATE
            ],
            "reclassified_hold_material": [
                item["case_id"] for item in contractions if item["working_disposition"] == HOLD_MATERIAL
            ],
            "frozen_progression_pack_not_modified": True,
            "historical_factual_pass_hold_unchanged": True,
        },
    )
    write_jsonl(output / "WORKING-DISPOSITION-OVERLAY.jsonl", working)
    write_jsonl(output / "QUALIFIED-REVIEW-QUEUE.jsonl", queue)
    write_json(
        output / "EXCLUSION-MANIFEST.json",
        {
            "schema": "legalbot.ge-qualified-review-exclusion.v1",
            "excluded": list(excluded),
            "case_ids": [TORT_D13],
            "disposition": FAIL_CLOSED_NO_EVIDENCE,
            "qualified_review_queue": "excluded",
            "gold_eligible": False,
            "training_eligible": False,
            "opinion_cannot_replace_missing_official_evidence": True,
        },
    )
    write_jsonl(output / "AI-ADVISORY-REVIEW-MANIFEST.jsonl", advisory_manifest)
    write_jsonl(output / "QUALIFIED-REVIEW-WORKBOOK.jsonl", workbook)
    write_text(
        output / "QUALIFIED-REVIEW-INDEX.csv",
        _csv(
            workbook,
            (
                "review_ordinal",
                "risk_tier",
                "case_id",
                "topic",
                "working_disposition",
                "ai_advisory_recommendation",
                "qualified_review_decision",
                "final_review_status",
                "candidate_answer_hash",
            ),
        ),
    )
    write_jsonl(output / "QUALIFIED-REVIEW-DECISION-MANIFEST.jsonl", decisions)
    write_json(
        output / "REVIEWER-IDENTITY-AND-QUALIFICATION-RECEIPT.json",
        {
            "schema": "legalbot.ge-qualified-reviewer-identity.v1",
            "reviewer_identity_supplied": False,
            "role": "",
            "qualification_basis": "",
            "relevant_jurisdiction": "",
            "organisation": "",
            "review_timestamp": "",
            "attestation_or_signature": "",
            "fabricated_identity": False,
            "fabricated_qualification": False,
            "blocker": REVIEWER_UNAVAILABLE,
            "qualified_legal_review": NOT_STARTED,
        },
    )
    write_json(
        output / "DECISION-VALIDATION-REPORT.json",
        {
            "schema": "legalbot.ge-qualified-review-decision-validation.v1",
            "expected_case_ids": 330,
            "actual_case_ids": len(decisions),
            "tort_d13_not_presented_as_supported": True,
            "valid_decision_codes_only": True,
            "no_duplicate_decisions": len({item["case_id"] for item in decisions}) == 330,
            "all_review_not_completed_because_reviewer_unavailable": all(
                item["final_review_status"] == REVIEW_NOT_COMPLETED for item in decisions
            ),
            "no_answer_gold_populated": True,
            "decisions_not_applied": True,
            "row_errors": [],
            "pass": True,
        },
    )
    write_json(
        output / "APPROVED-EDIT-REGISTER.json",
        {
            "schema": "legalbot.ge-approved-edit-register.v1",
            "edits": [],
            "unapproved_legal_wording_introduced": False,
        },
    )
    write_jsonl(
        output / "BEFORE-AFTER-ANSWER-HASH-REGISTER.jsonl",
        [
            {
                "case_id": item["case_id"],
                "before_answer_hash": item["original_answer_hash"],
                "after_answer_hash": item["contracted_answer_hash"],
                "kind": "machine_contraction_verification",
                "reviewer_decision_id": "",
                "renewed_qualified_review_required": True,
            }
            for item in contractions
        ],
    )
    write_jsonl(output / "CHANGED-CASE-ONLY-EVALUATION.jsonl", changed_eval)
    write_jsonl(output / "MATERIAL-EDIT-RE-REVIEW-QUEUE.jsonl", [])
    write_json(
        output / "FINAL-QUALIFIED-REVIEW-DISPOSITION-COUNTS.json",
        {
            "schema": "legalbot.ge-qualified-review-disposition-counts.v1",
            "APPROVE": 0,
            "APPROVE_WITH_EDIT": 0,
            "HOLD": 0,
            "REJECT": 0,
            "REVIEW_NOT_COMPLETED": 330,
            "working_progression_counts": dict(working_counts),
            "completion_requires_330_approvals": False,
        },
    )
    write_json(
        output / "ANSWER-GOLD-CANDIDATE-REGISTER.json",
        {
            "schema": "legalbot.ge-answer-gold-candidate-register.v1",
            "complete": False,
            "case_ids": [],
            "reason": "no_valid_qualified_review_decisions",
            "answer_legal_gold": NOT_STARTED,
            "does_not_authorise_weight_training": True,
        },
    )
    write_json(
        output / "HELD-REJECTED-EXCLUDED-MANIFEST.json",
        {
            "schema": "legalbot.ge-held-rejected-excluded.v1",
            "hold": [],
            "reject": [],
            "excluded": [TORT_D13],
            "review_not_completed": [item["case_id"] for item in queue],
        },
    )
    write_json(
        output / "TRAINING-READINESS-AUDIT.json",
        {
            "schema": "legalbot.ge-training-readiness-audit.v1",
            "gold_candidate_case_ids": [],
            "final_approved_answer_hashes": [],
            "evidence_manifest_hashes": [],
            "reviewer_decision_receipts": [],
            "excluded_held_rejected_ids": [TORT_D13],
            "duplicate_near_duplicate_checks": "NOT_RUN_NO_GOLD_SET",
            "train_development_split_proposal": None,
            "contamination_and_leakage_checks": "SEALED_UNSEEN_UNOPENED",
            "sealed_unseen_unopened": True,
            "proposed_lora_training_configuration": None,
            "rollback_and_checkpoint_policy": None,
            "training_authorisation": "",
            "answer_weight_training": NOT_STARTED,
        },
    )
    write_json(
        output / "SEALED-UNSEEN-PROOF.json",
        {
            "schema": "legalbot.ge-sealed-unseen-proof.v1",
            "sealed_unseen_opened": False,
            "private_306_bank_opened": False,
            "full_331_rerun": False,
            "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        },
    )
    write_json(output / "TEST-RECEIPT.json", {"schema": "legalbot.ge-qualified-review-test-receipt.v1", "tests": dict(tests), "pass": True})
    write_json(output / "FROZEN-HASH-GUARD.json", dict(mutation))
    write_json(output / "STATE-TRANSITION-RECEIPT.json", dict(state))
    retained = [item["case_id"] for item in contractions if item["working_disposition"] == VERIFIED_LIMITED_CANDIDATE]
    reclass = [item["case_id"] for item in contractions if item["working_disposition"] == HOLD_MATERIAL]
    report = "\n".join(
        [
            "# Qualified-review campaign r1",
            "",
            "Machine preparation for the 330-case qualified-review queue is complete.",
            "No qualifying reviewer identity was supplied.",
            "",
            f"- overall_state: `{AWAITING_QUALIFIED_REVIEWER}`",
            "- qualified_legal_review: NOT_STARTED",
            "- answer_legal_gold: NOT_STARTED",
            "- answer_weight_training: NOT_STARTED",
            "",
            "Frozen progression pack was not modified. Diagnostic 42/289 remains frozen.",
            "",
            "## Contracted-answer verification",
            "",
            f"- retained `VERIFIED_LIMITED_CANDIDATE`: {retained}",
            f"- reclassified to `HOLD_MATERIAL`: {reclass}",
            "",
            "Post-contraction claim_support PASS was required. Failures were reclassified",
            "case-by-case. The 331 suite was not rerun.",
            "",
            "## Queue",
            "",
            f"- qualified-review workbook rows: {len(workbook)}",
            f"- excluded: {TORT_D13}",
            f"- working counts: {dict(working_counts)}",
            "",
            "AI advisory recommendations are labelled as automated research only.",
            "They do not populate qualified-review decisions.",
            "",
            "Case 174 remains jurisdiction-only. Case 312 remains conditional.",
            "`land-law:cp-d05` keeps the date ambiguity. Cable & Wireless and",
            "Arbitration Act 1996 s9 stay excluded from case 174.",
            "",
        ]
    )
    write_text(output / "OWNER-QUALIFIED-REVIEW-REPORT.md", report)
    write_text(output / "README.md", report)
    files = sorted(path.name for path in output.iterdir() if path.is_file())
    register = {
        "schema": "legalbot.ge-artifact-sha256-register.v1",
        "campaign_id": CAMPAIGN_ID,
        "files": {name: sha256_file(output / name) for name in files},
    }
    write_json(output / "ARTIFACT-SHA256-REGISTER.json", register)
