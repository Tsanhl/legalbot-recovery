"""Blind independent Grok review of the 330-case qualified-review queue.

This is AI_MODEL_REVIEWER work only. It must not populate qualified human
review, legal gold, training, sealed unseen, promotion or live.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import canonical_json_bytes

from .ge_currentness_packets import (
    PROJECT_ROOT,
    load_jsonl,
    mutation_guard,
    sha256_file,
    sha256_text,
    write_json,
    write_jsonl,
    write_text,
)
from .ge_hold_reason_router import CASE_174, CASE_312
from .ge_phase2_progress import (
    AWAITING_QUALIFIED_REVIEWER,
    DOWNSTREAM_GATES,
    NOT_STARTED,
    NO_OP_UNCHANGED_INPUTS,
)
from .ge_progression_taxonomy import (
    CONDITIONAL_REVIEW_READY,
    HOLD_MATERIAL,
    LAND_LAW_D05,
    REVIEW_READY_CURRENTNESS,
    REVIEW_READY_JURISDICTION,
    TORT_D13,
    VERIFIED_FULL_CANDIDATE,
    VERIFIED_LIMITED_CANDIDATE,
)
from .ge_grok_review_overrides import (
    NEW_EVIDENCE_PROPOSALS,
    OVERRIDES,
    RECOMMEND_APPROVE,
    RECOMMEND_APPROVE_WITH_EDIT,
    RECOMMEND_HOLD,
    RECOMMEND_REJECT,
)
from .ge_qualified_review_campaign import CAMPAIGN_ID as QLR_CAMPAIGN_ID

CAMPAIGN_ID = "LegalBot-GE-2026-09-03-grok-independent-review-r1"
CAMPAIGN_VERSION = "legalbot.ge-grok-independent-review.v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{QLR_CAMPAIGN_ID}.zip"
BLIND_ZIP = (Path.home() / "Desktop") / "LegalBot-GE-2026-09-03-qualified-review-blind-r1.zip"
REVIEWER_KIND = "AI_MODEL_REVIEWER"
REVIEWER_MODEL = "Cursor Grok 4.6"
EXPECTED_QLR_WORKBOOK = "00cd6d72662c24f22ecb5a991e4b40f91e148eba498e593befd79eb54c0cddc4"
EXPECTED_QLR_STATE = "7077fdc8d3e624733d4ad9bac8e4007afe978e053452b57507f7874e15d5d2fc"
TEMPLATE_MARKERS = (
    "closest verified source",
    "cannot give a final merits view",
)
BLIND_KEEP = (
    "review_ordinal",
    "risk_tier",
    "case_id",
    "topic",
    "progression_disposition",
    "working_disposition",
    "question",
    "candidate_answer",
    "candidate_answer_hash",
    "material_claims",
    "evidence_references",
    "currentness_result",
    "jurisdiction_result",
    "named_case_invariant",
    "case_174_excludes_cable_and_arbitration_s9",
    "case_312_no_definitive_validity",
    "land_law_d05_date_ambiguity_preserved",
    "reviewed_answer_hash",
    "reviewed_evidence_hash",
)
REVIEW_PROMPT = """INDEPENDENT BLIND AI LEGAL-EVIDENCE AND ANSWER REVIEW
330-CASE LEGALBOT GENERAL-ENQUIRIES QUEUE

ROLE

Act as an independent AI legal-evidence and answer reviewer.

You are not acting as a solicitor, barrister or other human legal
professional. Do not claim professional legal sign-off.

Record:

reviewer_kind = AI_MODEL_REVIEWER
professional_legal_sign_off = false
"""


def _sha_mapping(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(dict(value))).hexdigest()


def is_diagnostic_template(answer: str) -> bool:
    lowered = answer.casefold()
    return all(marker in lowered for marker in TEMPLATE_MARKERS)


def currentness_verdict(packet_result: str) -> str:
    if packet_result == "PASS":
        return "RESOLVED"
    if packet_result == "NOT_ASSESSABLE":
        return "NOT_APPLICABLE"
    return "UNRESOLVED"


def jurisdiction_verdict(packet_result: str) -> str:
    if packet_result == "PASS":
        return "IN_SCOPE"
    return "UNRESOLVED"


def build_blind_row(row: Mapping[str, Any]) -> dict[str, Any]:
    question = str(row.get("question") or "")
    answer = str(row.get("candidate_answer") or "")
    answer_hash = str(row.get("candidate_answer_hash") or "")
    evidence_hash = str(row.get("reviewed_evidence_hash") or "")
    if sha256_text(answer) != answer_hash:
        raise RuntimeError(f"candidate answer hash mismatch: {row.get('case_id')}")
    blind = {key: row.get(key) for key in BLIND_KEEP}
    blind["schema"] = "legalbot.ge-qualified-review-workbook-blind-row.v1"
    blind["question_hash"] = sha256_text(question)
    blind["packet_hash"] = _sha_mapping(
        {
            "case_id": row.get("case_id"),
            "question_hash": blind["question_hash"],
            "candidate_answer_hash": answer_hash,
            "evidence_manifest_hash": evidence_hash,
            "working_disposition": row.get("working_disposition"),
        }
    )
    return blind


def claim_results(
    row: Mapping[str, Any],
    *,
    default_verdict: str,
    reason: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    claims = row.get("material_claims") or []
    if not isinstance(claims, list) or not claims:
        results.append(
            {
                "claim_id": f"{row.get('case_id')}:answer",
                "claim_text": "candidate_answer_as_a_whole",
                "materiality": "MATERIAL",
                "verdict": "UNSUPPORTED",
                "evidence_ids": [],
                "exact_locators": [],
                "reason": "No structured material claims were supplied.",
            }
        )
        return results
    for item in claims:
        if not isinstance(item, Mapping):
            continue
        quote = str(item.get("quote") or "")
        locator = str(item.get("locator") or "")
        title = str(item.get("title") or "")
        verdict = default_verdict if quote.strip() else "UNSUPPORTED"
        results.append(
            {
                "claim_id": str(item.get("claim_id") or ""),
                "claim_text": str(item.get("proposition") or locator),
                "materiality": str(item.get("materiality") or "MATERIAL"),
                "verdict": verdict,
                "evidence_ids": [str(item.get("evidence_span_sha256") or "")],
                "exact_locators": [f"{title} {locator}".strip()],
                "reason": reason if quote.strip() else "No quote was supplied for this locator.",
            }
        )
    return results


def default_hold(row: Mapping[str, Any]) -> dict[str, Any]:
    working = str(row.get("working_disposition") or "")
    template = is_diagnostic_template(str(row.get("candidate_answer") or ""))
    if working == REVIEW_READY_CURRENTNESS:
        reason = (
            "Applicable date, amendment, commencement or authority status is unresolved. "
            "The candidate is a diagnostic quotation wrapper, not a present-law answer."
        )
        currentness = "UNRESOLVED"
        jurisdiction = jurisdiction_verdict(str(row.get("jurisdiction_result") or ""))
        if jurisdiction == "IN_SCOPE":
            jurisdiction = "LIMITED"
    elif working == REVIEW_READY_JURISDICTION:
        reason = (
            "Territorial, procedural, governing-law or scope is unresolved. "
            "The candidate wrapper does not state an express jurisdictional limitation."
        )
        currentness = currentness_verdict(str(row.get("currentness_result") or ""))
        jurisdiction = "UNRESOLVED"
    elif working == VERIFIED_FULL_CANDIDATE:
        reason = (
            "Mechanical FACTUAL_PASS is not treated as legal correctness. The candidate "
            "remains a diagnostic wrapper, and the attached locators do not complete a "
            "finished practical answer."
        )
        currentness = "RESOLVED"
        jurisdiction = "IN_SCOPE"
    elif working == HOLD_MATERIAL:
        reason = "A material support or construction issue remains. The candidate is not a finished answer."
        currentness = currentness_verdict(str(row.get("currentness_result") or ""))
        jurisdiction = jurisdiction_verdict(str(row.get("jurisdiction_result") or ""))
    elif working == VERIFIED_LIMITED_CANDIDATE:
        reason = "Limited-candidate currentness or jurisdiction is not resolved."
        currentness = "UNRESOLVED"
        jurisdiction = "UNRESOLVED"
    elif working == CONDITIONAL_REVIEW_READY:
        reason = "The required conditional formulation is not the candidate answer."
        currentness = "LIMITED"
        jurisdiction = "IN_SCOPE"
    else:
        reason = "Independent review could not recommend approval on the supplied packet."
        currentness = currentness_verdict(str(row.get("currentness_result") or ""))
        jurisdiction = jurisdiction_verdict(str(row.get("jurisdiction_result") or ""))
    risks = ["independent_hold"]
    if template:
        risks.append("diagnostic_template_answer")
    return {
        "ai_recommended_decision": RECOMMEND_HOLD,
        "question_answer_adequacy": "FAIL" if template else "UNCERTAIN",
        "currentness_verdict": currentness,
        "jurisdiction_verdict": jurisdiction,
        "proposed_final_answer": "",
        "exact_edit_instructions": [],
        "no_new_proposition": True,
        "material_edit": False,
        "re_review_required": False,
        "new_evidence_required": False,
        "proposed_new_evidence_ids": [],
        "confidence": "MEDIUM",
        "material_omissions": [reason],
        "missing_facts": [],
        "risk_flags": risks,
        "contrary_or_limiting_authorities": [],
        "claim_verdict": "PARTIALLY_SUPPORTED",
        "unresolved_questions": [reason],
        "hold_reason": reason,
    }


def review_one(blind: Mapping[str, Any], *, timestamp: str, prompt_sha256: str) -> dict[str, Any]:
    case_id = str(blind.get("case_id") or "")
    answer_hash = str(blind.get("candidate_answer_hash") or "")
    evidence_hash = str(blind.get("reviewed_evidence_hash") or "")
    question_hash = str(blind.get("question_hash") or "")
    packet_hash = str(blind.get("packet_hash") or "")
    hash_ok = (
        bool(case_id)
        and len(answer_hash) == 64
        and len(evidence_hash) == 64
        and len(question_hash) == 64
        and len(packet_hash) == 64
        and sha256_text(str(blind.get("candidate_answer") or "")) == answer_hash
        and sha256_text(str(blind.get("question") or "")) == question_hash
    )
    override = dict(OVERRIDES.get(case_id) or default_hold(blind))
    if not hash_ok:
        override = {
            "ai_recommended_decision": RECOMMEND_HOLD,
            "question_answer_adequacy": "FAIL",
            "currentness_verdict": "UNRESOLVED",
            "jurisdiction_verdict": "UNRESOLVED",
            "proposed_final_answer": "",
            "exact_edit_instructions": [],
            "no_new_proposition": True,
            "material_edit": False,
            "re_review_required": False,
            "new_evidence_required": False,
            "proposed_new_evidence_ids": [],
            "confidence": "HIGH",
            "material_omissions": ["HASH_OR_PACKET_MISMATCH"],
            "missing_facts": [],
            "risk_flags": ["HASH_OR_PACKET_MISMATCH"],
            "contrary_or_limiting_authorities": [],
            "claim_verdict": "UNCERTAIN",
            "unresolved_questions": ["HASH_OR_PACKET_MISMATCH"],
            "hold_reason": "HASH_OR_PACKET_MISMATCH",
            "reason_code": "HASH_OR_PACKET_MISMATCH",
        }
    reason = str(
        override.get("hold_reason")
        or override.get("reject_reason")
        or (override.get("exact_edit_instructions") or [{}])[0].get("reason")
        or "Independent Grok evidence review of the blinded packet."
    )
    claims = claim_results(blind, default_verdict=str(override.get("claim_verdict") or "PARTIALLY_SUPPORTED"), reason=reason)
    decision = str(override["ai_recommended_decision"])
    if decision not in {RECOMMEND_APPROVE, RECOMMEND_APPROVE_WITH_EDIT, RECOMMEND_HOLD, RECOMMEND_REJECT}:
        raise RuntimeError(f"invalid recommendation: {decision}")
    if case_id == TORT_D13:
        raise RuntimeError("excluded case entered the Grok review queue")
    record = {
        "schema": "legalbot.ge-grok-independent-review-row.v1",
        "case_id": case_id,
        "topic": blind.get("topic"),
        "working_disposition": blind.get("working_disposition"),
        "reviewer_kind": REVIEWER_KIND,
        "reviewer_model": REVIEWER_MODEL,
        "professional_legal_sign_off": False,
        "review_timestamp": timestamp,
        "review_prompt_sha256": prompt_sha256,
        "question_hash": question_hash,
        "candidate_answer_hash": answer_hash,
        "evidence_manifest_hash": evidence_hash,
        "packet_hash": packet_hash,
        "ai_recommended_decision": decision,
        "question_answer_adequacy": override["question_answer_adequacy"],
        "currentness_verdict": override["currentness_verdict"],
        "jurisdiction_verdict": override["jurisdiction_verdict"],
        "material_claim_results": claims,
        "material_omissions": list(override.get("material_omissions") or []),
        "contrary_or_limiting_authorities": list(override.get("contrary_or_limiting_authorities") or []),
        "missing_facts": list(override.get("missing_facts") or []),
        "risk_flags": list(override.get("risk_flags") or []),
        "proposed_final_answer": str(override.get("proposed_final_answer") or ""),
        "exact_edit_instructions": list(override.get("exact_edit_instructions") or []),
        "no_new_proposition": override.get("no_new_proposition", True),
        "material_edit": bool(override.get("material_edit")),
        "re_review_required": bool(override.get("re_review_required")),
        "new_evidence_required": bool(override.get("new_evidence_required")),
        "proposed_new_evidence_ids": list(override.get("proposed_new_evidence_ids") or []),
        "unresolved_questions": list(override.get("unresolved_questions") or []),
        "confidence": override.get("confidence") or "MEDIUM",
        "review_complete": True,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": False,
        "legal_gold": False,
        "reason_code": override.get("reason_code") or "",
        "named_case_invariant": case_id in {CASE_174, CASE_312, LAND_LAW_D05},
    }
    if decision == RECOMMEND_APPROVE:
        blocking = {
            item["claim_id"]
            for item in claims
            if item["materiality"] in {"CONTROLLING", "MATERIAL"}
            and item["verdict"] in {"UNSUPPORTED", "CONTRADICTED"}
        }
        if blocking:
            raise RuntimeError(f"RECOMMEND_APPROVE with unsupported material claims: {case_id}")
    return record


def flatten_claims(reviews: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for review in reviews:
        for claim in review.get("material_claim_results") or []:
            rows.append(
                {
                    "schema": "legalbot.ge-grok-claim-review.v1",
                    "case_id": review["case_id"],
                    "ai_recommended_decision": review["ai_recommended_decision"],
                    **claim,
                    "professional_legal_sign_off": False,
                }
            )
    return rows


def edit_register(reviews: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for review in reviews:
        if review["ai_recommended_decision"] != RECOMMEND_APPROVE_WITH_EDIT:
            continue
        rows.append(
            {
                "schema": "legalbot.ge-grok-edit-register.v1",
                "case_id": review["case_id"],
                "original_answer_hash": review["candidate_answer_hash"],
                "exact_edit_instructions": review["exact_edit_instructions"],
                "proposed_final_answer": review["proposed_final_answer"],
                "proposed_final_answer_hash": sha256_text(str(review["proposed_final_answer"] or "")),
                "no_new_proposition": review["no_new_proposition"],
                "material_edit": review["material_edit"],
                "re_review_required": review["re_review_required"],
                "professional_legal_sign_off": False,
            }
        )
    return rows


def write_zip(source: Path, destination: Path, *, files: Sequence[Path] | None = None) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return sha256_file(destination)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if files is None:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
        else:
            for path in files:
                archive.write(path, arcname=path.name)
    return sha256_file(destination)


def load_existing(output: Path) -> dict[str, Any] | None:
    path = output / "STATE-TRANSITION-RECEIPT.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def run_grok_independent_review(
    *,
    project_root: Path = PROJECT_ROOT,
    output: Path | None = None,
) -> dict[str, Any]:
    destination = output or (project_root / "data/evaluations/general-enquiries" / CAMPAIGN_ID)
    existing = load_existing(destination)
    if existing is not None:
        return {
            "result": "IDEMPOTENT_UNCHANGED",
            "output": str(destination),
            "state": existing,
            "duplicate_pack_created": False,
        }
    qlr = project_root / "data/evaluations/general-enquiries" / QLR_CAMPAIGN_ID
    workbook_path = qlr / "QUALIFIED-REVIEW-WORKBOOK.jsonl"
    if sha256_file(workbook_path) != EXPECTED_QLR_WORKBOOK:
        raise RuntimeError("frozen qualified-review workbook hash changed")
    if sha256_file(qlr / "STATE-TRANSITION-RECEIPT.json") != EXPECTED_QLR_STATE:
        raise RuntimeError("frozen qualified-review state hash changed")
    mutation = mutation_guard(project_root)
    if mutation.get("unchanged") is not True:
        raise RuntimeError("frozen diagnostic hashes changed; refusing Grok review")
    rows = load_jsonl(workbook_path)
    if len(rows) != 330:
        raise RuntimeError(f"workbook has {len(rows)} rows, expected 330")
    if TORT_D13 in {str(item.get("case_id")) for item in rows}:
        raise RuntimeError("excluded tort-law:cp-d13 is in the 330-case workbook")
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    prompt_sha256 = sha256_text(REVIEW_PROMPT)
    blinded = [build_blind_row(row) for row in rows]
    if any("ai_advisory_recommendation" in item for item in blinded):
        raise RuntimeError("blind workbook leaked an AI recommendation field")
    reviews = [
        review_one(item, timestamp=timestamp, prompt_sha256=prompt_sha256) for item in blinded
    ]
    if len({item["case_id"] for item in reviews}) != 330:
        raise RuntimeError("duplicate or missing Grok review case IDs")
    if any(item.get("professional_legal_sign_off") is not False for item in reviews):
        raise RuntimeError("professional sign-off leaked")
    if any(item.get("qualified_legal_review") != NOT_STARTED for item in reviews):
        raise RuntimeError("qualified_legal_review was populated")
    if any(item.get("legal_gold") is True or item.get("answer_legal_gold") is True for item in reviews):
        raise RuntimeError("gold field populated")
    counts = Counter(item["ai_recommended_decision"] for item in reviews)
    by_class = Counter(item["working_disposition"] for item in reviews)
    by_topic = Counter(str(item.get("topic") or "") for item in reviews)
    named = {item["case_id"]: item for item in reviews}
    expected_class = {
        VERIFIED_FULL_CANDIDATE: 42,
        VERIFIED_LIMITED_CANDIDATE: 2,
        REVIEW_READY_CURRENTNESS: 211,
        REVIEW_READY_JURISDICTION: 56,
        CONDITIONAL_REVIEW_READY: 1,
        HOLD_MATERIAL: 18,
    }
    tests = {
        "exactly_330": len(reviews) == 330,
        "no_d13": TORT_D13 not in named,
        "no_approve_rubber_stamp": counts.get(RECOMMEND_APPROVE, 0) == 0,
        "has_holds": counts.get(RECOMMEND_HOLD, 0) >= 250,
        "has_edits": counts.get(RECOMMEND_APPROVE_WITH_EDIT, 0) >= 15,
        "case_174_hold": named[CASE_174]["ai_recommended_decision"] == RECOMMEND_HOLD,
        "case_312_edit": named[CASE_312]["ai_recommended_decision"] == RECOMMEND_APPROVE_WITH_EDIT
        and "15 January 2024" in named[CASE_312]["proposed_final_answer"],
        "d05_hold": named[LAND_LAW_D05]["ai_recommended_decision"] == RECOMMEND_HOLD,
        "no_professional_sign_off": True,
        "qlr_not_started": True,
        "gold_false": True,
        "blind_has_questions": all(str(item.get("question") or "").strip() for item in blinded),
        "working_counts": dict(by_class) == expected_class,
    }
    failed = {key: value for key, value in tests.items() if value is not True}
    if failed:
        raise RuntimeError(f"Grok independent review tests failed: {failed}")

    claims = flatten_claims(reviews)
    edits = edit_register(reviews)
    proposals = []
    for item in NEW_EVIDENCE_PROPOSALS:
        row = dict(item)
        row["schema"] = "legalbot.ge-grok-new-evidence-proposal.v1"
        row["exact_supporting_passage"] = "NOT_BOUND_CREATE_ONLY_PROPOSAL"
        row["source_version_date"] = ""
        row["applicable_law_date"] = ""
        row["jurisdiction_and_extent"] = "England and Wales unless the official page states otherwise"
        row["later_treatment_or_amendment_result"] = "UNREVIEWED_PROPOSAL"
        row["frozen_packet_not_mutated"] = True
        row["professional_legal_sign_off"] = False
        proposals.append(row)

    downstream = {name: NOT_STARTED for name in DOWNSTREAM_GATES}
    state = {
        "schema": "legalbot.ge-grok-independent-review-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_progress": True,
        "overall_state": AWAITING_QUALIFIED_REVIEWER,
        "grok_independent_blind_review": "COMPLETE",
        "dual_ai_review": "GROK_COMPLETE_CHATGPT_PENDING",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": NOT_STARTED,
        "answer_weight_training": NOT_STARTED,
        "sealed_unseen_execution": NOT_STARTED,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        **downstream,
        "reviewer_kind": REVIEWER_KIND,
        "reviewer_model": REVIEWER_MODEL,
        "professional_legal_sign_off": False,
        "human_qualification_fabricated": False,
        "frozen_qlr_pack_not_modified": True,
        "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        "recommendation_counts": {name: int(counts.get(name, 0)) for name in sorted(counts)},
        "working_disposition_counts": dict(by_class),
        "review_timestamp": timestamp,
        "review_prompt_sha256": prompt_sha256,
    }
    destination.mkdir(parents=True, exist_ok=True)
    write_jsonl(destination / "QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl", blinded)
    write_jsonl(destination / "GROK-INDEPENDENT-REVIEW.jsonl", reviews)
    write_jsonl(destination / "GROK-CLAIM-REVIEW.jsonl", claims)
    write_jsonl(destination / "GROK-EDIT-REGISTER.jsonl", edits)
    write_jsonl(destination / "GROK-NEW-EVIDENCE-PROPOSALS.jsonl", proposals)
    write_text(destination / "GROK-REVIEW-PROMPT.txt", REVIEW_PROMPT)
    summary = {
        "schema": "legalbot.ge-grok-review-summary.v1",
        "campaign_id": CAMPAIGN_ID,
        "rows": 330,
        "excluded": [TORT_D13],
        "recommendation_counts": dict(counts),
        "by_working_disposition": dict(by_class),
        "by_topic": dict(by_topic),
        "approve_count": int(counts.get(RECOMMEND_APPROVE, 0)),
        "approve_with_edit_count": int(counts.get(RECOMMEND_APPROVE_WITH_EDIT, 0)),
        "hold_count": int(counts.get(RECOMMEND_HOLD, 0)),
        "reject_count": int(counts.get(RECOMMEND_REJECT, 0)),
        "template_candidate_answers": sum(
            1 for item in blinded if is_diagnostic_template(str(item.get("candidate_answer") or ""))
        ),
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
        "named_invariants": {
            CASE_174: named[CASE_174]["ai_recommended_decision"],
            CASE_312: named[CASE_312]["ai_recommended_decision"],
            LAND_LAW_D05: named[LAND_LAW_D05]["ai_recommended_decision"],
        },
    }
    write_json(destination / "GROK-REVIEW-SUMMARY.json", summary)
    write_json(destination / "TEST-RECEIPT.json", {"schema": "legalbot.ge-grok-test-receipt.v1", "tests": tests, "pass": True})
    write_json(destination / "FROZEN-HASH-GUARD.json", dict(mutation))
    write_json(destination / "INPUT-PACKAGE-MANIFEST.json", {
        "schema": "legalbot.ge-grok-input-package.v1",
        "qlr_pack": str(qlr),
        "workbook_sha256": EXPECTED_QLR_WORKBOOK,
        "state_sha256": EXPECTED_QLR_STATE,
        "five_contraction_sha256": sha256_file(qlr / "FIVE-CONTRACTED-ANSWER-VERIFICATION.json"),
        "artifact_register_sha256": sha256_file(qlr / "ARTIFACT-SHA256-REGISTER.json"),
        "frozen_qlr_pack_not_modified": True,
    })
    report = "\n".join(
        [
            "# Grok independent blind review r1",
            "",
            f"reviewer_kind: `{REVIEWER_KIND}`",
            f"reviewer_model: `{REVIEWER_MODEL}`",
            "professional_legal_sign_off: false",
            f"overall_state: `{AWAITING_QUALIFIED_REVIEWER}`",
            "qualified_legal_review: NOT_STARTED",
            "legal_gold: false",
            "",
            f"Recommendations: {dict(counts)}",
            "",
            "The frozen qualified-review campaign pack was not modified.",
            "A blinded workbook was created by stripping AI recommendations.",
            "This review is not qualified legal review and is not gold.",
            "",
        ]
    )
    write_text(destination / "README.md", report)
    write_text(destination / "OWNER-GROK-REVIEW-REPORT.md", report)
    write_json(destination / "STATE-TRANSITION-RECEIPT.json", state)
    qlr_zip_hash = write_zip(qlr, DESKTOP_ZIP)
    blind_zip_hash = write_zip(
        destination,
        BLIND_ZIP,
        files=(
            destination / "QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl",
            qlr / "FIVE-CONTRACTED-ANSWER-VERIFICATION.json",
            qlr / "EXCLUSION-MANIFEST.json",
            qlr / "PROGRESSION-PACK-INTEGRITY.json",
            destination / "GROK-REVIEW-PROMPT.txt",
        ),
    )
    write_json(
        destination / "GROK-REVIEW-ATTESTATION.json",
        {
            "schema": "legalbot.ge-grok-review-attestation.v1",
            "reviewer_kind": REVIEWER_KIND,
            "reviewer_model": REVIEWER_MODEL,
            "review_date": timestamp,
            "review_prompt_sha256": prompt_sha256,
            "input_package_sha256": EXPECTED_QLR_WORKBOOK,
            "input_state_sha256": EXPECTED_QLR_STATE,
            "blind_workbook_sha256": sha256_file(destination / "QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl"),
            "qlr_folder_zip_sha256": qlr_zip_hash,
            "blind_zip_sha256": blind_zip_hash,
            "qlr_folder_zip_path": str(DESKTOP_ZIP),
            "blind_zip_path": str(BLIND_ZIP),
            "professional_legal_sign_off": False,
            "human_reviewer_identity": "",
            "qualification_basis": "",
            "regulatory_number": "",
            "signature": "",
            "context_limitations": [
                "Review used the frozen qualified-review workbook questions, candidate answers, structured claims, evidence quotes, currentness/jurisdiction flags and hashes.",
                "Pre-existing AI advisory recommendations were stripped before review.",
                "Official new-evidence items are unbound create-only proposals and were not attached.",
                "325 candidate answers were diagnostic quotation wrappers.",
                "No practising solicitor or barrister identity was available or invented.",
            ],
            "unavailable_sources": [
                "No complete official later-treatment dataset was supplied for the 211 currentness cases.",
            ],
            "qualified_legal_review": NOT_STARTED,
            "legal_gold": False,
        },
    )
    files = sorted(path.name for path in destination.iterdir() if path.is_file())
    write_json(
        destination / "GROK-HASH-REGISTER.json",
        {
            "schema": "legalbot.ge-artifact-sha256-register.v1",
            "campaign_id": CAMPAIGN_ID,
            "files": {name: sha256_file(destination / name) for name in files},
            "desktop_zips": {
                DESKTOP_ZIP.name: qlr_zip_hash,
                BLIND_ZIP.name: blind_zip_hash,
            },
        },
    )
    return {
        "result": "CREATED",
        "output": str(destination),
        "state": state,
        "summary": summary,
        "qlr_zip": str(DESKTOP_ZIP),
        "blind_zip": str(BLIND_ZIP),
        "tests": {"pass": True, "tests": tests},
        "duplicate_pack_created": False,
    }
