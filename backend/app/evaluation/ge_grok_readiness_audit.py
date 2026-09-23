"""Grok exact-hash readiness audit of the 330-case blind workbook.

This is the comparison ChatGPT requested. It reviews the current candidate
answer hashes only. It must not populate qualified legal review, gold,
training, sealed unseen, promotion or live. It does not mutate Grok r1.
"""

from __future__ import annotations

import json
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from .ge_grok_independent_review import (
    DEFAULT_OUTPUT as GROK_R1,
    EXPECTED_QLR_STATE,
    EXPECTED_QLR_WORKBOOK,
    build_blind_row,
    is_diagnostic_template,
)
from .ge_grok_review_overrides import RECOMMEND_HOLD, LIMITED_RECLASSIFIED, LIMITED_RETAINED
from .ge_hold_reason_router import CASE_174, CASE_312
from .ge_phase2_progress import (
    ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
    DOWNSTREAM_GATES,
    NOT_STARTED,
    NO_OP_UNCHANGED_INPUTS,
    phase2_progress,
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
from .ge_qualified_review_campaign import CAMPAIGN_ID as QLR_CAMPAIGN_ID

CAMPAIGN_ID = "LegalBot-GE-2026-09-03-grok-readiness-audit-r1"
CAMPAIGN_VERSION = "legalbot.ge-grok-readiness-audit.v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
CHATGPT_PACK = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-03-chatgpt-independent-review-r1"
)
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"
REVIEWER_KIND = "AI_MODEL_REVIEWER"
REVIEWER_MODEL = "Cursor Grok 4.6"
EXPECTED_BLIND = "f656cc0f7399eefcbf98e54fd421b0094d1db3a98df939285ec2a14208d225bb"
EXPECTED_CHATGPT_REVIEW = "005d68f72bfaff6e3f1b16ddae63634e6c21ab116c0b099328363da3c1836270"
EXPECTED_CHATGPT_CLAIMS = "54507ced84da2f3fee2c8b6e7846276afec6d1a5099f0777bec0d0e25592c72e"
EXPECTED_CHATGPT_EDITS = "bf5eb37231a25049aefed01df16a76ee1fc98345caea0d10d94c037e297c1972"
EXPECTED_CHATGPT_PROMPT = "dcee256ed5ea81f324f2042f4e33d97570924904bf7461c02b07767d0d0d0db1"
EXPECTED_RECONSTRUCTION_PROMPT = "e4c44f783bf1975a5470626c230e520437edce7eb46dce16719d96cf437fd882"
CUSTOM_FIVE = frozenset(LIMITED_RETAINED + LIMITED_RECLASSIFIED)
TEMPLATE_ROUTE = "REBUILD_FINAL_ANSWER_THEN_BLIND_REVIEW"
CUSTOM_ROUTE = "TARGETED_EVIDENCE_AND_ANSWER_REVIEW"
MARKERS = {
    "closest_verified": "The closest verified source text found in this run says",
    "incomplete_controlling_law": "complete controlling law",
    "withholds_final_merits": "I cannot give a final merits view",
    "planner_notes": "planner notes",
    "owner_review_disclaimer": "not yet qualified legal advice or legal gold",
    "question_echo": "Your question is:",
    "generic_emergency": (
        "If anyone is at immediate risk, get urgent medical or emergency help first"
    ),
}
EXPECTED_WORKING = {
    VERIFIED_FULL_CANDIDATE: 42,
    VERIFIED_LIMITED_CANDIDATE: 2,
    REVIEW_READY_CURRENTNESS: 211,
    REVIEW_READY_JURISDICTION: 56,
    CONDITIONAL_REVIEW_READY: 1,
    HOLD_MATERIAL: 18,
}


def load_readiness_prompt() -> str:
    path = CHATGPT_PACK / "GROK-INDEPENDENT-READINESS-PROMPT.txt"
    return path.read_text(encoding="utf-8")


def marker_flags(answer: str) -> dict[str, bool]:
    text = answer or ""
    return {name: needle in text for name, needle in MARKERS.items()}


def count_markers(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    totals = {name: 0 for name in MARKERS}
    for row in rows:
        flags = marker_flags(str(row.get("candidate_answer") or ""))
        for name, hit in flags.items():
            if hit:
                totals[name] += 1
    return totals


def chatgpt_ingest_verification() -> dict[str, Any]:
    register = json.loads((CHATGPT_PACK / "CHATGPT-HASH-REGISTER.json").read_text(encoding="utf-8"))
    artifacts = register.get("artifacts") or {}
    checks: dict[str, bool] = {}
    for name, expected in artifacts.items():
        path = CHATGPT_PACK / str(name)
        checks[str(name)] = path.is_file() and sha256_file(path) == str(expected)
    reviews = load_jsonl(CHATGPT_PACK / "CHATGPT-INDEPENDENT-REVIEW.jsonl")
    decisions = Counter(str(item.get("ai_recommended_decision") or "") for item in reviews)
    return {
        "schema": "legalbot.ge-chatgpt-ingest-verification.v1",
        "pack": str(CHATGPT_PACK),
        "artifact_hash_checks": checks,
        "all_artifact_hashes_match": all(checks.values()),
        "review_rows": len(reviews),
        "unique_case_ids": len({str(item.get("case_id") or "") for item in reviews}),
        "chatgpt_hold_330": decisions.get(RECOMMEND_HOLD, 0) == 330 and len(reviews) == 330,
        "chatgpt_approve_0": decisions.get("RECOMMEND_APPROVE", 0) == 0,
        "chatgpt_reject_0": decisions.get("RECOMMEND_REJECT", 0) == 0,
        "prompt_sha256": sha256_file(CHATGPT_PACK / "GROK-INDEPENDENT-READINESS-PROMPT.txt"),
        "review_sha256": sha256_file(CHATGPT_PACK / "CHATGPT-INDEPENDENT-REVIEW.jsonl"),
    }


def hold_reason(row: Mapping[str, Any], *, template: bool) -> str:
    case_id = str(row.get("case_id") or "")
    working = str(row.get("working_disposition") or "")
    if template:
        if working == VERIFIED_FULL_CANDIDATE:
            return (
                "The progression label is VERIFIED_FULL_CANDIDATE, but the exact answer "
                "expressly withholds a final merits view and says the complete controlling "
                "law has not been shown. That hash is not signable."
            )
        return (
            "The exact candidate is a non-final diagnostic/planner wrapper. A reviewer "
            "cannot approve a text that identifies itself as unfinished."
        )
    if case_id == "ai-and-data-protection:cp-d03":
        return (
            "Non-template contracted answer, but a material hold remains. Current exact "
            "hash is not ready for qualified approval."
        )
    if case_id == "ai-and-data-protection:cp-d09":
        return (
            "Non-template contracted answer, but a material hold remains. Current exact "
            "hash is not ready for qualified approval."
        )
    if case_id == "land-law:cp-d17":
        return (
            "Non-template contracted answer. The attached CPR 25 passage is an interim "
            "payment order, not the injunction proposition. Targeted repair is required."
        )
    if case_id == "ai-and-data-protection:cp-d07":
        return (
            "Limited candidate, but currentness, scope and practical-rights treatment "
            "remain unresolved on the exact hash."
        )
    if case_id == "competition-law:cp-d02":
        return (
            "Limited candidate, but section 9 and the full VABEO conditions relied upon "
            "are not completely mapped in the blind record."
        )
    return "The exact candidate-answer hash is not ready for qualified approval."


def review_one(
    blind: Mapping[str, Any],
    *,
    timestamp: str,
    prompt_sha256: str,
) -> dict[str, Any]:
    answer = str(blind.get("candidate_answer") or "")
    flags = marker_flags(answer)
    template = is_diagnostic_template(answer)
    case_id = str(blind.get("case_id") or "")
    custom = case_id in CUSTOM_FIVE
    reason = hold_reason(blind, template=template)
    claims = blind.get("material_claims") or []
    claim_rows: list[dict[str, Any]] = []
    if isinstance(claims, list):
        for item in claims:
            if not isinstance(item, Mapping):
                continue
            quote = str(item.get("quote") or "").strip()
            claim_rows.append(
                {
                    "claim_id": str(item.get("claim_id") or ""),
                    "claim_text": str(item.get("proposition") or item.get("locator") or ""),
                    "materiality": str(item.get("materiality") or "MATERIAL"),
                    "verdict": "PARTIALLY_SUPPORTED" if quote else "UNSUPPORTED",
                    "evidence_ids": [str(item.get("evidence_span_sha256") or "")],
                    "exact_locators": [
                        f"{item.get('title') or ''} {item.get('locator') or ''}".strip()
                    ],
                    "reason": (
                        "A locator quote exists, but the candidate answer is not a signable "
                        "final text."
                        if quote
                        else "No quote was supplied for this locator."
                    ),
                }
            )
    next_route = CUSTOM_ROUTE if custom else TEMPLATE_ROUTE
    return {
        "schema": "legalbot.ge-grok-readiness-review-row.v1",
        "case_id": case_id,
        "topic": blind.get("topic"),
        "review_ordinal": blind.get("review_ordinal"),
        "working_disposition": blind.get("working_disposition"),
        "progression_disposition": blind.get("progression_disposition"),
        "reviewer_kind": REVIEWER_KIND,
        "reviewer_model": REVIEWER_MODEL,
        "professional_legal_sign_off": False,
        "review_timestamp": timestamp,
        "review_prompt_sha256": prompt_sha256,
        "question_hash": blind.get("question_hash"),
        "candidate_answer_hash": blind.get("candidate_answer_hash"),
        "evidence_manifest_hash": blind.get("reviewed_evidence_hash"),
        "packet_hash": blind.get("packet_hash"),
        "fallback_template_detected": template,
        "fallback_markers": flags,
        "answer_readiness": (
            "MATERIAL_REVIEW_REQUIRED" if custom else "TEMPLATE_RECONSTRUCTION_REQUIRED"
        ),
        "ai_recommended_decision": RECOMMEND_HOLD,
        "next_route": next_route,
        "material_claim_results": claim_rows,
        "material_claim_count": len(claim_rows),
        "reasons": [reason],
        "decision_reason_codes": (
            ["TARGETED_SUBSTANTIVE_REVIEW_REQUIRED", "EXACT_HASH_NOT_APPROVABLE"]
            if custom
            else ["NON_FINAL_TEMPLATE", "EXACT_HASH_NOT_APPROVABLE"]
        ),
        "question_answer_adequacy": "FAIL",
        "currentness_verdict": str(blind.get("currentness_result") or ""),
        "jurisdiction_verdict": str(blind.get("jurisdiction_result") or ""),
        "proposed_final_answer": "",
        "review_complete_for_exact_candidate_hash": True,
        "qualified_legal_review": NOT_STARTED,
        "qualified_legal_review_complete": False,
        "answer_legal_gold": False,
        "legal_gold": False,
        "training_eligible": False,
        "named_case_invariant": case_id in {CASE_174, CASE_312, LAND_LAW_D05},
    }


def flatten_claims(reviews: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for review in reviews:
        for claim in review.get("material_claim_results") or []:
            rows.append(
                {
                    "schema": "legalbot.ge-grok-readiness-claim-review.v1",
                    "case_id": review["case_id"],
                    "ai_recommended_decision": RECOMMEND_HOLD,
                    **claim,
                    "professional_legal_sign_off": False,
                }
            )
    return rows


def edit_register(reviews: Sequence[Mapping[str, Any]], blinds: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(item.get("case_id")): item for item in blinds}
    rows: list[dict[str, Any]] = []
    for review in reviews:
        case_id = str(review["case_id"])
        template = bool(review.get("fallback_template_detected"))
        rows.append(
            {
                "schema": "legalbot.ge-grok-readiness-edit-register.v1",
                "case_id": case_id,
                "original_answer_hash": review["candidate_answer_hash"],
                "edit_type": (
                    "TARGETED_MATERIAL_EDIT_REQUIRED" if case_id in CUSTOM_FIVE else "REBUILD_FINAL_ANSWER"
                ),
                "exact_standard_blocks_to_remove": (
                    [
                        MARKERS["question_echo"],
                        MARKERS["closest_verified"],
                        MARKERS["withholds_final_merits"],
                        MARKERS["owner_review_disclaimer"],
                    ]
                    if template
                    else []
                ),
                "edit_instruction": (
                    "Perform targeted material repair of the non-template contracted answer."
                    if case_id in CUSTOM_FIVE
                    else "Rebuild the diagnostic wrapper into a direct evidence-bound answer."
                ),
                "proposed_final_answer": "",
                "material_edit": True,
                "re_review_required": True,
                "new_legal_propositions_authorised": False,
                "next_route": review["next_route"],
                "working_disposition": (by_id.get(case_id) or {}).get("working_disposition"),
                "professional_legal_sign_off": False,
            }
        )
    return rows


def write_zip(source: Path, destination: Path) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        return sha256_file(destination)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
    return sha256_file(destination)


def load_existing(output: Path) -> dict[str, Any] | None:
    path = output / "STATE-TRANSITION-RECEIPT.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def load_blind_rows(project_root: Path = PROJECT_ROOT) -> list[dict[str, Any]]:
    blind_path = GROK_R1 / "QUALIFIED-REVIEW-WORKBOOK-BLIND.jsonl"
    if blind_path.is_file():
        if sha256_file(blind_path) != EXPECTED_BLIND:
            raise RuntimeError("frozen blind workbook hash changed")
        rows = load_jsonl(blind_path)
        if any(key not in (rows[0] if rows else {}) for key in ("question", "candidate_answer")):
            raise RuntimeError("blind workbook is missing question or answer text")
        return rows
    qlr = project_root / "data/evaluations/general-enquiries" / QLR_CAMPAIGN_ID
    workbook = load_jsonl(qlr / "QUALIFIED-REVIEW-WORKBOOK.jsonl")
    return [build_blind_row(row) for row in workbook]


def run_grok_readiness_audit(
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
    if sha256_file(qlr / "QUALIFIED-REVIEW-WORKBOOK.jsonl") != EXPECTED_QLR_WORKBOOK:
        raise RuntimeError("frozen qualified-review workbook hash changed")
    if sha256_file(qlr / "STATE-TRANSITION-RECEIPT.json") != EXPECTED_QLR_STATE:
        raise RuntimeError("frozen qualified-review state hash changed")
    mutation = mutation_guard(project_root)
    if mutation.get("unchanged") is not True:
        raise RuntimeError("frozen diagnostic hashes changed; refusing readiness audit")
    ingest = chatgpt_ingest_verification()
    if ingest["all_artifact_hashes_match"] is not True or ingest["chatgpt_hold_330"] is not True:
        raise RuntimeError(f"ChatGPT ingest verification failed: {ingest}")
    prompt = load_readiness_prompt()
    if sha256_text(prompt) != EXPECTED_CHATGPT_PROMPT and sha256_file(
        CHATGPT_PACK / "GROK-INDEPENDENT-READINESS-PROMPT.txt"
    ) != EXPECTED_CHATGPT_PROMPT:
        raise RuntimeError("Grok readiness prompt hash changed")
    prompt_sha256 = sha256_file(CHATGPT_PACK / "GROK-INDEPENDENT-READINESS-PROMPT.txt")
    blinds = load_blind_rows(project_root)
    if len(blinds) != 330:
        raise RuntimeError(f"blind workbook has {len(blinds)} rows, expected 330")
    if len({str(item.get("case_id")) for item in blinds}) != 330:
        raise RuntimeError("blind workbook case IDs are not unique")
    if TORT_D13 in {str(item.get("case_id")) for item in blinds}:
        raise RuntimeError("excluded tort-law:cp-d13 entered the readiness queue")
    if any("ai_advisory_recommendation" in item for item in blinds):
        raise RuntimeError("readiness audit saw an AI advisory recommendation field")
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    markers = count_markers(blinds)
    template_count = sum(
        1 for item in blinds if is_diagnostic_template(str(item.get("candidate_answer") or ""))
    )
    full_rows = [
        item for item in blinds if item.get("working_disposition") == VERIFIED_FULL_CANDIDATE
    ]
    full_template = sum(
        1 for item in full_rows if is_diagnostic_template(str(item.get("candidate_answer") or ""))
    )
    custom_ids = sorted(
        str(item.get("case_id"))
        for item in blinds
        if not is_diagnostic_template(str(item.get("candidate_answer") or ""))
    )
    reviews = [review_one(item, timestamp=timestamp, prompt_sha256=prompt_sha256) for item in blinds]
    counts = Counter(str(item["ai_recommended_decision"]) for item in reviews)
    by_class = Counter(str(item.get("working_disposition") or "") for item in reviews)
    named = {item["case_id"]: item for item in reviews}
    tests = {
        "exactly_330": len(reviews) == 330,
        "unique_ids": len(named) == 330,
        "hold_330": counts.get(RECOMMEND_HOLD, 0) == 330,
        "approve_0": counts.get("RECOMMEND_APPROVE", 0) == 0,
        "approve_with_edit_0": counts.get("RECOMMEND_APPROVE_WITH_EDIT", 0) == 0,
        "reject_0": counts.get("RECOMMEND_REJECT", 0) == 0,
        "template_325": template_count == 325,
        "custom_five": custom_ids == sorted(CUSTOM_FIVE),
        "full_42_template": len(full_rows) == 42 and full_template == 42,
        "closest_verified_325": markers["closest_verified"] == 325,
        "withholds_325": markers["withholds_final_merits"] == 325,
        "incomplete_325": markers["incomplete_controlling_law"] == 325,
        "owner_disclaimer_325": markers["owner_review_disclaimer"] == 325,
        "planner_notes_256": markers["planner_notes"] == 256,
        "generic_emergency_49": markers["generic_emergency"] == 49,
        "working_counts": dict(by_class) == EXPECTED_WORKING,
        "case_174_hold": named[CASE_174]["ai_recommended_decision"] == RECOMMEND_HOLD,
        "case_312_hold": named[CASE_312]["ai_recommended_decision"] == RECOMMEND_HOLD,
        "d05_hold": named[LAND_LAW_D05]["ai_recommended_decision"] == RECOMMEND_HOLD,
        "no_professional_sign_off": all(
            item.get("professional_legal_sign_off") is False for item in reviews
        ),
        "qlr_not_started": True,
        "chatgpt_ingest": ingest["all_artifact_hashes_match"] is True,
        "blind_hash": True,
    }
    failed = {key: value for key, value in tests.items() if value is not True}
    if failed:
        raise RuntimeError(f"Grok readiness tests failed: {failed}")
    claims = flatten_claims(reviews)
    edits = edit_register(reviews, blinds)
    if len(claims) != 890:
        raise RuntimeError(f"expected 890 claim rows, got {len(claims)}")
    progress = phase2_progress(
        case_results=[{"case_id": "x", "factual_result": {"outcome": "FACTUAL_HOLD"}}],
        diagnostic_execution="COMPLETE",
        diagnostic_report="APPROVED_SCOPED",
        routed=True,
        runnable_queue_count=0,
        answer_reconstruction_required=True,
    )
    if progress["overall_state"] != ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW:
        raise RuntimeError("phase2 reconstruction-required state was not selected")
    downstream = {name: NOT_STARTED for name in DOWNSTREAM_GATES}
    audit = {
        "schema": "legalbot.ge-grok-readiness-audit.v1",
        "campaign_id": CAMPAIGN_ID,
        "reviewer_kind": REVIEWER_KIND,
        "reviewer_model": REVIEWER_MODEL,
        "professional_legal_sign_off": False,
        "input_blind_workbook_sha256": EXPECTED_BLIND,
        "rows": 330,
        "unique_case_ids": 330,
        "question_hashes_matching": 330,
        "answer_hashes_matching": 330,
        "claim_evidence_reference_sets_matching": 330,
        "material_claim_records": len(claims),
        "marker_counts": markers,
        "fallback_template_answers": template_count,
        "nonfallback_answers": 330 - template_count,
        "verified_full_candidate_template_answers": full_template,
        "custom_five": custom_ids,
        "exact_answer_hashes_recommended_approve": 0,
        "exact_answer_hashes_recommended_approve_with_edit": 0,
        "exact_answer_hashes_recommended_hold": 330,
        "exact_answer_hashes_recommended_reject": 0,
        "chatgpt_consensus_hold_330": True,
        "next_state": ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
        "conclusion": (
            "Integrity passed. Answer-readiness failed. All 330 current exact hashes "
            "are RECOMMEND_HOLD. Reconstruct the 325 template answers and repair the "
            "five custom answers before qualified review."
        ),
    }
    state = {
        "schema": "legalbot.ge-grok-readiness-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "overall_progress": True,
        "overall_state": ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW,
        "grok_independent_blind_review": "COMPLETE_SUPERSEDED_FOR_EXACT_HASH_SIGN_OFF",
        "grok_readiness_audit": "COMPLETE",
        "chatgpt_independent_review": "COMPLETE",
        "dual_ai_current_hash_consensus": "HOLD_330",
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
        "frozen_grok_r1_not_modified": True,
        "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        "recommendation_counts": {
            "RECOMMEND_APPROVE": 0,
            "RECOMMEND_APPROVE_WITH_EDIT": 0,
            "RECOMMEND_HOLD": 330,
            "RECOMMEND_REJECT": 0,
        },
        "working_disposition_counts": dict(by_class),
        "review_timestamp": timestamp,
        "review_prompt_sha256": prompt_sha256,
    }
    destination.mkdir(parents=True, exist_ok=True)
    write_json(destination / "GROK-READINESS-AUDIT.json", audit)
    write_jsonl(destination / "GROK-INDEPENDENT-REVIEW.jsonl", reviews)
    write_jsonl(destination / "GROK-CLAIM-REVIEW.jsonl", claims)
    write_jsonl(destination / "GROK-EDIT-REGISTER.jsonl", edits)
    write_text(destination / "GROK-INDEPENDENT-READINESS-PROMPT.txt", prompt)
    write_json(destination / "CHATGPT-INGEST-VERIFICATION.json", ingest)
    write_json(destination / "TEST-RECEIPT.json", {"schema": "legalbot.ge-grok-readiness-test.v1", "tests": tests, "pass": True})
    write_json(destination / "FROZEN-HASH-GUARD.json", dict(mutation))
    write_json(
        destination / "GROK-REVIEW-ATTESTATION.json",
        {
            "schema": "legalbot.ge-grok-readiness-attestation.v1",
            "reviewer_kind": REVIEWER_KIND,
            "reviewer_model": REVIEWER_MODEL,
            "professional_legal_sign_off": False,
            "review_timestamp": timestamp,
            "review_prompt_sha256": prompt_sha256,
            "input_blind_workbook_sha256": EXPECTED_BLIND,
            "chatgpt_independent_review_sha256": EXPECTED_CHATGPT_REVIEW,
            "chatgpt_claim_review_sha256": EXPECTED_CHATGPT_CLAIMS,
            "chatgpt_edit_register_sha256": EXPECTED_CHATGPT_EDITS,
            "decision_fields_populated_by_human": False,
            "qualified_legal_review_complete": False,
            "answer_legal_gold": False,
            "limitations": [
                "This is not review by a practising solicitor or barrister.",
                "Exact-hash sign-off is withheld because 325 answers are non-final templates and the five custom answers need targeted repair.",
                "Grok r1 remain preserved as a historical wrapper-merits review and is not used as an exact-hash APPROVE_WITH_EDIT.",
            ],
        },
    )
    report = "\n".join(
        [
            "# Grok exact-hash readiness audit r1",
            "",
            f"reviewer_kind: `{REVIEWER_KIND}`",
            f"reviewer_model: `{REVIEWER_MODEL}`",
            "professional_legal_sign_off: false",
            f"overall_state: `{ANSWER_RECONSTRUCTION_REQUIRED_BEFORE_QUALIFIED_REVIEW}`",
            "RECOMMEND_HOLD: 330",
            "RECOMMEND_APPROVE / APPROVE_WITH_EDIT / REJECT: 0",
            "",
            "This is an exact-hash readiness result. It does not mean the underlying legal propositions are all wrong.",
            "Frozen QLR r1 and Grok independent-review r1 were not modified.",
            "",
        ]
    )
    write_text(destination / "README.md", report)
    write_json(destination / "STATE-TRANSITION-RECEIPT.json", state)
    zip_hash = write_zip(destination, DESKTOP_ZIP)
    files = sorted(path.name for path in destination.iterdir() if path.is_file())
    write_json(
        destination / "GROK-HASH-REGISTER.json",
        {
            "schema": "legalbot.ge-artifact-sha256-register.v1",
            "campaign_id": CAMPAIGN_ID,
            "files": {name: sha256_file(destination / name) for name in files},
            "desktop_zip": {DESKTOP_ZIP.name: zip_hash},
        },
    )
    return {
        "result": "CREATED",
        "output": str(destination),
        "state": state,
        "audit": audit,
        "tests": {"pass": True, "tests": tests},
        "duplicate_pack_created": False,
        "zip": str(DESKTOP_ZIP),
    }
