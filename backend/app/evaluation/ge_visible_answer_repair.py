"""Create and verify the bounded visible repair of failed r2 adapter answers.

This lane changes answer text only. It does not train weights, activate the
adapter, inspect private unseen material, or create legal gold.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ge_currentness_packets import PROJECT_ROOT, load_jsonl, sha256_file, sha256_text
from .ge_visible_harness import FACTUAL_CHECKS, QUALITY_CRITICAL_FLOORS, QUALITY_DIMENSION_MAX

SOURCE_CAMPAIGN_ID = "LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2"
SOURCE_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / SOURCE_CAMPAIGN_ID
CAMPAIGN_ID = "LegalBot-GE-2026-09-04-visible-answer-repair-r1"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
EXPECTED_SOURCE_STATE_SHA256 = "ba7c86cfd6c21985a7944f9d75ca045abc3995aa2a60c597c22a6a2b2e576f74"

REPAIR_CASE_IDS = (
    "administrative-law:fv-r1-01",
    "commercial-law:fv-r1-01",
    "competition-law:fv-r1-01",
    "contemporary-biolaw-and-regulation:fv-r1-01",
    "contract-law:fv-r1-01",
    "criminal-law:fv-r1-01",
    "eu-internal-market-law:fv-r1-01",
    "land-law:fv-r1-01",
    "law-and-medicine:fv-r1-01",
    "pensions-law:fv-r1-01",
    "private-international-law:fv-r1-01",
    "housing:fv-r1-01",
    "employment:fv-r1-01",
    "family:fv-r1-01",
    "consumer:fv-r1-01",
)

PROHIBITED_PLANNER_PHRASES = (
    "cannot give a final merits view",
    "complete controlling law has not been shown",
    "candidate answer for owner review",
    "source extract",
    "internal planner",
)


class VisibleAnswerRepairError(ValueError):
    """The visible repair input, review, or gate is invalid."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sealed(payload: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(payload)
    result["content_sha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def _write_json_create(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _write_jsonl_create(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    with path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def surface_guard(answer: str) -> list[str]:
    """Return deterministic defects that make a repaired answer nonreviewable."""

    stripped = answer.strip()
    defects: list[str] = []
    word_count = len(stripped.split())
    if word_count < 60:
        defects.append("TOO_SHORT_FOR_MATERIAL_ANSWER")
    if word_count > 260:
        defects.append("EXCEEDS_260_WORD_REPAIR_LIMIT")
    terminal = stripped.rstrip("\"'”’)]}")
    if not terminal.endswith((".", "?", "!")):
        defects.append("INCOMPLETE_FINAL_SENTENCE")
    lowered = stripped.casefold()
    if any(phrase in lowered for phrase in PROHIBITED_PLANNER_PHRASES):
        defects.append("PLANNER_OR_NONFINAL_LANGUAGE")
    return defects


def _source_adapter_reviews() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = load_jsonl(SOURCE_ROOT / "CODEX-REVIEW-WITH-VARIANTS.jsonl")
    adapter = [row for row in rows if row["candidate_variant"] == "R2_ADAPTER"]
    ready = [row for row in adapter if row["quality_gate_pass"] is True]
    repair = [row for row in adapter if row["quality_gate_pass"] is not True]
    if len(adapter) != 23 or len(ready) != 8 or len(repair) != 15:
        raise VisibleAnswerRepairError("source adapter disposition counts changed")
    if {row["case_id"] for row in repair} != set(REPAIR_CASE_IDS):
        raise VisibleAnswerRepairError("source repair case set changed")
    return ready, repair


def prepare_campaign(
    repaired_answers: Mapping[str, str],
    output: Path = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    """Bind 15 owner-directed Codex repairs into a changed-answer workbook."""

    if output.exists():
        raise VisibleAnswerRepairError(f"refusing to replace output: {output}")
    if sha256_file(SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json") != EXPECTED_SOURCE_STATE_SHA256:
        raise VisibleAnswerRepairError("source visible-evaluation state changed")
    source_state = json.loads((SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json").read_text())
    if (
        source_state["overall_state"]
        != "FRESH_VISIBLE_ADAPTER_EVALUATION_HOLD_VISIBLE_REPAIR_REQUIRED"
    ):
        raise VisibleAnswerRepairError("source state is not the expected visible hold")
    if source_state["private_306_bank"] != "SEALED_NOT_OPENED":
        raise VisibleAnswerRepairError("private unseen custody is not sealed")
    ready, repair = _source_adapter_reviews()
    if set(repaired_answers) != set(REPAIR_CASE_IDS):
        raise VisibleAnswerRepairError("repair answer set must contain exactly 15 cases")

    source_workbook = {
        (row["case_id"], row["candidate_answer_hash"]): row
        for row in load_jsonl(SOURCE_ROOT / "BLIND-REVIEW-WORKBOOK.jsonl")
    }
    repair_rows: list[dict[str, Any]] = []
    workbook_rows: list[dict[str, Any]] = []
    new_hashes: set[str] = set()
    for source_review in sorted(repair, key=lambda row: row["case_id"]):
        case_id = source_review["case_id"]
        answer = repaired_answers[case_id].strip()
        defects = surface_guard(answer)
        if defects:
            raise VisibleAnswerRepairError(f"surface guard failed for {case_id}: {defects}")
        answer_hash = sha256_text(answer)
        if answer_hash == source_review["candidate_answer_hash"]:
            raise VisibleAnswerRepairError(f"repair did not change exact answer: {case_id}")
        if answer_hash in new_hashes:
            raise VisibleAnswerRepairError("duplicate repaired answer hash")
        new_hashes.add(answer_hash)
        source_row = source_workbook[(case_id, source_review["candidate_answer_hash"])]
        repair_row = _sealed(
            {
                "schema": "legalbot.ge-visible-answer-repair.v1",
                "case_id": case_id,
                "question_hash": source_row["question_hash"],
                "original_adapter_answer": source_row["candidate_answer"],
                "original_adapter_answer_hash": source_review["candidate_answer_hash"],
                "original_factual_outcome": source_review["factual_outcome"],
                "original_quality_outcome": source_review["quality_outcome"],
                "original_assessment_summary": source_review["assessment_summary"],
                "repaired_answer": answer,
                "repaired_answer_hash": answer_hash,
                "surface_guard": "PASS",
                "surface_word_count": len(answer.split()),
                "evidence_references": source_row["evidence_references"],
            }
        )
        repair_rows.append(repair_row)
        workbook_rows.append(
            {
                "schema": "legalbot.ge-visible-changed-answer-review-row.v1",
                "case_id": case_id,
                "question": source_row["question"],
                "question_hash": source_row["question_hash"],
                "candidate_answer": answer,
                "candidate_answer_hash": answer_hash,
                "evidence_references": source_row["evidence_references"],
                "required_points": source_row["required_points"],
                "material_limits": source_row["material_limits"],
                "prohibited_overclaims": source_row["prohibited_overclaims"],
            }
        )

    output.mkdir(parents=True)
    _write_jsonl_create(output / "REPAIRED-ANSWERS.jsonl", repair_rows)
    _write_jsonl_create(output / "CHANGED-ANSWER-REVIEW-WORKBOOK.jsonl", workbook_rows)
    _write_json_create(
        output / "OWNER-ROUTE-CONTINUATION.json",
        _sealed(
            {
                "schema": "legalbot.ge-visible-repair-owner-route.v1",
                "owner_instruction": "Repair the 15 nonready visible answers, run changed-answer checks and another fresh visible evaluation; determine whether training or unseen is next.",
                "route": "NON_WEIGHT_VISIBLE_ANSWER_REPAIR",
                "further_training_authorized": False,
                "private_unseen_authorized": False,
                "private_306_bank": "SEALED_NOT_OPENED",
            }
        ),
    )
    preparation = _sealed(
        {
            "schema": "legalbot.ge-visible-answer-repair-preparation.v1",
            "campaign_id": CAMPAIGN_ID,
            "source_campaign_id": SOURCE_CAMPAIGN_ID,
            "source_state_sha256": EXPECTED_SOURCE_STATE_SHA256,
            "unchanged_adapter_full_pass_count": len(ready),
            "changed_answer_count": len(repair_rows),
            "changed_answer_workbook_sha256": sha256_file(
                output / "CHANGED-ANSWER-REVIEW-WORKBOOK.jsonl"
            ),
            "weight_training": "NOT_AUTHORIZED_NOT_PERFORMED",
            "private_306_bank": "SEALED_NOT_OPENED",
            "adapter_runtime_activation": "NOT_AUTHORIZED_NOT_PERFORMED",
            "prepared_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    _write_json_create(output / "PREPARATION-MANIFEST.json", preparation)
    return {
        "output": str(output),
        "changed_answer_count": len(repair_rows),
        "unchanged_full_pass_count": len(ready),
        "workbook_sha256": sha256_file(output / "CHANGED-ANSWER-REVIEW-WORKBOOK.jsonl"),
    }


def _quality_pass(scores: Mapping[str, Any]) -> bool:
    if set(scores) != set(QUALITY_DIMENSION_MAX):
        return False
    if any(
        float(scores[name]) < 0 or float(scores[name]) > maximum
        for name, maximum in QUALITY_DIMENSION_MAX.items()
    ):
        return False
    return sum(float(value) for value in scores.values()) >= 70 and all(
        float(scores[name]) >= floor for name, floor in QUALITY_CRITICAL_FLOORS.items()
    )


def finalize_campaign(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Validate changed-answer reviews and seal the visible repair result."""

    if (output / "STATE-TRANSITION-RECEIPT.json").exists():
        raise VisibleAnswerRepairError("refusing to replace finalized repair campaign")
    workbook = load_jsonl(output / "CHANGED-ANSWER-REVIEW-WORKBOOK.jsonl")
    reviews = load_jsonl(output / "CODEX-CHANGED-ANSWER-REVIEW.jsonl")
    expected = {(row["case_id"], row["candidate_answer_hash"]) for row in workbook}
    actual = {(row["case_id"], row["candidate_answer_hash"]) for row in reviews}
    if len(workbook) != 15 or len(reviews) != 15 or expected != actual:
        raise VisibleAnswerRepairError("changed-answer review does not cover all 15 hashes")
    workbook_by_case = {row["case_id"]: row for row in workbook}
    claim_count = 0
    factual_pass_count = 0
    quality_pass_count = 0
    for review in reviews:
        if review.get("reviewer_kind") != "AI_MODEL_REVIEWER":
            raise VisibleAnswerRepairError("reviewer kind must remain AI_MODEL_REVIEWER")
        if review.get("professional_legal_sign_off") is not False:
            raise VisibleAnswerRepairError("AI review cannot claim professional sign-off")
        claims = review.get("material_claims")
        if not isinstance(claims, list) or not claims:
            raise VisibleAnswerRepairError("material claims are required")
        allowed = {
            item["evidence_span_sha256"]
            for item in workbook_by_case[review["case_id"]]["evidence_references"]
        }
        for claim in claims:
            if claim.get("support_status") not in {"SUPPORTED", "UNSUPPORTED"}:
                raise VisibleAnswerRepairError("invalid material claim support status")
            hashes = claim.get("evidence_span_sha256")
            if not isinstance(hashes, list):
                raise VisibleAnswerRepairError("material claim evidence list missing")
            if claim["support_status"] == "SUPPORTED" and (
                not hashes or not set(hashes) <= allowed
            ):
                raise VisibleAnswerRepairError("supported claim lacks allowed evidence")
            claim_count += 1
        if set(review.get("factual_checks", {})) != set(FACTUAL_CHECKS):
            raise VisibleAnswerRepairError("factual check set mismatch")
        factual_pass = (
            review.get("material_proposition_coverage_complete") is True
            and all(claim["support_status"] == "SUPPORTED" for claim in claims)
            and all(
                value in {"PASS", "NOT_APPLICABLE"} for value in review["factual_checks"].values()
            )
        )
        if review.get("factual_outcome") != ("FACTUAL_PASS" if factual_pass else "FACTUAL_HOLD"):
            raise VisibleAnswerRepairError("factual outcome mismatch")
        scores = review.get("quality_dimensions", {})
        if factual_pass:
            if set(scores) != set(QUALITY_DIMENSION_MAX):
                raise VisibleAnswerRepairError("quality dimensions missing")
            total = round(sum(float(value) for value in scores.values()), 2)
            if float(review.get("quality_score", -1)) != total:
                raise VisibleAnswerRepairError("quality total mismatch")
            quality_pass = _quality_pass(scores)
            expected_quality = "MEETS_70_STANDARD" if quality_pass else "BELOW_70_OR_CRITICAL_FLOOR"
        else:
            if scores or review.get("quality_score") is not None:
                raise VisibleAnswerRepairError("factual hold must not receive a quality score")
            quality_pass = False
            expected_quality = "NOT_SCORED_FACTUAL_HOLD"
        if review.get("quality_outcome") != expected_quality:
            raise VisibleAnswerRepairError("quality outcome mismatch")
        factual_pass_count += int(factual_pass)
        quality_pass_count += int(quality_pass)

    ready, _ = _source_adapter_reviews()
    projected_factual_pass = len(ready) + factual_pass_count
    projected_quality_pass = len(ready) + quality_pass_count
    repair_pass = factual_pass_count == 15 and quality_pass_count == 15
    overall_state = (
        "VISIBLE_REPAIR_COMPLETE_AWAITING_NEW_FRESH_VISIBLE_EVALUATION"
        if repair_pass
        else "VISIBLE_REPAIR_INCOMPLETE_FURTHER_VISIBLE_REPAIR_REQUIRED"
    )
    next_gate = "NEW_FRESH_VISIBLE_EVALUATION" if repair_pass else "VISIBLE_REPAIR_ONLY"
    metrics = _sealed(
        {
            "schema": "legalbot.ge-visible-answer-repair-metrics.v1",
            "campaign_id": CAMPAIGN_ID,
            "changed_answer_count": 15,
            "changed_factual_pass_count": factual_pass_count,
            "changed_quality_pass_count": quality_pass_count,
            "unchanged_prior_full_pass_count": len(ready),
            "projected_visible_factual_pass_count": projected_factual_pass,
            "projected_visible_quality_pass_count": projected_quality_pass,
            "projected_visible_denominator": 23,
            "declared_material_claim_count": claim_count,
            "declared_material_claim_checked_count": claim_count,
            "declared_material_claim_review_coverage_pct": 100.0,
            "repair_pass": repair_pass,
            "fresh_generalisation_claim": False,
        }
    )
    _write_json_create(output / "METRIC-REPORT.json", metrics)
    state = _sealed(
        {
            "schema": "legalbot.ge-visible-answer-repair-state.v1",
            "campaign_id": CAMPAIGN_ID,
            "overall_state": overall_state,
            "visible_repair": "PASS" if repair_pass else "HOLD",
            "private_306_bank": "SEALED_NOT_OPENED",
            "weight_training": "NOT_AUTHORIZED_NOT_PERFORMED",
            "adapter_runtime_activation": "NOT_AUTHORIZED_NOT_PERFORMED",
            "qualified_legal_review": "NOT_STARTED",
            "answer_legal_gold": "NOT_STARTED",
            "sealed_unseen_execution": "NOT_STARTED",
            "promotion": "NOT_STARTED",
            "live": "NOT_STARTED",
            "next_owner_gate": next_gate,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        }
    )
    _write_json_create(output / "STATE-TRANSITION-RECEIPT.json", state)
    readme = f"""# {CAMPAIGN_ID}

This create-only campaign repairs only the 15 nonready adapter answers from
`{SOURCE_CAMPAIGN_ID}`. It changes answer text, not model weights, runtime
configuration or unseen custody.

## Result

- Changed answers: {factual_pass_count}/15 factual pass;
  {quality_pass_count}/15 meet 70+ and every critical floor.
- Prior unchanged full passes: {len(ready)}/8.
- Projected visible set: {projected_factual_pass}/23 factual and
  {projected_quality_pass}/23 full pass.
- State: `{overall_state}`.

The repaired questions are now exposed visible diagnostics. Even a 23/23
projection is not fresh generalisation evidence. A separate new visible set is
required before any unseen decision. The private 306-case bank remains sealed.
"""
    with (output / "README.md").open("x", encoding="utf-8") as handle:
        handle.write(readme)
    manifest = _sealed(
        {
            "schema": "legalbot.ge-visible-answer-repair-run.v1",
            "campaign_id": CAMPAIGN_ID,
            "source_state_sha256": EXPECTED_SOURCE_STATE_SHA256,
            "repaired_answers_sha256": sha256_file(output / "REPAIRED-ANSWERS.jsonl"),
            "changed_answer_review_sha256": sha256_file(
                output / "CODEX-CHANGED-ANSWER-REVIEW.jsonl"
            ),
            "metric_report_sha256": sha256_file(output / "METRIC-REPORT.json"),
            "state_transition_receipt_sha256": sha256_file(
                output / "STATE-TRANSITION-RECEIPT.json"
            ),
            "implementation_sha256": sha256_file(Path(__file__)),
            "private_unseen_opened": False,
            "weight_training_performed": False,
            "adapter_runtime_activated": False,
        }
    )
    _write_json_create(output / "RUN-MANIFEST.json", manifest)
    artifacts = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"
    }
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-visible-answer-repair-artifact-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": artifacts,
        },
    )
    return {
        "output": str(output),
        "overall_state": overall_state,
        "repair_pass": repair_pass,
        "projected_factual_pass": projected_factual_pass,
        "projected_quality_pass": projected_quality_pass,
        "state_transition_receipt_sha256": sha256_file(output / "STATE-TRANSITION-RECEIPT.json"),
    }


__all__ = [
    "CAMPAIGN_ID",
    "DEFAULT_OUTPUT",
    "REPAIR_CASE_IDS",
    "VisibleAnswerRepairError",
    "finalize_campaign",
    "prepare_campaign",
    "surface_guard",
]
