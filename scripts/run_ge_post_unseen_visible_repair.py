#!/usr/bin/env python3
"""Repair and re-review only the nonready post-unseen visible answers."""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.run_ge_post_unseen_clean_visible import (
    FACTUAL_CHECKS,
    PROJECT_ROOT,
    QUALITY_FLOORS,
    QUALITY_MAX,
    answer_schema,
    load_jsonl,
    normalise,
    review_schema,
    run_codex,
    sealed,
    sha256_bytes,
    sha256_file,
    shard,
    verify_content_seal,
    write_json,
    write_jsonl,
)

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-post-unseen-visible-repair-r1"
SOURCE_ID = "LegalBot-GE-2026-09-04-post-unseen-clean-visible-r3"
SOURCE_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / SOURCE_ID
PUBLIC_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
SESSION_ROOT = Path.home() / ".legalbot-v111-clean-visible" / "2026-09-04" / CAMPAIGN_ID

REPAIR_PROMPT = """Read input.json only. Rewrite every assigned exact answer to cure every disclosed factual-completeness defect. Use only the supplied question, official evidence, and controls. Cover every required point accurately, remove every unsupported addition, preserve all necessary limits, distinguish law from the user's unverified facts, identify the official source and locator, and give a safe practical next step. Do not browse, run code, inspect other paths, add authority or claim professional review. Return each assigned case exactly once as a finished answer."""

REVIEW_PROMPT = """Read input.json only. Review every changed exact answer from scratch against the supplied official evidence and controls. Do not defer to the prior review. Review each required point and mark it SUPPORTED only when the answer states it accurately and the source supports it. Fail material_proposition_coverage_complete for any omission, contradiction, or unsupported material addition. Apply all factual checks and score each quality dimension independently without inflating it. Do not browse, run code, inspect other paths, rewrite answers, or infer professional approval. Return every assigned case exactly once."""


class RepairError(RuntimeError):
    """The bounded repair or re-review failed its contract."""


def collect(stage: str, key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((SESSION_ROOT / stage).glob("shard-*/output.json")):
        rows.extend(json.loads(path.read_text())[key])
    return rows


def run_stage(stage: str) -> dict[str, Any]:
    root = SESSION_ROOT / stage
    prompt = REPAIR_PROMPT if stage == "repair" else REVIEW_PROMPT
    workdirs = sorted(path for path in root.iterdir() if path.is_dir())
    if not workdirs or any((path / "output.json").exists() for path in workdirs):
        raise RepairError(f"stage is not clean: {stage}")
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_codex, path, prompt): path for path in workdirs}
        for future in as_completed(futures):
            results.append(future.result())
    failures = [item for item in results if item[1] != 0 or not (root / item[0] / "output.json").is_file()]
    if failures:
        raise RepairError(f"{stage} failures: {failures}")
    return {"stage": stage, "completed_shards": len(results)}


def prepare() -> dict[str, Any]:
    if PUBLIC_ROOT.exists() or SESSION_ROOT.exists():
        raise RepairError("refusing to replace existing repair campaign")
    for name in ("FRESH-VISIBLE-CASES.jsonl", "EXPECTED-CONTROLS.jsonl", "OFFICIAL-SOURCE-MANIFEST.jsonl", "CODEX-SOURCE-BOUND-OUTPUTS.jsonl", "CODEX-BLIND-REVIEW.jsonl", "METRIC-REPORT.json", "STATE-TRANSITION-RECEIPT.json"):
        if not (SOURCE_ROOT / name).is_file():
            raise RepairError(f"source campaign member missing: {name}")
    source_state = json.loads((SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json").read_text())
    source_metrics = json.loads((SOURCE_ROOT / "METRIC-REPORT.json").read_text())
    verify_content_seal(source_state)
    verify_content_seal(source_metrics)
    if source_state["overall_state"] != "POST_UNSEEN_CLEAN_VISIBLE_HOLD_VISIBLE_REPAIR_REQUIRED" or source_metrics["factual_pass_count"] != 12 or source_metrics["quality_70_floor_pass_count"] != 12:
        raise RepairError("source campaign is not the expected 12/23 hold")
    PUBLIC_ROOT.mkdir(parents=True)
    SESSION_ROOT.mkdir(parents=True, mode=0o700)
    SESSION_ROOT.chmod(0o700)
    contract = sealed({
        "schema": "legalbot.ge-post-unseen-visible-repair-contract.v1",
        "campaign_id": CAMPAIGN_ID,
        "source_campaign_id": SOURCE_ID,
        "source_state_sha256": sha256_file(SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json"),
        "scope": "ONLY_11_NONREADY_VISIBLE_EXACT_HASHES",
        "repair_kind": "NON_WEIGHT_ANSWER_RECONSTRUCTION",
        "consumed_unseen_prompt_or_findings_used": False,
        "answer_weight_training": "NOT_AUTHORIZED_NOT_PERFORMED",
        "r2_adapter": "INACTIVE_NOT_USED",
        "result_interpretation": "EXPOSED_VISIBLE_PROJECTION_NOT_FRESH_GENERALISATION",
        "qualified_legal_review": "NOT_STARTED",
        "legal_gold": "NOT_STARTED",
    })
    write_json(PUBLIC_ROOT / "REPAIR-CONTRACT.json", contract)
    cases = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "EXPECTED-CONTROLS.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(SOURCE_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    outputs = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "CODEX-SOURCE-BOUND-OUTPUTS.jsonl")}
    reviews = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "CODEX-BLIND-REVIEW.jsonl")}
    failed = [case_id for case_id, row in reviews.items() if row["quality_outcome"] != "MEETS_70_STANDARD"]
    if len(failed) != 11 or set(failed) != set(source_metrics["failed_case_ids"]):
        raise RepairError("repair case set does not reconcile")
    payload = []
    register = []
    for case_id in sorted(failed):
        case = cases[case_id]
        output = outputs[case_id]
        review = reviews[case_id]
        source = sources[case["topic"]]
        payload.append({
            "case_id": case_id,
            "question": case["question"],
            "original_answer": output["candidate_answer"],
            "original_answer_hash": output["candidate_answer_hash"],
            "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")},
            "required_points": controls[case_id]["required_points"],
            "material_limits": controls[case_id]["material_limits"],
            "prohibited_overclaims": controls[case_id]["prohibited_overclaims"],
            "prior_review_findings": {
                "required_point_reviews": review["required_point_reviews"],
                "failed_factual_checks": [name for name, value in review["factual_checks"].items() if value == "FAIL"],
                "assessment_summary": review["assessment_summary"],
            },
        })
        register.append(sealed({"schema": "legalbot.ge-post-unseen-visible-repair-register.v1", "case_id": case_id, "question_hash": case["question_hash"], "original_answer_hash": output["candidate_answer_hash"], "repair_reason": review["assessment_summary"], "consumed_unseen_source": False}))
    write_jsonl(PUBLIC_ROOT / "REPAIR-REGISTER.jsonl", register)
    repair_root = SESSION_ROOT / "repair"
    repair_root.mkdir(mode=0o700)
    for index, group in enumerate(shard(payload, 3), 1):
        work = repair_root / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        write_json(work / "input.json", {"cases": group, "expected_case_ids": [row["case_id"] for row in group]}, mode=0o600)
        write_json(work / "schema.json", answer_schema(), mode=0o600)
    return {"stage": "PREPARED", "repair_case_count": len(payload)}


def accept_repairs() -> dict[str, Any]:
    repair_register = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "REPAIR-REGISTER.jsonl")}
    answers = collect("repair", "answers")
    if len(answers) != 11 or {row.get("case_id") for row in answers} != set(repair_register):
        raise RepairError("repair output case set mismatch")
    cases = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "EXPECTED-CONTROLS.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(SOURCE_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    changed = []
    review_payload = []
    for case_id in sorted(repair_register):
        answer = normalise(str(next(row["candidate_answer"] for row in answers if row["case_id"] == case_id)))
        word_count = len(answer.split())
        if not 70 <= word_count <= 450:
            raise RepairError(f"repair surface length failed: {case_id} {word_count}")
        answer_hash = sha256_bytes(answer.encode())
        if answer_hash == repair_register[case_id]["original_answer_hash"]:
            raise RepairError(f"repair did not change answer: {case_id}")
        case = cases[case_id]
        source = sources[case["topic"]]
        control = controls[case_id]
        changed.append(sealed({"schema": "legalbot.ge-post-unseen-visible-repaired-answer.v1", "case_id": case_id, "question_hash": case["question_hash"], "original_answer_hash": repair_register[case_id]["original_answer_hash"], "repaired_answer": answer, "repaired_answer_hash": answer_hash, "word_count": word_count, "weight_training_performed": False, "adapter_used": False, "professional_legal_sign_off": False}))
        review_payload.append({"case_id": case_id, "question": case["question"], "question_hash": case["question_hash"], "candidate_answer": answer, "candidate_answer_hash": answer_hash, "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}, "required_points": control["required_points"], "material_limits": control["material_limits"], "prohibited_overclaims": control["prohibited_overclaims"], "factual_checks": list(FACTUAL_CHECKS), "quality_dimension_maxima": QUALITY_MAX, "critical_floors": QUALITY_FLOORS})
    write_jsonl(PUBLIC_ROOT / "REPAIRED-ANSWERS.jsonl", changed)
    review_root = SESSION_ROOT / "review"
    review_root.mkdir(mode=0o700)
    for index, group in enumerate(shard(review_payload, 3), 1):
        work = review_root / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        write_json(work / "input.json", {"cases": group, "expected_case_ids": [row["case_id"] for row in group]}, mode=0o600)
        write_json(work / "schema.json", review_schema(), mode=0o600)
    return {"stage": "REPAIRS_ACCEPTED", "changed_hash_count": len(changed)}


def finalize() -> dict[str, Any]:
    repaired = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "REPAIRED-ANSWERS.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "EXPECTED-CONTROLS.jsonl")}
    raw = collect("review", "reviews")
    if len(raw) != 11 or {row.get("case_id") for row in raw} != set(repaired):
        raise RepairError("re-review case set mismatch")
    normalized = []
    factual = 0
    full = 0
    claims = 0
    failed = []
    corrections = []
    for case_id in sorted(repaired):
        row = next(item for item in raw if item["case_id"] == case_id)
        expected_hash = repaired[case_id]["repaired_answer_hash"]
        if row["candidate_answer_hash"] != expected_hash:
            corrections.append(sealed({"schema": "legalbot.ge-post-unseen-visible-repair-hash-correction.v1", "case_id": case_id, "reviewer_echoed_hash": row["candidate_answer_hash"], "bound_hash": expected_hash, "answer_changed": False, "review_changed": False}))
        points = row["required_point_reviews"]
        expected_indices = set(range(1, len(controls[case_id]["required_points"]) + 1))
        if len(points) != len(expected_indices) or {item["required_point_index"] for item in points} != expected_indices:
            raise RepairError(f"point review mismatch: {case_id}")
        claims += len(points)
        checks = row["factual_checks"]
        if set(checks) != set(FACTUAL_CHECKS):
            raise RepairError(f"factual checks mismatch: {case_id}")
        fact_pass = row["material_proposition_coverage_complete"] is True and all(item["support_status"] == "SUPPORTED" for item in points) and all(value in {"PASS", "NOT_APPLICABLE"} for value in checks.values())
        dimensions = {name: round(float(row["quality_dimensions"][name]), 2) for name in QUALITY_MAX}
        if any(not 0 <= dimensions[name] <= QUALITY_MAX[name] for name in QUALITY_MAX):
            raise RepairError(f"quality dimension invalid: {case_id}")
        score = round(sum(dimensions.values()), 2) if fact_pass else None
        floor_pass = fact_pass and all(dimensions[name] >= value for name, value in QUALITY_FLOORS.items())
        quality_pass = fact_pass and score is not None and score >= 70 and floor_pass
        factual += int(fact_pass)
        full += int(quality_pass)
        if not quality_pass:
            failed.append(case_id)
        normalized.append(sealed({"schema": "legalbot.ge-post-unseen-visible-repair-ai-review.v1", "case_id": case_id, "candidate_answer_hash": expected_hash, "reviewer_kind": "AI_MODEL_REVIEWER", "professional_legal_sign_off": False, "material_proposition_coverage_complete": row["material_proposition_coverage_complete"], "required_point_reviews": points, "factual_checks": checks, "factual_outcome": "FACTUAL_PASS" if fact_pass else "FACTUAL_HOLD", "quality_dimensions": dimensions if fact_pass else {}, "quality_score": score, "critical_floor_pass": floor_pass, "quality_outcome": "MEETS_70_STANDARD" if quality_pass else ("BELOW_70_OR_CRITICAL_FLOOR" if fact_pass else "NOT_SCORED_FACTUAL_HOLD"), "assessment_summary": normalise(str(row["assessment_summary"]))}))
    write_jsonl(PUBLIC_ROOT / "CHANGED-HASH-BLIND-REVIEW.jsonl", normalized)
    if corrections:
        write_jsonl(PUBLIC_ROOT / "MECHANICAL-REVIEW-HASH-CORRECTIONS.jsonl", corrections)
    projection_factual = 12 + factual
    projection_full = 12 + full
    all_pass = projection_factual == 23 and projection_full == 23
    metrics = sealed({"schema": "legalbot.ge-post-unseen-visible-repair-metrics.v1", "campaign_id": CAMPAIGN_ID, "changed_hash_count": 11, "changed_hash_factual_pass_count": factual, "changed_hash_70_floor_pass_count": full, "changed_hash_failed_case_ids": failed, "changed_hash_claim_reviews": claims, "mechanical_hash_correction_count": len(corrections), "source_unchanged_full_pass_count": 12, "exposed_projection_factual_pass_count": projection_factual, "exposed_projection_70_floor_pass_count": projection_full, "exposed_projection_case_count": 23, "all_changed_hashes_pass": all_pass, "fresh_generalisation_result": False})
    write_json(PUBLIC_ROOT / "METRIC-REPORT.json", metrics)
    state_name = "POST_UNSEEN_VISIBLE_REPAIR_PASS_AWAITING_NEW_FRESH_VISIBLE_EVALUATION" if all_pass else "POST_UNSEEN_VISIBLE_REPAIR_HOLD_FURTHER_BOUNDED_REPAIR_REQUIRED"
    state = sealed({"schema": "legalbot.ge-post-unseen-visible-repair-state.v1", "campaign_id": CAMPAIGN_ID, "overall_state": state_name, "consumed_private_306_bank": "OPENED_ONCE_RETIRED_NOT_ACCESSED", "consumed_unseen_prompt_or_findings_used": False, "answer_weight_training": "NOT_AUTHORIZED_NOT_PERFORMED", "r2_adapter": "INACTIVE_NOT_USED", "qualified_legal_review": "NOT_STARTED", "answer_legal_gold": "NOT_STARTED", "promotion": "NOT_STARTED", "live": "NOT_STARTED", "next_gate": "NEW_FRESH_VISIBLE_SOURCE_FIRST_EVALUATION" if all_pass else "VISIBLE_REPAIR_ONLY", "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z")})
    write_json(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json", state)
    (PUBLIC_ROOT / "README.md").write_text(f"# {CAMPAIGN_ID}\n\nChanged-answer repair and fresh-context review for the 11 nonready hashes from `{SOURCE_ID}`.\n\n- Changed hashes passing factual and 70+/floor gates: {full}/11\n- Exposed-set projection: {projection_full}/23\n- State: `{state_name}`\n\nThis exposed repair projection is not fresh generalisation, qualified legal review, professional assurance, or legal gold. No training occurred, the r2 adapter remained inactive, and the consumed unseen bank was not used.\n")
    manifest = sealed({"schema": "legalbot.ge-post-unseen-visible-repair-run.v1", "campaign_id": CAMPAIGN_ID, "source_state_sha256": sha256_file(SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json"), "repair_register_sha256": sha256_file(PUBLIC_ROOT / "REPAIR-REGISTER.jsonl"), "repaired_answers_sha256": sha256_file(PUBLIC_ROOT / "REPAIRED-ANSWERS.jsonl"), "blind_review_sha256": sha256_file(PUBLIC_ROOT / "CHANGED-HASH-BLIND-REVIEW.jsonl"), "metric_sha256": sha256_file(PUBLIC_ROOT / "METRIC-REPORT.json"), "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json"), "implementation_sha256": sha256_file(Path(__file__)), "same_provider_ai": True, "ephemeral_contexts": 6})
    write_json(PUBLIC_ROOT / "RUN-MANIFEST.json", manifest)
    artifacts = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    write_json(PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json", {"schema": "legalbot.ge-post-unseen-visible-repair-artifacts.v1", "campaign_id": CAMPAIGN_ID, "artifacts": artifacts})
    return {"overall_state": state_name, "changed_hash_full_pass": full, "exposed_projection_full_pass": projection_full, "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json")}


def verify() -> dict[str, Any]:
    register = json.loads((PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json").read_text())
    actual = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    if register["artifacts"] != actual:
        raise RepairError("artifact register mismatch")
    for name in ("REPAIR-CONTRACT.json", "METRIC-REPORT.json", "STATE-TRANSITION-RECEIPT.json", "RUN-MANIFEST.json"):
        verify_content_seal(json.loads((PUBLIC_ROOT / name).read_text()))
    metrics = json.loads((PUBLIC_ROOT / "METRIC-REPORT.json").read_text())
    return {"verified": True, "changed_hash_full_pass": metrics["changed_hash_70_floor_pass_count"], "exposed_projection_full_pass": metrics["exposed_projection_70_floor_pass_count"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "run-repair", "accept-repair", "run-review", "finalize", "verify"))
    args = parser.parse_args()
    actions = {"prepare": prepare, "run-repair": lambda: run_stage("repair"), "accept-repair": accept_repairs, "run-review": lambda: run_stage("review"), "finalize": finalize, "verify": verify}
    print(json.dumps(actions[args.stage](), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
