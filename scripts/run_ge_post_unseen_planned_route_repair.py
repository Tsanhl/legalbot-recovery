#!/usr/bin/env python3
"""Repair and re-review the three nonready fresh planned-route answers."""

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

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-post-unseen-planned-route-repair-r1"
SOURCE_ID = "LegalBot-GE-2026-09-04-post-unseen-fresh-planned-route-r1"
SOURCE_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / SOURCE_ID
PUBLIC_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
SESSION_ROOT = Path.home() / ".legalbot-v111-clean-visible" / "2026-09-04" / CAMPAIGN_ID

REPAIR_PROMPT = """Read input.json only. Rewrite every assigned answer to cure each disclosed defect while preserving its supported substance. Use only the question, official evidence, independent coverage plan and evaluator controls supplied. State every required point expressly, remove unsupported narrowing or additions, preserve material limits, identify the source and locator, and give a safe practical step. Do not browse, run code, inspect other paths, mention evaluation, or claim professional review. Return every assigned case exactly once."""

REVIEW_PROMPT = """Read input.json only. Review every changed exact answer from scratch against the official evidence and controls. Review each required point, unsupported addition, factual check, quality dimension and critical floor. Do not defer to the prior review or coverage plan. Do not browse, run code, inspect other paths, rewrite an answer, or infer professional approval. Return every assigned case exactly once."""


class PlannedRepairError(RuntimeError):
    """The three-case planned-route repair failed its exact contract."""


def collect(stage: str, key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((SESSION_ROOT / stage).glob("shard-*/output.json")):
        rows.extend(json.loads(path.read_text())[key])
    return rows


def make_shards(stage: str, rows: list[dict[str, Any]], schema: dict[str, Any]) -> None:
    root = SESSION_ROOT / stage
    root.mkdir(mode=0o700)
    for index, group in enumerate(shard(rows, 2), 1):
        if not group:
            continue
        work = root / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        write_json(work / "input.json", {"cases": group, "expected_case_ids": [row["case_id"] for row in group]}, mode=0o600)
        write_json(work / "schema.json", schema, mode=0o600)


def run_stage(stage: str) -> dict[str, Any]:
    root = SESSION_ROOT / stage
    workdirs = sorted(path for path in root.iterdir() if path.is_dir())
    if not workdirs or any((path / "output.json").exists() for path in workdirs):
        raise PlannedRepairError(f"stage is not clean: {stage}")
    results = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(run_codex, work, REPAIR_PROMPT if stage == "repair" else REVIEW_PROMPT): work for work in workdirs}
        for future in as_completed(futures):
            results.append(future.result())
    failures = [item for item in results if item[1] != 0 or not (root / item[0] / "output.json").is_file()]
    if failures:
        raise PlannedRepairError(f"{stage} failures: {failures}")
    return {"stage": stage, "completed_shards": len(results)}


def prepare() -> dict[str, Any]:
    if PUBLIC_ROOT.exists() or SESSION_ROOT.exists():
        raise PlannedRepairError("refusing to replace existing repair campaign")
    metrics = json.loads((SOURCE_ROOT / "METRIC-REPORT.json").read_text())
    state = json.loads((SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json").read_text())
    verify_content_seal(metrics)
    verify_content_seal(state)
    if metrics["factual_pass_count"] != 20 or metrics["quality_70_floor_pass_count"] != 20 or len(metrics["failed_case_ids"]) != 3:
        raise PlannedRepairError("source is not the expected 20/23 fresh hold")
    PUBLIC_ROOT.mkdir(parents=True)
    SESSION_ROOT.mkdir(parents=True, mode=0o700)
    SESSION_ROOT.chmod(0o700)
    contract = sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-contract.v1", "campaign_id": CAMPAIGN_ID, "source_campaign_id": SOURCE_ID, "source_state_sha256": sha256_file(SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json"), "scope": metrics["failed_case_ids"], "repair_kind": "NON_WEIGHT_CHANGED_ANSWER_ONLY", "fresh_generalisation_result": False, "consumed_unseen_prompt_or_findings_used": False, "training": "NOT_AUTHORIZED_NOT_PERFORMED", "adapter": "INACTIVE_NOT_USED", "qualified_legal_review": "NOT_STARTED", "legal_gold": "NOT_STARTED"})
    write_json(PUBLIC_ROOT / "REPAIR-CONTRACT.json", contract)
    cases = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "EXPECTED-CONTROLS.jsonl")}
    plans = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "ANSWER-COVERAGE-PLANS.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(SOURCE_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    outputs = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "PLANNED-CODEX-OUTPUTS.jsonl")}
    reviews = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "CODEX-BLIND-REVIEW.jsonl")}
    payload = []
    register = []
    for case_id in metrics["failed_case_ids"]:
        case = cases[case_id]
        source = sources[case["topic"]]
        payload.append({"case_id": case_id, "question": case["question"], "original_answer": outputs[case_id]["candidate_answer"], "original_answer_hash": outputs[case_id]["candidate_answer_hash"], "independent_coverage_plan": {key: plans[case_id][key] for key in ("direct_answer", "material_conditions_and_exceptions", "unverified_facts", "jurisdiction_and_currentness_limits", "source_name", "locator", "safe_practical_next_step", "urgent_safety_wording_needed")}, "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}, "required_points": controls[case_id]["required_points"], "material_limits": controls[case_id]["material_limits"], "prohibited_overclaims": controls[case_id]["prohibited_overclaims"], "prior_review": {"required_point_reviews": reviews[case_id]["required_point_reviews"], "failed_factual_checks": [name for name, value in reviews[case_id]["factual_checks"].items() if value == "FAIL"], "assessment_summary": reviews[case_id]["assessment_summary"]}})
        register.append(sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-register.v1", "case_id": case_id, "question_hash": case["question_hash"], "original_answer_hash": outputs[case_id]["candidate_answer_hash"], "repair_reason": reviews[case_id]["assessment_summary"], "unseen_source": False}))
    write_jsonl(PUBLIC_ROOT / "REPAIR-REGISTER.jsonl", register)
    make_shards("repair", payload, answer_schema())
    return {"stage": "PREPARED", "repair_case_count": len(payload)}


def accept() -> dict[str, Any]:
    answers = collect("repair", "answers")
    register = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "REPAIR-REGISTER.jsonl")}
    if len(answers) != 3 or {row.get("case_id") for row in answers} != set(register):
        raise PlannedRepairError("repair answer case set mismatch")
    cases = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "EXPECTED-CONTROLS.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(SOURCE_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    changed = []
    review_rows = []
    for case_id in sorted(register):
        answer = normalise(str(next(row["candidate_answer"] for row in answers if row["case_id"] == case_id)))
        answer_hash = sha256_bytes(answer.encode())
        if answer_hash == register[case_id]["original_answer_hash"] or not 70 <= len(answer.split()) <= 500:
            raise PlannedRepairError(f"changed answer failed surface or identity: {case_id}")
        changed.append(sealed({"schema": "legalbot.ge-post-unseen-planned-route-repaired-answer.v1", "case_id": case_id, "question_hash": cases[case_id]["question_hash"], "original_answer_hash": register[case_id]["original_answer_hash"], "repaired_answer": answer, "repaired_answer_hash": answer_hash, "word_count": len(answer.split()), "adapter_used": False, "training_performed": False, "professional_legal_sign_off": False}))
        source = sources[cases[case_id]["topic"]]
        control = controls[case_id]
        review_rows.append({"case_id": case_id, "question": cases[case_id]["question"], "candidate_answer": answer, "candidate_answer_hash": answer_hash, "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}, "required_points": control["required_points"], "material_limits": control["material_limits"], "prohibited_overclaims": control["prohibited_overclaims"], "factual_checks": list(FACTUAL_CHECKS), "quality_dimension_maxima": QUALITY_MAX, "critical_floors": QUALITY_FLOORS})
    write_jsonl(PUBLIC_ROOT / "REPAIRED-ANSWERS.jsonl", changed)
    make_shards("review", review_rows, review_schema())
    return {"stage": "REPAIRS_ACCEPTED", "changed_hash_count": len(changed)}


def finalize() -> dict[str, Any]:
    changed = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "REPAIRED-ANSWERS.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(SOURCE_ROOT / "EXPECTED-CONTROLS.jsonl")}
    raw = collect("review", "reviews")
    if len(raw) != 3 or {row.get("case_id") for row in raw} != set(changed):
        raise PlannedRepairError("changed review case set mismatch")
    normalized = []
    full = 0
    factual = 0
    claims = 0
    failed = []
    corrections = []
    for case_id in sorted(changed):
        row = next(item for item in raw if item["case_id"] == case_id)
        expected_hash = changed[case_id]["repaired_answer_hash"]
        if row["candidate_answer_hash"] != expected_hash:
            corrections.append(sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-hash-correction.v1", "case_id": case_id, "echoed_hash": row["candidate_answer_hash"], "bound_hash": expected_hash, "content_changed": False}))
        points = row["required_point_reviews"]
        indices = set(range(1, len(controls[case_id]["required_points"]) + 1))
        if len(points) != len(indices) or {item["required_point_index"] for item in points} != indices or set(row["factual_checks"]) != set(FACTUAL_CHECKS):
            raise PlannedRepairError(f"review structure mismatch: {case_id}")
        claims += len(points)
        fact_pass = row["material_proposition_coverage_complete"] is True and all(item["support_status"] == "SUPPORTED" for item in points) and all(value in {"PASS", "NOT_APPLICABLE"} for value in row["factual_checks"].values())
        dimensions = {name: round(float(row["quality_dimensions"][name]), 2) for name in QUALITY_MAX}
        if any(not 0 <= dimensions[name] <= QUALITY_MAX[name] for name in QUALITY_MAX):
            raise PlannedRepairError(f"quality range mismatch: {case_id}")
        score = round(sum(dimensions.values()), 2) if fact_pass else None
        floors = fact_pass and all(dimensions[name] >= floor for name, floor in QUALITY_FLOORS.items())
        quality_pass = fact_pass and score is not None and score >= 70 and floors
        factual += int(fact_pass)
        full += int(quality_pass)
        if not quality_pass:
            failed.append(case_id)
        normalized.append(sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-ai-review.v1", "case_id": case_id, "candidate_answer_hash": expected_hash, "reviewer_kind": "AI_MODEL_REVIEWER", "professional_legal_sign_off": False, "material_proposition_coverage_complete": row["material_proposition_coverage_complete"], "required_point_reviews": points, "factual_checks": row["factual_checks"], "factual_outcome": "FACTUAL_PASS" if fact_pass else "FACTUAL_HOLD", "quality_dimensions": dimensions if fact_pass else {}, "quality_score": score, "critical_floor_pass": floors, "quality_outcome": "MEETS_70_STANDARD" if quality_pass else ("BELOW_70_OR_CRITICAL_FLOOR" if fact_pass else "NOT_SCORED_FACTUAL_HOLD"), "assessment_summary": normalise(str(row["assessment_summary"]))}))
    write_jsonl(PUBLIC_ROOT / "CHANGED-HASH-BLIND-REVIEW.jsonl", normalized)
    if corrections:
        write_jsonl(PUBLIC_ROOT / "MECHANICAL-REVIEW-HASH-CORRECTIONS.jsonl", corrections)
    projection = 20 + full
    all_pass = projection == 23
    metrics = sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-metrics.v1", "campaign_id": CAMPAIGN_ID, "changed_hash_count": 3, "changed_hash_factual_pass_count": factual, "changed_hash_70_floor_pass_count": full, "changed_hash_failed_case_ids": failed, "changed_hash_claim_reviews": claims, "source_unchanged_full_pass_count": 20, "exposed_projection_case_count": 23, "exposed_projection_70_floor_pass_count": projection, "fresh_generalisation_result": False})
    write_json(PUBLIC_ROOT / "METRIC-REPORT.json", metrics)
    state_name = "POST_UNSEEN_PLANNED_ROUTE_REPAIR_23_OF_23_EXPOSED_AWAITING_FRESH_AUDITED_ROUTE_EVALUATION" if all_pass else "POST_UNSEEN_PLANNED_ROUTE_REPAIR_HOLD_STOP_NO_LOOP"
    state = sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-state.v1", "campaign_id": CAMPAIGN_ID, "overall_state": state_name, "consumed_unseen_prompt_or_findings_used": False, "training": "NOT_AUTHORIZED_NOT_PERFORMED", "adapter": "INACTIVE_NOT_USED", "qualified_legal_review": "NOT_STARTED", "legal_gold": "NOT_STARTED", "promotion": "NOT_STARTED", "live": "NOT_STARTED", "next_gate": "NEW_FRESH_VISIBLE_PLANNED_AND_COVERAGE_AUDITED_ROUTE" if all_pass else "STOP_NO_LOOP", "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z")})
    write_json(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json", state)
    (PUBLIC_ROOT / "README.md").write_text(f"# {CAMPAIGN_ID}\n\nChanged-hash repair and fresh-context review for the three nonready answers from `{SOURCE_ID}`.\n\n- Changed hashes passing: {full}/3\n- Exposed projection: {projection}/23\n- State: `{state_name}`\n\nThis projection is exposed visible evidence, not fresh generalisation, professional review or legal gold. No training, adapter use, or consumed-unseen access occurred.\n")
    manifest = sealed({"schema": "legalbot.ge-post-unseen-planned-route-repair-run.v1", "campaign_id": CAMPAIGN_ID, "source_state_sha256": sha256_file(SOURCE_ROOT / "STATE-TRANSITION-RECEIPT.json"), "answers_sha256": sha256_file(PUBLIC_ROOT / "REPAIRED-ANSWERS.jsonl"), "reviews_sha256": sha256_file(PUBLIC_ROOT / "CHANGED-HASH-BLIND-REVIEW.jsonl"), "metrics_sha256": sha256_file(PUBLIC_ROOT / "METRIC-REPORT.json"), "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json"), "implementation_sha256": sha256_file(Path(__file__)), "same_provider_ai": True, "ephemeral_contexts": 4})
    write_json(PUBLIC_ROOT / "RUN-MANIFEST.json", manifest)
    artifacts = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    write_json(PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json", {"schema": "legalbot.ge-post-unseen-planned-route-repair-artifacts.v1", "campaign_id": CAMPAIGN_ID, "artifacts": artifacts})
    return {"overall_state": state_name, "changed_full_pass": full, "exposed_projection": projection, "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json")}


def verify() -> dict[str, Any]:
    register = json.loads((PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json").read_text())
    actual = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    if register["artifacts"] != actual:
        raise PlannedRepairError("artifact register mismatch")
    for name in ("REPAIR-CONTRACT.json", "METRIC-REPORT.json", "STATE-TRANSITION-RECEIPT.json", "RUN-MANIFEST.json"):
        verify_content_seal(json.loads((PUBLIC_ROOT / name).read_text()))
    metrics = json.loads((PUBLIC_ROOT / "METRIC-REPORT.json").read_text())
    return {"verified": True, "changed_full_pass": metrics["changed_hash_70_floor_pass_count"], "exposed_projection": metrics["exposed_projection_70_floor_pass_count"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "run-repair", "accept", "run-review", "finalize", "verify"))
    args = parser.parse_args()
    actions = {"prepare": prepare, "run-repair": lambda: run_stage("repair"), "accept": accept, "run-review": lambda: run_stage("review"), "finalize": finalize, "verify": verify}
    print(json.dumps(actions[args.stage](), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
