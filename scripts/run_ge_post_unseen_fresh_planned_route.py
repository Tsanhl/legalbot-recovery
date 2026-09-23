#!/usr/bin/env python3
"""Evaluate the repaired source-first route on a second new 23-domain set."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scripts.run_ge_post_unseen_clean_visible import (
    FACTUAL_CHECKS,
    PROJECT_ROOT,
    QUALITY_FLOORS,
    QUALITY_MAX,
    Source,
    answer_schema,
    author_schema,
    fetch_source,
    load_jsonl,
    normalise,
    parse_source,
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

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-post-unseen-fresh-planned-route-r1"
PUBLIC_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
SESSION_ROOT = Path.home() / ".legalbot-v111-clean-visible" / "2026-09-04" / CAMPAIGN_ID

SOURCES = (
    Source("administrative-law", "LEGAL_TOPIC", "inquiries5", "Inquiries Act 2005", "ukpga/2005/12/section/5", "section 5"),
    Source("ai-and-data-protection", "LEGAL_TOPIC", "dua71", "Data (Use and Access) Act 2025", "ukpga/2025/18/section/71", "section 71"),
    Source("business-and-company-law", "LEGAL_TOPIC", "eccta199", "Economic Crime and Corporate Transparency Act 2023", "ukpga/2023/56/section/199", "section 199"),
    Source("commercial-law", "LEGAL_TOPIC", "bea3", "Bills of Exchange Act 1882", "ukpga/1882/61/section/3", "section 3"),
    Source("competition-law", "LEGAL_TOPIC", "dmcca2", "Digital Markets, Competition and Consumers Act 2024", "ukpga/2024/13/section/2", "section 2"),
    Source("contemporary-biolaw-and-regulation", "LEGAL_TOPIC", "mmda2", "Medicines and Medical Devices Act 2021", "ukpga/2021/3/section/2", "section 2"),
    Source("contract-law", "LEGAL_TOPIC", "minors3", "Minors’ Contracts Act 1987", "ukpga/1987/13/section/3", "section 3"),
    Source("criminal-law", "LEGAL_TOPIC", "bribery1", "Bribery Act 2010", "ukpga/2010/23/section/1", "section 1"),
    Source("eu-internal-market-law", "LEGAL_TOPIC", "eufra29", "European Union (Future Relationship) Act 2020", "ukpga/2020/29/section/29", "section 29"),
    Source("international-commercial-mediation", "LEGAL_TOPIC", "sia9", "State Immunity Act 1978", "ukpga/1978/33/section/9", "section 9"),
    Source("land-law", "LEGAL_TOPIC", "lpa52", "Law of Property Act 1925", "ukpga/1925/20/section/52", "section 52"),
    Source("law-and-medicine", "LEGAL_TOPIC", "nhsa3", "National Health Service Act 2006", "ukpga/2006/41/section/3", "section 3"),
    Source("pensions-law", "LEGAL_TOPIC", "psa2015_48", "Pension Schemes Act 2015", "ukpga/2015/8/section/48", "section 48"),
    Source("private-international-law", "LEGAL_TOPIC", "dmpa1", "Domicile and Matrimonial Proceedings Act 1973", "ukpga/1973/45/section/1", "section 1"),
    Source("tort-law", "LEGAL_TOPIC", "compensation1", "Compensation Act 2006", "ukpga/2006/29/section/1", "section 1"),
    Source("trusts-law", "LEGAL_TOPIC", "paa5", "Perpetuities and Accumulations Act 2009", "ukpga/2009/18/section/5", "section 5"),
    Source("wills-and-estates", "LEGAL_TOPIC", "edp1", "Estates of Deceased Persons (Forfeiture Rule and Law of Succession) Act 2011", "ukpga/2011/7/section/1", "section 1"),
    Source("housing", "PUBLIC_ACCESS_DOMAIN", "tfa1", "Tenant Fees Act 2019", "ukpga/2019/4/section/1", "section 1"),
    Source("employment", "PUBLIC_ACCESS_DOMAIN", "era1999_10", "Employment Relations Act 1999", "ukpga/1999/26/section/10", "section 10"),
    Source("family", "PUBLIC_ACCESS_DOMAIN", "cpa2004_1", "Civil Partnership Act 2004", "ukpga/2004/33/section/1", "section 1"),
    Source("immigration", "PUBLIC_ACCESS_DOMAIN", "niaa82", "Nationality, Immigration and Asylum Act 2002", "ukpga/2002/41/section/82", "section 82"),
    Source("benefits-and-debt", "PUBLIC_ACCESS_DOMAIN", "ssa12", "Social Security Act 1998", "ukpga/1998/14/section/12", "section 12"),
    Source("consumer", "PUBLIC_ACCESS_DOMAIN", "pmo4", "The Price Marking Order 2004", "uksi/2004/102/article/4", "article 4"),
)

PRIOR_IDS = (
    "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1",
    "LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2",
    "LegalBot-GE-2026-09-04-fresh-visible-codex-evaluation-r1",
    "LegalBot-GE-2026-09-04-post-unseen-clean-visible-r3",
)

AUTHOR_PROMPT = """Read input.json only. For each new current official legislation excerpt, create one focused visible General Enquiry case for an ordinary England-and-Wales user. Keep the assigned identifiers exactly. Ask only a question the excerpt can answer. State 3-5 separately checkable required points that are necessary to answer that question; do not turn unrelated provisions in the excerpt into requirements. State 1-3 material limits and 2-4 prohibited overclaims. Mark source_sufficient true only if the excerpt supports the bounded question. Do not browse, run code, inspect other paths, answer the question, or refer to prior evaluations. Return all assigned cases exactly once."""

PLAN_PROMPT = """Read input.json only. For each question, build an answer-coverage plan from the supplied official evidence without seeing any evaluator controls. Identify the direct answer, every statutory condition and exception material to the question, every fact that remains unverified, any date/currentness or jurisdiction limit stated in the evidence, the source name and locator, a safe practical next step, and whether explicit urgent-safety wording is needed. Use only the evidence. Do not draft the final answer, browse, run code, inspect other paths, or infer hidden requirements. Return every assigned case exactly once."""

ANSWER_PROMPT = """Read input.json only. Draft every final General Enquiry answer using the question, official evidence, and independently generated coverage plan. State the direct answer first. Cover every planned condition, exception and material limit; distinguish law from unverified facts; identify the official source and locator in ordinary prose; and give the planned practical step and proportionate urgent-safety wording where required. Use only the evidence. Do not mention the plan, browse, run code, inspect other paths, invent authority or facts, or claim professional review. Return every assigned case exactly once."""

REVIEW_PROMPT = """Read input.json only. Blindly review each exact answer against its official evidence and evaluator controls. Do not defer to the answer-coverage plan, which is not supplied. Review every required point; mark it SUPPORTED only if accurately stated and supported. Fail completeness for any material omission, contradiction or unsupported addition. Apply all factual checks, then score every quality dimension independently without inflation. Do not browse, run code, inspect other paths, rewrite answers, or infer professional approval. Return every assigned case exactly once."""


class PlannedRouteError(RuntimeError):
    """The new planned-route evaluation violated its contract."""


def prior_strings() -> set[str]:
    found: set[str] = set()
    base = PROJECT_ROOT / "data/evaluations/general-enquiries"
    for campaign_id in PRIOR_IDS:
        root = base / campaign_id
        for path in root.glob("*.json*"):
            try:
                values: Any = load_jsonl(path) if path.suffix == ".jsonl" else json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            stack = [values]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    stack.extend(value.values())
                elif isinstance(value, list):
                    stack.extend(value)
                elif isinstance(value, str):
                    found.add(value)
    return found


def plan_schema() -> dict[str, Any]:
    return {"type": "object", "properties": {"plans": {"type": "array", "items": {"type": "object", "properties": {
        "case_id": {"type": "string"}, "direct_answer": {"type": "string"},
        "material_conditions_and_exceptions": {"type": "array", "items": {"type": "string"}},
        "unverified_facts": {"type": "array", "items": {"type": "string"}},
        "jurisdiction_and_currentness_limits": {"type": "array", "items": {"type": "string"}},
        "source_name": {"type": "string"}, "locator": {"type": "string"},
        "safe_practical_next_step": {"type": "string"}, "urgent_safety_wording_needed": {"type": "boolean"},
    }, "required": ["case_id", "direct_answer", "material_conditions_and_exceptions", "unverified_facts", "jurisdiction_and_currentness_limits", "source_name", "locator", "safe_practical_next_step", "urgent_safety_wording_needed"], "additionalProperties": False}}}, "required": ["plans"], "additionalProperties": False}


def collect(stage: str, key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((SESSION_ROOT / stage).glob("shard-*/output.json")):
        rows.extend(json.loads(path.read_text())[key])
    return rows


def make_shards(stage: str, rows: list[dict[str, Any]], schema: dict[str, Any], key: str) -> None:
    root = SESSION_ROOT / stage
    root.mkdir(mode=0o700)
    for index, group in enumerate(shard(rows), 1):
        work = root / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        write_json(work / "input.json", {"cases": group, "expected_case_ids": [row["case_id"] for row in group]}, mode=0o600)
        write_json(work / "schema.json", schema, mode=0o600)


def run_stage(stage: str) -> dict[str, Any]:
    prompts = {"author": AUTHOR_PROMPT, "plan": PLAN_PROMPT, "answer": ANSWER_PROMPT, "review": REVIEW_PROMPT}
    root = SESSION_ROOT / stage
    workdirs = sorted(path for path in root.iterdir() if path.is_dir())
    if not workdirs or any((path / "output.json").exists() for path in workdirs):
        raise PlannedRouteError(f"stage is not clean: {stage}")
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_codex, work, prompts[stage]): work for work in workdirs}
        for future in as_completed(futures):
            results.append(future.result())
    failures = [item for item in results if item[1] != 0 or not (root / item[0] / "output.json").is_file()]
    if failures:
        raise PlannedRouteError(f"{stage} failures: {failures}")
    return {"stage": stage, "completed_shards": len(results)}


def prepare() -> dict[str, Any]:
    if PUBLIC_ROOT.exists() or SESSION_ROOT.exists():
        raise PlannedRouteError("refusing to replace existing planned-route campaign")
    if len(SOURCES) != 23 or len({source.topic for source in SOURCES}) != 23 or Counter(source.coverage_kind for source in SOURCES) != {"LEGAL_TOPIC": 17, "PUBLIC_ACCESS_DOMAIN": 6}:
        raise PlannedRouteError("domain topology changed")
    prior = prior_strings()
    overlap = sorted(source.title for source in SOURCES if source.title in prior)
    if overlap:
        raise PlannedRouteError(f"prior source-title overlap: {overlap}")
    PUBLIC_ROOT.mkdir(parents=True)
    (PUBLIC_ROOT / "official-source-snapshots").mkdir()
    SESSION_ROOT.mkdir(parents=True, mode=0o700)
    SESSION_ROOT.chmod(0o700)
    captures = []
    bodies: dict[str, bytes] = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(fetch_source, source) for source in SOURCES]
        for future in as_completed(futures):
            source, body, headers, final_url = future.result()
            record = parse_source(source, body, headers, final_url)
            captures.append(record)
            bodies[str(record["raw_sha256"])] = body
    topics = [source.topic for source in SOURCES]
    captures.sort(key=lambda row: topics.index(str(row["topic"])))
    for row in captures:
        with (PUBLIC_ROOT / "official-source-snapshots" / f"{row['raw_sha256']}.xml").open("xb") as handle:
            handle.write(bodies[str(row["raw_sha256"])])
    write_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl", captures)
    contract = sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-route-contract.v1", "campaign_id": CAMPAIGN_ID, "route": "FRESH_SOURCE_FIRST_COVERAGE_PLAN_THEN_NON_WEIGHT_ANSWER", "case_count": 23, "domain_count": 23, "source_title_overlap_with_prior_evaluations": 0, "candidate_planner_sees_evaluator_controls": False, "consumed_unseen_prompt_or_findings_used": False, "new_unseen_bank": "NOT_CREATED", "answer_weight_training": "NOT_AUTHORIZED_NOT_PERFORMED", "r2_adapter": "INACTIVE_NOT_USED", "pass_rule": "23/23 factual and 23/23 score at least 70 with all critical floors", "same_provider_ai": True, "qualified_legal_review": "NOT_STARTED", "legal_gold": "NOT_STARTED"})
    write_json(PUBLIC_ROOT / "EVALUATION-CONTRACT.json", contract)
    author_rows = []
    for row in captures:
        case_id = f"{row['topic']}:post-unseen-fresh-plan-r1-01"
        item = {key: row[key] for key in ("topic", "coverage_kind", "source_key", "title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}
        item["case_id"] = case_id
        author_rows.append(item)
    make_shards("author", author_rows, author_schema(), "cases")
    return {"stage": "PREPARED", "sources": len(captures)}


def accept_authors() -> dict[str, Any]:
    authors = collect("author", "cases")
    expected = {f"{source.topic}:post-unseen-fresh-plan-r1-01" for source in SOURCES}
    if len(authors) != 23 or {row.get("case_id") for row in authors} != expected:
        raise PlannedRouteError("author case set mismatch")
    prior = prior_strings()
    sources = {row["topic"]: row for row in load_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    cases = []
    controls = []
    plan_rows = []
    question_hashes: set[str] = set()
    for ordinal, source_spec in enumerate(SOURCES, 1):
        case_id = f"{source_spec.topic}:post-unseen-fresh-plan-r1-01"
        row = next(item for item in authors if item["case_id"] == case_id)
        if row["topic"] != source_spec.topic or row["coverage_kind"] != source_spec.coverage_kind or row["source_sufficient"] is not True:
            raise PlannedRouteError(f"invalid author binding: {case_id}")
        question = normalise(str(row["question"]))
        question_hash = sha256_bytes(question.encode())
        required = [normalise(str(item)) for item in row["required_points"]]
        limits = [normalise(str(item)) for item in row["material_limits"]]
        overclaims = [normalise(str(item)) for item in row["prohibited_overclaims"]]
        if question in prior or question_hash in prior or question_hash in question_hashes or not 3 <= len(required) <= 5 or not 1 <= len(limits) <= 3 or not 2 <= len(overclaims) <= 4:
            raise PlannedRouteError(f"author controls or leakage failed: {case_id}")
        question_hashes.add(question_hash)
        source = sources[source_spec.topic]
        reference = {key: source[key] for key in ("source_key", "title", "locator", "raw_sha256", "evidence_span_sha256")}
        cases.append(sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-case.v1", "ordinal": ordinal, "case_id": case_id, "topic": source_spec.topic, "coverage_kind": source_spec.coverage_kind, "question": question, "question_hash": question_hash, "evidence_references": [reference], "private_unseen_source": False}))
        controls.append(sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-control.v1", "ordinal": ordinal, "case_id": case_id, "required_points": required, "material_limits": limits, "prohibited_overclaims": overclaims, "evidence_references": [reference]}))
        plan_rows.append({"case_id": case_id, "question": question, "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}})
    write_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl", cases)
    write_jsonl(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl", controls)
    make_shards("plan", plan_rows, plan_schema(), "plans")
    return {"stage": "AUTHORING_ACCEPTED", "case_count": len(cases)}


def accept_plans() -> dict[str, Any]:
    plans = collect("plan", "plans")
    cases = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    if len(plans) != 23 or {row.get("case_id") for row in plans} != set(cases):
        raise PlannedRouteError("coverage plan case set mismatch")
    records = []
    answer_rows = []
    locator_normalizations = []
    for case_id in sorted(cases, key=lambda key: cases[key]["ordinal"]):
        row = next(item for item in plans if item["case_id"] == case_id)
        source = sources[cases[case_id]["topic"]]
        conditions = [normalise(str(item)) for item in row["material_conditions_and_exceptions"]]
        echoed_locator = normalise(str(row["locator"]))
        canonical_locator = str(source["locator"])
        locator_matches = echoed_locator.lower() == canonical_locator.lower() or echoed_locator.lower().startswith(canonical_locator.lower() + ";")
        if row["source_name"] != source["title"] or not locator_matches or not conditions:
            raise PlannedRouteError(f"coverage plan binding failed: {case_id}")
        if echoed_locator != canonical_locator:
            locator_normalizations.append(sealed({"schema": "legalbot.ge-post-unseen-plan-locator-normalization.v1", "case_id": case_id, "echoed_locator": echoed_locator, "canonical_locator": canonical_locator, "plan_content_changed": False}))
        record = sealed({"schema": "legalbot.ge-post-unseen-answer-coverage-plan.v1", "case_id": case_id, "question_hash": cases[case_id]["question_hash"], "direct_answer": normalise(str(row["direct_answer"])), "material_conditions_and_exceptions": conditions, "unverified_facts": [normalise(str(item)) for item in row["unverified_facts"]], "jurisdiction_and_currentness_limits": [normalise(str(item)) for item in row["jurisdiction_and_currentness_limits"]], "source_name": row["source_name"], "locator": canonical_locator, "safe_practical_next_step": normalise(str(row["safe_practical_next_step"])), "urgent_safety_wording_needed": row["urgent_safety_wording_needed"], "evaluator_controls_seen": False})
        records.append(record)
        answer_rows.append({"case_id": case_id, "question": cases[case_id]["question"], "coverage_plan": {key: record[key] for key in ("direct_answer", "material_conditions_and_exceptions", "unverified_facts", "jurisdiction_and_currentness_limits", "source_name", "locator", "safe_practical_next_step", "urgent_safety_wording_needed")}, "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}})
    write_jsonl(PUBLIC_ROOT / "ANSWER-COVERAGE-PLANS.jsonl", records)
    if locator_normalizations:
        write_jsonl(PUBLIC_ROOT / "PLAN-LOCATOR-NORMALIZATIONS.jsonl", locator_normalizations)
    make_shards("answer", answer_rows, answer_schema(), "answers")
    return {"stage": "PLANS_ACCEPTED", "plan_count": len(records)}


def accept_answers() -> dict[str, Any]:
    answers = collect("answer", "answers")
    cases = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    if len(answers) != 23 or {row.get("case_id") for row in answers} != set(cases):
        raise PlannedRouteError("answer case set mismatch")
    outputs = []
    reviews = []
    for case_id in sorted(cases, key=lambda key: cases[key]["ordinal"]):
        answer = normalise(str(next(row["candidate_answer"] for row in answers if row["case_id"] == case_id)))
        if not 70 <= len(answer.split()) <= 500 or any(token in answer.lower() for token in ("candidate answer", "owner review", "coverage plan")):
            raise PlannedRouteError(f"answer surface failed: {case_id}")
        answer_hash = sha256_bytes(answer.encode())
        outputs.append(sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-output.v1", "case_id": case_id, "question_hash": cases[case_id]["question_hash"], "candidate_answer": answer, "candidate_answer_hash": answer_hash, "candidate_variant": "CODEX_SOURCE_BOUND_PLANNED_NON_WEIGHT", "adapter_used": False, "weight_training_performed": False, "professional_legal_sign_off": False}))
        source = sources[cases[case_id]["topic"]]
        control = controls[case_id]
        reviews.append({"case_id": case_id, "question": cases[case_id]["question"], "question_hash": cases[case_id]["question_hash"], "candidate_answer": answer, "candidate_answer_hash": answer_hash, "official_evidence": {key: source[key] for key in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}, "required_points": control["required_points"], "material_limits": control["material_limits"], "prohibited_overclaims": control["prohibited_overclaims"], "factual_checks": list(FACTUAL_CHECKS), "quality_dimension_maxima": QUALITY_MAX, "critical_floors": QUALITY_FLOORS})
    write_jsonl(PUBLIC_ROOT / "PLANNED-CODEX-OUTPUTS.jsonl", outputs)
    make_shards("review", reviews, review_schema(), "reviews")
    return {"stage": "ANSWERS_ACCEPTED", "answer_count": len(outputs)}


def finalize() -> dict[str, Any]:
    cases = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl")}
    controls = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl")}
    outputs = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "PLANNED-CODEX-OUTPUTS.jsonl")}
    raw = collect("review", "reviews")
    if len(raw) != 23 or {row.get("case_id") for row in raw} != set(cases):
        raise PlannedRouteError("review case set mismatch")
    normalized = []
    corrections = []
    factual = 0
    full = 0
    claims = 0
    failed = []
    scores = []
    for case_id in sorted(cases, key=lambda key: cases[key]["ordinal"]):
        row = next(item for item in raw if item["case_id"] == case_id)
        expected_hash = outputs[case_id]["candidate_answer_hash"]
        if row["candidate_answer_hash"] != expected_hash:
            corrections.append(sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-review-hash-correction.v1", "case_id": case_id, "reviewer_echoed_hash": row["candidate_answer_hash"], "bound_hash": expected_hash, "answer_changed": False, "review_changed": False}))
        points = row["required_point_reviews"]
        expected_indices = set(range(1, len(controls[case_id]["required_points"]) + 1))
        if len(points) != len(expected_indices) or {item["required_point_index"] for item in points} != expected_indices or set(row["factual_checks"]) != set(FACTUAL_CHECKS):
            raise PlannedRouteError(f"review structure failed: {case_id}")
        claims += len(points)
        fact_pass = row["material_proposition_coverage_complete"] is True and all(item["support_status"] == "SUPPORTED" for item in points) and all(value in {"PASS", "NOT_APPLICABLE"} for value in row["factual_checks"].values())
        dimensions = {name: round(float(row["quality_dimensions"][name]), 2) for name in QUALITY_MAX}
        if any(not 0 <= dimensions[name] <= QUALITY_MAX[name] for name in QUALITY_MAX):
            raise PlannedRouteError(f"quality range failed: {case_id}")
        score = round(sum(dimensions.values()), 2) if fact_pass else None
        floors = fact_pass and all(dimensions[name] >= floor for name, floor in QUALITY_FLOORS.items())
        quality_pass = fact_pass and score is not None and score >= 70 and floors
        factual += int(fact_pass)
        full += int(quality_pass)
        if score is not None:
            scores.append(score)
        if not quality_pass:
            failed.append(case_id)
        normalized.append(sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-ai-review.v1", "case_id": case_id, "candidate_answer_hash": expected_hash, "reviewer_kind": "AI_MODEL_REVIEWER", "professional_legal_sign_off": False, "material_proposition_coverage_complete": row["material_proposition_coverage_complete"], "required_point_reviews": points, "factual_checks": row["factual_checks"], "factual_outcome": "FACTUAL_PASS" if fact_pass else "FACTUAL_HOLD", "quality_dimensions": dimensions if fact_pass else {}, "quality_score": score, "critical_floor_pass": floors, "quality_outcome": "MEETS_70_STANDARD" if quality_pass else ("BELOW_70_OR_CRITICAL_FLOOR" if fact_pass else "NOT_SCORED_FACTUAL_HOLD"), "assessment_summary": normalise(str(row["assessment_summary"]))}))
    write_jsonl(PUBLIC_ROOT / "CODEX-BLIND-REVIEW.jsonl", normalized)
    if corrections:
        write_jsonl(PUBLIC_ROOT / "MECHANICAL-REVIEW-HASH-CORRECTIONS.jsonl", corrections)
    route_pass = factual == 23 and full == 23
    metrics = sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-metrics.v1", "campaign_id": CAMPAIGN_ID, "case_count": 23, "domain_count": 23, "source_count": 23, "coverage_plan_count": 23, "factual_pass_count": factual, "factual_hold_count": 23 - factual, "quality_70_floor_pass_count": full, "quality_hold_count": 23 - full, "mean_quality_score_on_factual_pass": round(sum(scores) / len(scores), 2) if scores else None, "minimum_quality_score_on_factual_pass": min(scores) if scores else None, "declared_material_claim_count": claims, "reviewed_material_claim_count": claims, "review_coverage_pct": 100.0, "failed_case_ids": failed, "mechanical_hash_correction_count": len(corrections), "route_pass": route_pass, "pass_definition": "23/23 factual and 23/23 score at least 70 with all critical floors."})
    write_json(PUBLIC_ROOT / "METRIC-REPORT.json", metrics)
    state_name = "POST_UNSEEN_FRESH_PLANNED_ROUTE_PASS_AWAITING_NEW_UNSEEN_BANK_DESIGN" if route_pass else "POST_UNSEEN_FRESH_PLANNED_ROUTE_HOLD_VISIBLE_REPAIR_REQUIRED"
    state = sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-state.v1", "campaign_id": CAMPAIGN_ID, "overall_state": state_name, "fresh_visible_generalisation": "PASS" if route_pass else "HOLD", "consumed_private_306_bank": "OPENED_ONCE_RETIRED_NOT_ACCESSED", "consumed_unseen_prompt_or_findings_used": False, "new_unseen_bank": "NOT_CREATED", "new_unseen_execution": "NOT_AUTHORIZED_NOT_STARTED", "answer_weight_training": "NOT_AUTHORIZED_NOT_PERFORMED", "r2_adapter": "INACTIVE_NOT_USED", "qualified_legal_review": "NOT_STARTED", "answer_legal_gold": "NOT_STARTED", "promotion": "NOT_STARTED", "live": "NOT_STARTED", "next_gate": "DESIGN_AND_INDEPENDENT_CUSTODY_OF_NEW_UNSEEN_BANK" if route_pass else "VISIBLE_REPAIR_ONLY", "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z")})
    write_json(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json", state)
    (PUBLIC_ROOT / "README.md").write_text(f"# {CAMPAIGN_ID}\n\nSecond new source-first visible evaluation after the exposed repair projection. Separate ephemeral contexts authored 23 cases, independently planned answer coverage without evaluator controls, wrote the answers, and performed blind review.\n\n- Factual pass: {factual}/23\n- Full 70+/floor pass: {full}/23\n- Declared claims reviewed: {claims}/{claims}\n- State: `{state_name}`\n\nThis is same-provider AI evidence, not qualified legal review, professional assurance or legal gold. No training or adapter use occurred. The consumed unseen bank and its findings were not accessed.\n")
    manifest = sealed({"schema": "legalbot.ge-post-unseen-fresh-planned-run.v1", "campaign_id": CAMPAIGN_ID, "source_manifest_sha256": sha256_file(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl"), "cases_sha256": sha256_file(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl"), "controls_sha256": sha256_file(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl"), "plans_sha256": sha256_file(PUBLIC_ROOT / "ANSWER-COVERAGE-PLANS.jsonl"), "outputs_sha256": sha256_file(PUBLIC_ROOT / "PLANNED-CODEX-OUTPUTS.jsonl"), "reviews_sha256": sha256_file(PUBLIC_ROOT / "CODEX-BLIND-REVIEW.jsonl"), "metrics_sha256": sha256_file(PUBLIC_ROOT / "METRIC-REPORT.json"), "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json"), "implementation_sha256": sha256_file(Path(__file__)), "model": "gpt-5.6-sol", "reasoning_effort": "high", "same_provider_ai": True, "ephemeral_contexts": 24, "consumed_unseen_root_read_denied": True})
    write_json(PUBLIC_ROOT / "RUN-MANIFEST.json", manifest)
    artifacts = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    write_json(PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json", {"schema": "legalbot.ge-post-unseen-fresh-planned-artifacts.v1", "campaign_id": CAMPAIGN_ID, "artifacts": artifacts})
    return {"overall_state": state_name, "factual_pass": factual, "full_pass": full, "claim_reviews": claims, "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json")}


def verify() -> dict[str, Any]:
    register = json.loads((PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json").read_text())
    actual = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    if register["artifacts"] != actual:
        raise PlannedRouteError("artifact register mismatch")
    for name in ("EVALUATION-CONTRACT.json", "METRIC-REPORT.json", "STATE-TRANSITION-RECEIPT.json", "RUN-MANIFEST.json"):
        verify_content_seal(json.loads((PUBLIC_ROOT / name).read_text()))
    state = json.loads((PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json").read_text())
    metrics = json.loads((PUBLIC_ROOT / "METRIC-REPORT.json").read_text())
    return {"verified": True, "overall_state": state["overall_state"], "factual_pass": metrics["factual_pass_count"], "full_pass": metrics["quality_70_floor_pass_count"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "run-author", "accept-author", "run-plan", "accept-plan", "run-answer", "accept-answer", "run-review", "finalize", "verify"))
    args = parser.parse_args()
    actions = {"prepare": prepare, "run-author": lambda: run_stage("author"), "accept-author": accept_authors, "run-plan": lambda: run_stage("plan"), "accept-plan": accept_plans, "run-answer": lambda: run_stage("answer"), "accept-answer": accept_answers, "run-review": lambda: run_stage("review"), "finalize": finalize, "verify": verify}
    print(json.dumps(actions[args.stage](), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
