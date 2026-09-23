#!/usr/bin/env python3
"""Run the source-first visible GE cycle after the retired one-pass unseen run.

This runner never reads the consumed unseen prompt bank or its detailed results.
It gives separate ephemeral Codex contexts only fresh official-source bundles,
then validates and seals the visible authoring, answer, and blind-review records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import certifi

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN_ID = "LegalBot-GE-2026-09-04-post-unseen-clean-visible-r3"
PUBLIC_ROOT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
SESSION_ROOT = Path.home() / ".legalbot-v111-clean-visible" / "2026-09-04" / CAMPAIGN_ID
CONSUMED_UNSEEN_ROOT = Path.home() / ".legalbot-v111-private/sealed-unseen-review"
CODEX = Path.home() / ".nvm/versions/node/v24.19.0/bin/codex"
REVIEW_AS_OF = date(2026, 9, 4)

LEG_NS = "http://www.legislation.gov.uk/namespaces/legislation"
META_NS = "http://www.legislation.gov.uk/namespaces/metadata"
DC_NS = "http://purl.org/dc/elements/1.1/"
DCT_NS = "http://purl.org/dc/terms/"

FACTUAL_CHECKS = (
    "integrity_chain",
    "claim_evidence_support",
    "user_fact_provenance",
    "jurisdiction_scope",
    "requested_date_and_currentness",
    "dates_amounts_and_deadlines",
    "citation_and_quotation_identity",
    "contradiction_and_counterauthority",
    "safety_and_urgent_action",
    "privacy_and_instruction_isolation",
)
QUALITY_MAX = {
    "legal_and_factual_accuracy": 25.0,
    "issue_coverage_and_reasoning": 15.0,
    "authority_and_currentness": 15.0,
    "practical_steps_and_urgency": 15.0,
    "uncertainty_limits_and_clarification": 10.0,
    "organisation_and_plain_language": 10.0,
    "traceability_and_citations": 10.0,
}
QUALITY_FLOORS = {
    "legal_and_factual_accuracy": 17.5,
    "authority_and_currentness": 10.5,
    "practical_steps_and_urgency": 9.0,
}


class CycleError(RuntimeError):
    """The clean visible cycle violated its frozen controls."""


@dataclass(frozen=True, slots=True)
class Source:
    topic: str
    coverage_kind: str
    key: str
    title: str
    path: str
    locator: str

    @property
    def url(self) -> str:
        return f"https://www.legislation.gov.uk/{self.path}/data.xml"


SOURCES = (
    Source("administrative-law", "LEGAL_TOPIC", "jrca1", "Judicial Review and Courts Act 2022", "ukpga/2022/35/section/1", "section 1"),
    Source("ai-and-data-protection", "LEGAL_TOPIC", "pecr22", "The Privacy and Electronic Communications (EC Directive) Regulations 2003", "uksi/2003/2426/regulation/22", "regulation 22"),
    Source("business-and-company-law", "LEGAL_TOPIC", "lpa1907_4", "Limited Partnerships Act 1907", "ukpga/1907/24/section/4", "section 4"),
    Source("commercial-law", "LEGAL_TOPIC", "etda2", "Electronic Trade Documents Act 2023", "ukpga/2023/38/section/2", "section 2"),
    Source("competition-law", "LEGAL_TOPIC", "sca12", "Subsidy Control Act 2022", "ukpga/2022/23/section/12", "section 12"),
    Source("contemporary-biolaw-and-regulation", "LEGAL_TOPIC", "oda1", "Organ Donation (Deemed Consent) Act 2019", "ukpga/2019/7/section/1", "section 1"),
    Source("contract-law", "LEGAL_TOPIC", "sgsa13", "Supply of Goods and Services Act 1982", "ukpga/1982/29/section/13", "section 13"),
    Source("criminal-law", "LEGAL_TOPIC", "fraud1", "Fraud Act 2006", "ukpga/2006/35/section/1", "section 1"),
    Source("eu-internal-market-law", "LEGAL_TOPIC", "reul3", "Retained EU Law (Revocation and Reform) Act 2023", "ukpga/2023/28/section/3", "section 3"),
    Source("international-commercial-mediation", "LEGAL_TOPIC", "icsid1", "Arbitration (International Investment Disputes) Act 1966", "ukpga/1966/41/section/1", "section 1"),
    Source("land-law", "LEGAL_TOPIC", "ltca5", "Landlord and Tenant (Covenants) Act 1995", "ukpga/1995/30/section/5", "section 5"),
    Source("law-and-medicine", "LEGAL_TOPIC", "aa1967_1", "Abortion Act 1967", "ukpga/1967/87/section/1", "section 1"),
    Source("pensions-law", "LEGAL_TOPIC", "psa1993_94", "Pension Schemes Act 1993", "ukpga/1993/48/section/94", "section 94"),
    Source("private-international-law", "LEGAL_TOPIC", "fjrea4", "Foreign Judgments (Reciprocal Enforcement) Act 1933", "ukpga/1933/13/section/4", "section 4"),
    Source("tort-law", "LEGAL_TOPIC", "animals2", "Animals Act 1971", "ukpga/1971/22/section/2", "section 2"),
    Source("trusts-law", "LEGAL_TOPIC", "tda1", "Trustee Delegation Act 1999", "ukpga/1999/15/section/1", "section 1"),
    Source("wills-and-estates", "LEGAL_TOPIC", "wills1963_1", "Wills Act 1963", "ukpga/1963/44/section/1", "section 1"),
    Source("housing", "PUBLIC_ACCESS_DOMAIN", "ha2004_213", "Housing Act 2004", "ukpga/2004/34/section/213", "section 213"),
    Source("employment", "PUBLIC_ACCESS_DOMAIN", "nmwa1", "National Minimum Wage Act 1998", "ukpga/1998/39/section/1", "section 1"),
    Source("family", "PUBLIC_ACCESS_DOMAIN", "daa1", "Domestic Abuse Act 2021", "ukpga/2021/17/section/1", "section 1"),
    Source("immigration", "PUBLIC_ACCESS_DOMAIN", "ia2014_22", "Immigration Act 2014", "ukpga/2014/22/section/22", "section 22"),
    Source("benefits-and-debt", "PUBLIC_ACCESS_DOMAIN", "wra1", "Welfare Reform Act 2012", "ukpga/2012/5/section/1", "section 1"),
    Source("consumer", "PUBLIC_ACCESS_DOMAIN", "ccr29", "The Consumer Contracts (Information, Cancellation and Additional Charges) Regulations 2013", "uksi/2013/3134/regulation/29", "regulation 29"),
)

PREDECESSOR_ROOTS = (
    PROJECT_ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-04-ai-auto-quality-review-r1",
    PROJECT_ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-04-fresh-visible-adapter-evaluation-r2",
    PROJECT_ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-04-fresh-visible-codex-evaluation-r1",
)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sealed(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = sha256_bytes(canonical(result))
    return result


def write_json(path: Path, value: Any, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    if mode is not None:
        path.chmod(mode)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(canonical(row).decode())


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def normalise(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def fetch_source(source: Source) -> tuple[Source, bytes, dict[str, str], str]:
    parsed = urlparse(source.url)
    if parsed.scheme != "https" or parsed.hostname != "www.legislation.gov.uk":
        raise CycleError(f"source URL rejected: {source.url}")
    request = urllib.request.Request(source.url, headers={"User-Agent": "LegalBot-evaluation/1.0"})
    context = ssl.create_default_context(cafile=certifi.where())
    with urllib.request.urlopen(request, timeout=45, context=context) as response:
        if response.status != 200:
            raise CycleError(f"HTTP {response.status}: {source.url}")
        return source, response.read(), dict(response.headers.items()), response.url


def parse_source(source: Source, body: bytes, headers: dict[str, str], final_url: str) -> dict[str, Any]:
    if urlparse(final_url).hostname != "www.legislation.gov.uk":
        raise CycleError(f"off-allowlist redirect: {final_url}")
    root = ET.fromstring(body)
    title = normalise(root.findtext(f".//{{{DC_NS}}}title") or "")
    valid = normalise(root.findtext(f".//{{{DCT_NS}}}valid") or "")
    modified = normalise(root.findtext(f".//{{{DC_NS}}}modified") or "")
    status_node = root.find(f".//{{{META_NS}}}DocumentStatus")
    status = status_node.attrib.get("Value", "") if status_node is not None else ""
    if title != source.title or status != "revised":
        raise CycleError(f"official metadata mismatch: {source.key} {title!r} {status!r}")
    if not valid or not modified or date.fromisoformat(valid) > REVIEW_AS_OF or date.fromisoformat(modified) > REVIEW_AS_OF:
        raise CycleError(f"invalid as-of metadata: {source.key} {valid!r} {modified!r}")
    texts = [normalise("".join(node.itertext())) for node in root.findall(f".//{{{LEG_NS}}}P1para//{{{LEG_NS}}}Text")]
    excerpt = " ".join(text for text in texts if text)
    if not excerpt or len(excerpt) > 12_000:
        raise CycleError(f"source excerpt size rejected: {source.key} {len(excerpt)}")
    raw_sha = sha256_bytes(body)
    return sealed({
        "schema": "legalbot.ge-post-unseen-clean-visible-source.v1",
        "source_key": source.key,
        "topic": source.topic,
        "coverage_kind": source.coverage_kind,
        "title": title,
        "locator": source.locator,
        "canonical_url": final_url.replace("http://", "https://"),
        "document_status": status,
        "consolidated_valid_date": valid,
        "metadata_modified_date": modified,
        "http_last_modified": headers.get("Last-Modified", ""),
        "raw_sha256": raw_sha,
        "raw_bytes": len(body),
        "evidence_excerpt": excerpt,
        "evidence_span_sha256": sha256_bytes(excerpt.encode()),
        "retrieved_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "runtime_admitted": False,
        "qualified_legal_review": "NOT_STARTED",
        "legal_gold": False,
    })


def all_predecessor_strings() -> set[str]:
    values: set[str] = set()
    for root in PREDECESSOR_ROOTS:
        for path in root.glob("*.json*"):
            try:
                content: Any = load_jsonl(path) if path.suffix == ".jsonl" else json.loads(path.read_text())
            except (OSError, ValueError):
                continue
            stack = [content]
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(item.values())
                elif isinstance(item, list):
                    stack.extend(item)
                elif isinstance(item, str):
                    values.add(item)
    return values


def author_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {"cases": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "case_id": {"type": "string"}, "topic": {"type": "string"},
                "coverage_kind": {"type": "string"}, "question": {"type": "string"},
                "required_points": {"type": "array", "items": {"type": "string"}},
                "material_limits": {"type": "array", "items": {"type": "string"}},
                "prohibited_overclaims": {"type": "array", "items": {"type": "string"}},
                "source_sufficient": {"type": "boolean"},
            },
            "required": ["case_id", "topic", "coverage_kind", "question", "required_points", "material_limits", "prohibited_overclaims", "source_sufficient"],
            "additionalProperties": False,
        }}},
        "required": ["cases"], "additionalProperties": False,
    }


def answer_schema() -> dict[str, Any]:
    return {
        "type": "object", "properties": {"answers": {"type": "array", "items": {
            "type": "object", "properties": {"case_id": {"type": "string"}, "candidate_answer": {"type": "string"}},
            "required": ["case_id", "candidate_answer"], "additionalProperties": False,
        }}}, "required": ["answers"], "additionalProperties": False,
    }


def review_schema() -> dict[str, Any]:
    check_props = {name: {"enum": ["PASS", "FAIL", "NOT_APPLICABLE"]} for name in FACTUAL_CHECKS}
    score_props = {name: {"type": "number", "minimum": 0, "maximum": maximum} for name, maximum in QUALITY_MAX.items()}
    return {
        "type": "object", "properties": {"reviews": {"type": "array", "items": {
            "type": "object", "properties": {
                "case_id": {"type": "string"}, "candidate_answer_hash": {"type": "string"},
                "material_proposition_coverage_complete": {"type": "boolean"},
                "required_point_reviews": {"type": "array", "items": {"type": "object", "properties": {
                    "required_point_index": {"type": "integer", "minimum": 1},
                    "support_status": {"enum": ["SUPPORTED", "UNSUPPORTED"]},
                    "explanation": {"type": "string"},
                }, "required": ["required_point_index", "support_status", "explanation"], "additionalProperties": False}},
                "factual_checks": {"type": "object", "properties": check_props, "required": list(check_props), "additionalProperties": False},
                "quality_dimensions": {"type": "object", "properties": score_props, "required": list(score_props), "additionalProperties": False},
                "assessment_summary": {"type": "string"},
            },
            "required": ["case_id", "candidate_answer_hash", "material_proposition_coverage_complete", "required_point_reviews", "factual_checks", "quality_dimensions", "assessment_summary"],
            "additionalProperties": False,
        }}}, "required": ["reviews"], "additionalProperties": False,
    }


def shard(items: list[Any], count: int = 6) -> list[list[Any]]:
    return [items[index::count] for index in range(count)]


def prepare() -> dict[str, Any]:
    if PUBLIC_ROOT.exists() or SESSION_ROOT.exists():
        raise CycleError("refusing to replace an existing clean-visible campaign")
    if not CODEX.is_file():
        raise CycleError(f"Codex CLI missing: {CODEX}")
    topics = [source.topic for source in SOURCES]
    if len(SOURCES) != 23 or len(set(topics)) != 23 or Counter(x.coverage_kind for x in SOURCES) != {"LEGAL_TOPIC": 17, "PUBLIC_ACCESS_DOMAIN": 6}:
        raise CycleError("23-domain topology changed")
    prior = all_predecessor_strings()
    overlap = sorted(source.title for source in SOURCES if source.title in prior)
    if overlap:
        raise CycleError(f"source-title leakage from prior public cycles: {overlap}")
    PUBLIC_ROOT.mkdir(parents=True)
    snapshots = PUBLIC_ROOT / "official-source-snapshots"
    snapshots.mkdir()
    SESSION_ROOT.mkdir(parents=True, mode=0o700)
    SESSION_ROOT.chmod(0o700)
    captured: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(fetch_source, source) for source in SOURCES]
        for future in as_completed(futures):
            source, body, headers, final_url = future.result()
            record = parse_source(source, body, headers, final_url)
            path = snapshots / f"{record['raw_sha256']}.xml"
            with path.open("xb") as handle:
                handle.write(body)
            captured.append(record)
    captured.sort(key=lambda row: topics.index(str(row["topic"])))
    write_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl", captured)
    contract = sealed({
        "schema": "legalbot.ge-post-unseen-clean-visible-contract.v1",
        "campaign_id": CAMPAIGN_ID,
        "route": "FRESH_SOURCE_FIRST_VISIBLE_CODEX_NON_WEIGHT",
        "case_count": 23,
        "coverage": {"legal_topics": 17, "public_access_domains": 6},
        "review_as_of": REVIEW_AS_OF.isoformat(),
        "old_unseen_bank": "CONSUMED_RETIRED_DENIED_TO_SESSIONS",
        "old_unseen_prompt_or_findings_use": False,
        "answer_weight_training": "NOT_AUTHORIZED_NOT_PERFORMED",
        "r2_adapter": "INACTIVE_NOT_USED",
        "pass_rule": "23/23 factual passes and 23/23 scores at least 70 with every critical floor met",
        "reviewer_kind": "AI_MODEL_REVIEWER",
        "same_provider_limitation": True,
        "qualified_legal_review": "NOT_STARTED",
        "legal_gold": "NOT_STARTED",
    })
    write_json(PUBLIC_ROOT / "EVALUATION-CONTRACT.json", contract)
    author_dir = SESSION_ROOT / "author"
    author_dir.mkdir(mode=0o700)
    for index, group in enumerate(shard(captured), 1):
        work = author_dir / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        expected = []
        payload = []
        for row in group:
            case_id = f"{row['topic']}:post-unseen-visible-r1-01"
            expected.append(case_id)
            payload.append({k: row[k] for k in ("topic", "coverage_kind", "source_key", "title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")})
            payload[-1]["case_id"] = case_id
        write_json(work / "input.json", {"cases": payload, "expected_case_ids": expected}, mode=0o600)
        write_json(work / "schema.json", author_schema(), mode=0o600)
    return {"campaign": str(PUBLIC_ROOT), "session_root": str(SESSION_ROOT), "sources": len(captured), "stage": "PREPARED_FOR_AUTHORING"}


AUTHOR_PROMPT = """Read input.json only. For each supplied current official legislation excerpt, create one new visible General Enquiry evaluation case for an ordinary England-and-Wales user. Use only that excerpt. Keep the assigned case_id, topic and coverage_kind exactly. Ask a focused practical question answerable from the excerpt. State 3-5 separately checkable required legal points, 1-3 material limits or missing facts, and 2-4 concrete prohibited overclaims. source_sufficient must be true only if the excerpt is sufficient for that bounded question. Do not browse, run code, inspect other paths, answer the question, or refer to any prior evaluation. Return every assigned case exactly once."""

ANSWER_PROMPT = """Read input.json only. Answer every assigned General Enquiry question using only its supplied official evidence. Give a direct, complete, plain-English answer. Separate the law from unverified user facts; include the material statutory conditions and limits needed for the question; identify the source and locator in ordinary prose; and give a safe, useful next step. Do not invent cases, remedies, deadlines, amounts, facts, currentness, professional sign-off or material beyond the evidence. Do not browse, run code, inspect other paths, or refer to hidden controls or evaluation. Return every assigned case exactly once and only finished answers."""

REVIEW_PROMPT = """Read input.json only. Blindly review every exact candidate against its official excerpt and disclosed controls. Review all required points. A required point is SUPPORTED only when the answer states it accurately and the excerpt supports it. Mark material_proposition_coverage_complete false for a material omission, contradiction or unsupported addition. Apply every factual check; use NOT_APPLICABLE only when truly irrelevant. Score each quality dimension independently within its stated maximum; do not inflate scores and do not assume that 70 is earned. Quality scores are considered only after factual pass. Do not browse, run code, inspect other paths, rewrite an answer, or infer professional approval. Return every assigned case exactly once."""


def run_codex(work: Path, prompt: str) -> tuple[str, int, str]:
    profile = (
        '(version 1)(allow default)'
        f'(deny file-read* (subpath "{PROJECT_ROOT}"))'
        f'(deny file-read* (subpath "{CONSUMED_UNSEEN_ROOT}"))'
        f'(deny file-write* (subpath "{PROJECT_ROOT}"))'
        f'(deny file-write* (subpath "{CONSUMED_UNSEEN_ROOT}"))'
    )
    command = [
        "/usr/bin/sandbox-exec", "-p", profile, str(CODEX), "exec", "--ephemeral",
        "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "-C", str(work),
        "--dangerously-bypass-approvals-and-sandbox", "-m", "gpt-5.6-sol",
        "-c", 'model_reasoning_effort="high"',
        "--output-schema", str(work / "schema.json"), "-o", str(work / "output.json"), "-",
    ]
    completed = subprocess.run(
        command,
        input=prompt,
        text=True,
        capture_output=True,
        timeout=1200,
        cwd=work,
    )
    (work / "codex.stdout.log").write_text(completed.stdout)
    (work / "codex.stderr.log").write_text(completed.stderr)
    for path in work.iterdir():
        if path.is_file():
            path.chmod(0o600)
    return work.name, completed.returncode, completed.stderr[-1200:]


def run_stage(stage: str) -> dict[str, Any]:
    prompts = {"author": AUTHOR_PROMPT, "candidate": ANSWER_PROMPT, "review": REVIEW_PROMPT}
    root = SESSION_ROOT / stage
    if not root.is_dir():
        raise CycleError(f"stage inputs missing: {root}")
    workdirs = sorted(path for path in root.iterdir() if path.is_dir())
    if not workdirs or any((path / "output.json").exists() for path in workdirs):
        raise CycleError(f"stage is not clean: {stage}")
    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_codex, path, prompts[stage]): path for path in workdirs}
        for future in as_completed(futures):
            results.append(future.result())
    failures = [item for item in results if item[1] != 0 or not (root / item[0] / "output.json").is_file()]
    if failures:
        raise CycleError(f"{stage} session failures: {failures}")
    return {"stage": stage, "completed_shards": len(results), "results": sorted(results)}


def collect_stage(stage: str, key: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((SESSION_ROOT / stage).glob("shard-*/output.json")):
        value = json.loads(path.read_text())
        rows.extend(value[key])
    return rows


def build_candidate_inputs() -> dict[str, Any]:
    sources = load_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")
    source_by_topic = {row["topic"]: row for row in sources}
    authors = collect_stage("author", "cases")
    expected_ids = {f"{source.topic}:post-unseen-visible-r1-01" for source in SOURCES}
    if len(authors) != 23 or {row.get("case_id") for row in authors} != expected_ids:
        raise CycleError("authoring output case set mismatch")
    prior = all_predecessor_strings()
    cases = []
    controls = []
    questions: set[str] = set()
    for ordinal, source in enumerate(SOURCES, 1):
        case_id = f"{source.topic}:post-unseen-visible-r1-01"
        row = next(item for item in authors if item["case_id"] == case_id)
        if row["topic"] != source.topic or row["coverage_kind"] != source.coverage_kind or row["source_sufficient"] is not True:
            raise CycleError(f"invalid author binding: {case_id}")
        question = normalise(str(row["question"]))
        required = [normalise(str(x)) for x in row["required_points"]]
        limits = [normalise(str(x)) for x in row["material_limits"]]
        overclaims = [normalise(str(x)) for x in row["prohibited_overclaims"]]
        if not 3 <= len(required) <= 5 or not 1 <= len(limits) <= 3 or not 2 <= len(overclaims) <= 4:
            raise CycleError(f"invalid control cardinality: {case_id}")
        question_hash = sha256_bytes(question.encode())
        if question in prior or question_hash in prior or question_hash in questions:
            raise CycleError(f"question leakage or duplicate: {case_id}")
        questions.add(question_hash)
        evidence = source_by_topic[source.topic]
        ref = {k: evidence[k] for k in ("source_key", "title", "locator", "raw_sha256", "evidence_span_sha256")}
        cases.append(sealed({"schema": "legalbot.ge-post-unseen-clean-visible-case.v1", "ordinal": ordinal, "case_id": case_id, "topic": source.topic, "coverage_kind": source.coverage_kind, "question": question, "question_hash": question_hash, "evidence_references": [ref], "private_unseen_source": False, "trained_or_prior_visible_question": False}))
        controls.append(sealed({"schema": "legalbot.ge-post-unseen-clean-visible-control.v1", "ordinal": ordinal, "case_id": case_id, "required_points": required, "material_limits": limits, "prohibited_overclaims": overclaims, "evidence_references": [ref]}))
    write_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl", cases)
    write_jsonl(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl", controls)
    candidate_dir = SESSION_ROOT / "candidate"
    candidate_dir.mkdir(mode=0o700)
    rows = []
    for case in cases:
        evidence = source_by_topic[case["topic"]]
        rows.append({"case_id": case["case_id"], "question": case["question"], "official_evidence": {k: evidence[k] for k in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}})
    for index, group in enumerate(shard(rows), 1):
        work = candidate_dir / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        write_json(work / "input.json", {"cases": group, "expected_case_ids": [x["case_id"] for x in group]}, mode=0o600)
        write_json(work / "schema.json", answer_schema(), mode=0o600)
    return {"stage": "AUTHORING_ACCEPTED", "case_count": len(cases), "next": "candidate"}


def build_review_inputs() -> dict[str, Any]:
    cases = load_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl")
    controls = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl")}
    sources = {row["topic"]: row for row in load_jsonl(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl")}
    answers = collect_stage("candidate", "answers")
    expected = {row["case_id"] for row in cases}
    if len(answers) != 23 or {row.get("case_id") for row in answers} != expected:
        raise CycleError("candidate output case set mismatch")
    output_rows = []
    review_rows = []
    for case in cases:
        answer = normalise(str(next(row["candidate_answer"] for row in answers if row["case_id"] == case["case_id"])))
        if len(answer.split()) < 70 or len(answer.split()) > 420 or any(token in answer.lower() for token in ("candidate answer", "owner review", "complete controlling law has not been shown")):
            raise CycleError(f"candidate surface guard failed: {case['case_id']}")
        answer_hash = sha256_bytes(answer.encode())
        output_rows.append(sealed({"schema": "legalbot.ge-post-unseen-clean-visible-output.v1", "ordinal": case["ordinal"], "case_id": case["case_id"], "question_hash": case["question_hash"], "candidate_answer": answer, "candidate_answer_hash": answer_hash, "candidate_variant": "CODEX_SOURCE_BOUND_NON_WEIGHT", "professional_legal_sign_off": False, "weight_training_performed": False, "adapter_used": False}))
        source = sources[case["topic"]]
        control = controls[case["case_id"]]
        review_rows.append({"case_id": case["case_id"], "topic": case["topic"], "coverage_kind": case["coverage_kind"], "question": case["question"], "question_hash": case["question_hash"], "candidate_answer": answer, "candidate_answer_hash": answer_hash, "official_evidence": {k: source[k] for k in ("title", "locator", "canonical_url", "document_status", "consolidated_valid_date", "metadata_modified_date", "raw_sha256", "evidence_span_sha256", "evidence_excerpt")}, "required_points": control["required_points"], "material_limits": control["material_limits"], "prohibited_overclaims": control["prohibited_overclaims"], "factual_checks": list(FACTUAL_CHECKS), "quality_dimension_maxima": QUALITY_MAX, "critical_floors": QUALITY_FLOORS, "reviewer_kind_required": "AI_MODEL_REVIEWER", "professional_legal_sign_off": False})
    write_jsonl(PUBLIC_ROOT / "CODEX-SOURCE-BOUND-OUTPUTS.jsonl", output_rows)
    review_dir = SESSION_ROOT / "review"
    review_dir.mkdir(mode=0o700)
    for index, group in enumerate(shard(review_rows), 1):
        work = review_dir / f"shard-{index:02d}"
        work.mkdir(mode=0o700)
        write_json(work / "input.json", {"cases": group, "expected_case_ids": [x["case_id"] for x in group]}, mode=0o600)
        write_json(work / "schema.json", review_schema(), mode=0o600)
    return {"stage": "CANDIDATES_ACCEPTED", "answer_count": len(output_rows), "next": "review"}


def verify_content_seal(value: dict[str, Any]) -> None:
    claimed = value.get("content_sha256")
    material = dict(value)
    material.pop("content_sha256", None)
    if claimed != sha256_bytes(canonical(material)):
        raise CycleError("content seal mismatch")


def finalize() -> dict[str, Any]:
    cases = load_jsonl(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl")
    controls = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl")}
    outputs = {row["case_id"]: row for row in load_jsonl(PUBLIC_ROOT / "CODEX-SOURCE-BOUND-OUTPUTS.jsonl")}
    raw_reviews = collect_stage("review", "reviews")
    expected = {row["case_id"] for row in cases}
    if len(raw_reviews) != 23 or {row.get("case_id") for row in raw_reviews} != expected:
        raise CycleError("blind review case set mismatch")
    reviews = []
    claim_count = 0
    factual_pass_count = 0
    full_pass_count = 0
    failed_cases = []
    hash_corrections = []
    for case in cases:
        case_id = case["case_id"]
        row = next(item for item in raw_reviews if item["case_id"] == case_id)
        expected_answer_hash = outputs[case_id]["candidate_answer_hash"]
        echoed_answer_hash = row["candidate_answer_hash"]
        if echoed_answer_hash != expected_answer_hash:
            if expected_answer_hash != sha256_bytes(outputs[case_id]["candidate_answer"].encode()):
                raise CycleError(f"frozen answer identity mismatch: {case_id}")
            hash_corrections.append(sealed({
                "schema": "legalbot.ge-post-unseen-review-hash-correction.v1",
                "case_id": case_id,
                "reviewer_echoed_candidate_answer_hash": echoed_answer_hash,
                "bound_candidate_answer_hash": expected_answer_hash,
                "correction_kind": "MECHANICAL_ECHO_NORMALIZATION",
                "answer_text_changed": False,
                "review_changed": False,
            }))
        expected_indices = set(range(1, len(controls[case_id]["required_points"]) + 1))
        point_reviews = row["required_point_reviews"]
        if {item["required_point_index"] for item in point_reviews} != expected_indices or len(point_reviews) != len(expected_indices):
            raise CycleError(f"required point review mismatch: {case_id}")
        claim_count += len(point_reviews)
        checks = row["factual_checks"]
        if set(checks) != set(FACTUAL_CHECKS):
            raise CycleError(f"factual check mismatch: {case_id}")
        factual_pass = row["material_proposition_coverage_complete"] is True and all(item["support_status"] == "SUPPORTED" for item in point_reviews) and all(value in {"PASS", "NOT_APPLICABLE"} for value in checks.values())
        dimensions = {name: round(float(row["quality_dimensions"][name]), 2) for name in QUALITY_MAX}
        if any(dimensions[name] < 0 or dimensions[name] > QUALITY_MAX[name] for name in QUALITY_MAX):
            raise CycleError(f"quality score outside range: {case_id}")
        score = round(sum(dimensions.values()), 2) if factual_pass else None
        floor_pass = factual_pass and all(dimensions[name] >= floor for name, floor in QUALITY_FLOORS.items())
        quality_pass = factual_pass and score is not None and score >= 70 and floor_pass
        factual_pass_count += int(factual_pass)
        full_pass_count += int(quality_pass)
        if not quality_pass:
            failed_cases.append(case_id)
        reviews.append(sealed({
            "schema": "legalbot.ge-post-unseen-clean-visible-ai-review.v1", "case_id": case_id,
            "question_hash": case["question_hash"], "candidate_answer_hash": expected_answer_hash,
            "reviewer_kind": "AI_MODEL_REVIEWER", "professional_legal_sign_off": False,
            "review_scope": "Exact candidate against one newly captured official source excerpt and disclosed controls only.",
            "material_proposition_coverage_complete": row["material_proposition_coverage_complete"],
            "required_point_reviews": point_reviews, "factual_checks": checks,
            "factual_outcome": "FACTUAL_PASS" if factual_pass else "FACTUAL_HOLD",
            "quality_dimensions": dimensions if factual_pass else {}, "quality_score": score,
            "critical_floor_pass": floor_pass,
            "quality_outcome": "MEETS_70_STANDARD" if quality_pass else ("BELOW_70_OR_CRITICAL_FLOOR" if factual_pass else "NOT_SCORED_FACTUAL_HOLD"),
            "assessment_summary": normalise(str(row["assessment_summary"])),
        }))
    write_jsonl(PUBLIC_ROOT / "CODEX-BLIND-REVIEW.jsonl", reviews)
    if hash_corrections:
        write_jsonl(PUBLIC_ROOT / "MECHANICAL-REVIEW-HASH-CORRECTIONS.jsonl", hash_corrections)
    route_pass = factual_pass_count == 23 and full_pass_count == 23
    state_name = "POST_UNSEEN_CLEAN_VISIBLE_PASS_NEXT_NEW_UNSEEN_BANK_DESIGN" if route_pass else "POST_UNSEEN_CLEAN_VISIBLE_HOLD_VISIBLE_REPAIR_REQUIRED"
    metrics = sealed({
        "schema": "legalbot.ge-post-unseen-clean-visible-metrics.v1", "campaign_id": CAMPAIGN_ID,
        "case_count": 23, "source_count": 23, "domain_count": 23,
        "factual_pass_count": factual_pass_count, "factual_hold_count": 23 - factual_pass_count,
        "quality_70_floor_pass_count": full_pass_count, "quality_hold_count": 23 - full_pass_count,
        "declared_material_claim_count": claim_count, "reviewed_material_claim_count": claim_count,
        "review_coverage_pct": 100.0, "route_pass": route_pass, "failed_case_ids": failed_cases,
        "mechanical_reviewer_hash_correction_count": len(hash_corrections),
        "pass_definition": "All 23 cases factually pass and score at least 70 with each critical floor met.",
    })
    write_json(PUBLIC_ROOT / "METRIC-REPORT.json", metrics)
    state = sealed({
        "schema": "legalbot.ge-post-unseen-clean-visible-state.v1", "campaign_id": CAMPAIGN_ID,
        "overall_state": state_name, "fresh_visible_evaluation": "PASS" if route_pass else "HOLD",
        "consumed_private_306_bank": "OPENED_ONCE_RETIRED_NOT_ACCESSED_BY_THIS_CYCLE",
        "consumed_unseen_prompt_or_findings_used": False,
        "new_unseen_bank": "NOT_CREATED", "new_unseen_execution": "NOT_AUTHORIZED_NOT_STARTED",
        "answer_weight_training": "NOT_AUTHORIZED_NOT_PERFORMED", "r2_adapter": "INACTIVE_NOT_USED",
        "qualified_legal_review": "NOT_STARTED", "answer_legal_gold": "NOT_STARTED",
        "promotion": "NOT_STARTED", "live": "NOT_STARTED",
        "next_gate": "DESIGN_AND_INDEPENDENT_CUSTODY_OF_A_NEW_UNSEEN_BANK" if route_pass else "VISIBLE_REPAIR_ONLY",
        "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    })
    write_json(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json", state)
    readme = f"""# {CAMPAIGN_ID}\n\nThis source-first visible campaign used 23 new official legislation.gov.uk snapshots, one for each GE domain. Separate ephemeral Codex contexts authored the cases, generated the non-weight answers, and performed blind factual-first 70+/floor review. The consumed unseen bank and its findings were denied to these sessions.\n\n- Factual pass: {factual_pass_count}/23\n- Full 70+/floor pass: {full_pass_count}/23\n- Reviewed declared claims: {claim_count}/{claim_count}\n- State: `{state_name}`\n\nThis is same-provider AI evaluation. It is not qualified legal review, professional assurance, answer legal gold, promotion, or live authorization. The r2 adapter remained inactive and no training occurred.\n"""
    with (PUBLIC_ROOT / "README.md").open("x") as handle:
        handle.write(readme)
    manifest = sealed({
        "schema": "legalbot.ge-post-unseen-clean-visible-run.v1", "campaign_id": CAMPAIGN_ID,
        "official_source_manifest_sha256": sha256_file(PUBLIC_ROOT / "OFFICIAL-SOURCE-MANIFEST.jsonl"),
        "cases_sha256": sha256_file(PUBLIC_ROOT / "FRESH-VISIBLE-CASES.jsonl"),
        "controls_sha256": sha256_file(PUBLIC_ROOT / "EXPECTED-CONTROLS.jsonl"),
        "outputs_sha256": sha256_file(PUBLIC_ROOT / "CODEX-SOURCE-BOUND-OUTPUTS.jsonl"),
        "blind_review_sha256": sha256_file(PUBLIC_ROOT / "CODEX-BLIND-REVIEW.jsonl"),
        "metrics_sha256": sha256_file(PUBLIC_ROOT / "METRIC-REPORT.json"),
        "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json"),
        "implementation_sha256": sha256_file(Path(__file__)),
        "model": "gpt-5.6-sol", "reasoning_effort": "high", "same_provider_ai": True,
        "ephemeral_stage_contexts": 18, "old_unseen_root_read_denied": True,
    })
    write_json(PUBLIC_ROOT / "RUN-MANIFEST.json", manifest)
    artifacts = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    write_json(PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json", {"schema": "legalbot.ge-post-unseen-clean-visible-artifacts.v1", "campaign_id": CAMPAIGN_ID, "artifacts": artifacts})
    return {"campaign": str(PUBLIC_ROOT), "overall_state": state_name, "factual_pass": factual_pass_count, "full_pass": full_pass_count, "claim_reviews": claim_count, "state_sha256": sha256_file(PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json")}


def verify() -> dict[str, Any]:
    register = json.loads((PUBLIC_ROOT / "ARTIFACT-SHA256-REGISTER.json").read_text())
    actual = {path.relative_to(PUBLIC_ROOT).as_posix(): sha256_file(path) for path in sorted(PUBLIC_ROOT.rglob("*")) if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"}
    if register.get("artifacts") != actual:
        raise CycleError("artifact register mismatch")
    for name in ("EVALUATION-CONTRACT.json", "METRIC-REPORT.json", "STATE-TRANSITION-RECEIPT.json", "RUN-MANIFEST.json"):
        verify_content_seal(json.loads((PUBLIC_ROOT / name).read_text()))
    metrics = json.loads((PUBLIC_ROOT / "METRIC-REPORT.json").read_text())
    state = json.loads((PUBLIC_ROOT / "STATE-TRANSITION-RECEIPT.json").read_text())
    if metrics["case_count"] != 23 or metrics["factual_pass_count"] + metrics["factual_hold_count"] != 23 or metrics["quality_70_floor_pass_count"] + metrics["quality_hold_count"] != 23:
        raise CycleError("metric denominator mismatch")
    if state["consumed_unseen_prompt_or_findings_used"] is not False or state["answer_weight_training"] != "NOT_AUTHORIZED_NOT_PERFORMED" or state["r2_adapter"] != "INACTIVE_NOT_USED":
        raise CycleError("terminal controls changed")
    return {"verified": True, "overall_state": state["overall_state"], "factual_pass": metrics["factual_pass_count"], "full_pass": metrics["quality_70_floor_pass_count"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "run-author", "accept-author", "run-candidate", "accept-candidate", "run-review", "finalize", "verify"))
    args = parser.parse_args()
    actions = {
        "prepare": prepare, "run-author": lambda: run_stage("author"),
        "accept-author": build_candidate_inputs, "run-candidate": lambda: run_stage("candidate"),
        "accept-candidate": build_review_inputs, "run-review": lambda: run_stage("review"),
        "finalize": finalize, "verify": verify,
    }
    print(json.dumps(actions[args.stage](), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
