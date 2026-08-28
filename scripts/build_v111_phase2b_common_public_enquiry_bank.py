#!/usr/bin/env python3
"""Build a non-authorizing common-public enquiry bank for Phase 2B review.

This builder creates synthetic question records and a readable owner-review
projection. It does not read Phase 2A evidence, admit sources, scan, build an
index, run retrieval, call an answer model, freeze validation, or start Phase 2B.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PARENT = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
RUN_NAME = "LegalBot-Phase2B-2026-08-28-common-public-enquiries-draft-r1"
OUTPUT_ROOT = OUTPUT_PARENT / RUN_NAME
QUESTION_MODULE = PROJECT_ROOT / "scripts/phase2b_common_public_enquiry_questions.py"

R3_RUN_NAME = "LegalBot-Phase2B-2026-08-28-full-question-bank-draft-r3"
R3_ROOT = OUTPUT_PARENT / R3_RUN_NAME
R3_PACKAGE_SHA256 = "cc625f2b80323654fbd4c3e3a53b16ac99fe54eb460f1a20fc04461c98ce79ec"
EXPANSION_RUN_NAME = "LegalBot-Phase2B-2026-08-28-expansion-and-pre-gold-r1"
EXPANSION_ROOT = OUTPUT_PARENT / EXPANSION_RUN_NAME
EXPANSION_PACKAGE_SHA256 = "66493d9a8dcf54f5fa563be521ce42674ff30222d54b037e76e7b0afa47f968a"

LEGAL_CURRENTNESS_CUTOFF = "2026-08-28"
LEAKAGE_COSINE_THRESHOLD = 0.55
QUESTION_SCHEMA = "legalbot.v111.phase2b.common-public-enquiry-draft.v1"
TOPIC_SCHEMA = "legalbot.v111.phase2b.common-public-topic-draft.v1"
PACKAGE_SCHEMA = "legalbot.v111.phase2b.common-public-enquiry-package.v1"

DISPLAY_NAMES = {
    "administrative-law": "Administrative Law",
    "ai-and-data-protection": "AI and Data Protection",
    "business-and-company-law": "Business and Company Law",
    "commercial-law": "Commercial Law",
    "competition-law": "Competition Law",
    "contemporary-biolaw-and-regulation": "Contemporary Biolaw and Regulation",
    "contract-law": "Contract Law",
    "criminal-law": "Criminal Law",
    "eu-internal-market-law": "EU Internal Market Law",
    "international-commercial-mediation": "International Commercial Mediation",
    "land-law": "Land Law",
    "law-and-medicine": "Law and Medicine",
    "pensions-law": "Pensions Law",
    "private-international-law": "Private International Law",
    "tort-law": "Tort Law",
    "trusts-law": "Trusts Law",
    "wills-and-estates": "Wills and Estates",
}

DEFAULT_JURISDICTIONS = {
    "administrative-law": ["ENGLAND_AND_WALES"],
    "ai-and-data-protection": ["UNITED_KINGDOM", "EUROPEAN_UNION"],
    "business-and-company-law": ["ENGLAND_AND_WALES", "UNITED_KINGDOM"],
    "commercial-law": ["ENGLAND_AND_WALES"],
    "competition-law": ["UNITED_KINGDOM", "EUROPEAN_UNION"],
    "contemporary-biolaw-and-regulation": ["UNITED_KINGDOM"],
    "contract-law": ["ENGLAND_AND_WALES"],
    "criminal-law": ["ENGLAND_AND_WALES"],
    "eu-internal-market-law": ["EUROPEAN_UNION"],
    "international-commercial-mediation": ["ENGLAND_AND_WALES", "CROSS_BORDER"],
    "land-law": ["ENGLAND_AND_WALES"],
    "law-and-medicine": ["UNITED_KINGDOM_NATION_CHECK_REQUIRED"],
    "pensions-law": ["UNITED_KINGDOM"],
    "private-international-law": ["ENGLAND_AND_WALES", "CROSS_BORDER"],
    "tort-law": ["ENGLAND_AND_WALES"],
    "trusts-law": ["ENGLAND_AND_WALES"],
    "wills-and-estates": ["ENGLAND_AND_WALES"],
}

TOPIC_DOCUMENTS = {
    "administrative-law": ["DECISION_LETTER", "PUBLISHED_POLICY", "STATUTORY_APPEAL_INFORMATION", "RELEVANT_CORRESPONDENCE"],
    "ai-and-data-protection": ["PRIVACY_NOTICE", "ACCESS_OR_CORRECTION_REQUEST", "AUTOMATED_DECISION_NOTICE", "RELEVANT_SCREENSHOTS"],
    "business-and-company-law": ["COMPANY_REGISTER", "ARTICLES_OR_AGREEMENT", "BOARD_AND_SHARE_RECORDS", "RELEVANT_CONTRACT"],
    "commercial-law": ["SALE_CONTRACT", "INVOICE_AND_PAYMENT_RECORD", "DELIVERY_OR_TITLE_DOCUMENT", "RELEVANT_CORRESPONDENCE"],
    "competition-law": ["AGREEMENT_OR_TERMS", "PRICING_OR_ACCESS_RECORD", "MARKET_AND_COMPETITOR_FACTS", "RELEVANT_COMMUNICATIONS"],
    "contemporary-biolaw-and-regulation": ["CONSENT_FORM", "DEVICE_OR_STUDY_INFORMATION", "DATA_NOTICE", "CLINICAL_OR_INCIDENT_RECORD"],
    "contract-law": ["CONTRACT_AND_TERMS", "ORDER_OR_PAYMENT_RECORD", "NOTICE_OR_CANCELLATION", "RELEVANT_CORRESPONDENCE"],
    "criminal-law": ["POLICE_OR_COURT_DOCUMENT", "TIMELINE", "WITNESS_OR_DEVICE_EVIDENCE", "BAIL_OR_DEADLINE_INFORMATION"],
    "eu-internal-market-law": ["NATIONAL_DECISION", "RESIDENCE_OR_WORK_RECORD", "PRODUCT_OR_SERVICE_REQUIREMENT", "APPEAL_INFORMATION"],
    "international-commercial-mediation": ["DISPUTE_CLAUSE", "MEDIATION_RULES_OR_ORDER", "AUTHORITY_TO_SETTLE", "SETTLEMENT_DRAFT"],
    "land-law": ["OFFICIAL_TITLE_AND_PLAN", "TRANSFER_OR_LEASE", "MORTGAGE_OR_TRUST_DOCUMENT", "OCCUPATION_AND_PAYMENT_RECORD"],
    "law-and-medicine": ["CLINICAL_RECORD", "CONSENT_OR_CAPACITY_RECORD", "DECISION_OR TREATMENT_PLAN", "RELEVANT_CORRESPONDENCE"],
    "pensions-law": ["SCHEME_RULE_OR BOOKLET", "BENEFIT_STATEMENT", "CONTRIBUTION_OR_TRANSFER_RECORD", "DECISION_AND_COMPLAINT_CORRESPONDENCE"],
    "private-international-law": ["CONTRACT_AND_FORUM_CLAUSE", "FOREIGN_PROCEEDING_OR_JUDGMENT", "SERVICE_RECORD", "ASSET_AND_PARTY_LOCATION"],
    "tort-law": ["INCIDENT_TIMELINE", "MEDICAL_OR_REPAIR_RECORD", "PHOTO_VIDEO_OR_WITNESS_EVIDENCE", "LOSS_AND_INSURANCE_RECORD"],
    "trusts-law": ["TRUST_INSTRUMENT", "TRUSTEE_ACCOUNTS_AND_MINUTES", "ASSET_TRANSFER_RECORD", "BENEFICIARY_CORRESPONDENCE"],
    "wills-and-estates": ["WILL_AND_CODICIL", "DEATH_AND_GRANT_RECORD", "ESTATE_ASSET_SCHEDULE", "EXECUTOR_OR_FAMILY_CORRESPONDENCE"],
}

FUNCTION_CHECKS = [
    "JURISDICTION_CHECK",
    "ISSUE_SPOTTING",
    "REQUEST_MATERIAL_FACTS",
    "REQUEST_RELEVANT_DOCUMENTS",
    "DISTINGUISH_LAW_FROM_EVIDENCE",
    "OFFICIAL_SOURCE_GROUNDING",
    "REMEDY_AND_DEADLINE_TRIAGE",
    "SAFE_BOUNDARY_AND_ESCALATION",
    "NO_CLAIM_OF_LAWYER_CLIENT_RELATIONSHIP",
]


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(payload: dict[str, Any], *, field: str) -> dict[str, Any]:
    value = dict(payload)
    value[field] = _sha256_bytes(_canonical_json(value))
    return value


def _load_module():
    spec = importlib.util.spec_from_file_location("phase2b_common_public_questions", QUESTION_MODULE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load common-public question module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_source_package(root: Path, expected_run: str, expected_content_sha256: str) -> dict[str, Any]:
    manifest = json.loads((root / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    if manifest["run_name"] != expected_run or manifest["package_content_sha256"] != expected_content_sha256:
        raise ValueError(f"source package identity changed: {expected_run}")
    checksum_count = 0
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        if _sha256_file(root / relative) != expected:
            raise ValueError(f"source package checksum mismatch: {expected_run}/{relative}")
        checksum_count += 1
    return {
        "run_name": expected_run,
        "package_content_sha256": expected_content_sha256,
        "verified_checksum_entry_count": checksum_count,
    }


def _scenario_class(ordinal: int) -> str:
    if ordinal <= 8:
        return "EVERYDAY_SINGLE_ISSUE"
    if ordinal <= 13:
        return "MULTI_ISSUE_FACT_PATTERN"
    if ordinal <= 16:
        return "FALSE_PREMISE_CORRECTION"
    return "URGENT_OR_SAFETY_BOUNDARY"


def _difficulty(ordinal: int) -> str:
    if ordinal <= 8:
        return "EVERYDAY"
    if ordinal <= 16:
        return "MULTI_ISSUE"
    return "BOUNDARY_OR_URGENT"


def _source_scope_status(topic_id: str) -> str:
    if topic_id in {"administrative-law", "wills-and-estates"}:
        return "EXPANSION_SOURCE_SCOPE_PROPOSED_NOT_ADMITTED"
    return "R3_TOPIC_SCOPE_REFERENCE_ONLY_NOT_RESEARCHED_FOR_THIS_BANK"


def _question_record(topic_id: str, lane: str, ordinal: int, seed: dict[str, Any]) -> dict[str, Any]:
    visible = lane == "COMMON_PUBLIC_DEVELOPMENT_EVALUATION_DRAFT"
    prefix = "cp-d" if visible else "cp-u"
    scenario_class = _scenario_class(ordinal)
    urgent = scenario_class == "URGENT_OR_SAFETY_BOUNDARY"
    false_premise = scenario_class == "FALSE_PREMISE_CORRECTION"
    payload = {
        "schema": QUESTION_SCHEMA,
        "question_id": f"{topic_id}:{prefix}{ordinal:02d}",
        "ordinal_within_lane": ordinal,
        "topic_id": topic_id,
        "question_type": "GENERAL_ENQUIRY",
        "scenario_class": scenario_class,
        "difficulty": _difficulty(ordinal),
        "prompt": seed["prompt"],
        "issue_tags": seed["issue_tags"],
        "lane": lane,
        "visible_to_development_remediation": visible,
        "development_remediation_eligible": visible,
        "unseen_validation_candidate": not visible,
        "unseen_freeze_status": "NOT_APPLICABLE" if visible else "CUSTODY_DRAFT_NOT_OWNER_FROZEN",
        "frozen_validation_eligible": False,
        "fact_status": "HYPOTHETICAL",
        "procedural_posture": "PUBLIC_LEGAL_INFORMATION_TRIAGE",
        "response_mode": "LAWYER_STYLE_ISSUE_SPOTTING_WITHOUT_CLAIMING_REPRESENTATION",
        "expected_function_checks": FUNCTION_CHECKS,
        "must_ask_clarifying_questions": True,
        "clarification_targets": ["LOCATION_AND_GOVERNING_JURISDICTION", "EVENT_TIMELINE_AND_DEADLINES", "PARTIES_AND_RELATIONSHIPS", "MATERIAL_DOCUMENTS_AND_EVIDENCE"],
        "jurisdiction_targets": DEFAULT_JURISDICTIONS[topic_id],
        "required_document_categories": TOPIC_DOCUMENTS[topic_id],
        "must_correct_false_premise": false_premise,
        "safe_routing_required": urgent or topic_id in {"criminal-law", "law-and-medicine"},
        "urgency": "URGENT" if urgent else ("ELEVATED" if topic_id in {"criminal-law", "law-and-medicine"} else "ROUTINE"),
        "legal_currentness_cutoff": LEGAL_CURRENTNESS_CUTOFF,
        "required_authority_types": ["PRIMARY_LEGISLATION_IF_APPLICABLE", "OFFICIAL_JUDGMENTS", "OFFICIAL_RULES_OR_REGULATOR_MATERIAL_IF_APPLICABLE"],
        "topic_source_scope_status": _source_scope_status(topic_id),
        "requires_issue_decomposition_before_execution": True,
        "requires_official_source_research": True,
        "gold_answer_created": False,
        "evidence_ledger_created": False,
        "source_admission_authorized": False,
        "source_scan_authorized": False,
        "index_build_authorized": False,
        "retrieval_authorized": False,
        "answer_model_authorized": False,
        "answer_model_run": False,
        "model_training_authorized": False,
        "model_training_run": False,
        "phase2b_authorized": False,
        "phase2b_run": False,
        "execution_bank_membership": False,
    }
    return _sealed(payload, field="record_content_sha256")


TOKEN_RE = re.compile(r"[a-z0-9]+(?:['’-][a-z0-9]+)?")
STOPWORDS = {"the", "and", "for", "that", "this", "with", "from", "what", "when", "where", "which", "who", "why", "how", "can", "does", "did", "are", "was", "were", "have", "has", "had", "may", "might", "should", "would", "could", "must", "into", "after", "before", "about", "their", "they", "them", "your", "ours", "mine"}


def _features(prompt: str) -> Counter[str]:
    tokens = [token for token in TOKEN_RE.findall(prompt.casefold()) if len(token) > 2 and token not in STOPWORDS]
    values = Counter(tokens)
    values.update(f"{left}__{right}" for left, right in zip(tokens, tokens[1:]))
    return values


def _leakage_audit(visible: list[dict[str, Any]], unseen: list[dict[str, Any]]) -> dict[str, Any]:
    normalized_visible = {re.sub(r"\W+", " ", row["prompt"].casefold()).strip() for row in visible}
    normalized_unseen = {re.sub(r"\W+", " ", row["prompt"].casefold()).strip() for row in unseen}
    if normalized_visible & normalized_unseen:
        raise ValueError("visible/unseen exact prompt leakage")
    docs = [_features(row["prompt"]) for row in visible + unseen]
    document_frequency: Counter[str] = Counter()
    for doc in docs:
        document_frequency.update(doc.keys())
    total = len(docs)
    idf = {key: math.log((1 + total) / (1 + frequency)) + 1 for key, frequency in document_frequency.items()}

    def weighted(doc: Counter[str]) -> tuple[dict[str, float], float]:
        vector = {key: count * idf[key] for key, count in doc.items()}
        norm = math.sqrt(sum(value * value for value in vector.values()))
        return vector, norm

    weighted_docs = [weighted(doc) for doc in docs]
    maximum = 0.0
    pair: tuple[str, str] | None = None
    visible_count = len(visible)
    for visible_index, visible_row in enumerate(visible):
        visible_vector, visible_norm = weighted_docs[visible_index]
        for unseen_offset, unseen_row in enumerate(unseen):
            unseen_vector, unseen_norm = weighted_docs[visible_count + unseen_offset]
            if not visible_norm or not unseen_norm:
                score = 0.0
            else:
                small, large = (visible_vector, unseen_vector) if len(visible_vector) <= len(unseen_vector) else (unseen_vector, visible_vector)
                score = sum(value * large.get(key, 0.0) for key, value in small.items()) / (visible_norm * unseen_norm)
            if score > maximum:
                maximum = score
                pair = (visible_row["question_id"], unseen_row["question_id"])
    if maximum >= LEAKAGE_COSINE_THRESHOLD:
        raise ValueError(f"visible/unseen near-overlap threshold failed: {maximum:.6f} {pair}")
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.common-public-unseen-leakage-audit.v1",
            "status": "PASS_DRAFT_CUSTODY_SEPARATION",
            "visible_question_count": len(visible),
            "unseen_question_count": len(unseen),
            "exact_normalized_prompt_overlap_count": 0,
            "method": "UNIGRAM_AND_ORDERED_BIGRAM_TFIDF_COSINE",
            "near_overlap_threshold_exclusive": LEAKAGE_COSINE_THRESHOLD,
            "maximum_similarity": round(maximum, 8),
            "maximum_pair_question_ids": list(pair) if pair else None,
            "semantic_independence_certified": False,
            "human_owner_freeze_review_required": True,
        },
        field="audit_content_sha256",
    )


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_canonical_json(value))


def _write_jsonl(path: Path, records: list[dict[str, Any]], *, private: bool = False) -> bytes:
    raw = b"".join(_canonical_json(record) for record in records)
    path.write_bytes(raw)
    if private:
        path.chmod(0o600)
    return raw


def _topic_markdown(display_name: str, records: list[dict[str, Any]]) -> str:
    lines = [f"# {display_name} — Common-public Development/Evaluation questions", "", "> Review draft only. It is not legal advice, a gold answer, authority, or permission to run Phase 2B.", ""]
    for record in records:
        lines += [f"## {record['question_id']} — {record['scenario_class']}", "", record["prompt"], "", "Issue tags: " + ", ".join(record["issue_tags"]), ""]
    return "\n".join(lines).rstrip() + "\n"


def _owner_review_guide(visible_by_topic: dict[str, list[dict[str, Any]]]) -> str:
    lines = [
        "# Owner review — Common-public legal enquiries",
        "",
        "Status: non-authorizing Phase 2B question-bank draft. Review the visible questions only; unseen prompts are deliberately omitted.",
        "",
        "Please check whether each question sounds like something an ordinary person might actually ask, whether the facts are understandable, whether the legal issue belongs in the topic, and whether the set includes enough difficult, false-premise and urgent cases.",
        "",
        "Suggested review notation: `KEEP`, `AMEND: <exact replacement>`, `MOVE: <topic>`, or `REMOVE: <reason>`.",
        "",
        "Per-topic mix: 8 everyday single-issue + 5 multi-issue + 3 false-premise correction + 2 urgent/safety-boundary questions.",
        "",
    ]
    for topic_id in sorted(visible_by_topic):
        records = visible_by_topic[topic_id]
        lines += [f"# {DISPLAY_NAMES[topic_id]}", ""]
        for record in records:
            lines += [f"- **{record['question_id']}** [{record['scenario_class']}]: {record['prompt']}", ""]
    return "\n".join(lines).rstrip() + "\n"


def _assert_generated_safety(root: Path) -> None:
    forbidden = (re.compile(rb"/Users/", re.IGNORECASE), re.compile(rb"hltsang", re.IGNORECASE), re.compile(rb"\bAgnes\b", re.IGNORECASE))
    question_ids: set[str] = set()
    prompts: set[str] = set()
    record_count = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        raw = path.read_bytes()
        for pattern in forbidden:
            if pattern.search(raw):
                raise ValueError(f"private identifier or path leaked into {path.name}")
        if path.suffix == ".jsonl":
            for line in raw.splitlines():
                record = json.loads(line)
                question_id = record["question_id"]
                if question_id in question_ids:
                    raise ValueError(f"duplicate question id: {question_id}")
                if record["prompt"] in prompts:
                    raise ValueError("duplicate prompt")
                question_ids.add(question_id)
                prompts.add(record["prompt"])
                record_count += 1
    if record_count != 612:
        raise ValueError(f"expected 612 question records, got {record_count}")
    if list(root.rglob("unseen-custody/**/*.md")):
        raise ValueError("unseen Markdown projection created")


def build() -> Path:
    if OUTPUT_ROOT.exists():
        raise FileExistsError(f"create-only output already exists: {OUTPUT_ROOT}")
    source_receipts = [
        _verify_source_package(R3_ROOT, R3_RUN_NAME, R3_PACKAGE_SHA256),
        _verify_source_package(EXPANSION_ROOT, EXPANSION_RUN_NAME, EXPANSION_PACKAGE_SHA256),
    ]
    question_module = _load_module()
    question_module.validate_common_public_bank()
    if set(question_module.COMMON_PUBLIC_BANK) != set(DISPLAY_NAMES):
        raise ValueError("question/display topic mismatch")

    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{RUN_NAME}-", dir=OUTPUT_PARENT))
    try:
        visible_by_topic: dict[str, list[dict[str, Any]]] = {}
        all_visible: list[dict[str, Any]] = []
        all_unseen: list[dict[str, Any]] = []
        topic_rows: list[dict[str, Any]] = []
        for topic_id in sorted(DISPLAY_NAMES):
            seeds = question_module.COMMON_PUBLIC_BANK[topic_id]
            visible = [_question_record(topic_id, "COMMON_PUBLIC_DEVELOPMENT_EVALUATION_DRAFT", index, seed) for index, seed in enumerate(seeds["visible"], start=1)]
            unseen = [_question_record(topic_id, "COMMON_PUBLIC_UNSEEN_CUSTODY_DRAFT", index, seed) for index, seed in enumerate(seeds["unseen"], start=1)]
            visible_by_topic[topic_id] = visible
            all_visible += visible
            all_unseen += unseen
            development_dir = staging / "topics" / topic_id / "development"
            custody_dir = staging / "topics" / topic_id / "unseen-custody"
            development_dir.mkdir(parents=True)
            custody_dir.mkdir(parents=True)
            visible_raw = _write_jsonl(development_dir / "COMMON-PUBLIC-QUESTION-SET.jsonl", visible)
            (development_dir / "COMMON-PUBLIC-QUESTION-SET.md").write_text(_topic_markdown(DISPLAY_NAMES[topic_id], visible), encoding="utf-8")
            unseen_raw = _write_jsonl(custody_dir / "PRIVATE-COMMON-PUBLIC-UNSEEN.jsonl", unseen, private=True)
            manifest = _sealed(
                {
                    "schema": TOPIC_SCHEMA,
                    "status": "COMMON_PUBLIC_TOPIC_DRAFT_READY_NOT_PHASE2B",
                    "topic_id": topic_id,
                    "display_name": DISPLAY_NAMES[topic_id],
                    "visible_question_count": 18,
                    "unseen_custody_draft_question_count": 18,
                    "scenario_distribution_per_lane": {"EVERYDAY_SINGLE_ISSUE": 8, "MULTI_ISSUE_FACT_PATTERN": 5, "FALSE_PREMISE_CORRECTION": 3, "URGENT_OR_SAFETY_BOUNDARY": 2},
                    "visible_jsonl_sha256": _sha256_bytes(visible_raw),
                    "unseen_jsonl_sha256": _sha256_bytes(unseen_raw),
                    "unseen_file_mode": "0600",
                    "unseen_markdown_projection_created": False,
                    "topic_source_scope_status": _source_scope_status(topic_id),
                    "owner_question_review_required": True,
                    "owner_unseen_freeze_required": True,
                    "phase2b_authorized": False,
                    "phase2b_run": False,
                },
                field="topic_content_sha256",
            )
            _write_json(staging / "topics" / topic_id / "TOPIC-MANIFEST.json", manifest)
            topic_rows.append({"topic_id": topic_id, "display_name": DISPLAY_NAMES[topic_id], "visible_question_count": 18, "unseen_question_count": 18, "topic_content_sha256": manifest["topic_content_sha256"]})

        leakage = _leakage_audit(all_visible, all_unseen)
        _write_json(staging / "UNSEEN-LEAKAGE-AUDIT.json", leakage)
        function_contract = _sealed(
            {
                "schema": "legalbot.v111.phase2b.common-public-function-test-contract.v1",
                "status": "DRAFT_NOT_EXECUTED",
                "purpose": "Test ordinary-person legal enquiries across clarification, issue spotting, evidence discipline, official-source grounding, remedies, deadlines and safe routing.",
                "expected_function_checks": FUNCTION_CHECKS,
                "answer_style": "PLAIN_LANGUAGE_LAWYER_STYLE_ANALYSIS_WITHOUT_CLAIMING_A_LAWYER_CLIENT_RELATIONSHIP",
                "conversation_context_rule": "Conversation may inform query rewriting and facts to clarify but never counts as legal evidence or authority.",
                "citation_rule": "Only deterministic citations from reviewed official-source metadata may support material legal propositions.",
                "false_premise_rule": "Correct the premise explicitly before applying law to the scenario.",
                "urgent_rule": "Identify immediate safety, limitation, evidence-preservation or interim-remedy needs and route appropriately.",
                "model_training_export": False,
                "execution_authorized": False,
            },
            field="contract_content_sha256",
        )
        _write_json(staging / "FUNCTION-TEST-CONTRACT.json", function_contract)
        registry = _sealed(
            {
                "schema": "legalbot.v111.phase2b.common-public-question-bank-registry.v1",
                "status": "NON_AUTHORIZING_REVIEW_DRAFT",
                "topic_count": 17,
                "visible_question_count": 306,
                "unseen_custody_draft_question_count": 306,
                "total_question_record_count": 612,
                "per_topic_visible_question_count": 18,
                "per_topic_unseen_question_count": 18,
                "recommended_execution_wave_size": 1,
                "maximum_administrative_wave_size": 2,
                "topic_results_and_owner_deltas_remain_independent": True,
                "topics": topic_rows,
            },
            field="registry_content_sha256",
        )
        _write_json(staging / "QUESTION-BANK-REGISTRY.json", registry)
        (staging / "OWNER-REVIEW-GUIDE.md").write_text(_owner_review_guide(visible_by_topic), encoding="utf-8")
        (staging / "README.md").write_text(
            f"# {RUN_NAME}\n\nThis immutable package contains synthetic common-public legal-enquiry questions for owner review only. It contains 17 topics, 306 visible Development/evaluation drafts and 306 separate unseen-custody drafts. It does not contain answers, legal authority, EvidenceSpans or an execution authorization.\n\nNothing in this package starts Phase 2B, reads or consumes the separately running Phase 2A chain, admits sources, scans, builds or embeds an index, runs retrieval, calls an answer model, trains a model, freezes unseen validation, promotes a candidate or activates live.\n\nThe visible set is readable in `OWNER-REVIEW-GUIDE.md` and each topic's Development folder. Unseen prompts have no Markdown projection and remain only private custody drafts until an exact owner freeze gate.\n",
            encoding="utf-8",
        )
        package = _sealed(
            {
                "schema": PACKAGE_SCHEMA,
                "status": "COMMON_PUBLIC_QUESTION_BANK_READY_FOR_OWNER_REVIEW_NOT_PHASE2B",
                "run_name": RUN_NAME,
                "legal_currentness_cutoff": LEGAL_CURRENTNESS_CUTOFF,
                "source_package_receipts": source_receipts,
                "question_registry_content_sha256": registry["registry_content_sha256"],
                "function_test_contract_content_sha256": function_contract["contract_content_sha256"],
                "leakage_audit_content_sha256": leakage["audit_content_sha256"],
                "topic_count": 17,
                "visible_question_count": 306,
                "unseen_custody_draft_question_count": 306,
                "frozen_validation_question_count": 0,
                "total_question_record_count": 612,
                "phase2a_running_task_read_or_consumed": False,
                "successful_phase2a_digest_received": False,
                "successful_phase2a_digest_owner_adopted": False,
                "owner_question_review_required": True,
                "owner_unseen_freeze_required": True,
                "source_admission_authorized": False,
                "source_admitted": False,
                "source_scan_run": False,
                "index_built": False,
                "embedding_run": False,
                "retrieval_run": False,
                "gold_answers_created": False,
                "evidence_spans_created": False,
                "answer_model_authorized": False,
                "answer_model_run": False,
                "model_training_authorized": False,
                "model_training_run": False,
                "phase2b_authorized": False,
                "phase2b_run": False,
                "validation_authorized": False,
                "promotion_authorized": False,
                "active_pointer_written": False,
                "previous_pointer_written": False,
                "phase2c_authorized": False,
                "live_activation_authorized": False,
                "live_activation_run": False,
            },
            field="package_content_sha256",
        )
        _write_json(staging / "PACKAGE-MANIFEST.json", package)
        _assert_generated_safety(staging)
        checksum_lines = [f"{_sha256_file(path)}  {path.relative_to(staging).as_posix()}" for path in sorted(item for item in staging.rglob("*") if item.is_file())]
        (staging / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
        os.replace(staging, OUTPUT_ROOT)
    except Exception:
        if staging.exists() and staging.parent == OUTPUT_PARENT:
            shutil.rmtree(staging)
        raise
    return OUTPUT_ROOT


def main() -> None:
    print(build())


if __name__ == "__main__":
    main()
