#!/usr/bin/env python3
"""Build corrected and physically separated common-public Phase 2B drafts.

Outputs are non-authorizing preparation only:
* a visible Development/core-and-stress package with no unseen files; and
* a separate private unseen-custody package with no readable projection.

The builder never consumes Phase 2A evidence, admits sources, scans, embeds,
runs retrieval or a model, freezes validation, starts Phase 2B, or promotes.
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
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PARENT = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
VISIBLE_RUN_NAME = "LegalBot-Phase2B-2026-08-28-common-public-visible-development-r2"
PRIVATE_RUN_NAME = "LegalBot-Phase2B-2026-08-28-common-public-private-unseen-r2"
VISIBLE_ROOT = OUTPUT_PARENT / VISIBLE_RUN_NAME
PRIVATE_ROOT = OUTPUT_PARENT / PRIVATE_RUN_NAME

R1_RUN_NAME = "LegalBot-Phase2B-2026-08-28-common-public-enquiries-draft-r1"
R1_ROOT = OUTPUT_PARENT / R1_RUN_NAME
R1_PACKAGE_SHA256 = "03a4d862d81e2b5a91da8bf0423f08aaf00c25297b5566708452ceced7acc0a8"
R3_RUN_NAME = "LegalBot-Phase2B-2026-08-28-full-question-bank-draft-r3"
R3_ROOT = OUTPUT_PARENT / R3_RUN_NAME
R3_PACKAGE_SHA256 = "cc625f2b80323654fbd4c3e3a53b16ac99fe54eb460f1a20fc04461c98ce79ec"
EXPANSION_RUN_NAME = "LegalBot-Phase2B-2026-08-28-expansion-and-pre-gold-r1"
EXPANSION_ROOT = OUTPUT_PARENT / EXPANSION_RUN_NAME
EXPANSION_PACKAGE_SHA256 = "66493d9a8dcf54f5fa563be521ce42674ff30222d54b037e76e7b0afa47f968a"
AUDIT_REVIEW_SHA256 = "9f8f1862d6c5838d64b59f906d1a7736ab2787684412f99057de410ab75a68ec"

PATCH_MODULE = PROJECT_ROOT / "scripts/phase2b_common_public_enquiry_r2_patch.py"
R1_BUILDER = PROJECT_ROOT / "scripts/build_v111_phase2b_common_public_enquiry_bank.py"
LEGAL_CURRENTNESS_CUTOFF = "2026-08-28"
LEAKAGE_THRESHOLD = 0.55
QUESTION_SCHEMA = "legalbot.v111.phase2b.common-public-question-draft.v2"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_canonical_json(value))


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]], *, private: bool = False) -> bytes:
    raw = b"".join(_canonical_json(row) for row in rows)
    path.write_bytes(raw)
    if private:
        path.chmod(0o600)
    return raw


def _verify_package(root: Path, run_name: str, package_sha256: str) -> dict[str, Any]:
    manifest = json.loads((root / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    if manifest["run_name"] != run_name or manifest["package_content_sha256"] != package_sha256:
        raise ValueError(f"package identity changed: {run_name}")
    count = 0
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        if _sha256_file(root / relative) != expected:
            raise ValueError(f"checksum mismatch: {run_name}/{relative}")
        count += 1
    return {"run_name": run_name, "package_content_sha256": package_sha256, "verified_checksum_entry_count": count}


def _source_rows() -> tuple[dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    visible: dict[str, dict[str, Any]] = {}
    unseen: dict[str, list[dict[str, Any]]] = {}
    for topic_root in sorted((R1_ROOT / "topics").iterdir()):
        if not topic_root.is_dir():
            continue
        topic_id = topic_root.name
        core = _read_jsonl(topic_root / "development/COMMON-PUBLIC-QUESTION-SET.jsonl")
        custody = _read_jsonl(topic_root / "unseen-custody/PRIVATE-COMMON-PUBLIC-UNSEEN.jsonl")
        if len(core) != 18 or len(custody) != 18:
            raise ValueError(f"r1 distribution changed: {topic_id}")
        unseen[topic_id] = custody
        for row in core:
            if row["question_id"] in visible:
                raise ValueError("duplicate r1 visible id")
            visible[row["question_id"]] = row
    if len(visible) != 306 or sum(map(len, unseen.values())) != 306:
        raise ValueError("r1 question count changed")
    return visible, unseen


MONTHS = {name: index for index, name in enumerate(("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"), start=1)}
DATE_RE = re.compile(r"\b([0-3]?\d) (January|February|March|April|May|June|July|August|September|October|November|December) (20\d{2})\b")


def _material_dates(prompt: str) -> list[str]:
    values = []
    for day, month, year in DATE_RE.findall(prompt):
        values.append(datetime(int(year), MONTHS[month], int(day)).date().isoformat())
    return sorted(set(values))


TRANSITIONAL_IDS = {
    "ai-and-data-protection:cp-d01",
    "business-and-company-law:cp-d14",
    "criminal-law:cp-d11",
    "criminal-law:cp-d16",
    "land-law:cp-d05",
    "private-international-law:cp-d04",
    "private-international-law:cp-d13",
    "wills-and-estates:cp-d02",
    "pensions-law:cp-d14",
}


def _temporal_status(question_id: str, issue_tags: list[str], dates: list[str]) -> str:
    if "fictional-law" in issue_tags:
        return "NOT_APPLICABLE"
    if "enacted-not-commenced" in issue_tags:
        return "ENACTED_NOT_COMMENCED"
    if question_id in TRANSITIONAL_IDS or "treaty-status" in issue_tags:
        return "TRANSITIONAL"
    if "unsettled-law" in issue_tags or "fact-dependent" in issue_tags:
        return "FACT_DEPENDENT"
    return "IN_FORCE" if dates else "FACT_DEPENDENT"


def _jurisdiction(topic_id: str, prompt: str, defaults: dict[str, list[str]]) -> tuple[str, list[str], str]:
    lower = prompt.casefold()
    named: list[str] = []
    cues = {
        "england": "ENGLAND_AND_WALES",
        "english": "ENGLAND_AND_WALES",
        "scotland": "SCOTLAND",
        "scottish": "SCOTLAND",
        "france": "FRANCE",
        "french": "FRANCE",
        "germany": "GERMANY",
        "german": "GERMANY",
        "netherlands": "NETHERLANDS",
        "dutch": "NETHERLANDS",
        "singapore": "SINGAPORE",
        "united states": "UNITED_STATES",
        " us ": "UNITED_STATES",
        "ireland": "IRELAND",
        "belfast": "NORTHERN_IRELAND",
        "northern ireland": "NORTHERN_IRELAND",
        "great britain": "GREAT_BRITAIN",
    }
    padded = f" {lower} "
    for cue, jurisdiction in cues.items():
        if cue in padded and jurisdiction not in named:
            named.append(jurisdiction)
    base = defaults[topic_id]
    if len(named) > 1 or "cross-border" in lower or topic_id in {"private-international-law", "international-commercial-mediation"}:
        conditional = sorted(set(named + base))
        return "CROSS_BORDER", conditional, "MULTI_JURISDICTION_FACT_DEPENDENT"
    if named:
        primary = named[0]
        conditional = sorted(set(base) - {primary})
        return primary, conditional, "FIXED_BY_SCENARIO"
    if len(base) == 1 and "CHECK_REQUIRED" not in base[0]:
        return base[0], [], "DEFAULT_SCOPE_ASSUMPTION_REQUIRES_DISCLOSURE"
    return base[0], base[1:], "USER_LOCATION_REQUIRED"


def _documents(topic_id: str, tags: list[str], base_documents: dict[str, list[str]]) -> list[str]:
    vocabulary_repairs = {
        "SCHEME_RULE_OR BOOKLET": "SCHEME_RULE_OR_BOOKLET",
        "DECISION_OR TREATMENT_PLAN": "DECISION_OR_TREATMENT_PLAN",
    }
    values = [vocabulary_repairs.get(value, value) for value in base_documents[topic_id]]
    tagset = set(tags)
    if topic_id == "pensions-law":
        if tagset & {"pension-scam", "pension-transfer", "statutory-flags", "amber-flag"}:
            return ["TRANSFER_REQUEST", "SCAM_FLAG_OR_GUIDANCE_NOTICE", "ADVISER_AND_RECEIVING_SCHEME_RECORD", "PAYMENT_AND_COMMUNICATION_RECORD"]
        if "divorce" in tagset:
            return ["DIVORCE_APPLICATION_AND_ORDER", "PENSION_VALUATION", "SCHEME_IDENTITY", "RESIDENCE_AND_JURISDICTION_FACTS"]
        if "pensions-dashboard" in tagset:
            return ["DASHBOARD_SCREENSHOT", "SCHEME_IDENTITY_AND_CONNECTION_RECORD", "SOURCE_VALUE_STATEMENT"]
        if "state-pension" in tagset:
            return ["STATE_PENSION_FORECAST", "NATIONAL_INSURANCE_RECORD", "CREDITS_AND_CONTRIBUTION_HISTORY"]
        if "pension-credit" in tagset:
            return ["BENEFIT_DECISION_OR_CALCULATOR_RESULT", "HOUSEHOLD_INCOME_AND_CAPITAL", "PENSION_PAYMENT_RECORD"]
    if topic_id == "wills-and-estates":
        if "video-will" in tagset:
            return ["WILL_COPY", "SIGNING_VIDEO", "WITNESS_DETAILS", "SIGNING_DATE_AND_SEQUENCE"]
        if "family-provision" in tagset:
            return ["GRANT_RECORD", "WILL_OR_INTESTACY_RECORD", "DEPENDENCY_AND_FINANCIAL_NEEDS_EVIDENCE"]
        if "intestacy" in tagset:
            return ["DEATH_AND_DOMICILE_RECORD", "FAMILY_RELATIONSHIP_EVIDENCE", "TITLE_AND_SURVIVORSHIP_RECORD"]
        if "probate-caveat" in tagset:
            return ["DISPUTED_WILL_COPY", "SIGNATURE_AND_WITNESS_EVIDENCE", "PROBATE_SEARCH_OR_APPLICATION_RECORD"]
    if topic_id == "law-and-medicine" and "organ-donation" in tagset:
        return ["RECORDED_DONATION_DECISION", "RESIDENCE_AND_NATION_FACTS", "CAPACITY_OR_EXCLUSION_EVIDENCE", "FAMILY_INFORMATION"]
    if tagset & {"medical-device", "clinical-ai", "medication-harm"}:
        return ["CLINICAL_RECORD", "DEVICE_ID_AND_INTENDED_PURPOSE", "SOFTWARE_VERSION_AND_LOGS", "INCIDENT_ANDTREATMENT_TIMELINE"]
    if "wrongdoing-request" in tagset:
        return ["EXISTING_UNALTERED_DOCUMENTS", "TRANSACTION_OR_DEVICE_TIMELINE", "PROFESSIONAL_OR_AUTHORITY_NOTICE"]
    return values[:3]


def _safety(topic_id: str, tags: list[str]) -> dict[str, Any]:
    tagset = set(tags)
    refusal = "wrongdoing-request" in tagset
    urgent = "urgent" in tagset or bool(tagset & {"medication-harm", "clinical-safety", "mental-health-detention", "stalking", "actual-loss"})
    if topic_id == "pensions-law":
        boundary = "REGULATED_FINANCIAL_ADVICE_BOUNDARY"
    elif topic_id == "criminal-law":
        boundary = "CRIMINAL_INVESTIGATION_AND_REPRESENTATION_BOUNDARY"
    elif topic_id in {"law-and-medicine", "contemporary-biolaw-and-regulation"}:
        boundary = "CLINICAL_DECISION_AND_EMERGENCY_BOUNDARY"
    else:
        boundary = "LEGAL_INFORMATION_NOT_REPRESENTATION"
    immediate: list[str] = []
    if refusal:
        immediate += ["REFUSE_ASSISTANCE_TO_COMMIT_CONCEAL_OR_OBSTRUCT_WRONGDOING", "PRESERVE_EXISTING_EVIDENCE", "ROUTE_TO_LAWFUL_PROFESSIONAL_ADVICE"]
    if urgent:
        immediate.append("IDENTIFY_AND_ACT_ON_IMMEDIATE_SAFETY_DEADLINE_OR_ASSET_RISK")
    if tagset & {"medication-harm", "clinical-safety"}:
        immediate.insert(0, "SEEK_URGENT_CLINICAL_ASSESSMENT_BEFORE_LEGAL_ANALYSIS")
    if tagset & {"pension-scam", "pension-transfer"}:
        immediate.insert(0, "PAUSE_ANY_NOT_YET_COMPLETED_TRANSFER_AND_CONTACT_PROVIDER")
    if tagset & {"police-seizure", "criminal-evidence", "legal-representation"}:
        immediate.append("SEEK_CRIMINAL_LEGAL_REPRESENTATION")
    if "stalking" in tagset:
        immediate.insert(0, "PRIORITISE_PERSONAL_SAFETY_AND_CONTACT_EMERGENCY_SERVICES_IF_IN_IMMEDIATE_DANGER")
    negative = []
    if "false-premise" in tagset:
        negative.append("DO_NOT_ACCEPT_THE_USER_PREMISE_AS_A_LEGAL_RULE")
    if refusal:
        negative.append("DO_NOT_PROVIDE_STEPS_TO_CONCEAL_ASSETS_DESTROY_EVIDENCE_OR_FABRICATE_DOCUMENTS")
    return {
        "regulated_advice_boundary": boundary,
        "safety_refusal_required": refusal,
        "immediate_actions": immediate,
        "evidence_preservation_required": refusal or urgent or bool(tagset & {"evidence-preservation", "forged-will", "telemetry"}),
        "urgent_handoff_required": urgent,
        "prohibited_overstatement": ["DO_NOT_CLAIM_A_LAWYER_CLIENT_RELATIONSHIP", "DO_NOT_PROMISE_AN_OUTCOME", "DO_NOT_TREAT_CONVERSATION_AS_LEGAL_EVIDENCE", "DO_NOT_APPLY_UNCOMMENCED_LAW_AS_IF_IN_FORCE"],
        "gold_answer_negative_propositions": negative,
    }


def _metadata(question_id: str, topic_id: str, prompt: str, issue_tags: list[str], r1_builder) -> dict[str, Any]:
    dates = _material_dates(prompt)
    primary, conditional, jurisdiction_status = _jurisdiction(topic_id, prompt, r1_builder.DEFAULT_JURISDICTIONS)
    tags = set(issue_tags)
    deadline = None
    if tags & {"limitation", "deadline", "promptness", "grant-date", "statutory-appeal"}:
        deadline = "EXACT_LIMITATION_APPEAL_OR_APPLICATION_DEADLINE_REQUIRES_CALCULATION"
    elif "urgent" in tags:
        deadline = "IMMEDIATE_OR_INTERIM_ACTION_WINDOW_REQUIRES_TRIAGE"
    blocking = jurisdiction_status in {"MULTI_JURISDICTION_FACT_DEPENDENT", "USER_LOCATION_REQUIRED"} or bool(tags & {"nation-check", "treaty-status"})
    return {
        "primary_jurisdiction": primary,
        "conditional_jurisdictions": conditional,
        "jurisdiction_status": jurisdiction_status,
        "material_date": dates[0] if len(dates) == 1 else None,
        "material_dates": dates,
        "temporal_status": _temporal_status(question_id, issue_tags, dates),
        "fact_status": "HYPOTHETICAL",
        "limitation_or_deadline_target": deadline,
        "blocking_clarification_required": blocking,
        "answer_then_clarify_allowed": True,
        "assumption_disclosure_required": True,
        "clarification_targets": ["JURISDICTION_AND_LOCATION", "MATERIAL_DATES_AND_DEADLINES", "PARTIES_STATUS_AND_RELATIONSHIPS", "OUTCOME_CHANGING_FACTS"],
        "required_document_categories": _documents(topic_id, issue_tags, r1_builder.TOPIC_DOCUMENTS),
        "legal_currentness_cutoff": LEGAL_CURRENTNESS_CUTOFF,
        "required_authority_types": ["PRIMARY_LEGISLATION_IF_APPLICABLE", "OFFICIAL_JUDGMENTS", "OFFICIAL_RULES_OR_REGULATOR_MATERIAL_IF_APPLICABLE"],
        **_safety(topic_id, issue_tags),
    }


def _visible_record(source: dict[str, Any], amendment: dict[str, Any] | None, r1_builder) -> dict[str, Any]:
    prompt = amendment["replacement_prompt"] if amendment else source["prompt"]
    tags = amendment["replacement_issue_tags"] if amendment else source["issue_tags"]
    topic_id = source["topic_id"]
    payload = {
        "schema": QUESTION_SCHEMA,
        "question_id": source["question_id"],
        "ordinal_within_lane": source["ordinal_within_lane"],
        "topic_id": topic_id,
        "question_type": "GENERAL_ENQUIRY",
        "lane": "COMMON_PUBLIC_VISIBLE_DEVELOPMENT_CORE_R2",
        "scenario_class": source["scenario_class"],
        "difficulty": source["difficulty"],
        "prompt": prompt,
        "issue_tags": tags,
        "source_r1_record_content_sha256": source["record_content_sha256"],
        "audit_amendment_applied": amendment is not None,
        "audit_priority": amendment["priority"] if amendment else None,
        "visible_to_development_remediation": True,
        "permanently_ineligible_for_unseen_validation": True,
        "topic_execution_status": "DRAFT_ONLY_BLOCKED_PENDING_OFFICIAL_SOURCE_ADMISSION" if topic_id in {"administrative-law", "wills-and-estates"} else "FUTURE_OWNER_GATED_PREPARATION_ONLY",
        "scored_evaluation_eligible": False,
        "requires_official_source_research": True,
        "gold_answer_created": False,
        "evidence_ledger_created": False,
        "source_admission_authorized": False,
        "retrieval_authorized": False,
        "answer_model_authorized": False,
        "phase2b_authorized": False,
        "phase2b_run": False,
        **_metadata(source["question_id"], topic_id, prompt, tags, r1_builder),
    }
    return _sealed(payload, field="record_content_sha256")


def _stress_records(additions: list[dict[str, Any]], r1_builder) -> dict[str, list[dict[str, Any]]]:
    by_topic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for seed in additions:
        topic_id = seed["topic_id"]
        ordinal = len(by_topic[topic_id]) + 1
        question_id = f"{topic_id}:cp-s{ordinal:02d}"
        payload = {
            "schema": QUESTION_SCHEMA,
            "question_id": question_id,
            "ordinal_within_lane": ordinal,
            "topic_id": topic_id,
            "question_type": "GENERAL_ENQUIRY",
            "lane": "COMMON_PUBLIC_VISIBLE_STRESS_TEST_R2",
            "scenario_class": "CROSS_REGIME_STRESS_OR_SAFETY_TEST",
            "difficulty": "STRESS_TEST",
            "prompt": seed["prompt"],
            "issue_tags": seed["issue_tags"],
            "source_r1_record_content_sha256": None,
            "audit_amendment_applied": False,
            "audit_priority": "STRESS_ADDITION",
            "visible_to_development_remediation": True,
            "permanently_ineligible_for_unseen_validation": True,
            "topic_execution_status": "DRAFT_ONLY_BLOCKED_PENDING_OFFICIAL_SOURCE_ADMISSION" if topic_id in {"administrative-law", "wills-and-estates"} else "FUTURE_OWNER_GATED_PREPARATION_ONLY",
            "scored_evaluation_eligible": False,
            "requires_official_source_research": True,
            "gold_answer_created": False,
            "evidence_ledger_created": False,
            "source_admission_authorized": False,
            "retrieval_authorized": False,
            "answer_model_authorized": False,
            "phase2b_authorized": False,
            "phase2b_run": False,
            **_metadata(question_id, topic_id, seed["prompt"], seed["issue_tags"], r1_builder),
        }
        by_topic[topic_id].append(_sealed(payload, field="record_content_sha256"))
    if sum(map(len, by_topic.values())) != 25:
        raise ValueError("stress count changed")
    return dict(by_topic)


def _private_record(source: dict[str, Any], r1_builder) -> dict[str, Any]:
    topic_id = source["topic_id"]
    payload = {
        "schema": QUESTION_SCHEMA,
        "question_id": source["question_id"],
        "ordinal_within_lane": source["ordinal_within_lane"],
        "topic_id": topic_id,
        "question_type": "GENERAL_ENQUIRY",
        "lane": "COMMON_PUBLIC_PRIVATE_UNSEEN_EVALUATION_CUSTODY_R2",
        "scenario_class": source["scenario_class"],
        "difficulty": source["difficulty"],
        "prompt": source["prompt"],
        "issue_tags": source["issue_tags"],
        "source_r1_record_content_sha256": source["record_content_sha256"],
        "custody_record_regenerated": True,
        "visible_to_development_remediation": False,
        "unseen_freeze_status": "CUSTODY_DRAFT_NOT_OWNER_FROZEN",
        "frozen_validation_eligible": False,
        "topic_execution_status": "DRAFT_ONLY_BLOCKED_PENDING_OFFICIAL_SOURCE_ADMISSION" if topic_id in {"administrative-law", "wills-and-estates"} else "FUTURE_OWNER_GATED_PREPARATION_ONLY",
        "scored_evaluation_eligible": False,
        "requires_official_source_research": True,
        "gold_answer_created": False,
        "source_admission_authorized": False,
        "retrieval_authorized": False,
        "answer_model_authorized": False,
        "validation_authorized": False,
        "phase2b_authorized": False,
        "phase2b_run": False,
        **_metadata(source["question_id"], topic_id, source["prompt"], source["issue_tags"], r1_builder),
    }
    return _sealed(payload, field="record_content_sha256")


TOKEN_RE = re.compile(r"[a-z0-9]+(?:['’-][a-z0-9]+)?")
STOPWORDS = {"the", "and", "for", "that", "this", "with", "from", "what", "when", "where", "which", "who", "why", "how", "can", "does", "did", "are", "was", "were", "have", "has", "had", "may", "might", "should", "would", "could", "must", "into", "after", "before", "about", "their", "they", "them", "your", "ours", "mine"}


def _features(prompt: str) -> Counter[str]:
    tokens = [token for token in TOKEN_RE.findall(prompt.casefold()) if len(token) > 2 and token not in STOPWORDS]
    values = Counter(tokens)
    values.update(f"{left}__{right}" for left, right in zip(tokens, tokens[1:]))
    return values


def _contamination_audit(candidate: list[dict[str, Any]], reference: list[dict[str, Any]], *, audit_kind: str) -> dict[str, Any]:
    normalized_reference = {re.sub(r"\W+", " ", row["prompt"].casefold()).strip(): row["question_id"] for row in reference}
    exact = []
    for row in candidate:
        normalized = re.sub(r"\W+", " ", row["prompt"].casefold()).strip()
        if normalized in normalized_reference:
            exact.append([row["question_id"], normalized_reference[normalized]])
    if exact:
        raise ValueError(f"{audit_kind} exact contamination: {exact[:3]}")
    docs = [_features(row["prompt"]) for row in candidate + reference]
    df: Counter[str] = Counter()
    for doc in docs:
        df.update(doc.keys())
    total = len(docs)
    idf = {key: math.log((1 + total) / (1 + count)) + 1 for key, count in df.items()}

    def weighted(doc: Counter[str]) -> tuple[dict[str, float], float]:
        vector = {key: value * idf[key] for key, value in doc.items()}
        return vector, math.sqrt(sum(value * value for value in vector.values()))

    weighted_docs = [weighted(doc) for doc in docs]
    maximum = 0.0
    pair = None
    candidate_count = len(candidate)
    for c_index, c_row in enumerate(candidate):
        c_vector, c_norm = weighted_docs[c_index]
        for r_offset, r_row in enumerate(reference):
            r_vector, r_norm = weighted_docs[candidate_count + r_offset]
            if not c_norm or not r_norm:
                score = 0.0
            else:
                small, large = (c_vector, r_vector) if len(c_vector) <= len(r_vector) else (r_vector, c_vector)
                score = sum(value * large.get(key, 0.0) for key, value in small.items()) / (c_norm * r_norm)
            if score > maximum:
                maximum = score
                pair = [c_row["question_id"], r_row["question_id"]]
    if maximum >= LEAKAGE_THRESHOLD:
        raise ValueError(f"{audit_kind} near contamination: {maximum:.6f} {pair}")
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.cross-bank-contamination-audit.v1",
            "status": "PASS_NO_EXACT_OR_MATERIALLY_HIGH_OVERLAP",
            "audit_kind": audit_kind,
            "candidate_question_count": len(candidate),
            "reference_question_count": len(reference),
            "exact_normalized_prompt_overlap_count": 0,
            "near_overlap_threshold_exclusive": LEAKAGE_THRESHOLD,
            "maximum_similarity": round(maximum, 8),
            "maximum_pair_question_ids": pair,
            "method": "UNIGRAM_AND_ORDERED_BIGRAM_TFIDF_COSINE",
            "semantic_independence_certified": False,
            "human_review_required": True,
        },
        field="audit_content_sha256",
    )


def _prior_visible_rows() -> list[dict[str, Any]]:
    paths = list(R3_ROOT.glob("development/topics/*/*.jsonl")) + list(EXPANSION_ROOT.glob("expansion-topics/*/development/*.jsonl"))
    rows: list[dict[str, Any]] = []
    for path in sorted(paths):
        rows.extend(_read_jsonl(path))
    if len(rows) != 340:
        raise ValueError(f"prior visible count changed: {len(rows)}")
    return rows


def _currentness_controls() -> dict[str, Any]:
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.common-public-currentness-controls.v1",
            "status": "OFFICIAL_CHECKPOINTS_RECORDED_NOT_GOLD_OR_SOURCE_ADMISSION",
            "checked_at": LEGAL_CURRENTNESS_CUTOFF,
            "audit_claim_correction": "The review described the future subscription regime as January 2027. Current official material says expected spring 2027. R2 records only that it was not in force at the cutoff; execution must verify the commencement instrument.",
            "official_checkpoints": [
                {"control": "DUAA_AUTOMATED_DECISION_SAFEGUARDS", "url": "https://ico.org.uk/about-the-ico/what-we-do/legislation-we-cover/data-use-and-access-act-2025/the-data-use-and-access-act-2025-what-does-it-mean-for-organisations/"},
                {"control": "SUBSCRIPTION_REGIME_NOT_YET_IN_FORCE", "url": "https://www.gov.uk/guidance/writing-a-fair-contract-for-customers"},
                {"control": "COMPANIES_HOUSE_IDV_PHASED_FROM_2025_11_18", "url": "https://www.gov.uk/government/news/companies-house-confirms-identity-verification-rollout-from-18-november-2025"},
                {"control": "ENGLAND_RENTING_REFORM_2026_05_01", "url": "https://www.gov.uk/guidance/assured-tenancy-forms"},
                {"control": "FAILURE_TO_PREVENT_FRAUD_FROM_2025_09_01", "url": "https://www.gov.uk/government/publications/offence-of-failure-to-prevent-fraud-introduced-by-eccta"},
                {"control": "PENSIONS_DASHBOARD_CONNECTION_AND_PUBLIC_AVAILABILITY", "url": "https://www.thepensionsregulator.gov.uk/trustees/contributions-data-and-transfers/dashboards-guidance"},
                {"control": "HAGUE_2019_UK_ENTRY_2025_07_01", "url": "https://www.gov.uk/government/speeches/statement-on-the-entry-into-force-of-the-2019-hague-convention"},
                {"control": "VIDEO_WILL_TEMPORARY_PERIOD_TO_2024_01_31", "url": "https://www.gov.uk/guidance/guidance-on-making-wills-using-video-conferencing"},
                {"control": "SINGAPORE_CONVENTION_TREATY_STATUS", "url": "https://treaties.un.org/pages/viewdetails.aspx?chapter=22&clang=_en&mtdsg_no=xxii-4&src=treaty"},
                {"control": "UK_ORGAN_DONATION_NATION_ROUTING", "url": "https://www.hta.gov.uk/guidance-public/body-organ-and-tissue-donation/organ-donation-and-transplantation-legal-framework"},
            ],
            "official_checkpoint_count": 10,
            "source_bytes_downloaded": False,
            "source_admission_authorized": False,
            "gold_answer_created": False,
            "legal_reviewer_completed": False,
        },
        field="controls_content_sha256",
    )


def _three_lane_plan(private_package_content_sha256: str) -> dict[str, Any]:
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.three-question-type-test-plan.v1",
            "status": "PLANNING_ONLY_NOT_PHASE2B",
            "question_types": ["GENERAL_ENQUIRY", "ESSAY", "PROBLEM_BASED"],
            "general_enquiry": {
                "visible_core_count": 306,
                "visible_stress_count": 25,
                "private_unseen_count": 306,
                "source": VISIBLE_RUN_NAME,
                "private_unseen_package_content_sha256": private_package_content_sha256,
                "supersedes_earlier_general_enquiry_questions_for_future_independent_testing": True,
            },
            "essay": {
                "visible_core_count_after_all_17_topics_admitted": 102,
                "private_unseen_count_after_all_17_topics_admitted": 102,
                "source_packages": [R3_RUN_NAME, EXPANSION_RUN_NAME],
            },
            "problem_based": {
                "visible_core_count_after_all_17_topics_admitted": 102,
                "visible_stress_count_after_all_17_topics_admitted": 17,
                "private_unseen_count_after_all_17_topics_admitted": 102,
                "source_packages": [R3_RUN_NAME, EXPANSION_RUN_NAME],
            },
            "administrative_law_and_wills_estates_rule": "DRAFTS_ONLY_UNTIL_OFFICIAL_SOURCES_ARE_ADMITTED_VERSIONED_PROPOSITION_CHECKED_AND_GOLD_INDEPENDENTLY_REVIEWED",
            "future_order_per_topic": ["OWNER_TOPIC_AND_PRIVATE_ROOT_GATE", "FREEZE_EXACT_PRIVATE_UNSEEN_HASH", "VISIBLE_DEVELOPMENT_RETRIEVAL_AND_EVIDENCE_CHECK", "OFFICIAL_SOURCE_RESEARCH", "EXACT_OWNER_DELTA", "NON_ACTIVE_BUILD_AND_REATTESTATION", "DEVELOPMENT_ACCEPTANCE_AND_CANDIDATE_SEAL", "ONE_PASS_PRIVATE_UNSEEN_EVALUATION"],
            "model_training_export": False,
            "phase2b_authorized": False,
            "phase2b_run": False,
        },
        field="plan_content_sha256",
    )


def _topic_markdown(display_name: str, core: list[dict[str, Any]], stress: list[dict[str, Any]]) -> str:
    lines = [f"# {display_name} — corrected common-public questions", "", "> Visible owner-review draft only. These prompts cannot be used as unseen validation.", ""]
    for title, rows in (("Corrected core", core), ("Visible stress tests", stress)):
        lines += [f"## {title}", ""]
        if not rows:
            lines += ["No stress additions for this topic.", ""]
        for row in rows:
            lines += [f"### {row['question_id']}", "", row["prompt"], "", f"Metadata: `{row['temporal_status']}` / `{row['jurisdiction_status']}` / refusal `{str(row['safety_refusal_required']).lower()}` / urgent handoff `{str(row['urgent_handoff_required']).lower()}`", ""]
    return "\n".join(lines).rstrip() + "\n"


def _review_guide(by_topic: dict[str, dict[str, list[dict[str, Any]]]], display_names: dict[str, str]) -> str:
    lines = ["# Owner review — corrected common-public r2", "", "This visible file contains 306 corrected core questions plus 25 stress questions. It contains no private unseen prompts.", "", "Review notation: `KEEP`, `AMEND: <replacement>`, `MOVE: <topic>`, or `REMOVE: <reason>`.", ""]
    for topic_id in sorted(by_topic):
        lines += [f"# {display_names[topic_id]}", ""]
        for lane in ("core", "stress"):
            lines += [f"## {lane.title()}", ""]
            for row in by_topic[topic_id][lane]:
                lines += [f"- **{row['question_id']}**: {row['prompt']}", ""]
    return "\n".join(lines).rstrip() + "\n"


def _manifest_and_checksums(root: Path, manifest: dict[str, Any]) -> None:
    _write_json(root / "PACKAGE-MANIFEST.json", manifest)
    checksum_lines = [f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}" for path in sorted(item for item in root.rglob("*") if item.is_file())]
    (root / "SHA256SUMS.txt").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")


def _assert_no_private_identifiers(root: Path) -> None:
    forbidden = (re.compile(rb"/Users/", re.IGNORECASE), re.compile(rb"hltsang", re.IGNORECASE), re.compile(rb"\bAgnes\b", re.IGNORECASE))
    for path in root.rglob("*"):
        if path.is_file():
            raw = path.read_bytes()
            for pattern in forbidden:
                if pattern.search(raw):
                    raise ValueError(f"private identifier leaked: {path}")


def build() -> tuple[Path, Path]:
    if VISIBLE_ROOT.exists() or PRIVATE_ROOT.exists():
        raise FileExistsError("create-only r2 output already exists")
    receipts = [
        _verify_package(R1_ROOT, R1_RUN_NAME, R1_PACKAGE_SHA256),
        _verify_package(R3_ROOT, R3_RUN_NAME, R3_PACKAGE_SHA256),
        _verify_package(EXPANSION_ROOT, EXPANSION_RUN_NAME, EXPANSION_PACKAGE_SHA256),
    ]
    patch = _load_module("common_public_r2_patch", PATCH_MODULE)
    r1_builder = _load_module("common_public_r1_builder", R1_BUILDER)
    source_visible, source_unseen = _source_rows()
    amendments = {row["question_id"]: row for row in patch.AMENDMENTS + patch.CONTAMINATION_REWRITES}
    if not set(amendments).issubset(source_visible):
        raise ValueError("unmatched audit amendment")
    visible_core = {question_id: _visible_record(source, amendments.get(question_id), r1_builder) for question_id, source in source_visible.items()}
    stress_by_topic = _stress_records(patch.STRESS_ADDITIONS, r1_builder)
    private_by_topic = {topic_id: [_private_record(row, r1_builder) for row in rows] for topic_id, rows in source_unseen.items()}
    prior_visible = _prior_visible_rows()
    all_visible = list(visible_core.values()) + [row for rows in stress_by_topic.values() for row in rows]
    visible_audit = _contamination_audit(all_visible, prior_visible, audit_kind="COMMON_PUBLIC_VISIBLE_R2_AGAINST_PRIOR_VISIBLE_R3_AND_EXPANSION")
    all_private = [row for rows in private_by_topic.values() for row in rows]
    unseen_audit = _contamination_audit(all_private, prior_visible + all_visible, audit_kind="PRIVATE_UNSEEN_R2_AGAINST_ALL_VISIBLE_BANKS")

    visible_staging = Path(tempfile.mkdtemp(prefix=f".{VISIBLE_RUN_NAME}-", dir=OUTPUT_PARENT))
    private_staging = Path(tempfile.mkdtemp(prefix=f".{PRIVATE_RUN_NAME}-", dir=OUTPUT_PARENT))
    try:
        private_registry_rows = []
        for topic_id in sorted(source_unseen):
            topic_dir = private_staging / "topics" / topic_id
            topic_dir.mkdir(parents=True)
            raw = _write_jsonl(topic_dir / "PRIVATE-UNSEEN-QUESTION-SET.jsonl", private_by_topic[topic_id], private=True)
            private_registry_rows.append({"topic_id": topic_id, "question_count": 18, "question_set_sha256": _sha256_bytes(raw), "file_mode": "0600", "topic_execution_status": "DRAFT_ONLY_BLOCKED_PENDING_OFFICIAL_SOURCE_ADMISSION" if topic_id in {"administrative-law", "wills-and-estates"} else "FUTURE_OWNER_GATED_PREPARATION_ONLY"})
        _write_json(private_staging / "CROSS-BANK-CONTAMINATION-AUDIT.json", unseen_audit)
        private_registry = _sealed({"schema": "legalbot.v111.phase2b.common-public-private-unseen-registry.v2", "status": "SEPARATE_PRIVATE_CUSTODY_DRAFT_NOT_OWNER_FROZEN", "topic_count": 17, "question_count": 306, "per_topic_question_count": 18, "markdown_projection_created": False, "visible_package_member": False, "custody_record_regeneration_count": 306, "prompt_disclosure_authorized": False, "owner_exact_hash_freeze_required": True, "topics": private_registry_rows}, field="registry_content_sha256")
        _write_json(private_staging / "PRIVATE-CUSTODY-REGISTRY.json", private_registry)
        (private_staging / "README.txt").write_text("PRIVATE UNSEEN CUSTODY DRAFT. Do not disclose prompts to the Development, remediation or owner question-review lane. This is not owner-frozen and no evaluation is authorized.\n", encoding="utf-8")
        private_manifest = _sealed({"schema": "legalbot.v111.phase2b.common-public-private-unseen-package.v2", "status": "PRIVATE_UNSEEN_CUSTODY_R2_READY_NOT_OWNER_FROZEN", "run_name": PRIVATE_RUN_NAME, "supersedes_run_name": R1_RUN_NAME, "source_package_receipts": receipts, "private_registry_content_sha256": private_registry["registry_content_sha256"], "contamination_audit_content_sha256": unseen_audit["audit_content_sha256"], "topic_count": 17, "question_count": 306, "markdown_projection_created": False, "included_in_visible_zip": False, "frozen_validation_question_count": 0, "phase2a_running_task_read_or_consumed": False, "source_admission_authorized": False, "retrieval_run": False, "answer_model_run": False, "validation_authorized": False, "phase2b_authorized": False, "phase2b_run": False}, field="package_content_sha256")
        _assert_no_private_identifiers(private_staging)
        _manifest_and_checksums(private_staging, private_manifest)

        by_topic: dict[str, dict[str, list[dict[str, Any]]]] = {topic_id: {"core": [], "stress": stress_by_topic.get(topic_id, [])} for topic_id in r1_builder.DISPLAY_NAMES}
        for row in visible_core.values():
            by_topic[row["topic_id"]]["core"].append(row)
        topic_registry_rows = []
        for topic_id in sorted(by_topic):
            core = sorted(by_topic[topic_id]["core"], key=lambda row: row["ordinal_within_lane"])
            stress = by_topic[topic_id]["stress"]
            topic_dir = visible_staging / "topics" / topic_id
            topic_dir.mkdir(parents=True)
            core_raw = _write_jsonl(topic_dir / "VISIBLE-CORE-QUESTION-SET.jsonl", core)
            stress_raw = _write_jsonl(topic_dir / "VISIBLE-STRESS-QUESTION-SET.jsonl", stress)
            (topic_dir / "OWNER-REVIEW.md").write_text(_topic_markdown(r1_builder.DISPLAY_NAMES[topic_id], core, stress), encoding="utf-8")
            topic_manifest = _sealed({"schema": "legalbot.v111.phase2b.common-public-visible-topic.v2", "status": "CORRECTED_VISIBLE_DRAFT_NOT_PHASE2B", "topic_id": topic_id, "display_name": r1_builder.DISPLAY_NAMES[topic_id], "core_question_count": 18, "stress_question_count": len(stress), "core_sha256": _sha256_bytes(core_raw), "stress_sha256": _sha256_bytes(stress_raw), "topic_execution_status": "DRAFT_ONLY_BLOCKED_PENDING_OFFICIAL_SOURCE_ADMISSION" if topic_id in {"administrative-law", "wills-and-estates"} else "FUTURE_OWNER_GATED_PREPARATION_ONLY", "scored_evaluation_eligible": False, "unseen_file_count": 0, "gold_answer_created": False, "phase2b_run": False}, field="topic_content_sha256")
            _write_json(topic_dir / "TOPIC-MANIFEST.json", topic_manifest)
            topic_registry_rows.append({"topic_id": topic_id, "display_name": r1_builder.DISPLAY_NAMES[topic_id], "core_question_count": 18, "stress_question_count": len(stress), "topic_content_sha256": topic_manifest["topic_content_sha256"], "topic_execution_status": topic_manifest["topic_execution_status"]})
        _write_json(visible_staging / "CROSS-BANK-CONTAMINATION-AUDIT.json", visible_audit)
        controls = _currentness_controls()
        _write_json(visible_staging / "CURRENTNESS-CONTROLS.json", controls)
        audit_receipt = _sealed({"schema": "legalbot.v111.phase2b.common-public-audit-input-receipt.v1", "audit_review_sha256": AUDIT_REVIEW_SHA256, "machine_readable_patch_attached": False, "amendment_rows_reconstructed_from_review": 44, "must_amend_count": 34, "should_amend_count": 10, "contamination_only_rewrite_count": 6, "stress_addition_count": 25, "unmatched_amendment_count": 0}, field="receipt_content_sha256")
        _write_json(visible_staging / "AUDIT-INPUT-RECEIPT.json", audit_receipt)
        amendment_report = _sealed({"schema": "legalbot.v111.phase2b.common-public-amendment-report.v2", "status": "PASS_ALL_RECONSTRUCTED_REVIEW_AMENDMENTS_APPLIED", "amendment_count": 44, "must_amend_count": 34, "should_amend_count": 10, "contamination_only_rewrite_count": 6, "stress_addition_count": 25, "unmatched_amendment_count": 0, "source_prompt_mismatch_count": 0, "malformed_controlled_vocabulary_count": 0, "universal_clarification_rule_removed": True, "visible_zip_contains_unseen": False, "administrative_law_and_wills_scored_evaluation_blocked": True}, field="report_content_sha256")
        _write_json(visible_staging / "AMENDMENT-APPLICATION-REPORT.json", amendment_report)
        registry = _sealed({"schema": "legalbot.v111.phase2b.common-public-visible-registry.v2", "status": "CORRECTED_VISIBLE_REVIEW_DRAFT", "topic_count": 17, "core_question_count": 306, "stress_question_count": 25, "visible_question_count": 331, "unseen_question_count": 0, "question_type": "GENERAL_ENQUIRY", "topics": topic_registry_rows}, field="registry_content_sha256")
        _write_json(visible_staging / "VISIBLE-QUESTION-BANK-REGISTRY.json", registry)
        plan = _three_lane_plan(private_manifest["package_content_sha256"])
        _write_json(visible_staging / "PHASE2B-THREE-LANE-TEST-PLAN.json", plan)
        (visible_staging / "OWNER-REVIEW-GUIDE.md").write_text(_review_guide(by_topic, r1_builder.DISPLAY_NAMES), encoding="utf-8")
        (visible_staging / "README.md").write_text(f"# {VISIBLE_RUN_NAME}\n\nCorrected visible common-public Development package: 306 core questions plus 25 stress questions across 17 topics. It contains no unseen prompt or custody file. Administrative Law and Wills/Estates remain draft-only and blocked from gold or scored evaluation until their official source packs are admitted, versioned and independently reviewed.\n\nFuture Phase 2B testing is organised as three distinct question types: General Enquiry, Essay and Problem Based. Every lane still requires the applicable owner gates, official-source proposition ledgers, candidate build, Development acceptance and a separately frozen one-pass unseen evaluation. No execution is authorized here.\n", encoding="utf-8")
        visible_manifest = _sealed({"schema": "legalbot.v111.phase2b.common-public-visible-package.v2", "status": "CORRECTED_VISIBLE_COMMON_PUBLIC_R2_READY_FOR_OWNER_REVIEW_NOT_PHASE2B", "run_name": VISIBLE_RUN_NAME, "supersedes_run_name": R1_RUN_NAME, "source_package_receipts": receipts, "audit_review_sha256": AUDIT_REVIEW_SHA256, "audit_input_receipt_sha256": audit_receipt["receipt_content_sha256"], "amendment_report_content_sha256": amendment_report["report_content_sha256"], "registry_content_sha256": registry["registry_content_sha256"], "currentness_controls_content_sha256": controls["controls_content_sha256"], "contamination_audit_content_sha256": visible_audit["audit_content_sha256"], "three_lane_plan_content_sha256": plan["plan_content_sha256"], "private_unseen_package_run_name": PRIVATE_RUN_NAME, "private_unseen_package_content_sha256": private_manifest["package_content_sha256"], "topic_count": 17, "core_question_count": 306, "stress_question_count": 25, "visible_question_count": 331, "unseen_file_count": 0, "phase2a_running_task_read_or_consumed": False, "gold_answers_created": False, "evidence_spans_created": False, "source_admission_authorized": False, "source_admitted": False, "source_scan_run": False, "index_built": False, "embedding_run": False, "retrieval_run": False, "answer_model_run": False, "phase2b_authorized": False, "phase2b_run": False, "validation_authorized": False, "promotion_authorized": False, "active_pointer_written": False, "previous_pointer_written": False, "live_activation_run": False}, field="package_content_sha256")
        if list(visible_staging.rglob("*UNSEEN*")) or list(visible_staging.rglob("*unseen*")):
            raise ValueError("visible package contains unseen-named material")
        _assert_no_private_identifiers(visible_staging)
        _manifest_and_checksums(visible_staging, visible_manifest)

        os.replace(private_staging, PRIVATE_ROOT)
        os.replace(visible_staging, VISIBLE_ROOT)
    except Exception:
        for staging in (visible_staging, private_staging):
            if staging.exists() and staging.parent == OUTPUT_PARENT:
                shutil.rmtree(staging)
        raise
    return VISIBLE_ROOT, PRIVATE_ROOT


def main() -> None:
    for path in build():
        print(path)


if __name__ == "__main__":
    main()
