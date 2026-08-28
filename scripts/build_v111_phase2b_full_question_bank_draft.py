#!/usr/bin/env python3
"""Build the non-authorizing Phase 2B full question-bank and unseen-custody draft.

The builder consumes the immutable r2 draft plus the owner-supplied audit patch,
applies amendments fail-closed, adds a visible stress lane, and prepares a
separate unseen-custody *draft*.  It never runs retrieval, a model, source
admission, an index build, Phase 2B, promotion, or live activation.
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
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PARENT = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
RUN_NAME = "LegalBot-Phase2B-2026-08-28-full-question-bank-draft-r3"
OUTPUT_ROOT = OUTPUT_PARENT / RUN_NAME
SOURCE_RUN_NAME = "LegalBot-Phase2B-2026-08-28-question-bank-draft-r2"
SOURCE_PACKAGE_ROOT = OUTPUT_PARENT / SOURCE_RUN_NAME
SOURCE_BUILDER = PROJECT_ROOT / "scripts/build_v111_phase2b_question_bank_draft.py"
UNSEEN_MODULE = PROJECT_ROOT / "scripts/phase2b_unseen_question_bank.py"
PATCH_RELATIVE_PATH = Path(
    "data/evaluations/phase2b-question-drafts/source-inputs/"
    "LegalBot-Phase2B-question-bank-audit-patch-2026-08-28.zip"
)
PATCH_ZIP = PROJECT_ROOT / PATCH_RELATIVE_PATH
EXPECTED_PATCH_SHA256 = "403354ad02832852b0bce9dafca628b334d83871ecbec289a269924d88547e15"
LEGAL_CURRENTNESS_CUTOFF = "2026-08-28"
LEAKAGE_COSINE_THRESHOLD = 0.55

QUESTION_SCHEMA = "legalbot.v111.phase2b.full-question-draft.v2"
TOPIC_SCHEMA = "legalbot.v111.phase2b.full-topic-draft.v2"
PACKAGE_SCHEMA = "legalbot.v111.phase2b.full-question-bank-package.v2"


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(payload: dict[str, Any], *, field: str = "record_content_sha256") -> dict[str, Any]:
    value = dict(payload)
    value[field] = _sha256_bytes(_canonical_json(value))
    return value


def _load_python_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_checksum_file(root: Path) -> int:
    lines = (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    count = 0
    for line in lines:
        expected, rel = line.split("  ", 1)
        path = root / rel
        if not path.is_file() or _sha256_file(path) != expected:
            raise ValueError(f"source package checksum mismatch: {rel}")
        count += 1
    return count


def _load_patch() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if _sha256_file(PATCH_ZIP) != EXPECTED_PATCH_SHA256:
        raise ValueError("audit patch ZIP digest mismatch")
    with zipfile.ZipFile(PATCH_ZIP) as archive:
        names = archive.namelist()
        if not names:
            raise ValueError("empty audit patch")
        for name in names:
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe audit patch member: {name}")
        roots = {Path(name).parts[0] for name in names}
        if len(roots) != 1:
            raise ValueError("audit patch must have one package root")
        prefix = next(iter(roots)) + "/"
        expected_members = {
            "ADDITIONS.jsonl",
            "AMENDMENTS.jsonl",
            "AUDIT-REPORT.md",
            "EXACT-QUESTIONS.md",
            "PATCH-MANIFEST.json",
            "README.md",
            "SHA256SUMS.txt",
        }
        actual_members = {name.removeprefix(prefix) for name in names if name != prefix}
        if actual_members != expected_members:
            raise ValueError("audit patch member set changed")
        checksum_lines = archive.read(prefix + "SHA256SUMS.txt").decode("utf-8").splitlines()
        for line in checksum_lines:
            expected, rel = line.split("  ", 1)
            if _sha256_bytes(archive.read(prefix + rel)) != expected:
                raise ValueError(f"audit patch internal checksum mismatch: {rel}")
        manifest = json.loads(archive.read(prefix + "PATCH-MANIFEST.json"))
        amendments = [
            json.loads(line)
            for line in archive.read(prefix + "AMENDMENTS.jsonl").decode("utf-8").splitlines()
        ]
        additions = [
            json.loads(line)
            for line in archive.read(prefix + "ADDITIONS.jsonl").decode("utf-8").splitlines()
        ]
    if manifest["source_run_name"] != SOURCE_RUN_NAME:
        raise ValueError("audit patch source run changed")
    if manifest["legal_currentness_cutoff"] != LEGAL_CURRENTNESS_CUTOFF:
        raise ValueError("audit patch cutoff changed")
    if len(amendments) != 44 or len(additions) != 30:
        raise ValueError("audit patch counts changed")
    for row in amendments + additions:
        sealed = dict(row)
        expected = sealed.pop("record_content_sha256")
        patch_canonical = json.dumps(
            sealed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if _sha256_bytes(patch_canonical) != expected:
            raise ValueError("audit patch record digest mismatch")
    receipt = {
        "patch_zip_sha256": EXPECTED_PATCH_SHA256,
        "patch_relative_path": PATCH_RELATIVE_PATH.as_posix(),
        "internal_checksum_entry_count": len(checksum_lines),
        "manifest_sha256": _sha256_bytes(_canonical_json(manifest)),
        "amendment_count": len(amendments),
        "addition_count": len(additions),
    }
    return manifest, amendments, additions, receipt


DEFAULT_JURISDICTIONS: dict[str, list[str]] = {
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
}


def _jurisdictions(topic_id: str, prompt: str) -> list[str]:
    values = set(DEFAULT_JURISDICTIONS[topic_id])
    lower = prompt.casefold()
    cues = {
        "scotland": "SCOTLAND",
        "scottish": "SCOTLAND",
        "northern ireland": "NORTHERN_IRELAND",
        "belfast": "NORTHERN_IRELAND",
        "england": "ENGLAND_AND_WALES",
        "english": "ENGLAND_AND_WALES",
        "wales": "WALES",
        "jersey": "JERSEY",
        "member state": "EUROPEAN_UNION",
        "eu ": "EUROPEAN_UNION",
        "cross-border": "CROSS_BORDER",
        "overseas": "CROSS_BORDER",
    }
    for cue, jurisdiction in cues.items():
        if cue in lower:
            values.add(jurisdiction)
    return sorted(values)


def _fact_status(question_type: str, prompt: str) -> str:
    lower = prompt.casefold()
    if any(cue in lower for cue in ("assume solely", "future artificial", "not specifically regulated", "proposed reform")):
        return "UNSETTLED"
    if question_type == "ESSAY":
        return "MIXED" if any(cue in lower for cue in ("at 28 august 2026", "compare", "future")) else "REAL"
    return "HYPOTHETICAL"


def _temporal_status(prompt: str) -> str:
    lower = prompt.casefold()
    if any(cue in lower for cue in ("not specifically regulated", "future artificial", "assume solely")):
        return "PROPOSED"
    if any(cue in lower for cue in ("commencement", "not in force", "enacted", "transition", "after 1 september 2025", "at 28 august 2026")):
        return "TRANSITIONAL"
    return "IN_FORCE"


def _false_premise(question_type: str, prompt: str) -> bool:
    if question_type != "GENERAL_ENQUIRY":
        return False
    lower = prompt.casefold()
    return any(
        cue in lower
        for cue in (
            "automatically",
            "always",
            "never",
            "anything posted publicly",
            "every contract",
            "must accept",
            "is conclusive",
            "no need",
            "no regulator",
            "told me",
            "says that because",
            "says payment alone",
            "says it has anonymised",
        )
    )


def _safe_routing(topic_id: str, difficulty: str, prompt: str) -> bool:
    lower = prompt.casefold()
    return difficulty == "BOUNDARY_OR_URGENT" or topic_id in {"criminal-law", "law-and-medicine"} or any(
        cue in lower
        for cue in ("police", "removal", "hospital", "injured", "fire", "insolvency today", "expires tomorrow")
    )


def _difficulty_features(question_type: str, difficulty: str, prompt: str) -> list[str]:
    if question_type == "ESSAY":
        features = ["CONTESTABLE_PROPOSITION", "DOCTRINAL_SYNTHESIS"]
        if difficulty in {"HARDER", "EVEN_HARDER"}:
            features += ["COMPARATIVE_OR_BOUNDARY_ANALYSIS", "COMPETING_VALUES"]
        if difficulty == "EVEN_HARDER":
            features += ["CROSS_REGIME_OR_SYSTEMIC_ANALYSIS", "CURRENTNESS_CONTROL"]
        return features
    if question_type == "PROBLEM_BASED":
        features = ["MULTIPLE_ACTORS", "OUTCOME_CHANGING_FACTS", "REMEDY_ANALYSIS"]
        if difficulty in {"HARDER", "EVEN_HARDER"}:
            features += ["COMPETING_DOCUMENTS_OR_EVIDENCE", "INCONSISTENT_ACTOR_KNOWLEDGE"]
        if difficulty == "EVEN_HARDER":
            features += ["MULTIPLE_PROCEDURAL_ROUTES", "JURISDICTION_OR_TEMPORAL_CONTROL"]
        if any(cue in prompt.casefold() for cue in ("deadline", "limitation", "tomorrow", "five days")):
            features.append("DEADLINE_CONTROL")
        return features
    features = ["PLAIN_LANGUAGE_TRIAGE", "CLARIFICATION_REQUIRED"]
    if difficulty == "MULTI_ISSUE":
        features += ["MULTIPLE_LEGAL_ROUTES", "FALSE_PREMISE_OR_BOUNDARY_CONTROL"]
    if difficulty == "BOUNDARY_OR_URGENT":
        features += ["URGENT_DEADLINE_OR_EVIDENCE_PRESERVATION", "SAFE_ROUTING"]
    return features


def _metadata(topic_id: str, question_type: str, difficulty: str, prompt: str) -> dict[str, Any]:
    false_premise = _false_premise(question_type, prompt)
    posture = {
        "ESSAY": "ACADEMIC_ANALYSIS",
        "PROBLEM_BASED": "PRE_ACTION_ADVICE_WITH_PROCEDURAL_ROUTE_CHECK",
        "GENERAL_ENQUIRY": "URGENT_TRIAGE" if difficulty == "BOUNDARY_OR_URGENT" else "PRE_ACTION_OR_INFORMATION_TRIAGE",
    }[question_type]
    remedy_targets = {
        "ESSAY": ["DOCTRINAL_CONCLUSION", "REMEDY_AND_ENFORCEMENT_WHERE_RELEVANT"],
        "PROBLEM_BASED": ["PRIMARY_REMEDIES", "DEFENCES", "PROCEDURE", "LIMITATION_OR_DEADLINE_CHECK"],
        "GENERAL_ENQUIRY": ["PRACTICAL_NEXT_STEPS", "REMEDIES", "DEADLINE_AND_URGENCY_CHECK"],
    }[question_type]
    return {
        "jurisdiction_targets": _jurisdictions(topic_id, prompt),
        "legal_currentness_cutoff": LEGAL_CURRENTNESS_CUTOFF,
        "fact_status": _fact_status(question_type, prompt),
        "temporal_status": _temporal_status(prompt),
        "procedural_posture": posture,
        "remedy_and_deadline_targets": remedy_targets,
        "must_correct_false_premise": false_premise,
        "safe_routing_required": _safe_routing(topic_id, difficulty, prompt),
        "required_authority_types": [
            "PRIMARY_LEGISLATION_IF_APPLICABLE",
            "OFFICIAL_JUDGMENTS",
            "OFFICIAL_RULES_OR_REGULATOR_MATERIAL_IF_APPLICABLE",
        ],
        "difficulty_features": _difficulty_features(question_type, difficulty, prompt),
        "gold_answer_requires_negative_proposition": false_premise or any(
            cue in prompt.casefold()
            for cue in ("not in force", "distinguish rules actually in force", "alternative statutory or common-law routes")
        ),
    }


def _final_question(
    *,
    question_id: str,
    ordinal_within_lane: int,
    topic_id: str,
    question_type: str,
    difficulty: str,
    prompt: str,
    issue_tags: Iterable[str],
    clarification_targets: Iterable[str],
    lane: str,
    source_record_sha256: str | None,
    amendment_record_sha256: str | None = None,
) -> dict[str, Any]:
    visible = lane != "UNSEEN_VALIDATION_CUSTODY_DRAFT"
    payload = {
        "schema": QUESTION_SCHEMA,
        "question_id": question_id,
        "ordinal_within_lane": ordinal_within_lane,
        "topic_id": topic_id,
        "question_type": question_type,
        "difficulty": difficulty,
        "prompt": " ".join(prompt.split()),
        "issue_tags": list(issue_tags),
        "clarification_targets": list(clarification_targets),
        "lane": lane,
        "visible_to_development_remediation": visible,
        "development_remediation_eligible": visible,
        "unseen_validation_candidate": not visible,
        "unseen_freeze_status": "NOT_APPLICABLE" if visible else "CUSTODY_DRAFT_NOT_OWNER_FROZEN",
        "frozen_validation_eligible": False,
        "requires_issue_decomposition_before_execution": True,
        "requires_official_source_research": True,
        "source_record_sha256": source_record_sha256,
        "amendment_record_sha256": amendment_record_sha256,
        "gold_answer_created": False,
        "source_admission_authorized": False,
        "retrieval_authorized": False,
        "answer_model_authorized": False,
        "answer_model_run": False,
        "model_training_authorized": False,
        "model_training_run": False,
        "phase2b_authorized": False,
        "phase2b_run": False,
        **_metadata(topic_id, question_type, difficulty, prompt),
    }
    return _sealed(payload)


def _build_question_sets(r2, unseen, amendments: list[dict[str, Any]], additions: list[dict[str, Any]]):
    unseen.validate_unseen_bank(set(r2.TOPICS))
    source_by_id: dict[str, dict[str, Any]] = {}
    for topic_id, topic in r2.TOPICS.items():
        for record in r2._question_records(topic_id, topic):
            if record["question_id"] in source_by_id:
                raise ValueError("duplicate source question id")
            source_by_id[record["question_id"]] = record
    amendment_by_id = {row["question_id"]: row for row in amendments}
    if len(amendment_by_id) != 44 or not set(amendment_by_id).issubset(source_by_id):
        raise ValueError("amendment question-id boundary changed")

    core_by_topic: dict[str, list[dict[str, Any]]] = {topic_id: [] for topic_id in r2.TOPICS}
    for question_id, source in source_by_id.items():
        row = amendment_by_id.get(question_id)
        prompt = source["prompt"]
        tags = source["issue_tags"]
        amendment_sha = None
        if row:
            if any(
                (
                    row["topic_id"] != source["topic_id"],
                    row["question_type"] != source["question_type"],
                    row["difficulty"] != source["difficulty"],
                    row["original_prompt"] != source["prompt"],
                    row["original_issue_tags"] != source["issue_tags"],
                )
            ):
                raise ValueError(f"amendment source mismatch: {question_id}")
            prompt = row["replacement_prompt"]
            tags = row["replacement_issue_tags"]
            amendment_sha = row["record_content_sha256"]
        record = _final_question(
            question_id=question_id,
            ordinal_within_lane=source["ordinal_within_topic"],
            topic_id=source["topic_id"],
            question_type=source["question_type"],
            difficulty=source["difficulty"],
            prompt=prompt,
            issue_tags=tags,
            clarification_targets=source["clarification_targets"],
            lane="DEVELOPMENT_REMEDIATION_CORE",
            source_record_sha256=source["record_content_sha256"],
            amendment_record_sha256=amendment_sha,
        )
        core_by_topic[source["topic_id"]].append(record)

    stress_by_topic: dict[str, list[dict[str, Any]]] = {topic_id: [] for topic_id in r2.TOPICS}
    for row in additions:
        if row["topic_id"] not in r2.TOPICS:
            raise ValueError("stress addition topic changed")
        record = _final_question(
            question_id=row["proposed_question_id"],
            ordinal_within_lane=len(stress_by_topic[row["topic_id"]]) + 1,
            topic_id=row["topic_id"],
            question_type=row["question_type"],
            difficulty=row["difficulty"],
            prompt=row["prompt"],
            issue_tags=row["issue_tags"],
            clarification_targets=row["clarification_targets"],
            lane="DEVELOPMENT_STRESS_SUPPLEMENT",
            source_record_sha256=row["record_content_sha256"],
        )
        stress_by_topic[row["topic_id"]].append(record)

    unseen_by_topic: dict[str, list[dict[str, Any]]] = {topic_id: [] for topic_id in r2.TOPICS}
    prefixes = {"ESSAY": "u-e", "PROBLEM_BASED": "u-p", "GENERAL_ENQUIRY": "u-g"}
    difficulties = {
        "ESSAY": unseen.ACADEMIC_DIFFICULTIES,
        "PROBLEM_BASED": unseen.ACADEMIC_DIFFICULTIES,
        "GENERAL_ENQUIRY": unseen.GENERAL_DIFFICULTIES,
    }
    for topic_id in sorted(r2.TOPICS):
        ordinal = 0
        for question_type in ("ESSAY", "PROBLEM_BASED", "GENERAL_ENQUIRY"):
            for index, seed in enumerate(unseen.UNSEEN_BANK[topic_id][question_type], start=1):
                ordinal += 1
                record = _final_question(
                    question_id=f"{topic_id}:{prefixes[question_type]}{index:02d}",
                    ordinal_within_lane=ordinal,
                    topic_id=topic_id,
                    question_type=question_type,
                    difficulty=difficulties[question_type][index - 1],
                    prompt=seed["prompt"],
                    issue_tags=seed["issue_tags"],
                    clarification_targets=seed["clarification_targets"],
                    lane="UNSEEN_VALIDATION_CUSTODY_DRAFT",
                    source_record_sha256=None,
                )
                unseen_by_topic[topic_id].append(record)
    return core_by_topic, stress_by_topic, unseen_by_topic


TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-'][a-z0-9]+)?")
STOPWORDS = {
    "the", "and", "that", "with", "from", "this", "under", "where", "when", "what",
    "which", "their", "into", "after", "before", "while", "have", "does", "should",
    "would", "could", "whether", "advise", "critically", "evaluate", "assess", "discuss",
}


def _features(prompt: str) -> Counter[str]:
    tokens = [token for token in TOKEN_RE.findall(prompt.casefold()) if len(token) > 2 and token not in STOPWORDS]
    values = Counter(tokens)
    values.update(f"{a}__{b}" for a, b in zip(tokens, tokens[1:]))
    return values


def _leakage_audit(visible: list[dict[str, Any]], unseen: list[dict[str, Any]]) -> dict[str, Any]:
    normalized_visible = {re.sub(r"\W+", " ", row["prompt"].casefold()).strip() for row in visible}
    normalized_unseen = {re.sub(r"\W+", " ", row["prompt"].casefold()).strip() for row in unseen}
    exact_overlap = normalized_visible & normalized_unseen
    if exact_overlap:
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
    for v_index, v_row in enumerate(visible):
        v_vector, v_norm = weighted_docs[v_index]
        for u_offset, u_row in enumerate(unseen):
            u_vector, u_norm = weighted_docs[visible_count + u_offset]
            if not v_norm or not u_norm:
                score = 0.0
            else:
                small, large = (v_vector, u_vector) if len(v_vector) <= len(u_vector) else (u_vector, v_vector)
                score = sum(value * large.get(key, 0.0) for key, value in small.items()) / (v_norm * u_norm)
            if score > maximum:
                maximum = score
                pair = (v_row["question_id"], u_row["question_id"])
    passed = maximum < LEAKAGE_COSINE_THRESHOLD
    if not passed:
        raise ValueError(f"visible/unseen near-overlap threshold failed: {maximum:.6f} {pair}")
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.unseen-leakage-audit.v1",
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


def _markdown(display_name: str, lane: str, records: list[dict[str, Any]]) -> str:
    lines = [
        f"# {display_name} — {lane}",
        "",
        "> Non-authorizing visible development/remediation draft. These questions are permanently ineligible for frozen unseen validation.",
        "",
    ]
    for record in records:
        lines += [
            f"## {record['question_id']} — {record['question_type']} / {record['difficulty']}",
            "",
            record["prompt"],
            "",
            "Issue tags: " + ", ".join(record["issue_tags"]),
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def _future_checklist(display_name: str) -> str:
    return f"""# Future Phase 2B run checklist — {display_name}

Status: planning scaffold only; no execution is authorized.

1. Complete Phase 2A and adopt every applicable exact owner decision.
2. Owner selects this topic in a wave of no more than two topics and approves the exact private Development root, currentness cutoff, resource envelope and model transport.
3. Before any Development remediation, owner freezes the exact 18-question unseen custody hash for this topic. The prompts remain unavailable to the Development/research lane.
4. Decompose the 20 visible questions (18 core plus 2 stress) into proposition and issue rows.
5. Inspect retrieval/evidence against the authorized non-ACTIVE candidate; classify support, weakness, gap, currentness hold and representation hold.
6. Research gaps using official sources only and produce an exact source/evidence delta. Automated monitoring cannot approve it.
7. After owner approval, run the bounded scan and versioned non-ACTIVE index/embedding build, re-attest retrieval and rerun Development evaluation.
8. Repeat only through new immutable deltas until Development is accepted, then seal the final candidate and prohibit further mutation.
9. Behind the separate one-pass disclosure gate, run the 18 unseen questions once. Do not repair the same candidate from unseen results.
10. Seal topic results. Any unseen failure becomes a finding for a later candidate or Phase 2C, not an in-place validation repair.

Two topics may share administrative scheduling, but folders, evidence ledgers, deltas, results and pass/fail remain independent.
"""


def _currentness_checkpoints() -> dict[str, Any]:
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.currentness-checkpoints-draft.v1",
            "status": "OFFICIAL_ENDPOINTS_RECORDED_NOT_GOLD_ANSWER_LEDGER",
            "cutoff": LEGAL_CURRENTNESS_CUTOFF,
            "execution_rule": "Every proposition must be revalidated against official sources and exact commencement/territorial provisions before scoring.",
            "audit_correction": {
                "claim": "DMCC subscription-contract regime commencement",
                "patch_report_wording": "scheduled for January 2027",
                "corrected_control": "Not in force at the cutoff; the official government response anticipated commencement in spring 2027. Execution must verify the actual commencement instrument.",
            },
            "official_source_endpoints": [
                {"checkpoint_id": "data-use-and-access-act-2025", "url": "https://www.legislation.gov.uk/ukpga/2025/18/pdfs/ukpga_20250018_en.pdf"},
                {"checkpoint_id": "dmcc-subscriptions-government-response", "url": "https://assets.publishing.service.gov.uk/media/69cce372a2e82c1bd822d7de/government-response-to-consultation-on-the-implementation-of-the-new-subscription-contracts-regime.pdf"},
                {"checkpoint_id": "property-digital-assets-act-2025", "url": "https://www.legislation.gov.uk/ukpga/2025/29/pdfs/ukpga_20250029_en.pdf"},
                {"checkpoint_id": "digital-assets-scotland-act-2026", "url": "https://www.legislation.gov.uk/asp/2026/12/pdfs/asp_20260012_en.pdf"},
                {"checkpoint_id": "renters-rights-commencement-no-2", "url": "https://www.legislation.gov.uk/uksi/2026/421/pdfs/uksi_20260421_en.pdf"},
                {"checkpoint_id": "pension-schemes-act-2026", "url": "https://www.legislation.gov.uk/ukpga/2026/22/pdfs/ukpga_20260022_en.pdf"},
                {"checkpoint_id": "hague-2019-judgments-status-table", "url": "https://www.hcch.net/en/instruments/conventions/status-table/?cid=137"},
                {"checkpoint_id": "failure-to-prevent-fraud-guidance", "url": "https://www.gov.uk/government/publications/failure-to-prevent-fraud-offence-guidance"},
            ],
            "official_endpoint_count": 8,
            "legal_reviewer_completed": False,
            "gold_answers_created": False,
            "owner_currentness_decision_required": True,
        },
        field="checkpoint_content_sha256",
    )


def _execution_plan() -> dict[str, Any]:
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.future-execution-plan.v2",
            "status": "PLANNING_ONLY_ALL_EXECUTION_BLOCKED",
            "administrative_wave_size_maximum": 2,
            "topic_independence_required": True,
            "development_questions_per_topic": 20,
            "unseen_questions_per_topic": 18,
            "model_fine_tuning_in_scope": False,
            "development_remediation_description": "Visible questions may drive retrieval/evidence diagnosis and owner-approved resource repair; they are not a model-training export.",
            "ordered_gates": [
                "PHASE2A_COMPLETION_AND_APPLICABLE_OWNER_ADOPTION",
                "PHASE2B_TOPIC_WAVE_SCOPE_AND_PRIVATE_ROOT_OWNER_GATE",
                "EXACT_UNSEEN_CUSTODY_HASH_OWNER_FREEZE_BEFORE_DEVELOPMENT",
                "VISIBLE_DEVELOPMENT_RETRIEVAL_AND_EVIDENCE_DIAGNOSIS",
                "OFFICIAL_SOURCE_RESEARCH_AND_EXACT_OWNER_DELTA",
                "BOUNDED_NON_ACTIVE_INDEX_BUILD_AND_REATTESTATION",
                "DEVELOPMENT_ACCEPTANCE_AND_FINAL_CANDIDATE_SEAL",
                "ONE_PASS_UNSEEN_DISCLOSURE_AND_EXECUTION_GATE",
                "IMMUTABLE_TOPIC_RESULT_AND_FINDINGS_REVIEW",
                "OWNER_DECISION_ON_PHASE2C_SCOPE",
            ],
            "unseen_failure_rule": "Seal the result; do not repair the same candidate using unseen prompts. Route findings to a new candidate or Phase 2C.",
            "phase2c_automatic": False,
            "promotion_automatic": False,
            "live_automatic": False,
        },
        field="plan_content_sha256",
    )


def _assert_distribution(records: list[dict[str, Any]], *, unseen: bool = False) -> None:
    if len(records) != 18:
        raise ValueError("topic set must contain 18 questions")
    if Counter(row["question_type"] for row in records) != {
        "ESSAY": 6,
        "PROBLEM_BASED": 6,
        "GENERAL_ENQUIRY": 6,
    }:
        raise ValueError("question-type distribution changed")
    for kind in ("ESSAY", "PROBLEM_BASED"):
        if Counter(row["difficulty"] for row in records if row["question_type"] == kind) != {
            "SCHOOL_COMPARABLE": 2,
            "HARDER": 2,
            "EVEN_HARDER": 2,
        }:
            raise ValueError("academic difficulty distribution changed")
    if Counter(row["difficulty"] for row in records if row["question_type"] == "GENERAL_ENQUIRY") != {
        "EVERYDAY": 4,
        "MULTI_ISSUE": 1,
        "BOUNDARY_OR_URGENT": 1,
    }:
        raise ValueError("general difficulty distribution changed")


def _assert_generated_safety(root: Path) -> None:
    forbidden = (
        re.compile(rb"/Users/", re.IGNORECASE),
        re.compile(rb"hltsang", re.IGNORECASE),
        re.compile(rb"\bAgnes\b", re.IGNORECASE),
    )
    ids: set[str] = set()
    prompts: set[str] = set()
    count = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        raw = path.read_bytes()
        for pattern in forbidden:
            if pattern.search(raw):
                raise ValueError(f"private identifier or path leaked into {path.name}")
        if path.suffix == ".jsonl":
            for line in raw.decode("utf-8").splitlines():
                row = json.loads(line)
                if row["question_id"] in ids:
                    raise ValueError("duplicate question id")
                ids.add(row["question_id"])
                normalized = re.sub(r"\W+", " ", row["prompt"].casefold()).strip()
                if normalized in prompts:
                    raise ValueError("duplicate question prompt")
                prompts.add(normalized)
                if any(
                    (
                        row["answer_model_authorized"],
                        row["model_training_authorized"],
                        row["phase2b_authorized"],
                        row["frozen_validation_eligible"],
                    )
                ):
                    raise ValueError("draft became authorizing")
                mandatory = (
                    "jurisdiction_targets",
                    "legal_currentness_cutoff",
                    "fact_status",
                    "temporal_status",
                    "procedural_posture",
                    "remedy_and_deadline_targets",
                    "must_correct_false_premise",
                    "safe_routing_required",
                    "required_authority_types",
                    "difficulty_features",
                    "gold_answer_requires_negative_proposition",
                )
                if any(field not in row or row[field] is None for field in mandatory):
                    raise ValueError("mandatory execution metadata missing")
                count += 1
    if count != 570:
        raise ValueError(f"full question count changed: {count}")
    for path in root.rglob("*.md"):
        if "unseen" in path.read_text(encoding="utf-8").casefold() and "PRIVATE-UNSEEN" in path.name:
            raise ValueError("unseen markdown projection created")


def build() -> Path:
    if OUTPUT_ROOT.exists():
        raise FileExistsError(f"full question-bank draft already exists: {RUN_NAME}")
    if not SOURCE_PACKAGE_ROOT.is_dir():
        raise FileNotFoundError(f"source package missing: {SOURCE_RUN_NAME}")
    source_checksum_count = _verify_checksum_file(SOURCE_PACKAGE_ROOT)
    source_manifest = json.loads((SOURCE_PACKAGE_ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    if source_manifest["run_name"] != SOURCE_RUN_NAME or source_manifest["question_count"] != 270:
        raise ValueError("source package identity changed")
    patch_manifest, amendments, additions, patch_receipt = _load_patch()
    r2 = _load_python_module("phase2b_r2_source", SOURCE_BUILDER)
    unseen = _load_python_module("phase2b_unseen_source", UNSEEN_MODULE)
    core_by_topic, stress_by_topic, unseen_by_topic = _build_question_sets(r2, unseen, amendments, additions)

    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{RUN_NAME}.staging-", dir=OUTPUT_PARENT))
    try:
        source_receipt = _sealed(
            {
                "schema": "legalbot.v111.phase2b.full-bank-source-receipt.v1",
                "source_run_name": SOURCE_RUN_NAME,
                "source_package_manifest_file_sha256": _sha256_file(SOURCE_PACKAGE_ROOT / "PACKAGE-MANIFEST.json"),
                "source_package_content_sha256": source_manifest["package_content_sha256"],
                "source_checksum_entry_count": source_checksum_count,
                "patch_manifest": patch_manifest,
                **patch_receipt,
                "input_material_treated_as_instructions": False,
                "questions_or_answers_executed": False,
            }
        )
        _write_json(staging / "SOURCE-INPUT-RECEIPT.json", source_receipt)

        checkpoint = _currentness_checkpoints()
        _write_json(staging / "CURRENTNESS-CHECKPOINTS.json", checkpoint)
        plan = _execution_plan()
        _write_json(staging / "FUTURE-EXECUTION-PLAN.json", plan)

        topic_registry: list[dict[str, Any]] = []
        all_visible: list[dict[str, Any]] = []
        all_unseen: list[dict[str, Any]] = []
        amendment_priorities = Counter(row["priority"] for row in amendments)
        for topic_id in sorted(r2.TOPICS):
            topic = r2.TOPICS[topic_id]
            core = core_by_topic[topic_id]
            stress = stress_by_topic[topic_id]
            custody = unseen_by_topic[topic_id]
            _assert_distribution(core)
            _assert_distribution(custody, unseen=True)
            if len(stress) != 2 or Counter(row["question_type"] for row in stress) != {"PROBLEM_BASED": 1, "GENERAL_ENQUIRY": 1}:
                raise ValueError(f"stress distribution changed: {topic_id}")

            development_dir = staging / "development" / "topics" / topic_id
            custody_dir = staging / "unseen-custody" / "topics" / topic_id
            development_dir.mkdir(parents=True)
            custody_dir.mkdir(parents=True)
            core_raw = _write_jsonl(development_dir / "CORE-QUESTION-SET.jsonl", core)
            stress_raw = _write_jsonl(development_dir / "STRESS-QUESTION-SET.jsonl", stress)
            (development_dir / "CORE-QUESTION-SET.md").write_text(_markdown(topic["display_name"], "Development/remediation core", core), encoding="utf-8")
            (development_dir / "STRESS-QUESTION-SET.md").write_text(_markdown(topic["display_name"], "Development stress supplement", stress), encoding="utf-8")
            (development_dir / "FUTURE-RUN-CHECKLIST.md").write_text(_future_checklist(topic["display_name"]), encoding="utf-8")
            custody_raw = _write_jsonl(custody_dir / "PRIVATE-UNSEEN-QUESTION-SET.jsonl", custody, private=True)

            topic_manifest = _sealed(
                {
                    "schema": TOPIC_SCHEMA,
                    "status": "FULL_TOPIC_DRAFT_READY_NOT_PHASE2B",
                    "topic_id": topic_id,
                    "display_name": topic["display_name"],
                    "coverage": topic["coverage"],
                    "development_core_question_count": len(core),
                    "development_stress_question_count": len(stress),
                    "development_question_count": len(core) + len(stress),
                    "unseen_custody_draft_question_count": len(custody),
                    "core_jsonl_sha256": _sha256_bytes(core_raw),
                    "stress_jsonl_sha256": _sha256_bytes(stress_raw),
                    "unseen_custody_jsonl_sha256": _sha256_bytes(custody_raw),
                    "unseen_custody_file_mode": "0600",
                    "unseen_markdown_projection_created": False,
                    "owner_unseen_freeze_required": True,
                    "owner_topic_selection_required": True,
                    "source_admission_authorized": False,
                    "retrieval_run": False,
                    "answer_model_run": False,
                    "phase2b_authorized": False,
                    "phase2b_run": False,
                },
                field="topic_content_sha256",
            )
            _write_json(development_dir / "TOPIC-MANIFEST.json", topic_manifest)
            custody_manifest = _sealed(
                {
                    "schema": "legalbot.v111.phase2b.unseen-topic-custody-draft.v1",
                    "status": "CUSTODY_DRAFT_NOT_OWNER_FROZEN",
                    "topic_id": topic_id,
                    "question_count": len(custody),
                    "question_set_sha256": _sha256_bytes(custody_raw),
                    "prompt_content_disclosed_in_manifest": False,
                    "development_access_authorized": False,
                    "one_pass_validation_authorized": False,
                    "owner_freeze_required": True,
                    "owner_disclosure_gate_required": True,
                },
                field="custody_content_sha256",
            )
            _write_json(custody_dir / "CUSTODY-MANIFEST.json", custody_manifest)
            topic_registry.append(
                {
                    "topic_id": topic_id,
                    "display_name": topic["display_name"],
                    "development_question_count": len(core) + len(stress),
                    "unseen_question_count": len(custody),
                    "topic_content_sha256": topic_manifest["topic_content_sha256"],
                    "unseen_custody_content_sha256": custody_manifest["custody_content_sha256"],
                }
            )
            all_visible += core + stress
            all_unseen += custody

        leakage = _leakage_audit(all_visible, all_unseen)
        _write_json(staging / "UNSEEN-LEAKAGE-AUDIT.json", leakage)
        registry = _sealed(
            {
                "schema": "legalbot.v111.phase2b.full-topic-registry-draft.v2",
                "status": "NON_AUTHORIZING_FULL_BANK_DRAFT",
                "topic_count": len(topic_registry),
                "development_core_question_count": 270,
                "development_stress_question_count": 30,
                "development_question_count": 300,
                "unseen_custody_draft_question_count": 270,
                "total_question_record_count": 570,
                "recommended_execution_wave_size": 2,
                "maximum_execution_wave_size": 2,
                "topics": topic_registry,
            },
            field="registry_content_sha256",
        )
        _write_json(staging / "TOPIC-REGISTRY.json", registry)
        patch_report = _sealed(
            {
                "schema": "legalbot.v111.phase2b.patch-application-report.v1",
                "status": "PASS_ALL_PATCH_ROWS_APPLIED_FAIL_CLOSED",
                "amendment_count": len(amendments),
                "must_amend_count": amendment_priorities["MUST_AMEND"],
                "should_amend_count": amendment_priorities["SHOULD_AMEND"],
                "stress_addition_count": len(additions),
                "unmatched_amendment_count": 0,
                "source_prompt_mismatch_count": 0,
                "currentness_audit_correction_count": 1,
                "currentness_audit_correction": "DMCC subscription commencement wording corrected from January 2027 to official-government anticipated spring 2027; actual commencement remains an execution-time check.",
                "legal_reviewer_completed": False,
                "gold_answer_created": False,
            },
            field="report_content_sha256",
        )
        _write_json(staging / "PATCH-APPLICATION-REPORT.json", patch_report)

        unseen_custody_manifest = _sealed(
            {
                "schema": "legalbot.v111.phase2b.unseen-custody-draft-registry.v1",
                "status": "CUSTODY_DRAFT_PREPARED_NOT_OWNER_FROZEN",
                "topic_count": 15,
                "question_count": 270,
                "per_topic_question_count": 18,
                "private_question_files_mode": "0600",
                "development_markdown_projection_created": False,
                "exact_overlap_count": leakage["exact_normalized_prompt_overlap_count"],
                "maximum_tfidf_similarity": leakage["maximum_similarity"],
                "owner_exact_hash_freeze_required_before_development": True,
                "owner_one_pass_disclosure_gate_required": True,
                "validation_run_authorized": False,
            },
            field="custody_registry_content_sha256",
        )
        _write_json(staging / "UNSEEN-CUSTODY-MANIFEST.json", unseen_custody_manifest)

        readme = f"""# {RUN_NAME}

This immutable package is a non-authorizing Phase 2B planning and question-bank draft. It does not start Phase 2B, admit sources, scan, build or embed an index, run retrieval, run an answer model, train a model, disclose frozen validation, promote a candidate or activate live.

- Topics: 15
- Visible development/remediation core: 270 (18 per topic)
- Visible development stress supplement: 30 (2 per topic)
- Unseen validation custody draft: 270 (18 per topic)
- Total exact question records: 570
- Maximum administrative wave: 2 topics, with independent topic folders and decisions
- Audit amendments applied: 44 (32 must-amend and 12 should-amend)

The word “training” is not used as authority for model fine-tuning. The visible 300-question lane is for retrieval/evidence diagnosis, official-source gap research and owner-approved resource repair. The 270 unseen prompts are kept only in private custody JSONL files with no Markdown projection; they are not a frozen validation set until the owner adopts their exact hashes. Once frozen, they cannot be used to repair the Development candidate and may be disclosed only for the separate one-pass validation gate.

After Phase 2A, the future workflow is: owner topic/wave gate → exact unseen hash freeze → visible Development diagnosis → official-source research → exact owner delta → non-ACTIVE build and retrieval re-attestation → Development acceptance and candidate seal → one-pass unseen validation → immutable missing-coverage review → owner decision on Phase 2C. Phase 2C, promotion and live are never automatic.
"""
        (staging / "README.md").write_text(readme, encoding="utf-8")

        package = _sealed(
            {
                "schema": PACKAGE_SCHEMA,
                "status": "FULL_QUESTION_BANK_AND_UNSEEN_CUSTODY_DRAFT_READY_NOT_PHASE2B",
                "run_name": RUN_NAME,
                "revision": 3,
                "supersedes_run_name": SOURCE_RUN_NAME,
                "revision_reason": "APPLIED_SUBSTANTIVE_AUDIT_PATCH_ADDED_STRESS_LANE_AND_PREPARED_18_UNSEEN_DRAFTS_PER_TOPIC",
                "source_input_receipt_sha256": source_receipt["record_content_sha256"],
                "topic_registry_content_sha256": registry["registry_content_sha256"],
                "unseen_custody_registry_content_sha256": unseen_custody_manifest["custody_registry_content_sha256"],
                "leakage_audit_content_sha256": leakage["audit_content_sha256"],
                "currentness_checkpoint_content_sha256": checkpoint["checkpoint_content_sha256"],
                "future_execution_plan_content_sha256": plan["plan_content_sha256"],
                "patch_application_report_content_sha256": patch_report["report_content_sha256"],
                "topic_count": 15,
                "development_core_question_count": 270,
                "development_stress_question_count": 30,
                "development_question_count": 300,
                "unseen_custody_draft_question_count": 270,
                "frozen_validation_question_count": 0,
                "total_question_record_count": 570,
                "owner_unseen_freeze_required": True,
                "owner_topic_selection_required": True,
                "owner_phase2b_gate_required": True,
                "source_admission_authorized": False,
                "source_admitted": False,
                "source_scan_run": False,
                "index_built": False,
                "embedding_run": False,
                "retrieval_run": False,
                "gold_answers_created": False,
                "answer_model_authorized": False,
                "answer_model_run": False,
                "model_training_authorized": False,
                "model_training_run": False,
                "phase2b_authorized": False,
                "phase2b_run": False,
                "development_authorized": False,
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
        checksum_lines = []
        for path in sorted(item for item in staging.rglob("*") if item.is_file()):
            checksum_lines.append(f"{_sha256_file(path)}  {path.relative_to(staging).as_posix()}")
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
