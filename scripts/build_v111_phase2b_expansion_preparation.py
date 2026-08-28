#!/usr/bin/env python3
"""Build non-executing Phase 2B expansion and pre-gold work ledgers.

This package prepares Administrative Law and Wills/Estates source-scope and
question drafts, then creates proposition/evidence work slots for every visible
question.  It does not certify gold, admit or download a source, run Phase 2A,
run Phase 2B, build an index, retrieve evidence, or invoke an answer model.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PARENT = PROJECT_ROOT / "data/evaluations/phase2b-question-drafts"
RUN_NAME = "LegalBot-Phase2B-2026-08-28-expansion-and-pre-gold-r1"
OUTPUT_ROOT = OUTPUT_PARENT / RUN_NAME
SOURCE_RUN_NAME = "LegalBot-Phase2B-2026-08-28-full-question-bank-draft-r3"
SOURCE_PACKAGE_ROOT = OUTPUT_PARENT / SOURCE_RUN_NAME
SOURCE_BUILDER = PROJECT_ROOT / "scripts/build_v111_phase2b_full_question_bank_draft.py"
QUESTION_MODULE = PROJECT_ROOT / "scripts/phase2b_expansion_preparation_questions.py"
LEGAL_CURRENTNESS_CUTOFF = "2026-08-28"


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
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


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module: {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verify_package_checksums(root: Path) -> int:
    count = 0
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = root / relative
        if not path.is_file() or _sha256_file(path) != expected:
            raise ValueError(f"source package checksum mismatch: {relative}")
        count += 1
    return count


OFFICIAL_SOURCE_CANDIDATES: dict[str, list[dict[str, Any]]] = {
    "administrative-law": [
        {
            "source_scope_id": "admin-senior-courts-act-1981-s31",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Senior Courts Act 1981, section 31",
            "url": "https://www.legislation.gov.uk/ukpga/1981/54/section/31",
            "coverage_tags": ["judicial-review", "standing", "remedies", "time-limit"],
        },
        {
            "source_scope_id": "admin-cpr-part-54",
            "authority_type": "OFFICIAL_PROCEDURAL_RULES",
            "title": "Civil Procedure Rules, Part 54",
            "url": "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part54",
            "coverage_tags": [
                "judicial-review",
                "procedure",
                "permission",
                "time-limit",
                "remedies",
            ],
        },
        {
            "source_scope_id": "admin-human-rights-act-1998",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Human Rights Act 1998",
            "url": "https://www.legislation.gov.uk/ukpga/1998/42/contents",
            "coverage_tags": ["human-rights", "public-authority", "remedies", "proportionality"],
        },
        {
            "source_scope_id": "admin-judicial-review-and-courts-act-2022",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Judicial Review and Courts Act 2022",
            "url": "https://www.legislation.gov.uk/ukpga/2022/35/contents",
            "coverage_tags": [
                "ouster-clauses",
                "remedies",
                "suspended-quashing-order",
                "currentness",
            ],
        },
        {
            "source_scope_id": "admin-constitutional-reform-act-2005",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Constitutional Reform Act 2005",
            "url": "https://www.legislation.gov.uk/ukpga/2005/4/contents",
            "coverage_tags": ["rule-of-law", "judicial-independence", "institutional-competence"],
        },
        {
            "source_scope_id": "admin-freedom-of-information-act-2000",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Freedom of Information Act 2000",
            "url": "https://www.legislation.gov.uk/ukpga/2000/36/contents",
            "coverage_tags": ["information", "disclosure", "public-authority", "appeal"],
        },
        {
            "source_scope_id": "admin-equality-act-2010-s149",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Equality Act 2010, section 149",
            "url": "https://www.legislation.gov.uk/ukpga/2010/15/section/149",
            "coverage_tags": ["public-sector-equality-duty", "relevant-considerations", "equality"],
        },
        {
            "source_scope_id": "admin-miller-2019-uksc-41",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "R (Miller) v The Prime Minister [2019] UKSC 41",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2019/41",
            "coverage_tags": ["reviewability", "constitutional-principle", "remedies"],
        },
        {
            "source_scope_id": "admin-privacy-international-2019-uksc-22",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "R (Privacy International) v Investigatory Powers Tribunal [2019] UKSC 22",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2019/22",
            "coverage_tags": ["ouster-clause", "jurisdictional-error", "rule-of-law"],
        },
        {
            "source_scope_id": "admin-unison-2017-uksc-51",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "R (UNISON) v Lord Chancellor [2017] UKSC 51",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2017/51",
            "coverage_tags": ["access-to-justice", "rule-of-law", "statutory-purpose"],
        },
        {
            "source_scope_id": "admin-begum-2021-uksc-7",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "R (Begum) v Special Immigration Appeals Commission [2021] UKSC 7",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2021/7",
            "coverage_tags": [
                "national-security",
                "fair-process",
                "appeal",
                "institutional-competence",
            ],
        },
        {
            "source_scope_id": "admin-aaa-syria-2023-uksc-42",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "R (AAA (Syria)) v Secretary of State for the Home Department [2023] UKSC 42",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2023/42",
            "coverage_tags": ["rationality", "evidence", "international-material", "human-rights"],
        },
    ],
    "wills-and-estates": [
        {
            "source_scope_id": "wills-wills-act-1837",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Wills Act 1837",
            "url": "https://www.legislation.gov.uk/ukpga/Will4and1Vict/7/26/contents",
            "coverage_tags": ["execution", "attestation", "revocation", "witness-benefit"],
        },
        {
            "source_scope_id": "wills-administration-of-estates-act-1925",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Administration of Estates Act 1925",
            "url": "https://www.legislation.gov.uk/ukpga/Geo5/15-16/23/contents",
            "coverage_tags": [
                "intestacy",
                "personal-representative",
                "administration",
                "creditors",
            ],
        },
        {
            "source_scope_id": "wills-inheritance-provision-act-1975",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Inheritance (Provision for Family and Dependants) Act 1975",
            "url": "https://www.legislation.gov.uk/ukpga/1975/63/contents",
            "coverage_tags": ["family-provision", "dependants", "time-limit", "remedies"],
        },
        {
            "source_scope_id": "wills-administration-of-justice-act-1982",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Administration of Justice Act 1982",
            "url": "https://www.legislation.gov.uk/ukpga/1982/53/contents",
            "coverage_tags": ["interpretation", "rectification", "evidence"],
        },
        {
            "source_scope_id": "wills-mental-capacity-act-2005-s18",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Mental Capacity Act 2005, section 18",
            "url": "https://www.legislation.gov.uk/ukpga/2005/9/section/18",
            "coverage_tags": ["statutory-will", "capacity", "court-of-protection"],
        },
        {
            "source_scope_id": "wills-inheritance-and-trustees-powers-act-2014",
            "authority_type": "PRIMARY_LEGISLATION",
            "title": "Inheritance and Trustees’ Powers Act 2014",
            "url": "https://www.legislation.gov.uk/ukpga/2014/16/contents",
            "coverage_tags": ["intestacy", "family-provision", "trustee-powers", "currentness"],
        },
        {
            "source_scope_id": "wills-non-contentious-probate-rules-1987",
            "authority_type": "OFFICIAL_PROCEDURAL_RULES",
            "title": "Non-Contentious Probate Rules 1987",
            "url": "https://www.legislation.gov.uk/uksi/1987/2024/contents",
            "coverage_tags": ["probate", "grant", "caveat", "procedure"],
        },
        {
            "source_scope_id": "wills-cpr-part-57",
            "authority_type": "OFFICIAL_PROCEDURAL_RULES",
            "title": "Civil Procedure Rules, Part 57",
            "url": "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part57",
            "coverage_tags": ["probate-claim", "estate", "procedure", "remedies"],
        },
        {
            "source_scope_id": "wills-ilott-2017-uksc-17",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "Ilott v The Blue Cross [2017] UKSC 17",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2017/17",
            "coverage_tags": ["family-provision", "maintenance", "testamentary-freedom", "remedy"],
        },
        {
            "source_scope_id": "wills-hirachand-2024-uksc-43",
            "authority_type": "OFFICIAL_JUDGMENT",
            "title": "Hirachand v Hirachand [2024] UKSC 43",
            "url": "https://caselaw.nationalarchives.gov.uk/uksc/2024/43",
            "coverage_tags": [
                "family-provision",
                "financial-need",
                "success-fee",
                "remedy",
                "currentness",
            ],
        },
    ],
}


def _source_scope_proposal(question_topics: dict[str, Any]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    allowed_hosts = {
        "www.legislation.gov.uk",
        "www.justice.gov.uk",
        "caselaw.nationalarchives.gov.uk",
    }
    for topic_id in sorted(OFFICIAL_SOURCE_CANDIDATES):
        expected_ids = set(question_topics[topic_id]["official_source_scope_ids"])
        actual_ids = {row["source_scope_id"] for row in OFFICIAL_SOURCE_CANDIDATES[topic_id]}
        if actual_ids != expected_ids:
            raise ValueError(f"source/question scope mismatch: {topic_id}")
        for row in OFFICIAL_SOURCE_CANDIDATES[topic_id]:
            host = urlparse(row["url"]).hostname
            if host not in allowed_hosts or not row["url"].startswith("https://"):
                raise ValueError("non-official source candidate")
            records.append(
                _sealed(
                    {
                        "schema": "legalbot.v111.phase2b.official-source-scope-candidate.v1",
                        "topic_id": topic_id,
                        **row,
                        "jurisdiction": "ENGLAND_AND_WALES",
                        "official_endpoint_http_status_checked": 200,
                        "endpoint_checked_at": "2026-08-28",
                        "exact_version_at_cutoff_requires_freeze": True,
                        "downloaded": False,
                        "quarantined": False,
                        "substantive_content_verified": False,
                        "legal_currentness_verified": False,
                        "owner_approved": False,
                        "source_admitted": False,
                        "indexed": False,
                        "evidence_span_created": False,
                    }
                )
            )
    return _sealed(
        {
            "schema": "legalbot.v111.phase2b.official-source-scope-proposal.v1",
            "status": "PROPOSED_NOT_OWNER_APPROVED_NOT_ADMITTED",
            "legal_currentness_cutoff": LEGAL_CURRENTNESS_CUTOFF,
            "topic_count": 2,
            "source_candidate_count": len(records),
            "source_candidate_counts_by_topic": dict(Counter(row["topic_id"] for row in records)),
            "records": records,
            "source_bytes_downloaded": False,
            "source_admission_authorized": False,
            "source_admitted": False,
            "scan_run": False,
            "index_build_run": False,
            "owner_exact_scope_decision_required": True,
            "warning": "Endpoint availability is not substantive-content, currentness, legal-review or admission approval. Exact official bytes and commencement state must be frozen later.",
        },
        field="scope_content_sha256",
    )


def _question_records(
    topic_id: str, topic: dict[str, Any], r3
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    r3.DEFAULT_JURISDICTIONS[topic_id] = ["ENGLAND_AND_WALES"]
    difficulties = {
        "ESSAY": (
            "SCHOOL_COMPARABLE",
            "SCHOOL_COMPARABLE",
            "HARDER",
            "HARDER",
            "EVEN_HARDER",
            "EVEN_HARDER",
        ),
        "PROBLEM_BASED": (
            "SCHOOL_COMPARABLE",
            "SCHOOL_COMPARABLE",
            "HARDER",
            "HARDER",
            "EVEN_HARDER",
            "EVEN_HARDER",
        ),
        "GENERAL_ENQUIRY": (
            "EVERYDAY",
            "EVERYDAY",
            "EVERYDAY",
            "EVERYDAY",
            "MULTI_ISSUE",
            "BOUNDARY_OR_URGENT",
        ),
    }
    prefixes = {"ESSAY": "e", "PROBLEM_BASED": "p", "GENERAL_ENQUIRY": "g"}
    unseen_prefixes = {"ESSAY": "u-e", "PROBLEM_BASED": "u-p", "GENERAL_ENQUIRY": "u-g"}

    def make(
        lane_name: str, source: dict[str, list[dict[str, Any]]], prefixes_for_lane: dict[str, str]
    ) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        ordinal = 0
        for kind in ("ESSAY", "PROBLEM_BASED", "GENERAL_ENQUIRY"):
            for index, seed in enumerate(source[kind], start=1):
                ordinal += 1
                row = r3._final_question(
                    question_id=f"{topic_id}:{prefixes_for_lane[kind]}{index:02d}",
                    ordinal_within_lane=ordinal,
                    topic_id=topic_id,
                    question_type=kind,
                    difficulty=difficulties[kind][index - 1],
                    prompt=seed["prompt"],
                    issue_tags=seed["issue_tags"],
                    clarification_targets=seed["clarification_targets"],
                    lane=lane_name,
                    source_record_sha256=None,
                )
                payload = dict(row)
                payload.pop("record_content_sha256")
                payload.update(
                    {
                        "topic_source_scope_status": "PROPOSED_NOT_OWNER_APPROVED_NOT_ADMITTED",
                        "execution_bank_membership": False,
                        "development_remediation_eligible": False,
                        "source_admission_precondition_satisfied": False,
                    }
                )
                output.append(_sealed(payload))
        return output

    core = make("DEVELOPMENT_REMEDIATION_CORE", topic["core"], prefixes)
    unseen = make("UNSEEN_VALIDATION_CUSTODY_DRAFT", topic["unseen"], unseen_prefixes)
    stress: list[dict[str, Any]] = []
    for index, (kind, difficulty, seed) in enumerate(
        (
            ("PROBLEM_BASED", "EVEN_HARDER", topic["stress"][0]),
            ("GENERAL_ENQUIRY", "BOUNDARY_OR_URGENT", topic["stress"][1]),
        ),
        start=1,
    ):
        question_id = f"{topic_id}:{'p07' if kind == 'PROBLEM_BASED' else 'g07'}"
        row = r3._final_question(
            question_id=question_id,
            ordinal_within_lane=index,
            topic_id=topic_id,
            question_type=kind,
            difficulty=difficulty,
            prompt=seed["prompt"],
            issue_tags=seed["issue_tags"],
            clarification_targets=seed["clarification_targets"],
            lane="DEVELOPMENT_STRESS_SUPPLEMENT",
            source_record_sha256=None,
        )
        payload = dict(row)
        payload.pop("record_content_sha256")
        payload.update(
            {
                "topic_source_scope_status": "PROPOSED_NOT_OWNER_APPROVED_NOT_ADMITTED",
                "execution_bank_membership": False,
                "development_remediation_eligible": False,
                "source_admission_precondition_satisfied": False,
            }
        )
        stress.append(_sealed(payload))
    return core, stress, unseen


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _source_r3_questions() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    visible: list[dict[str, Any]] = []
    unseen: list[dict[str, Any]] = []
    for path in sorted((SOURCE_PACKAGE_ROOT / "development/topics").rglob("*.jsonl")):
        visible.extend(_read_jsonl(path))
    for path in sorted(
        (SOURCE_PACKAGE_ROOT / "unseen-custody/topics").rglob("PRIVATE-UNSEEN-QUESTION-SET.jsonl")
    ):
        unseen.extend(_read_jsonl(path))
    if len(visible) != 300 or len(unseen) != 270:
        raise ValueError("source r3 question boundary changed")
    return visible, unseen


def _proposition_role(issue_tag: str, question: dict[str, Any]) -> str:
    lower = issue_tag.casefold()
    if question["gold_answer_requires_negative_proposition"] or any(
        word in lower for word in ("false", "boundary", "does-not")
    ):
        return "NEGATIVE_BOUNDARY_OR_NON_APPLICATION"
    if any(
        word in lower
        for word in ("remedy", "procedure", "deadline", "time-limit", "appeal", "court", "cost")
    ):
        return "REMEDY_PROCEDURE_OR_DEADLINE"
    if any(word in lower for word in ("defence", "exception", "exemption", "justification")):
        return "EXCEPTION_DEFENCE_OR_JUSTIFICATION"
    if any(word in lower for word in ("evidence", "proof", "knowledge", "intention", "causation")):
        return "EVIDENTIAL_OR_FACTUAL_THRESHOLD"
    return "GOVERNING_RULE_OR_THRESHOLD"


def _build_pre_gold_ledgers(visible_questions: list[dict[str, Any]], source_scope: dict[str, Any]):
    scope_by_topic: dict[str, list[str]] = {}
    for row in source_scope["records"]:
        scope_by_topic.setdefault(row["topic_id"], []).append(row["source_scope_id"])
    proposition_by_topic: dict[str, list[dict[str, Any]]] = {}
    answer_by_topic: dict[str, list[dict[str, Any]]] = {}
    for question in sorted(visible_questions, key=lambda row: row["question_id"]):
        topic_id = question["topic_id"]
        proposition_ids: list[str] = []
        proposition_rows = proposition_by_topic.setdefault(topic_id, [])
        for ordinal, issue_tag in enumerate(question["issue_tags"], start=1):
            work_item_id = f"{question['question_id']}:proposition-{ordinal:02d}"
            proposition_ids.append(work_item_id)
            proposition_rows.append(
                _sealed(
                    {
                        "schema": "legalbot.v111.phase2b.proposition-evidence-work-item.v1",
                        "status": "PENDING_PHASE2A_SUCCESS_DIGEST_AND_PHASE2B_OWNER_GATE",
                        "work_item_id": work_item_id,
                        "question_id": question["question_id"],
                        "question_record_sha256": question["record_content_sha256"],
                        "topic_id": topic_id,
                        "issue_tag": issue_tag,
                        "proposition_role": _proposition_role(issue_tag, question),
                        "target_proposition_instruction": f"Establish the legally supportable proposition, threshold, exception or negative boundary for issue tag '{issue_tag}' necessary to answer this question.",
                        "jurisdiction_targets": question["jurisdiction_targets"],
                        "legal_currentness_cutoff": question["legal_currentness_cutoff"],
                        "required_authority_types": question["required_authority_types"],
                        "candidate_source_scope_ids": scope_by_topic.get(topic_id, []),
                        "existing_topic_scope_inherited_from_r3": topic_id not in scope_by_topic,
                        "proposition_text": None,
                        "official_source_identity": None,
                        "official_source_version_sha256": None,
                        "evidence_span_ids": [],
                        "deterministic_citation_record_ids": [],
                        "jurisdiction_verified": False,
                        "currentness_verified": False,
                        "later_treatment_verified": False,
                        "locator_verified": False,
                        "legal_reviewer_decision": None,
                        "gold_eligible": False,
                        "answer_release_authorized": False,
                        "phase2b_authorized": False,
                    }
                )
            )
        answer_by_topic.setdefault(topic_id, []).append(
            _sealed(
                {
                    "schema": "legalbot.v111.phase2b.gold-answer-work-item.v1",
                    "status": "GOLD_NOT_CREATED_PREPARATION_ONLY",
                    "question_id": question["question_id"],
                    "question_record_sha256": question["record_content_sha256"],
                    "topic_id": topic_id,
                    "proposition_work_item_ids": proposition_ids,
                    "proposition_work_item_count": len(proposition_ids),
                    "required_answer_sections": [
                        "ISSUE_IDENTIFICATION",
                        "VERIFIED_GOVERNING_PROPOSITIONS",
                        "APPLICATION_TO_FACTS",
                        "REMEDIES_PROCEDURE_AND_DEADLINES",
                        "NEGATIVE_PROPOSITIONS_AND_SAFE_BOUNDARIES",
                        "CONCLUSION_AND_CLARIFICATIONS",
                        "DETERMINISTIC_OSCOLA_CITATION_RECORDS",
                    ],
                    "must_correct_false_premise": question["must_correct_false_premise"],
                    "safe_routing_required": question["safe_routing_required"],
                    "gold_answer_text": None,
                    "evidence_coverage_complete": False,
                    "legal_reviewer_completed": False,
                    "answer_model_run": False,
                    "gold_certified": False,
                    "development_authorized": False,
                    "phase2b_authorized": False,
                }
            )
        )
    return proposition_by_topic, answer_by_topic


def _write_json(path: Path, value: Any) -> None:
    path.write_bytes(_canonical_json(value))


def _write_jsonl(path: Path, records: list[dict[str, Any]], *, private: bool = False) -> bytes:
    raw = b"".join(_canonical_json(row) for row in records)
    path.write_bytes(raw)
    if private:
        path.chmod(0o600)
    return raw


def _markdown(display_name: str, lane: str, records: list[dict[str, Any]]) -> str:
    lines = [
        f"# {display_name} — {lane}",
        "",
        "> Pre-admission, non-authorizing review draft. It is not part of the executable Phase 2B bank.",
        "",
    ]
    for row in records:
        lines += [
            f"## {row['question_id']} — {row['question_type']} / {row['difficulty']}",
            "",
            row["prompt"],
            "",
            "Issue tags: " + ", ".join(row["issue_tags"]),
            "",
        ]
    return "\n".join(lines).rstrip() + "\n"


def _validate_questions(
    core: list[dict[str, Any]], stress: list[dict[str, Any]], unseen: list[dict[str, Any]]
) -> None:
    for records in (core, unseen):
        if len(records) != 18 or Counter(row["question_type"] for row in records) != {
            "ESSAY": 6,
            "PROBLEM_BASED": 6,
            "GENERAL_ENQUIRY": 6,
        }:
            raise ValueError("expansion question distribution changed")
    if len(stress) != 2 or Counter(row["question_type"] for row in stress) != {
        "PROBLEM_BASED": 1,
        "GENERAL_ENQUIRY": 1,
    }:
        raise ValueError("expansion stress distribution changed")


def _assert_safety(root: Path) -> None:
    forbidden = (
        re.compile(rb"/Users/", re.IGNORECASE),
        re.compile(rb"hltsang", re.IGNORECASE),
        re.compile(rb"\bAgnes\b", re.IGNORECASE),
    )
    question_count = 0
    proposition_count = 0
    answer_count = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.name == "SHA256SUMS.txt":
            continue
        raw = path.read_bytes()
        for pattern in forbidden:
            if pattern.search(raw):
                raise ValueError(f"private path or identifier leaked into {path.name}")
        if path.suffix != ".jsonl":
            continue
        for line in raw.decode("utf-8").splitlines():
            row = json.loads(line)
            schema = row.get("schema", "")
            if schema == "legalbot.v111.phase2b.full-question-draft.v2":
                question_count += 1
                if any(
                    row[field]
                    for field in (
                        "source_admission_authorized",
                        "retrieval_authorized",
                        "answer_model_authorized",
                        "model_training_authorized",
                        "phase2b_authorized",
                        "frozen_validation_eligible",
                    )
                ):
                    raise ValueError("expansion question became authorizing")
            elif schema == "legalbot.v111.phase2b.proposition-evidence-work-item.v1":
                proposition_count += 1
                if (
                    row["proposition_text"] is not None
                    or row["evidence_span_ids"]
                    or row["gold_eligible"]
                ):
                    raise ValueError("pre-gold proposition falsely completed")
            elif schema == "legalbot.v111.phase2b.gold-answer-work-item.v1":
                answer_count += 1
                if row["gold_answer_text"] is not None or row["gold_certified"]:
                    raise ValueError("pre-gold answer falsely certified")
    if question_count != 76 or answer_count != 340 or proposition_count <= answer_count:
        raise ValueError(
            f"preparation counts changed: questions={question_count}, answers={answer_count}, propositions={proposition_count}"
        )


def build() -> Path:
    if OUTPUT_ROOT.exists():
        raise FileExistsError(f"preparation package already exists: {RUN_NAME}")
    if not SOURCE_PACKAGE_ROOT.is_dir():
        raise FileNotFoundError(f"source package missing: {SOURCE_RUN_NAME}")
    source_checksum_count = _verify_package_checksums(SOURCE_PACKAGE_ROOT)
    source_manifest = json.loads(
        (SOURCE_PACKAGE_ROOT / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8")
    )
    if (
        source_manifest["package_content_sha256"]
        != "cc625f2b80323654fbd4c3e3a53b16ac99fe54eb460f1a20fc04461c98ce79ec"
    ):
        raise ValueError("source r3 package digest changed")
    r3 = _load_module("phase2b_r3_builder", SOURCE_BUILDER)
    question_module = _load_module("phase2b_expansion_questions", QUESTION_MODULE)
    question_module.validate_expansion_topics()
    source_scope = _source_scope_proposal(question_module.EXPANSION_TOPICS)
    existing_visible, existing_unseen = _source_r3_questions()

    expansion: dict[
        str, tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]
    ] = {}
    expansion_visible: list[dict[str, Any]] = []
    expansion_unseen: list[dict[str, Any]] = []
    for topic_id, topic in question_module.EXPANSION_TOPICS.items():
        records = _question_records(topic_id, topic, r3)
        _validate_questions(*records)
        expansion[topic_id] = records
        expansion_visible += records[0] + records[1]
        expansion_unseen += records[2]
    leakage = r3._leakage_audit(
        existing_visible + expansion_visible,
        existing_unseen + expansion_unseen,
    )
    all_visible = existing_visible + expansion_visible
    proposition_by_topic, answer_by_topic = _build_pre_gold_ledgers(all_visible, source_scope)

    OUTPUT_PARENT.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{RUN_NAME}.staging-", dir=OUTPUT_PARENT))
    try:
        _write_json(staging / "OFFICIAL-SOURCE-SCOPE-PROPOSAL.json", source_scope)
        _write_json(staging / "COMBINED-UNSEEN-LEAKAGE-AUDIT.json", leakage)
        source_receipt = _sealed(
            {
                "schema": "legalbot.v111.phase2b.expansion-preparation-source-receipt.v1",
                "source_run_name": SOURCE_RUN_NAME,
                "source_package_content_sha256": source_manifest["package_content_sha256"],
                "source_package_checksum_entry_count": source_checksum_count,
                "local_administrative_law_container_status": "EMPTY",
                "local_wills_estates_container_status": "EMPTY",
                "teaching_material_used_as_legal_authority": False,
                "phase2a_running_task_read_or_consumed": False,
                "official_endpoint_availability_checks_only": True,
            }
        )
        _write_json(staging / "SOURCE-RECEIPT.json", source_receipt)

        topic_registry: list[dict[str, Any]] = []
        for topic_id in sorted(expansion):
            topic = question_module.EXPANSION_TOPICS[topic_id]
            core, stress, unseen = expansion[topic_id]
            development_dir = staging / "expansion-topics" / topic_id / "development"
            custody_dir = staging / "expansion-topics" / topic_id / "unseen-custody"
            development_dir.mkdir(parents=True)
            custody_dir.mkdir(parents=True)
            core_raw = _write_jsonl(development_dir / "CORE-QUESTION-SET.jsonl", core)
            stress_raw = _write_jsonl(development_dir / "STRESS-QUESTION-SET.jsonl", stress)
            unseen_raw = _write_jsonl(
                custody_dir / "PRIVATE-UNSEEN-QUESTION-SET.jsonl", unseen, private=True
            )
            (development_dir / "CORE-QUESTION-SET.md").write_text(
                _markdown(topic["display_name"], "Development core proposal", core),
                encoding="utf-8",
            )
            (development_dir / "STRESS-QUESTION-SET.md").write_text(
                _markdown(topic["display_name"], "Development stress proposal", stress),
                encoding="utf-8",
            )
            topic_manifest = _sealed(
                {
                    "schema": "legalbot.v111.phase2b.expansion-topic-preparation.v1",
                    "status": "SOURCE_SCOPE_PROPOSED_QUESTIONS_DRAFTED_NOT_EXECUTION_BANK",
                    "topic_id": topic_id,
                    "display_name": topic["display_name"],
                    "coverage": topic["coverage"],
                    "official_source_scope_ids": topic["official_source_scope_ids"],
                    "development_core_question_count": 18,
                    "development_stress_question_count": 2,
                    "unseen_custody_draft_question_count": 18,
                    "core_question_set_sha256": _sha256_bytes(core_raw),
                    "stress_question_set_sha256": _sha256_bytes(stress_raw),
                    "unseen_question_set_sha256": _sha256_bytes(unseen_raw),
                    "unseen_question_file_mode": "0600",
                    "unseen_markdown_projection_created": False,
                    "owner_source_scope_approval_required": True,
                    "source_admission_required_before_execution_bank_membership": True,
                    "source_admitted": False,
                    "phase2b_authorized": False,
                },
                field="topic_content_sha256",
            )
            _write_json(
                staging / "expansion-topics" / topic_id / "TOPIC-MANIFEST.json", topic_manifest
            )
            topic_registry.append(
                {
                    "topic_id": topic_id,
                    "display_name": topic["display_name"],
                    "topic_content_sha256": topic_manifest["topic_content_sha256"],
                    "development_question_count": 20,
                    "unseen_question_count": 18,
                }
            )

        proposition_count = 0
        answer_count = 0
        ledger_registry: list[dict[str, Any]] = []
        for topic_id in sorted(answer_by_topic):
            ledger_dir = staging / "pre-gold-ledgers" / "topics" / topic_id
            ledger_dir.mkdir(parents=True)
            propositions = proposition_by_topic[topic_id]
            answers = answer_by_topic[topic_id]
            proposition_raw = _write_jsonl(
                ledger_dir / "PROPOSITION-EVIDENCE-WORK-LEDGER.jsonl", propositions
            )
            answer_raw = _write_jsonl(ledger_dir / "GOLD-ANSWER-WORK-ITEMS.jsonl", answers)
            proposition_count += len(propositions)
            answer_count += len(answers)
            ledger_manifest = _sealed(
                {
                    "schema": "legalbot.v111.phase2b.pre-gold-topic-ledger.v1",
                    "status": "WORK_SLOTS_CREATED_GOLD_NOT_CREATED",
                    "topic_id": topic_id,
                    "visible_question_count": len(answers),
                    "proposition_work_item_count": len(propositions),
                    "proposition_ledger_sha256": _sha256_bytes(proposition_raw),
                    "gold_answer_work_items_sha256": _sha256_bytes(answer_raw),
                    "proposition_text_completed_count": 0,
                    "evidence_span_bound_count": 0,
                    "gold_answer_completed_count": 0,
                    "legal_reviewer_completed": False,
                    "phase2b_authorized": False,
                },
                field="ledger_content_sha256",
            )
            _write_json(ledger_dir / "LEDGER-MANIFEST.json", ledger_manifest)
            ledger_registry.append(
                {
                    "topic_id": topic_id,
                    "visible_question_count": len(answers),
                    "proposition_work_item_count": len(propositions),
                    "ledger_content_sha256": ledger_manifest["ledger_content_sha256"],
                }
            )

        registry = _sealed(
            {
                "schema": "legalbot.v111.phase2b.expansion-and-pre-gold-registry.v1",
                "status": "PREPARATION_ONLY",
                "existing_topic_count": 15,
                "expansion_topic_count": 2,
                "future_combined_topic_count": 17,
                "existing_visible_question_count": 300,
                "expansion_visible_question_count": 40,
                "future_combined_visible_question_count": 340,
                "existing_unseen_custody_draft_count": 270,
                "expansion_unseen_custody_draft_count": 36,
                "future_combined_unseen_custody_draft_count": 306,
                "expansion_topics": topic_registry,
                "pre_gold_topic_ledgers": ledger_registry,
                "gold_answer_work_item_count": answer_count,
                "proposition_work_item_count": proposition_count,
            },
            field="registry_content_sha256",
        )
        _write_json(staging / "REGISTRY.json", registry)

        merge_plan = _sealed(
            {
                "schema": "legalbot.v111.phase2b.future-expansion-merge-plan.v1",
                "status": "BLOCKED_PENDING_PHASE2A_SUCCESS_DIGEST_AND_SEPARATE_OWNER_ADOPTION",
                "ordered_preconditions": [
                    "SUCCESSFUL_PHASE2A_DIGEST_DELIVERED_BY_OTHER_TASK",
                    "SUCCESSFUL_PHASE2A_DIGEST_SEPARATELY_OWNER_ADOPTED",
                    "EXACT_PHASE2B_TOPIC_AND_RESOURCE_OWNER_GATE",
                    "EXACT_OFFICIAL_SOURCE_SCOPE_OWNER_DECISION",
                    "OFFICIAL_SOURCE_QUARANTINE_AND_SUBSTANTIVE_CONTENT_VERIFICATION",
                    "LEGAL_CURRENTNESS_AND_JURISDICTION_REVIEW",
                    "SOURCE_ADMISSION_AND_VERSIONED_NON_ACTIVE_INDEX_BUILD",
                    "PROPOSITION_TEXT_AND_EVIDENCE_SPAN_COMPLETION",
                    "LEGAL_REVIEWER_GOLD_DECISION",
                    "NEW_IMMUTABLE_FULL_BANK_REVISION_AND_UNSEEN_HASH_FREEZE",
                ],
                "phase2a_running_task_material_consumed": False,
                "automatic_merge": False,
                "automatic_phase2b_start": False,
            },
            field="plan_content_sha256",
        )
        _write_json(staging / "FUTURE-MERGE-PLAN.json", merge_plan)

        approval_prompt = (
            "Future owner decision only — do not use before the successful Phase 2A digest has been delivered and separately adopted.\n\n"
            f"I approve only the exact Phase 2B Administrative Law and Wills/Estates official-source scope proposal with content SHA-256 {source_scope['scope_content_sha256']} for bounded quarantine collection, substantive-content verification and legal-currentness review. This approval does not admit any source, create gold, run retrieval or an answer model, build or activate an index, start Phase 2B, freeze unseen validation, promote, write ACTIVE/PREVIOUS or activate live. Any changed URL, bytes, locator, commencement conclusion or source set requires a new exact delta.\n\n"
            "Typed owner name: ____________________\n"
            "Decision date (YYYY-MM-DD): ____________________\n"
        )
        (staging / "FUTURE-OWNER-SOURCE-SCOPE-DECISION-PROMPT.txt").write_text(
            approval_prompt, encoding="utf-8"
        )

        readme = f"""# {RUN_NAME}

This is a non-executing preparation package. It does not read or consume the running Phase 2A task, and it does not start Phase 2B.

- Existing r3 topics referenced: 15
- New pre-admission topic proposals: Administrative Law and Wills/Estates
- New visible question drafts: 40 (18 core + 2 stress per topic)
- New unseen custody drafts: 36 (18 per topic; private JSONL, no Markdown projection)
- Future combined visible questions if separately approved and admitted: 340
- Future combined unseen drafts: 306
- Gold-answer work slots created: {answer_count}
- Proposition/evidence work slots created: {proposition_count}
- Completed proposition texts, EvidenceSpans and gold answers: 0

The work ledgers make the later task deterministic: every visible question already has issue-bound proposition slots, required authority types, jurisdiction/currentness controls, evidence fields and gold-answer section requirements. They are deliberately empty of legal propositions and EvidenceSpans until Phase 2A succeeds, its digest is separately adopted, the exact Phase 2B/source scope is owner-approved, and official bytes pass substantive-content/currentness review.

The two empty local teaching containers are not treated as authority. Only official legislation, procedural rules and official judgments are proposed, and endpoint availability is not represented as admission or legal-currentness approval.
"""
        (staging / "README.md").write_text(readme, encoding="utf-8")

        package = _sealed(
            {
                "schema": "legalbot.v111.phase2b.expansion-and-pre-gold-package.v1",
                "status": "EXPANSION_AND_PRE_GOLD_PREPARATION_READY_NOT_PHASE2B",
                "run_name": RUN_NAME,
                "source_run_name": SOURCE_RUN_NAME,
                "source_package_content_sha256": source_manifest["package_content_sha256"],
                "source_receipt_sha256": source_receipt["record_content_sha256"],
                "official_source_scope_content_sha256": source_scope["scope_content_sha256"],
                "combined_leakage_audit_content_sha256": leakage["audit_content_sha256"],
                "registry_content_sha256": registry["registry_content_sha256"],
                "future_merge_plan_content_sha256": merge_plan["plan_content_sha256"],
                "expansion_topic_count": 2,
                "official_source_candidate_count": source_scope["source_candidate_count"],
                "expansion_visible_question_count": 40,
                "expansion_unseen_custody_draft_count": 36,
                "gold_answer_work_item_count": answer_count,
                "proposition_work_item_count": proposition_count,
                "completed_gold_answer_count": 0,
                "evidence_span_bound_count": 0,
                "phase2a_running_task_read_or_consumed": False,
                "successful_phase2a_digest_received": False,
                "successful_phase2a_digest_owner_adopted": False,
                "source_scope_owner_approved": False,
                "source_admission_authorized": False,
                "source_admitted": False,
                "source_scan_run": False,
                "index_built": False,
                "embedding_run": False,
                "retrieval_run": False,
                "answer_model_run": False,
                "model_training_run": False,
                "gold_certified": False,
                "development_authorized": False,
                "validation_authorized": False,
                "phase2b_authorized": False,
                "phase2b_run": False,
                "promotion_authorized": False,
                "active_pointer_written": False,
                "previous_pointer_written": False,
                "live_activation_authorized": False,
            },
            field="package_content_sha256",
        )
        _write_json(staging / "PACKAGE-MANIFEST.json", package)
        _assert_safety(staging)
        checksum_lines = [
            f"{_sha256_file(path)}  {path.relative_to(staging).as_posix()}"
            for path in sorted(item for item in staging.rglob("*") if item.is_file())
        ]
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
