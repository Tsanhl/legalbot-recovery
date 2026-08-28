#!/usr/bin/env python3
"""Create or verify the immutable live30 registry from the owner source document."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.live30 import (  # noqa: E402
    SECTIONED_CASE_IDS,
    STRUCTURAL_STANDARD_IDS,
    case_record_sha256,
    load_live30_suite,
    question_sha256,
)

ROOT = PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-30-v1"
SOURCE = ROOT / "source-questions.md"
REGISTRY = ROOT / "cases.jsonl"
SOURCE_HASH = ROOT / "source-questions.sha256"

HEADING = re.compile(
    r"^## Question (?P<ordinal>\d+) — (?P<words>[\d,]+) words — "
    r"(?P<task>Problem|Essay) — (?P<label>.+)$",
    re.MULTILINE,
)

SUBJECTS = (
    "contract",
    "consumer",
    "tort",
    "criminal",
    "professional negligence",
    "criminal evidence",
    "employment and equality",
    "land",
    "public law",
    "company",
    "family",
    "human rights and constitutional",
    "equity and trusts",
    "civil litigation",
    "intellectual property",
    "wills and succession",
    "corporate governance",
    "banking fraud and restitution",
    "competition and digital markets",
    "medical",
    "public procurement and administrative",
    "environmental and climate",
    "data protection and privacy",
    "legal ethics and artificial intelligence",
    "insolvency and corporate transactions",
    "construction and commercial",
    "constitutional and administrative",
    "land trusts family property and insolvency",
    "corporate fraud regulation and litigation",
    "multi-area artificial intelligence litigation",
)

ISSUES: tuple[tuple[str, ...], ...] = (
    (
        "breach",
        "classification of contractual terms",
        "termination",
        "causation",
        "remoteness",
        "mitigation",
        "damages",
        "limitation clause",
    ),
    (
        "satisfactory quality",
        "fitness for purpose",
        "description",
        "pre-contract statements",
        "statutory remedies",
        "repair and replacement",
        "rejection",
        "misrepresentation",
        "restriction of consumer rights",
    ),
    (
        "incremental duty development",
        "assumption of responsibility",
        "omissions",
        "public-authority liability",
        "pure economic loss",
        "foreseeability and proximity",
        "fairness and precedent",
    ),
    (
        "homicide",
        "unlawful act manslaughter",
        "causation and thin skull",
        "mens rea",
        "attempts and impossibility",
        "uncertain time of death",
        "defences",
    ),
    (
        "duty and breach",
        "scope of duty",
        "causation",
        "loss of a chance",
        "contributory negligence",
        "recoverable loss",
        "professional reliance on AI",
    ),
    (
        "confessions",
        "oppression and unreliability",
        "improperly obtained evidence",
        "fairness discretion",
        "identification evidence",
        "hearsay",
        "fact-finding and public confidence",
    ),
    (
        "unfair dismissal and redundancy",
        "direct discrimination",
        "indirect discrimination",
        "disability discrimination",
        "reasonable adjustments",
        "victimisation",
        "justification",
        "evidential burdens",
        "remedies",
    ),
    (
        "proprietary estoppel",
        "constructive trusts",
        "lease formalities",
        "overriding interests",
        "actual occupation",
        "registered priorities",
        "remedies",
    ),
    (
        "illegality",
        "procedural fairness",
        "legitimate expectation",
        "irrationality",
        "proportionality",
        "justiciability",
        "ouster clauses",
        "constitutional relationships",
    ),
    (
        "directors’ duties",
        "corporate opportunities",
        "conflicts and secret profits",
        "ratification",
        "derivative claims",
        "unfair prejudice",
        "remedies",
    ),
    (
        "needs",
        "sharing",
        "compensation",
        "matrimonial and non-matrimonial property",
        "inheritance",
        "business assets and pensions",
        "children",
        "transactions defeating claims",
    ),
    (
        "statutory interpretation",
        "declarations of incompatibility",
        "public-authority liability",
        "proportionality",
        "positive obligations",
        "horizontal effect",
        "parliamentary responses",
        "Strasbourg relationship",
    ),
    (
        "certainty",
        "constitution and imperfect gifts",
        "testamentary trusts",
        "fiduciary duties",
        "breach of trust",
        "assignment of equitable interests",
        "tracing mixed funds",
        "proprietary and personal remedies",
        "third-party liability",
    ),
    (
        "overriding objective",
        "case management",
        "sanctions and relief",
        "disclosure",
        "witness and expert evidence",
        "summary judgment and strike-out",
        "ADR",
        "costs and Part 36",
        "access to justice",
    ),
    (
        "employee-created works",
        "originality and substantial copying",
        "computer programs",
        "training material",
        "generated outputs",
        "confidential information",
        "licensing",
        "remedies",
    ),
    (
        "execution formalities",
        "testamentary capacity",
        "knowledge and approval",
        "undue influence",
        "revocation and interpretation",
        "intestacy",
        "reasonable financial provision",
    ),
    (
        "proper purposes",
        "company success",
        "independent judgment",
        "care and skill",
        "conflicts",
        "stakeholder considerations",
        "creditor interests",
        "ratification and derivative claims",
        "enforcement limits",
    ),
    (
        "payment authority",
        "bank contractual duties and negligence",
        "unjust enrichment",
        "change of position",
        "knowing receipt",
        "tracing and proprietary claims",
        "freezing relief",
        "practical recovery",
    ),
    (
        "market definition",
        "dominance",
        "self-preferencing and tying",
        "discriminatory and exclusive access",
        "predatory conduct",
        "data advantages",
        "merger control",
        "consumer harm and innovation",
        "public and private enforcement",
    ),
    (
        "capacity",
        "consent",
        "best interests and emergency treatment",
        "risk disclosure",
        "clinical negligence",
        "causation",
        "confidentiality",
        "medical reliance on AI",
    ),
    (
        "procurement obligations",
        "procedural fairness and bias",
        "improper purpose",
        "rationality and proportionality",
        "standing and time limits",
        "interim relief",
        "damages",
        "operational-contract consequences",
    ),
    (
        "statutory climate duties",
        "standing and justiciability",
        "rationality and proportionality",
        "human rights",
        "causation and scientific uncertainty",
        "intergenerational interests",
        "corporate disclosure",
        "remedies and constitutional limits",
    ),
    (
        "lawful processing and transparency",
        "special-category inferences",
        "profiling and automated decisions",
        "security",
        "breach notification",
        "access and explanation rights",
        "commercial confidentiality",
        "equality interaction",
        "compensation and enforcement",
    ),
    (
        "client duties",
        "duties to the court",
        "authority verification and candour",
        "confidentiality and privilege",
        "data security",
        "supervision and providers",
        "discrimination and explainability",
        "billing and access to justice",
        "responsibility for generated work",
    ),
    (
        "creditor priorities",
        "fixed and floating charges",
        "transactions at an undervalue",
        "preferences",
        "invalid floating charges",
        "wrongful and fraudulent trading",
        "misfeasance and creditor interests",
        "set-off",
        "retention of title",
    ),
    (
        "contract interpretation and design responsibility",
        "variations and prevention",
        "delay and extensions",
        "liquidated damages",
        "defects and fire safety",
        "causation and remoteness",
        "economic loss and contribution",
        "insurance and bonds",
        "adjudication",
        "limitation and remedies",
    ),
    (
        "parliamentary sovereignty",
        "rule of law",
        "constitutional statutes",
        "judicial review and prerogative",
        "devolution",
        "retained and assimilated law",
        "human rights and ouster clauses",
        "access to courts",
        "ministerial accountability",
        "legal and political constitutionalism",
    ),
    (
        "express resulting and constructive trusts",
        "proprietary estoppel",
        "actual occupation and overriding interests",
        "mortgage priority",
        "undue influence",
        "leases and easements",
        "registration",
        "transactions defrauding creditors",
        "insolvency",
        "family occupation and remedies",
    ),
    (
        "corporate and individual criminal liability",
        "bribery fraud sanctions and false accounting",
        "directors’ duties",
        "whistleblowing and retaliation",
        "privilege and internal investigations",
        "disclosure and evidence preservation",
        "regulatory cooperation",
        "shareholder and securities claims",
        "contract termination",
        "insolvency and creditor interests",
        "interim remedies and litigation strategy",
    ),
    (
        "claimant and defendant map",
        "strongest and weakest causes of action",
        "overlapping and alternative claims",
        "missing factual evidence",
        "defences",
        "causation and quantification",
        "public and private remedies",
        "regulatory consequences",
        "insolvency consequences",
        "litigation and settlement strategy",
        "contract and misrepresentation",
        "professional negligence and loss of chance",
        "equality and automated decisions",
        "data protection and confidentiality",
        "public-law procedural fairness",
        "intellectual property",
        "directors and shareholder remedies",
        "evidence preservation and privilege",
    ),
)


def _extract() -> list[dict[str, object]]:
    text = SOURCE.read_text(encoding="utf-8")
    matches = list(HEADING.finditer(text))
    if len(matches) != 30:
        raise ValueError("source document must contain exactly 30 question headings")
    standard_start = text.index("\n## Standard bot-training requirements")
    rows: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        ordinal = int(match.group("ordinal"))
        if ordinal != index + 1:
            raise ValueError("question headings are not ordered Q1-Q30")
        end = matches[index + 1].start() if index + 1 < len(matches) else standard_start
        question = text[match.end() : end].strip()
        case_id = f"live30-q{ordinal:02d}"
        record: dict[str, object] = {
            "schema": "legalbot.live-evaluation-case.v1",
            "suite_id": "live-evaluation-30-v1",
            "suite_version": "1.0.0",
            "split": "development_live",
            "purpose": "evaluation_only",
            "eligible_for_training": False,
            "training_export_allowed": False,
            "immutable": True,
            "case_id": case_id,
            "ordinal": ordinal,
            "question": question,
            "question_sha256": question_sha256(question),
            "task_type": match.group("task").casefold(),
            "subject": SUBJECTS[index],
            "jurisdiction": "England and Wales",
            "as_of_policy": "run_date",
            "word_target": int(match.group("words").replace(",", "")),
            "expected_research_route": (
                "sectioned" if case_id in SECTIONED_CASE_IDS else "full_enquiry"
            ),
            "expected_drafting_route": "sectioned",
            "expected_behaviour": "answer",
            "structural_standard_ids": list(STRUCTURAL_STANDARD_IDS),
            "must_cover_issues": list(ISSUES[index]),
            "acceptable_source_ids": [],
            "exact_gold_spans": [],
            "known_contrary_authority_ids": [],
            "forbidden_lanes": [],
            "coverage_status": "unqualified",
        }
        record["record_sha256"] = case_record_sha256(record)
        rows.append(record)
    return rows


def _bytes(rows: list[dict[str, object]]) -> bytes:
    return b"".join(
        (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        for row in rows
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("create", "verify"))
    args = parser.parse_args()
    rows = _extract()
    expected = _bytes(rows)
    source_digest = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    if args.command == "create":
        if REGISTRY.exists() or SOURCE_HASH.exists():
            raise FileExistsError("live30 registry is immutable and already exists")
        REGISTRY.write_bytes(expected)
        SOURCE_HASH.write_text(f"{source_digest}  source-questions.md\n", encoding="ascii")
    else:
        if REGISTRY.read_bytes() != expected:
            raise ValueError("live30 registry differs from the canonical owner source")
        expected_hash = f"{source_digest}  source-questions.md\n"
        if SOURCE_HASH.read_text(encoding="ascii") != expected_hash:
            raise ValueError("source question hash sidecar is stale")
    suite = load_live30_suite(REGISTRY)
    print(
        json.dumps(
            {
                "suite_id": "live-evaluation-30-v1",
                "case_count": suite.case_count,
                "total_word_target": suite.total_word_target,
                "suite_sha256": suite.canonical_sha256,
                "source_questions_sha256": source_digest,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
