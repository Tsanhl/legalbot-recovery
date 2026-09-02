#!/usr/bin/env python3
"""Run a create-only GE evidence-planner training and diagnostic unseen cycle.

This is an owner-review pipeline.  It deliberately does not claim qualified
legal review, legal gold, promotion, sealed validation, or live authority.  It
uses the exact visible GE pack and exact sources in the sealed recovery-b
manifest, creates a lexical evidence planner from those sources, and applies it
to all 331 visible cases. Retrieval-training candidates may be emitted, but
wrong routes receive negative labels and answer-weight training stays withheld.
A diagnostic probe of the previously exposed 60 cases is opt-in regression only;
new runs do not mint a fresh unseen set.

The answer format is intentionally conservative: legal text is quoted from a
bound evidence span with a deterministic OSCOLA-style parenthetical citation.
Any unresolved currentness, extent, missing-authority, or legal-review issue
keeps the case ineligible for the 70+ quality gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.evaluation.ge_diagnostic_evaluator import (
    VIDEO_WILL_TAGS,
    alphanumeric_token_count,
    assemble_locator_passages,
    combined_answer,
    displayed_quote,
    evaluate_factual_checks,
    locator_hints_for_case,
    training_eligibility,
    training_example_label,
    unseen_family_summary,
    user_facing_answer,
)
from app.evaluation.ge_factual_gap_fill import sidecar_packs
from app.evaluation.ge_locator_gold_overlay import (
    LocatorGoldOverlay,
    load_locator_gold_overlay,
    titles_equivalent,
)
from app.evaluation.ge_phase2_progress import phase2_progress

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VISIBLE_PACK = PROJECT_ROOT / "data/evaluations/general-enquiries/LegalBot-GE-2026-09-01-review-r3"
SOURCE_MANIFEST = (
    PROJECT_ROOT
    / "data/indexes/builds/current-law-ew-full-fp16-v111-20260829-recovery-b"
    / "approved-source-manifest.json"
)
CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_LOCATOR_OVERLAY = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-per-locator-evaluation-gold-resolved-r2"
    / "LOCATOR-EVALUATION-GOLD-REGISTER.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-01-improvement-training-unseen-r1"
)

SCHEMA = "legalbot.ge-improvement-training-unseen-run.v1"
VISIBLE_RESULT_SCHEMA = "legalbot.ge-evidence-review-result.v1"
TRAINING_SCHEMA = "legalbot.ge-retrieval-training-candidate.v1"
UNSEEN_SCHEMA = "legalbot.ge-diagnostic-unseen-case.v1"
UNSEEN_RESULT_SCHEMA = "legalbot.ge-diagnostic-unseen-result.v1"

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

STOP_WORDS = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "being",
        "but",
        "by",
        "can",
        "could",
        "did",
        "do",
        "does",
        "for",
        "from",
        "had",
        "has",
        "have",
        "how",
        "i",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "may",
        "me",
        "might",
        "my",
        "of",
        "on",
        "or",
        "our",
        "should",
        "so",
        "than",
        "that",
        "the",
        "their",
        "them",
        "then",
        "there",
        "they",
        "this",
        "to",
        "under",
        "use",
        "was",
        "we",
        "were",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "will",
        "with",
        "would",
        "you",
        "your",
        "after",
        "before",
        "about",
        "made",
        "make",
        "want",
        "need",
        "says",
        "said",
        "someone",
        "company",
        "employer",
        "council",
        "court",
        "law",
        "legal",
        "answer",
        "question",
    ]
)

TOPIC_SOURCES: Mapping[str, tuple[str, ...]] = {
    "administrative-law": (
        "Senior Courts Act 1981",
        "The Civil Procedure Rules 1998",
        "Tribunals, Courts and Enforcement Act 2007",
        "Human Rights Act 1998",
        "Judicial Review and Courts Act 2022",
        "Constitutional Reform Act 2005",
        "Equality Act 2010",
        "R (UNISON) v Lord Chancellor",
        "The Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility Regulations 2018",
    ),
    "ai-and-data-protection": (
        "Human Rights Act 1998",
        "Equality Act 2010",
        "Consumer Rights Act 2015",
        "Digital Markets, Competition and Consumers Act 2024",
        "Trade Secrets (Enforcement, etc.) Regulations 2018",
    ),
    "business-and-company-law": (
        "Companies Act 2006",
        "Insolvency Act 1986",
        "Company Directors Disqualification Act 1986",
        "Economic Crime and Corporate Transparency Act 2023",
        "Financial Services and Markets Act 2000",
        "BTI 2014 LLC v Sequana SA",
        "Sevilleja v Marex Financial Ltd",
    ),
    "commercial-law": (
        "Sale of Goods Act 1979",
        "Supply of Goods and Services Act 1982",
        "Consumer Rights Act 2015",
        "Unfair Contract Terms Act 1977",
        "Misrepresentation Act 1967",
        "Contracts (Rights of Third Parties) Act 1999",
        "Insolvency Act 1986",
        "Cavendish Square Holding BV v Makdessi; ParkingEye Ltd v Beavis",
        "Triple Point Technology Inc v PTT Public Company Ltd",
        "Bailey v Angove’s Pty Ltd",
    ),
    "competition-law": (
        "Digital Markets, Competition and Consumers Act 2024",
        "Financial Services and Markets Act 2000",
        "Lifestyle Equities CV v Amazon UK Services Ltd",
    ),
    "contemporary-biolaw-and-regulation": (
        "Human Rights Act 1998",
        "Equality Act 2010",
        "Consumer Protection Act 1987",
        "Consumer Rights Act 2015",
        "Children Act 1989",
        "Family Law Act 1996",
    ),
    "contract-law": (
        "Misrepresentation Act 1967",
        "Unfair Contract Terms Act 1977",
        "Consumer Rights Act 2015",
        "Sale of Goods Act 1979",
        "Supply of Goods and Services Act 1982",
        "Contracts (Rights of Third Parties) Act 1999",
        "Law Reform (Frustrated Contracts) Act 1943",
        "Cavendish Square Holding BV v Makdessi; ParkingEye Ltd v Beavis",
        "Triple Point Technology Inc v PTT Public Company Ltd",
    ),
    "criminal-law": (
        "Police and Criminal Evidence Act 1984",
        "Criminal Attempts Act 1981",
        "Criminal Justice Act 2003",
        "Coroners and Justice Act 2009",
        "Homicide Act 1957",
    ),
    "eu-internal-market-law": (
        "Human Rights Act 1998",
        "Equality Act 2010",
    ),
    "international-commercial-mediation": (
        "The Civil Procedure Rules 1998",
        "Civil Procedure Act 1997",
        "ICC Mediation Rules (contractually incorporated edition)",
        "Ohpen Operations UK Ltd v Invesco Fund Managers Ltd",
        "Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd",
        "Churchill v Merthyr Tydfil County Borough Council",
    ),
    "land-law": (
        "Law of Property Act 1925",
        "Land Registration Act 2002",
        "Trusts of Land and Appointment of Trustees Act 1996",
        "Law of Property (Miscellaneous Provisions) Act 1989",
        "Defective Premises Act 1972",
        "Limitation Act 1980",
        "The Civil Procedure Rules 1998",
    ),
    "law-and-medicine": (
        "Human Rights Act 1998",
        "Children Act 1989",
        "Family Law Act 1996",
        "Limitation Act 1980",
        "Consumer Protection Act 1987",
        "The Civil Procedure Rules 1998",
        "TUI UK Ltd v Griffiths",
    ),
    "pensions-law": (
        "Employment Rights Act 1996",
        "Equality Act 2010",
        "Insolvency Act 1986",
        "Companies Act 2006",
        "Financial Services and Markets Act 2000",
        "Uber BV v Aslam",
    ),
    "private-international-law": (
        "Arbitration Act 1996",
        "Arbitration Act 2025",
        "The Civil Procedure Rules 1998",
        "Civil Procedure Act 1997",
        "The Family Procedure Rules 2010",
    ),
    "tort-law": (
        "Defective Premises Act 1972",
        "Fatal Accidents Act 1976",
        "Limitation Act 1980",
        "Occupiers' Liability Act 1984",
        "Occupiers’ Liability Act 1957",
        "Consumer Protection Act 1987",
        "Law Reform (Contributory Negligence) Act 1945",
        "Manchester Building Society v Grant Thornton UK LLP",
        "Khan v Meadows",
        "TUI UK Ltd v Griffiths",
    ),
    "trusts-law": (
        "Trustee Act 1925",
        "Trustee Act 2000",
        "Variation of Trusts Act 1958",
        "Trusts of Land and Appointment of Trustees Act 1996",
        "Law of Property Act 1925",
        "Perpetuities and Accumulations Act 2009",
        "Twinsectra Ltd v Yardley",
        "Bank of Cyprus UK Ltd v Menelaou",
    ),
    "wills-and-estates": (
        "Wills Act 1837",
        "Wills Act 1837 (as at 2024-01-15)",
        "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
        "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
        "Administration of Estates Act 1925",
        "Inheritance (Provision for Family and Dependants) Act 1975",
        "Administration of Justice Act 1982",
        "Matrimonial Causes Act 1973",
        "Hirachand v Hirachand",
    ),
}

ISSUE_SOURCE_HINTS: Mapping[str, tuple[str, ...]] = {
    "consumer": ("Consumer Rights Act 2015",),
    "digital-content": ("Consumer Rights Act 2015",),
    "unfair-terms": ("Consumer Rights Act 2015", "Unfair Contract Terms Act 1977"),
    "sale-of-goods": ("Sale of Goods Act 1979",),
    "title": ("Sale of Goods Act 1979",),
    "nemo-dat": ("Sale of Goods Act 1979",),
    "misrepresentation": ("Misrepresentation Act 1967",),
    "frustration": ("Law Reform (Frustrated Contracts) Act 1943",),
    "company": ("Companies Act 2006",),
    "director-duties": ("Companies Act 2006",),
    "director-duty": ("Companies Act 2006",),
    "share-allotment": ("Companies Act 2006",),
    "minority-shareholder": ("Companies Act 2006",),
    "insolvency": ("Insolvency Act 1986",),
    "judicial-review": ("Senior Courts Act 1981", "The Civil Procedure Rules 1998"),
    "tribunal": ("Tribunals, Courts and Enforcement Act 2007",),
    "equality": ("Equality Act 2010",),
    "competition": ("Digital Markets, Competition and Consumers Act 2024",),
    "dominance": ("Digital Markets, Competition and Consumers Act 2024",),
    "price-fixing": ("Digital Markets, Competition and Consumers Act 2024",),
    "market-status": ("Digital Markets, Competition and Consumers Act 2024",),
    "police": ("Police and Criminal Evidence Act 1984",),
    "police-interview": ("Police and Criminal Evidence Act 1984",),
    "device-search": ("Police and Criminal Evidence Act 1984",),
    "attempt": ("Criminal Attempts Act 1981",),
    "land-registration": ("Land Registration Act 2002",),
    "registered-land": ("Land Registration Act 2002",),
    "adverse-possession": ("Land Registration Act 2002",),
    "co-ownership": ("Trusts of Land and Appointment of Trustees Act 1996",),
    "beneficial-interest": ("Trusts of Land and Appointment of Trustees Act 1996",),
    "formalities": ("Wills Act 1837", "Law of Property (Miscellaneous Provisions) Act 1989"),
    "marriage": ("Wills Act 1837",),
    "intestacy": ("Administration of Estates Act 1925",),
    "family-provision": ("Inheritance (Provision for Family and Dependants) Act 1975",),
    "occupiers-liability": ("Occupiers’ Liability Act 1957", "Occupiers' Liability Act 1984"),
    "limitation": ("Limitation Act 1980",),
    "product-liability": ("Consumer Protection Act 1987",),
    "contributory-negligence": ("Law Reform (Contributory Negligence) Act 1945",),
    "arbitration": ("Arbitration Act 1996", "Arbitration Act 2025"),
    "interim-relief": ("The Civil Procedure Rules 1998",),
}

# Exact provision anchors take priority over lexical retrieval.  They encode
# issue-to-authority routing only; they are not legal-gold answers.  The title
# must also be admitted for the case topic before an anchor can be used.
ISSUE_LOCATOR_HINTS: Mapping[str, tuple[tuple[str, str], ...]] = {
    "judicial-review": (
        ("Senior Courts Act 1981", "section 31"),
        ("The Civil Procedure Rules 1998", "rule 54.5"),
    ),
    "deadline": (("The Civil Procedure Rules 1998", "rule 54.5"),),
    "statutory-appeal": (("Tribunals, Courts and Enforcement Act 2007", "section 11"),),
    "discrimination": (("Equality Act 2010", "section 13"),),
    "indirect-discrimination": (("Equality Act 2010", "section 19"),),
    "reasonable-adjustments": (("Equality Act 2010", "section 20"),),
    "director-duties": (("Companies Act 2006", "section 172"),),
    "director-duty": (("Companies Act 2006", "section 172"),),
    "passive-director": (("Companies Act 2006", "section 174"),),
    "misuse-assets": (
        ("Companies Act 2006", "section 171"),
        ("Companies Act 2006", "section 172"),
        ("Companies Act 2006", "section 175"),
    ),
    "account-of-profits": (("Companies Act 2006", "section 175"),),
    "proper-purpose": (("Companies Act 2006", "section 171"),),
    "corporate-opportunity": (("Companies Act 2006", "section 175"),),
    "conflict": (("Companies Act 2006", "section 175"),),
    "share-allotment": (("Companies Act 2006", "section 549"),),
    "pre-emption": (("Companies Act 2006", "section 561"),),
    "minority-shareholder": (("Companies Act 2006", "section 994"),),
    "unfair-prejudice": (("Companies Act 2006", "section 994"),),
    "wrongful-trading": (("Insolvency Act 1986", "section 214"),),
    "transaction-undervalue": (("Insolvency Act 1986", "section 238"),),
    "creditor-defeat": (("Insolvency Act 1986", "section 423"),),
    "sale-of-goods": (
        ("Sale of Goods Act 1979", "section 13"),
        ("Sale of Goods Act 1979", "section 14"),
        ("Sale of Goods Act 1979", "section 15"),
    ),
    "nemo-dat": (("Sale of Goods Act 1979", "section 21"),),
    "bulk-goods": (("Sale of Goods Act 1979", "section 20A"),),
    "risk": (("Sale of Goods Act 1979", "section 20"),),
    "rejection": (("Sale of Goods Act 1979", "section 35"),),
    "misrepresentation": (("Misrepresentation Act 1967", "section 2"),),
    "frustration": (("Law Reform (Frustrated Contracts) Act 1943", "section 1"),),
    "consumer-remedies": (
        ("Consumer Rights Act 2015", "section 55"),
        ("Consumer Rights Act 2015", "section 56"),
    ),
    "digital-content": (
        ("Consumer Rights Act 2015", "section 34"),
        ("Consumer Rights Act 2015", "section 42"),
        ("Consumer Rights Act 2015", "section 43"),
        ("Consumer Rights Act 2015", "section 44"),
    ),
    "unfair-terms": (
        ("Consumer Rights Act 2015", "section 62"),
        ("Consumer Rights Act 2015", "section 64"),
        ("Unfair Contract Terms Act 1977", "section 11"),
    ),
    "police-interview": (("Police and Criminal Evidence Act 1984", "section 58"),),
    "legal-advice": (("Police and Criminal Evidence Act 1984", "section 58"),),
    "device-search": (
        ("Police and Criminal Evidence Act 1984", "section 8"),
        ("Police and Criminal Evidence Act 1984", "section 19"),
        ("Police and Criminal Evidence Act 1984", "section 22"),
    ),
    "attempt": (("Criminal Attempts Act 1981", "section 1"),),
    "adverse-possession": (("Land Registration Act 2002", "section 96"),),
    "actual-occupation": (("Land Registration Act 2002", "SCHEDULE 3"),),
    "registered-land": (
        ("Land Registration Act 2002", "section 27"),
        ("Land Registration Act 2002", "section 29"),
    ),
    "land-registration": (("Land Registration Act 2002", "section 27"),),
    "co-ownership": (
        ("Trusts of Land and Appointment of Trustees Act 1996", "section 14"),
        ("Trusts of Land and Appointment of Trustees Act 1996", "section 15"),
    ),
    "beneficial-interest": (("Trusts of Land and Appointment of Trustees Act 1996", "section 14"),),
    "mortgage": (("Law of Property Act 1925", "section 101"),),
    "occupiers-liability": (
        ("Occupiers’ Liability Act 1957", "section 2"),
        ("Occupiers' Liability Act 1984", "section 1"),
    ),
    "dangerous-premises": (("Defective Premises Act 1972", "section 4"),),
    "product-liability": (("Consumer Protection Act 1987", "section 2"),),
    "contributory-negligence": (("Law Reform (Contributory Negligence) Act 1945", "section 1"),),
    "clinical-negligence": (("Limitation Act 1980", "section 11"),),
    "date-of-knowledge": (("Limitation Act 1980", "section 14"),),
    "trustee-investment": (
        ("Trustee Act 2000", "section 3"),
        ("Trustee Act 2000", "section 4"),
    ),
    "delegation": (("Trustee Act 2000", "section 11"),),
    "formalities": (("Wills Act 1837", "section 9"),),
    "intestacy": (("Administration of Estates Act 1925", "section 46"),),
    "family-provision": (
        ("Inheritance (Provision for Family and Dependants) Act 1975", "section 1"),
        ("Inheritance (Provision for Family and Dependants) Act 1975", "section 2"),
        ("Inheritance (Provision for Family and Dependants) Act 1975", "section 4"),
    ),
    "marriage": (("Wills Act 1837", "section 18"),),
    "revocation": (("Wills Act 1837", "section 20"),),
    "codicil": (("Wills Act 1837", "section 9"),),
    "accessibility": (
        ("Equality Act 2010", "section 20"),
        ("Equality Act 2010", "section 21"),
        ("Equality Act 2010", "section 29"),
        ("Equality Act 2010", "schedule 2"),
        (
            "The Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility Regulations 2018",
            "regulation 12",
        ),
    ),
    "public-duty": (
        ("Equality Act 2010", "section 20"),
        ("Equality Act 2010", "section 21"),
        ("Equality Act 2010", "section 29"),
        ("Equality Act 2010", "schedule 2"),
        (
            "The Public Sector Bodies (Websites and Mobile Applications) (No. 2) Accessibility Regulations 2018",
            "regulation 12",
        ),
    ),
    "arbitration-clause": (("Arbitration Act 1996", "section 9"),),
    "stay": (("Arbitration Act 1996", "section 9"),),
    "icc-mediation": (
        ("ICC Mediation Rules (contractually incorporated edition)", "article 5"),
        ("Ohpen Operations UK Ltd v Invesco Fund Managers Ltd", "para 32"),
        ("Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd", "para 1"),
        ("Churchill v Merthyr Tydfil County Borough Council", "para 1"),
    ),
    "multi-tier-clause": (
        ("ICC Mediation Rules (contractually incorporated edition)", "article 5"),
        ("Ohpen Operations UK Ltd v Invesco Fund Managers Ltd", "para 32"),
    ),
    "video-will": (
        ("Wills Act 1837 (as at 2024-01-15)", "section 9"),
        (
            "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
            "article 2",
        ),
        (
            "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
            "article 2",
        ),
    ),
    "interim-relief": (
        ("The Civil Procedure Rules 1998", "rule 25.1"),
        ("Senior Courts Act 1981", "section 37"),
    ),
}

GENERIC_ISSUE_TAGS = frozenset(
    {
        "urgent",
        "false-premise",
        "material-dates",
        "limitation",
        "remedies",
        "procedure",
        "jurisdiction",
        "evidence",
        "england-and-wales",
        "uk",
    }
)

MISSING_PRIMARY_BY_TOPIC: Mapping[str, tuple[str, ...]] = {
    "ai-and-data-protection": (
        "Data Protection Act 2018",
        "UK GDPR",
        "Data (Use and Access) Act 2025",
        "The Data (Use and Access) Act 2025 (Commencement No. 1) Regulations 2026",
    ),
    "competition-law": ("Competition Act 1998", "Enterprise Act 2002"),
    "contemporary-biolaw-and-regulation": (
        "Data Protection Act 2018",
        "Mental Capacity Act 2005",
        "Human Fertilisation and Embryology Act 1990",
        "Human Fertilisation and Embryology Act 2008",
        "Medical Devices Regulations 2002",
    ),
    "criminal-law": (
        "Theft Act 1968",
        "Fraud Act 2006",
        "Computer Misuse Act 1990",
    ),
    "eu-internal-market-law": (
        "Treaty on the Functioning of the European Union",
        "Withdrawal Agreement",
        "European Union (Withdrawal) Act 2018",
        "European Union (Withdrawal Agreement) Act 2020",
        "Retained EU Law (Revocation and Reform) Act 2023",
    ),
    "international-commercial-mediation": (
        "ICC Mediation Rules (contractually incorporated edition)",
        "Ohpen Operations UK Ltd v Invesco Fund Managers Ltd",
        "Kajima Construction Europe (UK) Ltd v Children's Ark Partnership Ltd",
        "Churchill v Merthyr Tydfil County Borough Council",
    ),
    "law-and-medicine": (
        "Mental Capacity Act 2005",
        "Abortion Act 1967",
        "Human Fertilisation and Embryology Act 1990",
    ),
    "pensions-law": (
        "Pension Schemes Act 1993",
        "Pensions Act 1995",
        "Pensions Act 2004",
        "Pensions Act 2008",
        "Pension Schemes Act 2021",
        "Pension Schemes Act 2026",
        "Occupational and Personal Pension Schemes (Conditions for Transfers) Regulations 2021",
        "Pensions Dashboards Regulations 2022",
    ),
    "private-international-law": (
        "Civil Jurisdiction and Judgments Act 1982",
        "Private International Law (Implementation of Agreements) Act 2020",
        "Rome I Regulation",
        "Rome II Regulation",
    ),
}

MISSING_PRIMARY_BY_TAG: Mapping[str, tuple[str, ...]] = {
    "video-will": (
        "Wills Act 1837 section 9 as it had effect on 2024-01-15",
        "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
        "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
    ),
}


@dataclass(frozen=True)
class Evidence:
    chunk_id: str
    source_version_id: str
    title: str
    locator: str
    text: str
    rank: float
    currentness_status: str
    currentness_reviewed_as_of_date: str | None
    currentness_verified: bool
    full_current_law_verification_eligible: bool
    identity_verified: bool
    jurisdiction: str
    canonical_url: str | None
    stable_identifier: str
    authority_identity_id: str | None
    provision_extent_status: str
    unapplied_effect_count: int | None
    lane: str
    assembled_chunk_ids: tuple[str, ...] = ()
    passage_flags: tuple[str, ...] = ()
    point_in_time_as_at: str | None = None


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = _sha256_bytes(_canonical_bytes(result))
    return result


def _write_create_only(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        raise


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_create_only(
        path, json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    )


def _write_jsonl(path: Path, values: Iterable[Mapping[str, Any]]) -> None:
    data = b"".join(_canonical_bytes(value) for value in values)
    _write_create_only(path, data)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _load_visible() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    manifest = _load_json(VISIBLE_PACK / "PACK-MANIFEST.json")
    rows = [
        json.loads(line)
        for line in (VISIBLE_PACK / "GE-VISIBLE-REVIEW.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if len(rows) != 331:
        raise RuntimeError("visible GE denominator differs from 331")
    if [int(row["source_review_ordinal"]) for row in rows] != list(range(1, 332)):
        raise RuntimeError("visible GE order differs")
    if len({str(row["question_id"]) for row in rows}) != 331:
        raise RuntimeError("visible GE identity is duplicated")
    return rows, manifest


def _source_lookup(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != 85:
        raise RuntimeError("approved source manifest is not the exact 85-source build")
    result: dict[str, dict[str, Any]] = {}
    for raw in sources:
        if not isinstance(raw, dict):
            raise RuntimeError("source manifest row is invalid")
        source_id = str(raw.get("source_version_id") or "")
        if not source_id or source_id in result:
            raise RuntimeError("source identity is empty or duplicated")
        result[source_id] = raw
    for pack in sidecar_packs(PROJECT_ROOT):
        manifest_path = pack / "STAGED-SOURCE-MANIFEST.json"
        if not manifest_path.is_file():
            continue
        staged = _load_json(manifest_path)
        extra = staged.get("sources")
        if not isinstance(extra, list):
            continue
        for raw in extra:
            if not isinstance(raw, dict):
                continue
            source_id = str(raw.get("source_version_id") or "")
            if not source_id or source_id in result:
                continue
            result[source_id] = raw
    return result


def _insert_sidecar_chunks(
    out: sqlite3.Connection, sources: Mapping[str, Mapping[str, Any]]
) -> int:
    inserted = 0
    for pack in sidecar_packs(PROJECT_ROOT):
        chunks_path = pack / "chunks.sqlite3"
        if not chunks_path.is_file():
            continue
        staged = sqlite3.connect(f"file:{chunks_path.resolve()}?mode=ro", uri=True)
        staged.row_factory = sqlite3.Row
        try:
            staged_batch: list[tuple[str, str, str, str, str, int]] = []
            for row in staged.execute(
                """
                SELECT chunk_id, source_version_id, title, locator, body, ordinal
                FROM chunk_meta
                ORDER BY source_version_id, ordinal, chunk_id
                """
            ):
                source_id = str(row["source_version_id"])
                if source_id not in sources:
                    continue
                body = str(row["body"] or "").strip()
                if not body:
                    continue
                staged_batch.append(
                    (
                        str(row["chunk_id"]),
                        source_id,
                        str(row["title"] or ""),
                        str(row["locator"] or ""),
                        body,
                        int(row["ordinal"] or 0),
                    )
                )
                if len(staged_batch) >= 2000:
                    out.executemany("INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)", staged_batch)
                    out.executemany("INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)", staged_batch)
                    inserted += len(staged_batch)
                    staged_batch.clear()
            if staged_batch:
                out.executemany("INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)", staged_batch)
                out.executemany("INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)", staged_batch)
                inserted += len(staged_batch)
        finally:
            staged.close()
    return inserted


def _create_fts(path: Path, sources: Mapping[str, Mapping[str, Any]]) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"create-only FTS output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, stat.S_IRWXU)
    out = sqlite3.connect(path)
    try:
        out.executescript(
            """
            PRAGMA journal_mode=DELETE;
            PRAGMA synchronous=FULL;
            CREATE VIRTUAL TABLE chunks_fts USING fts5(
              chunk_id UNINDEXED,
              source_version_id UNINDEXED,
              title,
              locator,
              body,
              ordinal UNINDEXED,
              tokenize='porter unicode61'
            );
            CREATE TABLE chunk_meta(
              chunk_id TEXT PRIMARY KEY,
              source_version_id TEXT NOT NULL,
              title TEXT NOT NULL,
              locator TEXT NOT NULL,
              body TEXT NOT NULL,
              ordinal INTEGER NOT NULL
            );
            CREATE INDEX idx_chunk_meta_title_locator
              ON chunk_meta(title, locator, ordinal, chunk_id);
            CREATE TABLE build_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """
        )
        catalogue = sqlite3.connect(f"file:{CATALOGUE.resolve()}?mode=ro", uri=True)
        catalogue.row_factory = sqlite3.Row
        try:
            batch: list[tuple[str, str, str, str, str, int]] = []
            inserted = 0
            for source_id, meta in sources.items():
                for row in catalogue.execute(
                    """
                    SELECT id, locator, markdown_text, ordinal
                    FROM chunks
                    WHERE source_version_id = ? AND stream = 'body'
                    ORDER BY ordinal, id
                    """,
                    (source_id,),
                ):
                    body = str(row["markdown_text"] or "").strip()
                    if not body:
                        continue
                    batch.append(
                        (
                            str(row["id"]),
                            source_id,
                            str(meta.get("title") or "Untitled source"),
                            str(row["locator"] or ""),
                            body,
                            int(row["ordinal"] or 0),
                        )
                    )
                    if len(batch) >= 2000:
                        out.executemany("INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)", batch)
                        out.executemany("INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)", batch)
                        inserted += len(batch)
                        batch.clear()
            if batch:
                out.executemany("INSERT INTO chunks_fts VALUES (?,?,?,?,?,?)", batch)
                out.executemany("INSERT INTO chunk_meta VALUES (?,?,?,?,?,?)", batch)
                inserted += len(batch)
            inserted += _insert_sidecar_chunks(out, sources)
            out.executemany(
                "INSERT INTO build_meta(key,value) VALUES (?,?)",
                (
                    ("schema", "legalbot.ge-approved-source-fts.v3"),
                    ("source_count", str(len(sources))),
                    ("chunk_count", str(inserted)),
                    ("source_manifest_sha256", str(_load_json(SOURCE_MANIFEST)["manifest_sha256"])),
                ),
            )
            out.commit()
        finally:
            catalogue.close()
    finally:
        out.close()
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _tokens(*values: Any) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            text = " ".join(str(item) for item in value)
        else:
            text = str(value or "")
        for token in re.findall(r"[a-z0-9]{3,}", text.casefold().replace("-", " ")):
            if token in STOP_WORDS or token in seen:
                continue
            seen.add(token)
            result.append(token)
    return tuple(result[:24])


def _fts_query(tokens: Sequence[str]) -> str:
    safe = [token for token in tokens if re.fullmatch(r"[a-z0-9]+", token)]
    return " OR ".join(f'"{token}"' for token in safe)


def _hinted_titles(topic: str, issue_tags: Sequence[str]) -> tuple[str, ...]:
    hinted: list[str] = []
    for tag in issue_tags:
        lowered = str(tag).casefold()
        for key, titles in ISSUE_SOURCE_HINTS.items():
            if key == lowered:
                hinted.extend(titles)
    if not hinted:
        for tag in issue_tags:
            lowered = str(tag).casefold()
            for key, titles in ISSUE_SOURCE_HINTS.items():
                if key in lowered:
                    hinted.extend(titles)
    ordered: list[str] = []
    for title in hinted:
        if title not in ordered:
            ordered.append(title)
    return tuple(ordered)


def _evidence_from_row(
    row: Mapping[str, Any],
    *,
    meta: Mapping[str, Any],
    rank: float,
    text: str | None = None,
    assembled_chunk_ids: tuple[str, ...] = (),
    passage_flags: tuple[str, ...] = (),
) -> Evidence:
    return Evidence(
        chunk_id=str(row["chunk_id"]),
        source_version_id=str(row["source_version_id"]),
        title=str(row["title"]),
        locator=str(row["locator"] or "").strip(),
        text=str(text if text is not None else row["body"] or "").strip(),
        rank=round(rank, 6),
        currentness_status=str(meta.get("currentness_status") or "unknown"),
        currentness_reviewed_as_of_date=(
            str(meta["currentness_reviewed_as_of_date"])
            if meta.get("currentness_reviewed_as_of_date")
            else None
        ),
        currentness_verified=meta.get("currentness_verified") is True,
        full_current_law_verification_eligible=(
            meta.get("full_current_law_verification_eligible") is True
        ),
        identity_verified=meta.get("identity_verified") is True,
        jurisdiction=str(meta.get("jurisdiction") or ""),
        canonical_url=(str(meta["canonical_url"]) if meta.get("canonical_url") else None),
        stable_identifier=str(meta.get("stable_identifier") or ""),
        authority_identity_id=(
            str(meta["authority_identity_id"]) if meta.get("authority_identity_id") else None
        ),
        provision_extent_status=str(meta.get("provision_extent_status") or "unknown"),
        unapplied_effect_count=(
            int(meta["unapplied_effect_count"])
            if isinstance(meta.get("unapplied_effect_count"), int)
            else None
        ),
        lane=str(meta.get("lane") or ""),
        assembled_chunk_ids=assembled_chunk_ids,
        passage_flags=passage_flags,
        point_in_time_as_at=(
            str(meta["point_in_time_as_at"]) if meta.get("point_in_time_as_at") else None
        ),
    )


def _locator_aliases(locator: str) -> tuple[str, ...]:
    text = str(locator or "").strip()
    lowered = text.casefold()
    aliases = {lowered}
    if lowered.startswith("para ") and not lowered.startswith("paragraph "):
        aliases.add("paragraph " + lowered[5:])
    if lowered.startswith("paragraph "):
        aliases.add("para " + lowered[10:])
    if lowered == "schedule 2":
        aliases.update({"schedule 2", "schedule 2 paragraphs 1-2"})
    return tuple(sorted(aliases))


def _keep_exact_chunk(*, title: str, locator: str, body: str) -> bool:
    title_l = title.casefold()
    locator_l = locator.casefold()
    text = body.casefold()
    if "cable & wireless" in title_l:
        return False
    if "equality act 2010" in title_l and locator_l.startswith("schedule 2"):
        if "paragraph 3" in text or "paragraph 4" in text:
            return False
        return (
            "paragraph 1" in text
            or "paragraph 2" in text
            or "services and public functions" in text
        )
    if "icc mediation rules" in title_l and locator_l == "article 5":
        if "currency" in text and "vat" in text:
            return False
        if "appendix" in text:
            return False
        return True
    return True


def _is_rejected_mandatory(title: str, overlay: LocatorGoldOverlay | None) -> bool:
    if "cable & wireless" in title.casefold():
        return True
    if overlay is not None:
        return overlay.is_rejected_mandatory(title)
    return False


def _exact_locator_candidates(
    connection: sqlite3.Connection,
    *,
    topic: str,
    issue_tags: Sequence[str],
    sources: Mapping[str, Mapping[str, Any]],
    overlay: LocatorGoldOverlay | None = None,
) -> tuple[Evidence, ...]:
    allowed_titles = set(TOPIC_SOURCES.get(topic, ()))
    exact_hints = locator_hints_for_case(issue_tags, ISSUE_LOCATOR_HINTS)

    candidates: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    for title, locator in exact_hints:
        if title not in allowed_titles or (title, locator) in seen:
            continue
        if _is_rejected_mandatory(title, overlay):
            continue
        seen.add((title, locator))
        aliases = _locator_aliases(locator)
        placeholders = ",".join("?" for _ in aliases)
        rows = connection.execute(
            f"""
            SELECT chunk_id, source_version_id, title, locator, body, ordinal
            FROM chunk_meta
            WHERE lower(title) = lower(?) AND lower(locator) IN ({placeholders})
            ORDER BY ordinal, chunk_id
            """,
            (title, *aliases),
        ).fetchall()
        rows = [
            row
            for row in rows
            if _keep_exact_chunk(
                title=str(row["title"] or ""),
                locator=str(row["locator"] or ""),
                body=str(row["body"] or ""),
            )
        ]
        if not rows:
            continue
        assembled = assemble_locator_passages(rows)
        if assembled is None:
            continue
        primary = next(row for row in rows if str(row["chunk_id"]) == assembled.primary_chunk_id)
        meta = sources.get(str(primary["source_version_id"]))
        if meta is None:
            raise RuntimeError("exact locator returned a source outside the exact manifest")
        flags = []
        if assembled.punctuation_only:
            flags.append("punctuation_only")
        if assembled.skipped_punctuation_chunk_ids:
            flags.append("skipped_repealed_or_empty_fragments")
        evidence = _evidence_from_row(
            primary,
            meta=meta,
            rank=-100.0,
            text=assembled.text,
            assembled_chunk_ids=assembled.assembled_chunk_ids,
            passage_flags=tuple(flags),
        )
        if alphanumeric_token_count(evidence.text) >= 8 or assembled.punctuation_only:
            candidates.append(evidence)
    return tuple(candidates)


def _retrieve(
    connection: sqlite3.Connection,
    *,
    case: Mapping[str, Any],
    sources: Mapping[str, Mapping[str, Any]],
    overlay: LocatorGoldOverlay | None = None,
    limit: int = 3,
) -> tuple[Evidence, ...]:
    topic = str(case.get("topic_id") or "")
    tags = tuple(
        str(value)
        for value in case.get("issue_tags") or ()
        if str(value).casefold() not in GENERIC_ISSUE_TAGS
    )
    exact = _exact_locator_candidates(
        connection,
        topic=topic,
        issue_tags=tags,
        sources=sources,
        overlay=overlay,
    )
    tag_set = {str(tag).casefold() for tag in tags}
    if tag_set & VIDEO_WILL_TAGS:
        return exact
    if exact:
        return exact
    titles = list(_hinted_titles(topic, tags))
    available_titles = {str(value.get("title") or "") for value in sources.values()}
    for name in MISSING_PRIMARY_BY_TOPIC.get(topic, ()):
        if name in available_titles and name not in titles:
            titles.append(name)
    for tag in tags:
        for name in MISSING_PRIMARY_BY_TAG.get(str(tag).casefold(), ()):
            if name in available_titles and name not in titles:
                titles.append(name)
    titles = [
        title
        for title in titles
        if title in available_titles and not _is_rejected_mandatory(title, overlay)
    ]
    if not titles:
        return ()
    query_tokens = _tokens(case.get("prompt"), tags, case.get("scenario_family_id"))
    query = _fts_query(query_tokens)
    if not query:
        return ()
    placeholders = ",".join("?" for _ in titles)
    rows = connection.execute(
        f"""
        SELECT chunk_id, source_version_id, title, locator, body,
               bm25(chunks_fts, 0.0, 0.0, 1.7, 1.2, 2.4) AS rank
        FROM chunks_fts
        WHERE chunks_fts MATCH ? AND title IN ({placeholders})
        ORDER BY rank, source_version_id, chunk_id
        LIMIT 80
        """,
        (query, *titles),
    ).fetchall()
    token_set = set(query_tokens)
    candidates: list[tuple[float, Evidence]] = []
    for row in rows:
        meta = sources.get(str(row["source_version_id"]))
        if meta is None:
            raise RuntimeError("FTS returned a source outside the exact manifest")
        if _is_rejected_mandatory(str(row["title"] or ""), overlay):
            continue
        body = str(row["body"] or "").strip()
        locator = str(row["locator"] or "").strip()
        if alphanumeric_token_count(body) < 8 or not locator:
            continue
        words = set(re.findall(r"[a-z0-9]{3,}", f"{locator} {body}".casefold()))
        overlap = len(token_set.intersection(words)) / max(1, len(token_set))
        title_bonus = 0.12 if str(row["title"]) in titles[:3] else 0.0
        locator_bonus = (
            0.12
            if re.match(r"(?i)^(section|article|regulation|rule|paragraph)\b", locator)
            else 0.0
        )
        score = overlap + title_bonus + locator_bonus - (float(row["rank"]) / 100.0)
        evidence = _evidence_from_row(row, meta=meta, rank=float(row["rank"]))
        candidates.append((score, evidence))
    candidates.sort(key=lambda item: (-item[0], item[1].rank, item[1].chunk_id))
    selected: list[Evidence] = []
    seen_chunks: set[str] = set()
    for score, evidence in candidates:
        if evidence.chunk_id in seen_chunks:
            continue
        evidence_words = set(re.findall(r"[a-z0-9]{3,}", evidence.text.casefold()))
        if len(token_set.intersection(evidence_words)) < 2 or score < 0.18:
            continue
        selected.append(evidence)
        seen_chunks.add(evidence.chunk_id)
        if len(selected) >= limit:
            break
    return tuple(selected)


def _locator_abbreviation(locator: str) -> str:
    match = re.match(r"(?i)^section\s+(.+)$", locator)
    if match:
        return f"s {match.group(1)}"
    match = re.match(r"(?i)^sections\s+(.+)$", locator)
    if match:
        return f"ss {match.group(1)}"
    match = re.match(r"(?i)^article\s+(.+)$", locator)
    if match:
        return f"art {match.group(1)}"
    match = re.match(r"(?i)^regulation\s+(.+)$", locator)
    if match:
        return f"reg {match.group(1)}"
    match = re.match(r"(?i)^paragraph\s+(.+)$", locator)
    if match:
        return f"para {match.group(1)}"
    return locator


def _citation(evidence: Evidence) -> str:
    locator = _locator_abbreviation(evidence.locator)
    if evidence.authority_identity_id and "neutral-citation:" in evidence.authority_identity_id:
        neutral = evidence.authority_identity_id.split("neutral-citation:", 1)[1]
        return f"{evidence.title} {neutral}, {locator}"
    if locator.casefold() == evidence.title.casefold():
        return evidence.title
    return f"{evidence.title}, {locator}"


def _quote(evidence: Evidence, limit: int = 120) -> str:
    return displayed_quote(evidence.text, evidence.locator, word_limit=limit)


def _evidence_row(evidence: Evidence) -> dict[str, Any]:
    quote = _quote(evidence)
    citation = _citation(evidence)
    span_digest = _sha256_bytes(
        _canonical_bytes(
            {
                "source_version_id": evidence.source_version_id,
                "chunk_id": evidence.chunk_id,
                "locator": evidence.locator,
                "quote": quote,
            }
        )
    )
    return {
        "source_version_id": evidence.source_version_id,
        "chunk_id": evidence.chunk_id,
        "title": evidence.title,
        "locator": evidence.locator,
        "quote": quote,
        "oscola_parenthetical": f"({citation})",
        "canonical_url": evidence.canonical_url,
        "stable_identifier": evidence.stable_identifier,
        "authority_identity_id": evidence.authority_identity_id,
        "jurisdiction": evidence.jurisdiction,
        "lane": evidence.lane,
        "currentness_status": evidence.currentness_status,
        "currentness_reviewed_as_of_date": evidence.currentness_reviewed_as_of_date,
        "currentness_verified": evidence.currentness_verified,
        "full_current_law_verification_eligible": evidence.full_current_law_verification_eligible,
        "identity_verified": evidence.identity_verified,
        "provision_extent_status": evidence.provision_extent_status,
        "unapplied_effect_count": evidence.unapplied_effect_count,
        "retrieval_rank": evidence.rank,
        "evidence_span_sha256": span_digest,
        "stored_text": evidence.text,
        "assembled_chunk_ids": list(evidence.assembled_chunk_ids),
        "passage_flags": list(evidence.passage_flags),
        "point_in_time_as_at": evidence.point_in_time_as_at,
    }


def _documents(case: Mapping[str, Any]) -> list[str]:
    values = case.get("required_document_categories")
    if isinstance(values, list):
        return [str(value) for value in values if str(value).strip()][:6]
    return []


def _clarifications(case: Mapping[str, Any]) -> list[str]:
    value = case.get("proposed_clarification_criteria")
    if isinstance(value, Mapping):
        items = value.get("indispensable_facts")
        if isinstance(items, list):
            return [str(item) for item in items if str(item).strip()][:3]
    return []


def _safe_first_response(case: Mapping[str, Any]) -> str:
    value = case.get("proposed_clarification_criteria")
    if isinstance(value, Mapping):
        result = str(value.get("safe_first_response") or "").strip()
        if result:
            return result
    return "Preserve the relevant documents and obtain the missing facts before taking an irreversible step."


def _answer(case: Mapping[str, Any], evidence_rows: Sequence[Mapping[str, Any]]) -> str:
    return combined_answer(case, evidence_rows)


def _factual_result(
    *,
    case: Mapping[str, Any],
    evidence_rows: Sequence[Mapping[str, Any]],
    source_manifest_sha256: str,
    user_facing_answer_text: str,
    overlay: LocatorGoldOverlay | None = None,
) -> tuple[dict[str, str], dict[str, str], list[str], dict[str, dict[str, str]]]:
    evaluation = evaluate_factual_checks(
        case=case,
        evidence_rows=evidence_rows,
        source_manifest_sha256=source_manifest_sha256,
        user_facing_answer_text=user_facing_answer_text,
        overlay=overlay,
    )
    return evaluation.checks, evaluation.reasons, evaluation.failed, evaluation.diagnostic_checks


def _result_for_case(
    *,
    case: Mapping[str, Any],
    evidence: Sequence[Evidence],
    source_manifest_sha256: str,
    ordinal: int,
    lane: str,
    overlay: LocatorGoldOverlay | None = None,
    available_titles: set[str] | None = None,
) -> dict[str, Any]:
    evidence_rows = [_evidence_row(item) for item in evidence]
    answer = _answer(case, evidence_rows)
    checks, reasons, failed, diagnostic_checks = _factual_result(
        case=case,
        evidence_rows=evidence_rows,
        source_manifest_sha256=source_manifest_sha256,
        user_facing_answer_text=answer,
        overlay=overlay,
    )
    tags = {str(tag).casefold() for tag in case.get("issue_tags") or ()}
    factual_outcome = "FACTUAL_PASS" if not failed else "FACTUAL_HOLD"
    improvement_reasons: list[str] = []
    if tags & VIDEO_WILL_TAGS:
        factual_outcome = "FACTUAL_HOLD"
        improvement_reasons.append("case_validity:video_will_sequence_fact_dependent")
    missing = list(MISSING_PRIMARY_BY_TOPIC.get(str(case.get("topic_id") or ""), ()))
    for tag in case.get("issue_tags") or ():
        missing.extend(MISSING_PRIMARY_BY_TAG.get(str(tag).casefold(), ()))
    present = available_titles or set()
    missing = [
        name
        for name in dict.fromkeys(missing)
        if not _is_rejected_mandatory(name, overlay)
        and name not in present
        and not any(titles_equivalent(name, title) for title in present)
    ]
    if not evidence_rows:
        improvement_reasons.append("retrieval:no_relevant_primary_passage")
    improvement_reasons.extend(f"factual:{name}" for name in failed)
    if missing:
        improvement_reasons.append("source_scope:known_primary_authority_gap")
    quality = {
        "eligible": factual_outcome == "FACTUAL_PASS",
        "score": None,
        "outcome": "NOT_ELIGIBLE" if factual_outcome != "FACTUAL_PASS" else "PENDING_QUALIFIED_REVIEW",
        "reason": (
            "Quality scoring is prohibited while a material factual check fails or case validity remains fact-dependent."
            if factual_outcome != "FACTUAL_PASS"
            else "Automated structure passed; qualified legal review is still required before a 70+ decision."
        ),
    }
    value = {
        "schema": VISIBLE_RESULT_SCHEMA if lane == "visible" else UNSEEN_RESULT_SCHEMA,
        "case_id": str(case.get("question_id") or case.get("case_id") or f"case-{ordinal:03d}"),
        "case_version_id": str(
            case.get("question_version_id") or case.get("case_version_id") or "diagnostic-v1"
        ),
        "ordinal": ordinal,
        "lane": lane,
        "topic_id": str(case.get("topic_id") or "general"),
        "scenario_family_id": str(case.get("scenario_family_id") or ""),
        "issue_tags": [str(tag) for tag in case.get("issue_tags") or []],
        "question": str(case.get("prompt") or ""),
        "planner_output": _safe_first_response(case),
        "answer": answer,
        "user_facing_answer": user_facing_answer(case, evidence_rows),
        "answer_kind": "evidence_bound_owner_review_candidate",
        "evidence": evidence_rows,
        "factual_result": {
            "outcome": factual_outcome,
            "checks": checks,
            "reasons": reasons,
            "diagnostic_checks": diagnostic_checks,
        },
        "quality_70_plus": quality,
        "known_missing_primary_authorities": missing,
        "improvement_reasons": improvement_reasons,
        "training_eligibility": training_eligibility(lane=lane),
        "owner_review": {
            "decision": "UNREVIEWED",
            "options": ["APPROVE", "RE_EVALUATE", "TUNE_OR_TRAIN", "HOLD"],
        },
        "non_authorizing": {
            "qualified_legal_review": False,
            "legal_gold": False,
            "sealed_validation": False,
            "promotion": False,
            "live": False,
        },
    }
    return _sealed(value)


def _training_row(result: Mapping[str, Any]) -> dict[str, Any]:
    evidence = result.get("evidence")
    selected = evidence if isinstance(evidence, list) else []
    diagnostic = {}
    factual = result.get("factual_result")
    if isinstance(factual, Mapping):
        raw = factual.get("diagnostic_checks")
        if isinstance(raw, Mapping):
            diagnostic = raw
    label = training_example_label(evidence_rows=selected, diagnostic_checks=diagnostic)
    value = {
        "schema": TRAINING_SCHEMA,
        "example_id": f"retrieval-{result['case_id']}",
        "source_case_id": result["case_id"],
        "scenario_family_id": result["scenario_family_id"],
        "input": result["question"],
        "behaviour_target": "retrieve_exact_primary_passages_or_hold",
        "selected_evidence": [
            {
                "source_version_id": row["source_version_id"],
                "chunk_id": row["chunk_id"],
                "evidence_span_sha256": row["evidence_span_sha256"],
            }
            for row in selected
        ],
        "label": label["label"],
        "negative_target": label["negative_target"],
        "eligible_for_prompt_and_retrieval_tuning": label["eligible_for_prompt_and_retrieval_tuning"],
        "eligible_for_weight_training": False,
        "weight_training_ineligibility_reason": "The answer is not qualified legal gold.",
    }
    return _sealed(value)


UNSEEN_BLUEPRINTS: tuple[dict[str, Any], ...] = (
    {
        "topic_id": "contract-law",
        "scenario_family_id": "unseen-consumer-cancellation",
        "prompt": "I ordered a made-to-measure sofa online, but the trader began work before giving me cancellation information. Can I cancel and recover my deposit?",
        "issue_tags": ["consumer", "cancellation", "deposit", "made-to-measure"],
        "documents": ["Order Confirmation", "Terms", "Cancellation Information", "Payment Record"],
        "questions": [
            "When did you order and when did work begin?",
            "What did the trader say about cancellation and custom goods?",
        ],
        "safe": "Preserve the order, terms and messages; do not assume that every online order has the same cancellation right.",
    },
    {
        "topic_id": "commercial-law",
        "scenario_family_id": "unseen-defective-marketplace-goods",
        "prompt": "I bought a refurbished laptop from a business seller on an online marketplace. It failed after six weeks and the seller says the platform rules exclude refunds. What can I ask for?",
        "issue_tags": ["consumer", "sale-of-goods", "repair", "rejection"],
        "documents": ["Listing", "Invoice", "Platform Terms", "Repair Report", "Messages"],
        "questions": [
            "Was the seller acting as a business?",
            "What fault occurred and when did you report it?",
        ],
        "safe": "Keep the laptop, listing and fault evidence, and notify both seller and platform in writing without accepting an unsupported waiver.",
    },
    {
        "topic_id": "administrative-law",
        "scenario_family_id": "unseen-council-housing-review",
        "prompt": "The council placed me in temporary accommodation and then ended it after relying on facts I was never shown. Can I ask for an urgent review?",
        "issue_tags": ["judicial-review", "housing", "procedural-fairness", "urgent"],
        "documents": ["Decision Letter", "Housing File", "Review Notice", "Emails"],
        "questions": [
            "What statutory review or appeal does the letter mention?",
            "When must you leave the accommodation?",
        ],
        "safe": "Preserve the decision and seek urgent housing-law help because review and court deadlines may be short.",
    },
    {
        "topic_id": "ai-and-data-protection",
        "scenario_family_id": "unseen-employer-ai-score",
        "prompt": "My employer used an AI risk score to suspend me but will not explain the data or let me correct it. Can I obtain the information and challenge the decision?",
        "issue_tags": ["automated-decision", "employment-ai", "accuracy", "profiling"],
        "documents": ["Suspension Letter", "Privacy Notice", "Access Request", "Policy", "Emails"],
        "questions": [
            "Was the decision made solely by the system?",
            "What personal data and outcome were communicated?",
        ],
        "safe": "Request the decision record and personal-data information promptly and preserve evidence of any deadline or loss.",
    },
    {
        "topic_id": "business-and-company-law",
        "scenario_family_id": "unseen-director-company-card",
        "prompt": "A director used the company card for personal expenses and says the other director informally agreed. What records should the company secure before deciding what to do?",
        "issue_tags": ["director-duties", "misuse-assets", "authority"],
        "documents": ["Bank Statements", "Receipts", "Board Minutes", "Expense Policy", "Messages"],
        "questions": [
            "What payments were personal and how were they recorded?",
            "Was any approval validly given and documented?",
        ],
        "safe": "Secure the records and prevent further disputed spending without destroying access or making an accusation before the facts are checked.",
    },
    {
        "topic_id": "criminal-law",
        "scenario_family_id": "unseen-fraud-bank-message",
        "prompt": "Someone used my account details to send payment requests to my customers. The police want a voluntary interview because one payment reached my account. What should I do?",
        "issue_tags": ["fraud", "voluntary-interview", "legal-advice", "digital-evidence"],
        "documents": ["Police Contact", "Bank Records", "Device Logs", "Customer Messages"],
        "questions": [
            "Are you being interviewed as a suspect or witness?",
            "Who controlled the account and devices at the relevant times?",
        ],
        "safe": "Do not alter devices or messages and obtain criminal-law advice before a voluntary interview.",
    },
    {
        "topic_id": "land-law",
        "scenario_family_id": "unseen-home-sale-beneficial-share",
        "prompt": "I paid most of the deposit and mortgage on a home in my partner's sole name. We are separating and they plan to sell. Can I claim a share or stop the sale?",
        "issue_tags": ["beneficial-interest", "co-ownership", "sale", "urgent"],
        "documents": [
            "Title Register",
            "Purchase File",
            "Bank Statements",
            "Mortgage Records",
            "Messages",
        ],
        "questions": [
            "What was agreed about ownership when the home was bought?",
            "Has a sale been agreed and what contributions can you prove?",
        ],
        "safe": "Obtain the title and purchase file urgently and preserve contribution and agreement evidence before any sale completes.",
    },
    {
        "topic_id": "law-and-medicine",
        "scenario_family_id": "unseen-parent-capacity-treatment",
        "prompt": "My father may lack capacity and the hospital proposes treatment that he previously said he would refuse. How should the decision be checked?",
        "issue_tags": ["capacity", "best-interests", "treatment-refusal", "urgent"],
        "documents": [
            "Clinical Records",
            "Capacity Assessment",
            "Advance Decision",
            "Power of Attorney",
            "Care Plan",
        ],
        "questions": [
            "Is there a valid advance decision or health and welfare attorney?",
            "What capacity assessment and treatment decision have been recorded?",
        ],
        "safe": "Ask for the recorded capacity and best-interests process immediately and seek urgent specialist help if treatment is imminent.",
    },
    {
        "topic_id": "pensions-law",
        "scenario_family_id": "unseen-workplace-pension-gap",
        "prompt": "My payslips show pension deductions but my scheme account has no contributions for four months. What should I compare and who should I contact?",
        "issue_tags": ["auto-enrolment", "missing-contributions"],
        "documents": ["Payslips", "Scheme Statements", "Employment Contract", "Employer Messages"],
        "questions": [
            "Which pay periods and contribution rates are missing?",
            "What have the employer and scheme administrator said?",
        ],
        "safe": "Compare payslips with the scheme record and complain in writing to the employer and scheme without assuming the cause.",
    },
    {
        "topic_id": "private-international-law",
        "scenario_family_id": "unseen-foreign-online-contract",
        "prompt": "I live in England and bought an expensive service from a French website whose terms select French courts. The service failed. Must I sue in France?",
        "issue_tags": ["consumer-contract", "jurisdiction", "choice-of-law", "france"],
        "documents": ["Contract", "Website Terms", "Invoice", "Communications", "Service Evidence"],
        "questions": [
            "Was the purchase mainly for personal use?",
            "How did the trader direct its activity to England?",
        ],
        "safe": "Preserve the version of the website terms and do not assume the court clause is conclusive before the consumer and post-Brexit rules are checked.",
    },
    {
        "topic_id": "tort-law",
        "scenario_family_id": "unseen-rental-stair-injury",
        "prompt": "I fell on a broken communal stair in my rented building after reporting it twice. Who may be responsible and what evidence should I keep?",
        "issue_tags": ["occupiers-liability", "landlord", "negligence", "property-damage"],
        "documents": [
            "Tenancy",
            "Repair Reports",
            "Photographs",
            "Medical Records",
            "Witness Details",
        ],
        "questions": [
            "Who controlled and maintained the communal stair?",
            "When were defects reported and when did the accident occur?",
        ],
        "safe": "Photograph the defect, preserve repair reports and obtain medical evidence without carrying out a repair that destroys proof unless safety requires it.",
    },
    {
        "topic_id": "trusts-law",
        "scenario_family_id": "unseen-trustee-self-sale",
        "prompt": "A trustee sold trust property to a company they secretly own at a low price. What can beneficiaries ask the court to do?",
        "issue_tags": ["breach-of-trust", "self-dealing", "conflict", "account-of-profits"],
        "documents": [
            "Trust Instrument",
            "Sale Contract",
            "Valuation",
            "Company Records",
            "Trustee Minutes",
        ],
        "questions": [
            "What interest does the trustee have in the buyer?",
            "What valuation and approval process was used?",
        ],
        "safe": "Secure the trust, sale and ownership records and seek urgent advice before assets or proceeds are moved.",
    },
    {
        "topic_id": "wills-and-estates",
        "scenario_family_id": "unseen-handwritten-will",
        "prompt": "My mother left a handwritten document signed at home, but only one neighbour remembers seeing it signed. Can it operate as her will?",
        "issue_tags": ["formalities", "two-witnesses", "evidence-preservation"],
        "documents": [
            "Original Document",
            "Prior Wills",
            "Witness Details",
            "Medical Records",
            "Messages",
        ],
        "questions": [
            "Who was present at signing and did two witnesses sign?",
            "Are there earlier wills or later alterations?",
        ],
        "safe": "Protect the original without writing on it and obtain witness accounts before memories or evidence are lost.",
    },
    {
        "topic_id": "competition-law",
        "scenario_family_id": "unseen-platform-price-rule",
        "prompt": "A delivery platform requires restaurants not to offer lower prices on their own websites. Could that rule create a competition problem?",
        "issue_tags": ["price-parity", "platform", "vertical-agreement", "market-definition"],
        "documents": ["Platform Agreement", "Price Policy", "Market Information", "Communications"],
        "questions": [
            "What products, area and competing channels are affected?",
            "How large is the platform and how is the clause enforced?",
        ],
        "safe": "Preserve the exact clause and market evidence; do not coordinate prices or contact competitors about a common response.",
    },
    {
        "topic_id": "international-commercial-mediation",
        "scenario_family_id": "unseen-cross-border-mediation-signature",
        "prompt": "We settled an English-Singapore supply dispute in mediation and signed electronically. The other side now denies that its negotiator had authority. Can the settlement be enforced?",
        "issue_tags": [
            "cross-border-settlement",
            "electronic-signature",
            "settlement-authority",
            "enforcement",
        ],
        "documents": [
            "Settlement",
            "Signature Record",
            "Mediation Agreement",
            "Authority Evidence",
            "Governing-Law Clause",
        ],
        "questions": [
            "What authority did the negotiator have or appear to have?",
            "Which law and enforcement route does the settlement select?",
        ],
        "safe": "Preserve the electronic signature and authority record and avoid assuming treaty enforcement until status and scope are checked.",
    },
)


def _expand_unseen(base: Sequence[Mapping[str, Any]], count: int = 60) -> list[dict[str, Any]]:
    modifiers = (
        ("The other side says its standard terms remove all liability.", "terms"),
        ("I first complained by email and received no reply.", "complaint"),
        ("A deadline in the latest letter may expire soon.", "deadline"),
        ("Some records are held only in an online account.", "records"),
    )
    rows: list[dict[str, Any]] = []
    ordinal = 0
    for cycle, (suffix, suffix_id) in enumerate(modifiers, start=1):
        for item in base:
            ordinal += 1
            if ordinal > count:
                break
            prompt = str(item["prompt"])
            if cycle > 1:
                prompt = f"{prompt} {suffix}"
            value = {
                "schema": UNSEEN_SCHEMA,
                "case_id": f"ge-unseen-{ordinal:03d}",
                "case_version_id": f"ge-unseen-{ordinal:03d}:v1",
                "ordinal": ordinal,
                "topic_id": item["topic_id"],
                "scenario_family_id": f"{item['scenario_family_id']}:{suffix_id}",
                "prompt": prompt,
                "issue_tags": list(item["issue_tags"]),
                "primary_jurisdiction": "ENGLAND_AND_WALES",
                "legal_currentness_cutoff": "2026-09-01",
                "required_document_categories": list(item["documents"]),
                "proposed_clarification_criteria": {
                    "indispensable_facts": list(item["questions"]),
                    "safe_first_response": item["safe"],
                },
                "generated_after_training_seal": True,
                "usage_role": "EXPOSED_DIAGNOSTIC_REGRESSION",
                "fresh_unseen": False,
                "eligible_for_training": False,
                "eligible_for_promotion": False,
            }
            rows.append(_sealed(value))
        if ordinal >= count:
            break
    if len(rows) != count:
        raise RuntimeError("diagnostic unseen set count differs")
    return rows


def _jaccard(left: str, right: str) -> float:
    a = set(_tokens(left))
    b = set(_tokens(right))
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _leakage_audit(
    visible: Sequence[Mapping[str, Any]], unseen: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    maximum = 0.0
    pair: tuple[str, str] | None = None
    violations: list[dict[str, Any]] = []
    for candidate in unseen:
        for source in visible:
            score = _jaccard(str(candidate["prompt"]), str(source["prompt"]))
            if score > maximum:
                maximum = score
                pair = (str(candidate["case_id"]), str(source["question_id"]))
            if score >= 0.72:
                violations.append(
                    {
                        "unseen_case_id": candidate["case_id"],
                        "visible_case_id": source["question_id"],
                        "token_jaccard": round(score, 4),
                    }
                )
    return _sealed(
        {
            "schema": "legalbot.ge-diagnostic-unseen-leakage-audit.v1",
            "visible_count": len(visible),
            "unseen_count": len(unseen),
            "threshold": 0.72,
            "maximum_similarity": round(maximum, 4),
            "maximum_pair": list(pair) if pair else None,
            "violations": violations,
            "passed": not violations,
        }
    )


def _summary(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    factual = Counter(str(row["factual_result"]["outcome"]) for row in results)
    quality = Counter(str(row["quality_70_plus"]["outcome"]) for row in results)
    topics: dict[str, dict[str, int]] = {}
    for row in results:
        topic = str(row["topic_id"])
        bucket = topics.setdefault(
            topic, {"total": 0, "factual_pass": 0, "factual_hold": 0, "evidence_present": 0}
        )
        bucket["total"] += 1
        if row["factual_result"]["outcome"] == "FACTUAL_PASS":
            bucket["factual_pass"] += 1
        else:
            bucket["factual_hold"] += 1
        if row.get("evidence"):
            bucket["evidence_present"] += 1
    return {
        "total": len(results),
        "factual": dict(sorted(factual.items())),
        "quality": dict(sorted(quality.items())),
        "evidence_present": sum(bool(row.get("evidence")) for row in results),
        "claim_support_pass": sum(
            str((row.get("factual_result") or {}).get("checks", {}).get("claim_evidence_support"))
            == "PASS"
            for row in results
        ),
        "topics": topics,
    }


def run(
    output: Path,
    *,
    diagnostic_probe: str = "omit",
    owner_instruction: Mapping[str, Any] | None = None,
    locator_overlay_path: Path | None = None,
) -> dict[str, Any]:
    if diagnostic_probe not in {"omit", "exposed-regression"}:
        raise ValueError("diagnostic_probe must be omit or exposed-regression")
    output = output.resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"create-only run root already exists: {output}")
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, stat.S_IRWXU)
    started = datetime.now(UTC)

    visible, visible_manifest = _load_visible()
    source_manifest = _load_json(SOURCE_MANIFEST)
    sources = _source_lookup(source_manifest)
    overlay_path = locator_overlay_path or (
        DEFAULT_LOCATOR_OVERLAY if DEFAULT_LOCATOR_OVERLAY.is_file() else None
    )
    overlay = load_locator_gold_overlay(overlay_path)
    available_titles = {str(value.get("title") or "") for value in sources.values()}
    fts_path = output / "retrieval/approved-sources-fts.sqlite3"
    _create_fts(fts_path, sources)

    connection = sqlite3.connect(f"file:{fts_path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    unseen: list[dict[str, Any]] = []
    unseen_results: list[dict[str, Any]] = []
    leakage: dict[str, Any] | None = None
    try:
        visible_results = [
            _result_for_case(
                case=case,
                evidence=_retrieve(
                    connection, case=case, sources=sources, overlay=overlay
                ),
                source_manifest_sha256=str(source_manifest["manifest_sha256"]),
                ordinal=index,
                lane="visible",
                overlay=overlay,
                available_titles=available_titles,
            )
            for index, case in enumerate(visible, start=1)
        ]
        _write_jsonl(output / "visible/RESULTS.jsonl", visible_results)
        training = [_training_row(row) for row in visible_results]
        _write_jsonl(output / "training/RETRIEVAL-TRAINING-CANDIDATES.jsonl", training)
        training_manifest = _sealed(
            {
                "schema": "legalbot.ge-retrieval-training-manifest.v1",
                "example_count": len(training),
                "source_visible_result_sha256": _sha256_file(output / "visible/RESULTS.jsonl"),
                "training_file_sha256": _sha256_file(
                    output / "training/RETRIEVAL-TRAINING-CANDIDATES.jsonl"
                ),
                "training_kind": "deterministic_prompt_and_retrieval_planner_tuning",
                "answer_weight_training_executed": False,
                "answer_weight_training_ineligibility_reason": (
                    "No candidate answer has qualified legal-gold/currentness approval."
                ),
            }
        )
        _write_json(output / "training/TRAINING-MANIFEST.json", training_manifest)

        if diagnostic_probe == "exposed-regression":
            unseen = _expand_unseen(UNSEEN_BLUEPRINTS, count=60)
            leakage = _leakage_audit(visible, unseen)
            if leakage["passed"] is not True:
                raise RuntimeError("diagnostic unseen leakage audit failed")
            _write_jsonl(output / "unseen/PRIVATE-QUESTIONS.jsonl", unseen)
            _write_json(output / "unseen/LEAKAGE-AUDIT.json", leakage)
            _write_json(output / "unseen/FAMILY-SUMMARY.json", unseen_family_summary(unseen))
            unseen_results = [
                _result_for_case(
                    case=case,
                    evidence=_retrieve(
                    connection, case=case, sources=sources, overlay=overlay
                ),
                    source_manifest_sha256=str(source_manifest["manifest_sha256"]),
                    ordinal=index,
                    lane="diagnostic_unseen",
                    overlay=overlay,
                    available_titles=available_titles,
                )
                for index, case in enumerate(unseen, start=1)
            ]
            _write_jsonl(output / "unseen/RESULTS.jsonl", unseen_results)
    finally:
        connection.close()

    completed = datetime.now(UTC)
    if owner_instruction is None:
        owner_instruction = {
            "schema": "legalbot.owner-session-instruction-record.v1",
            "recorded_at": started.isoformat(),
            "instruction_summary": (
                "Owner adopted the 67-locator evaluation-gold resolution r2 and "
                "authorized visible diagnostic 331 r2. Locator APPROVE is evaluation "
                "gold only. Case-level holds do not set global progress false. This "
                "does not set qualified legal review, answer gold, runtime admission, "
                "full-current-law eligibility, answer-weight training, sealed unseen, "
                "promotion or live."
            ),
            "evaluation_state": True,
            "authorized": [
                "visible_331_diagnostic_r2",
                "locator_evaluation_gold_from_resolved_r2",
                "factual_first_evaluation_gate",
                "evaluator_retrieval_non_weight_planner_repairs",
                "case_scoped_progress_not_global_stall",
            ],
            "not_authorized_or_not_supplied": [
                "answer_weight_training",
                "qualified_england_and_wales_legal_reviewer_identity",
                "legal_gold",
                "runtime_admission_of_staging_sources",
                "full_current_law_eligible",
                "sealed_validation_private_root",
                "fresh_unseen_or_private_306_disclosure",
                "promotion",
                "live_activation",
                "git_mutation",
                "deletion",
            ],
            "signature_status": "session_instruction_not_cryptographic_signature",
        }
    owner_instruction_record = _sealed(dict(owner_instruction))
    _write_json(output / "OWNER-INSTRUCTION.json", owner_instruction_record)

    locator_hold = 0
    locator_pending = 0
    locator_reject = 0
    if overlay is not None:
        locator_hold = sum(item.owner_decision == "HOLD" for item in overlay.receipts)
        locator_pending = sum(item.owner_decision == "PENDING" for item in overlay.receipts)
        locator_reject = sum(item.owner_decision == "REJECT" for item in overlay.receipts)
    progress = phase2_progress(
        case_results=visible_results,
        locator_hold_count=locator_hold,
        locator_pending_count=locator_pending,
        locator_reject_count=locator_reject,
    )
    _write_json(output / "PROGRESS-AND-BLOCKER-LEDGER.json", _sealed(progress))

    artifacts: list[dict[str, Any]] = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "RUN-MANIFEST.json":
            artifacts.append(
                {
                    "path": path.relative_to(output).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }
            )
    if diagnostic_probe == "omit":
        unseen_custody = {
            "kind": "OMITTED_EXPOSED_DIAGNOSTIC_REGRESSION",
            "case_count": 0,
            "historical_exposed_case_count": 60,
            "historical_exposed_run_id": "LegalBot-GE-2026-09-01-improvement-training-unseen-r3",
            "fresh_unseen": False,
            "sealed_validation_executed": False,
            "sealed_validation_ineligibility_reason": (
                "The previous 60 diagnostic cases are exposed regression material. "
                "The official 306 private bank remains sealed."
            ),
        }
        unseen_summary: dict[str, Any] = {
            "total": 0,
            "omitted": True,
            "reason": "diagnostic probe omitted; do not mint a fresh unseen set",
        }
    else:
        unseen_custody = {
            "kind": "EXPOSED_DIAGNOSTIC_REGRESSION",
            "case_count": len(unseen),
            "family_summary": unseen_family_summary(unseen),
            "leakage_audit_passed": None if leakage is None else leakage["passed"],
            "fresh_unseen": False,
            "sealed_validation_executed": False,
            "sealed_validation_ineligibility_reason": (
                "These 60 cases are exposed diagnostic/regression material, not sealed Validation."
            ),
        }
        unseen_summary = _summary(unseen_results)
        unseen_summary["family_summary"] = unseen_family_summary(unseen)
    manifest = _sealed(
        {
            "schema": SCHEMA,
            "run_id": output.name,
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "visible_pack_manifest_sha256": str(visible_manifest.get("content_sha256") or ""),
            "source_manifest_sha256": str(source_manifest["manifest_sha256"]),
            "source_count": len(sources),
            "visible_summary": _summary(visible_results),
            "training_summary": {
                "retrieval_training_examples": len(training),
                "prompt_and_retrieval_tuning_completed": True,
                "answer_weight_training_completed": False,
                "answer_weight_training_ineligible": True,
            },
            "unseen_summary": unseen_summary,
            "unseen_custody": unseen_custody,
            "diagnostic_probe": diagnostic_probe,
            "evaluation_state": True,
            "visible_331_rerun_authorized": True,
            "locator_overlay_path": str(overlay_path) if overlay_path else None,
            "locator_overlay_signed": bool(overlay and overlay.owner_pack_signed),
            "locator_evaluation_gold": True,
            "answer_legal_gold": False,
            "progress": {
                "overall_progress": progress["overall_progress"],
                "overall_state": progress["overall_state"],
                "held_or_fail_closed_cases": progress["held_or_fail_closed_cases"],
            },
            "staged_source_count": max(0, len(sources) - 85),
            "artifacts": artifacts,
            "non_authorizing": {
                "qualified_legal_review": False,
                "legal_gold": False,
                "admitted": False,
                "full_current_law_eligible": False,
                "answer_weight_training": False,
                "sealed_unseen": False,
                "promotion": False,
                "live": False,
                "git_mutation": False,
                "deletion": False,
            },
        }
    )
    _write_json(output / "RUN-MANIFEST.json", manifest)
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--diagnostic-probe",
        choices=("omit", "exposed-regression"),
        default="omit",
        help="Do not mint a fresh unseen set. Omit by default; reuse the exposed 60 only as labelled regression.",
    )
    parser.add_argument(
        "--locator-overlay",
        type=Path,
        default=None,
        help="Optional per-locator gold overlay. Unsigned drafts are a no-op.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = run(
        args.output,
        diagnostic_probe=args.diagnostic_probe,
        locator_overlay_path=args.locator_overlay,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
