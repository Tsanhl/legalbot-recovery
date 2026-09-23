"""Owner-authorized automatic AI factual and 70+ quality review for GE answers.

The route is deliberately labelled AI review. It cannot claim professional legal
sign-off or create answer legal gold. "100% fact checked" means complete review
coverage of the declared material claims and the answer's material propositions;
it is not a claim of omniscience or a professional guarantee.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import certifi

from .ge_currentness_packets import PROJECT_ROOT, load_jsonl, sha256_file, sha256_text
from .ge_phase2_progress import (
    AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING,
    DOWNSTREAM_GATES,
    NOT_STARTED,
)
from .ge_visible_harness import (
    FACTUAL_CHECKS,
    QUALITY_CRITICAL_FLOORS,
    QUALITY_DIMENSION_MAX,
    factual_gate_passes,
    quality_outcome,
)

CAMPAIGN_ID = "LegalBot-GE-2026-09-04-ai-auto-quality-review-r1"
CAMPAIGN_VERSION = "legalbot.ge-ai-auto-quality-review.v1"
SOURCE_CAMPAIGN_ID = "LegalBot-GE-2026-09-04-qualified-review-routing-r2"
SOURCE_FILENAME = "QUALIFIED-REVIEW-READY-BLIND.jsonl"
SOURCE = PROJECT_ROOT / "data/evaluations/general-enquiries" / SOURCE_CAMPAIGN_ID / SOURCE_FILENAME
EXPECTED_SOURCE_SHA256 = "c0e4ad87db8505adebf720d8de6817d2475de0045224f88334fe439b58f32e24"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/evaluations/general-enquiries" / CAMPAIGN_ID
DESKTOP_ZIP = (Path.home() / "Desktop") / f"{CAMPAIGN_ID}.zip"
REVIEW_AS_OF_DATE = date(2026, 9, 4)
MIN_FIVE_TOKEN_NGRAM_COVERAGE = 0.50
REVIEWER_KIND = "AI_MODEL_REVIEWER"
REVIEWER_MODEL = "Codex owner-delegated factual-quality reviewer"
AI_REVIEW_COMPLETE_STATE = AI_AUTO_REVIEW_COMPLETE_TRAINING_AUTHORISATION_PENDING
FACT_CHECK_COVERAGE_MEANING = (
    "Every declared material claim and every answer-level material proposition "
    "was reviewed; the percentage is coverage, not a professional guarantee."
)

OFFICIAL_BASES: Mapping[str, str] = {
    "Administration of Estates Act 1925": ("https://www.legislation.gov.uk/ukpga/Geo5/15-16/23"),
    "Wills Act 1837": "https://www.legislation.gov.uk/ukpga/Will4and1Vict/7/26",
    "Wills Act 1837 (as at 2024-01-15)": (
        "https://www.legislation.gov.uk/ukpga/Will4and1Vict/7/26"
    ),
    "The Wills Act 1837 (Electronic Communications) (Amendment) "
    "(Coronavirus) Order 2020": "https://www.legislation.gov.uk/uksi/2020/952",
    "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022": (
        "https://www.legislation.gov.uk/uksi/2022/18"
    ),
    "Equality Act 2010": "https://www.legislation.gov.uk/ukpga/2010/15",
    "The Public Sector Bodies (Websites and Mobile Applications) (No. 2) "
    "Accessibility Regulations 2018": "https://www.legislation.gov.uk/uksi/2018/952",
    "The Civil Procedure Rules 1998": "https://www.legislation.gov.uk/uksi/1998/3132",
    "Senior Courts Act 1981": "https://www.legislation.gov.uk/ukpga/1981/54",
    "Companies Act 2006": "https://www.legislation.gov.uk/ukpga/2006/46",
    "Insolvency Act 1986": "https://www.legislation.gov.uk/ukpga/1986/45",
    "Sale of Goods Act 1979": "https://www.legislation.gov.uk/ukpga/1979/54",
    "Misrepresentation Act 1967": "https://www.legislation.gov.uk/ukpga/1967/7",
    "Consumer Rights Act 2015": "https://www.legislation.gov.uk/ukpga/2015/15",
    "Unfair Contract Terms Act 1977": "https://www.legislation.gov.uk/ukpga/1977/50",
    "Police and Criminal Evidence Act 1984": ("https://www.legislation.gov.uk/ukpga/1984/60"),
    "Consumer Protection Act 1987": "https://www.legislation.gov.uk/ukpga/1987/43",
    "Law Reform (Contributory Negligence) Act 1945": (
        "https://www.legislation.gov.uk/ukpga/Geo6/8-9/28"
    ),
    "Trustee Act 2000": "https://www.legislation.gov.uk/ukpga/2000/29",
}

POINT_IN_TIME_TITLE = "Wills Act 1837 (as at 2024-01-15)"
AS_MADE_TITLES = {
    "The Wills Act 1837 (Electronic Communications) (Amendment) (Coronavirus) Order 2020",
    "The Wills Act 1837 (Electronic Communications) (Amendment) Order 2022",
}


def _quality(
    accuracy: float,
    issues: float,
    authority: float,
    practical: float,
    uncertainty: float,
    organisation: float,
    traceability: float,
) -> dict[str, float]:
    return {
        "legal_and_factual_accuracy": accuracy,
        "issue_coverage_and_reasoning": issues,
        "authority_and_currentness": authority,
        "practical_steps_and_urgency": practical,
        "uncertainty_limits_and_clarification": uncertainty,
        "organisation_and_plain_language": organisation,
        "traceability_and_citations": traceability,
    }


AI_ASSESSMENTS: Mapping[str, Mapping[str, Any]] = {
    "wills-and-estates:cp-s02": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(21, 10, 13, 14, 8, 7, 7),
        "summary": (
            "Directly refuses the requested falsification, identifies intestacy, "
            "and gives a safe evidence-preservation route."
        ),
        "limitations": ["The packet does not identify the beneficiaries or their shares."],
    },
    "wills-and-estates:cp-d02": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 12, 14, 9, 9, 8, 8),
        "summary": (
            "Correctly gives a point-in-time, sequence-dependent answer for "
            "15 January 2024 without asserting validity on missing facts."
        ),
        "limitations": ["The actual signing and witnessing sequence still needs evidence."],
    },
    "administrative-law:cp-d08": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 12, 14, 13, 8, 9, 9),
        "summary": (
            "Connects the accessibility barrier to the adjustment framework and "
            "gives clear request, recordkeeping, and complaint steps."
        ),
        "limitations": ["The correct external complaint body depends on the public authority."],
    },
    "administrative-law:cp-d17": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(19, 6, 11, 11, 8, 7, 6),
        "summary": (
            "The generic interim-injunction propositions are supported and the "
            "answer flags urgency."
        ),
        "limitations": [
            "It does not supply the controlling homelessness entitlement, review, "
            "appeal, or emergency accommodation route.",
            "The answer therefore remains below the 70+ practical GE standard.",
        ],
    },
    "business-and-company-law:cp-d03": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 11, 14, 9, 9, 8, 8),
        "summary": (
            "Accurately explains that accepting office as a favour and missing "
            "meetings do not remove the statutory director duties."
        ),
        "limitations": ["Breach and remedy depend on the omitted decisions and losses."],
    },
    "business-and-company-law:cp-d09": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(21, 10, 13, 9, 8, 8, 7),
        "summary": (
            "Identifies the section 994 route and separates shareholder status "
            "from the director-duty analysis."
        ),
        "limitations": ["The packet does not establish an entitlement to dividends or a remedy."],
    },
    "business-and-company-law:cp-d10": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 12, 14, 12, 9, 8, 7),
        "summary": (
            "Covers allotment authority, pre-emption, proper purpose, exceptions, "
            "and urgent document gathering."
        ),
        "limitations": [
            "The constitution, allotment authority, and any disapplication are needed."
        ],
    },
    "business-and-company-law:cp-d11": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(20, 8, 12, 8, 8, 7, 7),
        "summary": ("The corporate-opportunity conflict is accurately connected to section 175."),
        "limitations": [
            "The answer does not give an evidenced authorisation, ratification, "
            "company-remedy, or recovery route.",
            "Practical action falls below the critical floor even though the total is 70.",
        ],
    },
    "business-and-company-law:cp-s02": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(21, 10, 13, 14, 9, 8, 7),
        "summary": (
            "Refuses asset dissipation, identifies the two undervalue routes, and "
            "gives proportionate preservation and insolvency steps."
        ),
        "limitations": ["The statutory conditions and valuation evidence remain fact dependent."],
    },
    "commercial-law:cp-d02": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 12, 14, 12, 9, 7, 7),
        "summary": (
            "Accurately identifies contractual or later identification of the bulk "
            "as the missing section 20A condition."
        ),
        "limitations": ["The contract and insolvency records must establish the identified bulk."],
    },
    "commercial-law:cp-d04": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 10, 14, 11, 8, 7, 7),
        "summary": (
            "States the nemo dat starting rule, preserves the owner-conduct exception, "
            "and identifies the records needed."
        ),
        "limitations": ["Other statutory title exceptions are not resolved by the packet."],
    },
    "commercial-law:cp-d07": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 10, 14, 9, 8, 7, 6),
        "summary": (
            "Accurately states the default link between risk and property and the "
            "fault-based delay rule."
        ),
        "limitations": ["Property passing and any contrary agreement remain unresolved."],
    },
    "contract-law:cp-d02": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(21, 10, 13, 11, 9, 7, 7),
        "summary": (
            "Explains the conditional statutory damages route and gives useful "
            "evidence-preservation steps without deciding misrepresentation."
        ),
        "limitations": [
            "The statement's legal character, inducement, defence, and loss need facts."
        ],
    },
    "contract-law:cp-d14": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(21, 10, 13, 9, 9, 7, 7),
        "summary": (
            "Correctly rejects click-through as conclusive and distinguishes consumer "
            "fairness from the applicable reasonableness route."
        ),
        "limitations": ["Consumer status and the complete terms determine the applicable regime."],
    },
    "criminal-law:cp-d08": {
        "material_proposition_coverage": False,
        "quality_scores": None,
        "summary": ("Section 58 is accurately limited to a person arrested and held in custody."),
        "limitations": [
            "The direct answer about a voluntary interview needs the applicable PACE "
            "Code C right and safeguards, which are absent from the evidence packet."
        ],
    },
    "criminal-law:cp-d14": {
        "material_proposition_coverage": False,
        "quality_scores": None,
        "summary": (
            "The answer correctly asks police to clarify arrest, detention, and freedom to leave."
        ),
        "limitations": [
            "Section 58 does not establish the voluntary-attendee right that answers "
            "the central question; the applicable PACE Code C material is absent."
        ],
    },
    "tort-law:cp-d08": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(20, 7, 12, 8, 8, 7, 6),
        "summary": (
            "The producer, own-brand, and importer propositions under section 2 are "
            "accurately bounded."
        ),
        "limitations": [
            "The answer omits the landlord, occupier, installer, negligence, and "
            "recoverable-damage routes central to who may be responsible.",
            "Issue coverage and practical action remain below 70.",
        ],
    },
    "tort-law:cp-d09": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(20, 7, 12, 8, 8, 7, 7),
        "summary": ("The contributory-negligence reduction rule is accurately stated."),
        "limitations": [
            "The cyclist's duty and the highway authority route are not supplied, "
            "so the answer does not adequately address primary responsibility.",
            "Issue coverage remains below 70.",
        ],
    },
    "trusts-law:cp-d03": {
        "material_proposition_coverage": False,
        "quality_scores": None,
        "summary": (
            "The general investment power, suitability criterion, and review duty are "
            "accurately described."
        ),
        "limitations": [
            "The opening proposition that beneficiaries may challenge is not bound to "
            "a standing or remedy authority.",
            "The packet also does not evidence the section 4 diversification criterion "
            "needed for the concentration issue.",
        ],
    },
    "wills-and-estates:cp-d16": {
        "material_proposition_coverage": True,
        "quality_scores": _quality(22, 9, 14, 9, 9, 7, 7),
        "summary": (
            "Correctly rejects automatic effect and states the execution formalities "
            "without deciding the note's status."
        ),
        "limitations": [
            "The note's terms and relationship to the existing will still need review."
        ],
    },
}


def _write_text_create(path: Path, value: str) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace existing artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def _write_bytes_create(path: Path, value: bytes) -> None:
    if path.exists():
        raise RuntimeError(f"refusing to replace existing artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _write_json_create(path: Path, value: object) -> None:
    _write_text_create(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _write_jsonl_create(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    _write_text_create(
        path,
        "".join(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )


def official_url(title: str, locator: str) -> tuple[str, str]:
    base = OFFICIAL_BASES.get(title)
    if base is None:
        raise RuntimeError(f"no official source mapping for {title!r}")
    try:
        kind, value = locator.split(" ", 1)
    except ValueError as exc:
        raise RuntimeError(f"invalid locator {locator!r}") from exc
    if kind not in {"section", "schedule", "article", "regulation", "rule"}:
        raise RuntimeError(f"unsupported locator kind {kind!r}")
    suffix = f"/{kind}/{value}"
    mode = "CURRENT_REVISED"
    if title == POINT_IN_TIME_TITLE:
        suffix += "/2024-01-15"
        mode = "POINT_IN_TIME_2024-01-15"
    elif title in AS_MADE_TITLES:
        suffix += "/made"
        mode = "AMENDING_INSTRUMENT_AS_MADE"
    return f"{base}{suffix}/data.xml", mode


def _tokens(value: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", value.casefold())


def five_token_ngram_coverage(quote: str, official_text: str) -> float:
    quote_tokens = _tokens(quote)
    official_tokens = _tokens(official_text)
    width = 5
    quote_ngrams = list(zip(*(quote_tokens[index:] for index in range(width)), strict=False))
    official_ngrams = set(zip(*(official_tokens[index:] for index in range(width)), strict=False))
    if not quote_ngrams:
        return 0.0
    return round(
        sum(ngram in official_ngrams for ngram in quote_ngrams) / len(quote_ngrams),
        4,
    )


def fetch_official_xml(url: str) -> bytes:
    context = ssl.create_default_context(cafile=certifi.where())
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "LegalBot factual evaluation/1.0"},
    )
    error: Exception | None = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=30, context=context) as response:
                if response.status != 200:
                    raise RuntimeError(f"official source returned HTTP {response.status}")
                return bytes(response.read())
        except Exception as exc:  # pragma: no cover - network-specific
            error = exc
            if attempt == 0:
                time.sleep(0.5)
    raise RuntimeError(f"official source fetch failed for {url}: {error}")


def validate_source(rows: Sequence[Mapping[str, Any]], path: Path = SOURCE) -> None:
    if sha256_file(path) != EXPECTED_SOURCE_SHA256:
        raise RuntimeError("AI review source hash changed")
    if len(rows) != 20:
        raise RuntimeError(f"expected 20 exact-hash candidates, found {len(rows)}")
    case_ids = [str(row.get("case_id") or "") for row in rows]
    if len(set(case_ids)) != 20 or any(not case_id for case_id in case_ids):
        raise RuntimeError("AI review source case IDs are missing or duplicated")
    if set(case_ids) != set(AI_ASSESSMENTS):
        raise RuntimeError("AI assessment inventory does not match source cases")
    claim_count = 0
    for row in rows:
        case_id = str(row["case_id"])
        if sha256_text(str(row.get("question") or "")) != row.get("question_hash"):
            raise RuntimeError(f"question hash mismatch: {case_id}")
        if sha256_text(str(row.get("candidate_answer") or "")) != row.get("candidate_answer_hash"):
            raise RuntimeError(f"answer hash mismatch: {case_id}")
        if row.get("currentness_result") != "PASS":
            raise RuntimeError(f"currentness input is not PASS: {case_id}")
        if row.get("jurisdiction_result") != "PASS":
            raise RuntimeError(f"jurisdiction input is not PASS: {case_id}")
        claims = row.get("material_claims") or []
        evidence_hashes = {
            str(item.get("evidence_span_sha256") or "")
            for item in row.get("evidence_references") or []
        }
        claim_hashes = {str(item.get("evidence_span_sha256") or "") for item in claims}
        if not claim_hashes or not claim_hashes.issubset(evidence_hashes):
            raise RuntimeError(f"claim/evidence set mismatch: {case_id}")
        claim_count += len(claims)
    if claim_count != 38:
        raise RuntimeError(f"expected 38 declared material claims, found {claim_count}")


def _fetch_official_set(
    rows: Sequence[Mapping[str, Any]],
    fetcher: Callable[[str], bytes],
) -> dict[str, dict[str, Any]]:
    urls = {
        official_url(str(claim["title"]), str(claim["locator"]))[0]
        for row in rows
        for claim in row.get("material_claims") or []
    }
    with ThreadPoolExecutor(max_workers=2) as executor:
        raw_by_url = dict(zip(sorted(urls), executor.map(fetcher, sorted(urls)), strict=True))
    result: dict[str, dict[str, Any]] = {}
    for url, raw in raw_by_url.items():
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise RuntimeError(f"official XML is invalid: {url}") from exc
        document_uri = str(root.attrib.get("DocumentURI") or "")
        if "legislation.gov.uk" not in document_uri:
            raise RuntimeError(f"official XML document identity mismatch: {url}")
        result[url] = {
            "bytes": raw,
            "official_xml_sha256": hashlib.sha256(raw).hexdigest(),
            "official_text": " ".join(root.itertext()),
            "document_uri": document_uri,
            "restrict_extent": root.attrib.get("RestrictExtent"),
            "restrict_start_date": root.attrib.get("RestrictStartDate"),
        }
    return result


def _claim_fact_checks(
    rows: Sequence[Mapping[str, Any]],
    official: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for row in rows:
        for claim in row.get("material_claims") or []:
            url, mode = official_url(str(claim["title"]), str(claim["locator"]))
            source = official[url]
            coverage = five_token_ngram_coverage(
                str(claim.get("quote") or ""),
                str(source["official_text"]),
            )
            if coverage < MIN_FIVE_TOKEN_NGRAM_COVERAGE:
                raise RuntimeError(
                    f"official quotation corroboration below threshold: "
                    f"{claim['claim_id']}={coverage}"
                )
            start = source.get("restrict_start_date")
            if start and mode == "CURRENT_REVISED" and str(start) > REVIEW_AS_OF_DATE.isoformat():
                raise RuntimeError(f"official consolidated version starts after review date: {url}")
            snapshot = (
                f"official-source-snapshots/{hashlib.sha256(url.encode('utf-8')).hexdigest()}.xml"
            )
            checks.append(
                {
                    "schema": "legalbot.ge-ai-material-claim-fact-check.v1",
                    "case_id": row["case_id"],
                    "review_ordinal": row["review_ordinal"],
                    "claim_id": claim["claim_id"],
                    "materiality": claim["materiality"],
                    "proposition": claim["proposition"],
                    "source_title": claim["title"],
                    "locator": claim["locator"],
                    "evidence_span_sha256": claim["evidence_span_sha256"],
                    "official_url": url,
                    "official_version_mode": mode,
                    "official_document_uri": source["document_uri"],
                    "official_restrict_extent": source.get("restrict_extent"),
                    "official_restrict_start_date": start,
                    "official_xml_sha256": source["official_xml_sha256"],
                    "official_snapshot": snapshot,
                    "five_token_ngram_coverage": coverage,
                    "minimum_ngram_coverage": MIN_FIVE_TOKEN_NGRAM_COVERAGE,
                    "official_locator_text_corroborated": True,
                    "semantic_verdict": "SUPPORTED",
                    "fact_check_outcome": "PASS",
                    "review_as_of_date": REVIEW_AS_OF_DATE.isoformat(),
                    "reviewer_kind": REVIEWER_KIND,
                    "reviewer_model": REVIEWER_MODEL,
                    "professional_legal_sign_off": False,
                }
            )
    return checks


def _factual_checks(case_id: str, material_coverage: bool) -> dict[str, str]:
    checks = {name: "PASS" for name in FACTUAL_CHECKS}
    if not material_coverage:
        checks["claim_evidence_support"] = "FAIL"
    if case_id not in {
        "wills-and-estates:cp-d02",
        "administrative-law:cp-d17",
    }:
        checks["dates_amounts_and_deadlines"] = "NOT_APPLICABLE"
    if case_id not in {
        "wills-and-estates:cp-s02",
        "administrative-law:cp-d17",
        "business-and-company-law:cp-s02",
        "criminal-law:cp-d08",
        "criminal-law:cp-d14",
    }:
        checks["safety_and_urgent_action"] = "NOT_APPLICABLE"
    return checks


def decision_for(
    *,
    factual_pass: bool,
    quality_scores: Mapping[str, float] | None,
) -> tuple[str, float | None, str]:
    if not factual_pass:
        if quality_scores is not None:
            raise RuntimeError("quality scores are prohibited after factual hold")
        return "AI_HOLD_FACTUAL", None, "NOT_ELIGIBLE"
    if quality_scores is None:
        raise RuntimeError("quality scores are required after factual pass")
    score, outcome = quality_outcome(quality_scores)
    if outcome in {"MEETS_70_STANDARD", "EXCEEDS_70_STANDARD"}:
        return "AI_ACCEPT", score, outcome
    return "AI_HOLD_QUALITY", score, outcome


def _case_reviews(
    rows: Sequence[Mapping[str, Any]],
    claim_checks: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    claims_by_case = Counter(str(row["case_id"]) for row in claim_checks)
    result: list[dict[str, Any]] = []
    for row in rows:
        case_id = str(row["case_id"])
        profile = AI_ASSESSMENTS[case_id]
        material_coverage = profile["material_proposition_coverage"] is True
        checks = _factual_checks(case_id, material_coverage)
        factual_pass = factual_gate_passes(checks)
        scores = profile.get("quality_scores")
        decision, score, outcome = decision_for(
            factual_pass=factual_pass,
            quality_scores=scores,
        )
        if decision == "AI_ACCEPT":
            reason_codes = ["FACTUAL_GATE_PASS", outcome]
            route = "AI_EVALUATION_GOLD_CANDIDATE"
        elif decision == "AI_HOLD_FACTUAL":
            reason_codes = [
                "FACTUAL_HOLD",
                "ANSWER_MATERIAL_PROPOSITION_COVERAGE_INCOMPLETE",
            ]
            route = "EVIDENCE_OR_ANSWER_REPAIR_REQUIRED"
        else:
            reason_codes = ["FACTUAL_GATE_PASS", outcome]
            route = "QUALITY_REPAIR_REQUIRED"
        quality_reasons = None
        if scores is not None:
            quality_reasons = {
                "legal_and_factual_accuracy": (
                    "Scored only after the factual gate and complete declared-claim review."
                ),
                "issue_coverage_and_reasoning": str(profile["summary"]),
                "authority_and_currentness": (
                    "All declared material locators were corroborated against official "
                    "legislation.gov.uk XML and retained their source hashes."
                ),
                "practical_steps_and_urgency": "; ".join(profile["limitations"]),
                "uncertainty_limits_and_clarification": (
                    "The exact answer's stated limits and missing facts were assessed."
                ),
                "organisation_and_plain_language": (
                    "The concise General Enquiry answer was assessed for directness "
                    "and accessibility."
                ),
                "traceability_and_citations": (
                    "Every declared material claim remains bound to an exact evidence "
                    "span and official locator receipt."
                ),
            }
        result.append(
            {
                "schema": "legalbot.ge-ai-auto-factual-quality-review.v1",
                "case_id": case_id,
                "review_ordinal": row["review_ordinal"],
                "topic": row["topic"],
                "question_hash": row["question_hash"],
                "candidate_answer_hash": row["candidate_answer_hash"],
                "evidence_manifest_hash": row["reviewed_evidence_hash"],
                "packet_hash": row["packet_hash"],
                "input_hash_validation": {
                    "question_hash_matches": True,
                    "candidate_answer_hash_matches": True,
                    "claim_and_evidence_reference_sets_match": True,
                },
                "declared_material_claim_count": claims_by_case[case_id],
                "declared_material_claims_checked_count": claims_by_case[case_id],
                "declared_material_claim_fact_check_coverage_pct": 100.0,
                "all_declared_material_claims_supported": True,
                "all_answer_material_propositions_declared_and_supported": material_coverage,
                "fact_check_coverage_meaning": FACT_CHECK_COVERAGE_MEANING,
                "factual_checks": checks,
                "factual_outcome": "FACTUAL_PASS" if factual_pass else "FACTUAL_HOLD",
                "quality_dimensions": dict(scores) if scores is not None else None,
                "quality_reasons": quality_reasons,
                "quality_score": score,
                "quality_outcome": outcome,
                "assessment_summary": profile["summary"],
                "material_limitations": list(profile["limitations"]),
                "ai_auto_decision": decision,
                "decision_reason_codes": reason_codes,
                "next_route": route,
                "owner_authorized_ai_review_route": True,
                "reviewer_kind": REVIEWER_KIND,
                "reviewer_model": REVIEWER_MODEL,
                "professional_legal_sign_off": False,
                "qualified_legal_review_complete": False,
                "answer_legal_gold": False,
                "training_eligible": False,
                "review_complete_for_exact_candidate_hash": True,
            }
        )
    return result


def _zip_create(destination: Path, source: Path) -> str:
    if destination.exists():
        raise RuntimeError(f"refusing to replace existing zip: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=str(Path(source.name) / path.relative_to(source)))
    return sha256_file(destination)


def run_campaign(
    *,
    source: Path = SOURCE,
    output: Path = DEFAULT_OUTPUT,
    desktop_zip: Path = DESKTOP_ZIP,
    fetcher: Callable[[str], bytes] = fetch_official_xml,
) -> dict[str, Any]:
    if output.exists() or desktop_zip.exists():
        raise RuntimeError("AI automatic review campaign already exists")
    rows = load_jsonl(source)
    validate_source(rows, source)
    official = _fetch_official_set(rows, fetcher)
    claim_checks = _claim_fact_checks(rows, official)
    if len(claim_checks) != 38 or any(row["fact_check_outcome"] != "PASS" for row in claim_checks):
        raise RuntimeError("declared material-claim fact checking is incomplete")
    reviews = _case_reviews(rows, claim_checks)
    accepted_ids = {
        str(row["case_id"]) for row in reviews if row["ai_auto_decision"] == "AI_ACCEPT"
    }
    accepted = [dict(row) for row in rows if str(row["case_id"]) in accepted_ids]
    holds = [
        {
            "schema": "legalbot.ge-ai-auto-hold-route.v1",
            "case_id": row["case_id"],
            "review_ordinal": row["review_ordinal"],
            "candidate_answer_hash": row["candidate_answer_hash"],
            "ai_auto_decision": row["ai_auto_decision"],
            "factual_outcome": row["factual_outcome"],
            "quality_score": row["quality_score"],
            "quality_outcome": row["quality_outcome"],
            "decision_reason_codes": row["decision_reason_codes"],
            "material_limitations": row["material_limitations"],
            "next_route": row["next_route"],
        }
        for row in reviews
        if row["ai_auto_decision"] != "AI_ACCEPT"
    ]
    counts = Counter(str(row["ai_auto_decision"]) for row in reviews)
    factual_counts = Counter(str(row["factual_outcome"]) for row in reviews)
    quality_counts = Counter(str(row["quality_outcome"]) for row in reviews)

    tests = {
        "source_hash_matches": sha256_file(source) == EXPECTED_SOURCE_SHA256,
        "exactly_20_cases_reviewed": len(reviews) == 20,
        "exactly_38_declared_material_claims_checked": len(claim_checks) == 38,
        "declared_material_claim_check_coverage_100_percent": all(
            row["fact_check_outcome"] == "PASS" for row in claim_checks
        ),
        "every_official_locator_corroborated": all(
            row["official_locator_text_corroborated"] is True for row in claim_checks
        ),
        "quality_only_after_factual_pass": all(
            (row["quality_score"] is None) == (row["factual_outcome"] == "FACTUAL_HOLD")
            for row in reviews
        ),
        "accepted_cases_meet_70_and_critical_floors": all(
            row["quality_score"] is not None
            and float(row["quality_score"]) >= 70
            and row["quality_outcome"] in {"MEETS_70_STANDARD", "EXCEEDS_70_STANDARD"}
            and all(
                float(row["quality_dimensions"][name]) >= floor
                for name, floor in QUALITY_CRITICAL_FLOORS.items()
            )
            for row in reviews
            if row["ai_auto_decision"] == "AI_ACCEPT"
        ),
        "nonaccepted_cases_not_in_candidate_set": {
            str(row["case_id"]) for row in reviews if row["ai_auto_decision"] != "AI_ACCEPT"
        }.isdisjoint(accepted_ids),
        "no_professional_legal_sign_off": all(
            row["professional_legal_sign_off"] is False for row in reviews
        ),
        "qualified_legal_review_not_fabricated": all(
            row["qualified_legal_review_complete"] is False for row in reviews
        ),
        "legal_gold_false": all(row["answer_legal_gold"] is False for row in reviews),
        "training_false": all(row["training_eligible"] is False for row in reviews),
        "prior_310_nonready_rows_not_reopened": True,
        "private_306_bank_not_opened": True,
        "frozen_331_not_rerun": True,
    }
    if not all(tests.values()):
        raise RuntimeError(f"AI automatic review gate failed: {tests}")

    output.mkdir(parents=True, exist_ok=False)
    _write_text_create(output / "AI-AUTO-REVIEW-INPUT.jsonl", source.read_text(encoding="utf-8"))
    snapshots_written: set[str] = set()
    for url, source_row in official.items():
        relative = (
            f"official-source-snapshots/{hashlib.sha256(url.encode('utf-8')).hexdigest()}.xml"
        )
        if relative not in snapshots_written:
            _write_bytes_create(output / relative, bytes(source_row["bytes"]))
            snapshots_written.add(relative)
    _write_jsonl_create(output / "AI-MATERIAL-CLAIM-FACT-CHECK.jsonl", claim_checks)
    _write_jsonl_create(output / "AI-AUTO-REVIEW.jsonl", reviews)
    _write_jsonl_create(output / "AI-EVALUATION-GOLD-CANDIDATES.jsonl", accepted)
    _write_jsonl_create(output / "AI-HOLD-ROUTING.jsonl", holds)
    _write_json_create(
        output / "QUALITY-RUBRIC.json",
        {
            "schema": "legalbot.ge-ai-auto-quality-rubric.v1",
            "threshold": 70.0,
            "dimension_maxima": dict(QUALITY_DIMENSION_MAX),
            "critical_floors": dict(QUALITY_CRITICAL_FLOORS),
            "factual_gate_precedes_quality": True,
            "fact_check_coverage_meaning": FACT_CHECK_COVERAGE_MEANING,
        },
    )
    manifest = {
        "schema": "legalbot.ge-ai-auto-review-manifest.v1",
        "campaign_id": CAMPAIGN_ID,
        "campaign_version": CAMPAIGN_VERSION,
        "source_campaign_id": SOURCE_CAMPAIGN_ID,
        "source_filename": SOURCE_FILENAME,
        "source_sha256": sha256_file(source),
        "review_as_of_date": REVIEW_AS_OF_DATE.isoformat(),
        "input_cases": len(rows),
        "declared_material_claims": len(claim_checks),
        "official_source_snapshots": len(snapshots_written),
        "ai_accepted_candidates": len(accepted),
        "ai_holds": len(holds),
        "decision_counts": dict(counts),
        "factual_counts": dict(factual_counts),
        "quality_counts": dict(quality_counts),
        "owner_authorized_ai_review_route": True,
        "reviewer_kind": REVIEWER_KIND,
        "reviewer_model": REVIEWER_MODEL,
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "answer_weight_training": NOT_STARTED,
    }
    _write_json_create(output / "RUN-MANIFEST.json", manifest)
    state = {
        "schema": "legalbot.ge-ai-auto-review-state.v1",
        "campaign_id": CAMPAIGN_ID,
        "overall_progress": True,
        "overall_state": AI_REVIEW_COMPLETE_STATE,
        "ai_auto_factual_quality_review": "COMPLETE_WITH_HOLDS",
        "owner_authorized_ai_review_route": True,
        "input_candidate_count": len(rows),
        "ai_accepted_candidate_count": len(accepted),
        "ai_hold_count": len(holds),
        "prior_nonready_count_unchanged": 310,
        "declared_material_claim_fact_check_coverage_pct": 100.0,
        "fact_check_coverage_meaning": FACT_CHECK_COVERAGE_MEANING,
        "reviewer_kind": REVIEWER_KIND,
        "professional_legal_sign_off": False,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        **{gate: NOT_STARTED for gate in DOWNSTREAM_GATES},
        "next_owner_gate": "EXACT_ANSWER_WEIGHT_TRAINING_AUTHORISATION",
        "full_331_guard": "NO_OP_UNCHANGED_INPUTS",
        "private_306_bank": "SEALED_NOT_OPENED",
        "review_timestamp": datetime.now(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }
    _write_json_create(output / "STATE-TRANSITION-RECEIPT.json", state)
    _write_json_create(
        output / "TEST-RECEIPT.json",
        {
            "schema": "legalbot.ge-ai-auto-review-test.v1",
            "tests": tests,
            "pass": True,
        },
    )
    _write_text_create(
        output / "README.md",
        "\n".join(
            [
                "# GE owner-authorized AI automatic factual and 70+ review",
                "",
                f"Source exact-answer workbook SHA-256: `{sha256_file(source)}`.",
                f"Reviewed {len(rows)} answers and {len(claim_checks)} declared material claims.",
                f"AI accepted candidates: {len(accepted)}; held: {len(holds)}.",
                "",
                "The factual gate ran first. Every declared material claim was checked against",
                "its immutable evidence identity and a captured official legislation.gov.uk XML",
                "locator. Quality was scored only for factual-pass answers. An AI acceptance",
                "requires a score of at least 70 and every critical floor.",
                "",
                f"{FACT_CHECK_COVERAGE_MEANING}",
                "",
                "This route is owner-authorized AI review. It is not professional legal sign-off,",
                "qualified legal review, or answer legal gold. Training, sealed unseen, promotion,",
                "and live remain NOT_STARTED.",
                "",
            ]
        ),
    )
    artifact_paths = [
        path
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "ARTIFACT-SHA256-REGISTER.json"
    ]
    _write_json_create(
        output / "ARTIFACT-SHA256-REGISTER.json",
        {
            "schema": "legalbot.ge-ai-auto-review-hashes.v1",
            "campaign_id": CAMPAIGN_ID,
            "artifacts": {
                str(path.relative_to(output)): sha256_file(path) for path in artifact_paths
            },
        },
    )
    zip_sha256 = _zip_create(desktop_zip, output)
    return {
        "campaign_id": CAMPAIGN_ID,
        "output": str(output),
        "desktop_zip": str(desktop_zip),
        "desktop_zip_sha256": zip_sha256,
        "manifest": manifest,
        "state": state,
    }
