"""Build auditable currentness-review packets. Preparation only, not approval."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from app.contracts.schema_registry import ContractSchemaRegistry, canonical_json_bytes, seal_contract

from .ge_currentness_subrouter import classify_currentness_subreason
from .ge_hold_reason_router import CASE_174, CASE_312, route_results
from .ge_locator_gold_overlay import iso_date_from_prompt
from .ge_phase2_progress import DOWNSTREAM_GATES, NOT_STARTED, NO_OP_UNCHANGED_INPUTS

OWNER_CURRENTNESS_CUTOFF = "2026-08-28"
PACKET_SCHEMA = "legalbot.ge-currentness-review-packet.v1"
COUNT_RECONCILIATION_SCHEMA = "legalbot.ge-currentness-count-reconciliation.v1"
EXPECTED_FACTUAL_PASS = 42
EXPECTED_FACTUAL_HOLD = 289
EXPECTED_CURRENTNESS = 211
EXPECTED_JURISDICTION = 56
EXPECTED_LEFTOVER = 21
EXPECTED_FACT_DEPENDENT = 1
EXPECTED_TOTAL = 331
LEFTOVER_REASONS = frozenset({"CLAIM_NOT_SUPPORTED", "RETRIEVAL_NO_EVIDENCE"})
FORBIDDEN_CURRENTNESS_CONCLUSIONS = frozenset(
    {"CURRENT", "OWNER_APPROVED", "LEGAL_GOLD", "PASS"}
)
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LATEST_ACCEPTED_DELTA = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-03-mechanical-repair-delta-r1"
)
FROZEN_R1 = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r1"
)
FROZEN_R2 = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r2"
)
FROZEN_R3 = (
    PROJECT_ROOT
    / "data/evaluations/general-enquiries"
    / "LegalBot-GE-2026-09-02-visible-331-diagnostic-r3"
)
EXPECTED_R1_MANIFEST = "d43f2a47d3f0eff35785bfd37a193ba97267206816ac78cb25b9415715b78f9f"
EXPECTED_R2_MANIFEST = "d0ed806eee3ead78be77b5ca8eb150cbb7fd15f3eb9332637f230b38eef311c2"
EXPECTED_R2_RESULTS = "a3142fce995b7ae575864ae8411e9346d084306bf1197a4153326a8506a0908c"
EXPECTED_R3_MANIFEST = "80718e9ffaaf67aaabeee6f0a099d06365600f7c360ab86695dabfd68f0f592f"
EXPECTED_R3_RESULTS = "51eb7eda2f04b309b9c27ee4f9f4dd25ae57bc359f4df68acae4f5726ef851ef"
EXPECTED_DELTA_MANIFEST = "3eec7d56858d2102c9454daa3e6ffbf9a4580301f277dc064817926e62732fa2"
EXPECTED_DELTA_RESULTS = "78f345c58105f5b1187bb7c941292735575a11325f069f7e0b5e3cb2867c397a"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DAY_MONTH_YEAR = re.compile(
    r"\b(\d{1,2})\s+(January|February|March|April|May|June|July|"
    r"August|September|October|November|December)\s+(20\d{2})\b",
    re.IGNORECASE,
)
_ISO_DATE = re.compile(r"\b(20\d{2}-\d{2}-\d{2})\b")
_MONTHS = {
    "january": "01",
    "february": "02",
    "march": "03",
    "april": "04",
    "may": "05",
    "june": "06",
    "july": "07",
    "august": "08",
    "september": "09",
    "october": "10",
    "november": "11",
    "december": "12",
}
_JUDGMENT = re.compile(r"\s+v\s+|\[\d{4}]\s+(?:UKSC|UKHL|EWCA|EWHC|UKUT|UKFTT)", re.IGNORECASE)
_SI = re.compile(
    r"\b(?:Regulations \d{4}|SI \d{4}/\d+|S\.I\.|statutory instrument)\b",
    re.IGNORECASE,
)
_PROCEDURAL = re.compile(
    r"\b(?:civil procedure rules|practice direction|\bCPR\b|family procedure rules)\b",
    re.IGNORECASE,
)
_CONTRACTUAL = re.compile(
    r"\b(?:contractually incorporated|ICC Mediation|LCIA |UCP \d+|INCOTERMS?|ISDA |FIDIC )\b",
    re.IGNORECASE,
)
_TREATY = re.compile(r"\b(?:withdrawal agreement|treaty|convention)\b", re.IGNORECASE)
_ACT = re.compile(r"\bAct(?:\s+\d{4})?\b")
_GDPR = re.compile(r"\b(?:UK GDPR|GDPR)\b", re.IGNORECASE)
_PROSPECTIVE = re.compile(
    r"\b(?:prospective|not yet commenced|not yet in force|has not been brought into force)\b",
    re.IGNORECASE,
)
_COMMENCEMENT = re.compile(
    r"\b(?:commencement|coming into force|comes? into force)\b",
    re.IGNORECASE,
)
_TRANSITIONAL = re.compile(r"\b(?:transitional|savings provisions?)\b", re.IGNORECASE)
_REPEAL = re.compile(r"\b(?:repeal(?:ed|s)?|substituted|renumber(?:ed|ing)?)\b", re.IGNORECASE)

PILOT_PREFERRED_IDS = (
    "administrative-law:cp-d06",
    "contemporary-biolaw-and-regulation:cp-d10",
    "contract-law:cp-d06",
    "trusts-law:cp-d01",
    "ai-and-data-protection:cp-d01",
    "contemporary-biolaw-and-regulation:cp-d01",
    "administrative-law:cp-d02",
    "administrative-law:cp-d03",
    "commercial-law:cp-d10",
    "administrative-law:cp-d18",
    "land-law:cp-d05",
    "pensions-law:cp-d03",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def load_latest_delta_rows(project_root: Path = PROJECT_ROOT) -> list[dict[str, Any]]:
    path = (
        project_root
        / "data/evaluations/general-enquiries"
        / "LegalBot-GE-2026-09-03-mechanical-repair-delta-r1"
        / "visible"
        / "RESULTS.jsonl"
    )
    return load_jsonl(path)


def manifest_content_sha256(path: Path) -> str:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, Mapping) and raw.get("content_sha256"):
        return str(raw["content_sha256"])
    return sha256_file(path)


def frozen_baseline_hashes(project_root: Path = PROJECT_ROOT) -> dict[str, str]:
    r1 = project_root / FROZEN_R1.relative_to(PROJECT_ROOT)
    r2 = project_root / FROZEN_R2.relative_to(PROJECT_ROOT)
    r3 = project_root / FROZEN_R3.relative_to(PROJECT_ROOT)
    delta = project_root / LATEST_ACCEPTED_DELTA.relative_to(PROJECT_ROOT)
    return {
        "r1_manifest": manifest_content_sha256(r1 / "RUN-MANIFEST.json"),
        "r2_manifest": manifest_content_sha256(r2 / "RUN-MANIFEST.json"),
        "r2_results": sha256_file(r2 / "visible/RESULTS.jsonl"),
        "r3_manifest": manifest_content_sha256(r3 / "RUN-MANIFEST.json"),
        "r3_results": sha256_file(r3 / "visible/RESULTS.jsonl"),
        "delta_manifest": manifest_content_sha256(delta / "RUN-MANIFEST.json"),
        "delta_results": sha256_file(delta / "visible/RESULTS.jsonl"),
    }


def parse_calendar_date(value: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return None
    return parsed.date().isoformat()


def dates_in_prompt(prompt: str) -> list[str]:
    found: list[str] = []
    for match in _DAY_MONTH_YEAR.finditer(prompt or ""):
        day = int(match.group(1))
        month = _MONTHS[match.group(2).casefold()]
        found.append(f"{match.group(3)}-{month}-{day:02d}")
    for match in _ISO_DATE.finditer(prompt or ""):
        found.append(match.group(1))
    return found


def applicable_law_date_fields(
    question: str,
    *,
    owner_cutoff: str = OWNER_CURRENTNESS_CUTOFF,
) -> dict[str, str]:
    raw_dates = dates_in_prompt(question)
    parsed: list[str] = []
    invalid = False
    for item in raw_dates:
        calendar = parse_calendar_date(item)
        if calendar is None:
            invalid = True
        elif calendar not in parsed:
            parsed.append(calendar)
    if invalid or len(parsed) > 1:
        return {
            "applicable_law_date": "",
            "applicable_law_date_basis": "INVALID_OR_AMBIGUOUS",
            "applicable_law_date_status": "INVALID_OR_AMBIGUOUS",
        }
    if not parsed:
        iso = iso_date_from_prompt(question)
        calendar = parse_calendar_date(iso or "")
        if iso and calendar is None:
            return {
                "applicable_law_date": "",
                "applicable_law_date_basis": "INVALID_OR_AMBIGUOUS",
                "applicable_law_date_status": "INVALID_OR_AMBIGUOUS",
            }
        return {
            "applicable_law_date": owner_cutoff,
            "applicable_law_date_basis": "DEFAULT_OWNER_CUTOFF_NO_HISTORIC_DATE",
            "applicable_law_date_status": "DEFAULTED_TO_OWNER_CUTOFF",
        }
    date = parsed[0]
    if date == owner_cutoff:
        return {
            "applicable_law_date": date,
            "applicable_law_date_basis": "QUESTION_DATE_EQUALS_CUTOFF",
            "applicable_law_date_status": "PARSED",
        }
    return {
        "applicable_law_date": date,
        "applicable_law_date_basis": "QUESTION_AS_OF_DATE",
        "applicable_law_date_status": "PARSED",
    }


def classify_source_type(title: str) -> str:
    text = str(title or "")
    if _CONTRACTUAL.search(text):
        return "CONTRACTUAL_RULE"
    if _PROCEDURAL.search(text):
        return "PROCEDURAL_RULE"
    if _JUDGMENT.search(text):
        return "CASE_LAW"
    if _GDPR.search(text):
        return "ASSIMILATED_INSTRUMENT"
    if _TREATY.search(text):
        return "TREATY_OR_AGREEMENT"
    if _SI.search(text):
        return "SECONDARY_LEGISLATION"
    if _ACT.search(text):
        return "PRIMARY_LEGISLATION"
    if re.search(r"\bRules\b|\bscheme\b", text, re.IGNORECASE):
        return "PROCEDURAL_RULE"
    return "OTHER_INSTRUMENT"


def _evidence_rows(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = row.get("evidence") or []
    return [item for item in raw if isinstance(item, dict)]


def evidence_manifest(row: Mapping[str, Any]) -> list[dict[str, str]]:
    spans: list[dict[str, str]] = []
    for item in _evidence_rows(row):
        spans.append(
            {
                "source_version_id": str(item.get("source_version_id") or ""),
                "chunk_id": str(item.get("chunk_id") or ""),
                "locator": str(item.get("locator") or ""),
                "evidence_span_sha256": str(item.get("evidence_span_sha256") or ""),
                "quote": str(item.get("quote") or ""),
            }
        )
    return spans


def evidence_manifest_hash(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(evidence_manifest(row))).hexdigest()


def material_claims(row: Mapping[str, Any]) -> list[dict[str, str]]:
    claims: list[dict[str, str]] = []
    for tag in row.get("issue_tags") or []:
        text = str(tag or "").strip()
        if text:
            claims.append({"kind": "issue_tag", "text": text})
    planner = str(row.get("planner_output") or "").strip()
    if planner:
        claims.append({"kind": "planner_issue_summary", "text": planner[:4000]})
    factual = row.get("factual_result")
    if isinstance(factual, Mapping):
        reasons = factual.get("reasons")
        if isinstance(reasons, Mapping):
            currentness = str(reasons.get("requested_date_and_currentness") or "").strip()
            if currentness:
                claims.append({"kind": "currentness_reason", "text": currentness[:4000]})
    return claims


def _not_recorded(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else "not_recorded"


def build_locator_record(
    item: Mapping[str, Any],
    *,
    applicable_law_date: str,
    question: str,
) -> dict[str, Any]:
    title = str(item.get("title") or "")
    locator = str(item.get("locator") or "")
    quote = str(item.get("quote") or "")
    stored = str(item.get("stored_text") or "")
    blob = f"{title} {locator} {quote} {question}"
    source_type = classify_source_type(title)
    official = str(item.get("stable_identifier") or item.get("authority_identity_id") or "")
    reviewed = str(item.get("currentness_reviewed_as_of_date") or "")
    point_in_time = str(item.get("point_in_time_as_at") or "")
    effects = item.get("unapplied_effect_count")
    extent = str(item.get("provision_extent_status") or "unverified")
    prospective_text = bool(_PROSPECTIVE.search(blob))
    collected: list[str] = []
    if official:
        collected.append("official_identifier_present")
    if reviewed:
        collected.append(f"currentness_reviewed_as_of_date={reviewed}")
    if isinstance(effects, int):
        collected.append(f"unapplied_effect_count={effects}")
    collected.append(f"provision_extent_status={extent}")
    if point_in_time:
        collected.append(f"point_in_time_as_at={point_in_time}")
    if item.get("currentness_verified") is True:
        collected.append("currentness_verified=true_not_owner_approval")
    collected.append("retrieval_date_is_not_legal_currentness")
    if source_type == "CASE_LAW":
        collected.append("later_treatment_search_not_executed")
    amendments = (
        f"unapplied_effect_count={effects}; unclassified as to in-force versus prospective"
        if isinstance(effects, int)
        else "not_recorded"
    )
    prospective = (
        "text_flags_not_yet_in_force_or_prospective; not treated as in force"
        if prospective_text
        else "not_distinguished_from_unapplied_effects"
        if isinstance(effects, int)
        else "not_recorded"
    )
    commencement = (
        "mentioned_in_selected_text_not_verified"
        if _COMMENCEMENT.search(blob) or prospective_text
        else "not_recorded"
    )
    transitional = (
        "mentioned_in_selected_text_not_verified" if _TRANSITIONAL.search(blob) else "not_recorded"
    )
    repeal = "mentioned_in_selected_text_not_verified" if _REPEAL.search(blob) else "not_recorded"
    later_treatment = (
        "later_treatment_search_not_executed_in_this_packet"
        if source_type == "CASE_LAW"
        else "not_applicable_non_case_law"
    )
    unresolved = (
        "Owner must determine whether this locator is the correct applicable version "
        f"for relevant legal date {applicable_law_date or 'UNPARSED'}, including amendments, "
        "commencement, extent and authority status through 28 August 2026, without treating "
        "retrieval date or absent negative treatment as currentness."
    )
    return {
        "source_title": title,
        "source_type": source_type,
        "official_identifier": official,
        "canonical_url": str(item.get("canonical_url") or ""),
        "exact_locator": locator,
        "exact_supporting_passage": quote,
        "stored_text": stored,
        "source_byte_hash": "",
        "evidence_span_sha256": str(item.get("evidence_span_sha256") or ""),
        "source_version_id": str(item.get("source_version_id") or ""),
        "chunk_id": str(item.get("chunk_id") or ""),
        "retrieval_date": "not_recorded",
        "source_version_date": reviewed or point_in_time or "not_recorded",
        "relevant_legal_date": applicable_law_date or "not_recorded",
        "territorial_extent": extent or "unverified",
        "in_force_or_status_information": "not_recorded_do_not_infer_from_retrieval_date",
        "amendments_effective_by_relevant_date": amendments,
        "prospective_amendments": prospective,
        "prospective_amendment_treated_as_in_force": False,
        "commencement_information": commencement,
        "transitional_or_savings_provisions": transitional,
        "repeal_or_substitution_information": repeal,
        "later_treatment_or_appeal_status": later_treatment,
        "later_treatment_search_coverage": (
            "not_executed_in_this_packet" if source_type == "CASE_LAW" else "not_applicable"
        ),
        "later_treatment_search_date": "",
        "negative_treatment_found": False,
        "owner_status_decision": "NOT_STARTED",
        "authority_status": "UNRESOLVED",
        "unresolved_currentness_question": unresolved,
        "currentness_evidence_collected": collected,
        "owner_decision": "",
    }


def locator_missing_fields(record: Mapping[str, Any]) -> list[str]:
    missing: list[str] = []
    if not str(record.get("source_title") or "").strip():
        missing.append("source_title")
    if not str(record.get("official_identifier") or "").strip():
        missing.append("official_identifier")
    if not str(record.get("exact_locator") or "").strip():
        missing.append("exact_locator")
    if not str(record.get("exact_supporting_passage") or "").strip():
        missing.append("exact_supporting_passage")
    span = str(record.get("evidence_span_sha256") or "")
    if not _SHA256.fullmatch(span):
        missing.append("evidence_span_sha256")
    if not str(record.get("source_version_id") or "").strip():
        missing.append("source_version_id")
    if str(record.get("source_version_date") or "") in {"", "not_recorded"}:
        missing.append("source_version_date")
    return missing


def build_currentness_packet(
    row: Mapping[str, Any],
    *,
    routed: Mapping[str, Any] | None = None,
    owner_cutoff: str = OWNER_CURRENTNESS_CUTOFF,
) -> dict[str, Any]:
    routed_row = routed or next(
        (
            item
            for item in route_results([row])["holds"]
            if item["case_id"] == str(row.get("case_id") or "")
        ),
        {},
    )
    question = str(row.get("question") or row.get("prompt") or "")
    answer = str(row.get("user_facing_answer") or row.get("answer") or "")
    date_fields = applicable_law_date_fields(question, owner_cutoff=owner_cutoff)
    classified = classify_currentness_subreason(row)
    locators = [
        build_locator_record(
            item,
            applicable_law_date=date_fields["applicable_law_date"],
            question=question,
        )
        for item in _evidence_rows(row)
    ]
    missing: list[str] = []
    gaps: list[str] = []
    if date_fields["applicable_law_date_status"] == "INVALID_OR_AMBIGUOUS":
        missing.append("applicable_law_date")
    if not locators:
        missing.append("locators")
    for index, record in enumerate(locators):
        for field in locator_missing_fields(record):
            missing.append(f"locator[{index}].{field}")
        if str(record.get("territorial_extent") or "") != "verified":
            gaps.append(f"locator[{index}].territorial_extent_unverified")
        if record.get("authority_status") != "UNRESOLVED":
            raise RuntimeError("locator authority_status escaped UNRESOLVED")
        if record.get("prospective_amendment_treated_as_in_force") is not False:
            raise RuntimeError("prospective amendment was treated as in force")
        if str(record.get("authority_status") or "") in FORBIDDEN_CURRENTNESS_CONCLUSIONS:
            raise RuntimeError("locator concluded currentness")
        if record["source_type"] == "CASE_LAW" and record.get("negative_treatment_found") is False:
            gaps.append(f"locator[{index}].later_treatment_not_searched")
        if record["commencement_information"] == "not_recorded":
            gaps.append(f"locator[{index}].commencement_not_recorded")
        if record["transitional_or_savings_provisions"] == "not_recorded":
            gaps.append(f"locator[{index}].transitional_not_recorded")
        if str(record.get("retrieval_date") or "") in {"", "not_recorded"}:
            gaps.append(f"locator[{index}].retrieval_date_not_recorded_not_currentness")
    incomplete = bool(missing or not locators)
    packet_status = "INCOMPLETE" if incomplete else "READY_FOR_OWNER_CURRENTNESS_REVIEW"
    next_route = (
        "CURRENTNESS_PACKET_REPAIR" if incomplete else "DEFERRED_OWNER_CURRENTNESS_REVIEW"
    )
    subreasons = [str(classified.get("currentness_subreason") or "CONSOLIDATED_TEXT_DATE_UNVERIFIED")]
    for extra in classified.get("currentness_subreasons_additional") or []:
        if extra not in subreasons:
            subreasons.append(str(extra))
    packet = {
        "schema": PACKET_SCHEMA,
        "case_id": str(row.get("case_id") or ""),
        "topic": str(row.get("topic_id") or routed_row.get("topic") or ""),
        "subtopic": str(row.get("scenario_family_id") or routed_row.get("subtopic") or ""),
        "question": question,
        "candidate_answer": answer,
        "material_claims": material_claims(row),
        "factual_status": "FACTUAL_HOLD",
        "claim_support_status": "PASS",
        "hold_reason": "CURRENTNESS_UNRESOLVED",
        "currentness_subreason": subreasons[0],
        "currentness_subreasons": subreasons,
        "jurisdiction": str(
            row.get("primary_jurisdiction")
            or next((item.get("jurisdiction") for item in _evidence_rows(row) if item.get("jurisdiction")), "")
            or "England and Wales"
        ),
        "owner_currentness_cutoff": owner_cutoff,
        **date_fields,
        "packet_status": packet_status,
        "review_status": "NOT_STARTED",
        "currentness_status": "UNRESOLVED",
        "owner_decision": "",
        "owner_currentness_decision": "NOT_STARTED",
        "answer_hash": sha256_text(answer),
        "question_hash": sha256_text(question),
        "evidence_manifest_hash": evidence_manifest_hash(row),
        "locators": locators,
        "locator_count": len(locators),
        "missing_fields": sorted(set(missing)),
        "currentness_evidence_gaps": sorted(set(gaps)),
        "next_route": next_route,
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "admitted": False,
        "full_current_law_eligible": False,
        "answer_weight_training": NOT_STARTED,
        "sealed_unseen_execution": NOT_STARTED,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
    }
    sealed = seal_contract(packet, digest_field="packet_hash")
    if sealed["currentness_status"] != "UNRESOLVED":
        raise RuntimeError("packet preparation set currentness PASS")
    if sealed["owner_decision"] != "" or sealed["owner_currentness_decision"] != NOT_STARTED:
        raise RuntimeError("packet preparation filled an owner decision")
    if sealed["factual_status"] != "FACTUAL_HOLD":
        raise RuntimeError("packet preparation changed factual status")
    return sealed


def _clip(value: Any, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _apply_recovered_metadata(record: dict[str, Any], recovered: Mapping[str, str]) -> dict[str, Any]:
    updated = dict(record)
    collected = list(record.get("currentness_evidence_collected") or [])
    if recovered.get("source_version_date") and str(record.get("source_version_date") or "") in {
        "",
        "not_recorded",
    }:
        updated["source_version_date"] = _clip(recovered["source_version_date"], 40)
        origin = recovered.get("source_version_date_origin") or "official_or_stored_metadata"
        collected.append(_clip(f"source_version_date_recovered_from={origin}", 240))
    if recovered.get("restrict_extent"):
        collected.append(_clip(f"official_xml_restrict_extent={recovered['restrict_extent']}", 240))
        if str(updated.get("territorial_extent") or "") in {"", "unverified", "unknown"}:
            updated["territorial_extent"] = _clip(
                f"unverified; official_xml_restrict_extent={recovered['restrict_extent']}",
                200,
            )
    if recovered.get("restrict_start_date"):
        collected.append(
            _clip(f"official_xml_restrict_start_date={recovered['restrict_start_date']}", 240)
        )
        if updated.get("commencement_information") == "not_recorded":
            updated["commencement_information"] = _clip(
                f"official_xml_restrict_start_date={recovered['restrict_start_date']}; not_treated_as_in_force",
                400,
            )
    if recovered.get("commencement_markup_present") == "true":
        collected.append("official_xml_mentions_commencement")
    if recovered.get("transitional_markup_present") == "true":
        collected.append("official_xml_mentions_transitional_or_savings")
        if updated.get("transitional_or_savings_provisions") == "not_recorded":
            updated["transitional_or_savings_provisions"] = (
                "mentioned_in_official_xml_not_verified"
            )
    if recovered.get("unapplied_effect_markup_count"):
        collected.append(
            f"official_xml_unapplied_effect_markup_count={recovered['unapplied_effect_markup_count']}"
        )
        if updated.get("amendments_effective_by_relevant_date") == "not_recorded":
            updated["amendments_effective_by_relevant_date"] = (
                f"official_xml_unapplied_effect_markup_count={recovered['unapplied_effect_markup_count']}; unclassified"
            )
    if recovered.get("prospective_true_count") and recovered["prospective_true_count"] not in {"", "0"}:
        updated["prospective_amendments"] = (
            f"official_xml_prospective_true_count={recovered['prospective_true_count']}; not treated as in force"
        )
        updated["prospective_amendment_treated_as_in_force"] = False
    if recovered.get("judgment_date"):
        collected.append(f"official_judgment_date={recovered['judgment_date']}")
        if str(updated.get("source_version_date") or "") in {"", "not_recorded"}:
            updated["source_version_date"] = recovered["judgment_date"]
    if recovered.get("xml_origin"):
        collected.append(_clip(f"xml_origin={recovered['xml_origin']}", 240))
    if recovered.get("xml_sha256"):
        collected.append(_clip(f"xml_sha256={recovered['xml_sha256']}", 240))
    updated["currentness_evidence_collected"] = [_clip(item, 240) for item in collected]
    updated["authority_status"] = "UNRESOLVED"
    updated["owner_status_decision"] = "NOT_STARTED"
    updated["owner_decision"] = ""
    updated["prospective_amendment_treated_as_in_force"] = False
    return updated


def repair_currentness_packet(
    packet: Mapping[str, Any],
    metadata_index: Any,
) -> dict[str, Any]:
    """One bounded metadata repair. Does not change answers or decide currentness."""

    from .ge_official_currentness_metadata import CurrentnessMetadataIndex

    index = metadata_index or CurrentnessMetadataIndex(allow_network=False)
    locators = [_apply_recovered_metadata(dict(item), index.lookup_locator(item)) for item in packet["locators"]]
    missing: list[str] = []
    if packet.get("applicable_law_date_status") == "INVALID_OR_AMBIGUOUS":
        missing.append("applicable_law_date")
    for index_no, record in enumerate(locators):
        for field in locator_missing_fields(record):
            missing.append(f"locator[{index_no}].{field}")
    missing = sorted(set(missing))
    recovered = bool(missing) is False
    previous_missing = list(packet.get("missing_fields") or [])
    if not missing:
        packet_status = "READY_FOR_OWNER_CURRENTNESS_REVIEW"
        next_route = "DEFERRED_OWNER_CURRENTNESS_REVIEW"
        repair_status = "RECOVERED"
        failure: list[str] = []
        reason = ""
    else:
        packet_status = "INCOMPLETE_FINAL"
        next_route = "CURRENTNESS_METADATA_REPAIR_EXHAUSTED"
        repair_status = "EXHAUSTED_UNCHANGED" if missing == previous_missing else "EXHAUSTED_STILL_INCOMPLETE"
        failure = list(missing)
        reason = _clip("bounded_metadata_repair_could_not_recover: " + ",".join(missing), 400)
    rebuilt = {
        key: value
        for key, value in packet.items()
        if key not in {"packet_hash", "locators", "packet_status", "missing_fields", "next_route"}
    }
    rebuilt.update(
        {
            "locators": locators,
            "locator_count": len(locators),
            "missing_fields": missing,
            "packet_status": packet_status,
            "next_route": next_route,
            "repair_pass": 1,
            "metadata_repair_status": repair_status,
            "exact_failure_reason": failure,
            "exact_missing_reason": reason,
            "currentness_status": "UNRESOLVED",
            "owner_decision": "",
            "owner_currentness_decision": NOT_STARTED,
            "review_status": NOT_STARTED,
            "qualified_legal_review": NOT_STARTED,
            "answer_legal_gold": NOT_STARTED,
            "legal_gold": False,
            "admitted": False,
            "full_current_law_eligible": False,
            "factual_status": "FACTUAL_HOLD",
            "claim_support_status": "PASS",
        }
    )
    if rebuilt["question"] != packet["question"] or rebuilt["candidate_answer"] != packet["candidate_answer"]:
        raise RuntimeError("currentness repair mutated question or answer")
    if rebuilt["answer_hash"] != packet["answer_hash"] or rebuilt["evidence_manifest_hash"] != packet[
        "evidence_manifest_hash"
    ]:
        raise RuntimeError("currentness repair mutated answer or evidence hashes")
    sealed = seal_contract(rebuilt, digest_field="packet_hash")
    if sealed["currentness_status"] != "UNRESOLVED":
        raise RuntimeError("repair concluded currentness")
    _ = recovered
    return sealed


def repair_currentness_packets(
    packets: Sequence[Mapping[str, Any]],
    metadata_index: Any,
) -> list[dict[str, Any]]:
    repaired: list[dict[str, Any]] = []
    for packet in packets:
        if str(packet.get("packet_status") or "") == "INCOMPLETE":
            repaired.append(repair_currentness_packet(packet, metadata_index))
        else:
            repaired.append(dict(packet))
    repaired.sort(key=lambda item: str(item["case_id"]))
    return repaired


def route_sets(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    routed = route_results(rows)
    holds = {item["case_id"]: item for item in routed["holds"]}
    currentness = {
        item["case_id"]
        for item in routed["holds"]
        if item["hold_reason_code"] == "CURRENTNESS_UNRESOLVED"
    }
    jurisdiction = {
        item["case_id"]
        for item in routed["holds"]
        if item["hold_reason_code"] == "JURISDICTION_SCOPE_REVIEW"
    }
    leftover = {
        item["case_id"]
        for item in routed["holds"]
        if item["hold_reason_code"] in LEFTOVER_REASONS
    }
    fact_dependent = {
        item["case_id"]
        for item in routed["holds"]
        if item["hold_reason_code"] == "FACT_DEPENDENT_OUTCOME"
    }
    factual_pass = {item["case_id"] for item in routed["frozen_pass_cases"]}
    other_holds = {
        item["case_id"]
        for item in routed["holds"]
        if item["case_id"] not in currentness | jurisdiction | leftover | fact_dependent
    }
    by_id = {str(row.get("case_id") or ""): row for row in rows}
    selected = []
    for case_id in sorted(currentness):
        row = by_id[case_id]
        hold = holds[case_id]
        if hold.get("evidence_present") is True and hold.get("claim_support_status") == "PASS":
            selected.append(row)
    return {
        "routed": routed,
        "currentness": currentness,
        "jurisdiction": jurisdiction,
        "leftover": leftover,
        "fact_dependent": fact_dependent,
        "factual_pass": factual_pass,
        "other_holds": other_holds,
        "selected_currentness_rows": selected,
        "holds": holds,
    }


def pairwise_overlaps(sets: Mapping[str, set[str]]) -> dict[str, list[str]]:
    names = list(sets)
    overlaps: dict[str, list[str]] = {}
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            overlap = sorted(sets[left] & sets[right])
            overlaps[f"{left}∩{right}"] = overlap
    return overlaps


def reconcile_latest_routes(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    grouped = route_sets(rows)
    routed = grouped["routed"]
    stored = {
        "total": len(rows),
        "unique": len({str(row.get("case_id") or "") for row in rows}),
        "FACTUAL_PASS": routed["factual_pass_count"],
        "FACTUAL_HOLD": routed["hold_count"],
        "CURRENTNESS_UNRESOLVED": len(grouped["currentness"]),
        "JURISDICTION_SCOPE_REVIEW": len(grouped["jurisdiction"]),
        "LEFTOVER_CLAIM_OR_NO_EVIDENCE": len(grouped["leftover"]),
        "FACT_DEPENDENT_OUTCOME": len(grouped["fact_dependent"]),
        "other_hold_reasons": dict(routed["counts_by_hold_reason_code"]),
    }
    recomputed = {
        "FACTUAL_PASS": len(grouped["factual_pass"]),
        "FACTUAL_HOLD": len(grouped["currentness"] | grouped["jurisdiction"] | grouped["leftover"] | grouped["fact_dependent"] | grouped["other_holds"]),
        "CURRENTNESS_UNRESOLVED": len(grouped["currentness"]),
        "JURISDICTION_SCOPE_REVIEW": len(grouped["jurisdiction"]),
        "LEFTOVER_CLAIM_OR_NO_EVIDENCE": len(grouped["leftover"]),
        "FACT_DEPENDENT_OUTCOME": len(grouped["fact_dependent"]),
        "selected_currentness": len(grouped["selected_currentness_rows"]),
        "sum_routes_and_pass": (
            len(grouped["currentness"])
            + len(grouped["jurisdiction"])
            + len(grouped["leftover"])
            + len(grouped["fact_dependent"])
            + len(grouped["factual_pass"])
        ),
    }
    overlaps = pairwise_overlaps(
        {
            "currentness": grouped["currentness"],
            "jurisdiction": grouped["jurisdiction"],
            "leftover": grouped["leftover"],
            "case_312": grouped["fact_dependent"],
            "factual_pass": grouped["factual_pass"],
        }
    )
    duplicated = [
        case_id
        for case_id, count in Counter(str(row.get("case_id") or "") for row in rows).items()
        if count > 1
    ]
    expected_ids = {str(row.get("case_id") or "") for row in rows}
    covered = (
        grouped["currentness"]
        | grouped["jurisdiction"]
        | grouped["leftover"]
        | grouped["fact_dependent"]
        | grouped["factual_pass"]
    )
    missing = sorted(expected_ids - covered)
    extra = sorted(covered - expected_ids)
    blocked_reasons: list[str] = []
    if stored["total"] != EXPECTED_TOTAL or stored["unique"] != EXPECTED_TOTAL:
        blocked_reasons.append("suite_size")
    if stored["FACTUAL_PASS"] != EXPECTED_FACTUAL_PASS or recomputed["FACTUAL_PASS"] != EXPECTED_FACTUAL_PASS:
        blocked_reasons.append("factual_pass")
    if stored["FACTUAL_HOLD"] != EXPECTED_FACTUAL_HOLD:
        blocked_reasons.append("factual_hold")
    if recomputed["CURRENTNESS_UNRESOLVED"] != EXPECTED_CURRENTNESS:
        blocked_reasons.append("currentness")
    if recomputed["JURISDICTION_SCOPE_REVIEW"] != EXPECTED_JURISDICTION:
        blocked_reasons.append("jurisdiction")
    if recomputed["LEFTOVER_CLAIM_OR_NO_EVIDENCE"] != EXPECTED_LEFTOVER:
        blocked_reasons.append("leftover")
    if recomputed["FACT_DEPENDENT_OUTCOME"] != EXPECTED_FACT_DEPENDENT:
        blocked_reasons.append("fact_dependent")
    if recomputed["selected_currentness"] != EXPECTED_CURRENTNESS:
        blocked_reasons.append("selected_currentness_filters")
    if recomputed["sum_routes_and_pass"] != EXPECTED_TOTAL:
        blocked_reasons.append("sum")
    if any(overlaps[name] for name in overlaps):
        blocked_reasons.append("pairwise_overlap")
    if duplicated or missing or extra or grouped["other_holds"]:
        blocked_reasons.append("coverage")
    if CASE_174 not in grouped["jurisdiction"] or CASE_174 in grouped["currentness"]:
        blocked_reasons.append("case_174")
    if CASE_312 not in grouped["fact_dependent"] or CASE_312 in grouped["currentness"]:
        blocked_reasons.append("case_312")
    status = "COUNT_RECONCILIATION_BLOCKED" if blocked_reasons else "RECONCILED"
    receipt = {
        "schema": COUNT_RECONCILIATION_SCHEMA,
        "status": status,
        "blocked_reasons": blocked_reasons,
        "stored_counts": stored,
        "recomputed_counts": recomputed,
        "expected_counts": {
            "FACTUAL_PASS": EXPECTED_FACTUAL_PASS,
            "FACTUAL_HOLD": EXPECTED_FACTUAL_HOLD,
            "CURRENTNESS_UNRESOLVED": EXPECTED_CURRENTNESS,
            "JURISDICTION_SCOPE_REVIEW": EXPECTED_JURISDICTION,
            "LEFTOVER_CLAIM_OR_NO_EVIDENCE": EXPECTED_LEFTOVER,
            "FACT_DEPENDENT_OUTCOME": EXPECTED_FACT_DEPENDENT,
            "TOTAL": EXPECTED_TOTAL,
        },
        "duplicated_case_ids": duplicated,
        "missing_case_ids": missing,
        "extra_case_ids": extra,
        "other_hold_case_ids": sorted(grouped["other_holds"]),
        "pairwise_overlaps": overlaps,
        "case_174_in_jurisdiction_only": CASE_174 in grouped["jurisdiction"]
        and CASE_174 not in grouped["currentness"]
        and CASE_174 not in grouped["leftover"]
        and CASE_174 not in grouped["fact_dependent"],
        "case_312_in_fact_dependent_only": CASE_312 in grouped["fact_dependent"]
        and CASE_312 not in grouped["currentness"]
        and CASE_312 not in grouped["jurisdiction"]
        and CASE_312 not in grouped["leftover"],
        "selected_currentness_case_ids": [row["case_id"] for row in grouped["selected_currentness_rows"]],
        "locator_count_across_selected": sum(
            len(_evidence_rows(row)) for row in grouped["selected_currentness_rows"]
        ),
    }
    return receipt


def select_currentness_cases(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return route_sets(rows)["selected_currentness_rows"]


def select_representative_pilot_ids(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    selected = {str(row.get("case_id") or ""): row for row in select_currentness_cases(rows)}
    categories: dict[str, str | None] = {
        "amended_primary": None,
        "commencement": None,
        "transitional_or_savings": None,
        "territorial_extent": None,
        "historic_as_of": None,
        "statutory_instrument": None,
        "case_law_treatment": None,
        "procedural_rule_version": None,
        "contractual_rule_edition": None,
        "multiple_locators": None,
        "prospective_amendment": None,
        "incomplete_currentness_metadata": None,
    }
    for case_id in PILOT_PREFERRED_IDS:
        row = selected.get(case_id)
        if row is None:
            continue
        packet = build_currentness_packet(row)
        types = {item["source_type"] for item in packet["locators"]}
        sub = set(packet["currentness_subreasons"])
        if categories["amended_primary"] is None and "AMENDMENT_EFFECT_UNRESOLVED" in sub:
            if "PRIMARY_LEGISLATION" in types:
                categories["amended_primary"] = case_id
        if categories["commencement"] is None and "COMMENCEMENT_SCOPE_UNRESOLVED" in sub:
            categories["commencement"] = case_id
        if categories["transitional_or_savings"] is None and "TRANSITIONAL_OR_SAVINGS_REVIEW" in sub:
            categories["transitional_or_savings"] = case_id
        if categories["territorial_extent"] is None and "TERRITORIAL_EXTENT_OR_APPLICATION_REVIEW" in sub:
            categories["territorial_extent"] = case_id
        if categories["historic_as_of"] is None and (
            packet["applicable_law_date_basis"] == "QUESTION_AS_OF_DATE"
            or "HISTORIC_AS_OF_DATE_REVIEW" in sub
        ):
            categories["historic_as_of"] = case_id
        if categories["statutory_instrument"] is None and "SECONDARY_LEGISLATION" in types:
            categories["statutory_instrument"] = case_id
        if categories["case_law_treatment"] is None and "CASE_LAW" in types:
            categories["case_law_treatment"] = case_id
        if categories["procedural_rule_version"] is None and (
            "PROCEDURAL_RULE" in types or "PROCEDURAL_RULE_VERSION" in sub
        ):
            categories["procedural_rule_version"] = case_id
        if categories["contractual_rule_edition"] is None and (
            "CONTRACTUAL_RULE" in types or "CONTRACTUALLY_INCORPORATED_EDITION" in sub
        ):
            categories["contractual_rule_edition"] = case_id
        if categories["multiple_locators"] is None and packet["locator_count"] > 1:
            categories["multiple_locators"] = case_id
        if categories["prospective_amendment"] is None and any(
            "not yet in force" in item["prospective_amendments"]
            or "prospective" in item["prospective_amendments"]
            for item in packet["locators"]
        ):
            categories["prospective_amendment"] = case_id
        if categories["incomplete_currentness_metadata"] is None and packet["packet_status"] == "INCOMPLETE":
            categories["incomplete_currentness_metadata"] = case_id
    for case_id, row in selected.items():
        packet = build_currentness_packet(row)
        types = {item["source_type"] for item in packet["locators"]}
        sub = set(packet["currentness_subreasons"])
        if categories["amended_primary"] is None and "PRIMARY_LEGISLATION" in types and "AMENDMENT_EFFECT_UNRESOLVED" in sub:
            categories["amended_primary"] = case_id
        if categories["commencement"] is None and "COMMENCEMENT_SCOPE_UNRESOLVED" in sub:
            categories["commencement"] = case_id
        if categories["transitional_or_savings"] is None and "TRANSITIONAL_OR_SAVINGS_REVIEW" in sub:
            categories["transitional_or_savings"] = case_id
        if categories["territorial_extent"] is None and "TERRITORIAL_EXTENT_OR_APPLICATION_REVIEW" in sub:
            categories["territorial_extent"] = case_id
        if categories["historic_as_of"] is None and packet["applicable_law_date_basis"] == "QUESTION_AS_OF_DATE":
            categories["historic_as_of"] = case_id
        if categories["statutory_instrument"] is None and "SECONDARY_LEGISLATION" in types:
            categories["statutory_instrument"] = case_id
        if categories["case_law_treatment"] is None and "CASE_LAW" in types:
            categories["case_law_treatment"] = case_id
        if categories["procedural_rule_version"] is None and "PROCEDURAL_RULE" in types:
            categories["procedural_rule_version"] = case_id
        if categories["contractual_rule_edition"] is None and "CONTRACTUAL_RULE" in types:
            categories["contractual_rule_edition"] = case_id
        if categories["multiple_locators"] is None and packet["locator_count"] > 1:
            categories["multiple_locators"] = case_id
        if categories["prospective_amendment"] is None and any(
            "not yet in force" in item["prospective_amendments"] for item in packet["locators"]
        ):
            categories["prospective_amendment"] = case_id
        if categories["incomplete_currentness_metadata"] is None and packet["packet_status"] == "INCOMPLETE":
            categories["incomplete_currentness_metadata"] = case_id
    case_ids = []
    for case_id in PILOT_PREFERRED_IDS:
        if case_id in selected and case_id not in case_ids:
            case_ids.append(case_id)
    for case_id in categories.values():
        if case_id and case_id not in case_ids:
            case_ids.append(case_id)
    return {
        "case_ids": case_ids,
        "categories": categories,
        "absent_categories": sorted(name for name, value in categories.items() if value is None),
    }


def assert_packet_does_not_mutate_source(row: Mapping[str, Any], packet: Mapping[str, Any]) -> None:
    if packet["question"] != str(row.get("question") or row.get("prompt") or ""):
        raise RuntimeError("packet mutated question text")
    if packet["candidate_answer"] != str(row.get("user_facing_answer") or row.get("answer") or ""):
        raise RuntimeError("packet mutated candidate answer")
    source_locators = [(str(item.get("locator") or ""), str(item.get("quote") or "")) for item in _evidence_rows(row)]
    packet_locators = [(item["exact_locator"], item["exact_supporting_passage"]) for item in packet["locators"]]
    if source_locators != packet_locators:
        raise RuntimeError("packet mutated locators or evidence spans")
    if packet["answer_hash"] != sha256_text(str(row.get("user_facing_answer") or row.get("answer") or "")):
        raise RuntimeError("answer hash does not match source answer")
    if packet["evidence_manifest_hash"] != evidence_manifest_hash(row):
        raise RuntimeError("evidence hash does not match source evidence")


def render_topic_batch(topic: str, packets: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        f"# Currentness review packets — {topic}",
        "",
        "Packet preparation only. Owner currentness review is NOT_STARTED.",
        "Do not treat this file as CURRENT, OWNER_APPROVED, LEGAL_GOLD, admission or training.",
        "",
    ]
    for packet in packets:
        lines.extend(
            [
                f"## {packet['case_id']}",
                "",
                f"- packet_status: `{packet['packet_status']}`",
                f"- currentness_status: `{packet['currentness_status']}`",
                f"- currentness_subreason: `{packet['currentness_subreason']}`",
                f"- owner_currentness_cutoff: `{packet['owner_currentness_cutoff']}`",
                f"- applicable_law_date: `{packet['applicable_law_date']}` ({packet['applicable_law_date_basis']})",
                f"- locator_count: {packet['locator_count']}",
                f"- packet_hash: `{packet['packet_hash']}`",
                f"- missing_fields: {', '.join(packet['missing_fields']) or 'none'}",
                "",
                "### Question",
                "",
                packet["question"],
                "",
                "### Candidate answer",
                "",
                packet["candidate_answer"],
                "",
            ]
        )
        for record in packet["locators"]:
            lines.extend(
                [
                    f"### Locator — {record['source_title']} / {record['exact_locator']}",
                    "",
                    f"- source_type: `{record['source_type']}`",
                    f"- official_identifier: `{record['official_identifier']}`",
                    f"- evidence_span_sha256: `{record['evidence_span_sha256']}`",
                    f"- source_version_date: `{record['source_version_date']}`",
                    f"- territorial_extent: `{record['territorial_extent']}`",
                    f"- authority_status: `{record['authority_status']}`",
                    f"- negative_treatment_found: `{record['negative_treatment_found']}`",
                    f"- owner_status_decision: `{record['owner_status_decision']}`",
                    f"- owner_decision: blank",
                    "",
                    "Exact supporting passage:",
                    "",
                    record["exact_supporting_passage"],
                    "",
                    f"Unresolved currentness question: {record['unresolved_currentness_question']}",
                    "",
                ]
            )
    return "\n".join(lines)


def build_packets_for_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    routed_holds: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for row in rows:
        hold = None if routed_holds is None else routed_holds.get(str(row.get("case_id") or ""))
        packet = build_currentness_packet(row, routed=hold)
        assert_packet_does_not_mutate_source(row, packet)
        packets.append(packet)
    packets.sort(key=lambda item: str(item["case_id"]))
    return packets


def packet_index_rows(packets: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for packet in packets:
        rows.append(
            {
                "case_id": str(packet["case_id"]),
                "topic": str(packet["topic"]),
                "subtopic": str(packet["subtopic"]),
                "packet_status": str(packet["packet_status"]),
                "currentness_status": str(packet["currentness_status"]),
                "currentness_subreason": str(packet["currentness_subreason"]),
                "locator_count": str(packet["locator_count"]),
                "applicable_law_date": str(packet["applicable_law_date"]),
                "applicable_law_date_basis": str(packet["applicable_law_date_basis"]),
                "packet_hash": str(packet["packet_hash"]),
                "answer_hash": str(packet["answer_hash"]),
                "evidence_manifest_hash": str(packet["evidence_manifest_hash"]),
                "missing_fields": "|".join(packet["missing_fields"]),
                "next_route": str(packet["next_route"]),
            }
        )
    return rows


def csv_text(rows: Sequence[Mapping[str, str]]) -> str:
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def summarize_packets(packets: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    subreasons = Counter(str(item["currentness_subreason"]) for item in packets)
    source_types = Counter(
        str(record["source_type"]) for item in packets for record in item["locators"]
    )
    complete = sum(1 for item in packets if item["packet_status"] == "READY_FOR_OWNER_CURRENTNESS_REVIEW")
    incomplete = sum(1 for item in packets if item["packet_status"] == "INCOMPLETE")
    incomplete_final = sum(1 for item in packets if item["packet_status"] == "INCOMPLETE_FINAL")
    return {
        "packet_count": len(packets),
        "locator_count": sum(int(item["locator_count"]) for item in packets),
        "complete_packet_count": complete,
        "incomplete_packet_count": incomplete,
        "incomplete_final_packet_count": incomplete_final,
        "counts_by_currentness_subreason": dict(sorted(subreasons.items())),
        "counts_by_source_type": dict(sorted(source_types.items())),
        "owner_decision_blank": all(item["owner_decision"] == "" for item in packets),
        "currentness_unresolved": all(item["currentness_status"] == "UNRESOLVED" for item in packets),
        "no_forbidden_conclusions": all(
            item["currentness_status"] not in FORBIDDEN_CURRENTNESS_CONCLUSIONS
            and item["owner_currentness_decision"] == NOT_STARTED
            and item["qualified_legal_review"] == NOT_STARTED
            and item["answer_legal_gold"] == NOT_STARTED
            and item["legal_gold"] is False
            and item["admitted"] is False
            for item in packets
        ),
    }


def full_331_guard_result() -> str:
    return NO_OP_UNCHANGED_INPUTS


def downstream_gates_not_started() -> dict[str, str]:
    return {name: NOT_STARTED for name in DOWNSTREAM_GATES}


def validate_packet(packet: Mapping[str, Any], *, project_root: Path = PROJECT_ROOT) -> None:
    registry = ContractSchemaRegistry.from_project_root(project_root)
    registry.validate_new(dict(packet), verify_digest=False)
    expected = hashlib.sha256(
        canonical_json_bytes({key: value for key, value in packet.items() if key != "packet_hash"})
    ).hexdigest()
    if packet.get("packet_hash") != expected:
        raise RuntimeError("packet_hash does not match canonical content")


def mutation_guard(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    hashes = frozen_baseline_hashes(project_root)
    mismatches = []
    expected = {
        "r1_manifest": EXPECTED_R1_MANIFEST,
        "r2_manifest": EXPECTED_R2_MANIFEST,
        "r2_results": EXPECTED_R2_RESULTS,
        "r3_manifest": EXPECTED_R3_MANIFEST,
        "r3_results": EXPECTED_R3_RESULTS,
        "delta_manifest": EXPECTED_DELTA_MANIFEST,
        "delta_results": EXPECTED_DELTA_RESULTS,
    }
    for key, value in expected.items():
        if hashes.get(key) != value:
            mismatches.append({"field": key, "expected": value, "actual": hashes.get(key)})
    return {
        "frozen_hashes": hashes,
        "expected": expected,
        "unchanged": not mismatches,
        "mismatches": mismatches,
        "full_331_guard": full_331_guard_result(),
        "sealed_unseen_not_opened": True,
        "downstream_gates": downstream_gates_not_started(),
    }


def _write_create_only(path: Path, data: bytes) -> None:
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    _write_create_only(path, json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")


def write_text(path: Path, value: str) -> None:
    _write_create_only(path, value.encode("utf-8"))


def write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    data = b"".join(canonical_json_bytes(row) for row in rows)
    _write_create_only(path, data)


def load_existing_pack(output: Path) -> dict[str, Any] | None:
    manifest_path = output / "currentness-packet-manifest.jsonl"
    state_path = output / "currentness-packet-state-receipt.json"
    if not manifest_path.is_file() or not state_path.is_file():
        return None
    packets = load_jsonl(manifest_path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    return {"packets": packets, "state": state}


def write_currentness_pack(
    output: Path,
    packets: Sequence[Mapping[str, Any]],
    *,
    reconciliation: Mapping[str, Any],
    test_receipt: Mapping[str, Any],
    mutation: Mapping[str, Any],
    pilot: Mapping[str, Any] | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    existing = load_existing_pack(output)
    if existing is not None:
        existing_ids = [item["case_id"] for item in existing["packets"]]
        new_ids = [item["case_id"] for item in packets]
        existing_hashes = [item["packet_hash"] for item in existing["packets"]]
        new_hashes = [item["packet_hash"] for item in packets]
        if existing_ids == new_ids and existing_hashes == new_hashes:
            return {
                "result": "IDEMPOTENT_UNCHANGED",
                "output": str(output),
                "packet_count": len(existing["packets"]),
                "duplicate_packets_created": False,
                "state": existing["state"],
            }
        raise RuntimeError("currentness packet pack exists with different hashes; refusing overwrite")
    for packet in packets:
        validate_packet(packet, project_root=project_root)
    summary = summarize_packets(packets)
    incomplete = [item for item in packets if item["packet_status"] == "INCOMPLETE"]
    write_jsonl(output / "currentness-packet-manifest.jsonl", packets)
    write_text(output / "currentness-packet-index.csv", csv_text(packet_index_rows(packets)))
    write_text(
        output / "currentness-packet-incomplete-cases.csv",
        csv_text(packet_index_rows(incomplete)) if incomplete else "case_id,packet_status\n",
    )
    by_topic: dict[str, list[Mapping[str, Any]]] = {}
    for packet in packets:
        by_topic.setdefault(str(packet["topic"]), []).append(packet)
    topic_dir = output / "currentness-packets-by-topic"
    topic_hashes: dict[str, str] = {}
    for topic, group in sorted(by_topic.items()):
        rendered = render_topic_batch(topic, group)
        path = topic_dir / f"{topic}.md"
        write_text(path, rendered)
        topic_hashes[f"currentness-packets-by-topic/{topic}.md"] = sha256_file(path)
        for packet in group:
            if packet["question"] not in rendered or packet["candidate_answer"] not in rendered:
                raise RuntimeError(f"topic batch truncated case {packet['case_id']}")
            for record in packet["locators"]:
                if record["exact_supporting_passage"] not in rendered:
                    raise RuntimeError(f"topic batch truncated locator {packet['case_id']}")
    write_json(output / "COUNT-RECONCILIATION.json", dict(reconciliation))
    write_json(output / "currentness-packet-test-receipt.json", dict(test_receipt))
    if pilot is not None:
        write_json(output / "PILOT-SELECTION.json", dict(pilot))
    artifacts = {
        "currentness-packet-manifest.jsonl": sha256_file(output / "currentness-packet-manifest.jsonl"),
        "currentness-packet-index.csv": sha256_file(output / "currentness-packet-index.csv"),
        "currentness-packet-incomplete-cases.csv": sha256_file(
            output / "currentness-packet-incomplete-cases.csv"
        ),
        "COUNT-RECONCILIATION.json": sha256_file(output / "COUNT-RECONCILIATION.json"),
        "currentness-packet-test-receipt.json": sha256_file(output / "currentness-packet-test-receipt.json"),
        **topic_hashes,
    }
    state = {
        "schema": "legalbot.ge-currentness-packet-state.v1",
        "currentness_packet_preparation": "COMPLETE",
        "currentness_owner_review": "DEFERRED_NOT_STARTED",
        "qualified_legal_review": NOT_STARTED,
        "answer_legal_gold": NOT_STARTED,
        "legal_gold": False,
        "admitted": False,
        "full_current_law_eligible": False,
        "answer_weight_training": NOT_STARTED,
        "sealed_unseen_execution": NOT_STARTED,
        "promotion": NOT_STARTED,
        "live": NOT_STARTED,
        "next_route": "PREPARE_JURISDICTION_SCOPE_PACKETS",
        "full_331_rerun": False,
        "full_331_guard": NO_OP_UNCHANGED_INPUTS,
        "summary": summary,
        "mutation_guard": mutation,
        "artifacts": artifacts,
        "selected_case_ids": [item["case_id"] for item in packets],
    }
    sealed_state = seal_contract(state)
    write_json(output / "currentness-packet-state-receipt.json", sealed_state)
    artifacts["currentness-packet-state-receipt.json"] = sha256_file(
        output / "currentness-packet-state-receipt.json"
    )
    readme = (
        "# Currentness packet preparation\n\n"
        "Packet preparation only. Owner currentness review is DEFERRED_NOT_STARTED.\n"
        "This pack does not set qualified legal review, answer gold, admission, "
        "training, sealed unseen, promotion or live.\n"
        "Next operational route: PREPARE_JURISDICTION_SCOPE_PACKETS.\n"
    )
    write_text(output / "README.md", readme)
    return {
        "result": "CREATED",
        "output": str(output),
        "packet_count": len(packets),
        "duplicate_packets_created": False,
        "state": sealed_state,
        "artifacts": artifacts,
        "summary": summary,
    }
