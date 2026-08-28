"""Verify and optionally approve fail-closed catalogue review subsets.

This is an owner-operated audit utility.  It never approves legislation,
official guidance, books, sources without a public identifier, or unresolved
files.  Public verification uses only official Find Case Law metadata for
judgments and Crossref metadata for DOI journal articles.  All other public
sources remain pending for individual review.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import html
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from bs4 import BeautifulSoup

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.citations.oscola import CitationMetadataError, render_oscola  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.orchestration.retry_policy import (  # noqa: E402
    MAX_ATTEMPTS,
    decide_retry,
    failure_fingerprint,
)
from backend.app.privacy import prompt_injection_hits, scrub_pii  # noqa: E402

REVIEW_POLICY = "legalbot.verified-review.v1"
TODAY = date.today().isoformat()
_WORD = re.compile(r"[a-z0-9]+")
_CASE = re.compile(
    r"\[(?P<year>\d{4})\]\s+(?P<court>UKSC|UKHL|UKPC|EWCA\s+CIV|EWCA\s+CRIM|"
    r"EWHC)\s+(?P<number>\d+)(?:\s+\((?P<division>[A-Z]+)\))?",
    re.IGNORECASE,
)
_EW_APPEAL = re.compile(r"on appeal from.{0,80}\[(?:19|20)\d{2}\]\s+EW(?:CA|HC)", re.I | re.S)
_ACTIONABLE_POSITIVE = re.compile(
    r"(?i)\b(?:analysis|application|approach|argument|authorit(?:y|ies)|citation|clarity|clear|"
    r"concise|conclusion|counterargument|critical|evaluation|evidence|knowledge|reasoning|"
    r"research|remed(?:y|ies)|sources?|structur\w*|thesis|writ(?:ing|ten))\b"
)
_HEADING_RUN = re.compile(r"(?:\b[A-Z]{3,}\b[\s:,-]*){3,}")


def _normalise(value: str) -> str:
    return " ".join(_WORD.findall(html.unescape(value).casefold()))


def _metadata_text(value: Any) -> str:
    """Remove publisher markup before verified metadata is persisted or rendered."""

    return " ".join(
        BeautifulSoup(html.unescape(str(value or "")), "html.parser").get_text().split()
    )


def _title_coverage(title: str, local_text: str) -> float:
    wanted = {word for word in _normalise(title).split() if len(word) > 2}
    available = set(_normalise(local_text).split())
    return len(wanted & available) / len(wanted) if wanted else 0.0


def _canonical_neutral_citation(value: str) -> str | None:
    match = _CASE.fullmatch(value.strip())
    if match is None:
        return None
    court = " ".join(match.group("court").upper().split())
    court_display = {
        "EWCA CIV": "EWCA Civ",
        "EWCA CRIM": "EWCA Crim",
    }.get(court, court)
    division = (match.group("division") or "").casefold()
    division_display = {
        "admin": "Admin",
        "ch": "Ch",
        "comm": "Comm",
        "fam": "Fam",
        "ipec": "IPEC",
        "kb": "KB",
        "pat": "Pat",
        "qb": "QB",
        "tcc": "TCC",
    }.get(division)
    suffix = f" ({division_display})" if division_display else ""
    return f"[{match.group('year')}] {court_display} {match.group('number')}{suffix}"


def _case_url(neutral: str, local_text: str, catalog_jurisdiction: str) -> str | None:
    match = _CASE.fullmatch(neutral.strip())
    if match is None:
        return None
    year, number = match.group("year"), match.group("number")
    court = " ".join(match.group("court").upper().split())
    division = (match.group("division") or "").casefold()
    jurisdiction = catalog_jurisdiction.casefold()
    if jurisdiction not in {"england and wales", "united kingdom"}:
        return None
    if court == "EWCA CIV":
        path = f"ewca/civ/{year}/{number}"
    elif court == "EWCA CRIM":
        path = f"ewca/crim/{year}/{number}"
    elif court == "EWHC":
        division_paths = {
            "admin": "admin",
            "ch": "ch",
            "comm": "comm",
            "fam": "fam",
            "ipec": "ipec",
            "kb": "kb",
            "pat": "pat",
            "qb": "qb",
            "tcc": "tcc",
        }
        if division not in division_paths:
            return None
        path = f"ewhc/{division_paths[division]}/{year}/{number}"
    elif court in {"UKSC", "UKHL"}:
        # A generic UK label is insufficient to distinguish English, Scottish,
        # Northern Irish and overseas appeals.  Auto-approval is limited to an
        # explicit England-and-Wales appeal marker in the supplied judgment.
        if not _EW_APPEAL.search(local_text[:8_000]):
            return None
        path = f"{court.casefold()}/{year}/{number}"
    else:
        # UKPC is often an overseas appeal and must not be silently routed as
        # England and Wales or general UK law.
        return None
    return f"https://caselaw.nationalarchives.gov.uk/{path}"


def _authors(raw: Any) -> str | None:
    if not isinstance(raw, list):
        return None
    names: list[str] = []
    for author in raw:
        if not isinstance(author, dict):
            continue
        name = " ".join(
            part
            for part in (
                _metadata_text(author.get("given")),
                _metadata_text(author.get("family")),
            )
            if part
        ).strip()
        if name:
            names.append(name)
    if not names:
        return None
    if len(names) > 3:
        return f"{names[0]} and others"
    return ", ".join(names[:-1]) + (f" and {names[-1]}" if len(names) > 1 else names[0])


def _issued_year(message: dict[str, Any]) -> str | None:
    for field in ("published-print", "published-online", "issued", "created"):
        value = message.get(field)
        if not isinstance(value, dict):
            continue
        date_parts = value.get("date-parts")
        if not isinstance(date_parts, list) or not date_parts:
            continue
        first_part = date_parts[0]
        if not isinstance(first_part, list) or not first_part:
            continue
        try:
            year = int(first_part[0])
        except (TypeError, ValueError):
            continue
        if 1500 <= year <= date.today().year:
            return str(year)
    return None


def _rule_specificity_reasons(
    text: str, *, grade_band: str, polarity: str, subject: str, task_type: str | None = None
) -> list[str]:
    reasons: list[str] = []
    if _HEADING_RUN.search(text):
        reasons.append("feedback_heading_contamination")
    if grade_band == "70+" and polarity == "positive_pattern":
        if len(_WORD.findall(text)) < 5:
            reasons.append("positive_pattern_too_generic")
        if not _ACTIONABLE_POSITIVE.search(text):
            reasons.append("positive_pattern_not_actionable")
    if (
        grade_band in {"50-59", "60-69"}
        and polarity == "error_to_avoid"
        and subject.casefold() == "general"
        and re.search(r"['\"]", text)
    ):
        reasons.append("specific_criticism_has_unresolved_subject")
    if re.search(r"(?i)(?:\bBP\s*:|\bbrie(?:fing|ﬁng)\s+(?:note|paper))", text) and not task_type:
        reasons.append("feedback_task_type_unresolved")
    if re.search(
        r"(?i)(?:\[EMAIL\]|email\s+me|discuss\s+your\s+work|clarification\s+on\s+your\s+feedback)",
        text,
    ):
        reasons.append("administrative_feedback_not_assessment_rule")
    if re.search(
        r"(?i)(?:\bsee\s+above\b|\bwhere\s+the\s+extra\s+words\b|"
        r"^comment\s+\d+\s+this\s+needs\s+(?:some\s+)?more\s+exploration)",
        text,
    ):
        reasons.append("feedback_requires_missing_context")
    if re.search(r"(?i)^page\s+\d+\s+comment\s+\d+\b", text):
        reasons.append("feedback_heading_contamination")
    if re.search(
        r"(?i)(?:^|\s)(?:Q\d+\s*:?[ ]*\d{2}\b|Part\s+[a-z]\)|PAGE\s+\d+|"
        r"Comment\s+\d+|\d{2}%|(?:1st|2nd|first|second)\s+marker\s*:)",
        text,
    ):
        reasons.append("source_specific_marker_contamination")
    if re.search(r"(?i)(?:\bdoes\s+not\s+do\s+this\b|\bsee\s+especially\s+paragraphs?\b)", text):
        reasons.append("feedback_requires_missing_context")
    if subject.casefold() == "general" and re.search(
        r"(?i)\b(?:joint\s+tenancy|proprietary\s+estoppel|born\s+alive|implied\s+terms|"
        r"remedies?\s+for\s+breach|easements?|fiduciary\s+duties|in\s+Tabassum)\b",
        text,
    ):
        reasons.append("specific_legal_feedback_subject_unresolved")
    if re.search(r"(?i)\bbibliograph(?:y|ies)\b", text):
        reasons.append("citation_convention_requires_manual_review")
    if re.search(r"(?i)\bput\s+less\s+emphasis\s+on\b", text):
        reasons.append("feedback_requires_missing_context")
    return reasons


def _current_source_rows(database: Database, lane: str) -> list[Any]:
    return database.fetchall(
        """
        SELECT r.id AS review_id, r.target_id, d.id AS document_id,
               d.safe_display_name, d.status AS document_status, d.lane,
               d.jurisdiction, d.subject_primary, d.content_sha256,
               d.retrieval_canonical, sv.title, sv.version_sha256,
               sv.metadata_json, sv.review_status,
               COUNT(c.id) AS chunk_count
        FROM reviews r JOIN source_versions sv ON sv.id=r.target_id
        JOIN documents d ON d.id=sv.document_id
        LEFT JOIN chunks c ON c.source_version_id=sv.id AND c.stream='body'
        WHERE r.review_type='source_version' AND r.status='pending'
          AND sv.superseded_by IS NULL AND sv.version_sha256=d.content_sha256
          AND d.lane=?
        GROUP BY r.id ORDER BY r.id
        """,
        (lane,),
    )


def _source_text(database: Database, source_version_id: str, *, limit: int = 30_000) -> str:
    """Read only the bounded leading text needed for identity verification."""

    pieces: list[str] = []
    remaining = limit
    rows = database.fetchall(
        """
        SELECT markdown_text FROM chunks
        WHERE source_version_id=? AND stream='body'
        ORDER BY ordinal
        LIMIT 100
        """,
        (source_version_id,),
    )
    for row in rows:
        text = str(row["markdown_text"] or "")
        if not text:
            continue
        piece = text[:remaining]
        pieces.append(piece)
        remaining -= len(piece)
        if remaining <= 0:
            break
    return "\n".join(pieces)


async def _verified_get(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """Retry only transient official-metadata failures; permanent failures remain held."""

    prior_fingerprints: list[str] = []
    url_identity = hashlib.sha256(url.encode()).hexdigest()
    for attempt_number in range(1, MAX_ATTEMPTS + 1):
        response = await client.get(url)
        if response.status_code != 429 and response.status_code < 500:
            response.raise_for_status()
            return response
        retry_after = response.headers.get("Retry-After", "")
        try:
            delay = min(max(float(retry_after), 0.5), 5.0)
        except ValueError:
            delay = 0.75 * attempt_number
        fingerprint = failure_fingerprint(
            stage="official_metadata_fetch",
            reason_code=f"http_status_{response.status_code}",
            identity_digests=(url_identity,),
        )
        decision = decide_retry(
            attempt_number=attempt_number,
            failure_reason_code=f"http_status_{response.status_code}",
            failure_fingerprint_sha256=fingerprint,
            prior_failure_fingerprints=prior_fingerprints,
            input_or_condition_changed=delay > 0,
        )
        prior_fingerprints.append(fingerprint)
        if not decision.should_retry:
            response.raise_for_status()
        await asyncio.sleep(delay)
    raise RuntimeError("unreachable metadata retry state")


def approve_private_teaching(database: Database, *, apply: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    unsafe_targets = {
        str(row["target_id"])
        for row in database.fetchall(
            "SELECT target_id FROM reviews WHERE review_type='document_safety' AND status='pending'"
        )
    }
    for row in _current_source_rows(database, "private_teaching"):
        metadata = json.loads(row["metadata_json"] or "{}")
        reasons: list[str] = []
        if row["document_status"] != "private_teaching" or not row["retrieval_canonical"]:
            reasons.append("not_ready_canonical")
        if int(row["chunk_count"]) < 1 or int(metadata.get("selected_chunk_count") or 0) < 1:
            reasons.append("no_searchable_chunks")
        if str(row["target_id"]) in unsafe_targets:
            reasons.append("document_safety_review_pending")
        if (
            metadata.get("classification_confidence") != "high"
            or metadata.get("classification_reason") != "private_teaching_content_high_confidence"
        ):
            reasons.append("teaching_classification_not_high_confidence")
        material_type = str(metadata.get("material_type_candidate") or "")
        if material_type not in {"lecture", "tutorial", "seminar", "course_note"}:
            reasons.append("invalid_teaching_type")
        result = {
            "review_id": row["review_id"],
            "safe_name": row["safe_display_name"],
            "lane": "private_teaching",
            "decision": "approve" if not reasons else "hold",
            "reasons": reasons,
        }
        if apply and not reasons:
            database.decide_review(
                str(row["review_id"]),
                "approved",
                f"{REVIEW_POLICY}: hash/parity/parser verified; issue spotting only; not authority",
                {
                    "identity_verified": True,
                    "currentness_verified": False,
                    "stable_identifier": f"content-sha256:{row['content_sha256']}",
                    "identity_title": f"Private teaching source {str(row['content_sha256'])[:12]}",
                    "as_of_date": None,
                    "currentness_status": "not_applicable",
                    "material_type": material_type,
                    "citation_data": {},
                },
            )
        results.append(result)
    return results


async def _verify_case(client: httpx.AsyncClient, row: Any) -> tuple[Any, dict[str, Any]]:
    metadata = json.loads(row["metadata_json"] or "{}")
    candidate = metadata.get("public_identifier_candidate") or {}
    neutral = _canonical_neutral_citation(str(candidate.get("value") or "")) or ""
    local_text = str(row["local_text"] or "")
    reasons: list[str] = []
    url = _case_url(neutral, local_text, str(row["jurisdiction"] or ""))
    if not url:
        reasons.append("unsupported_or_unverified_jurisdiction")
        return row, {"decision": "hold", "reasons": reasons}
    try:
        response = await _verified_get(client, url)
    except httpx.HTTPError:
        return row, {"decision": "hold", "reasons": ["official_case_not_found"]}
    soup = BeautifulSoup(response.text, "html.parser")
    title_element = soup.select_one("h1#judgment-toolbar-title")
    canonical = soup.select_one('link[rel="canonical"]')
    official_title = (
        " ".join(title_element.get_text(" ", strip=True).split()) if title_element else ""
    )
    official_url = str(canonical.get("href") or "") if canonical else ""
    page_neutral = " ".join(
        element.get_text(" ", strip=True)
        for element in soup.select(
            ".judgment-toolbar__neutral-citation, .judgment-header__neutral-citation"
        )
    )
    if not official_title or neutral.casefold() not in page_neutral.casefold():
        reasons.append("official_identity_mismatch")
    if neutral.casefold() not in local_text[:8_000].casefold():
        reasons.append("local_identifier_not_in_leading_text")
    if official_url != url:
        reasons.append("official_canonical_url_mismatch")
    if _title_coverage(official_title, local_text[:20_000]) < 0.6:
        reasons.append("local_title_mismatch")
    citation_data = {
        "source_type": "case",
        "case_name": official_title,
        "neutral_citation": neutral,
    }
    try:
        render_oscola(citation_data)
    except CitationMetadataError:
        reasons.append("oscola_metadata_invalid")
    return row, {
        "decision": "approve" if not reasons else "hold",
        "reasons": reasons,
        "stable_identifier": f"neutral-citation:{neutral}",
        "canonical_url": official_url,
        "citation_data": citation_data,
        "material_type": "case",
    }


async def _verify_doi(client: httpx.AsyncClient, row: Any) -> tuple[Any, dict[str, Any]]:
    metadata = json.loads(row["metadata_json"] or "{}")
    candidate = metadata.get("public_identifier_candidate") or {}
    doi = str(candidate.get("value") or "").casefold()
    reasons: list[str] = []
    try:
        response = await _verified_get(
            client, f"https://api.crossref.org/works/{quote(doi, safe='')}"
        )
        message = response.json()["message"]
    except (httpx.HTTPError, KeyError, TypeError, ValueError):
        return row, {"decision": "hold", "reasons": ["crossref_metadata_unavailable"]}
    if str(message.get("DOI") or "").casefold() != doi:
        reasons.append("doi_mismatch")
    if message.get("type") != "journal-article":
        reasons.append("not_journal_article")
    relation = message.get("relation") or {}
    if isinstance(relation, dict) and any(
        key in relation for key in ("is-retracted-by", "is-corrected-by", "is-updated-by")
    ):
        reasons.append("update_or_retraction_review_required")
    update_to = message.get("update-to") or []
    if isinstance(update_to, list) and update_to:
        reasons.append("update_or_retraction_review_required")
    title = _metadata_text((message.get("title") or [""])[0])
    local_text = str(row["local_text"] or "")
    leading_text = local_text[:12_000]
    if doi not in leading_text.casefold():
        reasons.append("local_identifier_not_in_leading_text")
    if _title_coverage(title, leading_text) < 0.8:
        reasons.append("local_title_mismatch")
    jurisdiction = str(row["jurisdiction"] or "").casefold()
    folded = local_text[:30_000].casefold()
    jurisdiction_patterns = {
        "england and wales": r"\b(?:england|english law|united kingdom|uk law|uksc|ukhl|ewca|ewhc)\b",
        "united kingdom": r"\b(?:united kingdom|uk law|uksc|ukhl|parliament|british)\b",
        "european union": r"\b(?:european union|eu law|cjeu|tfeu|european court)\b",
    }
    jurisdiction_pattern = jurisdiction_patterns.get(jurisdiction)
    if jurisdiction_pattern is None:
        reasons.append("unsupported_or_unverified_jurisdiction")
    elif not re.search(jurisdiction_pattern, folded):
        reasons.append("jurisdiction_not_confirmed_in_source")
    author = _authors(message.get("author"))
    journal = _metadata_text((message.get("container-title") or [""])[0])
    year = _issued_year(message)
    if not author or not title or not journal or not year:
        reasons.append("incomplete_bibliographic_metadata")
    citation_data: dict[str, Any] = {
        "source_type": "journal",
        "author": author or "",
        "title": title,
        "year": year or "",
        "year_format": "round" if message.get("volume") else "square",
        "journal": journal,
    }
    for source, target in (("volume", "volume"), ("issue", "issue"), ("page", "first_page")):
        value = str(message.get(source) or "").strip()
        if value:
            citation_data[target] = value.split("-")[0]
    if not citation_data.get("first_page"):
        citation_data["online_only"] = True
    try:
        render_oscola(citation_data)
    except CitationMetadataError:
        reasons.append("oscola_metadata_invalid")
    return row, {
        "decision": "approve" if not reasons else "hold",
        "reasons": reasons,
        "stable_identifier": f"doi:{doi}",
        "canonical_url": f"https://doi.org/{doi}",
        "citation_data": citation_data,
        "material_type": "journal",
    }


async def verify_public(database: Database, *, apply: bool) -> list[dict[str, Any]]:
    candidates: list[tuple[str, dict[str, Any]]] = []
    results: list[dict[str, Any]] = []
    unsafe_targets = {
        str(row["target_id"])
        for row in database.fetchall(
            "SELECT target_id FROM reviews WHERE review_type='document_safety' AND status='pending'"
        )
    }
    for lane in ("primary_authority", "official_secondary", "scholarship"):
        for row in _current_source_rows(database, lane):
            metadata = json.loads(row["metadata_json"] or "{}")
            candidate = metadata.get("public_identifier_candidate") or {}
            base_reasons: list[str] = []
            if (
                row["document_status"] != "citable"
                or not row["retrieval_canonical"]
                or int(row["chunk_count"]) < 1
            ):
                base_reasons.append("source_not_ready_canonical")
            if str(row["target_id"]) in unsafe_targets:
                base_reasons.append("document_safety_review_pending")
            if metadata.get("classification_confidence") != "high":
                base_reasons.append("public_classification_not_high_confidence")
            if base_reasons:
                results.append(
                    {
                        "review_id": row["review_id"],
                        "safe_name": row["safe_display_name"],
                        "lane": row["lane"],
                        "decision": "hold",
                        "reasons": base_reasons,
                    }
                )
                continue
            if candidate.get("scheme") == "neutral_citation" and lane == "primary_authority":
                item = dict(row)
                item["local_text"] = _source_text(database, str(row["target_id"]))
                candidates.append(("case", item))
            elif candidate.get("scheme") == "doi" and lane == "scholarship":
                item = dict(row)
                item["local_text"] = _source_text(database, str(row["target_id"]))
                candidates.append(("doi", item))
            else:
                material_type = str(metadata.get("material_type_candidate") or "unknown")
                reason_by_type = {
                    "case": "official_case_identity_review_required",
                    "legislation": "official_currentness_verification_required",
                    "rule": "official_currentness_verification_required",
                    "official_guidance": "official_identity_currentness_verification_required",
                    "journal": "bibliographic_identity_review_required",
                    "book": "bibliographic_identity_rights_review_required",
                }
                results.append(
                    {
                        "review_id": row["review_id"],
                        "safe_name": row["safe_display_name"],
                        "lane": row["lane"],
                        "decision": "hold",
                        "reasons": [reason_by_type.get(material_type, "unsupported_material_type")],
                    }
                )
    limits = httpx.Limits(max_connections=8, max_keepalive_connections=8)
    timeout = httpx.Timeout(20.0)
    headers = {"User-Agent": "LegalBot-New owner metadata verifier/1.0"}
    semaphore = asyncio.Semaphore(4)
    async with httpx.AsyncClient(
        follow_redirects=True, limits=limits, timeout=timeout, headers=headers
    ) as client:

        async def run(kind: str, row: Any) -> tuple[Any, dict[str, Any]]:
            async with semaphore:
                return (
                    await _verify_case(client, row)
                    if kind == "case"
                    else await _verify_doi(client, row)
                )

        checked = await asyncio.gather(*(run(kind, row) for kind, row in candidates))
    for row, result in checked:
        item = {
            "review_id": row["review_id"],
            "safe_name": row["safe_display_name"],
            "lane": row["lane"],
            **result,
        }
        if apply and result["decision"] == "approve":
            database.decide_review(
                str(row["review_id"]),
                "approved",
                f"{REVIEW_POLICY}: official identity/bibliography, local match, jurisdiction and OSCOLA verified",
                {
                    "identity_verified": True,
                    "currentness_verified": True,
                    "stable_identifier": result["stable_identifier"],
                    "as_of_date": TODAY,
                    "currentness_status": "latest_available_revised_snapshot",
                    "material_type": result["material_type"],
                    "citation_data": result["citation_data"],
                    "canonical_url": result["canonical_url"],
                },
            )
        results.append(item)
    return sorted(results, key=lambda item: str(item["review_id"]))


def approve_rules(database: Database, *, apply: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    owner_identifiers = Settings().owner_identifiers
    rows = database.fetchall(
        """
        SELECT r.id AS review_id, rr.*, sv.metadata_json, sv.superseded_by,
               d.content_sha256, sv.version_sha256, d.lane
        FROM reviews r JOIN rubric_rules rr ON rr.id=r.target_id
        JOIN source_versions sv ON sv.id=rr.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE r.review_type='assessment_rule' AND r.status='pending'
          AND rr.review_status='staged'
        ORDER BY r.id
        """
    )
    positive = re.compile(
        r"(?i)\b(?:accurate|clear|coherent|compelling|critical|effective|excellent|good|"
        r"insightful|persuasive|precise|relevant|sophisticated|sound|strong|thorough|"
        r"very well|well[- ](?:argued|structured|supported|written))\b"
    )
    negative = re.compile(
        r"(?i)\b(?:could have|does not|error|fails? to|inaccurate|incomplete|"
        r"gaps?|insufficient|lack(?:s|ing)?|limited|missing|needs?|not enough|should|"
        r"too (?:brief|descriptive|general|limited|much|vague)|unclear|underdeveloped|"
        r"unsupported|weak|wrong)\b|\bmore (?:analysis|authority|detail|discussion|"
        r"evaluation|precision|support)\b"
    )
    for row in rows:
        metadata = json.loads(row["metadata_json"] or "{}")
        text = str(row["rule_text"] or "")
        reasons: list[str] = []
        if (
            row["lane"] != "assessment_guidance"
            or row["superseded_by"] is not None
            or row["version_sha256"] != row["content_sha256"]
        ):
            reasons.append("source_version_not_current")
        if metadata.get("assessment_rule_schema") != "legalbot.assessment-rules.v2":
            reasons.append("old_rule_schema")
        if not 12 <= len(text) <= 800:
            reasons.append("rule_length_out_of_bounds")
        if (
            scrub_pii(text, owner_identifiers) != text
            or prompt_injection_hits(text)
            or re.search(r"https?://", text)
        ):
            reasons.append("unsafe_rule_text")
        has_positive, has_negative = bool(positive.search(text)), bool(negative.search(text))
        expected = (
            row["grade_band"] == "70+"
            and row["polarity"] == "positive_pattern"
            and has_positive
            and not has_negative
        ) or (
            row["grade_band"] in {"50-59", "60-69"}
            and row["polarity"] == "error_to_avoid"
            and has_negative
            and not has_positive
        )
        if not expected:
            reasons.append("grade_polarity_mismatch")
        reasons.extend(
            _rule_specificity_reasons(
                text,
                grade_band=str(row["grade_band"] or ""),
                polarity=str(row["polarity"] or ""),
                subject=str(row["subject"] or "general"),
                task_type=str(row["task_type"]) if row["task_type"] is not None else None,
            )
        )
        if re.search(r"(?i)\bheadings?\b", text) and row["criterion"] != "structure":
            reasons.append("assessment_criterion_mismatch")
        safe_rule_text = scrub_pii(text, owner_identifiers)
        result = {
            "review_id": row["review_id"],
            "grade_band": row["grade_band"],
            "polarity": row["polarity"],
            "criterion": row["criterion"],
            "subject": row["subject"],
            "rule_text": safe_rule_text,
            "decision": "approve" if not reasons else "hold",
            "reasons": reasons,
        }
        if apply and not reasons:
            database.decide_review(
                str(row["review_id"]),
                "approved",
                f"{REVIEW_POLICY}: marker-only provenance, explicit band and consistent polarity verified",
            )
        results.append(result)
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--scope",
        choices=("all", "teaching", "rules", "public"),
        default="all",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("data/review_queue/verified-review-report.json"),
    )
    args = parser.parse_args()
    settings = Settings()
    database = Database(settings.database_path)
    active_scan = database.fetchone(
        "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
    )
    if active_scan is not None:
        raise SystemExit("source scan is active; wait for the immutable catalogue transition")
    report: dict[str, Any] = {
        "policy": REVIEW_POLICY,
        "as_of_date": TODAY,
        "applied": bool(args.apply),
        "scopes": {},
    }
    if args.scope in {"all", "teaching"}:
        report["scopes"]["teaching"] = approve_private_teaching(database, apply=args.apply)
    if args.scope in {"all", "rules"}:
        report["scopes"]["rules"] = approve_rules(database, apply=args.apply)
    if args.scope in {"all", "public"}:
        report["scopes"]["public"] = asyncio.run(verify_public(database, apply=args.apply))
    counts = Counter(item["decision"] for items in report["scopes"].values() for item in items)
    report["decision_counts"] = dict(sorted(counts.items()))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report["decision_counts"], sort_keys=True))


if __name__ == "__main__":
    main()
