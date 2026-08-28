#!/usr/bin/env python3
"""Quarantine bounded official later-treatment leads without admitting them.

This is a targeted, non-bulk collector.  A candidate is retained only when the
official judgment itself contains both its expected neutral citation and every
target citation named by the reviewed plan.  The result remains advisory and
requires proposition-level owner review.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = PROJECT_ROOT / "config/phase2a_targeted_later_treatment_sources.v1.json"
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-24/phase2a-targeted-later-treatment-r42"
)
ALLOWED_HOSTS = frozenset(
    {
        "supremecourt.uk",
        "www.supremecourt.uk",
        "jcpc.uk",
        "www.jcpc.uk",
    }
)
MAX_HTML_BYTES = 8 * 1024 * 1024
MAX_PDF_BYTES = 32 * 1024 * 1024
USER_AGENT = "LegalBot-v1.11-Phase2A-targeted-official-review/1.0"
EXPECTED_ITEM_COUNT = 9
EXPECTED_AS_OF_DATE = date(2026, 8, 14)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NEUTRAL_CITATION = re.compile(r"^\[(?P<year>\d{4})\]\s+(?P<court>UKSC|UKPC|UKHL)\s+(?P<number>\d+)$")
_JUDGMENT_DATE = re.compile(
    r"Judgment date\s+(?P<date>\d{1,2}\s+[A-Z][a-z]+\s+\d{4})",
    re.IGNORECASE,
)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise ValueError("phase2a_targeted_later_treatment_url_outside_allowlist")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("phase2a_targeted_later_treatment_url_forbidden_component")
    if parsed.port not in (None, 443):
        raise ValueError("phase2a_targeted_later_treatment_url_nonstandard_port")
    if not parsed.path.startswith("/cases/") and not parsed.path.startswith("/uploads/"):
        raise ValueError("phase2a_targeted_later_treatment_url_path_invalid")
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def _load_plan(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, Mapping):
        raise ValueError("phase2a_targeted_later_treatment_plan_not_object")
    return value


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    items = plan.get("items")
    expected_item_count = plan.get("expected_item_count", EXPECTED_ITEM_COUNT)
    if (
        plan.get("schema")
        != "legalbot.v111.phase2a.targeted-later-treatment-plan.v1"
        or plan.get("as_of_date") != EXPECTED_AS_OF_DATE.isoformat()
        or plan.get("purpose")
        != "TARGETED_NON_BULK_OFFICIAL_PRIMARY_LATER_TREATMENT_LEADS_ONLY"
        or plan.get("bulk_search") is not False
        or plan.get("owner_later_treatment_decision_required") is not True
        or plan.get("owner_source_admission_required") is not True
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("technical_qualification_assigned") is not False
        or plan.get("phase2b_authorized") is not False
        or plan.get("development30_authorized") is not False
        or not isinstance(expected_item_count, int)
        or isinstance(expected_item_count, bool)
        or expected_item_count < 1
        or expected_item_count > 32
        or not isinstance(items, list)
        or len(items) != expected_item_count
    ):
        raise ValueError("phase2a_targeted_later_treatment_plan_boundary_invalid")
    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_urls: set[str] = set()
    for raw in items:
        if not isinstance(raw, Mapping):
            raise ValueError("phase2a_targeted_later_treatment_plan_item_invalid")
        item = dict(raw)
        lead_id = str(item.get("lead_id") or "")
        case_id = str(item.get("candidate_case_id") or "")
        candidate_citation = str(item.get("candidate_neutral_citation") or "")
        targets = item.get("target_neutral_citations")
        official_url = _safe_url(str(item.get("official_case_url") or ""))
        pinned_pdf_url_raw = item.get("official_judgment_url")
        pinned_pdf_url = None
        if pinned_pdf_url_raw is not None:
            pinned_pdf_url = _safe_url(str(pinned_pdf_url_raw))
            if not urlsplit(pinned_pdf_url).path.casefold().endswith(".pdf"):
                raise ValueError(
                    "phase2a_targeted_later_treatment_pinned_judgment_not_pdf"
                )
        if (
            not lead_id.startswith("later-treatment-lead-")
            or lead_id in seen_ids
            or official_url in seen_urls
            or case_id not in urlsplit(official_url).path.casefold()
            or _NEUTRAL_CITATION.fullmatch(candidate_citation) is None
            or not isinstance(targets, list)
            or not targets
            or any(
                not isinstance(target, str)
                or _NEUTRAL_CITATION.fullmatch(target) is None
                for target in targets
            )
            or item.get("court_weight") not in {"UKSC_BINDING", "JCPC_PERSUASIVE"}
            or not str(item.get("candidate_case_name") or "").strip()
            or not str(item.get("provisional_relationship") or "").startswith(
                "POTENTIAL_"
            )
            or item.get("owner_decision_required") is not True
        ):
            raise ValueError("phase2a_targeted_later_treatment_plan_item_invalid")
        item["official_case_url"] = official_url
        if pinned_pdf_url is not None:
            item["official_judgment_url"] = pinned_pdf_url
        validated.append(item)
        seen_ids.add(lead_id)
        seen_urls.add(official_url)
    return tuple(validated)


def _normal_text(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def _pdf_text(raw: bytes) -> str:
    reader = PdfReader(io.BytesIO(raw))
    if reader.is_encrypted:
        raise ValueError("phase2a_targeted_later_treatment_pdf_encrypted")
    return _normal_text("\n".join(page.extract_text() or "" for page in reader.pages))


def _judgment_date(page_text: str) -> date:
    match = _JUDGMENT_DATE.search(page_text)
    if match is None:
        raise ValueError("phase2a_targeted_later_treatment_judgment_date_missing")
    return datetime.strptime(match.group("date"), "%d %B %Y").date()


def _judgment_pdf_url(
    page_url: str,
    page_html: bytes,
    *,
    pinned_url: str | None = None,
) -> str | None:
    if pinned_url is not None:
        return _safe_url(pinned_url)
    soup = BeautifulSoup(page_html, "html.parser")
    candidates: list[str] = []
    for link in soup.find_all("a", href=True):
        href = urljoin(page_url, str(link["href"]))
        text = _normal_text(link.get_text(" ", strip=True)).casefold()
        lowered = href.casefold()
        if (
            lowered.endswith(".pdf")
            and "summary" not in lowered
            and ("judgment" in text or "judgment" in lowered)
        ):
            candidates.append(_safe_url(href))
    return sorted(set(candidates))[0] if candidates else None


def _bounded_citation_context(text: str, citation: str, *, radius: int = 600) -> str:
    index = text.find(citation)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(citation) + radius)
    return text[start:end]


def _exact_citation_spans(
    *,
    page_html: bytes,
    pdf_raw: bytes,
    target_citations: list[str],
) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    soup = BeautifulSoup(page_html, "html.parser")
    for paragraph in soup.find_all("p"):
        text = _normal_text(paragraph.get_text(" ", strip=True))
        matched = [citation for citation in target_citations if citation in text]
        if not text or not matched:
            continue
        digest = _sha256(text.encode("utf-8"))
        key = ("OFFICIAL_CASE_PAGE_PARAGRAPH", digest)
        if key in seen:
            continue
        spans.append(
            {
                "representation": key[0],
                "page_number": None,
                "exact_text": text,
                "exact_text_sha256": digest,
                "matched_target_citations": matched,
                "exact_text_is_contiguous_in_representation": True,
            }
        )
        seen.add(key)
    if pdf_raw:
        reader = PdfReader(io.BytesIO(pdf_raw))
        if reader.is_encrypted:
            raise ValueError("phase2a_targeted_later_treatment_pdf_encrypted")
        for page_number, page in enumerate(reader.pages, start=1):
            page_text = _normal_text(page.extract_text() or "")
            for citation in target_citations:
                context = _bounded_citation_context(page_text, citation)
                if not context:
                    continue
                digest = _sha256(context.encode("utf-8"))
                key = (f"OFFICIAL_JUDGMENT_PDF_PAGE_{page_number}", digest)
                if key in seen:
                    continue
                spans.append(
                    {
                        "representation": "OFFICIAL_JUDGMENT_PDF_PAGE_EXTRACTION",
                        "page_number": page_number,
                        "exact_text": context,
                        "exact_text_sha256": digest,
                        "matched_target_citations": [citation],
                        "exact_text_is_contiguous_in_representation": True,
                    }
                )
                seen.add(key)
    return spans


def _citation_presence(
    *,
    item: Mapping[str, Any],
    page_text: str,
    pdf_text: str,
) -> dict[str, Any]:
    combined = _normal_text(f"{page_text}\n{pdf_text}")
    expected = str(item["candidate_neutral_citation"])
    targets = [str(value) for value in item["target_neutral_citations"]]
    missing = [citation for citation in [expected, *targets] if citation not in combined]
    return {
        "candidate_neutral_citation_found": expected in combined,
        "target_neutral_citations_found": {
            citation: citation in combined for citation in targets
        },
        "all_required_citations_found": not missing,
        "missing_citations": missing,
    }


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _get_bounded(client: httpx.Client, url: str, *, maximum: int) -> httpx.Response:
    response = client.get(_safe_url(url))
    response.raise_for_status()
    _safe_url(str(response.url))
    if len(response.content) > maximum:
        raise ValueError("phase2a_targeted_later_treatment_response_too_large")
    return response


def collect(
    *,
    plan_path: Path,
    output_root: Path,
    retrieved_at: datetime,
) -> dict[str, Any]:
    if retrieved_at.tzinfo is None:
        raise ValueError("phase2a_targeted_later_treatment_retrieved_at_naive")
    plan = _load_plan(plan_path)
    items = _validate_plan(plan)
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_targeted_later_treatment_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_targeted_later_treatment_output_mode_invalid")
    plan_file_sha256 = _sha256_file(plan_path)
    intent_material = {
        "schema": "legalbot.v111.phase2a.targeted-later-treatment-intent.v1",
        "status": "TARGETED_OFFICIAL_PRIMARY_QUARANTINE_ONLY",
        "retrieved_at": retrieved_at.astimezone(UTC).isoformat(timespec="seconds"),
        "as_of_date": EXPECTED_AS_OF_DATE.isoformat(),
        "source_plan_file_sha256": plan_file_sha256,
        "item_count": len(items),
        "bulk_search": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    intent = {
        **intent_material,
        "intent_content_sha256": _sha256(_canonical_json(intent_material)),
    }
    _write_exclusive(output_root / "INTENT.json", _pretty_json(intent))

    results: list[dict[str, Any]] = []
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/pdf"}
    with httpx.Client(
        headers=headers,
        follow_redirects=True,
        max_redirects=5,
        timeout=httpx.Timeout(60),
    ) as client:
        for ordinal, item in enumerate(items, start=1):
            member_root = output_root / f"{ordinal:02d}-{item['lead_id']}"
            member_root.mkdir(mode=0o700)
            page = _get_bounded(
                client, str(item["official_case_url"]), maximum=MAX_HTML_BYTES
            )
            if "html" not in page.headers.get("content-type", "").casefold():
                raise ValueError("phase2a_targeted_later_treatment_case_page_not_html")
            page_raw = page.content
            page_path = member_root / "official-case-page.html"
            _write_exclusive(page_path, page_raw)
            soup = BeautifulSoup(page_raw, "html.parser")
            page_text = _normal_text(soup.get_text(" ", strip=True))
            decision_date = _judgment_date(page_text)
            if decision_date > EXPECTED_AS_OF_DATE:
                raise ValueError("phase2a_targeted_later_treatment_after_target_ceiling")
            pdf_url = _judgment_pdf_url(
                str(page.url),
                page_raw,
                pinned_url=(
                    str(item["official_judgment_url"])
                    if item.get("official_judgment_url") is not None
                    else None
                ),
            )
            pdf_raw = b""
            extracted_pdf_text = ""
            pdf_record: dict[str, Any] | None = None
            if pdf_url is not None:
                pdf = _get_bounded(client, pdf_url, maximum=MAX_PDF_BYTES)
                if not pdf.content.startswith(b"%PDF-"):
                    raise ValueError("phase2a_targeted_later_treatment_pdf_invalid")
                pdf_raw = pdf.content
                extracted_pdf_text = _pdf_text(pdf_raw)
                pdf_path = member_root / "official-judgment.pdf"
                _write_exclusive(pdf_path, pdf_raw)
                pdf_record = {
                    "url": str(pdf.url),
                    "relative_path": str(pdf_path.relative_to(PROJECT_ROOT)),
                    "sha256": _sha256(pdf_raw),
                    "bytes": len(pdf_raw),
                }
            presence = _citation_presence(
                item=item,
                page_text=page_text,
                pdf_text=extracted_pdf_text,
            )
            if presence["all_required_citations_found"] is not True:
                raise ValueError("phase2a_targeted_later_treatment_citation_binding_missing")
            target_citations = [
                str(value) for value in item["target_neutral_citations"]
            ]
            exact_citation_spans = _exact_citation_spans(
                page_html=page_raw,
                pdf_raw=pdf_raw,
                target_citations=target_citations,
            )
            span_bound_targets = {
                citation
                for span in exact_citation_spans
                for citation in span["matched_target_citations"]
            }
            if span_bound_targets != set(target_citations):
                raise ValueError(
                    "phase2a_targeted_later_treatment_exact_citation_span_missing"
                )
            extracted_path = member_root / "derived-review-text.txt"
            extracted_raw = (
                f"OFFICIAL CASE PAGE\n{page_text}\n\nOFFICIAL PDF EXTRACTION\n{extracted_pdf_text}\n"
            ).encode()
            _write_exclusive(extracted_path, extracted_raw)
            result_material = {
                "schema": "legalbot.v111.phase2a.targeted-later-treatment-lead.v1",
                "ordinal": ordinal,
                "lead_id": item["lead_id"],
                "target_neutral_citations": item["target_neutral_citations"],
                "candidate_case_id": item["candidate_case_id"],
                "candidate_case_name": item["candidate_case_name"],
                "candidate_neutral_citation": item["candidate_neutral_citation"],
                "candidate_judgment_date": decision_date.isoformat(),
                "court_weight": item["court_weight"],
                "provisional_relationship": item["provisional_relationship"],
                "citation_presence": presence,
                "exact_citation_span_count": len(exact_citation_spans),
                "exact_citation_spans": exact_citation_spans,
                "official_case_page": {
                    "url": str(page.url),
                    "relative_path": str(page_path.relative_to(PROJECT_ROOT)),
                    "sha256": _sha256(page_raw),
                    "bytes": len(page_raw),
                },
                "official_judgment_pdf": pdf_record,
                "derived_review_text": {
                    "relative_path": str(extracted_path.relative_to(PROJECT_ROOT)),
                    "sha256": _sha256(extracted_raw),
                    "bytes": len(extracted_raw),
                    "is_official_source_representation": False,
                },
                "targeted_search_is_exhaustive": False,
                "absence_of_other_hits_proves_no_later_treatment": False,
                "owner_decision_required": True,
                "source_admitted": False,
                "indexed": False,
                "embedded": False,
                "technical_qualification_assigned": False,
            }
            result = {
                **result_material,
                "lead_content_sha256": _sha256(_canonical_json(result_material)),
            }
            _write_exclusive(member_root / "LEAD.json", _pretty_json(result))
            results.append(result)

    manifest_material = {
        "schema": "legalbot.v111.phase2a.targeted-later-treatment-quarantine.v1",
        "status": "TARGETED_OFFICIAL_LEADS_QUARANTINED_OWNER_REVIEW_REQUIRED",
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_plan_file_sha256": plan_file_sha256,
        "as_of_date": EXPECTED_AS_OF_DATE.isoformat(),
        "record_count": len(results),
        "records": results,
        "all_required_citations_found": all(
            record["citation_presence"]["all_required_citations_found"] is True
            for record in results
        ),
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    manifest = {
        **manifest_material,
        "artifact_content_sha256": _sha256(_canonical_json(manifest_material)),
    }
    manifest_path = output_root / f"TARGETED-LATER-TREATMENT-LEADS-{len(results)}.json"
    _write_exclusive(manifest_path, _pretty_json(manifest))
    checksum_paths = sorted(
        path
        for path in output_root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(
            f"{_sha256_file(path)}  {path.relative_to(output_root)}\n"
            for path in checksum_paths
        ).encode("utf-8"),
    )
    return {
        "output_root": str(output_root),
        "artifact_content_sha256": manifest["artifact_content_sha256"],
        "record_count": len(results),
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _failure_fingerprint(exc: BaseException) -> str:
    return _sha256(f"{type(exc).__name__}:{exc}".encode())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    try:
        result = collect(
            plan_path=args.plan.resolve(strict=True),
            output_root=output_root,
            retrieved_at=datetime.now(UTC),
        )
    except Exception as exc:
        if output_root.is_dir() and not (output_root / "FAILURE.json").exists():
            failure = {
                "schema": "legalbot.v111.phase2a.targeted-later-treatment-failure.v1",
                "status": "FAILED_DIAGNOSTICS_PERSISTED_BEFORE_EXIT",
                "failure_type": type(exc).__name__,
                "failure_message": str(exc),
                "failure_fingerprint": _failure_fingerprint(exc),
                "affected_stage": "PHASE2A_TARGETED_LATER_TREATMENT_QUARANTINE",
                "phase2b_authorized": False,
                "development30_authorized": False,
            }
            _write_exclusive(output_root / "FAILURE.json", _pretty_json(failure))
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
