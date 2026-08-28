#!/usr/bin/env python3
"""Quarantine official UKSC replacements for restricted Phase-2A source copies.

The collector is deliberately narrow and create-only.  It downloads only the
five case pages and judgment PDFs pinned in the reviewed plan, verifies their
identity and dates, and preserves deterministic page-text extractions for
later proposition-level owner review.  Nothing is admitted, indexed, embedded,
or used to mutate a candidate.
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
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = (
    PROJECT_ROOT / "config/phase2a_issue_source_rehoming.2026-08-25.v1.json"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-25/phase2a-issue-source-rehoming-r77"
)
EXPECTED_ITEM_COUNT = 5
TARGET_CEILING_DATE = date(2026, 8, 14)
ALLOWED_HOSTS = frozenset({"supremecourt.uk", "www.supremecourt.uk"})
MAX_HTML_BYTES = 8 * 1024 * 1024
MAX_PDF_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 5
USER_AGENT = "LegalBot-v1.11-Phase2A-official-source-rehoming/1.0"
_NEUTRAL_CITATION = re.compile(r"^\[(?P<year>\d{4})\]\s+UKSC\s+(?P<number>\d+)$")
_LOCATOR = re.compile(r"^p\s+(?P<number>[1-9]\d*)$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _safe_url(value: str, *, expected_path_prefix: str | None = None) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if (
        parsed.scheme != "https"
        or host not in ALLOWED_HOSTS
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise ValueError("phase2a_source_rehoming_url_outside_allowlist")
    if expected_path_prefix is not None and not parsed.path.startswith(
        expected_path_prefix
    ):
        raise ValueError("phase2a_source_rehoming_url_path_invalid")
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def _normal_text(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def _load_plan(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_source_rehoming_plan_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_source_rehoming_plan_not_object")
    return value


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    items = plan.get("items")
    if (
        plan.get("schema")
        != "legalbot.v111.phase2a.issue-source-rehoming-plan.v1"
        or plan.get("as_of_date") != TARGET_CEILING_DATE.isoformat()
        or plan.get("purpose")
        != "REHOME_RESTRICTED_FIND_CASE_LAW_REFERENCES_TO_OFFICIAL_UKSC_REPRESENTATIONS"
        or plan.get("bulk_search") is not False
        or plan.get("owner_proposition_level_admission_required") is not True
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("candidate_mutation_authorized") is not False
        or plan.get("technical_qualification_assigned") is not False
        or plan.get("phase2b_authorized") is not False
        or plan.get("development30_authorized") is not False
        or not isinstance(items, list)
        or len(items) != EXPECTED_ITEM_COUNT
    ):
        raise ValueError("phase2a_source_rehoming_plan_boundary_invalid")
    _safe_url(str(plan.get("licence_evidence_url") or ""), expected_path_prefix="/about/")
    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_citations: set[str] = set()
    seen_rows: set[str] = set()
    for raw in items:
        if not isinstance(raw, Mapping):
            raise ValueError("phase2a_source_rehoming_plan_item_invalid")
        item = dict(raw)
        proposal_id = str(item.get("proposal_id") or "")
        case_id = str(item.get("case_id") or "")
        citation = str(item.get("neutral_citation") or "")
        affected_rows = item.get("affected_rows")
        locators = item.get("locator_hints")
        case_url = _safe_url(
            str(item.get("official_case_url") or ""),
            expected_path_prefix="/cases/",
        )
        pdf_url = _safe_url(
            str(item.get("official_judgment_pdf_url") or ""),
            expected_path_prefix="/uploads/",
        )
        try:
            judgment_date = date.fromisoformat(str(item.get("judgment_date") or ""))
        except ValueError as exc:
            raise ValueError("phase2a_source_rehoming_judgment_date_invalid") from exc
        if (
            not proposal_id.startswith("issue-source-rehome-")
            or proposal_id in seen_ids
            or not case_id.startswith("uksc-")
            or case_id not in urlsplit(case_url).path.casefold()
            or _NEUTRAL_CITATION.fullmatch(citation) is None
            or citation in seen_citations
            or not str(item.get("case_name") or "").strip()
            or judgment_date > TARGET_CEILING_DATE
            or not urlsplit(pdf_url).path.casefold().endswith(".pdf")
            or not isinstance(affected_rows, list)
            or not affected_rows
            or any(
                not isinstance(row_id, str)
                or not re.fullmatch(r"live(?:30|60)-q\d{2}:issue-\d{2}", row_id)
                or row_id in seen_rows
                for row_id in affected_rows
            )
            or not isinstance(locators, list)
            or not locators
            or any(not isinstance(value, str) or _LOCATOR.fullmatch(value) is None for value in locators)
        ):
            raise ValueError("phase2a_source_rehoming_plan_item_invalid")
        item["official_case_url"] = case_url
        item["official_judgment_pdf_url"] = pdf_url
        item["judgment_date"] = judgment_date.isoformat()
        validated.append(item)
        seen_ids.add(proposal_id)
        seen_citations.add(citation)
        seen_rows.update(str(value) for value in affected_rows)
    return tuple(validated)


def _fetch_bounded(
    client: httpx.Client,
    url: str,
    *,
    maximum: int,
) -> tuple[str, int, str, bytes]:
    current = _safe_url(url)
    for _ in range(MAX_REDIRECTS + 1):
        response = client.get(current)
        if response.status_code in {301, 302, 303, 307, 308}:
            location = response.headers.get("location")
            if not location:
                raise ValueError("phase2a_source_rehoming_redirect_without_location")
            current = _safe_url(urljoin(current, location))
            continue
        response.raise_for_status()
        final_url = _safe_url(str(response.url))
        raw = response.content
        if len(raw) > maximum:
            raise ValueError("phase2a_source_rehoming_response_too_large")
        return (
            final_url,
            response.status_code,
            response.headers.get("content-type", ""),
            raw,
        )
    raise ValueError("phase2a_source_rehoming_redirect_limit_exceeded")


def _pdf_pages(raw: bytes) -> list[dict[str, Any]]:
    reader = PdfReader(io.BytesIO(raw))
    if reader.is_encrypted:
        raise ValueError("phase2a_source_rehoming_pdf_encrypted")
    pages: list[dict[str, Any]] = []
    for ordinal, page in enumerate(reader.pages, start=1):
        text = _normal_text(page.extract_text() or "")
        pages.append(
            {
                "page_number": ordinal,
                "text": text,
                "text_sha256": _sha256(text.encode("utf-8")),
            }
        )
    return pages


def _page_text_contains_identity(
    *, page_html: bytes, citation: str, judgment_date: str
) -> bool:
    text = _normal_text(BeautifulSoup(page_html, "html.parser").get_text(" ", strip=True))
    rendered_date = datetime.strptime(judgment_date, "%Y-%m-%d").strftime("%-d %B %Y")
    return citation in text and rendered_date in text


def _collect(
    *, plan_path: Path, output_root: Path, retrieved_at: datetime
) -> dict[str, Any]:
    if retrieved_at.tzinfo is None:
        raise ValueError("phase2a_source_rehoming_retrieved_at_naive")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_source_rehoming_output_exists")
    plan = _load_plan(plan_path)
    items = _validate_plan(plan)
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_source_rehoming_output_mode_invalid")

    plan_file_sha256 = _sha256_file(plan_path)
    plan_content_sha256 = _sealed(plan)
    retrieved = retrieved_at.astimezone(UTC).isoformat(timespec="seconds")
    intent_material = {
        "schema": "legalbot.v111.phase2a.issue-source-rehoming-intent.v1",
        "status": "OFFICIAL_UKSC_SOURCE_QUARANTINE_ONLY",
        "retrieved_at": retrieved,
        "target_ceiling_date": TARGET_CEILING_DATE.isoformat(),
        "source_plan_file_sha256": plan_file_sha256,
        "source_plan_content_sha256": plan_content_sha256,
        "record_count": len(items),
        "bulk_search": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    intent = {**intent_material, "intent_content_sha256": _sealed(intent_material)}
    _write_exclusive(output_root / "INTENT.json", _pretty_json(intent))

    records: list[dict[str, Any]] = []
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/pdf;q=0.9",
    }
    with httpx.Client(
        headers=headers,
        follow_redirects=False,
        timeout=httpx.Timeout(60.0, connect=15.0),
        trust_env=False,
    ) as client:
        licence_url, _, licence_type, licence_raw = _fetch_bounded(
            client,
            str(plan["licence_evidence_url"]),
            maximum=MAX_HTML_BYTES,
        )
        if "html" not in licence_type.casefold():
            raise ValueError("phase2a_source_rehoming_licence_page_not_html")
        licence_text = _normal_text(
            BeautifulSoup(licence_raw, "html.parser").get_text(" ", strip=True)
        )
        if "Open Government Licence" not in licence_text:
            raise ValueError("phase2a_source_rehoming_ogl_evidence_missing")
        _write_exclusive(output_root / "official-licence-evidence.html", licence_raw)

        for ordinal, item in enumerate(items, start=1):
            member_root = output_root / f"{ordinal:02d}-{item['proposal_id']}"
            member_root.mkdir(mode=0o700)
            case_url, _, case_type, case_raw = _fetch_bounded(
                client,
                str(item["official_case_url"]),
                maximum=MAX_HTML_BYTES,
            )
            if "html" not in case_type.casefold():
                raise ValueError("phase2a_source_rehoming_case_page_not_html")
            if not _page_text_contains_identity(
                page_html=case_raw,
                citation=str(item["neutral_citation"]),
                judgment_date=str(item["judgment_date"]),
            ):
                raise ValueError("phase2a_source_rehoming_case_identity_mismatch")
            pdf_url, _, pdf_type, pdf_raw = _fetch_bounded(
                client,
                str(item["official_judgment_pdf_url"]),
                maximum=MAX_PDF_BYTES,
            )
            if not pdf_raw.startswith(b"%PDF-") or "pdf" not in pdf_type.casefold():
                raise ValueError("phase2a_source_rehoming_judgment_pdf_invalid")
            pages = _pdf_pages(pdf_raw)
            combined_text = " ".join(str(page["text"]) for page in pages)
            if str(item["neutral_citation"]) not in combined_text:
                raise ValueError("phase2a_source_rehoming_pdf_identity_mismatch")
            maximum_locator = max(
                int(_LOCATOR.fullmatch(str(value)).group("number"))
                for value in item["locator_hints"]
            )
            if maximum_locator > len(pages):
                raise ValueError("phase2a_source_rehoming_locator_outside_pdf")

            case_path = member_root / "official-case-page.html"
            pdf_path = member_root / "official-judgment.pdf"
            pages_path = member_root / "derived-page-text.json"
            _write_exclusive(case_path, case_raw)
            _write_exclusive(pdf_path, pdf_raw)
            pages_material = {
                "schema": "legalbot.v111.phase2a.derived-uksc-page-text.v1",
                "source_pdf_sha256": _sha256(pdf_raw),
                "is_official_source_representation": False,
                "page_count": len(pages),
                "pages": pages,
            }
            _write_exclusive(pages_path, _pretty_json(pages_material))
            record_material = {
                "schema": "legalbot.v111.phase2a.issue-source-rehoming-record.v1",
                "ordinal": ordinal,
                "proposal_id": item["proposal_id"],
                "case_id": item["case_id"],
                "case_name": item["case_name"],
                "neutral_citation": item["neutral_citation"],
                "judgment_date": item["judgment_date"],
                "source_date": item["judgment_date"],
                "last_updated": retrieved,
                "affected_rows": item["affected_rows"],
                "locator_hints": item["locator_hints"],
                "official_case_page": {
                    "url": case_url,
                    "relative_path": str(case_path.relative_to(PROJECT_ROOT)),
                    "sha256": _sha256(case_raw),
                    "bytes": len(case_raw),
                },
                "official_judgment_pdf": {
                    "url": pdf_url,
                    "relative_path": str(pdf_path.relative_to(PROJECT_ROOT)),
                    "sha256": _sha256(pdf_raw),
                    "bytes": len(pdf_raw),
                    "page_count": len(pages),
                },
                "derived_page_text": {
                    "relative_path": str(pages_path.relative_to(PROJECT_ROOT)),
                    "sha256": _sha256_file(pages_path),
                    "is_official_source_representation": False,
                },
                "licence_name": "Open Government Licence",
                "licence_evidence_url": licence_url,
                "licence_evidence_sha256": _sha256(licence_raw),
                "official_primary_source": True,
                "find_case_law_full_text_used": False,
                "owner_proposition_level_admission_required": True,
                "source_admitted": False,
                "indexed": False,
                "embedded": False,
                "candidate_mutated": False,
                "technical_qualification_assigned": False,
            }
            record = {
                **record_material,
                "record_content_sha256": _sealed(record_material),
            }
            _write_exclusive(member_root / "RECORD.json", _pretty_json(record))
            records.append(record)

    manifest_material = {
        "schema": "legalbot.v111.phase2a.issue-source-rehoming-quarantine.v1",
        "status": "OFFICIAL_UKSC_SOURCES_QUARANTINED_OWNER_ADMISSION_REQUIRED",
        "created_at": retrieved,
        "target_ceiling_date": TARGET_CEILING_DATE.isoformat(),
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_plan_file_sha256": plan_file_sha256,
        "source_plan_content_sha256": plan_content_sha256,
        "licence_evidence_sha256": records[0]["licence_evidence_sha256"],
        "record_count": len(records),
        "affected_row_count": len(
            {row_id for record in records for row_id in record["affected_rows"]}
        ),
        "records": records,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    manifest = {
        **manifest_material,
        "artifact_content_sha256": _sealed(manifest_material),
    }
    _write_exclusive(
        output_root / "ISSUE-SOURCE-REHOMING-PROPOSALS-5.json",
        _pretty_json(manifest),
    )
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
    return manifest


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        fingerprint = _sha256(f"{type(exc).__name__}:{exc}".encode())
        material = {
            "schema": "legalbot.v111.phase2a.issue-source-rehoming-failure.v1",
            "status": "FAILED_DIAGNOSTICS_PERSISTED_BEFORE_EXIT",
            "failure_type": type(exc).__name__,
            "failure_message": str(exc),
            "failure_fingerprint": fingerprint,
            "affected_stage": "PHASE2A_OFFICIAL_UKSC_SOURCE_REHOMING",
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        manifest = _collect(
            plan_path=args.plan.resolve(strict=True),
            output_root=output_root,
            retrieved_at=datetime.now(UTC),
        )
    except Exception as exc:
        _persist_failure(output_root, exc)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": manifest["status"],
                "record_count": manifest["record_count"],
                "affected_row_count": manifest["affected_row_count"],
                "artifact_content_sha256": manifest["artifact_content_sha256"],
                "source_admitted": False,
                "candidate_mutated": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
