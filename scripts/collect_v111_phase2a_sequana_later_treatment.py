#!/usr/bin/env python3
"""Quarantine the bounded official Jardine/Sequana later-treatment lead.

This collector handles one individually identified official JCPC judgment.  It
does not search a corpus, make a later-treatment decision, admit a source, or
mutate any candidate.  Exact paragraphs containing the target citation are
retained as owner-review evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = (
    PROJECT_ROOT
    / "config/phase2a_targeted_later_treatment_sources.2026-08-25.v1.json"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-25/phase2a-targeted-later-treatment-sequana-r56"
)
ALLOWED_HOSTS = frozenset({"jcpc.uk", "www.jcpc.uk"})
EXPECTED_AS_OF_DATE = date(2026, 8, 14)
EXPECTED_DISCOVERY_DATE = date(2026, 8, 25)
EXPECTED_ITEM_COUNT = 1
MAX_HTML_BYTES = 8 * 1024 * 1024
USER_AGENT = "LegalBot-v1.11-Phase2A-Sequana-official-review/1.0"
_NEUTRAL_CITATION = re.compile(
    r"^\[(?P<year>\d{4})\]\s+(?P<court>UKSC|UKPC|UKHL)\s+(?P<number>\d+)$"
)
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


def _normal_text(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    host = (parsed.hostname or "").casefold()
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise ValueError("phase2a_sequana_later_treatment_url_outside_allowlist")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("phase2a_sequana_later_treatment_url_forbidden_component")
    if parsed.port not in (None, 443):
        raise ValueError("phase2a_sequana_later_treatment_url_nonstandard_port")
    if not parsed.path.startswith("/cases/judgments/jcpc-"):
        raise ValueError("phase2a_sequana_later_treatment_url_path_invalid")
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def _load_plan(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, Mapping):
        raise ValueError("phase2a_sequana_later_treatment_plan_not_object")
    return value


def _validate_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    items = plan.get("items")
    if (
        plan.get("schema")
        != "legalbot.v111.phase2a.targeted-later-treatment-plan.v2"
        or plan.get("as_of_date") != EXPECTED_AS_OF_DATE.isoformat()
        or plan.get("discovered_at") != EXPECTED_DISCOVERY_DATE.isoformat()
        or plan.get("purpose")
        != "TARGETED_NON_BULK_OFFICIAL_PRIMARY_LATER_TREATMENT_LEAD_ONLY"
        or plan.get("bulk_search") is not False
        or plan.get("owner_later_treatment_decision_required") is not True
        or plan.get("owner_source_admission_required") is not True
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("technical_qualification_assigned") is not False
        or plan.get("phase2b_authorized") is not False
        or plan.get("development30_authorized") is not False
        or not isinstance(items, list)
        or len(items) != EXPECTED_ITEM_COUNT
        or not isinstance(items[0], Mapping)
    ):
        raise ValueError("phase2a_sequana_later_treatment_plan_boundary_invalid")
    item = dict(items[0])
    official_url = _safe_url(str(item.get("official_case_url") or ""))
    targets = item.get("target_neutral_citations")
    if (
        item.get("lead_id") != "later-treatment-lead-010"
        or item.get("candidate_case_id") != "jcpc-2024-0077"
        or item.get("candidate_neutral_citation") != "[2025] UKPC 34"
        or item.get("candidate_judgment_date") != "2025-07-24"
        or item.get("court_weight") != "JCPC_PERSUASIVE"
        or item.get("owner_decision_required") is not True
        or not str(item.get("candidate_case_name") or "").strip()
        or not str(item.get("provisional_relationship") or "").startswith(
            "POTENTIAL_"
        )
        or not isinstance(targets, list)
        or targets != ["[2022] UKSC 25"]
        or any(_NEUTRAL_CITATION.fullmatch(str(value)) is None for value in targets)
    ):
        raise ValueError("phase2a_sequana_later_treatment_plan_item_invalid")
    item["official_case_url"] = official_url
    return item


def _judgment_date(page_text: str) -> date:
    match = _JUDGMENT_DATE.search(page_text)
    if match is None:
        raise ValueError("phase2a_sequana_later_treatment_judgment_date_missing")
    return datetime.strptime(match.group("date"), "%d %B %Y").date()


def _exact_target_paragraphs(
    page_html: bytes,
    *,
    target_citations: list[str],
) -> list[dict[str, Any]]:
    soup = BeautifulSoup(page_html, "html.parser")
    paragraphs: list[dict[str, Any]] = []
    seen: set[str] = set()
    for paragraph in soup.find_all("p"):
        text = _normal_text(paragraph.get_text(" ", strip=True))
        matched = [citation for citation in target_citations if citation in text]
        if not text or not matched:
            continue
        digest = _sha256(text.encode("utf-8"))
        if digest in seen:
            continue
        paragraphs.append(
            {
                "exact_text": text,
                "exact_text_sha256": digest,
                "matched_target_citations": matched,
                "selector": "official_case_page:p",
                "text_is_contiguous_dom_paragraph": True,
            }
        )
        seen.add(digest)
    return paragraphs


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _get_bounded(client: httpx.Client, url: str) -> httpx.Response:
    response = client.get(_safe_url(url))
    response.raise_for_status()
    _safe_url(str(response.url))
    if len(response.content) > MAX_HTML_BYTES:
        raise ValueError("phase2a_sequana_later_treatment_response_too_large")
    if "html" not in response.headers.get("content-type", "").casefold():
        raise ValueError("phase2a_sequana_later_treatment_case_page_not_html")
    return response


def collect(
    *,
    plan_path: Path,
    output_root: Path,
    retrieved_at: datetime,
) -> dict[str, Any]:
    if retrieved_at.tzinfo is None:
        raise ValueError("phase2a_sequana_later_treatment_retrieved_at_naive")
    item = _validate_plan(_load_plan(plan_path))
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_sequana_later_treatment_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_sequana_later_treatment_output_mode_invalid")

    plan_file_sha256 = _sha256_file(plan_path)
    intent_material = {
        "schema": "legalbot.v111.phase2a.sequana-later-treatment-intent.v1",
        "status": "ONE_OFFICIAL_PRIMARY_SOURCE_QUARANTINE_ONLY",
        "retrieved_at": retrieved_at.astimezone(UTC).isoformat(timespec="seconds"),
        "as_of_date": EXPECTED_AS_OF_DATE.isoformat(),
        "source_plan_file_sha256": plan_file_sha256,
        "bulk_search": False,
        "owner_decision_applied": False,
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

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html"}
    with httpx.Client(
        headers=headers,
        follow_redirects=True,
        max_redirects=5,
        timeout=httpx.Timeout(60),
    ) as client:
        page = _get_bounded(client, str(item["official_case_url"]))

    page_raw = page.content
    page_path = output_root / "official-case-page.html"
    _write_exclusive(page_path, page_raw)
    page_text = _normal_text(BeautifulSoup(page_raw, "html.parser").get_text(" ", strip=True))
    decision_date = _judgment_date(page_text)
    if decision_date.isoformat() != item["candidate_judgment_date"]:
        raise ValueError("phase2a_sequana_later_treatment_judgment_date_mismatch")
    if decision_date > EXPECTED_AS_OF_DATE:
        raise ValueError("phase2a_sequana_later_treatment_after_target_ceiling")
    if item["candidate_neutral_citation"] not in page_text:
        raise ValueError("phase2a_sequana_later_treatment_candidate_citation_missing")

    target_citations = [str(value) for value in item["target_neutral_citations"]]
    exact_paragraphs = _exact_target_paragraphs(
        page_raw,
        target_citations=target_citations,
    )
    matched_targets = {
        citation
        for paragraph in exact_paragraphs
        for citation in paragraph["matched_target_citations"]
    }
    if matched_targets != set(target_citations):
        raise ValueError("phase2a_sequana_later_treatment_exact_span_missing")

    spans_material = {
        "schema": "legalbot.v111.phase2a.sequana-exact-review-spans.v1",
        "official_source_relative_path": str(page_path.relative_to(PROJECT_ROOT)),
        "official_source_sha256": _sha256(page_raw),
        "target_neutral_citations": target_citations,
        "exact_paragraph_count": len(exact_paragraphs),
        "exact_paragraphs": exact_paragraphs,
        "derived_for_owner_review_only": True,
        "source_admitted": False,
        "indexed": False,
        "embedded": False,
    }
    spans = {
        **spans_material,
        "artifact_content_sha256": _sha256(_canonical_json(spans_material)),
    }
    spans_path = output_root / "EXACT-REVIEW-SPANS.json"
    _write_exclusive(spans_path, _pretty_json(spans))

    manifest_material = {
        "schema": "legalbot.v111.phase2a.sequana-later-treatment-quarantine.v1",
        "status": "OFFICIAL_LEAD_QUARANTINED_OWNER_REVIEW_REQUIRED",
        "source_intent_content_sha256": intent["intent_content_sha256"],
        "source_plan_file_sha256": plan_file_sha256,
        "as_of_date": EXPECTED_AS_OF_DATE.isoformat(),
        "lead_id": item["lead_id"],
        "candidate_case_id": item["candidate_case_id"],
        "candidate_case_name": item["candidate_case_name"],
        "candidate_neutral_citation": item["candidate_neutral_citation"],
        "candidate_judgment_date": decision_date.isoformat(),
        "court_weight": item["court_weight"],
        "provisional_relationship": item["provisional_relationship"],
        "target_neutral_citations": target_citations,
        "official_case_page": {
            "url": str(page.url),
            "relative_path": str(page_path.relative_to(PROJECT_ROOT)),
            "sha256": _sha256(page_raw),
            "bytes": len(page_raw),
        },
        "exact_review_spans": {
            "relative_path": str(spans_path.relative_to(PROJECT_ROOT)),
            "artifact_content_sha256": spans["artifact_content_sha256"],
            "exact_paragraph_count": len(exact_paragraphs),
        },
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "owner_decision_required": True,
        "owner_decision": None,
        "source_admission_required": True,
        "source_admitted": False,
        "indexed": False,
        "embedded": False,
        "technical_qualification_assigned": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    manifest = {
        **manifest_material,
        "artifact_content_sha256": _sha256(_canonical_json(manifest_material)),
    }
    manifest_path = output_root / "SEQUANA-LATER-TREATMENT-LEAD.json"
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
        "exact_paragraph_count": len(exact_paragraphs),
        "owner_decision_applied": False,
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
                "schema": "legalbot.v111.phase2a.sequana-later-treatment-failure.v1",
                "status": "FAILED_DIAGNOSTICS_PERSISTED_BEFORE_EXIT",
                "failure_type": type(exc).__name__,
                "failure_message": str(exc),
                "failure_fingerprint": _failure_fingerprint(exc),
                "affected_stage": "PHASE2A_SEQUANA_LATER_TREATMENT_QUARANTINE",
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
