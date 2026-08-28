#!/usr/bin/env python3
"""Collect exact official later-treatment evidence for four direct-ready holds.

The collection is a bounded, exact-citation review.  It is not a bulk Find
Case Law analysis and absence from the returned results is never treated as
proof that no later treatment exists.  All bytes remain in quarantine and the
result is advisory only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from lxml import etree

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = (
    PROJECT_ROOT / "config/phase2a_direct_hold_later_treatment.2026-08-27.v1.json"
)
DEFAULT_QUARANTINE = (
    PROJECT_ROOT
    / "data/quarantine/2026-08-27/phase2a-direct-hold-later-treatment-r1"
)
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
    / "DIRECT-HOLD-LATER-TREATMENT-ADVISORY-4.json"
)
EXPECTED_PLAN_FILE_SHA256 = (
    "34198599ea929042af4b59d4e34f3003cc7be8a1626b296d393932782a54c5b9"
)
EXPECTED_SOURCE_QUEUE_SHA256 = (
    "155af28ca81bb6848a875fab8173e0f646339282d695d2ae61edece143bda7a5"
)
ALLOWED_HOST = "caselaw.nationalarchives.gov.uk"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
USER_AGENT = "LegalBot-v1.11-targeted-exact-citation-review/1.0"
AKN_NS = "http://docs.oasis-open.org/legaldocml/ns/akn/3.0"
ATOM_NS = "http://www.w3.org/2005/Atom"
_PARAGRAPH_ID = re.compile(r"^para_[1-9][0-9]{0,3}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _safe_url(value: str, *, atom: bool = False) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").casefold() != ALLOWED_HOST
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in (None, 443)
    ):
        raise ValueError("phase2a_direct_hold_url_invalid")
    if atom:
        if parsed.path != "/atom.xml":
            raise ValueError("phase2a_direct_hold_atom_url_invalid")
    elif not parsed.path.endswith("/data.xml"):
        raise ValueError("phase2a_direct_hold_source_url_invalid")
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def _search_url(citation: str) -> str:
    return _safe_url(
        "https://caselaw.nationalarchives.gov.uk/atom.xml?"
        + urlencode({"query": citation, "per_page": 50, "page": 1}),
        atom=True,
    )


def _load_plan(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_direct_hold_plan_must_be_regular_file")
    if _sha256_file(path) != EXPECTED_PLAN_FILE_SHA256:
        raise ValueError("phase2a_direct_hold_plan_identity_invalid")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_direct_hold_plan_must_be_object")
    return value


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    targets = plan.get("targets")
    if (
        plan.get("schema")
        != "legalbot.v111.phase2a.direct-hold-later-treatment-plan.v1"
        or plan.get("purpose")
        != "TARGETED_NON_BULK_EXACT_CITATION_LATER_TREATMENT_FOR_DIRECT_READY_ROWS"
        or plan.get("source_ceiling_date") != "2026-08-14"
        or plan.get("as_of_date") != "2026-08-14"
        or plan.get("source_queue_content_sha256") != EXPECTED_SOURCE_QUEUE_SHA256
        or plan.get("bulk_search") is not False
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("owner_outcomes_applied") is not False
        or plan.get("candidate_mutated") is not False
        or plan.get("technical_qualification_assigned") is not False
        or plan.get("phase2b_authorized") is not False
        or not isinstance(targets, list)
        or len(targets) != 4
    ):
        raise ValueError("phase2a_direct_hold_plan_boundary_invalid")
    validated: list[dict[str, Any]] = []
    seen_targets: set[str] = set()
    seen_rows: set[str] = set()
    seen_urls: set[str] = set()
    candidate_count = 0
    for raw_target in targets:
        if not isinstance(raw_target, Mapping):
            raise ValueError("phase2a_direct_hold_target_invalid")
        target = dict(raw_target)
        citation = str(target.get("target_neutral_citation") or "")
        rows = target.get("row_ids")
        candidates = target.get("candidates")
        if (
            not citation.startswith("[")
            or citation in seen_targets
            or not isinstance(rows, list)
            or not rows
            or any(not isinstance(row, str) or row in seen_rows for row in rows)
            or not isinstance(candidates, list)
            or not candidates
            or not str(target.get("recommended_owner_outcome") or "").strip()
        ):
            raise ValueError("phase2a_direct_hold_target_invalid")
        clean_candidates: list[dict[str, Any]] = []
        for raw_candidate in candidates:
            if not isinstance(raw_candidate, Mapping):
                raise ValueError("phase2a_direct_hold_candidate_invalid")
            candidate = dict(raw_candidate)
            url = _safe_url(str(candidate.get("official_url") or ""))
            paragraph_ids = candidate.get("exact_paragraph_ids")
            if (
                url in seen_urls
                or not str(candidate.get("neutral_citation") or "").startswith("[")
                or not str(candidate.get("title") or "").strip()
                or not str(candidate.get("advisory_relationship") or "").strip()
                or candidate.get("candidate_existing") not in {True, False}
                or not isinstance(paragraph_ids, list)
                or not paragraph_ids
                or any(
                    not isinstance(value, str) or _PARAGRAPH_ID.fullmatch(value) is None
                    for value in paragraph_ids
                )
                or len(set(paragraph_ids)) != len(paragraph_ids)
            ):
                raise ValueError("phase2a_direct_hold_candidate_invalid")
            candidate["official_url"] = url
            clean_candidates.append(candidate)
            seen_urls.add(url)
            candidate_count += 1
        target["candidates"] = clean_candidates
        validated.append(target)
        seen_targets.add(citation)
        seen_rows.update(rows)
    if candidate_count != 7 or len(seen_rows) != 4:
        raise ValueError("phase2a_direct_hold_plan_scope_invalid")
    return tuple(validated)


def _fetch(client: httpx.Client, url: str, *, atom: bool = False) -> bytes:
    safe = _safe_url(url, atom=atom)
    with client.stream("GET", safe) as response:
        response.raise_for_status()
        _safe_url(str(response.url), atom=atom)
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ValueError("phase2a_direct_hold_response_too_large")
            chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw or b"<!DOCTYPE" in raw[:100_000].upper() or b"<!ENTITY" in raw[:100_000].upper():
        raise ValueError("phase2a_direct_hold_response_invalid")
    etree.fromstring(raw)
    return raw


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


def _judgment_metadata(raw: bytes) -> tuple[str, date, etree._Element]:
    root = etree.fromstring(raw)
    namespace = {"akn": AKN_NS, "tna": "https://caselaw.nationalarchives.gov.uk/akn"}
    citations = root.xpath(".//tna:cite/text()", namespaces=namespace)
    dates = root.xpath(
        './/akn:FRBRdate[@name="judgment"]/@date', namespaces=namespace
    )
    if len(set(citations)) != 1 or not dates:
        raise ValueError("phase2a_direct_hold_judgment_metadata_invalid")
    judgment_date = date.fromisoformat(str(dates[0])[:10])
    if judgment_date > date(2026, 8, 14):
        raise ValueError("phase2a_direct_hold_judgment_after_source_ceiling")
    return str(citations[0]).strip(), judgment_date, root


def _paragraph_spans(
    root: etree._Element, paragraph_ids: list[str], *, source_sha256: str
) -> list[dict[str, Any]]:
    namespace = {"akn": AKN_NS}
    spans: list[dict[str, Any]] = []
    for paragraph_id in paragraph_ids:
        matches = root.xpath(
            f'.//akn:paragraph[@eId="{paragraph_id}"]', namespaces=namespace
        )
        if len(matches) != 1:
            raise ValueError("phase2a_direct_hold_exact_paragraph_missing")
        exact_text = " ".join("".join(matches[0].itertext()).split())
        if not 20 <= len(exact_text) <= 20_000:
            raise ValueError("phase2a_direct_hold_exact_paragraph_invalid")
        material = {
            "schema": "legalbot.v111.phase2a.direct-hold-exact-span.v1",
            "source_sha256": source_sha256,
            "paragraph_id": paragraph_id,
            "exact_text": exact_text,
            "exact_text_sha256": _sha256(exact_text.encode("utf-8")),
            "exact_text_is_contiguous_in_official_xml": True,
        }
        spans.append({**material, "span_content_sha256": _sealed(material)})
    return spans


def _search_evidence(raw: bytes, target: Mapping[str, Any]) -> dict[str, Any]:
    root = etree.fromstring(raw)
    namespace = {"a": ATOM_NS}
    entries: list[dict[str, str]] = []
    for entry in root.xpath(".//a:entry", namespaces=namespace):
        titles = entry.xpath("./a:title//text()", namespaces=namespace)
        links = entry.xpath("./a:link/@href", namespaces=namespace)
        if not links:
            continue
        entries.append(
            {
                "title": " ".join("".join(titles).split()),
                "official_case_url": str(links[0]).rstrip("/"),
            }
        )
    expected_paths = {
        str(candidate["official_url"]).removesuffix("/data.xml")
        for candidate in target["candidates"]
    }
    result_paths = {entry["official_case_url"] for entry in entries}
    if not expected_paths.issubset(result_paths):
        raise ValueError("phase2a_direct_hold_planned_candidate_missing_from_search")
    return {
        "result_count_page_1": len(entries),
        "per_page": 50,
        "planned_candidate_urls_all_present": True,
        "entries": entries,
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
    }


def collect(
    *,
    plan_path: Path,
    quarantine_root: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Download and bind the bounded official representations."""

    if quarantine_root.exists() or quarantine_root.is_symlink():
        raise ValueError("phase2a_direct_hold_quarantine_already_exists")
    if output_path.exists() or output_path.is_symlink():
        raise ValueError("phase2a_direct_hold_output_already_exists")
    plan = _load_plan(plan_path)
    targets = _validate_plan(plan)
    quarantine_root.mkdir(parents=True, mode=0o700)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    client = httpx.Client(
        timeout=httpx.Timeout(45.0),
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    )
    try:
        for target in targets:
            target_citation = str(target["target_neutral_citation"])
            search_url = _search_url(target_citation)
            search_raw = _fetch(client, search_url, atom=True)
            search_sha256 = _sha256(search_raw)
            search_name = f"search-{search_sha256[:20]}.atom.xml"
            _write_exclusive(quarantine_root / search_name, search_raw)
            search = _search_evidence(search_raw, target)
            candidate_records: list[dict[str, Any]] = []
            for candidate in target["candidates"]:
                raw = _fetch(client, str(candidate["official_url"]))
                source_sha256 = _sha256(raw)
                citation, judgment_date, root = _judgment_metadata(raw)
                if citation != candidate["neutral_citation"]:
                    raise ValueError("phase2a_direct_hold_candidate_citation_mismatch")
                member_name = f"judgment-{source_sha256[:20]}.xml"
                _write_exclusive(quarantine_root / member_name, raw)
                material = {
                    "schema": "legalbot.v111.phase2a.direct-hold-candidate-review.v1",
                    "neutral_citation": citation,
                    "title": candidate["title"],
                    "judgment_date": judgment_date.isoformat(),
                    "official_url": candidate["official_url"],
                    "official_source_sha256": source_sha256,
                    "official_source_bytes": len(raw),
                    "quarantine_relative_path": str(
                        (quarantine_root / member_name).relative_to(PROJECT_ROOT)
                    ),
                    "candidate_existing": candidate["candidate_existing"],
                    "source_admission_required_for_treatment_only": False,
                    "advisory_relationship": candidate["advisory_relationship"],
                    "exact_treatment_spans": _paragraph_spans(
                        root,
                        list(candidate["exact_paragraph_ids"]),
                        source_sha256=source_sha256,
                    ),
                    "owner_outcome": None,
                }
                candidate_records.append(
                    {**material, "record_content_sha256": _sealed(material)}
                )
            material = {
                "schema": "legalbot.v111.phase2a.direct-hold-target-review.v1",
                "target_neutral_citation": target_citation,
                "row_ids": target["row_ids"],
                "search_url": search_url,
                "search_sha256": search_sha256,
                "search_bytes": len(search_raw),
                "search_quarantine_relative_path": str(
                    (quarantine_root / search_name).relative_to(PROJECT_ROOT)
                ),
                "search_evidence": search,
                "candidate_reviews": candidate_records,
                "recommended_owner_outcome": target["recommended_owner_outcome"],
                "owner_outcome": None,
            }
            records.append({**material, "record_content_sha256": _sealed(material)})
    except BaseException:
        raise
    finally:
        client.close()

    material = {
        "schema": "legalbot.v111.phase2a.direct-hold-later-treatment-advisory.v1",
        "status": "ADVISORY_ONLY_NOT_OWNER_ADOPTED",
        "created_at": datetime.now(UTC).isoformat(),
        "source_ceiling_date": "2026-08-14",
        "plan_file_sha256": EXPECTED_PLAN_FILE_SHA256,
        "source_queue_content_sha256": EXPECTED_SOURCE_QUEUE_SHA256,
        "record_count": len(records),
        "candidate_review_count": sum(len(row["candidate_reviews"]) for row in records),
        "records": records,
        "targeted_search_is_exhaustive": False,
        "absence_of_other_hits_proves_no_later_treatment": False,
        "owner_outcomes_applied": False,
        "automatic_source_admission": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "active_pointer_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
    }
    result = {**material, "artifact_content_sha256": _sealed(material)}
    _write_exclusive(output_path, _pretty_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--quarantine-root", type=Path, default=DEFAULT_QUARANTINE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = collect(
        plan_path=args.plan,
        quarantine_root=args.quarantine_root,
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "record_count": result["record_count"],
                "candidate_review_count": result["candidate_review_count"],
                "artifact_content_sha256": result["artifact_content_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
