#!/usr/bin/env python3
"""Resolve noisy seminar legislation titles against legislation.gov.uk only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT = PROJECT_ROOT / "data/reports/seminar-authority-coverage-2026-08-26-v5.json"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-title-resolution-2026-08-26.json"
)
REPORT_SCHEMA = "legalbot.seminar-gap-legislation-title-resolution.v1"
OFFICIAL_HOST = "www.legislation.gov.uk"
ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
SPACE = re.compile(r"\s+")
NON_ALNUM = re.compile(r"[^a-z0-9]+")
TITLE_END = re.compile(
    r"(?P<body>.+?\b(?:Act|Regulations|Rules|Order|Measure)\s+(?:18|19|20)\d{2})$",
    re.IGNORECASE,
)
SAFE_PREFIXES = re.compile(
    r"^(?:(?:cf\.?|see|under|use|note|if|introduction|scope of|impact of|"
    r"amendment of|reform in|ops for)\s+|s\d+(?:\([^)]*\))?\s+of\s+)",
    re.IGNORECASE,
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("legislation_resolution_input_must_be_object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _identity(value: str) -> str:
    normalised = NON_ALNUM.sub(" ", value.casefold()).strip()
    return normalised.removeprefix("the ")


def _clean(value: str) -> str:
    return SPACE.sub(" ", value.replace("’", "'")).strip(" \t\r\n.,:;()")


def _title_candidates(reference: str) -> list[str]:
    match = TITLE_END.search(_clean(reference))
    if match is None:
        return []
    base = _clean(match.group("body"))
    seeds = [base]
    lowered = base.casefold()
    last_the = lowered.rfind(" the ")
    if last_the >= 0:
        seeds.append(_clean(base[last_the + 5 :]))
    if ". " in base:
        seeds.append(_clean(base.rsplit(". ", 1)[-1]))

    stripped = base
    while True:
        next_value = _clean(SAFE_PREFIXES.sub("", stripped, count=1))
        if next_value == stripped:
            break
        seeds.append(next_value)
        stripped = next_value

    words = base.split()
    marker_index = next(
        (
            index
            for index, word in enumerate(words)
            if word.casefold().strip("(),") in {"act", "regulations", "rules", "order", "measure"}
        ),
        -1,
    )
    if marker_index >= 1:
        first_index = max(0, marker_index - 7)
        for index in range(first_index, marker_index):
            seeds.append(_clean(" ".join(words[index:])))

    candidates: list[str] = []
    seen: set[str] = set()
    for seed in seeds:
        seed = _clean(seed.replace(") ", " "))
        if not TITLE_END.fullmatch(seed):
            continue
        identity = _identity(seed)
        if identity in seen or len(identity.split()) < 3:
            continue
        seen.add(identity)
        candidates.append(seed)
    return candidates


class _OfficialTitleSearch:
    def __init__(self, *, timeout_seconds: float, delay_seconds: float) -> None:
        self.timeout_seconds = timeout_seconds
        self.delay_seconds = delay_seconds
        self.cache: dict[str, dict[str, Any]] = {}

    def search(self, candidate: str) -> dict[str, Any]:
        key = _identity(candidate)
        if key in self.cache:
            return self.cache[key]
        encoded = urllib.parse.quote(candidate, safe="")
        url = f"https://{OFFICIAL_HOST}/title/{encoded}/data.feed"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/atom+xml",
                "User-Agent": "LegalBot-v1.11-official-title-resolution/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
                    raise ValueError("legislation_search_redirected_outside_official_host")
                raw = response.read()
        except (TimeoutError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            result = {
                "candidate": candidate,
                "exact_matches": [],
                "reason_code": "official_title_search_http_error",
                "error_type": type(exc).__name__,
            }
        else:
            root = ET.fromstring(raw)
            exact: list[dict[str, str]] = []
            for entry in root.findall(f"{{{ATOM_NAMESPACE}}}entry"):
                title_node = entry.find(f"{{{ATOM_NAMESPACE}}}title")
                id_node = entry.find(f"{{{ATOM_NAMESPACE}}}id")
                title = _clean(title_node.text or "") if title_node is not None else ""
                official_id = (id_node.text or "").strip() if id_node is not None else ""
                if _identity(title) != key or not official_id:
                    continue
                parsed_id = urllib.parse.urlsplit(official_id)
                if parsed_id.hostname != OFFICIAL_HOST:
                    continue
                canonical_url = urllib.parse.urlunsplit(
                    ("https", OFFICIAL_HOST, parsed_id.path.rstrip("/"), "", "")
                )
                exact.append({"official_title": title, "canonical_url": canonical_url})
            exact = sorted(
                {item["canonical_url"]: item for item in exact}.values(),
                key=lambda item: item["canonical_url"],
            )
            result = {
                "candidate": candidate,
                "exact_matches": exact,
                "reason_code": (
                    "official_exact_title_match"
                    if len(exact) == 1
                    else "official_exact_title_ambiguous"
                    if exact
                    else "official_exact_title_not_found"
                ),
            }
        self.cache[key] = result
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return result


def resolve(*, audit_path: Path, timeout_seconds: float, delay_seconds: float) -> dict[str, Any]:
    audit = _load(audit_path)
    if audit.get("schema") != "legalbot.seminar-authority-coverage-audit.v3":
        raise ValueError("legislation_resolution_audit_schema_invalid")
    search = _OfficialTitleSearch(
        timeout_seconds=timeout_seconds,
        delay_seconds=delay_seconds,
    )
    records: list[dict[str, Any]] = []
    for reference in audit["references"]:
        if (
            reference.get("kind") != "legislation_title"
            or int(reference.get("presentation_document_count") or 0) <= 0
            or reference.get("coverage_status") != "catalogue_missing"
        ):
            continue
        extracted = str(reference["reference"])
        candidates = _title_candidates(extracted)
        attempts: list[dict[str, Any]] = []
        exact_matches: dict[str, dict[str, str]] = {}
        for candidate in candidates:
            attempt = search.search(candidate)
            attempts.append(attempt)
            for item in attempt["exact_matches"]:
                exact_matches[item["canonical_url"]] = item
            if len(exact_matches) == 1:
                break
        matches = sorted(exact_matches.values(), key=lambda item: item["canonical_url"])
        resolution_status = (
            "OFFICIAL_IDENTITY_RESOLVED_OWNER_REVIEW_REQUIRED"
            if len(matches) == 1
            else "OFFICIAL_IDENTITY_AMBIGUOUS_OWNER_REVIEW_REQUIRED"
            if matches
            else "UNRESOLVED_RESEARCH_REQUIRED"
        )
        records.append(
            {
                "extracted_reference": extracted,
                "extracted_reference_sha256": hashlib.sha256(extracted.encode("utf-8")).hexdigest(),
                "presentation_subjects": sorted(
                    str(value) for value in reference.get("presentation_subjects", [])
                ),
                "candidate_count": len(candidates),
                "attempts": attempts,
                "official_exact_matches": matches,
                "resolution_status": resolution_status,
                "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                "currentness_gate": "OWNER_REVIEW_REQUIRED",
            }
        )
    status_counts = Counter(record["resolution_status"] for record in records)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "as_of_date": "2026-08-26",
        "audit_sha256": _sha256(audit_path),
        "official_source_host": OFFICIAL_HOST,
        "matching_policy": (
            "Only an exact normalised title match in an official legislation.gov.uk Atom entry "
            "is accepted. Search ranking and fuzzy results are ignored."
        ),
        "summary": {
            "reference_count": len(records),
            "official_identity_resolved_count": status_counts[
                "OFFICIAL_IDENTITY_RESOLVED_OWNER_REVIEW_REQUIRED"
            ],
            "official_identity_ambiguous_count": status_counts[
                "OFFICIAL_IDENTITY_AMBIGUOUS_OWNER_REVIEW_REQUIRED"
            ],
            "unresolved_count": status_counts["UNRESOLVED_RESEARCH_REQUIRED"],
            "unique_official_queries": len(search.cache),
            "official_query_http_error_count": sum(
                attempt["reason_code"] == "official_title_search_http_error"
                for record in records
                for attempt in record["attempts"]
            ),
        },
        "records": records,
        "teaching_lane_use": "GAP_DISCOVERY_ONLY_NOT_LEGAL_AUTHORITY",
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_gold_change": False,
        "automatic_download": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
        "live_activation_authorized": False,
    }
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    report["report_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


def _write_exclusive(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    parser.add_argument("--delay-seconds", type=float, default=0.05)
    args = parser.parse_args()
    report = resolve(
        audit_path=args.audit,
        timeout_seconds=max(args.timeout_seconds, 1.0),
        delay_seconds=max(args.delay_seconds, 0.0),
    )
    _write_exclusive(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
