#!/usr/bin/env python3
"""Check unreviewed unified-index sources against the official record.

Owner direction 2026-09-25: research mode serves unreviewed sources labelled
"[unverified source]"; this pass upgrades those it can check automatically.

* Legislation (legislation.gov.uk XML): identity = same DocumentURI and title as
  the official record; currentness = the local copy is the latest revised
  version on legislation.gov.uk. Outstanding (unapplied) amendments are counted.
* Judgments (Find Case Law XML): identity = same neutral citation and name, and
  normally byte-identical to the official XML. Later treatment (appeal,
  overruling) cannot be checked automatically, so currentness stays unverified.
* Titled sources without an official URI: an exact, unique official title match
  gives identity only.

Only the official hosts allowed by ``ge_factual_gap_fill.host_allowed`` are
contacted. Results go to data/indexes/unified-local-v1/VERIFICATION.json, which
the research retriever reads at query time. The catalogue is not modified and
nothing is marked admitted, legally reviewed or gold: this is an automated
official-record check, not legal review.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.evaluation.ge_factual_gap_fill import (  # noqa: E402
    default_fetch,
    host_allowed,
    normalize_title,
    resolve_official,
)
from app.evaluation.ge_official_currentness_metadata import (  # noqa: E402
    extract_official_xml_metadata,
)

INDEX = ROOT / "data/indexes/unified-local-v1"
LEDGER = INDEX / "VERIFICATION.json"
VAULT = ROOT / "data/vault/objects/sha256"
SQL = """
SELECT sv.id, sv.title, d.lane, d.content_sha256, d.media_type
FROM documents d JOIN source_versions sv ON sv.document_id = d.id
WHERE d.duplicate_of IS NULL AND d.status = 'citable' AND sv.superseded_by IS NULL
  AND sv.review_status = 'staged' AND d.lane IN ('primary_authority', 'official_secondary')
ORDER BY sv.id
"""
_DOC_URI = re.compile(rb'DocumentURI="(https?://www\.legislation\.gov\.uk/[^"]+)"')
_DC_TITLE = re.compile(rb"<dc:title>([^<]+)</dc:title>")
_NEUTRAL = re.compile(rb"<uk:cite>([^<]+)</uk:cite>")
_FRBR_NAME = re.compile(rb'<FRBRname value="([^"]+)"')
_FRBR_URI = re.compile(rb'<FRBRuri value="(https://caselaw\.nationalarchives\.gov\.uk/[^"]+)"')
_SI_PREFIX = {"uksi": "SI", "ssi": "SSI", "wsi": "SI", "nisr": "SR"}
PAUSE_SECONDS = 0.5


def _raw(content_sha256: str) -> bytes | None:
    path = VAULT / content_sha256[:2] / content_sha256
    return path.read_bytes() if path.is_file() else None


def _text(pattern: re.Pattern[bytes], raw: bytes, limit: int = 200_000) -> str:
    match = pattern.search(raw[:limit])
    if not match:
        return ""
    return " ".join(html.unescape(match.group(1).decode("utf-8", "replace")).split())


def oscola_case_name(name: str) -> str:
    """Find Case Law lists Crown cases as 'Noye, R. v'; OSCOLA writes 'R v Noye'."""

    match = re.fullmatch(r"(.+?),\s*R\.?\s+v", name.strip())
    return f"R v {match.group(1)}" if match else name.strip()


def legislation_citation(title: str, uri: str) -> dict[str, Any]:
    parts = uri.rstrip("/").split("/")
    kind = parts[3] if len(parts) > 3 else ""
    if kind in _SI_PREFIX and len(parts) > 5:
        return {
            "source_type": "statutory_instrument",
            "title": title,
            "instrument_number": f"{_SI_PREFIX[kind]} {parts[4]}/{parts[5]}",
        }
    return {"source_type": "legislation", "title": title}


def check_legislation(raw: bytes, fetch=default_fetch) -> dict[str, Any]:
    uri = _text(_DOC_URI, raw, 4_000)
    local_title = _text(_DC_TITLE, raw)
    local = extract_official_xml_metadata(raw)
    base = uri.replace("http://", "https://", 1)
    official_url = f"{base}/contents/data.xml"
    result = fetch(official_url)
    if not result.get("ok"):
        return {"kind": "legislation", "status": "fetch_failed", "official_url": official_url,
                "error": result.get("error")}
    body = result["body"]
    official_uri = _text(_DOC_URI, body, 4_000)
    official_title = _text(_DC_TITLE, body)
    official = extract_official_xml_metadata(body)
    identity = bool(official_uri) and official_uri.rstrip("/") == uri.rstrip("/") and (
        normalize_title(official_title) == normalize_title(local_title)
    )
    local_version = local["source_version_date"]
    official_version = official["source_version_date"]
    current = identity and bool(local_version) and local_version == official_version
    effects = int(official["unapplied_effect_markup_count"] or 0)
    citation = legislation_citation(official_title or local_title, uri) if identity else None
    if citation is not None and effects:
        citation["research_note"] = "check amendments not yet applied on legislation.gov.uk"
    if citation is not None and identity and not current:
        citation["research_note"] = (
            f"local text is the {local_version or 'undated'} version; "
            f"legislation.gov.uk now has {official_version}"
        )
    return {
        "kind": "legislation",
        "status": "checked",
        "official_url": official_url,
        "official_sha256": result["sha256"],
        "identity_verified": identity,
        "currentness_verified": current,
        "currentness_status": (
            "latest_available_revised_snapshot" if current
            else "superseded_revised_version" if identity else "unknown"
        ),
        "local_version_date": local_version,
        "official_version_date": official_version,
        "unapplied_effects": effects,
        "citation_data": citation,
    }


def check_judgment(raw: bytes, content_sha256: str, fetch=default_fetch) -> dict[str, Any]:
    neutral = _text(_NEUTRAL, raw)
    name = _text(_FRBR_NAME, raw)
    uri = _text(_FRBR_URI, raw).replace("gov.uk/id/", "gov.uk/", 1)
    official_url = f"{uri.rstrip('/')}/data.xml"
    result = fetch(official_url)
    if not result.get("ok"):
        return {"kind": "judgment", "status": "fetch_failed", "official_url": official_url,
                "error": result.get("error")}
    body = result["body"]
    identity = (
        _text(_NEUTRAL, body) == neutral and bool(neutral)
        and normalize_title(_text(_FRBR_NAME, body)) == normalize_title(name)
    )
    citation = None
    if identity:
        citation = {
            "source_type": "case",
            "case_name": oscola_case_name(name),
            "neutral_citation": neutral,
            "research_note": "later treatment not checked",
        }
    return {
        "kind": "judgment",
        "status": "checked",
        "official_url": official_url,
        "official_sha256": result["sha256"],
        "byte_identical": result["sha256"] == content_sha256,
        "identity_verified": identity,
        "currentness_verified": False,
        "currentness_status": "case_later_treatment_unchecked",
        "citation_data": citation,
    }


def check_by_title(title: str, fetch=default_fetch) -> dict[str, Any]:
    spec = resolve_official(title, fetch)
    if not spec:
        return {"kind": "unidentified", "status": "needs_identification"}
    url = spec.get("url") or f"https://www.legislation.gov.uk/{spec.get('identifier', '')}"
    if not host_allowed(url):
        return {"kind": "unidentified", "status": "needs_identification"}
    if spec.get("kind") == "judgment":
        citation = None  # a name match alone does not supply the neutral citation safely
    else:
        citation = legislation_citation(title, url)
        citation["research_note"] = "local copy's version date not checked"
    return {
        "kind": f"{spec.get('kind', 'official')}_title_match",
        "status": "checked",
        "official_url": url,
        "identity_verified": citation is not None,
        "currentness_verified": False,
        "currentness_status": "unknown",
        "citation_data": citation,
    }


def verify_source(title: str, content_sha256: str, fetch=default_fetch) -> dict[str, Any]:
    raw = _raw(content_sha256)
    if raw is None:
        return {"kind": "missing", "status": "raw_bytes_missing"}
    if _DOC_URI.search(raw[:4_000]):
        return check_legislation(raw, fetch)
    if _NEUTRAL.search(raw[:200_000]) and _FRBR_URI.search(raw[:200_000]):
        return check_judgment(raw, content_sha256, fetch)
    if title and not re.match(r"source-[0-9a-f]+\.", title):
        return check_by_title(title, fetch)
    return {"kind": "unidentified", "status": "needs_identification"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0, help="Check at most N new sources")
    parser.add_argument("--recheck", action="store_true", help="Re-check sources already in the ledger")
    args = parser.parse_args()
    ledger: dict[str, Any] = (
        json.loads(LEDGER.read_text()) if LEDGER.is_file()
        else {"schema": "legalbot.unified-verification.v1", "entries": {}}
    )
    entries: dict[str, Any] = ledger["entries"]
    catalogue = sqlite3.connect(f"file:{ROOT / 'data/catalog.sqlite3'}?mode=ro", uri=True)
    rows = catalogue.execute(SQL).fetchall()
    done = 0
    for source_version_id, title, lane, content_sha256, _media in rows:
        if source_version_id in entries and not args.recheck:
            continue
        entry = verify_source(title or "", content_sha256)
        entry.update({"lane": lane, "title": title, "checked_at": datetime.now(UTC).isoformat()})
        entries[source_version_id] = entry
        done += 1
        if entry.get("official_url"):
            time.sleep(PAUSE_SECONDS)
        if done % 10 == 0:
            LEDGER.write_text(json.dumps(ledger, indent=1) + "\n")
            print(f"{done} checked", flush=True)
        if args.limit and done >= args.limit:
            break
    ledger["updated_at"] = datetime.now(UTC).isoformat()
    summary: dict[str, int] = {}
    for entry in entries.values():
        key = (
            f"{entry.get('kind')}:"
            f"{'identity' if entry.get('identity_verified') else entry.get('status')}"
            f"{'+current' if entry.get('currentness_verified') else ''}"
        )
        summary[key] = summary.get(key, 0) + 1
    ledger["summary"] = dict(sorted(summary.items()))
    LEDGER.write_text(json.dumps(ledger, indent=1) + "\n")
    print(json.dumps(ledger["summary"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
