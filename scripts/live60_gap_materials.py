#!/usr/bin/env python3
"""Acquire remaining Live60 knowledge-gap materials and ingest them locally.

Does not seal expert gold, promote ACTIVE, issue O-04, or activate candidate
assessment rules.  Full-text is taken only from official or last-resort public
hosts; paywalled and SRA materials stay rights-held.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
SCRIPTS_ROOT = Path(__file__).resolve().parent
for extra in (BACKEND_ROOT, SCRIPTS_ROOT):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from live60_apply_owner_delegated_fixes import apply_ticks, load_repair_payload  # noqa: E402

from app.config import Settings  # noqa: E402
from app.crypto import LocalCipher  # noqa: E402
from app.db import Database  # noqa: E402
from app.evaluation.live_suite_tick_draft import (  # noqa: E402
    lookup_spans_by_document_sha256,
    parse_issue_pinpoint_locators,
)
from app.ingestion.service import ingest_explicit_paths  # noqa: E402

OUT = PROJECT_ROOT / "Live60-2026-08-16" / "go-execution"
ARTIFACTS = PROJECT_ROOT / "Live60-2026-08-16" / "artifacts"
LAW_ROOT = Path.home() / "Desktop" / "Law"
AUDIT_DOCX = (
    Path.home() / "Downloads" / "LegalBot-Repository-Knowledge-And-Assessment-Gap-Audit.docx"
)
EXPECTED_AUDIT_SHA256 = "e01a0f5c43499713a61ad70bb6bbba555ea5bfccb3f8247869ff98f130e7cc1d"
USER_AGENT = "LegalBot-local-mechanical-check/1.0"
MAX_BYTES = 64 * 1024 * 1024
LEGISLATION_DIR = LAW_ROOT / "Official Legislation" / "live60-acquired-2026-08-16"
JUDGMENT_DIR = LAW_ROOT / "Official Legislation" / "live60-gap-judgments-2026-08-16"
ASSESSMENT_DIR = LAW_ROOT / "Assessment guidance" / "OSCOLA-5-official-2026"
TREATY_DIR = LAW_ROOT / "Official Legislation" / "live60-gap-treaties-2026-08-16"

TRUNCATED_LEGISLATION = (
    ("ENTERPRISE", "https://www.legislation.gov.uk/ukpga/2002/40/data.xml"),
    ("POCA", "https://www.legislation.gov.uk/ukpga/2002/29/data.xml"),
    ("TCPA", "https://www.legislation.gov.uk/ukpga/1990/8/data.xml"),
    ("ITEPA", "https://www.legislation.gov.uk/ukpga/2003/1/data.xml"),
    ("ITTOIA", "https://www.legislation.gov.uk/ukpga/2005/5/data.xml"),
    ("CTA2010", "https://www.legislation.gov.uk/ukpga/2010/4/data.xml"),
    ("CTA2009", "https://www.legislation.gov.uk/ukpga/2009/4/data.xml"),
    ("FA2004", "https://www.legislation.gov.uk/ukpga/2004/12/data.xml"),
)
UNINGESTED_KEYS = frozenset(
    {
        "ENTERPRISE",
        "UKGDPR",
        "POCA",
        "TCPA",
        "ROME_I",
        "ROME_II",
        "ITEPA",
        "ITTOIA",
        "CTA2010",
        "CTA2009",
        "FA2004",
    }
)
EUR_FULL_LEGISLATION = (
    ("UKGDPR", "https://www.legislation.gov.uk/eur/2016/679/data.xml"),
    ("ROME_I", "https://www.legislation.gov.uk/eur/2008/593/data.xml"),
    ("ROME_II", "https://www.legislation.gov.uk/eur/2007/864/data.xml"),
)
CASE_URLS: dict[str, tuple[str, ...]] = {
    "HONGKONGFIR": (
        "https://www.bailii.org/ew/cases/EWCA/Civ/1961/7.html",
        "https://www.bailii.org/ew/cases/EWCA/Civ/1961/4.html",
    ),
    "BUNGE": ("https://www.bailii.org/uk/cases/UKHL/1981/11.html",),
    "HADLEY": ("https://www.bailii.org/ew/cases/EWHC/Exch/1854/J70.html",),
    "BRITISH_WESTINGHOUSE": (
        "https://www.bailii.org/uk/cases/UKHL/1912/2.html",
        "https://www.bailii.org/uk/cases/UKHL/1912/1912.html",
    ),
    "CHURCH": (
        "https://www.bailii.org/ew/cases/EWCA/Crim/1965/4.html",
        "https://www.bailii.org/ew/cases/EWCA/Crim/1965/1.html",
    ),
    "NEWBURY": ("https://www.bailii.org/uk/cases/UKHL/1976/3.html",),
    "BLAUE": ("https://www.bailii.org/ew/cases/EWCA/Crim/1975/3.html",),
    "ALLIED_MAPLES": ("https://www.bailii.org/ew/cases/EWCA/Civ/1995/17.html",),
    "SANG": ("https://www.bailii.org/uk/cases/UKHL/1979/3.html",),
    "TURNBULL": ("https://www.bailii.org/ew/cases/EWCA/Crim/1976/4.html",),
    "BOLAND": ("https://www.bailii.org/uk/cases/UKHL/1980/4.html",),
    "COUGHLAN": (
        "https://caselaw.nationalarchives.gov.uk/ewca/civ/1999/1871",
        "https://www.bailii.org/ew/cases/EWCA/Civ/1999/1871.html",
    ),
    "COOLEY": (
        "https://www.bailii.org/ew/cases/EWHC/Ch/1972/1.html",
        "https://www.bailii.org/ew/cases/EWHC/Ch/1972/1972.html",
    ),
    "MILROY": ("https://www.bailii.org/ew/cases/EWHC/Ch/1862/J78.html",),
    "BANKS": ("https://www.bailii.org/ew/cases/EWHC/QB/1870/J83.html",),
    "BOLAM": (
        "https://www.bailii.org/ew/cases/EWHC/QB/1957/1.html",
        "https://www.bailii.org/ew/cases/EWHC/QB/1957/1957.html",
    ),
    "ROMALPA": ("https://www.bailii.org/ew/cases/EWCA/Civ/1976/3.html",),
    "CLOUGH": ("https://www.bailii.org/ew/cases/EWCA/Civ/1984/12.html",),
    "HELY": ("https://www.bailii.org/ew/cases/EWCA/Civ/1967/2.html",),
    "FREEMAN": ("https://www.bailii.org/ew/cases/EWCA/Civ/1964/1.html",),
    "ARMAGAS": ("https://www.bailii.org/uk/cases/UKHL/1986/10.html",),
    "FIRST_ENERGY": (
        "https://www.bailii.org/ew/cases/EWCA/Civ/1993/1.html",
        "https://www.bailii.org/ew/cases/EWCA/Civ/1993/10.html",
    ),
    "COLLEN": ("https://www.bailii.org/ew/cases/EWHC/QB/1857/J45.html",),
    "JOLLEY": (
        "https://caselaw.nationalarchives.gov.uk/ukhl/2000/31",
        "https://www.bailii.org/uk/cases/UKHL/2000/31.html",
    ),
    "HASELDINE": ("https://www.bailii.org/ew/cases/EWCA/Civ/1941/1.html",),
    "LEE_PARKER": ("https://www.bailii.org/ew/cases/EWHC/Ch/1971/1.html",),
    "BONDWORTH": ("https://www.bailii.org/ew/cases/EWHC/Ch/1979/1.html",),
    "BORDEN": ("https://www.bailii.org/ew/cases/EWCA/Civ/1979/4.html",),
    "MCGOVERN": ("https://www.bailii.org/ew/cases/EWHC/Ch/1981/1.html",),
    "BOWMAN": ("https://www.bailii.org/uk/cases/UKHL/1917/1.html",),
    "CLARK_UNI": (
        "https://caselaw.nationalarchives.gov.uk/ewca/civ/2000/129",
        "https://www.bailii.org/ew/cases/EWCA/Civ/2000/129.html",
    ),
    "TRIATHLON": (
        "https://caselaw.nationalarchives.gov.uk/ukut/lc/2024/33",
        "https://caselaw.nationalarchives.gov.uk/ukut/lc/2024/26",
        "https://www.bailii.org/uk/cases/UKUT/LC/2024/33.html",
        "https://www.bailii.org/uk/cases/UKUT/LC/2024/26.html",
    ),
}
OSCOLA5_URLS = (
    (
        "OSCOLA-5.pdf",
        "https://www.law.ox.ac.uk/sites/default/files/2026-03/OSCOLA%205.pdf",
    ),
    (
        "OSCOLA-5-quick-reference.pdf",
        "https://www.law.ox.ac.uk/sites/default/files/2026-03/OSCOLA%205th%20Edition%20-%20Quick%20Reference%20Guide.pdf",
    ),
    (
        "OSCOLA-5-key-changes.pdf",
        "https://www.law.ox.ac.uk/sites/default/files/2026-04/OSCOLA%20key%20changes.pdf",
    ),
)
TREATY_URLS = (
    (
        "REFUGEE",
        "https://www.ohchr.org/sites/default/files/refugees.pdf",
    ),
    (
        "REFUGEE",
        "https://www.unhcr.org/media/convention-and-protocol-relating-status-refugees",
    ),
)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def fetch_to_path(url: str, dest: Path) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        with urlopen(request, timeout=60) as response:
            status = int(getattr(response, "status", 200) or 200)
            media = str(response.headers.get("Content-Type") or "")
            final_url = str(response.geturl() or url)
            dest.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            size = 0
            truncated = False
            with dest.open("wb") as handle:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    if size > MAX_BYTES:
                        handle.write(block[: max(0, MAX_BYTES - (size - len(block)))])
                        truncated = True
                        break
                    handle.write(block)
                    digest.update(block)
            if truncated:
                dest.unlink(missing_ok=True)
                return {
                    "ok": False,
                    "http_status": status,
                    "final_url": final_url,
                    "error": "truncated",
                    "bytes": size,
                }
            return {
                "ok": 200 <= status < 300 and dest.stat().st_size > 400,
                "http_status": status,
                "final_url": final_url,
                "media_type": media,
                "sha256": digest.hexdigest(),
                "bytes": dest.stat().st_size,
                "error": "",
            }
    except HTTPError as exc:
        return {
            "ok": False,
            "http_status": int(exc.code),
            "final_url": url,
            "error": "HTTPError",
            "bytes": 0,
        }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "http_status": 0,
            "final_url": url,
            "error": type(exc).__name__,
            "bytes": 0,
        }


def html_looks_like_judgment(path: Path) -> bool:
    raw = path.read_bytes()[:8000].lower()
    if b"<html" not in raw and b"<!doctype" not in raw:
        return path.stat().st_size > 2000
    blocked = (b"404 not found", b"no matching", b"search results", b"page not found")
    return not any(token in raw for token in blocked)


def copy_audit_docx() -> dict[str, Any]:
    digest = sha256_file(AUDIT_DOCX)
    dest = OUT / "inputs" / "LegalBot-Repository-Knowledge-And-Assessment-Gap-Audit.docx"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(AUDIT_DOCX, dest)
    return {
        "copied": True,
        "sha256": digest,
        "matches_reported_digest": digest == EXPECTED_AUDIT_SHA256,
        "bytes": dest.stat().st_size,
        "destination_alias": "Live60-2026-08-16/go-execution/inputs/LegalBot-Repository-Knowledge-And-Assessment-Gap-Audit.docx",
    }


def extract_audit_tables() -> dict[str, Any]:
    from docx import Document

    document = Document(str(AUDIT_DOCX))

    def rows(index: int) -> list[dict[str, str]]:
        table = document.tables[index]
        headers = [cell.text.strip() for cell in table.rows[0].cells]
        payload = []
        for row in table.rows[1:]:
            payload.append({headers[i]: row.cells[i].text.strip() for i in range(len(headers))})
        return payload

    candidate_rules = rows(14)
    missing_materials = rows(15)
    no_url_sources = rows(92)
    write_json(
        OUT / "candidate-assessment-rules-2026-08-16.json",
        {
            "schema": "legalbot.candidate-assessment-rules.v1",
            "as_of_date": "2026-08-16",
            "status": "owner_review_required",
            "not_live": True,
            "do_not_bulk_approve": True,
            "active_bundle_untouched": "owner-standards-2026-08-14.1",
            "oscola_fourth_edition_must_not_overwrite_oscola_5": True,
            "rules": candidate_rules,
            "seals_expert_gold": False,
        },
    )
    write_json(
        OUT / "missing-assessment-materials-queue.json",
        {
            "schema": "legalbot.missing-assessment-materials.v1",
            "items": missing_materials,
            "no_url_sources": no_url_sources,
        },
    )
    return {
        "candidate_rule_count": len(candidate_rules),
        "missing_material_count": len(missing_materials),
        "no_url_source_count": len(no_url_sources),
    }


def redownload_truncated_legislation() -> list[dict[str, Any]]:
    LEGISLATION_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for key, url in TRUNCATED_LEGISLATION:
        dest = LEGISLATION_DIR / f"{key}-full.xml"
        fetched = fetch_to_path(url, dest)
        record = {
            "source_key": key,
            "requested_url": url,
            "host": urlparse(url).hostname,
            "rights": "open_government_licence",
            **fetched,
        }
        if fetched.get("ok"):
            final = LEGISLATION_DIR / f"{key}-{fetched['sha256'][:16]}.xml"
            dest.replace(final)
            for stale in LEGISLATION_DIR.glob(f"{key}-*.xml"):
                if stale.resolve() != final.resolve():
                    stale.unlink()
            record["stored_alias"] = (
                f"desktop-law/Official Legislation/live60-acquired-2026-08-16/{final.name}"
            )
            record["sha256"] = fetched["sha256"]
        else:
            dest.unlink(missing_ok=True)
        results.append(record)
        time.sleep(0.2)
    return results


def redownload_eur_full_legislation() -> list[dict[str, Any]]:
    LEGISLATION_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for key, url in EUR_FULL_LEGISLATION:
        dest = LEGISLATION_DIR / f"{key}-full.xml"
        fetched = fetch_to_path(url, dest)
        record = {
            "source_key": key,
            "requested_url": url,
            "host": urlparse(url).hostname,
            "rights": "open_government_licence",
            **fetched,
        }
        if fetched.get("ok"):
            final = LEGISLATION_DIR / f"{key}-{fetched['sha256'][:16]}.xml"
            dest.replace(final)
            for stale in LEGISLATION_DIR.glob(f"{key}-*.xml"):
                if stale.resolve() != final.resolve():
                    stale.unlink()
            record["stored_alias"] = (
                f"desktop-law/Official Legislation/live60-acquired-2026-08-16/{final.name}"
            )
            record["sha256"] = fetched["sha256"]
        else:
            dest.unlink(missing_ok=True)
        results.append(record)
        time.sleep(0.2)
    return results


def download_cases() -> list[dict[str, Any]]:
    JUDGMENT_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for key, urls in CASE_URLS.items():
        record: dict[str, Any] = {
            "source_key": key,
            "outcome": "unresolved",
            "attempts": [],
        }
        for url in urls:
            host = (urlparse(url).hostname or "").casefold()
            suffix = (
                ".html"
                if "bailii.org" in host or "caselaw.nationalarchives.gov.uk" in host
                else ".bin"
            )
            dest = JUDGMENT_DIR / f"{key}-trial{suffix}"
            fetched = fetch_to_path(url, dest)
            attempt = {"requested_url": url, "host": host, **fetched}
            record["attempts"].append(
                {
                    k: attempt[k]
                    for k in ("requested_url", "host", "ok", "http_status", "error")
                    if k in attempt
                }
            )
            if not fetched.get("ok"):
                dest.unlink(missing_ok=True)
                continue
            if suffix == ".html" and not html_looks_like_judgment(dest):
                dest.unlink(missing_ok=True)
                continue
            digest = sha256_file(dest)
            final = JUDGMENT_DIR / f"{key}-{digest[:16]}{suffix}"
            dest.replace(final)
            record.update(
                {
                    "outcome": "downloaded",
                    "sha256": digest,
                    "bytes": final.stat().st_size,
                    "final_url": fetched.get("final_url"),
                    "host": host,
                    "rights": (
                        "open_justice_licence_computational_use_not_separately_licensed"
                        if "caselaw.nationalarchives.gov.uk" in host
                        else "bailii_last_resort_public_representation"
                    ),
                    "stored_alias": f"desktop-law/Official Legislation/live60-gap-judgments-2026-08-16/{final.name}",
                }
            )
            break
        results.append(record)
        time.sleep(0.25)
    return results


def download_assessment_and_treaties() -> dict[str, Any]:
    ASSESSMENT_DIR.mkdir(parents=True, exist_ok=True)
    TREATY_DIR.mkdir(parents=True, exist_ok=True)
    oscola = []
    for name, url in OSCOLA5_URLS:
        dest = ASSESSMENT_DIR / name
        fetched = fetch_to_path(url, dest)
        oscola.append(
            {
                "name": name,
                "requested_url": url,
                "lane": "assessment_guidance",
                "does_not_overwrite_renderer": True,
                **fetched,
            }
        )
        time.sleep(0.2)
    treaties = []
    for key, url in TREATY_URLS:
        dest = TREATY_DIR / f"{key}-trial.bin"
        fetched = fetch_to_path(url, dest)
        if fetched.get("ok"):
            digest = sha256_file(dest)
            suffix = (
                ".pdf"
                if "pdf" in (fetched.get("media_type") or "").casefold() or url.endswith(".pdf")
                else ".html"
            )
            final = TREATY_DIR / f"{key}-{digest[:16]}{suffix}"
            dest.replace(final)
            treaties.append(
                {
                    "source_key": key,
                    "requested_url": url,
                    "sha256": digest,
                    "ok": True,
                    "stored_alias": f"desktop-law/Official Legislation/live60-gap-treaties-2026-08-16/{final.name}",
                }
            )
            break
        dest.unlink(missing_ok=True)
        treaties.append(
            {
                "source_key": key,
                "requested_url": url,
                "ok": False,
                "error": fetched.get("error"),
                "http_status": fetched.get("http_status"),
            }
        )
        time.sleep(0.2)
    return {"oscola5": oscola, "treaties": treaties}


def collect_ingest_paths() -> list[Path]:
    paths: list[Path] = []
    for key in UNINGESTED_KEYS:
        matches = sorted(
            LEGISLATION_DIR.glob(f"{key}-*.xml"),
            key=lambda item: item.stat().st_size,
        )
        if matches:
            paths.append(matches[-1])
    if JUDGMENT_DIR.is_dir():
        paths.extend(
            sorted(
                path
                for path in JUDGMENT_DIR.iterdir()
                if path.is_file() and path.suffix in {".html", ".pdf", ".xml"}
            )
        )
    if TREATY_DIR.is_dir():
        paths.extend(sorted(path for path in TREATY_DIR.iterdir() if path.is_file()))
    if ASSESSMENT_DIR.is_dir():
        paths.extend(sorted(path for path in ASSESSMENT_DIR.iterdir() if path.is_file()))
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def source_hash_map(
    case_records: list[dict[str, Any]], legislation_records: list[dict[str, Any]]
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    staged = json.loads((OUT / "missing-legislation-staged.json").read_text(encoding="utf-8"))
    for item in staged["items"]:
        mapping[item["source_key"]] = item["sha256"]
    for record in legislation_records:
        if record.get("ok") and record.get("sha256"):
            mapping[record["source_key"]] = record["sha256"]
    for record in case_records:
        if record.get("outcome") == "downloaded" and record.get("sha256"):
            mapping[record["source_key"]] = record["sha256"]
    for path in LEGISLATION_DIR.glob("*.xml"):
        key = path.name.split("-", 1)[0]
        mapping[key] = sha256_file(path)
    if TREATY_DIR.is_dir():
        for path in TREATY_DIR.glob("REFUGEE-*"):
            mapping["REFUGEE"] = sha256_file(path)
    if JUDGMENT_DIR.is_dir():
        for path in JUDGMENT_DIR.iterdir():
            if path.is_file() and "-" in path.stem:
                mapping[path.name.split("-", 1)[0]] = sha256_file(path)
    return mapping


def enrich_evidence(hash_map: dict[str, str]) -> dict[str, Any]:
    evidence_path = OUT / "issue-candidate-evidence-map.json"
    payload = json.loads(evidence_path.read_text(encoding="utf-8"))
    catalog = PROJECT_ROOT / "data" / "catalog.sqlite3"
    added = 0
    for issue in payload["issues"]:
        for candidate in issue.get("candidates") or ():
            key = str(candidate.get("source_key") or "")
            digest = hash_map.get(key)
            if not digest:
                continue
            locators = parse_issue_pinpoint_locators(str(candidate.get("pinpoint") or ""))
            if not locators:
                continue
            matches = lookup_spans_by_document_sha256(
                catalog_path=catalog,
                document_sha256=digest,
                locators=locators,
            )
            existing = {
                span.get("chunk_id")
                for span in candidate.get("local_spans") or ()
                if span.get("chunk_id")
            }
            for span in matches:
                if span["chunk_id"] in existing:
                    continue
                candidate.setdefault("local_spans", []).append(span)
                existing.add(span["chunk_id"])
                added += 1
        present = [
            span
            for candidate in issue.get("candidates") or ()
            for span in candidate.get("local_spans") or ()
            if span.get("catalogue_present") or span.get("chunk_id")
        ]
        issue["catalogue_span_hit_count"] = len(present)
        if present and not issue.get("proposed_span"):
            issue["proposed_span"] = present[0]
            issue["reason"] = "candidate_spans_present_but_owner_has_not_ticked_qualified"
    write_json(evidence_path, payload)
    return {"spans_added": added, "issue_count": len(payload["issues"])}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--skip-ingest", action="store_true")
    args = parser.parse_args()
    audit = copy_audit_docx()
    tables = extract_audit_tables()
    legislation_records: list[dict[str, Any]] = []
    case_records: list[dict[str, Any]] = []
    extras: dict[str, Any] = {}
    if not args.skip_download:
        legislation_records = redownload_truncated_legislation()
        case_records = download_cases()
        extras = download_assessment_and_treaties()
    eur_records = redownload_eur_full_legislation()
    legislation_records = [*legislation_records, *eur_records]
    ingest_result = None
    if not args.skip_ingest:
        paths = collect_ingest_paths()
        settings = Settings(project_root=PROJECT_ROOT)
        database = Database(settings.database_path)
        database.initialize()
        cipher = LocalCipher.from_local_key(create=True)
        database.migrate_sensitive_content(cipher)
        ingest_result = ingest_explicit_paths(
            settings,
            database,
            cipher,
            os.urandom(8).hex(),
            paths,
        )
        database.close()
        write_json(OUT / "gap-materials-ingest.json", ingest_result)
    if not case_records:
        previous = OUT / "gap-materials-report.json"
        if previous.is_file():
            prior = json.loads(previous.read_text(encoding="utf-8"))
            case_records = prior.get("cases") or []
            extras = extras or prior.get("assessment_and_treaties") or {}
            if not legislation_records:
                legislation_records = prior.get("truncated_legislation") or []
    hash_map = source_hash_map(case_records, legislation_records)
    write_json(
        OUT / "acquired-source-hash-map.json",
        {"schema": "legalbot.acquired-source-hash-map.v1", "items": hash_map},
    )
    enriched = enrich_evidence(hash_map)
    repair = load_repair_payload(ARTIFACTS / "held-span-contiguous-repair-v2.json") or {}
    ticks = apply_ticks(catalog=PROJECT_ROOT / "data" / "catalog.sqlite3", repair=dict(repair))
    report = {
        "schema": "legalbot.live60-gap-materials.v1",
        "retrieved_at": utc_now(),
        "audit_docx": audit,
        "audit_tables": tables,
        "truncated_legislation": [
            {k: v for k, v in item.items() if k != "raw"}
            for item in legislation_records
            if item.get("source_key") not in {"UKGDPR", "ROME_I", "ROME_II"}
        ],
        "eur_full_legislation": [
            {k: v for k, v in item.items() if k != "raw"} for item in eur_records
        ],
        "cases": [
            {
                "source_key": item.get("source_key"),
                "outcome": item.get("outcome"),
                "host": item.get("host"),
                "http_status": (item.get("attempts") or [{}])[-1].get("http_status")
                if item.get("outcome") != "downloaded"
                else 200,
                "sha256": item.get("sha256"),
                "rights": item.get("rights"),
                "final_url": item.get("final_url"),
            }
            for item in case_records
        ],
        "assessment_and_treaties": extras,
        "ingest": {
            "file_count": None if ingest_result is None else ingest_result.get("file_count"),
            "ingested": None if ingest_result is None else ingest_result.get("ingested"),
            "wrote_active": False,
        },
        "evidence_enrichment": enriched,
        "tick_progress": ticks["progress"],
        "candidate_rules_live": False,
        "wrote_active": False,
        "wrote_o04": False,
        "seals_expert_gold": False,
    }
    write_json(OUT / "gap-materials-report.json", report)
    print(
        json.dumps(
            {
                "audit_hash_ok": audit["matches_reported_digest"],
                "cases_downloaded": sum(
                    1 for item in case_records if item.get("outcome") == "downloaded"
                ),
                "legislation_full": sum(1 for item in legislation_records if item.get("ok")),
                "ingested": None if ingest_result is None else ingest_result.get("ingested"),
                "spans_added": enriched["spans_added"],
                "progress": ticks["progress"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
