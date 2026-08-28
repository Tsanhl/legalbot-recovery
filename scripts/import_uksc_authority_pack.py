#!/usr/bin/env python3
"""Download a bounded, reviewed UK Supreme Court judgment pack under the OGL."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "uksc_authority_pack.json"
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "sources" / "materials-2026-08-12" / "Official UK Supreme Court"
)
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "uksc-authority-download.json"
NEUTRAL = re.compile(r"\[(?P<year>\d{4})\]\s+UKSC\s+(?P<number>\d+)", re.I)
JUDGMENT_DATE = re.compile(r"Judgment date\s+(?P<date>\d{1,2}\s+[A-Z][a-z]+\s+\d{4})")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def _safe_host(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in {
        "supremecourt.uk",
        "www.supremecourt.uk",
    }


def _judgment_link(page_url: str, soup: BeautifulSoup) -> str:
    for link in soup.find_all("a", href=True):
        text = " ".join(link.get_text(" ", strip=True).casefold().split())
        href = urljoin(page_url, str(link["href"]))
        lowered = href.casefold()
        if (
            "pdf judgment" in text
            or (lowered.endswith(".pdf") and ("judgment" in lowered) and "summary" not in lowered)
        ) and _safe_host(href):
            return href
    raise RuntimeError("official case page has no same-host PDF judgment link")


def main() -> None:
    args = _parser().parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("schema") != "legalbot.uksc-authority-pack.v1":
        raise SystemExit("unsupported UKSC authority manifest")
    items = manifest.get("items")
    if not isinstance(items, list) or len(items) != 15:
        raise SystemExit("reviewed UKSC authority manifest must contain exactly 15 cases")
    results: list[dict[str, object]] = []
    headers = {"User-Agent": "LegalBot-New owner-only source verifier/1.0"}
    with httpx.Client(headers=headers, follow_redirects=True, timeout=60) as client:
        for item in items:
            case_id = str(item["case_id"])
            page_url = f"https://www.supremecourt.uk/cases/{case_id}"
            page = client.get(page_url)
            page.raise_for_status()
            if not _safe_host(str(page.url)):
                raise RuntimeError("case page redirected off the official UKSC host")
            soup = BeautifulSoup(page.text, "html.parser")
            title_node = soup.find("h1")
            title = " ".join(title_node.get_text(" ", strip=True).split()) if title_node else ""
            page_text = " ".join(soup.get_text(" ", strip=True).split())
            citations = {match.group(0) for match in NEUTRAL.finditer(page_text)}
            expected_citation = str(item["neutral_citation"])
            if expected_citation not in citations:
                raise RuntimeError(f"neutral citation mismatch for {case_id}")
            date_match = JUDGMENT_DATE.search(page_text)
            if date_match is None:
                raise RuntimeError(f"judgment date missing for {case_id}")
            judgment_date = (
                datetime.strptime(date_match.group("date"), "%d %B %Y").date().isoformat()
            )
            judgment_url = _judgment_link(str(page.url), soup)
            response = client.get(judgment_url)
            response.raise_for_status()
            if not _safe_host(str(response.url)) or not response.content.startswith(b"%PDF-"):
                raise RuntimeError(f"official judgment is not a same-host PDF for {case_id}")
            if len(response.content) > 25 * 1024 * 1024:
                raise RuntimeError("judgment exceeds the bounded download limit")
            folder = args.output_root / str(item["subject_folder"])
            folder.mkdir(parents=True, exist_ok=True)
            destination = folder / f"{case_id}.pdf"
            if destination.exists() and destination.read_bytes() != response.content:
                raise RuntimeError(f"existing immutable judgment differs: {destination.name}")
            if not destination.exists():
                temporary = destination.with_suffix(".tmp")
                temporary.write_bytes(response.content)
                temporary.replace(destination)
            results.append(
                {
                    "case_id": case_id,
                    "title": title,
                    "neutral_citation": expected_citation,
                    "case_name": item["case_name"],
                    "judgment_date": judgment_date,
                    "subject_folder": item["subject_folder"],
                    "canonical_url": page_url,
                    "judgment_url": judgment_url,
                    "sha256": hashlib.sha256(response.content).hexdigest(),
                    "bytes": len(response.content),
                    "relative_path": str(destination.relative_to(PROJECT_ROOT)),
                    "status": "downloaded",
                }
            )
    report = {
        "schema": "legalbot.uksc-authority-download-report.v1",
        "manifest_version": manifest["version"],
        "as_of_date": manifest["as_of_date"],
        "licence": manifest["licence"],
        "items": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"downloaded": len(results), "report": str(args.report)}, indent=2))


if __name__ == "__main__":
    main()
