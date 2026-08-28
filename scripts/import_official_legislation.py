#!/usr/bin/env python3
"""Download a reviewed pack of as-enacted legislation from Legislation.gov.uk.

The importer is deliberately narrow: it accepts only the checked-in manifest,
the allowlisted official host and PDF responses whose first pages contain the
reviewed Act or instrument title. It never overwrites different bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "official_legislation_pack.json"
DEFAULT_REPORT = (
    PROJECT_ROOT / "data" / "review_queue" / "official-legislation-download-2026-08-12.json"
)
OFFICIAL_ORIGIN = "https://www.legislation.gov.uk"
MAX_PDF_BYTES = 64 * 1024 * 1024


class OfficialPdfNeedsHtml(ValueError):
    """The official PDF is access- or permission-encrypted; use official HTML."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--destination-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def _safe_leaf(title: str) -> str:
    value = re.sub(r"[/:\\\x00-\x1f]+", " ", title)
    value = " ".join(value.split()).strip(" .")
    if not value or value in {".", ".."}:
        raise ValueError("official title cannot form a safe filename")
    return f"{value}.pdf"


def _normalise(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "legalbot.official-legislation-pack.v1":
        raise ValueError("unsupported official legislation manifest")
    if payload.get("source") != f"{OFFICIAL_ORIGIN}/":
        raise ValueError("official legislation manifest origin is not allowlisted")
    items = payload.get("items")
    if not isinstance(items, list) or not items:
        raise ValueError("official legislation manifest is empty")
    identities: set[str] = set()
    titles: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("official legislation item must be an object")
        identity = str(item.get("identity") or "")
        title = " ".join(str(item.get("title") or "").split())
        folder = " ".join(str(item.get("subject_folder") or "").split())
        filename = str(item.get("pdf_filename") or "")
        if not re.fullmatch(r"(?:ukpga|uksi)/[A-Za-z0-9-]+(?:/[A-Za-z0-9-]+){1,2}", identity):
            raise ValueError("official legislation identity is invalid")
        if not title or not folder or not re.fullmatch(r"(?:ukpga|uksi)_\d{8}_en\.pdf", filename):
            raise ValueError("official legislation metadata is incomplete")
        if identity in identities or title.casefold() in titles:
            raise ValueError("official legislation manifest contains a duplicate")
        identities.add(identity)
        titles.add(title.casefold())
    return payload


def _official_pdf_url(item: dict[str, Any]) -> str:
    url = f"{OFFICIAL_ORIGIN}/{item['identity']}/pdfs/{item['pdf_filename']}"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.legislation.gov.uk":
        raise ValueError("official PDF URL escaped the allowlisted origin")
    return url


def _official_html_url(item: dict[str, Any]) -> str:
    url = f"{OFFICIAL_ORIGIN}/{item['identity']}/enacted/data.html"
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "www.legislation.gov.uk":
        raise ValueError("official HTML URL escaped the allowlisted origin")
    return url


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _verify_pdf(path: Path, *, title: str) -> tuple[int, int]:
    if path.stat().st_size > MAX_PDF_BYTES:
        raise ValueError("official PDF exceeds the bounded file size")
    with path.open("rb") as stream:
        if stream.read(5) != b"%PDF-":
            raise ValueError("official response is not a PDF")
    reader = PdfReader(path)
    if reader.is_encrypted:
        raise OfficialPdfNeedsHtml("official PDF requires the official HTML representation")
    pages = min(3, len(reader.pages))
    opening = " ".join((reader.pages[index].extract_text() or "") for index in range(pages))
    if _normalise(title) not in _normalise(opening):
        raise OfficialPdfNeedsHtml(
            "official PDF title is not extractable; use the verified official HTML"
        )
    return len(reader.pages), path.stat().st_size


def _verify_html(path: Path, *, title: str) -> int:
    if path.stat().st_size > MAX_PDF_BYTES:
        raise ValueError("official HTML exceeds the bounded file size")
    raw = path.read_bytes()
    if b"<html" not in raw[:100_000].lower() and b"<!doctype" not in raw[:100_000].lower():
        raise ValueError("official response is not HTML")
    visible = html.unescape(raw.decode("utf-8", errors="strict"))
    if _normalise(title) not in _normalise(visible):
        raise ValueError("official HTML title does not match the reviewed manifest")
    return len(raw)


def _download_html(client: httpx.Client, item: dict[str, Any], pdf_target: Path) -> dict[str, Any]:
    title = str(item["title"])
    target = pdf_target.with_suffix(".html")
    if target.exists():
        size = _verify_html(target, title=title)
        return {
            "identity": item["identity"],
            "title": title,
            "status": "already_present",
            "representation": "official_as_enacted_html",
            "sha256": _sha256(target),
            "bytes": size,
            "pages": None,
        }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".official-law-incoming-", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        total = 0
        digest = hashlib.sha256()
        with (
            os.fdopen(descriptor, "wb") as output,
            client.stream(
                "GET",
                _official_html_url(item),
                headers={"User-Agent": "LegalBotResearch/1.0"},
            ) as response,
        ):
            response.raise_for_status()
            content_type = response.headers.get("content-type", "").casefold()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                raise ValueError("official endpoint did not return HTML content")
            for block in response.iter_bytes(1024 * 1024):
                total += len(block)
                if total > MAX_PDF_BYTES:
                    raise ValueError("official HTML exceeds the bounded file size")
                output.write(block)
                digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        size = _verify_html(temporary, title=title)
        os.chmod(temporary, 0o444)
        os.replace(temporary, target)
        return {
            "identity": item["identity"],
            "title": title,
            "status": "downloaded",
            "representation": "official_as_enacted_html",
            "sha256": digest.hexdigest(),
            "bytes": size,
            "pages": None,
        }
    finally:
        temporary.unlink(missing_ok=True)


def _download(client: httpx.Client, item: dict[str, Any], target: Path) -> dict[str, Any]:
    title = str(item["title"])
    if target.with_suffix(".html").exists():
        return _download_html(client, item, target)
    if target.exists():
        try:
            pages, size = _verify_pdf(target, title=title)
        except OfficialPdfNeedsHtml:
            return _download_html(client, item, target)
        return {
            "identity": item["identity"],
            "title": title,
            "status": "already_present",
            "representation": "official_as_enacted_pdf",
            "sha256": _sha256(target),
            "bytes": size,
            "pages": pages,
        }

    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".official-law-incoming-", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        total = 0
        digest = hashlib.sha256()
        with (
            os.fdopen(descriptor, "wb") as output,
            client.stream(
                "GET",
                _official_pdf_url(item),
                headers={"Accept": "application/pdf", "User-Agent": "LegalBotResearch/1.0"},
            ) as response,
        ):
            response.raise_for_status()
            if "application/pdf" not in response.headers.get("content-type", "").casefold():
                raise ValueError("official endpoint did not return PDF content")
            for block in response.iter_bytes(1024 * 1024):
                total += len(block)
                if total > MAX_PDF_BYTES:
                    raise ValueError("official PDF exceeds the bounded file size")
                output.write(block)
                digest.update(block)
            output.flush()
            os.fsync(output.fileno())
        try:
            pages, size = _verify_pdf(temporary, title=title)
        except OfficialPdfNeedsHtml:
            return _download_html(client, item, target)
        os.chmod(temporary, 0o444)
        os.replace(temporary, target)
        return {
            "identity": item["identity"],
            "title": title,
            "status": "downloaded",
            "representation": "official_as_enacted_pdf",
            "sha256": digest.hexdigest(),
            "bytes": size,
            "pages": pages,
        }
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    args = _parser().parse_args()
    manifest = _load_manifest(args.manifest)
    destination = args.destination_root.expanduser().resolve()
    if not destination.is_dir():
        raise SystemExit("destination source root does not exist")
    output: list[dict[str, Any]] = []
    with httpx.Client(timeout=45, follow_redirects=False, trust_env=False) as client:
        for item in manifest["items"]:
            folder = (
                destination
                / "Official Legislation"
                / "United Kingdom"
                / "As Enacted"
                / item["subject_folder"]
            )
            target = folder / _safe_leaf(str(item["title"]))
            result = _download(client, item, target)
            output.append(result)
            extent = f"{result['pages']} pages" if result["pages"] else result["representation"]
            print(f"{result['identity']}: {result['status']} ({extent})")

    report = {
        "schema": "legalbot.official-legislation-download-report.v1",
        "manifest_version": manifest["version"],
        "created_at": datetime.now(UTC).isoformat(),
        "version_status": manifest["version_status"],
        "licence": manifest["licence"],
        "items": output,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary_report = args.report.with_suffix(".tmp")
    temporary_report.write_text(
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_report, args.report)
    print(f"complete: {len(output)} official historical sources verified")


if __name__ == "__main__":
    main()
