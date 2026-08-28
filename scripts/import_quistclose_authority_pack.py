#!/usr/bin/env python3
"""Acquire the bounded, hash-pinned official Quistclose authority pack.

UK Parliament's historic judgment pages may present an anti-bot challenge to a
non-browser HTTP client.  In that case the five exact official pages must first
be exported from a browser into ``--verified-parliament-dir``.  This importer
does not trust that directory: it rechecks the pinned bytes, page identity,
paragraph locators and official URLs before making immutable source copies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "quistclose_authority_pack.json"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "sources" / "materials-2026-08-12" / "Official Quistclose"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "quistclose-authority-download.json"
SCHEMA = "legalbot.quistclose-authority-pack.v1"
REPORT_SCHEMA = "legalbot.quistclose-authority-download-report.v1"
ALLOWED_ROLES = {"holding_ratio", "obiter"}
PARLIAMENT_CONTENT_HOSTS = {"publications.parliament.uk"}
PARLIAMENT_TERMS_HOSTS = {"parliament.uk", "www.parliament.uk"}
UKSC_HOSTS = {"supremecourt.uk", "www.supremecourt.uk"}
OGL_HOSTS = {"nationalarchives.gov.uk", "www.nationalarchives.gov.uk"}
MAX_SOURCE_BYTES = 25 * 1024 * 1024
NEUTRAL = re.compile(r"\[(?P<year>\d{4})\]\s+(?P<court>UKHL|UKSC)\s+(?P<number>\d+)")
JUDGMENT_DATE = re.compile(
    r"Judgment date\s+(?P<date>\d{1,2}\s+[A-Z][a-z]+\s+\d{4})",
    re.IGNORECASE,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--verified-parliament-dir",
        type=Path,
        help="Directory containing the exact official yardle-1.htm ... yardle-5.htm snapshots",
    )
    parser.add_argument(
        "--verified-licence-dir",
        type=Path,
        help="Directory containing the two exact browser-exported official licence pages",
    )
    return parser


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return _sha256(encoded)


def _normalise_text(value: str) -> str:
    return " ".join(value.split())


def _safe_host(url: str, allowed: set[str]) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme == "https"
        and parsed.hostname is not None
        and parsed.hostname.casefold() in allowed
        and not parsed.username
        and not parsed.password
    )


def _require_safe_host(url: str, allowed: set[str], label: str) -> None:
    if not _safe_host(url, allowed):
        raise ValueError(f"{label} is not on an approved official HTTPS host")


def _representation_map(
    manifest: dict[str, Any],
) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    if manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported Quistclose authority manifest")
    items = manifest.get("items")
    if not isinstance(items, list) or len(items) != 3:
        raise ValueError("reviewed Quistclose manifest must contain exactly three cases")
    licences = manifest.get("licences")
    if not isinstance(licences, dict) or set(licences) != {
        "uk_parliament_opl_v3",
        "uksc_ogl_v3",
    }:
        raise ValueError("Quistclose manifest must contain the reviewed OPL and OGL licences")
    licence_snapshot_names: set[str] = set()
    for licence in licences.values():
        snapshot = licence.get("terms_snapshot")
        if not isinstance(snapshot, dict):
            raise ValueError("each reviewed licence must pin an official terms snapshot")
        filename = str(snapshot.get("safe_filename") or "")
        if (
            not filename
            or filename in licence_snapshot_names
            or Path(filename).name != filename
            or filename.startswith(".")
        ):
            raise ValueError("licence terms snapshot filename is unsafe or duplicated")
        licence_snapshot_names.add(filename)
        if not re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("sha256") or "")):
            raise ValueError("licence terms snapshot is not pinned to a SHA-256")
        if not isinstance(snapshot.get("bytes"), int) or not (
            1 <= int(snapshot["bytes"]) <= MAX_SOURCE_BYTES
        ):
            raise ValueError("licence terms snapshot size is missing or out of bounds")
    representations: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    authorities: set[str] = set()
    filenames: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("case record must be an object")
        authority_id = str(item.get("authority_id") or "")
        if authority_id in authorities or not authority_id.startswith("neutral-citation:"):
            raise ValueError("authority identities must be unique neutral citations")
        authorities.add(authority_id)
        citation = str(item.get("neutral_citation") or "")
        if not NEUTRAL.fullmatch(citation):
            raise ValueError("invalid neutral citation in Quistclose manifest")
        try:
            datetime.fromisoformat(str(item.get("decision_date") or ""))
        except ValueError as exc:
            raise ValueError("invalid case decision date") from exc
        licence_id = str(item.get("licence_id") or "")
        if licence_id not in licences:
            raise ValueError("case references an unknown licence")
        case_url = str(item.get("official_case_url") or "")
        expected_hosts = (
            PARLIAMENT_CONTENT_HOSTS if citation.startswith("[2002] UKHL") else UKSC_HOSTS
        )
        _require_safe_host(case_url, expected_hosts, "official case URL")
        case_representations = item.get("representations")
        if not isinstance(case_representations, list) or not case_representations:
            raise ValueError("each case must have an official representation")
        for representation in case_representations:
            if not isinstance(representation, dict):
                raise ValueError("representation must be an object")
            representation_id = str(representation.get("representation_id") or "")
            if not representation_id or representation_id in representations:
                raise ValueError("representation identities must be non-empty and unique")
            official_url = str(representation.get("official_url") or "")
            _require_safe_host(official_url, expected_hosts, "official representation URL")
            safe_filename = str(representation.get("safe_filename") or "")
            if (
                not safe_filename
                or safe_filename in filenames
                or Path(safe_filename).name != safe_filename
                or safe_filename.startswith(".")
            ):
                raise ValueError("representation filename is unsafe or duplicated")
            filenames.add(safe_filename)
            digest = str(representation.get("sha256") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("representation is not pinned to a SHA-256")
            size = representation.get("bytes")
            if not isinstance(size, int) or not (1 <= size <= MAX_SOURCE_BYTES):
                raise ValueError("representation byte size is missing or out of bounds")
            representations[representation_id] = (item, representation)
        passages = item.get("reviewed_passages")
        if not isinstance(passages, list) or not passages:
            raise ValueError("each case must contain reviewed paragraph-role metadata")
        for passage in passages:
            if not isinstance(passage, dict):
                raise ValueError("reviewed passage must be an object")
            if str(passage.get("representation_id") or "") not in {
                str(value["representation_id"]) for value in case_representations
            }:
                raise ValueError(
                    "reviewed passage references another case or a missing representation"
                )
            if passage.get("legal_role") not in ALLOWED_ROLES:
                raise ValueError("legal role must be holding_ratio or obiter")
            if not re.fullmatch(r"\[\d+\](?:-\[\d+\])?", str(passage.get("locator") or "")):
                raise ValueError("reviewed case locator must be a paragraph or paragraph range")
            if not isinstance(passage.get("issues"), list) or not passage["issues"]:
                raise ValueError("reviewed passage must state at least one legal issue")
            if not str(passage.get("review_note") or "").strip():
                raise ValueError(
                    "reviewed passage must explain its conservative role classification"
                )
    if len(representations) != 7:
        raise ValueError("reviewed Quistclose manifest must contain exactly seven representations")
    return representations


def validate_manifest(manifest: dict[str, Any]) -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    """Public validation hook used by the acquisition tool and unit tests."""

    return _representation_map(manifest)


def _paragraph_bounds(locator: str) -> tuple[int, int]:
    numbers = [int(value) for value in re.findall(r"\d+", locator)]
    return numbers[0], numbers[-1]


def _has_paragraph(text: str, paragraph: int) -> bool:
    return re.search(rf"(?:^|\s){paragraph}\.\s", text) is not None


def _verify_locators(item: dict[str, Any], representation_id: str, text: str) -> None:
    for passage in item["reviewed_passages"]:
        if passage["representation_id"] != representation_id:
            continue
        first, last = _paragraph_bounds(str(passage["locator"]))
        if not _has_paragraph(text, first) or not _has_paragraph(text, last):
            raise ValueError(
                f"reviewed locator {passage['locator']} is absent from {representation_id}"
            )


def verify_representation_payload(
    item: dict[str, Any], representation: dict[str, Any], data: bytes
) -> str:
    """Verify pinned bytes, official identity and reviewed paragraph boundaries."""

    if len(data) != int(representation["bytes"]):
        raise ValueError("representation byte size differs from the reviewed manifest")
    if _sha256(data) != representation["sha256"]:
        raise ValueError("representation SHA-256 differs from the reviewed manifest")
    representation_id = str(representation["representation_id"])
    kind = str(representation["kind"])
    if kind == "browser_rendered_official_html_snapshot":
        try:
            html = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("official Parliament snapshot is not UTF-8 HTML") from exc
        soup = BeautifulSoup(html, "html.parser")
        title = _normalise_text(soup.title.get_text(" ", strip=True) if soup.title else "")
        text = _normalise_text(soup.get_text(" ", strip=True))
        if (
            "Twinsectra Limited v Yardley" not in title
            or "Twinsectra Limited v Yardley" not in text
        ):
            raise ValueError("official Parliament judgment identity is absent")
        if representation_id.endswith("part-1"):
            if item["neutral_citation"] not in text or "21 MARCH 2002" not in text.upper():
                raise ValueError("Twinsectra citation or decision date is absent from part 1")
        elif "back to preceding text" not in text.casefold():
            raise ValueError("Twinsectra continuation marker is absent")
        _verify_locators(item, representation_id, text)
        return text
    if kind != "official_pdf" or not data.startswith(b"%PDF-"):
        raise ValueError("UKSC judgment must be a pinned official PDF")
    try:
        text = _normalise_text(
            "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(data)).pages)
        )
    except Exception as exc:  # PDF is an untrusted source boundary.
        raise ValueError("official PDF could not be parsed") from exc
    if item["neutral_citation"] not in text:
        raise ValueError("UKSC neutral citation is absent from the judgment PDF")
    case_tokens = set(re.findall(r"[a-z0-9]+", str(item["case_name"]).casefold()))
    text_tokens = set(re.findall(r"[a-z0-9]+", text[:20_000].casefold()))
    if len(case_tokens & text_tokens) / max(1, len(case_tokens)) < 0.65:
        raise ValueError("UKSC case identity is absent from the judgment PDF")
    _verify_locators(item, representation_id, text)
    return text


def _case_title_matches(expected: str, observed: str) -> bool:
    expected_tokens = set(re.findall(r"[a-z0-9]+", expected.casefold())) - {
        "ltd",
        "limited",
        "pty",
        "and",
        "v",
    }
    observed_tokens = set(re.findall(r"[a-z0-9]+", observed.casefold()))
    return len(expected_tokens & observed_tokens) / max(1, len(expected_tokens)) >= 0.8


def _judgment_link(page_url: str, soup: BeautifulSoup) -> str:
    candidates: list[str] = []
    for link in soup.find_all("a", href=True):
        href = urljoin(page_url, str(link["href"]))
        text = _normalise_text(link.get_text(" ", strip=True)).casefold()
        lowered = href.casefold()
        if (
            lowered.endswith(".pdf")
            and "judgment" in lowered
            and "summary" not in lowered
            and ("judgment" in text or "uploads" in lowered)
        ):
            _require_safe_host(href, UKSC_HOSTS, "UKSC judgment link")
            candidates.append(href)
    unique = list(dict.fromkeys(candidates))
    if len(unique) != 1:
        raise ValueError("official case page must expose exactly one same-host judgment PDF")
    return unique[0]


def _verified_licence_path(staging: Path, filename: str) -> Path:
    candidate = (staging / filename).resolve()
    try:
        candidate.relative_to(staging.resolve())
    except ValueError as exc:
        raise ValueError("licence snapshot escaped the verified staging directory") from exc
    return candidate


def _verify_licences(
    client: httpx.Client,
    manifest: dict[str, Any],
    verified_licence_dir: Path | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for licence_id, licence in manifest["licences"].items():
        terms_url = str(licence.get("terms_url") or licence["url"])
        allowed = PARLIAMENT_TERMS_HOSTS if licence_id == "uk_parliament_opl_v3" else UKSC_HOSTS
        _require_safe_host(terms_url, allowed, "licence terms URL")
        snapshot = licence["terms_snapshot"]
        if verified_licence_dir is not None:
            snapshot_path = _verified_licence_path(
                verified_licence_dir, str(snapshot["safe_filename"])
            )
            if not snapshot_path.is_file():
                raise ValueError(f"verified licence snapshot is missing: {snapshot_path.name}")
            snapshot_data = snapshot_path.read_bytes()
            if len(snapshot_data) != int(snapshot["bytes"]):
                raise ValueError("licence snapshot byte size differs from the manifest")
            if _sha256(snapshot_data) != snapshot["sha256"]:
                raise ValueError("licence snapshot SHA-256 differs from the manifest")
            try:
                snapshot_html = snapshot_data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("licence snapshot is not UTF-8 HTML") from exc
            text = _normalise_text(
                BeautifulSoup(snapshot_html, "html.parser").get_text(" ", strip=True)
            )
            resolved_terms_url = terms_url
            verification = "official_browser_snapshot_markers_and_hash_verified"
        else:
            response = client.get(terms_url)
            response.raise_for_status()
            _require_safe_host(str(response.url), allowed, "licence terms redirect")
            snapshot_data = response.content
            text = _normalise_text(
                BeautifulSoup(response.text, "html.parser").get_text(" ", strip=True)
            )
            resolved_terms_url = str(response.url)
            verification = "official_live_terms_markers_verified"
        missing = [
            marker
            for marker in licence["verification_markers"]
            if _normalise_text(str(marker)).casefold() not in text.casefold()
        ]
        if missing:
            raise ValueError(
                f"official licence terms are missing reviewed markers for {licence_id}"
            )
        if licence_id == "uksc_ogl_v3":
            _require_safe_host(str(licence["url"]), OGL_HOSTS, "OGL licence URL")
        results.append(
            {
                "licence_id": licence_id,
                "name": licence["name"],
                "version": licence["version"],
                "terms_url": resolved_terms_url,
                "licence_url": licence["url"],
                "publisher": licence["publisher"],
                "required_attribution": licence["required_attribution"],
                "terms_snapshot_sha256": _sha256(snapshot_data),
                "terms_snapshot_bytes": len(snapshot_data),
                "verification": verification,
            }
        )
    return results


def _download_uksc_case(
    client: httpx.Client, item: dict[str, Any], representation: dict[str, Any]
) -> tuple[bytes, str]:
    page = client.get(str(item["official_case_url"]))
    page.raise_for_status()
    _require_safe_host(str(page.url), UKSC_HOSTS, "UKSC case page redirect")
    soup = BeautifulSoup(page.text, "html.parser")
    page_text = _normalise_text(soup.get_text(" ", strip=True))
    title_node = soup.find("h1")
    title = _normalise_text(title_node.get_text(" ", strip=True) if title_node else "")
    if not _case_title_matches(str(item["case_name"]), f"{title} {page_text[:1000]}"):
        raise ValueError("official UKSC case page identity differs from the reviewed case")
    citations = {match.group(0) for match in NEUTRAL.finditer(page_text)}
    if item["neutral_citation"] not in citations:
        raise ValueError("official UKSC case page neutral citation mismatch")
    match = JUDGMENT_DATE.search(page_text)
    if match is None:
        raise ValueError("official UKSC case page has no judgment date")
    observed_date = datetime.strptime(match.group("date"), "%d %B %Y").date().isoformat()
    if observed_date != item["decision_date"]:
        raise ValueError("official UKSC case page judgment date mismatch")
    link = _judgment_link(str(page.url), soup)
    if link != representation["official_url"]:
        raise ValueError("official UKSC case page judgment link differs from the reviewed manifest")
    response = client.get(link)
    response.raise_for_status()
    _require_safe_host(str(response.url), UKSC_HOSTS, "UKSC PDF redirect")
    if len(response.content) > MAX_SOURCE_BYTES:
        raise ValueError("UKSC judgment exceeds the bounded source-size limit")
    return response.content, str(response.url)


def _parliament_snapshot_path(staging: Path, representation: dict[str, Any]) -> Path:
    name = Path(urlparse(str(representation["official_url"])).path).name
    if not re.fullmatch(r"yardle-[1-5]\.htm", name):
        raise ValueError("unexpected Parliament snapshot filename")
    candidate = (staging / name).resolve()
    try:
        candidate.relative_to(staging.resolve())
    except ValueError as exc:
        raise ValueError("Parliament snapshot escaped the verified staging directory") from exc
    return candidate


def _write_immutable(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != data:
            raise ValueError(f"existing immutable source differs: {destination.name}")
        return
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(destination)


def main() -> None:
    args = _parser().parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    representations = validate_manifest(manifest)
    if (
        any(
            representation["kind"] == "browser_rendered_official_html_snapshot"
            for _, representation in representations.values()
        )
        and args.verified_parliament_dir is None
    ):
        raise SystemExit(
            "the five official Parliament pages require --verified-parliament-dir; "
            "direct HTTP fallback is deliberately disabled"
        )
    manifest_sha256 = _canonical_sha256(manifest)
    downloaded: list[dict[str, Any]] = []
    headers = {"User-Agent": "LegalBot-New owner-only official-source verifier/1.0"}
    with httpx.Client(headers=headers, follow_redirects=True, timeout=60) as client:
        licence_results = _verify_licences(client, manifest, args.verified_licence_dir)
        for representation_id, (item, representation) in representations.items():
            if representation["kind"] == "browser_rendered_official_html_snapshot":
                assert args.verified_parliament_dir is not None
                staging_path = _parliament_snapshot_path(
                    args.verified_parliament_dir, representation
                )
                if not staging_path.is_file():
                    raise ValueError(
                        f"verified Parliament snapshot is missing: {staging_path.name}"
                    )
                data = staging_path.read_bytes()
                resolved_url = representation["official_url"]
            else:
                data, resolved_url = _download_uksc_case(client, item, representation)
            verify_representation_payload(item, representation, data)
            destination = args.output_root / str(representation["safe_filename"])
            _write_immutable(destination, data)
            reviewed_passages = [
                {
                    "locator": passage["locator"],
                    "legal_role": passage["legal_role"],
                    "issues": passage["issues"],
                    "review_note": passage["review_note"],
                }
                for passage in item["reviewed_passages"]
                if passage["representation_id"] == representation_id
            ]
            downloaded.append(
                {
                    "authority_id": item["authority_id"],
                    "case_id": item["case_id"],
                    "case_name": item["case_name"],
                    "neutral_citation": item["neutral_citation"],
                    "decision_date": item["decision_date"],
                    "representation_id": representation_id,
                    "representation_kind": representation["kind"],
                    "official_case_url": item["official_case_url"],
                    "official_representation_url": representation["official_url"],
                    "resolved_url": resolved_url,
                    "licence_id": item["licence_id"],
                    "sha256": _sha256(data),
                    "bytes": len(data),
                    "relative_path": destination.relative_to(PROJECT_ROOT).as_posix(),
                    "reviewed_passages": reviewed_passages,
                    "status": "downloaded_verified_unapproved",
                }
            )
    downloaded.sort(key=lambda value: str(value["representation_id"]))
    report = {
        "schema": REPORT_SCHEMA,
        "manifest_version": manifest["version"],
        "manifest_sha256": manifest_sha256,
        "as_of_date": manifest["as_of_date"],
        "downloaded_at": datetime.now(UTC).isoformat(),
        "approval_precondition": "fresh_complete_source_scan_after_downloaded_at",
        "indexing_status": "not_built_or_promoted",
        "licence_verification": licence_results,
        "items": downloaded,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        report_display = args.report.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        report_display = args.report.name
    print(
        json.dumps(
            {
                "downloaded_verified_unapproved": len(downloaded),
                "authorities": len(manifest["items"]),
                "report": report_display,
                "next_required_action": "run a fresh complete source scan",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
