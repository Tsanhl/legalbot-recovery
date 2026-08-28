#!/usr/bin/env python3
"""Recover direct-URL misses only through exact Find Case Law search links."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.ingestion.models import BlockKind, ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARENT = (
    PROJECT_ROOT / "config/seminar_gap_official_uk_judgments_round2.2026-08-26.v1.json"
)
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_RELATIVE_DIRECTORY = Path(
    "Official Legislation/seminar-gap-official-2026-08-26/uk-judgments-round4"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_fcl_search_recovery.2026-08-26.v1.json"
)
EXPECTED_PARENT_SCHEMA = "legalbot.seminar-gap-official-uk-judgment-plan.v1"
MANIFEST_SCHEMA = "legalbot.seminar-gap-official-fcl-search-recovery.v1"
OFFICIAL_HOST = "caselaw.nationalarchives.gov.uk"
NEUTRAL = re.compile(
    r"^\[(?P<year>\d{4})\] (?P<court>UKSC|UKHL|EWCA Civ|EWCA Crim|EWHC) "
    r"(?P<number>\d+)(?: \((?P<division>[A-Za-z]+)\))?$"
)
DIVISION_SLUG = {
    "Admin": "admin",
    "Ch": "ch",
    "Comm": "comm",
    "Fam": "fam",
    "IPEC": "ipec",
    "KB": "kb",
    "Pat": "pat",
    "QB": "qb",
    "TCC": "tcc",
}


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("fcl_search_recovery_input_must_be_object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _first(root: ET.Element | None, name: str) -> ET.Element | None:
    if root is None:
        return None
    return next((item for item in root.iter() if _local_name(item.tag) == name), None)


def _attr(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    for key, value in element.attrib.items():
        if _local_name(key) == name:
            return str(value).strip()
    return ""


def _text(element: ET.Element | None) -> str:
    return " ".join("".join(element.itertext()).split()) if element is not None else ""


def _xml_identity(raw: bytes) -> tuple[str, str, str]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("fcl_search_recovery_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    judgment = _first(root, "judgment")
    work = _first(judgment, "FRBRWork")
    expression = _first(judgment, "FRBRExpression")
    proprietary = _first(judgment, "proprietary")
    return (
        _attr(_first(work, "FRBRname"), "value"),
        _text(_first(proprietary, "cite")),
        _attr(_first(expression, "FRBRthis"), "value"),
    )


def _expected_path(citation: str) -> str:
    match = NEUTRAL.fullmatch(citation)
    if match is None:
        raise ValueError("fcl_search_recovery_citation_invalid")
    year = match.group("year")
    number = match.group("number")
    court = match.group("court")
    if court == "UKSC":
        return f"/uksc/{year}/{number}"
    if court == "UKHL":
        return f"/ukhl/{year}/{number}"
    if court == "EWCA Civ":
        return f"/ewca/civ/{year}/{number}"
    if court == "EWCA Crim":
        return f"/ewca/crim/{year}/{number}"
    division = match.group("division")
    if not division or division not in DIVISION_SLUG:
        raise ValueError("fcl_search_recovery_ewhc_division_invalid")
    return f"/ewhc/{DIVISION_SLUG[division]}/{year}/{number}"


def _get(url: str, *, accept: str, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "LegalBot-v1.11-fcl-search-recovery/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
            raise ValueError("fcl_search_recovery_redirected_outside_official_host")
        return response.read()


def _write_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def stage(
    *,
    parent_path: Path,
    catalogue_path: Path,
    source_root: Path,
    relative_directory: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    parent = _load(parent_path)
    if parent.get("schema") != EXPECTED_PARENT_SCHEMA:
        raise ValueError("fcl_search_recovery_parent_schema_invalid")
    misses = [
        item
        for item in parent["unresolved_references"]
        if item["reason_code"] == "find_case_law_http_error"
    ]
    if len(misses) != 40:
        raise ValueError("fcl_search_recovery_parent_inventory_invalid")

    source_root = source_root.resolve(strict=True)
    output_directory = (source_root / relative_directory).resolve()
    output_directory.relative_to(source_root)
    output_directory.mkdir(parents=True, exist_ok=True)
    parser = ParserRegistry.default()
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1", uri=True
    )
    connection.row_factory = sqlite3.Row
    targets: list[dict[str, Any]] = []
    already_catalogued: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    try:
        for item in misses:
            citation = str(item["authority_identity"])
            expected_path = _expected_path(citation)
            query_url = "https://" + OFFICIAL_HOST + "/search?" + urllib.parse.urlencode(
                {"query": citation}
            )
            try:
                search_html = html.unescape(
                    _get(
                        query_url,
                        accept="text/html",
                        timeout_seconds=timeout_seconds,
                    ).decode("utf-8", errors="replace")
                )
            except (TimeoutError, urllib.error.URLError) as exc:
                unresolved.append(
                    {
                        "authority_identity": citation,
                        "subjects": sorted(str(value) for value in item["subjects"]),
                        "reason_code": "find_case_law_search_http_error",
                        "error_type": type(exc).__name__,
                    }
                )
                continue
            matching_links = sorted(
                set(
                    link.split("?", 1)[0]
                    for link in re.findall(r'href="(/[a-z0-9/?=&%+.-]+)"', search_html)
                    if link.split("?", 1)[0] == expected_path
                )
            )
            if len(matching_links) != 1:
                unresolved.append(
                    {
                        "authority_identity": citation,
                        "subjects": sorted(str(value) for value in item["subjects"]),
                        "reason_code": (
                            "find_case_law_exact_search_link_not_found"
                            if not matching_links
                            else "find_case_law_exact_search_link_ambiguous"
                        ),
                    }
                )
                continue
            judgment_url = "https://" + OFFICIAL_HOST + expected_path
            data_url = judgment_url + "/data.xml"
            try:
                raw = _get(
                    data_url,
                    accept="application/xml",
                    timeout_seconds=timeout_seconds,
                )
            except (TimeoutError, urllib.error.URLError) as exc:
                unresolved.append(
                    {
                        "authority_identity": citation,
                        "subjects": sorted(str(value) for value in item["subjects"]),
                        "reason_code": "find_case_law_exact_search_link_data_unavailable",
                        "error_type": type(exc).__name__,
                    }
                )
                continue
            title, actual_citation, uri = _xml_identity(raw)
            if actual_citation != citation or uri != judgment_url:
                raise ValueError("fcl_search_recovery_official_identity_mismatch")
            parsed = parser.parse(raw, filename=expected_path.rsplit("/", 1)[-1] + ".xml")
            paragraphs = [
                block for block in parsed.body_blocks if block.kind is BlockKind.PARAGRAPH
            ]
            if parsed.status is not ParseStatus.READY or not paragraphs:
                raise ValueError("fcl_search_recovery_runtime_parser_not_ready")
            content_hash = hashlib.sha256(raw).hexdigest()
            existing = connection.execute(
                """
                SELECT d.status, d.lane FROM documents d
                JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                WHERE d.content_sha256=?
                """,
                (content_hash,),
            ).fetchall()
            record = {
                "authority_identity": citation,
                "content_sha256": content_hash,
                "official_url": data_url,
                "presentation_subjects": sorted(
                    str(value) for value in item["subjects"]
                ),
            }
            if any(row["status"] == "citable" and row["lane"] == "primary_authority" for row in existing):
                already_catalogued.append(record)
                continue
            slug = expected_path.strip("/").replace("/", "-") + "-data.xml"
            _write_exclusive(output_directory / slug, raw)
            targets.append(
                {
                    **record,
                    "source_title": title,
                    "source_root_relative_path": str(relative_directory / slug),
                    "byte_count": len(raw),
                    "identity_verified_from_official_xml": True,
                    "currentness_status": "official_judgment_snapshot_unreviewed",
                }
            )
    finally:
        connection.close()

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "version": "seminar-gap-official-fcl-search-recovery-2026-08-26-v1",
        "download_date": "2026-08-26",
        "parent_manifest_sha256": _sha256_file(parent_path),
        "source": "Find Case Law",
        "source_root_relative_directory": str(relative_directory),
        "targets": targets,
        "already_catalogued": already_catalogued,
        "still_unresolved": unresolved,
        "teaching_lane_use": "GAP_DISCOVERY_ONLY_NOT_LEGAL_AUTHORITY",
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_later_treatment_approval": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutation_authorized": False,
        "active_promotion_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
        "live_activation_authorized": False,
    }
    encoded = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    manifest["manifest_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, default=DEFAULT_PARENT)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--relative-directory", type=Path, default=DEFAULT_RELATIVE_DIRECTORY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    manifest = stage(
        parent_path=args.parent,
        catalogue_path=args.catalogue,
        source_root=args.source_root,
        relative_directory=args.relative_directory,
        timeout_seconds=max(args.timeout_seconds, 1.0),
    )
    _write_exclusive(
        args.manifest,
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    print(
        json.dumps(
            {
                "already_catalogued_count": len(manifest["already_catalogued"]),
                "staged_target_count": len(manifest["targets"]),
                "still_unresolved_count": len(manifest["still_unresolved"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
