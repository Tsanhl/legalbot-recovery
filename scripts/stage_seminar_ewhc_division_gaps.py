#!/usr/bin/env python3
"""Resolve incomplete EWHC citations through exact Find Case Law judgment links."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.ingestion.models import BlockKind, ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARENT = PROJECT_ROOT / "config/seminar_gap_official_uk_judgments_round2.2026-08-26.v1.json"
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_RELATIVE_DIRECTORY = Path(
    "Official Legislation/seminar-gap-official-2026-08-26/uk-judgments-round3"
)
DEFAULT_MANIFEST = PROJECT_ROOT / "config/seminar_gap_official_ewhc_divisions.2026-08-26.v1.json"
PARENT_SCHEMA = "legalbot.seminar-gap-official-uk-judgment-plan.v1"
MANIFEST_SCHEMA = "legalbot.seminar-gap-official-ewhc-division-plan.v1"
OFFICIAL_HOST = "caselaw.nationalarchives.gov.uk"
BASE_CITATION = re.compile(r"^\[(\d{4})\] EWHC (\d+)$")


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("ewhc_division_input_must_be_object")
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
        raise ValueError("ewhc_division_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    if _local_name(root.tag) != "akomaNtoso":
        raise ValueError("ewhc_division_xml_root_invalid")
    judgment = _first(root, "judgment")
    work = _first(judgment, "FRBRWork")
    expression = _first(judgment, "FRBRExpression")
    proprietary = _first(judgment, "proprietary")
    return (
        _attr(_first(work, "FRBRname"), "value"),
        _text(_first(proprietary, "cite")),
        _attr(_first(expression, "FRBRthis"), "value"),
    )


def _get(url: str, *, accept: str, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": "LegalBot-v1.11-ewhc-division-resolution/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
            raise ValueError("ewhc_division_redirected_outside_official_host")
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
    if parent.get("schema") != PARENT_SCHEMA:
        raise ValueError("ewhc_division_parent_schema_invalid")
    unresolved = [
        item
        for item in parent["unresolved_references"]
        if item["reason_code"] == "ewhc_division_missing"
    ]
    if len(unresolved) != 8:
        raise ValueError("ewhc_division_parent_inventory_invalid")

    source_root = source_root.resolve(strict=True)
    output_directory = (source_root / relative_directory).resolve()
    output_directory.relative_to(source_root)
    output_directory.mkdir(parents=True, exist_ok=True)
    parser = ParserRegistry.default()
    connection = sqlite3.connect(f"file:{catalogue_path.resolve()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    targets: list[dict[str, Any]] = []
    already_catalogued: list[dict[str, Any]] = []
    still_unresolved: list[dict[str, Any]] = []
    try:
        for item in unresolved:
            base = str(item["authority_identity"])
            match = BASE_CITATION.fullmatch(base)
            if match is None:
                raise ValueError("ewhc_division_base_citation_invalid")
            year, number = match.groups()
            query_url = (
                "https://" + OFFICIAL_HOST + "/search?" + urllib.parse.urlencode({"query": base})
            )
            search_html = html.unescape(
                _get(
                    query_url,
                    accept="text/html",
                    timeout_seconds=timeout_seconds,
                ).decode("utf-8", errors="replace")
            )
            links = sorted(
                set(
                    re.findall(
                        rf'href="(/ewhc/[a-z0-9-]+/{year}/{number})(?:\?[^\"]*)?"',
                        search_html,
                    )
                )
            )
            if len(links) != 1:
                still_unresolved.append(
                    {
                        "authority_identity": base,
                        "subjects": sorted(str(value) for value in item["subjects"]),
                        "reason_code": (
                            "find_case_law_exact_judgment_link_not_found"
                            if not links
                            else "find_case_law_exact_judgment_link_ambiguous"
                        ),
                    }
                )
                continue
            judgment_url = "https://" + OFFICIAL_HOST + links[0]
            data_url = judgment_url + "/data.xml"
            raw = _get(data_url, accept="application/xml", timeout_seconds=timeout_seconds)
            title, citation, uri = _xml_identity(raw)
            if not citation.startswith(base + " (") or not citation.endswith(")"):
                raise ValueError("ewhc_division_official_citation_not_exact_extension")
            if uri != judgment_url:
                raise ValueError("ewhc_division_official_uri_mismatch")
            parsed = parser.parse(raw, filename=links[0].rsplit("/", 1)[-1] + ".xml")
            paragraphs = [
                block for block in parsed.body_blocks if block.kind is BlockKind.PARAGRAPH
            ]
            if parsed.status is not ParseStatus.READY or not paragraphs:
                raise ValueError("ewhc_division_runtime_parser_not_ready")
            content_hash = hashlib.sha256(raw).hexdigest()
            existing = connection.execute(
                """
                SELECT d.status, d.lane, sv.version_sha256
                  FROM documents d
                  JOIN source_versions sv
                    ON sv.document_id=d.id AND sv.superseded_by IS NULL
                 WHERE d.content_sha256=?
                """,
                (content_hash,),
            ).fetchall()
            if any(
                row["status"] == "citable" and row["lane"] == "primary_authority"
                for row in existing
            ):
                already_catalogued.append(
                    {
                        "authority_identity": citation,
                        "content_sha256": content_hash,
                        "official_url": data_url,
                        "subjects": sorted(str(value) for value in item["subjects"]),
                    }
                )
                continue
            slug = links[0].strip("/").replace("/", "-") + "-data.xml"
            destination = output_directory / slug
            _write_exclusive(destination, raw)
            targets.append(
                {
                    "authority_identity": citation,
                    "source_title": title,
                    "official_url": data_url,
                    "source_root_relative_path": str(relative_directory / slug),
                    "content_sha256": content_hash,
                    "byte_count": len(raw),
                    "identity_verified_from_official_xml": True,
                    "presentation_subjects": sorted(str(value) for value in item["subjects"]),
                    "currentness_status": "official_judgment_snapshot_unreviewed",
                }
            )
    finally:
        connection.close()

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "version": "seminar-gap-official-ewhc-divisions-2026-08-26-v1",
        "download_date": "2026-08-26",
        "parent_manifest_sha256": _sha256_file(parent_path),
        "source": "Find Case Law",
        "source_root_relative_directory": str(relative_directory),
        "targets": targets,
        "already_catalogued": already_catalogued,
        "still_unresolved": still_unresolved,
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
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
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
