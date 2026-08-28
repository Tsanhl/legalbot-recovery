#!/usr/bin/env python3
"""Stage exact official XML for resolved cross-subject seminar legislation gaps."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESOLUTION = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-legislation-title-resolution-2026-08-26.json"
)
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_RELATIVE_DIRECTORY = Path(
    "Official Legislation/seminar-gap-official-2026-08-26/legislation-round2"
)
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v1.json"
)
EXPECTED_RESOLUTION_SCHEMA = "legalbot.seminar-gap-legislation-title-resolution.v1"
MANIFEST_SCHEMA = "legalbot.seminar-gap-official-legislation-plan.v1"
OFFICIAL_HOST = "www.legislation.gov.uk"
DC = "http://purl.org/dc/elements/1.1/"
MAX_XML_BYTES = 128 * 1024 * 1024


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("legislation_staging_input_must_be_object")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalise_identity(value: str) -> str:
    return value.strip().replace("https://", "http://").rstrip("/")


def _xml_identity(raw: bytes) -> tuple[str, str]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("official_legislation_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    title = root.find(f".//{{{DC}}}title")
    identifier = root.find(f".//{{{DC}}}identifier")
    if title is None or identifier is None:
        raise ValueError("official_legislation_xml_identity_missing")
    return (
        " ".join("".join(title.itertext()).split()),
        " ".join("".join(identifier.itertext()).split()),
    )


def _download_url(canonical_url: str) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(canonical_url)
    if parsed.scheme != "https" or parsed.hostname != OFFICIAL_HOST:
        raise ValueError("official_legislation_identity_host_invalid")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4 or parts[0] != "id":
        raise ValueError("official_legislation_identity_path_invalid")
    identity_path = "/".join(parts[1:])
    official_identifier = f"http://{OFFICIAL_HOST}/{identity_path}"
    data_url = f"https://{OFFICIAL_HOST}/{identity_path}/data.xml"
    filename = "-".join(parts[1:]) + "-data.xml"
    return official_identifier, data_url, filename


def _download(data_url: str, *, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(
        data_url,
        headers={
            "Accept": "application/xml",
            "User-Agent": "LegalBot-v1.11-official-legislation-staging/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
            raise ValueError("official_legislation_download_redirected_outside_official_host")
        raw = response.read(MAX_XML_BYTES + 1)
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("official_legislation_xml_exceeds_byte_limit")
    return raw


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


def _current_exact_title_rows(
    connection: sqlite3.Connection, title: str
) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT sv.version_sha256, sv.review_status, d.status, d.lane, d.media_type
          FROM source_versions sv
          JOIN documents d ON d.id=sv.document_id
         WHERE sv.superseded_by IS NULL AND lower(sv.title)=lower(?)
         ORDER BY sv.version_sha256
        """,
        (title,),
    ).fetchall()


def stage(
    *,
    resolution_path: Path,
    catalogue_path: Path,
    source_root: Path,
    relative_directory: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    resolution = _load(resolution_path)
    if resolution.get("schema") != EXPECTED_RESOLUTION_SCHEMA:
        raise ValueError("legislation_staging_resolution_schema_invalid")
    source_root = source_root.resolve(strict=True)
    output_directory = (source_root / relative_directory).resolve()
    output_directory.relative_to(source_root)
    output_directory.mkdir(parents=True, exist_ok=True)

    identities: dict[str, dict[str, Any]] = {}
    subjects_by_url: dict[str, set[str]] = defaultdict(set)
    for record in resolution["records"]:
        matches = record.get("official_exact_matches") or []
        if len(matches) != 1:
            continue
        match = matches[0]
        canonical_url = str(match["canonical_url"])
        identities[canonical_url] = {
            "official_title": str(match["official_title"]),
            "canonical_url": canonical_url,
        }
        subjects_by_url[canonical_url].update(
            str(value) for value in record.get("presentation_subjects", [])
        )

    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1", uri=True
    )
    connection.row_factory = sqlite3.Row
    targets: list[dict[str, Any]] = []
    already_catalogued: list[dict[str, Any]] = []
    rejected_downloads: list[dict[str, Any]] = []
    try:
        active_scan_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM source_scans WHERE status IN ('queued','running')"
            ).fetchone()[0]
        )
        if active_scan_count:
            raise ValueError("legislation_staging_requires_frozen_catalogue")
        for canonical_url, item in sorted(identities.items()):
            title = str(item["official_title"])
            existing = _current_exact_title_rows(connection, title)
            primary_xml = [
                row
                for row in existing
                if row["lane"] == "primary_authority"
                and row["media_type"] == "application/xml"
                and row["status"] == "citable"
            ]
            if primary_xml:
                already_catalogued.append(
                    {
                        "official_title": title,
                        "canonical_url": canonical_url,
                        "presentation_subjects": sorted(subjects_by_url[canonical_url]),
                        "current_primary_xml_count": len(primary_xml),
                        "current_version_sha256": sorted(
                            str(row["version_sha256"]) for row in primary_xml
                        ),
                        "owner_metadata_binding_required": True,
                    }
                )
                continue
            official_identifier, data_url, filename = _download_url(canonical_url)
            try:
                raw = _download(data_url, timeout_seconds=timeout_seconds)
                actual_title, actual_identifier = _xml_identity(raw)
                if actual_title != title:
                    raise ValueError("official_legislation_xml_title_mismatch")
                if _normalise_identity(actual_identifier) != _normalise_identity(
                    official_identifier
                ):
                    raise ValueError("official_legislation_xml_identifier_mismatch")
                destination = output_directory / filename
                _write_exclusive(destination, raw)
            except (OSError, TimeoutError, urllib.error.URLError, ValueError) as exc:
                rejected_downloads.append(
                    {
                        "official_title": title,
                        "canonical_url": canonical_url,
                        "reason_code": str(exc),
                        "error_type": type(exc).__name__,
                    }
                )
                continue
            targets.append(
                {
                    "authority_identity": official_identifier,
                    "source_title": title,
                    "official_url": data_url,
                    "canonical_url": canonical_url,
                    "source_root_relative_path": str(relative_directory / filename),
                    "content_sha256": _sha256_bytes(raw),
                    "byte_count": len(raw),
                    "identity_verified_from_xml": True,
                    "presentation_subjects": sorted(subjects_by_url[canonical_url]),
                    "currentness_status": "downloaded_latest_available_snapshot_unreviewed",
                }
            )
    finally:
        connection.close()

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "version": "seminar-gap-official-legislation-round2-2026-08-26-v1",
        "download_date": "2026-08-26",
        "source": "legislation.gov.uk",
        "source_resolution_sha256": _sha256_file(resolution_path),
        "source_root_relative_directory": str(relative_directory),
        "resolved_unique_official_identity_count": len(identities),
        "targets": targets,
        "already_catalogued": already_catalogued,
        "rejected_downloads": rejected_downloads,
        "teaching_lane_use": "GAP_DISCOVERY_ONLY_NOT_LEGAL_AUTHORITY",
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
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
    parser.add_argument("--resolution", type=Path, default=DEFAULT_RESOLUTION)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--relative-directory", type=Path, default=DEFAULT_RELATIVE_DIRECTORY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    manifest = stage(
        resolution_path=args.resolution,
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
                "rejected_download_count": len(manifest["rejected_downloads"]),
                "staged_target_count": len(manifest["targets"]),
            },
            sort_keys=True,
        )
    )
    return 0 if not manifest["rejected_downloads"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
