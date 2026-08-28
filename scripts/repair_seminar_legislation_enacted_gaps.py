#!/usr/bin/env python3
"""Repair the six historic legislation targets available only as enacted XML."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARENT = PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v1.json"
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_MANIFEST = (
    PROJECT_ROOT
    / "config/seminar_gap_official_legislation_round2.2026-08-26.v2-enacted-repair.json"
)
EXPECTED_PARENT_SCHEMA = "legalbot.seminar-gap-official-legislation-plan.v1"
MANIFEST_SCHEMA = "legalbot.seminar-gap-official-legislation-enacted-repair.v1"
OFFICIAL_HOST = "www.legislation.gov.uk"
DC = "http://purl.org/dc/elements/1.1/"
MAX_XML_BYTES = 128 * 1024 * 1024


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("enacted_repair_input_must_be_object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalise_identity(value: str) -> str:
    return value.strip().replace("https://", "http://").rstrip("/")


def _download_identity(canonical_url: str) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(canonical_url)
    if parsed.scheme != "https" or parsed.hostname != OFFICIAL_HOST:
        raise ValueError("enacted_repair_official_identity_host_invalid")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4 or parts[0] != "id":
        raise ValueError("enacted_repair_official_identity_path_invalid")
    identity_path = "/".join(parts[1:])
    expected_enacted_identifier = f"http://{OFFICIAL_HOST}/{identity_path}/enacted"
    data_url = f"https://{OFFICIAL_HOST}/{identity_path}/data.xml"
    filename = "-".join(parts[1:]) + "-data.xml"
    return expected_enacted_identifier, data_url, filename


def _download(url: str, *, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/xml",
            "User-Agent": "LegalBot-v1.11-official-enacted-repair/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
            raise ValueError("enacted_repair_redirected_outside_official_host")
        raw = response.read(MAX_XML_BYTES + 1)
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("enacted_repair_xml_exceeds_byte_limit")
    return raw


def _xml_identity(raw: bytes) -> tuple[str, str]:
    opening = raw[:100_000].upper()
    if b"<!DOCTYPE" in opening or b"<!ENTITY" in opening:
        raise ValueError("enacted_repair_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    title = root.find(f".//{{{DC}}}title")
    identifier = root.find(f".//{{{DC}}}identifier")
    if title is None or identifier is None:
        raise ValueError("enacted_repair_xml_identity_missing")
    return (
        " ".join("".join(title.itertext()).split()),
        " ".join("".join(identifier.itertext()).split()),
    )


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


def repair(*, parent_path: Path, source_root: Path, timeout_seconds: float) -> dict[str, Any]:
    parent = _load(parent_path)
    if parent.get("schema") != EXPECTED_PARENT_SCHEMA:
        raise ValueError("enacted_repair_parent_schema_invalid")
    rejected = parent.get("rejected_downloads")
    if not isinstance(rejected, list) or len(rejected) != 6:
        raise ValueError("enacted_repair_parent_rejection_inventory_invalid")
    if any(
        item.get("reason_code") != "official_legislation_xml_identifier_mismatch"
        for item in rejected
    ):
        raise ValueError("enacted_repair_parent_failure_fingerprint_invalid")

    source_root = source_root.resolve(strict=True)
    relative_directory = Path(str(parent["source_root_relative_directory"]))
    output_directory = (source_root / relative_directory).resolve(strict=True)
    output_directory.relative_to(source_root)
    targets: list[dict[str, Any]] = []
    for item in sorted(rejected, key=lambda value: str(value["canonical_url"])):
        title = str(item["official_title"])
        canonical_url = str(item["canonical_url"])
        expected_identifier, data_url, filename = _download_identity(canonical_url)
        raw = _download(data_url, timeout_seconds=timeout_seconds)
        actual_title, actual_identifier = _xml_identity(raw)
        if actual_title != title:
            raise ValueError("enacted_repair_xml_title_mismatch")
        if _normalise_identity(actual_identifier) != _normalise_identity(expected_identifier):
            raise ValueError("enacted_repair_xml_identifier_not_exact_enacted_representation")
        destination = output_directory / filename
        _write_exclusive(destination, raw)
        targets.append(
            {
                "authority_identity": expected_identifier.removesuffix("/enacted"),
                "representation_identity": expected_identifier,
                "source_title": title,
                "official_url": data_url,
                "canonical_url": canonical_url,
                "source_root_relative_path": str(relative_directory / filename),
                "content_sha256": hashlib.sha256(raw).hexdigest(),
                "byte_count": len(raw),
                "identity_verified_from_xml": True,
                "currentness_status": "official_enacted_snapshot_unreviewed",
            }
        )

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "version": "seminar-gap-official-legislation-round2-2026-08-26-v2-enacted-repair",
        "download_date": "2026-08-26",
        "parent_manifest_sha256": _sha256_file(parent_path),
        "parent_manifest_content_sha256": parent["manifest_content_sha256"],
        "source": "legislation.gov.uk",
        "source_root_relative_directory": str(relative_directory),
        "repair_failure_fingerprint": "official_legislation_xml_identifier_mismatch",
        "targets": targets,
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
    parser.add_argument("--parent", type=Path, default=DEFAULT_PARENT)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    args = parser.parse_args()
    manifest = repair(
        parent_path=args.parent,
        source_root=args.source_root,
        timeout_seconds=max(args.timeout_seconds, 1.0),
    )
    _write_exclusive(
        args.manifest,
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    print(json.dumps({"repaired_target_count": len(manifest["targets"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
