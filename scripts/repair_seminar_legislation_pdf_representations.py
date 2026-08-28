#!/usr/bin/env python3
"""Stage official enacted PDFs for four metadata-only historic XML records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ingestion.models import ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PARENT_INGESTION = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-legislation-round2-2026-08-26-explicit-ingestion.json"
)
DEFAULT_PARENT_MANIFEST = (
    PROJECT_ROOT
    / "config/seminar_gap_official_legislation_round2.2026-08-26.v2-enacted-repair.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v3-pdf-repair.json"
)
EXPECTED_INGESTION_SCHEMA = "legalbot.seminar-gap-official-legislation-explicit-ingestion.v1"
EXPECTED_PARENT_SCHEMA = "legalbot.seminar-gap-official-legislation-enacted-repair.v1"
MANIFEST_SCHEMA = "legalbot.seminar-gap-official-legislation-pdf-repair.v1"
OFFICIAL_HOST = "www.legislation.gov.uk"
MAX_PDF_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PdfTarget:
    authority_identity: str
    source_title: str
    official_url: str
    expected_parser_status: ParseStatus


TARGETS = (
    PdfTarget(
        "http://www.legislation.gov.uk/ukpga/Edw7/8/67",
        "Children Act 1908",
        "https://www.legislation.gov.uk/ukpga/Edw7/8/67/pdfs/ukpga_19080067_en.pdf",
        ParseStatus.OCR_REQUIRED,
    ),
    PdfTarget(
        "http://www.legislation.gov.uk/ukpga/Vict/36-37/66",
        "Supreme Court of Judicature Act 1873",
        "https://www.legislation.gov.uk/ukpga/Vict/36-37/66/pdfs/ukpga_18730066_en.pdf",
        ParseStatus.READY,
    ),
    PdfTarget(
        "http://www.legislation.gov.uk/ukpga/Vict/38-39/87",
        "The Land Transfer Act 1875",
        "https://www.legislation.gov.uk/ukpga/Vict/38-39/87/pdfs/ukpga_18750087_en.pdf",
        ParseStatus.READY,
    ),
    PdfTarget(
        "http://www.legislation.gov.uk/ukpga/Vict/60-61/65",
        "Land Transfer Act 1897",
        "https://www.legislation.gov.uk/ukpga/Vict/60-61/65/pdfs/ukpga_18970065_en.pdf",
        ParseStatus.READY,
    ),
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("pdf_repair_input_must_be_object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _download(url: str, *, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/pdf",
            "User-Agent": "LegalBot-v1.11-official-pdf-repair/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        final = urllib.parse.urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname != OFFICIAL_HOST:
            raise ValueError("pdf_repair_redirected_outside_official_host")
        raw = response.read(MAX_PDF_BYTES + 1)
    if len(raw) > MAX_PDF_BYTES:
        raise ValueError("pdf_repair_exceeds_byte_limit")
    if not raw.startswith(b"%PDF-"):
        raise ValueError("pdf_repair_official_response_is_not_pdf")
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


def repair(
    *,
    parent_ingestion_path: Path,
    parent_manifest_path: Path,
    source_root: Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    ingestion = _load(parent_ingestion_path)
    parent = _load(parent_manifest_path)
    if ingestion.get("schema") != EXPECTED_INGESTION_SCHEMA:
        raise ValueError("pdf_repair_parent_ingestion_schema_invalid")
    if parent.get("schema") != EXPECTED_PARENT_SCHEMA:
        raise ValueError("pdf_repair_parent_manifest_schema_invalid")
    quarantined = {
        str(record["authority_identity"]): record
        for record in ingestion["records"]
        if record["status"] == "quarantined" and record["reason"] == "parse_failed"
    }
    expected_identities = {target.authority_identity for target in TARGETS}
    if set(quarantined) != expected_identities:
        raise ValueError("pdf_repair_parent_quarantine_inventory_invalid")

    source_root = source_root.resolve(strict=True)
    relative_directory = Path(str(parent["source_root_relative_directory"]))
    output_directory = (source_root / relative_directory).resolve(strict=True)
    output_directory.relative_to(source_root)
    parser = ParserRegistry.default()
    targets: list[dict[str, Any]] = []
    for target in TARGETS:
        raw = _download(target.official_url, timeout_seconds=timeout_seconds)
        filename = target.official_url.rsplit("/", 1)[-1]
        parsed = parser.parse(raw, filename=filename)
        if parsed.status is not target.expected_parser_status:
            raise ValueError("pdf_repair_runtime_parser_status_changed")
        if parsed.status is ParseStatus.READY and not parsed.body_blocks:
            raise ValueError("pdf_repair_ready_document_has_no_blocks")
        destination = output_directory / filename
        _write_exclusive(destination, raw)
        targets.append(
            {
                "authority_identity": target.authority_identity,
                "representation_identity": target.official_url,
                "source_title": target.source_title,
                "official_url": target.official_url,
                "source_root_relative_path": str(relative_directory / filename),
                "content_sha256": hashlib.sha256(raw).hexdigest(),
                "byte_count": len(raw),
                "runtime_parser_status": parsed.status.value,
                "runtime_parser_block_count": len(parsed.body_blocks),
                "currentness_status": "official_enacted_snapshot_unreviewed",
            }
        )

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "version": "seminar-gap-official-legislation-round2-2026-08-26-v3-pdf-repair",
        "download_date": "2026-08-26",
        "parent_ingestion_sha256": _sha256_file(parent_ingestion_path),
        "parent_manifest_sha256": _sha256_file(parent_manifest_path),
        "source": "legislation.gov.uk",
        "source_root_relative_directory": str(relative_directory),
        "repair_failure_fingerprint": "parse_failed:no_legislative_provisions",
        "targets": targets,
        "automatic_ocr_acceptance": False,
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
    parser.add_argument("--parent-ingestion", type=Path, default=DEFAULT_PARENT_INGESTION)
    parser.add_argument("--parent-manifest", type=Path, default=DEFAULT_PARENT_MANIFEST)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()
    manifest = repair(
        parent_ingestion_path=args.parent_ingestion,
        parent_manifest_path=args.parent_manifest,
        source_root=args.source_root,
        timeout_seconds=max(args.timeout_seconds, 1.0),
    )
    _write_exclusive(
        args.manifest,
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    print(
        json.dumps(
            {
                "ocr_required_count": sum(
                    target["runtime_parser_status"] == "ocr_required"
                    for target in manifest["targets"]
                ),
                "ready_count": sum(
                    target["runtime_parser_status"] == "ready" for target in manifest["targets"]
                ),
                "target_count": len(manifest["targets"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
