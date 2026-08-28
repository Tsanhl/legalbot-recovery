#!/usr/bin/env python3
"""Explicitly ingest the three newly resolved EWHC seminar authorities."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from app.config import Settings
from app.crypto import LocalCipher
from app.db import Database
from app.ingestion.service import ingest_explicit_paths

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_ewhc_divisions.2026-08-26.v1.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-ewhc-divisions-2026-08-26-explicit-ingestion.json"
)
EXPECTED_SCHEMA = "legalbot.seminar-gap-official-ewhc-division-plan.v1"
REPORT_SCHEMA = "legalbot.seminar-gap-official-ewhc-explicit-ingestion.v1"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("ewhc_ingestion_manifest_must_be_object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_exclusive(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
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


def ingest(
    *, manifest_path: Path, source_root: Path, output_path: Path
) -> dict[str, Any]:
    manifest = _load(manifest_path)
    if manifest.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("ewhc_ingestion_manifest_schema_invalid")
    targets = manifest["targets"]
    if len(targets) != 3:
        raise ValueError("ewhc_ingestion_target_inventory_invalid")
    source_root = source_root.resolve(strict=True)
    paths: list[Path] = []
    for target in targets:
        path = (source_root / str(target["source_root_relative_path"])).resolve(strict=True)
        path.relative_to(source_root)
        if path.is_symlink() or not path.is_file():
            raise ValueError("ewhc_ingestion_target_must_be_regular_file")
        if _sha256_file(path) != target["content_sha256"]:
            raise ValueError("ewhc_ingestion_target_hash_mismatch")
        paths.append(path)

    settings = Settings(project_root=PROJECT_ROOT)
    if source_root not in {
        root.expanduser().absolute() for root in settings.source_roots
    }:
        raise ValueError("ewhc_ingestion_source_root_not_configured")
    database = Database(settings.database_path)
    database.initialize()
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ):
            raise ValueError("ewhc_ingestion_requires_no_active_source_scan")
        result = ingest_explicit_paths(
            settings,
            database,
            LocalCipher.from_local_key(create=True),
            "seminar-gap-ewhc-divisions-20260826",
            paths,
        )
    finally:
        database.close()
    if len(result["items"]) != len(targets):
        raise ValueError("ewhc_ingestion_result_cardinality_mismatch")
    records: list[dict[str, Any]] = []
    for target, item in zip(targets, result["items"], strict=True):
        if item["content_sha256"] != target["content_sha256"]:
            raise ValueError("ewhc_ingestion_result_hash_mismatch")
        records.append(
            {
                "authority_identity": target["authority_identity"],
                "content_sha256": target["content_sha256"],
                "status": item["status"],
                "reason": item["reason"],
            }
        )
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "as_of_date": "2026-08-26",
        "manifest_sha256": _sha256_file(manifest_path),
        "summary": {
            "target_count": len(records),
            "citable_count": sum(record["status"] == "citable" for record in records),
            "non_citable_count": sum(record["status"] != "citable" for record in records),
        },
        "records": records,
        "full_source_scan_required_before_candidate": True,
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_later_treatment_approval": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
        "live_activation_authorized": False,
    }
    encoded = json.dumps(
        report, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    report["report_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    _write_exclusive(output_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = ingest(
        manifest_path=args.manifest,
        source_root=args.source_root,
        output_path=args.output,
    )
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["summary"]["non_citable_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
