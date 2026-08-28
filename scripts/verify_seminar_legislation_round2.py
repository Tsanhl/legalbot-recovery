#!/usr/bin/env python3
"""Verify the cross-subject legislation round-two representations and holds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.ingestion.models import ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFESTS = (
    PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v1.json",
    PROJECT_ROOT
    / "config/seminar_gap_official_legislation_round2.2026-08-26.v2-enacted-repair.json",
    PROJECT_ROOT / "config/seminar_gap_official_legislation_round2.2026-08-26.v3-pdf-repair.json",
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-legislation-round2-2026-08-26-verification.json"
)
REPORT_SCHEMA = "legalbot.seminar-gap-official-legislation-verification.v1"
DC = "http://purl.org/dc/elements/1.1/"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("legislation_verification_input_must_be_object")
    return value


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
        raise ValueError("legislation_verification_xml_unsafe_declaration")
    root = ET.fromstring(raw)
    title = root.find(f".//{{{DC}}}title")
    identifier = root.find(f".//{{{DC}}}identifier")
    if title is None or identifier is None:
        raise ValueError("legislation_verification_xml_identity_missing")
    return (
        " ".join("".join(title.itertext()).split()),
        " ".join("".join(identifier.itertext()).split()),
    )


def _catalogue_row(connection: sqlite3.Connection, content_hash: str) -> sqlite3.Row | None:
    rows = connection.execute(
        """
        SELECT d.id AS document_id, d.status, d.lane, d.subject_primary,
               d.media_type, d.retrieval_canonical, sv.id AS source_version_id,
               sv.version_sha256, sv.review_status, sv.currentness_status,
               sv.stable_identifier, sv.canonical_url,
               json_extract(sv.metadata_json, '$.classification_schema')
                 AS classification_schema,
               COUNT(c.id) AS chunk_count,
               SUM(CASE WHEN trim(c.markdown_text)='' THEN 1 ELSE 0 END)
                 AS empty_chunk_count,
               SUM(CASE WHEN c.markdown_text LIKE '%/Users/%' THEN 1 ELSE 0 END)
                 AS path_leak_chunk_count,
               SUM(c.token_count) AS token_count
          FROM documents d
     LEFT JOIN source_versions sv
            ON sv.document_id=d.id AND sv.superseded_by IS NULL
     LEFT JOIN chunks c ON c.source_version_id=sv.id
         WHERE d.content_sha256=?
      GROUP BY d.id, sv.id
        """,
        (content_hash,),
    ).fetchall()
    return rows[0] if len(rows) == 1 else None


def verify(
    *, manifest_paths: tuple[Path, ...], source_root: Path, catalogue_path: Path
) -> dict[str, Any]:
    manifests = [_load(path) for path in manifest_paths]
    source_root = source_root.resolve(strict=True)
    parser = ParserRegistry.default()
    v3_identities = {str(target["authority_identity"]) for target in manifests[2]["targets"]}
    representations: list[dict[str, Any]] = []
    authority_representations: dict[str, list[dict[str, Any]]] = defaultdict(list)

    connection = sqlite3.connect(f"file:{catalogue_path.resolve()}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        active_scans = int(
            connection.execute(
                "SELECT COUNT(*) FROM source_scans WHERE status IN ('queued','running')"
            ).fetchone()[0]
        )
        if active_scans:
            raise ValueError("legislation_verification_requires_no_active_source_scan")
        for manifest_index, manifest in enumerate(manifests):
            for target in manifest["targets"]:
                identity = str(target["authority_identity"])
                relative_path = str(target["source_root_relative_path"])
                source_path = (source_root / relative_path).resolve(strict=True)
                source_path.relative_to(source_root)
                raw = source_path.read_bytes()
                expected_status = "citable"
                if manifest_index == 1 and identity in v3_identities:
                    expected_status = "quarantined"
                if manifest_index == 2 and target["runtime_parser_status"] == "ocr_required":
                    expected_status = "ocr_required"
                parsed = parser.parse(raw, filename=source_path.name)
                row = _catalogue_row(connection, str(target["content_sha256"]))
                checks = {
                    "catalogue_exact_single_document": row is not None,
                    "catalogue_expected_status": row is not None
                    and row["status"] == expected_status,
                    "catalogue_primary_authority_lane": row is not None
                    and row["lane"] == "primary_authority",
                    "file_byte_count_exact": len(raw) == int(target["byte_count"]),
                    "file_hash_exact": hashlib.sha256(raw).hexdigest() == target["content_sha256"],
                    "file_regular_non_symlink": source_path.is_file()
                    and not source_path.is_symlink(),
                }
                if source_path.suffix.casefold() == ".xml":
                    actual_title, actual_identifier = _xml_identity(raw)
                    expected_identifier = str(
                        target.get("representation_identity") or target["authority_identity"]
                    )
                    checks.update(
                        {
                            "official_xml_title_exact": actual_title == target["source_title"],
                            "official_xml_identifier_exact": _normalise_identity(actual_identifier)
                            == _normalise_identity(expected_identifier),
                        }
                    )
                else:
                    checks.update(
                        {
                            "official_pdf_signature_present": raw.startswith(b"%PDF-"),
                            "runtime_parser_status_expected": parsed.status.value
                            == target["runtime_parser_status"],
                            "runtime_parser_ready_has_blocks": (
                                parsed.status is not ParseStatus.READY or bool(parsed.body_blocks)
                            ),
                        }
                    )
                if expected_status == "citable":
                    checks.update(
                        {
                            "catalogue_current_source_version_present": row is not None
                            and row["source_version_id"] is not None,
                            "catalogue_version_hash_exact": row is not None
                            and row["version_sha256"] == target["content_sha256"],
                            "catalogue_classification_schema_v10": row is not None
                            and row["classification_schema"]
                            == "legalbot.content-classification.v10",
                            "chunks_present_nonempty_path_free": row is not None
                            and int(row["chunk_count"] or 0) > 0
                            and int(row["empty_chunk_count"] or 0) == 0
                            and int(row["path_leak_chunk_count"] or 0) == 0,
                        }
                    )
                else:
                    checks["nonready_representation_has_no_chunks"] = (
                        row is not None and int(row["chunk_count"] or 0) == 0
                    )
                record = {
                    "authority_identity": identity,
                    "representation_identity": str(
                        target.get("representation_identity") or target["official_url"]
                    ),
                    "content_sha256": target["content_sha256"],
                    "expected_catalogue_status": expected_status,
                    "checks": checks,
                    "technical_integrity_passed": all(checks.values()),
                    "catalogue": {
                        "chunk_count": int(row["chunk_count"] or 0) if row else 0,
                        "review_status": row["review_status"] if row else None,
                        "subject_primary": row["subject_primary"] if row else None,
                        "token_count": int(row["token_count"] or 0) if row else 0,
                    },
                }
                representations.append(record)
                authority_representations[identity].append(record)
    finally:
        connection.close()

    authorities: list[dict[str, Any]] = []
    for identity, records in sorted(authority_representations.items()):
        citable = [
            record
            for record in records
            if record["expected_catalogue_status"] == "citable"
            and record["technical_integrity_passed"]
        ]
        authorities.append(
            {
                "authority_identity": identity,
                "representation_count": len(records),
                "citable_representation_count": len(citable),
                "retrieval_ready": bool(citable),
                "hold_reason": None if citable else "OCR_TOOLCHAIN_UNAVAILABLE",
                "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                "currentness_extent_effects_gate": "OWNER_REVIEW_REQUIRED",
                "metadata_binding_gate": "OWNER_REVIEW_REQUIRED",
            }
        )

    integrity_failures = sum(not record["technical_integrity_passed"] for record in representations)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "as_of_date": "2026-08-26",
        "manifest_sha256": {path.name: _sha256_file(path) for path in manifest_paths},
        "summary": {
            "authority_count": len(authorities),
            "retrieval_ready_authority_count": sum(
                authority["retrieval_ready"] for authority in authorities
            ),
            "ocr_held_authority_count": sum(
                not authority["retrieval_ready"] for authority in authorities
            ),
            "representation_count": len(representations),
            "technical_integrity_failure_count": integrity_failures,
            "chunk_count": sum(record["catalogue"]["chunk_count"] for record in representations),
            "token_count": sum(record["catalogue"]["token_count"] for record in representations),
        },
        "authorities": authorities,
        "representations": representations,
        "technical_integrity_passed": integrity_failures == 0,
        "full_source_scan_required_before_candidate": True,
        "release_state": "STAGED_OWNER_REVIEW_REQUIRED_WITH_ONE_OCR_HOLD",
        "automatic_source_admission": False,
        "automatic_currentness_approval": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "active_pointer_written": False,
        "live_activation_authorized": False,
    }
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    report["report_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", action="append", type=Path)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifests = tuple(args.manifest) if args.manifest else DEFAULT_MANIFESTS
    report = verify(
        manifest_paths=manifests,
        source_root=args.source_root,
        catalogue_path=args.catalogue,
    )
    _write_exclusive(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["technical_integrity_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
