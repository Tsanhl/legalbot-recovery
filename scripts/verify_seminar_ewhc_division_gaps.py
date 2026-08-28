#!/usr/bin/env python3
"""Verify staged EWHC division resolutions without admitting the authorities."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.ingestion.models import BlockKind, ParseStatus
from app.ingestion.parsers import ParserRegistry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_ewhc_divisions.2026-08-26.v1.json"
)
DEFAULT_SOURCE_ROOT = Path("/Users/hltsang/Desktop/Law")
DEFAULT_CATALOGUE = PROJECT_ROOT / "data/catalog.sqlite3"
DEFAULT_OUTPUT = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-ewhc-divisions-2026-08-26-verification.json"
)
EXPECTED_SCHEMA = "legalbot.seminar-gap-official-ewhc-division-plan.v1"
REPORT_SCHEMA = "legalbot.seminar-gap-official-ewhc-division-verification.v1"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("ewhc_verification_input_must_be_object")
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


def verify(
    *, manifest_path: Path, source_root: Path, catalogue_path: Path
) -> dict[str, Any]:
    manifest = _load(manifest_path)
    if manifest.get("schema") != EXPECTED_SCHEMA:
        raise ValueError("ewhc_verification_manifest_schema_invalid")
    source_root = source_root.resolve(strict=True)
    connection = sqlite3.connect(
        f"file:{catalogue_path.resolve()}?mode=ro&immutable=1", uri=True
    )
    connection.row_factory = sqlite3.Row
    parser = ParserRegistry.default()
    records: list[dict[str, Any]] = []
    try:
        if connection.execute(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ).fetchone():
            raise ValueError("ewhc_verification_requires_no_active_source_scan")
        for target in manifest["targets"]:
            path = (source_root / str(target["source_root_relative_path"])).resolve(
                strict=True
            )
            path.relative_to(source_root)
            raw = path.read_bytes()
            title, citation, uri = _xml_identity(raw)
            parsed = parser.parse(raw, filename=path.name)
            paragraphs = [
                block for block in parsed.body_blocks if block.kind is BlockKind.PARAGRAPH
            ]
            rows = connection.execute(
                """
                SELECT d.status, d.lane, d.retrieval_canonical, sv.version_sha256,
                       sv.review_status, sv.currentness_status,
                       json_extract(sv.metadata_json, '$.classification_schema')
                         AS classification_schema,
                       COUNT(c.id) AS chunk_count,
                       SUM(CASE WHEN trim(c.markdown_text)='' THEN 1 ELSE 0 END)
                         AS empty_chunk_count,
                       SUM(CASE WHEN c.markdown_text LIKE '%/Users/%' THEN 1 ELSE 0 END)
                         AS path_leak_chunk_count,
                       SUM(c.token_count) AS token_count
                  FROM documents d
                  JOIN source_versions sv
                    ON sv.document_id=d.id AND sv.superseded_by IS NULL
             LEFT JOIN chunks c ON c.source_version_id=sv.id
                 WHERE d.content_sha256=?
              GROUP BY d.id, sv.id
                """,
                (target["content_sha256"],),
            ).fetchall()
            row = rows[0] if len(rows) == 1 else None
            expected_uri = str(target["official_url"]).removesuffix("/data.xml")
            checks = {
                "catalogue_exact_single_current_source_version": row is not None,
                "catalogue_citable_primary_authority": row is not None
                and row["status"] == "citable"
                and row["lane"] == "primary_authority",
                "catalogue_retrieval_canonical": row is not None
                and int(row["retrieval_canonical"] or 0) == 1,
                "catalogue_version_hash_exact": row is not None
                and row["version_sha256"] == target["content_sha256"],
                "catalogue_classification_schema_v10": row is not None
                and row["classification_schema"] == "legalbot.content-classification.v10",
                "chunks_present_nonempty_path_free": row is not None
                and int(row["chunk_count"] or 0) > 0
                and int(row["empty_chunk_count"] or 0) == 0
                and int(row["path_leak_chunk_count"] or 0) == 0,
                "file_byte_count_exact": len(raw) == int(target["byte_count"]),
                "file_hash_exact": hashlib.sha256(raw).hexdigest()
                == target["content_sha256"],
                "official_xml_title_exact": title == target["source_title"],
                "official_xml_citation_exact": citation == target["authority_identity"],
                "official_xml_uri_exact": uri == expected_uri,
                "runtime_parser_ready_with_paragraphs": parsed.status is ParseStatus.READY
                and bool(paragraphs),
            }
            records.append(
                {
                    "authority_identity": target["authority_identity"],
                    "content_sha256": target["content_sha256"],
                    "technical_verification_passed": all(checks.values()),
                    "checks": checks,
                    "catalogue": {
                        "chunk_count": int(row["chunk_count"] or 0) if row else 0,
                        "review_status": row["review_status"] if row else None,
                        "token_count": int(row["token_count"] or 0) if row else 0,
                    },
                    "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                    "currentness_gate": "OWNER_REVIEW_REQUIRED",
                    "later_treatment_gate": "OWNER_REVIEW_REQUIRED",
                }
            )
    finally:
        connection.close()
    failures = sum(not record["technical_verification_passed"] for record in records)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "as_of_date": "2026-08-26",
        "manifest_sha256": _sha256_file(manifest_path),
        "summary": {
            "staged_target_count": len(records),
            "technical_pass_count": len(records) - failures,
            "technical_failure_count": failures,
            "already_catalogued_count": len(manifest["already_catalogued"]),
            "still_unresolved_count": len(manifest["still_unresolved"]),
            "chunk_count": sum(record["catalogue"]["chunk_count"] for record in records),
            "token_count": sum(record["catalogue"]["token_count"] for record in records),
        },
        "records": records,
        "already_catalogued": manifest["already_catalogued"],
        "still_unresolved": manifest["still_unresolved"],
        "technical_verification_passed": failures == 0,
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
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = verify(
        manifest_path=args.manifest,
        source_root=args.source_root,
        catalogue_path=args.catalogue,
    )
    _write_exclusive(args.output, report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["technical_verification_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
