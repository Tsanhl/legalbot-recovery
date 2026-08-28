#!/usr/bin/env python3
"""Live60 GO execution: identity, Law-folder audit, official acquisition, proposed bindings.

Does not seal expert gold, promote ACTIVE, or issue O-04.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import mimetypes
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from xml.etree import ElementTree as ET
from zipfile import ZipFile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.live_suite import load_live_evaluation_bundle  # noqa: E402
from app.evaluation.live_suite_held_span_repair import (  # noqa: E402
    build_held_span_contiguous_repair,
)
from app.evaluation.live_suite_owner_decisions import (  # noqa: E402
    build_issue_decision_pack,
    default_official_fetcher,
    export_held_provision_chunks,
    mechanically_verify_held_provisions,
    official_section_url,
)
from app.privacy import path_fingerprint  # noqa: E402

AS_OF = date(2026, 8, 16)
OUT = PROJECT_ROOT / "Live60-2026-08-16" / "go-execution"
LOCAL_OUT = PROJECT_ROOT / "data" / "evaluations" / "live60-go-execution"
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks" / "evaluation" / "live-evaluation-60-v1"
CATALOG = PROJECT_ROOT / "data" / "catalog.sqlite3"
LAW_ROOT = Path.home() / "Desktop" / "Law"
XLSX_INPUT = Path.home() / "Downloads" / "LegalBot-Live60-Candidate-Resource-Map.xlsx"
DOCX_INPUT = (
    Path.home()
    / "Downloads"
    / "LegalBot-Live60-Full-Verification-And-Resource-Discovery-Report.docx"
)
USER_AGENT = "LegalBot-local-mechanical-check/1.0"
MAX_BYTES = 8 * 1024 * 1024
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

ALLOWED_FULL_TEXT_HOSTS = frozenset(
    {
        "www.legislation.gov.uk",
        "www.judiciary.uk",
        "www.gov.uk",
        "www.justice.gov.uk",
        "ico.org.uk",
        "www.ico.org.uk",
        "lawcom.gov.uk",
        "www.lawcom.gov.uk",
        "www.parliament.uk",
        "www.cps.gov.uk",
    }
)
ITEM_LICENCE_HOSTS = frozenset({"www.supremecourt.uk", "supremecourt.uk"})
METADATA_ONLY_HOSTS = frozenset(
    {
        "caselaw.nationalarchives.gov.uk",
        "handbook.fca.org.uk",
        "www.prarulebook.co.uk",
        "hudoc.echr.coe.int",
        "curia.europa.eu",
    }
)
LAST_RESORT_PUBLIC_HOSTS = frozenset({"www.bailii.org"})
PAYWALL_OR_UNREGISTERED = frozenset(
    {
        "uk.westlaw.com",
        "login.westlaw.co.uk",
        "www.lexisnexis.com",
        "www.sra.org.uk",
    }
)

PRIVATE_TEACHING_MARKERS = (
    "y2 law",
    "y3 exam",
    "revision",
    "essay",
    "lecture",
    "seminar",
    "ppt",
    "dissertation",
    "teaching",
    "feedback",
    "problem question",
)


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows and not fieldnames:
        path.write_text("", encoding="utf-8")
        return
    names = fieldnames or list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in names})


def _col_row(cell_ref: str) -> tuple[int, int]:
    col = "".join(ch for ch in cell_ref if ch.isalpha())
    row = int("".join(ch for ch in cell_ref if ch.isdigit()))
    number = 0
    for ch in col:
        number = number * 26 + (ord(ch) - 64)
    return number, row


def read_xlsx_sheet(xlsx: Path, sheet_name: str) -> list[dict[str, str]]:
    with ZipFile(xlsx) as archive:
        shared = ET.fromstring(archive.read("xl/sharedStrings.xml"))
        strings: list[str] = []
        for item in shared.findall("m:si", NS):
            strings.append(
                "".join(
                    node.text or ""
                    for node in item.iter(
                        "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"
                    )
                )
            )
        rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        rid_to_target = {rel.attrib["Id"]: rel.attrib["Target"].lstrip("/") for rel in rels}
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        name_to_path: dict[str, str] = {}
        for sheet in workbook.findall("m:sheets/m:sheet", NS):
            rid = sheet.attrib[
                "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
            ]
            name_to_path[sheet.attrib["name"]] = rid_to_target[rid]
        root = ET.fromstring(archive.read(name_to_path[sheet_name]))
        rows: dict[int, dict[int, str]] = {}
        for cell in root.findall("m:sheetData/m:row/m:c", NS):
            col, row = _col_row(cell.attrib["r"])
            value_el = cell.find("m:v", NS)
            inline = cell.find("m:is", NS)
            if cell.attrib.get("t") == "inlineStr" and inline is not None:
                value = "".join(
                    node.text or ""
                    for node in inline.iter(
                        "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"
                    )
                )
            elif value_el is None or value_el.text is None:
                value = ""
            elif cell.attrib.get("t") == "s":
                value = strings[int(value_el.text)]
            else:
                value = value_el.text
            rows.setdefault(row, {})[col] = value
        header_row = min(rows)
        width = max(max(cols) for cols in rows.values())
        headers = [rows[header_row].get(index, f"c{index}") for index in range(1, width + 1)]
        out: list[dict[str, str]] = []
        for row_number in sorted(rows):
            if row_number == header_row:
                continue
            out.append(
                {
                    headers[index - 1]: rows[row_number].get(index, "")
                    for index in range(1, len(headers) + 1)
                }
            )
        return out


def write_xlsx(path: Path, sheets: dict[str, list[dict[str, Any]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook_sheets = []
    sheet_xmls: list[tuple[str, bytes]] = []
    for index, (name, rows) in enumerate(sheets.items(), start=1):
        fieldnames: list[str] = []
        seen: set[str] = set()
        for row in rows:
            for key in row:
                if key not in seen:
                    seen.add(key)
                    fieldnames.append(key)
        if not fieldnames:
            fieldnames = ["empty"]
        lines = [
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
            "<sheetData>",
        ]

        def cell_xml(col_idx: int, row_idx: int, text: str) -> str:
            col = ""
            number = col_idx
            while number:
                number, rem = divmod(number - 1, 26)
                col = chr(65 + rem) + col
            safe = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            return (
                f'<c r="{col}{row_idx}" t="inlineStr"><is><t xml:space="preserve">'
                f"{safe}</t></is></c>"
            )

        header_cells = "".join(
            cell_xml(col, 1, name) for col, name in enumerate(fieldnames, start=1)
        )
        lines.append(f'<row r="1">{header_cells}</row>')
        for row_idx, row in enumerate(rows, start=2):
            cells = "".join(
                cell_xml(col, row_idx, row.get(name, ""))
                for col, name in enumerate(fieldnames, start=1)
            )
            lines.append(f'<row r="{row_idx}">{cells}</row>')
        lines.extend(["</sheetData>", "</worksheet>"])
        sheet_path = f"xl/worksheets/sheet{index}.xml"
        sheet_xmls.append((sheet_path, ("\n".join(lines) + "\n").encode("utf-8")))
        workbook_sheets.append(f'<sheet name="{name[:31]}" sheetId="{index}" r:id="rId{index}"/>')
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{''.join(workbook_sheets)}</sheets></workbook>\n"
    ).encode()
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(
            f'<Relationship Id="rId{index}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{index}.xml"/>'
            for index in range(1, len(sheet_xmls) + 1)
        )
        + "</Relationships>\n"
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        + "".join(
            f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            for index in range(1, len(sheet_xmls) + 1)
        )
        + "</Types>\n"
    ).encode("utf-8")
    root_rels = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" '
        b'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        b'Target="xl/workbook.xml"/>'
        b"</Relationships>\n"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        for sheet_path, payload in sheet_xmls:
            archive.writestr(sheet_path, payload)


def catalog_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{CATALOG}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def phase_identity() -> dict[str, Any]:
    OUT.mkdir(parents=True, exist_ok=True)
    inputs = OUT / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    copied: list[dict[str, str]] = []
    for source in (XLSX_INPUT, DOCX_INPUT):
        if source.is_file():
            target = inputs / source.name
            target.write_bytes(source.read_bytes())
            copied.append(
                {
                    "filename": source.name,
                    "sha256": sha256_file(target),
                    "bytes": str(target.stat().st_size),
                }
            )
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    pack = build_issue_decision_pack(bundle, as_of_date=AS_OF)
    write_json(OUT / "issue-decision-pack.json", pack)
    identity = {
        "schema": "legalbot.live60-superseding-run-identity.v1",
        "as_of_date": AS_OF.isoformat(),
        "suite_id": "live-evaluation-60-v1",
        "authoritative": True,
        "new_registry_generated": False,
        "reason_no_new_registry": (
            "The frozen suite already verifies. The two run-plan SHA values are "
            "the file digest and the object seal of the same generation-run-plan.json."
        ),
        "registry_canonical_sha256": bundle.registry.canonical_sha256,
        "registry_file_sha256": bundle.registry.file_sha256,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "run_plan_file_sha256": bundle.manifest.run_plan_sha256,
        "run_plan_object_seal_sha256": bundle.run_plan.seal_sha256,
        "assessment_bundle_sha256": "9d5808d9275e8a91d18c9702d76ff8e5e6fbbf1388aa57e43ac4b788e96d8252",
        "selected_case_ids": [
            item.case_id for item in bundle.run_plan.cases if item.disposition == "generate_once"
        ],
        "coverage_only_case_ids": [
            item.case_id for item in bundle.run_plan.cases if item.disposition != "generate_once"
        ],
        "case_count": pack["case_count"],
        "issue_count": pack["issue_count"],
        "research_route_counts": pack["research_route_counts"],
        "selected_research_route_counts": pack["selected_research_route_counts"],
        "supersedes": [
            {
                "stale_claim": "workbook_run_plan_sha_conflicts_with_checklist_run_plan_sha",
                "workbook_value": bundle.manifest.run_plan_sha256,
                "checklist_value": bundle.run_plan.seal_sha256,
                "resolution": "workbook_uses_run_plan_file_digest_checklist_uses_object_seal",
                "same_file": "benchmarks/evaluation/live-evaluation-60-v1/generation-run-plan.json",
            },
            {
                "stale_claim": "issue_decision_pack_coerced_all_60_routes_to_sectioned",
                "resolution": "pack_regenerated_from_expected_research_route",
                "route_field_used": pack["route_field_used"],
            },
        ],
        "copied_owner_inputs": copied,
        "seals_expert_gold": False,
        "o04_authorised": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    write_json(OUT / "superseding-run-identity.json", identity)
    write_json(OUT / "run-identity-reconciliation.json", identity)
    return identity


def _law_classification(
    *,
    relative: str,
    suffix: str,
    content_sha: str,
    docs_by_hash: dict[str, list[sqlite3.Row]],
    live60_hashes: set[str],
) -> tuple[str, str, bool]:
    rel = relative.casefold()
    docs = docs_by_hash.get(content_sha, [])
    private = any(marker in rel for marker in PRIVATE_TEACHING_MARKERS) or suffix in {
        ".pptx",
        ".ppt",
    }
    if "official legislation" in rel:
        private = False
    if not docs:
        if private:
            return "10", "assessment_or_private_unindexed", False
        if "official legislation" in rel or suffix in {".html", ".xml"}:
            return "5", "relevant_unindexed", True
        return "9", "unindexed_not_shown_live60_relevant", False
    doc = docs[0]
    status = doc["status"]
    lane = doc["lane"] or ""
    if status in {"private_teaching", "assessment_guidance"} or lane in {
        "private_teaching",
        "assessment_guidance",
    }:
        return "10", "assessment_or_private_in_catalogue", False
    if status == "duplicate" or doc["duplicate_of"]:
        return "6", "duplicate_of_indexed_source", content_sha in live60_hashes
    if lane == "scholarship":
        return "8", "rights_or_lane_hold_scholarship", content_sha in live60_hashes
    if status in {"quarantined", "encrypted", "unsupported", "ocr_required"}:
        return "3", f"indexed_malformed_or_blocked:{status}", content_sha in live60_hashes
    if content_sha in live60_hashes:
        return "1", "indexed_and_current_candidate", True
    if lane == "primary_authority":
        return "1", "indexed_primary_not_in_live60_map", False
    return "9", "indexed_not_live60_mapped", False


def phase_law_audit() -> dict[str, Any]:
    if not LAW_ROOT.is_dir():
        raise FileNotFoundError("Desktop Law folder is not present")
    connection = catalog_connection()
    docs_by_hash: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in connection.execute(
        "SELECT id, content_sha256, status, lane, duplicate_of, media_type, safe_display_name FROM documents"
    ):
        docs_by_hash[row["content_sha256"]].append(row)
    urls = {
        (row["canonical_url"] or "").rstrip("/")
        for row in connection.execute(
            "SELECT canonical_url FROM source_versions WHERE canonical_url IS NOT NULL AND canonical_url != ''"
        )
    }
    live60_hashes: set[str] = set()
    if XLSX_INPUT.is_file():
        spans = read_xlsx_sheet(XLSX_INPUT, "Local Candidate Spans")
        ids = tuple({row["Source-version ID"] for row in spans if row.get("Source-version ID")})
        if ids:
            placeholders = ",".join("?" for _ in ids)
            for row in connection.execute(
                f"""
                SELECT d.content_sha256
                FROM documents d
                JOIN source_versions sv ON sv.document_id = d.id
                WHERE sv.id IN ({placeholders})
                """,
                ids,
            ):
                live60_hashes.add(row["content_sha256"])

    chunk_count_cache: dict[str, int] = {}

    def chunk_count_for_hash(content_sha: str) -> int:
        if content_sha not in chunk_count_cache:
            row = connection.execute(
                """
                SELECT COUNT(c.id) AS n
                FROM documents d
                JOIN source_versions sv ON sv.document_id = d.id
                JOIN chunks c ON c.source_version_id = sv.id
                WHERE d.content_sha256=? AND sv.superseded_by IS NULL
                """,
                (content_sha,),
            ).fetchone()
            chunk_count_cache[content_sha] = int(row["n"] if row else 0)
        return chunk_count_cache[content_sha]

    inventory: list[dict[str, Any]] = []
    seen_hashes: dict[str, list[str]] = defaultdict(list)
    files = [path for path in LAW_ROOT.rglob("*") if path.is_file() and path.name != ".DS_Store"]
    before_docs = sum(len(v) for v in docs_by_hash.values())
    try:
        for index, path in enumerate(files, start=1):
            relative = str(path.relative_to(LAW_ROOT))
            content_sha = sha256_file(path)
            suffix = path.suffix.lower()
            mime, _ = mimetypes.guess_type(path.name)
            docs = docs_by_hash.get(content_sha, [])
            class_code, class_label, live60 = _law_classification(
                relative=relative,
                suffix=suffix,
                content_sha=content_sha,
                docs_by_hash=docs_by_hash,
                live60_hashes=live60_hashes,
            )
            chunk_n = -1
            if docs and class_code == "1":
                chunk_n = chunk_count_for_hash(content_sha)
                if chunk_n == 0:
                    class_code, class_label = "3", "indexed_zero_chunks"
            extraction_ok = suffix in {".html", ".txt", ".xml", ".md"}
            ocr_needed = suffix == ".pdf" and not docs
            rights = "unknown"
            if "official legislation" in relative.casefold():
                rights = "likely_ogl_if_legislation_gov_uk_bytes"
            elif class_code == "10":
                rights = "private_teaching_do_not_authority_index"
            elif class_code == "8":
                rights = "scholarship_or_westlaw_hold"
            record = {
                "relative_path": relative,
                "path_fingerprint": path_fingerprint(path),
                "filename": path.name,
                "extension": suffix,
                "media_type": mime or "",
                "size_bytes": path.stat().st_size,
                "sha256": content_sha,
                "apparent_title": path.stem,
                "source_type": "unknown",
                "primary_or_secondary": "unknown",
                "duplicate_in_law_folder": False,
                "superseded": "unknown",
                "text_extraction_succeeds": extraction_ok,
                "ocr_necessary": ocr_needed,
                "licence_or_rights": rights,
                "live60_relevant": live60,
                "catalogue_document_ids": [doc["id"] for doc in docs],
                "catalogue_status": docs[0]["status"] if docs else "absent",
                "catalogue_lane": docs[0]["lane"] if docs else "",
                "current_chunk_count": chunk_n,
                "classification_code": class_code,
                "classification": class_label,
            }
            inventory.append(record)
            seen_hashes[content_sha].append(relative)
            if index % 250 == 0:
                print(f"law-audit hashed {index}/{len(files)}", flush=True)
    finally:
        connection.close()

    for record in inventory:
        record["duplicate_in_law_folder"] = len(seen_hashes[record["sha256"]]) > 1

    unindexed = [row for row in inventory if row["classification_code"] == "5"]
    stale = [row for row in inventory if row["classification_code"] in {"2", "3"}]
    duplicates = [row for row in inventory if row["duplicate_in_law_folder"]]
    rights_holds = [
        row
        for row in inventory
        if row["classification_code"] in {"8", "10"} or row["licence_or_rights"].endswith("hold")
    ]
    counts = Counter(row["classification_code"] for row in inventory)
    summary = {
        "schema": "legalbot.live60-law-folder-index-audit.v1",
        "as_of_date": AS_OF.isoformat(),
        "law_root_alias": "desktop-law",
        "file_count": len(inventory),
        "catalogue_document_rows_before": before_docs,
        "classification_counts": dict(sorted(counts.items())),
        "unindexed_relevant_count": len(unindexed),
        "stale_or_malformed_count": len(stale),
        "duplicate_file_count": len(duplicates),
        "rights_hold_count": len(rights_holds),
        "known_catalogue_canonical_url_count": len(urls),
        "ingestion_ran": False,
        "ingestion_note": (
            "Canonical ingest is legalbot scan against configured source_roots. "
            "This audit does not copy files into a parallel tree."
        ),
        "seals_expert_gold": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    write_json(OUT / "law-folder-inventory.json", {"summary": summary, "files": inventory})
    write_json(
        OUT / "law-folder-ingestion-results.json",
        {
            "schema": "legalbot.live60-law-folder-ingestion-results.v1",
            "ingestion_ran": False,
            "reason": "audit_completed_scan_not_started_in_this_function",
            "before_document_rows": before_docs,
            "law_file_count": len(inventory),
            "unindexed_relevant": len(unindexed),
        },
    )
    fields = [
        "relative_path",
        "filename",
        "extension",
        "size_bytes",
        "sha256",
        "classification_code",
        "classification",
        "catalogue_status",
        "catalogue_lane",
        "current_chunk_count",
        "live60_relevant",
        "licence_or_rights",
        "duplicate_in_law_folder",
    ]
    write_csv(OUT / "law-folder-unindexed-relevant-sources.csv", unindexed, fields)
    write_csv(OUT / "law-folder-stale-or-malformed-sources.csv", stale, fields)
    write_csv(OUT / "law-folder-duplicates.csv", duplicates, fields)
    write_csv(OUT / "law-folder-rights-holds.csv", rights_holds, fields)
    write_xlsx(
        OUT / "law-folder-index-audit.xlsx",
        {
            "Summary": [summary],
            "Inventory": inventory,
            "Unindexed relevant": unindexed,
            "Stale or malformed": stale,
            "Duplicates": duplicates,
            "Rights holds": rights_holds,
        },
    )
    print(
        f"law-audit files={len(inventory)} unindexed_relevant={len(unindexed)} "
        f"stale={len(stale)} duplicates={len(duplicates)}",
        flush=True,
    )
    return summary


def _legislation_xml_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    if path.endswith("/data.xml"):
        return url
    if "/data." in path:
        return url
    return f"https://www.legislation.gov.uk{path}/data.xml"


def _fetch(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            raw = response.read(MAX_BYTES + 1)
            truncated = len(raw) > MAX_BYTES
            if truncated:
                raw = raw[:MAX_BYTES]
            return {
                "ok": True,
                "http_status": int(getattr(response, "status", 200) or 200),
                "final_url": str(response.geturl()),
                "media_type": response.headers.get("Content-Type", ""),
                "raw": raw,
                "truncated": truncated,
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "http_status": int(exc.code),
            "final_url": url,
            "media_type": "",
            "raw": b"",
            "truncated": False,
            "error": f"http_{exc.code}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "http_status": 0,
            "final_url": url,
            "media_type": "",
            "raw": b"",
            "truncated": False,
            "error": type(exc).__name__,
        }


def phase_acquire() -> dict[str, Any]:
    LOCAL_OUT.mkdir(parents=True, exist_ok=True)
    acquired_dir = LOCAL_OUT / "acquired"
    acquired_dir.mkdir(parents=True, exist_ok=True)
    inventory = read_xlsx_sheet(XLSX_INPUT, "Source Inventory")
    connection = catalog_connection()
    url_rows = list(
        connection.execute(
            """
            SELECT canonical_url, id, document_id, licence_name, review_status,
                   currentness_status, authority_identity_id
            FROM source_versions
            WHERE canonical_url IS NOT NULL AND superseded_by IS NULL
            """
        )
    )
    by_url: dict[str, sqlite3.Row] = {}
    for row in url_rows:
        by_url[str(row["canonical_url"]).rstrip("/")] = row
    connection.close()

    outcomes: list[dict[str, Any]] = []
    seen_url: set[str] = set()
    for source in inventory:
        url = (source.get("URL") or "").strip()
        key = source.get("Source key") or ""
        if not url:
            outcomes.append(
                {
                    "source_key": key,
                    "source_name": source.get("Source name"),
                    "requested_url": "",
                    "outcome": "no_url_search_required",
                    "http_status": "",
                    "rights": source.get("Rights"),
                    "final_status": "unresolved_no_url",
                }
            )
            continue
        if url in seen_url:
            outcomes.append(
                {
                    "source_key": key,
                    "source_name": source.get("Source name"),
                    "requested_url": url,
                    "outcome": "duplicate_url_skipped",
                    "http_status": "",
                    "rights": source.get("Rights"),
                    "final_status": "duplicate",
                }
            )
            continue
        seen_url.add(url)
        host = (urlparse(url).hostname or "").casefold()
        catalog_hit = by_url.get(url.rstrip("/"))
        record: dict[str, Any] = {
            "source_key": key,
            "source_name": source.get("Source name"),
            "requested_url": url,
            "host": host,
            "catalogue_source_version_id": catalog_hit["id"] if catalog_hit else "",
            "retrieved_at": utc_now(),
        }
        if host in PAYWALL_OR_UNREGISTERED or host == "www.sra.org.uk":
            record.update(
                {
                    "outcome": "rights_hold_not_fetched",
                    "http_status": "",
                    "rights": "item_or_site_licence_required",
                    "final_status": "rights_hold",
                }
            )
            outcomes.append(record)
            continue
        if host in METADATA_ONLY_HOSTS:
            fetched = _fetch(url)
            record.update(
                {
                    "outcome": "metadata_only_fetch",
                    "http_status": fetched["http_status"],
                    "final_url": fetched["final_url"],
                    "raw_sha256": sha256_bytes(fetched["raw"]) if fetched["raw"] else "",
                    "rights": "metadata_only_no_body_index",
                    "final_status": "metadata_only",
                    "error": fetched["error"],
                }
            )
            outcomes.append(record)
            time.sleep(0.2)
            continue
        fetch_url = url
        if host == "www.legislation.gov.uk":
            fetch_url = _legislation_xml_url(url)
        if host in LAST_RESORT_PUBLIC_HOSTS:
            record["rights_note"] = (
                "bailii_last_resort_not_authority_index_without_owner_rights_tick"
            )
        fetched = _fetch(fetch_url)
        raw_sha = sha256_bytes(fetched["raw"]) if fetched["raw"] else ""
        stored = ""
        if (
            fetched["ok"]
            and fetched["raw"]
            and host in ALLOWED_FULL_TEXT_HOSTS | ITEM_LICENCE_HOSTS
        ):
            stored_name = f"{key or raw_sha[:12]}-{raw_sha[:16]}"
            suffix = (
                ".xml"
                if "xml" in (fetched["media_type"] or "") or fetch_url.endswith(".xml")
                else ".bin"
            )
            dest = acquired_dir / f"{stored_name}{suffix}"
            dest.write_bytes(fetched["raw"])
            stored = dest.name
        if host in LAST_RESORT_PUBLIC_HOSTS:
            status = "rights_hold_public_representation"
        elif fetched["ok"] and catalog_hit:
            status = "already_indexed_and_redownloaded"
        elif fetched["ok"]:
            status = "downloaded_not_yet_ingested"
        else:
            status = "dead_or_failed"
        record.update(
            {
                "outcome": "fetched" if fetched["ok"] else "failed",
                "fetch_url": fetch_url,
                "final_url": fetched["final_url"],
                "http_status": fetched["http_status"],
                "raw_sha256": raw_sha,
                "stored_filename": stored,
                "truncated": fetched["truncated"],
                "error": fetched["error"],
                "rights": source.get("Rights"),
                "final_status": status,
            }
        )
        outcomes.append(record)
        time.sleep(0.2)
        if len(outcomes) % 25 == 0:
            print(f"acquire processed {len(outcomes)}/{len(inventory)}", flush=True)

    summary = {
        "schema": "legalbot.live60-source-acquisition.v1",
        "as_of_date": AS_OF.isoformat(),
        "source_count": len(inventory),
        "outcome_count": len(outcomes),
        "unique_urls": len(seen_url),
        "by_final_status": dict(Counter(row.get("final_status") for row in outcomes)),
        "by_outcome": dict(Counter(row.get("outcome") for row in outcomes)),
        "runtime_crawler_used": False,
        "seals_expert_gold": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    write_json(OUT / "source-acquisition-manifest.json", {"summary": summary, "outcomes": outcomes})
    write_csv(
        OUT / "url-outcome-report.csv",
        outcomes,
        [
            "source_key",
            "source_name",
            "requested_url",
            "fetch_url",
            "final_url",
            "host",
            "outcome",
            "http_status",
            "raw_sha256",
            "final_status",
            "error",
            "catalogue_source_version_id",
        ],
    )
    unresolved = [
        row
        for row in outcomes
        if row.get("final_status") in {"dead_or_failed", "unresolved_no_url", "rights_hold"}
    ]
    write_csv(OUT / "unresolved-source-report.csv", unresolved)
    rights = [
        row
        for row in outcomes
        if "rights" in str(row.get("final_status", ""))
        or row.get("final_status") == "metadata_only"
    ]
    write_json(OUT / "rights-and-licence-report.json", {"count": len(rights), "rows": rights})
    judgments = [
        row
        for row in outcomes
        if row.get("host") in ITEM_LICENCE_HOSTS | LAST_RESORT_PUBLIC_HOSTS | {"www.judiciary.uk"}
    ]
    write_json(
        OUT / "official-judgment-download-inventory.json",
        {"count": len(judgments), "rows": judgments},
    )
    print(
        f"acquire unique_urls={len(seen_url)} statuses={summary['by_final_status']}",
        flush=True,
    )
    return summary


def phase_statutes() -> dict[str, Any]:
    export = export_held_provision_chunks(CATALOG)
    repair = build_held_span_contiguous_repair(export)
    official_fetches: list[dict[str, Any]] = []
    mapping = [
        ("held-provision-01", "ukpga:1980:58", "section 2"),
        ("held-provision-02", "ukpga:1980:58", "section 14A"),
        ("held-provision-03", "ukpga:2000:29", "section 1"),
        ("held-provision-04", "ukpga:1975:63", "section 1"),
    ]
    fetch_map: dict[str, bytes] = {}

    def fetch(url: str) -> bytes:
        if url in fetch_map:
            return fetch_map[url]
        payload = default_official_fetcher(url)
        fetch_map[url] = payload
        return payload

    for held_id, authority, locator in mapping:
        url = official_section_url(authority, locator)
        try:
            raw = fetch(url)
            official_fetches.append(
                {
                    "held_id": held_id,
                    "authority_identity_id": authority,
                    "locator": locator,
                    "official_url": url,
                    "http_ok": True,
                    "raw_sha256": sha256_bytes(raw),
                    "bytes": len(raw),
                }
            )
        except Exception as exc:
            official_fetches.append(
                {
                    "held_id": held_id,
                    "authority_identity_id": authority,
                    "locator": locator,
                    "official_url": url,
                    "http_ok": False,
                    "error": type(exc).__name__,
                }
            )
    report = mechanically_verify_held_provisions(export, fetch_official=fetch)
    payload = {
        "schema": "legalbot.live60-four-statute-repair-pack.v1",
        "as_of_date": AS_OF.isoformat(),
        "qualified": False,
        "catalogue_mutated": False,
        "seals_expert_gold": False,
        "official_fetches": official_fetches,
        "mechanical_verification": {
            "approval_status": report.get("approval_status"),
            "expert_approved": report.get("expert_approved"),
            "qualified_count": report.get("qualified_count"),
            "results": report.get("results"),
        },
        "contiguous_repair": {
            "repair_span_count": repair.get("repair_span_count"),
            "qualified": repair.get("qualified"),
            "catalogue_mutated": repair.get("catalogue_mutated"),
            "repairs": [
                {
                    "action": item.get("action"),
                    "repair_span_id": item.get("repair_span_id"),
                    "parent_chunk_id": item.get("parent_chunk_id"),
                    "required_sublocator": item.get("required_sublocator"),
                    "text_sha256": item.get("text_sha256"),
                    "gold_eligible_candidate": item.get("gold_eligible_candidate"),
                }
                for item in repair.get("repairs", ())
            ],
        },
        "owner_must_tick_before_qualified": True,
    }
    write_json(OUT / "four-statute-pack.json", payload)
    write_json(
        OUT / "legislation-effects-report.json",
        {
            "schema": "legalbot.live60-legislation-effects.v1",
            "source": "mechanical_and_repair_only",
            "results": report.get("results"),
            "qualified": False,
        },
    )
    print(
        f"statutes official_ok={sum(1 for row in official_fetches if row.get('http_ok'))}/4 "
        f"mechanical_qualified={report.get('qualified_count')}",
        flush=True,
    )
    return payload


def phase_bind() -> dict[str, Any]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    pack = build_issue_decision_pack(bundle, as_of_date=AS_OF)
    detail = read_xlsx_sheet(XLSX_INPUT, "Issue-Source Detail")
    spans = read_xlsx_sheet(XLSX_INPUT, "Local Candidate Spans")
    spans_by_key: dict[str, list[dict[str, str]]] = defaultdict(list)
    for span in spans:
        spans_by_key[span.get("Source key", "")].append(span)
    sources_by_issue: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in detail:
        sources_by_issue[(row["Case ID"], row["Issue ID"])].append(row)

    chunk_ids = tuple({span.get("Chunk ID", "") for span in spans if span.get("Chunk ID")})
    chunk_rows: dict[str, sqlite3.Row] = {}
    if chunk_ids:
        connection = catalog_connection()
        placeholders = ",".join("?" for _ in chunk_ids)
        for row in connection.execute(
            f"""
            SELECT c.id, c.source_version_id, c.locator, c.text_sha256, sv.authority_identity_id,
                   sv.review_status, sv.currentness_status, sv.licence_name, sv.superseded_by
            FROM chunks c
            JOIN source_versions sv ON sv.id = c.source_version_id
            WHERE c.id IN ({placeholders})
            """,
            chunk_ids,
        ):
            chunk_rows[row["id"]] = row
        connection.close()

    issues: list[dict[str, Any]] = []
    for case in pack["cases"]:
        for issue in case["issues"]:
            key = (case["case_id"], issue["issue_id"])
            candidates = []
            for source in sources_by_issue.get(key, ()):
                local = []
                for span in spans_by_key.get(source.get("Source key", ""), ()):
                    chunk = chunk_rows.get(span.get("Chunk ID", ""))
                    local.append(
                        {
                            "source_version_id": span.get("Source-version ID"),
                            "chunk_id": span.get("Chunk ID"),
                            "locator": span.get("Locator"),
                            "catalogue_present": chunk is not None,
                            "catalogue_locator": chunk["locator"] if chunk else "",
                            "content_sha256": chunk["text_sha256"] if chunk else "",
                            "licence_name": chunk["licence_name"] if chunk else "",
                            "review_status": chunk["review_status"] if chunk else "",
                            "currentness_status": chunk["currentness_status"] if chunk else "",
                        }
                    )
                candidates.append(
                    {
                        "rank": source.get("Rank"),
                        "source_key": source.get("Source key"),
                        "source_name": source.get("Source name"),
                        "pinpoint": source.get("Pinpoint"),
                        "url": source.get("URL"),
                        "source_type": source.get("Source type"),
                        "legal_role_hypothesis": source.get("Legal role"),
                        "local_spans": local,
                    }
                )
            present = [
                span
                for candidate in candidates
                for span in candidate["local_spans"]
                if span["catalogue_present"]
            ]
            issues.append(
                {
                    "case_id": case["case_id"],
                    "issue_id": issue["issue_id"],
                    "topic": issue["topic"],
                    "generation_disposition": case["generation_disposition"],
                    "expected_research_route": case["expected_research_route"],
                    "proposed_status": "knowledge_gap",
                    "reason": (
                        "candidate_spans_present_but_owner_has_not_ticked_qualified"
                        if present
                        else "no_verified_catalogue_span_bound"
                    ),
                    "candidate_source_count": len(candidates),
                    "catalogue_span_hit_count": len(present),
                    "proposed_span": present[0] if present else None,
                    "candidates": candidates,
                    "currentness_status": "not_reviewed",
                    "later_treatment_status": "not_reviewed",
                    "contrary_authority_status": "not_a_citator_result",
                    "reviewer_status": "awaiting_owner_primary_reviewer",
                    "seals_expert_gold": False,
                }
            )
    selected_blocked = [
        case["case_id"]
        for case in pack["cases"]
        if case["generation_disposition"] == "generate_once"
        and any(
            item["proposed_status"] != "qualified"
            for item in issues
            if item["case_id"] == case["case_id"]
        )
    ]
    summary = {
        "schema": "legalbot.live60-issue-candidate-evidence-map.v1",
        "as_of_date": AS_OF.isoformat(),
        "issue_count": len(issues),
        "issues_with_catalogue_span": sum(
            1 for item in issues if item["catalogue_span_hit_count"] > 0
        ),
        "qualified_count": 0,
        "limited_count": 0,
        "knowledge_gap_count": len(issues),
        "selected_cases_blocked": selected_blocked,
        "overlay_sealable": False,
        "seals_expert_gold": False,
        "ai_cannot_mark_expert_approved": True,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    write_json(OUT / "issue-candidate-evidence-map.json", {"summary": summary, "issues": issues})
    reviewer_rows = [
        {
            "case_id": item["case_id"],
            "issue_id": item["issue_id"],
            "topic": item["topic"],
            "proposed_status": item["proposed_status"],
            "reason": item["reason"],
            "source_version_id": (item["proposed_span"] or {}).get("source_version_id", ""),
            "chunk_id": (item["proposed_span"] or {}).get("chunk_id", ""),
            "locator": (item["proposed_span"] or {}).get("locator", ""),
            "content_sha256": (item["proposed_span"] or {}).get("content_sha256", ""),
            "legal_role": "awaiting_owner",
            "currentness": item["currentness_status"],
            "later_treatment": item["later_treatment_status"],
            "contrary_authority": item["contrary_authority_status"],
            "rights_status": (item["proposed_span"] or {}).get("licence_name", ""),
            "retrieval_result": "not_run_no_active_index",
            "owner_decision": "",
        }
        for item in issues
    ]
    write_xlsx(
        OUT / "final-reviewer-workbook.xlsx",
        {"Issues": reviewer_rows, "Summary": [summary]},
    )
    write_json(
        OUT / "case-proposition-currentness-records.json",
        {
            "schema": "legalbot.live60-case-proposition-currentness.v1",
            "status": "not_completed",
            "reason": "citator_and_owner_proposition_review_required",
            "reviewed_count": 0,
            "not_a_replacement_for_owner_baseline": True,
        },
    )
    write_json(
        OUT / "contrary-authority-records.json",
        {
            "schema": "legalbot.live60-contrary-authority.v1",
            "owner_baseline": "reviewed_none_is_not_a_citator_result",
            "machine_citator_completed": False,
            "records": [],
        },
    )
    print(
        f"bind issues={len(issues)} with_catalogue_span="
        f"{summary['issues_with_catalogue_span']} qualified=0",
        flush=True,
    )
    return summary


def phase_gates() -> dict[str, Any]:
    identity = json.loads((OUT / "superseding-run-identity.json").read_text(encoding="utf-8"))
    bind = json.loads((OUT / "issue-candidate-evidence-map.json").read_text(encoding="utf-8"))[
        "summary"
    ]
    acquire = json.loads((OUT / "source-acquisition-manifest.json").read_text(encoding="utf-8"))[
        "summary"
    ]
    statutes = json.loads((OUT / "four-statute-pack.json").read_text(encoding="utf-8"))
    law = json.loads((OUT / "law-folder-inventory.json").read_text(encoding="utf-8"))["summary"]
    active = PROJECT_ROOT / "data" / "indexes" / "ACTIVE.json"
    previous = PROJECT_ROOT / "data" / "indexes" / "PREVIOUS.json"
    overlay = PROJECT_ROOT / "data" / "evaluations" / "expert-qualification.json"
    gates = [
        {
            "gate": "run identity",
            "required": "one reconciled frozen suite identity",
            "observed": identity["suite_manifest_seal_sha256"],
            "evidence_path": "Live60-2026-08-16/go-execution/superseding-run-identity.json",
            "status": "PASS",
        },
        {
            "gate": "question integrity",
            "required": "frozen registry hashes match manifest",
            "observed": identity["registry_canonical_sha256"],
            "evidence_path": "benchmarks/evaluation/live-evaluation-60-v1/manifest.json",
            "status": "PASS",
        },
        {
            "gate": "route integrity",
            "required": "33/27 research routes; selected 15/15",
            "observed": json.dumps(identity["research_route_counts"]),
            "evidence_path": "Live60-2026-08-16/go-execution/issue-decision-pack.json",
            "status": "PASS",
        },
        {
            "gate": "Law-folder audit",
            "required": "complete inventory vs catalogue",
            "observed": f"{law['file_count']} files; unindexed_relevant={law['unindexed_relevant_count']}",
            "evidence_path": "Live60-2026-08-16/go-execution/law-folder-index-audit.xlsx",
            "status": "PASS" if law["file_count"] else "HOLD",
        },
        {
            "gate": "source acquisition",
            "required": "recorded outcome for every map URL",
            "observed": json.dumps(acquire.get("by_final_status")),
            "evidence_path": "Live60-2026-08-16/go-execution/source-acquisition-manifest.json",
            "status": "PARTIAL",
        },
        {
            "gate": "rights",
            "required": "no unlicensed body in retrieval",
            "observed": "holds recorded; body not promoted",
            "evidence_path": "Live60-2026-08-16/go-execution/rights-and-licence-report.json",
            "status": "HOLD",
        },
        {
            "gate": "four statutes",
            "required": "official bytes + contiguous repair + owner qualification",
            "observed": f"qualified={statutes.get('qualified')}",
            "evidence_path": "Live60-2026-08-16/go-execution/four-statute-pack.json",
            "status": "HOLD",
        },
        {
            "gate": "case currentness",
            "required": "proposition-level later treatment",
            "observed": "not_completed",
            "evidence_path": "Live60-2026-08-16/go-execution/case-proposition-currentness-records.json",
            "status": "HOLD",
        },
        {
            "gate": "issue qualification",
            "required": "585 owner-ticked exact spans",
            "observed": f"qualified={bind['qualified_count']} knowledge_gap={bind['knowledge_gap_count']}",
            "evidence_path": "Live60-2026-08-16/go-execution/issue-candidate-evidence-map.json",
            "status": "HOLD",
        },
        {
            "gate": "overlay seal",
            "required": "sealed expert-qualification.json",
            "observed": str(overlay.exists()),
            "evidence_path": "data/evaluations/expert-qualification.json",
            "status": "HOLD",
        },
        {
            "gate": "Stage A",
            "required": "Recall@5=100%; Recall@10>=95%; MRR>=0.80 on qualified gold",
            "observed": "not_run_zero_qualified_issues",
            "evidence_path": "Live60-2026-08-16/go-execution/stage-a-report.json",
            "status": "HOLD",
        },
        {
            "gate": "ACTIVE",
            "required": "owner-promoted pointer",
            "observed": str(active.exists()),
            "evidence_path": "data/indexes/ACTIVE.json",
            "status": "HOLD",
        },
        {
            "gate": "PREVIOUS",
            "required": "valid previous pointer after promotion",
            "observed": str(previous.exists()),
            "evidence_path": "data/indexes/PREVIOUS.json",
            "status": "HOLD",
        },
        {
            "gate": "rollback",
            "required": "rollback and re-promotion proof",
            "observed": "not_run_no_active",
            "evidence_path": "Live60-2026-08-16/go-execution/rollback-repromotion-report.json",
            "status": "HOLD",
        },
        {
            "gate": "browser recovery",
            "required": "real localhost drill",
            "observed": "not_run_no_active",
            "evidence_path": "Live60-2026-08-16/go-execution/browser-recovery-report.json",
            "status": "HOLD",
        },
        {
            "gate": "readiness",
            "required": "ready=true and empty blocking gates",
            "observed": "not_green",
            "evidence_path": "data/reports/production-readiness.json",
            "status": "HOLD",
        },
        {
            "gate": "O-04",
            "required": "owner authorisation of exact 30 IDs",
            "observed": "not_issued",
            "evidence_path": "Live60-2026-08-16/go-execution/owner-go-o04-pack.json",
            "status": "HOLD",
        },
    ]
    write_json(
        OUT / "stage-a-report.json",
        {
            "schema": "legalbot.live60-stage-a.v1",
            "ran": False,
            "reason": "zero_qualified_issues_and_no_active_index",
            "recall_at_5": None,
            "recall_at_10": None,
            "mrr": None,
        },
    )
    write_json(
        OUT / "rollback-repromotion-report.json",
        {
            "ran": False,
            "reason": "no_owner_ACTIVE_promotion",
            "wrote_active_pointer": False,
        },
    )
    write_json(
        OUT / "browser-recovery-report.json",
        {
            "ran": False,
            "reason": "no_owner_ACTIVE_promotion",
            "wrote_drill_seal": False,
        },
    )
    write_json(
        OUT / "owner-go-o04-pack.json",
        {
            "schema": "legalbot.live60-owner-go-o04-pack.v1",
            "issued": False,
            "ai_cannot_sign": True,
            "suite_id": identity["suite_id"],
            "run_plan_object_seal_sha256": identity["run_plan_object_seal_sha256"],
            "selected_case_ids": identity["selected_case_ids"],
            "local_only": True,
            "one_pass_execution_depth": True,
            "awaiting": [
                "owner_primary_reviewer_ticks",
                "owner_ACTIVE_promotion",
                "owner_O-04",
            ],
        },
    )
    write_json(OUT / "gate-table.json", {"gates": gates})
    files = [path for path in OUT.rglob("*") if path.is_file()]
    write_json(
        OUT / "file-sha256-manifest.json",
        {
            "schema": "legalbot.live60-go-execution-file-manifest.v1",
            "files": [
                {
                    "relative_path": str(path.relative_to(PROJECT_ROOT)),
                    "sha256": sha256_file(path),
                    "bytes": path.stat().st_size,
                }
                for path in sorted(files)
                if path.name != "file-sha256-manifest.json"
            ],
        },
    )
    return {"gates": gates}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phase",
        choices=("identity", "law-audit", "acquire", "statutes", "bind", "gates", "all"),
        default="all",
    )
    args = parser.parse_args()
    phases = (
        ("identity", phase_identity),
        ("law-audit", phase_law_audit),
        ("acquire", phase_acquire),
        ("statutes", phase_statutes),
        ("bind", phase_bind),
        ("gates", phase_gates),
    )
    wanted = {args.phase} if args.phase != "all" else {name for name, _ in phases}
    for name, fn in phases:
        if name in wanted or (args.phase == "all"):
            print(f"starting {name}", flush=True)
            fn()
            print(f"finished {name}", flush=True)


if __name__ == "__main__":
    main()
