#!/usr/bin/env python3
"""Materialise paragraph-level reviewed judgment chunks for the Quistclose pack.

The official files and canonical Markdown remain immutable.  This tool creates
additional disposable, content-derived ``chunks`` for the exact reviewed
judgment paragraphs.  Their metadata carries the conservative legal role used
by the runtime quality gate.  It cannot create persisted ``EvidenceSpan`` rows
because those rows must reference a particular immutable index build; retrieval
will create them from these chunks after a candidate is built.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.currentness import (  # noqa: E402
    apply_historical_case_treatment_hold,
)
from backend.app.db import Database  # noqa: E402

from scripts.import_quistclose_authority_pack import (  # noqa: E402
    REPORT_SCHEMA,
    _canonical_sha256,
    validate_manifest,
    verify_representation_payload,
)

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "quistclose_authority_pack.json"
DEFAULT_DOWNLOAD_REPORT = (
    PROJECT_ROOT / "data" / "review_queue" / "quistclose-authority-download.json"
)
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "quistclose-evidence-materialization.json"
DERIVED_SCHEMA = "legalbot.reviewed-judgment-paragraph-chunk.v1"
REPORT_SCHEMA_DERIVED = "legalbot.quistclose-evidence-materialization-report.v1"
DERIVED_ORDINAL_BASE = 1_000_000
_WORD_RE = re.compile(r"\b[\w’'-]+\b", re.UNICODE)
ZERO_REVIEWED_REPRESENTATIONS = {
    "ukhl-2002-12-part-2": (
        "Paragraphs [37]-[61] concern dishonest assistance and factual narrative, "
        "not a reviewed Quistclose holding or theoretical limit."
    ),
    "ukhl-2002-12-part-5": (
        "Paragraphs [123]-[145] concern dishonesty/accessory liability and contain no "
        "reviewed Quistclose trust proposition."
    ),
}


def apply_present_law_treatment_hold(
    metadata: dict[str, Any], *, source_pack_manifest_sha256: str
) -> dict[str, Any]:
    """Mark a historic judgment as identity-verified but not current-law verified.

    The official judgment bytes establish what the court decided on the
    decision date.  They do not, by themselves, establish that the proposition
    remains good law for a later live issue.  Runtime retrieval reads these
    source-level fields and therefore fails closed until a separate reviewed
    subsequent-treatment contract binds a review to the exact EvidenceSpan
    hash and proposition hash.  A source-level flag is deliberately
    insufficient.
    """

    output = apply_historical_case_treatment_hold(metadata)
    output["source_pack_manifest_sha256"] = source_pack_manifest_sha256
    return output


@dataclass(frozen=True)
class DerivedChunk:
    chunk_id: str
    source_version_id: str
    ordinal: int
    heading_path: str
    locator: str
    text_sha256: str
    text: str
    token_count: int
    stream: str
    metadata_json: str

    def safe_report_row(self) -> dict[str, Any]:
        metadata = json.loads(self.metadata_json)
        return {
            "chunk_id": self.chunk_id,
            "representation_id": metadata["representation_id"],
            "locator": self.locator,
            "reviewed_range": metadata["reviewed_range"],
            "legal_role": metadata["legal_role"],
            "material_claim_support_eligible": metadata["material_claim_support_eligible"],
            "exact_span_sha256": self.text_sha256,
            "characters": len(self.text),
            "tokens": self.token_count,
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--download-report", type=Path, default=DEFAULT_DOWNLOAD_REPORT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--apply", action="store_true")
    return parser


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_chunk_id(*parts: str) -> str:
    payload = "\0".join(parts).encode("utf-8")
    return f"chunk-reviewed-{hashlib.sha256(payload).hexdigest()[:40]}"


def _normalise_paragraph_text(value: str) -> str:
    return " ".join(value.replace("\u00a0", " ").split())


def _paragraph_numbers(locator: str) -> tuple[int, ...]:
    values = [int(value) for value in re.findall(r"\d+", locator)]
    if len(values) not in {1, 2}:
        raise ValueError("reviewed locator is not a paragraph or paragraph range")
    first, last = values[0], values[-1]
    if first < 1 or last < first:
        raise ValueError("reviewed paragraph range is invalid")
    return tuple(range(first, last + 1))


def _paragraphs_from_html(data: bytes, requested: set[int]) -> dict[int, str]:
    try:
        soup = BeautifulSoup(data.decode("utf-8"), "html.parser")
    except UnicodeDecodeError as exc:
        raise ValueError("reviewed Parliament source is not UTF-8 HTML") from exc
    output: dict[int, str] = {}
    for element in soup.find_all("p"):
        text = _normalise_paragraph_text(element.get_text(" ", strip=True))
        match = re.match(r"^(\d{1,3})\.\s+", text)
        if match is None:
            continue
        number = int(match.group(1))
        if number not in requested:
            continue
        if number in output:
            raise ValueError(f"official HTML contains duplicate paragraph {number}")
        output[number] = text
    return output


def _paragraphs_from_pdf(data: bytes, requested: set[int]) -> dict[int, str]:
    try:
        raw = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(data)).pages)
    except Exception as exc:  # PDF is an untrusted parsing boundary.
        raise ValueError("reviewed UKSC PDF could not be parsed") from exc
    # UKSC page furniture is not part of a numbered judgment paragraph.
    raw = re.sub(r"(?im)^\s*Page\s+\d+\s*$", "", raw)
    output: dict[int, str] = {}
    for number in sorted(requested):
        starts = list(re.finditer(rf"(?m)^\s*{number}\.\s+", raw))
        if len(starts) != 1:
            raise ValueError(f"official PDF must contain exactly one judgment paragraph {number}")
        start = starts[0].start()
        next_matches = [
            match
            for match in re.finditer(rf"(?m)^\s*{number + 1}\.\s+", raw)
            if match.start() > start
        ]
        if not next_matches:
            raise ValueError(f"official PDF has no boundary after judgment paragraph {number}")
        text = _normalise_paragraph_text(raw[start : next_matches[0].start()])
        if not text.startswith(f"{number}. "):
            raise ValueError("derived judgment paragraph lost its legal locator")
        output[number] = text
    return output


def derive_passage_chunks(
    *,
    item: dict[str, Any],
    representation: dict[str, Any],
    data: bytes,
    source_version_id: str,
    source_pack_manifest_sha256: str,
) -> list[DerivedChunk]:
    """Derive one stable chunk per reviewed judgment paragraph."""

    passages = [
        passage
        for passage in item["reviewed_passages"]
        if passage["representation_id"] == representation["representation_id"]
    ]
    if not passages:
        return []
    role_by_paragraph: dict[int, dict[str, Any]] = {}
    for passage in passages:
        for number in _paragraph_numbers(str(passage["locator"])):
            if number in role_by_paragraph:
                raise ValueError(
                    f"reviewed paragraph {number} has overlapping legal-role classifications"
                )
            role_by_paragraph[number] = passage
    requested = set(role_by_paragraph)
    if representation["kind"] == "browser_rendered_official_html_snapshot":
        paragraphs = _paragraphs_from_html(data, requested)
    elif representation["kind"] == "official_pdf":
        paragraphs = _paragraphs_from_pdf(data, requested)
    else:
        raise ValueError("unsupported reviewed representation kind")
    if set(paragraphs) != requested:
        missing = sorted(requested - set(paragraphs))
        raise ValueError(f"reviewed judgment paragraphs are missing: {missing}")

    output: list[DerivedChunk] = []
    for number in sorted(requested):
        passage = role_by_paragraph[number]
        text = paragraphs[number]
        text_sha256 = _sha256(text.encode("utf-8"))
        legal_role = str(passage["legal_role"])
        locator = f"[{number}]"
        chunk_id = _stable_chunk_id(
            DERIVED_SCHEMA,
            str(item["authority_id"]),
            str(representation["representation_id"]),
            locator,
            legal_role,
            text_sha256,
        )
        metadata = {
            "schema": DERIVED_SCHEMA,
            "source_pack_manifest_sha256": source_pack_manifest_sha256,
            "authority_id": item["authority_id"],
            "representation_id": representation["representation_id"],
            "source_representation_sha256": representation["sha256"],
            "reviewed_range": passage["locator"],
            "paragraph_number": number,
            "legal_locator_kind": "judgment_paragraph",
            "legal_locator": locator,
            "legal_role": legal_role,
            "material_claim_support_eligible": legal_role == "holding_ratio",
            "support_policy": "only_holding_ratio_supports_material_case_propositions",
            "issues": passage["issues"],
            "review_note": passage["review_note"],
            "exact_span_sha256": text_sha256,
            "derivation": "deterministic_paragraph_extraction_from_hash_pinned_official_source",
            "stream": "body",
        }
        output.append(
            DerivedChunk(
                chunk_id=chunk_id,
                source_version_id=source_version_id,
                ordinal=DERIVED_ORDINAL_BASE + number,
                heading_path=json.dumps(
                    [item["case_name"], "Reviewed judgment paragraph"],
                    ensure_ascii=False,
                ),
                locator=locator,
                text_sha256=text_sha256,
                text=text,
                token_count=max(1, len(_WORD_RE.findall(text))),
                stream="body",
                metadata_json=json.dumps(metadata, ensure_ascii=False, sort_keys=True),
            )
        )
    return output


def _safe_source_path(relative_path: object) -> Path:
    value = str(relative_path or "")
    if not value or Path(value).is_absolute():
        raise ValueError("download report path must be project-relative")
    path = (PROJECT_ROOT / value).resolve()
    allowed = (PROJECT_ROOT / "sources" / "materials-2026-08-12" / "Official Quistclose").resolve()
    try:
        path.relative_to(allowed)
    except ValueError as exc:
        raise ValueError("download report path escaped the official source pack") from exc
    return path


def _load_pack(
    manifest_path: Path, report_path: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, tuple[dict[str, Any], dict[str, Any]]]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    representations = validate_manifest(manifest)
    if report.get("schema") != REPORT_SCHEMA:
        raise ValueError("unsupported Quistclose download report")
    if report.get("manifest_version") != manifest.get("version"):
        raise ValueError("Quistclose report and manifest versions differ")
    if report.get("manifest_sha256") != _canonical_sha256(manifest):
        raise ValueError("Quistclose report is not bound to the reviewed manifest")
    downloaded = {str(value["representation_id"]): value for value in report.get("items", [])}
    if set(downloaded) != set(representations):
        raise ValueError("Quistclose report and representations do not reconcile exactly")
    return manifest, report, representations


def _materialization_digest(chunks: list[DerivedChunk]) -> str:
    payload = [chunk.safe_report_row() for chunk in sorted(chunks, key=lambda row: row.chunk_id)]
    return _canonical_sha256(payload)


def materialize_reviewed_chunks(
    database: Database,
    *,
    manifest: dict[str, Any],
    download_report: dict[str, Any],
    representations: dict[str, tuple[dict[str, Any], dict[str, Any]]],
    apply: bool,
    source_scan_manifest_sha256: str,
) -> dict[str, Any]:
    downloaded = {str(value["representation_id"]): value for value in download_report["items"]}
    all_chunks: list[DerivedChunk] = []
    chunks_by_source: dict[str, list[DerivedChunk]] = {}
    source_rows: dict[str, Any] = {}
    source_items: dict[str, dict[str, Any]] = {}
    zero_reviewed: list[dict[str, str]] = []
    for representation_id, (item, representation) in representations.items():
        local = downloaded[representation_id]
        path = _safe_source_path(local["relative_path"])
        data = path.read_bytes()
        verify_representation_payload(item, representation, data)
        rows = database.fetchall(
            """
            SELECT sv.id AS source_version_id,sv.review_status,sv.stable_identifier,
                   sv.title,sv.author_or_body,sv.source_date,sv.metadata_json
            FROM documents d
            JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
            WHERE d.content_sha256=? AND d.duplicate_of IS NULL
            """,
            (representation["sha256"],),
        )
        if len(rows) != 1:
            raise ValueError(f"catalogue identity is not unique for {representation_id}")
        row = rows[0]
        if row["review_status"] != "approved":
            raise ValueError(f"source is not approved for {representation_id}")
        if str(row["stable_identifier"] or "") != item["authority_id"]:
            raise ValueError(f"authority identity differs for {representation_id}")
        source_version_id = str(row["source_version_id"])
        derived = derive_passage_chunks(
            item=item,
            representation=representation,
            data=data,
            source_version_id=source_version_id,
            source_pack_manifest_sha256=str(download_report["manifest_sha256"]),
        )
        all_chunks.extend(derived)
        chunks_by_source[source_version_id] = derived
        source_rows[source_version_id] = row
        source_items[source_version_id] = item
        if not derived:
            reason = ZERO_REVIEWED_REPRESENTATIONS.get(representation_id)
            if reason is None:
                raise ValueError(
                    f"representation {representation_id} has no reviewed chunks or exclusion reason"
                )
            zero_reviewed.append({"representation_id": representation_id, "reason": reason})
    if {value["representation_id"] for value in zero_reviewed} != set(
        ZERO_REVIEWED_REPRESENTATIONS
    ):
        raise ValueError("zero-reviewed representation dispositions do not reconcile")
    if len(all_chunks) != 69:
        raise ValueError("reviewed Quistclose pack must derive exactly 69 paragraph chunks")
    if len({chunk.chunk_id for chunk in all_chunks}) != len(all_chunks):
        raise ValueError("derived judgment chunk identities are not unique")
    ratio_count = sum(
        json.loads(chunk.metadata_json)["legal_role"] == "holding_ratio" for chunk in all_chunks
    )
    obiter_count = len(all_chunks) - ratio_count
    inserted = 0
    already_present = 0
    raw_chunks_excluded = 0
    raw_chunks_already_excluded = 0
    identity_titles_corrected = 0

    if apply:
        with database.transaction() as connection:
            for source_version_id, chunks in chunks_by_source.items():
                evidence_reference = connection.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM evidence_spans e JOIN chunks c ON c.id=e.chunk_id
                    WHERE c.source_version_id=?
                      AND COALESCE(json_extract(c.metadata_json,'$.schema'),'')<>?
                    """,
                    (source_version_id, DERIVED_SCHEMA),
                ).fetchone()
                if evidence_reference is not None and int(evidence_reference["n"]) > 0:
                    raise ValueError(
                        "cannot exclude raw chunks already referenced by persisted evidence"
                    )
                raw_chunks = connection.execute(
                    """
                    SELECT id,stream,metadata_json FROM chunks
                    WHERE source_version_id=?
                      AND COALESCE(json_extract(metadata_json,'$.schema'),'')<>?
                    """,
                    (source_version_id, DERIVED_SCHEMA),
                ).fetchall()
                for raw_chunk in raw_chunks:
                    raw_metadata = json.loads(raw_chunk["metadata_json"] or "{}")
                    if not isinstance(raw_metadata, dict):
                        raise ValueError("raw source chunk metadata is not an object")
                    old_stream = str(raw_chunk["stream"])
                    if old_stream == "source_raw_unreviewed":
                        raw_chunks_already_excluded += 1
                    else:
                        raw_chunks_excluded += 1
                    raw_metadata.setdefault("pre_review_stream", old_stream)
                    raw_metadata.update(
                        {
                            "stream": "source_raw_unreviewed",
                            "legal_role": "unclassified",
                            "material_claim_support_eligible": False,
                            "retrieval_disposition": (
                                "excluded_raw_parser_chunk_after_reviewed_paragraph_materialization"
                            ),
                            "reviewed_derivation_schema": DERIVED_SCHEMA,
                            "source_pack_manifest_sha256": download_report["manifest_sha256"],
                        }
                    )
                    connection.execute(
                        "UPDATE chunks SET stream='source_raw_unreviewed',metadata_json=? WHERE id=?",
                        (
                            json.dumps(raw_metadata, ensure_ascii=False, sort_keys=True),
                            raw_chunk["id"],
                        ),
                    )
                expected_ids = {chunk.chunk_id for chunk in chunks}
                existing_derived = connection.execute(
                    """
                    SELECT id FROM chunks
                    WHERE source_version_id=?
                      AND json_extract(metadata_json,'$.schema')=?
                      AND json_extract(metadata_json,'$.source_pack_manifest_sha256')=?
                    """,
                    (
                        source_version_id,
                        DERIVED_SCHEMA,
                        download_report["manifest_sha256"],
                    ),
                ).fetchall()
                unexpected = {str(row["id"]) for row in existing_derived} - expected_ids
                if unexpected:
                    raise ValueError(
                        "stale reviewed chunks require an explicit source-pack version change"
                    )
                for chunk in chunks:
                    existing = connection.execute(
                        "SELECT * FROM chunks WHERE id=?", (chunk.chunk_id,)
                    ).fetchone()
                    expected_values = (
                        chunk.source_version_id,
                        chunk.ordinal,
                        chunk.heading_path,
                        chunk.locator,
                        chunk.text_sha256,
                        chunk.text,
                        chunk.token_count,
                        chunk.stream,
                        chunk.metadata_json,
                    )
                    if existing is not None:
                        observed_values = (
                            str(existing["source_version_id"]),
                            int(existing["ordinal"]),
                            str(existing["heading_path"]),
                            str(existing["locator"]),
                            str(existing["text_sha256"]),
                            str(existing["markdown_text"]),
                            int(existing["token_count"]),
                            str(existing["stream"]),
                            str(existing["metadata_json"]),
                        )
                        if observed_values != expected_values:
                            raise ValueError(
                                "existing reviewed chunk differs from deterministic bytes"
                            )
                        already_present += 1
                        continue
                    ordinal_conflict = connection.execute(
                        "SELECT id FROM chunks WHERE source_version_id=? AND ordinal=?",
                        (source_version_id, chunk.ordinal),
                    ).fetchone()
                    if ordinal_conflict is not None:
                        raise ValueError(
                            "derived paragraph ordinal conflicts with an existing chunk"
                        )
                    connection.execute(
                        """
                        INSERT INTO chunks(
                          id,source_version_id,ordinal,heading_path,locator,text_sha256,
                          markdown_text,token_count,stream,metadata_json
                        ) VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (chunk.chunk_id, *expected_values),
                    )
                    inserted += 1
                source = source_rows[source_version_id]
                item = source_items[source_version_id]
                metadata = json.loads(source["metadata_json"] or "{}")
                if not isinstance(metadata, dict):
                    raise ValueError("approved source metadata is not an object")
                metadata["reviewed_evidence_materialization"] = {
                    "schema": DERIVED_SCHEMA,
                    "source_pack_manifest_sha256": download_report["manifest_sha256"],
                    "source_scan_manifest_sha256": source_scan_manifest_sha256,
                    "chunk_count": len(chunks),
                    "chunk_ids": [chunk.chunk_id for chunk in chunks],
                    "materialization_sha256": _materialization_digest(chunks),
                    "material_claim_policy": (
                        "holding_ratio may support material case propositions; "
                        "obiter and unclassified chunks may not"
                    ),
                }
                citation_data = metadata.get("citation_data")
                if not isinstance(citation_data, dict):
                    raise ValueError("approved case metadata has no structured citation identity")
                if (
                    citation_data.get("case_name") != item["case_name"]
                    or citation_data.get("neutral_citation") != item["neutral_citation"]
                ):
                    raise ValueError(
                        "approved case citation identity differs from reviewed manifest"
                    )
                prior_title = str(source["title"] or "")
                metadata["reviewed_identity_override"] = {
                    "schema": "legalbot.reviewed-case-identity-override.v1",
                    "case_name": item["case_name"],
                    "neutral_citation": item["neutral_citation"],
                    "decision_date": item["decision_date"],
                    "court": item["court"],
                    "superseded_parser_title": (
                        prior_title if prior_title != item["case_name"] else None
                    ),
                    "reason": (
                        "Use reviewed official case identity; never use an HTML shell/cookie "
                        "heading as the citable title"
                    ),
                    "source_pack_manifest_sha256": download_report["manifest_sha256"],
                }
                metadata = apply_present_law_treatment_hold(
                    metadata,
                    source_pack_manifest_sha256=str(download_report["manifest_sha256"]),
                )
                if (
                    prior_title != item["case_name"]
                    or str(source["author_or_body"] or "") != item["court"]
                    or str(source["source_date"] or "") != item["decision_date"]
                ):
                    identity_titles_corrected += 1
                connection.execute(
                    """
                    UPDATE source_versions
                    SET title=?,author_or_body=?,source_date=?,as_of_date=?,
                        currentness_status='historical',metadata_json=?
                    WHERE id=?
                    """,
                    (
                        item["case_name"],
                        item["court"],
                        item["decision_date"],
                        item["decision_date"],
                        json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                        source_version_id,
                    ),
                )

    return {
        "schema": REPORT_SCHEMA_DERIVED,
        "apply": apply,
        "manifest_version": manifest["version"],
        "source_pack_manifest_sha256": download_report["manifest_sha256"],
        "source_scan_manifest_sha256": source_scan_manifest_sha256,
        "derived_chunk_schema": DERIVED_SCHEMA,
        "paragraph_chunks": len(all_chunks),
        "holding_ratio_chunks": ratio_count,
        "obiter_chunks": obiter_count,
        "inserted": inserted,
        "already_present": already_present,
        "raw_chunks_excluded": raw_chunks_excluded,
        "raw_chunks_already_excluded": raw_chunks_already_excluded,
        "identity_titles_corrected": identity_titles_corrected,
        "material_claim_support_policy": (
            "Only chunks labelled holding_ratio are eligible to support material case propositions; "
            "obiter remains indexed and labelled but cannot pass the case-role quality gate."
        ),
        "present_law_currentness_policy": (
            "Identity and historic decision text are verified, but every representation is "
            "currentness_verified=false and retrieval-ineligible for present-law material "
            "claims until later-treatment review is bound to the exact EvidenceSpan and "
            "proposition hashes; a source-level flag is insufficient."
        ),
        "present_law_currentness_verified": False,
        "subsequent_treatment_check_required": True,
        "evidence_span_state": (
            "ready_for_index_build; runtime EvidenceSpan IDs remain build-bound and were not fabricated"
        ),
        "representations_with_zero_reviewed_chunks": zero_reviewed,
        "chunks": [
            chunk.safe_report_row()
            for chunk in sorted(
                all_chunks,
                key=lambda value: (
                    json.loads(value.metadata_json)["representation_id"],
                    value.ordinal,
                ),
            )
        ],
        "materialization_sha256": _materialization_digest(all_chunks),
    }


def main() -> None:
    args = _parser().parse_args()
    manifest, download_report, representations = _load_pack(args.manifest, args.download_report)
    database = Database(Settings().database_path)
    database.initialize()
    try:
        scan = database.fetchone(
            """
            SELECT id,manifest_sha256,expected_file_count,files_accounted
            FROM source_scans WHERE status='complete'
            ORDER BY completed_at DESC,created_at DESC LIMIT 1
            """
        )
        if (
            scan is None
            or int(scan["expected_file_count"]) != int(scan["files_accounted"])
            or not re.fullmatch(r"[0-9a-f]{64}", str(scan["manifest_sha256"] or ""))
        ):
            raise ValueError("reviewed evidence materialization requires a reconciled source scan")
        result = materialize_reviewed_chunks(
            database,
            manifest=manifest,
            download_report=download_report,
            representations=representations,
            apply=args.apply,
            source_scan_manifest_sha256=str(scan["manifest_sha256"]),
        )
        result["source_scan_id"] = scan["id"]
        result["created_at"] = datetime.now(UTC).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "apply": args.apply,
                    "paragraph_chunks": result["paragraph_chunks"],
                    "holding_ratio_chunks": result["holding_ratio_chunks"],
                    "obiter_chunks": result["obiter_chunks"],
                    "inserted": result["inserted"],
                    "already_present": result["already_present"],
                    "raw_chunks_excluded": result["raw_chunks_excluded"],
                    "raw_chunks_already_excluded": result["raw_chunks_already_excluded"],
                    "identity_titles_corrected": result["identity_titles_corrected"],
                    "index_built_or_promoted": False,
                    "materialization_sha256": result["materialization_sha256"],
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
