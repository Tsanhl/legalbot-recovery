#!/usr/bin/env python3
"""Audit seminar authority references against catalogue and candidate coverage.

The audit is deliberately non-authorising.  Teaching files are used only to
discover authority identifiers and subject coverage.  Source prose, source
paths and original filenames are never written to the report.  The script
does not change catalogue review state, build embeddings, or write ACTIVE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

SCHEMA = "legalbot.seminar-authority-coverage-audit.v3"
TEACHING_PATH_MARKERS = ("seminar", "tutorial", "lecture")
PRESENTATION_SUFFIXES = {".ppt", ".pptx"}
TEACHING_LANES = {"private_teaching", "assessment_guidance"}
AUTHORITY_LANES = {"primary_authority", "official_secondary"}
NEUTRAL_CITATION = re.compile(
    r"\[(?P<year>\d{4})\]\s+"
    r"(?P<court>UKSC|UKHL|UKPC|EWCA\s+Civ|EWCA\s+Crim|EWHC)\s+"
    r"(?P<number>\d+)(?:\s+\((?P<division>[A-Za-z]+)\))?",
    re.IGNORECASE,
)
LEGISLATION_TITLE = re.compile(
    r"\b(?P<title>(?:(?:[A-Z][A-Za-z0-9&'’()./\-]*|of|the|and|for|in|to|"
    r"No\.?|Northern|Scotland|Wales|England|European|Union)\s+){1,12}?"
    r"(?:Act|Regulations|Rules|Order|Measure)\s+(?:18|19|20)\d{2})\b"
)
SPACE = re.compile(r"\s+")
NON_WORD = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class Document:
    id: str
    content_sha256: str
    lane: str
    status: str
    subject: str
    jurisdiction: str
    retrieval_canonical: bool


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalise_words(value: str) -> str:
    return " ".join(NON_WORD.sub(" ", value.casefold()).split())


def _canonical_neutral(match: re.Match[str]) -> str:
    court_key = " ".join(match.group("court").upper().split())
    court = {
        "EWCA CIV": "EWCA Civ",
        "EWCA CRIM": "EWCA Crim",
    }.get(court_key, court_key)
    division = (match.group("division") or "").casefold()
    division_value = {
        "admin": "Admin",
        "ch": "Ch",
        "comm": "Comm",
        "fam": "Fam",
        "ipec": "IPEC",
        "kb": "KB",
        "pat": "Pat",
        "qb": "QB",
        "tcc": "TCC",
    }.get(division)
    suffix = f" ({division_value})" if division_value else ""
    return f"[{match.group('year')}] {court} {match.group('number')}{suffix}"


def _canonical_legislation(value: str) -> str:
    result = SPACE.sub(" ", value).strip(" .,:;()")
    result = re.sub(r"^(?:of|the|and|for|in|to)\s+", "", result, flags=re.IGNORECASE)
    return result


def _connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _documents(connection: sqlite3.Connection) -> dict[str, Document]:
    rows = connection.execute(
        """
        SELECT id, content_sha256, lane, status, subject_primary, jurisdiction,
               retrieval_canonical
        FROM documents
        """
    )
    return {
        str(row["content_sha256"]): Document(
            id=str(row["id"]),
            content_sha256=str(row["content_sha256"]),
            lane=str(row["lane"] or "unknown"),
            status=str(row["status"] or "unknown"),
            subject=str(row["subject_primary"] or "general"),
            jurisdiction=str(row["jurisdiction"] or "unknown"),
            retrieval_canonical=bool(row["retrieval_canonical"]),
        )
        for row in rows
    }


def _current_source_version(
    connection: sqlite3.Connection, document: Document
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT id, title, stable_identifier, canonical_url, currentness_status,
               review_status, authority_identity_id
        FROM source_versions
        WHERE document_id=? AND superseded_by IS NULL AND version_sha256=?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (document.id, document.content_sha256),
    ).fetchone()


def _source_text(connection: sqlite3.Connection, source_version_id: str) -> Iterable[str]:
    for row in connection.execute(
        """
        SELECT markdown_text FROM chunks
        WHERE source_version_id=? AND stream IN ('body', 'comments', 'revisions')
        ORDER BY CASE stream WHEN 'body' THEN 0 WHEN 'comments' THEN 1 ELSE 2 END,
                 ordinal
        """,
        (source_version_id,),
    ):
        yield str(row["markdown_text"] or "")


def _candidate_sources(path: Path) -> tuple[set[str], set[str], dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    sources = value.get("sources")
    if not isinstance(sources, list):
        raise ValueError("candidate approved-source manifest has no sources list")
    neutral: set[str] = set()
    legislation: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            continue
        for identity in (
            source.get("stable_identifier"),
            source.get("authority_identity_id"),
        ):
            if not identity:
                continue
            match = NEUTRAL_CITATION.search(str(identity))
            if match:
                neutral.add(_canonical_neutral(match))
        title = str(source.get("title") or "")
        if LEGISLATION_TITLE.fullmatch(title):
            legislation.add(_normalise_words(_canonical_legislation(title)))
    metadata = {
        "corpus_id": value.get("corpus_id"),
        "manifest_sha256": value.get("manifest_sha256"),
        "source_count": len(sources),
    }
    return neutral, legislation, metadata


def _catalogue_authorities(
    connection: sqlite3.Connection,
) -> tuple[
    dict[str, list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    neutral: dict[str, list[dict[str, Any]]] = defaultdict(list)
    legislation: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows = connection.execute(
        """
        SELECT d.id AS document_id, d.lane, d.status, d.subject_primary,
               d.jurisdiction, d.retrieval_canonical, sv.id AS source_version_id,
               sv.title, sv.stable_identifier, sv.authority_identity_id,
               sv.currentness_status, sv.review_status
        FROM documents d JOIN source_versions sv ON sv.document_id=d.id
        WHERE sv.superseded_by IS NULL AND sv.version_sha256=d.content_sha256
          AND d.lane IN ('primary_authority', 'official_secondary')
        """
    )
    for row in rows:
        record = {
            "document_id": str(row["document_id"]),
            "source_version_id": str(row["source_version_id"]),
            "lane": str(row["lane"]),
            "document_status": str(row["status"]),
            "subject": str(row["subject_primary"] or "general"),
            "jurisdiction": str(row["jurisdiction"] or "unknown"),
            "retrieval_canonical": bool(row["retrieval_canonical"]),
            "review_status": str(row["review_status"]),
            "currentness_status": str(row["currentness_status"]),
        }
        for value in (row["stable_identifier"], row["authority_identity_id"]):
            match = NEUTRAL_CITATION.search(str(value or ""))
            if match:
                neutral[_canonical_neutral(match)].append(record)
        title = str(row["title"] or "")
        if LEGISLATION_TITLE.fullmatch(title):
            legislation[_normalise_words(_canonical_legislation(title))].append(record)
    return neutral, legislation


def _eligible_catalogue_match(records: Iterable[dict[str, Any]]) -> bool:
    for row in records:
        if (
            row["lane"] in AUTHORITY_LANES
            and row["document_status"] == "citable"
            and row["retrieval_canonical"]
            and row["review_status"] == "approved"
        ):
            return True
    return False


def _reference_status(
    *, candidate_present: bool, catalogue_records: list[dict[str, Any]]
) -> str:
    if candidate_present:
        return "candidate_present"
    if _eligible_catalogue_match(catalogue_records):
        return "catalogue_approved_not_candidate"
    if catalogue_records:
        return "catalogue_present_not_eligible"
    return "catalogue_missing"


def audit(
    *, source_root: Path, database_path: Path, candidate_manifest: Path
) -> dict[str, Any]:
    connection = _connection(database_path)
    documents = _documents(connection)
    candidate_neutral, candidate_legislation, candidate_metadata = _candidate_sources(
        candidate_manifest
    )
    catalogue_neutral, catalogue_legislation = _catalogue_authorities(connection)

    selected_files = 0
    selected_bytes = 0
    presentation_files = 0
    matched_documents: dict[str, Document] = {}
    presentation_documents: dict[str, Document] = {}
    document_roles: dict[str, set[str]] = defaultdict(set)
    attached_authorities: dict[str, Document] = {}
    unreadable: list[dict[str, Any]] = []
    scan_counts: Counter[str] = Counter()

    for path in sorted(source_root.rglob("*")):
        if not path.is_file() or path.name == ".DS_Store" or path.name.startswith("~$"):
            continue
        relative = path.relative_to(source_root)
        lowered = str(relative).casefold()
        is_presentation = path.suffix.casefold() in PRESENTATION_SUFFIXES
        in_teaching_path = any(marker in lowered for marker in TEACHING_PATH_MARKERS)
        if not is_presentation and not in_teaching_path:
            continue
        selected_files += 1
        selected_bytes += path.stat().st_size
        if is_presentation:
            presentation_files += 1
        digest = _sha256(path)
        document = documents.get(digest)
        if document is None:
            unreadable.append(
                {
                    "content_sha256": digest,
                    "reason_code": "not_in_catalogue",
                    "media_suffix": path.suffix.casefold() or "none",
                }
            )
            continue
        scan_counts[f"lane:{document.lane}"] += 1
        scan_counts[f"status:{document.status}"] += 1
        if in_teaching_path and document.lane in AUTHORITY_LANES:
            attached_authorities[document.id] = document
        if is_presentation or (
            document.lane in TEACHING_LANES and in_teaching_path
        ):
            matched_documents[document.id] = document
            if is_presentation:
                presentation_documents[document.id] = document
                document_roles[document.id].add("presentation")
            if in_teaching_path:
                document_roles[document.id].add("seminar_path")

    references: dict[tuple[str, str], dict[str, Any]] = {}
    inspected_chunks = 0
    inspected_characters = 0
    inspection_failures: list[dict[str, Any]] = []
    for document in sorted(matched_documents.values(), key=lambda value: value.id):
        source_version = _current_source_version(connection, document)
        if source_version is None:
            inspection_failures.append(
                {
                    "document_id": document.id,
                    "content_sha256": document.content_sha256,
                    "reason_code": "no_current_parsed_source_version",
                    "document_status": document.status,
                    "source_roles": sorted(document_roles[document.id]),
                    "presentation_document": document.id in presentation_documents,
                }
            )
            continue
        chunk_seen = False
        for text in _source_text(connection, str(source_version["id"])):
            chunk_seen = True
            inspected_chunks += 1
            inspected_characters += len(text)
            for match in NEUTRAL_CITATION.finditer(text):
                value = _canonical_neutral(match)
                key = ("neutral_citation", value)
                record = references.setdefault(
                    key,
                    {
                        "kind": key[0],
                        "reference": value,
                        "normalised_reference": value.casefold(),
                        "teaching_document_ids": set(),
                        "subjects": set(),
                        "presentation_document_ids": set(),
                        "presentation_subjects": set(),
                        "source_roles": set(),
                    },
                )
                record["teaching_document_ids"].add(document.id)
                record["subjects"].add(document.subject)
                record["source_roles"].update(document_roles[document.id])
                if document.id in presentation_documents:
                    record["presentation_document_ids"].add(document.id)
                    record["presentation_subjects"].add(document.subject)
            for match in LEGISLATION_TITLE.finditer(text):
                value = _canonical_legislation(match.group("title"))
                normalised = _normalise_words(value)
                key = ("legislation_title", normalised)
                record = references.setdefault(
                    key,
                    {
                        "kind": key[0],
                        "reference": value,
                        "normalised_reference": normalised,
                        "teaching_document_ids": set(),
                        "subjects": set(),
                        "presentation_document_ids": set(),
                        "presentation_subjects": set(),
                        "source_roles": set(),
                    },
                )
                record["teaching_document_ids"].add(document.id)
                record["subjects"].add(document.subject)
                record["source_roles"].update(document_roles[document.id])
                if document.id in presentation_documents:
                    record["presentation_document_ids"].add(document.id)
                    record["presentation_subjects"].add(document.subject)
        if not chunk_seen:
            inspection_failures.append(
                {
                    "document_id": document.id,
                    "content_sha256": document.content_sha256,
                    "reason_code": "current_source_version_has_no_chunks",
                    "document_status": document.status,
                    "source_roles": sorted(document_roles[document.id]),
                    "presentation_document": document.id in presentation_documents,
                }
            )

    result_references: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    subject_gaps: dict[str, Counter[str]] = defaultdict(Counter)
    presentation_status_counts: Counter[str] = Counter()
    presentation_subject_gaps: dict[str, Counter[str]] = defaultdict(Counter)
    for key in sorted(references):
        record = references[key]
        if record["kind"] == "neutral_citation":
            catalogue_records = catalogue_neutral.get(record["reference"], [])
            candidate_present = record["reference"] in candidate_neutral
        else:
            catalogue_records = catalogue_legislation.get(record["normalised_reference"], [])
            candidate_present = record["normalised_reference"] in candidate_legislation
        status = _reference_status(
            candidate_present=candidate_present, catalogue_records=catalogue_records
        )
        status_counts[status] += 1
        for subject in record["subjects"]:
            subject_gaps[subject][status] += 1
        if record["presentation_document_ids"]:
            presentation_status_counts[status] += 1
            for subject in record["presentation_subjects"]:
                presentation_subject_gaps[subject][status] += 1
        result_references.append(
            {
                "kind": record["kind"],
                "reference": record["reference"],
                "normalised_reference": record["normalised_reference"],
                "teaching_document_count": len(record["teaching_document_ids"]),
                "teaching_document_ids": sorted(record["teaching_document_ids"]),
                "subjects": sorted(record["subjects"]),
                "presentation_document_count": len(
                    record["presentation_document_ids"]
                ),
                "presentation_document_ids": sorted(
                    record["presentation_document_ids"]
                ),
                "presentation_subjects": sorted(record["presentation_subjects"]),
                "source_roles": sorted(record["source_roles"]),
                "candidate_present": candidate_present,
                "catalogue_match_count": len(catalogue_records),
                "catalogue_eligible_match": _eligible_catalogue_match(catalogue_records),
                "catalogue_matches": catalogue_records,
                "coverage_status": status,
                "official_fact_check_status": "not_started",
            }
        )

    attachment_counts = Counter()
    for document in attached_authorities.values():
        source_version = _current_source_version(connection, document)
        if source_version is None:
            attachment_counts["no_current_source_version"] += 1
            continue
        if (
            document.status == "citable"
            and document.retrieval_canonical
            and str(source_version["review_status"]) == "approved"
        ):
            attachment_counts["catalogue_eligible"] += 1
        else:
            attachment_counts["catalogue_present_not_eligible"] += 1

    connection.close()
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "audit_date": date.today().isoformat(),
        "authority_effect": "none_non_authorising_projection",
        "teaching_lane_policy": "issue_discovery_only_never_legal_authority",
        "candidate": candidate_metadata,
        "inventory": {
            "selected_files": selected_files,
            "selected_bytes": selected_bytes,
            "presentation_files": presentation_files,
            "catalogue_matched_presentation_documents": len(
                presentation_documents
            ),
            "presentation_documents_by_subject": dict(
                sorted(
                    Counter(
                        document.subject
                        for document in presentation_documents.values()
                    ).items()
                )
            ),
            "catalogue_matched_teaching_documents": len(matched_documents),
            "seminar_attached_authority_documents": len(attached_authorities),
            "scan_counts": dict(sorted(scan_counts.items())),
            "unmatched_files": unreadable,
        },
        "inspection": {
            "current_teaching_documents_attempted": len(matched_documents),
            "presentation_documents_attempted": len(presentation_documents),
            "presentation_document_failures": sum(
                bool(failure["presentation_document"])
                for failure in inspection_failures
            ),
            "chunks_inspected": inspected_chunks,
            "characters_inspected": inspected_characters,
            "failures": inspection_failures,
        },
        "seminar_attached_authority_status": dict(sorted(attachment_counts.items())),
        "reference_summary": {
            "total_unique_references": len(result_references),
            "coverage_status_counts": dict(sorted(status_counts.items())),
            "by_subject": {
                subject: dict(sorted(counts.items()))
                for subject, counts in sorted(subject_gaps.items())
            },
            "presentation_only": {
                "total_unique_references": sum(presentation_status_counts.values()),
                "coverage_status_counts": dict(
                    sorted(presentation_status_counts.items())
                ),
                "by_subject": {
                    subject: dict(sorted(counts.items()))
                    for subject, counts in sorted(presentation_subject_gaps.items())
                },
            },
        },
        "references": result_references,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit(
        source_root=args.source_root,
        database_path=args.database,
        candidate_manifest=args.candidate_manifest,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "schema": report["schema"],
                "output": str(args.output),
                "inventory": report["inventory"],
                "inspection": report["inspection"],
                "reference_summary": report["reference_summary"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
