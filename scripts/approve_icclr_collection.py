#!/usr/bin/env python3
"""Verify and approve the exact owner-authorised I.C.C.L.R. educational export."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

from pypdf import PdfReader

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

APPROVAL_POLICY = "legalbot.owner-supplied-icclr-educational-export.v1"
JOURNAL = "I.C.C.L.R."
AUTHORISED_COLLECTION_SHA256 = "51a43cfa90f310861578862b73e2d2e4a117820c2a12dc31d4ce76585cf8c326"
_CITATION = re.compile(
    r"I\.C\.C\.L\.R\.\s+(?P<year>\d{4}),\s*(?P<volume>\d+)\((?P<issue>\d+)\),\s*"
    r"(?P<pages>[N\d]+(?:[-\u2013][N\d]+)?)"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _join_people(values: list[str]) -> str:
    cleaned: list[str] = []
    for value in values:
        person = value.strip()
        while True:
            without_title = re.sub(
                r"^(?:(?:assoc(?:iate)?\.?\s+)?prof(?:essor)?\.?|dr\.?)\s+",
                "",
                person,
                flags=re.IGNORECASE,
            )
            if without_title == person:
                break
            person = without_title
        cleaned.append(person)
    if len(cleaned) == 1:
        return cleaned[0]
    return ", ".join(cleaned[:-1]) + f" and {cleaned[-1]}"


def _bibliography(path: Path) -> dict[str, str]:
    reader = PdfReader(path)
    if reader.is_encrypted or not reader.pages:
        raise ValueError("I.C.C.L.R. source must be a readable PDF")
    items: list[tuple[float, float, str]] = []

    def visitor(text: str, _cm: Any, tm: Any, _font: Any, size: float) -> None:
        cleaned = " ".join(text.split())
        if cleaned:
            items.append((float(tm[5]), float(size), cleaned))

    full = reader.pages[0].extract_text(visitor_text=visitor) or ""
    if (
        "For educational use only" not in full
        or "I.C.C.L.R." not in full
        or "Thomson Reuters" not in full
    ):
        raise ValueError("PDF is outside the owner-authorised I.C.C.L.R. collection")
    title_items = [
        (vertical, text)
        for vertical, size, text in items
        if size >= 16 and vertical < 180 and "educational use" not in text.casefold()
    ]
    title = " ".join(text for _, text in sorted(title_items))
    if not title:
        raise ValueError("I.C.C.L.R. title could not be verified")
    last_title = max(vertical for vertical, _ in title_items)
    stop = min(
        (
            vertical
            for vertical, _, text in items
            if vertical > last_title
            and text in {"Table of Contents", "Journal Article", "Editorial"}
        ),
        default=400,
    )
    people = [
        re.sub(r"\s*[*\u2020\u2021]+\s*$", "", text).strip()
        for vertical, size, text in items
        if last_title < vertical < stop
        and 9.5 <= size <= 10.5
        and text not in {"1", "For educational use only", "Piper Alderman"}
        and not text.startswith("©")
    ]
    if "Publication Review" in full:
        reviewed_by = re.search(r"Reviewed by:\s*([^\n]+)", full)
        if reviewed_by:
            people = [reviewed_by.group(1).strip()]
    if not people:
        raise ValueError("I.C.C.L.R. author could not be verified")
    citations = list(_CITATION.finditer(full))
    if not citations:
        raise ValueError("I.C.C.L.R. volume citation could not be verified")
    citation = citations[-1].groupdict()
    first_page = re.split(r"[-\u2013]", citation["pages"], maxsplit=1)[0]
    return {
        "author": _join_people(people),
        "title": title,
        "year": citation["year"],
        "volume": citation["volume"],
        "issue": citation["issue"],
        "first_page": first_page,
        "stable_identifier": (
            f"journal:icclr:{citation['year']}:{citation['volume']}:"
            f"{citation['issue']}:{first_page.casefold()}"
        ),
    }


def main() -> None:
    args = _parser().parse_args()
    source_dir = args.source_dir.expanduser().resolve()
    files = sorted(source_dir.glob("*.pdf"))
    if len(files) != 100:
        raise SystemExit("the owner-authorised I.C.C.L.R. collection must contain exactly 100 PDFs")
    file_hashes = {path: _sha256(path) for path in files}
    collection_sha256 = hashlib.sha256(
        ("\n".join(sorted(file_hashes.values())) + "\n").encode("ascii")
    ).hexdigest()
    if collection_sha256 != AUTHORISED_COLLECTION_SHA256:
        raise SystemExit("the I.C.C.L.R. folder does not match the owner-authorised content set")

    database = Database(Settings().database_path)
    database.initialize()
    ready: list[tuple[Any, dict[str, str]]] = []
    holds: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued', 'running') LIMIT 1"
        ):
            raise SystemExit("source scan is active; approval requires a frozen catalogue")
        for path in files:
            digest = file_hashes[path]
            bibliography = _bibliography(path)
            reasons: list[str] = []
            if bibliography["stable_identifier"] in identifiers:
                reasons.append("duplicate_bibliographic_identity")
            identifiers.add(bibliography["stable_identifier"])
            rows = database.fetchall(
                """
                SELECT d.lane, d.jurisdiction, d.status, d.retrieval_canonical,
                       sv.id AS source_version_id, sv.review_status AS source_review_status,
                       sv.metadata_json, r.id AS review_id, r.status AS card_status,
                       (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) AS chunk_count,
                       (SELECT group_concat(c.markdown_text, ' ') FROM chunks c
                        WHERE c.source_version_id=sv.id) AS local_text
                FROM documents d
                JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                LEFT JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
                WHERE d.content_sha256=? AND d.lane='scholarship'
                  AND d.retrieval_canonical=1
                """,
                (digest,),
            )
            if len(rows) != 1:
                reasons.append("catalogue_identity_not_unique")
                row = None
                metadata: dict[str, Any] = {}
            else:
                row = rows[0]
                metadata = json.loads(row["metadata_json"] or "{}")
                if row["lane"] != "scholarship":
                    reasons.append("wrong_lane")
                if row["status"] not in {"citable", "duplicate"}:
                    reasons.append("source_not_citable")
                if int(row["chunk_count"]) < 1:
                    reasons.append("no_searchable_chunks")
                if metadata.get("classification_confidence") != "high":
                    reasons.append("classification_not_high_confidence")
                if metadata.get("material_type_candidate") != "journal":
                    reasons.append("not_journal")
                if row["source_review_status"] not in {"staged", "approved"}:
                    reasons.append("source_review_not_actionable")
                if row["card_status"] not in {"pending", "approved"}:
                    reasons.append("review_not_actionable")
                local_text = str(row["local_text"] or "")
                if "/Users/" in local_text or prompt_injection_hits(local_text):
                    reasons.append("unsafe_retrieval_text")
            result = {
                "stable_identifier": bibliography["stable_identifier"],
                "decision": "approve" if not reasons else "hold",
                "reasons": reasons,
            }
            if reasons or row is None:
                holds.append(result)
                continue
            ready.append((row, bibliography))

        if holds:
            print(json.dumps({"ready": len(ready), "holds": holds}, indent=2, sort_keys=True))
            raise SystemExit("I.C.C.L.R. approval stopped: resolve all holds first")
        if args.apply:
            for row, bibliography in ready:
                if row["source_review_status"] == "approved" and row["card_status"] == "approved":
                    continue
                database.decide_review(
                    str(row["review_id"]),
                    "approved",
                    f"{APPROVAL_POLICY}: exact 100-file collection verified; scholarship only; local educational use",
                    {
                        "identity_verified": True,
                        "currentness_verified": True,
                        "stable_identifier": bibliography["stable_identifier"],
                        "as_of_date": date.today().isoformat(),
                        "currentness_status": "historical",
                        "material_type": "journal",
                        "citation_data": {
                            "source_type": "journal",
                            "author": bibliography["author"],
                            "title": bibliography["title"],
                            "year": bibliography["year"],
                            "year_format": "round",
                            "volume": bibliography["volume"],
                            "issue": bibliography["issue"],
                            "journal": JOURNAL,
                            "first_page": bibliography["first_page"],
                        },
                        "licence_name": "Westlaw educational-use copy (owner-supplied; local-only)",
                    },
                )
        print(
            json.dumps({"apply": args.apply, "approved_or_ready": len(ready), "holds": 0}, indent=2)
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
