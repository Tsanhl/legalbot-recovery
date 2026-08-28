#!/usr/bin/env python3
"""Approve only exact verified latest-available legislation XML snapshots."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "current_legislation_pack.json"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "current-legislation-download.json"
DEFAULT_SUBJECT_REPORT = (
    PROJECT_ROOT / "data" / "review_queue" / "current-legislation-subject-corrections.json"
)
POLICY = "legalbot.current-legislation-approval.v1"
SNAPSHOT_ID_RE = re.compile(
    r"^(?P<authority>(?:ukpga|uksi):.+):latest-available@(?P<date>20\d{2}-\d{2}-\d{2})$"
)
SUBJECTS = {
    "Contract law": "contract",
    "Consumer law": "consumer",
    "Tort and professional negligence law": "professional negligence",
    "Criminal law": "criminal",
    "Criminal evidence law": "criminal evidence",
    "Employment and equality law": "employment",
    "Land law": "land",
    "Public and constitutional law": "public and constitutional",
    "Company law": "company",
    "Family law": "family",
    "Wills and succession law": "wills and succession",
    "Trusts law": "trusts",
    "Civil litigation law": "civil litigation",
    "Intellectual property law": "intellectual property",
    "Commercial law": "commercial",
    "Financial services law": "financial services",
}


def _normalise_title(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--subject-report", type=Path, default=DEFAULT_SUBJECT_REPORT)
    parser.add_argument("--apply", action="store_true")
    return parser


def _stable_identifier(identity: str, as_of_date: str) -> str:
    return f"{':'.join(identity.split('/'))}:latest-available@{as_of_date}"


def _source_approval(item: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    identity = str(item["identity"])
    title = str(item["title"])
    if identity.startswith("uksi/"):
        _, year, number, *_ = identity.split("/")
        citation_data = {
            "source_type": "statutory_instrument",
            "title": title.removeprefix("The "),
            "instrument_number": f"SI {year}/{number}",
        }
    else:
        citation_data = {"source_type": "legislation", "title": title}
    licence = manifest["licence"]
    canonical_identity = identity.removesuffix("/made")
    return {
        "identity_verified": True,
        "currentness_verified": True,
        "stable_identifier": _stable_identifier(identity, str(manifest["as_of_date"])),
        "as_of_date": manifest["as_of_date"],
        # legislation.gov.uk "latest available" can still disclose unapplied
        # effects. It is not a verified historical point-in-time consolidation.
        "currentness_status": "latest_available_revised_snapshot",
        "material_type": "legislation",
        "citation_data": citation_data,
        "canonical_url": f"https://www.legislation.gov.uk/{canonical_identity}",
        "licence_name": f"{licence['name']} v{licence['version']}",
        "licence_url": licence["url"],
    }


def _review_id(source_version_id: str) -> str:
    digest = hashlib.sha256(f"{POLICY}\0{source_version_id}".encode()).hexdigest()
    return f"review-current-legislation-{digest[:40]}"


def _previous_snapshot_for(
    row: Any,
    *,
    identity: str,
    current_as_of_date: str,
) -> bool:
    match = SNAPSHOT_ID_RE.fullmatch(str(row["stable_identifier"] or ""))
    return bool(
        match
        and match.group("authority") == ":".join(identity.split("/"))
        and match.group("date") < current_as_of_date
        and row["source_review_status"] == "approved"
    )


def _resolve_catalogue_occurrence(
    rows: list[Any],
    *,
    identity: str,
    current_as_of_date: str,
) -> tuple[Any | None, Any | None, list[str]]:
    """Resolve a fresh occurrence without confusing identical bytes with ambiguity.

    An unchanged official XML snapshot is represented by a new staged occurrence
    whose bytes match the prior approved snapshot.  The staged occurrence is the
    successor; the prior approved occurrence remains immutable audit history and
    is explicitly superseded only during ``--apply``.
    """

    authority = ":".join(identity.split("/"))
    current_identifier = f"{authority}:latest-available@{current_as_of_date}"
    exact_current = [
        row for row in rows if str(row["stable_identifier"] or "") == current_identifier
    ]
    if len(exact_current) == 1:
        return exact_current[0], None, []
    if len(exact_current) > 1:
        return None, None, ["catalogue_identity_not_unique"]
    staged = [
        row
        for row in rows
        if row["source_review_status"] == "staged"
        and str(row["stable_identifier"] or "").startswith("local-path-sha256:")
    ]
    previous = [
        row
        for row in rows
        if _previous_snapshot_for(
            row,
            identity=identity,
            current_as_of_date=current_as_of_date,
        )
    ]
    same_authority_snapshots = [
        row
        for row in rows
        if (match := SNAPSHOT_ID_RE.fullmatch(str(row["stable_identifier"] or "")))
        and match.group("authority") == authority
    ]
    if len(staged) == 1 and not previous and not same_authority_snapshots:
        return staged[0], None, []
    if len(staged) != 1 or len(previous) != 1:
        return None, None, ["catalogue_identity_not_unique"]
    successor = staged[0]
    predecessor = previous[0]
    if (
        successor["version_sha256"] != predecessor["version_sha256"]
        or successor["document_content_sha256"] != predecessor["document_content_sha256"]
        or str(successor["created_at"] or "") <= str(predecessor["created_at"] or "")
    ):
        return None, None, ["identical_snapshot_lineage_invalid"]
    return successor, predecessor, []


def _prepare_identical_rollforward(
    database: Database,
    *,
    successor: Any,
    predecessor: Any,
    reviewed_subject: str,
) -> str:
    """Make the new identical-byte occurrence current, atomically and resumably."""

    successor_document_id = str(successor["document_id"])
    predecessor_document_id = str(predecessor["document_id"])
    successor_source_version_id = str(successor["source_version_id"])
    predecessor_source_version_id = str(predecessor["source_version_id"])
    review_id = (
        str(successor["review_id"])
        if successor["review_id"] and successor["card_status"] == "pending"
        else _review_id(successor_source_version_id)
    )
    with database.transaction() as connection:
        current = connection.execute(
            """
            SELECT d.id AS document_id,d.content_sha256,d.status,d.retrieval_canonical,
                   d.duplicate_of,d.lane,d.jurisdiction,
                   sv.id AS source_version_id,sv.version_sha256,sv.review_status,
                   sv.superseded_by
            FROM documents d JOIN source_versions sv ON sv.document_id=d.id
            WHERE sv.id IN (?,?)
            """,
            (successor_source_version_id, predecessor_source_version_id),
        ).fetchall()
        by_source = {str(row["source_version_id"]): row for row in current}
        new = by_source.get(successor_source_version_id)
        old = by_source.get(predecessor_source_version_id)
        if new is None or old is None:
            raise RuntimeError("identical legislation roll-forward lineage disappeared")
        if (
            new["content_sha256"] != old["content_sha256"]
            or new["version_sha256"] != old["version_sha256"]
            or new["lane"] != "primary_authority"
            or new["jurisdiction"] != "United Kingdom"
            or new["review_status"] != "staged"
            or old["review_status"] != "approved"
            or old["superseded_by"] is not None
        ):
            raise RuntimeError("identical legislation roll-forward failed validation")

        # Retire the old semantic canonical before promoting the successor, so
        # the unique canonical-content index remains valid throughout.
        connection.execute(
            """
            UPDATE documents
            SET retrieval_canonical=0,status='duplicate',duplicate_of=?
            WHERE id=?
            """,
            (successor_document_id, predecessor_document_id),
        )
        connection.execute(
            """
            UPDATE documents
            SET retrieval_canonical=1,status='citable',duplicate_of=NULL,
                subject_primary=?
            WHERE id=?
            """,
            (reviewed_subject, successor_document_id),
        )
        connection.execute(
            "UPDATE source_versions SET superseded_by=? WHERE id=? AND superseded_by IS NULL",
            (successor_source_version_id, predecessor_source_version_id),
        )
        connection.execute(
            """
            INSERT INTO reviews(id,review_type,target_id,status,reason,created_at)
            VALUES (?,'source_version',?,'pending',?,CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                review_id,
                successor_source_version_id,
                "Official snapshot re-fetched with bytes identical to the prior approved occurrence",
            ),
        )
    return review_id


def _close_superseded_pending_reviews(
    database: Database,
    *,
    source_version_id: str,
    approved_review_id: str,
) -> None:
    database.execute(
        """
        UPDATE reviews
        SET status='rejected',
            reason='Superseded by the verified current-legislation approval',
            decided_at=CURRENT_TIMESTAMP
        WHERE review_type='source_version' AND target_id=? AND status='pending' AND id<>?
        """,
        (source_version_id, approved_review_id),
    )


def _official_snapshot_metadata(
    downloaded: dict[str, Any],
    *,
    predecessor_source_version_id: str | None,
    predecessor_bytes_unchanged: bool = False,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "legalbot.official-snapshot.v1",
        "representation": "latest_available_revised_xml",
        "source_modified": downloaded.get("source_modified"),
        "source_valid_from": downloaded.get("source_valid_from"),
        "restrict_start_date": downloaded.get("restrict_start_date"),
        "unapplied_effect_count": int(downloaded.get("unapplied_effect_count") or 0),
        "qualification": ("Legislation.gov.uk latest available text; unapplied effects may remain"),
    }
    if predecessor_source_version_id:
        payload["supersedes_source_version_id"] = predecessor_source_version_id
        payload["source_bytes_unchanged_from_predecessor"] = predecessor_bytes_unchanged
        if predecessor_bytes_unchanged:
            payload["identical_bytes_supersedes_source_version_id"] = predecessor_source_version_id
    return payload


def _rollforward_predecessor_id(
    database: Database,
    *,
    source_version_id: str,
    existing_official_snapshot: Any,
) -> str | None:
    if isinstance(existing_official_snapshot, dict):
        existing = existing_official_snapshot.get("supersedes_source_version_id")
        if not existing:
            existing = existing_official_snapshot.get(
                "identical_bytes_supersedes_source_version_id"
            )
        if existing:
            return str(existing)
    predecessor = database.fetchone(
        """
        SELECT id FROM source_versions
        WHERE superseded_by=? AND stable_identifier LIKE '%:latest-available@%'
        ORDER BY created_at DESC,id DESC LIMIT 1
        """,
        (source_version_id,),
    )
    return str(predecessor["id"]) if predecessor is not None else None


def _active_snapshot_predecessors(
    database: Database,
    *,
    identity: str,
    current_as_of_date: str,
    successor_source_version_id: str,
) -> list[Any]:
    authority = ":".join(identity.split("/"))
    rows = database.fetchall(
        """
        SELECT sv.id AS source_version_id,sv.stable_identifier,sv.version_sha256,
               d.content_sha256 AS document_content_sha256
        FROM source_versions sv JOIN documents d ON d.id=sv.document_id
        WHERE sv.authority_identity_id=? AND sv.id<>?
          AND sv.review_status='approved' AND sv.superseded_by IS NULL
        ORDER BY sv.created_at DESC,sv.id DESC
        """,
        (authority, successor_source_version_id),
    )
    return [
        row
        for row in rows
        if _previous_snapshot_for(
            {
                "stable_identifier": row["stable_identifier"],
                "source_review_status": "approved",
            },
            identity=identity,
            current_as_of_date=current_as_of_date,
        )
    ]


def main() -> None:
    args = _parser().parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if manifest.get("schema") != "legalbot.current-legislation-pack.v1":
        raise SystemExit("unsupported current legislation manifest")
    if report.get("schema") != "legalbot.current-legislation-download-report.v1":
        raise SystemExit("unsupported current legislation download report")
    if report.get("manifest_version") != manifest.get("version"):
        raise SystemExit("download report does not match the reviewed manifest")
    if report.get("as_of_date") != manifest.get("as_of_date"):
        raise SystemExit("download report has a different as-of date")
    by_identity = {str(item["identity"]): item for item in report["items"]}
    expected = {str(item["identity"]): item for item in manifest["items"]}
    if len(by_identity) != len(report["items"]) or set(by_identity) != set(expected):
        raise SystemExit("download identities do not exactly match the manifest")

    database = Database(Settings().database_path)
    database.initialize()
    ready: list[tuple[Any, Any | None, dict[str, Any], dict[str, Any]]] = []
    holds: list[dict[str, Any]] = []
    subject_corrections: list[dict[str, str]] = []
    try:
        if database.fetchone(
            "SELECT id FROM source_scans WHERE status IN ('queued','running') LIMIT 1"
        ):
            raise SystemExit("source scan is active; approval requires a frozen catalogue")
        for identity, item in expected.items():
            downloaded = by_identity[identity]
            reasons: list[str] = []
            if not re.fullmatch(r"[0-9a-f]{64}", str(downloaded.get("sha256") or "")):
                reasons.append("missing_verified_download")
                rows: list[Any] = []
            else:
                rows = database.fetchall(
                    """
                    SELECT d.lane,d.jurisdiction,d.status,d.retrieval_canonical,
                           d.id AS document_id,d.subject_primary,d.duplicate_of,
                           d.content_sha256 AS document_content_sha256,
                           sv.id AS source_version_id,
                           sv.version_sha256,sv.stable_identifier,sv.created_at,
                           sv.review_status AS source_review_status,sv.metadata_json,
                           r.id AS review_id,r.status AS card_status,
                           (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) AS chunk_count,
                           (SELECT group_concat(c.markdown_text,' ') FROM chunks c
                            WHERE c.source_version_id=sv.id) AS local_text
                    FROM documents d
                    JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                    LEFT JOIN reviews r ON r.id=(
                      SELECT r2.id FROM reviews r2
                      WHERE r2.review_type='source_version' AND r2.target_id=sv.id
                      ORDER BY
                        CASE r2.status
                          WHEN 'pending' THEN 0
                          WHEN 'approved' THEN 1
                          ELSE 2
                        END,
                        r2.created_at DESC,r2.id DESC
                      LIMIT 1
                    )
                    WHERE d.content_sha256=?
                    """,
                    (downloaded["sha256"],),
                )
            row, predecessor, resolution_reasons = _resolve_catalogue_occurrence(
                rows,
                identity=identity,
                current_as_of_date=str(manifest["as_of_date"]),
            )
            reasons.extend(resolution_reasons)
            if _normalise_title(str(downloaded.get("title") or "")) != _normalise_title(
                str(item["title"])
            ):
                reasons.append("download_title_mismatch")
            if downloaded.get("status") not in {"downloaded", "already_present"}:
                reasons.append("download_not_verified")
            if downloaded.get("document_status") not in {"revised", "enacted", "final", None}:
                reasons.append("unrecognised_official_document_status")
            if row is not None:
                metadata = json.loads(row["metadata_json"] or "{}")
                if row["lane"] != "primary_authority":
                    reasons.append("wrong_lane")
                if row["jurisdiction"] != "United Kingdom":
                    reasons.append("wrong_jurisdiction")
                if predecessor is None and (
                    row["status"] != "citable" or int(row["retrieval_canonical"]) != 1
                ):
                    reasons.append("not_canonical_citable_source")
                if row["source_review_status"] not in {"staged", "approved"}:
                    reasons.append("source_review_not_actionable")
                if row["source_review_status"] == "approved" and row[
                    "stable_identifier"
                ] != _stable_identifier(identity, str(manifest["as_of_date"])):
                    reasons.append("approved_snapshot_date_mismatch")
                if (
                    predecessor is None
                    and row["source_review_status"] == "staged"
                    and row["card_status"] != "pending"
                ):
                    reasons.append("review_card_not_actionable")
                if int(row["chunk_count"]) < 1:
                    reasons.append("no_chunks")
                if metadata.get("material_type_candidate") != "legislation":
                    reasons.append("not_legislation_candidate")
                local_text = str(row["local_text"] or "")
                if "/Users/" in local_text or prompt_injection_hits(local_text):
                    reasons.append("unsafe_retrieval_text")
            result = {
                "identity": identity,
                "decision": "approve" if not reasons else "hold",
                "reasons": reasons,
            }
            if reasons or row is None:
                holds.append(result)
            else:
                ready.append((row, predecessor, item, downloaded))
        if holds:
            print(json.dumps({"ready": len(ready), "holds": holds}, indent=2, sort_keys=True))
            raise SystemExit("current legislation approval stopped: resolve every hold")
        if args.apply:
            cipher = LocalCipher.from_local_key(create=False)
            encrypted_note = cipher.encrypt_text(
                f"{POLICY}: exact OGL latest-available XML snapshot verified; owner must heed recorded unapplied effects"
            )
            identical_rollforwards = 0
            for row, predecessor, item, downloaded in ready:
                reviewed_subject = SUBJECTS.get(str(item["subject_folder"]))
                if reviewed_subject is None:
                    raise RuntimeError("current legislation manifest has an unknown subject")
                if str(row["subject_primary"]) != reviewed_subject:
                    subject_corrections.append(
                        {
                            "stable_identifier": _stable_identifier(
                                str(item["identity"]), str(manifest["as_of_date"])
                            ),
                            "from": str(row["subject_primary"]),
                            "to": reviewed_subject,
                        }
                    )
                review_id = str(row["review_id"] or "")
                if predecessor is not None:
                    review_id = _prepare_identical_rollforward(
                        database,
                        successor=row,
                        predecessor=predecessor,
                        reviewed_subject=reviewed_subject,
                    )
                    identical_rollforwards += 1
                elif str(row["subject_primary"]) != reviewed_subject:
                    database.execute(
                        "UPDATE documents SET subject_primary=? WHERE id=?",
                        (reviewed_subject, row["document_id"]),
                    )
                if row["source_review_status"] != "approved" and not database.decide_review(
                    review_id,
                    "approved",
                    None,
                    _source_approval(item, manifest),
                    encrypted_note=encrypted_note,
                ):
                    raise RuntimeError("current legislation review changed during approval")
                approved_review_id = review_id
                if row["source_review_status"] == "approved":
                    approved_review = database.fetchone(
                        """
                        SELECT id FROM reviews
                        WHERE review_type='source_version' AND target_id=? AND status='approved'
                        ORDER BY decided_at DESC,created_at DESC,id DESC LIMIT 1
                        """,
                        (row["source_version_id"],),
                    )
                    if approved_review is None:
                        raise RuntimeError("approved source version has no approval record")
                    approved_review_id = str(approved_review["id"])
                _close_superseded_pending_reviews(
                    database,
                    source_version_id=str(row["source_version_id"]),
                    approved_review_id=approved_review_id,
                )
                active_predecessors = _active_snapshot_predecessors(
                    database,
                    identity=str(item["identity"]),
                    current_as_of_date=str(manifest["as_of_date"]),
                    successor_source_version_id=str(row["source_version_id"]),
                )
                for active_predecessor in active_predecessors:
                    database.execute(
                        """
                        UPDATE source_versions SET superseded_by=?
                        WHERE id=? AND superseded_by IS NULL
                        """,
                        (
                            row["source_version_id"],
                            active_predecessor["source_version_id"],
                        ),
                    )
                source_version = database.fetchone(
                    "SELECT metadata_json FROM source_versions WHERE id=?",
                    (row["source_version_id"],),
                )
                if source_version is None:
                    raise RuntimeError("approved source version disappeared")
                metadata = json.loads(source_version["metadata_json"])
                existing_official_snapshot = metadata.get("official_snapshot")
                predecessor_source_version_id = (
                    str(predecessor["source_version_id"])
                    if predecessor is not None
                    else (
                        str(active_predecessors[0]["source_version_id"])
                        if active_predecessors
                        else _rollforward_predecessor_id(
                            database,
                            source_version_id=str(row["source_version_id"]),
                            existing_official_snapshot=existing_official_snapshot,
                        )
                    )
                )
                predecessor_bytes_unchanged = bool(
                    predecessor is not None
                    or (
                        active_predecessors
                        and str(active_predecessors[0]["document_content_sha256"])
                        == str(downloaded["sha256"])
                        and str(active_predecessors[0]["version_sha256"])
                        == str(row["version_sha256"])
                    )
                    or (
                        isinstance(existing_official_snapshot, dict)
                        and existing_official_snapshot.get(
                            "source_bytes_unchanged_from_predecessor"
                        )
                        is True
                    )
                    or (
                        isinstance(existing_official_snapshot, dict)
                        and bool(
                            existing_official_snapshot.get(
                                "identical_bytes_supersedes_source_version_id"
                            )
                        )
                    )
                )
                metadata["official_snapshot"] = _official_snapshot_metadata(
                    downloaded,
                    predecessor_source_version_id=predecessor_source_version_id,
                    predecessor_bytes_unchanged=predecessor_bytes_unchanged,
                )
                stable_identifier = _stable_identifier(
                    str(item["identity"]), str(manifest["as_of_date"])
                )
                database.execute(
                    """
                    UPDATE source_versions
                    SET metadata_json=?,authority_identity_id=?
                    WHERE id=?
                    """,
                    (
                        json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                        stable_identifier.rsplit(":latest-available@", 1)[0],
                        row["source_version_id"],
                    ),
                )
            lineage_rows = database.fetchall(
                """
                SELECT stable_identifier,
                       json_extract(
                         metadata_json,
                         '$.official_snapshot.supersedes_source_version_id'
                       ) AS predecessor_source_version_id,
                       json_extract(
                         metadata_json,
                         '$.official_snapshot.source_bytes_unchanged_from_predecessor'
                       ) AS source_bytes_unchanged
                FROM source_versions
                WHERE review_status='approved' AND superseded_by IS NULL
                  AND stable_identifier LIKE ?
                  AND json_extract(
                        metadata_json,
                        '$.official_snapshot.supersedes_source_version_id'
                      ) IS NOT NULL
                ORDER BY stable_identifier
                """,
                (f"%:latest-available@{manifest['as_of_date']}",),
            )
            args.subject_report.parent.mkdir(parents=True, exist_ok=True)
            args.subject_report.write_text(
                json.dumps(
                    {
                        "schema": "legalbot.subject-correction-report.v1",
                        "policy": POLICY,
                        "manifest_version": manifest["version"],
                        "snapshot_rollforwards": len(lineage_rows),
                        "identical_byte_rollforwards": sum(
                            bool(item["source_bytes_unchanged"]) for item in lineage_rows
                        ),
                        "identical_byte_rollforwards_applied_this_run": (identical_rollforwards),
                        "rollforward_lineages": [dict(item) for item in lineage_rows],
                        "corrections": subject_corrections,
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        print(
            json.dumps(
                {
                    "apply": args.apply,
                    "approved_or_ready": len(ready),
                    "identical_byte_rollforwards": sum(
                        predecessor is not None for _row, predecessor, _item, _downloaded in ready
                    ),
                    "holds": 0,
                    "subject_corrections": len(subject_corrections),
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
