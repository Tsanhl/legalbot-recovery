#!/usr/bin/env python3
"""Approve only exact official UKSC judgments in the reviewed bounded pack."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.citations.oscola import render_oscola  # noqa: E402
from backend.app.config import Settings  # noqa: E402
from backend.app.crypto import LocalCipher  # noqa: E402
from backend.app.currentness import apply_historical_case_treatment_hold  # noqa: E402
from backend.app.db import Database  # noqa: E402
from backend.app.privacy import prompt_injection_hits  # noqa: E402

DEFAULT_MANIFEST = PROJECT_ROOT / "config" / "uksc_authority_pack.json"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "uksc-authority-download.json"
DEFAULT_CORRECTIONS = (
    PROJECT_ROOT / "data" / "review_queue" / "uksc-classification-corrections.json"
)
POLICY = "legalbot.verified-uksc-oglv3.v2"
SUBJECTS = {
    "Contract law": "contract",
    "Consumer law": "consumer",
    "Professional negligence law": "professional negligence",
    "Civil litigation law": "civil litigation",
    "Intellectual property law": "intellectual property",
    "Wills and succession law": "wills and succession",
    "Public and constitutional law": "public and constitutional",
    "Employment and equality law": "employment",
    "Company law": "company",
    "Family law": "family",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--corrections", type=Path, default=DEFAULT_CORRECTIONS)
    parser.add_argument("--apply", action="store_true")
    return parser


def _approval(
    item: dict[str, Any], downloaded: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    citation_data = {
        "source_type": "case",
        "case_name": str(item["case_name"]),
        "neutral_citation": str(item["neutral_citation"]),
        "decision_date": str(downloaded["judgment_date"]),
    }
    render_oscola(citation_data)
    licence = manifest["licence"]
    return {
        "identity_verified": True,
        "currentness_verified": False,
        "stable_identifier": f"neutral-citation:{item['neutral_citation']}",
        # This verifies the immutable historic judgment at its decision date;
        # it is not a source-wide subsequent-treatment check.
        "as_of_date": downloaded["judgment_date"],
        "currentness_status": "historical",
        "material_type": "case",
        "citation_data": citation_data,
        "canonical_url": downloaded["canonical_url"],
        "licence_name": f"{licence['name']} v{licence['version']}",
        "licence_url": licence["url"],
    }


def main() -> None:
    args = _parser().parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if manifest.get("schema") != "legalbot.uksc-authority-pack.v1":
        raise SystemExit("unsupported UKSC manifest")
    if report.get("schema") != "legalbot.uksc-authority-download-report.v1":
        raise SystemExit("unsupported UKSC download report")
    if report.get("manifest_version") != manifest.get("version"):
        raise SystemExit("UKSC report and manifest versions differ")
    expected = {str(item["case_id"]): item for item in manifest["items"]}
    downloaded = {str(item["case_id"]): item for item in report["items"]}
    if len(expected) != 15 or set(expected) != set(downloaded):
        raise SystemExit("UKSC pack identities do not reconcile exactly")

    database = Database(Settings().database_path)
    database.initialize()
    ready: list[tuple[Any, dict[str, Any], dict[str, Any], str]] = []
    holds: list[dict[str, Any]] = []
    corrections: list[dict[str, str]] = []
    try:
        if database.fetchone("SELECT id FROM source_scans WHERE status IN ('queued','running')"):
            raise SystemExit("source scan is active; UKSC approval requires a frozen catalogue")
        for case_id, item in expected.items():
            local = downloaded[case_id]
            subject = SUBJECTS.get(str(item["subject_folder"]))
            if subject is None:
                raise SystemExit("UKSC manifest has an unknown subject folder")
            rows = database.fetchall(
                """
                SELECT d.id AS document_id,d.lane,d.status,d.subject_primary,d.jurisdiction,
                       d.retrieval_canonical,sv.id AS source_version_id,
                       sv.review_status AS source_review_status,sv.metadata_json,
                       r.id AS review_id,r.status AS card_status,
                       (SELECT COUNT(*) FROM chunks c WHERE c.source_version_id=sv.id) chunk_count,
                       (SELECT group_concat(c.markdown_text,' ') FROM chunks c
                        WHERE c.source_version_id=sv.id) local_text
                FROM documents d
                JOIN source_versions sv ON sv.document_id=d.id AND sv.superseded_by IS NULL
                LEFT JOIN reviews r ON r.review_type='source_version' AND r.target_id=sv.id
                WHERE d.content_sha256=?
                """,
                (local["sha256"],),
            )
            reasons: list[str] = []
            row = rows[0] if len(rows) == 1 else None
            if row is None:
                reasons.append("catalogue_identity_not_unique")
            else:
                text = str(row["local_text"] or "")
                if int(row["retrieval_canonical"]) != 1:
                    reasons.append("not_canonical_representation")
                if int(row["chunk_count"]) < 1:
                    reasons.append("no_chunks")
                if row["source_review_status"] not in {"staged", "approved"}:
                    reasons.append("source_review_not_actionable")
                if row["source_review_status"] == "staged" and row["card_status"] != "pending":
                    reasons.append("review_card_not_actionable")
                if str(item["neutral_citation"]) not in text:
                    reasons.append("neutral_citation_not_in_judgment")
                title_tokens = set(re.findall(r"[a-z0-9]+", str(item["case_name"]).casefold()))
                text_tokens = set(re.findall(r"[a-z0-9]+", text[:50_000].casefold()))
                if len(title_tokens & text_tokens) / max(1, len(title_tokens)) < 0.7:
                    reasons.append("case_identity_not_in_judgment")
                if "/Users/" in text or prompt_injection_hits(text):
                    reasons.append("unsafe_retrieval_text")
            if reasons or row is None:
                holds.append({"case_id": case_id, "reasons": reasons})
            else:
                ready.append((row, item, local, subject))
        if holds:
            print(json.dumps({"ready": len(ready), "holds": holds}, indent=2, sort_keys=True))
            raise SystemExit("UKSC approval stopped: resolve every hold")
        if args.apply:
            note: bytes | None = None
            if any(row["source_review_status"] != "approved" for row, _, _, _ in ready):
                cipher = LocalCipher.from_local_key(create=False)
                note = cipher.encrypt_text(
                    f"{POLICY}: exact official UKSC judgment and neutral citation verified; "
                    "treatment must be checked per live issue"
                )
            for row, item, local, subject in ready:
                previous = {
                    "lane": str(row["lane"]),
                    "status": str(row["status"]),
                    "subject": str(row["subject_primary"]),
                }
                target = {"lane": "primary_authority", "status": "citable", "subject": subject}
                if previous != target:
                    corrections.append(
                        {
                            "stable_identifier": f"neutral-citation:{item['neutral_citation']}",
                            "from_lane": previous["lane"],
                            "to_lane": target["lane"],
                            "from_status": previous["status"],
                            "to_status": target["status"],
                            "from_subject": previous["subject"],
                            "to_subject": target["subject"],
                        }
                    )
                    database.execute(
                        "UPDATE documents SET lane=?,status=?,subject_primary=? WHERE id=?",
                        (target["lane"], target["status"], target["subject"], row["document_id"]),
                    )
                if row["source_review_status"] != "approved" and not database.decide_review(
                    str(row["review_id"]),
                    "approved",
                    None,
                    _approval(item, local, manifest),
                    encrypted_note=note,
                    trusted_case_snapshot_approval=True,
                ):
                    raise RuntimeError("UKSC review changed during approval")
                source_row = database.fetchone(
                    "SELECT metadata_json FROM source_versions WHERE id=?",
                    (row["source_version_id"],),
                )
                metadata = json.loads(source_row["metadata_json"] or "{}")
                metadata["official_snapshot"] = {
                    "schema": "legalbot.official-judgment-snapshot.v1",
                    "publisher": "UK Supreme Court",
                    "case_id": item["case_id"],
                    "download_sha256": local["sha256"],
                    "judgment_date": local["judgment_date"],
                    "treatment_qualification": "Expert must verify subsequent treatment for the live issue",
                }
                metadata = apply_historical_case_treatment_hold(metadata, policy_version=POLICY)
                database.execute(
                    """
                    UPDATE source_versions
                    SET title=?,author_or_body='UK Supreme Court',source_date=?,as_of_date=?,
                        currentness_status='historical',metadata_json=?
                    WHERE id=?
                    """,
                    (
                        item["case_name"],
                        local["judgment_date"],
                        local["judgment_date"],
                        json.dumps(metadata, ensure_ascii=False, sort_keys=True),
                        row["source_version_id"],
                    ),
                )
            args.corrections.parent.mkdir(parents=True, exist_ok=True)
            args.corrections.write_text(
                json.dumps(
                    {
                        "schema": "legalbot.classification-correction-report.v1",
                        "policy": POLICY,
                        "corrections": corrections,
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
                    "holds": 0,
                    "classification_corrections": len(corrections),
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
