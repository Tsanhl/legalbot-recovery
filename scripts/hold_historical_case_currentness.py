#!/usr/bin/env python3
"""Apply audited present-law and rights holds to every approved case source.

Official judgment bytes verify identity and the decision-date text, not later
treatment of every proposition.  This migration is dry-run by default.  It
does not alter source bytes, canonical Markdown, indexes, or promotion
pointers; any pre-existing index containing affected rows must be rebuilt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.config import Settings  # noqa: E402
from backend.app.currentness import (  # noqa: E402
    HISTORICAL_CASE_CURRENTNESS_POLICY,
    apply_historical_case_treatment_hold,
)
from backend.app.db import Database  # noqa: E402

REPORT_SCHEMA = "legalbot.case-currentness-rights-hold-report.v2"
DEFAULT_REPORT = PROJECT_ROOT / "data" / "review_queue" / "historical-case-currentness-hold.json"


def _canonical_sha256(value: object) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(data).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser


def approved_case_rows(database: Database) -> list[Any]:
    return database.fetchall(
        """
        SELECT sv.id AS source_version_id,sv.stable_identifier,sv.version_sha256,
               sv.currentness_status,sv.licence_name,sv.metadata_json,d.lane,d.status
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND d.lane='primary_authority'
          AND d.status='citable'
          AND sv.stable_identifier LIKE 'neutral-citation:%'
          AND json_extract(sv.metadata_json,'$.identity_verified')=1
          AND lower(COALESCE(json_extract(sv.metadata_json,'$.citation_data.source_type'),''))='case'
        ORDER BY sv.stable_identifier,sv.id
        """
    )


def case_policy_metadata(
    metadata: dict[str, Any], *, licence_name: object
) -> tuple[dict[str, Any], str]:
    """Hold currentness, and keep unreviewed-rights full text metadata-only."""

    output = apply_historical_case_treatment_hold(metadata)
    licence = str(licence_name or "")
    rights_reviewed = licence.startswith(("Open Government Licence", "Open Parliament Licence"))
    if rights_reviewed:
        output["rights_runtime_status"] = "rights_reviewed_official_judgment"
        output["rights_review_required"] = False
        # Do not upgrade an independently false model-use decision.
        output["full_text_runtime_eligible"] = output.get("eligible_for_model_use") is True
        return output, "rights_reviewed_official"
    output.update(
        {
            "eligible_for_model_use": False,
            "authority_eligible": False,
            "full_text_runtime_eligible": False,
            "rights_review_required": True,
            "rights_runtime_status": "metadata_only_pending_rights_review",
            "ai_use_policy": "metadata_only_pending_rights_review",
        }
    )
    return output, "metadata_only_unreviewed_rights"


def apply_currentness_holds(database: Database, *, apply: bool) -> dict[str, Any]:
    rows = approved_case_rows(database)
    decisions: list[dict[str, Any]] = []
    changed = 0
    already_held = 0
    affected_ids: list[str] = []
    rights_counts = {
        "rights_reviewed_official": 0,
        "metadata_only_unreviewed_rights": 0,
    }

    for row in rows:
        metadata = json.loads(row["metadata_json"] or "{}")
        if not isinstance(metadata, dict):
            raise ValueError("approved historical case metadata is not an object")
        citation_data = metadata.get("citation_data")
        if not isinstance(citation_data, dict) or citation_data.get("source_type") != "case":
            raise ValueError("historical case row lost its structured case identity")
        held, rights_status = case_policy_metadata(metadata, licence_name=row["licence_name"])
        rights_counts[rights_status] += 1
        is_already_held = metadata == held
        already_held += int(is_already_held)
        changed += int(not is_already_held)
        affected_ids.append(str(row["source_version_id"]))
        decisions.append(
            {
                "source_version_id": str(row["source_version_id"]),
                "stable_identifier": str(row["stable_identifier"]),
                "source_version_sha256": str(row["version_sha256"]),
                "currentness_status": str(row["currentness_status"]),
                "rights_runtime_status": rights_status,
                "prior_currentness_verified": metadata.get("currentness_verified") is True,
                "present_law_currentness_verified": False,
                "subsequent_treatment_check_required": True,
            }
        )

    evidence_rows_held = 0
    if apply and affected_ids:
        with database.transaction() as connection:
            for row in rows:
                metadata = json.loads(row["metadata_json"] or "{}")
                held, _ = case_policy_metadata(metadata, licence_name=row["licence_name"])
                connection.execute(
                    "UPDATE source_versions SET metadata_json=? WHERE id=?",
                    (
                        json.dumps(held, ensure_ascii=False, sort_keys=True),
                        row["source_version_id"],
                    ),
                )
            placeholders = ",".join("?" for _ in affected_ids)
            cursor = connection.execute(
                f"""
                UPDATE evidence_spans
                SET currentness_verified=0
                WHERE source_version_id IN ({placeholders})
                  AND currentness_verified<>0
                """,
                tuple(affected_ids),
            )
            evidence_rows_held = max(0, int(cursor.rowcount))

    active_pointer = Settings().index_dir / "ACTIVE.json"
    nonterminal_builds = database.fetchall(
        """
        SELECT id,status FROM index_builds
        WHERE status NOT IN ('failed','invalidated','superseded')
        ORDER BY created_at,id
        """
    )
    safe_builds = [
        {"index_build_id": str(row["id"]), "status": str(row["status"])}
        for row in nonterminal_builds
    ]
    return {
        "schema": REPORT_SCHEMA,
        "apply": apply,
        "policy_version": HISTORICAL_CASE_CURRENTNESS_POLICY,
        "approved_case_source_versions": len(rows),
        "historical_case_source_versions": sum(
            str(row["currentness_status"]) == "historical" for row in rows
        ),
        "point_in_time_case_source_versions": sum(
            str(row["currentness_status"]) == "point_in_time" for row in rows
        ),
        "rights_runtime_counts": rights_counts,
        "changed": changed,
        "already_held": already_held,
        "persisted_evidence_rows_held": evidence_rows_held,
        "present_law_currentness_verified": False,
        "required_release_status": "evidence_span_and_proposition_treatment_contract_required",
        "source_level_later_treatment_flag_sufficient": False,
        "source_bytes_or_canonical_markdown_changed": False,
        "index_built_or_promoted": False,
        "active_pointer_exists": active_pointer.is_file(),
        "preexisting_nonterminal_indexes_require_rebuild": safe_builds,
        "decisions": decisions,
        "decision_digest": _canonical_sha256(decisions),
    }


def main() -> None:
    args = _parser().parse_args()
    database = Database(Settings().database_path)
    database.initialize()
    try:
        if database.fetchone("SELECT id FROM source_scans WHERE status IN ('queued','running')"):
            raise SystemExit(
                "source scan is active; currentness migration requires a frozen catalogue"
            )
        if database.fetchone("SELECT id FROM index_builds WHERE status='building'"):
            raise SystemExit(
                "index build is active; currentness migration requires a frozen catalogue"
            )
        result = apply_currentness_holds(database, apply=args.apply)
        result["created_at"] = datetime.now(UTC).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in (
                        "apply",
                        "approved_case_source_versions",
                        "historical_case_source_versions",
                        "point_in_time_case_source_versions",
                        "rights_runtime_counts",
                        "changed",
                        "already_held",
                        "persisted_evidence_rows_held",
                        "active_pointer_exists",
                        "index_built_or_promoted",
                        "decision_digest",
                    )
                },
                indent=2,
                sort_keys=True,
            )
        )
    finally:
        database.close()


if __name__ == "__main__":
    main()
