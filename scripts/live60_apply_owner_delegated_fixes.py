#!/usr/bin/env python3
"""Apply owner-delegated Live60 catalogue cleanup and issue ticks.

Does not write ACTIVE.json, O-04, or a sealed expert-qualification overlay.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.evaluation.live_suite_held_span_repair import (  # noqa: E402
    apply_held_span_catalogue_cleanup,
    build_held_span_contiguous_repair,
)
from app.evaluation.live_suite_owner_decisions import (  # noqa: E402
    export_held_provision_chunks,
    mechanically_verify_held_provisions,
)
from app.evaluation.live_suite_tick_draft import (  # noqa: E402
    SPLICED_PARENT_CHUNK_IDS,
    apply_contrary_authority_status,
    bind_issue_tick,
    empty_tick_draft,
    load_live60_bundle,
    load_repair_payload,
    summarize_tick_draft,
    write_json,
)

OUT = PROJECT_ROOT / "Live60-2026-08-16" / "go-execution"
CATALOG = PROJECT_ROOT / "data" / "catalog.sqlite3"
EVIDENCE = OUT / "issue-candidate-evidence-map.json"
DRAFT = PROJECT_ROOT / "Live60-2026-08-16" / "artifacts" / "issue-ticks-draft.json"
OGL_MARKERS = ("open government licence", "ogl")
APPROVED = frozenset({"approved"})
LEGISLATION_CURRENT = frozenset({"latest_available_revised_snapshot", "point_in_time"})


def _chunk_row(connection: sqlite3.Connection, chunk_id: str) -> sqlite3.Row | None:
    row = connection.execute(
        """
        SELECT c.id, c.source_version_id, c.locator, c.text_sha256, c.stream,
               sv.licence_name, sv.review_status, sv.currentness_status, sv.superseded_by
        FROM chunks c
        JOIN source_versions sv ON sv.id = c.source_version_id
        WHERE c.id = ?
        """,
        (chunk_id,),
    ).fetchone()
    if row is None:
        return None
    current_id = row["superseded_by"]
    seen: set[str] = set()
    while current_id and current_id not in seen:
        seen.add(current_id)
        replacement = connection.execute(
            """
            SELECT c.id, c.source_version_id, c.locator, c.text_sha256, c.stream,
                   sv.licence_name, sv.review_status, sv.currentness_status, sv.superseded_by
            FROM chunks c
            JOIN source_versions sv ON sv.id = c.source_version_id
            WHERE sv.id = ?
              AND c.locator = ?
              AND COALESCE(c.stream, 'body') = 'body'
            ORDER BY c.ordinal, c.id
            LIMIT 1
            """,
            (current_id, row["locator"]),
        ).fetchone()
        if replacement is None:
            break
        row = replacement
        current_id = row["superseded_by"]
    return row


def _is_ogl(value: str | None) -> bool:
    lowered = (value or "").casefold()
    return any(marker in lowered for marker in OGL_MARKERS)


def _source_type(issue: dict) -> str:
    for candidate in issue.get("candidates") or ():
        kind = str(candidate.get("source_type") or "").casefold()
        if kind:
            return kind
    return ""


def apply_ticks(*, catalog: Path, repair: dict) -> dict:
    bundle = load_live60_bundle(PROJECT_ROOT)
    draft = empty_tick_draft(as_of_date=date(2026, 8, 16).isoformat())
    draft["owner_delegated_execution"] = True
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    connection = sqlite3.connect(f"file:{catalog}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    bound = 0
    try:
        for issue in evidence["issues"]:
            status = "knowledge_gap"
            span = None
            later = None
            gap_reason = "no_verified_catalogue_span_bound"
            qualified_span = None
            limited_span = None
            limited_reason = None
            for candidate in issue.get("candidates") or ():
                kind = str(candidate.get("source_type") or "").casefold()
                for local in candidate.get("local_spans") or ():
                    chunk_id = str(local.get("chunk_id") or "")
                    if not chunk_id or chunk_id in SPLICED_PARENT_CHUNK_IDS:
                        continue
                    row = _chunk_row(connection, chunk_id)
                    if row is None or row["superseded_by"]:
                        continue
                    if str(row["stream"] or "body") != "body":
                        continue
                    found = {
                        "chunk_id": row["id"],
                        "content_sha256": row["text_sha256"],
                        "legal_locator": row["locator"],
                        "source_version_id": row["source_version_id"],
                    }
                    legislation_ok = (
                        "legislation" in kind
                        and _is_ogl(row["licence_name"])
                        and row["review_status"] in APPROVED
                        and (row["currentness_status"] or "") in LEGISLATION_CURRENT
                    )
                    if legislation_ok and qualified_span is None:
                        qualified_span = found
                    elif limited_span is None:
                        limited_span = found
                        limited_reason = (
                            "owner_delegated_limited_pending_later_treatment"
                            if "legislation" not in kind
                            else "owner_delegated_limited_unapproved_or_non_current"
                        )
                if qualified_span:
                    break
            if qualified_span:
                status = "qualified"
                span = qualified_span
                later = "legislation_latest_available_snapshot"
                gap_reason = None
            elif limited_span:
                status = "limited"
                span = limited_span
                later = "not_reviewed"
                gap_reason = limited_reason
            bind_issue_tick(
                draft,
                bundle=bundle,
                case_id=issue["case_id"],
                issue_id=issue["issue_id"],
                status=status,
                span=span,
                catalog_path=catalog,
                repair=repair,
                later_treatment=later,
                gap_reason=gap_reason,
            )
            bound += 1
    finally:
        connection.close()
    apply_contrary_authority_status(draft, status="reviewed_none")
    write_json(DRAFT, draft)
    progress = summarize_tick_draft(draft)
    write_json(DRAFT.with_name("owner-tick-progress.json"), progress)
    return {"bound_issues": bound, "progress": progress, "draft": str(DRAFT)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--skip-cleanup", action="store_true")
    parser.add_argument("--skip-ticks", action="store_true")
    args = parser.parse_args()
    catalog = args.catalog
    export = export_held_provision_chunks(catalog)
    repair = build_held_span_contiguous_repair(export)
    cleanup = None
    if not args.skip_cleanup:
        cleanup = apply_held_span_catalogue_cleanup(catalog, export=export, repair=repair)
        write_json(OUT / "held-span-catalogue-cleanup.json", cleanup)
        export = export_held_provision_chunks(catalog)
        repair = build_held_span_contiguous_repair(export)
        mechanical = mechanically_verify_held_provisions(export, fetch_official=None)
        write_json(
            OUT / "four-statute-pack.json",
            {
                "schema": "legalbot.live60-four-statute-repair-pack.v1",
                "cleanup": {
                    "excluded": cleanup["excluded_parent_chunk_ids"],
                    "inserted": len(cleanup["inserted_contiguous_chunks"]),
                    "parent_bytes_deleted": False,
                },
                "mechanical_verification": {
                    "approval_status": mechanical.get("approval_status"),
                    "expert_approved": mechanical.get("expert_approved"),
                    "qualified_count": mechanical.get("qualified_count"),
                    "results": [
                        {
                            "held_id": item.get("held_id"),
                            "title": item.get("title"),
                            "disposition": item.get("disposition"),
                            "structural_defect_count": item.get("structural_defect_count"),
                            "qualified": item.get("qualified"),
                            "official_normalised_exact_match": item.get(
                                "official_normalised_exact_match"
                            ),
                        }
                        for item in mechanical.get("results", ())
                    ],
                },
                "contiguous_repair": {
                    "repair_span_count": repair.get("repair_span_count"),
                    "qualified": False,
                },
                "qualified": False,
                "catalogue_parents_excluded_from_body": True,
                "seals_expert_gold": False,
            },
        )
        print(
            json.dumps(
                {
                    "excluded": cleanup["excluded_parent_chunk_ids"],
                    "inserted": len(cleanup["inserted_contiguous_chunks"]),
                    "locator_updates": len(cleanup["locator_updates"]),
                    "structural_defects_after": sum(
                        item.get("structural_defect_count") or 0
                        for item in mechanical.get("results", ())
                    ),
                },
                indent=2,
            )
        )
    ticks = None
    if not args.skip_ticks:
        repair_payload = (
            load_repair_payload(
                PROJECT_ROOT
                / "Live60-2026-08-16"
                / "artifacts"
                / "held-span-contiguous-repair-v2.json"
            )
            or repair
        )
        ticks = apply_ticks(catalog=catalog, repair=dict(repair_payload))
        print(json.dumps(ticks["progress"], indent=2, sort_keys=True))
    write_json(
        OUT / "owner-delegated-application.json",
        {
            "cleanup": cleanup,
            "ticks": ticks["progress"] if ticks else None,
            "wrote_active": False,
            "wrote_o04": False,
            "seals_expert_gold": False,
        },
    )


if __name__ == "__main__":
    main()
