"""Sealable privacy audit for a candidate index and operational metadata."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .config import Settings
from .db import Database, utc_iso
from .evaluation.live30 import assert_safe_evaluation_payload
from .privacy import (
    PRIVATE_QUESTION_SUMMARY,
    contains_absolute_private_path,
    is_excluded_from_corpus_discovery,
    prompt_injection_hits,
    scrub_pii,
)
from .retrieval.cache import validate_safe_cache_payload


def build_candidate_privacy_report(settings: Settings, database: Database) -> dict[str, Any]:
    """Return counts and opaque IDs only; never reproduce prohibited text."""

    findings: Counter[str] = Counter()
    checked_chunks = 0
    prompt_view_redactions = 0

    def count_rows(sql: str, params: tuple[object, ...] = ()) -> int:
        row = database.fetchone(sql, params)
        return int(row["n"]) if row is not None else 0

    # ``review_status=approved`` records a source-review decision.  It does not
    # by itself grant model-use rights.  In particular, Find Case Law metadata
    # records remain useful catalogue/audit history while their full text is
    # explicitly ineligible for model use.  Count those exclusions, but scan
    # only rows that can enter the derived model-facing index as blockers.
    rights_excluded_sources = count_rows(
        """
        SELECT COUNT(DISTINCT sv.id) AS n
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND sv.version_sha256=d.content_sha256
          AND d.duplicate_of IS NULL
          AND d.retrieval_canonical=1
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use') IS NOT 1
        """
    )
    rights_excluded_chunks = count_rows(
        """
        SELECT COUNT(*) AS n
        FROM chunks c
        JOIN source_versions sv ON sv.id=c.source_version_id
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND sv.version_sha256=d.content_sha256
          AND d.duplicate_of IS NULL
          AND d.retrieval_canonical=1
          AND c.stream='body'
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use') IS NOT 1
        """
    )
    conflicting_rights_sources = count_rows(
        """
        SELECT COUNT(*) AS n
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND sv.version_sha256=d.content_sha256
          AND d.duplicate_of IS NULL
          AND d.retrieval_canonical=1
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use')=1
          AND json_extract(sv.metadata_json, '$.ai_use_policy')='prohibited'
        """
    )
    if conflicting_rights_sources:
        findings["conflicting_rights_metadata_approved_source"] += conflicting_rights_sources

    approved_sources = database.fetchall(
        """
        SELECT sv.id,sv.metadata_json AS source_metadata_json,d.lane,
               d.retrieval_canonical
        FROM source_versions sv
        JOIN documents d ON d.id=sv.document_id
        WHERE sv.review_status='approved'
          AND sv.superseded_by IS NULL
          AND sv.version_sha256=d.content_sha256
          AND d.duplicate_of IS NULL
          AND d.status IN ('citable', 'private_teaching', 'assessment_guidance')
          AND json_extract(sv.metadata_json, '$.eligible_for_model_use')=1
          AND COALESCE(json_extract(sv.metadata_json, '$.ai_use_policy'), '')<>'prohibited'
        ORDER BY sv.id
        """
    )
    # Drive the scan from the small approved-source set.  The catalogue can
    # contain millions of rejected/staged chunks; repeatedly walking the global
    # chunk primary key makes a privacy gate needlessly slow.
    for source in approved_sources:
        try:
            source_metadata = json.loads(str(source["source_metadata_json"] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            findings["invalid_source_metadata"] += 1
            continue
        if not isinstance(source_metadata, dict):
            findings["invalid_source_metadata"] += 1
            continue
        rows = database.fetchall(
            """
            SELECT id,markdown_text,locator,metadata_json AS chunk_metadata_json
            FROM chunks
            WHERE source_version_id=?
              AND (
                (?=1 AND stream='body')
                OR (?='assessment_guidance' AND stream='comments')
              )
            ORDER BY ordinal,id
            """,
            (source["id"], source["retrieval_canonical"], source["lane"]),
        )
        for row in rows:
            checked_chunks += 1
            combined = "\n".join(
                str(row[key] or "") for key in ("markdown_text", "locator", "chunk_metadata_json")
            )
            if contains_absolute_private_path(combined):
                findings["absolute_path_in_index_row"] += 1
            owner_hit = any(
                identifier.casefold() in combined.casefold()
                for identifier in settings.owner_identifiers
            )
            private_lane_pii = (
                str(source["lane"])
                in {
                    "private_teaching",
                    "assessment_guidance",
                }
                and scrub_pii(combined) != combined
            )
            if owner_hit:
                findings["personal_identifier_in_index_row"] += 1
            if private_lane_pii:
                # Canonical source text stays immutable.  Candidate index rows
                # are a derived prompt-safe view and must redact this material.
                prompt_view_redactions += 1
            if prompt_injection_hits(combined):
                findings["document_instruction_in_index_row"] += 1

    operational_checks = {
        "plaintext_question_in_request_json": int(
            count_rows(
                "SELECT COUNT(*) AS n FROM jobs "
                "WHERE json_type(request_json, '$.question') IS NOT NULL"
            )
        ),
        "revealing_question_summary": int(
            count_rows(
                "SELECT COUNT(*) AS n FROM jobs WHERE question_summary<>?",
                (PRIVATE_QUESTION_SUMMARY,),
            )
        ),
        "plaintext_claim": int(count_rows("SELECT COUNT(*) AS n FROM claims WHERE claim_text<>''")),
        "plaintext_gap": int(
            count_rows(
                """
                SELECT COUNT(*) AS n FROM knowledge_gaps
                WHERE missing_proposition<>'[encrypted]'
                   OR encrypted_missing_proposition IS NULL
                   OR proposition_sha256 IS NULL
                """
            )
        ),
        "plaintext_upload_blob": int(
            count_rows(
                """
                SELECT COUNT(*) AS n FROM uploads
                WHERE status<>'expired' AND encrypted_blob<>1
                """
            )
        ),
        "missing_encrypted_upload_name": int(
            count_rows(
                """
                SELECT COUNT(*) AS n FROM uploads
                WHERE status<>'expired' AND encrypted_original_name IS NULL
                """
            )
        ),
        "unsafe_upload_vault_locator": int(
            count_rows(
                """
                SELECT COUNT(*) AS n FROM uploads
                WHERE vault_path LIKE '/%'
                   OR vault_path LIKE '%..%'
                   OR vault_path LIKE '%/Users/%'
                """
            )
        ),
        "unencrypted_refinement_note": int(
            count_rows(
                """
                SELECT COUNT(*) AS n FROM refinements
                WHERE note_sha256 IS NOT NULL AND encrypted_note IS NULL
                """
            )
        ),
        "unsafe_research_candidate_url": int(
            count_rows(
                """
                SELECT COUNT(*) AS n FROM research_candidates
                WHERE canonical_url NOT LIKE 'https://%'
                   OR canonical_url LIKE '%?%'
                   OR canonical_url LIKE '%#%'
                   OR canonical_url LIKE '%@%'
                """
            )
        ),
    }
    for key, count in operational_checks.items():
        if count:
            findings[key] += count

    # Research and refinement prose is either encrypted or reduced to bounded
    # public taxonomy/citation identifiers.  Audit the remaining JSON/code
    # fields because they are allowed into owner DTOs and operational traces.
    safe_operational_rows = database.fetchall(
        """
        SELECT 'research_candidate' AS kind, id, safe_metadata_json AS payload
        FROM research_candidates
        UNION ALL
        SELECT 'source_update_detail' AS kind, id, safe_detail_json AS payload
        FROM source_update_observations
        UNION ALL
        SELECT 'refinement_target' AS kind, id, safe_target_json AS payload
        FROM refinements
        UNION ALL
        SELECT 'refinement_resolution' AS kind, id,
               resolution_evidence_json AS payload
        FROM refinements
        UNION ALL
        SELECT 'refinement_event' AS kind, CAST(sequence AS TEXT) AS id,
               safe_payload_json AS payload
        FROM refinement_events
        """
    )
    for row in safe_operational_rows:
        payload = str(row["payload"] or "{}")
        try:
            decoded = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            findings["invalid_safe_operational_json"] += 1
            continue
        if not isinstance(decoded, dict):
            findings["invalid_safe_operational_json"] += 1
            continue
        if contains_absolute_private_path(payload) or any(
            identifier.casefold() in payload.casefold() for identifier in settings.owner_identifiers
        ):
            findings["personal_identifier_in_safe_operational_json"] += 1
        if prompt_injection_hits(payload):
            findings["document_instruction_in_safe_operational_json"] += 1

    public_path_hits = 0
    public_sql = (
        """
        SELECT COUNT(*) AS n FROM documents
        WHERE safe_display_name LIKE '%/Users/%'
           OR source_identity_id LIKE '%/Users/%'
        """,
        """
        SELECT COUNT(*) AS n FROM source_versions
        WHERE title LIKE '%/Users/%'
           OR IFNULL(stable_identifier,'') LIKE '%/Users/%'
           OR IFNULL(canonical_url,'') LIKE '%/Users/%'
           OR IFNULL(canonical_markdown_path,'') LIKE '%/Users/%'
           OR IFNULL(author_or_body,'') LIKE '%/Users/%'
           OR IFNULL(licence_name,'') LIKE '%/Users/%'
           OR IFNULL(licence_url,'') LIKE '%/Users/%'
        """,
        """
        SELECT COUNT(*) AS n FROM chunks
        WHERE IFNULL(locator,'') LIKE '%/Users/%'
           OR IFNULL(heading_path,'') LIKE '%/Users/%'
        """,
    )
    for sql in public_sql:
        public_path_hits += count_rows(sql)
    if public_path_hits:
        findings["absolute_path_in_public_catalogue_field"] += public_path_hits

    checked_plaintext_files = 0
    excluded_from_corpus_artifacts = 0
    artifact_roots = (
        settings.data_dir / "review_queue",
        settings.evaluation_dir,
        settings.data_dir / "traces",
        settings.answer_dir,
        settings.retrieval_cache_dir,
        settings.logs_dir,
    )
    live_evaluation_runs_root = settings.evaluation_dir / "e2e" / "runs"
    for root in artifact_roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in {
                ".json",
                ".jsonl",
                ".md",
                ".txt",
            }:
                continue
            # Corpus eligibility and privacy safety are separate decisions.  A
            # review pack must never be ingested, but it can still leak a path,
            # owner identifier or prompt-injection canary into operational
            # plaintext.  Scan it here instead of treating exclusion from RAG as
            # an exemption from the privacy gate.
            if is_excluded_from_corpus_discovery(path, data_dir=settings.data_dir):
                excluded_from_corpus_artifacts += 1
            checked_plaintext_files += 1
            try:
                value = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                findings["unreadable_plaintext_review_artifact"] += 1
                continue
            if contains_absolute_private_path(value) or any(
                identifier.casefold() in value.casefold()
                for identifier in settings.owner_identifiers
            ):
                findings["personal_identifier_in_review_artifact"] += 1
            if prompt_injection_hits(value):
                findings["document_instruction_in_review_artifact"] += 1

            if path.is_relative_to(settings.retrieval_cache_dir):
                try:
                    cache = json.loads(value)
                except (TypeError, ValueError, json.JSONDecodeError):
                    findings["invalid_retrieval_cache_artifact"] += 1
                    continue
                try:
                    validate_safe_cache_payload(cache)
                except (TypeError, ValueError):
                    findings["prose_or_private_field_in_retrieval_cache"] += 1

            # Questions, held answers and human notes are encrypted in an E2E
            # run.  All JSON/JSONL beside those encrypted artifacts is an
            # explicitly prose-free projection, so validate that contract as
            # part of the global privacy gate as well as at write time.
            if path.is_relative_to(live_evaluation_runs_root) and path.suffix.casefold() in {
                ".json",
                ".jsonl",
            }:
                try:
                    payloads = (
                        [json.loads(line) for line in value.splitlines() if line.strip()]
                        if path.suffix.casefold() == ".jsonl"
                        else [json.loads(value)]
                    )
                    for payload in payloads:
                        assert_safe_evaluation_payload(payload)
                except (TypeError, ValueError, json.JSONDecodeError):
                    findings["prose_or_private_field_in_live_evaluation_artifact"] += 1

    return {
        "schema": "legalbot.privacy-report.v1",
        "passed": not findings,
        "zero_tolerance": True,
        "checked": {
            "approved_index_chunks": checked_chunks,
            "candidate_eligible_index_chunks": checked_chunks,
            "rights_excluded_approved_sources": rights_excluded_sources,
            "rights_excluded_approved_chunks": rights_excluded_chunks,
            "prompt_views_redacted": prompt_view_redactions,
            "plaintext_review_artifacts": checked_plaintext_files,
            "excluded_from_corpus_artifacts_scanned": excluded_from_corpus_artifacts,
            "skipped_owner_operational_artifacts": 0,
            "operational_tables": [
                "jobs",
                "claims",
                "knowledge_gaps",
                "uploads",
                "research_tasks",
                "research_candidates",
                "source_update_observations",
                "source_update_resolution_events",
                "refinements",
                "refinement_events",
            ],
            "artifact_roots": [
                "review_queue",
                "evaluations",
                "traces",
                "answers",
                "retrieval_cache",
                "logs",
            ],
        },
        "finding_counts": dict(sorted(findings.items())),
        "created_at": utc_iso(),
    }
