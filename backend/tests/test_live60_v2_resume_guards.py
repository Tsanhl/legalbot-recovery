from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.db import utc_iso
from app.evaluation.live_runtime_separation import (
    derive_evaluation_candidate_state,
    ordinary_live_smoke_uses_active,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.live_suite_hold_taxonomy import (
    classify_hold_queue,
    issue_state_review_complete,
)
from app.evaluation.live_suite_overlay_complete import overlay_complete_v2
from app.evaluation.live_suite_owner_adjudication import (
    build_owner_adjudication_pack,
    require_adjudication_confirmation,
)
from app.evaluation.live_suite_production_promotion import (
    require_live60_production_attestation,
)
from app.evaluation.live_suite_semantic_resume import resume_semantic_hold
from app.evaluation.live_suite_source_version_pack import (
    apply_source_version_decision_pack,
    build_source_version_decision_pack,
    confirmation_token,
)
from app.evaluation.live_suite_stage_a_v2 import score_stage_a_v2
from app.evaluation.live_suite_status_artifact import build_live60_v2_status
from app.ingestion.scan_attestation import (
    build_scan_attestation,
    latest_complete_reconciled_scan,
    selected_sources_exclude_quarantine,
)
from app.retrieval.diagnostic_slice import (
    DIAGNOSTIC_SLICE_BUILD_ID,
    bind_current_candidate_build_id,
    refuse_diagnostic_slice_for_production,
)
from app.retrieval.index_build import IndexBuildConflictError, enqueue_index_build
from app.retrieval.service import promote_candidate_index
from app.retrieval.source_manifest import (
    build_approved_source_manifest,
    is_current_law_full_corpus,
    is_current_law_slice_corpus,
    select_approved_authority_rows,
)


def _insert_build(database: Any, build_id: str, status: str = "building") -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at
        ) VALUES (?, ?, ?, 0, 0, 0, 'test-embed', 'test-rerank', ?)
        """,
        (build_id, status, f"data/indexes/{build_id}", now),
    )


def _write_scan(
    database: Any,
    tmp_path: Path,
    scan_id: str,
    *,
    expected: int,
    accounted: int,
    complete: bool,
    quarantine: int = 0,
) -> None:
    root = tmp_path / scan_id
    root.mkdir(parents=True, exist_ok=True)
    descriptors = database.create_source_scan(scan_id, (root,))
    database.start_source_scan(scan_id, roots_seen=descriptors, expected_file_count=expected)
    for index in range(accounted):
        quarantined = index < quarantine
        database.record_source_scan_file(
            scan_id,
            path_fingerprint=f"{index:064x}",
            document_id=None,
            status="quarantined" if quarantined else "citable",
            content_sha256=f"{index + 1:064x}",
            reason="processing_policy_rollback_refused" if quarantined else None,
        )
    if complete:
        database.complete_source_scan(scan_id)
    else:
        database.fail_source_scan(
            scan_id,
            error_code="RuntimeError",
            error_message="Source scan failed; durable accounting is available for resume",
        )


def _semantic_record(*, result: str, seal: str = "a" * 64) -> dict[str, Any]:
    nested = {
        "schema": "legalbot.semantic-verification-result.v2",
        "result": result,
        "claims_supported": result in {"supported", "limited"},
        "unsupported_claim_count": 0 if result in {"supported", "limited"} else 1,
        "contradiction_count": 1 if result == "unsupported" else 0,
        "seal_sha256": seal,
    }
    return {
        "row_id": "live30-q06:issue-07",
        "issue_id": "issue-07",
        "exact_gold_spans": [{"chunk_id": "chunk-1"}],
        "semantic_result": nested,
    }


def _attestation(candidate_build_id: str) -> dict[str, Any]:
    payload = {
        "schema": "legalbot.production-promotion-attestation.v2",
        "candidate_build_id": candidate_build_id,
        "candidate_seal_sha256": "1" * 64,
        "evaluation_run_id": "eval-run-01",
        "evaluation_aggregate_sha256": "2" * 64,
        "answer_quality_passed": True,
        "privacy_security_passed": True,
        "required_readiness_passed": True,
        "rollback_canary_required": False,
        "operator_deployment_authorization": "operator:" + ("3" * 64),
        "policy_version": "v1",
        "writes_active": True,
        "legal_evidence_review_is_not_deployment": True,
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    return payload


def test_failed_unreconciled_scan_cannot_override_later_complete_scan(
    database: Any, tmp_path: Path
) -> None:
    _write_scan(database, tmp_path, "failed-3429", expected=3, accounted=2, complete=False)
    _write_scan(
        database,
        tmp_path,
        "complete-3581",
        expected=3,
        accounted=3,
        complete=True,
        quarantine=1,
    )
    latest = latest_complete_reconciled_scan(database)
    assert latest is not None
    assert latest["scan_id"] == "complete-3581"
    assert latest["expected_file_count"] == latest["files_accounted"] == 3
    attestation = build_scan_attestation(database, scan_id="complete-3581")
    assert attestation["quarantine_count"] == 1
    assert "failed-3429" in attestation["superseded_scan_ids"]
    with pytest.raises(ValueError, match="latest complete"):
        build_scan_attestation(database, scan_id="failed-3429")


def test_completed_scan_may_include_quarantined_files(database: Any, tmp_path: Path) -> None:
    _write_scan(
        database, tmp_path, "with-quarantine", expected=2, accounted=2, complete=True, quarantine=1
    )
    latest = latest_complete_reconciled_scan(database)
    assert latest is not None
    assert latest["scan_id"] == "with-quarantine"


def test_quarantined_sources_are_excluded_from_selection_and_index_lanes(
    database: Any, tmp_path: Path
) -> None:
    now = utc_iso()
    markdown = tmp_path / "data" / "vault" / "source.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("# Act\n\nSection 1.", encoding="utf-8")
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-ok', ?, 'ukpga:1977:50', 'ok.pdf', 'application/pdf',
                  'citable', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-q', ?, 'ukpga:1977:51', 'q.pdf', 'application/pdf',
                  'quarantined', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("b" * 64, now, now),
    )
    for doc_id, version_id, ident, sha in (
        ("doc-ok", "sv-ok", "ukpga:1977:50:enacted", "a" * 64),
        ("doc-q", "sv-q", "ukpga:1977:51:enacted", "b" * 64),
    ):
        database.execute(
            """
            INSERT INTO source_versions(
              id, document_id, version_sha256, canonical_markdown_path, title,
              stable_identifier, currentness_status, licence_name, review_status,
              metadata_json, created_at
            ) VALUES (?, ?, ?, ?, 'Act', ?, 'historical', 'Open Government Licence v3.0',
                      'approved', ?, ?)
            """,
            (
                version_id,
                doc_id,
                sha,
                "data/vault/source.md",
                ident,
                json.dumps({"eligible_for_model_use": True, "ai_use_policy": "unreviewed"}),
                now,
            ),
        )
        database.execute(
            """
            INSERT INTO chunks(
              id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count, stream
            ) VALUES (?, ?, 0, 's 1', ?, 'Section 1.', 4, 'body')
            """,
            (f"chunk-{version_id}", version_id, sha),
        )
    settings = Settings(project_root=tmp_path, test_mode=True)
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0", "url": "x"},
                "items": [
                    {"identity": "ukpga/1977/50", "title": "Unfair Contract Terms Act 1977"},
                    {"identity": "ukpga/1977/51", "title": "Quarantined"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0"},
                "items": [],
            }
        ),
        encoding="utf-8",
    )
    rows = select_approved_authority_rows(database, settings, corpus_id="test-corpus")
    assert {row["source_version_id"] for row in rows} == {"sv-ok"}
    selected_sources_exclude_quarantine(rows)
    with pytest.raises(ValueError, match="quarantined source versions"):
        selected_sources_exclude_quarantine(
            [{"source_version_id": "sv-q", "document_status": "quarantined"}]
        )


def test_running_diagnostic_build_is_not_duplicated(database: Any, tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    _insert_build(database, DIAGNOSTIC_SLICE_BUILD_ID, status="building")
    with pytest.raises(IndexBuildConflictError, match="diagnostic slice"):
        enqueue_index_build(
            settings,
            database,
            corpus_id="test-corpus",
            build_id=DIAGNOSTIC_SLICE_BUILD_ID,
            skip_embedding=True,
        )
    database.execute("DELETE FROM index_builds WHERE id=?", (DIAGNOSTIC_SLICE_BUILD_ID,))
    _insert_build(database, DIAGNOSTIC_SLICE_BUILD_ID, status="built_unscored")
    with pytest.raises(IndexBuildConflictError, match="diagnostic slice"):
        enqueue_index_build(
            settings,
            database,
            corpus_id="test-corpus",
            build_id=DIAGNOSTIC_SLICE_BUILD_ID,
            skip_embedding=True,
        )


def test_diagnostic_slice_cannot_be_production_promoted(database: Any, tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, test_mode=True)
    _insert_build(database, DIAGNOSTIC_SLICE_BUILD_ID, status="candidate")
    with (
        pytest.raises(ValueError, match="diagnostic slice"),
        patch("app.evaluation.owner_quality_v111_promotion.verify_v111_promotion_for_service"),
    ):
        promote_candidate_index(
            settings,
            database,
            DIAGNOSTIC_SLICE_BUILD_ID,
            v111_promotion_presentation=object(),
            v111_owner_authorization=object(),
        )
    with pytest.raises(ValueError, match="diagnostic slice"):
        refuse_diagnostic_slice_for_production(
            DIAGNOSTIC_SLICE_BUILD_ID, purpose="production-promotion attestation"
        )


def test_hold_count_is_derived_not_hard_coded() -> None:
    issues = [
        {
            "row_id": f"live30-q02:issue-{index:02d}",
            "case_id": "live30-q02",
            "issue_id": f"issue-{index:02d}",
            "disposition": "qualified" if index < 2 else "pending_official_materialisation",
            "status": "qualified" if index < 2 else "HOLD",
            "final_verification_status": "VERIFIED" if index < 2 else "HOLD",
            "exact_gold_spans": [{"chunk_id": f"chunk-{index}"}] if index < 2 else [],
            "semantic_result_seal_sha256": "c" * 64 if index < 2 else "",
            "invented_span": False,
        }
        for index in range(5)
    ]
    taxonomy = classify_hold_queue(
        issues,
        semantic_checkpoints={
            "live30-q02:issue-02": _semantic_record(result="unsupported"),
        },
        pending_approval_row_ids={"live30-q02:issue-03", "live30-q02:issue-04"},
    )
    assert taxonomy["hard_coded_hold_count"] is False
    assert taxonomy["selected_total"] == 5
    assert taxonomy["verified_qualified"] == 2
    assert taxonomy["semantic_hold"] == 1
    assert taxonomy["official_source_version_approval_pending"] == 2
    assert taxonomy["total_hold"] == 3
    assert taxonomy["total_hold"] != 93
    held = classify_hold_queue(
        issues,
        owner_held_source_version_row_ids={"live30-q02:issue-03", "live30-q02:issue-04"},
    )
    assert held["source_effects_hold"] == 2
    assert held["owner_held_source_version"] == 0
    assert held["official_source_version_approval_pending"] == 0
    assert held["total_hold"] == 3
    pending = classify_hold_queue(
        [
            {
                "row_id": "live30-q02:issue-09",
                "case_id": "live30-q02",
                "issue_id": "issue-09",
                "disposition": "HOLD",
                "status": "HOLD",
                "final_verification_status": "HOLD",
                "exact_gold_spans": [{"chunk_id": "chunk-9"}],
                "gap_reason": "source_admitted_semantic_pending",
                "invented_span": False,
            },
            {
                "row_id": "live30-q23:issue-05",
                "case_id": "live30-q23",
                "issue_id": "issue-05",
                "disposition": "HOLD",
                "status": "HOLD",
                "final_verification_status": "HOLD",
                "exact_gold_spans": [],
                "gap_reason": "source_admission_operator_hold",
                "invented_span": False,
            },
            {
                "row_id": "live30-q24:issue-02",
                "case_id": "live30-q24",
                "issue_id": "issue-02",
                "disposition": "HOLD",
                "status": "HOLD",
                "final_verification_status": "HOLD",
                "exact_gold_spans": [],
                "gap_reason": "source_admission_rejected",
                "invented_span": False,
            },
        ]
    )
    assert pending["source_admitted_semantic_pending"] == 1
    assert pending["source_effects_hold"] == 1
    assert pending["source_admission_rejected"] == 1
    assert pending["source_identity_or_hash_failure"] == 0
    assert pending["other_hold"] == 0
    assert pending["owner_confirmation_required"] is False


def test_semantic_hold_resume_is_idempotent_and_cannot_force_verified() -> None:
    record = _semantic_record(result="unsupported", seal="d" * 64)
    first = resume_semantic_hold(record)
    second = resume_semantic_hold(record)
    assert first["resumed"] is True
    assert first["final_verification_status"] == "HOLD"
    assert first["seal_sha256"] == second["seal_sha256"]
    with pytest.raises(ValueError, match="cannot be forced to VERIFIED"):
        resume_semantic_hold(record, force_verified=True)


def test_source_version_pack_is_digest_bound_and_token_invalidates_on_change() -> None:
    pack = build_source_version_decision_pack(
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        catalogue_state_sha256="f" * 64,
        as_of_date="2026-08-17",
        decisions=[
            {
                "decision_id": "svd-001",
                "source_version_id": "sv-1",
                "stable_source_id": "ukpga:2015:15",
                "recommended_decision": "HOLD",
                "reason_codes": ["operator_source_approval_required"],
                "affected_row_ids": ["live30-q02:issue-09"],
            }
        ],
    )
    token = confirmation_token(str(pack["pack_sha256"]))
    assert token == pack["confirmation_token"]
    applied = apply_source_version_decision_pack(pack, confirmation_token_value=token)
    assert applied["applied"] is True
    assert applied["operator_confirmed"] is True
    assert applied["operator_decision_counts"] == {"APPROVE": 0, "REJECT": 0, "HOLD": 1}
    assert applied["issue_gold_minted"] is False
    assert applied["sources_indexed"] is False
    changed = {**pack, "as_of_date": "2026-08-18"}
    with pytest.raises(ValueError, match="does not match"):
        apply_source_version_decision_pack(changed, confirmation_token_value=token)
    approve_pack = build_source_version_decision_pack(
        code_sha="e" * 64,
        scan_id="a6200da832c587e7",
        catalogue_state_sha256="f" * 64,
        as_of_date="2026-08-17",
        decisions=[
            {
                "decision_id": "svd-002",
                "source_version_id": None,
                "stable_source_id": "ukpga:2015:15",
                "recommended_decision": "APPROVE",
                "affected_row_ids": ["live30-q02:issue-09"],
            }
        ],
    )
    with pytest.raises(ValueError, match="source_version_id"):
        apply_source_version_decision_pack(
            approve_pack, confirmation_token_value=approve_pack["confirmation_token"]
        )


def test_issue_state_cannot_report_review_complete_while_hold_remains() -> None:
    assert issue_state_review_complete(hold_count=93, unreviewed_count=0) is False
    assert (
        derive_evaluation_candidate_state(
            candidate_build_present=True,
            unreviewed_issue_count=0,
            hold_issue_count=93,
            review_complete=True,
        )
        == "EVIDENCE_REVIEW"
    )
    overlay = overlay_complete_v2(
        selected_issues=[
            {
                "row_id": "live30-q02:issue-01",
                "case_id": "live30-q02",
                "issue_id": "issue-01",
                "disposition": "HOLD",
                "status": "HOLD",
                "final_verification_status": "HOLD",
                "exact_gold_spans": [],
            }
        ],
        selected_issue_count=1,
        selected_case_count=1,
        enforce_frozen_identities=False,
    )
    assert overlay["review_overlay_complete"] is False
    assert overlay["unreviewed_issue_count"] == 1


def test_full_candidate_rejects_incomplete_scan_and_quarantine_leak(
    database: Any, tmp_path: Path
) -> None:
    assert is_current_law_full_corpus("current-law-ew-full-fp16-v111-20260817-a") is True
    assert is_current_law_slice_corpus("current-law-ew-full-fp16-v111-20260817-a") is False
    _write_scan(database, tmp_path, "failed-only", expected=2, accounted=1, complete=False)
    settings = Settings(project_root=tmp_path, test_mode=True)
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0", "url": "x"},
                "items": [{"identity": "ukpga/1977/50", "title": "Unfair Contract Terms Act 1977"}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0"},
                "items": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="incomplete scan"):
        build_approved_source_manifest(
            database, settings, corpus_id="current-law-ew-full-fp16-v111-20260817-a"
        )


def test_full_candidate_accepts_reconciled_scan_and_excludes_quarantine(
    database: Any, tmp_path: Path
) -> None:
    _write_scan(
        database,
        tmp_path,
        "complete-with-quarantine",
        expected=2,
        accounted=2,
        complete=True,
        quarantine=1,
    )
    now = utc_iso()
    markdown = tmp_path / "data" / "vault" / "source.md"
    markdown.parent.mkdir(parents=True)
    markdown.write_text("# Act\n\nSection 1.", encoding="utf-8")
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-ok', ?, 'ukpga:1977:50', 'ok.pdf', 'application/pdf',
                  'citable', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("a" * 64, now, now),
    )
    database.execute(
        """
        INSERT INTO documents(
          id, content_sha256, source_identity_id, safe_display_name, media_type,
          status, lane, subject_primary, jurisdiction, retrieval_canonical,
          created_at, updated_at
        ) VALUES ('doc-q', ?, 'ukpga:1977:51', 'q.pdf', 'application/pdf',
                  'quarantined', 'primary_authority', 'contract', 'England and Wales', 1, ?, ?)
        """,
        ("b" * 64, now, now),
    )
    for doc_id, version_id, ident, sha in (
        ("doc-ok", "sv-ok", "ukpga:1977:50:enacted", "a" * 64),
        ("doc-q", "sv-q", "ukpga:1977:51:enacted", "b" * 64),
    ):
        database.execute(
            """
            INSERT INTO source_versions(
              id, document_id, version_sha256, canonical_markdown_path, title,
              stable_identifier, currentness_status, licence_name, review_status,
              metadata_json, created_at
            ) VALUES (?, ?, ?, ?, 'Act', ?, 'historical', 'Open Government Licence v3.0',
                      'approved', ?, ?)
            """,
            (
                version_id,
                doc_id,
                sha,
                "data/vault/source.md",
                ident,
                json.dumps({"eligible_for_model_use": True, "ai_use_policy": "unreviewed"}),
                now,
            ),
        )
        database.execute(
            """
            INSERT INTO chunks(
              id, source_version_id, ordinal, locator, text_sha256, markdown_text, token_count, stream
            ) VALUES (?, ?, 0, 's 1', ?, 'Section 1.', 4, 'body')
            """,
            (f"chunk-{version_id}", version_id, sha),
        )
    settings = Settings(project_root=tmp_path, test_mode=True)
    (tmp_path / "config").mkdir(exist_ok=True)
    (tmp_path / "config" / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0", "url": "x"},
                "items": [
                    {"identity": "ukpga/1977/50", "title": "Unfair Contract Terms Act 1977"},
                    {"identity": "ukpga/1977/51", "title": "Quarantined"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "config" / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "licence": {"name": "Open Government Licence", "version": "3.0"},
                "items": [],
            }
        ),
        encoding="utf-8",
    )
    manifest = build_approved_source_manifest(
        database, settings, corpus_id="current-law-ew-full-fp16-v111-20260817-a"
    )
    assert manifest["source_scan_id"] == "complete-with-quarantine"
    assert manifest["source_scan_reconciled"] is True
    selected = {item["source_version_id"] for item in manifest["sources"]}
    assert "sv-ok" in selected
    assert "sv-q" not in selected
    assert all(item["document_status"] == "citable" for item in manifest["sources"])


def test_current_pointer_and_stage_a_reject_diagnostic_slice() -> None:
    with pytest.raises(ValueError, match="CURRENT.candidate_build_id"):
        bind_current_candidate_build_id({}, DIAGNOSTIC_SLICE_BUILD_ID)
    bound = bind_current_candidate_build_id({}, None)
    assert bound["candidate_build_id"] is None
    bound["diagnostic_slice_build_id"] = DIAGNOSTIC_SLICE_BUILD_ID
    with pytest.raises(ValueError, match="production Stage A"):
        score_stage_a_v2(
            issues=[],
            unreviewed_issue_count=93,
            candidate_build_id=DIAGNOSTIC_SLICE_BUILD_ID,
            rankings=[],
        )


def test_production_attestation_rejects_diagnostic_and_mismatched_candidate(
    tmp_path: Path,
) -> None:
    settings = Settings(
        project_root=tmp_path,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        test_mode=True,
    )
    with pytest.raises(ValueError, match="diagnostic slice"):
        require_live60_production_attestation(
            settings=settings,
            build_id=DIAGNOSTIC_SLICE_BUILD_ID,
            attestation=_attestation(DIAGNOSTIC_SLICE_BUILD_ID),
        )
    with pytest.raises(ValueError, match="different candidate"):
        require_live60_production_attestation(
            settings=settings,
            build_id="current-law-ew-full-fp16-v111-20260817-a",
            attestation=_attestation("current-law-ew-full-fp16-v111-20260817-b"),
        )


def test_github_safe_status_rejects_private_paths() -> None:
    with pytest.raises(ValueError, match="sensitive"):
        build_live60_v2_status({"scan_id": "a6200da832c587e7", "note": "/Users/owner/secret"})
    status = build_live60_v2_status(
        {
            "scan_id": "a6200da832c587e7",
            "expected_file_count": 3581,
            "accounted_file_count": 3581,
            "quarantine_count": 75,
            "hold": 93,
        }
    )
    assert status["schema"] == "legalbot.live60-v2-status.v1"
    assert "/Users/" not in json.dumps(status)
    assert "status_publisher_sha" not in status
    assert status["publisher_identity"] == "containing_git_commit"


def test_ordinary_live_smoke_requires_active() -> None:
    with pytest.raises(ValueError, match="requires ACTIVE"):
        ordinary_live_smoke_uses_active(active_build_id=None, job_pinned_build_id="x")
    with pytest.raises(ValueError, match="must pin ACTIVE"):
        ordinary_live_smoke_uses_active(
            active_build_id="active-1",
            job_pinned_build_id=DIAGNOSTIC_SLICE_BUILD_ID,
        )
    from app.retrieval.diagnostic_slice import allowed_index_statuses_for_pin

    assert "built_unscored" in allowed_index_statuses_for_pin(DIAGNOSTIC_SLICE_BUILD_ID)
    assert "built_unscored" not in allowed_index_statuses_for_pin(
        "current-law-ew-full-fp16-v111-20260818-a"
    )


def test_first_live_torch_retrieval_stays_on_cpu(monkeypatch: Any) -> None:
    from app.retrieval.service import _preferred_torch_device, _torch_retrieval_device_name

    monkeypatch.setenv("LEGALBOT_LIVE_PROFILE", "first_live_local_only")
    monkeypatch.delenv("LEGALBOT_TORCH_DEVICE", raising=False)
    assert _torch_retrieval_device_name() == "cpu"

    class _Torch:
        @staticmethod
        def device(name: str) -> str:
            return name

    assert _preferred_torch_device(_Torch) == "cpu"
    monkeypatch.setenv("LEGALBOT_TORCH_DEVICE", "mps")
    assert _torch_retrieval_device_name() == "mps"


def test_diagnostic_runtime_uses_pinned_verification() -> None:
    import inspect

    from app.retrieval.service import HybridRetrievalService

    boundary_source = inspect.getsource(HybridRetrievalService._open_retrieval_boundary)
    verification_source = inspect.getsource(HybridRetrievalService._ensure_verified_build)
    assert "_ensure_verified_build(" in boundary_source
    assert "_verify_pinned_build(" in verification_source
    assert "_verify_sealed_build(" not in verification_source


def test_owner_adjudication_pack_token_is_digest_bound() -> None:
    pack = build_owner_adjudication_pack(
        code_sha="a" * 64,
        scan_id="a6200da832c587e7",
        as_of_date="2026-08-17",
        rows=[
            {
                "row_id": "live30-q06:issue-07",
                "ai_recommendation": "KEEP_HOLD",
                "choices": ["QUALIFIED", "LIMITED", "KNOWLEDGE_GAP", "KEEP_HOLD"],
            }
        ],
    )
    require_adjudication_confirmation(pack, pack["confirmation_token"])
    with pytest.raises(ValueError, match="does not match"):
        require_adjudication_confirmation(pack, "CONFIRM_OWNER_ADJUDICATION:" + ("0" * 64))
