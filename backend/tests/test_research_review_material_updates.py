from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import date
from pathlib import Path

import pytest

from app.config import Settings
from app.db import Database, utc_iso
from app.quality.evaluator import QualityEvaluator
from app.quality.evidence import evidence_span_eligible_for_drafting
from app.research.material_updates import MaterialUpdateGate
from app.research.review import ResearchReviewService
from app.retrieval.lancedb import ImmutableLanceRepository
from app.retrieval.source_manifest import approved_source_manifest_sha256
from app.types import (
    EvidenceSpan,
    StructuredClaimDraft,
    StructuredDraft,
    StructuredSectionDraft,
    TaskType,
)


def _enqueue(database: Database, task_id: str = "research-review-1") -> None:
    database.enqueue_research_task(
        task_id=task_id,
        idempotency_key=f"idem-{task_id}",
        task_type="source_update_check",
        trigger_kind="manual",
        priority_band="high",
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date="2026-08-15",
        query_sha256=hashlib.sha256(task_id.encode()).hexdigest(),
    )


def _bind_authority(database: Database, evidence: EvidenceSpan) -> str:
    authority_id = "ukpga:2026:1"
    database.execute(
        """
        UPDATE source_versions SET authority_identity_id=?, stable_identifier=?
        WHERE id=?
        """,
        (authority_id, authority_id, evidence.source_version_id),
    )
    return authority_id


def _observe(
    database: Database,
    authority_id: str,
    *,
    observation_id: str,
    task_id: str = "research-review-1",
    pinned_build_id: str | None = None,
    stale_active: bool = False,
) -> None:
    database.add_source_update_observation(
        observation_id=observation_id,
        task_id=task_id,
        source_id="legislation_gov_uk",
        authority_identity_id=authority_id,
        comparison_state="changed",
        pinned_index_build_id=pinned_build_id,
        observed_active_build_id=pinned_build_id,
        baseline_version_sha256="a" * 64,
        remote_content_sha256="d" * 64,
        stale_active=stale_active,
        safe_detail={
            "recompare_required": stale_active,
            "change_summary_code": "official_bytes_changed",
        },
    )


def test_candidate_owner_contract_is_safe_and_hands_off_only_to_source_intake(
    tmp_path: Path, database: Database
) -> None:
    _enqueue(database)
    database.add_research_candidate(
        candidate_id="candidate-owner-review",
        task_id="research-review-1",
        source_id="legislation_gov_uk",
        source_identity="ukpga/2026/1",
        canonical_url="https://www.legislation.gov.uk/ukpga/2026/1",
        content_sha256="a" * 64,
        metadata_sha256="b" * 64,
        content_object_key=None,
        safe_metadata={
            "content_type": "application/xml",
            "disposition": "staged_only",
            "network_fetch": "official_allowlist",
        },
    )
    service = ResearchReviewService(Settings(project_root=tmp_path, test_mode=True), database)
    candidate = service.candidates()[0]
    safe = dataclasses.asdict(candidate)
    assert "canonical_url" not in safe
    assert "content_object_key" not in safe
    assert "safe_metadata_json" not in safe

    with pytest.raises(RuntimeError, match="system verification"):
        service.review_candidate(
            candidate.id,
            decision="accept_for_source_intake",
            rights_state="verified",
            identity_review_state="candidate_matched",
            currentness_review_state="requires_source_review",
            reviewer_ref=f"reviewer:{'c' * 64}",
            review_manifest_sha256="d" * 64,
        )

    database.execute(
        "UPDATE research_tasks SET status='review_required' WHERE id='research-review-1'"
    )
    system_seal = service.system_verify_candidate(candidate.id)
    assert len(system_seal) == 64
    intake_review_id = service.review_candidate(
        candidate.id,
        decision="accept_for_source_intake",
        rights_state="verified",
        identity_review_state="candidate_matched",
        currentness_review_state="verified",
        reviewer_ref=f"reviewer:{'c' * 64}",
        review_manifest_sha256="d" * 64,
    )
    assert intake_review_id == "review-research-intake-candidate-owner-review"
    intake = database.fetchone("SELECT * FROM reviews WHERE id=?", (intake_review_id,))
    assert intake is not None
    assert intake["review_type"] == "research_source_intake"
    assert intake["status"] == "pending"
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM index_builds")["n"] == 0


def test_raw_change_alerts_but_only_reviewed_material_update_blocks(
    database: Database, evidence: EvidenceSpan
) -> None:
    _enqueue(database)
    authority_id = _bind_authority(database, evidence)
    _observe(database, authority_id, observation_id="update-raw")

    raw = MaterialUpdateGate(database).assess(evidence)
    assert raw.qualified
    assert raw.pending_alert_ids == ("update-raw",)
    assert evidence_span_eligible_for_drafting(
        evidence, as_of_date=date(2026, 8, 15), database=database
    )

    database.record_source_update_review(
        "update-raw",
        review_id="review-update-material",
        review_status="approved",
        materiality_status="material",
        reviewer_ref=f"reviewer:{'e' * 64}",
        review_manifest_sha256="f" * 64,
    )
    reviewed = MaterialUpdateGate(database).assess(evidence)
    assert not reviewed.qualified
    assert reviewed.blocked_observation_ids == ("update-raw",)
    assert not evidence_span_eligible_for_drafting(
        evidence,
        as_of_date=date(2026, 8, 15),
        database=database,
    )


def test_proposition_scope_is_exact_and_unknown_review_fails_closed(
    database: Database, evidence: EvidenceSpan
) -> None:
    _enqueue(database)
    authority_id = _bind_authority(database, evidence)
    _observe(database, authority_id, observation_id="update-proposition")
    proposition_hash = "1" * 64
    database.record_source_update_review(
        "update-proposition",
        review_id="review-update-proposition",
        review_status="approved",
        materiality_status="unknown",
        reviewer_ref=f"reviewer:{'2' * 64}",
        review_manifest_sha256="3" * 64,
        scope_kind="proposition",
        legal_locator=evidence.locator,
        proposition_sha256=proposition_hash,
    )
    gate = MaterialUpdateGate(database)
    assert not gate.assess(evidence).qualified
    assert not gate.assess(evidence, proposition_hash=proposition_hash).qualified
    assert gate.assess(evidence, proposition_hash="4" * 64).qualified
    assert gate.assess(
        evidence.model_copy(update={"locator": "s 2"}),
        proposition_hash=proposition_hash,
    ).qualified


def test_frozen_evidence_release_gate_rechecks_reviewed_material_update(
    database: Database, evidence: EvidenceSpan
) -> None:
    _enqueue(database)
    authority_id = _bind_authority(database, evidence)
    _observe(database, authority_id, observation_id="update-after-freeze")
    database.record_source_update_review(
        "update-after-freeze",
        review_id="review-update-after-freeze",
        review_status="approved",
        materiality_status="material",
        reviewer_ref=f"reviewer:{'a' * 64}",
        review_manifest_sha256="b" * 64,
    )
    claim_text = "The verified statutory proposition is the applicable current rule."
    draft = StructuredDraft(
        title="Currentness race test",
        task_type=TaskType.GENERAL,
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 15),
        sections=[
            StructuredSectionDraft(
                id="law",
                heading="Law",
                claims=[
                    StructuredClaimDraft(
                        id="claim-1",
                        text=claim_text,
                        evidence_ids=[evidence.id],
                        material=True,
                    )
                ],
            )
        ],
    )
    report = QualityEvaluator(database).evaluate(
        answer_version_id="answer-update-race",
        draft=draft,
        rendered_text=claim_text,
        evidence_by_id={evidence.id: evidence},
        word_count=100,
        word_target=100,
        rubric_scores={},
    )
    assert not report.evidence_passed
    assert any(finding.code == "reviewed_material_update_unresolved" for finding in report.findings)


def test_resolution_is_append_only_build_bound_and_rollback_reblocks(
    database: Database, evidence: EvidenceSpan
) -> None:
    _enqueue(database)
    authority_id = _bind_authority(database, evidence)
    _observe(
        database,
        authority_id,
        observation_id="update-resolved",
        pinned_build_id="build-1",
    )
    database.record_source_update_review(
        "update-resolved",
        review_id="review-update-resolved",
        review_status="approved",
        materiality_status="material",
        reviewer_ref=f"reviewer:{'5' * 64}",
        review_manifest_sha256="6" * 64,
    )
    now = utc_iso()
    database.execute("UPDATE index_builds SET status='superseded' WHERE id='build-1'")
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,source_manifest_hash,created_at
        ) VALUES ('build-2','active','data/indexes/build-2','embed','rerank',?,?)
        """,
        ("7" * 64, now),
    )
    database.record_source_update_resolution(
        "update-resolved",
        resolution_id="resolution-update-resolved",
        resolved_by_build_id="build-2",
        source_manifest_sha256="7" * 64,
        resolution_kind="updated_authority_included",
        authority_identity_id=authority_id,
        legal_locator=None,
        proposition_sha256=None,
        evidence_sha256="8" * 64,
        reviewer_ref=f"reviewer:{'9' * 64}",
    )
    gate = MaterialUpdateGate(database)
    promoted_span = evidence.model_copy(update={"index_build_id": "build-2"})
    assert gate.assess(promoted_span).qualified
    assert gate.assess(promoted_span).resolved_observation_ids == ("update-resolved",)
    assert not gate.assess(evidence).qualified
    assert len(database.source_update_resolutions()) == 1


def test_stale_active_observation_cannot_receive_materiality_decision(database: Database) -> None:
    _enqueue(database)
    _observe(
        database,
        "ukpga:2026:1",
        observation_id="update-stale",
        stale_active=True,
    )
    service = ResearchReviewService(
        Settings(project_root=database.path.parent, test_mode=True), database
    )
    with pytest.raises(RuntimeError, match="recomputed"):
        service.review_update(
            "update-stale",
            materiality_status="material",
            review_status="approved",
            scope_kind="authority",
            legal_locator=None,
            proposition_sha256=None,
            reviewer_ref=f"reviewer:{'a' * 64}",
            review_manifest_sha256="b" * 64,
        )


def test_resolution_service_binds_exact_new_active_source_manifest(
    tmp_path: Path, database: Database, evidence: EvidenceSpan
) -> None:
    _enqueue(database)
    authority_id = _bind_authority(database, evidence)
    _observe(
        database,
        authority_id,
        observation_id="update-service-resolution",
        pinned_build_id="build-1",
    )
    database.record_source_update_review(
        "update-service-resolution",
        review_id="review-update-service-resolution",
        review_status="approved",
        materiality_status="material",
        reviewer_ref=f"reviewer:{'c' * 64}",
        review_manifest_sha256="d" * 64,
    )
    settings = Settings(project_root=tmp_path, test_mode=True)
    repository = ImmutableLanceRepository(settings.index_dir)
    build_id = "build-2"
    build_path = repository.builds / build_id
    build_path.mkdir(parents=True)
    build_manifest = {
        "schema": "legalbot.lance-build.v1",
        "build_id": build_id,
        "created_at": utc_iso(),
        "chunk_count": 1,
        "vector_dimensions": 1024,
        "embedding_model": "embed",
        "reranker_model": "rerank",
        "source_manifest_sha256": "placeholder",
        "sealed": True,
    }
    (build_path / "manifest.json").write_text(
        json.dumps(build_manifest, sort_keys=True), encoding="utf-8"
    )
    source_manifest = {
        "schema": "legalbot.approved-source-manifest.v1",
        "sources": [
            {
                "authority_identity_id": authority_id,
                "content_sha256": "d" * 64,
                "version_sha256": "e" * 64,
            }
        ],
    }
    source_manifest["manifest_sha256"] = approved_source_manifest_sha256(source_manifest)
    source_manifest_sha = str(source_manifest["manifest_sha256"])
    (build_path / "approved-source-manifest.json").write_text(
        json.dumps(source_manifest, sort_keys=True), encoding="utf-8"
    )
    database.execute("UPDATE index_builds SET status='superseded' WHERE id='build-1'")
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,source_manifest_hash,created_at
        ) VALUES (?,?,?,?,?,?,?)
        """,
        (
            build_id,
            "active",
            str(build_path),
            "embed",
            "rerank",
            source_manifest_sha,
            utc_iso(),
        ),
    )
    repository.promote(build_id)
    service = ResearchReviewService(settings, database)
    resolution_id = service.resolve_material_update(
        "update-service-resolution",
        evidence_sha256="f" * 64,
        reviewer_ref=f"reviewer:{'1' * 64}",
    )
    assert resolution_id.startswith("source-update-resolution-")
    assert database.source_update_resolutions()[0]["resolved_by_build_id"] == build_id
