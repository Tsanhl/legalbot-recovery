from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.retrieval.ge_index_build_authorization as ge_authorization_module
from app.config import Settings
from app.contracts import canonical_json_bytes, seal_contract
from app.db import Database
from app.governance.owner_stop import (
    OwnerDecisionStore,
    seal_owner_decision_request,
    seal_owner_decision_resolution,
)
from app.ingestion.models import Jurisdiction, MaterialLane
from app.retrieval.ge_index_build_authorization import (
    build_ge_index_build_decision_request,
    ge_index_build_decision_binding,
    ge_index_build_decision_id,
)
from app.retrieval.ge_source_scope import (
    SCOPE_FILENAME,
    ge_source_scope_review_root,
    prepare_ge_source_scope,
    select_ge_source_scope_rows,
    snapshot_ge_source_binding,
    validate_ge_source_scope,
)
from app.retrieval.incomplete_index_audit import (
    ObservedIndexRow,
    compare_index_identities,
    load_expected_index_rows,
    source_lane_bindings_for_manifest,
)
from app.retrieval.index_build import (
    IndexBuildContext,
    IndexBuildStageError,
    _apply_source_lane_binding,
    _integrity_source_lane_claims,
    _iter_scoped_chunks,
    _require_enqueued_source_manifest_unchanged,
    _verify_held_ge_successor_tree,
    enqueue_index_build,
)
from app.retrieval.models import VECTOR_DIMENSIONS, IndexedChunk
from app.retrieval.source_manifest import (
    approved_source_manifest_sha256,
    build_approved_source_manifest,
    select_approved_authority_rows,
)

NOW = "2026-09-01T00:00:00+00:00"
_ORDINARY_SOURCE_MANIFEST = {
    "schema": "legalbot.approved-source-manifest.v1",
    "selection_policy": "synthetic-ordinary-candidate",
    "sources": [],
    "successor_must_remain_non_active": False,
}
_ORDINARY_SOURCE_MANIFEST_SHA256 = approved_source_manifest_sha256(
    _ORDINARY_SOURCE_MANIFEST
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _stored_value(value: object) -> object:
    if isinstance(value, bytes | bytearray | memoryview):
        content = bytes(value)
        return {
            "type": "bytes",
            "length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    if value is None or isinstance(value, str | int | float):
        return value
    return str(value)


def _stored_record_sha256(row: sqlite3.Row, *, table: str) -> str:
    fields = {
        str(key): _stored_value(row[key])
        for key in row.keys()  # noqa: SIM118
    }
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": "legalbot.exact-stored-record.v1",
                "table": table,
                "fields": fields,
            }
        )
    ).hexdigest()


def _settings(project: Path) -> Settings:
    return Settings(project_root=project, test_mode=True)


def _seed_pack_configuration(project: Path) -> None:
    config = project / "config"
    config.mkdir(parents=True, exist_ok=True)
    (config / "official_legislation_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.official-legislation-pack.v1",
                "version": "test",
                "items": [],
            }
        ),
        encoding="utf-8",
    )
    (config / "uksc_authority_pack.json").write_text(
        json.dumps(
            {
                "schema": "legalbot.uksc-authority-pack.v1",
                "version": "test",
                "items": [],
            }
        ),
        encoding="utf-8",
    )


def _seed_strict_predecessor(
    database: Database,
    settings: Settings,
    *,
    key: str,
) -> str:
    from app.jobs import CHUNKER_VERSION, INDEX_SCHEMA_VERSION, PARSER_VERSION

    suffix = _digest(f"strict-predecessor:{key}")[:16]
    build_id = f"ge-predecessor-{suffix}"
    document_id = f"doc-predecessor-{suffix}"
    source_version_id = f"sv-predecessor-{suffix}"
    markdown_path = Path("data/vault/ge-predecessors") / f"{suffix}.md"
    markdown = settings.project_root / markdown_path
    markdown.parent.mkdir(parents=True, exist_ok=True)
    markdown.write_text(
        f"# Preserved predecessor {suffix}\n\nExisting legal source.\n",
        encoding="utf-8",
    )
    content_sha256 = hashlib.sha256(markdown.read_bytes()).hexdigest()
    metadata = {
        "material_type": "legislation",
        "identity_verified": True,
        "currentness_verified": True,
        "currentness_applicable": True,
        "authority_eligible": True,
        "citation_rendering_enabled": True,
        "eligible_for_model_use": True,
        "ai_use_policy": "permitted",
        "approval_as_of_date": "2026-09-01",
        "currentness_reviewed_as_of_date": "2026-09-01",
    }
    database.execute(
        """
        INSERT INTO documents(
          id,content_sha256,source_identity_id,representation_group_id,
          safe_display_name,media_type,status,lane,subject_primary,
          jurisdiction,retrieval_canonical,searchable_text,created_at,updated_at
        ) VALUES (?, ?, ?, ?, ?, 'text/markdown', 'citable',
                  'primary_authority', 'general', 'England and Wales', 1, 1, ?, ?)
        """,
        (
            document_id,
            content_sha256,
            f"predecessor:{suffix}",
            f"predecessor:{suffix}",
            f"predecessor-{suffix}.md",
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id,document_id,authority_identity_id,version_sha256,
          canonical_markdown_path,title,stable_identifier,canonical_url,
          source_date,as_of_date,currentness_status,licence_name,licence_url,
          review_status,processing_fingerprint,metadata_json,created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2026-08-31', '2026-09-01',
                  'current', 'Open Government Licence v3.0',
                  'https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/',
                  'approved', ?, ?, ?)
        """,
        (
            source_version_id,
            document_id,
            f"authority-predecessor-{suffix}",
            content_sha256,
            markdown_path.as_posix(),
            "Preserved predecessor",
            f"official:predecessor:{suffix}",
            f"https://www.legislation.gov.uk/id/predecessor-{suffix}",
            f"predecessor-{suffix}",
            json.dumps(metadata, sort_keys=True),
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id,source_version_id,ordinal,locator,text_sha256,markdown_text,
          token_count,stream
        ) VALUES (?, ?, 0, 'section 1', ?, 'Existing legal source.', 4, 'body')
        """,
        (f"chunk-predecessor-{suffix}", source_version_id, _digest(content_sha256)),
    )
    member = {
        "source_version_id": source_version_id,
        "document_id": document_id,
        "document_status": "citable",
        "stable_identifier": f"official:predecessor:{suffix}",
        "authority_identity_id": f"authority:official:predecessor:{suffix}",
        "title": "Preserved predecessor",
        "lane": "primary_authority",
        "jurisdiction": "England and Wales",
        "licence_name": "Open Government Licence v3.0",
        "canonical_url": f"https://www.legislation.gov.uk/id/predecessor-{suffix}",
        "content_sha256": content_sha256,
        "version_sha256": content_sha256,
        "canonical_markdown_path": markdown_path.as_posix(),
        "body_chunk_count": 1,
        "currentness_status": "current",
        "source_date": "2026-08-31",
        "as_of_date": "2026-09-01",
        "last_updated": NOW,
        "currentness_reviewed_as_of_date": "2026-09-01",
        "catalogue_currentness_status": "current",
        "identity_verified": True,
        "currentness_verified": True,
        "subsequent_treatment_check_required": False,
        "subsequent_treatment_verified": False,
        "unapplied_effect_count": None,
        "provision_extent_status": "unverified",
        "full_current_law_verification_eligible": False,
    }
    source_manifest: dict[str, object] = {
        "schema": "legalbot.approved-source-manifest.v1",
        "corpus_id": f"synthetic-predecessor-{suffix}",
        "created_at": NOW,
        "selection_policy": "synthetic-ordinary-candidate",
        "authority_lane_only": True,
        "successor_must_remain_non_active": False,
        "answer_release_eligible": False,
        "active_or_previous_write_authorized": False,
        "promotion_authorized": False,
        "parser_version": PARSER_VERSION,
        "chunker_version": CHUNKER_VERSION,
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "source_count": 1,
        "chunk_count": 1,
        "sources": [member],
    }
    source_manifest["manifest_sha256"] = approved_source_manifest_sha256(source_manifest)
    build_path = settings.index_dir / "builds" / build_id
    build_path.mkdir(parents=True)

    def write_json(path: Path, value: object) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    source_path = build_path / "approved-source-manifest.json"
    write_json(source_path, source_manifest)
    build_manifest = {
        "schema": "legalbot.lance-build.v1",
        "build_id": build_id,
        "sealed": True,
        "chunk_count": 1,
        "vector_dimensions": VECTOR_DIMENSIONS,
        "embedding_model": "embedding@test",
        "reranker_model": "reranker@test",
        "source_manifest_sha256": source_manifest["manifest_sha256"],
    }
    build_manifest_path = build_path / "manifest.json"
    write_json(build_manifest_path, build_manifest)
    seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": build_id,
        "promotion": "not_requested",
        "manifest_sha256": hashlib.sha256(build_manifest_path.read_bytes()).hexdigest(),
        "source_manifest_file_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
    }
    seal_path = build_path / "seal.json"
    write_json(seal_path, seal)
    seal_sha256 = hashlib.sha256(seal_path.read_bytes()).hexdigest()
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,document_count,chunk_count,vector_count,
          embedding_model,reranker_model,manifest_sha256,created_at,
          corpus_id,scoped_corpus_id,source_manifest_hash,parser_version,
          chunker_version,index_schema_version,stage,candidate_manifest_hash,
          promotion_decision
        ) VALUES (?, 'candidate', ?, 1, 1, 1, 'embedding@test', 'reranker@test',
                  ?, ?, ?, ?, ?, ?, ?, ?, 'candidate', ?, 'not_requested')
        """,
        (
            build_id,
            f"data/indexes/builds/{build_id}",
            seal_sha256,
            NOW,
            source_manifest["corpus_id"],
            source_manifest["corpus_id"],
            source_manifest["manifest_sha256"],
            PARSER_VERSION,
            CHUNKER_VERSION,
            INDEX_SCHEMA_VERSION,
            seal_sha256,
        ),
    )
    return build_id


def _candidate_retrieval_proof(
    project: Path,
    *,
    key: str,
    candidate_build_id: str,
    source_manifest_sha256: str,
    case_id: str,
    diagnosis_id: str,
    query: str,
    query_sha256: str,
    proposition_sha256: str,
) -> tuple[object, str]:
    from app.research.retrieval_attempt import (
        CandidateBuildBinding,
        CandidateRetrievalExecutorHit,
        CandidateRetrievalExecutorResult,
        HitQualificationDisposition,
        RetrievalAttemptBinding,
        _file_sha256,
        _tree_sha256,
        execute_candidate_retrieval_attempt,
        opaque_gap_reference,
    )

    chunk_id = f"candidate-gap-proof-{key}"
    build_root = project / "data/indexes/builds" / candidate_build_id
    authority = build_root / "lance/authority"
    authority.mkdir(parents=True)
    import lancedb

    lancedb.connect(str(authority)).create_table(
        "chunks",
        data=[
            {
                "chunk_id": chunk_id,
                "source_version_id": f"candidate-proof-source-{key}",
                "content_sha256": _digest(f"candidate-proof-content:{key}"),
                "locator": "section 1",
                "catalog_lane": "primary_authority",
                "catalog_jurisdiction": "England and Wales",
                "identity_verified": True,
                "currentness_verified": True,
            }
        ],
    )
    manifest = {
        "schema": "legalbot.index-manifest.v2",
        "build_id": candidate_build_id,
        "source_manifest_sha256": source_manifest_sha256,
        "chunk_count": 1,
        "sealed": True,
    }
    manifest_path = build_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    assert source_manifest_sha256 == _ORDINARY_SOURCE_MANIFEST_SHA256
    source_manifest = {
        **_ORDINARY_SOURCE_MANIFEST,
        "manifest_sha256": source_manifest_sha256,
    }
    source_manifest_path = build_root / "approved-source-manifest.json"
    source_manifest_path.write_text(
        json.dumps(
            source_manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": candidate_build_id,
        "manifest_sha256": _file_sha256(manifest_path),
        "source_manifest_file_sha256": _file_sha256(source_manifest_path),
        "lance_tree_sha256": _tree_sha256(build_root / "lance"),
    }
    seal_path = build_root / "seal.json"
    seal_path.write_text(json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8")
    binding = CandidateBuildBinding(
        candidate_build_id=candidate_build_id,
        candidate_seal_sha256=_file_sha256(seal_path),
        source_manifest_sha256=source_manifest_sha256,
    )

    def executor(request: object) -> CandidateRetrievalExecutorResult:
        return CandidateRetrievalExecutorResult(
            invocation_id=f"ge-source-scope-{key}",
            candidate_build_id=candidate_build_id,
            candidate_rows_examined=1,
            ranked_hits=(
                CandidateRetrievalExecutorHit(
                    chunk_id=chunk_id,
                    qualification_disposition=(
                        HitQualificationDisposition.NO_MATERIAL_SUPPORT
                    ),
                ),
            ),
        )

    attempt = execute_candidate_retrieval_attempt(
        settings=_settings(project),
        binding=RetrievalAttemptBinding(
            candidate_build_id=candidate_build_id,
            candidate_seal_sha256=binding.candidate_seal_sha256,
            source_manifest_sha256=source_manifest_sha256,
            case_ref=opaque_gap_reference("case", case_id),
            issue_ref=opaque_gap_reference("issue", diagnosis_id),
            subject="general enquiries",
            jurisdiction="England and Wales",
            as_of_date=date(2026, 9, 1),
            proposition_sha256=proposition_sha256,
            query_sha256=query_sha256,
        ),
        canonical_query=query,
        executor=executor,
        created_at=datetime(2026, 9, 1, 0, 0, tzinfo=UTC),
    )
    return binding, attempt.artifact_sha256


def _seed_source(
    database: Database,
    project: Path,
    *,
    key: str,
    catalogue_lane: str,
    material_type: str,
) -> str:
    from app.evaluation.ge_improvement_loop import (
        GEDiagnosisInput,
        build_diagnosis,
        build_official_research_intent,
    )
    from app.evaluation.ge_research_control import (
        GEOfficialResearchAdmission,
        build_verified_ge_source_provenance,
    )
    from app.evaluation.ge_visible_harness import FACTUAL_CHECKS
    from app.research.control_plane import ResearchControlPlane
    from app.research.retrieval_attempt import opaque_gap_reference
    from app.research.source_intake_bridge import StagedSourceIntake
    from app.research.source_registry import OfficialSourceRegistry

    document_id = f"doc-{key}"
    source_version_id = f"sv-{key}"
    candidate_id = f"candidate-{key}"
    task_id = f"task-{key}"
    gap_id = f"gap-{key}"
    case_id = f"ge-visible-{key}"
    diagnosis_id = f"ge-diagnosis-{key}"
    candidate_build_id = f"candidate-build-{key}"
    source_manifest_sha256 = _ORDINARY_SOURCE_MANIFEST_SHA256
    query = f"general legislation {key}"
    query_sha256 = hashlib.sha256(query.encode()).hexdigest()
    proposition_sha256 = _digest(f"proposition:{key}")
    candidate_binding, retrieval_attempt_sha256 = _candidate_retrieval_proof(
        project,
        key=key,
        candidate_build_id=candidate_build_id,
        source_manifest_sha256=source_manifest_sha256,
        case_id=case_id,
        diagnosis_id=diagnosis_id,
        query=query,
        query_sha256=query_sha256,
        proposition_sha256=proposition_sha256,
    )
    database.execute(
        """
        INSERT INTO index_builds(
          id,status,path,embedding_model,reranker_model,source_manifest_hash,created_at
        ) VALUES (?, 'candidate', ?, 'embedding@test', 'reranker@test', ?, ?)
        """,
        (
            candidate_build_id,
            f"data/indexes/builds/{candidate_build_id}",
            source_manifest_sha256,
            NOW,
        ),
    )

    factual_checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    factual_checks["claim_evidence_support"] = "FAIL"
    result = seal_contract(
        {
            "schema": "legalbot.evaluation-case-result.v2",
            "case_id": case_id,
            "case_version_sha256": _digest(f"case-version:{key}"),
            "factual_checks": [
                {"check_id": name, "outcome": factual_checks[name]}
                for name in FACTUAL_CHECKS
            ],
            "factual_outcome": "FACTUAL_HOLD",
            "quality_outcome": None,
            "quality_dimensions": None,
            "root_cause_layers": ["retrieval"],
        }
    )
    diagnosis = build_diagnosis(
        GEDiagnosisInput(
            diagnosis_id=diagnosis_id,
            case_id=case_id,
            case_kind="visible",
            failure_class="factual",
            scenario_family_id=f"ge-family-{key}",
            case_version_sha256=str(result["case_version_sha256"]),
            materiality="material",
            finding_sha256=_digest(f"finding:{key}"),
            knowledge_or_source_gap=True,
            subject="general enquiries",
            jurisdiction="England and Wales",
            as_of_date=date(2026, 9, 1),
            retrieval_query_sha256=query_sha256,
            proposition_sha256=proposition_sha256,
            retrieval_attempt_artifact_sha256=retrieval_attempt_sha256,
        ),
        diagnosed_result=result,
    )
    intent = build_official_research_intent(
        diagnosis=diagnosis,
        diagnosed_result=result,
        candidate_build_id=candidate_build_id,
    )

    markdown_path = Path("data/vault/ge-sources") / f"{key}.md"
    target = project / markdown_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"# Official {key}\n\nVerified official text.\n", encoding="utf-8")
    content_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
    system_sha256 = _digest(f"system:{key}")
    owner_manifest_sha256 = _digest(f"owner-review:{key}")
    owner_review_id = f"owner-review-{key}"
    intake_review_id = f"review-research-intake-{key}"
    source_review_id = f"review-{key}"
    source_identity = f"ukpga:2026:{_digest(key)[:12]}"
    candidate_url = f"https://www.legislation.gov.uk/id/{key}"
    safe_metadata = {
        "content_type": "text/plain",
        "disposition": "staged_only",
        "response_sha256": content_sha256,
        "owner_decision_required": True,
    }
    metadata_sha256 = hashlib.sha256(
        json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
    ).hexdigest()
    object_key = f"ge-source-test:{content_sha256}"
    database.store_runtime_object(
        object_key=object_key,
        namespace="ge-source-test",
        content_sha256=content_sha256,
        relative_path=f"ge-source-test/{content_sha256}.enc",
        byte_size=target.stat().st_size,
        metadata={},
        expires_at=None,
    )
    binding_payload = {
        "schema": "legalbot.research-source-intake-bridge.v1",
        "candidate_id": candidate_id,
        "task_id": task_id,
        "source_id": "legislation_gov_uk",
        "source_identity": source_identity,
        "content_sha256": content_sha256,
        "metadata_sha256": metadata_sha256,
        "content_object_key": object_key,
        "system_verification_sha256": system_sha256,
        "owner_review_id": owner_review_id,
        "owner_review_manifest_sha256": owner_manifest_sha256,
        "rights_state": "verified",
        "pending_intake_review_id": intake_review_id,
    }
    binding_sha256 = hashlib.sha256(
        json.dumps(
            binding_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    intake_id = f"source-intake-{binding_sha256[:40]}"
    scan_id = f"research-intake-{binding_sha256[:40]}"
    marker = {
        "schema": "legalbot.research-source-intake-bridge.v1",
        "intake_id": intake_id,
        "binding_sha256": binding_sha256,
        "candidate_id": candidate_id,
        "task_id": task_id,
        "source_id": "legislation_gov_uk",
        "content_sha256": content_sha256,
        "system_verification_sha256": system_sha256,
        "owner_review_id": owner_review_id,
        "owner_review_manifest_sha256": owner_manifest_sha256,
        "rights_state": "verified",
        "pending_intake_review_id": intake_review_id,
    }
    staged_metadata = {
        "schema": "legalbot.research-source-create-only-ingestion.v1",
        "processing_fingerprint": f"ge-source-test-{key}",
        "scan_id": scan_id,
        "raw_object_sha256": content_sha256,
        "raw_vault_path": markdown_path.as_posix(),
        "canonical_markdown_path": markdown_path.as_posix(),
        "content_type": "text/plain",
        "official_source_identity_sha256": hashlib.sha256(
            source_identity.encode()
        ).hexdigest(),
        "official_canonical_url_sha256": hashlib.sha256(
            candidate_url.encode()
        ).hexdigest(),
        "identity_verified": False,
        "currentness_verified": False,
        "currentness_applicable": False,
        "authority_eligible": False,
        "citation_rendering_enabled": False,
        "eligible_for_model_use": True,
        "ai_use_policy": "permitted_after_rights_review",
        "ai_use_restriction_codes": [],
        "research_source_intake": marker,
    }

    database.execute(
        """
        INSERT INTO research_gap_bindings(
          id,fingerprint_sha256,candidate_build_id,source_manifest_sha256,
          case_id,issue_id,subject,jurisdiction,as_of_date,
          attempted_retrieval_sha256,materiality,detail_sha256,
          encrypted_detail,status,created_at,updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'general enquiries', 'England and Wales',
                  '2026-09-01', ?, 'material', ?, ?, 'source_needed', ?, ?)
        """,
        (
            gap_id,
            _digest(f"gap-fingerprint:{key}"),
            candidate_build_id,
            source_manifest_sha256,
            opaque_gap_reference("case", case_id),
            opaque_gap_reference("issue", diagnosis_id),
            retrieval_attempt_sha256,
            _digest(f"gap-detail:{key}"),
            f"encrypted-gap:{key}".encode(),
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO research_tasks(
          id,idempotency_key,task_type,trigger_kind,priority_band,base_priority,
          subject,jurisdiction,as_of_date,source_id,knowledge_gap_id,
          pinned_index_build_id,source_manifest_sha256,query_sha256,status,
          max_attempts,candidate_cap,created_at,updated_at
        ) VALUES (?, ?, 'gap_research', 'enquiry', 'high', 80,
                  'general enquiries', 'England and Wales', '2026-09-01',
                  'legislation_gov_uk', ?, ?, ?, ?, 'review_required', 3, 20, ?, ?)
        """,
        (
            task_id,
            _digest(f"task-idempotency:{key}"),
            gap_id,
            candidate_build_id,
            source_manifest_sha256,
            query_sha256,
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO reviews(
          id,review_type,target_id,status,reason,decision_note,created_at,decided_at
        ) VALUES (?, 'research_candidate_system_verification', ?, 'approved', ?,
                  '[redacted]', ?, ?)
        """,
        (
            f"review-research-system-{candidate_id}",
            candidate_id,
            f"Deterministic candidate envelope {system_sha256}",
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO reviews(
          id,review_type,target_id,status,reason,decision_note,created_at,decided_at
        ) VALUES (?, 'official_research_candidate', ?, 'approved', ?,
                  '[redacted]', ?, ?)
        """,
        (
            owner_review_id,
            candidate_id,
            f"Explicit reviewed manifest {owner_manifest_sha256}",
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO reviews(id,review_type,target_id,status,reason,created_at)
        VALUES (?, 'research_source_intake', ?, 'pending',
                'source intake review required', ?)
        """,
        (intake_review_id, candidate_id, NOW),
    )
    database.execute(
        """
        INSERT INTO research_candidates(
          id,task_id,source_id,source_identity,canonical_url,content_sha256,
          metadata_sha256,content_object_key,status,rights_state,review_id,
          system_verification_sha256,system_verified_at,intake_review_id,
          identity_review_state,currentness_review_state,reviewer_ref,
          review_manifest_sha256,safe_metadata_json,created_at,updated_at
        ) VALUES (?, ?, 'legislation_gov_uk', ?, ?, ?, ?, ?,
                  'source_intake_pending', 'verified', ?, ?, ?, ?,
                  'candidate_matched', 'verified', ?, ?, ?, ?, ?)
        """,
        (
            candidate_id,
            task_id,
            source_identity,
            candidate_url,
            content_sha256,
            metadata_sha256,
            object_key,
            owner_review_id,
            system_sha256,
            NOW,
            intake_review_id,
            f"reviewer:{_digest(key)}",
            owner_manifest_sha256,
            json.dumps(safe_metadata, sort_keys=True),
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO documents(
          id,content_sha256,source_identity_id,representation_group_id,
          safe_display_name,media_type,status,lane,subject_primary,
          jurisdiction,retrieval_canonical,searchable_text,created_at,updated_at
        ) VALUES (?, ?, ?, ?, ?, 'text/markdown', 'ready', ?, 'general',
                  'England and Wales', 0, 1, ?, ?)
        """,
        (
            document_id,
            content_sha256,
            f"research-intake:{binding_sha256}",
            f"research-intake:{binding_sha256}",
            f"official-{key}.md",
            catalogue_lane,
            NOW,
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO source_versions(
          id,document_id,authority_identity_id,version_sha256,
          canonical_markdown_path,title,stable_identifier,currentness_status,
          review_status,processing_fingerprint,metadata_json,created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'unknown', 'staged', ?, ?, ?)
        """,
        (
            source_version_id,
            document_id,
            source_identity,
            content_sha256,
            markdown_path.as_posix(),
            f"Official {key}",
            f"research-intake-sha256:{binding_sha256}",
            f"ge-source-test-{key}",
            json.dumps(staged_metadata, sort_keys=True),
            NOW,
        ),
    )
    database.execute(
        """
        INSERT INTO chunks(
          id,source_version_id,ordinal,locator,text_sha256,markdown_text,
          token_count,stream
        ) VALUES (?, ?, 0, 'p 1', ?, 'Verified official text.', 4, 'body')
        """,
        (f"chunk-{key}", source_version_id, _digest(f"chunk:{key}")),
    )
    database.execute(
        """
        INSERT INTO reviews(id,review_type,target_id,status,reason,created_at)
        VALUES (?, 'source_version', ?, 'pending', 'source approval required', ?)
        """,
        (source_review_id, source_version_id, NOW),
    )

    admission = GEOfficialResearchAdmission(
        gap_id=gap_id,
        task_id=task_id,
        task_status="queued",
        source_id="legislation_gov_uk",
        candidate_build_id=candidate_build_id,
        source_manifest_sha256=source_manifest_sha256,
        query_sha256=query_sha256,
        retrieval_attempt_artifact_sha256=retrieval_attempt_sha256,
        intent_sha256=str(intent["content_sha256"]),
    )
    receipt = StagedSourceIntake(
        schema="legalbot.research-source-intake-bridge.v1",
        intake_id=intake_id,
        binding_sha256=binding_sha256,
        candidate_id=candidate_id,
        task_id=task_id,
        source_id="legislation_gov_uk",
        content_sha256=content_sha256,
        system_verification_sha256=system_sha256,
        owner_review_id=owner_review_id,
        owner_review_manifest_sha256=owner_manifest_sha256,
        rights_state="verified",
        pending_intake_review_id=intake_review_id,
        opaque_relative_path=(
            "official-research-intake/legislation/"
            f"official-{binding_sha256[:32]}-{content_sha256[:16]}.txt"
        ),
        scan_id=scan_id,
        materialization_state="created",
        ingestion_status="ready",
        source_version_id=source_version_id,
        source_review_id=source_review_id,
        source_review_status="pending",
        source_version_review_status="staged",
        currentness_status="unknown",
        provenance_marker_schema="legalbot.research-source-intake-bridge.v1",
    )
    registry_path = Path(__file__).resolve().parents[2] / "config/official_sources.json"
    control = ResearchControlPlane(
        _settings(project),
        database,
        registry=OfficialSourceRegistry.load(registry_path),
        candidate_binding_loader=(
            lambda _settings_value, _database_value, _build_id: candidate_binding
        ),
    )
    provenance = build_verified_ge_source_provenance(
        control_plane=control,
        diagnosis=diagnosis,
        diagnosed_result=result,
        sealed_intent=intent,
        research_admission=admission,
        source_intake_receipt=receipt,
    )

    approved_metadata = {
        **staged_metadata,
        "material_type": material_type,
        "identity_verified": True,
        "currentness_verified": True,
        "currentness_applicable": True,
        "authority_eligible": True,
        "citation_rendering_enabled": True,
        "approval_as_of_date": "2026-09-01",
        "currentness_reviewed_as_of_date": "2026-09-01",
        "ge_source_provenance_chain": provenance,
    }
    database.execute(
        """
        UPDATE source_versions
        SET authority_identity_id=?, source_date='2026-08-31', as_of_date='2026-09-01',
            canonical_url=?, stable_identifier=?, currentness_status='current',
            licence_name='Open Government Licence v3.0',
            licence_url='https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/',
            review_status='approved', metadata_json=?
        WHERE id=?
        """,
        (
            f"authority-{key}",
            candidate_url,
            f"official:{key}",
            json.dumps(approved_metadata, sort_keys=True),
            source_version_id,
        ),
    )
    database.execute(
        "UPDATE documents SET status='citable', retrieval_canonical=1 WHERE id=?",
        (document_id,),
    )
    database.execute(
        """
        UPDATE reviews SET status='approved', decision_note=?, decided_at=?
        WHERE id=?
        """,
        (
            f"Explicit GE provenance chain {provenance['content_sha256']}",
            NOW,
            source_review_id,
        ),
    )
    return source_version_id


def _write_scope(settings: Settings, scope: dict[str, object], *, run: str) -> Path:
    path = ge_source_scope_review_root(settings) / run / SCOPE_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scope, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _approved_scope(
    database: Database,
    settings: Settings,
    bindings: list[tuple[str, str]],
    *,
    run: str = "scope-r1",
) -> dict[str, object]:
    predecessor_build_id = _seed_strict_predecessor(
        database, settings, key=run
    )
    sources = [
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=source_version_id,
            scope_lane=scope_lane,
        )
        for source_version_id, scope_lane in bindings
    ]
    scope = prepare_ge_source_scope(
        sources,
        database=database,
        settings=settings,
        predecessor_build_id=predecessor_build_id,
        owner_approval_digest=_digest(f"owner-approval:{run}"),
        created_at=NOW,
    )
    _write_scope(settings, scope, run=run)
    return scope


def _store_ge_index_build_authorization(
    database: Database,
    settings: Settings,
    manifest: dict[str, object],
    *,
    build_id: str,
) -> tuple[str, str]:
    binding = ge_index_build_decision_binding(
        settings, database, manifest, build_id=build_id
    )
    request = build_ge_index_build_decision_request(
        binding=binding,
        created_at=datetime(2026, 9, 1, 0, 10, tzinfo=UTC),
    )
    resolution = seal_owner_decision_resolution(
        request=request,
        selected_option_id="approve-exact-ge-scope-and-held-index-build",
        owner_ref=f"owner:{'e' * 64}",
        decided_at=datetime(2026, 9, 1, 0, 11, tzinfo=UTC),
    )
    store = OwnerDecisionStore(settings.owner_decision_root)
    store.write_request(request)
    store.write_resolution(resolution)
    return request.decision_id, resolution.seal_sha256


def _reseal_approved_source_manifest(
    manifest: dict[str, object],
) -> dict[str, object]:
    resealed = json.loads(json.dumps(manifest))
    assert isinstance(resealed, dict)
    resealed.pop("manifest_sha256", None)
    resealed["manifest_sha256"] = approved_source_manifest_sha256(resealed)
    return resealed


def _reseal_mutated_predecessor_member(
    database: Database,
    settings: Settings,
    *,
    predecessor_build_id: str,
) -> None:
    build_path = settings.index_dir / "builds" / predecessor_build_id
    source_path = build_path / "approved-source-manifest.json"
    build_manifest_path = build_path / "manifest.json"
    seal_path = build_path / "seal.json"
    source_manifest = json.loads(source_path.read_text(encoding="utf-8"))
    assert isinstance(source_manifest, dict)
    sources = source_manifest["sources"]
    assert isinstance(sources, list) and isinstance(sources[0], dict)
    sources[0]["title"] = "Substituted predecessor member"
    source_manifest = _reseal_approved_source_manifest(source_manifest)
    source_path.write_text(
        json.dumps(source_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    build_manifest = json.loads(build_manifest_path.read_text(encoding="utf-8"))
    assert isinstance(build_manifest, dict)
    build_manifest["source_manifest_sha256"] = source_manifest["manifest_sha256"]
    build_manifest_path.write_text(
        json.dumps(build_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    assert isinstance(seal, dict)
    seal["manifest_sha256"] = hashlib.sha256(
        build_manifest_path.read_bytes()
    ).hexdigest()
    seal["source_manifest_file_sha256"] = hashlib.sha256(
        source_path.read_bytes()
    ).hexdigest()
    seal_path.write_text(
        json.dumps(seal, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    seal_sha256 = hashlib.sha256(seal_path.read_bytes()).hexdigest()
    database.execute(
        """
        UPDATE index_builds
        SET source_manifest_hash=?, manifest_sha256=?, candidate_manifest_hash=?
        WHERE id=?
        """,
        (
            source_manifest["manifest_sha256"],
            seal_sha256,
            seal_sha256,
            predecessor_build_id,
        ),
    )


def test_only_exact_owner_approved_ge_scope_sources_and_lanes_are_selectable(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    primary = _seed_source(
        database,
        tmp_path,
        key="act",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    guidance = _seed_source(
        database,
        tmp_path,
        key="guidance",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    procedure = _seed_source(
        database,
        tmp_path,
        key="procedure",
        catalogue_lane="primary_authority",
        material_type="rule",
    )
    _seed_source(
        database,
        tmp_path,
        key="not-approved-for-this-scope",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    scope = _approved_scope(
        database,
        settings,
        [
            (primary, "primary_authority"),
            (guidance, "official_guidance"),
            (procedure, "official_procedure"),
        ],
    )

    rows = select_approved_authority_rows(
        database, settings, corpus_id=str(scope["corpus_id"])
    )

    predecessor_id = str(scope["predecessor"]["source_version_ids"][0])
    assert {row["source_version_id"] for row in rows} == {
        predecessor_id,
        primary,
        guidance,
        procedure,
    }
    assert {row["ge_scope_lane"] for row in rows} == {
        "primary_authority",
        "official_guidance",
        "official_procedure",
    }
    assert {row["source_version_id"]: row["lane"] for row in rows} == {
        predecessor_id: "primary_authority",
        primary: "primary_authority",
        guidance: "official_secondary",
        procedure: "primary_authority",
    }
    assert all(row["answer_release_eligible_in_successor"] is False for row in rows)
    assert scope["successor_must_remain_non_active"] is True
    assert scope["promotion_authorized"] is False
    assert scope["index_enqueue_authorized"] is False
    assert scope["index_build_authorized"] is False


def test_prepared_scope_without_external_owner_approval_is_not_selectable(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="pending",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    binding = snapshot_ge_source_binding(
        database,
        settings,
        source_version_id=source,
        scope_lane="primary_authority",
    )
    scope = prepare_ge_source_scope(
        [binding],
        database=database,
        settings=settings,
        predecessor_build_id=_seed_strict_predecessor(
            database, settings, key="pending-scope"
        ),
        owner_approval_digest=None,
        created_at=NOW,
    )
    validate_ge_source_scope(scope, require_approved=False)
    _write_scope(settings, scope, run="pending-scope")

    with pytest.raises(ValueError, match="owner_approval_required"):
        select_ge_source_scope_rows(
            database,
            settings,
            corpus_id=str(scope["corpus_id"]),
            max_chunks=None,
            preferred_small_first=False,
        )


def test_ge_scope_rejects_legacy_only_generic_intake_marker(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="legacy-only-intake",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    row = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?", (source,)
    )
    assert row is not None
    metadata = json.loads(str(row["metadata_json"]))
    metadata["ge_source_provenance_chain"] = None
    database.execute(
        "UPDATE source_versions SET metadata_json=? WHERE id=?",
        (json.dumps(metadata, sort_keys=True), source),
    )

    with pytest.raises(ValueError, match="ge_provenance_chain_missing"):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=source,
            scope_lane="primary_authority",
        )


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        (
            "research_gap_id",
            "gap-orphaned-provenance",
            "component_admission_invalid",
        ),
        (
            "source_version_id",
            "sv-substituted-provenance",
            "ge_provenance_binding_invalid",
        ),
    ],
    ids=["orphan-gap", "substituted-source"],
)
def test_ge_scope_rejects_orphaned_or_substituted_provenance_chain(
    database: Database,
    tmp_path: Path,
    field: str,
    replacement: str,
    error: str,
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key=f"provenance-{field}",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    row = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?", (source,)
    )
    assert row is not None
    metadata = json.loads(str(row["metadata_json"]))
    provenance = dict(metadata["ge_source_provenance_chain"])
    provenance.pop("content_sha256")
    provenance[field] = replacement
    metadata["ge_source_provenance_chain"] = seal_contract(provenance)
    database.execute(
        "UPDATE source_versions SET metadata_json=? WHERE id=?",
        (json.dumps(metadata, sort_keys=True), source),
    )

    with pytest.raises(ValueError, match=error):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=source,
            scope_lane="primary_authority",
        )


def test_ge_scope_rejects_exact_research_task_record_drift(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="provenance-task-drift",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    row = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?", (source,)
    )
    assert row is not None
    metadata = json.loads(str(row["metadata_json"]))
    provenance = metadata["ge_source_provenance_chain"]
    database.execute(
        "UPDATE research_tasks SET status_reason='synthetic-drift' WHERE id=?",
        (provenance["research_task_id"],),
    )

    with pytest.raises(ValueError, match="ge_provenance_record_drift"):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=source,
            scope_lane="primary_authority",
        )


def test_ge_scope_rejects_missing_or_substituted_exact_component_receipt(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    first = _seed_source(
        database,
        tmp_path,
        key="component-first",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    second = _seed_source(
        database,
        tmp_path,
        key="component-second",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    first_row = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?", (first,)
    )
    second_row = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?", (second,)
    )
    assert first_row is not None and second_row is not None
    first_metadata = json.loads(str(first_row["metadata_json"]))
    second_metadata = json.loads(str(second_row["metadata_json"]))

    missing = dict(first_metadata["ge_source_provenance_chain"])
    missing.pop("content_sha256")
    missing["component_receipt_artifact_sha256"] = "f" * 64
    first_metadata["ge_source_provenance_chain"] = seal_contract(missing)
    database.execute(
        "UPDATE source_versions SET metadata_json=? WHERE id=?",
        (json.dumps(first_metadata, sort_keys=True), first),
    )
    with pytest.raises(ValueError, match="component_artifact_missing"):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=first,
            scope_lane="primary_authority",
        )

    first_metadata = json.loads(str(first_row["metadata_json"]))
    substituted = dict(first_metadata["ge_source_provenance_chain"])
    substituted.pop("content_sha256")
    substituted["component_receipt_artifact_sha256"] = second_metadata[
        "ge_source_provenance_chain"
    ]["component_receipt_artifact_sha256"]
    first_metadata["ge_source_provenance_chain"] = seal_contract(substituted)
    database.execute(
        "UPDATE source_versions SET metadata_json=? WHERE id=?",
        (json.dumps(first_metadata, sort_keys=True), first),
    )
    with pytest.raises(ValueError, match="component_.*(?:differed|invalid)"):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=first,
            scope_lane="primary_authority",
        )


def test_ge_scope_rejects_component_bytes_or_unbound_source_approval(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="component-byte-custody",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    row = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?", (source,)
    )
    assert row is not None
    metadata = json.loads(str(row["metadata_json"]))
    provenance = metadata["ge_source_provenance_chain"]
    component_sha256 = str(provenance["component_receipt_artifact_sha256"])
    component_path = (
        tmp_path
        / "data/evaluations/research/ge-source-provenance-components"
        / f"{component_sha256}.json"
    )
    original = component_path.read_bytes()
    component_path.write_bytes(original + b" ")
    component_path.chmod(0o600)
    with pytest.raises(ValueError, match="component_artifact_bytes_differ"):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=source,
            scope_lane="primary_authority",
        )

    component_path.write_bytes(original)
    component_path.chmod(0o600)
    database.execute(
        "UPDATE reviews SET decision_note='unbound approval' WHERE target_id=?",
        (source,),
    )
    with pytest.raises(ValueError, match="staged_history_invalid"):
        snapshot_ge_source_binding(
            database,
            settings,
            source_version_id=source,
            scope_lane="primary_authority",
        )


def test_ge_build_rejects_stored_owner_decision_with_wrong_purpose(
    database: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    _seed_pack_configuration(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="wrong-decision-purpose",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    scope = _approved_scope(
        database,
        settings,
        [(source, "official_guidance")],
        run="wrong-decision-purpose",
    )
    manifest = build_approved_source_manifest(
        database,
        settings,
        corpus_id=str(scope["corpus_id"]),
    )
    binding = ge_index_build_decision_binding(
        settings,
        database,
        manifest,
        build_id="ge-wrong-purpose",
    )
    decision_id = ge_index_build_decision_id(binding)
    wrong_request = seal_owner_decision_request(
        decision_id=decision_id,
        category="policy",
        scope_id="unrelated-policy:wrong-purpose",
        reason_codes=("UNRELATED_OWNER_DECISION",),
        evidence=(
            {
                "evidence_id": "unrelated-evidence",
                "kind": "unrelated_record",
                "sha256": "7" * 64,
                "summary_code": "UNRELATED_EVIDENCE",
            },
        ),
        options=(
            {
                "option_id": "keep-closed",
                "outcome_code": "KEEP_CLOSED",
                "recommended": True,
                "consequence_codes": (),
            },
            {
                "option_id": "approve-exact-ge-scope-and-held-index-build",
                "outcome_code": "UNRELATED_APPROVAL",
                "recommended": False,
                "consequence_codes": (),
            },
        ),
        blocked_actions=("unrelated-action",),
        created_at=datetime(2026, 9, 1, 0, 10, tzinfo=UTC),
    )
    wrong_resolution = seal_owner_decision_resolution(
        request=wrong_request,
        selected_option_id="approve-exact-ge-scope-and-held-index-build",
        owner_ref=f"owner:{'d' * 64}",
        decided_at=datetime(2026, 9, 1, 0, 11, tzinfo=UTC),
    )
    store = OwnerDecisionStore(settings.owner_decision_root)
    store.write_request(wrong_request)
    store.write_resolution(wrong_resolution)
    monkeypatch.setattr(
        ge_authorization_module,
        "_verify_trusted_ge_index_build_authorization_signature",
        lambda _request, _resolution: None,
    )

    with pytest.raises(PermissionError, match="request_binding_invalid"):
        enqueue_index_build(
            settings,
            database,
            corpus_id=str(scope["corpus_id"]),
            build_id="ge-wrong-purpose",
            ge_index_build_owner_decision_id=decision_id,
            ge_index_build_owner_decision_content_sha256=(
                wrong_resolution.seal_sha256
            ),
        )


def test_approved_source_manifest_carries_ge_scope_and_non_active_boundary(
    database: Database, tmp_path: Path
) -> None:
    _seed_pack_configuration(tmp_path)
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="manifest-guidance",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    scope = _approved_scope(database, settings, [(source, "official_guidance")])

    manifest = build_approved_source_manifest(
        database, settings, corpus_id=str(scope["corpus_id"])
    )

    assert manifest["selection_policy"] == (
        "exact-owner-approved-ge-source-versions-and-lanes"
    )
    assert manifest["source_count"] == 2
    assert manifest["sources"][0] == scope["predecessor"]["source_members"][0]
    assert manifest["sources"][1]["lane"] == "official_secondary"
    assert manifest["sources"][1]["ge_scope_lane"] == "official_guidance"
    assert manifest["ge_expansion_mode"] == "strict_successor"
    assert manifest["ge_predecessor_build_id"] == scope["predecessor_build_id"]
    assert manifest["ge_added_source_count"] == 1
    assert manifest["ge_successor_member_sequence_sha256"] == scope[
        "successor_member_sequence_sha256"
    ]
    assert manifest["ge_source_scope_content_sha256"] == scope["scope_content_sha256"]
    assert manifest["ge_source_scope_owner_approval_digest"] == scope[
        "owner_approval_digest"
    ]
    assert manifest["authority_lane_only"] is False
    assert manifest["approved_legal_source_lanes_only"] is True
    assert manifest["index_enqueue_authorized"] is False
    assert manifest["index_build_authorized"] is False
    assert manifest["successor_must_remain_non_active"] is True
    assert manifest["promotion_authorized"] is False


def test_strict_successor_requires_nonempty_additions_and_one_exact_held_predecessor(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="strict-boundary",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    addition = snapshot_ge_source_binding(
        database,
        settings,
        source_version_id=source,
        scope_lane="primary_authority",
    )
    predecessor_build_id = _seed_strict_predecessor(
        database, settings, key="strict-boundary"
    )

    with pytest.raises(ValueError, match="requires_nonempty_additions"):
        prepare_ge_source_scope(
            [],
            database=database,
            settings=settings,
            predecessor_build_id=predecessor_build_id,
            owner_approval_digest=_digest("strict-boundary-approval"),
            created_at=NOW,
        )
    with pytest.raises(ValueError, match="predecessor_index_build_missing"):
        prepare_ge_source_scope(
            [addition],
            database=database,
            settings=settings,
            predecessor_build_id="fabricated-held-predecessor",
            owner_approval_digest=_digest("strict-boundary-approval"),
            created_at=NOW,
        )

    settings.ensure_runtime_dirs()
    (settings.index_dir / "ACTIVE.json").write_text(
        json.dumps({"build_id": predecessor_build_id}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="release_pointer_history_forbidden"):
        prepare_ge_source_scope(
            [addition],
            database=database,
            settings=settings,
            predecessor_build_id=predecessor_build_id,
            owner_approval_digest=_digest("strict-boundary-approval"),
            created_at=NOW,
        )


def test_strict_successor_replays_exact_predecessor_row_after_scope_approval(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="stale-predecessor-row",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    scope = _approved_scope(
        database,
        settings,
        [(source, "primary_authority")],
        run="stale-predecessor-row",
    )
    database.execute(
        "UPDATE index_builds SET status='built_unscored', stage='built_unscored' WHERE id=?",
        (scope["predecessor_build_id"],),
    )

    with pytest.raises(ValueError, match="predecessor_proof_replay_differed"):
        build_approved_source_manifest(
            database, settings, corpus_id=str(scope["corpus_id"])
        )


def test_strict_successor_rejects_resealed_predecessor_member_mutation(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="mutated-predecessor-member",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    scope = _approved_scope(
        database,
        settings,
        [(source, "primary_authority")],
        run="mutated-predecessor-member",
    )
    _reseal_mutated_predecessor_member(
        database,
        settings,
        predecessor_build_id=str(scope["predecessor_build_id"]),
    )

    with pytest.raises(ValueError, match="predecessor_proof_replay_differed"):
        build_approved_source_manifest(
            database, settings, corpus_id=str(scope["corpus_id"])
        )


@pytest.mark.parametrize(
    "attack",
    [
        "equal-set",
        "shrink",
        "replacement",
        "reordered",
        "duplicate",
        "predecessor-member-mutation",
        "added-set-drift",
    ],
)
def test_owner_binding_rejects_non_preserving_or_unproved_successor_manifest(
    database: Database, tmp_path: Path, attack: str
) -> None:
    settings = _settings(tmp_path)
    _seed_pack_configuration(tmp_path)
    first = _seed_source(
        database,
        tmp_path,
        key=f"manifest-attack-{attack}-first",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    second = _seed_source(
        database,
        tmp_path,
        key=f"manifest-attack-{attack}-second",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    scope = _approved_scope(
        database,
        settings,
        [(first, "primary_authority"), (second, "official_guidance")],
        run=f"manifest-attack-{attack}",
    )
    manifest = build_approved_source_manifest(
        database, settings, corpus_id=str(scope["corpus_id"])
    )
    mutated = json.loads(json.dumps(manifest))
    assert isinstance(mutated, dict)
    members = mutated["sources"]
    assert isinstance(members, list) and len(members) == 3
    predecessor_count = int(scope["predecessor_source_count"])

    if attack == "equal-set":
        mutated["sources"] = members[:predecessor_count]
        mutated["source_count"] = predecessor_count
        mutated["chunk_count"] = int(scope["predecessor_chunk_count"])
        mutated["ge_added_source_count"] = 0
        mutated["ge_added_chunk_count"] = 0
    elif attack == "shrink":
        mutated["sources"] = members[:-1]
        mutated["source_count"] = len(members) - 1
        mutated["chunk_count"] = int(mutated["chunk_count"]) - int(
            members[-1]["body_chunk_count"]
        )
        mutated["ge_added_source_count"] = int(mutated["ge_added_source_count"]) - 1
        mutated["ge_added_chunk_count"] = int(mutated["ge_added_chunk_count"]) - int(
            members[-1]["body_chunk_count"]
        )
    elif attack == "replacement":
        replacement = dict(members[-1])
        replacement["source_version_id"] = "sv-unproved-replacement"
        mutated["sources"] = [*members[:-1], replacement]
    elif attack == "reordered":
        mutated["sources"] = [members[1], members[0], members[2]]
    elif attack == "duplicate":
        mutated["sources"] = [members[0], members[1], members[1]]
    elif attack == "predecessor-member-mutation":
        changed = dict(members[0])
        changed["title"] = "Altered predecessor in successor"
        mutated["sources"] = [changed, *members[1:]]
    elif attack == "added-set-drift":
        mutated["ge_added_member_set_sha256"] = "0" * 64
    else:  # pragma: no cover - exhaustive parameter list
        raise AssertionError(attack)
    mutated = _reseal_approved_source_manifest(mutated)

    with pytest.raises(
        ValueError,
        match="(?:ge_(?:index_build|source_lane)_|source_lane_binding_)",
    ):
        ge_index_build_decision_binding(
            settings,
            database,
            mutated,
            build_id=f"ge-reject-{attack}",
        )


def test_enqueue_and_scan_replay_bind_exact_predecessor_and_preservation_proof(
    database: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    _seed_pack_configuration(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="frozen-expansion-replay",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    scope = _approved_scope(
        database,
        settings,
        [(source, "primary_authority")],
        run="frozen-expansion-replay",
    )
    manifest = build_approved_source_manifest(
        database, settings, corpus_id=str(scope["corpus_id"])
    )
    monkeypatch.setattr(
        ge_authorization_module,
        "_verify_trusted_ge_index_build_authorization_signature",
        lambda _request, _resolution: None,
    )
    build_id = "ge-frozen-expansion-replay"
    decision_id, decision_content_sha256 = _store_ge_index_build_authorization(
        database,
        settings,
        manifest,
        build_id=build_id,
    )

    with pytest.raises(ValueError, match="vector_parent_must_equal_predecessor"):
        enqueue_index_build(
            settings,
            database,
            corpus_id=str(scope["corpus_id"]),
            build_id=build_id,
            reuse_vectors_from_build_id="fabricated-vector-parent",
            ge_index_build_owner_decision_id=decision_id,
            ge_index_build_owner_decision_content_sha256=decision_content_sha256,
        )

    queued = enqueue_index_build(
        settings,
        database,
        corpus_id=str(scope["corpus_id"]),
        build_id=build_id,
        ge_index_build_owner_decision_id=decision_id,
        ge_index_build_owner_decision_content_sha256=decision_content_sha256,
    )
    job = database.job(str(queued["job_id"]))
    assert job is not None
    request = json.loads(str(job["request_json"]))
    build_models = database.fetchone(
        "SELECT embedding_model,reranker_model FROM index_builds WHERE id=?",
        (build_id,),
    )
    assert build_models is not None
    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id=str(queued["job_id"]),
        build_id=build_id,
        corpus_id=str(scope["corpus_id"]),
        manifest=manifest,
        source_ids=tuple(request["source_version_ids"]),
        embedding_model=str(build_models["embedding_model"]),
        reranker_model=str(build_models["reranker_model"]),
        build_dir=settings.index_dir / "builds" / build_id,
        timings={},
        counts={},
        release_pointer_snapshot=request["release_pointer_snapshot_at_enqueue"],
    )
    substituted_request = json.loads(json.dumps(request))
    substituted_request["ge_preservation_proof_sha256"] = "0" * 64
    with pytest.raises(IndexBuildStageError) as substituted:
        _require_enqueued_source_manifest_unchanged(ctx, substituted_request)
    assert (
        substituted.value.reason_code
        == "ge_successor_index_build_authorization_invalid"
    )

    database.execute(
        "UPDATE index_builds SET status='built_unscored', stage='built_unscored' WHERE id=?",
        (scope["predecessor_build_id"],),
    )
    with pytest.raises(IndexBuildStageError) as stale_predecessor:
        _require_enqueued_source_manifest_unchanged(ctx, request)
    assert (
        stale_predecessor.value.reason_code
        == "ge_successor_index_build_authorization_invalid"
    )


def _make_unapproved(database: Database, source_version_id: str) -> None:
    database.execute(
        "UPDATE source_versions SET review_status='staged' WHERE id=?",
        (source_version_id,),
    )


def _make_superseded(database: Database, source_version_id: str) -> None:
    row = database.fetchone(
        "SELECT document_id,canonical_markdown_path,metadata_json FROM source_versions WHERE id=?",
        (source_version_id,),
    )
    assert row is not None
    successor_id = f"{source_version_id}-successor"
    database.execute(
        """
        INSERT INTO source_versions(
          id,document_id,version_sha256,canonical_markdown_path,review_status,
          metadata_json,created_at
        ) VALUES (?, ?, ?, ?, 'staged', ?, ?)
        """,
        (
            successor_id,
            row["document_id"],
            _digest(successor_id),
            row["canonical_markdown_path"],
            row["metadata_json"],
            NOW,
        ),
    )
    database.execute(
        "UPDATE source_versions SET superseded_by=? WHERE id=?",
        (successor_id, source_version_id),
    )


def _make_duplicate(database: Database, source_version_id: str) -> None:
    row = database.fetchone(
        "SELECT document_id FROM source_versions WHERE id=?", (source_version_id,)
    )
    assert row is not None
    database.execute(
        """
        INSERT INTO documents(
          id,content_sha256,source_identity_id,safe_display_name,media_type,
          status,lane,subject_primary,jurisdiction,retrieval_canonical,
          created_at,updated_at
        ) VALUES ('duplicate-parent', ?, 'duplicate-parent', 'parent.md',
                  'text/markdown', 'citable', 'primary_authority', 'general',
                  'England and Wales', 1, ?, ?)
        """,
        (_digest("duplicate-parent"), NOW, NOW),
    )
    database.execute(
        "UPDATE documents SET duplicate_of='duplicate-parent', retrieval_canonical=0 WHERE id=?",
        (row["document_id"],),
    )


def _drift_currentness(database: Database, source_version_id: str) -> None:
    database.execute(
        "UPDATE source_versions SET currentness_status='historical' WHERE id=?",
        (source_version_id,),
    )


def _drift_rights(database: Database, source_version_id: str) -> None:
    database.execute(
        "UPDATE source_versions SET licence_name='Changed licence' WHERE id=?",
        (source_version_id,),
    )


def _drift_review_binding(database: Database, source_version_id: str) -> None:
    database.execute(
        "UPDATE reviews SET decided_at='2026-09-01T00:00:01+00:00' WHERE target_id=?",
        (source_version_id,),
    )


@pytest.mark.parametrize(
    "mutate",
    [
        _make_unapproved,
        _make_superseded,
        _make_duplicate,
        _drift_currentness,
        _drift_rights,
        _drift_review_binding,
    ],
    ids=[
        "unapproved",
        "superseded",
        "duplicate",
        "currentness",
        "rights",
        "review-binding",
    ],
)
def test_catalogue_eligibility_or_binding_drift_fails_closed(
    database: Database,
    tmp_path: Path,
    mutate: Callable[[Database, str], None],
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="drift",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    scope = _approved_scope(database, settings, [(source, "primary_authority")])
    mutate(database, source)

    with pytest.raises(ValueError, match="ge_source_scope_"):
        select_ge_source_scope_rows(
            database,
            settings,
            corpus_id=str(scope["corpus_id"]),
            max_chunks=None,
            preferred_small_first=False,
        )


def test_scope_rejects_duplicate_members_and_non_source_content_flags(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="boundary",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    binding = snapshot_ge_source_binding(
        database,
        settings,
        source_version_id=source,
        scope_lane="primary_authority",
    )
    with pytest.raises(ValueError, match="duplicate"):
        prepare_ge_source_scope(
            [binding, binding],
            database=database,
            settings=settings,
            predecessor_build_id=_seed_strict_predecessor(
                database, settings, key="duplicate-scope"
            ),
            owner_approval_digest=_digest("approval"),
            created_at=NOW,
        )

    unsafe = dict(binding)
    unsafe.pop("record_content_sha256")
    unsafe["contains_unseen_content"] = True
    unsafe["record_content_sha256"] = _digest(
        json.dumps(unsafe, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    )
    with pytest.raises(ValueError, match="source_boundary_invalid"):
        prepare_ge_source_scope(
            [unsafe],
            database=database,
            settings=settings,
            predecessor_build_id=_seed_strict_predecessor(
                database, settings, key="unsafe-scope"
            ),
            owner_approval_digest=_digest("approval"),
            created_at=NOW,
        )


def test_approved_scope_cannot_be_reordered_or_truncated(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    source = _seed_source(
        database,
        tmp_path,
        key="fixed",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    scope = _approved_scope(database, settings, [(source, "primary_authority")])

    with pytest.raises(ValueError, match="cannot_be_reordered_or_truncated"):
        select_ge_source_scope_rows(
            database,
            settings,
            corpus_id=str(scope["corpus_id"]),
            max_chunks=1,
            preferred_small_first=False,
        )


def test_ge_expected_rows_keep_exact_catalogue_and_material_lanes(
    database: Database, tmp_path: Path
) -> None:
    settings = _settings(tmp_path)
    _seed_pack_configuration(tmp_path)
    primary = _seed_source(
        database,
        tmp_path,
        key="index-primary",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    guidance = _seed_source(
        database,
        tmp_path,
        key="index-guidance",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    procedure = _seed_source(
        database,
        tmp_path,
        key="index-procedure",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    scope = _approved_scope(
        database,
        settings,
        [
            (primary, "primary_authority"),
            (guidance, "official_guidance"),
            (procedure, "official_procedure"),
        ],
        run="index-lanes",
    )
    manifest = build_approved_source_manifest(
        database, settings, corpus_id=str(scope["corpus_id"])
    )
    bindings = source_lane_bindings_for_manifest(manifest)
    rows = load_expected_index_rows(
        database,
        source_ids=tuple(binding.source_version_id for binding in bindings),
        allowlists={},
        prompt_safe=lambda row: str(row["markdown_text"]),
        source_lane_bindings=bindings,
    )

    assert {
        row.source_version_id: (row.catalogue_lane, row.material_lane, row.lane)
        for row in rows
    } == {
        str(scope["predecessor"]["source_version_ids"][0]): (
            "primary_authority",
            "primary_authority",
            "authority",
        ),
        primary: ("primary_authority", "primary_authority", "authority"),
        guidance: ("official_secondary", "official_guidance", "authority"),
        procedure: ("official_secondary", "procedure_rule", "authority"),
    }

    guidance_expected = next(row for row in rows if row.source_version_id == guidance)
    relabelled = ObservedIndexRow(
        chunk_id=guidance_expected.chunk_id,
        content_sha256=guidance_expected.content_sha256,
        source_version_id=guidance_expected.source_version_id,
        vector_dimensions=VECTOR_DIMENSIONS,
        lane="authority",
        material_lane="primary_authority",
        catalogue_lane="primary_authority",
    )
    comparison = compare_index_identities([guidance_expected], [relabelled])
    assert comparison["embedding_complete"] is False
    assert comparison["material_lane_mismatches"] == [guidance_expected.chunk_id]
    assert comparison["catalogue_lane_mismatches"] == [guidance_expected.chunk_id]

    class _Embedder:
        def embed_documents(self, texts: list[str]) -> list[tuple[float, ...]]:
            return [(0.0,) * VECTOR_DIMENSIONS for _text in texts]

    def _to_indexed(row: object, vector: tuple[float, ...]) -> IndexedChunk:
        item = row
        catalogue_lane = str(item["lane"])  # type: ignore[index]
        return IndexedChunk(
            chunk_id=str(item["chunk_id"]),  # type: ignore[index]
            text=str(item["markdown_text"]),  # type: ignore[index]
            vector=vector,
            jurisdiction=Jurisdiction.ENGLAND_WALES,
            material_lane=(
                MaterialLane.PRIMARY_AUTHORITY
                if catalogue_lane == "primary_authority"
                else MaterialLane.OFFICIAL_GUIDANCE
            ),
            subject="general",
            review_state="approved",
            source_identity=str(item["stable_identifier"]),  # type: ignore[index]
            content_sha256=_digest(str(item["markdown_text"])),  # type: ignore[index]
            metadata={
                "source_version_id": str(item["source_version_id"]),  # type: ignore[index]
                "catalog_lane": catalogue_lane,
            },
        )

    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id="synthetic-ge-lane-test",
        build_id="synthetic-ge-lane-test",
        corpus_id=str(scope["corpus_id"]),
        manifest=manifest,
        source_ids=tuple(binding.source_version_id for binding in bindings),
        embedding_model="test-embedding",
        reranker_model="test-reranker",
        build_dir=settings.index_dir / "builds" / "synthetic-ge-lane-test",
        timings={},
        counts={},
    )
    chunks = list(
        _iter_scoped_chunks(
            ctx,
            _Embedder(),
            _to_indexed,
            lambda row: str(row["markdown_text"]),
        )
    )
    assert {chunk.material_lane for chunk in chunks} == {
        MaterialLane.PRIMARY_AUTHORITY,
        MaterialLane.OFFICIAL_GUIDANCE,
        MaterialLane.PROCEDURE_RULE,
    }


def test_ge_embedding_binding_preserves_guidance_and_procedure_labels() -> None:
    base = IndexedChunk(
        chunk_id="chunk-guidance",
        text="Official guidance.",
        vector=(0.0,) * VECTOR_DIMENSIONS,
        jurisdiction=Jurisdiction.ENGLAND_WALES,
        material_lane=MaterialLane.OFFICIAL_GUIDANCE,
        subject="general",
        review_state="approved",
        source_identity="official:guidance",
        content_sha256=_digest("Official guidance."),
        metadata={
            "source_version_id": "sv-guidance",
            "catalog_lane": "official_secondary",
        },
    )
    guidance_binding, procedure_binding = source_lane_bindings_for_manifest(
        {
                "selection_policy": "exact-owner-approved-ge-source-versions-and-lanes",
                "ge_expansion_mode": "strict_successor",
            "authority_lane_only": False,
            "approved_legal_source_lanes_only": True,
            "successor_must_remain_non_active": True,
            "answer_release_eligible": False,
            "active_or_previous_write_authorized": False,
            "promotion_authorized": False,
            "index_enqueue_authorized": False,
            "index_build_authorized": False,
            "ge_source_scope_content_sha256": "a" * 64,
            "ge_source_scope_owner_approval_digest": "b" * 64,
            "ge_source_scope_lanes": ["official_guidance", "official_procedure"],
                "source_count": 2,
                "ge_source_lane_bindings": [
                    {
                        "source_version_id": "sv-guidance",
                        "catalogue_lane": "official_secondary",
                        "scope_lane": "official_guidance",
                        "material_lane": "official_guidance",
                        "physical_lane": "authority",
                    },
                    {
                        "source_version_id": "sv-procedure",
                        "catalogue_lane": "official_secondary",
                        "scope_lane": "official_procedure",
                        "material_lane": "procedure_rule",
                        "physical_lane": "authority",
                    },
                ],
                "sources": [
                {
                    "source_version_id": "sv-guidance",
                    "lane": "official_secondary",
                    "ge_scope_lane": "official_guidance",
                },
                {
                    "source_version_id": "sv-procedure",
                    "lane": "official_secondary",
                    "ge_scope_lane": "official_procedure",
                },
            ],
        }
    )
    guidance = _apply_source_lane_binding(base, guidance_binding)
    procedure = _apply_source_lane_binding(
        replace(
            base,
            chunk_id="chunk-procedure",
            metadata={
                "source_version_id": "sv-procedure",
                "catalog_lane": "official_secondary",
            },
        ),
        procedure_binding,
    )

    assert guidance.material_lane is MaterialLane.OFFICIAL_GUIDANCE
    assert procedure.material_lane is MaterialLane.PROCEDURE_RULE
    assert procedure.metadata["catalog_lane"] == "official_secondary"


def test_ge_enqueue_requires_separate_exact_build_gate_and_freezes_lanes(
    database: Database, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path)
    _seed_pack_configuration(tmp_path)
    primary = _seed_source(
        database,
        tmp_path,
        key="enqueue-primary",
        catalogue_lane="primary_authority",
        material_type="legislation",
    )
    guidance = _seed_source(
        database,
        tmp_path,
        key="enqueue-guidance",
        catalogue_lane="official_secondary",
        material_type="official_guidance",
    )
    scope = _approved_scope(
        database,
        settings,
        [(primary, "primary_authority"), (guidance, "official_guidance")],
        run="enqueue-lanes",
    )
    corpus_id = str(scope["corpus_id"])
    settings.ensure_runtime_dirs()
    active_path = settings.index_dir / "ACTIVE.json"
    unrelated_manifest = settings.index_dir / "builds" / "unrelated-active-build" / "manifest.json"
    unrelated_manifest.parent.mkdir(parents=True)
    unrelated_manifest.write_text(
        json.dumps({"schema": "synthetic-unrelated-active.v1"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    active_path.write_text(
        json.dumps(
            {
                "build_id": "unrelated-active-build",
                "manifest_sha256": hashlib.sha256(
                    unrelated_manifest.read_bytes()
                ).hexdigest(),
                "promoted_at": NOW,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    active_before = active_path.read_bytes()
    with pytest.raises(ValueError, match="ge_successor_index_build_authorization_required"):
        enqueue_index_build(
            settings,
            database,
            corpus_id=corpus_id,
            build_id="ge-without-build-gate",
        )

    manifest = build_approved_source_manifest(database, settings, corpus_id=corpus_id)
    arbitrary_binding = ge_index_build_decision_binding(
        settings,
        database,
        manifest,
        build_id="ge-arbitrary-digest",
    )
    with pytest.raises(PermissionError, match="decision_unavailable"):
        enqueue_index_build(
            settings,
            database,
            corpus_id=corpus_id,
            build_id="ge-arbitrary-digest",
            ge_index_build_owner_decision_id=ge_index_build_decision_id(
                arbitrary_binding
            ),
            ge_index_build_owner_decision_content_sha256="f" * 64,
        )

    monkeypatch.setattr(
        ge_authorization_module,
        "_verify_trusted_ge_index_build_authorization_signature",
        lambda _request, _resolution: None,
    )
    fault_decision_id, fault_decision_content_sha256 = (
        _store_ge_index_build_authorization(
            database,
            settings,
            manifest,
            build_id="ge-with-fault-injection",
        )
    )
    with pytest.raises(ValueError, match="ge_successor_fault_injection_forbidden"):
        enqueue_index_build(
            settings,
            database,
            corpus_id=corpus_id,
            build_id="ge-with-fault-injection",
            fail_at_stage="embedding",
            ge_index_build_owner_decision_id=fault_decision_id,
            ge_index_build_owner_decision_content_sha256=(
                fault_decision_content_sha256
            ),
        )
    decision_id, decision_content_sha256 = _store_ge_index_build_authorization(
        database,
        settings,
        manifest,
        build_id="ge-with-build-gate",
    )
    with pytest.raises(PermissionError, match="decision_id_mismatch"):
        enqueue_index_build(
            settings,
            database,
            corpus_id=corpus_id,
            build_id="ge-substituted-build-id",
            ge_index_build_owner_decision_id=decision_id,
            ge_index_build_owner_decision_content_sha256=decision_content_sha256,
        )
    queued = enqueue_index_build(
        settings,
        database,
        corpus_id=corpus_id,
        build_id="ge-with-build-gate",
        ge_index_build_owner_decision_id=decision_id,
        ge_index_build_owner_decision_content_sha256=decision_content_sha256,
    )
    job = database.job(str(queued["job_id"]))
    assert job is not None
    request = json.loads(str(job["request_json"]))
    assert request["authority_lane_only"] is False
    assert request["approved_legal_source_lanes_only"] is True
    assert request["allowed_catalogue_lanes"] == [
        "official_secondary",
        "primary_authority",
    ]
    assert [item["material_lane"] for item in request["source_lane_bindings"]] == [
        "primary_authority",
        "official_guidance",
        "primary_authority",
    ]
    assert request["successor_must_remain_non_active"] is True
    assert "fail_at_stage" not in request
    assert request["ge_index_build_owner_decision_id"] == decision_id
    assert (
        request["ge_index_build_owner_decision_content_sha256"]
        == decision_content_sha256
    )
    assert request["ge_source_intake_chain_sha256"] == queued[
        "ge_source_intake_chain_sha256"
    ]
    assert active_path.read_bytes() == active_before
    assert not (settings.index_dir / "PREVIOUS.json").exists()

    claims = _integrity_source_lane_claims(manifest)
    assert claims["authority_lane_only"] is False
    assert claims["approved_legal_source_lanes_only"] is True
    build_models = database.fetchone(
        "SELECT embedding_model,reranker_model FROM index_builds WHERE id=?",
        (queued["build_id"],),
    )
    assert build_models is not None

    ctx = IndexBuildContext(
        settings=settings,
        database=database,
        job_id=str(queued["job_id"]),
        build_id=str(queued["build_id"]),
        corpus_id=corpus_id,
        manifest=manifest,
        source_ids=tuple(item["source_version_id"] for item in request["source_lane_bindings"]),
        embedding_model=str(build_models["embedding_model"]),
        reranker_model=str(build_models["reranker_model"]),
        build_dir=settings.index_dir / "builds" / str(queued["build_id"]),
        timings={},
        counts={},
        release_pointer_snapshot=request["release_pointer_snapshot_at_enqueue"],
    )
    changed = json.loads(json.dumps(request))
    changed["source_lane_bindings"][1]["material_lane"] = "primary_authority"
    with pytest.raises(IndexBuildStageError) as stopped:
        _require_enqueued_source_manifest_unchanged(ctx, changed)
    assert stopped.value.reason_code in {
        "source_lane_binding_invalid",
        "source_lane_binding_changed_after_enqueue",
    }
    fault_injected = json.loads(json.dumps(request))
    fault_injected["fail_at_stage"] = "embedding"
    with pytest.raises(IndexBuildStageError) as fault_stop:
        _require_enqueued_source_manifest_unchanged(ctx, fault_injected)
    assert fault_stop.value.reason_code == "ge_successor_fault_injection_forbidden"
    substituted = json.loads(json.dumps(request))
    substituted["ge_index_build_owner_decision_content_sha256"] = "0" * 64
    with pytest.raises(IndexBuildStageError) as substituted_stop:
        _require_enqueued_source_manifest_unchanged(ctx, substituted)
    assert (
        substituted_stop.value.reason_code
        == "ge_successor_index_build_authorization_invalid"
    )
    from app.retrieval.index_build import IndexBuildRunner

    IndexBuildRunner(settings, database)._mark_failed(
        ctx,
        "scanning",
        "synthetic_original_failure",
        RuntimeError("synthetic original failure"),
    )
    failed_build = database.fetchone(
        "SELECT failure_reason_code,metrics_json FROM index_builds WHERE id=?",
        (ctx.build_id,),
    )
    assert failed_build is not None
    assert failed_build["failure_reason_code"] == "synthetic_original_failure"
    metrics = json.loads(str(failed_build["metrics_json"]))
    assert metrics["release_pointer_state_unchanged"] is True
    assert active_path.read_bytes() == active_before
    from app.retrieval.index_recovery import (
        resume_ge_successor_index_build,
        resume_index_build,
    )

    with pytest.raises(PermissionError, match="dedicated_ge_index_recovery"):
        resume_index_build(settings, database, ctx.job_id)
    assert database.job(ctx.job_id)["status"] == "failed"
    resumed = resume_ge_successor_index_build(
        settings,
        database,
        ctx.job_id,
        decision_id=decision_id,
        decision_content_sha256=decision_content_sha256,
    )
    assert resumed["ge_authorization_replayed"] is True
    assert resumed["build_id"] == ctx.build_id
    assert database.job(ctx.job_id)["status"] == "queued"

    from app.retrieval.service import PHYSICAL_LANES, _prompt_safe_index_text, _tree_sha256

    bindings = source_lane_bindings_for_manifest(manifest)
    expected_rows = load_expected_index_rows(
        database,
        source_ids=ctx.source_ids,
        allowlists=manifest.get("locator_allowlists") or {},
        prompt_safe=_prompt_safe_index_text,
        source_lane_bindings=bindings,
    )
    assert len(expected_rows) == 3
    lance_rows = [
        {
            "chunk_id": row.chunk_id,
            "content_sha256": row.content_sha256,
            "source_version_id": row.source_version_id,
            "vector": [0.0] * VECTOR_DIMENSIONS,
            "lane_key": row.material_lane,
            "catalog_lane": row.catalogue_lane,
        }
        for row in expected_rows
    ]

    def _write_json(path: Path, value: dict[str, object]) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _file_digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_held_tree(
        path: Path,
        *,
        rows_by_lane: dict[str, list[dict[str, object]]],
        claimed_lane_counts: dict[str, int],
        claimed_chunk_count: int,
        fake_authority_table: bool = False,
    ) -> str:
        import lancedb

        for lane in PHYSICAL_LANES:
            lane_path = path / "lance" / lane
            lane_path.mkdir(parents=True, exist_ok=True)
            rows = rows_by_lane.get(lane) or []
            if rows:
                lancedb.connect(str(lane_path)).create_table(
                    "chunks", data=rows, mode="create"
                )
        if fake_authority_table:
            fake = path / "lance" / "authority" / "chunks.lance"
            fake.mkdir()
            (fake / "data.bin").write_bytes(b"not-a-lance-table")
        _write_json(
            path / "lance" / "physical-lanes.json",
            {
                "schema": "legalbot.physical-lanes.v1",
                "separated": True,
                "tables": {
                    lane: {"row_count": count}
                    for lane, count in claimed_lane_counts.items()
                },
            },
        )
        lance_tree_sha256 = _tree_sha256(path / "lance")
        _write_json(
            path / "manifest.json",
            {
                "schema": "legalbot.lance-build.v1",
                "build_id": ctx.build_id,
                "chunk_count": claimed_chunk_count,
                "embedding_model": ctx.embedding_model,
                "reranker_model": ctx.reranker_model,
                "source_manifest_sha256": manifest["manifest_sha256"],
            },
        )
        _write_json(path / "approved-source-manifest.json", manifest)
        privacy = {"schema": "legalbot.privacy-report.v1", "passed": True}
        _write_json(path / "privacy-report.json", privacy)
        _write_json(
            path / "evaluation.json",
            {
                "schema": "legalbot.index-evaluation.v2",
                "passed": True,
                "promotion_eligible": False,
                "scoped_corpus_id": corpus_id,
                "integrity": {
                    "approved_only": True,
                    **claims,
                    "successor_must_remain_non_active": True,
                    "chunk_count": claimed_chunk_count,
                    "vector_count": claimed_chunk_count,
                    "vector_dimensions": VECTOR_DIMENSIONS,
                    "source_manifest_sha256": manifest["manifest_sha256"],
                    "source_snapshot_stable": True,
                    "lance_tree_sha256": lance_tree_sha256,
                    "physical_lane_isolation": True,
                    "physical_lane_counts": claimed_lane_counts,
                },
                "privacy": privacy,
            },
        )
        _write_json(
            path / "seal.json",
            {
                "schema": "legalbot.index-seal.v2",
                "build_id": ctx.build_id,
                "promotion": "not_requested",
                "manifest_sha256": _file_digest(path / "manifest.json"),
                "evaluation_sha256": _file_digest(path / "evaluation.json"),
                "privacy_report_sha256": _file_digest(path / "privacy-report.json"),
                "source_manifest_file_sha256": _file_digest(
                    path / "approved-source-manifest.json"
                ),
                "physical_lane_manifest_sha256": _file_digest(
                    path / "lance" / "physical-lanes.json"
                ),
                "lance_tree_sha256": lance_tree_sha256,
            },
        )
        return _file_digest(path / "seal.json")

    lane_counts = {"authority": 3, "teaching": 0, "assessment": 0}
    final = settings.index_dir / "builds" / str(queued["build_id"])
    seal_sha256 = _write_held_tree(
        final,
        rows_by_lane={"authority": lance_rows},
        claimed_lane_counts=lane_counts,
        claimed_chunk_count=3,
    )
    _verify_held_ge_successor_tree(ctx, final, expected_seal_sha256=seal_sha256)
    _verify_held_ge_successor_tree(ctx, final, expected_seal_sha256=seal_sha256)

    corrupt_count = settings.index_dir / "builds" / "ge-held-corrupt-count"
    corrupt_count_seal = _write_held_tree(
        corrupt_count,
        rows_by_lane={"authority": lance_rows},
        claimed_lane_counts={"authority": 4, "teaching": 0, "assessment": 0},
        claimed_chunk_count=4,
    )
    with pytest.raises(RuntimeError, match="lance_inventory_mismatch"):
        _verify_held_ge_successor_tree(
            ctx, corrupt_count, expected_seal_sha256=corrupt_count_seal
        )

    cross_lane = settings.index_dir / "builds" / "ge-held-cross-lane"
    cross_lane_seal = _write_held_tree(
        cross_lane,
        rows_by_lane={"authority": lance_rows[:2], "teaching": [lance_rows[2]]},
        claimed_lane_counts={"authority": 2, "teaching": 1, "assessment": 0},
        claimed_chunk_count=3,
    )
    with pytest.raises(
        RuntimeError,
        match="ge_held_successor_(?:tree_verification_failed|physical_lane_inventory_invalid)",
    ):
        _verify_held_ge_successor_tree(
            ctx, cross_lane, expected_seal_sha256=cross_lane_seal
        )

    substituted_rows = [dict(row) for row in lance_rows]
    substituted_rows[1]["source_version_id"] = "sv-substituted-unapproved"
    substituted = settings.index_dir / "builds" / "ge-held-source-substitution"
    substituted_seal = _write_held_tree(
        substituted,
        rows_by_lane={"authority": substituted_rows},
        claimed_lane_counts=lane_counts,
        claimed_chunk_count=3,
    )
    with pytest.raises(RuntimeError, match="lance_inventory_mismatch"):
        _verify_held_ge_successor_tree(
            ctx, substituted, expected_seal_sha256=substituted_seal
        )

    fake_table = settings.index_dir / "builds" / "ge-held-fake-table"
    fake_table_seal = _write_held_tree(
        fake_table,
        rows_by_lane={},
        claimed_lane_counts=lane_counts,
        claimed_chunk_count=3,
        fake_authority_table=True,
    )
    with pytest.raises(Exception, match="lance|Lance|dataset|table|manifest"):
        _verify_held_ge_successor_tree(
            ctx, fake_table, expected_seal_sha256=fake_table_seal
        )

    database.execute(
        """
        UPDATE index_builds
        SET status='built_unscored', stage='built_unscored',
            promotion_decision='not_requested', promoted_at=NULL,
            candidate_manifest_hash=?, manifest_sha256=?, chunk_count=3,
            vector_count=3, counts_json=?
        WHERE id=?
        """,
        (
            seal_sha256,
            seal_sha256,
            json.dumps({"chunks_written": 3, "vectors": 3}, sort_keys=True),
            ctx.build_id,
        ),
    )
    database.execute(
        "UPDATE jobs SET status='complete', stage='built_unscored' WHERE id=?",
        (ctx.job_id,),
    )
    import app.retrieval.ge_evaluation_index as ge_evaluation_index_module
    import app.retrieval.service as retrieval_service_module
    from app.contracts import (
        CapabilityInput,
        ContractSchemaRegistry,
        build_runtime_capability_manifest,
    )
    from app.evaluation.visible_ge_admission import (
        VISIBLE_GE_OPERATION,
        VISIBLE_GE_REQUIRED_CAPABILITIES,
        VisibleGEExecutionBinding,
    )
    from app.retrieval.ge_evaluation_index import (
        GEEvaluationIndex,
        issue_visible_ge_index_capability,
        open_ge_evaluation_index,
        verify_ge_evaluation_index,
    )
    from app.retrieval.models import QueryFilters, SearchQuery

    capability_binding = VisibleGEExecutionBinding(
        candidate_sha256="1" * 64,
        model_sha256="2" * 64,
        prompt_sha256="3" * 64,
        renderer_sha256="4" * 64,
        validator_bundle_sha256="5" * 64,
        case_manifest_sha256="6" * 64,
        case_order_sha256="7" * 64,
        system_manifest_sha256="8" * 64,
        system_order_sha256="9" * 64,
        input_projection_sha256="a" * 64,
        factual_gate_policy_sha256="b" * 64,
        quality_gate_policy_sha256="c" * 64,
        gold_currentness_decision_sha256="d" * 64,
        development_private_root_capability_sha256="e" * 64,
        evaluation_authority_sha256="f" * 64,
        resource_policy_sha256="1" * 64,
        unseen_custody_ledger_sha256="2" * 64,
        iteration_plan_sha256="3" * 64,
        diagnostic_pack_sha256="4" * 64,
        ge_held_index_seal_sha256=seal_sha256,
        ge_source_manifest_sha256=manifest["manifest_sha256"],
        ge_source_scope_sha256=manifest["ge_source_scope_content_sha256"],
        ge_index_build_authorization_sha256=decision_content_sha256,
        ge_index_build_owner_decision_id_sha256=hashlib.sha256(
            decision_id.encode("utf-8")
        ).hexdigest(),
        ge_source_intake_chain_sha256=request["ge_source_intake_chain_sha256"],
    )
    capability_registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    capability_created = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
    capability_expires = datetime(2026, 9, 1, 1, 10, tzinfo=UTC)
    capability_now = [datetime(2026, 9, 1, 1, 1, tzinfo=UTC)]
    capability_manifest = build_runtime_capability_manifest(
        process_role="evaluation_harness",
        process_instance_id="ge-evaluation-harness-test",
        config_sha256="0" * 64,
        environment_sha256="1" * 64,
        capabilities=[
            CapabilityInput(
                name=name,
                status="PASS",
                evidence_sha256=hashlib.sha256(name.encode("utf-8")).hexdigest(),
                reason_code="verified",
                checked_at=capability_created,
                valid_until=capability_expires,
            )
            for name in VISIBLE_GE_REQUIRED_CAPABILITIES
        ],
        operation_requirements={
            VISIBLE_GE_OPERATION: VISIBLE_GE_REQUIRED_CAPABILITIES,
        },
        bound_artifacts=capability_binding.bound_artifacts(),
        created_at=capability_created,
        expires_at=capability_expires,
        registry=capability_registry,
    )
    capability_sha256 = str(capability_manifest["manifest_sha256"])
    monkeypatch.setattr(
        ge_evaluation_index_module,
        "_utc_now",
        lambda: capability_now[0],
    )
    capability = issue_visible_ge_index_capability(
        capability_manifest,
        expected_manifest_sha256=capability_sha256,
        expected_process_instance_id="ge-evaluation-harness-test",
        expected_config_sha256="0" * 64,
        expected_environment_sha256="1" * 64,
        binding=capability_binding,
        registry=capability_registry,
    )
    verified = verify_ge_evaluation_index(
        settings,
        database,
        build_id=ctx.build_id,
        capability=capability,
    )
    assert verified.build_authorization_decision_id == decision_id
    assert verified.capability_manifest_sha256 == capability_sha256
    forged_duck_capability = SimpleNamespace(
        require_current=lambda: capability_sha256,
        binding=capability_binding,
    )
    with pytest.raises(TypeError, match="not verifier-issued"):
        verify_ge_evaluation_index(
            settings,
            database,
            build_id=ctx.build_id,
            capability=forged_duck_capability,  # type: ignore[arg-type]
        )

    with pytest.raises(TypeError, match="cannot be subclassed"):
        type(
            "OverridingVisibleGEIndexCapability",
            (ge_evaluation_index_module.VisibleGEIndexCapabilityContext,),
            {"require_current": lambda self: capability_sha256},
        )
    with pytest.raises(TypeError, match="cannot be subclassed"):
        type(
            "OverridingGEEvaluationIndex",
            (GEEvaluationIndex,),
            {"search": lambda self, query: ()},
        )

    class _FakeTable:
        @staticmethod
        def count_rows() -> int:
            return 3

    class _FakeConnection:
        @staticmethod
        def open_table(_name: str) -> _FakeTable:
            return _FakeTable()

    class _FakeLanceModule:
        @staticmethod
        def connect(_path: str) -> _FakeConnection:
            return _FakeConnection()

    class _FactoryRetriever:
        def __init__(self, **_kwargs: object) -> None:
            self.search_count = 0

        def search(self, _query: SearchQuery) -> tuple[()]:
            self.search_count += 1
            return ()

    monkeypatch.setattr(retrieval_service_module, "_import_lancedb", lambda: _FakeLanceModule())
    monkeypatch.setattr(
        retrieval_service_module,
        "_embedding_provider",
        lambda _settings, _model: object(),
    )
    monkeypatch.setattr(
        retrieval_service_module,
        "_reranker_provider",
        lambda _settings, _model: object(),
    )
    monkeypatch.setattr(
        ge_evaluation_index_module.CandidateLegislationReferenceResolver,
        "from_path",
        staticmethod(lambda _path: None),
    )
    monkeypatch.setattr(ge_evaluation_index_module, "HybridRetriever", _FactoryRetriever)
    opened = open_ge_evaluation_index(
        settings,
        database,
        build_id=ctx.build_id,
        as_of_date=capability_created.date(),
        capability=capability,
    )
    query = SearchQuery(
        text="What is the legal position?",
        filters=QueryFilters(
            jurisdictions=frozenset({Jurisdiction.ENGLAND_WALES}),
            material_lanes=frozenset({MaterialLane.PRIMARY_AUTHORITY}),
        ),
        limit=1,
        candidate_limit=1,
    )
    assert opened.search(query) == ()
    factory_retriever = opened._retriever
    assert factory_retriever.search_count == 1
    with pytest.raises(TypeError, match="factory-issued only"):
        GEEvaluationIndex(
            binding=verified,
            capability=capability,
            retriever=factory_retriever,
            require_owner_authorization=lambda: None,
            connection=object(),
        )
    with pytest.raises(AttributeError, match="inputs are frozen"):
        capability._expected_manifest_sha256 = "0" * 64
    with pytest.raises(AttributeError, match="binding is frozen"):
        opened._require_owner_authorization = lambda: None

    database.execute(
        "UPDATE index_builds SET candidate_manifest_hash=? WHERE id=?",
        ("0" * 64, ctx.build_id),
    )
    with pytest.raises(RuntimeError, match="not sealed non-ACTIVE held evidence"):
        opened.search(query)
    assert factory_retriever.search_count == 1
    database.execute(
        "UPDATE index_builds SET candidate_manifest_hash=? WHERE id=?",
        (seal_sha256, ctx.build_id),
    )
    capability_now[0] = capability_expires
    with pytest.raises(RuntimeError, match="validity window"):
        opened.search(query)
    assert factory_retriever.search_count == 1
