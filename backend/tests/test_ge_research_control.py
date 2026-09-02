from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.contracts import seal_contract
from app.crypto import LocalCipher
from app.db import Database, utc_iso
from app.evaluation.ge_improvement_loop import (
    GEDiagnosisInput,
    build_diagnosis,
    build_official_research_intent,
)
from app.evaluation.ge_research_control import (
    ADAPTER_REQUIRED_HOLD,
    GEOfficialResearchAdmission,
    GEOfficialResearchControlError,
    GEOfficialResearchHold,
    admit_ge_official_research,
    build_verified_ge_source_provenance,
    load_ge_source_provenance_components,
    validate_verified_ge_source_provenance,
)
from app.evaluation.ge_visible_harness import FACTUAL_CHECKS
from app.orchestration.object_store import EncryptedObjectStore
from app.research.control_plane import ResearchControlPlane
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
from app.research.review import ResearchReviewService
from app.research.source_intake_bridge import (
    ResearchSourceIntakeBridge,
    StagedSourceIntake,
)
from app.research.source_registry import OfficialSourceRegistry
from app.research.worker import EncryptedResearchQuarantine
from app.retrieval.source_manifest import approved_source_manifest_sha256

_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config" / "official_sources.json"
_CANDIDATE_BUILD_ID = "candidate-ge-research-control"
_CASE_ID = "ge-visible-case-research-001"
_DIAGNOSIS_ID = "ge-diagnosis-research-001"
_QUERY = "contract"
_QUERY_SHA256 = hashlib.sha256(_QUERY.encode()).hexdigest()
_PROPOSITION_SHA256 = hashlib.sha256(b"missing material statutory rule").hexdigest()
_ORDINARY_SOURCE_MANIFEST = {
    "schema": "legalbot.approved-source-manifest.v1",
    "selection_policy": "synthetic-ordinary-candidate",
    "sources": [],
    "successor_must_remain_non_active": False,
}
_SOURCE_MANIFEST_SHA256 = approved_source_manifest_sha256(
    _ORDINARY_SOURCE_MANIFEST
)
_CHUNK_ID = "chunk-ge-gap-proof-1"


def _ensure_candidate_tree(root: Path, build_id: str) -> CandidateBuildBinding:
    build_root = root / "data/indexes/builds" / build_id
    authority = build_root / "lance" / "authority"
    if not authority.is_dir():
        authority.mkdir(parents=True)
        import lancedb

        lancedb.connect(str(authority)).create_table(
            "chunks",
            data=[
                {
                    "chunk_id": _CHUNK_ID,
                    "source_version_id": "source-version-ge-gap-proof-1",
                    "content_sha256": "d" * 64,
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
            "build_id": build_id,
            "source_manifest_sha256": _SOURCE_MANIFEST_SHA256,
            "chunk_count": 1,
            "sealed": True,
        }
        manifest_path = build_root / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8"
        )
        source_manifest = {
            **_ORDINARY_SOURCE_MANIFEST,
            "manifest_sha256": _SOURCE_MANIFEST_SHA256,
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
            "build_id": build_id,
            "manifest_sha256": _file_sha256(manifest_path),
            "source_manifest_file_sha256": _file_sha256(source_manifest_path),
            "lance_tree_sha256": _tree_sha256(build_root / "lance"),
        }
        (build_root / "seal.json").write_text(
            json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8"
        )
    return CandidateBuildBinding(
        candidate_build_id=build_id,
        candidate_seal_sha256=_file_sha256(build_root / "seal.json"),
        source_manifest_sha256=_SOURCE_MANIFEST_SHA256,
    )


class _NoMaterialSupportExecutor:
    def __call__(self, request: Any) -> CandidateRetrievalExecutorResult:
        return CandidateRetrievalExecutorResult(
            invocation_id="ge-retrieval-invocation-001",
            candidate_build_id=request.candidate_build_id,
            candidate_rows_examined=1,
            ranked_hits=(
                CandidateRetrievalExecutorHit(
                    chunk_id=_CHUNK_ID,
                    qualification_disposition=(
                        HitQualificationDisposition.NO_MATERIAL_SUPPORT
                    ),
                ),
            ),
        )


@dataclass(frozen=True, slots=True)
class _ProvedGap:
    control: ResearchControlPlane
    result: dict[str, Any]
    diagnosis: dict[str, Any]
    intent: dict[str, Any]
    artifact_sha256: str


def _control(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher | None,
    *,
    source_root: Path | None = None,
) -> ResearchControlPlane:
    return ResearchControlPlane(
        Settings(
            project_root=tmp_path,
            test_mode=True,
            explicit_source_roots=((source_root,) if source_root is not None else None),
        ),
        database,
        cipher=cipher,
        registry=OfficialSourceRegistry.load(_REGISTRY_PATH),
        candidate_binding_loader=lambda _settings, _database, build_id: (
            _ensure_candidate_tree(tmp_path, build_id)
        ),
    )


def _proved_gap(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    *,
    materiality: str = "material",
    artifact_sha256: str | None = None,
) -> _ProvedGap:
    binding = _ensure_candidate_tree(tmp_path, _CANDIDATE_BUILD_ID)
    if database.fetchone("SELECT id FROM index_builds WHERE id=?", (_CANDIDATE_BUILD_ID,)) is None:
        database.execute(
            """
            INSERT INTO index_builds(
              id, status, path, embedding_model, reranker_model,
              source_manifest_hash, created_at
            ) VALUES (?, 'candidate', ?, ?, ?, ?, ?)
            """,
            (
                _CANDIDATE_BUILD_ID,
                f"data/indexes/builds/{_CANDIDATE_BUILD_ID}",
                "embedding-model@ge-research-test",
                "reranker-model@ge-research-test",
                _SOURCE_MANIFEST_SHA256,
                utc_iso(),
            ),
        )
    if artifact_sha256 is None:
        artifact = execute_candidate_retrieval_attempt(
            settings=Settings(project_root=tmp_path, test_mode=True),
            binding=RetrievalAttemptBinding(
                candidate_build_id=_CANDIDATE_BUILD_ID,
                candidate_seal_sha256=binding.candidate_seal_sha256,
                source_manifest_sha256=binding.source_manifest_sha256,
                case_ref=opaque_gap_reference("case", _CASE_ID),
                issue_ref=opaque_gap_reference("issue", _DIAGNOSIS_ID),
                subject="contract",
                jurisdiction="England and Wales",
                as_of_date=date(2026, 9, 1),
                proposition_sha256=_PROPOSITION_SHA256,
                query_sha256=_QUERY_SHA256,
            ),
            canonical_query=_QUERY,
            executor=_NoMaterialSupportExecutor(),
            created_at=datetime(2026, 9, 1, 8, 0, tzinfo=UTC),
        )
        artifact_sha256 = artifact.artifact_sha256
    factual_checks = dict.fromkeys(FACTUAL_CHECKS, "PASS")
    factual_checks["claim_evidence_support"] = "FAIL"
    result = seal_contract(
        {
            "schema": "legalbot.evaluation-case-result.v2",
            "case_id": _CASE_ID,
            "case_version_sha256": "b" * 64,
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
            diagnosis_id=_DIAGNOSIS_ID,
            case_id=_CASE_ID,
            case_kind="visible",
            failure_class="factual",
            scenario_family_id="ge-family-contract",
            case_version_sha256="b" * 64,
            materiality=materiality,  # type: ignore[arg-type]
            finding_sha256="c" * 64,
            knowledge_or_source_gap=True,
            subject="contract",
            jurisdiction="England and Wales",
            as_of_date=date(2026, 9, 1),
            retrieval_query_sha256=_QUERY_SHA256,
            proposition_sha256=_PROPOSITION_SHA256,
            retrieval_attempt_artifact_sha256=artifact_sha256,
        ),
        diagnosed_result=result,
    )
    intent = build_official_research_intent(
        diagnosis=diagnosis,
        diagnosed_result=result,
        candidate_build_id=_CANDIDATE_BUILD_ID,
    )
    return _ProvedGap(
        control=_control(tmp_path, database, cipher),
        result=result,
        diagnosis=diagnosis,
        intent=intent,
        artifact_sha256=artifact_sha256,
    )


def _counts(database: Database) -> tuple[int, int]:
    gaps = int(database.fetchone("SELECT COUNT(*) AS n FROM research_gap_bindings")["n"])
    tasks = int(database.fetchone("SELECT COUNT(*) AS n FROM research_tasks")["n"])
    return gaps, tasks


@dataclass(frozen=True, slots=True)
class _SourceChainFixture:
    proved: _ProvedGap
    control: ResearchControlPlane
    admission: GEOfficialResearchAdmission
    receipt: StagedSourceIntake
    provenance: dict[str, Any]


def _source_chain_fixture(
    tmp_path: Path, database: Database, cipher: LocalCipher
) -> _SourceChainFixture:
    proved = _proved_gap(tmp_path, database, cipher)
    source_root = tmp_path / "permitted-source-root"
    source_root.mkdir()
    control = _control(tmp_path, database, cipher, source_root=source_root)
    admission = admit_ge_official_research(
        control_plane=control,
        diagnosis=proved.diagnosis,
        diagnosed_result=proved.result,
        sealed_intent=proved.intent,
        candidate_build_id=_CANDIDATE_BUILD_ID,
        source_id="legislation_gov_uk",
    )
    assert isinstance(admission, GEOfficialResearchAdmission)

    content = b"""<?xml version='1.0' encoding='UTF-8'?>
    <Legislation xmlns='http://www.legislation.gov.uk/namespaces/legislation'
      xmlns:dc='http://purl.org/dc/elements/1.1/'
      DocumentURI='http://www.legislation.gov.uk/ukpga/2026/1'>
      <Metadata><dc:title>Example Act 2026</dc:title>
        <dc:modified>2026-09-01</dc:modified></Metadata>
      <Body><Part DocumentURI='http://www.legislation.gov.uk/ukpga/2026/1/part/1'>
        <Number>PART 1</Number><Title>General provision</Title>
        <P1 DocumentURI='http://www.legislation.gov.uk/ukpga/2026/1/section/1'>
          <Pnumber>1</Pnumber><P1para><Text>The material statutory rule applies.</Text></P1para>
        </P1>
      </Part></Body>
    </Legislation>"""
    content_sha256 = hashlib.sha256(content).hexdigest()
    objects = EncryptedObjectStore(control.settings.runtime_object_dir, database, cipher)
    object_key = EncryptedResearchQuarantine(objects).store(
        source_id="legislation_gov_uk",
        source_identity="ukpga:2026:1",
        content=content,
        content_sha256=content_sha256,
    )
    safe_metadata = {
        "content_type": "application/xml",
        "disposition": "staged_only",
        "response_sha256": content_sha256,
        "owner_decision_required": True,
    }
    metadata_sha256 = hashlib.sha256(
        json.dumps(safe_metadata, sort_keys=True).encode("utf-8")
    ).hexdigest()
    candidate_id = "candidate-ge-source-chain-001"
    database.add_research_candidate(
        candidate_id=candidate_id,
        task_id=admission.task_id,
        source_id="legislation_gov_uk",
        source_identity="ukpga:2026:1",
        canonical_url="https://www.legislation.gov.uk/ukpga/2026/1/data.xml",
        metadata_sha256=metadata_sha256,
        content_sha256=content_sha256,
        content_object_key=object_key,
        status="quarantined",
        rights_state="unreviewed",
        safe_metadata=safe_metadata,
    )
    database.mark_staged_research_task_for_review(admission.task_id)
    review = ResearchReviewService(control.settings, database)
    review.system_verify_candidate(candidate_id)
    review.review_candidate(
        candidate_id,
        decision="accept_for_source_intake",
        rights_state="verified",
        identity_review_state="candidate_matched",
        currentness_review_state="verified",
        reviewer_ref=f"reviewer:{'b' * 64}",
        review_manifest_sha256="c" * 64,
    )
    receipt = ResearchSourceIntakeBridge(
        control.settings,
        database,
        cipher,
        objects=objects,
        registry=OfficialSourceRegistry.load(_REGISTRY_PATH),
    ).intake(candidate_id, source_root=source_root)
    provenance = build_verified_ge_source_provenance(
        control_plane=control,
        diagnosis=proved.diagnosis,
        diagnosed_result=proved.result,
        sealed_intent=proved.intent,
        research_admission=admission,
        source_intake_receipt=receipt,
    )
    return _SourceChainFixture(
        proved=proved,
        control=control,
        admission=admission,
        receipt=receipt,
        provenance=provenance,
    )


def test_exact_material_gap_is_idempotently_logged_and_queued_staging_only(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    proved = _proved_gap(tmp_path, database, cipher)

    first = admit_ge_official_research(
        control_plane=proved.control,
        diagnosis=proved.diagnosis,
        diagnosed_result=proved.result,
        sealed_intent=proved.intent,
        candidate_build_id=_CANDIDATE_BUILD_ID,
        source_id="legislation_gov_uk",
    )
    replay = admit_ge_official_research(
        control_plane=proved.control,
        diagnosis=proved.diagnosis,
        diagnosed_result=proved.result,
        sealed_intent=proved.intent,
        candidate_build_id=_CANDIDATE_BUILD_ID,
        source_id="legislation_gov_uk",
    )

    assert isinstance(first, GEOfficialResearchAdmission)
    assert replay == first
    assert first.task_status == "queued"
    assert first.staging_only
    assert first.source_id == "legislation_gov_uk"
    assert first.candidate_build_id == _CANDIDATE_BUILD_ID
    assert first.query_sha256 == _QUERY_SHA256
    assert first.retrieval_attempt_artifact_sha256 == proved.artifact_sha256
    assert first.network_action_performed is False
    assert first.source_admission_authorized is False
    assert first.promotion_authorized is False
    assert _counts(database) == (1, 1)

    gap = database.research_gap_binding(first.gap_id)
    task = database.research_task(first.task_id)
    assert gap is not None and task is not None
    assert gap["candidate_build_id"] == _CANDIDATE_BUILD_ID
    assert gap["materiality"] == "material"
    assert gap["attempted_retrieval_sha256"] == proved.artifact_sha256
    assert task["task_type"] == "gap_research"
    assert task["trigger_kind"] == "enquiry"
    assert task["source_id"] == "legislation_gov_uk"
    assert task["query_sha256"] == _QUERY_SHA256
    assert task["encrypted_query"] is None
    assert task["pinned_index_build_id"] == _CANDIDATE_BUILD_ID
    detail = json.loads(cipher.decrypt_text(bytes(gap["encrypted_detail"])))
    assert set(detail) == {
        "schema",
        "diagnosis_id",
        "failure_class",
        "failure_code",
        "failure_fingerprint_sha256",
        "finding_sha256",
        "result_sha256",
        "intent_sha256",
    }
    assert database.active_index_id() is None
    assert database.fetchone("SELECT COUNT(*) AS n FROM documents")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM chunks")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_candidates")["n"] == 0


def test_intent_candidate_and_materiality_gates_fail_before_writes(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    proved = _proved_gap(tmp_path, database, cipher)
    tampered = seal_contract(
        {**proved.intent, "retrieval_query_sha256": "f" * 64}
    )
    with pytest.raises(GEOfficialResearchControlError) as intent_error:
        admit_ge_official_research(
            control_plane=proved.control,
            diagnosis=proved.diagnosis,
            diagnosed_result=proved.result,
            sealed_intent=tampered,
            candidate_build_id=_CANDIDATE_BUILD_ID,
            source_id="legislation_gov_uk",
        )
    assert intent_error.value.code == "GE_RESEARCH_INTENT_REPLAY_MISMATCH"

    with pytest.raises(GEOfficialResearchControlError) as candidate_error:
        admit_ge_official_research(
            control_plane=proved.control,
            diagnosis=proved.diagnosis,
            diagnosed_result=proved.result,
            sealed_intent=proved.intent,
            candidate_build_id="candidate-ge-research-different",
            source_id="legislation_gov_uk",
        )
    assert candidate_error.value.code == "GE_RESEARCH_INTENT_REPLAY_MISMATCH"

    potential = _proved_gap(
        tmp_path,
        database,
        cipher,
        materiality="potentially_material",
        artifact_sha256=proved.artifact_sha256,
    )
    with pytest.raises(GEOfficialResearchControlError) as materiality_error:
        admit_ge_official_research(
            control_plane=potential.control,
            diagnosis=potential.diagnosis,
            diagnosed_result=potential.result,
            sealed_intent=potential.intent,
            candidate_build_id=_CANDIDATE_BUILD_ID,
            source_id="legislation_gov_uk",
        )
    assert materiality_error.value.code == "GE_RESEARCH_GAP_NOT_MATERIAL"
    assert _counts(database) == (0, 0)


def test_sealed_retrieval_attempt_mismatch_fails_before_task(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    proved = _proved_gap(
        tmp_path,
        database,
        cipher,
        artifact_sha256="e" * 64,
    )
    with pytest.raises(GEOfficialResearchControlError) as exc_info:
        admit_ge_official_research(
            control_plane=proved.control,
            diagnosis=proved.diagnosis,
            diagnosed_result=proved.result,
            sealed_intent=proved.intent,
            candidate_build_id=_CANDIDATE_BUILD_ID,
            source_id="legislation_gov_uk",
        )
    assert exc_info.value.code == "GE_RESEARCH_GAP_ADMISSION_FAILED"
    assert "artifact root is missing" in str(exc_info.value)
    assert _counts(database) == (0, 0)


def test_registered_primary_source_without_adapter_returns_write_free_hold(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    proved = _proved_gap(tmp_path, database, cipher)
    result = admit_ge_official_research(
        control_plane=proved.control,
        diagnosis=proved.diagnosis,
        diagnosed_result=proved.result,
        sealed_intent=proved.intent,
        candidate_build_id=_CANDIDATE_BUILD_ID,
        source_id="eur_lex",
    )

    assert isinstance(result, GEOfficialResearchHold)
    assert result.hold_code == ADAPTER_REQUIRED_HOLD
    assert result.source_id == "eur_lex"
    assert result.research_gap_created is False
    assert result.research_task_created is False
    assert _counts(database) == (0, 0)


@pytest.mark.parametrize(
    ("source_id", "error_code"),
    [
        ("open_scholarship_discovery", "GE_RESEARCH_PRIMARY_AUTHORITY_REQUIRED"),
        ("gov_uk", "GE_RESEARCH_PRIMARY_AUTHORITY_REQUIRED"),
        ("find_case_law", "GE_RESEARCH_RIGHTS_OWNER_DECISION_REQUIRED"),
        ("not_registered", "GE_RESEARCH_SOURCE_NOT_REGISTERED"),
    ],
)
def test_non_authority_unregistered_or_rights_ambiguous_source_fails_closed(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    source_id: str,
    error_code: str,
) -> None:
    proved = _proved_gap(tmp_path, database, cipher)
    with pytest.raises(GEOfficialResearchControlError) as exc_info:
        admit_ge_official_research(
            control_plane=proved.control,
            diagnosis=proved.diagnosis,
            diagnosed_result=proved.result,
            sealed_intent=proved.intent,
            candidate_build_id=_CANDIDATE_BUILD_ID,
            source_id=source_id,
        )
    assert exc_info.value.code == error_code
    assert _counts(database) == (0, 0)


def test_missing_cipher_or_changed_diagnosed_result_fails_before_writes(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    proved = _proved_gap(tmp_path, database, cipher)
    without_cipher = replace(proved, control=_control(tmp_path, database, None))
    with pytest.raises(GEOfficialResearchControlError) as cipher_error:
        admit_ge_official_research(
            control_plane=without_cipher.control,
            diagnosis=without_cipher.diagnosis,
            diagnosed_result=without_cipher.result,
            sealed_intent=without_cipher.intent,
            candidate_build_id=_CANDIDATE_BUILD_ID,
            source_id="legislation_gov_uk",
        )
    assert cipher_error.value.code == "GE_RESEARCH_ENCRYPTED_GAP_GATE_MISSING"

    changed_result = seal_contract(
        {
            **proved.result,
            "factual_outcome": "FACTUAL_PASS",
            "quality_outcome": "MEETS_70_STANDARD",
        }
    )
    with pytest.raises(GEOfficialResearchControlError) as result_error:
        admit_ge_official_research(
            control_plane=proved.control,
            diagnosis=proved.diagnosis,
            diagnosed_result=changed_result,
            sealed_intent=proved.intent,
            candidate_build_id=_CANDIDATE_BUILD_ID,
            source_id="legislation_gov_uk",
        )
    assert result_error.value.code == "GE_RESEARCH_EVIDENCE_INVALID"
    assert _counts(database) == (0, 0)


def test_provenance_chain_replays_both_exact_ends_and_remains_non_authorizing(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    fixture = _source_chain_fixture(tmp_path, database, cipher)
    before = {
        table: int(database.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"])
        for table in (
            "research_gap_bindings",
            "research_tasks",
            "research_candidates",
            "source_versions",
            "chunks",
            "reviews",
            "index_builds",
        )
    }

    replay = build_verified_ge_source_provenance(
        control_plane=fixture.control,
        diagnosis=fixture.proved.diagnosis,
        diagnosed_result=fixture.proved.result,
        sealed_intent=fixture.proved.intent,
        research_admission=fixture.admission,
        source_intake_receipt=fixture.receipt,
    )
    validate_verified_ge_source_provenance(
        fixture.provenance,
        control_plane=fixture.control,
        diagnosis=fixture.proved.diagnosis,
        diagnosed_result=fixture.proved.result,
        sealed_intent=fixture.proved.intent,
        research_admission=fixture.admission,
        source_intake_receipt=fixture.receipt,
    )

    assert replay == fixture.provenance
    assert fixture.provenance["diagnosis_sha256"] == (
        fixture.proved.diagnosis["content_sha256"]
    )
    assert fixture.provenance["failure_fingerprint_sha256"] == (
        fixture.proved.diagnosis["failure_fingerprint_sha256"]
    )
    assert fixture.provenance["research_intent_sha256"] == (
        fixture.proved.intent["content_sha256"]
    )
    assert fixture.provenance["candidate_build_id"] == _CANDIDATE_BUILD_ID
    assert fixture.provenance["retrieval_query_sha256"] == _QUERY_SHA256
    assert fixture.provenance["proposition_sha256"] == _PROPOSITION_SHA256
    assert fixture.provenance["retrieval_attempt_artifact_sha256"] == (
        fixture.proved.artifact_sha256
    )
    assert fixture.provenance["source_object_sha256"] == fixture.receipt.content_sha256
    assert fixture.provenance["source_chunk_count"] >= 1
    assert fixture.provenance["source_state"] == "STAGED_PENDING_SOURCE_ADMISSION"
    assert fixture.provenance["source_identity_verified_for_index"] is False
    assert fixture.provenance["source_currentness_verified_for_index"] is False
    assert fixture.provenance["source_authority_eligible_for_index"] is False
    assert fixture.provenance["writes_active"] is False
    assert fixture.provenance["enqueues_embedding"] is False
    assert fixture.provenance["trains_model"] is False
    after = {
        table: int(database.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"])
        for table in before
    }
    assert after == before

    components = load_ge_source_provenance_components(
        control_plane=fixture.control,
        artifact_sha256=str(
            fixture.provenance["component_receipt_artifact_sha256"]
        ),
    )
    assert components["diagnosis"] == fixture.proved.diagnosis
    assert components["diagnosed_result"] == fixture.proved.result
    assert components["research_intent"] == fixture.proved.intent
    assert components["source_intake_receipt"]["intake_id"] == (
        fixture.receipt.intake_id
    )
    assert components["authorizes_source_admission"] is False
    assert components["authorizes_indexing"] is False
    assert components["authorizes_promotion"] is False

    forged = seal_contract({**fixture.provenance, "proposition_sha256": "f" * 64})
    with pytest.raises(GEOfficialResearchControlError) as forged_error:
        validate_verified_ge_source_provenance(
            forged,
            control_plane=fixture.control,
            diagnosis=fixture.proved.diagnosis,
            diagnosed_result=fixture.proved.result,
            sealed_intent=fixture.proved.intent,
            research_admission=fixture.admission,
            source_intake_receipt=fixture.receipt,
        )
    assert forged_error.value.code == "GE_SOURCE_CHAIN_REPLAY_DIFFERED"


def test_provenance_chain_rejects_changed_private_component_receipt_bytes(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    fixture = _source_chain_fixture(tmp_path, database, cipher)
    artifact_sha256 = str(
        fixture.provenance["component_receipt_artifact_sha256"]
    )
    artifact_path = (
        tmp_path
        / "data/evaluations/research/ge-source-provenance-components"
        / f"{artifact_sha256}.json"
    )
    artifact_path.write_bytes(artifact_path.read_bytes() + b" ")
    artifact_path.chmod(0o600)

    with pytest.raises(GEOfficialResearchControlError) as error:
        validate_verified_ge_source_provenance(
            fixture.provenance,
            control_plane=fixture.control,
            diagnosis=fixture.proved.diagnosis,
            diagnosed_result=fixture.proved.result,
            sealed_intent=fixture.proved.intent,
            research_admission=fixture.admission,
            source_intake_receipt=fixture.receipt,
        )
    assert error.value.code == "GE_SOURCE_CHAIN_COMPONENT_ARTIFACT_COLLISION"


def test_provenance_chain_rejects_orphan_and_exact_object_or_record_drift(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    fixture = _source_chain_fixture(tmp_path, database, cipher)
    orphan = replace(fixture.receipt, task_id="research-orphan-substitution")
    with pytest.raises(GEOfficialResearchControlError) as orphan_error:
        build_verified_ge_source_provenance(
            control_plane=fixture.control,
            diagnosis=fixture.proved.diagnosis,
            diagnosed_result=fixture.proved.result,
            sealed_intent=fixture.proved.intent,
            research_admission=fixture.admission,
            source_intake_receipt=orphan,
        )
    assert orphan_error.value.code == "GE_SOURCE_CHAIN_RECEIPT_REPLAY_FAILED"

    database.execute(
        "UPDATE research_tasks SET query_sha256=? WHERE id=?",
        ("f" * 64, fixture.admission.task_id),
    )
    with pytest.raises(GEOfficialResearchControlError) as task_error:
        validate_verified_ge_source_provenance(
            fixture.provenance,
            control_plane=fixture.control,
            diagnosis=fixture.proved.diagnosis,
            diagnosed_result=fixture.proved.result,
            sealed_intent=fixture.proved.intent,
            research_admission=fixture.admission,
            source_intake_receipt=fixture.receipt,
        )
    assert task_error.value.code == "GE_SOURCE_CHAIN_CONTROL_RECORD_REPLAY_FAILED"
    database.execute(
        "UPDATE research_tasks SET query_sha256=? WHERE id=?",
        (_QUERY_SHA256, fixture.admission.task_id),
    )

    artifact_path = (
        tmp_path
        / "data/evaluations/research/candidate-retrieval-attempts"
        / f"{fixture.proved.artifact_sha256}.json"
    )
    original_artifact = artifact_path.read_bytes()
    artifact_path.write_bytes(original_artifact + b" ")
    artifact_path.chmod(0o600)
    with pytest.raises(GEOfficialResearchControlError) as retrieval_error:
        validate_verified_ge_source_provenance(
            fixture.provenance,
            control_plane=fixture.control,
            diagnosis=fixture.proved.diagnosis,
            diagnosed_result=fixture.proved.result,
            sealed_intent=fixture.proved.intent,
            research_admission=fixture.admission,
            source_intake_receipt=fixture.receipt,
        )
    assert retrieval_error.value.code == "GE_SOURCE_CHAIN_RETRIEVAL_OBJECT_REPLAY_FAILED"
    artifact_path.write_bytes(original_artifact)
    artifact_path.chmod(0o600)

    source_version = database.fetchone(
        "SELECT metadata_json FROM source_versions WHERE id=?",
        (fixture.receipt.source_version_id,),
    )
    assert source_version is not None
    metadata = json.loads(source_version["metadata_json"])
    wrong_object = tmp_path / "data/vault/objects/sha256/bad-source-object"
    wrong_object.parent.mkdir(parents=True, exist_ok=True)
    wrong_object.write_bytes(b"different source bytes")
    metadata["raw_vault_path"] = wrong_object.relative_to(tmp_path).as_posix()
    database.execute(
        "UPDATE source_versions SET metadata_json=? WHERE id=?",
        (json.dumps(metadata, ensure_ascii=False, sort_keys=True), fixture.receipt.source_version_id),
    )
    with pytest.raises(GEOfficialResearchControlError) as source_error:
        validate_verified_ge_source_provenance(
            fixture.provenance,
            control_plane=fixture.control,
            diagnosis=fixture.proved.diagnosis,
            diagnosed_result=fixture.proved.result,
            sealed_intent=fixture.proved.intent,
            research_admission=fixture.admission,
            source_intake_receipt=fixture.receipt,
        )
    assert source_error.value.code == "GE_SOURCE_CHAIN_SOURCE_OBJECT_DIGEST_DIFFERED"
