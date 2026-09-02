from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.crypto import LocalCipher
from app.db import Database, utc_iso
from app.research.control_plane import ResearchControlPlane
from app.research.models import (
    OWNER_DECISION_REQUIRED,
    GapMateriality,
    ResearchGapBindingRequest,
    ResearchPriority,
    ResearchTaskRequest,
    ResearchTaskType,
    ResearchTrigger,
)
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
from app.research.review import OwnerDecisionRequired, ResearchReviewService
from app.research.source_registry import OfficialSourceRegistry
from app.research.worker import (
    OfficialResearchDispatcher,
    PermanentResearchError,
    ResearchWorker,
)
from app.retrieval.source_manifest import approved_source_manifest_sha256

_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "config" / "official_sources.json"
_QUERY_SHA256 = hashlib.sha256(b"contract").hexdigest()
_PROPOSITION_SHA256 = hashlib.sha256(b"missing statutory proposition").hexdigest()
_SOURCE_MANIFEST_BASE = {
    "schema": "legalbot.approved-source-manifest.v1",
    "selection_policy": "synthetic-ordinary-candidate",
    "sources": [],
}
_SOURCE_MANIFEST_SHA256 = approved_source_manifest_sha256(_SOURCE_MANIFEST_BASE)
_CHUNK_ID = "chunk-gap-proof-1"


def _ensure_candidate_tree(tmp_path: Path, build_id: str) -> None:
    build_root = tmp_path / "data/indexes/builds" / build_id
    if build_root.is_dir():
        return
    authority = build_root / "lance" / "authority"
    authority.mkdir(parents=True)
    import lancedb

    lancedb.connect(str(authority)).create_table(
        "chunks",
        data=[
            {
                "chunk_id": _CHUNK_ID,
                "source_version_id": "source-version-gap-proof-1",
                "content_sha256": "d" * 64,
                "locator": "section 1",
                "catalog_lane": "primary_authority",
                "catalog_jurisdiction": "England and Wales",
                "identity_verified": True,
                "currentness_verified": True,
            }
        ],
    )
    source_manifest = {
        **_SOURCE_MANIFEST_BASE,
        "manifest_sha256": _SOURCE_MANIFEST_SHA256,
    }
    source_manifest_path = build_root / "approved-source-manifest.json"
    source_manifest_path.write_text(
        json.dumps(source_manifest, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "schema": "legalbot.index-manifest.v2",
        "build_id": build_id,
        "source_manifest_sha256": _SOURCE_MANIFEST_SHA256,
        "chunk_count": 1,
        "sealed": True,
    }
    manifest_path = build_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": build_id,
        "manifest_sha256": _file_sha256(manifest_path),
        "source_manifest_file_sha256": _file_sha256(source_manifest_path),
        "lance_tree_sha256": _tree_sha256(build_root / "lance"),
    }
    (build_root / "seal.json").write_text(json.dumps(seal, sort_keys=True) + "\n", encoding="utf-8")


def _candidate_binding(tmp_path: Path, build_id: str) -> CandidateBuildBinding:
    _ensure_candidate_tree(tmp_path, build_id)
    return CandidateBuildBinding(
        candidate_build_id=build_id,
        candidate_seal_sha256=_file_sha256(
            tmp_path / "data/indexes/builds" / build_id / "seal.json"
        ),
        source_manifest_sha256=_SOURCE_MANIFEST_SHA256,
    )


class _Executor:
    def __init__(
        self,
        disposition: HitQualificationDisposition = HitQualificationDisposition.NO_MATERIAL_SUPPORT,
        *,
        empty: bool = False,
    ) -> None:
        self.disposition = disposition
        self.empty = empty

    def __call__(self, request: Any) -> CandidateRetrievalExecutorResult:
        hits = (
            ()
            if self.empty
            else (
                CandidateRetrievalExecutorHit(
                    chunk_id=_CHUNK_ID,
                    qualification_disposition=self.disposition,
                ),
            )
        )
        return CandidateRetrievalExecutorResult(
            invocation_id="retrieval-invocation-001",
            candidate_build_id=request.candidate_build_id,
            candidate_rows_examined=1,
            ranked_hits=hits,
        )


class _NoFetch:
    def __init__(self) -> None:
        self.called = False

    async def fetch(self, *_args: Any, **_kwargs: Any) -> Any:
        self.called = True
        raise AssertionError("network fetch must not occur")


def _control(tmp_path: Path, database: Database, cipher: LocalCipher) -> ResearchControlPlane:
    return ResearchControlPlane(
        Settings(project_root=tmp_path, test_mode=True),
        database,
        cipher=cipher,
        registry=OfficialSourceRegistry.load(_REGISTRY_PATH),
        candidate_binding_loader=lambda _settings, _database, build_id: (
            _candidate_binding(tmp_path, build_id)
        ),
    )


def _sealed_candidate(database: Database, build_id: str = "candidate-gap-base") -> None:
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, embedding_model, reranker_model, source_manifest_hash,
          created_at
        ) VALUES (?, 'candidate', ?, ?, ?, ?, ?)
        """,
        (
            build_id,
            f"data/indexes/builds/{build_id}",
            "embedding-model@revision-1",
            "reranker-model@revision-1",
            _SOURCE_MANIFEST_SHA256,
            utc_iso(),
        ),
    )


def _gap_request(
    tmp_path: Path,
    *,
    issue_id: str = "live60-issue-01",
    materiality: GapMateriality = GapMateriality.MATERIAL,
    detail: str = "The sealed evidence set lacks the material statutory proposition.",
    hit_disposition: HitQualificationDisposition = HitQualificationDisposition.NO_MATERIAL_SUPPORT,
    artifact_candidate_build_id: str = "candidate-gap-base",
    artifact_query_sha256: str = _QUERY_SHA256,
) -> ResearchGapBindingRequest:
    binding = _candidate_binding(tmp_path, artifact_candidate_build_id)
    attempt = execute_candidate_retrieval_attempt(
        settings=Settings(project_root=tmp_path, test_mode=True),
        binding=RetrievalAttemptBinding(
            candidate_build_id=artifact_candidate_build_id,
            candidate_seal_sha256=binding.candidate_seal_sha256,
            source_manifest_sha256=_SOURCE_MANIFEST_SHA256,
            case_ref=opaque_gap_reference("case", "live60-case-01"),
            issue_ref=opaque_gap_reference("issue", issue_id),
            subject="contract",
            jurisdiction="England and Wales",
            as_of_date=date(2026, 8, 20),
            proposition_sha256=_PROPOSITION_SHA256,
            query_sha256=artifact_query_sha256,
        ),
        canonical_query="contract" if artifact_query_sha256 == _QUERY_SHA256 else "changed",
        executor=_Executor(hit_disposition),
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    return ResearchGapBindingRequest(
        candidate_build_id="candidate-gap-base",
        case_id="live60-case-01",
        issue_id=issue_id,
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        retrieval_query_sha256=_QUERY_SHA256,
        proposition_sha256=_PROPOSITION_SHA256,
        retrieval_attempt_artifact_sha256=attempt.artifact_sha256,
        materiality=materiality,
        detail=detail,
    )


def _discovery_request(
    *,
    trigger: ResearchTrigger,
    gap_id: str | None,
    task_type: ResearchTaskType = ResearchTaskType.BROAD_DISCOVERY,
) -> ResearchTaskRequest:
    return ResearchTaskRequest(
        task_type=task_type,
        trigger=trigger,
        priority=ResearchPriority.HIGH,
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        source_id="legislation_gov_uk",
        knowledge_gap_id=gap_id,
        public_query="contract",
    )


def test_gap_is_encrypted_semantically_deduplicated_and_pins_candidate(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    _sealed_candidate(database)
    control = _control(tmp_path, database, cipher)
    request = _gap_request(tmp_path)
    artifact_path = (
        tmp_path
        / "data/evaluations/research/candidate-retrieval-attempts"
        / f"{request.retrieval_attempt_artifact_sha256}.json"
    )
    assert artifact_path.stat().st_mode & 0o777 == 0o600
    assert artifact_path.parent.stat().st_mode & 0o777 == 0o700
    artifact_bytes = artifact_path.read_bytes()
    assert b"live60-case-01" not in artifact_bytes
    assert b"statutory proposition" not in artifact_bytes
    first = control.log_knowledge_gap(request)
    duplicate = control.log_knowledge_gap(
        replace(
            request,
            detail="A differently worded private explanation for the same binding.",
        )
    )

    assert duplicate["id"] == first["id"]
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_gap_bindings")["n"] == 1
    assert first["case_id"] == f"case:{hashlib.sha256(b'live60-case-01').hexdigest()}"
    assert first["issue_id"] == f"issue:{hashlib.sha256(b'live60-issue-01').hexdigest()}"
    assert first["case_id"] != "live60-case-01"
    assert first["issue_id"] != "live60-issue-01"
    assert first["attempted_retrieval_sha256"] == (request.retrieval_attempt_artifact_sha256)
    assert b"statutory proposition" not in bytes(first["encrypted_detail"])
    assert (
        cipher.decrypt_text(bytes(first["encrypted_detail"]))
        == "The sealed evidence set lacks the material statutory proposition."
    )

    task = control.admit(
        _discovery_request(trigger=ResearchTrigger.MANUAL, gap_id=str(first["id"]))
    )
    assert task["knowledge_gap_id"] == first["id"]
    assert task["pinned_index_build_id"] == "candidate-gap-base"
    assert task["source_manifest_sha256"] == _SOURCE_MANIFEST_SHA256


@pytest.mark.parametrize("trigger", [ResearchTrigger.MANUAL, ResearchTrigger.ENQUIRY])
def test_manual_and_enquiry_discovery_fail_before_crawl_without_gap(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
    trigger: ResearchTrigger,
) -> None:
    control = _control(tmp_path, database, cipher)
    with pytest.raises(ValueError, match="existing knowledge-gap"):
        control.admit(_discovery_request(trigger=trigger, gap_id=None))
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_tasks")["n"] == 0


def test_gap_research_and_non_material_binding_fail_closed(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    _sealed_candidate(database)
    control = _control(tmp_path, database, cipher)
    with pytest.raises(ValueError, match="existing knowledge-gap"):
        control.admit(
            _discovery_request(
                trigger=ResearchTrigger.ENQUIRY,
                gap_id=None,
                task_type=ResearchTaskType.GAP_RESEARCH,
            )
        )

    non_material = control.log_knowledge_gap(
        _gap_request(
            tmp_path,
            issue_id="live60-issue-02",
            materiality=GapMateriality.NON_MATERIAL,
        )
    )
    with pytest.raises(ValueError, match="open material gap"):
        control.admit(
            _discovery_request(
                trigger=ResearchTrigger.ENQUIRY,
                gap_id=str(non_material["id"]),
                task_type=ResearchTaskType.GAP_RESEARCH,
            )
        )


def test_missing_or_tampered_retrieval_attempt_cannot_create_gap(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    _sealed_candidate(database)
    control = _control(tmp_path, database, cipher)
    valid = _gap_request(tmp_path)

    with pytest.raises(ValueError, match="artifact is missing"):
        control.log_knowledge_gap(replace(valid, retrieval_attempt_artifact_sha256="b" * 64))

    artifact = (
        tmp_path
        / "data/evaluations/research/candidate-retrieval-attempts"
        / f"{valid.retrieval_attempt_artifact_sha256}.json"
    )
    artifact.write_bytes(artifact.read_bytes() + b" ")
    artifact.chmod(0o600)
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        control.log_knowledge_gap(valid)
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_gap_bindings")["n"] == 0


def test_retrieval_attempt_requires_executor_hits_and_derives_execution_identity(
    tmp_path: Path,
) -> None:
    binding = _candidate_binding(tmp_path, "candidate-gap-base")
    request_binding = RetrievalAttemptBinding(
        candidate_build_id=binding.candidate_build_id,
        candidate_seal_sha256=binding.candidate_seal_sha256,
        source_manifest_sha256=binding.source_manifest_sha256,
        case_ref=opaque_gap_reference("case", "live60-case-01"),
        issue_ref=opaque_gap_reference("issue", "live60-issue-empty"),
        subject="contract",
        jurisdiction="England and Wales",
        as_of_date=date(2026, 8, 20),
        proposition_sha256=_PROPOSITION_SHA256,
        query_sha256=_QUERY_SHA256,
    )
    with pytest.raises(ValueError, match="invalid completed result"):
        execute_candidate_retrieval_attempt(
            settings=Settings(project_root=tmp_path, test_mode=True),
            binding=request_binding,
            canonical_query="contract",
            executor=_Executor(empty=True),
        )
    parameters = inspect.signature(execute_candidate_retrieval_attempt).parameters
    assert "retrieval_execution_sha256" not in parameters
    assert "ranked_hits" not in parameters


def test_retrieval_attempt_rejects_executor_hit_outside_sealed_candidate(
    tmp_path: Path,
) -> None:
    binding = _candidate_binding(tmp_path, "candidate-gap-base")

    class _ForeignExecutor:
        def __call__(self, request: Any) -> CandidateRetrievalExecutorResult:
            return CandidateRetrievalExecutorResult(
                invocation_id="retrieval-invocation-foreign",
                candidate_build_id=request.candidate_build_id,
                candidate_rows_examined=1,
                ranked_hits=(
                    CandidateRetrievalExecutorHit(
                        chunk_id="chunk-not-in-candidate",
                        qualification_disposition=(HitQualificationDisposition.NO_MATERIAL_SUPPORT),
                    ),
                ),
            )

    with pytest.raises(ValueError, match="exact sealed-candidate member"):
        execute_candidate_retrieval_attempt(
            settings=Settings(project_root=tmp_path, test_mode=True),
            binding=RetrievalAttemptBinding(
                candidate_build_id=binding.candidate_build_id,
                candidate_seal_sha256=binding.candidate_seal_sha256,
                source_manifest_sha256=binding.source_manifest_sha256,
                case_ref=opaque_gap_reference("case", "live60-case-01"),
                issue_ref=opaque_gap_reference("issue", "live60-issue-foreign"),
                subject="contract",
                jurisdiction="England and Wales",
                as_of_date=date(2026, 8, 20),
                proposition_sha256=_PROPOSITION_SHA256,
                query_sha256=_QUERY_SHA256,
            ),
            canonical_query="contract",
            executor=_ForeignExecutor(),
        )


def test_mismatched_candidate_attempt_and_existing_hit_block_gap_research(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    _sealed_candidate(database)
    control = _control(tmp_path, database, cipher)
    mismatched = _gap_request(tmp_path, artifact_candidate_build_id="candidate-different")
    with pytest.raises(ValueError, match="candidate_build_id binding mismatch"):
        control.log_knowledge_gap(mismatched)

    qualifying = _gap_request(
        tmp_path,
        issue_id="live60-issue-qualifying",
        hit_disposition=HitQualificationDisposition.QUALIFYING_EXISTING_AUTHORITY,
    )
    with pytest.raises(ValueError, match="already contains a qualifying existing hit"):
        control.log_knowledge_gap(qualifying)
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_gap_bindings")["n"] == 0
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_tasks")["n"] == 0


def test_gap_crawl_requires_the_exact_sealed_retrieval_query(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    _sealed_candidate(database)
    control = _control(tmp_path, database, cipher)
    gap = control.log_knowledge_gap(_gap_request(tmp_path))

    changed_query = replace(
        _discovery_request(trigger=ResearchTrigger.ENQUIRY, gap_id=str(gap["id"])),
        public_query="negligence",
    )
    with pytest.raises(ValueError, match="query changed from the sealed candidate attempt"):
        control.admit(changed_query)
    assert database.fetchone("SELECT COUNT(*) AS n FROM research_tasks")["n"] == 0


async def test_dispatch_revalidates_gap_and_stops_before_fetch(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    _sealed_candidate(database)
    control = _control(tmp_path, database, cipher)
    gap = control.log_knowledge_gap(_gap_request(tmp_path))
    task = control.admit(_discovery_request(trigger=ResearchTrigger.ENQUIRY, gap_id=str(gap["id"])))
    database.execute(
        """
        UPDATE research_gap_bindings
        SET status='resolved', resolved_at=?, updated_at=? WHERE id=?
        """,
        (utc_iso(), utc_iso(), gap["id"]),
    )
    fetcher = _NoFetch()
    dispatcher = OfficialResearchDispatcher(control, fetcher=fetcher)

    with pytest.raises(PermanentResearchError) as exc_info:
        await dispatcher.dispatch(dict(task))
    assert exc_info.value.code == "knowledge_gap_not_open_at_dispatch"
    assert not fetcher.called


async def test_rights_identity_or_currentness_ambiguity_requires_owner_and_no_intake(
    tmp_path: Path,
    database: Database,
    cipher: LocalCipher,
) -> None:
    control = _control(tmp_path, database, cipher)
    task = control.admit(
        ResearchTaskRequest(
            task_type=ResearchTaskType.SOURCE_UPDATE_CHECK,
            trigger=ResearchTrigger.MANUAL,
            priority=ResearchPriority.HIGH,
            subject="case law",
            jurisdiction="England and Wales",
            as_of_date=date(2026, 8, 20),
            source_id="find_case_law",
            authority_identity_id="case:ewhc:2026:1",
        )
    )
    fetcher = _NoFetch()
    dispatcher = OfficialResearchDispatcher(control, fetcher=fetcher)
    worker = ResearchWorker(
        database,
        control,
        dispatcher,
        worker_id="research-test-worker",
    )

    assert await worker.run_once()
    assert not fetcher.called
    finished = database.research_task(str(task["id"]))
    assert finished is not None
    assert finished["status"] == "review_required"
    assert finished["status_reason"] == OWNER_DECISION_REQUIRED

    service = ResearchReviewService(control.settings, database)
    candidate = service.candidates()[0]
    assert candidate.owner_decision_required
    service.system_verify_candidate(candidate.id)
    with pytest.raises(OwnerDecisionRequired, match=f"^{OWNER_DECISION_REQUIRED}$"):
        service.review_candidate(
            candidate.id,
            decision="accept_for_source_intake",
            rights_state="metadata_only",
            identity_review_state="ambiguous",
            currentness_review_state="requires_source_review",
            reviewer_ref=f"reviewer:{'c' * 64}",
            review_manifest_sha256="d" * 64,
        )
    assert (
        database.fetchone(
            "SELECT COUNT(*) AS n FROM reviews WHERE review_type='research_source_intake'"
        )["n"]
        == 0
    )

    intake_id = service.review_candidate(
        candidate.id,
        decision="accept_for_source_intake",
        rights_state="licensed",
        identity_review_state="candidate_matched",
        currentness_review_state="verified",
        reviewer_ref=f"reviewer:{'c' * 64}",
        review_manifest_sha256="e" * 64,
    )
    assert intake_id == f"review-research-intake-{candidate.id}"
    intake = database.fetchone("SELECT * FROM reviews WHERE id=?", (intake_id,))
    assert intake is not None
    assert intake["status"] == "pending"
    assert database.fetchone("SELECT COUNT(*) AS n FROM source_versions")["n"] == 0
    assert database.active_index_id() is None
