from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.evaluation.all60_evidence_review import (
    REQUIRED_AI_REASON_CODES,
    _candidate_context,
    _gate_span,
    _tree_sha256,
    all60_issue_identity_sha256,
    build_all60_issue_review_input,
)
from app.evaluation.all60_qualification import (
    ExactAll60Qualification,
    build_exact_all60_qualification,
    exact_all60_qualification_bytes,
    write_exact_all60_qualification,
)
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_gold import LiveSuiteExpertQualification
from app.evaluation.owner_quality_canary import load_all60_qualification
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.quality.ai_evidence_reviewer import (
    AIReviewerClaimCheckpoint,
    ClaimEvidenceVerdict,
    ai_evidence_reviewer_toolchain_sha256,
    frozen_claim_bundle_sha256,
    seal_ai_reviewer_claim_checkpoint,
    seal_ai_reviewer_invocation_trace,
)
from app.quality.draft_identity import source_draft_sha256
from app.quality.policy import POLICY_SHA256
from app.retrieval.source_manifest import (
    MANIFEST_SCHEMA,
    approved_source_manifest_sha256,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
AS_OF = date(2026, 8, 20)
SOURCE_VERSION_ID = "source-version-1"
STABLE_IDENTIFIER = "ukpga:2026:1:latest-available@2026-08-20"


@dataclass(frozen=True, slots=True)
class _FakeVerifiedAll60AIReviewBatch:
    """Test-only stand-in accepted solely by the monkeypatched verifier."""

    attestation: Any
    checkpoints: tuple[AIReviewerClaimCheckpoint, ...]
    checkpoint_names: tuple[str, ...]
    checkpoint_directory: Path
    manifest_seal_sha256: str
    checkpoint_set_sha256: str
    invocation_intent_ledger_sha256: str
    invocation_outcome_ledger_sha256: str
    launcher_start_attestation_sha256: str
    launcher_end_attestation_sha256: str


def _test_digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture
def verified_batch_factory(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Make the consumer exercise an opaque, verifier-issued capability."""

    def require_test_capability(value: object) -> _FakeVerifiedAll60AIReviewBatch:
        if type(value) is not _FakeVerifiedAll60AIReviewBatch:
            raise RuntimeError("all60_ai_review_batch_capability_not_loader_verified")
        return value

    monkeypatch.setattr(
        "app.evaluation.all60_ai_review_batch.require_verified_all60_ai_review_batch",
        require_test_capability,
    )

    def factory(
        *,
        checkpoint_directory: Path,
        bundle: Any,
        candidate: SealedCandidateIdentity,
        expert: LiveSuiteExpertQualification,
    ) -> _FakeVerifiedAll60AIReviewBatch:
        checkpoint_paths = tuple(sorted(checkpoint_directory.glob("*.json")))
        checkpoints = tuple(
            AIReviewerClaimCheckpoint.model_validate_json(path.read_bytes())
            for path in checkpoint_paths
        )
        run_id = "test-all60-batch"
        attestation_seal = _test_digest("test-all60-batch-attestation")
        issue_identity_set_sha256 = sealed_sha256(
            {
                "schema": "legalbot.live60-all-issue-identity-set.v1",
                "issue_identity_sha256s": [
                    all60_issue_identity_sha256(
                        case_id=source_case.case_id,
                        issue_id=issue.issue_id,
                        question_sha256=source_case.question_sha256,
                        record_sha256=source_case.record_sha256,
                        topic=topic,
                    )
                    for source_case, expert_case in zip(
                        bundle.registry.cases, expert.cases, strict=True
                    )
                    for topic, issue in zip(
                        source_case.must_cover_issues, expert_case.issues, strict=True
                    )
                ],
            }
        )
        attestation = SimpleNamespace(
            run_id=run_id,
            candidate_build_id=candidate.build_id,
            candidate_manifest_sha256=candidate.candidate_manifest_sha256,
            candidate_seal_sha256=candidate.candidate_seal_sha256,
            suite_registry_canonical_sha256=bundle.registry.canonical_sha256,
            run_plan_sha256=bundle.manifest.run_plan_sha256,
            expert_qualification_seal_sha256=expert.seal_sha256,
            issue_identity_set_sha256=issue_identity_set_sha256,
            required_as_of_date=AS_OF,
            authoritative=True,
            qualification_eligible=True,
            completed=True,
            all_reviews_passed=True,
            seal_sha256=attestation_seal,
        )
        logical_checkpoint_directory = (
            checkpoint_directory.parent
            / "all60-ai-review"
            / AS_OF.isoformat()
            / run_id
            / "checkpoints"
        )
        return _FakeVerifiedAll60AIReviewBatch(
            attestation=attestation,
            checkpoints=checkpoints,
            checkpoint_names=tuple(path.name for path in checkpoint_paths),
            checkpoint_directory=logical_checkpoint_directory,
            manifest_seal_sha256=_test_digest("test-all60-batch-manifest"),
            checkpoint_set_sha256=_test_digest("test-all60-batch-checkpoint-set"),
            invocation_intent_ledger_sha256=_test_digest("test-all60-batch-intents"),
            invocation_outcome_ledger_sha256=_test_digest("test-all60-batch-outcomes"),
            launcher_start_attestation_sha256=_test_digest("test-all60-batch-launcher-start"),
            launcher_end_attestation_sha256=_test_digest("test-all60-batch-launcher-end"),
        )

    return factory


def _span_text(topic: str, *, reuse_one_chunk: bool) -> str:
    if reuse_one_chunk:
        return "A generic synthetic provision with no issue-specific legal proposition."
    return f"The official statutory rule addresses {topic}. This exact proposition applies."


def _expert(
    *,
    limited_first: bool = False,
    missing_last: bool = False,
    reuse_one_chunk: bool = False,
) -> Any:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    cases: list[dict[str, Any]] = []
    global_ordinal = 0
    for case_ordinal, case in enumerate(bundle.registry.cases, start=1):
        topics = tuple(case.must_cover_issues)
        if missing_last and case_ordinal == 60:
            topics = topics[:-1]
        issues: list[dict[str, Any]] = []
        for issue_ordinal, topic in enumerate(topics, start=1):
            global_ordinal += 1
            limited = limited_first and case_ordinal == 1 and issue_ordinal == 1
            issue_id = f"issue-{issue_ordinal:02d}"
            text = _span_text(topic, reuse_one_chunk=reuse_one_chunk)
            chunk_id = "chunk-reused-1" if reuse_one_chunk else f"chunk-exact-{global_ordinal:03d}"
            locator = "section 1" if reuse_one_chunk else f"section {global_ordinal}"
            issues.append(
                {
                    "schema": "legalbot.live-issue-qualification.v1",
                    "issue_id": issue_id,
                    "status": "limited" if limited else "qualified",
                    "reason_code": "owner-confirmed-limited" if limited else None,
                    "exact_gold_spans": [
                        {
                            "schema": "legalbot.live-gold-span.v1",
                            "gold_span_id": f"gold-{case_ordinal:02d}-{issue_ordinal:02d}",
                            "issue_id": issue_id,
                            "stable_source_id": "source-identity-1",
                            "legal_authority_id": None,
                            "source_version_id": SOURCE_VERSION_ID,
                            "chunk_id": chunk_id,
                            "legal_locator": locator,
                            "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "source_type": "legislation",
                            "legal_role": "statutory_text",
                            "proposition_hash": None,
                            "case_currentness_review": None,
                            "relevance_grade": 3,
                            "contrary_or_limiting": False,
                        }
                    ],
                }
            )
        case_status = "limited" if limited_first and case_ordinal == 1 else "qualified"
        cases.append(
            {
                "schema": "legalbot.live-case-qualification.v1",
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": case_status,
                "contrary_authority_status": "reviewed_none",
                "acceptable_source_ids": ["source-identity-1"],
                "issues": issues,
            }
        )
    material: dict[str, Any] = {
        "schema": "legalbot.live-expert-qualification.v1",
        "suite_id": bundle.manifest.suite_id,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "index_build_id": "candidate-v111",
        "as_of_date": AS_OF.isoformat(),
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "expert_approved",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": "legal_reviewer",
        "approval_reviewer_ref": "reviewer:" + "d" * 64,
        "owner_is_primary_reviewer": True,
        "independent_second_review_status": "not_required",
        "independent_second_reviewer_role": None,
        "independent_second_reviewer_ref": None,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": 60,
        "cases": cases,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return LiveSuiteExpertQualification.model_validate(material)


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _candidate_build(
    tmp_path: Path,
    expert: LiveSuiteExpertQualification,
) -> tuple[SealedCandidateIdentity, Path]:
    root = tmp_path / "data/indexes/builds/candidate-v111"
    authority = root / "lance/authority"
    authority.mkdir(parents=True)
    spans = tuple(span for case in expert.cases for span in case.exact_gold_spans)
    rows_by_id: dict[str, dict[str, Any]] = {}
    topics = {
        f"{case.case_id}:{issue.issue_id}": topic
        for case, expert_case in zip(
            load_live_evaluation_bundle(BUNDLE_ROOT).registry.cases,
            expert.cases,
            strict=True,
        )
        for topic, issue in zip(case.must_cover_issues, expert_case.issues, strict=True)
    }
    for case in expert.cases:
        for issue in case.issues:
            row_id = f"{case.case_id}:{issue.issue_id}"
            for span in issue.exact_gold_spans:
                rows_by_id.setdefault(
                    span.chunk_id,
                    {
                        "chunk_id": span.chunk_id,
                        "source_version_id": SOURCE_VERSION_ID,
                        "source_identity": STABLE_IDENTIFIER,
                        "text": _span_text(
                            topics[row_id], reuse_one_chunk=span.chunk_id == "chunk-reused-1"
                        ),
                        "content_sha256": span.content_sha256,
                        "locator": span.legal_locator,
                        "catalog_lane": "primary_authority",
                        "catalog_jurisdiction": "England and Wales",
                        "currentness_status": "latest_available_revised_snapshot",
                        "identity_verified": True,
                        "currentness_verified": True,
                        "legal_role": "statutory_text",
                        "case_currentness_reviews_json": "[]",
                        "case_currentness_manifest_seals_json": "[]",
                    },
                )
    import lancedb

    lancedb.connect(str(authority)).create_table("chunks", data=list(rows_by_id.values()))
    source_manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "created_at": "2026-08-20T00:00:00Z",
        "authority_lane_only": True,
        "benchmark_answers_used_for_selection": False,
        "current_law_as_of_date": AS_OF.isoformat(),
        "sources": [
            {
                "source_version_id": SOURCE_VERSION_ID,
                "document_id": "document-1",
                "stable_identifier": STABLE_IDENTIFIER,
                "authority_identity_id": "ukpga:2026:1",
                "content_sha256": "1" * 64,
                "version_sha256": "1" * 64,
                "document_status": "citable",
                "lane": "primary_authority",
                "jurisdiction": "England and Wales",
                "licence_name": "Open Government Licence v3.0",
                "identity_verified": True,
                "currentness_verified": True,
                "currentness_reviewed_as_of_date": AS_OF.isoformat(),
                "currentness_status": "latest_available_revised_snapshot",
                "unapplied_effect_count": 0,
            }
        ],
    }
    source_manifest["manifest_sha256"] = approved_source_manifest_sha256(source_manifest)
    source_path = root / "approved-source-manifest.json"
    source_path.write_text(
        json.dumps(source_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    provision = {
        "schema": "legalbot.provision-verification.v1",
        "as_of_date": AS_OF.isoformat(),
        "records": [
            {
                "stable_source_id": STABLE_IDENTIFIER,
                "legal_locator": locator,
                "verified_extent": "E+W",
                "section_unapplied_effect_count": 0,
                "unapplied_effect_materiality": "none_recorded",
                "source_content_sha256": "1" * 64,
                "source_version_sha256": "1" * 64,
            }
            for locator in sorted({span.legal_locator for span in spans})
        ],
    }
    provision_path = root / "provision-verification.v1.json"
    provision_path.write_text(
        json.dumps(provision, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    candidate_manifest = {
        "schema": "legalbot.index-manifest.v2",
        "build_id": "candidate-v111",
        "source_manifest_sha256": source_manifest["manifest_sha256"],
        "chunk_count": len(rows_by_id),
        "sealed": True,
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(
        json.dumps(candidate_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    seal = {
        "schema": "legalbot.index-seal.v2",
        "build_id": "candidate-v111",
        "manifest_sha256": _sha_file(manifest_path),
        "source_manifest_file_sha256": _sha_file(source_path),
        "provision_verification_sha256": _sha_file(provision_path),
        "lance_tree_sha256": _tree_sha256(root / "lance"),
    }
    seal_path = root / "seal.json"
    seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    candidate = SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256=_sha_file(manifest_path),
        candidate_seal_sha256=_sha_file(seal_path),
        source_manifest_sha256=str(source_manifest["manifest_sha256"]),
        embedding_model="embedding-model-v1",
        reranker_model="reranker-model-v1",
        document_count=1,
        chunk_count=len(rows_by_id),
        vector_count=len(rows_by_id),
    )
    return candidate, root


def _checkpoints(
    tmp_path: Path,
    *,
    bundle: Any,
    candidate: SealedCandidateIdentity,
    root: Path,
    expert: LiveSuiteExpertQualification,
) -> Path:
    directory = tmp_path / "ai-review-checkpoints"
    directory.mkdir(mode=0o700)
    context = _candidate_context(
        candidate=candidate,
        candidate_build_root=root,
        spans=tuple(span for case in expert.cases for span in case.exact_gold_spans),
    )
    ordinal = 0
    for source_case, expert_case in zip(bundle.registry.cases, expert.cases, strict=True):
        for topic, issue in zip(source_case.must_cover_issues, expert_case.issues, strict=True):
            ordinal += 1
            row_id = f"{source_case.case_id}:{issue.issue_id}"
            evidence = tuple(
                _gate_span(
                    span=span,
                    row_id=row_id,
                    required_as_of_date=AS_OF,
                    context=context,
                )[0]
                for span in issue.exact_gold_spans
            )
            draft, frozen = build_all60_issue_review_input(
                row_id=row_id,
                topic=topic,
                task_type=source_case.task_type,
                as_of_date=AS_OF,
                evidence=evidence,
            )
            decision = ClaimEvidenceVerdict(
                claim_id=frozen.identity.claim_id,
                claim_sha256=frozen.identity.claim_sha256,
                evidence_span_ids=frozen.identity.evidence_span_ids,
                evidence_bundle_sha256=frozen.identity.evidence_bundle_sha256,
                verdict="supported",
                reason_codes=tuple(sorted(REQUIRED_AI_REASON_CODES)),
                cited_evidence_ids=(evidence[0].id,),
            )
            trace = seal_ai_reviewer_invocation_trace(
                claim_id=row_id,
                invocation_id=f"all60-review-{ordinal:04d}",
                duration_ms=1,
                timing_source="local_monotonic",
            )
            checkpoint = seal_ai_reviewer_claim_checkpoint(
                source_draft_sha256=source_draft_sha256(draft),
                frozen_claim_bundle_sha256=frozen_claim_bundle_sha256((frozen,)),
                frozen_claim=frozen,
                decision=decision,
                invocation_trace=trace,
                model_id="test-ai-evidence-reviewer",
                model_version="test-revision-1",
                policy_sha256=POLICY_SHA256,
                toolchain_sha256=ai_evidence_reviewer_toolchain_sha256(),
            )
            path = directory / f"{ordinal:04d}.json"
            path.write_text(
                json.dumps(checkpoint.model_dump(mode="json", by_alias=True), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
    return directory


def test_builder_derives_deterministic_exact_60_585_private_artifact(
    tmp_path: Path, verified_batch_factory: Any
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    expert = _expert()
    candidate, candidate_root = _candidate_build(tmp_path, expert)
    checkpoints = _checkpoints(
        tmp_path,
        bundle=bundle,
        candidate=candidate,
        root=candidate_root,
        expert=expert,
    )
    verified_batch = verified_batch_factory(
        checkpoint_directory=checkpoints,
        bundle=bundle,
        candidate=candidate,
        expert=expert,
    )

    first = build_exact_all60_qualification(
        bundle=bundle,
        candidate=candidate,
        expert_qualification=expert,
        required_as_of_date=AS_OF,
        candidate_build_root=candidate_root,
        ai_review_batch=verified_batch,
    )
    second = build_exact_all60_qualification(
        bundle=bundle,
        candidate=candidate,
        expert_qualification=expert,
        required_as_of_date=AS_OF,
        candidate_build_root=candidate_root,
        ai_review_batch=verified_batch,
    )
    assert isinstance(first, ExactAll60Qualification)
    assert first == second
    assert first.case_count == 60 and first.issue_count == 585
    assert first.qualified_issue_count == first.positive_span_issue_count == 585
    assert len(first.case_bindings) == 60
    assert len(first.issue_bindings) == 585
    assert first.qualified_case_ids == first.case_ids
    assert not first.limited_case_ids
    assert first.ai_evidence_review_issue_count == 585
    assert first.deterministic_gate_issue_count == 585
    assert first.stage_a_used_for_qualification is False
    assert first.ai_review_batch_run_id == verified_batch.attestation.run_id
    assert first.ai_review_batch_run_date == AS_OF
    assert first.ai_review_batch_attestation_seal_sha256 == verified_batch.attestation.seal_sha256
    assert first.ai_review_batch_manifest_seal_sha256 == verified_batch.manifest_seal_sha256
    assert first.ai_review_batch_checkpoint_set_sha256 == verified_batch.checkpoint_set_sha256
    assert (
        first.ai_review_batch_intent_ledger_sha256 == verified_batch.invocation_intent_ledger_sha256
    )
    assert (
        first.ai_review_batch_outcome_ledger_sha256
        == verified_batch.invocation_outcome_ledger_sha256
    )
    assert (
        first.ai_review_batch_launcher_start_sha256
        == verified_batch.launcher_start_attestation_sha256
    )
    assert (
        first.ai_review_batch_launcher_end_sha256 == verified_batch.launcher_end_attestation_sha256
    )

    encoded = exact_all60_qualification_bytes(first)
    assert b'"question":' not in encoded
    assert b'"topic":' not in encoded
    assert b"/Users/" not in encoded
    assert all(case.question.encode() not in encoded for case in bundle.registry.cases)

    output_parent = tmp_path / "private"
    output_parent.mkdir(mode=0o700)
    destination = write_exact_all60_qualification(
        output_directory=output_parent / "qualification",
        qualification=first,
    )
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert load_all60_qualification(destination) == first
    with pytest.raises(FileExistsError, match="create-only"):
        write_exact_all60_qualification(
            output_directory=destination.parent,
            qualification=first,
        )


@pytest.mark.parametrize(
    ("expert", "message"),
    [
        (_expert(limited_first=True), "limited"),
        (_expert(missing_last=True), "missing"),
    ],
)
def test_builder_fails_closed_on_limited_or_missing_issues(
    tmp_path: Path, expert: LiveSuiteExpertQualification, message: str
) -> None:
    candidate, candidate_root = _candidate_build(tmp_path, _expert())
    with pytest.raises(ValueError):
        build_exact_all60_qualification(
            bundle=load_live_evaluation_bundle(BUNDLE_ROOT),
            candidate=candidate,
            expert_qualification=expert,
            required_as_of_date=AS_OF,
            candidate_build_root=candidate_root,
            ai_review_batch={"unverified": message},
        )


def test_builder_fails_closed_on_candidate_contrary_and_currentness_drift(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    expert = _expert()
    candidate, candidate_root = _candidate_build(tmp_path, expert)

    with pytest.raises(ValueError, match="mismatched sealed identities"):
        build_exact_all60_qualification(
            bundle=bundle,
            candidate=replace(candidate, build_id="candidate-other"),
            expert_qualification=expert,
            required_as_of_date=AS_OF,
            candidate_build_root=candidate_root,
            ai_review_batch=object(),
        )

    first = expert.cases[0].model_copy(update={"contrary_authority_status": "unresolved"})
    contrary = expert.model_copy(update={"cases": (first, *expert.cases[1:])})
    with pytest.raises(ValueError):
        build_exact_all60_qualification(
            bundle=bundle,
            candidate=candidate,
            expert_qualification=contrary,
            required_as_of_date=AS_OF,
            candidate_build_root=candidate_root,
            ai_review_batch=object(),
        )

    changed = expert.model_dump(mode="json", by_alias=True)
    changed["as_of_date"] = date(2026, 8, 19).isoformat()
    changed["seal_sha256"] = sealed_sha256(changed)
    currentness_drift = LiveSuiteExpertQualification.model_validate(changed)
    assert currentness_drift.as_of_date != AS_OF
    with pytest.raises(ValueError, match="mismatched sealed identities"):
        build_exact_all60_qualification(
            bundle=bundle,
            candidate=candidate,
            expert_qualification=currentness_drift,
            required_as_of_date=AS_OF,
            candidate_build_root=candidate_root,
            ai_review_batch=object(),
        )


def test_file_loader_rejects_hand_authored_v1_summary(tmp_path: Path) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    case_ids = [case.case_id for case in bundle.registry.cases]
    value = {
        "schema": "legalbot.live60-all-case-qualification.v1",
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": "candidate-v111",
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": case_ids,
        "limited_case_ids": [],
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    value["seal_sha256"] = sealed_sha256(value)
    path = tmp_path / "hand-authored.json"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        load_all60_qualification(path)


def test_adversarial_585_issue_one_irrelevant_chunk_cannot_self_qualify(
    tmp_path: Path,
    verified_batch_factory: Any,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    expert = _expert(reuse_one_chunk=True)
    candidate, candidate_root = _candidate_build(tmp_path, expert)
    checkpoints = _checkpoints(
        tmp_path,
        bundle=bundle,
        candidate=candidate,
        root=candidate_root,
        expert=expert,
    )
    assert candidate.chunk_count == 1
    assert len(tuple(checkpoints.iterdir())) == 585
    verified_batch = verified_batch_factory(
        checkpoint_directory=checkpoints,
        bundle=bundle,
        candidate=candidate,
        expert=expert,
    )

    with pytest.raises(ValueError, match="no independently relevant exact candidate span"):
        build_exact_all60_qualification(
            bundle=bundle,
            candidate=candidate,
            expert_qualification=expert,
            required_as_of_date=AS_OF,
            candidate_build_root=candidate_root,
            ai_review_batch=verified_batch,
        )


def test_builder_rejects_raw_checkpoint_directory_without_verified_batch(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    expert = _expert()
    candidate, candidate_root = _candidate_build(tmp_path, expert)
    checkpoints = _checkpoints(
        tmp_path,
        bundle=bundle,
        candidate=candidate,
        root=candidate_root,
        expert=expert,
    )

    with pytest.raises(RuntimeError, match="all60_ai_review_batch_capability_not_loader_verified"):
        build_exact_all60_qualification(
            bundle=bundle,
            candidate=candidate,
            expert_qualification=expert,
            required_as_of_date=AS_OF,
            candidate_build_root=candidate_root,
            ai_review_batch=checkpoints,
        )
