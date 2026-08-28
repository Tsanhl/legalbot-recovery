from __future__ import annotations

import json
import stat
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_gold import LiveSuiteExpertQualification
from app.evaluation.live_suite_stage_a_v2_runner import (
    run_stage_a_v2_create_only,
    validate_stage_a_inputs,
)
from app.evaluation.owner_quality_canary import All60CaseQualification
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.types import EvidenceSpan, MaterialLane

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
AS_OF = date(2026, 8, 20)


def _candidate() -> SealedCandidateIdentity:
    return SealedCandidateIdentity(
        build_id="candidate-v111",
        status="candidate",
        candidate_manifest_sha256="a" * 64,
        candidate_seal_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        embedding_model="Qwen/Qwen3-Embedding-0.6B",
        reranker_model="Qwen/Qwen3-Reranker-0.6B",
        document_count=85,
        chunk_count=149_855,
        vector_count=149_855,
    )


def _qualifications(*, one_positive: bool) -> tuple[Any, Any, Any]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    cases: list[dict[str, Any]] = []
    for case_index, case in enumerate(bundle.registry.cases):
        issues: list[dict[str, Any]] = []
        for issue_index, _topic in enumerate(case.must_cover_issues, start=1):
            positive = one_positive and case_index == 0 and issue_index == 1
            span = {
                "schema": "legalbot.live-gold-span.v1",
                "gold_span_id": "gold-stage-a-1",
                "issue_id": "issue-01",
                "stable_source_id": "source-identity-1",
                "legal_authority_id": None,
                "source_version_id": "source-version-1",
                "chunk_id": "chunk-stage-a-1",
                "legal_locator": "section 1",
                "content_sha256": "e" * 64,
                "source_type": "legislation",
                "legal_role": "statutory_text",
                "proposition_hash": None,
                "case_currentness_review": None,
                "relevance_grade": 3,
                "contrary_or_limiting": False,
            }
            issues.append(
                {
                    "schema": "legalbot.live-issue-qualification.v1",
                    "issue_id": f"issue-{issue_index:02d}",
                    "status": "qualified" if positive else "knowledge_gap",
                    "reason_code": None if positive else "no_qualified_span",
                    "exact_gold_spans": [span] if positive else [],
                }
            )
        case_status = "limited" if one_positive and case_index == 0 else "knowledge_gap"
        cases.append(
            {
                "schema": "legalbot.live-case-qualification.v1",
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": case_status,
                "contrary_authority_status": "reviewed_none",
                "acceptable_source_ids": ["source-identity-1"]
                if case_index == 0 and one_positive
                else [],
                "issues": issues,
            }
        )
    expert_value: dict[str, Any] = {
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
        "approval_reviewer_ref": f"reviewer:{'f' * 64}",
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
    expert_value["seal_sha256"] = sealed_sha256(expert_value)
    expert = LiveSuiteExpertQualification.model_validate(expert_value)
    case_ids = [case.case_id for case in bundle.registry.cases]
    all60_value: dict[str, Any] = {
        "schema": "legalbot.live60-all-case-qualification.v1",
        "suite_id": bundle.manifest.suite_id,
        "suite_manifest_seal_sha256": bundle.manifest.seal_sha256,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "candidate_build_id": "candidate-v111",
        "case_count": 60,
        "case_ids": case_ids,
        "qualified_case_ids": [],
        "limited_case_ids": case_ids,
        "review_complete": True,
        "unreviewed_issue_count": 0,
    }
    all60_value["seal_sha256"] = sealed_sha256(all60_value)
    return bundle, All60CaseQualification.model_validate(all60_value), expert


def _evidence() -> EvidenceSpan:
    return EvidenceSpan(
        id="evidence-stage-a-1",
        source_version_id="source-version-1",
        chunk_id="chunk-stage-a-1",
        text="A safe statutory test span.",
        locator="section 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="contract",
        citation_data={"source_type": "legislation"},
        currentness_status="current",
        content_sha256="e" * 64,
        index_build_id="candidate-v111",
        legal_role="statutory_text",
        identity_verified=True,
        currentness_verified=True,
    )


def test_stage_a_requires_exact_60_585_dual_qualification() -> None:
    bundle, all60, expert = _qualifications(one_positive=False)
    validated = validate_stage_a_inputs(
        bundle=bundle,
        candidate=_candidate(),
        all60_qualification=all60,
        expert_qualification=expert,
        as_of_date=AS_OF,
    )
    assert len(validated.all_issues) == 585
    assert len(validated.positive_issues) == 0

    changed = all60.model_dump(mode="json", by_alias=True)
    changed["case_ids"] = list(reversed(changed["case_ids"]))
    changed["seal_sha256"] = sealed_sha256(changed)
    reordered = All60CaseQualification.model_validate(changed)
    with pytest.raises(ValueError, match="identity mismatch"):
        validate_stage_a_inputs(
            bundle=bundle,
            candidate=_candidate(),
            all60_qualification=reordered,
            expert_qualification=expert,
            as_of_date=AS_OF,
        )


@pytest.mark.asyncio
async def test_all_gap_stage_a_writes_585_private_checkpoints_and_resumes_zero_call(
    tmp_path: Path,
) -> None:
    bundle, all60, expert = _qualifications(one_positive=False)

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve(self, **_kwargs: Any) -> list[Any]:
            self.calls += 1
            raise AssertionError("knowledge gaps must not retrieve")

    retriever = Retriever()
    kwargs = {
        "run_id": "stage-a-all-gap",
        "output_root": tmp_path / "stage-a",
        "bundle": bundle,
        "candidate": _candidate(),
        "all60_qualification": all60,
        "expert_qualification": expert,
        "retriever": retriever,
        "as_of_date": AS_OF,
        "code_revision": "d" * 40,
        "code_dirty": False,
    }
    result = await run_stage_a_v2_create_only(**kwargs)
    assert result["stage_a_passed"] is False
    assert result["completed_checkpoint_count"] == 585
    assert retriever.calls == 0
    run_root = tmp_path / "stage-a/stage-a-all-gap"
    checkpoints = tuple((run_root / "checkpoints").glob("*.json"))
    assert len(checkpoints) == 585
    original = (run_root / "stage-a-result.json").read_bytes()
    resumed = await run_stage_a_v2_create_only(**kwargs)
    assert resumed == result
    assert (run_root / "stage-a-result.json").read_bytes() == original
    assert retriever.calls == 0
    assert stat.S_IMODE(run_root.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in checkpoints)
    encoded = "\n".join(path.read_text() for path in run_root.rglob("*.json"))
    assert bundle.registry.cases[0].question not in encoded
    assert all(topic not in encoded for topic in bundle.registry.cases[0].must_cover_issues)
    assert "/Users/" not in encoded


@pytest.mark.asyncio
async def test_stage_a_exact_positive_ranking_passes_and_is_candidate_bound(
    tmp_path: Path,
) -> None:
    bundle, all60, expert = _qualifications(one_positive=True)

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve(self, **_kwargs: Any) -> list[EvidenceSpan]:
            self.calls += 1
            return [_evidence()]

    retriever = Retriever()
    result = await run_stage_a_v2_create_only(
        run_id="stage-a-positive",
        output_root=tmp_path / "stage-a",
        bundle=bundle,
        candidate=_candidate(),
        all60_qualification=all60,
        expert_qualification=expert,
        retriever=retriever,
        as_of_date=AS_OF,
        code_revision="d" * 40,
        code_dirty=False,
    )
    assert result["stage_a_passed"] is True
    assert result["scored_issue_count"] == 1
    assert result["completed_checkpoint_count"] == 585
    assert retriever.calls == 1


@pytest.mark.asyncio
async def test_stage_a_same_chunk_with_wrong_exact_metadata_remains_ranked_miss(
    tmp_path: Path,
) -> None:
    bundle, all60, expert = _qualifications(one_positive=True)

    class Retriever:
        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve(self, **_kwargs: Any) -> list[EvidenceSpan]:
            return [_evidence().model_copy(update={"content_sha256": "9" * 64})]

    result = await run_stage_a_v2_create_only(
        run_id="stage-a-exact-miss",
        output_root=tmp_path / "stage-a",
        bundle=bundle,
        candidate=_candidate(),
        all60_qualification=all60,
        expert_qualification=expert,
        retriever=Retriever(),
        as_of_date=AS_OF,
        code_revision="d" * 40,
        code_dirty=False,
    )

    assert result["stage_a_passed"] is False
    assert result["recall_at_5"] == 0.0
    checkpoint = json.loads(
        (
            tmp_path / "stage-a/stage-a-exact-miss/checkpoints/0001-live30-q01-issue-01.json"
        ).read_text()
    )
    assert checkpoint["ranked_identity_tokens"][0].startswith("miss:")
    assert checkpoint["ranked_identity_tokens"][0] != "gold-stage-a-1"


@pytest.mark.asyncio
async def test_stage_a_wrong_returned_candidate_pin_hard_stops_without_checkpoint(
    tmp_path: Path,
) -> None:
    bundle, all60, expert = _qualifications(one_positive=True)

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve(self, **_kwargs: Any) -> list[EvidenceSpan]:
            self.calls += 1
            return [_evidence().model_copy(update={"index_build_id": "candidate-other"})]

    retriever = Retriever()
    result = await run_stage_a_v2_create_only(
        run_id="stage-a-wrong-pin",
        output_root=tmp_path / "stage-a",
        bundle=bundle,
        candidate=_candidate(),
        all60_qualification=all60,
        expert_qualification=expert,
        retriever=retriever,
        as_of_date=AS_OF,
        code_revision="d" * 40,
        code_dirty=False,
    )

    assert result["status"] == "stopped"
    assert result["failure_reason_code"] == "evidence_filter_violation"
    assert result["stop_reason"] == "deterministic_safety_failure"
    assert retriever.calls == 1
    assert not (
        tmp_path / "stage-a/stage-a-wrong-pin/checkpoints/0001-live30-q01-issue-01.json"
    ).exists()


@pytest.mark.asyncio
async def test_stage_a_opaque_runtime_failure_stops_without_unproved_retry(
    tmp_path: Path,
) -> None:
    bundle, all60, expert = _qualifications(one_positive=True)

    class Retriever:
        calls = 0

        def active_build_id(self) -> str:
            return "candidate-v111"

        async def retrieve(self, **_kwargs: Any) -> list[Any]:
            self.calls += 1
            raise RuntimeError("transient_worker_failure")

    retriever = Retriever()
    result = await run_stage_a_v2_create_only(
        run_id="stage-a-stop",
        output_root=tmp_path / "stage-a",
        bundle=bundle,
        candidate=_candidate(),
        all60_qualification=all60,
        expert_qualification=expert,
        retriever=retriever,
        as_of_date=AS_OF,
        code_revision="d" * 40,
        code_dirty=False,
    )
    assert result["status"] == "stopped"
    assert result["stop_reason"] == "retry_condition_unchanged"
    assert retriever.calls == 1
    assert not (tmp_path / "stage-a/stage-a-stop/stage-a-result.json").exists()
    stopped = json.loads((tmp_path / "stage-a/stage-a-stop/STOPPED.json").read_text())
    assert stopped["completed_checkpoint_count"] == 0
