from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation.live30 import Live30RunStore, RunProvenance, load_live30_suite
from app.evaluation.live30_coverage import _candidate_matches_gold, run_suite_coverage
from app.evaluation.live30_gold import (
    Live30ExpertQualification,
    Live30GoldSpan,
    Live30IssueQualification,
    qualification_sha256,
)
from app.types import EvidenceSpan, MaterialLane, case_proposition_review_sha256


def _suite():
    root = Path(__file__).resolve().parents[2]
    return load_live30_suite(
        root / "benchmarks" / "evaluation" / "live-evaluation-30-v1" / "cases.jsonl"
    )


def _store(tmp_path: Path) -> tuple[Live30RunStore, str]:
    suite = _suite()
    store = Live30RunStore(
        tmp_path,
        LocalCipher(Fernet(Fernet.generate_key())),
    )
    run_id = "live30-coverage-test"
    store.create_run(
        run_id=run_id,
        suite=suite,
        provenance=RunProvenance(
            git_sha="a" * 40,
            git_dirty=False,
            index_build_id="candidate-test-v1",
            policy_sha256="b" * 64,
            assessment_rules_sha256="c" * 64,
        ),
        as_of_date=date(2026, 8, 14),
    )
    return store, run_id


class _QualifiedRetriever:
    async def retrieve(self, **_kwargs):
        return (
            EvidenceSpan(
                id="evidence-safe-001",
                source_version_id="source-version-safe-001",
                chunk_id="chunk-safe-001",
                text="The verified source contains a substantive legal proposition.",
                locator="paragraph 12",
                lane=MaterialLane.PRIMARY_AUTHORITY,
                jurisdiction="England and Wales",
                subject="contract",
                citation_data={"source_type": "legislation"},
                canonical_citation="[2020] UKSC 1",
                currentness_status="latest_available_revised_snapshot",
                content_sha256="d" * 64,
                index_build_id="candidate-test-v1",
                retrieval_relevance_score=0.9,
                legal_role="statutory_text",
                provision_extent_status="england_and_wales_verified",
                unapplied_effect_count=0,
                identity_verified=True,
                currentness_verified=True,
            ),
        )


class _EmptyRetriever:
    async def retrieve(self, **_kwargs):
        return ()


def _expert_qualification() -> Live30ExpertQualification:
    suite = _suite()
    value = {
        "schema": "legalbot.live30-expert-qualification.v2",
        "suite_id": "live-evaluation-30-v1",
        "suite_canonical_sha256": suite.canonical_sha256,
        "index_build_id": "candidate-test-v1",
        "as_of_date": "2026-08-14",
        "purpose": "evaluation_only",
        "eligible_for_training": False,
        "training_export_allowed": False,
        "approval_status": "expert_approved",
        "approval_role": "legal_expert_owner",
        "approval_reviewer_role": "england_wales_qualified_solicitor",
        "approval_reviewer_ref": f"reviewer:{'1' * 64}",
        "independent_second_review_status": "confirmed",
        "independent_second_reviewer_role": ("england_wales_qualified_legal_academic"),
        "independent_second_reviewer_ref": f"reviewer:{'2' * 64}",
        "material_disagreement_status": "none",
        "adjudication_ref": None,
        "case_count": 30,
        "cases": [
            {
                "schema": "legalbot.live30-case-qualification.v2",
                "case_id": case.case_id,
                "question_sha256": case.question_sha256,
                "record_sha256": case.record_sha256,
                "status": "qualified",
                "contrary_authority_status": "reviewed_none",
                "acceptable_source_ids": ["authority-safe-001"],
                "issues": [
                    {
                        "schema": "legalbot.live30-issue-qualification.v1",
                        "issue_id": f"issue-{number:02d}",
                        "status": "qualified",
                        "reason_code": None,
                        "exact_gold_spans": [
                            {
                                "schema": "legalbot.live30-gold-span.v2",
                                "gold_span_id": f"gold-{case.case_id}-{number:02d}",
                                "issue_id": f"issue-{number:02d}",
                                "stable_source_id": "authority-safe-001",
                                "legal_authority_id": None,
                                "source_version_id": "source-version-safe-001",
                                "chunk_id": "chunk-safe-001",
                                "legal_locator": "paragraph 12",
                                "content_sha256": "d" * 64,
                                "source_type": "legislation",
                                "legal_role": "statutory_text",
                                "proposition_hash": None,
                                "case_currentness_review": None,
                                "relevance_grade": 3,
                                "contrary_or_limiting": False,
                            }
                        ],
                    }
                    for number in range(1, len(case.must_cover_issues) + 1)
                ],
            }
            for case in suite.cases
        ],
    }
    value["seal_sha256"] = qualification_sha256(value)
    return Live30ExpertQualification.model_validate(value)


def _partial_expert_qualification() -> Live30ExpertQualification:
    value = _expert_qualification().model_dump(mode="json", by_alias=True)
    first = value["cases"][0]
    first["status"] = "limited"
    first["issues"][0]["status"] = "limited"
    first["issues"][0]["reason_code"] = "known_incomplete_authority_set"
    first["issues"][1]["status"] = "knowledge_gap"
    first["issues"][1]["reason_code"] = "authority_not_yet_qualified"
    first["issues"][1]["exact_gold_spans"] = []
    second = value["cases"][1]
    second["status"] = "knowledge_gap"
    second["acceptable_source_ids"] = []
    for issue in second["issues"]:
        issue["status"] = "knowledge_gap"
        issue["reason_code"] = "authority_not_yet_qualified"
        issue["exact_gold_spans"] = []
    value["seal_sha256"] = qualification_sha256(value)
    return Live30ExpertQualification.model_validate(value)


@pytest.mark.parametrize(
    ("status", "reason_code", "keep_gold", "message"),
    (
        ("qualified", "unexpected_limit", True, "qualified issue requires"),
        ("limited", None, True, "limited issue requires"),
        (
            "knowledge_gap",
            "authority_not_yet_qualified",
            True,
            "cannot contain fabricated gold",
        ),
    ),
)
def test_issue_dispositions_fail_closed_when_status_and_gold_disagree(
    status: str,
    reason_code: str | None,
    keep_gold: bool,
    message: str,
) -> None:
    span = _expert_qualification().cases[0].issues[0].exact_gold_spans[0]

    with pytest.raises(ValueError, match=message):
        Live30IssueQualification.model_validate(
            {
                "schema": "legalbot.live30-issue-qualification.v1",
                "issue_id": "issue-01",
                "status": status,
                "reason_code": reason_code,
                "exact_gold_spans": [span.model_dump(mode="json", by_alias=True)]
                if keep_gold
                else [],
            }
        )


@pytest.mark.asyncio
async def test_coverage_records_candidates_but_does_not_invent_gold_or_enable_generation(
    tmp_path: Path,
) -> None:
    suite = _suite()
    store, run_id = _store(tmp_path)
    summary = await run_suite_coverage(
        store=store,
        retriever=_QualifiedRetriever(),
        run_id=run_id,
        suite=suite,
        case_ids=("live30-q01",),
    )

    assert summary["case_count"] == 1
    assert summary["generation_eligible_case_count"] == 0
    assert summary["ranking_metric_state"] == "not_evaluated_without_expert_qualification"
    case_root = tmp_path / "data/evaluations/e2e/runs" / run_id / "cases/live30-q01"
    metrics = json.loads((case_root / "metrics.json").read_text())
    coverage = json.loads((case_root / "coverage.json").read_text())
    evidence = json.loads((case_root / "evidence-map.json").read_text())
    assert metrics["recall_at_5"] is None
    assert coverage["generation_eligible"] is False
    assert evidence["expert_qualified"] is False
    assert evidence["issues"][0]["candidates"][0]["index_build_id"] == "candidate-test-v1"


@pytest.mark.asyncio
async def test_sealed_expert_gold_enables_generation_only_after_exact_runtime_match(
    tmp_path: Path,
) -> None:
    suite = _suite()
    store, run_id = _store(tmp_path)
    summary = await run_suite_coverage(
        store=store,
        retriever=_QualifiedRetriever(),
        run_id=run_id,
        suite=suite,
        case_ids=("live30-q01",),
        qualification=_expert_qualification(),
    )

    assert summary["generation_eligible_case_count"] == 1
    assert summary["ranking_metric_state"] == "evaluated_against_sealed_qualifying_issue_gold"
    assert summary["recall_at_5"] == 1.0
    assert summary["mrr"] == 1.0
    assert summary["ndcg_at_10"] == 1.0
    assert summary["contrary_authority_recall"] == 1.0
    coverage = json.loads(
        (
            tmp_path
            / "data/evaluations/e2e/runs/live30-coverage-test/cases/live30-q01/coverage.json"
        ).read_text()
    )
    assert coverage["generation_eligible"] is True


@pytest.mark.asyncio
async def test_partial_sealed_qualification_scores_only_annotated_issues(
    tmp_path: Path,
) -> None:
    suite = _suite()
    store, run_id = _store(tmp_path)

    summary = await run_suite_coverage(
        store=store,
        retriever=_QualifiedRetriever(),
        run_id=run_id,
        suite=suite,
        case_ids=("live30-q01", "live30-q02"),
        qualification=_partial_expert_qualification(),
    )

    assert summary["qualification_status_counts"] == {
        "knowledge_gap": 1,
        "limited": 1,
    }
    assert summary["scored_issue_count"] == len(suite.cases[0].must_cover_issues) - 2
    assert summary["recall_at_5"] == 1.0
    assert summary["recall_at_10"] == 1.0
    assert summary["generation_eligible_case_count"] == 0
    assert summary["deterministic_limited_case_ids"] == ["live30-q01"]
    assert summary["deterministic_held_case_ids"] == ["live30-q02"]
    first_coverage = json.loads(
        (store.runs_root / run_id / "cases/live30-q01/coverage.json").read_text()
    )
    first_metrics = json.loads(
        (store.runs_root / run_id / "cases/live30-q01/metrics.json").read_text()
    )
    second_metrics = json.loads(
        (store.runs_root / run_id / "cases/live30-q02/metrics.json").read_text()
    )
    assert first_coverage["coverage_status"] == "evidence_limited"
    assert first_coverage["deterministic_outcome"] == "limited"
    assert first_metrics["scored_issue_count"] == len(suite.cases[0].must_cover_issues) - 2
    assert second_metrics["ranking_metric_state"] == ("not_evaluated_explicit_knowledge_gap")
    assert second_metrics["recall_at_5"] is None


@pytest.mark.asyncio
async def test_coverage_accepts_repaired_q24_subject_family_without_narrow_misrouting(
    tmp_path: Path,
) -> None:
    suite = _suite()
    store, run_id = _store(tmp_path)

    summary = await run_suite_coverage(
        store=store,
        retriever=_QualifiedRetriever(),
        run_id=run_id,
        suite=suite,
        case_ids=("live30-q24",),
        qualification=_expert_qualification(),
    )

    assert summary["subject_routing_pass_count"] == 1
    assert summary["subject_incompatible_case_ids"] == []
    assert summary["generation_eligible_case_count"] == 1
    coverage = json.loads(
        (store.runs_root / run_id / "cases/live30-q24/coverage.json").read_text(encoding="utf-8")
    )
    assert coverage["subject_routing_state"] == "compatible"
    assert coverage["recognised_subjects"][0] == ("legal ethics and artificial intelligence")


@pytest.mark.asyncio
async def test_empty_retrieval_creates_hash_only_gap_index(tmp_path: Path) -> None:
    suite = _suite()
    store, run_id = _store(tmp_path)
    await run_suite_coverage(
        store=store,
        retriever=_EmptyRetriever(),
        run_id=run_id,
        suite=suite,
        case_ids=("live30-q01",),
    )

    gap_path = tmp_path / "data/evaluations/e2e/runs" / run_id / "knowledge-gaps/index.jsonl"
    raw = gap_path.read_text()
    assert "breach" not in raw.casefold()
    rows = [json.loads(line) for line in raw.splitlines()]
    assert rows
    assert all(row["status"] == "open" for row in rows)
    assert all(len(row["issue_sha256"]) == 64 for row in rows)


def test_plaintext_safe_case_artifact_rejects_question_or_path(tmp_path: Path) -> None:
    store, run_id = _store(tmp_path)
    with pytest.raises(ValueError, match="forbidden plaintext evaluation field"):
        store.store_safe_case_json(
            run_id=run_id,
            case_id="live30-q01",
            filename="metrics.json",
            value={"question": "private"},
        )
    with pytest.raises(ValueError, match="sensitive text"):
        store.store_safe_case_json(
            run_id=run_id,
            case_id="live30-q01",
            filename="metrics.json",
            value={"safe_code": "/Users/example/private"},
        )


def test_exact_statutory_gold_role_matches_runtime_candidate() -> None:
    gold = Live30GoldSpan(
        gold_span_id="gold-statute-001",
        issue_id="issue-01",
        stable_source_id="ukpga:2026:1",
        legal_authority_id=None,
        source_version_id="source-version-statute-001",
        chunk_id="chunk-statute-001",
        legal_locator="paragraph 100",
        content_sha256="e" * 64,
        source_type="legislation",
        legal_role="statutory_text",
        relevance_grade=3,
    )
    candidate = {
        "source_version_id": "source-version-statute-001",
        "chunk_id": "chunk-statute-001",
        "content_sha256": "e" * 64,
        "locator": "paragraph 100",
        "legal_role": "statutory_text",
        "runtime_qualification_passed": True,
    }

    assert _candidate_matches_gold(candidate, gold) is True


def _case_review_value() -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "legalbot.case-proposition-currentness-review.v1",
        "source_version_id": "source-version-quistclose-001",
        "chunk_id": "chunk-quistclose-001",
        "legal_locator": "paragraph 100",
        "exact_span_sha256": "e" * 64,
        "proposition_hash": "f" * 64,
        "legal_role": "holding_ratio",
        "later_treatment_reviewed_as_of_date": "2026-08-14",
        "later_treatment_status": "confirmed_current",
        "contrary_or_limiting_authority_ids": [],
        "reviewer_role": "england_wales_qualified_legal_academic",
        "reviewer_ref": f"reviewer:{'a' * 64}",
        "review_scope": "ordinary",
        "second_review_status": "not_required",
        "second_reviewer_ref": None,
    }
    value["seal_sha256"] = case_proposition_review_sha256(value)
    return value


def test_case_gold_requires_and_matches_exact_sealed_proposition_review() -> None:
    with pytest.raises(ValueError, match="requires an exact proposition review"):
        Live30GoldSpan(
            gold_span_id="gold-quistclose-001",
            issue_id="issue-01",
            stable_source_id="neutral-citation-sha256:abc123",
            legal_authority_id="neutral-citation:[2002] UKHL 12",
            source_version_id="source-version-quistclose-001",
            chunk_id="chunk-quistclose-001",
            legal_locator="paragraph 100",
            content_sha256="e" * 64,
            source_type="case",
            legal_role="holding_ratio",
            relevance_grade=3,
        )

    gold = Live30GoldSpan(
        gold_span_id="gold-quistclose-001",
        issue_id="issue-01",
        stable_source_id="neutral-citation-sha256:abc123",
        legal_authority_id="neutral-citation:[2002] UKHL 12",
        source_version_id="source-version-quistclose-001",
        chunk_id="chunk-quistclose-001",
        legal_locator="paragraph 100",
        content_sha256="e" * 64,
        source_type="case",
        legal_role="holding_ratio",
        proposition_hash="f" * 64,
        case_currentness_review=_case_review_value(),
        relevance_grade=3,
    )
    candidate = {
        "source_version_id": "source-version-quistclose-001",
        "chunk_id": "chunk-quistclose-001",
        "content_sha256": "e" * 64,
        "locator": "paragraph 100",
        "legal_role": "holding_ratio",
        "case_proposition_hashes": ["f" * 64],
        "case_currentness_review_seals": [gold.case_currentness_review.seal_sha256],
        "runtime_qualification_passed": True,
    }
    assert _candidate_matches_gold(candidate, gold)
    candidate["case_proposition_hashes"] = ["0" * 64]
    assert not _candidate_matches_gold(candidate, gold)


def test_expert_gold_rejects_duplicate_span_identity_with_a_new_display_id() -> None:
    value = _expert_qualification().model_dump(mode="json", by_alias=True)
    duplicate = dict(value["cases"][0]["issues"][0]["exact_gold_spans"][0])
    duplicate["gold_span_id"] = "gold-live30-q01-duplicate"
    value["cases"][0]["issues"][0]["exact_gold_spans"].append(duplicate)
    value["seal_sha256"] = qualification_sha256(value)

    with pytest.raises(ValueError, match="gold span identity is duplicated"):
        Live30ExpertQualification.model_validate(value)
