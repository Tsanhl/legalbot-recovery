from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

from app.crypto import LocalCipher
from app.evaluation.live30 import RunProvenance
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_contrary_authority import CONTRARY_REVIEW_SCHEMA
from app.evaluation.live_suite_coverage import run_case_coverage
from app.evaluation.live_suite_gold import LiveCaseQualification
from app.evaluation.live_suite_owner_decision_contract import owner_decision_template
from app.evaluation.live_suite_owner_decisions import (
    apply_owner_ticks,
    build_issue_decision_pack,
    build_owner_reviewer_identity,
)
from app.evaluation.live_suite_path_b import (
    export_review_candidates,
    import_reviewed_rows,
    reconstruct_overlay,
    seal_overlay_from_reviewed_rows,
    selected_generation_case_ids,
)
from app.evaluation.live_suite_store import LiveSuiteRunStore
from app.types import EvidenceSpan, MaterialLane

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


def _cipher() -> LocalCipher:
    return LocalCipher(Fernet(Fernet.generate_key()))


def test_review_export_has_585_rows_and_no_question_prose(tmp_path: Path) -> None:
    destination = tmp_path / "review-export.json"
    result = export_review_candidates(
        project_root=PROJECT_ROOT,
        destination=destination,
        cipher=_cipher(),
        as_of_date=date(2026, 8, 16),
    )
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert result["row_count"] == 585
    assert payload["issue_count"] == 585
    assert payload["seals_expert_gold"] is False
    assert payload["writes_active"] is False
    assert payload["writes_o04"] is False
    dumped = json.dumps(payload)
    assert '"question":' not in dumped
    assert "question_sha256" in dumped
    assert payload["plaintext_span_preview"] == "encrypted_object_only"
    assert (destination.parent / "encrypted" / payload["encrypted_preview_object"]).is_file()


def test_review_import_rejects_foreign_rows_and_named_qualify_without_spans(
    tmp_path: Path,
) -> None:
    export_path = tmp_path / "review-export.json"
    export_review_candidates(
        project_root=PROJECT_ROOT,
        destination=export_path,
        cipher=_cipher(),
        as_of_date=date(2026, 8, 16),
    )
    export = json.loads(export_path.read_text(encoding="utf-8"))
    foreign = tmp_path / "foreign.json"
    foreign.write_text(
        json.dumps(
            {
                "schema": "legalbot.live60-review-import.v1",
                "rows": [
                    {
                        "row_id": "live30-q99:issue-01",
                        "case_id": "live30-q99",
                        "issue_id": "issue-01",
                        "status": "qualified",
                        "exact_gold_spans": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not in the sealed export"):
        import_reviewed_rows(
            project_root=PROJECT_ROOT,
            export_path=export_path,
            reviewed_path=foreign,
        )
    named = tmp_path / "named.json"
    first = export["rows"][0]
    named.write_text(
        json.dumps(
            {
                "schema": "legalbot.live60-review-import.v1",
                "rows": [
                    {
                        **{key: first[key] for key in ("row_id", "case_id", "issue_id")},
                        "status": "qualified",
                        "exact_gold_spans": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="exact spans"):
        import_reviewed_rows(
            project_root=PROJECT_ROOT,
            export_path=export_path,
            reviewed_path=named,
        )


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def _sealed_path_b_artifacts(
    tmp_path: Path,
    bundle: Any,
    *,
    run_id: str,
    index_build_id: str,
    as_of_date: str = "2026-08-16",
    contrary_status: str = "reviewed_none_in_defined_source_set",
    independent_second_review_status: str = "not_required",
) -> tuple[Path, Path]:
    contrary = {
        "schema": CONTRARY_REVIEW_SCHEMA,
        "suite_id": "live-evaluation-60-v1",
        "as_of_date": as_of_date,
        "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
        "run_plan_sha256": bundle.manifest.run_plan_sha256,
        "index_build_id": index_build_id,
        "run_id": run_id,
        "owner_authored": True,
        "ai_self_authored": False,
        "status": contrary_status,
        "defined_source_set_id": "live60-defined-source-set-v1",
        "defined_source_set_review_method": "owner_manual_named_source_set",
        "defined_source_set_reviewed_as_of_date": as_of_date,
        "reviewer_scope": "owner_primary_defined_source_set",
        "means_english_law_has_no_contrary_authority": False,
        "critical_or_disputed_requires_independent_second_review": True,
        "bound_contrary_span_count": 0,
        "independent_second_review_status": independent_second_review_status,
    }
    contrary["seal_sha256"] = sealed_sha256(contrary)
    template = owner_decision_template(as_of_date=as_of_date)
    decisions = []
    for item in template["decisions"]:
        state = "pending" if item["state"] == "unsigned" else item["state"]
        decisions.append({**item, "state": state})
    owner = {
        key: value for key, value in template.items() if key not in {"unsigned", "seal_sha256"}
    }
    owner.update(
        {
            "suite_registry_canonical_sha256": bundle.registry.canonical_sha256,
            "run_plan_sha256": bundle.manifest.run_plan_sha256,
            "index_build_id": index_build_id,
            "run_id": run_id,
            "owner_authored": True,
            "ai_self_authored": False,
            "decisions": decisions,
        }
    )
    owner["seal_sha256"] = sealed_sha256(owner)
    return (
        _write_json(tmp_path / "contrary-review.json", contrary),
        _write_json(tmp_path / "owner-decisions.json", owner),
    )


def test_overlay_reconstruction_and_owner_seal_require_585_and_reviewer_ref(
    tmp_path: Path,
) -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    export_path = tmp_path / "review-export.json"
    export_review_candidates(
        project_root=PROJECT_ROOT,
        destination=export_path,
        cipher=_cipher(),
        as_of_date=date(2026, 8, 16),
    )
    export = json.loads(export_path.read_text(encoding="utf-8"))
    reviewed_path = tmp_path / "reviewed.json"
    reviewed_path.write_text(
        json.dumps({"schema": "legalbot.live60-review-import.v1", "rows": export["rows"]}),
        encoding="utf-8",
    )
    imported = import_reviewed_rows(
        project_root=PROJECT_ROOT,
        export_path=export_path,
        reviewed_path=reviewed_path,
    )
    reconstruction = reconstruct_overlay(
        project_root=PROJECT_ROOT,
        imported=imported,
        as_of_date=date(2026, 8, 16),
    )
    assert reconstruction["issue_count"] == 585
    assert reconstruction["knowledge_gap_issue_count"] == 585
    assert reconstruction["selected_issue_count"] == 305
    assert reconstruction["selected_qualified_issue_count"] == 0
    assert reconstruction["selected_qualified_case_count"] == 0
    assert reconstruction["full_run_overlay_ready"] is False
    assert reconstruction["seals_expert_gold"] is False
    assert reconstruction["issue_identities"]
    assert {case["contrary_authority_status"] for case in reconstruction["cases"]} == {"unresolved"}
    refused = seal_overlay_from_reviewed_rows(
        project_root=PROJECT_ROOT,
        reconstruction=reconstruction,
        reviewer_ref="not-a-reviewer",
        index_build_id="candidate-test-v1",
    )
    assert refused["sealed"] is False
    assert refused["approval_status"] == "uncertain_hold"
    assert "owner_reviewer_ref_invalid" in refused["blocking_reason_codes"]
    assert "contrary_review_missing_or_unresolved" in refused["blocking_reason_codes"]
    assert "owner_decisions_missing_or_unsealed" in refused["blocking_reason_codes"]
    identity = build_owner_reviewer_identity(as_of_date=date(2026, 8, 16))
    destination = tmp_path / "expert-qualification.json"
    held = seal_overlay_from_reviewed_rows(
        project_root=PROJECT_ROOT,
        reconstruction=reconstruction,
        reviewer_ref=identity["approval_reviewer_ref"],
        index_build_id="candidate-test-v1",
        run_id="live60-path-b-test",
        destination=destination,
    )
    assert held["sealed"] is False
    assert held["approval_status"] == "uncertain_hold"
    assert not destination.exists()
    contrary_path, decisions_path = _sealed_path_b_artifacts(
        tmp_path,
        bundle,
        run_id="live60-path-b-test",
        index_build_id="candidate-test-v1",
    )
    unsigned_hold = seal_overlay_from_reviewed_rows(
        project_root=PROJECT_ROOT,
        reconstruction=reconstruction,
        reviewer_ref=identity["approval_reviewer_ref"],
        index_build_id="candidate-test-v1",
        run_id="live60-path-b-test",
        contrary_review_path=tmp_path / "missing-contrary.json",
        owner_decisions_path=decisions_path,
        require_full_30_selected=False,
    )
    assert unsigned_hold["sealed"] is False
    assert unsigned_hold["approval_status"] == "uncertain_hold"
    unresolved_dir = tmp_path / "unresolved-review"
    unresolved_dir.mkdir()
    unresolved_contrary, unresolved_decisions = _sealed_path_b_artifacts(
        unresolved_dir,
        bundle,
        run_id="live60-path-b-test",
        index_build_id="candidate-test-v1",
        independent_second_review_status="needs_independent_review",
    )
    unresolved = seal_overlay_from_reviewed_rows(
        project_root=PROJECT_ROOT,
        reconstruction=reconstruction,
        reviewer_ref=identity["approval_reviewer_ref"],
        index_build_id="candidate-test-v1",
        run_id="live60-path-b-test",
        contrary_review_path=unresolved_contrary,
        owner_decisions_path=unresolved_decisions,
        destination=destination,
        require_full_30_selected=False,
    )
    assert unresolved["sealed"] is False
    assert unresolved["approval_status"] == "uncertain_hold"
    assert "contrary_review_unresolved" in unresolved["blocking_reason_codes"]
    assert not destination.exists()
    sealed = seal_overlay_from_reviewed_rows(
        project_root=PROJECT_ROOT,
        reconstruction=reconstruction,
        reviewer_ref=identity["approval_reviewer_ref"],
        index_build_id="candidate-test-v1",
        run_id="live60-path-b-test",
        contrary_review_path=contrary_path,
        owner_decisions_path=decisions_path,
        destination=destination,
        require_full_30_selected=False,
    )
    assert sealed["sealed"] is True
    assert sealed["approval_status"] == "expert_approved"
    overlay = json.loads(destination.read_text())
    assert overlay["case_count"] == 60
    assert {case["contrary_authority_status"] for case in overlay["cases"]} == {"reviewed_none"}
    full_run_hold = seal_overlay_from_reviewed_rows(
        project_root=PROJECT_ROOT,
        reconstruction=reconstruction,
        reviewer_ref=identity["approval_reviewer_ref"],
        index_build_id="candidate-test-v1",
        run_id="live60-path-b-test",
        contrary_review_path=contrary_path,
        owner_decisions_path=decisions_path,
    )
    assert full_run_hold["sealed"] is False
    assert full_run_hold["approval_status"] == "uncertain_hold"
    assert "selected_qualified_case_count_not_30" in full_run_hold["blocking_reason_codes"]
    assert "selected_issues_missing_positive_exact_spans" in full_run_hold["blocking_reason_codes"]
    identity_pack = build_issue_decision_pack(bundle, as_of_date=date(2026, 8, 16))
    with pytest.raises(ValueError, match="exact spans"):
        apply_owner_ticks(
            bundle=bundle,
            identity=identity,
            issue_pack=identity_pack,
            mechanical={"results": []},
            contrary_authority_status=None,
            qualified_issue_ids=["live30-q03:issue-01"],
        )


def _q03_qualification(bundle: Any, *, qualified_count: int) -> LiveCaseQualification:
    case = bundle.registry.case("live30-q03")
    issues = []
    for number, _topic in enumerate(case.must_cover_issues, start=1):
        qualified = number <= qualified_count
        issues.append(
            {
                "schema": "legalbot.live-issue-qualification.v1",
                "issue_id": f"issue-{number:02d}",
                "status": "qualified" if qualified else "knowledge_gap",
                "reason_code": None if qualified else "owner_confirmed_knowledge_gap",
                "exact_gold_spans": [
                    {
                        "schema": "legalbot.live-gold-span.v1",
                        "gold_span_id": f"gold-live30-q03-{number:02d}",
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
                ]
                if qualified
                else [],
            }
        )
    statuses = {item["status"] for item in issues}
    status = (
        "qualified"
        if statuses == {"qualified"}
        else "knowledge_gap"
        if statuses == {"knowledge_gap"}
        else "limited"
    )
    return LiveCaseQualification.model_validate(
        {
            "schema": "legalbot.live-case-qualification.v1",
            "case_id": case.case_id,
            "question_sha256": case.question_sha256,
            "record_sha256": case.record_sha256,
            "status": status,
            "contrary_authority_status": "reviewed_none",
            "acceptable_source_ids": ["authority-safe-001"] if qualified_count else [],
            "issues": issues,
        }
    )


class _MatchingRetriever:
    async def retrieve(self, **_kwargs: Any) -> tuple[EvidenceSpan, ...]:
        return (
            EvidenceSpan(
                id="evidence-safe-001",
                source_version_id="source-version-safe-001",
                chunk_id="chunk-safe-001",
                text="The verified source contains a substantive legal proposition.",
                locator="paragraph 12",
                lane=MaterialLane.PRIMARY_AUTHORITY,
                jurisdiction="England and Wales",
                subject="tort",
                citation_data={"source_type": "legislation"},
                canonical_citation="[2020] UKSC 1",
                currentness_status="latest_available_revised_snapshot",
                content_sha256="d" * 64,
                index_build_id="candidate-live60-q03",
                retrieval_relevance_score=0.9,
                legal_role="statutory_text",
                provision_extent_status="england_and_wales_verified",
                unapplied_effect_count=0,
                identity_verified=True,
                currentness_verified=True,
            ),
        )


class _EmptyRetriever:
    async def retrieve(self, **_kwargs: Any) -> tuple[Any, ...]:
        return ()


def _run_store(tmp_path: Path) -> tuple[LiveSuiteRunStore, Any]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    store = LiveSuiteRunStore(tmp_path / "project", _cipher())
    store.create_run(
        run_id="live60-q03-path-b",
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="a" * 40,
            git_dirty=False,
            index_build_id="candidate-live60-q03",
        ),
        admitted_at=datetime(2026, 8, 15, 23, 30, tzinfo=UTC),
    )
    return store, bundle


@pytest.mark.asyncio
async def test_q03_six_of_seven_is_not_generation_eligible(tmp_path: Path) -> None:
    store, bundle = _run_store(tmp_path)
    case = bundle.registry.case("live30-q03")
    assert len(case.must_cover_issues) == 7
    result = await run_case_coverage(
        store=store,
        retriever=_MatchingRetriever(),
        run_id="live60-q03-path-b",
        case=case,
        disposition="generate_once",
        qualification=_q03_qualification(bundle, qualified_count=6),
    )
    assert result.selected_generation_eligible is False
    assert result.deterministic_outcome in {"held", "limited"}


@pytest.mark.asyncio
async def test_q03_seven_of_seven_missing_retrieval_is_held(tmp_path: Path) -> None:
    store, bundle = _run_store(tmp_path)
    result = await run_case_coverage(
        store=store,
        retriever=_EmptyRetriever(),
        run_id="live60-q03-path-b",
        case=bundle.registry.case("live30-q03"),
        disposition="generate_once",
        qualification=_q03_qualification(bundle, qualified_count=7),
    )
    assert result.selected_generation_eligible is False
    assert result.deterministic_outcome == "held"
    assert result.coverage_status == "qualified_gold_not_retrieved"


@pytest.mark.asyncio
async def test_q03_all_retrieved_is_eligible_only_for_that_case(tmp_path: Path) -> None:
    store, bundle = _run_store(tmp_path)
    result = await run_case_coverage(
        store=store,
        retriever=_MatchingRetriever(),
        run_id="live60-q03-path-b",
        case=bundle.registry.case("live30-q03"),
        disposition="generate_once",
        qualification=_q03_qualification(bundle, qualified_count=7),
    )
    assert result.selected_generation_eligible is True
    assert result.deterministic_outcome == "generate"
    other_store = LiveSuiteRunStore(tmp_path / "other", _cipher())
    other_store.create_run(
        run_id="live60-other-selected",
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="b" * 40,
            git_dirty=False,
            index_build_id="candidate-live60-q03",
        ),
        admitted_at=datetime(2026, 8, 15, 23, 30, tzinfo=UTC),
    )
    other_case = bundle.registry.case("live30-q02")
    other = await run_case_coverage(
        store=other_store,
        retriever=_EmptyRetriever(),
        run_id="live60-other-selected",
        case=other_case,
        disposition="generate_once",
        qualification=None,
    )
    assert other.selected_generation_eligible is False
    assert other.deterministic_outcome in {"held", "limited"}
    selected = selected_generation_case_ids(bundle)
    assert len(selected) == 30
    assert "live30-q03" in selected
    assert len([case_id for case_id in selected if case_id != "live30-q03"]) == 29
