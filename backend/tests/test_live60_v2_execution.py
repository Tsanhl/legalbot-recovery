from __future__ import annotations

import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.api.main import app
from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.db import utc_iso
from app.evaluation.live30 import RunProvenance
from app.evaluation.live_suite import load_live_evaluation_bundle
from app.evaluation.live_suite_admission import (
    Live60EvaluationAdmissionBinding,
    validate_live60_api_admission,
)
from app.evaluation.live_suite_current_state import (
    CurrentLiveStateResolver,
    selected_knowledge_gap_count,
)
from app.evaluation.live_suite_evaluation_auth import (
    issue_evaluation_authorization_v2,
    seal_evaluation_authorization_v2,
)
from app.evaluation.live_suite_evaluation_run import (
    execute_evaluation_only_run,
    outcome_gate_payload,
    plan_evaluation_only_run,
)
from app.evaluation.live_suite_evidence_policy import (
    ActorProvenanceV2,
    run_evidence_pipeline,
)
from app.evaluation.live_suite_execute import Live60ExecutionOutcome
from app.evaluation.live_suite_gap_verification import seal_gap_verification
from app.evaluation.live_suite_overlay_complete import overlay_complete_v2
from app.evaluation.live_suite_path_b import (
    frozen_selected_issue_identities,
    selected_generation_case_ids,
)
from app.evaluation.live_suite_semantic_result import invoke_semantic_verifier
from app.evaluation.live_suite_stage_a_v2 import evaluate_stage_a_from_retrieval, score_stage_a_v2
from app.evaluation.live_suite_store import LiveSuiteRunStore
from app.evaluation.live_suite_v1_to_v2_migration import (
    build_v1_to_v2_migration,
    migrate_selected_issue,
)
from app.evaluation.prompt_templates import (
    PROPOSER_TEMPLATE_SHA256,
    SEMANTIC_VERIFIER_TEMPLATE_SHA256,
    prompt_template_sha256,
)
from app.orchestration.classifier import CLASSIFIER_VERSION
from app.orchestration.routing import ROUTER_VERSION
from app.quality.policy import POLICY_SHA256
from app.retrieval.pinned_factory import PinnedRetrieverFactory
from app.retrieval.service import HybridRetrievalService, promote_candidate_index
from app.runtime_adapters import PROMPT_VERSION
from app.types import QuestionRequest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
AS_OF = "2026-08-16"


def test_prompt_hashes_are_computed_from_tracked_bytes() -> None:
    assert prompt_template_sha256("proposer_mapping.v2.txt") == PROPOSER_TEMPLATE_SHA256
    assert prompt_template_sha256("semantic_verifier.v2.txt") == SEMANTIC_VERIFIER_TEMPLATE_SHA256
    assert PROPOSER_TEMPLATE_SHA256 != SEMANTIC_VERIFIER_TEMPLATE_SHA256


def _bundle():
    return load_live_evaluation_bundle(BUNDLE_ROOT)


def _gap(issue_id: str) -> dict[str, Any]:
    return seal_gap_verification(
        {
            "issue_id": issue_id,
            "defined_source_set_id": "ew-primary-official-2026-08-17",
            "source_set_manifest_sha256": "1" * 64,
            "search_review_method": "defined_source_set_review",
            "coverage_result": "reviewed_none_in_defined_source_set",
            "as_of_date": AS_OF,
            "reason_code": "no_safe_span",
            "review_actor": "deterministic",
        }
    ).model_dump(mode="json", by_alias=True)


def _complete_issues(bundle, *, qualified: int = 1):
    identities = frozen_selected_issue_identities(bundle)
    issues: list[dict[str, Any]] = []
    for index, item in enumerate(identities):
        if index < qualified:
            issues.append(
                {
                    **item,
                    "disposition": "qualified",
                    "status": "qualified",
                    "final_verification_status": "VERIFIED",
                    "exact_gold_spans": [
                        {
                            "chunk_id": f"chunk-{item['issue_id']}",
                            "content_sha256": hashlib.sha256(item["row_id"].encode()).hexdigest(),
                            "legal_locator": "section 1",
                        }
                    ],
                    "semantic_result_seal_sha256": "e" * 64,
                    "invented_span": False,
                }
            )
        else:
            issues.append(
                {
                    **item,
                    "disposition": "knowledge_gap",
                    "status": "knowledge_gap",
                    "final_verification_status": "VERIFIED",
                    "exact_gold_spans": [],
                    "gap_reason": "no_safe_span",
                    "gap_verification": _gap(str(item["issue_id"])),
                    "invented_span": False,
                }
            )
    return issues


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _insert_candidate(database: Any, build_id: str, status: str = "candidate") -> None:
    now = utc_iso()
    database.execute(
        """
        INSERT INTO index_builds(
          id, status, path, document_count, chunk_count, vector_count,
          embedding_model, reranker_model, created_at, promoted_at
        ) VALUES (?, ?, ?, 1, 1, 1, 'Qwen/Qwen3-Embedding-0.6B',
                  'Qwen/Qwen3-Reranker-0.6B', ?, ?)
        """,
        (build_id, status, f"data/indexes/{build_id}", now, now if status == "active" else None),
    )


def _settings(tmp_path: Path) -> Settings:
    benchmarks = tmp_path / "benchmarks"
    if not benchmarks.exists():
        benchmarks.symlink_to(PROJECT_ROOT / "benchmarks")
    settings = Settings(project_root=tmp_path, test_mode=True)
    settings.ensure_runtime_dirs()
    return settings


def _passing_stage_a(candidate: str, issues: list[dict[str, Any]]) -> dict[str, Any]:
    rankings = []
    for issue in issues:
        if issue.get("disposition") in {"qualified", "limited"}:
            gold = [str(span["chunk_id"]) for span in issue.get("exact_gold_spans") or ()]
            rankings.append(
                {
                    "issue_id": issue["issue_id"],
                    "gold_span_ids": gold,
                    "ranked_chunk_ids": [*gold, "other-chunk"],
                    "filter_violation_count": 0,
                }
            )
    return score_stage_a_v2(
        issues=issues,
        unreviewed_issue_count=0,
        candidate_build_id=candidate,
        rankings=rankings,
    )


def test_selected_gap_arithmetic_subtracts_qualified_and_limited() -> None:
    assert (
        selected_knowledge_gap_count(
            selected_qualified=77, selected_limited=10, selected_unreviewed=0
        )
        == 218
    )


def test_overlay_rejects_305_issues_on_one_case() -> None:
    bundle = _bundle()
    issues = []
    for number in range(1, 306):
        issues.append(
            {
                "row_id": f"live30-q02:issue-{number:02d}",
                "case_id": "live30-q02",
                "issue_id": f"issue-{number:02d}",
                "disposition": "knowledge_gap",
                "status": "knowledge_gap",
                "final_verification_status": "VERIFIED",
                "gap_reason": "no_safe_span",
                "gap_verification": _gap(f"issue-{number:02d}"),
                "exact_gold_spans": [],
            }
        )
    payload = overlay_complete_v2(
        selected_issues=issues, bundle=bundle, enforce_frozen_identities=True
    )
    assert payload["review_overlay_complete"] is False
    assert "frozen_issue_identities_mismatch" in payload["blocking_reason_codes"] or (
        "frozen_identities_cannot_attach_all_issues_to_one_case" in payload["blocking_reason_codes"]
        or "frozen_case_identities_mismatch" in payload["blocking_reason_codes"]
    )


def test_overlay_rejects_duplicate_issue_identity() -> None:
    bundle = _bundle()
    issues = _complete_issues(bundle)
    issues[-1] = dict(issues[0])
    payload = overlay_complete_v2(selected_issues=issues, bundle=bundle)
    assert payload["review_overlay_complete"] is False
    assert "duplicate_row_ids" in payload["blocking_reason_codes"]


def test_knowledge_gap_with_positive_span_is_rejected() -> None:
    issue = {
        "row_id": "live30-q02:issue-01",
        "case_id": "live30-q02",
        "issue_id": "issue-01",
        "disposition": "knowledge_gap",
        "status": "knowledge_gap",
        "final_verification_status": "VERIFIED",
        "gap_reason": "no_safe_span",
        "gap_verification": _gap("issue-01"),
        "exact_gold_spans": [
            {
                "chunk_id": "chunk-1",
                "content_sha256": "a" * 64,
                "legal_locator": "s 1",
            }
        ],
    }
    payload = overlay_complete_v2(selected_issues=[issue], enforce_frozen_identities=False)
    assert payload["review_overlay_complete"] is False
    classified = payload["unreviewed_issue_count"]
    assert classified == 1


def test_knowledge_gap_without_attestation_is_hold() -> None:
    migrated = migrate_selected_issue(
        row={
            "row_id": "live30-q02:issue-99",
            "case_id": "live30-q02",
            "issue_id": "issue-99",
            "status": "knowledge_gap",
            "reason_code": "no_safe_span",
            "exact_gold_spans": [],
        },
        bind={"bind_status": "keep_gap", "reason": "no_safe_span"},
    )
    assert migrated["final_verification_status"] == "HOLD"
    assert migrated["v2_classification"] == "gap_attestation_required"


def test_v1_exact_span_requires_semantic_reverification() -> None:
    migrated = migrate_selected_issue(
        row={
            "row_id": "live30-q02:issue-01",
            "case_id": "live30-q02",
            "issue_id": "issue-01",
            "status": "qualified",
            "exact_gold_spans": [
                {
                    "chunk_id": "chunk-1",
                    "content_sha256": "a" * 64,
                    "legal_locator": "s 1",
                }
            ],
        },
        bind=None,
    )
    assert migrated["migration_action"] == "mechanical_exact_reused"
    assert migrated["v2_classification"] == "semantic_reverify_required"
    assert migrated["final_verification_status"] == "HOLD"


def test_migration_without_reviewed_input_is_unreviewed() -> None:
    payload = build_v1_to_v2_migration(project_root=PROJECT_ROOT, reviewed_rows=None)
    assert payload["final_verification_status"] == "UNREVIEWED"
    assert payload["review_overlay_complete"] is False
    assert "reviewed_input_missing" in payload["blocking_reason_codes"]
    assert payload["issues"] == []


def test_stage_a_caller_metrics_cannot_pass() -> None:
    scored = score_stage_a_v2(
        issues=[{"status": "qualified"}, {"status": "limited"}],
        unreviewed_issue_count=0,
        recall_at_5=1.0,
        recall_at_10=1.0,
        mrr=1.0,
        filter_violation_count=0,
        candidate_build_id="candidate-eval-04",
    )
    assert scored["stage_a_passed"] is False
    assert scored["authorization_eligible"] is False
    assert scored["metrics_source"] == "caller_injected"


def test_stage_a_metrics_from_rankings() -> None:
    scored = score_stage_a_v2(
        issues=[{"status": "qualified", "disposition": "qualified"}],
        unreviewed_issue_count=0,
        candidate_build_id="candidate-eval-04",
        rankings=[
            {
                "issue_id": "issue-01",
                "gold_span_ids": ["chunk-1"],
                "ranked_chunk_ids": ["chunk-1", "chunk-2"],
                "filter_violation_count": 0,
            }
        ],
    )
    assert scored["metrics_source"] == "derived_rankings"
    assert scored["recall_at_5"] == 1.0
    assert scored["stage_a_passed"] is True


def test_authorization_rejects_placeholder_hashes(database: Any) -> None:
    bundle = _bundle()
    with pytest.raises(ValueError, match="placeholder"):
        seal_evaluation_authorization_v2(
            evaluation_run_id="eval-fake-hashes",
            bundle=bundle,
            candidate_build_id="candidate-eval-05",
            overlay_seal_sha256="c" * 64,
            stage_a_result_sha256="d" * 64,
            as_of_date=AS_OF,
            authorized_case_ids=selected_generation_case_ids(bundle),
            issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        )


def test_authorization_rejects_stage_a_for_another_build(tmp_path: Path, database: Any) -> None:
    bundle = _bundle()
    candidate = "candidate-eval-real"
    other = "candidate-other"
    _insert_candidate(database, candidate)
    issues = _complete_issues(bundle)
    overlay = overlay_complete_v2(selected_issues=issues, bundle=bundle)
    overlay_path = _write_json(tmp_path / "overlay.json", overlay)
    stage_a = _passing_stage_a(other, issues)
    stage_path = _write_json(tmp_path / "stage-a.json", stage_a)
    with pytest.raises(ValueError, match="different candidate"):
        issue_evaluation_authorization_v2(
            evaluation_run_id="eval-wrong-stage-a",
            bundle=bundle,
            candidate_build_id=candidate,
            overlay_path=overlay_path,
            stage_a_path=stage_path,
            database=database,
            as_of_date=AS_OF,
            issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        )


def test_planner_does_not_pass_hard_gates() -> None:
    bundle = _bundle()
    overlay = overlay_complete_v2(selected_issues=_complete_issues(bundle), bundle=bundle)
    auth = seal_evaluation_authorization_v2(
        evaluation_run_id="eval-plan-gates",
        bundle=bundle,
        candidate_build_id="candidate-plan",
        overlay_seal_sha256=overlay["seal_sha256"],
        stage_a_result_sha256="1" * 64,
        as_of_date=AS_OF,
        authorized_case_ids=selected_generation_case_ids(bundle),
        issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    planned = plan_evaluation_only_run(
        authorization=auth,
        candidate_build_id="candidate-plan",
        selected_cases=[
            {"case_id": case_id, "execution_status": "generate"}
            for case_id in selected_generation_case_ids(bundle)
        ],
        overlay_complete=True,
        unreviewed_issue_count=0,
    )
    assert planned["planned"] is True
    assert planned["started"] is False
    for outcome in planned["outcomes"]:
        for gate in (
            "evidence_gate",
            "currentness_gate",
            "jurisdiction_gate",
            "citation_gate",
            "privacy_gate",
            "oscola_gate",
            "rights_gate",
        ):
            assert outcome[gate] is not True


def test_current_state_follows_pointer_not_python_constants(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    live60 = settings.project_root / "data/evaluations/live60"
    live60.mkdir(parents=True, exist_ok=True)
    artifact = {
        "schema": "legalbot.live60-issue-state.v1",
        "reviewed_rows_sha256": "a" * 64,
        "counts": {
            "qualified": 10,
            "limited": 5,
            "knowledge_gap": 570,
            "knowledge_gap_total": 570,
            "spans_bound": 12,
            "selected_qualified": 10,
            "selected_limited": 5,
            "selected_unreviewed": 0,
        },
    }
    artifact_path = live60 / "issue-state.json"
    raw = (json.dumps(artifact, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    artifact_path.write_bytes(raw)
    pointer = {
        "schema": "legalbot.live60-current-pointer.v1",
        "run_id": "pointer-test",
        "review_import_path": "fixture.json",
        "review_import_sha256": "a" * 64,
        "issue_state_path": "data/evaluations/live60/issue-state.json",
        "issue_state_sha256": hashlib.sha256(raw).hexdigest(),
        "migration_or_overlay_path": "data/evaluations/live60/issue-state.json",
        "migration_or_overlay_sha256": hashlib.sha256(raw).hexdigest(),
        "candidate_build_id": None,
        "updated_at": "2026-08-17T00:00:00Z",
    }
    (live60 / "CURRENT.json").write_text(
        json.dumps(pointer, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    state = CurrentLiveStateResolver(project_root=settings.project_root).authoritative_issue_state()
    assert state["selected_qualified"] == 10
    assert state["selected_limited"] == 5
    assert state["selected_knowledge_gap"] == 290


def test_live60_production_promotion_requires_attestation(tmp_path: Path, database: Any) -> None:
    settings = Settings(
        project_root=tmp_path,
        live_profile=FIRST_LIVE_LOCAL_ONLY_PROFILE,
        online_default="local_only",
        official_research_enabled=False,
        test_mode=True,
    )
    _insert_candidate(database, "candidate-promote", status="candidate")
    with pytest.raises(ValueError, match="production-promotion"):
        promote_candidate_index(settings, database, "candidate-promote")


def test_evaluation_does_not_write_active(tmp_path: Path, database: Any) -> None:
    _insert_candidate(database, "candidate-eval", status="candidate")
    _insert_candidate(database, "active-prod", status="active")
    assert database.active_index_id() == "active-prod"
    bundle = _bundle()
    issues = _complete_issues(bundle)
    overlay = overlay_complete_v2(selected_issues=issues, bundle=bundle)
    planned = plan_evaluation_only_run(
        authorization=seal_evaluation_authorization_v2(
            evaluation_run_id="eval-no-active-write",
            bundle=bundle,
            candidate_build_id="candidate-eval",
            overlay_seal_sha256=overlay["seal_sha256"],
            stage_a_result_sha256="2" * 64,
            as_of_date=AS_OF,
            authorized_case_ids=selected_generation_case_ids(bundle),
            issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        ),
        candidate_build_id="candidate-eval",
        selected_cases=[{"case_id": "live30-q02", "execution_status": "generate"}],
        overlay_complete=True,
        unreviewed_issue_count=0,
        active_build_id="active-prod",
    )
    assert planned["writes_active"] is False
    assert database.active_index_id() == "active-prod"


def test_pinned_factory_isolates_builds(tmp_path: Path, database: Any) -> None:
    settings = _settings(tmp_path)
    _insert_candidate(database, "active-a", status="active")
    _insert_candidate(database, "candidate-b", status="candidate")
    factory = PinnedRetrieverFactory(settings, database)
    left = factory.for_build("active-a")
    right = factory.for_build("candidate-b")
    assert left is not right
    assert left._pinned_build_id == "active-a"
    assert right._pinned_build_id == "candidate-b"


def test_missing_candidate_fails_closed(tmp_path: Path, database: Any) -> None:
    settings = _settings(tmp_path)
    service = HybridRetrievalService(
        settings=settings, database=database, pinned_build_id="missing-candidate"
    )
    with pytest.raises(RuntimeError, match="pinned evaluation build"):
        service.active_build_id()


def test_caller_boolean_cannot_create_verified_gold() -> None:
    proposer = ActorProvenanceV2.model_validate(
        {
            "actor_type": "ai",
            "actor_ref": "actor-opaque-001",
            "role": "evidence_reviewer",
            "verification_method": "ai_evidence_verification",
            "model_id": "qwen-local",
            "model_version": "qwen3.5-9b-4bit",
            "policy_sha256": "a" * 64,
            "prompt_template_sha256": PROPOSER_TEMPLATE_SHA256,
            "toolchain_sha256": "b" * 64,
            "source_set_id": "ew-primary-official-2026-08-17",
            "invocation_id": "invoke-proposer-bool",
        }
    )
    verifier = proposer.model_copy(
        update={
            "role": "semantic_verifier",
            "invocation_id": "invoke-verifier-bool",
            "prompt_template_sha256": SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            "actor_ref": "actor-opaque-002",
        }
    )
    result = run_evidence_pipeline(
        disposition="qualified",
        proposer=proposer,
        verifier=verifier,
        spans=[
            {
                "chunk_id": "chunk-1",
                "content_sha256": "a" * 64,
                "legal_locator": "s 1",
            }
        ],
        semantic_claims_supported=True,
    )
    assert result["final_verification_status"] == "HOLD"


@pytest.mark.asyncio
async def test_proposer_and_verifier_are_separate_invocations() -> None:
    class _FakeModel:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def invoke_json(self, *, system_prompt: str, user_payload: dict, mode: str):
            invocation = f"invoke-{mode}-{len(self.calls)}"
            self.calls.append(invocation)
            return invocation, {
                "schema": "legalbot.semantic-verification-result.v2",
                "issue_id": "issue-01",
                "proposition_hash": "a" * 64,
                "claims_supported": True,
                "unsupported_claim_count": 0,
                "contradiction_count": 0,
                "result": "supported",
            }

    model = _FakeModel()
    first = await invoke_semantic_verifier(
        model=model,
        issue_id="issue-01",
        proposition_hash="a" * 64,
        proposition_text="A frozen proposition.",
        evidence=[{"id": "chunk-1", "content_sha256": "b" * 64, "text": "exact words"}],
        legal_locator="s 1",
        source_identity="ukpga:2015:15",
        citation_metadata={"source_type": "legislation"},
        currentness_status="current",
        policy_sha256="a" * 64,
        toolchain_sha256="b" * 64,
        model_id="qwen-local",
        model_version="qwen3.5-9b-4bit",
    )
    second = await invoke_semantic_verifier(
        model=model,
        issue_id="issue-01",
        proposition_hash="a" * 64,
        proposition_text="A frozen proposition.",
        evidence=[{"id": "chunk-1", "content_sha256": "b" * 64, "text": "exact words"}],
        legal_locator="s 1",
        source_identity="ukpga:2015:15",
        citation_metadata={"source_type": "legislation"},
        currentness_status="current",
        policy_sha256="a" * 64,
        toolchain_sha256="b" * 64,
        model_id="qwen-local",
        model_version="qwen3.5-9b-4bit",
    )
    assert first.verifier_invocation_id != second.verifier_invocation_id
    assert first.verifier_prompt_sha256 == SEMANTIC_VERIFIER_TEMPLATE_SHA256
    assert first.verifier_prompt_sha256 != PROPOSER_TEMPLATE_SHA256
    assert len(model.calls) == 2


@pytest.mark.asyncio
async def test_v2_release_api_admission_is_superseded_before_job_creation(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    settings = _settings(tmp_path)
    bundle = load_live_evaluation_bundle(
        settings.project_root / "benchmarks/evaluation/live-evaluation-60-v1"
    )
    candidate = "candidate-eval-admit"
    _insert_candidate(database, candidate)
    issues = _complete_issues(bundle)
    overlay = overlay_complete_v2(selected_issues=issues, bundle=bundle)
    overlay_path = _write_json(tmp_path / "overlay.json", overlay)
    stage_path = _write_json(tmp_path / "stage-a.json", _passing_stage_a(candidate, issues))
    run_id = "eval-admit-v2"
    store = LiveSuiteRunStore(settings.project_root, cipher)
    store.create_run(
        run_id=run_id,
        bundle=bundle,
        provenance=RunProvenance(
            git_sha="0" * 40,
            git_dirty=False,
            model_version="test-model",
            index_build_id=candidate,
            prompt_version=PROMPT_VERSION,
            router_version=ROUTER_VERSION,
            classifier_version=CLASSIFIER_VERSION,
            policy_sha256=POLICY_SHA256,
            assessment_rules_sha256=POLICY_SHA256,
        ),
    )
    auth = issue_evaluation_authorization_v2(
        evaluation_run_id=run_id,
        bundle=bundle,
        candidate_build_id=candidate,
        overlay_path=overlay_path,
        stage_a_path=stage_path,
        database=database,
        as_of_date=store.load_run_manifest(run_id).as_of_date,
        issued_at=datetime.now(UTC),
    )
    auth_path = store.runs_root / run_id / "execution-authorization.json"
    auth_path.write_text(
        json.dumps(auth.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    case = bundle.registry.case(selected_generation_case_ids(bundle)[0])
    as_of = date.fromisoformat(store.load_run_manifest(run_id).as_of_date)
    payload = QuestionRequest(
        question=case.question,
        task_type=case.task_type,
        jurisdiction=case.jurisdiction,
        as_of_date=as_of,
        word_target=case.word_target,
        online_mode="local_only",
        upload_ids=[],
    )
    binding = validate_live60_api_admission(
        settings=settings,
        cipher=cipher,
        run_id=run_id,
        case_id=case.case_id,
        payload=payload,
        database=database,
    )
    assert isinstance(binding, Live60EvaluationAdmissionBinding)
    assert binding.candidate_build_id == candidate
    assert "cannot use the production" not in binding.request_sha256

    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
        runner=SimpleNamespace(ids=[]),
        observability=SimpleNamespace(
            validate_live30_binding=lambda *_args, **_kwargs: None,
            record_intake=lambda *_args, **_kwargs: None,
        ),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            accepted = await client.post(
                "/api/v1/questions",
                headers={
                    "X-Evaluation-Run-ID": run_id,
                    "X-Evaluation-Case-ID": case.case_id,
                    "X-Idempotency-Key": "live60-eval-admit-key-01",
                },
                json={
                    "question": case.question,
                    "task_type": case.task_type,
                    "jurisdiction": case.jurisdiction,
                    "as_of_date": as_of.isoformat(),
                    "word_target": case.word_target,
                    "online_mode": "local_only",
                    "upload_ids": [],
                },
            )
        assert accepted.status_code == 503, accepted.text
        assert accepted.json()["detail"] == (
            "TECHNICAL_IMPLEMENTATION_REQUIRED:"
            "superseded_evaluation_release_content_certification_missing"
        )
        row = database.fetchone("SELECT COUNT(*) AS count FROM jobs")
        assert row["count"] == 0
        assert database.active_index_id() is None
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_ordinary_question_still_requires_active(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    settings = _settings(tmp_path)
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
        runner=SimpleNamespace(ids=[]),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            rejected = await client.post(
                "/api/v1/questions",
                json={
                    "question": "Was a contract formed?",
                    "task_type": "problem",
                    "jurisdiction": "England and Wales",
                    "word_target": 500,
                    "online_mode": "local_only",
                    "upload_ids": [],
                },
            )
        assert rejected.status_code == 503
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


@pytest.mark.asyncio
async def test_diagnostic_canary_pins_built_unscored_slice_without_active(
    tmp_path: Path, database: Any, cipher: Any
) -> None:
    from app.retrieval.diagnostic_slice import DIAGNOSTIC_SLICE_BUILD_ID

    settings = _settings(tmp_path)
    _insert_candidate(database, DIAGNOSTIC_SLICE_BUILD_ID, status="built_unscored")
    previous = getattr(app.state, "services", None)
    app.state.services = SimpleNamespace(
        settings=settings,
        database=database,
        cipher=cipher,
        runner=SimpleNamespace(ids=[]),
        observability=SimpleNamespace(record_intake=lambda *_args, **_kwargs: None),
    )
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 4321))
    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://127.0.0.1:8777"
        ) as client:
            forbidden = await client.post(
                "/api/v1/questions",
                headers={"X-LegalBot-Canary-Build-Id": "current-law-ew-full-fp16-v111-20260818-x"},
                json={
                    "question": "Was a contract formed?",
                    "task_type": "problem",
                    "jurisdiction": "England and Wales",
                    "word_target": 500,
                    "online_mode": "local_only",
                    "upload_ids": [],
                },
            )
            accepted = await client.post(
                "/api/v1/questions",
                headers={
                    "X-LegalBot-Canary-Build-Id": DIAGNOSTIC_SLICE_BUILD_ID,
                    "X-Idempotency-Key": "live60-diag-canary-key-01",
                },
                json={
                    "question": "Was a contract formed?",
                    "task_type": "problem",
                    "jurisdiction": "England and Wales",
                    "word_target": 500,
                    "online_mode": "local_only",
                    "upload_ids": [],
                },
            )
        assert forbidden.status_code == 409, forbidden.text
        assert accepted.status_code == 202, accepted.text
        row = database.fetchone("SELECT pinned_index_build_id FROM jobs LIMIT 1")
        assert row["pinned_index_build_id"] == DIAGNOSTIC_SLICE_BUILD_ID
        assert database.active_index_id() is None
    finally:
        if previous is None:
            del app.state.services
        else:
            app.state.services = previous


def test_ai_verifier_broken_hash_is_hold() -> None:
    result = run_evidence_pipeline(
        disposition="qualified",
        proposer=ActorProvenanceV2.model_validate(
            {
                "actor_type": "ai",
                "actor_ref": "actor-opaque-001",
                "role": "evidence_reviewer",
                "verification_method": "ai_evidence_verification",
                "model_id": "qwen-local",
                "model_version": "qwen3.5-9b-4bit",
                "policy_sha256": "a" * 64,
                "prompt_template_sha256": PROPOSER_TEMPLATE_SHA256,
                "toolchain_sha256": "b" * 64,
                "source_set_id": "ew-primary-official-2026-08-17",
                "invocation_id": "invoke-proposer-broken",
            }
        ),
        verifier=ActorProvenanceV2.model_validate(
            {
                "actor_type": "ai",
                "actor_ref": "actor-opaque-002",
                "role": "semantic_verifier",
                "verification_method": "ai_evidence_verification",
                "model_id": "qwen-local",
                "model_version": "qwen3.5-9b-4bit",
                "policy_sha256": "a" * 64,
                "prompt_template_sha256": SEMANTIC_VERIFIER_TEMPLATE_SHA256,
                "toolchain_sha256": "b" * 64,
                "source_set_id": "ew-primary-official-2026-08-17",
                "invocation_id": "invoke-verifier-broken",
            }
        ),
        spans=[
            {
                "chunk_id": "chunk-1",
                "content_sha256": "a" * 64,
                "legal_locator": "s 1",
            }
        ],
        exact_mechanical_passed=False,
    )
    assert result["final_verification_status"] == "HOLD"


def _held_outcome(*, case_id: str, citation_passed: bool = False) -> Live60ExecutionOutcome:
    return Live60ExecutionOutcome(
        outcome_id=f"outcome-{case_id}-held",
        run_id="eval-citation-gate",
        case_id=case_id,
        pass_number=1,
        run_plan_disposition="generate_once",
        requested_word_target=1_000,
        expected_research_route="sectioned",
        terminal_state="held",
        released=False,
        job_id=f"job-{case_id}",
        privacy_passed=True,
        evidence_passed=True,
        currentness_passed=True,
        jurisdiction_passed=True,
        citation_passed=citation_passed,
        injection_passed=True,
        oscola_passed=True,
        completed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )


def _released_outcome(*, case_id: str) -> Live60ExecutionOutcome:
    return Live60ExecutionOutcome(
        outcome_id=f"outcome-{case_id}-released",
        run_id="eval-citation-gate",
        case_id=case_id,
        pass_number=1,
        run_plan_disposition="generate_once",
        requested_word_target=1_000,
        expected_research_route="sectioned",
        terminal_state="released",
        released=True,
        job_id=f"job-{case_id}",
        answer_artifact_id=f"answer-{case_id}",
        answer_sha256="a" * 64,
        word_count=1_000,
        privacy_passed=True,
        evidence_passed=True,
        currentness_passed=True,
        jurisdiction_passed=True,
        citation_passed=True,
        injection_passed=True,
        oscola_passed=True,
        release_gate_report_sha256="b" * 64,
        completed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )


def test_citation_gate_failure_is_not_released() -> None:
    payload = outcome_gate_payload(_held_outcome(case_id="live30-q02"))
    assert payload["released"] is False
    assert payload["terminal_state"] == "held"
    assert payload["citation_gate"] is False
    assert payload["job_id"] == "job-live30-q02"


@pytest.mark.asyncio
async def test_held_case_does_not_block_other_executor_outcomes() -> None:
    bundle = _bundle()
    selected = selected_generation_case_ids(bundle)
    overlay = overlay_complete_v2(selected_issues=_complete_issues(bundle), bundle=bundle)
    auth = seal_evaluation_authorization_v2(
        evaluation_run_id="eval-mixed-exec",
        bundle=bundle,
        candidate_build_id="candidate-eval-mixed",
        overlay_seal_sha256=overlay["seal_sha256"],
        stage_a_result_sha256="1" * 64,
        as_of_date=AS_OF,
        authorized_case_ids=selected,
        issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )

    class _Executor:
        async def execute(self) -> tuple[Live60ExecutionOutcome, ...]:
            return (
                _held_outcome(case_id=selected[0]),
                _released_outcome(case_id=selected[1]),
            )

    payload = await execute_evaluation_only_run(
        authorization=auth,
        candidate_build_id="candidate-eval-mixed",
        executor=_Executor(),
    )
    assert payload["started"] is True
    assert payload["writes_active"] is False
    assert payload["held_case_count"] == 1
    assert payload["generate_case_count"] == 1
    assert payload["one_held_case_blocks_others"] is False
    assert payload["outcomes"][0]["terminal_state"] == "held"
    assert payload["outcomes"][1]["terminal_state"] == "released"
    assert payload["outcomes"][1]["citation_gate"] is True


@pytest.mark.asyncio
async def test_stage_a_metrics_from_retriever_rankings() -> None:
    class _Retriever:
        async def retrieve(self, **_kwargs: Any) -> list[SimpleNamespace]:
            return [SimpleNamespace(chunk_id="chunk-gold"), SimpleNamespace(chunk_id="other")]

    scored = await evaluate_stage_a_from_retrieval(
        retriever=_Retriever(),
        issues=[
            {
                "issue_id": "issue-01",
                "disposition": "qualified",
                "status": "qualified",
                "topic": "formation",
                "exact_gold_spans": [{"chunk_id": "chunk-gold"}],
            },
            {
                "issue_id": "issue-02",
                "disposition": "knowledge_gap",
                "status": "knowledge_gap",
            },
        ],
        candidate_build_id="candidate-stage-a-retrieve",
        unreviewed_issue_count=0,
        as_of_date=date.fromisoformat(AS_OF),
    )
    assert scored["metrics_source"] == "derived_rankings"
    assert scored["recall_at_5"] == 1.0
    assert scored["stage_a_passed"] is True
    assert scored["selected_knowledge_gap_count"] == 1
