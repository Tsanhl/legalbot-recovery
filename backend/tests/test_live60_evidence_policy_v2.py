from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.evaluation.live_runtime_separation import (
    derive_evaluation_candidate_state,
    derive_production_promotion_state,
)
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.live_suite_current_state import (
    CurrentLiveStateResolver,
    ticks_are_known_stale,
)
from app.evaluation.live_suite_evaluation_auth import (
    EVALUATION_AUTHORIZATION_V2_SCHEMA,
    seal_evaluation_authorization_v2,
    verify_evaluation_runtime_bindings,
)
from app.evaluation.live_suite_evaluation_run import plan_evaluation_only_run
from app.evaluation.live_suite_evidence_policy import (
    ActorProvenanceV2,
    ContraryAuthorityReviewV2,
    ReviewAttestationV2,
    hold_confidence_only_claim,
    run_evidence_pipeline,
    run_semantic_verifier,
)
from app.evaluation.live_suite_gap_verification import seal_gap_verification
from app.evaluation.live_suite_http_execute import refuse_silent_active_fallback
from app.evaluation.live_suite_official_materialise import (
    classify_unmatched_official_candidate,
)
from app.evaluation.live_suite_overlay_complete import (
    derive_case_execution_status,
    overlay_complete_v2,
)
from app.evaluation.live_suite_path_b import selected_generation_case_ids
from app.evaluation.live_suite_semantic_result import _test_only_semantic_result
from app.evaluation.live_suite_span_accuracy import verify_user_span_exact_match
from app.evaluation.live_suite_stage_a_v2 import score_stage_a_v2
from app.evaluation.live_suite_v1_to_v2_migration import migrate_selected_issue
from app.evaluation.prompt_templates import (
    PROPOSER_TEMPLATE_SHA256,
    SEMANTIC_VERIFIER_TEMPLATE_SHA256,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
AS_OF = "2026-08-16"


def _actor(
    *,
    actor_type: str,
    role: str,
    method: str,
    invocation: str,
    template: str,
    ref: str = "actor-opaque-001",
) -> ActorProvenanceV2:
    kwargs: dict[str, object] = {
        "actor_type": actor_type,
        "actor_ref": ref,
        "role": role,
        "verification_method": method,
        "invocation_id": invocation,
        "prompt_template_sha256": template,
    }
    if actor_type == "ai":
        kwargs.update(
            {
                "model_id": "qwen-local",
                "model_version": "qwen3.5-9b-4bit",
                "policy_sha256": "a" * 64,
                "toolchain_sha256": "b" * 64,
                "source_set_id": "ew-primary-official-2026-08-17",
            }
        )
    return ActorProvenanceV2.model_validate(kwargs)


def _span(index: int = 1) -> dict[str, str]:
    return {
        "chunk_id": f"chunk-safe-{index:03d}",
        "content_sha256": f"{index:064x}"[-64:],
        "legal_locator": f"section {index}",
        "source_version_id": f"source-version-safe-{index:03d}",
        "legal_authority_id": "ukpga:2015:15",
        "legal_role": "statutory_text",
    }


def _semantic(*, issue_id: str = "issue-01", supported: bool = True):
    span = _span()
    return _test_only_semantic_result(
        issue_id=issue_id,
        proposition_hash="1" * 64,
        evidence_span_ids=[span["chunk_id"]],
        evidence_span_hashes=[span["content_sha256"]],
        claims_supported=supported,
        verifier_invocation_id="invoke-verifier-test",
    )


def _gap_attestation(issue_id: str, reason: str = "no_safe_span") -> dict[str, object]:
    return seal_gap_verification(
        {
            "issue_id": issue_id,
            "defined_source_set_id": "ew-primary-official-2026-08-17",
            "source_set_manifest_sha256": "1" * 64,
            "search_review_method": "defined_source_set_review",
            "coverage_result": "reviewed_none_in_defined_source_set",
            "as_of_date": AS_OF,
            "reason_code": reason,
            "review_actor": "deterministic",
        }
    ).model_dump(mode="json", by_alias=True)


def _issue(
    *,
    case_id: str,
    number: int,
    disposition: str,
    spans: list[dict[str, str]] | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    issue_id = f"issue-{number:02d}"
    payload: dict[str, object] = {
        "row_id": f"{case_id}:{issue_id}",
        "case_id": case_id,
        "issue_id": issue_id,
        "disposition": disposition,
        "status": disposition,
        "final_verification_status": "VERIFIED",
        "exact_gold_spans": spans or [],
        "gap_reason": reason,
        "limitation_reason": reason if disposition == "limited" else None,
        "invented_span": False,
    }
    if disposition in {"qualified", "limited"}:
        payload["semantic_result_seal_sha256"] = "e" * 64
        payload["proof_seal_sha256"] = "f" * 64
    if disposition == "knowledge_gap":
        payload["gap_verification"] = _gap_attestation(issue_id, reason or "no_safe_span")
    return payload


def test_a_proof_based_ai_gold_is_verified(tmp_path: Path) -> None:
    import hashlib
    import sqlite3

    text = "The verified statutory proposition."
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    span = {**_span(), "content_sha256": digest, "legal_locator": "s 1"}
    catalog = tmp_path / "catalog.sqlite3"
    connection = sqlite3.connect(catalog)
    connection.execute(
        """
        CREATE TABLE chunks (
          id TEXT, source_version_id TEXT, locator TEXT,
          text_sha256 TEXT, markdown_text TEXT
        )
        """
    )
    connection.execute(
        "INSERT INTO chunks VALUES (?, ?, ?, ?, ?)",
        (span["chunk_id"], span["source_version_id"], "s 1", digest, text),
    )
    connection.commit()
    connection.close()
    semantic = _test_only_semantic_result(
        issue_id="issue-01",
        proposition_hash="1" * 64,
        evidence_span_ids=[span["chunk_id"]],
        evidence_span_hashes=[digest],
        claims_supported=True,
        verifier_invocation_id="invoke-verifier-01",
    )
    result = run_evidence_pipeline(
        disposition="qualified",
        proposer=_actor(
            actor_type="ai",
            role="evidence_reviewer",
            method="ai_evidence_verification",
            invocation="invoke-proposer-01",
            template=PROPOSER_TEMPLATE_SHA256,
        ),
        verifier=_actor(
            actor_type="ai",
            role="semantic_verifier",
            method="ai_evidence_verification",
            invocation="invoke-verifier-01",
            template=SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            ref="actor-opaque-002",
        ),
        spans=[span],
        catalog_path=catalog,
        semantic_result=semantic,
    )
    assert result["final_verification_status"] == "VERIFIED"
    assert result["ai_confidence_gold_field"] is False
    assert result["identity_is_not_truth"] is True


def test_b_confidence_only_claim_is_hold() -> None:
    result = hold_confidence_only_claim({"ai_confidence": 1.0, "status": "qualified"})
    assert result["final_verification_status"] == "HOLD"
    assert result["ai_confidence_gold_field"] is True
    pipeline = run_evidence_pipeline(
        disposition="qualified",
        proposer=_actor(
            actor_type="ai",
            role="evidence_reviewer",
            method="ai_evidence_verification",
            invocation="invoke-proposer-02",
            template=PROPOSER_TEMPLATE_SHA256,
        ),
        verifier=_actor(
            actor_type="ai",
            role="semantic_verifier",
            method="ai_evidence_verification",
            invocation="invoke-verifier-02",
            template=SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            ref="actor-opaque-002",
        ),
        incoming_payload={"ai_confidence": 1.0},
    )
    assert pipeline["final_verification_status"] == "HOLD"


def test_c_human_attestation_with_bad_hash_is_hold() -> None:
    result = run_evidence_pipeline(
        disposition="qualified",
        proposer=_actor(
            actor_type="human",
            role="legal_reviewer",
            method="human_attestation",
            invocation="invoke-human-01",
            template=PROPOSER_TEMPLATE_SHA256,
        ),
        verifier=_actor(
            actor_type="deterministic",
            role="semantic_verifier",
            method="exact_mechanical",
            invocation="invoke-verifier-03",
            template=SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            ref="actor-opaque-002",
        ),
        spans=[_span()],
        exact_mechanical_passed=False,
        human_attestation=True,
    )
    assert result["final_verification_status"] == "HOLD"
    assert "human_attestation_cannot_override_hash_failure" in result["blocking_reason_codes"]


def test_d_verified_knowledge_gap_has_reason_and_no_span() -> None:
    attestation = ReviewAttestationV2(
        actor=_actor(
            actor_type="deterministic",
            role="evidence_reviewer",
            method="exact_mechanical",
            invocation="invoke-gap-01",
            template=PROPOSER_TEMPLATE_SHA256,
        ),
        issue_id="issue-01",
        attestation="knowledge_gap",
        independent_of_proposer=True,
        notes_code="held_statute_keep_as_gap",
    )
    result = run_evidence_pipeline(
        disposition="knowledge_gap",
        proposer=attestation.actor,
        verifier=_actor(
            actor_type="deterministic",
            role="semantic_verifier",
            method="exact_mechanical",
            invocation="invoke-gap-02",
            template=SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            ref="actor-opaque-002",
        ),
        attestation=attestation,
    )
    assert result["final_verification_status"] == "VERIFIED"
    assert result["disposition"] == "knowledge_gap"
    issue = migrate_selected_issue(
        row={
            "row_id": "live30-q02:issue-99",
            "case_id": "live30-q02",
            "issue_id": "issue-99",
            "status": "knowledge_gap",
            "reason_code": "held_statute_held-provision-01",
            "exact_gold_spans": [],
        },
        bind={"bind_status": "keep_gap", "reason": "held_statute_held-provision-01"},
        gap_verification=_gap_attestation("issue-99", "held_statute_held-provision-01"),
    )
    assert issue["disposition"] == "knowledge_gap"
    assert issue["final_verification_status"] == "VERIFIED"
    assert issue["exact_gold_spans"] == []
    assert issue["invented_span"] is False
    held = migrate_selected_issue(
        row={
            "row_id": "live30-q02:issue-98",
            "case_id": "live30-q02",
            "issue_id": "issue-98",
            "status": "knowledge_gap",
            "reason_code": "held_statute_held-provision-01",
            "exact_gold_spans": [],
        },
        bind={"bind_status": "keep_gap", "reason": "held_statute_held-provision-01"},
    )
    assert held["final_verification_status"] == "HOLD"


def test_e_305_issues_on_one_case_are_rejected() -> None:
    issues: list[dict[str, object]] = []
    case_id = "live30-q02"
    for number in range(1, 261):
        issues.append(
            _issue(
                case_id=case_id,
                number=number,
                disposition="qualified",
                spans=[_span(number)],
            )
        )
    for number in range(261, 281):
        issues.append(
            _issue(
                case_id=case_id,
                number=number,
                disposition="limited",
                spans=[_span(number)],
                reason="qualified_current_limitation",
            )
        )
    for number in range(281, 306):
        issues.append(
            _issue(
                case_id=case_id,
                number=number,
                disposition="knowledge_gap",
                reason="no_safe_span",
            )
        )
    payload = overlay_complete_v2(
        selected_issues=issues,
        bundle=load_live_evaluation_bundle(BUNDLE_ROOT),
    )
    assert payload["review_overlay_complete"] is False
    assert (
        "frozen_issue_identities_mismatch" in payload["blocking_reason_codes"]
        or "frozen_case_identities_mismatch" in payload["blocking_reason_codes"]
        or "frozen_identities_cannot_attach_all_issues_to_one_case"
        in payload["blocking_reason_codes"]
    )


def test_f_mixed_case_evaluation_plan_does_not_block_on_one_held() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    selected = list(selected_generation_case_ids(bundle))
    overlay = overlay_complete_v2(
        selected_issues=[
            _issue(
                case_id=selected[0],
                number=1,
                disposition="knowledge_gap",
                reason="no_safe_span",
            )
        ],
        enforce_frozen_identities=False,
    )
    auth = seal_evaluation_authorization_v2(
        evaluation_run_id="eval-mixed-01",
        bundle=bundle,
        candidate_build_id="candidate-eval-01",
        overlay_seal_sha256=overlay["seal_sha256"],
        stage_a_result_sha256="1" * 64,
        as_of_date=AS_OF,
        authorized_case_ids=selected,
        issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    cases = [
        {"case_id": selected[0], "execution_status": "generate", "issues": []},
        {"case_id": selected[1], "execution_status": "verified_limited", "issues": []},
        {"case_id": selected[2], "execution_status": "held", "issues": []},
    ]
    cases.extend(
        {"case_id": case_id, "execution_status": "generate", "issues": []}
        for case_id in selected[3:]
    )
    planned = plan_evaluation_only_run(
        authorization=auth,
        candidate_build_id="candidate-eval-01",
        selected_cases=cases,
        active_build_id=None,
        overlay_complete=True,
        unreviewed_issue_count=0,
    )
    assert planned["started"] is False
    assert planned["planned"] is True
    assert planned["writes_active"] is False
    assert planned["one_held_case_blocks_others"] is False
    assert planned["held_case_count"] == 1
    assert planned["limited_case_count"] == 1
    assert planned["generate_case_count"] == 28
    assert all(item["blocked_by_other_held_case"] is False for item in planned["outcomes"])
    assert all(item["evidence_gate"] is not True for item in planned["outcomes"])


def test_g_evaluation_plans_without_active() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    selected = list(selected_generation_case_ids(bundle))
    overlay = overlay_complete_v2(
        selected_issues=[
            _issue(
                case_id=selected[0],
                number=1,
                disposition="knowledge_gap",
                reason="no_safe_span",
            )
        ],
        enforce_frozen_identities=False,
    )
    auth = seal_evaluation_authorization_v2(
        evaluation_run_id="eval-no-active",
        bundle=bundle,
        candidate_build_id="candidate-eval-02",
        overlay_seal_sha256=overlay["seal_sha256"],
        stage_a_result_sha256="2" * 64,
        as_of_date=AS_OF,
        authorized_case_ids=selected,
        issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    assert auth.schema_name == EVALUATION_AUTHORIZATION_V2_SCHEMA
    assert auth.requires_active is False
    assert auth.requires_o04 is False
    binding = verify_evaluation_runtime_bindings(
        authorization=auth,
        candidate_build_id="candidate-eval-02",
        active_build_id=None,
        fallback_to_active=False,
    )
    assert binding["used_active_fallback"] is False
    planned = plan_evaluation_only_run(
        authorization=auth,
        candidate_build_id="candidate-eval-02",
        selected_cases=[
            {"case_id": case_id, "execution_status": "generate"} for case_id in selected
        ],
        active_build_id=None,
        overlay_complete=True,
        unreviewed_issue_count=0,
    )
    assert planned["active_build_id"] is None
    assert planned["production_promotion_state"] == "NOT_ELIGIBLE"
    assert planned["started"] is False


def test_h_evaluation_refuses_silent_active_fallback() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    selected = list(selected_generation_case_ids(bundle))
    overlay = overlay_complete_v2(
        selected_issues=[
            _issue(
                case_id=selected[0],
                number=1,
                disposition="knowledge_gap",
                reason="no_safe_span",
            )
        ],
        enforce_frozen_identities=False,
    )
    auth = seal_evaluation_authorization_v2(
        evaluation_run_id="eval-no-fallback",
        bundle=bundle,
        candidate_build_id="candidate-eval-03",
        overlay_seal_sha256=overlay["seal_sha256"],
        stage_a_result_sha256="3" * 64,
        as_of_date=AS_OF,
        authorized_case_ids=selected,
        issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="silently fall back"):
        verify_evaluation_runtime_bindings(
            authorization=auth,
            candidate_build_id="candidate-eval-03",
            active_build_id="active-production-01",
            fallback_to_active=True,
        )
    refuse_silent_active_fallback(
        evaluation_candidate_build_id="candidate-eval-03",
        active_build_id="active-production-01",
    )
    with pytest.raises(RuntimeError, match="silently fall back"):
        refuse_silent_active_fallback(
            evaluation_candidate_build_id="candidate-eval-03",
            active_build_id="active-production-01",
            retrieval_build_id="active-production-01",
        )


def test_i_production_still_needs_operator_promotion() -> None:
    assert (
        derive_production_promotion_state(
            operator_promoted=False,
            v1_overlay_may_replace_production=False,
        )
        == "NOT_ELIGIBLE"
    )
    assert (
        derive_evaluation_candidate_state(
            candidate_build_present=True,
            review_complete=True,
            stage_a_ready=True,
            evaluation_authorized=True,
        )
        == "EVALUATION_READY"
    )
    assert (
        derive_production_promotion_state(
            operator_promoted=False,
            v1_overlay_may_replace_production=True,
        )
        == "AWAITING_OPERATOR"
    )


def test_j_no_self_approve() -> None:
    proposer = _actor(
        actor_type="ai",
        role="evidence_reviewer",
        method="ai_evidence_verification",
        invocation="invoke-same",
        template=PROPOSER_TEMPLATE_SHA256,
    )
    semantic = run_semantic_verifier(
        proposer=proposer,
        verifier=proposer.model_copy(update={"role": "semantic_verifier"}),
        claims_supported=True,
    )
    assert semantic["passed"] is False
    assert "self_approve_forbidden" in semantic["blocking_reason_codes"]


def test_k_stale_zero_of_585_cannot_override_canonical_import() -> None:
    stale = {"qualified": 0, "limited": 0, "gap": 585, "spans_bound": 0}
    assert ticks_are_known_stale(stale) is True
    resolver = CurrentLiveStateResolver(project_root=PROJECT_ROOT, ticks=stale)
    state = resolver.authoritative_issue_state()
    counts = json.loads(
        (PROJECT_ROOT / "data/evaluations/live60/issue-state.json").read_text(encoding="utf-8")
    )["counts"]
    assert state["qualified"] == counts["qualified"]
    assert state["knowledge_gap"] == counts["knowledge_gap"]
    assert state["selected_qualified"] == counts["selected_qualified"]
    assert state["selected_knowledge_gap"] == counts["selected_knowledge_gap"]
    assert state["reviewed_rows_sha256"] == (
        "e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d"
    )
    report = resolver.report()
    assert report["authoritative"] is True
    assert report["stale_tick_progress_ignored"] is True
    assert report["current_issue_state"]["qualified"] != 0


def test_l_multi_span_and_unresolved_contrary(tmp_path: Path) -> None:
    import hashlib
    import sqlite3

    texts = {
        1: "First verified statutory sentence.",
        2: "Second verified statutory sentence.",
    }
    spans = []
    catalog = tmp_path / "catalog.sqlite3"
    connection = sqlite3.connect(catalog)
    connection.execute(
        """
        CREATE TABLE chunks (
          id TEXT, source_version_id TEXT, locator TEXT,
          text_sha256 TEXT, markdown_text TEXT
        )
        """
    )
    for index, text in texts.items():
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        span = {**_span(index), "content_sha256": digest, "legal_locator": f"s {index}"}
        spans.append(span)
        connection.execute(
            "INSERT INTO chunks VALUES (?, ?, ?, ?, ?)",
            (span["chunk_id"], span["source_version_id"], f"s {index}", digest, text),
        )
    connection.commit()
    connection.close()
    issues = [
        _issue(
            case_id="live30-q02",
            number=1,
            disposition="qualified",
            spans=spans,
        )
    ]
    classified = overlay_complete_v2(selected_issues=issues, enforce_frozen_identities=False)
    assert classified["selected_positive_span_issue_count"] == 1
    assert len(issues[0]["exact_gold_spans"]) == 2
    contrary = ContraryAuthorityReviewV2(
        actor=_actor(
            actor_type="human",
            role="contrary_authority_reviewer",
            method="human_attestation",
            invocation="invoke-contrary-01",
            template=PROPOSER_TEMPLATE_SHA256,
        ),
        status="unresolved",
        defined_source_set_id="ew-primary-official-2026-08-17",
        bound_contrary_span_count=0,
    )
    semantic = _test_only_semantic_result(
        issue_id="issue-01",
        proposition_hash="1" * 64,
        evidence_span_ids=[span["chunk_id"] for span in spans],
        evidence_span_hashes=[span["content_sha256"] for span in spans],
        claims_supported=True,
        verifier_invocation_id="invoke-ver-c",
    )
    result = run_evidence_pipeline(
        disposition="qualified",
        proposer=_actor(
            actor_type="human",
            role="evidence_reviewer",
            method="human_attestation",
            invocation="invoke-prop-c",
            template=PROPOSER_TEMPLATE_SHA256,
        ),
        verifier=_actor(
            actor_type="deterministic",
            role="semantic_verifier",
            method="exact_mechanical",
            invocation="invoke-ver-c",
            template=SEMANTIC_VERIFIER_TEMPLATE_SHA256,
            ref="actor-opaque-002",
        ),
        spans=spans,
        catalog_path=catalog,
        semantic_result=semantic,
        contrary=contrary,
        contrary_required=True,
    )
    assert result["final_verification_status"] == "HOLD"
    assert result["disposition"] == "limited"
    assert "contrary_unresolved" in result["blocking_reason_codes"]


def test_stage_a_scores_positive_gold_only_and_does_not_fabricate_gap_recall() -> None:
    scored = score_stage_a_v2(
        issues=[{"status": "qualified"}, {"status": "limited"}, {"status": "knowledge_gap"}],
        unreviewed_issue_count=0,
        recall_at_5=1.0,
        recall_at_10=0.96,
        mrr=0.85,
        filter_violation_count=0,
        candidate_build_id="candidate-eval-04",
    )
    assert scored["scored_issue_count"] == 2
    assert scored["selected_knowledge_gap_count"] == 1
    assert scored["fabricated_gap_recall"] is False
    assert scored["stage_a_passed"] is False
    assert scored["metrics_source"] == "caller_injected"
    empty = score_stage_a_v2(
        issues=[{"status": "knowledge_gap"}],
        unreviewed_issue_count=0,
        recall_at_5=1.0,
        recall_at_10=1.0,
        mrr=1.0,
        filter_violation_count=0,
        candidate_build_id="candidate-eval-04",
    )
    assert empty["recall_at_5"] is None
    assert empty["stage_a_passed"] is False


def test_catalogue_miss_is_not_automatic_knowledge_gap() -> None:
    pending = classify_unmatched_official_candidate(
        row_id="live30-q02:issue-04",
        reason="official_exact_text_no_approved_catalogue_hash",
        ingested=True,
    )
    assert pending["automatic_knowledge_gap"] is False
    assert pending["disposition"] == "pending_official_materialisation"
    assert pending["verification_status"] == "HOLD"


def test_derived_case_status_mixes_generate_limited_and_held() -> None:
    generate = derive_case_execution_status(
        [_issue(case_id="live30-q02", number=1, disposition="qualified", spans=[_span()])]
    )
    limited = derive_case_execution_status(
        [
            _issue(case_id="live30-q03", number=1, disposition="qualified", spans=[_span()]),
            _issue(
                case_id="live30-q03",
                number=2,
                disposition="knowledge_gap",
                reason="no_safe_span",
            ),
        ]
    )
    held = derive_case_execution_status(
        [
            _issue(
                case_id="live30-q06",
                number=1,
                disposition="knowledge_gap",
                reason="held_statute_held-provision-01",
            )
        ]
    )
    assert generate == "generate"
    assert limited == "verified_limited"
    assert held == "held"


def test_v1_exact_match_verifier_still_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="exact-match"):
        verify_user_span_exact_match(
            chunk_id="chunk-missing",
            content_sha256="0" * 64,
            legal_locator="section 1",
            catalog_path=tmp_path / "missing-catalog.sqlite3",
        )


def test_v2_authorization_seal_and_forbidden_production_fields() -> None:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    selected = list(selected_generation_case_ids(bundle))
    overlay = overlay_complete_v2(
        selected_issues=[
            _issue(
                case_id=selected[0],
                number=1,
                disposition="knowledge_gap",
                reason="no_safe_span",
            )
        ],
        enforce_frozen_identities=False,
    )
    auth = seal_evaluation_authorization_v2(
        evaluation_run_id="eval-seal",
        bundle=bundle,
        candidate_build_id="candidate-eval-05",
        overlay_seal_sha256=overlay["seal_sha256"],
        stage_a_result_sha256="5" * 64,
        as_of_date=AS_OF,
        authorized_case_ids=selected,
        issued_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
    )
    dumped = auth.model_dump(mode="json", by_alias=True)
    assert dumped["seal_sha256"] == sealed_sha256(dumped)
    assert "active_build_id" not in dumped
    assert dumped["requires_o04"] is False


def test_committed_v1_to_v2_migration_preserves_mechanical_reuse_without_auto_verified() -> None:
    path = PROJECT_ROOT / "Live60-2026-08-16/artifacts/V1_TO_V2_MIGRATION.json"
    if not path.is_file():
        pytest.skip("local V1→V2 migration ledger is not present")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["selected_issue_count"] == 305
    assert data["counts"]["selected_qualified"] == 77
    assert data["re_research"] is False
    assert data["invented_span"] is False
    assert data["writes_active"] is False
