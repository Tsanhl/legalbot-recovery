from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from app.evaluation import all60_ai_review_batch as batch
from app.evaluation import all60_evidence_review
from app.evaluation.all60_ai_review_batch import (
    ALL60_ISSUE_COUNT,
    All60ReviewBatchStore,
    All60ReviewInvocationIntent,
    All60ReviewInvocationOutcome,
    VerifiedAll60AIReviewBatch,
    _issue_identity,
    _semantic_failure_fingerprint,
    _validate_replayed_attempt,
    build_synthetic_all60_review_receipt,
    load_verified_all60_ai_review_batch,
    require_verified_all60_ai_review_batch,
)
from app.evaluation.all60_evidence_review import build_all60_issue_review_input
from app.evaluation.candidate_completion_authority import (
    LAUNCHER_END_SCHEMA,
    LAUNCHER_START_SCHEMA,
    MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
    MEMORY_MEASUREMENT_METHOD,
    MEMORY_MEASUREMENT_SCHEMA,
    MEMORY_SAMPLE_INTERVAL_SECONDS,
    CompletionMemoryPolicy,
    LoadedCompletionMemoryPolicy,
)
from app.evaluation.live_suite import sealed_sha256
from app.evaluation.nonrelease_artifacts import sealed_safe_payload
from app.model_runtime.config import PINNED_RUNTIME_MODEL_VERSION, PINNED_RUNTIME_REPO
from app.orchestration.retry_policy import decide_retry
from app.quality.ai_evidence_reviewer import (
    AIReviewerClaimCheckpoint,
    ClaimEvidenceVerdict,
    FrozenClaimReviewInput,
    ai_evidence_reviewer_toolchain_sha256,
    frozen_claim_bundle_sha256,
    seal_ai_reviewer_claim_checkpoint,
    seal_ai_reviewer_invocation_trace,
)
from app.quality.draft_identity import source_draft_sha256
from app.quality.policy import POLICY_SHA256
from app.types import EvidenceSpan, MaterialLane, StructuredDraft

RUN_ID = "all60-review-test-run"
RUNTIME_SEAL = "d" * 64
GIB = 1024**3


@dataclass(frozen=True, slots=True)
class _TestReviewerInput:
    ordinal: int
    row_id: str
    case_id: str
    issue_id: str
    issue_identity_sha256: str
    deterministic_gate_sha256: str
    draft: StructuredDraft
    frozen_claim: FrozenClaimReviewInput
    evidence_by_id: dict[str, EvidenceSpan]


def _memory_policy() -> CompletionMemoryPolicy:
    material: dict[str, Any] = {
        "schema": "legalbot.completion-memory-policy.v2",
        "policy_id": "owner-memory-envelope-test",
        "candidate_build_id": "candidate-v111",
        "candidate_manifest_sha256": "a" * 64,
        "runtime_binding_sha256": RUNTIME_SEAL,
        "integration_sha": "b" * 40,
        "measurement_schema": MEMORY_MEASUREMENT_SCHEMA,
        "host_physical_memory_bytes": 16 * GIB,
        "max_peak_combined_working_set_bytes": 12 * GIB,
        "minimum_host_available_memory_bytes": 3 * GIB,
        "owner_decision_id": f"v111-completion-memory-{'1' * 20}",
        "owner_decision_request_seal_sha256": "c" * 64,
        "owner_decision_resolution_seal_sha256": "e" * 64,
        "owner_selected_option_id": "max-12884901888-min-3221225472",
        "created_at": "2026-08-20T08:00:00+00:00",
    }
    material["seal_sha256"] = sealed_sha256(material)
    return CompletionMemoryPolicy.model_validate(material)


def _loaded_memory_policy() -> LoadedCompletionMemoryPolicy:
    # The loader capability itself is exercised elsewhere; these unit tests
    # isolate exact retry/memory replay without minting owner authority.
    return cast(
        LoadedCompletionMemoryPolicy,
        SimpleNamespace(policy=_memory_policy(), source_file_sha256="f" * 64),
    )


def _review_fixture() -> tuple[
    _TestReviewerInput,
    batch.All60ReviewIssueIdentity,
    dict[str, Any],
    AIReviewerClaimCheckpoint,
]:
    text = "The statutory formation rule applies to an accepted offer."
    span = EvidenceSpan(
        id="gold-01-01",
        source_version_id="source-version-1",
        chunk_id="chunk-1",
        text=text,
        locator="section 1",
        lane=MaterialLane.PRIMARY_AUTHORITY,
        jurisdiction="England and Wales",
        subject="contract formation",
        citation_data={"source_type": "legislation"},
        canonical_citation="Example Act 2026, s 1",
        currentness_status="latest_available_revised_snapshot",
        content_sha256=hashlib.sha256(text.encode()).hexdigest(),
        index_build_id="candidate-v111",
        legal_role="statutory_text",
        unapplied_effect_count=0,
        provision_extent_status="england_and_wales_verified",
        identity_verified=True,
        currentness_verified=True,
    )
    draft, frozen = build_all60_issue_review_input(
        row_id="live30-q01:issue-01",
        topic="contract formation",
        task_type="problem",
        as_of_date=date(2026, 8, 20),
        evidence=(span,),
    )
    issue = _TestReviewerInput(
        ordinal=1,
        row_id="live30-q01:issue-01",
        case_id="live30-q01",
        issue_id="issue-01",
        issue_identity_sha256="1" * 64,
        deterministic_gate_sha256="2" * 64,
        draft=draft,
        frozen_claim=frozen,
        evidence_by_id={span.id: span},
    )
    identity = _issue_identity(issue)
    runtime_binding: dict[str, Any] = {
        "seal_sha256": RUNTIME_SEAL,
        "model_id": PINNED_RUNTIME_REPO,
        "model_version": PINNED_RUNTIME_MODEL_VERSION,
    }
    trace = seal_ai_reviewer_invocation_trace(
        claim_id=frozen.identity.claim_id,
        invocation_id="all60-ai-00000000000000000000000000000001",
        duration_ms=25,
        input_token_count=100,
        output_token_count=20,
        timing_source="transport",
    )
    decision = ClaimEvidenceVerdict(
        claim_id=frozen.identity.claim_id,
        claim_sha256=frozen.identity.claim_sha256,
        evidence_span_ids=frozen.identity.evidence_span_ids,
        evidence_bundle_sha256=frozen.identity.evidence_bundle_sha256,
        verdict="supported",
        reason_codes=(
            "issue_relevance_supported",
            "contrary_authority_checked",
            "currentness_inputs_checked",
        ),
        cited_evidence_ids=(span.id,),
    )
    checkpoint = seal_ai_reviewer_claim_checkpoint(
        source_draft_sha256=source_draft_sha256(draft),
        frozen_claim_bundle_sha256=frozen_claim_bundle_sha256((frozen,)),
        frozen_claim=frozen,
        decision=decision,
        invocation_trace=trace,
        model_id=PINNED_RUNTIME_REPO,
        model_version=PINNED_RUNTIME_MODEL_VERSION,
        policy_sha256=POLICY_SHA256,
        toolchain_sha256=ai_evidence_reviewer_toolchain_sha256(),
    )
    return issue, identity, runtime_binding, checkpoint


def _intent(
    *,
    identity: batch.All60ReviewIssueIdentity,
    attempt: int,
    prior: tuple[str, ...] = (),
) -> All60ReviewInvocationIntent:
    material: dict[str, Any] = {
        "schema": batch.ALL60_AI_REVIEW_INTENT_SCHEMA,
        "run_id": RUN_ID,
        "ordinal": identity.ordinal,
        "row_id": identity.row_id,
        "attempt_number": attempt,
        "request_id": f"all60-ai-{attempt:032x}",
        "invocation_nonce_sha256": f"{attempt + 2:x}" * 64,
        "issue_input_identity_sha256": identity.identity_sha256,
        "runtime_binding_sha256": RUNTIME_SEAL,
        "runtime_instance_sha256": f"{attempt + 3:x}" * 64,
        "owned_listener_proof_sha256": f"{attempt + 4:x}" * 64,
        "launch_nonce_sha256": f"{attempt + 5:x}" * 64,
        "prior_failure_fingerprints": list(prior),
        "condition_change": (
            "initial_owned_runtime"
            if attempt == 1
            else "fresh_owned_runtime_after_retryable_failure"
        ),
        "created_at": datetime(2026, 8, 20, 8, attempt, tzinfo=UTC)
        .isoformat()
        .replace("+00:00", "Z"),
        "prose_persisted": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return All60ReviewInvocationIntent.model_validate(material)


def _memory_fields(*, high: bool) -> dict[str, Any]:
    if high:
        controller, sidecar, combined, available = GIB, 12 * GIB, 13 * GIB, GIB
    else:
        controller, sidecar, combined, available = GIB, 2 * GIB, 3 * GIB, 4 * GIB
    return {
        "memory_policy_sha256": _memory_policy().seal_sha256,
        "memory_measurement_schema": MEMORY_MEASUREMENT_SCHEMA,
        "memory_measurement_method": MEMORY_MEASUREMENT_METHOD,
        "memory_sampling_interval_seconds": MEMORY_SAMPLE_INTERVAL_SECONDS,
        "memory_max_allowed_sample_interval_seconds": MEMORY_MAX_SAMPLE_INTERVAL_SECONDS,
        "memory_sample_count": 3,
        "memory_max_observed_sample_interval_seconds": 0.1,
        "memory_max_sampling_jitter_seconds": 0.01,
        "controller_peak_rss_bytes": controller,
        "sidecar_peak_rss_bytes": sidecar,
        "peak_combined_working_set_bytes": combined,
        "minimum_host_available_memory_bytes": available,
        "startup_memory_measurement_sha256": "9" * 64,
        "startup_memory_sample_count": 3,
        "startup_memory_max_observed_sample_interval_seconds": 0.1,
        "startup_controller_peak_rss_bytes": controller,
        "startup_sidecar_peak_rss_bytes": sidecar,
        "startup_peak_combined_working_set_bytes": combined,
        "startup_minimum_host_available_memory_bytes": available,
    }


def _failed_outcome(
    *,
    identity: batch.All60ReviewIssueIdentity,
    intent: All60ReviewInvocationIntent,
    reason: str,
    prior: tuple[str, ...],
    high_memory: bool,
) -> All60ReviewInvocationOutcome:
    fingerprint = _semantic_failure_fingerprint(
        reason_code=reason,
        identity=identity,
        runtime_binding_sha256=RUNTIME_SEAL,
    )
    deterministic = reason in batch._DETERMINISTIC_REVIEW_FAILURE_CODES
    decision = decide_retry(
        attempt_number=intent.attempt_number,
        failure_reason_code=reason,
        failure_fingerprint_sha256=fingerprint,
        prior_failure_fingerprints=prior,
        deterministic_safety=deterministic,
        retryable=not deterministic,
        input_or_condition_changed=True,
    )
    material: dict[str, Any] = {
        "schema": batch.ALL60_AI_REVIEW_OUTCOME_SCHEMA,
        "run_id": RUN_ID,
        "ordinal": identity.ordinal,
        "row_id": identity.row_id,
        "attempt_number": intent.attempt_number,
        "intent_seal_sha256": intent.seal_sha256,
        "request_id": intent.request_id,
        "invocation_nonce_sha256": intent.invocation_nonce_sha256,
        "issue_input_identity_sha256": identity.identity_sha256,
        "status": "invocation_failed",
        "invocation_id": intent.request_id,
        "duration_ms": 10,
        "input_token_count": None,
        "output_token_count": None,
        "usage_observed": False,
        **_memory_fields(high=high_memory),
        "checkpoint": None,
        "checkpoint_seal_sha256": None,
        "failure_reason_code": reason,
        "failure_fingerprint_sha256": fingerprint,
        "deterministic_safety_failure": deterministic,
        "retry_action": decision.action,
        "retry_reason": decision.reason,
        "completed_at": datetime(2026, 8, 20, 8, 10, tzinfo=UTC).isoformat().replace("+00:00", "Z"),
        "prose_persisted": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    return All60ReviewInvocationOutcome.model_validate(material)


def _reseal_outcome(
    outcome: All60ReviewInvocationOutcome, **changes: Any
) -> All60ReviewInvocationOutcome:
    material = outcome.model_dump(mode="json", by_alias=True)
    material.update(changes)
    material.pop("seal_sha256", None)
    material["seal_sha256"] = sealed_sha256(material)
    return All60ReviewInvocationOutcome.model_validate(material)


def _reseal_intent(
    intent: All60ReviewInvocationIntent, **changes: Any
) -> All60ReviewInvocationIntent:
    material = intent.model_dump(mode="json", by_alias=True)
    material.update(changes)
    material.pop("seal_sha256", None)
    material["seal_sha256"] = sealed_sha256(material)
    return All60ReviewInvocationIntent.model_validate(material)


def test_memory_breach_is_replayed_before_retry_classification() -> None:
    issue, identity, runtime_binding, _ = _review_fixture()
    intent = _intent(identity=identity, attempt=1)
    outcome = _failed_outcome(
        identity=identity,
        intent=intent,
        reason="memory_working_set_exceeds_owner_ceiling",
        prior=(),
        high_memory=True,
    )
    assert outcome.retry_action == "stop"
    assert outcome.retry_reason == "deterministic_safety_failure"
    assert (
        _validate_replayed_attempt(
            intent=intent,
            outcome=outcome,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(),
        )
        is None
    )

    relabelled = _failed_outcome(
        identity=identity,
        intent=intent,
        reason="transient_model_failure",
        prior=(),
        high_memory=True,
    )
    with pytest.raises(ValueError, match="memory failure"):
        _validate_replayed_attempt(
            intent=intent,
            outcome=relabelled,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(),
        )


def test_repeated_semantic_failure_stops_and_unique_fingerprint_mutation_rejects() -> None:
    issue, identity, runtime_binding, _ = _review_fixture()
    first_fingerprint = _semantic_failure_fingerprint(
        reason_code="transient_model_failure",
        identity=identity,
        runtime_binding_sha256=RUNTIME_SEAL,
    )
    intent = _intent(identity=identity, attempt=2, prior=(first_fingerprint,))
    outcome = _failed_outcome(
        identity=identity,
        intent=intent,
        reason="transient_model_failure",
        prior=(first_fingerprint,),
        high_memory=False,
    )
    assert outcome.failure_fingerprint_sha256 == first_fingerprint
    assert outcome.retry_action == "stop"
    assert outcome.retry_reason == "repeated_failure_fingerprint"
    assert (
        _validate_replayed_attempt(
            intent=intent,
            outcome=outcome,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(first_fingerprint,),
        )
        is None
    )

    mutated = _reseal_outcome(outcome, failure_fingerprint_sha256="0" * 64)
    with pytest.raises(ValueError, match="retry decision replay"):
        _validate_replayed_attempt(
            intent=intent,
            outcome=mutated,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(first_fingerprint,),
        )


def test_passed_checkpoint_must_match_exact_issue_intent_and_counters() -> None:
    issue, identity, runtime_binding, checkpoint = _review_fixture()
    intent = _intent(identity=identity, attempt=1)
    material: dict[str, Any] = {
        "schema": batch.ALL60_AI_REVIEW_OUTCOME_SCHEMA,
        "run_id": RUN_ID,
        "ordinal": identity.ordinal,
        "row_id": identity.row_id,
        "attempt_number": 1,
        "intent_seal_sha256": intent.seal_sha256,
        "request_id": intent.request_id,
        "invocation_nonce_sha256": intent.invocation_nonce_sha256,
        "issue_input_identity_sha256": identity.identity_sha256,
        "status": "passed",
        "invocation_id": intent.request_id,
        "duration_ms": 25,
        "input_token_count": 100,
        "output_token_count": 20,
        "usage_observed": True,
        **_memory_fields(high=False),
        "checkpoint": checkpoint.model_dump(mode="json", by_alias=True),
        "checkpoint_seal_sha256": checkpoint.seal_sha256,
        "failure_reason_code": None,
        "failure_fingerprint_sha256": None,
        "deterministic_safety_failure": False,
        "retry_action": "not_applicable",
        "retry_reason": "not_applicable",
        "completed_at": "2026-08-20T08:10:00Z",
        "prose_persisted": False,
    }
    material["seal_sha256"] = sealed_sha256(material)
    outcome = All60ReviewInvocationOutcome.model_validate(material)
    assert (
        _validate_replayed_attempt(
            intent=intent,
            outcome=outcome,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(),
        )
        == checkpoint
    )
    with pytest.raises(ValueError, match="completed outcome is inconsistent"):
        _reseal_outcome(outcome, deterministic_safety_failure=True)
    mismatched = _reseal_outcome(outcome, duration_ms=24)
    with pytest.raises(ValueError, match="independently bound"):
        _validate_replayed_attempt(
            intent=intent,
            outcome=mismatched,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(),
        )
    mismatched_intent = _reseal_intent(intent, issue_input_identity_sha256="0" * 64)
    with pytest.raises(ValueError, match="attempt binding"):
        _validate_replayed_attempt(
            intent=mismatched_intent,
            outcome=outcome,
            issue=issue,
            identity=identity,
            runtime_binding=runtime_binding,
            memory_policy=_loaded_memory_policy(),
            prior_fingerprints=(),
        )


def test_synthetic_or_caller_minted_value_cannot_create_verified_capability() -> None:
    receipt = build_synthetic_all60_review_receipt(
        run_id=RUN_ID,
        checkpoint_seal_sha256s=("a" * 64,),
    )
    with pytest.raises(RuntimeError, match="not_loader_verified"):
        require_verified_all60_ai_review_batch(receipt)
    minted = object.__new__(VerifiedAll60AIReviewBatch)
    with pytest.raises(RuntimeError, match="not_loader_verified"):
        require_verified_all60_ai_review_batch(minted)


def test_store_persists_full_launcher_attestations_create_only(tmp_path: Path) -> None:
    evaluation_root = tmp_path / "evaluations"
    evaluation_root.mkdir(mode=0o700)
    store = All60ReviewBatchStore(
        evaluation_root=evaluation_root,
        run_date=date(2026, 8, 20),
        run_id=RUN_ID,
        resume=False,
    )
    start = sealed_safe_payload(
        {"schema": "test-launcher-start.v1", "run_id": RUN_ID, "phase": "start"}
    )
    end = sealed_safe_payload({"schema": "test-launcher-end.v1", "run_id": RUN_ID, "phase": "end"})
    store.write_launcher_start(start)
    store.write_launcher_end(end)
    assert store.read_launcher_start() == start
    assert store.read_launcher_end() == end
    with pytest.raises(FileExistsError):
        store.write_launcher_start(start)
    with pytest.raises(FileExistsError):
        store.write_launcher_end(end)


def test_checkpoint_only_585_directory_cannot_be_loaded_as_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evaluation_root = tmp_path / "evaluations"
    evaluation_root.mkdir(mode=0o700)
    store = All60ReviewBatchStore(
        evaluation_root=evaluation_root,
        run_date=date(2026, 8, 20),
        run_id=RUN_ID,
        resume=False,
    )
    for ordinal in range(1, ALL60_ISSUE_COUNT + 1):
        row_id = f"live30-q01:issue-{((ordinal - 1) % 99) + 1:02d}"
        store._write(("checkpoints", store.checkpoint_name(ordinal, row_id)), {})
    assert len(store.members("checkpoints")) == ALL60_ISSUE_COUNT

    monkeypatch.setattr(
        all60_evidence_review,
        "load_all60_reviewer_batch_inputs",
        lambda **_kwargs: (),
        raising=False,
    )
    monkeypatch.setattr(batch, "_validate_runtime_binding", lambda **_kwargs: None)
    monkeypatch.setattr(batch, "_validate_memory_policy_binding", lambda **_kwargs: None)
    monkeypatch.setattr(batch, "_validate_inventory", lambda _values: ())
    with pytest.raises(ValueError, match="root inventory"):
        load_verified_all60_ai_review_batch(
            evaluation_root=evaluation_root,
            run_date=date(2026, 8, 20),
            run_id=RUN_ID,
            bundle=cast(Any, object()),
            candidate=cast(Any, object()),
            expert=cast(Any, object()),
            required_as_of_date=date(2026, 8, 20),
            runtime_binding={},
            memory_policy=cast(Any, object()),
            candidate_build_root=tmp_path / "candidate",
        )


def test_loader_replays_full_start_then_binds_end_to_verified_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected_members = (
        "batch-attestation.json",
        "checkpoints",
        "intents",
        "launcher-end-attestation.json",
        "launcher-start-attestation.json",
        "manifest.json",
        "outcomes",
    )
    fake_manifest = SimpleNamespace(launcher_run_id="launcher-test-run")
    fake_store = SimpleNamespace(
        relative=("all60-ai-review", "2026-08-20", RUN_ID),
        read_stop=lambda: None,
        read_manifest=lambda: fake_manifest,
        read_attestation=lambda: object(),
        read_launcher_start=lambda: {"phase": "start"},
        read_launcher_end=lambda: {"phase": "end"},
    )
    monkeypatch.setattr(batch, "All60ReviewBatchStore", lambda **_kwargs: fake_store)
    monkeypatch.setattr(batch, "list_directory_at", lambda *_args: expected_members)
    monkeypatch.setattr(
        all60_evidence_review,
        "load_all60_reviewer_batch_inputs",
        lambda **_kwargs: (),
        raising=False,
    )
    monkeypatch.setattr(batch, "_validate_runtime_binding", lambda **_kwargs: None)
    monkeypatch.setattr(batch, "_validate_memory_policy_binding", lambda **_kwargs: None)
    monkeypatch.setattr(batch, "_validate_inventory", lambda _values: ())
    verified_start = {
        "schema": LAUNCHER_START_SCHEMA,
        "run_id": "launcher-test-run",
        "seal_sha256": "a" * 64,
    }
    calls: list[tuple[str, object | None]] = []

    def _verify(value: object, *, schema: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((schema, kwargs.get("verified_start_attestation")))
        if schema == LAUNCHER_START_SCHEMA:
            assert value == {"phase": "start"}
            return verified_start
        assert value == {"phase": "end"}
        assert kwargs["verified_start_attestation"] is verified_start
        raise RuntimeError("production_launcher_attestation_invalid")

    monkeypatch.setattr(batch, "verify_launcher_attestation", _verify)
    runtime_binding = {
        "seal_sha256": RUNTIME_SEAL,
        "integration_sha": "b" * 40,
        "trusted_model_identity_sha256": "c" * 64,
        "launcher_implementation_sha256": "d" * 64,
        "model_toolchain": {
            "trusted_toolchain_identity_sha256": "e" * 64,
            "installed_environment_manifest_sha256": "f" * 64,
            "base_python_runtime_manifest_sha256": "1" * 64,
            "venv_control_manifest_sha256": "2" * 64,
        },
    }
    with pytest.raises(RuntimeError, match="production_launcher_attestation_invalid"):
        load_verified_all60_ai_review_batch(
            evaluation_root=tmp_path,
            run_date=date(2026, 8, 20),
            run_id=RUN_ID,
            bundle=cast(Any, object()),
            candidate=cast(Any, object()),
            expert=cast(Any, object()),
            required_as_of_date=date(2026, 8, 20),
            runtime_binding=runtime_binding,
            memory_policy=cast(Any, object()),
            candidate_build_root=tmp_path / "candidate",
        )
    assert calls == [
        (LAUNCHER_START_SCHEMA, None),
        (LAUNCHER_END_SCHEMA, verified_start),
    ]
