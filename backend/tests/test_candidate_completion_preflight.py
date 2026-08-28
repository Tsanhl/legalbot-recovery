from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, date, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import pytest

from app.config import FIRST_LIVE_LOCAL_ONLY_PROFILE, Settings
from app.evaluation import candidate_completion_runtime as completion_runtime
from app.evaluation.candidate_completion_authority import CompletionMemoryPolicy
from app.evaluation.candidate_completion_preflight import (
    CompletionWorkflowObservation,
    _failed_observation,
    _verify_completion_case_selection,
    _verify_completion_memory_envelope,
    _verify_completion_retry_attempt,
    completion_runtime_binding,
    load_verified_authoritative_completion_preflight,
    run_candidate_completion_preflight,
    run_synthetic_candidate_completion_preflight,
)
from app.evaluation.candidate_completion_runtime import (
    _enforce_startup_memory_policy,
    _exact_verified_full_suppression,
    _verify_model_artifact_manifest,
    validate_completion_launcher_settings,
)
from app.evaluation.candidate_runtime_preflight import build_preflight_case_selection
from app.evaluation.live_suite import load_live_evaluation_bundle, sealed_sha256
from app.evaluation.sealed_candidate import SealedCandidateIdentity
from app.model_runtime.config import PINNED_RUNTIME_REPO, PINNED_RUNTIME_REVISION
from app.observability.live_metrics import load_slo_policy
from app.orchestration.retry_policy import failure_fingerprint

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"


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


def _binding() -> dict[str, Any]:
    return completion_runtime_binding(
        candidate=_candidate(),
        model_id=PINNED_RUNTIME_REPO,
        model_revision=PINNED_RUNTIME_REVISION,
        model_version=f"{PINNED_RUNTIME_REPO}@{PINNED_RUNTIME_REVISION[:12]}",
        model_runtime_implementation_sha256="8" * 64,
        launcher_implementation_sha256="a" * 64,
        authority_implementation_sha256="b" * 64,
        model_artifact_metadata_sha256="9" * 64,
        trusted_model_identity_sha256="0" * 64,
        model_toolchain={
            "trusted_toolchain_identity_sha256": "a" * 64,
            "uv_executable_sha256": "b" * 64,
            "python_executable_sha256": "c" * 64,
            "model_runtime_lock_sha256": "d" * 64,
            "model_runtime_pyproject_sha256": "e" * 64,
            "locked_package_set_sha256": "f" * 64,
            "launch_environment_policy_sha256": "1" * 64,
            "installed_environment_manifest_sha256": "2" * 64,
            "base_python_runtime_manifest_sha256": "3" * 64,
            "venv_control_manifest_sha256": "4" * 64,
            "system_tool_set_sha256": "5" * 64,
        },
        model_runtime_profile={
            "context_window_tokens": 8192,
            "max_output_tokens": 2048,
            "prefill_step_size": 512,
            "kv_cache_bits": 8,
            "kv_group_size": 64,
            "clear_cache_after_request": True,
            "single_flight_generation": True,
        },
        draft_prompt_version="evidence-first-structured-json-v3",
        draft_prompt_implementation_sha256="d" * 64,
        quality_policy_version="quality-v1",
        quality_policy_sha256="e" * 64,
        standards_bundle_version="standards-v1",
        standards_bundle_sha256="f" * 64,
        reviewer_role="ai_evidence_reviewer",
        reviewer_prompt_sha256="1" * 64,
        reviewer_policy_sha256="2" * 64,
        reviewer_toolchain_sha256="3" * 64,
        reviewer_implementation_sha256="4" * 64,
        retry_implementation_sha256="5" * 64,
        slo_policy_id="local-e2e-provisional-v2",
        slo_policy_sha256=hashlib.sha256(
            (PROJECT_ROOT / "config/observability_slo.yaml").read_bytes()
        ).hexdigest(),
        integration_sha="7" * 40,
    )


def _memory_policy(
    binding: dict[str, Any],
    *,
    maximum_bytes: int = 4 * 1024**3,
    minimum_headroom_bytes: int = 4 * 1024**3,
) -> CompletionMemoryPolicy:
    payload: dict[str, Any] = {
        "schema": "legalbot.completion-memory-policy.v2",
        "policy_id": "owner-memory-envelope-test",
        "candidate_build_id": "candidate-v111",
        "candidate_manifest_sha256": "a" * 64,
        "runtime_binding_sha256": binding["seal_sha256"],
        "integration_sha": binding["integration_sha"],
        "measurement_schema": "legalbot.completion-memory-measurement.v2",
        "host_physical_memory_bytes": 16 * 1024**3,
        "max_peak_combined_working_set_bytes": maximum_bytes,
        "minimum_host_available_memory_bytes": minimum_headroom_bytes,
        "owner_decision_id": f"v111-completion-memory-{'1' * 20}",
        "owner_decision_request_seal_sha256": "b" * 64,
        "owner_decision_resolution_seal_sha256": "c" * 64,
        "owner_selected_option_id": "max-12884901888-min-3221225472",
        "created_at": "2026-08-20T08:00:00+00:00",
    }
    payload["seal_sha256"] = sealed_sha256(payload)
    return CompletionMemoryPolicy.model_validate(payload)


def test_only_exact_final_verified_full_suppression_counts_as_release_gate() -> None:
    final_answer_id = "answer-v3"
    assert _exact_verified_full_suppression(
        [("older", "verified_full"), (final_answer_id, "verified_full")],
        start=1,
        final_answer_id=final_answer_id,
    )
    assert not _exact_verified_full_suppression(
        [("other-answer", "verified_full")], start=0, final_answer_id=final_answer_id
    )
    assert not _exact_verified_full_suppression(
        [(final_answer_id, "verified_limited")], start=0, final_answer_id=final_answer_id
    )
    assert not _exact_verified_full_suppression(
        [(final_answer_id, "verified_full"), (final_answer_id, "verified_full")],
        start=0,
        final_answer_id=final_answer_id,
    )


class _FakeClock:
    def now(self) -> datetime:
        return datetime(2026, 8, 20, 8, 0, tzinfo=UTC)


class _FakeRuntime:
    def __init__(
        self,
        *,
        binding: dict[str, Any],
        failures: dict[tuple[str, str, int, int], str] | None = None,
        completion_multiplier: float = 0.1,
        mismatch_warm_instance: bool = False,
        controller_peak_bytes: int = 512 * 1024**2,
        sidecar_peak_rss_bytes: int = 2 * 1024**3,
        model_allocator_peak_bytes: int = 64 * 1024**2,
        host_available_bytes: int = 8 * 1024**3,
        memory_overrides: dict[tuple[str, str, int, int], tuple[int, int, int]] | None = None,
    ) -> None:
        self.binding = binding
        self.failures = failures or {}
        self.completion_multiplier = completion_multiplier
        self.mismatch_warm_instance = mismatch_warm_instance
        self.controller_peak_bytes = controller_peak_bytes
        self.sidecar_peak_rss_bytes = sidecar_peak_rss_bytes
        self.model_allocator_peak_bytes = model_allocator_peak_bytes
        self.host_available_bytes = host_available_bytes
        self.memory_overrides = memory_overrides or {}
        self.calls: list[tuple[str, str, int, int]] = []
        self.instances: dict[str, tuple[str, str]] = {}

    async def run_workflow(
        self,
        *,
        case: Any,
        band: Any,
        as_of_date: date,
        sample_kind: Literal["cold", "warm"],
        sample_ordinal: int,
        attempt_number: int,
        runtime_binding_sha256: str,
    ) -> CompletionWorkflowObservation:
        del as_of_date
        key = (case.case_id, sample_kind, sample_ordinal, attempt_number)
        self.calls.append(key)
        if sample_kind == "cold":
            instance = hashlib.sha256(
                f"instance:{case.case_id}:{attempt_number}".encode()
            ).hexdigest()
            proof = hashlib.sha256(f"proof:{instance}".encode()).hexdigest()
            self.instances[case.case_id] = (instance, proof)
        instance, proof = self.instances[case.case_id]
        if self.mismatch_warm_instance and sample_kind == "warm":
            instance = "9" * 64
        reason = self.failures.get(key)
        succeeded = reason is None
        controller_peak, sidecar_peak, host_available = self.memory_overrides.get(
            key,
            (
                self.controller_peak_bytes,
                self.sidecar_peak_rss_bytes,
                self.host_available_bytes,
            ),
        )
        return CompletionWorkflowObservation(
            case_id=case.case_id,
            question_sha256=case.question_sha256,
            sample_kind=sample_kind,
            sample_ordinal=sample_ordinal,
            attempt_number=attempt_number,
            route=case.expected_research_route,
            word_target=case.word_target,
            slo_band_id=band.id,
            runtime_binding_sha256=runtime_binding_sha256,
            runtime_instance_sha256=instance,
            cold_launch_proof_sha256=proof,
            candidate_build_id="candidate-v111",
            model_version=str(self.binding["model_version"]),
            model_state=(
                "verified_fresh_instance" if sample_kind == "cold" else "warm_same_instance"
            ),
            retrieval_cache_state=(
                "bypassed" if sample_kind == "cold" else "enabled_state_unobserved"
            ),
            status="succeeded" if succeeded else "failed",
            failure_reason_code=reason,
            completion_seconds=(
                float(band.targets_p95_seconds["completion_seconds"]) * self.completion_multiplier
            ),
            stage_timings_seconds={
                "retrieval": 1.0,
                "drafting": 2.0,
                "verification": 3.0,
                "reviewer": 0.5,
            },
            reviewer_phase_seconds=0.5,
            ttft_observed=True,
            time_to_first_token_seconds=0.25,
            controller_peak_rss_bytes=controller_peak,
            sidecar_peak_rss_bytes=sidecar_peak,
            model_allocator_peak_bytes=self.model_allocator_peak_bytes,
            peak_combined_working_set_bytes=(controller_peak + sidecar_peak),
            minimum_host_available_memory_bytes=host_available,
            memory_sample_count=10,
            memory_max_observed_sample_interval_seconds=0.1,
            memory_max_sampling_jitter_seconds=0.0,
            startup_controller_peak_rss_bytes=controller_peak,
            startup_sidecar_peak_rss_bytes=sidecar_peak,
            startup_peak_combined_working_set_bytes=(controller_peak + sidecar_peak),
            startup_minimum_host_available_memory_bytes=host_available,
            startup_memory_sample_count=10,
            startup_memory_max_observed_sample_interval_seconds=0.1,
            startup_memory_max_sampling_jitter_seconds=0.0,
            startup_memory_measurement_sha256=hashlib.sha256(
                f"startup:{case.case_id}:{attempt_number}".encode()
            ).hexdigest(),
            input_token_count=100,
            output_token_count=50,
            total_token_count=150,
            evidence_span_count=4 if succeeded else 0,
            material_claim_count=2 if succeeded else 0,
            quality_release_state="verified_full" if succeeded else None,
            hard_quality_gates_passed=succeeded,
            ai_evidence_reviewer_passed=succeeded,
            standards_avoidance_passed=succeeded,
            word_tolerance_passed=succeeded,
            public_release_written=False,
            answer_release_state_present=False,
            plaintext_prose_written=False,
            encrypted_prose_retained=True,
        )


def _inputs() -> tuple[Any, Any]:
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT)
    slo = load_slo_policy(PROJECT_ROOT / "config/observability_slo.yaml")
    return bundle, slo


def _selected_case_id() -> str:
    bundle, slo = _inputs()
    return build_preflight_case_selection(
        bundle=bundle,
        slo_policy=slo,
        additional_case_ids=None,
    ).selected_case_ids[0]


def _retry_attempt(
    *,
    reason_code: str,
    attempt_number: int,
    failure_fingerprint_sha256: str,
    decision_action: str,
    decision_reason: str,
    retries_remaining: int,
) -> tuple[dict[str, Any], Any, Any, dict[str, Any]]:
    bundle, slo = _inputs()
    binding = _binding()
    case = bundle.registry.case(_selected_case_id())
    band = slo.band_for(route=case.expected_research_route, word_target=case.word_target)
    observation = _failed_observation(
        case=case,
        band=band,
        sample_kind="cold",
        sample_ordinal=1,
        attempt_number=attempt_number,
        runtime_binding=binding,
        candidate=_candidate(),
        reason_code=reason_code,
    )
    payload = observation.model_dump(mode="json", by_alias=True)
    payload.update(
        controller_peak_rss_bytes=512 * 1024**2,
        sidecar_peak_rss_bytes=2 * 1024**3,
        peak_combined_working_set_bytes=512 * 1024**2 + 2 * 1024**3,
        minimum_host_available_memory_bytes=8 * 1024**3,
        memory_sample_count=10,
        memory_max_observed_sample_interval_seconds=0.1,
        startup_controller_peak_rss_bytes=512 * 1024**2,
        startup_sidecar_peak_rss_bytes=2 * 1024**3,
        startup_peak_combined_working_set_bytes=512 * 1024**2 + 2 * 1024**3,
        startup_minimum_host_available_memory_bytes=8 * 1024**3,
        startup_memory_sample_count=10,
        startup_memory_max_observed_sample_interval_seconds=0.1,
        startup_memory_measurement_sha256="6" * 64,
        failure_fingerprint_sha256=failure_fingerprint_sha256,
        decision_action=decision_action,
        decision_reason=decision_reason,
        retries_remaining=retries_remaining,
    )
    return payload, case, band, binding


def _expected_retry_fingerprint(reason_code: str) -> str:
    bundle, _ = _inputs()
    binding = _binding()
    case = bundle.registry.case(_selected_case_id())
    return failure_fingerprint(
        stage="completion_preflight",
        reason_code=reason_code,
        scope_id=case.case_id,
        identity_digests=(
            case.question_sha256,
            _candidate().candidate_manifest_sha256,
            str(binding["seal_sha256"]),
        ),
        safe_context={"sample_kind": "cold", "sample_ordinal": 1},
    )


def test_authoritative_loader_requires_exact_representative_case_contract() -> None:
    bundle, slo = _inputs()
    incomplete_selection = {
        "case_ids": [_selected_case_id()],
        "case_count": 1,
        "case_contracts": [],
        "sample_plan": [
            {"sample_kind": "cold", "sample_ordinal": 1},
            *({"sample_kind": "warm", "sample_ordinal": ordinal} for ordinal in range(1, 4)),
        ],
        "warm_runs_per_case": 3,
    }
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_case_contract_invalid",
    ):
        _verify_completion_case_selection(incomplete_selection, bundle=bundle, slo_policy=slo)


def test_authoritative_loader_recomputes_owner_memory_envelope() -> None:
    binding = _binding()
    policy = _memory_policy(
        binding,
        maximum_bytes=12 * 1024**3,
        minimum_headroom_bytes=3 * 1024**3,
    )
    _verify_completion_memory_envelope(
        policy,
        observed_maximum_peak=12 * 1024**3,
        observed_minimum_headroom=3 * 1024**3,
    )
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_memory_policy_exceeded",
    ):
        _verify_completion_memory_envelope(
            policy,
            observed_maximum_peak=12 * 1024**3 + 1,
            observed_minimum_headroom=3 * 1024**3,
        )
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_memory_policy_exceeded",
    ):
        _verify_completion_memory_envelope(
            policy,
            observed_maximum_peak=10 * 1024**3,
            observed_minimum_headroom=3 * 1024**3 - 1,
        )


def test_completion_observation_rejects_favorable_startup_combined_rss() -> None:
    bundle, slo = _inputs()
    binding = _binding()
    case = bundle.registry.case(_selected_case_id())
    band = slo.band_for(route=case.expected_research_route, word_target=case.word_target)
    payload = _failed_observation(
        case=case,
        band=band,
        sample_kind="cold",
        sample_ordinal=1,
        attempt_number=1,
        runtime_binding=binding,
        candidate=_candidate(),
        reason_code="transient_runtime",
    ).model_dump(mode="json", by_alias=True)
    payload.update(
        startup_controller_peak_rss_bytes=512 * 1024**2,
        startup_sidecar_peak_rss_bytes=4 * 1024**3,
        startup_peak_combined_working_set_bytes=1,
    )
    with pytest.raises(
        ValueError,
        match="startup combined working-set measurement is inconsistent",
    ):
        CompletionWorkflowObservation.model_validate(payload)


def test_authoritative_loader_replays_retry_fingerprint_and_policy() -> None:
    expected = _expected_retry_fingerprint("transient_runtime")
    valid, case, band, binding = _retry_attempt(
        reason_code="transient_runtime",
        attempt_number=1,
        failure_fingerprint_sha256=expected,
        decision_action="retry",
        decision_reason="retry_allowed",
        retries_remaining=2,
    )
    memory_policy = _memory_policy(
        binding,
        maximum_bytes=12 * 1024**3,
        minimum_headroom_bytes=3 * 1024**3,
    )
    assert (
        _verify_completion_retry_attempt(
            valid,
            case=case,
            band=band,
            candidate=_candidate(),
            runtime_binding=binding,
            sample_kind="cold",
            sample_ordinal=1,
            attempt_number=1,
            prior_fingerprints=(),
            memory_policy=memory_policy,
        )
        == expected
    )

    fabricated = dict(valid, failure_fingerprint_sha256="f" * 64)
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_retry_chain_invalid",
    ):
        _verify_completion_retry_attempt(
            fabricated,
            case=case,
            band=band,
            candidate=_candidate(),
            runtime_binding=binding,
            sample_kind="cold",
            sample_ordinal=1,
            attempt_number=1,
            prior_fingerprints=(),
            memory_policy=memory_policy,
        )


@pytest.mark.parametrize(
    "memory_mutation",
    (
        {
            "controller_peak_rss_bytes": 1 * 1024**3,
            "sidecar_peak_rss_bytes": 13 * 1024**3,
            "peak_combined_working_set_bytes": 14 * 1024**3,
            "startup_controller_peak_rss_bytes": 1 * 1024**3,
            "startup_sidecar_peak_rss_bytes": 13 * 1024**3,
            "startup_peak_combined_working_set_bytes": 14 * 1024**3,
        },
        {
            "minimum_host_available_memory_bytes": 1 * 1024**3,
            "startup_minimum_host_available_memory_bytes": 1 * 1024**3,
        },
    ),
)
def test_authoritative_loader_rejects_retry_attempt_memory_mutation(
    memory_mutation: dict[str, int],
) -> None:
    expected = _expected_retry_fingerprint("transient_runtime")
    attempt, case, band, binding = _retry_attempt(
        reason_code="transient_runtime",
        attempt_number=1,
        failure_fingerprint_sha256=expected,
        decision_action="retry",
        decision_reason="retry_allowed",
        retries_remaining=2,
    )
    attempt.update(memory_mutation)
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_retry_chain_invalid",
    ):
        _verify_completion_retry_attempt(
            attempt,
            case=case,
            band=band,
            candidate=_candidate(),
            runtime_binding=binding,
            sample_kind="cold",
            sample_ordinal=1,
            attempt_number=1,
            prior_fingerprints=(),
            memory_policy=_memory_policy(
                binding,
                maximum_bytes=12 * 1024**3,
                minimum_headroom_bytes=3 * 1024**3,
            ),
        )


def test_authoritative_loader_rejects_deterministic_and_repeated_retry_relabels() -> None:
    deterministic_fingerprint = _expected_retry_fingerprint("evidence_empty")
    deterministic, case, band, binding = _retry_attempt(
        reason_code="evidence_empty",
        attempt_number=1,
        failure_fingerprint_sha256=deterministic_fingerprint,
        decision_action="retry",
        decision_reason="retry_allowed",
        retries_remaining=2,
    )
    memory_policy = _memory_policy(
        binding,
        maximum_bytes=12 * 1024**3,
        minimum_headroom_bytes=3 * 1024**3,
    )
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_retry_chain_invalid",
    ):
        _verify_completion_retry_attempt(
            deterministic,
            case=case,
            band=band,
            candidate=_candidate(),
            runtime_binding=binding,
            sample_kind="cold",
            sample_ordinal=1,
            attempt_number=1,
            prior_fingerprints=(),
            memory_policy=memory_policy,
        )

    repeated_fingerprint = _expected_retry_fingerprint("transient_runtime")
    repeated, case, band, binding = _retry_attempt(
        reason_code="transient_runtime",
        attempt_number=2,
        failure_fingerprint_sha256=repeated_fingerprint,
        decision_action="retry",
        decision_reason="retry_allowed",
        retries_remaining=1,
    )
    with pytest.raises(
        RuntimeError,
        match="authoritative_completion_preflight_retry_chain_invalid",
    ):
        _verify_completion_retry_attempt(
            repeated,
            case=case,
            band=band,
            candidate=_candidate(),
            runtime_binding=binding,
            sample_kind="cold",
            sample_ordinal=1,
            attempt_number=2,
            prior_fingerprints=(repeated_fingerprint,),
            memory_policy=memory_policy,
        )


@pytest.mark.asyncio
async def test_full_completion_preflight_proves_cold_warm_p95_without_release(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(binding=binding)
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-pass",
        output_root=tmp_path / "private",
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
        clock=_FakeClock(),
    )

    assert result["completion_preflight_passed"] is False
    assert result["synthetic_checks_passed"] is True
    assert result["synthetic_non_authoritative"] is True
    assert result["sample_count"] == result["case_count"] * 4
    assert result["cold_sample_count"] == result["case_count"]
    assert result["verified_fresh_model_instance_count"] == result["case_count"]
    assert all(row["warm_sample_count"] >= 3 for row in result["band_summaries"])
    assert all(row["completion_p95_passed"] for row in result["band_summaries"])
    assert {row["completion_p95_ceiling_seconds"] for row in result["band_summaries"]} == {
        1_800.0,
        3_600.0,
        5_400.0,
        10_800.0,
    }
    assert result["writes_active"] is False
    assert result["writes_o04"] is False
    assert result["writes_release"] is False

    run_root = tmp_path / "private/completion-test-pass"
    assert stat.S_IMODE(run_root.stat().st_mode) == 0o700
    assert stat.S_IMODE((run_root / "run-manifest.json").stat().st_mode) == 0o600
    manifest = json.loads((run_root / "run-manifest.json").read_text())
    assert manifest["created_at"] == "2026-08-20T08:00:00+00:00"
    selected_case_id = str(manifest["case_ids"][0])
    cold = json.loads((run_root / f"samples/{selected_case_id}/cold-01.json").read_text())
    warm = json.loads((run_root / f"samples/{selected_case_id}/warm-01.json").read_text())
    assert cold["model_state"] == "verified_fresh_instance"
    assert cold["retrieval_cache_state"] == "bypassed"
    assert warm["model_state"] == "warm_same_instance"
    assert warm["retrieval_cache_state"] == "enabled_state_unobserved"
    assert warm["runtime_instance_sha256"] == cold["runtime_instance_sha256"]
    serialized = json.dumps(result).casefold()
    assert 'question"' not in serialized
    assert "answer_text" not in serialized
    with pytest.raises(RuntimeError, match="completion_memory_policy_not_loader_verified"):
        load_verified_authoritative_completion_preflight(
            run_root,
            project_root=PROJECT_ROOT,
            memory_policy=_memory_policy(binding),  # type: ignore[arg-type]
            expected_candidate_build_id=_candidate().build_id,
            expected_candidate_manifest_sha256=_candidate().candidate_manifest_sha256,
            expected_integration_sha=str(binding["integration_sha"]),
            expected_runtime_binding_sha256=str(binding["seal_sha256"]),
            expected_trusted_toolchain_identity_sha256=str(
                binding["model_toolchain"]["trusted_toolchain_identity_sha256"]
            ),
            expected_base_python_runtime_manifest_sha256=str(
                binding["model_toolchain"]["base_python_runtime_manifest_sha256"]
            ),
            expected_venv_control_manifest_sha256=str(
                binding["model_toolchain"]["venv_control_manifest_sha256"]
            ),
        )


@pytest.mark.asyncio
async def test_completion_preflight_stops_deterministic_failure_without_retry(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(
        binding=binding,
        failures={(_selected_case_id(), "cold", 1, 1): "evidence_empty"},
    )
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-deterministic-stop",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
    )

    assert result["status"] == "stopped"
    assert result["stop_reason"] == "deterministic_safety_failure"
    assert result["attempt_number"] == 1
    assert len(runtime.calls) == 1


@pytest.mark.asyncio
async def test_completion_preflight_stops_second_identical_failure(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(
        binding=binding,
        failures={
            (_selected_case_id(), "cold", 1, 1): "transient_runtime",
            (_selected_case_id(), "cold", 1, 2): "transient_runtime",
        },
    )
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-repeat-stop",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
    )

    assert result["stop_reason"] == "repeated_failure_fingerprint"
    assert result["attempt_number"] == 2
    assert len(runtime.calls) == 2


@pytest.mark.asyncio
async def test_completion_preflight_never_exceeds_initial_plus_two_attempts(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(
        binding=binding,
        failures={
            (_selected_case_id(), "cold", 1, 1): "transient_one",
            (_selected_case_id(), "cold", 1, 2): "transient_two",
            (_selected_case_id(), "cold", 1, 3): "transient_three",
        },
    )
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-cap-stop",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
    )

    assert result["stop_reason"] == "retry_cap_exhausted"
    assert result["attempt_number"] == 3
    assert len(runtime.calls) == 3


@pytest.mark.asyncio
async def test_completion_preflight_fails_warm_instance_fork(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(binding=binding, mismatch_warm_instance=True)
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-instance-fork",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
    )

    assert result["status"] == "stopped"
    assert result["failure_reason_code"] == "runtime_binding_mismatch"
    assert result["stop_reason"] == "deterministic_safety_failure"


@pytest.mark.asyncio
async def test_completion_preflight_fails_provisional_completion_p95(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(binding=binding, completion_multiplier=1.1)
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-slo-fail",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
    )

    assert result["status"] == "failed"
    assert result["completion_preflight_passed"] is False
    assert any(not row["completion_p95_passed"] for row in result["band_summaries"])


@pytest.mark.asyncio
async def test_sidecar_rss_exceeds_ceiling_even_when_allocator_telemetry_is_low(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    runtime = _FakeRuntime(binding=binding)
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-memory-stop",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
        memory_policy=_memory_policy(binding, maximum_bytes=2 * 1024**3),
    )

    assert result["status"] == "stopped"
    assert result["failure_reason_code"] == "memory_working_set_exceeds_owner_ceiling"
    assert result["attempt_number"] == 1


@pytest.mark.asyncio
async def test_failed_high_memory_attempt_stops_before_later_success(tmp_path: Path) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    selected_case_id = _selected_case_id()
    first_attempt = (selected_case_id, "cold", 1, 1)
    runtime = _FakeRuntime(
        binding=binding,
        failures={first_attempt: "transient_runtime"},
        memory_overrides={
            first_attempt: (
                1 * 1024**3,
                13 * 1024**3,
                1 * 1024**3,
            )
        },
    )
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-failed-memory-stop",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
        memory_policy=_memory_policy(
            binding,
            maximum_bytes=12 * 1024**3,
            minimum_headroom_bytes=3 * 1024**3,
        ),
    )

    assert result["status"] == "stopped"
    assert result["failure_reason_code"] == "memory_working_set_exceeds_owner_ceiling"
    assert result["stop_reason"] == "deterministic_safety_failure"
    assert runtime.calls == [first_attempt]
    attempt = json.loads(
        (
            tmp_path
            / "completion-test-failed-memory-stop"
            / f"attempts/{selected_case_id}/cold-01-attempt-01.json"
        ).read_text(encoding="utf-8")
    )
    assert attempt["status"] == "failed"
    assert attempt["failure_reason_code"] == "memory_working_set_exceeds_owner_ceiling"
    assert attempt["decision_action"] == "stop"
    assert attempt["peak_combined_working_set_bytes"] == 14 * 1024**3
    assert attempt["startup_peak_combined_working_set_bytes"] == 14 * 1024**3
    assert attempt["minimum_host_available_memory_bytes"] == 1 * 1024**3


@pytest.mark.asyncio
async def test_completion_preflight_reports_runwide_failed_attempt_memory_extrema(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    selected_case_id = _selected_case_id()
    first_attempt = (selected_case_id, "cold", 1, 1)
    first_attempt_peak = 11 * 1024**3
    first_attempt_headroom = 7 * 1024**3 // 2
    runtime = _FakeRuntime(
        binding=binding,
        failures={first_attempt: "transient_runtime"},
        memory_overrides={
            first_attempt: (
                1 * 1024**3,
                10 * 1024**3,
                first_attempt_headroom,
            )
        },
    )
    result = await run_synthetic_candidate_completion_preflight(
        run_id="completion-test-attempt-memory-extrema",
        output_root=tmp_path,
        bundle=bundle,
        candidate=_candidate(),
        runtime=runtime,
        runtime_binding=binding,
        slo_policy=slo,
        as_of_date=date(2026, 8, 20),
        memory_policy=_memory_policy(
            binding,
            maximum_bytes=12 * 1024**3,
            minimum_headroom_bytes=3 * 1024**3,
        ),
    )

    assert result["synthetic_checks_passed"] is True
    assert runtime.calls[:2] == [first_attempt, (selected_case_id, "cold", 1, 2)]
    assert result["maximum_peak_combined_working_set_bytes"] == first_attempt_peak
    assert result["minimum_observed_host_available_memory_bytes"] == first_attempt_headroom
    assert result["memory_safety_passed"] is True


@pytest.mark.asyncio
async def test_production_preflight_refuses_injected_synthetic_runtime(
    tmp_path: Path,
) -> None:
    bundle, slo = _inputs()
    binding = _binding()
    with pytest.raises(RuntimeError, match="non_authoritative_completion_runtime_refused"):
        await run_candidate_completion_preflight(
            run_id="completion-test-fake-production",
            output_root=tmp_path,
            bundle=bundle,
            candidate=_candidate(),
            runtime=_FakeRuntime(binding=binding),
            runtime_binding=binding,
            slo_policy=slo,
            as_of_date=date(2026, 8, 20),
            memory_policy=None,  # type: ignore[arg-type]
        )


def test_completion_launcher_rejects_non_loopback_and_online_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    common = {
        "project_root": tmp_path,
        "live_profile": FIRST_LIVE_LOCAL_ONLY_PROFILE,
        "online_default": "local_only",
        "official_research_enabled": False,
        "test_mode": False,
        "model_id": PINNED_RUNTIME_REPO,
    }
    settings = Settings(**common, host="0.0.0.0", model_url="http://127.0.0.1:8778")
    with pytest.raises(RuntimeError, match="non_loopback_runtime"):
        validate_completion_launcher_settings(settings)

    settings = Settings(**common, host="127.0.0.1", model_url="http://127.0.0.1:8778")
    assert validate_completion_launcher_settings(settings) == ("127.0.0.1", 8778)
    monkeypatch.setenv("LEGALBOT_MODEL_ADAPTER_PATH", "/private/adapter")
    with pytest.raises(RuntimeError, match="unapproved_model_adapter_configured"):
        validate_completion_launcher_settings(settings)


def test_completion_launcher_rehashes_exact_model_artifact(tmp_path: Path) -> None:
    model_root = tmp_path / "model"
    model_root.mkdir()
    config = model_root / "config.json"
    weights = model_root / "model.safetensors"
    config.write_bytes(b"config-bytes")
    weights.write_bytes(b"weight-bytes")
    records = [
        {
            "path": path.name,
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (config, weights)
    ]
    provenance_path = model_root / "runtime-model.json"
    provenance = {
        "source_repo": PINNED_RUNTIME_REPO,
        "revision": PINNED_RUNTIME_REVISION,
        "post_trained": True,
        "quantization_bits": 4,
        "files": records,
    }
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    trusted = {
        "runtime_model_sha256": hashlib.sha256(provenance_path.read_bytes()).hexdigest(),
        "file_manifest_sha256": sealed_sha256(
            {"schema": "legalbot.trusted-model-file-manifest.v1", "files": records}
        ),
    }

    _verify_model_artifact_manifest(model_root, trusted)
    weights.write_bytes(b"changed-weights")
    changed_records = [
        {
            "path": path.name,
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (config, weights)
    ]
    provenance["files"] = changed_records
    provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
    with pytest.raises(RuntimeError, match="model_artifact_manifest_invalid"):
        _verify_model_artifact_manifest(model_root, trusted)


def test_startup_memory_spike_stops_before_answer_workflow() -> None:
    binding = _binding()
    policy = _memory_policy(binding, maximum_bytes=12 * 1024**3)
    with pytest.raises(RuntimeError, match="memory_working_set_exceeds_owner_ceiling"):
        _enforce_startup_memory_policy(
            policy,
            sampled_peak_combined_working_set_bytes=13 * 1024**3,
            minimum_sampled_host_available_memory_bytes=3 * 1024**3,
            maximum_observed_sample_interval_seconds=0.1,
        )
    with pytest.raises(RuntimeError, match="memory_sampling_interval_exceeded"):
        _enforce_startup_memory_policy(
            policy,
            sampled_peak_combined_working_set_bytes=10 * 1024**3,
            minimum_sampled_host_available_memory_bytes=4 * 1024**3,
            maximum_observed_sample_interval_seconds=0.251,
        )


@pytest.mark.asyncio
async def test_launcher_health_ignores_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    class Response:
        status_code = 200

        def json(self) -> dict[str, Any]:
            return {
                "status": "ok",
                "backend": "mlx_lm",
                "model_id": PINNED_RUNTIME_REPO,
                "model_loaded": True,
                "stub_mode": False,
                "memory_profile": {"profile": "pinned"},
            }

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            observed.update(kwargs)

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: Any) -> None:
            del args

        async def get(self, url: str) -> Response:
            observed["url"] = url
            return Response()

    launcher = object.__new__(completion_runtime.LoopbackCandidateCompletionLauncher)
    launcher._model_host = "127.0.0.1"
    launcher._model_port = 8778
    launcher.settings = SimpleNamespace(model_id=PINNED_RUNTIME_REPO)
    launcher.runtime_binding = {"model_runtime_profile": {"profile": "pinned"}}
    launcher._sidecar = SimpleNamespace(pid=123)
    launcher._launch_nonce = "a" * 64
    launcher._owned_listener_proof_sha256 = None
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9998")
    monkeypatch.setattr(completion_runtime.httpx, "AsyncClient", Client)
    monkeypatch.setattr(completion_runtime, "attest_owned_listener", lambda **kwargs: "b" * 64)

    assert await completion_runtime.LoopbackCandidateCompletionLauncher._health(launcher)
    assert observed["trust_env"] is False
    assert observed["follow_redirects"] is False
    assert observed["url"] == "http://127.0.0.1:8778/api/v1/health"
