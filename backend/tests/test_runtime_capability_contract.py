from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.contracts import (
    CapabilityInput,
    ContractSchemaRegistry,
    build_runtime_capability_manifest,
    require_runtime_operation,
)
from app.evaluation.visible_ge_admission import (
    VISIBLE_GE_OPERATION,
    VISIBLE_GE_REQUIRED_CAPABILITIES,
    VisibleGEExecutionBinding,
    require_visible_ge_evaluation_capability,
)


def _build(*, candidate_status: str = "PASS"):
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    created = datetime(2026, 9, 1, tzinfo=UTC)
    manifest = build_runtime_capability_manifest(
        process_role="answer_worker",
        process_instance_id="answer-worker-test",
        config_sha256="1" * 64,
        environment_sha256="2" * 64,
        capabilities=(
            CapabilityInput(
                name="contracts.selected",
                status="PASS",
                evidence_sha256="3" * 64,
                reason_code="schema.bundle.verified",
                checked_at=created,
                valid_until=created + timedelta(minutes=10),
            ),
            CapabilityInput(  # type: ignore[arg-type]
                name="candidate.bound",
                status=candidate_status,
                evidence_sha256="4" * 64 if candidate_status == "PASS" else None,
                reason_code="candidate.verified"
                if candidate_status == "PASS"
                else "candidate.missing",
                checked_at=created,
                valid_until=created + timedelta(minutes=10),
            ),
        ),
        operation_requirements={
            "answer.retrieve": ("contracts.selected", "candidate.bound"),
        },
        bound_artifacts={"candidate": "5" * 64},
        created_at=created,
        expires_at=created + timedelta(minutes=5),
        registry=registry,
    )
    return registry, created, manifest


def test_operation_grant_is_derived_and_replayed_against_external_digest() -> None:
    registry, created, manifest = _build()
    observed = require_runtime_operation(
        manifest,
        operation="answer.retrieve",
        expected_manifest_sha256=manifest["manifest_sha256"],
        expected_process_role="answer_worker",
        expected_process_instance_id="answer-worker-test",
        expected_config_sha256="1" * 64,
        expected_environment_sha256="2" * 64,
        expected_bound_artifacts={"candidate": "5" * 64},
        required_capabilities=("contracts.selected", "candidate.bound"),
        now=created + timedelta(minutes=1),
        registry=registry,
    )
    assert observed == manifest["manifest_sha256"]


def test_failed_capability_cannot_self_grant_or_run() -> None:
    registry, created, manifest = _build(candidate_status="FAIL")
    assert manifest["operation_grants"][0]["granted"] is False
    with pytest.raises(RuntimeError, match="capability"):
        require_runtime_operation(
            manifest,
            operation="answer.retrieve",
            expected_manifest_sha256=manifest["manifest_sha256"],
            expected_process_role="answer_worker",
            expected_process_instance_id="answer-worker-test",
            expected_config_sha256="1" * 64,
            expected_environment_sha256="2" * 64,
            expected_bound_artifacts={"candidate": "5" * 64},
            required_capabilities=("contracts.selected", "candidate.bound"),
            now=created + timedelta(minutes=1),
            registry=registry,
        )


def test_manifest_expiry_fails_closed() -> None:
    registry, created, manifest = _build()
    with pytest.raises(RuntimeError, match="validity"):
        require_runtime_operation(
            manifest,
            operation="answer.retrieve",
            expected_manifest_sha256=manifest["manifest_sha256"],
            expected_process_role="answer_worker",
            expected_process_instance_id="answer-worker-test",
            expected_config_sha256="1" * 64,
            expected_environment_sha256="2" * 64,
            expected_bound_artifacts={"candidate": "5" * 64},
            required_capabilities=("contracts.selected", "candidate.bound"),
            now=created + timedelta(minutes=6),
            registry=registry,
        )


def test_visible_ge_admission_requires_every_exact_external_gate() -> None:
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    created = datetime(2026, 9, 1, tzinfo=UTC)
    expires = created + timedelta(minutes=10)
    binding = VisibleGEExecutionBinding(
        candidate_sha256="1" * 64,
        model_sha256="2" * 64,
        prompt_sha256="3" * 64,
        renderer_sha256="4" * 64,
        validator_bundle_sha256="5" * 64,
        case_manifest_sha256="6" * 64,
        case_order_sha256="7" * 64,
        system_manifest_sha256="8" * 64,
        system_order_sha256="9" * 64,
        input_projection_sha256="a" * 64,
        factual_gate_policy_sha256="b" * 64,
        quality_gate_policy_sha256="c" * 64,
        gold_currentness_decision_sha256="d" * 64,
        development_private_root_capability_sha256="e" * 64,
        evaluation_authority_sha256="f" * 64,
        resource_policy_sha256="1" * 64,
        unseen_custody_ledger_sha256="2" * 64,
        iteration_plan_sha256="3" * 64,
        diagnostic_pack_sha256="4" * 64,
    )
    capabilities = [
        CapabilityInput(
            name=name,
            status="PASS",
            evidence_sha256=hashlib.sha256(name.encode()).hexdigest(),
            reason_code="verified",
            checked_at=created,
            valid_until=expires,
        )
        for name in VISIBLE_GE_REQUIRED_CAPABILITIES
    ]
    manifest = build_runtime_capability_manifest(
        process_role="evaluation_harness",
        process_instance_id="evaluation-harness-1",
        config_sha256="0" * 64,
        environment_sha256="1" * 64,
        capabilities=capabilities,
        operation_requirements={VISIBLE_GE_OPERATION: VISIBLE_GE_REQUIRED_CAPABILITIES},
        bound_artifacts=binding.bound_artifacts(),
        created_at=created,
        expires_at=expires,
        registry=registry,
    )
    observed = require_visible_ge_evaluation_capability(
        manifest,
        expected_manifest_sha256=manifest["manifest_sha256"],
        expected_process_instance_id="evaluation-harness-1",
        expected_config_sha256="0" * 64,
        expected_environment_sha256="1" * 64,
        binding=binding,
        now=created + timedelta(minutes=1),
        registry=registry,
    )
    assert observed == manifest["manifest_sha256"]

    changed = replace(binding, candidate_sha256="0" * 64)
    with pytest.raises(RuntimeError, match="artifact identity differs"):
        require_visible_ge_evaluation_capability(
            manifest,
            expected_manifest_sha256=manifest["manifest_sha256"],
            expected_process_instance_id="evaluation-harness-1",
            expected_config_sha256="0" * 64,
            expected_environment_sha256="1" * 64,
            binding=changed,
            now=created + timedelta(minutes=1),
            registry=registry,
        )
