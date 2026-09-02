"""Fail-closed admission for the exact visible General Enquiry evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..contracts import ContractSchemaRegistry, require_runtime_operation

VISIBLE_GE_OPERATION = "execute_visible_ge_evaluation"
VISIBLE_GE_REQUIRED_CAPABILITIES: tuple[str, ...] = (
    "non_active_candidate_qualified",
    "answer_model_transport_verified",
    "visible_gold_currentness_approved",
    "development_private_root_verified",
    "evaluation_execution_authority_verified",
    "resource_envelope_verified",
    "unseen_custody_verified",
    "system_suite_verified",
    "ge_iteration_plan_verified",
    "visible_diagnostic_custody_verified",
    "ge_evaluation_index_verified",
)


@dataclass(frozen=True, slots=True)
class VisibleGEExecutionBinding:
    candidate_sha256: str
    model_sha256: str
    prompt_sha256: str
    renderer_sha256: str
    validator_bundle_sha256: str
    case_manifest_sha256: str
    case_order_sha256: str
    system_manifest_sha256: str
    system_order_sha256: str
    input_projection_sha256: str
    factual_gate_policy_sha256: str
    quality_gate_policy_sha256: str
    gold_currentness_decision_sha256: str
    development_private_root_capability_sha256: str
    evaluation_authority_sha256: str
    resource_policy_sha256: str
    unseen_custody_ledger_sha256: str
    iteration_plan_sha256: str
    diagnostic_pack_sha256: str
    predecessor_visible_run_sha256: str | None = None
    repair_manifest_sha256: str | None = None
    ge_held_index_seal_sha256: str | None = None
    ge_source_manifest_sha256: str | None = None
    ge_source_scope_sha256: str | None = None
    ge_index_build_authorization_sha256: str | None = None
    ge_index_build_owner_decision_id_sha256: str | None = None
    ge_source_intake_chain_sha256: str | None = None

    def bound_artifacts(self) -> dict[str, str]:
        artifacts = {
            "candidate": self.candidate_sha256,
            "model": self.model_sha256,
            "prompt": self.prompt_sha256,
            "renderer": self.renderer_sha256,
            "validator_bundle": self.validator_bundle_sha256,
            "visible_case_manifest": self.case_manifest_sha256,
            "visible_case_order": self.case_order_sha256,
            "visible_system_manifest": self.system_manifest_sha256,
            "visible_system_order": self.system_order_sha256,
            "visible_input_projection": self.input_projection_sha256,
            "factual_gate_policy": self.factual_gate_policy_sha256,
            "quality_gate_policy": self.quality_gate_policy_sha256,
            "gold_currentness_decision": self.gold_currentness_decision_sha256,
            "development_private_root_capability": (
                self.development_private_root_capability_sha256
            ),
            "evaluation_authority": self.evaluation_authority_sha256,
            "resource_policy": self.resource_policy_sha256,
            "unseen_custody_ledger": self.unseen_custody_ledger_sha256,
            "ge_iteration_plan": self.iteration_plan_sha256,
            "visible_diagnostic_pack": self.diagnostic_pack_sha256,
        }
        if self.predecessor_visible_run_sha256 is not None:
            artifacts["predecessor_visible_run"] = self.predecessor_visible_run_sha256
        if self.repair_manifest_sha256 is not None:
            artifacts["repair_manifest"] = self.repair_manifest_sha256
        ge_index_artifacts = {
            "ge_held_index_seal": self.ge_held_index_seal_sha256,
            "ge_source_manifest": self.ge_source_manifest_sha256,
            "ge_source_scope": self.ge_source_scope_sha256,
            "ge_index_build_authorization": self.ge_index_build_authorization_sha256,
            "ge_index_build_owner_decision_id": (
                self.ge_index_build_owner_decision_id_sha256
            ),
            "ge_source_intake_chain": self.ge_source_intake_chain_sha256,
        }
        supplied = [value is not None for value in ge_index_artifacts.values()]
        if any(supplied) and not all(supplied):
            raise ValueError("GE evaluation index artifacts must be bound as one exact set")
        if all(supplied):
            artifacts.update({key: str(value) for key, value in ge_index_artifacts.items()})
        return artifacts


def require_visible_ge_evaluation_capability(
    manifest: Mapping[str, Any],
    *,
    expected_manifest_sha256: str,
    expected_process_instance_id: str,
    expected_config_sha256: str,
    expected_environment_sha256: str,
    binding: VisibleGEExecutionBinding,
    now: datetime,
    registry: ContractSchemaRegistry,
) -> str:
    """Require the exact externally pinned gate; never derive owner authority here."""

    return require_runtime_operation(
        manifest,
        operation=VISIBLE_GE_OPERATION,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_process_role="evaluation_harness",
        expected_process_instance_id=expected_process_instance_id,
        expected_config_sha256=expected_config_sha256,
        expected_environment_sha256=expected_environment_sha256,
        expected_bound_artifacts=binding.bound_artifacts(),
        required_capabilities=VISIBLE_GE_REQUIRED_CAPABILITIES,
        now=now,
        registry=registry,
    )


__all__ = [
    "VISIBLE_GE_OPERATION",
    "VISIBLE_GE_REQUIRED_CAPABILITIES",
    "VisibleGEExecutionBinding",
    "require_visible_ge_evaluation_capability",
]
