"""Derived runtime capabilities and operation grants for Phase 2."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from .schema_registry import (
    ContractSchemaRegistry,
    canonical_json_bytes,
    content_sha256,
    seal_contract,
)

ProcessRole = Literal["api", "answer_worker", "index_worker", "model_sidecar", "evaluation_harness"]
CapabilityStatus = Literal["PASS", "FAIL", "NOT_APPLICABLE"]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class CapabilityInput:
    name: str
    status: CapabilityStatus
    evidence_sha256: str | None
    reason_code: str
    checked_at: datetime
    valid_until: datetime | None

    def as_contract(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "evidence_sha256": self.evidence_sha256,
            "reason_code": self.reason_code,
            "checked_at": _utc(self.checked_at).isoformat(),
            "valid_until": (
                _utc(self.valid_until).isoformat() if self.valid_until is not None else None
            ),
        }


def build_runtime_capability_manifest(
    *,
    process_role: ProcessRole,
    process_instance_id: str,
    config_sha256: str,
    environment_sha256: str,
    capabilities: Sequence[CapabilityInput],
    operation_requirements: Mapping[str, Sequence[str]],
    bound_artifacts: Mapping[str, str],
    created_at: datetime,
    expires_at: datetime,
    registry: ContractSchemaRegistry,
) -> dict[str, Any]:
    """Derive every operation grant from PASS capabilities; never accept a grant flag."""

    created = _utc(created_at)
    expires = _utc(expires_at)
    if expires <= created:
        raise ValueError("runtime capability manifest expiry must follow creation")
    cap_values = tuple(capabilities)
    by_name = {item.name: item for item in cap_values}
    if len(by_name) != len(cap_values):
        raise ValueError("runtime capability names must be unique")
    grants = []
    for operation, requirements in sorted(operation_requirements.items()):
        required = list(dict.fromkeys(requirements))
        passing = True
        for name in required:
            item = by_name.get(name)
            if (
                item is None
                or item.status != "PASS"
                or item.evidence_sha256 is None
                or (item.valid_until is not None and _utc(item.valid_until) < expires)
            ):
                passing = False
                break
        grants.append(
            {
                "operation": operation,
                "granted": passing,
                "required_capabilities": required,
                "decision_reason_code": (
                    "all_required_capabilities_pass" if passing else "required_capability_failed"
                ),
            }
        )
    artifact_values = [
        {"name": name, "sha256": digest} for name, digest in sorted(bound_artifacts.items())
    ]
    identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "process_role": process_role,
                "process_instance_id": process_instance_id,
                "config_sha256": config_sha256,
                "environment_sha256": environment_sha256,
                "capabilities": [item.as_contract() for item in cap_values],
                "operation_grants": grants,
                "bound_artifacts": artifact_values,
                "created_at": created.isoformat(),
                "expires_at": expires.isoformat(),
            }
        )
    ).hexdigest()
    manifest = seal_contract(
        {
            "schema": "legalbot.runtime-capability-manifest.v1",
            "manifest_id": f"runtime-capability-{identity[:40]}",
            "process_role": process_role,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "config_sha256": config_sha256,
            "capabilities": [item.as_contract() for item in cap_values],
            "operation_grants": grants,
            "process_instance_id": process_instance_id,
            "environment_sha256": environment_sha256,
            "schema_selection_sha256": registry.manifest_sha256,
            "bound_artifacts": artifact_values,
        },
        digest_field="manifest_sha256",
    )
    registry.validate_new(manifest)
    if manifest["manifest_sha256"] != content_sha256(manifest, digest_field="manifest_sha256"):
        raise RuntimeError("runtime capability manifest seal differs")
    return manifest


def require_runtime_operation(
    manifest: Mapping[str, Any],
    *,
    operation: str,
    expected_manifest_sha256: str,
    expected_process_role: ProcessRole,
    expected_process_instance_id: str,
    expected_config_sha256: str,
    expected_environment_sha256: str,
    expected_bound_artifacts: Mapping[str, str],
    required_capabilities: Sequence[str],
    now: datetime,
    registry: ContractSchemaRegistry,
) -> str:
    """Recompute one grant against an externally pinned manifest digest."""

    registry.validate_new(manifest)
    observed = content_sha256(manifest, digest_field="manifest_sha256")
    if manifest.get("manifest_sha256") != observed or observed != expected_manifest_sha256:
        raise RuntimeError("runtime capability manifest authority differs")
    if manifest.get("schema_selection_sha256") != registry.manifest_sha256:
        raise RuntimeError("runtime capability schema selection differs")
    if (
        manifest.get("process_role") != expected_process_role
        or manifest.get("process_instance_id") != expected_process_instance_id
        or manifest.get("config_sha256") != expected_config_sha256
        or manifest.get("environment_sha256") != expected_environment_sha256
    ):
        raise RuntimeError("runtime process capability identity differs")
    current = _utc(now)
    if current < datetime.fromisoformat(
        str(manifest["created_at"])
    ) or current >= datetime.fromisoformat(str(manifest["expires_at"])):
        raise RuntimeError("runtime capability manifest is outside its validity window")
    artifacts = {str(item["name"]): str(item["sha256"]) for item in manifest["bound_artifacts"]}
    if artifacts != dict(expected_bound_artifacts):
        raise RuntimeError("runtime bound artifact identity differs")
    capabilities = {str(item["name"]): item for item in manifest["capabilities"]}
    required = list(dict.fromkeys(required_capabilities))
    for name in required:
        capability = capabilities.get(name)
        if (
            capability is None
            or capability["status"] != "PASS"
            or capability["evidence_sha256"] is None
            or (
                capability["valid_until"] is not None
                and current >= datetime.fromisoformat(str(capability["valid_until"]))
            )
        ):
            raise RuntimeError(f"runtime capability is not current: {name}")
    grants = [item for item in manifest["operation_grants"] if item["operation"] == operation]
    if len(grants) != 1:
        raise RuntimeError("runtime operation grant is not unique")
    grant = grants[0]
    if (
        grant["granted"] is not True
        or set(grant["required_capabilities"]) != set(required)
        or grant["decision_reason_code"] != "all_required_capabilities_pass"
    ):
        raise RuntimeError("runtime operation is not granted")
    return observed


__all__ = [
    "CapabilityInput",
    "CapabilityStatus",
    "ProcessRole",
    "build_runtime_capability_manifest",
    "require_runtime_operation",
]
