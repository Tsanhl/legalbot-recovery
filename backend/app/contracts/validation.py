"""Deterministic factual and quality validation report construction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from .schema_registry import ContractSchemaRegistry, canonical_json_bytes

ValidationKind = Literal[
    "identity",
    "fact_provenance",
    "evidence_support",
    "currentness",
    "quotation",
    "citation",
    "date_amount",
    "contradiction",
    "privacy",
    "output_shape",
]
ValidationResult = Literal["PASS", "FAIL", "NOT_APPLICABLE"]
ReleaseDisposition = Literal[
    "verified_full", "verified_concise", "verified_limited", "held", "system_error"
]


@dataclass(frozen=True, slots=True)
class ValidationCheckInput:
    check_id: str
    kind: ValidationKind
    result: ValidationResult
    material: bool
    reason_code: str
    affected_ids: tuple[str, ...]
    validator_sha256: str
    input_sha256: str
    output_sha256: str | None = None

    def as_contract(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "kind": self.kind,
            "result": self.result,
            "material": self.material,
            "reason_code": self.reason_code,
            "affected_ids": list(self.affected_ids),
            "validator_sha256": self.validator_sha256,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
        }


@dataclass(frozen=True, slots=True)
class FrozenValidationReport:
    value: dict[str, Any]
    content_sha256: str


def build_validation_report(
    *,
    draft_id: str,
    draft_sha256: str,
    validator_bundle_sha256: str,
    checks: tuple[ValidationCheckInput, ...],
    advisory_status: Literal["PASS", "FAIL", "UNCERTAIN", "NOT_RUN"],
    advisory_report_sha256: str | None,
    repair_parent_id: str | None,
    requested_disposition: ReleaseDisposition,
    claim_set_sha256: str,
    evidence_pack_sha256: str,
    fact_snapshot_sha256: str | None,
    policy_sha256: str,
    created_at: datetime,
    registry: ContractSchemaRegistry,
) -> FrozenValidationReport:
    """Freeze all check outputs; a material failure always forces a hold."""

    if not checks:
        raise ValueError("validation report requires at least one check")
    check_ids = [check.check_id for check in checks]
    if len(check_ids) != len(set(check_ids)):
        raise ValueError("validation check IDs must be unique")
    has_material_failure = any(check.material and check.result == "FAIL" for check in checks)
    final_disposition: ReleaseDisposition = (
        "held" if has_material_failure else requested_disposition
    )
    stamp = created_at
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=UTC)
    stamp_text = stamp.astimezone(UTC).isoformat()
    material = {
        "schema": "legalbot.validation-report-identity.v1",
        "draft_id": draft_id,
        "draft_sha256": draft_sha256,
        "validator_bundle_sha256": validator_bundle_sha256,
        "checks": [check.as_contract() for check in checks],
        "claim_set_sha256": claim_set_sha256,
        "evidence_pack_sha256": evidence_pack_sha256,
        "fact_snapshot_sha256": fact_snapshot_sha256,
        "policy_sha256": policy_sha256,
        "created_at": stamp_text,
    }
    identity = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    value = {
        "schema": "legalbot.validation-report.v1",
        "validation_report_id": f"validation-report-{identity[:40]}",
        "draft_id": draft_id,
        "draft_sha256": draft_sha256,
        "validator_bundle_sha256": validator_bundle_sha256,
        "checks": [check.as_contract() for check in checks],
        "advisory_review": {
            "status": advisory_status,
            "report_sha256": advisory_report_sha256,
        },
        "repair_parent_id": repair_parent_id,
        "final_disposition": final_disposition,
        "created_at": stamp_text,
        "claim_set_sha256": claim_set_sha256,
        "evidence_pack_sha256": evidence_pack_sha256,
        "fact_snapshot_sha256": fact_snapshot_sha256,
        "policy_sha256": policy_sha256,
    }
    registry.validate_new(value)
    return FrozenValidationReport(
        value=value,
        content_sha256=hashlib.sha256(canonical_json_bytes(value)).hexdigest(),
    )


__all__ = [
    "FrozenValidationReport",
    "ReleaseDisposition",
    "ValidationCheckInput",
    "ValidationKind",
    "ValidationResult",
    "build_validation_report",
]
