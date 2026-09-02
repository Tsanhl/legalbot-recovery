from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.contracts import (
    ContractSchemaRegistry,
    ValidationCheckInput,
    build_validation_report,
)


def _check(*, result: str, material: bool) -> ValidationCheckInput:
    return ValidationCheckInput(  # type: ignore[arg-type]
        check_id="check-evidence-support",
        kind="evidence_support",
        result=result,
        material=material,
        reason_code="evidence.support",
        affected_ids=("claim-1",),
        validator_sha256="1" * 64,
        input_sha256="2" * 64,
        output_sha256="3" * 64,
    )


def _build(*, result: str, material: bool):
    registry = ContractSchemaRegistry.from_project_root(Path.cwd())
    report = build_validation_report(
        draft_id="draft-validation-1",
        draft_sha256="4" * 64,
        validator_bundle_sha256="5" * 64,
        checks=(_check(result=result, material=material),),
        advisory_status="NOT_RUN",
        advisory_report_sha256=None,
        repair_parent_id=None,
        requested_disposition="verified_full",
        claim_set_sha256="6" * 64,
        evidence_pack_sha256="7" * 64,
        fact_snapshot_sha256="8" * 64,
        policy_sha256="9" * 64,
        created_at=datetime(2026, 9, 1, tzinfo=UTC),
        registry=registry,
    )
    registry.validate_new(report.value)
    return report


def test_material_failure_forces_hold() -> None:
    assert _build(result="FAIL", material=True).value["final_disposition"] == "held"


def test_nonmaterial_failure_cannot_change_verified_disposition() -> None:
    report = _build(result="FAIL", material=False)
    assert report.value["final_disposition"] == "verified_full"
    assert len(report.content_sha256) == 64
