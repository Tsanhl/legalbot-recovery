#!/usr/bin/env python3
"""Build the non-authorizing advisory for the 45 locally full Phase-2A rows.

This artifact records which rows already have byte-verified local evidence and
which rows still need proposition-specific currentness or later-treatment
review.  It deliberately does not make an owner decision, clear a hold, admit
a source, mutate a candidate, run embedding, or authorize a later phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKING_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2A-2026-08-27-remediation-working-r1"
)
DEFAULT_LEDGER = WORKING_ROOT / "PROPOSITION-RECONCILIATION-WORKING-LEDGER-361.json"
DEFAULT_EVIDENCE_AUDIT = WORKING_ROOT / "PROPOSITION-EVIDENCE-BYTE-AUDIT-361.json"
DEFAULT_TARGET_DATE = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-26-r96-approved-binding-reconciliation"
    / "TARGET-DATE-EVIDENCE-READY-ROWS-3.json"
)
DEFAULT_TREATMENT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r58-additional-treatment-advisory"
    / "ADDITIONAL-LATER-TREATMENT-RELATIONSHIPS-ADVISORY-5.json"
)
DEFAULT_OUTPUT = WORKING_ROOT / "DIRECT-READY-OWNER-ADVISORY-45.json"

EXPECTED_LEDGER_CONTENT_SHA256 = "62d56c8b34d1fc964dca1a5920ee49b87499471c187dbe82aa58ebee191737ce"
EXPECTED_EVIDENCE_AUDIT_CONTENT_SHA256 = (
    "b0f87b5d4026ee371e1402e73ea3c9bfd5cc25ea8204770559f4864f7c6efd4c"
)
EXPECTED_TARGET_DATE_CONTENT_SHA256 = (
    "8c7bcebacb7a1c06cdcc9408a85fb97f48c0415f1c05265a97d49396f58b87f9"
)
EXPECTED_TREATMENT_CONTENT_SHA256 = (
    "e35406b3bfebadec733017ef6577cbafc2a3868e84f91d878520f8e208214f66"
)
EXPECTED_READY_FULL_ROWS = 45
EXPECTED_NO_HOLD_ROWS = 34
EXPECTED_HOLD_ROWS = 11
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sealed(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _load_sealed(path: Path, *, expected: str, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{code}_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{code}_must_be_object")
    supplied = str(value.get("artifact_content_sha256") or "")
    material = dict(value)
    material.pop("artifact_content_sha256", None)
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material) or supplied != expected:
        raise ValueError(f"{code}_seal_invalid")
    return value


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _procurement_dependency(target_date: Mapping[str, Any]) -> dict[str, Any]:
    matches = [
        record
        for record in target_date.get("records", [])
        if isinstance(record, Mapping) and record.get("row_id") == "live30-q21:issue-08"
    ]
    if len(matches) != 1:
        raise ValueError("phase2a_direct_ready_procurement_dependency_missing")
    bindings = matches[0].get("bindings")
    if not isinstance(bindings, list) or len(bindings) != 1:
        raise ValueError("phase2a_direct_ready_procurement_binding_invalid")
    binding = bindings[0]
    currentness = [
        span
        for span in binding.get("currentness_spans", [])
        if isinstance(span, Mapping)
        and span.get("claim_id") == "procurement-s104-in-force-for-operational-contract"
    ]
    material = [
        span
        for span in binding.get("material_claim_spans", [])
        if isinstance(span, Mapping)
        and span.get("claim_id") == "procurement-s104-2-set-aside-and-damages"
    ]
    if len(currentness) != 1 or len(material) != 1:
        raise ValueError("phase2a_direct_ready_procurement_spans_missing")
    return {
        "prior_owner_approved_row_id": "live30-q21:issue-08",
        "prior_binding_id": binding.get("binding_id"),
        "prior_owner_approval_bound_to_r94": binding.get("owner_approval_bound_to_r94"),
        "section_104_currentness_span": dict(currentness[0]),
        "section_104_damages_span": dict(material[0]),
        "advisory_relationship": (
            "SAME_SECTION_AND_NARROW_DAMAGES_PROPOSITION_REQUIRES_EXACT_ROW_CROSSWALK"
        ),
        "recommended_owner_currentness_outcome": (
            "CURRENT_AT_SOURCE_CEILING_SUBJECT_TO_PROCUREMENT_TRANSITIONAL_FACTS"
        ),
    }


def _manchester_dependencies(treatment: Mapping[str, Any]) -> list[dict[str, Any]]:
    matches = [
        record
        for record in treatment.get("records", [])
        if isinstance(record, Mapping) and record.get("target_neutral_citation") == "[2021] UKSC 20"
    ]
    relationships = {str(record.get("advisory_relationship")) for record in matches}
    expected = {
        "AFFIRMED_OR_APPLIED",
        "LIMITED_CHECKLIST_USE_OUTSIDE_SCOPE_OF_DUTY_CONTEXT",
    }
    if len(matches) != 2 or relationships != expected:
        raise ValueError("phase2a_direct_ready_manchester_dependencies_invalid")
    return [
        {
            "lead_id": record.get("lead_id"),
            "candidate_neutral_citation": record.get("candidate_neutral_citation"),
            "advisory_relationship": record.get("advisory_relationship"),
            "recommended_owner_outcome": record.get("recommended_owner_outcome"),
            "exact_treatment_spans": record.get("exact_treatment_spans"),
            "record_content_sha256": record.get("record_content_sha256"),
        }
        for record in sorted(matches, key=lambda item: str(item.get("lead_id")))
    ]


def build_direct_ready_advisory(
    *,
    ledger_path: Path,
    evidence_audit_path: Path,
    target_date_path: Path,
    treatment_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    """Create the bounded 45-row advisory artifact."""

    if output_path.exists() or output_path.is_symlink():
        raise ValueError("phase2a_direct_ready_output_already_exists")
    ledger = _load_sealed(
        ledger_path,
        expected=EXPECTED_LEDGER_CONTENT_SHA256,
        code="phase2a_direct_ready_ledger",
    )
    evidence_audit = _load_sealed(
        evidence_audit_path,
        expected=EXPECTED_EVIDENCE_AUDIT_CONTENT_SHA256,
        code="phase2a_direct_ready_evidence_audit",
    )
    target_date = _load_sealed(
        target_date_path,
        expected=EXPECTED_TARGET_DATE_CONTENT_SHA256,
        code="phase2a_direct_ready_target_date",
    )
    treatment = _load_sealed(
        treatment_path,
        expected=EXPECTED_TREATMENT_CONTENT_SHA256,
        code="phase2a_direct_ready_treatment",
    )
    if evidence_audit.get("status") != "PASS_NON_AUTHORIZING_BYTE_AUDIT":
        raise ValueError("phase2a_direct_ready_evidence_audit_not_passed")

    rows = [
        row
        for row in ledger.get("records", [])
        if isinstance(row, Mapping)
        and row.get("proposition_status") == "READY_FOR_EVIDENCE_REVIEW"
        and row.get("local_evidence_fit") == "FULL"
    ]
    if len(rows) != EXPECTED_READY_FULL_ROWS:
        raise ValueError("phase2a_direct_ready_row_count_invalid")

    procurement = _procurement_dependency(target_date)
    manchester = _manchester_dependencies(treatment)
    records: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda item: str(item.get("row_id"))):
        evidence = row.get("selected_local_evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError("phase2a_direct_ready_selected_evidence_missing")
        currentness_hold = any(item.get("currentness_verified") is not True for item in evidence)
        later_hold = any(item.get("later_treatment_review_required") is True for item in evidence)
        row_id = str(row.get("row_id"))
        dependencies: list[dict[str, Any]] = []
        advisory_status = "NO_ADDITIONAL_HOLD_IN_WORKING_LEDGER"
        recommendation: str | None = "ADOPT_EXACT_PROPOSITION_AND_BOUND_LOCAL_SPANS"
        if row_id == "live30-q21:issue-07":
            dependencies = [procurement]
            advisory_status = "EXACT_PRIOR_CURRENTNESS_CROSSWALK_AVAILABLE"
            recommendation = "ADOPT_WITH_EXACT_SECTION_104_ROW_CROSSWALK"
        elif row_id in {"live30-q05:issue-02", "live60-q36:issue-07"}:
            dependencies = manchester
            advisory_status = "TARGETED_LATER_TREATMENT_EVIDENCE_AVAILABLE"
            recommendation = (
                "AFFIRM_CORE_PURPOSE_OF_DUTY_PRINCIPLE_WITH_SIX_QUESTION_CHECKLIST_LIMIT"
            )
        elif currentness_hold or later_hold:
            advisory_status = "PENDING_TARGETED_CURRENTNESS_OR_LATER_TREATMENT_REVIEW"
            recommendation = None
        material = {
            "schema": "legalbot.v111.phase2a.direct-ready-owner-advisory-row.v1",
            "row_id": row_id,
            "source_proposition_record_content_sha256": row.get("record_content_sha256"),
            "canonical_atomic_proposition": row.get("canonical_atomic_proposition"),
            "selected_local_evidence": evidence,
            "currentness_hold_present": currentness_hold,
            "later_treatment_hold_present": later_hold,
            "supporting_advisory_dependencies": dependencies,
            "advisory_status": advisory_status,
            "recommended_owner_outcome": recommendation,
            "owner_outcome": None,
            "technical_qualification_assigned": False,
        }
        records.append({**material, "record_content_sha256": _sealed(material)})

    hold_rows = [
        row
        for row in records
        if row["currentness_hold_present"] or row["later_treatment_hold_present"]
    ]
    if (
        len(hold_rows) != EXPECTED_HOLD_ROWS
        or len(records) - len(hold_rows) != EXPECTED_NO_HOLD_ROWS
    ):
        raise ValueError("phase2a_direct_ready_hold_count_invalid")

    material = {
        "schema": "legalbot.v111.phase2a.direct-ready-owner-advisory.v1",
        "status": "ADVISORY_ONLY_NOT_OWNER_ADOPTED",
        "source_ceiling_date": "2026-08-14",
        "source_proposition_ledger_content_sha256": EXPECTED_LEDGER_CONTENT_SHA256,
        "source_evidence_audit_content_sha256": EXPECTED_EVIDENCE_AUDIT_CONTENT_SHA256,
        "source_target_date_artifact_content_sha256": EXPECTED_TARGET_DATE_CONTENT_SHA256,
        "source_treatment_artifact_content_sha256": EXPECTED_TREATMENT_CONTENT_SHA256,
        "record_count": len(records),
        "no_additional_hold_row_count": EXPECTED_NO_HOLD_ROWS,
        "hold_row_count": EXPECTED_HOLD_ROWS,
        "records": records,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "source_admitted": False,
        "candidate_mutated": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "technical_qualification_assigned": False,
        "active_pointer_write_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation30_authorized": False,
    }
    result = {**material, "artifact_content_sha256": _sealed(material)}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _write_exclusive(output_path, _pretty_json(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--evidence-audit", type=Path, default=DEFAULT_EVIDENCE_AUDIT)
    parser.add_argument("--target-date", type=Path, default=DEFAULT_TARGET_DATE)
    parser.add_argument("--treatment", type=Path, default=DEFAULT_TREATMENT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = build_direct_ready_advisory(
        ledger_path=args.ledger,
        evidence_audit_path=args.evidence_audit,
        target_date_path=args.target_date,
        treatment_path=args.treatment,
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "record_count": result["record_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
