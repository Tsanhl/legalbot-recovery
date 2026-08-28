from __future__ import annotations

from pathlib import Path

from scripts import build_v111_phase2a_direct_ready_advisory as advisory


def _build(tmp_path: Path) -> dict:
    return advisory.build_direct_ready_advisory(
        ledger_path=advisory.DEFAULT_LEDGER,
        evidence_audit_path=advisory.DEFAULT_EVIDENCE_AUDIT,
        target_date_path=advisory.DEFAULT_TARGET_DATE,
        treatment_path=advisory.DEFAULT_TREATMENT,
        output_path=tmp_path / "DIRECT-READY-OWNER-ADVISORY-45.json",
    )


def test_direct_ready_advisory_is_complete_and_non_authorizing(tmp_path: Path) -> None:
    result = _build(tmp_path)

    assert result["record_count"] == 45
    assert result["no_additional_hold_row_count"] == 34
    assert result["hold_row_count"] == 11
    assert result["owner_decisions_applied"] is False
    assert result["source_admitted"] is False
    assert result["candidate_mutated"] is False
    assert result["automatic_embedding"] is False
    assert result["active_pointer_write_authorized"] is False
    assert result["phase2b_authorized"] is False
    assert all(row["owner_outcome"] is None for row in result["records"])


def test_direct_ready_advisory_reuses_exact_approved_dependencies(tmp_path: Path) -> None:
    result = _build(tmp_path)
    by_id = {row["row_id"]: row for row in result["records"]}

    procurement = by_id["live30-q21:issue-07"]
    assert procurement["advisory_status"] == "EXACT_PRIOR_CURRENTNESS_CROSSWALK_AVAILABLE"
    dependency = procurement["supporting_advisory_dependencies"][0]
    assert dependency["section_104_currentness_span"]["claim_id"] == (
        "procurement-s104-in-force-for-operational-contract"
    )
    assert dependency["section_104_damages_span"]["claim_id"] == (
        "procurement-s104-2-set-aside-and-damages"
    )

    for row_id in ("live30-q05:issue-02", "live60-q36:issue-07"):
        manchester = by_id[row_id]
        assert manchester["advisory_status"] == (
            "TARGETED_LATER_TREATMENT_EVIDENCE_AVAILABLE"
        )
        assert {item["advisory_relationship"] for item in manchester["supporting_advisory_dependencies"]} == {
            "AFFIRMED_OR_APPLIED",
            "LIMITED_CHECKLIST_USE_OUTSIDE_SCOPE_OF_DUTY_CONTEXT",
        }


def test_direct_ready_advisory_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "DIRECT-READY-OWNER-ADVISORY-45.json"
    output.write_text("occupied", encoding="utf-8")
    try:
        advisory.build_direct_ready_advisory(
            ledger_path=advisory.DEFAULT_LEDGER,
            evidence_audit_path=advisory.DEFAULT_EVIDENCE_AUDIT,
            target_date_path=advisory.DEFAULT_TARGET_DATE,
            treatment_path=advisory.DEFAULT_TREATMENT,
            output_path=output,
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_direct_ready_output_already_exists"
    else:
        raise AssertionError("existing output was overwritten")
