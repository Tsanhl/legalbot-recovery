from __future__ import annotations

import json
from pathlib import Path

from scripts import build_v111_phase2a_legislation_byte_mismatch_reconciliation as reconciliation


def test_compare_provisions_distinguishes_representation_and_text_changes() -> None:
    old = {
        "https://example.test/section/1": {
            "locator": "section 1",
            "text": "section 1 Same text",
            "text_sha256": "a" * 64,
        }
    }
    identical = reconciliation._compare_provisions(old, dict(old))
    added = reconciliation._compare_provisions(
        old,
        {
            **old,
            "https://example.test/section/2": {
                "locator": "section 2",
                "text": "section 2 New text",
                "text_sha256": "b" * 64,
            },
        },
    )
    changed = reconciliation._compare_provisions(
        old,
        {
            "https://example.test/section/1": {
                "locator": "section 1",
                "text": "section 1 Changed text",
                "text_sha256": "c" * 64,
            }
        },
    )

    assert identical["classification"] == ("SEMANTIC_PROVISION_TEXT_IDENTICAL_BYTE_MISMATCH_ONLY")
    assert added["classification"] == ("FRESH_OFFICIAL_VERSION_HAS_ADDITIONAL_PROVISION_BLOCKS")
    assert changed["classification"] == (
        "FRESH_OFFICIAL_VERSION_HAS_CHANGED_OR_REMOVED_PROVISION_BLOCKS"
    )


def test_point_in_time_anchor_date_is_not_a_semantic_change() -> None:
    assert (
        reconciliation._canonical_anchor(
            "https://www.legislation.gov.uk/ukpga/2025/1/section/2/2026-08-14"
        )
        == "https://www.legislation.gov.uk/ukpga/2025/1/section/2"
    )


def test_representation_selector_is_not_a_provision_identity_change() -> None:
    assert (
        reconciliation._canonical_anchor(
            "https://www.legislation.gov.uk/uksi/2018/597/regulation/4/1/a/made"
        )
        == "https://www.legislation.gov.uk/uksi/2018/597/regulation/4/1/a"
    )


def test_all_65_mismatches_are_reconciled_without_authorization(tmp_path: Path) -> None:
    result = reconciliation.build_reconciliation(
        candidate_manifest_path=reconciliation.DEFAULT_CANDIDATE_MANIFEST,
        quarantine_root=reconciliation.DEFAULT_QUARANTINE_ROOT,
        output_root=tmp_path / "reconciliation",
    )
    artifact = json.loads(
        (tmp_path / "reconciliation/LEGISLATION-BYTE-MISMATCH-RECONCILIATION-65.json").read_bytes()
    )

    assert result["summary"]["record_count"] == 65
    assert sum(result["summary"]["classification_counts"].values()) == 65
    assert len(artifact["records"]) == 65
    assert artifact["owner_decisions_applied"] is False
    assert artifact["source_admission_authorized"] is False
    assert artifact["automatic_indexing"] is False
    assert artifact["automatic_embedding"] is False
    assert artifact["candidate_mutated"] is False
    assert artifact["technical_qualification_assigned"] is False
    assert artifact["phase2b_authorized"] is False
    assert artifact["development30_authorized"] is False
