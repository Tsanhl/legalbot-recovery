from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import apply_v111_phase2a_safe_subset_580 as safe_subset


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def test_exact_safe_subset_records_580_and_carries_478_forward(tmp_path: Path) -> None:
    source_batch = safe_subset.DEFAULT_SOURCE_ROOT / "OWNER-DECISION-BATCH-1058.json"
    source_before = safe_subset._sha256_file(source_batch)
    output = tmp_path / "approved"

    result = safe_subset.apply_safe_subset(
        source_root=safe_subset.DEFAULT_SOURCE_ROOT,
        output_root=output,
        owner_reply=safe_subset.EXPECTED_OWNER_REPLY,
        owner_decision_date="2026-08-25",
        recorded_at=datetime(2026, 8, 25, 1, 2, 3, tzinfo=UTC),
    )

    assert result["approved_decision_count"] == 580
    assert result["remaining_substantive_decision_count"] == 478
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False
    assert safe_subset._sha256_file(source_batch) == source_before

    effects = _load(output / "APPROVED-LEGISLATIVE-EFFECT-DECISIONS-516.json")
    mismatches = _load(output / "APPROVED-BYTE-MISMATCH-DECISIONS-64.json")
    remaining = _load(output / "REMAINING-SUBSTANTIVE-OWNER-DECISIONS-478.json")
    inventory = _load(output / "POST-580-PHASE2A-INVENTORY.json")
    assert effects["record_count"] == 516
    assert mismatches["record_count"] == 64
    assert remaining["item_count"] == 478
    assert remaining["category_counts"] == safe_subset.EXPECTED_REMAINING_COUNTS
    assert inventory["recorded_legislative_effect_count"] == 1896
    assert inventory["pending_legislative_effect_count"] == 0
    assert inventory["recorded_byte_mismatch_count"] == 64
    assert inventory["pending_byte_mismatch_count"] == 1
    assert inventory["phase2b_authorized"] is False
    assert inventory["development30_authorized"] is False

    effect_rows = effects["records"]
    mismatch_rows = mismatches["records"]
    assert isinstance(effect_rows, list)
    assert isinstance(mismatch_rows, list)
    assert {row["owner_outcome"] for row in effect_rows if isinstance(row, dict)} == {
        "APPROVE_METADATA_OR_CURRENTNESS_ONLY_DISPOSITION"
    }
    assert {row["owner_outcome"] for row in mismatch_rows if isinstance(row, dict)} == {
        "APPROVE_NONMATERIAL_REPRESENTATION_BYTE_MISMATCH"
    }
    remaining_rows = remaining["items"]
    assert isinstance(remaining_rows, list)
    assert Counter(
        str(row["category"]) for row in remaining_rows if isinstance(row, dict)
    ) == Counter(safe_subset.EXPECTED_REMAINING_COUNTS)

    for name in (
        "OWNER-APPROVAL-RECEIPT-580.json",
        "APPROVED-LEGISLATIVE-EFFECT-DECISIONS-516.json",
        "APPROVED-BYTE-MISMATCH-DECISIONS-64.json",
        "REMAINING-SUBSTANTIVE-OWNER-DECISIONS-478.json",
        "POST-580-PHASE2A-INVENTORY.json",
    ):
        value = _load(output / name)
        assert safe_subset._verify_seal(value, "artifact_content_sha256", "invalid")


def test_safe_subset_rejects_nonexact_owner_reply_without_output(tmp_path: Path) -> None:
    output = tmp_path / "rejected"
    with pytest.raises(ValueError, match="owner_reply_not_exact"):
        safe_subset.apply_safe_subset(
            source_root=safe_subset.DEFAULT_SOURCE_ROOT,
            output_root=output,
            owner_reply="OK",
            owner_decision_date="2026-08-25",
            recorded_at=datetime(2026, 8, 25, tzinfo=UTC),
        )
    assert not output.exists()


def test_safe_subset_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        safe_subset.apply_safe_subset(
            source_root=safe_subset.DEFAULT_SOURCE_ROOT,
            output_root=output,
            owner_reply=safe_subset.EXPECTED_OWNER_REPLY,
            owner_decision_date="2026-08-25",
            recorded_at=datetime(2026, 8, 25, tzinfo=UTC),
        )
