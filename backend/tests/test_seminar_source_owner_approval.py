from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts import apply_seminar_source_owner_approval as approval


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    assert isinstance(value, dict)
    return value


def test_exact_seminar_source_approval_is_recorded_without_execution(
    tmp_path: Path,
) -> None:
    output = tmp_path / "approved"
    result = approval.apply_approval(
        source_root=approval.DEFAULT_SOURCE_ROOT,
        output_root=output,
        owner_statement=approval.OWNER_APPROVAL_STATEMENT,
        recorded_at=datetime(2026, 8, 27, 2, 0, tzinfo=UTC),
    )

    assert result["owner_approval_payload_content_sha256"] == (
        approval.EXPECTED_APPROVAL_PAYLOAD_SHA256
    )
    assert result["owner_decision_batch_content_sha256"] == (
        approval.EXPECTED_DECISION_BATCH_SHA256
    )
    assert result["source_authority_count"] == 142
    assert result["source_family_counts"] == {
        "legislation": 43,
        "official_judgment": 99,
    }
    assert result["source_admission_authorized"] is True
    assert result["one_consolidated_full_source_scan_authorized"] is True
    assert result["one_consolidated_successor_candidate_build_authorized"] is True
    assert result["embedding_in_consolidated_successor_authorized"] is True
    assert result["source_scan_started"] is False
    assert result["candidate_build_started"] is False
    assert result["successor_must_remain_non_active"] is True
    assert result["answer_release_eligible"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False

    receipt = _load(output / "OWNER-APPROVAL-RECEIPT.json")
    approval._verify_seal(
        receipt,
        "approval_receipt_content_sha256",
        "test_receipt_invalid",
    )
    package = _load(output / "PACKAGE-INDEX.json")
    approval._verify_seal(
        package,
        "package_index_content_sha256",
        "test_package_invalid",
    )
    assert package["file_count"] == 3
    assert not (output / "APPROVED-SOURCE-ADMISSIONS-142.json").exists()
    for line in (output / "SHA256SUMS.txt").read_text().splitlines():
        expected, name = line.split("  ", 1)
        assert approval._sha256_file(output / name) == expected


def test_seminar_source_approval_rejects_changed_statement(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="statement_not_exact"):
        approval.apply_approval(
            source_root=approval.DEFAULT_SOURCE_ROOT,
            output_root=tmp_path / "rejected",
            owner_statement=approval.OWNER_APPROVAL_STATEMENT.replace(
                "successor non-ACTIVE", "successor ACTIVE"
            ),
            recorded_at=datetime(2026, 8, 27, 2, 0, tzinfo=UTC),
        )


def test_seminar_source_approval_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="output_already_exists"):
        approval.apply_approval(
            source_root=approval.DEFAULT_SOURCE_ROOT,
            output_root=output,
            owner_statement=approval.OWNER_APPROVAL_STATEMENT,
            recorded_at=datetime(2026, 8, 27, 2, 0, tzinfo=UTC),
        )
