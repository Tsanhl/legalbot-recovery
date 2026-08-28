from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scripts.apply_v111_phase2a_materiality_approval import (
    EXPECTED_BATCH_DIGEST,
    EXPECTED_OWNER_REPLY,
    _pretty_json,
    _sealed,
    apply_approval,
)

ROOT = Path(__file__).resolve().parents[2]
BATCH = (
    ROOT
    / "data"
    / "evaluations"
    / "phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-24-r27"
    / "OWNER-MATERIALITY-DECISION-BATCH-54.json"
)


def test_exact_owner_reply_records_54_scopes_without_advancing_gates(tmp_path: Path) -> None:
    result = apply_approval(
        batch_path=BATCH,
        output_root=tmp_path / "output",
        owner_reply=EXPECTED_OWNER_REPLY,
        recorded_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
    )

    assert result["approved_row_count"] == 54
    assert result["approved_source_admission_authority_count"] == 16
    assert result["recorded_owner_decision_count"] == 137
    assert result["remaining_owner_decision_issue_count"] == 448
    assert result["candidate_build_deferred"] is True
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False

    output = tmp_path / "output"
    receipt = json.loads((output / "OWNER-APPROVAL-RECEIPT-54.json").read_bytes())
    source_scope = json.loads(
        (output / "OWNER-APPROVED-SOURCE-ADMISSION-SCOPE-16.json").read_bytes()
    )
    approved = json.loads((output / "OWNER-DECISIONS-APPROVED-54.json").read_bytes())
    assert receipt["source_batch_content_sha256"] == EXPECTED_BATCH_DIGEST
    assert receipt["automatic_indexing_or_embedding_authorized"] is False
    assert source_scope["authority_count"] == 16
    assert source_scope["row_count"] == 29
    assert approved["row_count"] == 54
    assert all(row["indexing_authorized"] is False for row in approved["rows"])
    assert all(row["embedding_authorized"] is False for row in approved["rows"])


def test_owner_reply_must_bind_the_exact_batch_digest(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError,
        match="phase2a_materiality_approval_owner_reply_not_exact",
    ):
        apply_approval(
            batch_path=BATCH,
            output_root=tmp_path / "output",
            owner_reply="OK",
            recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
        )


def test_resealed_batch_cannot_expand_indexing_authority(tmp_path: Path) -> None:
    batch = json.loads(BATCH.read_bytes())
    batch.pop("artifact_content_sha256")
    batch["automatic_indexing"] = True
    batch["artifact_content_sha256"] = _sealed(batch)
    tampered = tmp_path / "tampered.json"
    tampered.write_bytes(_pretty_json(batch))

    with pytest.raises(ValueError, match="phase2a_materiality_approval_batch_boundary_invalid"):
        apply_approval(
            batch_path=tampered,
            output_root=tmp_path / "output",
            owner_reply=EXPECTED_OWNER_REPLY,
            recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
        )


def test_row_tamper_fails_before_any_scope_is_applied(tmp_path: Path) -> None:
    batch = json.loads(BATCH.read_bytes())
    batch["rows"][0]["indexing_authorized"] = True
    batch.pop("artifact_content_sha256")
    batch["artifact_content_sha256"] = _sealed(batch)
    tampered = tmp_path / "tampered-row.json"
    tampered.write_bytes(_pretty_json(batch))

    with pytest.raises(ValueError, match="phase2a_materiality_approval_batch_boundary_invalid"):
        apply_approval(
            batch_path=tampered,
            output_root=tmp_path / "output",
            owner_reply=EXPECTED_OWNER_REPLY,
            recorded_at=datetime(2026, 8, 24, tzinfo=UTC),
        )
