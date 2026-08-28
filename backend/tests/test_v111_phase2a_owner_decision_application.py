from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.apply_v111_phase2a_owner_decisions import (
    _apply_category,
    _historical_recovery_assessment,
)


def _entry(*, source_sha256: str, outcome: str) -> dict[str, object]:
    return {
        "item_id": "effect-0001",
        "item_sha256": "a" * 64,
        "source_record_sha256": source_sha256,
        "owner_decision": {
            "owner_outcome": outcome,
            "owner_typed_name": "Agnes",
            "owner_decision_date": "2026-08-24",
            "decision_basis_sha256s": [source_sha256],
            "findings": {"effect_disposition": "NOT_YET_COMMENCED"},
        },
    }


def test_applies_exact_owner_decision_without_expanding_authority() -> None:
    record = {
        "record_sha256": "b" * 64,
        "disposition": "NOT_YET_COMMENCED",
        "owner_decision_required": False,
    }

    applied = _apply_category(
        category="legislative_effect",
        records=[record],
        entries=[
            _entry(
                source_sha256=record["record_sha256"],
                outcome="APPROVE_EFFECT_DISPOSITION",
            )
        ],
        receipt_sha256="c" * 64,
    )

    assert applied[0]["disposition"] == "NOT_YET_COMMENCED"
    assert applied[0]["owner_decision_required"] is False
    assert applied[0]["owner_review"]["status"] == ("OWNER_APPROVED_RECORDED_DISPOSITION")
    assert applied[0]["owner_review"]["does_not_admit_index_or_embed_source"] is True
    assert applied[0]["owner_review"]["does_not_authorize_phase2b_or_development30"] is True


def test_source_version_subset_must_be_explicitly_scoped() -> None:
    reviewed = {"sha256": "d" * 64}
    unreviewed = {"sha256": "e" * 64}
    entry = _entry(
        source_sha256=reviewed["sha256"],
        outcome="REQUEST_MORE_EVIDENCE",
    )

    with pytest.raises(
        ValueError,
        match="phase2a_decision_application_inventory_incomplete",
    ):
        _apply_category(
            category="source_version",
            records=[reviewed, unreviewed],
            entries=[entry],
            receipt_sha256="f" * 64,
        )

    applied = _apply_category(
        category="source_version",
        records=[reviewed, unreviewed],
        entries=[entry],
        receipt_sha256="f" * 64,
        require_complete_source_inventory=False,
    )
    assert len(applied) == 1
    assert applied[0]["owner_review"]["status"] == "OWNER_REQUESTED_MORE_EVIDENCE"


def test_historical_review_hash_mismatch_remains_non_authoritative(tmp_path: Path) -> None:
    historical = tmp_path / "historical-review.json"
    historical.write_text(
        json.dumps({"schema": "historical", "records": [{"row": 1}]}),
        encoding="utf-8",
    )

    assessment = _historical_recovery_assessment(historical)

    assert assessment["status"] == "HASH_MISMATCH_NOT_IMPORTED"
    assert assessment["imported"] is False
    assert assessment["authoritative"] is False
    assert assessment["may_qualify_issue"] is False
    assert assessment["file_name"] == historical.name
    assert str(tmp_path) not in json.dumps(assessment)
