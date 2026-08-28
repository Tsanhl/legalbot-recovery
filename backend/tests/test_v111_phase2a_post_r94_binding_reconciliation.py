from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from scripts import build_v111_phase2a_post_r94_binding_reconciliation as reconciliation


def _source_batches() -> tuple[Path, Path, Path]:
    return (
        reconciliation.DEFAULT_R83_BATCH,
        reconciliation.DEFAULT_R84_BATCH,
        reconciliation.DEFAULT_R85_BATCH,
    )


def test_reconciliation_preserves_gate_and_distinguishes_incomplete_bindings(
    tmp_path: Path,
) -> None:
    output = tmp_path / "r96"

    package = reconciliation.build_reconciliation(
        r95_root=reconciliation.DEFAULT_R95_ROOT,
        source_batch_paths=_source_batches(),
        r86_batch_path=reconciliation.DEFAULT_R86_BATCH,
        output_root=output,
    )

    assert package["target_date_evidence_ready_count"] == 3
    assert package["retained_binding_gap_count"] == 5
    assert package["remaining_research_row_count"] == 361
    assert package["technical_qualification_assigned"] is False
    assert package["phase2b_authorized"] is False
    assert package["development30_authorized"] is False
    assert package["automatic_indexing"] is False
    assert package["automatic_embedding"] is False
    assert package["candidate_mutated"] is False

    ready = json.loads((output / "TARGET-DATE-EVIDENCE-READY-ROWS-3.json").read_bytes())
    retained = json.loads(
        (output / "RETAINED-DIRECT-OR-PARTIAL-GAPS-5.json").read_bytes()
    )
    remaining = json.loads(
        (output / "REMAINING-PHASE2A-RESEARCH-ROWS-361.json").read_bytes()
    )
    assert {row["row_id"] for row in ready["records"]} == set(
        reconciliation.EXPECTED_TARGET_DATE_READY_ROWS
    )
    assert {row["row_id"] for row in retained["records"]} == set(
        reconciliation.EXPECTED_UKSC_CURRENTNESS_PENDING_ROWS
        | reconciliation.EXPECTED_PARTIAL_ROWS
    )
    assert len({row["row_id"] for row in remaining["records"]}) == 361
    assert not set(reconciliation.EXPECTED_TARGET_DATE_READY_ROWS) & {
        row["row_id"] for row in remaining["records"]
    }


def test_reconciliation_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "r96"
    kwargs = {
        "r95_root": reconciliation.DEFAULT_R95_ROOT,
        "source_batch_paths": _source_batches(),
        "r86_batch_path": reconciliation.DEFAULT_R86_BATCH,
        "output_root": output,
    }
    reconciliation.build_reconciliation(**kwargs)

    with pytest.raises(ValueError, match="phase2a_post_r94_output_already_exists"):
        reconciliation.build_reconciliation(**kwargs)


def test_reconciliation_rejects_tampered_r95_gap_artifact(tmp_path: Path) -> None:
    copied = tmp_path / "r95"
    shutil.copytree(reconciliation.DEFAULT_R95_ROOT, copied)
    gap_path = copied / "REMAINING-MATERIAL-GAPS-364.json"
    value = json.loads(gap_path.read_bytes())
    value["records"][0]["gap_reason"] = "tampered"
    gap_path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="phase2a_post_r94_file_inventory_invalid|phase2a_post_r94_gap_seal_invalid",
    ):
        reconciliation.build_reconciliation(
            r95_root=copied,
            source_batch_paths=_source_batches(),
            r86_batch_path=reconciliation.DEFAULT_R86_BATCH,
            output_root=tmp_path / "r96",
        )
