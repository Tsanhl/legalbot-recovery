from __future__ import annotations

import json
from pathlib import Path

from scripts import finalize_v111_phase2a_r107_held_source_links as resolution


def test_resolves_only_two_overlength_holds_without_model_or_gate_change(
    tmp_path: Path,
) -> None:
    artifact = resolution.build_resolution(tmp_path / "r108")

    assert artifact["row_source_link_count"] == 26
    assert artifact["held_row_resolution_count"] == 2
    assert artifact["remaining_held_row_count"] == 0
    assert artifact["assessment_counts"] == {"PARTIAL": 1, "UNRELATED": 25}
    by_row = {item["row_id"]: item for item in artifact["findings"]}
    delivery = by_row["live60-q33:issue-02"]
    trespasser = by_row["live60-q33:issue-03"]
    assert delivery["assessment"] == "PARTIAL"
    assert delivery["exact_span_binding"]["locator"] == "section 1 2"
    assert delivery["model_invoked_for_resolution"] is False
    assert trespasser["assessment"] == "UNRELATED"
    assert trespasser["exact_span_binding"] is None
    assert trespasser["model_invoked_for_resolution"] is False
    assert artifact["source_admission_authorized"] is False
    assert artifact["automatic_indexing"] is False
    assert artifact["phase2b_authorized"] is False
    assert artifact["development30_authorized"] is False
    persisted = json.loads(
        (tmp_path / "r108" / resolution.OUTPUT_NAME).read_bytes()
    )
    assert persisted == artifact
