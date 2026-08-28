from __future__ import annotations

from pathlib import Path

from scripts import build_v111_phase2a_patents_s60_7_advisory as patents


def test_patents_delta_is_exact_and_non_authorizing(tmp_path: Path) -> None:
    result = patents.build_patents_delta_packet(
        register_path=patents.DEFAULT_REGISTER,
        candidate_manifest_path=patents.DEFAULT_CANDIDATE_MANIFEST,
        quarantine_root=patents.DEFAULT_QUARANTINE_ROOT,
        output_root=tmp_path / "packet",
    )

    assert result["removed_text"] == "section 53 of the Civil Aviation Act 1949 "
    assert result["exact_differences"] == [
        {
            "operation": "DELETE",
            "old_start_character": 488,
            "old_end_character_exclusive": 530,
            "fresh_start_character": 488,
            "fresh_end_character_exclusive": 488,
            "old_text": "section 53 of the Civil Aviation Act 1949 ",
            "fresh_text": "",
        }
    ]
    assert result["changed_locator_pending_issue_row_ids"] == []
    assert result["authority_general_pending_issue_row_count"] == 17
    assert result["owner_outcome"] is None
    assert result["source_admitted"] is False
    assert result["candidate_mutated"] is False
    assert result["phase2b_authorized"] is False
    assert result["development30_authorized"] is False


def test_patents_packet_is_create_only(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    try:
        patents.build_patents_delta_packet(
            register_path=patents.DEFAULT_REGISTER,
            candidate_manifest_path=patents.DEFAULT_CANDIDATE_MANIFEST,
            quarantine_root=patents.DEFAULT_QUARANTINE_ROOT,
            output_root=output,
        )
    except ValueError as exc:
        assert str(exc) == "phase2a_patents_output_already_exists"
    else:
        raise AssertionError("existing output was overwritten")
