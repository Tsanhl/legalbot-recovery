from scripts.run_ge_direct_evidence_diagnostic import build_diagnostic


def test_direct_evidence_diagnostic_is_isolated_and_fail_closed() -> None:
    result = build_diagnostic()
    assert result["same_frozen_query_plan"] is True
    assert result["formal_end_to_end_score_included"] is False
    assert result["unseen_material_used"] is False
    assert result["normal_route"]["selected_evidence_ids"] == []
    assert result["normal_route"]["claim_gate"]["rejected"] is True
    assert result["direct_evidence_route"]["selected_evidence_ids"] == [
        "evidence-synthetic-notice-1"
    ]
    assert result["direct_evidence_route"]["claim_support_graph_valid"] is True
