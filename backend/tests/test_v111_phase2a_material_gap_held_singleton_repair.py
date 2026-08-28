from __future__ import annotations

from pathlib import Path

from scripts import plan_v111_phase2a_material_gap_research as planner
from scripts import repair_v111_phase2a_material_gap_research_held_rows as repair


def test_r117_source_is_exact_and_crosswalks_all_held_rows() -> None:
    source = repair._load_source_state()
    crosswalk = repair._crosswalk(source)

    assert source.artifact["artifact_content_sha256"] == (repair.EXPECTED_R117_CONTENT_SHA256)
    assert len(source.accepted_plans) == repair.EXPECTED_REUSED_PLAN_COUNT
    assert len(source.held_row_ids) == repair.EXPECTED_HELD_ROW_COUNT
    assert len(source.crosswalk_records) == repair.EXPECTED_HELD_ROW_COUNT
    assert [record["row_id"] for record in source.crosswalk_records] == list(source.held_row_ids)
    assert all(record["source_attempt_count"] == 2 for record in source.crosswalk_records)
    planner._verify_seal(
        crosswalk,
        "artifact_content_sha256",
        "test_crosswalk_seal_invalid",
    )
    assert crosswalk["accepted_r117_rows_will_not_be_reinvoked"] is True
    assert crosswalk["phase2b_authorized"] is False


def test_merge_reuses_271_plans_and_fills_only_93_held_rows() -> None:
    source = repair._load_source_state()
    gap_rows, _ = planner._load_gap_rows(planner.DEFAULT_TRIAGE)
    synthetic_repairs = [{"row_id": row_id} for row_id in source.held_row_ids]

    merged = repair._merge_plans(
        gap_rows=gap_rows,
        source_plans=source.accepted_plans,
        repair_plans=synthetic_repairs,
    )

    assert len(merged) == planner.EXPECTED_GAP_COUNT
    assert [row["row_id"] for row in merged] == [row["row_id"] for row in gap_rows]
    assert {row["row_id"] for row in merged if set(row) == {"row_id"}} == set(source.held_row_ids)


def _invented_authority_invoke(envelope: dict[str, object]) -> dict[str, object]:
    payload = envelope["payload"]
    assert isinstance(payload, dict)
    rows = payload["rows"]
    assert isinstance(rows, list)
    return {
        "request_id": envelope["request_id"],
        "model_version": planner.EXPECTED_MODEL_VERSION,
        "backend": planner.MODEL_BACKEND,
        "deterministic": True,
        "finish_reason": "stop",
        "warnings": [],
        "peak_memory_gb": 1.0,
        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        "structured": {
            "schema": planner.OUTPUT_SCHEMA,
            "case_id": payload["case_id"],
            "rows": [
                {
                    "row_id": row["row_id"],
                    "classification": row["advisory_classification_hint"],
                    "proposition": f"{row['issue_label']} requires an identified legal rule.",
                    "selections": [{"id": "ukpga:9999:1", "locator": "section 1"}],
                    "search_query": "",
                }
                for row in rows
            ],
        },
        "raw_text": "not persisted",
    }


def test_invented_authority_fallback_is_limited_to_singletons(tmp_path: Path) -> None:
    case = {
        "case_id": "live30-q01",
        "subject": "contract",
        "question": "Synthetic immutable scenario",
    }
    rows = [
        {
            "row_id": "live30-q01:issue-01",
            "issue_label": "breach",
            "legal_domain": "contract",
            "triage_class": "UNRESOLVED_SOURCE_PLAN_GAP",
        },
        {
            "row_id": "live30-q01:issue-03",
            "issue_label": "termination",
            "legal_domain": "contract",
            "triage_class": "UNRESOLVED_SOURCE_PLAN_GAP",
        },
    ]

    singleton_root = tmp_path / "singleton"
    singleton_checkpoints = singleton_root / "checkpoints"
    singleton_diagnostics = singleton_root / "diagnostics"
    singleton_checkpoints.mkdir(parents=True)
    singleton_diagnostics.mkdir()
    singleton = planner._review_batch(
        ordinal=1,
        batch=rows[:1],
        case=case,
        sources=[],
        candidate_authorities=frozenset(),
        invoke=_invented_authority_invoke,
        checkpoints_root=singleton_checkpoints,
        diagnostics_root=singleton_diagnostics,
    )
    assert singleton["schema"] == "legalbot.v111.phase2a.gap-plan-checkpoint.v1"
    assert singleton["attempt_count"] == 2
    assert singleton["plans"][0]["selections"] == []
    assert singleton["model_metrics"]["deterministic_validation_repair_count"] == 1

    multi_root = tmp_path / "multi"
    multi_checkpoints = multi_root / "checkpoints"
    multi_diagnostics = multi_root / "diagnostics"
    multi_checkpoints.mkdir(parents=True)
    multi_diagnostics.mkdir()
    multi = planner._review_batch(
        ordinal=1,
        batch=rows,
        case=case,
        sources=[],
        candidate_authorities=frozenset(),
        invoke=_invented_authority_invoke,
        checkpoints_root=multi_checkpoints,
        diagnostics_root=multi_diagnostics,
    )
    assert multi["schema"] == "legalbot.v111.phase2a.gap-plan-held-batch.v1"
    assert multi["attempt_count"] == 2
    assert multi["debug_required_before_third_attempt"] is True
