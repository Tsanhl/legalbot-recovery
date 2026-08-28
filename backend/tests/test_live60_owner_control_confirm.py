from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from shutil import copyfile
from typing import Any

import pytest

from app.cli import parser
from app.evaluation.live_suite_contrary_authority import contrary_review_template
from app.evaluation.live_suite_full_run_status import build_full_run_remaining_status
from app.evaluation.live_suite_owner_control_confirm import (
    OWNER_CONTROL_CONFIRMATION_TOKEN,
    REQUIRED_DECISION_STATES,
    confirm_owner_control_records,
)
from app.evaluation.live_suite_owner_decision_contract import owner_decision_template

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AS_OF_DATE = date(2026, 8, 16)


def _filled_decisions() -> dict[str, Any]:
    template = owner_decision_template(as_of_date=AS_OF_DATE.isoformat())
    decisions = [
        {**item, "state": REQUIRED_DECISION_STATES[str(item["id"])]}
        for item in template["decisions"]
    ]
    return {**template, "decisions": decisions}


def _filled_contrary() -> dict[str, Any]:
    template = contrary_review_template(as_of_date=AS_OF_DATE.isoformat())
    return {
        **template,
        "status": "reviewed_none_in_defined_source_set",
        "defined_source_set_id": "live60-defined-source-set-v1",
        "defined_source_set_review_method": "owner_manual_named_source_set",
        "defined_source_set_reviewed_as_of_date": AS_OF_DATE.isoformat(),
        "reviewer_scope": "owner_primary_defined_source_set",
        "independent_second_review_status": "not_required",
    }


def test_owner_control_confirm_requires_token_and_rejects_premature_active(
    tmp_path: Path,
) -> None:
    decisions_in = tmp_path / "decisions-unsigned.json"
    contrary_in = tmp_path / "contrary-unsigned.json"
    decisions_in.write_text(json.dumps(_filled_decisions()), encoding="utf-8")
    contrary_in.write_text(json.dumps(_filled_contrary()), encoding="utf-8")
    with pytest.raises(ValueError, match="confirmation token"):
        confirm_owner_control_records(
            project_root=PROJECT_ROOT,
            decisions_path=decisions_in,
            contrary_path=contrary_in,
            decisions_destination=tmp_path / "decisions-sealed.json",
            contrary_destination=tmp_path / "contrary-sealed.json",
            confirmation_token="not-the-token",
            index_build_id="candidate-pending-owner-review",
            run_id="live60-owner-control-test",
            as_of_date=AS_OF_DATE,
        )

    premature = _filled_decisions()
    for item in premature["decisions"]:
        if item["id"] == "D-06":
            item["state"] = "accepted"
    decisions_in.write_text(json.dumps(premature), encoding="utf-8")
    with pytest.raises(ValueError, match="D-06"):
        confirm_owner_control_records(
            project_root=PROJECT_ROOT,
            decisions_path=decisions_in,
            contrary_path=contrary_in,
            decisions_destination=tmp_path / "decisions-sealed.json",
            contrary_destination=tmp_path / "contrary-sealed.json",
            confirmation_token=OWNER_CONTROL_CONFIRMATION_TOKEN,
            index_build_id="candidate-pending-owner-review",
            run_id="live60-owner-control-test",
            as_of_date=AS_OF_DATE,
        )


def test_owner_control_confirm_seals_records_without_overlay_or_active(
    tmp_path: Path,
) -> None:
    decisions_in = tmp_path / "decisions-unsigned.json"
    contrary_in = tmp_path / "contrary-unsigned.json"
    decisions_out = tmp_path / "decisions-sealed.json"
    contrary_out = tmp_path / "contrary-sealed.json"
    decisions_in.write_text(json.dumps(_filled_decisions()), encoding="utf-8")
    contrary_in.write_text(json.dumps(_filled_contrary()), encoding="utf-8")
    active = PROJECT_ROOT / "data" / "indexes" / "ACTIVE.json"
    active_before = active.read_bytes() if active.is_file() else None

    result = confirm_owner_control_records(
        project_root=PROJECT_ROOT,
        decisions_path=decisions_in,
        contrary_path=contrary_in,
        decisions_destination=decisions_out,
        contrary_destination=contrary_out,
        confirmation_token=OWNER_CONTROL_CONFIRMATION_TOKEN,
        index_build_id="candidate-pending-owner-review",
        run_id="live60-owner-control-test",
        as_of_date=AS_OF_DATE,
    )

    decisions = json.loads(decisions_out.read_text(encoding="utf-8"))
    contrary = json.loads(contrary_out.read_text(encoding="utf-8"))
    assert result["owner_authored"] is True
    assert result["ready_for_overlay_seal"] is False
    assert result["writes_active"] is False
    assert result["writes_o04"] is False
    assert decisions["owner_authored"] is True
    assert contrary["owner_authored"] is True
    assert contrary["means_english_law_has_no_contrary_authority"] is False
    assert decisions["seal_sha256"]
    assert contrary["seal_sha256"]
    active_after = active.read_bytes() if active.is_file() else None
    assert active_after == active_before
    assert not (PROJECT_ROOT / "data" / "evaluations" / "expert-qualification.json").is_file()


def test_full_run_status_records_honest_blockers(tmp_path: Path) -> None:
    root = tmp_path / "project"
    artifacts = root / "Live60-2026-08-16" / "artifacts"
    artifacts.mkdir(parents=True)
    source = PROJECT_ROOT / "Live60-2026-08-16" / "artifacts"
    for name in (
        "owner-tick-progress.json",
        "owner-route-selection.json",
        "held-span-contiguous-repair-v2.json",
    ):
        copyfile(source / name, artifacts / name)
    pointer_dir = root / "data" / "evaluations" / "live60"
    pointer_dir.mkdir(parents=True)
    copyfile(
        PROJECT_ROOT / "data" / "evaluations" / "live60" / "CURRENT.json",
        pointer_dir / "CURRENT.json",
    )
    copyfile(
        PROJECT_ROOT / "data" / "evaluations" / "live60" / "issue-state.json",
        pointer_dir / "issue-state.json",
    )
    payload = build_full_run_remaining_status(
        project_root=root,
        as_of_date=AS_OF_DATE,
    )
    assert payload["path_b_overlay"]["sealed"] is False
    assert payload["candidate_stage_a"]["passed"] is False
    assert payload["candidate_stage_a"]["candidate_built"] is False
    assert payload["fabricated_any_pass"] is False
    assert payload["generation_authorised"] is False
    counts = json.loads(
        (PROJECT_ROOT / "data/evaluations/live60/issue-state.json").read_text(encoding="utf-8")
    )["counts"]
    assert payload["current_issue_state"]["qualified"] == counts["qualified"]
    assert payload["current_issue_state"]["knowledge_gap"] == counts["knowledge_gap"]
    assert payload["stale_tick_progress_ignored"] is True
    assert (
        "selected_issues_missing_positive_exact_spans"
        in payload["path_b_overlay"]["blocking_reason_codes"]
    )
    assert (artifacts / "owner-decisions-d1-d15-unsigned.json").is_file()
    assert (artifacts / "contrary-authority-review-unsigned.json").is_file()
    unsigned = json.loads((artifacts / "owner-decisions-d1-d15-unsigned.json").read_text())
    assert unsigned["owner_authored"] is False
    assert unsigned["unsigned"] is True


def test_cli_registers_owner_control_and_full_run_status() -> None:
    confirm = parser().parse_args(
        [
            "live60-owner-control-confirm",
            "--decisions",
            "d.json",
            "--contrary",
            "c.json",
            "--decisions-out",
            "d-out.json",
            "--contrary-out",
            "c-out.json",
            "--index-build-id",
            "candidate-pending-owner-review",
            "--run-id",
            "live60-owner-control-test",
            "--confirm",
            OWNER_CONTROL_CONFIRMATION_TOKEN,
        ]
    )
    assert confirm.command == "live60-owner-control-confirm"
    status = parser().parse_args(["live60-full-run-status", "--out", "status.json"])
    assert status.command == "live60-full-run-status"
    current = parser().parse_args(["live60-current-state"])
    assert current.command == "live60-current-state"
