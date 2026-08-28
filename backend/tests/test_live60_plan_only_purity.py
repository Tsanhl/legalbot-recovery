from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from app.evaluation import live_suite_evaluate_cli as module


@pytest.mark.asyncio
async def test_plan_only_does_not_construct_store_or_write_authorization(
    monkeypatch, tmp_path
) -> None:
    overlay_path = tmp_path / "overlay.json"
    overlay_path.write_text(
        json.dumps(
            {
                "review_overlay_complete": True,
                "unreviewed_issue_count": 0,
                "case_execution": [{"case_id": "live30-q02", "issues": []}],
            }
        ),
        encoding="utf-8",
    )
    stage_a = tmp_path / "stage-a.json"
    stage_a.write_text("{}", encoding="utf-8")
    bundle = SimpleNamespace()
    authorization = SimpleNamespace()

    monkeypatch.setattr(module, "load_live_evaluation_bundle", lambda _path: bundle)
    monkeypatch.setattr(
        module,
        "issue_evaluation_authorization_v2",
        lambda **_kwargs: authorization,
    )
    monkeypatch.setattr(
        module,
        "selected_generation_case_ids",
        lambda _bundle: ("live30-q02",),
    )
    monkeypatch.setattr(
        module,
        "plan_evaluation_only_run",
        lambda **_kwargs: {"schema": "plan", "outcomes": []},
    )

    class ForbiddenStore:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("plan-only constructed a persistent run store")

    monkeypatch.setattr(module, "LiveSuiteRunStore", ForbiddenStore)
    settings = SimpleNamespace(project_root=tmp_path)
    database = SimpleNamespace(active_index_id=lambda: None)

    result = await module.run_live60_evaluate_v2(
        settings=settings,
        database=database,
        cipher=object(),
        run_id="plan-only-test",
        candidate_build_id="candidate-one",
        overlay_path=overlay_path,
        stage_a_path=stage_a,
        client=object(),
        as_of_date="2026-08-16",
        execute=False,
    )
    assert result == {"schema": "plan", "outcomes": []}
    assert not any(tmp_path.rglob("execution-authorization.json"))
